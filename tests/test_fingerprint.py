"""Tests for function-level fingerprinting (binary SCA)."""

from __future__ import annotations

import hashlib
import struct

import firefly.analyzers.fingerprint as analyzer_mod
from firefly.analyzers.fingerprint import FingerprintAnalyzer
from firefly.analyzers import ScanContext
from firefly.fingerprint import FunctionSig, extract_functions
from firefly.fpdb import FpDB, Identification
from firefly.inventory import Inventory
from firefly.models import Severity

from elfbuild import ET_EXEC, build_elf

VBASE = 0x10000


def _elf_with_function(func_name: str, code: bytes, machine: int = 0x28) -> bytes:
    """Minimal 32-bit LE ELF with one defined STT_FUNC covering `code`."""
    ehsize, phentsize, shentsize = 52, 32, 40
    phoff = ehsize
    code_off = phoff + phentsize  # one program header
    strtab = b"\x00" + func_name.encode() + b"\x00"
    strtab_off = code_off + len(code)
    symtab_off = strtab_off + len(strtab)
    # null symbol + one FUNC
    sym_null = struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)
    sym_func = struct.pack("<IIIBBH", 1, VBASE + code_off, len(code), (1 << 4) | 2, 0, 1)  # GLOBAL|FUNC, shndx=1
    symtab = sym_null + sym_func
    shoff = symtab_off + len(symtab)

    def shdr(sh_type, off, size, link=0, entsize=0):
        return struct.pack("<IIIIIIIIII", 0, sh_type, 0, 0, off, size, link, 0, 0, entsize)

    shdrs = shdr(0, 0, 0) + shdr(3, strtab_off, len(strtab)) + shdr(2, symtab_off, len(symtab), link=1, entsize=16)
    total = shoff + len(shdrs)

    phdr = struct.pack("<IIIIIIII", 1, 0, VBASE, VBASE, total, total, 5, 0x1000)  # PT_LOAD, maps file 1:1
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    ehdr = ident + struct.pack("<HHIIIIIHHHHHH", 2, machine, 1, 0, phoff, shoff, 0, ehsize, phentsize, 1, shentsize, 3, 0)
    blob = ehdr + phdr + code + strtab + symtab + shdrs
    assert len(blob) == total, (len(blob), total)
    return blob


# --------------------------------------------------------------------------- extraction


def test_extract_function_hashes_the_code():
    code = bytes(range(64))  # 64 distinct bytes as "function body"
    elf = _elf_with_function("inflate", code)
    sigs = extract_functions(elf)
    assert len(sigs) == 1
    assert sigs[0].name == "inflate"
    assert sigs[0].size == 64
    assert sigs[0].hash == hashlib.sha256(code).hexdigest()[:32]


def test_extract_skips_tiny_functions():
    sigs = extract_functions(_elf_with_function("stub", b"\x90" * 8))  # below MIN_FUNC_BYTES
    assert sigs == []


def test_extract_ignores_non_elf():
    assert extract_functions(b"not an elf") == []


# --------------------------------------------------------------------------- signature DB


def test_fpdb_identifies_on_overlap(tmp_path):
    db = FpDB(str(tmp_path / "fp.sqlite"))
    hashes = [f"{i:032x}" for i in range(10)]
    db.add(hashes=hashes, arch="x86_64", vendor="zlib", product="zlib", version="1.2.11")
    # A binary sharing 8 of the 10 reference functions.
    found = db.identify(set(hashes[:8]), "x86_64")
    assert len(found) == 1
    ident = found[0]
    assert (ident.product, ident.version, ident.matched, ident.reference_total) == ("zlib", "1.2.11", 8, 10)
    assert ident.ratio == 0.8
    db.close()


def test_fpdb_respects_arch_and_thresholds(tmp_path):
    db = FpDB(str(tmp_path / "fp.sqlite"))
    hashes = [f"{i:032x}" for i in range(10)]
    db.add(hashes=hashes, arch="arm", vendor=None, product="zlib", version="1.2.11")
    assert db.identify(set(hashes), "mips") == []          # wrong arch
    assert db.identify(set(hashes[:3]), "arm") == []        # below min_matched (6)
    assert len(db.identify(set(hashes[:6]), "arm")) == 1    # exactly min_matched
    db.close()


# --------------------------------------------------------------------------- analyzer


def _ctx(tmp_path, fpdb_path):
    root = tmp_path / "root"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "httpd").write_bytes(build_elf(etype=ET_EXEC))  # x86-ish arm ELF, machine 0x28
    inv = Inventory.build(str(root))
    return ScanContext(firmware_path="x", workdir="x", jobs=1, inventory=inv, fpdb_path=fpdb_path)


def test_analyzer_emits_component_and_finding(tmp_path, monkeypatch):
    dbfile = tmp_path / "fp.sqlite"
    db = FpDB(str(dbfile))
    hashes = [f"{i:032x}" for i in range(10)]
    db.add(hashes=hashes, arch="arm", vendor="zlib", product="zlib", version="1.2.11")
    db.close()

    # The scanned binary shares 8 of zlib's functions.
    monkeypatch.setattr(
        analyzer_mod, "extract_functions_file",
        lambda path: [FunctionSig(name=f"f{i}", size=32, hash=h) for i, h in enumerate(hashes[:8])],
    )

    res = FingerprintAnalyzer().run(_ctx(tmp_path, str(dbfile)))
    assert [(c.product, c.version) for c in res.components] == [("zlib", "1.2.11")]
    assert res.components[0].paths == ["bin/httpd"]
    assert any(f.severity is Severity.INFO and "zlib" in f.title for f in res.findings)
    assert res.artifacts["binaries_fingerprinted"] == 1


def test_analyzer_without_db_warns(tmp_path):
    res = FingerprintAnalyzer().run(_ctx(tmp_path, str(tmp_path / "absent.sqlite")))
    assert res.components == []
    assert any("fingerprint database" in w for w in res.warnings)
