"""Tests for function-level fingerprinting (binary SCA)."""

from __future__ import annotations

import hashlib
import json
import struct

import firefly.analyzers.fingerprint as analyzer_mod
from firefly.analyzers.fingerprint import FingerprintAnalyzer
from firefly.analyzers import ScanContext
from firefly.fingerprint import FunctionSig, extract_functions
from firefly.fpdb import FpDB, Identification, build_from_manifest
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


def _elf_with_reloc(code: bytes, reloc_k: int | None = None) -> bytes:
    """Like _elf_with_function (name 'fn'), optionally with one 32-bit RELA
    entry whose r_offset points at byte `reloc_k` inside the function."""
    ehsize, phentsize, shentsize = 52, 32, 40
    phoff = ehsize
    code_off = phoff + phentsize
    strtab = b"\x00fn\x00"
    strtab_off = code_off + len(code)
    symtab_off = strtab_off + len(strtab)
    sym_null = struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)
    sym_func = struct.pack("<IIIBBH", 1, VBASE + code_off, len(code), (1 << 4) | 2, 0, 1)
    symtab = sym_null + sym_func
    rela_off = symtab_off + len(symtab)
    rela = struct.pack("<IIi", VBASE + code_off + reloc_k, 0, 0) if reloc_k is not None else b""
    shoff = rela_off + len(rela)

    def shdr(sh_type, off, size, link=0, entsize=0):
        return struct.pack("<IIIIIIIIII", 0, sh_type, 0, 0, off, size, link, 0, 0, entsize)

    shdrs = shdr(0, 0, 0) + shdr(3, strtab_off, len(strtab)) + shdr(2, symtab_off, len(symtab), link=1, entsize=16)
    if rela:
        shdrs += shdr(4, rela_off, len(rela), entsize=12)  # SHT_RELA
    nshdr = 4 if rela else 3
    total = shoff + len(shdrs)
    phdr = struct.pack("<IIIIIIII", 1, 0, VBASE, VBASE, total, total, 5, 0x1000)
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    ehdr = ident + struct.pack("<HHIIIIIHHHHHH", 2, 0x28, 1, 0, phoff, shoff, 0, ehsize, phentsize, 1, shentsize, nshdr, 0)
    blob = ehdr + phdr + code + strtab + symtab + rela + shdrs
    assert len(blob) == total
    return blob


def test_relocation_masking_matches_differently_linked_builds():
    base = bytes(range(32))
    # two builds differ only in a 4-byte word at offset 8 (a relocated address)
    a = base[:8] + b"\xaa\xaa\xaa\xaa" + base[12:]
    b = base[:8] + b"\xbb\xbb\xbb\xbb" + base[12:]
    # control: with no relocation there, the differing word makes them mismatch
    assert extract_functions(_elf_with_reloc(a))[0].hash != extract_functions(_elf_with_reloc(b))[0].hash
    # with a relocation covering offset 8, that word is masked -> equal hashes
    ra = extract_functions(_elf_with_reloc(a, reloc_k=8))[0].hash
    rb = extract_functions(_elf_with_reloc(b, reloc_k=8))[0].hash
    assert ra == rb
    assert ra == hashlib.sha256(a[:8] + b"\x00\x00\x00\x00" + a[12:]).hexdigest()[:32]


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


def test_build_from_manifest_defaults_arch_to_elf_machine(tmp_path):
    # ppc64 (e_machine 0x15) is in inventory's canonical map; a divergent local
    # map in fpdb would store it under the raw hex "0x15" and never match the
    # "ppc64" that inventory assigns to a scanned binary.
    elf = _elf_with_function("deflate", bytes(range(32)), machine=0x15)
    (tmp_path / "libfoo.so").write_bytes(elf)
    sig = extract_functions(elf)[0]

    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps([{"path": "libfoo.so", "product": "foo", "version": "1.0"}]))
    info = build_from_manifest(str(tmp_path / "fp.sqlite"), str(manifest))
    assert info["signatures"] == "1"

    db = FpDB(str(tmp_path / "fp.sqlite"))
    assert [i.product for i in db.identify({sig.hash}, "ppc64", min_matched=1)] == ["foo"]
    assert db.identify({sig.hash}, "0x15", min_matched=1) == []  # not stored under raw hex
    db.close()


def test_build_from_manifest_reports_skipped(tmp_path):
    manifest = tmp_path / "m.json"
    manifest.write_text(json.dumps([{"path": "missing.bin", "product": "x", "version": "1"}]))
    info = build_from_manifest(str(tmp_path / "fp.sqlite"), str(manifest))
    assert info["signatures"] == "0"
    assert "not found" in info.get("skipped", "")


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


def test_analyzer_keeps_one_version_per_product(tmp_path, monkeypatch):
    # Two close versions of one product share most functions; the binary must be
    # reported as one component (the best-matching version), not one per version.
    dbfile = tmp_path / "fp.sqlite"
    db = FpDB(str(dbfile))
    common = [f"{i:032x}" for i in range(8)]
    db.add(hashes=common + ["a" * 32, "b" * 32], arch="arm", vendor="zlib", product="zlib", version="1.2.11")
    db.add(hashes=common + ["c" * 32, "d" * 32], arch="arm", vendor="zlib", product="zlib", version="1.2.12")
    db.close()

    bin_hashes = common + ["a" * 32, "b" * 32]  # exactly 1.2.11; overlaps 8/10 of 1.2.12
    monkeypatch.setattr(
        analyzer_mod, "extract_functions_file",
        lambda path: [FunctionSig(name=f"f{i}", size=32, hash=h) for i, h in enumerate(bin_hashes)],
    )

    res = FingerprintAnalyzer().run(_ctx(tmp_path, str(dbfile)))
    assert [(c.product, c.version) for c in res.components] == [("zlib", "1.2.11")]


def test_analyzer_without_db_warns(tmp_path):
    res = FingerprintAnalyzer().run(_ctx(tmp_path, str(tmp_path / "absent.sqlite")))
    assert res.components == []
    assert any("fingerprint database" in w for w in res.warnings)
