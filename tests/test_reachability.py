"""Tests for reachability-aware CVE triage."""

from __future__ import annotations

import struct

from firefly.analyzers import ScanContext
from firefly.analyzers.cves import CveAnalyzer
from firefly.elf import ElfInfo
from firefly.inventory import Inventory
from firefly.models import Component
from firefly.reachability import classify, component_symbols, load_cve_functions
from firefly.vulndb import VulnDB, import_files

from nvdfeed import cve, match, write_feed

VBASE = 0x10000


def _elf_defining(func_name: str, code: bytes = bytes(range(32))) -> bytes:
    """Minimal 32-bit LE ET_EXEC ELF with one defined STT_FUNC named func_name."""
    ehsize, phentsize, shentsize = 52, 32, 40
    phoff = ehsize
    code_off = phoff + phentsize
    strtab = b"\x00" + func_name.encode() + b"\x00"
    strtab_off = code_off + len(code)
    symtab_off = strtab_off + len(strtab)
    sym_null = struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)
    sym_func = struct.pack("<IIIBBH", 1, VBASE + code_off, len(code), (1 << 4) | 2, 0, 1)
    symtab = sym_null + sym_func
    shoff = symtab_off + len(symtab)

    def shdr(sh_type, off, size, link=0, entsize=0):
        return struct.pack("<IIIIIIIIII", 0, sh_type, 0, 0, off, size, link, 0, 0, entsize)

    shdrs = shdr(0, 0, 0) + shdr(3, strtab_off, len(strtab)) + shdr(2, symtab_off, len(symtab), link=1, entsize=16)
    total = shoff + len(shdrs)
    phdr = struct.pack("<IIIIIIII", 1, 0, VBASE, VBASE, total, total, 5, 0x1000)
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    ehdr = ident + struct.pack("<HHIIIIIHHHHHH", 2, 0x28, 1, 0, phoff, shoff, 0, ehsize, phentsize, 1, shentsize, 3, 0)
    return ehdr + phdr + code + strtab + symtab + shdrs


# --------------------------------------------------------------------------- loader + classify


def test_load_ships_known_products():
    table = load_cve_functions()
    assert "CVE-2022-37434" in table["zlib"]
    assert table["openssl"]["CVE-2022-0778"] == ["BN_mod_sqrt"]


def test_load_missing_file_is_empty(tmp_path):
    assert load_cve_functions(str(tmp_path / "nope.json")) == {}


def test_classify_branches():
    table = {"zlib": {"CVE-X": ["inflate", "inflateGetHeader"]}}
    # reachable: at least one vulnerable function observed
    r = classify("CVE-X", "zlib", {"inflate", "other"}, True, table)
    assert r.status == "reachable" and r.present == ["inflate"]
    # not present: symbols were readable but none of the vulnerable ones appear
    assert classify("CVE-X", "zlib", {"other"}, True, table).status == "not_present"
    # unknown: no symbols readable at all
    assert classify("CVE-X", "zlib", set(), False, table).status == "unknown"
    # unknown: no data for this CVE
    assert classify("CVE-Y", "zlib", {"inflate"}, True, table).status == "unknown"


# --------------------------------------------------------------------------- symbol gathering


def test_component_symbols_reads_defined_functions(tmp_path):
    root = tmp_path / "root"
    (root / "lib").mkdir(parents=True)
    (root / "lib" / "libz.so").write_bytes(_elf_defining("inflateGetHeader"))
    inv = Inventory.build(str(root))
    observed, known = component_symbols(["lib/libz.so"], inv)
    assert known and "inflateGetHeader" in observed


def _stripped_elf() -> bytes:
    """A valid ET_EXEC ELF with no section headers at all (fully stripped)."""
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    body = b"\x00" * 32
    total = 52 + 32 + len(body)
    phdr = struct.pack("<IIIIIIII", 1, 0, VBASE, VBASE, total, total, 5, 0x1000)  # PT_LOAD
    ehdr = ident + struct.pack("<HHIIIIIHHHHHH", 2, 0x28, 1, 0, 52, 0, 0, 52, 32, 1, 40, 0, 0)  # shoff=0, shnum=0
    return ehdr + phdr + body


def test_component_symbols_unknown_for_stripped_binary(tmp_path):
    # A stripped binary (no symbol tables) must read as unknown, so a truly
    # present-but-unhashable function is never falsely reported not_present.
    root = tmp_path / "root"
    (root / "lib").mkdir(parents=True)
    (root / "lib" / "stripped.so").write_bytes(_stripped_elf())
    inv = Inventory.build(str(root))
    observed, known = component_symbols(["lib/stripped.so"], inv)
    assert observed == set() and known is False


def test_component_symbols_unknown_when_no_elf(tmp_path):
    root = tmp_path / "root"
    (root / "etc").mkdir(parents=True)
    (root / "etc" / "motd").write_text("hello")
    inv = Inventory.build(str(root))
    observed, known = component_symbols(["etc/motd"], inv)
    assert observed == set() and known is False


class _FakeRec:
    is_executable_code = True
    size = 100


class _FakeInv:
    def get(self, rel):
        return _FakeRec()

    def abspath(self, rec):
        return "ignored"


def test_component_symbols_imports_only_is_unknown(monkeypatch):
    # A stripped binary that only exposes dynamic imports must read as unknown:
    # a defined vulnerable function we can't see must never look not_present.
    info = ElfInfo(bits=32, endian="little", machine=0x28, etype=2,
                   imported_functions={"printf", "malloc"}, defined_functions=set(), stripped=True)
    monkeypatch.setattr("firefly.reachability.parse_file", lambda path, size: info)
    observed, known = component_symbols(["usr/sbin/httpd"], _FakeInv())
    assert observed == {"printf", "malloc"} and known is False


# --------------------------------------------------------------------------- analyzer integration


def _zlib_db(tmp_path, kev=None):
    path = str(tmp_path / "vulndb.sqlite")
    feed = [cve("CVE-2022-37434", [match("cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*", versionStartIncluding="1.2.0", versionEndExcluding="1.2.12")], kev=kev)]
    with VulnDB(path) as db:
        import_files(db, [str(write_feed(tmp_path / "feed.json", feed))])
    return path


def _ctx_with(tmp_path, libs: dict[str, str], db_path):
    """libs maps rel path -> the function the ELF at that path defines."""
    root = tmp_path / "root"
    (root / "lib").mkdir(parents=True)
    comps = []
    for rel, func in libs.items():
        (root / rel).parent.mkdir(parents=True, exist_ok=True)
        (root / rel).write_bytes(_elf_defining(func))
        comps.append(Component(product="zlib", version="1.2.11", vendor="zlib", paths=[rel]))
    inv = Inventory.build(str(root))
    ctx = ScanContext(firmware_path="x", workdir="x", jobs=1, inventory=inv, db_path=db_path)
    ctx.components = comps
    return ctx


def test_reachable_cve_is_annotated_not_downranked(tmp_path):
    ctx = _ctx_with(tmp_path, {"lib/good.so": "inflateGetHeader"}, _zlib_db(tmp_path))
    res = CveAnalyzer().run(ctx)
    hit = next(f for f in res.findings if f.metadata["cve"] == "CVE-2022-37434")
    assert hit.metadata["reachability"]["status"] == "reachable"
    assert hit.confidence == "high"  # vendor known, not down-ranked
    assert res.artifacts["reachability"]["reachable"] == 1


def test_absent_function_downranks_to_low(tmp_path):
    ctx = _ctx_with(tmp_path, {"lib/bad.so": "some_unrelated_function"}, _zlib_db(tmp_path))
    res = CveAnalyzer().run(ctx)
    hit = next(f for f in res.findings if f.metadata["cve"] == "CVE-2022-37434")
    assert hit.metadata["reachability"]["status"] == "not_present"
    assert hit.confidence == "low"
    assert any("absent from the matched binary" in r for r in hit.metadata["confidence_reasons"])
    assert res.artifacts["reachability"]["not_present"] == 1


def test_kev_cve_is_not_hidden_when_absent(tmp_path):
    # A known-exploited CVE whose function looks absent is annotated but NOT
    # down-ranked to low — reachability must never hide an exploited bug.
    ctx = _ctx_with(tmp_path, {"lib/bad.so": "some_unrelated_function"}, _zlib_db(tmp_path, kev="2099-01-01"))
    res = CveAnalyzer().run(ctx)
    hit = next(f for f in res.findings if f.metadata["cve"] == "CVE-2022-37434")
    assert hit.metadata["kev"] is True
    assert hit.metadata["reachability"]["status"] == "not_present"
    assert hit.confidence != "low"
