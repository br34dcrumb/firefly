"""Function-level fingerprints for binary software composition analysis.

Version strings are missing from stripped or statically-linked firmware
binaries, so the ``versions``/``cves`` analyzers go blind on them. Here we
identify the *code* instead: hash each defined function's bytes and match those
hashes against a signature database built from reference builds of common
libraries (see :mod:`firefly.fpdb`). Enough matching functions identify the
library and version with no banner, which then feeds the normal CVE matcher.

Scope of this first increment: it matches *exact compiled code* (same
architecture, compiler and options), which covers the very common case of a
vendor shipping one prebuilt library statically linked into several binaries.
Matching across optimization/compiler differences needs normalized
disassembly per architecture; :func:`_normalize` marks that seam and is a
later increment.

Everything here is bounds-checked: firmware ELFs are hostile input.
"""

from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass

STT_FUNC = 2
SHN_UNDEF = 0
SHN_LORESERVE = 0xFF00
SHT_SYMTAB, SHT_DYNSYM = 2, 11
PT_LOAD = 1

MIN_FUNC_BYTES = 16  # skip PLT stubs and trivial thunks
MAX_FUNCS = 200_000  # don't walk an absurd symbol count from a crafted header
HASH_HEX = 32  # 128-bit prefix of the sha256 — plenty to avoid collisions


@dataclass(frozen=True)
class FunctionSig:
    name: str
    size: int
    hash: str


def _endian(b: int) -> str | None:
    return {1: "little", 2: "big"}.get(b)


def _normalize(code: bytes, machine: int) -> bytes:
    """Hook for architecture-aware normalization (masking immediates/relocs).

    First increment: identity (exact-code matching). Normalized matching that
    survives relocation and optimization differences needs a per-architecture
    disassembler and is a later increment.
    """
    return code


def extract_functions(data: bytes) -> list[FunctionSig]:
    """Return a fingerprint per defined function in an ELF image."""
    if len(data) < 64 or data[:4] != b"\x7fELF":
        return []
    bits = {1: 32, 2: 64}.get(data[4])
    endian = _endian(data[5])
    if bits is None or endian is None:
        return []
    e = "<" if endian == "little" else ">"
    is64 = bits == 64
    try:
        machine = struct.unpack_from(e + "H", data, 18)[0]
        if is64:
            e_phoff = struct.unpack_from(e + "Q", data, 32)[0]
            e_shoff = struct.unpack_from(e + "Q", data, 40)[0]
            e_phentsize, e_phnum = struct.unpack_from(e + "HH", data, 54)
            e_shentsize, e_shnum = struct.unpack_from(e + "HH", data, 58)
        else:
            e_phoff = struct.unpack_from(e + "I", data, 28)[0]
            e_shoff = struct.unpack_from(e + "I", data, 32)[0]
            e_phentsize, e_phnum = struct.unpack_from(e + "HH", data, 42)
            e_shentsize, e_shnum = struct.unpack_from(e + "HH", data, 46)
    except struct.error:
        return []

    loads = _program_loads(data, e, is64, e_phoff, e_phentsize, e_phnum)
    sections = _sections(data, e, is64, e_shoff, e_shentsize, e_shnum)
    if not sections:
        return []

    out: dict[tuple[str, str], FunctionSig] = {}
    for sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
        if sh_type not in (SHT_SYMTAB, SHT_DYNSYM) or not sh_entsize or sh_link >= len(sections):
            continue
        str_off, str_size = sections[sh_link][1], sections[sh_link][2]
        count = min(sh_size // sh_entsize, MAX_FUNCS)
        for i in range(count):
            sym = _symbol(data, e, is64, sh_offset + i * sh_entsize, str_off, str_size)
            if sym is None:
                continue
            name, value, size = sym
            if size < MIN_FUNC_BYTES or size > len(data):
                continue
            off = _vaddr_to_offset(value, loads)
            if off is None or off + size > len(data):
                continue
            code = _normalize(data[off : off + size], machine)
            h = hashlib.sha256(code).hexdigest()[:HASH_HEX]
            out[(name, h)] = FunctionSig(name=name, size=size, hash=h)
    return list(out.values())


def extract_functions_file(path: str, max_bytes: int = 256 * 1024**2) -> list[FunctionSig]:
    try:
        import os

        if os.path.getsize(path) > max_bytes:
            return []
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return []
    return extract_functions(data)


def _program_loads(data: bytes, e: str, is64: bool, phoff: int, phentsize: int, phnum: int) -> list[tuple[int, int, int]]:
    loads: list[tuple[int, int, int]] = []  # (vaddr, offset, filesz)
    for i in range(min(phnum, 256)):
        base = phoff + i * phentsize
        try:
            if is64:
                p_type = struct.unpack_from(e + "I", data, base)[0]
                p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from(e + "QQQQ", data, base + 8)
            else:
                p_type, p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from(e + "IIIII", data, base)
        except struct.error:
            break
        if p_type == PT_LOAD:
            loads.append((p_vaddr, p_offset, p_filesz))
    return loads


def _sections(data: bytes, e: str, is64: bool, shoff: int, shentsize: int, shnum: int) -> list[tuple[int, int, int, int, int]]:
    # Returns (sh_type, sh_offset, sh_size, sh_link, sh_entsize) per section.
    if not shoff or not shnum or shnum > 4096:
        return []
    sections: list[tuple[int, int, int, int, int]] = []
    for i in range(shnum):
        base = shoff + i * shentsize
        try:
            if is64:
                sh_type = struct.unpack_from(e + "I", data, base + 4)[0]
                sh_offset, sh_size = struct.unpack_from(e + "QQ", data, base + 24)
                sh_link = struct.unpack_from(e + "I", data, base + 40)[0]
                sh_entsize = struct.unpack_from(e + "Q", data, base + 56)[0]
            else:
                sh_type = struct.unpack_from(e + "I", data, base + 4)[0]
                sh_offset, sh_size = struct.unpack_from(e + "II", data, base + 16)
                sh_link = struct.unpack_from(e + "I", data, base + 24)[0]
                sh_entsize = struct.unpack_from(e + "I", data, base + 36)[0]
        except struct.error:
            return sections
        sections.append((sh_type, sh_offset, sh_size, sh_link, sh_entsize))
    return sections


def _symbol(data: bytes, e: str, is64: bool, sb: int, str_off: int, str_size: int) -> tuple[str, int, int] | None:
    # Elf32_Sym and Elf64_Sym order differently.
    try:
        if is64:
            st_name = struct.unpack_from(e + "I", data, sb)[0]
            st_info = data[sb + 4]
            st_shndx = struct.unpack_from(e + "H", data, sb + 6)[0]
            st_value, st_size = struct.unpack_from(e + "QQ", data, sb + 8)
        else:
            st_name, st_value, st_size = struct.unpack_from(e + "III", data, sb)
            st_info = data[sb + 12]
            st_shndx = struct.unpack_from(e + "H", data, sb + 14)[0]
    except (struct.error, IndexError):
        return None
    if (st_info & 0xF) != STT_FUNC:
        return None
    if st_shndx == SHN_UNDEF or st_shndx >= SHN_LORESERVE:  # undefined or special section
        return None
    if not st_name or st_name >= str_size:
        return None
    end = data.find(b"\x00", str_off + st_name)
    if end == -1:
        return None
    name = data[str_off + st_name : end].decode("utf-8", "replace")
    if not name:
        return None
    return name, st_value, st_size


def _vaddr_to_offset(vaddr: int, loads: list[tuple[int, int, int]]) -> int | None:
    for seg_vaddr, seg_off, seg_size in loads:
        if seg_vaddr <= vaddr < seg_vaddr + seg_size:
            return seg_off + (vaddr - seg_vaddr)
    return None
