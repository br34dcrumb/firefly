"""A small, dependency-free ELF reader for the checks Firefly needs.

Only what the analyzers use is parsed: program headers (for NX and RELRO),
the dynamic section (BIND_NOW, flags, needed libraries, RPATH) and the dynamic
symbol table (for imported functions and the stack-canary marker). Firmware
binaries are hostile, so every field is bounds-checked and anything malformed
raises :class:`ElfError` rather than reading out of range.
"""

from __future__ import annotations

import struct
from dataclasses import dataclass, field
from functools import lru_cache

# segment / dynamic-tag constants
PT_INTERP = 3
PT_DYNAMIC = 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
DT_NEEDED = 1
DT_RUNPATH = 29
DT_RPATH = 15
DT_FLAGS = 30
DT_FLAGS_1 = 0x6FFFFFFB
DT_BIND_NOW = 24
DT_STRTAB = 5
DT_SYMTAB = 6
DT_STRSZ = 10
DT_SONAME = 14
DF_BIND_NOW = 0x08
DF_1_NOW = 0x01
DF_1_PIE = 0x08000000
PF_X = 0x1
ET_EXEC = 2
ET_DYN = 3
STT_FUNC = 2
SHN_UNDEF = 0
MAX_SYMBOLS = 200_000  # don't walk an absurd symbol count from a crafted header


class ElfError(ValueError):
    pass


@dataclass
class ElfInfo:
    bits: int
    endian: str
    machine: int
    etype: int
    interp: str | None = None
    nx: bool = False
    pie: bool = False
    relro: str = "none"  # "none" | "partial" | "full"
    bind_now: bool = False
    needed: list[str] = field(default_factory=list)
    runpath: str | None = None
    imported_functions: set[str] = field(default_factory=set)
    has_stack_canary: bool = False
    stripped: bool = True
    soname: str | None = None


def _s(endian: str) -> str:
    return "<" if endian == "little" else ">"


class _Reader:
    def __init__(self, data: bytes):
        self.data = data

    def at(self, off: int, size: int) -> bytes:
        if off < 0 or off + size > len(self.data):
            raise ElfError(f"read {size} bytes at {off} out of range ({len(self.data)})")
        return self.data[off : off + size]

    def cstr(self, off: int) -> str:
        end = self.data.find(b"\x00", off)
        if off < 0 or off >= len(self.data) or end == -1:
            return ""
        return self.data[off:end].decode("utf-8", "replace")


def parse(data: bytes) -> ElfInfo:
    if len(data) < 64 or data[:4] != b"\x7fELF":
        raise ElfError("not an ELF file")
    bits = {1: 32, 2: 64}.get(data[4])
    endian = {1: "little", 2: "big"}.get(data[5])
    if bits is None or endian is None:
        raise ElfError("invalid ELF class/endianness")
    r = _Reader(data)
    e = _s(endian)
    is64 = bits == 64

    etype, machine = struct.unpack_from(e + "HH", data, 16)
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

    info = ElfInfo(bits=bits, endian=endian, machine=machine, etype=etype)
    dyn_off = dyn_size = 0
    relro_present = False
    loads: list[tuple[int, int, int]] = []  # (vaddr, offset, filesz) of PT_LOAD segments

    for i in range(min(e_phnum, 256)):
        base = e_phoff + i * e_phentsize
        if is64:
            p_type, p_flags = struct.unpack_from(e + "II", data, base)
            p_offset, p_vaddr, _paddr, p_filesz = struct.unpack_from(e + "QQQQ", data, base + 8)
        else:
            p_type, p_offset, p_vaddr, _paddr, p_filesz, _memsz, p_flags = struct.unpack_from(e + "IIIIIII", data, base)
        if p_type == 1:  # PT_LOAD
            loads.append((p_vaddr, p_offset, p_filesz))
        elif p_type == PT_INTERP:
            info.interp = r.cstr(p_offset)
        elif p_type == PT_GNU_STACK:
            info.nx = not (p_flags & PF_X)
        elif p_type == PT_GNU_RELRO:
            relro_present = True
        elif p_type == PT_DYNAMIC:
            dyn_off, dyn_size = p_offset, p_filesz

    _parse_dynamic(r, e, is64, dyn_off, dyn_size, loads, info)
    # ET_DYN with an interpreter (or the explicit PIE flag) is a PIE executable;
    # ET_DYN without one is a shared library, for which PIE doesn't apply.
    info.pie = info.etype == ET_DYN and (info.interp is not None or info._df1_pie)  # type: ignore[attr-defined]
    if relro_present:
        info.relro = "full" if info.bind_now else "partial"
    _parse_symbols(r, e, is64, data, e_shoff, e_shentsize, e_shnum, info)
    return info


def _vaddr_to_offset(vaddr: int, loads: list[tuple[int, int, int]]) -> int | None:
    for seg_vaddr, seg_off, seg_size in loads:
        if seg_vaddr <= vaddr < seg_vaddr + seg_size:
            return seg_off + (vaddr - seg_vaddr)
    return None


def _parse_dynamic(r: _Reader, e: str, is64: bool, off: int, size: int, loads: list[tuple[int, int, int]], info: ElfInfo) -> None:
    info._df1_pie = False  # type: ignore[attr-defined]
    if not off or not size:
        return
    entsize = 16 if is64 else 8
    fmt = e + ("qQ" if is64 else "iI")
    strtab = 0
    needed_offsets: list[int] = []
    runpath_off = None
    soname_off = None
    for i in range(min(size // entsize, 4096)):
        try:
            tag, val = struct.unpack_from(fmt, r.data, off + i * entsize)
        except struct.error:
            break
        if tag == 0:  # DT_NULL
            break
        if tag == DT_NEEDED:
            needed_offsets.append(val)
        elif tag == DT_STRTAB:
            strtab = val
        elif tag in (DT_RUNPATH, DT_RPATH):
            runpath_off = val
        elif tag == DT_SONAME:
            soname_off = val
        elif tag == DT_BIND_NOW:
            info.bind_now = True
        elif tag == DT_FLAGS:
            info.bind_now = info.bind_now or bool(val & DF_BIND_NOW)
        elif tag == DT_FLAGS_1:
            info.bind_now = info.bind_now or bool(val & DF_1_NOW)
            info._df1_pie = bool(val & DF_1_PIE)  # type: ignore[attr-defined]

    # DT_STRTAB is a virtual address: map it to a file offset through PT_LOAD.
    # Fall back to treating it as a direct offset (true for some libraries).
    base = _vaddr_to_offset(strtab, loads)
    if base is None:
        base = strtab if strtab < len(r.data) else None
    if base is None:
        return
    for o in needed_offsets:
        name = r.cstr(base + o)
        if name:
            info.needed.append(name)
    if runpath_off is not None:
        info.runpath = r.cstr(base + runpath_off) or None
    if soname_off is not None:
        info.soname = r.cstr(base + soname_off) or None


def _parse_symbols(r: _Reader, e: str, is64: bool, data: bytes, shoff: int, shentsize: int, shnum: int, info: ElfInfo) -> None:
    if not shoff or not shnum or shnum > 4096:
        return
    sections = []
    for i in range(shnum):
        base = shoff + i * shentsize
        try:
            if is64:
                sh_name, sh_type = struct.unpack_from(e + "II", data, base)
                sh_offset, sh_size = struct.unpack_from(e + "QQ", data, base + 24)
                sh_link, _sh_info, _align, sh_entsize = struct.unpack_from(e + "IIQQ", data, base + 40)
            else:
                sh_name, sh_type = struct.unpack_from(e + "II", data, base)
                sh_offset, sh_size = struct.unpack_from(e + "II", data, base + 16)
                sh_link, _sh_info, _align, sh_entsize = struct.unpack_from(e + "IIII", data, base + 24)
        except struct.error:
            return
        sections.append((sh_name, sh_type, sh_offset, sh_size, sh_link, sh_entsize))

    SHT_SYMTAB, SHT_DYNSYM = 2, 11
    for _name, sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
        if sh_type == SHT_SYMTAB:
            info.stripped = False  # a full symbol table survived
        if sh_type not in (SHT_SYMTAB, SHT_DYNSYM) or not sh_entsize or sh_link >= len(sections):
            continue
        str_off, str_size = sections[sh_link][2], sections[sh_link][3]
        count = min(sh_size // sh_entsize, MAX_SYMBOLS)
        for i in range(count):
            sb = sh_offset + i * sh_entsize
            try:
                if is64:
                    st_name, st_info = struct.unpack_from(e + "IB", data, sb)
                    st_shndx = struct.unpack_from(e + "H", data, sb + 6)[0]
                else:
                    st_name = struct.unpack_from(e + "I", data, sb)[0]
                    st_info, _other, st_shndx = struct.unpack_from(e + "BBH", data, sb + 12)
            except struct.error:
                break
            if not st_name or st_name >= str_size:
                continue
            name = r.cstr(str_off + st_name)
            if not name:
                continue
            if name == "__stack_chk_fail":
                info.has_stack_canary = True
            # imported function = undefined symbol of type FUNC
            if sh_type == SHT_DYNSYM and st_shndx == SHN_UNDEF and (st_info & 0xF) == STT_FUNC:
                info.imported_functions.add(name)


MAX_ELF_BYTES = 256 * 1024**2  # don't load an implausibly large "ELF" into memory


@lru_cache(maxsize=512)
def parse_file(path: str, size: int) -> ElfInfo | None:
    """Parse an ELF by path. ``size`` is part of the cache key so a replaced
    file is re-parsed. Returns None if the file isn't a valid ELF."""
    if size > MAX_ELF_BYTES:
        return None
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError:
        return None
    try:
        return parse(data)
    except ElfError:
        return None
