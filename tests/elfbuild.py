"""Build minimal but valid 32-bit little-endian ELF files for tests.

Enough structure for firefly.elf to parse: ELF header, program headers
(PT_LOAD, optional PT_INTERP/PT_GNU_STACK/PT_GNU_RELRO, PT_DYNAMIC), a dynamic
section (DT_NEEDED/DT_SONAME/DT_FLAGS/DT_STRTAB/DT_SYMTAB) and section headers
with .dynstr/.dynsym so imported functions resolve.
"""

from __future__ import annotations

import struct

ET_EXEC, ET_DYN = 2, 3
PT_LOAD, PT_DYNAMIC, PT_INTERP, PT_GNU_STACK, PT_GNU_RELRO = 1, 2, 3, 0x6474E551, 0x6474E552
PF_R, PF_W, PF_X = 4, 2, 1
VBASE = 0x10000


def build_elf(
    *,
    etype=ET_EXEC,
    interp=None,
    nx=True,
    relro=None,  # None | "partial" | "full"
    pie_flag=False,
    needed=(),
    soname=None,
    imports=(),  # undefined FUNC symbols
    canary=False,
    with_symtab=False,
) -> bytes:
    syms = list(imports) + (["__stack_chk_fail"] if canary else [])

    # .dynstr
    dynstr = b"\x00"
    offs: dict[str, int] = {}
    for name in list(needed) + ([soname] if soname else []) + syms:
        if name not in offs:
            offs[name] = len(dynstr)
            dynstr += name.encode() + b"\x00"

    # .dynsym: null entry + one undefined FUNC per symbol
    def sym(name_off, info, shndx):
        return struct.pack("<IIIBBH", name_off, 0, 0, info, 0, shndx)

    dynsym = sym(0, 0, 0)
    for name in syms:
        dynsym += sym(offs[name], (1 << 4) | 2, 0)  # STB_GLOBAL|STT_FUNC, SHN_UNDEF

    # .dynamic
    dyn = b""

    def d(tag, val):
        nonlocal dyn
        dyn += struct.pack("<iI", tag, val)

    # offsets are filled after we know the layout; placeholders via two passes
    # Simplests: lay out dynstr, dynsym, dynamic contiguously after phdrs.
    ehsize = 52
    phentsize = 32
    nph = 1 + (interp is not None) + 1 + (relro is not None) + 1  # LOAD, [INTERP], GNU_STACK, [RELRO], DYNAMIC
    phoff = ehsize
    body_off = phoff + nph * phentsize

    interp_bytes = (interp.encode() + b"\x00") if interp else b""
    interp_off = body_off
    dynstr_off = interp_off + len(interp_bytes)
    dynsym_off = dynstr_off + len(dynstr)
    dyn_off = dynsym_off + len(dynsym)

    # now build dynamic with real vaddrs
    DT_NEEDED, DT_STRTAB, DT_SYMTAB, DT_STRSZ, DT_SYMENT, DT_SONAME, DT_FLAGS, DT_FLAGS_1, DT_NULL = 1, 5, 6, 10, 11, 14, 30, 0x6FFFFFFB, 0
    for name in needed:
        d(DT_NEEDED, offs[name])
    if soname:
        d(DT_SONAME, offs[soname])
    d(DT_STRTAB, VBASE + dynstr_off)
    d(DT_SYMTAB, VBASE + dynsym_off)
    d(DT_STRSZ, len(dynstr))
    d(DT_SYMENT, 16)
    flags1 = 0x08000000 if pie_flag else 0
    if relro == "full":
        d(DT_FLAGS, 0x08)  # DF_BIND_NOW
    if flags1:
        d(DT_FLAGS_1, flags1)
    d(DT_NULL, 0)

    dyn_size = len(dyn)
    total_body = interp_bytes + dynstr + dynsym + dyn
    end_of_body = dyn_off + dyn_size

    # section headers: null, .dynstr, .dynsym, [.symtab]
    shoff = end_of_body
    shentsize = 40
    SHT_SYMTAB, SHT_STRTAB, SHT_DYNSYM = 2, 3, 11
    dynstr_shidx = 1

    def shdr(sh_type, off, size, link=0, entsize=0):
        return struct.pack("<IIIIIIIIII", 0, sh_type, 0, 0, off, size, link, 0, 0, entsize)

    shdrs = shdr(0, 0, 0)  # null
    shdrs += shdr(SHT_STRTAB, dynstr_off, len(dynstr))  # .dynstr idx 1
    shdrs += shdr(SHT_DYNSYM, dynsym_off, len(dynsym), link=dynstr_shidx, entsize=16)  # .dynsym idx 2
    nsh = 3
    if with_symtab:
        shdrs += shdr(SHT_SYMTAB, dynsym_off, len(dynsym), link=dynstr_shidx, entsize=16)
        nsh += 1

    # program headers
    stack_flags = (PF_R | PF_W) if nx else (PF_R | PF_W | PF_X)
    total_len = shoff + len(shdrs)
    phdrs = struct.pack("<IIIIIIII", PT_LOAD, 0, VBASE, VBASE, total_len, total_len, PF_R | PF_X, 0x1000)
    if interp is not None:
        phdrs += struct.pack("<IIIIIIII", PT_INTERP, interp_off, VBASE + interp_off, VBASE + interp_off, len(interp_bytes), len(interp_bytes), PF_R, 1)
    phdrs += struct.pack("<IIIIIIII", PT_GNU_STACK, 0, 0, 0, 0, 0, stack_flags, 0x10)
    if relro is not None:
        phdrs += struct.pack("<IIIIIIII", PT_GNU_RELRO, dyn_off, VBASE + dyn_off, VBASE + dyn_off, dyn_size, dyn_size, PF_R, 1)
    phdrs += struct.pack("<IIIIIIII", PT_DYNAMIC, dyn_off, VBASE + dyn_off, VBASE + dyn_off, dyn_size, dyn_size, PF_R | PF_W, 8)

    # ELF header
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    ehdr = ident + struct.pack(
        "<HHIIIIIHHHHHH",
        etype, 40, 1, 0, phoff, shoff, 0, ehsize, phentsize, nph, shentsize, nsh, dynstr_shidx,
    )
    blob = ehdr + phdrs + total_body + shdrs
    assert len(blob) == total_len, (len(blob), total_len)
    return blob
