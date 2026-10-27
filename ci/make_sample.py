#!/usr/bin/env python3
"""Build a tiny synthetic firmware rootfs tarball for CI.

Real firmware samples are never committed, so CI needs a deterministic fixture
that exercises several analyzers (hardening, dangerfns, accounts, services,
credentials) without any external tool or vulnerability database. Usage:

    python ci/make_sample.py out.tar.gz
"""

from __future__ import annotations

import io
import struct
import sys
import tarfile


def fake_elf(imports: list[str], *, nx: bool = True) -> bytes:
    """A minimal 32-bit ARM ELF: header, one PT_LOAD/PT_GNU_STACK, a .dynsym."""
    VBASE = 0x10000
    dynstr = b"\x00"
    offs = {}
    for name in imports:
        offs[name] = len(dynstr)
        dynstr += name.encode() + b"\x00"
    dynsym = struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)
    for name in imports:
        dynsym += struct.pack("<IIIBBH", offs[name], 0, 0, (1 << 4) | 2, 0, 0)  # GLOBAL FUNC, UNDEF

    ehsize, phentsize, shentsize = 52, 32, 40
    nph = 2
    phoff = ehsize
    body_off = phoff + nph * phentsize
    dynstr_off = body_off
    dynsym_off = dynstr_off + len(dynstr)
    shoff = dynsym_off + len(dynsym)

    def shdr(sh_type, off, size, link=0, entsize=0):
        return struct.pack("<IIIIIIIIII", 0, sh_type, 0, 0, off, size, link, 0, 0, entsize)

    shdrs = shdr(0, 0, 0) + shdr(3, dynstr_off, len(dynstr)) + shdr(11, dynsym_off, len(dynsym), link=1, entsize=16)
    total = shoff + len(shdrs)

    stack_flags = (4 | 2) if nx else (4 | 2 | 1)  # PF_R|PF_W[|PF_X]
    phdrs = struct.pack("<IIIIIIII", 1, 0, VBASE, VBASE, total, total, 4 | 1, 0x1000)  # PT_LOAD
    phdrs += struct.pack("<IIIIIIII", 0x6474E551, 0, 0, 0, 0, 0, stack_flags, 0x10)  # PT_GNU_STACK

    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    ehdr = ident + struct.pack("<HHIIIIIHHHHHH", 2, 40, 1, 0, phoff, shoff, 0, ehsize, phentsize, nph, shentsize, 3, 1)
    blob = ehdr + phdrs + dynstr + dynsym + shdrs
    assert len(blob) == total
    return blob


FILES: dict[str, bytes] = {
    # unhardened binary that also imports a command-exec function
    "bin/busybox": fake_elf(["system", "strcpy", "recv"], nx=False),
    "usr/sbin/telnetd": fake_elf(["accept"], nx=False),  # insecure service binary present
    # account policy problems
    "etc/passwd": b"root::0:0:root:/root:/bin/sh\nbackdoor::0:0::/root:/bin/sh\n",
    "etc/shadow": b"root::19000:0:99999:7:::\n",
    # insecure service started at boot
    "etc/init.d/rcS": b"#!/bin/sh\n/usr/sbin/telnetd -l /bin/sh\n",
    # a hardcoded secret (synthetic, not a real key)
    "etc/config.conf": b"api_key = AKIAIOSFODNN7EXAMPLE\ndevice_password = Sup3rS3cr3tP@ss1\n",
}
DIRS = ["bin", "etc", "etc/init.d", "lib", "usr", "usr/sbin", "var"]


def build(path: str) -> None:
    with tarfile.open(path, "w:gz") as tar:
        for d in DIRS:
            info = tarfile.TarInfo(d)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            tar.addfile(info)
        for name, data in FILES.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            info.mode = 0o755 if name.startswith(("bin/", "usr/sbin/", "etc/init.d/")) else 0o644
            tar.addfile(info, io.BytesIO(data))


if __name__ == "__main__":
    out = sys.argv[1] if len(sys.argv) > 1 else "sample.tar.gz"
    build(out)
    print(f"wrote {out}")
