"""Map an ELF's architecture to a qemu-user program and locate it.

qemu-user ("qemu-arm", "qemu-mipsel", ...) runs a single foreign-architecture
binary by translating its syscalls to the host. The right program depends on
both the machine and the endianness (big-endian MIPS is ``qemu-mips``,
little-endian is ``qemu-mipsel``), so the mapping is keyed by ``(machine,
endian)`` with a machine-only fallback.

Note: qemu-user translates syscalls straight to the host kernel and is **not**
a security boundary. Isolation is the sandbox's job (see
:mod:`firefly.emulation.sandbox`); this module only decides *what* to run.
"""

from __future__ import annotations

import shutil

from firefly.models import ElfInfo

# (machine, endian) -> qemu-user program base name. Endian-agnostic machines are
# listed with both endiannesses pointing at the same program.
_BY_ARCH: dict[tuple[str, str], str] = {
    ("arm", "little"): "qemu-arm",
    ("arm", "big"): "qemu-armeb",
    ("aarch64", "little"): "qemu-aarch64",
    ("aarch64", "big"): "qemu-aarch64_be",
    ("mips", "big"): "qemu-mips",
    ("mips", "little"): "qemu-mipsel",
    ("x86", "little"): "qemu-i386",
    ("x86_64", "little"): "qemu-x86_64",
    ("ppc", "big"): "qemu-ppc",
    ("ppc64", "big"): "qemu-ppc64",
    ("ppc64", "little"): "qemu-ppc64le",
    ("sparc", "big"): "qemu-sparc",
    ("superh", "little"): "qemu-sh4",
    ("superh", "big"): "qemu-sh4eb",
    ("riscv", "little"): "qemu-riscv64",  # 64-bit refined below by bits
    ("s390", "big"): "qemu-s390x",
    ("xtensa", "little"): "qemu-xtensa",
    ("arc", "little"): "qemu-arc",
    ("loongarch", "little"): "qemu-loongarch64",
}


def qemu_program(elf: ElfInfo) -> str | None:
    """The qemu-user program name for this ELF, or None if unsupported."""
    prog = _BY_ARCH.get((elf.machine, elf.endian))
    if prog is None:
        return None
    # RISC-V split by width (the table defaults to 64-bit).
    if elf.machine == "riscv" and elf.bits == 32:
        return "qemu-riscv32"
    return prog


def find_qemu(program: str) -> str | None:
    """Locate a qemu-user program, preferring the statically linked variant.

    Distributions ship either ``qemu-arm`` or ``qemu-arm-static`` (the latter is
    what qemu-user-static installs and what works inside a chroot/sandbox).
    """
    return shutil.which(f"{program}-static") or shutil.which(program)


def resolve(elf: ElfInfo) -> tuple[str | None, str | None]:
    """Return ``(program, path)``; ``path`` is None when the program isn't installed."""
    program = qemu_program(elf)
    if program is None:
        return None, None
    return program, find_qemu(program)
