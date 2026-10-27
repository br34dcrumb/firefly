"""Phase A emulation stage: pick binaries, run each under qemu-user, collect.

This is the opt-in dynamic stage. It is deliberately *not* a
:class:`~firefly.analyzers.Analyzer` (those are contractually static): the
pipeline calls it only when ``--emulate`` is given, and it converts its own
:class:`~firefly.emulation.result.EmulationResult` into findings.
"""

from __future__ import annotations

import logging
import os
import re
import sys
from dataclasses import dataclass

from firefly.emulation import qemu, shimbuild
from firefly.emulation.result import EmulationResult
from firefly.emulation.runner import run_binary
from firefly.emulation.sandbox import SandboxPolicy, detect_tier
from firefly.inventory import Inventory
from firefly.models import FileKind, FileRecord

log = logging.getLogger(__name__)

# Binary basenames that are worth emulating first: network-facing services and
# the usual firmware shells where command-injection bugs cluster.
PRIORITY_NAMES = (
    "httpd", "telnetd", "utelnetd", "dropbear", "sshd", "upnpd", "miniupnpd",
    "lighttpd", "goahead", "boa", "uhttpd", "dnsmasq", "ftpd", "vsftpd",
    "cgibin", "cgi-bin",
)

# Shared objects are ET_DYN too, so is_executable_code() can't tell them from
# PIE programs. Firmware ships hundreds of libraries that are not meant to be
# executed on their own (running one just errors), so exclude anything whose
# name looks like a shared object: ``libc.so.6``, ``ld-linux.so.3``, ``foo.so``.
_SHARED_OBJECT = re.compile(r"\.so(\.\d+)*$")


@dataclass
class EmulationOptions:
    enabled: bool = False
    timeout_s: float = 20.0
    max_binaries: int = 64
    require_sandbox: bool = True  # False == --no-emulate-sandbox
    args: tuple[str, ...] = ()
    build_shim: bool = False  # cross-compile the interception shim if a toolchain exists
    workdir: str | None = None  # where built shims are written


def _priority(rec: FileRecord) -> int:
    base = os.path.basename(rec.path).lower()
    return 0 if any(name in base for name in PRIORITY_NAMES) else 1


def _is_program(rec: FileRecord) -> bool:
    return bool(rec.is_executable_code and rec.elf) and not _SHARED_OBJECT.search(os.path.basename(rec.path))


def select_binaries(inv: Inventory, limit: int) -> list[FileRecord]:
    """Executable ELF programs (not shared libraries), priority services first."""
    elves = [r for r in inv.of_kind(FileKind.ELF) if _is_program(r)]
    elves.sort(key=lambda r: (_priority(r), r.path))
    return elves[:limit]


def run_emulation(rootfs: str, inv: Inventory, options: EmulationOptions) -> EmulationResult:
    """Run the emulation stage against an extracted root filesystem."""
    if not sys.platform.startswith("linux"):
        return EmulationResult(available=False, reason="emulation requires Linux (qemu-user)")

    # --no-emulate-sandbox (require_sandbox=False) both allows running without a
    # sandbox and forces the rlimit-only tier instead of bubblewrap.
    policy = SandboxPolicy(require_isolation=options.require_sandbox, use_bwrap=options.require_sandbox)
    tier, refusal = detect_tier(policy)
    if refusal:
        return EmulationResult(available=False, reason=refusal)

    candidates = select_binaries(inv, options.max_binaries)
    result = EmulationResult(available=True, sandbox=tier, candidates=len(candidates))

    shims: dict[tuple[str, str], str | None] = {}  # (machine, endian) -> shim path or None

    def shim_for(machine: str, endian: str) -> str | None:
        if not options.build_shim or options.workdir is None:
            return None
        key = (machine, endian)
        if key not in shims:
            shims[key] = shimbuild.build_for(machine, endian, os.path.join(options.workdir, "shims"))
        return shims[key]

    for i, rec in enumerate(candidates):
        assert rec.elf is not None
        program, qemu_path = qemu.resolve(rec.elf)
        if program is None:
            result.skipped += 1
            log.debug("no qemu mapping for %s (%s)", rec.path, rec.elf.machine)
            continue
        if qemu_path is None:
            result.skipped += 1
            log.debug("qemu program %s not installed for %s", program, rec.path)
            continue
        result.qemu_found[rec.elf.machine] = qemu_path
        shim_path = shim_for(rec.elf.machine, rec.elf.endian)
        log_path = (
            os.path.join(options.workdir, "shim-logs", f"{i:04d}.log")
            if shim_path and options.workdir
            else None
        )
        run = run_binary(
            rootfs,
            rec.path,
            rec.elf,
            qemu_path,
            tier=tier,
            policy=policy,
            args=list(options.args),
            timeout_s=options.timeout_s,
            shim_path=shim_path,
            log_path=log_path,
        )
        result.runs.append(run)

    if candidates and not result.qemu_found:
        archs = sorted({r.elf.machine for r in candidates if r.elf})
        result.reason = f"no qemu-user program installed for the image's architecture(s): {', '.join(archs)}"
    return result
