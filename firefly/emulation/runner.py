"""Run a single firmware binary once under qemu-user, inside the sandbox.

This is the lowest layer of Phase A: given an extracted root filesystem and one
ELF inside it, launch it under the matching qemu-user program with the root
filesystem as the loader prefix, bounded by a wall-clock timeout and the
sandbox's resource limits, and report how it exited.
"""

from __future__ import annotations

import os
import subprocess
import time

from firefly.emulation.result import BinaryRun
from firefly.emulation.sandbox import SandboxPolicy, build_command
from firefly.models import ElfInfo

MAX_OUTPUT = 16 * 1024  # bytes of stdout/stderr kept per run


def _tail(data: bytes, limit: int = MAX_OUTPUT) -> str:
    if len(data) > limit:
        data = data[-limit:]
    return data.decode("utf-8", "replace")


def run_binary(
    rootfs: str,
    rel_path: str,
    elf: ElfInfo,
    qemu_path: str,
    *,
    tier: str,
    policy: SandboxPolicy,
    args: list[str] | None = None,
    timeout_s: float = 20.0,
    shim_path: str | None = None,
    log_path: str | None = None,
) -> BinaryRun:
    """Execute ``rootfs/rel_path`` under qemu-user and return the outcome."""
    args = list(args or [])
    run = BinaryRun(path=rel_path, arch=elf.machine, qemu=os.path.basename(qemu_path), args=args)

    qemu_cmd = [qemu_path, "-L", rootfs]
    extra_ro = [qemu_path]
    rw_binds: list[str] = []
    use_shim = bool(shim_path and os.path.exists(shim_path) and log_path)
    if use_shim:
        # qemu-user injects guest environment with -E; LD_PRELOAD loads the
        # interception shim and FIREFLY_SHIM_LOG tells it where to record events.
        qemu_cmd += ["-E", f"LD_PRELOAD={shim_path}", "-E", f"FIREFLY_SHIM_LOG={log_path}"]
        extra_ro.append(shim_path)  # type: ignore[arg-type]
        log_dir = os.path.dirname(log_path)  # type: ignore[arg-type]
        os.makedirs(log_dir, exist_ok=True)
        open(log_path, "w").close()  # type: ignore[arg-type]
        rw_binds.append(log_dir)
    qemu_cmd += [os.path.join(rootfs, rel_path), *args]

    argv, preexec = build_command(tier, policy, rootfs, qemu_cmd, extra_ro=extra_ro, rw_binds=rw_binds)

    start = time.perf_counter()
    try:
        proc = subprocess.run(
            argv,
            stdin=subprocess.DEVNULL,  # never let a binary block waiting on input
            capture_output=True,
            timeout=timeout_s,
            cwd=rootfs,
            preexec_fn=preexec,  # type: ignore[arg-type]  # None on bwrap/Windows
            env={"PATH": "/bin:/sbin:/usr/bin:/usr/sbin", "HOME": "/tmp"},
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        run.timed_out = True
        run.duration_s = time.perf_counter() - start
        run.stdout_tail = _tail(exc.stdout or b"")
        run.stderr_tail = _tail(exc.stderr or b"")
        if use_shim:
            _read_shim_log(log_path, run)  # type: ignore[arg-type]
        return run
    except OSError as exc:
        run.error = f"could not launch: {exc}"
        run.duration_s = time.perf_counter() - start
        return run

    run.duration_s = time.perf_counter() - start
    run.stdout_tail = _tail(proc.stdout)
    run.stderr_tail = _tail(proc.stderr)
    # POSIX: a negative returncode is -signal.
    if proc.returncode is not None and proc.returncode < 0:
        run.term_signal = -proc.returncode
    else:
        run.returncode = proc.returncode
    if use_shim:
        _read_shim_log(log_path, run)  # type: ignore[arg-type]
    return run


def _read_shim_log(log_path: str, run: BinaryRun) -> None:
    """Fold the shim's observation log into the run (deduped, bounded)."""
    try:
        with open(log_path, encoding="utf-8", errors="replace") as fh:
            lines = fh.read().splitlines()
    except OSError:
        return
    cmds: list[str] = []
    opened: list[str] = []
    for line in lines:
        kind, _, value = line.partition("\t")
        if not value:
            continue
        if kind in ("CMD", "EXEC") and value not in cmds:
            cmds.append(value)
        elif kind == "OPEN" and value not in opened:
            opened.append(value)
    run.commands = cmds[:100]
    run.opened_paths = opened[:200]
