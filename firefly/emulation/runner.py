"""Run a single firmware binary once under qemu-user, inside the sandbox.

This is the lowest layer of Phase A: given an extracted root filesystem and one
ELF inside it, launch it under the matching qemu-user program with the root
filesystem as the loader prefix, bounded by a wall-clock timeout and the
sandbox's resource limits, and report how it exited.
"""

from __future__ import annotations

import os
import signal
import subprocess
import time

from firefly.emulation.result import CRASH_SIGNALS, BinaryRun
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
        with open(log_path, "w"):  # type: ignore[arg-type]
            pass  # truncate any stale log before the run
        rw_binds.append(log_dir)
    qemu_cmd += [os.path.join(rootfs, rel_path), *args]

    argv, preexec = build_command(tier, policy, rootfs, qemu_cmd, extra_ro=extra_ro, rw_binds=rw_binds)

    start = time.perf_counter()
    try:
        # start_new_session puts the child in its own process group so that, on
        # timeout, we can kill the whole group — qemu plus anything the guest
        # forked (e.g. a daemon it spawned). Under bwrap the pid namespace
        # already contains those, but this also covers the rlimit-only tier.
        proc = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,  # never let a binary block waiting on input
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=rootfs,
            preexec_fn=preexec,  # type: ignore[arg-type]  # None on bwrap/Windows
            env={"PATH": "/bin:/sbin:/usr/bin:/usr/sbin", "HOME": "/tmp"},
            start_new_session=True,
        )
    except OSError as exc:
        run.error = f"could not launch: {exc}"
        run.duration_s = time.perf_counter() - start
        return run

    try:
        stdout, stderr = proc.communicate(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        _kill_group(proc)
        stdout, stderr = proc.communicate()
        run.timed_out = True

    run.duration_s = time.perf_counter() - start
    run.stdout_tail = _tail(stdout or b"")
    run.stderr_tail = _tail(stderr or b"")
    if not run.timed_out:
        run.term_signal, run.returncode = _classify_exit(proc.returncode)
    if use_shim:
        _read_shim_log(log_path, run)  # type: ignore[arg-type]
    return run


def _kill_group(proc: subprocess.Popen) -> None:
    """Kill the child's whole process group, falling back to the child alone."""
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, AttributeError, OSError):
        try:
            proc.kill()
        except OSError:
            pass


def _classify_exit(returncode: int | None) -> tuple[int | None, int | None]:
    """Split a subprocess return code into ``(term_signal, returncode)``.

    Two cases both mean "killed by signal N":
      * ``returncode < 0`` — the direct child (qemu, no sandbox) was killed by
        signal ``-returncode``;
      * ``returncode >= 128`` where ``returncode - 128`` is a crash signal — an
        intermediate parent (bubblewrap) reaped the crashed qemu and re-exited
        with the shell's ``128 + signal`` convention, masking the signal. We
        only remap codes whose ``- 128`` is a known crash signal, so an ordinary
        high exit status (e.g. 129) is still reported as a return code.
    """
    if returncode is None:
        return None, None
    if returncode < 0:
        return -returncode, None
    if returncode >= 128 and (returncode - 128) in CRASH_SIGNALS:
        return returncode - 128, None
    return None, returncode


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
