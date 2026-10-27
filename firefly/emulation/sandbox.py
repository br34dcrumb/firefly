"""Confine an emulated binary so a hostile firmware process can't reach out.

qemu-user is not a security boundary, so the real confinement comes from here.
Two tiers, strongest first:

* **bwrap** (bubblewrap): a new mount/pid/ipc/uts/**network** namespace, the
  host filesystem bound read-only, writable tmpfs for the working dirs, and the
  process dies with its parent. This blocks network egress and host writes.
* **rlimit-only**: no namespaces, just POSIX resource limits via a ``preexec``
  hook (CPU time, address space, file size, no new processes). This is a
  fallback with no network or filesystem isolation.

Firefly refuses to run emulation without bwrap unless the operator explicitly
opts out (``--no-emulate-sandbox``), because that means executing untrusted
code with host network and filesystem access.
"""

from __future__ import annotations

import os
import shutil
from dataclasses import dataclass

# POSIX-only; emulation never runs on Windows (qemu-user is Linux), but the
# module must still import there so the CLI help and tests work.
try:
    import resource
except ImportError:  # pragma: no cover - Windows
    resource = None  # type: ignore[assignment]

DEFAULT_MEM_BYTES = 2 * 1024**3  # 2 GiB address space
DEFAULT_CPU_SECONDS = 30  # CPU time, independent of the wall-clock timeout
DEFAULT_FSIZE_BYTES = 64 * 1024**2  # largest file the binary may create


@dataclass
class SandboxPolicy:
    mem_bytes: int = DEFAULT_MEM_BYTES
    cpu_seconds: int = DEFAULT_CPU_SECONDS
    fsize_bytes: int = DEFAULT_FSIZE_BYTES
    require_isolation: bool = True  # refuse rlimit-only unless explicitly allowed


def bwrap_available() -> bool:
    return shutil.which("bwrap") is not None


def detect_tier(policy: SandboxPolicy) -> tuple[str, str | None]:
    """Decide which sandbox tier to use.

    Returns ``(tier, refusal_reason)``. When ``refusal_reason`` is set the
    caller must not execute anything.
    """
    if bwrap_available():
        return "bwrap", None
    if policy.require_isolation:
        return "none", (
            "no sandbox available: install bubblewrap (bwrap) or run inside the "
            "Firefly Docker image. Pass --no-emulate-sandbox to run with resource "
            "limits only (executes untrusted code with host network/filesystem access)."
        )
    return "rlimit-only", None


def _rlimits(policy: SandboxPolicy):
    """A ``preexec_fn`` that caps resources in the child before exec."""
    if resource is None:  # pragma: no cover - Windows
        return None

    def apply() -> None:
        resource.setrlimit(resource.RLIMIT_AS, (policy.mem_bytes, policy.mem_bytes))
        resource.setrlimit(resource.RLIMIT_CPU, (policy.cpu_seconds, policy.cpu_seconds))
        resource.setrlimit(resource.RLIMIT_FSIZE, (policy.fsize_bytes, policy.fsize_bytes))
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # no core dumps of firmware

    return apply


def _bwrap_prefix(rootfs: str, extra_ro: list[str], rw_binds: list[str]) -> list[str]:
    """Build the ``bwrap ... --`` prefix that precedes the qemu command.

    The host filesystem is mounted read-only so qemu and its libraries resolve,
    the scan root is also read-only, and ``/tmp``, ``/var`` and ``/run`` are
    fresh tmpfs so a firmware process has somewhere to write without touching
    the host. ``--unshare-all`` includes the network namespace, so there is no
    egress. ``rw_binds`` are the only writable host paths (used for the shim's
    observation log), bound read-write so we can read events back afterwards.
    """
    cmd = [
        "bwrap",
        "--unshare-all",
        "--die-with-parent",
        "--ro-bind", "/", "/",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--tmpfs", "/run",
        "--tmpfs", "/var/tmp",
        "--ro-bind", rootfs, rootfs,
        "--chdir", rootfs,
    ]
    for path in extra_ro:
        cmd += ["--ro-bind", path, path]
    for path in rw_binds:
        cmd += ["--bind", path, path]
    cmd.append("--")
    return cmd


def build_command(
    tier: str,
    policy: SandboxPolicy,
    rootfs: str,
    inner: list[str],
    extra_ro: list[str] | None = None,
    rw_binds: list[str] | None = None,
):
    """Wrap ``inner`` (the qemu command) for the chosen tier.

    Returns ``(argv, preexec_fn)``. ``preexec_fn`` is None under bwrap (the
    namespace already constrains the process) and on non-POSIX hosts.
    """
    if tier == "bwrap":
        return _bwrap_prefix(rootfs, extra_ro or [], rw_binds or []) + inner, None
    # rlimit-only
    return inner, _rlimits(policy)
