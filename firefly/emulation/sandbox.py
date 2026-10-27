"""Confine an emulated binary so a hostile firmware process can't reach out.

qemu-user is not a security boundary, so the real confinement comes from here.
Two tiers, strongest first:

* **bwrap** (bubblewrap): a new mount/pid/ipc/uts/**network** namespace, only
  the system code directories bound read-only (never home directories or the
  secrets under ``/etc``), writable tmpfs for the working dirs, and the process
  dies with its parent. This blocks network egress, host writes, and reading of
  the operator's files.
* **rlimit-only**: no namespaces, just POSIX resource limits via a ``preexec``
  hook (CPU time, file size, process count, no core dumps). This is a fallback
  with no network or filesystem isolation.

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

DEFAULT_CPU_SECONDS = 30  # CPU time, independent of the wall-clock timeout
DEFAULT_FSIZE_BYTES = 64 * 1024**2  # largest file the binary may create

# Host directories bound read-only into the sandbox so a dynamically linked
# qemu-user (and the guest, via -L) can resolve its code. Deliberately omits
# /home, /root, /mnt, /media, /opt, /srv and the bulk of /etc, so an emulated
# binary cannot read the operator's files or secrets like /etc/shadow. Only the
# paths that actually exist on the host are bound.
_HOST_CODE_DIRS = (
    "/usr", "/lib", "/lib64", "/lib32", "/libx32", "/bin", "/sbin",
    # just enough of /etc for the dynamic loader, not the whole directory
    "/etc/ld.so.cache", "/etc/ld.so.conf", "/etc/ld.so.conf.d", "/etc/alternatives",
)


def host_ro_binds() -> list[str]:
    """The subset of :data:`_HOST_CODE_DIRS` present on this host."""
    return [p for p in _HOST_CODE_DIRS if os.path.exists(p)]


@dataclass
class SandboxPolicy:
    cpu_seconds: int = DEFAULT_CPU_SECONDS
    fsize_bytes: int = DEFAULT_FSIZE_BYTES
    require_isolation: bool = True  # refuse to run at all when no sandbox is available
    use_bwrap: bool = True  # False (via --no-emulate-sandbox) forces rlimit-only


def bwrap_available() -> bool:
    return shutil.which("bwrap") is not None


def detect_tier(policy: SandboxPolicy) -> tuple[str, str | None]:
    """Decide which sandbox tier to use.

    Returns ``(tier, refusal_reason)``. When ``refusal_reason`` is set the
    caller must not execute anything.
    """
    if policy.use_bwrap and bwrap_available():
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
        # NB: no RLIMIT_AS. qemu-user reserves a huge contiguous virtual address
        # space for the guest (~4 GiB for a 32-bit guest); an address-space cap
        # makes it fail to start ("Unable to reserve ... virtual address space")
        # rather than bound anything useful. Runaway memory in this degraded
        # tier is bounded by the wall-clock timeout; bubblewrap is the real
        # sandbox. We still cap CPU time, file size, process count and cores.
        resource.setrlimit(resource.RLIMIT_CPU, (policy.cpu_seconds, policy.cpu_seconds))
        resource.setrlimit(resource.RLIMIT_FSIZE, (policy.fsize_bytes, policy.fsize_bytes))
        resource.setrlimit(resource.RLIMIT_NPROC, (64, 64))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # no core dumps of firmware

    return apply


def _bwrap_prefix(rootfs: str, extra_ro: list[str], rw_binds: list[str], allow_network: bool) -> list[str]:
    """Build the ``bwrap ... --`` prefix that precedes the qemu command.

    Only the host's system-code directories are mounted read-only (so qemu and
    its libraries resolve) — never home directories or the secrets in ``/etc``.
    The scan root, the qemu binary and the shim are bound read-only explicitly
    (they may live outside those dirs, e.g. under the output directory), and
    ``/tmp``, ``/run`` and ``/var/tmp`` are fresh tmpfs so a firmware process
    has somewhere to write without touching the host. ``rw_binds`` are the only
    writable host paths (the shim's observation log), bound read-write so we can
    read events back afterwards.

    ``allow_network`` controls the network namespace. Phase A (user-mode) sets
    it False, so ``--unshare-all`` blocks all egress. Phase B (full-system)
    sets it True: qemu's user-mode (slirp) network needs the host namespace so
    forwarded ports are reachable, and slirp itself NATs the guest with no raw
    host access — so every namespace *except* net is still unshared.
    """
    cmd = ["bwrap"]
    if allow_network:
        cmd += ["--unshare-user-try", "--unshare-pid", "--unshare-ipc", "--unshare-uts", "--unshare-cgroup-try"]
    else:
        cmd += ["--unshare-all"]
    cmd += [
        "--die-with-parent",
        "--dev", "/dev",
        "--proc", "/proc",
        "--tmpfs", "/tmp",
        "--tmpfs", "/run",
        "--tmpfs", "/var/tmp",
    ]
    for path in host_ro_binds():
        cmd += ["--ro-bind", path, path]
    cmd += ["--ro-bind", rootfs, rootfs, "--chdir", rootfs]
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
    allow_network: bool = False,
):
    """Wrap ``inner`` (the qemu command) for the chosen tier.

    Returns ``(argv, preexec_fn)``. ``preexec_fn`` is None under bwrap (the
    namespace already constrains the process) and on non-POSIX hosts.
    ``allow_network`` keeps the host network namespace (Phase B slirp); it is
    ignored in the rlimit-only tier, which never had network isolation.
    """
    if tier == "bwrap":
        return _bwrap_prefix(rootfs, extra_ro or [], rw_binds or [], allow_network) + inner, None
    # rlimit-only
    return inner, _rlimits(policy)
