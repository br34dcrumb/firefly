"""Phase B: full-system emulation (``qemu-system``, FirmAE / firmadyne style).

Where Phase A (:mod:`firefly.emulation.stage`) runs one binary under qemu-user,
Phase B boots the *whole device*: a kernel plus the extracted root filesystem
under ``qemu-system``, with user-mode (slirp) networking so exposed services
become reachable and can be probed. From a booted device the later phases
(live surface crawl, auth testing, fuzzing) become possible.

Honest scope: booting arbitrary firmware is the hard, research-grade part of
this field — even FirmAE only boots ~60-80% of router images, using a stable of
hand-picked kernels and machine quirks. This module provides the orchestration,
sane per-architecture defaults, and override flags (kernel / machine / dtb /
nic / append / image); real images frequently need tuning via those overrides.
A failed boot is reported as a result, never an error.

Safety: the whole qemu-system process runs inside the Phase B sandbox
(bubblewrap with the host filesystem hidden, see :mod:`firefly.emulation.sandbox`).
Unlike Phase A the network namespace is kept, because slirp needs it — but
slirp only NATs the guest, giving it no raw access to the host network, and we
forward just a fixed set of ports to probe.
"""

from __future__ import annotations

import logging
import os
import shutil
import socket
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from typing import Any

from firefly.emulation.runner import _kill_group
from firefly.emulation.sandbox import SandboxPolicy, build_command, detect_tier
from firefly.extract import ExtractionResult
from firefly.inventory import Inventory
from firefly.models import Finding, Severity

log = logging.getLogger(__name__)

# (machine, endian) -> qemu-system program.
_SYSTEM_QEMU: dict[tuple[str, str], str] = {
    ("arm", "little"): "qemu-system-arm",
    ("aarch64", "little"): "qemu-system-aarch64",
    ("mips", "big"): "qemu-system-mips",
    ("mips", "little"): "qemu-system-mipsel",
    ("x86", "little"): "qemu-system-i386",
    ("x86_64", "little"): "qemu-system-x86_64",
    ("ppc", "big"): "qemu-system-ppc",
    ("riscv", "little"): "qemu-system-riscv64",
}

# Reasonable default -M machine per architecture. MIPS firmware is almost always
# emulated on "malta" (what firmadyne/FirmAE use); ARM/riscv default to the
# generic "virt". Vendor kernels often need a different board — hence the
# --system-machine override.
_DEFAULT_MACHINE = {
    "arm": "virt", "aarch64": "virt", "mips": "malta", "mipsel": "malta",
    "x86": "pc", "x86_64": "pc", "ppc": "g3beige", "riscv": "virt",
}
# Default NIC model per machine (slirp attaches to it).
_DEFAULT_NIC = {
    "virt": "virtio-net-device", "malta": "pcnet", "pc": "e1000",
    "g3beige": "ne2k_pci",
}

# Kernel images commonly shipped inside firmware, in rough order of preference.
_KERNEL_NAMES = ("vmlinux", "vmlinuz", "bzImage", "zImage", "uImage")

# Guest ports we forward and probe, with the service each implies.
COMMON_PORTS = {
    21: "ftp", 22: "ssh", 23: "telnet", 53: "dns", 80: "http", 443: "https",
    1900: "upnp", 7547: "tr069", 8080: "http-alt", 8443: "https-alt", 9000: "http-admin",
}
_HOST_PORT_BASE = 45000  # host side of each forward: base + guest port

# Serial-console markers. Order matters: a panic seen anywhere means failure
# even if a login prompt scrolled past earlier.
_BOOT_FAIL = (
    "Kernel panic",
    "VFS: Unable to mount root",
    "VFS: Cannot open root device",
    "No filesystem could mount root",
    "Attempted to kill init",
)
_BOOT_OK = (
    "login:",
    "Please press Enter to activate",
    "init started",
    "Starting kernel",  # weak, but a sign we at least left the loader
    "BusyBox v",
    "Welcome to",
)

MAX_CONSOLE = 256 * 1024  # bytes of serial console kept


@dataclass
class SystemOptions:
    timeout_s: float = 90.0
    service_grace_s: float = 6.0  # after a boot marker, wait this long for services to bind
    require_sandbox: bool = True
    kernel: str | None = None
    machine: str | None = None
    dtb: str | None = None
    nic: str | None = None
    append: str | None = None
    image: str | None = None  # prebuilt root disk image; else we try to build one
    initrd: str | None = None  # initramfs to boot (bypasses needing a disk driver)
    workdir: str | None = None


@dataclass
class SystemBootResult:
    available: bool
    reason: str = ""
    qemu: str = ""
    machine: str = ""
    kernel: str | None = None
    booted: bool = False
    boot_reason: str = ""
    console_tail: str = ""
    open_ports: list[int] = field(default_factory=list)  # guest ports found open

    def to_artifact(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "reason": self.reason,
            "qemu": self.qemu,
            "machine": self.machine,
            "kernel": self.kernel,
            "booted": self.booted,
            "boot_reason": self.boot_reason,
            "open_ports": [{"port": p, "service": COMMON_PORTS.get(p, "unknown")} for p in self.open_ports],
            "console_tail": self.console_tail[-4000:],
        }

    def to_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        if self.booted:
            findings.append(
                Finding(
                    analyzer="emulation",
                    title="Firmware booted under full-system emulation",
                    severity=Severity.INFO,
                    confidence="medium",
                    description=(
                        f"The image booted under {self.qemu} (-M {self.machine}): {self.boot_reason}. "
                        "A live device enables dynamic testing of its services."
                    ),
                    metadata={"machine": self.machine, "open_ports": self.open_ports},
                )
            )
        for port in self.open_ports:
            service = COMMON_PORTS.get(port, "unknown")
            cleartext = service in ("telnet", "ftp", "http", "upnp", "tr069", "http-alt", "http-admin")
            findings.append(
                Finding(
                    analyzer="emulation",
                    title=f"Service reachable on the running device: {service} (port {port})",
                    severity=Severity.MEDIUM if cleartext else Severity.LOW,
                    confidence="medium",
                    evidence=f"{service}/{port} answered a TCP connection on the emulated device",
                    description=(
                        f"The booted device accepted a connection on port {port} ({service}). "
                        + ("This is a cleartext/administrative service — a prime attack surface. "
                           if cleartext else "")
                        + "Confirm on real hardware and review its authentication."
                    ),
                    metadata={"port": port, "service": service},
                )
            )
        return findings


def qemu_system_program(machine: str, endian: str) -> str | None:
    return _SYSTEM_QEMU.get((machine, endian))


def find_qemu_system(program: str) -> str | None:
    return shutil.which(program)


def default_machine(machine: str, endian: str) -> str:
    key = "mipsel" if machine == "mips" and endian == "little" else machine
    return _DEFAULT_MACHINE.get(key, "virt")


def find_kernel(search_root: str) -> str | None:
    """Return the most likely kernel image under ``search_root``, if any."""
    best: tuple[int, int, str] | None = None  # (name rank, -size, path)
    for dirpath, _dirs, files in os.walk(search_root):
        for name in files:
            low = name.lower()
            rank = next((i for i, k in enumerate(_KERNEL_NAMES) if k.lower() in low), None)
            if rank is None:
                continue
            path = os.path.join(dirpath, name)
            try:
                size = os.path.getsize(path)
            except OSError:
                continue
            if size < 100 * 1024:  # a real kernel is not tiny; skip stubs/configs
                continue
            cand = (rank, -size, path)
            if best is None or cand < best:
                best = cand
    return best[2] if best else None


def build_ext2_image(rootfs: str, out_path: str, size_mb: int = 256) -> str | None:
    """Pack ``rootfs`` into a raw ext2 image using ``mke2fs -d`` (best effort).

    Returns the image path, or None when e2fsprogs is unavailable or the build
    fails — the caller then reports that a prebuilt ``--system-image`` is needed.
    """
    mke2fs = shutil.which("mke2fs")
    if not mke2fs:
        return None
    try:
        with open(out_path, "wb") as fh:
            fh.truncate(size_mb * 1024 * 1024)
        proc = subprocess.run(
            [mke2fs, "-F", "-q", "-t", "ext2", "-d", rootfs, out_path],
            capture_output=True, text=True, timeout=300, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.debug("mke2fs failed: %s", exc)
        return None
    if proc.returncode != 0:
        log.debug("mke2fs exit %d: %s", proc.returncode, proc.stderr.strip())
        return None
    return out_path


def classify_console(text: str) -> tuple[bool, str]:
    """Decide boot success from serial-console text. (booted, reason)."""
    for marker in _BOOT_FAIL:
        if marker in text:
            return False, f"boot failed: saw {marker!r} on the console"
    for marker in _BOOT_OK:
        if marker in text:
            return True, f"reached {marker!r} on the console"
    return False, "no boot markers seen before the timeout (kernel/machine likely need tuning)"


def _host_port(guest_port: int) -> int:
    return _HOST_PORT_BASE + guest_port


def _probe_ports(guest_ports: list[int], connect_timeout: float = 2.0, read_timeout: float = 1.0) -> list[int]:
    """Return guest ports that are actually listening on the booted device.

    A bare ``connect()`` is not enough: qemu's slirp accepts the host-side
    connection *before* it checks the guest, so every forwarded port looks open.
    We therefore look at what happens next — if the guest has nothing listening,
    slirp closes the connection (a clean EOF or reset); if a service is there it
    either sends a banner or holds the connection open:

      * recv returns data        -> open (banner, e.g. telnet/ftp/ssh)
      * recv times out           -> open (listening but silent, e.g. http)
      * recv returns b"" / reset -> closed (slirp gave up on the guest)
    """
    open_ports: list[int] = []
    for gp in guest_ports:
        try:
            s = socket.create_connection(("127.0.0.1", _host_port(gp)), timeout=connect_timeout)
        except OSError:
            continue
        try:
            s.settimeout(read_timeout)
            if s.recv(64):
                open_ports.append(gp)  # banner -> listening
        except socket.timeout:
            open_ports.append(gp)      # silent but holding the connection -> listening
        except OSError:
            pass                       # reset -> nothing on the guest port
        finally:
            s.close()
    return open_ports


def _hostfwd_args(guest_ports: list[int]) -> str:
    fwds = "".join(f",hostfwd=tcp:127.0.0.1:{_host_port(gp)}-:{gp}" for gp in guest_ports)
    return "user,id=net0" + fwds


def build_qemu_command(qemu_path: str, machine: str, kernel: str, image: str | None, nic: str, append: str, guest_ports: list[int], dtb: str | None = None, initrd: str | None = None) -> list[str]:
    """Assemble the qemu-system argv (without the sandbox prefix)."""
    cmd = [
        qemu_path,
        # Explicit serial->stdout, no display, no monitor. (-nographic muxes the
        # serial and monitor onto stdio and ties them to stdin; with stdin set to
        # /dev/null that EOF suppresses the serial console.)
        "-display", "none", "-serial", "stdio", "-monitor", "none", "-no-reboot",
        "-M", machine, "-m", "256",
        "-kernel", kernel,
        "-append", append,
        "-netdev", _hostfwd_args(guest_ports),
        "-device", f"{nic},netdev=net0",
    ]
    if dtb:
        cmd += ["-dtb", dtb]
    if initrd:
        cmd += ["-initrd", initrd]
    if image:
        cmd += ["-drive", f"file={image},format=raw,if=ide"]
    return cmd


def run_system(extraction: ExtractionResult, inv: Inventory, options: SystemOptions) -> SystemBootResult:
    """Attempt a full-system boot of the extracted firmware and probe services."""
    if not sys.platform.startswith("linux"):
        return SystemBootResult(available=False, reason="full-system emulation requires Linux (qemu-system)")

    # Architecture comes from the dominant executable in the image.
    arch = _dominant_arch(inv)
    if arch is None:
        return SystemBootResult(available=False, reason="could not determine the image's architecture")
    machine_name, endian = arch
    program = qemu_system_program(machine_name, endian)
    if program is None:
        return SystemBootResult(available=False, reason=f"no qemu-system mapping for {machine_name}/{endian}")
    qemu_path = find_qemu_system(program)
    if qemu_path is None:
        return SystemBootResult(available=False, reason=f"{program} is not installed")

    policy = SandboxPolicy(require_isolation=options.require_sandbox, use_bwrap=options.require_sandbox)
    tier, refusal = detect_tier(policy)
    if refusal:
        return SystemBootResult(available=False, reason=refusal)

    kernel = options.kernel or find_kernel(extraction.extract_dir)
    if not kernel:
        return SystemBootResult(
            available=False,
            reason="no kernel found in the image; supply one with --system-kernel",
            qemu=os.path.basename(qemu_path),
        )

    machine = options.machine or default_machine(machine_name, endian)
    nic = options.nic or _DEFAULT_NIC.get(machine, "e1000")
    initrd = options.initrd
    # Only build a disk image when there's no initramfs to boot from.
    image = options.image
    if image is None and initrd is None and options.workdir:
        image = build_ext2_image(extraction.scan_root, os.path.join(options.workdir, "rootfs.ext2"))
    if options.append:
        append = options.append
    elif image:
        append = "console=ttyS0 root=/dev/sda rw"
    else:  # initramfs (or last-resort) boot: the kernel runs /init itself
        append = "console=ttyS0"
    guest_ports = sorted(COMMON_PORTS)

    result = SystemBootResult(
        available=True, qemu=os.path.basename(qemu_path), machine=machine, kernel=kernel,
    )
    qemu_cmd = build_qemu_command(qemu_path, machine, kernel, image, nic, append, guest_ports, dtb=options.dtb, initrd=initrd)
    extra_ro = [qemu_path, kernel] + ([image] if image else []) + ([options.dtb] if options.dtb else []) + ([initrd] if initrd else [])
    argv, preexec = build_command(
        tier, policy, extraction.scan_root, qemu_cmd, extra_ro=extra_ro, allow_network=True,
    )

    console, open_ports = _boot(argv, preexec, extraction.scan_root, guest_ports, options)
    result.console_tail = console
    # If *every* forwarded port looks open, the guest never became reachable
    # (slirp accepts the host side but has no guest to connect to, so each probe
    # just times out). A real device does not listen on all of these, so treat
    # this as "no services reliably detected" rather than a wall of false hits.
    if len(open_ports) >= len(guest_ports):
        open_ports = []
    result.open_ports = open_ports
    result.booted, result.boot_reason = classify_console(console)
    # Services answering is itself strong evidence the device is up.
    if open_ports and not result.booted:
        result.booted, result.boot_reason = True, "services responded on forwarded ports"
    return result


def _boot(argv: list[str], preexec, cwd: str, guest_ports: list[int], options: SystemOptions) -> tuple[str, list[int]]:
    """Run qemu-system, capture serial, probe ports after it settles, then stop."""
    buf = bytearray()
    try:
        proc = subprocess.Popen(
            argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
            cwd=cwd, preexec_fn=preexec, start_new_session=True,
            env={"PATH": "/bin:/sbin:/usr/bin:/usr/sbin", "HOME": "/tmp"},
        )
    except OSError as exc:
        return f"could not launch qemu-system: {exc}", []

    def reader() -> None:
        assert proc.stdout is not None
        # read1() returns whatever is available instead of blocking for a full
        # fixed-size chunk, so a short trailing line (e.g. the "login:" marker,
        # after which the guest goes quiet) is seen promptly rather than only on
        # EOF. buf.extend (not buf += ...) keeps buf the enclosing bytearray; an
        # augmented assignment would make it local and raise UnboundLocalError.
        for chunk in iter(lambda: proc.stdout.read1(65536), b""):
            if len(buf) < MAX_CONSOLE:
                buf.extend(chunk)

    t = threading.Thread(target=reader, daemon=True)
    t.start()

    # Probe exactly once, when the device is settled. Probing early is wrong:
    # before the guest's network is up, slirp accepts the host connection and
    # sits waiting on an unreachable guest, which the recv heuristic reads as a
    # silent-but-open service — a false positive on every forwarded port. So we
    # wait for a boot marker on the console (then a short grace for services to
    # bind), or for the process to exit / the timeout, and probe just once.
    start = time.monotonic()
    while time.monotonic() - start < options.timeout_s:
        if proc.poll() is not None:
            break
        text = bytes(buf).decode("utf-8", "replace")
        booted, _ = classify_console(text)
        if booted:
            remaining = options.timeout_s - (time.monotonic() - start)
            time.sleep(max(0.0, min(options.service_grace_s, remaining)))
            break
        if any(marker in text for marker in _BOOT_FAIL):
            break
        time.sleep(1.0)

    open_ports = _probe_ports(guest_ports)
    _kill_group(proc)
    t.join(timeout=2.0)
    return bytes(buf).decode("utf-8", "replace"), open_ports


def _dominant_arch(inv: Inventory) -> tuple[str, str] | None:
    """Pick the architecture/endianness most ELF executables in the image use."""
    from collections import Counter

    from firefly.models import FileKind

    counts: Counter[tuple[str, str]] = Counter()
    for rec in inv.of_kind(FileKind.ELF):
        if rec.elf:
            counts[(rec.elf.machine, rec.elf.endian)] += 1
    if not counts:
        return None
    return counts.most_common(1)[0][0]
