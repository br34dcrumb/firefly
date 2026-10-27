"""Tests for Phase B full-system emulation.

Like the Phase A tests, these never launch qemu-system or bwrap: the mapping,
kernel discovery, command construction, console classification and finding
conversion are exercised directly, and the one boot function is faked. They
pass on any OS without qemu-system installed.
"""

from __future__ import annotations

import firefly.emulation.system as system
from firefly.emulation.system import (
    SystemBootResult,
    SystemOptions,
    build_qemu_command,
    classify_console,
    default_machine,
    find_kernel,
    qemu_system_program,
    run_system,
)
from firefly.extract import ExtractionResult
from firefly.inventory import Inventory
from firefly.models import Severity

from elfbuild import ET_EXEC, build_elf

# --------------------------------------------------------------------------- mapping


def test_qemu_system_program_and_default_machine():
    assert qemu_system_program("mips", "big") == "qemu-system-mips"
    assert qemu_system_program("mips", "little") == "qemu-system-mipsel"
    assert qemu_system_program("arm", "little") == "qemu-system-arm"
    assert qemu_system_program("sparc", "big") is None
    assert default_machine("mips", "little") == "malta"  # mipsel still boots on malta
    assert default_machine("arm", "little") == "virt"


# --------------------------------------------------------------------------- kernel discovery


def test_find_kernel_prefers_vmlinux_and_skips_stubs(tmp_path):
    (tmp_path / "boot").mkdir()
    (tmp_path / "boot" / "vmlinux").write_bytes(b"\x00" * 200_000)
    (tmp_path / "boot" / "uImage").write_bytes(b"\x00" * 500_000)
    (tmp_path / "etc").mkdir()
    (tmp_path / "etc" / "vmlinuz.conf").write_bytes(b"tiny")  # too small, skipped
    found = find_kernel(str(tmp_path))
    assert found is not None and found.endswith("vmlinux")  # name rank beats size


def test_find_kernel_none_when_absent(tmp_path):
    (tmp_path / "readme.txt").write_bytes(b"x" * 200_000)
    assert find_kernel(str(tmp_path)) is None


# --------------------------------------------------------------------------- command build


def test_build_qemu_command_has_kernel_net_and_drive():
    cmd = build_qemu_command("/usr/bin/qemu-system-arm", "virt", "/k/vmlinux", "/img.ext2", "virtio-net-device", "console=ttyS0 root=/dev/sda rw", [23, 80], dtb="/d.dtb")
    assert "-kernel" in cmd and "/k/vmlinux" in cmd
    assert cmd[cmd.index("-M") + 1] == "virt"
    netdev = cmd[cmd.index("-netdev") + 1]
    assert "hostfwd=tcp:127.0.0.1:45023-:23" in netdev and "hostfwd=tcp:127.0.0.1:45080-:80" in netdev
    assert "-dtb" in cmd and "/d.dtb" in cmd
    assert any(a.startswith("file=/img.ext2") for a in cmd)


def test_build_qemu_command_without_image_omits_drive():
    cmd = build_qemu_command("/q", "malta", "/vmlinux", None, "pcnet", "console=ttyS0", [80])
    assert "-drive" not in cmd


# --------------------------------------------------------------------------- console classification


def test_classify_console_detects_panic():
    booted, reason = classify_console("... Kernel panic - not syncing ...")
    assert booted is False and "panic" in reason.lower()


def test_classify_console_detects_login():
    booted, reason = classify_console("init done\nmydevice login:")
    assert booted is True and "login" in reason


def test_classify_console_panic_wins_over_login():
    # Failure markers take priority even if a prompt scrolled past earlier.
    assert classify_console("login:\n...\nKernel panic")[0] is False


def test_classify_console_silent_is_failure():
    booted, reason = classify_console("")
    assert booted is False and "no boot markers" in reason


# --------------------------------------------------------------------------- findings


def test_findings_boot_and_services():
    res = SystemBootResult(available=True, qemu="qemu-system-mipsel", machine="malta", booted=True, boot_reason="reached 'login:'", open_ports=[23, 22])
    findings = res.to_findings()
    titles = [f.title for f in findings]
    assert any("booted under full-system emulation" in t for t in titles)
    telnet = next(f for f in findings if "telnet" in f.title)
    ssh = next(f for f in findings if "ssh" in f.title)
    assert telnet.severity is Severity.MEDIUM  # cleartext service
    assert ssh.severity is Severity.LOW


def test_no_findings_when_not_booted_and_no_ports():
    assert SystemBootResult(available=True, booted=False).to_findings() == []


# --------------------------------------------------------------------------- port probing


def test_probe_ports_distinguishes_listening():
    import socket

    # A silent listener (never accepts) stands in for a service that holds the
    # connection open; a free port stands in for a refused connection. This is
    # exactly what separates a real service from slirp's accept-everything.
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listener.bind(("127.0.0.1", system._host_port(7547)))
    listener.listen(1)
    try:
        found = system._probe_ports([7547, 9000], connect_timeout=1.0, read_timeout=0.3)
    finally:
        listener.close()
    assert 7547 in found      # listening (silent) -> detected
    assert 9000 not in found  # nothing there -> refused


# --------------------------------------------------------------------------- orchestration


def _arm_inv(tmp_path):
    root = tmp_path / "root"
    for rel in ("bin/busybox", "sbin/init"):
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(build_elf(etype=ET_EXEC))
    return Inventory.build(str(root))


def _extraction(tmp_path):
    root = str(tmp_path / "root")
    return ExtractionResult(str(tmp_path), "firmware", "unblob", str(tmp_path), root)


def test_run_system_requires_linux(tmp_path, monkeypatch):
    monkeypatch.setattr(system.sys, "platform", "win32")
    res = run_system(_extraction(tmp_path), _arm_inv(tmp_path), SystemOptions())
    assert res.available is False and "Linux" in res.reason


def test_run_system_reports_missing_kernel(tmp_path, monkeypatch):
    monkeypatch.setattr(system.sys, "platform", "linux")
    monkeypatch.setattr(system, "detect_tier", lambda policy: ("bwrap", None))
    monkeypatch.setattr(system, "find_qemu_system", lambda prog: "/usr/bin/" + prog)
    monkeypatch.setattr(system, "find_kernel", lambda root: None)
    res = run_system(_extraction(tmp_path), _arm_inv(tmp_path), SystemOptions())
    assert res.available is False and "no kernel" in res.reason


def test_run_system_all_ports_open_is_discarded(tmp_path, monkeypatch):
    # If every forwarded port looks open, the guest was unreachable (slirp
    # accepted but had nothing to connect to) -> discard as false positives.
    monkeypatch.setattr(system.sys, "platform", "linux")
    monkeypatch.setattr(system, "detect_tier", lambda policy: ("bwrap", None))
    monkeypatch.setattr(system, "find_qemu_system", lambda prog: "/usr/bin/" + prog)
    monkeypatch.setattr(system, "find_kernel", lambda root: "/boot/vmlinux")
    monkeypatch.setattr(system, "build_ext2_image", lambda rootfs, out, size_mb=256: None)
    monkeypatch.setattr(system, "_boot", lambda argv, pre, cwd, ports, opts: ("mydev login:", list(system.COMMON_PORTS)))

    res = run_system(_extraction(tmp_path), _arm_inv(tmp_path), SystemOptions())
    assert res.open_ports == []          # all-open rejected
    assert res.booted is True            # console marker still shows it booted
    assert not any("reachable" in f.title for f in res.to_findings())


def test_run_system_boots_and_probes(tmp_path, monkeypatch):
    monkeypatch.setattr(system.sys, "platform", "linux")
    monkeypatch.setattr(system, "detect_tier", lambda policy: ("bwrap", None))
    monkeypatch.setattr(system, "find_qemu_system", lambda prog: "/usr/bin/" + prog)
    monkeypatch.setattr(system, "find_kernel", lambda root: "/boot/vmlinux")
    monkeypatch.setattr(system, "build_ext2_image", lambda rootfs, out, size_mb=256: None)
    monkeypatch.setattr(system, "_boot", lambda argv, preexec, cwd, ports, opts: ("mydev login:", [23, 80]))

    res = run_system(_extraction(tmp_path), _arm_inv(tmp_path), SystemOptions(require_sandbox=True))
    assert res.available and res.booted
    assert res.qemu == "qemu-system-arm" and res.machine == "virt"
    assert res.open_ports == [23, 80]
    sev = {f.title: f.severity for f in res.to_findings()}
    assert any("booted" in t for t in sev)
    assert any("telnet" in t for t in sev)
