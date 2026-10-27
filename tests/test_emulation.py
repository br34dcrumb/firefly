"""Tests for the Phase A emulation stage.

These never launch qemu or bwrap: the architecture mapping, candidate
selection, sandbox decision, and finding conversion are all exercised directly,
and the one stage test fakes the runner. So they pass on any OS and on CI
without qemu-user or bubblewrap installed.
"""

from __future__ import annotations

import firefly.emulation.stage as stage
from firefly.emulation import qemu, sandbox
from firefly.emulation.result import BinaryRun, EmulationResult
from firefly.emulation.sandbox import SandboxPolicy
from firefly.emulation.stage import EmulationOptions, run_emulation, select_binaries
from firefly.inventory import Inventory
from firefly.models import ElfInfo, FileKind, FileRecord, Severity

from elfbuild import ET_EXEC, build_elf

# --------------------------------------------------------------------------- qemu mapping


def test_qemu_program_endianness():
    assert qemu.qemu_program(ElfInfo(32, "little", "arm", "exec")) == "qemu-arm"
    assert qemu.qemu_program(ElfInfo(32, "big", "arm", "exec")) == "qemu-armeb"
    assert qemu.qemu_program(ElfInfo(32, "big", "mips", "exec")) == "qemu-mips"
    assert qemu.qemu_program(ElfInfo(32, "little", "mips", "exec")) == "qemu-mipsel"
    assert qemu.qemu_program(ElfInfo(64, "little", "aarch64", "exec")) == "qemu-aarch64"


def test_qemu_program_riscv_width():
    assert qemu.qemu_program(ElfInfo(32, "little", "riscv", "exec")) == "qemu-riscv32"
    assert qemu.qemu_program(ElfInfo(64, "little", "riscv", "exec")) == "qemu-riscv64"


def test_qemu_program_unknown_arch():
    assert qemu.qemu_program(ElfInfo(32, "little", "0xabc", "exec")) is None


def test_find_qemu_prefers_static(monkeypatch):
    seen = {}

    def fake_which(name):
        seen[name] = True
        return "/usr/bin/" + name if name == "qemu-arm-static" else None

    monkeypatch.setattr(qemu.shutil, "which", fake_which)
    assert qemu.find_qemu("qemu-arm") == "/usr/bin/qemu-arm-static"


# --------------------------------------------------------------------------- sandbox


def test_detect_tier_refuses_without_isolation(monkeypatch):
    monkeypatch.setattr(sandbox, "bwrap_available", lambda: False)
    tier, refusal = sandbox.detect_tier(SandboxPolicy(require_isolation=True))
    assert tier == "none"
    assert refusal and "bwrap" in refusal


def test_detect_tier_rlimit_optout(monkeypatch):
    monkeypatch.setattr(sandbox, "bwrap_available", lambda: False)
    tier, refusal = sandbox.detect_tier(SandboxPolicy(require_isolation=False))
    assert tier == "rlimit-only"
    assert refusal is None


def test_detect_tier_prefers_bwrap(monkeypatch):
    monkeypatch.setattr(sandbox, "bwrap_available", lambda: True)
    tier, refusal = sandbox.detect_tier(SandboxPolicy(require_isolation=True))
    assert tier == "bwrap" and refusal is None


def test_build_command_bwrap_isolates_and_binds():
    argv, preexec = sandbox.build_command(
        "bwrap", SandboxPolicy(), "/root", ["qemu-arm", "/root/bin/sh"],
        extra_ro=["/usr/bin/qemu-arm"], rw_binds=["/logs"],
    )
    assert argv[0] == "bwrap"
    assert "--unshare-all" in argv  # network namespace included
    assert "--bind" in argv and "/logs" in argv
    assert argv[-2:] == ["qemu-arm", "/root/bin/sh"]
    assert preexec is None  # namespace does the confining


# --------------------------------------------------------------------------- candidate selection


def _elf_tree(tmp_path, names):
    root = tmp_path / "root"
    for rel in names:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(build_elf(etype=ET_EXEC))
    return Inventory.build(str(root))


def test_select_binaries_prioritises_services(tmp_path):
    inv = _elf_tree(tmp_path, ["bin/ls", "usr/sbin/httpd", "bin/cat"])
    selected = [r.path for r in select_binaries(inv, limit=10)]
    assert selected[0] == "usr/sbin/httpd"  # service first
    assert set(selected) == {"usr/sbin/httpd", "bin/ls", "bin/cat"}


def test_select_binaries_respects_limit(tmp_path):
    inv = _elf_tree(tmp_path, ["bin/a", "bin/b", "bin/c"])
    assert len(select_binaries(inv, limit=2)) == 2


# --------------------------------------------------------------------------- result -> findings


def test_crash_run_becomes_high_finding():
    run = BinaryRun(path="usr/sbin/httpd", arch="arm", qemu="qemu-arm", term_signal=11, stderr_tail="boom")
    assert run.crashed and run.signal_name == "SIGSEGV"
    res = EmulationResult(available=True, runs=[run])
    findings = res.to_findings()
    assert len(findings) == 1
    assert findings[0].severity is Severity.HIGH
    assert findings[0].analyzer == "emulation"
    assert findings[0].path == "usr/sbin/httpd"


def test_clean_exit_produces_no_finding():
    run = BinaryRun(path="bin/ls", arch="arm", qemu="qemu-arm", returncode=0)
    assert not run.crashed
    assert EmulationResult(available=True, runs=[run]).to_findings() == []


def test_runtime_command_becomes_finding():
    run = BinaryRun(path="usr/sbin/httpd", arch="arm", qemu="qemu-arm", returncode=0, commands=["sh -c 'reboot'"])
    findings = EmulationResult(available=True, runs=[run]).to_findings()
    assert len(findings) == 1
    assert findings[0].severity is Severity.MEDIUM
    assert "shell command" in findings[0].title


# --------------------------------------------------------------------------- stage orchestration


def test_run_emulation_requires_linux(tmp_path, monkeypatch):
    monkeypatch.setattr(stage.sys, "platform", "win32")
    inv = _elf_tree(tmp_path, ["bin/ls"])
    res = run_emulation(str(tmp_path), inv, EmulationOptions(enabled=True))
    assert res.available is False
    assert "Linux" in res.reason


def test_run_emulation_runs_candidates(tmp_path, monkeypatch):
    inv = _elf_tree(tmp_path, ["usr/sbin/httpd", "bin/ls"])

    monkeypatch.setattr(stage.sys, "platform", "linux")
    monkeypatch.setattr(stage, "detect_tier", lambda policy: ("rlimit-only", None))
    monkeypatch.setattr(stage.qemu, "resolve", lambda elf: ("qemu-arm", "/usr/bin/qemu-arm"))

    calls: list[str] = []

    def fake_run_binary(rootfs, rel_path, elf, qemu_path, **kw):
        calls.append(rel_path)
        sig = 11 if "httpd" in rel_path else None
        return BinaryRun(path=rel_path, arch=elf.machine, qemu="qemu-arm", term_signal=sig, returncode=None if sig else 0)

    monkeypatch.setattr(stage, "run_binary", fake_run_binary)

    res = run_emulation(str(inv.root), inv, EmulationOptions(enabled=True, require_sandbox=False))
    assert res.available and res.sandbox == "rlimit-only"
    assert res.candidates == 2 and len(res.runs) == 2
    assert calls[0] == "usr/sbin/httpd"  # priority ordering preserved
    assert res.qemu_found == {"arm": "/usr/bin/qemu-arm"}
    findings = res.to_findings()
    assert any(f.severity is Severity.HIGH for f in findings)


def test_run_emulation_reports_missing_qemu(tmp_path, monkeypatch):
    inv = _elf_tree(tmp_path, ["bin/ls"])
    monkeypatch.setattr(stage.sys, "platform", "linux")
    monkeypatch.setattr(stage, "detect_tier", lambda policy: ("rlimit-only", None))
    monkeypatch.setattr(stage.qemu, "resolve", lambda elf: ("qemu-arm", None))  # program known, not installed

    res = run_emulation(str(inv.root), inv, EmulationOptions(enabled=True, require_sandbox=False))
    assert res.available and res.skipped == 1 and not res.runs
    assert "qemu-user" in res.reason
