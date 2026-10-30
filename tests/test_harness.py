"""Tests for the Phase C3 heavy per-binary harness fuzzer (firefly/emulation/harness.py).

No qemu and no AFL++: the runner is faked, engine detection is monkeypatched,
and the AFL path is driven with a stub afl_runner over a hand-built crashes/
directory. They pass on any OS and on CI without qemu-user, bubblewrap, or AFL.
"""

from __future__ import annotations

import base64
import os

from firefly.emulation import harness
from firefly.emulation.harness import (
    HarnessCrash,
    HarnessOptions,
    HarnessResult,
    afl_argv,
    collect_afl_crashes,
    detect_engine,
    fuzz_binary_afl,
    fuzz_binary_stdlib,
    run_harness,
    select_targets,
)
from firefly.emulation.result import BinaryRun, EmulationResult
from firefly.emulation.sandbox import SandboxPolicy
from firefly.inventory import Inventory
from firefly.models import ElfInfo, Finding, Severity

from elfbuild import ET_EXEC, build_elf

_ELF = ElfInfo(32, "little", "arm", "exec")
_POLICY = SandboxPolicy(require_isolation=False)
_OPTS = HarnessOptions(iterations=4, wall_clock_s=10.0, run_timeout_s=0.5, max_input=128, seed=1)


def _make_runner(*, baseline_crash=False, crash_on=lambda d: False, hang_on=lambda d: False, commands=None):
    """A fake run_binary: benign on the empty baseline, then crash/hang per the predicates."""
    def run(rootfs, rel_path, elf, qemu_path, **kw):
        data = kw.get("input_bytes")
        r = BinaryRun(path=rel_path, arch=elf.machine, qemu="qemu-arm")
        if not data:  # baseline (empty input)
            if baseline_crash:
                r.term_signal = 11
            return r
        if hang_on(data):
            r.timed_out = True
        elif crash_on(data):
            r.term_signal = 11
            r.commands = list(commands or [])
        return r
    return run


# --------------------------------------------------------------------------- engine detection


def test_detect_engine_forced_afl_falls_back_when_absent(monkeypatch):
    monkeypatch.setattr(harness, "afl_available", lambda: False)
    engine, reason = detect_engine("afl++")
    assert engine == "stdlib" and "afl" in reason.lower()


def test_detect_engine_stdlib_and_auto(monkeypatch):
    assert detect_engine("stdlib") == ("stdlib", "")
    monkeypatch.setattr(harness, "afl_available", lambda: True)
    assert detect_engine("auto") == ("afl++", "")
    monkeypatch.setattr(harness, "afl_available", lambda: False)
    assert detect_engine("auto") == ("stdlib", "")


# --------------------------------------------------------------------------- stdlib engine


def test_fuzz_binary_stdlib_finds_input_crash():
    run_fn = _make_runner(crash_on=lambda d: True, commands=["sh -c reboot"])
    crashes, iters, skip = fuzz_binary_stdlib(
        "/root", "usr/sbin/httpd", _ELF, "/usr/bin/qemu-arm",
        tier="rlimit-only", policy=_POLICY, shim_path=None, log_path=None,
        opts=_OPTS, run_fn=run_fn,
    )
    assert skip == "" and len(crashes) == 1
    c = crashes[0]
    assert c.signal == "SIGSEGV" and c.engine == "stdlib" and not c.is_hang
    assert base64.b64decode(c.repro_b64)              # usable reproducer
    assert c.commands == ["sh -c reboot"]             # shim triage carried through
    assert c.iteration == 1                           # first mutated input already crashed


def test_fuzz_binary_stdlib_skips_baseline_crasher():
    run_fn = _make_runner(baseline_crash=True, crash_on=lambda d: True)
    crashes, iters, skip = fuzz_binary_stdlib(
        "/root", "bin/crasher", _ELF, "/usr/bin/qemu-arm",
        tier="rlimit-only", policy=_POLICY, shim_path=None, log_path=None,
        opts=_OPTS, run_fn=run_fn,
    )
    assert crashes == [] and iters == 0 and "bare-launch" in skip


def test_fuzz_binary_stdlib_reports_hang():
    run_fn = _make_runner(hang_on=lambda d: True)
    crashes, _iters, skip = fuzz_binary_stdlib(
        "/root", "usr/sbin/upnpd", _ELF, "/usr/bin/qemu-arm",
        tier="rlimit-only", policy=_POLICY, shim_path=None, log_path=None,
        opts=_OPTS, run_fn=run_fn,
    )
    assert skip == "" and len(crashes) == 1 and crashes[0].is_hang


def test_fuzz_binary_stdlib_clean_runs_all_iterations():
    run_fn = _make_runner()  # never crashes
    crashes, iters, skip = fuzz_binary_stdlib(
        "/root", "bin/ls", _ELF, "/usr/bin/qemu-arm",
        tier="rlimit-only", policy=_POLICY, shim_path=None, log_path=None,
        opts=_OPTS, run_fn=run_fn,
    )
    assert crashes == [] and skip == "" and iters == _OPTS.iterations


def test_fuzz_binary_stdlib_launch_error_skips():
    def run_fn(rootfs, rel_path, elf, qemu_path, **kw):
        return BinaryRun(path=rel_path, arch=elf.machine, qemu="qemu-arm", error="exec format error")
    crashes, iters, skip = fuzz_binary_stdlib(
        "/root", "bin/x", _ELF, "/usr/bin/qemu-arm",
        tier="rlimit-only", policy=_POLICY, shim_path=None, log_path=None,
        opts=_OPTS, run_fn=run_fn,
    )
    assert crashes == [] and iters == 0 and "could not launch" in skip


# --------------------------------------------------------------------------- target selection


def test_select_targets_prioritises_sinks_excludes_crashers_dedups():
    runs = [
        BinaryRun(path="usr/sbin/httpd", arch="arm", qemu="q"),               # healthy service
        BinaryRun(path="bin/crasher", arch="arm", qemu="q", term_signal=11),  # bare-launch crasher
    ]
    targets = select_targets(runs, ("bin/cgi-bin/foo.cgi", "usr/sbin/httpd"), limit=8)
    assert targets[0] == "bin/cgi-bin/foo.cgi"   # sink first
    assert "usr/sbin/httpd" in targets           # healthy service kept, de-duplicated once
    assert targets.count("usr/sbin/httpd") == 1
    assert "bin/crasher" not in targets          # crasher excluded (Phase A owns it)


# --------------------------------------------------------------------------- AFL++ engine


def test_afl_argv_shape():
    argv = afl_argv("/usr/bin/afl-fuzz", "/in", "/out", 30, "/root/usr/sbin/httpd")
    assert argv[0] == "/usr/bin/afl-fuzz"
    assert "-Q" in argv and argv[argv.index("-V") + 1] == "30"
    assert argv[argv.index("-i") + 1] == "/in" and argv[argv.index("-o") + 1] == "/out"
    sep = argv.index("--")
    # qemu-mode launches the target directly (sysroot via QEMU_LD_PREFIX) — no qemu/-L wrapper.
    assert argv[sep + 1:] == ["/root/usr/sbin/httpd"]


def test_collect_afl_crashes_reads_only_crash_ids(tmp_path):
    crashes_dir = tmp_path / "default" / "crashes"
    crashes_dir.mkdir(parents=True)
    # Real AFL names these "id:...,sig:11"; the colon is illegal on Windows, so
    # the fixtures use a portable name — collect_afl_crashes matches by exclusion.
    (crashes_dir / "id_000000_sig11").write_bytes(b"first")
    (crashes_dir / "id_000001_sig06").write_bytes(b"second")
    (crashes_dir / "README.txt").write_bytes(b"not a crash")
    found = collect_afl_crashes(str(tmp_path))
    assert set(found) == {b"first", b"second"}      # README excluded
    assert len(found) == 2


def _afl_stub(repro: bytes):
    """A fake afl-fuzz: it 'finds' one crash by writing a reproducer into the
    -o dir it was handed, exactly where the real tool would (<out>/default/crashes)."""
    captured = {}
    def run(argv, timeout, env=None):
        captured["argv"] = argv
        captured["env"] = env
        out_dir = argv[argv.index("-o") + 1]
        crashes = os.path.join(out_dir, "default", "crashes")
        os.makedirs(crashes, exist_ok=True)
        with open(os.path.join(crashes, "id_000000_sig11"), "wb") as fh:
            fh.write(repro)
        return 0
    run.captured = captured  # type: ignore[attr-defined]
    return run


def test_fuzz_binary_afl_confirms_and_triages(tmp_path, monkeypatch):
    monkeypatch.setattr(harness.shutil, "which", lambda n: "/usr/bin/afl-fuzz")
    fake_afl = _afl_stub(b"BOOM")
    run_fn = _make_runner(crash_on=lambda d: d == b"BOOM", commands=["system(evil)"])

    crashes, n, skip = fuzz_binary_afl(
        "/root", "usr/sbin/httpd", _ELF, "/usr/bin/qemu-arm",
        tier="rlimit-only", policy=_POLICY, shim_path=None, log_path=None,
        workdir=str(tmp_path), opts=_OPTS, run_fn=run_fn, afl_runner=fake_afl,
    )
    assert skip == "" and len(crashes) == 1
    assert crashes[0].engine == "afl++" and crashes[0].signal == "SIGSEGV"
    assert crashes[0].commands == ["system(evil)"]
    assert fake_afl.captured["argv"][0] == "/usr/bin/afl-fuzz"  # type: ignore[attr-defined]
    assert fake_afl.captured["env"]["QEMU_LD_PREFIX"] == "/root"  # sysroot passed via env, not -L  # type: ignore[attr-defined]


def test_fuzz_binary_afl_drops_unconfirmed_repro(tmp_path, monkeypatch):
    monkeypatch.setattr(harness.shutil, "which", lambda n: "/usr/bin/afl-fuzz")
    run_fn = _make_runner()  # replay never crashes -> AFL's crash is not reproduced

    crashes, n, skip = fuzz_binary_afl(
        "/root", "usr/sbin/httpd", _ELF, "/usr/bin/qemu-arm",
        tier="rlimit-only", policy=_POLICY, shim_path=None, log_path=None,
        workdir=str(tmp_path), opts=_OPTS, run_fn=run_fn, afl_runner=_afl_stub(b"noop"),
    )
    assert crashes == [] and skip == ""


# --------------------------------------------------------------------------- orchestration


def _elf_tree(tmp_path, names):
    root = tmp_path / "root"
    for rel in names:
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(build_elf(etype=ET_EXEC))
    return Inventory.build(str(root))


def test_run_harness_fuzzes_healthy_binaries_stdlib(tmp_path):
    inv = _elf_tree(tmp_path, ["usr/sbin/httpd", "bin/ls"])
    runs = [BinaryRun(path="usr/sbin/httpd", arch="arm", qemu="q"), BinaryRun(path="bin/ls", arch="arm", qemu="q")]
    run_fn = _make_runner(crash_on=lambda d: True)

    res = run_harness(
        str(inv.root), inv, runs,
        tier="rlimit-only", policy=_POLICY, qemu_found={"arm": "/usr/bin/qemu-arm"},
        workdir=str(tmp_path), opts=HarnessOptions(engine="stdlib", iterations=2, run_timeout_s=0.1), run_fn=run_fn,
    )
    assert res.engine == "stdlib" and res.available
    assert "usr/sbin/httpd" in res.targets_fuzzed
    assert len(res.crashes) >= 1 and res.crashes[0].signal == "SIGSEGV"


def test_run_harness_skips_targets_without_qemu(tmp_path, monkeypatch):
    inv = _elf_tree(tmp_path, ["usr/sbin/httpd"])
    runs = [BinaryRun(path="usr/sbin/httpd", arch="arm", qemu="q")]
    monkeypatch.setattr(harness.qemu, "resolve", lambda elf: ("qemu-arm", None))  # program known, not installed
    res = run_harness(
        str(inv.root), inv, runs,
        tier="rlimit-only", policy=_POLICY, qemu_found={},
        workdir=str(tmp_path), opts=HarnessOptions(engine="stdlib"), run_fn=_make_runner(),
    )
    assert res.crashes == [] and any("no qemu-user" in s for s in res.skipped)


def test_run_harness_no_targets_is_unavailable(tmp_path):
    inv = _elf_tree(tmp_path, ["bin/crasher"])
    runs = [BinaryRun(path="bin/crasher", arch="arm", qemu="q", term_signal=11)]  # only a crasher -> nothing healthy
    res = run_harness(
        str(inv.root), inv, runs,
        tier="rlimit-only", policy=_POLICY, qemu_found={"arm": "/usr/bin/qemu-arm"},
        workdir=str(tmp_path), opts=HarnessOptions(engine="stdlib"), run_fn=_make_runner(),
    )
    assert res.available is False and res.reason


# --------------------------------------------------------------------------- findings / artifact / upgrade


def test_to_findings_severity_by_signal():
    res = HarnessResult(crashes=[
        HarnessCrash("a", "arm", "SIGSEGV", "stdlib", base64.b64encode(b"x").decode(), 1),
        HarnessCrash("b", "arm", "SIGABRT", "stdlib", base64.b64encode(b"y").decode(), 2),
        HarnessCrash("c", "arm", "hang", "afl++", base64.b64encode(b"z").decode(), 3),
    ])
    by_path = {f.path: f for f in res.to_findings()}
    assert by_path["a"].severity is Severity.CRITICAL and by_path["a"].confidence == "high"
    assert by_path["b"].severity is Severity.HIGH
    assert by_path["c"].severity is Severity.HIGH and "hung" in by_path["c"].title
    assert all(f.metadata["confirmed_fuzz_crash"] and "repro_b64" in f.metadata for f in by_path.values())


def test_upgrade_bare_launch_raises_matching_finding_only():
    bare = Finding(analyzer="emulation", title="crashed", severity=Severity.MEDIUM, confidence="low",
                   path="usr/sbin/httpd", description="bare.", metadata={"bare_launch": True})
    other = Finding(analyzer="emulation", title="crashed", severity=Severity.MEDIUM, confidence="low",
                    path="bin/ls", description="bare.", metadata={"bare_launch": True})
    res = HarnessResult(crashes=[HarnessCrash("usr/sbin/httpd", "arm", "SIGSEGV", "stdlib", "eA==", 1)])
    res.upgrade_bare_launch([bare, other])
    assert bare.severity is Severity.HIGH and bare.confidence == "high" and bare.metadata["confirmed_fuzz_crash"]
    assert other.severity is Severity.MEDIUM and "confirmed_fuzz_crash" not in other.metadata  # untouched


def test_upgrade_bare_launch_never_lowers():
    crit = Finding(analyzer="emulation", title="crashed", severity=Severity.CRITICAL, confidence="high",
                   path="usr/sbin/httpd", description="x.", metadata={"bare_launch": True})
    HarnessResult(crashes=[HarnessCrash("usr/sbin/httpd", "arm", "SIGABRT", "stdlib", "eA==", 1)]).upgrade_bare_launch([crit])
    assert crit.severity is Severity.CRITICAL  # not lowered to HIGH


def test_emulation_result_folds_in_harness():
    run = BinaryRun(path="bin/ls", arch="arm", qemu="qemu-arm", returncode=0)
    hr = HarnessResult(crashes=[HarnessCrash("usr/sbin/httpd", "arm", "SIGSEGV", "stdlib", "eA==", 1)], targets_fuzzed=["usr/sbin/httpd"])
    emu = EmulationResult(available=True, runs=[run], harness=hr)
    art = emu.to_artifact()
    assert art["harness"]["targets_fuzzed"] == ["usr/sbin/httpd"]
    findings = emu.to_findings()
    assert any(f.analyzer == "harness" and f.severity is Severity.CRITICAL for f in findings)


def test_artifact_shape():
    res = HarnessResult(
        crashes=[HarnessCrash("usr/sbin/httpd", "arm", "SIGSEGV", "afl++", base64.b64encode(b"x").decode(), 2, commands=["id"])],
        engine="afl++", targets_fuzzed=["usr/sbin/httpd"], iterations=50, skipped=["bin/ls: no qemu-user for sparc"],
    )
    art = res.to_artifact()
    assert art["engine"] == "afl++" and art["iterations"] == 50
    assert art["crashes"][0]["signal"] == "SIGSEGV" and art["crashes"][0]["repro_b64"]
    assert art["crashes"][0]["commands"] == ["id"] and art["skipped"]
