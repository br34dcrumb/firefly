"""Phase C3 (heavy): a per-binary harness fuzzer for the emulated firmware.

The minimal C3 step (:mod:`firefly.emulation.fuzz`) fuzzes the *booted system*
over the network. This is the other, heavier half of C3: it harnesses the
individual service and sink binaries Phase A already runs under qemu-user,
re-executing each one many times with mutated input on stdin (and CGI-style
environment) and watching for a crash the input caused — a real memory-safety
signal (SIGSEGV/SIGBUS/…) or a hang that the benign baseline input did not
produce. Every crash records a base64 reproducer and is triaged back to the
binary through the existing LD_PRELOAD shim (what the binary executed / opened
at the moment it died).

Engine: the mutator is runtime-detected like the rest of Firefly's heavy tools
(qemu, radare2). When AFL++ qemu-mode (``afl-fuzz`` + ``afl-qemu-trace``) is
installed it is driven for real coverage-guided generation; its ``crashes/``
outputs are then replayed through the same qemu-user runner to confirm the
signal and collect shim triage. When AFL++ is absent the fuzzer falls back to a
bounded, seeded, stdlib mutational loop — no new dependency, always available.

Safety: this only ever *re-runs the Phase A machinery* — the same qemu-user
program, the same sandbox tier (bubblewrap when available), the same per-run
wall-clock. It adds an iteration cap and a per-target wall-clock on top, writes
only inside the scan workdir, and makes no network request. It is opt-in behind
``scan --fuzz-binaries`` (which implies ``--emulate``).
"""

from __future__ import annotations

import base64
import logging
import os
import random
import shutil
import subprocess
import time
import zlib
from dataclasses import dataclass, field
from typing import Any, Callable

from firefly.emulation import qemu, shimbuild
from firefly.emulation.result import BinaryRun
from firefly.emulation.runner import run_binary
from firefly.emulation.sandbox import SandboxPolicy
from firefly.emulation.mutator import mutate
from firefly.inventory import Inventory
from firefly.models import ElfInfo, FileKind, Finding, Severity

log = logging.getLogger(__name__)

# Generic seed inputs the mutator works from. Firmware CGIs and line protocols
# both tend to read a short line or a small blob from stdin.
_SEEDS: tuple[bytes, ...] = (
    b"",
    b"A" * 32,
    b"GET / HTTP/1.0\r\n\r\n",
    b"username=admin&password=admin\r\n",
    b"/../../../../etc/passwd\r\n",
    b"1\r\n",
)

# A binary whose name looks like a CGI gets a minimal CGI environment so its
# request parsing is actually exercised instead of bailing out immediately.
_CGI_HINTS = ("cgi", "nph-")


@dataclass
class HarnessOptions:
    iterations: int = 150          # mutated inputs per target (hard cap)
    wall_clock_s: float = 45.0     # ceiling on time spent per target
    max_targets: int = 8           # distinct binaries fuzzed per scan
    max_input: int = 4096          # cap on a single mutated input
    run_timeout_s: float = 5.0     # per-execution wall-clock
    seed: int = 0                  # base RNG seed; per-target offset keeps runs reproducible
    engine: str = "auto"           # "auto" | "stdlib" | "afl++"
    build_shim: bool = False       # cross-compile the triage shim if a toolchain exists


@dataclass
class HarnessCrash:
    path: str          # binary, relative to the scan root
    arch: str
    signal: str        # "SIGSEGV", "SIGABRT", … or "hang"
    engine: str        # "stdlib" | "afl++"
    repro_b64: str     # base64 of the input that triggered it
    iteration: int
    commands: list[str] = field(default_factory=list)   # shim: what it shelled out to at crash
    opened_paths: list[str] = field(default_factory=list)

    @property
    def is_hang(self) -> bool:
        return self.signal == "hang"


@dataclass
class HarnessResult:
    crashes: list[HarnessCrash] = field(default_factory=list)
    engine: str = "stdlib"             # engine actually used
    targets_fuzzed: list[str] = field(default_factory=list)
    iterations: int = 0
    skipped: list[str] = field(default_factory=list)   # "path: reason"
    available: bool = True
    reason: str = ""                   # why the stage produced nothing

    def to_artifact(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "reason": self.reason,
            "engine": self.engine,
            "targets_fuzzed": self.targets_fuzzed,
            "iterations": self.iterations,
            "crashes": [
                {
                    "path": c.path,
                    "arch": c.arch,
                    "signal": c.signal,
                    "engine": c.engine,
                    "iteration": c.iteration,
                    "repro_b64": c.repro_b64,
                    "commands": c.commands,
                    "opened_paths": c.opened_paths,
                }
                for c in self.crashes
            ],
            "skipped": self.skipped,
        }

    def to_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for c in self.crashes:
            corruption = c.signal in ("SIGSEGV", "SIGBUS")
            if c.is_hang:
                sev, what = Severity.HIGH, "hung (stopped responding)"
            else:
                sev = Severity.CRITICAL if corruption else Severity.HIGH
                what = f"crashed with {c.signal}"
            findings.append(
                Finding(
                    analyzer="harness",
                    title=f"Binary {what} on fuzzed input: {c.path}",
                    severity=sev,
                    confidence="high",
                    path=c.path,
                    evidence=f"{c.signal} after {c.iteration} mutated input(s) [{c.engine}]",
                    description=(
                        f"{c.path} {what} when fed a mutated input under qemu-user that a benign "
                        "baseline input did not trigger — an input-dependent memory-safety / "
                        "denial-of-service bug worth triaging. A reproducing input is recorded "
                        "(base64) in the harness artifact."
                        + (f" At the crash the binary had executed: {c.commands[0]}" if c.commands else "")
                    ),
                    metadata={
                        "signal": c.signal,
                        "arch": c.arch,
                        "engine": c.engine,
                        "iteration": c.iteration,
                        "repro_b64": c.repro_b64,
                        "commands": c.commands[:10],
                        "confirmed_fuzz_crash": True,
                    },
                )
            )
        return findings

    def upgrade_bare_launch(self, findings: list[Finding]) -> None:
        """Raise a Phase A bare-launch crash finding whose binary the harness
        has now crashed on *input* — the confirmation its own text invites.

        Positive-signal only: it never lowers a severity or confidence, and the
        absence of a harness crash changes nothing (mirrors C2's
        ``upgrade_static_findings``).
        """
        crashed_paths = {c.path for c in self.crashes if not c.is_hang}
        for f in findings:
            if (
                f.analyzer == "emulation"
                and f.metadata.get("bare_launch")
                and f.path in crashed_paths
            ):
                if Severity.HIGH.rank > f.severity.rank:
                    f.severity = Severity.HIGH
                f.confidence = "high"
                f.metadata["confirmed_fuzz_crash"] = True
                f.description += (
                    " A later harness-fuzzing pass reproduced a crash on attacker-supplied input, "
                    "so this is an input-triggered defect, not just a missing-environment crash."
                )


# --------------------------------------------------------------------------- engine detection


def afl_available() -> bool:
    """AFL++ qemu-mode needs both the fuzzer and its qemu tracer on PATH."""
    return bool(shutil.which("afl-fuzz") and shutil.which("afl-qemu-trace"))


def detect_engine(requested: str) -> tuple[str, str]:
    """Resolve the configured engine to one we can actually run.

    Returns ``(engine, reason)``; ``reason`` is non-empty only when a forced
    engine is unavailable and we fell back.
    """
    if requested == "afl++":
        return ("afl++", "") if afl_available() else ("stdlib", "afl-fuzz/afl-qemu-trace not installed; using the stdlib engine")
    if requested == "stdlib":
        return "stdlib", ""
    # auto
    return ("afl++", "") if afl_available() else ("stdlib", "")


# --------------------------------------------------------------------------- crash classification


def _crash_signal(run: BinaryRun) -> str | None:
    """The crash signal name for a run that died on a memory-safety fault, else None.

    A timeout is reported separately as a hang; SIGKILL (our own timeout kill) is
    never a crash (``run.crashed`` already excludes it).
    """
    if run.crashed:
        return run.signal_name
    return None


def _cgi_env(rel_path: str, data: bytes) -> dict[str, str] | None:
    """A minimal CGI environment for a binary whose name looks like a CGI."""
    base = os.path.basename(rel_path).lower()
    if not any(h in base for h in _CGI_HINTS):
        return None
    return {
        "REQUEST_METHOD": "POST",
        "CONTENT_LENGTH": str(len(data)),
        "CONTENT_TYPE": "application/x-www-form-urlencoded",
        "QUERY_STRING": "a=1",
        "REMOTE_ADDR": "127.0.0.1",
        "SERVER_PROTOCOL": "HTTP/1.0",
    }


# --------------------------------------------------------------------------- stdlib engine


def _run_once(
    run_fn: Callable[..., BinaryRun],
    rootfs: str,
    rel_path: str,
    elf: ElfInfo,
    qemu_path: str,
    data: bytes,
    *,
    tier: str,
    policy: SandboxPolicy,
    shim_path: str | None,
    log_path: str | None,
    timeout_s: float,
) -> BinaryRun:
    return run_fn(
        rootfs, rel_path, elf, qemu_path,
        tier=tier, policy=policy,
        timeout_s=timeout_s,
        shim_path=shim_path, log_path=log_path,
        input_bytes=data,
        extra_env=_cgi_env(rel_path, data),
    )


def fuzz_binary_stdlib(
    rootfs: str,
    rel_path: str,
    elf: ElfInfo,
    qemu_path: str,
    *,
    tier: str,
    policy: SandboxPolicy,
    shim_path: str | None,
    log_path: str | None,
    opts: HarnessOptions,
    run_fn: Callable[..., BinaryRun] = run_binary,
) -> tuple[list[HarnessCrash], int, str]:
    """Bounded, seeded stdlib mutational fuzz of one binary.

    Returns ``(crashes, iterations_run, skip_reason)``. A crash is reported only
    when the mutated input turned a binary that *did not* crash on the benign
    baseline input into one that crashes (or hangs) — an unambiguous
    input-triggered bug. ``rel_path`` is stored on the crash; ``rootfs/rel_path``
    is what actually runs. Only one crash per binary is recorded (the first).
    """
    base = _run_once(run_fn, rootfs, rel_path, elf, qemu_path, b"", tier=tier, policy=policy, shim_path=shim_path, log_path=log_path, timeout_s=opts.run_timeout_s)
    if base.error:
        return [], 0, f"{rel_path}: could not launch ({base.error})"
    # A binary that already crashes or hangs on empty input is an environmental
    # bare-launch crash (Phase A reports it); the harness looks for *new*,
    # input-dependent crashes, so such a binary is skipped here.
    if base.crashed or base.timed_out:
        return [], 0, f"{rel_path}: crashes on the baseline input (bare-launch; left to Phase A)"

    # crc32 (not hash()) so the per-target offset is stable across processes and
    # a recorded seed reproduces the run exactly.
    rng = random.Random(opts.seed + zlib.crc32(rel_path.encode()))
    deadline = time.monotonic() + opts.wall_clock_s
    it = 0
    while it < opts.iterations and time.monotonic() < deadline:
        it += 1
        data = mutate(rng.choice(_SEEDS), rng, opts.max_input)
        run = _run_once(run_fn, rootfs, rel_path, elf, qemu_path, data, tier=tier, policy=policy, shim_path=shim_path, log_path=log_path, timeout_s=opts.run_timeout_s)
        sig = _crash_signal(run)
        if sig:
            return [_crash(rel_path, elf, sig, "stdlib", data, it, run)], it, ""
        if run.timed_out:  # input made a responsive binary hang -> DoS
            return [_crash(rel_path, elf, "hang", "stdlib", data, it, run)], it, ""
    return [], it, ""


def _crash(rel_path: str, elf: ElfInfo, signal: str, engine: str, data: bytes, it: int, run: BinaryRun) -> HarnessCrash:
    return HarnessCrash(
        path=rel_path,
        arch=elf.machine,
        signal=signal,
        engine=engine,
        repro_b64=base64.b64encode(data).decode("ascii"),
        iteration=it,
        commands=list(run.commands),
        opened_paths=list(run.opened_paths),
    )


# --------------------------------------------------------------------------- AFL++ engine


def afl_argv(afl_fuzz: str, in_dir: str, out_dir: str, secs: int, qemu_path: str, rootfs: str, target: str) -> list[str]:
    """The ``afl-fuzz`` command line for a one-shot, time-boxed qemu-mode run.

    ``-Q`` selects qemu-mode (foreign-architecture instrumentation via
    ``afl-qemu-trace``); ``-V`` time-boxes the campaign; the target reads its
    input on stdin (no ``@@``). ``-L -1``/``AFL_QEMU_PERSISTENT`` tuning is left
    off on purpose — this stays a conservative, portable invocation.
    """
    return [
        afl_fuzz, "-Q", "-V", str(secs), "-i", in_dir, "-o", out_dir,
        "--", qemu_path, "-L", rootfs, target,
    ]


def _write_seeds(in_dir: str) -> None:
    os.makedirs(in_dir, exist_ok=True)
    for i, seed in enumerate(_SEEDS):
        with open(os.path.join(in_dir, f"seed{i:02d}"), "wb") as fh:
            fh.write(seed or b"A")  # AFL rejects an empty seed file


def collect_afl_crashes(out_dir: str, limit: int = 32) -> list[bytes]:
    """Read the reproducer inputs AFL++ saved under ``<out>/**/crashes/``.

    Every file in a ``crashes/`` directory is a reproducer (AFL names them
    ``id:...``) except ``README.txt`` and dotfiles, which are metadata. Returned
    newest-first, bounded.
    """
    found: list[tuple[float, bytes]] = []
    for root, _dirs, files in os.walk(out_dir):
        if os.path.basename(root) != "crashes":
            continue
        for name in files:
            if name == "README.txt" or name.startswith("."):
                continue
            p = os.path.join(root, name)
            try:
                with open(p, "rb") as fh:
                    found.append((os.path.getmtime(p), fh.read()))
            except OSError:
                continue
    found.sort(key=lambda t: -t[0])
    return [data for _mtime, data in found[:limit]]


def fuzz_binary_afl(
    rootfs: str,
    rel_path: str,
    elf: ElfInfo,
    qemu_path: str,
    *,
    tier: str,
    policy: SandboxPolicy,
    shim_path: str | None,
    log_path: str | None,
    workdir: str,
    opts: HarnessOptions,
    run_fn: Callable[..., BinaryRun] = run_binary,
    afl_runner: Callable[[list[str], float], int] | None = None,
) -> tuple[list[HarnessCrash], int, str]:
    """Drive AFL++ qemu-mode over one binary, then confirm each crash it saved.

    AFL generates coverage-guided inputs; every reproducer under its ``crashes/``
    directory is replayed once through the qemu-user runner so the crash signal
    and shim triage come from the same path the stdlib engine uses. A reproducer
    that does not crash on replay is dropped (AFL's own crash detection can be
    noisier than a clean signal). ``afl_runner`` is injectable for testing.
    """
    afl_fuzz = shutil.which("afl-fuzz")
    if not afl_fuzz:
        return [], 0, f"{rel_path}: afl-fuzz disappeared"
    in_dir = os.path.join(workdir, "afl-in")
    out_dir = os.path.join(workdir, "afl-out")
    shutil.rmtree(out_dir, ignore_errors=True)
    _write_seeds(in_dir)
    argv = afl_argv(afl_fuzz, in_dir, out_dir, max(1, int(opts.wall_clock_s)), qemu_path, rootfs, os.path.join(rootfs, rel_path))
    runner = afl_runner or _default_afl_runner
    try:
        runner(argv, opts.wall_clock_s + 30.0)
    except Exception as exc:  # AFL misconfiguration must never abort the scan
        log.debug("afl-fuzz failed for %s: %s", rel_path, exc)
        return [], 0, f"{rel_path}: afl-fuzz did not run ({type(exc).__name__})"

    crashes: list[HarnessCrash] = []
    for i, data in enumerate(collect_afl_crashes(out_dir), 1):
        run = _run_once(run_fn, rootfs, rel_path, elf, qemu_path, data, tier=tier, policy=policy, shim_path=shim_path, log_path=log_path, timeout_s=opts.run_timeout_s)
        sig = _crash_signal(run)
        if sig:
            crashes.append(_crash(rel_path, elf, sig, "afl++", data, i, run))
        elif run.timed_out:
            crashes.append(_crash(rel_path, elf, "hang", "afl++", data, i, run))
        if crashes:  # one confirmed crash per binary is enough
            break
    return crashes, len(crashes), ""


def _default_afl_runner(argv: list[str], timeout_s: float) -> int:
    """Run afl-fuzz, time-boxed. ``AFL_BENCH_UNTIL_CRASH`` would stop early but we
    rely on ``-V`` and this hard timeout; the env quiets AFL's interactive gates."""
    env = dict(os.environ, AFL_SKIP_CPUFREQ="1", AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES="1", AFL_NO_AFFINITY="1")
    try:
        proc = subprocess.run(argv, capture_output=True, timeout=timeout_s, env=env, check=False)
        return proc.returncode
    except subprocess.TimeoutExpired:
        return 0


# --------------------------------------------------------------------------- target selection + orchestration


def select_targets(runs: list[BinaryRun], sink_paths: tuple[str, ...], limit: int) -> list[str]:
    """Binaries worth harnessing, most promising first, de-duplicated and bounded.

    Priority: binaries flagged with an input-reachable dangerous sink, then the
    service binaries Phase A ran *without* a bare-launch crash (a healthy service
    gives a clean input-triggered signal). Bare-launch crashers are deliberately
    excluded — Phase A already reports them and the stdlib loop would only skip
    them.
    """
    crashed = {r.path for r in runs if r.crashed or r.timed_out}
    ordered: list[str] = []
    for path in list(sink_paths) + [r.path for r in runs]:
        if path and path not in crashed and path not in ordered:
            ordered.append(path)
    return ordered[:limit]


def _record_for(inv: Inventory, rel_path: str):
    for rec in inv.of_kind(FileKind.ELF):
        if rec.path == rel_path:
            return rec
    return None


def run_harness(
    rootfs: str,
    inv: Inventory,
    runs: list[BinaryRun],
    *,
    tier: str,
    policy: SandboxPolicy,
    qemu_found: dict[str, str],
    workdir: str | None,
    sink_paths: tuple[str, ...] = (),
    shims: dict[tuple[str, str], str | None] | None = None,
    opts: HarnessOptions | None = None,
    run_fn: Callable[..., BinaryRun] = run_binary,
) -> HarnessResult:
    """Harness-fuzz the firmware's service/sink binaries over qemu-user.

    Reuses Phase A's already-resolved sandbox ``tier``/``policy`` and qemu paths.
    ``shims`` (arch,endian -> shim .so) is reused when Phase A built it; otherwise
    the shim is built here when ``opts.build_shim`` and a toolchain exist. Returns
    a :class:`HarnessResult`; a missing qemu for a target's architecture skips
    that target with a reason, never a crash.
    """
    opts = opts or HarnessOptions()
    engine, fallback_reason = detect_engine(opts.engine)
    res = HarnessResult(engine=engine, reason=fallback_reason)
    shims = dict(shims or {})

    targets = select_targets(runs, sink_paths, opts.max_targets)
    if not targets:
        res.available = False
        res.reason = res.reason or "no healthy service/sink binaries to harness"
        return res

    for idx, rel_path in enumerate(targets):
        rec = _record_for(inv, rel_path)
        if rec is None or rec.elf is None:
            res.skipped.append(f"{rel_path}: not an inventoried ELF")
            continue
        elf = rec.elf
        qemu_path = qemu_found.get(elf.machine) or qemu.resolve(elf)[1]
        if not qemu_path:
            res.skipped.append(f"{rel_path}: no qemu-user for {elf.machine}")
            continue

        shim_path = _ensure_shim(shims, elf, workdir, opts.build_shim)
        log_path = (
            os.path.join(workdir, "harness-logs", f"{idx:04d}.log")
            if shim_path and workdir
            else None
        )
        target_workdir = os.path.join(workdir, "harness", f"{idx:04d}") if workdir else None

        try:
            if engine == "afl++" and target_workdir:
                crashes, iters, skip = fuzz_binary_afl(
                    rootfs, rel_path, elf, qemu_path,
                    tier=tier, policy=policy, shim_path=shim_path, log_path=log_path,
                    workdir=target_workdir, opts=opts, run_fn=run_fn,
                )
            else:
                crashes, iters, skip = fuzz_binary_stdlib(
                    rootfs, rel_path, elf, qemu_path,
                    tier=tier, policy=policy, shim_path=shim_path, log_path=log_path,
                    opts=opts, run_fn=run_fn,
                )
        except Exception as exc:  # one target's failure never aborts the stage
            log.debug("harness fuzz failed for %s", rel_path, exc_info=True)
            res.skipped.append(f"{rel_path}: {type(exc).__name__}: {exc}")
            continue

        res.iterations += iters
        if skip:
            res.skipped.append(skip)
            continue
        res.targets_fuzzed.append(rel_path)
        res.crashes.extend(crashes)
    return res


def _ensure_shim(shims: dict[tuple[str, str], str | None], elf: ElfInfo, workdir: str | None, build: bool) -> str | None:
    key = (elf.machine, elf.endian)
    if key in shims:
        return shims[key]
    if build and workdir:
        shims[key] = shimbuild.build_for(elf.machine, elf.endian, os.path.join(workdir, "shims"))
        return shims[key]
    shims[key] = None
    return None
