"""Data types produced by the emulation stage.

These are kept separate from :mod:`firefly.models` because emulation is an
opt-in stage that *executes* binaries, not a static analyzer. The result is
serialised into the scan report's ``artifacts`` section (plain dicts) and also
converted into ordinary :class:`~firefly.models.Finding` objects so emulation
evidence shows up alongside the static findings.
"""

from __future__ import annotations

import signal
from dataclasses import dataclass, field
from typing import Any

from firefly.models import Finding, Severity

# Signals that mean the binary crashed on a memory-safety or illegal-instruction
# fault rather than being stopped by us. SIGKILL is excluded: that is normally
# our timeout or an out-of-memory kill, not a bug in the binary.
# Built with getattr because Windows' signal module lacks SIGBUS/SIGSYS; the
# numeric fallbacks are the standard Linux values, which is what matters since
# emulation only ever runs on Linux.
CRASH_SIGNALS = {
    getattr(signal, "SIGSEGV", 11): "SIGSEGV",
    getattr(signal, "SIGABRT", 6): "SIGABRT",
    getattr(signal, "SIGBUS", 7): "SIGBUS",
    getattr(signal, "SIGILL", 4): "SIGILL",
    getattr(signal, "SIGFPE", 8): "SIGFPE",
    getattr(signal, "SIGSYS", 31): "SIGSYS",
}


@dataclass
class BinaryRun:
    """The outcome of running one binary once under emulation."""

    path: str  # relative to the scan root
    arch: str
    qemu: str  # the qemu-user program used
    args: list[str] = field(default_factory=list)
    returncode: int | None = None
    term_signal: int | None = None  # POSIX signal that killed it, if any
    timed_out: bool = False
    duration_s: float = 0.0
    stdout_tail: str = ""
    stderr_tail: str = ""
    # Observed at runtime through the LD_PRELOAD shim (empty if the shim was
    # not built for this architecture).
    commands: list[str] = field(default_factory=list)
    opened_paths: list[str] = field(default_factory=list)
    error: str | None = None  # set when the binary could not be launched at all

    @property
    def crashed(self) -> bool:
        return self.term_signal in CRASH_SIGNALS

    @property
    def signal_name(self) -> str | None:
        if self.term_signal is None:
            return None
        return CRASH_SIGNALS.get(self.term_signal) or f"signal {self.term_signal}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "arch": self.arch,
            "qemu": self.qemu,
            "args": self.args,
            "returncode": self.returncode,
            "signal": self.signal_name,
            "timed_out": self.timed_out,
            "crashed": self.crashed,
            "duration_s": round(self.duration_s, 3),
            "commands": self.commands,
            "opened_paths": self.opened_paths,
            "error": self.error,
        }


@dataclass
class EmulationResult:
    """Everything the emulation stage produced (or why it produced nothing)."""

    available: bool
    reason: str = ""  # why emulation did not run, when available is False
    sandbox: str = "none"  # "bwrap" | "rlimit-only" | "none"
    qemu_found: dict[str, str] = field(default_factory=dict)  # arch -> qemu path
    runs: list[BinaryRun] = field(default_factory=list)
    candidates: int = 0  # binaries selected for emulation
    skipped: int = 0  # candidates skipped (no qemu for arch, launch error)

    def to_artifact(self) -> dict[str, Any]:
        return {
            "available": self.available,
            "reason": self.reason,
            "sandbox": self.sandbox,
            "qemu_found": self.qemu_found,
            "candidates": self.candidates,
            "skipped": self.skipped,
            "runs": [r.to_dict() for r in self.runs],
        }

    def to_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for run in self.runs:
            if run.crashed:
                findings.append(
                    Finding(
                        analyzer="emulation",
                        title=f"Binary crashed under emulation: {run.path} ({run.signal_name})",
                        severity=Severity.HIGH,
                        confidence="medium",
                        path=run.path,
                        evidence=(run.stderr_tail or run.stdout_tail or "")[:240] or None,
                        description=(
                            f"{run.path} terminated with {run.signal_name} when run under "
                            f"{run.qemu} with args {run.args or '(none)'}. A crash on launch or on "
                            "trivial input is a strong signal of a memory-safety defect worth a "
                            "closer look (and a candidate for fuzzing)."
                        ),
                        metadata={"signal": run.signal_name, "args": run.args, "qemu": run.qemu},
                    )
                )
            # Runtime command execution observed through the shim: a binary that
            # shells out is a command-injection candidate.
            for cmd in run.commands:
                findings.append(
                    Finding(
                        analyzer="emulation",
                        title=f"Binary executed a shell command at runtime: {run.path}",
                        severity=Severity.MEDIUM,
                        confidence="medium",
                        path=run.path,
                        evidence=cmd[:240],
                        description=(
                            f"{run.path} called system()/exec() at runtime. If any part of this "
                            "command string is attacker-controlled this is a command-injection sink."
                        ),
                        metadata={"command": cmd[:500], "qemu": run.qemu},
                    )
                )
        return findings
