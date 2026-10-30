"""Phase C3 (minimal): a stdlib mutational network fuzzer for the live device.

This is the deliberately small first step of Phase C3. It mutates inputs to the
device's open TCP ports and watches for a crash — either a crash marker on the
serial console (a kernel oops/panic, a segfault logged by the service) or the
port going dead (the service stops accepting connections). A reproducing input
is recorded with every crash, as a base64 blob, so a human can replay it.

What this is **not** (yet): coverage-guided fuzzing. Real AFL++ qemu-mode /
boofuzz pull in heavy external dependencies and must be optional/runtime-detected
like qemu and radare2; harnessing the individual crashable binaries Phase A flags
(triaging a crash back to a binary through the LD_PRELOAD shim) is likewise
deferred to its own milestone. This module intentionally stays dependency-free
and dumb: a bounded, seeded, mutational black-box network fuzzer.

Safety: every connection is to a ``127.0.0.1`` slirp forward of the sandboxed
guest; the fuzzer is bounded by an iteration cap, a per-service wall-clock, and a
maximum input size; and it only ever *sends bytes to a socket* — no new deps, no
shell, no outbound network. It is gated behind its own ``scan --fuzz`` flag,
separate from ``--dynamic``, because it is the heaviest and most disruptive stage
(it tries to crash the device).
"""

from __future__ import annotations

import base64
import logging
import random
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from firefly.emulation.mutator import BAD_TOKENS as _BAD_TOKENS
from firefly.emulation.mutator import mutate as _mutate
from firefly.models import Finding, Severity

log = logging.getLogger(__name__)

# TCP services worth fuzzing. DNS is UDP and SSH is a robust handshake with low
# payoff for a dumb mutator, so both are left out.
_FUZZABLE = frozenset(
    {"http", "https", "http-alt", "https-alt", "http-admin", "upnp", "tr069", "telnet", "ftp"}
)

# Per-service seed inputs the mutator works from. HTTP-speaking services share
# the default HTTP seeds.
_SEEDS: dict[str | None, list[bytes]] = {
    "telnet": [b"root\r\n", b"admin\r\n"],
    "ftp": [b"USER root\r\n", b"LIST\r\n", b"RETR x\r\n"],
    None: [
        b"GET / HTTP/1.0\r\n\r\n",
        b"POST / HTTP/1.1\r\nContent-Length: 8\r\n\r\nAAAAAAAA",
        b"GET /cgi-bin/ HTTP/1.1\r\nHost: dev\r\n\r\n",
        b"\r\n",
    ],
}

# Serial-console strings that mean something crashed. Kernel-level markers are
# treated as more severe than a service segfault.
_CRASH_MARKERS: tuple[str, ...] = (
    "Kernel panic", "Oops", "Unable to handle kernel", "Internal error",
    "BUG:", "Call Trace", "segfault", "Unhandled fault",
    "general protection fault", "stack backtrace",
)


@dataclass
class FuzzOptions:
    iterations: int = 200          # mutated inputs per service (hard cap)
    wall_clock_s: float = 30.0     # ceiling on time spent per service
    max_input: int = 4096          # cap on a single mutated input
    connect_timeout_s: float = 3.0
    io_timeout_s: float = 2.0
    seed: int = 0                  # base RNG seed; per-port offset keeps runs reproducible


@dataclass
class Crash:
    service: str
    port: int
    kind: str          # "console:<marker>" or "port-dead"
    detail: str
    repro_b64: str     # base64 of the input that triggered it
    iteration: int


@dataclass
class FuzzResult:
    crashes: list[Crash] = field(default_factory=list)
    services_fuzzed: list[int] = field(default_factory=list)
    iterations: int = 0
    skipped: list[str] = field(default_factory=list)

    def to_artifact(self) -> dict[str, Any]:
        return {
            "iterations": self.iterations,
            "services_fuzzed": self.services_fuzzed,
            "crashes": [
                {
                    "service": c.service,
                    "port": c.port,
                    "kind": c.kind,
                    "detail": c.detail,
                    "repro_b64": c.repro_b64,
                    "iteration": c.iteration,
                }
                for c in self.crashes
            ],
            "skipped": self.skipped,
        }

    def to_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for c in self.crashes:
            kernel = "panic" in c.kind.lower() or "oops" in c.kind.lower() or "unable to handle" in c.kind.lower()
            console = c.kind.startswith("console")
            findings.append(
                Finding(
                    analyzer="fuzz",
                    title=f"Network input crashed the device: {c.service} (port {c.port})",
                    severity=Severity.CRITICAL if kernel else Severity.HIGH,
                    confidence="high" if console else "medium",
                    evidence=f"{c.kind} after {c.iteration} mutated input(s)",
                    description=(
                        f"Mutated input sent to port {c.port} ({c.service}) crashed the running "
                        f"device: {c.detail}. A network-reachable crash is a memory-safety / "
                        "denial-of-service bug worth triaging; a reproducing input is recorded "
                        "(base64) in the fuzz artifact."
                    ),
                    metadata={
                        "service": c.service,
                        "port": c.port,
                        "kind": c.kind,
                        "iteration": c.iteration,
                        "repro_b64": c.repro_b64,
                    },
                )
            )
        return findings


# --------------------------------------------------------------------------- mutation


def _crash_marker(text: str) -> str | None:
    for m in _CRASH_MARKERS:
        if m in text:
            return m
    return None


# --------------------------------------------------------------------------- socket I/O


def _send_once(host: str, port: int, data: bytes, opts: FuzzOptions) -> None:
    """Fire one input at the port; swallow every error (the point is to break it)."""
    try:
        s = socket.create_connection((host, port), timeout=opts.connect_timeout_s)
    except OSError:
        return
    try:
        s.settimeout(opts.io_timeout_s)
        s.sendall(data)
        try:
            s.recv(256)
        except OSError:
            pass
    except OSError:
        pass
    finally:
        s.close()


def _responsive(host: str, port: int, opts: FuzzOptions) -> bool:
    """Is the port still backed by a live service? Uses the same recv heuristic as
    the boot probe: data or a silent-but-held connection means alive; an empty EOF
    or a reset (slirp giving up on a dead guest) means dead."""
    try:
        s = socket.create_connection((host, port), timeout=opts.connect_timeout_s)
    except OSError:
        return False
    try:
        s.settimeout(opts.io_timeout_s)
        try:
            return bool(s.recv(64))
        except socket.timeout:
            return True
        except OSError:
            return False
    finally:
        s.close()


# --------------------------------------------------------------------------- fuzz loop


def fuzz_service(host: str, port: int, service: str, console_fn: Callable[[], str], opts: FuzzOptions) -> tuple[list[Crash], int, str]:
    """Fuzz one service. Returns (crashes, iterations_run, skip_reason).

    ``console_fn`` returns the device's serial console so far; a crash marker
    appearing *after* the baseline, or the port going dead, ends the run with a
    recorded reproducer. ``port`` is the value stored on the crash (callers pass
    the guest port) while ``host:port`` is what is actually connected to.
    """
    if not _responsive(host, port, opts):
        return [], 0, f"{service}/{port}: not responsive before fuzzing"

    baseline = len(console_fn())
    rng = random.Random(opts.seed + port)
    seeds = _SEEDS.get(service) or _SEEDS[None]
    deadline = time.monotonic() + opts.wall_clock_s
    crashes: list[Crash] = []
    it = 0
    while it < opts.iterations and time.monotonic() < deadline:
        it += 1
        data = _mutate(rng.choice(seeds), rng, opts.max_input)
        _send_once(host, port, data, opts)

        marker = _crash_marker(console_fn()[baseline:])
        if marker:
            crashes.append(Crash(service, port, f"console:{marker}", f"{marker!r} on the serial console", base64.b64encode(data).decode("ascii"), it))
            break
        # Require two consecutive dead checks to avoid a transient miss.
        if not _responsive(host, port, opts) and not _responsive(host, port, opts):
            crashes.append(Crash(service, port, "port-dead", "the service stopped accepting connections", base64.b64encode(data).decode("ascii"), it))
            break
    return crashes, it, ""


def run_fuzz(target: Any, open_ports: list[int], services: dict[int, str], opts: FuzzOptions | None = None) -> FuzzResult:
    """Fuzz every fuzzable open TCP port of a booted :class:`LiveTarget`.

    ``target`` needs ``host_port(guest_port) -> int`` and a ``console`` property
    (a stub suffices in tests). Crashes are reported against the *guest* port.
    """
    opts = opts or FuzzOptions()
    res = FuzzResult()
    for port in open_ports:
        service = services.get(port, "unknown")
        if service not in _FUZZABLE:
            continue
        host_port = target.host_port(port)
        crashes, iters, skip = fuzz_service("127.0.0.1", host_port, service, lambda: target.console, opts)
        res.iterations += iters
        if skip:
            res.skipped.append(skip)
            continue
        res.services_fuzzed.append(port)
        for c in crashes:
            c.port = port  # report the guest port, not the 127.0.0.1 forward
        res.crashes.extend(crashes)
    return res
