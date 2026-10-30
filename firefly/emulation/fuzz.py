"""Phase C3: a network fuzzer for the live device, with two engines.

It fuzzes the device's open TCP ports and watches for a crash — either a crash
marker on the serial console (a kernel oops/panic, a segfault logged by the
service) or the port going dead (the service stops accepting connections). A
reproducing input is recorded with every crash, as a base64 blob, so a human can
replay it.

Two engines, selected like Firefly's other heavy tools (qemu, radare2, AFL++):

* **stdlib** (always available, the default and the fallback): a bounded, seeded,
  dependency-free *mutational* black-box fuzzer — it mutates per-service seed
  inputs and fires them at the port.
* **boofuzz** (optional, runtime-detected): when the ``boofuzz`` package is
  importable it drives *structured protocol* fuzzing from a per-service request
  grammar, which reaches parser states a blind mutator rarely hits. boofuzz is
  never a hard dependency; if it is absent, or errors at runtime, the service
  falls back to the stdlib engine. Crash detection is shared: the same
  serial-console marker and port-death probe decide a crash for both engines, so
  the findings are identical whichever engine found them.

Safety: every connection is to a ``127.0.0.1`` slirp forward of the sandboxed
guest; the fuzzer is bounded by an iteration cap, a per-service wall-clock, and a
maximum input size; and it only ever *sends bytes to a socket* — no outbound
network, no shell. It is gated behind its own ``scan --fuzz`` flag, separate from
``--dynamic``, because it is the heaviest and most disruptive stage (it tries to
crash the device).
"""

from __future__ import annotations

import base64
import importlib.util
import logging
import random
import socket
import time
from dataclasses import dataclass, field
from typing import Any, Callable

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
    engine: str = "auto"           # "auto" | "stdlib" | "boofuzz"


@dataclass
class Crash:
    service: str
    port: int
    kind: str          # "console:<marker>" or "port-dead"
    detail: str
    repro_b64: str     # base64 of the input that triggered it
    iteration: int
    engine: str = "stdlib"   # which engine found it


@dataclass
class FuzzResult:
    crashes: list[Crash] = field(default_factory=list)
    services_fuzzed: list[int] = field(default_factory=list)
    iterations: int = 0
    skipped: list[str] = field(default_factory=list)
    engine: str = "stdlib"   # engine resolved for this run

    def to_artifact(self) -> dict[str, Any]:
        return {
            "engine": self.engine,
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
                    "engine": c.engine,
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


def _crash_detail(kind: str) -> str:
    """Human-readable detail for a crash kind, shared by both engines."""
    if kind.startswith("console:"):
        return f"{kind.split(':', 1)[1]!r} on the serial console"
    return "the service stopped accepting connections"


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
            crashes.append(Crash(service, port, f"console:{marker}", _crash_detail(f"console:{marker}"), base64.b64encode(data).decode("ascii"), it, "stdlib"))
            break
        # Require two consecutive dead checks to avoid a transient miss.
        if not _responsive(host, port, opts) and not _responsive(host, port, opts):
            crashes.append(Crash(service, port, "port-dead", _crash_detail("port-dead"), base64.b64encode(data).decode("ascii"), it, "stdlib"))
            break
    return crashes, it, ""


# --------------------------------------------------------------------------- boofuzz engine

# Per-service structured request grammar for the boofuzz engine: an ordered list
# of ``("static" | "fuzz", bytes)`` segments. Static parts are sent verbatim;
# fuzz parts are the fields boofuzz mutates. Kept as plain data so it can be
# built and tested without boofuzz installed; the driver translates it into
# boofuzz primitives.
_REQUEST_SPECS: dict[str | None, list[tuple[str, bytes]]] = {
    "ftp": [("static", b"USER "), ("fuzz", b"root"), ("static", b"\r\nPASS "), ("fuzz", b"x"), ("static", b"\r\n")],
    "telnet": [("fuzz", b"admin"), ("static", b"\r\n"), ("fuzz", b"password"), ("static", b"\r\n")],
    "upnp": [
        ("static", b"POST /ctl HTTP/1.1\r\nSOAPAction: \""), ("fuzz", b"urn:schemas-upnp-org:service:WANIPConnection:1#AddPortMapping"),
        ("static", b"\"\r\nContent-Type: text/xml\r\nContent-Length: 4\r\n\r\n<s>"), ("fuzz", b"AAAA"), ("static", b"</s>"),
    ],
    None: [  # HTTP-speaking services
        ("static", b"GET /"), ("fuzz", b"index.html"), ("static", b" HTTP/1.1\r\nHost: "), ("fuzz", b"dev"),
        ("static", b"\r\nUser-Agent: "), ("fuzz", b"firefly"), ("static", b"\r\n\r\n"),
    ],
}
_REQUEST_SPECS["tr069"] = _REQUEST_SPECS["upnp"]


def boofuzz_available() -> bool:
    """True when the optional ``boofuzz`` package can be imported."""
    try:
        return importlib.util.find_spec("boofuzz") is not None
    except (ImportError, ValueError):
        return False


def detect_net_engine(requested: str) -> tuple[str, str]:
    """Resolve the configured network-fuzz engine to one we can run.

    Returns ``(engine, reason)``; ``reason`` is non-empty only when a forced
    engine is unavailable and we fell back to the stdlib engine.
    """
    if requested == "boofuzz":
        return ("boofuzz", "") if boofuzz_available() else ("stdlib", "boofuzz not installed; using the stdlib engine")
    if requested == "stdlib":
        return "stdlib", ""
    return ("boofuzz", "") if boofuzz_available() else ("stdlib", "")  # auto


def _request_spec(service: str) -> list[tuple[str, bytes]]:
    return _REQUEST_SPECS.get(service) or _REQUEST_SPECS[None]


# A driver runs one boofuzz campaign and returns ``(crash_kind, repro, iterations)``.
# ``crash_kind`` is None when no crash was seen; ``iterations`` is -1 when boofuzz
# could not run at all (so the caller falls back to the stdlib engine). It is
# injectable so the orchestration is testable without boofuzz.
BoofuzzOutcome = tuple[str | None, bytes | None, int]
BoofuzzDriver = Callable[[str, int, list[tuple[str, bytes]], Callable[[bytes], str | None], FuzzOptions], BoofuzzOutcome]


def fuzz_service_boofuzz(
    host: str,
    port: int,
    service: str,
    console_fn: Callable[[], str],
    opts: FuzzOptions,
    driver: BoofuzzDriver | None = None,
) -> tuple[list[Crash], int, bool]:
    """Structured-protocol fuzz of one service via boofuzz.

    Returns ``(crashes, iterations, ran)``. ``ran`` is False when boofuzz could
    not drive the service at all, so the caller should fall back to the stdlib
    engine. Crash detection reuses the shared console-marker / port-death probe,
    so a boofuzz crash maps to exactly the same :class:`Crash` the stdlib engine
    would produce (tagged ``engine="boofuzz"``).
    """
    if not _responsive(host, port, opts):
        return [], 0, True  # ran (nothing to fuzz); caller records the skip like stdlib does
    baseline = len(console_fn())

    def probe(_last_sent: bytes) -> str | None:
        marker = _crash_marker(console_fn()[baseline:])
        if marker:
            return f"console:{marker}"
        if not _responsive(host, port, opts) and not _responsive(host, port, opts):
            return "port-dead"
        return None

    drive = driver or _default_boofuzz_driver
    kind, repro, iters = drive(host, port, _request_spec(service), probe, opts)
    if iters < 0:
        return [], 0, False  # boofuzz unavailable at runtime -> fall back
    if kind:
        crash = Crash(service, port, kind, _crash_detail(kind), base64.b64encode(repro or b"").decode("ascii"), max(1, iters), "boofuzz")
        return [crash], iters, True
    return [], iters, True


def _default_boofuzz_driver(host: str, port: int, spec: list[tuple[str, bytes]], probe: Callable[[bytes], str | None], opts: FuzzOptions) -> BoofuzzOutcome:
    """Drive a real boofuzz session, bounded, with the shared crash probe.

    Everything boofuzz is wrapped: a missing package or any API mismatch returns
    the ``-1`` "could not run" sentinel so the caller falls back to the stdlib
    engine. When the probe reports a crash after a test case, the mutated bytes
    boofuzz last transmitted are captured as the reproducer and the campaign
    stops.
    """
    state: dict[str, Any] = {"kind": None, "repro": None, "n": 0}
    try:
        import boofuzz  # noqa: PLC0415  (optional, runtime-detected)

        def _after(target=None, fuzz_data_logger=None, session=None, *args: Any, **kwargs: Any) -> None:
            state["n"] += 1
            last = b""
            try:
                last = bytes(getattr(session, "last_send", b"") or b"")
            except Exception:  # last_send shape varies across boofuzz versions
                last = b""
            kind = probe(last)
            if kind:
                state["kind"], state["repro"] = kind, last
                if session is not None:
                    session.end_session = True  # ask boofuzz to stop the campaign

        request = _build_boofuzz_request(boofuzz, spec)
        connection = boofuzz.TCPSocketConnection(host, port, send_timeout=opts.io_timeout_s, recv_timeout=opts.io_timeout_s)
        session = boofuzz.Session(
            target=boofuzz.Target(connection=connection),
            post_test_case_callbacks=[_after],
            sleep_time=0.0,
            keep_web_open=False,
        )
        session.connect(request)
        session.fuzz(max_depth=opts.iterations)
    except Exception as exc:  # boofuzz absent or an API change -> fall back cleanly
        log.debug("boofuzz engine unavailable for %s:%d: %s", host, port, exc)
        if state["kind"] is None:
            return None, None, -1
    return state["kind"], state["repro"], state["n"]


def _build_boofuzz_request(boofuzz: Any, spec: list[tuple[str, bytes]]) -> Any:
    """Translate a request spec into a boofuzz :class:`Request` of Static/Bytes."""
    children = []
    for i, (kind, data) in enumerate(spec):
        if kind == "static":
            children.append(boofuzz.Static(name=f"s{i}", default_value=data))
        else:
            children.append(boofuzz.Bytes(name=f"f{i}", default_value=data))
    return boofuzz.Request("req", children=children)


# --------------------------------------------------------------------------- orchestration


def run_fuzz(target: Any, open_ports: list[int], services: dict[int, str], opts: FuzzOptions | None = None) -> FuzzResult:
    """Fuzz every fuzzable open TCP port of a booted :class:`LiveTarget`.

    ``target`` needs ``host_port(guest_port) -> int`` and a ``console`` property
    (a stub suffices in tests). The engine is resolved once from ``opts.engine``
    ("auto" prefers boofuzz when it is importable, else the stdlib engine); a
    service that boofuzz cannot drive at runtime falls back to the stdlib engine.
    Crashes are reported against the *guest* port.
    """
    opts = opts or FuzzOptions()
    engine, fallback_reason = detect_net_engine(opts.engine)
    res = FuzzResult(engine=engine)
    if fallback_reason:
        res.skipped.append(fallback_reason)
    for port in open_ports:
        service = services.get(port, "unknown")
        if service not in _FUZZABLE:
            continue
        host_port = target.host_port(port)
        console_fn = lambda: target.console
        # One responsiveness gate for both engines, so a dead port is skipped the
        # same way regardless of which engine was chosen.
        if not _responsive("127.0.0.1", host_port, opts):
            res.skipped.append(f"{service}/{port}: not responsive before fuzzing")
            continue

        if engine == "boofuzz":
            crashes, iters, ran = fuzz_service_boofuzz("127.0.0.1", host_port, service, console_fn, opts)
            if not ran:  # boofuzz could not drive this service at runtime -> stdlib
                res.skipped.append(f"{service}/{port}: boofuzz unavailable at runtime, used stdlib")
                crashes, iters, _skip = fuzz_service("127.0.0.1", host_port, service, console_fn, opts)
        else:
            crashes, iters, _skip = fuzz_service("127.0.0.1", host_port, service, console_fn, opts)

        res.iterations += iters
        res.services_fuzzed.append(port)
        for c in crashes:
            c.port = port  # report the guest port, not the 127.0.0.1 forward
        res.crashes.extend(crashes)
    return res
