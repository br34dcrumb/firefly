"""Tests for the Phase C3 minimal network fuzzer (firefly/emulation/fuzz.py).

No qemu: the mutator and crash detection are exercised directly, the socket loop
runs against a throwaway stdlib TCP stub, and the port-dead path is driven by
stubbing the liveness check. They pass on any OS.
"""

from __future__ import annotations

import base64
import random
import socketserver
import threading

import pytest

from firefly.emulation import fuzz
from firefly.emulation.fuzz import (
    Crash,
    FuzzOptions,
    FuzzResult,
    _crash_marker,
    _mutate,
    fuzz_service,
    run_fuzz,
)
from firefly.models import Severity

_OPTS = FuzzOptions(iterations=6, wall_clock_s=10.0, io_timeout_s=0.3, connect_timeout_s=0.5, max_input=256, seed=1)


# --------------------------------------------------------------------------- mutation / markers


def test_mutate_is_deterministic_and_bounded():
    a = _mutate(b"GET / HTTP/1.0\r\n\r\n", random.Random(42), 128)
    b = _mutate(b"GET / HTTP/1.0\r\n\r\n", random.Random(42), 128)
    assert a == b                      # same seed -> same mutation (reproducible)
    assert 0 < len(a) <= 128           # never empty, never over the cap
    assert isinstance(a, bytes)


def test_mutate_handles_empty_seed():
    assert _mutate(b"", random.Random(1), 64)  # non-empty result, no crash


def test_crash_marker_matches_kernel_and_service_crashes():
    assert _crash_marker("...\nKernel panic - not syncing") == "Kernel panic"
    assert _crash_marker("httpd[123]: segfault at 0") == "segfault"
    assert _crash_marker("all good, login:") is None


# --------------------------------------------------------------------------- stub TCP server


class _ByteHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.server.hits += 1  # type: ignore[attr-defined]
        try:
            self.request.sendall(b"x")  # a byte so the liveness recv returns at once
        except OSError:
            pass


@pytest.fixture
def tcp_server():
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _ByteHandler)
    srv.hits = 0  # type: ignore[attr-defined]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv
    finally:
        srv.shutdown()
        t.join(timeout=2.0)


# --------------------------------------------------------------------------- fuzz_service


def test_fuzz_service_skips_dead_port():
    crashes, iters, skip = fuzz_service("127.0.0.1", 1, "http", lambda: "", _OPTS)
    assert crashes == [] and iters == 0 and "not responsive" in skip


def test_fuzz_service_healthy_runs_all_iterations_without_crash(tcp_server):
    port = tcp_server.server_address[1]
    crashes, iters, skip = fuzz_service("127.0.0.1", port, "http", lambda: "", _OPTS)
    assert skip == "" and crashes == [] and iters == _OPTS.iterations


def test_fuzz_service_detects_console_crash(tcp_server):
    port = tcp_server.server_address[1]
    # The serial console "shows" a panic once a few connections have landed.
    console = lambda: "Kernel panic - not syncing: fault" if tcp_server.hits >= 4 else ""
    crashes, iters, skip = fuzz_service("127.0.0.1", port, "http", console, _OPTS)
    assert skip == "" and len(crashes) == 1
    c = crashes[0]
    assert c.kind == "console:Kernel panic"
    assert base64.b64decode(c.repro_b64)  # a usable reproducer was recorded
    assert c.iteration >= 1


def test_fuzz_service_detects_port_death(monkeypatch):
    # Liveness: True once (baseline), dead on every later check.
    calls = {"n": 0}

    def fake_responsive(host, port, opts):
        calls["n"] += 1
        return calls["n"] == 1

    monkeypatch.setattr(fuzz, "_responsive", fake_responsive)
    monkeypatch.setattr(fuzz, "_send_once", lambda *a, **k: None)

    crashes, iters, skip = fuzz_service("127.0.0.1", 4567, "ftp", lambda: "", _OPTS)
    assert skip == "" and len(crashes) == 1
    assert crashes[0].kind == "port-dead" and crashes[0].iteration == 1


# --------------------------------------------------------------------------- orchestration


class _StubTarget:
    def __init__(self, mapping, console_fn=lambda: ""):
        self._m = mapping
        self._console_fn = console_fn

    def host_port(self, guest_port):
        return self._m[guest_port]

    @property
    def console(self):
        return self._console_fn()


def test_run_fuzz_skips_non_tcp_services_and_fuzzes_the_rest(tcp_server):
    port = tcp_server.server_address[1]
    target = _StubTarget({80: port, 53: 9})  # 53/dns forward points at a dead port
    res = run_fuzz(target, [80, 53], {80: "http", 53: "dns"}, _OPTS)
    assert res.services_fuzzed == [80]          # dns is not fuzzable, 80 was fuzzed
    assert res.crashes == [] and res.iterations == _OPTS.iterations


def test_run_fuzz_reports_crash_against_guest_port(tcp_server):
    port = tcp_server.server_address[1]
    # Panic appears on the console once a few connections have landed.
    target = _StubTarget({80: port}, console_fn=lambda: "Oops - BUG: kernel" if tcp_server.hits >= 4 else "")
    res = run_fuzz(target, [80], {80: "http"}, _OPTS)
    assert len(res.crashes) == 1
    assert res.crashes[0].port == 80  # the guest port, not the 127.0.0.1 forward


# --------------------------------------------------------------------------- findings / artifact


def test_to_findings_severity_by_crash_kind():
    res = FuzzResult(
        crashes=[
            Crash("http", 80, "console:Kernel panic", "panic", base64.b64encode(b"x").decode(), 3),
            Crash("ftp", 21, "console:segfault", "segfault", base64.b64encode(b"y").decode(), 5),
            Crash("telnet", 23, "port-dead", "dead", base64.b64encode(b"z").decode(), 2),
        ]
    )
    by_title = {f.title: f for f in res.to_findings()}
    kernel = next(f for f in res.to_findings() if f.metadata["port"] == 80)
    seg = next(f for f in res.to_findings() if f.metadata["port"] == 21)
    dead = next(f for f in res.to_findings() if f.metadata["port"] == 23)
    assert kernel.severity is Severity.CRITICAL and kernel.confidence == "high"
    assert seg.severity is Severity.HIGH and seg.confidence == "high"
    assert dead.severity is Severity.HIGH and dead.confidence == "medium"
    assert all("repro_b64" in f.metadata for f in by_title.values())


def test_artifact_shape():
    res = FuzzResult(
        crashes=[Crash("http", 80, "port-dead", "dead", base64.b64encode(b"x").decode(), 1)],
        services_fuzzed=[80],
        iterations=6,
        skipped=["ssh/22: n/a"],
    )
    art = res.to_artifact()
    assert art["iterations"] == 6 and art["services_fuzzed"] == [80]
    assert art["crashes"][0]["kind"] == "port-dead" and art["crashes"][0]["repro_b64"]
    assert art["skipped"]
