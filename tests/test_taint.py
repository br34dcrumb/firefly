"""Tests for --deep-taint: input->sink call-graph reachability in dangerfns.

radare2 is never invoked here — ``firefly.disasm.call_graph`` is stubbed, so
the suite runs the same with or without radare2 installed. The pure graph logic
is tested against a call graph shaped exactly like radare2's ``agCj``.
"""

from __future__ import annotations

from firefly import disasm
from firefly.analyzers import ScanContext
from firefly.analyzers.dangerfns import DangerousFunctionsAnalyzer
from firefly.inventory import Inventory
from firefly.models import Severity

from elfbuild import build_elf

# agCj-shaped graph (already parsed to {caller: {callees}}):
#   handler calls recv (input source) and system (sink)  -> input reaches system
#   util calls getenv (input source) but never reaches strcpy
#   lonely calls strcpy, but nothing with input ever reaches lonely
GRAPH = {
    "entry0": {"sym.main"},
    "sym.main": {"sym.handler", "sym.util"},
    "sym.handler": {"sym.imp.recv", "sym.imp.system"},
    "sym.util": {"sym.imp.getenv"},
    "sym.lonely": {"sym.imp.strcpy"},
}


# --------------------------------------------------------------------------- pure helper


def test_input_reaches_sink_found():
    # system is called by handler, which also consumes recv -> reachable
    assert disasm.input_reaches_sinks(GRAPH, {"system"}) == ["system"]


def test_input_does_not_reach_isolated_sink():
    # strcpy sits behind lonely, which no input-consuming function reaches
    assert disasm.input_reaches_sinks(GRAPH, {"strcpy"}) == []


def test_input_reaches_sink_filters_to_reachable_subset():
    # of the two sinks asked about, only system has an input path
    assert disasm.input_reaches_sinks(GRAPH, {"system", "strcpy"}) == ["system"]


def test_input_reaches_sink_absent_sink():
    assert disasm.input_reaches_sinks(GRAPH, {"not_imported_here"}) == []


def test_input_reaches_sink_no_input_source():
    # same sink wiring but nothing consumes external input -> no path
    g = {"sym.main": {"sym.handler"}, "sym.handler": {"sym.imp.system"}}
    assert disasm.input_reaches_sinks(g, {"system"}) == []


# --------------------------------------------------------------------------- analyzer integration


def _tree(tmp_path, files: dict[str, bytes]) -> Inventory:
    root = tmp_path / "root"
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return Inventory.build(str(root))


def _ctx(inv, *, deep_taint=False):
    ctx = ScanContext(firmware_path="x", workdir="x", jobs=1, inventory=inv)
    ctx.deep_taint = deep_taint
    return ctx


def test_deep_taint_confirms_path_and_raises_severity(tmp_path, monkeypatch):
    # system is HIGH on its own; a confirmed input->system path bumps it to
    # CRITICAL, forces high confidence, and records the reachable sink.
    inv = _tree(tmp_path, {"usr/sbin/cgi": build_elf(imports=["system", "recv"])})
    monkeypatch.setattr("firefly.disasm.call_graph", lambda path, **k: GRAPH)
    finding = DangerousFunctionsAnalyzer().run(_ctx(inv, deep_taint=True)).findings[0]
    assert finding.metadata["taint"] == {"input_reaches_sink": True, "sinks": ["system"]}
    assert finding.severity is Severity.CRITICAL
    assert finding.confidence == "high"
    assert "External input can reach system" in finding.description


def test_deep_taint_no_path_leaves_finding_unchanged(tmp_path, monkeypatch):
    # strcpy in a network-facing binary is MEDIUM; with no input->strcpy path the
    # taint result is recorded but severity/confidence are not changed.
    inv = _tree(tmp_path, {"usr/sbin/netd": build_elf(imports=["strcpy", "recv"])})
    monkeypatch.setattr("firefly.disasm.call_graph", lambda path, **k: GRAPH)
    finding = DangerousFunctionsAnalyzer().run(_ctx(inv, deep_taint=True)).findings[0]
    assert finding.metadata["taint"] == {"input_reaches_sink": False, "sinks": []}
    assert finding.severity is Severity.MEDIUM
    assert "External input can reach" not in finding.description


def test_deep_taint_degrades_when_radare2_absent(tmp_path, monkeypatch):
    # radare2 unavailable -> call_graph None -> no taint metadata, finding stands.
    inv = _tree(tmp_path, {"usr/sbin/cgi": build_elf(imports=["system", "recv"])})
    monkeypatch.setattr("firefly.disasm.call_graph", lambda path, **k: None)
    finding = DangerousFunctionsAnalyzer().run(_ctx(inv, deep_taint=True)).findings[0]
    assert "taint" not in finding.metadata
    assert finding.severity is Severity.HIGH


def test_without_deep_taint_radare2_is_never_called(tmp_path, monkeypatch):
    # The default path must be identical to today's behavior and never touch
    # radare2 (it is heavy and gated behind the flag).
    inv = _tree(tmp_path, {"usr/sbin/cgi": build_elf(imports=["system", "recv"])})

    def _boom(*a, **k):
        raise AssertionError("call_graph must not be called without --deep-taint")

    monkeypatch.setattr("firefly.disasm.call_graph", _boom)
    finding = DangerousFunctionsAnalyzer().run(_ctx(inv)).findings[0]
    assert "taint" not in finding.metadata
    assert finding.severity is Severity.HIGH
