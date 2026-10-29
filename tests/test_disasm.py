"""Tests for the optional radare2 call-graph backend.

These never invoke radare2: the subprocess boundary is stubbed, so the suite
runs the same with or without radare2 installed (CI has none). The pure graph
logic is tested against a call graph shaped exactly like radare2's ``agCj``.
"""

from __future__ import annotations

from firefly import disasm

# A call graph in agCj shape (already parsed to {caller: {callees}}):
#   entry0 -> main -> handle_request -> {recv (input), inflate (vuln leaf)}
#   util -> {getenv (input), BN_mod_sqrt (vuln leaf)}   (util not reached from entry0)
#   dead -> SHA1_Init (vuln leaf)                        (dead unreachable from anything)
GRAPH = {
    "entry0": {"sym.main"},
    "sym.main": {"sym.handle_request"},
    "sym.handle_request": {"sym.imp.recv", "sym.inflate"},
    "sym.util": {"sym.imp.getenv", "sym.BN_mod_sqrt"},
    "sym.dead": {"sym.SHA1_Init"},
}


def test_basename_strips_r2_prefixes():
    assert disasm._basename("sym.imp.recv") == "recv"
    assert disasm._basename("sym.inflate") == "inflate"
    assert disasm._basename("fcn.14001bdac") == "14001bdac"
    assert disasm._basename("BN_mod_sqrt") == "BN_mod_sqrt"


def test_reachable_from_entry_and_input():
    # inflate: reached from entry0 (live) and from the recv-caller (attacker)
    assert disasm.function_reachable(GRAPH, {"inflate"}) == (True, True)


def test_reachable_from_input_only():
    # BN_mod_sqrt: only util reaches it, and util isn't reached from entry0;
    # but util consumes getenv -> reachable from input, not from the entrypoint
    assert disasm.function_reachable(GRAPH, {"BN_mod_sqrt"}) == (False, True)


def test_unreachable_function():
    # SHA1_Init sits behind dead code reached from neither entry nor input
    assert disasm.function_reachable(GRAPH, {"SHA1_Init"}) == (False, False)


def test_absent_function_is_not_reachable():
    assert disasm.function_reachable(GRAPH, {"not_in_this_binary"}) == (False, False)


def test_target_does_not_reach_itself():
    # a self-recursive vuln function must not count as reaching itself
    g = {"sym.main": {"sym.inflate"}, "sym.inflate": {"sym.inflate"}}
    # inflate is reached from main (entry-like? main is an entry name) -> from_entry True
    assert disasm.function_reachable(g, {"inflate"})[0] is True
    # with no entry/input path, self-recursion alone is not reachability
    g2 = {"sym.inflate": {"sym.inflate"}}
    assert disasm.function_reachable(g2, {"inflate"}) == (False, False)


# --------------------------------------------------------------------------- run/parse/degrade


def test_call_graph_parses_agcj(monkeypatch):
    agcj = '[{"name":"entry0","size":10,"imports":["sym.main"]},{"name":"sym.main","size":5,"imports":["sym.inflate"]}]'
    monkeypatch.setattr(disasm, "radare2_path", lambda: "radare2")
    monkeypatch.setattr(disasm, "_run", lambda *a, **k: "WARN leading noise\n" + agcj)
    g = disasm.call_graph("x.bin")
    assert g == {"entry0": {"sym.main"}, "sym.main": {"sym.inflate"}}


def test_call_graph_degrades_without_radare2(monkeypatch):
    monkeypatch.setattr(disasm, "radare2_path", lambda: None)
    assert disasm.call_graph("x.bin") is None


def test_call_graph_degrades_on_garbage(monkeypatch):
    monkeypatch.setattr(disasm, "radare2_path", lambda: "radare2")
    monkeypatch.setattr(disasm, "_run", lambda *a, **k: "not json at all")
    assert disasm.call_graph("x.bin") is None


def test_radare2_path_env_override(monkeypatch, tmp_path):
    exe = tmp_path / "radare2"
    exe.write_text("")
    monkeypatch.setenv("FIREFLY_RADARE2", str(exe))
    assert disasm.radare2_path() == str(exe)
    monkeypatch.setenv("FIREFLY_RADARE2", str(tmp_path / "missing"))
    assert disasm.radare2_path() is None
