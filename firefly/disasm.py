"""Optional radare2 backend: a call graph for the static analyzers.

radare2 is an **optional, runtime-detected external tool**, in the same spirit
as unblob and qemu: if it isn't installed the callers degrade gracefully (the
symbol-presence reachability heuristic still runs). radare2 only *reads* the
binary — it does not execute firmware — but full analysis (`aaa`) is heavy, so
the call-graph path is opt-in (``scan --deep-reachability``).

The firmware binary is attacker-controlled, so radare2 is always invoked with an
argv list (never a shell string) and a wall-clock timeout; any failure, timeout
or unparseable output degrades to ``None`` rather than raising.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from collections import deque

# Imported symbols that mark a function as consuming externally-controlled input.
# A vulnerable function reachable from one of these is reachable from an attacker.
INPUT_SOURCE_SYMBOLS = frozenset(
    {
        "recv", "recvfrom", "recvmsg", "read", "accept", "accept4", "fgets", "fread",
        "getenv", "scanf", "__isoc99_scanf", "fscanf", "nvram_get", "nvram_safe_get",
        "websGetVar", "webGetVarString", "SSL_read", "BIO_read",
    }
)
# Function names that are entrypoints in their own right.
ENTRY_NAMES = frozenset({"entry0", "main", "sym.main", "sym.entry0"})

_PREFIXES = ("sym.imp.", "sym.", "fcn.", "sub.", "imp.", "loc.", "dbg.", "func.")


def radare2_path() -> str | None:
    """The radare2 executable to use: ``$FIREFLY_RADARE2`` or one on ``PATH``."""
    override = os.environ.get("FIREFLY_RADARE2")
    if override:
        return override if os.path.isfile(override) else None
    return shutil.which("radare2")


def _run(r2: str, binary: str, commands: str, timeout: float) -> str | None:
    # radare2 has no "--" end-of-options token; pass an absolute path, which can
    # never start with "-", so a hostile firmware filename can't become a flag.
    try:
        proc = subprocess.run(
            [r2, "-q", "-e", "scr.color=0", "-c", commands, os.path.abspath(binary)],
            capture_output=True,
            text=True,
            errors="replace",
            timeout=timeout,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    return proc.stdout or None


def _basename(name: str) -> str:
    """The bare symbol name r2 wraps in prefixes (``sym.imp.recv`` -> ``recv``)."""
    for p in _PREFIXES:
        if name.startswith(p):
            name = name[len(p):]
    return name.split(".")[-1] if "." in name else name


def call_graph(binary: str, *, timeout: float = 180.0) -> dict[str, set[str]] | None:
    """``{caller name: {callee names}}`` from radare2's global call graph.

    Returns None when radare2 is unavailable or analysis fails/times out, so the
    caller can fall back to the lighter heuristic.
    """
    r2 = radare2_path()
    if r2 is None:
        return None
    out = _run(r2, binary, "aaa;agCj", timeout)
    if not out:
        return None
    start = out.find("[")
    if start < 0:
        return None
    try:
        nodes = json.loads(out[start:])
    except (json.JSONDecodeError, ValueError):
        return None
    if not isinstance(nodes, list):
        return None
    graph: dict[str, set[str]] = {}
    for node in nodes:
        if isinstance(node, dict) and node.get("name"):
            graph[node["name"]] = {c for c in (node.get("imports") or []) if isinstance(c, str)}
    return graph


def _nodes_named(graph: dict[str, set[str]], wanted: set[str]) -> set[str]:
    """Names in the graph whose bare symbol is one of ``wanted``.

    Considers both callers (keys) and callees (edge targets): a vulnerable
    function is often a leaf that only ever appears as something's callee.
    """
    names = set(graph)
    for callees in graph.values():
        names |= callees
    return {name for name in names if _basename(name) in wanted}


def reachable_from(graph: dict[str, set[str]], sources: set[str], targets: set[str]) -> bool:
    """True if any ``targets`` node is reachable from any ``sources`` node."""
    if not sources or not targets:
        return False
    seen = set(sources)
    queue = deque(sources)
    while queue:
        cur = queue.popleft()
        for callee in graph.get(cur, ()):
            if callee in targets:
                return True
            if callee not in seen:
                seen.add(callee)
                queue.append(callee)
    return False


def function_reachable(graph: dict[str, set[str]], function_names: set[str]) -> tuple[bool, bool]:
    """Is a vulnerable function reachable in the call graph?

    Returns ``(reachable_from_entry, reachable_from_input)`` — two independent
    signals: whether any target function is reachable from an entrypoint (live
    code), and whether it is reachable from a function that consumes external
    input (attacker-reachable, the stronger signal). Target nodes are excluded
    from the source sets so a function never counts as reaching itself.
    """
    targets = _nodes_named(graph, {_basename(n) for n in function_names})
    if not targets:
        return False, False
    entries = {n for n in graph if _basename(n) in ENTRY_NAMES or n in ENTRY_NAMES} - targets
    input_sources = {n for n, callees in graph.items() if any(_basename(c) in INPUT_SOURCE_SYMBOLS for c in callees)} - targets
    return reachable_from(graph, entries, targets), reachable_from(graph, input_sources, targets)
