"""Reachability-aware CVE triage.

A version match alone says a vulnerable *version* of a library is present; it
does not say the vulnerable *code* is. If a build compiled the affected feature
out (or the firmware links only a safe subset), the CVE is a false positive that
buries the real ones.

This module checks whether a CVE's vulnerable function(s) are observable in the
matched component's binaries — as a defined/exported symbol or an imported one,
both read by :mod:`firefly.elf`. The result feeds the CVE analyzer's existing
confidence model: a function that is nowhere to be seen *down-ranks* the finding
(with a reason), it never drops or clears it. Absence is a hint, not proof:
inlining, stripping and static linking can hide a function that is really there,
so a binary whose defined symbols were stripped is reported as ``unknown`` (we
only conclude ``not_present`` when a full symbol table was actually readable).

Scope: this is symbol presence/import, not call-graph reachability (it does not
prove a path from an entrypoint to the function). Only CVEs listed in
``data/cve_functions.json`` are triaged; everything else is left untouched.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass

from firefly.elf import parse_file

_DEFAULT_PATH = os.path.join(os.path.dirname(__file__), "data", "cve_functions.json")


def load_cve_functions(path: str | None = None) -> dict[str, dict[str, list[str]]]:
    """Load the product -> {cve_id: [functions]} map. Missing/garbled -> {}."""
    try:
        with open(path or _DEFAULT_PATH, encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, json.JSONDecodeError):
        return {}
    products = data.get("products") if isinstance(data, dict) else None
    if not isinstance(products, dict):
        return {}
    return {str(product).lower(): cves for product, cves in products.items()}


@dataclass
class Reachability:
    status: str  # "reachable" | "not_present" | "unknown"
    functions: list[str]  # the CVE's vulnerable functions we have data for
    present: list[str]  # which of them were observed in the binaries


def classify(cve: str, product: str, observed: set[str], known: bool, table: dict[str, dict[str, list[str]]]) -> Reachability:
    """Decide whether a CVE's vulnerable code is present in a component.

    ``observed`` are the symbols seen across the component's binaries and
    ``known`` is whether any symbol table was readable at all — when nothing was
    readable we can't conclude anything, so the result is ``unknown``.
    """
    funcs = table.get(product.lower(), {}).get(cve)
    if not funcs:
        return Reachability("unknown", [], [])
    if not known:
        return Reachability("unknown", list(funcs), [])
    present = [f for f in funcs if f in observed]
    return Reachability("reachable" if present else "not_present", list(funcs), present)


def component_symbols(paths: list[str], inventory) -> tuple[set[str], bool]:
    """Observed function names across a component's ELF binaries, and whether we
    could actually see the binaries' *defined* functions.

    ``observed`` unions defined/exported names (symbol tables) and imported names
    (dynamic undefined symbols). The second return value is True only when a full
    symbol table (``.symtab``) survived on at least one binary — i.e. we could
    enumerate its internal defined functions. Without that we must not conclude a
    function is absent: a stripped binary that merely imports libc, or whose
    local symbols were removed, would otherwise falsely read as not-present.
    """
    observed: set[str] = set()
    defined_visible = False
    for rel in paths:
        rec = inventory.get(rel)
        if rec is None or not rec.is_executable_code:
            continue
        info = parse_file(inventory.abspath(rec), rec.size)  # one parse; returns None on any error
        if info is None:
            continue
        observed |= info.defined_functions
        observed |= info.imported_functions
        if not info.stripped:
            defined_visible = True
    return observed, defined_visible
