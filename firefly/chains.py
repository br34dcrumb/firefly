"""Correlate a scan report's findings into ranked attack chains.

Firefly's analyzers each report an isolated weakness. A human triaging a report
still has to join them up — *"telnet is exposed, the root account has no password,
and there's a reachable busybox CVE, so that's remote root"*. This module does
that join mechanically and offline (no LLM): it classifies each finding into a
kill-chain stage, links steps that share a pivot, and ranks the resulting chains
so the few that matter rise to the top.

The stages, in order:

* **entry**   — a network-reachable foothold (an exposed service, a live port, a
                binary confirmed reachable on the running device);
* **access**  — an authentication weakness (empty/default/hardcoded credentials,
                a Phase C-confirmed login);
* **exploit** — a code-level flaw reachable from input (a reachable CVE, an input
                that reaches a dangerous sink, a runtime command-injection sink);
* **impact**  — a demonstrated outcome (a harness/network crash, a bare-launch
                crash — memory-safety / denial-of-service).

A chain holds at most one node per stage and at most one *binary* (binary-scoped
nodes must share a path; device-scoped nodes — services, credentials, network
crashes — link to anything on the same device), so every chain is a single,
coherent path. Chains are scored by the severity × confidence of their steps,
with a weight for the number of distinct stages and a strong bonus for steps a
Phase C dynamic stage **confirmed** (a confirmed login, a confirmed crash, a KEV
or reachable CVE). This is a correlation heuristic over automated findings, not a
proven exploit: it is explicitly for prioritisation, and a human confirms it.
"""

from __future__ import annotations

import hashlib
from typing import Any

from firefly.models import Severity
from firefly.report import CONFIDENCE_RANK

# Kill-chain stages in order; a chain reads from the lowest present stage up.
_STAGES = ("entry", "access", "exploit", "impact")
_STAGE_INDEX = {s: i for i, s in enumerate(_STAGES)}

_SEV_WEIGHT = {"critical": 5.0, "high": 4.0, "medium": 3.0, "low": 2.0, "info": 1.0}
_CONF_WEIGHT = {"high": 1.0, "medium": 0.6, "low": 0.3}

# Analyzers whose findings are device-scoped (they describe the whole device, not
# one binary): a telnet service, a shared credential, a crash seen over the wire.
# Everything else that chains is binary-scoped and pivots on its `path`.
_DEVICE_SCOPED = frozenset({"services", "accounts", "credentials", "auth", "fuzz", "crawl", "surface"})

DISCLAIMER = (
    "Attack chains are a correlation heuristic over automated findings, for "
    "prioritisation only — not a proven exploit. A human must confirm each chain."
)


def _stage(f: dict[str, Any]) -> str | None:
    """The kill-chain stage a finding belongs to, or None if it does not chain."""
    a = f.get("analyzer")
    title = (f.get("title") or "").lower()
    meta = f.get("metadata") or {}
    if a == "services" or a in ("crawl", "surface"):
        return "entry"
    if a in ("accounts", "credentials", "auth"):
        return "access"
    if a == "cves":
        return "exploit"
    if a == "dangerfns":
        # Only a sink that input can actually reach is an exploit step; a bare
        # dangerous-function lead is too weak to chain.
        return "exploit" if (meta.get("taint") or {}).get("input_reaches_sink") else None
    if a == "harness" or a == "fuzz":
        return "impact"
    if a == "emulation":
        if "shell command" in title:
            return "exploit"  # a runtime command-injection sink
        if "reachable on the running device" in title:
            return "entry"
        if meta.get("confirmed_fuzz_crash") or meta.get("bare_launch"):
            return "impact"
    return None


def _is_binary_scoped(f: dict[str, Any]) -> bool:
    return f.get("analyzer") not in _DEVICE_SCOPED


def _confirmed(f: dict[str, Any]) -> bool:
    """Did a dynamic stage (or a KEV/reachable CVE) corroborate this finding?"""
    meta = f.get("metadata") or {}
    reach = (meta.get("reachability") or {}).get("status")
    return bool(
        meta.get("confirmed_login")
        or meta.get("confirmed_fuzz_crash")
        or meta.get("kev")
        or reach == "reachable"
    )


def _node_weight(f: dict[str, Any]) -> float:
    w = _SEV_WEIGHT.get(f.get("severity", "info"), 1.0) * _CONF_WEIGHT.get(f.get("confidence", "medium"), 0.6)
    return w * (1.6 if _confirmed(f) else 1.0)


def _sev_rank(sev: str) -> int:
    try:
        return Severity(sev).rank
    except ValueError:
        return 0


def _label(f: dict[str, Any], stage: str) -> str:
    """A short phrase describing one step, for the chain summary."""
    a = f.get("analyzer")
    meta = f.get("metadata") or {}
    base = f.get("path") or ""
    if stage == "entry":
        return (f.get("title") or "exposed service").split(":")[0].strip()
    if a == "accounts":
        acct = meta.get("account")
        return f"login as {acct}" if acct else "weak account login"
    if a == "credentials":
        return "hardcoded credential"
    if a == "auth":
        return "confirmed default credentials"
    if a == "cves":
        cve = meta.get("cve", "CVE")
        return f"{cve} in {base}" if base else cve
    if a == "dangerfns":
        sinks = ", ".join((meta.get("taint") or {}).get("sinks") or []) or "a dangerous sink"
        return f"input reaches {sinks} in {base}"
    if a == "emulation" and "shell command" in (f.get("title") or "").lower():
        return f"runtime command execution in {base}"
    if stage == "impact":
        if a == "fuzz":
            return f"network crash on port {meta.get('port', '?')}"
        sig = meta.get("signal") or meta.get("kind") or "crash"
        return f"{sig} in {base}" if base else str(sig)
    return f.get("title") or (a or "finding")


def _best_per_stage(nodes: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """The single strongest finding at each stage among ``nodes``.

    Tie-break deterministically on severity, then confidence, then id so output
    is stable across runs.
    """
    best: dict[str, dict[str, Any]] = {}
    for f in nodes:
        stage = _stage(f)
        if stage is None:
            continue
        cur = best.get(stage)
        if cur is None or _rank_key(f) > _rank_key(cur):
            best[stage] = f
    return best


def _rank_key(f: dict[str, Any]) -> tuple[float, int, int, str]:
    return (
        _node_weight(f),
        _sev_rank(f.get("severity", "info")),
        CONFIDENCE_RANK.get(f.get("confidence", "medium"), 1),
        f.get("id", ""),
    )


def _build_chain(nodes: list[dict[str, Any]], binary: str | None) -> dict[str, Any] | None:
    """Assemble the best chain confined to device-scoped nodes plus one ``binary``.

    ``binary`` is the single binary path the chain may use (None for a
    device-only chain). Returns a chain dict, or None when the result is not a
    chain worth showing (fewer than two stages, or no access/exploit/impact).
    """
    eligible = [f for f in nodes if not _is_binary_scoped(f) or f.get("path") == binary]
    best = _best_per_stage(eligible)
    if len(best) < 2 or max((_STAGE_INDEX[s] for s in best), default=0) < _STAGE_INDEX["access"]:
        return None  # a lone entry, or a single stage, is not an attack chain

    steps = []
    for stage in _STAGES:
        f = best.get(stage)
        if f is None:
            continue
        steps.append({
            "stage": stage,
            "analyzer": f.get("analyzer"),
            "title": f.get("title"),
            "path": f.get("path"),
            "severity": f.get("severity"),
            "confidence": f.get("confidence"),
            "confirmed": _confirmed(f),
            "finding_id": f.get("id"),
            "label": _label(f, stage),
        })

    worst = max((s["severity"] for s in steps), key=_sev_rank)
    confirmed = any(s["confirmed"] for s in steps)
    score = sum(_node_weight(best[s]) for s in best) + 0.5 * len(best) + (1.5 if confirmed else 0.0)
    ids = [s["finding_id"] for s in steps]
    return {
        "id": "CHAIN-" + hashlib.sha256("|".join(i or "" for i in ids).encode()).hexdigest()[:10],
        "score": round(score, 2),
        "severity": worst,
        "confirmed": confirmed,
        "summary": " → ".join(s["label"] for s in steps),
        "steps": steps,
    }


def correlate(report: dict[str, Any], min_confidence: str = "medium", max_chains: int = 20) -> dict[str, Any]:
    """Correlate a scan report's findings into ranked attack chains."""
    floor = CONFIDENCE_RANK.get(min_confidence, 1)
    findings = [
        f for f in report.get("findings", [])
        if CONFIDENCE_RANK.get(f.get("confidence", "medium"), 1) >= floor and _stage(f) is not None
    ]

    # One candidate chain per distinct vulnerable binary, plus a device-only chain.
    binaries = sorted({f.get("path") for f in findings if _is_binary_scoped(f) and f.get("path")})
    chains: dict[str, dict[str, Any]] = {}
    for binary in [*binaries, None]:
        chain = _build_chain(findings, binary)
        if chain is not None:
            chains[chain["id"]] = chain  # dedupe identical step-sets by id

    # Drop a chain whose steps are a strict subset of a fuller chain's (e.g. the
    # bare telnet+creds foothold that a complete chain already contains).
    id_sets = {cid: {s["finding_id"] for s in c["steps"]} for cid, c in chains.items()}
    kept = [
        c for cid, c in chains.items()
        if not any(oid != cid and id_sets[cid] < id_sets[oid] for oid in chains)
    ]

    ranked = sorted(kept, key=lambda c: (c["score"], _sev_rank(c["severity"])), reverse=True)[:max_chains]
    return {
        "chains": ranked,
        "count": len(ranked),
        "confirmed": sum(1 for c in ranked if c["confirmed"]),
        "disclaimer": DISCLAIMER,
    }


def print_chains(result: dict[str, Any]) -> None:
    from rich.console import Console

    from firefly.report import _SEVERITY_STYLE

    console = Console()
    chains = result["chains"]
    if not chains:
        console.print("No attack chains correlated from this report's findings.")
        console.print(f"[dim]{result['disclaimer']}[/]")
        return
    console.print(f"[bold]Attack chains[/bold] — {result['count']} correlated, {result['confirmed']} dynamically confirmed\n")
    for i, c in enumerate(chains, 1):
        try:
            sev = f"[{_SEVERITY_STYLE[Severity(c['severity'])]}]{c['severity']}[/]"
        except (ValueError, KeyError):
            sev = c["severity"]
        mark = " [bold red]● confirmed[/]" if c["confirmed"] else ""
        console.print(f"[bold]{i}.[/] ({sev}, score {c['score']}){mark}")
        console.print(f"   {c['summary']}")
        for s in c["steps"]:
            tick = "[green]✓[/]" if s["confirmed"] else " "
            console.print(f"     {tick} [dim]{s['stage']:<8}[/] {s['label']}  [dim]{s['finding_id']}[/]")
        console.print()
    console.print(f"[dim]{result['disclaimer']}[/]")
