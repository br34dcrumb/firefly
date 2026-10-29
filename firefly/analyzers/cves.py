"""Match identified components against the local NVD database."""

from __future__ import annotations

import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field

from firefly.analyzers import Analyzer, AnalyzerResult, ScanContext
from firefly.cvecheck import Range, description_agrees, fixed_in_branch, platform_only
from firefly.models import Component, Finding, Severity
from firefly.disasm import function_reachable
from firefly.reachability import classify, component_call_graph, component_symbols, load_cve_functions
from firefly.vercmp import compare, in_range
from firefly.vulndb import SCHEMA_VERSION, VulnDB

SEVERITY = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "moderate": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": Severity.INFO,
}
CONFIDENCE_ORDER = ["low", "medium", "high"]
_DEBIAN_REVISION = re.compile(r"-[0-9]+$")


def exact_match(version: str, exact: str) -> bool:
    return compare(version, exact) == 0 or compare(_DEBIAN_REVISION.sub("", version), exact) == 0


def range_match(version: str, row: sqlite3.Row) -> bool:
    bounds = (row["start_incl"], row["start_excl"], row["end_incl"], row["end_excl"])
    # "every version" entries are mostly unmaintained products; too noisy.
    return any(bounds) and in_range(version, *bounds)


@dataclass
class CveMatch:
    row: sqlite3.Row
    confidence: str
    reasons: list[str] = field(default_factory=list)


def _assess(comp: Component, rows: list[sqlite3.Row]) -> CveMatch | None:
    exact_rows = [r for r in rows if r["version"] not in (None, "", "*", "-") and exact_match(comp.version, r["version"])]
    range_rows = [r for r in rows if r["version"] in (None, "", "*") and range_match(comp.version, r)]
    matched = exact_rows or range_rows
    if not matched:
        return None
    # Prefer an unconditional row: "X running on Y" only applies in some deployments.
    row = min(matched, key=lambda r: r["conditional"])
    reasons: list[str] = []
    confidence = "high" if comp.vendor else "medium"
    if not comp.vendor:
        reasons.append("matched on product name only")
    if row["conditional"]:
        confidence = "medium" if confidence == "high" else "low"
        reasons.append("NVD lists it only in combination with another product or platform")

    downgrade: list[str] = []
    if not exact_rows and all(not (r["start_incl"] or r["start_excl"]) for r in range_rows):
        # Only open-ended ranges ("* <= X") matched; that's the shape that sweeps
        # in other release branches, so double-check it.
        ceiling = fixed_in_branch(comp.version, [Range(r["version"], r["start_incl"], r["start_excl"], r["end_incl"], r["end_excl"]) for r in rows])
        if ceiling:
            downgrade.append(f"NVD's range for the {comp.version} release branch ends at {ceiling}")
        elif description_agrees(comp.version, row["description"] or "", row["end_incl"] or row["end_excl"]) is False:
            downgrade.append(f"the CVE description's affected versions don't include {comp.version}")
    platform = platform_only(row["description"] or "")
    if platform:
        downgrade.append(f"description says it applies on {platform}")
    if "disputed" in (row["tags"] or "").split(","):
        downgrade.append("the vendor disputes this CVE")
    if downgrade:
        confidence = "low"
        reasons.extend(downgrade)
    return CveMatch(row, confidence, reasons)


def match_component(db: VulnDB, comp: Component) -> dict[str, CveMatch]:
    by_cve: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for row in db.candidates(comp.product, comp.vendor):
        by_cve[row["cve_id"]].append(row)
    hits = {}
    for cve, rows in by_cve.items():
        m = _assess(comp, rows)
        if m is not None:
            hits[cve] = m
    return hits


class CveAnalyzer(Analyzer):
    name = "cves"
    description = "Known CVEs for identified components (offline NVD, CISA KEV)"

    def run(self, ctx: ScanContext) -> AnalyzerResult:
        result = AnalyzerResult()
        db = VulnDB.open_existing(ctx.db_path)
        if db is None:
            result.warnings.append("no vulnerability database found; run `firefly db update` to enable CVE matching")
            return result
        with db:
            info = db.info()
            if info.get("schema") != str(SCHEMA_VERSION):
                result.warnings.append("vulnerability database uses an older schema; run `firefly db update` to rebuild it")
            result.artifacts["database"] = {k: info[k] for k in ("release", "updated_at", "cves")}
            cve_functions = load_cve_functions()
            reach_counts = {"reachable": 0, "not_present": 0, "reachable_network_facing": 0}
            for comp in ctx.components:
                # Symbols are gathered once per component, lazily, and only for
                # products we actually have reachability data for.
                has_reach_data = ctx.inventory is not None and comp.product.lower() in cve_functions
                comp_syms: tuple[set[str], bool, bool] | None = None
                comp_graph: dict[str, set[str]] | None = None
                graph_done = False
                for cve, m in sorted(match_component(db, comp).items()):
                    row = m.row
                    kev = row["kev_added"] is not None
                    severity = SEVERITY.get(row["severity"] or "", Severity.MEDIUM)
                    title = f"{cve} in {comp.product} {comp.version}" + (" (known exploited)" if kev else "")
                    confidence = m.confidence
                    reasons = list(m.reasons)
                    reachability = None
                    if has_reach_data:
                        if comp_syms is None:
                            comp_syms = component_symbols(comp.paths, ctx.inventory)
                        observed, known, exposed = comp_syms
                        reach = classify(cve, comp.product, observed, known, cve_functions)
                        if reach.status != "unknown":
                            reachability = {"status": reach.status, "functions": reach.functions, "present": reach.present, "network_facing": exposed}
                            reach_counts[reach.status] += 1
                            if reach.status == "not_present":
                                reasons.append(
                                    f"vulnerable function(s) {', '.join(reach.functions)} are absent from the matched "
                                    "binary (may be compiled out, inlined, or stripped)"
                                )
                                # Down-rank out of the default view — but never
                                # hide a known-exploited or critical CVE on a
                                # symbol-presence guess that can be wrong.
                                if not kev and severity is not Severity.CRITICAL:
                                    confidence = "low"
                            elif exposed:
                                # Present in a network-facing binary: the stronger
                                # reachability signal. Annotated, never down-ranked.
                                reach_counts["reachable_network_facing"] += 1
                                reasons.append(f"vulnerable function(s) {', '.join(reach.present)} referenced in a network-facing binary")
                            else:
                                reasons.append(
                                    f"binary references vulnerable function(s): {', '.join(reach.present)}; no network-facing "
                                    "surface observed, so external reachability is less likely"
                                )
                            # Opt-in call-graph confirmation. Positive signal only:
                            # a found path strengthens the finding; a missing path
                            # never hides it (indirect/pointer calls defeat the graph).
                            if ctx.deep_reachability and reach.status == "reachable":
                                if not graph_done:
                                    comp_graph = component_call_graph(comp.paths, ctx.inventory)
                                    graph_done = True
                                if comp_graph:
                                    from_entry, from_input = function_reachable(comp_graph, set(reach.functions))
                                    reachability["call_reachable_from_entry"] = from_entry
                                    reachability["call_reachable_from_input"] = from_input
                                    if from_input:
                                        reasons.append("call-graph analysis confirms a path to it from external input")
                                    elif from_entry:
                                        reasons.append("call-graph analysis confirms it is reached from an entrypoint")
                                    else:
                                        reasons.append("call-graph analysis found no path from an entrypoint or external input (it may still be reached indirectly)")
                    metadata = {
                        "cve": cve,
                        "cvss_score": row["score"],
                        "cvss_version": row["cvss_version"],
                        "cvss_vector": row["vector"],
                        "cwe": row["cwe"],
                        "kev": kev,
                        "kev_added": row["kev_added"],
                        "published": row["published"],
                        "confidence_reasons": reasons,
                        "component": {"vendor": comp.vendor, "product": comp.product, "version": comp.version, "cpe": comp.cpe},
                        "paths": comp.paths,
                        "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                    }
                    if reachability is not None:
                        metadata["reachability"] = reachability
                    result.findings.append(
                        Finding(
                            analyzer=self.name,
                            title=title,
                            severity=severity,
                            confidence=confidence,
                            path=comp.paths[0] if comp.paths else None,
                            description=(row["description"] or "")[:1000],
                            metadata=metadata,
                        )
                    )
            if reach_counts["reachable"] or reach_counts["not_present"]:
                result.artifacts["reachability"] = reach_counts
            low = sum(1 for f in result.findings if f.confidence == "low")
            result.artifacts["confidence"] = {c: sum(1 for f in result.findings if f.confidence == c) for c in CONFIDENCE_ORDER}
            if low:
                result.artifacts["low_confidence_note"] = f"{low} match(es) look doubtful; see confidence_reasons"
        return result
