"""Match identified components against the local NVD database."""

from __future__ import annotations

import re
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field

from firefly.analyzers import Analyzer, AnalyzerResult, ScanContext
from firefly.cvecheck import Range, description_agrees, fixed_in_branch, platform_only
from firefly.models import Component, Finding, Severity
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
            for comp in ctx.components:
                for cve, m in sorted(match_component(db, comp).items()):
                    row = m.row
                    kev = row["kev_added"] is not None
                    title = f"{cve} in {comp.product} {comp.version}" + (" (known exploited)" if kev else "")
                    result.findings.append(
                        Finding(
                            analyzer=self.name,
                            title=title,
                            severity=SEVERITY.get(row["severity"] or "", Severity.MEDIUM),
                            confidence=m.confidence,
                            path=comp.paths[0] if comp.paths else None,
                            description=(row["description"] or "")[:1000],
                            metadata={
                                "cve": cve,
                                "cvss_score": row["score"],
                                "cvss_version": row["cvss_version"],
                                "cvss_vector": row["vector"],
                                "cwe": row["cwe"],
                                "kev": kev,
                                "kev_added": row["kev_added"],
                                "published": row["published"],
                                "confidence_reasons": m.reasons,
                                "component": {"vendor": comp.vendor, "product": comp.product, "version": comp.version, "cpe": comp.cpe},
                                "paths": comp.paths,
                                "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                            },
                        )
                    )
            low = sum(1 for f in result.findings if f.confidence == "low")
            result.artifacts["confidence"] = {c: sum(1 for f in result.findings if f.confidence == c) for c in CONFIDENCE_ORDER}
            if low:
                result.artifacts["low_confidence_note"] = f"{low} match(es) look doubtful; see confidence_reasons"
        return result
