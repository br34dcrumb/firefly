"""Watch mode: re-check a stored report against today's vulnerability database.

A shipped device's firmware does not change, but the CVE database does. Watch
mode re-matches the components already recorded in a scan report against the
*current* local vuln DB and reports the CVEs that are **new** since the report
was written — so an operator can tell, from the stored SBOM alone and without
access to the firmware, that a fielded device is now affected by a freshly
published (or newly known-exploited) CVE.

Offline like the rest of Firefly: it reads the local DB (refresh it with
`firefly db update`) and never touches the network. This is a one-shot re-check
meant to be scheduled (cron), not a long-running service.
"""

from __future__ import annotations

from typing import Any

from firefly.analyzers.cves import match_component
from firefly.models import Component
from firefly.report import CONFIDENCE_RANK
from firefly.vulndb import VulnDB


def _components(report: dict[str, Any]) -> list[Component]:
    return [
        Component(
            product=c.get("product") or "",
            version=c.get("version") or "",
            vendor=c.get("vendor"),
            paths=list(c.get("paths") or []),
        )
        for c in report.get("components", [])
        if c.get("product") and c.get("version")
    ]


def _baseline(report: dict[str, Any]) -> set[tuple[str, str, str]]:
    """(cve, vendor, product) already recorded in the report's findings."""
    base: set[tuple[str, str, str]] = set()
    for f in report.get("findings", []):
        md = f.get("metadata") or {}
        cve = md.get("cve")
        if not cve:
            continue
        comp = md.get("component") or {}
        base.add((cve, comp.get("vendor") or "", comp.get("product") or ""))
    return base


def new_cves(report: dict[str, Any], db: VulnDB, *, min_confidence: str = "medium", since: str | None = None) -> list[dict[str, Any]]:
    """CVEs that match the report's components now but weren't in the report.

    ``since`` (an ISO date) keeps only CVEs published or KEV-listed on/after it,
    so a daily watch alerts on genuinely new entries rather than the backlog.
    """
    floor = CONFIDENCE_RANK.get(min_confidence, 1)
    baseline = _baseline(report)
    out: list[dict[str, Any]] = []
    seen: set[tuple[str, str, str]] = set()
    for comp in _components(report):
        for cve, m in match_component(db, comp).items():
            if CONFIDENCE_RANK.get(m.confidence, 1) < floor:
                continue
            key = (cve, comp.vendor or "", comp.product)
            if key in baseline or key in seen:
                continue
            row = m.row
            if since and max(row["published"] or "", row["kev_added"] or "") < since:
                continue
            seen.add(key)
            out.append(
                {
                    "cve": cve,
                    "vendor": comp.vendor,
                    "product": comp.product,
                    "version": comp.version,
                    "severity": row["severity"] or "medium",
                    "score": row["score"],
                    "kev": row["kev_added"] is not None,
                    "kev_added": row["kev_added"],
                    "published": row["published"],
                    "confidence": m.confidence,
                    "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
                }
            )
    out.sort(key=lambda r: (-(r["score"] or 0), not r["kev"], r["cve"]))
    return out


def print_new(report: dict[str, Any], new: list[dict[str, Any]], since: str | None = None) -> None:
    from rich.console import Console
    from rich.table import Table

    from firefly.models import Severity
    from firefly.report import _SEVERITY_STYLE

    console = Console()
    window = f" since {since}" if since else ""
    console.print(f"[bold]Firefly watch[/bold]  {report.get('input', {}).get('path')}")
    if not new:
        console.print(f"[green]No new CVEs{window}[/] for the {len(report.get('components', []))} recorded component(s).")
        return
    kev = sum(1 for r in new if r["kev"])
    table = Table(title=f"New CVEs ({len(new)}{window})" + (f"  [bold red]{kev} KEV[/]" if kev else ""))
    table.add_column("CVE")
    table.add_column("Score", justify="right")
    table.add_column("Component")
    table.add_column("Published")
    for r in new:
        name = f"{r['product']} {r['version']}" if r.get("version") else (r.get("product") or "")
        label = r["cve"] + ("  (KEV)" if r["kev"] else "")
        try:
            style = _SEVERITY_STYLE[Severity(r["severity"])]
            label = f"[{style}]{label}[/]"
        except (ValueError, KeyError):
            pass
        table.add_row(label, f"{r['score']:.1f}" if r.get("score") is not None else "", name, (r.get("published") or "")[:10])
    console.print(table)
