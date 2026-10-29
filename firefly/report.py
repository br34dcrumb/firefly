"""Write scan results: machine-readable JSON and a console summary."""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import Any

from firefly import __version__
from firefly.models import Finding, Severity
from firefly.pipeline import REPORT_SCHEMA, ScanResult


def to_dict(result: ScanResult) -> dict[str, Any]:
    out: dict[str, Any] = {
        "schema": REPORT_SCHEMA,
        "tool": {"name": "firefly", "version": __version__},
        "input": {"path": result.input_path, "sha256": result.input_sha256, "size": result.input_size},
        "started": result.started,
        "finished": result.finished,
        "extraction": result.extraction,
        "inventory": result.inventory,
        "timings": result.timings,
        "components": [{**asdict(c), "cpe": c.cpe} for c in result.components],
        "findings": [f.to_dict() for f in result.findings],
        "artifacts": result.artifacts,
        "errors": result.errors,
        "warnings": result.warnings,
    }
    # Omit "files" entirely when the per-file inventory wasn't recorded, so a
    # diff can tell "not recorded" apart from "genuinely empty" and degrade
    # instead of reporting every file as added/removed.
    if result.file_inventory:
        out["files"] = result.files
    return out


def write_json(result: ScanResult, path: str | None = None) -> str:
    path = path or os.path.join(result.workdir, "firefly.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(to_dict(result), fh, indent=2)
    return path


_SEVERITY_STYLE = {
    Severity.CRITICAL: "bold white on red",
    Severity.HIGH: "bold red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "cyan",
    Severity.INFO: "dim",
}


MAX_FINDINGS_SHOWN = 25
CONFIDENCE_RANK = {"low": 0, "medium": 1, "high": 2}


def _cve_counts(findings: list[Finding]) -> dict[tuple[str, str, str], tuple[int, int, str]]:
    """(vendor, product, version) -> (CVE count, known-exploited count, worst severity)."""
    counts: dict[tuple[str, str, str], tuple[int, int, str]] = {}
    for f in findings:
        comp = f.metadata.get("component")
        if not comp:
            continue
        key = (comp["vendor"] or "", comp["product"], comp["version"])
        n, kev, worst = counts.get(key, (0, 0, "info"))
        if Severity(f.severity).rank > Severity(worst).rank:
            worst = f.severity.value
        counts[key] = (n + 1, kev + int(bool(f.metadata.get("kev"))), worst)
    return counts


def print_summary(result: ScanResult, report_path: str, sbom_path: str | None = None, min_confidence: str = "medium") -> None:
    from rich.console import Console
    from rich.table import Table

    console = Console()
    console.print(f"[bold]Firefly[/bold] {__version__}  {result.input_path}")
    console.print(f"sha256 {result.input_sha256}")
    if result.extraction:
        ex = result.extraction
        rootfs = ", ".join(ex["rootfs"]) or "none found"
        console.print(f"extraction: {ex['kind']} via {ex['backend'] or 'n/a'}; rootfs: {rootfs}")
        for w in ex["warnings"]:
            console.print(f"[yellow]warning:[/yellow] {w}")
    if result.inventory:
        inv = result.inventory
        console.print(f"inventory: {inv['total']} entries, {inv['elf']} ELF, {inv['script']} scripts, {inv['symlink']} symlinks")

    floor = CONFIDENCE_RANK[min_confidence]
    findings = [f for f in result.findings if CONFIDENCE_RANK.get(f.confidence, 1) >= floor]
    hidden = _cve_counts([f for f in result.findings if CONFIDENCE_RANK.get(f.confidence, 1) < floor])

    if result.components:
        table = Table(title=f"Components ({len(result.components)})", show_lines=False)
        table.add_column("Component")
        table.add_column("Version")
        table.add_column("CVEs", justify="right")
        table.add_column("Found in")
        counts = _cve_counts(findings)
        for c in result.components:
            name = f"{c.vendor}:{c.product}" if c.vendor and c.vendor != c.product else c.product
            where = c.paths[0] + (f" (+{len(c.paths) - 1})" if len(c.paths) > 1 else "")
            n, kev, worst = counts.get((c.vendor or "", c.product, c.version), (0, 0, "info"))
            cves = f"[{_SEVERITY_STYLE[Severity(worst)]}]{n}[/]" + (f" [bold red]({kev} KEV)[/]" if kev else "") if n else ""
            doubtful = hidden.get((c.vendor or "", c.product, c.version), (0,))[0]
            if doubtful:
                cves += f" [dim]+{doubtful}?[/]"
            table.add_row(name, c.version, cves, where)
        console.print(table)

    if findings:
        shown = findings[:MAX_FINDINGS_SHOWN]
        title = f"Findings ({len(findings)}" + (f", top {len(shown)} shown)" if len(shown) < len(findings) else ")")
        table = Table(title=title)
        table.add_column("Severity")
        table.add_column("Score", justify="right")
        table.add_column("Title")
        table.add_column("Path")
        for f in shown:
            score = f.metadata.get("cvss_score")
            table.add_row(f"[{_SEVERITY_STYLE[f.severity]}]{f.severity.value}[/]", f"{score:.1f}" if score is not None else "", f.title, f.path or "")
        console.print(table)

    n_hidden = len(result.findings) - len(findings)
    if n_hidden:
        console.print(
            f"[dim]{n_hidden} lower-confidence finding(s) hidden (shown as +N? above); "
            f"`--min-confidence low` shows them, firefly.json has all with reasons[/]"
        )
    for warning in result.warnings:
        console.print(f"[yellow]warning:[/yellow] {warning}")
    for err in result.errors:
        console.print(f"[red]error in {err['stage']}:[/red] {err['error']}")
    total = sum(result.timings.values())
    console.print(f"done in {total:.1f}s  report: {report_path}")
    if sbom_path:
        console.print(f"sbom: {sbom_path}")
