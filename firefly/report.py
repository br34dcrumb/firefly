"""Write scan results: machine-readable JSON and a console summary."""

from __future__ import annotations

import json
import os
from dataclasses import asdict
from typing import Any

from firefly import __version__
from firefly.models import Severity
from firefly.pipeline import REPORT_SCHEMA, ScanResult


def to_dict(result: ScanResult) -> dict[str, Any]:
    return {
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
    }


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


def print_summary(result: ScanResult, report_path: str) -> None:
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

    if result.components:
        table = Table(title=f"Components ({len(result.components)})", show_lines=False)
        table.add_column("Component")
        table.add_column("Version")
        table.add_column("Found in")
        for c in result.components:
            name = f"{c.vendor}:{c.product}" if c.vendor and c.vendor != c.product else c.product
            where = c.paths[0] + (f" (+{len(c.paths) - 1})" if len(c.paths) > 1 else "")
            table.add_row(name, c.version, where)
        console.print(table)

    if result.findings:
        table = Table(title=f"Findings ({len(result.findings)})")
        table.add_column("Severity")
        table.add_column("Title")
        table.add_column("Path")
        for f in result.findings:
            table.add_row(f"[{_SEVERITY_STYLE[f.severity]}]{f.severity.value}[/]", f.title, f.path or "")
        console.print(table)

    for err in result.errors:
        console.print(f"[red]error in {err['stage']}:[/red] {err['error']}")
    total = sum(result.timings.values())
    console.print(f"done in {total:.1f}s  report: {report_path}")
