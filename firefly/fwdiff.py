"""Diff two Firefly scan reports: what changed between two firmware builds.

Given the ``firefly.json`` of an old image and a new one, this reports the
security-relevant delta: components added / removed / version-bumped, findings
that are new / fixed / still present, and the CVE delta (the headline — which
CVE IDs a release actually cleared or introduced). It consumes the reports the
pipeline already writes, so it needs no re-execution and no access to either
image.

Scope of this increment: the JSON report stores the inventory as counts only,
not per-file hashes, so this compares components / findings / CVEs, not
individual files. Per-file diffing needs a richer inventory dump (or re-scanning
both images) and is a later increment.
"""

from __future__ import annotations

import json
import os
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

from firefly import vercmp
from firefly.models import Severity
from firefly.report import CONFIDENCE_RANK


class DiffError(Exception):
    """A report could not be loaded or is not a Firefly scan report."""


def load_report(path: str) -> dict[str, Any]:
    """Load a ``firefly.json`` report, given the file or a directory holding it."""
    if os.path.isdir(path):
        candidate = os.path.join(path, "firefly.json")
        if not os.path.isfile(candidate):
            raise DiffError(f"no firefly.json in directory: {path}")
        path = candidate
    if not os.path.isfile(path):
        raise DiffError(f"report not found: {path}")
    try:
        with open(path, encoding="utf-8") as fh:
            report = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        raise DiffError(f"cannot read report {path}: {exc}") from exc
    if not isinstance(report, dict) or "findings" not in report:
        raise DiffError(f"not a Firefly scan report: {path}")
    return report


# --------------------------------------------------------------------------- types


@dataclass
class ComponentChange:
    vendor: str | None
    product: str
    old_version: str
    new_version: str
    direction: str  # "upgrade" | "downgrade" | "changed"


@dataclass
class ComponentDiff:
    added: list[dict[str, Any]] = field(default_factory=list)
    removed: list[dict[str, Any]] = field(default_factory=list)
    changed: list[ComponentChange] = field(default_factory=list)


@dataclass
class FindingDelta:
    new: list[dict[str, Any]] = field(default_factory=list)
    fixed: list[dict[str, Any]] = field(default_factory=list)
    persisting: int = 0
    new_by_severity: dict[str, int] = field(default_factory=dict)
    fixed_by_severity: dict[str, int] = field(default_factory=dict)


@dataclass
class CveDelta:
    new: list[dict[str, Any]] = field(default_factory=list)
    fixed: list[dict[str, Any]] = field(default_factory=list)
    still_present: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class FileDiff:
    added: list[dict[str, Any]] = field(default_factory=list)
    removed: list[dict[str, Any]] = field(default_factory=list)
    changed: list[dict[str, Any]] = field(default_factory=list)


@dataclass
class FirmwareDiff:
    old_input: dict[str, Any]
    new_input: dict[str, Any]
    components: ComponentDiff
    findings: FindingDelta
    cves: CveDelta
    files: FileDiff | None = None  # None when either report has no file inventory

    def to_dict(self) -> dict[str, Any]:
        out = {
            "old": self.old_input,
            "new": self.new_input,
            "summary": self.summary(),
            "components": {
                "added": self.components.added,
                "removed": self.components.removed,
                "changed": [c.__dict__ for c in self.components.changed],
            },
            "findings": {
                "new": self.findings.new,
                "fixed": self.findings.fixed,
                "persisting": self.findings.persisting,
                "new_by_severity": self.findings.new_by_severity,
                "fixed_by_severity": self.findings.fixed_by_severity,
            },
            "cves": {
                "new": self.cves.new,
                "fixed": self.cves.fixed,
                "still_present": self.cves.still_present,
            },
            "files": None if self.files is None else {
                "added": self.files.added,
                "removed": self.files.removed,
                "changed": self.files.changed,
            },
        }
        return out

    def summary(self) -> dict[str, int]:
        s = {
            "components_added": len(self.components.added),
            "components_removed": len(self.components.removed),
            "components_changed": len(self.components.changed),
            "findings_new": len(self.findings.new),
            "findings_fixed": len(self.findings.fixed),
            "findings_persisting": self.findings.persisting,
            "cves_new": len(self.cves.new),
            "cves_fixed": len(self.cves.fixed),
            "cves_still_present": len(self.cves.still_present),
            "new_kev": sum(1 for c in self.cves.new if c.get("kev")),
        }
        if self.files is not None:
            s["files_added"] = len(self.files.added)
            s["files_removed"] = len(self.files.removed)
            s["files_changed"] = len(self.files.changed)
        return s

    @property
    def has_regression(self) -> bool:
        """True if the new image introduced any CVE or non-info finding."""
        return bool(self.cves.new) or any(
            Severity(f["severity"]).rank >= Severity.LOW.rank for f in self.findings.new
        )


# --------------------------------------------------------------------------- diffing


def _input_summary(report: dict[str, Any]) -> dict[str, Any]:
    inp = report.get("input", {})
    return {"path": inp.get("path"), "sha256": inp.get("sha256"), "size": inp.get("size")}


def _components_by_product(components: list[dict[str, Any]]) -> tuple[dict, dict]:
    """(vendor, product) -> set of versions, and -> a representative component."""
    versions: dict[tuple[str, str], set[str]] = defaultdict(set)
    rep: dict[tuple[str, str], dict[str, Any]] = {}
    for c in components:
        key = (c.get("vendor") or "", c.get("product") or "")
        versions[key].add(c.get("version") or "")
        rep.setdefault(key, c)
    return versions, rep


def _repr_component(rep: dict[str, Any], versions: set[str]) -> dict[str, Any]:
    return {
        "vendor": rep.get("vendor"),
        "product": rep.get("product"),
        "version": sorted(versions)[0] if len(versions) == 1 else sorted(versions),
        "paths": rep.get("paths", []),
    }


def _diff_components(old: list[dict], new: list[dict]) -> ComponentDiff:
    old_v, old_rep = _components_by_product(old)
    new_v, new_rep = _components_by_product(new)
    diff = ComponentDiff()
    for key in new_v.keys() - old_v.keys():
        diff.added.append(_repr_component(new_rep[key], new_v[key]))
    for key in old_v.keys() - new_v.keys():
        diff.removed.append(_repr_component(old_rep[key], old_v[key]))
    for key in old_v.keys() & new_v.keys():
        if old_v[key] == new_v[key]:
            continue
        vendor, product = key
        ov, nv = sorted(old_v[key]), sorted(new_v[key])
        if len(ov) == 1 and len(nv) == 1:
            cmp = vercmp.compare(nv[0], ov[0])
            direction = "upgrade" if cmp > 0 else "downgrade" if cmp < 0 else "changed"
            diff.changed.append(ComponentChange(vendor or None, product, ov[0], nv[0], direction))
        else:
            diff.changed.append(ComponentChange(vendor or None, product, ", ".join(ov), ", ".join(nv), "changed"))
    diff.added.sort(key=lambda c: (c["vendor"] or "", c["product"]))
    diff.removed.sort(key=lambda c: (c["vendor"] or "", c["product"]))
    diff.changed.sort(key=lambda c: (c.vendor or "", c.product))
    return diff


def _filter_confidence(findings: list[dict], min_confidence: str) -> list[dict]:
    floor = CONFIDENCE_RANK[min_confidence]
    return [f for f in findings if CONFIDENCE_RANK.get(f.get("confidence", "medium"), 1) >= floor]


def _severity_counts(findings: list[dict]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity", "info")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _diff_findings(old: list[dict], new: list[dict]) -> FindingDelta:
    old_by_id = {f["id"]: f for f in old if f.get("id")}
    new_by_id = {f["id"]: f for f in new if f.get("id")}
    new_ids = new_by_id.keys() - old_by_id.keys()
    fixed_ids = old_by_id.keys() - new_by_id.keys()
    new_findings = [new_by_id[i] for i in new_ids]
    fixed_findings = [old_by_id[i] for i in fixed_ids]
    _sort = lambda fs: sorted(fs, key=lambda f: (-Severity(f.get("severity", "info")).rank, f.get("title", "")))
    return FindingDelta(
        new=_sort(new_findings),
        fixed=_sort(fixed_findings),
        persisting=len(new_by_id.keys() & old_by_id.keys()),
        new_by_severity=_severity_counts(new_findings),
        fixed_by_severity=_severity_counts(fixed_findings),
    )


def _cves_by_key(findings: list[dict]) -> dict[tuple[str, str, str], dict]:
    """(cve, vendor, product) -> a flat record. Version-independent per product,
    so a version bump that clears a CVE shows up as 'fixed', not new+fixed."""
    out: dict[tuple[str, str, str], dict] = {}
    for f in findings:
        md = f.get("metadata") or {}
        cve = md.get("cve")
        if not cve:
            continue
        comp = md.get("component") or {}
        key = (cve, comp.get("vendor") or "", comp.get("product") or "")
        out[key] = {
            "cve": cve,
            "vendor": comp.get("vendor"),
            "product": comp.get("product"),
            "version": comp.get("version"),
            "severity": f.get("severity"),
            "score": md.get("cvss_score"),
            "kev": bool(md.get("kev")),
            "path": f.get("path"),
        }
    return out


def _diff_cves(old: list[dict], new: list[dict]) -> CveDelta:
    old_c = _cves_by_key(old)
    new_c = _cves_by_key(new)
    _sort = lambda recs: sorted(recs, key=lambda r: (-(r.get("score") or 0), not r.get("kev"), r.get("cve", "")))
    return CveDelta(
        new=_sort([new_c[k] for k in new_c.keys() - old_c.keys()]),
        fixed=_sort([old_c[k] for k in old_c.keys() - new_c.keys()]),
        still_present=_sort([new_c[k] for k in new_c.keys() & old_c.keys()]),
    )


def _content_id(entry: dict[str, Any]) -> str | None:
    """What identifies this file's content: a symlink's target, else its sha256.
    None means content can't be compared (unhashable file, read error)."""
    if entry.get("kind") == "symlink":
        return entry.get("link_target")
    return entry.get("sha256")


def _diff_files(old_files: list[dict], new_files: list[dict]) -> FileDiff:
    old_by_path = {f["path"]: f for f in old_files if f.get("path")}
    new_by_path = {f["path"]: f for f in new_files if f.get("path")}
    diff = FileDiff()
    for path in new_by_path.keys() - old_by_path.keys():
        n = new_by_path[path]
        diff.added.append({"path": path, "kind": n.get("kind"), "size": n.get("size")})
    for path in old_by_path.keys() - new_by_path.keys():
        o = old_by_path[path]
        diff.removed.append({"path": path, "kind": o.get("kind"), "size": o.get("size")})
    for path in old_by_path.keys() & new_by_path.keys():
        o, n = old_by_path[path], new_by_path[path]
        kind_changed = o.get("kind") != n.get("kind")
        oc, nc = _content_id(o), _content_id(n)
        content_changed = oc is not None and nc is not None and oc != nc
        # When content can't be compared on at least one side (e.g. a file that
        # crossed inventory's HASH_LIMIT between builds, so it's hashed on one
        # side and not the other), a differing size still proves a change; use it
        # as a fallback so large blobs aren't silently skipped.
        size_changed = (oc is None or nc is None) and not kind_changed and o.get("size") != n.get("size")
        if kind_changed or content_changed or size_changed:
            diff.changed.append({
                "path": path,
                "old_kind": o.get("kind"),
                "new_kind": n.get("kind"),
                "old": oc,
                "new": nc,
                "old_size": o.get("size"),
                "new_size": n.get("size"),
            })
    diff.added.sort(key=lambda f: f["path"])
    diff.removed.sort(key=lambda f: f["path"])
    diff.changed.sort(key=lambda f: f["path"])
    return diff


def diff_reports(old: dict[str, Any], new: dict[str, Any], min_confidence: str = "medium") -> FirmwareDiff:
    """Compute the delta between two scan reports.

    ``min_confidence`` filters findings (and the CVE delta) the same way the
    scan summary does, so the diff reflects what an operator would actually see.
    """
    old_f = _filter_confidence(old.get("findings", []), min_confidence)
    new_f = _filter_confidence(new.get("findings", []), min_confidence)
    # File-level diff only when both reports carry a file inventory (schema >= 2
    # scans without --no-file-inventory); otherwise it degrades to None.
    files = None
    if "files" in old and "files" in new:
        files = _diff_files(old["files"], new["files"])
    return FirmwareDiff(
        old_input=_input_summary(old),
        new_input=_input_summary(new),
        components=_diff_components(old.get("components", []), new.get("components", [])),
        findings=_diff_findings(old_f, new_f),
        cves=_diff_cves(old_f, new_f),
        files=files,
    )


# --------------------------------------------------------------------------- console


def print_diff(diff: FirmwareDiff) -> None:
    from rich.console import Console
    from rich.table import Table

    from firefly.report import _SEVERITY_STYLE

    console = Console()
    console.print(f"[bold]Firefly diff[/bold]  {diff.old_input.get('path')}  →  {diff.new_input.get('path')}")
    s = diff.summary()
    line = (
        f"components: [green]+{s['components_added']}[/] [red]-{s['components_removed']}[/] "
        f"~{s['components_changed']}   "
        f"CVEs: [red]+{s['cves_new']}[/] [green]-{s['cves_fixed']}[/] ={s['cves_still_present']}"
        + (f"   [bold red]{s['new_kev']} new KEV[/]" if s["new_kev"] else "")
    )
    if diff.files is not None:
        line += f"   files: [green]+{s['files_added']}[/] [red]-{s['files_removed']}[/] ~{s['files_changed']}"
    console.print(line)

    if diff.components.changed or diff.components.added or diff.components.removed:
        table = Table(title="Components")
        table.add_column("Change")
        table.add_column("Component")
        table.add_column("Version")
        for c in diff.components.changed:
            name = f"{c.vendor}:{c.product}" if c.vendor and c.vendor != c.product else c.product
            arrow = {"upgrade": "[green]↑[/]", "downgrade": "[red]↓[/]", "changed": "~"}[c.direction]
            table.add_row(arrow + " " + c.direction, name, f"{c.old_version} → {c.new_version}")
        for c in diff.components.added:
            name = f"{c['vendor']}:{c['product']}" if c["vendor"] and c["vendor"] != c["product"] else c["product"]
            table.add_row("[green]+ added[/]", name, str(c["version"]))
        for c in diff.components.removed:
            name = f"{c['vendor']}:{c['product']}" if c["vendor"] and c["vendor"] != c["product"] else c["product"]
            table.add_row("[red]- removed[/]", name, str(c["version"]))
        console.print(table)

    for label, recs, style in (("New CVEs", diff.cves.new, "red"), ("Fixed CVEs", diff.cves.fixed, "green")):
        if not recs:
            continue
        table = Table(title=f"{label} ({len(recs)})")
        table.add_column("CVE")
        table.add_column("Score", justify="right")
        table.add_column("Component")
        for r in recs:
            name = f"{r['product']} {r['version']}" if r.get("version") else (r.get("product") or "")
            cve = f"[{style}]{r['cve']}[/]" + (" [bold red](KEV)[/]" if r.get("kev") else "")
            table.add_row(cve, f"{r['score']:.1f}" if r.get("score") is not None else "", name)
        console.print(table)

    if diff.files is None:
        console.print("[dim]file-level diff unavailable: re-scan both images without --no-file-inventory[/]")
    else:
        _print_file_changes(console, diff.files)

    nb = diff.findings.new_by_severity
    fb = diff.findings.fixed_by_severity
    if diff.findings.new or diff.findings.fixed:
        new_desc = ", ".join(f"[{_SEVERITY_STYLE[Severity(k)]}]{v} {k}[/]" for k, v in _sorted_sev(nb)) or "none"
        fixed_desc = ", ".join(f"{v} {k}" for k, v in _sorted_sev(fb)) or "none"
        console.print(f"findings: [bold]new[/] {new_desc}; [bold]fixed[/] {fixed_desc}; persisting {diff.findings.persisting}")
    else:
        console.print(f"findings: no change (persisting {diff.findings.persisting})")


def _sorted_sev(counts: dict[str, int]) -> list[tuple[str, int]]:
    return sorted(counts.items(), key=lambda kv: -Severity(kv[0]).rank)


_MAX_FILES_SHOWN = 30


def _print_file_changes(console, files: FileDiff) -> None:
    # No "no change" line here: the summary row already shows files +0 -0 ~0.
    if not (files.added or files.removed or files.changed):
        return
    from rich.table import Table

    table = Table(title=f"Files (+{len(files.added)} -{len(files.removed)} ~{len(files.changed)})")
    table.add_column("Change")
    table.add_column("Path")
    rows = (
        [("[yellow]~ changed[/]", f["path"]) for f in files.changed]
        + [("[green]+ added[/]", f["path"]) for f in files.added]
        + [("[red]- removed[/]", f["path"]) for f in files.removed]
    )
    for change, path in rows[:_MAX_FILES_SHOWN]:
        table.add_row(change, path)
    console.print(table)
    if len(rows) > _MAX_FILES_SHOWN:
        console.print(f"[dim]… and {len(rows) - _MAX_FILES_SHOWN} more file change(s); full list in --json / -o[/]")
