"""CycloneDX 1.6 SBOM (with vulnerabilities) for a scan result."""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

from firefly import __version__
from firefly.models import Finding, Severity
from firefly.pipeline import ScanResult

_CVSS_METHOD = {"2.0": "CVSSv2", "3.0": "CVSSv3", "3.1": "CVSSv31", "4.0": "CVSSv4"}


def _component_type(paths: list[str]) -> str:
    return "library" if paths and all(".so" in os.path.basename(p) for p in paths) else "application"


def _vex_analysis(finding: Finding) -> dict[str, Any] | None:
    """CycloneDX VEX ``analysis`` block for a CVE finding, or None to omit it.

    Reachability (symbol presence) is turned into a machine-readable triage
    state: a vulnerable function that is nowhere in the matched binary is a
    concrete ``not_affected`` / ``code_not_present`` statement. But absence is a
    heuristic (inlining, stripping and static linking can hide a real function),
    so — matching the CVE analyzer's own caution — a known-exploited or critical
    CVE is never cleared this way; it stays ``in_triage`` for a human to confirm.
    """
    meta = finding.metadata
    reach = meta.get("reachability")
    if isinstance(reach, dict):
        status = reach.get("status")
        funcs = ", ".join(reach.get("functions") or [])
        if status == "not_present":
            if meta.get("kev") or finding.severity is Severity.CRITICAL:
                return {
                    "state": "in_triage",
                    "detail": f"vulnerable function(s) {funcs} appear absent from the matched binary, but "
                    "this CVE is known-exploited or critical — confirm manually (functions can be "
                    "inlined, stripped, or statically linked).",
                }
            return {
                "state": "not_affected",
                "justification": "code_not_present",
                "detail": f"vulnerable function(s) {funcs} are absent from the matched binary "
                "(may be compiled out, inlined, or stripped).",
            }
        if status == "reachable":
            present = ", ".join(reach.get("present") or [])
            return {"state": "in_triage", "detail": f"binary references vulnerable function(s): {present}."}
    if finding.confidence == "low":
        # Keep doubtful matches visible to SBOM consumers, but as untriaged.
        return {"state": "in_triage", "detail": "; ".join(meta.get("confidence_reasons", []))}
    return None


def build(result: ScanResult) -> dict[str, Any]:
    refs: dict[tuple[str, str, str], str] = {}
    components = []
    for i, comp in enumerate(result.components, 1):
        ref = f"component-{i}"
        refs[(comp.vendor or "", comp.product, comp.version)] = ref
        entry: dict[str, Any] = {
            "type": _component_type(comp.paths),
            "bom-ref": ref,
            "name": comp.product,
            "version": comp.version,
            "cpe": comp.cpe,
            "evidence": {"occurrences": [{"location": p} for p in comp.paths]},
        }
        if comp.vendor:
            entry["publisher"] = comp.vendor
        if comp.license:
            entry["licenses"] = [{"license": {"name": comp.license}}]
        components.append(entry)

    vulnerabilities = []
    for finding in result.findings:
        cve = finding.metadata.get("cve")
        comp = finding.metadata.get("component")
        if not cve or not comp:
            continue
        ref = refs.get((comp["vendor"] or "", comp["product"], comp["version"]))
        vuln: dict[str, Any] = {
            "bom-ref": f"{cve}/{ref}",
            "id": cve,
            "source": {"name": "NVD", "url": finding.metadata.get("url")},
            "description": finding.description,
            "affects": [{"ref": ref}] if ref else [],
            "properties": [{"name": "firefly:confidence", "value": finding.confidence}],
        }
        score = finding.metadata.get("cvss_score")
        if score is not None:
            rating = {
                "source": {"name": "NVD"},
                "score": score,
                "severity": finding.severity.value,
                "method": _CVSS_METHOD.get(finding.metadata.get("cvss_version") or "", "other"),
            }
            if finding.metadata.get("cvss_vector"):
                rating["vector"] = finding.metadata["cvss_vector"]
            vuln["ratings"] = [rating]
        if finding.metadata.get("cwe", "") and finding.metadata["cwe"].startswith("CWE-"):
            try:
                vuln["cwes"] = [int(finding.metadata["cwe"].split("-", 1)[1])]
            except ValueError:
                pass
        reach = finding.metadata.get("reachability")
        if isinstance(reach, dict) and reach.get("status"):
            vuln["properties"].append({"name": "firefly:reachability", "value": reach["status"]})
        analysis = _vex_analysis(finding)
        if analysis is not None:
            vuln["analysis"] = analysis
        if finding.metadata.get("kev"):
            vuln["properties"].append({"name": "cisa:kev:dateAdded", "value": finding.metadata["kev_added"]})
        vulnerabilities.append(vuln)

    name = os.path.basename(result.input_path.rstrip("/\\"))
    bom: dict[str, Any] = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "serialNumber": f"urn:uuid:{uuid.uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": result.finished or result.started,
            "tools": {"components": [{"type": "application", "name": "firefly", "version": __version__}]},
            "component": {
                "type": "firmware",
                "bom-ref": "firmware",
                "name": name,
                "hashes": [{"alg": "SHA-256", "content": result.input_sha256}] if result.input_size else [],
            },
        },
        "components": components,
    }
    if vulnerabilities:
        bom["vulnerabilities"] = vulnerabilities
    return bom


def write(result: ScanResult, path: str | None = None) -> str:
    path = path or os.path.join(result.workdir, "sbom.cdx.json")
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build(result), fh, indent=2)
    return path
