"""CycloneDX 1.6 SBOM (with vulnerabilities) for a scan result."""

from __future__ import annotations

import json
import os
import uuid
from typing import Any

from firefly import __version__
from firefly.pipeline import ScanResult

_CVSS_METHOD = {"2.0": "CVSSv2", "3.0": "CVSSv3", "3.1": "CVSSv31", "4.0": "CVSSv4"}


def _component_type(paths: list[str]) -> str:
    return "library" if paths and all(".so" in os.path.basename(p) for p in paths) else "application"


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
        if finding.confidence == "low":
            # Keep doubtful matches visible to SBOM consumers, but as untriaged.
            vuln["analysis"] = {"state": "in_triage", "detail": "; ".join(finding.metadata.get("confidence_reasons", []))}
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
