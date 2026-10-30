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


def _dynamically_crashed_paths(findings: list[Finding]) -> set[str]:
    """Binaries a Phase C / emulation stage *confirmed* crash on attacker input.

    The per-binary harness fuzzer (`--fuzz-binaries`) and the bare-launch crashes
    it upgrades both tag their finding with ``confirmed_fuzz_crash``; the binary
    they name is one firmware executable demonstrably crashable on input. Network
    and default-credential confirmations are service-level and are not mapped to a
    specific CVE here (they remain their own findings) to avoid over-claiming.
    """
    crashed: set[str] = set()
    for f in findings:
        if f.path and f.analyzer in ("harness", "emulation") and f.metadata.get("confirmed_fuzz_crash"):
            crashed.add(f.path)
    return crashed


def _vex_analysis(finding: Finding, crashed_paths: frozenset[str] | set[str] = frozenset()) -> dict[str, Any] | None:
    """CycloneDX VEX ``analysis`` block for a CVE finding, or None to omit it.

    Reachability (symbol presence) is turned into a machine-readable triage
    state: a vulnerable function that is nowhere in the matched binary is a
    concrete ``not_affected`` / ``code_not_present`` statement. But absence is a
    heuristic (inlining, stripping and static linking can hide a real function),
    so — matching the CVE analyzer's own caution — a known-exploited or critical
    CVE is never cleared this way; it stays ``in_triage`` for a human to confirm.

    Phase C sharpens this: when the binary hosting the component was dynamically
    *crashed on attacker-controlled input*, the state escalates. A reachable CVE
    on a crashed binary becomes ``exploitable`` (symbols present **and** the
    binary is proven input-reachable and memory-unsafe); a crashed binary whose
    vulnerable symbols look absent is pulled back up to ``in_triage`` rather than
    cleared. The detail is careful never to claim the crash is a PoC for this
    specific CVE — only that the hosting binary is confirmed crashable.
    """
    meta = finding.metadata
    reach = meta.get("reachability")
    crashed = bool(finding.path and finding.path in crashed_paths)
    crash_note = (
        f"The hosting binary {finding.path} was dynamically crashed on attacker-controlled input by "
        "Firefly's harness fuzzer (reproducer recorded) — a confirmed input-reachable "
        "memory-safety/DoS defect in that binary."
    ) if crashed else ""

    if isinstance(reach, dict):
        status = reach.get("status")
        funcs = ", ".join(reach.get("functions") or [])
        if status == "not_present":
            if meta.get("kev") or finding.severity is Severity.CRITICAL or crashed:
                detail = (
                    f"vulnerable function(s) {funcs} appear absent from the matched binary, but "
                    "this CVE is known-exploited or critical — confirm manually (functions can be "
                    "inlined, stripped, or statically linked)."
                )
                return {"state": "in_triage", "detail": f"{detail} {crash_note}".strip()}
            return {
                "state": "not_affected",
                "justification": "code_not_present",
                "detail": f"vulnerable function(s) {funcs} are absent from the matched binary "
                "(may be compiled out, inlined, or stripped).",
            }
        if status == "reachable":
            present = ", ".join(reach.get("present") or [])
            if crashed:
                return {
                    "state": "exploitable",
                    "detail": f"binary references vulnerable function(s): {present}. {crash_note} "
                    "Confirm whether this specific CVE is the trigger.",
                }
            return {"state": "in_triage", "detail": f"binary references vulnerable function(s): {present}."}
    if finding.confidence == "low":
        # Keep doubtful matches visible to SBOM consumers, but as untriaged.
        reasons = "; ".join(meta.get("confidence_reasons", []))
        if crashed:
            return {"state": "in_triage", "detail": f"{reasons}. {crash_note}" if reasons else crash_note}
        return {"state": "in_triage", "detail": reasons}
    if crashed:
        return {"state": "in_triage", "detail": f"confident CVE match with no symbol-level reachability analysis. {crash_note}"}
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

    crashed_paths = _dynamically_crashed_paths(result.findings)
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
        if finding.path and finding.path in crashed_paths:
            vuln["properties"].append({"name": "firefly:dynamic", "value": "crashed"})
        analysis = _vex_analysis(finding, crashed_paths)
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
