"""SARIF 2.1.0 output, for CI (GitHub code scanning, etc.).

Each finding becomes a SARIF result; each analyzer becomes a rule. Severity is
exported both as a SARIF ``level`` and as the numeric ``security-severity``
property that code-scanning UIs rank by (the CVSS score when known). A stable
``partialFingerprints`` entry lets CI de-duplicate a finding across runs.
"""

from __future__ import annotations

import json
import os
from typing import Any

from firefly import __version__
from firefly.analyzers import all_analyzers

SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/br34dcrumb/firefly"

# SARIF has three result levels; map our five severities onto them.
_LEVEL = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}
# Fallback numeric severity (0-10) when a finding has no CVSS score.
_SEVERITY_NUMBER = {"critical": 9.5, "high": 8.0, "medium": 5.5, "low": 3.0, "info": 0.0}


def _rules() -> list[dict[str, Any]]:
    rules = []
    for cls in all_analyzers():
        rules.append(
            {
                "id": cls.name,
                "name": cls.name,
                "shortDescription": {"text": cls.description},
                "helpUri": INFO_URI,
                "properties": {"tags": ["security", cls.name]},
            }
        )
    return rules


def _result(finding: dict[str, Any]) -> dict[str, Any]:
    severity = finding["severity"]
    md = finding.get("metadata", {})
    score = md.get("cvss_score")
    sec_sev = float(score) if isinstance(score, (int, float)) else _SEVERITY_NUMBER.get(severity, 0.0)

    result: dict[str, Any] = {
        "ruleId": finding["analyzer"],
        "level": _LEVEL.get(severity, "warning"),
        "message": {"text": _message(finding)},
        "properties": {
            "security-severity": f"{sec_sev:.1f}",
            "severity": severity,
            "confidence": finding.get("confidence", "medium"),
        },
        # Stable across runs: lets code scanning track/dedupe the same finding.
        "partialFingerprints": {"fireflyFindingId/v1": finding.get("id", "")},
    }
    if finding.get("path"):
        region = {}
        if isinstance(md.get("line"), int):
            region["startLine"] = max(1, md["line"])
        location = {"physicalLocation": {"artifactLocation": {"uri": finding["path"]}}}
        if region:
            location["physicalLocation"]["region"] = region
        result["locations"] = [location]
    for key in ("cve", "cwe", "url"):
        if md.get(key):
            result["properties"][key] = md[key]
    return result


def _message(finding: dict[str, Any]) -> str:
    text = finding["title"]
    if finding.get("description"):
        text += "\n\n" + finding["description"]
    if finding.get("evidence"):
        text += f"\n\nEvidence (redacted): {finding['evidence']}"
    return text


def build(report: dict[str, Any]) -> dict[str, Any]:
    results = [_result(f) for f in report.get("findings", [])]
    inp = report.get("input", {})
    return {
        "$schema": SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Firefly",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": _rules(),
                    }
                },
                "results": results,
                "properties": {
                    "firmware": inp.get("path"),
                    "sha256": inp.get("sha256"),
                    "scanned": report.get("finished"),
                },
            }
        ],
    }


def write(report: dict[str, Any], path: str) -> str:
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(build(report), fh, indent=2)
    return path
