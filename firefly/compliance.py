"""Map scan findings to a compliance framework — indicative coverage only.

Three frameworks are supported, selected by key:

* ``owasp``    — OWASP IoT Top 10 (2018), the numbered list firmware
                 assessments cite (there is no separate "OWASP Firmware Top 10").
* ``cra``      — EU Cyber Resilience Act, Annex I Part I (the essential
                 cybersecurity *product* requirements).
* ``iec62443`` — IEC 62443-4-2 Foundational Requirements (FR1–FR7), the
                 component-level technical security requirements.

This is **not** a certification or an attestation. Each finding is grouped under
the one category it most directly evidences; findings with no clean home are
counted as ``unmapped`` rather than forced into an ill-fitting bucket. A category
with no findings means only that *this scan surfaced nothing for it* — never that
the device complies. The mappings are conservative and automated-evidence-based;
a human must confirm them before any reporting.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Callable

from firefly.models import Severity
from firefly.report import CONFIDENCE_RANK

# OWASP IoT Top 10 (2018), full labels.
OWASP: dict[str, str] = {
    "I1": "I1:2018 Weak, Guessable, or Hardcoded Passwords",
    "I2": "I2:2018 Insecure Network Services",
    "I3": "I3:2018 Insecure Ecosystem Interfaces",
    "I4": "I4:2018 Lack of Secure Update Mechanism",
    "I5": "I5:2018 Use of Insecure or Outdated Components",
    "I6": "I6:2018 Insufficient Privacy Protection",
    "I7": "I7:2018 Insecure Data Transfer and Storage",
    "I8": "I8:2018 Lack of Device Management",
    "I9": "I9:2018 Insecure Default Settings",
    "I10": "I10:2018 Lack of Physical Hardening",
}

# EU Cyber Resilience Act, Annex I Part I — the essential cybersecurity product
# requirements Firefly can evidence from static/dynamic findings.
CRA: dict[str, str] = {
    "no-known-vuln": "Annex I(1) Made available without known exploitable vulnerabilities",
    "secure-defaults": "Annex I(2)(b) Secure-by-default configuration",
    "access-control": "Annex I(2)(d) Protection from unauthorised access (authentication)",
    "confidentiality": "Annex I(2)(e) Confidentiality of stored/transmitted data (encryption)",
    "integrity": "Annex I(2)(f) Integrity of data, commands and configuration",
    "attack-surface": "Annex I(2)(j) Limited attack surfaces",
    "exploit-mitigation": "Annex I(2)(k) Reduced impact of incidents (exploitation mitigation)",
    "secure-updates": "Annex I(2)(c) Secure update mechanism",
}

# IEC 62443-4-2 Foundational Requirements (component-level).
IEC62443: dict[str, str] = {
    "FR1": "FR 1 Identification and Authentication Control",
    "FR2": "FR 2 Use Control",
    "FR3": "FR 3 System Integrity",
    "FR4": "FR 4 Data Confidentiality",
    "FR5": "FR 5 Restricted Data Flow",
    "FR6": "FR 6 Timely Response to Events",
    "FR7": "FR 7 Resource Availability",
}

DISCLAIMER = (
    "Indicative coverage derived from automated findings. Not a certification or "
    "attestation; a category with no findings is not evidence of compliance."
)


def category(finding: dict[str, Any]) -> str | None:
    """The OWASP IoT Top 10 id a finding most directly evidences, or None.

    Mapped conservatively: only where an analyzer's finding corresponds cleanly
    to a category. Exploit mitigations (hardening), dangerous-function leads
    (dangerfns), component identification (fingerprint) and the entropy signal
    have no clean Top 10 home and are deliberately left unmapped.
    """
    analyzer = finding.get("analyzer")
    title = (finding.get("title") or "").lower()
    if analyzer in ("accounts", "credentials"):
        return "I1"  # weak/empty passwords, hardcoded secrets
    if analyzer == "services":
        return "I2"  # telnet/rsh/anon-FTP/weak-SSH at boot
    if analyzer == "cves":
        return "I5"  # known CVE in a shipped component
    if analyzer == "crypto":
        # secure-boot posture -> update mechanism; everything else crypto -> data protection
        return "I4" if "boot-integrity" in title else "I7"
    if analyzer == "emulation":
        return "I2" if "reachable on the running device" in title else None
    return None


def _cra_category(finding: dict[str, Any]) -> str | None:
    """CRA Annex I Part I requirement a finding most directly evidences.

    Unlike the OWASP map, hardening and dangerous-function leads have a home
    here (exploitation-mitigation), so fewer findings are left unmapped.
    """
    analyzer = finding.get("analyzer")
    title = (finding.get("title") or "").lower()
    if analyzer in ("accounts", "credentials"):
        return "access-control"
    if analyzer == "services":
        return "attack-surface"
    if analyzer == "cves":
        return "no-known-vuln"
    if analyzer == "crypto":
        return "secure-updates" if "boot-integrity" in title else "confidentiality"
    if analyzer in ("hardening", "dangerfns"):
        return "exploit-mitigation"
    if analyzer == "emulation":
        return "attack-surface" if "reachable on the running device" in title else None
    return None


def _iec62443_category(finding: dict[str, Any]) -> str | None:
    """IEC 62443-4-2 Foundational Requirement a finding most directly evidences."""
    analyzer = finding.get("analyzer")
    title = (finding.get("title") or "").lower()
    if analyzer in ("accounts", "credentials"):
        return "FR1"  # identification & authentication control
    if analyzer == "services":
        return "FR5"  # restricted data flow: unnecessary/insecure open services
    if analyzer == "crypto":
        return "FR3" if "boot-integrity" in title else "FR4"  # integrity vs data confidentiality
    if analyzer in ("cves", "hardening", "dangerfns"):
        return "FR3"  # system integrity: vulnerable/unmitigated code
    if analyzer == "emulation":
        return "FR5" if "reachable on the running device" in title else None
    return None


@dataclass(frozen=True)
class Framework:
    key: str
    standard: str
    labels: dict[str, str]
    classify: Callable[[dict[str, Any]], str | None]


FRAMEWORKS: dict[str, Framework] = {
    "owasp": Framework("owasp", "OWASP IoT Top 10 (2018)", OWASP, category),
    "cra": Framework("cra", "EU Cyber Resilience Act, Annex I Part I", CRA, _cra_category),
    "iec62443": Framework("iec62443", "IEC 62443-4-2 Foundational Requirements", IEC62443, _iec62443_category),
}


def map_report(report: dict[str, Any], min_confidence: str = "medium", framework: str = "owasp") -> dict[str, Any]:
    fw = FRAMEWORKS.get(framework)
    if fw is None:
        raise ValueError(f"unknown compliance framework: {framework!r} (choose from {', '.join(FRAMEWORKS)})")
    floor = CONFIDENCE_RANK.get(min_confidence, 1)
    findings = [f for f in report.get("findings", []) if CONFIDENCE_RANK.get(f.get("confidence", "medium"), 1) >= floor]

    grouped: dict[str, list[dict[str, Any]]] = {}
    unmapped = 0
    for f in findings:
        cat = fw.classify(f)
        if cat is None:
            unmapped += 1
        else:
            grouped.setdefault(cat, []).append(f)

    def worst(fs: list[dict[str, Any]]) -> str:
        return max((f.get("severity", "info") for f in fs), key=lambda s: _rank(s))

    order = list(fw.labels)  # category order follows the framework's own numbering
    categories = [
        {
            "id": cid,
            "name": fw.labels[cid],
            "findings": len(grouped[cid]),
            "worst_severity": worst(grouped[cid]),
            "finding_ids": [f.get("id") for f in grouped[cid] if f.get("id")],
            "titles": sorted({f.get("title", "") for f in grouped[cid]}),
        }
        for cid in sorted(grouped, key=order.index)
    ]
    return {
        "standard": fw.standard,
        "framework": fw.key,
        "disclaimer": DISCLAIMER,
        "categories": categories,
        "unmapped": unmapped,
        "without_findings": [fw.labels[cid] for cid in fw.labels if cid not in grouped],
    }


def _rank(sev: str) -> int:
    try:
        return Severity(sev).rank
    except ValueError:
        return 0


def print_coverage(coverage: dict[str, Any]) -> None:
    from rich.console import Console
    from rich.table import Table

    from firefly.report import _SEVERITY_STYLE

    console = Console()
    console.print(f"[bold]Compliance coverage[/bold] — {coverage['standard']}")
    if coverage["categories"]:
        table = Table()
        table.add_column("Category")
        table.add_column("Findings", justify="right")
        table.add_column("Worst", justify="left")
        for c in coverage["categories"]:
            try:
                sev = f"[{_SEVERITY_STYLE[Severity(c['worst_severity'])]}]{c['worst_severity']}[/]"
            except (ValueError, KeyError):
                sev = c["worst_severity"]
            table.add_row(c["name"], str(c["findings"]), sev)
        console.print(table)
    else:
        console.print(f"No findings mapped to a {coverage['standard']} category.")
    if coverage["unmapped"]:
        console.print(f"[dim]{coverage['unmapped']} finding(s) have no category in this framework (e.g. exploit mitigations, dangerous-function leads).[/]")
    if coverage["without_findings"]:
        console.print(f"[dim]No findings for: {', '.join(c.split(' ', 1)[0] for c in coverage['without_findings'])}[/]")
    console.print(f"[dim]{coverage['disclaimer']}[/]")
