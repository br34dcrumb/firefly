"""Map scan findings to the OWASP IoT Top 10 (2018) — indicative coverage only.

This is **not** a certification or an attestation. There is no separate numbered
"OWASP Firmware Top 10"; the OWASP IoT Top 10 is the standard numbered list and
is what firmware assessments cite, so that is what Firefly maps to.

Each finding is grouped under the one category it most directly evidences.
Findings that don't correspond to a category (e.g. exploit-mitigation hardening,
which the Top 10 has no entry for) are counted separately rather than forced
into an ill-fitting bucket. A category with no findings means only that *this
scan surfaced nothing for it* — never that the device complies.
"""

from __future__ import annotations

from typing import Any

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


def map_report(report: dict[str, Any], min_confidence: str = "medium") -> dict[str, Any]:
    floor = CONFIDENCE_RANK.get(min_confidence, 1)
    findings = [f for f in report.get("findings", []) if CONFIDENCE_RANK.get(f.get("confidence", "medium"), 1) >= floor]

    grouped: dict[str, list[dict[str, Any]]] = {}
    unmapped = 0
    for f in findings:
        cat = category(f)
        if cat is None:
            unmapped += 1
        else:
            grouped.setdefault(cat, []).append(f)

    def worst(fs: list[dict[str, Any]]) -> str:
        return max((f.get("severity", "info") for f in fs), key=lambda s: _rank(s))

    categories = [
        {
            "id": cid,
            "name": OWASP[cid],
            "findings": len(grouped[cid]),
            "worst_severity": worst(grouped[cid]),
            "finding_ids": [f.get("id") for f in grouped[cid] if f.get("id")],
            "titles": sorted({f.get("title", "") for f in grouped[cid]}),
        }
        for cid in sorted(grouped, key=_cat_order)
    ]
    return {
        "standard": "OWASP IoT Top 10 (2018)",
        "disclaimer": DISCLAIMER,
        "categories": categories,
        "unmapped": unmapped,
        "without_findings": [OWASP[cid] for cid in OWASP if cid not in grouped],
    }


def _rank(sev: str) -> int:
    try:
        return Severity(sev).rank
    except ValueError:
        return 0


def _cat_order(cid: str) -> int:
    return int(cid[1:])  # "I7" -> 7


def print_coverage(coverage: dict[str, Any]) -> None:
    from rich.console import Console
    from rich.table import Table

    from firefly.report import _SEVERITY_STYLE

    console = Console()
    console.print(f"[bold]OWASP coverage[/bold] — {coverage['standard']}")
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
        console.print("No findings mapped to an OWASP IoT Top 10 category.")
    if coverage["unmapped"]:
        console.print(f"[dim]{coverage['unmapped']} finding(s) have no OWASP Top 10 category (e.g. exploit mitigations, dangerous-function leads).[/]")
    if coverage["without_findings"]:
        console.print(f"[dim]No findings for: {', '.join(c.split(' ', 1)[0] for c in coverage['without_findings'])}[/]")
    console.print(f"[dim]{coverage['disclaimer']}[/]")
