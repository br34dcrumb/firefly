"""Render coordinated-disclosure advisory drafts (Markdown) from items.

Output is a *draft* for a human to review, complete and send. It never
contains exploit steps, and secret values stay redacted. Vendor-contact
guidance is offline: Firefly does not fetch anything (that would reveal which
firmware is being analysed). If the user supplies a saved ``security.txt`` it
is parsed locally; otherwise the advisory explains where to look.
"""

from __future__ import annotations

import re
from datetime import date

from firefly.disclosure import DisclosureItem

_CONTACT = re.compile(r"^\s*Contact\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_ENCRYPTION = re.compile(r"^\s*Encryption\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)
_POLICY = re.compile(r"^\s*Policy\s*:\s*(.+?)\s*$", re.IGNORECASE | re.MULTILINE)


def parse_security_txt(text: str) -> dict[str, list[str]]:
    """Parse the fields of a saved security.txt (RFC 9116). Local text only."""
    return {
        "contact": _CONTACT.findall(text),
        "encryption": _ENCRYPTION.findall(text),
        "policy": _POLICY.findall(text),
    }


def contact_section(vendor: str | None, security_txt: str | None) -> str:
    if security_txt:
        fields = parse_security_txt(security_txt)
        lines = ["Vendor security contact (from the supplied security.txt):"]
        for c in fields["contact"]:
            lines.append(f"- Contact: {c}")
        for p in fields["policy"]:
            lines.append(f"- Policy: {p}")
        for e in fields["encryption"]:
            lines.append(f"- Encryption key: {e}")
        if len(lines) > 1:
            return "\n".join(lines)
    v = vendor or "the vendor"
    return (
        f"No vendor security contact was supplied. To find {v}'s contact, check, in order:\n"
        f"1. `https://<{v}-domain>/.well-known/security.txt` (RFC 9116)\n"
        f"2. The vendor's security / PSIRT / \"report a vulnerability\" page\n"
        f"3. A CNA listing at https://www.cve.org/PartnerInformation/ListofPartners\n"
        f"4. CERT/CC coordination (https://kb.cert.org/vuls/) if the vendor is unresponsive\n\n"
        f"Confirm the contact before sending. Firefly does not contact anyone on your behalf."
    )


def render_advisory(item: DisclosureItem, *, researcher: str, vendor: str | None, discovered: str, deadline: str, security_txt: str | None) -> str:
    paths = "\n".join(f"- `{p}`" for p in item.affected_paths[:50]) or "- (see scan report)"
    evidence = "\n".join(f"- `{e}`" for e in item.evidence) if item.evidence else "- (redacted; see scan report)"
    refs = "\n".join(f"- {r}" for r in item.references) if item.references else ""
    cwe = f"\n- **CWE:** {item.cwe}" if item.cwe else ""
    embargo = (
        "These are already-public CVEs; no embargo applies."
        if item.category == "known_cves"
        else f"Requested coordinated-disclosure date: **{deadline}** (configurable). Please acknowledge receipt."
    )
    # Built outside the f-string: an f-string expression cannot contain a
    # backslash on Python < 3.12.
    references = ("## References\n\n" + refs) if refs else ""
    return f"""# Security advisory (DRAFT): {item.title}

> DRAFT for review. Verify every detail and the vendor contact before sending.
> Firefly prepared this from an automated scan; it does not send disclosures.

- **Advisory ID:** {item.id}
- **Severity:** {item.severity}
- **Confidence:** {item.confidence}
- **Category:** {item.category}{cwe}
- **Reporter:** {researcher}
- **Vendor:** {vendor or "(fill in)"}
- **Discovered:** {discovered}
- **Disclosure target:** {deadline}

## Summary

{item.summary}

## Affected files

{paths}

## Evidence (redacted)

{evidence}

## Remediation

{item.remediation}

## Disclosure

{embargo}

## Vendor contact

{contact_section(vendor, security_txt)}

{references}
"""


def render_index(items: list[DisclosureItem], *, target: str, discovered: str, researcher: str) -> str:
    rows = "\n".join(
        f"| {i.id} | {i.severity} | {i.category} | {i.title} |" for i in items
    )
    counts: dict[str, int] = {}
    for i in items:
        counts[i.severity] = counts.get(i.severity, 0) + 1
    tally = ", ".join(f"{n} {sev}" for sev, n in sorted(counts.items(), key=lambda kv: -_rank(kv[0])))
    return f"""# Disclosure package: {target}

Prepared {date.today().isoformat()} by {researcher} using Firefly.
**{len(items)} item(s)** — {tally or "none"}.

These are drafts. Review each advisory, confirm the vendor contact, and send
them yourself. Firefly never contacts a vendor.

| ID | Severity | Category | Title |
|----|----------|----------|-------|
{rows}

See `advisories/` for one draft per item and `tracker.json` for the timeline.
"""


def _rank(sev: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, 0)
