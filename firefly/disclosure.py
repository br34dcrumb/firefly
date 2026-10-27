"""Prepare a coordinated-disclosure package from a scan report.

Firefly never contacts a vendor. This module turns findings into advisory
*drafts* plus a timeline tracker, for a human to review and send. Design
choices that keep disclosure safe and responsible:

* Secrets are already redacted in findings; nothing here un-redacts them, and
  exploit steps are never generated — advisories describe the weakness and its
  fix, not how to attack it.
* Known-CVE findings are public already, so they are collapsed into one
  "update this component" remediation item, not treated as new disclosures.
* First-party issues (hardcoded keys, weak accounts, insecure services,
  dangerous attack surface) each become a disclosure item with a deadline.
* The timeline tracker preserves the original discovery date across re-scans,
  so the disclosure clock is not reset by re-running Firefly.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timedelta, timezone

from firefly.models import Severity

DEFAULT_DEADLINE_DAYS = 90

# analyzers whose findings are newly-discovered issues worth coordinated
# disclosure (as opposed to already-public CVEs)
FIRST_PARTY = {"credentials", "accounts", "services", "hardening", "dangerfns"}

# per-analyzer remediation guidance (no exploit detail)
REMEDIATION = {
    "credentials": "Remove the hardcoded secret from the image. Rotate it, since anyone with the firmware already has it. Load secrets at runtime from a provisioned, per-device store.",
    "accounts": "Set a unique strong password per device (never a shared default), remove unused accounts, drop extra UID-0 accounts, and re-hash with yescrypt or SHA-512.",
    "services": "Disable the service by default, or replace it with an authenticated, encrypted equivalent (e.g. SSH instead of telnet). Do not enable remote administration on untrusted interfaces.",
    "hardening": "Rebuild with modern mitigations: -fstack-protector-strong, -D_FORTIFY_SOURCE=2, -fPIE -pie, -Wl,-z,relro,-z,now, and a non-executable stack.",
    "dangerfns": "Review each call for untrusted input. Replace command execution with argument-vector APIs (no shell), and unbounded string/format functions with bounded equivalents.",
}


@dataclass
class DisclosureItem:
    id: str
    title: str
    category: str  # analyzer name, or "known_cves"
    severity: str
    confidence: str
    summary: str
    remediation: str
    affected_paths: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)  # already redacted
    cwe: str | None = None
    references: list[str] = field(default_factory=list)
    finding_ids: list[str] = field(default_factory=list)


def _sev_rank(name: str) -> int:
    try:
        return Severity(name).rank
    except ValueError:
        return 0


def build_items(report: dict, min_confidence: str = "medium", include_cves: bool = False) -> list[DisclosureItem]:
    floor = {"low": 0, "medium": 1, "high": 2}.get(min_confidence, 1)
    conf_rank = {"low": 0, "medium": 1, "high": 2}
    findings = [f for f in report.get("findings", []) if conf_rank.get(f.get("confidence", "medium"), 1) >= floor]
    items: list[DisclosureItem] = []

    # First-party issues: group by (analyzer, subtype) so identical problems
    # across many files become one item with a list of locations.
    groups: dict[tuple[str, str], list[dict]] = {}
    for f in findings:
        if f["analyzer"] not in FIRST_PARTY:
            continue
        groups.setdefault((f["analyzer"], _subtype(f)), []).append(f)

    for (analyzer, subtype), fs in sorted(groups.items()):
        worst = max(fs, key=lambda f: (_sev_rank(f["severity"]), f.get("metadata", {}).get("cvss_score") or 0))
        paths = _dedup([f["path"] for f in fs if f.get("path")])
        evidence = _dedup([f["evidence"] for f in fs if f.get("evidence")])[:5]
        cwe = next((f["metadata"].get("cwe") for f in fs if f.get("metadata", {}).get("cwe")), None)
        items.append(
            DisclosureItem(
                id=_item_id(analyzer, subtype),
                title=_group_title(analyzer, subtype, fs),
                category=analyzer,
                severity=worst["severity"],
                confidence=_best_confidence(fs),
                summary=_group_summary(analyzer, subtype, fs, paths),
                remediation=REMEDIATION.get(analyzer, "Review and remediate per vendor policy."),
                affected_paths=paths[:50],
                evidence=evidence,
                cwe=cwe,
                finding_ids=_dedup([f.get("id", "") for f in fs]),
            )
        )

    # Known CVEs: one remediation item per outdated component.
    if include_cves:
        comp_groups: dict[tuple, list[dict]] = {}
        for f in findings:
            if f["analyzer"] != "cves":
                continue
            c = f["metadata"].get("component", {})
            comp_groups.setdefault((c.get("vendor"), c.get("product"), c.get("version")), []).append(f)
        for (vendor, product, version), fs in sorted(comp_groups.items(), key=lambda kv: str(kv[0])):
            cves = _dedup([f["metadata"]["cve"] for f in fs])
            worst = max(fs, key=lambda f: (_sev_rank(f["severity"]), f["metadata"].get("cvss_score") or 0))
            items.append(
                DisclosureItem(
                    id=_item_id("cves", f"{vendor}:{product}:{version}"),
                    title=f"Outdated {product} {version} with {len(cves)} known CVE(s)",
                    category="known_cves",
                    severity=worst["severity"],
                    confidence="high",
                    summary=f"The image ships {product} {version}, which has {len(cves)} publicly known CVEs. These are already public; coordinated embargo does not apply, but the component should be updated.",
                    remediation=f"Update {product} to a fixed release and rebuild. See the referenced CVEs for fixed versions.",
                    affected_paths=_dedup([f["path"] for f in fs if f.get("path")])[:50],
                    references=[f["metadata"].get("url", "") for f in fs[:20] if f.get("metadata", {}).get("url")],
                    finding_ids=_dedup([f.get("id", "") for f in fs]),
                )
            )

    items.sort(key=lambda i: (-_sev_rank(i.severity), i.category, i.title))
    return items


def _subtype(f: dict) -> str:
    md = f.get("metadata", {})
    if f["analyzer"] == "credentials":
        return md.get("kind", "secret")
    if f["analyzer"] == "accounts":
        return "policy"
    if f["analyzer"] == "services":
        return "insecure_service"
    if f["analyzer"] == "hardening":
        return "mitigations"
    if f["analyzer"] == "dangerfns":
        return "attack_surface"
    return "issue"


def _group_title(analyzer: str, subtype: str, fs: list[dict]) -> str:
    titles = {
        ("credentials", "private_key"): "Hardcoded private key(s) in firmware",
        ("credentials", "password"): "Hardcoded credential(s) in firmware",
        ("credentials", "api_token"): "Hardcoded API token(s)/secret(s) in firmware",
        ("accounts", "policy"): "Weak account / password-hash policy",
        ("services", "insecure_service"): "Insecure network service(s) enabled or shipped",
        ("hardening", "mitigations"): "Binaries built without exploit mitigations",
        ("dangerfns", "attack_surface"): "Memory-unsafe / command-exec functions in binaries",
    }
    return titles.get((analyzer, subtype), f"{analyzer}: {subtype}")


def _group_summary(analyzer: str, subtype: str, fs: list[dict], paths: list[str]) -> str:
    n = len(paths) or len(fs)
    where = f"{n} location(s)"
    if analyzer == "credentials":
        return f"Secrets are embedded in the firmware image ({where}). Values are redacted in this report. Anyone who obtains the firmware obtains these secrets."
    if analyzer == "accounts":
        return "The account database has weak policy: " + "; ".join(_dedup([f["title"] for f in fs]))[:400] + "."
    if analyzer == "services":
        return "Insecure services detected: " + "; ".join(_dedup([f["title"] for f in fs]))[:400] + "."
    if analyzer == "hardening":
        return f"{where} lack one or more exploit mitigations, lowering the bar for memory-corruption exploitation."
    if analyzer == "dangerfns":
        return f"{where} import memory-unsafe or command-execution functions. These are leads for manual review, not confirmed bugs."
    return where


def _best_confidence(fs: list[dict]) -> str:
    order = {"low": 0, "medium": 1, "high": 2}
    return max((f.get("confidence", "medium") for f in fs), key=lambda c: order.get(c, 1))


def _dedup(seq) -> list:
    out, seen = [], set()
    for x in seq:
        if x and x not in seen:
            seen.add(x)
            out.append(x)
    return out


def _item_id(analyzer: str, subtype: str) -> str:
    import hashlib

    return "FD-" + hashlib.sha256(f"{analyzer}|{subtype}".encode()).hexdigest()[:10]


# --------------------------------------------------------------------------- tracker


def load_tracker(path: str) -> dict:
    if os.path.isfile(path):
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, json.JSONDecodeError):
            pass
    return {"items": {}}


def update_tracker(tracker: dict, items: list[DisclosureItem], deadline_days: int, today: date | None = None) -> dict:
    today = today or datetime.now(timezone.utc).date()
    entries = tracker.setdefault("items", {})
    for item in items:
        existing = entries.get(item.id)
        if existing and existing.get("discovered"):
            # Preserve the original clock; only refresh mutable fields.
            discovered = date.fromisoformat(existing["discovered"])
            existing.update(title=item.title, severity=item.severity, category=item.category)
        else:
            discovered = today
            entries[item.id] = {
                "title": item.title,
                "category": item.category,
                "severity": item.severity,
                "discovered": discovered.isoformat(),
                "reported": None,
                "status": "draft",
            }
        entry = entries[item.id]
        entry.setdefault("status", "draft")
        base = date.fromisoformat(entry["reported"]) if entry.get("reported") else discovered
        entry["deadline"] = (base + timedelta(days=deadline_days)).isoformat()
    tracker["updated"] = today.isoformat()
    tracker["deadline_days"] = deadline_days
    return tracker


def save_tracker(tracker: dict, path: str) -> None:
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(tracker, fh, indent=2)
