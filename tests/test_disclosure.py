import json
from datetime import date

import pytest

from firefly import advisory, disclosure
from firefly.cli import main


def _f(analyzer, title, severity, confidence="high", path=None, evidence=None, metadata=None):
    return {
        "analyzer": analyzer,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "path": path,
        "evidence": evidence,
        "description": title,
        "metadata": metadata or {},
        "id": f"FF-{abs(hash((analyzer, title, path))) % 10**10:010d}",
    }


@pytest.fixture
def report():
    return {
        "input": {"path": "/firmware/router.bin", "sha256": "abc"},
        "findings": [
            _f("credentials", "Private key in a.pem (RSA PRIVATE KEY)", "critical", path="etc/a.pem", evidence="-----BEGIN RSA PRIVATE KEY----- (100 base64 chars)", metadata={"kind": "private_key"}),
            _f("credentials", "Private key in b.pem (RSA PRIVATE KEY)", "critical", path="etc/b.pem", evidence="-----BEGIN RSA PRIVATE KEY----- (120 base64 chars)", metadata={"kind": "private_key"}),
            _f("credentials", "Hardcoded credential in cfg (admin_pw)", "high", path="etc/cfg", evidence="admin_pw=R3**********", metadata={"kind": "password"}),
            _f("services", "Telnet server started at boot (etc/inittab)", "high", path="etc/inittab", evidence="::respawn:/usr/sbin/telnetd"),
            _f("hardening", "Executable stack / no NX in foo", "medium", path="bin/foo"),
            _f("cves", "CVE-2016-2108 in openssl 1.0.2a", "critical", path="lib/libssl.so", metadata={"cve": "CVE-2016-2108", "cvss_score": 9.8, "component": {"vendor": "openssl", "product": "openssl", "version": "1.0.2a"}, "url": "https://nvd.nist.gov/vuln/detail/CVE-2016-2108"}),
            _f("cves", "CVE-2016-2109 in openssl 1.0.2a", "high", path="lib/libssl.so", metadata={"cve": "CVE-2016-2109", "cvss_score": 7.5, "component": {"vendor": "openssl", "product": "openssl", "version": "1.0.2a"}, "url": "https://nvd.nist.gov/vuln/detail/CVE-2016-2109"}),
            _f("dangerfns", "noise", "medium", confidence="low", path="bin/x", metadata={"functions": ["strcpy"]}),
        ],
    }


def test_build_items_groups_and_filters(report):
    items = disclosure.build_items(report)
    cats = {i.category: i for i in items}
    # first-party only (no cves by default), low-confidence dangerfns dropped
    assert set(cats) == {"credentials", "services", "hardening"}
    # two private keys grouped into one item with both paths; password is a separate item
    cred_items = [i for i in items if i.category == "credentials"]
    pk = next(i for i in cred_items if "private key" in i.title.lower())
    assert set(pk.affected_paths) == {"etc/a.pem", "etc/b.pem"} and len(pk.evidence) == 2
    assert any("credential" in i.title.lower() for i in cred_items)
    # sorted by severity: critical private key first
    assert items[0].severity == "critical"


def test_include_cves_groups_per_component(report):
    items = disclosure.build_items(report, include_cves=True)
    cve_items = [i for i in items if i.category == "known_cves"]
    assert len(cve_items) == 1
    assert "openssl 1.0.2a" in cve_items[0].title and "2 known" in cve_items[0].title
    assert len(cve_items[0].references) == 2


def test_items_carry_no_unredacted_secret(report):
    items = disclosure.build_items(report)
    blob = json.dumps([i.__dict__ for i in items])
    assert "R3**********" in blob  # the redacted form is kept
    assert "BEGIN RSA PRIVATE KEY----- (" in blob  # only the redacted preview
    # no base64 key body
    import re

    assert not re.search(r"MI[A-Za-z0-9+/]{40,}", blob)


def test_tracker_preserves_discovery_date(report):
    items = disclosure.build_items(report)
    t = disclosure.update_tracker({"items": {}}, items, 90, today=date(2026, 1, 1))
    first = {k: v["deadline"] for k, v in t["items"].items()}
    assert all(v["discovered"] == "2026-01-01" for v in t["items"].values())
    assert all(v == "2026-04-01" for v in first.values())
    # re-run a month later: discovery date and deadline must not move
    t2 = disclosure.update_tracker(t, items, 90, today=date(2026, 2, 1))
    assert all(v["discovered"] == "2026-01-01" for v in t2["items"].values())
    assert {k: v["deadline"] for k, v in t2["items"].items()} == first


def test_tracker_deadline_counts_from_reported_date(report):
    items = disclosure.build_items(report)
    t = disclosure.update_tracker({"items": {}}, items, 90, today=date(2026, 1, 1))
    some_id = next(iter(t["items"]))
    t["items"][some_id]["reported"] = "2026-03-01"
    t = disclosure.update_tracker(t, items, 90, today=date(2026, 3, 2))
    assert t["items"][some_id]["deadline"] == date(2026, 5, 30).isoformat()


def test_parse_security_txt():
    txt = "Contact: mailto:security@acme.example\nContact: https://acme.example/report\nEncryption: https://acme.example/pgp.txt\nPolicy: https://acme.example/policy\n"
    fields = advisory.parse_security_txt(txt)
    assert fields["contact"] == ["mailto:security@acme.example", "https://acme.example/report"]
    assert fields["policy"] == ["https://acme.example/policy"]


def test_render_advisory_is_a_redacted_draft(report):
    item = disclosure.build_items(report)[0]
    md = advisory.render_advisory(item, researcher="R <r@e.com>", vendor="ACME", discovered="2026-01-01", deadline="2026-04-01", security_txt=None)
    assert "DRAFT" in md and "does not send" in md
    assert "security.txt" in md  # contact guidance present
    import re

    assert not re.search(r"MI[A-Za-z0-9+/]{40,}", md)


def test_render_advisory_uses_supplied_security_txt(report):
    item = disclosure.build_items(report)[0]
    md = advisory.render_advisory(item, researcher="R", vendor="ACME", discovered="d", deadline="x", security_txt="Contact: security@acme.example\n")
    assert "security@acme.example" in md


def test_disclose_cli_writes_package(report, tmp_path):
    rpt = tmp_path / "firefly.json"
    rpt.write_text(json.dumps(report), encoding="utf-8")
    out = tmp_path / "disc"
    rc = main(["disclose", str(rpt), "-o", str(out), "--vendor", "ACME", "--researcher", "R <r@e.com>"])
    assert rc == 0
    assert (out / "README.md").exists() and (out / "tracker.json").exists()
    advisories = list((out / "advisories").glob("*.md"))
    assert len(advisories) == 4  # grouped keys + password + services + hardening
    tracker = json.loads((out / "tracker.json").read_text())
    assert tracker["deadline_days"] == 90 and len(tracker["items"]) == len(advisories)
