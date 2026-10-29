"""Tests for compliance-framework mapping (firefly comply)."""

from __future__ import annotations

import json

import pytest

from firefly import compliance
from firefly.cli import main


def _f(analyzer, title, severity="high", confidence="high", cve=None):
    md = {"cve": cve, "component": {"vendor": "x", "product": "x", "version": "1"}} if cve else {}
    return {"analyzer": analyzer, "title": title, "severity": severity, "confidence": confidence,
            "id": f"FF-{analyzer}-{abs(hash(title)) % 10000:04d}", "metadata": md}


def _report(findings):
    return {"input": {"path": "/fw/router.bin", "sha256": "abc"}, "components": [], "findings": findings}


FINDINGS = [
    _f("credentials", "Private key in a.pem", "critical"),
    _f("accounts", "root empty password", "critical"),
    _f("services", "Telnet server started at boot (etc/inittab)", "high"),
    _f("cves", "CVE-2021-3711 in openssl 1.1.1k", "critical", cve="CVE-2021-3711"),
    _f("crypto", "RC4 referenced by 2 binaries", "medium"),
    _f("crypto", "No boot-integrity mechanism detected", "low"),
    _f("hardening", "Executable stack / no NX in foo", "medium"),  # intentionally unmapped
]


def test_category_mapping():
    assert compliance.category(FINDINGS[0]) == "I1"  # credentials
    assert compliance.category(FINDINGS[1]) == "I1"  # accounts
    assert compliance.category(FINDINGS[2]) == "I2"  # services
    assert compliance.category(FINDINGS[3]) == "I5"  # cves
    assert compliance.category(FINDINGS[4]) == "I7"  # crypto primitive
    assert compliance.category(FINDINGS[5]) == "I4"  # crypto secure-boot posture
    assert compliance.category(FINDINGS[6]) is None  # hardening has no clean Top 10 home


def test_map_report_groups_and_counts():
    cov = compliance.map_report(_report(FINDINGS))
    by_id = {c["id"]: c for c in cov["categories"]}
    assert by_id["I1"]["findings"] == 2 and by_id["I1"]["worst_severity"] == "critical"
    assert set(by_id) == {"I1", "I2", "I4", "I5", "I7"}
    # categories are ordered I1, I2, I4, I5, I7
    assert [c["id"] for c in cov["categories"]] == ["I1", "I2", "I4", "I5", "I7"]
    assert cov["unmapped"] == 1  # the hardening finding
    assert "I3:2018 Insecure Ecosystem Interfaces" in cov["without_findings"]
    assert "attestation" in cov["disclaimer"]


def test_min_confidence_filters():
    findings = [_f("cves", "low-conf match", "high", confidence="low", cve="CVE-X")]
    assert compliance.map_report(_report(findings))["categories"] == []  # low hidden at medium
    assert compliance.map_report(_report(findings), min_confidence="low")["categories"][0]["id"] == "I5"


def test_cli_json_and_file(tmp_path, capsys):
    rpt = tmp_path / "firefly.json"
    rpt.write_text(json.dumps(_report(FINDINGS)), encoding="utf-8")
    out = tmp_path / "coverage.json"
    rc = main(["comply", str(rpt), "-o", str(out), "--json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["standard"] == "OWASP IoT Top 10 (2018)"
    assert doc["framework"] == "owasp"
    assert json.loads(out.read_text())["categories"][0]["id"] == "I1"


# --------------------------------------------------------------------------- CRA


def test_cra_mapping():
    m = lambda f: compliance.map_report(_report([f]), framework="cra")["categories"][0]["id"]  # noqa: E731
    assert m(FINDINGS[0]) == "access-control"      # credentials
    assert m(FINDINGS[1]) == "access-control"      # accounts
    assert m(FINDINGS[2]) == "attack-surface"      # services
    assert m(FINDINGS[3]) == "no-known-vuln"       # cves
    assert m(FINDINGS[4]) == "confidentiality"     # crypto primitive
    assert m(FINDINGS[5]) == "secure-updates"      # crypto secure-boot
    assert m(FINDINGS[6]) == "exploit-mitigation"  # hardening has a home in CRA


def test_cra_report_shape():
    cov = compliance.map_report(_report(FINDINGS), framework="cra")
    assert cov["framework"] == "cra" and cov["standard"].startswith("EU Cyber Resilience Act")
    assert cov["unmapped"] == 0  # every sample finding maps under CRA
    # categories keep the framework's own (insertion) order
    ids = [c["id"] for c in cov["categories"]]
    assert ids == [cid for cid in compliance.CRA if cid in ids]


# --------------------------------------------------------------------------- IEC 62443


def test_iec62443_mapping():
    m = lambda f: compliance.map_report(_report([f]), framework="iec62443")["categories"][0]["id"]  # noqa: E731
    assert m(FINDINGS[1]) == "FR1"  # accounts -> identification & auth
    assert m(FINDINGS[2]) == "FR5"  # services -> restricted data flow
    assert m(FINDINGS[3]) == "FR3"  # cves -> system integrity
    assert m(FINDINGS[4]) == "FR4"  # crypto primitive -> data confidentiality
    assert m(FINDINGS[5]) == "FR3"  # crypto secure-boot -> system integrity
    assert m(FINDINGS[6]) == "FR3"  # hardening -> system integrity


def test_unknown_framework_rejected():
    with pytest.raises(ValueError):
        compliance.map_report(_report(FINDINGS), framework="nope")


def test_cli_framework_flag(tmp_path, capsys):
    rpt = tmp_path / "firefly.json"
    rpt.write_text(json.dumps(_report(FINDINGS)), encoding="utf-8")
    rc = main(["comply", str(rpt), "--framework", "iec62443", "--json"])
    assert rc == 0
    doc = json.loads(capsys.readouterr().out)
    assert doc["framework"] == "iec62443"
    assert any(c["id"] == "FR3" for c in doc["categories"])
