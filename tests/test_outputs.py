import json
import re

import pytest

from firefly import htmlreport, sarif


@pytest.fixture
def report():
    return {
        "input": {"path": "/fw/router.bin", "sha256": "deadbeef", "size": 1024},
        "started": "2026-10-27T00:00:00+00:00",
        "finished": "2026-10-27T00:01:00+00:00",
        "components": [
            {"vendor": "openssl", "product": "openssl", "version": "1.0.2a", "paths": ["lib/libssl.so"], "cpe": "cpe:2.3:a:openssl:openssl:1.0.2a:*:*:*:*:*:*:*"},
        ],
        "findings": [
            {"analyzer": "cves", "title": "CVE-2016-2108 in openssl 1.0.2a", "severity": "critical", "confidence": "high", "path": "lib/libssl.so", "description": "ASN.1 bug.", "evidence": None, "id": "FF-aaa", "metadata": {"cve": "CVE-2016-2108", "cvss_score": 9.8, "kev": False, "component": {"vendor": "openssl", "product": "openssl", "version": "1.0.2a"}, "url": "https://nvd.nist.gov/vuln/detail/CVE-2016-2108", "line": None}},
            {"analyzer": "credentials", "title": "Private key in a.pem", "severity": "critical", "confidence": "high", "path": "etc/a.pem", "description": "Key.", "evidence": "-----BEGIN RSA PRIVATE KEY----- (100 base64 chars)", "id": "FF-bbb", "metadata": {"kind": "private_key", "line": 1}},
            {"analyzer": "accounts", "title": "root empty password", "severity": "high", "confidence": "high", "path": "etc/shadow", "description": "No password.", "evidence": None, "id": "FF-ccc", "metadata": {}},
            {"analyzer": "crypto", "title": "No boot-integrity mechanism detected", "severity": "low", "confidence": "low", "path": None, "description": "Posture.", "evidence": None, "id": "FF-ddd", "metadata": {}},
        ],
        "artifacts": {},
        "errors": [],
    }


# --------------------------------------------------------------------------- SARIF


def test_sarif_structure(report):
    doc = sarif.build(report)
    assert doc["version"] == "2.1.0"
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "Firefly"
    assert len(run["results"]) == 4
    rule_ids = {r["id"] for r in run["tool"]["driver"]["rules"]}
    assert {"cves", "credentials", "accounts"} <= rule_ids


def test_sarif_every_result_has_a_location(report):
    # GitHub code scanning rejects the whole upload if any result lacks a
    # location, so a path-less finding must fall back to the firmware image.
    results = sarif.build(report)["runs"][0]["results"]
    assert all(r["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] for r in results)
    posture = next(r for r in results if r["ruleId"] == "crypto")
    assert posture["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "router.bin"


def test_sarif_levels_and_severity(report):
    cve = next(r for r in sarif.build(report)["runs"][0]["results"] if r["ruleId"] == "cves")
    assert cve["level"] == "error" and cve["properties"]["security-severity"] == "9.8"
    # a finding without CVSS falls back to the severity number
    acct = next(r for r in sarif.build(report)["runs"][0]["results"] if r["ruleId"] == "accounts")
    assert acct["level"] == "error" and acct["properties"]["security-severity"] == "8.0"


def test_sarif_fingerprints_and_locations(report):
    results = sarif.build(report)["runs"][0]["results"]
    assert all("fireflyFindingId/v1" in r["partialFingerprints"] for r in results)
    key = next(r for r in results if r["ruleId"] == "credentials")
    assert key["locations"][0]["physicalLocation"]["artifactLocation"]["uri"] == "etc/a.pem"
    assert key["locations"][0]["physicalLocation"]["region"]["startLine"] == 1


def test_sarif_write(report, tmp_path):
    p = sarif.write(report, str(tmp_path / "out.sarif"))
    doc = json.loads(open(p, encoding="utf-8").read())
    assert doc["$schema"].endswith("sarif-2.1.0.json")


# --------------------------------------------------------------------------- HTML


def test_html_is_self_contained(report):
    html = htmlreport.build(report)
    assert html.lstrip().startswith("<!doctype html>")
    # no external resources (ignore the W3C namespace in any SVG/xmlns)
    body = html.replace("http://www.w3.org", "")
    assert "src=" not in body and "cdn" not in body.lower() and "//unpkg" not in body
    assert "<link" not in body


def test_html_embeds_data_safely(report):
    html = htmlreport.build(report)
    # the JSON is embedded but closing-tag sequences are neutralised
    assert "</script" not in html.split('id="data"')[1].split("</script>")[0].replace("<\\/script", "")
    # data is parseable: extract and load it
    raw = html.split('type="application/json">', 1)[1].split("</script>", 1)[0].replace("<\\/", "</")
    data = json.loads(raw)
    assert len(data["findings"]) == 4


def test_html_contains_no_unredacted_secret(report):
    html = htmlreport.build(report)
    assert not re.search(r"MI[A-Za-z0-9+/]{40,}", html)
    assert "BEGIN RSA PRIVATE KEY----- (100 base64 chars)" in html  # redacted preview kept


def test_html_write_result(report, tmp_path, monkeypatch):
    # write_result goes through report.to_dict, so drive it from a ScanResult
    from firefly.pipeline import ScanResult

    r = ScanResult(input_path="/fw/x.bin", input_sha256="abc", input_size=10, workdir=str(tmp_path), started="t")
    p = htmlreport.write_result(r, str(tmp_path / "r.html"))
    assert open(p, encoding="utf-8").read().lstrip().startswith("<!doctype html>")


def test_to_dict_omits_files_unless_recorded(tmp_path):
    # The diff relies on the "files" key's presence to tell "not recorded" from
    # "genuinely empty", so to_dict must omit it when file_inventory is False.
    from firefly.report import to_dict
    from firefly.pipeline import ScanResult

    base = dict(input_path="/fw/x.bin", input_sha256="abc", input_size=10, workdir=str(tmp_path), started="t")
    assert "files" not in to_dict(ScanResult(**base))  # default: not recorded
    recorded = ScanResult(**base, files=[{"path": "a", "kind": "data", "size": 1, "sha256": "h"}], file_inventory=True)
    out = to_dict(recorded)
    assert out["files"] == [{"path": "a", "kind": "data", "size": 1, "sha256": "h"}]
