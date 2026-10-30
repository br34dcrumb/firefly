"""CycloneDX VEX (analysis block) derived from reachability triage."""

from __future__ import annotations

from firefly import sbom
from firefly.models import Component, Finding, Severity
from firefly.pipeline import ScanResult


def _result(finding: Finding, extra: list[Finding] | None = None) -> dict:
    comp = Component(product="zlib", version="1.2.11", vendor="zlib", paths=["lib/libz.so"])
    res = ScanResult(
        input_path="/fw/router.bin",
        input_sha256="abc",
        input_size=10,
        workdir="x",
        started="t",
        components=[comp],
        findings=[finding, *(extra or [])],
    )
    bom = sbom.build(res)
    return next(v for v in bom["vulnerabilities"] if v["id"] == finding.metadata["cve"])


def _crash_finding(path="lib/libz.so"):
    """A harness-fuzzer crash finding on the given binary (what Phase C emits)."""
    return Finding(analyzer="harness", title="crashed", severity=Severity.CRITICAL, confidence="high",
                   path=path, metadata={"confirmed_fuzz_crash": True, "repro_b64": "eA=="})


def _cve_finding(cve="CVE-2022-37434", *, severity=Severity.HIGH, confidence="high", reachability=None, reasons=None, kev=False):
    meta = {
        "cve": cve,
        "component": {"vendor": "zlib", "product": "zlib", "version": "1.2.11"},
        "url": f"https://nvd.nist.gov/vuln/detail/{cve}",
        "kev": kev,
        "kev_added": "2099-01-01" if kev else None,
        "confidence_reasons": reasons or [],
    }
    if reachability is not None:
        meta["reachability"] = reachability
    return Finding(analyzer="cves", title=cve, severity=severity, confidence=confidence, path="lib/libz.so", metadata=meta)


def test_not_present_becomes_not_affected():
    reach = {"status": "not_present", "functions": ["inflate", "inflateGetHeader"], "present": []}
    vuln = _result(_cve_finding(confidence="low", reachability=reach))
    assert vuln["analysis"]["state"] == "not_affected"
    assert vuln["analysis"]["justification"] == "code_not_present"
    assert "inflate" in vuln["analysis"]["detail"]
    # the raw status is also queryable as a property
    assert {"name": "firefly:reachability", "value": "not_present"} in vuln["properties"]


def test_kev_not_present_stays_in_triage():
    # A known-exploited CVE whose symbols look absent must never be cleared to
    # not_affected on a symbol-presence guess.
    reach = {"status": "not_present", "functions": ["inflate"], "present": []}
    vuln = _result(_cve_finding(reachability=reach, kev=True))
    assert vuln["analysis"]["state"] == "in_triage"
    assert "justification" not in vuln["analysis"]
    assert "known-exploited or critical" in vuln["analysis"]["detail"]


def test_critical_not_present_stays_in_triage():
    reach = {"status": "not_present", "functions": ["inflate"], "present": []}
    vuln = _result(_cve_finding(severity=Severity.CRITICAL, reachability=reach))
    assert vuln["analysis"]["state"] == "in_triage"
    assert "justification" not in vuln["analysis"]


def test_reachable_is_in_triage_with_present_functions():
    reach = {"status": "reachable", "functions": ["inflate", "inflateGetHeader"], "present": ["inflate"]}
    vuln = _result(_cve_finding(reachability=reach))
    assert vuln["analysis"]["state"] == "in_triage"
    assert "inflate" in vuln["analysis"]["detail"]
    assert {"name": "firefly:reachability", "value": "reachable"} in vuln["properties"]


def test_low_confidence_without_reachability_is_untriaged():
    # Unchanged behaviour: a doubtful match with no reachability data still
    # surfaces as in_triage carrying its confidence reasons.
    vuln = _result(_cve_finding(confidence="low", reasons=["matched on product name only"]))
    assert vuln["analysis"] == {"state": "in_triage", "detail": "matched on product name only"}
    assert not any(p["name"] == "firefly:reachability" for p in vuln["properties"])


def test_confident_match_without_reachability_has_no_analysis():
    vuln = _result(_cve_finding(confidence="high"))
    assert "analysis" not in vuln


# --------------------------------------------------------------------------- Phase C dynamic confirmation


def test_reachable_and_crashed_becomes_exploitable():
    reach = {"status": "reachable", "functions": ["inflate"], "present": ["inflate"]}
    vuln = _result(_cve_finding(reachability=reach), extra=[_crash_finding("lib/libz.so")])
    assert vuln["analysis"]["state"] == "exploitable"
    assert "crashed" in vuln["analysis"]["detail"] and "reproducer" in vuln["analysis"]["detail"]
    assert {"name": "firefly:dynamic", "value": "crashed"} in vuln["properties"]


def test_not_present_but_crashed_stays_in_triage_not_cleared():
    # Symbols look absent, but the hosting binary was crashed: don't clear to
    # not_affected — pull it back to in_triage.
    reach = {"status": "not_present", "functions": ["inflate"], "present": []}
    vuln = _result(_cve_finding(confidence="low", reachability=reach), extra=[_crash_finding("lib/libz.so")])
    assert vuln["analysis"]["state"] == "in_triage"
    assert "justification" not in vuln["analysis"]
    assert "dynamically crashed" in vuln["analysis"]["detail"]


def test_confident_match_crashed_becomes_in_triage():
    # No reachability data, but the hosting binary was crashed -> surfaced, not silent.
    vuln = _result(_cve_finding(confidence="high"), extra=[_crash_finding("lib/libz.so")])
    assert vuln["analysis"]["state"] == "in_triage"
    assert "dynamically crashed" in vuln["analysis"]["detail"]


def test_crash_on_a_different_binary_does_not_escalate():
    reach = {"status": "reachable", "functions": ["inflate"], "present": ["inflate"]}
    vuln = _result(_cve_finding(reachability=reach), extra=[_crash_finding("usr/sbin/httpd")])
    assert vuln["analysis"]["state"] == "in_triage"      # unchanged: crash was elsewhere
    assert not any(p["name"] == "firefly:dynamic" for p in vuln["properties"])


def test_network_and_cred_confirmations_do_not_touch_cve_vex():
    # A network-fuzz crash and a confirmed login are service-level: they must not
    # flip a CVE's VEX (only the per-binary harness crash does).
    reach = {"status": "reachable", "functions": ["inflate"], "present": ["inflate"]}
    netcrash = Finding(analyzer="fuzz", title="net crash", severity=Severity.HIGH, confidence="high",
                       path=None, metadata={"port": 80, "kind": "console:Oops"})
    cred = Finding(analyzer="accounts", title="empty password", severity=Severity.CRITICAL, confidence="high",
                   path="lib/libz.so", metadata={"confirmed_login": True})
    vuln = _result(_cve_finding(reachability=reach), extra=[netcrash, cred])
    assert vuln["analysis"]["state"] == "in_triage"      # not exploitable
    assert not any(p["name"] == "firefly:dynamic" for p in vuln["properties"])
