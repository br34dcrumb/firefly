"""Tests for attack-chain correlation (firefly/chains.py).

Pure functions over a report dict — no scan, no network, no qemu. Findings are
built as the plain dicts the report serialises to.
"""

from __future__ import annotations

from firefly import chains
from firefly.chains import _stage, correlate


def _f(analyzer, title, severity="high", confidence="high", path=None, metadata=None, fid=None):
    return {
        "analyzer": analyzer,
        "title": title,
        "severity": severity,
        "confidence": confidence,
        "path": path,
        "metadata": metadata or {},
        "id": fid or f"FF-{analyzer}-{title[:6]}",
    }


def _report(findings):
    return {"findings": findings}


# --------------------------------------------------------------------------- stage classification


def test_stage_classification():
    assert _stage(_f("services", "Insecure service telnet")) == "entry"
    assert _stage(_f("accounts", "empty password", metadata={"account": "root"})) == "access"
    assert _stage(_f("credentials", "hardcoded key")) == "access"
    assert _stage(_f("cves", "CVE-2021-1", metadata={"cve": "CVE-2021-1"})) == "exploit"
    assert _stage(_f("harness", "crashed", metadata={"confirmed_fuzz_crash": True})) == "impact"
    assert _stage(_f("fuzz", "net crash", metadata={"port": 80})) == "impact"
    assert _stage(_f("hardening", "no NX")) is None          # does not chain
    assert _stage(_f("entropy", "high entropy")) is None


def test_dangerfns_only_chains_when_input_reaches_sink():
    assert _stage(_f("dangerfns", "system in x", path="bin/x")) is None
    reached = _f("dangerfns", "system in x", path="bin/x", metadata={"taint": {"input_reaches_sink": True, "sinks": ["system"]}})
    assert _stage(reached) == "exploit"


# --------------------------------------------------------------------------- chain assembly


def _full_chain_findings():
    return [
        _f("services", "Insecure service: telnet", severity="high"),
        _f("accounts", "Account root has an empty password", severity="critical",
           metadata={"account": "root", "confirmed_login": True}, fid="FF-acct-root"),
        _f("cves", "CVE-2015-1234", severity="high", path="bin/busybox",
           metadata={"cve": "CVE-2015-1234", "reachability": {"status": "reachable"}}, fid="FF-cve-bb"),
        _f("harness", "crashed on fuzzed input", severity="critical", path="bin/busybox",
           metadata={"confirmed_fuzz_crash": True, "signal": "SIGSEGV"}, fid="FF-harn-bb"),
    ]


def test_full_chain_entry_to_impact():
    res = correlate(_report(_full_chain_findings()))
    assert res["count"] == 1
    c = res["chains"][0]
    assert [s["stage"] for s in c["steps"]] == ["entry", "access", "exploit", "impact"]
    assert c["confirmed"] is True and c["severity"] == "critical"
    assert "→" in c["summary"] and "busybox" in c["summary"]
    # Only the one binary appears; device steps carry no path.
    assert {s["path"] for s in c["steps"] if s["path"]} == {"bin/busybox"}


def test_device_only_chain_from_service_and_creds():
    res = correlate(_report([
        _f("services", "Insecure service: telnet"),
        _f("accounts", "Account admin empty password", metadata={"account": "admin"}, fid="FF-acct-admin"),
    ]))
    assert res["count"] == 1
    assert [s["stage"] for s in res["chains"][0]["steps"]] == ["entry", "access"]


def test_lone_entry_is_not_a_chain():
    assert correlate(_report([_f("services", "Insecure service: telnet")]))["count"] == 0


def test_subset_chain_is_pruned():
    # telnet + creds is a subset of the full busybox chain -> only the full chain remains.
    res = correlate(_report(_full_chain_findings()))
    assert res["count"] == 1
    assert len(res["chains"][0]["steps"]) == 4


def test_separate_binaries_make_separate_chains():
    findings = [
        _f("services", "Insecure service: telnet"),
        _f("accounts", "root empty password", severity="critical", metadata={"account": "root"}, fid="FF-acct"),
        _f("cves", "CVE-A", path="bin/a", metadata={"cve": "CVE-A", "reachability": {"status": "reachable"}}, fid="FF-a"),
        _f("cves", "CVE-B", path="bin/b", metadata={"cve": "CVE-B", "reachability": {"status": "reachable"}}, fid="FF-b"),
    ]
    res = correlate(_report(findings))
    assert res["count"] == 2
    paths = [sorted({s["path"] for s in c["steps"] if s["path"]}) for c in res["chains"]]
    assert ["bin/a"] in paths and ["bin/b"] in paths   # never mixed into one chain


def test_confirmed_chain_outranks_unconfirmed():
    confirmed = _full_chain_findings()
    # A second, unconfirmed binary with a weaker CVE.
    unconfirmed = [
        _f("cves", "CVE-weak", severity="medium", confidence="medium", path="bin/weak",
           metadata={"cve": "CVE-weak"}, fid="FF-weak"),
    ]
    res = correlate(_report(confirmed + unconfirmed))
    assert res["chains"][0]["confirmed"] is True            # confirmed chain ranks first
    assert res["chains"][0]["score"] > res["chains"][-1]["score"]


# --------------------------------------------------------------------------- filtering / limits / shape


def test_min_confidence_filters_findings():
    findings = [
        _f("services", "Insecure service: telnet"),
        _f("accounts", "maybe weak", confidence="low", metadata={"account": "x"}, fid="FF-low"),
    ]
    assert correlate(_report(findings), min_confidence="medium")["count"] == 0   # access step filtered out
    assert correlate(_report(findings), min_confidence="low")["count"] == 1


def test_max_chains_caps_output():
    findings = [_f("services", "Insecure service: telnet"), _f("accounts", "root empty", metadata={"account": "root"}, fid="FF-acct")]
    for i in range(5):
        findings.append(_f("cves", f"CVE-{i}", path=f"bin/{i}", metadata={"cve": f"CVE-{i}", "reachability": {"status": "reachable"}}, fid=f"FF-{i}"))
    res = correlate(_report(findings), max_chains=3)
    assert res["count"] == 3


def test_result_shape_and_disclaimer():
    res = correlate(_report(_full_chain_findings()))
    assert set(res) == {"chains", "count", "confirmed", "disclaimer"}
    assert res["confirmed"] == 1 and "heuristic" in res["disclaimer"].lower()
    c = res["chains"][0]
    assert c["id"].startswith("CHAIN-") and isinstance(c["score"], float)


def test_print_chains_smoke(capsys):
    chains.print_chains(correlate(_report(_full_chain_findings())))
    chains.print_chains({"chains": [], "count": 0, "confirmed": 0, "disclaimer": "none"})
    out = capsys.readouterr().out
    assert "Attack chains" in out and "No attack chains" in out
