"""Tests for firmware diffing (firefly diff)."""

from __future__ import annotations

import json

import pytest

from firefly.fwdiff import DiffError, diff_reports, load_report


def _comp(product, version, vendor=None, paths=None):
    return {"product": product, "version": version, "vendor": vendor, "paths": paths or [f"bin/{product}"]}


def _finding(fid, severity, *, confidence="medium", title="t", path=None,
             cve=None, product=None, version=None, vendor=None, kev=False, score=None):
    md: dict = {}
    if cve:
        md = {"cve": cve, "kev": kev, "cvss_score": score,
              "component": {"vendor": vendor, "product": product, "version": version}}
    return {"id": fid, "analyzer": "cves" if cve else "x", "title": title,
            "severity": severity, "confidence": confidence, "path": path, "metadata": md}


def _report(components=(), findings=(), path="fw.bin"):
    return {"input": {"path": path, "sha256": "abc", "size": 1},
            "components": list(components), "findings": list(findings)}


# --------------------------------------------------------------------------- components


def test_component_added_removed_and_upgraded():
    old = _report([_comp("zlib", "1.2.11", "zlib"), _comp("busybox", "1.30")])
    new = _report([_comp("zlib", "1.2.13", "zlib"), _comp("openssl", "3.0.0", "openssl")])
    d = diff_reports(old, new)

    assert [c["product"] for c in d.components.added] == ["openssl"]
    assert [c["product"] for c in d.components.removed] == ["busybox"]
    assert len(d.components.changed) == 1
    chg = d.components.changed[0]
    assert (chg.product, chg.old_version, chg.new_version, chg.direction) == ("zlib", "1.2.11", "1.2.13", "upgrade")


def test_component_downgrade_is_flagged():
    old = _report([_comp("openssl", "3.0.8", "openssl")])
    new = _report([_comp("openssl", "3.0.2", "openssl")])
    d = diff_reports(old, new)
    assert d.components.changed[0].direction == "downgrade"


def test_unchanged_component_not_reported():
    rep = _report([_comp("zlib", "1.2.13", "zlib")])
    d = diff_reports(rep, _report([_comp("zlib", "1.2.13", "zlib")]))
    assert d.components.added == d.components.removed == d.components.changed == []


# --------------------------------------------------------------------------- findings


def test_findings_new_fixed_persisting():
    old = _report(findings=[_finding("a", "high"), _finding("b", "medium")])
    new = _report(findings=[_finding("b", "medium"), _finding("c", "critical")])
    d = diff_reports(old, new)

    assert [f["id"] for f in d.findings.new] == ["c"]
    assert [f["id"] for f in d.findings.fixed] == ["a"]
    assert d.findings.persisting == 1
    assert d.findings.new_by_severity == {"critical": 1}
    assert d.findings.fixed_by_severity == {"high": 1}


def test_min_confidence_filters_findings():
    old = _report()
    new = _report(findings=[_finding("lowc", "high", confidence="low")])
    assert diff_reports(old, new, min_confidence="medium").findings.new == []
    assert [f["id"] for f in diff_reports(old, new, min_confidence="low").findings.new] == ["lowc"]


# --------------------------------------------------------------------------- CVEs


def test_cve_delta_new_fixed_still_present():
    old = _report(findings=[
        _finding("o1", "high", cve="CVE-1", product="zlib", vendor="zlib", version="1.2.11", score=7.5),
        _finding("o2", "critical", cve="CVE-2", product="busybox", version="1.30", score=9.8, kev=True),
    ])
    new = _report(findings=[
        # zlib bumped to 1.2.13 but CVE-1 still applies -> still present (version-independent key)
        _finding("n1", "high", cve="CVE-1", product="zlib", vendor="zlib", version="1.2.13", score=7.5),
        _finding("n3", "medium", cve="CVE-3", product="openssl", vendor="openssl", version="3.0.0", score=5.3),
    ])
    d = diff_reports(old, new)

    assert [c["cve"] for c in d.cves.new] == ["CVE-3"]
    assert [c["cve"] for c in d.cves.fixed] == ["CVE-2"]
    assert [c["cve"] for c in d.cves.still_present] == ["CVE-1"]
    assert d.summary()["new_kev"] == 0  # the KEV one was fixed
    assert d.has_regression is True  # CVE-3 is newly introduced


def test_no_regression_when_new_build_only_fixes():
    old = _report(findings=[_finding("o1", "high", cve="CVE-1", product="zlib", version="1.0", score=7.5)])
    new = _report()
    d = diff_reports(old, new)
    assert d.cves.fixed and not d.cves.new
    assert d.has_regression is False


# --------------------------------------------------------------------------- loading & serialization


def test_load_report_variants(tmp_path):
    rep = _report([_comp("zlib", "1.0")])
    f = tmp_path / "firefly.json"
    f.write_text(json.dumps(rep))
    assert load_report(str(f))["components"][0]["product"] == "zlib"
    assert load_report(str(tmp_path))["components"][0]["product"] == "zlib"  # directory holding it

    with pytest.raises(DiffError):
        load_report(str(tmp_path / "nope.json"))
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"not": "a report"}))
    with pytest.raises(DiffError):
        load_report(str(bad))


def test_to_dict_is_json_serializable():
    old = _report([_comp("zlib", "1.2.11", "zlib")],
                  [_finding("a", "high", cve="CVE-1", product="zlib", version="1.2.11", score=7.5)])
    new = _report([_comp("zlib", "1.2.13", "zlib")])
    out = json.dumps(diff_reports(old, new).to_dict())  # must not raise
    assert "CVE-1" in out and "upgrade" in out
