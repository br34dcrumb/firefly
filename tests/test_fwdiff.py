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


def _report(components=(), findings=(), path="fw.bin", files=None):
    rep = {"input": {"path": path, "sha256": "abc", "size": 1},
           "components": list(components), "findings": list(findings)}
    if files is not None:
        rep["files"] = list(files)
    return rep


def _file(path, sha256=None, kind="data", size=1, link_target=None):
    e = {"path": path, "kind": kind, "size": size, "sha256": sha256}
    if link_target is not None:
        e["link_target"] = link_target
    return e


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


# --------------------------------------------------------------------------- files


def test_file_diff_added_removed_changed():
    old = _report(files=[
        _file("bin/busybox", "h1"),
        _file("etc/passwd", "p1"),
        _file("lib/old.so", "o1"),
    ])
    new = _report(files=[
        _file("bin/busybox", "h2"),   # content changed
        _file("etc/passwd", "p1"),    # unchanged
        _file("bin/new", "n1"),       # added
    ])
    d = diff_reports(old, new)
    assert d.files is not None
    assert [f["path"] for f in d.files.added] == ["bin/new"]
    assert [f["path"] for f in d.files.removed] == ["lib/old.so"]
    assert [f["path"] for f in d.files.changed] == ["bin/busybox"]
    assert d.files.changed[0]["old"] == "h1" and d.files.changed[0]["new"] == "h2"
    assert d.summary()["files_changed"] == 1


def test_file_diff_symlink_retarget_and_kind_change():
    old = _report(files=[
        _file("sbin/init", kind="symlink", link_target="/bin/busybox"),
        _file("a", "x1"),
    ])
    new = _report(files=[
        _file("sbin/init", kind="symlink", link_target="/sbin/myinit"),  # retargeted
        _file("a", kind="symlink", link_target="b"),                     # file -> symlink
    ])
    changed = {f["path"] for f in diff_reports(old, new).files.changed}
    assert changed == {"sbin/init", "a"}


def test_file_diff_unknown_hash_not_flagged():
    # A file with no sha256 on either side (e.g. a device node) and the same
    # size must not be reported as changed just because content is unknowable.
    old = _report(files=[_file("dev/null", None, kind="other", size=0)])
    new = _report(files=[_file("dev/null", None, kind="other", size=0)])
    assert diff_reports(old, new).files.changed == []


def test_file_diff_size_fallback_for_unhashable():
    # Two same-kind files that can't be hashed (e.g. over HASH_LIMIT) but whose
    # sizes differ are a provable change and must be flagged.
    old = _report(files=[_file("big.bin", None, size=600_000_000)])
    new = _report(files=[_file("big.bin", None, size=800_000_000)])
    changed = diff_reports(old, new).files.changed
    assert [f["path"] for f in changed] == ["big.bin"]
    assert changed[0]["old_size"] == 600_000_000 and changed[0]["new_size"] == 800_000_000


def test_file_diff_unavailable_when_inventory_missing():
    # Old-schema report (no "files" key) -> file diff degrades to None.
    old = _report(components=[_comp("zlib", "1.0")])            # no files key
    new = _report(components=[_comp("zlib", "1.0")], files=[_file("a", "x")])
    d = diff_reports(old, new)
    assert d.files is None
    assert d.to_dict()["files"] is None
    assert "files_changed" not in d.summary()


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
