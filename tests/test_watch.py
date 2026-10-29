"""Tests for watch mode (firefly watch): new CVEs for a stored report."""

from __future__ import annotations

import json

from firefly import watch
from firefly.cli import main
from firefly.vulndb import VulnDB, import_files

from nvdfeed import cve, match, write_feed


def _db(tmp_path, kev=None):
    path = str(tmp_path / "vulndb.sqlite")
    feed = [
        cve(
            "CVE-2022-37434",
            [match("cpe:2.3:a:zlib:zlib:*:*:*:*:*:*:*:*", versionStartIncluding="1.2.0", versionEndExcluding="1.2.12")],
            severity="CRITICAL",
            score=9.8,
            kev=kev,
        )
    ]
    with VulnDB(path) as db:
        import_files(db, [str(write_feed(tmp_path / "feed.json", feed))])
    return path


def _report(findings=()):
    return {
        "input": {"path": "/fw/router.bin", "sha256": "abc"},
        "components": [{"vendor": "zlib", "product": "zlib", "version": "1.2.11", "paths": ["lib/libz.so"]}],
        "findings": list(findings),
    }


def _cve_finding(cve_id):
    return {"analyzer": "cves", "metadata": {"cve": cve_id, "component": {"vendor": "zlib", "product": "zlib", "version": "1.2.11"}}}


def test_reports_cve_absent_from_the_report(tmp_path):
    with VulnDB.open_existing(_db(tmp_path)) as db:
        new = watch.new_cves(_report(), db)
    assert [r["cve"] for r in new] == ["CVE-2022-37434"]
    assert new[0]["score"] == 9.8 and new[0]["kev"] is False


def test_cve_already_in_report_is_not_new(tmp_path):
    report = _report(findings=[_cve_finding("CVE-2022-37434")])
    with VulnDB.open_existing(_db(tmp_path)) as db:
        assert watch.new_cves(report, db) == []


def test_since_filters_out_older_cves(tmp_path):
    # the synthetic CVE is published 2021-08-24; a 2099 cutoff hides it
    with VulnDB.open_existing(_db(tmp_path)) as db:
        assert watch.new_cves(_report(), db, since="2099-01-01") == []
        assert [r["cve"] for r in watch.new_cves(_report(), db, since="2021-01-01")] == ["CVE-2022-37434"]


def test_since_includes_newly_kev_listed(tmp_path):
    # published in 2021 but KEV-listed in 2099 -> a 2099 watch still surfaces it
    with VulnDB.open_existing(_db(tmp_path, kev="2099-06-01")) as db:
        new = watch.new_cves(_report(), db, since="2099-01-01")
    assert [r["cve"] for r in new] == ["CVE-2022-37434"] and new[0]["kev"] is True


def test_cli_fail_on_new_exit_code(tmp_path, capsys):
    report_path = tmp_path / "firefly.json"
    report_path.write_text(json.dumps(_report()), encoding="utf-8")
    db_path = _db(tmp_path)
    assert main(["watch", str(report_path), "--db", db_path, "--fail-on-new"]) == 1
    # once the CVE is recorded in the report, nothing is new -> exit 0
    report_path.write_text(json.dumps(_report(findings=[_cve_finding("CVE-2022-37434")])), encoding="utf-8")
    assert main(["watch", str(report_path), "--db", db_path, "--fail-on-new"]) == 0


def test_cli_json_output(tmp_path, capsys):
    report_path = tmp_path / "firefly.json"
    report_path.write_text(json.dumps(_report()), encoding="utf-8")
    rc = main(["watch", str(report_path), "--db", _db(tmp_path), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert out[0]["cve"] == "CVE-2022-37434"


def test_cli_missing_db(tmp_path):
    report_path = tmp_path / "firefly.json"
    report_path.write_text(json.dumps(_report()), encoding="utf-8")
    assert main(["watch", str(report_path), "--db", str(tmp_path / "nope.sqlite")]) == 1
