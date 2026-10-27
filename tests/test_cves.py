import json

import pytest

from firefly import sbom
from firefly.components import merge, suppress_multicall
from firefly.models import Component, Severity
from firefly.pipeline import ScanOptions, scan
from firefly.vulndb import VulnDB, import_files

from nvdfeed import SAMPLE_RECORDS, write_feed


@pytest.fixture
def db_path(tmp_path):
    path = str(tmp_path / "vulndb.sqlite")
    with VulnDB(path) as db:
        import_files(db, [str(write_feed(tmp_path / "feed.json", SAMPLE_RECORDS))])
    return path


def test_merge_aliases():
    merged = merge(
        [
            Component("glibc", "2.30", paths=["lib/libc.so.6"]),
            Component("glibc", "2.30", vendor="gnu", paths=["lib/libc.so.6"]),
            Component("sqlite3", "3.42.0", paths=["usr/lib/libsqlite3.so"]),
            Component("sqlite", "3.42.0", paths=["usr/lib/libsqlite3.so.0"]),
        ]
    )
    assert [(c.vendor, c.product, c.version, len(c.paths)) for c in merged] == [
        ("gnu", "glibc", "2.30", 1),
        ("sqlite", "sqlite", "3.42.0", 2),
    ]


def test_multicall_applets_are_suppressed():
    kept, suppressed = suppress_multicall(
        [
            Component("busybox", "1.24.1", vendor="busybox", paths=["bin/busybox", "bin/ash"]),
            Component("sed", "4.0", vendor="gnu", paths=["bin/busybox", "bin/ash"]),
            Component("wget", "1.21", vendor="gnu", paths=["bin/busybox", "usr/bin/wget"]),
        ]
    )
    assert [c.product for c in kept] == ["busybox", "wget"]
    assert kept[1].paths == ["usr/bin/wget"]
    assert [c.product for c in suppressed] == ["sed"]


def test_scan_reports_cves(rootfs_tar, tmp_path, db_path):
    result = scan(str(rootfs_tar), ScanOptions(output_dir=str(tmp_path / "out"), jobs=1, db_path=db_path))
    cves = {f.metadata["cve"]: f for f in result.findings if f.analyzer == "cves"}
    # openssl 1.1.1k is in [1.1.1, 1.1.1l) but not in Heartbleed's range;
    # "all versions" and rejected entries never match
    assert set(cves) == {"CVE-2021-3711", "CVE-2099-0001", "CVE-2099-0002"}
    assert cves["CVE-2021-3711"].severity is Severity.CRITICAL
    assert cves["CVE-2021-3711"].confidence == "high"
    assert cves["CVE-2099-0001"].metadata["kev"] and "known exploited" in cves["CVE-2099-0001"].title
    assert cves["CVE-2099-0002"].confidence == "medium"  # "running on" configuration
    # most severe first
    assert result.findings[0].metadata.get("cve") == "CVE-2021-3711"


def test_scan_without_database_warns(rootfs_tar, tmp_path):
    result = scan(str(rootfs_tar), ScanOptions(output_dir=str(tmp_path / "out"), jobs=1, db_path=str(tmp_path / "missing.sqlite")))
    assert any("firefly db update" in w for w in result.warnings)
    assert result.errors == []


def test_cyclonedx_sbom(rootfs_tar, tmp_path, db_path):
    result = scan(str(rootfs_tar), ScanOptions(output_dir=str(tmp_path / "out"), jobs=1, db_path=db_path))
    bom = json.loads(open(sbom.write(result), encoding="utf-8").read())
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.6"
    assert bom["metadata"]["component"]["hashes"][0]["content"] == result.input_sha256
    refs = {c["bom-ref"]: c for c in bom["components"]}
    openssl = next(c for c in bom["components"] if c["name"] == "openssl")
    assert openssl["cpe"] == "cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*"
    assert openssl["type"] == "library"
    vuln = next(v for v in bom["vulnerabilities"] if v["id"] == "CVE-2021-3711")
    assert refs[vuln["affects"][0]["ref"]]["name"] == "openssl"
    assert vuln["ratings"][0]["method"] == "CVSSv31" and vuln["ratings"][0]["severity"] == "critical"
    assert vuln["cwes"] == [120]
