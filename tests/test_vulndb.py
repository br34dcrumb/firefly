import hashlib
import io
import json

import pytest

from firefly import vulndb
from firefly.vulndb import SCHEMA_VERSION, VulnDB, download_verified, import_files, iter_feed_records

from nvdfeed import SAMPLE_RECORDS, cve, match, write_feed


@pytest.mark.parametrize("layout", ["mirror", "api"])
def test_streaming_parser_handles_tiny_chunks(tmp_path, layout):
    path = write_feed(tmp_path / "feed.json", SAMPLE_RECORDS, layout)
    with open(path, encoding="utf-8") as fh:
        records = list(iter_feed_records(fh, chunk_size=7))  # force records across chunk boundaries
    assert [r["id"] for r in records] == [r["id"] for r in SAMPLE_RECORDS]


def test_import_and_query(tmp_path):
    feed = write_feed(tmp_path / "CVE-2021.json.xz", SAMPLE_RECORDS)
    with VulnDB(str(tmp_path / "db.sqlite")) as db:
        assert import_files(db, [str(feed)]) == 5  # rejected record skipped
        info = db.info()
        assert info["cves"] == 5 and info["known_exploited"] == 1
        # import records the current schema, so a later scan doesn't warn to rebuild
        assert info["schema"] == str(SCHEMA_VERSION)
        rows = db.candidates("openssl", "openssl")
        assert {r["cve_id"] for r in rows} == {"CVE-2021-3711", "CVE-2014-0160"}
        heartbleed = next(r for r in rows if r["cve_id"] == "CVE-2014-0160")
        assert (heartbleed["start_incl"], heartbleed["end_excl"]) == ("1.0.1", "1.0.1g")
        dropbear = db.candidates("dropbear_ssh")[0]
        assert dropbear["conditional"] == 1


def test_upsert_replaces_and_rejection_deletes(tmp_path):
    with VulnDB(str(tmp_path / "db.sqlite")) as db:
        db.upsert(SAMPLE_RECORDS)
        # NVD narrows the range and later rejects the CVE
        db.upsert([cve("CVE-2021-3711", [match("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", versionEndExcluding="1.1.1j")])])
        rows = [r for r in db.candidates("openssl") if r["cve_id"] == "CVE-2021-3711"]
        assert len(rows) == 1 and rows[0]["end_excl"] == "1.1.1j"
        db.upsert([cve("CVE-2021-3711", [], status="Rejected")])
        assert not [r for r in db.candidates("openssl") if r["cve_id"] == "CVE-2021-3711"]


class _FakeResponse(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *exc):
        return False


def test_download_rejects_bad_checksum(tmp_path, monkeypatch):
    tmp_path = tmp_path / "dl"
    tmp_path.mkdir()
    monkeypatch.setattr(vulndb, "_http_get", lambda url, accept=None: _FakeResponse(b"tampered"))
    with pytest.raises(RuntimeError, match="checksum mismatch"):
        download_verified("https://example/feed.xz", "sha256:" + "0" * 64, str(tmp_path))
    with pytest.raises(RuntimeError, match="unverified"):
        download_verified("https://example/feed.xz", None, str(tmp_path))
    assert list(tmp_path.iterdir()) == []  # nothing left behind


def _fake_release(tmp_path, monkeypatch, tag, files):
    blobs = {}
    assets = []
    for name, records in files.items():
        path = write_feed(tmp_path / name, records)
        data = path.read_bytes()
        url = f"https://example/{tag}/{name}"
        blobs[url] = data
        assets.append({"name": name, "size": len(data), "browser_download_url": url, "digest": "sha256:" + hashlib.sha256(data).hexdigest()})
    monkeypatch.setattr(vulndb, "latest_release", lambda: {"tag_name": tag, "assets": assets})
    monkeypatch.setattr(vulndb, "_http_get", lambda url, accept=None: _FakeResponse(blobs[url]))


def test_update_full_then_incremental(tmp_path, monkeypatch):
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    db_path = str(tmp_path / "db" / "vulndb.sqlite")
    _fake_release(feeds, monkeypatch, "v1", {"CVE-2014.json.xz": SAMPLE_RECORDS[1:2], "CVE-2021.json.xz": SAMPLE_RECORDS[:1], "CVE-modified.json.xz": []})
    info = vulndb.update(db_path, progress=lambda *_: None)
    assert info["cves"] == 2 and info["release"] == "v1"

    fetched = []
    new = cve("CVE-2099-0001", [match("cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*")], kev="2099-01-01")
    _fake_release(feeds, monkeypatch, "v2", {"CVE-2014.json.xz": [], "CVE-modified.json.xz": [new]})
    info = vulndb.update(db_path, progress=fetched.append)
    assert fetched[0].startswith("fetching CVE-modified")  # only the delta was downloaded
    assert info["cves"] == 3 and info["known_exploited"] == 1 and info["release"] == "v2"

    assert vulndb.update(db_path, progress=fetched.append)["release"] == "v2"
    assert fetched[-1] == "already at v2"


def test_schema_change_forces_full_rebuild(tmp_path, monkeypatch):
    feeds = tmp_path / "feeds"
    feeds.mkdir()
    db_path = str(tmp_path / "vulndb.sqlite")
    _fake_release(feeds, monkeypatch, "v1", {"CVE-2021.json.xz": SAMPLE_RECORDS[:1], "CVE-modified.json.xz": []})
    vulndb.update(db_path, progress=lambda *_: None)
    with VulnDB(db_path) as db:
        db.set_meta("schema", "1")
        db.conn.commit()
    fetched = []
    vulndb.update(db_path, progress=fetched.append)  # same release, old schema
    assert fetched[0].startswith("fetching CVE-2021")
