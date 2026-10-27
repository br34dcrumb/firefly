"""Local, offline vulnerability database built from NVD CVE records.

Scans never talk to the network: which software a firmware contains is
sensitive (it can identify an unreleased product), so CVE matching runs
against a local SQLite file. ``firefly db update`` refreshes it from the
daily NVD mirror at github.com/fkie-cad/nvd-json-data-feeds, verifying every
download against the SHA-256 digest GitHub publishes for the release asset.
Records include CISA KEV (known exploited) data.
"""

from __future__ import annotations

import hashlib
import json
import logging
import lzma
import os
import re
import sqlite3
import tempfile
import urllib.request
import zlib
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import IO, Any

log = logging.getLogger(__name__)

SCHEMA_VERSION = 3
FEED_REPO = "fkie-cad/nvd-json-data-feeds"
RELEASE_API = f"https://api.github.com/repos/{FEED_REPO}/releases/latest"
# The Modified feed covers changes from the last 8 days; refresh fully if older.
INCREMENTAL_MAX_AGE = timedelta(days=7)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS cve (
    id TEXT PRIMARY KEY,
    published TEXT,
    modified TEXT,
    status TEXT,
    severity TEXT,
    score REAL,
    cvss_version TEXT,
    vector TEXT,
    cwe TEXT,
    kev_added TEXT,
    kev_name TEXT,
    description TEXT,
    tags TEXT
);
CREATE TABLE IF NOT EXISTS match (
    cve_id TEXT NOT NULL,
    part TEXT,
    vendor TEXT NOT NULL,
    product TEXT NOT NULL,
    version TEXT,
    start_incl TEXT,
    start_excl TEXT,
    end_incl TEXT,
    end_excl TEXT,
    conditional INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS match_product ON match (product, vendor);
-- match_cve is created only when an incremental update needs it (see ensure_update_index);
-- a full build never deletes, so it would be 68 MB of dead weight.
"""

_METRIC_KEYS = (("cvssMetricV40", "4.0"), ("cvssMetricV31", "3.1"), ("cvssMetricV30", "3.0"), ("cvssMetricV2", "2.0"))


def _compress(text: str | None) -> bytes | None:
    """zlib-compress a description for storage (NVD text compresses ~3x)."""
    return zlib.compress(text.encode("utf-8"), 6) if text else None


def _decompress(blob: object) -> str:
    """Inverse of _compress; tolerates legacy uncompressed TEXT descriptions."""
    if blob is None:
        return ""
    if isinstance(blob, str):  # a pre-compression (schema < 3) database
        return blob
    if isinstance(blob, (bytes, bytearray)):
        try:
            return zlib.decompress(blob).decode("utf-8", "replace")
        except zlib.error:
            return bytes(blob).decode("utf-8", "replace")
    return str(blob)
_ARRAY_KEY = re.compile(r'"(?:cve_items|vulnerabilities|CVE_Items)"\s*:\s*\[')


def default_db_path() -> str:
    if os.environ.get("FIREFLY_DB"):
        return os.environ["FIREFLY_DB"]
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "firefly", "vulndb.sqlite")


# --------------------------------------------------------------------------- parsing


def iter_feed_records(stream: IO[str], chunk_size: int = 1 << 20) -> Iterator[dict[str, Any]]:
    """Yield CVE records from a feed without loading the whole file.

    Recent year feeds decompress to hundreds of MB; records are decoded one at
    a time from a sliding buffer. Accepts the mirror's ``cve_items`` layout and
    the NVD API's ``vulnerabilities: [{"cve": ...}]`` layout.
    """
    decoder = json.JSONDecoder()
    buf = ""
    while True:
        m = _ARRAY_KEY.search(buf)
        if m:
            buf = buf[m.end() :]
            break
        chunk = stream.read(chunk_size)
        if not chunk:
            return
        buf = buf[-64:] + chunk
    while True:
        buf = buf.lstrip(" \t\r\n,")
        if not buf:
            chunk = stream.read(chunk_size)
            if not chunk:
                return
            buf = chunk
            continue
        if buf[0] == "]":
            return
        try:
            obj, end = decoder.raw_decode(buf)
        except json.JSONDecodeError:
            chunk = stream.read(chunk_size)
            if not chunk:
                raise
            buf += chunk
            continue
        buf = buf[end:]
        yield obj.get("cve", obj) if isinstance(obj, dict) else obj


def _cpe_fields(criteria: str) -> list[str] | None:
    # cpe:2.3:part:vendor:product:version:update:... with '\'-escaped ':'
    parts = re.split(r"(?<!\\):", criteria)
    if len(parts) < 6 or parts[0] != "cpe" or parts[1] != "2.3":
        return None
    return [p.replace("\\", "").lower() for p in parts]


def _best_metric(metrics: dict[str, Any]) -> tuple[str | None, float | None, str | None, str | None]:
    for key, version in _METRIC_KEYS:
        entries = metrics.get(key) or []
        if not entries:
            continue
        entry = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        data = entry.get("cvssData", {})
        severity = data.get("baseSeverity") or entry.get("baseSeverity")
        return (severity.lower() if severity else None), data.get("baseScore"), version, data.get("vectorString")
    return None, None, None, None


@dataclass
class ParsedCve:
    row: tuple
    matches: list[tuple]


def parse_record(rec: dict[str, Any]) -> ParsedCve | None:
    cve_id = rec.get("id")
    if not cve_id or rec.get("vulnStatus") == "Rejected":
        return None
    description = next((d["value"] for d in rec.get("descriptions", []) if d.get("lang") == "en"), "")
    severity, score, cvss_version, vector = _best_metric(rec.get("metrics") or {})
    cwe = next(
        (d["value"] for w in rec.get("weaknesses", []) for d in w.get("description", []) if d.get("value", "").startswith("CWE-")),
        None,
    )
    row = (
        cve_id,
        rec.get("published"),
        rec.get("lastModified"),
        rec.get("vulnStatus"),
        severity,
        score,
        cvss_version,
        vector,
        cwe,
        rec.get("cisaExploitAdd"),
        rec.get("cisaVulnerabilityName"),
        _compress(description),
        ",".join(sorted({t for entry in rec.get("cveTags", []) for t in entry.get("tags", [])})) or None,
    )
    matches = []
    for config in rec.get("configurations", []):
        nodes = config.get("nodes", [])
        # "AND" configurations ("X running on Y") only apply in some deployments.
        conditional = int(config.get("operator") == "AND" or len(nodes) > 1)
        for node in nodes:
            if node.get("negate"):
                continue
            for cm in node.get("cpeMatch", []):
                if not cm.get("vulnerable"):
                    continue
                fields = _cpe_fields(cm.get("criteria", ""))
                if fields is None:
                    continue
                matches.append(
                    (
                        cve_id,
                        fields[2],
                        fields[3],
                        fields[4],
                        fields[5],
                        cm.get("versionStartIncluding"),
                        cm.get("versionStartExcluding"),
                        cm.get("versionEndIncluding"),
                        cm.get("versionEndExcluding"),
                        conditional,
                    )
                )
    return ParsedCve(row, matches)


# --------------------------------------------------------------------------- database


class VulnDB:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.executescript(_SCHEMA)
        columns = {row[1] for row in self.conn.execute("PRAGMA table_info(cve)")}
        if "tags" not in columns:  # schema 1 database; `db update` rebuilds it fully
            self.conn.execute("ALTER TABLE cve ADD COLUMN tags TEXT")

    @classmethod
    def open_existing(cls, path: str | None = None) -> "VulnDB | None":
        path = path or default_db_path()
        if not os.path.isfile(path):
            return None
        return cls(path)

    def close(self) -> None:
        self.conn.close()

    def __enter__(self) -> "VulnDB":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def meta(self, key: str) -> str | None:
        row = self.conn.execute("SELECT value FROM meta WHERE key = ?", (key,)).fetchone()
        return row[0] if row else None

    def set_meta(self, key: str, value: str) -> None:
        self.conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value))

    def ensure_update_index(self) -> None:
        """Create the index that makes replace/delete-by-CVE fast.

        Only incremental updates need it; a full build never deletes, so this is
        kept off the base schema to save ~68 MB on the shipped database."""
        self.conn.execute("CREATE INDEX IF NOT EXISTS match_cve ON match (cve_id)")

    def upsert(self, records: Iterable[dict[str, Any]], fresh: bool = False) -> int:
        """Insert CVE records. Returns the number stored.

        With ``fresh=True`` (a full build into an empty database) no delete runs,
        so the match_cve index is not needed. Otherwise each CVE's prior match
        rows are replaced, which needs that index — created on demand here."""
        if not fresh:
            self.ensure_update_index()
        count = 0
        batch_rows: list[tuple] = []
        batch_matches: list[tuple] = []

        def flush() -> None:
            if not fresh:
                ids = [(r[0],) for r in batch_rows]
                self.conn.executemany("DELETE FROM match WHERE cve_id = ?", ids)
            self.conn.executemany("INSERT OR REPLACE INTO cve VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?)", batch_rows)
            self.conn.executemany("INSERT INTO match VALUES (?,?,?,?,?,?,?,?,?,?)", batch_matches)
            batch_rows.clear()
            batch_matches.clear()

        with self.conn:
            for rec in records:
                parsed = parse_record(rec)
                if parsed is None:
                    if not fresh and rec.get("vulnStatus") == "Rejected" and rec.get("id"):
                        self.conn.execute("DELETE FROM match WHERE cve_id = ?", (rec["id"],))
                        self.conn.execute("DELETE FROM cve WHERE id = ?", (rec["id"],))
                    continue
                batch_rows.append(parsed.row)
                batch_matches.extend(parsed.matches)
                count += 1
                if len(batch_rows) >= 5000:
                    flush()
            if batch_rows:
                flush()
        return count

    def candidates(self, product: str, vendor: str | None = None) -> list[dict[str, Any]]:
        self.conn.row_factory = sqlite3.Row
        sql = (
            "SELECT m.*, c.severity, c.score, c.cvss_version, c.vector, c.cwe, c.kev_added, c.kev_name, "
            "c.description, c.published, c.tags FROM match m JOIN cve c ON c.id = m.cve_id WHERE m.product = ?"
        )
        args: list[str] = [product.lower()]
        if vendor:
            sql += " AND m.vendor = ?"
            args.append(vendor.lower())
        rows = self.conn.execute(sql, args).fetchall()
        self.conn.row_factory = None
        out = []
        for r in rows:
            d = dict(r)
            d["description"] = _decompress(d.get("description"))
            out.append(d)
        return out

    def info(self) -> dict[str, Any]:
        cves = self.conn.execute("SELECT COUNT(*) FROM cve").fetchone()[0]
        kev = self.conn.execute("SELECT COUNT(*) FROM cve WHERE kev_added IS NOT NULL").fetchone()[0]
        return {
            "path": self.path,
            "cves": cves,
            "known_exploited": kev,
            "release": self.meta("release"),
            "updated_at": self.meta("updated_at"),
            "schema": self.meta("schema"),
        }


def open_feed(path: str) -> IO[str]:
    if path.endswith(".xz"):
        return lzma.open(path, "rt", encoding="utf-8")
    return open(path, encoding="utf-8")


def import_files(db: VulnDB, paths: Iterable[str], fresh: bool = False) -> int:
    total = 0
    for path in paths:
        with open_feed(path) as fh:
            n = db.upsert(iter_feed_records(fh), fresh=fresh)
        log.info("imported %d records from %s", n, path)
        total += n
    db.set_meta("updated_at", _now())
    db.conn.commit()
    return total


# --------------------------------------------------------------------------- download


def _http_get(url: str, accept: str = "application/octet-stream") -> urllib.request.addinfourl:
    headers = {"User-Agent": "firefly-vulndb", "Accept": accept}
    token = os.environ.get("GITHUB_TOKEN")
    if token and url.startswith("https://api.github.com/"):
        headers["Authorization"] = f"Bearer {token}"
    return urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=120)


def latest_release() -> dict[str, Any]:
    with _http_get(RELEASE_API, "application/vnd.github+json") as resp:
        return json.load(resp)


def download_verified(url: str, digest: str | None, dest_dir: str) -> str:
    """Download to a temp file in `dest_dir`, refusing anything whose SHA-256 is wrong."""
    if not digest or not digest.startswith("sha256:"):
        raise RuntimeError(f"no SHA-256 digest published for {url}; refusing unverified download")
    expected = digest.split(":", 1)[1]
    fd, tmp = tempfile.mkstemp(dir=dest_dir, suffix=".download")
    h = hashlib.sha256()
    try:
        with os.fdopen(fd, "wb") as out, _http_get(url) as resp:
            for chunk in iter(lambda: resp.read(1 << 20), b""):
                h.update(chunk)
                out.write(chunk)
        if h.hexdigest() != expected:
            raise RuntimeError(f"checksum mismatch for {url}")
    except BaseException:
        os.remove(tmp)
        raise
    return tmp


def select_assets(release: dict[str, Any], incremental: bool) -> list[dict[str, Any]]:
    assets = [a for a in release.get("assets", []) if a["name"].endswith(".json.xz")]
    if incremental:
        # The mirror names it "CVE-modified.json.xz"; don't depend on the case.
        return [a for a in assets if a["name"].lower() == "cve-modified.json.xz"]
    return sorted((a for a in assets if re.fullmatch(r"CVE-\d{4}\.json\.xz", a["name"])), key=lambda a: a["name"])


def update(path: str | None = None, full: bool = False, progress=print) -> dict[str, Any]:
    """Bring the local database up to date with the latest mirror release."""
    path = path or default_db_path()
    os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
    release = latest_release()
    tag = release.get("tag_name", "unknown")

    incremental = False
    if not full and os.path.isfile(path):
        with VulnDB(path) as db:
            schema = db.meta("schema")
            if db.meta("release") == tag and schema == str(SCHEMA_VERSION):
                progress(f"already at {tag}")
                return db.info()
            updated = db.meta("updated_at")
        if schema == str(SCHEMA_VERSION) and updated:
            incremental = datetime.now(timezone.utc) - datetime.fromisoformat(updated) < INCREMENTAL_MAX_AGE

    assets = select_assets(release, incremental)
    if not assets:
        raise RuntimeError(f"release {tag} has no usable feed assets")

    # Full rebuilds go to a temp file swapped in at the end, so a scan never
    # sees a half-built database.
    target = path if incremental else path + ".building"
    if not incremental and os.path.exists(target):
        os.remove(target)
    db = VulnDB(target)
    try:
        for asset in assets:
            progress(f"fetching {asset['name']} ({asset['size'] / 1e6:.1f} MB)")
            tmp = download_verified(asset["browser_download_url"], asset.get("digest"), os.path.dirname(os.path.abspath(path)))
            try:
                with lzma.open(tmp, "rt", encoding="utf-8") as fh:
                    n = db.upsert(iter_feed_records(fh), fresh=not incremental)
            finally:
                os.remove(tmp)
            progress(f"  {n} records")
        db.set_meta("schema", str(SCHEMA_VERSION))
        db.set_meta("source", f"https://github.com/{FEED_REPO}")
        db.set_meta("release", tag)
        db.set_meta("updated_at", _now())
        db.conn.commit()
        if not incremental:
            # Defragment and reclaim free pages from the fresh build.
            progress("compacting database")
            db.conn.execute("VACUUM")
        info = db.info()
    finally:
        db.close()
    if not incremental:
        os.replace(target, path)
        info["path"] = path
    return info


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
