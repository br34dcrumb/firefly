"""Offline function-fingerprint signature database.

Built from reference library builds: for each reference binary we store the
fingerprint of every defined function, tagged with its product/version/arch.
Scanning then counts how many of a firmware binary's function fingerprints
appear in the DB for a given product/version/arch; a strong overlap identifies
the library even with no version string.

Offline and self-contained, in the spirit of the vuln DB: no network, a plain
SQLite file, and a `build` step that ingests local reference binaries described
by a JSON manifest.
"""

from __future__ import annotations

import json
import os
import sqlite3
from dataclasses import dataclass

from firefly import disasm
from firefly.fingerprint import extract_functions_file
from firefly.inventory import ELF_MACHINES

SCHEMA_VERSION = 2  # v2 adds the norm_signatures table (radare2-normalized fingerprints)

# Normalized signatures live in their own table so the exact-match path — the
# signatures table, its NOT NULL hash, and all its counting — is untouched: a v1
# database keeps working for exact matching and simply has no normalized data
# until it is rebuilt.
_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS signatures (
    hash TEXT NOT NULL,
    arch TEXT NOT NULL,
    vendor TEXT,
    product TEXT NOT NULL,
    version TEXT NOT NULL,
    function TEXT
);
CREATE INDEX IF NOT EXISTS idx_sig_hash ON signatures (hash, arch);
CREATE TABLE IF NOT EXISTS norm_signatures (
    norm_hash TEXT NOT NULL,
    arch TEXT NOT NULL,
    vendor TEXT,
    product TEXT NOT NULL,
    version TEXT NOT NULL,
    function TEXT
);
CREATE INDEX IF NOT EXISTS idx_norm_hash ON norm_signatures (norm_hash, arch);
"""


def default_fpdb_path() -> str:
    if os.environ.get("FIREFLY_FPDB"):
        return os.environ["FIREFLY_FPDB"]
    base = os.environ.get("XDG_CACHE_HOME") or os.path.join(os.path.expanduser("~"), ".cache")
    return os.path.join(base, "firefly", "fpdb.sqlite")


@dataclass
class Identification:
    vendor: str | None
    product: str
    version: str
    arch: str
    matched: int  # distinct function hashes of the scanned binary found in the DB
    reference_total: int  # functions the reference build of this version has
    # Separate, weaker signal: operand-normalized matches (radare2). Kept apart
    # from the exact ratio so permissive normalized matches never inflate it.
    normalized_matched: int = 0
    normalized_total: int = 0

    @property
    def ratio(self) -> float:
        return self.matched / self.reference_total if self.reference_total else 0.0

    @property
    def normalized_ratio(self) -> float:
        return self.normalized_matched / self.normalized_total if self.normalized_total else 0.0


def arch_name(machine: str | int) -> str:
    # Reuse inventory's canonical e_machine -> short-name map so the names we
    # store for reference binaries match the names inventory assigns to scanned
    # binaries; a private copy would silently mismatch on any ISA they disagree
    # on (e.g. ppc64, xtensa), producing zero fingerprint matches.
    if isinstance(machine, int):
        return ELF_MACHINES.get(machine, f"0x{machine:x}")
    return machine  # inventory already stores the short name


class FpDB:
    def __init__(self, path: str):
        self.path = path
        self.conn = sqlite3.connect(path)
        self.conn.row_factory = sqlite3.Row
        self.conn.executescript(_SCHEMA)
        # Per-arch reference totals are identical for every binary in a scan;
        # compute each once and reuse. Invalidated whenever signatures change.
        self._totals_cache: dict[str, dict[tuple[str | None, str, str], int]] = {}
        self._norm_totals_cache: dict[str, dict[tuple[str | None, str, str], int]] = {}

    @classmethod
    def open_existing(cls, path: str | None) -> "FpDB | None":
        path = path or default_fpdb_path()
        if not os.path.isfile(path):
            return None
        return cls(path)

    def __enter__(self) -> "FpDB":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    def close(self) -> None:
        self.conn.close()

    def add(self, *, hashes: list[str], arch: str, vendor: str | None, product: str, version: str, functions: list[str] | None = None) -> None:
        functions = functions or [None] * len(hashes)  # type: ignore[list-item]
        self.conn.executemany(
            "INSERT INTO signatures (hash, arch, vendor, product, version, function) VALUES (?, ?, ?, ?, ?, ?)",
            [(h, arch, vendor, product, version, fn) for h, fn in zip(hashes, functions)],
        )
        self.conn.commit()
        self._totals_cache.clear()  # signatures changed; stale totals must not be reused

    def add_normalized(self, *, norm_hashes: list[str], arch: str, vendor: str | None, product: str, version: str, functions: list[str] | None = None) -> None:
        """Store operand-normalized function signatures (radare2) for a build."""
        functions = functions or [None] * len(norm_hashes)  # type: ignore[list-item]
        self.conn.executemany(
            "INSERT INTO norm_signatures (norm_hash, arch, vendor, product, version, function) VALUES (?, ?, ?, ?, ?, ?)",
            [(h, arch, vendor, product, version, fn) for h, fn in zip(norm_hashes, functions)],
        )
        self.conn.commit()
        self._norm_totals_cache.clear()

    def info(self) -> dict[str, str]:
        cur = self.conn.cursor()
        sigs = cur.execute("SELECT COUNT(*) FROM signatures").fetchone()[0]
        norm = cur.execute("SELECT COUNT(*) FROM norm_signatures").fetchone()[0]
        prods = cur.execute("SELECT COUNT(DISTINCT product || version || arch) FROM signatures").fetchone()[0]
        meta = dict(cur.execute("SELECT key, value FROM meta").fetchall())
        return {"schema": str(SCHEMA_VERSION), "signatures": str(sigs), "normalized": str(norm), "builds": str(prods), **meta}

    def identify(self, func_hashes: set[str], arch: str, norm_hashes: set[str] | None = None, min_matched: int = 6, min_ratio: float = 0.1) -> list[Identification]:
        """Identify which reference builds this binary's functions overlap with.

        With ``norm_hashes`` (radare2-normalized signatures of the scanned
        binary) it also matches against the normalized table, reported as a
        separate signal. A build is returned when *either* the exact or the
        normalized match clears the thresholds. Passing ``norm_hashes=None`` (the
        default) leaves the exact-match result byte-for-byte unchanged.
        """
        if not func_hashes and not norm_hashes:
            return []
        cur = self.conn.cursor()
        exact = self._count_matches(cur, "signatures", "hash", "_q", func_hashes or set(), arch)
        norm = self._count_matches(cur, "norm_signatures", "norm_hash", "_qn", norm_hashes or set(), arch)
        exact_totals = self._totals_for_arch(arch)
        norm_totals = self._norm_totals_for_arch(arch) if norm_hashes else {}

        results = []
        for key in exact.keys() | norm.keys():
            vendor, product, version = key
            ident = Identification(
                vendor, product, version, arch,
                matched=exact.get(key, 0), reference_total=exact_totals.get(key, 0),
                normalized_matched=norm.get(key, 0), normalized_total=norm_totals.get(key, 0),
            )
            exact_hit = ident.matched >= min_matched and ident.ratio >= min_ratio
            norm_hit = ident.normalized_matched >= min_matched and ident.normalized_ratio >= min_ratio
            if exact_hit or norm_hit:
                results.append(ident)
        results.sort(key=lambda i: (-max(i.matched, i.normalized_matched), -max(i.ratio, i.normalized_ratio)))
        return results

    @staticmethod
    def _count_matches(cur, table: str, column: str, tmp: str, hashes: set[str], arch: str) -> dict[tuple[str | None, str, str], int]:
        if not hashes:
            return {}
        cur.execute(f"CREATE TEMP TABLE IF NOT EXISTS {tmp} (h TEXT PRIMARY KEY)")
        cur.execute(f"DELETE FROM {tmp}")
        cur.executemany(f"INSERT OR IGNORE INTO {tmp} (h) VALUES (?)", [(h,) for h in hashes])
        rows = cur.execute(
            f"SELECT vendor, product, version, COUNT(DISTINCT s.{column}) AS m "
            f"FROM {table} s JOIN {tmp} ON s.{column} = {tmp}.h WHERE s.arch = ? "
            f"GROUP BY vendor, product, version",
            (arch,),
        ).fetchall()
        return {(r["vendor"], r["product"], r["version"]): r["m"] for r in rows}

    def _totals_for_arch(self, arch: str) -> dict[tuple[str | None, str, str], int]:
        """Distinct-function counts per reference build for one arch, cached."""
        cached = self._totals_cache.get(arch)
        if cached is None:
            cached = {
                (r["vendor"], r["product"], r["version"]): r["t"]
                for r in self.conn.execute(
                    "SELECT vendor, product, version, COUNT(DISTINCT hash) AS t FROM signatures WHERE arch = ? GROUP BY vendor, product, version",
                    (arch,),
                ).fetchall()
            }
            self._totals_cache[arch] = cached
        return cached

    def _norm_totals_for_arch(self, arch: str) -> dict[tuple[str | None, str, str], int]:
        """Distinct normalized-function counts per reference build, cached."""
        cached = self._norm_totals_cache.get(arch)
        if cached is None:
            cached = {
                (r["vendor"], r["product"], r["version"]): r["t"]
                for r in self.conn.execute(
                    "SELECT vendor, product, version, COUNT(DISTINCT norm_hash) AS t FROM norm_signatures WHERE arch = ? GROUP BY vendor, product, version",
                    (arch,),
                ).fetchall()
            }
            self._norm_totals_cache[arch] = cached
        return cached


def build_from_manifest(db_path: str, manifest_path: str) -> dict[str, str]:
    """Build a signature DB from a JSON manifest of reference binaries.

    Manifest: ``[{"path": "...", "product": "zlib", "version": "1.2.11",
    "vendor": "zlib", "arch": "x86_64"}, ...]``. ``vendor``/``arch`` are
    optional; ``arch`` defaults to the binary's own ELF machine.
    """
    with open(manifest_path, encoding="utf-8") as fh:
        entries = json.load(fh)
    base = os.path.dirname(os.path.abspath(manifest_path))
    os.makedirs(os.path.dirname(os.path.abspath(db_path)) or ".", exist_ok=True)
    added = 0
    skipped: list[str] = []
    with FpDB(db_path) as db:
        for entry in entries:
            path = entry["path"]
            if not os.path.isabs(path):
                path = os.path.join(base, path)
            label = f"{entry.get('product', '?')} {entry.get('version', '?')} ({os.path.basename(path)})"
            if not os.path.isfile(path):
                skipped.append(f"{label}: not found")
                continue
            sigs = extract_functions_file(path)
            if not sigs:
                skipped.append(f"{label}: no usable functions (stripped, too large, or unreadable)")
                continue
            arch = entry.get("arch") or _arch_of(path)
            db.add(
                hashes=[s.hash for s in sigs],
                functions=[s.name for s in sigs],
                arch=arch,
                vendor=entry.get("vendor"),
                product=entry["product"],
                version=str(entry["version"]),
            )
            added += len(sigs)
            # Also store radare2-normalized signatures when radare2 is available,
            # so scans can match this build across relocation/operand differences.
            norm = disasm.normalized_functions(path)
            if norm:
                db.add_normalized(
                    norm_hashes=list(norm.values()),
                    functions=list(norm.keys()),
                    arch=arch,
                    vendor=entry.get("vendor"),
                    product=entry["product"],
                    version=str(entry["version"]),
                )
        db.conn.execute("INSERT OR REPLACE INTO meta (key, value) VALUES ('source', ?)", (os.path.basename(manifest_path),))
        db.conn.commit()
        info = db.info()
    if skipped:
        info["skipped"] = f"{len(skipped)}/{len(entries)}: " + "; ".join(skipped)
    return info


def _arch_of(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            head = fh.read(20)
        if head[:4] != b"\x7fELF" or len(head) < 20:
            return "unknown"
        endian = "<" if head[5] == 1 else ">"
        import struct

        machine = struct.unpack_from(endian + "H", head, 18)[0]
        return arch_name(machine)
    except OSError:
        return "unknown"
