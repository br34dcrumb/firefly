"""Scan orchestration: extract -> inventory -> analyzers -> report."""

from __future__ import annotations

import hashlib
import logging
import os
import time
import traceback
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from firefly.analyzers import Analyzer, ScanContext, all_analyzers
from firefly.extract import ExtractionError, extract
from firefly.inventory import Inventory
from firefly.models import Component, Finding

log = logging.getLogger(__name__)

REPORT_SCHEMA = 1


@dataclass
class ScanOptions:
    output_dir: str = "firefly-out"
    jobs: int = os.cpu_count() or 1
    backend: str = "auto"
    extract_depth: int = 10
    extract_timeout: int = 3600
    only: list[str] | None = None
    skip: list[str] = field(default_factory=list)


@dataclass
class ScanResult:
    input_path: str
    input_sha256: str
    input_size: int
    workdir: str
    started: str
    finished: str = ""
    extraction: dict[str, Any] = field(default_factory=dict)
    inventory: dict[str, int] = field(default_factory=dict)
    timings: dict[str, float] = field(default_factory=dict)
    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    errors: list[dict[str, str]] = field(default_factory=list)


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _input_identity(path: str) -> tuple[str, int]:
    if os.path.isfile(path):
        return sha256_file(path), os.path.getsize(path)
    # Directories: identity from the path itself; content hashes live in the inventory.
    return hashlib.sha256(os.path.abspath(path).encode()).hexdigest(), 0


def select_analyzers(options: ScanOptions) -> list[Analyzer]:
    classes = all_analyzers()
    if options.only:
        classes = [c for c in classes if c.name in options.only]
    return [c() for c in classes if c.name not in options.skip]


def scan(path: str, options: ScanOptions | None = None) -> ScanResult:
    options = options or ScanOptions()
    path = os.path.abspath(path)
    digest, size = _input_identity(path)
    name = os.path.basename(path.rstrip("/\\")) or "input"
    workdir = os.path.abspath(os.path.join(options.output_dir, f"{name}_{digest[:12]}"))
    os.makedirs(workdir, exist_ok=True)

    result = ScanResult(path, digest, size, workdir, started=_now())
    ctx = ScanContext(firmware_path=path, workdir=workdir, jobs=max(1, options.jobs))

    t0 = time.perf_counter()
    try:
        ext = extract(path, workdir, options.backend, ctx.jobs, options.extract_depth, options.extract_timeout)
        ctx.extraction = ext
        result.extraction = {
            "kind": ext.input_kind,
            "backend": ext.backend,
            "scan_root": ext.scan_root,
            "rootfs": [os.path.relpath(c, ext.extract_dir).replace(os.sep, "/") for c in ext.rootfs_candidates],
            "warnings": ext.warnings,
        }
    except ExtractionError as exc:
        result.errors.append({"stage": "extract", "error": str(exc)})
    result.timings["extract"] = round(time.perf_counter() - t0, 3)

    if ctx.extraction:
        t0 = time.perf_counter()
        ctx.inventory = Inventory.build(ctx.extraction.scan_root, ctx.jobs, ctx.extraction.original_modes)
        result.inventory = ctx.inventory.stats()
        result.timings["inventory"] = round(time.perf_counter() - t0, 3)

    for analyzer in select_analyzers(options):
        if analyzer.requires_inventory and ctx.inventory is None:
            continue
        t0 = time.perf_counter()
        try:
            out = analyzer.run(ctx)
        except Exception as exc:  # one broken analyzer must not lose the whole scan
            log.debug("analyzer %s failed", analyzer.name, exc_info=True)
            result.errors.append({"stage": analyzer.name, "error": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc()})
            continue
        finally:
            result.timings[analyzer.name] = round(time.perf_counter() - t0, 3)
        result.findings.extend(out.findings)
        result.components.extend(out.components)
        if out.artifacts:
            result.artifacts[analyzer.name] = out.artifacts

    result.findings.sort(key=lambda f: (-f.severity.rank, f.analyzer, f.path or ""))
    result.finished = _now()
    return result


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
