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
from firefly.elf import parse_file
from firefly.extract import ExtractionError, extract
from firefly.inventory import Inventory, file_strings
from firefly.models import Component, Finding

log = logging.getLogger(__name__)

REPORT_SCHEMA = 2  # v2 adds the per-file inventory ("files") that firmware diffing uses

# Above this file count the per-file inventory makes the report notably large;
# warn so users who never diff know they can drop it (capping would corrupt diffs).
FILE_INVENTORY_WARN = 50_000


@dataclass
class ScanOptions:
    output_dir: str = "firefly-out"
    jobs: int = os.cpu_count() or 1
    backend: str = "auto"
    extract_depth: int = 10
    extract_timeout: int = 3600
    only: list[str] | None = None
    skip: list[str] = field(default_factory=list)
    db_path: str | None = None
    fpdb_path: str | None = None
    file_inventory: bool = True  # emit the per-file list in the report (enables file-level diff)
    deep_reachability: bool = False  # confirm CVE reachability via radare2's call graph (opt-in, heavier)
    deep_fingerprint: bool = False  # match radare2-normalized function fingerprints (opt-in, heavier)
    run_static: bool = True  # run the static analyzers (off for `firefly emulate`)
    emulate: bool = False  # opt-in dynamic emulation stage (executes binaries)
    emulate_timeout: float = 20.0
    emulate_max: int = 64
    emulate_sandbox: bool = True  # False == --no-emulate-sandbox
    emulate_shim: bool = False
    emulate_args: tuple[str, ...] = ()
    # Phase B: full-system emulation
    emulate_system: bool = False
    emulate_system_timeout: float = 90.0
    emulate_kernel: str | None = None
    emulate_machine: str | None = None
    emulate_dtb: str | None = None
    emulate_nic: str | None = None
    emulate_append: str | None = None
    emulate_image: str | None = None
    emulate_initrd: str | None = None


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
    files: list[dict] = field(default_factory=list)
    file_inventory: bool = False  # True once the per-file list was actually recorded
    timings: dict[str, float] = field(default_factory=dict)
    components: list[Component] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    errors: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)


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

    # These module caches are keyed by (path, size); clear them per scan so a
    # second scan of a path whose content changed but kept its size in the same
    # process (library/server reuse) never returns a stale parse.
    parse_file.cache_clear()
    file_strings.cache_clear()

    result = ScanResult(path, digest, size, workdir, started=_now())
    ctx = ScanContext(firmware_path=path, workdir=workdir, jobs=max(1, options.jobs), db_path=options.db_path, fpdb_path=options.fpdb_path, deep_reachability=options.deep_reachability, deep_fingerprint=options.deep_fingerprint)

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
        if options.file_inventory:
            result.files = ctx.inventory.file_entries()
            result.file_inventory = True
            if len(result.files) > FILE_INVENTORY_WARN:
                result.warnings.append(
                    f"recorded a {len(result.files)}-file inventory in the report (large JSON); "
                    "pass --no-file-inventory to omit it if you won't run `firefly diff`"
                )
        result.timings["inventory"] = round(time.perf_counter() - t0, 3)

    if options.run_static:
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
            ctx.components.extend(out.components)
            result.warnings.extend(out.warnings)
            if out.artifacts:
                result.artifacts[analyzer.name] = out.artifacts

    if options.emulate and ctx.inventory is not None and ctx.extraction is not None:
        _run_emulation(result, ctx, options)

    if options.emulate_system and ctx.inventory is not None and ctx.extraction is not None:
        _run_system_emulation(result, ctx, options)

    result.findings.sort(key=lambda f: (-f.severity.rank, not f.metadata.get("kev"), -(f.metadata.get("cvss_score") or 0), f.analyzer, f.title))
    result.finished = _now()
    return result


def _run_emulation(result: ScanResult, ctx: ScanContext, options: ScanOptions) -> None:
    """Run the opt-in dynamic emulation stage, folding its output into the scan.

    Isolated in its own try/except (like an analyzer) so that a failure to
    emulate never costs the static results.
    """
    t0 = time.perf_counter()
    try:
        from firefly.emulation import EmulationOptions, run_emulation

        assert ctx.extraction is not None and ctx.inventory is not None
        emu_opts = EmulationOptions(
            timeout_s=options.emulate_timeout,
            max_binaries=options.emulate_max,
            jobs=options.jobs,
            require_sandbox=options.emulate_sandbox,
            args=tuple(options.emulate_args),
            build_shim=options.emulate_shim,
            workdir=ctx.workdir,
        )
        emu = run_emulation(ctx.extraction.scan_root, ctx.inventory, emu_opts)
        result.findings.extend(emu.to_findings())
        result.artifacts["emulation"] = emu.to_artifact()
        if not emu.available and emu.reason:
            result.warnings.append(f"emulation skipped: {emu.reason}")
        elif emu.reason:
            result.warnings.append(f"emulation: {emu.reason}")
    except Exception as exc:  # emulation failure must not lose the scan
        log.debug("emulation stage failed", exc_info=True)
        result.errors.append({"stage": "emulation", "error": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc()})
    finally:
        result.timings["emulation"] = round(time.perf_counter() - t0, 3)


def _run_system_emulation(result: ScanResult, ctx: ScanContext, options: ScanOptions) -> None:
    """Run the opt-in full-system (Phase B) emulation stage."""
    t0 = time.perf_counter()
    try:
        from firefly.emulation.system import SystemOptions, run_system

        assert ctx.extraction is not None and ctx.inventory is not None
        sys_opts = SystemOptions(
            timeout_s=options.emulate_system_timeout,
            require_sandbox=options.emulate_sandbox,
            kernel=options.emulate_kernel,
            machine=options.emulate_machine,
            dtb=options.emulate_dtb,
            nic=options.emulate_nic,
            append=options.emulate_append,
            image=options.emulate_image,
            initrd=options.emulate_initrd,
            workdir=ctx.workdir,
        )
        res = run_system(ctx.extraction, ctx.inventory, sys_opts)
        result.findings.extend(res.to_findings())
        result.artifacts["system_emulation"] = res.to_artifact()
        if not res.available and res.reason:
            result.warnings.append(f"full-system emulation skipped: {res.reason}")
        elif not res.booted:
            result.warnings.append(f"full-system emulation: {res.boot_reason}")
    except Exception as exc:  # emulation failure must not lose the scan
        log.debug("system emulation stage failed", exc_info=True)
        result.errors.append({"stage": "system_emulation", "error": f"{type(exc).__name__}: {exc}", "traceback": traceback.format_exc()})
    finally:
        result.timings["system_emulation"] = round(time.perf_counter() - t0, 3)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
