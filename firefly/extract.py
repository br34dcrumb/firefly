"""Turn a firmware input (blob, tarball or directory) into a tree on disk.

Raw firmware blobs are unpacked by an external, sandboxable backend (unblob
preferred, binwalk as fallback). Firefly never shells out with a command
string: every external call is an argument list, so file names coming from a
firmware image cannot be interpreted by a shell.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import tarfile
from dataclasses import dataclass, field

from firefly.safety import safe_extract_tar

log = logging.getLogger(__name__)

# Directories that define the root of a UNIX filesystem
UNIX_DIRS = frozenset(
    ["bin", "boot", "dev", "etc", "home", "lib", "mnt", "opt", "proc", "root", "run", "sbin", "sys", "tmp", "usr", "var", "www"]
)
UNIX_THRESHOLD = 4
ROOTFS_SEARCH_DEPTH = 8

BACKENDS = ("unblob", "binwalk")


class ExtractionError(RuntimeError):
    pass


@dataclass
class ExtractionResult:
    input_path: str
    input_kind: str  # "directory" | "tar" | "firmware"
    backend: str | None
    extract_dir: str
    scan_root: str
    rootfs_candidates: list[str] = field(default_factory=list)
    original_modes: dict[str, int] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


def rootfs_score(path: str) -> int:
    try:
        entries = os.listdir(path)
    except OSError:
        return 0
    # Count symlinks too: `lib -> usr/lib` is common in merged-/usr layouts.
    return sum(
        1
        for name in entries
        if name in UNIX_DIRS and (os.path.isdir(os.path.join(path, name)) or os.path.islink(os.path.join(path, name)))
    )


def find_rootfs_candidates(start: str, max_depth: int = ROOTFS_SEARCH_DEPTH) -> list[str]:
    """Return directories under `start` that look like a Linux root filesystem.

    Best candidates come first. A candidate nested inside another candidate
    (e.g. ``rootfs/usr``) is dropped.
    """
    scored: list[tuple[int, str]] = []
    start = os.path.abspath(start)
    base_depth = start.rstrip(os.sep).count(os.sep)
    for dirpath, dirnames, _ in os.walk(start, followlinks=False):
        if dirpath.count(os.sep) - base_depth >= max_depth:
            dirnames.clear()
        score = rootfs_score(dirpath)
        if score >= UNIX_THRESHOLD:
            scored.append((score, dirpath))
            # Don't descend into a rootfs looking for more rootfs; firmware
            # images with several filesystems keep them side by side.
            dirnames[:] = [d for d in dirnames if d not in UNIX_DIRS]
    scored.sort(key=lambda item: (-item[0], len(item[1])))
    result: list[str] = []
    for _, path in scored:
        if not any(os.path.commonpath([path, kept]) == kept for kept in result):
            result.append(path)
    return result


def available_backends() -> list[str]:
    return [name for name in BACKENDS if shutil.which(name)]


def _run_backend(backend: str, firmware: str, outdir: str, jobs: int, depth: int, timeout: int, workdir: str) -> None:
    exe = shutil.which(backend)
    if not exe:
        raise ExtractionError(f"extraction backend {backend!r} is not installed")
    if backend == "unblob":
        cmd = [exe, "-f", "-e", outdir, "-d", str(depth), "-p", str(jobs), "--report", os.path.join(workdir, "unblob-report.json"), firmware]
    elif backend == "binwalk":
        cmd = [exe, "-M", "-e", "-C", outdir, firmware]
    else:
        raise ExtractionError(f"unknown backend {backend!r}")
    log.info("running %s", " ".join(cmd))
    try:
        proc = subprocess.run(cmd, cwd=workdir, capture_output=True, text=True, errors="replace", timeout=timeout)
    except subprocess.TimeoutExpired as exc:
        raise ExtractionError(f"{backend} timed out after {timeout}s") from exc
    with open(os.path.join(workdir, f"{backend}.log"), "w", encoding="utf-8") as fh:
        fh.write(proc.stdout)
        fh.write(proc.stderr)
    if proc.returncode != 0:
        # unblob exits non-zero when some chunks fail; partial output is still useful.
        log.warning("%s exited with %d (see %s.log)", backend, proc.returncode, backend)


def extract(
    path: str,
    workdir: str,
    backend: str = "auto",
    jobs: int = 1,
    depth: int = 10,
    timeout: int = 3600,
) -> ExtractionResult:
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise ExtractionError(f"input not found: {path}")
    os.makedirs(workdir, exist_ok=True)

    if os.path.isdir(path):
        candidates = find_rootfs_candidates(path)
        return ExtractionResult(path, "directory", None, path, candidates[0] if len(candidates) == 1 else path, candidates)

    extract_dir = os.path.join(workdir, "extracted")
    if os.path.exists(extract_dir):
        shutil.rmtree(extract_dir)

    if tarfile.is_tarfile(path):
        stats = safe_extract_tar(path, extract_dir)
        candidates = find_rootfs_candidates(extract_dir)
        warnings = [f"skipped {len(stats.skipped)} archive member(s)"] if stats.skipped else []
        if stats.skipped:
            with open(os.path.join(workdir, "skipped-members.txt"), "w", encoding="utf-8") as fh:
                fh.write("\n".join(stats.skipped))
        scan_root = candidates[0] if len(candidates) == 1 else extract_dir
        modes = _rebase_modes(stats.original_modes, extract_dir, scan_root)
        return ExtractionResult(path, "tar", "tarfile", extract_dir, scan_root, candidates, modes, warnings)

    if backend == "auto":
        found = available_backends()
        if not found:
            raise ExtractionError(
                "no extraction backend found (install unblob or binwalk, or use the Docker image); "
                "already-extracted root filesystems can be scanned as a directory or tarball"
            )
        backend = found[0]
    _run_backend(backend, path, extract_dir, jobs, depth, timeout, workdir)
    if not os.path.isdir(extract_dir) or not os.listdir(extract_dir):
        raise ExtractionError(f"{backend} extracted nothing from {path}")
    candidates = find_rootfs_candidates(extract_dir)
    warnings = [] if candidates else ["no Linux root filesystem found; analysing everything that was extracted"]
    scan_root = candidates[0] if len(candidates) == 1 else extract_dir
    return ExtractionResult(path, "firmware", backend, extract_dir, scan_root, candidates, warnings=warnings)


def _rebase_modes(modes: dict[str, int], extract_dir: str, scan_root: str) -> dict[str, int]:
    """Re-key archive member modes relative to the scan root."""
    prefix = os.path.relpath(scan_root, extract_dir).replace(os.sep, "/")
    if prefix == ".":
        return {name.lstrip("/").removeprefix("./"): mode for name, mode in modes.items()}
    prefix += "/"
    out = {}
    for name, mode in modes.items():
        name = name.lstrip("/").removeprefix("./")
        if name.startswith(prefix):
            out[name[len(prefix):]] = mode
    return out
