"""Helpers for handling untrusted firmware content without trusting it.

Everything that comes out of a firmware image (file names, link targets,
archive members, sizes) is attacker controlled. Code in this module is the
only place that writes such content to disk.
"""

from __future__ import annotations

import os
import posixpath
import tarfile
from dataclasses import dataclass, field

DEFAULT_MAX_BYTES = 8 * 1024**3  # 8 GiB of extracted file data
DEFAULT_MAX_MEMBERS = 500_000


class ExtractionLimitError(RuntimeError):
    """Raised when an archive exceeds the configured size or member limits."""


@dataclass
class TarStats:
    members: int = 0
    bytes: int = 0
    skipped: list[str] = field(default_factory=list)
    # Original permission bits per member path, before the safety filter
    # stripped setuid/setgid. Analyzers need these to flag setuid binaries.
    original_modes: dict[str, int] = field(default_factory=dict)


def is_within(root: str, path: str) -> bool:
    """True if `path` resolves to a location inside `root` (symlinks resolved)."""
    root = os.path.realpath(root)
    path = os.path.realpath(path)
    try:
        return os.path.commonpath([root, path]) == root
    except ValueError:  # different drives on Windows
        return False


def rebase_absolute_link(member_name: str, link_target: str) -> str:
    """Rewrite an absolute symlink target as a relative one, chroot style.

    Firmware root filesystems are full of links like ``sh -> /bin/busybox``.
    Inside the extraction directory they must point at the extracted
    ``bin/busybox``, never at the host's ``/bin/busybox``.
    """
    parent = "/" + posixpath.dirname(member_name.lstrip("/"))
    target = posixpath.normpath("/" + link_target.lstrip("/"))
    return posixpath.relpath(target, parent)


def safe_extract_tar(
    archive: str,
    dest: str,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_members: int = DEFAULT_MAX_MEMBERS,
) -> TarStats:
    """Extract a tar archive so that nothing can land outside `dest`.

    Uses the stdlib ``data`` filter (blocks path traversal, absolute paths,
    links escaping `dest`, device files) and adds firmware-specific handling:
    absolute symlinks are rebased into the root, special files are skipped,
    and per-member failures (e.g. names Windows cannot represent) are recorded
    instead of aborting the whole extraction.
    """
    if not hasattr(tarfile, "data_filter"):
        raise RuntimeError("Python with tarfile extraction filters is required (3.11.4+ / 3.12+)")

    os.makedirs(dest, exist_ok=True)
    stats = TarStats()

    def _filter(member: tarfile.TarInfo, path: str) -> tarfile.TarInfo | None:
        stats.members += 1
        if stats.members > max_members:
            raise ExtractionLimitError(f"archive has more than {max_members} members")
        if member.ischr() or member.isblk() or member.isfifo():
            stats.skipped.append(f"{member.name}: special file")
            return None
        if member.issym() and member.linkname.startswith("/"):
            member = member.replace(linkname=rebase_absolute_link(member.name, member.linkname), deep=False)
        original_mode = member.mode
        try:
            member = tarfile.data_filter(member, path)
        except tarfile.FilterError as exc:
            stats.skipped.append(f"{member.name}: {exc}")
            return None
        if member.isfile():
            stats.bytes += member.size
            if stats.bytes > max_bytes:
                raise ExtractionLimitError(f"archive expands beyond {max_bytes} bytes")
        stats.original_modes[member.name] = original_mode
        # Keep everything readable/traversable by us so analysis never trips
        # over a read-only directory baked into the image.
        if member.isdir():
            member = member.replace(mode=(member.mode or 0) | 0o700, deep=False)
        elif member.isfile():
            member = member.replace(mode=(member.mode or 0) | 0o600, deep=False)
        return member

    with tarfile.open(archive, "r:*") as tar:
        tar.errorlevel = 1
        for member in tar:
            try:
                tar.extract(member, dest, filter=_filter)
            except ExtractionLimitError:
                raise
            except (OSError, tarfile.TarError) as exc:
                stats.skipped.append(f"{member.name}: {exc}")
    return stats
