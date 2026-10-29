"""Walk the extracted tree once and classify every file.

Every analyzer works from this inventory, so the filesystem is walked, typed
and hashed exactly once per scan. Classification reads file headers directly
(no libmagic, no subprocess per file), and symlinks are recorded but never
followed: a firmware link like ``etc/passwd -> /etc/passwd`` must not make us
read the host's files.
"""

from __future__ import annotations

import hashlib
import os
import re
import stat
from concurrent.futures import ThreadPoolExecutor
from functools import lru_cache

from firefly.models import ElfInfo, FileKind, FileRecord

HASH_LIMIT = 512 * 1024**2  # don't hash single files beyond 512 MiB
STRINGS_LIMIT = 64 * 1024**2  # don't run strings over files beyond 64 MiB

ELF_MACHINES = {
    0x02: "sparc", 0x03: "x86", 0x08: "mips", 0x14: "ppc", 0x15: "ppc64", 0x16: "s390",
    0x28: "arm", 0x2A: "superh", 0x32: "ia64", 0x3E: "x86_64", 0x5D: "arc", 0xB7: "aarch64",
    0xBC: "tilepro", 0xC3: "arcv2", 0xF3: "riscv", 0x102: "loongarch", 0x5E: "xtensa",
}
ELF_TYPES = {1: "rel", 2: "exec", 3: "dyn", 4: "core"}

_PRINTABLE = re.compile(rb"[\x20-\x7e\t]{4,}")


def parse_elf_header(header: bytes) -> ElfInfo | None:
    if len(header) < 20 or header[:4] != b"\x7fELF":
        return None
    bits = {1: 32, 2: 64}.get(header[4])
    endian = {1: "little", 2: "big"}.get(header[5])
    if bits is None or endian is None:
        return None
    e_type = int.from_bytes(header[16:18], endian)
    e_machine = int.from_bytes(header[18:20], endian)
    return ElfInfo(
        bits=bits,
        endian=endian,
        machine=ELF_MACHINES.get(e_machine, f"0x{e_machine:x}"),
        elf_type=ELF_TYPES.get(e_type, "unknown"),
    )


def _classify(abs_path: str, rel_path: str, st: os.stat_result) -> FileRecord:
    if stat.S_ISLNK(st.st_mode):
        try:
            target = os.readlink(abs_path)
        except OSError:
            target = None
        return FileRecord(rel_path, FileKind.SYMLINK, mode=st.st_mode & 0o7777, link_target=target)
    if not stat.S_ISREG(st.st_mode):
        return FileRecord(rel_path, FileKind.OTHER, mode=st.st_mode & 0o7777)

    record = FileRecord(rel_path, FileKind.DATA, size=st.st_size, mode=st.st_mode & 0o7777)
    try:
        hasher = hashlib.sha256()
        with open(abs_path, "rb") as fh:
            head = fh.read(64)
            hasher.update(head)
            if st.st_size <= HASH_LIMIT:
                for chunk in iter(lambda: fh.read(1024 * 1024), b""):
                    hasher.update(chunk)
                record.sha256 = hasher.hexdigest()
    except OSError:
        return record

    elf = parse_elf_header(head)
    if elf:
        record.kind = FileKind.ELF
        record.elf = elf
    elif head.startswith(b"#!"):
        record.kind = FileKind.SCRIPT
    return record


class Inventory:
    def __init__(self, root: str, records: list[FileRecord], original_modes: dict[str, int] | None = None):
        self.root = root
        self.records = records
        if original_modes:
            for rec in records:
                if rec.path in original_modes:
                    rec.mode = original_modes[rec.path] & 0o7777
        self._by_path = {r.path: r for r in records}

    @classmethod
    def build(cls, root: str, jobs: int = 8, original_modes: dict[str, int] | None = None) -> "Inventory":
        root = os.path.abspath(root)
        entries: list[tuple[str, str, os.stat_result]] = []
        stack = [root]
        while stack:
            current = stack.pop()
            try:
                with os.scandir(current) as it:
                    for entry in it:
                        try:
                            st = entry.stat(follow_symlinks=False)
                        except OSError:
                            continue
                        rel = os.path.relpath(entry.path, root).replace(os.sep, "/")
                        if stat.S_ISDIR(st.st_mode):
                            stack.append(entry.path)
                        else:
                            entries.append((entry.path, rel, st))
            except OSError:
                continue
        with ThreadPoolExecutor(max_workers=max(1, jobs)) as pool:
            records = list(pool.map(lambda e: _classify(*e), entries, chunksize=64))
        records.sort(key=lambda r: r.path)
        return cls(root, records, original_modes)

    def __iter__(self):
        return iter(self.records)

    def __len__(self) -> int:
        return len(self.records)

    def get(self, rel_path: str) -> FileRecord | None:
        return self._by_path.get(rel_path)

    def abspath(self, record: FileRecord) -> str:
        return os.path.join(self.root, *record.path.split("/"))

    def of_kind(self, kind: FileKind) -> list[FileRecord]:
        return [r for r in self.records if r.kind is kind]

    def strings(self, record: FileRecord, min_len: int = 4) -> str:
        return file_strings(self.abspath(record), record.size, min_len)

    def stats(self) -> dict[str, int]:
        counts: dict[str, int] = {k.value: 0 for k in FileKind}
        for r in self.records:
            counts[r.kind.value] += 1
        counts["total"] = len(self.records)
        counts["bytes"] = sum(r.size for r in self.records)
        return counts

    def file_entries(self) -> list[dict]:
        """Per-file inventory for the report, enabling file-level diffing.

        Compact on purpose (path, kind, sha256, size, and a symlink's target):
        enough to tell added/removed/changed files apart across two scans
        without carrying the whole FileRecord.
        """
        out: list[dict] = []
        for r in self.records:
            entry: dict = {"path": r.path, "kind": r.kind.value, "size": r.size, "sha256": r.sha256}
            if r.link_target is not None:
                entry["link_target"] = r.link_target
            out.append(entry)
        return out


@lru_cache(maxsize=256)
def file_strings(abs_path: str, size: int, min_len: int = 4) -> str:
    """Equivalent of ``strings -n min_len`` returning newline-joined text."""
    if size > STRINGS_LIMIT:
        return ""
    try:
        with open(abs_path, "rb") as fh:
            data = fh.read()
    except OSError:
        return ""
    pattern = _PRINTABLE if min_len == 4 else re.compile(rb"[\x20-\x7e\t]{%d,}" % min_len)
    return b"\n".join(pattern.findall(data)).decode("ascii")
