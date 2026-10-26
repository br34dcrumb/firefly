"""Data types shared by every pipeline stage."""

from __future__ import annotations

import enum
import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any


class Severity(str, enum.Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return list(Severity).index(self)


class FileKind(str, enum.Enum):
    ELF = "elf"
    SCRIPT = "script"
    SYMLINK = "symlink"
    DATA = "data"
    OTHER = "other"  # devices, sockets, fifos


@dataclass
class ElfInfo:
    bits: int
    endian: str  # "little" | "big"
    machine: str
    elf_type: str  # "exec" | "dyn" | "rel" | "core" | "unknown"


@dataclass
class FileRecord:
    """One entry of the firmware inventory. Paths are relative to the scan root."""

    path: str
    kind: FileKind
    size: int = 0
    mode: int = 0
    sha256: str | None = None
    link_target: str | None = None
    elf: ElfInfo | None = None

    @property
    def is_executable_code(self) -> bool:
        return self.kind is FileKind.ELF and self.elf is not None and self.elf.elf_type in ("exec", "dyn")


@dataclass
class Component:
    """A piece of identified software (an SBOM entry)."""

    product: str
    version: str
    vendor: str | None = None
    paths: list[str] = field(default_factory=list)
    evidence: list[str] = field(default_factory=list)
    license: str | None = None

    @property
    def cpe(self) -> str:
        part = "o" if self.product in ("linux_kernel",) else "a"
        vendor = self.vendor or self.product
        return f"cpe:2.3:{part}:{_cpe_escape(vendor)}:{_cpe_escape(self.product)}:{_cpe_escape(self.version)}:*:*:*:*:*:*:*"

    def key(self) -> tuple[str, str, str]:
        return (self.vendor or "", self.product, self.version)


def _cpe_escape(value: str) -> str:
    out = []
    for ch in value.lower():
        if ch.isalnum() or ch in "_-.":
            out.append(ch)
        else:
            out.append("\\" + ch)
    return "".join(out)


@dataclass
class Finding:
    analyzer: str
    title: str
    severity: Severity
    description: str = ""
    path: str | None = None
    evidence: str | None = None
    confidence: str = "medium"  # "low" | "medium" | "high"
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def id(self) -> str:
        """Stable identifier so the same issue keeps its id across re-scans."""
        h = hashlib.sha256(f"{self.analyzer}|{self.title}|{self.path or ''}".encode())
        return "FF-" + h.hexdigest()[:12]

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["id"] = self.id
        d["severity"] = self.severity.value
        return d
