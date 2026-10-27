"""Analyzer plugin interface and registry.

An analyzer receives the shared :class:`ScanContext` and returns an
:class:`AnalyzerResult`. Third-party analyzers can be added without touching
Firefly by exposing a subclass through the ``firefly.analyzers`` entry point
group.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from importlib.metadata import entry_points
from typing import Any

from firefly.extract import ExtractionResult
from firefly.inventory import Inventory
from firefly.models import Component, Finding

log = logging.getLogger(__name__)


@dataclass
class ScanContext:
    firmware_path: str
    workdir: str
    jobs: int
    extraction: ExtractionResult | None = None
    inventory: Inventory | None = None
    db_path: str | None = None
    # Components found by analyzers that already ran (analyzers run in order).
    components: list[Component] = field(default_factory=list)


@dataclass
class AnalyzerResult:
    findings: list[Finding] = field(default_factory=list)
    components: list[Component] = field(default_factory=list)
    artifacts: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)


class Analyzer:
    name: str = ""
    description: str = ""
    # False for analyzers that work on the raw image and can run even when
    # extraction failed (e.g. entropy).
    requires_inventory: bool = True

    def run(self, ctx: ScanContext) -> AnalyzerResult:
        raise NotImplementedError


def builtin_analyzers() -> list[type[Analyzer]]:
    from firefly.analyzers.cves import CveAnalyzer
    from firefly.analyzers.entropy import EntropyAnalyzer
    from firefly.analyzers.versions import VersionAnalyzer

    # Order matters: cves consumes the components versions produces.
    return [EntropyAnalyzer, VersionAnalyzer, CveAnalyzer]


def all_analyzers() -> list[type[Analyzer]]:
    found = builtin_analyzers()
    for ep in entry_points(group="firefly.analyzers"):
        try:
            cls = ep.load()
        except Exception as exc:  # a broken plugin must not break scans
            log.warning("could not load analyzer plugin %s: %s", ep.name, exc)
            continue
        if isinstance(cls, type) and issubclass(cls, Analyzer):
            found.append(cls)
    return found
