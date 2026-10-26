"""Identify software components and versions from strings in ELF binaries."""

from __future__ import annotations

import os
from concurrent.futures import ProcessPoolExecutor

from firefly.analyzers import Analyzer, AnalyzerResult, ScanContext
from firefly.inventory import file_strings
from firefly.models import Component
from firefly.versioncfg import VersionRule, load_default_rules

_RULES: list[VersionRule] | None = None
# Below this many binaries, process start-up costs more than it saves.
PARALLEL_MIN_TASKS = 8


def _init_worker() -> None:
    global _RULES
    _RULES, _ = load_default_rules()


def _rules() -> list[VersionRule]:
    if _RULES is None:
        _init_worker()
    return _RULES  # type: ignore[return-value]


def match_text(text: str, basename: str, rules: list[VersionRule]) -> list[tuple[int, str, str]]:
    """Return ``(rule index, normalised id, matched string)`` for each rule that hits."""
    hits = []
    for idx, rule in enumerate(rules):
        if rule.mode == "strict" and basename != rule.name:
            continue
        if any(lit is not None and lit not in text for lit in rule.literals):
            continue
        last = None
        for pattern in rule.patterns:
            last = pattern.search(text)
            if last is None:
                break
        if last is None:
            continue
        matched = last.group(0)
        normalised = rule.normalise(matched).strip()
        if any(ch.isdigit() for ch in normalised):
            hits.append((idx, normalised, matched))
    return hits


def _scan_file(task: tuple[str, int, str, str]) -> tuple[str, list[tuple[int, str, str]]]:
    abs_path, size, rel_path, basename = task
    text = file_strings(abs_path, size)
    if not text:
        return rel_path, []
    return rel_path, match_text(text, basename, _rules())


def split_identifier(normalised: str) -> tuple[str | None, str, str] | None:
    """``vendor:product:version`` or ``product:version`` -> parts."""
    parts = [p.strip() for p in normalised.split(":")]
    if len(parts) < 2 or not parts[-1]:
        return None
    version = parts[-1]
    if len(parts) == 2:
        return None, parts[0], version
    return parts[0], ":".join(parts[1:-1]), version


class VersionAnalyzer(Analyzer):
    name = "versions"
    description = "Software inventory from version strings (bin_version_strings.cfg)"

    def run(self, ctx: ScanContext) -> AnalyzerResult:
        assert ctx.inventory is not None
        result = AnalyzerResult()
        rules, errors = load_default_rules()
        if errors:
            result.artifacts["rule_errors"] = errors
        tasks = [
            (ctx.inventory.abspath(r), r.size, r.path, os.path.basename(r.path))
            for r in ctx.inventory
            if r.is_executable_code
        ]
        if ctx.jobs > 1 and len(tasks) > PARALLEL_MIN_TASKS:
            with ProcessPoolExecutor(max_workers=ctx.jobs, initializer=_init_worker) as pool:
                outputs = list(pool.map(_scan_file, tasks, chunksize=8))
        else:
            outputs = [_scan_file(t) for t in tasks]

        components: dict[tuple[str, str, str], Component] = {}
        for rel_path, hits in outputs:
            for idx, normalised, matched in hits:
                parts = split_identifier(normalised)
                if parts is None:
                    continue
                vendor, product, version = parts
                comp = components.setdefault(
                    (vendor or "", product, version),
                    Component(product=product, version=version, vendor=vendor, license=rules[idx].license),
                )
                if rel_path not in comp.paths:
                    comp.paths.append(rel_path)
                if matched not in comp.evidence and len(comp.evidence) < 5:
                    comp.evidence.append(matched)

        result.components = sorted(components.values(), key=lambda c: (c.product, c.version))
        result.artifacts["binaries_scanned"] = len(tasks)
        return result
