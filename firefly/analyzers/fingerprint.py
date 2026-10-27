"""Identify statically-linked / stripped components by function fingerprints.

Runs between ``versions`` and ``cves``: where a binary carries no version
string, matching its function fingerprints against the signature DB recovers a
component (product + version), which the CVE analyzer then matches as usual.
A match is reported as a Component (so it flows into CVE matching) and an
informational finding (so it is visible even when no CVE applies).
"""

from __future__ import annotations

from firefly.analyzers import Analyzer, AnalyzerResult, ScanContext
from firefly.components import merge
from firefly.fingerprint import extract_functions_file
from firefly.fpdb import FpDB
from firefly.models import Component, FileKind, Finding, Severity


class FingerprintAnalyzer(Analyzer):
    name = "fingerprint"
    description = "Identify stripped/statically-linked components by function fingerprints"

    def run(self, ctx: ScanContext) -> AnalyzerResult:
        assert ctx.inventory is not None
        result = AnalyzerResult()
        db = FpDB.open_existing(ctx.fpdb_path)
        if db is None:
            result.warnings.append("no fingerprint database found; run `firefly fpdb build` to enable binary SCA")
            return result

        raw: list[Component] = []
        scanned = 0
        with db:
            result.artifacts["database"] = db.info()
            for rec in ctx.inventory.of_kind(FileKind.ELF):
                if not (rec.is_executable_code and rec.elf):
                    continue
                sigs = extract_functions_file(ctx.inventory.abspath(rec))
                if not sigs:
                    continue
                scanned += 1
                hashes = {s.hash for s in sigs}
                # identify() returns every reference build over threshold, best
                # first; close versions of one product share most functions, so
                # keep only the strongest version per product to avoid emitting
                # a component (and CVEs) for a version that isn't present.
                seen: set[tuple[str | None, str]] = set()
                for ident in db.identify(hashes, rec.elf.machine):
                    if (ident.vendor, ident.product) in seen:
                        continue
                    seen.add((ident.vendor, ident.product))
                    raw.append(
                        Component(
                            product=ident.product,
                            version=ident.version,
                            vendor=ident.vendor,
                            paths=[rec.path],
                            evidence=[f"{ident.matched}/{ident.reference_total} functions match {ident.product} {ident.version} by code fingerprint"],
                        )
                    )

        result.components = merge(raw)  # canonicalize names so CVE matching lines up
        for comp in result.components:
            result.findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"Identified {comp.product} {comp.version} by code fingerprint",
                    severity=Severity.INFO,
                    confidence="medium",
                    path=comp.paths[0] if comp.paths else None,
                    evidence=comp.evidence[0] if comp.evidence else None,
                    description=(
                        f"{comp.product} {comp.version} was identified by matching function "
                        "fingerprints, not a version string — so it is detected even though it is "
                        "stripped or statically linked. CVEs are matched against it like any other component."
                    ),
                    metadata={"component": {"vendor": comp.vendor, "product": comp.product, "version": comp.version}},
                )
            )
        result.artifacts["binaries_fingerprinted"] = scanned
        return result
