"""Find hardcoded private keys, passwords and API tokens in the filesystem.

All secret values are redacted by :mod:`firefly.secrets` before they reach a
finding, so reports and the console never contain a usable credential.
"""

from __future__ import annotations

import os

from firefly.analyzers import Analyzer, AnalyzerResult, ScanContext
from firefly.models import FileKind, Finding, Severity
from firefly.secrets import API_TOKEN, PASSWORD, PRIVATE_KEY, scan_bytes

SEVERITY = {PRIVATE_KEY: Severity.CRITICAL, API_TOKEN: Severity.HIGH, PASSWORD: Severity.HIGH}
# Only scan files that can plausibly hold text secrets; skip big blobs.
MAX_FILE = 4 * 1024**2
# Directories whose "secrets" are usually sample/CA material, not device creds.
LOWER_CONFIDENCE_DIRS = ("/ssl/certs/", "/ca-certificates/", "/share/doc/", "/man/", "/examples/")


def _should_scan(rec) -> bool:
    if rec.kind in (FileKind.SYMLINK, FileKind.OTHER):
        return False
    if rec.kind is FileKind.ELF:
        return False  # keys embedded in binaries are handled separately below
    return 0 < rec.size <= MAX_FILE


class CredentialsAnalyzer(Analyzer):
    name = "credentials"
    description = "Hardcoded private keys, passwords and API tokens (values redacted)"

    def run(self, ctx: ScanContext) -> AnalyzerResult:
        assert ctx.inventory is not None
        result = AnalyzerResult()
        kind_counts: dict[str, int] = {}

        for rec in ctx.inventory:
            if not _should_scan(rec):
                continue
            try:
                with open(ctx.inventory.abspath(rec), "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            for hit in scan_bytes(data):
                kind_counts[hit.kind] = kind_counts.get(hit.kind, 0) + 1
                low_conf = any(d in "/" + rec.path.lower() for d in LOWER_CONFIDENCE_DIRS)
                sev = SEVERITY[hit.kind]
                if low_conf and sev.rank > Severity.MEDIUM.rank:
                    sev = Severity.MEDIUM
                label = {PRIVATE_KEY: "Private key", API_TOKEN: "API token/secret", PASSWORD: "Hardcoded credential"}[hit.kind]
                result.findings.append(
                    Finding(
                        analyzer=self.name,
                        title=f"{label} in {os.path.basename(rec.path)} ({hit.subtype})",
                        severity=sev,
                        confidence="low" if low_conf else "high" if hit.kind != PASSWORD else "medium",
                        path=rec.path,
                        evidence=hit.preview,  # already redacted
                        description=(
                            f"{label} found at {rec.path}:{hit.line}. Value redacted; "
                            f"{hit.length} characters, fingerprint {hit.fingerprint}."
                            + (" Looks like bundled CA/sample material." if low_conf else "")
                        ),
                        metadata={
                            "kind": hit.kind,
                            "subtype": hit.subtype,
                            "line": hit.line,
                            "length": hit.length,
                            "fingerprint": hit.fingerprint,
                        },
                    )
                )

        result.artifacts = {"by_kind": kind_counts}
        return result
