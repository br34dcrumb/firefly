"""Flag use of memory-unsafe and command-execution C library functions.

Evidence is the dynamic symbol table (imported functions), not string
matching, so this is far less noisy than grepping for names: a binary that
imports ``system`` and ``strcpy`` genuinely calls them. The finding is a
prompt to review, not proof of a bug; severity reflects how dangerous the
function is and whether the binary is network-facing.
"""

from __future__ import annotations

import os

from firefly.analyzers import Analyzer, AnalyzerResult, ScanContext
from firefly.analyzers.hardening import is_network_facing
from firefly.elf import parse_file
from firefly.models import FileKind, Finding, Severity

# function -> (base severity, why)
DANGEROUS = {
    "system": (Severity.HIGH, "runs a shell command; command injection if any part is attacker-influenced"),
    "popen": (Severity.HIGH, "runs a shell command; command injection risk"),
    "execl": (Severity.MEDIUM, "executes a program; unsafe if the path or args are attacker-influenced"),
    "execlp": (Severity.MEDIUM, "searches PATH to execute a program; unsafe with attacker-influenced input"),
    "execvp": (Severity.MEDIUM, "searches PATH to execute a program; unsafe with attacker-influenced input"),
    "gets": (Severity.HIGH, "unbounded stdin read; always a buffer overflow"),
    "strcpy": (Severity.LOW, "no bounds check; overflow if source is longer than the destination"),
    "strcat": (Severity.LOW, "no bounds check; overflow risk"),
    "sprintf": (Severity.LOW, "no bounds check; overflow if the formatted output is long"),
    "vsprintf": (Severity.LOW, "no bounds check; overflow risk"),
    "scanf": (Severity.LOW, "unbounded %s can overflow the destination"),
    "sscanf": (Severity.LOW, "unbounded %s can overflow the destination"),
    "memcpy": (Severity.INFO, "safe only if the length is validated"),
    "strncpy": (Severity.INFO, "does not null-terminate on truncation"),
}
# These are only worth surfacing in a binary that also handles the network.
CONTEXT_ONLY = frozenset({"strcpy", "strcat", "sprintf", "vsprintf", "scanf", "sscanf", "memcpy", "strncpy"})


class DangerousFunctionsAnalyzer(Analyzer):
    name = "dangerfns"
    description = "Memory-unsafe and command-exec C functions imported by binaries"

    def run(self, ctx: ScanContext) -> AnalyzerResult:
        assert ctx.inventory is not None
        result = AnalyzerResult()
        histogram: dict[str, int] = {}

        for rec in ctx.inventory:
            if rec.kind is not FileKind.ELF:
                continue
            info = parse_file(ctx.inventory.abspath(rec), rec.size)
            if info is None:
                continue
            found = info.imported_functions & DANGEROUS.keys()
            if not found:
                continue
            exposed = is_network_facing(rec.path, info.imported_functions)
            flagged = {f for f in found if f not in CONTEXT_ONLY or exposed}
            for f in found:
                histogram[f] = histogram.get(f, 0) + 1
            if not flagged:
                continue

            worst = max((DANGEROUS[f][0] for f in flagged), key=lambda s: s.rank)
            # command-exec functions keep their severity; raw string functions
            # only reach MEDIUM, and only in network-facing binaries.
            if worst.rank <= Severity.LOW.rank and exposed:
                sev = Severity.MEDIUM
            else:
                sev = worst
            details = ", ".join(f"{f} ({DANGEROUS[f][1]})" for f in sorted(flagged, key=lambda f: -DANGEROUS[f][0].rank))
            result.findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"Dangerous functions in {os.path.basename(rec.path)}: {', '.join(sorted(flagged))}",
                    severity=sev,
                    confidence="medium" if not any(DANGEROUS[f][0].rank >= Severity.HIGH.rank for f in flagged) else "high",
                    path=rec.path,
                    description=f"{'Network-facing binary' if exposed else 'Binary'} imports: {details}.",
                    metadata={"functions": sorted(flagged), "network_facing": exposed},
                )
            )

        result.artifacts = {"function_histogram": dict(sorted(histogram.items(), key=lambda kv: -kv[1]))}
        return result
