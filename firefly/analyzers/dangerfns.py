"""Flag use of memory-unsafe and command-execution C library functions.

Evidence is the dynamic symbol table (imported functions), not string
matching, so this is far less noisy than grepping for names: a binary that
imports ``system`` and ``strcpy`` genuinely calls them. The finding is a
prompt to review, not proof of a bug; severity reflects how dangerous the
function is and whether the binary is network-facing.
"""

from __future__ import annotations

import os

from firefly import disasm
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

_LEVELS = list(Severity)


def _bump(sev: Severity) -> Severity:
    """One severity rank higher, capped at CRITICAL."""
    return _LEVELS[min(sev.rank + 1, len(_LEVELS) - 1)]


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
            confidence = "high" if any(DANGEROUS[f][0].rank >= Severity.HIGH.rank for f in flagged) else "medium"
            details = ", ".join(f"{f} ({DANGEROUS[f][1]})" for f in sorted(flagged, key=lambda f: -DANGEROUS[f][0].rank))
            description = f"{'Network-facing binary' if exposed else 'Binary'} imports: {details}."
            metadata = {"functions": sorted(flagged), "network_facing": exposed}

            # Opt-in (radare2, heavy): does external input reach one of these
            # sinks through the call graph? This is call-graph reachability, not
            # data-flow taint — a found path is a candidate ("input can reach the
            # sink's caller"), never proof a tainted value flows there. Positive
            # signal only: a path raises severity/confidence and adds a note; a
            # missing path (or absent radare2) leaves the finding exactly as it
            # was. See disasm.input_reaches_sinks for the honest caveats.
            if ctx.deep_taint:
                graph = disasm.call_graph(ctx.inventory.abspath(rec))
                if graph:
                    reached = disasm.input_reaches_sinks(graph, set(flagged))
                    metadata["taint"] = {"input_reaches_sink": bool(reached), "sinks": reached}
                    if reached:
                        sev = _bump(sev)
                        confidence = "high"
                        description += (
                            f" External input can reach {', '.join(reached)} via the call graph "
                            "(call-graph reachability, not proven data-flow taint)."
                        )

            result.findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"Dangerous functions in {os.path.basename(rec.path)}: {', '.join(sorted(flagged))}",
                    severity=sev,
                    confidence=confidence,
                    path=rec.path,
                    description=description,
                    metadata=metadata,
                )
            )

        result.artifacts = {"function_histogram": dict(sorted(histogram.items(), key=lambda kv: -kv[1]))}
        return result
