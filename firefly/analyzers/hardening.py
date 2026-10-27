"""Exploit-mitigation audit of ELF binaries (NX, PIE, RELRO, stack canary).

Missing mitigations don't prove a bug, but they decide how easily a memory
bug becomes code execution. Firmware routinely ships binaries built without
any of them. Findings are rated by how exposed the binary is: a network
daemon with no NX and no canary is worse than a one-shot setup helper.
"""

from __future__ import annotations

import os

from firefly.analyzers import Analyzer, AnalyzerResult, ScanContext
from firefly.elf import ET_DYN, parse_file
from firefly.models import FileKind, Finding, Severity

# Imported symbols that imply the binary speaks to the network directly.
NETWORK_SYMBOLS = frozenset({"accept", "accept4", "recv", "recvfrom", "recvmsg", "bind", "listen", "SSL_accept", "SSL_read"})
# Daemon name hints, for when a binary is stripped of dynamic symbols. These
# are specific service names, never a whole directory like /sbin.
NETWORK_PATH_HINTS = ("httpd", "telnetd", "upnpd", "miniupnpd", "dnsmasq", "dropbear", "sshd", "ftpd", "openvpn", "hostapd", "wpa_supplicant", "smbd", "lighttpd", "boa", "goahead", "radvd", "pppd", "igmpproxy")


def is_network_facing(rel_path: str, imports: set[str]) -> bool:
    if imports & NETWORK_SYMBOLS:
        return True
    low = rel_path.lower()
    return any(h in low for h in NETWORK_PATH_HINTS)


class HardeningAnalyzer(Analyzer):
    name = "hardening"
    description = "Exploit mitigations on ELF binaries (NX, PIE, RELRO, stack canary)"

    def run(self, ctx: ScanContext) -> AnalyzerResult:
        assert ctx.inventory is not None
        result = AnalyzerResult()
        counts = {"nx": 0, "pie": 0, "relro_full": 0, "canary": 0, "total": 0}
        # Binaries whose only weakness is the firmware's build defaults (missing
        # canary/full-RELRO/PIE but NX present, not network-facing) are counted,
        # not reported one by one — that is a toolchain setting, not 400 bugs.
        # NX-present binaries only weakened by the image's uniform build flags
        # are aggregated, not reported one by one. Full lists stay in metadata.
        exposed_weak: list[str] = []
        other_weak: list[str] = []

        for rec in ctx.inventory:
            if rec.kind is not FileKind.ELF:
                continue
            info = parse_file(ctx.inventory.abspath(rec), rec.size)
            if info is None:
                continue
            counts["total"] += 1
            is_lib = info.etype == ET_DYN and info.interp is None
            # A library's network exposure depends on its callers, so only an
            # executable is treated as "the network-facing thing" here.
            exposed = not is_lib and is_network_facing(rec.path, info.imported_functions)

            missing = []
            if not info.nx:
                missing.append("NX")
            if not is_lib and not info.pie:
                missing.append("PIE")
            if info.relro != "full":
                missing.append("partial RELRO" if info.relro == "partial" else "no RELRO")
            if not info.has_stack_canary:
                missing.append("no stack canary")

            counts["nx"] += info.nx
            counts["pie"] += info.pie or is_lib
            counts["relro_full"] += info.relro == "full"
            counts["canary"] += info.has_stack_canary

            # Missing NX is the one weakness worth a finding of its own: it is
            # almost always directly exploitable and is rare, so never aggregated.
            if not info.nx:
                result.findings.append(
                    Finding(
                        analyzer=self.name,
                        title=f"Executable stack / no NX in {os.path.basename(rec.path)}",
                        severity=Severity.HIGH if exposed else Severity.MEDIUM,
                        confidence="high",
                        path=rec.path,
                        description=(
                            f"{'Network-facing binary' if exposed else 'Binary'} has a writable-executable stack "
                            f"(no NX); also missing {', '.join(m for m in missing if m != 'NX')}. A stack overflow "
                            f"here can run injected code directly."
                        ),
                        metadata={"nx": False, "pie": info.pie, "relro": info.relro, "stack_canary": info.has_stack_canary, "network_facing": exposed},
                    )
                )
            elif missing:
                (exposed_weak if exposed else other_weak).append(rec.path)

        rebuild = "Rebuild with -fstack-protector-strong and -Wl,-z,relro,-z,now (and -fPIE -pie for executables)."
        if exposed_weak:
            result.findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{len(exposed_weak)} network-facing executables lack PIE / stack canary / full RELRO",
                    severity=Severity.MEDIUM,
                    confidence="high",
                    description=(
                        f"{len(exposed_weak)} executables that use sockets were built without the full set of "
                        f"exploit mitigations, so a memory bug in any of them is easier to exploit. {rebuild} "
                        f"See metadata for the list."
                    ),
                    metadata={"count": len(exposed_weak), "binaries": sorted(exposed_weak)},
                )
            )
        if other_weak:
            result.findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{len(other_weak)} other binaries lack a stack canary / full RELRO (build defaults)",
                    severity=Severity.LOW,
                    confidence="high",
                    description=(
                        f"{len(other_weak)} of {counts['total']} binaries have NX but were built without a stack "
                        f"canary and/or full RELRO — a toolchain default across the image. {rebuild} Only "
                        f"{counts['canary']} binaries have a stack canary and {counts['relro_full']} have full RELRO."
                    ),
                    metadata={"count": len(other_weak), "total_binaries": counts["total"]},
                )
            )

        result.artifacts = {
            "network_facing_weak": len(exposed_weak),
            "build_default_weak": len(other_weak),
            "binaries": counts["total"],
            "nx": counts["nx"],
            "pie_or_lib": counts["pie"],
            "full_relro": counts["relro_full"],
            "stack_canary": counts["canary"],
        }
        return result
