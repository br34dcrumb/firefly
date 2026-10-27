"""Flag insecure services configured to start at boot.

Looks at init scripts, inittab and inetd/xinetd config for services that are
dangerous by default: cleartext remote shells (telnet, rsh), an unauthenticated
or unconfigured daemon, FTP that allows anonymous write, SSH that permits empty
passwords, and so on. Evidence is the config line itself.
"""

from __future__ import annotations

import os
import re

from firefly.analyzers import Analyzer, AnalyzerResult, ScanContext
from firefly.models import FileKind, Finding, Severity

# A path segment that marks a boot-time script location, matched at any depth
# so overlays like rom/etc/init.d are covered too.
STARTUP_DIR_SEGMENTS = ("init.d", "rc.d", "xinetd.d", "init", "systemd", "rc0.d", "rc1.d", "rc2.d", "rc3.d", "rcS.d")
STARTUP_BASENAMES = ("inittab", "rcs", "rc.local", "rc", "inetd.conf", "rc.conf", "services.sh")
# service config files recognised by basename, wherever they live
CONFIG_BASENAMES = ("sshd_config", "vsftpd.conf", "proftpd.conf", "dropbear.conf", "telnetd.conf")
# Insecure service *binaries*: their mere presence in the image is worth noting.
INSECURE_BINARIES = {
    "telnetd": (Severity.MEDIUM, "A telnet server binary is present; telnet is cleartext."),
    "utelnetd": (Severity.MEDIUM, "A telnet server binary is present; telnet is cleartext."),
    "in.telnetd": (Severity.MEDIUM, "A telnet server binary is present; telnet is cleartext."),
    "rshd": (Severity.MEDIUM, "An rsh server binary is present; rsh is unauthenticated cleartext."),
    "rlogind": (Severity.MEDIUM, "An rlogin server binary is present; cleartext remote login."),
    "tftpd": (Severity.LOW, "A TFTP server binary is present; TFTP is unauthenticated."),
}

# (regex, severity, title, why) applied line by line to startup/config files.
RULES = [
    (re.compile(r"\b(telnetd|in\.telnetd|utelnetd)\b"), Severity.HIGH, "Telnet server started at boot", "Telnet sends credentials and sessions in cleartext."),
    (re.compile(r"\b(in\.rshd|rshd|rlogind|rexecd)\b"), Severity.HIGH, "r-services (rsh/rlogin) started", "The r-services are unauthenticated cleartext remote shells."),
    (re.compile(r"\btftpd\b.*-c|\btftpd\b.*--create"), Severity.MEDIUM, "TFTP server allows file creation", "Writable TFTP lets anyone upload files to the device."),
    (re.compile(r"PermitRootLogin\s+yes", re.I), Severity.MEDIUM, "SSH permits root login", "Direct root login over SSH widens the attack surface."),
    (re.compile(r"PermitEmptyPasswords\s+yes", re.I), Severity.HIGH, "SSH permits empty passwords", "Accounts with no password can log in over SSH."),
    (re.compile(r"anonymous_enable\s*=\s*YES", re.I), Severity.LOW, "FTP anonymous access enabled", "Anonymous FTP is enabled."),
    (re.compile(r"anon_upload_enable\s*=\s*YES", re.I), Severity.MEDIUM, "FTP anonymous upload enabled", "Anonymous users can write files over FTP."),
    (re.compile(r"\bdropbear\b.*\s-s\b"), Severity.LOW, "Dropbear password login enabled", "Dropbear started without disabling password auth."),
]
MAX_FILE = 512 * 1024


def _is_startup_file(path: str) -> bool:
    p = path.lower()
    segments = p.split("/")
    base = segments[-1]
    if base in CONFIG_BASENAMES or base in STARTUP_BASENAMES or base.endswith(".rc"):
        return True
    return any(seg in STARTUP_DIR_SEGMENTS for seg in segments[:-1])


class ServicesAnalyzer(Analyzer):
    name = "services"
    description = "Insecure services enabled at boot (telnet, rsh, anon FTP, weak SSH)"

    def run(self, ctx: ScanContext) -> AnalyzerResult:
        assert ctx.inventory is not None
        result = AnalyzerResult()
        checked = 0

        for rec in ctx.inventory:
            if rec.kind in (FileKind.SYMLINK, FileKind.OTHER) or rec.size > MAX_FILE:
                continue
            if not _is_startup_file(rec.path):
                continue
            try:
                with open(ctx.inventory.abspath(rec), "rb") as fh:
                    text = fh.read().decode("utf-8", "replace")
            except OSError:
                continue
            checked += 1
            seen: set[str] = set()
            for lineno, line in enumerate(text.splitlines(), 1):
                stripped = line.strip()
                if not stripped or stripped.startswith("#"):
                    continue
                for pattern, sev, title, why in RULES:
                    if title in seen:
                        continue
                    m = pattern.search(line)
                    if not m:
                        continue
                    seen.add(title)
                    result.findings.append(
                        Finding(
                            analyzer=self.name,
                            title=f"{title} ({rec.path})",
                            severity=sev,
                            confidence="high",
                            path=rec.path,
                            evidence=stripped[:160],
                            description=f"{why} Found in {rec.path}:{lineno}.",
                            metadata={"line": lineno, "match": m.group(0)},
                        )
                    )

        # The presence of an insecure-service binary is a weaker signal than a
        # boot config that launches it, but still worth reporting once each.
        seen_bin: set[str] = set()
        for rec in ctx.inventory:
            if rec.kind is FileKind.SYMLINK:
                continue
            base = os.path.basename(rec.path).lower()
            if base in INSECURE_BINARIES and base not in seen_bin:
                seen_bin.add(base)
                sev, why = INSECURE_BINARIES[base]
                result.findings.append(
                    Finding(
                        analyzer=self.name,
                        title=f"Insecure service binary present: {base}",
                        severity=sev,
                        confidence="medium",
                        path=rec.path,
                        description=f"{why} Confirm whether it is started at runtime (e.g. from NVRAM settings or a boot script).",
                        metadata={"binary": base},
                    )
                )

        result.artifacts = {"startup_files_checked": checked, "insecure_binaries": sorted(seen_bin)}
        return result
