import io
import os
import tarfile

import pytest

from firefly.analyzers import ScanContext
from firefly.analyzers.accounts import AccountsAnalyzer, classify_hash
from firefly.analyzers.credentials import CredentialsAnalyzer
from firefly.analyzers.dangerfns import DangerousFunctionsAnalyzer
from firefly.analyzers.hardening import HardeningAnalyzer, is_network_facing
from firefly.analyzers.services import ServicesAnalyzer
from firefly.inventory import Inventory
from firefly.models import Severity
from firefly.secrets import redact, scan_bytes

from elfbuild import ET_DYN, build_elf


def _tree(tmp_path, files: dict[str, bytes]) -> Inventory:
    root = tmp_path / "root"
    for rel, data in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(data)
    return Inventory.build(str(root))


def _ctx(inv):
    return ScanContext(firmware_path="x", workdir="x", jobs=1, inventory=inv)


# --------------------------------------------------------------------------- hardening


def test_network_facing_detection():
    assert is_network_facing("usr/sbin/foo", {"accept"})
    assert is_network_facing("usr/sbin/telnetd", set())
    assert not is_network_facing("bin/ls", {"strcpy"})


def test_hardening_flags_network_daemon_without_nx(tmp_path):
    inv = _tree(
        tmp_path,
        {
            "usr/sbin/httpd": build_elf(nx=False, imports=["accept", "recv"]),
            "bin/ls": build_elf(nx=True, relro="full", pie_flag=True, etype=ET_DYN, interp="/lib/ld.so", canary=True),
        },
    )
    findings = HardeningAnalyzer().run(_ctx(inv)).findings
    httpd = [f for f in findings if "httpd" in f.path]
    assert httpd and httpd[0].severity is Severity.HIGH and "NX" in httpd[0].title
    assert not any("ls" in f.path for f in findings)  # fully hardened → no finding


def test_hardening_aggregates_build_default_weakness(tmp_path):
    # NX present but no canary/RELRO: one network-facing exe, one plain exe.
    inv = _tree(
        tmp_path,
        {
            "usr/sbin/netd": build_elf(nx=True, relro="partial", imports=["accept"]),
            "bin/helper": build_elf(nx=True, relro="partial"),
        },
    )
    findings = HardeningAnalyzer().run(_ctx(inv)).findings
    # aggregated into two summaries, not per-binary
    assert len(findings) == 2
    exposed = next(f for f in findings if f.severity is Severity.MEDIUM)
    assert "network-facing" in exposed.title and "usr/sbin/netd" in exposed.metadata["binaries"]
    assert any(f.severity is Severity.LOW for f in findings)


def test_hardening_library_not_flagged_for_pie(tmp_path):
    inv = _tree(tmp_path, {"lib/libc.so.6": build_elf(etype=ET_DYN, nx=True, relro="full", soname="libc.so.6")})
    findings = HardeningAnalyzer().run(_ctx(inv)).findings
    assert all("PIE" not in f.title for f in findings)


# --------------------------------------------------------------------------- dangerous functions


def test_dangerfns_command_exec_is_high(tmp_path):
    inv = _tree(tmp_path, {"usr/sbin/cgi": build_elf(nx=True, imports=["system", "strcpy"])})
    findings = DangerousFunctionsAnalyzer().run(_ctx(inv)).findings
    assert findings and findings[0].severity is Severity.HIGH and "system" in findings[0].title


def test_dangerfns_string_funcs_only_flagged_in_network_binaries(tmp_path):
    inv = _tree(
        tmp_path,
        {
            "bin/util": build_elf(nx=True, imports=["strcpy", "sprintf"]),  # not network-facing
            "usr/sbin/netd": build_elf(nx=True, imports=["strcpy", "recv"]),  # network-facing
        },
    )
    findings = {os.path.basename(f.path): f for f in DangerousFunctionsAnalyzer().run(_ctx(inv)).findings}
    assert "util" not in findings  # strcpy alone in a non-network binary is suppressed
    assert "netd" in findings and findings["netd"].severity is Severity.MEDIUM


# --------------------------------------------------------------------------- secrets / credentials


def test_redact_never_reveals():
    assert redact("short") == "*****"
    assert redact("supersecretvalue") == "su**************"
    assert "secret" not in redact("mysecretpassword")[2:]


def test_scan_bytes_redacts_private_key():
    pem = b"-----BEGIN RSA PRIVATE KEY-----\n" + b"MIIBOgIBAAJ" * 20 + b"\n-----END RSA PRIVATE KEY-----\n"
    hits = scan_bytes(pem)
    assert len(hits) == 1 and hits[0].kind == "private_key"
    assert "MIIB" not in hits[0].preview and "PRIVATE KEY" in hits[0].preview


def test_scan_bytes_finds_tokens_and_passwords():
    data = b"AWS_KEY=AKIAIOSFODNN7EXAMPLE\npassword = Sup3rS3cr3tP@ss\nhost = localhost\n"
    kinds = {h.subtype: h for h in scan_bytes(data)}
    assert any(h.kind == "api_token" for h in kinds.values())
    pw = next(h for h in kinds.values() if h.kind == "password")
    assert "Sup3r" not in pw.preview[len(pw.subtype) + 3:]  # value redacted


def test_scan_bytes_ignores_placeholders():
    data = b"password = changeme\nsecret = <your-secret>\ntoken = ${TOKEN}\npassword=x\n"
    assert [h for h in scan_bytes(data) if h.kind == "password"] == []


def test_credentials_analyzer_redacts_in_findings(tmp_path):
    inv = _tree(
        tmp_path,
        {
            "etc/config": b"admin_password = R3alP@ssw0rd123\n",
            "etc/ssl/private/server.key": b"-----BEGIN EC PRIVATE KEY-----\n" + b"abcd" * 30 + b"\n-----END EC PRIVATE KEY-----\n",
        },
    )
    findings = CredentialsAnalyzer().run(_ctx(inv)).findings
    assert any(f.metadata["kind"] == "private_key" and f.severity is Severity.CRITICAL for f in findings)
    pw = next(f for f in findings if f.metadata["kind"] == "password")
    blob = pw.title + pw.description + (pw.evidence or "")
    assert "R3alP@ssw0rd123" not in blob and "R3" in (pw.evidence or "")


# --------------------------------------------------------------------------- accounts


@pytest.mark.parametrize(
    "field, expected",
    [
        ("$1$abc$def", ("MD5", True)),
        ("$6$salt$hash", ("SHA-512", False)),
        ("$y$j9T$xyz", ("yescrypt", False)),
        ("AbCdEfGhIjKlM", ("DES (legacy)", True)),  # 13-char DES crypt
        ("*", None),
        ("!", None),
        ("", None),
    ],
)
def test_classify_hash(field, expected):
    assert classify_hash(field) == expected


def test_accounts_flags_empty_password_and_uid0(tmp_path):
    passwd = b"root:x:0:0:root:/root:/bin/sh\nbackdoor:x:0:0::/root:/bin/sh\nguest::1000:1000::/home/guest:/bin/sh\n"
    shadow = b"root:$1$abc$weakmd5hash:19000:0:99999:7:::\nguest::19000:0:99999:7:::\n"
    inv = _tree(tmp_path, {"etc/passwd": passwd, "etc/shadow": shadow})
    findings = AccountsAnalyzer().run(_ctx(inv)).findings
    titles = " ".join(f.title for f in findings)
    assert "UID 0" in titles and "backdoor" in titles
    assert any("empty password" in f.title and f.severity is Severity.CRITICAL for f in findings)
    assert any("weak password hash (MD5)" in f.title for f in findings)
    # no hash value leaks into any finding
    assert all("weakmd5hash" not in (f.description or "") for f in findings)


# --------------------------------------------------------------------------- services


def test_services_flags_telnet_and_weak_ssh(tmp_path):
    inv = _tree(
        tmp_path,
        {
            "etc/inittab": b"::sysinit:/etc/init.d/rcS\n::respawn:/usr/sbin/telnetd -l /bin/sh\n",
            "etc/ssh/sshd_config": b"PermitRootLogin yes\nPermitEmptyPasswords yes\n",
            "etc/init.d/rcS": b"#!/bin/sh\n/usr/sbin/httpd\n",
        },
    )
    findings = ServicesAnalyzer().run(_ctx(inv)).findings
    titles = [f.title for f in findings]
    assert any("Telnet" in t for t in titles)
    assert any("empty passwords" in t for t in titles)
    assert any(f.severity is Severity.HIGH for f in findings)


def test_services_ignores_comments(tmp_path):
    inv = _tree(tmp_path, {"etc/init.d/x": b"#!/bin/sh\n# telnetd is disabled here\n"})
    assert ServicesAnalyzer().run(_ctx(inv)).findings == []
