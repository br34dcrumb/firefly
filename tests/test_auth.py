"""Tests for Phase C2 runtime auth testing (firefly/emulation/auth.py).

No qemu and no LiveTarget: the protocol clients talk to throwaway stdlib stub
servers (a line-based telnet, a minimal FTP for ftplib, an HTTP Basic endpoint)
on 127.0.0.1, and SSH is exercised only through its argv builder and its
"skipped when absent" path. They pass on any OS.
"""

from __future__ import annotations

import base64
import socketserver
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from firefly.emulation import auth
from firefly.emulation.auth import (
    AuthOptions,
    AuthResult,
    Credential,
    build_candidates,
    run_auth,
    try_telnet,
    try_ftp,
    try_http_basic,
    try_ssh,
    _ssh_argv,
    upgrade_static_findings,
)
from firefly.models import Finding, Severity

# --------------------------------------------------------------------------- stub servers


class _TelnetHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"\r\nmydev login: ")
        self.wfile.flush()
        user = self.rfile.readline().strip().decode("latin-1")
        self.wfile.write(b"Password: ")
        self.wfile.flush()
        pw = self.rfile.readline().strip().decode("latin-1")
        if (user, pw) == self.server.ok:  # type: ignore[attr-defined]
            self.wfile.write(b"\r\nBusyBox v1.31\r\n# ")
        else:
            self.wfile.write(b"\r\nLogin incorrect\r\nmydev login: ")
        self.wfile.flush()


class _FtpHandler(socketserver.StreamRequestHandler):
    def handle(self):
        self.wfile.write(b"220 stub FTP ready\r\n")
        self.wfile.flush()
        user = ""
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd = line.strip().decode("latin-1")
            up = cmd.upper()
            if up.startswith("USER"):
                user = cmd[5:].strip()
                self.wfile.write(b"331 need password\r\n")
            elif up.startswith("PASS"):
                pw = cmd[5:].strip()
                self.wfile.write(b"230 logged in\r\n" if (user, pw) == self.server.ok else b"530 nope\r\n")  # type: ignore[attr-defined]
            elif up.startswith("QUIT"):
                self.wfile.write(b"221 bye\r\n")
                self.wfile.flush()
                return
            else:
                self.wfile.write(b"200 ok\r\n")
            self.wfile.flush()


def _start_tcp(handler, ok):
    srv = socketserver.ThreadingTCPServer(("127.0.0.1", 0), handler)
    srv.ok = ok  # read by the handler
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, t


@pytest.fixture
def telnet_server():
    srv, t = _start_tcp(_TelnetHandler, ("root", ""))
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        t.join(timeout=2.0)


@pytest.fixture
def ftp_server():
    srv, t = _start_tcp(_FtpHandler, ("admin", "admin"))
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        t.join(timeout=2.0)


class _BasicHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def do_GET(self):
        want = "Basic " + base64.b64encode(b"admin:admin").decode()
        if self.headers.get("Authorization") == want:
            body = b"welcome"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(401)
            self.send_header("WWW-Authenticate", 'Basic realm="dev"')
            self.send_header("Content-Length", "0")
            self.end_headers()


@pytest.fixture
def http_basic_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _BasicHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv.server_address[1]
    finally:
        srv.shutdown()
        t.join(timeout=2.0)


_OPTS = AuthOptions(io_timeout_s=2.0, connect_timeout_s=2.0)


# --------------------------------------------------------------------------- per-protocol


def test_try_telnet_confirms_and_rejects(telnet_server):
    assert try_telnet("127.0.0.1", telnet_server, Credential("root", "", "x"), _OPTS) is True
    assert try_telnet("127.0.0.1", telnet_server, Credential("root", "wrong", "x"), _OPTS) is False


def test_try_telnet_unreachable_is_false():
    assert try_telnet("127.0.0.1", 1, Credential("root", "", "x"), _OPTS) is False


def test_try_ftp_confirms_and_rejects(ftp_server):
    assert try_ftp("127.0.0.1", ftp_server, Credential("admin", "admin", "x"), _OPTS) is True
    assert try_ftp("127.0.0.1", ftp_server, Credential("admin", "nope", "x"), _OPTS) is False


def test_try_http_basic_requires_a_401_challenge(http_basic_server):
    assert try_http_basic("127.0.0.1", http_basic_server, "http", Credential("admin", "admin", "x"), _OPTS) is True
    assert try_http_basic("127.0.0.1", http_basic_server, "http", Credential("admin", "bad", "x"), _OPTS) is False


# --------------------------------------------------------------------------- ssh (no real login)


def test_ssh_argv_is_a_safe_argv_list():
    argv = _ssh_argv("127.0.0.1", 45022, Credential("root", "s3cret", "x"))
    assert argv[0] == "sshpass" and "s3cret" in argv  # password passed as an arg, no shell
    assert "PubkeyAuthentication=no" in argv and "root@127.0.0.1" in argv
    assert all(isinstance(a, str) for a in argv)  # argv list, never a shell string


def test_try_ssh_skips_when_client_absent(monkeypatch):
    monkeypatch.setattr(auth.shutil, "which", lambda name: None)
    assert try_ssh("127.0.0.1", 45022, Credential("root", "root", "x"), _OPTS) is False


def test_run_auth_records_skip_for_ssh_without_client(monkeypatch):
    monkeypatch.setattr(auth.shutil, "which", lambda name: None)
    target = _StubTarget({22: 45022})
    findings = [_empty_pw_finding("root")]
    res = run_auth(target, [22], {22: "ssh"}, findings, _OPTS)
    assert res.confirmations == []
    assert any("ssh/22" in s for s in res.skipped)


# --------------------------------------------------------------------------- candidates


def _empty_pw_finding(account: str) -> Finding:
    return Finding(
        analyzer="accounts",
        title=f"Account '{account}' has an empty password",
        severity=Severity.HIGH,
        metadata={"account": account},
    )


def test_build_candidates_prefers_static_empty_accounts_then_defaults():
    creds = build_candidates([_empty_pw_finding("admin")])
    assert creds[0] == Credential("admin", "", "empty-account")
    # ("admin","") also appears in the default list -> de-duped, keeps the first.
    assert sum(1 for c in creds if (c.username, c.password) == ("admin", "")) == 1
    assert any(c.source == "default-list" for c in creds)


def test_build_candidates_capped():
    creds = build_candidates([], AuthOptions(max_candidates=3))
    assert len(creds) == 3


# --------------------------------------------------------------------------- orchestration


class _StubTarget:
    def __init__(self, mapping):
        self._m = mapping

    def host_port(self, guest_port):
        return self._m[guest_port]


def test_run_auth_confirms_telnet_and_ftp(telnet_server, ftp_server):
    target = _StubTarget({23: telnet_server, 21: ftp_server})
    services = {23: "telnet", 21: "ftp"}
    findings = [_empty_pw_finding("root")]  # makes ("root","") the first candidate
    res = run_auth(target, [23, 21], services, findings, _OPTS)
    got = {(c["service"], c["username"]) for c in res.confirmations}
    assert ("telnet", "root") in got  # empty-password account confirmed
    assert ("ftp", "admin") in got    # default admin/admin confirmed


def test_run_auth_respects_attempt_cap(telnet_server):
    # Telnet server only accepts root/"", but we cap at 1 attempt with a
    # candidate list whose first entry is wrong -> no confirmation, 1 attempt.
    target = _StubTarget({23: telnet_server})
    res = run_auth(target, [23], {23: "telnet"}, [], AuthOptions(max_attempts=1, io_timeout_s=2.0, connect_timeout_s=2.0))
    assert res.attempts == 1 and res.confirmations == []


def test_run_auth_skips_non_auth_services(telnet_server):
    target = _StubTarget({23: telnet_server, 53: 9})
    res = run_auth(target, [23, 53], {23: "telnet", 53: "dns"}, [_empty_pw_finding("root")], _OPTS)
    assert all(c["service"] != "dns" for c in res.confirmations)


# --------------------------------------------------------------------------- upgrade + output


def test_upgrade_static_findings_is_positive_signal_only():
    acct = _empty_pw_finding("root")
    svc = Finding("services", "Telnet server started at boot (etc/inittab)", Severity.HIGH, confidence="high")
    unrelated = Finding("services", "FTP anonymous access enabled (etc/vsftpd.conf)", Severity.LOW)
    findings = [acct, svc, unrelated]
    n = upgrade_static_findings(findings, [{"service": "telnet", "port": 23, "username": "root", "password": "", "source": "empty-account"}])
    assert n == 2  # the account and the telnet service finding
    assert acct.severity is Severity.CRITICAL and acct.confidence == "high"
    assert acct.metadata["confirmed_login"] is True and "Confirmed" in acct.description
    assert svc.severity is Severity.CRITICAL
    assert unrelated.severity is Severity.LOW  # untouched, never lowered or raised


def test_auth_result_findings_and_artifact():
    res = AuthResult(
        confirmations=[{"service": "telnet", "port": 23, "username": "root", "password": "", "source": "empty-account"}],
        attempts=3,
        skipped=["ssh/22: no sshpass+ssh client available"],
    )
    f = res.to_findings()[0]
    assert f.analyzer == "auth" and f.severity is Severity.CRITICAL and f.confidence == "high"
    art = res.to_artifact()
    assert art["attempts"] == 3 and art["confirmed"][0]["service"] == "telnet"
    assert art["skipped"]
