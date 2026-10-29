"""Phase C2: runtime authentication testing (confirm) — the differentiator.

Static analysis *suspects*: the ``accounts`` analyzer finds an empty-password
account, the ``services`` analyzer finds telnet/ftp/weak-ssh enabled. This stage
*confirms* by actually logging in to the booted device over its forwarded
localhost ports, then upgrades the related static finding from "suspected" to
"confirmed" — positive signal only, exactly like ``--deep-reachability``.

This is **confirmation of a tiny, known set**, not brute force and not cracking:

* candidates are only (a) empty-password accounts the static scan already found
  and (b) a small curated list of *public* default credentials (``admin/admin``
  …). Nothing here is derived from a captured hash — we never crack.
* a hard global cap (:attr:`AuthOptions.max_attempts`) bounds the total tries, so
  it can never slide into brute force.
* every connection is to a ``127.0.0.1`` slirp forward of the sandboxed guest,
  never the real network.

Clients are stdlib only (``socket`` for telnet, ``ftplib`` for FTP, ``http.client``
for HTTP Basic). SSH password auth shells out to a present ``sshpass`` + ``ssh``
client (argv list, never a shell string) and is skipped when they are absent — no
``paramiko`` dependency.
"""

from __future__ import annotations

import base64
import ftplib
import http.client
import logging
import shutil
import socket
import ssl
import subprocess
import time
from dataclasses import dataclass, field
from typing import Any, Callable

from firefly.models import Finding, Severity

log = logging.getLogger(__name__)

# A small, curated list of *public* default credentials seen on consumer
# firmware. This is a known set to confirm, deliberately short — not a wordlist.
DEFAULT_CREDS: tuple[tuple[str, str], ...] = (
    ("admin", "admin"),
    ("admin", "password"),
    ("admin", ""),
    ("admin", "1234"),
    ("root", "root"),
    ("root", ""),
    ("root", "admin"),
    ("root", "password"),
    ("user", "user"),
    ("guest", "guest"),
    ("support", "support"),
)

_HTTPS_SERVICES = frozenset({"https", "https-alt"})
_HTTP_SERVICES = frozenset({"http", "https", "http-alt", "https-alt", "http-admin"})
_SHELL_SERVICES = frozenset({"telnet", "ssh"})
_AUTH_SERVICES = frozenset({"telnet", "ftp", "ssh"}) | _HTTP_SERVICES


@dataclass
class Credential:
    username: str
    password: str
    source: str  # "empty-account" (from the static scan) or "default-list"


@dataclass
class AuthOptions:
    max_attempts: int = 16        # hard global cap across all services (anti-brute-force)
    connect_timeout_s: float = 4.0
    io_timeout_s: float = 4.0
    allow_ssh: bool = True        # shell out to sshpass+ssh when available
    max_candidates: int = 16


@dataclass
class AuthResult:
    confirmations: list[dict[str, Any]] = field(default_factory=list)
    attempts: int = 0
    skipped: list[str] = field(default_factory=list)

    def to_artifact(self) -> dict[str, Any]:
        return {
            "attempts": self.attempts,
            "confirmed": [
                {
                    "service": c["service"],
                    "port": c["port"],
                    "username": c["username"],
                    "password": c["password"],
                    "source": c["source"],
                }
                for c in self.confirmations
            ],
            "skipped": self.skipped,
        }

    def to_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for c in self.confirmations:
            service, port = c["service"], c["port"]
            shell = service in _SHELL_SERVICES
            cred = f"{c['username']}:{c['password'] or '<empty>'}"
            how = (
                "an empty-password account the static scan flagged"
                if c["source"] == "empty-account"
                else "a known default credential"
            )
            findings.append(
                Finding(
                    analyzer="auth",
                    title=f"Confirmed working credential on the live device: {service} (port {port})",
                    severity=Severity.CRITICAL if shell else Severity.HIGH,
                    confidence="high",
                    evidence=f"{cred} authenticated over {service}",
                    description=(
                        f"Dynamic auth testing logged in to the running device on port {port} "
                        f"({service}) using {how} ({cred}). This is a confirmed working login, not a "
                        "suspicion"
                        + (" — it yields an interactive shell." if shell else ".")
                    ),
                    metadata={
                        "service": service,
                        "port": port,
                        "username": c["username"],
                        "source": c["source"],
                        "confirmed_login": True,
                    },
                )
            )
        return findings


# --------------------------------------------------------------------------- candidates


def build_candidates(static_findings: list[Finding], opts: AuthOptions | None = None) -> list[Credential]:
    """Assemble the credentials to confirm: empty-password accounts the static
    scan already found, then the curated public-default list. De-duplicated,
    order-preserving, and capped by ``max_candidates``."""
    opts = opts or AuthOptions()
    creds: list[Credential] = []
    seen: set[tuple[str, str]] = set()

    def add(user: str, pw: str, source: str) -> None:
        key = (user, pw)
        if key not in seen:
            seen.add(key)
            creds.append(Credential(user, pw, source))

    for f in static_findings:
        if f.analyzer == "accounts" and "empty password" in f.title.lower():
            account = f.metadata.get("account")
            if account:
                add(account, "", "empty-account")
    for user, pw in DEFAULT_CREDS:
        add(user, pw, "default-list")
    return creds[: opts.max_candidates]


# --------------------------------------------------------------------------- telnet


def _strip_iac(data: bytes) -> bytes:
    """Drop telnet IAC negotiation so marker matching sees plain text."""
    out = bytearray()
    i = 0
    while i < len(data):
        b = data[i]
        if b == 0xFF:
            nxt = data[i + 1] if i + 1 < len(data) else 0
            if nxt == 0xFF:  # escaped 0xFF
                out.append(0xFF)
                i += 2
            elif nxt in (0xFB, 0xFC, 0xFD, 0xFE):  # WILL/WONT/DO/DONT + option byte
                i += 3
            else:
                i += 2
            continue
        out.append(b)
        i += 1
    return bytes(out)


def _tn_read_until(s: socket.socket, markers: tuple[str, ...], opts: AuthOptions) -> str:
    buf = b""
    deadline = time.monotonic() + opts.io_timeout_s
    while time.monotonic() < deadline:
        try:
            chunk = s.recv(2048)
        except (socket.timeout, OSError):
            break
        if not chunk:
            break
        buf += chunk
        text = _strip_iac(buf).decode("latin-1", "replace")
        if any(m in text.lower() for m in markers):
            return text
    return _strip_iac(buf).decode("latin-1", "replace")


def try_telnet(host: str, port: int, cred: Credential, opts: AuthOptions) -> bool:
    """Confirm a telnet login: wait for the login/password prompts, send the
    credential, and decide success from what comes back (a shell prompt, not a
    re-prompt or an "incorrect" message)."""
    try:
        s = socket.create_connection((host, port), timeout=opts.connect_timeout_s)
    except OSError:
        return False
    try:
        s.settimeout(opts.io_timeout_s)
        _tn_read_until(s, ("login:", "username:"), opts)
        s.sendall((cred.username + "\r\n").encode("latin-1", "replace"))
        _tn_read_until(s, ("password:", "assword"), opts)
        s.sendall((cred.password + "\r\n").encode("latin-1", "replace"))
        resp = _tn_read_until(s, ("#", "$", "incorrect", "failed", "denied"), opts)
        low = resp.lower()
        if any(bad in low for bad in ("incorrect", "failed", "denied", "login:")):
            return False
        return ("#" in resp or "$" in resp or "busybox" in low or "last login" in low)
    except OSError:
        return False
    finally:
        s.close()


# --------------------------------------------------------------------------- ftp


def try_ftp(host: str, port: int, cred: Credential, opts: AuthOptions) -> bool:
    """Confirm an FTP login via stdlib ``ftplib`` (USER/PASS -> 230)."""
    ftp = ftplib.FTP(timeout=opts.io_timeout_s)
    try:
        ftp.connect(host, port, timeout=opts.io_timeout_s)
        ftp.login(cred.username, cred.password)  # raises error_perm on 530
        return True
    except (ftplib.all_errors) as exc:  # type: ignore[attr-defined]
        log.debug("ftp login %s failed: %s", cred.username, exc)
        return False
    finally:
        try:
            ftp.close()
        except OSError:
            pass


# --------------------------------------------------------------------------- http basic


def _http_status(host: str, port: int, scheme: str, path: str, auth_token: str | None, opts: AuthOptions) -> int | None:
    if scheme == "https":
        conn: http.client.HTTPConnection = http.client.HTTPSConnection(
            host, port, timeout=opts.io_timeout_s, context=ssl._create_unverified_context()
        )
    else:
        conn = http.client.HTTPConnection(host, port, timeout=opts.io_timeout_s)
    headers = {"User-Agent": "firefly-auth/1.0", "Connection": "close"}
    if auth_token:
        headers["Authorization"] = "Basic " + auth_token
    try:
        conn.request("GET", path, headers=headers)
        resp = conn.getresponse()
        resp.read(1024)
        return resp.status
    except (http.client.HTTPException, OSError, ValueError) as exc:
        log.debug("http %s%s failed: %s", host, path, exc)
        return None
    finally:
        try:
            conn.close()
        except OSError:
            pass


def try_http_basic(host: str, port: int, service: str, cred: Credential, opts: AuthOptions, path: str = "/") -> bool:
    """Confirm HTTP Basic auth: only when the server actually challenges with 401
    does a 2xx/3xx *with* the credential count as a confirmed login."""
    scheme = "https" if service in _HTTPS_SERVICES else "http"
    noauth = _http_status(host, port, scheme, path, None, opts)
    if noauth != 401:  # no Basic challenge here -> nothing to confirm
        return False
    token = base64.b64encode(f"{cred.username}:{cred.password}".encode("latin-1", "replace")).decode("ascii")
    authed = _http_status(host, port, scheme, path, token, opts)
    return authed is not None and 200 <= authed < 400


# --------------------------------------------------------------------------- ssh (shell-out)


def ssh_client() -> str | None:
    return shutil.which("ssh") or shutil.which("dbclient")


def ssh_available(opts: AuthOptions) -> bool:
    return bool(opts.allow_ssh and shutil.which("sshpass") and ssh_client())


def _ssh_argv(host: str, port: int, cred: Credential) -> list[str]:
    """Argv for a single scripted password login (no shell string is ever built)."""
    return [
        "sshpass", "-p", cred.password,
        ssh_client() or "ssh", "-p", str(port),
        "-o", "StrictHostKeyChecking=no",
        "-o", "UserKnownHostsFile=/dev/null",
        "-o", "PreferredAuthentications=password",
        "-o", "PubkeyAuthentication=no",
        "-o", "NumberOfPasswordPrompts=1",
        "-o", "ConnectTimeout=4",
        f"{cred.username}@{host}",
        "echo", "FIREFLY_SSH_OK",
    ]


def try_ssh(host: str, port: int, cred: Credential, opts: AuthOptions) -> bool:
    if not ssh_available(opts):
        return False
    try:
        proc = subprocess.run(
            _ssh_argv(host, port, cred),
            capture_output=True, text=True, timeout=opts.io_timeout_s + opts.connect_timeout_s, check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.debug("ssh login %s failed: %s", cred.username, exc)
        return False
    return "FIREFLY_SSH_OK" in proc.stdout


# --------------------------------------------------------------------------- orchestration


def _client_for(service: str) -> Callable[[str, int, str, Credential, AuthOptions], bool] | None:
    if service == "telnet":
        return lambda h, p, s, c, o: try_telnet(h, p, c, o)
    if service == "ftp":
        return lambda h, p, s, c, o: try_ftp(h, p, c, o)
    if service == "ssh":
        return lambda h, p, s, c, o: try_ssh(h, p, c, o)
    if service in _HTTP_SERVICES:
        return lambda h, p, s, c, o: try_http_basic(h, p, s, c, o)
    return None


def run_auth(target: Any, open_ports: list[int], services: dict[int, str], static_findings: list[Finding], opts: AuthOptions | None = None) -> AuthResult:
    """Confirm candidate credentials against each authenticable open port.

    ``target`` only needs ``host_port(guest_port) -> int`` (a stub suffices in
    tests). Stops at the global ``max_attempts`` cap; one confirmed credential
    per service is enough (we are confirming reachability, not enumerating)."""
    opts = opts or AuthOptions()
    res = AuthResult()
    candidates = build_candidates(static_findings, opts)
    if not candidates:
        return res

    for port in open_ports:
        service = services.get(port, "unknown")
        if service not in _AUTH_SERVICES:
            continue
        client = _client_for(service)
        if client is None:
            continue
        if service == "ssh" and not ssh_available(opts):
            res.skipped.append(f"ssh/{port}: no sshpass+ssh client available")
            continue
        host, hp = "127.0.0.1", target.host_port(port)
        for cred in candidates:
            if res.attempts >= opts.max_attempts:
                break
            res.attempts += 1
            try:
                ok = client(host, hp, service, cred, opts)
            except Exception:  # a hostile service must never abort the stage
                log.debug("auth attempt crashed on %s/%s", service, port, exc_info=True)
                ok = False
            if ok:
                res.confirmations.append(
                    {
                        "service": service,
                        "port": port,
                        "username": cred.username,
                        "password": cred.password,
                        "source": cred.source,
                    }
                )
                break  # one working credential per service is sufficient
    return res


# --------------------------------------------------------------------------- finding upgrade


def _raise_to(f: Finding, target: Severity) -> None:
    if target.rank > f.severity.rank:
        f.severity = target


def _matches(f: Finding, service: str, username: str) -> bool:
    if f.analyzer == "accounts":
        return f.metadata.get("account") == username
    if f.analyzer == "services":
        t = f.title.lower()
        if service == "telnet":
            return "telnet" in t
        if service == "ftp":
            return "ftp" in t
        if service == "ssh":
            return "ssh" in t or "dropbear" in t
    return False


def upgrade_static_findings(findings: list[Finding], confirmations: list[dict[str, Any]]) -> int:
    """Positive-signal upgrade: a confirmed login raises the matching static
    finding(s) to CRITICAL/high-confidence and annotates them. Never lowers a
    severity and never removes a finding."""
    upgraded = 0
    for c in confirmations:
        service, username = c["service"], c["username"]
        cred = f"{username}:{c['password'] or '<empty>'}"
        note = f" Confirmed on the live device: {cred} logs in over {service}."
        for f in findings:
            if not _matches(f, service, username):
                continue
            _raise_to(f, Severity.CRITICAL)
            f.confidence = "high"
            if note not in f.description:
                f.description += note
            f.metadata["confirmed_login"] = True
            upgraded += 1
    return upgraded
