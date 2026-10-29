"""Phase C1: live surface probe (crawl).

Given a booted :class:`~firefly.emulation.system.LiveTarget`, enumerate the real
attack surface behind each reachable HTTP-speaking port: fetch pages, follow
same-host links, read ``<form>``s, hit common firmware paths (``/cgi-bin/``,
``/goform/``, ``/HNAP1/``, ``/api/`` …), and pull UPnP device/service
descriptions (SCPD action names). The output is a surface map (artifact) plus
findings for notable surfaces — unauthenticated admin pages, HNAP, CGI, SOAP
control URLs — which later phases (C2 auth testing) turn from *surface* into
*confirmed*.

Everything here is bounded, because the service is firmware we do not trust:

* a hard cap on pages, crawl depth, wall-clock time and bytes read per response,
* same-host links only (never follow a redirect or ``href`` off the device),
* a per-request socket timeout, and
* XML parsing that refuses a DOCTYPE/ENTITY (no billion-laughs, no XXE).

Every request goes to a ``127.0.0.1`` slirp forward, never the real network, so
the offline invariant holds. stdlib only (``http.client`` / ``html.parser`` /
``xml.etree``) — no new dependencies.
"""

from __future__ import annotations

import http.client
import logging
import socket
import ssl
import time
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit, urljoin
from xml.etree import ElementTree

from firefly.models import Finding, Severity

log = logging.getLogger(__name__)

# Services (by COMMON_PORTS name) that speak HTTP over their forward and can be
# crawled. telnet/ftp/ssh/dns are left for the auth phase (C2); upnp and tr069
# (CWMP) both ride on HTTP, so they crawl like any web port.
_HTTPS_SERVICES = frozenset({"https", "https-alt"})
_CRAWLABLE = frozenset({"http", "https", "http-alt", "https-alt", "http-admin", "upnp", "tr069"})

# Seed paths tried on every HTTP service in addition to "/": the firmware
# endpoints that most often exist and matter. Bounded and static on purpose.
_SEED_PATHS = (
    "/",
    "/cgi-bin/",
    "/goform/",
    "/HNAP1/",
    "/api/",
    "/login",
    "/login.asp",
    "/index.asp",
    "/setup.cgi",
    "/admin",
    "/admin/",
    # Common UPnP/IGD device-description locations (parsed as SCPD when XML).
    "/rootDesc.xml",
    "/description.xml",
    "/igd.xml",
    "/gatedesc.xml",
    "/upnp/desc.xml",
)

# Paths whose mere reachability is notable, and how to describe them.
_HNAP = "/hnap1"
_CGI_PREFIXES = ("/cgi-bin/", "/goform/", "/hnap1", "/setup.cgi")
_ADMIN_HINTS = ("admin", "login", "setup", "password", "config", "management")

_UA = "firefly-surface-probe/1.0"


@dataclass
class SurfaceOptions:
    max_pages: int = 40          # total fetches across all paths of one service
    max_depth: int = 2           # how far link-following may descend from a seed
    wall_clock_s: float = 20.0   # ceiling on time spent crawling one service
    request_timeout_s: float = 4.0
    max_body: int = 256 * 1024   # bytes read from any one response
    max_forms: int = 24          # forms recorded per service
    max_actions: int = 64        # UPnP SCPD action names recorded per service


@dataclass
class Endpoint:
    path: str
    status: int
    content_type: str = ""
    title: str = ""
    forms: list[dict[str, Any]] = field(default_factory=list)
    note: str = ""  # a short tag, e.g. "HNAP", "CGI", "unauthenticated-admin"


@dataclass
class ServiceSurface:
    port: int
    service: str
    scheme: str
    endpoints: list[Endpoint] = field(default_factory=list)
    upnp_actions: list[str] = field(default_factory=list)
    error: str = ""  # set when the service could not be crawled at all


@dataclass
class SurfaceMap:
    services: list[ServiceSurface] = field(default_factory=list)

    def to_artifact(self) -> dict[str, Any]:
        return {
            "services": [
                {
                    "port": s.port,
                    "service": s.service,
                    "scheme": s.scheme,
                    "error": s.error,
                    "endpoints": [
                        {
                            "path": e.path,
                            "status": e.status,
                            "content_type": e.content_type,
                            "title": e.title,
                            "forms": e.forms,
                            "note": e.note,
                        }
                        for e in s.endpoints
                    ],
                    "upnp_actions": s.upnp_actions,
                }
                for s in self.services
            ]
        }

    def to_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for s in self.services:
            live = [e for e in s.endpoints if e.status and e.status < 400]
            if not live and not s.upnp_actions:
                continue
            findings.append(
                Finding(
                    analyzer="surface",
                    title=f"Live HTTP surface mapped on {s.service} (port {s.port})",
                    severity=Severity.INFO,
                    confidence="medium",
                    description=(
                        f"Crawling the running device on port {s.port} ({s.service}) reached "
                        f"{len(live)} endpoint(s). This is live attack surface for review and "
                        "for dynamic auth testing."
                    ),
                    metadata={
                        "port": s.port,
                        "service": s.service,
                        "endpoints": [e.path for e in live],
                    },
                )
            )
            findings.extend(self._notable(s, live))
        return findings

    def _notable(self, s: ServiceSurface, live: list[Endpoint]) -> list[Finding]:
        out: list[Finding] = []
        for e in live:
            if e.note == "HNAP":
                out.append(
                    Finding(
                        analyzer="surface",
                        title=f"HNAP interface reachable on the device (port {s.port})",
                        severity=Severity.MEDIUM,
                        confidence="medium",
                        evidence=f"{e.path} -> HTTP {e.status}",
                        description=(
                            "The HNAP (Home Network Administration Protocol) endpoint answered. "
                            "HNAP has a long history of authentication-bypass and command-injection "
                            "flaws (e.g. the SOAPAction CVEs); confirm its auth and firmware version."
                        ),
                        metadata={"port": s.port, "service": s.service, "path": e.path},
                    )
                )
            elif e.note == "CGI":
                out.append(
                    Finding(
                        analyzer="surface",
                        title=f"CGI/handler endpoint reachable on the device (port {s.port})",
                        severity=Severity.LOW,
                        confidence="medium",
                        evidence=f"{e.path} -> HTTP {e.status}",
                        description=(
                            f"A CGI/form handler ({e.path}) answered on the running device. These "
                            "handlers are a frequent command-injection surface in firmware; review "
                            "its input handling."
                        ),
                        metadata={"port": s.port, "service": s.service, "path": e.path},
                    )
                )
            elif e.note == "unauthenticated-admin":
                out.append(
                    Finding(
                        analyzer="surface",
                        title=f"Admin page served without authentication (port {s.port})",
                        severity=Severity.MEDIUM,
                        confidence="low",
                        evidence=f"{e.path} -> HTTP 200",
                        description=(
                            f"An admin/login/config page ({e.path}) returned 200 with no "
                            "authentication challenge. It may expose configuration without a login — "
                            "confirm whether it is actually unauthenticated."
                        ),
                        metadata={"port": s.port, "service": s.service, "path": e.path},
                    )
                )
        if s.upnp_actions:
            out.append(
                Finding(
                    analyzer="surface",
                    title=f"UPnP/SOAP control actions exposed on the device (port {s.port})",
                    severity=Severity.MEDIUM if _risky_upnp(s.upnp_actions) else Severity.LOW,
                    confidence="medium",
                    evidence=", ".join(s.upnp_actions[:8]),
                    description=(
                        f"The UPnP description on port {s.port} advertises {len(s.upnp_actions)} SOAP "
                        "action(s). UPnP control endpoints are often unauthenticated; port-mapping "
                        "actions in particular let an attacker pierce the NAT."
                    ),
                    metadata={"port": s.port, "service": s.service, "actions": s.upnp_actions},
                )
            )
        return out


def _risky_upnp(actions: list[str]) -> bool:
    risky = {"addportmapping", "deleteportmapping", "getexternalipaddress", "setdefaultconnectionservice"}
    return any(a.lower() in risky for a in actions)


# --------------------------------------------------------------------------- HTML parsing


class _PageParser(HTMLParser):
    """Pull the title, same-page links, and forms out of one HTML body.

    Deliberately forgiving (firmware HTML is often malformed) and bounded by the
    caller via ``max_body``; it records raw hrefs/actions, which the crawler then
    resolves and filters to the same host.
    """

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.links: list[str] = []
        self.forms: list[dict[str, Any]] = []
        self._in_title = False
        self._form: dict[str, Any] | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        a = {k.lower(): (v or "") for k, v in attrs}
        if tag == "title":
            self._in_title = True
        elif tag == "a" and a.get("href"):
            self.links.append(a["href"])
        elif tag == "form":
            self._form = {"action": a.get("action", ""), "method": (a.get("method") or "get").lower(), "inputs": []}
        elif tag in ("input", "select", "textarea") and self._form is not None:
            name = a.get("name")
            if name:
                self._form["inputs"].append(name)

    def handle_endtag(self, tag: str) -> None:
        if tag == "title":
            self._in_title = False
        elif tag == "form" and self._form is not None:
            self.forms.append(self._form)
            self._form = None

    def handle_data(self, data: str) -> None:
        if self._in_title and len(self.title) < 200:
            self.title += data.strip()


# --------------------------------------------------------------------------- HTTP fetch


def _connect(host: str, port: int, scheme: str, timeout: float) -> http.client.HTTPConnection:
    if scheme == "https":
        # Firmware serves self-signed certs; we must not verify. This only ever
        # talks to a localhost slirp forward, never a real remote host.
        ctx = ssl._create_unverified_context()
        return http.client.HTTPSConnection(host, port, timeout=timeout, context=ctx)
    return http.client.HTTPConnection(host, port, timeout=timeout)


def _fetch(host: str, port: int, scheme: str, path: str, opts: SurfaceOptions) -> tuple[int, str, bytes, str] | None:
    """GET one path. Returns (status, content_type, body, location) or None on error."""
    conn = _connect(host, port, scheme, opts.request_timeout_s)
    try:
        conn.request("GET", path, headers={"User-Agent": _UA, "Accept": "*/*", "Connection": "close"})
        resp = conn.getresponse()
        body = resp.read(opts.max_body + 1)[: opts.max_body]
        ctype = (resp.getheader("Content-Type") or "").split(";")[0].strip().lower()
        location = resp.getheader("Location") or ""
        return resp.status, ctype, body, location
    except (http.client.HTTPException, OSError, socket.timeout, ValueError) as exc:
        log.debug("fetch %s%s failed: %s", host, path, exc)
        return None
    finally:
        try:
            conn.close()
        except OSError:
            pass


def _same_host_path(base_path: str, href: str, host: str, port: int) -> str | None:
    """Resolve ``href`` against ``base_path`` and keep it only if same-host.

    Returns the ``path[?query]`` to enqueue, or None for off-host links, mailto:,
    javascript:, fragments, and anything whose scheme/host points elsewhere.
    """
    href = href.strip()
    if not href or href.startswith(("#", "mailto:", "javascript:", "tel:", "data:")):
        return None
    resolved = urljoin(f"http://{host}:{port}{base_path}", href)
    parts = urlsplit(resolved)
    if parts.scheme not in ("http", "https", ""):
        return None
    if parts.hostname and parts.hostname not in (host, "127.0.0.1", "localhost"):
        return None
    if parts.port and parts.port != port:
        return None
    path = parts.path or "/"
    if parts.query:
        path += "?" + parts.query
    return path


def _is_present(status: int) -> bool:
    """A probed path that actually names a resource: 2xx/3xx, or protected
    (401/403). A 404/405/400/5xx is not surface and is dropped."""
    return (200 <= status < 400) or status in (401, 403)


def _classify(path: str, status: int, title: str) -> str:
    if status >= 400:  # only a reachable (<400) resource is reported as notable
        return ""
    low = path.lower()
    if _HNAP in low:
        return "HNAP"
    if any(low.startswith(p) for p in _CGI_PREFIXES):
        return "CGI"
    if status == 200 and any(h in low or h in title.lower() for h in _ADMIN_HINTS):
        return "unauthenticated-admin"
    return ""


def _looks_like_upnp(ctype: str, body: bytes) -> bool:
    if "xml" not in ctype and not body.lstrip().startswith(b"<?xml"):
        return False
    head = body[:4096].lower()
    return b"urn:" in head and (b"service" in head or b"device" in head or b"scpd" in head)


def _parse_upnp(body: bytes, host: str, port: int, scheme: str, opts: SurfaceOptions) -> list[str]:
    """From a UPnP device/service description, collect SOAP action names.

    Refuses any document carrying a DOCTYPE or ENTITY declaration (billion-laughs
    / XXE defense) and ignores XML namespaces by matching on local tag names.
    """
    if b"<!doctype" in body[:2048].lower() or b"<!entity" in body.lower():
        log.debug("UPnP description with DOCTYPE/ENTITY refused")
        return []
    try:
        root = ElementTree.fromstring(body)
    except ElementTree.ParseError:
        return []

    def local(tag: str) -> str:
        return tag.rsplit("}", 1)[-1].lower()

    # Actions live directly in the description for embedded SCPD, or in a separate
    # SCPD document referenced by <SCPDURL>. Collect both the referenced SCPD URLs
    # and any action names already inline.
    actions: list[str] = []
    scpd_urls: list[str] = []
    for el in root.iter():
        tag = local(el.tag)
        if tag == "scpdurl" and el.text:
            scpd_urls.append(el.text.strip())
        elif tag == "action":
            for child in el:
                if local(child.tag) == "name" and child.text:
                    actions.append(child.text.strip())
    for url in scpd_urls[:8]:
        if len(actions) >= opts.max_actions:
            break
        path = _same_host_path("/", url, host, port)
        if not path:
            continue
        got = _fetch(host, port, scheme, path, opts)
        if not got or got[0] != 200:
            continue
        sub = got[2]
        if b"<!doctype" in sub[:2048].lower() or b"<!entity" in sub.lower():
            continue
        try:
            sroot = ElementTree.fromstring(sub)
        except ElementTree.ParseError:
            continue
        for el in sroot.iter():
            if local(el.tag) == "action":
                for child in el:
                    if local(child.tag) == "name" and child.text:
                        actions.append(child.text.strip())
    # de-dup, preserve order, cap.
    seen: dict[str, None] = {}
    for a in actions:
        seen.setdefault(a, None)
    return list(seen)[: opts.max_actions]


# --------------------------------------------------------------------------- crawl


def crawl_service(host: str, port: int, service: str, opts: SurfaceOptions | None = None) -> ServiceSurface:
    """Bounded crawl of one HTTP-speaking service on ``host:port``."""
    opts = opts or SurfaceOptions()
    scheme = "https" if service in _HTTPS_SERVICES else "http"
    surface = ServiceSurface(port=port, service=service, scheme=scheme)

    deadline = time.monotonic() + opts.wall_clock_s
    queue: list[tuple[str, int]] = [(p, 0) for p in _SEED_PATHS]
    seen_paths: set[str] = set()
    fetched = 0
    reachable = False

    while queue and fetched < opts.max_pages and time.monotonic() < deadline:
        path, depth = queue.pop(0)
        if path in seen_paths:
            continue
        seen_paths.add(path)
        got = _fetch(host, port, scheme, path, opts)
        fetched += 1
        if got is None:
            continue
        status, ctype, body, location = got
        reachable = True
        ep = Endpoint(path=path, status=status, content_type=ctype)

        if _looks_like_upnp(ctype, body):
            surface.upnp_actions = _merge_actions(
                surface.upnp_actions, _parse_upnp(body, host, port, scheme, opts), opts
            )

        if "html" in ctype or (not ctype and body[:1].startswith(b"<")):
            parser = _PageParser()
            try:
                parser.feed(body.decode("utf-8", "replace"))
            except Exception:  # a hostile/malformed page must not abort the crawl
                log.debug("HTML parse of %s failed", path, exc_info=True)
            ep.title = parser.title
            ep.forms = parser.forms[: opts.max_forms]
            if depth < opts.max_depth:
                for href in parser.links:
                    nxt = _same_host_path(path, href, host, port)
                    if nxt and nxt not in seen_paths:
                        queue.append((nxt, depth + 1))

        # Follow a same-host redirect as a link (never auto-follow off-host).
        if status in (301, 302, 303, 307, 308) and location and depth < opts.max_depth:
            nxt = _same_host_path(path, location, host, port)
            if nxt and nxt not in seen_paths:
                queue.append((nxt, depth + 1))

        ep.note = _classify(path, status, ep.title)
        if _is_present(status):
            surface.endpoints.append(ep)

    if not reachable:
        surface.error = "no response on any probed path"
    return surface


def _merge_actions(existing: list[str], new: list[str], opts: SurfaceOptions) -> list[str]:
    seen: dict[str, None] = {a: None for a in existing}
    for a in new:
        seen.setdefault(a, None)
    return list(seen)[: opts.max_actions]


def crawl_surface(target: Any, open_ports: list[int], services: dict[int, str], opts: SurfaceOptions | None = None) -> SurfaceMap:
    """Crawl every crawlable open port of a booted :class:`LiveTarget`.

    ``target`` only needs a ``host_port(guest_port) -> int`` method (the
    ``127.0.0.1`` forward), so a stub suffices in tests. ``services`` maps guest
    port -> service name (``COMMON_PORTS``). Non-HTTP services (telnet, ftp, ssh,
    dns) are skipped here — they belong to the auth phase.
    """
    opts = opts or SurfaceOptions()
    smap = SurfaceMap()
    for port in open_ports:
        service = services.get(port, "unknown")
        if service not in _CRAWLABLE:
            continue
        host_port = target.host_port(port)
        surface = crawl_service("127.0.0.1", host_port, service, opts)
        surface.port = port  # report the guest port, not the 127.0.0.1 forward
        smap.services.append(surface)
    return smap
