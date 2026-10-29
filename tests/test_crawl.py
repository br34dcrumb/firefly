"""Tests for Phase C1 live surface crawling (firefly/emulation/crawl.py).

No qemu and no LiveTarget boot: the crawler talks plain HTTP, so we exercise it
against a throwaway stdlib ``http.server`` thread serving a tiny firmware-like
site, plus a stub target for the port-fan-out. They pass on any OS.
"""

from __future__ import annotations

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from firefly.emulation import crawl
from firefly.emulation.crawl import (
    SurfaceMap,
    SurfaceOptions,
    ServiceSurface,
    Endpoint,
    crawl_service,
    crawl_surface,
    _same_host_path,
    _classify,
    _parse_upnp,
)
from firefly.emulation.system import reliable_open_ports
from firefly.models import Severity

# --------------------------------------------------------------------------- fixtures

_ROOT_DESC = b"""<?xml version="1.0"?>
<root xmlns="urn:schemas-upnp-org:device-1-0">
  <device>
    <deviceType>urn:schemas-upnp-org:device:InternetGatewayDevice:1</deviceType>
    <actionList><action><name>Ping</name></action></actionList>
    <serviceList>
      <service>
        <serviceType>urn:schemas-upnp-org:service:WANIPConnection:1</serviceType>
        <SCPDURL>/scpd.xml</SCPDURL>
      </service>
    </serviceList>
  </device>
</root>
"""

_SCPD = b"""<?xml version="1.0"?>
<scpd xmlns="urn:schemas-upnp-org:service-1-0">
  <actionList>
    <action><name>AddPortMapping</name></action>
    <action><name>GetExternalIPAddress</name></action>
  </actionList>
</scpd>
"""

_INDEX = (
    b"<html><head><title>Router</title></head><body>"
    b"<a href='/status.html'>status</a>"
    b"<a href='http://evil.example/x'>offsite</a>"
    b"<form action='/goform/login' method='post'>"
    b"<input name='user'><input name='pass'></form>"
    b"</body></html>"
)


class _FirmwareHandler(BaseHTTPRequestHandler):
    def log_message(self, *a):  # keep test output quiet
        pass

    def _send(self, body: bytes, status: int = 200, ctype: str = "text/html"):
        self.send_response(status)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        routes = {
            "/": (_INDEX, 200, "text/html"),
            "/status.html": (b"<html><title>Status</title></html>", 200, "text/html"),
            "/cgi-bin/": (b"cgi root", 200, "text/plain"),
            "/goform/": (b"form handler", 200, "text/plain"),
            "/HNAP1/": (b"<soap/>", 200, "text/xml"),
            "/admin": (b"<html><title>Admin Login</title></html>", 200, "text/html"),
            "/rootDesc.xml": (_ROOT_DESC, 200, "text/xml"),
            "/scpd.xml": (_SCPD, 200, "text/xml"),
        }
        if self.path in routes:
            self._send(*routes[self.path])
        else:
            self._send(b"not found", 404, "text/plain")


@pytest.fixture
def firmware_http():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _FirmwareHandler)
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    try:
        yield srv.server_address[1]  # the bound port
    finally:
        srv.shutdown()
        t.join(timeout=2.0)


# --------------------------------------------------------------------------- live crawl


def test_crawl_service_maps_endpoints_forms_and_follows_links(firmware_http):
    s = crawl_service("127.0.0.1", firmware_http, "http")
    paths = {e.path for e in s.endpoints}
    assert "/" in paths
    assert "/status.html" in paths  # followed a same-host link
    assert s.error == ""

    root = next(e for e in s.endpoints if e.path == "/")
    assert root.title == "Router"
    assert root.forms and root.forms[0]["action"] == "/goform/login"
    assert set(root.forms[0]["inputs"]) == {"user", "pass"}


def test_crawl_does_not_follow_offsite_links(firmware_http):
    s = crawl_service("127.0.0.1", firmware_http, "http")
    assert all("evil.example" not in e.path for e in s.endpoints)


def test_crawl_classifies_notable_endpoints(firmware_http):
    s = crawl_service("127.0.0.1", firmware_http, "http")
    notes = {e.path: e.note for e in s.endpoints}
    assert notes.get("/HNAP1/") == "HNAP"
    assert notes.get("/cgi-bin/") == "CGI"
    assert notes.get("/goform/") == "CGI"
    assert notes.get("/admin") == "unauthenticated-admin"


def test_crawl_extracts_upnp_actions_including_scpd(firmware_http):
    s = crawl_service("127.0.0.1", firmware_http, "http")
    # Inline action from the device description + both actions from the SCPD.
    assert set(s.upnp_actions) >= {"Ping", "AddPortMapping", "GetExternalIPAddress"}


def test_crawl_findings_flag_hnap_and_risky_upnp(firmware_http):
    s = crawl_service("127.0.0.1", firmware_http, "http")
    smap = SurfaceMap(services=[s])
    findings = smap.to_findings()
    titles = [f.title for f in findings]
    assert any("Live HTTP surface mapped" in t for t in titles)
    assert any("HNAP" in t for t in titles)
    upnp = next(f for f in findings if "UPnP/SOAP" in f.title)
    assert upnp.severity is Severity.MEDIUM  # AddPortMapping is risky


def test_crawl_respects_max_pages(firmware_http):
    s = crawl_service("127.0.0.1", firmware_http, "http", SurfaceOptions(max_pages=2))
    assert len(s.endpoints) <= 2


def test_crawl_unreachable_service_degrades_gracefully():
    # Nothing listening on this port -> every fetch fails, no crash.
    s = crawl_service("127.0.0.1", 1, "https")
    assert s.scheme == "https"  # scheme still derived from the service name
    assert s.error == "no response on any probed path"
    assert s.endpoints == []


# --------------------------------------------------------------------------- unit helpers


def test_same_host_path_filters_offsite_and_junk():
    h, p = "127.0.0.1", 8080
    assert _same_host_path("/", "/a?b=1", h, p) == "/a?b=1"
    assert _same_host_path("/dir/", "sub", h, p) == "/dir/sub"
    assert _same_host_path("/", "http://evil.example/x", h, p) is None
    assert _same_host_path("/", "javascript:void(0)", h, p) is None
    assert _same_host_path("/", "#frag", h, p) is None
    assert _same_host_path("/", f"http://127.0.0.1:{p}/ok", h, p) == "/ok"
    assert _same_host_path("/", "http://127.0.0.1:9999/other", h, p) is None  # wrong port


def test_classify_rules():
    assert _classify("/HNAP1/", 200, "") == "HNAP"
    assert _classify("/cgi-bin/foo", 200, "") == "CGI"
    assert _classify("/admin", 200, "Admin") == "unauthenticated-admin"
    assert _classify("/admin", 401, "Admin") == ""  # a challenge is not "unauthenticated"
    assert _classify("/static/x.js", 200, "App") == ""


def test_parse_upnp_refuses_doctype_entity():
    evil = b"""<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY a "x">]>
    <root xmlns="urn:schemas-upnp-org:device-1-0"><action><name>&a;</name></action></root>"""
    assert _parse_upnp(evil, "127.0.0.1", 80, "http", SurfaceOptions()) == []


# --------------------------------------------------------------------------- surface fan-out


class _StubTarget:
    def __init__(self, mapping: dict[int, int]):
        self._mapping = mapping

    def host_port(self, guest_port: int) -> int:
        return self._mapping[guest_port]


def test_crawl_surface_skips_non_http_services(firmware_http):
    target = _StubTarget({80: firmware_http})
    services = {80: "http", 23: "telnet", 22: "ssh"}
    smap = crawl_surface(target, [80, 23, 22], services)
    assert [s.service for s in smap.services] == ["http"]  # telnet/ssh skipped
    assert smap.services[0].port == 80


def test_surface_map_artifact_is_json_shaped(firmware_http):
    s = crawl_service("127.0.0.1", firmware_http, "http")
    art = SurfaceMap(services=[s]).to_artifact()
    assert art["services"][0]["service"] == "http"
    assert isinstance(art["services"][0]["endpoints"], list)
    assert isinstance(art["services"][0]["upnp_actions"], list)


def test_to_findings_empty_when_nothing_reachable():
    dead = ServiceSurface(port=80, service="http", scheme="http", error="no response on any probed path")
    assert SurfaceMap(services=[dead]).to_findings() == []


# --------------------------------------------------------------------------- shared helper


def test_reliable_open_ports_drops_wall_of_false_positives():
    guest = [21, 22, 23, 80, 443]
    assert reliable_open_ports([23, 80], guest) == [23, 80]
    assert reliable_open_ports(guest, guest) == []  # all open -> none reliable
