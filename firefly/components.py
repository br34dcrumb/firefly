"""Clean up raw version hits into a component list worth matching CVEs against.

Two problems with raw rule hits:

* names don't line up with NVD's CPE vendor/product dictionary
  (``glibc`` vs ``gnu:glibc``, ``sqlite3`` vs ``sqlite``), which splits one
  component in two and makes CVE lookups miss;
* multi-call binaries (BusyBox, Toybox) embed the help text of every applet,
  so rules for ``sed``, ``udhcp``, ``wget``, … fire inside them and report
  software that isn't actually installed.
"""

from __future__ import annotations

from firefly.models import Component

# cfg name (or "vendor:product") -> NVD (vendor, product)
CPE_ALIASES: dict[str, tuple[str, str]] = {
    "glibc": ("gnu", "glibc"),
    "gnu:glibc": ("gnu", "glibc"),
    "eglibc": ("eglibc", "eglibc"),
    "uclibc": ("uclibc", "uclibc"),
    "uclibc-ng": ("uclibc-ng_project", "uclibc-ng"),
    "musl": ("musl-libc", "musl"),
    "busybox": ("busybox", "busybox"),
    "bash": ("gnu", "bash"),
    "openssl": ("openssl", "openssl"),
    "libressl": ("openbsd", "libressl"),
    "wolfssl": ("wolfssl", "wolfssl"),
    "mbedtls": ("arm", "mbed_tls"),
    "gnutls": ("gnu", "gnutls"),
    "openssh": ("openbsd", "openssh"),
    "dropbear_ssh": ("dropbear_ssh_project", "dropbear_ssh"),
    "curl": ("haxx", "curl"),
    "libcurl": ("haxx", "libcurl"),
    "wget": ("gnu", "wget"),
    "sqlite": ("sqlite", "sqlite"),
    "sqlite3": ("sqlite", "sqlite"),
    "zlib": ("zlib", "zlib"),
    "expat": ("libexpat_project", "libexpat"),
    "libexpat": ("libexpat_project", "libexpat"),
    "libxml2": ("xmlsoft", "libxml2"),
    "lz4": ("lz4_project", "lz4"),
    "liblz4": ("lz4_project", "lz4"),
    "xz": ("tukaani", "xz"),
    "linux_kernel": ("linux", "linux_kernel"),
    "dnsmasq": ("thekelleys", "dnsmasq"),
    "lighttpd": ("lighttpd", "lighttpd"),
    "nginx": ("f5", "nginx"),
    "apache": ("apache", "http_server"),
    "boa": ("boa", "boa_web_server"),
    "goahead": ("embedthis", "goahead"),
    "mini_httpd": ("acme", "mini_httpd"),
    "thttpd": ("acme", "thttpd"),
    "openvpn": ("openvpn", "openvpn"),
    "wpa_supplicant": ("w1.fi", "wpa_supplicant"),
    "wpa_cli": ("w1.fi", "wpa_supplicant"),
    "hostapd": ("w1.fi", "hostapd"),
    "miniupnpd": ("miniupnp_project", "miniupnpd"),
    "iptables": ("netfilter", "iptables"),
    "samba": ("samba", "samba"),
    "quagga": ("quagga", "quagga"),
    "ntp": ("ntp", "ntp"),
    "net-snmp": ("net-snmp", "net-snmp"),
    "pppd": ("point-to-point_protocol_project", "point-to-point_protocol"),
    "avahi:avahi": ("avahi", "avahi"),
    "netatalk:afpd": ("netatalk", "netatalk"),
    "gnu:binutils": ("gnu", "binutils"),
    "gnu:sed": ("gnu", "sed"),
    "proftpd": ("proftpd", "proftpd"),
    "vsftpd": ("beasts", "vsftpd"),
    "pure-ftpd": ("pureftpd", "pure-ftpd"),
    "openldap": ("openldap", "openldap"),
    "libpcap": ("tcpdump", "libpcap"),
    "tcpdump": ("tcpdump", "tcpdump"),
    "libupnp": ("libupnp_project", "libupnp"),
    "json-c": ("json-c_project", "json-c"),
    "jansson": ("jansson_project", "jansson"),
    "libjpeg-turbo": ("libjpeg-turbo", "libjpeg-turbo"),
    "libpng": ("libpng", "libpng"),
    "freetype": ("freetype", "freetype"),
    "pcre": ("pcre", "pcre"),
    "python": ("python", "python"),
    "perl": ("perl", "perl"),
    "lua": ("lua", "lua"),
    "php": ("php", "php"),
    "u-boot": ("denx", "u-boot"),
}

# Binaries that bundle many tools and therefore contain other tools' strings.
MULTICALL_PRODUCTS = frozenset({"busybox", "toybox"})


def canonicalize(vendor: str | None, product: str) -> tuple[str | None, str]:
    key = f"{vendor}:{product}" if vendor else product
    if key in CPE_ALIASES:
        return CPE_ALIASES[key]
    if product in CPE_ALIASES and vendor is None:
        return CPE_ALIASES[product]
    return vendor, product


def merge(components: list[Component]) -> list[Component]:
    """Canonicalize names and merge components that turn out to be the same."""
    merged: dict[tuple[str, str, str], Component] = {}
    for comp in components:
        vendor, product = canonicalize(comp.vendor, comp.product)
        key = (vendor or "", product, comp.version)
        target = merged.get(key)
        if target is None:
            merged[key] = Component(
                product=product,
                version=comp.version,
                vendor=vendor,
                paths=list(comp.paths),
                evidence=list(comp.evidence),
                license=comp.license,
            )
            continue
        target.paths.extend(p for p in comp.paths if p not in target.paths)
        target.evidence.extend(e for e in comp.evidence if e not in target.evidence)
        target.evidence = target.evidence[:5]
        target.license = target.license or comp.license
    return sorted(merged.values(), key=lambda c: (c.product, c.version))


def suppress_multicall(components: list[Component]) -> tuple[list[Component], list[Component]]:
    """Drop hits that only come from inside multi-call binaries.

    Returns ``(kept, suppressed)``. A component also seen in a standalone
    binary is kept, minus the multi-call paths.
    """
    multicall_paths = {p for c in components if c.product in MULTICALL_PRODUCTS for p in c.paths}
    if not multicall_paths:
        return components, []
    kept, suppressed = [], []
    for comp in components:
        if comp.product in MULTICALL_PRODUCTS:
            kept.append(comp)
            continue
        own = [p for p in comp.paths if p not in multicall_paths]
        if own:
            comp.paths = own
            kept.append(comp)
        else:
            suppressed.append(comp)
    return kept, suppressed
