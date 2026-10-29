"""Tests for the crypto & secure-boot analyzer and its X.509 reader."""

from __future__ import annotations

import struct
from datetime import datetime, timezone

from firefly import x509
from firefly.analyzers import ScanContext
from firefly.analyzers.crypto import CryptoAnalyzer
from firefly.inventory import Inventory

# Real self-signed certificates, minted with openssl once and pinned here so the
# tests parse genuine DER without needing openssl at runtime.
GOOD_CERT = """-----BEGIN CERTIFICATE-----
MIIDDzCCAfegAwIBAgIUDrUsefDeKMxCvg9c0O+8zeKe/cAwDQYJKoZIhvcNAQEL
BQAwFzEVMBMGA1UEAwwMZ29vZC5leGFtcGxlMB4XDTI2MTAyOTA5MTMyMFoXDTM2
MTAyNjA5MTMyMFowFzEVMBMGA1UEAwwMZ29vZC5leGFtcGxlMIIBIjANBgkqhkiG
9w0BAQEFAAOCAQ8AMIIBCgKCAQEApAvOfUUdHycjt8bLHPIGxYOpUKJIkPAxhkuu
1UW4GnCqQRE0OAeWJfwXXdTfJVL9XmCavh+dDEEqe9DAVvL0Ih2Si1jVZpvWoNb0
gNXSCJ7iEiSynv/wFTw59CQEDwlAmkJJUmAmhcW9bsvRFIkjFS4qhuAEp1Gp//LU
HnEQkDxpUPItG7WlUhhoZHL1l2hsGWZ6WT/c76CsWYpHwQcnnuPolqR5dJClTs/s
JSK3ahsRU9elTJyuieXvAqMgc/ZZaWh6u+cyZJkGh1fjBVyjplt27Eihf/1355xN
Yww4AZNU7Q0UnBJuNXURzQu6rqH1kbCf2vGZfS05Mi8Fnmwi9wIDAQABo1MwUTAd
BgNVHQ4EFgQUka6OuZ/WRlVy8+qqfOJ7r8lxeIowHwYDVR0jBBgwFoAUka6OuZ/W
RlVy8+qqfOJ7r8lxeIowDwYDVR0TAQH/BAUwAwEB/zANBgkqhkiG9w0BAQsFAAOC
AQEAdEfmvUE3MyWrmhUFy7x+RaZC82RVe89OY0kUMch77i6Ir4AC0z2oHpdDQ1Ir
7YQgvbn7PwnMaJmpO12k3DqE+FtGuOmtrmhb8Urb7JuCiK3cWp+h7DD4SF6uywos
MPxommaNbFDKqrtBC+UAO4DZI8oogmBKYhvIOz9JEiv8i4u98U0d+1YvI8BaBdTG
20CDowQkX2euDLM2upCHyKnqo+0XeARNNixWMGriW+auyXAPU737gRmJT+OJJ1Wm
HXI2Tx1N5rz2yLheUndvb+rZndYn5UY3hP+QElpjNZ9BaWFCJ19+PSWenLtLSrd4
oBXLIQION1kxdbbr85d1pgHlfw==
-----END CERTIFICATE-----
"""

WEAK_CERT = """-----BEGIN CERTIFICATE-----
MIICCjCCAXOgAwIBAgIUMXksxNaTeNlPzhXeYP8kSq3EkOUwDQYJKoZIhvcNAQEF
BQAwFzEVMBMGA1UEAwwMd2Vhay5leGFtcGxlMB4XDTI2MTAyOTA5MTMyMFoXDTM2
MTAyNjA5MTMyMFowFzEVMBMGA1UEAwwMd2Vhay5leGFtcGxlMIGfMA0GCSqGSIb3
DQEBAQUAA4GNADCBiQKBgQDBrUOT0Qxyz76A8JS+5ifPyadtzeH4+0PtRRSA1FoZ
yCjlkrgjq3eYXNq2KJVTKNOkMGfX2g1KfKPWRyRFRlFoR67p36cTVqiBgJiE37nH
NH6kgYJt4Uw2zQDwFbIpT2hQKU+AfTMrS6cvDd2kl645pkbhghl4pSu2h7bqNGV3
fQIDAQABo1MwUTAdBgNVHQ4EFgQUBS5jUDUlKXjJytpwVgG5x7AVS2MwHwYDVR0j
BBgwFoAUBS5jUDUlKXjJytpwVgG5x7AVS2MwDwYDVR0TAQH/BAUwAwEB/zANBgkq
hkiG9w0BAQUFAAOBgQBBZmt4Uv4ZNuC1CbiGlvohV++WrkLl1PUXPmfoQmrz+xkt
AVMLxvaZS7f2scfnN4S37bkM/rFXh/USDVoP7beApObhPfb8dJEZ0oLhNk50qGlH
rGzn/stgU6M0w9khQYVW1+zSOB1aF6dyAOrx+CrOvFE7fW1gKfWAKF9mXPWXow==
-----END CERTIFICATE-----
"""

VBASE = 0x10000


def _elf_defining(func_name: str) -> bytes:
    """Minimal 32-bit LE ET_EXEC ELF defining one STT_FUNC named func_name."""
    code = bytes(range(32))
    ehsize, phentsize, shentsize = 52, 32, 40
    phoff = ehsize
    code_off = phoff + phentsize
    strtab = b"\x00" + func_name.encode() + b"\x00"
    strtab_off = code_off + len(code)
    symtab_off = strtab_off + len(strtab)
    sym_null = struct.pack("<IIIBBH", 0, 0, 0, 0, 0, 0)
    sym_func = struct.pack("<IIIBBH", 1, VBASE + code_off, len(code), (1 << 4) | 2, 0, 1)
    symtab = sym_null + sym_func
    shoff = symtab_off + len(symtab)

    def shdr(sh_type, off, size, link=0, entsize=0):
        return struct.pack("<IIIIIIIIII", 0, sh_type, 0, 0, off, size, link, 0, 0, entsize)

    shdrs = shdr(0, 0, 0) + shdr(3, strtab_off, len(strtab)) + shdr(2, symtab_off, len(symtab), link=1, entsize=16)
    total = shoff + len(shdrs)
    phdr = struct.pack("<IIIIIIII", 1, 0, VBASE, VBASE, total, total, 5, 0x1000)
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    ehdr = ident + struct.pack("<HHIIIIIHHHHHH", 2, 0x28, 1, 0, phoff, shoff, 0, ehsize, phentsize, 1, shentsize, 3, 0)
    return ehdr + phdr + code + strtab + symtab + shdrs


# --------------------------------------------------------------------------- X.509 reader


def test_parse_good_cert():
    certs = x509.parse_certificates(GOOD_CERT.encode())
    assert len(certs) == 1
    c = certs[0]
    assert c.key_type == "rsa" and c.key_bits == 2048
    # strong signature: not flagged; sig_alg is the raw OID (only weak algs get a name)
    assert c.weak_sig is False and c.sig_alg == "1.2.840.113549.1.1.11"
    assert c.self_issued is True
    assert c.not_after is not None and c.not_after.year == 2036


def test_parse_weak_cert():
    c = x509.parse_certificates(WEAK_CERT.encode())[0]
    assert c.key_type == "rsa" and c.key_bits == 1024
    assert c.weak_sig is True and "sha1" in c.sig_alg.lower()
    assert c.self_issued is True


def test_parse_junk_is_empty():
    assert x509.parse_certificates(b"not a certificate at all") == []
    # a PEM block with a corrupt body is skipped, not raised
    broken = b"-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n"
    assert x509.parse_certificates(broken) == []


# --------------------------------------------------------------------------- analyzer


def _inv(tmp_path, files: dict[str, bytes]):
    root = tmp_path / "root"
    for rel, content in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_bytes(content)
    return Inventory.build(str(root))


def _ctx(inv):
    return ScanContext(firmware_path="x", workdir="x", jobs=1, inventory=inv)


def _find(result, substr):
    return next((f for f in result.findings if substr in f.title), None)


def test_weak_primitive_family_is_flagged(tmp_path):
    inv = _inv(tmp_path, {"bin/vpn": _elf_defining("DES_set_key")})
    res = CryptoAnalyzer().run(_ctx(inv))
    f = _find(res, "DES/3DES")
    assert f is not None and f.severity.value == "medium" and f.confidence == "medium"
    assert f.metadata["binaries"] == ["bin/vpn"]
    assert "DES/3DES" in res.artifacts["weak_primitive_families"]


def test_network_facing_primitive_bumps_severity(tmp_path):
    # a path-hinted daemon name marks the binary network-facing -> high
    inv = _inv(tmp_path, {"usr/sbin/httpd": _elf_defining("RC4")})
    res = CryptoAnalyzer().run(_ctx(inv))
    f = _find(res, "RC4")
    assert f is not None and f.severity.value == "high" and f.metadata["network_facing"] is True


def test_legacy_hash_is_low_and_aggregated(tmp_path):
    inv = _inv(tmp_path, {"bin/a": _elf_defining("MD5_Init"), "bin/b": _elf_defining("SHA1_Init")})
    res = CryptoAnalyzer().run(_ctx(inv))
    f = _find(res, "Legacy hash")
    assert f is not None and f.severity.value == "low"
    assert sorted(f.metadata["binaries"]) == ["bin/a", "bin/b"]


def test_weak_cert_key_and_signature(tmp_path):
    inv = _inv(tmp_path, {"etc/weak.pem": WEAK_CERT.encode(), "etc/good.pem": GOOD_CERT.encode()})
    res = CryptoAnalyzer().run(_ctx(inv))
    key = _find(res, "undersized RSA key")
    sig = _find(res, "broken hash")
    assert key is not None and any("1024-bit" in c for c in key.metadata["certificates"])
    assert sig is not None and any("weak.pem" in c for c in sig.metadata["certificates"])
    assert res.artifacts["certificates"] == 2


def test_expired_cert_detected_against_now(tmp_path):
    inv = _inv(tmp_path, {"etc/good.pem": GOOD_CERT.encode()})
    future = datetime(3000, 1, 1, tzinfo=timezone.utc)
    res = CryptoAnalyzer().run(_ctx(inv), now=future)
    f = _find(res, "expired certificate")
    assert f is not None and any("good.pem" in c for c in f.metadata["certificates"])


def test_boot_integrity_detected(tmp_path):
    inv = _inv(tmp_path, {"etc/fstab": b"/dev/root / ext4 ro 0 1\n# dm-verity root hash\n"})
    res = CryptoAnalyzer().run(_ctx(inv))
    f = _find(res, "Boot-integrity mechanism detected")
    assert f is not None and f.severity.value == "info"
    assert "dm-verity" in f.metadata["mechanisms"]
    assert _find(res, "No boot-integrity") is None


def test_boot_integrity_absent_posture(tmp_path):
    inv = _inv(tmp_path, {"etc/motd": b"welcome\n"})
    res = CryptoAnalyzer().run(_ctx(inv))
    f = _find(res, "No boot-integrity mechanism detected")
    assert f is not None and f.severity.value == "low" and f.confidence == "low"
