"""A small, dependency-free X.509 reader for certificate *posture*.

Firefly has no ``cryptography`` dependency (see the invariants in CLAUDE.md), so
this parses just enough DER to judge a certificate's quality: the signature
algorithm, the public-key type and size, the validity window, and whether the
certificate is self-issued. It never verifies a signature or builds a chain.

Certificates in firmware are attacker-controlled, so — like :mod:`firefly.elf` —
every read is bounds-checked and anything malformed makes the parse return
``None`` rather than raising or reading out of range.
"""

from __future__ import annotations

import base64
import binascii
import re
from dataclasses import dataclass
from datetime import datetime, timezone

# ASN.1 tags we care about.
_INTEGER = 0x02
_BIT_STRING = 0x03
_OID = 0x06
_SEQUENCE = 0x30
_UTCTIME = 0x17
_GENERALIZEDTIME = 0x18
_CONTEXT_0 = 0xA0  # [0] EXPLICIT — the optional TBS version

_MAX_DEPTH = 40
_MAX_CHILDREN = 64

# Signature-algorithm OIDs that are broken or deprecated for signing.
_WEAK_SIG = {
    "1.2.840.113549.1.1.2": "md2WithRSAEncryption",
    "1.2.840.113549.1.1.3": "md4WithRSAEncryption",
    "1.2.840.113549.1.1.4": "md5WithRSAEncryption",
    "1.2.840.113549.1.1.5": "sha1WithRSAEncryption",
    "1.2.840.10040.4.3": "dsa-with-sha1",
    "1.2.840.10045.4.1": "ecdsa-with-SHA1",
}
# Public-key algorithm OIDs.
_PK_ALGS = {
    "1.2.840.113549.1.1.1": "rsa",
    "1.2.840.10045.2.1": "ec",
    "1.2.840.10040.4.1": "dsa",
}

_PEM_CERT = re.compile(rb"-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----", re.DOTALL)


@dataclass
class CertInfo:
    key_type: str  # "rsa" | "ec" | "dsa" | "unknown"
    key_bits: int | None  # modulus size for RSA; None when not computable
    sig_alg: str  # a friendly name for known OIDs, else the raw OID
    weak_sig: bool  # signed with a broken/deprecated hash
    not_after: datetime | None  # end of validity (UTC), None if unparseable
    self_issued: bool  # issuer == subject (self-signed shape)


class _Der:
    """A bounds-checked DER cursor over ``data[start:end)``."""

    def __init__(self, data: bytes, start: int, end: int):
        self.data = data
        self.pos = start
        self.end = end

    def at_end(self) -> bool:
        return self.pos >= self.end

    def read_tlv(self) -> tuple[int, int, int]:
        """Return (tag, content_start, content_end) and advance past the value."""
        data = self.data
        if self.pos + 2 > self.end:
            raise ValueError("truncated TLV")
        tag = data[self.pos]
        p = self.pos + 1
        length = data[p]
        p += 1
        if length & 0x80:  # long form
            nbytes = length & 0x7F
            if nbytes == 0 or nbytes > 4 or p + nbytes > self.end:
                raise ValueError("bad length")
            length = int.from_bytes(data[p : p + nbytes], "big")
            p += nbytes
        content_start = p
        content_end = p + length
        if content_end > self.end:
            raise ValueError("length exceeds container")
        self.pos = content_end
        return tag, content_start, content_end


def _children(data: bytes, start: int, end: int, depth: int = 0) -> list[tuple[int, int, int]]:
    out: list[tuple[int, int, int]] = []
    if depth > _MAX_DEPTH:
        return out
    cur = _Der(data, start, end)
    while not cur.at_end() and len(out) < _MAX_CHILDREN:
        out.append(cur.read_tlv())
    return out


def _decode_oid(data: bytes, start: int, end: int) -> str:
    raw = data[start:end]
    if not raw:
        return ""
    first = raw[0]
    parts = [str(first // 40), str(first % 40)]
    val = 0
    for b in raw[1:]:
        val = (val << 7) | (b & 0x7F)
        if not (b & 0x80):
            parts.append(str(val))
            val = 0
    return ".".join(parts)


def _first_oid(data: bytes, seq_start: int, seq_end: int) -> str:
    for tag, cs, ce in _children(data, seq_start, seq_end):
        if tag == _OID:
            return _decode_oid(data, cs, ce)
    return ""


def _parse_time(tag: int, raw: bytes) -> datetime | None:
    s = raw.decode("ascii", "replace").strip()
    # Only the UTC "Z" forms appear in practice; offsets are not parsed.
    if not s.endswith("Z"):
        return None
    body = s[:-1]
    fmts = ("%y%m%d%H%M%S", "%y%m%d%H%M") if tag == _UTCTIME else ("%Y%m%d%H%M%S", "%Y%m%d%H%M")
    for fmt in fmts:
        try:
            return datetime.strptime(body, fmt).replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    return None


def _rsa_bits(data: bytes, bit_start: int, bit_end: int) -> int | None:
    # subjectPublicKey BIT STRING: first content byte is the unused-bit count,
    # then the DER of RSAPublicKey ::= SEQUENCE { modulus INTEGER, exponent }.
    if bit_start >= bit_end:
        return None
    inner = _children(data, bit_start + 1, bit_end)
    if not inner or inner[0][0] != _SEQUENCE:
        return None
    _t, cs, ce = inner[0]
    fields = _children(data, cs, ce)
    if not fields or fields[0][0] != _INTEGER:
        return None
    _mt, ms, me = fields[0]
    modulus = int.from_bytes(data[ms:me], "big")  # leading 0x00 sign byte folds away
    return modulus.bit_length() or None


def parse_cert(der: bytes) -> CertInfo | None:
    """Parse one DER certificate. Returns None on anything malformed."""
    try:
        top = _children(der, 0, len(der))
        if len(top) != 1 or top[0][0] != _SEQUENCE:
            return None
        _t, cs, ce = top[0]
        cert = _children(der, cs, ce)
        if len(cert) < 2 or cert[0][0] != _SEQUENCE:
            return None
        tbs = _children(der, cert[0][1], cert[0][2])
        # TBSCertificate: [0] version is optional; serialNumber, signature,
        # issuer, validity, subject, subjectPublicKeyInfo follow in order.
        i = 1 if tbs and tbs[0][0] == _CONTEXT_0 else 0
        if len(tbs) < i + 6:
            return None
        sig_seq = tbs[i + 1]
        issuer = tbs[i + 2]
        validity = tbs[i + 3]
        subject = tbs[i + 4]
        spki = tbs[i + 5]

        sig_oid = _first_oid(der, sig_seq[1], sig_seq[2])
        sig_alg = _WEAK_SIG.get(sig_oid, sig_oid)
        weak_sig = sig_oid in _WEAK_SIG

        self_issued = der[issuer[1] : issuer[2]] == der[subject[1] : subject[2]]

        not_after = None
        vfields = _children(der, validity[1], validity[2])
        if len(vfields) >= 2 and vfields[1][0] in (_UTCTIME, _GENERALIZEDTIME):
            not_after = _parse_time(vfields[1][0], der[vfields[1][1] : vfields[1][2]])

        key_type, key_bits = "unknown", None
        spki_children = _children(der, spki[1], spki[2])
        if len(spki_children) >= 2 and spki_children[0][0] == _SEQUENCE and spki_children[1][0] == _BIT_STRING:
            pk_oid = _first_oid(der, spki_children[0][1], spki_children[0][2])
            key_type = _PK_ALGS.get(pk_oid, "unknown")
            if key_type == "rsa":
                key_bits = _rsa_bits(der, spki_children[1][1], spki_children[1][2])

        return CertInfo(key_type, key_bits, sig_alg, weak_sig, not_after, self_issued)
    except (ValueError, IndexError):
        return None


def parse_certificates(data: bytes) -> list[CertInfo]:
    """Parse every certificate in a file's bytes (PEM blocks, or a bare DER).

    Never raises: unparseable certificates are skipped.
    """
    certs: list[CertInfo] = []
    found_pem = False
    for m in _PEM_CERT.finditer(data):
        found_pem = True
        try:
            der = base64.b64decode(b"".join(m.group(1).split()), validate=False)
        except (binascii.Error, ValueError):
            continue
        info = parse_cert(der)
        if info is not None:
            certs.append(info)
    # A bare DER certificate starts with SEQUENCE in long form (0x30 0x82 ...).
    if not found_pem and data[:2] == b"\x30\x82":
        info = parse_cert(data)
        if info is not None:
            certs.append(info)
    return certs
