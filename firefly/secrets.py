"""Detect hardcoded secrets, and redact them before they leave this module.

A firmware scan that printed the keys and passwords it found would itself be
a disclosure risk (reports get pasted into tickets and chats). So detection
and redaction live together: callers only ever receive a :class:`SecretHit`,
which carries a masked preview, the length, and a short salted-free hash for
correlating duplicates — never the raw secret. The raw bytes stay local to
the functions here.
"""

from __future__ import annotations

import hashlib
import math
import re
from collections import Counter
from dataclasses import dataclass

# Severity-ranked kinds; the analyzer maps these to Finding severities.
PRIVATE_KEY = "private_key"
PASSWORD = "password"
API_TOKEN = "api_token"

_PEM = re.compile(
    rb"-----BEGIN (?P<label>[A-Z0-9 ]*?PRIVATE KEY)-----(?P<body>.*?)-----END [A-Z0-9 ]*?PRIVATE KEY-----",
    re.DOTALL,
)
# Assignments in configs/scripts: key = value, key: value, key value
_ASSIGN = re.compile(
    r"""(?P<key>[A-Za-z0-9_.\-]*(?:pass(?:w(?:or)?d)?|secret|api[_-]?key|token|auth[_-]?key|private[_-]?key|credential)[A-Za-z0-9_.\-]*)"""
    r"""\s*[:=]\s*(?P<q>["']?)(?P<val>[^\s"'#;]{1,256})(?P=q)""",
    re.IGNORECASE,
)
# High-signal provider token formats.
_TOKENS = [
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z\-]{10,48}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[0-9A-Za-z]{36}\b")),
    ("jwt", re.compile(r"\beyJ[0-9A-Za-z_\-]{10,}\.eyJ[0-9A-Za-z_\-]{10,}\.[0-9A-Za-z_\-]{10,}\b")),
    ("private_key_openssh", re.compile(r"-----BEGIN OPENSSH PRIVATE KEY-----")),
]
# Values that look like credentials but are placeholders, not real secrets.
_PLACEHOLDERS = frozenset(
    {"", "password", "passwd", "changeme", "x", "xxxx", "none", "null", "nil", "true", "false", "yes", "no", "example",
     "your_password", "your-password", "<password>", "test", "admin", "default", "secret", "redacted", "password123"}
)
_PLACEHOLDER_RE = re.compile(r"^[*x.]+$|^\$\{|^%[a-z_]+%$|^<.*>$|^\$[A-Za-z_]", re.IGNORECASE)


@dataclass(frozen=True)
class SecretHit:
    kind: str
    subtype: str  # e.g. "RSA PRIVATE KEY", "aws_access_key", or the config key name
    preview: str  # already redacted, safe to print
    length: int
    fingerprint: str  # short hash of the raw value, for de-duplication only
    line: int | None = None


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


def _fingerprint(raw: bytes | str) -> str:
    if isinstance(raw, str):
        raw = raw.encode("utf-8", "replace")
    return hashlib.sha256(raw).hexdigest()[:12]


def redact(value: str) -> str:
    """A preview that proves what was found without disclosing it.

    Short values are fully masked; longer ones keep the first two characters
    so a reviewer can tell two different secrets apart, never more.
    """
    n = len(value)
    if n <= 6:
        return "*" * n
    return value[:2] + "*" * (n - 2)


def _looks_real(value: str) -> bool:
    v = value.strip()
    if v.lower() in _PLACEHOLDERS or _PLACEHOLDER_RE.match(v):
        return False
    if len(v) < 6:
        return False
    # Reject obvious non-secrets: pure words, file paths, URLs without creds.
    if v.startswith(("/", "./", "http://", "https://")) and "@" not in v:
        return False
    # Require some complexity so we don't flag "enabled", "localhost", etc.
    return _entropy(v) >= 2.6 or bool(re.search(r"\d", v) and re.search(r"[A-Za-z]", v))


def scan_bytes(data: bytes) -> list[SecretHit]:
    """Find secrets in a file's bytes. Returns redacted hits only."""
    hits: list[SecretHit] = []

    for m in _PEM.finditer(data):
        label = m.group("label").decode("ascii", "replace").strip()
        body = b"".join(m.group("body").split())
        hits.append(
            SecretHit(
                kind=PRIVATE_KEY,
                subtype=label or "PRIVATE KEY",
                preview=f"-----BEGIN {label}----- ({len(body)} base64 chars)",
                length=len(body),
                fingerprint=_fingerprint(body),
                line=data[: m.start()].count(b"\n") + 1,
            )
        )

    # Text scans only make sense on text-ish content.
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        text = data.decode("latin-1", "replace")

    for subtype, pattern in _TOKENS:
        for m in pattern.finditer(text):
            val = m.group(0)
            if val.startswith("-----BEGIN"):
                continue  # already handled by _PEM
            hits.append(
                SecretHit(
                    kind=API_TOKEN,
                    subtype=subtype,
                    preview=redact(val),
                    length=len(val),
                    fingerprint=_fingerprint(val),
                    line=text[: m.start()].count("\n") + 1,
                )
            )

    seen: set[tuple[str, str]] = set()
    for m in _ASSIGN.finditer(text):
        val = m.group("val")
        key = m.group("key")
        if not _looks_real(val):
            continue
        fp = _fingerprint(val)
        if (key.lower(), fp) in seen:
            continue
        seen.add((key.lower(), fp))
        hits.append(
            SecretHit(
                kind=PASSWORD,
                subtype=key,
                preview=f"{key}={redact(val)}",
                length=len(val),
                fingerprint=fp,
                line=text[: m.start()].count("\n") + 1,
            )
        )
    return hits
