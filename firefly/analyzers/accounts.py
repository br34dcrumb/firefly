"""Audit account and password-hash policy in /etc/passwd and /etc/shadow.

This reports *policy* problems only: empty passwords, extra UID-0 accounts,
and password hashes stored with an outdated algorithm. It never attempts to
recover, guess or crack any password, and hash values are redacted. The point
is to tell the vendor which accounts need attention, not to break into them.
"""

from __future__ import annotations

from firefly.analyzers import Analyzer, AnalyzerResult, ScanContext
from firefly.models import Finding, Severity

# Firmware often ships the real passwd/shadow in a read-only overlay that is
# copied to /etc at boot (/rom/etc, /etc_ro, /usr/etc, ...), so match these
# files wherever an "etc"-like directory holds them, at any depth.
import re as _re

PASSWD_RE = _re.compile(r"(^|.*/)(etc|etc_ro|etc_default)/passwd$")
SHADOW_RE = _re.compile(r"(^|.*/)(etc|etc_ro|etc_default)/(shadow|master\.passwd)$")

# crypt() id -> (algorithm, is weak). "des" is the no-$ legacy format.
HASH_ALGOS = {
    "des": ("DES (legacy)", True),
    "1": ("MD5", True),
    "2": ("Blowfish/bcrypt", False),
    "2a": ("bcrypt", False),
    "2b": ("bcrypt", False),
    "2y": ("bcrypt", False),
    "5": ("SHA-256", False),
    "6": ("SHA-512", False),
    "y": ("yescrypt", False),
    "gy": ("gost-yescrypt", False),
    "7": ("scrypt", False),
}
# Non-hash shadow fields that mean "no login via password".
LOCKED_MARKERS = ("*", "!", "!!", "x", "")
# Interactive shells; a system account pointing at one is worth noting.
LOGIN_SHELLS = ("/bin/sh", "/bin/bash", "/bin/ash", "/bin/csh", "/bin/ksh", "/bin/zsh")


def classify_hash(field: str) -> tuple[str, bool] | None:
    """Return (algorithm name, is_weak) for a shadow password field, or None
    if it is not a password hash (locked/disabled account)."""
    if field in LOCKED_MARKERS or not field.startswith("$"):
        # A bare non-empty, non-$ field that isn't a lock marker is a DES hash.
        if field and field not in LOCKED_MARKERS and "$" not in field and len(field) >= 13:
            return HASH_ALGOS["des"]
        return None
    ident = field.split("$", 2)[1]
    return HASH_ALGOS.get(ident, (f"${ident}$ (unknown)", False))


def parse_passwd(text: str) -> list[dict]:
    users = []
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) < 7:
            continue
        users.append({"name": parts[0], "pw": parts[1], "uid": parts[2], "gid": parts[3], "shell": parts[6]})
    return users


def parse_shadow(text: str) -> dict[str, str]:
    out = {}
    for line in text.splitlines():
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 2:
            out[parts[0]] = parts[1]
    return out


class AccountsAnalyzer(Analyzer):
    name = "accounts"
    description = "Account and password-hash policy in /etc/passwd and /etc/shadow (no cracking)"

    def _read(self, ctx: ScanContext, rec) -> str | None:
        if rec is None:
            return None
        try:
            with open(ctx.inventory.abspath(rec), "rb") as fh:
                return fh.read(1024 * 1024).decode("utf-8", "replace")
        except OSError:
            return None

    def run(self, ctx: ScanContext) -> AnalyzerResult:
        assert ctx.inventory is not None
        result = AnalyzerResult()
        passwd_rec = next((r for r in ctx.inventory if PASSWD_RE.match(r.path)), None)
        passwd_text = self._read(ctx, passwd_rec)
        if passwd_text is None:
            return result
        users = parse_passwd(passwd_text)
        passwd_path = passwd_rec.path
        # Prefer a shadow file next to the passwd we used.
        base = passwd_path.rsplit("/", 1)[0]
        shadow_rec = next(
            (r for r in ctx.inventory if SHADOW_RE.match(r.path) and r.path.rsplit("/", 1)[0] == base),
            next((r for r in ctx.inventory if SHADOW_RE.match(r.path)), None),
        )
        shadow = parse_shadow(self._read(ctx, shadow_rec) or "")
        shadow_path = shadow_rec.path if shadow_rec else passwd_path

        def add(title, sev, desc, conf="high", path=passwd_path, meta=None):
            result.findings.append(Finding("accounts", title, sev, description=desc, confidence=conf, path=path, metadata=meta or {}))

        uid0 = [u["name"] for u in users if u["uid"] == "0" and u["name"] != "root"]
        if uid0:
            add(
                f"Non-root accounts with UID 0: {', '.join(uid0)}",
                Severity.HIGH,
                f"These accounts have full root privileges: {', '.join(uid0)}.",
                meta={"accounts": uid0},
            )

        for u in users:
            pw_field = shadow.get(u["name"], u["pw"])
            # Empty password field = login with no password at all.
            if pw_field == "":
                sev = Severity.CRITICAL if u["uid"] == "0" or u["shell"] in LOGIN_SHELLS else Severity.HIGH
                add(
                    f"Account '{u['name']}' has an empty password",
                    sev,
                    f"Account '{u['name']}' (uid {u['uid']}, shell {u['shell']}) can be used with no password.",
                    meta={"account": u["name"], "uid": u["uid"], "shell": u["shell"]},
                )
                continue
            algo = classify_hash(pw_field)
            if algo and algo[1]:
                is_root = u["uid"] == "0"
                add(
                    f"Account '{u['name']}' uses a weak password hash ({algo[0]})",
                    Severity.HIGH if is_root else Severity.MEDIUM,
                    f"Account '{u['name']}' stores its password with {algo[0]}, which is cheap to brute-force offline. "
                    f"Hash value redacted. Re-hash with yescrypt or SHA-512.",
                    path=shadow_path,
                    meta={"account": u["name"], "algorithm": algo[0], "uid": u["uid"]},
                )

        result.artifacts = {"users": len(users), "has_shadow": bool(shadow)}
        return result
