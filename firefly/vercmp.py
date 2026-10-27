"""Version comparison tuned for the versions found in firmware and in NVD.

Firmware versions are rarely semver: ``0.9.8zh`` (OpenSSL letter releases),
``2.0.10-4`` (Debian revisions), ``2019.78``, ``1.0rc1``. Versions are split
into numeric and alphabetic tokens and compared token by token, with two
rules for alphabetic tokens:

* pre-release markers (``alpha``, ``beta``, ``rc``, …) sort *before* the
  release they precede: ``1.0rc1 < 1.0``;
* any other letters are post-release suffixes: ``1.0.1 < 1.0.1a < 1.0.1g``.
"""

from __future__ import annotations

import functools
import re

_TOKEN = re.compile(r"[0-9]+|[a-z]+")
PRERELEASE = frozenset({"dev", "alpha", "beta", "pre", "preview", "rc", "cr", "snapshot"})
# Single letters are pre-release markers only when a number follows
# ("1.0a1", "2.0b3"); otherwise they are letter releases ("1.0.1a").
SHORT_PRERELEASE = frozenset({"a", "b", "m"})


def tokenize(version: str) -> list[int | str]:
    v = version.strip().lower()
    if v.startswith("v") and len(v) > 1 and v[1].isdigit():
        v = v[1:]
    return [int(t) if t.isdigit() else t for t in _TOKEN.findall(v)]


def _pre_flags(tokens: list[int | str]) -> list[bool]:
    flags = []
    for i, t in enumerate(tokens):
        nxt = tokens[i + 1] if i + 1 < len(tokens) else None
        flags.append(isinstance(t, str) and (t in PRERELEASE or (t in SHORT_PRERELEASE and isinstance(nxt, int))))
    return flags


def compare(a: str, b: str) -> int:
    """Return -1, 0 or 1 like a classic ``cmp``."""
    ta, tb = tokenize(a), tokenize(b)
    pa, pb = _pre_flags(ta), _pre_flags(tb)
    for i, (x, y) in enumerate(zip(ta, tb)):
        if x == y:
            continue
        if isinstance(x, int) and isinstance(y, int):
            return -1 if x < y else 1
        if isinstance(x, str) and isinstance(y, str):
            if pa[i] != pb[i]:
                return -1 if pa[i] else 1
            return -1 if x < y else 1
        # number vs letters ("1.0rc1" vs "1.0.1", "1.0a" vs "1.0.1"): the number wins
        return -1 if isinstance(x, str) else 1
    if len(ta) == len(tb):
        return 0
    flags, sign = (pa, 1) if len(ta) > len(tb) else (pb, -1)
    # "1.0rc1" vs "1.0": the extra pre-release token makes the longer one older
    return -sign if flags[min(len(ta), len(tb))] else sign


def in_range(
    version: str,
    start_incl: str | None = None,
    start_excl: str | None = None,
    end_incl: str | None = None,
    end_excl: str | None = None,
) -> bool:
    if start_incl and compare(version, start_incl) < 0:
        return False
    if start_excl and compare(version, start_excl) <= 0:
        return False
    if end_incl and compare(version, end_incl) > 0:
        return False
    if end_excl and compare(version, end_excl) >= 0:
        return False
    return True


sort_key = functools.cmp_to_key(compare)
