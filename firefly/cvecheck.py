"""Second opinions on NVD's CPE ranges, from data NVD already ships.

NVD's machine-readable ranges are often broader than the advisory they encode:
two release branches get folded into one open-ended range (``* <= 1.0.0e``
for a bug fixed in 0.9.8s and 1.0.0f), or a range is simply wrong (an
OpenSSL 3.0-only bug listed as ``* <= 1.0.2``). The human-written
description and the shape of the CVE's other ranges usually tell the real
story. These checks never drop a match; callers lower its confidence and
record why.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass

from firefly.vercmp import compare, in_range, tokenize

_V = r"\d+(?:\.(?:\d+|x))*[a-z]*\d*"
_RANGE = re.compile(
    rf"(?P<a>{_V})(?:\.x)?\s*(?:(?P<incl>\bthrough|\bthru|\bto|\buntil|-|–)|(?P<excl>\bbefore|\bprior to|<))\s*(?P<b>{_V})",
    re.IGNORECASE,
)
_UPPER = re.compile(
    rf"(?P<op>\b(?:before|prior to|earlier than|older than|through|thru|up to|until)\b|<=|<)"
    rf"(?P<including>\s+and\s+including)?\s*(?:versions?\s+)?(?P<v>{_V})",
    re.IGNORECASE,
)
_UPPER_SUFFIX = re.compile(rf"(?P<v>{_V})\s+(?:and|or)\s+(?:earlier|before|prior|below|older|lower)", re.IGNORECASE)
# "fixed in OpenSSL 3.0.1", "This was fixed in version 2.32"
_FIXED = re.compile(
    rf"\b(?:fixed|patched|resolved|addressed|corrected)\s+in\s+(?:[A-Za-z][\w-]*\s+){{0,4}}?(?:versions?\s+)?(?P<v>{_V})",
    re.IGNORECASE,
)
_LOWER = re.compile(
    rf"(?:(?P<v1>{_V})\s+(?:and|or)\s+(?:later|after|above|newer|higher)"
    rf"|(?:\bsince|\bstarting (?:with|from|in)|\bfrom)\s+(?:versions?\s+)?(?P<v2>{_V})"
    rf"|\bintroduced\s+in\s+(?:[A-Za-z][\w-]*\s+){{0,4}}?(?:versions?\s+)?(?P<v4>{_V})"
    rf"|(?P<v3>{_V})\+)",
    re.IGNORECASE,
)
# OpenSSL advisories end with "Fixed in OpenSSL 3.0.1 (Affected 3.0.0)"; that list is exact.
_AFFECTED_CLAUSE = re.compile(r"\(Affected\s+([^)]*)\)", re.IGNORECASE)
_BARE = re.compile(rf"(?<![\w.]){_V}(?![\w])", re.IGNORECASE)
_PLATFORM = re.compile(
    r"\b(?:on|for|under|in)\s+(?:Microsoft\s+)?(?P<p>Windows|macOS|Mac OS X|OS X|iOS)\b|\b(?P<q>Windows|macOS)[- ]only\b",
    re.IGNORECASE,
)


@dataclass(frozen=True)
class Constraint:
    kind: str  # "range" | "upper" | "lower" | "branch"
    low: str | None = None
    high: str | None = None
    inclusive: bool = False

    def admits(self, version: str) -> bool:
        if self.kind == "branch":
            want = [t for t in tokenize(self.low or "") if t != "x"]
            have = tokenize(version)
            # "glibc 2.30.9000" (a development snapshot) still speaks for the 2.30 line
            return bool(want) and (have[: len(want)] == want or release_branch(self.low or "") == release_branch(version))
        # "1.x" as a bound means "the 1 branch onwards"
        low = self.low.lower().removesuffix(".x") if self.low else None
        if low is not None and compare(version, low) < 0:
            return False
        if self.high is None:
            return True
        hi = compare(version, self.high)
        return hi <= 0 if self.inclusive else hi < 0


def _looks_like_version(v: str) -> bool:
    # A dotted version or an "N.x" branch; plain integers are too ambiguous.
    return "." in v


def description_constraints(text: str) -> list[Constraint]:
    """Version statements made in a CVE description."""
    constraints: list[Constraint] = []
    spans: list[tuple[int, int]] = []

    def taken(m: re.Match) -> bool:
        return any(s <= m.start() < e for s, e in spans)

    for m in _RANGE.finditer(text):
        a, b = m.group("a"), m.group("b")
        if not (_looks_like_version(a) and _looks_like_version(b)):
            continue
        # "1.x before 1.0.0f" keeps the branch lower bound; "1.0.2 before 1.0.2c" too
        constraints.append(Constraint("range", low=a, high=b, inclusive=bool(m.group("incl"))))
        spans.append(m.span())
    for m in _UPPER.finditer(text):
        if taken(m) or not _looks_like_version(m.group("v")):
            continue
        op = m.group("op").lower()
        inclusive = bool(m.group("including")) or op in ("<=", "through", "thru", "up to", "until")
        constraints.append(Constraint("upper", high=m.group("v"), inclusive=inclusive))
        spans.append(m.span())
    for m in _FIXED.finditer(text):
        if taken(m) or not _looks_like_version(m.group("v")):
            continue
        constraints.append(Constraint("upper", high=m.group("v")))
        spans.append(m.span())
    for m in _UPPER_SUFFIX.finditer(text):
        if taken(m) or not _looks_like_version(m.group("v")):
            continue
        constraints.append(Constraint("upper", high=m.group("v"), inclusive=True))
        spans.append(m.span())
    for m in _LOWER.finditer(text):
        v = m.group("v1") or m.group("v2") or m.group("v3") or m.group("v4")
        if taken(m) or not _looks_like_version(v):
            continue
        constraints.append(Constraint("lower", low=v))
        spans.append(m.span())
    for m in _BARE.finditer(text):
        if taken(m) or not _looks_like_version(m.group(0)):
            continue
        constraints.append(Constraint("branch", low=m.group(0)))
    return constraints


def _mentions(constraint: Constraint, version: str) -> bool:
    return any(b is not None and compare(b.lower().removesuffix(".x"), version) == 0 for b in (constraint.low, constraint.high))


def description_agrees(version: str, text: str, nvd_ceiling: str | None = None) -> bool | None:
    """False if the description states versions and none of them covers `version`.

    None when the description says nothing usable about versions, or when it
    doesn't even agree with NVD's own upper bound (`nvd_ceiling`): then it is
    probably about another product or contains a typo ("thru 1.3.7" for
    1.37), and it is not evidence either way.
    """
    text = text or ""
    clause = _AFFECTED_CLAUSE.search(text)
    constraints = description_constraints(clause.group(1) if clause else text)
    if not constraints:
        return None
    if any(c.admits(version) for c in constraints):
        return True
    if clause is None and nvd_ceiling and not any(c.admits(nvd_ceiling) or _mentions(c, nvd_ceiling) for c in constraints):
        return None
    return False


def release_branch(version: str) -> tuple[int, ...]:
    """The maintenance line a version belongs to.

    ``0.9.8zh`` -> (0, 9, 8) (letter releases), ``4.19.183`` -> (4, 19),
    ``2.30`` -> (2, 30).
    """
    tokens = tokenize(version)
    numeric: list[int] = []
    for t in tokens:
        if not isinstance(t, int):
            return tuple(numeric)
        numeric.append(t)
    return tuple(numeric[:-1]) if len(numeric) > 2 else tuple(numeric)


@dataclass(frozen=True)
class Range:
    version: str | None
    start_incl: str | None
    start_excl: str | None
    end_incl: str | None
    end_excl: str | None


def fixed_in_branch(version: str, ranges: Sequence[Range]) -> str | None:
    """Detect a version that is past its own branch's vulnerable ceiling.

    When a CVE lists several open-ended ranges (``* <= 0.9.8r``,
    ``* <= 1.0.0e``) each one stands for a release branch. A version in the
    0.9.8 branch newer than 0.9.8r is fixed, even though ``* <= 1.0.0e``
    technically contains it. Returns the ceiling that rules it out.
    """
    branch = release_branch(version)
    for r in ranges:
        if r.version not in (None, "", "*") or r.start_incl or r.start_excl:
            continue
        ceiling = r.end_incl or r.end_excl
        if not ceiling or release_branch(ceiling) != branch:
            continue
        if not in_range(version, end_incl=r.end_incl, end_excl=r.end_excl):
            return ceiling
    return None


def platform_only(text: str) -> str | None:
    """Platform named as a precondition ("on Windows"), if any."""
    m = _PLATFORM.search(text or "")
    return (m.group("p") or m.group("q")) if m else None
