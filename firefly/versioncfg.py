"""Parser for ``bin_version_strings.cfg`` (the EMBA version-identifier format).

Each line is ``name;mode;license;"grep -E regex";"sed -r 's/re/repl/'";``.
The original tooling piped ``strings | grep -o -a -E | sed`` through a shell
for every binary and every rule. Here every rule is translated once into a
compiled Python regex plus a substitution, and matched in-process.

mode:
  ""          plain rule, applied to every binary
  strict      only applied to binaries whose file name equals ``name``
  multi_grep  regexes joined by ``&&``; all must match, the last yields the version
  live, no_static, zgrep
              need emulation or kernel-config inputs; skipped by static analysis
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from importlib import resources

STATIC_SKIP_MODES = frozenset({"live", "no_static", "zgrep"})

_POSIX_CLASSES = {
    "[:alpha:]": "a-zA-Z",
    "[:digit:]": "0-9",
    "[:alnum:]": "a-zA-Z0-9",
    "[:upper:]": "A-Z",
    "[:lower:]": "a-z",
    "[:space:]": r" \t\n\r\f\v",
    "[:xdigit:]": "0-9a-fA-F",
    "[:punct:]": r"!-/:-@\[-`{-~",
}
_POSIX_IN_BRACKET = re.compile(r"\[:[a-z]+:\]|[^\[]+|\[")
_QUANTIFIERS = "+*?"
_GENERIC_VERSION = re.compile(r"[0-9]+(?:\.[0-9]+)+[a-z]?|[0-9]+")


@dataclass
class VersionRule:
    name: str
    mode: str
    license: str | None
    patterns: list[re.Pattern[str]]
    literals: list[str | None]  # literal each pattern requires, for cheap prefiltering
    sed_pattern: re.Pattern[str] | None
    sed_repl: str | None
    line_no: int

    def normalise(self, matched: str) -> str:
        if self.sed_pattern is not None:
            out, count = self.sed_pattern.subn(self.sed_repl, matched, count=1)
            if count:
                return out
        # No usable normaliser: fall back to the first version-looking token.
        version = _GENERIC_VERSION.search(matched)
        return f"{self.name}:{version.group(0)}" if version else ""


def ere_to_python(ere: str) -> str:
    """Translate a POSIX ERE (as used by ``grep -E`` / ``sed -r``) to Python ``re``.

    Python reads ``X+?`` as a *lazy* quantifier, but in ERE it is ``(X+)?``
    which is just greedy ``X*``. Getting this wrong truncates versions
    (``4.3.30`` would come out as ``4``), so stacked quantifiers are collapsed.
    """
    out: list[str] = []
    i = 0
    n = len(ere)
    while i < n:
        ch = ere[i]
        if ch == "\\" and i + 1 < n:
            nxt = ere[i + 1]
            if nxt == "<" or nxt == ">":
                out.append(r"\b")
            elif nxt.isalnum() and nxt not in "wWsSdDbB":
                out.append(re.escape(nxt))  # e.g. \% or \e have no meaning; treat literally
            elif nxt.isalnum():
                out.append("\\" + nxt)
            else:
                out.append(re.escape(nxt))
            i += 2
            continue
        if ch == "[":
            j = i + 1
            if j < n and ere[j] == "^":
                j += 1
            if j < n and ere[j] == "]":
                j += 1
            while j < n and ere[j] != "]":
                if ere.startswith("[:", j):
                    end = ere.find(":]", j)
                    j = end + 2 if end != -1 else j + 1
                else:
                    j += 1
            # Inside an ERE bracket '\' and '[' are literal; POSIX classes are not.
            body = _POSIX_IN_BRACKET.sub(
                lambda m: _POSIX_CLASSES.get(m.group(0)) or m.group(0).replace("\\", "\\\\").replace("[", "\\["),
                ere[i + 1 : j],
            )
            out.append("[" + body + "]")
            i = j + 1
            continue
        if ch in _QUANTIFIERS:
            j = i
            while j < n and ere[j] in _QUANTIFIERS:
                j += 1
            run = ere[i:j]
            if len(run) == 1:
                out.append(run)
            elif "*" in run or ("?" in run and "+" in run):
                out.append("*")
            elif "+" in run:
                out.append("+")
            else:
                out.append("?")
            i = j
            continue
        if ch == "~" and i + 1 < n and ere[i + 1] == "`":
            out.append("`")  # cfg's escape for a back-tick
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


def required_literal(ere: str, min_len: int = 3) -> str | None:
    """Longest literal substring every match of `ere` must contain.

    Used like grep's Boyer-Moore prefilter: a cheap ``in`` test skips the
    regex engine for binaries that cannot possibly match.
    """
    runs: list[str] = []
    cur: list[str] = []
    i = 0
    n = len(ere)
    depth = 0

    def flush() -> None:
        if cur:
            runs.append("".join(cur))
            cur.clear()

    while i < n:
        ch = ere[i]
        if ch == "|" and depth == 0:
            return None
        if ch == "(":
            depth += 1
            flush()
            i += 1
            continue
        if ch == ")":
            depth = max(0, depth - 1)
            flush()
            i += 1
            continue
        if depth:
            i += 1
            continue
        if ch == "[":
            flush()
            j = ere.find("]", i + 2)
            i = (j + 1) if j != -1 else n
            continue
        if ch in "?*{":
            if cur:
                cur.pop()
            flush()
            if ch == "{":
                j = ere.find("}", i)
                i = (j + 1) if j != -1 else n
            else:
                i += 1
            continue
        if ch == "+":
            flush()
            i += 1
            continue
        if ch in ".^$":
            flush()
            i += 1
            continue
        if ch == "\\" and i + 1 < n:
            nxt = ere[i + 1]
            if nxt.isalnum() and nxt in "wWsSdDbB<>":
                flush()
            else:
                cur.append(nxt)
            i += 2
            continue
        if ch == "~" and i + 1 < n and ere[i + 1] == "`":
            cur.append("`")
            i += 2
            continue
        cur.append(ch)
        i += 1
    flush()
    best = max(runs, key=len, default="")
    return best if len(best) >= min_len else None


_SED_RE = re.compile(r"""^\s*sed\s+-r\s+'s/(?P<re>(?:\\.|[^/\\])*)/(?P<repl>(?:\\.|[^/\\])*)/(?P<flags>[a-z]*)'?\s*$""")


def parse_sed(expr: str) -> tuple[re.Pattern[str], str] | None:
    m = _SED_RE.match(expr)
    if not m:
        return None
    try:
        # A few upstream rules have unbalanced groups that GNU sed rejects too.
        pattern = re.compile(ere_to_python(m.group("re")))
    except re.error:
        return None
    repl = m.group("repl").replace("\\/", "/")
    # sed back-references \1..\9 -> Python \g<1>; & -> whole match
    repl = re.sub(r"\\([0-9])", r"\\g<\1>", repl)
    repl = re.sub(r"(?<!\\)&", r"\\g<0>", repl)
    return pattern, repl


def _split_fields(line: str) -> list[str]:
    """Split a rule into name, mode, license, grep and (optional) sed fields.

    Quoting in the cfg is not balanced (patterns contain apostrophes), so the
    first three fields are split on ``;`` and the sed normaliser is located
    from the right instead of tokenising quotes.
    """
    head = line.split(";", 3)
    if len(head) < 4:
        return head
    rest = head[3].rstrip().rstrip(";")
    idx = max(rest.rfind(';"sed '), rest.rfind(';""sed '))
    if idx == -1:
        return head[:3] + [rest]
    return head[:3] + [rest[:idx], rest[idx + 1 :]]


def _unquote(value: str) -> str:
    # Only strip line endings: a pattern may legitimately end in an escaped space.
    value = value.strip("\r\n")
    while len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        value = value[1:-1]
    # Some upstream rules have an unbalanced quote on one side only.
    value = value.lstrip('"')
    if value.endswith('"') and not value.endswith('\\"'):
        value = value[:-1]
    return value


def parse_rules(text: str) -> tuple[list[VersionRule], list[str]]:
    rules: list[VersionRule] = []
    errors: list[str] = []
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        fields = _split_fields(line)
        if len(fields) < 4:
            errors.append(f"line {line_no}: expected at least 4 fields")
            continue
        # The grep field is not stripped: patterns may end in an escaped space.
        name, mode, lic, grep_field = fields[0].strip(), fields[1].strip(), fields[2].strip(), fields[3]
        sed_field = _unquote(fields[4]) if len(fields) > 4 else ""
        if mode in STATIC_SKIP_MODES:
            continue
        inner = grep_field
        if inner.startswith("'") and inner.endswith("'"):
            inner = inner[1:-1]
        raw_patterns = [_unquote(p) for p in inner.split("&&")] if mode == "multi_grep" else [_unquote(inner)]
        try:
            patterns = [re.compile(ere_to_python(p), re.MULTILINE) for p in raw_patterns]
        except re.error as exc:
            errors.append(f"line {line_no} ({name}): bad regex: {exc}")
            continue
        sed = parse_sed(sed_field) if sed_field else None
        if sed_field and sed is None:
            errors.append(f"line {line_no} ({name}): unusable normaliser, falling back to a generic version match")
        rules.append(
            VersionRule(
                name=name,
                mode=mode,
                license=None if lic in ("", "unknown") else lic,
                patterns=patterns,
                literals=[required_literal(p) for p in raw_patterns],
                sed_pattern=sed[0] if sed else None,
                sed_repl=sed[1] if sed else None,
                line_no=line_no,
            )
        )
    return rules, errors


def load_default_rules() -> tuple[list[VersionRule], list[str]]:
    text = resources.files("firefly.data").joinpath("bin_version_strings.cfg").read_text(encoding="utf-8")
    return parse_rules(text)
