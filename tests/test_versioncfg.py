import re

from firefly.analyzers.versions import match_text, split_identifier
from firefly.versioncfg import ere_to_python, load_default_rules, parse_rules, parse_sed, required_literal


def test_ere_stacked_quantifiers_are_greedy():
    # In ERE `(X)+?` means `((X)+)?`; Python would read it as lazy and truncate.
    pattern = re.compile(ere_to_python(r"bash\ version\ [0-9](\.[0-9]+)+?"))
    assert pattern.search("GNU bash version 4.3.30(1)").group(0) == "bash version 4.3.30"
    assert re.compile(ere_to_python(r"v[0-9](\.[0-9]+)?+$")).search("v1.2.3").group(0) == "v1.2.3"


def test_ere_brackets_and_escapes():
    assert ere_to_python(r"[[:alpha:]]+") == "[a-zA-Z]+"
    assert re.fullmatch(ere_to_python(r"[[0-9]x"), "[x")
    assert re.fullmatch(ere_to_python(r"a\%s"), "a%s")
    assert re.fullmatch(ere_to_python(r"table\ ~`%s'"), "table `%s'")


def test_required_literal():
    assert required_literal(r"BusyBox\ v[0-9](\.[0-9]+)+?\ ") == "BusyBox v"
    assert required_literal(r"^Server version: Apache/[0-9]") == "Server version: Apache/"
    assert required_literal(r"[0-9](\.[0-9]+)+?") is None
    assert required_literal(r"foo|barbaz") is None
    assert required_literal(r"abcd?efgh") == "efgh"


def test_parse_sed():
    pattern, repl = parse_sed(r"sed -r 's/BusyBox\ v([0-9](\.[0-9]+)+?)\ .*/busybox:\1/'")
    assert pattern.sub(repl, "BusyBox v1.31.1 (2020)") == "busybox:1.31.1"
    pattern, repl = parse_sed(r"sed -r 's/^Server version: Apache\/([0-9](\.[0-9]+)+?)/apache:\1/g'")
    assert pattern.sub(repl, "Server version: Apache/2.4.1") == "apache:2.4.1"


def test_rule_modes():
    text = "\n".join(
        [
            r'''plain;;mit;"plain\ [0-9](\.[0-9]+)+?";"sed -r 's/plain\ ([0-9](\.[0-9]+)+?)/plain:\1/'";''',
            r'''strictbin;strict;unknown;"^[0-9](\.[0-9]+)+?$";"sed -r 's/([0-9](\.[0-9]+)+?)$/strictbin:\1/'";''',
            r'''multi;multi_grep;gpl;'"^Multi tool$"&&"^[0-9](\.[0-9]+)+?$"';"sed -r 's/([0-9](\.[0-9]+)+?)$/multi:\1/'";''',
            r'''emu;live;unknown;"^emu\ [0-9]$";"sed -r 's/emu\ ([0-9])/emu:\1/'";''',
        ]
    )
    rules, errors = parse_rules(text)
    assert errors == []
    assert [r.name for r in rules] == ["plain", "strictbin", "multi"]  # live rules are skipped

    text = "plain 1.2.3\n2.0.1\nsomething"
    names = {rules[i].name for i, *_ in match_text(text, "otherbin", rules)}
    assert names == {"plain"}  # strict rule needs a matching file name; multi needs both lines
    hits = match_text(text, "strictbin", rules)
    assert ("strictbin:2.0.1" in {h[1] for h in hits})
    hits = match_text("Multi tool\n3.4\n", "x", rules)
    assert [h[1] for h in hits] == ["multi:3.4"]


def test_default_rules_compile():
    rules, errors = load_default_rules()
    assert len(rules) > 700
    # only the known-broken upstream normalisers should be reported
    assert all("unusable normaliser" in e for e in errors), errors


def test_split_identifier():
    assert split_identifier("busybox:1.31.1") == (None, "busybox", "1.31.1")
    assert split_identifier("gnu:binutils:2.30") == ("gnu", "binutils", "2.30")
    assert split_identifier("nonsense") is None
