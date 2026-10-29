import re

import pytest

from firefly.analyzers.versions import match_text, split_identifier
from firefly.versioncfg import ere_to_python, load_default_rules, load_rules, parse_rules, parse_sed, required_literal


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


# --------------------------------------------------------------------------- rule-set selection


def test_load_rules_defaults_to_emba():
    # None and "emba" both load the broad bundled EMBA set.
    assert len(load_rules()[0]) == len(load_default_rules()[0]) > 700
    assert len(load_rules("emba")[0]) == len(load_default_rules()[0])


def test_native_ruleset_is_clean_and_compiles():
    # Firefly's own clean-room set parses with no errors (every normaliser works).
    rules, errors = load_rules("native")
    assert errors == []
    assert 20 < len(rules) < 200  # a focused firmware set, not EMBA's long tail
    assert all(r.license == "native" for r in rules)


def test_native_ruleset_detects_common_firmware_packages():
    rules, _ = load_rules("native")
    cases = {
        "BusyBox v1.36.1 (2023-01-01 10:00:00 UTC)": "busybox:busybox:1.36.1",
        "OpenSSL 1.1.1w  11 Sep 2023": "openssl:openssl:1.1.1w",
        "Dropbear v2022.83": "dropbear:dropbear:2022.83",
        "OpenSSH_9.6p1, OpenSSL": "openbsd:openssh:9.6p1",
        "Linux version 5.15.0 (gcc version 11)": "linux:linux_kernel:5.15.0",
        "inflate 1.2.11 Copyright 1995-2017 Jean-loup Gailly": "zlib:zlib:1.2.11",
    }
    for text, want in cases.items():
        assert want in {h[1] for h in match_text(text, "x", rules)}, text


def test_load_rules_from_path(tmp_path):
    cfg = tmp_path / "custom.cfg"
    cfg.write_text(
        r'''mytool;;mit;"MyTool\ [0-9]+\.[0-9]+";"sed -r 's/MyTool\ ([0-9]+\.[0-9]+).*/mytool:\1/'";''' + "\n",
        encoding="utf-8",
    )
    rules, errors = load_rules(str(cfg))
    assert errors == [] and [r.name for r in rules] == ["mytool"]
    assert "mytool:1.2" in {h[1] for h in match_text("MyTool 1.2.3", "x", rules)}


def test_load_rules_missing_path_raises():
    with pytest.raises(OSError):
        load_rules("does-not-exist.cfg")


def test_version_analyzer_honors_version_config(tmp_path):
    # End to end: an ELF carrying a BusyBox banner is identified only when the
    # chosen rule set has a matching rule. The native set does; a custom set
    # that only knows "mytool" does not.
    from elfbuild import build_elf

    from firefly.analyzers import ScanContext
    from firefly.analyzers.versions import VersionAnalyzer
    from firefly.inventory import Inventory

    root = tmp_path / "root"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "busybox").write_bytes(build_elf(imports=["printf"]) + b"\x00BusyBox v1.36.1 (2023)\x00")
    inv = Inventory.build(str(root))

    def run(version_config):
        ctx = ScanContext(firmware_path="x", workdir="x", jobs=1, inventory=inv)
        ctx.version_config = version_config
        return {(c.product, c.version) for c in VersionAnalyzer().run(ctx).components}

    assert ("busybox", "1.36.1") in run("native")

    other = tmp_path / "other.cfg"
    other.write_text(r'''mytool;;mit;"MyTool\ [0-9]+";"sed -r 's/MyTool\ ([0-9]+).*/mytool:\1/'";''' + "\n", encoding="utf-8")
    assert ("busybox", "1.36.1") not in run(str(other))
