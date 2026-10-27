import pytest

from firefly.vercmp import compare, in_range, sort_key


@pytest.mark.parametrize(
    "lower, higher",
    [
        ("1.0.1", "1.0.1a"),  # OpenSSL letter releases
        ("1.0.1f", "1.0.1g"),
        ("0.9.8z", "0.9.8za"),
        ("0.9.8za", "0.9.8zh"),
        ("1.1.1k", "1.1.1l"),
        ("1.0rc1", "1.0"),  # pre-releases come first
        ("1.0beta2", "1.0rc1"),
        ("1.0", "1.0.1"),
        ("1.9", "1.10"),  # numeric, not lexicographic
        ("2.0.10", "2.0.10-4"),  # Debian revision
        ("2019.78", "2020.79"),
        ("v1.2", "1.3"),
        ("1.0rc1", "1.0.1"),
    ],
)
def test_ordering(lower, higher):
    assert compare(lower, higher) == -1
    assert compare(higher, lower) == 1


def test_equal():
    assert compare("1.2.3", "1.2.3") == 0
    assert compare("V1.2.3", "1.2.3") == 0
    assert compare("1.2-3", "1.2.3") == 0  # separators don't matter


def test_in_range():
    assert in_range("1.0.1f", start_incl="1.0.1", end_excl="1.0.1g")
    assert not in_range("1.0.1g", start_incl="1.0.1", end_excl="1.0.1g")
    assert not in_range("1.0.0", start_incl="1.0.1", end_excl="1.0.1g")
    assert in_range("2.4", end_incl="2.4")
    assert not in_range("2.4", start_excl="2.4")


def test_sort_key():
    assert sorted(["1.10", "1.9", "1.9a", "1.9rc1"], key=sort_key) == ["1.9rc1", "1.9", "1.9a", "1.10"]
