import pytest

from firefly.analyzers.cves import match_component
from firefly.cvecheck import Range, description_agrees, fixed_in_branch, platform_only, release_branch
from firefly.models import Component
from firefly.vulndb import VulnDB

from nvdfeed import cve, match

OPENSSL = "cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*"

# Real NVD descriptions
D_4576 = (
    "The SSL 3.0 implementation in OpenSSL before 0.9.8s and 1.x before 1.0.0f does not properly initialize "
    "data structures for block cipher padding."
)
D_4044 = "Internally libssl in OpenSSL calls X509_verify_cert() ... a separate bug in OpenSSL 3.0 ... Fixed in OpenSSL 3.0.1 (Affected 3.0.0)."
D_2108 = "The ASN.1 implementation in OpenSSL before 1.0.1o and 1.0.2 before 1.0.2c allows remote attackers to execute arbitrary code."
D_HEARTBLEED = "The (1) TLS and (2) DTLS implementations in OpenSSL 1.0.1 before 1.0.1g do not properly handle Heartbeat Extension packets."


@pytest.mark.parametrize(
    "version, text, expected",
    [
        ("0.9.8zh", D_4576, False),  # 0.9.8 branch fixed in 0.9.8s
        ("0.9.8r", D_4576, True),
        ("1.0.0e", D_4576, True),
        ("1.0.0f", D_4576, False),
        ("0.9.8zh", D_4044, False),  # a 3.0-only bug
        ("3.0.0", D_4044, True),
        ("0.9.8zh", D_2108, True),  # "before 1.0.1o" has no lower bound
        ("1.0.2b", D_2108, True),
        ("1.0.1f", D_HEARTBLEED, True),
        ("1.0.2a", D_HEARTBLEED, False),
        ("2.4.1", "A flaw was found in the parser 2.4.x and later.", True),
        ("1.2.3", "OpenSSL 1.1.1k and earlier mishandles X.", False),
        ("1.2.3", "A buffer overflow allows remote attackers to execute code.", None),  # no version info
    ],
)
def test_description_agrees(version, text, expected):
    assert description_agrees(version, text) is expected


# Real descriptions that an earlier, naive parser misread; each must keep the match.
@pytest.mark.parametrize(
    "version, text, ceiling",
    [
        ("7.84.0", "A use after free vulnerability exists in curl <7.87.0. Curl can be asked to tunnel.", "7.87.0"),
        (
            "2.30",
            "A use-after-free vulnerability introduced in glibc upstream version 2.14 was found in the way the tilde "
            "expansion was carried out. This was fixed in version 2.32.",
            "2.32.0",
        ),
        (
            "0.6.10",
            "Both hostapd with SAE support and wpa_supplicant with SAE support prior to and including version 2.4 are affected.",
            "2.4",
        ),
        ("2.30", "An exploitable signed comparison vulnerability exists in the ARMv7 memcpy() of GNU glibc 2.30.9000.", "2.31"),
        # NVD typo: "1.3.7" means 1.37; the description then contradicts NVD's own range, so it is ignored
        ("1.24.1", "BusyBox wget thru 1.3.7 accepted raw CR (0x0D)/LF (0x0A) and other C0 control bytes.", "1.37.0"),
    ],
)
def test_description_misreads_do_not_downgrade(version, text, ceiling):
    assert description_agrees(version, text, ceiling) is not False


def test_release_branch():
    assert release_branch("0.9.8zh") == (0, 9, 8)
    assert release_branch("4.19.183") == (4, 19)
    assert release_branch("2.30") == (2, 30)


def test_fixed_in_branch():
    ranges = [Range("*", None, None, "0.9.8r", None), Range("*", None, None, "1.0.0e", None)]
    assert fixed_in_branch("0.9.8zh", ranges) == "0.9.8r"
    assert fixed_in_branch("0.9.8q", ranges) is None
    assert fixed_in_branch("1.0.0d", ranges) is None
    # kernel-style maintenance lines
    kernel = [Range("*", None, None, None, "4.19.150"), Range("*", None, None, None, "5.4.70")]
    assert fixed_in_branch("4.19.183", kernel) == "4.19.150"
    assert fixed_in_branch("4.14.300", kernel) is None


def test_platform_only():
    assert platform_only("A DLL hijacking issue in OpenSSL on Windows allows ...") == "Windows"
    assert platform_only("A heap overflow in libfoo allows remote attackers ...") is None


@pytest.fixture
def db(tmp_path):
    records = [
        # NVD folded two branches into open ranges; 0.9.8zh is past its branch's ceiling
        cve("CVE-2011-4576", [match(OPENSSL, versionEndIncluding="0.9.8r"), match(OPENSSL, versionEndIncluding="1.0.0e")], description=D_4576),
        # wrong range: a 3.0-only bug listed as "* <= 1.0.2"
        cve("CVE-2021-4044", [match(OPENSSL, versionEndIncluding="1.0.2"), match("cpe:2.3:a:openssl:openssl:3.0.0:*:*:*:*:*:*:*")], description=D_4044),
        # legitimate open range
        cve("CVE-2016-2108", [match(OPENSSL, versionEndIncluding="1.0.1n")], description=D_2108),
        cve("CVE-2099-1000", [match(OPENSSL, versionEndExcluding="9.0")], description="Something in OpenSSL is disputed.", tags=["disputed"]),
        cve("CVE-2099-1001", [match(OPENSSL, versionEndExcluding="9.0")], description="OpenSSL on Windows loads a DLL from the current directory."),
        # explicit lower bound: trusted even if the description is vague about versions
        cve("CVE-2099-1002", [match(OPENSSL, versionStartIncluding="0.9.8", versionEndExcluding="0.9.8zz")], description="OpenSSL 3.0.0 is affected."),
    ]
    with VulnDB(str(tmp_path / "db.sqlite")) as handle:
        handle.upsert(records)
        yield handle


def test_noisy_ranges_are_downgraded_not_dropped(db):
    hits = match_component(db, Component("openssl", "0.9.8zh", vendor="openssl"))
    confidence = {cve: m.confidence for cve, m in hits.items()}
    assert confidence == {
        "CVE-2011-4576": "low",
        "CVE-2021-4044": "low",
        "CVE-2016-2108": "high",
        "CVE-2099-1000": "low",
        "CVE-2099-1001": "low",
        "CVE-2099-1002": "high",
    }
    assert "ends at 0.9.8r" in hits["CVE-2011-4576"].reasons[0]
    assert "description" in hits["CVE-2021-4044"].reasons[0]
    assert "disputes" in hits["CVE-2099-1000"].reasons[0]
    assert "Windows" in hits["CVE-2099-1001"].reasons[0]


def test_exact_version_rows_are_trusted(db):
    hits = match_component(db, Component("openssl", "3.0.0", vendor="openssl"))
    assert hits["CVE-2021-4044"].confidence == "high"
