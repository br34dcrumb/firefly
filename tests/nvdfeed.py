"""Builders for synthetic NVD feed records used by the tests."""

import json
import lzma


def cve(cve_id, matches, severity="HIGH", score=7.5, kev=None, status="Analyzed", and_config=False, version="3.1", description=None, tags=()):
    nodes = [{"operator": "OR", "negate": False, "cpeMatch": matches}]
    config = {"nodes": nodes}
    if and_config:
        config["operator"] = "AND"
        nodes.append(
            {"operator": "OR", "negate": False, "cpeMatch": [{"vulnerable": False, "criteria": "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*"}]}
        )
    key = {"3.1": "cvssMetricV31", "4.0": "cvssMetricV40", "2.0": "cvssMetricV2"}[version]
    rec = {
        "id": cve_id,
        "published": "2021-08-24T15:15:09.133",
        "lastModified": "2024-01-01T00:00:00.000",
        "vulnStatus": status,
        "cveTags": [{"sourceIdentifier": "cve@mitre.org", "tags": list(tags)}] if tags else [],
        "descriptions": [{"lang": "en", "value": description or f"Description of {cve_id}"}],
        "metrics": {
            key: [
                {
                    "source": "nvd@nist.gov",
                    "type": "Primary",
                    "cvssData": {"version": version, "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "baseScore": score, "baseSeverity": severity},
                }
            ]
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-120"}]}],
        "configurations": [config],
    }
    if kev:
        rec["cisaExploitAdd"] = kev
        rec["cisaVulnerabilityName"] = f"{cve_id} exploited"
    return rec


def match(criteria, **bounds):
    return {"vulnerable": True, "criteria": criteria, **bounds}


SAMPLE_RECORDS = [
    cve(
        "CVE-2021-3711",
        [match("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", versionStartIncluding="1.1.1", versionEndExcluding="1.1.1l")],
        severity="CRITICAL",
        score=9.8,
    ),
    cve("CVE-2014-0160", [match("cpe:2.3:a:openssl:openssl:*:*:*:*:*:*:*:*", versionStartIncluding="1.0.1", versionEndExcluding="1.0.1g")]),
    cve("CVE-2099-0001", [match("cpe:2.3:a:busybox:busybox:1.31.1:*:*:*:*:*:*:*")], severity="MEDIUM", score=5.5, kev="2099-01-01"),
    cve(
        "CVE-2099-0002",
        [match("cpe:2.3:a:dropbear_ssh_project:dropbear_ssh:*:*:*:*:*:*:*:*", versionEndExcluding="2020.79")],
        and_config=True,
    ),
    # "all versions" entries are ignored
    cve("CVE-2099-0003", [match("cpe:2.3:a:busybox:busybox:*:*:*:*:*:*:*:*")]),
    cve("CVE-2099-0004", [match("cpe:2.3:a:openssl:openssl:1.1.1k:*:*:*:*:*:*:*")], status="Rejected"),
]


def write_feed(path, records, layout="mirror"):
    if layout == "mirror":
        doc = {"timestamp": "2026-10-26T00:00:00", "cve_count": len(records), "cve_items": records}
    else:  # NVD API 2.0 layout
        doc = {"resultsPerPage": len(records), "format": "NVD_CVE", "vulnerabilities": [{"cve": r} for r in records]}
    data = json.dumps(doc).encode()
    if str(path).endswith(".xz"):
        data = lzma.compress(data)
    with open(path, "wb") as fh:
        fh.write(data)
    return path
