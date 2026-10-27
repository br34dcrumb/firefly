# Firefly

Fast, safe static analysis of firmware images: unpack the image, inventory
every file, identify the software inside it, and report what needs attention.
Firefly takes inspiration from [EMBA](https://github.com/e-m-b-a/emba) but is
built as a single-pass, parallel Python pipeline that treats every byte of the
firmware as hostile input.

## Quick start

The Docker image bundles the full extraction tool-chain (unblob, sasquatch,
7z, …) and runs as an unprivileged user. Network access is not needed, so
switch it off:

```sh
docker build -t firefly .
docker run --rm --network none \
  -v "$PWD/samples:/data/in:ro" -v "$PWD/firefly-out:/data/out" \
  firefly scan /data/in/router.bin
```

Without Docker (Python 3.11+):

```sh
pip install -e ".[extract]"   # unblob needs Linux/macOS plus its external tools
firefly scan router.bin
```

Already-extracted root filesystems need no extraction tools at all, on any OS:

```sh
firefly scan rootfs.tar.gz
firefly scan path/to/squashfs-root/
```

Each scan writes `firefly-out/<name>_<sha256[:12]>/` containing `firefly.json`
(full results) and `sbom.cdx.json` (CycloneDX 1.6 SBOM with vulnerabilities),
and prints a summary.

## Vulnerability database

CVE matching is fully offline. The software list of a firmware image can
identify an unreleased product, so scans never send it anywhere. Build the
local database once (about 115 MB download), then refresh it daily (about 9 MB):

```sh
firefly db update      # full build first time, then incremental
firefly db info
```

Data comes from the daily NVD mirror at
[fkie-cad/nvd-json-data-feeds](https://github.com/fkie-cad/nvd-json-data-feeds),
including CISA KEV (known exploited) flags. Every file is checked against the
SHA-256 digest GitHub publishes for it before it is parsed. For air-gapped
hosts, copy the feeds over and run `firefly db import CVE-*.json.xz`. The
database lives in `~/.cache/firefly/vulndb.sqlite` (override with `--db` or
`$FIREFLY_DB`). With Docker, mount a volume there so it persists between runs.

## Pipeline

```
input ─▶ extract ─▶ inventory ─▶ analyzers ─▶ firefly.json
         unblob     walk once,    entropy      hardening    sbom.cdx.json
         binwalk    hash, type    versions     dangerfns
         tarfile    every file    cves         credentials
                                  (plugins)    accounts, services
```

| Stage | What it does |
|---|---|
| `extract` | Raw images go through unblob (or binwalk); tarballs are unpacked with a hardened extractor; directories are used in place. Root filesystems are located automatically. |
| `inventory` | One parallel walk over the tree: SHA-256, ELF header parsing (arch, type), script detection. Symlinks are recorded, never followed. |
| `entropy` | 4 KiB block entropy profile of the raw image; flags likely-encrypted firmware. |
| `versions` | Matches ~730 identifier rules (`firefly/data/bin_version_strings.cfg`) against strings of every ELF, in parallel. Names are mapped to NVD vendor/product pairs, duplicates merged, and applet strings inside BusyBox/Toybox are not reported as separate software. |
| `cves` | Matches components against the local NVD database with firmware-aware version comparison (`0.9.8zh`, `1.0.1g`, `1.0rc1`, `2.0.10-4`). Each hit carries CVSS, CWE, CISA KEV status and a confidence level. |
| `hardening` | Parses each ELF (no external tools) for exploit mitigations: NX, PIE, RELRO, stack canary. Missing NX is reported per binary; uniform build-default weaknesses are summarized. Network-facing binaries are rated higher. |
| `dangerfns` | Reports memory-unsafe and command-exec functions a binary actually *imports* (`system`, `popen`, `gets`, `strcpy`, …), from the dynamic symbol table rather than string matching. |
| `credentials` | Finds hardcoded private keys, passwords and API tokens. **Every value is redacted** before it reaches a finding — reports carry a masked preview, a length and a short fingerprint, never a usable secret. |
| `accounts` | Reads `/etc/passwd` and `/etc/shadow` (and read-only overlays like `/rom/etc`) for empty passwords, extra UID-0 accounts and weak password-hash *algorithms* (DES, MD5). It never attempts to recover or crack a password; hash values are redacted. |
| `services` | Flags insecure services started at boot (telnet, rsh, anonymous/writable FTP, SSH permitting root or empty passwords) and the presence of insecure service binaries. |

NVD's version ranges are often broader than the advisories behind them, so the
`cves` analyzer cross-checks every match that relies only on an open-ended range
(`* <= X`) before trusting it:

- **Release branches:** if NVD lists `<= 0.9.8r` and `<= 1.0.0e`, then 0.9.8zh
  is past its own branch's fix, even though `<= 1.0.0e` technically contains it.
- **Description:** the human-written description ("before 0.9.8s and 1.x
  before 1.0.0f", "Fixed in OpenSSL 3.0.1 (Affected 3.0.0)") must cover the
  version. It is ignored when it contradicts NVD's own range, which is usually
  a typo.
- **Disputed** CVEs and ones that only apply **on Windows/macOS** are flagged.

Doubtful matches are never dropped. They get `low` confidence with
`confidence_reasons` in `firefly.json`, `analysis.state: in_triage` in the SBOM,
and are hidden from the console unless you pass `--min-confidence low`.

List analyzers with `firefly analyzers`. Run a subset with `--only versions` or
`--skip entropy`. Third-party analyzers subclass `firefly.analyzers.Analyzer`
and register under the `firefly.analyzers` entry-point group.

## Safety model

Firmware is attacker-controlled. Firefly:

- never builds shell command strings; external tools get argument lists;
- extracts tarballs with the stdlib `data` filter plus firmware-specific rules:
  no path traversal, no links escaping the root, absolute symlinks rebased
  chroot-style, device files skipped, size/member limits (anti zip-bomb);
- records setuid/setgid bits for analysis but never applies them to disk;
- never follows symlinks while inventorying, so a firmware `etc/passwd ->
  /etc/passwd` cannot make it read the host's files;
- isolates analyzer failures so one bad file cannot abort a scan;
- **redacts every secret** it reports, and never attempts to recover, guess or
  crack a password — it reports only the hash *algorithm* and account policy.

## Development

```sh
python -m venv .venv && .venv/bin/pip install -e ".[dev]"
.venv/bin/pytest
```

Keep firmware samples in `samples/` (git-ignored). Never commit firmware.

## Licensing note

`bin_version_strings.cfg` comes from EMBA, which is licensed GPL-3.0. Firefly
must therefore be distributed under GPL-3.0-compatible terms, or that rule set
must be replaced before Firefly ships under another licence.
