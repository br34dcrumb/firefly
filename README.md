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

Each scan writes `firefly-out/<name>_<sha256[:12]>/firefly.json` and prints a summary.

## Pipeline

```
input ─▶ extract ─▶ inventory ─▶ analyzers ─▶ firefly.json
         unblob     walk once,    entropy
         binwalk    hash, type    versions
         tarfile    every file    (plugins)
```

| Stage | What it does |
|---|---|
| `extract` | Raw images go through unblob (or binwalk); tarballs are unpacked with a hardened extractor; directories are used in place. Root filesystems are located automatically. |
| `inventory` | One parallel walk over the tree: SHA-256, ELF header parsing (arch, type), script detection. Symlinks are recorded, never followed. |
| `entropy` | 4 KiB block entropy profile of the raw image; flags likely-encrypted firmware. |
| `versions` | Matches ~730 identifier rules (`firefly/data/bin_version_strings.cfg`) against strings of every ELF, in parallel, and emits components with CPEs. |

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
- isolates analyzer failures so one bad file cannot abort a scan.

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
