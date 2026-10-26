import json
import os

import pytest

from firefly.analyzers.entropy import EntropyAnalyzer, shannon_entropy
from firefly.analyzers import ScanContext
from firefly.cli import main
from firefly.extract import ExtractionError, extract, find_rootfs_candidates
from firefly.inventory import Inventory, parse_elf_header
from firefly.models import FileKind
from firefly.pipeline import ScanOptions, scan

from conftest import BUSYBOX, symlinks_supported


def test_parse_elf_header():
    info = parse_elf_header(BUSYBOX[:64])
    assert (info.bits, info.endian, info.machine, info.elf_type) == (32, "little", "arm", "exec")
    assert parse_elf_header(b"#!/bin/sh\n") is None


def test_scan_rootfs_tarball(rootfs_tar, tmp_path, _isolated_cwd):
    result = scan(str(rootfs_tar), ScanOptions(output_dir=str(tmp_path / "out"), jobs=1))
    assert result.errors == []
    found = {(c.product, c.version) for c in result.components}
    assert {("busybox", "1.31.1"), ("openssl", "1.1.1k"), ("dropbear_ssh", "2019.78")} <= found
    assert result.inventory["elf"] == 4
    assert result.inventory["script"] == 1
    # the hostile file name was analysed like any other and nothing executed it
    busybox = next(c for c in result.components if c.product == "busybox")
    assert any("PWNED" in p for p in busybox.paths)
    assert not any(name.startswith("PWNED") for name in os.listdir(_isolated_cwd))
    assert not any(name.startswith("PWNED") for name in os.listdir(tmp_path))


def test_setuid_mode_survives_into_inventory(rootfs_tar, tmp_path):
    ext = extract(str(rootfs_tar), str(tmp_path / "work"))
    inv = Inventory.build(ext.scan_root, jobs=2, original_modes=ext.original_modes)
    assert inv.get("usr/sbin/dropbear").mode & 0o4000
    assert inv.get("etc/passwd").kind is FileKind.DATA


def test_directory_input_and_rootfs_detection(tmp_path):
    root = tmp_path / "fw" / "squashfs-root"
    for d in ("bin", "etc", "lib", "usr", "sbin"):
        (root / d).mkdir(parents=True)
    (root / "usr" / "bin").mkdir()
    (root / "bin" / "busybox").write_bytes(BUSYBOX)
    assert find_rootfs_candidates(str(tmp_path / "fw")) == [str(root)]
    ext = extract(str(tmp_path / "fw"), str(tmp_path / "work"))
    assert ext.scan_root == str(root)


def test_symlinks_are_not_followed(tmp_path):
    if not symlinks_supported(tmp_path):
        pytest.skip("symlinks not available")
    secret = tmp_path / "host-secret"
    secret.write_text("do not read")
    root = tmp_path / "root"
    root.mkdir()
    os.symlink(secret, root / "passwd")
    inv = Inventory.build(str(root))
    rec = inv.get("passwd")
    assert rec.kind is FileKind.SYMLINK and rec.sha256 is None


def test_raw_firmware_without_backend_reports_error(tmp_path, monkeypatch):
    monkeypatch.setattr("firefly.extract.shutil.which", lambda name: None)
    blob = tmp_path / "fw.bin"
    blob.write_bytes(os.urandom(256 * 1024))
    with pytest.raises(ExtractionError):
        extract(str(blob), str(tmp_path / "work"))
    # the scan still runs analyzers that only need the raw image
    result = scan(str(blob), ScanOptions(output_dir=str(tmp_path / "out"), jobs=1))
    assert result.errors[0]["stage"] == "extract"
    assert any(f.analyzer == "entropy" for f in result.findings)


def test_entropy():
    assert shannon_entropy(b"\x00" * 100) == 0.0
    assert abs(shannon_entropy(bytes(range(256))) - 8.0) < 1e-9


def test_entropy_quiet_on_low_entropy_image(tmp_path):
    blob = tmp_path / "plain.bin"
    blob.write_bytes(b"A" * 128 * 1024)
    out = EntropyAnalyzer().run(ScanContext(str(blob), str(tmp_path), 1))
    assert out.findings == []
    assert out.artifacts["overall"] == 0.0


def test_cli_writes_json(rootfs_tar, tmp_path, capsys):
    rc = main(["scan", str(rootfs_tar), "-o", str(tmp_path / "out"), "-j", "1", "-q"])
    assert rc == 0
    report = capsys.readouterr().out.strip()
    data = json.loads(open(report, encoding="utf-8").read())
    assert data["schema"] == 1
    assert any(c["cpe"].startswith("cpe:2.3:a:openssl:openssl:1.1.1k") for c in data["components"])


def test_parallel_matches_serial(rootfs_tar, tmp_path, monkeypatch):
    monkeypatch.setattr("firefly.analyzers.versions.PARALLEL_MIN_TASKS", 0)
    serial = scan(str(rootfs_tar), ScanOptions(output_dir=str(tmp_path / "a"), jobs=1))
    parallel = scan(str(rootfs_tar), ScanOptions(output_dir=str(tmp_path / "b"), jobs=4))
    key = lambda r: sorted((c.product, c.version, tuple(sorted(c.paths))) for c in r.components)
    assert key(serial) == key(parallel)
