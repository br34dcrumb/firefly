import os
import tarfile

import pytest

from firefly.safety import ExtractionLimitError, is_within, rebase_absolute_link, safe_extract_tar

from conftest import add_bytes, add_dir, symlinks_supported


def _tar(path, build):
    with tarfile.open(path, "w") as tar:
        build(tar)
    return path


def test_path_traversal_members_are_not_written_outside(tmp_path):
    archive = _tar(
        tmp_path / "evil.tar",
        lambda t: (
            add_bytes(t, "../escaped.txt", b"x"),
            add_bytes(t, "a/../../escaped2.txt", b"x"),
            add_bytes(t, "ok.txt", b"fine"),
        ),
    )
    dest = tmp_path / "out"
    stats = safe_extract_tar(str(archive), str(dest))
    assert (dest / "ok.txt").read_bytes() == b"fine"
    assert not (tmp_path / "escaped.txt").exists()
    assert not (tmp_path / "escaped2.txt").exists()
    assert len(stats.skipped) == 2


def test_absolute_member_names_stay_inside(tmp_path):
    archive = _tar(tmp_path / "abs.tar", lambda t: add_bytes(t, "/abs-escape.txt", b"x"))
    dest = tmp_path / "out"
    safe_extract_tar(str(archive), str(dest))
    # data filter strips the leading slash: the file lands inside dest
    assert (dest / "abs-escape.txt").exists()


def test_symlink_escape_then_write_through_is_blocked(tmp_path):
    if not symlinks_supported(tmp_path):
        pytest.skip("symlinks not available")
    outside = tmp_path / "outside"
    outside.mkdir()

    def build(t):
        link = tarfile.TarInfo("link")
        link.type = tarfile.SYMTYPE
        link.linkname = "../outside"
        t.addfile(link)
        add_bytes(t, "link/pwned.txt", b"x")

    archive = _tar(tmp_path / "sym.tar", build)
    safe_extract_tar(str(archive), str(tmp_path / "out"))
    assert not (outside / "pwned.txt").exists()


def test_absolute_symlink_is_rebased_into_root(tmp_path):
    if not symlinks_supported(tmp_path):
        pytest.skip("symlinks not available")

    def build(t):
        add_dir(t, "bin")
        add_bytes(t, "bin/busybox", b"bb")
        link = tarfile.TarInfo("bin/sh")
        link.type = tarfile.SYMTYPE
        link.linkname = "/bin/busybox"
        t.addfile(link)

    dest = tmp_path / "out"
    safe_extract_tar(str(_tar(tmp_path / "abs.tar", build), ), str(dest))
    assert os.readlink(dest / "bin" / "sh") == "busybox"
    assert is_within(str(dest), str(dest / "bin" / "sh"))


def test_rebase_absolute_link():
    assert rebase_absolute_link("bin/sh", "/bin/busybox") == "busybox"
    assert rebase_absolute_link("usr/bin/env", "/bin/busybox") == "../../bin/busybox"
    assert rebase_absolute_link("var", "/tmp") == "tmp"
    # cannot climb above the root
    assert rebase_absolute_link("etc/x", "/../../../etc/shadow") == "shadow"


def test_device_files_are_skipped(tmp_path):
    def build(t):
        dev = tarfile.TarInfo("dev/mem")
        dev.type = tarfile.CHRTYPE
        dev.devmajor, dev.devminor = 1, 1
        t.addfile(dev)

    stats = safe_extract_tar(str(_tar(tmp_path / "dev.tar", build)), str(tmp_path / "out"))
    assert not (tmp_path / "out" / "dev" / "mem").exists()
    assert any("special file" in s for s in stats.skipped)


def test_setuid_bits_are_recorded_but_not_applied(tmp_path):
    archive = _tar(tmp_path / "suid.tar", lambda t: add_bytes(t, "su", b"x", mode=0o4755))
    stats = safe_extract_tar(str(archive), str(tmp_path / "out"))
    assert stats.original_modes["su"] & 0o4000
    if os.name == "posix":
        assert not os.stat(tmp_path / "out" / "su").st_mode & 0o4000


def test_size_limit(tmp_path):
    archive = _tar(tmp_path / "big.tar", lambda t: add_bytes(t, "big", b"x" * 2048))
    with pytest.raises(ExtractionLimitError):
        safe_extract_tar(str(archive), str(tmp_path / "out"), max_bytes=1024)
