import io
import os
import tarfile

import pytest


def fake_elf(strings: list[bytes], machine: int = 0x28, elf_type: int = 2) -> bytes:
    """A minimal little-endian 32-bit ELF header followed by embedded strings."""
    ident = b"\x7fELF" + bytes([1, 1, 1]) + bytes(9)
    header = ident + elf_type.to_bytes(2, "little") + machine.to_bytes(2, "little") + bytes(32)
    return header + b"\x00\x01\x02" + b"\x00\xff\x00".join(strings) + b"\x00"


def add_bytes(tar: tarfile.TarFile, name: str, data: bytes, mode: int = 0o755) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    tar.addfile(info, io.BytesIO(data))


def add_dir(tar: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    tar.addfile(info)


BUSYBOX = fake_elf([b"BusyBox v1.31.1 (2020-01-01 00:00:00 UTC) multi-call binary.", b"Usage: busybox"])
LIBSSL = fake_elf([b"OpenSSL 1.1.1k  25 Mar 2021", b"SSLv3 part of OpenSSL"], elf_type=3)
DROPBEAR = fake_elf([b"Dropbear sshd v2019.78"])


@pytest.fixture
def rootfs_tar(tmp_path):
    """A small synthetic router rootfs packed as a tarball."""
    path = tmp_path / "rootfs.tar.gz"
    with tarfile.open(path, "w:gz") as tar:
        for d in ("bin", "etc", "lib", "usr", "usr/sbin", "var", "tmp"):
            add_dir(tar, d)
        add_bytes(tar, "bin/busybox", BUSYBOX)
        add_bytes(tar, "lib/libssl.so.1.1", LIBSSL)
        add_bytes(tar, "usr/sbin/dropbear", DROPBEAR, mode=0o4755)
        add_bytes(tar, "etc/passwd", b"root:x:0:0:root:/root:/bin/sh\n", mode=0o644)
        add_bytes(tar, "etc/init.sh", b"#!/bin/sh\necho hi\n")
        # A hostile file name: the old implementation passed paths to a shell.
        add_bytes(tar, "usr/sbin/$(touch PWNED)`touch PWNED2`;touch PWNED3", BUSYBOX)
    return path


@pytest.fixture(autouse=True)
def _isolated_cwd(tmp_path, monkeypatch):
    work = tmp_path / "cwd"
    work.mkdir()
    monkeypatch.chdir(work)
    return work


def symlinks_supported(tmp_path) -> bool:
    try:
        os.symlink("target", tmp_path / "probe-link")
    except (OSError, NotImplementedError):
        return False
    os.remove(tmp_path / "probe-link")
    return True
