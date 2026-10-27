"""Locate and (best-effort) cross-compile the runtime interception shim.

The shim (``shim/libfirefly_preload.c``) must be built for the *target*
architecture, which needs a cross toolchain Firefly cannot assume is present.
So shim use is opt-in: the stage runs shim-less unless a prebuilt ``.so`` is
supplied or a matching cross compiler is found.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess

log = logging.getLogger(__name__)

_SHIM_DIR = os.path.join(os.path.dirname(__file__), "shim")
_SOURCE = os.path.join(_SHIM_DIR, "libfirefly_preload.c")

# firefly machine name -> candidate cross-compiler prefixes (first that exists wins)
_CROSS_PREFIXES: dict[str, tuple[str, ...]] = {
    "arm": ("arm-linux-gnueabi-", "arm-linux-gnueabihf-"),
    "aarch64": ("aarch64-linux-gnu-",),
    "mips": ("mips-linux-gnu-",),
    "x86": ("i686-linux-gnu-", ""),
    "x86_64": ("x86_64-linux-gnu-", ""),
    "ppc": ("powerpc-linux-gnu-",),
    "riscv": ("riscv64-linux-gnu-",),
}


def source_path() -> str:
    return _SOURCE


def _cross_compiler(machine: str, endian: str) -> str | None:
    prefixes = list(_CROSS_PREFIXES.get(machine, ()))
    if machine == "mips" and endian == "little":
        prefixes = ["mipsel-linux-gnu-", *prefixes]
    for prefix in prefixes:
        cc = shutil.which(f"{prefix}gcc")
        if cc:
            return cc
    return None


def build_for(machine: str, endian: str, out_dir: str) -> str | None:
    """Try to cross-compile the shim for ``machine``; return its path or None."""
    cc = _cross_compiler(machine, endian)
    if not cc or not os.path.exists(_SOURCE):
        return None
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, f"libfirefly_preload-{machine}-{endian}.so")
    cmd = [cc, "-shared", "-fPIC", "-O2", "-o", out, _SOURCE, "-ldl"]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        log.debug("shim build failed for %s: %s", machine, exc)
        return None
    if proc.returncode != 0 or not os.path.exists(out):
        log.debug("shim compiler exited %d: %s", proc.returncode, proc.stderr.strip())
        return None
    return out
