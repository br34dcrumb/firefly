"""Cryptographic posture: weak primitives, certificate quality, secure boot.

Checks, all offline and failure-isolated:

* **Weak primitives** — which binaries reference broken ciphers/hashes (DES,
  RC4, MD4/MD2, ECB mode, and the legacy MD5/SHA-1 hashes), read from the ELF
  symbol tables :mod:`firefly.elf` already parses. Symbol presence is not proof
  of security-sensitive use, so findings are aggregated and rated modestly.
* **Certificate quality** — small RSA keys, broken signature hashes and expired
  validity, via the dependency-free :mod:`firefly.x509` reader.
* **Secure-boot posture** — whether any boot-integrity mechanism (dm-verity,
  IMA/EVM, signed FIT images) is visible in the extracted filesystem, **and**
  whether it is *weakened or bypassed*: a bootloader/kernel configuration that
  disables image verification, drops to a root shell, leaves IMA non-enforcing,
  or ships FIT signing support without making it mandatory. Presence of a
  mechanism that is then defeated is worse than its plain absence.
* **Predictable entropy** — a random seed file shipped inside the image, which
  gives every device the same "random" state at first boot.

Hardcoded *private keys* are the credentials analyzer's job; this one judges the
cryptography around them, and never handles a raw secret.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from datetime import datetime, timezone

from firefly import x509
from firefly.analyzers import Analyzer, AnalyzerResult, ScanContext
from firefly.analyzers.hardening import is_network_facing
from firefly.elf import parse_file
from firefly.models import FileKind, Finding, Severity

# Broken or rarely-legitimate primitives, by family. ECB is matched on the
# OpenSSL EVP cipher-mode symbols rather than a bare substring.
WEAK_PRIMITIVES: dict[str, frozenset[str]] = {
    "DES/3DES": frozenset({"DES_set_key", "DES_set_key_unchecked", "DES_ecb_encrypt", "DES_ncbc_encrypt",
                           "DES_cbc_encrypt", "DES_ede3_cbc_encrypt", "EVP_des_cbc", "EVP_des_ecb",
                           "EVP_des_ede3_cbc", "EVP_des_ede3"}),
    "RC4": frozenset({"RC4", "RC4_set_key", "EVP_rc4"}),
    "MD4": frozenset({"MD4", "MD4_Init", "MD4_Update", "MD4_Final"}),
    "MD2": frozenset({"MD2", "MD2_Init"}),
    "ECB mode": frozenset({"EVP_aes_128_ecb", "EVP_aes_192_ecb", "EVP_aes_256_ecb", "EVP_bf_ecb", "EVP_des_ecb"}),
}
# Ubiquitous legacy hashes: reported once, at low severity, because they are
# often used for non-security checksums.
LEGACY_HASH = frozenset({"MD5", "MD5_Init", "MD5_Update", "MD5_Final", "SHA1", "SHA1_Init", "SHA1_Update", "SHA1_Final"})

# Secure-boot / integrity markers, searched as bytes in filesystem files.
BOOT_MARKERS: dict[str, tuple[bytes, ...]] = {
    "dm-verity": (b"dm-verity", b"veritysetup", b"veritytab"),
    "IMA/EVM": (b"ima_policy", b"ima_appraise", b"CONFIG_IMA="),
    "signed FIT image": (b"key-name-hint", b"CONFIG_FIT_SIGNATURE"),
}


@dataclass(frozen=True)
class _Bypass:
    label: str
    severity: Severity
    patterns: tuple[bytes, ...]
    advice: str


# Signs that a boot-integrity / secure-boot mechanism is disabled or bypassable.
# Matched as bytes in bootloader environments, boot scripts and kernel-config
# fragments. Conservative, specific byte strings to keep false positives low.
BYPASS_CHECKS: tuple[_Bypass, ...] = (
    _Bypass("U-Boot image verification disabled (verify=no)", Severity.HIGH,
            (b"verify=no", b"verify = no"),
            "U-Boot is told not to verify image signatures, so unsigned kernel/FIT images will boot"),
    _Bypass("root shell at boot (init=/bin/sh)", Severity.HIGH,
            (b"init=/bin/sh", b"init=/bin/bash", b"rdinit=/bin/sh"),
            "a boot argument drops straight to an unauthenticated root shell, bypassing the normal init"),
    _Bypass("IMA appraisal not enforced (ima_appraise=off/fix)", Severity.MEDIUM,
            (b"ima_appraise=off", b"ima_appraise=fix"),
            "IMA is present but not enforcing, so modified files are not blocked at access time"),
    _Bypass("secure boot explicitly disabled", Severity.MEDIUM,
            (b"secure_boot=0", b"secureboot=off", b"CONFIG_SECURE_BOOT=n", b"SECURE_BOOT=n"),
            "a build or runtime flag turns verified boot off"),
)

# A non-negative U-Boot bootdelay leaves the boot interruptible at the console,
# where bootargs can be edited to defeat verified boot (-1 disables the prompt).
_BOOTDELAY_RE = re.compile(rb"bootdelay\s*=\s*(\d+)")
_FIT_SIG = (b"CONFIG_FIT_SIGNATURE=y", b"CONFIG_FIT_SIGNATURE=1")
_FIT_MANDATORY = (b"CONFIG_FIT_SIGNATURE_MANDATORY",)

# Shipping a seed file bakes the same entropy into every device; basenames only.
SEED_FILENAMES = frozenset({"random-seed", "urandom-seed", "prng_seed", "entropy", ".rnd", "poolseed"})

MAX_FILE = 4 * 1024**2
RSA_MIN_BITS = 2048


def _scannable(rec) -> bool:
    if rec.kind in (FileKind.SYMLINK, FileKind.OTHER, FileKind.ELF):
        return False
    return 0 < rec.size <= MAX_FILE


class CryptoAnalyzer(Analyzer):
    name = "crypto"
    description = "Weak cryptography, certificate quality and secure-boot posture"

    def run(self, ctx: ScanContext, now: datetime | None = None) -> AnalyzerResult:
        assert ctx.inventory is not None
        now = now or datetime.now(timezone.utc)
        result = AnalyzerResult()

        # family -> {"paths": [...], "exposed": bool}
        prim: dict[str, dict] = {}
        legacy_paths: list[str] = []
        weak_key: list[str] = []
        weak_sig: list[str] = []
        expired: list[str] = []
        cert_count = 0
        boot_found: dict[str, str] = {}  # mechanism -> first path it was seen at
        bypass_found: dict[str, tuple[str, Severity, str]] = {}  # label -> (path, severity, advice)
        seed_paths: list[str] = []
        fit_sig = fit_mandatory = False

        for rec in ctx.inventory:
            # A shipped RNG seed file is predictable regardless of file type
            # (a raw seed blob is usually inventoried as OTHER); never follow a symlink.
            if rec.kind is not FileKind.SYMLINK and os.path.basename(rec.path).lower() in SEED_FILENAMES:
                seed_paths.append(rec.path)

            if rec.kind is FileKind.ELF:
                info = parse_file(ctx.inventory.abspath(rec), rec.size)
                if info is None:
                    continue
                syms = info.imported_functions | info.defined_functions
                exposed = rec.is_executable_code and is_network_facing(rec.path, info.imported_functions)
                for family, names in WEAK_PRIMITIVES.items():
                    if syms & names:
                        slot = prim.setdefault(family, {"paths": [], "exposed": False})
                        slot["paths"].append(rec.path)
                        slot["exposed"] = slot["exposed"] or exposed
                if syms & LEGACY_HASH:
                    legacy_paths.append(rec.path)
                continue

            if not _scannable(rec):
                continue
            try:
                with open(ctx.inventory.abspath(rec), "rb") as fh:
                    data = fh.read()
            except OSError:
                continue

            for cert in x509.parse_certificates(data):
                cert_count += 1
                if cert.key_type == "rsa" and cert.key_bits is not None and cert.key_bits < RSA_MIN_BITS:
                    weak_key.append(f"{rec.path} ({cert.key_bits}-bit RSA)")
                if cert.weak_sig:
                    weak_sig.append(f"{rec.path} ({cert.sig_alg})")
                if cert.not_after is not None and cert.not_after < now:
                    expired.append(f"{rec.path} (expired {cert.not_after.date().isoformat()})")

            for mechanism, markers in BOOT_MARKERS.items():
                if mechanism not in boot_found and any(mk in data for mk in markers):
                    boot_found[mechanism] = rec.path

            for check in BYPASS_CHECKS:
                if check.label not in bypass_found and any(p in data for p in check.patterns):
                    bypass_found[check.label] = (rec.path, check.severity, check.advice)
            m = _BOOTDELAY_RE.search(data)
            if m and "interruptible boot (non-negative U-Boot bootdelay)" not in bypass_found:
                bypass_found["interruptible boot (non-negative U-Boot bootdelay)"] = (
                    rec.path, Severity.MEDIUM,
                    f"bootdelay={m.group(1).decode()} leaves the boot interruptible at the console, where "
                    "bootargs can be edited to bypass verified boot (set bootdelay=-1 to disable the prompt)",
                )
            fit_sig = fit_sig or any(s in data for s in _FIT_SIG)
            fit_mandatory = fit_mandatory or any(s in data for s in _FIT_MANDATORY)

        if fit_sig and not fit_mandatory:
            bypass_found.setdefault(
                "FIT signature supported but not mandatory (CONFIG_FIT_SIGNATURE_MANDATORY unset)",
                (boot_found.get("signed FIT image", ""), Severity.MEDIUM,
                 "FIT signature verification is compiled in but not required, so an unsigned image can still boot"),
            )

        self._emit_primitives(result, prim, legacy_paths)
        self._emit_certs(result, weak_key, weak_sig, expired)
        self._emit_boot(result, boot_found)
        self._emit_bypass(result, bypass_found, bool(boot_found))
        self._emit_seed(result, seed_paths)

        result.artifacts = {
            "weak_primitive_families": sorted(prim),
            "legacy_hash_binaries": len(legacy_paths),
            "certificates": cert_count,
            "weak_cert_keys": len(weak_key),
            "weak_cert_signatures": len(weak_sig),
            "expired_certs": len(expired),
            "boot_integrity": sorted(boot_found),
            "secure_boot_bypass": sorted(bypass_found),
            "predictable_seed_files": len(seed_paths),
        }
        return result

    def _emit_primitives(self, result: AnalyzerResult, prim: dict[str, dict], legacy_paths: list[str]) -> None:
        for family in sorted(prim):
            paths = sorted(prim[family]["paths"])
            exposed = prim[family]["exposed"]
            result.findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{family} referenced by {len(paths)} binar{'y' if len(paths) == 1 else 'ies'}",
                    severity=Severity.HIGH if exposed else Severity.MEDIUM,
                    confidence="medium",
                    path=paths[0],
                    description=(
                        f"{len(paths)} binary/binaries reference {family}, a broken or deprecated primitive"
                        + (" (at least one is network-facing)" if exposed else "")
                        + ". Symbol presence does not prove it is used for security, but it warrants review. "
                        "See metadata for the full list."
                    ),
                    metadata={"family": family, "network_facing": exposed, "binaries": paths},
                )
            )
        if legacy_paths:
            result.findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"Legacy hash (MD5/SHA-1) referenced by {len(legacy_paths)} binaries",
                    severity=Severity.LOW,
                    confidence="medium",
                    path=sorted(legacy_paths)[0],
                    description=(
                        f"{len(legacy_paths)} binaries reference MD5 or SHA-1. These remain common for non-security "
                        "checksums, so this is informational; confirm they are not used for signatures or passwords. "
                        "See metadata for the full list."
                    ),
                    metadata={"binaries": sorted(legacy_paths)},
                )
            )

    def _emit_certs(self, result: AnalyzerResult, weak_key: list[str], weak_sig: list[str], expired: list[str]) -> None:
        if weak_key:
            result.findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{len(weak_key)} certificate(s) use an undersized RSA key (< {RSA_MIN_BITS}-bit)",
                    severity=Severity.MEDIUM,
                    confidence="high",
                    path=weak_key[0].split(" (", 1)[0],
                    description=(
                        f"{len(weak_key)} certificate(s) carry an RSA key smaller than {RSA_MIN_BITS} bits, which is "
                        "below current guidance and feasible to attack. See metadata for the list."
                    ),
                    metadata={"certificates": sorted(weak_key)},
                )
            )
        if weak_sig:
            result.findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{len(weak_sig)} certificate(s) signed with a broken hash (MD5/SHA-1)",
                    severity=Severity.MEDIUM,
                    confidence="high",
                    path=weak_sig[0].split(" (", 1)[0],
                    description=(
                        f"{len(weak_sig)} certificate(s) are signed with a deprecated algorithm; such signatures are "
                        "forgeable and the certificate should be reissued. See metadata for the list."
                    ),
                    metadata={"certificates": sorted(weak_sig)},
                )
            )
        if expired:
            result.findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"{len(expired)} expired certificate(s) shipped in the image",
                    severity=Severity.LOW,
                    confidence="high",
                    path=expired[0].split(" (", 1)[0],
                    description=(
                        f"{len(expired)} certificate(s) are past their validity window. If any is a trusted root or a "
                        "device identity certificate, TLS will fail or fall back insecurely. See metadata for the list."
                    ),
                    metadata={"certificates": sorted(expired)},
                )
            )

    def _emit_bypass(self, result: AnalyzerResult, bypass_found: dict[str, tuple[str, Severity, str]], mechanism_present: bool) -> None:
        for label in sorted(bypass_found):
            path, severity, advice = bypass_found[label]
            # A mechanism that is present but defeated is worse than its absence.
            if mechanism_present and severity is Severity.MEDIUM:
                severity = Severity.HIGH
            result.findings.append(
                Finding(
                    analyzer=self.name,
                    # "boot-integrity" in the title routes this to the right
                    # compliance category (integrity / secure update).
                    title=f"Secure-boot / boot-integrity weakened: {label}",
                    severity=severity,
                    confidence="medium",
                    path=path or None,
                    description=(
                        f"{advice}. "
                        + ("A boot-integrity mechanism is present but this defeats it. " if mechanism_present else "")
                        + "This was read from a shipped configuration/script; confirm it is the active boot path."
                    ),
                    metadata={"weakness": label, "secure_boot": True, "mechanism_present": mechanism_present},
                )
            )

    def _emit_seed(self, result: AnalyzerResult, seed_paths: list[str]) -> None:
        if not seed_paths:
            return
        result.findings.append(
            Finding(
                analyzer=self.name,
                title=f"Predictable RNG seed shipped in the image ({len(seed_paths)} file(s))",
                severity=Severity.MEDIUM,
                confidence="medium",
                path=sorted(seed_paths)[0],
                description=(
                    "A random-seed file is baked into the firmware image, so every device starts with the "
                    "same entropy pool at first boot — keys, nonces and session tokens generated before fresh "
                    "entropy is gathered are predictable. The seed should be generated per-device at first boot, "
                    "not shipped. See metadata for the full list."
                ),
                metadata={"seed_files": sorted(seed_paths)},
            )
        )

    def _emit_boot(self, result: AnalyzerResult, boot_found: dict[str, str]) -> None:
        if boot_found:
            result.findings.append(
                Finding(
                    analyzer=self.name,
                    title=f"Boot-integrity mechanism detected: {', '.join(sorted(boot_found))}",
                    severity=Severity.INFO,
                    confidence="medium",
                    description=(
                        "The filesystem references a boot-integrity mechanism. This does not confirm it is enabled or "
                        "correctly configured, only that support is present. See metadata for where each was seen."
                    ),
                    metadata={"mechanisms": boot_found},
                )
            )
        else:
            result.findings.append(
                Finding(
                    analyzer=self.name,
                    title="No boot-integrity mechanism detected (secure boot / dm-verity / IMA)",
                    severity=Severity.LOW,
                    confidence="low",
                    description=(
                        "No dm-verity, IMA/EVM or signed-FIT markers were found in the extracted filesystem, so "
                        "nothing appears to verify the firmware or rootfs at boot. A mechanism implemented entirely in "
                        "a bootloader partition that was not extracted would not be visible here — confirm manually."
                    ),
                    metadata={},
                )
            )
