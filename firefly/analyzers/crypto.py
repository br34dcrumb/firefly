"""Cryptographic posture: weak primitives, certificate quality, secure boot.

Three independent checks, all offline and failure-isolated:

* **Weak primitives** — which binaries reference broken ciphers/hashes (DES,
  RC4, MD4/MD2, ECB mode, and the legacy MD5/SHA-1 hashes), read from the ELF
  symbol tables :mod:`firefly.elf` already parses. Symbol presence is not proof
  of security-sensitive use, so findings are aggregated and rated modestly.
* **Certificate quality** — small RSA keys, broken signature hashes and expired
  validity, via the dependency-free :mod:`firefly.x509` reader.
* **Secure-boot posture** — whether any boot-integrity mechanism (dm-verity,
  IMA/EVM, signed FIT images) is visible in the extracted filesystem.

Hardcoded *private keys* are the credentials analyzer's job; this one judges the
cryptography around them, and never handles a raw secret.
"""

from __future__ import annotations

import os
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

        for rec in ctx.inventory:
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

        self._emit_primitives(result, prim, legacy_paths)
        self._emit_certs(result, weak_key, weak_sig, expired)
        self._emit_boot(result, boot_found)

        result.artifacts = {
            "weak_primitive_families": sorted(prim),
            "legacy_hash_binaries": len(legacy_paths),
            "certificates": cert_count,
            "weak_cert_keys": len(weak_key),
            "weak_cert_signatures": len(weak_sig),
            "expired_certs": len(expired),
            "boot_integrity": sorted(boot_found),
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
