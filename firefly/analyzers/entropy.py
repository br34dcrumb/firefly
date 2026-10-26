"""Entropy profile of the raw image, to spot encrypted or packed firmware."""

from __future__ import annotations

import math
import os
from collections import Counter

from firefly.analyzers import Analyzer, AnalyzerResult, ScanContext
from firefly.models import Finding, Severity

BLOCK_SIZE = 4096
# Random data in a 4 KiB block measures ~7.95 bits/byte; compressed data
# usually sits a little lower and has structure (headers, padding) between.
HIGH_ENTROPY = 7.9
MAX_PROFILE_POINTS = 1024
MIN_SIZE = 64 * 1024


def shannon_entropy(data: bytes) -> float:
    if not data:
        return 0.0
    n = len(data)
    return -sum(c / n * math.log2(c / n) for c in Counter(data).values())


def block_entropies(path: str, block_size: int = BLOCK_SIZE) -> tuple[list[float], float]:
    totals: Counter[int] = Counter()
    blocks: list[float] = []
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(block_size), b""):
            counts = Counter(block)
            totals.update(counts)
            n = len(block)
            blocks.append(-sum(c / n * math.log2(c / n) for c in counts.values()))
    size = sum(totals.values())
    overall = -sum(c / size * math.log2(c / size) for c in totals.values()) if size else 0.0
    return blocks, overall


def downsample(values: list[float], points: int = MAX_PROFILE_POINTS) -> list[float]:
    if len(values) <= points:
        return [round(v, 3) for v in values]
    step = len(values) / points
    return [round(max(values[int(i * step) : int((i + 1) * step)] or [0.0]), 3) for i in range(points)]


class EntropyAnalyzer(Analyzer):
    name = "entropy"
    description = "Block entropy profile of the firmware image; flags likely encryption"
    requires_inventory = False

    def run(self, ctx: ScanContext) -> AnalyzerResult:
        result = AnalyzerResult()
        # Only meaningful for raw images; a rootfs tarball is just gzip noise.
        if not os.path.isfile(ctx.firmware_path) or (ctx.extraction and ctx.extraction.input_kind != "firmware"):
            return result
        blocks, overall = block_entropies(ctx.firmware_path)
        high = sum(1 for b in blocks if b >= HIGH_ENTROPY)
        ratio = high / len(blocks) if blocks else 0.0
        result.artifacts = {
            "block_size": BLOCK_SIZE,
            "overall": round(overall, 4),
            "high_entropy_ratio": round(ratio, 4),
            "profile": downsample(blocks),
        }
        size = os.path.getsize(ctx.firmware_path)
        extracted_nothing = ctx.extraction is None or not ctx.extraction.rootfs_candidates
        if size >= MIN_SIZE and ratio >= 0.9:
            result.findings.append(
                Finding(
                    analyzer=self.name,
                    title="Firmware image appears to be encrypted",
                    severity=Severity.INFO,
                    confidence="high" if extracted_nothing else "low",
                    description=(
                        f"{ratio:.0%} of {BLOCK_SIZE}-byte blocks have entropy >= {HIGH_ENTROPY} bits/byte "
                        f"(overall {overall:.3f}). The image is likely encrypted or a single compressed "
                        "stream; static analysis will be limited until it is decrypted."
                    ),
                    metadata={"overall_entropy": round(overall, 4), "high_entropy_ratio": round(ratio, 4)},
                )
            )
        return result
