"""The shared, seeded byte mutator used by both C3 fuzzers.

Kept in one place so the network fuzzer (:mod:`firefly.emulation.fuzz`) and the
per-binary harness fuzzer (:mod:`firefly.emulation.harness`) mutate inputs the
same way — one canonical mutator, reused everywhere, rather than two copies that
drift. It is deterministic given its ``random.Random``, so a recorded seed
reproduces a run exactly.
"""

from __future__ import annotations

import random

# Classic trouble tokens a dumb mutator should try: format strings, traversal,
# overflow fillers, NULs, huge/negative numbers.
BAD_TOKENS: tuple[bytes, ...] = (
    b"%n" * 8, b"%s" * 16, b"%x" * 16,
    b"../" * 16, b"A" * 512, b"\x00" * 16, b"\xff" * 16,
    b"-1", b"99999999999999999999", b"\r\n" * 8, b"${" + b"A" * 16 + b"}",
)


def mutate(seed: bytes, rng: random.Random, max_input: int) -> bytes:
    """Mutate ``seed`` into a new input, bounded by ``max_input`` bytes.

    Never returns empty (an empty input exercises nothing) and never exceeds the
    cap. Deterministic for a given ``rng`` state.
    """
    data = bytearray(seed) or bytearray(b"A")
    for _ in range(rng.randint(1, 6)):
        if not data:
            data = bytearray(b"A")
        op = rng.randint(0, 5)
        if op == 0:  # bit flip
            i = rng.randrange(len(data))
            data[i] ^= 1 << rng.randrange(8)
        elif op == 1:  # random byte
            data[rng.randrange(len(data))] = rng.randrange(256)
        elif op == 2:  # splice in a trouble token
            tok = rng.choice(BAD_TOKENS)
            i = rng.randrange(len(data) + 1)
            data[i:i] = tok
        elif op == 3 and len(data) > 1:  # delete a chunk
            i = rng.randrange(len(data))
            n = rng.randint(1, min(8, len(data) - i))
            del data[i:i + n]
        elif op == 4:  # duplicate a chunk
            i = rng.randrange(len(data))
            n = rng.randint(1, max(1, min(16, len(data) - i)))
            data[i:i] = data[i:i + n]
        else:  # append a trouble token
            data += rng.choice(BAD_TOKENS)
        if len(data) > max_input:
            del data[max_input:]
    return bytes(data)
