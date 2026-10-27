"""Opt-in dynamic emulation of firmware binaries (Phase A: qemu-user).

Emulation *executes untrusted code*, so unlike the static analyzers it runs
only when explicitly requested, only on Linux with qemu-user installed, and
only inside a sandbox (bubblewrap by default). See :mod:`firefly.emulation.stage`
for the orchestration entry point and ``ROADMAP.md`` for the broader plan.
"""

from __future__ import annotations

from firefly.emulation.result import BinaryRun, EmulationResult
from firefly.emulation.stage import EmulationOptions, run_emulation

__all__ = ["BinaryRun", "EmulationResult", "EmulationOptions", "run_emulation"]
