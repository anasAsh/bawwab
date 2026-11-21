"""Deep mode: run a target in a locked-down Docker sandbox with decoy credentials and a network trap.

Runner interface: `bawwab.scan.SandboxRunner` (`run(fetched, timeout_s) -> (findings, tools)`).
  - DockerRunner (docker.py): the real one.
  - FakeRunner (fake.py): replays recorded observations, for tests.
Both feed the same `observe.analyze`, which turns observations into `sandbox.*` findings.
"""
from __future__ import annotations

from bawwab.sandbox.docker import DockerRunner, SandboxUnavailable
from bawwab.sandbox.fake import FakeRunner
from bawwab.sandbox.observe import Observation, analyze

__all__ = ["DockerRunner", "FakeRunner", "Observation", "SandboxUnavailable", "analyze", "default_runner"]


def default_runner() -> DockerRunner:
    return DockerRunner()
