"""A SandboxRunner for tests: replays recorded sandbox observations through the real finding logic."""
from __future__ import annotations

from collections.abc import Callable

from bawwab.sandbox.observe import Observation, analyze
from bawwab.types import Fetched, Finding, ToolInfo


class FakeRunner:
    """Feeds a recorded Observation (or one built per target by `make`) into `analyze`, the same code the
    Docker runner uses. Nothing runs."""

    def __init__(self, obs: Observation | Callable[[Fetched], Observation]) -> None:
        self._obs = obs
        self.calls: list[tuple[Fetched, float]] = []

    def run(self, f: Fetched, timeout_s: float) -> tuple[list[Finding], list[ToolInfo]]:
        self.calls.append((f, timeout_s))
        obs = self._obs(f) if callable(self._obs) else self._obs
        return analyze(obs)
