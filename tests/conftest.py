"""Global isolation backstop: no test may touch the real HOME, ~/.claude or ~/.bawwab."""
from __future__ import annotations

from pathlib import Path

import pytest

REAL_HOME = Path.home()


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path_factory, monkeypatch, request):
    root = tmp_path_factory.mktemp("iso")
    monkeypatch.setenv("HOME", str(root / "home"))
    monkeypatch.setenv("BAWWAB_HOME", str(root / "bawwab"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(root / "xdg"))
    monkeypatch.delenv("BAWWAB_CHILD", raising=False)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)  # the install marker is also written there
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)  # an extra project scope
    (root / "home").mkdir()
    if "real_spawn" not in request.keywords:
        def _no_spawn(cwd):
            raise AssertionError("test tried to spawn the background inventory; mark it real_spawn or patch it")

        monkeypatch.setattr("bawwab.inventory.spawn_background", _no_spawn)
    yield


@pytest.fixture
def real_home() -> Path:
    return REAL_HOME
