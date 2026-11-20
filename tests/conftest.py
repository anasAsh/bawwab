"""Global isolation backstop: no test may touch the real HOME, ~/.claude or ~/.bawwab."""
from __future__ import annotations

from pathlib import Path

import pytest

REAL_HOME = Path.home()
_ROOT = Path(__file__).resolve().parent.parent


def _boot_token() -> str:
    import importlib.util

    spec = importlib.util.spec_from_file_location("_hook_for_token", _ROOT / "hooks" / "bawwab_hook.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m._boot_token()


@pytest.fixture(autouse=True)
def _isolated_env(tmp_path_factory, monkeypatch, request):
    root = tmp_path_factory.mktemp("iso")
    monkeypatch.setenv("HOME", str(root / "home"))
    monkeypatch.setenv("BAWWAB_HOME", str(root / "bawwab"))
    monkeypatch.setenv("XDG_CONFIG_HOME", str(root / "xdg"))
    monkeypatch.setenv("XDG_STATE_HOME", str(root / "home" / ".local" / "state"))  # the third marker copy
    monkeypatch.delenv("CLAUDE_PLUGIN_ROOT", raising=False)  # "installed as a plugin" (lost-state check)
    monkeypatch.delenv("BAWWAB_CHILD", raising=False)
    monkeypatch.delenv("CLAUDE_CONFIG_DIR", raising=False)
    # cli.main lowers the process's address-space limit; in-process tests must not lower pytest's own (and
    # then wrap every child argv). The limit itself is tested in subprocesses (test_scan_memory.py).
    monkeypatch.setenv("BAWWAB_MEMORY_LIMIT_MB", "0")
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA", raising=False)  # the install marker is also written there
    monkeypatch.delenv("CLAUDE_PROJECT_DIR", raising=False)  # an extra project scope
    monkeypatch.delenv("BAWWAB_SESSION_ID", raising=False)  # the hook sets it from its input (lost-state check)
    (root / "home").mkdir()
    # The hook's first-run bootstrap (fix round 2, I4) is done: the dev checkout's own venv is the one to use.
    # Tests of the bootstrap itself remove the marker or point BAWWAB_VENV elsewhere.
    monkeypatch.setenv("BAWWAB_VENV", str(_ROOT / ".venv"))
    (root / "bawwab").mkdir()
    (root / "bawwab" / "bootstrap-complete").write_text(_boot_token())
    if "real_spawn" not in request.keywords:
        def _no_spawn(cwd):
            raise AssertionError("test tried to spawn the background inventory; mark it real_spawn or patch it")

        monkeypatch.setattr("bawwab.inventory.spawn_background", _no_spawn)
    import bawwab.scan.osv as osv

    osv.clear_cache()
    if "real_docker" not in request.keywords:
        # No test reaches a real Docker daemon: deep scans see "docker could not be run" (sandbox.unavailable).
        def _no_docker(argv, stdin, timeout):
            raise FileNotFoundError("docker disabled in tests")

        monkeypatch.setattr("bawwab.sandbox.docker._run_cmd", _no_docker)
    if "real_osv" not in request.keywords:
        # No test reaches the real OSV API: registry scans see "no advisories" (Task 10c).
        monkeypatch.setattr(osv, "_post", lambda url, body, timeout: {})
    yield


@pytest.fixture
def real_home() -> Path:
    return REAL_HOME
