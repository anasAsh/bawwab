"""Fix round 2 (I4, M8): the first-run venv sync runs detached, never trips the lost-state check, and the venv
never lives in the plugin root."""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from bawwab import effects as fx
from bawwab import inventory as inv
from conftest import _boot_token

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "bawwab_hook.py"


def _w(p: Path, data) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data if isinstance(data, str) else json.dumps(data))


def _fake_uv(tmp_path: Path, sync_sleep: float = 0.0, context: str = "FIRST-RUN QUESTION") -> tuple[dict, Path]:
    """A `uv` that logs its arguments and UV_PROJECT_ENVIRONMENT; `sync` succeeds after sync_sleep seconds and
    `run ... bawwab inventory` prints a SessionStart context."""
    b = tmp_path / "fakebin"
    b.mkdir(exist_ok=True)
    log = tmp_path / "uv.log"
    out = json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": context}})
    (b / "uv").write_text(
        f"#!{sys.executable}\nimport os, sys, time\n"
        f"open({str(log)!r}, 'a').write(' '.join(sys.argv[1:]) + ' | ' + os.environ.get('UV_PROJECT_ENVIRONMENT', '-') + '\\n')\n"
        f"if sys.argv[1:2] == ['sync']:\n    time.sleep({sync_sleep})\n    sys.exit(0)\n"
        f"if sys.argv[-1] == 'inventory':\n    sys.stdin.read()\n    print({out!r})\n")
    (b / "uv").chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k not in ("BAWWAB_CHILD", "BAWWAB_VENV")}
    env["PATH"] = f"{b}:{os.environ['PATH']}"
    return env, log


def _hook(sub: str, stdin: str, env: dict):
    return subprocess.run([sys.executable, str(HOOK), sub], input=stdin, capture_output=True, text=True, env=env,
                          timeout=60)


def _bh() -> Path:
    return Path(os.environ["BAWWAB_HOME"])


def _wait(p: Path, secs: float = 15) -> bool:
    end = time.time() + secs
    while time.time() < end:
        if p.exists():
            return True
        time.sleep(0.05)
    return False


@pytest.fixture
def fresh(tmp_path):
    """No bootstrap yet (the conftest marks it done for every other test)."""
    (_bh() / "bootstrap-complete").unlink()
    return tmp_path


def test_gate_holds_installs_until_setup_is_done(fresh):
    env, log = _fake_uv(fresh, sync_sleep=0.5)
    install = json.dumps({"tool_name": "Bash", "tool_input": {"command": "claude mcp add x -- npx -y x@1"},
                          "cwd": str(fresh)})
    r = _hook("gate", install, env)
    d = json.loads(r.stdout)["hookSpecificOutput"]
    assert d["permissionDecision"] == "deny" and "still setting up" in d["permissionDecisionReason"]
    assert _hook("gate", json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": str(fresh)}),
                 env).stdout == ""  # other calls pass
    assert _wait(_bh() / "bootstrap-complete")
    assert (_bh() / "bootstrap-complete").read_text() == _boot_token()
    sync = [x for x in log.read_text().splitlines() if x.startswith("sync")]
    assert sync == [f"sync --project {ROOT.resolve()} --frozen --quiet | {_bh() / 'venv'}"]  # M8: bawwab_home/venv
    r = _hook("gate", install, env)  # setup done: now the real gate child runs (the fake uv prints nothing)
    assert "still setting up" not in r.stdout
    assert any(x.startswith(f"run --project {ROOT.resolve()} --frozen --quiet bawwab gate") for x in
               log.read_text().splitlines())


def test_sessionstart_during_setup_then_first_run_question_on_next_prompt(fresh):
    env, log = _fake_uv(fresh)
    ss = json.dumps({"session_id": "s1", "hook_event_name": "SessionStart", "cwd": str(fresh)})
    r = _hook("inventory", ss, env)
    ctx = json.loads(r.stdout)["hookSpecificOutput"]
    assert ctx["hookEventName"] == "SessionStart" and "still setting up" in ctx["additionalContext"]
    assert _wait(_bh() / "bootstrap-complete")
    assert any(x.endswith("bawwab inventory | " + str(_bh() / "venv")) for x in log.read_text().splitlines())
    r = _hook("notify", json.dumps({"session_id": "s1", "prompt": "hi"}), env)
    ctx = json.loads(r.stdout)["hookSpecificOutput"]
    assert ctx["hookEventName"] == "UserPromptSubmit" and "FIRST-RUN QUESTION" in ctx["additionalContext"]
    assert _hook("notify", json.dumps({"prompt": "again"}), env).stdout == ""  # shown once


def test_bootstrap_in_plugin_data_dir_never_in_root(fresh):
    env, log = _fake_uv(fresh)
    data = fresh / "plugindata" / "bawwab-mkt"
    env["CLAUDE_PLUGIN_DATA"] = str(data)
    _hook("bootstrap", "", env)
    assert (data / "bootstrap-complete").read_text() == _boot_token()
    assert log.read_text().splitlines()[0].endswith(f"| {data / 'venv'}")
    assert not (ROOT / "venv").exists()


def test_failed_sync_is_not_complete(fresh):
    b = fresh / "fakebin"
    b.mkdir()
    (b / "uv").write_text("#!/bin/sh\nexit 1\n")
    (b / "uv").chmod(0o755)
    env = {k: v for k, v in os.environ.items() if k != "BAWWAB_VENV"}
    env["PATH"] = f"{b}:{os.environ['PATH']}"
    _hook("bootstrap", "", env)
    assert not (_bh() / "bootstrap-complete").exists() and not (_bh() / "bootstrap.lock").exists()


def test_stale_marker_from_another_version_reruns_setup(fresh):
    (_bh() / "bootstrap-complete").write_text("an older version's token")
    env, _ = _fake_uv(fresh)
    r = _hook("gate", json.dumps({"tool_name": "Bash", "tool_input": {"command": "claude mcp add x -- npx -y x@1"},
                                  "cwd": str(fresh)}), env)
    assert "still setting up" in r.stdout


# ------------------------------------------------------------------ lost-state rule (R37-R39 + I4)

def _iso(t: datetime) -> str:
    return t.isoformat().replace("+00:00", "Z")


@pytest.fixture
def plugin(tmp_path, monkeypatch):
    monkeypatch.setattr(inv, "spawn_background", lambda cwd, full=False: None)
    home = Path.home()
    proj = tmp_path / "proj"
    proj.mkdir()
    _w(home / ".claude.json", {"numStartups": 1, "mcpServers": {}})
    data = home / ".claude/plugins/data/bawwab-mkt"
    data.mkdir(parents=True)
    return home, proj, data


def _installed(home: Path, ago: timedelta) -> datetime:
    at = datetime.now(UTC) - ago
    _w(home / ".claude/plugins/installed_plugins.json", {"version": 2, "plugins": {
        "bawwab@mkt": [{"scope": "user", "installPath": "/x", "installedAt": _iso(at)}]}})
    return at


def _transcript(home: Path, sid: str, at: datetime) -> None:
    _w(home / f".claude/projects/-p/{sid}.jsonl", json.dumps({"sessionId": sid, "timestamp": _iso(at)}) + "\n")


def test_slow_first_setup_is_not_lost_and_first_run_follows(plugin, monkeypatch):
    """The first session's setup never finished (no bootstrap-complete), a later session starts: first run."""
    home, proj, data = plugin
    at = _installed(home, timedelta(minutes=30))
    _transcript(home, "s1", at + timedelta(minutes=1))
    monkeypatch.setenv("BAWWAB_SESSION_ID", "s2")
    assert fx.fp_module().plugin_lost(str(home)) is None
    text = fx.session_start(proj)
    assert text and "has not scanned this machine yet" in text and "lost" not in text


def test_state_wiped_after_state_created_alarms(plugin, monkeypatch):
    home, proj, data = plugin
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(data))
    _installed(home, timedelta(minutes=1))  # recent install, no other session: only state-created can tell
    fx.session_start(proj)
    assert (data / "state-created").exists()
    import shutil

    shutil.rmtree(_bh())
    for p in fx.fp_module().marker_paths(str(home)):
        Path(p).unlink(missing_ok=True)
    assert fx.fp_module().plugin_lost(str(home)) is not None
    monkeypatch.delenv("CLAUDE_PLUGIN_DATA")  # the user's `!` shell has no plugin env: same answer
    assert fx.fp_module().plugin_lost(str(home)) is not None


def test_state_wiped_without_state_created_but_setup_done_and_later_session_alarms(plugin, monkeypatch):
    home, proj, data = plugin
    at = _installed(home, timedelta(hours=2))
    _transcript(home, "s1", at + timedelta(minutes=5))
    (data / "bootstrap-complete").write_text("x")
    monkeypatch.setenv("BAWWAB_SESSION_ID", "s2")
    assert fx.fp_module().plugin_lost(str(home)) is not None
