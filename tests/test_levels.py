"""Security levels: low warns only, medium blocks malicious, high (the default) blocks anything not clean.
Bawwab's self-protection blocks at every level, and only the user can lower the level."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from bawwab import effects as fx
from bawwab import inventory as inv
from bawwab.cli import main
from bawwab.config import blocks, level_is_set, load_config, set_level
from bawwab.gate.detect import Protected, detect_install
from bawwab.gate.gate import run_gate
from bawwab.store import open_store
from bawwab.types import Verdict
from test_effects import FakeScan, _w
from test_gate import bash, decision, fake_scan

S, M, C = Verdict.SUSPICIOUS, Verdict.MALICIOUS, Verdict.CLEAN


@pytest.mark.parametrize("level, verdict, blocked", [
    ("high", S, True), ("high", M, True), ("high", C, False),
    ("medium", S, False), ("medium", M, True), ("medium", C, False),
    ("low", S, False), ("low", M, False), ("low", C, False),
    ("bogus", S, True),  # an unknown level fails closed
])
def test_blocks(level, verdict, blocked):
    assert blocks(level, verdict) is blocked


def test_level_defaults_to_high_until_chosen(tmp_path):
    assert load_config().level == "high" and not level_is_set()
    set_level("low")
    assert load_config().level == "low" and level_is_set()
    with pytest.raises(ValueError):
        set_level("none")


def test_project_config_may_only_raise_the_level(tmp_path):
    proj = tmp_path / "proj"
    set_level("low")
    _w(proj / ".claude/bawwab.json", {"level": "medium"})
    assert load_config(proj).level == "medium"
    set_level("high")
    _w(proj / ".claude/bawwab.json", {"level": "low"})
    assert load_config(proj).level == "high"


def test_set_level_keeps_other_keys(tmp_path):
    from bawwab.paths import bawwab_home

    _w(bawwab_home() / "config.json", {"mode": "deep"})
    set_level("medium")
    assert json.loads((bawwab_home() / "config.json").read_text()) == {"mode": "deep", "level": "medium"}


# ------------------------------------------------------------------ install gate

INSTALL = "claude mcp add gh -- npx -y @a/b@1.0.0"


@pytest.mark.parametrize("level, verdict, out", [
    ("high", S, "deny"), ("medium", S, "warn"), ("medium", M, "deny"), ("low", M, "warn"),
])
def test_gate_by_level(level, verdict, out):
    set_level(level)
    store = open_store()
    r = run_gate(bash(INSTALL), scan=fake_scan({"@a/b": verdict}), store=store)
    if out == "deny":
        assert decision(r) == "deny"
    else:
        assert "permissionDecision" not in r["hookSpecificOutput"]  # no allow: normal permissions decide
        assert f"({level} level, not blocked)" in r["systemMessage"]
        assert r["hookSpecificOutput"]["additionalContext"] == r["systemMessage"]
        assert store.take_warnings()  # Claude also hears it on the next prompt


def test_self_protection_blocks_at_low():
    set_level("low")
    r = run_gate(bash("bawwab approve AB12"), scan=fake_scan({}), store=open_store())
    assert decision(r) == "deny"


@pytest.mark.parametrize("cmd, protected", [
    ("bawwab level low", True), ("bawwab level medium", True), ("bawwab level $L", True),
    ("bawwab level high", False), ("bawwab level", False),
])
def test_only_the_user_lowers_the_level(home, cmd, protected):
    assert isinstance(detect_install(bash(cmd)), Protected) is protected


@pytest.fixture
def home(tmp_path):
    return Path.home()


def test_level_command(capsys):
    assert main(["level"]) == 0
    assert "high (the default: no level chosen yet)" in capsys.readouterr().out
    assert main(["level", "medium"]) == 0
    assert "set to medium" in capsys.readouterr().out and load_config().level == "medium"


# ------------------------------------------------------------------ effect check

@pytest.fixture
def proj(tmp_path, monkeypatch):
    monkeypatch.setattr(inv, "spawn_background", lambda cwd, full=False: None)
    home = Path.home()
    proj = tmp_path / "proj"
    proj.mkdir()
    _w(home / ".claude.json", {"projects": {str(proj): {}}})
    _w(home / ".claude/settings.json", {"enabledPlugins": {"p1@mkt": True}})
    fx.session_start(proj)
    fx.init_skip(proj)
    inst = home / ".claude/plugins/cache/mkt/p1/1.0.0"
    _w(inst / ".claude-plugin/plugin.json", {"name": "p1"})
    _w(home / ".claude/plugins/installed_plugins.json", {"version": 2, "plugins": {
        "p1@mkt": [{"scope": "user", "installPath": str(inst), "version": "1.0.0"}]}})
    return proj


@pytest.mark.parametrize("level, verdict, held", [
    ("high", S, True), ("medium", S, False), ("medium", M, True), ("low", M, False),
])
def test_effect_check_by_level(proj, level, verdict, held):
    set_level(level)
    store = open_store()
    fx.refresh(proj, scan=FakeScan(verdict))
    assert bool(fx.quarantined(store)) is held
    if not held:
        warnings = store.take_warnings()
        assert any(f"({level} level, not blocked): plugin p1 is {verdict.value}" in w for w in warnings)
        assert fx.pre_tool_decision("Bash", proj) is None
        assert fx.refresh(proj, scan=FakeScan(verdict)) == [] and store.take_warnings() == []  # warned once


# ------------------------------------------------------------------ first run

def test_first_run_welcomes_and_asks_for_a_level(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(inv, "spawn_background", lambda cwd, full=False: None)
    proj = tmp_path / "proj"
    proj.mkdir()
    monkeypatch.setattr("sys.stdin", __import__("io").StringIO(json.dumps({"cwd": str(proj)})))
    assert main(["inventory"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert out["systemMessage"].startswith("Welcome to Bawwab")
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert "security level" in ctx and "level high" in ctx and "! " in ctx and "init --scan" in ctx


def test_first_run_skips_the_level_question_once_chosen(tmp_path, monkeypatch):
    monkeypatch.setattr(inv, "spawn_background", lambda cwd, full=False: None)
    set_level("medium")
    assert "choose Bawwab's security level" not in fx.ask_context(tmp_path)
