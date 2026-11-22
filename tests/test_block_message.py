"""The quarantine block message is a compact table (one row per item, commands once); `bawwab effects` has the
details; approve/reject take several ids and name what they decided; Claude may ask with AskUserQuestion."""
from __future__ import annotations

from pathlib import Path

import pytest

from bawwab import effects as fx
from bawwab import inventory as inv
from bawwab.cli import main
from bawwab.clicmd import cmd
from bawwab.store import open_store
from bawwab.types import Verdict
from test_effects import FakeScan, _w


@pytest.fixture
def held(tmp_path, monkeypatch):
    """Two plugins quarantined after init: p1 suspicious, p2 malicious."""
    monkeypatch.setattr(inv, "spawn_background", lambda cwd, full=False: None)
    home = Path.home()
    proj = tmp_path / "proj"
    proj.mkdir()
    _w(home / ".claude.json", {"projects": {str(proj): {}}})
    _w(home / ".claude/settings.json", {"enabledPlugins": {"p1@mkt": True, "p2@mkt": True}})  # accepted at init
    fx.session_start(proj)
    fx.init_skip(proj)
    plugins = {}
    for name in ("p1", "p2"):
        inst = home / f".claude/plugins/cache/mkt/{name}/1.0.0"
        _w(inst / ".claude-plugin/plugin.json", {"name": name})
        plugins[f"{name}@mkt"] = [{"scope": "user", "installPath": str(inst), "version": "1.0.0"}]
    _w(home / ".claude/plugins/installed_plugins.json", {"version": 2, "plugins": plugins})
    fx.refresh(proj, scan=FakeScan(Verdict.SUSPICIOUS, p2=Verdict.MALICIOUS))
    entries = fx.quarantined()
    ids = {fx.item_name(q): q["id"] for q in entries}
    assert set(ids) == {"plugin p1", "plugin p2"}
    return proj, ids


def test_table_has_one_row_per_item_and_the_commands_once(held):
    _, ids = held
    text = fx.quarantine_text(fx.quarantined())
    assert text.startswith("⛔ bawwab: 2 changes to Claude's setup are on hold.")
    rows = [line for line in text.splitlines() if line.startswith("  ") and line.split()[0] in ids.values()]
    assert len(rows) == 2
    assert any("plugin p1" in r and "suspicious" in r for r in rows)
    assert any("plugin p2" in r and "malicious" in r for r in rows)
    assert text.count(cmd("approve")) == 2  # one keep line, one --force line for the malicious item
    assert f"! {cmd('approve')} {ids['plugin p1']}  # plugin p1\n" in text  # each command names its item
    assert f"! {cmd('approve --force')} {ids['plugin p2']}  # plugin p2\n" in text
    assert f"! {cmd('reject')} {ids['plugin p1']} {ids['plugin p2']}  # plugin p1, plugin p2\n" in text  # real ids
    assert f"! {cmd('effects')}" in text and "AskUserQuestion" in text
    assert "[med]" not in text and "[high]" not in text  # evidence lives in `bawwab effects`


def test_details_name_every_command(held, capsys):
    _, ids = held
    main(["effects"])
    out = capsys.readouterr().out
    assert f"approve {ids['plugin p1']}  # plugin p1" in out
    assert f"approve --force {ids['plugin p2']}  # plugin p2" in out
    assert f"reject {ids['plugin p2']}  # plugin p2" in out


def test_approve_several_ids_names_them(held, capsys):
    _, ids = held
    assert main(["approve", "--force", ids["plugin p1"], ids["plugin p2"]]) == 0
    out = capsys.readouterr().out.splitlines()
    assert out == [f"approved plugin p1 ({ids['plugin p1']})", f"approved plugin p2 ({ids['plugin p2']})"]
    assert open_store().active_quarantine() == []


def test_one_bad_id_fails_but_the_rest_are_decided(held, capsys):
    _, ids = held
    assert main(["approve", ids["plugin p1"], "ZZZZ"]) == 1
    out = capsys.readouterr().out
    assert f"approved plugin p1 ({ids['plugin p1']})" in out and "error: ZZZZ" in out
    assert [fx.item_name(q) for q in fx.quarantined()] == ["plugin p2"]


def test_ask_user_question_runs_during_quarantine(held):
    proj, _ = held
    assert fx.pre_tool_decision("AskUserQuestion", proj) is None
    assert fx.pre_tool_decision("Bash", proj)["hookSpecificOutput"]["permissionDecision"] == "deny"
