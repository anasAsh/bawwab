"""Effect check: settings `permissions` (0.1.4). Only a change that lets more run without a prompt is held: a
wildcard/unscoped Bash or Write allow, defaultMode bypassPermissions/acceptEdits, a removed deny or ask rule.
Narrow allows and new deny/ask rules stay silent (Bawwab must not get noisier)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from bawwab import effects as fx
from bawwab.agents import claude_code_watch as w
from bawwab.cli import main
from bawwab.store import open_store
from test_effects import FakeScan, _w


@pytest.fixture
def env(tmp_path):
    home = Path.home()
    proj = tmp_path / "proj"
    proj.mkdir()
    _w(home / ".claude.json", {"numStartups": 1, "mcpServers": {}, "projects": {str(proj): {"allowedTools": []}}})
    _w(home / ".claude/settings.json", {"theme": "dark", "permissions": {
        "allow": ["Bash(npm test)"], "deny": ["Read(./.env)"], "ask": ["Bash(git push:*)"]}})
    fx.session_start(proj)
    assert fx.refresh(proj, scan=FakeScan()) == []
    return home, proj


def _set_perms(p: Path, perms: dict) -> None:
    d = json.loads(p.read_text()) if p.exists() else {}
    d["permissions"] = perms
    _w(p, d)


BASE = {"allow": ["Bash(npm test)"], "deny": ["Read(./.env)"], "ask": ["Bash(git push:*)"]}

SILENT = [
    {**BASE, "allow": ["Bash(npm test)", "Bash(npm run lint)"]},
    {**BASE, "allow": ["Bash(npm test)", "Read(~/notes/**)", "Bash(git add:*)", "Bash(uv run pytest:*)",
                       "Edit(src/**)", "WebFetch(domain:docs.python.org)", "mcp__github__get_issue"]},
    {**BASE, "deny": ["Read(./.env)", "Bash(rm -rf:*)"]},
    {**BASE, "ask": ["Bash(git push:*)", "Bash(docker:*)"]},
    {**BASE, "defaultMode": "plan"},
    {**BASE, "allow": []},  # removing an allow narrows
    {**BASE, "additionalDirectories": ["../shared"]},
]

FLAGGED = [
    ({**BASE, "allow": ["Bash(npm test)", "Bash(*)"]}, "allow Bash(*)"),
    ({**BASE, "allow": ["Bash"]}, "allow Bash"),
    ({**BASE, "allow": ["Bash(:*)"]}, "allow Bash(:*)"),
    ({**BASE, "allow": ["Bash(bash:*)"]}, "allow Bash(bash:*)"),
    ({**BASE, "allow": ["Bash(sudo:*)"]}, "allow Bash(sudo:*)"),
    ({**BASE, "allow": ["Write"]}, "allow Write"),
    ({**BASE, "allow": ["Edit(//**)"]}, "allow Edit(//**)"),
    ({**BASE, "allow": ["Write(~/**)"]}, "allow Write(~/**)"),
    ({**BASE, "defaultMode": "bypassPermissions"}, "defaultMode bypassPermissions"),
    ({**BASE, "defaultMode": "acceptEdits"}, "defaultMode acceptEdits"),
    ({**BASE, "deny": []}, "removes deny Read(./.env)"),
    ({**BASE, "ask": []}, "removes ask Bash(git push:*)"),
]


@pytest.mark.parametrize("perms", SILENT)
def test_narrow_permission_changes_stay_silent(env, perms):
    home, proj = env
    scan = FakeScan()
    _set_perms(home / ".claude/settings.json", perms)
    assert fx.refresh(proj, scan=scan) == [] and open_store().active_quarantine() == []
    assert open_store().take_warnings() == [] and scan.calls == []


@pytest.mark.parametrize("perms,why", FLAGGED)
def test_broadening_permission_changes_are_held(env, perms, why):
    home, proj = env
    _set_perms(home / ".claude/settings.json", perms)
    ids = fx.refresh(proj, scan=FakeScan())
    assert len(ids) == 1
    text = fx.quarantine_text(fx.quarantined())
    assert "setting permissions" in text and "permissions widened by hand" in text
    assert why in fx.quarantine_details(fx.quarantined())


def test_narrow_allow_does_not_even_move_the_semantic_digest(env):
    home, proj = env
    fpm = fx.fp_module()
    before = fpm.semantic_digest(str(proj), str(home))
    _set_perms(home / ".claude/settings.json", {**BASE, "allow": ["Bash(npm test)", "Bash(git status)"]})
    assert fpm.semantic_digest(str(proj), str(home)) == before
    _set_perms(home / ".claude/settings.json", {**BASE, "allow": ["Bash(*)"]})
    assert fpm.semantic_digest(str(proj), str(home)) != before


def test_new_project_settings_file_with_bypass_is_held(env):
    home, proj = env
    _set_perms(proj / ".claude/settings.local.json", {"defaultMode": "bypassPermissions"})
    assert len(fx.refresh(proj, scan=FakeScan())) == 1


def test_approved_broadening_is_the_new_baseline(env, capsys):
    home, proj = env
    _set_perms(home / ".claude/settings.json", {**BASE, "allow": ["Bash(*)"]})
    (qid,) = fx.refresh(proj, scan=FakeScan())
    assert main(["approve", qid]) == 0
    assert open_store().active_quarantine() == []
    # a later narrow change keeps Bash(*): nothing new is held
    _set_perms(home / ".claude/settings.json", {**BASE, "allow": ["Bash(*)", "Bash(npm run build)"],
                                                 "deny": ["Read(./.env)", "Read(./secrets/**)"]})
    assert fx.refresh(proj, scan=FakeScan()) == []
    # but a further broadening is
    _set_perms(home / ".claude/settings.json", {**BASE, "allow": ["Bash(*)"], "defaultMode": "acceptEdits"})
    assert len(fx.refresh(proj, scan=FakeScan())) == 1


def test_existing_broad_permissions_at_upgrade_are_not_held(tmp_path):
    """Permissions already in place when this check first sees them (an install from before 0.1.4) are the
    baseline: no new quarantine on upgrade."""
    home = Path.home()
    proj = tmp_path / "proj"
    proj.mkdir()
    _w(home / ".claude.json", {"numStartups": 1, "mcpServers": {}, "projects": {}})
    _w(home / ".claude/settings.json", {"theme": "dark"})
    fx.session_start(proj)
    assert fx.refresh(proj, scan=FakeScan()) == []
    store = open_store()
    for ident in [i for i in store.all_effect_rows() if i.endswith(":permissions")]:
        store.drop_effect(ident)  # as if the rows and meta were written by 0.1.3
        store.set_meta(fx._perm_meta(ident), "null")
    _w(home / ".claude/settings.json", {"theme": "dark", "permissions": {"allow": ["Bash(*)"],
                                                                        "defaultMode": "acceptEdits"}})
    assert fx.refresh(proj, scan=FakeScan()) == []
    _set_perms(home / ".claude/settings.json", {"allow": ["Bash(*)", "Write"], "defaultMode": "acceptEdits"})
    assert len(fx.refresh(proj, scan=FakeScan())) == 1  # from then on, a broadening is held


@pytest.mark.parametrize("rule,dangerous", [
    ("Bash", True), ("Bash(*)", True), ("Bash( * )", True), ("Bash(* --help)", True), ("Bash(sh -c:*)", True),
    ("Bash(npm test)", False), ("Bash(npm:*)", False), ("Bash(git add:*)", False), ("Bash(python3 -m pytest:*)", False),
    ("Read", False), ("Read(**)", False), ("Edit", True), ("Edit(**)", True), ("Edit(src/**)", False),
    ("Write(./docs/*.md)", False), ("NotebookEdit", True), ("PowerShell(*)", True), ("WebFetch", False), (3, False),
])
def test_dangerous_allow_rules(rule, dangerous):
    assert w.dangerous_allow(rule) is dangerous
