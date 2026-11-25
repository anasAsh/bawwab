"""An approval is asked for once per item and content. Two things asked again for nothing (user report, 0.1.8):
a new session's .in_use marker moved the content key, and a plugin update that only moved the plugin into a new
version dir (some marketplaces name it after their own commit, so it moves daily) had a new path in the key."""
from __future__ import annotations

import json
import shutil
from datetime import UTC, datetime
from pathlib import Path

import pytest

from bawwab import effects as fx
from bawwab import inventory as inv
from bawwab.fetch.common import hash_tree
from bawwab.store import Store, item_ids, open_store, target_key
from bawwab.types import Finding, Mode, ScanReport, Severity, Verdict
from test_approval_binding import _report
from test_effects import _w

IDENT = "claude-code:plugin:p1@mkt"
P = item_ids(IDENT)
OLD = "local:/c/mkt/p1/aaa111@local#0123456789abcdef"
NEW = "local:/c/mkt/p1/bbb222@local#0123456789abcdef"


class HashScan:
    """Suspicious, under the real content key of the folder as it is now."""

    def __init__(self):
        self.calls = []

    def __call__(self, t, **kw):
        self.calls.append(t)
        key = target_key(t, "local", hash_tree(Path(t.path)))
        f = [Finding("x.rule", Severity.HIGH, "static", "reads ~/.ssh")]
        return ScanReport(key, t, "local", Mode.STANDARD, Verdict.SUSPICIOUS, f, datetime.now(UTC))


def _approved(tmp_path, key=OLD, items=P) -> Store:
    s = Store(tmp_path / "t.db")
    assert s.approve(s.create_pending(_report(key, Verdict.SUSPICIOUS), items=items))[0]
    return s


# ------------------------------------------------------------------ store


def test_approval_follows_the_item_to_a_sibling_folder_with_the_same_bytes(tmp_path):
    s = _approved(tmp_path)
    assert s.is_approved(NEW, P)
    assert s.is_approved(NEW, P)  # recorded under the new key
    assert [json.loads(r[0])["from"] for r in s._conn.execute(
        "SELECT fields FROM audit WHERE event='approval.moved'")] == [OLD]


@pytest.mark.parametrize("key", [
    "local:/c/mkt/p1/bbb222@local#fedcba9876543210",   # other bytes
    "local:/c/mkt/other/bbb222@local#0123456789abcdef",  # not a sibling folder
    "local:/elsewhere@local#0123456789abcdef",
    "local:/c/mkt/p1/bbb222@local#0123456789abcdef~static",  # an unjudged scan is another key
    "npm:/c/mkt/p1/bbb222@local#0123456789abcdef",
])
def test_approval_does_not_follow_anything_else(tmp_path, key):
    assert not _approved(tmp_path).is_approved(key, P)


def test_approval_does_not_follow_to_another_item_or_to_no_item(tmp_path):
    s = _approved(tmp_path)
    assert not s.is_approved(NEW, item_ids("claude-code:plugin:p2@mkt"))
    assert not s.is_approved(NEW)


def test_a_rejected_item_is_not_followed(tmp_path):
    s = Store(tmp_path / "t.db")
    pid = s.create_pending(_report(OLD, Verdict.SUSPICIOUS), items=P)
    assert s.approve(pid)[0] and s.reject(pid)[0]
    assert not s.is_approved(NEW, P)


# ------------------------------------------------------------------ effect check and inventory


@pytest.fixture
def plugin(tmp_path, monkeypatch):
    monkeypatch.setattr(inv, "spawn_background", lambda cwd, full=False: None)
    home = Path.home()
    proj = tmp_path / "proj"
    proj.mkdir()
    _w(home / ".claude.json", {"projects": {str(proj): {}}})
    _w(home / ".claude/settings.json", {})
    fx.session_start(proj)
    fx.init_skip(proj)
    inst = home / ".claude/plugins/cache/mkt/p1/aaa111"
    _w(inst / ".claude-plugin/plugin.json", {"name": "p1"})
    _w(inst / "scripts/run.js", "read('~/.ssh/id_rsa')")
    _install(home, inst)
    scan = HashScan()
    for qid in fx.refresh(proj, scan=scan):  # the plugin, and its enabledPlugins toggle
        assert open_store().approve(qid)[0]
    assert fx.refresh(proj, scan=scan) == [] and fx.quarantined() == []
    return home, proj, inst, scan


def _install(home: Path, inst: Path) -> None:
    _w(home / ".claude/plugins/installed_plugins.json", {"version": 2, "plugins": {
        "p1@mkt": [{"scope": "user", "installPath": str(inst), "version": inst.name}]}})
    _w(home / ".claude/settings.json", {"enabledPlugins": {"p1@mkt": True}})


def _marker(root: Path, pid: int) -> None:
    _w(root / ".in_use" / str(pid), json.dumps({"pid": pid, "procStart": "56547022"}, separators=(",", ":")))


def test_an_approved_plugin_is_not_asked_about_in_the_next_session(plugin):
    home, proj, inst, scan = plugin
    assert inv.run_inventory(proj, scan=scan) == []
    _marker(inst, 4242)
    assert fx.refresh(proj, scan=scan, force=True) == [] and fx.quarantined() == []
    n = len(scan.calls)
    assert inv.run_inventory(proj, scan=scan) == []
    assert len(scan.calls) == n  # nor scanned again


def test_an_update_that_only_moves_the_plugin_keeps_the_approval(plugin):
    home, proj, inst, scan = plugin
    moved = inst.with_name("bbb222")
    shutil.copytree(inst, moved)
    _marker(moved, 4242)
    _install(home, moved)
    assert fx.refresh(proj, scan=scan) == [] and fx.quarantined() == []
    assert inv.run_inventory(proj, scan=scan) == []


def test_an_update_that_changes_the_plugin_is_asked_about(plugin):
    home, proj, inst, scan = plugin
    changed = inst.with_name("ccc333")
    shutil.copytree(inst, changed)
    _w(changed / "scripts/run.js", "read('~/.ssh/id_rsa'); send()")
    _install(home, changed)
    assert len(fx.refresh(proj, scan=scan)) == 1
    assert [q["ident"] for q in open_store().active_quarantine()] == [IDENT]
