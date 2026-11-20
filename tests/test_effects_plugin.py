"""Task 13: the effect check loads hooks/fingerprint.py from the plugin root (never the cwd), and
install-time hooks and exec settings found by `init --scan` are approved as one batch."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from bawwab import effects as fx
from bawwab import inventory as inv
from bawwab.cli import main
from bawwab.store import open_store
from test_effects import FakeScan, _w

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def fresh_fp(monkeypatch):
    monkeypatch.setattr(fx, "_fp_mod", None)
    yield
    fx._fp_mod = None  # monkeypatch restores the cached module from before the test


def _plant(d: Path, marker: str) -> None:
    for rel in ("hooks/fingerprint.py", "bawwab/_fingerprint.py", "_fingerprint.py"):
        _w(d / rel, f"PLANTED = {marker!r}\n")


def test_fingerprint_from_running_plugin_root_not_env(fresh_fp, monkeypatch, tmp_path):
    from bawwab import selfid

    root = tmp_path / "plugin"
    _w(root / "hooks/fingerprint.py", "PLANTED = 'plugin-root'\n")
    _w(root / "hooks/bawwab_hook.py", "")
    monkeypatch.setenv("CLAUDE_PLUGIN_ROOT", str(root))  # the env var alone loads nothing (fix round 1)
    m = fx.fp_module()
    assert not hasattr(m, "PLANTED") and Path(m.__file__) == ROOT / "hooks" / "fingerprint.py"
    fx._fp_mod = None
    monkeypatch.setattr(selfid, "_HERE", root / "bawwab" / "selfid.py")  # the code runs from that plugin tree
    assert fx.fp_module().PLANTED == "plugin-root"


def test_fingerprint_never_from_cwd(fresh_fp, monkeypatch, tmp_path):
    cwd = tmp_path / "scanned-repo"
    _plant(cwd, "cwd")
    monkeypatch.chdir(cwd)
    m = fx.fp_module()
    assert not hasattr(m, "PLANTED") and hasattr(m, "fingerprint") and hasattr(m, "quarantine_active")


def test_fingerprint_outside_a_plugin_tree_is_the_package_copy(fresh_fp, monkeypatch, tmp_path):
    from bawwab import selfid

    monkeypatch.setattr(selfid, "_HERE", tmp_path / "site-packages" / "bawwab" / "selfid.py")
    _w(tmp_path / "site-packages/hooks/fingerprint.py", "PLANTED = 'other-package'\n")
    m = fx.fp_module()
    assert not hasattr(m, "PLANTED") and Path(m.__file__) == Path(fx.__file__).resolve().parent / "_fingerprint.py"


def test_package_copy_is_the_hook_file():
    """bawwab/_fingerprint.py links to hooks/fingerprint.py so a wheel install (uvx) ships the same code."""
    assert (ROOT / "bawwab/_fingerprint.py").read_bytes() == (ROOT / "hooks/fingerprint.py").read_bytes()


# ------------------------------------------------------------------ batch approval at init

@pytest.fixture
def env(tmp_path, monkeypatch):
    monkeypatch.setattr(inv, "spawn_background", lambda cwd, full=False: None)
    home = Path.home()
    proj = tmp_path / "proj"
    proj.mkdir()
    _w(home / ".claude.json", {"numStartups": 1, "mcpServers": {}, "projects": {str(proj): {"allowedTools": []}}})
    _w(home / ".claude/settings.json", {
        "statusLine": {"type": "command", "command": "other-status"},
        "hooks": {"Stop": [{"hooks": [{"type": "command", "command": "other-plugin-stop"}]}],
                  "PreToolUse": [{"matcher": "Bash", "hooks": [{"type": "command", "command": "other-guard"}]}]}})
    return home, proj


def _active():
    return open_store().active_quarantine()


def test_init_scan_batches_install_time_hooks(env, capsys):
    home, proj = env
    fx.session_start(proj)
    fx.full_scan(proj, scan=FakeScan())
    q = _active()
    assert len(q) == 3 and len({x["id"] for x in q}) == 1  # two hooks and a setting, one approval id
    text = fx.quarantine_text(fx.quarantined())
    assert text.count("bawwab approve") == 1 and "3 existing hooks/settings" in text
    details = fx.quarantine_details(fx.quarantined())
    for c in ("other-plugin-stop", "other-guard", "statusLine"):
        assert c in details
    capsys.readouterr()
    assert main(["approve", q[0]["id"]]) == 0
    assert capsys.readouterr().out == f"approved 3 existing hooks/settings ({q[0]['id']})\n"  # the batch, as listed
    assert _active() == [] and not fx.flag_path().exists()
    statuses = {i: r["status"] for i, r in open_store().all_effect_rows().items()}
    assert sum(1 for s in statuses.values() if s == "approved") == 3
    fx.full_scan(proj, scan=FakeScan())  # `scan --all` later: the batch approval still holds
    assert _active() == []
    assert fx.refresh(proj, scan=FakeScan()) == []


def test_hook_added_after_install_is_not_batched(env):
    home, proj = env
    fx.session_start(proj)
    s = json.loads((home / ".claude/settings.json").read_text())
    s["hooks"]["Stop"].append({"hooks": [{"type": "command", "command": "late-hook"}]})
    _w(home / ".claude/settings.json", s)
    fx.full_scan(proj, scan=FakeScan())
    q = _active()
    late = [x for x in q if "late-hook" in x["item"]]
    assert len(late) == 1 and len(q) == 4
    assert late[0]["id"] not in {x["id"] for x in q if x is not late[0]}


def test_batch_reissued_expired_id_stays_one(env, monkeypatch):
    home, proj = env
    fx.session_start(proj)
    fx.full_scan(proj, scan=FakeScan())
    store = open_store()
    monkeypatch.setattr(type(store), "pending_expired", lambda self, pid: True)
    ids = {q["id"] for q in fx.quarantined(store)}
    assert len(ids) == 1


def test_reject_batch_removes_every_item(env):
    home, proj = env
    fx.session_start(proj)
    fx.full_scan(proj, scan=FakeScan())
    qid = _active()[0]["id"]
    assert main(["reject", qid]) == 0
    assert _active() == []
    s = json.loads((home / ".claude/settings.json").read_text())
    assert "statusLine" not in s and not any(s.get("hooks", {}).values())
