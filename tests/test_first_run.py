"""First run (spec §1a): ask before scanning, init --scan / --skip, scan --all."""
from __future__ import annotations

import io
import json
from datetime import UTC, datetime
from pathlib import Path

import pytest

from bawwab import effects as fx
from bawwab import inventory as inv
from bawwab.agents import value_hash
from bawwab.cli import main
from bawwab.gate.detect import HookInput
from bawwab.gate.gate import run_gate
from bawwab.store import open_store
from bawwab.types import Finding, Mode, ScanReport, Severity, Verdict


def _w(p: Path, data) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data if isinstance(data, str) else json.dumps(data))


class FakeScan:
    def __init__(self, **by_raw):
        self.by_raw, self.calls = by_raw, []

    def __call__(self, t, **kw):
        self.calls.append(t)
        v = next((v for k, v in self.by_raw.items() if k in t.raw), Verdict.CLEAN)
        f = [] if v == Verdict.CLEAN else [Finding("x.rule", Severity.HIGH, "static", "BAWWAB-CANARY")]
        return ScanReport(f"k:{t.raw}", t, "1.0.0", Mode.STANDARD, v, f, datetime.now(UTC))


@pytest.fixture
def proj(tmp_path):
    home = Path.home()
    _w(home / ".claude.json", {"mcpServers": {"a": {"command": "npx", "args": ["-y", "a@1.0.0"]},
                                              "b": {"url": "https://b.invalid/mcp"}}})
    _w(home / ".claude/skills/s1/SKILL.md", "# s1")
    _w(home / ".claude/settings.json", {"hooks": {"Stop": [{"hooks": [{"type": "command", "command": "say hi"}]}]}})
    p = tmp_path / "proj"
    p.mkdir()
    return p


def _session_start(proj: Path, capsys) -> dict | None:
    assert main(["inventory", "--cwd", str(proj)]) == 0
    out = capsys.readouterr().out.strip()
    return json.loads(out) if out else None


def _flat(proj: Path) -> dict:
    return {i: value_hash(v) for cat in fx.semantic_state(proj).values() for i, v in cat.items()}


def test_fresh_install_asks_and_spawns_nothing(proj, capsys):
    out = _session_start(proj, capsys)  # conftest fails the test if the background scan is spawned
    ctx = out["hookSpecificOutput"]["additionalContext"]
    assert out["hookSpecificOutput"]["hookEventName"] == "SessionStart"
    assert "2 MCP servers, 1 skills, 0 plugins (3 items)" in ctx
    assert "about 1 min" in ctx and "bawwab init --scan" in ctx and "! bawwab init --skip" in ctx
    store = open_store()
    assert store.init_state() == "none"
    rows = store.all_effect_rows()
    assert {i: r["hash"] for i, r in rows.items()} == _flat(proj)
    assert {r["status"] for r in rows.values()} == {"provisional"}
    # no answer: asked again next session
    assert "bawwab init --scan" in _session_start(proj, capsys)["hookSpecificOutput"]["additionalContext"]


def test_init_scan_spawns_and_sets_scanned(proj, monkeypatch, capsys):
    spawned = []
    monkeypatch.setattr(inv, "spawn_background", lambda cwd, full=False: spawned.append((Path(cwd), full)))
    assert main(["init", "--scan", "--cwd", str(proj)]) == 0
    assert spawned == [(proj, True)]
    assert open_store().init_state() == "scanned"
    assert "background" in capsys.readouterr().out
    # after init the SessionStart hook is the usual background inventory, no question
    spawned.clear()
    out = _session_start(proj, capsys)
    assert spawned == [(proj, False)] and out is None


def test_init_skip_trusts_current_state(proj, capsys):
    _session_start(proj, capsys)
    assert main(["init", "--skip", "--cwd", str(proj)]) == 0
    store = open_store()
    assert store.init_state() == "skipped"
    rows = store.all_effect_rows()
    assert {i: r["hash"] for i, r in rows.items()} == _flat(proj)
    assert {r["status"] for r in rows.values()} == {"unscanned"}
    assert "trusted without scan" in capsys.readouterr().out


def test_init_skip_without_session_start(proj):
    assert main(["init", "--skip", "--cwd", str(proj)]) == 0
    assert {i: r["hash"] for i, r in open_store().all_effect_rows().items()} == _flat(proj)


def test_effect_check_before_init_uses_provisional_baseline(proj, capsys):
    _session_start(proj, capsys)
    scan = FakeScan(**{"evil": Verdict.SUSPICIOUS})
    assert fx.refresh(proj, scan=scan) == [] and scan.calls == []  # pre-install state: not flagged
    d = json.loads((Path.home() / ".claude.json").read_text())
    d["mcpServers"]["evil"] = {"command": "npx", "args": ["-y", "evil@1.0.0"]}
    _w(Path.home() / ".claude.json", d)
    assert len(fx.refresh(proj, scan=scan)) == 1  # a change after install is


def test_full_scan_accepts_clean_quarantines_rest(proj, capsys):
    _session_start(proj, capsys)
    scan = FakeScan(**{"b.invalid": Verdict.SUSPICIOUS})
    ids = fx.full_scan(proj, scan=scan)
    store = open_store()
    assert store.init_state() == "scanned"
    assert len(ids) == 2
    q = fx.quarantined(store)
    assert [x["ident"] for x in q][0] == "claude-code:mcp:user:b"
    assert ":hook:" in q[1]["ident"]  # nothing is trusted without a scan: the install-time hook needs approval
    rows = store.all_effect_rows()
    assert rows["claude-code:mcp:user:a"]["status"] == "accepted"
    assert rows["claude-code:skill:user:s1"]["status"] == "accepted"
    assert not any(":hook:" in i for i in rows)
    assert any("is SUSPICIOUS" in w for w in store.take_warnings())  # the Task 10 inventory ran too


def test_background_full_flag_runs_full_scan(proj, monkeypatch):
    got = []
    monkeypatch.setattr(fx, "full_scan", lambda cwd, **kw: got.append(Path(cwd)) or [])
    assert main(["inventory", "--background", "--full", "--cwd", str(proj)]) == 0
    assert got == [proj]


def test_scan_all_spawns_full_inventory(proj, monkeypatch, capsys):
    spawned = []
    monkeypatch.setattr(inv, "spawn_background", lambda cwd, full=False: spawned.append(full))
    monkeypatch.chdir(proj)
    assert main(["scan", "--all"]) == 0
    assert spawned == [True]
    assert main(["scan"]) == 3  # a target or --all is required


@pytest.mark.parametrize("cmd,blocked", [
    ("bawwab init --skip", True),
    ("bawwab init", True),
    ("cd /tmp && bawwab init --skip", True),
    ("uv run bawwab init --skip", True),
    ("bawwab init --scan --skip", True),
    ("bawwab init --scan", False),
    ("bawwab scan --all", False),
    ("bawwab approve ABCD", True),
    ("bawwab reject ABCD", True),
])
def test_gate_protects_init_skip(cmd, blocked, tmp_path):
    out = run_gate(HookInput("Bash", {"command": cmd}, str(tmp_path)), scan=FakeScan())
    if blocked:
        assert out["hookSpecificOutput"]["permissionDecision"] == "deny", cmd
    else:
        assert out is None, cmd


@pytest.mark.real_spawn
def test_spawn_background_full_argv(monkeypatch, proj):
    calls = []
    monkeypatch.setattr(inv.subprocess, "Popen", lambda argv, **kw: calls.append(argv))
    inv.spawn_background(proj, full=True)
    inv.spawn_background(proj)
    assert calls[0][-4:] == ["--background", "--full", "--cwd", str(proj)]
    assert calls[1][-3:] == ["--background", "--cwd", str(proj)]


def test_hook_stdin_cwd_for_inventory(proj, monkeypatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({"cwd": str(proj)})))
    assert main(["inventory"]) == 0
    assert "bawwab init --scan" in capsys.readouterr().out
