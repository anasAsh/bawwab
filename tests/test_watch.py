"""v1.1: the background watcher: holds for agents without a blocking hook, the loop, the service, status."""
from __future__ import annotations

import json
import sys
import tomllib
from datetime import UTC, datetime
from pathlib import Path

import pytest

from bawwab import effects as fx
from bawwab import watch
from bawwab.agents import ADAPTERS, WATCHED
from bawwab.agents.generic import TableAdapter
from bawwab.cli import main
from bawwab.store import open_store
from bawwab.types import Finding, Mode, ScanReport, Severity, Verdict

ROOT = Path(__file__).resolve().parent.parent
SECRET = "sk-SECRET-VALUE-123"


def _w(p: Path, data) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data if isinstance(data, str) else json.dumps(data, indent=2))
    return p


class FakeScan:
    def __init__(self, default=Verdict.CLEAN, **by_raw):
        self.default, self.by_raw, self.calls = default, by_raw, []

    def __call__(self, t, **kw):
        self.calls.append(t)
        v = next((v for k, v in self.by_raw.items() if k in (t.raw or "")), self.default)
        findings = [] if v == Verdict.CLEAN else [Finding("x.rule", Severity.HIGH, "static", "BAWWAB-CANARY evil")]
        return ScanReport(f"k:{t.kind}:{t.name or t.raw}", t, "1.0.0", Mode.STANDARD, v, findings, datetime.now(UTC))


def _a(name: str) -> TableAdapter:
    return next(a for a in WATCHED if a.name == name)


CODEX_TOML = f"""model = "gpt-5"

[projects."/home/x/dev"]
trust_level = "trusted"

[mcp_servers.good]
command = "npx"
args = ["-y", "good-mcp@1.0.0"]

[mcp_servers.good.env]
API_TOKEN = "{SECRET}"

[mcp_servers."evil.one"]
command = "npx"
args = ["-y", "evil-mcp@2.0.0"]
tools = {{ x = {{ approval_mode = "auto" }} }}

[mcp_servers.remote]
url = "https://mcp.example.com/mcp"
http_headers = {{ Authorization = "Bearer {SECRET}" }}

[mcp_servers.loader]
command = "npx"
args = ["-y", "loader-mcp@1.0.0"]
env_vars = ["NODE_OPTIONS"]

[mcp_servers.off]
command = "npx"
args = ["-y", "off-mcp@1.0.0"]
enabled = false

[[hooks.PreToolUse]]
matcher = "^Bash$"

[[hooks.PreToolUse.hooks]]
type = "command"
command = "python3 ~/.codex/guard.py"

[hooks.state."x:hooks.json:pre_tool_use:0:0"]
trusted_hash = "abc"
"""


@pytest.fixture
def codex(tmp_path):
    home = Path.home()
    cfg = _w(home / ".codex/config.toml", CODEX_TOML)
    _w(home / ".agents/skills/s1/SKILL.md", "# s1")
    return home, cfg


# ------------------------------------------------------------------ holds

def test_hold_is_recorded_not_blocking(codex):
    store = open_store()
    scan = FakeScan(**{"evil-mcp": Verdict.SUSPICIOUS})
    ids = watch.check_agent(_a("codex"), [], scan, store)
    held = store.quarantine_rows(fx.HELD)
    # evil server held; the env loader and the hook are unscannable, held until approved
    names = sorted(q["ident"] for q in held)
    assert "codex:mcp:user:evil.one" in names and "codex:mcp:user:loader" in names
    assert any(n.startswith("codex:hook:") for n in names)
    assert "codex:mcp:user:good" not in names and len(ids) == len(held)
    assert store.active_quarantine() == []  # Claude Code is never blocked by another agent's item
    assert not fx.fp_module().quarantine_active(str(fx.bawwab_home()))
    n_calls = len(scan.calls)
    assert watch.check_agent(_a("codex"), [], scan, store) == []  # nothing new: no rescan, no second hold
    assert len(scan.calls) == n_calls
    for q in held:
        assert SECRET not in q["item"] + q["report"]


def test_status_approve_and_reject(codex, capsys):
    home, cfg = codex
    store = open_store()
    watch.check_agent(_a("codex"), [], FakeScan(**{"evil-mcp": Verdict.SUSPICIOUS}), store)
    assert main(["status"]) == 1
    out = capsys.readouterr().out
    assert "Codex CLI —" in out and "on hold" in out and "was not stopped" in out
    assert "Claude Code — nothing quarantined." in out and SECRET not in out
    by = {q["ident"]: q for q in fx.quarantined(store, fx.HELD)}
    assert main(["reject", by["codex:mcp:user:evil.one"]["id"]]) == 0
    data = tomllib.loads(cfg.read_text())
    assert "evil.one" not in data["mcp_servers"]
    assert data["mcp_servers"]["good"]["env"]["API_TOKEN"] == SECRET  # the rest is untouched
    assert data["projects"] == {"/home/x/dev": {"trust_level": "trusted"}}
    assert list((fx.bawwab_home() / "backups").iterdir())
    assert main(["approve", by["codex:mcp:user:loader"]["id"]]) == 0
    capsys.readouterr()
    left = {q["ident"] for q in fx.quarantined(store, fx.HELD)}
    assert "codex:mcp:user:loader" not in left and "codex:mcp:user:evil.one" not in left
    assert watch.check_agent(_a("codex"), [], FakeScan(), store) == []  # approved stays accepted
    row = store.effect_rows_by_ident("codex:mcp:user:loader")
    assert row["status"] == "approved" and row["scope"] == "codex:user"


def test_changed_item_held_again_and_gone(codex):
    home, cfg = codex
    store = open_store()
    scan = FakeScan(**{"evil-mcp": Verdict.SUSPICIOUS})
    watch.check_agent(_a("codex"), [], scan, store)
    cfg.write_text(CODEX_TOML.replace('[mcp_servers."evil.one"]\ncommand = "npx"\nargs = ["-y", "evil-mcp@2.0.0"]\n'
                                      'tools = { x = { approval_mode = "auto" } }\n', ""))
    watch.check_agent(_a("codex"), [], scan, store)
    assert "codex:mcp:user:evil.one" not in {q["ident"] for q in store.quarantine_rows(fx.HELD)}


@pytest.mark.parametrize("level,verdict,held", [("low", Verdict.MALICIOUS, False), ("medium", Verdict.SUSPICIOUS, False),
                                                ("medium", Verdict.MALICIOUS, True), ("high", Verdict.SUSPICIOUS, True)])
def test_levels(level, verdict, held, tmp_path):
    from bawwab.config import set_level

    set_level(level)
    _w(Path.home() / ".cursor/mcp.json", {"mcpServers": {"e": {"command": "npx", "args": ["-y", "evil-mcp@1.0.0"]}}})
    store = open_store()
    warned: list[str] = []
    ids = watch.check_agent(_a("cursor"), [], FakeScan(**{"evil-mcp": verdict}), store, warned)
    assert bool(ids) == held and bool(warned) == (not held)
    if not held:
        assert store.effect_rows_by_ident("cursor:mcp:user:e")["status"] == "warned"


def test_reject_json_hook_and_skill(tmp_path):
    home = Path.home()
    hooks = _w(home / ".cursor/hooks.json", {"version": 1, "hooks": {"stop": [{"command": "a.sh"}, {"command": "b.sh"}]}})
    _w(home / ".agents/skills/bad/SKILL.md", "# bad")
    store = open_store()
    watch.check_agent(_a("cursor"), [], FakeScan(), store)
    watch.check_agent(_a("codex"), [], FakeScan(Verdict.SUSPICIOUS), store)
    rows = {q["ident"]: q for q in fx.quarantined(store, fx.HELD)}
    hook_a = next(q for i, q in rows.items() if i.startswith("cursor:hook:") and "a.sh" in q["item"])
    ok, msg = fx.reject_quarantined(hook_a["id"], store)
    assert ok, msg
    assert json.loads(hooks.read_text())["hooks"] == {"stop": [{"command": "b.sh"}]}
    skill = next(q for i, q in rows.items() if i.startswith("codex:skill:"))
    ok, msg = fx.reject_quarantined(skill["id"], store)
    assert ok and not (home / ".agents/skills/bad").exists()
    assert any(p.name.endswith("-bad") for p in (fx.bawwab_home() / "quarantine").iterdir())


def test_toml_removal_keeps_layout_and_refuses_inline(tmp_path):
    from bawwab.agents.generic import _remove_toml_table

    f = _w(tmp_path / "c.toml", 'a = 1\n\n[mcp_servers."x.y"]\ncommand = "n"\n\n[mcp_servers."x.y".env]\nK = "v"\n\n'
                                '[mcp_servers.z]\ncommand = "m"\n# trailing\n[other]\nb = 2\n')
    ok, msg = _remove_toml_table(f, ["mcp_servers", "x.y"])
    assert ok, msg
    assert tomllib.loads(f.read_text()) == {"a": 1, "mcp_servers": {"z": {"command": "m"}}, "other": {"b": 2}}
    g = _w(tmp_path / "d.toml", '[mcp_servers]\nq = { command = "n" }\n')
    ok, msg = _remove_toml_table(g, ["mcp_servers", "q"])
    assert not ok and "by hand" in msg and tomllib.loads(g.read_text())["mcp_servers"]["q"]
    h = _w(tmp_path / "e.toml", '[mcp_servers.only]\ncommand = "n"\n')
    assert _remove_toml_table(h, ["mcp_servers", "only"])[0] and tomllib.loads(h.read_text()) == {}


def test_jsonc_file_is_left_to_the_user(tmp_path):
    import os

    f = _w(Path(os.environ["XDG_CONFIG_HOME"]) / "Code/User/mcp.json",
           '{\n // c\n "servers": {"e": {"command": "npx", "args": ["-y", "evil-mcp@1.0.0"]}}\n}\n')
    store = open_store()
    (qid,) = watch.check_agent(_a("vscode"), [], FakeScan(Verdict.SUSPICIOUS), store)
    ok, msg = fx.reject_quarantined(qid, store)
    assert not ok and "by hand" in msg and "// c" in f.read_text()


# ------------------------------------------------------------------ the watcher loop

class Clock:
    def __init__(self):
        self.t = 1000.0

    def __call__(self):
        return self.t


def test_watcher_debounces_then_notifies(codex):
    notes: list[tuple[str, str]] = []
    clock = Clock()
    w = watch.Watcher(agents=[_a("codex")], projects=[], scan=FakeScan(**{"evil-mcp": Verdict.SUSPICIOUS}),
                      notifier=lambda t, b: notes.append((t, b)), debounce=1.5, clock=clock, log=lambda m: None)
    assert w.tick() == {} and notes == []  # change seen, not settled yet
    clock.t += 2
    found = w.tick()
    assert found.get("codex") and len(notes) == 1
    assert "Codex CLI" in notes[0][0] and "on hold" in notes[0][0] and SECRET not in notes[0][1]
    clock.t += 5
    assert w.tick() == {} and len(notes) == 1  # unchanged: fingerprint only
    st = json.loads(watch.state_path().read_text())
    assert st["agents"]["codex"]["fp"] and st["heartbeat"] == clock.t


def test_watcher_noise_does_not_check(codex):
    home, cfg = codex
    scan = FakeScan()
    w = watch.Watcher(agents=[_a("codex")], projects=[], scan=scan, notifier=None, debounce=0, log=lambda m: None)
    w.tick()
    n = len(scan.calls)
    cfg.write_text(CODEX_TOML.replace('model = "gpt-5"', 'model = "gpt-6"'))
    w.tick()
    assert len(scan.calls) == n


def test_watcher_survives_unreadable_and_failures(codex, monkeypatch):
    home, cfg = codex
    cfg.write_text("[mcp_servers.x\n")  # mid-write
    notes = []
    w = watch.Watcher(agents=[_a("codex")], projects=[], scan=FakeScan(), notifier=lambda t, b: notes.append(t),
                      debounce=0, log=lambda m: None)
    w.tick()
    assert "codex" not in json.loads(watch.state_path().read_text())["agents"]  # looked at again next tick
    cfg.write_text(CODEX_TOML)
    monkeypatch.setattr(watch, "check_agent", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    w.tick()
    w.tick()
    assert notes == ["bawwab: could not check Codex CLI"]  # once, not every tick


def test_watcher_runs_claude_codes_own_check(monkeypatch):
    seen = []
    monkeypatch.setattr(fx, "refresh", lambda cwd, scan=None, store=None: seen.append(Path(cwd)) or ["QID1"])
    notes = []
    w = watch.Watcher(agents=list(ADAPTERS), projects=[], notifier=lambda t, b: notes.append((t, b)), debounce=0,
                      log=lambda m: None)
    assert w.tick(force=True) == {"claude-code": ["QID1"]}
    assert seen == [watch.claude_scope_dir()] and "quarantined" in notes[0][0]


def test_once_cli(capsys):
    assert main(["watch", "--once", "--no-notify", "--agent", "claude-desktop"]) == 0  # nothing configured
    out = capsys.readouterr().out
    assert "bawwab status" in out and "Claude Desktop — nothing on hold." in out
    assert "claude-desktop" in json.loads(watch.state_path().read_text())["agents"]
    assert main(["watch", "--agent", "nope"]) == 3


# ------------------------------------------------------------------ service files and notifications

def test_install_systemd_unit_into_injected_dir(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    calls = []
    path, msgs = watch.install_service(tmp_path / "units", runner=calls.append)
    text = path.read_text()
    assert path.name == "bawwab-watch.service" and calls == []  # an injected dir is never started
    assert f"ExecStart={sys.executable} -P -m bawwab.cli watch" in text and "WorkingDirectory=" in text and "WantedBy=default.target" in text
    assert "BAWWAB_HOME=" in text
    assert any("systemctl --user enable --now" in m for m in msgs)
    path, _ = watch.install_service(tmp_path / "units", start=True, runner=calls.append)
    assert calls == [["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now",
                                                                "bawwab-watch.service"]]
    ok, _ = watch.uninstall_service(tmp_path / "units", runner=calls.append)
    assert ok and not path.exists() and len(calls) == 2


def test_install_launchd_plist(tmp_path, monkeypatch):
    import plistlib

    monkeypatch.setattr(sys, "platform", "darwin")
    path, _ = watch.install_service(tmp_path)
    data = plistlib.loads(path.read_bytes())
    assert path.name == "dev.bawwab.watch.plist" and data["Label"] == "dev.bawwab.watch"
    assert data["ProgramArguments"][-3:] == ["-m", "bawwab.cli", "watch"] and data["KeepAlive"] is True


def test_cli_install_uses_unit_dir(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(sys, "platform", "linux")
    assert main(["watch", "--install", "--unit-dir", str(tmp_path)]) == 0
    assert (tmp_path / "bawwab-watch.service").exists()
    assert main(["watch", "--uninstall", "--unit-dir", str(tmp_path)]) == 0
    assert not (tmp_path / "bawwab-watch.service").exists()
    assert main(["watch", "--uninstall", "--unit-dir", str(tmp_path)]) == 1


def test_notify_is_best_effort(monkeypatch):
    import subprocess

    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(watch.shutil, "which", lambda n: None)
    assert watch.notify("t", "b") is False
    monkeypatch.setattr(watch.shutil, "which", lambda n: "/usr/bin/" + n)
    seen = []
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: seen.append(argv))
    assert watch.notify("title", "body") is True and seen[0][0] == "notify-send" and seen[0][-2:] == ["title", "body"]

    def boom(*a, **k):
        raise OSError("no display")

    monkeypatch.setattr(subprocess, "run", boom)
    assert watch.notify("t", "b") is False
    monkeypatch.setattr(sys, "platform", "darwin")
    monkeypatch.setattr(subprocess, "run", lambda argv, **kw: seen.append(argv))
    assert watch.notify('say "hi"', "b") is True
    assert seen[-1][0] == "osascript" and seen[-1][-2] == 'say "hi"'  # argv, never pasted into the script
