"""Agent adapters, ident migration and cache ruleset versioning (Task 10b)."""
from __future__ import annotations

import json
import sqlite3
from pathlib import Path

import bawwab.store as store_mod
from bawwab import inventory as inv
from bawwab.agents import ADAPTERS, AgentAdapter
from bawwab.agents.claude_code import ClaudeCodeAdapter
from bawwab.config import Config
from bawwab.fetch import parse_target
from bawwab.scan import scan_target
from bawwab.store import Store, _MIGRATIONS

FIX = Path(__file__).parent / "fixtures"


class Fake:
    def __init__(self):
        self.calls = 0

    def complete(self, system, user, schema, timeout_s):
        self.calls += 1
        return '{"findings":[]}'


def _w(p: Path, data) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data if isinstance(data, str) else json.dumps(data))


def test_adapters_registry():
    assert [a.name for a in ADAPTERS] == ["claude-code"]
    a = ADAPTERS[0]
    assert isinstance(a, ClaudeCodeAdapter)
    assert isinstance(a, AgentAdapter)


def test_watched_paths(tmp_path):
    home, cwd = Path.home(), tmp_path / "proj"
    paths = {str(p) for p in ClaudeCodeAdapter().watched_paths(cwd, home)}
    for p in (home / ".claude.json", home / ".claude/settings.json", home / ".claude/skills",
              home / ".claude/commands", home / ".claude/agents", cwd / ".mcp.json",
              cwd / ".claude/settings.json", cwd / ".claude/settings.local.json", cwd / ".claude/skills",
              home / ".claude/plugins/installed_plugins.json", home / ".claude/plugins/known_marketplaces.json"):
        assert str(p) in paths, p


def test_watch_table_is_stdlib_only():
    src = (Path(__file__).resolve().parent.parent / "bawwab/agents/claude_code_watch.py").read_text()
    assert "import bawwab" not in src and "from bawwab" not in src


def test_idents_prefixed_and_wrapper(tmp_path):
    h = Path.home()
    _w(h / ".claude.json", {"mcpServers": {"alpha": {"command": "npx", "args": ["-y", "@a/b"]}}})
    _w(h / ".claude/skills/s1/SKILL.md", "# s1")
    proj = tmp_path / "p"
    proj.mkdir()
    ids = {i.ident for i in ClaudeCodeAdapter().list_installed(proj)}
    assert ids == {"claude-code:mcp:user:alpha", "claude-code:skill:user:s1"}
    assert {i.ident for i in inv.list_installed(proj)} == ids


def test_baseline_idents_migrated(tmp_path):
    db = tmp_path / "old.db"
    conn = sqlite3.connect(str(db), isolation_level=None)
    for i in range(3):
        _MIGRATIONS[i](conn)
    conn.execute("PRAGMA user_version=3")
    conn.execute("INSERT INTO baseline VALUES ('mcp:user:x', 'k1', 't')")
    conn.execute("INSERT INTO inventory_seen VALUES ('skill:user:s', 'fp', 'k2', 'clean', 't')")
    conn.close()
    s = Store(db)
    assert s.get_baseline() == {"claude-code:mcp:user:x": "k1"}
    assert s.get_inventory_seen("claude-code:skill:user:s") == ("fp", "k2", "clean")
    Store(db)  # re-open: idempotent, no double prefix
    assert Store(db).get_baseline() == {"claude-code:mcp:user:x": "k1"}


def test_ruleset_version_computed():
    from bawwab.ruleset import RULESET_VERSION

    assert len(RULESET_VERSION) == 64 and store_mod.RULESET_VERSION == RULESET_VERSION


def test_ruleset_change_forces_rescan(tmp_path, monkeypatch):
    store = Store(tmp_path / "t.db")
    b = Fake()
    cfg = Config(review_enabled=False)  # count judge calls only; the reviewer (spec §4a) is tested in test_reviewer
    t = parse_target(str(FIX / "text/inject_skill"))
    r1 = scan_target(t, store=store, backend=b, cfg=cfg)
    assert b.calls == 1
    scan_target(t, store=store, backend=b, cfg=cfg)
    assert b.calls == 1  # cached
    assert store.get_cached(r1.key) is not None
    monkeypatch.setattr(store_mod, "RULESET_VERSION", "f" * 64)
    assert store.get_cached(r1.key) is None
    scan_target(t, store=store, backend=b, cfg=cfg)
    assert b.calls == 2  # rules changed: rescanned
    assert store.get_cached(r1.key) is not None


def test_old_rows_without_ruleset_are_ignored(tmp_path):
    store = Store(tmp_path / "t.db")
    store._conn.execute("INSERT INTO scans(key, report, scanned_at) VALUES ('K', '{}', 't')")
    assert store.get_cached("K") is None
