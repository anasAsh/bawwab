"""v1.1: adapters for the agents bawwab watches but doesn't gate (Cursor, Codex CLI, Claude Desktop, VS Code)."""
from __future__ import annotations

import json
import sys
from datetime import UTC, datetime
from pathlib import Path

import pytest

from bawwab import effects as fx
from bawwab.agents import ADAPTERS, ALL_ADAPTERS, WATCHED, AgentAdapter, adapter_for
from bawwab.agents.generic import TableAdapter, redact
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


# ------------------------------------------------------------------ registry and tables

def test_registry_keeps_claude_code_alone_in_the_gate():
    assert [a.name for a in ADAPTERS] == ["claude-code"]
    assert [a.name for a in ALL_ADAPTERS] == ["claude-code", "cursor", "codex", "claude-desktop", "vscode"]
    for a in WATCHED:
        assert isinstance(a, AgentAdapter) and not a.gated
    assert adapter_for("codex:mcp:user:x").name == "codex"
    assert adapter_for("claude-desktop:mcp:user:x").name == "claude-desktop"
    assert adapter_for("claude-code:mcp:user:x").name == "claude-code"


@pytest.mark.parametrize("name", ["cursor", "codex", "claude_desktop", "vscode"])
def test_watch_tables_are_stdlib_only(name):
    src = (ROOT / f"bawwab/agents/{name}_watch.py").read_text()
    assert "import bawwab" not in src and "from bawwab" not in src


def test_hook_loads_only_the_gated_table():
    fpm = fx.fp_module()
    assert [t.NAME for t in fpm._watch_tables()] == ["claude-code"]
    assert [t.NAME for t in fpm._watch_tables(("codex", "vscode"))] == ["codex", "vscode"]


def test_hook_fingerprint_ignores_other_agents(codex, tmp_path):
    fpm = fx.fp_module()
    home, cfg = codex
    before = fpm.fingerprint(str(tmp_path), str(home))
    cfg.write_text(CODEX_TOML + '\n[mcp_servers.new]\ncommand = "npx"\nargs = ["-y", "n@1"]\n')
    assert fpm.fingerprint(str(tmp_path), str(home)) == before  # Claude Code's hook never pays for Codex


def test_toml_digest_counts_only_servers_and_hooks(codex):
    fpm = fx.fp_module()
    home, cfg = codex
    d0 = fpm.semantic_digest("", str(home), ("codex",))
    f0 = fpm.fingerprint("", str(home), ("codex",))
    cfg.write_text(CODEX_TOML.replace('trust_level = "trusted"', 'trust_level = "untrusted"'))
    assert fpm.fingerprint("", str(home), ("codex",)) != f0
    assert fpm.semantic_digest("", str(home), ("codex",)) == d0  # Codex rewriting project trust is noise
    cfg.write_text(CODEX_TOML.replace("good-mcp@1.0.0", "good-mcp@1.0.1"))
    assert fpm.semantic_digest("", str(home), ("codex",)) != d0


# ------------------------------------------------------------------ reading each agent's config

def test_codex_items(codex):
    items = {it.ident: it for it in _a("codex").effect_items(None)}
    assert set(items) >= {"codex:mcp:user:good", "codex:mcp:user:evil.one", "codex:mcp:user:remote",
                          "codex:mcp:user:loader"}
    assert "codex:mcp:user:off" not in items  # enabled = false: nothing runs
    good = items["codex:mcp:user:good"]
    assert (good.target.kind, good.target.name, good.target.version) == ("npm", "good-mcp", "1.0.0")
    assert good.scope == "codex:user" and good.keypath == ("mcp_servers", "good")
    assert items["codex:mcp:user:remote"].target.kind == "remote"
    assert items["codex:mcp:user:loader"].env_hold == ("NODE_OPTIONS",)
    hooks = [it for it in items.values() if it.category == "hooks"]
    assert len(hooks) == 1 and "guard.py" in hooks[0].label  # [hooks.state] is Codex's own, not a hook
    skills = [it for it in items.values() if it.category == "skills"]
    assert [Path(s.path).name for s in skills] == ["s1"]
    dumped = json.dumps([it.value for it in items.values()]) + json.dumps([it.to_dict() for it in items.values()])
    assert SECRET not in dumped  # env and header values never leave the agent's file


def test_codex_project_scope(tmp_path):
    proj = tmp_path / "proj"
    _w(proj / ".codex/config.toml", '[mcp_servers.p]\ncommand = "npx"\nargs = ["-y", "p@1.0.0"]\n')
    _w(proj / ".agents/skills/ps/SKILL.md", "# ps")
    ids = {it.ident for it in _a("codex").effect_items(proj)}
    assert f"codex:mcp:project:{proj.resolve()}:p" in ids
    assert any(i.startswith("codex:skill:project:") for i in ids)
    assert not _a("codex").effect_items(None)


def test_cursor_items(tmp_path):
    home, proj = Path.home(), tmp_path / "proj"
    _w(home / ".cursor/mcp.json", {"mcpServers": {"c1": {"type": "stdio", "command": "npx", "args": ["-y", "c1@1.0.0"],
                                                         "env": {"KEY": SECRET}}}})
    _w(home / ".cursor/hooks.json", {"version": 1, "hooks": {"beforeShellExecution": [{"command": "./audit.sh"}]}})
    _w(proj / ".cursor/mcp.json", {"mcpServers": {"r": {"url": "https://x.example/mcp", "headers": {"A": SECRET}}}})
    items = {it.ident: it for it in _a("cursor").effect_items(proj)}
    assert "cursor:mcp:user:c1" in items and f"cursor:mcp:project:{proj.resolve()}:r" in items
    assert [it.category for it in items.values()].count("hooks") == 1
    assert SECRET not in json.dumps([it.value for it in items.values()])


def test_claude_desktop_paths(monkeypatch, tmp_path):
    import os

    xdg = Path(os.environ["XDG_CONFIG_HOME"])
    _w(xdg / "Claude/claude_desktop_config.json", {"preferences": {"x": 1},
                                                   "mcpServers": {"fs": {"command": "npx", "args": [
                                                       "-y", "@modelcontextprotocol/server-filesystem@1.0.0", "/tmp"]}}})
    _w(xdg / "Claude/Claude Extensions/ext.one/manifest.json", {"name": "ext"})
    ids = {it.ident: it for it in _a("claude-desktop").effect_items(None)}
    assert set(ids) == {"claude-desktop:mcp:user:fs", "claude-desktop:extension:ext.one"}
    assert ids["claude-desktop:extension:ext.one"].category == "plugins"
    monkeypatch.setattr(sys, "platform", "darwin")
    mac = Path.home() / "Library/Application Support/Claude/claude_desktop_config.json"
    assert str(mac) in {str(p) for p in _a("claude-desktop").watched_paths(None, Path.home())}


def test_vscode_items_jsonc(tmp_path):
    import os

    xdg, proj = Path(os.environ["XDG_CONFIG_HOME"]), tmp_path / "proj"
    _w(xdg / "Code/User/mcp.json", '{\n  // my servers\n  "servers": {\n    "v1": {"type": "stdio", "command": "npx",'
                                    ' "args": ["-y", "v1@1.0.0"],},\n  },\n  "inputs": [],\n}\n')
    _w(xdg / "Code/User/settings.json", {"editor.fontSize": 12, "mcp": {"servers": {"old": {"command": "uvx",
                                                                                        "args": ["old-mcp"]}}}})
    _w(proj / ".vscode/mcp.json", {"servers": {"w": {"type": "http", "url": "https://w.example/mcp"}}})
    _w(Path.home() / ".copilot/mcp-config.json", {"mcpServers": {"cp": {"command": "npx", "args": ["-y", "cp@1"]}}})
    _w(Path.home() / ".copilot/skills/k/SKILL.md", "# k")
    ids = {it.ident for it in _a("vscode").effect_items(proj)}
    assert {"vscode:mcp:user:v1", "vscode:mcp:user:old", "vscode:mcp:user:cp",
            f"vscode:mcp:project:{proj.resolve()}:w"} <= ids
    assert any(i.startswith("vscode:skill:user:") for i in ids)


def test_redact():
    r = redact({"command": "x", "env": {"A": SECRET}, "auth": {"client_secret": SECRET}, "url": "u"})
    assert SECRET not in json.dumps(r) and r["command"] == "x" and r["env"]["A"].startswith("sha256:")
    assert redact({"env": {"A": "1"}}) != redact({"env": {"A": "2"}})  # a changed value is still a change
