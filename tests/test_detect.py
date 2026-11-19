from __future__ import annotations

import importlib.util
import json
from pathlib import Path

import pytest

from bawwab.gate.detect import HookInput, Protected, Targets, detect_install
from bawwab.types import Target

ROOT = Path(__file__).resolve().parent.parent


def _load_hook():
    spec = importlib.util.spec_from_file_location("bawwab_hook", ROOT / "hooks" / "bawwab_hook.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def home(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("BAWWAB_HOME", str(h / ".bawwab"))
    mk = h / ".claude" / "plugins" / "marketplaces" / "mk"
    (mk / ".claude-plugin").mkdir(parents=True)
    (mk / "plugins" / "foo").mkdir(parents=True)
    (mk / ".claude-plugin" / "marketplace.json").write_text(json.dumps({
        "name": "mk",
        "plugins": [
            {"name": "foo", "source": "./plugins/foo"},
            {"name": "gh", "source": {"source": "github", "repo": "o/r"}},
            {"name": "u", "source": {"source": "url", "url": "https://example.com/x.git", "sha": "abc"}},
            {"name": "sub", "source": {"source": "git-subdir", "url": "https://github.com/o/mono.git",
                                       "path": "plugins/sub", "ref": "v1.0"}},
            {"name": "cmd", "source": {"source": "command", "command": "xcrun thing"}},
        ],
    }))
    (h / ".claude" / "plugins" / "known_marketplaces.json").write_text(json.dumps({
        "mk": {"source": {"source": "github", "repo": "o/mk"}, "installLocation": str(mk)},
    }))
    proj = tmp_path / "proj"
    proj.mkdir()
    return h


def bash(cmd: str, cwd: str = "/tmp") -> HookInput:
    return HookInput("Bash", {"command": cmd}, cwd)


def only(res) -> Target:
    assert isinstance(res, Targets), res
    assert len(res.targets) == 1, res.targets
    return res.targets[0]


# ------------------------------------------------------------------ positives

def _positive_cases(home: Path) -> list[HookInput]:
    proj = home.parent / "proj"
    (proj / "myskill").mkdir(exist_ok=True)
    return [
        bash("claude mcp add gh -- npx -y @a/b"),
        bash("cd /x && FOO=1 claude mcp add gh -- npx -y @a/b"),
        bash('bash -c "claude mcp add gh -- uvx mcp-x"'),
        bash("sudo -E env A=1 command claude mcp add -s user -e A=1 B=2 gh -- npx -y @a/b@1.2.3"),
        bash("claude mcp add --transport http notion https://mcp.notion.com/mcp"),
        bash("claude mcp add weird -- ./run.sh"),
        bash("""claude mcp add-json gh '{"command":"npx","args":["-y","@a/b"]}'"""),
        bash("""claude mcp add-json r '{"type":"http","url":"https://mcp.example.com/mcp"}'"""),
        bash("claude mcp add-json bad '{not json'"),
        bash("claude plugin install foo@mk"),
        bash("claude plugin install gh@mk"),
        bash("claude plugin install u@mk --scope project"),
        bash("claude plugin install sub@mk"),
        bash("claude plugin install cmd@mk"),
        bash("claude plugin install nope@mk"),
        bash("claude plugin install foo@nomk"),
        bash("claude plugin marketplace add o/r"),
        bash("git clone https://github.com/o/r ~/.claude/skills/r"),
        bash("cd ~/.claude/skills && git clone --depth 1 https://github.com/o/r"),
        bash(f"cp -r ./myskill {home}/.claude/skills/", cwd=str(proj)),
        bash("mv ./myskill .claude/commands/", cwd=str(proj)),
        bash("curl -sL -o ~/.claude/commands/x.md https://example.com/x.md"),
        bash("wget -O ~/.claude/skills/x.zip https://example.com/x.zip"),
        bash("bawwab approve ab12"),
        bash("uv run bawwab reject AB12"),
        bash("rm -f ~/.bawwab/bawwab.db"),
        bash("echo '{}' > .claude/bawwab.json", cwd=str(proj)),
        bash("echo hi > ~/.claude/skills/a/SKILL.md"),
        bash("""echo '{"mcpServers":{}}' > .mcp.json""", cwd=str(proj)),
        bash("c\"\"laude mcp add gh -- npx -y @a/b"),
        HookInput("Write", {"file_path": str(home / ".claude/skills/foo/SKILL.md"), "content": "x"}, "/tmp"),
        HookInput("Write", {"file_path": ".mcp.json", "content": '{"mcpServers":{"x":{"command":"uvx","args":["m"]}}}'},
                  str(proj)),
        HookInput("Write", {"file_path": str(home / ".claude.json"),
                            "content": '{"mcpServers":{"x":{"command":"uvx","args":["m"]}}}'}, "/tmp"),
        HookInput("Write", {"file_path": str(home / ".claude/settings.json"), "content": '{"hooks":{"a":1}}'}, "/tmp"),
        HookInput("Write", {"file_path": ".claude/bawwab.json", "content": "{}"}, str(proj)),
        HookInput("Write", {"file_path": str(home / ".bawwab/config.json"), "content": "{}"}, "/tmp"),
    ]


def test_claude_mcp_add_npx(home):
    t = only(detect_install(bash("claude mcp add gh -- npx -y @a/b")))
    assert (t.kind, t.name, t.version) == ("npm", "@a/b", None)
    assert detect_install(bash("claude mcp add gh -- npx -y @a/b")).pinnable


def test_chained_and_prefixed(home):
    t = only(detect_install(bash("cd /x && FOO=1 claude mcp add gh -- npx -y @a/b")))
    assert (t.kind, t.name) == ("npm", "@a/b")
    t = only(detect_install(bash("ls; sudo -E env A=1 command claude mcp add gh -- npx -y @a/b@1.2.3")))
    assert (t.name, t.version) == ("@a/b", "1.2.3")
    t = only(detect_install(bash("true\n/usr/local/bin/claude mcp add gh -- npx -y @a/b")))
    assert t.name == "@a/b"


def test_bash_c_recursion(home):
    t = only(detect_install(bash('bash -c "claude mcp add gh -- uvx mcp-x"')))
    assert (t.kind, t.name) == ("pypi", "mcp-x")
    t = only(detect_install(bash("sh -lc 'cd /x && claude mcp add gh -- uvx mcp-y'")))
    assert t.name == "mcp-y"


def test_mcp_add_flags_and_env(home):
    t = only(detect_install(bash("claude mcp add -s user -e A=1 B=2 gh -- npx -y @a/b@1.2.3")))
    assert (t.name, t.version) == ("@a/b", "1.2.3")
    t = only(detect_install(bash("claude mcp add gh --env A=1 -- uvx --from mcp-z==0.3 mcp-z")))
    assert (t.kind, t.name, t.version) == ("pypi", "mcp-z", "0.3")


def test_mcp_add_transport_url(home):
    t = only(detect_install(bash("claude mcp add --transport http notion https://mcp.notion.com/mcp")))
    assert (t.kind, t.url) == ("remote", "https://mcp.notion.com/mcp")
    t = only(detect_install(bash("claude mcp add -t sse -H 'Authorization: x' s https://mcp.example.com/sse")))
    assert t.url == "https://mcp.example.com/sse"


def test_mcp_add_unrecognized_is_protected(home):
    r = detect_install(bash("claude mcp add weird -- ./run.sh"))
    assert isinstance(r, Protected) and "unrecognized MCP command" in r.reason


def test_mcp_add_json(home):
    t = only(detect_install(bash("""claude mcp add-json gh '{"command":"npx","args":["-y","@a/b"]}'""")))
    assert (t.kind, t.name) == ("npm", "@a/b")
    t = only(detect_install(bash("""claude mcp add-json -s user r '{"type":"http","url":"https://mcp.example.com/mcp"}'""")))
    assert t.kind == "remote"
    assert isinstance(detect_install(bash("claude mcp add-json bad '{not json'")), Protected)


def test_plugin_install_relative(home):
    t = only(detect_install(bash("claude plugin install foo@mk")))
    mk = home / ".claude" / "plugins" / "marketplaces" / "mk"
    assert t.kind == "local" and Path(t.path) == (mk / "plugins" / "foo").resolve()
    assert not detect_install(bash("claude plugin install foo@mk")).pinnable


def test_plugin_install_git_sources(home):
    t = only(detect_install(bash("claude plugin install gh@mk")))
    assert (t.kind, t.url) == ("git", "https://github.com/o/r.git")
    t = only(detect_install(bash("claude plugin install u@mk --scope project")))
    assert (t.kind, t.url) == ("git", "https://example.com/x.git")
    t = only(detect_install(bash("claude plugin install sub@mk")))
    assert (t.kind, t.url, t.version) == ("git", "https://github.com/o/mono.git", "v1.0")


def test_plugin_install_unique_name_without_marketplace(home):
    t = only(detect_install(bash("claude plugin install foo")))
    assert t.kind == "local"


@pytest.mark.parametrize("cmd", [
    "claude plugin install cmd@mk", "claude plugin install nope@mk", "claude plugin install foo@nomk",
])
def test_plugin_install_unresolvable(home, cmd):
    assert isinstance(detect_install(bash(cmd)), Protected)


def test_marketplace_add(home):
    r = detect_install(bash("claude plugin marketplace add o/r"))
    assert isinstance(r, Protected) and r.reason == "new marketplace: o/r"


def test_git_clone_into_skills(home):
    t = only(detect_install(bash("git clone https://github.com/o/r ~/.claude/skills/r")))
    assert (t.kind, t.url) == ("git", "https://github.com/o/r")
    t = only(detect_install(bash("cd ~/.claude/skills && git clone --depth 1 -b v2 https://github.com/o/r")))
    assert (t.url, t.version) == ("https://github.com/o/r", "v2")
    assert detect_install(bash("git clone https://github.com/o/r /tmp/r")) is None


def test_cp_mv_into_dirs(home):
    proj = home.parent / "proj"
    (proj / "myskill").mkdir()
    t = only(detect_install(bash(f"cp -r ./myskill {home}/.claude/skills/", cwd=str(proj))))
    assert t.kind == "local" and Path(t.path) == (proj / "myskill").resolve()
    t = only(detect_install(bash("mv ./myskill .claude/commands/", cwd=str(proj))))
    assert Path(t.path) == (proj / "myskill").resolve()
    assert detect_install(bash("cp -r ./myskill /tmp/elsewhere", cwd=str(proj))) is None


@pytest.mark.parametrize("cmd", [
    "curl -sL -o ~/.claude/commands/x.md https://example.com/x.md",
    "wget -O ~/.claude/skills/x.zip https://example.com/x.zip",
    "cd ~/.claude/skills && curl -O https://example.com/x.zip",
])
def test_downloads_are_protected(home, cmd):
    r = detect_install(bash(cmd))
    assert isinstance(r, Protected) and r.reason == "unscannable download"


@pytest.mark.parametrize("cmd", [
    "bawwab approve ab12", "uv run bawwab reject AB12", "BAWWAB_X=1 bawwab approve --force ab12",
    "rm -f ~/.bawwab/bawwab.db", "sqlite3 ~/.bawwab/bawwab.db 'insert into approvals values(1,2)'",
])
def test_bawwab_self_protection(home, cmd):
    assert isinstance(detect_install(bash(cmd)), Protected)


def test_project_bawwab_json_protected(home):
    proj = str(home.parent / "proj")
    assert isinstance(detect_install(bash("echo '{}' > .claude/bawwab.json", cwd=proj)), Protected)
    w = HookInput("Write", {"file_path": f"{proj}/.claude/bawwab.json", "content": "{}"}, proj)
    assert isinstance(detect_install(w), Protected)
    w = HookInput("Write", {"file_path": f"{home}/.bawwab/config.json", "content": "{}"}, proj)
    assert isinstance(detect_install(w), Protected)


def test_shell_writes_into_install_dirs_protected(home):
    assert isinstance(detect_install(bash("echo hi > ~/.claude/skills/a/SKILL.md")), Protected)
    assert isinstance(detect_install(bash("echo hi | tee ~/.claude/agents/a.md")), Protected)
    proj = str(home.parent / "proj")
    assert isinstance(detect_install(bash("""echo '{"mcpServers":{}}' > .mcp.json""", cwd=proj)), Protected)


@pytest.mark.parametrize("cmd", [
    "ls -la", "grep approve bawwab/store.py", "claude --version", "claude mcp list",
    "cat ~/.claude.json | jq .mcpServers", "mkdir -p ~/.claude/skills/new", "git status",
    "echo claude > /tmp/x", "git clone https://github.com/o/r",
])
def test_negatives(home, cmd):
    assert detect_install(bash(cmd)) is None


# ------------------------------------------------------------- config edits

def _claude_json(home: Path, data: dict) -> Path:
    p = home / ".claude.json"
    p.write_text(json.dumps(data, indent=2))
    return p


def test_claude_json_numstartups_only_is_none(home):
    p = _claude_json(home, {"numStartups": 5, "mcpServers": {"a": {"command": "npx", "args": ["-y", "a"]}}})
    e = HookInput("Edit", {"file_path": str(p), "old_string": '"numStartups": 5', "new_string": '"numStartups": 6'}, "/tmp")
    assert detect_install(e) is None


def test_claude_json_adding_server_is_target(home):
    p = _claude_json(home, {"numStartups": 5, "mcpServers": {}})
    e = HookInput("Edit", {
        "file_path": str(p), "old_string": '"mcpServers": {}',
        "new_string": '"mcpServers": {"foo": {"command": "npx", "args": ["-y", "@a/foo"]}}',
    }, "/tmp")
    res = detect_install(e)
    t = only(res)
    assert (t.kind, t.name) == ("npm", "@a/foo") and res.pinnable


def test_claude_json_project_servers(home):
    p = _claude_json(home, {"projects": {"/p": {"mcpServers": {}}}})
    new = {"projects": {"/p": {"mcpServers": {"r": {"type": "http", "url": "https://mcp.example.com/m"}}}}}
    w = HookInput("Write", {"file_path": str(p), "content": json.dumps(new)}, "/tmp")
    assert only(detect_install(w)).kind == "remote"


def test_mcp_json_write_and_multiedit(home):
    proj = home.parent / "proj"
    w = HookInput("Write", {"file_path": str(proj / ".mcp.json"),
                            "content": json.dumps({"mcpServers": {"x": {"command": "uvx", "args": ["mcp-x"]}}})}, str(proj))
    assert only(detect_install(w)).name == "mcp-x"
    (proj / ".mcp.json").write_text('{"mcpServers": {}}')
    m = HookInput("MultiEdit", {"file_path": ".mcp.json", "edits": [
        {"old_string": "{}", "new_string": '{"y": {"command": "npx", "args": ["-y", "yy"]}}'},
        {"old_string": '"yy"', "new_string": '"zz"'},
    ]}, str(proj))
    assert only(detect_install(m)).name == "zz"


def test_mcp_json_invalid_is_protected(home):
    proj = home.parent / "proj"
    w = HookInput("Write", {"file_path": str(proj / ".mcp.json"), "content": "{nope"}, str(proj))
    assert isinstance(detect_install(w), Protected)


def test_settings_hooks_protected(home):
    s = home / ".claude" / "settings.json"
    s.write_text('{"model": "x"}')
    w = HookInput("Write", {"file_path": str(s), "content": json.dumps(
        {"model": "x", "hooks": {"PreToolUse": [{"hooks": [{"type": "command", "command": "evil"}]}]}})}, "/tmp")
    assert isinstance(detect_install(w), Protected)
    w = HookInput("Write", {"file_path": str(s), "content": '{"model": "y"}'}, "/tmp")
    assert detect_install(w) is None


def test_settings_enabled_plugins(home):
    s = home.parent / "proj" / ".claude" / "settings.local.json"
    s.parent.mkdir(parents=True)
    s.write_text('{"enabledPlugins": {"foo@mk": false}}')
    w = HookInput("Write", {"file_path": str(s), "content": '{"enabledPlugins": {"foo@mk": true}}'}, "/tmp")
    assert only(detect_install(w)).kind == "local"


def test_skill_write_overlays_containing_dir(home):
    f = home / ".claude" / "skills" / "foo" / "SKILL.md"
    w = HookInput("Write", {"file_path": str(f), "content": "# hi"}, "/tmp")
    res = detect_install(w)
    t = only(res)
    assert t.kind == "local" and Path(t.path) == f.parent
    assert res.overlays[t] == {str(f): "# hi"}


def test_command_edit_overlay(home):
    f = home / ".claude" / "commands" / "x.md"
    f.parent.mkdir(parents=True)
    f.write_text("hello world")
    e = HookInput("Edit", {"file_path": str(f), "old_string": "world", "new_string": "there"}, "/tmp")
    res = detect_install(e)
    t = only(res)
    assert Path(t.path) == f.parent and res.overlays[t] == {str(f): "hello there"}


def test_unrelated_write_is_none(home):
    assert detect_install(HookInput("Write", {"file_path": "/tmp/a.json", "content": "{}"}, "/tmp")) is None
    assert detect_install(HookInput("Read", {"file_path": str(home / ".claude.json")}, "/tmp")) is None


# ------------------------------------------------------------- pre-filter

def test_prefilter_is_superset_of_detect(home):
    hook = _load_hook()
    cases = _positive_cases(home)
    for inp in cases:
        res = detect_install(inp)
        assert res is not None, inp
        assert hook.prefilter({"tool_name": inp.tool_name, "tool_input": inp.tool_input, "cwd": inp.cwd}), inp


def test_prefilter_negative_fast_path(home):
    hook = _load_hook()
    assert not hook.prefilter({"tool_name": "Bash", "tool_input": {"command": "ls -la"}, "cwd": "/tmp"})
    assert not hook.prefilter({"tool_name": "Write", "tool_input": {"file_path": "/tmp/x.py"}, "cwd": "/tmp"})
    assert not hook.prefilter({"tool_name": "Read", "tool_input": {"file_path": "/tmp/.mcp.json"}, "cwd": "/tmp"})
