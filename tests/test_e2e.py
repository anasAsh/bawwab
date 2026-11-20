"""End to end: the plugin's hook script, the real bawwab CLI child, and the packaging files (Task 13)."""
from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
HOOK = ROOT / "hooks" / "bawwab_hook.py"
FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def proj(tmp_path):
    """A project dir holding copies of the fixtures at the paths the commands name."""
    p = tmp_path / "proj"
    for name in ("postinstall_curl", "clean_server"):
        shutil.copytree(FIX / "code" / name, p / "tests/fixtures/code" / name)
    return p


def _gate(proj: Path, tmp_path: Path, command: str) -> str:
    fake = tmp_path / "judge.json"
    fake.write_text('{"findings":[]}')
    env = {k: v for k, v in os.environ.items() if k not in ("BAWWAB_CHILD", "CLAUDE_PLUGIN_ROOT")}
    env["BAWWAB_FAKE_JUDGE"] = str(fake)
    data = {"session_id": "e2e", "hook_event_name": "PreToolUse", "tool_name": "Bash",
            "tool_input": {"command": command}, "cwd": str(proj)}
    r = subprocess.run(["python3", str(HOOK), "gate"], input=json.dumps(data), capture_output=True, text=True,
                       env=env, cwd=proj, timeout=300)
    assert r.returncode == 0, r.stderr
    return r.stdout.strip()


def _decision(out: str) -> str | None:
    return json.loads(out).get("hookSpecificOutput", {}).get("permissionDecision") if out else None


def test_e2e_malicious_install_denied(proj, tmp_path):
    out = _gate(proj, tmp_path, "claude mcp add x -- node tests/fixtures/code/postinstall_curl/index.js")
    assert _decision(out) == "deny"
    assert "MALICIOUS" in json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"]


def test_e2e_clean_install_not_denied(proj, tmp_path):
    # bawwab never emits "allow": a clean install gets no decision, so Claude Code's own permissions apply
    out = _gate(proj, tmp_path, "claude mcp add x -- node tests/fixtures/code/clean_server/index.js")
    assert _decision(out) not in ("deny", "allow", "ask")


def test_e2e_ordinary_call_silent(proj, tmp_path):
    assert _gate(proj, tmp_path, "ls") == ""


# ------------------------------------------------------------------ packaging

def test_plugin_manifest():
    m = json.loads((ROOT / ".claude-plugin/plugin.json").read_text())
    assert m["name"] == "bawwab" and m["version"] == "0.1.0"
    assert m["mcpServers"]["bawwab"] == {
        "command": "uv", "args": ["run", "--project", "${CLAUDE_PLUGIN_ROOT}", "--quiet", "bawwab-mcp"]}


def test_marketplace_manifest():
    m = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text())
    assert m["name"] == "bawwab" and m["owner"]["name"]
    assert [(p["name"], p["source"]) for p in m["plugins"]] == [("bawwab", "./")]


def test_hooks_manifest():
    h = json.loads((ROOT / "hooks/hooks.json").read_text())["hooks"]
    cmd = 'python3 "${CLAUDE_PLUGIN_ROOT}/hooks/bawwab_hook.py" '

    def only(event):
        assert len(h[event]) == 1 and len(h[event][0]["hooks"]) == 1
        return h[event][0], h[event][0]["hooks"][0]

    for event, sub in (("PreToolUse", "gate"), ("PostToolUse", "post")):
        group, hook = only(event)
        assert group["matcher"] == "*"
        assert hook == {"type": "command", "command": cmd + sub, "timeout": hook["timeout"]}
        assert hook["timeout"] >= 600
    for event, sub in (("SessionStart", "inventory"), ("UserPromptSubmit", "notify")):
        group, hook = only(event)
        assert "matcher" not in group and hook == {"type": "command", "command": cmd + sub}
    assert set(h) == {"PreToolUse", "PostToolUse", "SessionStart", "UserPromptSubmit"}


def test_skill_rules():
    text = (ROOT / "skills/bawwab/SKILL.md").read_text()
    assert text.startswith("---\nname: bawwab\ndescription: ")
    for needle in ("verbatim", "bawwab approve", "--deep", "bawwab explain", "scan_mcp_server"):
        assert needle in text
