"""`bawwab allow-env <repo>`: the user lets commands in that repo set BAWWAB_HOME to a dir inside it (tests of
Bawwab's own tree). Claude can't run it; it never covers a nested claude; and Bawwab's hooks never enforce from
such a home (bawwab/allowenv.py, gate/detect.py _allowed_test_home, hooks/bawwab_hook.py _test_home)."""
from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from bawwab import allowenv
from bawwab.cli import main
from bawwab.gate.detect import HookInput, detect_install
from bawwab.gate.gate import run_gate

ROOT = Path(__file__).resolve().parent.parent
OVERRIDE = "bawwab environment override"


@pytest.fixture
def repo(tmp_path):
    r = tmp_path / "bawwab-dev"
    (r / "scripts").mkdir(parents=True)
    return r


def _reason(cmd: str, cwd: Path) -> str:
    d = detect_install(HookInput("Bash", {"command": cmd}, str(cwd)))
    return "" if d is None else d.reason if hasattr(d, "reason") else "; ".join(d.protected)


ALLOWED = [
    "BAWWAB_HOME=./.bw python3 scripts/report.py --out report/",
    "BAWWAB_HOME=.tmp/bw uv run pytest tests/test_report.py -q",
    "export BAWWAB_HOME=./.bw && uv run pytest -q",
    "env BAWWAB_HOME=.bw pytest -q",
]


@pytest.mark.parametrize("cmd", ALLOWED)
def test_refused_until_the_user_allows_the_repo(cmd, repo):
    assert OVERRIDE in _reason(cmd, repo)
    assert main(["allow-env", str(repo)]) == 0
    assert OVERRIDE not in _reason(cmd, repo), cmd
    assert run_gate(HookInput("Bash", {"command": cmd}, str(repo))) is None


@pytest.mark.parametrize("cmd", [
    "BAWWAB_HOME=./.bw claude -p 'install x'",                     # a nested claude: never covered
    "BAWWAB_HOME=./.bw npx -y @anthropic-ai/claude-code -p x",
    "BAWWAB_HOME=./.bw sh -c 'claude mcp list'",
    "BAWWAB_HOME=./.bw python3 -c \"import subprocess; subprocess.run(['claude'])\"",
    "BAWWAB_HOME=/tmp/bw-test pytest -q",                          # outside the repo
    "BAWWAB_HOME=../elsewhere pytest -q",
    "BAWWAB_HOME=. pytest -q",                                      # the repo itself
    "BAWWAB_HOME=$(mktemp -d) pytest -q",                           # not a literal path
    "BAWWAB_HOME=$HOME/.bawwab pytest -q",
    "BAWWAB_HOME=~/.bawwab pytest -q",
    "BAWWAB_HOME=./link/bw pytest -q",                             # a symlink out of the repo
    "HOME=./h BAWWAB_HOME=./.bw python3 x.py",                     # another HOME (another ~/.bawwab)
    "CLAUDE_CONFIG_DIR=./c BAWWAB_HOME=./.bw python3 x.py",
    "cd /tmp && BAWWAB_HOME=./.bw pytest -q",                      # a relative path after cd
    "unset BAWWAB_HOME; pytest -q",                                 # not a dir inside the repo
    "read BAWWAB_HOME < f; pytest -q",
    "BAWWAB_HOME=./.bw BAWWAB_CHILD=1 pytest -q",
    "BAWWAB_HOME+=./.bw pytest -q",
    "BAWWAB_HOME=./.bw pytest -q <<'EOF'\nx\nEOF",
])
def test_near_misses_stay_refused_after_allow(cmd, repo, tmp_path):
    (repo / "link").symlink_to(tmp_path)
    assert main(["allow-env", str(repo)]) == 0
    assert OVERRIDE in _reason(cmd, repo), cmd


def test_cwd_outside_the_repo_stays_refused(repo, tmp_path):
    assert main(["allow-env", str(repo)]) == 0
    assert OVERRIDE in _reason(f"BAWWAB_HOME={repo}/.bw pytest -q", tmp_path)


def test_other_protected_actions_are_not_covered(repo):
    assert main(["allow-env", str(repo)]) == 0
    r = _reason("BAWWAB_HOME=./.bw bawwab approve ABCD", repo)
    assert "bawwab approval via tool call" in r


@pytest.mark.parametrize("cmd", ["bawwab allow-env .", "bawwab allow-env --remove .",
                                 f"{ROOT}/bin/bawwab allow-env /tmp/x", "python3 -m bawwab allow-env ."])
def test_claude_cant_allow_a_repo(cmd, repo):
    out = run_gate(HookInput("Bash", {"command": cmd}, str(repo)))
    assert out and out["hookSpecificOutput"]["permissionDecision"] == "deny", cmd


def test_claude_may_list(repo):
    assert run_gate(HookInput("Bash", {"command": "bawwab allow-env --list"}, str(repo))) is None


def test_claude_cant_write_the_list(repo):
    ti = {"file_path": allowenv.list_path(), "content": json.dumps({"repos": [str(repo)]})}
    out = run_gate(HookInput("Write", ti, str(repo)))
    assert out and out["hookSpecificOutput"]["permissionDecision"] == "deny"
    out = run_gate(HookInput("Bash", {"command": f"echo '{{}}' > {allowenv.list_path()}"}, str(repo)))
    assert out and out["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_allow_env_refuses_home_and_config_dirs(tmp_path):
    home = Path.home()
    (home / ".claude").mkdir(parents=True, exist_ok=True)
    for d in (home, home / ".claude", home.parent, Path("/")):
        assert main(["allow-env", str(d)]) == 1, d
    assert main(["allow-env", str(tmp_path / "missing")]) == 1
    assert allowenv.repos() == []


def test_list_and_remove(repo, capsys):
    assert main(["allow-env", str(repo)]) == 0
    assert main(["allow-env", "--list"]) == 0
    assert str(repo.resolve()) in capsys.readouterr().out
    assert main(["allow-env", "--remove", str(repo)]) == 0
    assert allowenv.repos() == []
    assert OVERRIDE in _reason(ALLOWED[0], repo)


def _hook(sub: str, payload: dict, env: dict) -> dict | None:
    r = subprocess.run([sys.executable, str(ROOT / "hooks" / "bawwab_hook.py"), sub], input=json.dumps(payload),
                       capture_output=True, text=True, env=env, timeout=60)
    return json.loads(r.stdout) if r.stdout.strip() else None


def test_hooks_never_enforce_from_a_test_home(repo):
    """A Claude Code started with BAWWAB_HOME inside an allowed repo (by a test, or a script Claude wrote) gets
    read-only tools only: a test home can't stand in for the user's real state."""
    assert main(["allow-env", str(repo)]) == 0
    env = {**os.environ, "BAWWAB_HOME": str(repo / ".bw")}
    out = _hook("gate", {"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": str(repo)}, env)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "allow-env" in out["hookSpecificOutput"]["permissionDecisionReason"]
    assert _hook("gate", {"tool_name": "Read", "tool_input": {"file_path": "x"}, "cwd": str(repo)}, env) is None
    out = _hook("post", {"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": str(repo)}, env)
    assert out["decision"] == "block"
    # another BAWWAB_HOME (outside the repo) is not affected
    env["BAWWAB_HOME"] = str(repo.parent / "bw-other")
    assert _hook("gate", {"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": str(repo)}, env) is None
