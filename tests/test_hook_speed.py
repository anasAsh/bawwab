from __future__ import annotations

import json
import os
import statistics
import subprocess
import sys
import time
from pathlib import Path

import pytest

HOOK = Path(__file__).resolve().parent.parent / "hooks" / "bawwab_hook.py"
LS = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": "/tmp"})
INSTALL = json.dumps({"tool_name": "Bash", "tool_input": {"command": "claude mcp add gh -- npx -y @a/b"}, "cwd": "/tmp"})


def run(stdin: str, *args: str, env: dict | None = None):
    e = {k: v for k, v in os.environ.items() if k != "BAWWAB_CHILD"}
    e.update(env or {})
    return subprocess.run(["python3", str(HOOK), *args], input=stdin, capture_output=True, text=True, env=e, timeout=60)


def test_non_install_fast_and_silent():
    times = []
    for _ in range(5):
        t0 = time.perf_counter()
        r = run(LS, "gate")
        times.append(time.perf_counter() - t0)
        assert r.returncode == 0 and r.stdout == ""
    assert statistics.median(times) < 0.100, times


def test_child_env_short_circuits():
    r = run(INSTALL, "gate", env={"BAWWAB_CHILD": "1"})
    assert r.returncode == 0 and r.stdout == ""


def test_unknown_subcommand_silent():
    for args in (("bogus",), ()):
        r = run(INSTALL, *args)
        assert r.returncode == 0 and r.stdout == ""


def _fake_bawwab(tmp_path: Path, body: str) -> dict:
    b = tmp_path / "bin"
    b.mkdir()
    exe = b / "bawwab"
    exe.write_text(f"#!{sys.executable}\n{body}\n")
    exe.chmod(0o755)
    return {"PATH": f"{b}:{os.environ.get('PATH', '')}"}


def test_dispatches_to_bawwab_gate(tmp_path):
    env = _fake_bawwab(tmp_path, (
        "import sys, json\n"
        "assert sys.argv[1:] == ['gate'], sys.argv\n"
        "d = json.load(sys.stdin)\n"
        "print(json.dumps({'hookSpecificOutput': {'hookEventName': 'PreToolUse', 'permissionDecision': 'allow',"
        " 'permissionDecisionReason': d['tool_input']['command']}}))"
    ))
    r = run(INSTALL, "gate", env=env)
    assert r.returncode == 0
    out = json.loads(r.stdout)
    assert out["hookSpecificOutput"]["permissionDecisionReason"] == "claude mcp add gh -- npx -y @a/b"


@pytest.mark.parametrize("body", ["import sys; sys.exit(3)", "print('garbage')"])
def test_child_failure_denies_install(tmp_path, body):
    r = run(INSTALL, "gate", env=_fake_bawwab(tmp_path, body))
    assert r.returncode == 0
    out = json.loads(r.stdout)["hookSpecificOutput"]
    assert out["permissionDecision"] == "deny" and out["permissionDecisionReason"].startswith("bawwab error: gate unavailable")
