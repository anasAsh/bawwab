"""Task 15: a small subset of the effectiveness evaluation (eval/run_eval.py), so CI catches regressions.

Replays a few red-team entries and ordinary developer calls through the real hooks inside a scratch HOME, exactly
as the full run does (no live Claude, nothing executed: the harness writes each command's effect itself).
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import tempfile
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("run_eval", ROOT / "eval" / "run_eval.py")
run_eval = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_eval)

ATTACKS = {e["id"]: e for e in run_eval.load_yaml(ROOT / "eval" / "redteam" / "attacks.yaml")["attacks"]}
NORMAL = {e["id"]: e for e in run_eval.load_yaml(ROOT / "eval" / "redteam" / "normal.yaml")["tasks"]}


@pytest.fixture(scope="module")
def sandbox():
    base = "/var/tmp" if Path("/var/tmp").is_dir() else None  # /tmp may be a small tmpfs
    work = Path(tempfile.mkdtemp(prefix="bawwab-eval-test-", dir=base)).resolve()
    sb = run_eval.Sandbox(work, latency_copies=0)
    try:
        sb.prepare()
        yield sb
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_data_files_load_and_ids_unique():
    entries = run_eval.load_yaml(ROOT / "eval" / "redteam" / "attacks.yaml")["attacks"]
    assert len(ATTACKS) == len(entries) >= 100
    assert len(NORMAL) >= 30
    for e in ATTACKS.values():
        assert e["expect"]["outcome"] in ("blocked", "caught", "missed")
        assert e["expect"]["outcome"] != "missed" or e["expect"].get("residual"), e["id"]  # a miss is documented
    json.dumps(ATTACKS)  # plain data only


def test_refuses_the_real_home(tmp_path):
    env = {"HOME": str(run_eval.REAL_HOME)}
    with pytest.raises(run_eval.Unsafe):
        run_eval.check_safe(env, tmp_path)


@pytest.mark.parametrize("aid,outcome", [
    ("plain-local-malicious", "blocked"),
    ("heredoc-bash", "blocked"),
    ("config-write-mcp-json", "blocked"),
    ("ifs-comma", "caught"),             # parked gate bypass: the effect check quarantines it
    ("approve-sh-script", "blocked"),    # R56: an approval inside a script is refused
    ("residual-npm-script", "missed"),   # documented residual (npm scripts)
])
def test_attack_subset(sandbox, aid, outcome):
    r = run_eval.run_entry(sandbox, ATTACKS[aid])
    assert "error" not in r, r
    assert r["outcome"] == outcome, json.dumps(r, indent=1)[:3000]
    assert r["outcome"] == ATTACKS[aid]["expect"]["outcome"]


@pytest.mark.parametrize("tid", ["git-commit-heredoc", "edit-permissions", "skill-script-sh"])
def test_normal_subset_is_silent(sandbox, tid):
    r = run_eval.run_normal(sandbox, NORMAL[tid])
    assert r["notices"] == [] and r["denies"] == 0, json.dumps(r, indent=1)[:3000]


def test_claude_never_ran(sandbox):
    assert not sandbox.guard_log.exists()
