"""Task 15 fix round 2.

R1-I1: a server the user approved at the gate (its env holds a loader key) is accepted once by the effect check: the
approval is linked to a hash of the entry (command, args, env), and any later change to the entry is quarantined.
R1-M1: more loader / index keys in bawwab/envkeys.py.
R1-M3: --workdir through a symlink.
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import pytest

from bawwab import envkeys

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("run_eval", ROOT / "eval" / "run_eval.py")
run_eval = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_eval)
NORMAL = {e["id"]: e for e in run_eval.load_yaml(ROOT / "eval" / "redteam" / "normal.yaml")["tasks"]}
VAR_TMP = "/var/tmp" if Path("/var/tmp").is_dir() else None


# ------------------------------------------------------------------ R1-M1

@pytest.mark.parametrize("key,kind", [
    ("LD_AUDIT", "code"), ("GCONV_PATH", "code"), ("_JAVA_OPTIONS", "code"), ("JDK_JAVA_OPTIONS", "code"),
    ("CLASSPATH", "code"), ("PERLLIB", "code"), ("PYTHONUSERBASE", "code"),
    ("YARN_REGISTRY", "index"), ("BUN_CONFIG_REGISTRY", "index"), ("PIP_TRUSTED_HOST", "index"),
    ("yarn_registry", "index"),
])
def test_more_loader_keys(key, kind):
    assert envkeys.loader_key(key) == kind


def test_path_is_not_a_loader_key():  # documented residual (README "Honest limitations")
    assert envkeys.loader_key("PATH") is None
    assert "PATH" in (ROOT / "README.md").read_text().split("## Honest limitations", 1)[1].split("\n## ", 1)[0]


# ------------------------------------------------------------------ R1-I1: entry hash

def test_entry_hash_matches_gate_and_config_forms():
    h = envkeys.server_entry_hash("python3", ["/s/server.py"], {"PYTHONPATH": "/lib"})
    spec = {"type": "stdio", "command": "python3", "args": ["/s/server.py"], "env": {"PYTHONPATH": "/lib"}}
    assert envkeys.spec_entry_hash(spec) == h
    assert envkeys.spec_entry_hash({**spec, "env": {"PYTHONPATH": "/lib2"}}) != h
    assert envkeys.spec_entry_hash({**spec, "args": ["/s/other.py"]}) != h
    assert envkeys.spec_entry_hash({**spec, "cwd": "/elsewhere"}) is None  # fields the gate never saw: no link
    assert envkeys.spec_entry_hash({**spec, "type": "http"}) is None


@pytest.fixture(scope="module")
def sandbox():
    work = Path(tempfile.mkdtemp(prefix="bawwab-eval-r2-", dir=VAR_TMP)).resolve()
    sb = run_eval.Sandbox(work, latency_copies=0)
    try:
        sb.prepare()
        yield sb
    finally:
        shutil.rmtree(work, ignore_errors=True)


def test_gate_approved_loader_server_needs_one_approval(sandbox):
    """normal.yaml's flow: the gate asks once; after the approval the install, the effect check and later calls pass."""
    r = run_eval.run_normal(sandbox, NORMAL["mcp-add-pythonpath-approved"])
    assert r["setup_pending"]["decision"] == "deny" and r["setup_pending"]["kind"] == "protected"
    assert r["notices"] == [] and r["denies"] == 0, json.dumps(r, indent=1)[:3000]


@pytest.mark.parametrize("change", [
    {"env": {"PYTHONPATH": "{V}/invariant_tool_poisoning-v2"}},  # env changed after the approval
    {"args": ["{V}/postmark_rugpull-v2/server.py"]},              # args changed
    {"cwd": "/var/tmp"},                                          # a field the gate never saw
])
def test_changed_entry_after_approval_is_quarantined(sandbox, change):
    task = json.loads(json.dumps(NORMAL["mcp-add-pythonpath-approved"]))
    value = dict(task["effect"][0]["value"])
    value.update(change)
    task["effect"] = [dict(task["effect"][0], value=value)]
    r = run_eval.run_normal(sandbox, task)
    assert r["post"]["decision"] == "block" and r["post"]["kind"] == "quarantine", json.dumps(r, indent=1)[:3000]


def test_unapproved_loader_server_still_quarantined(sandbox):
    task = json.loads(json.dumps(NORMAL["mcp-add-pythonpath-approved"]))
    task["setup"].pop("approve")
    r = run_eval.run_normal(sandbox, task)
    assert r["post"]["decision"] == "block", json.dumps(r, indent=1)[:3000]


# ------------------------------------------------------------------ R1-M3: --workdir through a symlink

def _run_eval(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(ROOT / "eval" / "run_eval.py"), *args], capture_output=True, text=True,
                          timeout=600, cwd=str(ROOT))


def test_symlinked_workdir_non_empty_is_refused_and_kept():
    base = Path(tempfile.mkdtemp(prefix="bawwab-eval-ln-", dir=VAR_TMP))
    try:
        real = base / "real"
        real.mkdir()
        (real / "IMPORTANT.txt").write_text("keep me")
        link = base / "link"
        link.symlink_to(real)
        r = _run_eval("--only", "baseline", "--no-write", "--workdir", str(link))
        assert r.returncode == 2 and "not empty" in r.stderr
        assert (real / "IMPORTANT.txt").read_text() == "keep me" and link.is_symlink()
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_symlinked_workdir_empty_is_used_and_kept():
    base = Path(tempfile.mkdtemp(prefix="bawwab-eval-ln-", dir=VAR_TMP))
    try:
        real = base / "real"
        real.mkdir()
        link = base / "link"
        link.symlink_to(real)
        r = _run_eval("--only", "baseline", "--no-write", "--workdir", str(link))
        assert r.returncode == 0, r.stderr[-2000:]
        assert link.is_symlink() and real.is_dir() and os.listdir(real) == []
    finally:
        shutil.rmtree(base, ignore_errors=True)


def test_symlink_to_repo_is_refused(tmp_path):
    link = tmp_path / "repo-link"
    link.symlink_to(ROOT)
    with pytest.raises(run_eval.Unsafe):
        run_eval.resolve_workdir(str(link))
