"""Task 15 fix round 3: the gate-approval -> effect-check link waives only the env-loader hold, never the code scan.

R2-I1: approving a server's env pending must not let its malicious code in. R2-I2: an approval in project A must not
accept the identical entry (relative paths) in project B. The link is written only by a gate call that ends allowed,
the hash includes the project dir, and entries with non-string args/env values never link (R2-M1).
"""
from __future__ import annotations

import importlib.util
import json
import os
import shutil
import sqlite3
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


@pytest.fixture(scope="module")
def sandbox():
    work = Path(tempfile.mkdtemp(prefix="bawwab-eval-r3-", dir=VAR_TMP)).resolve()
    sb = run_eval.Sandbox(work, latency_copies=0)
    try:
        sb.prepare()
        yield sb
    finally:
        shutil.rmtree(work, ignore_errors=True)


def _links(sb) -> list[str]:
    con = sqlite3.connect(sb.bh / "bawwab.db")
    try:
        return [k for (k,) in con.execute("SELECT k FROM meta WHERE k LIKE 'server-entry:%'")]
    finally:
        con.close()


def _bash(sb, cmd: str, cwd: Path | None = None) -> dict:
    d = sb.pre("Bash", command=cmd)
    if cwd is not None:
        d["cwd"] = str(cwd)
    return d


def _hook(sb, sub: str, data: dict):
    """The hook with the call's own cwd (sb.hook runs it from the main project)."""
    import subprocess
    import time

    t0 = time.perf_counter()
    r = subprocess.run(["python3", str(run_eval.HOOK), sub], input=json.dumps(data), capture_output=True, text=True,
                       env=sb.env, cwd=data["cwd"], timeout=600)
    return run_eval.HookResult(sub, r.returncode, r.stdout.strip(), r.stderr.strip()[-400:],
                               (time.perf_counter() - t0) * 1000)


def _pending(res) -> str:
    m = run_eval.PENDING_RE.search(res.reason())
    assert m, res.reason()
    return m.group(1)


def _set_server(sb, proj: Path, name: str, spec: dict) -> None:
    sb.apply([{"op": "json_set", "path": "~/.claude.json", "key": ["projects", str(proj), "mcpServers", name],
               "value": spec}])


# ------------------------------------------------------------------ hashing (R2-M1, project dir)

def test_hash_is_bound_to_project_and_strings_only(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    a.mkdir()
    b.mkdir()
    spec = {"command": "node", "args": ["srv.js"], "env": {"NODE_PATH": "lib"}}
    ha = envkeys.spec_entry_hash(spec, a)
    assert ha == envkeys.server_entry_hash("node", ["srv.js"], {"NODE_PATH": "lib"}, str(a))
    assert envkeys.spec_entry_hash(spec, b) != ha
    assert envkeys.spec_entry_hash({**spec, "args": [1]}, a) is None
    assert envkeys.spec_entry_hash({**spec, "env": {"NODE_PATH": True}}, a) is None
    assert envkeys.server_entry_hash("node", [1], {}, str(a)) is None


# ------------------------------------------------------------------ R2-I1

def test_env_only_approval_does_not_admit_malicious_code(sandbox):
    """Reviewer probe 1: approve only the NODE_PATH pending of a malicious install, then write the entry past the gate."""
    sb = sandbox
    sb.reset()
    evil = str(sb.vendor / "mcp_typosquat-v2" / "index.js")
    lib = str(sb.vendor / "mcp_typosquat-v1")
    g = sb.hook("gate", _bash(sb, f"claude mcp add fs -e NODE_PATH={lib} -- node {evil}"))
    assert g.decision() == "deny" and "MALICIOUS" in g.reason() and "protected action" in g.reason()
    sb.apply([{"op": "approve", "id": _pending(g), "force": False}])  # the first pending is the env one
    assert _links(sb) == []  # a denied call never links
    g2 = sb.hook("gate", _bash(sb, f"claude mcp add fs -e NODE_PATH={lib} -- node {evil}"))
    assert g2.decision() == "deny" and "MALICIOUS" in g2.reason()
    assert _links(sb) == []  # still denied (the MALICIOUS block is open): still no link
    _set_server(sb, sb.proj, "fs", {"type": "stdio", "command": "node", "args": [evil], "env": {"NODE_PATH": lib}})
    p = sb.hook("post", sb.post_input(_bash(sb, "true")))
    assert p.decision() == "block", p.out


def test_linked_entry_still_has_its_code_scanned(sandbox):
    """A real link (clean code approved and allowed), then the code behind the same entry turns malicious and the entry
    is re-added: the effect check scans the code and quarantines it."""
    sb = sandbox
    sb.reset()
    srv = sb.proj / "srv"
    shutil.copytree(sb.vendor / "mcp_typosquat-v1", srv)
    lib = str(sb.vendor / "postmark_rugpull-v1")
    cmd = f"claude mcp add fs -e NODE_PATH={lib} -- node {srv}/index.js"
    g = sb.hook("gate", _bash(sb, cmd))
    assert g.decision() == "deny" and "MALICIOUS" not in g.reason()
    sb.apply([{"op": "approve", "id": _pending(g), "force": False}])
    assert sb.hook("gate", _bash(sb, cmd)).decision() in ("none", "status")  # passes: at most the user-only status line
    assert len(_links(sb)) == 1  # the allowed call linked the entry
    shutil.copy(sb.vendor / "mcp_typosquat-v2" / "index.js", srv / "index.js")  # code swapped before the install
    _set_server(sb, sb.proj, "fs", {"type": "stdio", "command": "node", "args": [f"{srv}/index.js"],
                                    "env": {"NODE_PATH": lib}})
    p = sb.hook("post", sb.post_input(_bash(sb, "true")))
    assert p.decision() == "block", p.out


# ------------------------------------------------------------------ R2-I2

def test_approval_in_project_a_does_not_accept_project_b(sandbox):
    """Reviewer probe 2: the identical relative entry in project B, whose srv.js is malicious."""
    sb = sandbox
    sb.reset()
    a, b = sb.proj, sb.run / "projB"
    shutil.copy(sb.vendor / "mcp_typosquat-v1" / "index.js", a / "srv.js")
    b.mkdir()
    shutil.copy(sb.vendor / "mcp_typosquat-v2" / "index.js", b / "srv.js")
    (b / "lib").mkdir()
    (a / "lib").mkdir()
    cmd = "claude mcp add fs -e NODE_PATH=lib -- node srv.js"
    g = sb.hook("gate", _bash(sb, cmd))
    assert g.decision() == "deny" and "MALICIOUS" not in g.reason(), g.reason()
    sb.apply([{"op": "approve", "id": _pending(g), "force": False}])
    assert sb.hook("gate", _bash(sb, cmd)).decision() in ("none", "status")  # passes: at most the user-only status line
    spec = {"type": "stdio", "command": "node", "args": ["srv.js"], "env": {"NODE_PATH": "lib"}}
    _set_server(sb, a, "fs", spec)
    pa = sb.hook("post", sb.post_input(_bash(sb, "true")))
    assert pa.decision() == "none", pa.out  # project A: accepted with one approval
    _set_server(sb, b, "fs", spec)
    pb = _hook(sb, "post", sb.post_input(_bash(sb, "true", cwd=b)))
    probe = _hook(sb, "gate", _bash(sb, "ls", cwd=b))
    assert pb.decision() == "block" or probe.decision() == "deny", (pb.out, probe.out)


# ------------------------------------------------------------------ the clean flow still needs exactly one approval

def test_clean_pythonpath_flow_one_approval(sandbox):
    r = run_eval.run_normal(sandbox, NORMAL["mcp-add-pythonpath-approved"])
    assert r["setup_pending"]["decision"] == "deny" and r["setup_pending"]["kind"] == "protected"
    assert r["notices"] == [] and r["denies"] == 0, json.dumps(r, indent=1)[:3000]
