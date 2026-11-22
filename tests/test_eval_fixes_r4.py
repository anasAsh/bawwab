"""Task 15 fix round 4 (R3-I1): an env-loader approval is per project.

The gate's protected-action key for a server-env reason now includes the server's entry hash, which binds the project
dir. The same command in project B is a new pending approval, and B never gets a link from A's approval. Other
protected actions keep their keys (R55/R56 approval flows unchanged).
"""
from __future__ import annotations

import importlib.util
import json
import shutil
import sqlite3
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from bawwab import envkeys
from bawwab.gate.detect import HookInput
from bawwab.gate.gate import protected_key

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("run_eval", ROOT / "eval" / "run_eval.py")
run_eval = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_eval)
VAR_TMP = "/var/tmp" if Path("/var/tmp").is_dir() else None


@pytest.fixture(scope="module")
def sandbox():
    work = Path(tempfile.mkdtemp(prefix="bawwab-eval-r4-", dir=VAR_TMP)).resolve()
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


def _gate(sb, cmd: str, cwd: Path):
    d = sb.pre("Bash", command=cmd)
    d["cwd"] = str(cwd)
    t0 = time.perf_counter()
    r = subprocess.run(["python3", str(run_eval.HOOK), "gate"], input=json.dumps(d), capture_output=True, text=True,
                       env=sb.env, cwd=str(cwd), timeout=600)
    return run_eval.HookResult("gate", r.returncode, r.stdout.strip(), r.stderr.strip()[-400:],
                               (time.perf_counter() - t0) * 1000)


def test_env_loader_approval_in_a_does_not_carry_to_b(sandbox):
    """Reviewer probe P3b: approve in A, then the same command in B (its NODE_PATH payload ../pl is malicious)."""
    sb = sandbox
    sb.reset()
    a = sb.run / "a" / "projA"
    b = sb.run / "b" / "projB"
    for proj, payload in ((a, "mcp_typosquat-v1"), (b, "mcp_typosquat-v2")):
        proj.mkdir(parents=True)
        shutil.copy(sb.vendor / "mcp_typosquat-v1" / "index.js", proj / "srv.js")  # both servers clean
        shutil.copytree(sb.vendor / payload, proj.parent / "pl")  # B's env-loaded payload is malicious
    cmd = "claude mcp add fs -e NODE_PATH=../pl -- node srv.js"
    ga = _gate(sb, cmd, a)
    assert ga.decision() == "deny" and "protected action" in ga.reason(), ga.reason()
    m = run_eval.PENDING_RE.search(ga.reason())
    sb.apply([{"op": "approve", "id": m.group(1), "force": False}])
    assert _gate(sb, cmd, a).decision() in ("none", "status")  # passes: at most the user-only status line
    hash_a = envkeys.server_entry_hash("node", ["srv.js"], {"NODE_PATH": "../pl"}, str(a))
    hash_b = envkeys.server_entry_hash("node", ["srv.js"], {"NODE_PATH": "../pl"}, str(b))
    assert _links(sb) == [envkeys.entry_meta_key(hash_a)]
    gb = _gate(sb, cmd, b)
    assert gb.decision() == "deny" and "protected action" in gb.reason(), gb.reason()  # its own pending in B
    mb = run_eval.PENDING_RE.search(gb.reason())
    assert mb and mb.group(1) != m.group(1)
    assert envkeys.entry_meta_key(hash_b) not in _links(sb)


def test_non_env_protected_keys_unchanged(tmp_path):
    """Keys of other protected actions are not bound to the cwd (R55/R56 flows keep working as before)."""
    inp_a = HookInput("Bash", {"command": "bawwab approve X"}, str(tmp_path / "a"))
    inp_b = HookInput("Bash", {"command": "bawwab approve X"}, str(tmp_path / "b"))
    assert protected_key(inp_a, "r") == protected_key(inp_b, "r")
    assert protected_key(inp_a, "r", ()) == protected_key(inp_a, "r")
    assert protected_key(inp_a, "r", ("h1",)) != protected_key(inp_a, "r")
    assert protected_key(inp_a, "r", ("h1",)) != protected_key(inp_a, "r", ("h2",))
