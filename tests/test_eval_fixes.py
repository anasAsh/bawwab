"""Task 15 fix round 1: the eval's two open misses (I1, I2) closed, and run_eval.py's workdir safety (C1).

I1: a prompt-injecting slash command or subagent (.claude/commands/*.md, .claude/agents/*.md) is scanned with the
text rules: the scanned copy keeps its commands/ or agents/ path segment, at the gate and in the effect check.
I2: a server whose env loads code or switches the package index is never accepted by the effect check without an
explicit approval (one shared list of keys, bawwab/envkeys.py, used by the gate and the effect check).
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
from bawwab.config import Config
from bawwab.gate import detect
from bawwab.gate.detect import HookInput, Targets, detect_install
from bawwab.gate.gate import _materialize
from bawwab.scan import scan_target
from bawwab.store import Store
from bawwab.types import Mode, Target, Verdict

ROOT = Path(__file__).resolve().parent.parent
EVIL_TEXT = (ROOT / "eval" / "fixtures" / "evil-skill" / "SKILL.md").read_text()
CLEAN_TEXT = "---\ndescription: Review the staged diff.\n---\nReview the staged diff and list risky changes.\n"


class _FakeJudge:
    def complete(self, system, user, schema, timeout_s):
        return '{"findings":[]}'


def _scan(t: Target, tmp: Path):
    return scan_target(t, store=Store(tmp / "s.db"), backend=_FakeJudge(), cfg=Config(), mode=Mode.STANDARD,
                       no_cache=True)


# ------------------------------------------------------------------ I1: commands / agents text

@pytest.mark.parametrize("rel", ["commands/review.md", "agents/reviewer.md", "commands/ns/deep.md"])
def test_effect_check_scan_keeps_kind_segment(rel, tmp_path):
    f = tmp_path / "proj" / ".claude" / rel
    f.parent.mkdir(parents=True)
    f.write_text(EVIL_TEXT)
    st, cleanup = _materialize(Target("local", str(f), name=str(f), path=str(f)), None)  # as _scan_item does
    try:
        kind_rel = os.path.relpath(next(Path(st.path).rglob(f.name)), st.path)
        assert kind_rel == rel
        assert _scan(st, tmp_path).verdict != Verdict.CLEAN
    finally:
        cleanup()


def test_clean_command_still_clean(tmp_path):
    f = tmp_path / "proj" / ".claude" / "commands" / "review.md"
    f.parent.mkdir(parents=True)
    f.write_text(CLEAN_TEXT)
    st, cleanup = _materialize(Target("local", str(f), name=str(f), path=str(f)), None)
    try:
        assert _scan(st, tmp_path).verdict == Verdict.CLEAN
    finally:
        cleanup()


def test_lone_file_outside_claude_dirs_unchanged(tmp_path):
    f = tmp_path / "notes" / "commands" / "x.md"  # not under .claude/: layout as before
    f.parent.mkdir(parents=True)
    f.write_text("x")
    st, cleanup = _materialize(Target("local", str(f), name=str(f), path=str(f)), None)
    try:
        assert sorted(os.listdir(st.path)) == ["x.md"]
    finally:
        cleanup()


@pytest.mark.parametrize("rel", ["commands/review.md", "agents/reviewer.md"])
def test_gate_write_scan_keeps_kind_segment(rel, tmp_path):
    f = tmp_path / "proj" / ".claude" / rel
    det = detect_install(HookInput("Write", {"file_path": str(f), "content": EVIL_TEXT}, str(tmp_path / "proj")))
    assert isinstance(det, Targets) and len(det.targets) == 1
    t = det.targets[0]
    st, cleanup = _materialize(t, det.overlays.get(t))
    try:
        assert any(os.path.relpath(p, st.path) == rel for p in Path(st.path).rglob("*.md"))
        assert _scan(st, tmp_path).verdict != Verdict.CLEAN
    finally:
        cleanup()


# ------------------------------------------------------------------ I2: server env loaders

def test_one_shared_list():
    assert detect.loader_key is envkeys.loader_key  # the gate uses the shared list
    for k in ("NODE_OPTIONS", "NODE_PATH", "PYTHONPATH", "PYTHONSTARTUP", "PYTHONHOME", "LD_PRELOAD",
              "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES", "BASH_ENV", "ENV", "PERL5OPT", "RUBYOPT",
              "JAVA_TOOL_OPTIONS"):
        assert envkeys.loader_key(k) == "code", k
    for k in ("UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_DEFAULT_INDEX", "UV_INDEX_PRIVATE_URL", "PIP_INDEX_URL",
              "PIP_EXTRA_INDEX_URL", "npm_config_registry", "NPM_CONFIG_REGISTRY"):
        assert envkeys.loader_key(k) == "index", k
    for k in ("NODE_ENV", "DEBUG", "API_TOKEN", "PATH", "HOME"):
        assert envkeys.loader_key(k) is None, k


def _cj(home: Path, servers: dict) -> None:
    (home / ".claude.json").write_text(json.dumps({"numStartups": 1, "mcpServers": servers}))


def test_server_with_loader_env_is_unscannable(tmp_path):
    from bawwab.agents.claude_code import _servers_items

    srv = tmp_path / "srv"
    srv.mkdir()
    (srv / "server.py").write_text("print(1)\n")
    data = {"mcpServers": {
        "plain": {"command": "python3", "args": [str(srv / "server.py")]},
        "loader": {"command": "python3", "args": [str(srv / "server.py")], "env": {"PYTHONPATH": "/x"}},
        "index": {"command": "uvx", "args": ["x"], "env": {"UV_INDEX_URL": "https://i.invalid"}},
        "harmless": {"command": "python3", "args": [str(srv / "server.py")], "env": {"DEBUG": "1"}},
    }}
    items = {it.label.split()[2]: it for it in _servers_items("user", "user", data, tmp_path / "c.json",
                                                              ("mcpServers",), "~/.claude.json", tmp_path)}
    assert items["plain"].target is not None and items["harmless"].target is not None
    assert items["loader"].target is None and items["index"].target is None


# ------------------------------------------------------------------ hook replay (the eval harness)

_spec = importlib.util.spec_from_file_location("run_eval", ROOT / "eval" / "run_eval.py")
run_eval = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_eval)
ATTACKS = {e["id"]: e for e in run_eval.load_yaml(ROOT / "eval" / "redteam" / "attacks.yaml")["attacks"]}


@pytest.fixture(scope="module")
def sandbox():
    base = "/var/tmp" if Path("/var/tmp").is_dir() else None
    work = Path(tempfile.mkdtemp(prefix="bawwab-eval-fix-", dir=base)).resolve()
    sb = run_eval.Sandbox(work, latency_copies=0)
    try:
        sb.prepare()
        yield sb
    finally:
        shutil.rmtree(work, ignore_errors=True)


@pytest.mark.parametrize("aid", ["config-command-write-skilltext", "config-user-command-write",
                                 "config-agent-write"])
def test_injected_command_write_is_blocked(sandbox, aid):
    r = run_eval.run_entry(sandbox, ATTACKS[aid])
    assert r["outcome"] == "blocked", json.dumps(r, indent=1)[:2000]


@pytest.mark.parametrize("aid", ["combo-ifs-node-options", "combo-python-pythonpath"])
def test_server_env_loader_is_caught_after(sandbox, aid):
    r = run_eval.run_entry(sandbox, ATTACKS[aid])
    assert r["outcome"] == "caught", json.dumps(r, indent=1)[:2000]


def test_loader_env_added_later_to_accepted_server_is_quarantined(sandbox):
    """Review case F: a clean server accepted at init, then only its env changes."""
    clean = str(sandbox.vendor / "postmark_rugpull-v1" / "server.py")
    entry = {"id": "env-added-later", "family": "t",
             "setup": {"effect": [{"op": "json_set", "path": "~/.claude.json", "key": ["mcpServers", "mail"],
                                   "value": {"command": "python3", "args": [clean]}}]},
             "calls": [{"tool_name": "Bash", "tool_input": {"command": "true"}}],
             "effect": [{"op": "json_set", "path": "~/.claude.json", "key": ["mcpServers", "mail"],
                         "value": {"command": "python3", "args": [clean], "env": {"LD_PRELOAD": "/var/tmp/x.so"}}}]}
    r = run_eval.run_entry(sandbox, entry)
    assert r["setup_baseline"]["decision"] == "none", r  # the clean server itself was accepted
    assert r["outcome"] == "caught", json.dumps(r, indent=1)[:2000]


# ------------------------------------------------------------------ C1: run_eval never deletes what it didn't create

def _run_eval(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(ROOT / "eval" / "run_eval.py"), *args], capture_output=True, text=True,
                          timeout=600, cwd=str(ROOT))


def test_workdir_non_empty_is_refused_and_kept(tmp_path):
    wd = Path(tempfile.mkdtemp(prefix="bawwab-eval-wd-", dir="/var/tmp" if Path("/var/tmp").is_dir() else None))
    try:
        (wd / "IMPORTANT.txt").write_text("keep me")
        r = _run_eval("--only", "baseline", "--no-write", "--workdir", str(wd))
        assert r.returncode != 0 and "not empty" in r.stderr
        assert (wd / "IMPORTANT.txt").read_text() == "keep me"
    finally:
        shutil.rmtree(wd, ignore_errors=True)


def test_workdir_empty_is_used_and_kept(tmp_path):
    wd = Path(tempfile.mkdtemp(prefix="bawwab-eval-wd-", dir="/var/tmp" if Path("/var/tmp").is_dir() else None))
    try:
        r = _run_eval("--only", "baseline", "--no-write", "--workdir", str(wd))
        assert r.returncode == 0, r.stderr[-2000:]
        assert wd.is_dir() and os.listdir(wd) == []  # only the run's own temp dir inside it was removed
    finally:
        shutil.rmtree(wd, ignore_errors=True)


@pytest.mark.parametrize("which", ["home", "repo", "root"])
def test_workdir_ancestor_of_home_or_repo_is_refused(which):
    target = {"home": run_eval.REAL_HOME, "repo": ROOT, "root": Path("/")}[which]
    with pytest.raises(run_eval.Unsafe):
        run_eval.resolve_workdir(str(target))
