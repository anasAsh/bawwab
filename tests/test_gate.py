from __future__ import annotations

import io
import json
import re
from datetime import UTC, datetime

import pytest

from bawwab.gate import gate as gate_mod
from bawwab.gate.detect import HookInput
from bawwab.gate.gate import run_gate
from bawwab.store import open_store
from bawwab.types import Finding, Mode, ScanReport, Severity, Verdict


@pytest.fixture
def store(tmp_path, monkeypatch):
    h = tmp_path / "home"
    h.mkdir()
    monkeypatch.setenv("HOME", str(h))
    monkeypatch.setenv("BAWWAB_HOME", str(h / ".bawwab"))
    return open_store()


def fake_scan(verdicts: dict[str, Verdict], version="1.0.0", calls=None):
    def scan(t, **kw):
        if calls is not None:
            calls.append((t, kw))
        v = verdicts.get(t.name or t.url or t.path, Verdict.CLEAN)
        findings = [] if v == Verdict.CLEAN else [
            Finding("x.rule", Severity.CRITICAL if v == Verdict.MALICIOUS else Severity.MED, "static", f"bad {t.name}")
        ]
        return ScanReport(f"{t.kind}:{t.name}@{version}#abc", t, version, Mode.STANDARD, v, findings, datetime.now(UTC))
    return scan


def bash(cmd):
    return HookInput("Bash", {"command": cmd}, "/tmp")


def decision(out):
    return out["hookSpecificOutput"]["permissionDecision"]


def reason(out):
    return out["hookSpecificOutput"]["permissionDecisionReason"]


def pid_of(out):
    return re.search(r"! bawwab approve (?:--force )?([A-Z2-7]{4})", reason(out)).group(1)


def test_non_install_is_none(store):
    assert run_gate(bash("ls -la"), scan=fake_scan({}), store=store) is None


def test_clean_allows_and_pins(store):
    calls = []
    out = run_gate(bash("claude mcp add gh -- npx -y @a/b"), scan=fake_scan({}, calls=calls), store=store)
    assert out["hookSpecificOutput"]["hookEventName"] == "PreToolUse"
    assert decision(out) == "allow"
    assert out["hookSpecificOutput"]["updatedInput"] == {"command": "claude mcp add gh -- npx -y @a/b@1.0.0"}
    assert calls[0][1]["mode"] == Mode.STANDARD


def test_clean_already_pinned_has_no_updated_input(store):
    out = run_gate(bash("claude mcp add gh -- npx -y @a/b@1.0.0"), scan=fake_scan({}), store=store)
    assert decision(out) == "allow" and "updatedInput" not in out["hookSpecificOutput"]


def test_suspicious_denies_then_approve_allows(store):
    inp = bash("claude mcp add gh -- npx -y @a/b")
    scan = fake_scan({"@a/b": Verdict.SUSPICIOUS})
    out = run_gate(inp, scan=scan, store=store)
    assert decision(out) == "deny" and "! bawwab approve " in reason(out)
    ok, _ = store.approve(pid_of(out))
    assert ok
    out = run_gate(inp, scan=scan, store=store)
    assert decision(out) == "allow"
    assert out["hookSpecificOutput"]["updatedInput"]["command"].endswith("@a/b@1.0.0")


def test_malicious_denies_and_plain_approve_fails(store):
    inp = bash("claude mcp add gh -- npx -y @a/b")
    scan = fake_scan({"@a/b": Verdict.MALICIOUS})
    out = run_gate(inp, scan=scan, store=store)
    assert decision(out) == "deny" and "MALICIOUS" in reason(out)
    ok, msg = store.approve(pid_of(out))
    assert not ok and "malicious" in msg
    assert decision(run_gate(inp, scan=scan, store=store)) == "deny"


def test_rejected_denies(store):
    inp = bash("claude mcp add gh -- npx -y @a/b")
    scan = fake_scan({"@a/b": Verdict.SUSPICIOUS})
    store.reject(pid_of(run_gate(inp, scan=scan, store=store)))
    out = run_gate(inp, scan=scan, store=store)
    assert decision(out) == "deny" and "previously rejected" in reason(out)


def test_scan_raises_denies(store):
    def boom(t, **kw):
        raise RuntimeError("kaput")
    out = run_gate(bash("claude mcp add gh -- npx -y @a/b"), scan=boom, store=store)
    assert decision(out) == "deny" and reason(out).startswith("bawwab error")


def test_detect_raises_is_none_and_audited(store, monkeypatch):
    def boom(inp):
        raise RuntimeError("detect broke")
    monkeypatch.setattr(gate_mod, "detect_install", boom)
    assert run_gate(bash("claude mcp add gh -- npx -y @a/b"), scan=fake_scan({}), store=store) is None
    rows = store._conn.execute("SELECT event FROM audit").fetchall()
    assert any(r[0] == "gate.detect_error" for r in rows)


def test_protected_pending_then_approved(store):
    inp = bash("claude plugin marketplace add o/evil")
    out = run_gate(inp, scan=fake_scan({}), store=store)
    assert decision(out) == "deny" and "new marketplace: o/evil" in reason(out)
    assert store.approve(pid_of(out))[0]
    assert decision(run_gate(inp, scan=fake_scan({}), store=store)) == "allow"
    other = run_gate(bash("claude plugin marketplace add o/other"), scan=fake_scan({}), store=store)
    assert decision(other) == "deny"


def test_multiple_targets_worst_wins(store, tmp_path):
    content = json.dumps({"mcpServers": {
        "a": {"command": "npx", "args": ["-y", "aa"]},
        "b": {"command": "npx", "args": ["-y", "bb"]},
        "c": {"command": "npx", "args": ["-y", "cc"]},
    }}, indent=2)
    inp = HookInput("Write", {"file_path": str(tmp_path / ".mcp.json"), "content": content}, str(tmp_path))
    out = run_gate(inp, scan=fake_scan({"bb": Verdict.SUSPICIOUS, "cc": Verdict.SUSPICIOUS}), store=store)
    assert decision(out) == "deny"
    ids = re.findall(r"! bawwab approve ([A-Z2-7]{4})", reason(out))
    assert len(ids) == 2 and ids[0] != ids[1]
    assert "\n\n" in reason(out)


def test_overlay_scanned_in_temp_copy(store, tmp_path):
    skill = tmp_path / "home" / ".claude" / "skills" / "foo"
    skill.mkdir(parents=True)
    (skill / "helper.py").write_text("print(1)")
    seen = {}

    def scan(t, **kw):
        from pathlib import Path
        p = Path(t.path)
        seen["files"] = sorted(x.name for x in p.iterdir())
        seen["skill"] = (p / "SKILL.md").read_text()
        seen["name"] = t.name
        return fake_scan({})(t, **kw)

    inp = HookInput("Write", {"file_path": str(skill / "SKILL.md"), "content": "# new"}, "/tmp")
    out = run_gate(inp, scan=scan, store=store)
    assert decision(out) == "allow"
    assert seen == {"files": ["SKILL.md", "helper.py"], "skill": "# new", "name": str(skill)}
    assert not (skill / "SKILL.md").exists()


def test_decisions_audited(store):
    run_gate(bash("claude mcp add gh -- npx -y @a/b"), scan=fake_scan({}), store=store)
    rows = store._conn.execute("SELECT fields FROM audit WHERE event='gate.decision'").fetchall()
    f = json.loads(rows[-1][0])
    assert f["decision"] == "allow" and f["tool_name"] == "Bash" and f["keys"] == ["npm:@a/b@1.0.0#abc"]


def test_cli_gate(store, monkeypatch, capsys):
    from bawwab import cli

    monkeypatch.setattr(gate_mod, "scan_target", fake_scan({"@a/b": Verdict.SUSPICIOUS}))
    hook = {"tool_name": "Bash", "tool_input": {"command": "claude mcp add gh -- npx -y @a/b"},
            "cwd": "/tmp", "hook_event_name": "PreToolUse", "session_id": "s"}
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(hook)))
    assert cli.main(["gate"]) == 0
    out = json.loads(capsys.readouterr().out)
    assert decision(out) == "deny"

    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps({**hook, "tool_input": {"command": "ls"}})))
    assert cli.main(["gate"]) == 0
    assert capsys.readouterr().out == ""

    monkeypatch.setattr("sys.stdin", io.StringIO("not json"))
    assert cli.main(["gate"]) == 0
    assert capsys.readouterr().out == ""
