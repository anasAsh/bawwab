from __future__ import annotations

import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from bawwab.cli import main
from bawwab.store import Store

FIX = Path(__file__).parent / "fixtures"


@pytest.fixture
def env(tmp_path, monkeypatch):
    fake = tmp_path / "judge.json"
    fake.write_text('{"findings":[]}')
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path / "home"))
    monkeypatch.setenv("BAWWAB_FAKE_JUDGE", str(fake))
    monkeypatch.chdir(tmp_path)
    return tmp_path


def test_scan_exit_codes(env, capsys):
    assert main(["scan", str(FIX / "code/clean_server")]) == 0
    assert main(["scan", str(FIX / "text/inject_skill")]) == 1
    assert main(["scan", str(FIX / "code/postinstall_curl")]) == 2
    assert "MALICIOUS" in capsys.readouterr().out


def test_scan_json_and_approve_flow(env, capsys):
    assert main(["scan", str(FIX / "text/inject_skill"), "--json"]) == 1
    d = json.loads(capsys.readouterr().out)
    assert d["verdict"] == "suspicious" and d["approval_id"]
    assert main(["approve", d["approval_id"]]) == 0
    assert capsys.readouterr().out.startswith("approved ")
    assert main(["approve", "ZZZZ"]) == 1
    assert "error: unknown id" in capsys.readouterr().out


def test_malicious_needs_force_and_explain(env, capsys):
    main(["scan", str(FIX / "code/postinstall_curl"), "--json"])
    d = json.loads(capsys.readouterr().out)
    pid = d["approval_id"]
    assert main(["approve", pid]) == 1
    assert "malicious: use --force" in capsys.readouterr().out
    assert main(["approve", pid, "--force"]) == 0
    capsys.readouterr()
    assert main(["explain", d["findings"][0]["id"]]) == 0
    assert "Why" in capsys.readouterr().out
    assert main(["reject", pid]) == 0
    assert capsys.readouterr().out.startswith("rejected ")


def test_error_no_traceback(env, capsys, monkeypatch):
    blocker = env / "file"
    blocker.write_text("x")
    monkeypatch.setenv("BAWWAB_HOME", str(blocker / "sub"))  # unusable state dir
    assert main(["scan", str(FIX / "code/clean_server")]) == 3
    cap = capsys.readouterr()
    assert "Traceback" not in cap.out + cap.err


def test_console_script_exit_2(env):
    r = subprocess.run(
        [sys.executable, "-m", "bawwab.cli", "scan", str(FIX / "code/postinstall_curl"), "--json"],
        capture_output=True, text=True, env=os.environ.copy(),
    )
    assert r.returncode == 2, r.stderr


def test_bare_relative_path_is_local(env, capsys, monkeypatch):
    monkeypatch.chdir(FIX.parent.parent)
    assert main(["scan", "tests/fixtures/code/postinstall_curl", "--json"]) == 2


def test_no_cache_flag(env, capsys, monkeypatch):
    calls = []
    import bawwab.scan as sm

    real = sm.scan_target

    def spy(*a, **k):
        calls.append(k.get("no_cache"))
        return real(*a, **k)

    monkeypatch.setattr(sm, "scan_target", spy)
    main(["scan", str(FIX / "code/clean_server")])
    main(["scan", str(FIX / "code/clean_server"), "--no-cache"])
    assert calls == [False, True]
