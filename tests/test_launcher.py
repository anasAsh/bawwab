"""Task 13 fix round 4: recoverable setup failures (I6) and the plugin CLI launcher bin/bawwab (R54)."""
from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from bawwab import clicmd
from bawwab.gate.detect import HookInput
from bawwab.gate.gate import run_gate
from conftest import _boot_token
from test_bootstrap import _bh, _call, _changed_initialised, _failing_uv, _fake_uv, _hook, _no_lock
from test_first_run import FakeScan

ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "bin" / "bawwab"
QUOTED = shlex.quote(str(LAUNCHER.resolve()))


def _path_without_bawwab(*extra: Path) -> str:
    """PATH with no `bawwab` executable on it (a plugin-only install), plus the given dirs in front."""
    keep = [d for d in os.environ["PATH"].split(os.pathsep) if d and not (Path(d) / "bawwab").exists()]
    return os.pathsep.join([str(p) for p in extra] + keep)


def _plugin_only(env: dict, fakebin: Path) -> dict:
    env = dict(env)
    env["PATH"] = _path_without_bawwab(fakebin)
    return env


@pytest.fixture
def fresh(tmp_path):
    (_bh() / "bootstrap-complete").unlink()
    return tmp_path


def _gate(env: dict, tool: str, proj: Path, **ti) -> str:
    return _hook("gate", _call(tool, proj, **ti), env).stdout


def _deny_reason(out: str) -> str:
    d = json.loads(out)["hookSpecificOutput"]
    assert d["permissionDecision"] == "deny"
    return d["permissionDecisionReason"]


# ------------------------------------------------------------------ A. I6: no lock-out while setup fails

def _failed_setup(fresh: Path) -> tuple[Path, dict]:
    proj = _changed_initialised(fresh)
    env, _ = _failing_uv(fresh)
    _hook("bootstrap", "", env)
    assert (_bh() / "bootstrap-failed").exists()
    return proj, env


@pytest.mark.parametrize("tool,ti", [("Read", {"file_path": "/etc/hostname"}), ("Grep", {"pattern": "x"}),
                                     ("Glob", {"pattern": "*"}), ("LS", {"path": "/"}), ("TodoWrite", {"todos": []})])
def test_setup_failed_read_only_tools_pass(fresh, tool, ti):
    proj, env = _failed_setup(fresh)
    assert _gate(env, tool, proj, **ti) == ""


def test_setup_failed_changed_config_bash_still_denied(fresh):
    proj, env = _failed_setup(fresh)
    assert "setup failed" in _deny_reason(_gate(env, "Bash", proj, command="ls"))
    assert "setup failed" in _deny_reason(_gate(env, "WebFetch", proj, url="https://x.invalid"))
    p = json.loads(_hook("post", _call("Edit", proj, file_path="/x"), env).stdout)
    assert p["decision"] == "block"


def test_setup_running_read_only_tools_pass_too(fresh):
    proj = _changed_initialised(fresh)
    env, _ = _fake_uv(fresh, sync_sleep=3)
    assert "still setting up" in _deny_reason(_gate(env, "Bash", proj, command="ls"))
    assert _gate(env, "Read", proj, file_path="/etc/hostname") == ""
    _no_lock()


def test_quarantine_and_setup_uses_the_same_read_only_set():
    import importlib.util

    from bawwab import effects as fx

    spec = importlib.util.spec_from_file_location("_hook_ro", ROOT / "hooks" / "bawwab_hook.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    assert m.READ_ONLY_TOOLS == fx.READ_ONLY_TOOLS


def _assert_recovery(text: str, exe: str) -> None:
    assert f"{exe} setup --retry" in text, text
    assert "proxy" in text and "network" in text and "uv" in text, text
    assert "/plugin disable bawwab" in text and "turns off" in text and "protection" in text, text
    assert "effects --retry" not in text  # re-runs the effect check, never syncs the venv


def test_setup_failed_texts_name_working_commands_plugin_only(fresh):
    """No `bawwab` on PATH: every text names the launcher by its absolute path."""
    proj = _changed_initialised(fresh)
    env, _ = _failing_uv(fresh)
    env = _plugin_only(env, fresh / "failbin")
    _hook("bootstrap", "", env)
    _assert_recovery(_deny_reason(_gate(env, "Bash", proj, command="ls")), QUOTED)
    _assert_recovery(json.loads(_hook("post", _call("Edit", proj, file_path="/x"), env).stdout)["reason"], QUOTED)
    ctx = json.loads(_hook("inventory", json.dumps({"session_id": "s1", "cwd": str(proj)}), env).stdout)
    _assert_recovery(ctx["hookSpecificOutput"]["additionalContext"], QUOTED)


def test_setup_running_text_names_working_commands(fresh):
    proj = _changed_initialised(fresh)
    env, _ = _fake_uv(fresh, sync_sleep=3)
    env = _plugin_only(env, fresh / "fakebin")
    reason = _deny_reason(_gate(env, "Bash", proj, command="ls"))
    assert f"{QUOTED} setup --retry" in reason and "/plugin disable bawwab" in reason
    _no_lock()


def test_setup_failed_texts_use_bare_name_when_on_path(fresh):
    proj, env = _failed_setup(fresh)  # the dev venv's `bawwab` is on PATH
    _assert_recovery(_deny_reason(_gate(env, "Bash", proj, command="ls")), "bawwab")


def _launch(args: list[str], env: dict, cwd: Path | None = None, exe: str | None = None):
    return subprocess.run([exe or str(LAUNCHER), *args], capture_output=True, text=True, env=env, cwd=cwd,
                          timeout=60)


def test_setup_retry_reports_the_error_then_succeeds_once_online(fresh):
    _failed_setup(fresh)
    env, _ = _failing_uv(fresh)
    r = _launch(["setup", "--retry"], env)
    assert r.returncode != 0
    out = r.stdout + r.stderr
    assert "failed" in out and "proxy" in out and "/plugin disable bawwab" in out
    assert not (_bh() / "bootstrap-complete").exists()
    env, log = _fake_uv(fresh)  # the network is back
    r = _launch(["setup", "--retry"], env)
    assert r.returncode == 0, r.stdout + r.stderr
    assert (_bh() / "bootstrap-complete").read_text() == _boot_token()
    assert not (_bh() / "bootstrap-failed").exists()
    assert any(x.startswith(f"sync --project {ROOT.resolve()} --frozen") for x in log.read_text().splitlines())


def test_setup_retry_ignores_the_respawn_rate_limit(fresh):
    _failed_setup(fresh)
    import time

    (_bh() / "bootstrap.spawned").write_text(str(time.time()))  # a background start just now
    env, _ = _fake_uv(fresh)
    assert _launch(["setup", "--retry"], env).returncode == 0
    assert (_bh() / "bootstrap-complete").read_text() == _boot_token()


def test_cli_setup_retry_runs_the_plugin_setup(fresh, monkeypatch, capsys):
    """`bawwab setup --retry` from an installed CLI (on PATH) runs the same foreground setup."""
    from bawwab.cli import main

    env, _ = _fake_uv(fresh)
    monkeypatch.setenv("PATH", env["PATH"])
    monkeypatch.delenv("BAWWAB_VENV")
    assert main(["setup", "--retry"]) == 0
    assert (_bh() / "bootstrap-complete").read_text() == _boot_token()


# ------------------------------------------------------------------ B. R54: bin/bawwab


def test_launcher_is_posix_sh_and_executable():
    assert LAUNCHER.is_file() and os.access(LAUNCHER, os.X_OK)
    assert LAUNCHER.read_text().splitlines()[0] == "#!/bin/sh"
    assert "CLAUDE_PLUGIN_ROOT" not in LAUNCHER.read_text()  # its root comes from $0, never env
    if shutil.which("dash"):
        assert subprocess.run(["dash", "-n", str(LAUNCHER)]).returncode == 0


def _log_lines(log: Path) -> list[str]:
    return [x for x in log.read_text().splitlines() if x.startswith("run ")]


def test_launcher_root_from_dollar0_not_env(fresh, tmp_path):
    env, log = _fake_uv(fresh)
    env.pop("BAWWAB_VENV", None)
    env["CLAUDE_PLUGIN_ROOT"] = str(tmp_path / "evil")
    r = _launch(["scan", "x y"], env)
    assert r.returncode == 0, r.stderr
    assert _log_lines(log) == [f"run --project {ROOT.resolve()} --frozen --quiet bawwab scan x y | {_bh() / 'venv'}"]


@pytest.mark.parametrize("how", ["absolute", "relative", "bare", "symlink"])
def test_launcher_invocations_find_the_root(fresh, tmp_path, how):
    env, log = _fake_uv(fresh)
    env.pop("BAWWAB_VENV", None)
    cwd, exe = None, str(LAUNCHER)
    if how == "relative":
        cwd, exe = ROOT, "bin/bawwab"
    elif how == "bare":
        env["PATH"] = f"{ROOT / 'bin'}:{env['PATH']}"
        exe = "bawwab"
    elif how == "symlink":
        (tmp_path / "lnk").mkdir()
        (tmp_path / "lnk" / "bawwab").symlink_to(LAUNCHER)
        exe = str(tmp_path / "lnk" / "bawwab")
    r = _launch(["version"], env, cwd=cwd, exe=exe)
    assert r.returncode == 0, r.stderr
    assert _log_lines(log)[-1].startswith(f"run --project {ROOT.resolve()} --frozen --quiet bawwab version |")


def test_launcher_venv_in_plugin_data_dir(fresh, tmp_path):
    env, log = _fake_uv(fresh)
    data = tmp_path / "data" / "bawwab-mkt"
    env["CLAUDE_PLUGIN_DATA"] = str(data)
    assert _launch(["version"], env).returncode == 0
    assert _log_lines(log)[-1].endswith(f"| {data / 'venv'}")


def test_launcher_in_installed_layout_finds_the_data_dir_without_env(fresh, tmp_path):
    """The user's `!` shell has no CLAUDE_PLUGIN_DATA: the installed tree's data dir is derived from its own
    path (<plugins>/cache/<mkt>/<plugin>/<ver> -> <plugins>/data/<plugin>-<mkt>), so it shares the hook's venv."""
    from test_plugin_self import _builder

    plugins = Path.home() / ".claude" / "plugins"
    tree = _builder().build(plugins / "cache" / "mkt" / "bawwab" / "0.1.0")
    data = plugins / "data" / "bawwab-mkt"
    data.mkdir(parents=True)
    env, log = _fake_uv(fresh)
    env.pop("BAWWAB_VENV", None)
    r = _launch(["version"], env, exe=str(tree / "bin" / "bawwab"))
    assert r.returncode == 0, r.stderr
    assert _log_lines(log)[-1] == f"run --project {tree.resolve()} --frozen --quiet bawwab version | {data / 'venv'}"


def test_build_ships_the_launcher(tmp_path):
    from test_plugin_self import _builder

    out = _builder().build(tmp_path / "tree")
    assert (out / "bin" / "bawwab").read_bytes() == LAUNCHER.read_bytes()
    assert os.access(out / "bin" / "bawwab", os.X_OK)


# ------------------------------------------------------------------ the one helper


def test_helper_bare_name_when_on_path(monkeypatch, tmp_path):
    other = tmp_path / "bin" / "bawwab"
    other.parent.mkdir()
    other.write_text("#!/bin/sh\n")
    monkeypatch.setattr(clicmd.shutil, "which", lambda name: str(other))
    assert clicmd.cmd("approve AB12") == "bawwab approve AB12"


def test_helper_launcher_path_when_not_on_path(monkeypatch):
    monkeypatch.setattr(clicmd.shutil, "which", lambda name: None)
    assert clicmd.cmd("approve AB12") == f"{QUOTED} approve AB12"


def test_helper_launcher_path_when_only_the_launcher_itself_is_on_path(monkeypatch):
    """The hook's PATH may hold the plugin bin/ while the user's `!` shell does not: the absolute path is safe."""
    monkeypatch.setattr(clicmd.shutil, "which", lambda name: str(LAUNCHER))
    assert clicmd.cmd("x") == f"{QUOTED} x"


def test_helper_quotes_the_path(monkeypatch, tmp_path):
    root = tmp_path / "a b's"
    (root / "bin").mkdir(parents=True)
    (root / "bin" / "bawwab").write_text("#!/bin/sh\n")
    monkeypatch.setattr(clicmd, "LAUNCHER", str(root / "bin" / "bawwab"))
    monkeypatch.setattr(clicmd.shutil, "which", lambda name: None)
    got = clicmd.cmd("approve AB12")
    assert shlex.split(got) == [str(root / "bin" / "bawwab"), "approve", "AB12"]


def test_block_text_uses_the_helper(monkeypatch):
    from test_report import mk

    from bawwab.report import format_report

    monkeypatch.setattr(clicmd.shutil, "which", lambda name: None)
    out = format_report(mk(), "A7F3")
    assert f"! {QUOTED} approve A7F3" in out and f"! {QUOTED} explain F3a91c" in out
    assert "! bawwab " not in out


def test_quarantine_and_first_run_texts_use_the_helper(monkeypatch):
    from bawwab import effects as fx

    monkeypatch.setattr(clicmd.shutil, "which", lambda name: None)
    assert QUOTED in fx.lost_fix() and "! bawwab" not in fx.lost_fix()
    assert f"! {QUOTED} init --skip" in fx.ask_context(Path.cwd())


def test_no_hardcoded_user_commands_left():
    """Every `! bawwab …` instruction is rendered by the helper; none is hard-coded in the code."""
    import re

    hits = []
    for p in list((ROOT / "bawwab").rglob("*.py")) + [ROOT / "hooks" / "bawwab_hook.py"]:
        for i, line in enumerate(p.read_text().splitlines(), 1):
            if re.search(r"!\s+bawwab\s+[a-z]", line) and not line.lstrip().startswith("#"):
                hits.append(f"{p.relative_to(ROOT)}:{i}: {line.strip()}")
    assert not hits, "\n".join(hits)


# ------------------------------------------------------------------ gate protection through the launcher

_ABS = str(LAUNCHER)


@pytest.mark.parametrize("cmd", [
    "bawwab approve ABCD",
    f"{_ABS} approve ABCD",
    f"'{_ABS}' approve --force ABCD",
    "./bin/bawwab reject ABCD",
    "bin/bawwab approve ABCD",
    "../x/bin/bawwab init --skip",
    f"{_ABS} init --skip",
    f"{_ABS} init",
    f"sh {_ABS} approve ABCD",
    f"env A=1 {_ABS} reject ABCD",
    f"cd /tmp && {_ABS} approve ABCD",
    f"{_ABS} effects --retry",
])
def test_gate_refuses_user_only_commands_through_the_launcher(cmd, tmp_path):
    out = run_gate(HookInput("Bash", {"command": cmd}, str(tmp_path)), scan=FakeScan())
    assert out and out["hookSpecificOutput"]["permissionDecision"] == "deny", cmd


@pytest.mark.parametrize("cmd", [f"{_ABS} init --scan", f"{_ABS} scan --all", f"{_ABS} setup --retry",
                                 "bin/bawwab explain F3a91c"])
def test_gate_lets_claude_run_safe_launcher_commands(cmd, tmp_path):
    assert run_gate(HookInput("Bash", {"command": cmd}, str(tmp_path)), scan=FakeScan()) is None, cmd
