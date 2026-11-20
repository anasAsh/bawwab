"""Ruling R55 (fix round 5, C3): a renamed, linked or copied bawwab never approves without the user.

Bawwab and Claude's tool shell run as the same OS user, so the gate defends the ordinary routes: it
recognises bawwab by what a command word resolves to (not only by its name), refuses a protected argv tail on
any command word that isn't a known system program, and protects copying/linking bawwab's executables and
writing a script that runs one. Deliberate forging of bawwab's own state is a documented residual.
"""
from __future__ import annotations

import os
import shutil
import stat
import statistics
import time
from pathlib import Path

import pytest

from bawwab import clicmd
from bawwab.gate import detect
from bawwab.gate.detect import HookInput, Protected, detect_install
from bawwab.gate.gate import run_gate
from bawwab.gate.prefilter import bawwab_exe_file, prefilter
from test_first_run import FakeScan

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "bin" / "bawwab"
CONSOLE = """#!{py}
# -*- coding: utf-8 -*-
import sys
from bawwab.cli import main
if __name__ == "__main__":
    sys.exit(main())
"""


def _x(p: Path, text: str) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return p


@pytest.fixture
def lay(tmp_path):
    """An installed-layout data dir with a venv console script, and a scratch dir with no "bawwab" in its name."""
    home = Path(os.environ["HOME"])
    data = home / ".claude" / "plugins" / "data" / "bawwab-bawwab"
    venv_exe = _x(data / "venv" / "bin" / "bawwab", CONSOLE.format(py=data / "venv" / "bin" / "python"))
    work = tmp_path / "w"
    work.mkdir()
    return {"data": data, "venv_exe": venv_exe, "work": work}


def _deny(cmd: str, cwd: str = "/tmp") -> bool:
    out = run_gate(HookInput("Bash", {"command": cmd}, cwd), scan=FakeScan())
    return bool(out) and out["hookSpecificOutput"]["permissionDecision"] == "deny"


def _none(cmd: str, cwd: str = "/tmp") -> bool:
    return detect_install(HookInput("Bash", {"command": cmd}, cwd)) is None


# ------------------------------------------------------------------ the reviewer's C3 probes


def test_c3_symlink_to_launcher_then_approve(lay):
    w = lay["work"]
    assert _deny(f"ln -s {LAUNCHER} {w}/bw && {w}/bw approve AB12")


def test_c3_copy_of_venv_console_script_then_reject(lay):
    w = lay["work"]
    assert _deny(f"cp {lay['venv_exe']} {w}/bw2 && {w}/bw2 reject AB12")


def test_c3_existing_renamed_copy_with_force(lay):
    w = lay["work"]
    helper = _x(w / "helper", LAUNCHER.read_text())
    cmd = f"{helper} approve X --force"
    assert "bawwab" not in cmd
    assert _deny(cmd)


def test_c3_python_c_imports_bawwab_and_approves():
    assert _deny("python3 -c 'from bawwab.cli import main; main([\"approve\", \"X\"])'")
    assert _deny("python3 -c 'import bawwab.store as s; s.open_store().approve(\"X\", force=True)'")
    assert _deny("python3 -c 'from bawwab.effects import init_skip; init_skip(\".\")'")


def test_c3_python_m_bawwab_cli():
    assert _deny("python3 -m bawwab.cli approve X")
    assert _deny("python3.12 -m bawwab reject X")
    assert _deny("python -m bawwab.cli init --skip")


# ------------------------------------------------------------------ recognised by what it resolves to


@pytest.mark.parametrize("args", ["init", "effects --retry", "$(printf apprXve | tr X o) AB12", "`echo x`"])
def test_renamed_existing_copy_any_protected_form(lay, args):
    """Not only the argv-tail guess: the word resolves to a bawwab executable, so every user-only form is refused."""
    helper = _x(lay["work"] / "helper", LAUNCHER.read_text())
    assert _deny(f"{helper} {args}")


@pytest.mark.parametrize("make", ["symlink", "console", "hardlink"])
def test_renamed_resolution_kinds(lay, make):
    w = lay["work"]
    t = w / "tool"
    if make == "symlink":
        t.symlink_to(LAUNCHER)
    elif make == "console":
        shutil.copy2(lay["venv_exe"], t)
    else:
        os.link(lay["venv_exe"], t)
    assert bawwab_exe_file(str(t))
    assert _deny(f"{t} init")
    assert _deny(f"cd {w} && ./tool init")
    assert _deny(f"setsid {t} approve AB12")
    assert _deny(f"sh {t} approve AB12")


def test_renamed_copy_on_path_by_bare_name(lay, monkeypatch):
    bindir = lay["work"] / "bin"
    (bindir).mkdir()
    (bindir / "bw").symlink_to(lay["venv_exe"])
    monkeypatch.setenv("PATH", f"{bindir}:{os.environ.get('PATH', '/usr/bin:/bin')}")
    assert _deny("bw init")
    assert _deny("bw effects --retry")


def test_script_that_execs_bawwab_is_recognised(lay):
    s = _x(lay["work"] / "run.sh", f'#!/bin/sh\nexec {LAUNCHER} "$@"\n')
    assert _deny(f"{s} init")


def test_safe_launcher_commands_still_allowed_under_another_name(lay):
    helper = _x(lay["work"] / "helper", LAUNCHER.read_text())
    for cmd in (f"{helper} init --scan", f"{helper} scan --all", f"{helper} explain F3a91c", f"{helper} --help"):
        assert _none(cmd), cmd


# ------------------------------------------------------------------ argv tail on unknown command words


@pytest.mark.parametrize("cmd", [
    "/tmp/nonexistent-bw approve X --force",
    "./bw reject AB12",
    "bw-not-on-path approve AB12",
    "$B approve AB12",
    "f init --skip",
    "timeout 5 /tmp/nonexistent-bw approve AB12",
    "env -i /tmp/x approve AB12",
    "/tmp/x effects --retry",
])
def test_unknown_word_with_protected_tail_is_denied(cmd):
    assert _deny(cmd), cmd


@pytest.mark.parametrize("cmd", [
    "ls",
    "ls -la /tmp",
    "cp a b",
    "ln -s x y",
    "mv a b",
    "echo approve AB12",
    "printf '%s\\n' reject AB12",
    "git init",
    "npm init -y",
    "git rebase --skip",
    'git commit -m "approve AB12 later"',
    "git commit -F- <<'EOF'\nPlease approve this change\n- reject the old one\nEOF",
    "cat <<EOF > notes.md\nthen approve AB12\nEOF",
    "uv run pytest tests/test_cli.py -k approve",
])
def test_negatives_not_denied(cmd):
    assert _none(cmd), cmd


def test_known_system_binary_takes_approve_argv():
    git = shutil.which("git")
    if not git or not os.path.realpath(git).startswith(("/usr/", "/bin/", "/opt/homebrew", "/nix/store")):
        pytest.skip("no system git")
    assert _none("git approve AB12")
    assert _none(f"{git} approve AB12")


def test_known_system_check_rejects_a_bawwab_copy_in_a_system_named_place(lay, monkeypatch):
    """A copy that runs bawwab is never "known system", whatever its name."""
    t = _x(lay["work"] / "git", LAUNCHER.read_text())
    monkeypatch.setattr(detect, "_SYSTEM_DIRS", (str(lay["work"]),))
    assert not detect._known_system(str(t), "/", False)
    assert _deny(f"{t} approve AB12")


# ------------------------------------------------------------------ copying / linking bawwab executables


@pytest.mark.parametrize("tmpl", [
    "cp {venv} {w}/x",
    "cp -p {venv} {w}/",
    "install -m755 {launcher} {w}/x",
    "ln {venv} {w}/x",
    "ln -s {launcher} {w}/x",
    "ln -sf {rel} {w}/x",  # relative target: read from the link's dir
    "rsync -a {venv} {w}/x",
    "mv {w}/tool {w}/x",
    "cp -t {w} {launcher}",
    "cat {launcher} > {w}/x",
    "cat {venv} | tee {w}/x",
    "dd if={venv} of={w}/x",
])
def test_copying_or_linking_a_bawwab_executable_is_protected(lay, tmpl):
    w = lay["work"]
    (w / "tool").symlink_to(LAUNCHER)
    rel = os.path.relpath(LAUNCHER, w).replace("bin/bawwab", "bin/./bawwab")  # basename still bawwab: also via path
    cmd = tmpl.format(venv=lay["venv_exe"], launcher=LAUNCHER, w=w, rel=rel)
    r = detect_install(HookInput("Bash", {"command": cmd}, str(w)))
    assert isinstance(r, Protected) and ("bawwab executable" in r.reason or "bawwab state" in r.reason), (cmd, r)


def test_copying_docs_that_mention_the_launcher_is_fine(lay):
    w = lay["work"]
    assert _none(f"cp {ROOT / 'README.md'} {w}/r.md")
    assert _none(f"cat {ROOT / 'README.md'} > {w}/r.md")
    assert _none(f"cp -r {ROOT / 'bawwab'} {w}/pkg")  # the Python package dir is not an executable


# ------------------------------------------------------------------ writing a script that runs bawwab


@pytest.mark.parametrize("content", [
    '#!/bin/sh\nexec /home/u/.claude/plugins/cache/bawwab/bawwab/0.1.0/bin/bawwab "$@"\n',
    '#!/bin/sh\nbawwab approve "$1"\n',
    "#!/usr/bin/env python3\nimport sys\nfrom bawwab.cli import main\nsys.exit(main())\n",
    '#!/usr/bin/env python3\nimport subprocess, sys\nsubprocess.run(["bawwab", *sys.argv[1:]])\n',
])
def test_write_tool_script_that_runs_bawwab_is_denied(lay, content):
    p = str(lay["work"] / "bw")
    data = {"tool_name": "Write", "tool_input": {"file_path": p, "content": content}, "cwd": "/"}
    assert prefilter(data)
    r = detect_install(HookInput("Write", {"file_path": p, "content": content}, "/"))
    assert isinstance(r, Protected) and "runs bawwab" in r.reason, r


def test_edit_that_makes_a_script_run_bawwab_is_denied(lay):
    p = lay["work"] / "s.sh"
    p.write_text("#!/bin/sh\necho hi\n")
    ti = {"file_path": str(p), "old_string": "echo hi", "new_string": 'exec bawwab "$@"'}
    assert prefilter({"tool_name": "Edit", "tool_input": ti, "cwd": "/"})
    r = detect_install(HookInput("Edit", ti, "/"))
    assert isinstance(r, Protected) and "runs bawwab" in r.reason, r


@pytest.mark.parametrize("content", [
    "# Notes\nRun `bawwab approve AB12` in your own terminal.\n",  # prose, no shebang
    "#!/bin/sh\necho hello \"$@\"\n",  # a script, but no bawwab
])
def test_write_tool_negatives(lay, content):
    p = str(lay["work"] / "f")
    assert detect_install(HookInput("Write", {"file_path": p, "content": content}, "/")) is None


@pytest.mark.parametrize("tmpl", [
    "printf '#!/bin/sh\\nexec bawwab \"$@\"\\n' > {w}/bw",
    "echo '#!/bin/sh' > {w}/bw; echo 'exec {launcher} \"$@\"' >> {w}/bw",
    "cat > {w}/bw <<'EOF'\n#!/bin/sh\nexec {launcher} \"$@\"\nEOF",
    "tee {w}/bw <<'EOF'\n#!/bin/sh\nbawwab approve \"$1\"\nEOF",
])
def test_shell_write_of_a_script_that_runs_bawwab(lay, tmpl):
    cmd = tmpl.format(w=lay["work"], launcher=LAUNCHER)
    r = detect_install(HookInput("Bash", {"command": cmd}, "/"))
    assert isinstance(r, Protected), (cmd, r)


# ------------------------------------------------------------------ plugin data dir and venv are bawwab state


@pytest.mark.parametrize("tmpl", [
    "echo x > {data}/bootstrap-complete",
    "touch {data}/state-created",
    "rm -rf {data}/venv",
    "rm -rf {data}",
    "cp evil.py {data}/venv/lib/python3.12/site-packages/bawwab/cli.py",
    "sed -i s/x/y/ {data}/venv/bin/bawwab",
    "rm -rf ~/.claude/plugins/data/baw*",
])
def test_plugin_data_dir_and_venv_are_protected(lay, tmpl):
    cmd = tmpl.format(data=lay["data"])
    r = detect_install(HookInput("Bash", {"command": cmd}, "/"))
    assert r is not None and "bawwab state change" in (r.reason if isinstance(r, Protected) else r.protected), (cmd, r)
    assert _deny(cmd, "/")


def test_plugin_data_dir_write_tool_protected(lay):
    p = str(lay["data"] / "bootstrap-complete")
    r = detect_install(HookInput("Write", {"file_path": p, "content": "x"}, "/"))
    assert isinstance(r, Protected) and "bawwab state" in r.reason


def test_env_data_dir_and_venv_protected(tmp_path, monkeypatch):
    pd, venv = tmp_path / "pd", tmp_path / "venv"
    monkeypatch.setenv("CLAUDE_PLUGIN_DATA", str(pd))
    monkeypatch.setenv("BAWWAB_VENV", str(venv))
    assert isinstance(detect_install(HookInput("Bash", {"command": f"touch {pd}/bootstrap-complete"}, "/")), Protected)
    assert isinstance(detect_install(HookInput("Bash", {"command": f"rm -rf {venv}/bin"}, "/")), Protected)


def test_other_plugin_data_dirs_and_reads_are_fine(lay):
    other = Path(os.environ["HOME"]) / ".claude" / "plugins" / "data" / "other-mkt"
    assert not detect._bawwab_path(str(other / "x"))
    assert detect._bawwab_path(str(lay["data"] / "x"))
    assert _none(f"ls {lay['data']}")
    assert _none(f"cat {lay['data']}/bootstrap-failed")


# ------------------------------------------------------------------ pre-filter


def test_prefilter_catches_renamed_forms_without_the_word_bawwab(lay):
    helper = _x(lay["work"] / "helper", LAUNCHER.read_text())
    for cmd in (f"{helper} init", f"{helper} $(x) Y", "/tmp/bw approve AB12", "./x reject AB12", "./x init --skip"):
        assert "bawwab" not in cmd
        assert prefilter({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(lay["work"])}), cmd


def test_prefilter_stays_quiet_on_ordinary_commands(lay):
    for cmd in ("ls -la", "git status", "cat src/app.py", "pytest -q tests/", "npm test"):
        assert not prefilter({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(lay["work"])}), cmd


def test_prefilter_speed_on_ordinary_commands(lay):
    cmds = ["ls -la", "git status && git diff --stat", "cat src/app.py | grep -n foo > /tmp/out.txt",
            "python3 scripts/build.py --out dist/x", "npm run build -- --prod"]
    times = []
    for _ in range(200):
        for c in cmds:
            t0 = time.perf_counter()
            prefilter({"tool_name": "Bash", "tool_input": {"command": c}, "cwd": str(lay["work"])})
            times.append(time.perf_counter() - t0)
    assert statistics.median(times) < 0.0005, statistics.median(times)


# ------------------------------------------------------------------ M17: clicmd


def test_clicmd_plugin_root_always_renders_launcher(monkeypatch, tmp_path):
    """Even with another `bawwab` first on PATH, a plugin renders its own absolute launcher (M17)."""
    other = _x(tmp_path / "planted" / "bawwab", "#!/bin/sh\n")
    monkeypatch.setenv("PATH", f"{other.parent}:{os.environ.get('PATH', '')}")
    got = clicmd.cmd("approve AB12")
    assert got.startswith(str(LAUNCHER.resolve())) or got.startswith("'" + str(LAUNCHER.resolve()))
    assert got != "bawwab approve AB12"


def test_clicmd_pure_cli_install_renders_bare(monkeypatch, tmp_path):
    monkeypatch.setattr(clicmd, "LAUNCHER", str(tmp_path / "site-packages" / "bin" / "bawwab"))
    assert clicmd.cmd("approve AB12") == "bawwab approve AB12"


def test_relative_symlink_target_is_read_from_the_links_dir(lay):
    w = lay["work"]
    (w / "tool").symlink_to(LAUNCHER)
    r = detect_install(HookInput("Bash", {"command": f"ln -s tool {w}/x"}, "/"))
    assert isinstance(r, Protected) and "bawwab executable" in r.reason, r
