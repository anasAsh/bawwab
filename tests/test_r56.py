"""Ruling R56 (Task 13b): protected bawwab actions inside files the command runs or writes.

The reviewer's C4: a script holding `bawwab approve "$1" --force` (no shebang) run by `sh`/`bash`/`dash`/`.`/
`source`/`./`/`make` approved a MALICIOUS quarantine, because the gate only read the command's own argv. Now
the gate reads the file (never runs it) and applies the same protected-action check to its lines, following
nested script calls three files deep. Writing such a file is refused whatever its name or shebang. M19: during
setup, only calls bawwab's detection finds protected or install-like wait.
"""
from __future__ import annotations

import json
import os
import stat
import statistics
import subprocess
import sys
import time
from pathlib import Path

import pytest

from bawwab.gate.detect import HookInput, Protected, detect_install
from bawwab.gate.gate import run_gate
from bawwab.gate.prefilter import prefilter
from test_bootstrap import _fake_uv, _hook, fresh  # noqa: F401 - fixture
from test_first_run import FakeScan

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER = ROOT / "bin" / "bawwab"
APPROVE_1 = 'bawwab approve "$1" --force\n'


def _w(p: Path, text: str, exe: bool = False) -> Path:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    if exe:
        p.chmod(p.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return p


def _out(tool: str, ti: dict, cwd: Path):
    return run_gate(HookInput(tool, ti, str(cwd)), scan=FakeScan())


def _deny(cmd: str, cwd: Path) -> bool:
    out = _out("Bash", {"command": cmd}, cwd)
    return bool(out) and out["hookSpecificOutput"]["permissionDecision"] == "deny"


def _reason(cmd: str, cwd: Path) -> str:
    det = detect_install(HookInput("Bash", {"command": cmd}, str(cwd)))
    return det.reason if isinstance(det, Protected) else ""


def _none(cmd: str, cwd: Path) -> bool:
    return detect_install(HookInput("Bash", {"command": cmd}, str(cwd))) is None


def _routed(cmd: str, cwd: Path) -> bool:
    return prefilter({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(cwd)})


@pytest.fixture
def w(tmp_path):
    d = tmp_path / "repo"
    _w(d / "scripts" / "noshebang.sh", APPROVE_1, exe=True)
    _w(d / "scripts" / "ok.sh", "#!/bin/sh\n" + APPROVE_1)
    _w(d / "doit.sh", f"#!/bin/sh\n{LAUNCHER} approve AB12 --force\n")
    _w(d / "Makefile", "ok:\n\tbawwab approve HABZ --force\n\nclean:\n\trm -rf build\n")
    _w(d / "benign.sh", "#!/bin/sh\necho hello\nls -la\n")
    return d


# ------------------------------------------------------------------ the reviewer's C4 probes (no shebang, $1 id)


@pytest.mark.parametrize("cmd", [
    "sh scripts/noshebang.sh HABZ",
    "bash scripts/noshebang.sh HABZ",
    "dash scripts/noshebang.sh HABZ",
    "zsh scripts/noshebang.sh HABZ",
    ". scripts/noshebang.sh HABZ",
    "source scripts/noshebang.sh HABZ",
    "bash scripts/ok.sh HABZ",
    "bash doit.sh",
    "sh doit.sh",
    ". ./doit.sh",
    "make -f Makefile ok",
    "make ok",
    "make",
    "make -C . ok",
    "/bin/sh scripts/noshebang.sh HABZ",
    "env sh scripts/noshebang.sh HABZ",
    "nohup bash scripts/noshebang.sh HABZ",
    "cd scripts && sh noshebang.sh HABZ",
    "sh < scripts/noshebang.sh",
    "cat scripts/noshebang.sh | sh",
    "bash -e -o pipefail scripts/noshebang.sh HABZ",
])
def test_c4_script_holding_approve_is_denied(w, cmd):
    assert _deny(cmd, w), cmd
    assert _routed(cmd, w), cmd


def test_c4_dot_slash_text_file_without_shebang(w):
    _w(w / "run", APPROVE_1, exe=True)
    assert _deny("./run HABZ", w)
    assert _deny(f"{w}/run HABZ", w)
    assert _routed("./run HABZ", w)


def test_c4_shebang_script_by_path(w):
    _w(w / "go.sh", "#!/usr/bin/env bash\nset -eu\n" + APPROVE_1, exe=True)
    assert _deny("./go.sh HABZ", w)


@pytest.mark.parametrize("line", [
    "bawwab reject \"$1\"",
    "bawwab init --skip",
    "bawwab effects --retry",
    f"{LAUNCHER} approve \"$1\"",
    "python3 -m bawwab approve \"$1\"",
    "uv run bawwab approve \"$1\"",
    "exec bawwab \"$@\"",  # forwards the call's argv: approve HABZ
])
def test_c4_every_protected_form_inside_a_script(w, line):
    _w(w / "s.sh", line + "\n")
    assert _deny("sh s.sh approve HABZ" if "$@" in line else "sh s.sh HABZ", w), line


def test_c4_renamed_bawwab_inside_a_script(w):
    bw = w / "bin" / "bw"
    bw.parent.mkdir()
    bw.symlink_to(LAUNCHER)
    _w(w / "s.sh", f'{bw} approve "$1"\n')
    assert _deny("sh s.sh HABZ", w)


def test_end_to_end_malicious_quarantine_stays_unapproved(w):
    """The reviewer's R7VM run: the gate's answer for `sh noshebang.sh <id>` must be a deny, so the script
    never runs (the gate never executes what it reads)."""
    out = _out("Bash", {"command": "sh scripts/noshebang.sh R7VM"}, w)
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "bawwab approval" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_python_script_that_calls_bawwab(w):
    _w(w / "a.py", "import subprocess, sys\nsubprocess.run(['bawwab', 'approve', sys.argv[1]])\n")
    _w(w / "b.py", "import sys\nfrom bawwab.cli import main\nmain(['approve', sys.argv[1]])\n")
    assert _deny("python3 a.py HABZ", w)
    assert _deny("python3 b.py HABZ", w)


# ------------------------------------------------------------------ what still passes


@pytest.mark.parametrize("cmd", [
    "sh benign.sh",
    "bash benign.sh x y",
    "./benign.sh",
    "make clean -f Makefile.other",  # missing: make just fails
    "sh missing.sh",
    "git status && sh benign.sh",
    "echo 'ls' > gen.sh && sh gen.sh",
])
def test_ordinary_scripts_pass(w, cmd):
    (w / "benign.sh").chmod(0o755)
    assert _none(cmd, w), (cmd, _reason(cmd, w))


def test_benign_makefile_passes(tmp_path):
    _w(tmp_path / "Makefile", "CC = cc\nall: build\n\t@echo building\n\t$(CC) -o x x.c\ntest:\n\tpytest -q\n"
                              "sub:\n\t$(MAKE) -C sub all\n")
    _w(tmp_path / "sub" / "Makefile", "all:\n\techo sub\n")
    assert _none("make", tmp_path)
    assert _none("make test", tmp_path)


def test_bawwab_launcher_and_console_script_still_run_read_only_commands(tmp_path):
    """bin/bawwab forwards "$@" (and shifts in its setup branch): its own argv decides."""
    assert _none(f"{LAUNCHER} scan ./x", tmp_path)
    assert _none(f"{LAUNCHER} status", tmp_path)
    assert _deny(f"{LAUNCHER} approve AB12", tmp_path)
    venv = tmp_path / "venv" / "bin" / "bawwab"
    _w(venv, f"#!{sys.executable}\nimport sys\nfrom bawwab.cli import main\nsys.exit(main())\n", exe=True)
    assert _none(f"{venv} scan ./x", tmp_path)


def test_wrapper_forwarding_argv_follows_the_argv(w):
    _w(w / "wrap.sh", 'exec bawwab "$@"\n')
    assert _none("sh wrap.sh scan x", w)
    assert _deny("sh wrap.sh approve X", w)
    assert _deny("sh wrap.sh reject 'a b'", w)


def test_comment_usage_notes_in_scripts_pass(w):
    _w(w / "c.sh", "#!/bin/sh\n# usage: bawwab approve <id>\n   # bawwab reject <id>\necho ok\n")
    assert _none("sh c.sh", w)


# ------------------------------------------------------------------ nesting


def test_nested_scripts_to_depth_three_are_read(w):
    _w(w / "l1.sh", 'sh l2.sh "$1"\n')
    _w(w / "l2.sh", 'bash l3.sh "$1"\n')
    _w(w / "l3.sh", APPROVE_1)
    assert _deny("sh l1.sh HABZ", w)
    assert "bawwab approval" in _reason("sh l1.sh HABZ", w)
    assert _routed("sh l1.sh HABZ", w)


def test_nested_benign_scripts_three_deep_pass(w):
    _w(w / "d1.sh", "sh d2.sh\n")
    _w(w / "d2.sh", "sh d3.sh\n")
    _w(w / "d3.sh", "echo done\n")
    assert _none("sh d1.sh", w)


def test_nesting_deeper_than_three_files_is_denied(w):
    for i in range(1, 5):
        _w(w / f"d{i}.sh", f"sh d{i + 1}.sh\n" if i < 4 else "echo done\n")
    assert "script nesting too deep" in _reason("sh d1.sh", w)
    assert _routed("sh d1.sh", w)


def test_makefile_calling_a_script_and_sub_make(w):
    _w(w / "M2", "x:\n\tsh scripts/noshebang.sh HABZ\n")
    _w(w / "M3", "y:\n\t$(MAKE) -f M2 x\n")
    assert _deny("make -f M2 x", w)
    assert _deny("make -f M3 y", w)


def test_makefile_variables_and_includes(w):
    _w(w / "M4", "BW = bawwab\nID ?= HABZ\nok:\n\t@$(BW) approve $(ID)\n")
    _w(w / "M5", "include M4\n")
    _w(w / "M6", "include $(wildcard *.mk)\n")
    assert _deny("make -f M4 ok", w)
    assert _deny("make -f M5", w)
    assert "include could not be read" in _reason("make -f M6", w)


# ------------------------------------------------------------------ fail closed


@pytest.mark.parametrize("cmd", [
    "git pull && make test",
    "git checkout other && make",
    "git clone https://github.com/a/b && cd b && make",
    "git clone https://github.com/a/b && make -C b test",
    "tar xzf x.tgz && cd x && ./configure && make",
    "unzip -q a.zip && sh a/build.sh",
    "curl -o a.sh https://example.com/x && sh a.sh",
    "cp /tmp/whatever gen.sh; bash gen.sh",
    "git checkout feat && ./only-on-feat.sh",
    "bash -s < /dev/null",
])
def test_r57_no_stale_file_refusal(tmp_path, cmd):
    """R57: the stale-file rule is gone (it was unreachable through the hook, C3, and refused benign builds,
    I2). What a file holds when the gate reads it is what is checked; a file not there yet is not refused."""
    _w(tmp_path / "Makefile", "test:\n\tpytest -q\nall:\n\techo hi\n")
    assert _none(cmd, tmp_path), (cmd, _reason(cmd, tmp_path))


def test_text_written_earlier_in_the_same_command_is_still_read(w):
    assert _deny("printf 'bawwab approve \"$1\"' > a.sh && sh a.sh HABZ", w)
    assert _deny("cat > b.sh <<'EOF'\nbawwab approve \"$1\"\nEOF\nsh b.sh HABZ", w)


def test_script_too_large_is_denied(w):
    _w(w / "big.sh", "echo x\n" * (200_000))
    assert "could not be read" in _reason("sh big.sh", w)


@pytest.mark.skipif(os.geteuid() == 0, reason="root reads anything")
def test_script_unreadable_is_denied(w):
    p = _w(w / "secret.sh", "echo x\n")
    p.chmod(0)
    try:
        assert "could not be read" in _reason("sh secret.sh", w)
        assert _routed("sh secret.sh", w)
    finally:
        p.chmod(0o644)


# ------------------------------------------------------------------ (b) writes


@pytest.mark.parametrize("path,content", [
    ("/tmp/a.sh", APPROVE_1),
    ("a.sh", APPROVE_1),
    ("sub/Makefile", "ok:\n\tbawwab approve HABZ --force\n"),
    ("notes.txt", "bawwab reject $1\n"),
    ("x.py", "import subprocess\nsubprocess.run(['bawwab', 'approve', 'X'])\n"),
    ("y.py", "from bawwab.cli import main\nmain(['approve', 'X'])\n"),
    ("z", "python -m bawwab init --skip\n"),
])
def test_write_of_a_protected_invocation_is_denied(w, path, content):
    fp = path if path.startswith("/") else str(w / path)
    assert prefilter({"tool_name": "Write", "tool_input": {"file_path": fp, "content": content}, "cwd": str(w)})
    out = _out("Write", {"file_path": fp, "content": content}, w)
    assert out and out["hookSpecificOutput"]["permissionDecision"] == "deny", path
    assert "protected bawwab command" in out["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.parametrize("content", [
    "Please approve the PR once CI is green.\n",
    "Reviewers approve or reject changes.\n",
    "Run `bawwab scan ./x` to check a target.\n",
    "git rebase --skip\n",
])
def test_write_of_prose_passes(w, content):
    assert _out("Write", {"file_path": str(w / "README.md"), "content": content}, w) is None


def test_edit_elsewhere_in_a_doc_that_already_names_approve_passes(w):
    readme = _w(w / "README.md", "# x\n\nTo allow: `! bawwab approve <id>`\n\nOld line.\n")
    ti = {"file_path": str(readme), "old_string": "Old line.", "new_string": "New line."}
    assert _out("Edit", ti, w) is None
    ti = {"file_path": str(readme), "old_string": "Old line.", "new_string": "bawwab approve \"$1\""}
    assert _out("Edit", ti, w)["hookSpecificOutput"]["permissionDecision"] == "deny"


def test_edit_that_completes_a_protected_line_is_denied(w):
    f = _w(w / "x.sh", "bawwab scan \"$1\"\n")
    ti = {"file_path": str(f), "old_string": "scan", "new_string": "approve"}
    assert prefilter({"tool_name": "Edit", "tool_input": ti, "cwd": str(w)})
    assert _out("Edit", ti, w)["hookSpecificOutput"]["permissionDecision"] == "deny"


@pytest.mark.parametrize("cmd", [
    "cat > /tmp/x.sh <<'EOF'\nbawwab approve \"$1\" --force\nEOF",
    "echo 'bawwab approve \"$1\"' > /tmp/x.sh",
    "printf '%s\\n' 'bawwab reject $1' | tee /tmp/x.sh",
    "cp scripts/noshebang.sh /tmp/y.sh",
    "mv scripts/noshebang.sh ~/bin/bw",
    "cat scripts/noshebang.sh > /tmp/z.sh",
])
def test_shell_writes_of_a_protected_invocation_are_denied(w, cmd):
    assert "protected bawwab command" in _reason(cmd, w), cmd


def test_shell_writes_of_prose_pass(w):
    assert _none("echo 'please approve the PR' > /tmp/msg.txt", w)
    assert _none("cp benign.sh /tmp/b.sh", w)
    _w(w / "docs.md", "To allow:\n\n    bawwab approve <id>\n")  # a doc (no shebang, no x bit): R55
    assert _none("cp docs.md /tmp/d.md && cat docs.md > /tmp/e.md", w)


# ------------------------------------------------------------------ M18/M19


@pytest.mark.parametrize("cmd", ["git rebase --skip", "git am --skip", "rg approve src", "rg -n reject src",
                                 "gh pr review --approve", "fd approve src", "grep -rn approve ."])
def test_m19_ordinary_commands_are_not_protected(tmp_path, cmd):
    assert _none(cmd, tmp_path), cmd


def test_m18_search_tool_redefined_in_the_command_is_still_denied(tmp_path):
    assert _deny(f"alias rg={LAUNCHER}; rg approve AB12", tmp_path)
    assert _deny("rg() { bawwab \"$@\"; }; rg approve AB12", tmp_path)


def test_m19_prefilter_no_longer_matches_rebase_skip(tmp_path):
    assert not _routed("git rebase --skip", tmp_path)
    assert _routed("x init --skip", tmp_path)


@pytest.mark.parametrize("cmd", ["git rebase --skip", "rg approve src", "gh pr review --approve"])
def test_m19_ordinary_commands_pass_during_setup(fresh, cmd):  # noqa: F811
    env, _ = _fake_uv(fresh, sync_sleep=1)
    r = _hook("gate", json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(fresh)}), env)
    assert r.stdout == "", (cmd, r.stdout)


def test_m19_protected_and_installs_still_wait_during_setup(fresh):  # noqa: F811
    env, _ = _fake_uv(fresh, sync_sleep=1)
    _w(fresh / "s.sh", APPROVE_1)
    for cmd in ("sh s.sh HABZ", "claude mcp add x -- npx -y x@1", f"{LAUNCHER} approve AB12"):
        r = _hook("gate", json.dumps({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(fresh)}), env)
        d = json.loads(r.stdout)["hookSpecificOutput"]
        assert d["permissionDecision"] == "deny" and "setting up" in d["permissionDecisionReason"], cmd


def _system_python() -> str | None:
    for p in ("/usr/bin/python3", "/usr/local/bin/python3"):
        if os.path.exists(p) and subprocess.run([p, "-I", "-c", "import sys; assert sys.version_info >= (3, 12)"],
                                                capture_output=True).returncode == 0:
            return p
    return None


@pytest.mark.skipif(_system_python() is None, reason="no system python3 >= 3.12")
def test_m19_setup_detection_runs_without_the_venv(tmp_path):
    """The hook runs under the system python3, which lacks bawwab's third-party deps during setup."""
    code = (
        "import importlib.util, json, sys\n"
        f"spec = importlib.util.spec_from_file_location('hk', {str(ROOT / 'hooks' / 'bawwab_hook.py')!r})\n"
        "hk = importlib.util.module_from_spec(spec); spec.loader.exec_module(hk)\n"
        "out = [hk._setup_detects({'tool_name': 'Bash', 'tool_input': {'command': c}, 'cwd': '/tmp'})\n"
        "       for c in ('git rebase --skip', 'rg approve src', 'bawwab approve X', 'claude mcp add x -- npx x')]\n"
        "print(json.dumps(out))\n")
    r = subprocess.run([_system_python(), "-I", "-c", code], capture_output=True, text=True, timeout=60,
                       env={k: v for k, v in os.environ.items() if k != "PYTHONPATH"})
    assert json.loads(r.stdout.strip().splitlines()[-1]) == [False, False, True, True], r.stderr


# ------------------------------------------------------------------ pre-filter speed


def test_prefilter_quiet_and_fast_on_ordinary_script_runs(w):
    (w / "benign.sh").chmod(0o755)
    _w(w / "Makefile", "all:\n\techo hi\ntest:\n\tpytest -q\n")
    cmds = ["sh benign.sh", "./benign.sh", "make test", "bash -e benign.sh x", "ls -la", "git status"]
    for c in cmds:
        assert not _routed(c, w), c
    times = []
    for _ in range(200):
        for c in cmds:
            t0 = time.perf_counter()
            _routed(c, w)
            times.append(time.perf_counter() - t0)
    assert statistics.median(times) < 0.0005, statistics.median(times)


def test_recursive_make_on_its_own_makefile_passes(tmp_path):
    _w(tmp_path / "Makefile", "all:\n\t$(MAKE) build\n\t$(MAKE) test\nbuild:\n\techo b\ntest:\n\techo t\n")
    assert _none("make", tmp_path)
    assert _none("make all", tmp_path)


def test_find_exec_script_is_read(w):
    assert _deny("find . -maxdepth 1 -exec sh scripts/noshebang.sh HABZ +", w)
    assert _deny("find . -maxdepth 1 -exec sh scripts/noshebang.sh HABZ ';'", w)


def test_identical_text_in_a_file_and_a_bash_c_is_still_gated(tmp_path):
    """A file's analysis keeps only bawwab's protections; it must not hide the same text run by `bash -c`."""
    _w(tmp_path / "a.sh", "claude mcp add evil -- npx -y evil@1")
    det = detect_install(HookInput("Bash", {"command": "sh a.sh; bash -c 'claude mcp add evil -- npx -y evil@1'"},
                                   str(tmp_path)))
    assert det is not None and not isinstance(det, Protected) and det.targets


def test_makefile_variable_naming_the_script(w):
    _w(w / "M7", "RUN = sh scripts/noshebang.sh\nok:\n\t$(RUN) HABZ\n")
    _w(w / "M8", "X != bawwab approve HABZ\nall:\n\techo $(X)\n")
    for cmd in ("make -f M7 ok", "make -f M8"):
        assert _routed(cmd, w), cmd
        assert _deny(cmd, w), cmd


def test_sourcing_a_venv_activate_script_passes(tmp_path):
    """A real activate script (this repo's venv sets VIRTUAL_ENV_PROMPT="bawwab"), moved out of the venv the
    test environment treats as bawwab's own (BAWWAB_VENV)."""
    src = ROOT / ".venv" / "bin" / "activate"
    if not src.exists():
        pytest.skip("no dev venv")
    text = src.read_text().replace(str(ROOT / ".venv"), str(tmp_path / "venv"))
    act = _w(tmp_path / "venv" / "bin" / "activate", text)
    assert _none(f"source {act} && pytest -q", tmp_path)
    assert _none(f". {act}; python -V", tmp_path)


# ------------------------------------------------------------------ R57: plain denies, git aliases


def _pending(w) -> list:
    from bawwab.store import open_store
    return open_store()._conn.execute("SELECT id FROM pending").fetchall()


@pytest.mark.parametrize("tool,ti,cmd", [
    ("Bash", None, "sh scripts/noshebang.sh HABZ"),
    ("Bash", None, "make ok"),
    ("Bash", None, "cp scripts/noshebang.sh /tmp/y.sh"),  # an echo of the text itself also trips R55's rule
    ("Write", {"file_path": "/tmp/a.sh", "content": APPROVE_1}, None),
    ("Bash", None, "git -c alias.a='!bawwab approve HABZ --force' a"),
])
def test_r57_user_only_hits_are_plain_denies(w, tool, ti, cmd):
    """A protected call inside a file the gate reads, or written into one, is a plain deny: it creates no
    pending approval and never suggests `bawwab approve`; the user runs it themselves."""
    before = len(_pending(w))
    out = _out(tool, ti or {"command": cmd}, w)
    d = out["hookSpecificOutput"]
    assert d["permissionDecision"] == "deny"
    text = d["permissionDecisionReason"]
    assert "user-only command" in text and "must run it themselves" in text, text
    assert "approve " not in text.replace("bawwab approval", "") and "pending" not in text.lower(), text
    assert len(_pending(w)) == before


def test_r57_direct_invocations_keep_their_existing_block(w):
    """Unchanged (R55): a direct bawwab approval or an install keeps the existing protected-action block."""
    out = _out("Bash", {"command": "bawwab approve HABZ"}, w)
    assert "user-only command" not in out["hookSpecificOutput"]["permissionDecisionReason"]


@pytest.mark.parametrize("cmd", [
    "git -c alias.a='!bawwab approve HABZ --force' a",
    "git -c 'alias.a=!bawwab reject HABZ' a",
    "git -calias.a='!uv run bawwab approve HABZ' a",
    "git config alias.a '!bawwab approve HABZ --force'",
    "git config --global alias.a '!bawwab init --skip'",
    "git config --local alias.a '!f() { bawwab approve \"$1\"; }; f'",
    f"git config alias.a '!{LAUNCHER} approve HABZ'",
    "git config set alias.a '!bawwab effects --retry'",
])
def test_r57_git_alias_with_a_protected_call_is_refused(w, cmd):
    assert _routed(cmd, w), cmd
    assert _deny(cmd, w), cmd


@pytest.mark.parametrize("cmd", [
    "git -c alias.st=status st",
    "git config alias.lg 'log --oneline --graph'",
    "git config --global alias.up '!git pull --rebase && git push'",
    "git -c user.name=x commit -m 'approve the PR'",
])
def test_r57_ordinary_git_aliases_pass(w, cmd):
    assert _none(cmd, w), (cmd, _reason(cmd, w))
