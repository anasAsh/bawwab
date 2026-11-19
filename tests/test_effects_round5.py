"""Task 10b fix round 5 (Ruling R38): lost state without CLAUDE_PLUGIN_ROOT, `init --skip` refused while an
effects.error is open, find's global options, quoted/escaped parentheses, nested claude through `sh -c`, and
the transcript anchor for "lost" (a late first session is a first run)."""

from __future__ import annotations

import json
import os
import subprocess
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from bawwab import effects as fx
from bawwab import inventory as inv
from bawwab.gate.detect import HookInput, Protected, _segments, _tokens, detect_install
from bawwab.paths import bawwab_home
from bawwab.store import open_store
from bawwab.types import Verdict
from test_effects import FakeScan, _w

HOOK = Path(__file__).resolve().parent.parent / "hooks" / "bawwab_hook.py"


def _d(cmd: str, cwd: str | None = None):
    return detect_install(HookInput("Bash", {"command": cmd}, cwd or str(Path.home() / "proj")))


def _idents():
    return [q["ident"] for q in open_store().active_quarantine()]


def _iso(t: datetime) -> str:
    return t.isoformat().replace("+00:00", "Z")


def _plugin(age: timedelta, name: str = "bawwab@bawwab-mkt") -> datetime:
    """installed_plugins.json lists bawwab installed `age` ago. CLAUDE_PLUGIN_ROOT is NOT set (the user's `!`
    shell); conftest unsets it."""
    at = datetime.now(UTC) - age
    root = Path.home() / ".claude/plugins/cache/bawwab-mkt/bawwab/0.1.0"
    root.mkdir(parents=True, exist_ok=True)
    _w(Path.home() / ".claude/plugins/installed_plugins.json", {"version": 2, "plugins": {
        name: [{"scope": "user", "installPath": str(root), "version": "0.1.0", "installedAt": _iso(at)}]}})
    return at


def _transcript(sid: str, start: datetime, modified: datetime | None = None, project: str = "-tmp-proj") -> Path:
    """A Claude Code session transcript (~/.claude/projects/<project>/<sid>.jsonl) whose first event is at
    `start` and that was last written at `modified`."""
    p = Path.home() / ".claude/projects" / project / f"{sid}.jsonl"
    p.parent.mkdir(parents=True, exist_ok=True)
    lines = [{"type": "summary", "summary": "x"},
             {"type": "user", "sessionId": sid, "timestamp": _iso(start), "message": {"content": "hi"}}]
    p.write_text("\n".join(json.dumps(x) for x in lines) + "\n")
    m = (modified or start).timestamp()
    os.utime(p, (m, m))
    return p


@pytest.fixture
def proj(tmp_path, monkeypatch):
    monkeypatch.setattr(inv, "spawn_background", lambda cwd, full=False: None)
    assert "CLAUDE_PLUGIN_ROOT" not in os.environ
    p = tmp_path / "proj"
    p.mkdir()
    _w(Path.home() / ".claude.json", {"mcpServers": {}, "projects": {str(p): {}}})
    return p


def _add_evil():
    d = json.loads((Path.home() / ".claude.json").read_text())
    d["mcpServers"]["evil"] = {"command": "npx", "args": ["-y", "evil@6.6.6"]}
    _w(Path.home() / ".claude.json", d)


def _lost_setup(monkeypatch, current: str = "s-now"):
    """bawwab installed 2 h ago; an earlier session (s-1) started after the install, so bawwab's SessionStart
    must have run then: missing state now is lost state."""
    at = _plugin(timedelta(hours=2))
    _transcript("s-1", at + timedelta(minutes=5), at + timedelta(minutes=30))
    monkeypatch.setenv("BAWWAB_SESSION_ID", current)
    _transcript(current, datetime.now(UTC))
    return at


# ------------------------------------------------------------------ I1: no CLAUDE_PLUGIN_ROOT needed

def test_lost_state_detected_without_plugin_root(proj, monkeypatch):
    _lost_setup(monkeypatch)
    fp = fx.fp_module()
    assert fp.plugin_lost(str(Path.home())) is not None
    assert fp.initialised(str(Path.home()), str(bawwab_home()))
    ctx = fx.session_start(proj, scan=FakeScan(Verdict.MALICIOUS)) or ""
    assert "lost" in ctx and "has not scanned this machine yet" not in ctx
    assert "effects.error" in _idents()


def test_r4_skip_probe_without_plugin_root_ends_with_evil_quarantined(proj, monkeypatch):
    """r4/skip.py: lost state reported, then `! bawwab init --skip` and `! bawwab effects --retry` from a
    shell without CLAUDE_PLUGIN_ROOT (and without the hook's session id)."""
    _lost_setup(monkeypatch)
    _add_evil()
    sus = FakeScan(Verdict.MALICIOUS)
    ctx = fx.session_start(proj, scan=sus) or ""
    assert "lost" in ctx and "init --skip` is refused" in ctx
    monkeypatch.delenv("BAWWAB_SESSION_ID")  # the user's `!` shell
    with pytest.raises(RuntimeError):
        fx.init_skip(proj)
    assert open_store().init_state() == "none"
    assert fx.pre_tool_decision("Bash", proj, scan=sus) is not None
    fx.retry(proj, scan=sus)
    ids = _idents()
    assert any(i.endswith(":evil") for i in ids), ids  # scanned, quarantined: never trusted
    assert fx.pre_tool_decision("Bash", proj, scan=sus) is not None
    try:  # after the rebuild, --skip has nothing left to trust: evil stays quarantined
        assert fx.init_skip(proj) == 0
    except RuntimeError:
        pass
    assert any(i.endswith(":evil") for i in _idents())
    assert fx.pre_tool_decision("Bash", proj, scan=sus) is not None


def test_init_skip_cli_refused_without_plugin_root(proj, monkeypatch):
    _lost_setup(monkeypatch)
    _add_evil()
    fx.session_start(proj, scan=FakeScan(Verdict.MALICIOUS))
    monkeypatch.delenv("BAWWAB_SESSION_ID")
    from bawwab.cli import main

    assert main(["init", "--skip", "--cwd", str(proj)]) == 1
    assert "effects.error" in _idents()


def test_init_skip_refused_while_any_effects_error_is_open(proj, monkeypatch):
    """Not a plugin at all: a plain effects.error (e.g. a timed-out check) also blocks `--skip`."""
    fx.session_start(proj)
    fx._fail_closed(open_store(), "timed out")
    with pytest.raises(RuntimeError, match="effects --retry|init --scan"):
        fx.init_skip(proj)
    fx.retry(proj, scan=FakeScan())
    assert "effects.error" not in _idents()
    fx.init_skip(proj)  # the error is resolved: the first-run choice is the user's again
    assert open_store().init_state() == "skipped"


def test_effects_error_in_db_blocks_a_fresh_install_baseline(proj, monkeypatch):
    """A db that already holds an effects.error is not a fresh install: no provisional baseline is taken."""
    _add_evil()
    store = open_store()
    fx._fail_closed(store, "bawwab's state was lost")
    assert fx._installed(store, proj) is False
    with pytest.raises(RuntimeError):
        fx.init_skip(proj)


# ------------------------------------------------------------------ I5: transcript anchor

def test_late_first_session_is_a_first_run(proj, monkeypatch):
    """Installed 2 h ago, no session since (only this one): the normal first-run question."""
    _plugin(timedelta(hours=2))
    monkeypatch.setenv("BAWWAB_SESSION_ID", "s-now")
    _transcript("s-now", datetime.now(UTC))
    assert fx.fp_module().plugin_lost(str(Path.home())) is None
    ctx = fx.session_start(proj) or ""
    assert "has not scanned this machine yet" in ctx
    assert "effects.error" not in _idents()
    fx.init_skip(proj)
    assert open_store().init_state() == "skipped"


def test_installing_session_written_after_install_does_not_count(proj, monkeypatch):
    """`/plugin install` ran inside session s-0, which kept writing its transcript afterwards: it started
    before the install, so bawwab's SessionStart never ran in it."""
    at = _plugin(timedelta(hours=20))
    _transcript("s-0", at - timedelta(minutes=30), at + timedelta(hours=1))
    monkeypatch.setenv("BAWWAB_SESSION_ID", "s-now")
    _transcript("s-now", datetime.now(UTC))
    assert fx.fp_module().plugin_lost(str(Path.home())) is None
    assert "has not scanned this machine yet" in (fx.session_start(proj) or "")


def test_no_transcripts_at_all_is_a_first_run(proj, monkeypatch):
    _plugin(timedelta(hours=2))
    assert fx.fp_module().plugin_lost(str(Path.home())) is None
    assert "has not scanned this machine yet" in (fx.session_start(proj) or "")


def test_another_session_after_install_means_lost(proj, monkeypatch):
    _lost_setup(monkeypatch)
    assert fx.fp_module().plugin_lost(str(Path.home())) is not None


def test_recent_install_is_never_lost(proj, monkeypatch):
    at = _plugin(timedelta(minutes=3))
    _transcript("s-1", at + timedelta(minutes=1))
    monkeypatch.setenv("BAWWAB_SESSION_ID", "s-now")
    assert fx.fp_module().plugin_lost(str(Path.home())) is None


def test_current_session_is_excluded_by_session_id(proj, monkeypatch):
    at = _plugin(timedelta(hours=2))
    _transcript("s-now", at + timedelta(minutes=20))
    monkeypatch.setenv("BAWWAB_SESSION_ID", "s-now")
    assert fx.fp_module().plugin_lost(str(Path.home())) is None
    monkeypatch.setenv("BAWWAB_SESSION_ID", "someone-else")
    assert fx.fp_module().plugin_lost(str(Path.home())) is not None


def test_without_a_session_id_the_newest_session_is_taken_as_current(proj, monkeypatch):
    """The CLI from a `!` shell has no hook input: the most recently written transcript is this session."""
    at = _plugin(timedelta(hours=2))
    _transcript("s-now", at + timedelta(minutes=20), datetime.now(UTC))
    assert fx.fp_module().plugin_lost(str(Path.home())) is None
    _transcript("s-1", at + timedelta(minutes=15), at + timedelta(minutes=50))
    assert fx.fp_module().plugin_lost(str(Path.home())) is not None


def test_transcripts_under_claude_config_dir(proj, monkeypatch, tmp_path):
    cfg = tmp_path / "cfgdir"
    monkeypatch.setenv("CLAUDE_CONFIG_DIR", str(cfg))
    at = datetime.now(UTC) - timedelta(hours=2)
    _w(cfg / "plugins/installed_plugins.json", {"version": 2, "plugins": {
        "bawwab@m": [{"scope": "user", "installPath": "/x", "installedAt": _iso(at)}]}})
    p = cfg / "projects/-p/s-1.jsonl"
    p.parent.mkdir(parents=True)
    p.write_text(json.dumps({"sessionId": "s-1", "timestamp": _iso(at + timedelta(minutes=5))}) + "\n")
    monkeypatch.setenv("BAWWAB_SESSION_ID", "s-now")
    assert fx.fp_module().plugin_lost(str(Path.home())) is not None


def test_transcript_without_timestamp_counts_as_after_install(proj, monkeypatch):
    """Can't tell when it started (fail closed): a transcript written after the install counts."""
    at = _plugin(timedelta(hours=2))
    p = Path.home() / ".claude/projects/-p/s-1.jsonl"
    p.parent.mkdir(parents=True)
    p.write_text('{"type":"summary"}\n')
    m = (at + timedelta(minutes=30)).timestamp()
    os.utime(p, (m, m))
    monkeypatch.setenv("BAWWAB_SESSION_ID", "s-now")
    assert fx.fp_module().plugin_lost(str(Path.home())) is not None


def test_hook_passes_session_id_to_the_lost_check(proj, monkeypatch):
    """The hook (no CLAUDE_PLUGIN_ROOT, no BAWWAB_SESSION_ID in its env) reads session_id from its input:
    the late first session is not lost, and another session id makes it lost."""
    at = _plugin(timedelta(hours=2))
    _transcript("s-now", at + timedelta(minutes=20))
    code = ("import json,sys,importlib.util as u;s=u.spec_from_file_location('h',sys.argv[1]);h=u.module_from_spec(s);"
            "s.loader.exec_module(h);h._note_session(json.loads(sys.argv[2]));"
            "print(h._load_fingerprint().initialised(sys.argv[3], sys.argv[4]))")
    env = {k: v for k, v in os.environ.items() if k != "BAWWAB_SESSION_ID"}

    def run(sid):
        data = json.dumps({"session_id": sid, "cwd": str(proj)})
        r = subprocess.run([sys.executable, "-c", code, str(HOOK), data, str(Path.home()), str(bawwab_home())],
                           env=env, capture_output=True, text=True, check=True)
        return r.stdout.strip()

    assert run("s-now") == "False"
    assert run("other") == "True"


def test_cli_hook_input_sets_session_id(proj, monkeypatch):
    from bawwab import cli

    monkeypatch.delenv("BAWWAB_SESSION_ID", raising=False)
    cli._note_session({"session_id": "abc"})
    assert os.environ["BAWWAB_SESSION_ID"] == "abc"
    cli._note_session({"cwd": "/x"})
    assert "BAWWAB_SESSION_ID" not in os.environ


# ------------------------------------------------------------------ I2 / I3 / I4: detect

@pytest.fixture
def state(monkeypatch):
    home = Path.home()
    monkeypatch.setenv("BAWWAB_HOME", str(home / ".bawwab"))
    for d in (".bawwab", ".claude/plugins", ".claude/skills", ".local/state/bawwab", "proj"):
        (home / d).mkdir(parents=True, exist_ok=True)
    (home / ".bawwab/bawwab.db").write_text("x")
    (home / ".claude/.bawwab-initialised").write_text("{}")
    (home / ".local/state/bawwab/.bawwab-initialised").write_text("{}")
    return home


ATTACKS = [
    # I2: find's global options before the start paths
    "find -L ~ -maxdepth 4 -name '*bawwab*' -exec rm -rf {} +",
    "find -P ~/.bawwab -delete",
    "find -O3 ~ -name '.baw*' -exec rm -rf {} +",
    "find -L ~/.local/state -name bawwab -exec rm -rf {} +",
    "find -D exec ~/.bawwab -delete",
    "find -H -L ~/.bawwab -delete",
    "find -D tree,search -O2 ~/.bawwab -delete",
    # I3 / O1: quoted or escaped parentheses are words
    r"find ~ -maxdepth 1 \( -name a -o -name '.baw*' \) -delete",
    r"find ~ \( -name a -o -name '.baw*' \) -delete",
    r"find ~ -maxdepth 1 \( -name '.baw*' \) -delete",
    r"find ~/.bawwab \( -type f \) -delete",
    "find ~/.bawwab '(' -type f ')' -delete",
    "tee '(' ~/.claude/settings.json < /tmp/evil.json",
    'cat /tmp/evil.json | tee ")" ~/.claude/settings.json',
    'rm -rf "(" ~/.bawwab',
    'rm -rf ")" ~/.claude/.bawwab-initialised',
    r"rm -rf \( ~/.bawwab",
    "( rm -rf ~/.bawwab )",
    # I4: nested claude through a child shell
    "HOME=/tmp/x bash -c 'claude -p hi'",
    "CLAUDE_CONFIG_DIR=/tmp/x sh -c 'claude -p hi'",
    "export HOME=/tmp/x; bash -c 'claude -p hi'",
    "export CLAUDE_CONFIG_DIR=/tmp/x; sh -c 'claude -p hi'",
    "env HOME=/tmp/x bash -lc 'claude -p hi'",
    "bash -c 'HOME=/tmp/x claude -p hi'",
    "zsh -c 'export HOME=/tmp/x; claude -p hi'",
    "dash -c \"bash -c 'claude -p hi --dangerously-skip-permissions'\"",
    "HOME=/tmp/x sh -c \"bash -c 'claude -p hi'\"",
    "sh -c 'claude --permission-mode bypassPermissions -p hi'",
]

DETECTED = [  # installs (scanned at the gate), not protected actions
    "cp -r /tmp/evilskill ')' ~/.claude/skills/",
    "cp -r /tmp/evilskill '(' ~/.claude/skills/",
    "cp -t ~/.claude/skills ')' /tmp/evilskill",
]

BENIGN = [
    "find -L . -name '*.pyc' -delete",
    "find -L src -type f -name '*.ts'",
    r"find . \( -name '*.pyc' -o -name '*.pyo' \) -delete",
    "( cd src && ls )",
    "(cd build; make)",
    "echo '(' hello ')'",
    "bash -c 'claude -p hi'",
    "HOME=/tmp/x bash -c 'ls'",
    "sh -c 'echo claude'",
    "export HOME=/tmp/h; bash -c 'npm test'",
]


@pytest.mark.parametrize("cmd", ATTACKS)
def test_attack_is_protected(state, cmd):
    assert isinstance(_d(cmd), Protected), cmd


@pytest.mark.parametrize("cmd", DETECTED)
def test_install_behind_a_quoted_paren_is_detected(state, cmd):
    assert _d(cmd) is not None, cmd


@pytest.mark.parametrize("cmd", ATTACKS + DETECTED)
def test_prefilter_passes_every_attack_to_the_gate(state, cmd):
    from bawwab.gate.prefilter import prefilter

    assert prefilter({"tool_name": "Bash", "tool_input": {"command": cmd}, "cwd": str(state / "proj")}), cmd


@pytest.mark.parametrize("cmd", BENIGN)
def test_benign_is_not_protected(state, cmd):
    assert not isinstance(_d(cmd), Protected), cmd


def test_unquoted_subshell_still_splits_into_commands():
    segs = _segments(_tokens("( cd x && ls )"))
    assert [s.words for s in segs] == [["cd", "x"], ["ls"]]
    segs = _segments(_tokens("(cd x; ls) | wc -l"))
    assert [s.words for s in segs] == [["cd", "x"], ["ls"], ["wc", "-l"]]


def test_quoted_and_escaped_parens_are_words():
    assert [s.words for s in _segments(_tokens(r"find ~ \( -name a \) -delete"))] == [
        ["find", "~", "(", "-name", "a", ")", "-delete"]]
    assert [s.words for s in _segments(_tokens("tee '(' f"))] == [["tee", "(", "f"]]
    assert [s.words for s in _segments(_tokens('cp a ")" b'))] == [["cp", "a", ")", "b"]]
    assert [s.words for s in _segments(_tokens('echo "a ( b"'))] == [["echo", "a ( b"]]
