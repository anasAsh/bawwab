"""P4 false alarms: a search for the words `bawwab approve`, and Claude Code's heredoc commit idiom quoting the user's
command, pass; every near miss that could run the text is still refused (gate/detect.py _literal_text_only)."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from bawwab.gate.detect import HookInput, detect_install
from bawwab.gate.gate import run_gate

APPROVAL = "bawwab approval via tool call"


def _det(cmd: str, cwd: Path):
    return detect_install(HookInput("Bash", {"command": cmd}, str(cwd)))


def _refused(cmd: str, cwd: Path) -> bool:
    d = _det(cmd, cwd)
    return d is not None and (APPROVAL in getattr(d, "reason", "") or APPROVAL in getattr(d, "protected", [])
                              or bool(getattr(d, "plain", [])))


@pytest.fixture
def repo(tmp_path):
    """A git repo with only the sample hooks git init leaves (none of them runs)."""
    r = tmp_path / "repo"
    (r / ".git" / "hooks").mkdir(parents=True)
    (r / ".git" / "config").write_text("[core]\n\trepositoryformatversion = 0\n")
    (r / ".git" / "hooks" / "commit-msg.sample").write_text("#!/bin/sh\n")
    (r / "README.md").write_text("Run `! bawwab approve <id>`.\n")
    return r


# ------------------------------------------------------------------ searches


@pytest.mark.parametrize("cmd", [
    "grep -rn 'bawwab approve' README.md",
    'grep -rn "bawwab approve" docs/',
    "grep -rn 'bawwab approve <id>' . | head -20",
    "rg 'bawwab approve' .",
    "rg -n 'bawwab (approve|reject)' skills/ | sort | uniq",
    "git log --oneline --grep='bawwab approve'",
    "git grep -n 'bawwab approve'",
    "egrep -c 'bawwab approve --force' README.md",
])
def test_a_literal_search_for_the_words_passes(cmd, repo):
    assert run_gate(HookInput("Bash", {"command": cmd}, str(repo))) is None, cmd


@pytest.mark.parametrize("cmd", [
    "grep -rn 'bawwab approve ABCD' README.md | sh",                 # piped into a shell
    "grep -h 'bawwab approve ABCD' notes.txt | bash -s",
    "grep 'bawwab approve ABCD' x | xargs -0 echo; bawwab approve ABCD",
    "grep 'x' README.md; bawwab approve ABCD",                       # a second command
    "grep 'x' README.md && bawwab approve ABCD",
    "grep \"$(bawwab approve ABCD)\" README.md",                     # command substitution
    "grep `bawwab approve ABCD` README.md",                          # backquotes
    "grep 'x' \"$(bawwab approve ABCD)\"",
    "eval \"grep 'bawwab approve' README.md; bawwab approve ABCD\"",  # eval
    "eval 'bawwab approve ABCD'",
    "rg --pre 'bawwab approve ABCD' x README.md",                   # rg runs the preprocessor
    "rg --pre='bawwab approve ABCD' x README.md",
    "git grep -O'bawwab approve ABCD' x",                            # git grep opens files with a command
    "git grep --open-files-in-pager='bawwab approve ABCD' x",
    "git -c core.pager='bawwab approve ABCD' log",                  # git -c
    "find . -name 'x' -exec bawwab approve ABCD \\;",              # -exec
    "echo ABCD | xargs bawwab approve",                             # xargs
    "grep bawwab approve README.md",                                 # not quoted
    "GREP_COLOR=1 grep 'x' README.md; bawwab approve ABCD",
    "sh -c \"grep 'bawwab approve' README.md; bawwab approve ABCD\"",
    "grep 'bawwab approve ABCD' README.md > run.sh",                 # a redirect
    "grep 'bawwab approve' README.md\nbawwab approve ABCD",          # a second line
    "rg() { bawwab approve ABCD; }; rg 'bawwab approve' .",           # a redefined search tool
])
def test_near_misses_that_could_run_the_text_stay_refused(cmd, repo):
    assert _refused(cmd, repo), cmd


def test_a_search_tool_that_is_bawwab_stays_refused(repo, monkeypatch, tmp_path):
    """`grep` on PATH that resolves to a bawwab executable is not a search tool."""
    fake = tmp_path / "fakebin"
    fake.mkdir()
    (fake / "grep").write_text("#!/bin/sh\nexec /x/bin/bawwab \"$@\"\n")
    (fake / "grep").chmod(0o755)
    monkeypatch.setenv("PATH", f"{fake}:{os.environ['PATH']}")
    assert _refused("grep approve 'bawwab approve' ABCD", repo)


# ------------------------------------------------------------------ the heredoc commit idiom

IDIOM = "git commit -m \"$(cat <<'EOF'\n{body}\nEOF\n)\""
BODY = ("docs: blocks print the short command\n\nThe user runs:\n  ! bawwab approve <id>\n  bawwab approve <id>\n\n"
        "Co-Authored-By: Claude <noreply@anthropic.com>")


@pytest.mark.parametrize("cmd", [
    IDIOM.format(body=BODY),
    "git add README.md && " + IDIOM.format(body=BODY),
    "git commit -a -m \"$(cat <<'EOF'\nfix(gate): explain bawwab approve <id>\nEOF\n)\"",
    "git commit -m \"$(cat <<-'MSG'\n\tbawwab approve <id> is the user's command (theirs)\n\tMSG\n)\"".replace("user's", "user"),
    "git tag -a v1 -m \"$(cat <<'EOF'\nbawwab reject <id>\nEOF\n)\"",
])
def test_a_commit_message_heredoc_that_is_only_text_passes(cmd, repo):
    assert run_gate(HookInput("Bash", {"command": cmd}, str(repo))) is None, cmd


@pytest.mark.parametrize("cmd", [
    IDIOM.format(body="x") + "; bawwab approve ABCD",                                  # a command after it
    IDIOM.format(body="x") + " && bawwab approve ABCD",
    IDIOM.format(body="x") + " -m \"$(bawwab approve ABCD)\"",                        # another -m that runs
    # the heredoc ends at the first EOF line: the next line runs inside $( )
    "git commit -m \"$(cat <<'EOF'\nx\nEOF\nbawwab approve ABCD\nEOF\n)\"",
    # <<- strips tabs: a tab-indented delimiter ends it early
    "git commit -m \"$(cat <<-'EOF'\nx\n\tEOF\nbawwab approve ABCD\nEOF\n)\"",
    # unquoted delimiter: the body is expanded, $(…) runs
    "git commit -m \"$(cat <<EOF\n$(bawwab approve ABCD)\nEOF\n)\"",
    # the body goes to a shell, not to cat
    "git commit -m \"$(sh <<'EOF'\nbawwab approve ABCD\nEOF\n)\"",
    "git commit -m \"$(cat <<'EOF' | sh\nbawwab approve ABCD\nEOF\n)\"",
    "eval \"$(cat <<'EOF'\nbawwab approve ABCD\nEOF\n)\"",
    # prefix words in front of git (another config or repo)
    "GIT_CONFIG_GLOBAL=/tmp/c git commit -m \"$(cat <<'EOF'\nbawwab approve ABCD\nEOF\n)\"",
    "env GIT_DIR=/tmp/r git commit -m \"$(cat <<'EOF'\nbawwab approve ABCD\nEOF\n)\"",
    # text that some shells' $(…) parsing could read differently
    "git commit -m \"$(cat <<'EOF'\nx)\nbawwab approve ABCD\nEOF\n)\"",
    "git commit -m \"$(cat <<'EOF'\nit's `bawwab approve ABCD`\nEOF\n)\"",
])
def test_heredoc_near_misses_stay_refused(cmd, repo):
    assert _refused(cmd, repo), cmd


@pytest.mark.parametrize("hook", ["commit-msg", "prepare-commit-msg", "applypatch-msg"])
def test_a_commit_with_a_hook_that_reads_the_message_stays_refused(hook, repo):
    """A hook Claude wrote (`sh "$1"`) would run the message text: no relaxation in such a repo."""
    h = repo / ".git" / "hooks" / hook
    h.write_text("#!/bin/sh\nsh \"$1\"\n")
    h.chmod(0o755)
    assert _refused(IDIOM.format(body="bawwab approve ABCD"), repo)


def test_hooks_elsewhere_stay_refused(repo, tmp_path):
    (repo / ".git" / "config").write_text("[core]\n\thooksPath = /tmp/h\n")
    assert _refused(IDIOM.format(body="bawwab approve ABCD"), repo)
    (repo / ".git" / "config").write_text("[include]\n\tpath = /tmp/other\n")
    assert _refused(IDIOM.format(body="bawwab approve ABCD"), repo)
    (repo / ".git" / "config").write_text("")
    (Path.home() / ".gitconfig").parent.mkdir(parents=True, exist_ok=True)
    (Path.home() / ".gitconfig").write_text("[core]\n  hooksPath = ~/.hooks\n")
    assert _refused(IDIOM.format(body="bawwab approve ABCD"), repo)
    (Path.home() / ".gitconfig").unlink()
    assert not _refused(IDIOM.format(body="bawwab approve ABCD"), repo)


def test_a_worktree_reads_hooks_from_the_common_dir(tmp_path):
    main = tmp_path / "main"
    (main / ".git" / "hooks").mkdir(parents=True)
    (main / ".git" / "worktrees" / "wt").mkdir(parents=True)
    (main / ".git" / "worktrees" / "wt" / "commondir").write_text("../..\n")
    wt = tmp_path / "wt"
    wt.mkdir()
    (wt / ".git").write_text(f"gitdir: {main / '.git' / 'worktrees' / 'wt'}\n")
    cmd = IDIOM.format(body="bawwab approve ABCD")
    assert not _refused(cmd, wt)
    (main / ".git" / "hooks" / "commit-msg").write_text("#!/bin/sh\nsh \"$1\"\n")
    assert _refused(cmd, wt)


def test_git_commit_dash_f_with_a_written_file_is_still_a_plain_deny(repo):
    d = _det("printf 'docs\\n\\n! bawwab approve <id>\\n' > /tmp/msg.txt && git commit -F /tmp/msg.txt", repo)
    assert d is not None and d.plain


# ------------------------------------------------------------------ interpreter reads: still refused, with a hint


@pytest.mark.parametrize("cmd", [
    "python3 -c \"import json,os; print(list(json.load(open(os.path.expanduser('~/.claude.json')))['mcpServers']))\"",
    "python3 -c \"import os; print(os.listdir(os.path.expanduser('~/.claude/skills')))\"",
    # the same rule covers a write: Bawwab can't tell a one-liner that reads from one that writes
    "python3 -c \"import json,os; p=os.path.expanduser('~/.claude.json'); open(p,'w').write('{}')\"",
])
def test_interpreter_on_claude_config_stays_refused_and_says_what_passes(cmd, repo):
    d = _det(cmd, repo)
    assert d is not None and "interpreter may write Claude/bawwab config: python3" in d.reason
    assert "use the Read tool or jq instead" in d.reason
    out = run_gate(HookInput("Bash", {"command": cmd}, str(repo)))
    assert out["hookSpecificOutput"]["permissionDecision"] == "deny"
    assert "Read tool or jq" in out["hookSpecificOutput"]["permissionDecisionReason"]


def test_what_the_hint_suggests_passes(repo):
    assert run_gate(HookInput("Bash", {"command": "jq '.mcpServers | keys' ~/.claude.json"}, str(repo))) is None
    assert run_gate(HookInput("Read", {"file_path": str(Path.home() / ".claude.json")}, str(repo))) is None


@pytest.mark.parametrize("tool", ["rg", "grep", "git", "head"])
def test_a_search_tool_planted_in_a_user_bin_dir_stays_refused(tool, repo, monkeypatch, tmp_path):
    """A `rg` (or grep, git, a reader) Claude wrote into a dir on PATH, with no bawwab in it, that runs its
    argument: the quoted pattern would run. Only programs under system dirs count as search tools here."""
    ub = tmp_path / "home-bin"
    ub.mkdir()
    (ub / tool).write_text('#!/bin/sh\neval "$1"\n')
    (ub / tool).chmod(0o755)
    monkeypatch.setenv("PATH", f"{ub}:{os.environ['PATH']}")
    cmd = {"rg": "rg 'bawwab approve ABCD' .", "grep": "grep 'bawwab approve ABCD' README.md",
           "git": "git log --grep='bawwab approve ABCD'", "head": "grep 'bawwab approve ABCD' README.md | head"}[tool]
    assert _refused(cmd, repo), cmd
