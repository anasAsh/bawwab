"""The install-like pre-filter, shared by the PreToolUse hook and the gate. Stdlib only.

The hook loads this file by path (without importing the bawwab package) so ordinary tool calls stay fast;
`bawwab.gate.gate` imports it normally. There is exactly one predicate.
"""
from __future__ import annotations

import os
import re
import stat

_NEEDLES = ("claude", "bawwab", ".mcp.json", "BAWWAB_", "disableAllHooks")
_FILE_NEEDLES = (".claude", "bawwab", ".mcp.json")  # ~/.claude.json, .claude/{settings*,bawwab.json,skills,...}
_FILE_TOOLS = ("Write", "Edit", "MultiEdit")
# A shell glob or brace may hide ".claude" from the substring check (cp x ~/.c*/skills/, rm -rf ~/.baw{a..z}ab).
# claude reached through $(…), `…` or $VAR: detected by its subcommand.
_CLAUDE_SUBCMD = re.compile(
    r"\b(?:mcp\s+(?:add|add-json|add-from-claude-desktop)"
    r"|plugins?\s+(?:install|i|enable|disable|uninstall|remove|rm|update|marketplace))\b"
)
# ...and only when a path could reach a hidden dir (~, $HOME, a ".x" component) or names an install dir.
_GLOB_HIDDEN = re.compile(r"~|\$HOME|\$\{HOME\}|(?:^|[\s/=])\.[^\s/.]|skills|commands|agents|plugins|\.mcp\.json")
# mv/rsync/rm of a directory that contains ~/.claude, ~/.claude.json, the bawwab home or its XDG state dir
# (mv ~ /x, rm -rf ~/.local).
_MOVE = re.compile(r"(?:^|[\s;&|(`])(?:mv|rsync|rm|rmdir|unlink|shred|trash|trash-put|srm)\s")
_DOLLAR_QUOTE = re.compile(r"\$(?=['\"])")
_GLOB_COPY = re.compile(r"(?:^|[\s;&|(`])(?:cp|mv|rsync|ln|install|rm|rmdir|unlink|shred)\s")
# find that deletes, runs a command, or whose output goes somewhere (pipe, $(…), `…`, a loop): detect decides.
_FIND = re.compile(r"(?:^|[\s;&|(`])find\s")
_FIND_ACTS = re.compile(r"-delete|-exec|-ok|[|`]|\$\(|\bfor\b")
# A user-only bawwab subcommand in the argv of any command, whatever the command word is called (R55): a renamed
# or copied bawwab (ln -s <launcher> /tmp/bw; /tmp/bw approve AB12) has no "bawwab" in its command line.
_PROTECTED_TAIL = re.compile(r"(?<![\w./-])(?:approve|reject)(?![\w./-])|(?<![\w-])--sk|(?<![\w./-])effects\s[^;&|\n]*--re")
# Path-like words (a slash, not a URL): the pre-filter resolves these to spot a bawwab executable under any name.
_PATH_WORD = re.compile(r"(?<![\w:/.~$-])(?:~|\.{1,2}|\$HOME|\$\{HOME\})?/[^\s;&|()<>`'\"]*|(?<![\w/])[\w.-]+/[^\s;&|()<>`'\"]*")
_MAX_PATH_WORDS = 32
_HEAD = 8192
# What a bawwab executable contains: the uv/pip console script (`from bawwab.cli import main`), the plugin's
# bin/bawwab launcher (runs hooks/bawwab_hook.py, then `uv run ... bawwab "$@"`), or a wrapper that execs one.
_BAWWAB_BODY = re.compile(
    rb"bawwab\.cli\b|bawwab_hook\b|(?:from|import)[ \t]+bawwab\b|-m[ \t]+bawwab\b|/bin/bawwab\b"
    rb"|\bbawwab[\"']?[ \t]+[\"']?\$[@*1]"
)


def bawwab_exe_file(path: str, exec_only: bool = False) -> bool:
    """`path` (any name, symlinks followed) is a bawwab executable: its real file is called bawwab, or its
    first bytes run bawwab (console script, launcher, or a script that execs one). Never runs anything.
    exec_only: only read files with an execute bit (the pre-filter's cheap form)."""
    try:
        st = os.stat(path)  # one call, symlinks followed: most words are not executable files
        if not stat.S_ISREG(st.st_mode) or (exec_only and not st.st_mode & 0o111):
            return False
        real = os.path.realpath(path)
        if os.path.basename(real) in ("bawwab", "bawwab.cli"):
            return True
        with open(real, "rb") as fh:
            head = fh.read(_HEAD)
    except (OSError, ValueError):
        return False
    return _BAWWAB_BODY.search(head) is not None


def _unquote(cmd: str) -> str:
    """bash drops quotes and backslashes, and `$'…'` / `$"…"` quote too (cl$'a'ude is claude)."""
    return _DOLLAR_QUOTE.sub("", cmd).replace('"', "").replace("'", "").replace("\\", "")


def _path_words_bawwab(s: str, cwd: str) -> bool:
    """A path-like word of the command (at most _MAX_PATH_WORDS) is a bawwab executable, under any name
    (R55: /tmp/bw init, a copy of the launcher). Only in `prefilter` itself: the raw backstop calls
    bash_install_like per piece, and detection resolves the words it runs."""
    if "/" not in s:
        return False
    user = os.path.expanduser("~")
    for n, m in enumerate(_PATH_WORD.finditer(s)):
        if n >= _MAX_PATH_WORDS:
            return True  # too many to check cheaply: let detection decide
        t = m.group(0).replace("${HOME}", user).replace("$HOME", user)
        if "$" in t or "://" in t:
            continue
        t = os.path.expanduser(t)
        if bawwab_exe_file(t if os.path.isabs(t) else os.path.join(cwd or "/", t), exec_only=True):
            return True
    return False


def _bawwab_home() -> str:
    return os.path.normpath(os.environ.get("BAWWAB_HOME") or os.path.join(os.path.expanduser("~"), ".bawwab"))


def _under(p: str, root: str) -> bool:
    return p == root or p.startswith(root.rstrip("/") + "/")


def prefilter(data: dict) -> bool:
    """True when the call might be an install. May over-match; must never miss what detect_install finds."""
    tool = data.get("tool_name")
    ti = data.get("tool_input")
    if not isinstance(ti, dict):
        return False
    cwd = str(data.get("cwd") or "")
    home, extra = context()
    if tool == "Bash":
        cmd = ti.get("command")
        if not isinstance(cmd, str):
            return False
        return bash_install_like(cmd, cwd, home, extra) or _path_words_bawwab(_unquote(cmd), cwd)
    if tool in _FILE_TOOLS:
        fp = ti.get("file_path")
        if not isinstance(fp, str) or not fp:
            return False
        p = os.path.normpath(os.path.join(cwd or "/", fp))
        s = p + "\0" + os.path.realpath(p)
        return any(n in s for n in _FILE_NEEDLES + extra) or _script_text(ti, p)
    return False


def _script_text(ti: dict, p: str) -> bool:
    """R55: the write may create a script that runs bawwab (a shebang file whose new text names bawwab)."""
    parts = [ti.get("content"), ti.get("new_string")]
    edits = ti.get("edits")
    if isinstance(edits, list):
        parts += [e.get("new_string") for e in edits if isinstance(e, dict)]
    text = "".join(x for x in parts if isinstance(x, str))
    if "bawwab" not in text:
        return False
    if text.lstrip().startswith("#!"):
        return True
    try:
        with open(p, "rb") as fh:
            return fh.read(2) == b"#!"
    except OSError:
        return False


def context() -> tuple[str, tuple[str, ...]]:
    """(bawwab home, extra needles); computed once per call (detect's raw backstop reuses it per piece)."""
    home = _bawwab_home()
    return home, ((home, os.path.basename(home) or home) if os.environ.get("BAWWAB_HOME") else ())


def bash_install_like(cmd: str, cwd: str, home: str, extra: tuple[str, ...]) -> bool:
    """The Bash branch of `prefilter`."""
    # bash drops quotes and backslashes, and `$'…'` / `$"…"` quote too (cl$'a'ude is claude)
    s = _unquote(cmd)
    if any(n in s for n in _NEEDLES + extra):
        return True
    if _PROTECTED_TAIL.search(s):
        return True
    if _MOVE.search(s) and _moves_ancestor(s, cwd, home):
        return True
    if _FIND.search(s) and _FIND_ACTS.search(s):
        return True
    if _CLAUDE_SUBCMD.search(s) or (any(c in s for c in "*?[{") and _GLOB_COPY.search(s) and _GLOB_HIDDEN.search(s)):
        return True
    return "/.claude" in cwd or _under(os.path.normpath(cwd or "/"), home)


def _moves_ancestor(s: str, cwd: str, home: str) -> bool:
    user = os.path.expanduser("~")
    state = os.environ.get("XDG_STATE_HOME") or os.path.join(user, ".local", "state")
    roots = (os.path.join(user, ".claude"), os.path.join(user, ".claude.json"), home, os.path.join(state, "bawwab"))
    for tok in s.split():
        t = tok.replace("${HOME}", user).replace("$HOME", user)
        t = os.path.normpath(os.path.join(cwd or "/", os.path.expanduser(t)))
        if any(r == t or r.startswith(t.rstrip("/") + "/") for r in roots):
            return True
    return False
