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
_FILE_TOOLS = ("Write", "Edit", "MultiEdit", "NotebookEdit")
_PATH_KEY = {"NotebookEdit": "notebook_path"}  # NotebookEdit's input: notebook_path, new_source, cell_id, ...
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
_PROTECTED_TAIL = re.compile(r"(?<![\w./-])(?:approve|reject)(?![\w./-])|(?<![\w./-])init\s[^;&|\n]*--sk"
                             r"|(?<![\w./-])effects\s[^;&|\n]*--re|(?<![\w./-])setup\s[^;&|\n]*--l"
                             r"|(?<![\w./-])allow-env(?![\w./-])")
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
        s = _unquote(cmd)
        return bash_install_like(cmd, cwd, home, extra) or _path_words_bawwab(s, cwd) or _runs_file(s, cwd)
    if tool in _FILE_TOOLS:
        fp = ti.get(_PATH_KEY.get(tool, "file_path"))
        if not isinstance(fp, str) or not fp:
            return False
        p = os.path.normpath(os.path.join(cwd or "/", fp))
        s = p + "\0" + os.path.realpath(p)
        return any(n in s for n in _FILE_NEEDLES + extra) or _write_text(tool, ti, p, cwd)
    return False


def _write_text(tool: str, ti: dict, p: str, cwd: str) -> bool:
    """R55/R56: the write's result may hold a bawwab call (a script that runs bawwab, or a protected bawwab
    invocation in any file): its new text, plus for an edit the file's current text, names bawwab, or has a
    protected subcommand next to a path that is a bawwab executable."""
    parts = [ti.get("content"), ti.get("new_string"), ti.get("new_source")]
    edits = ti.get("edits")
    if isinstance(edits, list):
        parts += [e.get("new_string") for e in edits if isinstance(e, dict)]
    text = "\n".join(x for x in parts if isinstance(x, str))
    if tool != "Write":
        cur = _read(p)
        if cur is None:
            return True
        text += "\n" + cur
    return "bawwab" in text or (_PROTECTED_TAIL.search(text) is not None and _path_words_bawwab(text, cwd))


# ------------------------------------------------------------------ R56: files a command runs

_READ_MAX = 1 << 20  # what detection reads of a file it runs; larger: detection refuses, so route it
_FILE_DEPTH = 3
_MAX_FILES = 64
_SEG_SPLIT = re.compile(r"&&|\|\||[;&|(){}`\n!]")
_PREFIX_WORDS = {"sudo", "doas", "exec", "command", "builtin", "time", "nohup", "env", "nice", "ionice", "setsid",
                 "timeout", "stdbuf", "xargs", "chronic", "unbuffer", "caffeinate", "then", "do", "else", "elif",
                 "if", "while", "until", "-exec", "-execdir", "-ok", "-okdir"}
_SHELL_NAMES = {"sh", "bash", "dash", "zsh", "ksh"}
_RUNNER = re.compile(r"python[0-9.]*|node(js)?|perl|ruby|bun|deno|php")
_MAKEFILES = ("GNUmakefile", "makefile", "Makefile")
_MAKE_INCLUDE = re.compile(r"(?m)^\s*-?s?include\s")
_SUBCMD_WORD = re.compile(r"\b(?:approve|reject|init|effects|setup|allow-env)\b")
# a cheap test before splitting: a runner word, or a path command word at a segment start
_MAY_RUN = re.compile(r"(?<![\w.-])(?:sh|bash|dash|zsh|ksh|make|gmake|source|\.|python[0-9.]*|node|nodejs|perl|ruby|bun"
                      r"|deno|php|MAKE\)|MAKE\})(?![\w.-])"
                      r"|(?:^|[;&|(){}`\n!]|(?<![\w.-])(?:" + "|".join(sorted(_PREFIX_WORDS)) + r")(?![\w.-])|\w=\S*)"
                      r"(?:[ \t@+-]*(?:-\S+|\d\S*)(?=[ \t]))*[ \t@+-]*[^\s;&|(){}`]*/")


_VAR_DEF = re.compile(r"(?m)^[ \t]*(?:(?:export|override)[ \t]+)?([A-Za-z_][\w.-]*)[ \t]*"
                      r"(?::{1,3}|\?|\+|!)?=[ \t]*(.*)$")
_VAR_USE = re.compile(r"\$[({]([A-Za-z_][\w.-]*)[)}]")


def _expand_vars(text: str) -> str:
    """Simple variable definitions expanded (a makefile's `BW = ./x.sh` then `$(BW) approve`)."""
    if "$" not in text:
        return text
    defs = dict(_VAR_DEF.findall(text))
    if not defs:
        return text
    for _ in range(8):
        n = _VAR_USE.sub(lambda m: defs.get(m.group(1), m.group(0)), text)
        if n == text:
            break
        text = n
    return text.replace("$$", "$")


def _read(p: str) -> str | None:
    """A file's text for the pre-filter: "" when missing, None when it can't be read cheaply or is too large."""
    try:
        st = os.stat(p)
    except FileNotFoundError:
        return ""
    except (OSError, ValueError):
        return None
    if not stat.S_ISREG(st.st_mode) or st.st_size > _READ_MAX:
        return None
    try:
        with open(p, "rb") as fh:
            return fh.read(_READ_MAX).decode("utf-8", "replace")
    except OSError:
        return None


def _file_calls(s: str, cwd: str) -> list[str] | None:
    """Files the (unquoted) shell text `s` runs as code: a shell's or `.`/`source`'s file, a script given to
    python/node/..., a path command word, a makefile. Over-matches; None: one can't be named (let detection
    decide)."""
    out: list[str] = []
    piped_cat: list[str] = []
    for seg in _SEG_SPLIT.split(s.replace("$(MAKE)", "make").replace("${MAKE}", "make")):
        words = seg.split()
        if words[:1] == ["cat"]:
            piped_cat = [a for a in words[1:] if not a.startswith("-")]
            continue
        while words and (words[0] in _PREFIX_WORDS or re.fullmatch(r"\w+=\S*|[@+-]+|-\S+|\d\S*", words[0])):
            words = words[1:]
        if not words:
            continue
        w0 = words[0].lstrip("@+-") or words[0]
        exe, args = os.path.basename(w0), words[1:]
        if exe in _SHELL_NAMES or w0 in (".", "source") or _RUNNER.fullmatch(exe):
            if any((a in ("-c", "-e", "-m", "--eval", "-p", "--print") and exe not in _SHELL_NAMES) or
                   (a[:1] == "-" and a[1:2] != "-" and "c" in a[1:] and exe in _SHELL_NAMES) for a in args):
                continue
            if exe in _SHELL_NAMES and "<" in args:  # sh < file
                out += [args[k + 1] for k, a in enumerate(args[:-1]) if a == "<"]
                continue
            if exe in _SHELL_NAMES and piped_cat:  # cat file | sh
                out += piped_cat
            j = 0
            while j < len(args) and args[j][:1] in ("-", "+") and args[j] != "--":
                j += 2 if args[j] in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file") else 1
            j += j < len(args) and args[j] == "--"
            if j < len(args):
                out.append(args[j])
        elif exe in ("make", "gmake"):
            d, files = cwd, []
            for j, a in enumerate(args):
                nxt = args[j + 1] if j + 1 < len(args) else ""
                if a in ("-C", "--directory") or a.startswith(("-C", "--directory=")):
                    d = os.path.join(d, a.split("=", 1)[1] if "=" in a else (a[2:] or nxt))
                elif a in ("-f", "--file", "--makefile") or a.startswith(("-f", "--file=", "--makefile=")):
                    files.append(a.split("=", 1)[1] if "=" in a else (a[2:] or nxt))
            out += [os.path.join(d, f) for f in files] or \
                [next((os.path.join(d, n) for n in _MAKEFILES if os.path.exists(os.path.join(cwd or "/", d, n))),
                      os.path.join(d, "Makefile"))]
        elif "/" in w0:
            out.append(w0)
        if len(out) > _MAX_FILES:
            return None
    return out


def _runs_file(s: str, cwd: str, depth: int = 0, seen: set[str] | None = None) -> bool:
    """R56: the command runs a file (to _FILE_DEPTH deep) that is missing, unreadable, too large, includes
    other makefiles, or whose text could hold a bawwab call: detection must read it. Never runs anything."""
    if not _MAY_RUN.search(s):
        return False
    seen = set() if seen is None else seen
    calls = _file_calls(s, cwd)
    if calls is None:
        return True
    user = os.path.expanduser("~")
    for c in calls:
        if "$" in c or "`" in c:
            continue  # a runtime-computed path: detection can't read it either
        p = os.path.normpath(os.path.join(cwd or "/", os.path.expanduser(c.replace("${HOME}", user)
                                                                         .replace("$HOME", user))))
        if p in seen:
            continue
        seen.add(p)
        if len(seen) > _MAX_FILES or depth >= _FILE_DEPTH:
            return True
        if os.path.isdir(p):
            continue
        text = _read(p)
        if text is None or (not text and not os.path.exists(p)):
            return True  # unreadable, or missing (may be written earlier in the command): detection decides
        if "\0" in text[:8192]:
            continue  # a compiled program
        u = _expand_vars(_unquote(text))
        if "bawwab" in text or _PROTECTED_TAIL.search(u) or _MAKE_INCLUDE.search(text) or \
                (_SUBCMD_WORD.search(u) and _path_words_bawwab(u, cwd)) or _runs_file(u, cwd, depth + 1, seen):
            return True
    return False


def redirected_config_dir() -> str | None:
    """$CLAUDE_CONFIG_DIR, absolute and normalised: a copy of bawwab/agents/claude_code_watch.py's (this file
    imports nothing; tests/test_claude_config_dir.py keeps the two in step)."""
    v = os.environ.get("CLAUDE_CONFIG_DIR")
    return os.path.normpath(os.path.abspath(os.path.expanduser(v))) if v else None


def _config_needles() -> tuple[str, ...]:
    """Words that name a redirected Claude config dir (absolute, its realpath, ~/ and $HOME/ forms, its name):
    a write there is a write to Claude's config. () when CLAUDE_CONFIG_DIR is unset."""
    d = redirected_config_dir()
    if not d:
        return ()
    out = ["CLAUDE_CONFIG_DIR"]
    user = os.path.normpath(os.path.expanduser("~"))
    for p in (d, os.path.realpath(d)):
        out += [p, os.path.basename(p) or p]
        if _under(p, user) and p != user:
            rel = os.path.relpath(p, user)
            out += [f"~/{rel}", f"$HOME/{rel}"]
    return tuple(dict.fromkeys(out))


def context() -> tuple[str, tuple[str, ...]]:
    """(bawwab home, extra needles); computed once per call (detect's raw backstop reuses it per piece)."""
    home = _bawwab_home()
    extra = (home, os.path.basename(home) or home) if os.environ.get("BAWWAB_HOME") else ()
    return home, extra + _config_needles()


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
    cfg = redirected_config_dir()
    return "/.claude" in cwd or _under(os.path.normpath(cwd or "/"), home) or (
        cfg is not None and (_under(os.path.normpath(cwd or "/"), cfg) or _under(os.path.realpath(cwd or "/"), cfg)))


def _moves_ancestor(s: str, cwd: str, home: str) -> bool:
    user = os.path.expanduser("~")
    state = os.environ.get("XDG_STATE_HOME") or os.path.join(user, ".local", "state")
    roots = (os.path.join(user, ".claude"), os.path.join(user, ".claude.json"), home, os.path.join(state, "bawwab"))
    cfg = redirected_config_dir()  # $CLAUDE_CONFIG_DIR adds its dir; ~/.claude stays
    roots += (cfg, os.path.realpath(cfg)) if cfg else ()
    for tok in s.split():
        t = tok.replace("${HOME}", user).replace("$HOME", user)
        t = os.path.normpath(os.path.join(cwd or "/", os.path.expanduser(t)))
        if any(r == t or r.startswith(t.rstrip("/") + "/") for r in roots):
            return True
    return False
