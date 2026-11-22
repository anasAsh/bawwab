"""How bawwab tells the user (or Claude) to run a bawwab command (Ruling R54). Stdlib only: the hook loads this
file by path, without importing the bawwab package.

A plugin-only install has no `bawwab` on the user's PATH: it ships bin/bawwab, a launcher Claude Code puts on
the Bash tool's PATH, but the user's `!` shell is not documented to have it. So every instruction names, in order:
- bare `bawwab`, only when the user ran `bawwab setup --link` and that shim verifies now (linked() below);
- else a launcher path, shell-quoted, written `~/…` when it is under the home dir. In Claude Code's plugin cache
  (<plugins>/cache/<marketplace>/<plugin>/<version>) that is the stable launcher in the plugin's data dir
  (<plugins>/data/<id>/bin/bawwab), which bawwab rewrites at every session start to run the installed version, so
  a command left in scrollback keeps working after an upgrade removes the old version dir. Any other tree (a dev
  checkout, a local marketplace dir) prints its own launcher. A planted `bawwab` earlier on PATH never changes
  what is printed (R55, M17): PATH is consulted only for the opt-in shim, and only a shim whose bytes bawwab
  wrote, in a user bin dir, counts;
- else (a pure CLI install: no plugin root) `bawwab`.
"""
from __future__ import annotations

import os
import re
import shlex
import shutil
import stat

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LAUNCHER = os.path.join(ROOT, "bin", "bawwab")
SHIM_DIRS = ("~/.local/bin", "~/bin")  # where `bawwab setup --link` may write its shim (the first one on PATH)
_MAX = 4096  # a launcher or shim bawwab wrote is a few hundred bytes


def data_dir(root: str | None = None) -> str | None:
    """The data dir Claude Code gives a plugin installed at <plugins>/cache/<marketplace>/<plugin>/<version>:
    <plugins>/data/<plugin@marketplace, [^A-Za-z0-9_-] as ->, derived from the tree's own path (never from the
    environment), and only when bawwab-named. None for any other layout. The dir may not exist yet."""
    ver = os.path.realpath(root or ROOT)
    plugin = os.path.dirname(ver)
    mkt = os.path.dirname(plugin)
    cache = os.path.dirname(mkt)
    if os.path.basename(cache) != "cache" or os.path.basename(os.path.dirname(cache)) != "plugins":
        return None
    pid = re.sub(r"[^A-Za-z0-9_-]", "-", f"{os.path.basename(plugin)}@{os.path.basename(mkt)}")
    if re.fullmatch(r"bawwab(?:[-@_.].*)?", pid) is None:
        return None
    return os.path.join(os.path.dirname(cache), "data", pid)


def stable_path(root: str | None = None) -> str | None:
    d = data_dir(root)
    return os.path.join(d, "bin", "bawwab") if d else None


def stable_text(launcher: str) -> str:
    """The stable launcher's exact bytes for a version's bin/bawwab (absolute)."""
    q = shlex.quote(launcher)
    return ("#!/bin/sh\n"
            "# bawwab's stable launcher: bawwab rewrites it at every session start so that the commands it prints\n"
            "# keep working after a plugin upgrade. It runs the installed version's own launcher. Don't edit it.\n"
            f"t={q}\n"
            "[ -x \"$t\" ] || { echo \"bawwab: the plugin version this launcher points to is gone ($t); start a new "
            "Claude Code session to refresh it\" >&2; exit 1; }\n"
            "exec \"$t\" \"$@\"\n")


_SHIM_HEAD = ("#!/bin/sh\n"
              "# bawwab: written by `bawwab setup --link` (undo: `bawwab setup --unlink`). Runs bawwab's launcher.\n")


def shim_text(target: str) -> str:
    """The exact bytes `bawwab setup --link` writes into a user bin dir: run that launcher (absolute)."""
    return f"{_SHIM_HEAD}exec {shlex.quote(target)} \"$@\"\n"


def is_shim(text: str) -> bool:
    """text is a shim `bawwab setup --link` wrote (for any target): only those are replaced or removed."""
    if not text.startswith(_SHIM_HEAD) or not text.endswith(' "$@"\n'):
        return False
    try:
        words = shlex.split(text[len(_SHIM_HEAD):])
    except ValueError:
        return False
    return len(words) == 3 and words[0] == "exec" and os.path.isabs(words[1]) and \
        text == shim_text(words[1])


def _own_file(p: str) -> bool:
    """A regular file (not a symlink), owned by this user, not writable by group or others."""
    try:
        st = os.lstat(p)
    except OSError:
        return False
    return stat.S_ISREG(st.st_mode) and st.st_uid == os.getuid() and not st.st_mode & 0o022


def _holds(p: str, text: str) -> bool:
    if not _own_file(p):
        return False
    try:
        with open(p, "rb") as f:
            return f.read(_MAX + 1) == text.encode()
    except OSError:
        return False


def _launcher() -> str | None:
    launcher = os.path.realpath(LAUNCHER)
    return launcher if os.path.isfile(launcher) else None


def stable_ok(launcher: str | None = None) -> str | None:
    """The stable launcher's path when it exists and runs exactly this tree's launcher; else None."""
    launcher = launcher or _launcher()
    p = stable_path()
    return p if launcher and p and _holds(p, stable_text(launcher)) else None


def shim_target(launcher: str | None = None) -> str | None:
    """What a shim runs: the stable launcher in a plugin-cache install, else this tree's launcher."""
    launcher = launcher or _launcher()
    if launcher is None:
        return None
    return stable_path() or launcher


def shim_dirs(path: str | None = None) -> list[str]:
    """SHIM_DIRS that are on PATH, in PATH order (absolute, normalised)."""
    entries = _path_entries(path)
    want = {os.path.normpath(os.path.expanduser(d)) for d in SHIM_DIRS}
    return [e for e in dict.fromkeys(entries) if e in want]


def _path_entries(path: str | None = None) -> list[str]:
    raw = os.environ.get("PATH", "") if path is None else path
    return [os.path.normpath(e) if e else "" for e in raw.split(os.pathsep)]


def linked(launcher: str | None = None) -> bool:
    """`bawwab` on this process's PATH is the shim `bawwab setup --link` wrote, unchanged, in a user bin dir
    (SHIM_DIRS), every PATH entry before that dir is absolute, and what the shim runs verifies too. Checked each
    time a command is printed, never cached. It can't see the user's own shell (its PATH, aliases or functions)
    or a change made after this check: docs/threat-model.md 5.7."""
    launcher = launcher or _launcher()
    home = os.path.expanduser("~")
    if launcher is None or not home or home == "/" or not os.path.isabs(home):
        return False
    hit = shutil.which("bawwab")
    if not hit or not os.path.isabs(hit):
        return False
    where = os.path.normpath(os.path.dirname(hit))
    entries = _path_entries()
    if where not in shim_dirs() or not all(os.path.isabs(e) for e in entries[:entries.index(where)]):
        return False
    target = shim_target(launcher)
    if target is None or not _holds(hit, shim_text(target)):
        return False
    return target == launcher or stable_ok(launcher) is not None


def show_path(p: str) -> str:
    """p shell-quoted, as `~/…` when it is under the home dir (the user's shell expands an unquoted `~/`)."""
    home = os.path.expanduser("~")
    if home and home != "/" and p.startswith(home.rstrip("/") + "/"):
        return "~/" + shlex.quote(p[len(home.rstrip("/")) + 1:])
    return shlex.quote(p)


def exe() -> str:
    launcher = _launcher()
    if launcher is None or linked(launcher):
        return "bawwab"
    return show_path(stable_ok(launcher) or launcher)


def cmd(args: str) -> str:
    """The command line for `bawwab <args>`, e.g. cmd("approve AB12")."""
    return f"{exe()} {args}" if args else exe()
