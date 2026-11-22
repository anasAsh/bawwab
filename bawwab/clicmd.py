"""How bawwab tells the user (or Claude) to run a bawwab command (Ruling R54). Stdlib only: the hook loads this
file by path, without importing the bawwab package.

A plugin-only install has no `bawwab` on the user's PATH: it ships bin/bawwab, a launcher Claude Code puts on
the Bash tool's PATH, but the user's `!` shell is not documented to have it. So every instruction names, in order:
- a launcher path, shell-quoted, written `~/…` when it is under the home dir. In Claude Code's plugin cache
  (<plugins>/cache/<marketplace>/<plugin>/<version>) that is the stable launcher in the plugin's data dir
  (<plugins>/data/<id>/bin/bawwab), which bawwab rewrites at every session start to run the installed version, so
  a command left in scrollback keeps working after an upgrade removes the old version dir. Any other tree (a dev
  checkout, a local marketplace dir) prints its own launcher. A planted `bawwab` earlier on PATH never changes
  what is printed (R55, M17): PATH is never consulted;
- else (a pure CLI install: no plugin root) `bawwab`.
"""
from __future__ import annotations

import os
import re
import shlex
import stat

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LAUNCHER = os.path.join(ROOT, "bin", "bawwab")
_MAX = 4096  # a launcher bawwab wrote is a few hundred bytes


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


def show_path(p: str) -> str:
    """p shell-quoted, as `~/…` when it is under the home dir (the user's shell expands an unquoted `~/`)."""
    home = os.path.expanduser("~")
    if home and home != "/" and p.startswith(home.rstrip("/") + "/"):
        return "~/" + shlex.quote(p[len(home.rstrip("/")) + 1:])
    return shlex.quote(p)


def exe() -> str:
    launcher = _launcher()
    if launcher is None:
        return "bawwab"
    return show_path(stable_ok(launcher) or launcher)


def cmd(args: str) -> str:
    """The command line for `bawwab <args>`, e.g. cmd("approve AB12")."""
    return f"{exe()} {args}" if args else exe()
