"""How bawwab tells the user (or Claude) to run a bawwab command (Ruling R54). Stdlib only: the hook loads this
file by path, without importing the bawwab package.

A plugin-only install has no `bawwab` on the user's PATH: it ships bin/bawwab, a launcher Claude Code puts on
the Bash tool's PATH, but the user's `!` shell is not documented to have it. So every instruction names
- `bawwab` when a `bawwab` other than this launcher is on PATH (an installed CLI);
- else the launcher's absolute path, shell-quoted (it works in any shell);
- else (no launcher: a CLI install outside a plugin tree) `bawwab`.
"""
from __future__ import annotations

import os
import shlex
import shutil

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LAUNCHER = os.path.join(ROOT, "bin", "bawwab")


def exe() -> str:
    launcher = os.path.realpath(LAUNCHER)
    found = shutil.which("bawwab")
    if found and os.path.realpath(found) != launcher:
        return "bawwab"
    if os.path.isfile(launcher):
        return shlex.quote(launcher)
    return "bawwab"


def cmd(args: str) -> str:
    """The command line for `bawwab <args>`, e.g. cmd("approve AB12")."""
    return f"{exe()} {args}" if args else exe()
