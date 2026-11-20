"""How bawwab tells the user (or Claude) to run a bawwab command (Ruling R54). Stdlib only: the hook loads this
file by path, without importing the bawwab package.

A plugin-only install has no `bawwab` on the user's PATH: it ships bin/bawwab, a launcher Claude Code puts on
the Bash tool's PATH, but the user's `!` shell is not documented to have it. So every instruction names
- the launcher's absolute path, shell-quoted, whenever this code runs from a tree that has one (a plugin, or
  the dev checkout): it works in any shell, and no other `bawwab` on PATH can stand in for it (R55, M17);
- else (a pure CLI install: no plugin root) `bawwab`.
"""
from __future__ import annotations

import os
import shlex

ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))
LAUNCHER = os.path.join(ROOT, "bin", "bawwab")


def exe() -> str:
    launcher = os.path.realpath(LAUNCHER)
    if os.path.isfile(launcher):
        return shlex.quote(launcher)
    return "bawwab"


def cmd(args: str) -> str:
    """The command line for `bawwab <args>`, e.g. cmd("approve AB12")."""
    return f"{exe()} {args}" if args else exe()
