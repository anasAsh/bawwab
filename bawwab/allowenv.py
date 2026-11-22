"""`bawwab allow-env <repo-dir>`: the user lets commands run in that repo set BAWWAB_HOME to a dir inside it (a
test home for Bawwab's own dev tree), which the gate otherwise refuses ("bawwab environment override").
Stdlib only: the hook loads this file by path.

- Only the user can add a repo: allow-env is a protected subcommand, like approve (gate/detect.py).
- The list lives in ~/.bawwab/allow-env.json, found from HOME, never from BAWWAB_HOME (which is what it allows),
  and shell writes there are protected (R55).
- It never covers a nested `claude`: the gate refuses the relaxation when the command names claude, HOME or
  CLAUDE_CONFIG_DIR, and Bawwab's hooks refuse to run on a BAWWAB_HOME inside an allowed repo (a Claude Code a
  script started with that env gets no tool calls but read-only ones), so a test home can't stand in for the
  user's real state.
"""
from __future__ import annotations

import json
import os

_NAME = "allow-env.json"


def list_path() -> str:
    return os.path.join(os.path.expanduser("~"), ".bawwab", _NAME)


def repos() -> list[str]:
    """The allowed repo dirs (realpaths). Unreadable or malformed: none."""
    try:
        with open(list_path(), encoding="utf-8") as f:
            data = json.load(f)
    except (OSError, ValueError):
        return []
    got = data.get("repos") if isinstance(data, dict) else None
    return [r for r in got if isinstance(r, str) and os.path.isabs(r)] if isinstance(got, list) else []


def inside(p: str, root: str) -> bool:
    try:
        return os.path.commonpath([p, root]) == root
    except ValueError:
        return False


def real_inside(p: str, root: str) -> bool:
    """p (absolute, normalised; it may not exist yet) is inside root, and so is the realpath of its deepest
    existing ancestor (no symlink leads out)."""
    if not inside(p, root):
        return False
    cur = p
    while not os.path.lexists(cur) and os.path.dirname(cur) != cur:
        cur = os.path.dirname(cur)
    return inside(os.path.realpath(cur), root)


def repo_of(p: str) -> str | None:
    """The allowed repo p lies in, if any."""
    return next((r for r in repos() if real_inside(p, r)), None)


def refuse_repo(d: str) -> str | None:
    """Why d can't be allowed, or None. Not the home dir, `/`, or any dir holding Claude's config or Bawwab's
    state (a "test home" there could be the real one)."""
    if not os.path.isdir(d):
        return f"{d} is not a directory"
    home = os.path.realpath(os.path.expanduser("~"))
    state = os.environ.get("XDG_STATE_HOME") or os.path.join(home, ".local", "state")
    config = [os.path.join(home, ".claude"), os.path.join(home, ".bawwab"),
              os.path.join(os.path.realpath(state), "bawwab")]
    if any(inside(s, d) for s in [home, *config]) or any(inside(d, s) for s in config):
        return f"{d} is, or holds, Claude's config or Bawwab's state"
    return None


def _save(rs: list[str]) -> None:
    p = list_path()
    os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
    tmp = f"{p}.{os.getpid()}.tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump({"repos": rs}, f, indent=2)
    os.chmod(tmp, 0o600)
    os.replace(tmp, p)


def add(d: str) -> str:
    d = os.path.realpath(d)
    why = refuse_repo(d)
    if why:
        raise ValueError(why)
    rs = repos()
    if d not in rs:
        _save(rs + [d])
    return d


def remove(d: str) -> bool:
    d = os.path.realpath(d)
    rs = repos()
    if d not in rs:
        return False
    _save([r for r in rs if r != d])
    return True


def test_home() -> str | None:
    """This process runs with a BAWWAB_HOME inside an allowed repo: the allowed repo, else None. Bawwab's hooks
    refuse to enforce from such a home (a nested Claude Code started with it)."""
    bh = os.environ.get("BAWWAB_HOME")
    if not bh:
        return None
    p = os.path.normpath(os.path.abspath(bh))
    return repo_of(p)
