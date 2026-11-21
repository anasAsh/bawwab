from __future__ import annotations

import os
from pathlib import Path


def bawwab_home() -> Path:
    env = os.environ.get("BAWWAB_HOME")
    return Path(env) if env else Path.home() / ".bawwab"


def claude_home() -> Path:
    """The default Claude Code config dir, ~/.claude (claude_config_dirs adds $CLAUDE_CONFIG_DIR)."""
    return Path.home() / ".claude"


def claude_json() -> Path:
    """The default user config file, ~/.claude.json (claude_json_files adds $CLAUDE_CONFIG_DIR/.claude.json)."""
    return Path.home() / ".claude.json"


# The one resolver for Claude Code's user config locations (CLAUDE_CONFIG_DIR) is the stdlib watch table, which the
# hook's fingerprint loads by path, so the gate, the adapter and the fingerprint agree. It is loaded by path here
# too: importing the bawwab.agents package would pull in third-party deps, and the hook runs bawwab.gate.detect
# (which imports this module) without them during setup (M19).
_watch_mod = None


def _watch():
    global _watch_mod
    if _watch_mod is None:
        import sys

        m = sys.modules.get("bawwab.agents.claude_code_watch")
        if m is None:
            import importlib.util

            spec = importlib.util.spec_from_file_location(
                "_bawwab_paths_cc_watch", Path(__file__).resolve().parent / "agents" / "claude_code_watch.py")
            m = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(m)
        _watch_mod = m
    return _watch_mod


def claude_config_dirs() -> list[Path]:
    """~/.claude, then $CLAUDE_CONFIG_DIR when set: the variable adds a dir, it never removes ~/.claude."""
    return [Path(d) for d in _watch().config_dirs(str(Path.home()))]


def claude_json_files() -> list[Path]:
    """~/.claude.json, then $CLAUDE_CONFIG_DIR/.claude.json when the variable is set."""
    return [Path(f) for f in _watch().user_config_files(str(Path.home()))]


def claude_config_dir_label(d: Path) -> str:
    """How a config dir is named in idents and messages: "" for ~/.claude (idents unchanged), else "[<dir>]"."""
    return "" if os.path.normpath(str(d)) == os.path.normpath(str(claude_home())) else f"[{d}]"


# BAWWAB_CHILD short-circuits every hook, so a bare value (e.g. from settings `env`) must not count: only
# the per-install random token, stored 0600 in bawwab home and set by bawwab on the children it spawns.
# hooks/fingerprint.py reads the same file (stdlib, no bawwab import).
def _child_token_path() -> Path:
    return bawwab_home() / "child.token"


def child_token() -> str:
    """The per-install token (created on first use)."""
    import secrets

    p = _child_token_path()
    try:
        tok = p.read_text().strip()
        if tok:
            return tok
    except OSError:
        pass
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tok = secrets.token_hex(16)
    try:
        fd = os.open(p, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(tok)
    except FileExistsError:
        return p.read_text().strip()
    return tok


def child_env(env: dict | None = None) -> dict:
    """A copy of env (default os.environ) marked as a bawwab child."""
    out = dict(os.environ if env is None else env)
    out["BAWWAB_CHILD"] = child_token()
    return out


def is_bawwab_child() -> bool:
    import hmac

    v = os.environ.get("BAWWAB_CHILD", "")
    if not v or v == "0":
        return False
    try:
        tok = _child_token_path().read_text().strip()
    except OSError:
        return False
    return bool(tok) and hmac.compare_digest(v, tok)
