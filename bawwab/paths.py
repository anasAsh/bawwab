from __future__ import annotations

import os
from pathlib import Path


def bawwab_home() -> Path:
    env = os.environ.get("BAWWAB_HOME")
    return Path(env) if env else Path.home() / ".bawwab"


def claude_home() -> Path:
    return Path.home() / ".claude"


def claude_json() -> Path:
    return Path.home() / ".claude.json"


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
