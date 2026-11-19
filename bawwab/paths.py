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
