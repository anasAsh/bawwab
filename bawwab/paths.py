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


# There is no "bawwab child" switch in the environment (removed in 0.1.4): an env value that turns the hooks off
# can be set by anything that writes settings `env`. Bawwab's own `claude -p` children (judge, reviewer) load no
# settings, plugins or hooks of their own (bawwab/scan/judge/backends.py), so they never need one.
def judge_env(env: dict | None = None) -> dict:
    """A copy of env (default os.environ) for bawwab's own `claude -p` children."""
    out = dict(os.environ if env is None else env)
    out.pop("BAWWAB_CHILD", None)  # a leftover from <= 0.1.3; it means nothing now
    return out
