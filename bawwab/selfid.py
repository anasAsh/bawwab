"""Recognising bawwab's own installed plugin by the code that is running (R52).

Used by the inventory, the effect check and init only. The gate never uses it: installs and upgrades of
bawwab are scanned like anything else (and come back SUSPICIOUS: bawwab reads Claude's config and hooks every
tool).

An installed plugin is "self" only when all of these hold:
- its installPath is absolute and not itself a symlink;
- either its realpath equals the realpath of the plugin root this code runs from (the parent of this package,
  which must hold hooks/bawwab_hook.py; found via __file__, never from the environment: CLAUDE_PLUGIN_ROOT alone
  proves nothing), or it holds exactly the running code (same_code below: byte-identical runtime files and
  nothing else that could run), so a dev checkout or another copy of the same bawwab never quarantines the
  installed one (user decision 2026-11-20: bawwab never quarantines itself);
- its .claude-plugin/plugin.json names it "bawwab".
The name alone is never enough: a plugin called bawwab with different code is scanned like any other.
Any doubt: not self, so it is scanned (fail closed).
"""
from __future__ import annotations

import json
import os
from pathlib import Path

_HERE = Path(__file__)
SELF_LABEL = "bawwab (running code, not scanned)"
SELF_KEY_PREFIX = "self:running-code:"


def running_root() -> str | None:
    """realpath of the plugin root holding the running code, or None when not run from a plugin tree."""
    try:
        root = os.path.realpath(_HERE.resolve().parent.parent)
    except OSError:
        return None
    if not os.path.isfile(os.path.join(root, "hooks", "bawwab_hook.py")):
        return None
    return root


# The files that make up the running plugin (scripts/build_plugin.py ships these), and inert ones it may carry.
RUNTIME_FILES = (".claude-plugin/plugin.json", "pyproject.toml", "uv.lock")
RUNTIME_DIRS = ("bawwab", "hooks", "bin", "skills", "commands")
INERT_FILES = frozenset({"LICENSE", "NOTICE", "README.md"})
_MAX_CODE_BYTES = 64 * 1024 * 1024


def _code(root: str, strict: bool) -> dict[str, str] | None:
    """{rel: sha256} of root's runtime files. strict (an install): any other file, a link leaving the tree, or
    an unreadable entry makes it None, since anything else in a plugin dir could run. Not strict (the running
    tree, e.g. a dev checkout with tests/ and docs/): only the runtime files are read."""
    import hashlib

    from bawwab.agents.claude_code_watch import is_in_use_marker

    out: dict[str, str] = {}
    total = 0
    real_root = os.path.realpath(root)
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = os.path.relpath(dirpath, root)
        top = "" if rel_dir == "." else rel_dir.split(os.sep, 1)[0]
        dirnames[:] = sorted(d for d in dirnames if d != "__pycache__")
        if not strict and rel_dir == ".":
            dirnames[:] = [d for d in dirnames if d in RUNTIME_DIRS or d in (".claude-plugin", ".in_use")]
        for name in sorted(filenames):
            path = os.path.join(dirpath, name)
            rel = os.path.relpath(path, root).replace(os.sep, "/")
            if name.endswith((".pyc", ".pyo")) or is_in_use_marker(path, root):
                continue
            runtime = rel in RUNTIME_FILES or top in RUNTIME_DIRS
            if not runtime:
                if strict and rel not in INERT_FILES:
                    return None
                continue
            try:
                real = os.path.realpath(path)
                if strict and os.path.commonpath([real, real_root]) != real_root:
                    return None
                with open(path, "rb") as f:
                    data = f.read(_MAX_CODE_BYTES + 1)
            except (OSError, ValueError):
                return None
            total += len(data)
            if total > _MAX_CODE_BYTES:
                return None
            out[rel] = hashlib.sha256(data).hexdigest()
    return out


def same_code(install_path: str, root: str) -> bool:
    """install_path holds exactly the runtime files of the running tree at root, and nothing that could run."""
    mine, theirs = _code(root, strict=False), _code(install_path, strict=True)
    return bool(mine) and mine == theirs


def is_self(install_path: object) -> bool:
    if not isinstance(install_path, str) or not install_path or not os.path.isabs(install_path):
        return False
    try:
        if os.path.islink(install_path) or os.path.islink(install_path.rstrip(os.sep) or os.sep):
            return False
        root = running_root()
        if root is None:
            return False
        here = os.path.realpath(install_path)
        if here != root and not same_code(here, root):
            return False
        with open(os.path.join(here, ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, ValueError, RecursionError):
        return False
    return isinstance(manifest, dict) and manifest.get("name") == "bawwab"
