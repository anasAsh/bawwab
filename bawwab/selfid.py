"""Recognising bawwab's own installed plugin by the code that is running (R52).

Used by the inventory, the effect check and init only. The gate never uses it: installs and upgrades of
bawwab are scanned like anything else (and come back SUSPICIOUS: bawwab reads Claude's config and hooks every
tool).

An installed plugin is "self" only when all of these hold:
- its installPath is absolute and not itself a symlink;
- its realpath equals the realpath of the plugin root this code runs from: the parent of this package, which
  must hold hooks/bawwab_hook.py (found via __file__, never from the environment: CLAUDE_PLUGIN_ROOT alone
  proves nothing);
- its .claude-plugin/plugin.json names it "bawwab".
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


def is_self(install_path: object) -> bool:
    if not isinstance(install_path, str) or not install_path or not os.path.isabs(install_path):
        return False
    try:
        if os.path.islink(install_path) or os.path.islink(install_path.rstrip(os.sep) or os.sep):
            return False
        root = running_root()
        if root is None or os.path.realpath(install_path) != root:
            return False
        with open(os.path.join(root, ".claude-plugin", "plugin.json"), encoding="utf-8") as f:
            manifest = json.load(f)
    except (OSError, ValueError, RecursionError):
        return False
    return isinstance(manifest, dict) and manifest.get("name") == "bawwab"
