"""Agent adapters: where each coding agent keeps its servers, skills, plugins and hooks.

ADAPTERS are the gated agents (Claude Code: bawwab's hooks block before and after an install, and its quarantine
blocks tool calls). Inventory, the effect check and the hook's fingerprint iterate over them only.
WATCHED are the agents bawwab has no blocking hook in (Cursor, Codex CLI, Claude Desktop, VS Code, v1.1): the
background watcher (bawwab/watch.py) checks them and records holds, which never block anything.
Every adapter has a stdlib-only `<name>_watch.py` table, loaded by path (the hook loads the gated ones).
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Protocol, runtime_checkable

from bawwab.types import Target


@dataclass
class InstalledItem:
    source: str
    label: str
    target: Target
    unpinned: bool
    kind: Literal["mcp", "skill", "plugin"] = "mcp"
    ident: str = ""
    spec: dict = field(default_factory=dict)


CATEGORIES = ("servers", "plugins", "hooks", "exec_settings", "skills", "toggles", "permissions")
# Config that runs commands but has nothing to download and scan: quarantined unless approved.
# Toggles (enabledPlugins, enableAllProjectMcpServers, enabledMcpjsonServers) are accepted when what they
# switch on (`requires`) is accepted.
UNSCANNABLE = ("hooks", "exec_settings", "toggles")
# Permissions (settings `permissions`, as watch.permissions_projection) are accepted unless a change broadens what
# runs without a prompt (bawwab/effects.py _permissions).


def value_hash(value: object) -> str:
    canon = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)
    return hashlib.sha256(canon.encode()).hexdigest()[:24]


@dataclass
class EffectItem:
    """One entry of the semantic state, with what is needed to scan it and to remove it on reject."""

    ident: str
    category: str  # one of CATEGORIES
    value: object  # JSON-able; its hash is the item's content key
    scope: str  # "user" or the project directory it belongs to
    label: str
    target: Target | None = None  # what to scan (None: unscannable)
    file: str | None = None  # JSON file the entry lives in
    keypath: tuple = ()  # keys of the entry inside that file
    path: str | None = None  # a skill dir / command or agent file / plugin install dir
    requires: tuple = ()  # toggles: idents that must be accepted for an enable to be accepted
    # servers: env keys that load code or switch the package index (bawwab/envkeys.py). Such an item is held as
    # unscannable unless the user approved this exact entry at the gate (env_link: its entry hash); then only that hold
    # is waived and the code target is still scanned.
    env_hold: tuple = ()
    env_link: str | None = None

    @property
    def hash(self) -> str:
        return value_hash(self.value)

    def to_dict(self) -> dict:
        t = self.target
        return {
            "ident": self.ident, "category": self.category, "scope": self.scope, "label": self.label,
            "file": self.file, "keypath": list(self.keypath), "path": self.path, "hash": self.hash,
            "requires": list(self.requires),
            "target": None if t is None else {"kind": t.kind, "raw": t.raw, "name": t.name, "version": t.version,
                                               "url": t.url, "path": t.path},
        }


@runtime_checkable
class AgentAdapter(Protocol):
    name: str

    def watched_paths(self, cwd: Path, home: Path) -> list[Path]: ...

    def list_installed(self, cwd: Path) -> list[InstalledItem]: ...

    def semantic_state(self, cwd: Path) -> dict: ...

    def effect_items(self, cwd: Path) -> list[EffectItem]: ...

    def install_items(self, cwd: Path) -> list[EffectItem]: ...

    def remove(self, item: dict) -> tuple[bool, str]: ...


def adapter_for(ident: str) -> AgentAdapter | None:
    return next((a for a in ALL_ADAPTERS if ident.startswith(a.name + ":")), None)


from bawwab.agents.claude_code import ClaudeCodeAdapter  # noqa: E402 - needs InstalledItem/EffectItem above

ADAPTERS: list[AgentAdapter] = [ClaudeCodeAdapter()]

from bawwab.agents.generic import watched_adapters  # noqa: E402

WATCHED: list[AgentAdapter] = watched_adapters()
ALL_ADAPTERS: list[AgentAdapter] = [*ADAPTERS, *WATCHED]
