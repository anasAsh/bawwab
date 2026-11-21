"""Adapters for the agents bawwab watches but does not gate (Cursor, Codex CLI, Claude Desktop, VS Code).

Each one is driven by its stdlib-only watch table (bawwab/agents/<name>_watch.py), which declares the config files
(where the MCP servers and hooks live, and how to parse them), the skill dirs and the extension dirs. This module
turns them into EffectItems (the same ones the Claude Code effect check uses) and removes an item on reject.

Server entries keep their secrets out of bawwab: env, header and auth values are replaced by a hash in the
item's value (a change is still a change), so no report, hold or notification ever shows them.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import os
import re
import tomllib
from pathlib import Path

from bawwab.agents import CATEGORIES, EffectItem, InstalledItem
from bawwab.agents.claude_code import (UnreadableConfig, _dump_like, _local, _move_to_quarantine, _server_target,
                                       _skill_dirs, _stamp, _tree_hash)
from bawwab.envkeys import loader_keys
from bawwab.paths import bawwab_home

_SECRET_MAPS = ("env", "headers", "http_headers", "env_http_headers")
_SECRET_KEYS = ("auth", "oauth", "bearer_token")
_UNPINNED = (None, "latest")


def load_table(name: str):
    """The watch table bawwab/agents/<name>_watch.py, loaded by path like the hook does (one module per file)."""
    stem = name.replace("-", "_")
    path = Path(__file__).resolve().parent / f"{stem}_watch.py"
    spec = importlib.util.spec_from_file_location(f"_bawwab_watch_{stem}", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _digest(v: object) -> str:
    raw = v if isinstance(v, str) else json.dumps(v, sort_keys=True, default=str)
    return "sha256:" + hashlib.sha256(raw.encode()).hexdigest()[:16]


def redact(spec: object) -> object:
    """A server entry with its secret values (env, headers, auth) replaced by hashes."""
    if not isinstance(spec, dict):
        return spec
    out = {}
    for k, v in spec.items():
        if k in _SECRET_MAPS and isinstance(v, dict):
            out[k] = {name: _digest(x) for name, x in v.items()}
        elif k in _SECRET_KEYS:
            out[k] = _digest(v)
        else:
            out[k] = v
    return out


def _hook_id(value: object) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:12]


def _pick(data: object, keypath: tuple) -> object:
    for k in keypath:
        if not isinstance(data, dict):
            return None
        data = data.get(k)
    return data


def _scope_ident(scope: str) -> str:
    return "user" if scope == "user" else f"project:{scope}"


def _env_names(spec: dict) -> dict:
    """The server's env (values unused) plus Codex's forwarded env_vars names: both reach the server."""
    env = dict(spec.get("env")) if isinstance(spec.get("env"), dict) else {}
    for v in spec.get("env_vars") if isinstance(spec.get("env_vars"), list) else []:
        n = v.get("name") if isinstance(v, dict) else v
        if isinstance(n, str):
            env.setdefault(n, "")
    return env


class TableAdapter:
    """An AgentAdapter read from a watch table. Never gated: bawwab/watch.py checks it and records holds."""

    gated = False

    def __init__(self, name: str) -> None:
        self.t = load_table(name)
        self.name = self.t.NAME
        self.title = self.t.TITLE

    # --- paths
    def watched_paths(self, cwd: Path | None, home: Path) -> list[Path]:
        c, h = str(cwd or ""), str(home)
        return [Path(p) for p, _ in self.t.json_files(c, h)] + [Path(d) for d in self.t.dirs(c, h)]

    def _load(self, path: str) -> object:
        try:
            raw = Path(path).read_bytes()
        except FileNotFoundError:
            return None
        except OSError as e:
            raise UnreadableConfig(f"{path}: {type(e).__name__}") from e
        try:
            return self.t.load(raw, path)
        except (ValueError, RecursionError) as e:
            raise UnreadableConfig(f"{path}: does not parse") from e

    def _scope(self, scope: str) -> str:
        return f"{self.name}:{scope}"

    # --- items
    def effect_items(self, cwd: Path | None) -> list[EffectItem]:
        """Every server, hook, skill and extension, user scope plus cwd's project (cwd None: user scope only)."""
        c, home = str(cwd or ""), str(Path.home())
        out: dict[str, EffectItem] = {}
        cache: dict[str, object] = {}
        for path, scope, kind, kp in self.t.config_files(c, home):
            if path not in cache:
                cache[path] = self._load(path)
            node = _pick(cache[path], kp)
            if not isinstance(node, dict):
                continue
            items = self._servers(path, scope, kp, node) if kind == "servers" else self._hooks(path, scope, kp, node)
            for it in items:
                out.setdefault(it.ident, it)
        for root, scope in self.t.skill_roots(c, home):
            for d in _skill_dirs(Path(root)):
                ident = f"{self.name}:skill:{_scope_ident(scope)}:{d}"
                out.setdefault(ident, EffectItem(ident, "skills", _tree_hash(d), self._scope(scope),
                                                 f"skill {d.name} ({self.title}: {d})", _local(d), path=str(d)))
        for root, scope in self.t.extension_roots(c, home):
            try:
                exts = sorted(p for p in Path(root).iterdir() if p.is_dir())
            except OSError:
                exts = []
            for d in exts:
                ident = f"{self.name}:extension:{d.name}"
                out.setdefault(ident, EffectItem(ident, "plugins", {"content": _tree_hash(d)}, self._scope(scope),
                                                 f"extension {d.name} ({self.title}: {d})", _local(d), path=str(d)))
        return list(out.values())

    def _servers(self, path: str, scope: str, kp: tuple, node: dict) -> list[EffectItem]:
        out = []
        base = Path(scope) if scope != "user" else Path.home()
        for name, spec in node.items():
            if not isinstance(name, str):
                continue
            if isinstance(spec, dict) and spec.get("enabled") is False:
                continue  # Codex: switched off, nothing runs (switching it on makes it a new item)
            target = None
            if isinstance(spec, dict):
                cwd = spec.get("cwd")
                target = _server_target(spec, Path(cwd) if isinstance(cwd, str) and os.path.isabs(cwd) else base)
            hold = tuple(loader_keys(_env_names(spec))) if isinstance(spec, dict) else ()
            out.append(EffectItem(f"{self.name}:mcp:{_scope_ident(scope)}:{name}", "servers", redact(spec),
                                  self._scope(scope), f"MCP server {name} ({self.title}: {path})", target, path,
                                  (*kp, name), env_hold=hold))
        return out

    def _hooks(self, path: str, scope: str, kp: tuple, node: dict) -> list[EffectItem]:
        events = self.t.HOOK_EVENTS
        out = []
        for event, groups in node.items():
            if events is not None and event not in events:
                continue  # e.g. Codex's [hooks.state]: its own trust records, not hooks
            for g in groups if isinstance(groups, list) else [groups]:
                value = {"event": event, "hook": g}
                cmd = g.get("command") if isinstance(g, dict) else None
                if cmd is None and isinstance(g, dict) and isinstance(g.get("hooks"), list):
                    cmd = "; ".join(str(h.get("command")) for h in g["hooks"] if isinstance(h, dict))
                out.append(EffectItem(f"{self.name}:hook:{_scope_ident(scope)}:{event}:{_hook_id(value)}", "hooks",
                                      value, self._scope(scope), f"{event} hook `{cmd or g}` ({self.title}: {path})",
                                      None, path, (*kp, event)))
        return out

    def install_items(self, cwd: Path | None) -> list[EffectItem]:
        return self.effect_items(cwd)

    def semantic_state(self, cwd: Path | None) -> dict:
        state: dict = {c: {} for c in CATEGORIES}
        for it in self.effect_items(cwd):
            state[it.category][it.ident] = it.value
        return state

    def list_installed(self, cwd: Path | None) -> list[InstalledItem]:
        out = []
        for it in self.effect_items(cwd):
            if it.target is None or it.category not in ("servers", "skills"):
                continue
            t = it.target
            unpinned = it.category == "servers" and t.kind in ("npm", "pypi") and t.version in _UNPINNED
            kind = "mcp" if it.category == "servers" else "skill"
            out.append(InstalledItem(self.title, it.label, t, unpinned, kind, it.ident))
        return out

    # --- reject
    def remove(self, item: dict) -> tuple[bool, str]:
        cat, file, keypath, path = item.get("category"), item.get("file"), item.get("keypath") or [], item.get("path")
        if file and keypath:
            if file.endswith(".toml"):
                if cat != "servers":
                    return False, f"{file}: remove this {cat[:-1]} by hand (bawwab only edits server tables in TOML)"
                return _remove_toml_table(Path(file), list(keypath))
            return _remove_json(Path(file), list(keypath), item)
        if path and cat in ("skills", "plugins"):
            return _move_to_quarantine(Path(path))
        return False, "nothing to remove"


# ------------------------------------------------------------------ editing another agent's config (on reject)

def _backup(file: Path) -> Path:
    import shutil

    backups = bawwab_home() / "backups"
    backups.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = backups / f"{_stamp()}-{file.name}"
    shutil.copy2(file, backup)
    os.chmod(backup, 0o600)
    return backup


def _replace(file: Path, text: str) -> None:
    tmp = file.with_name(f".{file.name}.bawwab-{os.getpid()}.tmp")
    tmp.write_text(text)
    try:
        os.chmod(tmp, os.stat(file).st_mode & 0o777)
    except OSError:
        pass
    os.replace(tmp, file)


def _remove_json(file: Path, keypath: list, item: dict) -> tuple[bool, str]:
    """Remove a server entry (keypath ends at its name) or one hook group (keypath ends at its event; the group
    whose hash is the ident's last part). Plain JSON only: a file with comments is left for the user to edit."""
    try:
        original = file.read_text()
        data = json.loads(original)
    except (OSError, ValueError) as e:
        return False, f"could not read {file} as plain JSON ({type(e).__name__}): remove the entry by hand"
    parent = data
    for k in keypath[:-1]:
        parent = parent.get(k) if isinstance(parent, dict) else None
    last = keypath[-1]
    if not isinstance(parent, dict) or last not in parent:
        return False, f"entry not found in {file}"
    if item.get("category") == "hooks":
        groups = parent[last]
        want = str(item.get("ident", "")).rsplit(":", 1)[-1]
        seq = groups if isinstance(groups, list) else [groups]
        hit = next((g for g in seq if _hook_id({"event": last, "hook": g}) == want), None)
        if hit is None:
            return False, f"hook not found in {file}"
        if isinstance(groups, list):
            groups.remove(hit)
        if not isinstance(groups, list) or not groups:
            del parent[last]
    else:
        del parent[last]
    try:
        backup = _backup(file)
        _replace(file, _dump_like(original, data))
    except OSError as e:
        return False, f"could not write {file}: {type(e).__name__}"
    return True, f"removed it from {file} (backup: {backup})"


_HEADER = re.compile(r"^\s*(\[\[?)\s*(.+?)\s*(\]\]?)\s*(#.*)?$")


def _header_keys(line: str) -> list[str] | None:
    """The dotted key of a TOML table header line ([a.b] or [[a.b]], quoted parts included), read by tomllib."""
    m = _HEADER.match(line.rstrip("\r\n"))
    if not m:
        return None
    try:
        data = tomllib.loads(f"{m.group(1)}{m.group(2)}{m.group(3)}")
    except ValueError:
        return None
    keys = []
    while isinstance(data, (dict, list)):
        if isinstance(data, list):
            data = data[0] if data else None
            continue
        if len(data) != 1:
            break
        k = next(iter(data))
        keys.append(k)
        data = data[k]
    return keys


def _remove_toml_table(file: Path, keypath: list) -> tuple[bool, str]:
    """Remove the [mcp_servers.<name>] table and its sub-tables, line by line, then check with tomllib that exactly
    that entry went away and nothing else changed. Any other layout (an inline table...) is left to the user."""
    try:
        original = file.read_text()
        before = tomllib.loads(original)
    except (OSError, ValueError) as e:
        return False, f"could not read {file} ({type(e).__name__})"
    out, skipping = [], False
    for line in original.splitlines(keepends=True):
        keys = _header_keys(line) if line.lstrip().startswith("[") else None
        if keys is not None:
            skipping = keys[:len(keypath)] == keypath
        if not skipping:
            out.append(line)
    text = "".join(out)
    expected = copy.deepcopy(before)
    parent = _pick(expected, tuple(keypath[:-1]))
    if not isinstance(parent, dict) or keypath[-1] not in parent:
        return False, f"entry not found in {file}"
    del parent[keypath[-1]]
    try:
        after = tomllib.loads(text)
    except ValueError:
        after = None
    if after != expected and isinstance(after, dict) and parent == {} and _pick(after, tuple(keypath[:-1])) is None:
        top = _pick(expected, tuple(keypath[:-2])) if len(keypath) > 2 else expected
        top.pop(keypath[-2], None)  # the parent table only existed through this entry's header
    if after != expected:
        return False, f"{file}: the entry is not a plain [{'.'.join(keypath)}] table: remove it by hand"
    try:
        backup = _backup(file)
        _replace(file, text)
    except OSError as e:
        return False, f"could not write {file}: {type(e).__name__}"
    return True, f"removed it from {file} (backup: {backup})"


def watched_adapters() -> list[TableAdapter]:
    return [TableAdapter(n) for n in ("cursor", "codex", "claude-desktop", "vscode")]


__all__ = ["TableAdapter", "redact", "watched_adapters"]
