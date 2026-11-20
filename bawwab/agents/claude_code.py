"""Claude Code adapter: ~/.claude.json, settings*.json, .mcp.json, skills/commands/agents, plugins."""
from __future__ import annotations

import dataclasses
import hashlib
import json
import os
import re
import shutil
import time
from pathlib import Path

from bawwab.agents import CATEGORIES, EffectItem, InstalledItem
from bawwab.envkeys import loader_keys, spec_entry_hash
from bawwab.agents import claude_code_watch as watch
from bawwab.fetch.target import target_from_command, target_from_url
from bawwab.gate.detect import _read_json
from bawwab.paths import bawwab_home, claude_home, claude_json
from bawwab.types import Target

NAME = watch.NAME
_P = NAME + ":"
_UNPINNED = (None, "latest")
_MAX_HASH_FILES = 2000
_MAX_HASH_BYTES = 20 * 1024 * 1024
_MAX_DOC_FILES = 500
# Settings keys that run code (or switch hooks off) and so are checked as one item each.
EXEC_KEYS = ("apiKeyHelper", "statusLine", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "env",
             "disableAllHooks")
# Fields of an installed_plugins.json entry that identify what is installed (not timestamps).
_PLUGIN_FIELDS = ("scope", "projectPath", "installPath", "version", "gitCommitSha")


class UnreadableConfig(Exception):
    """A watched JSON file exists but does not parse (mid-write or corrupt): don't treat its items as removed."""


# ------------------------------------------------------------------ inventory (Task 10)

def _mcp_item(source: str, scope_ident: str, name: str, spec: object, cwd: Path) -> InstalledItem | None:
    if not isinstance(spec, dict):
        return None
    t = _server_target(spec, cwd)
    if t is None:
        return None
    unpinned = t.kind in ("npm", "pypi") and t.version in _UNPINNED
    return InstalledItem(source, name, t, unpinned, "mcp", f"{_P}mcp:{scope_ident}:{name}", dict(spec))


def _server_target(spec: dict, cwd: Path) -> Target | None:
    url, cmd, args = spec.get("url"), spec.get("command"), spec.get("args", [])
    if isinstance(url, str) and url:
        return target_from_url(url)
    if isinstance(cmd, str) and isinstance(args, list) and all(isinstance(a, str) for a in args):
        t = target_from_command(cmd, args)
        if t is not None and t.kind == "local":
            script = next((a for a in args if not a.startswith("-")), None)
            if script and not os.path.isabs(script):
                t = dataclasses.replace(t, path=str((cwd / script).parent))
        return t
    return None


def _servers(d: object) -> dict:
    s = d.get("mcpServers") if isinstance(d, dict) else None
    return s if isinstance(s, dict) else {}


def _skill_dirs(base: Path) -> list[Path]:
    try:
        return sorted(p for p in base.iterdir() if p.is_dir() and (p / "SKILL.md").is_file())
    except OSError:
        return []


def _skills(base: Path, scope: str, source: str) -> list[InstalledItem]:
    out: list[InstalledItem] = []
    for d in _skill_dirs(base):
        t = Target("local", str(d), name=str(d), path=str(d))
        out.append(InstalledItem(source, d.name, t, False, "skill", f"{_P}skill:{scope}:{d.name}"))
    return out


def _plugin_entry(entries: object, cwd: Path) -> dict | None:
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict) or not isinstance(e.get("installPath"), str) or not e["installPath"]:
            continue
        pp = e.get("projectPath")
        if e.get("scope") == "project" and isinstance(pp, str) and Path(pp) != cwd:
            continue
        return e
    return None


def _plugins_file() -> Path:
    return claude_home() / "plugins" / "installed_plugins.json"


def _plugins(cwd: Path) -> list[InstalledItem]:
    data = _read_json(_plugins_file())
    plugins = data.get("plugins") if isinstance(data, dict) else None
    out: list[InstalledItem] = []
    if not isinstance(plugins, dict):
        return out
    for spec, entries in plugins.items():
        e = _plugin_entry(entries, cwd)
        if e is not None:
            p = e["installPath"]
            t = Target("local", p, name=p, path=p)
            out.append(InstalledItem("installed_plugins.json", str(spec), t, False, "plugin", f"{_P}plugin:{spec}"))
    return out


# ------------------------------------------------------------------ semantic state (effect check)

def _load(p: Path) -> object:
    """Parsed JSON, None when the file is absent; UnreadableConfig when it exists but does not parse."""
    try:
        text = p.read_text()
    except FileNotFoundError:
        return None
    except OSError as e:
        raise UnreadableConfig(f"{p}: {type(e).__name__}") from e
    try:
        return json.loads(text)
    except (ValueError, RecursionError) as e:
        raise UnreadableConfig(f"{p}: invalid JSON") from e


_SUBTREE_FILES = 1000


def _subtree_files(top: Path, out: list, skipped: list) -> None:
    """Files under top (breadth-first by os.walk order), at most _SUBTREE_FILES; SKIP_DIRS not entered."""
    n = 0
    for dp, dns, fns in os.walk(top):
        keep = []
        for d in sorted(dns):
            full = Path(dp) / d
            if d in watch.SKIP_DIRS:
                skipped.append(full)
            elif os.path.islink(full):
                out.append(full)  # a nested link: its text is hashed, not followed
            else:
                keep.append(d)
        dns[:] = keep
        for fn in sorted(fns):
            if n >= _SUBTREE_FILES:
                skipped.append(Path(dp))
                return
            out.append(Path(dp) / fn)
            n += 1


def _package_files(pkg: Path) -> list[Path]:
    """Files of a referenced file's package (breadth-first, at most watch.PKG_BUDGET)."""
    out: list[Path] = []
    for dp, dns, fns in os.walk(pkg):
        dns.sort()
        for fn in sorted(fns):
            out.append(Path(dp) / fn)
            if len(out) >= watch.PKG_BUDGET:
                return out
    return out


def _tree_hash(root: Path) -> str:
    """Content hash of a directory (or file), resolving a symlinked root. The files that decide what runs
    (ALWAYS_FILES and every file directly in the root) are always hashed in full; each top-level subtree
    contributes at most _SUBTREE_FILES files; SKIP_DIRS (node_modules...) count by their own stat only;
    past the overall caps, files count by stat data. Nested link texts are hashed."""
    h = hashlib.sha256()
    if root.is_symlink():
        try:
            h.update(f"ROOTLINK\0{os.readlink(root)}\n".encode())
        except OSError:
            pass
    if not root.is_dir():
        files, base, always = [root], root.parent, {root}
        skipped: list[Path] = []
    else:
        base = root
        always_l = [root / rel for rel in watch.ALWAYS_FILES if (root / rel).is_file()]
        for ref in watch.entry_refs(str(root)):  # entry points config names, even inside node_modules & co
            always_l.append(Path(ref))
            pkg = watch.package_dir(str(root), ref)
            if pkg:
                always_l += _package_files(Path(pkg))
        files, skipped, subtrees = list(always_l), [], []
        try:
            entries = sorted(root.iterdir(), key=lambda p: p.name)
        except OSError:
            entries = []
        for p in entries:
            if p.is_symlink() and p.is_dir():
                files.append(p)
            elif p.is_dir():
                (skipped if p.name in watch.SKIP_DIRS else subtrees).append(p)
            else:
                files.append(p)
        always = set(files)
        for sub in subtrees:
            _subtree_files(sub, files, skipped)
        files = list(dict.fromkeys(files))
    budget = _MAX_HASH_BYTES
    for i, p in enumerate(files):
        rel = os.path.relpath(p, base)
        try:
            st = os.stat(p)
        except OSError:
            h.update(f"X\0{rel}\n".encode())
            continue
        if p != root and os.path.islink(p):
            try:
                h.update(f"L\0{rel}\0{os.readlink(p)}\n".encode())
            except OSError:
                pass
            if p.is_dir():
                continue
        if p in always or (i < _MAX_HASH_FILES and st.st_size <= budget):
            try:
                data = p.read_bytes()
            except OSError:
                data = b""
            budget -= len(data)
            h.update(f"F\0{rel}\0{len(data)}\n".encode())
            h.update(data)
        else:
            h.update(f"S\0{rel}\0{st.st_size}\0{st.st_mtime_ns}\0{st.st_ctime_ns}\n".encode())
    for d in skipped:
        try:
            st = os.stat(d)
            h.update(f"D\0{os.path.relpath(d, base)}\0{st.st_mtime_ns}\0{st.st_ctime_ns}\n".encode())
        except OSError:
            pass
    return h.hexdigest()


def _doc_files(base: Path) -> list[Path]:
    """Markdown files under a commands/ or agents/ dir (subdirectories are namespaces)."""
    out: list[Path] = []
    for dp, dns, fns in os.walk(base):
        dns[:] = sorted(d for d in dns if not d.startswith("."))
        for fn in sorted(fns):
            if fn.endswith(".md"):
                out.append(Path(dp) / fn)
                if len(out) >= _MAX_DOC_FILES:
                    return out
    return out


def _local(p: Path) -> Target:
    return Target("local", str(p), name=str(p), path=str(p))


def _servers_items(scope_ident: str, scope: str, data: object, file: Path, prefix: tuple, src: str,
                   base: Path) -> list[EffectItem]:
    out = []
    for name, spec in _servers(data).items():
        t = _server_target(spec, base) if isinstance(spec, dict) else None
        # its env loads code (or switches the package index) that scanning the server would not see: held until the
        # user approves it (here, or this exact entry at the gate); the code is scanned either way
        hold = tuple(loader_keys(spec.get("env"))) if isinstance(spec, dict) else ()
        link = spec_entry_hash(spec, base) if hold else None
        out.append(EffectItem(f"{_P}mcp:{scope_ident}:{name}", "servers", spec, scope,
                              f"MCP server {name} ({src})", t, str(file), (*prefix, name), env_hold=hold, env_link=link))
    return out


def _project_entry_items(projects: dict, key: str, cwd: Path) -> list[EffectItem]:
    p = os.path.realpath(key)
    return _servers_items(f"project:{p}", p, projects.get(key), claude_json(), ("projects", key, "mcpServers"),
                          "~/.claude.json (project)", Path(p))


def _hook_id(value: dict) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, default=str).encode()).hexdigest()[:12]


def _settings_items(label: str, scope: str, path: Path, data: object, projs: list[str],
                    mcpjson: dict[str, EffectItem]) -> list[EffectItem]:
    if not isinstance(data, dict):
        return []
    out: list[EffectItem] = []
    hooks = data.get("hooks")
    for event, groups in (hooks.items() if isinstance(hooks, dict) else []):
        for g in groups if isinstance(groups, list) else []:
            if not isinstance(g, dict):
                continue
            for h in g.get("hooks") if isinstance(g.get("hooks"), list) else []:
                value = {"event": event, "matcher": g.get("matcher"), "hook": h}
                cmd = h.get("command") if isinstance(h, dict) else None
                out.append(EffectItem(f"{_P}hook:{label}:{event}:{_hook_id(value)}", "hooks", value, scope,
                                      f"{event} hook `{cmd or h}` ({path})", None, str(path), ("hooks", event)))
    for k in EXEC_KEYS:
        if k in data:
            out.append(EffectItem(f"{_P}setting:{label}:{k}", "exec_settings", data[k], scope,
                                  f"setting {k} ({path})", None, str(path), (k,)))
    mk = data.get("extraKnownMarketplaces")
    for name, v in (mk.items() if isinstance(mk, dict) else []):
        out.append(EffectItem(f"{_P}setting:{label}:extraKnownMarketplaces:{name}", "exec_settings", v, scope,
                              f"marketplace {name} ({path})", None, str(path), ("extraKnownMarketplaces", name)))
    ep = data.get("enabledPlugins")
    for spec, on in (ep.items() if isinstance(ep, dict) else []):
        out.append(EffectItem(f"{_P}setting:{label}:enabledPlugins:{spec}", "toggles", on, scope,
                              f"enabledPlugins {spec}={json.dumps(on)} ({path})", None, str(path),
                              ("enabledPlugins", spec), requires=(f"{_P}plugin:{spec}",)))
    # .mcp.json servers this setting switches on: the project's own (project settings) or every project dir's
    dirs = projs if scope == "user" else [scope]
    servers = [i for i, it in mcpjson.items() if it.scope in dirs]
    if "enableAllProjectMcpServers" in data:
        v = data["enableAllProjectMcpServers"]
        out.append(EffectItem(f"{_P}setting:{label}:enableAllProjectMcpServers", "toggles", v, scope,
                              f"enableAllProjectMcpServers={json.dumps(v)} ({path})", None, str(path),
                              ("enableAllProjectMcpServers",), requires=tuple(sorted(servers))))
    if "enabledMcpjsonServers" in data:
        v = data["enabledMcpjsonServers"]
        names = v if isinstance(v, list) else []
        req = tuple(sorted(f"{_P}mcp:mcpjson:{d}:{n}" for d in dirs for n in names if isinstance(n, str)
                           if f"{_P}mcp:mcpjson:{d}:{n}" in mcpjson))
        missing = [n for n in names if not any(f"{_P}mcp:mcpjson:{d}:{n}" in mcpjson for d in dirs)]
        out.append(EffectItem(f"{_P}setting:{label}:enabledMcpjsonServers", "toggles", v, scope,
                              f"enabledMcpjsonServers={json.dumps(v)} ({path})", None, str(path),
                              ("enabledMcpjsonServers",), requires=req + tuple(f"missing:{n}" for n in missing)))
    return out


class ClaudeCodeAdapter:
    name = NAME

    # --- paths
    def watched_paths(self, cwd: Path, home: Path) -> list[Path]:
        return [Path(p) for p in watch.watched_paths(str(cwd), str(home))]

    # --- Task 10 inventory
    def list_installed(self, cwd: Path) -> list[InstalledItem]:
        cwd = Path(cwd)
        items: list[InstalledItem | None] = []
        cj = _read_json(claude_json())
        projects = cj.get("projects") if isinstance(cj, dict) else None
        proj = projects.get(str(cwd)) if isinstance(projects, dict) else None
        for name, spec in _servers(cj).items():
            items.append(_mcp_item("~/.claude.json", "user", name, spec, cwd))
        for name, spec in _servers(proj).items():
            items.append(_mcp_item("~/.claude.json (project)", f"project:{cwd}", name, spec, cwd))
        for name, spec in _servers(_read_json(cwd / ".mcp.json")).items():
            items.append(_mcp_item(".mcp.json", f"mcpjson:{cwd}", name, spec, cwd))
        out = [i for i in items if i is not None]
        out += _skills(claude_home() / "skills", "user", "~/.claude/skills")
        out += _skills(cwd / ".claude" / "skills", f"project:{cwd}", ".claude/skills")
        out += _plugins(cwd)
        return out

    # --- effect check
    def effect_items(self, cwd: Path) -> list[EffectItem]:
        home = str(Path.home())
        projs = watch.project_dirs(str(cwd), home)
        out: list[EffectItem] = []
        cj = _load(claude_json())
        projects = cj.get("projects") if isinstance(cj, dict) else None
        out += _servers_items("user", "user", cj, claude_json(), ("mcpServers",), "~/.claude.json", Path(cwd))
        for k in watch.project_keys(projects, str(cwd), home):
            out += _project_entry_items(projects, k, Path(cwd))
        for p in projs:
            out += _servers_items(f"mcpjson:{p}", p, _load(Path(p) / ".mcp.json"), Path(p) / ".mcp.json",
                                  ("mcpServers",), ".mcp.json", Path(p))
        settings = [("user", "user", claude_home() / "settings.json"),
                    ("user-local", "user", claude_home() / "settings.local.json")]
        for p in projs:
            settings += [(f"project:{p}", p, Path(p) / ".claude" / "settings.json"),
                         (f"project-local:{p}", p, Path(p) / ".claude" / "settings.local.json")]
        mcpjson = {it.ident: it for it in out if it.ident.startswith(f"{_P}mcp:mcpjson:")}
        for label, scope, path in settings:
            out += _settings_items(label, scope, path, _load(path), projs, mcpjson)
        km_file = claude_home() / "plugins" / "known_marketplaces.json"
        km = _load(km_file)
        for name, v in (km.items() if isinstance(km, dict) else []):
            value = {k: x for k, x in v.items() if k != "lastUpdated"} if isinstance(v, dict) else v
            out.append(EffectItem(f"{_P}marketplace:{name}", "exec_settings", value, "user",
                                  f"marketplace {name} (known_marketplaces.json)", None, str(km_file), (name,)))
        ip = _load(_plugins_file())
        plugins = ip.get("plugins") if isinstance(ip, dict) else None
        for spec, entries in (plugins.items() if isinstance(plugins, dict) else []):
            ents = entries if isinstance(entries, list) else []
            e = _plugin_entry(ents, Path(cwd)) or next((x for x in ents if isinstance(x, dict)
                                                        and isinstance(x.get("installPath"), str)
                                                        and x["installPath"]), None)
            t = _local(Path(e["installPath"])) if e else None
            value = {"entries": [{k: x.get(k) for k in _PLUGIN_FIELDS} if isinstance(x, dict) else x for x in ents],
                     "content": _tree_hash(Path(t.path)) if t else None}
            out.append(EffectItem(f"{_P}plugin:{spec}", "plugins", value, "user", f"plugin {spec}", t,
                                  str(_plugins_file()), ("plugins", spec), t.path if t else None))
        bases = [("user", "user", claude_home())] + [(f"project:{p}", p, Path(p) / ".claude") for p in projs]
        for scope_ident, scope, base in bases:
            for d in _skill_dirs(base / "skills"):
                out.append(EffectItem(f"{_P}skill:{scope_ident}:{d.name}", "skills", _tree_hash(d), scope,
                                      f"skill {d.name} ({d})", _local(d), path=str(d)))
            for kind in ("commands", "agents"):
                root = base / kind
                for f in _doc_files(root):
                    rel = os.path.relpath(f, root)
                    out.append(EffectItem(f"{_P}{kind[:-1]}:{scope_ident}:{rel}", "skills", _tree_hash(f), scope,
                                          f"{kind[:-1]} {rel} ({f})", _local(f), path=str(f)))
        return out

    def install_items(self, cwd: Path) -> list[EffectItem]:
        """effect_items plus every project's ~/.claude.json servers: the install-time snapshot."""
        out = self.effect_items(cwd)
        seen = {it.ident for it in out}
        cj = _load(claude_json())
        projects = cj.get("projects") if isinstance(cj, dict) else None
        for k in (projects if isinstance(projects, dict) else {}):
            if isinstance(k, str):
                out += [it for it in _project_entry_items(projects, k, Path(cwd)) if it.ident not in seen]
        return out

    def semantic_state(self, cwd: Path) -> dict:
        state: dict = {c: {} for c in CATEGORIES}
        for it in self.effect_items(cwd):
            state[it.category][it.ident] = it.value
        return state

    # --- reject
    def remove(self, item: dict) -> tuple[bool, str]:
        cat, file, keypath, path = item.get("category"), item.get("file"), item.get("keypath") or [], item.get("path")
        msgs: list[str] = []
        if file and keypath:
            ok, msg = _remove_json(Path(file), list(keypath), item)
            if not ok:
                return False, msg
            msgs.append(msg)
        if path and cat in ("skills", "plugins"):
            ok, msg = _move_to_quarantine(Path(path))
            if not ok and cat == "skills":
                return False, msg
            msgs.append(msg)
        if not msgs:
            return False, "nothing to remove"
        return True, "; ".join(msgs)


def _stamp() -> str:
    return time.strftime("%Y%m%d-%H%M%S") + f"-{os.getpid()}"


def _move_to_quarantine(p: Path) -> tuple[bool, str]:
    if not p.exists() and not p.is_symlink():
        return False, f"{p} is already gone"
    dest_dir = bawwab_home() / "quarantine"
    dest_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    dest = dest_dir / f"{_stamp()}-{p.name}"
    try:
        shutil.move(str(p), str(dest))
    except OSError as e:
        return False, f"could not move {p}: {type(e).__name__}"
    return True, f"moved {p} to {dest}"


def _remove_json(file: Path, keypath: list, item: dict) -> tuple[bool, str]:
    try:
        original = file.read_text()
        data = json.loads(original)
    except (OSError, ValueError) as e:
        return False, f"could not read {file}: {type(e).__name__}"
    parent = data
    for k in keypath[:-1]:
        parent = parent.get(k) if isinstance(parent, dict) else None
    last = keypath[-1]
    if not isinstance(parent, dict) or last not in parent:
        return False, f"entry not found in {file}"
    if item.get("category") == "hooks":
        if not _remove_hook(parent, last, item):
            return False, f"hook not found in {file}"
    else:
        del parent[last]
    backups = bawwab_home() / "backups"
    backups.mkdir(parents=True, exist_ok=True, mode=0o700)
    backup = backups / f"{_stamp()}-{file.name}"
    try:
        shutil.copy2(file, backup)
        os.chmod(backup, 0o600)
        tmp = file.with_name(f".{file.name}.bawwab-{os.getpid()}.tmp")
        tmp.write_text(_dump_like(original, data))
        try:
            os.chmod(tmp, os.stat(file).st_mode & 0o777)
        except OSError:
            pass
        os.replace(tmp, file)
    except OSError as e:
        return False, f"could not write {file}: {type(e).__name__}"
    return True, f"removed it from {file} (backup: {backup})"


def _dump_like(original: str, data: object) -> str:
    """JSON in the original file's style: its indentation (spaces or tab, or compact), raw unicode."""
    m = re.search(r"\n([ \t]+)\S", original)
    if m is None:
        return json.dumps(data, ensure_ascii=False, separators=(",", ":") if "\n" not in original.strip() else None)
    indent = m.group(1)
    text = json.dumps(data, ensure_ascii=False, indent="\t" if indent.startswith("\t") else len(indent))
    return text + ("\n" if original.endswith("\n") else "")


def _remove_hook(hooks: dict, event: str, item: dict) -> bool:
    """Remove the one hook whose (event, matcher, hook) hashes to the quarantined item's ident."""
    groups = hooks.get(event)
    want = item.get("ident", "").rsplit(":", 1)[-1]
    for g in groups if isinstance(groups, list) else []:
        hs = g.get("hooks") if isinstance(g, dict) else None
        for h in list(hs) if isinstance(hs, list) else []:
            if _hook_id({"event": event, "matcher": g.get("matcher"), "hook": h}) == want:
                hs.remove(h)
                if not hs:
                    groups.remove(g)
                if not groups:
                    del hooks[event]
                return True
    return False
