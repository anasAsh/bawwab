"""Cheap change detection for the effect check. Stdlib only; loaded by path from the hook and from bawwab.

fingerprint(): stat data (mtime, ctime, size, inode) of every watched JSON file, and of every entry under
the watched directories (skills/commands/agents, installed plugins' install paths): see _walk for the
rules (skip node_modules & co, breadth-first with per-root and per-subtree budgets, key files always).
It also covers the local code MCP server entries run (a script file, its package dir, `uv run`'s project:
the table's payload_candidates / payload_roots), so changed code under an unchanged entry counts.
Symlinks are followed (dirs once each, by device and inode) and their link text recorded; the effect item's
content hash (bawwab/agents/claude_code.py _tree_hash) follows the same rule.
semantic_digest(): the same, except JSON files count only through the keys that matter (mcpServers,
hooks, ...), so Claude rewriting ~/.claude.json (numStartups, tips, project metadata) is noise.

The stored state lives in $BAWWAB_HOME/fp:
  {"v": 1, "cwds": {cwd: [fingerprint, digest, ts]}, "quarantine": <active entries>}
$BAWWAB_HOME/fp-payloads caches the payload paths per cwd, keyed by the config files' stat data, so an idle
hook never parses ~/.claude.json: {cwd: [key, [[path, base], ...]]}.
check() is "same" (fingerprint unchanged), "noise" (fingerprint changed but the digest did not; the stored
fingerprint is updated) or "changed" (the slow path must run the effect check).
"""
import glob
import hashlib
import importlib.util
import json
import os
import time

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_WATCH_GLOB = os.path.join(_ROOT, "bawwab", "agents", "*_watch.py")
_MAX_CWDS = 32
ROOT_BUDGET = 5000  # entries walked per watched root, beyond the always-statted ones
SUBTREE_BUDGET = 1000  # per top-level subtree of an item root, so one big subtree can't starve its siblings
MARKER = ".bawwab-initialised"
_tables = None


# The tables the hook uses: the agents bawwab gates with hooks (Claude Code). The others (cursor, codex, ...) are
# loaded only when asked for by name, by the background watcher (bawwab/watch.py): the hot path never pays for them.
HOOK_TABLES = ("claude_code_watch.py",)


def _load_table(path: str):
    mod = _loaded.get(path)
    if mod is None:
        spec = importlib.util.spec_from_file_location(f"_bawwab_watch_{len(_loaded)}", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _loaded[path] = mod
    return mod


_loaded: dict = {}


def _watch_tables(agents=None) -> list:
    """Adapters' stdlib-only watch tables (bawwab/agents/*_watch.py), loaded by path once per process.
    agents=None: the hook's tables (HOOK_TABLES; the first is Claude Code's, whose walking rules every table
    shares). Else the tables whose NAME is in agents, in file order."""
    global _tables
    if agents is None:
        if _tables is None:
            mods = [_load_table(os.path.join(os.path.dirname(_WATCH_GLOB), n)) for n in HOOK_TABLES
                    if os.path.isfile(os.path.join(os.path.dirname(_WATCH_GLOB), n))]
            if not mods:
                raise RuntimeError("no watch tables found")
            _tables = mods
        return _tables
    mods = [_load_table(p) for p in sorted(glob.glob(_WATCH_GLOB))]
    return [m for m in mods if m.NAME in agents]


def _stat(path: str) -> str:
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return "-"
    except OSError as e:
        return f"E{e.errno}"
    return f"{st.st_mtime_ns}:{st.st_ctime_ns}:{st.st_size}:{st.st_ino}"


def _row(h, path: str, st, tag: str = "") -> None:
    h.update(f"{tag}{path}\0{st.st_mtime_ns}:{st.st_ctime_ns}:{st.st_size}:{st.st_ino}\n".encode())


def _link(h, path: str) -> None:
    try:
        h.update(f"L\0{os.readlink(path)}\n".encode())
    except OSError:
        pass


def _stat_into(h, path: str) -> None:
    try:
        st = os.stat(path)
    except FileNotFoundError:
        return
    except OSError as e:
        h.update(f"E\0{path}\0{e.errno}\n".encode())
        return
    _row(h, path, st, "A\0")
    if os.path.islink(path):
        _link(h, path)


def _entries(d: str, h) -> list:
    try:
        with os.scandir(d) as it:
            return sorted(it, key=lambda e: e.name)
    except OSError as e:
        h.update(f"E\0{d}\0{e.errno}\n".encode())
        return []


def _entry(h, e, seen: set, skip, tag: str = "") -> str | None:
    """Record one dir entry; returns its path when it is a directory to descend into."""
    try:
        st = e.stat()
    except OSError:
        h.update(f"?\0{e.path}\n".encode())
        return None
    _row(h, e.path, st, tag)
    if e.is_symlink():
        _link(h, e.path)
    if e.is_dir() and e.name not in skip:  # skipped dirs (node_modules...): their own stat only
        key = (st.st_dev, st.st_ino)
        if key not in seen:
            seen.add(key)
            return e.path
    return None


def _bfs(top: str, h, budget: int, seen: set, skip) -> int:
    """Breadth-first stat of everything under top, at most `budget` entries; returns the entries used."""
    queue, i, n = [top], 0, 0
    while i < len(queue):
        d = queue[i]
        i += 1
        for e in _entries(d, h):
            if n >= budget:
                h.update(f"TRUNCATED\0{top}\n".encode())
                return n
            n += 1
            sub = _entry(h, e, seen, skip)
            if sub:
                queue.append(sub)
    return n


def _in_use(h, d: str, item: str, seen: set, skip, t) -> list:
    """An item root's .in_use dir: Claude Code's per-process markers (and the dir's own stat, which they
    move) are left out; every other entry is recorded as usual. Returns the subdirs to descend into."""
    out = []
    for e in _entries(d, h):
        if not t.is_in_use_marker(e.path, item):
            sub = _entry(h, e, seen, skip, "D\0")
            if sub:
                out.append(sub)
    return out


def _walk(root: str, h, item_root: bool = False) -> None:
    """Feed a watched root into h. Every item root (each child dir of a skills/commands/agents dir, or the
    root itself for a plugin install path) gets its direct entries and its ALWAYS_FILES statted whatever
    the budgets; then each top-level subtree is walked breadth-first within SUBTREE_BUDGET, the whole root
    within ROOT_BUDGET, never descending into SKIP_DIRS. Symlinks are followed (loops cut)."""
    t = _watch_tables()[0]  # Claude Code's walking rules, shared by every adapter
    skip, always = t.SKIP_DIRS, t.ALWAYS_FILES
    try:
        st = os.stat(root)
    except FileNotFoundError:
        h.update(f"R\0{root}\0-\n".encode())
        return
    except OSError as e:
        h.update(f"R\0{root}\0E{e.errno}\n".encode())
        return
    _row(h, root, st, "R\0")
    if os.path.islink(root):
        _link(h, root)
    seen = {(st.st_dev, st.st_ino)}
    if item_root:
        items = [root]
    else:  # the container's own entries (skill dirs, command files); its subdirs are item roots
        items = [p for p in (_entry(h, e, seen, skip) for e in _entries(root, h)) if p]
    subtrees: list[str] = []
    for it in items:  # always, whatever the budgets: the files that decide what runs
        for rel in always:
            _stat_into(h, os.path.join(it, rel))
        for ref in t.entry_refs(it, skipped_only=True):  # entry points config names inside node_modules & co
            _stat_into(h, ref)
            pkg = t.package_dir(it, ref)
            if pkg:
                _bfs(pkg, h, t.PKG_BUDGET, set(), frozenset())
        for e in _entries(it, h):
            if e.name == t.IN_USE_DIR and e.is_dir(follow_symlinks=False):
                subtrees += _in_use(h, e.path, it, seen, skip, t)
            else:
                sub = _entry(h, e, seen, skip, "D\0")
                if sub:
                    subtrees.append(sub)
    left = ROOT_BUDGET
    for sub in subtrees:
        if left <= 0:
            h.update(f"TRUNCATED\0{root}\n".encode())
            break
        left -= _bfs(sub, h, min(SUBTREE_BUDGET, left), seen, skip)


def _paths(cwd: str, home: str, agents=None) -> tuple[list, list, list]:
    files, dirs = [], []
    tables = _watch_tables(agents)
    for t in tables:
        files += [(p, k, t) for p, k in t.json_files(cwd, home)]
        dirs += [(d, False) for d in t.dirs(cwd, home)] + [(d, True) for d in t.plugin_dirs(cwd, home)]
    return files, dirs, tables


def _candidates(tables: list, cwd: str, home: str, load) -> list:
    """(path, base) of the local code MCP server entries run (the tables' payload_candidates)."""
    out: list = []
    for t in tables:
        fn = getattr(t, "payload_candidates", None)
        out += [tuple(c) for c in fn(cwd, home, load)] if fn else []
    return sorted(set(out))


def _payloads(h, cwd: str, home: str, cands: list) -> None:
    """Feed the local code of MCP server entries into h: each file's stat (a missing one too, so creating it
    counts), each package dir walked like a plugin install path. The rules are payload_roots', shared with
    the effect item's content hash (bawwab/agents/claude_code.py)."""
    if not cands:
        return
    t = _watch_tables()[0]
    stops: dict = {}
    for path, base in cands:
        if base not in stops:
            stops[base] = t.stop_dirs(cwd, home, base)
        for root, tree in t.payload_roots(path, stops[base]):
            if tree:
                _walk(root, h, True)
            else:
                h.update(f"P\0{root}\0{_stat(root)}\n".encode())
                if os.path.islink(root):
                    _link(h, root)


_PAYLOAD_CACHE = "fp-payloads"
_MEMO: dict = {}  # cwd -> (jsig, candidates), this process only


def _json_loader(files: list):
    def load(path):
        for p, _k, t in files:
            if p == path:
                try:
                    with open(p, "rb") as f:
                        return _parse(t, f.read(), p)
                except (OSError, ValueError, RecursionError):
                    return None
        return None
    return load


def _cached_candidates(files: list, tables: list, cwd: str, home: str, jsig: str, bawwab_home) -> list:
    """The payload candidates, read from the config files only when their stat data (jsig) changed since the
    last call for this cwd: the hook must not parse a large ~/.claude.json on every tool call. The cache holds
    paths only; their stat data is read every time. Within one process (bawwab, the watcher) a memo does the
    same without the file."""
    if not any(getattr(t, "payload_candidates", None) for t in tables):
        return []
    mem = _MEMO.get(cwd)
    if mem is not None and mem[0] == jsig:
        return mem[1]
    path = os.path.join(bawwab_home, _PAYLOAD_CACHE) if bawwab_home else None
    data: dict = {}
    if path:
        try:
            with open(path) as f:
                data = json.load(f)
            row = data.get(cwd) if isinstance(data, dict) else None
            if isinstance(row, list) and len(row) == 2 and row[0] == jsig and isinstance(row[1], list):
                return [tuple(c) for c in row[1]]
        except (OSError, ValueError):
            data = {}
    cands = _candidates(tables, cwd, home, _json_loader(files))
    if len(_MEMO) >= _MAX_CWDS:
        _MEMO.clear()
    _MEMO[cwd] = (jsig, cands)
    if path and os.path.isdir(bawwab_home):
        data = data if isinstance(data, dict) else {}
        data.pop(cwd, None)
        data[cwd] = [jsig, cands]
        for k in list(data)[: max(0, len(data) - _MAX_CWDS)]:
            del data[k]
        try:
            tmp = f"{path}.{os.getpid()}.tmp"
            with open(tmp, "w") as f:
                json.dump(data, f)
            os.replace(tmp, path)
        except OSError:
            pass
    return cands


def fingerprint(cwd: str, home: str, agents=None, bawwab_home=None) -> str:
    """bawwab_home: where to cache the MCP payload paths between calls (the hook passes it)."""
    cwd, home = str(cwd), str(home)
    files, dirs, tables = _paths(cwd, home, agents)
    h = hashlib.sha256()
    rows = [f"J\0{p}\0{_stat(p)}\n" for p, _k, _t in files]
    for r in rows:
        h.update(r.encode())
    for d, item in dirs:
        _walk(d, h, item)
    jsig = hashlib.sha256(f"{cwd}\0{home}\0{os.environ.get('CLAUDE_PROJECT_DIR', '')}\0{''.join(rows)}".encode())
    _payloads(h, cwd, home, _cached_candidates(files, tables, cwd, home, jsig.hexdigest(), bawwab_home))
    return h.hexdigest()


def _pick(data: object, keypath: tuple, cwd: str, home: str, tables: list) -> object:
    for i, k in enumerate(keypath):
        if k == "{project}":
            keys = []
            for t in tables:
                pk = getattr(t, "project_keys", None)
                keys += pk(data, cwd, home) if pk else []
            return {pk: _pick(data[pk], keypath[i + 1:], cwd, home, tables) for pk in sorted(set(keys))}
        if not isinstance(data, dict) or k not in data:
            return None
        data = data[k]
    return data


def _parse(t, raw: bytes, path: str) -> object:
    """A watched config file's data: the table's own reader (TOML, JSON with comments) or plain JSON."""
    load = getattr(t, "load", None)
    return load(raw, path) if load is not None else json.loads(raw)


def semantic_digest(cwd: str, home: str, agents=None) -> str:
    cwd, home = str(cwd), str(home)
    files, dirs, tables = _paths(cwd, home, agents)
    h = hashlib.sha256()
    parsed: dict = {}
    for p, keypaths, t in files:
        try:
            with open(p, "rb") as f:
                data = _parse(t, f.read(), p)
            parsed[p] = data
            proj = getattr(t, "project_value", None)  # e.g. permissions: only what broadens counts
            part = [proj(kp, v) if proj else v for kp, v in ((kp, _pick(data, kp, cwd, home, tables))
                                                             for kp in keypaths)]
        except FileNotFoundError:
            part = "-"
        except (OSError, ValueError, RecursionError):
            part = ["unreadable", _stat(p), time.time()]  # never equal: the slow path decides
        h.update(f"J\0{p}\0{json.dumps(part, sort_keys=True, default=str)}\n".encode())
    for d, item in dirs:
        _walk(d, h, item)
    _payloads(h, cwd, home, _candidates(tables, cwd, home, parsed.get))
    return h.hexdigest()


# ------------------------------------------------------------------ install marker (outside $BAWWAB_HOME)

def marker_paths(home: str) -> list[str]:
    """Every copy of the install marker: ~/.claude, the XDG state dir, and bawwab's plugin data dir. A
    wipe has to find all of them, or the missing state is noticed (fail closed)."""
    state = os.environ.get("XDG_STATE_HOME") or os.path.join(home, ".local", "state")
    out = [os.path.join(home, ".claude", MARKER), os.path.join(state, "bawwab", MARKER)]
    pd = os.environ.get("CLAUDE_PLUGIN_DATA")
    if pd and is_bawwab_plugin_dir(pd):  # another plugin's data dir is not ours to write
        out.append(os.path.join(pd, MARKER))
    return out


def is_bawwab_plugin_dir(path: str) -> bool:
    """A plugin data dir whose own name is a bawwab plugin id (e.g. ~/.claude/plugins/data/bawwab-<mkt>)."""
    import re

    return re.fullmatch(r"bawwab(?:[-@_.].*)?", os.path.basename(os.path.normpath(path))) is not None


LOST_AFTER = 600  # seconds: a plugin install older than this with no bawwab state means the state was lost
STATE_CREATED = "state-created"  # in bawwab's plugin data dir: bawwab has written its state (fix round 2, I4)
BOOTSTRAP_COMPLETE = "bootstrap-complete"  # in bawwab's plugin data dir: the first-run venv sync finished


def plugin_data_dirs(home: str) -> list[str]:
    """bawwab's plugin data dirs: $CLAUDE_PLUGIN_DATA (when it is bawwab's) and every bawwab-named dir under
    <claude config>/plugins/data, so the user's `!` shell (no plugin env) finds the same ones as the hooks."""
    out = []
    pd = os.environ.get("CLAUDE_PLUGIN_DATA")
    if pd and os.path.isabs(pd) and is_bawwab_plugin_dir(pd):
        out.append(os.path.normpath(pd))
    for cfg in _claude_dirs(home):
        base = os.path.join(cfg, "plugins", "data")
        try:
            names = sorted(os.listdir(base))
        except OSError:
            names = []
        for n in names:
            d = os.path.join(base, n)
            if is_bawwab_plugin_dir(d) and os.path.isdir(d) and os.path.normpath(d) not in out:
                out.append(os.path.normpath(d))
    return out


def data_marker(home: str, name: str) -> bool:
    return any(os.path.exists(os.path.join(d, name)) for d in plugin_data_dirs(home))


def _claude_dirs(home: str) -> list:
    """Claude Code's config dirs: ~/.claude and $CLAUDE_CONFIG_DIR (never only the latter: see the watch table)."""
    return _watch_tables()[0].config_dirs(home)


def _installed_entries(home: str) -> list:
    """(key, entries) of every config dir's plugins/installed_plugins.json."""
    out = []
    for cfg in _claude_dirs(home):
        try:
            with open(os.path.join(cfg, "plugins", "installed_plugins.json")) as f:
                data = json.load(f)
        except (OSError, ValueError):
            continue
        plugins = data.get("plugins") if isinstance(data, dict) else None
        if isinstance(plugins, dict):
            out += list(plugins.items())
    return out


def plugin_installed_at(home: str) -> float | None:
    """When Claude Code installed bawwab as a plugin: the earliest installedAt of a `bawwab@*` entry (or the
    entry at CLAUDE_PLUGIN_ROOT, when set) in any config dir's installed_plugins.json; else None. Read from the file, never
    from the process environment, so the user's `!` shell and the hooks agree."""
    from datetime import datetime, timezone

    root = os.environ.get("CLAUDE_PLUGIN_ROOT")
    root = os.path.normpath(root) if root else None
    times = []
    for key, entries in _installed_entries(home):
        for e in entries if isinstance(entries, list) else [entries]:
            if not isinstance(e, dict):
                continue
            path = e.get("installPath")
            ours = str(key).split("@", 1)[0] == "bawwab" or (
                root is not None and isinstance(path, str) and os.path.normpath(path) == root)
            at = e.get("installedAt")
            if not ours or not isinstance(at, str):
                continue
            try:
                t = datetime.fromisoformat(at.replace("Z", "+00:00"))
            except ValueError:
                continue
            times.append((t if t.tzinfo else t.replace(tzinfo=timezone.utc)).timestamp())
    return min(times) if times else None


_HEAD_LINES = 50  # transcript lines read for a session's id and first timestamp


def _transcript_head(path: str) -> tuple[str | None, float | None]:
    """(sessionId, time of the first event) of a Claude Code transcript; None where it doesn't say."""
    from datetime import datetime, timezone

    sid = None
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            for _ in range(_HEAD_LINES):
                line = f.readline(1 << 20)
                if not line:
                    break
                try:
                    ev = json.loads(line)
                except ValueError:
                    continue
                if not isinstance(ev, dict):
                    continue
                if sid is None and isinstance(ev.get("sessionId"), str):
                    sid = ev["sessionId"]
                ts = ev.get("timestamp")
                if isinstance(ts, str):
                    try:
                        t = datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except ValueError:
                        continue
                    return sid, (t if t.tzinfo else t.replace(tzinfo=timezone.utc)).timestamp()
    except OSError:
        pass
    return sid, None


def session_after(home: str, at: float, current: str | None = None) -> bool:
    """Some Claude Code session other than `current` started after `at` (its transcript under the projects
    dir begins later). bawwab's SessionStart ran in it, so bawwab's state existed. A transcript written after
    `at` that doesn't say when it began counts (fail closed). Without `current` (the CLI from a `!` shell),
    the most recently written session is taken as the current one."""
    sessions: dict[str, list] = {}  # id -> [newest mtime, started after at]
    dirs = []
    for cfg in _claude_dirs(home):  # every config dir's projects/ (CLAUDE_CONFIG_DIR moves it)
        try:
            dirs += [d.path for d in os.scandir(os.path.join(cfg, "projects")) if d.is_dir(follow_symlinks=False)]
        except OSError:
            pass
    for d in dirs:
        try:
            files = [(e.path, e.name, e.stat().st_mtime) for e in os.scandir(d)
                     if e.name.endswith(".jsonl") and e.is_file(follow_symlinks=False)]
        except OSError:
            continue
        for path, name, mtime in files:
            if mtime <= at:
                continue  # not written since the install: began before it
            sid, start = _transcript_head(path)
            sid = sid or name[:-len(".jsonl")]
            s = sessions.setdefault(sid, [0.0, False])
            s[0] = max(s[0], mtime)
            s[1] = s[1] or start is None or start > at
            if s[1] and current is not None and sid != current:
                return True
    if current is None and sessions:
        current = max(sessions, key=lambda k: sessions[k][0])
    return any(after for sid, (_, after) in sessions.items() if sid != current)


def plugin_lost(home: str, session_id: str | None = None) -> str | None:
    """bawwab is an installed plugin (installed_plugins.json, more than LOST_AFTER ago) and another Claude
    Code session began after the install: its SessionStart wrote bawwab's state, so missing state now is lost
    (wiped), never a fresh install. The reason, or None (a late first session gets the first-run flow).
    session_id defaults to BAWWAB_SESSION_ID, which the hook sets from its input."""
    at = plugin_installed_at(home)
    if at is None:
        return None
    # Fix round 2 (I4): bawwab wrote its state once (state-created survives in its data dir), or the R39
    # transcript rule holds AND its first-run setup finished. A slow first setup is never "lost".
    if not data_marker(home, STATE_CREATED):
        if time.time() - at <= LOST_AFTER:
            return None
        if not session_after(home, at, session_id or os.environ.get("BAWWAB_SESSION_ID") or None):
            return None
        if not data_marker(home, BOOTSTRAP_COMPLETE):
            return None
    return ("bawwab's state was lost: bawwab has been installed as a plugin since "
            f"{time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(at))} and Claude Code has run since, but bawwab's "
            "state and install markers are missing")


def initialised(home: str, bawwab_home: str) -> bool:
    """Bawwab has had its first SessionStart (install marker), has effect-check state (the fp file), or is an
    installed plugin whose state was lost (fail closed). None of these = a fresh install (first-run prompt)."""
    return any(os.path.exists(p) for p in marker_paths(home)) or os.path.exists(state_path(bawwab_home)) \
        or plugin_lost(home) is not None


# ------------------------------------------------------------------ stored state

def state_path(bawwab_home: str) -> str:
    return os.path.join(bawwab_home, "fp")


def _read_state(bawwab_home: str) -> dict:
    try:
        with open(state_path(bawwab_home)) as f:
            data = json.load(f)
        if isinstance(data, dict) and isinstance(data.get("cwds"), dict):
            return data
    except (OSError, ValueError):
        pass
    return {"v": 1, "cwds": {}}


def _write_state(bawwab_home: str, data: dict) -> None:
    os.makedirs(bawwab_home, mode=0o700, exist_ok=True)
    path = state_path(bawwab_home)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def load(bawwab_home: str, cwd: str):
    row = _read_state(bawwab_home)["cwds"].get(str(cwd))
    return (row[0], row[1]) if isinstance(row, list) and len(row) >= 2 else None


def save(bawwab_home: str, cwd: str, fp: str, digest: str) -> None:
    data = _read_state(bawwab_home)
    cwds = data["cwds"]
    cwds[str(cwd)] = [fp, digest, time.time()]
    if len(cwds) > _MAX_CWDS:
        def ts(k):
            return cwds[k][2] if isinstance(cwds[k], list) and len(cwds[k]) > 2 else 0

        for k in sorted(cwds, key=ts)[: len(cwds) - _MAX_CWDS]:
            del cwds[k]
    _write_state(bawwab_home, data)


def forget(bawwab_home: str, cwd: str) -> None:
    """Make the next check() for cwd report "changed"."""
    data = _read_state(bawwab_home)
    if data["cwds"].pop(str(cwd), None) is not None:
        _write_state(bawwab_home, data)


def set_quarantine(bawwab_home: str, n: int) -> None:
    data = _read_state(bawwab_home)
    if data.get("quarantine", 0) != n:
        data["quarantine"] = n
        _write_state(bawwab_home, data)


def quarantine_active(bawwab_home: str) -> bool:
    """The quarantine flag, or the quarantine count kept in the state file (a deleted flag is not enough)."""
    if os.path.exists(os.path.join(bawwab_home, "quarantine.flag")):
        return True
    n = _read_state(bawwab_home).get("quarantine", 0)
    return isinstance(n, int) and n > 0


def check(cwd: str, home: str, bawwab_home: str) -> str:
    cwd, home = str(cwd), str(home)
    stored = load(bawwab_home, cwd)
    fp = fingerprint(cwd, home, bawwab_home=bawwab_home)
    if stored is not None and stored[0] == fp:
        return "same"
    if stored is None:
        return "changed"
    digest = semantic_digest(cwd, home)
    if digest != stored[1]:
        return "changed"
    try:
        save(bawwab_home, cwd, fp, digest)
    except OSError:
        pass
    return "noise"
