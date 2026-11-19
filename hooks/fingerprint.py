"""Cheap change detection for the effect check. Stdlib only; loaded by path from the hook and from bawwab.

fingerprint(): stat data (mtime, ctime, size, inode) of every watched JSON file, and of every entry under
the watched directories (skills/commands/agents, installed plugins' install paths): see _walk for the
rules (skip node_modules & co, breadth-first with per-root and per-subtree budgets, key files always).
semantic_digest(): the same, except JSON files count only through the keys that matter (mcpServers,
hooks, ...), so Claude rewriting ~/.claude.json (numStartups, tips, project metadata) is noise.

The stored state lives in $BAWWAB_HOME/fp:
  {"v": 1, "cwds": {cwd: [fingerprint, digest, ts]}, "quarantine": <active entries>}
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


def _watch_tables() -> list:
    """Every adapter's stdlib-only watch table (bawwab/agents/*_watch.py), loaded by path once per process."""
    global _tables
    if _tables is None:
        mods = []
        for i, path in enumerate(sorted(glob.glob(_WATCH_GLOB))):
            spec = importlib.util.spec_from_file_location(f"_bawwab_watch_{i}", path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            mods.append(mod)
        if not mods:
            raise RuntimeError("no watch tables found")
        _tables = mods
    return _tables


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


def _walk(root: str, h, item_root: bool = False) -> None:
    """Feed a watched root into h. Every item root (each child dir of a skills/commands/agents dir, or the
    root itself for a plugin install path) gets its direct entries and its ALWAYS_FILES statted whatever
    the budgets; then each top-level subtree is walked breadth-first within SUBTREE_BUDGET, the whole root
    within ROOT_BUDGET, never descending into SKIP_DIRS. Symlinks are followed (loops cut)."""
    t = _watch_tables()[0]
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
        subtrees += [p for p in (_entry(h, e, seen, skip, "D\0") for e in _entries(it, h)) if p]
    left = ROOT_BUDGET
    for sub in subtrees:
        if left <= 0:
            h.update(f"TRUNCATED\0{root}\n".encode())
            break
        left -= _bfs(sub, h, min(SUBTREE_BUDGET, left), seen, skip)


def _paths(cwd: str, home: str) -> tuple[list, list, list]:
    files, dirs = [], []
    for t in _watch_tables():
        files += t.json_files(cwd, home)
        dirs += [(d, False) for d in t.dirs(cwd, home)] + [(d, True) for d in t.plugin_dirs(cwd, home)]
    return files, dirs, _watch_tables()


def fingerprint(cwd: str, home: str) -> str:
    cwd, home = str(cwd), str(home)
    files, dirs, _ = _paths(cwd, home)
    h = hashlib.sha256()
    for p, _k in files:
        h.update(f"J\0{p}\0{_stat(p)}\n".encode())
    for d, item in dirs:
        _walk(d, h, item)
    return h.hexdigest()


def _pick(data: object, keypath: tuple, cwd: str, home: str, tables: list) -> object:
    for i, k in enumerate(keypath):
        if k == "{project}":
            keys = []
            for t in tables:
                keys += t.project_keys(data, cwd, home)
            return {pk: _pick(data[pk], keypath[i + 1:], cwd, home, tables) for pk in sorted(set(keys))}
        if not isinstance(data, dict) or k not in data:
            return None
        data = data[k]
    return data


def semantic_digest(cwd: str, home: str) -> str:
    cwd, home = str(cwd), str(home)
    files, dirs, tables = _paths(cwd, home)
    h = hashlib.sha256()
    for p, keypaths in files:
        try:
            with open(p, "rb") as f:
                data = json.loads(f.read())
            part = [_pick(data, kp, cwd, home, tables) for kp in keypaths]
        except FileNotFoundError:
            part = "-"
        except (OSError, ValueError, RecursionError):
            part = ["unreadable", _stat(p), time.time()]  # never equal: the slow path decides
        h.update(f"J\0{p}\0{json.dumps(part, sort_keys=True, default=str)}\n".encode())
    for d, item in dirs:
        _walk(d, h, item)
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


def initialised(home: str, bawwab_home: str) -> bool:
    """Bawwab has had its first SessionStart (install marker), or has effect-check state (the fp file).
    Both gone = a fresh install (first-run prompt; documented residual)."""
    return any(os.path.exists(p) for p in marker_paths(home)) or os.path.exists(state_path(bawwab_home))


def is_child(bawwab_home: str) -> bool:
    """BAWWAB_CHILD counts only when it equals the per-install token bawwab sets on its own children."""
    import hmac

    v = os.environ.get("BAWWAB_CHILD", "")
    if not v or v == "0":
        return False
    try:
        with open(os.path.join(bawwab_home, "child.token")) as f:
            tok = f.read().strip()
    except OSError:
        return False
    return bool(tok) and hmac.compare_digest(v, tok)


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
    fp = fingerprint(cwd, home)
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
