"""Cheap change detection for the effect check. Stdlib only; loaded by path from the hook and from bawwab.

fingerprint(): stat data (mtime, ctime, size, inode) of every watched JSON file, and of every entry under
the watched directories (skills/commands/agents, installed plugins' install paths), walked recursively,
following symlinks, up to MAX_ENTRIES per root (past that the root is marked truncated: coarse).
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
MAX_ENTRIES = 5000
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


def _walk(root: str, h) -> None:
    """Feed every entry under root (recursively, symlinks followed, loops cut) into the hash h."""
    try:
        st = os.stat(root)
    except FileNotFoundError:
        h.update(f"R\0{root}\0-\n".encode())
        return
    except OSError as e:
        h.update(f"R\0{root}\0E{e.errno}\n".encode())
        return
    h.update(f"R\0{root}\0{st.st_mtime_ns}:{st.st_ctime_ns}:{st.st_ino}\n".encode())
    if os.path.islink(root):
        h.update(f"L\0{os.readlink(root)}\n".encode())
    seen = {(st.st_dev, st.st_ino)}
    stack = [root]
    n = 0
    while stack:
        d = stack.pop()
        try:
            with os.scandir(d) as it:
                entries = sorted(it, key=lambda e: e.name)
        except OSError as e:
            h.update(f"E\0{d}\0{e.errno}\n".encode())
            continue
        for e in entries:
            n += 1
            if n > MAX_ENTRIES:
                h.update(b"TRUNCATED\n")
                return
            if e.name == ".git":
                continue
            try:
                s = e.stat()
            except OSError:
                h.update(f"?\0{e.path}\n".encode())
                continue
            link = e.is_symlink()
            h.update(f"{e.path}\0{s.st_mtime_ns}:{s.st_ctime_ns}:{s.st_size}:{s.st_ino}:{int(link)}\n".encode())
            if link:
                try:
                    h.update(f"L\0{os.readlink(e.path)}\n".encode())
                except OSError:
                    pass
            if e.is_dir():
                key = (s.st_dev, s.st_ino)
                if key not in seen:
                    seen.add(key)
                    stack.append(e.path)


def _paths(cwd: str, home: str) -> tuple[list, list, list]:
    files, dirs = [], []
    for t in _watch_tables():
        files += t.json_files(cwd, home)
        dirs += t.dirs(cwd, home) + t.plugin_dirs(cwd, home)
    return files, dirs, _watch_tables()


def fingerprint(cwd: str, home: str) -> str:
    cwd, home = str(cwd), str(home)
    files, dirs, _ = _paths(cwd, home)
    h = hashlib.sha256()
    for p, _k in files:
        h.update(f"J\0{p}\0{_stat(p)}\n".encode())
    for d in dirs:
        _walk(d, h)
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
    for d in dirs:
        _walk(d, h)
    return h.hexdigest()


# ------------------------------------------------------------------ install marker (outside $BAWWAB_HOME)

def marker_paths(home: str) -> list[str]:
    out = [os.path.join(home, ".claude", MARKER)]
    pd = os.environ.get("CLAUDE_PLUGIN_DATA")
    if pd:
        out.append(os.path.join(pd, MARKER))
    return out


def initialised(home: str, bawwab_home: str) -> bool:
    """Bawwab has had its first SessionStart (install marker), or has effect-check state (the fp file).
    Both gone = a fresh install (first-run prompt; documented residual)."""
    return any(os.path.exists(p) for p in marker_paths(home)) or os.path.exists(state_path(bawwab_home))


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
