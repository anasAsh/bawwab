"""Cheap change detection for the effect check. Stdlib only; loaded by path from the hook and from bawwab.

fingerprint(): stat data of every watched JSON file plus a two-level listing of every watched directory.
semantic_digest(): the same, except JSON files count only through the keys that matter (mcpServers,
hooks, ...), so Claude rewriting ~/.claude.json (numStartups, tips, project metadata) is noise.

The stored state lives in $BAWWAB_HOME/fp: {"v": 1, "cwds": {cwd: [fingerprint, digest, ts]}}.
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
    return f"{st.st_mtime_ns}:{st.st_size}:{st.st_ino}"


def _listing(path: str, depth: int = 2) -> list:
    """Names, types, mtimes and sizes of a directory's entries, and of its child directories' entries."""
    try:
        with os.scandir(path) as it:
            entries = sorted(it, key=lambda e: e.name)
    except FileNotFoundError:
        return ["-"]
    except OSError as e:
        return [f"E{e.errno}"]
    out = []
    for e in entries:
        try:
            st = e.stat()
            is_dir = e.is_dir()
        except OSError:
            out.append([e.name, "?"])
            continue
        row = [e.name, "d" if is_dir else "f", st.st_mtime_ns, st.st_size, st.st_ino]
        if is_dir and depth > 1:
            row.append(_listing(e.path, depth - 1))
        out.append(row)
    return out


def _paths(cwd: str, home: str) -> tuple[list, list]:
    files, dirs = [], []
    for t in _watch_tables():
        files += t.json_files(cwd, home)
        dirs += t.dirs(cwd, home)
    return files, dirs


def _digest(parts: list) -> str:
    return hashlib.sha256(json.dumps(parts, sort_keys=True, default=str).encode()).hexdigest()


def fingerprint(cwd: str, home: str) -> str:
    files, dirs = _paths(str(cwd), str(home))
    return _digest([[p, _stat(p)] for p, _ in files] + [[d, _listing(d)] for d in dirs])


def _pick(data: object, keypath: tuple) -> object:
    for k in keypath:
        if not isinstance(data, dict) or k not in data:
            return None
        data = data[k]
    return data


def semantic_digest(cwd: str, home: str) -> str:
    files, dirs = _paths(str(cwd), str(home))
    parts = []
    for p, keypaths in files:
        try:
            with open(p, "rb") as f:
                data = json.loads(f.read())
            parts.append([p, [_pick(data, kp) for kp in keypaths]])
        except FileNotFoundError:
            parts.append([p, "-"])
        except (OSError, ValueError, RecursionError):
            parts.append([p, "unreadable", _stat(p), time.time()])  # never equal: the slow path decides
    parts += [[d, _listing(d)] for d in dirs]
    return _digest(parts)


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


def load(bawwab_home: str, cwd: str):
    row = _read_state(bawwab_home)["cwds"].get(str(cwd))
    return (row[0], row[1]) if isinstance(row, list) and len(row) >= 2 else None


def save(bawwab_home: str, cwd: str, fp: str, digest: str) -> None:
    data = _read_state(bawwab_home)
    cwds = data["cwds"]
    cwds[str(cwd)] = [fp, digest, time.time()]
    if len(cwds) > _MAX_CWDS:
        for k in sorted(cwds, key=lambda k: cwds[k][2] if isinstance(cwds[k], list) and len(cwds[k]) > 2 else 0)[
            : len(cwds) - _MAX_CWDS
        ]:
            del cwds[k]
    os.makedirs(bawwab_home, mode=0o700, exist_ok=True)
    path = state_path(bawwab_home)
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        json.dump(data, f)
    os.replace(tmp, path)


def forget(bawwab_home: str, cwd: str) -> None:
    """Make the next check() for cwd report "changed"."""
    data = _read_state(bawwab_home)
    if data["cwds"].pop(str(cwd), None) is not None:
        path = state_path(bawwab_home)
        tmp = f"{path}.{os.getpid()}.tmp"
        with open(tmp, "w") as f:
            json.dump(data, f)
        os.replace(tmp, path)


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
