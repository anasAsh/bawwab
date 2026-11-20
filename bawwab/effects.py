"""Effect check (spec §1b): watch what actually changed in the agent's config and install dirs.

The PreToolUse gate parses commands, but it can't fully understand bash. This module compares the semantic
state (servers, plugins, hooks, code-running settings, toggles, skills/commands/agents) with the accepted
state; a new or changed item is accepted when its content was approved or scanned clean, and is otherwise
quarantined: every tool call except read-only ones is denied until the user approves or rejects it.

First run (spec §1a) lives here too. The provisional baseline is taken ONLY at the first SessionStart (the
install time), never by the effect check, and an install marker outside $BAWWAB_HOME
(~/.claude/.bawwab-initialised, and $CLAUDE_PLUGIN_DATA/.bawwab-initialised) records the install time and
init state: bawwab state that goes missing during a session fails closed (effects.error) until the user runs
`effects --retry` or `init --scan` (the commands shown come from bawwab.clicmd).
"""
from __future__ import annotations

import fcntl
import hashlib
import importlib.util
import json
import os
import shutil
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from bawwab.clicmd import cmd
from bawwab.config import blocks
from bawwab.envkeys import entry_meta_key
from bawwab.agents import ADAPTERS, UNSCANNABLE, EffectItem, adapter_for
from bawwab.agents.claude_code import UnreadableConfig
from bawwab.paths import bawwab_home
from bawwab.report import sanitise
from bawwab.scan import TRANSIENT_RULES, scan_target, synthetic_report
from bawwab.selfid import SELF_KEY_PREFIX, SELF_LABEL, is_self
from bawwab.store import Store, open_store, report_from_dict, report_to_dict
from bawwab.types import ScanReport, Target, Verdict

# Allowed while something is quarantined: they change nothing. AskUserQuestion lets Claude ask the user
# what to do with each item (the user still runs approve/reject).
READ_ONLY_TOOLS = frozenset({"Read", "Grep", "Glob", "LS", "TodoWrite", "NotebookRead", "AskUserQuestion"})
ERROR_IDENT = "effects.error"
MAX_SHOWN_FINDINGS = 5
MAX_BATCH_SHOWN = 20
SECONDS_PER_ITEM = 20
_fp_mod = None
_ACCEPTED = ("provisional", "unscanned", "accepted", "approved", "warned")  # warned: below the level
BATCHED = ("hooks", "exec_settings")  # at init, install-time items of these categories share one approval


class EffectsFailed(Exception):
    """The effect check could not run after a change, and not even its failure could be recorded in the db
    (the hook-visible marker and flag were written instead)."""


# ------------------------------------------------------------------ files shared with the hook

def fp_file() -> Path:
    """The fingerprint code the hook runs: <plugin root>/hooks/fingerprint.py when this package runs from a
    plugin tree (found from __file__, as selfid does; CLAUDE_PLUGIN_ROOT is never trusted to load code), else the
    package's own copy (bawwab/_fingerprint.py, a link to hooks/fingerprint.py in the source tree and a plain
    file in a wheel). Never the cwd or a repo being scanned."""
    from bawwab.selfid import running_root

    root = running_root()
    if root is not None:
        p = Path(root) / "hooks" / "fingerprint.py"
        if p.is_file():
            return p
    return Path(__file__).resolve().parent / "_fingerprint.py"


def fp_module():
    """hooks/fingerprint.py, loaded by path (the hook loads the same file)."""
    global _fp_mod
    if _fp_mod is None:
        spec = importlib.util.spec_from_file_location("_bawwab_fingerprint", fp_file())
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _fp_mod = mod
    return _fp_mod


def flag_path() -> Path:
    return bawwab_home() / "quarantine.flag"


def error_marker() -> Path:
    """Written by the hook (or here, when the db is unusable) when the effect check failed after a change."""
    return bawwab_home() / "effects.error"


def lock_path() -> Path:
    return bawwab_home() / "effects.lock"


def _db_path() -> Path:
    return bawwab_home() / "bawwab.db"


def _sync_flag(store: Store) -> None:
    try:
        n = len(store.active_quarantine())
        if n:
            flag_path().parent.mkdir(parents=True, exist_ok=True)
            flag_path().touch()
        else:
            flag_path().unlink(missing_ok=True)
        fp_module().set_quarantine(str(bawwab_home()), n)
    except OSError:
        pass


def _mark_failed(reason: str) -> None:
    """Fail closed without the db: the marker and flag the hook (stdlib) checks."""
    try:
        bawwab_home().mkdir(parents=True, exist_ok=True, mode=0o700)
        error_marker().write_text(reason[:200])
        flag_path().touch()
    except OSError:
        pass


@contextmanager
def _lock():
    """Exclusive effect-check lock. Any failure to take it (e.g. the path is a directory) raises."""
    p = lock_path()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(p, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


# ------------------------------------------------------------------ install marker

_CORRUPT = {"corrupt": True}


def read_marker() -> dict | None:
    """The install marker: None when absent; {"corrupt": True} when unreadable or the copies disagree."""
    found = []
    for p in fp_module().marker_paths(str(Path.home())):
        try:
            with open(p) as f:
                d = json.load(f)
        except FileNotFoundError:
            continue
        except (OSError, ValueError):
            return dict(_CORRUPT)
        if not isinstance(d, dict) or not isinstance(d.get("installed_at"), str):
            return dict(_CORRUPT)
        found.append(d)
    if not found:
        return None
    if any(d.get("installed_at") != found[0].get("installed_at") for d in found):
        return dict(_CORRUPT)
    return found[0]


def write_marker(installed_at: str, init_state: str) -> None:
    data = json.dumps({"installed_at": installed_at, "init_state": init_state})
    fpm = fp_module()
    for d in fpm.plugin_data_dirs(str(Path.home())):  # bawwab has written its state (lost-state rule, I4)
        try:
            p = os.path.join(d, fpm.STATE_CREATED)
            if not os.path.exists(p):
                with open(p, "w") as f:
                    f.write(installed_at)
        except OSError:
            pass
    for p in fpm.marker_paths(str(Path.home())):
        try:
            os.makedirs(os.path.dirname(p), exist_ok=True)
            tmp = f"{p}.{os.getpid()}.tmp"
            with open(tmp, "w") as f:
                f.write(data)
            os.replace(tmp, p)
        except OSError:
            pass


def set_init_state(store: Store, v: str) -> None:
    store.set_init_state(v)
    write_marker(store.get_meta("installed_at") or datetime.now(UTC).isoformat(), v)


def lost_fix() -> str:
    return f"run `! {cmd('init --scan')}` (a full scan: nothing is trusted without scanning)"


def _lost(store: Store, marker: dict | None) -> str | None:
    """Markers and state all gone while bawwab is a plugin installed long ago: lost, not a fresh install."""
    if marker is not None or store.get_meta("installed_at") is not None:
        return None
    return fp_module().plugin_lost(str(Path.home()))


def state_problem(store: Store, marker: dict | None) -> str | None:
    """Why bawwab's state can't be trusted (it was wiped, replaced or edited), or None."""
    if marker is None:
        return _lost(store, marker)
    if marker.get("corrupt"):
        return "the install marker (~/.claude/.bawwab-initialised) is unreadable"
    installed = store.get_meta("installed_at")
    if installed is None:
        return "bawwab's state (~/.bawwab) is missing or was reset"
    if installed != marker["installed_at"]:
        return "bawwab's state does not match the install marker"
    if marker.get("init_state") not in (None, store.init_state()):
        return "bawwab's init state was changed outside bawwab"
    return None


def _installed(store: Store, cwd: Path) -> bool:
    """First install: record the install time, take the provisional baseline, write the marker. False if
    bawwab was already installed (marker or db state)."""
    if read_marker() is not None or store.get_meta("installed_at") is not None:
        return False
    if _open_error(store):
        return False  # a db holding an open effects.error is not a fresh install (R38)
    if fp_module().plugin_lost(str(Path.home())):
        return False  # lost state (R37): never re-baselined as a fresh install
    ts = datetime.now(UTC).isoformat()
    take_install_baseline(store, cwd)
    store.set_meta("installed_at", ts)
    write_marker(ts, store.init_state())
    store.audit("install", installed_at=ts)
    return True


def _open_error(store: Store) -> bool:
    """An effects.error quarantine (failed check, lost or replaced state) that is not resolved or approved."""
    return any(q["ident"] == ERROR_IDENT and not store.is_approved(q["key"]) for q in store.active_quarantine())


def _restore_marker(store: Store) -> dict | None:
    marker = read_marker()
    installed = store.get_meta("installed_at")
    if marker is None and installed is not None:  # marker deleted, db intact: put it back
        write_marker(installed, store.init_state())
        store.audit("install.marker_restored")
        marker = read_marker()
    elif marker and state_problem(store, marker) is None and not all(
            os.path.exists(p) for p in fp_module().marker_paths(str(Path.home()))):
        write_marker(installed, store.init_state())  # one copy was removed: put it back while state is good
        store.audit("install.marker_restored")
    return marker


# ------------------------------------------------------------------ semantic state

def _retry_unreadable(fn):
    for attempt in range(3):
        try:
            return fn()
        except UnreadableConfig:
            if attempt == 2:
                raise
            time.sleep(0.1)
    return []  # pragma: no cover


def effect_items(cwd: Path) -> list[EffectItem]:
    """All adapters' items; a watched file caught mid-write is re-read (then the error propagates)."""
    return _retry_unreadable(lambda: [it for a in ADAPTERS for it in a.effect_items(Path(cwd))])


def semantic_state(cwd: Path) -> dict:
    state: dict = {}
    for a in ADAPTERS:
        for cat, items in a.semantic_state(Path(cwd)).items():
            state.setdefault(cat, {}).update(items)
    return state


def _scopes(cwd: Path) -> tuple[str, ...]:
    return ("user", *fp_module()._watch_tables()[0].project_dirs(str(cwd), str(Path.home())))


def take_install_baseline(store: Store, cwd: Path) -> int:
    """The provisional baseline: the state at install time (this project, the user, and every project's
    ~/.claude.json servers). Only the first SessionStart (or init) takes it, never the effect check."""
    items = _retry_unreadable(lambda: [it for a in ADAPTERS for it in a.install_items(Path(cwd))])
    for it in items:
        store.put_effect(it.ident, it.hash, it.scope, "provisional", only_new=True)
    return len(items)


# ------------------------------------------------------------------ evaluation

def _synthetic_key(it: EffectItem) -> str:
    return f"effect:{it.ident}#{it.hash}"


def _unscannable_report(it: EffectItem) -> ScanReport:
    rule = {"hooks": "effects.hook", "exec_settings": "effects.setting", "toggles": "effects.toggle"}.get(
        it.category, "effects.unscannable")
    what = json.dumps(it.value, sort_keys=True, default=str)
    reason = f"{it.label} was added or changed outside a scanned install: {what}"
    return synthetic_report(sanitise(reason, 400), _synthetic_key(it), Target("local", it.ident, name=it.label),
                            rule=rule)


def _scan_item(it: EffectItem, scan, cfg, store: Store) -> ScanReport:
    from bawwab.gate.gate import _materialize  # a lone file (command/agent) is scanned from a temp dir

    st, cleanup = _materialize(it.target, None)
    try:
        return scan(st, mode=cfg.mode, cfg=cfg, store=store, no_cache=st.kind == "remote")
    finally:
        cleanup()


def _gate_approved_entry(store: Store, it: EffectItem) -> bool:
    """R1-I1: the user approved this exact server entry (command, args, env, project dir) at the gate, from a call
    that ended allowed. Any other field, any change, or another project has another hash (or none) and no link."""
    if it.category != "servers" or not it.env_link:
        return False
    try:
        keys = json.loads(store.get_meta(entry_meta_key(it.env_link)) or "[]")
    except ValueError:
        return False
    return isinstance(keys, list) and any(isinstance(k, str) and store.is_approved(k) and not store.is_rejected(k)
                                          for k in keys)


def _batch_approved(store: Store, it: EffectItem) -> bool:
    """Approved as part of an init batch, and unchanged since."""
    row = store.effect_rows_by_ident(it.ident)
    return row is not None and row["status"] == "approved" and row["hash"] == it.hash \
        and row["key"].startswith("effect-batch:") and store.is_approved(row["key"]) \
        and not store.is_rejected(row["key"])


def _accepted_now(store: Store, ident: str, current: dict[str, str]) -> bool:
    row = store.effect_rows_by_ident(ident)
    return row is not None and row["status"] in _ACCEPTED and current.get(ident) == row["hash"]


def _evaluate(it: EffectItem, scan, cfg, store: Store, current: dict[str, str]) -> tuple[bool, ScanReport]:
    """(accepted, report). Accepted: approved (gate, quarantine or baseline) or scanned clean, or bawwab's own
    installed plugin recognised by its running code (R52: accepted, not scanned; `bawwab effects` lists it)."""
    if it.category == "plugins" and it.target is not None and is_self(it.target.path):
        store.audit("effects.self", ident=it.ident, hash=it.hash)
        return True, synthetic_report(f"{it.label}: {SELF_LABEL}", f"{SELF_KEY_PREFIX}{it.hash}",
                                      Target("local", it.ident, name=it.label), rule="effects.self")
    if it.category == "toggles":
        r = _unscannable_report(it)
        if store.is_rejected(r.key):
            return False, r
        off = it.value is False or it.value in ([], None)
        return off or store.is_approved(r.key) or all(_accepted_now(store, i, current) for i in it.requires), r
    # a server held for its env: unscannable unless the user approved this exact entry at the gate, which waives only
    # the hold (R2-I1): the code below is still scanned like any server's
    held = bool(it.env_hold) and not _gate_approved_entry(store, it)
    if it.category in UNSCANNABLE or it.target is None or held:
        r = _unscannable_report(it)
        if store.is_rejected(r.key):
            return False, r
        return store.is_approved(r.key) or _batch_approved(store, it), r
    try:
        r = _scan_item(it, scan, cfg, store)
    except Exception as e:  # noqa: BLE001 - one bad item fails closed on its own
        r = synthetic_report(sanitise(f"could not scan {it.label}: {type(e).__name__}: {e}", 300),
                             _synthetic_key(it), Target("local", it.ident, name=it.label), rule="effects.scan-error")
        return store.is_approved(r.key) and not store.is_rejected(r.key), r
    if store.is_rejected(r.key):
        return False, r
    transient = any(f.source == "gate" and f.rule in TRANSIENT_RULES for f in r.findings)
    if r.verdict == Verdict.CLEAN and not transient:
        return True, r
    if store.is_approved(r.key) or store.get_baseline().get(it.ident) == r.key:
        return True, r
    return False, r


def _is_quarantined(store: Store, it: EffectItem) -> bool:
    return any(q["ident"] == it.ident and q["hash"] == it.hash for q in store.active_quarantine())


def _quarantine(store: Store, it: EffectItem, r: ScanReport) -> str:
    qid = store.create_pending(r)
    store.add_quarantine(qid, it.ident, it.hash, r.key, it.to_dict(), report_to_dict(r))
    store.audit("effects.quarantine", id=qid, ident=it.ident, key=r.key, verdict=r.verdict.value)
    return qid


def _quarantine_batch(store: Store, batch: list[tuple[EffectItem, ScanReport]]) -> str:
    """Install-time hooks and exec settings (other plugins' and tools'): one quarantine id and one approval
    key for all of them, so `init --scan` asks once, not once per item."""
    idents = sorted(f"{it.ident}#{it.hash}" for it, _ in batch)
    key = "effect-batch:" + hashlib.sha256("\n".join(idents).encode()).hexdigest()[:24]
    labels = "; ".join(it.label for it, _ in batch)
    r = synthetic_report(sanitise(f"{len(batch)} hooks and settings that were already in Claude's configuration "
                                  f"when bawwab was installed (nothing to scan): {labels}", 1500),
                         key, Target("local", "init-batch", name="install-time hooks and settings"),
                         rule="effects.batch")
    qid = store.create_pending(r)
    for it, ir in batch:
        store.add_quarantine(qid, it.ident, it.hash, key, it.to_dict(), report_to_dict(ir))
    store.audit("effects.quarantine_batch", id=qid, key=key, idents=[it.ident for it, _ in batch])
    return qid


def _toggles_last(items: list[EffectItem]) -> list[EffectItem]:
    return sorted(items, key=lambda it: it.category == "toggles")


def check_effects(cwd: Path, scan=None, store: Store | None = None) -> list[str]:
    """Compare the semantic state with the accepted one. Returns the quarantine ids created.

    Never takes a baseline: an item that has no accepted row is new and is scanned (or quarantined)."""
    from bawwab.config import load_config

    cwd = Path(cwd)
    scan = scan or scan_target
    store = store or open_store()
    items = effect_items(cwd)
    cfg = load_config(cwd)
    accepted = store.effect_rows(_scopes(cwd))
    active = {(q["ident"], q["hash"]): q for q in store.active_quarantine()}
    current = {it.ident: it.hash for it in items}
    new_ids: list[str] = []
    for it in _toggles_last(items):
        row = accepted.get(it.ident)
        if (row and row["hash"] == it.hash) or (it.ident, it.hash) in active:
            continue
        ok, r = _evaluate(it, scan, cfg, store, current)
        if ok:
            store.put_effect(it.ident, it.hash, it.scope, "accepted", r.key)
            store.audit("effects.accept", ident=it.ident, key=r.key)
        else:
            if row is not None:
                store.drop_effect(it.ident)  # the old content is no longer what is installed
            if not store.is_rejected(r.key) and not blocks(cfg.level, r.verdict):
                _warn_only(store, it, r, cfg.level)
                continue
            new_ids.append(_quarantine(store, it, r))
    for ident in set(accepted) - set(current):
        store.drop_effect(ident)
    for (ident, h), q in active.items():
        if ident != ERROR_IDENT and q["item"] and _in_view(q, cwd) and current.get(ident) != h:
            store.set_quarantine(q["qrow"], status="gone")
    store.audit("effects.check", cwd=str(cwd), items=len(items), quarantined=len(new_ids))
    _sync_flag(store)
    return new_ids


def _warn_only(store: Store, it: EffectItem, r: ScanReport, level: str) -> None:
    """Below the security level's threshold: accept the item as "warned" and tell the user once."""
    store.put_effect(it.ident, it.hash, it.scope, "warned", r.key)
    store.audit("effects.warned", ident=it.ident, key=r.key, verdict=r.verdict.value, level=level)
    q = {"ident": it.ident, "item": json.dumps(it.to_dict())}
    store.add_warning(sanitise(f"⚠ bawwab ({level} level, not blocked): {item_name(q)} is {r.verdict.value} — "
                               f"{_why(q, r.findings)}. To see why: `{cmd('scan')} <target>`; to block such "
                               f"items, raise the level: `{cmd('level high')}`.", 400))


def _in_view(q: dict, cwd: Path) -> bool:
    try:
        return json.loads(q["item"]).get("scope") in _scopes(cwd)
    except (ValueError, AttributeError):
        return False


def _error_quarantine(store: Store, reason: str) -> str | None:
    if any(q["ident"] == ERROR_IDENT and not store.is_approved(q["key"]) for q in store.active_quarantine()):
        return None  # one open effects.error at a time (an approved one no longer counts)
    ts = datetime.now(UTC).isoformat()
    r = synthetic_report(sanitise(f"the effect check failed: {reason}", 300), f"effect:{ERROR_IDENT}#{ts}",
                         Target("local", ERROR_IDENT, name="effect check"), rule=ERROR_IDENT)
    qid = store.create_pending(r)
    store.add_quarantine(qid, ERROR_IDENT, ts, r.key, {}, report_to_dict(r))
    store.audit("effects.error", id=qid, reason=reason)
    return qid


def _fail_closed(store: Store | None, reason: str) -> list[str]:
    """Record a failed check as an effects.error quarantine; without a usable db, raise EffectsFailed."""
    try:
        store = store or open_store()
        qid = _error_quarantine(store, reason)
        _sync_flag(store)
        return [qid] if qid else []
    except Exception as e:  # noqa: BLE001
        _mark_failed(reason)
        raise EffectsFailed(reason) from e


def _active(store: Store | None) -> bool:
    """Bawwab has been installed (first SessionStart): an install marker, or install state in the db."""
    if read_marker() is not None:
        return True
    if fp_module().plugin_lost(str(Path.home())):
        return True  # lost state: the check runs and fails closed
    if not _db_path().exists():
        return False
    return (store or open_store()).get_meta("installed_at") is not None


def refresh(cwd: Path, scan=None, store: Store | None = None, force: bool = False) -> list[str]:
    """Fingerprint first; the semantic comparison (and scans) only when something really changed.

    Before the first SessionStart this does nothing. Missing/replaced state, or a check that fails after a
    change, is recorded as an effects.error quarantine (fail closed) and the stored fingerprint is left
    alone; when even that can't be recorded, EffectsFailed is raised (marker and flag written).
    """
    if not _active(store):
        return []
    fpm = fp_module()
    bh, home, c = str(bawwab_home()), str(Path.home()), str(cwd)
    try:
        store = store or open_store()
        new: list[str] = []
        _take_error_marker(store, new)
        marker = _restore_marker(store)
        problem = state_problem(store, marker)
    except EffectsFailed:
        raise
    except Exception as e:  # noqa: BLE001 - the db itself is unusable
        return _fail_closed(None, sanitise(f"{type(e).__name__}: {e}", 200))
    if problem:
        return new + _fail_closed(store, problem)
    try:
        stored = fpm.load(bh, c)
        fp = fpm.fingerprint(c, home)
        if not force and stored is not None and stored[0] == fp:
            return new
        digest = fpm.semantic_digest(c, home)
        if not force and stored is not None and stored[1] == digest:
            fpm.save(bh, c, fp, digest)
            return new
    except Exception as e:  # noqa: BLE001 - can't tell what changed: check fails closed
        return new + _fail_closed(store, sanitise(f"{type(e).__name__}: {e}", 200))
    try:
        with _lock():
            new += check_effects(Path(cwd), scan, store)
            fpm.save(bh, c, fp, digest)
    except Exception as e:  # noqa: BLE001 - fail closed
        return new + _fail_closed(store, sanitise(f"{type(e).__name__}: {e}", 200))
    return new


def _take_error_marker(store: Store, new: list[str]) -> None:
    m = error_marker()
    if not m.exists():
        return
    try:
        reason = m.read_text()[:200] or "timed out"
    except OSError:
        reason = "timed out"
    qid = _error_quarantine(store, reason)
    if qid:
        new.append(qid)
    m.unlink(missing_ok=True)
    _sync_flag(store)


def retry(cwd: Path, scan=None, store: Store | None = None) -> list[str]:
    """`bawwab effects --retry` (user): repair what can be repaired, clear effects.error, check again.

    Lost state is rebuilt by scanning: with no accepted rows, every installed item is new (scanned)."""
    lp = lock_path()
    if lp.is_symlink() or (lp.exists() and not lp.is_file()):  # e.g. replaced by a directory: wedges the lock
        if lp.is_dir() and not lp.is_symlink():
            shutil.rmtree(lp, ignore_errors=True)
        else:
            lp.unlink(missing_ok=True)
    store = store or open_store()
    marker = read_marker()
    installed = store.get_meta("installed_at")
    if marker is None or marker.get("corrupt") or installed != marker.get("installed_at"):
        ts = installed or (marker or {}).get("installed_at") or datetime.now(UTC).isoformat()
        if marker and not marker.get("corrupt") and marker.get("installed_at"):
            ts = marker["installed_at"]
        store.set_meta("installed_at", ts)
        state = (marker or {}).get("init_state") if marker and not marker.get("corrupt") else None
        if state in ("none", "scanned", "skipped") and state != store.init_state():
            store.set_init_state(state)
        write_marker(ts, store.init_state())
        store.audit("effects.rebuild", installed_at=ts)
    elif marker.get("init_state") != store.init_state():
        write_marker(installed, store.init_state())
    error_marker().unlink(missing_ok=True)
    for q in store.active_quarantine():
        if q["ident"] == ERROR_IDENT:
            store.set_quarantine(q["qrow"], status="resolved")
    _sync_flag(store)
    return refresh(cwd, scan, store, force=True)


# ------------------------------------------------------------------ quarantine

def quarantined(store: Store | None = None) -> list[dict]:
    """Active quarantine entries, after settling approvals and re-issuing expired approval ids."""
    store = store or open_store()
    _take_error_marker(store, [])
    out: list[dict] = []
    reissued: dict[str, str] = {}  # a batch shares one id: re-issue it once
    for q in store.active_quarantine():
        if store.is_approved(q["key"]) and not store.is_rejected(q["key"]):
            store.set_quarantine(q["qrow"], status="approved")
            item = json.loads(q["item"]) if q["item"] else {}
            if q["ident"] != ERROR_IDENT and item.get("scope"):
                store.put_effect(q["ident"], q["hash"], item["scope"], "approved", q["key"])
            store.audit("effects.approved", id=q["id"], ident=q["ident"], key=q["key"])
            continue
        if q["id"] in reissued:
            store.set_quarantine(q["qrow"], qid=reissued[q["id"]])
            q["id"] = reissued[q["id"]]
        elif store.pending_expired(q["id"]):
            try:
                rep = report_from_dict(json.loads(q["report"]))
                if rep.key != q["key"]:  # a batch row: its id stands for the batch report
                    rep = report_from_dict(store.pending_report(q["id"]))
                    if rep.key != q["key"]:
                        raise ValueError(q["key"])
                new_id = store.create_pending(rep)
            except (ValueError, KeyError, TypeError, AttributeError):
                new_id = store.create_pending(synthetic_report("quarantined item", q["key"]))
            store.set_quarantine(q["qrow"], qid=new_id)
            reissued[q["id"]] = new_id
            q["id"] = new_id
        out.append(q)
    _sync_flag(store)
    return out


def find_quarantine(store: Store, qid: str) -> dict | None:
    """The quarantine entry for an id, including an id that was since re-issued (same pending key)."""
    q = store.quarantine_by_id(qid)
    if q is not None:
        return q
    key = store.pending_key(qid)
    return next((x for x in store.active_quarantine() if x["key"] == key), None) if key else None


def reject_quarantined(qid: str, store: Store | None = None) -> tuple[bool, str]:
    """Remove the item (config entry, or move the dir/file to bawwab_home()/quarantine) and record the reject."""
    store = store or open_store()
    q = find_quarantine(store, qid)
    if q is None or q["status"] != "active":
        return False, "not an active quarantine id"
    group = [x for x in store.active_quarantine() if x["id"] == q["id"]] or [q]  # a batch: every item
    done: list[str] = []
    failed: list[str] = []
    for x in group:
        if x["ident"] == ERROR_IDENT:
            ok, msg = True, "dismissed the failed effect check (it runs again on the next tool call)"
        else:
            adapter = adapter_for(x["ident"])
            item = json.loads(x["item"]) if x["item"] else {}
            ok, msg = adapter.remove(item) if adapter else (False, f"no adapter for {x['ident']}")
        if not ok:
            failed.append(msg)
            continue
        store.set_quarantine(x["qrow"], status="rejected")
        store.audit("effects.reject", id=x["id"], ident=x["ident"], result=msg)
        done.append(msg)
    if not done:
        return False, "; ".join(failed)
    if not failed:  # else the rest stay quarantined under the same id, to retry or approve
        store.reject(q["id"])
    _sync_flag(store)
    return True, "; ".join(done + [f"not removed: {m}" for m in failed])


def self_text(store: Store | None = None) -> str:
    """Lines for bawwab's own plugin, accepted as the running code without a scan (shown, never hidden)."""
    store = store or open_store()
    names = sorted(i for i, r in store.all_effect_rows().items() if (r["key"] or "").startswith(SELF_KEY_PREFIX))
    return "\n".join(f"bawwab: {sanitise(i.rsplit(':', 1)[-1], 200)} is {SELF_LABEL}" for i in names)


def _report_of(q: dict) -> tuple[str, list]:
    try:
        rep = report_from_dict(json.loads(q["report"]))
        return rep.verdict.value.upper(), rep.findings
    except (ValueError, KeyError, TypeError):
        return "SUSPICIOUS", []


def _label_of(q: dict) -> str:
    if q["ident"] == ERROR_IDENT:
        return "the effect check itself failed (fail closed)"
    try:
        return json.loads(q["item"]).get("label") or q["ident"]
    except (ValueError, AttributeError):
        return q["ident"]


def item_name(q: dict) -> str:
    """The table's ITEM: "plugin superpowers@mkt" -> "plugin superpowers", "setting env (path)" -> "setting env"."""
    if q["ident"] == ERROR_IDENT:
        return "effect check"
    kind, _, rest = _label_of(q).partition(" ")
    rest = rest.split(" (", 1)[0]
    if kind == "plugin":
        rest = rest.split("@", 1)[0]
    return sanitise(f"{kind} {rest}".strip(), 40)


def _why(q: dict, findings: list) -> str:
    """The table's WHY: the distinct rule titles, most severe first, in a few words."""
    if q["ident"] == ERROR_IDENT:
        return "the effect check itself failed, so nothing is trusted (fail closed)"
    from bawwab.scan.rules.catalog import CATALOG

    titles: list[str] = []
    for f in sorted(findings, key=lambda f: -f.severity.rank):
        info = CATALOG.get(f.rule)
        t = info.title if info else f.rule
        t = t[:1].lower() + t[1:]
        if t not in titles:
            titles.append(t)
    if not titles:
        return "not accepted (no scan result)"
    text = "; ".join(titles[:2])
    if len(titles) > 2:
        text += f" (+{len(titles) - 2} more)"
    return sanitise(text, 90)


def _groups(entries: list[dict]) -> dict[str, list[dict]]:
    groups: dict[str, list[dict]] = {}
    for q in entries:
        groups.setdefault(q["id"], []).append(q)
    return groups


def quarantine_text(entries: list[dict]) -> str:
    """The block message: one row per quarantined item (or install-time batch), the commands once."""
    rows: list[tuple[str, str, str, str]] = []
    keep: list[str] = []
    force: list[str] = []
    for qid, g in _groups(entries).items():
        qid = sanitise(qid, 8)
        if len(g) > 1:
            rows.append((qid, f"{len(g)} existing hooks/settings", "SUSPICIOUS",
                         "set up before bawwab was installed; nothing to scan"))
            keep.append(qid)
            continue
        verdict, findings = _report_of(g[0])
        rows.append((qid, item_name(g[0]), verdict, _why(g[0], findings)))
        (force if verdict == "MALICIOUS" else keep).append(qid)
    n = len(rows)
    head = (f"⛔ bawwab: {n} change{'s' if n != 1 else ''} to Claude's setup {'are' if n != 1 else 'is'} on hold. "
            "Until the user decides, Claude can only read files and ask questions.")
    w_id = max(len("ID"), *(len(r[0]) for r in rows))
    w_item = max(len("ITEM"), *(len(r[1]) for r in rows))
    w_v = max(len("VERDICT"), *(len(r[2]) for r in rows))
    lines = [head, "", f"  {'ID':<{w_id}}  {'ITEM':<{w_item}}  {'VERDICT':<{w_v}}  WHY"]
    lines += [f"  {i:<{w_id}}  {it:<{w_item}}  {v.lower():<{w_v}}  {why}" for i, it, v, why in rows]
    lines.append("")
    if keep:
        lines.append(f"  keep:     ! {cmd('approve')} {' '.join(keep)}")
    if force:
        lines.append(f"  keep (malicious, overrides the block):  ! {cmd('approve --force')} {' '.join(force)}")
    lines.append(f"  remove:   ! {cmd('reject')} <ID>")
    lines.append(f"  details:  ! {cmd('effects')}")
    lines += ["", (
        "For Claude: show the user this message as is, in a code block. Then ask about each item with the "
        "AskUserQuestion tool (at most 4 per call; options Keep, Remove, Not now; name the item and its verdict in "
        "each question). Reply with the exact command lines for their answers, one line per item with its name "
        "as a trailing `# comment`, for the user to run. Never run approve or reject yourself: only the user can.")]
    return "\n".join(lines)


def quarantine_details(entries: list[dict]) -> str:
    """`bawwab effects`: every quarantined item with its findings and evidence, and its own commands."""
    groups = _groups(entries)
    out = [f"bawwab: {len(groups)} item{'s' if len(groups) != 1 else ''} on hold"]
    for qid, g in groups.items():
        qid = sanitise(qid, 8)
        out.append("")
        if len(g) > 1:
            out.append(f"{qid}  {len(g)} hooks and settings that were already configured when bawwab was installed "
                       "(other plugins' and tools'; nothing to scan) — SUSPICIOUS until approved:")
            out += [f"    - {sanitise(_label_of(q), 200)}" for q in g[:MAX_BATCH_SHOWN]]
            if len(g) > MAX_BATCH_SHOWN:
                out.append(f"    … and {len(g) - MAX_BATCH_SHOWN} more")
            name, force = "existing hooks/settings", ""
        else:
            verdict, findings = _report_of(g[0])
            name = item_name(g[0])
            out.append(f"{qid}  {sanitise(_label_of(g[0]), 200)} — {verdict}")
            for f in findings[:MAX_SHOWN_FINDINGS]:
                out.append(f"    [{f.severity.value}] {sanitise(f.rule, 60)}: {sanitise(f.evidence, 200)}")
            if len(findings) > MAX_SHOWN_FINDINGS:
                out.append(f"    … and {len(findings) - MAX_SHOWN_FINDINGS} more")
            force = " --force" if verdict == "MALICIOUS" else ""
        out.append(f"    keep:    ! {cmd('approve')}{force} {qid}  # {name}")
        out.append(f"    remove:  ! {cmd('reject')} {qid}  # {name}")
    return "\n".join(out)


def _deny(reason: str) -> dict:
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def _failed_text() -> str:
    return ("⛔ bawwab: the effect check failed and bawwab's state could not be updated, so tool calls are "
            f"blocked (fail closed). Tell the user to run `! {cmd('effects --retry')}`.")


def pre_tool_decision(tool_name: str, cwd: Path, scan=None, store: Store | None = None) -> dict | None:
    """PreToolUse: run the effect check if the fingerprint moved, then deny while anything is quarantined."""
    try:
        refresh(cwd, scan, store)
    except EffectsFailed as e:
        return None if tool_name in READ_ONLY_TOOLS else _deny(f"{_failed_text()} ({sanitise(str(e), 200)})")
    if tool_name in READ_ONLY_TOOLS:
        return None
    try:
        if store is None and not _db_path().exists():
            return None
        entries = quarantined(store or open_store())
    except Exception as e:  # noqa: BLE001 - can't list it: a known quarantine still blocks
        if fp_module().quarantine_active(str(bawwab_home())):
            return _deny(f"{_failed_text()} ({type(e).__name__})")
        return None
    return _deny(quarantine_text(entries)) if entries else None


def post_tool_decision(cwd: Path, scan=None, store: Store | None = None) -> dict | None:
    """PostToolUse: block (tell Claude at once) when this call's effects put something in quarantine."""
    try:
        new = refresh(cwd, scan, store)
    except EffectsFailed as e:
        return {"decision": "block", "reason": f"{_failed_text()} ({sanitise(str(e), 200)})"}
    if not new:
        return None
    entries = quarantined(store or open_store())
    return {"decision": "block", "reason": quarantine_text(entries)} if entries else None


# ------------------------------------------------------------------ first run

def session_start(cwd: Path, scan=None, store: Store | None = None) -> str | None:
    """SessionStart: first install takes the provisional baseline and asks; later sessions run the effect
    check (changes made between sessions) and report the quarantine. Returns additionalContext or None."""
    store = store or open_store()
    if _installed(store, cwd):
        return ask_context(cwd)
    marker = _restore_marker(store)
    problem = state_problem(store, marker)
    parts: list[str] = []
    if problem and _lost(store, marker):
        _fail_closed(store, problem)
        parts.append(f"bawwab: {problem}. Tool calls are blocked (fail closed). Tell the user to {lost_fix()}; "
                     f"`{cmd('init --skip')}` is refused while the state is lost.")
    elif problem:
        _fail_closed(store, problem)
        parts.append(f"bawwab: {problem}. Tool calls are blocked (fail closed) until the user runs "
                     f"`! {cmd('effects --retry')}` (rebuilds the state by scanning) or `! {cmd('init --scan')}`.")
    else:
        try:
            refresh(cwd, scan, store)
        except EffectsFailed:
            pass
        if store.init_state() == "none":
            parts.append(ask_context(cwd))
        else:
            from bawwab.config import level_is_set

            if not level_is_set():
                parts.append("Bawwab has no security level chosen yet (it is high until then). " + level_question())
    entries = quarantined(store)
    if entries:
        parts.append(quarantine_text(entries))
    return "\n\n".join(parts) or None


WELCOME = ("Welcome to Bawwab (بوّاب, gatekeeper). It checks MCP servers, skills and plugins before Claude installs "
           "them, and holds unscanned changes to Claude's setup until you decide. Claude will now ask you to pick a "
           "security level and whether to scan what is already installed.")


def level_question() -> str:
    """For Claude: how to ask the user for a security level (until one is chosen, the level is high)."""
    return (
        "Ask the user to choose Bawwab's security level (AskUserQuestion; put high first, as recommended):\n"
        "- low: warns about threats, never blocks them\n"
        "- medium: blocks malicious items, warns about suspicious ones\n"
        "- high (recommended, the default): blocks anything not clean until the user approves it\n"
        f"If they pick high, run `{cmd('level high')}` yourself. Medium or low lowers protection, so only the user "
        f"can set it: give them `! {cmd('level medium')}` or `! {cmd('level low')}` to run (you cannot). "
        "Bawwab's self-protection blocks at every level."
    )


def ask_context(cwd: Path) -> str:
    from bawwab.config import level_is_set
    from bawwab.inventory import list_installed

    items = list_installed(cwd)
    n = {k: sum(1 for i in items if i.kind == k) for k in ("mcp", "skill", "plugin")}
    total = len(items)
    secs = total * SECONDS_PER_ITEM
    est = f"about {max(1, round(secs / 60))} min" if secs >= 60 else f"about {secs} s"
    level = "" if level_is_set() else level_question() + "\n\n"
    return (
        "Bawwab (a security scanner for MCP servers, skills and plugins) is installed but has not scanned this machine yet. The user "
        "has seen a welcome message. Before anything else, ask them"
        f"{' (in one AskUserQuestion call)' if level else ''}:\n\n{level}"
        "Ask whether to run a full scan now.\n"
        f"Installed: {n['mcp']} MCP servers, {n['skill']} skills, {n['plugin']} plugins ({total} items). "
        "A full scan downloads each package from its registry (nothing is installed or run), has Claude review "
        f"each item, and takes {est} (~{SECONDS_PER_ITEM} s per item). It runs in the background; results "
        "arrive as warnings, and what happens to anything not clean depends on the security level.\n"
        f"- Yes: run `{cmd('init --scan')}` yourself.\n"
        f"- Skip: the user must run `! {cmd('init --skip')}` (this trusts everything installed now without "
        "scanning; you cannot run it).\n"
        "Until the user answers, this is asked again every session. Changes made from now on are checked either way."
    )


def _repair_for_init(store: Store, cwd: Path) -> None:
    """init after lost state: adopt the marker's install time; clear effects.error (the scan rebuilds)."""
    if _installed(store, cwd):
        return
    marker = read_marker()
    if store.get_meta("installed_at") is None and (marker is None or marker.get("corrupt")):
        # lost state, or an effects.error with no state: nothing is adopted, the full scan rebuilds from nothing
        ts = datetime.now(UTC).isoformat()
        store.set_meta("installed_at", ts)
        write_marker(ts, store.init_state())
        store.audit("install.lost_rebuild", installed_at=ts)
    elif state_problem(store, marker) and marker and not marker.get("corrupt"):
        store.set_meta("installed_at", marker["installed_at"])
    for q in store.active_quarantine():
        if q["ident"] == ERROR_IDENT:
            store.set_quarantine(q["qrow"], status="resolved")
    error_marker().unlink(missing_ok=True)
    _sync_flag(store)


def init_skip(cwd: Path, store: Store | None = None) -> int:
    """`init --skip`: rows recorded at install time become "trusted without scan". Refused on lost state and
    while an effects.error is open (wherever it runs: the check reads the db, not the environment)."""
    store = store or open_store()
    if _open_error(store):  # the state can't be trusted: only a scan may decide what is installed (R38)
        raise RuntimeError("the effect check failed or bawwab's state was lost (effects.error is quarantined); "
                           f"`init --skip` is refused until it is resolved: run `{cmd('init --scan')}` (a full "
                           f"scan) or `{cmd('effects --retry')}`")
    if not _installed(store, cwd):
        marker = _restore_marker(store)
        problem = state_problem(store, marker)
        if problem and _lost(store, marker):
            raise RuntimeError(f"{problem}; {lost_fix().replace('! ', '')}")
        if problem:
            raise RuntimeError(f"{problem}; run `{cmd('effects --retry')}` or `{cmd('init --scan')}`")
    n = store.promote_provisional("unscanned")
    set_init_state(store, "skipped")
    return n


def start_full_scan(cwd: Path, store: Store | None = None) -> None:
    from bawwab import inventory as inv

    store = store or open_store()
    _repair_for_init(store, cwd)
    if store.init_state() != "scanned":
        set_init_state(store, "scanned")
    inv.spawn_background(cwd, full=True)


def full_scan(cwd: Path, scan=None, store: Store | None = None) -> list[str]:
    """`init --scan` / `scan --all` (background child): the Task 10 inventory, then every item in view and
    every provisional (install-time) row is evaluated: accepted when clean or approved, else quarantined.
    Nothing is promoted without a scan (hooks and settings, which have nothing to scan, need approval)."""
    from bawwab.config import load_config
    from bawwab.inventory import run_inventory

    cwd = Path(cwd)
    scan = scan or scan_target
    store = store or open_store()
    _repair_for_init(store, cwd)
    if store.init_state() != "scanned":
        set_init_state(store, "scanned")
    warnings = run_inventory(cwd, scan=scan, store=store)
    cfg = load_config(cwd)
    rows = store.all_effect_rows()
    view = set(_scopes(cwd))
    items: dict[str, EffectItem] = {}
    dirs = [Path(cwd)] + [Path(r["scope"]) for r in rows.values()
                          if r["status"] == "provisional" and r["scope"] != "user" and Path(r["scope"]).is_dir()]
    for d in dict.fromkeys(dirs):
        for a in ADAPTERS:
            for it in _retry_unreadable(lambda a=a, d=d: a.install_items(d)):
                items.setdefault(it.ident, it)
    current = {i: it.hash for i, it in items.items()}
    new_ids: list[str] = []
    batch: list[tuple[EffectItem, ScanReport]] = []
    # no lock while scanning (minutes): the hooks' effect checks must not wait on a background scan
    for it in _toggles_last(list(items.values())):
        row = rows.get(it.ident)
        if row is None and it.scope not in view:
            continue  # another project's item that was never baselined: its own effect check handles it
        if _is_quarantined(store, it):
            continue
        ok, r = _evaluate(it, scan, cfg, store, current)
        if ok:
            store.put_effect(it.ident, it.hash, it.scope, "accepted", r.key)
            continue
        if it.category in BATCHED and row is not None and row["status"] == "provisional" \
                and row["hash"] == it.hash and not store.is_rejected(r.key):
            batch.append((it, r))  # there at install, nothing to scan: one approval for all of them
            continue
        with _lock():  # an effect check may have quarantined it meanwhile
            if not _is_quarantined(store, it):
                store.drop_effect(it.ident)
                new_ids.append(_quarantine(store, it, r))
    if batch:
        with _lock():
            batch = [(it, r) for it, r in batch if not _is_quarantined(store, it)]
            if batch:
                for it, _ in batch:
                    store.drop_effect(it.ident)
                new_ids.append(_quarantine_batch(store, batch))
    for ident, r in store.all_effect_rows().items():
        if r["status"] == "provisional":
            store.drop_effect(ident)  # gone since install: nothing left to trust
    store.audit("effects.full_scan", cwd=str(cwd), warnings=len(warnings), quarantined=len(new_ids))
    _sync_flag(store)
    return new_ids
