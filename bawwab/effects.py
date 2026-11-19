"""Effect check (spec §1b): watch what actually changed in the agent's config and install dirs.

The PreToolUse gate parses commands, but it can't fully understand bash. This module compares the semantic
state (servers, plugins, hooks, code-running settings, skills/commands/agents) with the accepted state; a
new or changed item is accepted when its content was approved or scanned clean, and is otherwise
quarantined: every tool call except read-only ones is denied until the user approves or rejects it.

First run (spec §1a) lives here too: the provisional baseline, `init --scan`/`--skip`, `scan --all`.
"""
from __future__ import annotations

import fcntl
import importlib.util
import json
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from bawwab.agents import ADAPTERS, UNSCANNABLE, EffectItem, adapter_for
from bawwab.agents.claude_code import UnreadableConfig
from bawwab.paths import bawwab_home
from bawwab.report import sanitise
from bawwab.scan import TRANSIENT_RULES, scan_target, synthetic_report
from bawwab.store import Store, open_store, report_from_dict, report_to_dict
from bawwab.types import ScanReport, Target, Verdict

READ_ONLY_TOOLS = frozenset({"Read", "Grep", "Glob", "LS", "TodoWrite", "NotebookRead"})
ERROR_IDENT = "effects.error"
MAX_SHOWN_FINDINGS = 5
SECONDS_PER_ITEM = 20
_FP_FILE = Path(__file__).resolve().parent.parent / "hooks" / "fingerprint.py"
_fp_mod = None


# ------------------------------------------------------------------ files shared with the hook

def fp_module():
    """hooks/fingerprint.py, loaded by path (the hook loads the same file)."""
    global _fp_mod
    if _fp_mod is None:
        spec = importlib.util.spec_from_file_location("_bawwab_fingerprint", _FP_FILE)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        _fp_mod = mod
    return _fp_mod


def flag_path() -> Path:
    return bawwab_home() / "quarantine.flag"


def error_marker() -> Path:
    """Written by the hook when the effect check timed out; turned into an effects.error quarantine."""
    return bawwab_home() / "effects.error"


def _sync_flag(store: Store) -> None:
    try:
        if store.active_quarantine():
            flag_path().parent.mkdir(parents=True, exist_ok=True)
            flag_path().touch()
        else:
            flag_path().unlink(missing_ok=True)
    except OSError:
        pass


@contextmanager
def _lock():
    p = bawwab_home() / "effects.lock"
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(p, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


# ------------------------------------------------------------------ semantic state

def effect_items(cwd: Path) -> list[EffectItem]:
    """All adapters' items; a watched file caught mid-write is re-read (then the error propagates)."""
    for attempt in range(3):
        try:
            return [it for a in ADAPTERS for it in a.effect_items(Path(cwd))]
        except UnreadableConfig:
            if attempt == 2:
                raise
            time.sleep(0.1)
    return []  # pragma: no cover


def semantic_state(cwd: Path) -> dict:
    state: dict = {"servers": {}, "plugins": {}, "hooks": {}, "exec_settings": {}, "skills": {}}
    for a in ADAPTERS:
        for cat, items in a.semantic_state(Path(cwd)).items():
            state.setdefault(cat, {}).update(items)
    return state


def _scopes(cwd: Path) -> tuple[str, str]:
    return "user", str(cwd)


def ensure_provisional(store: Store, cwd: Path, items: list[EffectItem] | None = None) -> int:
    """Before init, the first state seen for a scope (user, or this project) is its provisional baseline."""
    if store.init_state() != "none":
        return 0
    todo = [s for s in _scopes(cwd) if store.get_meta(f"provisional:{s}") is None]
    if not todo:
        return 0
    items = effect_items(cwd) if items is None else items
    n = 0
    for it in items:
        if it.scope in todo:
            store.put_effect(it.ident, it.hash, it.scope, "provisional", only_new=True)
            n += 1
    for s in todo:
        store.set_meta(f"provisional:{s}", datetime.now(UTC).isoformat())
    return n


# ------------------------------------------------------------------ evaluation

def _synthetic_key(it: EffectItem) -> str:
    return f"effect:{it.ident}#{it.hash}"


def _unscannable_report(it: EffectItem) -> ScanReport:
    rule = {"hooks": "effects.hook", "exec_settings": "effects.setting"}.get(it.category, "effects.unscannable")
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


def _evaluate(it: EffectItem, scan, cfg, store: Store) -> tuple[bool, ScanReport]:
    """(accepted, report). Accepted: approved (gate, quarantine or baseline) or scanned clean."""
    if it.category in UNSCANNABLE or it.target is None:
        r = _unscannable_report(it)
        return store.is_approved(r.key) and not store.is_rejected(r.key), r
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


def check_effects(cwd: Path, scan=None, store: Store | None = None) -> list[str]:
    """Compare the semantic state with the accepted one. Returns the quarantine ids created."""
    from bawwab.config import load_config

    cwd = Path(cwd)
    scan = scan or scan_target
    store = store or open_store()
    items = effect_items(cwd)
    ensure_provisional(store, cwd, items)
    cfg = load_config(cwd)
    accepted = store.effect_rows(_scopes(cwd))
    active = {(q["ident"], q["hash"]): q for q in store.active_quarantine()}
    current = {it.ident: it.hash for it in items}
    new_ids: list[str] = []
    for it in items:
        row = accepted.get(it.ident)
        if (row and row["hash"] == it.hash) or (it.ident, it.hash) in active:
            continue
        ok, r = _evaluate(it, scan, cfg, store)
        if ok:
            store.put_effect(it.ident, it.hash, it.scope, "accepted", r.key)
            store.audit("effects.accept", ident=it.ident, key=r.key)
        else:
            new_ids.append(_quarantine(store, it, r))
    for ident in set(accepted) - set(current):
        store.drop_effect(ident)
    for (ident, h), q in active.items():
        if ident != ERROR_IDENT and q["item"] and _in_view(q, cwd) and current.get(ident) != h:
            store.set_quarantine(q["qrow"], status="gone")
    store.audit("effects.check", cwd=str(cwd), items=len(items), quarantined=len(new_ids))
    _sync_flag(store)
    return new_ids


def _in_view(q: dict, cwd: Path) -> bool:
    try:
        return json.loads(q["item"]).get("scope") in _scopes(cwd)
    except (ValueError, AttributeError):
        return False


def _error_quarantine(store: Store, reason: str) -> str | None:
    if any(q["ident"] == ERROR_IDENT for q in store.active_quarantine()):
        return None
    ts = datetime.now(UTC).isoformat()
    r = synthetic_report(sanitise(f"the effect check failed: {reason}", 300), f"effect:{ERROR_IDENT}#{ts}",
                         Target("local", ERROR_IDENT, name="effect check"), rule=ERROR_IDENT)
    qid = store.create_pending(r)
    store.add_quarantine(qid, ERROR_IDENT, ts, r.key, {}, report_to_dict(r))
    store.audit("effects.error", id=qid, reason=reason)
    return qid


def refresh(cwd: Path, scan=None, store: Store | None = None, force: bool = False) -> list[str]:
    """Fingerprint first; the semantic comparison (and scans) only when something really changed.

    Never raises for a failed check: that is recorded as an effects.error quarantine (fail closed), and the
    stored fingerprint is left alone so the next call checks again.
    """
    store = store or open_store()
    fpm = fp_module()
    bh, home, c = str(bawwab_home()), str(Path.home()), str(cwd)
    new: list[str] = []
    with _lock():
        _take_error_marker(store, new)
        stored = fpm.load(bh, c)
        fp = fpm.fingerprint(c, home)
        if not force and stored is not None and stored[0] == fp:
            _sync_flag(store)
            return new
        digest = fpm.semantic_digest(c, home)
        if not force and stored is not None and stored[1] == digest:
            fpm.save(bh, c, fp, digest)
            _sync_flag(store)
            return new
        try:
            new += check_effects(Path(cwd), scan, store)
        except Exception as e:  # noqa: BLE001 - fail closed
            qid = _error_quarantine(store, sanitise(f"{type(e).__name__}: {e}", 200))
            new += [qid] if qid else []
            _sync_flag(store)
            return new
        fpm.save(bh, c, fp, digest)
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


# ------------------------------------------------------------------ quarantine

def quarantined(store: Store | None = None) -> list[dict]:
    """Active quarantine entries, after settling approvals and re-issuing expired approval ids."""
    store = store or open_store()
    _take_error_marker(store, [])
    out: list[dict] = []
    for q in store.active_quarantine():
        if store.is_approved(q["key"]) and not store.is_rejected(q["key"]):
            store.set_quarantine(q["qrow"], status="approved")
            item = json.loads(q["item"]) if q["item"] else {}
            if q["ident"] != ERROR_IDENT and item.get("scope"):
                store.put_effect(q["ident"], q["hash"], item["scope"], "approved", q["key"])
            store.audit("effects.approved", id=q["id"], ident=q["ident"], key=q["key"])
            continue
        if store.pending_expired(q["id"]):
            try:
                new_id = store.create_pending(report_from_dict(json.loads(q["report"])))
            except (ValueError, KeyError, TypeError):
                new_id = store.create_pending(synthetic_report("quarantined item", q["key"]))
            store.set_quarantine(q["qrow"], qid=new_id)
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
    item = json.loads(q["item"]) if q["item"] else {}
    if q["ident"] == ERROR_IDENT:
        ok, msg = True, "dismissed the failed effect check (it runs again on the next tool call)"
    else:
        adapter = adapter_for(q["ident"])
        if adapter is None:
            return False, f"no adapter for {q['ident']}"
        ok, msg = adapter.remove(item)
        if not ok:
            return False, msg
    store.reject(q["id"])
    store.set_quarantine(q["qrow"], status="rejected")
    store.audit("effects.reject", id=q["id"], ident=q["ident"], result=msg)
    _sync_flag(store)
    return True, msg


def _summary(q: dict) -> str:
    try:
        rep = report_from_dict(json.loads(q["report"]))
        verdict, findings = rep.verdict.value.upper(), rep.findings
    except (ValueError, KeyError, TypeError):
        verdict, findings = "SUSPICIOUS", []
    try:
        label = json.loads(q["item"]).get("label") or q["ident"]
    except (ValueError, AttributeError):
        label = q["ident"]
    if q["ident"] == ERROR_IDENT:
        label = "the effect check itself failed (fail closed)"
    lines = [f"• {sanitise(label, 200)} — {verdict}"]
    for f in findings[:MAX_SHOWN_FINDINGS]:
        lines.append(f"    [{f.severity.value}] {sanitise(f.rule, 60)}: {sanitise(f.evidence, 200)}")
    if len(findings) > MAX_SHOWN_FINDINGS:
        lines.append(f"    … and {len(findings) - MAX_SHOWN_FINDINGS} more")
    qid = sanitise(q["id"], 8)
    force = " --force" if verdict == "MALICIOUS" else ""
    lines.append(f"    keep it:  ! bawwab approve {qid}{force}      remove it:  ! bawwab reject {qid}")
    return "\n".join(lines)


def quarantine_text(entries: list[dict]) -> str:
    head = (
        "⛔ bawwab: quarantine — these items were added or changed in Claude's configuration and were not "
        "accepted (not scanned clean, not approved). Every tool except Read, Grep, Glob, LS, TodoWrite and "
        "NotebookRead is blocked until the user decides. Tell the user; only they can run these commands."
    )
    return head + "\n" + "\n".join(_summary(q) for q in entries)


def pre_tool_decision(tool_name: str, cwd: Path, scan=None, store: Store | None = None) -> dict | None:
    """PreToolUse: run the effect check if the fingerprint moved, then deny while anything is quarantined."""
    store = store or open_store()
    refresh(cwd, scan, store)
    if tool_name in READ_ONLY_TOOLS:
        return None
    entries = quarantined(store)
    if not entries:
        return None
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": quarantine_text(entries)}}


def post_tool_decision(cwd: Path, scan=None, store: Store | None = None) -> dict | None:
    """PostToolUse: block (tell Claude at once) when this call's effects put something in quarantine."""
    store = store or open_store()
    new = refresh(cwd, scan, store)
    if not new:
        return None
    entries = quarantined(store)
    return {"decision": "block", "reason": quarantine_text(entries)} if entries else None


# ------------------------------------------------------------------ first run

def ask_context(cwd: Path) -> str:
    from bawwab.inventory import list_installed

    items = list_installed(cwd)
    n = {k: sum(1 for i in items if i.kind == k) for k in ("mcp", "skill", "plugin")}
    total = len(items)
    secs = total * SECONDS_PER_ITEM
    est = f"about {max(1, round(secs / 60))} min" if secs >= 60 else f"about {secs} s"
    return (
        "Bawwab (a security scanner for MCP servers, skills and plugins) is installed but has not scanned this "
        "machine yet. Before anything else, ask the user whether to run a full scan now.\n"
        f"Installed: {n['mcp']} MCP servers, {n['skill']} skills, {n['plugin']} plugins ({total} items). "
        "A full scan downloads each package from its registry (nothing is installed or run), has Claude review "
        f"each item, and takes {est} (~{SECONDS_PER_ITEM} s per item). It runs in the background; results "
        "arrive as warnings, and anything not clean is quarantined until the user decides.\n"
        "- Yes: run `bawwab init --scan` yourself.\n"
        "- Skip: the user must run `! bawwab init --skip` (this trusts everything installed now without "
        "scanning; you cannot run it).\n"
        "Until the user answers, this question is asked again every session. Changes made from now on are "
        "checked either way."
    )


def init_skip(cwd: Path, store: Store | None = None) -> int:
    store = store or open_store()
    ensure_provisional(store, cwd)
    n = store.promote_provisional("unscanned")
    store.set_init_state("skipped")
    return n


def full_scan(cwd: Path, scan=None, store: Store | None = None) -> list[str]:
    """`init --scan` / `scan --all` (background child): the Task 10 inventory, then every item is accepted
    (clean or approved) or quarantined. Pre-existing hooks and settings, which have nothing to scan, are
    kept as "trusted without scan"."""
    from bawwab.config import load_config
    from bawwab.inventory import run_inventory

    cwd = Path(cwd)
    scan = scan or scan_target
    store = store or open_store()
    ensure_provisional(store, cwd)
    if store.init_state() == "none":
        store.set_init_state("scanned")
    warnings = run_inventory(cwd, scan=scan, store=store)
    cfg = load_config(cwd)
    rows = store.effect_rows(_scopes(cwd))
    new_ids: list[str] = []
    # no lock while scanning (minutes): the hooks' effect checks must not wait on a background scan
    for it in effect_items(cwd):
        row = rows.get(it.ident)
        same = row is not None and row["hash"] == it.hash
        if (it.category in UNSCANNABLE or it.target is None) and same:
            if row["status"] == "provisional":
                store.put_effect(it.ident, it.hash, it.scope, "unscanned", row["key"])
            continue
        if _is_quarantined(store, it):
            continue
        ok, r = _evaluate(it, scan, cfg, store)
        if ok:
            store.put_effect(it.ident, it.hash, it.scope, "accepted", r.key)
            continue
        with _lock():  # an effect check may have quarantined it meanwhile
            if not _is_quarantined(store, it):
                new_ids.append(_quarantine(store, it, r))
    store.promote_provisional("unscanned")  # other scopes' provisional rows: not scanned here
    store.audit("effects.full_scan", cwd=str(cwd), warnings=len(warnings), quarantined=len(new_ids))
    _sync_flag(store)
    return new_ids
