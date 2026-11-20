"""run_gate: turn a PreToolUse hook input into a decision.

The gate never emits "allow" (that would bypass Claude Code's own permission
prompt for the whole call). Clean or approved installs get no output; when
the call is rewritten to pin a version it gets "ask" with updatedInput, so the
normal permission flow still decides. Everything else is "deny".
"""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

from bawwab.clicmd import cmd
from bawwab.config import load_config
from bawwab.gate.detect import HookInput, Protected, Targets, detect_install
from bawwab.gate.pin import pin_changes
from bawwab.gate.prefilter import prefilter
from bawwab.report import format_report, sanitise
from bawwab.scan import scan_target, synthetic_report
from bawwab.store import Store, open_store
from bawwab.types import ScanReport, Target, Verdict

__all__ = ["HookInput", "decision", "protected_key", "run_gate"]

_KEY_FIELDS = {
    "Bash": ("command",),
    "Write": ("file_path", "content"),
    "Edit": ("file_path", "old_string", "new_string", "replace_all"),
    "MultiEdit": ("file_path", "edits"),
}


class SymlinkInPath(Exception):
    pass


def decision(kind: str, reason: str, updated: dict | None = None) -> dict:
    out = {"hookEventName": "PreToolUse", "permissionDecision": kind, "permissionDecisionReason": reason}
    if updated is not None:
        out["updatedInput"] = updated
    return {"hookSpecificOutput": out}


def protected_key(inp: HookInput, reason: str = "") -> str:
    """Bound to the effective action (not description/timeout) and to the protected reason."""
    ti = inp.tool_input if isinstance(inp.tool_input, dict) else {}
    fields = _KEY_FIELDS.get(inp.tool_name)
    material = {k: ti.get(k) for k in fields} if fields else ti
    canon = json.dumps(
        {"tool_name": inp.tool_name, "tool_input": material, "reason": reason},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str,
    )
    return "protected:" + hashlib.sha256(canon.encode()).hexdigest()[:16]


def _audit(store: Store | None, event: str, **fields) -> None:
    try:
        (store or open_store()).audit(event, **fields)
    except Exception:  # noqa: BLE001 - auditing must never change the decision
        pass


def _safe_dest(root: Path, rel: str) -> Path:
    """root/rel, refusing any symlink on the way (from root down) and any escape from root."""
    parts = Path(rel).parts
    if not parts or Path(rel).is_absolute() or ".." in parts:
        raise SymlinkInPath(rel)
    cur = root
    for part in parts:
        cur = cur / part
        if cur.is_symlink():
            raise SymlinkInPath(rel)
    real_root = os.path.realpath(root)
    if not os.path.realpath(cur).startswith(real_root.rstrip("/") + "/"):
        raise SymlinkInPath(rel)
    return cur


def _materialize(t: Target, overlay: dict[str, str] | None) -> tuple[Target, Callable[[], None]]:
    """A scannable copy: the target dir with overlaid new content, or a lone file in a temp dir."""
    src = Path(t.path) if t.kind == "local" and t.path else None
    if src is None or (not overlay and not src.is_file()):
        return t, lambda: None
    tmp = Path(tempfile.mkdtemp(prefix="bawwab-gate-"))
    try:
        dst = tmp / (src.name or "target")
        if overlay:
            if src.is_dir():
                shutil.copytree(src, dst, symlinks=True)
            else:
                dst.mkdir()
            for fpath, content in overlay.items():
                rel = os.path.relpath(fpath, src)
                out = _safe_dest(dst, rel)
                parent = out.parent
                parent.mkdir(parents=True, exist_ok=True)
                _safe_dest(dst, rel)  # re-check after creating parents
                out.write_text(content)
        else:
            dst.mkdir()
            shutil.copy2(src, dst / src.name, follow_symlinks=False)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    name = t.name or str(src)
    return Target("local", t.raw, name=name, path=str(dst)), lambda: shutil.rmtree(tmp, ignore_errors=True)


def _label(r: ScanReport) -> str:
    t = r.target
    return sanitise(f"{t.name or t.url or t.path or t.raw}@{r.resolved_version}", 200)


def _protected_block(inp: HookInput, reason: str, store: Store) -> tuple[str | None, str]:
    """(deny text or None when approved, key)."""
    key = protected_key(inp, reason)
    shown = sanitise(reason, 300)
    if store.is_rejected(key):
        return f"⛔ bawwab: previously rejected — protected action ({shown})", key
    if store.is_approved(key):
        return None, key
    r = synthetic_report(reason, key, Target("local", key, name="protected action"), rule="gate.protected")
    pid = store.create_pending(r)
    return (
        f"⛔ bawwab: blocked a protected action — {shown}\n"
        f"Blocked pending your approval. To allow:  ! {cmd('approve')} {sanitise(pid)}"
    ), key


def _scan_all(inp: HookInput, det: Targets, scan: Callable[..., ScanReport], store: Store,
              protected: list[str]) -> list[tuple[Target, ScanReport]]:
    cfg = load_config(Path(inp.cwd) if inp.cwd else None)
    results: list[tuple[Target, ScanReport]] = []
    for t in det.targets:
        try:
            st, cleanup = _materialize(t, det.overlays.get(t))
        except SymlinkInPath:
            protected.append(f"symlink in skill path: {t.path}")
            continue
        try:
            r = scan(st, mode=cfg.mode, cfg=cfg, store=store)
        finally:
            cleanup()
        results.append((t, r))
    return results


def _decide(inp: HookInput, det: Targets | Protected, scan: Callable[..., ScanReport],
            store: Store) -> tuple[dict | None, list[str]]:
    protected = [det.reason] if isinstance(det, Protected) else list(det.protected)
    results = _scan_all(inp, det, scan, store, protected) if isinstance(det, Targets) else []
    blocks: list[str] = []
    keys: list[str] = []
    for reason in protected:
        text, key = _protected_block(inp, reason, store)
        keys.append(key)
        if text:
            blocks.append(text)
    for _, r in results:
        keys.append(r.key)
        if store.is_rejected(r.key):
            blocks.append(f"⛔ bawwab: previously rejected — {_label(r)}\n{format_report(r)}")
        elif r.verdict != Verdict.CLEAN and not store.is_approved(r.key):
            blocks.append(format_report(r, store.create_pending(r)))
    if blocks:
        return decision("deny", "\n\n".join(blocks)), keys
    if isinstance(det, Targets) and det.pinnable:
        try:
            updated, changes = pin_changes(inp, {t: r.resolved_version for t, r in results})
        except Exception:  # noqa: BLE001 - a failed rewrite never blocks; just no pin
            updated, changes = None, []
        if updated is not None and changes:
            pinned = ", ".join(f"{name} to {version}" for name, version in changes)
            return decision("ask", sanitise(f"bawwab: scanned clean; pinned {pinned}", 500), updated), keys
    return None, keys


def run_gate(inp: HookInput, scan: Callable[..., ScanReport] | None = None, store: Store | None = None) -> dict | None:
    """Hook JSON ("deny", or "ask" with a pinned updatedInput) for an install-like call, or None."""
    try:
        det = detect_install(inp)
    except Exception as e:  # noqa: BLE001 - incl. MemoryError/RecursionError
        _audit(store, "gate.detect_error", tool_name=inp.tool_name, error=sanitise(f"{type(e).__name__}: {e}", 300))
        # R23: a detection failure never blocks an ordinary call, but never lets an install-like one through
        try:
            install_like = prefilter({"tool_name": inp.tool_name, "tool_input": inp.tool_input, "cwd": inp.cwd})
        except Exception:  # noqa: BLE001 - can't tell: fail closed
            install_like = True
        return decision("deny", "bawwab error: could not analyse command") if install_like else None
    if det is None:
        return None
    keys: list[str] = []
    try:
        store = store or open_store()
        out, keys = _decide(inp, det, scan or scan_target, store)
    except Exception as e:  # noqa: BLE001 - fail closed for install-like calls
        out = decision("deny", f"bawwab error: {sanitise(f'{type(e).__name__}: {e}', 300)}")
    kind = out["hookSpecificOutput"]["permissionDecision"] if out else "none"
    _audit(store, "gate.decision", decision=kind, keys=keys, tool_name=inp.tool_name)
    return out
