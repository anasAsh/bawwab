"""run_gate: turn a PreToolUse hook input into an allow / deny decision."""
from __future__ import annotations

import hashlib
import json
import os
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

from bawwab.config import load_config
from bawwab.gate.detect import HookInput, Protected, Targets, detect_install
from bawwab.gate.pin import pin_input
from bawwab.report import format_report, sanitise
from bawwab.scan import scan_target, synthetic_report
from bawwab.store import Store, open_store
from bawwab.types import ScanReport, Target, Verdict

__all__ = ["HookInput", "decision", "protected_key", "run_gate"]


def decision(kind: str, reason: str, updated: dict | None = None) -> dict:
    out = {"hookEventName": "PreToolUse", "permissionDecision": kind, "permissionDecisionReason": reason}
    if updated is not None:
        out["updatedInput"] = updated
    return {"hookSpecificOutput": out}


def protected_key(inp: HookInput) -> str:
    canon = json.dumps(
        {"tool_name": inp.tool_name, "tool_input": inp.tool_input},
        sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str,
    )
    return "protected:" + hashlib.sha256(canon.encode()).hexdigest()[:16]


def _audit(store: Store | None, event: str, **fields) -> None:
    try:
        (store or open_store()).audit(event, **fields)
    except Exception:  # noqa: BLE001 - auditing must never change the decision
        pass


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
                if rel.startswith(".."):
                    raise ValueError(f"overlay outside target: {fpath}")
                out = dst / rel
                out.parent.mkdir(parents=True, exist_ok=True)
                if out.is_symlink():
                    out.unlink()
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


def _protected(inp: HookInput, det: Protected, store: Store) -> tuple[dict, list[str]]:
    key = protected_key(inp)
    reason = sanitise(det.reason, 300)
    if store.is_rejected(key):
        return decision("deny", f"⛔ bawwab: previously rejected — protected action ({reason})"), [key]
    if store.is_approved(key):
        return decision("allow", f"bawwab: approved protected action ({reason})"), [key]
    r = synthetic_report(det.reason, key, Target("local", key, name="protected action"), rule="gate.protected")
    pid = store.create_pending(r)
    text = (
        f"⛔ bawwab: blocked a protected action — {reason}\n"
        f"Blocked pending your approval. To allow:  ! bawwab approve {sanitise(pid)}"
    )
    return decision("deny", text), [key]


def _targets(inp: HookInput, det: Targets, scan: Callable[..., ScanReport], store: Store) -> tuple[dict, list[str]]:
    cfg = load_config(Path(inp.cwd) if inp.cwd else None)
    results: list[tuple[Target, ScanReport]] = []
    for t in det.targets:
        st, cleanup = _materialize(t, det.overlays.get(t))
        try:
            r = scan(st, mode=cfg.mode, cfg=cfg, store=store)
        finally:
            cleanup()
        results.append((t, r))
    keys = [r.key for _, r in results]
    blocks: list[str] = []
    allowed: list[str] = []
    for _, r in results:
        if store.is_rejected(r.key):
            blocks.append(f"⛔ bawwab: previously rejected — {_label(r)}\n{format_report(r)}")
        elif r.verdict == Verdict.CLEAN:
            allowed.append(f"bawwab: clean — {_label(r)}")
        elif store.is_approved(r.key):
            allowed.append(f"bawwab: approved — {_label(r)}")
        else:
            blocks.append(format_report(r, store.create_pending(r)))
    if blocks:
        return decision("deny", "\n\n".join(blocks)), keys
    updated = None
    if det.pinnable:
        try:
            updated = pin_input(inp, {t: r.resolved_version for t, r in results})
        except Exception:  # noqa: BLE001 - a failed rewrite never blocks an allowed install
            updated = None
    return decision("allow", "\n".join(allowed), updated), keys


def run_gate(inp: HookInput, scan: Callable[..., ScanReport] | None = None, store: Store | None = None) -> dict | None:
    """Hook JSON for an install-like call, or None to make no decision."""
    try:
        det = detect_install(inp)
    except Exception as e:  # noqa: BLE001 - detection bugs never block ordinary calls
        _audit(store, "gate.detect_error", tool_name=inp.tool_name, error=sanitise(f"{type(e).__name__}: {e}", 300))
        return None
    if det is None:
        return None
    keys: list[str] = []
    try:
        store = store or open_store()
        if isinstance(det, Protected):
            out, keys = _protected(inp, det, store)
        else:
            out, keys = _targets(inp, det, scan or scan_target, store)
    except Exception as e:  # noqa: BLE001 - fail closed for install-like calls
        out = decision("deny", f"bawwab error: {sanitise(f'{type(e).__name__}: {e}', 300)}")
    _audit(store, "gate.decision", decision=out["hookSpecificOutput"]["permissionDecision"], keys=keys,
           tool_name=inp.tool_name)
    return out
