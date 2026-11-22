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
import shlex
import shutil
import tempfile
from collections.abc import Callable
from pathlib import Path

from bawwab.clicmd import cmd
from bawwab.config import DEFAULT_LEVEL, load_config
from bawwab.config import blocks as blocks_at
from bawwab.envkeys import entry_meta_key
from bawwab.gate.detect import _APPROVAL, HookInput, Protected, Targets, detect_install, install_dir
from bawwab.gate.pin import pin_changes, pins_needed
from bawwab.gate.prefilter import prefilter
from bawwab.report import FOR_CLAUDE, decision_lines, distinct_findings, sanitise, sanitise_lines, table, why_text
from bawwab.scan import scan_target, synthetic_report
from bawwab.selfid import is_self_path, other_build
from bawwab.store import Store, open_store
from bawwab.types import ScanReport, Target, Verdict

__all__ = ["HookInput", "decision", "protected_key", "run_gate"]

_KEY_FIELDS = {
    "Bash": ("command",),
    "Write": ("file_path", "content"),
    "Edit": ("file_path", "old_string", "new_string", "replace_all"),
    "MultiEdit": ("file_path", "edits"),
    "NotebookEdit": ("notebook_path", "cell_id", "new_source", "cell_type", "edit_mode"),
}


class SymlinkInPath(Exception):
    pass


def decision(kind: str, reason: str, updated: dict | None = None) -> dict:
    out = {"hookEventName": "PreToolUse", "permissionDecision": kind, "permissionDecisionReason": reason}
    if updated is not None:
        out["updatedInput"] = updated
    return {"hookSpecificOutput": out}


def protected_key(inp: HookInput, reason: str = "", bind: tuple | list = ()) -> str:
    """Bound to the effective action (not description/timeout) and to the protected reason. bind: server entry hashes
    (envkeys.server_entry_hash, which include the project dir) of the env-loader reasons in it, so such an approval is
    per project (R3-I1). Empty for every other protected action: their keys are unchanged."""
    ti = inp.tool_input if isinstance(inp.tool_input, dict) else {}
    fields = _KEY_FIELDS.get(inp.tool_name)
    material = {k: ti.get(k) for k in fields} if fields else ti
    body = {"tool_name": inp.tool_name, "tool_input": material, "reason": reason}
    if bind:
        body["entries"] = sorted(set(bind))
    canon = json.dumps(
        body,
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


def _kind_segment(src: Path) -> Path | None:
    """For a path inside Claude's commands or agents dir: that path from the kind dir down (commands/x.md,
    agents/ns). The scanned copy keeps it, so the text rules see a command/agent document (Task 15 I1)."""
    hit = install_dir(str(src))
    if hit is None or hit[0] not in ("commands", "agents"):
        return None
    return Path(hit[0], os.path.relpath(src, hit[1]))


def _materialize(t: Target, overlay: dict[str, str] | None) -> tuple[Target, Callable[[], None]]:
    """A scannable copy: the target dir with overlaid new content, or a lone file in a temp dir. Inside Claude's
    commands or agents dir the copy keeps the path from that dir down (<tmp>/t/commands/x.md)."""
    src = Path(t.path) if t.kind == "local" and t.path else None
    if src is None or (not overlay and not src.is_file()):
        return t, lambda: None
    tmp = Path(tempfile.mkdtemp(prefix="bawwab-gate-"))
    try:
        keep = _kind_segment(src)
        if keep is not None:
            top = tmp / "t"
            dst = top / keep if src.is_dir() or overlay else top / keep.parent
        else:
            top = dst = tmp / (src.name or "target")
        if overlay:
            if src.is_dir():
                shutil.copytree(src, dst, symlinks=True)
            else:
                dst.mkdir(parents=True)
            for fpath, content in overlay.items():
                rel = os.path.relpath(fpath, src)
                out = _safe_dest(dst, rel)
                parent = out.parent
                parent.mkdir(parents=True, exist_ok=True)
                _safe_dest(dst, rel)  # re-check after creating parents
                out.write_text(content)
        else:
            dst.mkdir(parents=True)
            shutil.copy2(src, dst / src.name, follow_symlinks=False)
    except BaseException:
        shutil.rmtree(tmp, ignore_errors=True)
        raise
    name = t.name or str(src)
    return (Target("local", t.raw, name=name, path=str(top), origin=t.origin or str(src)),
            lambda: shutil.rmtree(tmp, ignore_errors=True))


def _item(t: Target, r: ScanReport, names: dict[Target, str]) -> str:
    """How a block names what was scanned: the server's config name (`claude mcp add <name>`), a package with its
    resolved version, a URL, or a local directory's own name (never the temp copy's path)."""
    if t in names:
        return sanitise(f"{names[t]} (MCP server)", 60)
    if t.kind in ("npm", "pypi", "docker") and t.name:
        return sanitise(f"{t.name}@{r.resolved_version}", 60)
    if t.kind == "local":
        path = os.path.normpath(t.origin or t.path or t.raw or ".")
        mf = Path(t.path or path) / ".claude-plugin" / "plugin.json"
        try:  # a plugin dir: the name its manifest gives (what /plugin lists), as untrusted text; a regular file only
            if mf.is_file() and not mf.is_symlink() and mf.stat().st_size <= 65536:
                with open(mf, encoding="utf-8", errors="replace") as f:
                    manifest = json.loads(f.read(65536))
                if isinstance(manifest, dict) and isinstance(manifest.get("name"), str) and manifest["name"].strip():
                    return sanitise(f"{manifest['name']} (plugin)", 60)
        except (OSError, ValueError, RecursionError):
            pass
        return sanitise(os.path.basename(path) or path, 60)
    return sanitise(t.url or t.name or t.raw, 60)


def _item_rows(held: list[tuple[str, str, ScanReport]]) -> list[str]:
    return table([(pid, name, r.verdict.value.upper(), why_text(r.findings))  # every rule title, not just one per line
                  for pid, name, r in held])


def _held_block(held: list[tuple[str, str, ScanReport]], level: str) -> str:
    """One line per blocked item (id, name, verdict, top reason), then the commands once; the findings are behind
    `bawwab explain <id>`. The verdict and, for MALICIOUS, the --force override stay in view."""
    ids = " ".join(pid for pid, _, _ in held)
    what = "this install" if len(held) == 1 else f"{len(held)} items in this call"
    lines = [f"⛔ bawwab blocked {what} (security level {level}):", *_item_rows(held)]
    lines += decision_lines([(pid, name, r.verdict == Verdict.MALICIOUS) for pid, name, r in held], f"explain {ids}")
    lines.append(f"  {FOR_CLAUDE}")
    return "\n".join(lines)


def _warned_text(warned: list[tuple[str, str, ScanReport]], level: str) -> str:
    """Below the level's threshold: one warning with real lines (each sanitised on its own), nothing blocked."""
    ids = " ".join(pid for pid, _, _ in warned)
    what = "this install is" if len(warned) == 1 else f"{len(warned)} items in this call are"
    lines = [f"⚠ bawwab ({level} level, not blocked): {what} not clean", *_item_rows(warned),
             f"  details:  ! {cmd(f'explain {ids}')}    to block such items:  ! {cmd('level high')}"]
    return "\n".join(lines)


def _bawwab_call(inp: HookInput) -> tuple[str, str] | None:
    """(what it does, the command the user runs) for a call to one of bawwab's user-only subcommands, named from a
    fixed vocabulary (no argument of the call is echoed except a level name), or None when it can't be read."""
    import shlex

    ti = inp.tool_input if isinstance(inp.tool_input, dict) else {}
    try:
        words = shlex.split(str(ti.get("command") or ""))
    except ValueError:
        return None
    for i, w in enumerate(words):
        if os.path.basename(w) != "bawwab":
            continue
        rest = [a for a in words[i + 1:] if not a.startswith("-")]
        flags = [a for a in words[i + 1:] if a.startswith("-")]
        sub = rest[0] if rest else ""
        if sub == "level" and len(rest) > 1 and rest[1] in ("low", "medium"):
            return "lowering the security level", f"level {rest[1]}"
        if sub == "init" and any(f.startswith("--sk") for f in flags):
            return "trusting everything installed without a scan", "init --skip"
        if sub == "effects" and any(f.startswith("--re") for f in flags):
            return "clearing a failed effect check", "effects --retry"
        if sub in ("approve", "reject"):
            return f"{'approving' if sub == 'approve' else 'rejecting'} what bawwab holds", ""
        return None
    return None


def _user_only_block(reasons: list[str], inp: HookInput | None = None) -> str:
    shown = sanitise("; ".join(reasons), 400)
    writes = [r for r in reasons if r.startswith(("writes ", "in text written to a file"))]
    about_call = all(_APPROVAL in r for r in reasons)
    named = _bawwab_call(inp) if inp is not None and about_call and not writes else None
    if named is not None:  # one plain refusal under its real name
        what, args = named
        line = f"⛔ bawwab: refused — {what} is the user's decision; Claude can't run it, by any name or path."
        return line + (f"\nIf the user wants it, they run:  ! {cmd(args)}" if args else "")
    lines = [f"⛔ bawwab: refused — {shown}."]
    if writes:
        lines.append("This writes bawwab's user-only command into a file. Bawwab doesn't let Claude do that, and "
                     "there is nothing to approve: the user must run that command themselves; Claude shouldn't "
                     "write it into files.")
    if len(writes) < len(reasons):
        lines.append("This would run bawwab's user-only command. Bawwab doesn't let Claude run that, and there is "
                     "nothing to approve: the user must run it themselves, in their own terminal, if they want it.")
    return "\n".join(lines)


def _build_block(t: Target, differ: list[str], pid: str) -> str:
    """Another build of bawwab copied into an install dir (selfid.other_build): still an approval, in one line.
    Its scan of bawwab's own source (always SUSPICIOUS) stays one command away."""
    shown = ", ".join(differ[:3]) + (", …" if len(differ) > 3 else "")
    n = len(differ)
    return (f"⛔ bawwab: this installs a different build of Bawwab ({n} file{'s' if n != 1 else ''} differ: "
            f"{sanitise(shown, 200)}), which replaces the hooks that protect you. Keep it only if you built it.\n"
            f"To allow:  ! {cmd('approve')} {sanitise(pid)}   Its scan:  ! {cmd('scan')} "
            f"{shlex.quote(sanitise(t.origin or t.path or '', 300))}")


def _protected_block(inp: HookInput, reason: str, store: Store, bind: tuple | list = ()) -> tuple[str | None, str]:
    """(deny text or None when approved, key)."""
    key = protected_key(inp, reason, bind)
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


def _link_entries(store: Store, entries: list[tuple[str, str]], reason: str, key: str) -> None:
    """R1-I1: a protected server-env reason in this block: record that approving `key` also covers that exact server
    entry, so the effect check accepts it once (bawwab/envkeys.py; effects._gate_approved_entry)."""
    parts = reason.split("; ")
    for r, h in entries:
        if r not in parts:
            continue
        mk = entry_meta_key(h)
        try:
            linked = json.loads(store.get_meta(mk) or "[]")
        except ValueError:
            linked = []
        if not isinstance(linked, list):
            linked = []
        if key not in linked:
            store.set_meta(mk, json.dumps((linked + [key])[-16:]))


def _scan_all(inp: HookInput, det: Targets, scan: Callable[..., ScanReport], store: Store,
              protected: list[str]) -> list[tuple[Target, ScanReport]]:
    cfg = load_config(Path(inp.cwd) if inp.cwd else None)
    results: list[tuple[Target, ScanReport]] = []
    for t in det.targets:
        if t.kind == "local" and is_self_path(t.origin or t.path):
            continue  # R53: bawwab never scans itself on its own hooks (`bawwab scan <path>` still does)
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
    if isinstance(det, Protected):
        approvable = det.reason if det.approvable is None else det.approvable
        protected = [approvable] if approvable else []
    else:
        protected = list(det.protected)
    if det.plain and any(_APPROVAL in r for r in det.plain):
        # the same bawwab call is refused plainly (R57: the user runs it): a pending approval for it as well would
        # be an id that can't make the call pass. One refusal, no id.
        protected = [p for p in protected if p != _APPROVAL]
    results = _scan_all(inp, det, scan, store, protected) if isinstance(det, Targets) else []
    blocks: list[str] = []
    keys: list[str] = []
    links: list[tuple[str, str]] = []
    for reason in protected:
        parts = reason.split("; ")
        bind = [h for r, h in det.env_entries if r in parts]
        text, key = _protected_block(inp, reason, store, bind)
        keys.append(key)
        links.append((reason, key))
        if text:
            blocks.append(text)
    if det.plain:  # R57: a plain deny; no pending approval, and no `bawwab approve` to suggest
        blocks.append(_user_only_block(det.plain, inp))
    cfg = load_config(Path(inp.cwd) if inp.cwd else None) if results else None
    level = cfg.level if cfg else DEFAULT_LEVEL
    names = det.names if isinstance(det, Targets) else {}
    named = det.items if isinstance(det, Targets) else {}
    held: list[tuple[str, str, ScanReport]] = []
    warned: list[tuple[str, str, ScanReport]] = []
    passed: list[tuple[Target, str, ScanReport]] = []
    for t, r in results:
        keys.append(r.key)
        name = _item(t, r, names)
        build = other_build(t.origin or t.path) if t.kind == "local" and r.verdict == Verdict.SUSPICIOUS else None
        # a non-clean verdict's approval is per item: each server name this install creates needs it, not just
        # the code (two servers running the same code are two decisions); unnamed targets bind on first use
        items = named.get(t) or None
        approved = r.verdict != Verdict.CLEAN and (all(store.is_approved(r.key, (i,)) for i in items) if items
                                                   else store.is_approved(r.key))
        if store.is_rejected(r.key):
            blocks.append(f"⛔ bawwab: previously rejected — {name}: {r.verdict.value.upper()} — "
                          f"{why_text(distinct_findings(r.findings))}. The user rejected it; it stays blocked.")
        elif build and not approved:  # self-protection: held at every level, in one line
            blocks.append(_build_block(t, build, store.create_pending(r)))
        elif r.verdict != Verdict.CLEAN and not approved:
            # the id names it in the block and opens its full report (`bawwab explain <id>`)
            pid = sanitise(store.create_pending(r, items=items))
            (held if blocks_at(level, r.verdict) else warned).append((pid, name, r))
        else:
            passed.append((t, name, r))
    if held:
        blocks.append(_held_block(held, level))
    warnings = [_warned_text(warned, level)] if warned else []
    if blocks:
        return decision("deny", "\n\n".join(blocks + warnings)), keys
    for _, _, r in warned:  # told here, at the call: the effect check's own warning for it would repeat it
        _mark_told(store, r.key)
    # R2-I1: link only from a call that ends allowed (every protected reason approved, every target clean/approved)
    for reason, key in links:
        _link_entries(store, det.env_entries, reason, key)
    if isinstance(det, Targets) and det.pinnable:
        resolved = {t: r.resolved_version for t, r in results}
        try:
            updated, changes = pin_changes(inp, resolved)
        except Exception:  # noqa: BLE001 - see below: a needed pin that fails goes to the user
            try:
                needed = pins_needed(resolved)
            except Exception:  # noqa: BLE001 - can't tell whether a pin was needed: assume it was
                needed = [("the package", "the scanned version")]
            if needed:
                # The scan was of one resolved version; the unpinned call may run another (spec §1 "Version
                # pinning"). Bawwab never emits allow, and a broken rewrite is our failure, not the package's,
                # so "ask" without updatedInput: the user sees the unpinned command and decides.
                wanted = ", ".join(f"{name} to {version}" for name, version in needed)
                note = "scanned clean" if not warnings else "not blocked at this level"
                out = decision("ask", sanitise(
                    f"bawwab: {note}, but could not pin {wanted}; the command as written may install a "
                    f"different version than the one scanned", 500))
                return (_with_warning(out, warnings) if warnings else out), keys
            updated, changes = None, []
        if updated is not None and changes:
            pinned = ", ".join(f"{name} to {version}" for name, version in changes)
            note = "scanned clean" if not warnings else "not blocked at this level"
            out = decision("ask", sanitise(f"bawwab: {note}; pinned {pinned}", 500), updated)
            return (_with_warning(out, warnings) if warnings else out), keys
    if warnings:
        return _with_warning(None, warnings), keys
    return _scanned_note(det, passed, cfg), keys


def _scanned_note(det: Targets | Protected, passed: list[tuple[Target, str, ScanReport]], cfg) -> dict | None:
    """After an install the gate scanned and let through: one line for the user (systemMessage only, nothing for
    Claude), so a pass reads as "scanned", not as "never looked". Only installs: an edit of a skill's files (an
    overlay) stays silent, and so does every call the gate doesn't scan. config.json "quiet": true hides it."""
    if not passed or cfg is None or cfg.quiet or not isinstance(det, Targets):
        return None
    shown = [(name, r) for t, name, r in passed if t not in det.overlays]
    if not shown:
        return None
    parts = [f"{name}: {'clean' if r.verdict == Verdict.CLEAN else 'approved earlier'}" for name, r in shown[:4]]
    more = f"; and {len(shown) - 4} more" if len(shown) > 4 else ""
    return {"systemMessage": sanitise(f"bawwab: scanned {'; '.join(parts)}{more}", 300),
            "hookSpecificOutput": {"hookEventName": "PreToolUse"}}


TOLD_PREFIX = "told:gate:"  # meta: the gate warned about this report key at the call (effects._warn_only skips it)


def _mark_told(store: Store, key: str) -> None:
    try:
        store.set_meta(TOLD_PREFIX + key, "1")
    except Exception:  # noqa: BLE001 - at worst the effect check warns a second time
        pass


def _with_warning(out: dict | None, warnings: list[str]) -> dict:
    """A warning for the user (systemMessage) and for Claude (additionalContext), with no allow/deny of its own:
    Claude Code's normal permission rules still decide the call. It is said here once: not queued for the next
    prompt as well."""
    text = sanitise_lines("\n\n".join(warnings))[:4000]
    out = dict(out or {"hookSpecificOutput": {"hookEventName": "PreToolUse"}})
    out["systemMessage"] = text
    out["hookSpecificOutput"] = {**out["hookSpecificOutput"], "additionalContext": text}
    return out


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
    kind = out["hookSpecificOutput"].get("permissionDecision", "warn") if out else "none"
    _audit(store, "gate.decision", decision=kind, keys=keys, tool_name=inp.tool_name)
    return out
