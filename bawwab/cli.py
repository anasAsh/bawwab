from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from bawwab.paths import is_bawwab_child
from bawwab.report import explain, format_report, sanitise


class _Parser(argparse.ArgumentParser):
    def error(self, message: str):  # usage errors are exit 3 (2 means "malicious" for scan)
        self.print_usage(sys.stderr)
        print(f"error: {message}", file=sys.stderr)
        raise SystemExit(3)


def _build() -> argparse.ArgumentParser:
    p = _Parser(prog="bawwab", description="Scan MCP servers, skills and plugins before installing them.")
    sub = p.add_subparsers(dest="cmd", required=True, parser_class=_Parser)
    s = sub.add_parser("scan", help="scan a package, repo, path or remote MCP URL")
    s.add_argument("target", nargs="?")
    s.add_argument("--all", action="store_true", help="re-scan everything installed (in the background)")
    s.add_argument("--deep", action="store_true", help="also run the sandbox")
    s.add_argument("--no-cache", action="store_true", help="ignore cached results and rescan")
    s.add_argument("--json", action="store_true", help="print the report as JSON")
    a = sub.add_parser("approve", help="approve a blocked install")
    a.add_argument("id")
    a.add_argument("--force", action="store_true", help="override a malicious verdict")
    r = sub.add_parser("reject", help="reject a pending install")
    r.add_argument("id")
    e = sub.add_parser("explain", help="explain a finding")
    e.add_argument("id")
    d = sub.add_parser("diff", help="show what changed since the trusted snapshot")
    d.add_argument("name", help="trust name (e.g. npm:pkg) or a target spec")
    sub.add_parser("gate", help="PreToolUse hook: read hook JSON on stdin, print a decision (always exits 0)")
    i = sub.add_parser("inventory", help="SessionStart hook: scan installed items in the background")
    i.add_argument("--background", action="store_true", help="run the scan in this process (used by the hook's child)")
    i.add_argument("--full", action="store_true", help=argparse.SUPPRESS)
    i.add_argument("--cwd", help="project directory (default: from hook JSON on stdin, else the current directory)")
    n = sub.add_parser("init", allow_abbrev=False, help="first run: scan everything now, or trust it without a scan")
    g = n.add_mutually_exclusive_group()
    g.add_argument("--scan", action="store_true", help="scan everything installed, in the background")
    g.add_argument("--skip", action="store_true", help="trust everything installed now without scanning (user only)")
    n.add_argument("--cwd", help="project directory (default: the current directory)")
    sub.add_parser("notify", help="UserPromptSubmit hook: print queued warnings")
    sub.add_parser("post", help="PostToolUse hook: run the effect check, block when something was quarantined")
    fx = sub.add_parser("effects", help="check Claude's config for unscanned changes and list the quarantine")
    fx.add_argument("--cwd", help="project directory (default: the current directory)")
    fx.add_argument("--retry", action="store_true",
                    help="after a failed check or lost state: repair, rebuild by scanning, clear the error (user)")
    return p


_EXIT = {"clean": 0, "suspicious": 1, "malicious": 2}


def _spec(spec: str) -> str:
    """A bare relative path like tests/x that exists on disk is a local target, not an npm name."""
    if "/" in spec and not spec.startswith(("@", ".", "/", "~")) and ":" not in spec and Path(spec).exists():
        return "./" + spec
    return spec


def _start_full_scan(cwd: Path) -> None:
    from bawwab.effects import start_full_scan

    start_full_scan(cwd)
    print("bawwab: full scan started in the background. Results arrive as warnings; anything not clean is "
          "quarantined (tools are blocked) until the user approves or rejects it.")


def _init(args) -> int:
    cwd = Path(args.cwd) if args.cwd else Path.cwd()
    if args.scan:
        _start_full_scan(cwd)
        return 0
    if args.skip:
        from bawwab.effects import init_skip

        try:
            n = init_skip(cwd)
        except RuntimeError as e:
            print(f"error: {sanitise(str(e), 300)}", file=sys.stderr)
            return 1
        print(f"bawwab: {n} installed items accepted as trusted without scan; only later changes are checked. "
              "Run `bawwab scan --all` to scan them at any time.")
        return 0
    from bawwab.effects import ask_context
    from bawwab.store import open_store

    print(f"bawwab: init state is {open_store().init_state()}.\n{ask_context(cwd)}")
    return 0


def _scan(args) -> int:
    if args.all:
        _start_full_scan(Path.cwd())
        return 0
    if not args.target:
        print("error: give a target to scan, or --all", file=sys.stderr)
        return 3
    from bawwab.config import load_config
    from bawwab.fetch import parse_target
    from bawwab.scan import scan_target
    from bawwab.store import open_store, report_to_dict
    from bawwab.types import Mode, Verdict

    cfg = load_config(Path.cwd())
    store = open_store()
    report = scan_target(
        parse_target(_spec(args.target)), mode=Mode.DEEP if args.deep else cfg.mode, cfg=cfg, store=store, no_cache=args.no_cache
    )
    pid = store.create_pending(report) if report.verdict != Verdict.CLEAN else None
    if args.json:
        d = report_to_dict(report)
        d["approval_id"] = pid
        print(json.dumps(d, indent=2))
    else:
        print(format_report(report, pid))
    return _EXIT[report.verdict.value]


def _decide(args) -> int:
    from bawwab.store import open_store

    from bawwab import effects

    store = open_store()
    q = effects.find_quarantine(store, args.id)
    if args.cmd == "approve":
        ok, msg = store.approve(args.id, force=args.force)
        verb = "approved"
        if ok and q is not None:
            effects.quarantined(store)  # settle it now: the gate stops blocking at once
    elif q is not None and q["status"] == "active":
        ok, msg = effects.reject_quarantined(args.id, store)
        verb = "rejected and removed:"
    else:
        ok, msg = store.reject(args.id)
        verb = "rejected"
    print(f"{verb} {sanitise(msg, 300)}" if ok else f"error: {sanitise(msg, 300)}")
    return 0 if ok else 1


def _gate() -> int:
    """Hook entry point. Always exits 0; prints hook JSON or nothing."""
    if is_bawwab_child():
        return 0
    try:
        data = json.loads(sys.stdin.read())
    except (ValueError, OSError):
        return 0
    if not isinstance(data, dict):
        return 0
    _note_session(data)
    ti = data.get("tool_input")
    raw = (str(data.get("tool_name") or ""), ti if isinstance(ti, dict) else {}, str(data.get("cwd") or os.getcwd()))
    try:  # effect check + quarantine first: while anything is quarantined, only read-only tools run
        from bawwab.effects import pre_tool_decision

        out = pre_tool_decision(raw[0], Path(raw[2]))
    except Exception as e:  # noqa: BLE001 - a bawwab bug: blocks only if the config changed or is quarantined
        out = _effects_bug(raw[0], Path(raw[2]), e, post=False)
    if out is not None:
        print(json.dumps(out))
        return 0
    try:
        from bawwab.gate.gate import HookInput, run_gate

        out = run_gate(HookInput(*raw))
    except Exception as e:  # noqa: BLE001 - run_gate should not raise; fail closed for installs only
        try:
            from bawwab.gate.detect import HookInput, detect_install

            install = detect_install(HookInput(*raw)) is not None
        except Exception:  # noqa: BLE001
            install = True  # the hook pre-filter already matched; the gate itself is broken
        out = None
        if install:
            reason = f"bawwab error: {sanitise(f'{type(e).__name__}: {e}', 300)}"
            out = {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                          "permissionDecisionReason": reason}}
    if out is not None:
        print(json.dumps(out))
    return 0


def _note_session(data: object) -> None:
    """Hook input's session_id for the lost-state check (see hooks/bawwab_hook.py)."""
    sid = data.get("session_id") if isinstance(data, dict) else None
    if isinstance(sid, str) and sid:
        os.environ["BAWWAB_SESSION_ID"] = sid
    else:
        os.environ.pop("BAWWAB_SESSION_ID", None)


def _hook_cwd(arg: str | None) -> Path:
    if arg:
        return Path(arg)
    try:
        if not sys.stdin.isatty():
            data = json.loads(sys.stdin.read())
            _note_session(data)
            if isinstance(data, dict) and isinstance(data.get("cwd"), str) and data["cwd"]:
                return Path(data["cwd"])
    except (ValueError, OSError):
        pass
    return Path.cwd()


def _inventory(args) -> int:
    """SessionStart: start the scan detached, print what earlier scans queued. Always exits 0."""
    if is_bawwab_child():
        return 0
    try:
        from bawwab import inventory as inv

        cwd = _hook_cwd(args.cwd)
        if args.background:
            return inv.background(cwd, full=args.full)
        from bawwab.effects import session_start
        from bawwab.store import open_store

        store = open_store()
        ctx = session_start(cwd, store=store)
        if store.init_state() == "none":  # first run: ask the user before scanning anything
            if ctx:
                print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": ctx}}))
            return 0
        inv.spawn_background(cwd)
        warnings = store.take_warnings()
        parts = [ctx] if ctx else []
        if warnings:
            parts.append(inv.hook_output("SessionStart", warnings)["hookSpecificOutput"]["additionalContext"])
        if parts:
            print(json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart",
                                                     "additionalContext": "\n\n".join(parts)}}))
    except Exception:  # noqa: BLE001 - never break session start
        pass
    return 0


def _notify() -> int:
    """UserPromptSubmit: print queued warnings once. Always exits 0."""
    if is_bawwab_child():
        return 0
    try:
        from bawwab.inventory import hook_output
        from bawwab.store import open_store

        warnings = open_store().take_warnings()
        if warnings:
            print(json.dumps(hook_output("UserPromptSubmit", warnings)))
    except Exception:  # noqa: BLE001
        pass
    return 0


def _effects_bug(tool: str, cwd: Path, e: Exception, post: bool) -> dict | None:
    """An unexpected error in the effect check: fail closed when the watched config changed (or a quarantine
    is known), else stay out of the way (a non-install call is never blocked by a bawwab error)."""
    try:
        from bawwab import effects
        from bawwab.paths import bawwab_home

        fpm = effects.fp_module()
        home, bh = str(Path.home()), str(bawwab_home())
        if not fpm.initialised(home, bh):
            return None
        changed = fpm.check(str(cwd), home, bh) == "changed"
        known = fpm.quarantine_active(bh)
    except Exception:  # noqa: BLE001 - can't tell: fail closed
        changed, known = True, True
    if not changed and not (known and not post):
        return None
    reason = f"bawwab: the effect check failed ({sanitise(f'{type(e).__name__}: {e}', 200)}); tool calls are " \
             "blocked (fail closed) until the user runs `! bawwab effects --retry`"
    if changed:
        try:
            from bawwab import effects

            effects._mark_failed(reason)
        except Exception:  # noqa: BLE001
            pass
    if post:
        return {"decision": "block", "reason": reason}
    if tool in ("Read", "Grep", "Glob", "LS", "TodoWrite", "NotebookRead"):
        return None
    return {"hookSpecificOutput": {"hookEventName": "PreToolUse", "permissionDecision": "deny",
                                   "permissionDecisionReason": reason}}


def _hook_json() -> dict | None:
    try:
        data = json.loads(sys.stdin.read())
    except (ValueError, OSError):
        return None
    _note_session(data)
    return data if isinstance(data, dict) else None


def _post() -> int:
    """PostToolUse hook. Always exits 0; prints {"decision": "block", ...} when something new is quarantined."""
    if is_bawwab_child():
        return 0
    data = _hook_json()
    if data is None:
        return 0
    try:
        from bawwab.effects import post_tool_decision

        out = post_tool_decision(Path(str(data.get("cwd") or os.getcwd())))
    except Exception as e:  # noqa: BLE001 - a bawwab bug: blocks only if the config changed
        out = _effects_bug(str(data.get("tool_name") or ""), Path(str(data.get("cwd") or os.getcwd())), e, post=True)
    if out is not None:
        print(json.dumps(out))
    return 0


def _effects(args) -> int:
    from bawwab import effects

    cwd = Path(args.cwd) if args.cwd else Path.cwd()
    if args.retry:
        effects.retry(cwd)
    else:
        effects.refresh(cwd, force=True)
    entries = effects.quarantined()
    if not entries:
        print("bawwab: nothing is quarantined")
        return 0
    print(effects.quarantine_text(entries))
    return 1


def main(argv: list[str] | None = None) -> int:
    try:
        args = _build().parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 3
    if args.cmd == "gate":
        return _gate()
    if args.cmd == "inventory":
        return _inventory(args)
    if args.cmd == "notify":
        return _notify()
    if args.cmd == "post":
        return _post()
    try:
        if args.cmd == "effects":
            return _effects(args)
        if args.cmd == "init":
            return _init(args)
        if args.cmd == "scan":
            return _scan(args)
        if args.cmd in ("approve", "reject"):
            return _decide(args)
        from bawwab.store import open_store

        if args.cmd == "diff":
            from bawwab.trust import diff_since_trusted

            for line in diff_since_trusted(_spec(args.name), open_store()).splitlines():
                print(sanitise(line, 300))
            return 0
        out = explain(args.id, open_store())
        print(out)
        return 1 if out.startswith("unknown finding id") else 0
    except Exception as e:  # noqa: BLE001 - never show a traceback
        print(f"error: {sanitise(f'{type(e).__name__}: {e}', 300)}", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
