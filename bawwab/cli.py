from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

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
    s.add_argument("target")
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
    return p


_EXIT = {"clean": 0, "suspicious": 1, "malicious": 2}


def _spec(spec: str) -> str:
    """A bare relative path like tests/x that exists on disk is a local target, not an npm name."""
    if "/" in spec and not spec.startswith(("@", ".", "/", "~")) and ":" not in spec and Path(spec).exists():
        return "./" + spec
    return spec


def _scan(args) -> int:
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

    store = open_store()
    if args.cmd == "approve":
        ok, msg = store.approve(args.id, force=args.force)
        verb = "approved"
    else:
        ok, msg = store.reject(args.id)
        verb = "rejected"
    print(f"{verb} {sanitise(msg, 300)}" if ok else f"error: {sanitise(msg, 300)}")
    return 0 if ok else 1


def _gate() -> int:
    """Hook entry point. Always exits 0; prints hook JSON or nothing."""
    if os.environ.get("BAWWAB_CHILD", "") not in ("", "0"):
        return 0
    try:
        data = json.loads(sys.stdin.read())
    except (ValueError, OSError):
        return 0
    if not isinstance(data, dict):
        return 0
    ti = data.get("tool_input")
    raw = (str(data.get("tool_name") or ""), ti if isinstance(ti, dict) else {}, str(data.get("cwd") or os.getcwd()))
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


def main(argv: list[str] | None = None) -> int:
    try:
        args = _build().parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 3
    if args.cmd == "gate":
        return _gate()
    try:
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
