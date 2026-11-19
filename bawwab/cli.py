from __future__ import annotations

import argparse
import json
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


def main(argv: list[str] | None = None) -> int:
    try:
        args = _build().parse_args(argv)
    except SystemExit as e:
        return e.code if isinstance(e.code, int) else 3
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
