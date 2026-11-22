from __future__ import annotations

import argparse
import json
import os
import shlex
import sys
from pathlib import Path

from bawwab.clicmd import cmd
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
    a.add_argument("id", nargs="+", help="one or more ids")
    a.add_argument("--force", action="store_true", help="override a malicious verdict")
    r = sub.add_parser("reject", help="reject a pending install")
    r.add_argument("id", nargs="+", help="one or more ids")
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
    lv = sub.add_parser("level", help="show or set the security level: low (warn only), medium (block malicious), "
                                      "high (block anything not clean; the default)")
    lv.add_argument("value", nargs="?", choices=("low", "medium", "high"))
    sub.add_parser("notify", help="UserPromptSubmit hook: print queued warnings")
    sub.add_parser("post", help="PostToolUse hook: run the effect check, block when something was quarantined")
    fx = sub.add_parser("effects", help="check Claude's config for unscanned changes and list the quarantine")
    fx.add_argument("--cwd", help="project directory (default: the current directory)")
    fx.add_argument("--retry", action="store_true",
                    help="after a failed check or lost state: repair, rebuild by scanning, clear the error (user)")
    w = sub.add_parser("watch", help="watch every coding agent's config: scan new or changed MCP servers, skills and "
                                     "extensions, put what is not clean on hold, notify (foreground; --install for a "
                                     "user service)")
    w.add_argument("--once", action="store_true", help="one pass now (no debounce), then exit")
    w.add_argument("--interval", type=float, default=2.0, help="seconds between passes (default 2)")
    w.add_argument("--debounce", type=float, default=1.5, help="seconds a change must settle before it is checked")
    w.add_argument("--project", action="append", default=None, metavar="DIR",
                   help="also watch this project's config (repeatable; default: config.json watch.projects)")
    w.add_argument("--agent", action="append", default=None, metavar="NAME",
                   help="only these agents (claude-code, cursor, codex, claude-desktop, vscode)")
    w.add_argument("--no-notify", action="store_true", help="no desktop notifications")
    wg = w.add_mutually_exclusive_group()
    wg.add_argument("--install", action="store_true", help="install the watcher as a user service and start it")
    wg.add_argument("--uninstall", action="store_true", help="stop and remove the user service")
    w.add_argument("--unit-dir", help=argparse.SUPPRESS)  # tests: write the unit here, never start it
    sub.add_parser("status", help="what is quarantined or on hold, across every agent, and the watcher's state")
    ae = sub.add_parser("allow-env", help="let commands in a repo set BAWWAB_HOME to a dir inside it, for tests "
                                         "(user only; never a nested claude)")
    ae.add_argument("repo", nargs="?", help="the repo dir (default: list the allowed ones)")
    ae.add_argument("--remove", action="store_true", help="take the repo off the list")
    ae.add_argument("--list", action="store_true", help="list the allowed repos")
    sb = sub.add_parser("sandbox", help="deep mode: build the Docker sandbox image, or check that it can run")
    sb.add_argument("action", choices=("build", "check"))
    st = sub.add_parser("setup", help="plugin: sync bawwab's own dependencies now and show any error")
    sg = st.add_mutually_exclusive_group()
    sg.add_argument("--retry", action="store_true", help="retry a failed or stuck setup (the default)")
    sg.add_argument("--link", action="store_true",
                    help="put a `bawwab` command in ~/.local/bin or ~/bin, so messages print `bawwab …` (user only)")
    sg.add_argument("--unlink", action="store_true", help="remove the command --link wrote")
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
              f"Run `{cmd('scan --all')}` to scan them at any time.")
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


LEVEL_HELP = {
    "low": "warns about threats but never blocks them",
    "medium": "blocks malicious items, warns about suspicious ones",
    "high": "blocks anything that is not clean until you approve it",
}


def _level(args) -> int:
    from bawwab.config import level_is_set, load_config, set_level

    if args.value is None:
        level = load_config(Path.cwd()).level
        chosen = "" if level_is_set() else " (the default: no level chosen yet)"
        print(f"bawwab: security level {level}{chosen}: {LEVEL_HELP[level]}.")
        return 0
    set_level(args.value)
    print(f"bawwab: security level set to {args.value}: {LEVEL_HELP[args.value]}. "
          "Bawwab's self-protection blocks at every level.")
    return 0


def _decide(args) -> int:
    """approve/reject each id in turn; prints what each one was, by name."""
    from bawwab.store import open_store

    from bawwab import effects

    store = open_store()
    failed = 0
    for qid in dict.fromkeys(args.id):
        q = effects.find_quarantine(store, qid)
        name = effects.decision_name(store, q) if q is not None else None
        if args.cmd == "approve":
            ok, msg = store.approve(qid, force=args.force)
            verb = "approved"
            if ok and q is not None:
                effects.quarantined(store)  # settle it now: the gate stops blocking at once
                if q["status"] == effects.HELD:
                    effects.quarantined(store, effects.HELD)
        elif q is not None and q["status"] in ("active", effects.HELD):
            ok, msg = effects.reject_quarantined(qid, store)
            verb = "rejected and removed"
        else:
            ok, msg = store.reject(qid)
            verb = "rejected"
        what = f"{name} ({sanitise(qid, 8)})" if name else sanitise(msg, 300)
        if not ok:
            failed += 1
            print(f"error: {sanitise(qid, 8)}: {sanitise(msg, 300)}")
        elif verb == "rejected and removed":
            print(f"{verb}: {what} — {sanitise(msg, 300)}")
        else:
            print(f"{verb} {what}")
    return 1 if failed else 0


def _gate() -> int:
    """Hook entry point. Always exits 0; prints hook JSON or nothing."""
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
    try:
        from bawwab import inventory as inv

        cwd = _hook_cwd(args.cwd)
        if args.background:
            return inv.background(cwd, full=args.full)
        from bawwab.effects import session_start
        from bawwab.store import open_store

        store = open_store()
        ctx = session_start(cwd, store=store)
        if store.init_state() == "none":  # first run: welcome the user, ask before scanning anything
            if ctx:
                from bawwab.effects import WELCOME

                print(json.dumps({"systemMessage": WELCOME,
                                  "hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": ctx}}))
            return 0
        inv.spawn_background(cwd)
        warnings = store.take_warnings()
        out = inv.hook_output("SessionStart", warnings) if warnings else {}
        if ctx:
            out["hookSpecificOutput"] = {"hookEventName": "SessionStart", "additionalContext": ctx}
        if out:
            print(json.dumps(out))
    except Exception:  # noqa: BLE001 - never break session start
        pass
    return 0


def _notify() -> int:
    """UserPromptSubmit: print queued warnings once. Always exits 0."""
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
             f"blocked (fail closed) until the user runs `! {cmd('effects --retry')}`"
    if changed:
        try:
            from bawwab import effects

            effects._mark_failed(reason)
        except Exception:  # noqa: BLE001
            pass
    if post:
        return {"decision": "block", "reason": reason}
    from bawwab.effects import READ_ONLY_TOOLS

    if tool in READ_ONLY_TOOLS:
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
    own = effects.self_text()
    if own:
        print(own)
    entries = effects.quarantined()
    if not entries:
        print("bawwab: nothing is quarantined")
        return 0
    print(effects.quarantine_details(entries))
    return 1


def _watch(args) -> int:
    from bawwab import watch

    unit_dir = Path(args.unit_dir) if args.unit_dir else None
    if args.install:
        _, msgs = watch.install_service(unit_dir)
        print("\n".join(f"bawwab watch: {m}" for m in msgs))
        return 0
    if args.uninstall:
        ok, msgs = watch.uninstall_service(unit_dir)
        print("\n".join(f"bawwab watch: {m}" for m in msgs))
        return 0 if ok else 1
    from bawwab.agents import ALL_ADAPTERS

    agents = None
    if args.agent:
        names = {a.name for a in ALL_ADAPTERS}
        bad = [n for n in args.agent if n not in names]
        if bad:
            print(f"error: unknown agent {sanitise(bad[0], 40)} (one of {', '.join(sorted(names))})", file=sys.stderr)
            return 3
        agents = [a for a in ALL_ADAPTERS if a.name in args.agent]
    rc = watch.run(args.interval, args.once, agents=agents, projects=args.project,
                   notifier=None if args.no_notify else watch.notify, debounce=args.debounce)
    if args.once:
        text, n = watch.status_text()
        print(text)
        return 1 if n else rc
    return rc


def _status() -> int:
    from bawwab import watch

    text, n = watch.status_text()
    print(text)
    return 1 if n else 0


def _plugin_roots() -> list[str]:
    """The bawwab plugin trees to set up: the one this code runs from, else every installed `bawwab@*` plugin
    (installed_plugins.json) that holds the hook."""
    from bawwab.selfid import running_root

    root = running_root()
    if root:
        return [root]
    from bawwab.paths import claude_config_dirs

    found = []  # every config dir's install record (~/.claude and $CLAUDE_CONFIG_DIR)
    for cfg in claude_config_dirs():
        try:
            data = json.loads((cfg / "plugins" / "installed_plugins.json").read_text())
            plugins = data.get("plugins") if isinstance(data, dict) else None
        except (OSError, ValueError):
            plugins = None
        found += list(plugins.items()) if isinstance(plugins, dict) else []
    out: list[str] = []
    for key, entries in found:
        if not (isinstance(key, str) and key.split("@", 1)[0] == "bawwab" and isinstance(entries, list)):
            continue
        for e in entries:
            ip = e.get("installPath") if isinstance(e, dict) else None
            if isinstance(ip, str) and os.path.isabs(ip) and os.path.isfile(os.path.join(ip, "hooks", "bawwab_hook.py")):
                rp = os.path.realpath(ip)
                if rp not in out:
                    out.append(rp)
    return out


def _setup(args) -> int:
    """`bawwab setup --retry`: run the plugin's foreground setup (hooks/bawwab_hook.py setup, fix round 4 I6)."""
    import subprocess

    roots = _plugin_roots()
    if not roots:
        print("bawwab setup: no bawwab plugin install found; nothing to set up (the CLI needs no setup)",
              file=sys.stderr)
        return 1
    flag = "--link" if args.link else "--unlink" if args.unlink else "--retry"
    rc = 0
    for root in roots[:1] if flag != "--retry" else roots:  # one shim: the plugin this code runs from, or the first
        from bawwab.limits import child_argv

        # the setup runs `uv sync`: it must not inherit this process's scan memory limit
        r = subprocess.run(child_argv([sys.executable, os.path.join(root, "hooks", "bawwab_hook.py"), "setup", flag]))
        rc = rc or r.returncode
    return rc


def _allow_env(args) -> int:
    from bawwab import allowenv
    from bawwab.store import open_store

    if args.list or not args.repo:
        rs = allowenv.repos()
        print("\n".join(f"bawwab: commands in {sanitise(r, 300)} may set BAWWAB_HOME inside it" for r in rs)
              if rs else "bawwab: no repo may set BAWWAB_HOME (the gate refuses it everywhere)")
        return 0
    if args.remove:
        ok = allowenv.remove(args.repo)
        print(f"bawwab: {'removed' if ok else 'not on the list'}: {sanitise(os.path.realpath(args.repo), 300)}")
        open_store().audit("allow-env.remove", repo=os.path.realpath(args.repo), ok=ok)
        return 0 if ok else 1
    try:
        d = allowenv.add(args.repo)
    except ValueError as e:
        print(f"error: {sanitise(str(e), 300)}", file=sys.stderr)
        return 1
    open_store().audit("allow-env.add", repo=d)
    print(f"bawwab: commands run in {sanitise(d, 300)} may now set BAWWAB_HOME to a dir inside it (a test home). "
          "A command that also runs claude, or sets HOME or CLAUDE_CONFIG_DIR, is still refused, and Bawwab's "
          f"hooks never run on such a home. Undo: `{cmd('allow-env --remove')} {shlex.quote(d)}`.")
    return 0


def _sandbox(args) -> int:
    from bawwab.sandbox.docker import DockerRunner, SandboxUnavailable, build_image

    try:
        if args.action == "build":
            print("bawwab: building the sandbox image (this downloads the base image the first time)...")
            iid = build_image()
            print(f"bawwab: sandbox image built and recorded: {iid}")
        else:
            iid = DockerRunner().check()
            print(f"bawwab: Docker is reachable and the sandbox image is ready: {iid}")
        return 0
    except SandboxUnavailable as e:
        print(f"bawwab: sandbox not ready: {sanitise(e, 300)}", file=sys.stderr)
        return 1


def main(argv: list[str] | None = None) -> int:
    from bawwab.limits import apply_memory_limit

    apply_memory_limit()  # backstop for every entry that scans (gate, scan, effects...): fail closed, not OOM
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
        if args.cmd == "setup":
            return _setup(args)
        if args.cmd == "effects":
            return _effects(args)
        if args.cmd == "init":
            return _init(args)
        if args.cmd == "scan":
            return _scan(args)
        if args.cmd in ("approve", "reject"):
            return _decide(args)
        if args.cmd == "level":
            return _level(args)
        if args.cmd == "watch":
            return _watch(args)
        if args.cmd == "status":
            return _status()
        if args.cmd == "sandbox":
            return _sandbox(args)
        if args.cmd == "allow-env":
            return _allow_env(args)
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
