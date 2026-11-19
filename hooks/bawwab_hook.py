#!/usr/bin/env python3
"""Bawwab Claude Code hook entry point. Stdlib only.

Usage: bawwab_hook.py <subcommand>   (gate; later tasks add inventory and notify)

`gate` (PreToolUse): a cheap pre-filter lets ordinary tool calls through with no
output and without importing bawwab. Install-like calls are handed to
`bawwab gate`; if that fails, the call is denied (fail closed).
"""
import json
import os
import re
import sys

CHILD_TIMEOUT_S = 590
_NEEDLES = ("claude", "bawwab", ".mcp.json")
_FILE_NEEDLES = (".claude", "bawwab", ".mcp.json")  # ~/.claude.json, .claude/{settings*,bawwab.json,skills,...}
_FILE_TOOLS = ("Write", "Edit", "MultiEdit")
# A shell glob may hide ".claude" from the substring check (cp x ~/.c*/skills/).
# claude reached through $(…), `…` or $VAR: detected by its subcommand.
_CLAUDE_SUBCMD = re.compile(
    r"\b(?:mcp\s+(?:add|add-json|add-from-claude-desktop)|plugins?\s+(?:install|i|enable|update|marketplace))\b"
)
# ...and only when a path could reach a hidden dir (~, $HOME, a ".x" component) or names an install dir.
_GLOB_HIDDEN = re.compile(r"~|\$HOME|\$\{HOME\}|(?:^|[\s/=])\.[^\s/.]|skills|commands|agents|plugins|\.mcp\.json")
# mv/rsync of a directory that contains ~/.claude, ~/.claude.json or the bawwab home (mv ~ /x).
_MOVE = re.compile(r"(?:^|[\s;&|(])(?:mv|rsync)\s")
_GLOB_COPY = re.compile(r"(?:^|[\s;&|(])(?:cp|mv|rsync|ln|install)\s")


def _bawwab_home() -> str:
    return os.path.normpath(os.environ.get("BAWWAB_HOME") or os.path.join(os.path.expanduser("~"), ".bawwab"))


def _under(p: str, root: str) -> bool:
    return p == root or p.startswith(root.rstrip("/") + "/")


def prefilter(data: dict) -> bool:
    """True when the call might be an install. May over-match; must never miss what detect_install finds."""
    tool = data.get("tool_name")
    ti = data.get("tool_input")
    if not isinstance(ti, dict):
        return False
    cwd = str(data.get("cwd") or "")
    home = _bawwab_home()
    extra = (home, os.path.basename(home) or home) if os.environ.get("BAWWAB_HOME") else ()
    if tool == "Bash":
        needles = _NEEDLES + extra
        cmd = ti.get("command")
        if not isinstance(cmd, str):
            return False
        s = cmd.replace('"', "").replace("'", "").replace("\\", "")
        if any(n in s for n in needles):
            return True
        if _MOVE.search(s) and _moves_ancestor(s, cwd, home):
            return True
        if _CLAUDE_SUBCMD.search(s) or (any(c in s for c in "*?[") and _GLOB_COPY.search(s) and _GLOB_HIDDEN.search(s)):
            return True
        return "/.claude" in cwd or _under(os.path.normpath(cwd or "/"), home)
    if tool in _FILE_TOOLS:
        fp = ti.get("file_path")
        if not isinstance(fp, str) or not fp:
            return False
        p = os.path.normpath(os.path.join(cwd or "/", fp))
        s = p + "\0" + os.path.realpath(p)
        return any(n in s for n in _FILE_NEEDLES + extra)
    return False


def _moves_ancestor(s: str, cwd: str, home: str) -> bool:
    user = os.path.expanduser("~")
    roots = (os.path.join(user, ".claude"), os.path.join(user, ".claude.json"), home)
    for tok in s.split():
        t = tok.replace("${HOME}", user).replace("$HOME", user)
        t = os.path.normpath(os.path.join(cwd or "/", os.path.expanduser(t)))
        if any(r == t or r.startswith(t.rstrip("/") + "/") for r in roots):
            return True
    return False


def _deny(reason: str) -> str:
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason,
    }})


def _run_gate(raw: str) -> str | None:
    import shutil
    import subprocess

    exe = shutil.which("bawwab")
    if exe:
        cmd = [exe, "gate"]
    else:
        root = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        cmd = ["uv", "run", "--project", root, "--quiet", "bawwab", "gate"]
    unavailable = "bawwab error: gate unavailable"
    try:
        r = subprocess.run(cmd, input=raw, capture_output=True, text=True, timeout=CHILD_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return _deny(f"{unavailable} (timed out)")
    except OSError as e:
        return _deny(f"{unavailable} ({type(e).__name__})")
    if r.returncode != 0:
        return _deny(f"{unavailable} (exit {r.returncode})")
    out = r.stdout.strip()
    if not out:
        return None
    try:
        if not isinstance(json.loads(out), dict):
            raise ValueError
    except ValueError:
        return _deny(f"{unavailable} (invalid output)")
    return out


def gate() -> int:
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except ValueError:
        return 0
    if not isinstance(data, dict) or not prefilter(data):
        return 0
    try:
        out = _run_gate(raw)
    except Exception as e:  # noqa: BLE001 - the pre-filter matched: fail closed
        out = _deny(f"bawwab error: gate unavailable ({type(e).__name__})")
    if out:
        print(out)
    return 0


def main(argv: list[str]) -> int:
    if os.environ.get("BAWWAB_CHILD", "") not in ("", "0"):
        return 0
    if argv[1:2] == ["gate"]:
        try:
            return gate()
        except Exception:  # noqa: BLE001 - only reached before dispatch (bad input): never block
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
