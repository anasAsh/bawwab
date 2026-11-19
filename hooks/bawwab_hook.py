#!/usr/bin/env python3
"""Bawwab Claude Code hook entry point. Stdlib only.

Usage: bawwab_hook.py <subcommand>   (gate | inventory | notify)

`gate` (PreToolUse): a cheap pre-filter lets ordinary tool calls through with no
output and without importing bawwab. Install-like calls are handed to
`bawwab gate`; if that fails, the call is denied (fail closed).

`inventory` (SessionStart) and `notify` (UserPromptSubmit) never block: any failure exits 0 silently.
`notify` first checks for $BAWWAB_HOME/warnings.flag and does nothing (no bawwab import) when it is absent.
"""
import json
import os
import sys

CHILD_TIMEOUT_S = 590


def _load_prefilter():
    """Load bawwab/gate/prefilter.py by path: no bawwab package import on the hot path."""
    import importlib.util

    path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "bawwab", "gate", "prefilter.py")
    try:
        spec = importlib.util.spec_from_file_location("_bawwab_prefilter", path)
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        return mod.prefilter
    except Exception:  # noqa: BLE001 - can't tell what is install-like: send every call to the gate
        return lambda data: True


prefilter = _load_prefilter()


def _deny(reason: str) -> str:
    return json.dumps({"hookSpecificOutput": {
        "hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": reason,
    }})


def _bawwab_cmd(sub: str) -> list[str]:
    import shutil

    exe = shutil.which("bawwab")
    if exe:
        return [exe, sub]
    root = os.environ.get("CLAUDE_PLUGIN_ROOT") or os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    return ["uv", "run", "--project", root, "--quiet", "bawwab", sub]


def _run_gate(raw: str) -> str | None:
    import subprocess

    cmd = _bawwab_cmd("gate")
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
    if not isinstance(data, dict):
        return 0
    try:
        install_like = prefilter(data)
    except Exception:  # noqa: BLE001 - can't tell (e.g. NUL in a path): treat as install-like, fail closed
        install_like = True
    if not install_like:
        return 0
    try:
        out = _run_gate(raw)
    except Exception as e:  # noqa: BLE001 - the pre-filter matched: fail closed
        out = _deny(f"bawwab error: gate unavailable ({type(e).__name__})")
    if out:
        print(out)
    return 0


def _passthrough(sub: str, timeout: int) -> int:
    """Run `bawwab <sub>` with our stdin and print its JSON output; never fail the hook."""
    import subprocess

    try:
        raw = sys.stdin.read()
    except OSError:
        raw = ""
    try:
        r = subprocess.run(_bawwab_cmd(sub), input=raw, capture_output=True, text=True, timeout=timeout)
        out = r.stdout.strip()
        if r.returncode == 0 and out and isinstance(json.loads(out), dict):
            print(out)
    except Exception:  # noqa: BLE001 - informational hooks never block
        pass
    return 0


def _flag_present() -> bool:
    home = os.environ.get("BAWWAB_HOME") or os.path.join(os.path.expanduser("~"), ".bawwab")
    return os.path.exists(os.path.join(home, "warnings.flag"))


def main(argv: list[str]) -> int:
    if os.environ.get("BAWWAB_CHILD", "") not in ("", "0"):
        return 0
    if argv[1:2] == ["gate"]:
        try:
            return gate()
        except Exception:  # noqa: BLE001 - only reached before dispatch (bad input): never block
            return 0
    if argv[1:2] == ["inventory"]:
        return _passthrough("inventory", 60)
    if argv[1:2] == ["notify"]:
        return _passthrough("notify", 30) if _flag_present() else 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
