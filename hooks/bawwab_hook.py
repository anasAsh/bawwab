#!/usr/bin/env python3
"""Bawwab Claude Code hook entry point. Stdlib only.

Usage: bawwab_hook.py <subcommand>   (gate | post | inventory | notify)

`gate` (PreToolUse, every tool): a cheap pre-filter and the effect-check fingerprint
(hooks/fingerprint.py) let ordinary calls through with no output and without importing
bawwab. `bawwab gate` runs when the call is install-like, when the watched config really
changed, or (for any non-read-only tool) while something is quarantined. If it fails, an
install-like call, a quarantine or a changed config is denied (fail closed); an ordinary
call with no config change is not.

`post` (PostToolUse, Bash|Write|Edit|MultiEdit|NotebookEdit): when the fingerprint moved,
`bawwab post` runs the effect check and blocks if something new was quarantined.

When the watched config changed and the effect check fails for any reason (timeout,
crash, bad output), the hook leaves $BAWWAB_HOME/effects.error and the quarantine flag and
denies/blocks; bawwab turns the marker into a quarantine, cleared by `bawwab effects --retry`.
Before bawwab's first SessionStart (no install marker, no state) the effect check is inactive.

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

READ_ONLY_TOOLS = frozenset({"Read", "Grep", "Glob", "LS", "TodoWrite", "NotebookRead"})
POST_TOOLS = frozenset({"Bash", "Write", "Edit", "MultiEdit", "NotebookEdit"})


def _load_fingerprint():
    import importlib.util

    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fingerprint.py")
    spec = importlib.util.spec_from_file_location("_bawwab_fingerprint", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _bawwab_home() -> str:
    return os.environ.get("BAWWAB_HOME") or os.path.join(os.path.expanduser("~"), ".bawwab")


def _config_changed(cwd: str) -> bool:
    """Effect-check fingerprint: False only when nothing that matters changed, or bawwab was never
    initialised (no install marker and no state). Any doubt: True."""
    try:
        fp = _load_fingerprint()
        home, bh = os.path.expanduser("~"), _bawwab_home()
        if not fp.initialised(home, bh):
            return False
        return fp.check(cwd, home, bh) == "changed"
    except Exception:  # noqa: BLE001 - can't tell: let bawwab look
        return True


def _note_session(data: object) -> None:
    """The hook input's session_id, for the lost-state check (which excludes the current session) here and
    in the bawwab children (inherited env). Absent: unset, so an inherited value never counts."""
    sid = data.get("session_id") if isinstance(data, dict) else None
    if isinstance(sid, str) and sid:
        os.environ["BAWWAB_SESSION_ID"] = sid
    else:
        os.environ.pop("BAWWAB_SESSION_ID", None)


def _quarantine_flag() -> bool:
    try:
        return _load_fingerprint().quarantine_active(_bawwab_home())
    except Exception:  # noqa: BLE001
        return os.path.exists(os.path.join(_bawwab_home(), "quarantine.flag"))


def _mark_effects_error(reason: str) -> None:
    """The effect check could not finish: leave a marker bawwab turns into a quarantine, and the flag."""
    home = _bawwab_home()
    try:
        os.makedirs(home, mode=0o700, exist_ok=True)
        with open(os.path.join(home, "effects.error"), "w") as f:
            f.write(reason)
        open(os.path.join(home, "quarantine.flag"), "a").close()
    except OSError:
        pass


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


def _run_child(sub: str, raw: str) -> tuple[str | None, str | None]:
    """(stdout JSON or None, failure description or None)."""
    import subprocess

    try:
        r = subprocess.run(_bawwab_cmd(sub), input=raw, capture_output=True, text=True, timeout=CHILD_TIMEOUT_S)
    except subprocess.TimeoutExpired:
        return None, "timed out"
    except OSError as e:
        return None, type(e).__name__
    if r.returncode != 0:
        return None, f"exit {r.returncode}"
    out = r.stdout.strip()
    if not out:
        return None, None
    try:
        if not isinstance(json.loads(out), dict):
            raise ValueError
    except ValueError:
        return None, "invalid output"
    return out, None


_FAIL = ("bawwab: the effect check could not run after Claude's configuration changed ({}); tool calls are "
         "blocked until the user runs `! bawwab effects --retry` (fail closed)")


def _run_gate(raw: str, deny_on_error: bool = True, effects: bool = False) -> str | None:
    out, err = _run_child("gate", raw)
    if err is None:
        return out
    if effects:  # the watched config changed and nothing checked it: fail closed, whatever the error
        _mark_effects_error(f"effect check failed: {err}")
        return _deny(_FAIL.format(err))
    if deny_on_error:
        return _deny(f"bawwab error: gate unavailable ({err})")
    return None


def gate() -> int:
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except ValueError:
        return 0
    if not isinstance(data, dict):
        return 0
    _note_session(data)
    try:
        install_like = prefilter(data)
    except Exception:  # noqa: BLE001 - can't tell (e.g. NUL in a path): treat as install-like, fail closed
        install_like = True
    cwd = data.get("cwd") if isinstance(data.get("cwd"), str) and data.get("cwd") else os.getcwd()
    changed = _config_changed(cwd)
    blocked = data.get("tool_name") not in READ_ONLY_TOOLS and _quarantine_flag()
    if not (install_like or changed or blocked):
        return 0
    try:
        # a broken bawwab never blocks an ordinary call; it does block installs and an active quarantine
        out = _run_gate(raw, deny_on_error=bool(install_like or blocked), effects=changed)
    except Exception as e:  # noqa: BLE001
        if changed:
            _mark_effects_error(f"effect check failed: {type(e).__name__}")
        out = _deny(f"bawwab error: gate unavailable ({type(e).__name__})") if (install_like or blocked or changed) \
            else None
    if out:
        print(out)
    return 0


def post() -> int:
    raw = sys.stdin.read()
    try:
        data = json.loads(raw)
    except ValueError:
        return 0
    if not isinstance(data, dict) or data.get("tool_name") not in POST_TOOLS:
        return 0
    _note_session(data)
    cwd = data.get("cwd") if isinstance(data.get("cwd"), str) and data.get("cwd") else os.getcwd()
    if not _config_changed(cwd):
        return 0
    try:
        out, err = _run_child("post", raw)
    except Exception as e:  # noqa: BLE001
        out, err = None, type(e).__name__
    if err is not None:
        _mark_effects_error(f"effect check failed: {err}")
        out = json.dumps({"decision": "block", "reason": _FAIL.format(err)})
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
        _note_session(json.loads(raw))
    except ValueError:
        _note_session(None)
    try:
        r = subprocess.run(_bawwab_cmd(sub), input=raw, capture_output=True, text=True, timeout=timeout)
        out = r.stdout.strip()
        if r.returncode == 0 and out and isinstance(json.loads(out), dict):
            print(out)
    except Exception:  # noqa: BLE001 - informational hooks never block
        pass
    return 0


def _flag_present() -> bool:
    return os.path.exists(os.path.join(_bawwab_home(), "warnings.flag"))


def _is_child() -> bool:
    """BAWWAB_CHILD short-circuits only with bawwab's per-install token (a bare value from settings env
    must not switch the hook off)."""
    if os.environ.get("BAWWAB_CHILD", "") in ("", "0"):
        return False
    try:
        return _load_fingerprint().is_child(_bawwab_home())
    except Exception:  # noqa: BLE001 - can't verify: not a child
        return False


def main(argv: list[str]) -> int:
    if _is_child():
        return 0
    if argv[1:2] == ["gate"]:
        try:
            return gate()
        except Exception:  # noqa: BLE001 - only reached before dispatch (bad input): never block
            return 0
    if argv[1:2] == ["post"]:
        try:
            return post()
        except Exception:  # noqa: BLE001 - never break the tool result
            return 0
    if argv[1:2] == ["inventory"]:
        return _passthrough("inventory", 60)
    if argv[1:2] == ["notify"]:
        return _passthrough("notify", 30) if _flag_present() else 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
