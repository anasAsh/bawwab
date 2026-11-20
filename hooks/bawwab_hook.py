#!/usr/bin/env python3
"""Bawwab Claude Code hook entry point. Stdlib only.

Usage: bawwab_hook.py <subcommand>   (gate | post | inventory | notify | bootstrap)

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


PLUGIN_ROOT = os.path.dirname(os.path.dirname(os.path.realpath(__file__)))


def _bawwab_cmd(sub: str) -> list[str]:
    """Always this plugin's own code, pinned to its uv.lock: never a `bawwab` found on PATH (version skew) and
    never a root taken from the environment."""
    return ["uv", "run", "--project", PLUGIN_ROOT, "--frozen", "--quiet", "bawwab", sub]


def _boot_dir() -> str:
    """Where the venv and the bootstrap files live: the plugin's data dir, else bawwab's home. Never the root."""
    data = os.environ.get("CLAUDE_PLUGIN_DATA")
    return data if data and os.path.isabs(data) else _bawwab_home()


def _venv_dir() -> str:
    v = os.environ.get("BAWWAB_VENV")  # a dev checkout's own venv (tests); absolute only
    return v if v and os.path.isabs(v) else os.path.join(_boot_dir(), "venv")


def _child_env() -> dict:
    """The venv lives in the plugin's data dir (shared with the MCP server) or bawwab's home (fix round 2 M8),
    never inside the plugin root."""
    env = dict(os.environ)
    env["UV_PROJECT_ENVIRONMENT"] = _venv_dir()
    return env


# ------------------------------------------------------------------ first-run bootstrap (fix round 2, I4)
# The first `uv run` downloads bawwab's dependencies, which can take longer than any hook timeout. So the venv
# is synced by a detached `bootstrap` process, which writes <boot dir>/bootstrap-complete (this root and its
# uv.lock) when done. Until then: installs (and an active quarantine) are denied, other calls pass, and
# SessionStart says setup is running; the SessionStart work (and its first-run question) runs at the end of the
# bootstrap and is shown on the next prompt.

BOOT_DONE, BOOT_LOCK = "bootstrap-complete", "bootstrap.lock"
BOOT_PENDING, BOOT_CONTEXT = "pending-sessionstart.json", "pending-context.txt"
BOOT_STALE_S, BOOT_SYNC_S, BOOT_INVENTORY_S = 2400, 1800, 300
SETUP_DENY = ("bawwab is still setting up (installing its own dependencies in the background), so it can't check "
              "this install yet. Retry in a minute.")
SETUP_CONTEXT = ("Bawwab (a security scanner for MCP servers, skills and plugins) is still setting up: it is "
                 "installing its own dependencies in the background, which takes about a minute. Install commands "
                 "are held until then. Its first-run question follows on a later prompt once setup finishes.")


def _boot_token() -> str:
    import hashlib

    h = hashlib.sha256(PLUGIN_ROOT.encode() + b"\n")
    try:
        with open(os.path.join(PLUGIN_ROOT, "uv.lock"), "rb") as f:
            h.update(f.read())
    except OSError:
        h.update(b"no-lock")
    return h.hexdigest()


def _bootstrapped() -> bool:
    try:
        with open(os.path.join(_boot_dir(), BOOT_DONE)) as f:
            return f.read().strip() == _boot_token()
    except OSError:
        return False


def _lock_fresh(path: str) -> bool:
    import time

    try:
        pid_s, ts_s = open(path).read().split()
        if time.time() - float(ts_s) > BOOT_STALE_S:
            return False
        os.kill(int(pid_s), 0)
        return True
    except ProcessLookupError:
        return False
    except (OSError, ValueError):
        return os.path.exists(path)  # unreadable or another user's process: assume it runs


def _write(path: str, text: str) -> None:
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def _start_bootstrap(pending: str | None = None) -> None:
    """Start the detached bootstrap unless one is running. Never raises."""
    import subprocess

    try:
        d = _boot_dir()
        os.makedirs(d, mode=0o700, exist_ok=True)
        if pending is not None:
            _write(os.path.join(d, BOOT_PENDING), pending)
        if _lock_fresh(os.path.join(d, BOOT_LOCK)):
            return
        subprocess.Popen([sys.executable, os.path.realpath(__file__), "bootstrap"], start_new_session=True,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:  # noqa: BLE001 - a failed start is retried by the next hook
        pass


def bootstrap() -> int:
    """The detached first-run setup: sync the venv, run the SessionStart work, mark it complete."""
    import subprocess
    import time

    d = _boot_dir()
    lock = os.path.join(d, BOOT_LOCK)
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
        if os.path.exists(lock) and not _lock_fresh(lock):
            os.unlink(lock)
        fd = os.open(lock, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except OSError:
        return 0  # another bootstrap runs
    try:
        with os.fdopen(fd, "w") as f:
            f.write(f"{os.getpid()} {time.time()}")
        token = _boot_token()
        r = subprocess.run(["uv", "sync", "--project", PLUGIN_ROOT, "--frozen", "--quiet"], env=_child_env(),
                           stdin=subprocess.DEVNULL, capture_output=True, timeout=BOOT_SYNC_S)
        if r.returncode != 0:
            return 0
        pending = os.path.join(d, BOOT_PENDING)
        if os.path.exists(pending):
            raw = open(pending).read()
            try:
                _note_session(json.loads(raw))
            except ValueError:
                _note_session(None)
            try:
                out = subprocess.run(_bawwab_cmd("inventory"), input=raw, capture_output=True, text=True,
                                     timeout=BOOT_INVENTORY_S, env=_child_env()).stdout.strip()
                ctx = json.loads(out).get("hookSpecificOutput", {}).get("additionalContext") if out else None
                if isinstance(ctx, str) and ctx:
                    _write(os.path.join(d, BOOT_CONTEXT), ctx)
            except Exception:  # noqa: BLE001 - SessionStart work is retried next session
                pass
            os.unlink(pending)
        _write(os.path.join(d, BOOT_DONE), token)
    except Exception:  # noqa: BLE001
        pass
    finally:
        try:
            os.unlink(lock)
        except OSError:
            pass
    return 0


def _run_child(sub: str, raw: str) -> tuple[str | None, str | None]:
    """(stdout JSON or None, failure description or None)."""
    import subprocess

    try:
        r = subprocess.run(_bawwab_cmd(sub), input=raw, capture_output=True, text=True, timeout=CHILD_TIMEOUT_S,
                           env=_child_env())
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
    if not _bootstrapped():  # first run or upgrade: setup runs detached; installs wait, others pass
        _start_bootstrap()
        if install_like or blocked:
            print(_deny(SETUP_DENY))
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
    if not _bootstrapped():  # the next gate call checks the change once setup is done
        _start_bootstrap()
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


def _context_json(event: str, text: str) -> str:
    return json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}})


def _take_boot_context() -> str | None:
    """The SessionStart text (first-run question) the bootstrap produced, once."""
    path = os.path.join(_boot_dir(), BOOT_CONTEXT)
    try:
        text = open(path).read()
        os.unlink(path)
        return text or None
    except OSError:
        return None


def _passthrough(sub: str, timeout: int, run: bool = True) -> int:
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
    event = "SessionStart" if sub == "inventory" else "UserPromptSubmit"
    if not _bootstrapped():
        if sub == "inventory":
            _start_bootstrap(raw)
            print(_context_json(event, SETUP_CONTEXT))
        return 0
    extra = _take_boot_context() if sub == "notify" else None
    out = None
    if run:
        try:
            r = subprocess.run(_bawwab_cmd(sub), input=raw, capture_output=True, text=True, timeout=timeout,
                               env=_child_env())
            out = r.stdout.strip()
            if not (r.returncode == 0 and out and isinstance(json.loads(out), dict)):
                out = None
        except Exception:  # noqa: BLE001 - informational hooks never block
            out = None
    if extra:
        try:
            prev = json.loads(out).get("hookSpecificOutput", {}).get("additionalContext") if out else None
        except (ValueError, AttributeError):
            prev = None
        out = _context_json(event, extra + (f"\n\n{prev}" if isinstance(prev, str) and prev else ""))
    if out:
        print(out)
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
        if _flag_present():
            return _passthrough("notify", 30)
        if os.path.exists(os.path.join(_boot_dir(), BOOT_CONTEXT)):
            return _passthrough("notify", 30, run=False)
        return 0
    if argv[1:2] == ["bootstrap"]:
        try:
            return bootstrap()
        except Exception:  # noqa: BLE001
            return 0
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
