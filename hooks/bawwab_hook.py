#!/usr/bin/env python3
"""Bawwab Claude Code hook entry point. Stdlib only.

Usage: bawwab_hook.py <subcommand>   (gate | post | inventory | notify | bootstrap | setup | venv-dir)

`setup [--retry]` and `venv-dir` are for bin/bawwab (the user's `bawwab setup --retry`, and the launcher's venv).

`gate` (PreToolUse, every tool): a cheap pre-filter and the effect-check fingerprint
(hooks/fingerprint.py) let ordinary calls through with no output and without importing
bawwab. `bawwab gate` runs when the call is install-like, when the watched config really
changed, or (for any non-read-only tool) while something is quarantined. If it fails, an
install-like call, a quarantine or a changed config is denied (fail closed); an ordinary
call with no config change is not.

`post` (PostToolUse, the tools that can change files: Bash|PowerShell|Monitor|Write|Edit|MultiEdit|NotebookEdit
and every MCP tool, mcp__*, whose effects are opaque): when the fingerprint moved, `bawwab post` runs the effect
check and blocks if something new was quarantined. Read-only tools never pay for it.

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


def _setup_detects(data: dict) -> bool:
    """While setup runs there is no venv for `bawwab gate`, so a pre-filter hit is classified by bawwab's own
    detection from this tree, which needs only the stdlib (M19): only a call it finds protected or
    install-like waits for setup, and `git rebase --skip` or `rg approve src` passes. Any failure: True."""
    try:
        root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        if root not in sys.path:
            sys.path.insert(0, root)
        from bawwab.gate import detect  # stdlib-only; an install it must resolve needs httpx: ImportError, held
        ti = data.get("tool_input")
        cwd = data.get("cwd") if isinstance(data.get("cwd"), str) and data.get("cwd") else os.getcwd()
        inp = detect.HookInput(str(data.get("tool_name") or ""), ti if isinstance(ti, dict) else {}, cwd)
        return detect.detect_install(inp) is not None
    except BaseException:  # noqa: BLE001 - can't tell: hold the call (fail closed)
        return True


# Allowed while something is quarantined: they change nothing. AskUserQuestion lets Claude ask the user
# what to do with each item (the user still runs approve/reject).
READ_ONLY_TOOLS = frozenset({"Read", "Grep", "Glob", "LS", "TodoWrite", "NotebookRead", "AskUserQuestion"})
# PostToolUse effect check: the tools that can change files. MCP tools (mcp__<server>__<tool>, plugin servers
# included) may write anything, so each gets the check right after the call, not only at the next pre-call
# fingerprint. An unchanged fingerprint costs only the stat walk.
POST_TOOLS = frozenset({"Bash", "PowerShell", "Monitor", "Write", "Edit", "MultiEdit", "NotebookEdit"})


def _post_tool(name: object) -> bool:
    return isinstance(name, str) and (name in POST_TOOLS or name.startswith("mcp__"))


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


def _clicmd():
    """bawwab/clicmd.py (R54), loaded by path."""
    import importlib.util

    spec = importlib.util.spec_from_file_location("_bawwab_clicmd", os.path.join(PLUGIN_ROOT, "bawwab", "clicmd.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _cli(args: str) -> str:
    """The command line to show for `bawwab <args>`: the one helper, bawwab/clicmd.py (R54)."""
    try:
        return _clicmd().cmd(args)
    except Exception:  # noqa: BLE001
        return f"bawwab {args}"


def _refresh_stable_launcher() -> None:
    """In Claude Code's plugin cache, (re)write <data dir>/bin/bawwab, the stable launcher the printed commands
    name, so it runs this version (clicmd.stable_text). Only in bawwab's own existing data dir (derived from this
    tree's path, never from env), never through a symlink, only when its bytes differ. Never raises."""
    try:
        c = _clicmd()
        d, launcher = _installed_data_dir(), os.path.realpath(os.path.join(PLUGIN_ROOT, "bin", "bawwab"))
        if d is None or d != c.data_dir(PLUGIN_ROOT) or not os.path.isfile(launcher):
            return
        bindir = os.path.join(d, "bin")
        if os.path.islink(bindir):
            return
        os.makedirs(bindir, mode=0o700, exist_ok=True)
        path, text = os.path.join(bindir, "bawwab"), c.stable_text(launcher)
        if os.path.islink(path) or not os.path.isdir(bindir) or os.path.islink(bindir):
            return
        if _read(path) == text and c.stable_ok(launcher):
            return
        tmp = f"{path}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o755)
        with os.fdopen(fd, "w") as f:
            f.write(text)
        os.chmod(tmp, 0o755)
        os.replace(tmp, path)
    except Exception:  # noqa: BLE001 - the printed commands fall back to this version's own launcher
        pass


def _bawwab_cmd(sub: str) -> list[str]:
    """Always this plugin's own code, pinned to its uv.lock: never a `bawwab` found on PATH (version skew) and
    never a root taken from the environment."""
    return ["uv", "run", "--project", PLUGIN_ROOT, "--frozen", "--quiet", "bawwab", sub]


def _installed_data_dir() -> str | None:
    """The data dir Claude Code gives this installed tree, derived from the tree's own path (never from env):
    <plugins>/cache/<marketplace>/<plugin>/<version> -> <plugins>/data/<plugin@marketplace, [^A-Za-z0-9_-] as ->.
    Only when it exists and is bawwab-named. Lets bin/bawwab and `setup --retry`, run from the user's shell
    (no CLAUDE_PLUGIN_DATA), use the same venv and bootstrap files as the hooks (fix round 4)."""
    import re

    ver = PLUGIN_ROOT
    plugin = os.path.dirname(ver)
    mkt = os.path.dirname(plugin)
    cache = os.path.dirname(mkt)
    if os.path.basename(cache) != "cache" or os.path.basename(os.path.dirname(cache)) != "plugins":
        return None
    pid = re.sub(r"[^A-Za-z0-9_-]", "-", f"{os.path.basename(plugin)}@{os.path.basename(mkt)}")
    d = os.path.join(os.path.dirname(cache), "data", pid)
    try:
        ok = os.path.isdir(d) and not os.path.islink(d) and _load_fingerprint().is_bawwab_plugin_dir(d)
    except Exception:  # noqa: BLE001
        ok = False
    return d if ok else None


def _boot_dir() -> str:
    """Where the venv and the bootstrap files live: the plugin's data dir (CLAUDE_PLUGIN_DATA, else the one
    derived from this tree's install path), else bawwab's home. Never the root."""
    data = os.environ.get("CLAUDE_PLUGIN_DATA")
    if data and os.path.isabs(data):
        return data
    return _installed_data_dir() or _bawwab_home()


def _venv_dir() -> str:
    """<boot dir>/venv. BAWWAB_VENV (absolute) is a dev/test knob, honoured only outside a plugin install (no
    CLAUDE_PLUGIN_DATA): it never overrides the plugin data dir (fix round 3, M11)."""
    v = os.environ.get("BAWWAB_VENV")
    if v and os.path.isabs(v) and not os.environ.get("CLAUDE_PLUGIN_DATA"):
        return v
    return os.path.join(_boot_dir(), "venv")


def _child_env() -> dict:
    """The venv lives in the plugin's data dir (shared with the MCP server) or bawwab's home (fix round 2 M8),
    never inside the plugin root."""
    env = dict(os.environ)
    env["UV_PROJECT_ENVIRONMENT"] = _venv_dir()
    return env


# ------------------------------------------------------------------ first-run bootstrap (fix rounds 2-3)
# The first `uv run` downloads bawwab's dependencies, which can take longer than any hook timeout. So the venv
# is synced by a detached `bootstrap` process, which writes <boot dir>/bootstrap-complete (this root and its
# uv.lock) when done. Until then:
# - before bawwab is initialised (effect check inactive anyway): installs and an active quarantine are denied,
#   other calls pass;
# - once initialised: any call the effect check would have looked at (config changed, or can't tell) is denied
#   too, so a failing or blocked setup never turns the effect check off (I5).
# SessionStart says setup is running; the SessionStart work runs at the end of the bootstrap, and the next prompt
# shows a fixed notice chosen by a message id (never text read back from a file, M9).

BOOT_DONE, BOOT_LOCK, BOOT_FAILED = "bootstrap-complete", "bootstrap.lock", "bootstrap-failed"
BOOT_SPAWNED, BOOT_FAILED_TOLD = "bootstrap.spawned", "bootstrap-failed.told"
BOOT_PENDING, BOOT_CONTEXT = "pending-sessionstart.json", "pending-context.txt"
BOOT_STALE_S, BOOT_SYNC_S, BOOT_INVENTORY_S, BOOT_RESPAWN_S, BOOT_WAIT_S = 1800, 1800, 300, 60, 120
SETUP_OK = "bawwab setup complete: its dependencies are installed and its checks are active."


def _recovery() -> str:
    """What the user can do when setup keeps failing (I6): every step works in a plugin-only install."""
    return (f"To fix it, the user can run `! {_cli('setup --retry')}` (retries the setup now, in the foreground, and "
            "shows the error), or check their proxy settings (HTTPS_PROXY), network, and uv configuration (uv must "
            "be on PATH and able to reach the Python package index). Last resort: `/plugin disable bawwab`, which "
            "turns off bawwab's protection entirely.")


_READ_ONLY_NOTE = "read-only tools (Read, Grep, Glob, LS) still work"


def _setup_running_deny() -> str:
    return ("bawwab is still setting up (installing its own dependencies in the background), so it can't check "
            f"this yet; {_READ_ONLY_NOTE}. Retry in a minute. If this persists: {_recovery()}")


def _setup_failed_deny() -> str:
    return ("bawwab setup failed: it could not install its own dependencies, so it can't check this (fail "
            f"closed; {_READ_ONLY_NOTE}). Setup is retried automatically about once a minute. {_recovery()}")


SETUP_CONTEXT = ("Bawwab (a security scanner for MCP servers, skills and plugins) is still setting up: it is "
                 "installing its own dependencies in the background, which takes about a minute. Install commands "
                 "are held until then. Its first-run question follows on a later prompt once setup finishes.")


def _setup_failed_context() -> str:
    return ("Bawwab (a security scanner for MCP servers, skills and plugins) setup failed: it could not install "
            "its own dependencies (offline, a proxy, or the package index is unreachable). Until it succeeds, "
            "install commands are held, and once bawwab is initialised so are tool calls after Claude's "
            f"configuration changes; {_READ_ONLY_NOTE}. Setup is retried automatically about once a minute. "
            f"Tell the user: {_recovery()}")


def _boot_notice(nid: str) -> str | None:
    """Fixed notices the bootstrap can leave for the next prompt, by id (M9)."""
    if nid == "first-run":
        return ("Bawwab (a security scanner for MCP servers, skills and plugins) has finished setting up, and it "
                "has not scanned this machine yet. Before anything else, tell the user Bawwab is ready (it checks "
                "MCP servers, skills and plugins before Claude installs them), then ask them, in one AskUserQuestion "
                f"call:\n1. Bawwab's security level, unless `{_cli('level')}` says one is already chosen (put high "
                "first, as recommended): low warns about threats and never blocks them; medium blocks malicious "
                "items and warns about suspicious ones; high (the default) blocks anything not clean until the user "
                f"approves it. If they pick high, run `{_cli('level high')}` yourself. Medium or low lowers "
                f"protection, so only the user can set it: give them `! {_cli('level medium')}` or "
                f"`! {_cli('level low')}` to run (you cannot). Bawwab's self-protection blocks at every level.\n"
                "2. Whether to run a full scan now.\n"
                f"- Yes: run `{_cli('init --scan')}` yourself.\n- Skip: the user must run "
                f"`! {_cli('init --skip')}` (this trusts everything installed now without scanning; you cannot run "
                "it).")
    if nid == "lost":
        return ("bawwab's state was lost, so tool calls are blocked (fail closed). Tell the user to run "
                f"`! {_cli('init --scan')}` (a full scan: nothing is trusted without scanning).")
    return None


_SID_CHARS = frozenset("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_")


def _boot_token() -> str:
    import hashlib

    h = hashlib.sha256(PLUGIN_ROOT.encode() + b"\n")
    try:
        with open(os.path.join(PLUGIN_ROOT, "uv.lock"), "rb") as f:
            h.update(f.read())
    except OSError:
        h.update(b"no-lock")
    return h.hexdigest()


def _read(path: str) -> str | None:
    try:
        with open(path) as f:
            return f.read()
    except (OSError, UnicodeDecodeError):
        return None


def _bootstrapped() -> bool:
    return (_read(os.path.join(_boot_dir(), BOOT_DONE)) or "").strip() == _boot_token()


def _write(path: str, text: str) -> None:
    """Atomic: a reader sees the old file or the new one, never a partial write."""
    tmp = f"{path}.{os.getpid()}.tmp"
    with open(tmp, "w") as f:
        f.write(text)
    os.replace(tmp, path)


def _lock_live(content: str | None) -> bool:
    """A lock counts only for a live bootstrap: a sane, recent timestamp, a pid we can signal, and (where /proc
    exists) that pid running this hook's `bootstrap`. Anything else is stale (fix round 3, I5)."""
    import time

    try:
        pid_s, ts_s = (content or "").split()
        pid, ts = int(pid_s), float(ts_s)
    except ValueError:
        return False
    now = time.time()
    if pid <= 0 or ts > now + 5 or now - ts > BOOT_STALE_S:
        return False
    try:
        os.kill(pid, 0)
    except (PermissionError, ProcessLookupError, OSError):
        return False
    cmdline = f"/proc/{pid}/cmdline"
    if os.path.isdir("/proc/self"):
        raw = _read(cmdline)
        if raw is None:
            return False
        argv = raw.split("\0")
        return any(x.endswith("bawwab_hook.py") for x in argv) and "bootstrap" in argv
    return True


def _take_lock(path: str) -> bool:
    """O_CREAT|O_EXCL; a stale lock is moved aside atomically first (and put back if it changed meanwhile)."""
    import time

    for _ in range(2):
        try:
            fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
        except FileExistsError:
            seen = _read(path)
            if _lock_live(seen):
                return False
            aside = f"{path}.stale.{os.getpid()}"
            try:
                os.rename(path, aside)
            except OSError:
                continue
            if _read(aside) != seen:  # another process's fresh lock: put it back, give up
                try:
                    os.link(aside, path)
                except OSError:
                    pass
                os.unlink(aside)
                return False
            os.unlink(aside)
            continue
        except OSError:
            return False
        with os.fdopen(fd, "w") as f:
            f.write(f"{os.getpid()} {time.time()}")
        return True
    return False


def _respawn_allowed(d: str) -> bool:
    """At most one bootstrap start per BOOT_RESPAWN_S, recorded in a marker file."""
    import time

    try:
        last = float((_read(os.path.join(d, BOOT_SPAWNED)) or "0").strip() or 0)
    except ValueError:
        last = 0.0
    now = time.time()
    if 0 <= now - last < BOOT_RESPAWN_S:
        return False
    _write(os.path.join(d, BOOT_SPAWNED), str(now))
    return True


def _pending_input(raw: str) -> str:
    """The SessionStart input the bootstrap replays, rebuilt from checked fields only (M9)."""
    try:
        data = json.loads(raw)
    except ValueError:
        data = {}
    out: dict = {"hook_event_name": "SessionStart"}
    if isinstance(data, dict):
        sid, cwd = data.get("session_id"), data.get("cwd")
        if isinstance(sid, str) and 0 < len(sid) <= 100 and set(sid) <= _SID_CHARS:
            out["session_id"] = sid
        if isinstance(cwd, str) and os.path.isabs(cwd) and os.path.isdir(cwd) and "\n" not in cwd:
            out["cwd"] = cwd
    return json.dumps(out)


def _start_bootstrap(pending: str | None = None) -> None:
    """Start the detached bootstrap unless one is running or one started under a minute ago. Never raises."""
    import subprocess

    try:
        d = _boot_dir()
        os.makedirs(d, mode=0o700, exist_ok=True)
        if pending is not None:
            _write(os.path.join(d, BOOT_PENDING), _pending_input(pending))
        if _lock_live(_read(os.path.join(d, BOOT_LOCK))) or not _respawn_allowed(d):
            return
        subprocess.Popen([sys.executable, os.path.realpath(__file__), "bootstrap"], start_new_session=True,
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception:  # noqa: BLE001 - a failed start is retried by a later hook
        pass


def _notice_id(ctx: object) -> str | None:
    """Which fixed notice the SessionStart output calls for. The output's text itself is never kept."""
    if not isinstance(ctx, str):
        return None
    if "state was lost" in ctx:
        return "lost"
    if "has not scanned this machine yet" in ctx:
        return "first-run"
    return None


def _say(text: str, err: bool = False) -> None:
    print(text, file=sys.stderr if err else sys.stdout, flush=True)


def _wait_for_lock(lock: str, secs: float) -> None:
    import time

    end = time.time() + secs
    told = False
    while time.time() < end and _lock_live(_read(lock)):
        if not told:
            _say("bawwab: a background setup is running; waiting for it to finish...")
            told = True
        time.sleep(0.5)


def bootstrap(foreground: bool = False) -> int:
    """The first-run setup: sync the venv, run the SessionStart work, mark it complete. Detached (a hook starts
    it), or in the foreground (`bawwab setup --retry` via bin/bawwab, fix round 4 I6): then uv's own output
    reaches the user's terminal, the respawn rate limit is ignored, and the exit code tells success."""
    import subprocess

    d = _boot_dir()
    lock = os.path.join(d, BOOT_LOCK)
    try:
        os.makedirs(d, mode=0o700, exist_ok=True)
        got = _take_lock(lock)
        if not got and foreground:
            _wait_for_lock(lock, BOOT_WAIT_S)
            if _bootstrapped():
                _say(SETUP_OK)
                return 0
            got = _take_lock(lock)
        if not got:
            if foreground:
                _say(f"bawwab setup: another setup holds {lock}; try again in a few minutes. {_recovery()}", True)
                return 1
            return 0  # another bootstrap runs
    except OSError as e:
        if foreground:
            _say(f"bawwab setup failed: cannot write {d} ({e}). {_recovery()}", True)
            return 1
        return 0
    rc = 1
    try:
        token = _boot_token()
        try:
            if foreground:
                _say(f"bawwab: syncing its dependencies into {_venv_dir()} ...")
                r = subprocess.run(["uv", "sync", "--project", PLUGIN_ROOT, "--frozen"], env=_child_env(),
                                   stdin=subprocess.DEVNULL, timeout=BOOT_SYNC_S)
            else:
                r = subprocess.run(["uv", "sync", "--project", PLUGIN_ROOT, "--frozen", "--quiet"], env=_child_env(),
                                   stdin=subprocess.DEVNULL, capture_output=True, timeout=BOOT_SYNC_S)
            why = None if r.returncode == 0 else f"`uv sync` exited {r.returncode}"
        except subprocess.TimeoutExpired:
            why = f"`uv sync` took longer than {BOOT_SYNC_S} s"
        except OSError as e:
            why = f"could not run uv ({type(e).__name__}: is uv on PATH?)"
        if why:
            _write(os.path.join(d, BOOT_FAILED), "sync-failed")
            if foreground:
                _say(f"bawwab setup failed: {why}. {_recovery()}", True)
            return 1 if foreground else 0
        pending = os.path.join(d, BOOT_PENDING)
        raw = _read(pending)
        if raw is not None:
            raw = _pending_input(raw)
            _note_session(json.loads(raw))
            try:
                out = subprocess.run(_bawwab_cmd("inventory"), input=raw, capture_output=True, text=True,
                                     timeout=BOOT_INVENTORY_S, env=_child_env()).stdout.strip()
                nid = _notice_id(json.loads(out).get("hookSpecificOutput", {}).get("additionalContext")) \
                    if out else None
                if nid:
                    _write(os.path.join(d, BOOT_CONTEXT), nid)
            except Exception:  # noqa: BLE001 - SessionStart work is retried next session
                pass
            if _read(pending) is not None and _pending_input(_read(pending) or "") == raw:
                try:
                    os.unlink(pending)  # only the input we replayed, not a newer one
                except OSError:
                    pass
        for name in (BOOT_FAILED, BOOT_FAILED_TOLD):
            try:
                os.unlink(os.path.join(d, name))
            except OSError:
                pass
        _write(os.path.join(d, BOOT_DONE), token)
        _refresh_stable_launcher()
        rc = 0
        if foreground:
            _say(SETUP_OK)
    except Exception as e:  # noqa: BLE001
        if foreground:
            _say(f"bawwab setup failed: {type(e).__name__}: {e}. {_recovery()}", True)
    finally:
        try:
            if _read(lock) is not None and (_read(lock) or "").split()[:1] == [str(os.getpid())]:
                os.unlink(lock)
        except OSError:
            pass
    return rc if foreground else 0


def link(unlink: bool = False) -> int:
    """`bawwab setup --link` (the user's own command; the gate refuses it from Claude): write a 3-line shim named
    `bawwab` into the first of ~/.local/bin, ~/bin on PATH, running the stable launcher (plugin cache) or this
    tree's launcher, so Bawwab's messages can print bare `bawwab` while the shim verifies (clicmd.linked).
    Never replaces a file it didn't write, and refuses when another `bawwab` comes first on PATH.
    `--unlink` removes the shims it wrote."""
    import shutil

    c = _clicmd()
    if unlink:
        gone = []
        for d in c.SHIM_DIRS:
            p = os.path.join(os.path.expanduser(d), "bawwab")
            if not os.path.islink(p) and c.is_shim(_read(p) or ""):
                os.unlink(p)
                gone.append(p)
        _say(f"bawwab: removed {', '.join(gone)}; messages print the launcher's path again." if gone else
             "bawwab: no `bawwab` shim written by `bawwab setup --link` was found; nothing removed.")
        return 0
    launcher = os.path.realpath(os.path.join(PLUGIN_ROOT, "bin", "bawwab"))
    if not os.path.isfile(launcher):
        _say("bawwab setup --link: this install has no launcher (bin/bawwab); nothing to link.", True)
        return 1
    _refresh_stable_launcher()
    target = c.shim_target(launcher)
    if target != launcher and not c.stable_ok(launcher):
        _say("bawwab setup --link: the plugin's stable launcher isn't ready; start a Claude Code session (or run "
             f"`{_cli('setup --retry')}`), then try again.", True)
        return 1
    dirs = c.shim_dirs()
    if not dirs:
        _say("bawwab setup --link: neither ~/.local/bin nor ~/bin is on your PATH, so a `bawwab` there would not "
             "be found. Add one of them to PATH, then run this again.", True)
        return 1
    d = dirs[0]
    entries = c._path_entries()
    before = entries[:entries.index(d)]
    if not all(os.path.isabs(e) for e in before):
        _say(f"bawwab setup --link: your PATH has a relative entry before {d}; Bawwab only trusts a `bawwab` it "
             "can locate the same way from any directory. Not linked.", True)
        return 1
    other = shutil.which("bawwab", path=os.pathsep.join(before)) if before else None
    if other:
        _say(f"bawwab setup --link: {other} comes before {d} on your PATH and would run instead. Remove it (or "
             "reorder PATH), then run this again. Not linked.", True)
        return 1
    dest = os.path.join(d, "bawwab")
    if os.path.lexists(dest) and (os.path.islink(dest) or not c.is_shim(_read(dest) or "")):
        _say(f"bawwab setup --link: {dest} already exists and wasn't written by Bawwab; not replaced.", True)
        return 1
    try:
        os.makedirs(d, mode=0o755, exist_ok=True)
        tmp = f"{dest}.{os.getpid()}.tmp"
        fd = os.open(tmp, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o755)
        with os.fdopen(fd, "w") as f:
            f.write(c.shim_text(target))
        os.chmod(tmp, 0o755)
        os.replace(tmp, dest)
    except OSError as e:
        _say(f"bawwab setup --link: could not write {dest} ({e}).", True)
        return 1
    if c.linked(launcher):
        _say(f"bawwab: wrote {dest} (runs {c.show_path(target)}). Bawwab's messages now print `bawwab …`, checked "
             "each time: if that file changes or another `bawwab` comes first on PATH, they go back to the full "
             "path. Undo: `bawwab setup --unlink`.")
    else:
        _say(f"bawwab: wrote {dest}, but it doesn't verify on this PATH, so messages keep printing the full path.")
    return 0


def _setup_failed() -> bool:
    return os.path.exists(os.path.join(_boot_dir(), BOOT_FAILED))


def _setup_deny() -> str:
    return _setup_failed_deny() if _setup_failed() else _setup_running_deny()


def _initialised() -> bool:
    """bawwab has been initialised (install marker, effect-check state, or state-created). Any doubt: True."""
    try:
        fp = _load_fingerprint()
        home = os.path.expanduser("~")
        return bool(fp.initialised(home, _bawwab_home()) or fp.data_marker(home, fp.STATE_CREATED))
    except Exception:  # noqa: BLE001
        return True


def _take_failure_notice() -> str | None:
    """The setup-failed notice, once per failure."""
    d = _boot_dir()
    if not _setup_failed() or os.path.exists(os.path.join(d, BOOT_FAILED_TOLD)):
        return None
    try:
        _write(os.path.join(d, BOOT_FAILED_TOLD), "1")
    except OSError:
        pass
    return _setup_failed_context()


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


def _fail_text(err: str) -> str:
    return (f"bawwab: the effect check could not run after Claude's configuration changed ({err}); tool calls are "
            f"blocked until the user runs `! {_cli('effects --retry')}` (fail closed)")


def _run_gate(raw: str, deny_on_error: bool = True, effects: bool = False) -> str | None:
    out, err = _run_child("gate", raw)
    if err is None:
        return out
    if effects:  # the watched config changed and nothing checked it: fail closed, whatever the error
        _mark_effects_error(f"effect check failed: {err}")
        return _deny(_fail_text(err))
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
    if not _bootstrapped():  # first run or upgrade: setup runs detached
        _start_bootstrap()
        # installs and a quarantine always wait; once initialised, so does anything the effect check would
        # have looked at (I5): a failing or blocked setup never switches the effect check off. Read-only tools
        # pass, as during a quarantine (I6): the user is never locked out of reading while setup fails.
        read_only = data.get("tool_name") in READ_ONLY_TOOLS
        if (install_like and _setup_detects(data)) or blocked or (changed and not read_only and _initialised()):
            print(_deny(_setup_deny()))
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
    if not isinstance(data, dict) or not _post_tool(data.get("tool_name")):
        return 0
    _note_session(data)
    cwd = data.get("cwd") if isinstance(data.get("cwd"), str) and data.get("cwd") else os.getcwd()
    if not _config_changed(cwd):
        return 0
    if not _bootstrapped():  # setup runs detached; a change is never let through unchecked once initialised
        _start_bootstrap()
        if _initialised():
            print(json.dumps({"decision": "block", "reason": _setup_deny()}))
        return 0
    try:
        out, err = _run_child("post", raw)
    except Exception as e:  # noqa: BLE001
        out, err = None, type(e).__name__
    if err is not None:
        _mark_effects_error(f"effect check failed: {err}")
        out = json.dumps({"decision": "block", "reason": _fail_text(err)})
    if out:
        print(out)
    return 0


def _context_json(event: str, text: str) -> str:
    return json.dumps({"hookSpecificOutput": {"hookEventName": event, "additionalContext": text}})


def _take_boot_context() -> str | None:
    """The fixed notice the bootstrap left for the next prompt, once. The file holds a message id only; an
    unknown id (or any planted text) shows nothing (M9)."""
    path = os.path.join(_boot_dir(), BOOT_CONTEXT)
    nid = (_read(path) or "").strip()
    try:
        os.unlink(path)
    except OSError:
        pass
    return _boot_notice(nid)


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
        told = _take_failure_notice()
        if sub == "inventory":
            _start_bootstrap(raw)
            print(_context_json(event, told or SETUP_CONTEXT))
        elif told:
            print(_context_json(event, told))
        return 0
    if sub == "inventory":
        _refresh_stable_launcher()  # a new session: the stable launcher runs the version Claude Code loaded
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
            got = json.loads(out) if out else {}
            prev = got.get("hookSpecificOutput", {}).get("additionalContext")
            user = got.get("systemMessage")  # queued warnings, for the user only: kept as they are
        except (ValueError, AttributeError):
            prev, user = None, None
        merged = json.loads(_context_json(event, extra + (f"\n\n{prev}" if isinstance(prev, str) and prev else "")))
        if isinstance(user, str) and user:
            merged["systemMessage"] = user
        out = json.dumps(merged)
    if out:
        print(out)
    return 0


def _flag_present() -> bool:
    return os.path.exists(os.path.join(_bawwab_home(), "warnings.flag"))


def main(argv: list[str]) -> int:
    # user commands, run through bin/bawwab (R54): never hook work
    if argv[1:2] == ["venv-dir"]:
        print(_venv_dir())
        return 0
    if argv[1:2] == ["setup"]:
        if argv[2:] in (["--link"], ["--unlink"]):
            return link(unlink=argv[2] == "--unlink")
        if argv[2:] not in ([], ["--retry"]):
            _say("usage: bawwab setup [--retry]   (sync bawwab's own dependencies now and show any error)\n"
                 "       bawwab setup --link     (put a `bawwab` command in ~/.local/bin or ~/bin; user only)\n"
                 "       bawwab setup --unlink   (remove it)", True)
            return 2
        return bootstrap(foreground=True)
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
        if os.path.exists(os.path.join(_boot_dir(), BOOT_CONTEXT)) or _setup_failed():
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
