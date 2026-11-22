"""Background watcher (v1.1): detection right after an install, in every agent on the machine.

`bawwab watch` polls every adapter's paths with the cheap fingerprint (hooks/fingerprint.py, stat data only). When
an agent's fingerprint changes and then stays the same for the debounce time, the semantic digest decides whether
anything that matters changed; only then are the agent's items checked:

- Claude Code (gated): its own effect check runs (effects.refresh, user scope: a project-less scope dir), exactly
  as the hook would run it. What it quarantines blocks Claude Code's tool calls, as always.
- Every other agent (no blocking hook): each new or changed item is scanned. One that is not clean, at the
  security level's threshold, is put on hold (quarantine row status "held"), which only records and reports it:
  the agent itself is not stopped and may already be running it. `bawwab approve <id>` accepts it, `bawwab reject
  <id>` removes it from the agent's config (with a backup) or moves its dir to ~/.bawwab/quarantine.

New holds and quarantines raise a desktop notification (notify-send / osascript, best effort) and show in
`bawwab status`. `bawwab watch --install` writes a systemd user unit (Linux) or a launchd agent (macOS).
"""
from __future__ import annotations

import fcntl
import json
import os
import shutil
import subprocess
import sys
import time
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path

from bawwab import effects
from bawwab.agents import ALL_ADAPTERS, WATCHED, EffectItem
from bawwab.agents.claude_code import UnreadableConfig
from bawwab.clicmd import cmd
from bawwab.config import blocks
from bawwab.paths import bawwab_home
from bawwab.report import sanitise
from bawwab.store import Store, open_store, report_to_dict

HELD = effects.HELD
DEFAULT_INTERVAL = 2.0
DEFAULT_DEBOUNCE = 1.5
UNIT_NAME = "bawwab-watch.service"
PLIST_LABEL = "dev.bawwab.watch"


# ------------------------------------------------------------------ state

def state_path() -> Path:
    return bawwab_home() / "watch.json"


def _read_state() -> dict:
    try:
        data = json.loads(state_path().read_text())
        if isinstance(data, dict) and isinstance(data.get("agents"), dict):
            return data
    except (OSError, ValueError):
        pass
    return {"v": 1, "agents": {}}


def _write_state(data: dict) -> None:
    p = state_path()
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    tmp = p.with_name(f".{p.name}.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data))
    os.replace(tmp, p)


def config_projects() -> list[str]:
    """Project dirs to watch besides the user scope: ~/.bawwab/config.json {"watch": {"projects": [...]}}."""
    try:
        data = json.loads((bawwab_home() / "config.json").read_text())
    except (OSError, ValueError):
        return []
    w = data.get("watch") if isinstance(data, dict) else None
    ps = w.get("projects") if isinstance(w, dict) else None
    return [os.path.expanduser(p) for p in ps if isinstance(p, str)] if isinstance(ps, list) else []


def claude_scope_dir() -> Path:
    """The project-less cwd the watcher runs Claude Code's effect check from: user-scope items only."""
    d = bawwab_home() / "watch-scope"
    d.mkdir(parents=True, exist_ok=True, mode=0o700)
    return d


# ------------------------------------------------------------------ checking one agent

def _scopes(adapter, projects: list[str]) -> list[str]:
    out = [f"{adapter.name}:user"]
    for p in projects:
        out += [f"{adapter.name}:{d}" for d in adapter.t.project_dirs(p, str(Path.home()))]
    return out


def agent_items(adapter, projects: list[str]) -> list[EffectItem]:
    seen: dict[str, EffectItem] = {}
    for cwd in [None, *projects]:
        for it in effects._retry_unreadable(lambda: adapter.effect_items(Path(cwd) if cwd else None)):
            seen.setdefault(it.ident, it)
    return list(seen.values())


def check_agent(adapter, projects: list[str], scan=None, store: Store | None = None,
                warned: list[str] | None = None) -> list[str]:
    """Compare an unguarded agent's items with the accepted state; put what isn't accepted on hold. Returns the
    hold ids created. The same evaluation as Claude Code's effect check (effects._evaluate): approved, clean,
    or bawwab's baseline is accepted; below the security level's threshold it is accepted as warned."""
    from bawwab.config import load_config
    from bawwab.scan import scan_target

    scan = scan or scan_target
    store = store or open_store()
    items = agent_items(adapter, projects)
    cfg = load_config(None)
    scopes = _scopes(adapter, projects)
    accepted = store.effect_rows(scopes)
    held = {(q["ident"], q["hash"]): q for q in store.quarantine_rows(HELD) if q["ident"].startswith(adapter.name + ":")}
    current = {it.ident: it.hash for it in items}
    new_ids: list[str] = []
    for it in items:
        row = accepted.get(it.ident)
        if (row and row["hash"] == it.hash) or (it.ident, it.hash) in held:
            continue
        ok, r = effects._evaluate(it, scan, cfg, store, current)
        if ok:
            store.put_effect(it.ident, it.hash, it.scope, "accepted", r.key)
            store.audit("watch.accept", agent=adapter.name, ident=it.ident, key=r.key)
            continue
        if row is not None:
            store.drop_effect(it.ident)
        if not store.is_rejected(r.key) and not blocks(cfg.level, r.verdict):
            effects._warn_only(store, it, r, cfg.level)
            if warned is not None:
                warned.append(f"{effects.item_name({'ident': it.ident, 'item': json.dumps(it.to_dict())})} is "
                              f"{r.verdict.value}")
            continue
        qid = store.create_pending(r)
        store.add_quarantine(qid, it.ident, it.hash, r.key, it.to_dict(), report_to_dict(r), status=HELD)
        store.audit("watch.hold", agent=adapter.name, id=qid, ident=it.ident, key=r.key, verdict=r.verdict.value)
        new_ids.append(qid)
    for ident in set(accepted) - set(current):
        store.drop_effect(ident)
    for (ident, h), q in held.items():
        if _scope_of(q) in scopes and current.get(ident) != h:
            store.set_quarantine(q["qrow"], status="gone")
    store.audit("watch.check", agent=adapter.name, items=len(items), held=len(new_ids))
    return new_ids


def _scope_of(q: dict) -> str | None:
    try:
        return json.loads(q["item"]).get("scope")
    except (ValueError, AttributeError, TypeError):
        return None


def check_claude_code(scan=None, store: Store | None = None) -> list[str]:
    """Claude Code's own effect check at user scope (exactly what its hook runs; nothing before its first
    SessionStart). New quarantine ids block Claude Code's tools until the user decides."""
    return effects.refresh(claude_scope_dir(), scan, store)


@contextmanager
def _watch_lock():
    """The watcher's own lock (not effects.lock: a long scan here must never hold up Claude Code's hook)."""
    p = bawwab_home() / "watch.lock"
    p.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(p, "a") as f:
        fcntl.flock(f, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(f, fcntl.LOCK_UN)


# ------------------------------------------------------------------ notifications

def notify(title: str, body: str) -> bool:
    """A desktop notification, best effort: notify-send (Linux) or osascript (macOS). Never raises."""
    title, body = sanitise(title, 80), sanitise(body, 300)
    try:
        if sys.platform == "darwin" and shutil.which("osascript"):
            argv = ["osascript", "-e", "on run argv", "-e",
                    "display notification (item 2 of argv) with title (item 1 of argv)", "-e", "end run", title, body]
        elif shutil.which("notify-send"):
            argv = ["notify-send", "--app-name=bawwab", title, body]
        else:
            return False
        subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                       timeout=5, check=False)
        return True
    except (OSError, subprocess.SubprocessError, ValueError):
        return False


def _hold_message(adapter, ids: list[str], store: Store) -> tuple[str, str]:
    rows = [q for q in store.quarantine_rows(HELD) if q["id"] in ids]
    names = ", ".join(dict.fromkeys(effects.item_name(q) for q in rows)) or f"{len(ids)} item(s)"
    title = f"bawwab: {len(ids)} new {adapter.title} item{'s' if len(ids) != 1 else ''} on hold"
    body = (f"{names} — not clean. {adapter.title} was not stopped (bawwab has no hook there). "
            f"Run `{cmd('status')}` to approve or remove.")
    return title, body


def _quarantine_message(ids: list[str]) -> tuple[str, str]:
    title = f"bawwab: {len(ids)} Claude Code change{'s' if len(ids) != 1 else ''} quarantined"
    return title, f"Claude Code's tools are blocked until you decide. Run `{cmd('status')}`."


# ------------------------------------------------------------------ the loop

class Watcher:
    """Polls each agent's fingerprint; debounces; runs the check when the semantic digest changed."""

    def __init__(self, agents: list | None = None, projects: list[str] | None = None, scan=None,
                 store: Store | None = None, notifier=notify, debounce: float = DEFAULT_DEBOUNCE, clock=time.time,
                 log=None) -> None:
        self.agents = list(ALL_ADAPTERS if agents is None else agents)
        self.projects = [os.path.realpath(p) for p in (config_projects() if projects is None else projects)]
        self.scan, self.store, self.notifier, self.debounce, self.clock = scan, store, notifier, debounce, clock
        self.log = log or (lambda msg: print(msg, file=sys.stderr, flush=True))
        self.pending: dict[str, tuple[str, float]] = {}  # agent -> (fingerprint seen changing, when)
        self.failed: dict[str, str] = {}

    def _cwds(self, adapter) -> list[str]:
        if getattr(adapter, "gated", True):
            return [str(claude_scope_dir())]
        return ["", *self.projects]

    def _fp(self, adapter, digest: bool = False) -> str:
        fpm = effects.fp_module()
        home = str(Path.home())
        fn = fpm.semantic_digest if digest else fpm.fingerprint
        return "|".join(fn(c, home, (adapter.name,)) for c in self._cwds(adapter))

    def tick(self, force: bool = False) -> dict[str, list[str]]:
        """One pass over every agent. force: no debounce, check even when the digest looks unchanged."""
        state = _read_state()
        found: dict[str, list[str]] = {}
        for a in self.agents:
            row = state["agents"].get(a.name) or {}
            try:
                fp = self._fp(a)
            except Exception as e:  # noqa: BLE001 - one agent's failure must not stop the others
                self._failed(a, f"fingerprint: {type(e).__name__}")
                continue
            if fp == row.get("fp") and not force:
                self.pending.pop(a.name, None)
                continue
            if not force:
                seen = self.pending.get(a.name)
                if seen is None or seen[0] != fp:
                    self.pending[a.name] = (fp, self.clock())
                    if self.debounce > 0:
                        continue
                elif self.clock() - seen[1] < self.debounce:
                    continue
            self.pending.pop(a.name, None)
            try:
                digest = self._fp(a, digest=True)
                if digest == row.get("digest") and not force:
                    state["agents"][a.name] = {"fp": fp, "digest": digest, "ts": self.clock()}
                    continue
                ids = self._check(a)
            except UnreadableConfig:
                continue  # caught mid-write: the next tick looks again
            except Exception as e:  # noqa: BLE001 - reported, retried on the next change
                self._failed(a, f"{type(e).__name__}: {e}")
                continue
            self.failed.pop(a.name, None)
            state["agents"][a.name] = {"fp": fp, "digest": digest, "ts": self.clock()}
            if ids:
                found[a.name] = ids
                self._notify(a, ids)
        state["heartbeat"] = self.clock()
        state["pid"] = os.getpid()
        try:
            _write_state(state)
        except OSError:
            pass
        return found

    def _check(self, adapter) -> list[str]:
        if getattr(adapter, "gated", True):
            return check_claude_code(self.scan, self.store)
        warned: list[str] = []
        with _watch_lock():  # two watchers (a service and a --once) never hold the same item twice
            ids = check_agent(adapter, self.projects, self.scan, self.store, warned)
        if warned:
            title = f"bawwab: {adapter.title}: not clean (warned only, at your security level)"
            self.log(f"{title}: {'; '.join(warned)}")
            if self.notifier:
                self.notifier(title, "; ".join(warned))
        return ids

    def _notify(self, adapter, ids: list[str]) -> None:
        if getattr(adapter, "gated", True):
            title, body = _quarantine_message(ids)
        else:
            title, body = _hold_message(adapter, ids, self.store or open_store())
        self.log(f"{title}: {body}")
        if self.notifier:
            self.notifier(title, body)

    def _failed(self, adapter, msg: str) -> None:
        msg = sanitise(msg, 200)
        self.log(f"bawwab watch: {adapter.name}: {msg}")
        if self.failed.get(adapter.name) != msg:  # once per distinct failure, not every tick
            self.failed[adapter.name] = msg
            if self.notifier:
                self.notifier(f"bawwab: could not check {getattr(adapter, 'title', adapter.name)}", msg)


def run(interval: float = DEFAULT_INTERVAL, once: bool = False, **kw) -> int:
    w = Watcher(**kw)
    if once:
        w.tick(force=True)
        return 0
    w.log(f"bawwab watch: watching {', '.join(a.name for a in w.agents)} every {interval:g}s")
    try:
        while True:
            w.tick()
            time.sleep(interval)
    except KeyboardInterrupt:
        return 0


# ------------------------------------------------------------------ status

def status_text(store: Store | None = None) -> tuple[str, int]:
    """(text, number of items on hold or quarantined) across every agent."""
    store = store or open_store()
    active = effects.quarantined(store)
    held = effects.quarantined(store, HELD)
    lines = ["bawwab status"]
    lines.append("")
    if active:
        lines.append(f"Claude Code — {len(effects._groups(active))} quarantined: Claude Code's tools are blocked "
                     "until you decide (its hooks enforce it).")
        lines += _rows(active)
    else:
        lines.append("Claude Code — nothing quarantined.")
    by_agent: dict[str, list[dict]] = {}
    for q in held:
        by_agent.setdefault(q["ident"].split(":", 1)[0], []).append(q)
    for a in WATCHED:
        qs = by_agent.pop(a.name, [])
        if qs:
            lines.append(f"{a.title} — {len(effects._groups(qs))} on hold: recorded only, {a.title} was not "
                         "stopped (bawwab has no blocking hook there); it may already be running.")
            lines += _rows(qs)
        else:
            lines.append(f"{a.title} — nothing on hold.")
    for name, qs in by_agent.items():  # an agent this version no longer knows
        lines.append(f"{sanitise(name, 40)} — {len(qs)} on hold.")
        lines += _rows(qs)
    n = len(effects._groups(active)) + len(effects._groups(held))
    if n:  # the same command lines as every block: `!`, the real ids, each naming its items
        lines += ["", *effects.group_commands(active + held)]
    lines += ["", watcher_status()]
    return "\n".join(lines), n


def _rows(entries: list[dict]) -> list[str]:
    out = []
    for qid, g in effects._groups(entries).items():
        _, name, verdict, _, why = effects.group_row(sanitise(qid, 8), g)
        out.append(f"  {sanitise(qid, 8):<8}  {name:<40}  {verdict.lower():<10}  {why}")
    return out


def watcher_status() -> str:
    st = _read_state()
    hb = st.get("heartbeat")
    unit = unit_path()
    installed = f"service installed ({unit})" if unit.exists() else f"service not installed (! {cmd('watch --install')})"
    if isinstance(hb, (int, float)):
        when = datetime.fromtimestamp(hb, UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        return f"watcher: {installed}; last pass {when}"
    return f"watcher: {installed}; it has not run yet"


# ------------------------------------------------------------------ the user service

def unit_dir() -> Path:
    """Where the service file goes: $BAWWAB_UNIT_DIR (tests), else ~/.config/systemd/user or ~/Library/LaunchAgents."""
    env = os.environ.get("BAWWAB_UNIT_DIR")
    if env:
        return Path(env)
    if sys.platform == "darwin":
        return Path.home() / "Library" / "LaunchAgents"
    base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    return Path(base) / "systemd" / "user"


def unit_path(directory: Path | None = None) -> Path:
    d = directory or unit_dir()
    return d / (f"{PLIST_LABEL}.plist" if sys.platform == "darwin" else UNIT_NAME)


def _argv() -> list[str]:
    # -P: the working directory is never put on sys.path (no module planted there is imported)
    return [sys.executable, "-P", "-m", "bawwab.cli", "watch"]


def _env() -> dict[str, str]:
    return {k: os.environ[k] for k in ("BAWWAB_HOME", "CODEX_HOME", "COPILOT_HOME") if os.environ.get(k)}


def systemd_unit() -> str:
    def q(a: str) -> str:
        return '"' + a.replace("\\", "\\\\").replace('"', '\\"') + '"' if any(c in a for c in ' "\\') else a

    env = "".join(f"Environment={q(f'{k}={v}')}\n" for k, v in _env().items())
    return ("[Unit]\nDescription=bawwab: scan new MCP servers, skills and extensions of every coding agent\n\n"
            "[Service]\nType=simple\n"
            f"ExecStart={' '.join(q(a) for a in _argv())}\n{env}"
            f"WorkingDirectory={q(str(bawwab_home()))}\n"
            "Restart=on-failure\nRestartSec=30\nNice=10\n\n[Install]\nWantedBy=default.target\n")


def launchd_plist() -> str:
    from xml.sax.saxutils import escape

    args = "".join(f"    <string>{escape(a)}</string>\n" for a in _argv())
    env = "".join(f"    <key>{escape(k)}</key><string>{escape(v)}</string>\n" for k, v in _env().items())
    log = escape(str(bawwab_home() / "watch.log"))
    return ('<?xml version="1.0" encoding="UTF-8"?>\n'
            '<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n'
            '<plist version="1.0">\n<dict>\n'
            f"  <key>Label</key><string>{PLIST_LABEL}</string>\n"
            f"  <key>ProgramArguments</key>\n  <array>\n{args}  </array>\n"
            f"  <key>WorkingDirectory</key><string>{escape(str(bawwab_home()))}</string>\n"
            f"  <key>EnvironmentVariables</key>\n  <dict>\n{env}  </dict>\n"
            "  <key>RunAtLoad</key><true/>\n  <key>KeepAlive</key><true/>\n  <key>ProcessType</key><string>Background</string>\n"
            f"  <key>StandardErrorPath</key><string>{log}</string>\n"
            "</dict>\n</plist>\n")


def _service_commands(path: Path, install: bool) -> list[list[str]]:
    if sys.platform == "darwin":
        return [["launchctl", "load", "-w", str(path)]] if install else [["launchctl", "unload", "-w", str(path)]]
    if install:
        return [["systemctl", "--user", "daemon-reload"], ["systemctl", "--user", "enable", "--now", UNIT_NAME]]
    return [["systemctl", "--user", "disable", "--now", UNIT_NAME], ["systemctl", "--user", "daemon-reload"]]


def install_service(directory: Path | None = None, start: bool | None = None, runner=None) -> tuple[Path, list[str]]:
    """Write the unit (or plist). It is started only in the default unit dir (never with an injected dir, as in
    tests) unless start says otherwise. Returns (path, messages)."""
    injected = directory is not None or bool(os.environ.get("BAWWAB_UNIT_DIR"))
    path = unit_path(directory)
    path.parent.mkdir(parents=True, exist_ok=True)
    bawwab_home().mkdir(parents=True, exist_ok=True, mode=0o700)  # the service's working directory
    path.write_text(launchd_plist() if sys.platform == "darwin" else systemd_unit())
    msgs = [f"wrote {path}"]
    cmds = _service_commands(path, True)
    if start if start is not None else not injected:
        msgs += _run(cmds, runner)
    else:
        msgs.append("to start it: " + " && ".join(" ".join(c) for c in cmds))
    return path, msgs


def uninstall_service(directory: Path | None = None, stop: bool | None = None, runner=None) -> tuple[bool, list[str]]:
    injected = directory is not None or bool(os.environ.get("BAWWAB_UNIT_DIR"))
    path = unit_path(directory)
    msgs: list[str] = []
    if stop if stop is not None else not injected:
        msgs += _run(_service_commands(path, False), runner)
    if not path.exists():
        return False, msgs + [f"no service file at {path}"]
    path.unlink()
    return True, msgs + [f"removed {path}"]


def _run(cmds: list[list[str]], runner=None) -> list[str]:
    out = []
    for c in cmds:
        try:
            r = (runner or (lambda a: subprocess.run(a, capture_output=True, text=True, timeout=30)))(c)
            rc = getattr(r, "returncode", 0)
            out.append(f"ran {' '.join(c)}" + ("" if rc == 0 else f" (exit {rc})"))
        except (OSError, subprocess.SubprocessError) as e:
            out.append(f"could not run {' '.join(c)}: {type(e).__name__}")
    return out


__all__ = ["Watcher", "check_agent", "install_service", "notify", "run", "status_text", "uninstall_service"]
