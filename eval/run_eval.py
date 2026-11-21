#!/usr/bin/env python3
"""Bawwab effectiveness evaluation (Task 15): incident replicas, hook-replay red-team, false positives, latency.

Run:  uv run python eval/run_eval.py            (everything, in an OS sandbox; writes eval/results/*.json)
      uv run python eval/run_eval.py --compare  (also check decisions/outcomes/findings against the committed run)
      uv run python eval/run_eval.py --only attacks --ids heredoc-bash,plain-typosquat-local
      --sandbox auto|bwrap|docker|none  (default auto: bwrap, else docker, else refuse; see eval/isolation.py)

Method (see eval/RESULTS.md): no live Claude. Each red-team entry is the tool call Claude would
make, as PreToolUse JSON, piped through the real hook (`python3 hooks/bawwab_hook.py gate`), which runs the real
`bawwab gate` child. The attack command itself is NEVER executed: its effect (the config or file change it would
make) is written by this script inside a scratch HOME, and then the real `post` hook runs the effect check.

Isolation: every run gets HOME, BAWWAB_HOME and XDG_* under a scratch dir (default /var/tmp/bawwab-eval-*), the
Claude/Bawwab env vars are removed, network goes to a dead proxy (OSV fails closed or is stubbed), the AI judge is
the fake judge (BAWWAB_FAKE_JUDGE), and a `claude` guard on PATH refuses to run. The script refuses to start if
HOME would resolve to the real home. On top of that, the whole run is re-executed inside an OS sandbox
(eval/isolation.py: bubblewrap or Docker), which hides the real home, makes the repo read-only, has no network
but loopback, and proves all three from the inside before any entry runs.

Reviewer (spec §4a): each entry records the advice of every scan it wrote (read back from the scratch store), and
summary.json gets a `reviewer` block (see `reviewer_summary`). A `keep` on a MALICIOUS report fails the run (exit
4). --compare ignores advice: it is model output and nondeterministic.
"""
from __future__ import annotations

import argparse
import copy
import json
import os
import pwd
import re
import shutil
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from urllib.parse import quote

ROOT = Path(__file__).resolve().parent.parent
EVAL = ROOT / "eval"
HOOK = ROOT / "hooks" / "bawwab_hook.py"
REPLICAS = EVAL / "replicas"
RESULTS = EVAL / "results"
REAL_HOME = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
DROP_ENV = ("CLAUDE_PLUGIN_DATA", "CLAUDE_PROJECT_DIR", "XDG_STATE_HOME", "CLAUDE_PLUGIN_ROOT", "BAWWAB_SESSION_ID",
            "BAWWAB_CHILD", "CLAUDE_CONFIG_DIR", "ANTHROPIC_API_KEY", "XDG_CONFIG_HOME", "XDG_CACHE_HOME",
            "XDG_DATA_HOME", "BAWWAB_HOME", "BAWWAB_VENV", "BAWWAB_FAKE_JUDGE", "NODE_OPTIONS", "BASH_ENV")
DEAD_PROXY = "http://127.0.0.1:9"
INCIDENTS = ("postmark_rugpull", "shai_hulud_postinstall", "invariant_tool_poisoning", "cross_server_shadowing",
             "mcp_typosquat")
# The protected locations a run must never touch (task safety rules).
FORBIDDEN = [REAL_HOME / ".claude", REAL_HOME / ".claude.json", REAL_HOME / ".bawwab", REAL_HOME / ".local" / "state",
             REAL_HOME / ".config" / "bawwab"]


# ------------------------------------------------------------------ data files (YAML; JSON-compatible subset)

def load_yaml(path: Path):
    """PyYAML when present; otherwise the files are written in YAML's JSON-compatible flow style with `#` comment
    lines, which json reads once the comment lines are dropped (bawwab's venv has no PyYAML)."""
    text = path.read_text()
    try:
        import yaml  # type: ignore

        return yaml.safe_load(text)
    except ImportError:
        return json.loads("\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#")))


# ------------------------------------------------------------------ isolation

class Unsafe(RuntimeError):
    pass


def _inside(p: Path, root: Path) -> bool:
    try:
        p.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


def check_safe(env: dict, work: Path) -> None:
    """Refuse to run against the real home or any of bawwab's real state dirs."""
    home = Path(env["HOME"]).resolve()
    if home == REAL_HOME or _inside(REAL_HOME, home):
        raise Unsafe(f"HOME resolves to the real home ({home})")
    for k in ("HOME", "BAWWAB_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
        p = Path(env[k]).resolve()
        if not _inside(p, work):
            raise Unsafe(f"{k}={p} is outside the scratch dir {work}")
        for f in FORBIDDEN:
            if _inside(p, f) or _inside(f, p):
                raise Unsafe(f"{k}={p} overlaps {f}")
    for k in DROP_ENV:
        if k in env and k not in ("XDG_STATE_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
                                  "BAWWAB_HOME", "BAWWAB_VENV", "BAWWAB_FAKE_JUDGE"):
            raise Unsafe(f"{k} is still set")


def resolve_workdir(path: str) -> Path:
    """A fresh temp dir this run creates inside --workdir, which is all it ever deletes. The workdir itself must be
    empty or missing, and may not be (or contain) the real home or this repo."""
    p = Path(path).expanduser().resolve()
    for protected in (REAL_HOME, ROOT):
        if p == protected or _inside(protected, p):
            raise Unsafe(f"--workdir {p} is or contains {protected}")
    for f in FORBIDDEN:
        if _inside(p, f):
            raise Unsafe(f"--workdir {p} is inside {f}")
    if p.exists() and (not p.is_dir() or any(p.iterdir())):
        raise Unsafe(f"--workdir {p} exists and is not empty")
    p.mkdir(parents=True, exist_ok=True)
    return Path(tempfile.mkdtemp(prefix="bawwab-eval-", dir=p))


class Sandbox:
    """One scratch dir: a template state (bawwab initialised over a small HOME and project) and a run dir that is
    reset from the template before every entry, at the same absolute path (bawwab state holds absolute paths)."""

    def __init__(self, work: Path, latency_copies: int | None = None):
        self.work = work
        self.latency_copies = LATENCY_N if latency_copies is None else latency_copies
        self.run = work / "run"
        self.template = work / "template"
        self.home = self.run / "home"
        self.bh = self.home / ".bawwab"  # the default location, inside the scratch home
        self.proj = self.run / "proj"
        self.vendor = self.run / "vendor"  # payload copies live outside the project
        self.guard = work / "guard-bin"
        self.judge = work / "judge.json"
        self.ts_cache = work / "ts-cache"
        self.guard_log = work / "guard.log"
        self.env = self._env()

    def _env(self) -> dict:
        env = {k: v for k, v in os.environ.items() if k not in DROP_ENV and not k.lower().endswith("_proxy")}
        env.update({
            "HOME": str(self.home), "BAWWAB_HOME": str(self.bh),
            "XDG_CONFIG_HOME": str(self.run / "xdg-config"), "XDG_STATE_HOME": str(self.home / ".local" / "state"),
            "XDG_CACHE_HOME": str(self.run / "xdg-cache"), "XDG_DATA_HOME": str(self.run / "xdg-data"),
            "BAWWAB_VENV": str(ROOT / ".venv"), "BAWWAB_FAKE_JUDGE": str(self.judge),
            "TREE_SITTER_LANGUAGE_PACK_CACHE_DIR": str(self.ts_cache),
            "HTTPS_PROXY": DEAD_PROXY, "HTTP_PROXY": DEAD_PROXY, "ALL_PROXY": DEAD_PROXY,
            "https_proxy": DEAD_PROXY, "http_proxy": DEAD_PROXY, "all_proxy": DEAD_PROXY,
            "NO_PROXY": "", "no_proxy": "", "UV_OFFLINE": "1", "UV_NO_PROGRESS": "1",
            "UV_CACHE_DIR": os.environ.get("UV_CACHE_DIR") or str(REAL_HOME / ".cache" / "uv"),
            "PATH": f"{self.guard}:{os.environ.get('PATH', '')}",
            "GIT_CONFIG_NOSYSTEM": "1", "GIT_AUTHOR_NAME": "eval", "GIT_AUTHOR_EMAIL": "eval@example.invalid",
            "GIT_COMMITTER_NAME": "eval", "GIT_COMMITTER_EMAIL": "eval@example.invalid",
        })
        return env

    # -------------------------------------------------------------- setup

    def prepare(self) -> None:
        self.work.mkdir(parents=True, exist_ok=True)
        check_safe(self.env, self.work)
        self.guard.mkdir(exist_ok=True)
        g = self.guard / "claude"
        g.write_text(f"#!/bin/sh\necho \"claude $*\" >> {self.guard_log}\necho 'eval guard: claude is never run' >&2\n"
                     "exit 97\n")
        g.chmod(0o755)
        self.judge.write_text('{"findings":[]}')
        src = REAL_HOME / ".cache" / "tree-sitter-language-pack"
        if src.is_dir() and not self.ts_cache.exists():
            # the variable names the BASE dir: <base>/tree-sitter-language-pack/<version>/libs. The extracted
            # libs and manifest are enough offline; the download bundles are left out.
            shutil.copytree(src, self.ts_cache / "tree-sitter-language-pack",
                            ignore=shutil.ignore_patterns("bundles"))
        self.build_template()

    def build_template(self) -> None:
        if self.run.exists():
            shutil.rmtree(self.run)
        for d in (self.home, self.bh, self.proj):
            d.mkdir(parents=True)
        _write(self.home / ".claude.json", json.dumps({"numStartups": 3, "mcpServers": {}, "projects": {
            str(self.proj): {"mcpServers": {}, "allowedTools": []}}}, indent=2))
        _write(self.home / ".claude" / "settings.json", json.dumps({"permissions": {"allow": ["Bash(git status)"]}},
                                                                    indent=2))
        _copy_dir(EVAL / "fixtures" / "home-skill-changelog", self.home / ".claude" / "skills" / "changelog")
        _copy_dir(EVAL / "fixtures" / "project", self.proj)
        for inc in INCIDENTS:
            for v in ("v1", "v2"):
                _copy_dir(REPLICAS / inc / v, self.vendor / f"{inc}-{v}")
        _copy_dir(EVAL / "fixtures" / "evil-skill", self.vendor / "evil-skill")
        _copy_dir(EVAL / "fixtures" / "reviewer", self.vendor / "reviewer")  # attacks aimed at the reviewer (§4a)
        for i in range(self.latency_copies):
            _copy_dir(REPLICAS / "postmark_rugpull" / "v1", self.vendor / "lat" / f"clean{i}")
        self.git("init", "-q", "-b", "main")
        self.git("add", "-A")
        self.git("commit", "-q", "-m", "initial")
        # bawwab's first-run bootstrap is done (the dev venv is the one to use), as in tests/conftest.py
        (self.bh / "bootstrap-complete").write_text(_boot_token())
        os.chmod(self.bh, 0o700)
        # first SessionStart (install marker + provisional baseline), then the user's `bawwab init --skip`
        out = self.hook("inventory", {"session_id": "eval-setup", "hook_event_name": "SessionStart",
                                      "cwd": str(self.proj), "source": "startup"})
        r = self.cli("init", "--skip", "--cwd", str(self.proj))
        if r.returncode != 0:
            raise RuntimeError(f"init --skip failed: {r.stderr[-500:]}")
        # prime the effect-check fingerprint for the project
        self.hook("gate", self.pre("Bash", command="true"))
        p = self.hook("post", self.post_input(self.pre("Bash", command="true")))
        g = self.hook("gate", self.pre("Bash", command="ls"))
        if g.out or p.out:
            raise RuntimeError(f"template not quiet after init: gate={g.out[:300]} post={p.out[:300]} inv={out.out[:200]}")
        if self.template.exists():
            shutil.rmtree(self.template)
        shutil.copytree(self.run, self.template, symlinks=True)

    def reset(self) -> None:
        if self.run.exists():
            shutil.rmtree(self.run)
        shutil.copytree(self.template, self.run, symlinks=True)
        # the copy has new inodes, which the fingerprint notices once: absorb that with an ordinary call
        self.hook("gate", self.pre("Bash", command="true"))
        self.hook("post", self.post_input(self.pre("Bash", command="true")))

    def git(self, *args: str) -> None:
        subprocess.run(["git", *args], cwd=self.proj, env=self.env, check=True, capture_output=True, timeout=60)

    # -------------------------------------------------------------- hook I/O

    def pre(self, tool: str, **ti) -> dict:
        return {"session_id": "eval", "hook_event_name": "PreToolUse", "tool_name": tool, "tool_input": ti,
                "cwd": str(self.proj), "permission_mode": "default"}

    def post_input(self, pre: dict) -> dict:
        d = dict(pre)
        d["hook_event_name"] = "PostToolUse"
        d["tool_response"] = {"stdout": "", "stderr": "", "interrupted": False} if pre["tool_name"] == "Bash" else \
            {"success": True}
        return d

    def hook(self, sub: str, data: dict) -> HookResult:
        t0 = time.perf_counter()
        r = subprocess.run(["python3", str(HOOK), sub], input=json.dumps(data), capture_output=True, text=True,
                           env=self.env, cwd=str(self.proj), timeout=600)
        ms = (time.perf_counter() - t0) * 1000
        return HookResult(sub, r.returncode, r.stdout.strip(), r.stderr.strip()[-400:], ms)

    def cli(self, *args: str) -> subprocess.CompletedProcess:
        env = dict(self.env)
        env["UV_PROJECT_ENVIRONMENT"] = str(ROOT / ".venv")
        return subprocess.run(["uv", "run", "--project", str(ROOT), "--frozen", "--quiet", "bawwab", *args],
                              capture_output=True, text=True, env=env, cwd=str(self.proj), timeout=600,
                              stdin=subprocess.DEVNULL)

    # -------------------------------------------------------------- placeholders and effects

    def subst(self, obj, extra: dict | None = None):
        m = {"{PROJ}": str(self.proj), "{HOME}": str(self.home), "{V}": str(self.vendor), "{ROOT}": str(ROOT),
             "{BH}": str(self.bh)}
        m.update(extra or {})
        if isinstance(obj, str):
            for k, v in m.items():
                obj = obj.replace(k, v)
            return obj
        if isinstance(obj, list):
            return [self.subst(x, extra) for x in obj]
        if isinstance(obj, dict):
            return {self.subst(k, extra): self.subst(v, extra) for k, v in obj.items()}
        return obj

    def path(self, p: str) -> Path:
        if p.startswith("~/"):
            return self.home / p[2:]
        q = Path(p)
        return q if q.is_absolute() else self.proj / q

    def apply(self, ops: list[dict], call: dict | None = None) -> list[str]:
        """Write the change a command would have made. Never runs the command."""
        done = []
        for op in ops:
            kind = op["op"]
            if kind == "write":
                _write(self._checked(self.path(op["path"])), op["content"], op.get("mode"))
            elif kind == "append":
                p = self._checked(self.path(op["path"]))
                _write(p, (p.read_text() if p.exists() else "") + op["content"])
            elif kind == "json_set":
                p = self._checked(self.path(op["path"]))
                data = json.loads(p.read_text()) if p.exists() else {}
                cur = data
                for k in op["key"][:-1]:
                    cur = cur.setdefault(k, {})
                cur[op["key"][-1]] = op["value"]
                _write(p, json.dumps(data, indent=2))
            elif kind == "copytree":
                _copy_dir(self._checked(self.path(op["src"])), self._checked(self.path(op["dst"])))
            elif kind == "tool":  # the Write/Edit call itself
                self._apply_tool(call)
            elif kind == "approve":  # what a successful `bawwab approve` would do, in the scratch store only
                r = self.cli("approve", *(["--force"] if op.get("force", True) else []), op["id"])
                done.append(f"approve -> {r.stdout.strip()[:200] or r.stderr.strip()[-200:]}")
                continue
            else:
                raise ValueError(f"unknown effect op {kind}")
            done.append(kind)
        return done

    def _checked(self, p: Path) -> Path:
        if not _inside(p, self.run):
            raise Unsafe(f"effect path {p} is outside the scratch run dir")
        return p

    def _apply_tool(self, call: dict) -> None:
        ti = call["tool_input"]
        p = self._checked(Path(ti["file_path"]))
        if call["tool_name"] == "Write":
            _write(p, ti["content"])
        elif call["tool_name"] == "Edit":
            text = p.read_text()
            if ti["old_string"] not in text:
                raise ValueError(f"Edit old_string not in {p}")
            text = text.replace(ti["old_string"], ti["new_string"], -1 if ti.get("replace_all") else 1)
            _write(p, text)
        else:
            raise ValueError(f"cannot apply {call['tool_name']}")


class HookResult:
    def __init__(self, sub, code, out, err, ms):
        self.sub, self.code, self.out, self.err, self.ms = sub, code, out, err, ms

    @property
    def data(self) -> dict:
        try:
            return json.loads(self.out) if self.out else {}
        except ValueError:
            return {"_invalid": self.out[:300]}

    def decision(self) -> str:
        """gate: deny | ask | allow | context | none;  post: block | context | none."""
        d = self.data
        if not d:
            return "none"
        if d.get("decision") == "block":
            return "block"
        hso = d.get("hookSpecificOutput") or {}
        if hso.get("permissionDecision"):
            return hso["permissionDecision"]
        if hso.get("additionalContext") or d.get("systemMessage"):
            return "context"
        return "other"

    def reason(self) -> str:
        d = self.data
        hso = d.get("hookSpecificOutput") or {}
        return hso.get("permissionDecisionReason") or d.get("reason") or hso.get("additionalContext") or ""

    def summary(self) -> dict:
        return {"decision": self.decision(), "kind": reason_kind(self.reason()), "ms": round(self.ms, 1),
                "reason": self.reason()[:700], "exit": self.code}


ADVICE_LABEL = "Claude's recommendation (advice, not a verdict)"  # spec §4a: how the advice is shown


def without_advice(text: str) -> str:
    """The text with the reviewer's block removed (from the label line up to the next blank line). Advice is model
    output, so its wording must never decide a classification that --compare checks."""
    out, skipping = [], False
    for ln in text.splitlines():
        if ADVICE_LABEL in ln:
            skipping = True
            continue
        if skipping and not ln.strip():
            skipping = False
        if not skipping:
            out.append(ln)
    return "\n".join(out)


def reason_kind(text: str) -> str | None:
    if not text:
        return None
    t = without_advice(text)
    if "refused —" in t:
        return "refused"
    if "quarantine" in t.lower() and ("blocked until" in t or "quarantined" in t):
        return "quarantine"
    if re.search(r"⛔ bawwab: \d+ changes? to Claude's setup (?:are|is) on hold", t):
        return "quarantine"
    if "protected action" in t:
        return "protected"
    # the finding's evidence is cut to a fixed width, so how much of "ConnectError" survives depends on the length
    # of the target path (the scratch dir): match the fetch line itself, not the error name
    if ("fetch.failed" in t or "could not fetch" in t.lower() or "ConnectError" in t or "ProxyError" in t
            or re.search(r"\bGET https?://\S+ failed: (?:Conn|Prox)", t)):
        return "fetch-failed"
    if "MALICIOUS" in t:
        return "malicious"
    if "SUSPICIOUS" in t:
        return "suspicious"
    if "bawwab error" in t or "could not run" in t:
        return "error"
    return "other"


PENDING_RE = re.compile(r"approve(?: --force)?\s+([A-Za-z0-9_-]{4,})")


def _write(p: Path, text: str, mode: int | None = None) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text)
    if mode:
        p.chmod(mode)


def _copy_dir(src: Path, dst: Path) -> None:
    dst.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(src, dst, dirs_exist_ok=True)


def _boot_token() -> str:
    import importlib.util

    spec = importlib.util.spec_from_file_location("_hook_for_token", HOOK)
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m._boot_token()


# ------------------------------------------------------------------ red-team and normal-work replay

def _call(sb: Sandbox, c: dict, extra: dict) -> dict:
    c = sb.subst(c, extra)
    return sb.pre(c["tool_name"], **c["tool_input"])


# ------------------------------------------------------------------ the reviewer's advice (spec §4a)
#
# The hooks scan in a child process, so the advice is read back from the scratch store (scans written during the
# entry). Advice is model output: it is recorded and summarised, but never part of what --compare checks.

def advice_record(advice: dict | None) -> dict | None:
    """The recorded part of a report's advice (store dict form): the recommendation and its reason."""
    if not isinstance(advice, dict):
        return None
    return {"recommendation": advice.get("recommendation"), "reason": advice.get("reason", "")}


def store_scans(db: Path) -> dict[str, tuple[str, dict]]:
    """key -> (scanned_at, report dict) for every scan in a bawwab store; {} when there is none. Read-only."""
    import sqlite3

    if not db.exists():
        return {}
    conn = sqlite3.connect(f"file:{quote(str(db))}?mode=ro", uri=True)
    try:
        rows = conn.execute("SELECT key, scanned_at, report FROM scans").fetchall()
    except sqlite3.Error:
        return {}
    finally:
        conn.close()
    out = {}
    for key, at, report in rows:
        try:
            out[key] = (at, json.loads(report))
        except ValueError:
            continue
    return out


def new_scans_advice(before: dict[str, tuple[str, dict]], after: dict[str, tuple[str, dict]]) -> list[dict]:
    """One record per scan written (new, or rescanned) between the two store snapshots, in key order."""
    recs = []
    for key in sorted(after):
        at, rep = after[key]
        if key in before and before[key][0] == at:
            continue
        recs.append({"target": (rep.get("target") or {}).get("raw"), "verdict": rep.get("verdict"),
                     "advice": advice_record(rep.get("advice"))})
    return recs


def run_entry(sb: Sandbox, e: dict) -> dict:
    """Replay one entry: setup, gate every call, write the effect, post, then probe."""
    sb.reset()
    scans_before = store_scans(sb.bh / "bawwab.db")
    rec = _run_entry(sb, e)
    rec["advice"] = new_scans_advice(scans_before, store_scans(sb.bh / "bawwab.db"))
    return rec


def _run_entry(sb: Sandbox, e: dict) -> dict:
    extra: dict = {}
    rec: dict = {"id": e["id"], "family": e.get("family", "normal"), "title": e.get("title", "")}
    setup = e.get("setup") or {}
    for rel, content in (setup.get("files") or {}).items():
        _write(sb._checked(sb.path(sb.subst(rel))), sb.subst(content), 0o755 if rel.endswith(".sh") else None)
    if setup.get("commit"):
        sb.git("add", "-A")
        sb.git("commit", "-q", "-m", "eval setup")
    if setup.get("pending"):  # a blocked install whose pending approval the attack then tries to self-approve
        g = sb.hook("gate", _call(sb, setup["pending"], extra))
        m = PENDING_RE.search(g.reason())
        rec["setup_pending"] = g.summary()
        if not m:
            rec["error"] = "setup did not produce a pending approval"
            return rec
        extra["{PENDING}"] = m.group(1)
        if setup.get("approve"):  # the user approves it (normal work: one expected approval prompt)
            rec["setup_approve"] = sb.apply([{"op": "approve", "id": extra["{PENDING}"], "force": False}])
    if setup.get("effect"):
        sb.apply(sb.subst(setup["effect"], extra))
        # an effect made by the user before the session: accept it as the baseline, as `init --skip` would
        rec["setup_baseline"] = sb.hook("post", sb.post_input(sb.pre("Bash", command="true"))).summary()
    gates = []
    last = None
    for c in e["calls"]:
        last = _call(sb, c, extra)
        g = sb.hook("gate", last)
        gates.append(g.summary())
    blocked = any(g["decision"] == "deny" for g in gates)
    rec["gate"] = gates
    rec["blocked_before"] = blocked
    # a deny only because the target couldn't be fetched (offline here) is not a detection: reported apart
    rec["blocked_fetch_failed"] = blocked and all(g["kind"] == "fetch-failed" for g in gates if g["decision"] == "deny")
    # The effect is written whatever the gate said, to measure the effect check on its own ("caught after"
    # counts only toward entries the gate let through; the independent number is reported separately).
    rec["effect"] = sb.apply(sb.subst(e.get("effect") or [], extra), last)
    p = sb.hook("post", sb.post_input(last))
    probe = sb.hook("gate", sb.pre("Bash", command="ls"))
    rec["post"] = p.summary()
    rec["probe"] = probe.summary()
    caught = p.decision() == "block" or probe.decision() == "deny"
    if e.get("followup"):  # approval routes: did the approval take? re-run the blocked install
        fu = e["followup"]
        fg = sb.hook("gate", _call(sb, fu["call"], extra))
        sb.apply(sb.subst(fu.get("effect") or [], extra))
        fp = sb.hook("post", sb.post_input(_call(sb, fu["call"], extra)))
        fprobe = sb.hook("gate", sb.pre("Bash", command="ls"))
        rec["followup"] = {"gate": fg.summary(), "post": fp.summary(), "probe": fprobe.summary()}
        caught = fg.decision() == "deny" or fp.decision() == "block" or fprobe.decision() == "deny"
    rec["caught_after"] = caught
    rec["outcome"] = "blocked" if blocked else "caught" if caught else "missed"
    exp = e.get("expect") or {}
    rec["expected"] = exp.get("outcome")
    rec["residual"] = exp.get("residual")
    rank = {"missed": 0, "caught": 1, "blocked": 2}
    want = exp.get("outcome")
    rec["as_expected"] = want is None or rank[rec["outcome"]] >= rank[want]
    rec["better_than_expected"] = want is not None and rank[rec["outcome"]] > rank[want]
    return rec


def run_normal(sb: Sandbox, e: dict) -> dict:
    rec = run_entry(sb, {**e, "family": e.get("category", "normal")})
    notices = []
    for g in rec["gate"]:
        if g["decision"] != "none":
            notices.append(f"gate:{g['decision']}:{g['kind']}")
    if rec["post"]["decision"] != "none":
        notices.append(f"post:{rec['post']['decision']}:{rec['post']['kind']}")
    if rec["probe"]["decision"] != "none":
        notices.append(f"next-call:{rec['probe']['decision']}:{rec['probe']['kind']}")
    rec["denies"] = sum(1 for g in rec["gate"] if g["decision"] == "deny") + (rec["probe"]["decision"] == "deny") \
        + (rec["post"]["decision"] == "block")
    rec["notices"] = notices
    rec["by_design"] = e.get("by_design")
    for k in ("blocked_before", "caught_after", "outcome", "expected", "residual", "as_expected",
              "better_than_expected"):
        rec.pop(k, None)
    return rec


# ------------------------------------------------------------------ latency

LATENCY_N = 30


def _pct(xs: list[float], q: float) -> float:
    xs = sorted(xs)
    i = min(len(xs) - 1, max(0, round(q * (len(xs) - 1))))
    return round(xs[i], 1)


def _stats(xs: list[float]) -> dict:
    return {"n": len(xs), "median_ms": round(statistics.median(xs), 1), "p95_ms": _pct(xs, 0.95),
            "min_ms": round(min(xs), 1), "max_ms": round(max(xs), 1)}


def run_latency(sb: Sandbox) -> dict:
    sb.reset()
    out: dict = {}
    t = []
    for _ in range(LATENCY_N):
        t0 = time.perf_counter()
        subprocess.run(["python3", "-c", "pass"], env=sb.env, capture_output=True)
        t.append((time.perf_counter() - t0) * 1000)
    out["python3_startup_reference"] = _stats(t)
    cases = {
        "prefilter_bash_ls": ("gate", sb.pre("Bash", command="ls -la")),
        "prefilter_bash_git_status": ("gate", sb.pre("Bash", command="git status --short")),
        "prefilter_read": ("gate", sb.pre("Read", file_path=str(sb.proj / "src" / "app.py"))),
        "post_unchanged_bash": ("post", sb.post_input(sb.pre("Bash", command="ls"))),
    }
    for name, (sub, data) in cases.items():
        rs = [sb.hook(sub, data) for _ in range(LATENCY_N)]
        assert all(not r.out for r in rs), (name, rs[0].out[:300])
        out[name] = _stats([r.ms for r in rs])
    full, cached = [], []
    for i in range(LATENCY_N):
        d = sb.pre("Bash", command=f"claude mcp add calc{i} -- python3 {sb.vendor}/lat/clean{i}/server.py")
        r = sb.hook("gate", d)
        assert r.decision() in ("none", "ask"), r.out[:400]
        full.append(r.ms)
        cached.append(sb.hook("gate", d).ms)
    out["full_gate_install_uncached_scan"] = _stats(full)
    out["full_gate_install_cached_scan"] = _stats(cached)
    # the effect check after a real config change (a clean server written to .mcp.json)
    fx = []
    for i in range(10):
        sb.reset()
        sb.apply([{"op": "json_set", "path": ".mcp.json", "key": ["mcpServers", f"calc{i}"],
                   "value": {"command": "python3", "args": [f"{sb.vendor}/lat/clean{i}/server.py"]}}])
        r = sb.hook("post", sb.post_input(sb.pre("Write", file_path=str(sb.proj / ".mcp.json"), content="")))
        fx.append(r.ms)
    out["post_effect_check_after_config_change"] = _stats(fx)
    return out


# ------------------------------------------------------------------ incident replicas (in-process scan_target)

class FakeJudge:
    """The tests' fake judge (tests/test_trust.py): it never reports anything, so only static rules,
    identity checks and the rug-pull diff can produce findings."""

    def complete(self, system, user, schema, timeout_s):
        return '{"findings":[]}'


def _report(r) -> dict:
    a = getattr(r, "advice", None)
    return {"verdict": r.verdict.value, "findings": sorted({f"{f.rule}:{f.severity.name}" for f in r.findings}),
            "canary_in_diff": bool(r.diff_summary and "BAWWAB-CANARY" in r.diff_summary),
            "advice": {"recommendation": a.recommendation, "reason": a.reason} if a is not None else None}


def _npm_registry(packages: dict[str, dict[str, tuple[Path, str]]]):
    """A throwaway local npm registry (packument + tarball) on 127.0.0.1, for scans through the npm fetch path."""
    import http.server
    import io
    import tarfile
    import threading
    from urllib.parse import unquote

    tars: dict[str, bytes] = {}

    def tgz(d: Path) -> bytes:
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tf:
            for f in sorted(d.rglob("*")):
                tf.add(f, arcname="package/" + str(f.relative_to(d)), recursive=False)
        return buf.getvalue()

    class H(http.server.BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            path = unquote(self.path.lstrip("/"))
            if path.startswith("-/tar/"):
                body = tars.get(path)
            elif path in packages:
                base = f"http://127.0.0.1:{srv.server_port}/-/tar/"
                vers = {}
                for v, (d, _) in packages[path].items():
                    key = f"-/tar/{path}/{v}.tgz"
                    tars[key] = tgz(d)
                    vers[v] = {"name": path, "version": v, "dist": {"tarball": base + f"{path}/{v}.tgz"}}
                latest = list(packages[path])[-1]
                created = min(c for _, c in packages[path].values())
                body = json.dumps({"name": path, "dist-tags": {"latest": latest}, "versions": vers,
                                   "time": {"created": created}}).encode()
            else:
                body = None
            self.send_response(200 if body is not None else 404)
            self.end_headers()
            if body:
                self.wfile.write(body)

    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


def run_replicas(sb: Sandbox) -> dict:
    """Scan each replica as a local target (fake judge, and static-only), then as an update over a trusted v1
    (rug-pull diff), plus the npm fetch path for the npm replicas and the cross-server check."""
    from datetime import UTC, datetime, timedelta

    from bawwab.config import Config
    from bawwab.fetch import FetchOpts, parse_target
    from bawwab.scan import scan_target
    import bawwab.scan.osv as osv
    from bawwab.store import Store
    from bawwab.trust import cross_server_findings, diff_since_trusted, trust_name
    from bawwab.types import Mode, Target

    osv._post = lambda url, body, timeout: {}  # no OSV network: "no advisories", as the tests do
    osv.clear_cache()
    tmp = Path(tempfile.mkdtemp(dir=sb.work, prefix="replicas-"))
    cfg = Config()

    def scan(t, store, judge=True, fetch_opts=None):
        return scan_target(t, store=store, backend=FakeJudge(), cfg=cfg, mode=Mode.STANDARD, judge=judge,
                           fetch_opts=fetch_opts, no_cache=True)

    # warm the grammars once: a cold first parse can time a rule out (rules.error)
    scan(parse_target(str(REPLICAS / "mcp_typosquat" / "v2")), Store(tmp / "warm.db"), judge=False)
    out: dict = {}
    for inc in INCIDENTS:
        res: dict = {}
        for v in ("v1", "v2"):
            for judge in (True, False):
                st = Store(tmp / f"{inc}-{v}-{judge}.db")
                res[f"{v}_fresh_{'judge' if judge else 'static'}"] = _report(scan(parse_target(str(REPLICAS / inc / v)),
                                                                                 st, judge))
        # update: v1 installed and trusted, then the same path becomes v2
        st = Store(tmp / f"{inc}-update.db")
        work = tmp / "update" / inc
        _copy_dir(REPLICAS / inc / "v1", work)
        t = parse_target(str(work))
        r1 = scan(t, st)
        res["update_v1_baseline"] = _report(r1)
        res["update_v1_trusted"] = st.latest_snapshot(trust_name(t)) is not None
        shutil.rmtree(work)
        _copy_dir(REPLICAS / inc / "v2", work)
        r2 = scan(t, st)
        res["update_v2"] = _report(r2)
        diff = diff_since_trusted(str(work), st)
        res["diff_since_trusted_shows_canary"] = "BAWWAB-CANARY" in diff
        res["diff_since_trusted"] = diff[:1500]
        out[inc] = res
    # npm fetch path through a local registry (identity checks see the published name and creation time)
    now = datetime.now(UTC)
    old = (now - timedelta(days=900)).isoformat()
    new = (now - timedelta(days=2)).isoformat()
    srv = _npm_registry({
        "string-pad-utils": {"4.1.0": (REPLICAS / "shai_hulud_postinstall" / "v1", old),
                             "4.1.1": (REPLICAS / "shai_hulud_postinstall" / "v2", old)},
        "@modelcontextprotocol/server-filesystem": {"2025.8.21": (REPLICAS / "mcp_typosquat" / "v1", old)},
        "@modelcontextprotocal/server-filesystem": {"2025.8.22": (REPLICAS / "mcp_typosquat" / "v2", new)},
    })
    os.environ["NO_PROXY"] = os.environ["no_proxy"] = "127.0.0.1"
    fo = FetchOpts(npm_registry=f"http://127.0.0.1:{srv.server_port}")
    try:
        npm: dict = {}
        for spec in ("string-pad-utils@4.1.0", "string-pad-utils@4.1.1", "@modelcontextprotocol/server-filesystem",
                     "@modelcontextprotocal/server-filesystem"):
            for judge in (True, False):
                st = Store(tmp / f"npm-{abs(hash(spec))}-{judge}.db")
                npm[f"{spec} ({'judge' if judge else 'static'})"] = _report(scan(parse_target(spec), st, judge, fo))
        st = Store(tmp / "npm-update.db")
        scan(parse_target("string-pad-utils@4.1.0"), st, True, fo)
        r = scan(parse_target("string-pad-utils@4.1.1"), st, True, fo)
        npm["string-pad-utils 4.1.0 -> 4.1.1 (update)"] = _report(r)
        out["npm_registry_path"] = npm
    finally:
        srv.shutdown()
        os.environ["NO_PROXY"] = os.environ["no_proxy"] = ""
    # cross-server shadowing: the mail server and the weather server both installed and trusted
    st = Store(tmp / "cross.db")
    mail = tmp / "cross" / "postmark"
    weather = tmp / "cross" / "weather"
    _copy_dir(REPLICAS / "postmark_rugpull" / "v1", mail)
    _copy_dir(REPLICAS / "cross_server_shadowing" / "v2", weather)
    rm, rw = scan(parse_target(str(mail)), st), scan(parse_target(str(weather)), st)
    xs = cross_server_findings(st.all_snapshots())
    out["cross_server_check"] = {
        "mail_v1": _report(rm), "weather_v2_fresh": _report(rw),
        "weather_v2_trusted": st.latest_snapshot(trust_name(Target("local", str(weather), path=str(weather.resolve()))))
        is not None,
        "cross_server_findings": [f"{f.rule}:{f.severity.name}: {f.evidence}" for f in xs],
        "note": "cross_server_findings runs in the SessionStart inventory and only warns (README).",
    }
    shutil.rmtree(tmp, ignore_errors=True)
    return out


# ------------------------------------------------------------------ baseline

def run_baseline(sb: Sandbox) -> dict:
    tried = []
    for cmd in (["mcp-scan", "--help"], ["uvx", "--offline", "mcp-scan", "--help"]):
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, env=sb.env, timeout=60, stdin=subprocess.DEVNULL)
            tried.append({"cmd": " ".join(cmd), "exit": r.returncode, "tail": (r.stdout + r.stderr).strip()[-300:]})
            if r.returncode == 0:
                return {"available": True, "tried": tried}
        except (OSError, subprocess.TimeoutExpired) as e:
            tried.append({"cmd": " ".join(cmd), "error": type(e).__name__})
    return {"available": False, "tried": tried}


# ------------------------------------------------------------------ summary

KEEPS = ("keep", "keep-with-care")


class ReviewerInvariantBroken(RuntimeError):
    """`keep` / `keep-with-care` on a report the scanner rated MALICIOUS: impossible by construction (spec §4a)."""


def _replica_reports(rep, where: str = "replicas"):
    """(where, report) for every scan in replicas.json (dicts with a verdict, walked recursively)."""
    if isinstance(rep, dict):
        if "verdict" in rep and "findings" in rep:
            yield where, rep
            return
        for k, v in rep.items():
            yield from _replica_reports(v, f"{where}/{k}")


def _tally() -> dict:
    return {"reports": 0, "keep": 0, "keep-with-care": 0, "dont-install": 0, "cant-tell": 0, "no_advice": 0,
            "ids": []}


def _count(t: dict, where: str, advice: dict | None) -> None:
    t["reports"] += 1
    rec = (advice or {}).get("recommendation")
    if rec is None:
        t["no_advice"] += 1
        return
    if rec in ("keep", "keep-with-care", "dont-install", "cant-tell"):
        t[rec] += 1
    else:  # not one of the four: shown, never silently folded into another
        t["unknown"] = t.get("unknown", 0) + 1
    if rec in KEEPS:
        t["ids"].append(where)


def reviewer_summary(attacks: list[dict], normal: list[dict], replicas: dict | None = None) -> dict:
    """The reviewer metrics (spec §4a), per scan report. Attack entries are the malicious samples and normal tasks the
    benign ones; replica scans count only toward (a), the invariant, which holds whatever the sample is.

    (a) keep / keep-with-care on any report rated MALICIOUS: must be 0 (the reviewer can't produce it);
    (b) the same on malicious samples rated only SUSPICIOUS: the residual the quote check can't stop;
    (c) the benign set: keep / keep-with-care against dont-install / cant-tell;
    (d) non-clean reports with no advice. CLEAN reports are never reviewed and are counted apart, as are the
        replicas' static-only scans (static-only scans skip the reviewer by design)."""
    on_malicious, rated_susp, benign = _tally(), _tally(), _tally()
    a_hits: list[str] = []
    no_advice = {"attacks": 0, "normal": 0, "replicas": 0}
    clean = 0
    static_only = 0

    def seen(section: str, where: str, verdict: str | None, advice: dict | None, sample: dict | None) -> None:
        nonlocal clean
        if verdict == "clean":
            clean += 1
            return
        if advice is None:
            no_advice[section] += 1
        if verdict == "malicious" and (advice or {}).get("recommendation") in KEEPS:
            a_hits.append(where)
        if sample is not None:
            _count(sample, where, advice)

    for a in attacks:
        for s in a.get("advice") or []:
            where = f"attacks/{a['id']}: {s.get('target')}"
            sample = on_malicious if s.get("verdict") == "malicious" else rated_susp
            seen("attacks", where, s.get("verdict"), s.get("advice"), sample)
    for n in normal:
        for s in n.get("advice") or []:
            seen("normal", f"normal/{n['id']}: {s.get('target')}", s.get("verdict"), s.get("advice"), benign)
    for where, r in _replica_reports(replicas or {}):
        if "static" in where and r.get("advice") is None and r.get("verdict") != "clean":
            static_only += 1
            continue
        seen("replicas", where, r.get("verdict"), r.get("advice"), None)
    for t in (on_malicious, rated_susp, benign):
        t["keep_or_care"] = t["keep"] + t["keep-with-care"]
        t["dont_or_cant"] = t["dont-install"] + t["cant-tell"]
    return {
        "unit": "scan reports (non-clean) written during each entry; see run_eval.py: reviewer_summary",
        "a_keep_on_malicious_verdict": {"count": len(a_hits), "where": a_hits, "must_be": 0},
        "b_malicious_samples_rated_suspicious": rated_susp,
        "malicious_samples_rated_malicious": on_malicious,
        "c_benign_samples": benign,
        "d_no_advice": {"total": sum(no_advice.values()), **no_advice},
        "clean_not_reviewed": clean,
        "static_only_not_reviewed": static_only,
    }


def check_reviewer_invariant(summary: dict) -> None:
    """Raise when (a) is not 0. Called after the results are written, so the evidence is on disk."""
    a = (summary.get("reviewer") or {}).get("a_keep_on_malicious_verdict") or {}
    if a.get("count"):
        raise ReviewerInvariantBroken(
            f"{a['count']} report(s) rated MALICIOUS got keep/keep-with-care from the reviewer, which spec §4a "
            f"rules out by construction: " + "; ".join(a.get("where", [])[:20]))


def summarise(attacks: list[dict], normal: list[dict], replicas: dict | None = None) -> dict:
    fam: dict[str, dict] = {}
    for a in attacks:
        f = fam.setdefault(a["family"], {"n": 0, "blocked_before": 0, "caught_after_of_passed": 0, "passed_gate": 0,
                                         "missed": 0, "effect_check_alone": 0, "residual_missed": 0,
                                         "blocked_fetch_failed": 0})
        f["n"] += 1
        f["blocked_before"] += a["blocked_before"]
        f["blocked_fetch_failed"] += a.get("blocked_fetch_failed", False)
        f["effect_check_alone"] += a["caught_after"]
        if not a["blocked_before"]:
            f["passed_gate"] += 1
            f["caught_after_of_passed"] += a["caught_after"]
        if a["outcome"] == "missed":
            f["missed"] += 1
            f["residual_missed"] += a.get("expected") == "missed"  # documented misses only (not "parked" notes)
    misses = [{"id": a["id"], "family": a["family"], "outcome": a["outcome"], "expected": a["expected"],
               "residual": a.get("residual")} for a in attacks if a["outcome"] == "missed" or not a["as_expected"]]
    fp = {"tasks": len(normal), "tasks_with_deny": sum(1 for n in normal if n["denies"]),
          "tasks_with_any_notice": sum(1 for n in normal if n["notices"]),
          "unexpected": [n["id"] for n in normal if n["notices"] and not n.get("by_design")],
          "by_design": [n["id"] for n in normal if n["notices"] and n.get("by_design")]}
    return {"families": fam, "misses": misses, "false_positives": fp,
            "reviewer": reviewer_summary(attacks, normal, replicas)}


# ------------------------------------------------------------------ reproducibility: compare two result sets

def comparable(d: Path) -> dict:
    """The parts of a results dir that must not change between runs of the same tree: decisions, outcomes,
    verdicts and findings. Timings, reason wording and the diff text are left out.

    So is everything the reviewer produced (spec §4a): the per-entry `advice` records, the replicas' `advice`, and
    `summary.reviewer`. Advice is model output and not deterministic, and it never changes a verdict, a finding
    or a decision, so two runs of the same tree may differ there and still match. (The gate's reason is
    classified with the advice block removed, for the same reason: see `without_advice`.)"""
    def load(name):
        p = d / f"{name}.json"
        return json.loads(p.read_text()) if p.exists() else None

    out: dict = {}
    if (att := load("attacks")) is not None:
        out["attacks"] = {a["id"]: {
            "outcome": a.get("outcome"), "blocked_before": a.get("blocked_before"),
            "caught_after": a.get("caught_after"), "gate": [(g["decision"], g["kind"]) for g in a.get("gate", [])],
            "post": (a["post"]["decision"], a["post"]["kind"]) if a.get("post") else None,
            "probe": (a["probe"]["decision"], a["probe"]["kind"]) if a.get("probe") else None,
            "error": a.get("error")} for a in att}
    if (nor := load("normal")) is not None:
        out["normal"] = {n["id"]: {"notices": n.get("notices"), "denies": n.get("denies"), "error": n.get("error")}
                         for n in nor}
    if (rep := load("replicas")) is not None:
        def strip(x):
            if isinstance(x, dict):
                return {k: strip(v) for k, v in x.items() if k not in ("diff_since_trusted", "advice")}
            return x
        out["replicas"] = strip(rep)
    if (summ := load("summary")) is not None:
        out["summary"] = {k: v for k, v in summ.items() if k != "reviewer"}
    # tuples -> lists, as they would come back from disk; mkdtemp suffixes (replicas-XXXXXXXX) don't count
    return json.loads(re.sub(r"replicas-[A-Za-z0-9_]{8}", "replicas-*", json.dumps(out)))


def compare_results(expected: Path | dict, got: Path | dict) -> list[str]:
    """Differences between two results dirs, or their `comparable` snapshots (only the sections both have)."""
    a = copy.deepcopy(expected) if isinstance(expected, dict) else comparable(expected)
    b = copy.deepcopy(got) if isinstance(got, dict) else comparable(got)
    diffs: list[str] = []

    def walk(x, y, where):
        if isinstance(x, dict) and isinstance(y, dict):
            for k in sorted(set(x) | set(y), key=str):
                if k not in y:
                    diffs.append(f"{where}/{k}: missing in this run")
                elif k not in x:
                    diffs.append(f"{where}/{k}: new in this run")
                else:
                    walk(x[k], y[k], f"{where}/{k}")
        elif x != y:
            diffs.append(f"{where}: expected {json.dumps(x)[:200]}, got {json.dumps(y)[:200]}")

    # a partial run (--ids) is compared on the entries it ran, and its summary is not compared
    partial = any(s in a and s in b and set(b[s]) < set(a[s]) for s in ("attacks", "normal"))
    for section in sorted(set(a) & set(b)):
        if section in ("attacks", "normal") and set(b[section]) < set(a[section]):
            a[section] = {k: v for k, v in a[section].items() if k in b[section]}
        if section == "summary" and partial:
            continue
        walk(a[section], b[section], section)
    return diffs


def _git_state() -> dict:
    def git(*args):
        r = subprocess.run(["git", "-C", str(ROOT), *args], capture_output=True, text=True, timeout=30)
        return r.stdout.strip() if r.returncode == 0 else None
    return {"commit": git("rev-parse", "HEAD"), "dirty": bool(git("status", "--porcelain", "--untracked-files=no"))}


def _report_compare(expected: dict, got: Path, label: str) -> int:
    if not expected:
        print(f"run_eval: nothing to compare with in {label}", file=sys.stderr)
        return 1
    diffs = compare_results(expected, got)
    if diffs:
        print(f"run_eval: {len(diffs)} difference(s) from {label}:", file=sys.stderr)
        for d in diffs[:200]:
            print(f"  {d}", file=sys.stderr)
        return 1
    print(f"run_eval: decisions, outcomes and findings match {label}", file=sys.stderr)
    return 0


def _isolation():
    """eval/isolation.py, loaded by path (eval/ is not a package)."""
    name = "bawwab_eval_isolation"
    if name not in sys.modules:
        import importlib.util

        spec = importlib.util.spec_from_file_location(name, EVAL / "isolation.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[name]


def run_isolated(a, expected: dict | None = None, exec_=None) -> int:
    """The outer half of --sandbox bwrap|docker|auto: re-run this script inside the sandbox, then copy its
    results out and record which sandbox ran them."""
    isolation = _isolation()

    try:
        runner = isolation.choose(a.sandbox, exec_)
        scratch = resolve_workdir(a.workdir) if a.workdir else Path(tempfile.mkdtemp(prefix="bawwab-eval-",
                                                                                        dir="/var/tmp"))
    except (isolation.IsolationUnavailable, Unsafe) as e:
        print(f"run_eval: refused: {e}", file=sys.stderr)
        return 2
    inner = ["--only", a.only] + (["--ids", a.ids] if a.ids else []) + (["--keep"] if a.keep else [])
    spec = isolation.Spec(repo=ROOT, scratch=scratch.resolve(), real_home=REAL_HOME, python=Path(sys.executable),
                          inner_args=inner)
    print(f"run_eval: running inside {runner.name} (scratch {spec.scratch})", file=sys.stderr)
    try:
        try:
            code = runner.run(spec)
        except isolation.IsolationUnavailable as e:
            print(f"run_eval: refused: {e}", file=sys.stderr)
            return 2
        meta_p = spec.inner_out / "meta.json"
        # EXIT_REVIEWER: the inner run finished and wrote its results, but the reviewer invariant failed; copy the
        # results out (the evidence) and still fail
        if code not in (0, EXIT_REVIEWER) or not meta_p.exists():
            print(f"run_eval: the sandboxed run failed (exit {code})", file=sys.stderr)
            return code or 1
        meta = json.loads(meta_p.read_text())
        iso = meta.get("meta", {}).get("isolation", {})
        if iso.get("runner") != runner.name or not iso.get("ok"):
            print(f"run_eval: the inner run did not confirm {runner.name} isolation: {iso}", file=sys.stderr)
            return 1
        meta["meta"].update(_git_state())
        meta_p.write_text(json.dumps(meta, indent=2) + "\n")
        if not a.no_write:
            out = Path(a.out)
            out.mkdir(parents=True, exist_ok=True)
            for f in sorted(spec.inner_out.glob("*.json")):
                shutil.copyfile(f, out / f.name)
        if code == EXIT_REVIEWER:
            print(f"run_eval: FAILED: the reviewer invariant (a) broke inside the sandbox (exit {code}); "
                  "see summary.json: reviewer", file=sys.stderr)
        if a.compare:
            rc = _report_compare(expected or {}, spec.inner_out, a.compare)
            return code or rc
        return code
    finally:
        if not a.keep:
            shutil.rmtree(scratch, ignore_errors=True)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--only", default="replicas,attacks,normal,latency,baseline")
    ap.add_argument("--ids", default="", help="comma-separated entry ids (attacks/normal) to run")
    ap.add_argument("--workdir", help="an empty or new dir; the run makes (and removes) its own temp dir inside it "
                                      "(default: a new /var/tmp/bawwab-eval-* dir)")
    ap.add_argument("--keep", action="store_true", help="keep the scratch dir")
    ap.add_argument("--out", default=str(RESULTS), help="where to write the results JSON")
    ap.add_argument("--no-write", action="store_true")
    ap.add_argument("--sandbox", choices=("auto", "bwrap", "docker", "none"), default="auto",
                    help="OS isolation for the whole run (default auto: bwrap, else docker, else refuse). "
                         "`none` is environment isolation only")
    ap.add_argument("--compare", nargs="?", const=str(RESULTS), default=None, metavar="DIR",
                    help="after the run, compare decisions/outcomes/findings with DIR (default: the committed "
                         "eval/results) and exit 1 on any difference")
    a = ap.parse_args(argv)
    # snapshot before anything is written: --compare and --out are the same dir by default
    expected = comparable(Path(a.compare)) if a.compare else None
    if a.sandbox != "none":
        return run_isolated(a, expected)
    isolation = _isolation()

    if os.environ.get(isolation.ENV_ISOLATION):
        iso = isolation.self_check(ROOT)
        if not iso["ok"]:
            print(f"run_eval: refused: the sandbox is leaky: {json.dumps(iso)}", file=sys.stderr)
            return 3
    else:
        iso = {"runner": "none", "ok": True, "checks": {},
               "note": "environment isolation only (scratch HOME/XDG, dead proxy, claude guard); no OS sandbox"}
    parts = set(a.only.split(","))
    ids = {x for x in a.ids.split(",") if x}
    try:
        work = resolve_workdir(a.workdir) if a.workdir else Path(tempfile.mkdtemp(prefix="bawwab-eval-",
                                                                                     dir="/var/tmp"))
    except Unsafe as e:
        print(f"run_eval: refused: {e}", file=sys.stderr)
        return 2
    sb = Sandbox(work.resolve())
    results: dict = {}
    try:
        sb.prepare()
        # in-process scans use the same scratch env
        for k in ("HOME", "BAWWAB_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME",
                  "TREE_SITTER_LANGUAGE_PACK_CACHE_DIR", "HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy",
                  "http_proxy", "all_proxy", "NO_PROXY", "no_proxy", "BAWWAB_FAKE_JUDGE", "PATH"):
            os.environ[k] = sb.env[k]
        for k in DROP_ENV:
            if k not in sb.env:
                os.environ.pop(k, None)
        check_safe(dict(os.environ), sb.work)
        if "replicas" in parts:
            results["replicas"] = run_replicas(sb)
        if "attacks" in parts:
            entries = load_yaml(EVAL / "redteam" / "attacks.yaml")["attacks"]
            results["attacks"] = [run_entry(sb, e) for e in entries if not ids or e["id"] in ids]
        if "normal" in parts:
            entries = load_yaml(EVAL / "redteam" / "normal.yaml")["tasks"]
            results["normal"] = [run_normal(sb, e) for e in entries if not ids or e["id"] in ids]
        if "latency" in parts:
            results["latency"] = run_latency(sb)
        if "baseline" in parts:
            results["baseline"] = run_baseline(sb)
        results["summary"] = summarise(results.get("attacks", []), results.get("normal", []),
                                       results.get("replicas"))
        results["guard_claude_invocations"] = sb.guard_log.read_text().splitlines() if sb.guard_log.exists() else []
        results["meta"] = {"method": f"hook replay (no live Claude), isolation: {iso['runner']}",
                           "python": sys.version.split()[0], "when": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
                           "isolation": iso}
        if not os.environ.get(isolation.ENV_ISOLATION):
            results["meta"].update(_git_state())
    finally:
        if not a.keep:  # only the dir this run created (never the --workdir itself)
            shutil.rmtree(work, ignore_errors=True)
    if not a.no_write:
        out = Path(a.out)
        out.mkdir(parents=True, exist_ok=True)
        def dump(obj) -> str:  # no machine-specific paths in the committed results
            text = json.dumps(obj, indent=2, default=str)
            # the scratch dir's parent too: a reason cut short mid-path ("…/bawwab-ev…") keeps only that prefix
            for real, shown in ((str(sb.work), "<scratch>"), (str(sb.work.parent), "<workdir>"), (str(ROOT), "<repo>"),
                                (str(REAL_HOME), "~")):
                text = text.replace(real, shown).replace(quote(real, safe=""), quote(shown, safe=""))
            return text

        for k in ("replicas", "attacks", "normal", "latency", "baseline", "summary"):
            if k in results:
                (out / f"{k}.json").write_text(dump(results[k]) + "\n")
        (out / "meta.json").write_text(dump({"meta": results["meta"],
                                             "guard_claude_invocations": results["guard_claude_invocations"]}) + "\n")
    print(json.dumps(results.get("summary", {}), indent=2))
    broken = reviewer_failure(results.get("summary", {}))
    if a.compare and not a.no_write:
        rc = _report_compare(expected or {}, Path(a.out), a.compare)
        return EXIT_REVIEWER if broken else rc
    return EXIT_REVIEWER if broken else 0


EXIT_REVIEWER = 4  # the reviewer invariant (a) failed; the results are written so the evidence can be read


def reviewer_failure(summary: dict) -> bool:
    """Print the failure loudly and return True when (a) is not 0."""
    try:
        check_reviewer_invariant(summary)
    except ReviewerInvariantBroken as e:
        bar = "!" * 78
        print(f"{bar}\nrun_eval: FAILED: reviewer invariant (a): {e}\n{bar}", file=sys.stderr)
        return True
    return False


if __name__ == "__main__":
    sys.exit(main())
