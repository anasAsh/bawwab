"""Scan every target in report/targets.json with Bawwab's static rules and record the results.

    report/run_scan.sh [--only ID[,ID...]] [--limit N] [--retry-errors]

(run_scan.sh sets up an isolated HOME/BAWWAB_HOME/XDG/TMPDIR; scan.py refuses to run against the
real home directory.)

* Static rules only: scan_target(..., judge=False). No AI review, no sandbox, nothing installed or run.
* npm/PyPI targets go through Bawwab's own download-only fetchers. GitHub targets are fetched at
  their pinned commit with the same hardened git settings the benchmark uses (hooks off, no
  submodules, no file/ext protocols), the .git folder is removed, and the folder is scanned as a
  local target.
* Each target runs in its own child process with a hard timeout (default 600 s); a timeout, crash or
  fetch failure is recorded as status "error" ("not verified"), never as clean.
* Resumable: results are written after every target and targets already recorded (with the same
  pinned spec) are skipped. --retry-errors re-runs the ones that errored.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import pwd
import re
import shutil
import signal
import subprocess
import sys
import time
from datetime import UTC, datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from report.collect import load_targets  # noqa: E402

OUT = ROOT / "report" / "out" / "results.json"
SCHEMA_VERSION = 1
TIMEOUT_S = 600
EVIDENCE_CAP = 300
# A report made of one gate finding with these rules means nothing was actually scanned.
NOT_SCANNED_RULES = {"fetch.failed", "gate.error"}


# ---------------------------------------------------------------- safety

def check_isolated_env() -> None:
    real = Path(pwd.getpwuid(os.getuid()).pw_dir).resolve()
    home = Path(os.environ.get("HOME", "")).resolve()
    bh = os.environ.get("BAWWAB_HOME")
    problems = []
    if home == real:
        problems.append("HOME is the real home directory")
    if not bh or Path(bh).resolve() in (real / ".bawwab", real):
        problems.append("BAWWAB_HOME must point at a throwaway folder")
    for v in ("CLAUDE_PLUGIN_DATA", "CLAUDE_PROJECT_DIR", "CLAUDE_PLUGIN_ROOT", "BAWWAB_SESSION_ID"):
        if os.environ.get(v):
            problems.append(f"{v} is set")
    for v in ("XDG_STATE_HOME", "XDG_CONFIG_HOME", "XDG_CACHE_HOME", "XDG_DATA_HOME"):
        p = os.environ.get(v)
        if p and Path(p).resolve().is_relative_to(real):
            problems.append(f"{v} points inside the real home")
    if problems:
        raise SystemExit("refusing to scan outside an isolated environment (use report/run_scan.sh): "
                         + "; ".join(problems))


# ---------------------------------------------------------------- bawwab identity

def bawwab_commit() -> tuple[str, bool]:
    def git(*a: str) -> str:
        r = subprocess.run(["git", "-C", str(ROOT), *a], capture_output=True, text=True, timeout=30)
        return r.stdout.strip() if r.returncode == 0 else ""
    # The last commit that changed the scanner, so report-only commits do not force a rescan.
    sha = git("log", "-1", "--format=%H", "--", "bawwab") or git("rev-parse", "HEAD") or "unknown"
    dirty = bool(git("status", "--porcelain", "--untracked-files=no", "--", "bawwab"))
    return sha, dirty


def finding_key(rule: str, file: str | None, line: int | None, evidence: str) -> str:
    return hashlib.sha256(f"{rule}\0{file or ''}\0{line or ''}\0{evidence}".encode()).hexdigest()[:12]


# ---------------------------------------------------------------- one target (child process)

def git_checkout(spec: str, cache: Path) -> Path:
    """Fetch one pinned commit, files only (hooks off, no submodules; nothing is run)."""
    from bawwab.fetch.git import _run

    url, _, rest = spec[4:].rpartition("@")
    sha, _, sub = rest.partition("#")
    if not re.fullmatch(r"[0-9a-f]{40}", sha) or not url.startswith("https://github.com/"):
        raise ValueError("git spec must be an https GitHub URL pinned to a 40-hex commit")
    repo = cache / f"{re.sub(r'[^A-Za-z0-9._-]+', '_', url)}@{sha}"
    if not (repo / ".fetch-complete").exists():
        shutil.rmtree(repo, ignore_errors=True)
        home = cache / ".home"
        home.mkdir(parents=True, exist_ok=True)
        cfg = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "protocol.file.allow=never",
               "-c", "protocol.ext.allow=never"]
        _run(["git", "init", "-q", str(repo)], 120, home)
        _run(["git", *cfg, "-C", str(repo), "fetch", "-q", "--depth", "1", "--no-recurse-submodules", "--", url, sha],
             300, home)
        _run(["git", *cfg, "-C", str(repo), "-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"],
             120, home)
        shutil.rmtree(repo / ".git", ignore_errors=True)
        (repo / ".fetch-complete").write_text(sha)
    target = (repo / sub).resolve() if sub else repo
    if repo.resolve() not in (target, *target.parents) or not target.is_dir():
        raise ValueError(f"subdirectory {sub!r} not found at {sha[:12]}")
    return target


def keep_copy(target, tid: str, work: Path) -> str | None:
    """Download a flagged registry package again (files only) and keep it under work/pkgs/<id> for the
    hand-check. scan_target deletes its own download, so this is the reviewer's copy. Nothing is run."""
    from bawwab.fetch import FetchOpts, fetch_target

    dest = work / "pkgs" / re.sub(r"[^a-z0-9._-]+", "-", tid.lower())
    if dest.exists():
        return str(dest)
    try:
        f = fetch_target(target, FetchOpts())
    except Exception:  # noqa: BLE001 - the review list then says no local copy
        return None
    try:
        if f.root is None:
            return None
        shutil.copytree(f.root, dest, symlinks=True)
        return str(dest)
    finally:
        f.cleanup()


def scan_one(t: dict, work: Path) -> dict:
    from bawwab.config import Config
    from bawwab.fetch import FetchOpts, parse_target
    from bawwab.fetch.common import detect_artifact_type
    from bawwab.report import sanitise
    from bawwab.scan import scan_target
    from bawwab.severity import at_least
    from bawwab.store import Store
    from bawwab.types import Mode, Target

    cfg = Config(mode=Mode.STANDARD, trusted=[])  # trust nothing: no package gets a free pass
    store = Store(work / "store.db")
    spec = t["spec"]
    artifact = None
    local_path = None
    if spec.startswith("git:"):
        path = git_checkout(spec, work / "git")
        local_path = str(path)
        artifact = detect_artifact_type(path)
        target = Target("local", str(path), name="", path=str(path))
    else:
        target = parse_target(spec)
    r = scan_target(target, mode=Mode.STANDARD, cfg=cfg, store=store, no_cache=True, judge=False,
                    fetch_opts=FetchOpts())
    findings = []
    for f in r.findings:
        ev = sanitise(f.evidence, EVIDENCE_CAP)
        file = sanitise(f.file, 300) if f.file else None
        findings.append({
            "key": finding_key(f.rule, file, f.line, ev), "rule": f.rule, "severity": f.severity.value,
            "source": f.source, "file": file, "line": f.line, "evidence": ev,
            "counted": at_least(f.severity, cfg.suspicious),
        })
    unscanned = (r.resolved_version == "unknown" and len(r.findings) == 1
                 and r.findings[0].rule in NOT_SCANNED_RULES and r.findings[0].source == "gate")
    if not unscanned and r.verdict.value != "clean" and local_path is None:
        local_path = keep_copy(target, t.get("id") or "target", work)
    return {
        "status": "error" if unscanned else "ok",
        "local_path": local_path,
        "error": findings[0]["evidence"] if unscanned else None,
        "verdict": r.verdict.value,
        "resolved_version": sanitise(r.resolved_version, 120),
        "artifact_type": artifact,
        "findings": findings,
    }


def child_main(target_json: str, work: str) -> int:
    t = json.loads(target_json)
    try:
        out = scan_one(t, Path(work))
    except Exception as e:  # noqa: BLE001 - any failure is "not verified"
        from bawwab.report import sanitise
        out = {"status": "error", "error": sanitise(f"{type(e).__name__}: {e}", 300), "verdict": None, "local_path": None,
               "resolved_version": None, "artifact_type": None, "findings": []}
    sys.stdout.write("\n@@RESULT@@" + json.dumps(out) + "\n")
    return 0


# ---------------------------------------------------------------- driver

def run_child(t: dict, work: Path, timeout: float) -> dict:
    cmd = [sys.executable, "-I", str(Path(__file__).resolve()), "--child", json.dumps(t), "--work", str(work)]
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, start_new_session=True)
    try:
        so, se = p.communicate(timeout=timeout)
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        p.communicate()
        return {"status": "error", "error": f"timed out after {int(timeout)} s", "verdict": None,
                "resolved_version": None, "artifact_type": None, "findings": []}
    marker = so.rfind("@@RESULT@@")
    if marker < 0:
        from bawwab.report import sanitise
        tail = sanitise(se[-400:], 300) if se else f"exit code {p.returncode}"
        return {"status": "error", "error": f"scanner crashed: {tail}", "verdict": None,
                "resolved_version": None, "artifact_type": None, "findings": []}
    return json.loads(so[marker + len("@@RESULT@@"):].strip().splitlines()[0])


def is_done(prev: dict | None, spec: str, commit: str, ruleset: str, retry_errors: bool = False) -> bool:
    """A recorded result is reused only for the same pin, Bawwab commit and rule set, so one run is one commit."""
    if not prev or prev.get("spec") != spec:
        return False
    if prev.get("bawwab_commit") != commit or prev.get("ruleset_version") != ruleset:
        return False
    return not (retry_errors and prev.get("status") == "error")


def load_results(path: Path) -> dict:
    if path.exists():
        d = json.loads(path.read_text())
        if d.get("schema") == SCHEMA_VERSION:
            return d
    return {"schema": SCHEMA_VERSION, "static_only": True, "results": {}}


def save_results(path: Path, d: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(d, indent=1, ensure_ascii=False) + "\n")
    tmp.replace(path)


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", type=Path, default=ROOT / "report" / "targets.json")
    ap.add_argument("--out", type=Path, default=OUT)
    ap.add_argument("--work", type=Path, default=None, help="download/cache folder (default $TMPDIR/bawwab-report)")
    ap.add_argument("--only", default="", help="comma-separated target ids")
    ap.add_argument("--limit", type=int, default=0)
    ap.add_argument("--timeout", type=float, default=TIMEOUT_S)
    ap.add_argument("--retry-errors", action="store_true")
    ap.add_argument("--child", help=argparse.SUPPRESS)
    a = ap.parse_args(argv)
    check_isolated_env()
    work = a.work or Path(os.environ.get("TMPDIR", "/var/tmp")) / "bawwab-report"
    work.mkdir(parents=True, exist_ok=True)
    if a.child:
        return child_main(a.child, str(work))

    from bawwab.ruleset import RULESET_VERSION

    targets = load_targets(a.targets)
    if a.only:
        want = set(a.only.split(","))
        targets = [t for t in targets if t["id"] in want]
    res = load_results(a.out)
    commit, dirty = bawwab_commit()
    todo = []
    for t in targets:
        prev = res["results"].get(t["id"])
        if is_done(prev, t["spec"], commit, RULESET_VERSION, a.retry_errors):
            continue
        todo.append(t)
    if a.limit:
        todo = todo[: a.limit]
    print(f"{len(todo)} to scan, {len(targets) - len(todo)} already done", file=sys.stderr)
    res.setdefault("started_at", datetime.now(UTC).isoformat(timespec="seconds"))
    for i, t in enumerate(todo, 1):
        t0 = time.monotonic()
        out = run_child(t, work, a.timeout)
        out.update({
            "id": t["id"], "spec": t["spec"], "kind": t["kind"], "name": t["name"],
            "duration_s": round(time.monotonic() - t0, 1),
            "scanned_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "bawwab_commit": commit, "bawwab_dirty": dirty, "ruleset_version": RULESET_VERSION,
        })
        res["results"][t["id"]] = out
        res.update({"bawwab_commit": commit, "bawwab_dirty": dirty, "ruleset_version": RULESET_VERSION,
                    "timeout_s": a.timeout, "static_only": True,
                    "updated_at": datetime.now(UTC).isoformat(timespec="seconds")})
        save_results(a.out, res)
        print(f"[{i}/{len(todo)}] {out['duration_s']:>6}s {out['status']:5} {out['verdict'] or '-':10} {t['id']}",
              file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
