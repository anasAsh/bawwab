"""Recall gate: every malicious sample must keep at least the verdict it gets today.

    uv run python bench/recall_gate.py                     # check against bench/recall_baseline.json
    uv run python bench/recall_gate.py --update            # re-record the baseline (review the diff!)
    uv run python bench/recall_gate.py --datadog [--datadog-cache DIR]   # also the DataDog set (local only)

The CI form is tests/test_fp_corpus.py::test_recall_gate (marker `recall`, part of `-m "not timing"`).

Sets (all scanned with the current rules, static, offline: sockets refused except loopback, OSV stubbed to
"no advisories"):
* bench: every sample under bench/corpus/malicious, scanned the way bench/run.py --static-only scans it
  (bench.run.Scanner.sample: its label's package name, and cross-server checks for multi-server samples).
* replicas: eval/replicas/<incident>/{v1,v2} as fresh local targets (static only); the rug-pull path (v1 scanned
  and trusted, then the same folder becomes v2), with a fake AI judge that never reports anything, so only the
  static rules and the trust diff produce findings; the cross-server check (postmark v1 + the shadowing weather
  server v2 installed together); and the typosquat replica scanned under its typosquatted npm name.
* datadog (opt-in, local): the pinned DataDog sample (bench/datadog.lock.json) from an existing local cache of
  the encrypted zips. Never downloaded here: a missing or mismatching zip is reported and skipped.

A sample fails the gate when its verdict drops a level (malicious > suspicious > clean) or when it had at least
one counted finding (severity >= the suspicious threshold) and now has none. Rules that disappear while the
verdict holds are listed as warnings, not failures.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
import shutil
import sys
import tempfile
from pathlib import Path

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

BASELINE = BENCH / "recall_baseline.json"
REPLICAS = ROOT / "eval" / "replicas"
DATADOG_CACHE = BENCH / ".cache" / "datadog"
LEVELS = {"clean": 0, "suspicious": 1, "malicious": 2}
TYPOSQUAT_NAME = "@modelcontextprotocal/server-filesystem"  # the name run_eval's npm path publishes v2 under


def _load(name: str):
    mod_name = f"bench_{name}"
    if mod_name not in sys.modules:
        spec = importlib.util.spec_from_file_location(mod_name, BENCH / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[mod_name]


def offline(**kw) -> None:
    """The same network guards as the FP-corpus rescan (bench/fp_corpus.py)."""
    _load("fp_corpus").install_offline_guards(**kw)


class FakeJudge:
    """Never reports anything (as eval/run_eval.py's FakeJudge): judged scans stay offline and deterministic."""

    def complete(self, system, user, schema, timeout_s):
        return '{"findings":[]}'


def _rec(verdict: str, rules) -> dict:
    return {"verdict": verdict, "rules": sorted(set(rules))}


# ------------------------------------------------------------------ the sets

def scan_bench(corpus: Path = BENCH / "corpus") -> dict:
    run = _load("run")
    sc = run.Scanner(static_only=True, backend="api", no_cache=True)
    out = {}
    try:
        for sid, path, label in run.load_corpus(corpus):
            if not sid.startswith("malicious/"):
                continue
            r = sc.sample(sid, path, label)
            out[sid] = _rec(r.verdict, r.rules)
    finally:
        sc.close()
    return out


def scan_replicas(replicas: Path = REPLICAS) -> dict:
    from bawwab.config import Config
    from bawwab.scan import scan_target
    from bawwab.severity import compute_verdict
    from bawwab.store import Store
    from bawwab.trust import cross_server_findings
    from bawwab.types import Mode, Target

    cfg = Config(mode=Mode.STANDARD, trusted=[])
    th = cfg.suspicious
    tmp = Path(tempfile.mkdtemp(prefix="bawwab-recall-"))

    def local(p: Path, name: str = "") -> Target:
        return Target("local", str(p), name=name, path=str(p.resolve()))

    def scan(t, store, judge: bool):
        return scan_target(t, mode=Mode.STANDARD, cfg=cfg, store=store, backend=FakeJudge(), judge=judge,
                           no_cache=True)

    def rec(r) -> dict:
        return _rec(r.verdict.value, [f.rule for f in r.findings if f.severity >= th])

    def copy(src: Path, dst: Path) -> Path:
        shutil.copytree(src, dst, symlinks=True, dirs_exist_ok=True)
        return dst

    out: dict = {}
    try:
        incidents = sorted(p.name for p in replicas.iterdir() if (p / "v1").is_dir() and (p / "v2").is_dir())
        for n, inc in enumerate(incidents):
            for v in ("v1", "v2"):
                d = copy(replicas / inc / v, tmp / f"fresh-{n}-{v}" / v)
                out[f"{inc}/{v}"] = rec(scan(local(d), Store(tmp / f"{inc}-{v}.db"), judge=False))
            st = Store(tmp / f"{inc}-update.db")
            work = copy(replicas / inc / "v1", tmp / "update" / inc)
            t = local(work)
            scan(t, st, judge=True)  # v1 installed: trusted baseline
            shutil.rmtree(work)
            copy(replicas / inc / "v2", work)
            out[f"{inc}/update_v2"] = rec(scan(t, st, judge=True))
        if "mcp_typosquat" in incidents:
            d = copy(replicas / "mcp_typosquat" / "v2", tmp / "named" / "server-filesystem")
            out["mcp_typosquat/v2_named"] = rec(scan(local(d, TYPOSQUAT_NAME), Store(tmp / "named.db"),
                                                     judge=False))
        if {"postmark_rugpull", "cross_server_shadowing"} <= set(incidents):
            st = Store(tmp / "cross.db")
            mail = copy(replicas / "postmark_rugpull" / "v1", tmp / "cross" / "postmark")
            weather = copy(replicas / "cross_server_shadowing" / "v2", tmp / "cross" / "weather")
            scan(local(mail), st, judge=True)
            scan(local(weather), st, judge=True)
            xs = cross_server_findings(st.all_snapshots())
            out["cross_server_check"] = _rec(compute_verdict(xs, cfg.malicious, cfg.suspicious).value,
                                             [f.rule for f in xs if f.severity >= th])
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    return out


def _git_blob_sha(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def scan_datadog(cache: Path = DATADOG_CACHE) -> tuple[dict, list[str]]:
    """(results, missing) for the pinned DataDog sample, from the local cache only."""
    dd = _load("fetch_datadog")
    run = _load("run")
    sc = run.Scanner(static_only=True, backend="api", no_cache=True)
    lock = json.loads(dd.LOCK.read_text())
    out, missing = {}, []
    tmp = Path(tempfile.mkdtemp(prefix="bawwab-recall-dd-"))
    try:
        for i, s in enumerate(lock["samples"]):
            sid = f"{s['ecosystem']}/{s['package']}"
            z = cache / s["ecosystem"] / f"{s['blob']}.zip"
            if not z.is_file() or _git_blob_sha(z) != s["blob"] or (
                    s.get("sha256") and hashlib.sha256(z.read_bytes()).hexdigest() != s["sha256"]):
                missing.append(sid)
                continue
            work = tmp / str(i)
            root, _ = dd.unpack(z, s["ecosystem"], work)
            r = sc.scan(run._local(root, s["package"]), sc.local_store)
            out[sid] = _rec(r.verdict.value, sc.counted(r))
            shutil.rmtree(work, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
        sc.close()
    return out, missing


# ------------------------------------------------------------------ the gate

def check(baseline: dict, current: dict) -> tuple[list[str], list[str]]:
    """(failures, warnings) for one set: {sample id: {"verdict", "rules"}} each."""
    fails, warns = [], []
    for sid, b in sorted(baseline.items()):
        c = current.get(sid)
        if c is None:
            fails.append(f"{sid}: in the baseline but not scanned")
            continue
        if LEVELS[c["verdict"]] < LEVELS[b["verdict"]]:
            fails.append(f"{sid}: verdict dropped {b['verdict']} -> {c['verdict']} (rules now: "
                         f"{', '.join(c['rules']) or 'none'}; were: {', '.join(b['rules']) or 'none'})")
        elif b["rules"] and not c["rules"]:
            fails.append(f"{sid}: lost its last counted finding (were: {', '.join(b['rules'])})")
        else:
            lost = sorted(set(b["rules"]) - set(c["rules"]))
            if lost:
                warns.append(f"{sid}: no longer counts {', '.join(lost)} (verdict {c['verdict']} holds)")
    for sid in sorted(set(current) - set(baseline)):
        warns.append(f"{sid}: new sample, not in the baseline")
    return fails, warns


def counts(s: dict) -> dict:
    out = {k: 0 for k in LEVELS}
    for r in s.values():
        out[r["verdict"]] += 1
    return out


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--update", action="store_true", help="write the current verdicts as the new baseline")
    ap.add_argument("--baseline", type=Path, default=BASELINE)
    ap.add_argument("--datadog", action="store_true", help="also the DataDog set, from the local cache")
    ap.add_argument("--datadog-cache", type=Path, default=DATADOG_CACHE)
    a = ap.parse_args(argv)
    offline()
    cur = {"bench": scan_bench(), "replicas": scan_replicas()}
    missing: list[str] = []
    if a.datadog:
        cur["datadog"], missing = scan_datadog(a.datadog_cache)
        if missing:
            print(f"datadog: {len(missing)} sample(s) not in the local cache (not downloaded): "
                  f"{', '.join(missing[:10])}{' ...' if len(missing) > 10 else ''}", file=sys.stderr)
    base = json.loads(a.baseline.read_text()) if a.baseline.exists() else {}
    if a.update:
        new = {**base, **cur, "about": "per-sample verdict and counted rules; see bench/recall_gate.py"}
        if "datadog" in cur:
            new["datadog_missing"] = missing
        a.baseline.write_text(json.dumps(new, indent=1, sort_keys=True) + "\n")
        for k in ("bench", "replicas", "datadog"):
            if k in cur:
                print(f"{k}: {len(cur[k])} samples, verdicts {counts(cur[k])}", file=sys.stderr)
        return 0
    rc = 0
    for k, v in cur.items():
        fails, warns = check(base.get(k) or {}, v)
        print(f"{k}: {len(v)} samples, verdicts {counts(v)}; {len(fails)} failure(s)", file=sys.stderr)
        for w in warns:
            print(f"  warning: {w}", file=sys.stderr)
        for f in fails:
            print(f"  FAIL: {f}", file=sys.stderr)
        rc = rc or (1 if fails else 0)
    return rc


if __name__ == "__main__":
    sys.exit(main())
