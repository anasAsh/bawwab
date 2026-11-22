"""False-positive corpus: the reviewed real-world findings, and an offline rescan of them with the current rules.

    uv run python bench/fp_corpus.py build                 # (re)write bench/fp_corpus.json from report/ data
    uv run python bench/fp_corpus.py rescan [--jobs N] [--only ID,...] [--work DIR] [--json OUT]

What it measures. report/results.json is a static-rules scan of popular real MCP servers, skills and plugins
(pinned), and report/review.json gives every counted finding a reviewed status (false-positive,
expected-behaviour or confirmed). `build` turns that into bench/fp_corpus.json: per target the id, pin, local copy
(relative to the report run's work folder), old verdict, the rule/glob review entries, and one row per counted
finding (key, rule, severity, file, line, evidence hash, status). Clean targets whose pinned checkout is also on
disk are included with no findings, so a rule change that starts flagging them shows up as new findings.

`rescan` scans every corpus target that has a local copy, with the CURRENT rules, and reports, per rule and
overall: counted findings now present (split into reviewed false-positive / expected / confirmed / unreviewed),
how many are new, and how many previously counted findings disappeared (by their reviewed status). A false-positive
fix should move findings from "now: false-positive" to "gone: false-positive" and leave "gone: confirmed" at 0
and "new: unreviewed" low.

How a target is rescanned (static only, judge=False, no network):
* each target runs in its own `python -I` child process with a timeout (default 600 s, as report/scan.py);
* git targets are scanned exactly as the report scanned them: the same local folder, as a local target;
* npm/PyPI targets are scanned under their registry Target (same name, version and kind, so the npm-only
  `prepare` adjustment R31 applies) but the fetch step is replaced by the local copy report/scan.py kept
  (keep_copy). Registry metadata is NOT available: no first-publish date and no repository URL, so the
  identity.new-package and identity.repo-mismatch checks cannot fire (no such finding was counted in the corpus);
* OSV lookups are stubbed to "no advisories" (bawwab.scan.osv._post returns {}), as the tests do;
* every other non-local fetch (a plugin's npm/PyPI/remote bundled server) is refused with "offline rescan:"; its
  `fetch.failed` finding and the old findings of that server (evidence "[server NAME] ...") are put in an
  "offline" bucket on both sides and are not compared;
* outbound sockets are refused in the child (loopback and Unix sockets only) and the proxy variables point at a
  dead port, so nothing can reach the network even by mistake. Nothing scanned is ever run.
* the env-flow analysis stops a file after 2 s of wall-clock time (MED files.truncated "environment-flow analysis
  budget exceeded"). That is load-dependent: run with --jobs 1 (the default) on a quiet machine for numbers that
  compare with the report's serial scan; the report counts such new findings separately.
* verdicts in the comparison are recomputed from the compared findings (critical -> malicious, any counted ->
  suspicious), so a finding moved to the offline bucket does not change a target's verdict.

Matching old to new findings, per target, as multisets, in three passes (each pass only sees what is left):
  1. key           the report's finding key: sha256(rule, file, line, evidence)[:12]. Stable while the pinned
                   source and the rule's evidence text and line do not change.
  2. rule+file+evidence   catches a finding whose line moved (a rule now reports another line of the same match).
  3. rule+file+line       catches a finding whose evidence text changed (wording, capping) at the same place.
Limits: a finding whose evidence AND line both change, or that moves to another file or rule, counts as one gone
plus one new. When several identical candidates exist, pairing is by line order, which can swap two duplicates
(harmless for the counts). A new finding with no old partner takes its status from the target's rule/glob review
entries when one matches (build_site.match_review); such findings are reported separately ("new, glob-reviewed")
because the reviewer never saw that exact line. Key-only reviews never cover new findings.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

CORPUS = BENCH / "fp_corpus.json"
REPORT = ROOT / "report"
DEFAULT_WORK = Path("/var/tmp/bawwab-report-500/work")
OFFLINE_MARK = "offline rescan:"
TIMEOUT_S = 600
EVIDENCE_CAP = 300
FIELDS = ["key", "rule", "severity", "file", "line", "ev", "status", "server"]
STATUSES = ("false-positive", "expected-behaviour", "confirmed", "unreviewed")
SEVERITY_RANK = {"low": 0, "med": 1, "high": 2, "critical": 3}
RESULT_MARK = "@@FPRESULT@@"
_SERVER = re.compile(r"^\[server ([^\]]+)\] ")


def ev_hash(evidence: str) -> str:
    return hashlib.sha256((evidence or "").encode()).hexdigest()[:12]


# ------------------------------------------------------------------ build

def _review_module():
    from report import build_site

    return build_site


def build_corpus(targets: list[dict], results: dict, review: dict, work: Path) -> dict:
    """The corpus dict from report/targets.json targets, results.json `results` and review.json."""
    bs = _review_module()
    rv = review.get("targets") or {}
    out = []
    for tg in targets:
        res = results.get(tg["id"])
        if not res or res.get("status") != "ok" or res.get("spec") != tg["spec"]:
            continue
        counted = [f for f in res.get("findings") or [] if f.get("counted")]
        lp = res.get("local_path")
        if not counted and not (lp and Path(lp).is_dir()):
            continue  # clean and nothing on disk to rescan
        entries = (rv.get(tg["id"]) or {}).get("findings") or []
        rows = []
        for f in counted:
            r = bs.match_review(entries, f)
            m = _SERVER.match(f.get("evidence") or "")  # a bundled server's finding: "[server NAME] ..."
            rows.append([f.get("key"), f.get("rule"), f.get("severity"), f.get("file"), f.get("line"),
                         ev_hash(f.get("evidence") or ""), r["status"] if r else "unreviewed",
                         m.group(1) if m else None])
        globs = [[(e.get("match") or {}).get("rule"), (e.get("match") or {}).get("file"), e.get("status")]
                 for e in entries if "key" not in (e.get("match") or {}) and (e.get("match") or {}).get("rule")]
        rel = None
        if lp:
            p = Path(lp)
            try:
                rel = str(p.relative_to(work))
            except ValueError:
                rel = str(p)
        out.append({"id": tg["id"], "spec": tg["spec"], "kind": tg.get("kind"),
                    "version": res.get("resolved_version"), "local": rel, "verdict": res.get("verdict"),
                    "globs": globs, "findings": rows})
    return {"schema": 1, "about": "see bench/fp_corpus.py", "finding_fields": FIELDS,
            "work_default": str(work), "targets": out}


def write_corpus(c: dict, path: Path) -> None:
    """One target header per line and one finding per line: compact, and diffs stay readable."""
    lines = ["{", f' "schema": {c["schema"]},', f' "about": {json.dumps(c["about"])},',
             f' "finding_fields": {json.dumps(c["finding_fields"])},',
             f' "work_default": {json.dumps(c["work_default"])},', ' "targets": [']
    for i, t in enumerate(c["targets"]):
        head = {k: v for k, v in t.items() if k != "findings"}
        rows = t["findings"]
        body = json.dumps(head, ensure_ascii=False)[:-1] + ', "findings": ['
        if rows:
            body += "\n" + ",\n".join("   " + json.dumps(r, ensure_ascii=False) for r in rows) + "\n  ]}"
        else:
            body += "]}"
        lines.append("  " + body + ("," if i < len(c["targets"]) - 1 else ""))
    lines += [" ]", "}"]
    path.write_text("\n".join(lines) + "\n")


def load_corpus(path: Path = CORPUS) -> dict:
    c = json.loads(path.read_text())
    fields = c["finding_fields"]
    for t in c["targets"]:
        t["findings"] = [dict(zip(fields, r)) for r in t["findings"]]
    return c


# ------------------------------------------------------------------ matching and report math (pure)

def match_findings(old: list[dict], new: list[dict]) -> tuple[list[tuple[dict, dict, str]], list[dict], list[dict]]:
    """Pair old and new findings of ONE target: (pairs (old, new, how), old left over, new left over).
    Each finding is a dict with key, rule, file, line, ev (evidence hash)."""
    passes = [
        ("key", lambda f: f.get("key")),
        ("rule+file+evidence", lambda f: (f.get("rule"), f.get("file"), f.get("ev"))),
        ("rule+file+line", lambda f: (f.get("rule"), f.get("file"), f.get("line")) if f.get("line") is not None
         else None),
    ]
    order = lambda f: (f.get("line") is None, f.get("line") or 0)  # noqa: E731
    old_left = sorted(old, key=order)
    new_left = sorted(new, key=order)
    pairs: list[tuple[dict, dict, str]] = []
    for how, sig in passes:
        pool: dict = {}
        for n in new_left:
            s = sig(n)
            if s is not None:
                pool.setdefault(s, []).append(n)
        still_old = []
        used: set[int] = set()
        for o in old_left:
            s = sig(o)
            cand = pool.get(s) if s is not None else None
            if cand:
                n = cand.pop(0)
                used.add(id(n))
                pairs.append((o, n, how))
            else:
                still_old.append(o)
        old_left = still_old
        new_left = [n for n in new_left if id(n) not in used]
    return pairs, old_left, new_left


def glob_status(globs: list[list], f: dict) -> str | None:
    bs = _review_module()
    entries = [{"match": {"rule": r, **({"file": g} if g is not None else {})}, "status": s} for r, g, s in globs]
    m = bs.match_review(entries, {"rule": f.get("rule"), "file": f.get("file") or "", "key": None})
    return m["status"] if m else None


def _blank() -> dict:
    d = {"before": 0, "now": 0, "new": 0, "new_glob_reviewed": 0, "offline_old": 0, "offline_new": 0,
         "error_old": 0}
    for s in STATUSES:
        d[f"now_{s}"] = 0
        d[f"gone_{s}"] = 0
    return d


def _verdict(counted: list[dict]) -> str:
    if not counted:
        return "clean"
    return "malicious" if any(f.get("severity") == "critical" for f in counted) else "suspicious"


def _timing(f: dict) -> bool:
    """files.truncated from a wall-clock analysis budget: depends on machine load (see --jobs)."""
    return f.get("rule") == "files.truncated" and "budget exceeded" in (f.get("evidence") or "")


def compare_target(t: dict, scan: dict | None) -> dict:
    """Classify one target. `scan` is a rescan result: {"status", "verdict", "findings": [... counted ...]}
    or None/status!="ok" when it could not be rescanned."""
    rules: dict[str, dict] = {}
    rec = {"id": t["id"], "old_verdict": t.get("verdict"), "new_verdict": None, "status": "ok", "how": Counter(),
           "new": [], "gone": []}

    def r(rule: str) -> dict:
        return rules.setdefault(rule, _blank())

    old = t["findings"]
    if scan is None or scan.get("status") != "ok":
        rec["status"] = (scan or {}).get("status") or "missing"
        rec["error"] = (scan or {}).get("error")
        for o in old:
            r(o["rule"])["error_old"] += 1
        rec["rules"] = rules
        return rec
    rec["raw_verdict"] = scan.get("verdict")
    new = [f for f in scan.get("findings") or [] if f.get("counted", True)]
    offline_servers = {m.group(1) for f in new if f.get("rule") == "fetch.failed" and OFFLINE_MARK in
                       (f.get("evidence") or "") and (m := _SERVER.match(f.get("evidence") or ""))}
    top_offline = any(f.get("rule") == "fetch.failed" and OFFLINE_MARK in (f.get("evidence") or "")
                      and not _SERVER.match(f.get("evidence") or "") for f in new)

    def offline_new(f: dict) -> bool:
        return f.get("rule") == "fetch.failed" and OFFLINE_MARK in (f.get("evidence") or "")

    def offline_old(o: dict) -> bool:
        return o.get("server") in offline_servers if o.get("server") else False

    cmp_new = []
    for f in new:
        if offline_new(f):
            r(f["rule"])["offline_new"] += 1
        else:
            cmp_new.append(f)
    cmp_old = []
    for o in old:
        if offline_old(o) or top_offline:
            r(o["rule"])["offline_old"] += 1
        else:
            cmp_old.append(o)
    # The verdict the compared findings give (static thresholds: critical -> malicious, counted -> suspicious), so
    # a clean plugin whose remote server is unreachable offline is not counted as newly flagged.
    rec["old_verdict"], rec["new_verdict"] = _verdict(cmp_old), _verdict(cmp_new)
    for o in cmp_old:
        r(o["rule"])["before"] += 1
    pairs, gone, fresh = match_findings(cmp_old, cmp_new)
    for o, n, how in pairs:
        d = r(n["rule"])
        d["now"] += 1
        d[f"now_{o['status']}"] += 1
        rec["how"][how] += 1
    for o in gone:
        r(o["rule"])[f"gone_{o['status']}"] += 1
        rec["gone"].append(o)
    for n in fresh:
        d = r(n["rule"])
        d["now"] += 1
        d["new"] += 1
        st = glob_status(t.get("globs") or [], n)
        if st:
            d["new_glob_reviewed"] += 1
        d[f"now_{st or 'unreviewed'}"] += 1
        rec["new"].append({**n, "status": st or "unreviewed"})
    rec["rules"] = rules
    return rec


def summarise(recs: list[dict]) -> dict:
    rules: dict[str, dict] = {}
    overall = _blank()
    how: Counter = Counter()
    for rec in recs:
        how.update(rec["how"])
        for rule, d in rec["rules"].items():
            acc = rules.setdefault(rule, _blank())
            for k, v in d.items():
                acc[k] += v
                overall[k] += v
    flagged = lambda v: v in ("suspicious", "malicious")  # noqa: E731
    ok = [x for x in recs if x["status"] == "ok"]
    verdicts = Counter(f"{x['old_verdict']}->{x['new_verdict']}" for x in ok if x["old_verdict"] != x["new_verdict"])
    return {
        "targets": {"rescanned": len(ok), "not_rescanned": len(recs) - len(ok),
                    "flagged_before": sum(flagged(x["old_verdict"]) for x in ok),
                    "flagged_now": sum(flagged(x["new_verdict"]) for x in ok),
                    "verdict_changes": dict(sorted(verdicts.items()))},
        "overall": overall, "rules": dict(sorted(rules.items())), "matched_by": dict(how),
        "new_timing_sensitive": sum(_timing(f) for x in recs for f in x["new"]),
    }


def table(s: dict) -> str:
    cols = [("before", "before"), ("now", "now"), ("now_false-positive", "now FP"),
            ("now_expected-behaviour", "now expected"), ("now_confirmed", "now confirmed"),
            ("now_unreviewed", "now unreviewed"), ("new", "new"), ("new_glob_reviewed", "new, glob-reviewed"),
            ("gone_false-positive", "gone FP"), ("gone_expected-behaviour", "gone expected"),
            ("gone_confirmed", "gone confirmed")]
    lines = ["| rule | " + " | ".join(h for _, h in cols) + " |", "|---" * (len(cols) + 1) + "|"]
    for rule, d in s["rules"].items():
        if not any(d[k] for k, _ in cols):
            continue  # only in the offline / not-rescanned buckets
        lines.append(f"| `{rule}` | " + " | ".join(str(d[k]) for k, _ in cols) + " |")
    o = s["overall"]
    lines.append("| **all** | " + " | ".join(f"**{o[k]}**" for k, _ in cols) + " |")
    tg = s["targets"]
    extra = [
        "",
        f"Targets rescanned: {tg['rescanned']} (not rescanned: {tg['not_rescanned']}); flagged (suspicious or "
        f"malicious) before {tg['flagged_before']}, now {tg['flagged_now']}.",
        f"Verdict changes: {tg['verdict_changes'] or 'none'}. Matched by: {s['matched_by'] or 'nothing'}.",
        f"Not compared: {o['offline_old']} old / {o['offline_new']} new findings of bundled servers that need the "
        f"network (offline bucket); {o['error_old']} old findings on targets that could not be rescanned.",
    ]
    if s.get("new_timing_sensitive"):
        extra.append(f"{s['new_timing_sensitive']} of the new findings are files.truncated from a wall-clock analysis "
                     "budget: they depend on machine load (rerun those targets with --jobs 1 before trusting them).")
    return "\n".join(lines + extra)


# ------------------------------------------------------------------ offline scanning (child process)

def install_offline_guards(setattr_=setattr, setenv=os.environ.__setitem__) -> None:
    """No network in this process: sockets refused except loopback/Unix, dead proxies, OSV stubbed.
    Tests pass monkeypatch.setattr / monkeypatch.setenv so the guards are undone afterwards."""
    import socket

    try:  # load the JS/TS grammars first: with the proxies below a cold grammar cache could not be filled
        from tree_sitter_language_pack import get_parser

        for lang in ("javascript", "typescript", "tsx"):
            get_parser(lang)
    except Exception:  # noqa: BLE001 - the scan then reports rules.error, which the comparison shows
        pass
    for k in ("HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "https_proxy", "http_proxy", "all_proxy"):
        setenv(k, "http://127.0.0.1:9")
    setenv("NO_PROXY", "")
    setenv("no_proxy", "")
    orig_connect, orig_connect_ex = socket.socket.connect, socket.socket.connect_ex

    def _allowed(sock, address) -> bool:
        if sock.family == getattr(socket, "AF_UNIX", None):
            return True
        host = address[0] if isinstance(address, tuple) else address
        return host in ("127.0.0.1", "::1", "localhost")

    def connect(self, address):
        if not _allowed(self, address):
            raise OSError(f"{OFFLINE_MARK} network disabled")
        return orig_connect(self, address)

    def connect_ex(self, address):
        if not _allowed(self, address):
            raise OSError(f"{OFFLINE_MARK} network disabled")
        return orig_connect_ex(self, address)

    setattr_(socket.socket, "connect", connect)
    setattr_(socket.socket, "connect_ex", connect_ex)
    import bawwab.scan.osv as osv

    setattr_(osv, "_post", lambda url, body, timeout: {})
    osv.clear_cache()


def scan_offline(t: dict, path: Path) -> dict:
    """Scan one corpus target from its local copy (static rules, judge=False). In-process: call it in a child."""
    install_offline_guards()
    import bawwab.scan as scan_mod
    from bawwab.config import Config
    from bawwab.fetch import FetchError, FetchOpts, parse_target
    from bawwab.fetch.common import detect_artifact_type, hash_tree, symlink_findings
    from bawwab.report import sanitise
    from bawwab.severity import at_least
    from bawwab.store import Store
    from bawwab.types import Fetched, Mode, PackageMeta, Target
    from report.scan import finding_key

    cfg = Config(mode=Mode.STANDARD, trusted=[])
    real_fetch = scan_mod.fetch_target
    if t["spec"].startswith("git:"):
        top = Target("local", str(path), name="", path=str(path))
    else:
        top = parse_target(t["spec"])
    root = path.resolve()

    def offline_fetch(tt, opts=None):
        if tt is top and tt.kind != "local":
            return Fetched(tt, t.get("version") or tt.version or "unknown", root, hash_tree(root),
                           detect_artifact_type(root), PackageMeta(name=tt.name), [], symlink_findings(root),
                           lambda: None)
        if tt.kind == "local":
            return real_fetch(tt, opts)
        raise FetchError(f"{OFFLINE_MARK} {tt.kind} target {tt.name or tt.raw} was not fetched")

    scan_mod.fetch_target = offline_fetch
    with tempfile.TemporaryDirectory(prefix="bawwab-fp-") as tmp:
        os.environ["BAWWAB_HOME"] = str(Path(tmp) / "bawwab")
        store = Store(Path(tmp) / "store.db")
        r = scan_mod.scan_target(top, mode=Mode.STANDARD, cfg=cfg, store=store, no_cache=True, judge=False,
                                 fetch_opts=FetchOpts())
    findings = []
    for f in r.findings:
        ev = sanitise(f.evidence, EVIDENCE_CAP)
        file = sanitise(f.file, 300) if f.file else None
        if not at_least(f.severity, cfg.suspicious):
            continue
        findings.append({"key": finding_key(f.rule, file, f.line, ev), "rule": f.rule, "severity": f.severity.value,
                         "file": file, "line": f.line, "ev": ev_hash(ev), "evidence": ev, "counted": True})
    return {"status": "ok", "verdict": r.verdict.value, "findings": findings}


def _child(payload: str) -> int:
    d = json.loads(payload)
    try:
        out = scan_offline(d["target"], Path(d["path"]))
    except Exception as e:  # noqa: BLE001 - recorded as not rescanned
        import traceback

        where = " <- ".join(f"{Path(fr.filename).name}:{fr.lineno}" for fr in traceback.extract_tb(e.__traceback__)[::-1][:6])
        out = {"status": "error", "error": f"{type(e).__name__}: {str(e)[:200]} at {where}"}
    sys.stdout.write("\n" + RESULT_MARK + json.dumps(out) + "\n")
    return 0


def local_path(t: dict, work: Path) -> Path | None:
    if not t.get("local"):
        return None
    p = Path(t["local"])
    p = p if p.is_absolute() else work / p
    return p if p.is_dir() else None


def rescan_one(t: dict, work: Path, timeout: float) -> dict:
    p = local_path(t, work)
    if p is None:
        return {"status": "missing", "error": "no local copy"}
    head = {k: v for k, v in t.items() if k != "findings"}
    cmd = [sys.executable, "-I", str(Path(__file__).resolve()), "_child", json.dumps({"target": head, "path": str(p)})]
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, stdin=subprocess.DEVNULL,
                            cwd=tempfile.gettempdir())
    except subprocess.TimeoutExpired:
        return {"status": "error", "error": f"timed out after {int(timeout)} s"}
    i = cp.stdout.rfind(RESULT_MARK)
    if i < 0:
        return {"status": "error", "error": f"child crashed (exit {cp.returncode}): {cp.stderr[-300:]}"}
    return json.loads(cp.stdout[i + len(RESULT_MARK):].strip().splitlines()[0])


def rescan(c: dict, work: Path, jobs: int, timeout: float, only: set[str] | None = None,
           scans: dict | None = None) -> tuple[list[dict], dict]:
    """(comparison records, raw scans by id). With `scans` (a previous run's raw scans) nothing is rescanned."""
    targets = [t for t in c["targets"] if not only or t["id"] in only]
    if scans is None:
        with ThreadPoolExecutor(max_workers=max(1, jobs)) as ex:
            scans = dict(zip([t["id"] for t in targets], ex.map(lambda t: rescan_one(t, work, timeout), targets)))
    recs = []
    for t in targets:
        s = scans.get(t["id"]) or {"status": "missing", "error": "not in the saved scans"}
        recs.append(compare_target(t, s))
        print(f"  {s.get('status'):7} {t.get('verdict') or '-':10} -> {s.get('verdict') or '-':10} {t['id']}",
              file=sys.stderr)
    return recs, scans


# ------------------------------------------------------------------ main

def _cmd_build(a) -> int:
    from report.collect import load_targets

    targets = load_targets(REPORT / "targets.json")
    results = json.loads((REPORT / "results.json").read_text())["results"]
    review = _review_module().load_review(REPORT / "review.json")
    c = build_corpus(targets, results, review, a.work)
    write_corpus(c, a.out)
    n = sum(len(t["findings"]) for t in c["targets"])
    st = Counter(f[6] for t in c["targets"] for f in t["findings"])
    print(f"wrote {a.out}: {len(c['targets'])} targets, {n} counted findings {dict(st)}", file=sys.stderr)
    return 0


def _cmd_rescan(a) -> int:
    c = load_corpus(a.corpus)
    work = a.work or Path(c.get("work_default") or DEFAULT_WORK)
    only = set(a.only.split(",")) if a.only else None
    total = [t for t in c["targets"] if not only or t["id"] in only]
    saved = json.loads(a.from_scans.read_text())["scans"] if a.from_scans else None
    if saved is not None:
        have = [t for t in total if (saved.get(t["id"]) or {}).get("status") != "missing"]
    else:
        have = [t for t in total if local_path(t, work) is not None]
        print(f"{len(have)} of {len(total)} corpus targets have a local copy under {work}", file=sys.stderr)
    if not have:
        print("nothing to rescan: the local copies are not on this machine (this tool is local-only)",
              file=sys.stderr)
        return 2
    recs, scans = rescan(c, work, a.jobs, a.timeout, only, saved)
    s = summarise(recs)
    s["corpus"] = {"targets": len(total), "with_local_copy": len(have),
                   "findings": sum(len(t["findings"]) for t in total)}
    out = table(s)
    print(out)
    if a.json:
        detail = [{"id": r["id"], "status": r["status"], "old_verdict": r["old_verdict"],
                   "new_verdict": r["new_verdict"], "error": r.get("error"),
                   "new": [{k: f.get(k) for k in ("rule", "severity", "file", "line", "key", "status", "evidence")}
                           for f in r["new"]],
                   "gone": [{k: f.get(k) for k in ("rule", "severity", "file", "line", "key", "status")}
                            for f in r["gone"]]} for r in recs]
        a.json.write_text(json.dumps({"summary": s, "targets": detail, "scans": scans}, indent=1) + "\n")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = sys.argv[1:] if argv is None else argv
    if argv[:1] == ["_child"]:
        return _child(argv[1])
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    b = sub.add_parser("build", help="write the corpus file from report/ data")
    b.add_argument("--work", type=Path, default=DEFAULT_WORK, help="the report run's work folder")
    b.add_argument("--out", type=Path, default=CORPUS)
    r = sub.add_parser("rescan", help="rescan the corpus targets that have a local copy (offline)")
    r.add_argument("--corpus", type=Path, default=CORPUS)
    r.add_argument("--work", type=Path, default=None, help="where the local copies are (default: as built)")
    r.add_argument("--jobs", type=int, default=1,
                   help="parallel scans (default 1: the env-flow analysis has a 2 s wall-clock budget per file, so "
                        "parallel runs add load-dependent files.truncated findings on large bundles)")
    r.add_argument("--timeout", type=float, default=TIMEOUT_S)
    r.add_argument("--only", default="", help="comma-separated target ids")
    r.add_argument("--json", type=Path, help="write the summary, per-target new/gone findings and raw scans here")
    r.add_argument("--from-scans", type=Path, help="recompute the report from a previous --json file's raw scans")
    a = ap.parse_args(argv)
    return _cmd_build(a) if a.cmd == "build" else _cmd_rescan(a)


if __name__ == "__main__":
    sys.exit(main())
