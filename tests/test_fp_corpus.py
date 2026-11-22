"""The false-positive corpus (bench/fp_corpus.py) and the malicious-set recall gate (bench/recall_gate.py).

Runs in CI: the matching and report math on small fixtures, the committed corpus against report/ data, the offline
child scan on a tiny local fixture, and the recall gate over bench/corpus/malicious and the incident replicas.
Local only: the full corpus rescan (its pinned copies live under /var/tmp on the maintainer's machine) and the
DataDog recall set (needs the encrypted zips in a local cache; set BAWWAB_DATADOG_CACHE).
"""
from __future__ import annotations

import importlib.util
import json
import os
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _load(name: str):
    mod_name = f"bench_{name}"
    if mod_name not in sys.modules:
        spec = importlib.util.spec_from_file_location(mod_name, ROOT / "bench" / f"{name}.py")
        mod = importlib.util.module_from_spec(spec)
        sys.modules[mod_name] = mod
        spec.loader.exec_module(mod)
    return sys.modules[mod_name]


fp = _load("fp_corpus")
rg = _load("recall_gate")


def F(rule="credential-access", file="a.js", line=1, ev="e1", key=None, status="false-positive", **kw):
    return {"key": key or f"{rule}|{file}|{line}|{ev}", "rule": rule, "severity": "high", "file": file, "line": line,
            "ev": ev, "status": status, "server": None, **kw}


def N(rule="credential-access", file="a.js", line=1, ev="e1", key=None, evidence="", **kw):
    d = F(rule, file, line, ev, key)
    d.pop("status")
    d.pop("server")
    return {**d, "evidence": evidence, "counted": True, **kw}


# ------------------------------------------------------------------ matching

def test_match_by_key_first():
    old = [F(key="k1"), F(line=5, ev="e2", key="k2")]
    new = [N(line=5, ev="e2", key="k2"), N(key="k1")]
    pairs, gone, fresh = fp.match_findings(old, new)
    assert [(o["key"], n["key"], how) for o, n, how in sorted(pairs, key=lambda p: p[0]["key"])] == [
        ("k1", "k1", "key"), ("k2", "k2", "key")]
    assert gone == [] and fresh == []


def test_line_shift_matches_on_rule_file_evidence():
    pairs, gone, fresh = fp.match_findings([F(line=10, key="old")], [N(line=12, key="new")])
    assert [how for *_, how in pairs] == ["rule+file+evidence"] and not gone and not fresh


def test_evidence_change_matches_on_rule_file_line():
    pairs, gone, fresh = fp.match_findings([F(ev="a", key="old")], [N(ev="b", key="new")])
    assert [how for *_, how in pairs] == ["rule+file+line"] and not gone and not fresh


def test_line_and_evidence_change_or_other_file_is_gone_plus_new():
    for n in (N(line=9, ev="b", key="x"), N(file="b.js", key="y"), N(rule="exfil.combo", key="z")):
        pairs, gone, fresh = fp.match_findings([F(key="old")], [n])
        assert pairs == [] and len(gone) == 1 and len(fresh) == 1


def test_no_line_never_matches_on_line_pass():
    pairs, gone, fresh = fp.match_findings([F(line=None, ev="a", key="o")], [N(line=None, ev="b", key="n")])
    assert pairs == [] and len(gone) == 1 and len(fresh) == 1


def test_duplicates_pair_as_multisets():
    old = [F(key="d"), F(key="d"), F(key="d")]
    new = [N(key="d"), N(key="d")]
    pairs, gone, fresh = fp.match_findings(old, new)
    assert len(pairs) == 2 and len(gone) == 1 and fresh == []


# ------------------------------------------------------------------ report math

def _target(findings, globs=None, verdict="suspicious"):
    return {"id": "t1", "spec": "x@1.0.0", "verdict": verdict, "globs": globs or [], "findings": findings}


def test_compare_target_counts_now_gone_and_new():
    t = _target([F(key="fp1"), F(line=2, key="fp2"), F(rule="install-script", file="package.json", key="ex1",
                                                         status="expected-behaviour")],
                globs=[["exfil.combo", "dist/*.js", "false-positive"]])
    scan = {"status": "ok", "verdict": "suspicious", "findings": [
        N(key="fp1"),                                               # still there: reviewed FP
        N(rule="install-script", file="package.json", key="ex1"),   # still there: expected
        N(rule="exfil.combo", file="dist/x.js", key="g1"),          # new, covered by a rule/glob review
        N(rule="exfil.combo", file="lib/x.js", key="u1"),           # new, nobody reviewed it
    ]}
    rec = fp.compare_target(t, scan)
    s = fp.summarise([rec])
    o = s["overall"]
    assert o["before"] == 3 and o["now"] == 4 and o["new"] == 2 and o["new_glob_reviewed"] == 1
    assert o["now_false-positive"] == 2 and o["now_expected-behaviour"] == 1 and o["now_unreviewed"] == 1
    assert o["gone_false-positive"] == 1 and o["gone_expected-behaviour"] == 0 and o["gone_confirmed"] == 0
    ca = s["rules"]["credential-access"]
    assert (ca["before"], ca["now"], ca["gone_false-positive"]) == (2, 1, 1)
    assert s["targets"] == {"rescanned": 1, "not_rescanned": 0, "flagged_before": 1, "flagged_now": 1,
                            "verdict_changes": {}}
    assert s["matched_by"] == {"key": 2}
    # invariant: before - gone == now - new (every finding is matched, gone or new)
    gone = sum(o[f"gone_{st}"] for st in fp.STATUSES)
    assert o["before"] - gone == o["now"] - o["new"]
    table = fp.table(s)
    assert "| **all** | **3** | **4** |" in table


def test_compare_target_verdict_change_and_all_gone():
    rec = fp.compare_target(_target([F(key="a"), F(key="b", status="expected-behaviour")]),
                            {"status": "ok", "verdict": "clean", "findings": []})
    s = fp.summarise([rec])
    assert s["targets"]["flagged_now"] == 0 and s["targets"]["verdict_changes"] == {"suspicious->clean": 1}
    assert s["overall"]["gone_false-positive"] == 1 and s["overall"]["gone_expected-behaviour"] == 1


def test_offline_server_findings_are_not_compared():
    t = _target([F(key="s1", server="docs"), F(key="s2", rule="fetch.failed", file=None, line=None, server="docs"),
                 F(key="top")])
    scan = {"status": "ok", "verdict": "suspicious", "findings": [
        N(key="top"),
        N(rule="fetch.failed", file=None, line=None, key="off",
          evidence=f"[server docs] {fp.OFFLINE_MARK} npm target docs-mcp was not fetched"),
    ]}
    o = fp.summarise([fp.compare_target(t, scan)])["overall"]
    assert (o["before"], o["now"], o["new"], o["offline_old"], o["offline_new"]) == (1, 1, 0, 2, 1)
    assert sum(o[f"gone_{st}"] for st in fp.STATUSES) == 0


def test_unrescannable_target_counts_as_error_not_gone():
    for scan in (None, {"status": "error", "error": "timed out"}, {"status": "missing"}):
        s = fp.summarise([fp.compare_target(_target([F(key="a")]), scan)])
        assert s["overall"]["error_old"] == 1 and s["overall"]["before"] == 0
        assert s["targets"]["rescanned"] == 0 and s["targets"]["not_rescanned"] == 1


# ------------------------------------------------------------------ the corpus file

def _report_data():
    from report.build_site import load_review
    from report.collect import load_targets

    targets = load_targets(ROOT / "report" / "targets.json")
    results = json.loads((ROOT / "report" / "results.json").read_text())["results"]
    return targets, results, load_review(ROOT / "report" / "review.json")


def test_build_write_load_roundtrip(tmp_path):
    work = tmp_path / "work"
    (work / "git" / "repo@abc").mkdir(parents=True)
    targets = [{"id": "a", "spec": "pkg@1.0.0", "kind": "mcp"}, {"id": "b", "spec": "git:https://x/y@" + "0" * 40,
                                                                  "kind": "skill"},
               {"id": "c", "spec": "other@2.0.0", "kind": "mcp"}]
    results = {
        "a": {"status": "ok", "spec": "pkg@1.0.0", "verdict": "suspicious", "resolved_version": "1.0.0",
              "local_path": str(work / "pkgs" / "a"), "findings": [
                  {"key": "k1", "rule": "exfil.combo", "severity": "med", "file": "dist/i.js", "line": 3,
                   "evidence": "[server srv] x", "counted": True},
                  {"key": "k2", "rule": "install-script", "severity": "low", "file": "package.json", "line": 1,
                   "evidence": "y", "counted": False}]},
        "b": {"status": "ok", "spec": targets[1]["spec"], "verdict": "clean", "resolved_version": "local",
              "local_path": str(work / "git" / "repo@abc"), "findings": []},
        "c": {"status": "ok", "spec": "other@2.0.0", "verdict": "clean", "local_path": None, "findings": []},
    }
    review = {"targets": {"a": {"findings": [{"match": {"rule": "exfil.combo", "file": "dist/*.js"},
                                              "status": "false-positive", "note": "n"}]}}}
    c = fp.build_corpus(targets, results, review, work)
    assert [t["id"] for t in c["targets"]] == ["a", "b"]  # c: clean with nothing on disk
    a = c["targets"][0]
    assert a["local"] == "pkgs/a" and a["globs"] == [["exfil.combo", "dist/*.js", "false-positive"]]
    assert a["findings"] == [["k1", "exfil.combo", "med", "dist/i.js", 3, fp.ev_hash("[server srv] x"),
                              "false-positive", "srv"]]
    p = tmp_path / "c.json"
    fp.write_corpus(c, p)
    back = fp.load_corpus(p)
    assert back["targets"][0]["findings"][0]["status"] == "false-positive"
    assert back["targets"][0]["findings"][0]["server"] == "srv"
    assert back["targets"][1]["findings"] == []
    assert fp.local_path(back["targets"][1], work) == work / "git" / "repo@abc"
    assert fp.local_path(back["targets"][0], work) is None  # not on disk


def test_committed_corpus_matches_report_data():
    """bench/fp_corpus.json is up to date with report/results.json + review.json (re-run `build` if not)."""
    targets, results, review = _report_data()
    built = fp.build_corpus(targets, results, review, fp.DEFAULT_WORK)
    have = fp.load_corpus(fp.CORPUS)
    rows = lambda c: {t["id"]: [list(r.values()) if isinstance(r, dict) else r for r in t["findings"]]  # noqa: E731
                      for t in c["targets"] if t["findings"]}
    assert rows(have) == rows(built)
    n = sum(len(v) for v in rows(have).values())
    statuses = {r[6] for v in rows(have).values() for r in v}
    assert n == 1214 and statuses <= {"false-positive", "expected-behaviour", "confirmed"}


def test_rescan_without_local_copies_says_so(tmp_path, capsys):
    assert fp.main(["rescan", "--work", str(tmp_path / "nowhere")]) == 2
    assert "local-only" in capsys.readouterr().err


def test_offline_child_scan_on_a_local_fixture(tmp_path):
    """The real child process: a local (git-style) target is scanned offline and its findings come back keyed."""
    import shutil

    d = tmp_path / "repo"
    shutil.copytree(ROOT / "bench" / "corpus" / "malicious" / "cred-js-env-dump", d,
                    ignore=shutil.ignore_patterns("label.json"))
    t = {"id": "fx", "spec": "git:https://github.com/x/y@" + "a" * 40, "version": "local", "local": str(d),
         "verdict": "malicious", "globs": [], "findings": []}
    s = fp.rescan_one(t, tmp_path, timeout=300)
    assert s["status"] == "ok", s
    assert s["verdict"] != "clean" and s["findings"]
    f = s["findings"][0]
    from report.scan import finding_key

    assert f["key"] == finding_key(f["rule"], f["file"], f["line"], f["evidence"])


def test_offline_guards_refuse_outbound_sockets(monkeypatch):
    import socket

    fp.install_offline_guards(setattr_=monkeypatch.setattr, setenv=monkeypatch.setenv)
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    try:
        with pytest.raises(OSError, match="network disabled"):
            s.connect(("192.0.2.1", 443))
    finally:
        s.close()
    assert os.environ["HTTPS_PROXY"] == "http://127.0.0.1:9"


# ------------------------------------------------------------------ recall gate

def test_gate_check_rules():
    base = {"a": {"verdict": "malicious", "rules": ["x", "y"]}, "b": {"verdict": "suspicious", "rules": ["z"]},
            "c": {"verdict": "suspicious", "rules": ["z"]}, "d": {"verdict": "clean", "rules": []},
            "e": {"verdict": "malicious", "rules": ["x"]}}
    cur = {"a": {"verdict": "malicious", "rules": ["x"]},        # lost a rule: warning only
           "b": {"verdict": "clean", "rules": []},               # dropped a level: fail
           "c": {"verdict": "suspicious", "rules": []},          # kept verdict but lost its last finding: fail
           "d": {"verdict": "clean", "rules": []},               # clean stays clean: fine
           "e": {"verdict": "malicious", "rules": ["x", "w"]},   # gained: fine
           "f": {"verdict": "malicious", "rules": ["x"]}}        # new sample: warning
    fails, warns = rg.check(base, cur)
    assert [f.split(":")[0] for f in fails] == ["b", "c"]
    assert [w.split(":")[0] for w in warns] == ["a", "f"]
    fails, _ = rg.check(base, {k: v for k, v in cur.items() if k != "a"})
    assert any(f.startswith("a: in the baseline but not scanned") for f in fails)


@pytest.fixture
def offline(monkeypatch, real_home):
    """The JS/TS grammars are loaded first (the autouse fixture moved HOME, so the developer's grammar cache is
    pointed at when it exists; a fresh CI runner gets them the way every other JS-scanning test does). Then the
    scan itself runs with outbound sockets refused, dead proxies and OSV stubbed."""
    base = real_home / ".cache"
    if (base / "tree-sitter-language-pack").is_dir():
        monkeypatch.setenv("TREE_SITTER_LANGUAGE_PACK_CACHE_DIR", str(base))
    from tree_sitter_language_pack import get_parser

    for lang in ("javascript", "typescript", "tsx"):
        get_parser(lang)
    rg.offline(setattr_=monkeypatch.setattr, setenv=monkeypatch.setenv)


@pytest.mark.recall
def test_recall_gate(offline):
    """Every bench malicious sample and incident replica keeps at least today's verdict (bench/recall_baseline.json;
    re-record with `uv run python bench/recall_gate.py --update` only when a drop is intended and reviewed)."""
    base = json.loads(rg.BASELINE.read_text())
    problems = []
    for name, cur in (("bench", rg.scan_bench()), ("replicas", rg.scan_replicas())):
        assert len(base[name]) > 0
        fails, _ = rg.check(base[name], cur)
        problems += [f"{name}: {f}" for f in fails]
    assert not problems, "\n".join(problems)


@pytest.mark.recall
def test_recall_gate_datadog(offline):
    """Local only: set BAWWAB_DATADOG_CACHE to a folder holding the encrypted DataDog zips (never downloaded)."""
    cache = os.environ.get("BAWWAB_DATADOG_CACHE")
    if not cache or not Path(cache).is_dir():
        pytest.skip("BAWWAB_DATADOG_CACHE not set: the DataDog set is checked locally only")
    base = json.loads(rg.BASELINE.read_text())
    if not base.get("datadog"):
        pytest.skip("no DataDog baseline recorded")
    cur, missing = rg.scan_datadog(Path(cache))
    fails, _ = rg.check({k: v for k, v in base["datadog"].items() if k not in missing}, cur)
    assert not fails, "\n".join(fails)
