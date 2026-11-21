"""Spec §4a / plan Task 5: the evaluation of the reviewer (eval/run_eval.py).

The reviewer itself is not used here: reports carry hand-made Advice objects (a fake), written to a scratch store
the way the gate's child process would write them. Covered: recording the advice per entry and per replica scan,
the summary counts (a)-(d), the hard failure on (a), and that --compare ignores advice.
"""
from __future__ import annotations

import argparse
import copy
import importlib.util
import json
import os
import re
import shutil
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from bawwab.store import Store
from bawwab.types import Advice, Assessment, Finding, Mode, ScanReport, Severity, Target, Verdict

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("run_eval", ROOT / "eval" / "run_eval.py")
run_eval = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_eval)
iso = run_eval._isolation()

T0 = datetime(2026, 11, 21, tzinfo=UTC)


def _report(raw: str, verdict: Verdict, advice: Advice | None = None, at: datetime = T0) -> ScanReport:
    sev = Severity.CRITICAL if verdict is Verdict.MALICIOUS else Severity.HIGH
    f = Finding("exfil.combo", sev, "static", "fetch(BAWWAB-CANARY)", "index.js", 3)
    return ScanReport(f"local:{raw}@1#h", Target("local", raw, path=raw), "1", Mode.STANDARD, verdict, [f], at,
                      advice=advice)


KEEP = Advice("keep", "Harmless.", [Assessment("F1", "false-alarm", "a test", "fetch(BAWWAB-CANARY) // test",
                                               "index.js", 3)])
CARE = Advice("keep-with-care", "Sends a token to its own host.")
DONT = Advice("dont-install", "Reads an SSH key and posts it.")
CANT = Advice.cant_tell("the quote is not in index.js")


# ------------------------------------------------------------------ recording


def test_new_scans_advice_records_only_scans_written_during_the_entry(tmp_path):
    db = tmp_path / "bawwab.db"
    st = Store(db)
    st.put_report(_report("/v/old", Verdict.SUSPICIOUS))            # in the template: not this entry's
    st.put_report(_report("/v/rescanned", Verdict.SUSPICIOUS))
    before = run_eval.store_scans(db)
    st.put_report(_report("/v/new", Verdict.MALICIOUS, DONT))
    st.put_report(_report("/v/rescanned", Verdict.SUSPICIOUS, CANT, at=T0 + timedelta(seconds=5)))
    st.put_report(_report("/v/none", Verdict.SUSPICIOUS))           # no advice: recorded as null
    recs = run_eval.new_scans_advice(before, run_eval.store_scans(db))
    assert recs == [
        {"target": "/v/new", "verdict": "malicious",
         "advice": {"recommendation": "dont-install", "reason": ""}},
        {"target": "/v/none", "verdict": "suspicious", "advice": None},
        {"target": "/v/rescanned", "verdict": "suspicious",
         "advice": {"recommendation": "cant-tell", "reason": "the quote is not in index.js"}},
    ]


def test_store_scans_without_a_store_is_empty(tmp_path):
    assert run_eval.store_scans(tmp_path / "missing.db") == {}


class FakeSandbox(run_eval.Sandbox):
    """No hooks and no template: the gate 'scans' by writing a report with the given advice into the store."""

    def __init__(self, work: Path, advice: Advice | None, verdict: Verdict):
        super().__init__(work, latency_copies=0)
        self.advice, self.verdict = advice, verdict

    def reset(self) -> None:
        self.bh.mkdir(parents=True, exist_ok=True)
        self.proj.mkdir(parents=True, exist_ok=True)
        Store(self.bh / "bawwab.db").put_report(_report("/template/skill", Verdict.SUSPICIOUS))

    def hook(self, sub, data):
        cmd = (data.get("tool_input") or {}).get("command", "")
        if sub == "gate" and cmd.startswith("claude mcp add"):
            Store(self.bh / "bawwab.db").put_report(
                _report("node /v/x/index.js", self.verdict, self.advice, at=T0 + timedelta(minutes=1)))
            reason = (f"⛔ bawwab: {self.verdict.value.upper()} — x\n\n{run_eval.ADVICE_LABEL}: refused — "
                      "quarantined (words from the model)\n")
            out = json.dumps({"hookSpecificOutput": {"permissionDecision": "deny",
                                                     "permissionDecisionReason": reason}})
            return run_eval.HookResult(sub, 0, out, "", 1.0)
        return run_eval.HookResult(sub, 0, "", "", 1.0)


def test_run_entry_records_the_advice_of_the_scans_it_wrote(tmp_path):
    sb = FakeSandbox(tmp_path, CARE, Verdict.SUSPICIOUS)
    e = {"id": "reviewer-x", "family": "reviewer", "calls": [
        {"tool_name": "Bash", "tool_input": {"command": "claude mcp add x -- node /v/x/index.js"}}],
        "effect": [], "expect": {"outcome": "blocked"}}
    rec = run_eval.run_entry(sb, e)
    assert rec["outcome"] == "blocked"
    assert rec["advice"] == [{"target": "node /v/x/index.js", "verdict": "suspicious",
                              "advice": {"recommendation": "keep-with-care", "reason": ""}}]
    # the advice block's wording ("refused —", "quarantined") does not decide the compared kind
    assert rec["gate"][0]["kind"] == "suspicious"


def test_normal_tasks_record_advice_too(tmp_path):
    sb = FakeSandbox(tmp_path, KEEP, Verdict.SUSPICIOUS)
    rec = run_eval.run_normal(sb, {"id": "n1", "category": "install", "calls": [
        {"tool_name": "Bash", "tool_input": {"command": "claude mcp add x -- node /v/x/index.js"}}]})
    assert rec["advice"][0]["advice"]["recommendation"] == "keep"


def test_replica_report_records_advice():
    assert run_eval._report(_report("/r", Verdict.MALICIOUS, DONT))["advice"] == {
        "recommendation": "dont-install", "reason": ""}
    assert run_eval._report(_report("/r", Verdict.SUSPICIOUS))["advice"] is None


def test_without_advice_strips_only_the_advice_block():
    t = (f"⛔ bawwab: MALICIOUS — x\n  CRIT F1 exfil\n\n{run_eval.ADVICE_LABEL}: cant-tell — SUSPICIOUS\n"
         "  F1 real: posts the key\n\nRun bawwab approve F1")
    s = run_eval.without_advice(t)
    assert run_eval.ADVICE_LABEL not in s and "posts the key" not in s
    assert "MALICIOUS" in s and "Run bawwab approve F1" in s


# ------------------------------------------------------------------ summary counts


def _scan(target, verdict, rec=None, reason=""):
    return {"target": target, "verdict": verdict,
            "advice": {"recommendation": rec, "reason": reason} if rec else None}


ATTACKS = [
    {"id": "a-mal", "advice": [_scan("m1", "malicious", "dont-install"), _scan("m2", "malicious", "cant-tell"),
                               _scan("m3", "malicious")]},
    {"id": "a-susp", "advice": [_scan("s1", "suspicious", "keep"), _scan("s2", "suspicious", "keep-with-care"),
                                _scan("s3", "suspicious", "dont-install"), _scan("s4", "suspicious")]},
    {"id": "a-clean", "advice": [_scan("c1", "clean")]},
    {"id": "a-none"},  # an entry that wrote no scan
]
NORMAL = [
    {"id": "n-flagged", "advice": [_scan("b1", "suspicious", "keep"), _scan("b2", "suspicious", "cant-tell"),
                                   _scan("b3", "suspicious", "dont-install"), _scan("b4", "suspicious")]},
    {"id": "n-clean", "advice": [_scan("b5", "clean")]},
]
REPLICAS = {"inc": {"v2_fresh_judge": {"verdict": "malicious", "findings": [], "advice":
                                       {"recommendation": "dont-install", "reason": ""}},
                    "v2_fresh_static": {"verdict": "malicious", "findings": [], "advice": None},
                    "v1_fresh_judge": {"verdict": "clean", "findings": [], "advice": None},
                    "update_v2": {"verdict": "suspicious", "findings": [], "advice": None}}}


def test_reviewer_summary_counts():
    r = run_eval.reviewer_summary(ATTACKS, NORMAL, REPLICAS)
    assert r["a_keep_on_malicious_verdict"] == {"count": 0, "where": [], "must_be": 0}
    m = r["malicious_samples_rated_malicious"]
    assert (m["reports"], m["dont-install"], m["cant-tell"], m["no_advice"], m["keep_or_care"]) == (3, 1, 1, 1, 0)
    b = r["b_malicious_samples_rated_suspicious"]
    assert (b["reports"], b["keep"], b["keep-with-care"], b["dont-install"], b["no_advice"]) == (4, 1, 1, 1, 1)
    assert b["keep_or_care"] == 2 and b["dont_or_cant"] == 1
    assert b["ids"] == ["attacks/a-susp: s1", "attacks/a-susp: s2"]
    c = r["c_benign_samples"]
    assert (c["reports"], c["keep_or_care"], c["dont_or_cant"], c["no_advice"]) == (4, 1, 2, 1)
    # (d): m3, s4, b4 and the replicas' update_v2; the static-only replica scan is apart, clean ones are not counted
    assert r["d_no_advice"] == {"total": 4, "attacks": 2, "normal": 1, "replicas": 1}
    assert r["static_only_not_reviewed"] == 1
    assert r["clean_not_reviewed"] == 3


def test_summary_carries_the_reviewer_block():
    s = run_eval.summarise([], [])
    assert s["reviewer"]["d_no_advice"]["total"] == 0 and s["reviewer"]["a_keep_on_malicious_verdict"]["count"] == 0


def test_unknown_recommendation_is_shown_not_folded():
    r = run_eval.reviewer_summary([{"id": "a", "advice": [_scan("s", "suspicious", "yes")]}], [])
    b = r["b_malicious_samples_rated_suspicious"]
    assert b["unknown"] == 1 and b["keep_or_care"] == 0 and b["dont_or_cant"] == 0


# ------------------------------------------------------------------ (a): the hard failure


@pytest.mark.parametrize("where", ["attacks", "normal", "replicas"])
def test_keep_on_a_malicious_verdict_is_caught_anywhere(where):
    att, nor, rep = copy.deepcopy(ATTACKS), copy.deepcopy(NORMAL), copy.deepcopy(REPLICAS)
    if where == "attacks":
        att[0]["advice"][0]["advice"]["recommendation"] = "keep"
    elif where == "normal":
        nor[0]["advice"].append(_scan("bm", "malicious", "keep-with-care"))
    else:
        rep["inc"]["v2_fresh_judge"]["advice"]["recommendation"] = "keep"
    s = {"reviewer": run_eval.reviewer_summary(att, nor, rep)}
    assert s["reviewer"]["a_keep_on_malicious_verdict"]["count"] == 1
    with pytest.raises(run_eval.ReviewerInvariantBroken):
        run_eval.check_reviewer_invariant(s)


def test_main_writes_the_results_then_fails_loudly(tmp_path, monkeypatch, capsys):
    bad = {"id": "a-mal", "advice": [_scan("m1", "malicious", "keep")]}
    monkeypatch.setattr(run_eval.Sandbox, "prepare", lambda self: None)
    monkeypatch.setattr(run_eval, "run_baseline", lambda sb: {"available": False})
    real_summarise = run_eval.summarise
    monkeypatch.setattr(run_eval, "summarise", lambda a, n, r=None: {
        **real_summarise(a, n, r), "reviewer": run_eval.reviewer_summary([bad], [])})
    saved = dict(os.environ)
    try:
        code = run_eval.main(["--sandbox", "none", "--only", "baseline", "--out", str(tmp_path / "out"),
                              "--workdir", str(tmp_path / "wd")])
    finally:
        os.environ.clear()
        os.environ.update(saved)
    assert code == run_eval.EXIT_REVIEWER
    err = capsys.readouterr().err
    assert "FAILED: reviewer invariant (a)" in err and "attacks/a-mal: m1" in err
    summ = json.loads((tmp_path / "out" / "summary.json").read_text())
    assert summ["reviewer"]["a_keep_on_malicious_verdict"]["count"] == 1  # the evidence is on disk


def _fake_inner(code: int, summary: dict):
    def run(argv):
        out = Path(argv[argv.index("--mount") + 1].split("src=")[1].split(",")[0]) / "out"
        out.mkdir(parents=True, exist_ok=True)
        (out / "meta.json").write_text(json.dumps({"meta": {"isolation": {"runner": "docker", "ok": True}}}))
        (out / "summary.json").write_text(json.dumps(summary))
        return subprocess.CompletedProcess(argv, code, "", "")
    return run


class FakeExec:
    def __init__(self, answers):
        self.answers = answers

    def __call__(self, argv, **kw):
        argv = list(argv)
        for prefix, ans in self.answers.items():
            if tuple(argv[:len(prefix)]) == prefix:
                return ans(argv)
        return subprocess.CompletedProcess(argv, 0, "", "")


def _args(tmp_path, **kw):
    d = dict(sandbox="docker", only="attacks", ids="", keep=False, workdir=str(tmp_path / "wd"),
             out=str(tmp_path / "out"), no_write=False, compare=None)
    d.update(kw)
    return argparse.Namespace(**d)


def test_sandboxed_run_copies_the_evidence_and_keeps_the_failure(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(iso.shutil, "which", lambda n: f"/usr/bin/{n}")
    summ = {"reviewer": {"a_keep_on_malicious_verdict": {"count": 1, "where": ["attacks/a: m"], "must_be": 0}}}
    fx = FakeExec({("docker", "run"): _fake_inner(run_eval.EXIT_REVIEWER, summ)})
    assert run_eval.run_isolated(_args(tmp_path), exec_=fx) == run_eval.EXIT_REVIEWER
    assert json.loads((tmp_path / "out" / "summary.json").read_text()) == summ
    assert "reviewer invariant (a)" in capsys.readouterr().err


def test_sandboxed_run_still_refuses_other_failures(tmp_path, monkeypatch):
    monkeypatch.setattr(iso.shutil, "which", lambda n: f"/usr/bin/{n}")
    fx = FakeExec({("docker", "run"): _fake_inner(1, {})})
    assert run_eval.run_isolated(_args(tmp_path), exec_=fx) == 1
    assert not (tmp_path / "out").exists()


# ------------------------------------------------------------------ --compare ignores advice


def test_compare_ignores_advice(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    shutil.copytree(run_eval.RESULTS, a)
    shutil.copytree(run_eval.RESULTS, b)
    att = json.loads((b / "attacks.json").read_text())
    for i, x in enumerate(att):
        x["advice"] = [_scan("t", "suspicious", "keep" if i % 2 else "cant-tell", reason=f"run {i}")]
    (b / "attacks.json").write_text(json.dumps(att))
    nor = json.loads((b / "normal.json").read_text())
    for x in nor:
        x["advice"] = [_scan("t", "suspicious", "keep-with-care")]
    (b / "normal.json").write_text(json.dumps(nor))
    rep = json.loads((b / "replicas.json").read_text())
    rep["mcp_typosquat"]["v2_fresh_judge"]["advice"] = {"recommendation": "dont-install", "reason": "x"}
    (b / "replicas.json").write_text(json.dumps(rep))
    summ = json.loads((b / "summary.json").read_text())
    summ["reviewer"] = run_eval.reviewer_summary([], [])
    (b / "summary.json").write_text(json.dumps(summ))
    assert run_eval.compare_results(a, b) == []
    # and the other way round: a different advice in each run still matches
    summ["reviewer"]["b_malicious_samples_rated_suspicious"]["keep"] = 7
    (a / "summary.json").write_text(json.dumps(summ))
    assert run_eval.compare_results(a, b) == []
    # while a decision still counts
    att[0]["outcome"] = "missed" if att[0]["outcome"] != "missed" else "blocked"
    (b / "attacks.json").write_text(json.dumps(att))
    assert len(run_eval.compare_results(a, b)) == 1


def test_reviewer_attacks_are_in_the_red_team_set():
    entries = {e["id"]: e for e in run_eval.load_yaml(ROOT / "eval" / "redteam" / "attacks.yaml")["attacks"]}
    rev = [e for e in entries.values() if e["family"] == "reviewer"]
    assert len(rev) >= 6
    for e in rev:
        assert e["expect"]["outcome"] in ("blocked", "caught", "missed")
        for c in e["calls"]:
            cmd = c["tool_input"]["command"]
            assert "{V}/reviewer/" in cmd
            rel = cmd.split("{V}/reviewer/")[1].split()[0]
            assert (ROOT / "eval" / "fixtures" / "reviewer" / rel).exists(), rel
    for f in (ROOT / "eval" / "fixtures" / "reviewer").rglob("*"):
        if f.is_file():
            text = f.read_text()
            assert "Inert eval fixture" in text or f.name == "SKILL.md", f  # labelled
            for host in re.findall(r"https?://([^/\"'\s]+)", text):  # canary hosts only
                assert host.endswith(".invalid") and "BAWWAB-CANARY" in host, (f, host)


def test_without_advice_removes_exactly_the_rendered_block():
    """Strip only the label line and the lines under it, against the real layout (no blank line after it)."""
    from datetime import UTC, datetime

    from bawwab.report import format_report
    from bawwab.types import Advice, Assessment, Finding, Mode, ScanReport, Severity, Target, Verdict

    f = Finding("exfil.combo", Severity.HIGH, "static", "fetch(process.env.TOKEN)", "a.js", 1, "Fab10c")
    adv = Advice("keep-with-care", "PROTECTED ACTION quarantine MALICIOUS",  # words the classifier keys on
                 [Assessment("Fab10c", "expected", "fetch.failed", "q" * 25, "a.js", 1)])
    r = ScanReport("k", Target("npm", "x", name="x"), "1", Mode.STANDARD, Verdict.SUSPICIOUS, [f],
                   datetime.now(UTC), advice=adv)
    with_adv = format_report(r, "ABCD")
    plain = format_report(ScanReport(**{**r.__dict__, "advice": None}), "ABCD")
    assert run_eval.without_advice(with_adv) == plain.rstrip("\n")
    assert run_eval.reason_kind(with_adv) == run_eval.reason_kind(plain)
