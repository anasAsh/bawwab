"""Spec §4a: the reviewer's recommendation travels on the report (ScanReport.advice) and through the store."""
from __future__ import annotations

from datetime import UTC, datetime

from bawwab.store import report_from_dict, report_to_dict
from bawwab.types import (
    RECOMMENDATIONS, Advice, Assessment, Finding, Mode, ScanReport, Severity, Target, Verdict,
)


def _report(advice=None) -> ScanReport:
    f = Finding("exfil.combo", Severity.HIGH, "static", "fetch(process.env.TOKEN)", "index.js", 3, "Fab12c")
    return ScanReport("npm:x@1#h", Target("npm", "x", name="x"), "1.0.0", Mode.STANDARD, Verdict.SUSPICIOUS, [f],
                      datetime(2026, 11, 21, tzinfo=UTC), advice=advice)


def test_recommendations_are_fixed():
    assert RECOMMENDATIONS == ("keep", "keep-with-care", "dont-install", "cant-tell")


def test_advice_round_trips():
    a = Advice("keep-with-care", "Sends its own token to its own API.",
               [Assessment("Fab12c", "expected", "Its own API key, sent to its own host.",
                           "fetch(process.env.TOKEN)", "index.js", 3)], reason="")
    back = report_from_dict(report_to_dict(_report(a)))
    assert back.advice == a


def test_report_without_advice_round_trips_and_old_dicts_load():
    d = report_to_dict(_report())
    assert "advice" not in d  # unchanged shape when there is no advice
    assert report_from_dict(d).advice is None
    d.pop("diff_summary")
    assert report_from_dict(d).advice is None


def test_cant_tell_carries_its_reason():
    a = Advice.cant_tell("the reviewer timed out")
    assert a.recommendation == "cant-tell" and a.per_finding == [] and a.reason == "the reviewer timed out"
