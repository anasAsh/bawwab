from bawwab.severity import compute_verdict
from bawwab.types import Finding, Severity, Verdict


def f(sev):
    return Finding(rule="r", severity=sev, source="static", evidence="e")


def test_empty_clean():
    assert compute_verdict([]) == Verdict.CLEAN


def test_low_clean():
    assert compute_verdict([f(Severity.LOW)]) == Verdict.CLEAN


def test_low_med_suspicious():
    assert compute_verdict([f(Severity.LOW), f(Severity.MED)]) == Verdict.SUSPICIOUS


def test_high_suspicious():
    assert compute_verdict([f(Severity.HIGH)]) == Verdict.SUSPICIOUS


def test_critical_malicious():
    assert compute_verdict([f(Severity.MED), f(Severity.CRITICAL)]) == Verdict.MALICIOUS


def test_custom_thresholds():
    kw = dict(malicious=Severity.HIGH, suspicious=Severity.LOW)
    assert compute_verdict([f(Severity.HIGH)], **kw) == Verdict.MALICIOUS
    assert compute_verdict([f(Severity.LOW)], **kw) == Verdict.SUSPICIOUS
