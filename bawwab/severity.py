from __future__ import annotations

from bawwab.types import Finding, Severity, Verdict


def at_least(s: Severity, minimum: Severity) -> bool:
    return s.rank >= minimum.rank


def compute_verdict(
    findings: list[Finding],
    malicious: Severity = Severity.CRITICAL,
    suspicious: Severity = Severity.MED,
) -> Verdict:
    if any(at_least(f.severity, malicious) for f in findings):
        return Verdict.MALICIOUS
    if any(at_least(f.severity, suspicious) for f in findings):
        return Verdict.SUSPICIOUS
    return Verdict.CLEAN
