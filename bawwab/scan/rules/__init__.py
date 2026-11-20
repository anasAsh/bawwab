from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from bawwab.scan.files import ExtraText, ScanFile
from bawwab.scan.rules import code
from bawwab.scan.rules.catalog import CATALOG, RuleInfo
from bawwab.scan.rules.code import CODE_RULES
from bawwab.scan.rules.text import TEXT_RULES
from bawwab.types import Finding, Severity

__all__ = ["CATALOG", "ExtraText", "Rule", "RuleInfo", "ScanFile", "run_static_rules"]


class Rule(Protocol):
    id: str

    def run(self, files: list[ScanFile], extra: list[ExtraText]) -> list[Finding]: ...


ALL_RULES: list[Rule] = [*CODE_RULES, *TEXT_RULES]


def run_static_rules(files: list[ScanFile], extra: Sequence[ExtraText] = ()) -> list[Finding]:
    """Every rule over the files. One scan has one memory budget for parsed calls (code.begin_scan);
    the per-text caches are dropped afterwards so a long-lived process does not keep the last scan."""
    extra_list = list(extra)
    findings: list[Finding] = []
    code.begin_scan()
    try:
        for rule in ALL_RULES:
            try:
                findings.extend(rule.run(files, extra_list))
            except Exception as e:  # noqa: BLE001 - one broken rule must not hide the others
                findings.append(
                    Finding("rules.error", Severity.MED, "gate", f"rule {rule.id} failed: {type(e).__name__}")
                )
    finally:
        code.end_scan()
    return findings
