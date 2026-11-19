from __future__ import annotations

from collections.abc import Sequence
from typing import Protocol

from bawwab.scan.files import ExtraText, ScanFile
from bawwab.scan.rules.catalog import CATALOG, RuleInfo
from bawwab.scan.rules.code import CODE_RULES
from bawwab.types import Finding

__all__ = ["CATALOG", "ExtraText", "Rule", "RuleInfo", "ScanFile", "run_static_rules"]


class Rule(Protocol):
    id: str

    def run(self, files: list[ScanFile], extra: list[ExtraText]) -> list[Finding]: ...


# Task 3 adds its rule list here: ALL_RULES = [*CODE_RULES, *TEXT_RULES]
ALL_RULES: list[Rule] = [*CODE_RULES]


def run_static_rules(files: list[ScanFile], extra: Sequence[ExtraText] = ()) -> list[Finding]:
    extra_list = list(extra)
    findings: list[Finding] = []
    for rule in ALL_RULES:
        findings.extend(rule.run(files, extra_list))
    return findings
