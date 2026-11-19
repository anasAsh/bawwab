from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from pathlib import Path
from typing import Literal


class Severity(StrEnum):
    LOW = "low"
    MED = "med"
    HIGH = "high"
    CRITICAL = "critical"

    @property
    def rank(self) -> int:
        return _SEVERITY_ORDER.index(self)

    def __lt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank < other.rank

    def __le__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank <= other.rank

    def __gt__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank > other.rank

    def __ge__(self, other: object) -> bool:
        if not isinstance(other, Severity):
            return NotImplemented
        return self.rank >= other.rank


_SEVERITY_ORDER = [Severity.LOW, Severity.MED, Severity.HIGH, Severity.CRITICAL]


class Verdict(StrEnum):
    CLEAN = "clean"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class Mode(StrEnum):
    STANDARD = "standard"
    DEEP = "deep"


Source = Literal["static", "identity", "judge", "sandbox", "gate", "trust"]
TargetKind = Literal["npm", "pypi", "git", "local", "remote", "docker"]
ArtifactType = Literal["mcp", "skill", "plugin", "unknown"]


@dataclass
class Finding:
    rule: str
    severity: Severity
    source: Source
    evidence: str
    file: str | None = None
    line: int | None = None
    id: str = ""  # assigned by store


@dataclass(frozen=True)
class Target:
    kind: TargetKind
    raw: str
    name: str = ""
    version: str | None = None
    url: str | None = None
    path: str | None = None


@dataclass
class ToolInfo:
    name: str
    description: str
    input_schema: dict | None = None


@dataclass
class PackageMeta:
    name: str
    repo_url: str | None = None
    created_at: datetime | None = None


@dataclass
class Fetched:
    target: Target
    resolved_version: str
    root: Path | None
    content_hash: str
    artifact_type: ArtifactType
    meta: PackageMeta
    remote_tools: list[ToolInfo]
    findings: list[Finding]
    cleanup: Callable[[], None]


@dataclass
class ScanReport:
    key: str
    target: Target
    resolved_version: str
    mode: Mode
    verdict: Verdict
    findings: list[Finding]
    scanned_at: datetime
    diff_summary: str | None = None
