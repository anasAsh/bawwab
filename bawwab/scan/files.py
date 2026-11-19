from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from bawwab.types import Finding, Severity

SKIP_DIRS = {".git"}


@dataclass
class ScanFile:
    rel: str
    text: str


@dataclass
class ExtraText:
    label: str
    text: str


def _truncated(evidence: str, rel: str | None = None) -> Finding:
    return Finding("files.truncated", Severity.MED, "static", evidence, file=rel)


def load_files(
    root: Path, max_file_bytes: int = 1_000_000, max_files: int = 5000
) -> tuple[list[ScanFile], list[Finding]]:
    """Read text files under root. Never follows symlinks; skips binaries."""
    root = Path(root)
    files: list[ScanFile] = []
    findings: list[Finding] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if len(files) >= max_files:
                findings.append(_truncated(f"file limit of {max_files} reached; remaining files not scanned"))
                return files, findings
            try:
                size = path.stat().st_size
                if size > max_file_bytes:
                    findings.append(_truncated(f"{rel} is {size} bytes (limit {max_file_bytes}); not scanned", rel))
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            if b"\x00" in data[:8192]:
                continue
            files.append(ScanFile(rel, data.decode("utf-8", errors="replace")))
    return files, findings
