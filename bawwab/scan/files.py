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


# Executable formats: ELF, PE, Mach-O (32/64, both byte orders, fat), WebAssembly.
EXEC_MAGIC = (
    b"\x7fELF", b"MZ", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
    b"\xca\xfe\xba\xbe", b"\x00asm",
)


_TEXT_BYTES = bytes(range(0x20, 0x7F)) + b"\t\n\r\f\b"


def _is_binary(head: bytes) -> bool:
    """A real binary, not a text file with a stray NUL: an executable header, or mostly non-text bytes."""
    if b"\x00" not in head:
        return False
    if head.startswith(EXEC_MAGIC):
        return True
    return len(head.translate(None, _TEXT_BYTES)) > len(head) * 0.3


def _binary_unscanned(n: int) -> list[Finding]:
    if not n:
        return []
    noun = "file" if n == 1 else "files"
    return [Finding(
        "files.binary-unscanned", Severity.LOW, "static",
        f"{n} binary {noun} not analysed; use --deep to run in the sandbox",
    )]


def load_files(
    root: Path, max_file_bytes: int = 1_000_000, max_files: int = 5000
) -> tuple[list[ScanFile], list[Finding]]:
    """Read text files under root. Never follows symlinks; skips binaries.

    Oversized text files and the file cap give `files.truncated` (med). Prebuilt
    executables and oversized binaries are aggregated into one low finding.
    """
    root = Path(root)
    files: list[ScanFile] = []
    findings: list[Finding] = []
    binaries = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if len(files) >= max_files:
                findings.append(_truncated(f"file limit of {max_files} reached; remaining files not scanned"))
                return files, findings + _binary_unscanned(binaries)
            try:
                size = path.stat().st_size
                if size > max_file_bytes:
                    with path.open("rb") as fh:
                        head = fh.read(8192)
                    if _is_binary(head):
                        binaries += 1
                    else:
                        findings.append(_truncated(f"{rel} is {size} bytes (limit {max_file_bytes}); not scanned", rel))
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            if b"\x00" in data[:8192]:
                if data.startswith(EXEC_MAGIC):
                    binaries += 1
                continue
            files.append(ScanFile(rel, data.decode("utf-8", errors="replace")))
    return files, findings + _binary_unscanned(binaries)
