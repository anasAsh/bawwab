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


# Binary formats recognised by magic (R27 I6). Each magic starts with bytes that are not valid
# JavaScript or Python source, so a forged header cannot also be a runnable script.
# ELF, Mach-O (32/64, both byte orders, fat), WebAssembly, zip, gzip, PNG, JPEG. PE is checked separately.
BINARY_MAGIC = (
    b"\x7fELF", b"\xcf\xfa\xed\xfe", b"\xce\xfa\xed\xfe", b"\xfe\xed\xfa\xcf", b"\xfe\xed\xfa\xce",
    b"\xca\xfe\xba\xbe", b"\x00asm", b"PK\x03\x04", b"\x1f\x8b", b"\x89PNG\r\n\x1a\n", b"\xff\xd8\xff",
)
# Source files that run if left unscanned: a NUL byte must not hide them (R27 minor 7).
CODE_EXT = (
    ".py", ".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx", ".sh", ".bash", ".zsh", ".ps1",
    ".rb", ".pl", ".php", ".bat", ".cmd",
)


def _is_pe(head: bytes) -> bool:
    """"MZ" alone is a valid JS identifier; require the PE signature at e_lfanew."""
    if not head.startswith(b"MZ") or len(head) < 0x40:
        return False
    off = int.from_bytes(head[0x3C:0x40], "little")
    return head[off : off + 4] == b"PE\x00\x00"


EXEC_MAGIC = BINARY_MAGIC[:7]  # ELF, Mach-O, wasm


def _is_executable(head: bytes) -> bool:
    return head.startswith(EXEC_MAGIC) or _is_pe(head)


def _is_binary(head: bytes) -> bool:
    """A real binary format by magic; anything else (even with NUL bytes) is treated as text."""
    return head.startswith(BINARY_MAGIC) or _is_pe(head)


def _is_code_name(rel: str, head: bytes) -> bool:
    return rel.endswith(CODE_EXT) or head.startswith(b"#!")


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

    Oversized text files, source files with NUL bytes and the file cap give
    `files.truncated` (med). Files with a binary magic (executables, archives,
    images) are aggregated into one low finding.
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
                head = data[:8192]
                if _is_executable(head):  # small images/archives stay silent; prebuilt executables are counted
                    binaries += 1
                elif _is_code_name(rel, head):
                    findings.append(_truncated(f"{rel} is source code with NUL bytes; not scanned", rel))
                continue
            files.append(ScanFile(rel, data.decode("utf-8", errors="replace")))
    return files, findings + _binary_unscanned(binaries)
