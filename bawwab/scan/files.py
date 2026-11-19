from __future__ import annotations

import os
import re
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
    ".rb", ".pl", ".php", ".bat", ".cmd", ".ksh", ".fish", ".command", ".csh", ".tcsh",
)
# Text files that name what runs: manifests, hook configs and install/shell scripts (round 4, R30d).
LAUNCHER_BASES = {
    "package.json", "pyproject.toml", "setup.py", "setup.cfg", "Makefile", "Dockerfile", ".mcp.json", "mcp.json",
    "plugin.json", "hooks.json", "marketplace.json", "settings.json", "settings.local.json", "manifest.json",
}
SHELL_EXT = (".sh", ".bash", ".zsh", ".ksh", ".fish", ".command", ".csh", ".tcsh", ".ps1", ".bat", ".cmd")


def _is_pe(head: bytes) -> bool:
    """"MZ" alone is a valid JS identifier; require the PE signature at e_lfanew."""
    if not head.startswith(b"MZ") or len(head) < 0x40:
        return False
    off = int.from_bytes(head[0x3C:0x40], "little")
    return head[off : off + 4] == b"PE\x00\x00"


EXEC_MAGIC = BINARY_MAGIC[:7]  # ELF, Mach-O, wasm


def _is_executable(head: bytes) -> bool:
    return head.startswith(EXEC_MAGIC) or _is_pe(head)


def _ctrl(b: int) -> bool:
    """A control byte that is neither whitespace nor allowed in JS/Python source outside strings."""
    return b < 0x09 or 0x0E <= b < 0x20 or b == 0x7F


def _media_magic(h: bytes) -> bool:
    """Media, document, font and database formats (round 2).

    Every accepted header either starts with a byte that cannot begin JS/Python source,
    or is checked together with a NUL byte that JS and Python reject outside strings,
    so a forged header cannot also be a runnable script.
    """
    return (
        h.startswith((b"GIF87a", b"GIF89a")) and any(_ctrl(b) for b in h[6:13])  # GIF: binary dimensions
        or h.startswith(b"%PDF-")
        or h.startswith(b"RIFF") and h[8:12] in (b"WEBP", b"WAVE", b"AVI ") and b"\x00" in h[4:8] + h[12:20]
        or h.startswith(b"\x00\x00\x01\x00") or h.startswith(b"\x00\x00\x02\x00")  # ICO / CUR
        or h.startswith(b"BM") and h[6:10] == b"\x00\x00\x00\x00"  # BMP reserved fields
        or h.startswith((b"II*\x00", b"MM\x00*"))  # TIFF
        or h.startswith((b"wOFF", b"wOF2")) and h[12:14] == b"\x00\x00"  # WOFF reserved
        or h.startswith(b"\x00\x01\x00\x00\x00")  # TrueType
        or h.startswith(b"OTTO") and h[4:5] == b"\x00"  # OpenType numTables high byte
        or h[:1] == b"\x00" and h[4:8] == b"ftyp"  # MP4 / MOV / HEIC
        or h.startswith(b"ID3") and h[4:5] == b"\x00"  # MP3 with ID3v2
        or h.startswith((b"\xff\xfb", b"\xff\xf3", b"\xff\xf2"))  # MPEG audio frame
        or h.startswith(b"OggS\x00") or h.startswith(b"fLaC\x00")
        or h.startswith(b"SQLite format 3\x00")
        or h.startswith(b"\x1aE\xdf\xa3")  # Matroska / WebM
    )


def _is_binary(head: bytes) -> bool:
    """A real binary format by magic; anything else (even with NUL bytes) is treated as text."""
    return head.startswith(BINARY_MAGIC) or _is_pe(head) or _media_magic(head)


def _is_code_name(rel: str, head: bytes) -> bool:
    return rel.endswith(CODE_EXT) or head.startswith(b"#!")


def _is_launcher(rel: str) -> bool:
    base = rel.rsplit("/", 1)[-1]
    return base in LAUNCHER_BASES or rel.endswith(SHELL_EXT) or bool(re.search(r"(?:^|/)hooks/", rel))


def _referenced(rel: str, launchers: list[ScanFile]) -> bool:
    """A manifest, hook config or install script names this file as something to run (R30d)."""
    if "/" in rel:
        rx = re.compile(r"(?<![\w.-])(?:\./)?" + re.escape(rel) + r"(?![\w./-])")
    else:
        rx = re.compile(
            r"(?:\./|/)" + re.escape(rel) + r"(?![\w./-])"
            r"|\b(?:sh|bash|zsh|ksh|fish|source|exec)\s+" + re.escape(rel) + r"(?![\w./-])"
        )
    return any(rx.search(f.text) for f in launchers)


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
    images) are aggregated into one low finding, unless a manifest, hook config or
    install script names them as something to run (then `files.truncated`).
    """
    root = Path(root)
    files: list[ScanFile] = []
    findings: list[Finding] = []
    # Non-executable files that look binary by magic (media, documents, archives); decided after
    # every text file is read, because a file that a manifest/hook/install script runs is never
    # taken as media (R30d): bash runs line 2 of a "%PDF" script.
    pending: list[tuple[str, str, bool]] = []  # (rel, evidence if referenced, counts as binary otherwise)
    binaries = 0

    def finish() -> tuple[list[ScanFile], list[Finding]]:
        nonlocal binaries
        launchers = [f for f in files if _is_launcher(f.rel)]
        for rel, evidence, counted in pending:
            if _referenced(rel, launchers):
                findings.append(_truncated(evidence, rel))
            elif counted:
                binaries += 1
        return files, findings + _binary_unscanned(binaries)

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        for name in sorted(filenames):
            path = Path(dirpath) / name
            if path.is_symlink() or not path.is_file():
                continue
            rel = path.relative_to(root).as_posix()
            if len(files) >= max_files:
                findings.append(_truncated(f"file limit of {max_files} reached; remaining files not scanned"))
                return finish()
            try:
                size = path.stat().st_size
                if size > max_file_bytes:
                    with path.open("rb") as fh:
                        head = fh.read(8192)
                    # A code/script name (or #!) is never taken as media: bash runs line 2 of a "%PDF" script.
                    if _is_binary(head) and not _is_code_name(rel, head):
                        if _is_executable(head):  # a real executable: what a launcher runs, but not a script
                            binaries += 1
                        else:
                            pending.append((rel, f"{rel} is {size} bytes (limit {max_file_bytes}); not scanned", True))
                    else:
                        findings.append(_truncated(f"{rel} is {size} bytes (limit {max_file_bytes}); not scanned", rel))
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            if b"\x00" in data[:8192]:
                head = data[:8192]
                if _is_code_name(rel, head):
                    findings.append(_truncated(f"{rel} is source code with NUL bytes; not scanned", rel))
                elif _is_executable(head):  # prebuilt executables are counted
                    binaries += 1
                else:  # small images/archives stay silent unless a launcher runs them
                    pending.append((rel, f"{rel} contains NUL bytes; not scanned", False))
                continue
            files.append(ScanFile(rel, data.decode("utf-8", errors="replace")))
    return finish()
