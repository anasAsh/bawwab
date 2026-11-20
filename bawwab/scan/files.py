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


def _truncated(evidence: str, rel: str | None = None, severity: Severity = Severity.MED) -> Finding:
    return Finding("files.truncated", severity, "static", evidence, file=rel)


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


_RUNTIME_RE = re.compile(rb"(?:node|nodejs|python[\d.]*|deno|bun|tsx|ts-node)")


def _shell_shebang(head: bytes) -> bool:
    """A #! line for anything but a JS/Python runtime (a shell runs such a file line by line).

    Only the interpreter's basename counts, or for `env` its program argument (review M1):
    `#!/opt/node/../../bin/sh` is a shell script."""
    if not head.startswith(b"#!"):
        return False
    words = head[2:].split(b"\n", 1)[0].split()
    if not words:
        return True
    prog = words[0].rsplit(b"/", 1)[-1]
    if prog == b"env":
        rest = [w for w in words[1:] if not w.startswith(b"-") and b"=" not in w]
        prog = rest[0].rsplit(b"/", 1)[-1] if rest else b""
    return not _RUNTIME_RE.fullmatch(prog)


def _is_code_name(rel: str, head: bytes) -> bool:
    return rel.endswith(CODE_EXT) or head.startswith(b"#!")


_MACHO_CPUS = {7, 0x01000007, 12, 0x0100000C, 0x0200000C, 18, 0x01000012}


def _plausible_executable(h: bytes) -> bool:
    """An executable header that a real toolchain wrote (round 5): a bare magic followed by text is not."""
    if h.startswith(b"\x7fELF"):
        return len(h) > 6 and h[4] in (1, 2) and h[5] in (1, 2) and h[6] == 1
    if h[:4] in (b"\xfe\xed\xfa\xce", b"\xfe\xed\xfa\xcf"):
        return int.from_bytes(h[4:8], "big") in _MACHO_CPUS
    if h[:4] in (b"\xce\xfa\xed\xfe", b"\xcf\xfa\xed\xfe"):
        return int.from_bytes(h[4:8], "little") in _MACHO_CPUS
    if h.startswith(b"\xca\xfe\xba\xbe"):  # universal binary
        return 1 <= int.from_bytes(h[4:8], "big") <= 32 and int.from_bytes(h[8:12], "big") in _MACHO_CPUS
    if h.startswith(b"\x00asm"):
        return h[4:8] == b"\x01\x00\x00\x00"
    return _is_pe(h)


_INTERP = r"""(?:\b(?:sh|bash|zsh|dash|ksh|fish|source|exec)|(?:^|(?<=[\s;&|(`'"]))\.)"""
_INTERP_LIST = r"""['"](?:/usr)?(?:/bin/)?(?:env\s+)?(?:sh|bash|zsh|dash|ksh)['"]\s*,\s*(?:['"]-[\w-]+['"]\s*,\s*)*"""


def _interpreted(rel: str, texts: list[ScanFile]) -> bool:
    """Some file runs this one through a shell: `bash -x hooks/run`, `sh "payload"`, `. ./payload`,
    subprocess.call(['sh', 'payload']) (round 5). A shell runs the text lines after any header."""
    path = r"""(?:[^\s'"`;&|]*/)?""" + re.escape(rel.rsplit("/", 1)[-1] if "/" not in rel else rel)
    if "/" in rel:
        path = r"""(?:[^\s'"`;&|]*/)?""" + re.escape(rel)
    rx = re.compile(
        _INTERP + r"""\s+(?:-{1,2}[\w-]+\s+)*['"\\]*""" + path + r"""['"\\]*(?![\w./-])"""
        r"|" + _INTERP_LIST + r"""['"]""" + path + r"""['"]""",
        re.M,
    )
    return any(rx.search(f.text) for f in texts)


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


MAX_TOTAL_TEXT_BYTES = 128_000_000  # per scan: text held in memory and parsed (extraction allows 500 MB)


def load_files(
    root: Path, max_file_bytes: int = 1_000_000, max_files: int = 5000, max_text_bytes: int = 16_000_000,
    max_total_bytes: int = MAX_TOTAL_TEXT_BYTES,
) -> tuple[list[ScanFile], list[Finding]]:
    """Read text files under root. Never follows symlinks; skips binaries.

    Plain text (JS, Python, JSON...) is scanned in full up to max_text_bytes; above that, the
    first and last max_file_bytes are scanned and give `files.truncated` (med) (R40). Over
    max_file_bytes, a shell script / #! script, a forged binary header or NUL bytes give
    `files.truncated` (med), as do source files with NUL bytes and the file cap. Files with a
    binary magic (executables, archives, images) are aggregated into one low finding, unless a
    manifest, hook config or install script names them as something to run (then `files.truncated`).
    The scan holds at most max_total_bytes of text: past it, `files.truncated` (med) and the remaining
    files are not scanned (a memory budget, fail closed).
    """
    root = Path(root)
    files: list[ScanFile] = []
    findings: list[Finding] = []
    # Non-executable files that look binary by magic (media, documents, archives); decided after
    # every text file is read, because a file that a manifest/hook/install script runs is never
    # taken as media (R30d): bash runs line 2 of a "%PDF" script.
    # (rel, evidence, kind): kind "exec" (plausible executable), "forged" (executable magic with an
    # implausible header), "media" (counted as binary when left alone) or "quiet" (small media).
    pending: list[tuple[str, str, str]] = []
    total = 0

    def over_total(rel: str, n: int) -> bool:
        nonlocal total
        if total + n > max_total_bytes:
            findings.append(_truncated(
                f"text budget of {max_total_bytes} bytes reached at {rel}; remaining files not scanned", rel))
            return True
        total += n
        return False

    def finish() -> tuple[list[ScanFile], list[Finding]]:
        launchers = [f for f in files if _is_launcher(f.rel)]
        binaries = 0
        for rel, evidence, kind in pending:
            interpreted = _interpreted(rel, files)
            if kind == "exec" and not interpreted:
                binaries += 1  # a real executable launched directly (round 5)
            elif kind in ("exec", "forged") or interpreted or _referenced(rel, launchers):
                findings.append(_truncated(evidence, rel))
            elif kind == "media":
                binaries += 1
        return files, findings + _binary_unscanned(binaries)

    def exec_kind(head: bytes) -> str:
        return "exec" if _plausible_executable(head) else "forged"

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
                        kind = exec_kind(head) if _is_executable(head) else "media"
                        pending.append((rel, f"{rel} is {size} bytes (limit {max_file_bytes}); not scanned", kind))
                    elif (b"\x00" in head or _is_binary(head) or _is_executable(head)
                          or rel.endswith(SHELL_EXT) or _shell_shebang(head)):
                        # NUL bytes, a script under a forged binary/media header (R27 round 3), or a
                        # shell script / #! file: not bundled text, so the unscanned tail stays MED.
                        findings.append(_truncated(f"{rel} is {size} bytes (limit {max_file_bytes}); not scanned", rel))
                    elif size <= max_text_bytes:
                        # Big bundled text: scanned in full (R40).
                        if over_total(rel, size):
                            return finish()
                        data = path.read_bytes()
                        if b"\x00" in data:  # review M6: NUL anywhere, not only in the head
                            findings.append(_truncated(f"{rel} is source with NUL bytes; not scanned", rel))
                        else:
                            files.append(ScanFile(rel, data.decode("utf-8", errors="replace")))
                    else:
                        # Above the ceiling, padding that big is itself suspicious: head + tail, MED (R40).
                        with path.open("rb") as fh:
                            part = fh.read(max_file_bytes)
                            fh.seek(max(size - max_file_bytes, max_file_bytes))
                            tail = fh.read(max_file_bytes)
                        if b"\x00" in part or b"\x00" in tail:
                            findings.append(_truncated(f"{rel} is {size} bytes with NUL bytes; not scanned", rel))
                        elif over_total(rel, len(part) + len(tail)):
                            return finish()
                        else:
                            text = part.decode("utf-8", errors="replace") + "\n" + tail.decode("utf-8", errors="replace")
                            files.append(ScanFile(rel, text))
                            findings.append(_truncated(
                                f"{rel} is {size} bytes (limit {max_text_bytes}); only the first and last "
                                f"{max_file_bytes} bytes scanned", rel,
                            ))
                    continue
                data = path.read_bytes()
            except OSError:
                continue
            if b"\x00" in data[:8192]:
                head = data[:8192]
                if _is_code_name(rel, head):
                    findings.append(_truncated(f"{rel} is source code with NUL bytes; not scanned", rel))
                elif _is_executable(head):  # prebuilt executables are counted
                    pending.append((rel, f"{rel} contains NUL bytes; not scanned", exec_kind(head)))
                else:  # small images/archives stay silent unless a launcher runs them
                    pending.append((rel, f"{rel} contains NUL bytes; not scanned", "quiet"))
                continue
            if over_total(rel, len(data)):
                return finish()
            files.append(ScanFile(rel, data.decode("utf-8", errors="replace")))
    return finish()
