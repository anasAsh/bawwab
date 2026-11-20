"""RULESET_VERSION: a hash of everything that decides a scan's findings.

Cached scans carry the version they were made with; a changed rule, catalog entry, identity check, file
loader or judge prompt changes the hash, so stale cache entries are rescanned. Computed once at import
from the source files (no imports, a few hundred KB read).
"""
from __future__ import annotations

import hashlib
from pathlib import Path

_SCAN = Path(__file__).resolve().parent / "scan"
_SOURCES = ("rules/*.py", "identity.py", "files.py", "osv.py", "judge/prompt.py")
# Bumped by hand when something outside _SOURCES changes findings (Task 10c: PyPI first-upload date).
_REVISION = "10c-r4"


def _compute() -> str:
    h = hashlib.sha256(f"revision {_REVISION}\n".encode())
    files = sorted({p for pat in _SOURCES for p in _SCAN.glob(pat)})
    for p in files:
        try:
            data = p.read_bytes()
        except OSError:
            data = b"<unreadable>"
        h.update(f"{p.relative_to(_SCAN).as_posix()}\0{len(data)}\n".encode())
        h.update(data)
    return h.hexdigest()


RULESET_VERSION = _compute()
