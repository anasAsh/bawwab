"""Test helper: a fake `uv` on PATH that runs the fake `bawwab` next to it with bawwab's own arguments.

The hook always runs `uv run --project <plugin root> --frozen --quiet bawwab <sub>` (fix round 1 I2); tests that
fake bawwab put both on PATH."""
from __future__ import annotations

from pathlib import Path


def write_uv_shim(bin_dir: Path, log: Path | None = None) -> None:
    uv = bin_dir / "uv"
    rec = f'printf "%s\\n" "$*" >> "{log}"\n' if log else ""
    uv.write_text("#!/bin/sh\n" + rec + 'while [ $# -gt 0 ] && [ "$1" != bawwab ]; do shift; done\n'
                  '[ $# -gt 0 ] || exit 97\nshift\nexec "$(dirname "$0")/bawwab" "$@"\n')
    uv.chmod(0o755)
