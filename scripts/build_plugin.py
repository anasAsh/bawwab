#!/usr/bin/env python3
"""Build Bawwab's runtime-only plugin tree (R51).

Usage: python3 scripts/build_plugin.py OUTDIR

Copies an explicit allowlist (never tests/, bench/, docs/ or .superpowers/) so the installed plugin holds only
what runs. Symlinks are resolved to real files. No marketplace.json is written: the marketplace on main points
at the branch this tree is published to. Stdlib only.
"""
from __future__ import annotations

import shutil
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FILES = (".claude-plugin/plugin.json", "pyproject.toml", "uv.lock", "LICENSE", "NOTICE", "README.md")
DIRS = ("hooks", "skills", "bawwab", "bin")  # bin/bawwab: the plugin CLI launcher (R54)
_SKIP = shutil.ignore_patterns("__pycache__", "*.pyc", "*.pyo")


def build(out: Path) -> Path:
    out = Path(out).resolve()
    if out == ROOT or ROOT in out.parents and not str(out).startswith(str(ROOT / "dist")):
        raise SystemExit(f"refusing to build into the source tree: {out}")
    if out.exists() and any(out.iterdir()) and not (out / ".claude-plugin" / "plugin.json").is_file():
        raise SystemExit(f"refusing to replace a non-empty directory that is not a built plugin: {out}")
    if out.exists():
        shutil.rmtree(out)
    out.mkdir(parents=True)
    for f in FILES:
        (out / f).parent.mkdir(parents=True, exist_ok=True)
        shutil.copyfile(ROOT / f, out / f)  # follows symlinks
    for d in DIRS:
        shutil.copytree(ROOT / d, out / d, symlinks=False, ignore=_SKIP)  # symlinks become real files
    return out


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__.strip(), file=sys.stderr)
        return 2
    print(build(Path(argv[1])))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
