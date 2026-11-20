from __future__ import annotations

from pathlib import Path

from bawwab.fetch.common import FetchError, symlink_findings
from bawwab.types import Finding, PackageMeta, Target


def fetch_local(t: Target) -> tuple[Path, str, PackageMeta, list[Finding]]:
    p = Path(t.path or t.raw).expanduser()
    if not p.is_dir():
        raise FetchError(f"local path is not a directory: {p}")
    root = p.resolve()
    return root, "local", PackageMeta(name=t.name or root.name), symlink_findings(root)
