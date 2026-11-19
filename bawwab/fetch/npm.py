from __future__ import annotations

from datetime import datetime
from pathlib import Path
from urllib.parse import quote

from bawwab.fetch.common import FetchError, FetchOpts, download, http_get_json, strip_single_dir
from bawwab.fetch.extract import extract_archive
from bawwab.types import Finding, PackageMeta, Target


def _dt(s) -> datetime | None:
    try:
        return datetime.fromisoformat(s) if isinstance(s, str) else None
    except ValueError:
        return None


def fetch_npm(t: Target, opts: FetchOpts, tmp: Path) -> tuple[Path, str, PackageMeta, list[Finding]]:
    if not t.name:
        raise FetchError("npm target has no package name")
    doc = http_get_json(f"{opts.npm_registry.rstrip('/')}/{quote(t.name, safe='@')}", opts.timeout_s)
    version = t.version or (doc.get("dist-tags") or {}).get("latest")
    versions = doc.get("versions") or {}
    if not version or version not in versions:
        raise FetchError(f"npm: version {version!r} of {t.name} not found")
    try:
        tarball = versions[version]["dist"]["tarball"]
    except (KeyError, TypeError) as e:
        raise FetchError(f"npm: no tarball for {t.name}@{version}") from e
    arc = download(tarball, tmp / "download.tgz", opts.timeout_s)
    dest = tmp / "x"
    dest.mkdir()
    findings = extract_archive(arc, dest)
    arc.unlink(missing_ok=True)
    repo = doc.get("repository")
    repo_url = repo.get("url") if isinstance(repo, dict) else repo if isinstance(repo, str) else None
    created = _dt((doc.get("time") or {}).get("created")) if isinstance(doc.get("time"), dict) else None
    meta = PackageMeta(name=t.name, repo_url=repo_url, created_at=created)
    return strip_single_dir(dest, prefer="package"), str(version), meta, findings
