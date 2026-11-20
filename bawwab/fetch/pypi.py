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


def _first_upload(t: Target, opts: FetchOpts, doc: dict, urls: list[dict]) -> datetime | None:
    """When the project was first published: the earliest upload of any release (Task 10c E).

    The version endpoint has no "releases", so a pinned fetch reads the project document too. If that
    fails, the current release's upload time is used (as before): never older than the truth.
    """
    releases = doc.get("releases")
    if not isinstance(releases, dict) and t.version:
        try:
            project = http_get_json(f"{opts.pypi_base.rstrip('/')}/pypi/{quote(t.name, safe='')}/json", opts.timeout_s)
            releases = project.get("releases")
        except FetchError:
            releases = None
    files = list(urls)
    if isinstance(releases, dict):
        files += [u for rel in releases.values() if isinstance(rel, list) for u in rel if isinstance(u, dict)]
    times = sorted(d for d in (_dt(u.get("upload_time_iso_8601")) for u in files) if d)
    return times[0] if times else None


def fetch_pypi(t: Target, opts: FetchOpts, tmp: Path) -> tuple[Path, str, PackageMeta, list[Finding]]:
    if not t.name:
        raise FetchError("pypi target has no package name")
    path = f"/pypi/{quote(t.name, safe='')}" + (f"/{quote(t.version, safe='')}" if t.version else "") + "/json"
    doc = http_get_json(opts.pypi_base.rstrip("/") + path, opts.timeout_s)
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    urls = [u for u in (doc.get("urls") or []) if isinstance(u, dict) and u.get("url")]
    pick = next((u for u in urls if u.get("packagetype") == "sdist"), None) or next(
        (u for u in urls if u.get("packagetype") == "bdist_wheel"), None
    )
    if pick is None:
        raise FetchError(f"pypi: no sdist or wheel for {t.name}")
    version = str(info.get("version") or t.version or "unversioned")
    digest = (pick.get("digests") or {}).get("sha256")
    arc = download(pick["url"], tmp / "download.bin", opts.timeout_s, sha256=digest)
    dest = tmp / "x"
    dest.mkdir()
    findings = extract_archive(arc, dest)
    arc.unlink(missing_ok=True)
    purls = info.get("project_urls") if isinstance(info.get("project_urls"), dict) else {}
    repo_url = next((purls[k] for k in ("Source", "Repository", "Source Code", "Homepage", "GitHub") if purls.get(k)), None)
    meta = PackageMeta(name=t.name, repo_url=repo_url or info.get("home_page") or None, created_at=_first_upload(t, opts, doc, urls))
    root = strip_single_dir(dest) if pick.get("packagetype") == "sdist" else dest
    return root, version, meta, findings
