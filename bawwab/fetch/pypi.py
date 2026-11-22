from __future__ import annotations

import re
import sys
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


# ------------------------------------------------------------------ which file pip would install
# pip and uv install a wheel when one fits this interpreter and platform, and build the sdist (running setup.py)
# only when none does. So the scan reads what installs: a pure-Python wheel first, else the platform wheel that
# fits best, else the sdist.

_WHEEL = re.compile(r"^(?P<name>[^-]+)-(?P<ver>[^-]+)(?:-(?P<build>\d[^-]*))?-(?P<py>[^-]+)-(?P<abi>[^-]+)-(?P<plat>[^-]+)\.whl$")


def _wheel_tags(filename: str) -> list[tuple[str, str, str]] | None:
    m = _WHEEL.match(filename)
    if m is None:
        return None
    return [(py, abi, plat) for py in m["py"].split(".") for abi in m["abi"].split(".") for plat in m["plat"].split(".")]


def _pure_ok(py: str, abi: str, plat: str) -> bool:
    """A pure-Python tag this interpreter accepts: py3 / py3N (N <= ours) with no ABI on any platform."""
    if abi != "none" or plat != "any":
        return False
    major, minor = sys.version_info[:2]
    if py in (f"py{major}", f"py{major}{minor}"):
        return True
    m = re.fullmatch(r"py(\d)(\d+)?", py)
    return m is not None and int(m[1]) == major and m[2] is not None and int(m[2]) <= minor


def _platform_rank():
    """tag -> rank (lower is better) for this interpreter and platform, as pip orders them; None without the
    `packaging` library (then only pure-Python wheels are recognised, else the sdist is scanned)."""
    try:
        from packaging.tags import sys_tags
    except ImportError:  # pragma: no cover - packaging comes with bawwab's dependencies
        return None
    return {(t.interpreter, t.abi, t.platform): i for i, t in enumerate(sys_tags())}


def pick_file(urls: list[dict]) -> dict | None:
    """The release file pip would install here: a pure-Python wheel, else the best-fitting platform wheel, else
    the sdist; a wheel that fits nothing here is skipped (pip would build the sdist). Yanked files come last."""
    files = sorted(urls, key=lambda u: bool(u.get("yanked")))
    wheels = [(u, _wheel_tags(str(u.get("filename") or u["url"].rsplit("/", 1)[-1].split("#", 1)[0])))
              for u in files if u.get("packagetype") == "bdist_wheel"]
    wheels = [(u, tags) for u, tags in wheels if tags]
    pure = [u for u, tags in wheels if any(_pure_ok(*tag) for tag in tags)]
    if pure:
        return pure[0]
    rank = _platform_rank() or {}
    best = None
    for u, tags in wheels:
        r = min((rank[tag] for tag in tags if tag in rank), default=None)
        if r is not None and (best is None or r < best[0]):
            best = (r, u)
    if best is not None:
        return best[1]
    sdist = next((u for u in files if u.get("packagetype") == "sdist"), None)
    return sdist or next((u for u, _ in wheels), None)  # only wheels for other platforms: still read one


def fetch_pypi(t: Target, opts: FetchOpts, tmp: Path) -> tuple[Path, str, PackageMeta, list[Finding]]:
    if not t.name:
        raise FetchError("pypi target has no package name")
    path = f"/pypi/{quote(t.name, safe='')}" + (f"/{quote(t.version, safe='')}" if t.version else "") + "/json"
    doc = http_get_json(opts.pypi_base.rstrip("/") + path, opts.timeout_s)
    info = doc.get("info") if isinstance(doc.get("info"), dict) else {}
    urls = [u for u in (doc.get("urls") or []) if isinstance(u, dict) and u.get("url")]
    pick = pick_file(urls)
    if pick is None:
        raise FetchError(f"pypi: no sdist or wheel for {t.name} that installs here")
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
