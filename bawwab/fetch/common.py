from __future__ import annotations

import hashlib
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path

import httpx

from bawwab.types import ArtifactType, Finding, Severity

MAX_DOWNLOAD_BYTES = 200 * 1024 * 1024


class FetchError(Exception):
    pass


@dataclass
class FetchOpts:
    npm_registry: str = "https://registry.npmjs.org"
    pypi_base: str = "https://pypi.org"
    osv_url: str = "https://api.osv.dev"  # known-malware lookup (Task 10c)
    timeout_s: float = 60
    remote_timeout_s: float = 15
    # Test-only escape hatch: production keeps protocol.file.allow=never.
    git_allow_file: bool = False


def make_tmp() -> Path:
    return Path(tempfile.mkdtemp(prefix="bawwab-"))


def remover(path: Path):
    def cleanup() -> None:
        shutil.rmtree(path, ignore_errors=True)

    return cleanup


def unsafe(evidence: str, file: str | None = None) -> Finding:
    return Finding("fetch.unsafe-entry", Severity.HIGH, "static", evidence[:300], file=file)


def http_get_json(url: str, timeout: float) -> dict:
    try:
        r = httpx.get(url, timeout=timeout, follow_redirects=True)
        if r.status_code != 200:
            raise FetchError(f"GET {url} returned HTTP {r.status_code}")
        data = r.json()
    except FetchError:
        raise
    except Exception as e:
        raise FetchError(f"GET {url} failed: {type(e).__name__}: {e}") from e
    if not isinstance(data, dict):
        raise FetchError(f"GET {url} returned unexpected JSON")
    return data


def download(url: str, dest: Path, timeout: float, sha256: str | None = None) -> Path:
    """Stream url to dest, enforcing the size cap. Never interprets the content."""
    h = hashlib.sha256()
    total = 0
    try:
        with httpx.stream("GET", url, timeout=timeout, follow_redirects=True) as r:
            if r.status_code != 200:
                raise FetchError(f"GET {url} returned HTTP {r.status_code}")
            declared = r.headers.get("content-length")
            if declared and declared.isdigit() and int(declared) > MAX_DOWNLOAD_BYTES:
                raise FetchError(f"download exceeds {MAX_DOWNLOAD_BYTES} bytes")
            with open(dest, "wb") as fh:
                for chunk in r.iter_bytes(65536):
                    total += len(chunk)
                    if total > MAX_DOWNLOAD_BYTES:
                        raise FetchError(f"download exceeds {MAX_DOWNLOAD_BYTES} bytes")
                    h.update(chunk)
                    fh.write(chunk)
    except FetchError:
        raise
    except Exception as e:
        raise FetchError(f"download of {url} failed: {type(e).__name__}: {e}") from e
    if sha256 and h.hexdigest() != sha256.lower():
        raise FetchError(f"sha256 mismatch for {url}")
    return dest


def strip_single_dir(dest: Path, prefer: str | None = None) -> Path:
    """Archives usually wrap everything in one top directory; return that as root."""
    if prefer and (dest / prefer).is_dir() and not (dest / prefer).is_symlink():
        return dest / prefer
    entries = list(dest.iterdir())
    if len(entries) == 1 and entries[0].is_dir() and not entries[0].is_symlink():
        return entries[0]
    return dest


def hash_tree(root: Path) -> str:
    """sha256 over sorted `rel\\0sha256` lines. Symlinks are hashed by target, never followed."""
    lines: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in filenames:
            p = Path(dirpath) / name
            rel = p.relative_to(root).as_posix()
            try:
                if p.is_symlink():
                    digest = hashlib.sha256(b"symlink:" + os.readlink(p).encode("utf-8", "surrogateescape")).hexdigest()
                else:
                    fh = hashlib.sha256()
                    with open(p, "rb") as f:
                        for chunk in iter(lambda: f.read(1 << 20), b""):
                            fh.update(chunk)
                    digest = fh.hexdigest()
            except OSError:
                digest = "unreadable"
            lines.append(f"{rel}\0{digest}")
    lines.sort()
    return hashlib.sha256("\n".join(lines).encode("utf-8", "surrogateescape")).hexdigest()


def symlink_findings(root: Path) -> list[Finding]:
    out: list[Finding] = []
    real_root = root.resolve()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        for name in dirnames + filenames:
            p = Path(dirpath) / name
            if p.is_symlink():
                try:
                    target = p.resolve()
                    inside = target == real_root or real_root in target.parents
                except (OSError, RuntimeError):
                    inside = False
                if not inside:
                    rel = p.relative_to(root).as_posix()
                    out.append(unsafe(f"symlink {rel} points outside the target root", file=rel))
    return out


def detect_artifact_type(root: Path) -> ArtifactType:
    if (root / ".claude-plugin" / "plugin.json").is_file():
        return "plugin"
    if (root / "SKILL.md").is_file():
        return "skill"
    return "mcp"
