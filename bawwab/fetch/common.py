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


_SRI_ALGS = ("sha512", "sha384", "sha256", "sha1")  # strongest first (W3C Subresource Integrity)


def _sri(integrity: str | None, sha1_hex: str | None) -> dict[str, set[bytes]]:
    """Expected digests by algorithm from an npm `dist.integrity` SRI string ("sha512-<base64> ..."), only the
    strongest algorithm given counts (as SRI); else from `dist.shasum` (sha1 hex). {} when neither is usable."""
    import base64
    import binascii

    want: dict[str, set[bytes]] = {}
    for tok in (integrity or "").split():
        alg, _, b64 = tok.partition("-")
        if alg in _SRI_ALGS and b64:
            try:
                want.setdefault(alg, set()).add(base64.b64decode(b64.split("?", 1)[0], validate=True))
            except (binascii.Error, ValueError):
                continue
    if want:
        best = next(a for a in _SRI_ALGS if a in want)
        return {best: want[best]}
    if sha1_hex:
        try:
            return {"sha1": {bytes.fromhex(sha1_hex.strip())}}
        except ValueError:
            return {}
    return {}


def download(url: str, dest: Path, timeout: float, sha256: str | None = None, integrity: str | None = None,
             sha1_hex: str | None = None) -> Path:
    """Stream url to dest, enforcing the size cap. Never interprets the content. sha256 (hex, PyPI), or an npm
    SRI `integrity` string / sha1 `shasum`, is checked against the bytes received."""
    h = hashlib.sha256()
    want = _sri(integrity, sha1_hex)
    extra = {alg: hashlib.new(alg) for alg in want}
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
                    for x in extra.values():
                        x.update(chunk)
                    fh.write(chunk)
    except FetchError:
        raise
    except Exception as e:
        raise FetchError(f"download of {url} failed: {type(e).__name__}: {e}") from e
    if sha256 and h.hexdigest() != sha256.lower():
        raise FetchError(f"sha256 mismatch for {url}")
    for alg, x in extra.items():
        if x.digest() not in want[alg]:
            raise FetchError(f"{alg} integrity mismatch for {url}")
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
    """sha256 over sorted `rel\\0sha256` lines. Symlinks are hashed by target, never followed. Claude Code's
    .in_use markers of the root are left out, as the scanned file list leaves them out (bawwab/scan/files.py):
    they come and go with every session, and this hash is the approval key of an installed plugin."""
    from bawwab.agents.claude_code_watch import is_in_use_marker

    lines: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        for name in filenames:
            p = Path(dirpath) / name
            if is_in_use_marker(str(p), str(root)):
                continue
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
