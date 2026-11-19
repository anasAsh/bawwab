from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from bawwab.fetch.common import FetchError, FetchOpts, symlink_findings
from bawwab.types import Finding, PackageMeta, Target


def _run(cmd: list[str], timeout: float, cwd: Path | None = None) -> str:
    env = {"PATH": "/usr/local/bin:/usr/bin:/bin", "GIT_TERMINAL_PROMPT": "0", "GIT_CONFIG_NOSYSTEM": "1", "HOME": str(cwd or "/nonexistent")}
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, cwd=cwd, env=env)
    except subprocess.TimeoutExpired as e:
        raise FetchError("git timed out") from e
    except OSError as e:
        raise FetchError(f"git unavailable: {e}") from e
    if r.returncode != 0:
        raise FetchError(f"git failed: {r.stderr.strip()[:300]}")
    return r.stdout


def fetch_git(t: Target, opts: FetchOpts, tmp: Path) -> tuple[Path, str, PackageMeta, list[Finding]]:
    url = t.url or t.raw
    if not url or url.startswith("-") or any(c in url for c in "\0\n"):
        raise FetchError("invalid git url")
    dest = tmp / "repo"
    file_proto = "always" if opts.git_allow_file else "never"
    cmd = [
        "git", "clone", "--depth", "1", "--no-recurse-submodules",
        "-c", "core.hooksPath=/dev/null",
        "-c", f"protocol.file.allow={file_proto}",
        "-c", "protocol.ext.allow=never",
    ]
    if t.version:
        cmd += ["--branch", t.version]
    cmd += ["--", url, str(dest)]
    _run(cmd, opts.timeout_s)
    sha = _run(["git", "rev-parse", "HEAD"], opts.timeout_s, cwd=dest).strip()
    shutil.rmtree(dest / ".git", ignore_errors=True)
    name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    return dest, sha, PackageMeta(name=name, repo_url=url), symlink_findings(dest)
