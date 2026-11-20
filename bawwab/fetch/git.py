from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

from bawwab.fetch.common import FetchError, FetchOpts, symlink_findings
from bawwab.types import Finding, PackageMeta, Target


def _env(home: Path) -> dict[str, str]:
    """Environment that never reads config from the untrusted checkout."""
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "HOME": str(home),
    }


def _run(cmd: list[str], timeout: float, home: Path) -> str:
    try:
        from bawwab.limits import child_argv

        env = _env(home)
        r = subprocess.run(child_argv(cmd, env), capture_output=True, text=True, timeout=timeout, cwd=home, env=env)
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
    home = tmp / "home"
    home.mkdir()
    file_proto = "always" if opts.git_allow_file else "never"
    cmd = [
        "git", "clone", "--depth", "1", "--no-recurse-submodules",
        "-c", "core.hooksPath=/dev/null",
        "-c", "core.fsmonitor=false",
        "-c", f"protocol.file.allow={file_proto}",
        "-c", "protocol.ext.allow=never",
    ]
    if t.version:
        cmd += ["--branch", t.version]
    cmd += ["--", url, str(dest)]
    _run(cmd, opts.timeout_s, home)
    sha = _run(["git", "--git-dir", str(dest / ".git"), "-c", "core.fsmonitor=false", "rev-parse", "HEAD"], opts.timeout_s, home).strip()
    shutil.rmtree(dest / ".git", ignore_errors=True)
    name = url.rstrip("/").rsplit("/", 1)[-1].removesuffix(".git")
    return dest, sha, PackageMeta(name=name, repo_url=url), symlink_findings(dest)
