from __future__ import annotations

from bawwab.fetch.common import FetchError, FetchOpts, detect_artifact_type, hash_tree, make_tmp, remover
from bawwab.fetch.target import parse_target, target_from_command, target_from_url
from bawwab.fetch.extract import extract_archive
from bawwab.types import Fetched, Finding, PackageMeta, Severity, Target

__all__ = [
    "FetchError", "FetchOpts", "detect_artifact_type", "extract_archive", "fetch_target",
    "parse_target", "target_from_command", "target_from_url",
]


def fetch_target(t: Target, opts: FetchOpts | None = None) -> Fetched:
    """Download (never execute) the target and return a Fetched. Raises FetchError."""
    opts = opts or FetchOpts()
    if t.kind == "docker":
        meta = PackageMeta(name=t.name)
        f = Finding(
            "fetch.docker-unscanned", Severity.MED, "gate",
            f"docker image {t.name}:{t.version or 'latest'} cannot be statically scanned", None,
        )
        return Fetched(t, t.version or "unversioned", None, "", "unknown", meta, [], [f], lambda: None)
    if t.kind == "remote":
        from bawwab.fetch.remote import fetch_remote, remote_hash

        try:
            version, tools = fetch_remote(t.url or t.raw, opts.remote_timeout_s)
            return Fetched(t, version, None, remote_hash(tools), "mcp", PackageMeta(name=t.name or (t.url or "")), tools, [], lambda: None)
        except FetchError:
            raise
        except Exception as e:
            raise FetchError(f"remote fetch failed: {type(e).__name__}: {e}") from e
    if t.kind == "local":
        from bawwab.fetch.local import fetch_local

        try:
            root, version, meta, findings = fetch_local(t)
            return Fetched(t, version, root, hash_tree(root), detect_artifact_type(root), meta, [], findings, lambda: None)
        except FetchError:
            raise
        except Exception as e:
            raise FetchError(f"local fetch failed: {type(e).__name__}: {e}") from e
    tmp = make_tmp()
    cleanup = remover(tmp)
    try:
        if t.kind == "npm":
            from bawwab.fetch.npm import fetch_npm as fn
        elif t.kind == "pypi":
            from bawwab.fetch.pypi import fetch_pypi as fn
        elif t.kind == "git":
            from bawwab.fetch.git import fetch_git as fn
        else:
            raise FetchError(f"unsupported target kind {t.kind}")
        root, version, meta, findings = fn(t, opts, tmp)
        return Fetched(t, version, root, hash_tree(root), detect_artifact_type(root), meta, [], findings, cleanup)
    except BaseException as e:
        cleanup()
        if isinstance(e, FetchError):
            raise
        if isinstance(e, (KeyboardInterrupt, SystemExit)):
            raise
        raise FetchError(f"fetch failed: {type(e).__name__}: {e}") from e
