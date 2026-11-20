"""Process-level memory backstop (fix round 1, I2).

The scan's own budgets (call text, parse trees, loaded text) are the real bounds. This soft limit catches
whatever they miss: an allocation past it raises MemoryError, which the code rule reports per file as
`rules.error` (MED) and scan_target turns into a fail-closed report, instead of the kernel's OOM killer
taking the machine (or the hook) down. Only the soft limit is lowered, so a caller can raise it again.

RLIMIT_AS (address space) is used: a scan's virtual size stays close to its resident size (the 14.5 MB
@sveltejs/mcp bundle peaks at 1.4 GB virtual, 1.3 GB resident), and tree-sitter, git and docker run under
it. BAWWAB_MEMORY_LIMIT_MB overrides the size; 0 disables the limit.
"""
from __future__ import annotations

import os

try:
    import resource
except ImportError:  # pragma: no cover - non-POSIX
    resource = None  # type: ignore[assignment]

DEFAULT_LIMIT = 3 << 30
LIMIT = getattr(resource, "RLIMIT_AS", None)
_ORIGINAL: tuple[int, int] | None = None  # (soft, hard) before apply_memory_limit lowered the soft limit


def apply_memory_limit(limit: int | None = None) -> int | None:
    """Lower the soft address-space limit to `limit` bytes (default 3 GB). Returns the limit in force."""
    if resource is None or LIMIT is None:
        return None
    env = os.environ.get("BAWWAB_MEMORY_LIMIT_MB", "").strip()
    if limit is None and env:
        try:
            limit = int(env) << 20
        except ValueError:
            limit = None
        if limit == 0:
            return None
    limit = limit or DEFAULT_LIMIT
    global _ORIGINAL
    try:
        soft, hard = resource.getrlimit(LIMIT)
        if hard != resource.RLIM_INFINITY:
            limit = min(limit, hard)
        if soft == resource.RLIM_INFINITY or soft > limit:
            if _ORIGINAL is None:
                _ORIGINAL = (soft, hard)
            resource.setrlimit(LIMIT, (limit, hard))
        return resource.getrlimit(LIMIT)[0]
    except (OSError, ValueError):
        return None


def child_argv(argv: list[str], env: dict | None = None) -> list[str]:
    """`argv` for a child process that must not inherit the scan's limit (review R1-I1): the judge's
    `claude` (a Bun/JSC binary that reserves large regions), git, uv, a spawned bawwab. Unchanged unless
    apply_memory_limit lowered it; otherwise a /bin/sh wrapper raises the soft limit back to its original
    value (allowed: soft <= hard) and execs the program. No preexec_fn: scans run in threads in the MCP
    server, where preexec_fn can deadlock. The executable is resolved here, so a missing one still raises
    FileNotFoundError in the parent."""
    import shutil

    argv = [str(a) for a in argv]
    if _ORIGINAL is None or resource is None:
        return argv
    exe = argv[0]
    if not os.path.isabs(exe):
        found = shutil.which(exe, path=(env or os.environ).get("PATH"))
        if not found:
            raise FileNotFoundError(exe)
        exe = found
    soft = _ORIGINAL[0]
    value = "unlimited" if soft == resource.RLIM_INFINITY else str(max(soft // 1024, 1))
    return ["/bin/sh", "-c", f'ulimit -S -v {value} 2>/dev/null; exec "$@"', "bawwab-child", exe, *argv[1:]]


def limit_malloc_arenas(n: int = 2) -> None:
    """Cap glibc's per-thread malloc arenas (review R1-M2): each reserves 64 MB of address space, which
    RLIMIT_AS counts, so a threaded server would hit the limit at a few hundred MB of real memory."""
    try:
        import ctypes

        ctypes.CDLL(None).mallopt(-8, n)  # M_ARENA_MAX
    except (OSError, AttributeError, TypeError):  # pragma: no cover - not glibc
        pass
