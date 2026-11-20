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
    try:
        soft, hard = resource.getrlimit(LIMIT)
        if hard != resource.RLIM_INFINITY:
            limit = min(limit, hard)
        if soft == resource.RLIM_INFINITY or soft > limit:
            resource.setrlimit(LIMIT, (limit, hard))
        return resource.getrlimit(LIMIT)[0]
    except (OSError, ValueError):
        return None
