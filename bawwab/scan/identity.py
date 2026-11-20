"""Package identity checks: typosquatting, brand-new packages, and repo/name mismatch."""

from __future__ import annotations

import re
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from importlib import resources

from rapidfuzz.distance import Levenshtein

from bawwab.types import Finding, PackageMeta, Severity

NEW_PACKAGE_DAYS = 7


@lru_cache(maxsize=1)
def popular_names() -> tuple[str, ...]:
    text = resources.files("bawwab.scan").joinpath("popular.txt").read_text(encoding="utf-8")
    return tuple(_norm(line) for line in text.splitlines() if line.strip() and not line.startswith("#"))


def _norm(name: str) -> str:
    return name.strip().lower().replace("_", "-")


def _unscoped(name: str) -> str:
    return name.rsplit("/", 1)[-1] if name.startswith("@") else name


def _typosquat(name: str) -> Finding | None:
    n = _norm(name)
    popular = popular_names()
    if not n or n in popular:
        return None
    best: tuple[int, str] | None = None
    for p in popular:
        for a, b in ((n, p), (_unscoped(n), _unscoped(p))):
            # very short names are all within 2 edits of each other; require some length
            if min(len(a), len(b)) < 4:
                continue
            d = Levenshtein.distance(a, b)
            limit = 2 if min(len(a), len(b)) >= 6 else 1
            if 1 <= d <= limit and (best is None or d < best[0]):
                best = (d, p)
    if best is None:
        return None
    return Finding(
        "identity.typosquat", Severity.MED, "identity",
        f"{name!r} is {best[0]} edit(s) from the popular package {best[1]!r}",
    )


def _tokens(s: str) -> set[str]:
    out = set()
    for t in re.split(r"[^a-z0-9]+", s.lower()):
        if t:
            out.add(t[:-1] if len(t) > 3 and t.endswith("s") else t)
    return out


def _repo_segment(url: str) -> str:
    url = url.split("#", 1)[0].split("?", 1)[0].rstrip("/")
    seg = re.split(r"[/:]", url)[-1]
    return seg.removesuffix(".git")


def _repo_mismatch(meta: PackageMeta) -> Finding | None:
    if not meta.repo_url:
        return None
    seg = _repo_segment(meta.repo_url)
    repo_t, name_t = _tokens(seg), _tokens(meta.name)
    if not repo_t or not name_t or repo_t & name_t:
        return None
    return Finding(
        "identity.repo-mismatch", Severity.LOW, "identity",
        f"repository {seg!r} shares no word with package name {meta.name!r}",
    )


def identity_checks(meta: PackageMeta, now: datetime | None = None) -> list[Finding]:
    now = now or datetime.now(UTC)
    if now.tzinfo is None:
        now = now.replace(tzinfo=UTC)
    findings: list[Finding] = []
    if (f := _typosquat(meta.name)) is not None:
        findings.append(f)
    if meta.created_at is not None:
        created = meta.created_at if meta.created_at.tzinfo else meta.created_at.replace(tzinfo=UTC)
        if now - created < timedelta(days=NEW_PACKAGE_DAYS):
            findings.append(
                Finding("identity.new-package", Severity.MED, "identity", f"first published {created.date().isoformat()}, under {NEW_PACKAGE_DAYS} days ago")
            )
    if (f := _repo_mismatch(meta)) is not None:
        findings.append(f)
    return findings
