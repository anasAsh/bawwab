"""Known-malware lookup through OSV (https://osv.dev).

OSV carries the OpenSSF malicious-packages feed (github.com/ossf/malicious-packages, Apache-2.0)
as MAL-* advisories. A MAL-* advisory for the exact npm/PyPI name@version is a CRITICAL identity
finding. This is an extra signal: a lookup failure is a LOW note, never a fail-closed block.
Results are cached per ecosystem:name@version for the life of the process; failures are not cached.
"""
from __future__ import annotations

import time

import httpx

from bawwab.types import Finding, Severity

OSV_URL = "https://api.osv.dev"
ECOSYSTEMS = {"npm": "npm", "pypi": "PyPI"}
MAX_PAGES = 10
DEFAULT_BUDGET_S = 5.0  # one total deadline for all pages (review M5)
_CACHE: dict[str, tuple[tuple[str, str], ...]] = {}
_CACHE_MAX = 1024


class OsvError(Exception):
    pass


def clear_cache() -> None:
    _CACHE.clear()


def _post(url: str, body: dict, timeout: float) -> dict:
    try:
        r = httpx.post(url, json=body, timeout=timeout, follow_redirects=True)
        if r.status_code != 200:
            raise OsvError(f"HTTP {r.status_code}")
        data = r.json()
    except OsvError:
        raise
    except Exception as e:  # noqa: BLE001 - any transport/JSON failure is a lookup failure
        raise OsvError(f"{type(e).__name__}: {e}") from e
    if not isinstance(data, dict):
        raise OsvError("unexpected JSON")
    return data


def _mal_ids(v: dict) -> list[str]:
    ids = [v.get("id")] + list(v.get("aliases") or [])
    return [i for i in ids if isinstance(i, str) and i.startswith("MAL-")]


def _query(ecosystem: str, name: str, version: str | None, base: str, timeout: float,
           budget: float) -> tuple[tuple[str, str], ...]:
    body: dict = {"package": {"name": name, "ecosystem": ecosystem}}
    if version:
        body["version"] = version
    hits: list[tuple[str, str]] = []
    url = base.rstrip("/") + "/v1/query"
    deadline = time.monotonic() + budget
    for _ in range(MAX_PAGES):
        left = deadline - time.monotonic()
        if left <= 0:
            raise OsvError(f"no answer within {budget:g}s")
        data = _post(url, body, min(timeout, left))
        for v in data.get("vulns") or []:
            if isinstance(v, dict) and (ids := _mal_ids(v)):
                hits.append((ids[0], str(v.get("summary") or "")[:160]))
        token = data.get("next_page_token")
        if not isinstance(token, str) or not token:
            break
        body = {**body, "page_token": token}
    return tuple(hits)


def known_malware(kind: str, name: str, version: str | None, *, base: str = OSV_URL, timeout: float = 10,
                  budget: float = DEFAULT_BUDGET_S) -> list[Finding]:
    """identity.known-malicious (CRITICAL) for a MAL-* advisory; identity.osv-unavailable (LOW) on failure."""
    ecosystem = ECOSYSTEMS.get(kind)
    if ecosystem is None or not name:
        return []
    version = version if version and version != "unversioned" else None
    key = f"{ecosystem}:{name}@{version or ''}"
    hits = _CACHE.get(key)
    if hits is None:
        try:
            hits = _query(ecosystem, name, version, base, timeout, budget)
        except OsvError as e:
            return [Finding("identity.osv-unavailable", Severity.LOW, "identity",
                            f"known-malware lookup (OSV) failed: {str(e)[:160]}")]
        if len(_CACHE) >= _CACHE_MAX:
            _CACHE.clear()
        _CACHE[key] = hits
    if not hits:
        return []
    ids = ", ".join(sorted({i for i, _ in hits}))
    summary = next((s for _, s in hits if s), "")
    label = f"{name}@{version}" if version else name
    evidence = f"{label} is listed as malicious in OSV ({ids})" + (f": {summary}" if summary else "")
    return [Finding("identity.known-malicious", Severity.CRITICAL, "identity", evidence[:300])]


BATCH_MAX = 1000  # OSV querybatch limit per request


def known_malware_batch(kind: str, pkgs: list[tuple[str, str]], *, base: str = OSV_URL, timeout: float = 10,
                        budget: float = DEFAULT_BUDGET_S) -> list[Finding]:
    """Exact name==version pairs checked in OSV querybatch requests within one deadline.
    identity.known-malicious (CRITICAL) per MAL-* hit. Unlike known_malware, a failed or incomplete answer is
    plugin.deps-unverified (MED, fail closed): these packages are installed without any other scan."""
    ecosystem = ECOSYSTEMS.get(kind)
    if ecosystem is None or not pkgs:
        return []
    url = base.rstrip("/") + "/v1/querybatch"
    deadline = time.monotonic() + budget
    out: list[Finding] = []
    try:
        for i in range(0, len(pkgs), BATCH_MAX):
            chunk = pkgs[i:i + BATCH_MAX]
            left = deadline - time.monotonic()
            if left <= 0:
                raise OsvError(f"no answer within {budget:g}s")
            data = _post(url, {"queries": [{"package": {"name": n, "ecosystem": ecosystem}, "version": v}
                                           for n, v in chunk]}, min(timeout, left))
            results = data.get("results")
            if not isinstance(results, list) or len(results) != len(chunk):
                raise OsvError("incomplete answer")
            for (n, v), res in zip(chunk, results):
                if not isinstance(res, dict) or res.get("next_page_token"):
                    raise OsvError(f"incomplete answer for {n}")
                ids = sorted({x["id"] for x in res.get("vulns") or []
                              if isinstance(x, dict) and isinstance(x.get("id"), str) and x["id"].startswith("MAL-")})
                if ids:
                    out.append(Finding("identity.known-malicious", Severity.CRITICAL, "identity",
                                       f"{n}=={v} (locked dependency) is listed as malicious in OSV ({', '.join(ids)})"[:300]))
    except OsvError as e:
        return out + [Finding("plugin.deps-unverified", Severity.MED, "gate",
                              f"{len(pkgs)} locked dependencies could not be checked for known malware (OSV): "
                              f"{str(e)[:160]}")]
    return out
