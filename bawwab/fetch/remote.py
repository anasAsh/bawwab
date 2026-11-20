from __future__ import annotations

import asyncio
import json
import re
import urllib.error
import urllib.request
from contextlib import asynccontextmanager

from bawwab.fetch.common import FetchError
from bawwab.types import ToolInfo


class RemoteAuthRequired(FetchError):
    """The server answered 401/403: it needs sign-in before its tools can be listed."""


AUTH_STATUS = (401, 403)
_AUTH_ERR_RE = re.compile(r"\b(?:401 Unauthorized|403 Forbidden)\b")  # httpx status text
_INIT_PROBE = json.dumps({
    "jsonrpc": "2.0", "id": 0, "method": "initialize",
    "params": {"protocolVersion": "2025-06-18", "capabilities": {}, "clientInfo": {"name": "bawwab", "version": "0"}},
}).encode()


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


def _probe_auth(url: str, timeout_s: float) -> None:
    """Raise RemoteAuthRequired when the server rejects an unauthenticated initialize with 401/403.

    Anything else (success, other status, network error) is left to the MCP client,
    so network failures still fail closed as fetch.failed.
    """
    req = urllib.request.Request(
        url, data=_INIT_PROBE, method="POST",
        headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
    )
    try:
        with urllib.request.build_opener(_NoRedirect).open(req, timeout=timeout_s):
            return
    except urllib.error.HTTPError as e:
        e.close()
        if e.code in AUTH_STATUS:
            raise RemoteAuthRequired(f"remote server answered HTTP {e.code}; sign-in required") from None
    except Exception:  # noqa: BLE001 - not an auth answer; the MCP client decides
        return


@asynccontextmanager
async def _transport(url: str, kind: str):
    if kind == "http":
        try:
            from mcp.client.streamable_http import streamable_http_client as client
        except ImportError:  # older SDKs
            from mcp.client.streamable_http import streamablehttp_client as client
    else:
        from mcp.client.sse import sse_client as client
    async with client(url) as streams:
        yield streams[0], streams[1]


async def _session_dump(url: str, kind: str) -> tuple[str, list[ToolInfo]]:
    from mcp import ClientSession

    async with _transport(url, kind) as (read, write):
        async with ClientSession(read, write) as session:
            init = await session.initialize()
            info = getattr(init, "server_info", None) or getattr(init, "serverInfo", None)  # mcp 2.x / 1.x
            version = getattr(info, "version", None) or "unversioned"
            tools: list[ToolInfo] = []
            try:
                for t in (await session.list_tools()).tools:
                    tools.append(ToolInfo(t.name, t.description or "", getattr(t, "input_schema", None) or getattr(t, "inputSchema", None)))
            except Exception:
                pass
            try:
                for p in (await session.list_prompts()).prompts:
                    tools.append(ToolInfo(f"prompt:{p.name}", p.description or ""))
            except Exception:
                pass
            try:
                for r in (await session.list_resources()).resources:
                    tools.append(ToolInfo(f"resource:{r.name}", r.description or "", {"uri": str(r.uri)}))
            except Exception:
                pass
            return str(version), tools


async def _fetch(url: str) -> tuple[str, list[ToolInfo]]:
    errors = []
    for kind in ("http", "sse"):
        try:
            return await _session_dump(url, kind)
        except Exception as e:
            errors.append(f"{kind}: {type(e).__name__}: {e}")
    detail = "; ".join(errors)[:400]
    if _AUTH_ERR_RE.search(detail):
        raise RemoteAuthRequired(f"remote server requires sign-in ({detail})")
    raise FetchError("remote MCP server unreachable or invalid (" + detail + ")")


def fetch_remote(url: str, timeout_s: float) -> tuple[str, list[ToolInfo]]:
    if not url.startswith(("http://", "https://")):
        raise FetchError("remote url must be http(s)")
    _probe_auth(url, min(10.0, timeout_s / 2))
    try:
        return asyncio.run(asyncio.wait_for(_fetch(url), timeout_s))
    except FetchError:
        raise
    except TimeoutError as e:
        raise FetchError(f"remote MCP fetch timed out after {timeout_s}s") from e
    except BaseException as e:
        if isinstance(e, (KeyboardInterrupt, SystemExit)):
            raise
        raise FetchError(f"remote MCP fetch failed: {type(e).__name__}: {e}") from e


def remote_hash(tools: list[ToolInfo]) -> str:
    import hashlib

    blob = json.dumps(
        [{"name": t.name, "description": t.description, "input_schema": t.input_schema} for t in tools],
        sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )
    return hashlib.sha256(blob.encode("utf-8", "surrogatepass")).hexdigest()
