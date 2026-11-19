from __future__ import annotations

import asyncio
import json
from contextlib import asynccontextmanager

from bawwab.fetch.common import FetchError
from bawwab.types import ToolInfo


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
            version = getattr(getattr(init, "serverInfo", None), "version", None) or "unversioned"
            tools: list[ToolInfo] = []
            try:
                for t in (await session.list_tools()).tools:
                    tools.append(ToolInfo(t.name, t.description or "", t.inputSchema))
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
    raise FetchError("remote MCP server unreachable or invalid (" + "; ".join(errors)[:400] + ")")


def fetch_remote(url: str, timeout_s: float) -> tuple[str, list[ToolInfo]]:
    if not url.startswith(("http://", "https://")):
        raise FetchError("remote url must be http(s)")
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
    return hashlib.sha256(blob.encode()).hexdigest()
