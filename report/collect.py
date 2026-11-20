"""Build report/targets.json: the ranked, pinned list of popular MCP servers, skills and plugins.

    uv run python report/collect.py [--mcp 50] [--skills 30] [--plugins 20] [--refresh]

Read-only metadata calls only: the npm registry and downloads API, pypistats, the public
top-pypi-packages dataset, and the GitHub REST API through `gh api` (GET only). Nothing is
starred, forked, installed or run. Every ranking choice is documented in report/METHOD.md;
the tunables live in the constants below so the method and the code cannot drift apart silently.

API responses are cached under report/.cache/collect/ so a rerun is reproducible; --refresh
re-pulls them.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
import re
import subprocess
import sys
import time
import urllib.parse
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

HERE = Path(__file__).resolve().parent
CACHE = HERE / ".cache" / "collect"
OUT = HERE / "targets.json"
SCHEMA_VERSION = 1
UA = "bawwab-report/1 (read-only metadata collection)"

# ---------------------------------------------------------------- ranking constants (see METHOD.md)

NPM_QUERIES = ("mcp", "mcp server", "model context protocol", "keywords:mcp-server", "keywords:mcp",
               "keywords:modelcontextprotocol")
NPM_PAGES = 4  # x 250 results per query
NPM_POOL = 160  # top accepted candidates (by search-reported weekly downloads) re-checked against the downloads API
# Extra names put into the candidate pool (they are still ranked by downloads like everything else):
# the Task 10c top-20 MCP list, so search-relevance gaps cannot drop a well-known server.
NPM_SEEDS = ("@playwright/mcp", "chrome-devtools-mcp", "mcp-remote", "@upstash/context7-mcp",
             "@wonderwhy-er/desktop-commander", "@notionhq/notion-mcp-server", "figma-developer-mcp",
             "@supabase/mcp-server-supabase", "@browsermcp/mcp", "@executeautomation/playwright-mcp-server",
             "@agentdeskai/browser-tools-mcp", "@modelcontextprotocol/server-filesystem")
PYPI_TOP_URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
PYPI_POOL = 60

# Packages that match the MCP search but are not MCP servers a user installs into a client:
# SDKs, frameworks, scaffolders, test/inspection tools and unrelated CLIs. Each has a reason.
NOT_A_SERVER: dict[str, str] = {
    # npm
    "@modelcontextprotocol/sdk": "SDK library",
    "@modelcontextprotocol/inspector": "developer inspection tool",
    "@modelcontextprotocol/inspector-cli": "developer inspection tool",
    "@modelcontextprotocol/inspector-server": "developer inspection tool",
    "@modelcontextprotocol/inspector-client": "developer inspection tool",
    "@modelcontextprotocol/create-server": "scaffolder",
    "@modelcontextprotocol/ext-apps": "SDK extension library",
    "@modelcontextprotocol/server": "SDK library (server half)",
    "@modelcontextprotocol/client": "SDK library (client half)",
    "@modelcontextprotocol/node": "SDK library",
    "@modelcontextprotocol/express": "SDK library",
    "@modelcontextprotocol/conformance": "test suite",
    "@anthropic-ai/claude-code": "AI client, not an MCP server",
    "@anthropic-ai/claude-agent-sdk": "SDK library",
    "@anthropic-ai/mcpb": "bundle packaging CLI",
    "@anthropic-ai/dxt": "bundle packaging CLI",
    "@openai/codex": "AI client, not an MCP server",
    "@google/gemini-cli": "AI client, not an MCP server",
    "@github/copilot": "AI client, not an MCP server",
    "@qwen-code/qwen-code": "AI client, not an MCP server",
    "opencode-ai": "AI client, not an MCP server",
    "@sourcegraph/amp": "AI client, not an MCP server",
    "@kilocode/cli": "AI client, not an MCP server",
    "@vscode/vsce": "unrelated CLI",
    "mcp-framework": "framework/scaffolder",
    "fastmcp": "framework",
    "mcp-handler": "framework",
    "@vercel/mcp-adapter": "framework",
    "xmcp": "framework",
    "create-xmcp-app": "scaffolder",
    "@mastra/mcp": "framework",
    "@ai-sdk/mcp": "framework",
    "@langchain/mcp-adapters": "framework",
    "mcp-use": "framework",
    "@smithery/cli": "registry CLI",
    "@smithery/sdk": "SDK library",
    "@cloudflare/workers-oauth-provider": "library",
    "agents": "framework",
    "tsx": "unrelated CLI",
    "@nestjs/cli": "unrelated CLI",
    "nx": "build system whose CLI includes an MCP mode",
    "vitest": "unrelated CLI",
    "storybook": "unrelated CLI",
    "shadcn": "unrelated CLI with an MCP sub-command",
    "@angular/cli": "unrelated CLI with an MCP sub-command",
    "turbo": "unrelated CLI",
    "@nx/workspace": "unrelated CLI",
    "@expo/cli": "unrelated CLI",
    "expo": "unrelated CLI",
    "wrangler": "unrelated CLI",
    "vercel": "unrelated CLI",
    "netlify-cli": "unrelated CLI",
    "@sentry/wizard": "unrelated CLI",
    "@better-auth/cli": "unrelated CLI",
    "prisma": "unrelated CLI with an MCP sub-command",
    "@prisma/cli": "unrelated CLI",
    "@playwright/test": "test runner",
    "playwright": "browser automation library",
    "playwright-core": "browser automation library",
    "@stoplight/spectral-cli": "unrelated CLI",
    "@biomejs/biome": "unrelated CLI",
    "mint": "docs CLI",
    "@mintlify/cli": "docs CLI",
    "mcporter": "MCP client/runtime CLI",
    "add-mcp": "installer CLI that adds servers to AI clients",
    "@goke/mcp": "CLI generator built from MCP tools",
    "@mcp-use/cli": "developer CLI",
    "@mcpjam/cli": "developer test CLI",
    "malicious-mcp-server": "self-described test fixture",
    "mcp-echo-server": "template",
    "@smthrs/mcp": "MCP client adapter",
    "@copilotkit/aimock": "mock server for tests",
    "@tanstack/ai-mcp": "MCP client library",
    "@posthog/mcp": "SDK library",
    "@prefecthq/fastmcp-ts": "framework",
    "@cyanheads/mcp-ts-core": "framework",
    "fastmcp-slim": "framework",
    "fastmcp-tasks": "framework",
    "workers-mcp": "deployment CLI that turns a Cloudflare Worker into a server",
    # PyPI
    "mcp": "SDK library",
    "fastmcp": "framework",
    "mcp-agent": "framework",
    "langchain-mcp-adapters": "framework",
    "llama-index-tools-mcp": "framework",
    "fastapi-mcp": "framework",
    "pydantic-ai-slim": "framework",
    "openai-agents": "framework",
    "mcp-use": "framework",
    "strands-agents": "framework",
    "strands-agents-tools": "framework",
    "google-adk": "framework",
    "litellm": "library",
    "crewai-tools": "framework",
    "smolagents": "framework",
    "autogen-ext": "framework",
    "praisonaiagents": "framework",
}

SKILL_REPO_QUERIES = (
    "topic:agent-skills", "topic:claude-skills", "topic:claude-code-skills", "topic:skills claude",
    "claude skills in:name,description", "agent skills in:name,description",
)
SKILL_REPO_POOL = 40  # most-starred candidate repos inspected
SKILL_PER_REPO = 2  # cap per repo outside anthropics/skills, so one publisher cannot fill the list
SKILL_OFFICIAL = "anthropics/skills"

PLUGIN_OFFICIAL = "anthropics/claude-plugins-official"
PLUGIN_REPO_QUERIES = (
    "topic:claude-code-plugin", "topic:claude-plugins", "topic:claude-code-plugins",
    "claude code plugin marketplace in:name,description", "claude plugins in:name,description",
)
PLUGIN_REPO_POOL = 40
PLUGIN_PER_REPO = 2  # cap per hosting repo, so one publisher cannot fill the list


# ---------------------------------------------------------------- fetching (read-only, cached)

class Fetcher:
    def __init__(self, refresh: bool = False, cache: Path = CACHE) -> None:
        self.refresh = refresh
        self.cache = cache
        self.cache.mkdir(parents=True, exist_ok=True)
        self._last_pypistats = 0.0

    def _cached(self, key: str, fn):
        p = self.cache / (hashlib.sha256(key.encode()).hexdigest()[:24] + ".json")
        if p.exists() and not self.refresh:
            return json.loads(p.read_text())
        try:
            val = fn()
        except Exception as e:  # noqa: BLE001 - record misses so reruns stay stable
            val = {"__error__": f"{type(e).__name__}: {e}"[:300]}
        p.write_text(json.dumps(val))
        return val

    def http(self, url: str, accept: str = "application/json") -> dict | list:
        def go():
            if "pypistats.org" in url:  # pypistats asks for gentle use
                wait = 1.2 - (time.monotonic() - self._last_pypistats)
                if wait > 0:
                    time.sleep(wait)
                self._last_pypistats = time.monotonic()
            req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": accept})
            with urllib.request.urlopen(req, timeout=60) as r:  # noqa: S310 - fixed https endpoints
                return json.load(r)
        return self._cached(f"GET {accept} {url}", go)

    def gh(self, path: str, **params: str) -> dict | list:
        """`gh api` GET. Never any other method."""
        def go():
            cmd = ["gh", "api", "-X", "GET", path]
            for k, v in params.items():
                cmd += ["-f", f"{k}={v}"]
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if r.returncode != 0:
                raise RuntimeError(r.stderr.strip()[:200])
            return json.loads(r.stdout)
        return self._cached(f"gh {path} {sorted(params.items())}", go)


def _err(v) -> bool:
    return isinstance(v, dict) and "__error__" in v


def today() -> str:
    return datetime.now(UTC).date().isoformat()


# ---------------------------------------------------------------- MCP servers

def _npm_enc(name: str) -> str:
    return name.replace("/", "%2f")


def npm_candidates(f: Fetcher) -> dict[str, dict]:
    out: dict[str, dict] = {}
    for q in NPM_QUERIES:
        for page in range(NPM_PAGES):
            u = "https://registry.npmjs.org/-/v1/search?" + urllib.parse.urlencode(
                {"text": q, "size": 250, "from": page * 250})
            d = f.http(u)
            if _err(d):
                continue
            for o in d.get("objects", []):
                p = o["package"]
                out.setdefault(p["name"], {
                    "name": p["name"], "description": p.get("description") or "",
                    "keywords": p.get("keywords") or [], "search_weekly": (o.get("downloads") or {}).get("weekly", 0),
                    "repo": (p.get("links") or {}).get("repository"),
                })
    return out


def npm_latest(f: Fetcher, name: str) -> tuple[str | None, bool]:
    """(latest version, has bin) from the abbreviated packument."""
    d = f.http(f"https://registry.npmjs.org/{_npm_enc(name)}", accept="application/vnd.npm.install-v1+json")
    if _err(d):
        return None, False
    v = (d.get("dist-tags") or {}).get("latest")
    meta = (d.get("versions") or {}).get(v) or {}
    return v, bool(meta.get("bin"))


def npm_weekly(f: Fetcher, name: str) -> int | None:
    d = f.http(f"https://api.npmjs.org/downloads/point/last-week/{name}")
    return None if _err(d) else d.get("downloads")


def pypi_latest(f: Fetcher, name: str) -> tuple[str | None, str]:
    """(latest version, summary)."""
    d = f.http(f"https://pypi.org/pypi/{name}/json")
    return (None, "") if _err(d) else (d["info"]["version"], d["info"].get("summary") or "")


def pypi_weekly(f: Fetcher, name: str) -> int | None:
    d = f.http(f"https://pypistats.org/api/packages/{name.lower()}/recent")
    return None if _err(d) else (d.get("data") or {}).get("last_week")


_SERVER_DESC = re.compile(
    r"mcp[- ]?server|server[s]? for (the )?(mcp|model context)|context protocol \(?mcp\)? server|"
    r"context protocol server|\bmcp\b.{0,60}\bserver\b|\bserver\b.{0,60}\bmcp\b", re.I)
_NOT_SERVER_DESC = re.compile(
    r"\b(sdk|framework|library|instrumentation|scaffold\w*|boilerplate|template|code generator|"
    r"generates? mcp|evaluat\w+|inspector|for building mcp|build(ing)? mcp servers|author mcp servers|"
    r"for (e2e |end-to-end )?testing purposes|test (harness|tool)|mock|adapter extension|wire types|helpers)\b", re.I)
_LEADS_AS_SERVER = re.compile(
    r"^\W*((an?|the|official|local|remote)\s+)*(\w+\s+){0,3}(mcp|model context protocol( \(mcp\))?)\s+server", re.I)
_PLATFORM_BINARY = re.compile(r"-(linux|darwin|win32|windows|freebsd|macos)(-(x64|arm64|ia32|x86_64|musl))+$", re.I)


def server_reason(name: str, desc: str) -> str | None:
    """None when the package looks like an MCP server a user runs; otherwise why it is not counted."""
    if name in NOT_A_SERVER:
        return NOT_A_SERVER[name]
    if _PLATFORM_BINARY.search(name):
        return "platform-specific binary of another package"
    if "mcp" not in name.lower() and not _LEADS_AS_SERVER.match(desc):
        return "name lacks 'mcp' and the description does not lead with 'MCP server' (a general tool with an MCP mode)"
    m = _NOT_SERVER_DESC.search(desc)
    if m and not re.search(r"\bmcp[- ]server\b", name, re.I):
        return f"description marks a non-server package ({m.group(0).lower()!r})"
    if re.search(r"\bclient\b", desc, re.I) and not _SERVER_DESC.search(desc):
        return "description marks an MCP client"
    return None


def official_servers(f: Fetcher) -> list[tuple[str, str]]:
    """(source, package name) for each server under modelcontextprotocol/servers/src."""
    items = f.gh("repos/modelcontextprotocol/servers/contents/src")
    out: list[tuple[str, str]] = []
    if _err(items):
        return out
    for it in items:
        if it.get("type") != "dir":
            continue
        base = f"repos/modelcontextprotocol/servers/contents/src/{it['name']}"
        pj = f.gh(base + "/package.json")
        if not _err(pj) and pj.get("content"):
            out.append(("npm", json.loads(base64.b64decode(pj["content"]))["name"]))
            continue
        pp = f.gh(base + "/pyproject.toml")
        if not _err(pp) and pp.get("content"):
            m = re.search(r'^name\s*=\s*"([^"]+)"', base64.b64decode(pp["content"]).decode(), re.M)
            if m:
                out.append(("pypi", m.group(1)))
    return out


def collect_mcp(f: Fetcher, n: int, log) -> tuple[list[dict], list[dict]]:
    date = today()
    rows: dict[tuple[str, str], dict] = {}
    skipped: list[dict] = []

    official = official_servers(f)
    log(f"mcp: {len(official)} official servers")
    cands = npm_candidates(f)
    for name in NPM_SEEDS:
        if name not in cands:
            d = f.http(f"https://registry.npmjs.org/{_npm_enc(name)}")
            if not _err(d):
                cands[name] = {"name": name, "description": d.get("description") or "", "keywords": [],
                               "search_weekly": npm_weekly(f, name) or 0}
    log(f"mcp: {len(cands)} npm candidates")
    pool = sorted(cands.values(), key=lambda c: -c["search_weekly"])
    checked = 0
    for c in pool:
        if checked >= NPM_POOL:
            break
        why = server_reason(c["name"], c["description"])
        if why:
            if c["search_weekly"] >= 20000:  # keep the exclusion log readable
                skipped.append({"source": "npm", "name": c["name"], "reason": why})
            continue
        checked += 1
        ver, has_bin = npm_latest(f, c["name"])
        if ver is None:
            skipped.append({"source": "npm", "name": c["name"], "reason": "no latest version"})
            continue
        if not has_bin:
            skipped.append({"source": "npm", "name": c["name"],
                            "reason": "no executable (bin): a library, not a runnable server"})
            continue
        wk = npm_weekly(f, c["name"])
        if wk is None:
            continue
        rows[("npm", c["name"])] = _mcp_row("npm", c["name"], ver, wk, date, False)

    top = f.http(PYPI_TOP_URL)
    pnames = [] if _err(top) else [r["project"] for r in top.get("rows", []) if "mcp" in r["project"].lower()]
    log(f"mcp: {len(pnames)} PyPI top-15000 names containing 'mcp'")
    for name in pnames[:PYPI_POOL]:
        ver, summary = pypi_latest(f, name)
        if ver is None:
            continue
        why = server_reason(name, summary)
        if why:
            skipped.append({"source": "pypi", "name": name, "reason": why})
            continue
        wk = pypi_weekly(f, name)
        if wk is None:
            continue
        rows[("pypi", name)] = _mcp_row("pypi", name, ver, wk, date, False)

    for src, name in official:
        if (src, name) in rows:
            rows[(src, name)]["selection"] = "official"
            continue
        if src == "npm":
            ver, _ = npm_latest(f, name)
            wk = npm_weekly(f, name)
        else:
            ver, wk = pypi_latest(f, name)[0], pypi_weekly(f, name)
        if ver is None:
            skipped.append({"source": src, "name": name, "reason": "official but not published"})
            continue
        rows[(src, name)] = _mcp_row(src, name, ver, wk or 0, date, True)

    ordered = sorted(rows.values(), key=lambda r: -r["popularity"]["value"])
    chosen = [r for r in ordered if r["selection"] == "official"]
    for r in ordered:
        if len(chosen) >= n:
            break
        if r not in chosen:
            chosen.append(r)
    chosen.sort(key=lambda r: -r["popularity"]["value"])
    return chosen, skipped


def _mcp_row(src: str, name: str, ver: str, weekly: int, date: str, official: bool) -> dict:
    if src == "npm":
        spec, url = f"{name}@{ver}", f"https://www.npmjs.com/package/{name}/v/{ver}"
        metric, murl = "npm_weekly_downloads", f"https://api.npmjs.org/downloads/point/last-week/{name}"
    else:
        spec, url = f"pypi:{name}=={ver}", f"https://pypi.org/project/{name}/{ver}/"
        metric, murl = "pypi_weekly_downloads", f"https://pypistats.org/api/packages/{name.lower()}/recent"
    return {
        "kind": "mcp", "name": name, "source": src, "version": ver, "commit": None, "spec": spec, "url": url,
        "popularity": {"metric": metric, "value": int(weekly), "collected_at": date, "source_url": murl},
        "selection": "official" if official else "ranked",
    }


# ---------------------------------------------------------------- GitHub helpers

def repo_info(f: Fetcher, full: str) -> dict | None:
    d = f.gh(f"repos/{full}")
    if _err(d) or d.get("private") or d.get("archived") or d.get("fork"):
        return None
    return d


def head_sha(f: Fetcher, full: str, branch: str) -> str | None:
    d = f.gh(f"repos/{full}/commits/{branch}")
    return None if _err(d) else d.get("sha")


def tree(f: Fetcher, full: str, sha: str) -> list[str]:
    d = f.gh(f"repos/{full}/git/trees/{sha}", recursive="1")
    return [] if _err(d) else [t["path"] for t in d.get("tree", []) if t.get("type") == "blob"]


def search_repos(f: Fetcher, queries: tuple[str, ...]) -> list[str]:
    seen: dict[str, int] = {}
    for q in queries:
        d = f.gh("search/repositories", q=q, sort="stars", order="desc", per_page="50")
        if _err(d):
            continue
        for it in d.get("items", []):
            seen[it["full_name"]] = it["stargazers_count"]
    return sorted(seen, key=lambda k: -seen[k])


def _gh_row(kind: str, full: str, sha: str, path: str, name: str, stars: int, date: str, official: bool,
            extra: dict | None = None) -> dict:
    url = f"https://github.com/{full}/tree/{sha}/{path}".rstrip("/")
    spec = f"git:https://github.com/{full}.git@{sha}" + (f"#{path}" if path else "")
    row = {
        "kind": kind, "name": name, "source": "github", "version": None, "commit": sha, "spec": spec, "url": url,
        "repo": full, "path": path,
        "popularity": {"metric": "github_stars", "value": int(stars), "collected_at": date,
                       "source_url": f"https://api.github.com/repos/{full}"},
        "selection": "official" if official else "ranked",
    }
    if extra:
        row.update(extra)
    return row


# ---------------------------------------------------------------- plugins

def _parse_github(url: str) -> str | None:
    m = re.match(r"^(?:https?://github\.com/|git@github\.com:)([^/\s]+/[^/\s#?]+?)(?:\.git)?/?$", url.strip())
    return m.group(1) if m else None


def read_marketplace(f: Fetcher, full: str, sha: str) -> list[dict] | None:
    d = f.gh(f"repos/{full}/contents/.claude-plugin/marketplace.json", ref=sha)
    if _err(d) or not d.get("content"):
        return None
    try:
        data = json.loads(base64.b64decode(d["content"]))
    except ValueError:
        return None
    plugins = data.get("plugins")
    return plugins if isinstance(plugins, list) else None


def plugin_location(f: Fetcher, mkt: str, mkt_sha: str, entry: dict) -> tuple[str, str, str] | str:
    """(hosting repo, commit sha, path) for a marketplace entry, or a reason it cannot be pinned."""
    src = entry.get("source")
    if isinstance(src, str):
        path = src.strip().removeprefix("./").rstrip("/")
        if ".." in path.split("/"):
            return "relative source escapes the marketplace repo"
        return mkt, mkt_sha, path
    if not isinstance(src, dict):
        return "no source"
    kind = src.get("source")
    if kind == "github" and isinstance(src.get("repo"), str):
        full, path = src["repo"], src.get("path") or ""
    elif kind in ("url", "git-subdir") and isinstance(src.get("url"), str):
        full, path = _parse_github(src["url"]), (src.get("path") or "")
        if not full:
            return "source is not a GitHub repository"
    else:
        return f"source type {kind!r} cannot be fetched statically"
    sha = src.get("sha")
    if not (isinstance(sha, str) and re.fullmatch(r"[0-9a-f]{40}", sha)):
        info = repo_info(f, full)
        if not info:
            return "source repository unavailable"
        sha = head_sha(f, full, src.get("ref") or info["default_branch"])
        if not sha:
            return "could not resolve source commit"
    return full, sha, path.strip("/")


def collect_plugins(f: Fetcher, n: int, log) -> tuple[list[dict], list[dict]]:
    date = today()
    skipped: list[dict] = []
    mkts = [PLUGIN_OFFICIAL] + [r for r in search_repos(f, PLUGIN_REPO_QUERIES) if r != PLUGIN_OFFICIAL]
    cands: list[dict] = []
    inspected = 0
    for full in mkts:
        if inspected >= PLUGIN_REPO_POOL:
            break
        info = repo_info(f, full)
        if not info:
            continue
        sha = head_sha(f, full, info["default_branch"])
        plugins = read_marketplace(f, full, sha) if sha else None
        if not plugins:
            continue
        inspected += 1
        for i, e in enumerate(plugins):
            if not isinstance(e, dict) or not isinstance(e.get("name"), str):
                continue
            loc = plugin_location(f, full, sha, e)
            if isinstance(loc, str):
                skipped.append({"marketplace": full, "name": e["name"], "reason": loc})
                continue
            host, hsha, path = loc
            hinfo = info if host == full else repo_info(f, host)
            if not hinfo:
                skipped.append({"marketplace": full, "name": e["name"], "reason": "hosting repository unavailable"})
                continue
            cands.append({"marketplace": full, "order": i, "host": host, "sha": hsha, "path": path,
                          "name": e["name"], "stars": hinfo["stargazers_count"], "official": full == PLUGIN_OFFICIAL})
    log(f"plugins: {inspected} marketplaces, {len(cands)} pinnable entries")
    cands.sort(key=lambda c: (-c["stars"], c["host"], c["marketplace"] != PLUGIN_OFFICIAL, c["order"]))
    chosen: list[dict] = []
    seen: set[tuple[str, str]] = set()
    per_host: dict[str, int] = {}
    for c in cands:
        key = (c["host"], c["path"])
        if key in seen:
            continue
        if per_host.get(c["host"], 0) >= PLUGIN_PER_REPO:
            continue
        seen.add(key)
        per_host[c["host"]] = per_host.get(c["host"], 0) + 1
        chosen.append(_gh_row("plugin", c["host"], c["sha"], c["path"], c["name"], c["stars"], date, c["official"],
                              {"marketplace": c["marketplace"]}))
        if len(chosen) >= n:
            break
    return chosen, skipped


# ---------------------------------------------------------------- skills

def _skill_dirs(paths: list[str]) -> list[str]:
    dirs = sorted({p.rsplit("/", 1)[0] if "/" in p else "" for p in paths if p.rsplit("/", 1)[-1] == "SKILL.md"})
    # Skip templates and test fixtures, and skills under hidden folders (.claude/, .agents/, .github/...):
    # those are a repo's own development helpers, not skills published for users to install.
    # Translated copies under docs/ or i18n folders are skipped too. Order: skills in a top-level skills/
    # folder first, then shallower paths, then alphabetical.
    keep = [d for d in dirs
            if not re.search(r"(^|/)(template|templates|test|tests|fixtures|examples?|docs|i18n|locales?|translations)(/|$)", d)
            and not any(part.startswith(".") for part in d.split("/"))]
    return sorted(keep, key=lambda d: (not d.startswith("skills/"), d.count("/"), d))


def _under(path: str, prefixes: list[str]) -> bool:
    return any(p == "" or path == p or path.startswith(p + "/") for p in prefixes)


def collect_skills(f: Fetcher, n: int, plugins: list[dict], log) -> tuple[list[dict], list[dict]]:
    date = today()
    skipped: list[dict] = []
    covered: dict[str, list[str]] = {}
    for p in plugins:
        covered.setdefault(p["repo"], []).append(p["path"])
    chosen: list[dict] = []

    def add_repo(full: str, cap: int | None, official: bool) -> None:
        info = repo_info(f, full)
        if not info:
            return
        sha = head_sha(f, full, info["default_branch"])
        if not sha:
            return
        dirs = _skill_dirs(tree(f, full, sha))
        taken = 0
        for d in dirs:
            if cap is not None and taken >= cap:
                break
            if len(chosen) >= n:
                return
            if _under(d, covered.get(full, [])):
                skipped.append({"repo": full, "path": d, "reason": "already scanned as part of a selected plugin"})
                continue
            name = d.rsplit("/", 1)[-1] if d else full.split("/")[1]
            chosen.append(_gh_row("skill", full, sha, d, name, info["stargazers_count"], date, official))
            taken += 1

    add_repo(SKILL_OFFICIAL, None, True)
    log(f"skills: {len(chosen)} from {SKILL_OFFICIAL}")
    repos = [r for r in search_repos(f, SKILL_REPO_QUERIES) if r != SKILL_OFFICIAL][:SKILL_REPO_POOL]
    for full in repos:
        if len(chosen) >= n:
            break
        add_repo(full, SKILL_PER_REPO, False)
    return chosen, skipped


# ---------------------------------------------------------------- schema

KINDS = ("mcp", "skill", "plugin")
SOURCES = ("npm", "pypi", "github")
METRICS = ("npm_weekly_downloads", "pypi_weekly_downloads", "github_stars")
_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,120}$")
_DATE = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_SHA = re.compile(r"^[0-9a-f]{40}$")


def target_id(row: dict) -> str:
    base = f"{row['kind']}-{row['source']}-{row['name']}" + (f"-{row['path']}" if row.get("path") else "")
    if row["source"] == "github":
        base = f"{row['kind']}-{row['repo']}" + (f"-{row['path']}" if row.get("path") else "")
    slug = re.sub(r"-{2,}", "-", re.sub(r"[^a-z0-9._-]+", "-", base.lower())).strip("-.")
    return slug[:100] + "-" + hashlib.sha256(row["spec"].encode()).hexdigest()[:6]


def validate_target(t: object) -> list[str]:
    """Schema check for one targets.json entry. Returns problems (empty when valid)."""
    if not isinstance(t, dict):
        return ["entry is not an object"]
    errs: list[str] = []
    req = {"id": str, "rank": int, "kind_rank": int, "kind": str, "name": str, "source": str, "spec": str,
           "url": str, "popularity": dict, "selection": str}
    for k, ty in req.items():
        if not isinstance(t.get(k), ty) or isinstance(t.get(k), bool):
            errs.append(f"{k}: missing or not {ty.__name__}")
    if errs:
        return errs
    if not _ID.match(t["id"]):
        errs.append("id: not a lowercase slug")
    if t["kind"] not in KINDS:
        errs.append(f"kind: {t['kind']!r} not in {KINDS}")
    if t["source"] not in SOURCES:
        errs.append(f"source: {t['source']!r} not in {SOURCES}")
    if t["selection"] not in ("official", "ranked"):
        errs.append("selection: must be official or ranked")
    if not t["url"].startswith("https://"):
        errs.append("url: must be https")
    pop = t["popularity"]
    if pop.get("metric") not in METRICS:
        errs.append(f"popularity.metric: {pop.get('metric')!r} not in {METRICS}")
    if not isinstance(pop.get("value"), int) or isinstance(pop.get("value"), bool) or pop["value"] < 0:
        errs.append("popularity.value: must be a non-negative int")
    if not isinstance(pop.get("collected_at"), str) or not _DATE.match(pop["collected_at"]):
        errs.append("popularity.collected_at: must be YYYY-MM-DD")
    src, spec = t["source"], t["spec"]
    if src == "github":
        if not (isinstance(t.get("commit"), str) and _SHA.match(t["commit"])):
            errs.append("commit: github targets must pin a 40-hex commit SHA")
        if not isinstance(t.get("repo"), str) or not re.fullmatch(r"[\w.-]+/[\w.-]+", t.get("repo") or ""):
            errs.append("repo: must be owner/name")
        if not isinstance(t.get("path"), str):
            errs.append("path: must be a string (\"\" for the repo root)")
        elif ".." in t["path"].split("/") or t["path"].startswith("/"):
            errs.append("path: must stay inside the repo")
        exp = f"git:https://github.com/{t.get('repo')}.git@{t.get('commit')}" + (f"#{t['path']}" if t.get("path") else "")
        if spec != exp:
            errs.append("spec: does not match repo/commit/path")
        if pop.get("metric") != "github_stars":
            errs.append("popularity.metric: github targets rank by github_stars")
    else:
        v = t.get("version")
        if not (isinstance(v, str) and re.match(r"^\d", v)):
            errs.append("version: npm/pypi targets must pin an exact version")
        exp = f"{t['name']}@{v}" if src == "npm" else f"pypi:{t['name']}=={v}"
        if spec != exp:
            errs.append(f"spec: expected {exp!r}")
        if t["kind"] != "mcp":
            errs.append("kind: npm/pypi targets are MCP servers")
        if pop.get("metric") != f"{src}_weekly_downloads":
            errs.append(f"popularity.metric: {src} targets rank by {src}_weekly_downloads")
    return errs


def validate_targets(doc: object) -> list[str]:
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA_VERSION or not isinstance(doc.get("targets"), list):
        return [f"document: needs schema={SCHEMA_VERSION} and a targets list"]
    errs: list[str] = []
    ids: set[str] = set()
    for i, t in enumerate(doc["targets"]):
        for e in validate_target(t):
            errs.append(f"targets[{i}] {t.get('id') if isinstance(t, dict) else ''}: {e}")
        if isinstance(t, dict) and isinstance(t.get("id"), str):
            if t["id"] in ids:
                errs.append(f"targets[{i}]: duplicate id {t['id']}")
            ids.add(t["id"])
    return errs


def load_targets(path: Path = OUT) -> list[dict]:
    doc = json.loads(path.read_text())
    errs = validate_targets(doc)
    if errs:
        raise ValueError(f"{path}: invalid targets file:\n  " + "\n  ".join(errs[:20]))
    return doc["targets"]


# ---------------------------------------------------------------- main

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--mcp", type=int, default=50)
    ap.add_argument("--skills", type=int, default=30)
    ap.add_argument("--plugins", type=int, default=20)
    ap.add_argument("--refresh", action="store_true", help="re-pull cached API responses")
    ap.add_argument("--out", type=Path, default=OUT)
    a = ap.parse_args(argv)

    def log(s: str) -> None:
        print(s, file=sys.stderr)

    f = Fetcher(refresh=a.refresh)
    mcp, sk_m = collect_mcp(f, a.mcp, log)
    plugins, sk_p = collect_plugins(f, a.plugins, log)
    skills, sk_s = collect_skills(f, a.skills, plugins, log)
    rows: list[dict] = []
    rank = 0
    for group in (mcp, skills, plugins):
        for kr, r in enumerate(group, 1):
            rank += 1
            r["rank"], r["kind_rank"] = rank, kr
            r["id"] = target_id(r)
            rows.append(r)
    doc = {
        "schema": SCHEMA_VERSION,
        "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "counts": {k: sum(r["kind"] == k for r in rows) for k in KINDS},
        "targets": [{k: r[k] for k in sorted(r, key=_key_order)} for r in rows],
        "excluded": sk_m + sk_p + sk_s,
    }
    errs = validate_targets(doc)
    if errs:
        log("\n".join(errs))
        return 1
    a.out.write_text(json.dumps(doc, indent=1, ensure_ascii=False) + "\n")
    log(f"wrote {a.out}: {doc['counts']}")
    return 0


_ORDER = ["id", "rank", "kind", "kind_rank", "name", "source", "version", "commit", "repo", "path", "marketplace",
          "spec", "url", "popularity", "selection"]


def _key_order(k: str) -> int:
    return _ORDER.index(k) if k in _ORDER else len(_ORDER)


if __name__ == "__main__":
    sys.exit(main())
