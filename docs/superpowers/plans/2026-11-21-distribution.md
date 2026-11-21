# Distribution and discoverability plan

**Goal:** people (and LLM tools) searching for "MCP security scanner", "is this MCP server safe", "scan Claude
Code plugin" or "mcp-scan alternative" find Bawwab, and can install it in one step.

Nothing here has been submitted. Each outward step needs the maintainer's go-ahead.

## Done (2026-11-21)

- GitHub repo: English-first description, homepage = https://anasash.github.io/bawwab/, 20 topics.
- README: keyword H1 and one-sentence definition at the top; FAQ with question headings; mcp-scan comparison;
  tests badge corrected.
- Report site (`report/build_site.py`, live on the next report deploy): per-page meta description, canonical,
  OpenGraph; `robots.txt`, `sitemap.xml` and `llms.txt` (https://llmstxt.org).
- `pyproject.toml`: description, keywords, classifiers and project URLs for the PyPI page. `uv build` and
  `twine check` pass. The name `bawwab` is free on PyPI and TestPyPI (checked 2026-11-21).

## 1. Publish to PyPI

Why: `uvx bawwab scan <target>` works with no git URL, and PyPI pages rank well for package names.

1. On pypi.org, add a **pending trusted publisher** for project `bawwab`: owner `anasAsh`, repo `bawwab`,
   workflow `release.yml`, environment `pypi`. No API token is ever stored.
2. Add `.github/workflows/release.yml`, triggered by a `v*` tag:
   - a build job (`contents: read`) that runs the tests (`-m "not timing"`), `uv build`, `twine check`, and uploads
     `dist/` as an artifact;
   - a publish job (`id-token: write` only, `environment: pypi`) that runs `pypa/gh-action-pypi-publish`, pinned by
     SHA like the other workflows.
3. Rehearse on TestPyPI first (a second trusted publisher, environment `testpypi`).
4. Release = bump `.claude-plugin/plugin.json` + `pyproject.toml`, `uv lock`, tag `v0.1.x`, push the tag.
5. README: replace "once it is published to PyPI" with `uvx bawwab scan <target>` / `pipx install bawwab`.

Open question: the wheel ships the Claude Code hooks' Python code but not the plugin tree; that's intended (the
CLI and MCP server), but say so on the PyPI page.

## 2. MCP Registry

Bawwab ships an MCP server (`bawwab-mcp`: scan_mcp_server, scan_skill, scan_plugin, diff_since_trusted,
explain_finding). The official MCP Registry (registry.modelcontextprotocol.io) lists servers from PyPI/npm.

1. After PyPI: add the registry's ownership marker for PyPI packages (an `mcp-name:` line in the README, per the
   registry's current docs) and a `server.json`.
2. Publish with the registry's `mcp-publisher` CLI using GitHub authentication.
3. Verify the requirements against the registry docs at the time; they have changed before.

## 3. Directories and lists to submit to

Check each list's contribution rules first; most want one line, alphabetical, in a given section.

| Where | What | Section |
|---|---|---|
| Anthropic's Claude Code plugin directory (the `anthropic-plugin-directory` marketplace) | the plugin | security / developer tools |
| punkpeye/awesome-mcp-servers | the MCP server | Security |
| wong2/awesome-mcp-servers | the MCP server | Security / tools |
| hesreallyhim/awesome-claude-code | the plugin and skill | Hooks / security |
| Agent Skills lists (e.g. awesome-claude-skills) | the `bawwab` skill | Security |
| Glama, Smithery, mcp.so, PulseMCP | the MCP server listing | Security |
| LLM-security lists (e.g. awesome-llm-security) | the scanner and the report | Tools |

The public scan report is the strongest hook for links: a short post ("we scanned the 302 most popular MCP
servers, plugins and skills: N flagged, 0 confirmed harmful after review, here's what the false alarms look
like") gives lists and newsletters something to cite. Publish it only after the spot-check of the AI-assisted
reviews.

## 4. Keep it findable

- One name everywhere: "Bawwab, a security scanner for MCP servers, Claude Code plugins and Agent Skills".
- Keep the README's first sentence, the repo description, `pyproject` description and `llms.txt` saying the same
  thing.
- A social preview image (repo Settings → Social preview) for link cards.
- Re-run the weekly report: fresh scan dates are a reason for crawlers to return.
