# Method: how the Top 100 were chosen and scanned

This page records every choice behind the list in `report/targets.json` and the results built from
it. The numbers in brackets are constants in `report/collect.py`; change them there and here together.

## The 100

- **50 MCP servers, 30 skills and 20 plugins.** The split is a fixed editorial choice, not derived
  from data: MCP servers are the most installed of the three and the most varied in code.
- Every entry is **pinned**: npm and PyPI packages to the exact latest version at collection time,
  skills and plugins to a 40-character git commit SHA. The scan is of that pin, not of "latest".
- Each entry records the popularity metric, its value, the date it was collected and the API URL it
  came from.
- Collection uses read-only API calls only (npm registry and downloads API, pypistats, the public
  top-pypi-packages dataset, and the GitHub REST API through `gh api` with GET). Nothing is starred,
  forked, installed or run. Responses are cached in `report/.cache/collect/` so a rerun gives the same
  list; `--refresh` pulls fresh data.

## MCP servers (50)

- **Metric: weekly downloads.** npm packages use the npm downloads API (`last-week`); PyPI packages use
  pypistats `recent` (`last_week`). npm and PyPI numbers are ranked together on one scale. Both count
  CI and mirror traffic, so they measure reach, not distinct users.
- **npm candidates** come from the npm search API, four pages of 250 results for each of the queries
  `mcp`, `mcp server`, `model context protocol`, `keywords:mcp-server`, `keywords:mcp` and
  `keywords:modelcontextprotocol`. npm search is relevance-ranked and can miss very popular packages,
  so the Task 10c top-20 MCP names are added to the candidate pool as seeds. Seeds are ranked by
  downloads like everything else; they do not get a place for free.
- **PyPI candidates** are the names containing `mcp` in the top 15,000 PyPI projects by 30-day
  downloads (hugovk/top-pypi-packages), first 60 [PYPI_POOL].
- **What counts as an MCP server.** A package is kept when it is something a user runs as a server in an
  MCP client:
  - its name contains `mcp`, or its description leads with "MCP server" (so a general tool with an
    MCP sub-command, such as a build system or a vector database, is not counted);
  - its description does not mark it as a library, SDK, framework, adapter, client, template,
    generator, evaluation or test tool, or mock;
  - for npm, its latest version ships an executable (`bin`); a package with no executable is a library;
  - it is not a platform-specific binary of another package (for example `@azure/mcp-linux-x64`);
  - it is not on the hand-written exclusion list in `NOT_A_SERVER` (AI clients, SDKs, frameworks,
    installers, inspectors; each with its reason).
  The top 160 accepted npm candidates [NPM_POOL] are checked against the downloads API.
  `targets.json` lists the popular packages that were excluded and why under `excluded`.
- **Official servers always included.** Every server in `modelcontextprotocol/servers/src` is included
  whatever its rank, then the rest of the 50 are filled by downloads.
- **Dedupe** is by registry and name. An npm and a PyPI package with the same name are different
  packages and can both appear.
- Remote-only (hosted URL) servers are out of scope: a static scan needs code to read.

## Skills (30)

- **Metric: GitHub stars of the repository that hosts the skill.** No registry counts skill installs, so
  stars are the best public proxy. Every skill in a repository shares that repository's star count.
- **Anthropic's `anthropics/skills`** is included in full (all published skill folders, templates
  skipped).
- **Other repositories** come from GitHub repository search sorted by stars for `topic:agent-skills`,
  `topic:claude-skills`, `topic:claude-code-skills`, `topic:skills claude`, `claude skills` and
  `agent skills` (in name and description). The 40 most-starred [SKILL_REPO_POOL] are inspected; a
  repository counts if its tree at the pinned commit contains a `SKILL.md`.
- **At most 2 skills per repository** [SKILL_PER_REPO], so one publisher cannot fill the list. Within a
  repository skills in a top-level `skills/` folder come first, then shallower paths, then alphabetical.
- Skipped folders: templates, tests, fixtures, examples, translated copies under `docs/` or `i18n/`, and
  anything under a hidden folder such as `.claude/` or `.agents/` (a repository's own development helpers,
  not skills published for users).
- A skill folder that is part of a selected plugin is not counted again as a skill.
- Each skill is pinned to the repository's default-branch commit at collection time.

## Plugins (20)

- **Metric: GitHub stars of the repository that hosts the plugin's code** (the marketplace entry's
  source repository, which is the marketplace repository itself for relative sources).
- **Marketplaces read:** the official Anthropic directory `anthropics/claude-plugins-official`, plus the
  40 most-starred repositories [PLUGIN_REPO_POOL] found by GitHub search for `topic:claude-code-plugin`,
  `topic:claude-plugins`, `topic:claude-code-plugins`, `claude code plugin marketplace` and
  `claude plugins` that have a `.claude-plugin/marketplace.json`.
- **Pinning:** a marketplace entry that pins a `sha` is scanned at that commit. Otherwise the source
  repository's `ref` (or default branch) is resolved to a commit at collection time. Entries whose source
  cannot be fetched statically (a local command, or a non-GitHub URL) are skipped and listed in `excluded`.
- **At most 2 plugins per hosting repository** [PLUGIN_PER_REPO]. Plugins that share a repository
  (and so a star count) are taken in the marketplace's own listing order; the official directory lists
  alphabetically, so its two in-repository picks are simply the first two names.
- When the same plugin is listed in several marketplaces it is scanned once (dedupe by repository and path);
  the official directory wins the tie so the page can say it is officially listed.

## Scanning

- `report/scan.py` (run through `report/run_scan.sh`) scans each pinned target with Bawwab's static rules
  only: `scan_target(..., judge=False)`. There is **no AI review** and **no sandbox run**.
- npm and PyPI packages are downloaded with Bawwab's own fetchers and read as files; nothing is installed
  or executed. GitHub targets are fetched at the pinned commit with hooks off, no submodules and the
  file/ext git protocols disabled; the `.git` folder is removed and the folder is scanned as local files.
- Trust is switched off (`trusted: []`): official packages get no free pass.
- Each target runs in its own process with a 600-second limit. A timeout, crash or fetch failure is
  recorded as **not verified**, never as clean.
- Results record the Bawwab commit (and whether the working tree had uncommitted changes), the rule set
  version and the scan time of every target.

## Review before publishing

- Every target whose verdict is not clean is checked by a person before the site is published. Each
  counted finding (severity medium or above) gets a status in `report/review.json`:
  `confirmed`, `false-positive` (shown as "Known false alarm") or `expected-behaviour`, with a note.
- `report/needs_review.py` writes the worklist (`report/out/needs-review.md`) with each open finding and
  the local copy of the downloaded files. It never writes reviews.
- `report/build_site.py` refuses to build while any such finding lacks a review entry.
- A review entry names one finding by its key, or every finding of a rule (optionally limited to files
  matching a glob, where `*` stays inside one folder and `**/` spans folders) on that target. Target ids include a hash of the pinned spec, so a re-pin to a new
  version orphans the old review and forces a fresh look.
- Low-severity notes are shown as informational and do not need review: they do not change the verdict.
- "Suspicious" is worded "Not malicious, needs a look": static rules see patterns, not intent.

## Categories

- Each finding is tagged with the OWASP LLM Top 10, OWASP Agentic Top 10, MITRE ATLAS and CWE ids its rule
  maps to, from `bawwab/scan/rules/data/taxonomy.json` (versions and retrieval dates are listed there and on
  the overview). Coverage-note rules are untagged on purpose.

## Limits

- Popularity is a snapshot and can be gamed (download bots, star campaigns). It decides what was scanned,
  never how it scored.
- The "is it a server" test is a heuristic backed by a hand list; borderline packages are listed in
  `excluded` with the reason so the choice can be checked.
- Static rules skip very large files and cannot see code fetched or generated at run time.
- A clean result is not a guarantee, and it only covers the pinned version.
