# Bawwab (بوّاب) — Design

Date: 2026-11-19
Status: approved (merged with the earlier "Bawwab: MCP & Skill Security Scanner" doc)
Owner: Anas Al-Hamdan · open source

## Intent

Coding agents (Claude Code, Cursor, Copilot) install MCP servers, skills
and plugins from npm, PyPI, GitHub and marketplaces with one command. These
run with the agent's permissions: they can read files, call the network and
steer what the agent does. Almost nobody checks them, and skills (Markdown
plus scripts) are scanned by almost no tool.

Bawwab — "gatekeeper" — checks every such install **automatically, before
it happens**. It gives a fast, explainable verdict with evidence, and puts a
human in the loop whenever anything looks off.

## Goals

- Install actions Claude takes are intercepted and scanned before they run.
- Three verdicts with fixed behavior:
  - **clean** (allow) → allow silently
  - **suspicious** (warn) → **block until the user explicitly approves**
  - **malicious** (block) → block
- Two scan depths, the user chooses: **standard** (default: static rules +
  LLM judge) and **deep** (standard + Docker sandbox run).
- Covers MCP servers, skills and plugins.
- **Rug-pull protection:** remember what was trusted, and show exactly what
  changed since (`diff_since_trusted`).
- **Cross-server analysis:** catch one server's descriptions steering
  another server's tools.
- **Explainable:** every finding has an id, and `explain_finding(id)`
  returns a plain-language explanation and a suggested fix.
- **Measured:** a labelled benchmark with precision, recall and
  false-positive rate published in the README and re-run in CI.
- Usable by hand too (CLI + MCP tools) for anything the hook can't see.

## Non-goals (v1)

- Gates for agents other than Claude Code. The scanner stays
  agent-agnostic. In v1, the config readers for the inventory and the
  effect check are written as **agent adapters**, with only the Claude Code
  adapter implemented. *(Decided during build, 2026-11-19.)* v1.1 adds
  watched (not gated) adapters for four more agents: see "v1.1 as built".

## Roadmap: v1.1, multiple agents on one machine (user-approved 2026-11-19)

- **More adapters:** Cursor, Codex CLI, Claude Desktop, and VS Code/Copilot
  MCP config. Gemini CLI and Windsurf come later. Each adapter declares its
  config paths and how to read MCP servers, skills and extensions from
  them.
- **Background watcher:** a user service (systemd user unit on Linux,
  launchd agent on macOS) watches every adapter's paths. It scans new or
  changed items, quarantines anything not clean, and notifies the user with
  a desktop notification plus `bawwab status`. This is detection right after
  install, not blocking before it.
- **Hooks in other agents:** blocking before install in another agent is
  added only where that agent offers a hook mechanism comparable to Claude
  Code's, checked per agent.
- Monitoring tool calls at runtime after installation.
- A hosted service or public verdict registry.

### v1.1 as built (2026-11-21)

**Gated vs watched.** `ADAPTERS` stays Claude Code alone: it is the only
*gated* agent (hooks block before and after an install, and its
quarantine blocks tool calls). The four new adapters are *watched*
(`WATCHED` in `bawwab/agents/__init__.py`). The hook's fingerprint loads
only the gated watch table (`HOOK_TABLES` in `hooks/fingerprint.py`), so
Claude Code's hot path and its effect check are unchanged, and another
agent's item never blocks Claude Code. Each adapter is driven by its
stdlib-only `bawwab/agents/<name>_watch.py` table (config files with the
key path of their servers or hooks and how to parse them, skill dirs,
extension dirs). `bawwab/agents/generic.py` turns the tables into the same
`EffectItem`s the effect check uses. Env, header and auth values are
replaced by hashes in an item's value: a changed secret is still a change,
but no report, hold or notification carries it.

**Config locations** (checked against each agent's docs on 2026-11-21):

| Agent | MCP servers | Other watched items | Source |
|-|-|-|-|
| Codex CLI | `$CODEX_HOME/config.toml` (default `~/.codex/config.toml`) and a trusted project's `.codex/config.toml`: `[mcp_servers.<name>]` (command, args, env, env_vars, cwd / url, http_headers...; `enabled = false` is off and not checked) | hooks: `[hooks]` in config.toml and `hooks.json` (user, project); skills: `~/.agents/skills`, `<repo>/.agents/skills`, legacy `~/.codex/skills` | learn.chatgpt.com/docs (MCP, hooks, build-skills) |
| Cursor | `~/.cursor/mcp.json`, `<project>/.cursor/mcp.json`: `mcpServers` | hooks: `~/.cursor/hooks.json`, `<project>/.cursor/hooks.json` (`hooks` map) | cursor.com/docs/context/mcp, /agent/hooks |
| Claude Desktop | `claude_desktop_config.json` in `~/Library/Application Support/Claude/` (macOS) or `~/.config/Claude/` (Linux, `$XDG_CONFIG_HOME`): `mcpServers` | extensions: `Claude Extensions/<id>/` next to it (path from third-party docs only: unverified) | modelcontextprotocol.io/docs/develop/connect-local-servers |
| VS Code / Copilot | user profile `mcp.json` (`~/.config/Code/User/`, macOS `~/Library/Application Support/Code/User/`, also `Code - Insiders`) and workspace `.vscode/mcp.json`: `servers`; legacy `"mcp": {"servers"}` in user settings.json; Copilot `~/.copilot/mcp-config.json` (`$COPILOT_HOME`): `mcpServers`. JSON with comments is read. | skills: `~/.copilot/skills`, `<workspace>/.github/skills` | code.visualstudio.com/docs/agents/reference/mcp-configuration, /agent-customization/migrate-customizations |

Workspace `.mcp.json` (also read by Copilot) stays the Claude Code
adapter's; `.agents/skills` is the Codex adapter's (Copilot reads it too).
Not watched yet: Codex plugins and marketplaces (`[plugins]`,
`[marketplaces]`; format not documented where checked), Copilot agent hooks
(preview), Cursor rules.

**What "quarantine" means per agent.**

- **Claude Code (gated):** unchanged (§1b): an *active* quarantine row;
  every non-read-only tool call is denied until the user approves or
  rejects. The watcher runs Claude Code's own effect check (`effects.refresh`
  from a project-less scope dir under `~/.bawwab`, i.e. user scope only),
  exactly as the hook would. A change made while Claude Code is closed is
  then quarantined and notified right after it happens, not only at the
  next session's first tool call. An MCP server Claude Code starts at
  launch may still run once: no hook blocks a server start.
- **Codex CLI, Cursor, Claude Desktop, VS Code (watched):** a *hold*: a
  quarantine row with status `held`. It only **records and reports**: the
  item's report and an approval id are stored, a desktop notification is
  shown and `bawwab status` lists it. The agent is **not stopped**: Bawwab
  does not edit the agent's config on its own, and the agent may already
  have started the server before the watcher saw it. `bawwab approve <id>`
  accepts the item (it is not reported again until it changes); `bawwab
  reject <id>` removes it: the server entry from the agent's JSON file or
  plain `[mcp_servers.<name>]` TOML table (backup in `~/.bawwab/backups/`,
  the rewritten TOML checked with `tomllib` to differ only by that entry),
  or a skill/extension dir moved to `~/.bawwab/quarantine/`. Hooks in TOML,
  inline TOML tables and JSON files with comments are left for the user to
  edit, and reject says so.
- **Security levels** (§1c) apply as for Claude Code's config changes:
  high holds anything not clean, medium holds malicious and warns about
  suspicious, low only warns. A warned item is accepted as `warned`,
  reported once (notification plus the queued warning).

**Hooks in other agents, checked per agent** (none is installed by
Bawwab yet):

- **Codex CLI:** comparable. `PreToolUse` can deny (`permissionDecision:
  "deny"`, or exit 2) for shell, `apply_patch` and MCP tools, and there is
  `SessionStart`; new or changed hooks need the user's trust in `/hooks`.
  A Codex gate is the next step.
- **Cursor:** partly. `beforeShellExecution` / `beforeMCPExecution` can
  deny, but a failing hook is fail-open unless `failClosed` is set. Could
  enforce a hold by denying a held server's tools.
- **VS Code / Copilot:** agent hooks are in preview (`preToolUse` can
  deny); not relied on.
- **Claude Desktop:** no hook mechanism: holds stay report-only.

**Watcher.** `bawwab watch` is a foreground loop (default every 2 s). Per
agent it takes the cheap fingerprint (stat data) of the agent's paths, user
scope plus the projects in `--project` or `config.json` `watch.projects`.
A change must hold still for the debounce time (1.5 s) before it is
checked. The semantic digest (only the server and hook keys count, so
Codex rewriting project trust in `config.toml` is noise) then decides
whether the items are evaluated. Evaluation is the effect check's own
(`effects._evaluate`: approved, scanned clean, or baseline). State lives in
`~/.bawwab/watch.json`: per-agent fingerprint and digest, plus a heartbeat
that `bawwab status` shows. A file caught mid-write is read again on the
next pass. A failing agent is logged and notified once, and doesn't stop
the others. The first pass checks every item of the watched agents (there
is no `init --skip` for them). `--once` runs one pass and prints the
status. `bawwab watch --install` writes `~/.config/systemd/user/bawwab-watch.service`
(Linux) or `~/Library/LaunchAgents/dev.bawwab.watch.plist` (macOS) and
enables it. The service runs `python -P -m bawwab.cli watch` in
`~/.bawwab`. `--uninstall` stops and removes it; `--unit-dir` writes
elsewhere and never starts anything (tests). Notifications use
`notify-send` or `osascript` (text passed as argv), best effort, never
fatal.

**Limits.** Detection is after the fact. The watcher is not part of
Bawwab's self-protection: an agent (or Claude) that can run `systemctl
--user stop` can stop it, and `watch --uninstall` is not a protected
action. A changed config is noticed within about interval plus debounce
while the service runs.

## Anti-goals (failure even if it "works")

- **Executing untrusted code outside the sandbox.** Fetching is
  download-only.
- **The judge lowering a verdict.** The LLM can raise risk but never clear
  a static finding, so scanned text can't talk Bawwab into "clean".
- **Failing open.** Errors, timeouts, an unparseable judge reply, or Docker
  missing in deep mode all mean *suspicious*, never allow.
- **Alarm fatigue.** Popular legitimate servers must come back clean; the
  benchmark's false-positive rate is tracked for this.
- **Shipping exploits.** Malicious benchmark samples use canary strings
  only, never working payloads.

## Approaches considered

| | Approach | Trade-off |
|-|----------|-----------|
| A | Static rules only | Fast, offline, free; misses natural-language injection |
| B | Static + LLM judge | Catches semantic injection; small cost, ~10–30 s |
| C | B + sandbox run | Catches runtime-only behavior; needs Docker, slower |

**Chosen: B by default, C as user-selectable deep mode.** Prior art like
Invariant Labs' `mcp-scan` is MCP-only with no install gate, so we build
our own and borrow its rule ideas.

## Architecture

One Python package (`bawwab`), shipped as a **Claude Code plugin**
(`/plugin install bawwab`) and also usable standalone (`uvx bawwab`).
Python ≥ 3.12, managed with `uv`, using the official MCP Python SDK.

```
Claude tool call ──► PreToolUse hook ──► fast detector (stdlib only)
                                             │ install action?
                                             ▼ yes
                       fetch (download only) ──► static rules ──► LLM judge ──► [deep: sandbox]
                                                       │
                                  verdict + rug-pull diff + cross-server check
                                                       │
                          allow  /  block + `bawwab approve <id>`  /  block
```

### 1. Gate (hooks)

- **PreToolUse** (`Bash|Write|Edit|MultiEdit`): a tiny stdlib-only Python
  script decides in well under 100 ms whether the call is an install
  action. Only then does it run the full scanner.
  - clean → **no decision** (Claude Code's normal permission rules apply).
    If the version was pinned, `ask` with the rewritten command. *Revised
    during build: Bawwab never emits `allow`. An `allow` would approve the
    whole tool call, including anything chained after the install.*
  - suspicious → `deny` with the report and an approval id. The user runs
    `! bawwab approve <id>` and Claude retries. Decided instead of the
    hook's `ask` because auto-approve modes can skip an `ask` prompt.
  - malicious → `deny`. Override only with `bawwab approve --force <id>`.
  - Approval ids expire after 1 h and are bound to the exact version +
    content hash.
- Install actions: `claude mcp add|add-json`, `claude plugin install`,
  `plugin marketplace add`, copies/clones/downloads into skill/plugin/
  command/agent dirs, and edits to `.mcp.json`, `~/.claude.json`, or
  settings files touching `mcpServers`, `enabledPlugins` or `hooks`.
- **Protected actions** (always suspicious): hook changes, writes to
  Bawwab's own state/config, Claude running `bawwab approve|reject`,
  unscannable downloads into skill dirs.
- **Version pinning:** unpinned `npx -y pkg` / `uvx pkg` get rewritten to
  the scanned version (`updatedInput`), so an upgrade is a new install.
- **SessionStart** inventory runs in the background. It scans anything new
  or changed (including tools/list of remote servers, to catch rug-pulls
  without a version bump), flags unpinned items, and runs the cross-server
  check. Warnings are shown on the user's next message
  (**UserPromptSubmit**), because SessionStart can't block.
- Hook timeout 600 s. If the scan isn't done by then → suspicious.
- Bash detection is best-effort: no static reading of bash is complete. It
  handles the normal path (scan, pin and approve before the install runs).
  The guarantee comes from the effect check below.

### 1a. First run (added during build, user request 2026-11-19)

On a fresh install, before any baseline exists, Bawwab does **not** start
scanning on its own.

- **SessionStart** counts the installed MCP servers, skills and plugins.
  It then tells Claude, through additionalContext, to ask the user whether
  to run a full scan. The question states what a scan involves: package
  downloads, a Claude review of each item, and a rough time estimate.
- **Yes:** Claude runs `bawwab init --scan` (allowed; scanning only adds
  information). That starts the full inventory scan in the background, and
  the results arrive as the usual deferred warnings.
- **Skip:** the user runs `! bawwab init --skip`. The current state becomes
  the accepted baseline, marked "trusted without scan", and only later
  changes are checked. `init --skip` is a protected action, so Claude can't
  run it.
- **No answer:** the question is asked again next session until it's
  answered. After init, `bawwab scan --all` can run a full scan at any time.
- **Before init:** the effect check still runs, but it treats the
  pre-install state as the provisional baseline and only flags changes made
  after install.
- **Lost state is not a fresh install** (controller rulings R37, R38).
  bawwab's state and every install marker are missing, and both of these
  hold:
  - Claude Code's `installed_plugins.json` (under `$CLAUDE_CONFIG_DIR` or
    `~/.claude`) has a `bawwab@*` entry installed more than 10 minutes ago;
  - a Claude Code session other than the current one *started* after that
    install: its transcript under `projects/` begins later. bawwab's
    SessionStart ran in that session, so bawwab's state existed.

  Then the state was lost. Tool calls fail closed (`effects.error`),
  SessionStart tells the user to run `! bawwab init --scan` (nothing trusted
  without a scan), and `init --skip` is refused.
- **CLI and hooks read the same files.** Both rules work from
  `installed_plugins.json` and the transcripts, not from the plugin
  environment (`CLAUDE_PLUGIN_ROOT`), so the user's `!` shell gets the same
  answer as the hooks.
  - The hook passes the current session id (from its input) to its bawwab
    children.
  - A CLI run from a `!` shell has no session id, so it treats the most
    recently written transcript as the current session.
- **`init --skip` is refused while any `effects.error` is open,** whether
  from lost state, replaced state or a failed check. The check reads
  bawwab's database, so it doesn't depend on the environment. The user
  first runs `! bawwab init --scan` or `! bawwab effects --retry`.
- **Late first session:** if the user installs the plugin and no other
  session has started since, the first session gets the normal first-run
  question, however late it is. The session that ran `/plugin install`
  started before the install, so it doesn't count, even though it keeps
  writing its transcript.
- **Residuals.** In each of these cases, missing state after a wipe gets
  the first-run prompt, not "lost". `init --scan` still scans everything,
  and the gate protects every one-command form of the wipe it knows.
  - A non-plugin install (no `bawwab@*` entry) has no external anchor.
  - An attacker also rewrites or removes `installed_plugins.json` (or
    bawwab's entry), or rewrites, backdates or deletes the transcripts of
    every session since the install. Backdating the mtimes (`touch -d`) or
    editing a transcript's head (`sessionId`, `timestamp`) is anchor
    tampering just as deletion is, and each is a single command that is not
    Protected.
  - The wipe happens inside the first session after install. No other
    session exists yet, so for the rest of that session the effect check is
    off (no baseline), and `init --skip` from that session is accepted as a
    first-run skip, whose result then stands: that gives permanent trust.
    If no `init` ran in that session, the next session reports the state as
    lost.
  - A resumed or continued conversation (`claude --continue`, `--resume`)
    that began before the install never counts as a session since the
    install, because sessions are counted by their first event (R39). If
    Claude Code keeps the session id or copies the transcript head on
    resume, a wipe in such a conversation reads as a fresh install. Not
    verified.
  - A reinstall resets `installedAt`. This is plausible, not verified; it
    opens a 10-minute window.
  - **First-run setup markers (fix round 2, I4).** The first `uv` sync runs
    detached and writes `bootstrap-complete` in bawwab's plugin data dir;
    bawwab writes `state-created` there when it first writes its state.
    Lost state is reported when `state-created` exists, or when the R39
    transcript rule holds and `bootstrap-complete` exists, so a slow first
    setup is never a false alarm. A wipe that also removes both data-dir
    markers (and the transcripts' evidence) reads as a fresh install.
  - **Same-OS-user boundary (fix round 5, R55).** Bawwab and Claude's tool
    shell run as the same OS user, so Bawwab defends against an agent that
    has been steered into a protected action by ordinary means, not against
    one that deliberately reverse-engineers Bawwab's own state. The gate
    refuses `approve`, `reject`, `init --skip` and `effects --retry` by
    bawwab's name, by what a command word resolves to (a renamed symlink or
    copy of `bin/bawwab` or of a venv console script, by realpath or by
    content), on any command word that isn't a known system program when its
    argv reads as one of those subcommands, and through `python -m bawwab…` /
    `python -c` code that imports bawwab. Copying or linking a bawwab
    executable (`ln`, `cp`, `install`, `mv`, `rsync`, `cat … >`) is
    protected; so are shell writes to bawwab's home, its XDG state dir, its
    plugin data dir (`plugins/data/bawwab*`) and its venv.
  - **What the approval guarantee covers (R56, narrowed by R57).** The gate
    refuses Claude-run calls of bawwab's user-only commands (`approve`,
    `reject`, `init --skip`, `effects --retry`) in these forms, and only
    these:
    - direct and wrapper invocations it recognises (R55 above);
    - scripts it reads: a file named on the command line and run by
      `sh|bash|dash|zsh|ksh <file>`, `sh < file`, `cat file | sh`, `. <file>`,
      `source <file>`, a path command word (`./file`), or `make` (its
      makefiles and the literal, non-glob includes that exist, relative to
      make's directory; includes computed at make time or matched by a glob
      are skipped, and `-I` include paths are not searched). The gate reads the file as it is at check time (at
      most 1 MB; never run), fills in the call's positional arguments, and
      follows nested script calls three files deep. A file run by
      `python|node|perl|ruby… <file>` is checked by the write rule's content
      rule, so only literal single-line calls in plain strings or argv lists
      in that file are caught;
    - a git shell alias holding a protected call, set on the command line:
      `git -c alias.X='!…'` and `git config [--global|--local|-f F] alias.X
      '!…'` (option values such as `-f`/`--type`/`--blob`/`--comment` are
      skipped);
    - writing a protected bawwab call in a form it recognises (a bawwab
      command word at a line start, after a shell separator, or at the start
      of a quoted command string or argv list) with Write/Edit/MultiEdit,
      `tee`, a heredoc or a redirect. An edit is judged on the calls it
      adds.

    Every hit is a deny. Which kind is best-effort, not exact:
    - **Usually a plain deny** (no pending approval, never suggests `bawwab
      approve`; "the user must run it themselves", or for a write "the user
      must run that command themselves; Claude shouldn't write it into
      files"): a protected call found inside a file the gate reads, in a
      command-line git alias, or in a write; and an R55 hit whose only match is
      the text a redirect, `tee` or heredoc writes (the command is checked
      again with that text blanked, which only works for the quoted forms it
      can match).
    - **Usually an approvable block** (pending approval, as before): direct
      and wrapper invocations; install-gate blocks; and a file the gate could
      not check (unreadable, over 1 MB, nested more than three files deep).
    - Some write and alias forms (an unquoted or escaped `echo … > f`,
      `tee f <<< …`, `echo … | tee f`, aliases R55 also matches) still get an
      approvable block, and a few direct calls can come out plain.
  - **Not covered (R57).** Once Claude can run a program it writes, static
    inspection can't keep the approve command from the same OS user. These
    routes are not refused, and an agent instructed to bypass bawwab (for
    example by prompt injection) could approve through them:
    - interpreter imports (a script that imports a module that calls bawwab);
    - git hooks and other config-borne commands (`core.hooksPath`,
      `core.pager`, …), beyond the `!` aliases above;
    - npm, yarn, pnpm, just and tox scripts, and other build tools;
    - process substitution, `$(cat f)` as a script or `eval` text, here-strings
      of a file, `BASH_ENV`/`ENV`;
    - a script changed earlier in the same command, before it runs (a
      `git checkout`, `git pull`, `cp`, `curl -o` or archive extract): the gate
      checks the file as it is when it reads it;
    - copies, moves, `install` and `rsync` of scripts are not checked (the
      pre-filter doesn't route them); a copied script is still read when a
      covered runner runs it;
    - Python/Node calls the content rule doesn't parse (an argv list split
      over lines, JS template literals and other interpolated strings), and
      imports;
    - git aliases written into a git config file (an `[alias]` section) or set
      through `GIT_CONFIG_COUNT`/`GIT_CONFIG_KEY_n`/`GIT_CONFIG_VALUE_n`;
    - make includes computed at make time (`-include $(OBJS:.o=.d)`,
      `include $(wildcard *.mk)`) or matched by a glob (`include ev*.mk`),
      `make -I` include paths, `MAKEFILES=`, `make --eval`/`-E`, and
      `SHELL :=` in a makefile;
    - compiled programs, interpreters reading code from the network,
      runtime-computed paths, scripts run by a bare name on PATH;
    - write forms the rule doesn't parse (an argv list split over lines, a
      template literal, inline backticks, obfuscation);
    - any program Claude writes and then runs.

    A same-user agent can also forge bawwab's state directly (code that opens
    its SQLite store without naming it, the data-dir markers). User-presence
    approval through a channel the model can't drive (Claude Code's own
    permission prompt, or a model-blind channel) is planned for v1.1.
  - The CLI does not
    refuse under Claude's tool shell: Claude Code sets `CLAUDECODE=1` in its
    own process, so the user's `!` shell is not shown to lack it (not
    verified either way; for the smoke test).

### 1b. Effect check (added during build, user-approved 2026-11-19)

The check watches what actually changed, not what the command looked like.

- **Watched set:** `~/.claude.json` (`mcpServers`, `projects.*.mcpServers`),
  user and project `settings*.json` (`enabledPlugins`, `hooks`,
  marketplaces, keys that execute code), project `.mcp.json`,
  `~/.claude/{skills,commands,agents}`, project
  `.claude/{skills,commands,agents}`, and `installed_plugins.json` /
  `known_marketplaces.json`.
- **Fingerprint:** a cheap, stdlib-only fingerprint (stat data, plus one
  level of directory listing) on every tool call, in a few ms.
- **When the fingerprint changes:** compare the *semantic* state (server
  entries, enabled plugins, hook entries, skill directories and their
  content hash) with the last accepted state. Noise such as
  `numStartups` is ignored.
- **New or changed items:** each one is scanned. An item that was already
  scanned clean or approved (including through the gate) is accepted
  silently. Anything else is **quarantined**.
- **While anything is quarantined,** every tool call except read-only ones
  (Read, Grep, Glob, TodoWrite) is denied with the report and an
  approval id. The user runs `! bawwab approve <id>`, or
  `! bawwab reject <id>`, which removes the entry and moves a skill
  directory into `~/.bawwab/quarantine/`.
- **When it runs:** after every Bash/Write/Edit call (PostToolUse), and
  before every tool call (PreToolUse, all tools). The PreToolUse run also
  catches changes made outside Claude during the session.
- **Limit:** the effect check runs after the command, so code an install
  executes right away (for example a postinstall run through `npx`) may
  already have run. The parser-based gate stays the first line of
  defence for that.
- **Churn is not content** (2026-11-20). Claude Code writes
  `<plugin root>/.in_use/<pid>` for each running process and removes it
  on exit. The fingerprint, the content hash and the scanned file list skip
  a file only when it is exactly that shape: `{"pid":N,"procStart":"M"}`
  with `N` equal to its name, directly under the item root. Anything else
  under `.in_use/` counts. Without this, every new session re-quarantined
  installed plugins as "files changed since trusted".

### 1c. Security levels (user request 2026-11-20)

The user picks how Bawwab treats a verdict that isn't clean. The level is
`"level"` in `~/.bawwab/config.json`; until one is chosen it is **high**.

| | low | medium | high (default) |
|-|-----|--------|----------------|
| install, malicious | warn | block | block |
| install, suspicious (incl. failed/timed-out scans) | warn | warn | block |
| unscanned config change | warn | quarantine if malicious | quarantine if not clean |

- **Warn** means: no allow or deny of Bawwab's own (Claude Code's normal
  permissions decide), a `systemMessage` to the user, the same text to
  Claude, and a queued warning. A warned config change is accepted with
  status `warned`, so it is reported once.
- **Self-protection blocks at every level** (user decision): protected
  actions (Claude running `approve`/`reject`/`init --skip`, writes to
  Bawwab's state or config, hook changes) and a failed effect check. A
  level the agent could switch off would mean nothing.
- **Only the user lowers the level** (user decision). `bawwab level` shows
  it and `bawwab level high` is open to Claude; `level medium`/`level low`
  are protected actions. A project's `.claude/bawwab.json` may only raise it.
- **First run:** SessionStart shows the user a welcome (`systemMessage`)
  and tells Claude to ask, in one question prompt, for the level and
  whether to scan now. Later sessions ask for the level until one is set.

### 1d. Block message (user request 2026-11-20)

- The quarantine block is a **table**, one row per item (ID, item name,
  verdict, why in plain words from the rule catalog), with the commands
  once: `approve <ids…>`, `approve --force <ids…>` for malicious ones,
  `reject <ID>`, and `effects` for the evidence. `bawwab effects` prints
  the full findings, each command with the item's name as a `# comment`.
- `approve`/`reject` take several ids and print each item's name.
- Claude is told to show the table, ask about each item with
  AskUserQuestion (allowed during a quarantine: it changes nothing), and
  give back the exact command lines. The user still runs them: having a
  hook apply the answer was rejected because nothing proves an answer came
  from the user and not from another hook or the model.
- `/bawwab-run` (plugin command) shows what is on hold, helps decide, then
  offers a full scan. The `bawwab` skill is no longer in the slash menu.

### 1e. Known false positive: editing Bawwab with Bawwab on (user decision 2026-11-21: keep)

In Bawwab's own checkout, a `python3 - <<'EOF'` script that rewrites
Bawwab's source is refused twice:
- `from bawwab` inside a Python string matches the interpreter rule
  (`_BAWWAB_CODE`): the rule can't tell code from data;
- the heredoc fail-safe reads the body as shell, `Path("bawwab/effects.py")`
  splits into the command word `bawwab/effects.py`, and that file resolves
  as a bawwab executable (it imports bawwab).

Every fix found would stop refusing something refused today (bawwab run
through `importlib`/`exec`/`runpy` strings, or a renamed bawwab in a
misread heredoc), so the gate stays as is.
`tests/test_heredoc_python_fp.py` holds the false positive as strict
xfails, plus the true positives any future fix must keep refusing.
Workaround: edit Bawwab's source with Edit/Write, and disable the plugin
while developing it (writing approve/reject commands into files is refused
by design, R56).

### 2. Fetch (download only)

npm and PyPI via registry HTTP APIs + safe archive extraction; git via
`--depth 1` clone with hooks and submodules disabled; local paths in place;
remote MCP servers via `initialize` + list calls only; Docker images are
metadata-only unless deep. Exact versions are resolved for the cache key.

### 3. Static rules — can't be talked out of a finding

AST-based for Python (stdlib `ast`) and JS/TS (tree-sitter), plus
Semgrep-style patterns and manifest parsers. Covers:

- install-time execution (`postinstall`, `setup.py`), `curl | sh`
- remote code / eval of fetched or decoded content, obfuscation, base64 blobs
- credential access, exfiltration hosts, credential read + network in one file
- prompt injection in model-facing text, hidden Unicode, HTML comments
- tool shadowing, risky plugin hooks, bundled MCP servers (scanned recursively)
- identity: typosquats, very new packages, repo mismatch, unpinned deps

### 4. LLM judge — reads for intent

Reads tool descriptions and skill instructions for intent ("does this try
to steer the agent or hide something from the user?"), plus code around
static findings. Scanned content is passed strictly as quoted data. Fixed
JSON output schema; anything else is a failed scan (fail closed). No tools,
network or secrets are available to the judge. Backend: `claude -p`
(user's existing auth, all tools disabled) or the Anthropic API.

### 4a. Reviewer — a recommendation, never a verdict (user request 2026-11-21)

After the verdict is computed, a non-clean result (standard or deep mode) gets a **recommendation**: what
a careful reviewer would advise after reading the flagged code. It is what the maintainer's AI-assisted
report reviews did, built in. Config `"review": {"enabled": true}` (default on).

- **Input.** The verdict; every counted finding (rule, severity, file:line, evidence); about 40 lines of
  code around each; the target's file list and manifest. Scanned text is framed as data, as for the judge.
- **Looking deeper, bounded.** The reviewer may answer `{"read": [{"path", "start", "end"}]}` to see more of
  the downloaded target: paths inside the fetched root only (normalised, no symlinks), up to 8 reads and
  about 60 KB in total, over at most 3 rounds. A plain JSON exchange, so both judge backends work. Then it
  answers with the recommendation.
- **Output.** One of `keep` / `keep-with-care` / `dont-install` / `cant-tell`, a summary (≤ 300 chars),
  and per counted finding: an assessment (`false-alarm` / `expected` / `real`), a reason, and a quoted
  line with its file and line.
- **Checked by Bawwab; any failure is `cant-tell`.** Valid JSON; every counted finding covered; every quote
  (≥ 20 chars, or a whole source line ≥ 6) appears verbatim in the cited file within 5 lines of the cited
  line; any `real` assessment rules out `keep`; a timeout, a garbled answer or a failed check gives
  `cant-tell` with the reason.
- **Each quote is bound to its finding.** The cited file must be the finding's own (its path normalised as
  finding paths are, or its tool-description label exactly), and when the finding has a line the cited line
  must be within 5 lines of it (a finding with only a file may cite any line of it). A quote from a decoy
  file or an unrelated line is refused. Other code the reviewer read may be named in `why`, never used as
  the quote. A finding with no citable location (no file: identity, `plugin.unresolved-server`, judge and
  sandbox notes; or a file or label that can't be read) can't be grounded: its quote is still checked
  wherever it is from, but such a finding caps `keep` / `keep-with-care` to `cant-tell`, whatever its
  severity (counted findings are MED or above anyway).
- **Asymmetric (user decision).** `keep` and `keep-with-care` are allowed only for SUSPICIOUS. For MALICIOUS
  (a critical static finding) the result can only be `dont-install` or `cant-tell` ("read these lines"):
  the strongest signals can't be talked down.
- **Never changes anything else.** Verdict, findings, blocking, the security level and approval are as
  before; approve stays a user-only `!` command. The recommendation is stored on the report
  (`ScanReport.advice`) and cached with it, and shown labelled **"Claude's recommendation (advice, not a
  verdict)"**: in the gate's block, as a column of the quarantine table, in `bawwab scan` and the MCP tools
  (inside the untrusted frame), and in the question the skill has Claude ask.
- **Limit.** The quote check stops fabricated evidence, not a convincing misreading of real code: a
  well-built package could still win `keep` on a SUSPICIOUS item. The asymmetric rule bounds the damage;
  the threat model records the residual, and the red-team set adds attacks aimed at the reviewer, with the
  rate of `keep` on malicious samples rated only SUSPICIOUS reported in `eval/RESULTS.md`.

### 5. Deep mode — sandbox run

Docker, non-root, read-only target mount, resource limits, no network
except a logging proxy that refuses everything, and a decoy home with
canary credentials. Install, start, list tools, call each once. Flags
canary reads, canary leaks, network attempts, shell spawns, and writes
outside the workdir.

**As built (2026-11-21; unit-tested, not yet run on a live Docker daemon).**
Code in `bawwab/sandbox/`, image in `bawwab/sandbox/image/`.

- **Runner interface:** `SandboxRunner.run(fetched, timeout_s) -> (findings,
  tools)`. `DockerRunner` drives the `docker` CLI through subprocess (one
  injectable exec function, so tests pin every argv). `FakeRunner` replays a
  recorded `Observation`. Both feed the same `observe.analyze`.
- **Fail closed:** Docker is checked first on every deep run. No binary, an
  unreachable daemon, a missing or mismatched image, or docker refusing a
  command raises `SandboxUnavailable` → `sandbox.unavailable` (MED, not
  cached). `scan_target` uses `DockerRunner` whenever mode is deep and no
  runner is passed.
- **One run:** an `--internal` network; a trap container (`proxy.py`) that
  logs and refuses HTTP, `CONNECT` and DNS; the sandbox container
  (`harness.py` as PID 1) with the target mounted read-only at `/target`.
  Both: `--read-only`, non-root, `--cap-drop ALL`, `no-new-privileges`, pid,
  memory and CPU limits. Sandbox tmpfs: `/work` (exec), `/home/sandbox` and
  `/tmp` (noexec). All three objects are removed in a `finally`.
- **Image:** built by `bawwab sandbox build` from the package's own
  Dockerfile (base pinned by digest); its id is recorded in
  `~/.bawwab/sandbox-image.json` and is what the runner runs. An env override
  of the image or docker binary was left out on purpose: whoever picks the
  image picks the verdict.
- **Decoy home:** canaries random per run, in real credential shapes, never
  working credentials: `~/.ssh/id_ed25519`, `~/.aws/credentials`,
  `~/.config/gh/hosts.yml`, `~/.git-credentials`, `~/.npmrc`,
  `~/.claude.json`, `~/.config/openai/key`, `~/.env`, plus `GITHUB_TOKEN`,
  `AWS_*`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `NPM_TOKEN`. A canary sent
  to its own service (a GitHub token to api.github.com) is ordinary use, not
  a leak. Matching covers plain, reversed, hex and base64 forms.
- **Harness:** spec on stdin (nonce, plan, decoys, env, budgets), then
  `PR_SET_DUMPABLE 0`. Installs offline (`npm install --offline`, `pip
  install --no-index --no-build-isolation`), so the package manager makes no
  network calls of its own and any attempt is the package's. Starts the
  server (plan from `package.json` bin/main, `[project.scripts]`, a wheel's
  console script, or a plugin's `node|python <file>` command), runs
  `initialize`, `tools/list` (and prompts/resources when advertised), and
  calls each tool once (≤ 64) with placeholder arguments built from the
  schema. Everything runs under `strace -f -y`; a tracer that dies while its
  processes live on is "monitor lost". The writable trees are diffed at the
  end and changed files are searched for canaries.
- **Findings** (source `sandbox`): `canary-leak` (network: CRITICAL; tool
  result or copied file: HIGH; output: MED), `canary-read` (HIGH),
  `network-attempt` (install/start: MED, tool call: LOW, exfil host: HIGH),
  `shell-spawn` (install/start: MED, tool call: LOW), `write-outside`
  (profiles, `~/.ssh`, agent config, system paths: HIGH; other home: MED;
  `/tmp`, caches: LOW), `incomplete` (MED, also for a server it can't work
  out how to start; LOW when only the tool-call cap was hit), `no-entrypoint`
  (LOW: skills, plugins without their own server, remote servers, Docker
  images). Runtime tool text goes through the text
  rules and the judge, labelled `[sandbox]` in the snapshot.
- **Known limits:** offline means unbundled dependencies fail to install
  (`incomplete`, suspicious): most npm MCP servers today. HTTPS is refused
  at `CONNECT`, so only the host is seen. Sandbox-aware code passes. See
  threat model §5.9.

### 6. Trust store, rug-pull, cross-server

SQLite at `~/.bawwab/bawwab.db`. It holds scan results, findings (with
ids), pending approvals, approvals and rejections, the audit log and
**trusted snapshots**. A snapshot holds the file hashes, model-facing text
and tool list of every clean or approved scan.

- **Rug-pull:** when a previously trusted name comes back with different
  content, Bawwab rescans and attaches a diff. Changed model-facing text
  (descriptions, SKILL.md) is always at least *suspicious*.
  `diff_since_trusted(name)` shows that diff on demand.
- **Cross-server:** across all installed servers' tool names and
  descriptions, flag a description in server A that refers to or redirects
  a tool of server B.

### 7. Interfaces

- **CLI:** `bawwab scan <target> [--deep] [--json]`,
  `approve <id> [--force]`, `reject <id>`, `explain <finding-id>`,
  `diff <name>`, plus the hook entry points.
- **MCP tools:** `scan_mcp_server(target)`, `scan_skill(path)`,
  `scan_plugin(target)`, `diff_since_trusted(name)`,
  `explain_finding(id)`. No approval tools: approving is human-only.
- **Skill:** teaches Claude to show reports verbatim, never run
  `bawwab approve`, never route around a block, and to offer the user
  the approve or deep-scan commands.

### 8. Evaluation & benchmark

- A labelled corpus of safe and malicious MCP servers and skills (~60
  samples to start), with categories matching the rule families.
  Malicious samples print a canary string; they contain no working
  exploits or real payloads.
- The safe set includes popular legitimate servers, at pinned versions.
- It includes adversarial samples that target the judge itself.
- Reports per category: precision and recall, plus the false-positive
  rate on the safe set. Published in the README and re-run in CI
  (static-only without an API key, full when the secret is present).

## Config

`~/.bawwab/config.json`; project override `.claude/bawwab.json`, which can
only **tighten**.

```json
{
  "mode": "standard",
  "llm": { "backend": "claude-cli", "model": "claude-sonnet-5-5" },
  "thresholds": { "malicious": "critical", "suspicious": "med" },
  "trusted": ["@modelcontextprotocol/*"]
}
```

`trusted` names still get scanned, and identity checks always apply.
Low/med findings on trusted names are noted but don't block.

## Constraints

- No untrusted code outside Docker, ever.
- A non-install tool call adds well under 100 ms.
- Linux and macOS first. Requires `python3` ≥ 3.12 and `uv`.

## Left to the builder

Exact rule patterns and weights, judge prompt wording, sandbox image
details, Bash parsing approach, corpus contents beyond the categories
above.
