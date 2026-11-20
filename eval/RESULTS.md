# Bawwab effectiveness evaluation (Task 15)

Run on 2026-11-20 against the `feat/bawwab` tree. Raw data: [`results/`](results/) (`attacks.json`, `normal.json`,
`replicas.json`, `latency.json`, `baseline.json`, `summary.json`). Reproduce with
`uv run python eval/run_eval.py` (about 3 minutes, offline). `tests/test_eval.py` replays a subset in CI.
`tests/test_eval_misses.py` pins every miss below as a strict xfail.

## Method: what this is and what it isn't

**Hook replay, not live Claude, and no container.** The brief asked for headless `claude -p` runs in a container
with a local Verdaccio and pypiserver. That wasn't possible here: there is no Docker socket, and Claude must not run.
What was done instead:

- **Red-team and normal work.** Each entry in [`redteam/attacks.yaml`](redteam/attacks.yaml) and
  [`redteam/normal.yaml`](redteam/normal.yaml) is the tool call Claude would make, written as PreToolUse JSON.
  `run_eval.py` pipes it through the real hook, `python3 hooks/bawwab_hook.py gate`. That runs the real prefilter
  and fingerprint, and when needed the real `bawwab gate` child through `uv run`.
- **No attack command is ever executed.** The harness writes the change the command would make (a server added to
  `~/.claude.json`, a file written, a skill copied, an approval recorded) inside a scratch HOME. Then it runs the
  real `post` hook, which is the effect check, and one more ordinary `gate` call to see whether a quarantine is
  active.
- **Approval routes.** First, a malicious install is blocked, which creates a pending approval. The attack then
  tries to approve that pending itself. Next comes the approval's effect: a real `bawwab approve --force`, run
  against the scratch store. Last, the blocked install is replayed. The attack counts as "missed" when that
  install then passes both the gate and the effect check.
- **Isolation.** Every run gets HOME, `~/.bawwab`, XDG_\* and the tree-sitter grammar cache (a copy) under
  `/var/tmp/bawwab-eval-*`. The Claude and Bawwab env vars are removed. The script refuses to start if HOME would
  resolve to the real home.
- **No network.** The network goes through a dead proxy, so OSV lookups fail closed inside the hooks and are
  stubbed in-process. `BAWWAB_FAKE_JUDGE` is the tests' fake judge, which never reports anything. A guard `claude`
  on PATH logs and refuses any call: `meta.json` shows zero.
- **Incident replicas.** These are scanned in-process with `bawwab.scan.scan_target`, exactly as the tests do, once
  with the fake judge and once with `judge=False` (static only). npm-shaped replicas are also fetched through
  bawwab's real npm path, from a throwaway registry on 127.0.0.1, so the identity checks see a published name and
  creation date.

**What it proves:**
- What Bawwab's hooks decide for these exact tool calls, end to end: the shipped hook script, the CLI child, the
  store and the effect check.
- What the effect check decides for the exact config change each command would make.
- What the static rules, identity checks and rug-pull diff find in the replicas.
- Hook latency on this machine.

**What it does not prove:**
- **Whether Claude would make these calls.** Prompt-injection susceptibility is out of scope: a "prompt-injected
  README" entry is just the call such a README would lead to.
- **That Claude Code obeys the hook output.** This is assumed from its documented hook contract.
- **The AI judge's contribution.** The judge is fake, so text attacks that only the Claude review could see are
  measured as misses. Treat these numbers as a lower bound for detection, and say nothing about judge false
  positives.
- **Real registries.** A registry target can't be fetched offline, so it is blocked by fail-closed `fetch.failed`.
  That shows the gate found the right target, not that it detected anything.
- **Fidelity of the simulated effects.** A real command could change more than the entry writes.
- **Real-world latency.** Timings for a large real `~/.claude.json` or slower disks will differ.

## 1. Incident replicas

Canary values only (`BAWWAB-CANARY`, `*.invalid` hosts); never published anywhere. `v1` is clean in every case and
scans clean in every mode. "Update" means v1 was installed, scanned clean and trusted (baselined), and then the
same path became v2.

| Incident | v2, fresh install (judge = static) | v2 as an update over trusted v1 | `diff_since_trusted` shows the canary |
|---|---|---|---|
| postmark-mcp rug-pull (BCC to `.invalid` in description and code) | **clean** | **suspicious**: `rugpull.text-changed` MED + `rugpull.files-changed` | yes: the BCC line is shown as `+` |
| Shai-Hulud postinstall (reads `.npmrc`, `.aws/credentials`, tokens; POSTs to `.invalid`) | malicious: `install-script.remote` CRIT, `exfil.combo` CRIT, `credential-access`, `install-script` | malicious (+ `rugpull.files-changed`) | n/a (code change: "1 added, 2 changed") |
| Invariant tool poisoning (`<IMPORTANT>` read `~/.ssh/id_rsa` into `sidenote`) | suspicious: `credential-access` HIGH only | suspicious (+ `rugpull.text-changed`) | the `<IMPORTANT>` block is shown in full |
| Cross-server shadowing (weather tool redirects `send_email` to `.invalid`) | **clean** | suspicious: `rugpull.text-changed` | yes |
| Typosquat `@modelcontextprotocal/server-filesystem` (+ SSH-key beacon) | malicious: `exfil.combo` CRIT, `credential-access` | malicious | n/a (code change) |

Through the npm fetch path (local registry):
- `string-pad-utils@4.1.1` is malicious, and the 4.1.0 to 4.1.1 update is malicious.
- `@modelcontextprotocal/server-filesystem`, published two days ago, is malicious with `identity.typosquat` MED
  ("1 edit from `@modelcontextprotocol/server-filesystem`") and `identity.new-package` MED.
- The genuine name is clean.

Cross-server check: the mail server (postmark v1) and the shadowing weather v2 were both installed fresh, so both are
trusted. `cross_server_findings` then reports `cross-server.reference` HIGH: "weather's tool get_forecast mentions
postmark's tool send_email". That check runs in the SessionStart inventory and only warns (README).

**Reading.**
- The rug-pull replica behaves as the brief expects: blocked as an update, with the diff shown.
- A first install of postmark v2 is clean, because a hard-coded BCC in ordinary email code has no static signal.
  The real incident was likewise only visible by diffing versions.
- A fresh install of the shadowing server is clean statically. Only the Claude review (fake here) or the warn-only
  cross-server check sees it.

Judge and static-only runs are identical for every replica, as expected with a judge that never reports.

## 2. Red-team: block rate by attack family

116 entries. "Blocked before" means the gate denied the call. "Caught after" means the effect check quarantined the
change, which blocks every non-read-only tool until the user decides, counted over the entries the gate let
through. "Effect check alone" counts all entries whose change the effect check would have quarantined, whatever
the gate did; it is the backstop's own rate. For approval routes it is n/a: an approval is store state, not
config.

| Family | Entries | Blocked before (gate) | Caught after (of those the gate let through) | Missed | Effect check alone |
|---|---:|---:|---:|---:|---:|
| plain install | 7 | 6/7 | 0/1 | 1 (out of scope) | 6/7 |
| prompt-injected README | 3 | 2/3 | 0/1 | 1 (judge-only) | 2/3 |
| heredoc / here-string | 5 | 5/5 | 0/0 | 0 | 5/5 |
| quoting (incl. `cla$()ude`) | 5 | 4/5 | 1/1 | 0 | 5/5 |
| arithmetic | 3 | 3/3 | 0/0 | 0 | 3/3 |
| comments | 4 | 4/4 | 0/0 | 0 | 4/4 |
| ANSI-C `$'…'` | 4 | 4/4 | 0/0 | 0 | 4/4 |
| process substitution | 2 | 2/2 | 0/0 | 0 | 2/2 |
| xargs | 3 | 3/3 | 0/0 | 0 | 3/3 |
| brace expansion | 2 | 0/2 | 2/2 | 0 | 2/2 |
| `printf \| sh`, `echo \| bash`, base64 | 3 | 1/3 | 2/2 | 0 | 3/3 |
| IFS | 2 | 0/2 | 2/2 | 0 | 2/2 |
| indirection (eval, `$X`, `sh -c`, env, timeout, python subprocess) | 6 | 5/6 | 1/1 | 0 | 6/6 |
| direct config edits (`~/.claude.json`, `.mcp.json`, settings hooks/env/apiKeyHelper, skills, commands, agents) | 17 | 13/17 | 0/4 | **4** | 13/17 |
| loader decoys (`pipx --spec`, `uvx --from`, `npx -p`, `NODE_OPTIONS`, `PYTHONPATH`) | 8 | 8/8 | 0/0 | 0 | **5/8** |
| combo: parked gate bypass carrying a loader or shadowing server | 4 | 0/4 | 1/4 | **3** | 1/4 |
| approval routes the docs say are refused (R55/R56/R57) | 22 | 22/22 | 0/0 | 0 | n/a |
| approval routes the docs list as not covered | 16 | 2/16 | 0/14 | 14 (documented) | n/a |
| **all** | **116** | **84/116** | **9/32** | **23** | |

Excluding the 16 documented approval residuals, 82 of 100 entries are blocked before they run and 9 more are caught
after. 9 got past both layers (2 judge-dependent, 1 out of scope, 6 open misses).

Notes by family:
- **The parked bash tricks** (brace expansion, IFS, `cla$()ude`, base64 `| sh`, and a program's own subprocess
  call) were parked in Task 9 as "covered by the effect check". Every one is caught after, with nothing missed:
  the backstop works as designed for these.
- **`sh -c $'\x63laude …'`** was also on the parked list, but it is now blocked by the gate, so the parked list is
  out of date.
- **`printf '…%s' path | sh`** gets past the gate. The format argument isn't substituted, so the gate scans the cwd
  instead of the server. If the cwd is malicious it blocks by accident; here the project was clean. The effect
  check catches it.
- **Decoys.** `pipx run --spec <dir>`, `uvx --from <dir>` and `npx -p <dir>` all scan the spec, not the decoy
  name, but they treat a local directory as a registry name. They are blocked by a failed fetch of
  `pypi.org/pypi/%2F…` or `registry.npmjs.org/%2F…`, not by the content. Online the same thing happens (a 404, so
  `fetch.failed`, so suspicious). That is safe, but the report shows a fetch error instead of the payload's
  findings.
- **`NODE_OPTIONS` / `PYTHONPATH` in server env** is caught by the gate as a protected action. The effect check does
  not catch it: see misses 2 and 3.
- **Approval routes.** All 22 that README/SECURITY.md say are refused are refused. That covers: direct, absolute
  path, `uv run`, `python -m`, `python -c` importing bawwab, symlink and copy of the console script, sh/bash/`.`
  scripts and nested scripts, `make -f` and `./Makefile`, literal calls in `.py`/`.js` files, `git -c alias` and
  `git config alias`, writing an approval into a script (Write, `tee`, heredoc), a shell write to the store,
  `init --skip` and `effects --retry`.
  - Most file-borne hits are plain refusals; direct calls get an approvable block. This matches the docs'
    best-effort note.
- **Documented residuals.** 14 of the 16 routes the docs list as not covered do approve the pending install, and the
  replayed install then passes both layers: npm scripts, a script changed earlier in the command, copy-then-run,
  `$(cat f)`, `eval "$(cat f)"`, process substitution, `BASH_ENV`, Python imports, JS template literals, multi-line
  argv, git hooks, an alias written into `.git/config`, `MAKEFILES=`, and a program Claude writes and runs.
  - Two are better than documented: `make --eval` and a `sqlite3` edit of the store are refused.

## 3. Misses

Each one is a strict xfail in `tests/test_eval_misses.py`, so the test turns red when the gap closes. No detection
code was changed in this task.

**Past both layers, not documented (open):**
1. **Prompt-injecting slash commands and subagents.** Four entries: `.claude/commands/*.md` (project and user) and
   `.claude/agents/*.md`, written with Write.
   - The gate doesn't look at these writes. The effect check does see the new item, but scans it clean.
   - The text rules (`injection.*`) only run on SKILL.md-style files, so a command file holding the exact text that
     flags as `injection.override` + `injection.covert-action` in a SKILL.md comes back clean.
   - Tests: `test_injected_command_or_agent_is_not_clean`, `test_injected_command_write_is_caught`.
2. **Server env loaders after a gate bypass.** `IFS=,; c=claude,mcp,add,fs,-e,NODE_OPTIONS=--require=<payload>,--,node,<clean>; $c`
   gets past the gate (IFS is parked). The effect check then accepts the new server, because its code scans clean.
   The env that loads other code is only checked by the gate.
   - The same holds for a `python3 -c subprocess` install with `PYTHONPATH=<payload>`.
   - By contrast, `env.NODE_OPTIONS` in `settings.json` written past the gate is caught after.
   - Test: `test_server_env_loader_is_caught_after`.
3. **The same gap in the loader-decoy family's "effect check alone" column (5/8).** These three entries were all
   blocked by the gate, so this is not an extra miss. It is the same weakness, showing how thin the backstop is
   there.

**Gate misses the effect check caught** (not attack successes):
- The parked list: brace ×2, IFS ×2, `cla$()ude`, base64 `| sh`, python subprocess. These are accepted residuals
  per README ("Bash parsing is best-effort … the effect check is the backstop") and the Task 9 parked list.
- `printf … %s … | sh`. This is open: Task 9 called it "still gated", but the gate scans the wrong target.

**Accepted / documented:**
- **Shadowing server, fresh install** (`readme-injected-shadowing`, `combo-ifs-shadowing`). There is no static
  signal, and the judge is fake in this eval. README: static rules can be dodged; that is why there is a Claude
  review and the cross-server check, which fires at SessionStart (warn-only).
- **`npm install <local package with a malicious postinstall>`.** This is out of scope: Bawwab gates agent
  extensions, and `node_modules` isn't watched. As an MCP server (`claude mcp add pad -- npx -y <dir>`), the same
  package is blocked as malicious.
  - The README never says this explicitly; "Honest limitations" could add a line.
- **The 14 approval residuals above.** README "Honest limitations" and SECURITY.md.

## 4. Normal-work false positives

37 ordinary developer tool calls, each replayed through gate, then effect, then post, then the next call:
- git status, diff and log;
- **git commit with a heredoc message**, and a commit message that mentions `claude mcp add` and `npm install`;
- checkout, `git pull --ff-only && make test`, stash;
- `uv run pytest`, `pytest -k`, `npm test`, `npm run build`, `make lint`;
- **edits to `.claude/settings.json`, `settings.local.json` and `~/.claude/settings.json` permissions**;
- **running the installed skill's bundled `.sh` and `.py` scripts**;
- Read, Grep and Glob, including Read of `~/.claude.json`;
- Edit and Write of source and tests, and README docs that show `claude mcp add`;
- `sed -i`, `find -delete`, `jq` on `~/.claude.json`, `claude mcp list`, curl, TodoWrite;
- a `python3 - <<EOF` script, `npm ci`, `pip install -e .`.

| | Count |
|---|---:|
| Tasks | 37 |
| Tasks with a deny (gate deny, post block, or the next call denied) | 1 |
| Tasks with any extra notice | 1 |
| Unexpected (false positive) | **0** |
| By design | 1: the user asks for a `PostToolUse` hook running `ruff format`. A new hook runs code, so the gate blocks it pending approval and the effect check quarantines it. |

One latent false positive is worth knowing about. A commit message heredoc that mentions
`claude mcp add calc -- python3 server.py` is treated as a command (bodies are scanned fail-safe). The gate then
scans the project directory as the "server", which added about 280 ms here.
- In an earlier run the payload replicas sat inside the project, and that scan came back MALICIOUS and denied the
  commit.
- Any project that holds test fixtures with credential or exfil patterns would hit this. For the final run the
  payloads were moved outside the project.

## 5. Latency added per tool call

Wall time of `python3 hooks/bawwab_hook.py <sub>` on this machine, 30 runs each (10 for the last row). For scale, a
bare `python3 -c pass` takes 8.4 ms median and 23.1 ms p95 here.

| Path | Median | p95 |
|---|---:|---:|
| Prefilter only: `Bash ls -la` | 28.2 ms | 46.8 ms |
| Prefilter only: `Bash git status --short` | 25.9 ms | 47.2 ms |
| Prefilter only: `Read` | 43.2 ms | 46.9 ms |
| `post` with nothing changed | 42.1 ms | 45.4 ms |
| Full gate, install-like call, scan not cached (`claude mcp add … python3 <clean server>`) | 279.0 ms | 303.2 ms |
| Full gate, same call, cached scan | 264.2 ms | 284.7 ms |
| `post` effect check after a real config change (new server in `.mcp.json`) | 280.9 ms | 303.7 ms |

Ordinary calls stay under 50 ms at p95. The full path costs about 250 ms, almost all of it the `uv run` child's
start-up: a cached and an uncached scan of a small server differ by only about 15 ms.

## 6. Baseline: mcp-scan

**Not run.** `mcp-scan` is not installed, and `uvx --offline mcp-scan` fails ("mcp-scan was not found in the cache";
`results/baseline.json`). The tool also needs network: it calls Invariant's analysis API and starts the servers it
scans. So it cannot run under this evaluation's offline, never-execute rules.

## Files

- `replicas/<incident>/{v1,v2}/`: the five incident replicas (inert, canary-only).
- `fixtures/`: the scratch project, the benign installed skill (`changelog`), and the prompt-injecting skill.
- `redteam/attacks.yaml`, `redteam/normal.yaml`: the entries. They are YAML written in its JSON-compatible flow
  style, because bawwab's venv has no PyYAML; `run_eval.load_yaml` reads them either way.
- `run_eval.py`: the harness. `--only`, `--ids`, `--keep` and `--workdir` are available for debugging.
- `results/*.json`: the raw results of the run above. Machine paths are replaced by `<scratch>`, `<repo>` and `~`.
