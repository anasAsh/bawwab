# Hardening plan: the external review's structural items

Source: an independent read-only review of the code by OpenAI Codex (2026-11-21). Its smaller findings are
fixed on `feat/reviewer` (CLAUDE_CONFIG_DIR, reviewer binding, NotebookEdit/MCP coverage, effect hash bound to
the bytes that run, pin rewrite, cache policy, judge HIGH grounding, benchmark metrics, wording). These three need
design decisions first.

## 1. Approval the agent can't forge

**Today.** Bawwab and Claude run as the same OS user. The gate refuses approve/reject/level-lowering when
Claude runs them by any recognised route, but a program Claude writes and runs can edit `~/.bawwab` or the hook
directly (threat model T3, R55/R57).

**Options to evaluate.**
- A user-presence check on approve: `bawwab approve` asks for a code shown out of band (desktop notification or
  the terminal title), or for a confirmation through the OS (polkit / macOS authorization). The agent can run the
  command but can't see or type the code. Cost: one extra step per approval.
- Store the approval DB where the user's shell can write but Claude's tool sandbox can't (Claude Code's sandbox
  write rules, when the user runs with the sandbox on). Free when available, nothing otherwise.
- A separate OS user or a root-owned helper for the store (strongest, heaviest install).

**Decide:** which of these to offer, and whether to make one the default at the high level.

## 2. A structured install path

**Today.** Install detection parses arbitrary Bash; the prefilter, the detector and the pinner re-implement
parts of the same parsing and can drift (the prefilter's contract is to never miss what the detector finds).

**Plan.** Offer `bawwab install <spec>` (and an MCP tool) as the strongly enforced path: it scans, pins and writes
the config entry itself, after approval. Keep shell parsing as a compatibility layer. Add a cross-check test:
for every command in the corpus (tests, eval, the developer replay), prefilter ⊇ detector, and the pinner only
rewrites what the detector resolved.

**Decide:** whether the skill should steer Claude to `bawwab install` instead of `claude mcp add`.

## 3. A verifiable report

**Today.** The site records pins and scanner commit, but not digests of the scanned bytes; OSV results are live;
a rule-wide review entry can cover a finding nobody re-read.

**Plan.**
- Record a content digest per target (the fetch content hash Bawwab already computes) and the OSV response
  digest in results.json, and show them on each target page.
- Bind each review entry to the finding key and the scanner commit it was written against; a review for an older
  commit shows "reviewed under an earlier scanner version".
- Keep corrected versions: publish each weekly results.json as a release asset, link disputes to the version
  they concern.

**Decide:** whether to also sign results.json (e.g. Sigstore) or let the release history carry integrity.
