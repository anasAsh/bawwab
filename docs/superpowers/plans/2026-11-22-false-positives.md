# False-positive reduction plan

**Data (2026-11-22).** The 302-target report scan has 1,214 counted findings (medium or above) with a review
status in `report/review.json`: 860 false alarms (71%), 354 expected behaviour (29%), 0 confirmed harmful.

| Rule | Counted | False alarm | Expected | False-alarm share |
|---|---|---|---|---|
| credential-access | 658 | 473 | 185 | 72% |
| exfil.combo | 216 | 159 | 57 | 74% |
| exfil.host | 61 | 57 | 4 | 93% |
| tool-shadowing | 52 | 40 | 12 | 77% |
| remote-code.pipe-shell | 48 | 24 | 24 | 50% |
| files.truncated | 43 | 15 | 28 | 35% |
| injection.override | 31 | 31 | 0 | 100% |

Where the false alarms are (first matching cause): tests, fixtures, examples and benchmarks 34%; bundled or
minified third-party code 21%; CI workflows and dev scripts 14%; help text, descriptions and UI strings 10%;
skill/agent/command prose 4%; deny-lists and guards 3%; docs 3%; other (mostly over-loose patterns such as
`from .env import`, `.env("MCP_PROXY")`) 10%.

**Recall check (same day).** Of the 31 malicious benchmark samples, 5 had every counted finding in a `.md`
file or a script it runs: all five are skills, whose `SKILL.md` is the code Claude follows. So "non-runtime"
must be defined by what runs or is read by the agent, never by file type or folder name alone.

## Steps

0. **Measuring stick.** Freeze the reviewed findings as a corpus with an offline rescan, and a recall gate over
   the benchmark's malicious samples, the eval replicas and (where available locally) the DataDog set. Every
   later step must cut corpus false alarms and keep every detection.
1. **Weight by reachability** (≈ 51% of false alarms). Runtime = entry points (`main`/`bin`/exports, MCP
   server commands), install scripts and their targets, hooks and what they reference, model-facing files
   (`SKILL.md`, `agents/`, `commands/`, tool descriptions), and what these import/require/source/name by path,
   transitively. A finding in any other file becomes LOW (shown, not counted). Unknown = runtime (fail
   closed). Residual: a payload reached through a computed path; it is demoted, not dropped, and the judge and
   reviewer still see it.
2. **Proximity in bundles** (≈ 21%). In minified or bundled files, exfil.combo / credential-access need the
   credential read and the network call in the same function or within a few lines, not just the same file.
3. **Pattern precision** (≈ 10%). Credential paths only as path-like string literals or file-read arguments,
   not identifiers; secret-file lists used to exclude or redact, and permission deny rules, become LOW.
4. **Tool shadowing** (40 false alarms). Require another tool or server to be named, or imperative override
   wording; descriptive "instead of <parameter>" text doesn't count.

Expected combined effect: roughly 70-80% fewer false alarms, to be measured by step 0, never assumed.
