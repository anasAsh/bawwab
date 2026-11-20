# Weekly top-100 report refresh: design

**Status:** approved · 2026-11-20

## Intent

The top-100 report on GitHub Pages (https://anasash.github.io/bawwab/) should stay current without a manual run.
Once a week, a GitHub Action re-ranks the top 100 MCP servers, skills and plugins, pins the current versions,
scans them with Bawwab's static rules, and republishes the site.

## Decided by the user

- Run weekly.
- When a scan finds something nobody has reviewed yet, **publish anyway, clearly marked "Not yet reviewed"**
  (rather than holding the site back or opening a PR).

## Goals / non-goals / anti-goals

- Goal: the site reflects this week's top 100 at their current versions, scanned by the current rules.
- Goal: the reader can always tell a raw rule verdict from a hand-reviewed one.
- Non-goal: the LLM judge or deep mode in CI (static rules only, as in the first report).
- Non-goal: an automatic review step.
- Anti-goal: an unreviewed "possibly malicious" label reading like a finding against a real package.
- Anti-goal: CI that runs downloaded package code, or a scan step that holds a token able to write to the repo.

## Design

**Reviews never carry over to a new version.** A target's id already includes a hash of its pinned spec, so a
new release is a new target with no review. That's deliberate: carrying old reviews forward would hide exactly
the rug-pull that a new version can bring. Fast-moving packages will therefore often show as "Not yet reviewed".
That's the honest state.

**Site (`report/build_site.py`).**
- New flag `--allow-unreviewed`. Without it, the build still refuses unreviewed findings, so local publishing
  behaves exactly as today.
- With it:
  - each unreviewed finding gets a "Not yet reviewed" badge;
  - a flagged target with any unreviewed finding gets the outcome "Not yet reviewed: rule verdict only";
  - the overview headline becomes "N flagged by static rules · R reviewed · C confirmed harmful · U awaiting review";
  - a banner states the scan date and that unreviewed verdicts are what the rules said before anyone read the code.
- Unsafe-id and malformed-input problems still block publishing.

**Workflow (`.github/workflows/report.yml`).**
- Triggers: `schedule` (Mondays 06:00 UTC) and `workflow_dispatch`.
- Job `scan` (`permissions: contents: read`):
  1. `uv sync`;
  2. `report/collect.py --refresh` (GET-only API calls; `gh` uses the job's read-only token);
  3. `report/run_scan.sh` (downloads without executing, in a throwaway HOME);
  4. `build_site.py --allow-unreviewed`;
  5. upload the site with `actions/upload-pages-artifact`.

  A step summary lists the targets awaiting review, so you know what to hand-check. The fresh `targets.json`
  and `results.json` are uploaded as a run artifact for reproducibility. Timeout: 180 minutes.
- Job `deploy` (`needs: scan`; `permissions: pages: write, id-token: write`): `actions/deploy-pages`.
  This job never sees the downloaded packages.
- Pages source switches from the `gh-pages` branch to "GitHub Actions". The `gh-pages` branch stays as the
  record of the first, fully reviewed report.
- Third-party actions are pinned by commit SHA.

**Hand-reviewing later.** You add entries to `report/review.json` as today. The next weekly run, or a manual
"Run workflow", publishes them.

**Where the workflow lives.** GitHub only runs scheduled workflows from the default branch (`main`). `main`
currently holds docs only, so the workflow plus the code it runs (`report/`, `bawwab/`, `pyproject.toml`, `uv.lock`)
must be on `main`. Options:

- (a) merge `feat/bawwab` into `main`;
- (b) put only the workflow on `main`, and have it check out `feat/bawwab`.

**Chosen: (b)** until the plugin ships, then (a). It keeps unfinished code off `main`.
The dispute issue template goes to `main` in the same push.

## Tests

- `build_site.py` without the flag still refuses an unreviewed finding.
- With the flag:
  - the badge, outcome label, headline counts and banner render;
  - unsafe ids still block.
- The workflow YAML parses.
- The `scan` job has no write permission.
- Actions are SHA-pinned.

## Left to the builder

Badge styling, exact banner wording, cron minute.
