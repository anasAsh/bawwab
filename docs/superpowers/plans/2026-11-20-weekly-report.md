# Weekly Report Refresh Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** A weekly GitHub Action re-ranks, rescans and republishes the top-100 report, and every flagged target says why it was flagged.

**Architecture:**
- `report/build_site.py` gains two things:
  - a generated "Why it was flagged" section (plus a short "Why" column in the list);
  - an `--allow-unreviewed` mode that publishes unreviewed findings with a "Not yet reviewed" label.
- A new workflow, `.github/workflows/report.yml`, scans in a read-only job and deploys with `actions/deploy-pages` in a separate job.
- Only the workflow and the dispute template go to `main`; the workflow checks out `feat/bawwab`.

**Tech Stack:** Python 3.12 stdlib, pytest, GitHub Actions, uv.

**Spec:** `docs/superpowers/specs/2026-11-20-weekly-report-design.md`

## Global Constraints

- Without `--allow-unreviewed`, `build_site.py` behaves exactly as today: it refuses unreviewed findings and exits 2.
- Reviews never carry over to a new version. Matching stays by target id, which already hashes the pinned spec.
- Unsafe target ids block publishing in every mode.
- Every scanned string still goes through `e()`/`t()`. Never emit raw evidence.
- The scan job has `permissions: contents: read` only. Deploy has `pages: write, id-token: write` only.
- Third-party actions are pinned by full commit SHA, with the tag in a comment.
- Schedule: `cron: "0 6 * * 1"`, plus `workflow_dispatch`.
- Commit email `cisash+0@gmail.com`, with the session's commit trailers.

## Review Focus

- A target flagged only by findings the rules mark `counted` but with no catalog entry: the "why" still names the rule id.
- A target with both reviewed and unreviewed findings: the outcome is "Not yet reviewed", never "Reviewed: false alarm".
- An empty or failed weekly collect: the workflow fails before deploying, so the live site stays as it was.
- Hostile rule ids or file paths in the "why" text are escaped (covered by the escape test, extended).
- The step summary must not echo raw evidence (it uses `needs_review.py`, which sanitises).

---

### Task 1: "Why it was flagged" on target pages and in the list

**Files:**
- Modify: `report/build_site.py`: new `why_flagged`, plus calls from `target_page` and `targets_page`.
- Test: `tests/test_report_site.py`

**Interfaces:**
- Produces: `why_flagged(v: View) -> list[tuple[str, str, int, str]]`, a list of `(rule, title, count, first_location)`.
  It holds the counted findings at the view's highest severity, grouped by rule, in rule order.
  `title` is `CATALOG[rule].title`, or the rule id when the rule isn't in the catalog. It returns `[]` for clean and not-verified views.

- [ ] **Step 1: Failing tests**

```python
def test_flagged_target_page_says_why(tmp_path):
    # one critical exfil.combo in index.js:3 and one med install-script → malicious
    # page contains "Why it was flagged", "exfil.combo", the catalog title, "index.js:3";
    # install-script is NOT listed under "why" (lower severity), but is still in Findings
def test_targets_list_has_why_column(tmp_path):
    # targets.html row for that target contains the exfil.combo title; a clean row's Why cell is empty
def test_why_escapes_hostile_paths(tmp_path):
    # finding file '<img src=x onerror=alert(1)>.js' → no raw '<img' in the page
```

- [ ] **Step 2:** `uv run pytest tests/test_report_site.py -q -k why` → FAIL.
- [ ] **Step 3: Implement.**
  - Place the section directly under the verdict paragraph on the target page.
  - Heading: `Why it was flagged`.
  - Lead line: "The static rules marked this {label} because of:".
  - Each item: `<code>rule</code>: title (severity, N× · first at file:line)`.
  - List page: a `Why` column (`hide-sm`) after "Result", holding the first title, plus " +K more" when there are more.
- [ ] **Step 4:** `uv run pytest tests/test_report_site.py -q` → all PASS. Rebuild the site locally and compare the counts with the last run.
- [ ] **Step 5:** Commit `report: say why each flagged target was flagged`.

### Task 2: `--allow-unreviewed` publishing mode

**Files:**
- Modify: `report/build_site.py`: `plan`, `outcome_of`, `build`, `main`, `finding_card`, `index_page`, CSS.
- Test: `tests/test_report_site.py`

**Interfaces:**
- Produces: `build(..., allow_unreviewed: bool = False)`. The CLI flag is `--allow-unreviewed`.
  With the flag, "unreviewed …" problems become warnings, and every other problem still raises `PublishRefused`.
  `outcome_of` returns `"Not yet reviewed: rule verdict only"` when any counted finding of a flagged view has no review entry.

- [ ] **Step 1: Failing tests**

```python
def test_default_still_refuses_unreviewed(tmp_path)              # existing behaviour, exit 2
def test_allow_unreviewed_publishes_with_badges(tmp_path):
    # page has "Not yet reviewed" badge on the finding and outcome "Not yet reviewed: rule verdict only"
def test_mixed_reviewed_and_unreviewed_is_not_yet_reviewed(tmp_path)
def test_allow_unreviewed_headline_counts(tmp_path):
    # index: "2 flagged by static rules · 1 reviewed · 0 confirmed harmful · 1 awaiting review"
    # plus the banner text "awaiting review"
def test_allow_unreviewed_still_blocks_unsafe_ids(tmp_path)
```

- [ ] **Step 2:** → FAIL.
- [ ] **Step 3: Implement.**
  - Add a badge class `b-unreviewed` using the `--nv` colours.
  - Show the banner only when the awaiting count is above 0. Text: "Scanned {date}. {U} flagged targets are awaiting hand-review: their labels are what the static rules said before anyone read the code."
  - When the awaiting count is 0, keep today's headline wording exactly, so the existing `test_index_leads_with_reviewed_outcome` passes unchanged.
- [ ] **Step 4:** `uv run pytest -q` → all PASS.
- [ ] **Step 5:** Commit `report: --allow-unreviewed publishes unreviewed findings, clearly labelled`.

### Task 3: Weekly workflow, Pages switch, dispute template on main

**Files:**
- Create: `.github/workflows/report.yml` and `.github/ISSUE_TEMPLATE/dispute.md` (copied from `report/ISSUE_TEMPLATE_dispute.md`), on both `feat/bawwab` and `main`.
- Test: `tests/test_report_workflow.py` (on `feat/bawwab`).

**Workflow outline:**
- `on: schedule [cron "0 6 * * 1"] + workflow_dispatch`, with `concurrency: report`.
- Job `scan`:
  - `contents: read`, `timeout-minutes: 180`.
  - Check out `ref: feat/bawwab` (a top-level `env: SOURCE_REF: feat/bawwab`, so it's one line to change after the merge).
  - Set up uv (SHA-pinned) and run `uv sync --locked`.
  - Run `uv run python report/collect.py --refresh` with `GH_TOKEN: ${{ github.token }}`.
  - Run `REPORT_PYTHON=.venv/bin/python REPORT_WORK=$RUNNER_TEMP/rw report/run_scan.sh`.
  - Run `uv run python report/build_site.py --allow-unreviewed`.
  - Run `uv run python report/needs_review.py` and append its output to `$GITHUB_STEP_SUMMARY`.
  - Upload `report/targets.json` and `report/out/results.json` as artifact `report-data`.
  - Run `actions/upload-pages-artifact` with `path: report/out/site`.
- Job `deploy`:
  - `needs: scan`;
  - `pages: write, id-token: write`;
  - `environment: github-pages`;
  - runs `actions/deploy-pages`.

- [ ] **Step 1: Failing test `tests/test_report_workflow.py`.** Parse the YAML with `yaml.safe_load` (add `pyyaml` to the dev group only if it isn't already there) and assert:
  - the cron is `0 6 * * 1`;
  - `workflow_dispatch` is present;
  - the scan job has permissions exactly `{"contents": "read"}`;
  - deploy has exactly `{"pages": "write", "id-token": "write"}`;
  - every `uses:` matches `@[0-9a-f]{40}`;
  - the build step contains `--allow-unreviewed`;
  - no step in the scan job references `secrets.`.
- [ ] **Step 2:** → FAIL. **Step 3:** Write the workflow and the template. **Step 4:** `uv run pytest -q` → PASS.
- [ ] **Step 5:** Commit on `feat/bawwab`: `ci: weekly top-100 report refresh`.
- [ ] **Step 6: Publish (user-approved option b).**
  1. Commit the two files on top of `origin/main` from a clean worktree and push to `main`.
  2. Switch Pages to Actions: `gh api -X PUT repos/anasAsh/bawwab/pages -f build_type=workflow`.
  3. Trigger the first run: `gh workflow run report.yml --ref main`.
  4. Watch it. Report its duration, the counts, and how many targets await review.
  5. If the run fails, switch Pages back to `gh-pages` (`-f build_type=legacy -f "source[branch]=gh-pages" -f "source[path]=/"`) so the site stays up.
