"""Write report/out/needs-review.md: the hand-check worklist for every non-clean target.

    uv run python report/needs_review.py

Lists each counted (MED or higher) finding with its rule, file:line, sanitised and truncated evidence, finding
key and whether report/review.json already covers it, plus the local folder holding the downloaded copy.
It never writes reviews: deciding is the reviewer's job.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bawwab.report import sanitise  # noqa: E402
from report.build_site import load_review, match_review, state_of  # noqa: E402
from report.collect import load_targets  # noqa: E402

REPORT = ROOT / "report"


def md(s: object, cap: int) -> str:
    """Sanitised and safe inside a Markdown inline code span."""
    return sanitise(s or "", cap).replace("`", "'")


def render(targets: list[dict], results: dict, review: dict) -> tuple[str, dict[str, int], int]:
    lines: list[str] = []
    by_rule: dict[str, int] = {}
    open_count = 0
    flagged = errors = 0
    rv = review.get("targets") or {}
    body: list[str] = []
    for tg in targets:
        res = results.get(tg["id"])
        state = state_of(res, tg["spec"])
        if state == "not-verified":
            if res is not None:
                errors += 1
            continue
        if state == "clean":
            continue
        flagged += 1
        entries = (rv.get(tg["id"]) or {}).get("findings") or []
        counted = [f for f in res.get("findings") or [] if f.get("counted")]
        body += [f"## {tg['rank']}. {md(tg['name'], 120)} ({tg['kind']}, {state})", "",
                 f"- id: `{tg['id']}`", f"- pin: `{md(tg['spec'], 200)}`",
                 f"- local copy: `{md(res.get('local_path') or 'none kept', 300)}`", ""]
        for f in counted:
            r = match_review(entries, f)
            if r is None:
                open_count += 1
                by_rule[f["rule"]] = by_rule.get(f["rule"], 0) + 1
            loc = md(f.get("file") or "-", 200) + (f":{f['line']}" if isinstance(f.get("line"), int) else "")
            status = f"reviewed: {r['status']}" if r else "**NEEDS REVIEW**"
            body += [f"- [{'x' if r else ' '}] `{md(f['rule'], 60)}` {f['severity']} at `{loc}` (key `{f['key']}`) {status}",
                     f"  - evidence: `{md(f.get('evidence'), 200)}`"]
        body.append("")
    lines += ["# Findings that need a hand-check", "",
              f"{flagged} non-clean targets, {open_count} counted findings without a review entry. "
              f"{errors} targets errored (not verified; listed in results.json).", "",
              "Open findings by rule:", ""]
    lines += [f"- `{k}`: {n}" for k, n in sorted(by_rule.items(), key=lambda x: (-x[1], x[0]))] or ["- none"]
    lines += ["", "Add one entry per finding (or per rule + file glob) to report/review.json; "
              "`*` stays inside one folder, `**/` spans folders.", ""]
    return "\n".join(lines + body) + "\n", by_rule, open_count


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--targets", type=Path, default=REPORT / "targets.json")
    ap.add_argument("--results", type=Path, default=REPORT / "out" / "results.json")
    ap.add_argument("--review", type=Path, default=REPORT / "review.json")
    ap.add_argument("--out", type=Path, default=REPORT / "out" / "needs-review.md")
    a = ap.parse_args(argv)
    results = json.loads(a.results.read_text()).get("results") or {}
    text, by_rule, n = render(load_targets(a.targets), results, load_review(a.review))
    a.out.parent.mkdir(parents=True, exist_ok=True)
    a.out.write_text(text)
    print(f"wrote {a.out}: {n} open findings {by_rule}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
