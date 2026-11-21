"""Bawwab benchmark: scan a labelled corpus and report detection and false-positive rates.

    uv run python bench/run.py [--static-only] [--markdown] [--datadog [--datadog-all] [--guarddog]]

Samples are folders under bench/corpus/{safe,malicious}/<name>/ with a label.json:

    {"expected": "clean"|"suspicious"|"malicious", "category": "<rule family>", "adversarial": false}

Optional label keys: "name" (the package name the scan sees, for identity samples such as typosquats),
"servers" (sub-folders scanned as separate servers and then checked for cross-server references),
"note" (shown next to the sample when it is misclassified),
"heldout" (true: the sample is in the held-out set, see below).

Each sample is copied (without label.json) to a temp folder and scanned as a local target. Packages in
bench/safe-packages.txt are fetched with Bawwab's own fetchers (download only, never installed or run);
their scan reports are cached under bench/.cache/. A line there may carry "heldout" after the category.

Metrics (printed with their definitions):
- A sample is positive when its label is suspicious or malicious, safe when its label is clean.
- Detected: a positive whose verdict is not clean (flagged at any level).
- Exact verdict: a positive whose verdict equals its label.
- False positive: a safe sample whose verdict is not clean. The rate is over safe samples that were scored.
- Not scored: the fetch or scan failed (a fetch.failed, gate.error, rules.error or judge.unavailable finding,
  or an exception). Such a sample is neither detected nor a false positive and is listed apart.

Held-out set: samples marked "heldout" are reported separately from the samples the rules were tuned on.
Every sample that existed on 2026-11-22 was seen while tuning, so none of them is held out; new samples are
added as held out and leave the set (lose the mark) if a rule is changed because of them.
"""
from __future__ import annotations

import argparse
import json
import re
import shutil
import sys
import tempfile
from dataclasses import asdict, dataclass, field
from pathlib import Path

from bawwab.config import Config
from bawwab.fetch import FetchOpts, parse_target
from bawwab.scan import scan_target
from bawwab.severity import compute_verdict
from bawwab.store import Store
from bawwab.trust import cross_server_findings
from bawwab.types import Mode, ScanReport, Target

BENCH = Path(__file__).resolve().parent
ROOT = BENCH.parent
CACHE = BENCH / ".cache"
LEVELS = {"clean": 0, "suspicious": 1, "malicious": 2}
MAX_FP_RATE = 0.10
MAX_ERROR_RATE = 0.10  # more samples than this not scored: the numbers can't be trusted
# A finding with one of these rules means the scan failed closed instead of measuring the sample.
ERROR_RULES = frozenset({"fetch.failed", "gate.error", "rules.error", "judge.unavailable"})
START, END = "<!-- bench:start -->", "<!-- bench:end -->"
_SHA = re.compile(r"^[0-9a-f]{40}$")


@dataclass
class Result:
    id: str
    expected: str
    category: str
    adversarial: bool
    verdict: str
    rules: list[str] = field(default_factory=list)  # rules of findings that counted (>= med)
    note: str = ""
    heldout: bool = False
    error: str = ""  # set when the fetch or scan failed: the sample is not scored

    @property
    def positive(self) -> bool:
        return self.expected != "clean"

    @property
    def scored(self) -> bool:
        return not self.error

    @property
    def flagged(self) -> bool:
        """A scored sample with any verdict other than clean."""
        return self.scored and self.verdict != "clean"

    @property
    def exact(self) -> bool:
        return self.scored and self.verdict == self.expected


@dataclass
class PackageEntry:
    spec: str
    expected: str
    category: str
    note: str = ""
    heldout: bool = False


# ------------------------------------------------------------------ inputs

def parse_safe_packages(path: Path) -> list[PackageEntry]:
    """`<spec> <expected> <category> [heldout] [# note]` per line. Every spec must be pinned."""
    out: list[PackageEntry] = []
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        line, _, note = raw.partition("#") if not raw.lstrip().startswith("git:") else _split_git_note(raw)
        parts = line.split()
        if not parts:
            continue
        heldout = len(parts) == 4 and parts[3] == "heldout"
        if len(parts) not in (3, 4) or parts[1] not in LEVELS or (len(parts) == 4 and not heldout):
            raise ValueError(f"{path}:{n}: expected '<spec> <clean|suspicious|malicious> <category> [heldout]'")
        spec = parts[0]
        if not _pinned(spec):
            raise ValueError(f"{path}:{n}: {spec} is not pinned to an exact version or commit")
        out.append(PackageEntry(spec, parts[1], parts[2], note.strip(), heldout))
    return out


def _split_git_note(raw: str) -> tuple[str, str, str]:
    # A git spec carries "#subdir", so the note separator is " #" after the spec.
    i = raw.find(" #")
    return (raw, "", "") if i < 0 else (raw[:i], "#", raw[i + 2:])


def _pinned(spec: str) -> bool:
    if spec.startswith("git:"):
        url, _, rest = spec[4:].rpartition("@")
        return bool(url) and _SHA.match(rest.split("#", 1)[0]) is not None
    t = parse_target(spec)
    return t.kind in ("npm", "pypi") and bool(t.version) and re.match(r"^\d", t.version or "") is not None


def load_corpus(corpus: Path) -> list[tuple[str, Path, dict]]:
    out = []
    for split in ("malicious", "safe"):
        d = corpus / split
        if not d.is_dir():
            continue
        for s in sorted(p for p in d.iterdir() if p.is_dir()):
            label = json.loads((s / "label.json").read_text())
            if label.get("expected") not in LEVELS or not isinstance(label.get("category"), str):
                raise ValueError(f"{s}/label.json: bad expected/category")
            if (split == "safe") != (label["expected"] == "clean"):
                raise ValueError(f"{s}: samples under safe/ are labelled clean, under malicious/ not clean")
            if not isinstance(label.get("heldout", False), bool):
                raise ValueError(f"{s}/label.json: heldout must be true or false")
            out.append((f"{split}/{s.name}", s, label))
    return out


# ------------------------------------------------------------------ scanning

class Scanner:
    def __init__(self, static_only: bool, backend: str, no_cache: bool) -> None:
        self.static_only = static_only
        # Trust nothing: official packages get no free pass in the benchmark. The reviewer (Claude's
        # recommendation) runs after the verdict and never changes it, so the benchmark doesn't call it.
        self.cfg = Config(mode=Mode.STANDARD, llm_backend=backend, trusted=[], review_enabled=False)
        self.no_cache = no_cache
        self._tmp = Path(tempfile.mkdtemp(prefix="bawwab-bench-"))
        self.local_store = Store(self._tmp / "corpus.db")  # fresh each run: no cross-sample trust state
        self._pkg_store: Store | None = None

    @property
    def pkg_store(self) -> Store:
        if self._pkg_store is None:
            CACHE.mkdir(parents=True, exist_ok=True)
            self._pkg_store = Store(CACHE / ("static.db" if self.static_only else "full.db"))
        return self._pkg_store

    def scan(self, t: Target, store: Store, no_cache: bool = True) -> ScanReport:
        return scan_target(
            t, mode=Mode.STANDARD, cfg=self.cfg, store=store, no_cache=no_cache,
            judge=not self.static_only, fetch_opts=FetchOpts(),
        )

    def counted(self, r: ScanReport) -> list[str]:
        th = self.cfg.suspicious
        return sorted({f.rule for f in r.findings if f.severity >= th})

    @staticmethod
    def error_of(*reports: ScanReport) -> str:
        """The failure that kept a scan from measuring the sample (see ERROR_RULES), or ""."""
        for r in reports:
            for f in r.findings:
                if f.rule in ERROR_RULES:
                    return f"{f.rule}: {f.evidence}"[:200]
        return ""

    def sample(self, sid: str, src: Path, label: dict) -> Result:
        res = Result(sid, label["expected"], label["category"], bool(label.get("adversarial")), "error", [],
                     label.get("note", ""), bool(label.get("heldout")))
        try:
            self._sample(res, src, label)
        except Exception as e:  # noqa: BLE001 - one broken sample is reported, not scored
            res.error = f"{type(e).__name__}: {e}"[:200]
        return res

    def _sample(self, res: Result, src: Path, label: dict) -> None:
        work = Path(tempfile.mkdtemp(dir=self._tmp))
        dest = work / src.name
        shutil.copytree(src, dest, symlinks=True, ignore=shutil.ignore_patterns("label.json"))
        name = label.get("name") or ""
        servers = label.get("servers")
        if servers:
            reports = {s: self.scan(_local(dest / s, s), self.local_store) for s in servers}
            snaps = {s: self.local_store.get_scan_snapshot(r.key) or {} for s, r in reports.items()}
            cross = cross_server_findings(snaps)
            rules = sorted({x for r in reports.values() for x in self.counted(r)} | {f.rule for f in cross})
            levels = [LEVELS[r.verdict.value] for r in reports.values()]
            levels.append(LEVELS[compute_verdict(cross, self.cfg.malicious, self.cfg.suspicious).value])
            verdict = next(k for k, v in LEVELS.items() if v == max(levels))
            error = self.error_of(*reports.values())
        else:
            r = self.scan(_local(dest, name), self.local_store)
            verdict, rules, error = r.verdict.value, self.counted(r), self.error_of(r)
        shutil.rmtree(work, ignore_errors=True)
        res.verdict, res.rules, res.error = verdict, rules, error

    def package(self, e: PackageEntry) -> Result:
        res = Result(f"package/{e.spec}", e.expected, e.category, False, "error", [], e.note, e.heldout)
        try:
            if e.spec.startswith("git:"):
                t = _local(git_checkout(e.spec), "")
                r = self.scan(t, self.local_store)
            else:
                r = self.scan(parse_target(e.spec), self.pkg_store, no_cache=self.no_cache)
        except Exception as ex:  # noqa: BLE001 - e.g. a failed git fetch: not scored, never a false positive
            res.error = f"{type(ex).__name__}: {ex}"[:200]
            return res
        res.verdict, res.rules, res.error = r.verdict.value, self.counted(r), self.error_of(r)
        return res

    def close(self) -> None:
        shutil.rmtree(self._tmp, ignore_errors=True)


def _local(path: Path, name: str) -> Target:
    return Target("local", str(path), name=name, path=str(path.resolve()))


def git_checkout(spec: str) -> Path:
    """Shallow-fetch one pinned commit into bench/.cache/git (files only: hooks off, nothing is run)."""
    from bawwab.fetch.git import _run

    url, _, rest = spec[4:].rpartition("@")
    sha, _, sub = rest.partition("#")
    repo = CACHE / "git" / f"{re.sub(r'[^A-Za-z0-9._-]+', '_', url)}@{sha}"
    if not (repo / ".bench-complete").exists():
        shutil.rmtree(repo, ignore_errors=True)
        home = CACHE / "git" / ".home"
        home.mkdir(parents=True, exist_ok=True)
        cfg = ["-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false", "-c", "protocol.file.allow=never",
               "-c", "protocol.ext.allow=never"]
        _run(["git", "init", "-q", str(repo)], 120, home)
        _run(["git", *cfg, "-C", str(repo), "fetch", "-q", "--depth", "1", "--no-recurse-submodules", "--", url, sha],
             300, home)
        _run(["git", *cfg, "-C", str(repo), "-c", "advice.detachedHead=false", "checkout", "-q", "FETCH_HEAD"], 120, home)
        shutil.rmtree(repo / ".git", ignore_errors=True)
        (repo / ".bench-complete").write_text(sha)
    target = (repo / sub).resolve() if sub else repo
    if repo.resolve() not in (target, *target.parents) or not target.is_dir():
        raise ValueError(f"{spec}: subdirectory {sub!r} not found")
    return target


# ------------------------------------------------------------------ metrics

DEFINITIONS = [
    ("Positive", "a sample labelled suspicious or malicious. **Safe**: a sample labelled clean."),
    ("Detected", "a positive whose verdict is not clean (flagged at any level)."),
    ("Exact verdict", "a positive whose verdict equals its label (a malicious sample rated suspicious is "
                      "detected but not exact)."),
    ("False positive", "a safe sample whose verdict is not clean. The rate is over safe samples that were scored."),
    ("Not scored", "the fetch or scan failed (`fetch.failed`, `gate.error`, `rules.error`, `judge.unavailable`, "
                   "or an error in the runner). Counted as neither detected nor a false positive, and listed separately."),
]


def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 4) if b else None


def _bucket(rs: list[Result]) -> dict:
    scored = [r for r in rs if r.scored]
    pos = [r for r in scored if r.positive]
    safe = [r for r in scored if not r.positive]
    detected = sum(r.flagged for r in pos)
    exact = sum(r.exact for r in pos)
    fp = sum(r.flagged for r in safe)
    return {
        "n": len(rs), "errors": len(rs) - len(scored),
        "positives": len(pos), "detected": detected, "exact": exact, "missed": len(pos) - detected,
        "safe": len(safe), "safe_fp": fp,
        "detected_rate": _ratio(detected, len(pos)), "exact_rate": _ratio(exact, len(pos)),
        "safe_fp_rate": _ratio(fp, len(safe)),
    }


def _with_adversarial(rs: list[Result]) -> dict:
    adv = [r for r in rs if r.adversarial and r.positive and r.scored]
    return {**_bucket(rs), "adversarial": len(adv), "adversarial_detected": sum(r.flagged for r in adv),
            "adversarial_exact": sum(r.exact for r in adv)}


def metrics(results: list[Result]) -> dict:
    cats: dict[str, list[Result]] = {}
    for r in results:
        cats.setdefault(r.category, []).append(r)
    return {
        "categories": {k: _bucket(v) for k, v in sorted(cats.items())},
        "overall": _with_adversarial(results),
        "tuning": _with_adversarial([r for r in results if not r.heldout]),
        "heldout": _with_adversarial([r for r in results if r.heldout]),
        # Where the samples come from: handwritten folders in bench/corpus, or real packages (safe-packages.txt).
        "corpus": _bucket([r for r in results if not r.id.startswith("package/")]),
        "packages": _bucket([r for r in results if r.id.startswith("package/")]),
    }


def gate(m: dict, results: list[Result], full: bool) -> list[str]:
    fails = []
    o = m["overall"]
    rate = o["safe_fp_rate"]
    if rate is not None and rate > MAX_FP_RATE:
        fails.append(f"safe-set false-positive rate {rate:.1%} is above {MAX_FP_RATE:.0%}")
    if o["n"] and o["errors"] / o["n"] > MAX_ERROR_RATE:
        fails.append(f"{o['errors']}/{o['n']} samples not scored (fetch or scan failed): above {MAX_ERROR_RATE:.0%}")
    if full:
        fails += [f"malicious sample scanned clean: {r.id}" for r in results
                  if r.scored and r.expected == "malicious" and r.verdict == "clean"]
    return fails


# ------------------------------------------------------------------ output

def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.0%}"


def _frac(a: int, b: int) -> str:
    return f"{a}/{b} ({_pct(_ratio(a, b))})" if b else "n/a"


def _row(name: str, c: dict) -> str:
    return (f"| {name} | {_frac(c['detected'], c['positives'])} | {_frac(c['exact'], c['positives'])} | "
            f"{_frac(c['safe_fp'], c['safe'])} | {c['errors']} |")


def table(m: dict, results: list[Result], mode: str, datadog: dict | None = None) -> str:
    o, tu, ho = m["overall"], m["tuning"], m["heldout"]
    lines = [
        (f"Mode: **{mode}**. {o['n']} samples: {o['positives']} positive (labelled suspicious or malicious), "
         f"{o['safe']} safe (labelled clean), {o['errors']} not scored."),
        "",
        "| Family | Detected | Exact verdict | False positives | Not scored |",
        "|---|---|---|---|---|",
    ]
    for k, c in m["categories"].items():
        lines.append(_row(k, c))
    lines += [_row("**all**", o), "", "| Set | Detected | Exact verdict | False positives | Not scored |",
              "|---|---|---|---|---|", _row("seen during tuning", tu), _row("held out", ho),
              _row("handwritten corpus (`bench/corpus/`)", m["corpus"]),
              _row("real packages (`bench/safe-packages.txt`)", m["packages"])]
    if not ho["n"]:
        lines += ["", ("No held-out samples yet: every sample above was seen while the rules were tuned, so these "
                       "numbers show fit to this corpus, not performance on unseen samples.")]
    lines += ["", "Definitions:", ""] + [f"- **{k}**: {v}" for k, v in DEFINITIONS]
    lines += [
        "",
        (f"- **Adversarial samples** (written to talk the AI judge out of a finding): detected "
         f"{o['adversarial_detected']}/{o['adversarial']}, exact verdict {o['adversarial_exact']}/{o['adversarial']}"),
    ]
    if datadog:
        for eco, d in sorted(datadog.items()):
            gd = f"; GuardDog {d['guarddog_detected']}/{d['guarddog_n']}" if d.get("guarddog_n") else ""
            err = f", {d['errors']} not scored" if d.get("errors") else ""
            lines.append(f"- **Real malware** (DataDog dataset, {eco}): detected {d['detected']}/{d['n']}"
                         f" ({_pct(d['detected_rate'])}), rated malicious {d['malicious']}/{d['n']}{err}{gd}")
    wrong = [r for r in results if r.scored and r.verdict != r.expected]
    if wrong:
        lines += ["", "Not an exact verdict, or a false positive:", ""]
        for r in wrong:
            why = f" — {r.note}" if r.note else ""
            rules = ", ".join(r.rules) or "no findings"
            tag = " (held out)" if r.heldout else ""
            lines.append(f"- `{r.id}`{tag}: expected {r.expected}, got {r.verdict} ({rules}){why}")
    errs = [r for r in results if not r.scored]
    if errs:
        lines += ["", "Not scored:", ""]
        lines += [f"- `{r.id}`: {r.error}" for r in errs]
    return "\n".join(lines)


def rewrite_readme(readme: Path, block: str) -> bool:
    text = readme.read_text()
    if text.count(START) != 1 or text.count(END) != 1:  # missing or duplicated markers: refuse
        return False
    i, j = text.find(START), text.find(END)
    if j < i:
        return False
    new = text[: i + len(START)] + "\n" + block.rstrip("\n") + "\n" + text[j:]
    if new != text:
        readme.write_text(new)
    return True


# ------------------------------------------------------------------ main

def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--static-only", action="store_true", help="static rules only; never call the AI judge")
    ap.add_argument("--markdown", action="store_true", help="rewrite the bench block in README.md")
    ap.add_argument("--corpus", type=Path, default=BENCH / "corpus")
    ap.add_argument("--packages", type=Path, default=BENCH / "safe-packages.txt")
    ap.add_argument("--no-packages", action="store_true", help="skip the network-fetched safe packages")
    ap.add_argument("--readme", type=Path, default=ROOT / "README.md")
    ap.add_argument("--json", type=Path, help="write full results as JSON here")
    ap.add_argument("--backend", choices=["claude-cli", "api"], default="api", help="judge backend for a full run")
    ap.add_argument("--no-cache", action="store_true", help="rescan packages even when a cached report exists")
    ap.add_argument("--datadog", action="store_true", help="also scan the DataDog real-malware recall set")
    ap.add_argument("--datadog-all", action="store_true", help="scan every DataDog sample, not the pinned sample")
    ap.add_argument("--guarddog", action="store_true", help="run GuardDog on the DataDog set as a baseline")
    a = ap.parse_args(argv)

    mode = "static-only" if a.static_only else "full (static + AI judge)"
    sc = Scanner(a.static_only, a.backend, a.no_cache)
    results: list[Result] = []
    datadog = None
    try:
        for sid, path, label in load_corpus(a.corpus):
            results.append(sc.sample(sid, path, label))
            print(f"  {results[-1].verdict:10} {sid}", file=sys.stderr)
        if not a.no_packages and a.packages.is_file():
            for e in parse_safe_packages(a.packages):
                results.append(sc.package(e))
                print(f"  {results[-1].verdict:10} {e.spec}", file=sys.stderr)
        if a.datadog or a.datadog_all:
            sys.path.insert(0, str(BENCH))
            import fetch_datadog

            datadog = fetch_datadog.recall(sc, everything=a.datadog_all, guarddog=a.guarddog)
    finally:
        sc.close()
    m = metrics(results)
    out = table(m, results, mode, datadog)
    print(out)
    if a.json:
        a.json.write_text(json.dumps({**m, "mode": mode, "datadog": datadog,
                                      "samples": [asdict(r) for r in results]}, indent=2) + "\n")
    if a.markdown and not rewrite_readme(a.readme, out):
        print(f"error: {a.readme} has no {START} ... {END} block", file=sys.stderr)
        return 3
    fails = gate(m, results, full=not a.static_only)
    for f in fails:
        print(f"FAIL: {f}", file=sys.stderr)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
