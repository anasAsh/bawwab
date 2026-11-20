"""Bawwab benchmark: scan a labelled corpus and report precision, recall and the false-positive rate.

    uv run python bench/run.py [--static-only] [--markdown] [--datadog [--datadog-all] [--guarddog]]

Samples are folders under bench/corpus/{safe,malicious}/<name>/ with a label.json:

    {"expected": "clean"|"suspicious"|"malicious", "category": "<rule family>", "adversarial": false}

Optional label keys: "name" (the package name the scan sees, for identity samples such as typosquats),
"servers" (sub-folders scanned as separate servers and then checked for cross-server references),
"note" (shown next to the sample when it is misclassified).

Each sample is copied (without label.json) to a temp folder and scanned as a local target. Packages in
bench/safe-packages.txt are fetched with Bawwab's own fetchers (download only, never installed or run);
their scan reports are cached under bench/.cache/.

A sample is positive when its label is not clean. It is correct when verdict >= expected
(clean < suspicious < malicious). A clean-labelled sample with any other verdict is a false positive.
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

    @property
    def positive(self) -> bool:
        return self.expected != "clean"

    @property
    def correct(self) -> bool:
        return LEVELS[self.verdict] >= LEVELS[self.expected]


@dataclass
class PackageEntry:
    spec: str
    expected: str
    category: str
    note: str = ""


# ------------------------------------------------------------------ inputs

def parse_safe_packages(path: Path) -> list[PackageEntry]:
    """`<spec> <expected> <category> [# note]` per line. Every spec must be pinned."""
    out: list[PackageEntry] = []
    for n, raw in enumerate(path.read_text().splitlines(), 1):
        line, _, note = raw.partition("#") if not raw.lstrip().startswith("git:") else _split_git_note(raw)
        parts = line.split()
        if not parts:
            continue
        if len(parts) != 3 or parts[1] not in LEVELS:
            raise ValueError(f"{path}:{n}: expected '<spec> <clean|suspicious|malicious> <category>'")
        spec = parts[0]
        if not _pinned(spec):
            raise ValueError(f"{path}:{n}: {spec} is not pinned to an exact version or commit")
        out.append(PackageEntry(spec, parts[1], parts[2], note.strip()))
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
            out.append((f"{split}/{s.name}", s, label))
    return out


# ------------------------------------------------------------------ scanning

class Scanner:
    def __init__(self, static_only: bool, backend: str, no_cache: bool) -> None:
        self.static_only = static_only
        # Trust nothing: official packages get no free pass in the benchmark.
        self.cfg = Config(mode=Mode.STANDARD, llm_backend=backend, trusted=[])
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

    def sample(self, sid: str, src: Path, label: dict) -> Result:
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
        else:
            r = self.scan(_local(dest, name), self.local_store)
            verdict, rules = r.verdict.value, self.counted(r)
        shutil.rmtree(work, ignore_errors=True)
        return Result(sid, label["expected"], label["category"], bool(label.get("adversarial")), verdict, rules,
                      label.get("note", ""))

    def package(self, e: PackageEntry) -> Result:
        if e.spec.startswith("git:"):
            t = _local(git_checkout(e.spec), "")
            r = self.scan(t, self.local_store)
        else:
            r = self.scan(parse_target(e.spec), self.pkg_store, no_cache=self.no_cache)
        return Result(f"package/{e.spec}", e.expected, e.category, False, r.verdict.value, self.counted(r), e.note)

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

def _ratio(a: int, b: int) -> float | None:
    return round(a / b, 4) if b else None


def _bucket(rs: list[Result]) -> dict:
    pos = [r for r in rs if r.positive]
    neg = [r for r in rs if not r.positive]
    tp = sum(r.correct for r in pos)
    fp = sum(r.verdict != "clean" for r in neg)
    return {
        "n": len(rs), "positives": len(pos), "tp": tp, "fn": len(pos) - tp, "fp": fp,
        "detected": sum(r.verdict != "clean" for r in pos),
        "precision": _ratio(tp, tp + fp), "recall": _ratio(tp, len(pos)),
    }


def metrics(results: list[Result]) -> dict:
    cats: dict[str, list[Result]] = {}
    for r in results:
        cats.setdefault(r.category, []).append(r)
    b = _bucket(results)
    safe = [r for r in results if not r.positive]
    adv = [r for r in results if r.adversarial and r.positive]
    overall = {
        **b,
        "detected_rate": _ratio(b["detected"], b["positives"]),
        "safe": len(safe), "safe_fp": b["fp"], "safe_fp_rate": _ratio(b["fp"], len(safe)),
        "adversarial": len(adv), "adversarial_tp": sum(r.correct for r in adv),
        "adversarial_recall": _ratio(sum(r.correct for r in adv), len(adv)),
    }
    return {"categories": {k: _bucket(v) for k, v in sorted(cats.items())}, "overall": overall}


def gate(m: dict, results: list[Result], full: bool) -> list[str]:
    fails = []
    rate = m["overall"]["safe_fp_rate"]
    if rate is not None and rate > MAX_FP_RATE:
        fails.append(f"safe-set false-positive rate {rate:.1%} is above {MAX_FP_RATE:.0%}")
    if full:
        fails += [f"malicious sample scanned clean: {r.id}" for r in results
                  if r.expected == "malicious" and r.verdict == "clean"]
    return fails


# ------------------------------------------------------------------ output

def _pct(x: float | None) -> str:
    return "n/a" if x is None else f"{x:.0%}"


def table(m: dict, results: list[Result], mode: str, datadog: dict | None = None) -> str:
    o = m["overall"]
    lines = [
        f"Mode: **{mode}**. {len(results)} samples: {o['positives']} malicious or suspicious, {o['safe']} safe.",
        "",
        "| Category | Samples | Caught | Precision | Recall |",
        "|---|---|---|---|---|",
    ]
    for k, c in m["categories"].items():
        lines.append(f"| {k} | {c['n']} | {c['tp']}/{c['positives']} | {_pct(c['precision'])} | {_pct(c['recall'])} |")
    lines.append(f"| **all** | {o['n']} | {o['tp']}/{o['positives']} | {_pct(o['precision'])} | {_pct(o['recall'])} |")
    lines += [
        "",
        f"- **False-positive rate on the safe set:** {_pct(o['safe_fp_rate'])} ({o['safe_fp']}/{o['safe']})",
        (f"- **Flagged at all** (any non-clean verdict) among malicious samples: {_pct(o['detected_rate'])}"
         f" ({o['detected']}/{o['positives']})"),
        (f"- **Adversarial samples** (written to talk the AI reviewer out of a finding): "
         f"{o['adversarial_tp']}/{o['adversarial']} caught"),
    ]
    if datadog:
        for eco, d in sorted(datadog.items()):
            gd = f"; GuardDog {d['guarddog_detected']}/{d['guarddog_n']}" if d.get("guarddog_n") else ""
            lines.append(f"- **Real malware** (DataDog dataset, {eco}): flagged {d['detected']}/{d['n']}"
                         f" ({_pct(d['detected_rate'])}), malicious {d['malicious']}/{d['n']}{gd}")
    wrong = [r for r in results if not r.correct or (not r.positive and r.verdict != "clean")]
    if wrong:
        lines += ["", "Misclassified:", ""]
        for r in wrong:
            why = f" — {r.note}" if r.note else ""
            rules = ", ".join(r.rules) or "no findings"
            lines.append(f"- `{r.id}`: expected {r.expected}, got {r.verdict} ({rules}){why}")
    lines += [
        "",
        ("Correct means the verdict is at least the label (clean < suspicious < malicious). "
         "Precision counts clean-labelled samples that were flagged as false positives."),
    ]
    return "\n".join(lines)


def rewrite_readme(readme: Path, block: str) -> bool:
    text = readme.read_text()
    i, j = text.find(START), text.find(END)
    if i < 0 or j < i:
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
