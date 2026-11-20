"""Real-malware recall set: the DataDog malicious-software-packages-dataset (Apache-2.0).

    uv run python bench/fetch_datadog.py [--all] [--guarddog] [--json OUT]   # scan the recall set (static)
    uv run python bench/fetch_datadog.py --lock                               # re-pin the default sample

Samples are encrypted zips (password "infected"). They are downloaded at a pinned commit into
bench/.cache/datadog/ (git-ignored), checked against pinned checksums, and unpacked ONLY with Bawwab's
own safe extractor into a temporary folder outside the repository, then scanned as local targets.
Nothing is ever installed, imported or executed, and nothing from the dataset is committed: the lock
file holds only paths and checksums.

The default run is a reproducible sample of ~100 npm and ~100 PyPI "malicious_intent" packages chosen
deterministically (see select()); --all scans every sample in the pinned trees.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

import httpx

from bawwab.fetch.common import download
from bawwab.fetch.extract import extract_archive
from bawwab.types import Target

BENCH = Path(__file__).resolve().parent
CACHE = BENCH / ".cache" / "datadog"
LOCK = BENCH / "datadog.lock.json"
REPO = "DataDog/malicious-software-packages-dataset"
COMMIT = "72c723be547033c558244520524b117c8d71663b"  # main, 2026-11-05
TREES = {  # git tree of samples/<eco>/malicious_intent at COMMIT
    "npm": "cb873a4e837ca87bd2975dd699c92547229f748a",
    "pypi": "87dd5c123d47b5812367e45adddaebb17cea8586",
}
PASSWORD = b"infected"
PER_ECOSYSTEM = 100
MAX_ZIP_BYTES = 2 * 1024 * 1024  # keeps the default sample quick; --all has no cap
LEVELS = {"clean": 0, "suspicious": 1, "malicious": 2}


def _raw_url(eco: str, path: str) -> str:
    return f"https://raw.githubusercontent.com/{REPO}/{COMMIT}/samples/{eco}/malicious_intent/{path}"


def list_tree(eco: str) -> list[dict]:
    r = httpx.get(f"https://api.github.com/repos/{REPO}/git/trees/{TREES[eco]}?recursive=1", timeout=120,
                  follow_redirects=True)
    r.raise_for_status()
    d = r.json()
    if d.get("truncated"):
        raise RuntimeError(f"{eco} tree listing is truncated")
    return [{"path": e["path"], "size": e["size"], "blob": e["sha"]} for e in d["tree"]
            if e.get("type") == "blob" and e["path"].endswith(".zip")]


def select(eco: str, entries: list[dict], n: int = PER_ECOSYSTEM, max_bytes: int | None = MAX_ZIP_BYTES) -> list[dict]:
    """One zip per package (its lowest path), packages ordered by sha256(commit:eco:package), first n."""
    per_pkg: dict[str, dict] = {}
    for e in sorted(entries, key=lambda e: e["path"]):
        if max_bytes is not None and e["size"] > max_bytes:
            continue
        per_pkg.setdefault(e["path"].split("/", 1)[0], e)
    order = sorted(per_pkg, key=lambda p: hashlib.sha256(f"{COMMIT}:{eco}:{p}".encode()).hexdigest())
    picked = order if n is None else order[:n]
    return [{"ecosystem": eco, "package": p, **per_pkg[p]} for p in picked]


def _git_blob_sha(path: Path) -> str:
    data = path.read_bytes()
    return hashlib.sha1(b"blob %d\0" % len(data) + data).hexdigest()


def fetch(s: dict) -> Path:
    """The cached encrypted zip for a sample, downloaded and verified if missing."""
    dest = CACHE / s["ecosystem"] / f"{s['blob']}.zip"
    if dest.is_file() and _git_blob_sha(dest) == s["blob"] and (
        not s.get("sha256") or hashlib.sha256(dest.read_bytes()).hexdigest() == s["sha256"]
    ):
        return dest
    dest.parent.mkdir(parents=True, exist_ok=True)
    part = dest.with_suffix(".part")
    download(_raw_url(s["ecosystem"], s["path"]), part, 120, sha256=s.get("sha256"))
    if _git_blob_sha(part) != s["blob"]:
        part.unlink(missing_ok=True)
        raise RuntimeError(f"git blob mismatch for {s['path']}")
    part.replace(dest)
    return dest


def package_root(top: Path, eco: str) -> Path:
    """The folder holding the package itself (DataDog wraps it with a package_info-*.json)."""
    markers = ("package.json",) if eco == "npm" else ("setup.py", "pyproject.toml", "PKG-INFO", "setup.cfg")
    best = None
    for m in markers:
        for p in top.rglob(m):
            if p.is_file() and not p.is_symlink() and (best is None or len(p.parent.parts) < len(best.parts)):
                best = p.parent
        if best is not None:
            break
    return best or top


def unpack(zip_path: Path, eco: str, work: Path) -> tuple[Path, list]:
    work.mkdir(parents=True, exist_ok=True)
    findings = extract_archive(zip_path, work, password=PASSWORD)
    return package_root(work, eco), findings


def guarddog_scan(eco: str, root: Path) -> bool | None:
    """True/False when GuardDog flags the folder or not; None if it could not run."""
    cmd = ["uvx", "--quiet", "--python", "3.12", "guarddog@3.2.0", eco, "scan", str(root), "--output-format", "json"]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=300, cwd=tempfile.gettempdir(), check=False)
        start = p.stdout.find("{")
        d = json.loads(p.stdout[start:]) if start >= 0 else None
    except (OSError, subprocess.TimeoutExpired, ValueError):
        return None
    if not isinstance(d, dict) or "issues" not in d:
        return None
    return int(d["issues"]) > 0


def samples(everything: bool) -> list[dict]:
    if everything:
        return [s for eco in TREES for s in select(eco, list_tree(eco), n=None, max_bytes=None)]
    lock = json.loads(LOCK.read_text())
    if lock.get("commit") != COMMIT:
        raise RuntimeError("datadog.lock.json was made for a different commit; run --lock")
    return lock["samples"]


def recall(scanner, everything: bool = False, guarddog: bool = False, out: list | None = None) -> dict:
    """Scan the recall set with a bench Scanner. Returns per-ecosystem counts."""
    res: dict[str, dict] = {}
    tmp = Path(tempfile.mkdtemp(prefix="bawwab-datadog-"))  # outside the repo
    try:
        for i, s in enumerate(samples(everything)):
            eco = s["ecosystem"]
            d = res.setdefault(eco, {"n": 0, "detected": 0, "malicious": 0, "errors": 0,
                                     "guarddog_n": 0, "guarddog_detected": 0})
            work = tmp / str(i)
            try:
                root, _ = unpack(fetch(s), eco, work)
                r = scanner.scan(Target("local", str(root), name=s["package"], path=str(root.resolve())),
                                 scanner.local_store)
                verdict = r.verdict.value
                rules = scanner.counted(r)
            except Exception as e:  # noqa: BLE001 - one bad sample must not stop the run
                d["errors"] += 1
                print(f"  error      {eco}/{s['package']}: {type(e).__name__}: {e}", file=sys.stderr)
                shutil.rmtree(work, ignore_errors=True)
                continue
            d["n"] += 1
            d["detected"] += verdict != "clean"
            d["malicious"] += verdict == "malicious"
            gd = guarddog_scan(eco, root) if guarddog else None
            if gd is not None:
                d["guarddog_n"] += 1
                d["guarddog_detected"] += gd
            if out is not None:
                out.append({"ecosystem": eco, "package": s["package"], "verdict": verdict, "rules": rules,
                            "guarddog": gd})
            print(f"  {verdict:10} {eco}/{s['package']}" + ("" if gd is None else f"  guarddog={gd}"), file=sys.stderr)
            shutil.rmtree(work, ignore_errors=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)
    for d in res.values():
        d["detected_rate"] = round(d["detected"] / d["n"], 4) if d["n"] else None
    return res


def write_lock() -> None:
    picked = []
    for eco in TREES:
        for s in select(eco, list_tree(eco)):
            z = fetch(s)
            picked.append({**s, "sha256": hashlib.sha256(z.read_bytes()).hexdigest()})
            print(f"  locked {eco}/{s['package']}", file=sys.stderr)
    LOCK.write_text(json.dumps({"dataset": REPO, "commit": COMMIT, "trees": TREES, "samples": picked}, indent=1) + "\n")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--lock", action="store_true", help="re-select the default sample and pin its checksums")
    ap.add_argument("--all", action="store_true", help="scan every sample at the pinned commit")
    ap.add_argument("--guarddog", action="store_true", help="also run GuardDog (uvx) as a baseline")
    ap.add_argument("--json", type=Path, help="write per-sample results here")
    a = ap.parse_args(argv)
    if a.lock:
        write_lock()
        return 0
    sys.path.insert(0, str(BENCH))
    from run import Scanner

    sc = Scanner(static_only=True, backend="api", no_cache=True)
    rows: list = []
    try:
        res = recall(sc, everything=a.all, guarddog=a.guarddog, out=rows)
    finally:
        sc.close()
    print(json.dumps(res, indent=2))
    if a.json:
        a.json.write_text(json.dumps({"summary": res, "samples": rows}, indent=1) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
