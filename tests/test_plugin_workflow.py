"""The plugin publish workflow (.github/workflows/plugin.yml) and scripts/publish_plugin.sh (R51)."""
from __future__ import annotations

import importlib.util
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "plugin.yml"
PUBLISH = ROOT / "scripts" / "publish_plugin.sh"


@pytest.fixture(scope="module")
def wf() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def _steps(wf: dict, job: str) -> list[dict]:
    return wf["jobs"][job]["steps"]


def _uses(wf: dict, job: str, action: str) -> list[dict]:
    return [s for s in _steps(wf, job) if (s.get("uses") or "").startswith(action + "@")]


def _runs(wf: dict, job: str) -> str:
    return "\n".join(s.get("run") or "" for s in _steps(wf, job))


# ------------------------------------------------------------------ workflow shape

def test_runs_on_push_to_main_and_on_demand(wf):
    on = wf.get("on", wf.get(True))  # YAML 1.1 reads a bare `on` key as True
    assert on["push"] == {"branches": ["main"]}
    assert "workflow_dispatch" in on
    assert set(on) == {"push", "workflow_dispatch"}  # never pull_request: forks must not reach the write job
    assert wf["concurrency"] == {"group": "plugin", "cancel-in-progress": False}


def test_permissions_are_least_privilege(wf):
    assert wf.get("permissions") == {}
    assert set(wf["jobs"]) == {"build", "publish"}
    assert wf["jobs"]["build"]["permissions"] == {"contents": "read"}
    assert wf["jobs"]["publish"]["permissions"] == {"contents": "write"}
    assert wf["jobs"]["publish"]["needs"] == "build"


def test_every_action_is_pinned_by_full_sha():
    uses = re.findall(r"uses:\s*(\S+)(.*)", WORKFLOW.read_text())
    assert uses
    for ref, comment in uses:
        assert re.search(r"@[0-9a-f]{40}$", ref), ref
        assert re.search(r"#\s*v\d+\.\d+\.\d+", comment), f"{ref}: tag comment missing"


def test_no_secrets_and_no_stored_token(wf):
    text = WORKFLOW.read_text()
    assert "secrets." not in text
    for job in wf["jobs"]:
        for s in _uses(wf, job, "actions/checkout"):
            assert s["with"]["persist-credentials"] is False
    assert "github.token" not in repr(_steps(wf, "build"))
    # the token reaches git only through the environment of the push step, never argv or .git/config
    token_steps = [s for s in _steps(wf, "publish") if "github.token" in repr(s)]
    assert len(token_steps) == 1 and token_steps[0]["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert "GIT_CONFIG_VALUE_0" in token_steps[0]["run"] and "git config" not in text


def test_build_job_tests_then_builds_with_build_plugin(wf):
    runs = [s.get("run") or "" for s in _steps(wf, "build")]
    i_test = next(i for i, r in enumerate(runs) if "pytest" in r)
    i_build = next(i for i, r in enumerate(runs) if "scripts/build_plugin.py" in r)
    assert i_test < i_build
    for t in ("tests/test_plugin_self.py", "tests/test_plugin_workflow.py", "tests/test_e2e.py::test_plugin_manifest",
              "tests/test_e2e.py::test_marketplace_manifest"):
        assert t in runs[i_test]
    assert 'scripts/build_plugin.py "$RUNNER_TEMP/plugin"' in runs[i_build]
    assert 'tar -C "$RUNNER_TEMP/plugin" -cf "$RUNNER_TEMP/plugin.tar" .' in runs[i_build]  # tar keeps exec bits
    (up,) = _uses(wf, "build", "actions/upload-artifact")
    assert up["with"]["name"] == "plugin-tree" and up["with"]["path"] == "${{ runner.temp }}/plugin.tar"
    assert all("continue-on-error" not in s for j in wf["jobs"] for s in _steps(wf, j))


def test_publish_job_pushes_only_the_built_tree(wf):
    run = _runs(wf, "publish")
    (down,) = _uses(wf, "publish", "actions/download-artifact")
    assert down["with"]["name"] == "plugin-tree"
    assert 'tar -C "$RUNNER_TEMP/plugin" -xf "$RUNNER_TEMP/artifact/plugin.tar"' in run
    assert 'scripts/publish_plugin.sh "$RUNNER_TEMP/plugin" "$GITHUB_SHA" $parent' in run
    # the write job installs and runs nothing from the project but the publish script
    assert not _uses(wf, "publish", "astral-sh/setup-uv")
    for banned in ("uv ", "pytest", "pip", "build_plugin.py", "--force", "push -f", "+refs/heads/plugin:refs/heads"):
        assert banned not in run, banned
    pushes = re.findall(r"git push .*", run)
    assert pushes == ['git push origin "$commit:refs/heads/plugin"']  # fast-forward only: linear history


# ------------------------------------------------------------------ publish_plugin.sh

def _git(cwd: Path, *args: str) -> str:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    return subprocess.run(["git", *args], cwd=cwd, env=env, check=True, capture_output=True, text=True).stdout.strip()


def _publish(repo: Path, tree: Path, src: str, parent: str = "") -> subprocess.CompletedProcess:
    env = {**os.environ, "GIT_AUTHOR_NAME": "t", "GIT_AUTHOR_EMAIL": "t@t", "GIT_COMMITTER_NAME": "t",
           "GIT_COMMITTER_EMAIL": "t@t", "GIT_CONFIG_GLOBAL": os.devnull, "GIT_CONFIG_NOSYSTEM": "1"}
    args = [str(PUBLISH), str(tree), src] + ([parent] if parent else [])
    return subprocess.run(args, cwd=repo, env=env, check=True, capture_output=True, text=True)


def _build(out: Path) -> Path:
    spec = importlib.util.spec_from_file_location("_build_plugin", ROOT / "scripts" / "build_plugin.py")
    m = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(m)
    return m.build(out)


def _bump(tree: Path, version: str) -> None:
    p = tree / ".claude-plugin" / "plugin.json"
    m = json.loads(p.read_text())
    m["version"] = version
    p.write_text(json.dumps(m))


@pytest.mark.skipif(not shutil.which("git"), reason="needs git")
def test_publish_script_commits_exactly_the_built_tree(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    (repo / ".gitignore").write_text("*\n")  # the repo's ignores must not drop files from the published tree
    tree = _build(tmp_path / "tree")
    version = json.loads((tree / ".claude-plugin/plugin.json").read_text())["version"]

    first = _publish(repo, tree, "a" * 40).stdout.strip()
    assert _git(repo, "log", "--format=%s", first) == f"bawwab {version} from {'a' * 40}"
    assert _git(repo, "rev-list", "--count", first) == "1"
    listed = set(_git(repo, "ls-tree", "-r", "--name-only", first).splitlines())
    on_disk = {p.relative_to(tree).as_posix() for p in tree.rglob("*") if p.is_file()}
    assert listed == on_disk
    assert _git(repo, "ls-tree", first, "bin/bawwab").split()[0] == "100755"  # the launcher stays executable

    # nothing changed: nothing to publish
    assert _publish(repo, tree, "b" * 40, first).stdout == ""
    # code changed, version kept: not published (Claude Code would serve users the cached old copy)
    (tree / "README.md").write_text("changed\n")
    r = _publish(repo, tree, "c" * 40, first)
    assert r.stdout == "" and "bump the version" in r.stderr
    # bumped: a new commit on top of the previous release, tree exactly the new build
    _bump(tree, "99.0.0")
    second = _publish(repo, tree, "d" * 40, first).stdout.strip()
    assert _git(repo, "rev-parse", f"{second}^") == first
    assert _git(repo, "show", f"{second}:README.md") == "changed"
    assert _git(repo, "log", "-1", "--format=%s", second) == f"bawwab 99.0.0 from {'d' * 40}"
    assert _git(repo, "for-each-ref") == "" and not (repo / ".git" / "index").exists()  # no ref or index touched
