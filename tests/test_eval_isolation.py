"""The evaluation's OS sandbox (eval/isolation.py) and the reproducibility check (run_eval.compare_results).

Docker is never started here: the Docker runner is tested through a fake executor. One test runs a small part of
the harness inside bubblewrap for real when bwrap works on this machine.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("run_eval", ROOT / "eval" / "run_eval.py")
run_eval = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(run_eval)
iso = run_eval._isolation()


class FakeExec:
    """Records every argv; answers from a table of (argv prefix -> CompletedProcess or callable)."""

    def __init__(self, answers=None):
        self.calls: list[list[str]] = []
        self.answers = answers or {}

    def __call__(self, argv, **kw):
        argv = list(argv)
        self.calls.append(argv)
        for prefix, ans in self.answers.items():
            if tuple(argv[:len(prefix)]) == prefix:
                return ans(argv) if callable(ans) else ans
        return subprocess.CompletedProcess(argv, 0, "", "")


def which_all(name):
    return f"/usr/bin/{name}"


def which_none(name):
    return None


def _spec_for(tmp_path) -> "iso.Spec":
    home = tmp_path / "realhome"
    (home / ".claude").mkdir(parents=True)
    return iso.Spec(repo=ROOT, scratch=tmp_path / "scratch", real_home=home, python=ROOT / ".venv" / "bin" / "python",
                    inner_args=["--only", "attacks"])


def _pairs(argv, flag):
    return [(argv[i + 1], argv[i + 2]) for i, x in enumerate(argv) if x == flag]


# ------------------------------------------------------------------ bwrap


def test_bwrap_argv_hides_home_and_writes_only_scratch(tmp_path):
    spec = _spec_for(tmp_path)
    a = iso.BwrapRunner(FakeExec(), which_all).argv(spec)
    assert a[0] == "/usr/bin/bwrap"
    for flag in ("--unshare-all", "--die-with-parent", "--new-session", "--clearenv"):
        assert flag in a
    assert ("--tmpfs", str(spec.real_home)) in zip(a, a[1:])
    # the real home is masked before anything below it is bound back read-only
    i_home = a.index(str(spec.real_home))
    assert all(a.index(src) > i_home for src, _ in _pairs(a, "--ro-bind") if src.startswith(str(spec.real_home)))
    assert _pairs(a, "--bind") == [(str(spec.scratch), str(spec.scratch))]  # the only writable host path
    assert (str(ROOT), str(ROOT)) in _pairs(a, "--ro-bind")
    assert str(spec.real_home) not in [s for s, _ in _pairs(a, "--ro-bind")]
    env = dict(_pairs(a, "--setenv"))
    assert env[iso.ENV_ISOLATION] == "bwrap" and env[iso.ENV_HOST_HOME] == str(spec.real_home)
    assert env["HOME"].startswith(str(spec.scratch)) and env["UV_CACHE_DIR"].startswith(str(spec.scratch))
    tail = a[a.index(str(ROOT / "eval" / "run_eval.py")):]
    assert tail[1:3] == ["--only", "attacks"]
    assert tail[tail.index("--sandbox") + 1] == "none"  # the inner run never recurses
    assert tail[tail.index("--workdir") + 1].startswith(str(spec.scratch))
    assert tail[tail.index("--out") + 1].startswith(str(spec.scratch))


def test_bwrap_missing_or_blocked_is_a_clear_error(tmp_path):
    assert "not installed" in iso.BwrapRunner(FakeExec(), which_none).unavailable_reason()
    blocked = FakeExec({("/usr/bin/bwrap",): subprocess.CompletedProcess([], 1, "", "setting up uid map: "
                                                                          "Permission denied")})
    why = iso.BwrapRunner(blocked, which_all).unavailable_reason()
    assert "unprivileged namespaces" in why and "--sandbox docker" in why
    with pytest.raises(iso.IsolationUnavailable):
        iso.BwrapRunner(blocked, which_all).run(_spec_for(tmp_path))
    assert len(blocked.calls) == 2 and all("run_eval.py" not in " ".join(c) for c in blocked.calls)


# ------------------------------------------------------------------ docker (never started)

DENIED = subprocess.CompletedProcess([], 1, "", "permission denied while trying to connect to the docker API at "
                                                "unix:///var/run/docker.sock")


def test_docker_unreachable_daemon_is_a_clear_error(tmp_path):
    fx = FakeExec({("/usr/bin/docker", "info"): DENIED})
    r = iso.DockerRunner(fx, which_all)
    why = r.unavailable_reason()
    assert "permission denied" in why and "docker group" in why and "--sandbox bwrap" in why
    with pytest.raises(iso.IsolationUnavailable, match="docker group"):
        r.run(_spec_for(tmp_path))
    assert {c[1] for c in fx.calls} == {"info"}  # no build, no run
    assert "not installed" in iso.DockerRunner(FakeExec(), which_none).unavailable_reason()
    down = FakeExec({("/usr/bin/docker", "info"): subprocess.CompletedProcess(
        [], 1, "", "Cannot connect to the Docker daemon. Is the docker daemon running?")})
    assert "not running" in iso.DockerRunner(down, which_all).unavailable_reason()


def test_docker_argv_is_locked_down(tmp_path):
    spec = _spec_for(tmp_path)
    fx = FakeExec()
    r = iso.DockerRunner(fx, which_all)
    a = r.argv(spec)
    s = " ".join(a)
    for part in ("--network none", "--read-only", "--cap-drop ALL", "--security-opt no-new-privileges",
                 f"--user {spec.uid}:{spec.gid}", "--pids-limit", "--memory"):
        assert part in s
    mounts = [a[i + 1] for i, x in enumerate(a) if x in ("--mount", "-v", "--volume")]
    assert mounts == [f"type=bind,src={spec.scratch},dst=/scratch"]  # no repo, no home
    assert str(spec.real_home) not in " ".join(mounts)
    assert a[a.index(iso.DOCKER_IMAGE) + 1:a.index(iso.DOCKER_IMAGE) + 3] == ["/src/.venv/bin/python",
                                                                          "/src/eval/run_eval.py"]
    assert a[a.index("--sandbox") + 1] == "none"
    assert f"{iso.ENV_ISOLATION}=docker" in a
    # a full run builds the image first, then runs it
    assert r.run(spec) == 0
    assert [c[1] for c in fx.calls] == ["info", "build", "run"]
    assert "--build-arg" in fx.calls[1] and str(ROOT / "eval" / "Dockerfile") in fx.calls[1]


def test_docker_build_failure_refuses(tmp_path):
    fx = FakeExec({("docker", "build"): subprocess.CompletedProcess([], 1, "", "")})
    with pytest.raises(iso.IsolationUnavailable, match="building the evaluation image failed"):
        iso.DockerRunner(fx, which_all).run(_spec_for(tmp_path))
    assert not any(c[:2] == ["docker", "run"] for c in fx.calls)


def test_dockerfile_bakes_the_repo_and_runs_unprivileged():
    text = (ROOT / "eval" / "Dockerfile").read_text()
    assert "COPY --chown=eval:eval . /src" in text and "USER eval" in text and "uv sync --frozen" in text
    ignore = (ROOT / ".dockerignore").read_text().split()
    assert ".git" in ignore and ".venv" in ignore


# ------------------------------------------------------------------ choosing


def test_auto_prefers_bwrap_and_never_falls_back_to_none():
    assert iso.choose("auto", FakeExec(), which_all).name == "bwrap"
    fx = FakeExec({("/usr/bin/bwrap",): subprocess.CompletedProcess([], 1, "", "no userns"),
                   ("/usr/bin/docker", "info"): DENIED})
    with pytest.raises(iso.IsolationUnavailable) as e:
        iso.choose("auto", fx, which_all)
    assert "bwrap:" in str(e.value) and "docker:" in str(e.value) and "--sandbox none" in str(e.value)
    fx2 = FakeExec({("/usr/bin/bwrap",): subprocess.CompletedProcess([], 1, "", "no userns")})
    assert iso.choose("auto", fx2, which_all).name == "docker"
    with pytest.raises(ValueError):
        iso.choose("chroot")


# ------------------------------------------------------------------ the outer run


def _args(tmp_path, **kw):
    d = dict(sandbox="docker", only="attacks", ids="heredoc-bash", keep=False, workdir=str(tmp_path / "wd"),
             out=str(tmp_path / "out"), no_write=False, compare=None)
    d.update(kw)
    return argparse.Namespace(**d)


def _fake_inner(runner_name, ok=True):
    """A fake `docker run` that writes what the inner harness would."""
    def run(argv):
        out = Path(argv[argv.index("--mount") + 1].split("src=")[1].split(",")[0]) / "out"
        out.mkdir(parents=True, exist_ok=True)
        (out / "meta.json").write_text(json.dumps({"meta": {"isolation": {"runner": runner_name, "ok": ok}}}))
        (out / "attacks.json").write_text(json.dumps([{"id": "heredoc-bash", "outcome": "blocked"}]))
        return subprocess.CompletedProcess(argv, 0, "", "")
    return run


def test_run_isolated_unreachable_docker_refuses(tmp_path, capsys, monkeypatch):
    monkeypatch.setattr(iso.shutil, "which", which_all)
    fx = FakeExec({("/usr/bin/docker", "info"): DENIED})
    assert run_eval.run_isolated(_args(tmp_path), exec_=fx) == 2
    assert "docker group" in capsys.readouterr().err
    assert not (tmp_path / "out").exists()


def test_run_isolated_copies_results_and_records_commit(tmp_path, monkeypatch):
    monkeypatch.setattr(iso.shutil, "which", which_all)
    fx = FakeExec({("docker", "run"): _fake_inner("docker")})
    assert run_eval.run_isolated(_args(tmp_path), exec_=fx) == 0
    meta = json.loads((tmp_path / "out" / "meta.json").read_text())["meta"]
    assert meta["isolation"]["runner"] == "docker" and "commit" in meta and "dirty" in meta
    assert (tmp_path / "out" / "attacks.json").exists()
    assert list((tmp_path / "wd").iterdir()) == []  # scratch removed


@pytest.mark.parametrize("name,ok", [("none", True), ("docker", False)])
def test_run_isolated_rejects_an_unconfirmed_sandbox(tmp_path, monkeypatch, name, ok):
    monkeypatch.setattr(iso.shutil, "which", which_all)
    fx = FakeExec({("docker", "run"): _fake_inner(name, ok)})
    assert run_eval.run_isolated(_args(tmp_path), exec_=fx) == 1
    assert not (tmp_path / "out").exists()


# ------------------------------------------------------------------ inside: the self-check


def test_self_check_fails_when_home_repo_or_network_leak(tmp_path):
    home = tmp_path / "home"
    (home / ".claude").mkdir(parents=True)
    env = {iso.ENV_ISOLATION: "bwrap", iso.ENV_HOST_HOME: str(home)}
    r = iso.self_check(tmp_path, env, net=lambda: "connected to 192.0.2.1:9")
    assert not r["ok"]
    c = r["checks"]
    assert c["host_home_hidden"]["visible"] == [".claude"]
    assert not c["repo_read_only"]["ok"] and not c["no_network"]["ok"]
    assert not list(tmp_path.glob(".bawwab-eval-write-probe-*"))  # the probe cleans up after itself
    assert not iso.self_check(tmp_path, {iso.ENV_ISOLATION: "bwrap"}, net=lambda: None)["ok"]


def test_inner_run_refuses_a_leaky_sandbox(monkeypatch, capsys, tmp_path):
    (tmp_path / ".claude").mkdir()
    monkeypatch.setenv(iso.ENV_ISOLATION, "bwrap")
    monkeypatch.setenv(iso.ENV_HOST_HOME, str(tmp_path))  # a "host home" that is visible: not isolated
    assert run_eval.main(["--sandbox", "none", "--no-write", "--only", "baseline"]) == 3
    assert "leaky" in capsys.readouterr().err


# ------------------------------------------------------------------ reproducibility


def test_compare_results(tmp_path):
    a, b = tmp_path / "a", tmp_path / "b"
    shutil.copytree(run_eval.RESULTS, a)
    shutil.copytree(run_eval.RESULTS, b)
    assert run_eval.compare_results(a, b) == []
    lat = json.loads((b / "latency.json").read_text())
    lat["prefilter_bash_ls"]["median_ms"] += 50  # timings are not compared
    (b / "latency.json").write_text(json.dumps(lat))
    att = json.loads((b / "attacks.json").read_text())
    att[0]["gate"][0]["ms"] = 1.0
    att[0]["gate"][0]["reason"] = "reworded"
    (b / "attacks.json").write_text(json.dumps(att))
    assert run_eval.compare_results(a, b) == []
    att[1]["outcome"] = "missed"
    (b / "attacks.json").write_text(json.dumps(att))
    diffs = run_eval.compare_results(a, b)
    assert diffs == [f"attacks/{att[1]['id']}/outcome: expected \"{json.loads((a / 'attacks.json').read_text())[1]['outcome']}\", got \"missed\""]  # noqa: E501
    # a partial run is compared on the entries it ran; its summary is skipped
    (b / "attacks.json").write_text(json.dumps(json.loads((a / "attacks.json").read_text())[:3]))
    (b / "summary.json").write_text("{}")
    assert run_eval.compare_results(a, b) == []


def test_committed_results_name_their_sandbox():
    """Committed numbers must say how they were isolated (and from which commit)."""
    meta = json.loads((run_eval.RESULTS / "meta.json").read_text())["meta"]
    assert meta["isolation"]["runner"] in ("bwrap", "docker", "none")
    assert meta["isolation"]["ok"] is True
    assert meta.get("commit")


# ------------------------------------------------------------------ real bubblewrap (when it works here)

_bwrap_why = iso.BwrapRunner().unavailable_reason()


@pytest.mark.skipif(_bwrap_why is not None, reason=f"bwrap unusable: {_bwrap_why}")
def test_real_bwrap_run_confirms_isolation(tmp_path):
    base = "/var/tmp" if Path("/var/tmp").is_dir() else None
    import tempfile

    wd = Path(tempfile.mkdtemp(prefix="bawwab-iso-test-", dir=base))
    try:
        a = _args(tmp_path, sandbox="bwrap", only="baseline", ids="", workdir=str(wd / "w"))
        assert run_eval.run_isolated(a) == 0
        meta = json.loads((tmp_path / "out" / "meta.json").read_text())["meta"]
        assert meta["isolation"]["runner"] == "bwrap" and meta["isolation"]["ok"], meta
        assert all(c["ok"] for c in meta["isolation"]["checks"].values()), meta
    finally:
        shutil.rmtree(wd, ignore_errors=True)
