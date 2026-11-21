"""OS-level isolation for the effectiveness evaluation (eval/run_eval.py --sandbox ...).

run_eval.py already gives every run a scratch HOME/BAWWAB_HOME/XDG, a dead proxy and a `claude` guard. Those are
environment variables: the harness and every hook child still run as the real user, with the real home writable and
the real network reachable by anything that ignores proxy variables. This module re-runs the harness inside an
OS sandbox, so a harness bug, a Bawwab bug or a replica that was accidentally executed cannot reach the real machine:

- ``bwrap``  (bubblewrap, unprivileged user namespaces). The real home is a blank tmpfs; the repo, the Python
  install, `uv` and the grammar cache are bound read-only at their own paths; only a scratch dir is writable; new
  network namespace (loopback only), pid/ipc/uts/cgroup namespaces, cleared environment.
- ``docker`` (a pinned image built from eval/Dockerfile, a copy of the repo baked in). No network, read-only root,
  all capabilities dropped, no-new-privileges, pid/memory/cpu limits, non-root user; only a scratch dir is
  mounted. Needs access to the Docker daemon.
- ``none``   the old behaviour: environment isolation only. It must be asked for explicitly.

Each runner only builds an argv; executing goes through an injectable callable, so tests use a fake executor and
never start a container. Inside the sandbox, run_eval.py runs ``self_check`` and refuses to produce numbers if the
real home, the repo or the network turns out to be reachable.
"""
from __future__ import annotations

import os
import shutil
import socket
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Sequence

ENV_ISOLATION = "BAWWAB_EVAL_ISOLATION"  # set by the runner for the inner run: bwrap | docker
ENV_HOST_HOME = "BAWWAB_EVAL_HOST_HOME"  # the real home on the host, which the inner run must not see
ENV_HOST_REPO = "BAWWAB_EVAL_HOST_REPO"  # the repo path on the host (bwrap: same path, read-only)
DOCKER_IMAGE = "bawwab-eval:local"
DOCKERFILE = "eval/Dockerfile"
PROTECTED_NAMES = (".claude", ".claude.json", ".bawwab", ".config/bawwab", ".ssh", ".aws", ".npmrc")

Exec = Callable[..., subprocess.CompletedProcess]


class IsolationUnavailable(RuntimeError):
    """The chosen isolation can't be used on this machine; the message says what to do."""


@dataclass
class Spec:
    """What the inner run needs from the host."""

    repo: Path                   # the Bawwab checkout (read-only inside)
    scratch: Path                # the only writable host dir; the inner workdir and results live here
    real_home: Path              # hidden inside the sandbox
    python: Path                 # the interpreter that runs run_eval.py (the repo's venv python)
    inner_args: list[str] = field(default_factory=list)  # run_eval.py arguments for the inner run
    uid: int = field(default_factory=os.getuid)
    gid: int = field(default_factory=os.getgid)

    @property
    def inner_workdir(self) -> Path:
        return self.scratch / "work"

    @property
    def inner_out(self) -> Path:
        return self.scratch / "out"


def _default_exec(argv: Sequence[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(list(argv), **kw)


class Runner:
    name = "?"

    def __init__(self, exec_: Exec | None = None, which: Callable[[str], str | None] | None = None):
        self.exec = exec_ or _default_exec
        self.which = which or (lambda name: shutil.which(name))

    def unavailable_reason(self) -> str | None:  # None = usable
        raise NotImplementedError

    def argv(self, spec: Spec) -> list[str]:
        raise NotImplementedError

    def prepare(self, spec: Spec) -> None:
        """One-time setup before the run (the docker image build)."""

    def run(self, spec: Spec) -> int:
        why = self.unavailable_reason()
        if why:
            raise IsolationUnavailable(why)
        self.prepare(spec)
        spec.inner_workdir.mkdir(parents=True, exist_ok=True)
        spec.inner_out.mkdir(parents=True, exist_ok=True)
        return self.exec(self.argv(spec)).returncode


# ------------------------------------------------------------------ bubblewrap

class BwrapRunner(Runner):
    name = "bwrap"

    def unavailable_reason(self) -> str | None:
        exe = self.which("bwrap")
        if not exe:
            return "bwrap (bubblewrap) is not installed: install the `bubblewrap` package, or use --sandbox docker"
        try:
            r = self.exec([exe, "--unshare-all", "--ro-bind", "/", "/", "--dev", "/dev", "--proc", "/proc", "true"],
                          capture_output=True, text=True, timeout=30)
        except (OSError, subprocess.TimeoutExpired) as e:
            return f"bwrap could not start: {type(e).__name__}: {e}"
        if r.returncode != 0:
            return ("bwrap cannot create unprivileged namespaces here "
                    f"({(r.stderr or '').strip()[-200:] or 'exit ' + str(r.returncode)}). On Ubuntu 24.04+ this is "
                    "the AppArmor userns restriction; use --sandbox docker instead")
        return None

    @staticmethod
    def _python_roots(python: Path) -> list[Path]:
        """The venv's base interpreter (pyvenv.cfg `home`), which lives outside the repo (uv's python store)."""
        roots: list[Path] = []
        cfg = python.parent.parent / "pyvenv.cfg"
        homes = []
        if cfg.is_file():
            for line in cfg.read_text().splitlines():
                k, _, v = line.partition("=")
                if k.strip() == "home":
                    homes.append(Path(v.strip()))
        homes.append(Path(sys.base_prefix) / "bin")
        for h in homes:
            for p in (h.parent, h.resolve().parent):  # both the symlinked and the real install dir
                if p.is_dir() and p not in roots and p != Path("/usr"):
                    roots.append(p)
        return roots

    def argv(self, spec: Spec) -> list[str]:
        exe = self.which("bwrap") or "bwrap"
        a = [exe, "--unshare-all", "--die-with-parent", "--new-session", "--clearenv",
             "--ro-bind", "/usr", "/usr", "--ro-bind", "/etc", "/etc"]
        for d in ("/bin", "/lib", "/lib64", "/lib32", "/sbin"):
            if os.path.islink(d):
                a += ["--symlink", os.readlink(d), d]
            elif os.path.isdir(d):
                a += ["--ro-bind", d, d]
        a += ["--proc", "/proc", "--dev", "/dev", "--tmpfs", "/tmp", "--tmpfs", "/var/tmp",
              "--tmpfs", "/run", "--tmpfs", str(spec.real_home)]
        ro: list[Path] = [spec.repo, *self._python_roots(spec.python)]
        uv = self.which("uv")
        for tool in ("uv", "uvx"):  # uvx: the mcp-scan baseline probe
            if t := self.which(tool):
                ro += [Path(t), Path(t).resolve()]
        ts = spec.real_home / ".cache" / "tree-sitter-language-pack"
        if ts.is_dir():
            ro.append(ts)
        seen = set()
        for p in ro:
            if str(p) not in seen and p.exists():
                seen.add(str(p))
                a += ["--ro-bind", str(p), str(p)]
        a += ["--bind", str(spec.scratch), str(spec.scratch)]
        path = ":".join(dict.fromkeys(([str(Path(uv).parent)] if uv else []) + ["/usr/bin", "/bin"]))
        env = {"PATH": path, "LANG": "C.UTF-8", "HOME": str(spec.scratch / "outer-home"),
               "TMPDIR": str(spec.scratch / "tmp"), "UV_CACHE_DIR": str(spec.scratch / "uv-cache"),
               # the repo is read-only: without this every hook call recompiles its modules (~40 ms each)
               "PYTHONPYCACHEPREFIX": str(spec.scratch / "pycache"),
               ENV_ISOLATION: self.name, ENV_HOST_HOME: str(spec.real_home), ENV_HOST_REPO: str(spec.repo)}
        for k, v in env.items():
            a += ["--setenv", k, v]
        a += ["--chdir", str(spec.scratch), str(spec.python), str(spec.repo / "eval" / "run_eval.py"),
              *spec.inner_args, "--sandbox", "none", "--workdir", str(spec.inner_workdir),
              "--out", str(spec.inner_out)]
        return a

    def run(self, spec: Spec) -> int:
        for d in ("outer-home", "tmp", "uv-cache"):
            (spec.scratch / d).mkdir(parents=True, exist_ok=True)
        return super().run(spec)


# ------------------------------------------------------------------ docker

class DockerRunner(Runner):
    name = "docker"

    def __init__(self, exec_: Exec | None = None, which=None, image: str = DOCKER_IMAGE,
                 build: bool = True):
        super().__init__(exec_, which)
        self.image = image
        self.build = build

    def unavailable_reason(self) -> str | None:
        exe = self.which("docker")
        if not exe:
            return "docker is not installed; install Docker, or use --sandbox bwrap"
        try:
            r = self.exec([exe, "info", "--format", "{{.ServerVersion}}"], capture_output=True, text=True,
                          timeout=60)
        except (OSError, subprocess.TimeoutExpired) as e:
            return f"docker could not run: {type(e).__name__}: {e}"
        if r.returncode == 0:
            return None
        err = ((r.stderr or "") + (r.stdout or "")).strip()
        if "permission denied" in err.lower():
            return ("the Docker daemon is not reachable: permission denied on the Docker socket. Add yourself to "
                    "the docker group (`sudo usermod -aG docker $USER`, then log out and back in, or `newgrp "
                    "docker`), or use rootless Docker; or run with --sandbox bwrap")
        if "cannot connect" in err.lower() or "is the docker daemon running" in err.lower():
            return "the Docker daemon is not running (`sudo systemctl start docker`); or run with --sandbox bwrap"
        return f"`docker info` failed: {err[-300:] or 'exit ' + str(r.returncode)}"

    def build_argv(self, spec: Spec) -> list[str]:
        return ["docker", "build", "--pull=false", "-t", self.image, "-f", str(spec.repo / DOCKERFILE),
                "--build-arg", f"UID={spec.uid}", "--build-arg", f"GID={spec.gid}", str(spec.repo)]

    def prepare(self, spec: Spec) -> None:
        if not self.build:
            return
        r = self.exec(self.build_argv(spec))
        if r.returncode != 0:
            raise IsolationUnavailable(f"building the evaluation image failed (exit {r.returncode}); see the "
                                       "docker build output above")

    def argv(self, spec: Spec) -> list[str]:
        return ["docker", "run", "--rm", "--network", "none", "--read-only", "--cap-drop", "ALL",
                "--security-opt", "no-new-privileges", "--pids-limit", "1024", "--memory", "4g", "--cpus", "4",
                "--user", f"{spec.uid}:{spec.gid}",
                "--tmpfs", "/tmp:rw,exec,size=1g",
                "--mount", f"type=bind,src={spec.scratch},dst=/scratch",
                "-e", f"{ENV_ISOLATION}={self.name}", "-e", f"{ENV_HOST_HOME}={spec.real_home}",
                "-e", f"{ENV_HOST_REPO}=/src", "-e", "UV_CACHE_DIR=/scratch/uv-cache",
                "-e", "HOME=/scratch/outer-home", "-e", "TMPDIR=/scratch/tmp",
                "-e", "PYTHONPYCACHEPREFIX=/scratch/pycache",
                self.image, "/src/.venv/bin/python", "/src/eval/run_eval.py", *spec.inner_args,
                "--sandbox", "none", "--workdir", "/scratch/work", "--out", "/scratch/out"]

    def run(self, spec: Spec) -> int:
        for d in ("uv-cache", "tmp", "outer-home"):
            (spec.scratch / d).mkdir(parents=True, exist_ok=True)
        return super().run(spec)


RUNNERS = {"bwrap": BwrapRunner, "docker": DockerRunner}


def choose(kind: str, exec_: Exec | None = None, which=None) -> Runner:
    """`auto` takes bwrap (fast, no image build), then docker; it never falls back to `none`."""
    if kind in RUNNERS:
        return RUNNERS[kind](exec_, which)
    if kind != "auto":
        raise ValueError(f"unknown sandbox {kind!r}")
    reasons = []
    for name in ("bwrap", "docker"):
        r = RUNNERS[name](exec_, which)
        why = r.unavailable_reason()
        if why is None:
            return r
        reasons.append(f"{name}: {why}")
    raise IsolationUnavailable("no sandbox is available:\n  " + "\n  ".join(reasons) +
                               "\nRun with --sandbox none to accept environment-only isolation (recorded in "
                               "meta.json).")


# ------------------------------------------------------------------ inside the sandbox

def _net_reachable(host: str = "192.0.2.1", port: int = 9, timeout: float = 1.0) -> str | None:
    """None when no route leaves the box. 192.0.2.1 (TEST-NET-1) never answers; in a network namespace with only
    loopback the connect fails at once with ENETUNREACH, while on a real network it times out or is refused."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((host, port))
        return f"connected to {host}:{port}"
    except OSError as e:
        if e.errno in (101,):  # ENETUNREACH: no interface but loopback
            return None
        return f"{type(e).__name__}: {e}"  # timeout or refused means a route exists
    finally:
        s.close()


def self_check(repo: Path, env: dict | None = None, net: Callable[[], str | None] = _net_reachable) -> dict:
    """Run by the inner harness before any entry. Proves the sandbox does what it claims, from the inside."""
    env = os.environ if env is None else env
    kind = env.get(ENV_ISOLATION)
    checks: dict = {}
    host_home = env.get(ENV_HOST_HOME)
    if host_home:
        seen = [n for n in PROTECTED_NAMES if os.path.lexists(os.path.join(host_home, n))]
        checks["host_home_hidden"] = {"ok": not seen, "visible": seen}
    else:
        checks["host_home_hidden"] = {"ok": False, "visible": ["(host home not given)"]}
    probe = repo / f".bawwab-eval-write-probe-{os.getpid()}"
    try:
        probe.write_text("x")
        probe.unlink()
        checks["repo_read_only"] = {"ok": False, "detail": "the repo is writable"}
    except OSError as e:
        checks["repo_read_only"] = {"ok": True, "detail": type(e).__name__}
    why = net()
    checks["no_network"] = {"ok": why is None, "detail": why or "ENETUNREACH"}
    checks["not_root"] = {"ok": os.getuid() != 0, "uid": os.getuid()}
    return {"runner": kind, "ok": all(c["ok"] for c in checks.values()), "checks": checks}
