"""The real deep-mode runner: the docker CLI, driven through subprocess.

One run is three Docker objects, all labelled `bawwab.sandbox=<run id>` and always removed afterwards:
  - an `--internal` bridge network (no route out of it, not even to the host's networks);
  - the network trap (proxy.py), the only other host on that network;
  - the sandbox container (harness.py as PID 1), with the target mounted read-only at /target.
Both containers: read-only root, non-root user, every capability dropped, no-new-privileges, pid/memory/cpu
limits. The sandbox gets tmpfs for its workdir, its decoy home and /tmp, and nothing else writable.

Anything that stops the run from happening at all (no docker, daemon unreachable, image missing, docker
refusing a command) raises SandboxUnavailable: the caller records `sandbox.unavailable` (MED, fail closed).
"""
from __future__ import annotations

import json
import os
import re
import secrets
import subprocess
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from bawwab.report import sanitise
from bawwab.sandbox.canary import HOME, decoy_env, decoy_files, make_canaries
from bawwab.sandbox.observe import Observation, analyze
from bawwab.sandbox.plan import WORK, Plan, plan_for
from bawwab.types import Fetched, Finding, Severity, ToolInfo

SANDBOX_UID = "10001:10001"
PROXY_UID = "65534:65534"
PROXY_PORT = 3128
LABEL = "bawwab.sandbox"
MAX_STDOUT = 32 * 1024 * 1024


class SandboxUnavailable(Exception):
    """The sandbox could not run (fail closed: the scan gets sandbox.unavailable)."""


@dataclass
class Result:
    returncode: int
    stdout: bytes
    stderr: bytes
    timed_out: bool = False


Exec = Callable[[list[str], bytes | None, float], Result]


def _run_cmd(argv: list[str], stdin: bytes | None, timeout: float) -> Result:
    """Run one docker CLI command. Never raises for a non-zero exit; a missing binary raises OSError."""
    from bawwab.limits import child_argv  # docker (Go) must not inherit the scan's address-space limit

    try:
        p = subprocess.run(child_argv(argv), input=stdin, capture_output=True, timeout=timeout,
                           stdin=None if stdin is not None else subprocess.DEVNULL)
        return Result(p.returncode, p.stdout[:MAX_STDOUT], p.stderr[:65536])
    except subprocess.TimeoutExpired as e:
        return Result(-1, (e.stdout or b"")[:MAX_STDOUT], (e.stderr or b"")[:65536], timed_out=True)


@dataclass
class Limits:
    memory: str = "1g"
    cpus: str = "1"
    pids: int = 256
    work_size: str = "1g"
    home_size: str = "64m"
    tmp_size: str = "64m"
    nofile: int = 1024


def image_record_path() -> Path:
    from bawwab.paths import bawwab_home

    return bawwab_home() / "sandbox-image.json"


def recorded_image() -> str | None:
    """The image id `bawwab sandbox build` recorded, or None."""
    try:
        d = json.loads(image_record_path().read_text())
    except (OSError, ValueError):
        return None
    i = d.get("id") if isinstance(d, dict) else None
    return i if isinstance(i, str) and re.fullmatch(r"sha256:[0-9a-f]{64}", i) else None


def network_create_argv(docker: str, net: str, run_id: str) -> list[str]:
    return [docker, "network", "create", "--internal", "--driver", "bridge", "--label", f"{LABEL}={run_id}",
            "--opt", "com.docker.network.bridge.enable_ip_masquerade=false", net]


def proxy_argv(docker: str, image: str, name: str, net: str, run_id: str) -> list[str]:
    return [
        docker, "run", "-d", "--name", name, "--label", f"{LABEL}={run_id}",
        "--network", net, "--hostname", "trap",
        "--read-only", "--user", PROXY_UID, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", "32", "--memory", "128m", "--memory-swap", "128m", "--cpus", "0.5",
        "--sysctl", "net.ipv4.ip_unprivileged_port_start=0",  # bind :53 without NET_BIND_SERVICE
        "--log-driver", "json-file", "--log-opt", "max-size=16m",
        image, "python3", "-I", "/opt/bawwab/proxy.py",
    ]


def _mount_source(root: str) -> str:
    if any(c in root for c in '",\n\r\0'):
        raise SandboxUnavailable("the target's path can't be passed to docker safely")
    return root


def sandbox_argv(docker: str, image: str, name: str, net: str, run_id: str, proxy_ip: str, root: str,
                 limits: Limits | None = None) -> list[str]:
    lim = limits or Limits()
    uid, gid = SANDBOX_UID.split(":")
    return [
        docker, "run", "-i", "--rm", "--name", name, "--label", f"{LABEL}={run_id}",
        "--network", net, "--dns", proxy_ip, "--hostname", "workstation",
        "--read-only", "--user", SANDBOX_UID, "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--pids-limit", str(lim.pids), "--memory", lim.memory, "--memory-swap", lim.memory, "--cpus", lim.cpus,
        "--ulimit", f"nofile={lim.nofile}:{lim.nofile}", "--ulimit", "core=0",
        "--ipc", "private", "--sysctl", "net.ipv6.conf.all.disable_ipv6=1",
        "--tmpfs", f"{WORK}:rw,exec,nosuid,nodev,size={lim.work_size},uid={uid},gid={gid},mode=0700",
        "--tmpfs", f"{HOME}:rw,noexec,nosuid,nodev,size={lim.home_size},uid={uid},gid={gid},mode=0700",
        "--tmpfs", f"/tmp:rw,noexec,nosuid,nodev,size={lim.tmp_size},mode=1777",
        "--mount", f"type=bind,source={_mount_source(root)},target=/target,readonly",
        "--stop-timeout", "1",
        image, "python3", "-I", "/opt/bawwab/harness.py",
    ]


def target_env(proxy_ip: str, canaries: dict[str, str], plan: Plan) -> dict[str, str]:
    """The environment the target runs with: decoy credentials, the trap as proxy, caches in the workdir."""
    proxy = f"http://{proxy_ip}:{PROXY_PORT}"
    env = {
        "PATH": "/usr/local/bin:/usr/bin:/bin", "HOME": HOME, "USER": "sandbox", "LOGNAME": "sandbox",
        "LANG": "C.UTF-8", "TMPDIR": f"{WORK}/tmp", "XDG_CACHE_HOME": f"{WORK}/.cache",
        "npm_config_cache": f"{WORK}/.npm", "NPM_CONFIG_USERCONFIG": f"{WORK}/.npmrc",
        "NPM_CONFIG_UPDATE_NOTIFIER": "false", "NO_UPDATE_NOTIFIER": "1",
        "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_CACHE_DIR": "1", "PYTHONDONTWRITEBYTECODE": "1",
        "HTTP_PROXY": proxy, "HTTPS_PROXY": proxy, "http_proxy": proxy, "https_proxy": proxy,
        "ALL_PROXY": proxy, "all_proxy": proxy, "NO_PROXY": "", "no_proxy": "",
    }
    env.update(decoy_env(canaries))
    env.update(plan.env)
    return env


def harness_spec(nonce: str, plan: Plan, canaries: dict[str, str], env: dict[str, str], timeout_s: float) -> dict:
    total = max(30.0, timeout_s - 15)
    return {
        "nonce": nonce,
        "plan": {"install": plan.install, "start": plan.start, "runtime": plan.runtime},
        "decoys": decoy_files(canaries),
        "canaries": canaries,
        "env": env,
        "budgets": {"total_s": total, "install_s": min(90.0, total * 0.5), "start_s": 20.0, "call_s": 10.0,
                    "calls_total_s": max(10.0, total * 0.4)},
    }


def parse_lines(raw: bytes) -> tuple[list[dict], int]:
    """JSON-object lines from a container's stdout, and how many lines were not one."""
    recs, stray = [], 0
    for line in raw.decode("utf-8", "replace").splitlines():
        if not line.strip():
            continue
        try:
            d = json.loads(line)
        except ValueError:
            stray += 1
            continue
        if isinstance(d, dict):
            recs.append(d)
        else:
            stray += 1
    return recs, stray


class DockerRunner:
    """SandboxRunner backed by the docker CLI. `exec` is injectable so tests can check every argv."""

    def __init__(self, docker: str = "docker", image: str | None = None, exec: Exec | None = None,
                 limits: Limits | None = None) -> None:
        self.docker = docker
        self.image = image
        self.exec = exec or _run_cmd
        self.limits = limits or Limits()

    # ------------------------------------------------------------------ helpers
    def _x(self, argv: list[str], stdin: bytes | None = None, timeout: float = 30.0) -> Result:
        try:
            return self.exec(argv, stdin, timeout)
        except OSError as e:
            raise SandboxUnavailable(f"docker could not be run: {type(e).__name__}") from e

    def _must(self, argv: list[str], what: str, timeout: float = 30.0) -> Result:
        r = self._x(argv, None, timeout)
        if r.returncode != 0 or r.timed_out:
            raise SandboxUnavailable(f"{what} failed: {sanitise(r.stderr.decode('utf-8', 'replace'), 160)}")
        return r

    def check(self) -> str:
        """The image id to run. Raises SandboxUnavailable when Docker or the image is not usable."""
        r = self._x([self.docker, "version", "--format", "{{.Server.Version}}"], None, 15.0)
        if r.returncode != 0 or r.timed_out:
            err = sanitise(r.stderr.decode("utf-8", "replace"), 160) or "no answer"
            raise SandboxUnavailable(f"Docker is not reachable: {err}")
        image = self.image or recorded_image()
        if not image:
            raise SandboxUnavailable("the sandbox image is not built; run `bawwab sandbox build`")
        r = self._x([self.docker, "image", "inspect", "--format", "{{.Id}}", image], None, 15.0)
        got = r.stdout.decode("utf-8", "replace").strip()
        if r.returncode != 0 or not re.fullmatch(r"sha256:[0-9a-f]{64}", got):
            raise SandboxUnavailable("the sandbox image is missing; run `bawwab sandbox build`")
        if image.startswith("sha256:") and got != image:
            raise SandboxUnavailable("the sandbox image does not match the recorded build")
        return got

    def _cleanup(self, names: list[str], net: str) -> None:
        for n in names:
            self._x([self.docker, "rm", "-f", n], None, 30.0)
        self._x([self.docker, "network", "rm", net], None, 30.0)

    # ------------------------------------------------------------------ SandboxRunner
    def run(self, f: Fetched, timeout_s: float) -> tuple[list[Finding], list[ToolInfo]]:
        image = self.check()  # Docker first: deep mode without Docker is never a pass (fail closed)
        plan = plan_for(f)
        if isinstance(plan, str):
            if f.root is not None and f.artifact_type in ("mcp", "unknown") and f.target.kind != "docker":
                # a server we could not start was not observed: that is not a pass
                return [Finding("sandbox.incomplete", Severity.MED, "sandbox",
                                f"[sandbox] could not work out how to start it: {sanitise(plan, 160)}")], []
            return [Finding("sandbox.no-entrypoint", Severity.LOW, "sandbox", f"[sandbox] not run: {plan}")], []
        root = os.path.realpath(f.root) if f.root is not None else ""
        if not root or not os.path.isdir(root):
            raise SandboxUnavailable("the fetched target has no directory to mount")
        run_id = secrets.token_hex(6)
        net, proxy, sbx = f"bawwab-net-{run_id}", f"bawwab-trap-{run_id}", f"bawwab-sbx-{run_id}"
        canaries, nonce = make_canaries(), secrets.token_hex(16)
        notes: list[str] = []
        created_net = False
        try:
            self._must(network_create_argv(self.docker, net, run_id), "creating the sandbox network")
            created_net = True
            self._must(proxy_argv(self.docker, image, proxy, net, run_id), "starting the network trap", 60.0)
            r = self._must([self.docker, "inspect", "--format",
                            "{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}", proxy], "finding the trap")
            proxy_ip = r.stdout.decode("utf-8", "replace").strip()
            if not re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", proxy_ip):
                raise SandboxUnavailable("the network trap has no address")
            env = target_env(proxy_ip, canaries, plan)
            spec = json.dumps(harness_spec(nonce, plan, canaries, env, timeout_s)).encode()
            argv = sandbox_argv(self.docker, image, sbx, net, run_id, proxy_ip, root, self.limits)
            res = self._x(argv, spec, timeout_s + 30)
            if res.returncode == 125 and not res.stdout:  # docker itself refused to start the container
                raise SandboxUnavailable(
                    f"docker could not start the sandbox: {sanitise(res.stderr.decode('utf-8', 'replace'), 160)}")
            records, stray = parse_lines(res.stdout)
            logs = self._x([self.docker, "logs", proxy], None, 30.0)
            if logs.returncode != 0:
                notes.append("the network trap's log could not be read")
            proxy_recs, _ = parse_lines(logs.stdout)
            obs = Observation(records, proxy_recs, canaries, nonce, proxy_ip=proxy_ip, timed_out=res.timed_out,
                              stray_lines=stray, exit_code=res.returncode, notes=notes)
        finally:
            if created_net:
                self._cleanup([sbx, proxy], net)
        return analyze(obs)


def build_argv(docker: str, tag: str) -> list[str]:
    ctx = Path(__file__).resolve().parent
    return [docker, "build", "--pull=false", "-t", tag, "-f", str(ctx / "image" / "Dockerfile"), str(ctx)]


def build_image(docker: str = "docker", exec: Exec | None = None) -> str:
    """Build the sandbox image from this package and record its id. Returns the id."""
    run = exec or _run_cmd
    tag = f"bawwab-sandbox:{_version()}"
    r = run(build_argv(docker, tag), None, 1800.0)
    if r.returncode != 0:
        raise SandboxUnavailable(f"docker build failed: {sanitise(r.stderr.decode('utf-8', 'replace')[-400:], 300)}")
    r = run([docker, "image", "inspect", "--format", "{{.Id}}", tag], None, 30.0)
    iid = r.stdout.decode().strip()
    if r.returncode != 0 or not re.fullmatch(r"sha256:[0-9a-f]{64}", iid):
        raise SandboxUnavailable("built image could not be inspected")
    p = image_record_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps({"id": iid, "tag": tag}) + "\n")
    return iid


def _version() -> str:
    try:
        from importlib.metadata import version

        return version("bawwab")
    except Exception:  # noqa: BLE001
        return "dev"
