"""How to install and start a fetched target inside the sandbox.

Runs on the host and only *reads* the target's manifests (package.json, pyproject.toml, a wheel's
entry_points.txt): nothing here executes target code. Every value taken from a manifest is checked against a
strict pattern before it goes into the in-container argv.
"""
from __future__ import annotations

import json
import os
import posixpath
import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from bawwab.types import Fetched

WORK = "/work"
PKG = "/work/pkg"
VENV = "/work/venv"

_REL = re.compile(r"^(?!/)(?!.*(?:^|/)\.\.(?:/|$))[A-Za-z0-9@._+/-]{1,200}$")
_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,100}$")
_DOTTED = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*){0,10}$")
_ARG = re.compile(r"^[A-Za-z0-9@%+=:,./_-]{0,200}$")

NPM_INSTALL = ["npm", "install", "--offline", "--no-audit", "--no-fund", "--no-package-lock"]


@dataclass
class Plan:
    runtime: str  # node | python | python-wheel
    install: list[list[str]]
    start: list[str]
    env: dict[str, str] = field(default_factory=dict)


def _read_json(p: Path) -> dict:
    try:
        d = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, ValueError, RecursionError):
        return {}
    return d if isinstance(d, dict) else {}


def _rel_ok(root: Path, rel: str) -> str | None:
    rel = posixpath.normpath(rel.strip().removeprefix("./"))
    if not _REL.match(rel):
        return None
    p = root / rel
    try:
        real, base = os.path.realpath(p), os.path.realpath(root)
    except OSError:
        return None
    if not (real == base or real.startswith(base + os.sep)) or not os.path.isfile(real):
        return None
    return rel


def _node_plan(root: Path) -> Plan | str:
    pj = _read_json(root / "package.json")
    name = str(pj.get("name") or "")
    bin_ = pj.get("bin")
    cand: list[str] = []
    if isinstance(bin_, str):
        cand.append(bin_)
    elif isinstance(bin_, dict):
        short = name.rsplit("/", 1)[-1]
        if isinstance(bin_.get(short), str):
            cand.append(bin_[short])
        cand += [v for _, v in sorted(bin_.items()) if isinstance(v, str)]
    if isinstance(pj.get("main"), str):
        cand.append(pj["main"])
    cand += ["index.js", "dist/index.js", "build/index.js"]
    for c in cand:
        rel = _rel_ok(root, c)
        if rel:
            return Plan("node", [NPM_INSTALL], ["node", f"{PKG}/{rel}"])
    return "no start file found in package.json (bin/main) or index.js"


def _python_plan(root: Path) -> Plan | str:
    install = [["python3", "-m", "venv", "--system-site-packages", VENV],
               [f"{VENV}/bin/pip", "install", "--no-index", "--no-build-isolation", "--no-cache-dir", PKG]]
    data: dict = {}
    try:
        with open(root / "pyproject.toml", "rb") as fh:
            data = tomllib.load(fh)
    except (OSError, ValueError, RecursionError):
        data = {}
    proj = data.get("project") if isinstance(data.get("project"), dict) else {}
    name = str(proj.get("name") or "")
    scripts = proj.get("scripts") if isinstance(proj.get("scripts"), dict) else {}
    names = [k for k in scripts if isinstance(k, str) and _NAME.match(k)]
    if names:
        pick = name if name in names else sorted(names)[0]
        return Plan("python", install, [f"{VENV}/bin/{pick}"])
    mod = re.sub(r"[-.]+", "_", name).lower()
    if mod and _DOTTED.match(mod) and any((root / d / mod).is_dir() or (root / d / f"{mod}.py").is_file()
                                          for d in (".", "src")):
        return Plan("python", install, [f"{VENV}/bin/python", "-m", mod])
    return "no console script in pyproject.toml and no module named after the project"


def _wheel_plan(root: Path, dist: Path) -> Plan | str:
    ep = dist / "entry_points.txt"
    try:
        text = ep.read_text(encoding="utf-8")
    except OSError:
        return "wheel has no console script entry point"
    section = None
    for raw in text.splitlines():
        line = raw.strip()
        if line.startswith("["):
            section = line.strip("[]").strip()
            continue
        if section != "console_scripts" or "=" not in line:
            continue
        target = line.split("=", 1)[1].strip().split("[", 1)[0].strip()
        mod, _, fn = target.partition(":")
        if _DOTTED.match(mod) and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", fn):
            code = f"import sys; from {mod} import {fn} as f; sys.exit(f())"
            return Plan("python-wheel", [], ["python3", "-c", code], env={"PYTHONPATH": PKG})
    return "wheel has no usable console script entry point"


def _command_plan(f: Fetched, root: Path) -> Plan | str | None:
    """A local server given as a start command (`node ./srv/index.js`, from a plugin's .mcp.json)."""
    words = (f.target.raw or "").split()
    if len(words) < 2:
        return None
    exe = os.path.basename(words[0])
    if exe not in ("node", "python", "python3") and not re.fullmatch(r"python3(\.\d+)?", exe):
        return None
    base = os.path.realpath(root)
    out: list[str] = []
    for w in words[1:]:
        if w.startswith("/") and (os.path.realpath(w) == base or os.path.realpath(w).startswith(base + os.sep)):
            rel = os.path.relpath(os.path.realpath(w), base)
            w = PKG if rel == "." else f"{PKG}/{rel}"
        elif w.startswith("/") or not _ARG.match(w):
            return "start command uses paths outside the server's directory"
        out.append(w)
    runtime = "node" if exe == "node" else "python"
    install = [NPM_INSTALL] if runtime == "node" and (root / "package.json").is_file() else []
    return Plan(runtime, install, ["node" if runtime == "node" else "python3", *out])


def plan_for(f: Fetched) -> Plan | str:
    """A Plan, or the reason there is nothing to run."""
    if f.target.kind == "docker":
        return "docker image targets are not run in the sandbox yet"
    if f.root is None:
        return "remote server: nothing runs locally"
    if f.artifact_type == "skill":
        return "a skill has no server to start"
    if f.artifact_type == "plugin":
        return "a plugin has no server of its own (its bundled servers are run separately)"
    root = Path(f.root)
    if f.target.kind == "local":
        p = _command_plan(f, root)
        if p is not None:
            return p
    if (root / "package.json").is_file():
        return _node_plan(root)
    if any((root / n).is_file() for n in ("pyproject.toml", "setup.py", "setup.cfg")):
        return _python_plan(root)
    dists = sorted(root.glob("*.dist-info"))
    if dists:
        return _wheel_plan(root, dists[0])
    return "no package.json, pyproject.toml or wheel metadata: no known way to start it"
