from __future__ import annotations

import os
import posixpath
import re
from pathlib import Path

from bawwab.types import Target

GIT_HOSTS = ("github.com", "gitlab.com", "bitbucket.org", "codeberg.org")
_URL_RE = re.compile(r"^https?://([^/:?#]+)", re.I)


def _split_at_version(s: str) -> tuple[str, str | None]:
    i = s.rfind("@")
    if i > 0:
        return s[:i], (s[i + 1 :] or None)
    return s, None


# Server-entry transports that are always a live MCP endpoint, never a repository to clone.
REMOTE_TRANSPORTS = frozenset({"http", "sse", "streamable-http", "streamable_http", "streamablehttp"})
# On the git hosts a repository is /owner/name (GitLab: /group[/subgroup...]/project). Paths under these first
# segments, or containing GitLab's "/-/" separator, are the host's web/API surface (e.g. gitlab.com/api/v4/mcp).
_NON_REPO_FIRST = frozenset({"api", "-", "mcp"})


def _is_git_url(url: str) -> bool:
    if url.startswith("git@") or url.startswith("ssh://") or url.startswith("git://"):
        return True
    m = _URL_RE.match(url)
    if not m:
        return url.endswith(".git")
    host = m.group(1).lower()
    path = url.split("?", 1)[0].split("#", 1)[0]
    if path.rstrip("/").endswith(".git"):
        return True
    if host not in GIT_HOSTS:
        return False
    rest = path[m.end():]  # may start with :port
    segs = [x for x in rest[rest.find("/"):].split("/") if x] if "/" in rest else []
    if len(segs) < 2 or segs[0].lower() in _NON_REPO_FIRST or "-" in segs:
        return False
    return host == "gitlab.com" or len(segs) == 2  # only GitLab nests groups


def target_from_url(url: str, transport: object = None) -> Target:
    """A URL from a server entry or the CLI. A declared http/sse transport is always remote; otherwise a
    repo-shaped URL on a git host (or a .git URL) is cloned and anything else is fetched as a remote MCP server."""
    remote = isinstance(transport, str) and transport.lower() in REMOTE_TRANSPORTS
    return Target("git" if not remote and _is_git_url(url) else "remote", url, url=url)


def _local(raw: str, p: str) -> Target:
    return Target("local", raw, path=str(Path(p).expanduser().resolve()))


def parse_target(spec: str) -> Target:
    spec = spec.strip()
    if spec.startswith("pypi:"):
        body = spec[5:]
        name, _, version = body.partition("==")
        return Target("pypi", spec, name=name.strip(), version=version.strip() or None)
    if spec.startswith("docker:"):
        name, version = _docker_split(spec[7:])
        return Target("docker", spec, name=name, version=version)
    if spec.startswith(("http://", "https://", "git@", "ssh://", "git://")):
        return target_from_url(spec) if not spec.startswith(("git@", "ssh://", "git://")) else Target("git", spec, url=spec)
    if spec.endswith(".git"):
        return Target("git", spec, url=spec)
    if spec.startswith(("./", "../", "/", "~")) or spec in (".", ".."):
        return _local(spec, spec)
    name, version = _split_at_version(spec)
    return Target("npm", spec, name=name, version=version)


def _docker_split(ref: str) -> tuple[str, str | None]:
    ref = ref.split("@", 1)[0]  # drop digest
    last = ref.rsplit("/", 1)[-1]
    if ":" in last:
        name, _, tag = ref.rpartition(":")
        return name, tag or None
    return ref, None


_NPX_VALUE_FLAGS = {"-p", "--package"}
_DOCKER_VALUE_FLAGS = {
    "-e", "--env", "-v", "--volume", "--name", "-p", "--publish", "--network", "--net", "-w", "--workdir",
    "-u", "--user", "--entrypoint", "--mount", "--env-file", "-l", "--label", "--platform", "--add-host",
    "--memory", "-m", "--cpus", "--restart", "--pull", "-h", "--hostname", "--cap-add", "--cap-drop",
}


def target_from_command(command: str, args: list[str]) -> Target | None:
    if not command:
        return None
    exe = os.path.basename(command)
    raw = " ".join([command, *args])
    if exe in ("npx", "bunx") or (exe in ("pnpm", "yarn") and args[:1] == ["dlx"]):
        a = args[1:] if exe in ("pnpm", "yarn") else args
        spec = _npx_package(a)
        if not spec:
            return None
        name, version = _split_at_version(spec)
        return Target("npm", raw, name=name, version=version) if name else None
    if exe in ("uvx", "pipx") or (exe == "uv" and args[:1] == ["tool"]):
        a = args
        if exe == "pipx" and a[:1] == ["run"]:
            a = a[1:]
        if exe == "uv":
            a = a[2:] if a[:2] == ["tool", "run"] else a[1:]
        return _uvx(raw, a)
    if re.fullmatch(r"python[0-9.]*", exe):
        if args[:1] == ["-m"] and len(args) > 1:
            return Target("pypi", raw, name=args[1].split(".")[0])
        script = next((x for x in args if not x.startswith("-")), None)
        if script and script.endswith(".py"):
            return _local(raw, posixpath.dirname(script) or ".")
        return None
    if exe in ("node", "bun", "deno"):
        script = next((x for x in args if not x.startswith("-")), None)
        if script and script != "run":
            return _local(raw, posixpath.dirname(script) or ".")
        return None
    if exe == "docker":
        if args[:1] != ["run"]:
            return None
        i = 1
        while i < len(args):
            a = args[i]
            if a.startswith("-"):
                i += 1 if ("=" in a or a not in _DOCKER_VALUE_FLAGS) else 2
                continue
            name, version = _docker_split(a)
            return Target("docker", raw, name=name, version=version)
        return None
    return None


_NPX_OTHER_VALUE_FLAGS = {"--registry", "--userconfig", "--globalconfig", "--node-options", "--cache", "--prefix",
                          "-c", "--call", "--workspace", "-w", "--loglevel", "--script-shell", "--tag"}


def _npx_spec_pos(args: list[str]) -> tuple[int, int] | None:
    """(index into args, char offset) of the package spec npx/bunx/dlx installs."""
    i = 0
    while i < len(args):
        a = args[i]
        if a in _NPX_VALUE_FLAGS:
            return (i + 1, 0) if i + 1 < len(args) else None
        if a.startswith("--package="):
            return (i, len("--package=")) if len(a) > len("--package=") else None
        if a.startswith("-"):
            i += 2 if (a in _NPX_OTHER_VALUE_FLAGS and "=" not in a) else 1
            continue
        return i, 0
    return None


def _npx_package(args: list[str]) -> str | None:
    pos = _npx_spec_pos(args)
    return args[pos[0]][pos[1]:] if pos else None


def _uvx_spec_pos(args: list[str]) -> tuple[int, int] | None:
    """(index, char offset) of the package spec for uvx/pipx run/uv tool run (--from/--spec win)."""
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("--from", "--spec"):
            return (i + 1, 0) if i + 1 < len(args) else None
        if a.startswith(("--from=", "--spec=")):
            off = a.index("=") + 1
            return (i, off) if len(a) > off else None
        if a.startswith("-"):
            i += 2 if (a in _UV_VALUE_FLAGS and "=" not in a) else 1
            continue
        return i, 0
    return None


def _runner_args(command: str, args: list[str]) -> tuple[str, int] | None:
    """(runner kind "npm"|"pypi", offset of the runner's own args within args), or None."""
    exe = os.path.basename(command or "")
    if exe in ("npx", "bunx"):
        return "npm", 0
    if exe in ("pnpm", "yarn") and args[:1] == ["dlx"]:
        return "npm", 1
    if exe == "uvx":
        return "pypi", 0
    if exe == "pipx":
        return "pypi", 1 if args[:1] == ["run"] else 0
    if exe == "uv" and args[:1] == ["tool"]:
        return "pypi", 2 if args[:2] == ["tool", "run"] else 1
    return None


def package_position(command: str, args: list[str]) -> tuple[str, int, int] | None:
    """(kind, index into args, char offset) of the package spec a runner installs; used for pinning."""
    r = _runner_args(command, args)
    if r is None:
        return None
    kind, off = r
    pos = (_npx_spec_pos if kind == "npm" else _uvx_spec_pos)(args[off:])
    return (kind, pos[0] + off, pos[1]) if pos else None


def _uvx(raw: str, args: list[str]) -> Target | None:
    pos = _uvx_spec_pos(args)
    spec = args[pos[0]][pos[1]:] if pos else None
    if not spec:
        return None
    name, _, version = spec.partition("==")
    name = re.split(r"[<>=!~\[;]", name, maxsplit=1)[0].strip()
    return Target("pypi", raw, name=name, version=version.strip() or None) if name else None


_NPX_INDEX_FLAGS = ("--registry", "--userconfig", "--node-options")
_UV_INDEX_FLAGS = ("--index-url", "--extra-index-url", "--index", "--default-index", "-i", "--find-links", "-f",
                   "--pip-args")
_UV_VALUE_FLAGS = {"--from", "--python", "-p", "--with", "--with-requirements", "--with-editable", "--constraint",
                   "-c", "--override", "--cache-dir", "--directory", "--project", "--spec"} | set(_UV_INDEX_FLAGS)


def _flag(a: str) -> tuple[str, str | None]:
    if a.startswith("--") and "=" in a:
        k, _, v = a.partition("=")
        return k, v
    return a, None


def runner_extras(command: str, args: list[str]) -> tuple[list[Target], list[str]]:
    """Extra packages a runner installs besides its main package, and reasons the spec is unscannable
    (custom package index, requirements files). Only the runner's own flags (before the package) count."""
    exe = os.path.basename(command or "")
    extras: list[Target] = []
    reasons: list[str] = []
    if exe in ("npx", "bunx") or (exe in ("pnpm", "yarn") and args[:1] == ["dlx"]):
        a = args[1:] if exe in ("pnpm", "yarn") else args
        pkgs: list[str] = []
        i = 0
        while i < len(a):
            k, v = _flag(a[i])
            if k in _NPX_INDEX_FLAGS:
                reasons.append("npx --node-options" if k == "--node-options" else "custom package index")
            if k in _NPX_VALUE_FLAGS or k in _NPX_OTHER_VALUE_FLAGS:
                if v is None:
                    v = a[i + 1] if i + 1 < len(a) else None
                    i += 1
                if k in _NPX_VALUE_FLAGS and v:
                    pkgs.append(v)
                i += 1
                continue
            if not a[i].startswith("-"):
                break
            i += 1
        for spec in pkgs[1:]:
            name, version = _split_at_version(spec)
            if name:
                extras.append(Target("npm", spec, name=name, version=version))
        return extras, reasons
    if exe in ("uvx", "pipx") or (exe == "uv" and args[:1] == ["tool"]):
        a = args
        if exe == "pipx" and a[:1] == ["run"]:
            a = a[1:]
        if exe == "uv":
            a = a[2:] if a[:2] == ["tool", "run"] else a[1:]
        i = 0
        while i < len(a):
            tok = a[i]
            k, v = _flag(tok)
            if k in _UV_VALUE_FLAGS and v is None:
                v = a[i + 1] if i + 1 < len(a) else ""
                i += 1
            if k in _UV_INDEX_FLAGS:
                reasons.append("custom package index")
            elif k in ("--with-requirements", "--with-editable", "--constraint", "-c", "--override"):
                reasons.append(f"unscannable requirements: {k}")
            elif k == "--with" and v:
                for spec in v.split(","):
                    name, _, version = spec.strip().partition("==")
                    name = re.split(r"[<>=!~\[;]", name, maxsplit=1)[0].strip()
                    if name:
                        extras.append(Target("pypi", spec.strip(), name=name, version=version.strip() or None))
            elif not tok.startswith("-"):
                break
            i += 1
        return extras, reasons
    return extras, reasons
