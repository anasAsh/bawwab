"""Pure install detection for PreToolUse tool calls.

No network and no scanning. File reads are limited to the config file being
edited (to compute its new content), the marketplace JSONs and
known_marketplaces.json.
"""
from __future__ import annotations

import dataclasses
import json
import os
import posixpath
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from bawwab.fetch.target import target_from_command, target_from_url
from bawwab.paths import bawwab_home, claude_home, claude_json
from bawwab.types import Target


@dataclass
class HookInput:
    tool_name: str
    tool_input: dict
    cwd: str


@dataclass
class Targets:
    targets: list[Target]
    pinnable: bool
    # target -> {absolute file path: new content}; run_gate scans a temp copy of the
    # target dir with these files overlaid (Write/Edit under a skill/command/agent dir).
    overlays: dict[Target, dict[str, str]] = field(default_factory=dict)


@dataclass
class Protected:
    reason: str


INSTALL_DIRS = ("skills", "commands", "agents", "plugins")
_PUNCT = "();<>|&\n"
_SHELLS = {"bash", "sh", "zsh", "dash", "ksh"}
_READ_ONLY = {
    "cat", "less", "more", "head", "tail", "ls", "stat", "file", "wc", "grep", "egrep", "fgrep", "rg", "jq",
    "diff", "sha256sum", "sha1sum", "md5sum", "du", "echo", "printf", "test", "[", "realpath", "readlink",
    "bat", "git", "true", "false", "which", "type",
}
_SHELL_WRITERS = {"tee", "sed", "perl", "dd", "truncate", "patch", "python", "python3", "node"}


class _Unevaluable(Exception):
    pass


class _Acc:
    def __init__(self) -> None:
        self.targets: list[Target] = []
        self.protected: list[str] = []
        self.pinnable = False
        self.overlays: dict[Target, dict[str, str]] = {}

    def add(self, t: Target, pinnable: bool = False) -> None:
        if t not in self.targets:
            self.targets.append(t)
        self.pinnable = self.pinnable or pinnable

    def protect(self, reason: str) -> None:
        if reason not in self.protected:
            self.protected.append(reason)

    def result(self) -> Targets | Protected | None:
        if self.protected:
            return Protected("; ".join(self.protected))
        if self.targets:
            return Targets(self.targets, self.pinnable, self.overlays)
        return None


# ------------------------------------------------------------------ paths

def _home_vars(tok: str) -> str:
    home = str(Path.home())
    return re.sub(r"\$\{HOME\}|\$HOME(?![A-Za-z0-9_])", lambda _: home, tok)


def _abspath(tok: str, cwd: str) -> str:
    p = os.path.expanduser(_home_vars(tok))
    if not os.path.isabs(p):
        p = os.path.join(cwd or "/", p)
    return os.path.normpath(p)


def install_dir(p: str) -> tuple[str, str] | None:
    """(kind, path of the .claude/<kind> dir) when p is inside an install dir."""
    parts = Path(p).parts
    for i in range(len(parts) - 1):
        if parts[i] == ".claude" and parts[i + 1] in INSTALL_DIRS:
            return parts[i + 1], str(Path(*parts[: i + 2]))
    return None


def _under(p: str, root: str) -> bool:
    return p == root or p.startswith(root.rstrip("/") + "/")


def _bawwab_path(p: str) -> bool:
    if _under(p, os.path.normpath(str(bawwab_home()))):
        return True
    return os.path.basename(p) == "bawwab.json" and os.path.basename(os.path.dirname(p)) == ".claude"


def _config_kind(p: str) -> str | None:
    name = os.path.basename(p)
    if name == ".mcp.json":
        return "mcp"
    if p == os.path.normpath(str(claude_json())):
        return "claude_json"
    if os.path.basename(os.path.dirname(p)) == ".claude" and name.startswith("settings") and name.endswith(".json"):
        return "settings"
    return None


def _read_json(p: Path) -> object:
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError, RecursionError):
        return None


# ------------------------------------------------------------------ MCP specs

def _server_target(cmd: str, args: list[str], cwd: str) -> Target | None:
    t = target_from_command(cmd, args)
    if t is not None and t.kind == "local":
        script = next((a for a in args if not a.startswith("-")), None)
        if script and not os.path.isabs(script):
            t = dataclasses.replace(t, path=_abspath(posixpath.dirname(script) or ".", cwd))
    return t


def _spec_target(name: str, spec: dict, cwd: str, acc: _Acc) -> None:
    url = spec.get("url")
    if isinstance(url, str) and url:
        acc.add(target_from_url(url), pinnable=True)
        return
    cmd, args = spec.get("command"), spec.get("args", [])
    if isinstance(cmd, str) and isinstance(args, list) and all(isinstance(a, str) for a in args):
        t = _server_target(cmd, args, cwd)
        if t is not None:
            acc.add(t, pinnable=True)
            return
    acc.protect(f"unrecognized MCP command: {name}")


# ------------------------------------------------------------------ plugins

def _plugin_source(loc: Path, data: dict, src: object) -> Target | None:
    if isinstance(src, str):
        base = loc
        root = data.get("metadata", {}).get("pluginRoot") if isinstance(data.get("metadata"), dict) else None
        if isinstance(root, str) and not src.startswith(("./", "../", "/")):
            base = loc / root
        p = (base / src).resolve()
        return Target("local", src, name=str(p), path=str(p)) if p.is_dir() else None
    if not isinstance(src, dict):
        return None
    kind, ref = src.get("source"), src.get("ref")
    ref = ref if isinstance(ref, str) and ref else None
    if kind == "github" and isinstance(src.get("repo"), str):
        url = f"https://github.com/{src['repo']}.git"
        return Target("git", url, url=url, version=ref)
    if kind in ("url", "git", "git-subdir") and isinstance(src.get("url"), str):
        # git-subdir: the whole repo is scanned (a superset of the plugin).
        return Target("git", src["url"], url=src["url"], version=ref)
    if kind == "npm" and isinstance(src.get("package"), str):
        v = src.get("version")
        return Target("npm", src["package"], name=src["package"], version=v if isinstance(v, str) else None)
    if kind in ("pip", "pypi") and isinstance(src.get("package"), str):
        v = src.get("version")
        return Target("pypi", src["package"], name=src["package"], version=v if isinstance(v, str) else None)
    return None


def _plugin(spec: str, acc: _Acc) -> None:
    name, _, mk = spec.rpartition("@") if "@" in spec else (spec, "", "")
    known = _read_json(claude_home() / "plugins" / "known_marketplaces.json")
    known = known if isinstance(known, dict) else {}
    matches = []
    for m in [mk] if mk else list(known):
        entry = known.get(m)
        if not isinstance(entry, dict):
            continue
        loc = entry.get("installLocation")
        loc = Path(loc) if isinstance(loc, str) and loc else claude_home() / "plugins" / "marketplaces" / m
        data = _read_json(loc / ".claude-plugin" / "marketplace.json")
        if not isinstance(data, dict) or not isinstance(data.get("plugins"), list):
            continue
        for p in data["plugins"]:
            if isinstance(p, dict) and p.get("name") == name:
                matches.append((loc, data, p))
    t = _plugin_source(*matches[0][:2], matches[0][2].get("source")) if len(matches) == 1 else None
    if t is None:
        acc.protect(f"unresolvable plugin: {spec}")
    else:
        acc.add(t)


# ------------------------------------------------------------------ bash

def _tokens(cmd: str) -> list[str]:
    cmd = cmd.replace("\\\n", " ").replace("`", " ; ")
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=_PUNCT)
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    try:
        return list(lex)
    except ValueError:  # unbalanced quotes: crude split, quotes dropped
        return re.findall(r"[();<>|&\n]+|[^\s();<>|&\n]+", re.sub(r"[\"'\\]", "", cmd))


def _segments(tokens: list[str]) -> list[tuple[list[str], list[str]]]:
    """Split into (words, redirect targets) per simple command."""
    segs: list[tuple[list[str], list[str]]] = []
    words: list[str] = []
    redirs: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok and all(c in _PUNCT for c in tok):
            if ">" in tok:
                if i + 1 < len(tokens):
                    redirs.append(tokens[i + 1])
                i += 2
                continue
            if "<" in tok:
                i += 2
                continue
            if words or redirs:
                segs.append((words, redirs))
            words, redirs = [], []
            i += 1
            continue
        words.append(tok)
        i += 1
    if words or redirs:
        segs.append((words, redirs))
    return segs


_SUDO_VALUE = {"-u", "-g", "-U", "-C", "-h", "-p", "-r", "-t", "-D", "-R", "-T"}
_ENV_VALUE = {"-u", "--unset", "-C", "--chdir", "-S", "--split-string"}


def _strip_prefix(words: list[str]) -> list[str]:
    i = 0
    while i < len(words):
        w = words[i]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", w, re.S):
            i += 1
            continue
        b = os.path.basename(w)
        if b in ("sudo", "doas", "env", "command", "builtin", "exec", "nohup", "time", "nice", "stdbuf"):
            values = _SUDO_VALUE if b in ("sudo", "doas") else _ENV_VALUE if b == "env" else {"-n"}
            i += 1
            while i < len(words) and words[i].startswith("-") and words[i] != "-":
                i += 2 if words[i] in values else 1
            continue
        break
    return words[i:]


def _positionals(args: list[str], value_flags: set[str]) -> list[str]:
    out, i = [], 0
    while i < len(args):
        a = args[i]
        if a == "--":
            out.extend(args[i + 1:])
            break
        if a.startswith("-") and a != "-":
            i += 2 if a in value_flags else 1
            continue
        out.append(a)
        i += 1
    return out


_MCP_ADD_VALUE = {"-s", "--scope", "-t", "--transport", "--client-id", "--callback-port"}


def _mcp_add(args: list[str], cwd: str, acc: _Acc) -> None:
    pos: list[str] = []
    rest: list[str] = []
    transport = None
    dashdash = False
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            dashdash, rest = True, args[i + 1:]
            break
        if a in ("-t", "--transport") and i + 1 < len(args):
            transport = args[i + 1]
        elif a.startswith("--transport="):
            transport = a.split("=", 1)[1]
        if a in _MCP_ADD_VALUE:
            i += 2
            continue
        if a in ("-e", "--env", "-H", "--header"):
            i += 1
            pat = r"[A-Za-z_][A-Za-z0-9_]*=" if a in ("-e", "--env") else r"[^\s:/]+:"
            while i < len(args) and re.match(pat, args[i]) and not args[i].startswith(("http:", "https:")):
                i += 1
            continue
        if a.startswith("-"):
            i += 1
            continue
        pos.append(a)
        i += 1
        if len(pos) == 2:
            rest = args[i:]
            break
    if dashdash and len(pos) < 2:
        cmd, cargs = (rest[0], rest[1:]) if rest else (None, [])
    elif len(pos) >= 2:
        cmd, cargs = pos[1], rest
    else:
        cmd, cargs = None, []
    if not cmd:
        acc.protect("unrecognized MCP command")
        return
    if transport in ("http", "sse") or cmd.startswith(("http://", "https://")):
        acc.add(target_from_url(cmd), pinnable=True)
        return
    t = _server_target(cmd, cargs, cwd)
    if t is None:
        acc.protect(f"unrecognized MCP command: {cmd}")
    else:
        acc.add(t, pinnable=True)


def _claude(args: list[str], cwd: str, acc: _Acc) -> None:
    idx = next((i for i, a in enumerate(args) if a in ("mcp", "plugin", "plugins")), None)
    if idx is None:
        return
    group, rest = args[idx], args[idx + 1:]
    sub_i = next((i for i, a in enumerate(rest) if not a.startswith("-")), None)
    if sub_i is None:
        return
    sub, rest = rest[sub_i], rest[sub_i + 1:]
    if group == "mcp":
        if sub == "add":
            _mcp_add(rest, cwd, acc)
        elif sub == "add-json":
            pos = _positionals(rest, {"-s", "--scope"})
            try:
                spec = json.loads(pos[1]) if len(pos) > 1 else None
            except (ValueError, RecursionError):
                spec = None
            if not isinstance(spec, dict):
                acc.protect("unrecognized MCP command: invalid add-json")
                return
            _spec_target(pos[0], spec, cwd, acc)
        elif sub == "add-from-claude-desktop":
            acc.protect("import of MCP servers from Claude Desktop")
        return
    if sub in ("install", "i", "enable", "update"):
        pos = _positionals(rest, {"-s", "--scope"})
        if pos:
            _plugin(pos[0], acc)
        else:
            acc.protect("unrecognized plugin command")
    elif sub in ("marketplace", "marketplaces"):
        pos = _positionals(rest, {"-s", "--scope"})
        if pos[:1] == ["add"]:
            acc.protect(f"new marketplace: {pos[1] if len(pos) > 1 else '?'}")


_GIT_CLONE_VALUE = {
    "-b", "--branch", "--depth", "-o", "--origin", "-c", "--config", "--reference", "-j", "--jobs", "--template",
    "--separate-git-dir", "-u", "--upload-pack", "--filter", "--shallow-since", "--shallow-exclude",
    "--server-option", "--bundle-uri", "--reference-if-able",
}


def _git(args: list[str], cwd: str, acc: _Acc) -> None:
    i = 0
    while i < len(args) and args[i].startswith("-"):
        if args[i] == "-C" and i + 1 < len(args):
            cwd = _abspath(args[i + 1], cwd)
        i += 2 if args[i] in ("-C", "-c") else 1
    if i >= len(args) or args[i] != "clone":
        return
    rest = args[i + 1:]
    branch = None
    for j, a in enumerate(rest):
        if a in ("-b", "--branch") and j + 1 < len(rest):
            branch = rest[j + 1]
        elif a.startswith("--branch="):
            branch = a.split("=", 1)[1]
    pos = _positionals(rest, _GIT_CLONE_VALUE)
    if not pos:
        return
    url = pos[0]
    dest = pos[1] if len(pos) > 1 else url.rstrip("/").rsplit("/", 1)[-1].rsplit(":", 1)[-1].removesuffix(".git")
    if install_dir(_abspath(dest, cwd)):
        acc.add(Target("git", url, url=url, version=branch or None))


def _copy(exe: str, args: list[str], cwd: str, acc: _Acc) -> None:
    target_dir = None
    values = {"-t", "--target-directory", "-S", "--suffix", "-e", "--rsh", "-m", "--mode", "-o", "--owner",
              "-g", "--group"} if exe in ("cp", "mv", "ln", "install", "rsync") else set()
    for j, a in enumerate(args):
        if a in ("-t", "--target-directory") and j + 1 < len(args):
            target_dir = args[j + 1]
        elif a.startswith("--target-directory="):
            target_dir = a.split("=", 1)[1]
    pos = _positionals(args, values)
    if target_dir is not None:
        dest, srcs = target_dir, pos
    elif len(pos) >= 2:
        dest, srcs = pos[-1], pos[:-1]
    else:
        return
    if not install_dir(_abspath(dest, cwd)):
        return
    for s in srcs:
        if re.match(r"^[^/.~$][^/]*:", s) or s.startswith(("http://", "https://")):
            acc.protect("unscannable download")
            continue
        p = _abspath(s, cwd)
        acc.add(Target("local", s, name=p, path=p))


def _download(exe: str, args: list[str], cwd: str, acc: _Acc) -> None:
    outs: list[str] = []
    to_cwd = exe == "wget"
    i = 0
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if exe == "curl":
            if a in ("-o", "--output", "--output-dir"):
                outs.append(nxt)
                i += 2
                continue
            if a.startswith(("--output=", "--output-dir=")):
                outs.append(a.split("=", 1)[1])
            elif a in ("-O", "--remote-name", "--remote-name-all"):
                to_cwd = True
            elif a.startswith("-") and not a.startswith("--"):
                if "O" in a[1:]:
                    to_cwd = True
                if "o" in a[1:]:
                    val = a[a.index("o", 1) + 1:]
                    outs.append(val or nxt)
                    i += 1 if val else 2
                    continue
        else:  # wget
            if a in ("-O", "--output-document", "-P", "--directory-prefix"):
                outs.append(nxt)
                i += 2
                continue
            if a.startswith(("--output-document=", "--directory-prefix=")):
                outs.append(a.split("=", 1)[1])
            elif a.startswith("-O") and len(a) > 2:
                outs.append(a[2:])
        i += 1
    if to_cwd:
        outs.append(".")
    if any(o and o != "-" and install_dir(_abspath(o, cwd)) for o in outs):
        acc.protect("unscannable download")


def _extract(exe: str, args: list[str], cwd: str, acc: _Acc) -> None:
    if exe in ("tar", "bsdtar"):
        first = args[0] if args else ""
        extracting = any(
            a in ("--extract", "--get") or (a.startswith("-") and not a.startswith("--") and "x" in a) for a in args
        ) or (bool(first) and not first.startswith("-") and "x" in first)
        if not extracting:
            return
    paths = [cwd] + [_abspath(a.split("=", 1)[-1], cwd) for a in args]
    if any(install_dir(p) for p in paths):
        acc.protect("unscannable archive extract")


def _bawwab_decision(words: list[str]) -> bool:
    seen = False
    for w in words:
        b = os.path.basename(w)
        if b in ("bawwab", "bawwab.cli", "bawwab.cli:main"):
            seen = True
        elif seen and w in ("approve", "reject"):
            return True
    return False


def _bash(cmd: str, cwd: str, acc: _Acc, depth: int = 0) -> None:
    if depth > 3:
        acc.protect("shell nesting too deep")
        return
    for words, redirs in _segments(_tokens(cmd)):
        for r in redirs:
            p = _abspath(r, cwd)
            if install_dir(p):
                acc.protect("shell write into install dir")
            if _config_kind(p):
                acc.protect(f"shell write to Claude config: {os.path.basename(p)}")
            if _bawwab_path(p):
                acc.protect("bawwab state change")
        words = _strip_prefix(words)
        if not words:
            continue
        if _bawwab_decision(words):
            acc.protect("bawwab approval via tool call")
        exe = os.path.basename(words[0]).lstrip("(")
        args = words[1:]
        if exe == "cd":
            dest = next((a for a in args if not a.startswith("-")), None)
            cwd = str(Path.home()) if dest is None else (cwd if dest == "-" else _abspath(dest, cwd))
            continue
        if exe in _SHELLS:
            for j, a in enumerate(args):
                if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
                    script = next((x for x in args[j + 1:] if not x.startswith("-")), None)
                    if script is not None:
                        _bash(script, cwd, acc, depth + 1)
                    break
        elif exe == "eval":
            _bash(" ".join(args), cwd, acc, depth + 1)
        elif exe == "claude":
            _claude(args, cwd, acc)
        elif exe == "git":
            _git(args, cwd, acc)
        elif exe in ("cp", "mv", "ln", "rsync", "install"):
            _copy(exe, args, cwd, acc)
        elif exe in ("curl", "wget"):
            _download(exe, args, cwd, acc)
        elif exe in ("tar", "bsdtar", "unzip"):
            _extract(exe, args, cwd, acc)
        if exe in _READ_ONLY:
            continue
        for a in args:
            p = _abspath(a.split("=", 1)[-1] if a.startswith("-") or re.match(r"^\w+=", a) else a, cwd)
            if exe in _SHELL_WRITERS and install_dir(p):
                acc.protect("shell write into install dir")
            if _config_kind(p) and exe not in ("claude", "cd"):
                acc.protect(f"shell write to Claude config: {os.path.basename(p)}")
            if _bawwab_path(p):
                acc.protect("bawwab state change")


# ------------------------------------------------------------------ write / edit

def _new_content(inp: HookInput, path: str) -> str:
    ti = inp.tool_input
    if inp.tool_name == "Write":
        c = ti.get("content", "")
        if not isinstance(c, str):
            raise _Unevaluable
        return c
    try:
        cur = Path(path).read_text() if os.path.exists(path) else ""
    except (OSError, UnicodeDecodeError) as e:
        raise _Unevaluable from e
    edits = [ti] if inp.tool_name == "Edit" else ti.get("edits")
    if not isinstance(edits, list):
        raise _Unevaluable
    for e in edits:
        if not isinstance(e, dict):
            raise _Unevaluable
        old, new = e.get("old_string"), e.get("new_string")
        if not isinstance(old, str) or not isinstance(new, str):
            raise _Unevaluable
        if old == "" and cur == "":
            cur = new
            continue
        n = cur.count(old) if old else 0
        if n == 0 or (n > 1 and not e.get("replace_all")):
            raise _Unevaluable
        cur = cur.replace(old, new) if e.get("replace_all") else cur.replace(old, new, 1)
    return cur


def _servers(d: dict) -> dict[tuple[str, str], object]:
    out: dict[tuple[str, str], object] = {}
    top = d.get("mcpServers")
    if isinstance(top, dict):
        out.update({("", str(k)): v for k, v in top.items()})
    projects = d.get("projects")
    if isinstance(projects, dict):
        for pk, pv in projects.items():
            ms = pv.get("mcpServers") if isinstance(pv, dict) else None
            if isinstance(ms, dict):
                out.update({(str(pk), str(k)): v for k, v in ms.items()})
    return out


_PROTECTED_KEYS = ("hooks", "disableAllHooks", "extraKnownMarketplaces", "enableAllProjectMcpServers")


def _config_change(inp: HookInput, path: str, acc: _Acc) -> None:
    name = os.path.basename(path)
    try:
        new_text = _new_content(inp, path)
    except _Unevaluable:
        acc.protect(f"edit to {name} could not be evaluated")
        return
    try:
        old_text = Path(path).read_text() if os.path.exists(path) else ""
        old = json.loads(old_text) if old_text.strip() else {}
    except (OSError, ValueError, RecursionError):
        old = {}
    try:
        new = json.loads(new_text)
    except (ValueError, RecursionError):
        acc.protect(f"invalid JSON in {name}")
        return
    if not isinstance(new, dict):
        acc.protect(f"invalid JSON in {name}")
        return
    old = old if isinstance(old, dict) else {}
    for k in _PROTECTED_KEYS:
        if new.get(k) != old.get(k):
            acc.protect(f"{k} changed in {name}")
    old_servers = _servers(old)
    for key, spec in _servers(new).items():
        if spec == old_servers.get(key):
            continue
        if not isinstance(spec, dict):
            acc.protect(f"unrecognized MCP command: {key[1]}")
            continue
        _spec_target(key[1], spec, inp.cwd, acc)
    newp, oldp = new.get("enabledPlugins"), old.get("enabledPlugins")
    if isinstance(newp, dict):
        oldp = oldp if isinstance(oldp, dict) else {}
        for plugin, on in newp.items():
            if on is True and oldp.get(plugin) is not True:
                _plugin(str(plugin), acc)


def _install_write(inp: HookInput, path: str, acc: _Acc) -> None:
    kind, base = install_dir(path)  # type: ignore[misc]
    if kind == "plugins":
        acc.protect("direct write into plugins dir")
        return
    rel = Path(path).relative_to(base).parts
    root = os.path.join(base, rel[0]) if kind == "skills" and len(rel) >= 2 else os.path.dirname(path)
    try:
        content = _new_content(inp, path)
    except _Unevaluable:
        acc.protect(f"edit to {os.path.basename(path)} could not be evaluated")
        return
    t = Target("local", root, name=root, path=root)
    acc.add(t)
    acc.overlays.setdefault(t, {})[path] = content


def _file_tool(inp: HookInput, acc: _Acc) -> None:
    fp = inp.tool_input.get("file_path")
    if not isinstance(fp, str) or not fp:
        return
    p = os.path.normpath(fp if os.path.isabs(fp) else os.path.join(inp.cwd or "/", fp))
    cands = [p] + ([rp] if (rp := os.path.realpath(p)) != p else [])
    if any(_bawwab_path(c) for c in cands):
        acc.protect("bawwab state change")
        return
    for c in cands:
        if _config_kind(c):
            _config_change(inp, c, acc)
            return
    for c in cands:
        if install_dir(c):
            _install_write(inp, c, acc)
            return


def detect_install(inp: HookInput) -> Targets | Protected | None:
    acc = _Acc()
    ti = inp.tool_input if isinstance(inp.tool_input, dict) else {}
    inp = HookInput(inp.tool_name, ti, inp.cwd or "/")
    if inp.tool_name == "Bash":
        cmd = ti.get("command")
        if isinstance(cmd, str):
            _bash(cmd, inp.cwd, acc)
    elif inp.tool_name in ("Write", "Edit", "MultiEdit"):
        _file_tool(inp, acc)
    return acc.result()
