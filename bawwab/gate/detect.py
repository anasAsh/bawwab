"""Pure install detection for PreToolUse tool calls.

No network and no scanning. File reads are limited to the config file being
edited (to compute its new content), a project's .mcp.json (for
enabledMcpjsonServers), the marketplace JSONs and known_marketplaces.json;
directory listings only for shell globs in cp/mv/rsync arguments.
"""
from __future__ import annotations

import dataclasses
import functools
import glob as _glob
import json
import os
import posixpath
import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from bawwab.gate.prefilter import bash_install_like, context as _prefilter_context
from bawwab.fetch.target import runner_extras, target_from_command, target_from_url
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
    # Protected reasons found in the same call; each needs its own approval.
    protected: list[str] = field(default_factory=list)


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
_SHELL_WRITERS = {"tee", "sed", "perl", "truncate", "patch", "python", "python3", "node"}
_SENSITIVE = (
    ".claude.json", ".mcp.json", ".claude/settings", ".claude/skills", ".claude/commands", ".claude/agents",
    ".claude/plugins",
)
# Environment variables that make an interpreter load extra code, or that switch the package index.
_CODE_ENV = {
    "NODE_OPTIONS", "NODE_PATH", "PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH",
    "BASH_ENV", "ENV", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS",
}
_INDEX_ENV = {
    "NPM_CONFIG_REGISTRY", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_INDEX", "UV_DEFAULT_INDEX", "UV_FIND_LINKS",
    "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "NPM_CONFIG_USERCONFIG", "PIP_CONFIG_FILE",
    "UV_CONFIG_FILE",
}
_EXEC_SETTINGS = ("statusLine", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "env")
_PROTECTED_KEYS = ("hooks", "disableAllHooks", "extraKnownMarketplaces", "enableAllProjectMcpServers")
_CLAUDE_SUBCMD = re.compile(
    r"\b(?:mcp\s+(?:add|add-json|add-from-claude-desktop)|plugins?\s+(?:install|i|enable|update|marketplace))\b"
)


class _Unevaluable(Exception):
    pass


class _TooComplex(Exception):
    """The command needs more analysis work than the per-call budget allows."""


_MAX_DEPTH = 3


class _Acc:
    def __init__(self, budget: int = 1 << 62) -> None:
        self.targets: list[Target] = []
        self.protected: list[str] = []
        self.pinnable = False
        self.overlays: dict[Target, dict[str, str]] = {}
        self.budget = budget  # bytes of shell text we may still analyse in this detect_install call
        self.scanned: set[tuple[str, str]] = set()  # (text, cwd) already run through _bash
        self.root = ""  # the top-level command text (the raw backstop skips nested text that is part of it)

    def spend(self, n: int) -> None:
        self.budget -= n
        if self.budget < 0:
            raise _TooComplex

    def add(self, t: Target, pinnable: bool = False) -> None:
        if t not in self.targets:
            self.targets.append(t)
        self.pinnable = self.pinnable or pinnable

    def protect(self, reason: str) -> None:
        if reason not in self.protected:
            self.protected.append(reason)

    def result(self) -> Targets | Protected | None:
        if self.targets:
            return Targets(self.targets, self.pinnable, self.overlays, self.protected)
        if self.protected:
            return Protected("; ".join(self.protected))
        return None


# ------------------------------------------------------------------ paths

def _home_vars(tok: str) -> str:
    if "$" not in tok:
        return tok
    home = str(Path.home())
    return re.sub(r"\$\{HOME\}|\$HOME(?![A-Za-z0-9_])", lambda _: home, tok)


def _abspath(tok: str, cwd: str) -> str:
    p = _home_vars(tok)
    if p.startswith("~"):
        p = os.path.expanduser(p)
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


def _bawwab_root() -> str:
    return _norm_root(os.environ.get("BAWWAB_HOME"), os.environ.get("HOME"))


@functools.lru_cache(maxsize=16)
def _norm_root(_bawwab_env: str | None, _home_env: str | None) -> str:  # args are the cache key
    return os.path.normpath(str(bawwab_home()))


def _under(p: str, root: str) -> bool:
    return p == root or p.startswith(root.rstrip("/") + "/")


def _bawwab_path(p: str) -> bool:
    if _under(p, _bawwab_root()):
        return True
    return os.path.basename(p) == "bawwab.json" and os.path.basename(os.path.dirname(p)) == ".claude"


def _bawwab_mentions() -> tuple[str, ...]:
    home = os.path.normpath(str(bawwab_home()))
    out = [home, ".claude/bawwab.json"]
    user = str(Path.home())
    if _under(home, user) and home != user:
        rel = os.path.relpath(home, user)
        out += [f"~/{rel}", f"$HOME/{rel}", f"${{HOME}}/{rel}"]
    return tuple(out)


def _mentions_sensitive(text: str) -> bool:
    return any(s in text for s in _SENSITIVE + _bawwab_mentions())


def _config_kind(p: str) -> str | None:
    name = os.path.basename(p)
    if name == ".mcp.json":
        return "mcp"
    if name == ".claude.json" and p == os.path.normpath(str(claude_json())):
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

def _env_checks(env: dict[str, str], name: str, acc: _Acc) -> None:
    for k in env:
        if k in _CODE_ENV or k.startswith("DYLD_"):
            acc.protect(f"server env loads code: {k} ({name})")
        elif k.upper() in _INDEX_ENV or k.upper().startswith("UV_INDEX"):
            acc.protect(f"custom package index: {k} ({name})")


def _add_server(name: str, cmd: str, args: list[str], env: dict[str, str], cwd: str, acc: _Acc) -> None:
    _env_checks(env, name, acc)
    t = target_from_command(cmd, args)
    if t is None:
        acc.protect(f"unrecognized MCP command: {name}")
        return
    if t.kind == "local":
        script = next((a for a in args if not a.startswith("-")), None)
        if script and not os.path.isabs(script):
            t = dataclasses.replace(t, path=_abspath(posixpath.dirname(script) or ".", cwd))
    acc.add(t, pinnable=True)
    extras, reasons = runner_extras(cmd, args)
    for r in reasons:
        acc.protect(f"{r} ({name})")
    for e in extras:
        acc.add(e, pinnable=False)


def _spec_target(name: str, spec: dict, cwd: str, acc: _Acc) -> None:
    env = spec.get("env")
    env = {str(k): str(v) for k, v in env.items()} if isinstance(env, dict) else {}
    url = spec.get("url")
    if isinstance(url, str) and url:
        _env_checks(env, name, acc)
        acc.add(target_from_url(url), pinnable=True)
        return
    cmd, args = spec.get("command"), spec.get("args", [])
    if isinstance(cmd, str) and isinstance(args, list) and all(isinstance(a, str) for a in args):
        _add_server(name, cmd, args, env, cwd, acc)
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


def _is_bawwab_plugin(spec: str) -> bool:
    return str(spec).split("@", 1)[0] == "bawwab"


# ------------------------------------------------------------------ bash

def _strip_fd_numbers(cmd: str) -> str:
    """Drop fd numbers glued to redirections (2>x, 2>&1, 1>>x, 0<x) outside quotes."""
    out: list[str] = []
    quote = None
    i = 0
    while i < len(cmd):
        c = cmd[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < len(cmd):
                out.append(cmd[i:i + 2])
                i += 2
                continue
            if c == quote:
                quote = None
            out.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < len(cmd):
            out.append(cmd[i:i + 2])
            i += 2
            continue
        if c in "'\"":
            quote = c
            out.append(c)
            i += 1
            continue
        if c.isdigit() and (i == 0 or cmd[i - 1] in " \t\n;&|()"):
            j = i
            while j < len(cmd) and cmd[j].isdigit():
                j += 1
            if j < len(cmd) and cmd[j] in "<>":
                out.append(" ")
                i = j
                continue
        out.append(c)
        i += 1
    return "".join(out)


_HEREDOC_TOKEN = "__bawwab_heredoc_{}__"
_HEREDOC_TOKEN_RE = re.compile(r"__bawwab_heredoc_(\d+)__")
_HEREDOC_DELIM = re.compile(r"(-?)[ \t]*(?:'([^'\n]*)'|\"([^\"\n]*)\"|([A-Za-z0-9_.-]+))")


_LET = re.compile(r"let[ \t]")


class _AllText:
    """`as_text` value that reads every arithmetic-candidate region as ordinary text."""

    def __contains__(self, _: object) -> bool:
        return True


_ALL_TEXT = _AllText()


def _skip_quoted(cmd: str, j: int) -> int:
    """Index just past the quoted string / backtick group / escape starting at cmd[j] (n if unclosed)."""
    n = len(cmd)
    c = cmd[j]
    if c == "\\":
        return min(j + 2, n)
    j += 1
    while j < n:
        if cmd[j] == "\\" and c != "'":
            j += 2
            continue
        if cmd[j] == c:
            return j + 1
        j += 1
    return n


def _arith_region_end(cmd: str, i: int, spend) -> int | None:
    """End of the arithmetic-candidate region starting at i, or None if there is none.

    Candidates are `((` (also `for ((`), `$((`, `$[` and a `let` command. This is a simple, conservative
    quote-aware matched-pair scan: callers analyse the command under both readings (arithmetic and plain
    text), so it does not need to match bash exactly; it only needs a sensible extent. Scanned length is
    charged to `spend` so many unclosed candidates fail closed on the work budget instead of going quadratic.
    """
    n = len(cmd)
    if cmd.startswith("$[", i):
        close, opener, depth, j = "]", "[", 0, i + 2
    elif cmd.startswith("((", i) or cmd.startswith("$((", i):
        if cmd[i] == "(" and i > 0 and cmd[i - 1] in "$<>":
            return None  # `$((` is handled at the `$`; `<((`/`>((` is process substitution
        close, opener, depth, j = ")", "(", 0, i + (3 if cmd[i] == "$" else 2)
    elif _LET.match(cmd, i) and (i == 0 or cmd[i - 1] in " \t\n;&|(){}"):
        j = i + 3
        while j < n and cmd[j] not in ";&|\n)":
            j = _skip_quoted(cmd, j) if cmd[j] in "'\"`\\" else j + 1
        spend(j - i)
        return j
    else:
        return None
    start = j
    while j < n:
        c = cmd[j]
        if c in "'\"`\\":
            j = _skip_quoted(cmd, j)
            continue
        if c == opener:
            depth += 1
        elif c == close:
            if depth == 0:
                spend(j - start)
                if close == "]":
                    return j + 1
                return j + 2 if cmd.startswith("))", j) else None
            depth -= 1
        j += 1
    spend(n - start)
    return None


def _extract_heredocs(cmd: str, as_text=(), regions: list[int] | None = None,
                      spend=lambda n: None) -> tuple[str, list[str], dict[int, int]]:
    """Replace each real `<<DELIM … DELIM` with `< __bawwab_heredoc_N__` and return the bodies.

    Only operators outside quotes and comments count, and never `<<<`. Arithmetic-candidate regions
    (`((…))`, `$((…))`, `$[…]`, `let …`) are read as arithmetic (no heredocs inside) unless their start
    offset is in `as_text`, in which case they are read as ordinary text; offsets of the regions met are
    appended to `regions`. An unterminated heredoc consumes nothing: the following lines stay normal
    command lines (and are scanned there). Its body is not recorded as text; instead the third value maps
    its index to the offset where its (implicit, to end of input) body starts, for callers that need it.
    """
    out: list[str] = []
    bodies: list[str] = []
    open_from: dict[int, int] = {}
    missing: set[tuple[bool, str]] = set()  # delimiters known not to occur from some offset on
    pending: list[tuple[bool, str, int]] = []  # (strip tabs, delimiter, body index)
    quote = None
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if quote:
            if c == "\\" and quote == '"' and i + 1 < n:
                out.append(cmd[i:i + 2])
                i += 2
                continue
            if c == quote:
                quote = None
            out.append(c)
            i += 1
            continue
        if c == "\\" and i + 1 < n:
            out.append(cmd[i:i + 2])
            i += 2
            continue
        if c in "'\"":
            quote = c
        elif c == "#" and (i == 0 or cmd[i - 1] in " \t\n;&|("):
            j = cmd.find("\n", i)
            j = n if j < 0 else j
            out.append(cmd[i:j])
            i = j
            continue
        elif c in "($l" and (end := _arith_region_end(cmd, i, spend)) is not None:
            if regions is not None:
                regions.append(i)
            if i not in as_text:
                out.append(cmd[i:end])
                i = end
                continue
        elif cmd.startswith("<<", i) and not cmd.startswith("<<<", i) and (i == 0 or cmd[i - 1] != "<"):
            m = _HEREDOC_DELIM.match(cmd, i + 2)
            delim = next((g for g in (m.group(2), m.group(3), m.group(4)) if g is not None), None) if m else None
            if delim:
                pending.append((m.group(1) == "-", delim, len(bodies)))
                bodies.append("")
                out.append(f"< {_HEREDOC_TOKEN.format(len(bodies) - 1)}")
                i = m.end()
                continue
        elif c == "\n" and pending:
            out.append(c)
            i += 1
            for strip, delim, idx in pending:
                found = False
                if (strip, delim) not in missing:
                    lines: list[str] = []
                    j = i
                    while j <= n:
                        k = cmd.find("\n", j)
                        k = n if k < 0 else k
                        line = cmd[j:k]
                        if (line.lstrip("\t") if strip else line) == delim:
                            found, j = True, k + 1
                            break
                        lines.append(line)
                        if k >= n:
                            break
                        j = k + 1
                if found:
                    bodies[idx] = "\n".join(lines)
                    i = min(j, n)
                else:  # unterminated: the rest stays in place as normal command lines
                    missing.add((strip, delim))  # not found from i on, so not from any later offset either
                    open_from[idx] = i
                    break
            pending = []
            continue
        out.append(c)
        i += 1
    return "".join(out), bodies, open_from


def _balanced(cmd: str) -> bool:
    """The tokeniser reads cmd without running off an open quote."""
    try:
        _shlex_tokens(cmd)
    except ValueError:
        return False
    return True


def _shlex_tokens(cmd: str) -> list[str]:
    lex = shlex.shlex(cmd, posix=True, punctuation_chars=_PUNCT)
    lex.whitespace = " \t\r"
    lex.whitespace_split = True
    lex.commenters = ""
    return list(lex)


def _tokens(cmd: str) -> list[str]:
    cmd = _strip_fd_numbers(cmd.replace("\\\n", " ")).replace("`", " ; ")
    try:
        return _shlex_tokens(cmd)
    except ValueError:  # unbalanced quotes: crude split, quotes dropped
        return re.findall(r"[();<>|&\n]+|[^\s();<>|&\n]+", re.sub(r"[\"'\\]", "", cmd))


def _words(cmd: str) -> list[str]:
    return [t for t in _tokens(cmd) if not (t and all(c in _PUNCT for c in t))]


@dataclass
class _Seg:
    words: list[str]
    redirs: list[str]
    inputs: list[str]
    piped: bool  # stdin comes from the previous segment through a pipe


def _segments(tokens: list[str]) -> list[_Seg]:
    """Split into simple commands with their redirect targets and input sources."""
    segs: list[_Seg] = []
    cur = _Seg([], [], [], False)
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok and all(c in _PUNCT for c in tok):
            nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
            if ">" in tok:
                cur.redirs.append(nxt)
                i += 2
                continue
            if "<" in tok:
                cur.inputs.append(nxt)
                i += 2
                continue
            if cur.words or cur.redirs or cur.inputs:
                segs.append(cur)
            cur = _Seg([], [], [], tok in ("|", "|&"))
            i += 1
            continue
        cur.words.append(tok)
        i += 1
    if cur.words or cur.redirs or cur.inputs:
        segs.append(cur)
    return segs


# wrapper -> flags that take a value; positional count it consumes after flags (timeout's DURATION)
_WRAPPERS: dict[str, tuple[set[str], int]] = {
    "sudo": ({"-u", "-g", "-U", "-C", "-h", "-p", "-r", "-t", "-D", "-R", "-T", "--user", "--group"}, 0),
    "doas": ({"-u", "-C"}, 0),
    "env": ({"-u", "--unset", "-C", "--chdir"}, 0),
    "command": (set(), 0),
    "builtin": (set(), 0),
    "exec": ({"-a"}, 0),
    "nohup": (set(), 0),
    "time": ({"-f", "--format", "-o", "--output"}, 0),
    "nice": ({"-n", "--adjustment"}, 0),
    "ionice": ({"-c", "--class", "-n", "--classdata", "-p", "--pid", "-P", "--pgid", "-u", "--uid"}, 0),
    "stdbuf": ({"-i", "-o", "-e", "--input", "--output", "--error"}, 0),
    "timeout": ({"-s", "--signal", "-k", "--kill-after"}, 1),
    "xargs": ({"-I", "-i", "-n", "-P", "-L", "-l", "-d", "-E", "-e", "-s", "-a", "--arg-file", "--delimiter",
               "--max-args", "--max-procs", "--max-lines", "--max-chars", "--replace", "--eof"}, 0),
    "chronic": (set(), 0),
    "unbuffer": (set(), 0),
    "caffeinate": (set(), 0),
}


_RUNNERS = {"uv", "poetry", "pipenv", "pdm", "hatch", "rye"}
_RUN_VALUE = {"--with", "--python", "-p", "--project", "--directory", "--extra", "--group", "--env-file", "--index",
              "--index-url", "--extra-index-url", "--package", "-e", "--env", "-C", "--directory"}


def _strip_prefix(words: list[str]) -> list[str]:
    words = list(words)
    i = 0
    while i < len(words):
        w = words[i]
        if re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", w, re.S):
            i += 1
            continue
        b = os.path.basename(w)
        if b in _RUNNERS and i + 1 < len(words) and words[i + 1] == "run":
            i += 2
            while i < len(words) and words[i].startswith("-") and words[i] != "--":
                a = words[i]
                i += 2 if (a in _RUN_VALUE and "=" not in a) else 1
            if i < len(words) and words[i] == "--":
                i += 1
            continue
        if b not in _WRAPPERS:
            break
        values, npos = _WRAPPERS[b]
        i += 1
        while i < len(words) and words[i].startswith("-") and words[i] not in ("-", "--"):
            a = words[i]
            if b == "env" and (a in ("-S", "--split-string") or a.startswith(("-S", "--split-string="))):
                if a in ("-S", "--split-string"):
                    val = words[i + 1] if i + 1 < len(words) else ""
                    words[i:i + 2] = _words(val)
                else:
                    words[i:i + 1] = _words(a[2:] if a.startswith("-S") else a.split("=", 1)[1])
                break
            if a.startswith("--") and "=" in a:
                i += 1
            elif a in values:
                i += 2
            elif len(a) > 2 and not a.startswith("--") and a[:2] in values:  # -n10, -s9
                i += 1
            else:
                i += 1
        if i < len(words) and words[i] == "--":
            i += 1
        i += npos
    return words[i:]


def _claude_index(words: list[str]) -> int | None:
    """Index of the first claude argument when words invoke Claude Code (claude, npx @anthropic-ai/claude-code,
    node …/claude-code/cli.js), else None."""
    if not words:
        return None
    exe = os.path.basename(words[0])
    if exe == "claude":
        return 1
    if exe in ("npx", "bunx", "pnpm", "yarn"):
        i = 1
        if exe in ("pnpm", "yarn"):
            if words[1:2] != ["dlx"]:
                return None
            i = 2
        while i < len(words) and words[i].startswith("-"):
            i += 2 if words[i] in ("-p", "--package") else 1
        if i < len(words) and re.fullmatch(r"@anthropic-ai/claude-code(@[^\s]*)?", words[i]):
            return i + 1
        return None
    if re.fullmatch(r"node(js)?|bun|deno", exe):
        script = next((x for x in words[1:] if not x.startswith("-")), None)
        if script and "claude-code" in script and re.search(r"cli\.m?js$", script):
            return words.index(script) + 1
    return None


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
    env: dict[str, str] = {}
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
        elif a.startswith("--env="):
            k, _, v = a.split("=", 1)[1].partition("=")
            env[k] = v
        if a in _MCP_ADD_VALUE:
            i += 2
            continue
        if a in ("-e", "--env", "-H", "--header"):
            i += 1
            pat = r"[A-Za-z_][A-Za-z0-9_]*=" if a in ("-e", "--env") else r"[^\s:/]+:"
            while i < len(args) and re.match(pat, args[i]) and not args[i].startswith(("http:", "https:")):
                if a in ("-e", "--env"):
                    k, _, v = args[i].partition("=")
                    env[k] = v
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
    name = pos[0] if pos else "?"
    if not cmd:
        acc.protect("unrecognized MCP command")
        return
    if transport in ("http", "sse") or cmd.startswith(("http://", "https://")):
        _env_checks(env, name, acc)
        acc.add(target_from_url(cmd), pinnable=True)
        return
    before = len(acc.protected)
    _add_server(name, cmd, cargs, env, cwd, acc)
    if len(acc.protected) > before and acc.protected[-1] == f"unrecognized MCP command: {name}":
        acc.protected[-1] = f"unrecognized MCP command: {cmd}"


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
    pos = _positionals(rest, {"-s", "--scope"})
    if sub in ("install", "i", "enable", "update"):
        if pos:
            _plugin(pos[0], acc)
        else:
            acc.protect("unrecognized plugin command")
    elif sub in ("disable", "uninstall", "remove", "rm"):
        if any(_is_bawwab_plugin(p) for p in pos):
            acc.protect("disables bawwab")
    elif sub in ("marketplace", "marketplaces"):
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


def _has_glob(s: str) -> bool:
    return any(c in s for c in "*?[")


def _expand(tok: str, cwd: str) -> list[str]:
    if not _has_glob(tok):
        return [_abspath(tok, cwd)]
    return sorted(os.path.normpath(m) for m in _glob.glob(_abspath(tok, cwd)))


def _dot_component(tok: str) -> bool:
    return re.search(r"(?:^|/)\.[^/.]", os.path.expanduser(_home_vars(tok))) is not None


def _moves_config(p: str) -> bool:
    """p is, or contains, a Claude config/install path or the bawwab home."""
    p = os.path.normpath(p)
    if _config_kind(p) or _bawwab_path(p) or install_dir(p) or os.path.basename(p) == ".claude":
        return True
    roots = (str(claude_home()), str(claude_json()), str(bawwab_home()))
    return any(_under(os.path.normpath(r), p) for r in roots)


def _check_dest(p: str, acc: _Acc) -> None:
    if _config_kind(p):
        acc.protect(f"shell write to Claude config: {os.path.basename(p)}")
    if _bawwab_path(p):
        acc.protect("bawwab state change")


def _copy(exe: str, args: list[str], cwd: str, acc: _Acc) -> None:
    """cp/mv/ln/rsync/install: only the destination decides; sources are scanned when it is an install dir."""
    target_dir = None
    values = {"-t", "--target-directory", "-S", "--suffix", "-e", "--rsh", "-m", "--mode", "-o", "--owner",
              "-g", "--group"}
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
    removes_src = exe == "mv" or (exe == "rsync" and any(
        a.startswith(("--remove-source-files", "--remove-sent-files")) for a in args))
    if removes_src:
        for src in srcs:
            for sp in _expand(src, cwd) or [_abspath(src, cwd)]:
                if _moves_config(sp):
                    acc.protect("moves Claude config")
    if exe == "rsync" and any(a.startswith("--delete") for a in args):
        for d in _expand(dest, cwd) or [_abspath(dest, cwd)]:
            if _moves_config(d) or install_dir(d):
                acc.protect("moves Claude config")
    dests = _expand(dest, cwd)
    if not dests:
        if _dot_component(dest):  # may have been meant for a hidden dir such as ~/.claude
            acc.protect(f"unresolvable glob: {dest}")
        return
    for d in dests:
        _check_dest(d, acc)
        if os.path.isdir(d):  # cp x dir/ lands at dir/<basename>
            for s in srcs:
                _check_dest(os.path.join(d, os.path.basename(s.rstrip("/"))), acc)
    if not any(install_dir(d) for d in dests):
        return
    for s in srcs:
        if re.match(r"^[^/.~$][^/]*:", s) or s.startswith(("http://", "https://")):
            acc.protect("unscannable download")
            continue
        matches = _expand(s, cwd)
        if not matches:
            acc.protect(f"unresolvable glob: {s}")
        for p in matches:
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


_INTERPRETER = re.compile(r"python[0-9.]*|node(js)?|perl|ruby|bun|deno|php|bash|sh|zsh|dash|ksh")


def _is_interpreter(exe: str, args: list[str]) -> bool:
    """A program that may rewrite files named in its script or arguments."""
    if _INTERPRETER.fullmatch(exe):
        return True
    if exe in ("sed", "gsed"):
        return any(a.startswith(("-i", "--in-place")) or (a.startswith("-") and not a.startswith("--") and "i" in a[1:])
                   for a in args)
    if exe in ("awk", "gawk"):
        return any(a == "inplace" or a.endswith("inplace") for a in args)
    return False


def _script_index(exe: str, args: list[str]) -> int | None:
    """Index of the script file an interpreter runs, or None (-c/-e code, -m module, stdin)."""
    i = 0
    while i < len(args):
        a = args[i]
        if a in ("-c", "-e", "-m", "-", "--eval", "-p", "--print", "-r", "-E"):
            return None
        if a.startswith("-"):
            i += 1
            continue
        return i
    return None


def _sensitive_text(text: str, cwd: str) -> bool:
    """Mentions a Claude config / install dir / bawwab path, literally or relative to cwd."""
    if _mentions_sensitive(text):
        return True
    for c in re.findall(r"[A-Za-z0-9_./~${}+@-]+", text):
        if "." not in c and "/" not in c:
            continue
        p = _abspath(c, cwd)
        if _config_kind(p) or install_dir(p) or _bawwab_path(p):
            return True
    return False


# ------------------------------------------------------------------ raw-text backstop (R25)
#
# The structured passes model bash's quotes, comments, heredocs and arithmetic across the whole command.
# Wherever that model differs from bash, a line bash runs can look like quoted/comment/heredoc text and be
# skipped. The backstop does not carry any of that state: each physical line is read on its own, and
# every separator, quote and comment character on it is also a cut point, each piece being read as a fresh
# simple command. Only the per-segment recognisers run (claude invocations, copies/clones/downloads into
# install dirs, writes/moves of Claude config or the bawwab home, bawwab approvals, disabling bawwab); no
# interpreter-mention heuristic. Units of a line:
#   line   the whole line, fresh tokeniser state (unbalanced quotes: retried with quotes removed)
#   (b)    after each separator that the line reading sees inside quotes: quote characters deleted, up to
#          the next separator
#   (a)    after each separator inside quotes and after every quote/comment character: up to the next
#          separator, quote or comment character (targets only)
# A cut that the line reading already treats as a command start is not re-read as a piece, so a quoted
# argument of a visible command (`-H 'Authorization: x'`, `npx -c 'echo hi'`) is never split into a wrong
# package name. Protected reasons come from the line and (b) units; (a) units only add targets.

_RAW_SEP = re.compile(r"\$\(|\$\{|[;&|(){}`]")
_RAW_CUT_B = re.compile(r"\$\(|\$\{|[;&|(){}`#]")
_RAW_CUT_A = re.compile(r"\$\(|\$\{|[;&|(){}`'\"#]")
_RAW_BRACED = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")  # ${HOME} -> $HOME before `${` becomes a cut
_RAW_DOLLAR_QUOTE = re.compile(r"\$(?=['\"])")
_RAW_DOLLAR = re.compile(r"\$(?![A-Za-z_{(])")  # a `$` that starts no parameter (`$'…'`, `$"…"`, a stray one)
_RAW_KEYWORDS = {"if", "then", "else", "elif", "do", "while", "until", "!", "time", "coproc", "eval", "exec"}
_RAW_WRITERS = {"tee", "sed", "gsed", "perl", "truncate", "patch", "touch", "rm", "unlink", "shred", "sponge",
                "chmod", "chown", "chattr", "mkdir", "rmdir"}
_RAW_MAX_CWDS = 16


def _sensitive_dir(p: str) -> bool:
    """A cwd from which a relative path can reach Claude config, an install dir or the bawwab home."""
    return "/.claude/" in p + "/" or _moves_config(p) or _bawwab_path(p)


def _quoted_cuts(line: str) -> tuple[list[int], list[int]]:
    """(ends of separators inside quotes, ends of quote/comment characters) under a fresh reading of line."""
    seps: list[int] = []
    marks: list[int] = []
    q = None
    i, n = 0, len(line)
    while i < n:
        c = line[i]
        if c == "\\" and q != "'":
            i += 2
            continue
        if c in "'\"#":
            marks.append(i + 1)
            if q is None and c != "#":
                q = c
            elif q == c:
                q = None
        elif q is not None and (m := _RAW_SEP.match(line, i)):
            seps.append(m.end())
            i = m.end()
            continue
        i += 1
    return seps, marks


def _raw_cut(cut: re.Pattern[str], line: str, s: int) -> int:
    m = cut.search(line, s)
    return m.start() if m else len(line)


def _raw_clean(s: str) -> str:
    return _RAW_DOLLAR.sub("", s).replace("\\", "")


class _RawCwd:
    """cwds a raw unit may run in: the latest `cd`, every `cd` into a sensitive dir, and the start cwd.
    A fake `cd` (one inside quotes, read as a piece) can add a cwd but never hide a sensitive one."""

    def __init__(self, cwd: str) -> None:
        self.start = self.latest = cwd
        self.sensitive = [cwd] if _sensitive_dir(cwd) else []

    def cd(self, args: list[str]) -> None:
        dest = next((a for a in args if not a.startswith("-")), None)
        if dest == "-":
            return
        dest = "~" if dest is None else dest
        absolute = os.path.isabs(_home_vars(dest)) or dest.startswith("~")
        bases = [self.latest] if absolute else [self.latest, *self.sensitive]
        self.latest = _abspath(dest, self.latest)
        for p in (_abspath(dest, b) for b in bases):
            if p not in self.sensitive and _sensitive_dir(p):
                self.sensitive.append(p)
        if len(self.sensitive) > _RAW_MAX_CWDS:
            raise _TooComplex

    def all(self) -> list[str]:
        return list(dict.fromkeys((self.latest, *self.sensitive, self.start)))


def _raw(text: str, cwd: str, acc: _Acc) -> None:
    """Raw-text backstop over `text` (see above)."""
    acc.spend(len(text))
    home, extra = _prefilter_context()
    cwds = _RawCwd(cwd)
    seen: set[tuple[str, bool, tuple[str, ...]]] = set()
    text = _RAW_BRACED.sub(r"$\1", text.replace("\\\n", ""))
    lines = text.split("\n")
    for li, line in enumerate(lines):
        if not line.strip():
            continue
        units = [(_RAW_DOLLAR_QUOTE.sub("", _raw_line_unit(lines, li, acc)), True)]  # cl$'a'ude is claude
        seps, marks = _quoted_cuts(line)
        for s in seps:  # each unit ends at the next cut, so the units of a line add up to O(len(line))
            unit = _raw_clean(line[s:_raw_cut(_RAW_CUT_B, line, s)])
            units.append((unit.replace("'", "").replace('"', ""), True))
            units.append((_raw_clean(line[s:_raw_cut(_RAW_CUT_A, line, s)]), False))
        for s in marks:
            units.append((_raw_clean(line[s:_raw_cut(_RAW_CUT_A, line, s)]), False))
        for unit, protect in units:
            if not unit.strip():
                continue
            here = tuple(cwds.all())
            if (unit, protect, here) in seen:
                continue
            seen.add((unit, protect, here))
            # the shared pre-filter never misses what detection finds, so a unit it rejects can only cd
            relevant = [c for c in here if bash_install_like(unit, c, home, extra)]
            if not relevant and "cd" not in unit:
                continue
            acc.spend(len(unit) * max(1, len(here)))
            _raw_unit(unit, cwds, relevant, acc, protect, lambda c, u=unit: bash_install_like(u, c, home, extra))


_RAW_JOIN_LINES = 50


def _raw_line_unit(lines: list[str], li: int, acc: _Acc) -> str:
    """The line itself; for `add-json` with a quote left open on the line (pretty-printed JSON), the line
    joined with the following ones up to where the quote closes, so the spec is read whole."""
    line = lines[li]
    if "add-json" not in line or _balanced(line):
        return line
    for j in range(li + 1, min(len(lines), li + 1 + _RAW_JOIN_LINES)):
        joined = "\n".join(lines[li:j + 1])
        acc.spend(len(joined))
        if _balanced(joined):
            return joined
    return line


def _raw_unit(unit: str, cwds: _RawCwd, relevant: list[str], acc: _Acc, protect: bool, is_relevant) -> None:
    sink = acc if protect else _Acc()
    for seg in _segments(_tokens(unit)):
        words = _raw_words(seg.words)
        if words and words[0] == "cd":
            cwds.cd(words[1:])
            relevant = [c for c in cwds.all() if is_relevant(c)]
            continue
        for c in relevant:
            _raw_seg(seg.redirs, words, c, sink)
    if sink is not acc:
        for t in sink.targets:
            acc.add(t, sink.pinnable)
            if t in sink.overlays:
                acc.overlays.setdefault(t, sink.overlays[t])


def _raw_words(words: list[str]) -> list[str]:
    while True:
        n = len(words)
        while words and words[0] in _RAW_KEYWORDS:
            words = words[1:]
        words = _strip_prefix(words)
        if len(words) == n:
            return words


def _raw_seg(redirs: list[str], words: list[str], cwd: str, acc: _Acc) -> None:
    """One simple command of a raw unit, through the per-segment recognisers only."""
    for r in redirs:
        p = _abspath(r, cwd)
        if install_dir(p):
            acc.protect("shell write into install dir")
        _check_dest(p, acc)
    if not words:
        return
    exe = os.path.basename(words[0])
    args = words[1:]
    if exe in ("bawwab", "bawwab.cli", "bawwab.cli:main") and _bawwab_decision(words):
        acc.protect("bawwab approval via tool call")
    ci = _claude_index(words)
    if ci is not None:
        _claude(words[ci:], cwd, acc)
        return
    fb = next((i + 1 for i in range(1, len(words)) if os.path.basename(words[i]) == "claude"
               and any(w in ("mcp", "plugin", "plugins") for w in words[i + 1:])), None)
    if fb is not None:  # claude behind an unknown wrapper, or claude named in prose: targets only
        scratch = _Acc()
        _claude(words[fb:], cwd, scratch)
        for t in scratch.targets:
            acc.add(t, scratch.pinnable)
    if (exe in ("mcp", "plugin", "plugins") or words[0].startswith("$")) and \
            _CLAUDE_SUBCMD.search(" ".join(words)):
        acc.protect("unrecognised claude invocation")
        return
    if exe == "git":
        _git(args, cwd, acc)
    elif exe in ("cp", "mv", "ln", "rsync", "install"):
        _copy(exe, args, cwd, acc)
    elif exe in ("curl", "wget"):
        _download(exe, args, cwd, acc)
    elif exe in ("tar", "bsdtar", "unzip"):
        _extract(exe, args, cwd, acc)
    elif exe == "dd":
        for a in args:
            if a.startswith("of="):
                p = _abspath(a[3:], cwd)
                if install_dir(p):
                    acc.protect("shell write into install dir")
                _check_dest(p, acc)
    elif exe in _RAW_WRITERS and (exe not in ("sed", "gsed") or _is_interpreter(exe, args)):
        for a in args:
            p = _abspath(a.split("=", 1)[-1] if a.startswith("-") or re.match(r"^\w+=", a) else a, cwd)
            if exe in _SHELL_WRITERS and install_dir(p):
                acc.protect("shell write into install dir")
            _check_dest(p, acc)


# ------------------------------------------------------------------ structured passes

def _bash(cmd: str, cwd: str, acc: _Acc, depth: int = 0) -> None:
    if depth > _MAX_DEPTH:
        acc.protect("shell nesting too deep")
        return
    if depth:  # nested text (heredoc bodies, -c scripts, stdin) is analysed once per cwd
        if (cmd, cwd) in acc.scanned:
            return
        acc.scanned.add((cmd, cwd))
    # Arithmetic-candidate regions are ambiguous (bash's own rule depends on quoting and nesting), so never
    # pick one reading: analyse with every region arithmetic, then with every region plain text, and when
    # there are few regions also every mix of the two; the accumulator takes the union. Every pass counts
    # against the work budget. How many passes are needed is known from the region count alone, so a command
    # whose passes cannot fit the budget fails closed before any of them runs.
    # A reading only changes where heredocs are found, so without any `<<` all readings give the same text,
    # and readings whose extraction comes out identical share one pass.
    regions: list[int] = []
    first = _extract_heredocs(cmd, (), regions, acc.spend)
    regions = [r for r in regions if not _inert_region(cmd, r, acc.spend)] if "<<" in cmd else []
    k = len(regions)
    if k > _MAX_MIXED_REGIONS and any("<<" in cmd[r:_arith_region_end(cmd, r, acc.spend) or len(cmd)]
                                      for r in regions):
        raise _TooComplex  # too many readings to enumerate and a mixed one could open a heredoc: fail closed
    readings: list = [()]
    if k:
        readings.append(_ALL_TEXT)
    if 2 <= k <= _MAX_MIXED_REGIONS:
        readings += [frozenset(r for b, r in enumerate(regions) if mask >> b & 1) for mask in range(1, (1 << k) - 1)]
    raw = not depth or cmd not in acc.root  # nested text that is part of the command was covered at depth 0
    # A structured pass charges about 1.5-2x the command length (its text, then its words and pipelines);
    # the raw backstop about 1x. Decide up front instead of failing after most of the work is done.
    if (_PASS_COST * len(readings) + raw) * len(cmd) > acc.budget:
        raise _TooComplex
    if raw:
        _raw(cmd, cwd, acc)
    done: set[tuple] = set()
    for reading in readings:
        ext = first if reading == () else _extract_heredocs(cmd, reading, None, acc.spend)
        key = (ext[0], tuple(ext[1]), tuple(sorted(ext[2].items())))
        if key not in done:
            done.add(key)
            _bash_pass(cmd, cwd, acc, depth, ext)


_MAX_MIXED_REGIONS = 3  # up to 2**3 readings; beyond that: Protected if any region has `<<`, else two passes
_PASS_COST = 2  # estimated budget charge of one structured pass, per byte of command
_INERT_SKIP = re.compile(r"\$\(\(|\(\(|\$\[|let")  # the region's own opener
_NOT_INERT = re.compile(r"""['"`\\#<\n$()\[\]]|let""")


def _inert_region(cmd: str, start: int, spend) -> bool:
    """True when reading the region as text or as arithmetic cannot differ: its interior has no quote,
    escape, comment, `<`, newline, `$`, bracket or `let`, so the extractor's state and output are the same
    either way. Such regions need no separate readings."""
    end = _arith_region_end(cmd, start, spend)
    if end is None:
        return False
    m = _INERT_SKIP.match(cmd, start)
    inner = cmd[m.end() if m else start:end].rstrip(")]")
    return _NOT_INERT.search(inner) is None


def _bash_pass(cmd: str, cwd: str, acc: _Acc, depth: int, extracted: tuple[str, list[str], dict[int, int]]) -> None:
    """One structured pass over `cmd`, given its heredoc extraction under one reading of the regions."""
    acc.spend(len(cmd))
    start_cwd = cwd
    full = cmd
    cmd, bodies, open_from = extracted
    written: dict[str, str] = {}  # file path -> heredoc body written to it earlier in this command
    pipeline = ""  # text of the segments piped into the current one

    def heredoc_index(tok: str) -> int | None:
        m = _HEREDOC_TOKEN_RE.fullmatch(tok)
        return int(m.group(1)) if m and int(m.group(1)) < len(bodies) else None

    def body_of(tok: str) -> str:
        idx = heredoc_index(tok)
        if idx is None:
            return written.get(_abspath(tok, cwd), tok)
        if idx in open_from:  # unterminated: bash feeds it everything up to end of input
            acc.spend(len(full) - open_from[idx])
            return full[open_from[idx]:]
        return bodies[idx]

    for seg in _segments(_tokens(cmd)):
        redirs, raw_words = seg.redirs, seg.words
        stdin_parts = [body_of(t) for t in dict.fromkeys(seg.inputs)]  # body_of charges unterminated text
        acc.spend(sum(map(len, stdin_parts)))
        stdin_text = "\n".join(stdin_parts)
        upstream = pipeline if seg.piped else ""
        acc.spend(len(upstream) + sum(map(len, raw_words)))  # stdin_text was charged above
        pipeline = (upstream + "\n" if seg.piped else "") + " ".join(raw_words) + "\n" + stdin_text
        for r in redirs:
            p = _abspath(r, cwd)
            if install_dir(p):
                acc.protect("shell write into install dir")
            _check_dest(p, acc)
            if seg.inputs:
                written[p] = stdin_text
        words = _strip_prefix(raw_words)
        if not words:
            continue
        if _bawwab_decision(words):
            acc.protect("bawwab approval via tool call")
        exe = os.path.basename(words[0])
        args = words[1:]
        ci = _claude_index(words)
        if ci is not None:
            _claude(words[ci:], cwd, acc)
            continue
        # claude behind an unknown wrapper: scan its arguments too (the rest of the segment is still checked).
        fb = next((i + 1 for i in range(1, len(words)) if os.path.basename(words[i]) == "claude"
                   and any(w in ("mcp", "plugin", "plugins") for w in words[i + 1:])), None)
        if fb is not None:
            _claude(words[fb:], cwd, acc)
        if (exe in ("mcp", "plugin", "plugins") or words[0].startswith("$") or "`" in words[0]) and \
                _CLAUDE_SUBCMD.search(" ".join(words)):
            acc.protect("unrecognised claude invocation")
            continue
        if exe == "cd":
            dest = next((a for a in args if not a.startswith("-")), None)
            cwd = str(Path.home()) if dest is None else (cwd if dest == "-" else _abspath(dest, cwd))
            continue
        if _is_interpreter(exe, args):
            script_i = _script_index(exe, args)
            script_path = _abspath(args[script_i], cwd) if script_i is not None else None
            script_parts = [written[p] for p in dict.fromkeys(_abspath(a, cwd) for a in args) if p in written]
            acc.spend(sum(map(len, script_parts)))
            script_files = "\n".join(script_parts)
            # running a skill's/plugin's own bundled script is execution, not a write of that path
            own = [a for j, a in enumerate(args) if not (j == script_i and script_path and install_dir(script_path))]
            parts = [" ".join(own), stdin_text, upstream, script_files]
            acc.spend(sum(map(len, parts)))
            text = "\n".join(parts)
            if _sensitive_text(text, cwd):
                acc.protect(f"interpreter may write Claude/bawwab config: {exe}")
            if exe in _SHELLS:
                stdin_scan = "\n".join(body_of(t) for t in dict.fromkeys(seg.inputs)
                                       if (k := heredoc_index(t)) is None or k not in open_from)
                for text in (stdin_scan, script_files):
                    if text.strip():
                        _bash(text, cwd, acc, depth + 1)
            if script_path and install_dir(script_path):
                args = own
        if exe in _SHELLS:
            for j, a in enumerate(args):
                if a.startswith("-") and not a.startswith("--") and "c" in a[1:]:
                    script = next((x for x in args[j + 1:] if not x.startswith("-")), None)
                    if script is not None:
                        _bash(script, cwd, acc, depth + 1)
                    break
        elif exe == "eval":
            _bash(" ".join(args), cwd, acc, depth + 1)
        elif exe == "git":
            _git(args, cwd, acc)
        elif exe in ("cp", "mv", "ln", "rsync", "install"):
            _copy(exe, args, cwd, acc)
            continue
        elif exe in ("curl", "wget"):
            _download(exe, args, cwd, acc)
        elif exe in ("tar", "bsdtar", "unzip"):
            _extract(exe, args, cwd, acc)
        elif exe == "dd":
            for a in args:
                if a.startswith("of="):
                    p = _abspath(a[3:], cwd)
                    if install_dir(p):
                        acc.protect("shell write into install dir")
                    _check_dest(p, acc)
            continue
        if exe in _READ_ONLY or (exe in ("sed", "gsed", "awk", "gawk") and not _is_interpreter(exe, args)):
            continue
        for a in args:
            p = _abspath(a.split("=", 1)[-1] if a.startswith("-") or re.match(r"^\w+=", a) else a, cwd)
            if exe in _SHELL_WRITERS and install_dir(p):
                acc.protect("shell write into install dir")
            _check_dest(p, acc)
    # fail-safe: every terminated heredoc body is also scanned as commands, from the command's start cwd
    for body in dict.fromkeys(bodies):
        if body.strip():  # _bash skips it if this (body, cwd) pair was already scanned
            _bash(body, start_cwd, acc, depth + 1)


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


def _mcpjson_enabled(d: dict, top_dir: str) -> dict[tuple[str, str], None]:
    """(project dir, server name) pairs from enabledMcpjsonServers (top level and projects.*)."""
    out: dict[tuple[str, str], None] = {}
    lists = [(top_dir, d.get("enabledMcpjsonServers"))]
    projects = d.get("projects")
    if isinstance(projects, dict):
        lists += [(str(k), v.get("enabledMcpjsonServers")) for k, v in projects.items() if isinstance(v, dict)]
    for proj, names in lists:
        if isinstance(names, list):
            out.update({(proj, str(n)): None for n in names})
    return out


def _config_change(inp: HookInput, path: str, kind: str, acc: _Acc) -> None:
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
    if kind in ("settings", "claude_json"):
        for k in _EXEC_SETTINGS:
            if new.get(k) != old.get(k):
                acc.protect(f"settings key executes code: {k}")
    old_servers = _servers(old)
    for key, spec in _servers(new).items():
        if spec == old_servers.get(key):
            continue
        if not isinstance(spec, dict):
            acc.protect(f"unrecognized MCP command: {key[1]}")
            continue
        _spec_target(key[1], spec, inp.cwd, acc)
    newp, oldp = new.get("enabledPlugins"), old.get("enabledPlugins")
    newp = newp if isinstance(newp, dict) else {}
    oldp = oldp if isinstance(oldp, dict) else {}
    for plugin, on in newp.items():
        if on is True and oldp.get(plugin) is not True:
            _plugin(str(plugin), acc)
    for plugin, on in oldp.items():
        if on is True and _is_bawwab_plugin(plugin) and newp.get(plugin) is not True:
            acc.protect("disables bawwab")
    if kind == "settings" and os.path.dirname(path) != os.path.normpath(str(claude_home())):
        top_dir = os.path.dirname(os.path.dirname(path))
    else:
        top_dir = inp.cwd
    old_en = _mcpjson_enabled(old, top_dir)
    for proj, server in _mcpjson_enabled(new, top_dir):
        if (proj, server) in old_en:
            continue
        data = _read_json(Path(proj) / ".mcp.json")
        spec = _servers(data).get(("", server)) if isinstance(data, dict) else None
        if isinstance(spec, dict):
            _spec_target(server, spec, proj, acc)
        else:
            acc.protect(f"unresolvable project MCP server: {server}")


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
        kind = _config_kind(c)
        if kind:
            _config_change(inp, c, kind, acc)
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
            acc.budget = 4 * len(cmd) + 1_000_000
            acc.root = cmd
            try:
                _bash(cmd, inp.cwd, acc)
            except _TooComplex:
                return Protected("command too complex to analyse")
    elif inp.tool_name in ("Write", "Edit", "MultiEdit"):
        _file_tool(inp, acc)
    return acc.result()
