"""Pure install detection for PreToolUse tool calls.

No network and no scanning. File reads are limited to the config file being
edited (to compute its new content), a project's .mcp.json (for
enabledMcpjsonServers), the marketplace JSONs and known_marketplaces.json,
and (R56) the files a command runs or copies and a written file's current
text, at most 1 MB each, never executed; directory listings only for shell
globs in cp/mv/rsync arguments.
"""
from __future__ import annotations

import dataclasses
import fnmatch
import functools
import glob as _glob
import itertools
import json
import os
import posixpath
import re
import shlex
import shutil
from dataclasses import dataclass, field
from pathlib import Path

from bawwab.envkeys import loader_key, server_entry_hash
from bawwab.gate.prefilter import bash_install_like, bawwab_exe_file, context as _prefilter_context
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
    # R57: user-only reasons: a plain deny, never a pending approval (see Protected.plain).
    plain: list[str] = field(default_factory=list)
    # (protected reason, server entry hash): approving that reason also accepts the entry in the effect check
    env_entries: list[tuple[str, str]] = field(default_factory=list)


@dataclass
class Protected:
    reason: str  # every reason, "; "-joined
    # R57: the reasons that are a plain deny ("the user must run it themselves"), with no pending approval: a
    # protected bawwab call inside a file the gate reads or a git alias, or written into a file.
    plain: list[str] = field(default_factory=list)
    approvable: str | None = None  # the reasons that get a pending approval; None: all of `reason`
    env_entries: list[tuple[str, str]] = field(default_factory=list)  # as Targets.env_entries


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
_EXEC_SETTINGS = ("statusLine", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "env")
_PROTECTED_KEYS = ("hooks", "disableAllHooks", "extraKnownMarketplaces", "enableAllProjectMcpServers")
_CLAUDE_SUBCMD = re.compile(
    r"\b(?:mcp\s+(?:add|add-json|add-from-claude-desktop)"
    r"|plugins?\s+(?:install|i|enable|disable|uninstall|remove|rm|update|marketplace))\b"
)


class _Unevaluable(Exception):
    pass


class _TooComplex(Exception):
    """The command needs more analysis work than the per-call budget allows."""


_MAX_DEPTH = 3
_MAX_TARGETS = 64


class _Acc:
    def __init__(self, budget: int = 1 << 62) -> None:
        self.targets: list[Target] = []
        self.protected: list[str] = []
        self.pinnable = False
        self.overlays: dict[Target, dict[str, str]] = {}
        self.budget = budget  # bytes of shell text we may still analyse in this detect_install call
        self.scanned: set[tuple[str, str]] = set()  # (text, cwd) already run through _bash
        self.root = ""  # the top-level command text (the raw backstop skips nested text that is part of it)
        self.prose = 0  # >0 while scanning heredoc bodies only as a fail-safe (text that may be prose, R55)
        self.plain: list[str] = []  # R57: user-only reasons (a plain deny)
        self.write_texts: list[tuple[str, str]] = []  # ("body"|"word", text) a segment only writes to a file
        self.script_depth = 0  # files being analysed around this text (R56)
        self.script_files = 0  # files read in this call
        self.script_bytes = 0  # bytes of file text read in this call
        self.file_scanned: set[tuple[str, str]] = set()  # `scanned` of file analyses (their reasons are filtered)
        self.env_entries: list[tuple[str, str]] = []  # (protected reason, server entry hash) for server env loaders

    def spend(self, n: int) -> None:
        self.budget -= n
        if self.budget < 0:
            raise _TooComplex

    def add(self, t: Target, pinnable: bool = False) -> None:
        if t not in self.targets:
            if len(self.targets) >= _MAX_TARGETS:
                raise _TooComplex  # no real command installs this many things; scanning them all would not end
            self.targets.append(t)
        self.pinnable = self.pinnable or pinnable

    def protect(self, reason: str) -> None:
        if reason not in self.protected:
            self.protected.append(reason)

    def user_only(self, reason: str) -> None:
        """R57: a plain deny, not a protected action the user could approve."""
        if reason not in self.plain:
            self.plain.append(reason)

    def _entries(self) -> list[tuple[str, str]]:
        return [(r, h) for r, h in self.env_entries if r in self.protected]

    def result(self) -> Targets | Protected | None:
        if self.targets:
            return Targets(self.targets, self.pinnable, self.overlays, self.protected, self.plain,
                           self._entries())
        if self.protected or self.plain:
            return Protected("; ".join(self.protected + self.plain), list(self.plain),
                             "; ".join(self.protected) if self.plain else None, self._entries())
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


def _target_from_url(url: str, transport: object = None) -> Target:
    """bawwab.fetch (httpx) loads on first use, so the hook can run detection before setup installed the deps
    (M19); bawwab.fetch.target itself is stdlib-only."""
    from bawwab.fetch.target import target_from_url

    return target_from_url(url, transport)


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


_MARKER = ".bawwab-initialised"  # bawwab's install marker (~/.claude, $CLAUDE_PLUGIN_DATA): state like bawwab home
# Interpreter code that drives bawwab's own state from inside (approve, init --skip, quarantine...).
_BAWWAB_CODE = re.compile(
    r"\bimport\s+bawwab\b|\bfrom\s+bawwab\b|\bbawwab\.[a-z_]+|\binit_skip\b|bawwab\.db\b"
    r"|quarantine\.flag|\.bawwab-initialised|/bin/bawwab\b"
)


_GLOB_CHARS = re.compile(r"[*?\[]")
_STATE_FILES = ("fp", "quarantine.flag", "bawwab.db", "effects.error", "effects.lock")


def _xdg_state() -> str:
    return os.path.normpath(os.environ.get("XDG_STATE_HOME") or os.path.join(str(Path.home()), ".local", "state"))


def _xdg_bawwab() -> str:
    """bawwab's XDG state dir: holds the third copy of the install marker."""
    return os.path.join(_xdg_state(), "bawwab")


def _state_targets() -> list[str]:
    """bawwab's own state: its home and key files, and the install markers (paths a glob must not reach)."""
    home = os.path.normpath(str(bawwab_home()))
    out = [home, *(os.path.join(home, f) for f in _STATE_FILES), os.path.join(str(claude_home()), _MARKER),
           _xdg_bawwab(), os.path.join(_xdg_bawwab(), _MARKER)]
    pd = os.environ.get("CLAUDE_PLUGIN_DATA")
    if pd:
        out.append(os.path.join(os.path.normpath(pd), _MARKER))
    return out + _bawwab_data_dirs()


def _comp_match(pat: str, name: str, icase: bool = False) -> bool:
    if name.startswith(".") and not pat.startswith("."):
        return False  # a shell glob doesn't match a leading dot
    return fnmatch.fnmatchcase(name.lower(), pat.lower()) if icase else fnmatch.fnmatchcase(name, pat)


def _glob_hits_state(p: str) -> bool:
    """A glob path that matches bawwab state, or a directory that contains it (rm -rf ~/.baw*)."""
    pparts = p.rstrip("/").split("/")
    for t in _state_targets():
        tparts = t.split("/")
        for n in range(2, len(tparts) + 1):  # the target and each ancestor (deleting it deletes the target)
            if n == len(pparts) and all(_comp_match(a, b) for a, b in zip(pparts, tparts[:n])):
                return True
    return False


_BRACE = re.compile(r"\{([^{}]*)\}")
_MAX_BRACES = 64


def _brace_expand(s: str) -> list[str]:
    """Bash brace expansion ({a,b}, {1..3}, {a..c}), bounded to _MAX_BRACES results."""
    out, todo = [], [s]
    while todo and len(out) < _MAX_BRACES:
        cur = todo.pop(0)
        m = next((m for m in _BRACE.finditer(cur) if "," in m.group(1) or ".." in m.group(1)), None)
        if m is None:
            out.append(cur)
            continue
        body = m.group(1)
        r = re.fullmatch(r"(-?\d+|[A-Za-z])\.\.(-?\d+|[A-Za-z])", body)
        if r and "," not in body:
            a, b = r.groups()
            if a.lstrip("-").isdigit() and b.lstrip("-").isdigit():
                lo, hi = int(a), int(b)
                alts = [str(i) for i in (range(lo, hi + 1) if lo <= hi else range(lo, hi - 1, -1))][:_MAX_BRACES]
            elif a.isalpha() and b.isalpha():
                lo, hi = ord(a), ord(b)
                alts = [chr(i) for i in (range(lo, hi + 1) if lo <= hi else range(lo, hi - 1, -1))][:_MAX_BRACES]
            else:
                alts = [body]
        else:
            alts = body.split(",")
        todo += [cur[:m.start()] + alt + cur[m.end():] for alt in alts]
    return out


def _bawwab_path(p: str) -> bool:
    if "{" in p and "}" in p:
        alts = _brace_expand(p)
        if len(alts) > 1 or alts != [p]:
            return any(_bawwab_path1(os.path.normpath(a)) for a in alts)
    return _bawwab_path1(p)


_PLUGIN_DATA_RE = re.compile(r"(?:^|/)plugins/data/bawwab[^/]*(?:/|$)")


def _env_data_dirs() -> tuple[str, ...]:
    return tuple(os.path.normpath(v) for v in (os.environ.get("CLAUDE_PLUGIN_DATA"), os.environ.get("BAWWAB_VENV"))
                 if v and os.path.isabs(v))


def _bawwab_data_dirs() -> list[str]:
    """R55: bawwab's plugin data dir (bootstrap markers, its venv) and a venv set by BAWWAB_VENV."""
    return list(_data_dirs(os.environ.get("CLAUDE_PLUGIN_DATA"), os.environ.get("BAWWAB_VENV"), str(claude_home())))


@functools.lru_cache(maxsize=16)
def _data_dirs(plugin_data: str | None, venv: str | None, chome: str) -> tuple[str, ...]:  # args: the cache key
    out = [os.path.normpath(v) for v in (plugin_data, venv) if v and os.path.isabs(v)]
    base = os.path.join(chome, "plugins", "data")
    try:
        out += [os.path.join(base, n) for n in os.listdir(base) if n.startswith("bawwab")]
    except OSError:
        pass
    return tuple(out)


def _bawwab_path1(p: str) -> bool:
    if _under(p, _bawwab_root()) or os.path.basename(p) == _MARKER or _under(p, _xdg_bawwab()):
        return True
    if "/data/bawwab" in p and _PLUGIN_DATA_RE.search(p):  # <claude home>/plugins/data/bawwab*: data dir, venv
        return True
    env_dirs = _RESOLVED.get(("env-dirs",))
    if env_dirs is None:
        env_dirs = _cached(("env-dirs",), _env_data_dirs)
    if env_dirs and any(_under(p, d) for d in env_dirs):
        return True
    if _GLOB_CHARS.search(p) and _glob_hits_state(os.path.normpath(p)):
        return True
    return os.path.basename(p) == "bawwab.json" and os.path.basename(os.path.dirname(p)) == ".claude"


def _bawwab_mentions() -> tuple[str, ...]:
    home = os.path.normpath(str(bawwab_home()))
    out = [home, ".claude/bawwab.json", _MARKER]
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

def _env_checks(env: dict[str, str], name: str, acc: _Acc, entry: str | None = None) -> None:
    """entry: the server's entry hash (envkeys.server_entry_hash). Approving the protected action then also covers
    exactly that config entry in the effect check (R1-I1)."""
    for k in env:
        kind = loader_key(k)  # bawwab/envkeys.py: the list the effect check uses too
        if kind is None:
            continue
        reason = f"server env loads code: {k} ({name})" if kind == "code" else f"custom package index: {k} ({name})"
        acc.protect(reason)
        if entry is not None and (reason, entry) not in acc.env_entries:
            acc.env_entries.append((reason, entry))


def _add_server(name: str, cmd: str, args: list[str], env: dict[str, str], cwd: str, acc: _Acc) -> None:
    _env_checks(env, name, acc, server_entry_hash(cmd, args, env, cwd or os.getcwd()))
    from bawwab.fetch.target import target_from_command

    t = target_from_command(cmd, args)
    if t is None:
        acc.protect(f"unrecognized MCP command: {name}")
        return
    if t.kind == "local":
        script = next((a for a in args if not a.startswith("-")), None)
        if script and not os.path.isabs(script):
            t = dataclasses.replace(t, path=_abspath(posixpath.dirname(script) or ".", cwd))
    acc.add(t, pinnable=True)
    from bawwab.fetch.target import runner_extras

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
        acc.add(_target_from_url(url, spec.get("type")), pinnable=True)
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


class _Lit(str):
    """A token made of operator characters that were quoted or backslash-escaped: a word, not an operator
    (`find ~ \\( -name x \\) -delete`, `tee '(' f`)."""


_PAREN_SUB = {"(": "\ue000", ")": "\ue001"}
_PAREN_BACK = {v: k for k, v in _PAREN_SUB.items()}
_PAREN_TR = str.maketrans(_PAREN_SUB)


_QUOTED_OR_ESCAPED = re.compile(r"\\." r"|'[^']*'" r'|"(?:[^"\\]|\\.)*"', re.S)


def _protect_parens(cmd: str) -> str:
    """Quoted or backslash-escaped ( and ) become placeholders the tokeniser keeps inside words."""
    if "(" not in cmd and ")" not in cmd:
        return cmd

    def sub(m: re.Match) -> str:
        t = m.group(0)
        if "(" not in t and ")" not in t:
            return t
        if t[0] == "\\":
            return _PAREN_SUB[t[1]] if t[1] in _PAREN_SUB else t
        return t.translate(_PAREN_TR)

    return _QUOTED_OR_ESCAPED.sub(sub, cmd)


def _restore_parens(tok: str) -> str:
    if "\ue000" not in tok and "\ue001" not in tok:
        return tok
    t = tok.translate(str.maketrans(_PAREN_BACK))
    return _Lit(t) if all(c in _PUNCT for c in t) else t


def _is_op(tok: str) -> bool:
    return bool(tok) and not isinstance(tok, _Lit) and all(c in _PUNCT for c in tok)


def _tokens(cmd: str) -> list[str]:
    cmd = _strip_fd_numbers(cmd.replace("\\\n", " ")).replace("`", " ; ")
    try:
        return [_restore_parens(t) for t in _shlex_tokens(_protect_parens(cmd))]
    except ValueError:  # unbalanced quotes: crude split, quotes dropped
        return re.findall(r"[();<>|&\n]+|[^\s();<>|&\n]+", re.sub(r"[\"'\\]", "", cmd))


def _words(cmd: str) -> list[str]:
    return [t for t in _tokens(cmd) if not _is_op(t)]


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
        if _is_op(tok):
            nxt = tokens[i + 1] if i + 1 < len(tokens) else ""
            if "(" in tok and ("<" in tok or ">" in tok):  # <(…) / >(…): a command of its own
                if cur.words or cur.redirs or cur.inputs:
                    segs.append(cur)
                cur = _Seg([], [], [], False)
                i += 1
                continue
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
        acc.add(_target_from_url(cmd, transport), pinnable=True)
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
    """p is, or contains, a Claude config/install path or bawwab state."""
    p = os.path.normpath(p)
    if _config_kind(p) or _bawwab_path(p) or install_dir(p) or os.path.basename(p) == ".claude":
        return True
    roots = (str(claude_home()), str(claude_json()), str(bawwab_home()), _xdg_bawwab())
    return any(_under(os.path.normpath(r), p) for r in roots)


def _contains_state(p: str) -> bool:
    """p is a directory above bawwab state (~/.local, ~/.claude, ~): removing it removes the state."""
    p = os.path.normpath(p)
    return any(_under(t, p) and t != p for t in _state_targets())


_FIND_PATTERNS = {"-name": ("name", False), "-iname": ("name", True), "-path": ("path", False),
                  "-ipath": ("path", True), "-wholename": ("path", False), "-iwholename": ("path", True),
                  "-regex": ("regex", False), "-iregex": ("regex", True)}
_FIND_EXEC = {"-exec", "-execdir", "-ok", "-okdir"}
_DESTRUCTIVE = {"rm", "mv", "unlink", "shred", "rmdir", "cp", "rsync", "truncate"}
_REMOVERS = {"rm", "rmdir", "unlink", "shred", "trash", "trash-put", "srm", "wipe"}
# Commands that can remove or rewrite what find lists, when they receive its output (pipe, `while read`,
# `$(find …)`, a for loop) or run from -exec. xargs/parallel/sudo/env only wrap: the command they run counts.
_CONSUMERS = _DESTRUCTIVE | _REMOVERS | _SHELLS | {"dd", "tee", "sponge", "perl", "ruby", "node", "eval"}
_FIND_ALL = {"!", "-not", "-o", "-or", ","}  # negation / alternation: the patterns no longer limit the match


def _consumer(w: str) -> bool:
    b = os.path.basename(w)
    return b in _CONSUMERS or re.fullmatch(r"python[0-9.]*", b) is not None


@functools.lru_cache(maxsize=8)
def _find_consumed(cmd: str) -> bool:
    """Something in the command can act destructively on find's output."""
    return any(_consumer(w) for w in _words(cmd))


def _find_hits(kind: str, icase: bool, pat: str, t: str) -> bool:
    if kind == "name":  # find's -name has no leading-dot rule: '*' matches .bawwab
        name = t.rsplit("/", 1)[-1]
        return fnmatch.fnmatchcase(name.lower(), pat.lower()) if icase else fnmatch.fnmatchcase(name, pat)
    if kind == "path":
        return fnmatch.fnmatchcase(t.lower(), pat.lower()) if icase else fnmatch.fnmatchcase(t, pat)
    if len(pat) > 300:
        return True  # can't judge: fail closed (only reached for a destructive find over bawwab state)
    try:
        return re.fullmatch(pat, t, re.IGNORECASE if icase else 0) is not None
    except (re.error, RecursionError):
        return True


def _find(args: list[str], cwd: str, acc: _Acc, destructive: bool = False) -> None:
    """A destructive find (-delete, -exec/-ok… of a removing command, or output that reaches one) whose start
    is bawwab state, or contains it and whose -name/-path/-regex patterns (none, or negated/OR-ed: all) reach
    the state or a directory above it."""
    destructive = destructive or "-delete" in args or any(
        a in _FIND_EXEC and j + 1 < len(args) and _consumer(args[j + 1]) for j, a in enumerate(args))
    if not destructive:
        return
    starts: list[tuple[str, str]] = []  # (absolute, as find prints it)
    i = 0
    while i < len(args):  # find's global options come before the start paths: -H -L -P -O<n> -D <opts>
        if args[i] in ("-H", "-L", "-P") or re.fullmatch(r"-O\d*", args[i]):
            i += 1
        elif args[i] == "-D":
            i += 2
        elif args[i] == "--":
            i += 1
            break
        else:
            break
    for a in args[i:]:
        if a.startswith(("-", "(", "!")):
            break
        ab = _abspath(a, cwd)
        starts.append((ab, ab if a.startswith(("~", "$")) else a.rstrip("/") or "/"))
    starts = starts or [(cwd, ".")]
    if any(_bawwab_path(ab) for ab, _ in starts):
        acc.protect("bawwab state change")
        return
    cands: list[str] = []  # the state, and each directory from a start down to it, as find may print them
    for t in _state_targets():
        for ab, shown in starts:
            if not _under(t, ab):
                continue
            rel = os.path.relpath(t, ab).split(os.sep)
            for n in range(0, len(rel) + 1):
                tail = "/".join(rel[:n]) if rel != ["."] else ""
                cands += [os.path.join(ab, tail).rstrip("/") or "/", (shown.rstrip("/") + "/" + tail) if tail else shown]
    if not cands:
        return
    if any(a in _FIND_ALL for a in args):
        acc.protect("bawwab state change")
        return
    pats = [(args[j + 1], *_FIND_PATTERNS[a]) for j, a in enumerate(args[:-1]) if a in _FIND_PATTERNS]
    if not pats or any(_find_hits(kind, icase, pat, t) for pat, kind, icase in pats for t in cands):
        acc.protect("bawwab state change")


def _xargs_upstream(up_words: list[str], cwd: str, acc: _Acc) -> None:
    """`ls ~/.baw* | xargs rm -rf`, `find … | xargs rm`: what the upstream lists is what gets removed."""
    if os.path.basename(up_words[0]) == "find":
        _find(up_words[1:], cwd, acc, destructive=True)
        return
    for w in up_words[1:]:
        if not w.startswith("-") and _bawwab_path(_abspath(w, cwd)):
            acc.protect("bawwab state change")
            return


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
    if any(_copies_bawwab(exe, src, dest, cwd) for src in srcs):
        acc.protect("copies or links a bawwab executable")
    if exe in ("cp", "mv", "install", "rsync") and _copies_protected(srcs, dest, cwd):
        acc.user_only("writes a protected bawwab command")
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


def _copies_protected(srcs: list[str], dest: str, cwd: str) -> bool:
    """R56 (b): a copied script (a shebang or an execute bit: copying a doc that shows `bawwab approve <id>`
    passes, R55) holds a protected bawwab invocation its destination didn't."""
    d = _abspath(dest, cwd)
    for src in srcs[:_MAX_RESOLVE]:
        for sp in (_expand(src, cwd) or [_abspath(src, cwd)])[:_MAX_RESOLVE]:
            if not _script_file(sp):
                continue
            text = _read_text(sp)
            if text is None:
                return True  # unreadable or too large: fail closed
            target = os.path.join(d, os.path.basename(sp)) if os.path.isdir(d) else d
            if _new_protected(text, _read_text(target) or "", cwd):
                return True
    return False


def _script_file(p: str) -> bool:
    try:
        if not os.path.isfile(p):
            return False
        if os.stat(p).st_mode & 0o111:
            return True
        with open(p, "rb") as fh:
            return fh.read(2) == b"#!"
    except (OSError, ValueError):
        return False


def _copies_bawwab(exe: str, src: str, dest: str, cwd: str) -> bool:
    """R55: the source of cp/mv/ln/install/rsync is a bawwab executable (the launcher, a console script such as
    <data>/venv/bin/bawwab, or a copy of one): a renamed copy or link would run approve under another name."""
    if os.path.basename(src.rstrip("/")) in _BAWWAB_EXES and not os.path.isdir(_abspath(src, cwd)):
        return True
    cands = _expand(src, cwd) or [_abspath(src, cwd)]
    if exe == "ln" and not src.startswith(("/", "~", "$")):  # a relative symlink target is read from the link's dir
        d = _abspath(dest, cwd)
        cands.append(os.path.normpath(os.path.join(d if os.path.isdir(d) else os.path.dirname(d), src)))
    return any(_exe_file(c, exec_only=True) for c in cands)  # a doc that mentions bin/bawwab is no exe


# R55: a script that runs bawwab (and passes it arguments or a protected subcommand) is a renamed bawwab.
_RUNS_BAWWAB = re.compile(
    r"(?:^|[\s;&|('\"`=])(?:[^\s;&|('\"`]*/)?bawwab(?:\.cli)?['\"]?(?=[\s;&|)'\",\]]|$)"
    r"|bawwab\.cli\b|(?:from|import)\s+bawwab\b|-m\s+bawwab\b|bawwab_hook", re.M)
_PASSES_ARGS = re.compile(r"\$[@*1-9]|\$\{[@*1-9]|\bargv\b|\b(?:approve|reject|--skip|effects|level)\b")


_SHEBANG = re.compile(r"\s*#!")
_IS_ENTRY = re.compile(r"bawwab\.cli\b|bawwab_hook\b|-m\s+bawwab\b")  # bawwab's own entry points: run its argv


def _execs_bawwab(text: str) -> bool:
    if not _SHEBANG.match(text):
        return False
    return bool(_IS_ENTRY.search(text)) or (bool(_RUNS_BAWWAB.search(text)) and bool(_PASSES_ARGS.search(text)))


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


_BAWWAB_EXES = ("bawwab", "bawwab.cli", "bawwab.cli:main")


def _bawwab_vars(cmd: str) -> set[str]:
    """Shell variables a command assigns a bawwab executable to (B=bawwab; $B init --skip)."""
    return {m.group(1) for m in re.finditer(r"(?<![\w$])([A-Za-z_]\w*)=['\"]?([^\s;&|'\"]*)", cmd)
            if os.path.basename(m.group(2)) in _BAWWAB_EXES}


# Where a known, non-bawwab program lives (R55): a command word that resolves here (and doesn't run bawwab)
# may take an `approve <id>` argv (git approve, make approve) without being denied.
_SYSTEM_DIRS = ("/usr/bin", "/bin", "/usr/sbin", "/sbin", "/usr/libexec", "/usr/lib", "/usr/local/bin",
                "/usr/local/sbin", "/usr/local/Cellar", "/opt/homebrew", "/nix/store", "/run/current-system",
                "/snap", "/Library/Developer/CommandLineTools", "/Applications/Xcode.app")
# shell builtins: the shell never runs a file for these (`source`/`.` do run one, so they are not here)
_BUILTINS = {"echo", "printf", "test", "[", "[[", "cd", "pushd", "popd", "export", "read", "set", "unset",
             "local", "declare", "typeset", "readonly", "alias", "unalias", "type", "hash", "help", "history",
             "jobs", "kill", "wait", "true", "false", ":", "shift", "return", "exit", "trap", "ulimit", "umask",
             "getopts", "let", "bg", "fg", "disown", "complete", "shopt"}


_RESOLVED: dict[tuple, object] = {}  # per detect_install call: PATH lookups and bawwab-executable checks
_TEXTS: list[str] = []  # per detect_install call: the shell texts analysed (alias/function definitions)


def _cached(key: tuple, fn):
    if key not in _RESOLVED:
        if len(_RESOLVED) > 4096:
            _RESOLVED.clear()
        _RESOLVED[key] = fn()
    return _RESOLVED[key]


def _resolve_word(w: str, cwd: str, bare: bool) -> str | None:
    """The file a command word names: a path (relative to cwd), or with `bare` a PATH lookup. Never runs it."""
    if not w or "$" in w or "`" in w or "\0" in w:
        return None
    if "/" in w or w.startswith("~"):
        return _abspath(w, cwd)
    return _cached(("which", w), lambda: shutil.which(w)) if bare else None


def _exe_file(p: str, exec_only: bool = False) -> bool:
    return bool(_cached(("exe", p, exec_only), lambda: bawwab_exe_file(p, exec_only)))


def _is_bawwab_word(words: list[str], i: int, cwd: str, interp: bool) -> bool:
    """words[i] runs bawwab: by name (bawwab, bawwab.cli), or (R55) by what it resolves to: the command word,
    an executable path later in the words (setsid /tmp/bw), or the script an interpreter runs (sh /tmp/bw).
    interp: words[0] is an interpreter (sh, python3, ...)."""
    w = words[i]
    if "bawwab" in w and os.path.basename(w) in _BAWWAB_EXES:
        return True
    if i == 0:
        p = _resolve_word(w, cwd, True)
        return bool(p) and _exe_file(p)
    if w.startswith("-"):
        return False
    if "/" in w or w.startswith("~"):
        return _exe_file(_abspath(w, cwd), exec_only=not interp)
    if interp and all(a.startswith("-") for a in words[1:i]):
        return _exe_file(_abspath(w, cwd))  # sh bw / python3 bw: the script is read from cwd
    return False


def _known_system(w: str, cwd: str, bare: bool) -> bool:
    """words[0] (bare) or a path word is a known non-bawwab program: a shell builtin, or a file under a system
    dir that doesn't run bawwab. Unresolvable is unknown (fail closed)."""
    if bare and w in _BUILTINS:
        return True
    p = _resolve_word(w, cwd, bare)
    if not p:
        return False
    try:
        real = os.path.realpath(p)
    except (OSError, ValueError):
        return False
    if not os.path.isfile(real) or _exe_file(real):
        return False
    return any(_under(real, d) for d in _SYSTEM_DIRS)


def _protected_tail(args: list[str]) -> bool:
    """args read as bawwab's: `approve <id>`, `reject <id>`, `init --skip`, `effects --retry`, `level <lower>`."""
    j = next((k for k, a in enumerate(args) if not a.startswith("-")), None)
    if j is None:
        return False
    sub, rest = args[j], args[j + 1:]
    if sub in ("approve", "reject"):
        return any(not a.startswith("-") for a in rest)
    if sub == "init":
        return any(a.startswith("--sk") for a in rest)
    if sub == "effects":
        return any(a.startswith("--re") for a in rest)
    if sub == "level":
        return _lowers_level(rest)
    return False


def _lowers_level(rest: list[str]) -> bool:
    """`level` with any value but `high` (show and raise are Claude's; lowering is the user's)."""
    return any(a != "high" for a in rest if not a.startswith("-") or a == "-")


def _bawwab_decision(words: list[str], bawwab_vars: set[str] = frozenset(), cwd: str = "",
                     tail: bool = True) -> bool:
    """A user-only bawwab command: approve, reject, init without --scan (init --skip trusts everything),
    effects --retry, level lowered below high; also a bawwab call whose subcommand can't be read ($var, $(...), `...` split off by
    the parser into a bare `bawwab`).
    R55: bawwab is recognised by name and also by what the word resolves to (a renamed symlink or copy of
    the launcher or a console script); and with `tail`, any command word that isn't a known system program
    is refused when its argv reads as a protected bawwab subcommand (fail closed)."""
    if not words:
        return False
    w0 = words[0]
    if w0.startswith("$") and re.sub(r"^\$\{?(\w+)\}?$", r"\1", w0) in bawwab_vars:
        words = ["bawwab", *words[1:]]
    if len(words) == 1 and (os.path.basename(words[0]) in _BAWWAB_EXES or _is_bawwab_word(words, 0, cwd, False)):
        return True  # its subcommand may have been split off ($(...), `...`): fail closed
    if not any(w in _SUBCOMMANDS or "$" in w or "`" in w for w in words[1:]):
        return False  # no protected subcommand (or unreadable word) for any bawwab here to run
    seen = None
    interp = bool(_INTERPRETER.fullmatch(os.path.basename(w0)))
    for i, w in enumerate(words):
        if seen is None:
            if i < _MAX_RESOLVE and _is_bawwab_word(words, i, cwd, interp):
                seen = i
            continue
        if w.startswith("-"):
            continue
        # the subcommand position
        if "$" in w or "`" in w:
            return True
        rest = words[i + 1:]
        if w in ("approve", "reject"):
            return True
        if w == "init":
            return "--scan" not in rest or any(a.startswith("--sk") for a in rest)
        if w == "effects":
            return any(a.startswith("--re") for a in rest)
        if w == "level":
            return _lowers_level(rest)
        return False
    if not tail:
        return False
    for j, w in enumerate(words[:_MAX_RESOLVE]):
        if (j == 0 or ("/" in w and not w.startswith("-"))) and _protected_tail(words[j + 1:]) \
                and not _known_system(w, cwd, j == 0) and not (j == 0 and _search_tool(w, cwd)):
            return True
    return False


def _search_tool(w: str, cwd: str) -> bool:
    """A search tool by name (rg is a shell function in Claude Code's shell, so it may not resolve): its
    `approve` is a pattern (M18). Not when it resolves to a bawwab executable or this call defines it."""
    if w not in _SEARCH_TOOLS:
        return False
    p = _resolve_word(w, cwd, True)
    if p and _exe_file(p):
        return False
    name = re.escape(w)
    redef = re.compile(rf"(?<![\w.-])(?:alias\s+(?:-\S+\s+)*{name}=|function\s+{name}\b|{name}\s*\(\s*\))")
    return not any(redef.search(t) for t in _TEXTS)


_MAX_RESOLVE = 8  # words examined for a bawwab executable before the subcommand
_SUBCOMMANDS = frozenset({"approve", "reject", "init", "effects", "level"})


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
    if _mentions_sensitive(text) or _BAWWAB_CODE.search(text):
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
_RAW_CUT_B = re.compile(r"\$\(|\$\{|[;&|(){}`]|(?<![^\s;&|(){}`])#")  # `#` inside a word is no comment
_RAW_CUT_A = re.compile(r"\$\(|\$\{|[;&|(){}`'\"]|(?<![^\s;&|(){}`'\"])#")
# Protected reasons any raw piece may add, wherever it was cut from: writes, moves and removals of Claude
# config/install paths or the bawwab home, disabling bawwab, new marketplaces, Claude Desktop imports, bawwab
# approvals. Unresolvable-command reasons only come from line and (b) units, read from the command word.
_RAW_NARROW = ("shell write into install dir", "shell write to Claude config", "bawwab state change",
               "moves Claude config", "disables bawwab", "new marketplace", "import of MCP servers from Claude",
               "bawwab approval via tool call")
_RAW_RESTART = {"claude", "mv", "rm", "cp", "rsync", "ln", "install", "dd", "tee", "sed", "gsed", "perl",
                "truncate", "patch", "touch", "unlink", "shred", "sponge", "chmod", "chown", "chattr", "mkdir",
                "rmdir", "curl", "wget", "git", "tar", "bsdtar", "unzip", "npx", "bunx", "node"}
# `$(cmd <<'EOF'` with a non-shell cmd: the body is literal text (Claude Code's commit-message idiom)
_RAW_QUIET_OPEN = re.compile(r"\$\(\s*([\w./-]+)\b[^\n]*?<<(-?)\s*(['\"])([^'\"\n]+)\3")
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
    quiet_until: tuple[bool, str] | None = None  # inside a literal heredoc body: (strip tabs, delimiter)
    for li, line in enumerate(lines):
        quiet = quiet_until is not None
        if quiet_until is not None and (line.lstrip("\t") if quiet_until[0] else line) == quiet_until[1]:
            quiet_until = None
        elif quiet_until is None and (m := _RAW_QUIET_OPEN.search(line)) and \
                os.path.basename(m.group(1)) not in _SHELLS and not _is_interpreter(os.path.basename(m.group(1)), []):
            quiet_until = (m.group(2) == "-", m.group(4))
        if not line.strip():
            continue
        units = [(_RAW_DOLLAR_QUOTE.sub("", _raw_line_unit(lines, li, acc)), not quiet)]  # cl$'a'ude is claude
        seps, marks = _quoted_cuts(line)
        for s in seps:  # each unit ends at the next cut, so the units of a line add up to O(len(line))
            unit = _raw_clean(line[s:_raw_cut(_RAW_CUT_B, line, s)])
            units.append((unit.replace("'", "").replace('"', ""), not quiet))
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
    """protect=False: only targets and the narrow Protected reasons are kept."""
    sink = acc if protect else _Acc()
    for seg in _segments(_tokens(unit)):
        words = _raw_words(seg.words)
        if words and words[0] == "cd":
            cwds.cd(words[1:])
            relevant = [c for c in cwds.all() if is_relevant(c)]
            continue
        for c in relevant:
            _raw_seg(seg.redirs, words, c, sink, _via_xargs(seg.words, words))
            # the command word may sit anywhere in a piece cut at the wrong place: restart at each candidate
            for i in range(1, len(words)):
                if os.path.basename(words[i]) in _RAW_RESTART:
                    scratch = _Acc()
                    _raw_seg([], _raw_words(words[i:]), c, scratch, False)
                    _raw_merge(scratch, acc, narrow=True)
    if sink is not acc:
        _raw_merge(sink, acc, narrow=True)


def _raw_merge(src: _Acc, acc: _Acc, narrow: bool) -> None:
    for t in src.targets:
        acc.add(t, src.pinnable)
        if t in src.overlays:
            acc.overlays.setdefault(t, src.overlays[t])
    for reason in src.protected:
        if not narrow or reason.startswith(_RAW_NARROW):
            acc.protect(reason)
    for pair in src.env_entries:
        if pair[0] in acc.protected and pair not in acc.env_entries:
            acc.env_entries.append(pair)


_XARGS_CLAUDE = "claude via xargs with piped arguments"


def _via_xargs(raw_words: list[str], words: list[str]) -> bool:
    """`words` (prefix-stripped `raw_words`) run under xargs, which appends arguments the command line
    does not show."""
    n = len(raw_words) - len(words)
    return n > 0 and any(os.path.basename(w) == "xargs" for w in raw_words[:n])


def _raw_words(words: list[str]) -> list[str]:
    while True:
        n = len(words)
        while words and words[0] in _RAW_KEYWORDS:
            words = words[1:]
        words = _strip_prefix(words)
        if len(words) == n:
            return words


def _raw_seg(redirs: list[str], words: list[str], cwd: str, acc: _Acc, xargs: bool) -> None:
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
    if exe in _BAWWAB_EXES and _bawwab_decision(words, cwd=cwd, tail=False):
        acc.protect("bawwab approval via tool call")
    ci = _claude_index(words)
    if ci is not None:
        if xargs:
            acc.protect(_XARGS_CLAUDE)
        _claude(words[ci:], cwd, acc)
        return
    # claude later in the words (unknown wrapper, prose) is handled by _raw_unit's restarts
    if (exe in ("mcp", "plugin", "plugins") or words[0].startswith("$")) and \
            _CLAUDE_SUBCMD.search(" ".join(words)):
        acc.protect("unrecognised claude invocation")
        return
    if exe == "git":
        _git(args, cwd, acc)
    elif exe == "find":
        _find(args, cwd, acc, destructive=_find_consumed(acc.root or ""))
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
            if exe in _REMOVERS and _contains_state(p):
                acc.protect("bawwab state change")


# ------------------------------------------------------------------ structured passes

# ------------------------------------------------------------------ protected actions inside files (R56)
#
# A file can hold the protected command instead of the argv: `sh a.sh HABZ` with a.sh = `bawwab approve "$1"`.
# (a) When a segment runs a file as code (a shell or `.`/`source` on a file, a path command word, make, or a
# python/node/... script), the file is read (never run) and checked: shell text goes through the same
# structured pass (with the call's positional arguments filled in), other code through the content rule
# below. The file is read as it is at check time (R57: a change earlier in the same command is a documented
# residual). Unreadable or too large: refused. Nested calls are followed to _SCRIPT_DEPTH files deep; deeper:
# refused.
# (b) A write (Write/Edit/MultiEdit, a redirect, tee, a heredoc, cp/mv/install of a script) is refused when its
# result holds a protected bawwab invocation that wasn't there before: a bawwab command word followed by
# approve/reject/init --skip/effects --retry. Prose without a bawwab command word passes.
# R57: every refusal here is a plain deny (_Acc.user_only): no pending approval, the user runs it themselves.

_SCRIPT_MAX = 1 << 20  # bytes of one file the gate reads; larger: refused
_SCRIPT_DEPTH = 3  # nested script files followed; deeper: refused
_SCRIPT_TOTAL = 8 << 20  # bytes of file text analysed per call; more: refused
_SCRIPT_FILES = 64  # files read per call; more: refused
_MAKE_NAMES = ("GNUmakefile", "makefile", "Makefile")
_MAKES = {"make", "gmake"}
_SEARCH_TOOLS = {"rg", "fd", "fdfind", "ag", "ack", "ack-grep", "grep", "egrep", "fgrep", "ugrep", "git-grep"}

# Where a command word starts in file text (R56 b): a line's start (after `$ `/`! `/`> ` prompts), after a shell
# separator, `$(` or a keyword, or at the start of a quoted command string or argv list ("bawwab …", ['bawwab', …]);
# then any prefix words (VAR=x, exec, env, uv run, $(shell …)). Not inside Markdown inline code or mid-sentence, so
# prose like "Run `bawwab approve <id>` in your terminal" passes (R55); a file that is *run* is read in full (a).
_CMD_START = (r"(?:^[ \t]*(?:[$!>][ \t]+)?|(?:&&|\|\||[;|&({]|\$\(|\b(?:then|do|else|exec|xargs|-exec))[ \t]*"
              r"|\[?[ \t]*[\"'])"
              r"(?:(?:[A-Za-z_]\w*=\S*|exec|command|builtin|nohup|env|sudo|doas|time|nice|setsid|xargs|shell"
              r"|timeout[ \t]+\S+|uvx|npx|(?:uv|pipx|poetry|pdm|hatch|rye)[ \t]+run(?:[ \t]+-\S+)*)[ \t]+)*")
_BW_WORD = re.compile(
    _CMD_START + r"(?:[^\s;&|('\"`,\[\]{}]*/)?bawwab(?:\.cli)?(?=['\"]?(?:[\s;&|)\]},]|$))"
    r"|(?<![\w-])-m\s+['\"]?bawwab(?:\.cli)?\b", re.M)
_PATH_TOKEN = re.compile(_CMD_START + r"([^\s;&|('\"`,\[\]{}$]*/[^\s;&|('\"`,\[\]{}]+)", re.M)
_ARG_TOKEN = re.compile(r"[;&|]+|[^\s'\",\[\](){};&|]+")
_IMPORTS_BAWWAB = re.compile(r"(?:from|import)\s+bawwab\b")
_QUOTED_SUB = re.compile(r"['\"](?:approve|reject)['\"]")
_QUOTED_PAIRS = ((re.compile(r"['\"]init['\"]"), re.compile(r"['\"]--sk(?:ip)?['\"]")),
                 (re.compile(r"['\"]effects['\"]"), re.compile(r"['\"]--re(?:try)?['\"]")))


def _protected_args(rest: str) -> bool:
    """`rest` (the text after a bawwab command word) starts a protected subcommand: approve, reject,
    init --skip, effects --retry."""
    toks: list[str] = []
    for t in _ARG_TOKEN.findall(rest):
        if t[0] in ";&|":
            break
        toks.append(t)
    sub = next((t for t in toks if not t.startswith("-")), None)
    return sub in ("approve", "reject") or _protected_tail(toks)


def _protected_lines(text: str, cwd: str) -> set[str]:
    """The lines of `text` that hold a protected bawwab invocation (R56 b): a bawwab command word (by name, a
    path to it, `-m bawwab`, or a path that resolves to a bawwab executable) followed by approve/reject/
    init --skip/effects --retry; or code that imports bawwab and names a protected subcommand. Comment lines
    (`#`) are skipped. Reads nothing but the resolved path words."""
    out: set[str] = set()
    text = text.replace("\\\n", " ")
    imports = _IMPORTS_BAWWAB.search(text) is not None
    pairs = [flag for word, flag in _QUOTED_PAIRS if imports and word.search(text)]
    paths = 0
    for line in text.splitlines():
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        if imports and (_QUOTED_SUB.search(s) or any(f.search(s) for f in pairs)):
            out.add(s)
            continue
        if "bawwab" in s and any(_protected_args(s[m.end():]) for m in _BW_WORD.finditer(s)):
            out.add(s)
            continue
        if "/" in s and re.search(r"\b(?:approve|reject|init|effects)\b", s):
            for m in _PATH_TOKEN.finditer(s):
                paths += 1
                if paths > 256:
                    out.add(s)  # too many to resolve: fail closed
                    break
                tok = m.group(1)
                if _protected_args(s[m.end():]) and _exe_file(_abspath(tok, cwd), exec_only=True):
                    out.add(s)
                    break
    return out


def _new_protected(new: str, old: str, cwd: str) -> bool:
    """`new` holds a protected bawwab invocation that `old` didn't (an edit elsewhere in a doc passes)."""
    if "bawwab" not in new and not re.search(r"\b(?:approve|reject|init|effects)\b", new):
        return False
    return bool(_protected_lines(new, cwd) - _protected_lines(old, cwd))


def _read_text(p: str) -> str | None:
    """A regular file's text (at most _SCRIPT_MAX bytes), "" when missing, None when unreadable/too large."""
    try:
        st = os.stat(p)
    except FileNotFoundError:
        return ""
    except (OSError, ValueError):
        return None
    if not os.path.isfile(p) or st.st_size > _SCRIPT_MAX:
        return None
    try:
        with open(p, "rb") as fh:
            data = fh.read(_SCRIPT_MAX + 1)
    except OSError:
        return None
    return None if len(data) > _SCRIPT_MAX else data.decode("utf-8", "replace")


def _shell_script_arg(args: list[str]) -> int | None:
    """Index of the script file a shell runs, or None (-c code, -s / no file: stdin)."""
    i = 0
    while i < len(args):
        a = args[i]
        if a == "--":
            return i + 1 if i + 1 < len(args) else None
        if a in ("-o", "+o", "-O", "+O", "--rcfile", "--init-file"):
            i += 2
            continue
        if a.startswith("--"):
            i += 1
            continue
        if a[:1] in ("-", "+") and len(a) > 1:
            if "c" in a[1:] or "s" in a[1:]:
                return None
            i += 1
            continue
        return i
    return None


def _script_call(words: list[str]) -> tuple[str, str, list[str]] | None:
    """(kind, file word, its argv) when a segment runs a file as code. kind: "sh" (read as shell), "make",
    "code" (another interpreter: content rule), "path" (a path command word: its shebang decides)."""
    w0 = words[0]
    exe, args = os.path.basename(w0), words[1:]
    if exe in _SHELLS:
        i = _shell_script_arg(args)
        return ("sh", args[i], args[i + 1:]) if i is not None else None
    if w0 in (".", "source"):
        return ("sh", args[0], args[1:]) if args else None
    if exe in _MAKES or w0 in ("$(MAKE)", "${MAKE}", "$MAKE"):
        return "make", "", args
    if _INTERPRETER.fullmatch(exe):
        i = _script_index(exe, args)
        return ("code", args[i], args[i + 1:]) if i is not None else None
    if "/" in w0:
        return "path", w0, args
    return None


_POS_QUOTED = re.compile(r'"\$(?:\{([@*]|\d+)\}|([@*]|\d))"')
_POS_BARE = re.compile(r"\$(?:\{([@*]|\d+)\}|([@*]|\d))")
_POS_SHIFTS = re.compile(r"(?<![\w-])(?:shift|getopts)(?![\w-])")
_POS_RESET = re.compile(r"(?<![\w-])set\s+(?:-\S*\s+)*--?(?:\s|$)")
_SAFE_ARG = re.compile(r"[\w.@%+=:,/-]+")
_NO_ARGS = "__bawwab_no_args__"  # what an empty "$@" reads as: an inert word, not a split-off subcommand
_MAX_SHIFTS = 8


def _positional(text: str, argv: list[str]) -> list[str]:
    """The script text with its positional parameters filled in from its call's argv, so `bawwab approve "$1"`
    run as `sh a.sh HABZ` reads as `bawwab approve HABZ`. A script that shifts gets one reading per shift
    offset; one that resets them (`set --`) keeps the references (an unreadable subcommand is refused)."""
    if "$" not in text or _POS_RESET.search(text):
        return [text]
    if _POS_SHIFTS.search(text):
        if len(argv) > _MAX_SHIFTS:
            return [text]
        return [_fill(text, argv[k:]) for k in range(len(argv) + 1)]
    return [_fill(text, argv)]


def _fill(text: str, argv: list[str]) -> str:
    def value(name: str, quote: bool) -> str | None:
        if name == "0":
            return None
        vals = argv if name in ("@", "*") else argv[int(name) - 1:int(name)]
        if quote:
            if name in ("@", "*"):
                return " ".join(shlex.quote(v) for v in vals) or _NO_ARGS
            return shlex.quote(vals[0]) if vals else "''"
        if all(_SAFE_ARG.fullmatch(v) for v in vals):
            return " ".join(vals) or (_NO_ARGS if name in ("@", "*") else "")
        return None

    text = _POS_QUOTED.sub(lambda m: value(m.group(1) or m.group(2), True) or m.group(0), text)
    return _POS_BARE.sub(lambda m: v if (v := value(m.group(1) or m.group(2), False)) is not None else m.group(0),
                         text)


_MAKE_ASSIGN = re.compile(r"(?:(?:override|export|private)\s+)*([A-Za-z_][\w.-]*)\s*(::?=|:::=|\?=|\+=|!=|=)\s*(.*)",
                          re.S)
_MAKE_INCLUDE = re.compile(r"(?:-|s)?include\s+(.*)", re.S)
_MAKE_REF = re.compile(r"\$[({]([A-Za-z_][\w.-]*)[)}]")


def _make_expand(s: str, mvars: dict[str, str]) -> str:
    for _ in range(8):
        n = _MAKE_REF.sub(lambda m: mvars.get(m.group(1), m.group(0)), s)
        if n == s:
            break
        s = n
    return s


def _make_parse(text: str, mvars: dict[str, str]) -> tuple[list[str], list[str], list[str]]:
    """(recipe lines as shell text, other non-comment lines, include words) of a makefile; `mvars` gains its
    simple variable definitions. `$$` reads as `$`, $(MAKE) as make."""
    recipes: list[str] = []
    other: list[str] = []
    includes: list[str] = []
    text = text.replace("\\\n", " ")
    for line in text.splitlines():
        if line.startswith("\t"):
            recipes.append(line[1:])
            continue
        s = line.strip()
        if not s or s.startswith("#"):
            continue
        m = _MAKE_INCLUDE.fullmatch(s)
        if m:
            includes += m.group(1).split()
            continue
        m = _MAKE_ASSIGN.fullmatch(s)
        if m and ":" not in s.split("=", 1)[0].rstrip(":"):
            name, op, val = m.groups()
            mvars[name] = (mvars.get(name, "") + " " + val) if op == "+=" else val
            if op == "!=":  # its value is shell code, run when the makefile is read
                recipes.append(val)
            other.append(s)
            continue
        if ":" in s and ";" in s:  # target: prerequisites ; recipe
            recipes.append(s.split(";", 1)[1])
        other.append(s)
    mvars.setdefault("MAKE", "make")

    def shell(r: str) -> str:
        r = _make_expand(r.replace("$$", "\0"), mvars).replace("\0", "$")
        return r.lstrip().lstrip("@+-").lstrip()
    return [shell(r) for r in recipes if not r.lstrip().startswith("#")], [_make_expand(o, mvars) for o in other], \
        [_make_expand(i, mvars) for i in includes]


def _make_files(args: list[str], cwd: str) -> tuple[str, list[str], dict[str, str]]:
    """(make's dir, the makefiles it reads, command-line variables) for `make args` run in cwd."""
    d, files, mvars = cwd, [], {}
    i = 0
    while i < len(args):
        a = args[i]
        nxt = args[i + 1] if i + 1 < len(args) else ""
        if a in ("-f", "--file", "--makefile", "-C", "--directory"):
            val, i = nxt, i + 2
            flag = a
        elif a.startswith(("--file=", "--makefile=", "--directory=")):
            flag, val = a.split("=", 1)
            i += 1
        elif a.startswith(("-f", "-C")) and len(a) > 2:
            flag, val = a[:2], a[2:]
            i += 1
        else:
            m = re.fullmatch(r"([A-Za-z_][\w.-]*)\s*:?=(.*)", a, re.S)
            if m:
                mvars[m.group(1)] = m.group(2)
            i += 1
            continue
        if flag in ("-C", "--directory"):
            d = _abspath(val, d)
        else:
            files.append(val)
    if files:
        return d, [_abspath(f, d) for f in files], mvars
    found = next((os.path.join(d, n) for n in _MAKE_NAMES if os.path.exists(os.path.join(d, n))), None)
    return d, [found or os.path.join(d, "Makefile")], mvars


def _read_failure(reason: str) -> bool:
    """The gate couldn't check a file (unreadable, too large, nested too deep): an approvable block."""
    return reason.startswith(("script could not be read", "scripts too large", "script nesting too deep",
                              "shell nesting too deep", "command too complex"))


def _keeps(reason: str) -> bool:
    """Reasons a file's own analysis passes up: those that protect bawwab, not the install gate's."""
    return reason.startswith(("script", "makefile", "shell nesting too deep")) or \
        ("bawwab" in reason and not reason.startswith("interpreter may write"))


class _Changes:
    """Text a command writes to a file before a later segment runs it (a heredoc or echo/printf redirect): read
    with the file. R57: a file changed some other way (git checkout, curl -o, an archive) is not refused; what
    the gate reads when it checks is what it checks (a documented residual)."""

    def __init__(self) -> None:
        self.text: dict[str, str] = {}


def _file_text(p: str, changes: _Changes, acc: _Acc) -> str | None:
    """A file a segment runs, for analysis: the text written to it earlier in this command and/or its
    content on disk. None when nothing is to be checked (missing, or a device such as /dev/null); a plain
    deny (acc.user_only) when unreadable or too large."""
    name = os.path.basename(p) or p
    if p in changes.text:
        disk = _read_text(p)
        if disk is None:
            acc.protect(f"script could not be read: {name}")
            return None
        return changes.text[p] + "\n" + disk
    if os.path.exists(p) and not os.path.isfile(p):
        return None  # a device or fifo (/dev/null, /dev/stdin): nothing on disk to read
    text = _read_text(p)
    if text is None:
        acc.protect(f"script could not be read: {name}")
        return None
    if text == "" and not os.path.exists(p):
        return None  # nothing there to run, and nothing earlier in the command created it
    acc.script_files += 1
    acc.script_bytes += len(text)
    if acc.script_files > _SCRIPT_FILES or acc.script_bytes > _SCRIPT_TOTAL:
        acc.protect("scripts too large to analyse")
        return None
    return text


def _not_a_script(p: str) -> bool:
    """A path command word that is no script to read: a dir, a compiled program, or a system program (under a
    system dir, not a bawwab executable: the R55 rule for argv tails)."""
    try:
        real = os.path.realpath(p)
        if not os.path.isfile(real):
            return os.path.exists(real)  # a dir or device; missing: _file_text decides
        if any(_under(real, d) for d in _SYSTEM_DIRS) and not _exe_file(real):
            return True
        with open(real, "rb") as fh:
            return b"\0" in fh.read(8192)
    except (OSError, ValueError):
        return False  # unreadable: _file_text refuses it


def _sub_bash(text: str, cwd: str, acc: _Acc, depth: int, where: str = "a file it runs") -> None:
    """Analyse a file's (or a git alias's) shell text with the structured pass; only bawwab's own protections
    pass up, as plain denies (R57)."""
    if acc.script_depth >= _SCRIPT_DEPTH:
        acc.protect("script nesting too deep")
        return
    sub = _Acc()
    sub.scanned = sub.file_scanned = acc.file_scanned  # never the main pass's: a skip there would drop targets
    # The structured pass only: the raw backstop reads every quoted word as a command (`VIRTUAL_ENV_PROMPT=
    # "bawwab"` in a venv's activate script), which suits the command Claude wrote, not every file it runs.
    sub.root = text
    sub.script_depth = acc.script_depth + 1
    sub.script_files, sub.script_bytes = acc.script_files, acc.script_bytes
    acc.budget += 4 * len(text) + 100_000  # a file's text is analysed like a command of its size
    sub.budget = acc.budget
    try:
        _whole_command_checks(text, sub)
        _bash(text, cwd, sub, depth + 1)
    finally:
        acc.budget = sub.budget
        acc.script_files, acc.script_bytes = sub.script_files, sub.script_bytes
        for r in sub.protected:
            if _read_failure(r):
                acc.protect(r)  # fail closed, but approvable: nothing protected was found (R57 round 2)
            elif _keeps(r):
                acc.user_only(f"in {where}: {r}")
        for r in sub.plain:
            acc.user_only(r if r.startswith("in ") else f"in {where}: {r}")


_GIT_CONFIG_VALUE_OPTS = {"-f", "--file", "--blob", "--type", "--comment", "--default", "--value"}


def _git_aliases(args: list[str], cwd: str, acc: _Acc, depth: int) -> None:
    """R57: a git shell alias (`git -c alias.X='!…'`, `git config [--global] alias.X '!…'`) is shell text git
    runs; one holding a protected bawwab call is a plain deny. Other config-borne commands (core.pager, hooks
    …) are a documented residual."""
    values: list[str] = []
    i = 0
    while i < len(args):
        a = args[i]
        if a == "-c" and i + 1 < len(args):
            values.append(args[i + 1])
            i += 2
            continue
        if a.startswith("-c") and len(a) > 2:
            values.append(a[2:])
        elif a in ("-C", "--git-dir", "--work-tree", "--namespace", "--exec-path") and i + 1 < len(args):
            i += 2
            continue
        elif not a.startswith("-"):
            if a == "config":
                rest, j, cargs = [], 0, args[i + 1:]
                while j < len(cargs):  # option values aren't the key (git config -f .git/config alias.y …)
                    x = cargs[j]
                    if x in _GIT_CONFIG_VALUE_OPTS:
                        j += 2
                        continue
                    if not x.startswith("-"):
                        rest.append(x)
                    j += 1
                if rest[:1] in (["set"], ["add"]):
                    rest = rest[1:]
                if len(rest) >= 2 and rest[0].lower().startswith("alias."):
                    values.append(rest[0] + "=" + " ".join(rest[1:]))
            break
        i += 1
    for v in values:
        key, _, val = v.partition("=")
        if key.lower().startswith("alias.") and val.lstrip().startswith("!"):
            _sub_bash(val.lstrip()[1:], cwd, acc, depth, "a git alias")


def _run_file(words: list[str], cwd: str, acc: _Acc, depth: int, changes: _Changes) -> None:
    """R56 (a): the protected-action check on a file this segment runs (see the section comment)."""
    call = _script_call(words)
    if call is None:
        return
    kind, word, argv = call
    if kind == "make":
        mdir, files, mvars = _make_files(argv, cwd)
        recipes: list[str] = []
        seen: set[str] = set()
        queue = list(files)
        while queue:
            f = queue.pop(0)
            if f in seen:
                continue
            seen.add(f)
            text = _file_text(f, changes, acc)
            if text is None:
                continue
            r, other, inc = _make_parse(text, mvars)
            recipes += r
            if _protected_lines("\n".join(other), mdir):
                acc.user_only("makefile runs a protected bawwab command")
            for w in inc:
                if "$" in w or _has_glob(w):
                    continue  # computed at make time (-include $(OBJS:.o=.d)): a documented residual (R57)
                if len(seen) + len(queue) < _SCRIPT_FILES:
                    queue.append(_abspath(w, mdir))  # read when it exists; missing is skipped, as make does
                else:
                    acc.protect("scripts too large to analyse")
        if recipes:
            _sub_bash("\n".join(recipes), mdir, acc, depth)
        return
    if "$" in word or "`" in word or "\0" in word:
        return  # a runtime-computed path: a documented residual
    p = _abspath(word, cwd)
    if kind == "path" and p not in changes.text and _not_a_script(p):
        return
    text = _file_text(p, changes, acc)
    if text is None:
        return
    if "\0" in text[:8192]:
        return  # a compiled program: a documented residual (bawwab's own executables are recognised by name)
    if kind == "path":
        first = text.split("\n", 1)[0]
        if first.startswith("#!"):
            sb = first[2:].split()
            prog = os.path.basename(sb[0]) if sb else ""
            if prog == "env":
                prog = os.path.basename(next((x for x in sb[1:] if not x.startswith("-") and "=" not in x), ""))
            kind = "sh" if prog in _SHELLS else "code"
        else:
            kind = "sh"  # no shebang: the shell runs it as a script (ENOEXEC)
    if kind == "code":
        if _protected_lines(text, cwd):
            acc.user_only(f"script runs a protected bawwab command: {os.path.basename(p)}")
        return
    for reading in _positional(_COMMENT_LINE.sub("", text), argv):
        _sub_bash(reading, cwd, acc, depth)


# A whole-line comment in a file the gate reads: blanked, so the raw backstop (which reads past `#`) doesn't
# take a usage note (`#   bawwab approve <id>`) for a command.
_COMMENT_LINE = re.compile(r"(?m)^[ \t]*#.*$")


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


def _literal_output(words: list[str]) -> str:
    """What `echo …` / `printf FMT …` print, roughly (escapes \\n \\t decoded; also kept raw), else ""."""
    if not words or os.path.basename(words[0]) not in ("echo", "printf"):
        return ""
    args = words[1:]
    while args and re.fullmatch(r"-[neE]+", args[0]) and os.path.basename(words[0]) == "echo":
        args = args[1:]
    if args[:1] == ["--"]:
        args = args[1:]
    text = " ".join(args)
    decoded = text.replace("\\n", "\n").replace("\\t", "\t")
    return text if decoded == text else decoded + "\n" + text


def _bash_pass(cmd: str, cwd: str, acc: _Acc, depth: int, extracted: tuple[str, list[str], dict[int, int]]) -> None:
    """One structured pass over `cmd`, given its heredoc extraction under one reading of the regions."""
    acc.spend(len(cmd))
    start_cwd = cwd
    full = cmd
    cmd, bodies, open_from = extracted
    written: dict[str, str] = {}  # file path -> heredoc body written to it earlier in this command
    changes = _Changes()  # text written to files earlier in this command (a later segment may run one)
    _TEXTS.append(full)
    pipeline = ""  # text of the segments piped into the current one
    prev_words: list[str] = []  # prefix-stripped words of the previous segment

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
        words = _strip_prefix(raw_words)
        heredoc_in = any(heredoc_index(t) is not None for t in seg.inputs)
        for r in redirs:
            p = _abspath(r, cwd)
            if install_dir(p):
                acc.protect("shell write into install dir")
            _check_dest(p, acc)
            if seg.inputs:
                written[p] = stdin_text
            if heredoc_in or (words and os.path.basename(words[0]) in ("echo", "printf") and not seg.inputs):
                known = stdin_text if heredoc_in else _literal_output(words)
                changes.text[p] = changes.text.get(p, "") + "\n" + known
        up_words, prev_words = (prev_words if seg.piped else []), words
        exe0 = os.path.basename(words[0]) if words else ""
        if (redirs or exe0 == "tee") and exe0 not in _SHELLS and exe0 != "eval" and \
                not _INTERPRETER.fullmatch(exe0):  # text this segment writes and doesn't run (R57 round 2)
            acc.write_texts += [("body", bodies[k]) for t in seg.inputs
                                if (k := heredoc_index(t)) is not None and k not in open_from]
            if redirs and exe0 in ("echo", "printf"):
                acc.write_texts += [("word", a) for a in words[1:]]
        if redirs or exe0 == "tee":  # R55: writing a script that runs bawwab, or a copy of a bawwab executable
            texts = (stdin_text, _literal_output(words), _literal_output(up_words) if exe0 == "tee" else "")
            if any(t and _execs_bawwab(t) for t in texts):
                acc.user_only("writes a script that runs bawwab")
            srcs = words[1:] if redirs else [a for a in up_words[1:]]
            if any(not a.startswith("-") and _exe_file(_abspath(a, cwd), exec_only=True)
                   for a in srcs[:_MAX_RESOLVE]):
                acc.protect("copies or links a bawwab executable")
            # R56 (b): the written text holds a protected bawwab invocation (any file, shebang or not)
            cat = words if redirs and exe0 == "cat" else (up_words if exe0 == "tee" and up_words and
                                                         os.path.basename(up_words[0]) == "cat" else [])
            texts += tuple(_read_text(_abspath(a, cwd)) or "" for a in cat[1:_MAX_RESOLVE]
                           if not a.startswith("-") and _script_file(_abspath(a, cwd)))
            if any(t and _new_protected(t, "", cwd) for t in texts):
                acc.user_only("writes a protected bawwab command")
        if not words:
            continue
        # R56 (a): a file this segment runs as code; a shell's stdin from a file (sh < f, cat f | sh)
        _run_file(words, cwd, acc, depth, changes)
        if exe0 == "git":
            _git_aliases(words[1:], cwd, acc, depth)
        if exe0 == "find":  # find -exec sh a.sh {} \;
            for j, a in enumerate(words):
                if a in _FIND_EXEC:
                    group = list(itertools.takewhile(lambda x: x not in (";", "\\;", "+"), words[j + 1:]))
                    if group:
                        _run_file(_strip_prefix(group), cwd, acc, depth, changes)
        if exe0 in _SHELLS and _shell_script_arg(words[1:]) is None and \
                not any(a[:1] == "-" and "c" in a[1:] for a in words[1:] if not a.startswith("--")):
            feeds = [t for t in seg.inputs if heredoc_index(t) is None]
            if seg.piped and up_words and os.path.basename(up_words[0]) == "cat":
                feeds += [a for a in up_words[1:] if not a.startswith("-")]
            for f in dict.fromkeys(feeds):
                _run_file([exe0, f], cwd, acc, depth, changes)
        if _bawwab_decision(words, _bawwab_vars(cmd) if words[0].startswith("$") else frozenset(), cwd,
                            tail=not acc.prose):
            acc.protect("bawwab approval via tool call")
        exe = os.path.basename(words[0])
        args = words[1:]
        if up_words and exe in _DESTRUCTIVE and _via_xargs(raw_words, words):
            _xargs_upstream(up_words, cwd, acc)
        ci = _claude_index(words)
        if ci is not None:
            if _via_xargs(raw_words, words):
                acc.protect(_XARGS_CLAUDE)
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
                literal = _literal_output(up_words) if script_i is None else ""
                acc.spend(len(literal))
                for text in (stdin_scan, script_files, literal):
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
        elif exe == "find":
            _find(args, cwd, acc, destructive=_find_consumed(cmd))
            continue  # its -name/-path values are patterns, not paths
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
                elif a.startswith("if=") and _exe_file(_abspath(a[3:], cwd), exec_only=True):
                    acc.protect("copies or links a bawwab executable")
            continue
        if exe in _READ_ONLY or (exe in ("sed", "gsed", "awk", "gawk") and not _is_interpreter(exe, args)):
            continue
        for a in args:
            p = _abspath(a.split("=", 1)[-1] if a.startswith("-") or re.match(r"^\w+=", a) else a, cwd)
            if exe in _SHELL_WRITERS and install_dir(p):
                acc.protect("shell write into install dir")
            _check_dest(p, acc)
            if exe in _REMOVERS and _contains_state(p):
                acc.protect("bawwab state change")
    # fail-safe: every terminated heredoc body is also scanned as commands, from the command's start cwd
    for body in dict.fromkeys(bodies):
        if body.strip():  # _bash skips it if this (body, cwd) pair was already scanned
            acc.prose += 1  # may be prose (a commit message): no argv-tail guess on unknown words, R55
            try:
                _bash(body, start_cwd, acc, depth + 1)
            finally:
                acc.prose -= 1


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
    try:
        new = _new_content(inp, p)
    except _Unevaluable:
        new = ""  # an edit that doesn't apply changes nothing
    if "bawwab" in new and _execs_bawwab(new):  # R55: a script that runs bawwab under another name
        acc.user_only("writes a script that runs bawwab")
    old = _read_text(p)
    if old is None:
        old = ""  # unreadable or too large: every protected line counts as new
    if _new_protected(new, old, inp.cwd or "/"):  # R56 (b): any file, shebang or not
        acc.user_only("writes a protected bawwab command")
    for c in cands:
        kind = _config_kind(c)
        if kind:
            _config_change(inp, c, kind, acc)
            return
    for c in cands:
        if install_dir(c):
            _install_write(inp, c, acc)
            return


_NESTED_CLAUDE = re.compile(
    r"\bclaude\b[^\n;|&]*?\s--(?:settings|setting-sources|dangerously-skip-permissions"
    r"|allow-dangerously-skip-permissions|plugin-dir)\b"
)
_BAWWAB_ENV = re.compile(
    r"\bBAWWAB_(?:CHILD|HOME)\s*\+?=|\b(?:export|declare|typeset|readonly|local|unset|read|readarray|mapfile"
    r"|printf)\b[^\n;|&]*\bBAWWAB_(?:CHILD|HOME)\b"
)
_NO_HOOKS_FLAGS = ("--settings", "--setting-sources", "--dangerously-skip-permissions",
                   "--allow-dangerously-skip-permissions", "--plugin-dir")
_CONFIG_REDIRECT = re.compile(r"(?:CLAUDE_CONFIG_DIR|HOME)\+?=")  # a nested claude reading another config
_ASSIGN = re.compile(r"([A-Za-z_][A-Za-z0-9_]*)\+?=(.*)", re.S)
_VAR_REF = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")


def _claude_words(words: list[str]) -> tuple[list[str], list[str]] | None:
    """(words before the claude executable, claude's arguments) when the segment runs Claude Code."""
    sw = _strip_prefix(words)
    ci = _claude_index(sw)
    if ci is not None:
        return words[: len(words) - len(sw)], sw[ci:]
    j = next((j for j, w in enumerate(words) if os.path.basename(w) == "claude"), None)
    return None if j is None else (words[:j], words[j + 1:])


def _shell_script(words: list[str]) -> tuple[list[str], str] | None:
    """(words before the shell, its -c script) when the segment runs `sh/bash/zsh/dash/ksh -c '<script>'`."""
    sw = _strip_prefix(words)
    if not sw or os.path.basename(sw[0]) not in _SHELLS:
        return None
    args = sw[1:]
    for j, a in enumerate(args):
        if not a.startswith("-") or a.startswith("--"):
            break
        if "c" in a[1:]:
            script = next((x for x in args[j + 1:] if not x.startswith("-")), None)
            return (words[: len(words) - len(sw)], script) if script is not None else None
    return None


_NESTED_DEPTH = 4  # sh -c inside sh -c ... (each level is a quoted string: deeper is not plausible)


def _nested_claude(segs: list[_Seg], redirected: bool = False, assigned: dict[str, str] | None = None,
                   depth: int = 0) -> bool:
    """A claude run in this command that would skip bawwab's hooks: no-hooks flags, bypassPermissions, an
    inline settings value, or another config dir / HOME (on the tokenised command: quotes and line
    continuations can't hide a flag). A `sh -c` script is read the same way, with the HOME /
    CLAUDE_CONFIG_DIR overrides that reach it (its prefix, `env`, or an earlier export)."""
    assigned = dict(assigned or {})
    for seg in segs:
        words = seg.words
        cw = _claude_words(words)
        if cw is None:
            sh = _shell_script(words) if depth < _NESTED_DEPTH else None
            if sh is not None:
                pre, script = sh
                inner = redirected or any(_CONFIG_REDIRECT.match(w) for w in pre)
                if _nested_claude(_segments(_tokens(script)), inner, assigned, depth + 1):
                    return True
                continue
            for w in words[1:] if words[:1] in (["export"], ["declare"], ["typeset"], ["readonly"]) else words:
                m = _ASSIGN.fullmatch(w)
                if not m:
                    break
                assigned[m.group(1)] = m.group(2)
                redirected = redirected or _CONFIG_REDIRECT.match(w) is not None
            continue
        pre, args = cw
        if redirected or any(_CONFIG_REDIRECT.match(w) for w in pre):
            return True
        args = [_VAR_REF.sub(lambda m: assigned.get(m.group(1) or m.group(2), m.group(0)), a) for a in args]
        for j, a in enumerate(args):
            if a.startswith(_NO_HOOKS_FLAGS) or "disableAllHooks" in a or a == "--permission-mode=bypassPermissions":
                return True
            if a == "--permission-mode" and args[j + 1:j + 2] == ["bypassPermissions"]:
                return True
    return False


def _writes_anything(segs: list[_Seg]) -> bool:
    """Some segment redirects into a file or runs a command that isn't read-only."""
    for seg in segs:
        if seg.redirs:
            return True
        w = _strip_prefix(seg.words)
        if w and os.path.basename(w[0]) not in _READ_ONLY:
            return True
    return False


_WHOLE_TOKENISE = 20_000  # bytes: above this, the whole-command claude check tokenises only relevant lines


def _whole_command_checks(cmd: str, acc: _Acc) -> None:
    """Things no reading of the shell grammar may miss: a nested claude without bawwab's hooks, and
    overriding the variables that locate or switch off bawwab."""
    s = cmd.replace('"', "").replace("'", "").replace("\\", "")
    segs: list[_Seg] = []
    if "claude" in s or "disableAllHooks" in s:
        text = cmd
        if len(cmd) > _WHOLE_TOKENISE:  # a huge command: only the text around each mention can matter
            flat = cmd.replace("\\\n", " ")
            spans = [(max(0, m.start() - 500), m.end() + 2000)
                     for m in re.finditer(r"(?i:claude)|disableAllHooks", flat)][:64]
            text = "\n".join(flat[a:b] for a, b in spans)
        acc.spend(2 * len(text))
        segs = _segments(_tokens(text))
    if _NESTED_CLAUDE.search(s) or _nested_claude(segs) or ("disableAllHooks" in s and _writes_anything(segs)):
        acc.protect("nested claude without bawwab hooks")
    if _BAWWAB_ENV.search(s):
        acc.protect("bawwab environment override")


_APPROVAL = "bawwab approval via tool call"
_WRITE_REASONS = ("writes a protected bawwab command", "writes a script that runs bawwab")


def _write_text_only(cmd: str, cwd: str, acc: _Acc) -> None:
    """R57 round 2: when R55's approval reason comes only from text a redirect, tee or heredoc writes to a file
    (`echo 'bawwab approve "$1"' > x.sh`), it is a plain deny like the write rule's: the command is analysed
    again with that text blanked, and if the reason goes away it was the written text."""
    if _APPROVAL not in acc.protected or not acc.write_texts or not any(r in acc.plain for r in _WRITE_REASONS):
        return
    blanked = cmd
    for kind, t in sorted(set(acc.write_texts), key=lambda x: -len(x[1])):
        if not t.strip():
            continue
        if kind == "body":
            blanked = blanked.replace(t, re.sub(r"[^\n]", "", t))
        else:
            for q in ("'", '"'):
                blanked = blanked.replace(q + t + q, "'x'")
    if blanked == cmd:
        return
    again = _Acc(4 * len(blanked) + 1_000_000)
    again.root = blanked
    try:
        _whole_command_checks(blanked, again)
        _bash(blanked, cwd, again)
    except _TooComplex:
        return
    if _APPROVAL not in again.protected:
        acc.protected.remove(_APPROVAL)
        acc.user_only(f"in text written to a file: {_APPROVAL}")


def detect_install(inp: HookInput) -> Targets | Protected | None:
    _RESOLVED.clear()  # files may have changed since the last call
    _TEXTS.clear()
    acc = _Acc()
    ti = inp.tool_input if isinstance(inp.tool_input, dict) else {}
    inp = HookInput(inp.tool_name, ti, inp.cwd or "/")
    if inp.tool_name == "Bash":
        cmd = ti.get("command")
        if isinstance(cmd, str):
            acc.budget = 4 * len(cmd) + 1_000_000
            acc.root = cmd
            try:
                _whole_command_checks(cmd, acc)
                _bash(cmd, inp.cwd, acc)
                _write_text_only(cmd, inp.cwd, acc)
            except _TooComplex:
                return Protected("command too complex to analyse")
    elif inp.tool_name in ("Write", "Edit", "MultiEdit"):
        try:
            _file_tool(inp, acc)
        except _TooComplex:  # e.g. more than _MAX_TARGETS servers in one config write
            return Protected("change too complex to analyse")
    return acc.result()
