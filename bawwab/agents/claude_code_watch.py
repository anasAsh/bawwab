"""What the Claude Code adapter watches. Stdlib only, no bawwab imports.

hooks/fingerprint.py loads this file by path on every tool call, so it must stay a small, cheap table.
Paths are templates: {home} is the user's home directory, {proj} a project directory. A session has several
project directories (see project_dirs): the cwd, $CLAUDE_PROJECT_DIR and the cwd's git toplevel.
In a key path, "{project}" stands for every ~/.claude.json `projects` key that resolves to a project dir.
"""
import json
import os
import re

NAME = "claude-code"

# Settings keys whose value runs code, fetches code, or decides which servers/plugins/hooks run.
SETTINGS_KEYS = (
    "hooks", "disableAllHooks", "enabledPlugins", "extraKnownMarketplaces", "apiKeyHelper", "statusLine",
    "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "env", "enableAllProjectMcpServers",
    "enabledMcpjsonServers",
)
_SETTINGS = tuple((k,) for k in SETTINGS_KEYS)

USER_JSON = (
    ("{home}/.claude.json", (("mcpServers",), ("projects", "{project}", "mcpServers"))),
    ("{home}/.claude/settings.json", _SETTINGS),
    ("{home}/.claude/settings.local.json", _SETTINGS),
    ("{home}/.claude/plugins/installed_plugins.json", ((),)),
    ("{home}/.claude/plugins/known_marketplaces.json", ((),)),
)
PROJECT_JSON = (
    ("{proj}/.claude/settings.json", _SETTINGS),
    ("{proj}/.claude/settings.local.json", _SETTINGS),
    ("{proj}/.mcp.json", (("mcpServers",),)),
)
# Walking rules shared by the fingerprint and the content hash: never descend into these (their own stat
# is recorded), and always look at these files of an item root (a skill dir, a plugin install path)
# whatever the size budgets say.
SKIP_DIRS = frozenset({"node_modules", ".venv", "venv", "__pycache__", ".git", ".tox", ".mypy_cache",
                       ".pytest_cache"})
ALWAYS_FILES = ("SKILL.md", "hooks/hooks.json", ".mcp.json", ".claude-plugin/plugin.json", "package.json",
                "pyproject.toml", "setup.py")
# Claude Code writes <plugin root>/.in_use/<pid> for each running process and removes it on exit: churn, not
# content. Only that exact shape is ignored; anything else under .in_use counts like any other file.
IN_USE_DIR = ".in_use"
_IN_USE_TEXT = re.compile(rb'\{"pid":([1-9][0-9]{0,9}),"procStart":"[0-9]{1,20}"\}')


def is_in_use_marker(path: str, item_root: str) -> bool:
    """A regular file <item_root>/.in_use/<pid> whose whole text is {"pid":<pid>,"procStart":"<digits>"}."""
    if os.path.dirname(os.path.normpath(path)) != os.path.join(os.path.normpath(item_root), IN_USE_DIR):
        return False
    try:
        if os.path.islink(path) or not os.path.isfile(path) or os.path.getsize(path) > 64:
            return False
        with open(path, "rb") as f:
            m = _IN_USE_TEXT.fullmatch(f.read(65))
    except OSError:
        return False
    return m is not None and m.group(1).decode() == os.path.basename(path)

USER_DIRS = ("{home}/.claude/skills", "{home}/.claude/commands", "{home}/.claude/agents")
PROJECT_DIRS = ("{proj}/.claude/skills", "{proj}/.claude/commands", "{proj}/.claude/agents")


def _git_toplevel(start: str, home: str) -> str | None:
    d = start
    while True:
        if os.path.exists(os.path.join(d, ".git")):
            return None if d == home else d  # a dotfiles repo in ~ is not a project
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def project_dirs(cwd: str, home: str | None = None) -> list[str]:
    """Realpath-normalised project directories of a session: cwd, $CLAUDE_PROJECT_DIR, git toplevel."""
    home = os.path.realpath(home or os.path.expanduser("~"))
    out: list[str] = []
    for p in (cwd, os.environ.get("CLAUDE_PROJECT_DIR") or None):
        if p:
            rp = os.path.realpath(p)
            if rp not in out:
                out.append(rp)
    top = _git_toplevel(out[0], home) if out else None
    if top and top not in out:
        out.append(top)
    return out


def json_files(cwd: str, home: str) -> list[tuple[str, tuple]]:
    out = [(t.replace("{home}", home), keys) for t, keys in USER_JSON]
    for p in project_dirs(cwd, home):
        out += [(t.replace("{proj}", p), keys) for t, keys in PROJECT_JSON]
    return out


def dirs(cwd: str, home: str) -> list[str]:
    out = [t.replace("{home}", home) for t in USER_DIRS]
    for p in project_dirs(cwd, home):
        out += [t.replace("{proj}", p) for t in PROJECT_DIRS]
    return out


def plugin_dirs(cwd: str, home: str) -> list[str]:
    """Install paths of installed plugins (their content runs: watched like skills)."""
    try:
        with open(os.path.join(home, ".claude", "plugins", "installed_plugins.json"), "rb") as f:
            data = json.loads(f.read())
    except (OSError, ValueError, RecursionError):
        return []
    plugins = data.get("plugins") if isinstance(data, dict) else None
    out: list[str] = []
    for entries in plugins.values() if isinstance(plugins, dict) else []:
        for e in entries if isinstance(entries, list) else []:
            p = e.get("installPath") if isinstance(e, dict) else None
            if isinstance(p, str) and p and p not in out:
                out.append(p)
    return out


def project_keys(projects: object, cwd: str, home: str) -> list[str]:
    """~/.claude.json `projects` keys that resolve to one of the session's project dirs."""
    if not isinstance(projects, dict):
        return []
    want = set(project_dirs(cwd, home))
    return [k for k in projects if isinstance(k, str) and (k in want or os.path.realpath(k) in want)]


def watched_paths(cwd: str, home: str) -> list[str]:
    return [p for p, _ in json_files(cwd, home)] + dirs(cwd, home) + plugin_dirs(cwd, home)


# ------------------------------------------------------------------ entry points named by config

_JSON_REFS = (  # (file under the item root, keys whose string values may name a file to run)
    ("hooks/hooks.json", ("command",)),
    (".mcp.json", ("command", "args")),
    (".claude-plugin/plugin.json", ("command", "args")),
    ("package.json", ("main", "bin", "scripts", "exports", "module")),
)
_MD_GLOBS = ("SKILL.md", "commands", "agents")
_MAX_READ = 512 * 1024
MAX_REFS = 64
PKG_BUDGET = 200  # entries walked in the package dir of a referenced file inside a skipped dir
_TOKEN = re.compile(r"[\w${}@%./+~-]+")


def _strings(v: object, keys: tuple, inside: bool = False) -> list[str]:
    out: list[str] = []
    if isinstance(v, str):
        if inside:
            out.append(v)
    elif isinstance(v, list):
        for x in v:
            out += _strings(x, keys, inside)
    elif isinstance(v, dict):
        for k, x in v.items():
            out += _strings(x, keys, inside or k in keys)
    return out


def _read(path: str) -> str:
    try:
        with open(path, "rb") as f:
            return f.read(_MAX_READ).decode("utf-8", "replace")
    except OSError:
        return ""


def _texts(root: str) -> list[str]:
    out: list[str] = []
    for rel, keys in _JSON_REFS:
        raw = _read(os.path.join(root, rel))
        if raw:
            try:
                out += _strings(json.loads(raw), keys)
            except (ValueError, RecursionError):
                out.append(raw)
    for name in _MD_GLOBS:
        p = os.path.join(root, name)
        if name.endswith(".md"):
            out.append(_read(p))
            continue
        try:
            with os.scandir(p) as it:
                out += [_read(e.path) for e in it if e.name.endswith(".md") and e.is_file()]
        except OSError:
            pass
    return out


def entry_refs(root: str, skipped_only: bool = False) -> list[str]:
    """Files inside an item root that its hooks/MCP/plugin/package config or its markdown names (after
    ${CLAUDE_PLUGIN_ROOT} expansion, or relative to the root). They are always checked, even inside a
    skipped dir (node_modules...), because they are what runs."""
    out: list[str] = []
    for text in _texts(root):
        if skipped_only and not any(d in text for d in SKIP_DIRS):
            continue  # the hot path only needs what the normal walk can't see
        for tok in _TOKEN.findall(text):
            if "/" not in tok and "." not in tok:
                continue
            if skipped_only and not any(f"{d}/" in tok for d in SKIP_DIRS):
                continue
            t = tok.replace("${CLAUDE_PLUGIN_ROOT}", root).replace("$CLAUDE_PLUGIN_ROOT", root)
            p = os.path.normpath(t if os.path.isabs(t) else os.path.join(root, t))
            if p in out or not p.startswith(root.rstrip("/") + "/"):
                continue
            for f in [p] if os.path.isfile(p) else _dir_entries(p):
                if f not in out:
                    out.append(f)
                if len(out) >= MAX_REFS:
                    return out
    return out


_DIR_MAINS = ("index.js", "index.mjs", "index.cjs", "index.ts", "__main__.py", "__init__.py", "main.py")


def _dir_entries(d: str) -> list[str]:
    """The files a directory reference runs (`node dir`, `python dir`): package.json main/bin/exports, else
    index.js / __main__.py and the like."""
    if not os.path.isdir(d):
        return []
    out: list[str] = []
    raw = _read(os.path.join(d, "package.json"))
    if raw:
        out.append(os.path.join(d, "package.json"))
        try:
            data = json.loads(raw)
        except (ValueError, RecursionError):
            data = None
        if isinstance(data, dict):
            for v in _strings(data, ("main", "bin", "exports", "module")):
                f = os.path.normpath(os.path.join(d, v))
                if f.startswith(d.rstrip("/") + "/") and os.path.isfile(f) and f not in out:
                    out.append(f)
    out += [f for f in (os.path.join(d, n) for n in _DIR_MAINS) if os.path.isfile(f) and f not in out]
    return out


def package_dir(root: str, path: str) -> str | None:
    """The package a referenced file belongs to when it lies in a skipped dir: node_modules/<pkg> (or
    @scope/<pkg>), site-packages/<top>, else the file's own directory inside the skipped dir."""
    parts = os.path.relpath(path, root).split(os.sep)
    for i, part in enumerate(parts[:-1]):
        if part == "node_modules" and i + 1 < len(parts) - 1:
            n = 3 if parts[i + 1].startswith("@") and i + 2 < len(parts) - 1 else 2
            return os.path.join(root, *parts[: i + n])
        if part == "site-packages" and i + 1 < len(parts) - 1:
            return os.path.join(root, *parts[: i + 2])
        if part in SKIP_DIRS:
            return os.path.dirname(path)
    return None


# ------------------------------------------------------------------ local code an MCP server entry runs
# The effect item of a server binds its decision to these bytes (bawwab/agents/claude_code.py) and the fingerprint
# stats them (hooks/fingerprint.py), so code changed under an unchanged, accepted config entry is checked again.
# Candidates come from the entry's text alone (so the hook can cache them by the config files' stat data);
# payload_roots then looks at the disk. Registry runners (npx, uvx, docker) are not local; `$VAR` paths, bare
# command names (looked up on PATH) and `python -m <module>` are not resolved.

_SCRIPT_RUNNERS = re.compile(r"(node|nodejs|bun|deno|tsx|ts-node|python[0-9.]*|pypy[0-9.]*|ruby|perl|php|bash|sh"
                             r"|zsh)(\.exe)?")
_INLINE = frozenset({"-c", "-e", "--eval", "-p", "--print", "-m"})  # code in the entry itself, or a module name
_PRELOAD = frozenset({"-r", "--require", "--import", "--loader", "--experimental-loader"})  # node: files it runs
_VALUE_FLAGS = frozenset({"-C", "--conditions", "--env-file", "-X", "-W", "--config", "--title", "--input-type",
                          "--inspect-port", "--stack-size"})
_UV_DIRS = ("--directory", "--project")
_UV_VALUE_FLAGS = frozenset({"--with", "--with-requirements", "--with-editable", "--python", "-p", "--index",
                             "--default-index", "--index-url", "--extra-index-url", "-i", "--find-links", "-f",
                             "--env-file", "--extra", "--group", "--only-group", "--no-group", "--package",
                             "--cache-dir", "--config-file", "--color", "--exclude-newer", "--resolution",
                             "--prerelease", "--index-strategy", "--keyring-provider", "--link-mode",
                             "--python-preference", "--refresh-package", "--reinstall-package",
                             "--upgrade-package", "-P"})
PKG_MARKERS = ("package.json", "pyproject.toml", "setup.py")
_PKG_UP = 4  # parent levels searched for a script's package root


def _resolve(base: str, p: str) -> str | None:
    if not p or "$" in p or "\0" in p:
        return None
    p = os.path.expanduser(p)
    return os.path.normpath(p if os.path.isabs(p) else os.path.join(base, p))


def _pathlike(s: str) -> bool:
    return s.startswith(("/", "./", "../", "~")) or "/" in s


def _script_args(args: list, base: str, subcommand: bool) -> list:
    """Files a script runner (node, python, ...) runs: its node preloads and its first positional argument."""
    out: list = []
    i = 1 if subcommand and args[:1] == ["run"] else 0  # deno run x.ts, bun run x.ts
    while i < len(args):
        a = args[i]
        if a in _INLINE:
            break
        if a in _PRELOAD or a in _VALUE_FLAGS:
            if a in _PRELOAD and i + 1 < len(args) and _pathlike(args[i + 1]):
                out.append(_resolve(base, args[i + 1]))
            i += 2
            continue
        if a.startswith("-"):
            k, _, v = a.partition("=")
            if k in _PRELOAD and v and _pathlike(v):
                out.append(_resolve(base, v))
            i += 1
            continue
        out.append(_resolve(base, a))
        break
    return out


def _uv_args(args: list, base: str) -> list:
    """`uv [--directory D] run [--project P] [--with ...] <script.py | python x.py | entry point>`."""
    dirs: dict = {}
    i, run = 0, False
    while i < len(args):
        a = args[i]
        k, eq, v = a.partition("=")
        if k in _UV_DIRS:
            if not eq:
                v = args[i + 1] if i + 1 < len(args) else ""
                i += 1
            dirs[k] = v
            i += 1
            continue
        if a.startswith("-"):
            i += 2 if (a in _UV_VALUE_FLAGS and not eq) else 1
            continue
        if run:
            break
        if a != "run":
            return []  # uv tool run, uv pip ...: not a local project
        run = True
        i += 1
    if not run:
        return []
    cwd = _resolve(base, dirs["--directory"]) if dirs.get("--directory") else base
    if cwd is None:
        return []
    out = []
    if dirs.get("--project") or dirs.get("--directory"):
        out.append(_resolve(cwd, dirs["--project"]) if dirs.get("--project") else cwd)
    rest = args[i:]
    if rest:
        cmd = os.path.basename(rest[0])
        if _SCRIPT_RUNNERS.fullmatch(cmd):
            out += _script_args(rest[1:], cwd, cmd in ("deno", "bun"))
        elif _pathlike(rest[0]) or rest[0].endswith(".py"):
            out.append(_resolve(cwd, rest[0]))
    return out


def server_payloads(spec: object, base: str) -> list:
    """Local paths a server entry runs, from its text alone (base: the dir relative paths start from): the
    command when it is a path, the script (and node preloads) of a script runner, `uv run`'s project dir and
    script. A registry runner (npx, uvx, docker), a bare command name or a `$VAR` path gives nothing."""
    if not isinstance(spec, dict) or spec.get("url"):
        return []
    cmd, args = spec.get("command"), spec.get("args", [])
    if not isinstance(cmd, str) or not cmd or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return []
    exe = os.path.basename(cmd)
    if _SCRIPT_RUNNERS.fullmatch(exe):
        out = _script_args(args, base, exe in ("deno", "bun"))
    elif exe in ("uv", "uv.exe"):
        out = _uv_args(args, base)
    elif _pathlike(cmd):
        out = [_resolve(base, cmd)]
    else:
        out = []
    return list(dict.fromkeys(p for p in out if p))


def _servers_at(data: object, kp: tuple, cwd: str, home: str, base: str) -> list:
    for i, k in enumerate(kp):
        if k == "{project}":
            return [x for pk in project_keys(data, cwd, home)
                    for x in _servers_at(data[pk], kp[i + 1:], cwd, home, os.path.realpath(pk))]
        if not isinstance(data, dict):
            return []
        data = data.get(k)
    return [(base, s) for s in data.values()] if isinstance(data, dict) else []


def payload_candidates(cwd: str, home: str, load) -> list:
    """(path, base) for every server entry the effect check reads: ~/.claude.json's user servers (relative to
    cwd) and project servers (relative to the project), each project's .mcp.json (relative to its dir).
    load(path) returns a watched file's parsed data, or None."""
    out: list = []
    for path, keypaths in json_files(cwd, home):
        kps = [kp for kp in keypaths if kp and kp[-1] == "mcpServers"]
        data = load(path) if kps else None
        if data is None:
            continue
        base = os.path.dirname(path) if os.path.basename(path) == ".mcp.json" else cwd
        for kp in kps:
            for b, spec in _servers_at(data, kp, cwd, home, base):
                out += [(p, b) for p in server_payloads(spec, b)]
    return list(dict.fromkeys(out))


def stop_dirs(cwd: str, home: str, base: str) -> set:
    """Dirs never taken as a server's payload tree (with their parents and /): the session's project dirs,
    the home dir and the entry's own base dir. They are the user's own tree: every edit would re-check the
    server, so an entry that runs one keeps today's binding (its text, plus any script file it names)."""
    return {os.path.realpath(p) for p in [*project_dirs(cwd, home), home, base]}


def _stop(d: str, stops: set) -> bool:
    rd = os.path.realpath(d)
    return rd == os.sep or rd in stops or any(s.startswith(rd.rstrip(os.sep) + os.sep) for s in stops)


def payload_roots(path: str, stops: set) -> list:
    """What to hash (claude_code.py) or stat (fingerprint) for one candidate: [(path, is_tree)]. A dir is a
    tree (none for a stop dir); a file, or a missing path (creating it must count), is itself plus the tree of
    its package root: the nearest parent within _PKG_UP levels holding a PKG_MARKERS file, below any stop dir."""
    if os.path.isdir(path):
        return [] if _stop(path, stops) else [(path, True)]
    out = [(path, False)]
    d = os.path.dirname(path)
    for _ in range(_PKG_UP):
        if _stop(d, stops):
            break
        if any(os.path.isfile(os.path.join(d, m)) for m in PKG_MARKERS):
            out.append((d, True))
            break
        d = os.path.dirname(d)
    return out
