"""What the Claude Code adapter watches. Stdlib only, no bawwab imports.

hooks/fingerprint.py loads this file by path on every tool call, so it must stay a small, cheap table.
Paths are templates: {home} is the user's home directory, {proj} a project directory. A session has several
project directories (see project_dirs): the cwd, $CLAUDE_PROJECT_DIR and the cwd's git toplevel.
In a key path, "{project}" stands for every ~/.claude.json `projects` key that resolves to a project dir.
"""
import json
import os

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
