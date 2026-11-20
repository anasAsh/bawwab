"""What the VS Code (GitHub Copilot) adapter watches. Stdlib only, no bawwab imports (hooks/fingerprint.py loads it
by path).

Sources (checked 2026-11-21): code.visualstudio.com/docs/agents/reference/mcp-configuration,
code.visualstudio.com/docs/agent-customization/migrate-customizations.
- MCP servers: `servers` in the workspace's .vscode/mcp.json and in the user profile's mcp.json (<user dir>/mcp.json;
  user dir ~/.config/Code/User on Linux, ~/Library/Application Support/Code/User on macOS, "Code - Insiders" for
  Insiders); older builds kept them under "mcp": {"servers": ...} in the user settings.json. Fields: type
  (stdio/http/sse), command, args, cwd, env, envFile; url, headers. The files are JSON with comments.
- The Copilot harness reads ~/.copilot/mcp-config.json ($COPILOT_HOME) `mcpServers`, and skills from
  ~/.copilot/skills and <workspace>/.github/skills. (<workspace>/.mcp.json is Claude Code's file too: the Claude
  Code adapter owns it; .agents/skills is the Codex adapter's.)
Copilot agent hooks (~/.copilot/hooks, .github/hooks) are in preview and not watched yet.
"""
import json
import os
import re
import sys

NAME = "vscode"
TITLE = "VS Code"
HOOK = False  # bawwab installs no hook in VS Code: its holds are recorded and reported only
HOOK_EVENTS = None

_JSONC = re.compile(r'"(?:\\.|[^"\\])*"|//[^\n]*|/\*.*?\*/|,(?=\s*[}\]])', re.S)


def _strip(m: "re.Match") -> str:
    t = m.group(0)
    return t if t.startswith('"') else ""


def load(raw: bytes, path: str) -> object:
    """JSON with comments and trailing commas (VS Code's settings.json / mcp.json)."""
    text = raw.decode("utf-8")
    try:
        return json.loads(text)
    except ValueError:
        return json.loads(_JSONC.sub(_strip, text))


def user_dirs(home: str) -> list[str]:
    if sys.platform == "darwin":
        base = os.path.join(home, "Library", "Application Support")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config")
    return [os.path.join(base, app, "User") for app in ("Code", "Code - Insiders")]


def copilot_home(home: str) -> str:
    return os.environ.get("COPILOT_HOME") or os.path.join(home, ".copilot")


def _git_toplevel(start: str, home: str) -> str | None:
    d = start
    while True:
        if os.path.exists(os.path.join(d, ".git")):
            return None if d == home else d
        parent = os.path.dirname(d)
        if parent == d:
            return None
        d = parent


def project_dirs(cwd: str, home: str) -> list[str]:
    """The project dir and its git toplevel; none for the user-only pass (cwd "")."""
    if not cwd:
        return []
    out = [os.path.realpath(cwd)]
    top = _git_toplevel(out[0], os.path.realpath(home))
    if top and top not in out:
        out.append(top)
    return out


def config_files(cwd: str, home: str) -> list[tuple[str, str, str, tuple]]:
    """(path, scope, kind, keypath): kind "servers" (a name -> server spec table)."""
    out = []
    for u in user_dirs(home):
        out += [(os.path.join(u, "mcp.json"), "user", "servers", ("servers",)),
                (os.path.join(u, "settings.json"), "user", "servers", ("mcp", "servers"))]
    out.append((os.path.join(copilot_home(home), "mcp-config.json"), "user", "servers", ("mcpServers",)))
    for p in project_dirs(cwd, home):
        out.append((os.path.join(p, ".vscode", "mcp.json"), p, "servers", ("servers",)))
    return out


def skill_roots(cwd: str, home: str) -> list[tuple[str, str]]:
    out = [(os.path.join(copilot_home(home), "skills"), "user")]
    out += [(os.path.join(p, ".github", "skills"), p) for p in project_dirs(cwd, home)]
    return out


def extension_roots(cwd: str, home: str) -> list[tuple[str, str]]:
    return []


def json_files(cwd: str, home: str) -> list[tuple[str, tuple]]:
    files: dict[str, list] = {}
    for path, _scope, _kind, kp in config_files(cwd, home):
        files.setdefault(path, []).append(kp)
    return [(p, tuple(kps)) for p, kps in files.items()]


def dirs(cwd: str, home: str) -> list[str]:
    return [d for d, _ in skill_roots(cwd, home) + extension_roots(cwd, home)]


def plugin_dirs(cwd: str, home: str) -> list[str]:
    return []
