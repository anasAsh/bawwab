"""What the Cursor adapter watches. Stdlib only, no bawwab imports (hooks/fingerprint.py loads it by path).

Sources (checked 2026-11-21): cursor.com/docs/context/mcp and cursor.com/docs/agent/hooks.
- MCP servers: `mcpServers` in ~/.cursor/mcp.json (global) and <project>/.cursor/mcp.json. stdio: type, command,
  args, env, envFile; remote: url, headers, auth.
- Hooks: ~/.cursor/hooks.json and <project>/.cursor/hooks.json: {"version": 1, "hooks": {<event>: [{"command":
  ...}]}}. beforeShellExecution / beforeMCPExecution can deny, but a failing hook is fail-open unless
  failClosed is set.
"""
import json
import os

NAME = "cursor"
TITLE = "Cursor"
HOOK = False  # bawwab installs no hook in Cursor: its holds are recorded and reported only
HOOK_EVENTS = None  # every key of the hooks map is an event


def load(raw: bytes, path: str) -> object:
    return json.loads(raw)


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
    """(path, scope, kind, keypath): kind "servers" (a name -> server spec table) or "hooks" (event -> list)."""
    base = os.path.join(home, ".cursor")
    out = [(os.path.join(base, "mcp.json"), "user", "servers", ("mcpServers",)),
           (os.path.join(base, "hooks.json"), "user", "hooks", ("hooks",))]
    for p in project_dirs(cwd, home):
        out += [(os.path.join(p, ".cursor", "mcp.json"), p, "servers", ("mcpServers",)),
                (os.path.join(p, ".cursor", "hooks.json"), p, "hooks", ("hooks",))]
    return out


def skill_roots(cwd: str, home: str) -> list[tuple[str, str]]:
    return []


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
