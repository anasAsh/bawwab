"""What the Codex CLI adapter watches. Stdlib only, no bawwab imports (hooks/fingerprint.py loads it by path).

Sources (checked 2026-11-21): developers.openai.com/codex (now learn.chatgpt.com/docs):
- MCP servers: `[mcp_servers.<name>]` tables in $CODEX_HOME/config.toml (default ~/.codex/config.toml) and in a
  trusted project's .codex/config.toml. stdio: command, args, env, env_vars, cwd; HTTP: url, bearer_token_env_var,
  http_headers, env_http_headers, http_headers_helper; both: enabled (false = off), tools, timeouts...
- Hooks: $CODEX_HOME/hooks.json, <project>/.codex/hooks.json, or inline `[hooks]` in config.toml; events
  PreToolUse, PostToolUse, SessionStart, ... (`[hooks.state]` holds Codex's own trust hashes, not hooks).
- Skills: $HOME/.agents/skills (user), <repo>/.agents/skills (repo), /etc/codex/skills (admin); ~/.codex/skills is
  the older user location (still present on real machines, so it is watched too).
"""
import os
import tomllib

NAME = "codex"
TITLE = "Codex CLI"
HOOK = False  # bawwab has no blocking hook in Codex (yet): its holds are recorded and reported only

HOOK_EVENTS = ("SessionStart", "SessionEnd", "SubagentStart", "SubagentStop", "PreToolUse", "PermissionRequest",
               "PostToolUse", "PreCompact", "PostCompact", "UserPromptSubmit", "Stop", "Interrupt",
               "PreModelRequest", "PostModelRequest")


def load(raw: bytes, path: str) -> object:
    if path.endswith(".toml"):
        return tomllib.loads(raw.decode("utf-8"))
    import json

    return json.loads(raw)


def codex_home(home: str) -> str:
    return os.environ.get("CODEX_HOME") or os.path.join(home, ".codex")


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
    """(path, scope, kind, keypath): kind "servers" (a name -> server spec table) or "hooks" (event -> groups)."""
    ch = codex_home(home)
    out = [(os.path.join(ch, "config.toml"), "user", "servers", ("mcp_servers",)),
           (os.path.join(ch, "config.toml"), "user", "hooks", ("hooks",)),
           (os.path.join(ch, "hooks.json"), "user", "hooks", ("hooks",))]
    for p in project_dirs(cwd, home):
        out += [(os.path.join(p, ".codex", "config.toml"), p, "servers", ("mcp_servers",)),
                (os.path.join(p, ".codex", "config.toml"), p, "hooks", ("hooks",)),
                (os.path.join(p, ".codex", "hooks.json"), p, "hooks", ("hooks",))]
    return out


def skill_roots(cwd: str, home: str) -> list[tuple[str, str]]:
    out = [(os.path.join(home, ".agents", "skills"), "user"), (os.path.join(codex_home(home), "skills"), "user")]
    out += [(os.path.join(p, ".agents", "skills"), p) for p in project_dirs(cwd, home)]
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
