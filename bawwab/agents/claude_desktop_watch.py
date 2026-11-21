"""What the Claude Desktop adapter watches. Stdlib only, no bawwab imports (hooks/fingerprint.py loads it by path).

Sources (checked 2026-11-21): modelcontextprotocol.io/docs/develop/connect-local-servers.
- MCP servers: `mcpServers` (command, args, env) in claude_desktop_config.json, in
  ~/Library/Application Support/Claude/ (macOS) or ~/.config/Claude/ (Linux; $XDG_CONFIG_HOME when set, as
  Electron does). There is no project scope.
- Desktop extensions (.mcpb/.dxt) unpack into "Claude Extensions/<id>/" next to the config. That path is from
  third-party docs only (Anthropic's pages don't name it): unverified, watched as best effort.
Claude Desktop has no hook mechanism.
"""
import json
import os
import sys

NAME = "claude-desktop"
TITLE = "Claude Desktop"
HOOK = False  # no hook mechanism in Claude Desktop: its holds are recorded and reported only
HOOK_EVENTS = None


def load(raw: bytes, path: str) -> object:
    return json.loads(raw)


def config_dir(home: str) -> str:
    if sys.platform == "darwin":
        return os.path.join(home, "Library", "Application Support", "Claude")
    return os.path.join(os.environ.get("XDG_CONFIG_HOME") or os.path.join(home, ".config"), "Claude")


def project_dirs(cwd: str, home: str) -> list[str]:
    return []


def config_files(cwd: str, home: str) -> list[tuple[str, str, str, tuple]]:
    return [(os.path.join(config_dir(home), "claude_desktop_config.json"), "user", "servers", ("mcpServers",))]


def skill_roots(cwd: str, home: str) -> list[tuple[str, str]]:
    return []


def extension_roots(cwd: str, home: str) -> list[tuple[str, str]]:
    return [(os.path.join(config_dir(home), "Claude Extensions"), "user")]


def json_files(cwd: str, home: str) -> list[tuple[str, tuple]]:
    files: dict[str, list] = {}
    for path, _scope, _kind, kp in config_files(cwd, home):
        files.setdefault(path, []).append(kp)
    return [(p, tuple(kps)) for p, kps in files.items()]


def dirs(cwd: str, home: str) -> list[str]:
    return [d for d, _ in skill_roots(cwd, home) + extension_roots(cwd, home)]


def plugin_dirs(cwd: str, home: str) -> list[str]:
    return []
