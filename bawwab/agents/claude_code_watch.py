"""What the Claude Code adapter watches. Stdlib only, no bawwab imports.

hooks/fingerprint.py loads this file by path on every tool call, so it must stay a plain data table.
Paths are templates: {home} is the user's home directory, {cwd} the project directory.
"""

NAME = "claude-code"

# Settings keys whose value runs code, fetches code, or decides which servers/plugins/hooks run.
SETTINGS_KEYS = (
    "hooks", "disableAllHooks", "enabledPlugins", "extraKnownMarketplaces", "apiKeyHelper", "statusLine",
    "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper", "env", "enableAllProjectMcpServers",
    "enabledMcpjsonServers",
)

# (path template, key paths). Only these keys count for the semantic digest; [] = the whole file.
JSON_FILES = (
    ("{home}/.claude.json", (("mcpServers",), ("projects", "{cwd}", "mcpServers"))),
    ("{home}/.claude/settings.json", tuple((k,) for k in SETTINGS_KEYS)),
    ("{home}/.claude/settings.local.json", tuple((k,) for k in SETTINGS_KEYS)),
    ("{cwd}/.claude/settings.json", tuple((k,) for k in SETTINGS_KEYS)),
    ("{cwd}/.claude/settings.local.json", tuple((k,) for k in SETTINGS_KEYS)),
    ("{cwd}/.mcp.json", (("mcpServers",),)),
    ("{home}/.claude/plugins/installed_plugins.json", ((),)),
    ("{home}/.claude/plugins/known_marketplaces.json", ((),)),
)

# Directories listed two levels deep (entries, and the entries of each child directory).
DIRS = (
    "{home}/.claude/skills", "{home}/.claude/commands", "{home}/.claude/agents",
    "{cwd}/.claude/skills", "{cwd}/.claude/commands", "{cwd}/.claude/agents",
)


def _fill(template: str, cwd: str, home: str) -> str:
    return template.replace("{home}", home).replace("{cwd}", cwd)


def json_files(cwd: str, home: str) -> list[tuple[str, tuple]]:
    out = []
    for tpl, keys in JSON_FILES:
        filled = tuple(tuple(cwd if k == "{cwd}" else k for k in kp) for kp in keys)
        out.append((_fill(tpl, cwd, home), filled))
    return out


def dirs(cwd: str, home: str) -> list[str]:
    return [_fill(t, cwd, home) for t in DIRS]


def watched_paths(cwd: str, home: str) -> list[str]:
    return [p for p, _ in json_files(cwd, home)] + dirs(cwd, home)
