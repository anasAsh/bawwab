"""Environment keys that make a program load extra code, or switch the package index it installs from.

One list, shared by the gate (a server's env in an install command or config write) and the effect check (a
server's env in the config as it is). Stdlib only: the gate's detection also runs during setup, without the venv.
"""
from __future__ import annotations

CODE_ENV = frozenset({
    "NODE_OPTIONS", "NODE_PATH", "PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH",
    "BASH_ENV", "ENV", "PERL5OPT", "PERL5LIB", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS",
})
CODE_ENV_PREFIXES = ("DYLD_",)
INDEX_ENV = frozenset({
    "NPM_CONFIG_REGISTRY", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_INDEX", "UV_DEFAULT_INDEX", "UV_FIND_LINKS",
    "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "NPM_CONFIG_USERCONFIG", "PIP_CONFIG_FILE",
    "UV_CONFIG_FILE",
})
INDEX_ENV_PREFIXES = ("UV_INDEX",)  # compared upper-cased: npm and uv read these keys case-insensitively


def loader_key(key: str) -> str | None:
    """"code", "index", or None for an ordinary variable."""
    if key in CODE_ENV or key.startswith(CODE_ENV_PREFIXES):
        return "code"
    up = key.upper()
    if up in INDEX_ENV or up.startswith(INDEX_ENV_PREFIXES):
        return "index"
    return None


def loader_keys(env: object) -> list[str]:
    """The keys of a server env that load code or switch the package index (none when env isn't a dict)."""
    return [k for k in env if isinstance(k, str) and loader_key(k)] if isinstance(env, dict) else []
