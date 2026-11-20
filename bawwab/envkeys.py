"""Environment keys that make a program load extra code, or switch the package index it installs from.

One list, shared by the gate (a server's env in an install command or config write) and the effect check (a
server's env in the config as it is). Stdlib only: the gate's detection also runs during setup, without the venv.
"""
from __future__ import annotations

import hashlib
import json
import os

CODE_ENV = frozenset({
    "NODE_OPTIONS", "NODE_PATH", "PYTHONSTARTUP", "PYTHONPATH", "PYTHONHOME", "LD_PRELOAD", "LD_LIBRARY_PATH",
    "BASH_ENV", "ENV", "PERL5OPT", "PERL5LIB", "PERLLIB", "RUBYOPT", "RUBYLIB", "JAVA_TOOL_OPTIONS",
    "_JAVA_OPTIONS", "JDK_JAVA_OPTIONS", "CLASSPATH", "LD_AUDIT", "GCONV_PATH", "PYTHONUSERBASE",
})
# Not listed: PATH. A server env PATH=/evil:… can make `command` resolve to another binary, but PATH is set in many
# legitimate configs (nvm, Homebrew); README "Honest limitations" documents it.
CODE_ENV_PREFIXES = ("DYLD_",)
INDEX_ENV = frozenset({
    "NPM_CONFIG_REGISTRY", "UV_INDEX_URL", "UV_EXTRA_INDEX_URL", "UV_INDEX", "UV_DEFAULT_INDEX", "UV_FIND_LINKS",
    "PIP_INDEX_URL", "PIP_EXTRA_INDEX_URL", "PIP_FIND_LINKS", "NPM_CONFIG_USERCONFIG", "PIP_CONFIG_FILE",
    "UV_CONFIG_FILE", "YARN_REGISTRY", "BUN_CONFIG_REGISTRY", "PIP_TRUSTED_HOST",
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


# ------------------------------------------------------------------ gate approval -> effect check link
# What the link waives: ONLY the effect check's "env loads code, so it can't be accepted by a scan" hold, for the
# exact entry the user approved at the gate, in that project. The server's code is still scanned in place.

_LINKABLE_FIELDS = {"type", "command", "args", "env"}  # what `claude mcp add` writes; anything else: no link


def server_entry_hash(command: str, args: list, env: dict, base: str) -> str | None:
    """The identity of a command server's entry as the gate saw it: command, args and env exactly, plus the real path
    of the project dir its relative paths resolve against. None unless every arg and env value is a string."""
    if not isinstance(command, str) or not all(isinstance(a, str) for a in args) \
            or not all(isinstance(k, str) and isinstance(v, str) for k, v in env.items()):
        return None
    canon = json.dumps({"command": command, "args": list(args), "env": dict(env),
                        "base": os.path.realpath(base)},
                       sort_keys=True, separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(canon.encode()).hexdigest()[:32]


def spec_entry_hash(spec: object, base) -> str | None:
    """server_entry_hash of a config entry resolved against base, or None when the entry holds anything the gate's
    approval didn't see (a cwd, headers, another transport) or a non-string arg/env value: never linked."""
    if not isinstance(spec, dict) or not set(spec) <= _LINKABLE_FIELDS or spec.get("type", "stdio") != "stdio":
        return None
    cmd, args, env = spec.get("command"), spec.get("args", []), spec.get("env", {})
    if not isinstance(cmd, str) or not isinstance(args, list) or not isinstance(env, dict):
        return None
    return server_entry_hash(cmd, args, env, str(base))


def entry_meta_key(h: str) -> str:
    """Store meta key listing the protected-action approval keys that cover entry hash h."""
    return f"server-entry:{h}"
