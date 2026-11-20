"""Canary credentials for the deep-mode sandbox.

Stdlib only and Python 3.9 compatible: the image copies this file next to the in-container harness, which
uses the same matching code to look for canaries in files the target wrote.

Every value is random per run and is a *canary string*, never a working credential: the "keys" are random
characters shaped like the real formats (so code that filters by shape still takes them), the "private key"
is random bytes in a PEM frame. A canary seen anywhere outside its decoy file is evidence that the code read
it and moved it.
"""
from __future__ import annotations

import base64
import binascii
import secrets
import string
from typing import Dict, Iterable, List, Optional, Tuple

HOME = "/home/sandbox"

_ALNUM = string.ascii_letters + string.digits
_UPPER = string.ascii_uppercase + "234567"


def _rand(alphabet: str, n: int) -> str:
    return "".join(secrets.choice(alphabet) for _ in range(n))


# name -> (decoy file relative to HOME or None, env var or None, hosts the credential is normally sent to)
# A credential sent to its own service is ordinary use (a GitHub server calling api.github.com with
# GITHUB_TOKEN), not a leak.
_SPECS: Dict[str, Tuple[Optional[str], Optional[str], Tuple[str, ...]]] = {
    "aws_access_key": (".aws/credentials", "AWS_ACCESS_KEY_ID", ("amazonaws.com",)),
    "aws_secret_key": (".aws/credentials", "AWS_SECRET_ACCESS_KEY", ("amazonaws.com",)),
    "ssh_private_key": (".ssh/id_ed25519", None, ()),
    "github_token": (".config/gh/hosts.yml", "GITHUB_TOKEN", ("github.com", "githubusercontent.com")),
    "git_credentials": (".git-credentials", None, ("github.com",)),
    "npm_token": (".npmrc", "NPM_TOKEN", ("registry.npmjs.org", "npmjs.org")),
    "anthropic_key": (".claude.json", "ANTHROPIC_API_KEY", ("anthropic.com",)),
    "openai_key": (".config/openai/key", "OPENAI_API_KEY", ("openai.com",)),
    "dotenv_secret": (".env", None, ()),
}


def make_canaries() -> Dict[str, str]:
    """Fresh random canary values, one per credential kind."""
    return {
        "aws_access_key": "AKIA" + _rand(_UPPER, 16),
        "aws_secret_key": _rand(_ALNUM, 40),
        "ssh_private_key": _rand(_ALNUM, 64),
        "github_token": "ghp_" + _rand(_ALNUM, 36),
        "git_credentials": "ghp_" + _rand(_ALNUM, 36),
        "npm_token": "npm_" + _rand(_ALNUM, 36),
        "anthropic_key": "sk-ant-api03-" + _rand(_ALNUM, 40),
        "openai_key": "sk-proj-" + _rand(_ALNUM, 40),
        "dotenv_secret": _rand(_ALNUM, 32),
    }


def decoy_files(c: Dict[str, str]) -> Dict[str, str]:
    """Decoy home files (path relative to HOME -> content). Plausible shapes, canary values only."""
    pem_body = "\n".join(c["ssh_private_key"][i:i + 70] for i in range(0, len(c["ssh_private_key"]), 70))
    return {
        ".aws/credentials": "[default]\naws_access_key_id = %s\naws_secret_access_key = %s\n"
                            % (c["aws_access_key"], c["aws_secret_key"]),
        ".ssh/id_ed25519": "-----BEGIN OPENSSH PRIVATE KEY-----\n%s\n-----END OPENSSH PRIVATE KEY-----\n" % pem_body,
        ".config/gh/hosts.yml": "github.com:\n    oauth_token: %s\n    user: sandbox\n    git_protocol: https\n"
                                % c["github_token"],
        ".git-credentials": "https://sandbox:%s@github.com\n" % c["git_credentials"],
        ".npmrc": "//registry.npmjs.org/:_authToken=%s\n" % c["npm_token"],
        ".claude.json": '{"primaryApiKey": "%s"}\n' % c["anthropic_key"],
        ".config/openai/key": c["openai_key"] + "\n",
        ".env": "DATABASE_PASSWORD=%s\n" % c["dotenv_secret"],
    }


def decoy_env(c: Dict[str, str]) -> Dict[str, str]:
    return {env: c[name] for name, (_, env, _) in _SPECS.items() if env}


def decoy_paths() -> List[str]:
    """Absolute paths of the decoy credential files."""
    return sorted({HOME + "/" + f for f, _, _ in _SPECS.values() if f})


def own_hosts(name: str) -> Tuple[str, ...]:
    return _SPECS.get(name, (None, None, ()))[2]


def is_own_host(name: str, host: str) -> bool:
    h = (host or "").lower().rstrip(".")
    return any(h == d or h.endswith("." + d) for d in own_hosts(name))


def _b64_cores(raw: bytes) -> List[bytes]:
    """Base64 of `raw` at each of the three byte alignments, trimmed to the part that does not depend on
    the bytes around it, so the canary is found inside a longer base64 string too."""
    out = []
    for pad in range(3):
        enc = base64.b64encode(b"\0" * pad + raw)
        start = -(-8 * pad // 6)  # first output char made only of canary bits
        end = (8 * (pad + len(raw))) // 6  # one past the last such char
        core = enc[start:end]
        if len(core) >= 12:
            out.append(core)
    return out


def variants(value: str) -> List[bytes]:
    """Byte strings that mean "this canary": plain, reversed, hex, base64 (std and url-safe)."""
    raw = value.encode()
    vs = {raw, raw[::-1], binascii.hexlify(raw), binascii.hexlify(raw).upper()}
    for core in _b64_cores(raw):
        vs.add(core)
        vs.add(core.replace(b"+", b"-").replace(b"/", b"_"))
    return sorted(vs)


class Matcher:
    """Finds canary values (and their encodings) in text or bytes."""

    def __init__(self, canaries: Dict[str, str]) -> None:
        self._v = [(name, v) for name, value in sorted(canaries.items()) for v in variants(value)]

    def find(self, data: object) -> List[str]:
        if data is None:
            return []
        b = data if isinstance(data, (bytes, bytearray)) else str(data).encode("utf-8", "surrogateescape")
        return sorted({name for name, v in self._v if v in b})

    def find_all(self, items: Iterable[object]) -> List[str]:
        found = set()
        for x in items:
            found.update(self.find(x))
        return sorted(found)
