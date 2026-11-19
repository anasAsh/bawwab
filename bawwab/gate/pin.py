"""Rewrite an allowed install so it installs exactly the version that was scanned."""
from __future__ import annotations

import copy
import json
import re

from bawwab.fetch.target import target_from_command
from bawwab.gate.detect import HookInput
from bawwab.types import Target

_EXE = re.compile(r"(?<![\w./-])(?:npx|bunx|uvx|pipx|dlx|uv)(?![\w.-])")
_UNPINNED = (None, "latest")
_VERSION = re.compile(r"[A-Za-z0-9.+!_-]+")
_END = r"(?=$|[\s'\";|&)<>])"


def _pins(resolved: dict[Target, str]) -> list[tuple[Target, str]]:
    return [
        (t, v) for t, v in resolved.items()
        if t.kind in ("npm", "pypi") and t.name and t.version in _UNPINNED
        and isinstance(v, str) and _VERSION.fullmatch(v) and v not in ("unknown", "local", "unversioned")
    ]


def _spec_re(t: Target) -> re.Pattern[str]:
    name = re.escape(t.name)
    if t.kind == "npm":
        return re.compile(rf"(?<=[\s'\"=])({name})(?:@latest)?{_END}")
    return re.compile(rf"(?<=[\s'\"=])({name})(\[[^\]\s'\"]*\])?{_END}")


def _pinned(t: Target, v: str, m: re.Match[str]) -> str:
    if t.kind == "npm":
        return f"{m.group(1)}@{v}"
    return f"{m.group(1)}{m.group(2) or ''}=={v}"


def _pin_text(text: str, t: Target, v: str) -> str:
    """Replace the first unversioned spec of t after the runner (npx/uvx/…), or anywhere if no runner."""
    exe = _EXE.search(text)
    start = exe.end() if exe else 0
    m = _spec_re(t).search(" " + text[start:])  # leading space satisfies the look-behind at offset 0
    if not m:
        return text
    a, b = start + m.start() - 1, start + m.end() - 1
    return text[:a] + _pinned(t, v, m) + text[b:]


def _separators(cmd: str) -> list[int]:
    """Positions of unquoted shell separators (; | & ( ) < > newline)."""
    out: list[int] = []
    quote = None
    i = 0
    while i < len(cmd):
        c = cmd[i]
        if quote:
            if c == "\\" and quote == '"':
                i += 2
                continue
            if c == quote:
                quote = None
        elif c == "\\":
            i += 2
            continue
        elif c in "'\"":
            quote = c
        elif c in ";|&()<>\n":
            out.append(i)
        i += 1
    return out


def _pin_bash(cmd: str, t: Target, v: str) -> str:
    """Pin t only inside the shell segment of a runner (npx/uvx/…) that names it."""
    seps = _separators(cmd)
    for exe in _EXE.finditer(cmd):
        end = next((p for p in seps if p >= exe.end()), len(cmd))
        seg = cmd[exe.end():end]
        m = _spec_re(t).search(" " + seg)
        if m:
            a, b = exe.end() + m.start() - 1, exe.end() + m.end() - 1
            return cmd[:a] + _pinned(t, v, m) + cmd[b:]
    return cmd


def _pin_arg(arg: str, t: Target, v: str) -> str:
    m = _spec_re(t).search(" " + arg)
    return _pinned(t, v, m) if m is not None and (m.start(), m.end()) == (1, len(arg) + 1) else arg


def _server_specs(d: object) -> list[dict]:
    if not isinstance(d, dict):
        return []
    maps = [d.get("mcpServers")]
    projects = d.get("projects")
    if isinstance(projects, dict):
        maps += [p.get("mcpServers") for p in projects.values() if isinstance(p, dict)]
    return [s for ms in maps if isinstance(ms, dict) for s in ms.values() if isinstance(s, dict)]


def _indent(text: str) -> int | None:
    m = re.search(r"\n( +)\"", text)
    return len(m.group(1)) if m else None


def _pin_document(text: str, pins: list[tuple[Target, str]]) -> str | None:
    try:
        d = json.loads(text)
    except (ValueError, RecursionError):
        return None
    changed = False
    for spec in _server_specs(d):
        cmd, args = spec.get("command"), spec.get("args")
        if not isinstance(cmd, str) or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            continue
        st = target_from_command(cmd, args)
        if st is None or st.version not in _UNPINNED:
            continue
        for t, v in pins:
            if (st.kind, st.name) != (t.kind, t.name):
                continue
            for i, a in enumerate(args):
                new = _pin_arg(a, t, v)
                if new != a:
                    args[i] = new
                    changed = True
                    break
    if not changed:
        return None
    out = json.dumps(d, indent=_indent(text), ensure_ascii=False)
    return out + "\n" if text.endswith("\n") else out


def pin_input(inp: HookInput, resolved: dict[Target, str]) -> dict | None:
    """The updated tool_input with unversioned npm/pypi specs pinned to the scanned version, or None."""
    pins = _pins(resolved)
    if not pins:
        return None
    ti = copy.deepcopy(inp.tool_input)

    def text(d: dict, key: str, bash: bool = False) -> None:
        s = d.get(key)
        if isinstance(s, str):
            for t, v in pins:
                s = _pin_bash(s, t, v) if bash else _pin_text(s, t, v)
            d[key] = s

    if inp.tool_name == "Bash":
        text(ti, "command", bash=True)
    elif inp.tool_name == "Write":
        c = ti.get("content")
        new = _pin_document(c, pins) if isinstance(c, str) else None
        if new is not None:
            ti["content"] = new
    elif inp.tool_name == "Edit":
        text(ti, "new_string")
    elif inp.tool_name == "MultiEdit" and isinstance(ti.get("edits"), list):
        for e in ti["edits"]:
            if isinstance(e, dict):
                text(e, "new_string")
    return ti if ti != inp.tool_input else None
