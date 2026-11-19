"""Rewrite an allowed install so it installs exactly the version that was scanned.

Only package specs at parsed positions are rewritten: in Bash, the runner must
be the command word of a shell segment (after wrappers like sudo/env) or the
first word after `--` in `claude mcp add`, or sit in the JSON of
`claude mcp add-json`; in config files, the args entry of a server.
"""
from __future__ import annotations

import copy
import json
import re
import shlex

from bawwab.fetch.target import package_position
from bawwab.gate.detect import HookInput, _claude_index, _positionals, _strip_prefix
from bawwab.types import Target

_UNPINNED = (None, "latest")
_VERSION = re.compile(r"[A-Za-z0-9.+!_-]+")
_SAFE_WORD = re.compile(r"[A-Za-z0-9_@%+=:,./-]+")

Change = tuple[str, str]  # (package name, pinned version)


def _pins(resolved: dict[Target, str]) -> list[tuple[Target, str]]:
    return [
        (t, v) for t, v in resolved.items()
        if t.kind in ("npm", "pypi") and t.name and t.version in _UNPINNED
        and isinstance(v, str) and _VERSION.fullmatch(v) and v not in ("unknown", "local", "unversioned")
    ]


def _pin_spec(spec: str, kind: str, pins: list[tuple[Target, str]]) -> tuple[str, Change] | None:
    """The pinned spec when `spec` is an unversioned spec of one of the pinned targets."""
    for t, v in pins:
        if t.kind != kind:
            continue
        if kind == "npm" and spec in (t.name, f"{t.name}@latest"):
            return f"{t.name}@{v}", (t.name, v)
        if kind == "pypi":
            m = re.fullmatch(rf"({re.escape(t.name)})(\[[^\]]*\])?", spec)
            if m:
                return f"{m.group(1)}{m.group(2) or ''}=={v}", (t.name, v)
    return None


def _pin_argv(cmd: str, args: list[str], pins: list[tuple[Target, str]]) -> tuple[list[str], list[Change]]:
    """args with the runner's package spec pinned (cmd is the runner)."""
    pos = package_position(cmd, args)
    if pos is None:
        return args, []
    kind, idx, off = pos
    got = _pin_spec(args[idx][off:], kind, pins)
    if got is None:
        return args, []
    out = list(args)
    out[idx] = args[idx][:off] + got[0]
    return out, [got[1]]


# ------------------------------------------------------------------ bash

def _segment_spans(cmd: str) -> list[list[tuple[int, int, str]]]:
    """Words of each shell segment as (start, end, unquoted value); quote-aware; # comments dropped."""
    segs: list[list[tuple[int, int, str]]] = [[]]
    i, n = 0, len(cmd)
    while i < n:
        c = cmd[i]
        if c in " \t\r":
            i += 1
            continue
        if c in ";|&()<>\n":
            if segs[-1]:
                segs.append([])
            i += 1
            continue
        if c == "#":
            nl = cmd.find("\n", i)
            i = n if nl < 0 else nl
            continue
        start, val = i, []
        while i < n and cmd[i] not in " \t\r;|&()<>\n":
            ch = cmd[i]
            if ch == "\\" and i + 1 < n:
                val.append(cmd[i + 1])
                i += 2
            elif ch in "'\"":
                j = i + 1
                while j < n and cmd[j] != ch:
                    if ch == '"' and cmd[j] == "\\" and j + 1 < n:
                        val.append(cmd[j + 1])
                        j += 2
                        continue
                    val.append(cmd[j])
                    j += 1
                i = j + 1
            else:
                val.append(ch)
                i += 1
        segs[-1].append((start, i, "".join(val)))
    return [s for s in segs if s]


def _requote(raw: str, old_val: str, new_val: str) -> str:
    if raw == old_val and _SAFE_WORD.fullmatch(new_val):
        return new_val
    return shlex.quote(new_val)


def _pin_json_text(text: str, pins: list[tuple[Target, str]]) -> tuple[str, list[Change]]:
    try:
        spec = json.loads(text)
    except (ValueError, RecursionError):
        return text, []
    if not isinstance(spec, dict) or not isinstance(spec.get("command"), str) or not isinstance(spec.get("args"), list) \
            or not all(isinstance(a, str) for a in spec["args"]):
        return text, []
    args, changes = _pin_argv(spec["command"], spec["args"], pins)
    if not changes:
        return text, []
    spec["args"] = args
    seps = (",", ":") if '": ' not in text and '", ' not in text else (", ", ": ")
    return json.dumps(spec, separators=seps, ensure_ascii=False), changes


def _pin_bash(cmd: str, pins: list[tuple[Target, str]]) -> tuple[str, list[Change]]:
    if "<<" in cmd:  # heredoc bodies are not shell words; don't touch them
        return cmd, []
    edits: list[tuple[int, int, str]] = []
    changes: list[Change] = []
    for spans in _segment_spans(cmd):
        vals = [v for _, _, v in spans]
        rest = _strip_prefix(vals)
        off = len(vals) - len(rest)
        if not rest or vals[off:] != rest:
            continue
        runner = None
        ci = _claude_index(rest)
        if ci is not None:
            sub = rest[ci:]
            mi = next((i for i, a in enumerate(sub) if a == "mcp"), None)
            if mi is not None and sub[mi + 1:mi + 2] == ["add"] and "--" in sub[mi + 2:]:
                runner = off + ci + mi + 2 + sub[mi + 2:].index("--") + 1
            elif mi is not None and sub[mi + 1:mi + 2] == ["add-json"]:
                pos = _positionals(sub[mi + 2:], {"-s", "--scope"})
                if len(pos) > 1:
                    k = off + ci + mi + 2 + sub[mi + 2:].index(pos[1])
                    new, ch = _pin_json_text(vals[k], pins)
                    if ch:
                        s, e, _ = spans[k]
                        edits.append((s, e, shlex.quote(new)))
                        changes += ch
                continue
        else:
            runner = off
        if runner is None or runner >= len(vals):
            continue
        args, ch = _pin_argv(vals[runner], vals[runner + 1:], pins)
        for j, (old, new) in enumerate(zip(vals[runner + 1:], args)):
            if old != new:
                s, e, _ = spans[runner + 1 + j]
                edits.append((s, e, _requote(cmd[s:e], old, new)))
        changes += ch
    for s, e, text in sorted(edits, reverse=True):
        cmd = cmd[:s] + text + cmd[e:]
    return cmd, changes


# ------------------------------------------------------------------ config files

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


def _pin_document(text: str, pins: list[tuple[Target, str]]) -> tuple[str, list[Change]]:
    try:
        d = json.loads(text)
    except (ValueError, RecursionError):
        return text, []
    changes: list[Change] = []
    for spec in _server_specs(d):
        cmd, args = spec.get("command"), spec.get("args")
        if not isinstance(cmd, str) or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
            continue
        new, ch = _pin_argv(cmd, args, pins)
        if ch:
            spec["args"] = new
            changes += ch
    if not changes:
        return text, []
    out = json.dumps(d, indent=_indent(text), ensure_ascii=False)
    return (out + "\n" if text.endswith("\n") else out), changes


def _pin_fragment(text: str, pins: list[tuple[Target, str]]) -> tuple[str, list[Change]]:
    """Edit new_string fragments: rewrite whole JSON string values inside "args" arrays only."""
    changes: list[Change] = []

    def repl(m: re.Match[str]) -> str:
        if m.group(2):  # object key
            return m.group(0)
        val = m.group(1)
        for kind in ("npm", "pypi"):
            got = _pin_spec(val, kind, pins)
            if got:
                changes.append(got[1])
                return f'"{got[0]}"'
        return m.group(0)

    # Walk each `"args": [` array with a string-aware scanner: a `]` inside a JSON string does not end it,
    # and only string entries at the array's own level (not object keys or nested values) are rewritten.
    string = re.compile(r'"((?:[^"\\\n]|\\.)*)"(\s*:)?')
    out, pos = [], 0
    for m in re.finditer(r'"args"\s*:\s*\[', text):
        if m.start() < pos:  # inside an array we already walked
            continue
        out.append(text[pos:m.end()])
        i, depth = m.end(), 0
        while i < len(text):
            c = text[i]
            if c == '"':
                sm = string.match(text, i)
                if not sm:  # unterminated string: leave the rest alone
                    break
                out.append(repl(sm) if depth == 0 else sm.group(0))
                i = sm.end()
                continue
            out.append(c)
            i += 1
            if c in "[{":
                depth += 1
            elif c in "]}":
                if depth == 0:
                    break
                depth -= 1
        pos = i
    out.append(text[pos:])
    return "".join(out), changes


def pin_changes(inp: HookInput, resolved: dict[Target, str]) -> tuple[dict | None, list[Change]]:
    """(updated tool_input or None, what was pinned)."""
    pins = _pins(resolved)
    if not pins:
        return None, []
    ti = copy.deepcopy(inp.tool_input)
    changes: list[Change] = []

    def apply(d: dict, key: str, fn) -> None:
        s = d.get(key)
        if isinstance(s, str):
            new, ch = fn(s, pins)
            if ch:
                d[key] = new
                changes.extend(ch)

    if inp.tool_name == "Bash":
        apply(ti, "command", _pin_bash)
    elif inp.tool_name == "Write":
        apply(ti, "content", _pin_document)
    elif inp.tool_name == "Edit":
        apply(ti, "new_string", _pin_fragment)
    elif inp.tool_name == "MultiEdit" and isinstance(ti.get("edits"), list):
        for e in ti["edits"]:
            if isinstance(e, dict):
                apply(e, "new_string", _pin_fragment)
    if not changes or ti == inp.tool_input:
        return None, []
    return ti, list(dict.fromkeys(changes))


def pin_input(inp: HookInput, resolved: dict[Target, str]) -> dict | None:
    """The updated tool_input with unversioned npm/pypi specs pinned to the scanned version, or None."""
    return pin_changes(inp, resolved)[0]
