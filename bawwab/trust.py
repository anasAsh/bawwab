"""Trust snapshots: rug-pull detection (changes since trusted) and cross-server reference checks."""

from __future__ import annotations

import difflib
import hashlib
import re
import unicodedata
from typing import TYPE_CHECKING

from bawwab.clicmd import cmd
from bawwab.types import Finding, Severity, Target, ToolInfo

if TYPE_CHECKING:
    from bawwab.fetch import FetchOpts
    from bawwab.scan.files import ExtraText, ScanFile
    from bawwab.store import Store

MAX_DIFF_LINES = 40
CHUNK = 150  # diff lines stay under the report's per-line cap so appended text is never cut off
_SANDBOX = "[sandbox] "
_MORE = "… ({n} more lines; run ! {bawwab} diff <name>)"
MAX_SUMMARY_LINES = 120
_PLACEHOLDERS = {"(unnamed)", "(unparsed)"}
STOPLIST = {
    "query", "open", "create", "update", "delete", "status", "help", "find", "send", "save", "load", "call",
    "execute", "info", "data", "file", "files", "search", "list", "read", "write", "get", "fetch", "run",
}
MIN_TOOL_NAME = 4
# A tool name that is one ordinary word (claude, skill, setup, forecast) reads as prose in any README or
# SKILL.md, so it only counts as a mention when it is shaped like a tool call or a qualified tool id.
_PLAIN_WORD = re.compile(r"[A-Za-z][a-z]*|[A-Z]+")
_KNOWN_PREFIXES = ("npm:", "pypi:", "git:", "remote:", "local:", "docker:")


def trust_name(t: Target) -> str:
    """The name trusted snapshots are filed under for a target."""
    if t.kind in ("npm", "pypi", "docker"):
        return f"{t.kind}:{t.name}"
    if t.kind in ("git", "remote"):
        return f"{t.kind}:{t.url or t.raw}"
    return f"local:{t.origin or t.path or t.raw}"


def _target_from_trust_name(name: str) -> Target | None:
    from bawwab.fetch import parse_target, target_from_url

    if name.startswith("npm:"):
        return Target("npm", name[4:], name=name[4:])
    if name.startswith(("pypi:", "docker:")):
        return parse_target(name)
    if name.startswith("git:"):
        return Target("git", name[4:], url=name[4:])
    if name.startswith("remote:"):
        return target_from_url(name[7:], "http")  # recorded as remote: never re-read as a repo
    if name.startswith("local:"):
        return Target("local", name[6:], path=name[6:])
    return None


def make_snapshot(files: list[ScanFile], model_text: list[ExtraText], tools: list[ToolInfo]) -> dict:
    tool_map: dict[str, str] = {}
    text: dict[str, str] = {}
    for e in model_text:
        # duplicate labels (e.g. one tool defined in two files) are concatenated, never overwritten
        text[e.label] = f"{text[e.label]}\n{e.text}" if e.label in text else e.text
        if e.label.startswith("tool "):
            n = e.label[5:]
            if n and n not in _PLACEHOLDERS:
                tool_map[n] = f"{tool_map[n]}\n{e.text}" if n in tool_map else e.text
    for t in tools:
        if not t.name.startswith(("prompt:", "resource:")):
            tool_map[t.name] = t.description or ""
    return {
        "files": {f.rel: hashlib.sha256(f.text.encode("utf-8", "replace")).hexdigest() for f in files},
        "text": text,
        "tools": tool_map,
    }


def merge_snapshots(base: dict, other: dict, prefix: str) -> dict:
    """Fold `other` (a plugin child, sandbox result) into `base` under a label prefix."""
    out = {k: dict(base.get(k, {})) for k in ("files", "text", "tools")}
    for k in out:
        for name, v in other.get(k, {}).items():
            out[k][f"{prefix}{name}"] = v
    return out


_ANSI = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?|\x1b[PX^_][^\x1b]*(?:\x1b\\)?|\x1b[@-Z\\-_]"
)


def _visible(s: str) -> str:
    """Show invisible, format and control characters (and escape sequences) as <U+XXXX> markers."""
    s = _ANSI.sub(lambda m: "".join(f"<U+{ord(c):04X}>" for c in m.group()), s)
    return "".join(
        f"<U+{ord(c):04X}>" if c != "\n" and unicodedata.category(c) in ("Cc", "Cf", "Cs", "Co", "Zl", "Zp") else c
        for c in s
    )


def _wrapped(text: str) -> list[str]:
    out: list[str] = []
    for line in _visible(text).split("\n"):
        out.extend(line[i : i + CHUNK] for i in range(0, len(line), CHUNK)) if line else out.append("")
    return out


def _capped(lines: list[str], limit: int = MAX_DIFF_LINES) -> list[str]:
    if len(lines) <= limit:
        return lines
    return lines[: limit - 1] + [_MORE.format(n=len(lines) - limit + 1, bawwab=cmd(""))]


def _text_diff(label: str, old: str | None, new: str) -> list[str]:
    diff = difflib.unified_diff(
        _wrapped(old or ""), _wrapped(new), fromfile=f"trusted {_visible(label)[:100]}",
        tofile=f"current {_visible(label)[:100]}", lineterm="", n=1,
    )
    return _capped(list(diff))


def _has_sandbox(snap: dict) -> bool:
    return any(_SANDBOX in k for sec in ("files", "text", "tools") for k in snap.get(sec, {}))


def _comparable(old: dict, new: dict) -> tuple[dict, dict]:
    """Sandbox-derived labels exist only in deep scans: compare them only when both sides have them."""
    if _has_sandbox(old) and _has_sandbox(new):
        return old, new

    def strip(snap: dict) -> dict:
        return {sec: {k: v for k, v in snap.get(sec, {}).items() if _SANDBOX not in k}
                for sec in ("files", "text", "tools")}

    return strip(old), strip(new)


def diff_snapshots(old: dict, new: dict) -> tuple[list[Finding], str]:
    """Findings and a human summary for what changed in `new` relative to the trusted `old`."""
    findings: list[Finding] = []
    summary: list[str] = []
    old, new = _comparable(old, new)
    old_text, new_text = old.get("text", {}), new.get("text", {})
    for label in sorted(new_text):
        if old_text.get(label) == new_text[label]:
            continue
        diff = _text_diff(label, old_text.get(label), new_text[label])
        kind = "changed" if label in old_text else "added"
        from bawwab.report import sanitise

        findings.append(Finding(
            "rugpull.text-changed", Severity.MED, "trust", "\n".join(diff),
        ))
        summary.append(f"{sanitise(label, 80)}: {kind} since trusted")
        summary.extend(diff)
    added_tools = sorted(set(new.get("tools", {})) - set(old.get("tools", {})))
    if added_tools:
        from bawwab.report import sanitise

        names = ", ".join(sanitise(n, 60) for n in added_tools)
        findings.append(Finding("rugpull.tools-added", Severity.MED, "trust", f"new tool(s) since trusted: {names[:300]}"))
        summary.insert(0, f"new tools: {names[:300]}")
    of, nf = old.get("files", {}), new.get("files", {})
    added = len(set(nf) - set(of))
    removed = len(set(of) - set(nf))
    changed = sum(1 for k in nf if k in of and of[k] != nf[k])
    if added or removed or changed:
        counts = f"{added} added, {removed} removed, {changed} changed"
        findings.append(Finding("rugpull.files-changed", Severity.LOW, "trust", f"files since trusted: {counts}"))
        summary.insert(0, f"files since trusted: {counts}")
    return findings, "\n".join(_capped(summary, MAX_SUMMARY_LINES))


def diff_since_trusted(name: str, store: Store, fetch_opts: FetchOpts | None = None) -> str:
    from bawwab.fetch import FetchError, fetch_target, parse_target
    from bawwab.config import load_config
    from bawwab.scan import _analyze, _build_snapshot, _Ctx
    from pathlib import Path
    from bawwab.types import Mode

    name = name.strip()
    tname, target = name, None
    if store.latest_snapshot(name) is not None:
        target = _target_from_trust_name(name)
    if target is None:
        try:
            target = parse_target(name)
        except Exception:  # noqa: BLE001
            return f"no trusted snapshot for {name}"
        tname = trust_name(target)
    got = store.latest_snapshot(tname)
    if got is None:
        return f"no trusted snapshot for {name}"
    try:
        f = fetch_target(target, fetch_opts)
    except FetchError as e:
        from bawwab.report import sanitise

        return f"cannot fetch {name}: {sanitise(e, 200)}"
    try:
        ctx = _Ctx(load_config(Path.cwd()), Mode.STANDARD, None, fetch_opts, None, judge=False)
        _analyze(f, ctx)
        snap = _build_snapshot(ctx.parts)
    finally:
        f.cleanup()
    _, summary = diff_snapshots(got[1], snap)
    return summary or f"no changes since trusted snapshot for {name}"


def _mention_pattern(tool: str) -> re.Pattern[str]:
    """How a mention of `tool` looks in text. Every name matches as a qualified id (mcp__server__tool).
    A distinctive name (with _, -, digits or camelCase) also matches as a bare word; a plain word only
    as a call, `tool(` (not `skill(s)`), since as a bare word it is ordinary prose. That call form keeps
    the tool's exact case, so Claude Code's own `Agent(` / `Skill(` never count as a server's agent/skill."""
    t = re.escape(tool)
    qualified = rf"(?i:mcp__[\w-]+?__{t})(?![\w-])"
    if _PLAIN_WORD.fullmatch(tool):
        return re.compile(rf"{qualified}|(?<![\w.]){t}\((?!s\))")
    return re.compile(rf"{qualified}|(?i:(?<!\w){t}(?!\w))")


# Labels of a server's model-facing text (its tool, prompt and resource descriptions). Files (SKILL.md, agents,
# commands, READMEs) are instructions that name tools on purpose, so they are not cross-server evidence (user
# decision 2026-11-21); the injection and steering rules still read them.
_SERVER_TEXT = ("tool ", "prompt ", "resource ")


def cross_server_findings(snapshots: dict[str, dict]) -> list[Finding]:
    """One high finding per (A, B, tool) where A's server text (tool, prompt or resource descriptions) mentions
    B's tool by name (see _mention_pattern for what counts as a mention): one server steering another."""
    out: list[Finding] = []
    names = sorted(snapshots)
    for a in names:
        a_snap = snapshots[a]
        a_texts = {k: v for k, v in a_snap.get("text", {}).items() if k.startswith(_SERVER_TEXT)}
        if not a_texts:
            continue
        a_tools = set(a_snap.get("tools", {}))
        for b in names:
            if a == b:
                continue
            for tool in sorted(snapshots[b].get("tools", {})):
                if len(tool) < MIN_TOOL_NAME or tool.lower() in STOPLIST or tool in a_tools:
                    continue
                pat = _mention_pattern(tool)
                for label in sorted(a_texts):
                    if pat.search(a_texts[label]):
                        out.append(Finding(
                            "cross-server.reference", Severity.HIGH, "trust",
                            f"{a}'s {label} mentions {b}'s tool {tool}",
                        ))
                        break
    return out
