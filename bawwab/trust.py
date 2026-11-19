"""Trust snapshots: rug-pull detection (changes since trusted) and cross-server reference checks."""

from __future__ import annotations

import difflib
import hashlib
import re
from typing import TYPE_CHECKING

from bawwab.types import Finding, Severity, Target, ToolInfo

if TYPE_CHECKING:
    from bawwab.fetch import FetchOpts
    from bawwab.scan.files import ExtraText, ScanFile
    from bawwab.store import Store

MAX_DIFF_LINES = 40
MAX_SUMMARY_LINES = 120
_PLACEHOLDERS = {"(unnamed)", "(unparsed)"}
STOPLIST = {"read", "write", "search", "list", "get", "fetch", "run"}
MIN_TOOL_NAME = 4
_KNOWN_PREFIXES = ("npm:", "pypi:", "git:", "remote:", "local:", "docker:")


def trust_name(t: Target) -> str:
    """The name trusted snapshots are filed under for a target."""
    if t.kind in ("npm", "pypi", "docker"):
        return f"{t.kind}:{t.name}"
    if t.kind in ("git", "remote"):
        return f"{t.kind}:{t.url or t.raw}"
    return f"local:{t.path or t.raw}"


def _target_from_trust_name(name: str) -> Target | None:
    from bawwab.fetch import parse_target, target_from_url

    if name.startswith("npm:"):
        return Target("npm", name[4:], name=name[4:])
    if name.startswith(("pypi:", "docker:")):
        return parse_target(name)
    if name.startswith("git:"):
        return Target("git", name[4:], url=name[4:])
    if name.startswith("remote:"):
        return target_from_url(name[7:])
    if name.startswith("local:"):
        return Target("local", name[6:], path=name[6:])
    return None


def make_snapshot(files: list[ScanFile], model_text: list[ExtraText], tools: list[ToolInfo]) -> dict:
    tool_map: dict[str, str] = {}
    for e in model_text:
        if e.label.startswith("tool "):
            n = e.label[5:]
            if n and n not in _PLACEHOLDERS:
                tool_map[n] = e.text
    for t in tools:
        if not t.name.startswith(("prompt:", "resource:")):
            tool_map[t.name] = t.description or ""
    return {
        "files": {f.rel: hashlib.sha256(f.text.encode("utf-8", "replace")).hexdigest() for f in files},
        "text": {e.label: e.text for e in model_text},
        "tools": tool_map,
    }


def _clean_lines(lines: list[str]) -> list[str]:
    from bawwab.report import sanitise

    return [l[0] + sanitise(l[1:], 200) if l else l for l in lines]


def _capped(lines: list[str], limit: int = MAX_DIFF_LINES) -> list[str]:
    if len(lines) <= limit:
        return lines
    return lines[: limit - 1] + [f"… ({len(lines) - limit + 1} more lines)"]


def _text_diff(label: str, old: str | None, new: str) -> list[str]:
    diff = difflib.unified_diff(
        (old or "").splitlines(), new.splitlines(), fromfile=f"trusted {label}", tofile=f"current {label}",
        lineterm="", n=1,
    )
    return _capped(_clean_lines(list(diff)))


def diff_snapshots(old: dict, new: dict) -> tuple[list[Finding], str]:
    """Findings and a human summary for what changed in `new` relative to the trusted `old`."""
    findings: list[Finding] = []
    summary: list[str] = []
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
    from bawwab.scan import _static_step
    from bawwab.scan.rules.text import model_facing_text

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
        files, extra, _ = _static_step(f)
        snap = make_snapshot(files, model_facing_text(files, extra), f.remote_tools)
    finally:
        f.cleanup()
    _, summary = diff_snapshots(got[1], snap)
    return summary or f"no changes since trusted snapshot for {name}"


def cross_server_findings(snapshots: dict[str, dict]) -> list[Finding]:
    """One high finding per (A, B, tool) where A's model-facing text mentions B's tool by name."""
    out: list[Finding] = []
    names = sorted(snapshots)
    for a in names:
        a_snap = snapshots[a]
        a_texts = a_snap.get("text", {})
        a_tools = set(a_snap.get("tools", {}))
        for b in names:
            if a == b:
                continue
            for tool in sorted(snapshots[b].get("tools", {})):
                if len(tool) < MIN_TOOL_NAME or tool.lower() in STOPLIST or tool in a_tools:
                    continue
                pat = re.compile(rf"(?<!\w){re.escape(tool)}(?!\w)", re.I)
                for label in sorted(a_texts):
                    if pat.search(a_texts[label]):
                        out.append(Finding(
                            "cross-server.reference", Severity.HIGH, "trust",
                            f"{a}'s {label} mentions {b}'s tool {tool}",
                        ))
                        break
    return out
