from __future__ import annotations

import re
import unicodedata

from bawwab.scan.rules.catalog import CATALOG
from bawwab.store import Store
from bawwab.types import Finding, Mode, ScanReport, Severity, Verdict

MAX_LINE = 160
_ANSI = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]"  # CSI
    r"|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)?"  # OSC
    r"|\x1b[PX^_][^\x1b]*(?:\x1b\\)?"  # DCS/SOS/PM/APC
    r"|\x1b[@-Z\\-_]"  # other 2-byte escapes
)
_NEWLINES = re.compile(r"[\r\n\t\v\f\u0085  ]+")
_SEV_LABEL = {Severity.CRITICAL: "CRIT", Severity.HIGH: "HIGH", Severity.MED: "MED", Severity.LOW: "LOW"}


def sanitise(s: object, cap: int | None = MAX_LINE) -> str:
    """Make untrusted text safe to print: no escapes, control/format chars or newlines; capped."""
    text = _ANSI.sub("", str(s))
    text = _NEWLINES.sub(" ", text)
    text = "".join(c for c in text if unicodedata.category(c) not in ("Cc", "Cf", "Cs", "Co"))
    text = text.strip()
    if cap is not None and len(text) > cap:
        text = text[: cap - 1] + "…"
    return text


def _name(r: ScanReport) -> str:
    t = r.target
    return t.name or t.url or t.path or t.raw


def _deep_arg(r: ScanReport) -> str:
    t = r.target
    if t.kind in ("npm", "pypi") and t.name:
        return f"{t.name}@{t.version or r.resolved_version}"
    return t.raw or _name(r)


def _loc(f: Finding) -> str:
    if f.file:
        return f"{f.file}:{f.line}" if f.line else f.file
    return f.source if f.source == "identity" else "—"


def format_report(r: ScanReport, approval_id: str | None = None) -> str:
    ok = r.verdict == Verdict.CLEAN
    icon = "✅" if ok else "⛔"
    head = (
        f"{icon} bawwab: {r.verdict.value.upper()} — {sanitise(_name(r), 200)}@{sanitise(r.resolved_version, 80)}"
        f"  ({r.mode.value} scan)"
    )
    lines = [head]
    if r.diff_summary:
        raw = r.diff_summary.splitlines()
        for l in raw[:39 if len(raw) > 40 else 40]:
            lines.append("  " + sanitise(l, MAX_LINE))
        if len(raw) > 40:
            lines.append(f"  … ({len(raw) - 39} more lines; run ! bawwab diff <name>)")
    ordered = sorted(r.findings, key=lambda f: -f.severity.rank)
    for f in ordered:
        loc = sanitise(_loc(f), 40)
        lines.append(f"  {_SEV_LABEL[f.severity]:<4}  {sanitise(f.id or '-'):<6}  {loc:<20} {sanitise(f.evidence)}")
    pid = sanitise(approval_id) if approval_id else None
    if r.verdict == Verdict.SUSPICIOUS:
        if pid:
            lines.append(f"Blocked pending your approval. To allow:  ! bawwab approve {pid}")
        else:
            lines.append("Blocked pending your approval.")
        if r.mode == Mode.STANDARD:
            lines.append(f"Deep scan first:  ! bawwab scan --deep {sanitise(_deep_arg(r), 200)}")
    elif r.verdict == Verdict.MALICIOUS:
        lines.append(f"Blocked. Override (not recommended):  ! bawwab approve --force {pid or '<id>'}")
    if ordered and ordered[0].id:
        lines.append(f"Explain a finding:  ! bawwab explain {sanitise(ordered[0].id)}")
    return "\n".join(lines)


def explain(finding_id: str, store: Store) -> str:
    got = store.get_finding(finding_id.strip())
    if got is None:
        return f"unknown finding id: {sanitise(finding_id, 40)}"
    f, key = got
    info = CATALOG.get(f.rule) or (CATALOG["judge"] if f.rule.startswith("judge.") else None)
    title = info.title if info else sanitise(f.rule, 80)
    why = info.why if info else "No catalog entry for this rule."
    fix = info.fix if info else "Review the evidence manually."
    return "\n".join(
        [
            f"{title}  [{sanitise(f.rule, 80)}]",
            f"Why: {why}",
            f"Fix: {fix}",
            f"Severity: {f.severity.value}",
            f"Location: {sanitise(_loc(f) if f.file else '—', 120)}",
            f"Evidence: {sanitise(f.evidence)}",
            f"Target: {sanitise(key, 300)}",
        ]
    )
