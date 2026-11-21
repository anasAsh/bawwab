from __future__ import annotations

import re
import unicodedata

from bawwab.clicmd import cmd
from bawwab.scan.rules.catalog import CATALOG
from bawwab.store import Store
from bawwab.types import Advice, Finding, Mode, ScanReport, Severity, Verdict

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


ADVICE_TITLE = "Claude's recommendation (advice, not a verdict)"  # spec §4a: the label on every surface
ADVICE_LABEL = {"keep": "keep it", "keep-with-care": "keep it, with care", "dont-install": "don't install",
                "cant-tell": "can't tell"}
ADVICE_SHORT = {"keep": "keep", "keep-with-care": "care", "dont-install": "don't", "cant-tell": "?"}
_KEEPS = ("keep", "keep-with-care")


def shown_advice(advice: Advice | None, verdict: Verdict) -> tuple[str, str] | None:
    """(recommendation, reason) as displayed, or None. Fails to cant-tell: an unknown value, or a keep on MALICIOUS
    (the reviewer never allows one; a stored report that has it is not trusted to say so)."""
    if advice is None:
        return None
    rec, reason = advice.recommendation, advice.reason
    if rec not in ADVICE_LABEL:
        return "cant-tell", f"unknown recommendation {sanitise(rec, 30)!r}"
    if rec in _KEEPS and verdict == Verdict.MALICIOUS:
        return "cant-tell", "a keep recommendation is never allowed for a MALICIOUS verdict"
    return rec, reason


def advice_short(advice: Advice | None, verdict: Verdict) -> str:
    """The quarantine table's ADVICE cell: keep / care / don't / ? , or - when there is none."""
    shown = shown_advice(advice, verdict)
    return ADVICE_SHORT[shown[0]] if shown else "-"


def format_advice(advice: Advice | None, verdict: Verdict, indent: str = "") -> list[str]:
    """The recommendation block: the label line, the reason for cant-tell, one line per assessed finding.
    Everything in it is untrusted model output about scanned code, so every field is sanitised."""
    shown = shown_advice(advice, verdict)
    if shown is None:
        return []
    rec, reason = shown
    head = f"{indent}{ADVICE_TITLE}: {ADVICE_LABEL[rec]}"
    summary = sanitise(advice.summary, 300)
    lines = [f"{head} — {summary}" if summary else head]
    if rec == "cant-tell":
        lines.append(f"{indent}    reason: {sanitise(reason, 200) or 'none given'}")
    for x in advice.per_finding:
        lines.append(f"{indent}    {sanitise(x.finding_id or '-', 12)} {sanitise(x.assessment, 12)}: "
                     f"{sanitise(x.why, 200)}")
        quote = sanitise(x.quote, 80)
        if quote:
            loc = sanitise(f"{x.file}:{x.line}" if x.line else x.file, 60)
            lines.append(f"{indent}        \"{quote}\"" + (f" ({loc})" if loc else ""))
    return lines


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
            lines.append(f"  … ({len(raw) - 39} more lines; run ! {cmd('diff')} <name>)")
    ordered = sorted(r.findings, key=lambda f: -f.severity.rank)
    for f in ordered:
        loc = sanitise(_loc(f), 40)
        lines.append(f"  {_SEV_LABEL[f.severity]:<4}  {sanitise(f.id or '-'):<6}  {loc:<20} {sanitise(f.evidence)}")
    lines += format_advice(r.advice, r.verdict)
    pid = sanitise(approval_id) if approval_id else None
    if r.verdict == Verdict.SUSPICIOUS:
        if pid:
            lines.append(f"Blocked pending your approval. To allow:  ! {cmd('approve')} {pid}")
        else:
            lines.append("Blocked pending your approval.")
        if r.mode == Mode.STANDARD:
            lines.append(f"Deep scan first:  ! {cmd('scan --deep')} {sanitise(_deep_arg(r), 200)}")
    elif r.verdict == Verdict.MALICIOUS:
        lines.append(f"Blocked. Override (not recommended):  ! {cmd('approve --force')} {pid or '<id>'}")
    if ordered and ordered[0].id:
        lines.append(f"Explain a finding:  ! {cmd('explain')} {sanitise(ordered[0].id)}")
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
