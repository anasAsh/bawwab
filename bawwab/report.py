from __future__ import annotations

import re
import shlex
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


def sanitise_lines(text: str, cap: int = 400) -> str:
    """sanitise() line by line: real newlines and each line's indent kept; no escapes or control characters."""
    out = []
    for line in str(text).split("\n"):
        body = sanitise(line, cap)
        out.append(" " * (len(line) - len(line.lstrip(" "))) + body if body else "")
    return "\n".join(out)


def _name(r: ScanReport) -> str:
    t = r.target
    return t.name or t.url or t.path or t.raw


def _deep_arg(r: ScanReport) -> str:
    """A spec `bawwab scan --deep` parses back to this target, shell-quoted. A local server's raw text is its whole
    command (`node ./x/index.js`), which the CLI rejects: its scanned directory is the spec."""
    t = r.target
    if t.kind == "npm" and t.name:
        return shlex.quote(f"{t.name}@{t.version or r.resolved_version}")
    if t.kind == "pypi" and t.name:
        v = t.version or r.resolved_version
        return shlex.quote(f"pypi:{t.name}" + (f"=={v}" if v and v not in ("latest", "local") else ""))
    if t.kind == "docker" and t.name:
        return shlex.quote(f"docker:{t.name}" + (f":{t.version}" if t.version else ""))
    if t.kind == "local":
        path = t.origin or t.path or t.raw or "."
        if not path.startswith(("/", "./", "../", "~")) and path not in (".", ".."):
            path = "./" + path
        return shlex.quote(path)
    return shlex.quote(t.url or t.raw or _name(r))


def distinct_findings(findings: list[Finding]) -> list[Finding]:
    """Most severe first, without repeats: a finding whose evidence, at the same place, equals (or is quoted inside,
    or quotes) one already listed says nothing new: a command, and the package.json line that quotes it."""
    out: list[tuple[Finding, str]] = []
    for f in sorted(findings, key=lambda f: -f.severity.rank):
        ev = sanitise(f.evidence, None)
        if ev and any((g.file, g.line) == (f.file, f.line) and (ev in gev or gev in ev) for g, gev in out if gev):
            continue
        out.append((f, ev))
    return [f for f, _ in out]


def why_text(findings: list[Finding], cap: int = 90) -> str:
    """The plain-language WHY: the distinct rule titles, most severe first, in a few words."""
    titles: list[str] = []
    for f in sorted(findings, key=lambda f: -f.severity.rank):
        info = CATALOG.get(f.rule) or (CATALOG["judge"] if f.rule.startswith("judge.") else None)
        t = info.title if info else f.rule
        t = t[:1].lower() + t[1:]
        if t not in titles:
            titles.append(t)
    if not titles:
        return "not accepted (no scan result)"
    text = "; ".join(titles[:2])
    if len(titles) > 2:
        text += f" (+{len(titles) - 2} more)"
    return sanitise(text, cap)


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
    ordered = distinct_findings(r.findings)
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
        lines.append(f"Blocked. Override (not recommended):  ! {cmd('approve --force')} {pid}" if pid else "Blocked.")
    if ordered and ordered[0].id:
        lines.append(f"Explain a finding:  ! {cmd('explain')} {sanitise(ordered[0].id)}")
    return "\n".join(lines)


FOR_CLAUDE = ("For Claude: ask the user with AskUserQuestion (see the bawwab skill); never run approve or reject "
              "yourself, and never install it another way.")


def table(rows: list[tuple[str, ...]], indent: str = "  ") -> list[str]:
    """Rows of already-sanitised cells, each column padded to its widest cell; the last column is left ragged."""
    if not rows:
        return []
    widths = [max(len(r[i]) for r in rows) for i in range(len(rows[0]) - 1)]
    return [indent + "  ".join([c.ljust(w) for c, w in zip(r, widths)] + [r[-1]]).rstrip() for r in rows]


def decision_lines(items: list[tuple[str, str, bool]], details: str, remove: bool = False) -> list[str]:
    """The commands, once: keep (and keep --force for MALICIOUS items), remove, details. Every approve/reject line
    names its items as a trailing `# comment`. items: (id, name, malicious), all already sanitised."""
    keep = [(i, n) for i, n, m in items if not m]
    force = [(i, n) for i, n, m in items if m]

    def line(label: str, args: str, group: list[tuple[str, str]]) -> str:
        return f"  {label}  ! {cmd(args)} {' '.join(i for i, _ in group)}  # {', '.join(n for _, n in group)}"

    out = []
    if keep:
        out.append(line("keep:   ", "approve", keep))
    if force:
        out.append(line("keep (MALICIOUS, overrides the block):", "approve --force", force))
    if remove:
        out.append(line("remove: ", "reject", keep + force))
    out.append(f"  details:  ! {cmd(details)}")
    return out


def item_id_report(store: Store, item_id: str) -> tuple[ScanReport, str | None] | None:
    """The report an approval or quarantine id stands for, and the id when it can still be approved."""
    from bawwab.store import report_from_dict

    pid = item_id.strip().upper()
    d = store.pending_report(pid)
    if not isinstance(d, dict):
        return None
    try:
        r = report_from_dict(d)
    except (ValueError, KeyError, TypeError):
        return None
    return r, (None if store.pending_expired(pid) else pid)


def explain(finding_id: str, store: Store) -> str:
    """A finding id (Fxxxxxx): that finding in plain language. An approval or quarantine id: the full report it
    stands for (every finding, Claude's recommendation, the deep-scan and explain commands)."""
    got = store.get_finding(finding_id.strip())
    if got is None:
        item = item_id_report(store, finding_id) if re.fullmatch(r"\s*[A-Za-z2-7]{4}\s*", finding_id) else None
        if item is not None:
            return format_report(*item)
        return f"unknown id: {sanitise(finding_id, 40)} (not a finding, approval or quarantine id)"
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
