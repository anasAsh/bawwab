"""The reviewer (spec §4a): a recommendation on a non-clean scan, never a verdict.

`review` runs a bounded read loop with the judge's backend, then `validate` checks the answer against the
downloaded files. Every failure is `cant-tell`, never `keep`. Nothing here touches the verdict or findings.
"""
from __future__ import annotations

import json
import os
import re
import secrets
import stat
import time
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from bawwab.scan.files import ExtraText, ScanFile
from bawwab.scan.judge.backends import Backend
from bawwab.scan.review import prompt as P
from bawwab.types import ASSESSMENTS, RECOMMENDATIONS, Advice, Assessment, Finding, ScanReport, Severity, Verdict

MIN_QUOTE = 20  # as the judge's grounding rule
MIN_WHOLE_LINE = 6  # a shorter quote must be a whole source line (e.g. one file name in a list), never a fragment
QUOTE_WINDOW = 5  # a quote must be within this many lines of its cited line
CONTEXT_LINES = 20  # about 40 lines of code around each finding
MAX_SUMMARY = MAX_WHY = MAX_QUOTE = 300
MAX_FILE_LABEL = 200
MAX_REASON = 300
MAX_EVIDENCE = 500
MAX_INITIAL = 60_000  # the first message's quoted data
MAX_FILE_BYTES = 2_000_000  # a file larger than this is read only up to here
MAX_LISTED_FILES = 400
MAX_MANIFEST = 4_000
MAX_EXTRA = 8_000
MANIFESTS = ("package.json", "pyproject.toml", "setup.py", ".claude-plugin/plugin.json", ".mcp.json", "SKILL.md")
_KEEPS = ("keep", "keep-with-care")
_LINE_PREFIX = re.compile(r"^\s*\d+ \| ?")  # the `  N | ` prefix of the windows shown to the model


@dataclass(frozen=True)
class Budget:
    rounds: int = 3  # model calls; the last one must answer
    reads: int = 8
    bytes: int = 60_000  # text returned by reads
    timeout_s: float = 90.0  # per call
    total_s: float = 240.0  # whole review


class _CantTell(Exception):
    pass


class _Escape(_CantTell):
    """A path outside the fetched root (absolute, `..`, a symlink): the review ends as cant-tell."""


class _Unavailable(Exception):
    """A missing or non-regular file: reported to the model, not fatal."""


# ------------------------------------------------------------- confined file access

class _Root:
    """Reads files of the fetched root only: relative paths, no `..`, no symlinks anywhere, regular files."""

    def __init__(self, root: Path | None, extra: Iterable[ExtraText] = ()) -> None:
        self.base = Path(os.path.realpath(root)) if root is not None else None
        self.extra = {x.label: x.text.splitlines() for x in extra}
        self._cache: dict[str, list[str]] = {}

    def resolve(self, rel: object) -> Path:
        if not isinstance(rel, str) or not rel or "\0" in rel:
            raise _Escape("a read named no valid path")
        if rel.startswith("/") or os.path.isabs(rel) or rel.startswith("~"):
            raise _Escape(f"a read asked for an absolute path ({_clip(rel)})")
        parts = [p for p in rel.split("/") if p not in ("", ".")]
        if not parts or ".." in parts:
            raise _Escape(f"a read asked for a path outside the extension ({_clip(rel)})")
        if self.base is None:
            raise _Unavailable("nothing was downloaded to read")
        cur = self.base
        for i, part in enumerate(parts):
            cur = cur / part
            try:
                st = os.lstat(cur)
            except FileNotFoundError as e:
                raise _Unavailable("no such file") from e
            except OSError as e:
                raise _Unavailable("cannot be read") from e
            if stat.S_ISLNK(st.st_mode):
                raise _Escape(f"a read asked for a path through a symlink ({_clip(rel)})")
            if i < len(parts) - 1 and not stat.S_ISDIR(st.st_mode):
                raise _Unavailable("no such file")
        if not stat.S_ISREG(st.st_mode):
            raise _Unavailable("not a regular file")
        return cur

    def lines(self, rel: str, *, allow_extra: bool = False) -> list[str]:
        if allow_extra and rel in self.extra:
            return self.extra[rel]
        if rel in self._cache:
            return self._cache[rel]
        path = self.resolve(rel)
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_NONBLOCK", 0))
        try:
            if not stat.S_ISREG(os.fstat(fd).st_mode):
                raise _Unavailable("not a regular file")
            with os.fdopen(fd, "rb", closefd=False) as fh:
                data = fh.read(MAX_FILE_BYTES)
        finally:
            os.close(fd)
        out = data.decode("utf-8", errors="replace").splitlines()
        self._cache[rel] = out
        return out


def _clip(s: object, n: int = 80) -> str:
    from bawwab.report import sanitise

    return sanitise(s, n)


# ------------------------------------------------------------- inputs

def counted_findings(report: ScanReport, threshold: Severity) -> list[Finding]:
    """The findings that produced the verdict (severity at least the suspicious threshold)."""
    return [f for f in report.findings if f.severity >= threshold]


def _keys(report: ScanReport, counted: list[Finding]) -> dict[str, Finding]:
    from bawwab.store import provisional_finding_id

    out: dict[str, Finding] = {}
    for c in counted:
        i = next((i for i, f in enumerate(report.findings) if f is c), None)
        if i is None:
            i = report.findings.index(c)  # ValueError: not a finding of this report
        k = c.id or provisional_finding_id(report.key, c, i)
        if k in out:
            raise _CantTell("two findings share an id")
        out[k] = c
    return out


def _windows(root: _Root, keyed: dict[str, Finding]) -> list[tuple[str, int, int]]:
    ranges: dict[str, list[tuple[int, int]]] = {}
    for f in keyed.values():
        if not f.file:
            continue
        lo, hi = (max(1, f.line - CONTEXT_LINES), f.line + CONTEXT_LINES) if f.line else (1, 2 * CONTEXT_LINES)
        ranges.setdefault(f.file, []).append((lo, hi))
    out = []
    for rel in sorted(ranges):
        merged: list[list[int]] = []
        for lo, hi in sorted(ranges[rel]):
            if merged and lo <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], hi)
            else:
                merged.append([lo, hi])
        out += [(rel, lo, hi) for lo, hi in merged]
    return out


def build_initial(report: ScanReport, keyed: dict[str, Finding], root: _Root, files: list[ScanFile]) -> str:
    """The first message's data: findings, code windows, file list, manifest, tool descriptions."""
    out = ["=== findings to assess ===\n"]
    for k, f in keyed.items():
        loc = f"{f.file}:{f.line}" if f.file and f.line else (f.file or "-")
        out.append(f"[{k}] {f.severity.value} {f.rule} ({f.source}) at {loc}: {f.evidence[:MAX_EVIDENCE]}\n")
    used = sum(len(x.encode()) for x in out)
    truncated = False
    for rel, lo, hi in _windows(root, keyed):
        try:
            lines = root.lines(rel, allow_extra=True)
        except (_Unavailable, _Escape, OSError):
            out.append(f"=== {rel}: not available to read ===\n")
            continue
        hi = min(hi, len(lines))
        if lo > hi:
            continue
        part = f"=== {rel} (lines {lo}-{hi}) ===\n{P.numbered(lines, lo, hi)}"
        if used + len(part.encode()) > MAX_INITIAL:
            truncated = True
            break
        out.append(part)
        used += len(part.encode())
    rels = sorted(f.rel for f in files)
    out.append(f"=== file list ({len(rels)} files) ===\n" + "".join(f"{r}\n" for r in rels[:MAX_LISTED_FILES]))
    if len(rels) > MAX_LISTED_FILES:
        out.append(f"[{len(rels) - MAX_LISTED_FILES} more not listed]\n")
    for m in MANIFESTS:
        try:
            text = "\n".join(root.lines(m))
        except (_Unavailable, _Escape, OSError):
            continue
        out.append(f"=== manifest {m} ===\n{text[:MAX_MANIFEST]}\n")
    extra_used = 0
    for label, lines in root.extra.items():
        text = "\n".join(lines)
        if extra_used + len(text) > MAX_EXTRA:
            truncated = True
            break
        out.append(f"=== {label} ===\n{P.numbered(lines, 1, len(lines))}")
        extra_used += len(text)
    if truncated:
        out.append("[some code was left out to keep this message short; ask to read it]\n")
    return "".join(out)


# ------------------------------------------------------------- reads

def _int(v: object, default: int) -> int:
    return v if isinstance(v, int) and not isinstance(v, bool) else default


def serve_reads(root: _Root, reqs: list, reads_left: int, bytes_left: int) -> tuple[str, str, int, int]:
    """Serve one round of reads. Returns (what was asked, the reply text, reads used, bytes used).
    A path outside the root raises _Escape."""
    asked, parts, n, used = [], [], 0, 0
    for req in reqs:
        if not isinstance(req, dict):
            raise _CantTell("a read request was not an object")
        rel = req.get("path")
        try:
            root.resolve(rel)  # a path outside the root ends the review, even past the read limit
        except _Unavailable:
            pass  # reported below
        start, end = _int(req.get("start"), 1), _int(req.get("end"), 0)
        asked.append(f"{_clip(rel, 120)}:{start}-{end}")
        if n >= reads_left:
            parts.append(f"=== {rel}: not served, the read limit is reached ===\n")
            continue
        n += 1
        if used >= bytes_left:
            parts.append(f"=== {rel}: not served, the size limit is reached ===\n")
            continue
        try:
            lines = root.lines(rel)
        except _Unavailable as e:
            parts.append(f"=== {rel}: {e} ===\n")
            continue
        start = max(1, start)
        end = len(lines) if end < start else min(end, len(lines))
        if start > len(lines):
            parts.append(f"=== {rel}: has only {len(lines)} lines ===\n")
            continue
        body = P.numbered(lines, start, end)
        raw = body.encode()
        if used + len(raw) > bytes_left:
            body = raw[: bytes_left - used].decode("utf-8", errors="ignore") + "\n[cut: the size limit is reached]\n"
            raw = body.encode()
        parts.append(f"=== {rel} (lines {start}-{end}) ===\n{body}")
        used += len(raw)
    return ", ".join(asked) or "nothing", "".join(parts), n, used


# ------------------------------------------------------------- validation

def _check_quote(root: _Root, file: str, line: int, quote: str) -> None:
    """Verbatim, within QUOTE_WINDOW lines of the cited line. At least MIN_QUOTE characters, or (for a short line,
    such as one file name in a list) the whole stripped line, at least MIN_WHOLE_LINE characters."""
    q = _LINE_PREFIX.sub("", quote.strip(), count=1).strip()
    if len(q) < MIN_WHOLE_LINE:
        raise _CantTell(f"a quote is shorter than {MIN_WHOLE_LINE} characters")
    try:
        lines = root.lines(file, allow_extra=True)
    except (_Unavailable, _Escape, OSError) as e:
        raise _CantTell(f"a quote cites a file that can't be read ({_clip(file)})") from e
    if not 1 <= line <= len(lines):
        raise _CantTell(f"a quote cites a line outside {_clip(file)}")
    near = lines[max(0, line - 1 - QUOTE_WINDOW): line + QUOTE_WINDOW]
    if len(q) < MIN_QUOTE:
        if q not in (ln.strip() for ln in near):
            raise _CantTell(f"a quote shorter than {MIN_QUOTE} characters is not a whole line of {_clip(file)} "
                            f"near line {line}")
        return
    if q not in "\n".join(near):
        raise _CantTell(f"a quote does not appear in {_clip(file)} near line {line}")


def validate(
    answer: object, report: ScanReport, root: Path | _Root | None, *,
    counted: list[Finding] | None = None, threshold: Severity = Severity.MED, extra: Iterable[ExtraText] = (),
) -> Advice:
    """Check the reviewer's answer; any failed check is cant-tell with the reason. Never raises."""
    from bawwab.report import sanitise

    try:
        r = root if isinstance(root, _Root) else _Root(root, extra)
        keyed = _keys(report, counted if counted is not None else counted_findings(report, threshold))
        return _validate(answer, report, r, keyed)
    except _CantTell as e:
        return Advice.cant_tell(sanitise(e, MAX_REASON))
    except Exception as e:  # noqa: BLE001 - fail to cant-tell, never to keep
        return Advice.cant_tell(f"the reviewer's answer could not be checked ({type(e).__name__})")


def _validate(answer: object, report: ScanReport, root: _Root, keyed: dict[str, Finding]) -> Advice:
    from bawwab.report import sanitise

    if not isinstance(answer, dict):
        raise _CantTell("the reviewer's answer was not a JSON object")
    rec, summary, items = answer.get("recommendation"), answer.get("summary", ""), answer.get("per_finding")
    if rec not in RECOMMENDATIONS:
        raise _CantTell("the reviewer gave no valid recommendation")
    if not isinstance(summary, str) or not isinstance(items, list):
        raise _CantTell("the reviewer's answer did not match the schema")
    seen: set[str] = set()
    out: list[Assessment] = []
    for it in items:
        if not isinstance(it, dict):
            raise _CantTell("the reviewer's answer did not match the schema")
        fid, ass, why, quote, file, line = (it.get(k) for k in ("finding_id", "assessment", "why", "quote", "file",
                                                                 "line"))
        if not (isinstance(fid, str) and ass in ASSESSMENTS and isinstance(why, str) and why.strip()
                and isinstance(quote, str) and isinstance(file, str) and file
                and isinstance(line, int) and not isinstance(line, bool)):
            raise _CantTell("the reviewer's answer did not match the schema")
        if fid not in keyed:
            raise _CantTell(f"the reviewer assessed a finding that isn't listed ({_clip(fid, 20)})")
        if fid in seen:
            raise _CantTell(f"the reviewer assessed finding {fid} twice")
        seen.add(fid)
        _check_quote(root, file, line, quote)
        out.append(Assessment(fid, ass, sanitise(why, MAX_WHY), sanitise(quote.strip(), MAX_QUOTE),
                              sanitise(file, MAX_FILE_LABEL), line))
    missing = [k for k in keyed if k not in seen]
    if missing:
        raise _CantTell(f"the reviewer did not assess finding(s) {', '.join(missing[:5])}")
    reason = ""
    if rec in _KEEPS and report.verdict == Verdict.MALICIOUS:
        reason = f"capped: the reviewer said {rec}, but a MALICIOUS verdict allows only dont-install or cant-tell"
        rec = "cant-tell"
    elif rec in _KEEPS and any(a.assessment == "real" for a in out):
        reason = f"capped: the reviewer said {rec}, but assessed a finding as real"
        rec = "cant-tell"
    return Advice(rec, sanitise(summary, MAX_SUMMARY), out, reason)


# ------------------------------------------------------------- the loop

def review(
    fetched_root: Path | None, report: ScanReport, files: list[ScanFile], backend: Backend,
    budget: Budget = Budget(), *, counted: list[Finding] | None = None, threshold: Severity = Severity.MED,
    extra: Iterable[ExtraText] = (),
) -> Advice:
    """Claude's recommendation on a scanned report. Never raises; never changes the report."""
    from bawwab.report import sanitise

    try:
        return _review(fetched_root, report, files, backend, budget, counted, threshold, list(extra))
    except _CantTell as e:
        return Advice.cant_tell(sanitise(e, MAX_REASON))
    except TimeoutError:
        return Advice.cant_tell("the reviewer timed out")
    except Exception as e:  # noqa: BLE001 - fail to cant-tell, never to keep
        return Advice.cant_tell(f"reviewer error: {type(e).__name__}")


def _review(root_path, report, files, backend, budget, counted, threshold, extra) -> Advice:
    root = _Root(root_path, extra)
    keyed = _keys(report, counted if counted is not None else counted_findings(report, threshold))
    initial = build_initial(report, keyed, root, files)
    nonce = secrets.token_hex(8)
    deadline = time.monotonic() + budget.total_s
    rounds: list[tuple[str, str]] = []
    reads_used = bytes_used = 0
    for rnd in range(1, budget.rounds + 1):
        final = rnd == budget.rounds or reads_used >= budget.reads or bytes_used >= budget.bytes
        user = P.conversation(
            nonce, report.verdict.value, initial, rounds, reads_left=budget.reads - reads_used,
            bytes_left=budget.bytes - bytes_used, rounds_left=budget.rounds - rnd, final=final,
        )
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError
        raw = backend.complete(P.SYSTEM, user, P.SCHEMA, min(budget.timeout_s, remaining))
        try:
            data = json.loads(raw)
        except (ValueError, TypeError) as e:
            raise _CantTell("the reviewer's answer was not valid JSON") from e
        if isinstance(data, dict) and "recommendation" in data:
            return _validate(data, report, root, keyed)
        reqs = data.get("read") if isinstance(data, dict) else None
        if not isinstance(reqs, list) or not reqs:
            raise _CantTell("the reviewer gave neither a recommendation nor a read request")
        if final:
            raise _CantTell("the reviewer's read budget ran out before it answered")
        asked, served, n, used = serve_reads(root, reqs, budget.reads - reads_used, budget.bytes - bytes_used)
        reads_used += n
        bytes_used += used
        rounds.append((asked, served))
    raise _CantTell("the reviewer's read budget ran out before it answered")  # pragma: no cover
