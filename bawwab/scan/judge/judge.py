from __future__ import annotations

import json
import re

from bawwab.scan.files import ExtraText, ScanFile
from bawwab.scan.judge.backends import Backend
from bawwab.scan.judge.prompt import SCHEMA, build_prompt
from bawwab.types import Finding, Severity

TIMEOUT_S = 90.0
MAX_EVIDENCE = 500
MIN_QUOTE = 20
UNGROUNDED = Severity.LOW  # what an unquoted high/critical claim counts as
_SEVS = {s.value: s for s in Severity}
_QUOTED = re.compile(r"\"([^\"]+)\"|'([^']+)'|`([^`]+)`")


class _Invalid(Exception):
    pass


def _unavailable(reason: str) -> list[Finding]:
    return [Finding("judge.unavailable", Severity.MED, "gate", reason)]


def _quotes_input(evidence: str, sent: str) -> bool:
    cands = [evidence.strip()]
    for m in _QUOTED.finditer(evidence):
        cands.append(next(g for g in m.groups() if g is not None).strip())
    return any(len(c) >= MIN_QUOTE and c in sent for c in cands)


def _rule(raw: str) -> str:
    r = raw.strip().lower()
    if r.startswith("judge."):
        r = r[6:]
    r = re.sub(r"[^a-z0-9._-]+", "-", r).strip("-.")[:60]
    return "judge." + (r or "finding")


def _parse(raw: str, sent: str, allowed: set[str]) -> list[Finding]:
    try:
        data = json.loads(raw)
    except (ValueError, TypeError) as e:
        raise _Invalid("invalid JSON") from e
    if not isinstance(data, dict) or not isinstance(data.get("findings"), list):
        raise _Invalid("schema mismatch")
    out: list[Finding] = []
    for item in data["findings"]:
        if not isinstance(item, dict):
            raise _Invalid("schema mismatch")
        rule, sev, ev, file = item.get("rule"), item.get("severity"), item.get("evidence"), item.get("file")
        if not (isinstance(rule, str) and isinstance(ev, str) and sev in _SEVS):
            raise _Invalid("schema mismatch")
        if file is not None and not isinstance(file, str):
            raise _Invalid("schema mismatch")
        severity = _SEVS[sev]
        if severity >= Severity.HIGH and not _quotes_input(ev, sent):
            # Escalate-only: the judge may add weight, but only for what it can show. A HIGH or CRITICAL claim
            # without a verbatim quote of the sent text is kept for the user to read, at LOW, so it never makes
            # a verdict by itself (and a CRITICAL is not left at an equally ungrounded HIGH).
            severity = UNGROUNDED
        out.append(
            Finding(_rule(rule), severity, "judge", ev[:MAX_EVIDENCE], file=file if file in allowed else None)
        )
    return out


def judge(
    files: list[ScanFile], extra: list[ExtraText], static: list[Finding], backend: Backend
) -> list[Finding]:
    """Escalate-only: returns findings to ADD. Fails closed with judge.unavailable."""
    try:
        system, user, sent, allowed, truncated = build_prompt(files, extra, static)
        raw = backend.complete(system, user, SCHEMA, TIMEOUT_S)
        out = _parse(raw, sent, allowed)
    except _Invalid as e:
        return _unavailable(str(e))
    except TimeoutError:
        return _unavailable("timeout")
    except Exception as e:  # noqa: BLE001 - fail closed on anything
        return _unavailable(f"backend error: {type(e).__name__}")
    if truncated:
        out.append(
            Finding("judge.truncated", Severity.LOW, "judge", "content exceeded 60 KB; the judge saw a truncated view")
        )
    return out
