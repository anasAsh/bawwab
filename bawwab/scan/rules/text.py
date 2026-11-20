"""Rules over model-facing text (skills, tool descriptions, remote tool metadata) and plugin manifests."""

from __future__ import annotations

import ast
import json
import re
from collections import Counter
from dataclasses import dataclass

from bawwab.scan.files import ExtraText, ScanFile
from bawwab.scan.rules.code import JS_EXT, PY_EXT, TS_EXT, _js_lang
from bawwab.types import Finding, Severity

from tree_sitter_language_pack import get_parser

MAX_DESC = 20_000
VENDORED = ("node_modules/", "site-packages/", ".venv/", "vendor/")
DESC_KINDS = ("tool", "prompt", "resource")

# ---------------------------------------------------------------- collecting model-facing text


@dataclass
class _Text:
    label: str
    text: str
    is_description: bool  # tool/prompt/resource description or remote metadata (not a skill document)
    shadow_exempt: bool = False  # a protocol parameter table entry: every rule but tool-shadowing (R42 N2)


def _is_doc_path(rel: str, is_skill: bool = True) -> bool:
    low = rel.lower()
    if any(low.startswith(v) or f"/{v}" in low for v in VENDORED):
        return False
    parts = low.split("/")
    base = parts[-1]
    if base == "skill.md" or (base == "readme.md" and is_skill):
        return True
    return base.endswith(".md") and any(p in ("commands", "agents") for p in parts[:-1])


_UNESC_RE = re.compile(r"\\u\{([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\x([0-9a-fA-F]{2})|\\([nrt\\'\"`])")
_SIMPLE = {"n": "\n", "r": "\r", "t": "\t"}


def _unescape(s: str) -> str:
    def sub(m: re.Match) -> str:
        hexv = m.group(1) or m.group(2) or m.group(3)
        if hexv:
            try:
                return chr(int(hexv, 16))
            except (ValueError, OverflowError):
                return m.group(0)
        c = m.group(4)
        return _SIMPLE.get(c, c)

    return _UNESC_RE.sub(sub, s)


def _py_kind(dec: ast.expr) -> tuple[str | None, ast.Call | None]:
    call = dec if isinstance(dec, ast.Call) else None
    target = dec.func if call else dec
    attr = target.attr if isinstance(target, ast.Attribute) else getattr(target, "id", None)
    return (attr if attr in DESC_KINDS else None), call


def _const_str(node: ast.AST | None) -> str | None:
    return node.value if isinstance(node, ast.Constant) and isinstance(node.value, str) else None


def _py_descriptions(text: str) -> list[_Text]:
    tree = ast.parse(text)
    out: list[_Text] = []
    for n in ast.walk(tree):
        if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for dec in n.decorator_list:
                kind, call = _py_kind(dec)
                if kind is None:
                    continue
                kw = {k.arg: k.value for k in call.keywords} if call else {}
                desc = _const_str(kw.get("description")) or ast.get_docstring(n)
                if desc:
                    out.append(_Text(f"{kind} {_const_str(kw.get('name')) or n.name}", desc[:MAX_DESC], True))
                break
        elif isinstance(n, ast.Call) and getattr(n.func, "id", getattr(n.func, "attr", "")) == "Tool":
            kw = {k.arg: _const_str(k.value) for k in n.keywords}
            if kw.get("description"):
                out.append(_Text(f"tool {kw.get('name') or '(unnamed)'}", kw["description"][:MAX_DESC], True))
    return out


def _js_descriptions(text: str, lang: str) -> list[_Text]:
    src = text.encode()
    root = get_parser(lang).parse(src).root_node

    def txt(n) -> str:
        return src[n.start_byte : n.end_byte].decode("utf-8", "replace")

    def string_of(n) -> str | None:
        if n is None:
            return None
        if n.type == "string" or (n.type == "template_string" and "${" not in txt(n)):
            return _unescape(txt(n)[1:-1])
        if n.type == "binary_expression" and txt(n.child_by_field_name("operator")) == "+":
            a, b = string_of(n.child_by_field_name("left")), string_of(n.child_by_field_name("right"))
            return a + b if a is not None and b is not None else None
        if n.type == "parenthesized_expression" and n.named_children:
            return string_of(n.named_children[0])
        return None

    def pairs(obj) -> dict[str, object]:
        res = {}
        for c in obj.named_children:
            if c.type == "pair":
                k = c.child_by_field_name("key")
                if k is not None:
                    res[(string_of(k) if k.type == "string" else txt(k))] = c.child_by_field_name("value")
        return res

    out: list[_Text] = []
    consumed: set[int] = set()
    objects = []
    stack = [root]
    while stack:
        n = stack.pop()
        stack.extend(n.children)
        if n.type == "call_expression":
            fn, args = n.child_by_field_name("function"), n.child_by_field_name("arguments")
            if fn is None or args is None:
                continue
            callee = txt(fn.child_by_field_name("property")) if fn.type == "member_expression" else txt(fn)
            m = re.fullmatch(r"(?:register)?(Tool|Prompt|Resource)", callee, re.I)
            if not m:
                continue
            a = args.named_children
            name = string_of(a[0]) if a else None
            desc = None
            if len(a) > 1 and a[1].type != "object":
                desc = string_of(a[1])
            elif len(a) > 1:
                consumed.add(a[1].id)
                desc = string_of(pairs(a[1]).get("description"))
            if desc:
                out.append(_Text(f"{m.group(1).lower()} {name or '(unnamed)'}", desc[:MAX_DESC], True))
        elif n.type == "object":
            objects.append(n)
    for o in objects:
        if o.id in consumed:
            continue
        p = pairs(o)
        desc, name = string_of(p.get("description")), string_of(p.get("name"))
        if desc and name:
            out.append(_Text(f"tool {name}", desc[:MAX_DESC], True, _schema_param(o, p, string_of, txt)))
    return out


_SCHEMA_TYPES = {"string", "boolean", "integer", "number", "array", "object", "any", "null"}
_TOOL_KEYS = {"inputSchema", "input_schema", "parameters", "handler", "execute", "run", "annotations", "outputSchema"}


_PARAM_CONTAINERS = {"parameters", "returns", "properties", "items"}


def _schema_param(o, p: dict, string_of, txt) -> bool:
    """A protocol / JSON-schema parameter ({name, description, type: "boolean"} or a $ref) nested under a
    parameters / returns / properties / items key, as in the Chrome DevTools protocol tables bundled into
    chrome-devtools-mcp. Its description is still model-facing text for every other rule and the judge;
    it is only not a tool that can shadow another (R40 rescan, R42 N2)."""
    if _TOOL_KEYS & set(p):
        return False
    if not ("$ref" in p or string_of(p.get("type")) in _SCHEMA_TYPES):
        return False
    holder = o.parent
    in_array = holder is not None and holder.type == "array"
    if in_array:
        holder = holder.parent
    if holder is not None and holder.type == "arguments" and in_array:
        # inspectorBackend.registerCommand("Domain.cmd", [{name, type, optional, description, typeRef}])
        return "typeRef" in p  # the CDP table form; `optional` alone is attacker-cheap (review N9)
    if holder is None or holder.type != "pair":
        return False
    k = holder.child_by_field_name("key")
    key = (string_of(k) if k is not None and k.type == "string" else txt(k)) if k is not None else None
    return key in _PARAM_CONTAINERS


_FALLBACK_RE = re.compile(
    r'''description\s*[=:]\s*(?:"""(.{0,4000}?)"""|"((?:[^"\\\n]|\\.){0,4000})"|'((?:[^'\\\n]|\\.){0,4000})')''',
    re.S,
)


def _fallback_descriptions(text: str) -> list[_Text]:
    return [_Text("tool (unparsed)", _unescape(next(g for g in m.groups() if g is not None))[:MAX_DESC], True)
            for m in _FALLBACK_RE.finditer(text)]


def _source_descriptions(f: ScanFile) -> list[_Text]:
    if f.rel.lower().startswith(VENDORED) or any(f"/{v}" in f.rel.lower() for v in VENDORED):
        return []
    try:
        if f.rel.endswith(PY_EXT):
            if not re.search(r"description|tool|prompt|resource", f.text):
                return []
            try:
                return _py_descriptions(f.text)
            except (SyntaxError, ValueError, RecursionError, MemoryError):
                return _fallback_descriptions(f.text)
        if f.rel.endswith(JS_EXT + TS_EXT):
            if "description" not in f.text:
                return []
            try:
                return _js_descriptions(f.text, _js_lang(f.rel))
            except Exception:  # noqa: BLE001 - hostile source must not crash the scan
                return _fallback_descriptions(f.text)
    except Exception:  # noqa: BLE001
        return []
    return []


def _collect(files: list[ScanFile], extra: list[ExtraText]) -> list[_Text]:
    out: list[_Text] = []
    is_skill = any(f.rel.rsplit("/", 1)[-1].lower() == "skill.md" for f in files)
    for f in files:
        if _is_doc_path(f.rel, is_skill):
            out.append(_Text(f.rel, f.text, False))
    for f in files:
        out.extend(_source_descriptions(f))
    out.extend(_Text(e.label, e.text, True) for e in extra)
    return out


def model_facing_text(files: list[ScanFile], extra: list[ExtraText]) -> list[ExtraText]:
    return [ExtraText(t.label, t.text) for t in _collect(files, extra)]


# ---------------------------------------------------------------- patterns

_APOS = r"['\u2019]"
OVERRIDE_RES = [
    re.compile(
        r"\b(?:ignore|disregard|forget)\s+(?:(?:all|any|the|your|of|system)\s+){0,2}"
        r"(?:(?:previous|prior|above|earlier|preceding)\s+){0,2}(?:instructions?|prompts?|rules|directions|context)\b",
        re.I,
    ),
    re.compile(r"\byou\s+are\s+now\s+(?:an?|the|acting|playing|free|unrestricted|my)\b", re.I),
    re.compile(
        r"\b(?:reveal|print|repeat|leak|ignore|disregard|bypass|override|disclose|expose)"
        r"\s+(?:(?:your|the|all|any|its)\s+){0,2}(?:\w+\s+)?system\s+prompt\b",
        re.I,
    ),
    re.compile(r"\b(?:bypass|override)\s+(?:your|the)\s+(?:\w+\s+)?instructions\b", re.I),
    re.compile(
        rf"\b(?:do\s+not|don{_APOS}?t|never|must\s+not|without)\s+(?:(?:ever|even)\s+)?"
        r"(?:tell(?:ing)?|inform(?:ing)?|mention(?:ing)?|notify(?:ing)?|alert(?:ing)?)\s+(?:\w+\s+)?(?:the\s+)?user\b",
        re.I,
    ),
]
_OVERRIDE_QUALIFIER = re.compile(r"\b(?:all|any|previous|prior|above|earlier|preceding)\b", re.I)
_INSTRUCTIONS_DET = re.compile(r"\b(?:your|the|system)\s+(?:(?:system|previous|prior)\s+)?instructions?\b", re.I)


def _override_ok(m: re.Match) -> bool:
    if m.re is not OVERRIDE_RES[0]:
        return True
    g = m.group()
    return _OVERRIDE_QUALIFIER.search(g) is not None or _INSTRUCTIONS_DET.search(g) is not None

_SENSITIVE_PATH = (
    r"(?:~/|/home/\S+/|/root/)?\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.env\b(?!\.(?:example|sample|template))"
    r"|\.aws\b|\.npmrc\b|\.netrc\b|\.pgpass\b|\.git-credentials\b|/etc/passwd|/etc/shadow|\.kube/config|\.docker/config"
    r"|\bkeychain\b|\bcookies\.sqlite\b|\bLogin Data\b"
)
_EXFIL_VERB = r"(?:send|upload|post|forward|attach|append|exfiltrate|leak|email|transmit)"
_DELIVER_VERB = r"(?:put|paste|write|embed|base64|encode|pipe|dump|attach|append|include|send|upload|post|forward|copy|insert)"
_DEST = (
    r"\b(?:in|into|to|as)\s+(?:(?:your|the|a)\s+)?(?:\w+\s+)?"
    r"(?:answers?|repl(?:y|ies)|responses?|output|messages?|arguments?|args|url|parameters?|quer(?:y|ies)|requests?)\b|\bhere\b"
)
CONCEAL_RE = re.compile(
    rf"\b(?:do\s+not|don{_APOS}?t|never|must\s+not|without)\s+(?:(?:ever|even)\s+)?(?:tell|inform|mention|notify|alert|show)\w*\s+(?:\w+\s+)?(?:the\s+)?user\b"
    r"|\bsilently\b|\bquietly\b|\bsecretly\b|\bwithout\s+(?:telling|informing|mentioning)\b|\bhide\s+this\b",
    re.I,
)
COVERT_RES = [
    # read-style access to a sensitive target; only counts together with a concealment phrase nearby (see _covert_ok)
    re.compile(
        r"\b(?:read|cat|open|fetch|print|output|dump|copy|get)\b"
        rf"[^.\n]{{0,60}}?(?:{_SENSITIVE_PATH})",
        re.I,
    ),
    re.compile(rf"\b{_EXFIL_VERB}\b[^.\n]{{0,60}}?(?:{_SENSITIVE_PATH})", re.I),
    re.compile(
        rf"(?:{_SENSITIVE_PATH})[^.\n]{{0,80}}?(?:\b{_EXFIL_VERB}\b|https?://|[\w.-]+@[\w-]+\.)", re.I
    ),
    # target, then a delivery verb, then a destination the model's output goes to
    re.compile(rf"(?:{_SENSITIVE_PATH})[^.\n]{{0,80}}?\b{_DELIVER_VERB}\b[^.\n]{{0,40}}?(?:{_DEST})", re.I),
    re.compile(rf"\b{_DELIVER_VERB}\b[^.\n]{{0,60}}?(?:{_SENSITIVE_PATH})[^.\n]{{0,40}}?(?:{_DEST})", re.I),
    re.compile(
        r"\b(?:send|upload|post|forward|email|transmit|exfiltrate|leak|include|append|attach)\b[^.\n]{0,60}?"
        r"\b(?:secrets?|credentials|passwords?|api[ _-]?keys?|private\s+keys?|tokens?|ssh\s+keys?|env(?:ironment)?\s+(?:vars|variables))\b"
        r"[^.\n]{0,60}?(?:\bto\s+\S*(?:https?:|\.invalid|@|webhook|server|endpoint)|\bin\s+(?:your|the)\s+(?:reply|response|answer|output|message|tool\s+call|arguments?|parameters?)|\bhttps?://)",
        re.I,
    ),
    re.compile(r"\bbefore\s+(?:using|calling|running|invoking|you\s+use|this\s+tool)\b[^.\n]{0,40}?\bfirst\b", re.I),
]

# U+200B-200F, 2060-2064, FEFF, E0000-E007F, 202A-202E, 2066-2069
HIDDEN_RE = re.compile("[\u061c\u200b-\u200f\u2060-\u2064\ufeff\U000e0000-\U000e007f\u202a-\u202e\u2066-\u2069]")


def _html_comments(text: str):
    """Yield (start, end, body) of each <!-- --> comment, in linear time."""
    pos = 0
    while (i := text.find("<!--", pos)) >= 0:
        j = text.find("-->", i + 4)
        if j < 0:
            return
        yield i, j + 3, text[i + 4 : j][:4000]
        pos = j + 3


COMMENT_VERBS = ("read", "send", "run", "call", "include", "ignore", "execute", "fetch", "upload", "delete", "write")
VERB_RE = re.compile(r"(?<![\w-])(?:%s)(?![\w-])" % "|".join(COMMENT_VERBS), re.I)

_NAME = r"[`'\"]?(?P<n>[A-Za-z_][\w.:-]*)[`'\"]?"
_TOOLWORD = r"(?P<w>\s+(?:tool|server|function|command|mcp))?"
SHADOW_RES = [
    re.compile(
        r"\b(?:when|whenever|if|before|after)\s+(?:you\s+)?(?:are\s+)?(?:using|use|calling|call|invoking|invoke|running|run)\s+(?:the\s+)?"
        + _NAME + _TOOLWORD + r"[^.\n]{0,100}?\b(?:always|must|should|also|instead|never|ignore|first|bcc|cc|add|send|include|append)\b",
        re.I,
    ),
    re.compile(r"\binstead\s+of\s+(?:using\s+|calling\s+)?(?:the\s+)?" + _NAME + _TOOLWORD, re.I),
    re.compile(r"\bin\s+place\s+of\s+(?:the\s+)?" + _NAME + _TOOLWORD, re.I),
    re.compile(r"\b(?:always|must|should|first)\s+(?:call|use|invoke|run)\s+(?:the\s+)?" + _NAME + _TOOLWORD, re.I),
    re.compile(r"\boverrid(?:e|es|ing)\s+(?:the\s+)?" + _NAME + _TOOLWORD, re.I),
    re.compile(r"\bnever\s+(?:use|call|invoke)\s+(?:the\s+)?" + _NAME + _TOOLWORD, re.I),
]
_STRONG_SIBLING = (1, 2, 4, 5)  # indexes of SHADOW_RES that shadow even a tool from the same package
_REDIRECT_RE = re.compile(r"\b(?:bcc|cc|send|forward|copy\s+to)\b", re.I)
_GENERIC = {"this", "the", "a", "an", "that", "it", "any", "each", "every", "other", "another", "your", "same", "tool", "these",
            "those", "all", "these", "its", "their", "my", "our", "which", "what", "default", "following", "above", "below", "result"}


def _snip(text: str, start: int, end: int) -> str:
    return re.sub(r"\s+", " ", text[start:end]).strip()[:200]


def _line(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _tool_name(label: str) -> str | None:
    parts = label.split(" ", 1)
    if len(parts) == 2 and parts[0] in DESC_KINDS:
        return parts[1]
    return None


def _mk(rule: str, sev: Severity, t: _Text, pos: int, end: int) -> Finding:
    return Finding(rule, sev, "static", _snip(t.text, pos, end), file=t.label, line=_line(t.text, pos))


_RTL_LETTER = re.compile("[\u0590-\u05ff\u0600-\u06ff\u0750-\u077f\u08a0-\u08ff\ufb1d-\ufdff\ufe70-\ufefe]")
_ARABIC_LETTER = re.compile("[\u0600-\u06ff\u0750-\u077f\u08a0-\u08ff\ufb50-\ufdff\ufe70-\ufefe]")


def _tag_sequence_exempt(text: str) -> set[int]:
    """Indexes of tag characters forming an emoji subdivision flag (black flag + tags + cancel tag)."""
    ok: set[int] = set()
    i, n = 0, len(text)
    while i < n:
        if 0xE0020 <= ord(text[i]) <= 0xE007F:
            j = i
            while j < n and 0xE0020 <= ord(text[j]) <= 0xE007F:
                j += 1
            if i > 0 and text[i - 1] == "\U0001F3F4" and ord(text[j - 1]) == 0xE007F:
                ok.update(range(i, j))
            i = j
        else:
            i += 1
    return ok


def _hidden(t: _Text) -> Finding | None:
    counts: Counter[str] = Counter()
    first = -1
    text = t.text
    has_rtl = _RTL_LETTER.search(text) is not None
    tags_ok = _tag_sequence_exempt(text) if any(0xE0000 <= ord(c) <= 0xE007F for c in HIDDEN_RE.findall(text)) else set()
    for m in HIDDEN_RE.finditer(text):
        i, c = m.start(), m.group()
        if c == "\ufeff" and i == 0:
            continue  # byte-order mark
        if c == "\u200d" and i > 0 and ord(text[i - 1]) > 0x2000:
            continue  # joiner inside an emoji sequence
        if c in "\u200c\u200d" and (
            (i > 0 and _ARABIC_LETTER.match(text[i - 1])) or (i + 1 < len(text) and _ARABIC_LETTER.match(text[i + 1]))
        ):
            continue  # joiner/non-joiner is part of Arabic-script orthography
        if c in "\u200e\u200f\u061c" and has_rtl:
            continue  # directional marks in genuine right-to-left text
        if i in tags_ok:
            continue
        counts[f"U+{ord(c):04X}"] += 1
        if first < 0:
            first = i
    if not counts:
        return None
    ev = ", ".join(f"{cp} x{n}" for cp, n in sorted(counts.items()))
    return Finding("injection.hidden-unicode", Severity.HIGH, "static", f"invisible characters: {ev}"[:200],
                   file=t.label, line=_line(text, first))


def _first(regexes: list[re.Pattern], t: _Text, check=None) -> re.Match | None:
    best = None
    for rx in regexes:
        for m in rx.finditer(t.text):
            if check is None or check(m):
                if best is None or m.start() < best.start():
                    best = m
                break
    return best


def _covert_ok(m: re.Match) -> bool:
    if m.re is not COVERT_RES[0]:
        return True
    s = m.string
    return CONCEAL_RE.search(s, max(0, m.start() - 200), min(len(s), m.end() + 200)) is not None


class TextRules:
    id = "text"

    def run(self, files: list[ScanFile], extra: list[ExtraText]) -> list[Finding]:
        texts = _collect(files, extra)
        tool_names = {n for t in texts if not t.shadow_exempt and (n := _tool_name(t.label)) and n not in ("(unnamed)", "(unparsed)")}
        out: list[Finding] = []
        for t in texts:
            out.extend(self._one(t, tool_names))
        return out

    def _one(self, t: _Text, tool_names: set[str]) -> list[Finding]:
        out: list[Finding] = []
        m = _first(OVERRIDE_RES, t, _override_ok)
        if m:
            out.append(_mk("injection.override", Severity.HIGH, t, m.start(), m.end()))
        m = _first(COVERT_RES, t, _covert_ok)
        if m:
            out.append(_mk("injection.covert-action", Severity.HIGH, t, m.start(), m.end()))
        if (h := _hidden(t)) is not None:
            out.append(h)
        for start, end, body in _html_comments(t.text):
            if VERB_RE.search(body) or any(re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", body) for n in tool_names if len(n) >= 3):
                out.append(_mk("injection.html-comment", Severity.MED, t, start, end))
                break
        if t.is_description and not t.shadow_exempt:
            own = _tool_name(t.label)
            others = tool_names - ({own} if own else set())
            m = _first(SHADOW_RES, t, lambda m: self._names_other(m, own, others))
            if m:
                out.append(_mk("tool-shadowing", Severity.HIGH, t, m.start(), m.end()))
        return out

    @staticmethod
    def _names_other(m: re.Match, own: str | None, others: set[str]) -> bool:
        n = m.group("n").rstrip(".:,;-")
        if not n or n.lower() in _GENERIC or n == own:
            return False
        if n in others:  # a sibling tool: only a strong pattern counts
            return any(m.re is SHADOW_RES[i] for i in _STRONG_SIBLING) or (
                m.re is SHADOW_RES[0] and _REDIRECT_RE.search(m.string, m.start(), m.end() + 80) is not None
            )
        return n in others or bool(m.group("w")) or "_" in n or n.startswith("mcp__")


# ---------------------------------------------------------------- plugin manifests

TOOL_EVENTS = {"PreToolUse", "PostToolUse", "PostToolUseFailure", "PermissionRequest"}  # events where a matcher applies
NET_RE = re.compile(r"(?<![\w-])(?:curl|wget|nc|ncat|netcat)(?![\w-])|\bhttps?\b", re.I)


def _line_of_str(text: str, s: str) -> int | None:
    needle = json.dumps(s)[1:-1][:80]
    i = text.find(needle)
    return _line(text, i) if i >= 0 else None


def _hook_commands(data: object):
    """Yield (event, matcher, command) for each command hook in a hooks mapping."""
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return
    for event, groups in hooks.items():
        for g in groups if isinstance(groups, list) else []:
            if not isinstance(g, dict):
                continue
            matcher = g.get("matcher")
            for h in g.get("hooks", []) if isinstance(g.get("hooks"), list) else []:
                if isinstance(h, dict) and isinstance(h.get("command"), str):
                    yield event, matcher, h["command"]


# Hook matchers are classified as text, never compiled or run: a plugin-supplied regex could hang the scan
# (fix round 1 I1). Narrow: a plain alternation of tool names that doesn't cover the core tools, or a literal
# prefix of 3+ characters followed by `.*`. Everything else with regex syntax is broad (fail closed).
_NAMES_RE = re.compile(r"\^?([A-Za-z0-9_]+(?:\|[A-Za-z0-9_]+)*)\$?")
_PREFIX_RE = re.compile(r"\^?[A-Za-z0-9_]{3,}\.\*\$?")
_CORE_TOOLS = frozenset({"Bash", "Write", "Edit", "Read"})


def _broad_matcher(matcher: object) -> bool:
    """True when the hook may run on every tool call: no matcher, "", "*", a non-string, a name list covering
    Bash, Write, Edit and Read, or any matcher that is not a plain name list or a `prefix.*`."""
    if not isinstance(matcher, str):
        return True
    m = matcher.strip()
    if m in ("", "*") or len(m) > 500:
        return True
    names = _NAMES_RE.fullmatch(m)
    if names:
        return _CORE_TOOLS <= set(names.group(1).split("|"))
    return _PREFIX_RE.fullmatch(m) is None


class PluginRules:
    id = "plugin"

    def run(self, files: list[ScanFile], extra: list[ExtraText]) -> list[Finding]:
        out: list[Finding] = []
        rels = {f.rel for f in files}
        for f in files:
            base = f.rel.rsplit("/", 1)[-1]
            if base not in ("hooks.json", "plugin.json", ".mcp.json") or any(v in f.rel for v in VENDORED):
                continue
            try:
                data = json.loads(f.text)
            except (ValueError, RecursionError, MemoryError):
                continue
            if base != ".mcp.json":
                for event, matcher, cmd in _hook_commands(data):
                    line = _line_of_str(f.text, cmd)
                    if event in TOOL_EVENTS and _broad_matcher(matcher):
                        out.append(Finding("plugin.hook-broad", Severity.MED, "static", cmd[:200], file=f.rel, line=line))
                    if NET_RE.search(cmd):
                        out.append(Finding("plugin.hook-network", Severity.HIGH, "static", cmd[:200], file=f.rel, line=line))
            root = f.rel.rsplit("/", 1)[0] + "/" if "/" in f.rel else ""
            plugin_dir = base == "plugin.json" or (base == ".mcp.json" and f"{root}.claude-plugin/plugin.json" in rels)
            if plugin_dir and isinstance(data, dict):
                servers = data.get("mcpServers")
                if isinstance(servers, dict) and servers:
                    names = ", ".join(sorted(map(str, servers)))[:150]
                    out.append(Finding("plugin.bundled-mcp", Severity.LOW, "static", f"plugin bundles MCP server(s): {names}", file=f.rel))
        return out


TEXT_RULES = [TextRules(), PluginRules()]
