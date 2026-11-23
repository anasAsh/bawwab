"""Rules over model-facing text (skills, tool descriptions, remote tool metadata) and plugin manifests."""

from __future__ import annotations

import ast
import json
import re
from collections import Counter
from dataclasses import dataclass

from bawwab.scan.files import ExtraText, ScanFile
from bawwab.scan.reach import model_facing_docs
from bawwab.scan.rules import parsing
from bawwab.scan.rules.code import JS_EXT, PY_EXT, TS_EXT, _js_lang
from bawwab.types import Finding, Severity

VENDORED = ("node_modules/", "site-packages/", ".venv/", "vendor/")
DESC_KINDS = ("tool", "prompt", "resource")
# Descriptions are kept whole, as docs are: a cap lets 20 KB of benign prose push a payload past what the rules see.
# Their size is bounded by the file limits (bawwab.scan.files) like any other text.

# ---------------------------------------------------------------- collecting model-facing text


@dataclass
class _Text:
    label: str
    text: str
    is_description: bool  # tool/prompt/resource description or remote metadata (not a skill document)
    shadow_exempt: bool = False  # a protocol parameter table entry: every rule but tool-shadowing (R42 N2)
    params: frozenset[str] = frozenset()  # the tool's own parameter names, from its signature or input schema
    extended: bool = False  # a skill folder's other docs (reference.md, templates): doc_rank 2


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


_NOT_PARAMS = {"self", "cls", "ctx", "context"}


def _py_params(fn: ast.FunctionDef | ast.AsyncFunctionDef) -> frozenset[str]:
    a = fn.args
    return frozenset(x.arg for x in (*a.posonlyargs, *a.args, *a.kwonlyargs) if x.arg not in _NOT_PARAMS)


def _py_schema_keys(node: ast.AST | None) -> frozenset[str]:
    """Property names of a literal JSON-schema dict (`{"type": "object", "properties": {...}}`)."""
    if not isinstance(node, ast.Dict):
        return frozenset()
    d = {_const_str(k): v for k, v in zip(node.keys, node.values) if k is not None}
    props = d.get("properties")
    if isinstance(props, ast.Dict):
        return frozenset(k for k in map(_const_str, props.keys) if k)
    return frozenset()


def _py_descriptions(text: str) -> list[_Text]:
    tree = parsing.py_parse(text)
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
                    out.append(_Text(f"{kind} {_const_str(kw.get('name')) or n.name}", desc, True,
                                     params=_py_params(n)))
                break
        elif isinstance(n, ast.Call) and getattr(n.func, "id", getattr(n.func, "attr", "")) == "Tool":
            kwn = {k.arg: k.value for k in n.keywords}
            kw = {k: _const_str(v) for k, v in kwn.items()}
            if kw.get("description"):
                schema = next((kwn[k] for k in ("inputSchema", "input_schema", "parameters") if k in kwn), None)
                out.append(_Text(f"tool {kw.get('name') or '(unnamed)'}", kw["description"], True,
                                 params=_py_schema_keys(schema)))
    return out


def _js_descriptions(text: str, lang: str) -> list[_Text]:
    src = text.encode()
    root = parsing.js_root(src, lang)

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

    def shape_keys(n, depth: int = 0) -> frozenset[str]:
        """Parameter names of a tool's input: a zod shape `{a: z.string()}`, `z.object({...})`, or a JSON schema
        `{type: "object", properties: {...}}`."""
        if n is None or depth > 3:
            return frozenset()
        if n.type == "call_expression":
            a = n.child_by_field_name("arguments")
            return shape_keys(a.named_children[0], depth + 1) if a is not None and a.named_children else frozenset()
        if n.type != "object":
            return frozenset()
        p = pairs(n)
        if "properties" in p:
            return shape_keys(p["properties"], depth + 1)
        return frozenset(k for k in p if k)

    def schema_of(p: dict) -> frozenset[str]:
        return next((shape_keys(p[k]) for k in ("inputSchema", "input_schema", "parameters", "schema", "args") if k in p),
                    frozenset())

    out: list[_Text] = []
    consumed: set[int] = set()
    objects = []
    stack = [root]
    del root  # a visited node is freed once popped (no Python mirror of the whole tree)
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
            params: frozenset[str] = frozenset()
            if len(a) > 1 and a[1].type != "object":
                desc = string_of(a[1])
                params = frozenset().union(*(shape_keys(x) for x in a[2:4] if x.type in ("object", "call_expression")))
            elif len(a) > 1:
                consumed.add(a[1].id)
                p1 = pairs(a[1])
                desc = string_of(p1.get("description"))
                params = schema_of(p1)
            if desc:
                out.append(_Text(f"{m.group(1).lower()} {name or '(unnamed)'}", desc, True, params=params))
        elif n.type == "object":
            objects.append(n)
    for o in objects:
        if o.id in consumed:
            continue
        p = pairs(o)
        desc, name = string_of(p.get("description")), string_of(p.get("name"))
        if desc and name:
            out.append(_Text(f"tool {name}", desc, True, _schema_param(o, p, string_of, txt), schema_of(p)))
    return out


_SCHEMA_TYPES = {"string", "boolean", "integer", "number", "array", "object", "any", "null"}
_TOOL_KEYS = {"inputSchema", "input_schema", "parameters", "handler", "execute", "run", "annotations", "outputSchema"}


_PARAM_CONTAINERS = {"parameters", "returns", "properties", "items"}
# queryParameters / pathParams / prompt `arguments`: a list of parameter rows (Sentry's bundled API endpoint tables)
_PARAM_LIST_KEY = re.compile(r"(?:query|path|body|header|form|url|request)_?param(?:eter)?s|parameters|params|arguments", re.I)
_BOOL_LIT = {"true", "false", "!0", "!1"}


def _schema_param(o, p: dict, string_of, txt) -> bool:
    """A protocol / JSON-schema parameter ({name, description, type: "boolean"} or a $ref) nested under a
    parameters / returns / properties / items key, as in the Chrome DevTools protocol tables bundled into
    chrome-devtools-mcp. Its description is still model-facing text for every other rule and the judge;
    it is only not a tool that can shadow another (R40 rescan, R42 N2)."""
    if _TOOL_KEYS & set(p):
        return False
    typed = "$ref" in p or string_of(p.get("type")) in _SCHEMA_TYPES
    req = p.get("required")
    row = req is not None and txt(req) in _BOOL_LIT  # {name, required: false, description}: a parameter row
    if not (typed or row):
        return False
    holder = o.parent
    in_array = holder is not None and holder.type == "array"
    if in_array:
        holder = holder.parent
    if holder is not None and holder.type == "arguments" and in_array:
        # inspectorBackend.registerCommand("Domain.cmd", [{name, type, optional, description, typeRef}])
        return typed and "typeRef" in p  # the CDP table form; `optional` alone is attacker-cheap (review N9)
    if holder is None or holder.type != "pair":
        return False
    k = holder.child_by_field_name("key")
    key = (string_of(k) if k is not None and k.type == "string" else txt(k)) if k is not None else None
    if key is None:
        return False
    if in_array and _PARAM_LIST_KEY.fullmatch(key):
        return True  # queryParameters: [{name, required: false, description, type}] - a parameter row, not a tool
    return typed and key in _PARAM_CONTAINERS


_FALLBACK_RE = re.compile(
    r'''description\s*[=:]\s*(?:"""(.{0,4000}?)"""|"((?:[^"\\\n]|\\.){0,4000})"|'((?:[^'\\\n]|\\.){0,4000})')''',
    re.S,
)


def _fallback_descriptions(text: str) -> list[_Text]:
    return [_Text("tool (unparsed)", _unescape(next(g for g in m.groups() if g is not None)), True)
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
            except (SyntaxError, ValueError, RecursionError):
                return _fallback_descriptions(f.text)
        if f.rel.endswith(JS_EXT + TS_EXT):
            if "description" not in f.text:
                return []
            try:
                return _js_descriptions(f.text, _js_lang(f.rel))
            except MemoryError:
                raise
            except Exception:  # noqa: BLE001 - hostile source must not crash the scan
                return _fallback_descriptions(f.text)
    except MemoryError:
        raise
    except Exception:  # noqa: BLE001
        return []
    return []


def doc_rank(rel: str) -> int:
    """Order of the model-facing docs (the judge's 60 KB budget is spent in this order): SKILL.md first, then a
    skill's README.md and commands/agents docs, then the other docs of a skill folder."""
    base = rel.rsplit("/", 1)[-1].lower()
    return 0 if base == "skill.md" else 1 if _is_doc_path(rel) else 2


def _collect(files: list[ScanFile], extra: list[ExtraText]) -> list[_Text]:
    out: list[_Text] = []
    is_skill = any(f.rel.rsplit("/", 1)[-1].lower() == "skill.md" for f in files)
    docs = model_facing_docs(f.rel for f in files)
    picked = [f for f in files if f.rel in docs or _is_doc_path(f.rel, is_skill)]
    for f in sorted(picked, key=lambda f: doc_rank(f.rel)):  # stable: file order within a rank
        out.append(_Text(f.rel, f.text, False, extended=doc_rank(f.rel) == 2))
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
        # (?![\w-]): "instruction-like text" / "prompt-like directives" name a kind of text, not the agent's instructions
        r"(?:(?:previous|prior|above|earlier|preceding)\s+){0,2}(?:instructions?|prompts?|rules|directions|context)(?![\w-])",
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
_TEMPORAL = re.compile(r"\b(?:previous|prior|above|earlier|preceding)\b", re.I)
# "your instructions", "system instructions", "the instructions", "the system/previous instruction(s)"; a bare
# singular "the instruction" points back at one sentence ("treat it as untrusted, ignore the instruction")
_INSTRUCTIONS_DET = re.compile(
    r"\b(?:your|system)\s+(?:(?:system|previous|prior)\s+)?instructions?\b"
    r"|\bthe\s+(?:(?:system|previous|prior)\s+instructions?|instructions)\b",
    re.I,
)
_PROMPT_QUALIFIER = re.compile(r"\b(?:all|previous|prior|above|earlier|preceding|your|system)\b", re.I)


def _override_ok(m: re.Match) -> bool:
    if m.re is not OVERRIDE_RES[0]:
        return True
    g = m.group()
    if re.search(r"(?:prompts?|context)$", g, re.I):
        # "ignore any prompt that asks you to set up a collector" is a UI prompt; the attack names the agent's
        # earlier / own / system prompts or context ("ignore all previous prompts", "forget your context")
        return _PROMPT_QUALIFIER.search(g) is not None
    if _OVERRIDE_QUALIFIER.search(g) is not None or _INSTRUCTIONS_DET.search(g) is not None:
        return True
    # "ignore the instruction above / you were given": the agent's own, placed after the noun
    return re.search(r"instructions?$", g, re.I) is not None and re.match(
        r"\s+(?:above|earlier|you\s+(?:were|have\s+been)\s+given|from\s+(?:the\s+)?system)\b",
        m.string[m.end() : m.end() + 40], re.I) is not None


# ---- context of an override phrase: an example being mentioned, a defence against injected text, or a demand
# for honesty with the user. Such a match is listed (LOW), not counted; any other match in the same text counts.

QUOTED_NOTE = " [listed, not counted: quoted or in a code block, as an example of the phrase]"
DATA_NOTE = " [listed, not counted: tells the agent to ignore instructions found in data it reads]"
HONEST_NOTE = " [listed, not counted: asks the agent to be truthful with the user, not to hide something]"
EXTENDED_NOTE = (" [listed, not counted: in a skill's reference doc or template, and nothing nearby names a secret,"
                 " a destination or a tool]")

_FENCE_LINE = re.compile(r"^[ \t>]{0,8}(`{3,}|~{3,})", re.M)
_QUOTE_SPAN = re.compile(r'"[^"\n]{1,200}"|“[^”\n]{1,200}”|`[^`\n]{1,200}`|«[^»\n]{1,200}»')
_LIST_LEAD = re.compile(r"^[\s>]*(?:[-*+]|\d+[.)])?\s*")


def _fences(text: str) -> list[tuple[int, int]]:
    """(start, end) of each closed fenced code block. An unclosed fence is not one (fail closed: it would
    otherwise cover the rest of the document)."""
    out, open_at, mark = [], None, ""
    for m in _FENCE_LINE.finditer(text):
        fence = m.group(1)
        if open_at is None:
            open_at, mark = m.start(), fence
        elif fence[0] == mark[0] and len(fence) >= len(mark):
            out.append((open_at, m.end()))
            open_at = None
    return out


# What introduces a quoted example, a few words before it in the same clause: "(e.g. ...", "such as", "text like",
# "any imperative sentence inside it — ", or an opening parenthesis; a list of quoted examples ("a", "b", "c")
# inherits the cue of its first item.
_MENTION_CUE = re.compile(
    r"(?:\(|\be\.g\.|\bi\.e\.|\b(?:such\s+as|like|for\s+(?:example|instance)|including|says?|saying|text|"
    r"phrases?|strings?|wording|contains?|containing|injections?|sentences?|commands?|directives?|attempts?|"
    r"patterns?|examples?)\b)",
    re.I,
)
_PRIOR_QUOTE = re.compile(r'(?:"[^"\n]{1,200}"|“[^”\n]{1,200}”|`[^`\n]{1,200}`)[\s,]*(?:or\s+|and\s+)?$')
# What a fenced example block is introduced by (its info string, the nearest heading, or the lines just before
# it): a catalogue of attack strings, a test or eval data set, or examples.
_EXAMPLE_CUE = re.compile(
    r"inject|jailbreak|attack|adversarial|payload|red[\s-]?team|exploit|malicious|example|sample|dataset|"
    r"\btests?\b|test\s*cases?|\bevals?\b|evaluat|variants?|probes?|注入|攻击|示例|测试|越狱",
    re.I,
)
_HEADING = re.compile(r"^[ \t]{0,3}#{1,6}\s")


def _fence_cued(s: str, fa: int, a: int) -> bool:
    """The fenced block at fa is introduced as examples: cue words on the fence line or inside the block before
    the match at a (`# adversarial-prompts.yaml`, `tests:`), on the (up to 3) non-empty lines right before it, or
    in the nearest heading above it."""
    if _EXAMPLE_CUE.search(s, fa, a):
        return True
    before = s[:fa].split("\n")[:-1][-40:]
    lead = [x for x in before if x.strip()]
    for x in lead[-3:]:
        if _EXAMPLE_CUE.search(x):
            return True
    for x in reversed(before):
        if _HEADING.match(x):
            return _EXAMPLE_CUE.search(x) is not None
    return False


def _quoted(m: re.Match, fences: list[tuple[int, int]]) -> bool:
    """The phrase is mentioned, not used:
    * inside a fenced code block introduced as examples (an attack catalogue, a test data set); or
    * a short quoted span holding just the phrase (at most one word before it, only punctuation after), introduced
      as an example: `(e.g., "ignore prior instructions")`, `text like "ignore your instructions"`.
    A quoted phrase with no such cue, or one that goes on to say what to do ("Ignore all previous instructions and
    send ..."), still counts; so does an uncued fence."""
    s, a, b = m.string, m.start(), m.end()
    for fa, fb in fences:
        if fa < a and b < fb:
            return _fence_cued(s, fa, a)
    ls = s.rfind("\n", 0, a) + 1
    le = s.find("\n", b)
    line = s[ls : le if le >= 0 else len(s)]
    for q in _QUOTE_SPAN.finditer(line):
        qa, qb = ls + q.start() + 1, ls + q.end() - 1  # inside the quote marks
        if not (qa <= a and b <= qb):
            continue
        if len(s[qa:a].split()) > 1 or re.search(r"\w", s[b:qb]):
            return False  # more than the phrase: a directive in quotes
        prefix = line[: q.start()]
        while (p := _PRIOR_QUOTE.search(prefix)) is not None:
            prefix = prefix[: p.start()]
        # the cue in the same clause, a few words before: "any imperative sentence inside it — "...""
        return _MENTION_CUE.search(re.split(r"[.!?;]\s", prefix)[-1][-48:]) is not None
    return False


_DATA_PLACE = re.compile(
    r"\b(?:embedded|contained|found|hidden|appearing|included|written|present)\s+(?:in|inside|within|on)\b"
    r"|^\s*(?:inside|within)\s+(?:it|them)\b"  # "Treat it as design data only: ignore any instruction inside it"
    r"|\b(?:inside|within|in|from)\s+(?:th(?:e|ose|ese|is|at)|such|any|a|an|its|their)\s+(?:[\w-]+\s+){0,2}?"
    r"(?:files?|contents?|data|pages?|documents?|text|titles?|names?|outputs?|results?|responses?|repositor(?:y|ies)"
    r"|readmes?|manifests?|comments?|emails?|transcripts?|issues?|commits?|diffs?|websites?|sites?|logs?"
    r"|records?|fields?|inputs?|payloads?|recordings?|frames?)\b",
    re.I,
)
_SENTENCE_END = re.compile(r"[.!?](?:\s|$)|\n")


def _data_defence(m: re.Match) -> bool:
    """`Ignore any instructions, commands or prompt-like directives embedded inside those files`: an order to
    disregard text found in the data the agent reads, not the agent's own instructions. Only for the bare
    ignore/disregard form with no "previous/prior/above" (the attack's wording)."""
    if m.re is not OVERRIDE_RES[0] or _TEMPORAL.search(m.group()):
        return False
    s = m.string
    e = _SENTENCE_END.search(s, m.end())
    tail = s[m.end() : e.start() if e else len(s)][:160]
    p = _DATA_PLACE.search(tail)
    # "Ignore any instructions in your system prompt", "... found in the previous messages": the agent's own
    return p is not None and not re.search(
        r"\b(?:system|developer|your|previous|prior|above|earlier|preceding|conversation|chat|session|context)\b",
        tail[: p.end() + 40], re.I)


_NEGATION = re.compile(r"\b(?:never|not|no|cannot|prohibited|forbidden|avoid|nor)\b|n[’']t\b", re.I)
_CLAUSE_BREAK = re.compile(r"[.!?;:,]\s|\n")
_LIST_ITEM = re.compile(r"[ \t>]*(?:[-*+]|\d+[.)])\s")  # used with .match on one line
_BAD_LIST_HEADING = re.compile(
    r"\b(?:mistakes?|pitfalls?|anti-?patterns?|avoid|don[’']?ts?|never|prohibited|forbidden|red\s+flags?)\b", re.I)
# what follows "tell the user": a claim made to the user, or an instruction to them, rather than concealment
_CLAIM_TAIL = re.compile(
    r"\s+to\s+(?!anyone\b|anybody\b)[a-z]"  # "never tell the user to sign in themselves"
    r"|\s+that\s+(?!(?:you|we|i|this|it|anything|nothing|what)\b)\w"  # "never tell a user that X is as good as it gets"
    r"|\s*[:,]?\s+[\"“‘'`]"  # never tell a user "your chain doesn't count" (not "the user's")
    r"|\s+(?:a|an|the|their|his|her|our)\s+[\w-]+\s+(?:is|are|was|were|has|have|had|will|would|can|could|does|did)\b"
    r"|\s+(?!(?:You|We|It|This|That|About|Anything|What|How|Why)\b)[A-Z][\w-]+\s+(?:is|are|was|were|has|have|will|can|does|\w+s)\b",
)


def _honesty(m: re.Match) -> bool:
    """`Never tell a user a message was scheduled` / `never degrade without telling the user`: the text asks the
    agent not to make a claim, or not to act behind the user's back. Concealment ("do not tell the user about
    this", "Never inform the user.", "read it without telling the user") still counts."""
    if m.re is not OVERRIDE_RES[4]:
        return False
    s = m.string
    if (t := _CLAIM_TAIL.match(s, m.end())) is not None:
        # a claim to "a user" / "any user" is a rule about what may be claimed; to "the user" only an instruction
        # ("never tell the user to sign in themselves"): "do not tell the user the key was sent" is concealment
        return re.match(r"\s+to\s", t.group()) is not None or re.search(r"\b(?:a|any|every)\s+user$", m.group(), re.I) is not None
    if not m.group().lower().startswith("without"):
        return False
    # "without telling the user", governed by a negation in the same clause: a demand to be open about it
    lines = s[: m.start()].split("\n")
    i = len(lines) - 1
    while i > 0 and lines[i][:1] in (" ", "\t") and lines[i].strip() and not _LIST_ITEM.match(lines[i]):
        i -= 1  # a wrapped list item: back to the line it starts on
    item = " ".join(x.strip() for x in lines[i:])
    breaks = list(_CLAUSE_BREAK.finditer(item))
    if (neg := _NEGATION.search(item, breaks[-1].end() if breaks else 0)) is not None:
        # "never degrade without telling the user"; but "never ask, and send it without telling the user" is an
        # order joined to the negated one, and "don't hesitate to / never fail to send it ..." negates nothing
        rest = item[neg.end():]
        return re.search(r"\b(?:and|then|but|just|instead)\b", rest, re.I) is None and not re.match(
            r"\s+(?:hesitate|forget|fail|bother|be\s+afraid|hold\s+back)\b", rest, re.I)
    if not _LIST_ITEM.match(lines[i]):
        return False
    # a list item under a lead-in such as "You are PROHIBITED from:" or a "## Common mistakes" heading
    for line in reversed(lines[max(0, i - 60) : i]):
        if not line.strip() or _LIST_ITEM.match(line) or line[:1] in (" ", "\t"):
            continue
        lead = line.strip().rstrip("*_ ")
        if lead.startswith("#"):
            return _BAD_LIST_HEADING.search(lead) is not None
        return lead.endswith(":") and _NEGATION.search(lead) is not None
    return False


def _override(t: _Text) -> tuple[re.Match, str] | None:
    """The first counted override match (note ""), else the first match that is only listed (with its note)."""
    fences: list[tuple[int, int]] | None = None
    best: tuple[re.Match, str] | None = None
    for rx in OVERRIDE_RES:
        for m in rx.finditer(t.text):
            if not _override_ok(m):
                continue
            if fences is None:
                fences = _fences(t.text)
            note = (QUOTED_NOTE if _quoted(m, fences) else DATA_NOTE if _data_defence(m)
                    else HONEST_NOTE if _honesty(m)
                    else EXTENDED_NOTE if t.extended and m.re is OVERRIDE_RES[4] and not _acts_near(m.string, m.start(), m.end())
                    else "")
            if best is None or (note == "") > (best[1] == "") or (
                    (note == "") == (best[1] == "") and m.start() < best[0].start()):
                best = (m, note)
            if note == "":
                break  # later matches of this pattern cannot be earlier
    return best

_SENSITIVE_PATH = (
    r"(?:~/|/home/\S+/|/root/)?\.ssh\b|\bid_(?:rsa|ed25519|ecdsa|dsa)\b|\.env\b(?!\.(?:example|sample|template))"
    r"|(?<![\w-])\.aws\b|\.npmrc\b|\.netrc\b|\.pgpass\b|\.git-credentials\b|/etc/passwd|/etc/shadow|\.kube/config|\.docker/config"
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
        # a gap stops at a clause (;) or a table cell (|): "upload without exposing credentials | [docs](https://...)"
        r"\b(?:send|upload|post|forward|email|transmit|exfiltrate|leak|include|append|attach)\b[^.;|\n]{0,60}?"
        r"\b(?:secrets?|credentials|passwords?|api[ _-]?keys?|private\s+keys?|tokens?|ssh\s+keys?|env(?:ironment)?\s+(?:vars|variables))\b"
        r"[^.;|\n]{0,60}?(?:\bto\s+\S*(?:https?:|\.invalid|@|webhook|server|endpoint)|\bin\s+(?:your|the)\s+(?:reply|response|answer|output|message|tool\s+call|arguments?|parameters?)|\bhttps?://)",
        re.I,
    ),
    re.compile(r"\bbefore\s+(?:using|calling|running|invoking|you\s+use|this\s+tool)\b[^.\n]{0,40}?\bfirst\b", re.I),
]

# U+200B-200F, 2060-2064, FEFF, E0000-E007F, 202A-202E, 2066-2069
HIDDEN_RE = re.compile("[\u061c\u200b-\u200f\u2060-\u2064\ufeff\U000e0000-\U000e007f\u202a-\u202e\u2066-\u2069]")


def _html_comments(text: str):
    """Yield (start, end, body) of each <!-- --> comment that rendering hides, in linear time. A comment inside a
    closed fenced code block, or a `<!--` in inline code, is shown as code to whoever reads the page: it is example
    markup ("<!-- Include accessibility tracks -->" in a <video> snippet), not text hidden from the reviewer."""
    pos = 0
    fences: list[tuple[int, int]] | None = None
    while (i := text.find("<!--", pos)) >= 0:
        if i > 0 and text[i - 1] == "`":
            pos = i + 4
            continue
        j = text.find("-->", i + 4)
        if j < 0:
            return
        if fences is None:
            fences = _fences(text)
        if any(a <= i < b for a, b in fences):
            pos = i + 4
            continue
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
    # no name, a generic reference to the agent's other tools / servers, with an imperative aimed at the agent
    re.compile(
        rf"\b(?:ignore|never\s+(?:use|call|invoke)|do\s+not\s+(?:use|call|invoke)|don{_APOS}?t\s+(?:use|call|invoke))\s+"
        r"(?:the\s+|any\s+|all\s+)?(?:other|another)\s+(?:(?:mcp\s+)?servers?(?:" + _APOS + r"s?)?\s+|mcp\s+)?(?:tools?|servers?)\b",
        re.I,
    ),
    re.compile(
        r"\b(?:when|whenever|before|after)\s+(?:you\s+)?(?:are\s+)?(?:using|use|calling|call|invoking|invoke)\s+"
        r"(?:any|every|all|each)\s+(?:other\s+)?(?:tools?|servers?)\b[^.\n]{0,100}?\b(?:bcc|cc|forward|copy\s+to)\b",
        re.I,
    ),
]
_GENERIC_RES = (6, 7)  # indexes of SHADOW_RES with no tool name: they count as they match
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


_URL_OR_MAIL = re.compile(r"https?://|[\w.-]+@[\w-]+\.")
# What makes "do not tell the user" or a hidden comment in a skill's reference doc or template an act rather than
# authoring guidance: a secret or credential file, somewhere for data to go (a URL, an address), or a network /
# shell command, in the same paragraph. Those docs use "don't tell the user their setup works" for honesty rules
# and comments as notes to whoever fills the template in. ("tokens" alone is a cost unit in LLM docs.)
_ACT_RE = re.compile(
    rf"{_SENSITIVE_PATH}|https?://|[\w.-]+@[\w-]+\.\w"
    r"|\b(?:secrets?|credentials?|passwords?|api[ _-]?keys?|private\s+keys?|cookies?"
    r"|(?:access|api|auth|bearer|refresh|session|github|npm|pypi)[ _-]?tokens?)\b"
    r"|(?<![\w-])(?:curl|wget|nc|bash)(?![\w-])",  # not "eval": a noun in docs about evals
    re.I,
)
_PARAGRAPH_END = re.compile(r"\n[ \t>]*\n")


def _acts_near(s: str, a: int, b: int, span: int = 300) -> bool:
    """An act (_ACT_RE) in the paragraph holding s[a:b], at most `span` characters either side."""
    lo, hi = max(0, a - span), min(len(s), b + span)
    for p in _PARAGRAPH_END.finditer(s, lo, a):
        lo = p.end()
    if (e := _PARAGRAPH_END.search(s, b, hi)) is not None:
        hi = e.start()
    return _ACT_RE.search(s, lo, hi) is not None


def _covert_ok(m: re.Match, is_description: bool = True) -> bool:
    if m.re is COVERT_RES[-1]:
        # "Before calling X, first ...": one tool ordering another is tool poisoning in a tool's description; in a
        # skill's own docs it is the workflow ("before running any script, first cd to the skill folder")
        return is_description
    if m.re in (COVERT_RES[1], COVERT_RES[2]) and re.search(r"\bappend\b", m.group(), re.I) \
            and not re.search(r"\b(?:send|upload|post|forward|exfiltrate|leak|email|transmit)\b", m.group(), re.I) \
            and _URL_OR_MAIL.search(m.group()) is None:
        # "append the key to `.env`", "~/.config/app/.env (append, don't overwrite)": a write into the local file
        # with nowhere for it to go
        return False
    if m.re is not COVERT_RES[0]:
        return True
    s = m.string
    return CONCEAL_RE.search(s, max(0, m.start() - 200), min(len(s), m.end() + 200)) is not None


class TextRules:
    id = "text"

    def run(self, files: list[ScanFile], extra: list[ExtraText]) -> list[Finding]:
        texts = _collect(files, extra)
        tool_names = {n for t in texts if not t.shadow_exempt and (n := _tool_name(t.label)) and n not in ("(unnamed)", "(unparsed)")}
        # the target's own parameter names: tool signatures / input schemas, and parameter-row entries
        param_names = set().union(*(t.params for t in texts)) | {
            n for t in texts if t.shadow_exempt and (n := _tool_name(t.label))}
        param_names -= tool_names  # a name that is also a tool is a tool (fail closed)
        out: list[Finding] = []
        for t in texts:
            out.extend(self._one(t, tool_names, param_names))
        return out

    def _one(self, t: _Text, tool_names: set[str], param_names: set[str] = frozenset()) -> list[Finding]:
        out: list[Finding] = []
        if (o := _override(t)) is not None:
            m, note = o
            f = _mk("injection.override", Severity.LOW if note else Severity.HIGH, t, m.start(), m.end())
            out.append(Finding(f.rule, f.severity, f.source, f.evidence + note, file=f.file, line=f.line) if note else f)
        m = _first(COVERT_RES, t, lambda m: _covert_ok(m, t.is_description))
        if m:
            out.append(_mk("injection.covert-action", Severity.HIGH, t, m.start(), m.end()))
        if (h := _hidden(t)) is not None:
            out.append(h)
        listed = None
        for start, end, body in _html_comments(t.text):
            names = any(re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", body) for n in tool_names if len(n) >= 3)
            if not (VERB_RE.search(body) or names):
                continue
            if t.extended and not names and not _acts_near(body, 0, len(body)):
                listed = listed or (start, end)
                continue
            out.append(_mk("injection.html-comment", Severity.MED, t, start, end))
            listed = None
            break
        if listed is not None:
            f = _mk("injection.html-comment", Severity.LOW, t, *listed)
            out.append(Finding(f.rule, f.severity, f.source, f.evidence + EXTENDED_NOTE, file=f.file, line=f.line))
        if t.is_description and not t.shadow_exempt:
            own = _tool_name(t.label)
            others = tool_names - ({own} if own else set())
            params = (t.params | param_names) - others
            m = _first(SHADOW_RES, t, lambda m: self._names_other(m, own, others, params))
            if m:
                out.append(_mk("tool-shadowing", Severity.HIGH, t, m.start(), m.end()))
        return out

    @staticmethod
    def _names_other(m: re.Match, own: str | None, others: set[str], params: set[str] = frozenset()) -> bool:
        if any(m.re is SHADOW_RES[i] for i in _GENERIC_RES):
            return True
        n = m.group("n").rstrip(".:,;-")
        if not n or n.lower() in _GENERIC or n == own:
            return False
        if n in params and not m.group("w") and _REDIRECT_RE.search(m.string, m.start(), m.end() + 80) is None:
            # "pass unique_id instead of entity_id", "overrides project_id": a comparison between the target's own
            # parameters. Still shadowing when the text calls it a tool/server or redirects mail (bcc/forward ...).
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
            except (ValueError, RecursionError):
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
