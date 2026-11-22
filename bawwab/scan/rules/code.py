"""Static code and manifest rules: AST detectors (Python, JS/TS) plus a regex fallback."""
from __future__ import annotations

import ast
import base64
import binascii
import io
import json
import re
import threading
import tokenize
import tomllib
from bisect import bisect_right
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from posixpath import dirname, join, normpath

from bawwab.scan.files import ExtraText, ScanFile
from bawwab.scan.rules import bundle, dropper, envflow, parsing, proximity
from bawwab.types import Finding, Severity

PY_EXT = (".py",)
JS_EXT = (".js", ".mjs", ".cjs", ".jsx")
TS_EXT = (".ts", ".mts", ".cts", ".tsx")
DOC_EXT = (".md", ".mdx", ".rst", ".txt", ".map")
LOCKFILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "npm-shrinkwrap.json",
    "poetry.lock", "uv.lock", "Pipfile.lock", "Cargo.lock", "composer.lock",
}
INSTALL_KEYS = ("preinstall", "install", "postinstall", "prepare")


def _base(rel: str) -> str:
    return rel.rsplit("/", 1)[-1]


# Python package metadata (sdist PKG-INFO, wheel METADATA, everything in *.dist-info/ or *.egg-info/ that is not
# itself code): prose and manifests that nothing executes. PKG-INFO quotes the README, so code patterns there are
# words, not behaviour (requests' "honoring of `.netrc`" read as a credential read next to `requests.get`).
PKG_METADATA_BASES = {"PKG-INFO", "METADATA"}
_PKG_METADATA_DIR_RE = re.compile(r"(?:^|/)[^/]+\.(?:dist|egg)-info/")


def _is_pkg_metadata(rel: str) -> bool:
    if rel.endswith(PY_EXT + JS_EXT + TS_EXT + (".pyw", ".pth", ".sh")):
        return False
    return _base(rel) in PKG_METADATA_BASES or bool(_PKG_METADATA_DIR_RE.search(rel))


def _is_doc(rel: str) -> bool:
    return rel.endswith(DOC_EXT) or _is_pkg_metadata(rel)


# Data and tool-config files: not code, so code rules do not read them (R26a).
DATA_EXT = (".csv", ".tsv")
IGNORE_FILES = {".gitignore", ".npmignore", ".eslintignore", ".prettierignore", ".dockerignore"}
CONFIG_RE = re.compile(
    r"^(?:eslint\.config\.[\w.]+|\.eslintrc(?:\.[\w.]+)?|\.?prettier(?:rc)?(?:\.config)?(?:\.[\w.]+)?"
    r"|tsconfig(?:\.[\w.-]+)?\.json|jsconfig(?:\.[\w.-]+)?\.json|biome\.jsonc?)$"
)
DATA_DIR_RE = re.compile(r"(?:^|/)(?:data|fixtures|__fixtures__)/")
# Test code (R26b): findings downgraded to low unless the file runs at install time or from runtime code.
TEST_PATH_RE = re.compile(
    r"(?:^|/)(?:test|tests|__tests__|spec|fixtures|__fixtures__)/"
    r"|(?:^|/)[^/]+\.(?:test|spec)\.[\w]+$|(?:^|/)test_[^/]*\.py$|(?:^|/)[^/]*_test\.py$|(?:^|/)conftest\.py$"
)


EXEC_EXT = PY_EXT + JS_EXT + TS_EXT


def _is_config_code(rel: str) -> bool:
    """A lint/format config written as code (eslint.config.mjs, .prettierrc.js): scanned, exempt-like (R27 C2)."""
    return rel.endswith(EXEC_EXT) and bool(CONFIG_RE.match(_base(rel)))


def _is_data(rel: str) -> bool:
    """Data, ignore files and JSON configs: not code; scanned only when something executes them (R27 C2)."""
    base = _base(rel)
    if rel.endswith(EXEC_EXT):
        return False
    if rel.endswith(DATA_EXT) or base in IGNORE_FILES or CONFIG_RE.match(base):
        return True
    return rel.endswith(".json") and bool(DATA_DIR_RE.search(rel))


def _is_test(rel: str) -> bool:
    return bool(TEST_PATH_RE.search(rel))


def _is_code(rel: str) -> bool:
    return not _is_doc(rel) and _base(rel) not in LOCKFILES and not _is_data(rel)


def _custom_index(raw: str) -> tuple[int, str] | None:
    """(position, url) of the first non-PyPI package source in an install command or an index variable."""
    foreign = _foreign_url
    for m in PIP_CMD_RE.finditer(raw):
        seg = raw[m.end():m.end() + 400]
        end = _SEGMENT_END_RE.search(seg)
        seg = seg[:end.start()] if end else seg
        for u in PIP_URL_RE.finditer(seg):
            if foreign(u.group(1)):
                return m.start(), u.group(1)
    for m in INDEX_ENV_RE.finditer(raw):
        if foreign(m.group(1)):
            return m.start(), m.group(1)
    return None


REQ_FILE_RE = re.compile(r"(?:requirements|constraints)[\w.-]*\.txt")
INDEX_CONF_FILES = {"pip.conf", "pip.ini", "uv.toml"}
# pip honours these option lines inside a requirements/constraints file
REQ_INDEX_RE = re.compile(r"^[ \t]*(?:--index-url|--extra-index-url|--find-links|-i|-f)(?:[ \t]*=[ \t]*|[ \t]+)(\S+)", re.M)
CONF_INDEX_RE = re.compile(r"^[ \t]*(?:index-url|extra-index-url|find-links)[ \t]*[=:]", re.M)
_CONF_VALUE_END_RE = re.compile(r"\n(?=(?:[\w.-]+[ \t]*[=:]|\[|#|;))")


def _foreign_url(url: str) -> bool:
    from urllib.parse import urlsplit

    try:
        return urlsplit(url).hostname not in PYPI_HOSTS
    except ValueError:
        return True


def _config_index(rel: str, raw: str) -> tuple[int, str] | None:
    """(position, url) of a non-PyPI package source set by a shipped requirements/constraints file or a
    pip.conf/pip.ini/uv.toml (fix round 4, M13). Only http(s) URLs count; a local find-links dir does not."""
    base = _base(rel)
    if REQ_FILE_RE.fullmatch(base):
        for m in REQ_INDEX_RE.finditer(raw):
            u = PIP_URL_RE.match(m.group(1))
            if u and _foreign_url(u.group(1)):
                return m.start(), u.group(1)
    elif base in INDEX_CONF_FILES:
        for m in CONF_INDEX_RE.finditer(raw):
            seg = raw[m.end():m.end() + 2000]
            end = _CONF_VALUE_END_RE.search(seg)
            for u in PIP_URL_RE.finditer(seg[:end.start()] if end else seg):
                if _foreign_url(u.group(1)):
                    return m.start(), u.group(1)
    if base in ("uv.toml", "pyproject.toml"):
        return _uv_index(raw, base == "uv.toml")
    return None


_UV_INDEX_HEADER_RE = re.compile(r"^[ \t]*\[\[[ \t]*(?:tool\.uv\.)?index[ \t]*\]\][ \t]*$", re.M)
_TABLE_HEADER_RE = re.compile(r"^[ \t]*\[", re.M)
_URL_KEY_RE = re.compile(r"^[ \t]*url[ \t]*=", re.M)


def _uv_index(raw: str, uv_toml: bool) -> tuple[int, str] | None:
    """(position, url) of a non-PyPI uv index (M16): uv.toml `[[index]] url = …` or pyproject.toml
    `[[tool.uv.index]] url = …`, and `[tool.uv]` index-url/extra-index-url/find-links in pyproject.toml.
    Read with tomllib; a file it can't parse falls back to the `[[index]]` tables' url lines."""
    import tomllib

    urls: list[str] = []
    try:
        data = tomllib.loads(raw)
    except (tomllib.TOMLDecodeError, ValueError):
        data = None
    if data is not None:
        uv = data if uv_toml else data.get("tool", {}).get("uv", {}) if isinstance(data.get("tool"), dict) else {}
        if not isinstance(uv, dict):
            return None
        for sect in (uv, uv.get("pip") if isinstance(uv.get("pip"), dict) else {}):
            idx = sect.get("index")
            for e in idx if isinstance(idx, list) else []:
                if isinstance(e, dict) and isinstance(e.get("url"), str):
                    urls.append(e["url"])
            if not uv_toml or sect is not uv:  # uv.toml's top-level legacy keys are read above
                for k in ("index-url", "extra-index-url", "find-links"):
                    v = sect.get(k)
                    urls += [v] if isinstance(v, str) else [x for x in v if isinstance(x, str)] if isinstance(v, list) else []
    else:
        for h in _UV_INDEX_HEADER_RE.finditer(raw):
            nxt = _TABLE_HEADER_RE.search(raw, h.end())
            body = raw[h.end():nxt.start() if nxt else len(raw)]
            for m in _URL_KEY_RE.finditer(body):
                u = PIP_URL_RE.search(body, m.end())
                if u:
                    urls.append(u.group(1))
    for url in urls:
        u = PIP_URL_RE.match(url.strip())
        if u and _foreign_url(u.group(1)):
            pos = raw.find(url)
            return max(pos, 0), u.group(1)
    return None


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


def _line_text(text: str, line: int) -> str:
    lines = text.splitlines()
    return lines[line - 1].strip()[:200] if 0 < line <= len(lines) else ""


def _finding(rule: str, sev: Severity, f: ScanFile, line: int | None, evidence: str | None = None) -> Finding:
    if evidence is None:
        evidence = _line_text(f.text, line) if line else ""
    return Finding(rule, sev, "static", evidence, file=f.rel, line=line)


# ---------------------------------------------------------------- call extraction


@dataclass(frozen=True)
class Call:
    line: int
    callee: str
    args: str  # source text of the arguments, with simple variable resolution appended
    first: str = ""  # the first argument only (the evaluated code for eval/exec/vm.*), resolved the same way
    first_raw: str = ""  # the first argument's source text, unresolved
    args_raw: str = ""  # all arguments' source text, unresolved
    pos: int = -1  # UTF-8 byte offset of the call in the file (proximity in bundles); -1 unknown


_IDENT_RE = re.compile(r"[A-Za-z_$][\w$]*")

# Memory budget for the text kept on parsed calls (argument source plus resolved variable values).
# Nested calls repeat their arguments' source, and resolution appends a variable's whole value to every
# call that names it: a bundle binds each module body to a name (`var require_x = __commonJS(...)`), so a
# 15 MB bundle grew to gigabytes (@sveltejs/mcp 0.1.31 needed > 5 GB). Costs are charged before any text
# is built. Three tiers, and no call is ever dropped while the scan pool lasts (fix round 1, C1):
# - full: source text and resolved values, while the file's budget allows;
# - degraded: past it, a call keeps its argument text capped (DEGRADED_CAP, then DEGRADED_CAP_MIN) and is
#   not resolved. Every call is still analysed: LOW files.analysis-degraded (I3);
# - spent: the scan pool cannot hold even degraded calls. The file takes the regex fallback (as an
#   unparseable file does) and gets MED files.truncated: content really went unanalysed.
CALL_OVERHEAD = 256  # bytes charged per call for the object itself
CALL_TEXT_FACTOR = 16  # full text per file: CALL_TEXT_FACTOR x the file size + CALL_TEXT_FLOOR
CALL_TEXT_FLOOR = 64_000_000
SCAN_CALL_TEXT_BUDGET = 512_000_000  # per scan (run_static_rules), full and degraded text, across files
DEGRADED_CAP = 4096  # argument text kept per degraded call (head and tail)
DEGRADED_CAP_MIN = 256  # once a file's degraded text passes DEGRADED_FILE_POOL
DEGRADED_FILE_POOL = 32_000_000
# Sink calls (eval, exec, shells, loaders...) stay fully analysed in degraded mode (fix round 2, R1-C1): their
# text is kept uncapped and their arguments resolved from this reserve, beyond the full-text budget. A sink
# the reserve cannot cover gives MED files.truncated "sink call not fully analysed".
SINK_RESERVE = 32_000_000


class _Spent(Exception):
    """The scan's pool cannot hold this file's calls, even degraded."""


class _FileBudget:
    def __init__(self, full: int, hard: int):
        self.full, self.hard = full, hard  # full-text allowance; everything kept (full + degraded)
        self.used = 0
        self.degraded_used = 0
        self.sink_used = 0
        self.over = False
        self.sink_incomplete = False

    def take(self, n: int) -> bool:
        """Full text (source or resolved values) of n bytes, if the file's budget allows."""
        if self.used + n > min(self.full, self.hard):
            self.over = True
            return False
        self.used += n
        return True

    def take_sink(self, n: int) -> bool:
        """Text for a sink call, from the full budget or else the reserved slice."""
        if self.take(n):
            return True
        if self.sink_used + n > SINK_RESERVE or self.used + n > self.hard:
            self.sink_incomplete = True
            return False
        self.used += n
        self.sink_used += n
        return True

    def take_degraded(self, n: int) -> None:
        self.over = True
        if self.used + n > self.hard:
            raise _Spent
        self.used += n
        self.degraded_used += n

    @property
    def cap(self) -> int:
        return DEGRADED_CAP if self.degraded_used < DEGRADED_FILE_POOL else DEGRADED_CAP_MIN



class _ScanState(threading.local):
    budget: _FileBudget | None = None

    def __init__(self):
        self.charged: dict[tuple, int] = {}  # (rel, text hash, size) -> bytes charged to the scan
        self.spent: set[tuple] = set()  # files whose calls the pool could not hold


_SCAN = _ScanState()
_NO_LIMIT = 1 << 62


def _file_budget(size: int, key: tuple) -> _FileBudget:
    full = CALL_TEXT_FACTOR * size + CALL_TEXT_FLOOR
    scan = _SCAN.budget
    if scan is None:
        return _FileBudget(full, _NO_LIMIT)
    return _FileBudget(full, max(scan.hard - scan.used + _SCAN.charged.get(key, 0), 0))


def _charge_scan(key: tuple, used: int) -> None:
    """Charge a file's call text to the scan once (a cache eviction recomputes it, never double charges)."""
    if _SCAN.budget is not None and key not in _SCAN.charged:
        _SCAN.charged[key] = used
        _SCAN.budget.used += used


def begin_scan() -> None:
    """Start a scan's call-text pool; caches from an earlier scan are dropped (they hold its texts)."""
    clear_caches()
    _SCAN.budget = _FileBudget(SCAN_CALL_TEXT_BUDGET, SCAN_CALL_TEXT_BUDGET)
    _SCAN.charged = {}
    _SCAN.spent = set()


def end_scan() -> None:
    _SCAN.budget = None
    _SCAN.charged = {}
    _SCAN.spent = set()
    clear_caches()


def clear_caches() -> None:
    """Drop every per-text cache in this module (they hold file texts and parsed calls)."""
    for v in list(globals().values()):
        if callable(getattr(v, "cache_clear", None)) and getattr(v, "__module__", None) == __name__:
            v.cache_clear()
    bundle.is_bundle.cache_clear()
    proximity._index.cache_clear()
    parsing.clear()


class _Calls(tuple):
    """Parsed calls; `over` is True when the full-text budget ran out (some calls degraded);
    `sink_incomplete` when a sink call could not be kept or resolved in full even from the reserve."""

    over = False
    sink_incomplete = False


# Sink callees (fix round 2): code or commands run from their arguments. Generic leaves (run, call, load)
# count only with their module, so `fn.call(...)` in a bundle is not a sink.
_SINK_LEAVES = {
    "eval", "exec", "Function", "compile", "__import__", "import_module", "execSync", "execFile", "execFileSync",
    "spawn", "spawnSync", "fork", "system", "popen", "Popen", "check_output", "check_call", "getoutput",
    "getstatusoutput", "runInNewContext", "runInThisContext", "runInContext", "compileFunction",
}
_SINK_QUALIFIED_RE = re.compile(
    r"(?:^|\.)(?:subprocess\.(?:run|call)|os\.(?:exec\w*|spawn\w*)|(?:pickle|cPickle|_pickle|marshal|dill)\.loads?"
    r"|vm\.\w+|importlib\.\w+|runpy\.\w+)$"
)


def _is_sink(callee: str, first: str, first_is_function: bool) -> bool:
    c = callee.strip()
    if len(c) > 200:
        return False
    leaf = c.rsplit(".", 1)[-1]
    if c in EVAL_FUNCS or leaf in _SINK_LEAVES or _SINK_QUALIFIED_RE.search(c):
        return True
    if leaf in ("setTimeout", "setInterval", "setImmediate"):
        return bool(first) and not first_is_function  # a string of code, not a callback
    if c in DYNAMIC_LOADERS or leaf in ("require", "import"):
        return bool(first) and not _LITERAL_ARG_RE.match(first)
    return False


def _over(c) -> bool:
    return bool(getattr(c, "over", False))


def _spent(rel: str, text: str) -> bool:
    return (rel, hash(text), len(text)) in _SCAN.spent


def _capped(s: str, n: int) -> str:
    return s if len(s) <= n else s[: n // 2] + " ... " + s[-(n // 2) :]


class _Resolver:
    """Variable resolution under a budget: `size` is known before a value's text is built."""

    def __init__(self, get, size, budget: _FileBudget, has_names: bool = True):
        self.get, self.size, self.budget, self.has_names = get, size, budget, has_names

    def __call__(self, args: str, sink: bool = False) -> str:
        if not self.has_names:
            return args
        # findall is faster; its list is one str per identifier, so very long text is scanned lazily (M4)
        words = set(_IDENT_RE.findall(args)) if len(args) < 1_000_000 else {m.group() for m in _IDENT_RE.finditer(args)}
        keys = [w for w in words if self.size(w) is not None]
        if not keys:
            return args
        cost = sum(self.size(w) + 1 for w in keys)
        if not (self.budget.take_sink(cost) if sink else self.budget.take(cost)):
            return args  # over budget: kept unresolved (degraded; a sink sets sink_incomplete)
        return " ".join([args, *[self.get(w) for w in keys]])


def _build_calls(raw: list[tuple[int, str, str, str, str, bool, bool, int]], resolve: _Resolver) -> _Calls:
    """Sinks first: their resolution comes from the full budget and then the reserve, before padding calls
    can spend the full budget (R1-C1). The output keeps the extraction order."""
    built: list[Call | None] = [None] * len(raw)
    for pass_sinks in (True, False):
        for i, (line, callee, args, first, args_raw, full, sink, pos) in enumerate(raw):
            if sink != pass_sinks:
                continue
            if full:
                built[i] = Call(line, callee, resolve(args, sink), resolve(resolve(first, sink), sink) if first else "",
                                first, args_raw, pos)
            else:
                built[i] = Call(line, callee, args, first, first, args_raw, pos)
    out = _Calls(built)
    out.over = resolve.budget.over
    out.sink_incomplete = resolve.budget.sink_incomplete
    return out


def _dotted(node) -> str:
    """`a.b.c` for a Name/Attribute chain (no unparse: cheap and bounded), else ""."""
    parts = []
    while isinstance(node, ast.Attribute) and len(parts) < 20:
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
        return ".".join(reversed(parts))
    return ""


_PY_NL_RE = re.compile(rb"\r\n|\r|\n")  # the line split `ast` uses (not str.splitlines: R27 C3, review I1)


def _py_calls(text: str, budget: _FileBudget) -> _Calls | None:
    try:
        tree = parsing.py_parse(text)
    except (SyntaxError, ValueError, RecursionError):
        return None  # hostile, unparseable or too large: caller falls back to regex
    src = text.encode()
    starts = [0] + [m.end() for m in _PY_NL_RE.finditer(src)]  # line starts in UTF-8 bytes, as col_offset

    def span(n) -> tuple[int, int]:
        try:
            a = starts[n.lineno - 1] + n.col_offset
            return a, max(starts[n.end_lineno - 1] + n.end_col_offset, a)
        except (AttributeError, IndexError, TypeError):
            return 0, len(src)

    def size_of(n) -> int:
        a, b = span(n)
        return b - a + 16

    def seg(a: int, b: int, cap: int) -> str:
        if b - a <= cap:
            return src[a:b].decode("utf-8", "replace")
        h = cap // 2
        return src[a : a + h].decode("utf-8", "replace") + " ... " + src[b - h : b].decode("utf-8", "replace")

    def unparse(n, estimate: int) -> str:
        s = ast.unparse(n)
        if len(s) > estimate:  # the estimate is source extent; unparse can be longer: charge the rest
            budget.take(len(s) - estimate)
        return s

    names: dict[str, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            est = size_of(n.value)
            if budget.take(est):
                names[n.targets[0].id] = unparse(n.value, est)
        elif isinstance(n, ast.ImportFrom) and n.module:
            for a in n.names:
                names[a.asname or a.name] = f"{n.module}.{a.name}"
        elif isinstance(n, ast.Import):
            for a in n.names:
                if a.asname:
                    names[a.asname] = a.name
    raw = []
    for n in ast.walk(tree):  # breadth-first: outer calls first
        if not isinstance(n, ast.Call):
            continue
        argn = [*n.args, *n.keywords]
        est = CALL_OVERHEAD + size_of(n.func) + 2 * sum(size_of(a) for a in argn) + (size_of(n.args[0]) if n.args else 0)
        a0 = n.args[0] if n.args else None
        first_hint = (repr(a0.value) if isinstance(a0, ast.Constant) and isinstance(a0.value, str) else "x") if a0 else ""
        sink = _is_sink(_dotted(n.func), first_hint, isinstance(a0, ast.Lambda))
        if budget.take_sink(est) if sink else budget.take(est):
            parts = [unparse(a, size_of(a)) for a in n.args] + \
                [f"{k.arg}={unparse(k.value, size_of(k.value))}" for k in n.keywords]
            first = unparse(n.args[0], size_of(n.args[0])) if n.args else ""
            joined = ", ".join(parts)
            raw.append((n.lineno, unparse(n.func, size_of(n.func)), joined, first, joined, True, sink, span(n)[0]))
            continue
        cap = budget.cap  # degraded: capped source text, unresolved
        callee = seg(*span(n.func), cap)
        joined = seg(span(argn[0])[0], max(span(a)[1] for a in argn), cap) if argn else ""
        first = seg(*span(n.args[0]), cap) if n.args else ""
        budget.take_degraded(CALL_OVERHEAD + len(callee) + 2 * len(joined) + len(first))
        raw.append((n.lineno, callee, joined, first, joined, False, sink, span(n)[0]))
    resolve = _Resolver(names.__getitem__, lambda w: len(names[w]) if w in names else None, budget, bool(names))
    return _build_calls(raw, resolve)


_JS_FUNCTION_NODES = {"arrow_function", "function_expression", "function", "generator_function"}


def _js_lang(rel: str) -> str:
    if rel.endswith(".tsx"):
        return "tsx"
    return "typescript" if rel.endswith(TS_EXT) else "javascript"


def _js_calls(text: str, lang: str, budget: _FileBudget) -> _Calls:
    src = text.encode()

    def txt(a: int, b: int) -> str:
        return src[a:b].decode("utf-8", "replace")

    def capped(sp: tuple[int, int], cap: int) -> str:
        a, b = sp
        if b - a <= cap:
            return txt(a, b)
        return txt(a, a + cap // 2) + " ... " + txt(b - cap // 2, b)

    # Byte spans only while walking: no text is built until the budget allows it.
    names: dict[str, tuple[int, int]] = {}
    found = []
    stack = [parsing.js_root(src, lang)]  # no root reference kept (see _code_info)
    while stack:
        n = stack.pop()
        stack.extend(n.children)
        if n.type == "variable_declarator":
            name, val = n.child_by_field_name("name"), n.child_by_field_name("value")
            if name is not None and val is not None and name.type == "identifier":
                names[txt(name.start_byte, name.end_byte)] = (val.start_byte, val.end_byte)
        elif n.type in ("call_expression", "new_expression"):
            fn = n.child_by_field_name("function" if n.type == "call_expression" else "constructor")
            args = n.child_by_field_name("arguments")
            if fn is not None and args is not None:
                named = next((c for c in args.named_children if c.type != "comment"), None)
                first = (named.start_byte, named.end_byte) if named is not None else (0, 0)
                is_fn = named is not None and named.type in _JS_FUNCTION_NODES
                found.append((n.start_point[0] + 1, (fn.start_byte, fn.end_byte), (args.start_byte, args.end_byte), first,
                              is_fn, n.start_byte))
    del stack
    raw = []
    for line, fn, args, first, is_fn, pos in sorted(found):
        cost = CALL_OVERHEAD + fn[1] - fn[0] + 2 * (args[1] - args[0]) + first[1] - first[0]
        head = capped(fn, 256) if fn[1] - fn[0] > 256 else txt(*fn)
        sink = _is_sink(head, capped(first, 512), is_fn)
        if budget.take_sink(cost) if sink else budget.take(cost):
            a, full = txt(*args), True
            callee, first_s = txt(*fn), txt(*first)
        else:  # degraded: capped text, unresolved; the call is still analysed
            cap = budget.cap
            a, full = capped(args, cap), False
            callee, first_s = capped(fn, cap), capped(first, cap)
            budget.take_degraded(CALL_OVERHEAD + len(callee) + 2 * len(a) + len(first_s))
        raw.append((line, callee, a, first_s, a[1:-1] if a.startswith("(") and a.endswith(")") else a, full, sink, pos))
    del found
    resolve = _Resolver(lambda w: txt(*names[w]), lambda w: names[w][1] - names[w][0] if w in names else None, budget,
                        bool(names))
    return _build_calls(raw, resolve)


@lru_cache(maxsize=512)
def _calls(rel: str, text: str) -> _Calls | None:
    """Parsed calls, or None when the file is not (parseably) Python/JS/TS, is too large to parse, or the
    scan's pool is spent (_spent). `.over`: some calls degraded."""
    if not rel.endswith(PY_EXT + JS_EXT + TS_EXT):
        return None
    key = (rel, hash(text), len(text))
    budget = _file_budget(len(text) if text.isascii() else len(text.encode()), key)
    try:
        out = _py_calls(text, budget) if rel.endswith(PY_EXT) else _js_calls(text, _js_lang(rel), budget)
    except _Spent:
        _SCAN.spent.add(key)
        if _SCAN.budget is not None:  # the pool is closed for the rest of the scan: later files fall back too
            _SCAN.budget.used = _SCAN.budget.hard
        return None
    except MemoryError:
        raise  # the code rule reports it per file (rules.error, MED)
    except Exception:  # noqa: BLE001 - never let a hostile file crash the scan
        return None
    _charge_scan(key, budget.used)
    return out


# ---------------------------------------------------------------- patterns

EVAL_FUNCS = {"eval", "exec", "Function", "window.eval", "globalThis.eval", "vm.runInNewContext", "vm.runInThisContext", "vm.runInContext"}
ALL_ARGS_EVAL = {"Function"}  # new Function(a, b, body): the body is the last argument
# Decoding in the evaluated code (round 3). String literals are emptied first, so
# eval("typeof atob") is not decoding, but decode NAMES count as identifier tokens without
# requiring "(": const d = atob; eval(d(s)) / (0, atob)(s) / atob.call(null, s). Literals whose
# whole body is an encoding or decode-function name are kept, so getattr(base64, 'b64decode') counts.
DECODE_NAMES = (
    "atob", "b64decode", "b32decode", "b16decode", "a85decode", "b85decode", "standard_b64decode",
    "urlsafe_b64decode", "decodebytes", "decodestring", "a2b_base64", "a2b_hex", "unhexlify", "fromhex",
    "rot13", "rot_13",
)
DECODE_RE = re.compile(
    r"\b(?:" + "|".join(DECODE_NAMES) + r")\b|\bcodecs\.decode\b|\bcodecs\.getdecoder\b"
    r"|\.decode\(\s*['\"](?:base64|hex|rot13)",
    re.I,
)
_STR_LIT_RE = re.compile(r"""(['"])(?:\\.|(?!\1)[^\\\n])*\1|`(?:\\.|[^`\\$])*`""")
_ENCODING_NAMES = {"base64", "hex", "rot13", "rot_13", "base64url"}
# A function looked up by computed name and called, inside evaluated code (round 4).
COMPUTED_CALL_RE = re.compile(
    r"""\b(?:globalThis|window|self|global)\s*\[\s*(?!(['"])[^'"]*\1\s*\])[^\]\n]*\]\s*\("""
    r"""|\bgetattr\(\s*[\w.]+\s*,\s*(?!(['"])[^'"]*\2\s*\))[^)\n]*\)\s*\("""
)
_SAFE_BUFFER_ENC = re.compile(r"""^\s*(['"])(?:utf-?8|ascii|latin1|binary|utf16le|utf-16le|ucs-?2)\1\s*$""", re.I)


def _top_args(text: str, open_pos: int) -> list[str]:
    """Top-level comma-separated arguments of the call whose "(" is at open_pos."""
    depth, start, out = 0, open_pos + 1, []
    quote = None
    for j in range(open_pos, min(len(text), open_pos + 5000)):
        ch = text[j]
        if quote:
            if ch == "\\":
                continue
            if ch == quote:
                quote = None
            continue
        if ch in "'\"`":
            quote = ch
        elif ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                out.append(text[start:j])
                return out
        elif ch == "," and depth == 1:
            out.append(text[start:j])
            start = j + 1
    return out


def _decodes(code: str) -> bool:
    """The evaluated code (with one or two levels of aliases resolved) decodes something."""
    aliased_buffer = bool(re.search(r"\bBuffer\b", code))  # const B = Buffer: the alias value is appended
    for m in re.finditer(r"\b([\w$]+)\s*\.\s*from\s*\(", code):
        args = _top_args(code, m.end() - 1)
        if len(args) < 2 or _SAFE_BUFFER_ENC.match(args[1]):
            continue
        recv = m.group(1)
        if recv == "Buffer" or re.fullmatch(r"""\s*(['"])(?:base64|base64url|hex)\1\s*""", args[1], re.I):
            return True
        if aliased_buffer and not recv.endswith(("Array", "Object", "Set", "Map")):
            return True  # round 4: const B = Buffer; B.from(s, enc)
    if COMPUTED_CALL_RE.search(code):
        return True  # round 4: globalThis['at' + 'ob'](s) / getattr(base64, 'b6' + '4decode')(s)

    def keep(m: re.Match) -> str:
        body = m.group(0)[1:-1]
        return m.group(0) if body.lower() in _ENCODING_NAMES or body in DECODE_NAMES else '""'

    return bool(DECODE_RE.search(_STR_LIT_RE.sub(keep, code)))


FETCH_RE = re.compile(
    r"\b(fetch|requests\.\w+|urlopen|urllib\.\w+|httpx\.\w+|axios|XMLHttpRequest|http\.get|https\.get|curl|wget)\b"
)
SHELL_FUNCS = {"run", "call", "check_output", "check_call", "Popen", "system", "popen", "exec", "execSync", "spawn", "spawnSync", "execFile"}
CURL_RE = re.compile(r"\b(curl|wget)\b")
RUN_RE = re.compile(r"\b(sh|bash|zsh|chmod)\b")
URL_IMPORT_RE = re.compile(r"^\(?\s*['\"`]https?://")

PIPE_SHELL_RE = re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")
# Installing Python packages from somewhere other than PyPI (fix rounds 2-3): any URL on a `pip install`,
# `uv pip install` or `uv add` command (an index, find-links or a direct wheel/sdist/git requirement), or an
# index set through PIP_*/UV_* variables. Shell lines and argv lists alike.
_ARGSEP = r"""['"]?(?:\s*,\s*|\s+)['"]?"""
PIP_CMD_RE = re.compile(rf"(?:(?:\bpip3?|\buv{_ARGSEP}pip){_ARGSEP}install|\buv{_ARGSEP}add)\b")
PIP_URL_RE = re.compile(r"""(?:git\+)?(https?://[^\s'",\])]+)""")
INDEX_ENV_RE = re.compile(
    r"\b(?:PIP_INDEX_URL|PIP_EXTRA_INDEX_URL|PIP_FIND_LINKS|UV_INDEX_URL|UV_EXTRA_INDEX_URL|UV_DEFAULT_INDEX"
    r"|UV_INDEX|UV_FIND_LINKS)\b['\"]?\s*(?:=|:|\]\s*=)\s*['\"]?(?:[\w.-]+=)?(https?://[^\s'\",\])]+)"
)
_SEGMENT_END_RE = re.compile(r"(?<![\\,(\[])\n|\s#|;|&&|\|\|")
PYPI_HOSTS = {"pypi.org", "files.pythonhosted.org"}
# Fallback for shell scripts and anything that did not parse.
FB_EVAL_DECODED_RE = re.compile(
    r"\beval\b[^\n]*(?:base64\s+(?:-d|--decode)|\batob\b|b64decode|xxd\s+-r|rot13)"
    r"|base64\s+(?:-d|--decode)[^\n]*\|\s*(?:ba|z)?sh\b",
    re.I,
)
FB_EVAL_FETCH_RE = re.compile(
    r"\beval\b[^\n]*\$\(\s*(?:curl|wget)\b|\beval\b[^\n]*`\s*(?:curl|wget)\b"
    r"|(?:\biex\b|Invoke-Expression)[^\n]*(?:\biwr\b|Invoke-WebRequest|DownloadString)",
    re.I,
)

# Pattern catalogs live in data/patterns.json (R52): data, not code, so bawwab's own source does not match them.
with open(join(dirname(__file__), "data", "patterns.json"), encoding="utf-8") as _fh:
    _PATTERNS = json.load(_fh)
CRED_RES = [e["re"] for e in _PATTERNS["credential_paths"]]
DOTENV_RE = re.compile(
    r"\b(?:load_dotenv|dotenv_values|find_dotenv)\b|require\(\s*['\"]dotenv['\"]\s*\)"
    r"|import\s+['\"]dotenv(?:/config)?['\"]|\bfrom\s+['\"]dotenv['\"]|^\s*(?:import|from)\s+dotenv\b",
    re.M,
)
# A named entry (patterns.json "name") is a group, so its hits can be told apart (dotenv: FP plan step 3).
CRED_RE = re.compile(
    "|".join(f"(?P<{e['name']}>{e['re']})" if e.get("name") else e["re"] for e in _PATTERNS["credential_paths"]), re.I
)
# Copies of the whole environment (Task 10c B), as text: only for files that do not parse (R45 5).
# Parsed files are read on the tree (envflow.py). Serialising the env (json.dumps, JSON.stringify,
# str) stays a plain credential hit.
ENV_COPY_RE = re.compile("|".join(e["re"] for e in _PATTERNS["env_copies"]), re.I)
SPREAD_COPY_RE = re.compile("|".join(e["re"] for e in _PATTERNS["env_spreads"]), re.I)
# References into a .claude dir, as "/.claude/<sub>" or path.join(..., ".claude", "<sub>") (R26d, R27 I5).
# ".claude/x", or ".claude" then a string join: path.join(..., '.claude', 'x'), '.claude' + '/x',
# pathlib Path.home() / '.claude' / 'x' (round 3).
CLAUDE_REF_RE = re.compile(r"""\.claude(?:/([\w.-]*)|['"]\s*[,/+]\s*['"]/?([\w.-]+)|(?=['"]))""")
READ_ITER_RE = re.compile(
    r"\b(?:readdir\w*|readFile\w*|createReadStream|opendir\w*|glob\w*|walk\w*|rglob|iterdir|scandir|listdir"
    r"|read_text|read_bytes|open|copy\w*|cp\w*|archive|zip\w*|tar)\s*\("
)
CLAUDE_INSTALL_SUBDIRS = {"", "agents", "skills", "commands", "plugins", "CLAUDE.md"}
CLAUDE_CRED_FILE_RE = re.compile(r"^(?:\.credentials\.json|settings[\w.-]*\.json)$")
HOME_RE = re.compile(r"~|homedir|\bHOME\b|expanduser|Path\.home|USERPROFILE|os\.environ\[['\"]HOME", re.I)
WRITE_RE = re.compile(
    r"\b(?:write\w*|mkdir\w*|copy\w*|cp\w*|rename\w*|symlink\w*|appendFile\w*|createWriteStream|write_text|write_bytes)\s*\("
    r"|\bshutil\.(?:copy\w*|move)\b|\bopen\([^)\n]*['\"][wa]b?\+?['\"]"
)
# Names that mark a list/set/regex as a deny-list or matcher (R26c).
# FP plan step 3: lists that redact, mask, skip, omit or scrub secrets keep them out too.
DENY_WORD_RE = re.compile(
    r"deny|block|forbid|sensitive|protect|refus|exclu|ignor|reject|blacklist|disallow|redact|mask|skip|omit|scrub"
    r"|saniti|prune|exempt",
    re.I,
)
REGEX_CALL_RE = re.compile(r"^(?:re\.(?:compile|search|match|fullmatch|findall|finditer|sub|split)|RegExp)$")
CONTAINER_CALLEES = {"Set", "Array", "Array.of", "Map", "set", "frozenset", "list", "tuple"}
PATH_CALLEES = {"path.join", "path.resolve", "path.posix.join", "os.path.join", "os.path.expanduser", "Path", "String", "str"}
COLLECTION_METHODS = {"add", "has", "includes", "push", "test", "match", "indexOf", "some", "append", "extend", "update", "set"}
_DECL_TAIL_RE = re.compile(r"""(?:['"]?([\w$.]+)['"]?\s*[:=]\s*)?(?:new\s+)?([\w$.]*)\s*\(?\s*$""")
EXFIL_HOST_RE = re.compile("|".join(e["re"] for e in _PATTERNS["exfil_hosts"]), re.I)
NET_RE = re.compile(
    r"\b(?:fetch|axios|XMLHttpRequest|urlopen|urllib|httpx|requests\.\w+|http\.request|https\.request|http\.get|https\.get|curl|wget|socket)\b"
    r"|\bgot\(|Invoke-WebRequest|\bnc\s|\b(?:net|tls)\.(?:connect|createConnection)\b"
)
BLOB_RE = re.compile(r"""["'`]((?:[A-Za-z0-9+/]{200,}={0,2})|(?:[0-9a-fA-F]{200,}))["'`]""")
_SVG_HEAD_RE = re.compile(rb"^\s*(?:<\?xml[^>]*\?>\s*)?(?:<!--.*?-->\s*|<!DOCTYPE[^>]*>\s*)*<svg[\s>]", re.S | re.I)


_SVG_ACTIVE_RE = re.compile(rb"<script|<foreignObject|\bon[a-z]+\s*=|javascript:|<iframe|<embed|<object", re.I)


def _image_b64(lit: str) -> bool:
    """A base64 literal that decodes to a well-formed PNG, JPEG, GIF, WebP or a passive SVG image
    (Task 10c D). The header structure is checked, not just the magic (review M2)."""
    if not re.fullmatch(r"[A-Za-z0-9+/]+={0,2}", lit) or len(lit) < 8:
        return False  # hex blobs are never taken as images
    head = lit[:1024]
    head = head[: len(head) // 4 * 4]
    try:
        data = base64.b64decode(head, validate=True)
    except (binascii.Error, ValueError):
        return False
    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        return data[8:16] == b"\x00\x00\x00\x0dIHDR"
    if data.startswith(b"\xff\xd8\xff"):
        return len(data) > 5 and (0xE0 <= data[3] <= 0xEF or data[3] in (0xDB, 0xC0, 0xC2, 0xC4, 0xFE)) and data[4] < 0x10
    if data.startswith((b"GIF87a", b"GIF89a")):
        return any(b < 0x09 or 0x0E <= b < 0x20 or b >= 0x7F for b in data[6:13])  # binary screen descriptor
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return data[12:16] in (b"VP8 ", b"VP8L", b"VP8X")
    if _SVG_HEAD_RE.match(data):
        try:
            whole = base64.b64decode(lit + "=" * (-len(lit) % 4))
        except (binascii.Error, ValueError):
            return False
        return not _SVG_ACTIVE_RE.search(whole)
    return False


REMOTE_RE = re.compile(r"\b(?:curl|wget|fetch|urllib|requests|Invoke-WebRequest|iwr|httpx|axios)\b|\bhttps?\.get\b")


# ---------------------------------------------------------------- manifests / install hooks


@dataclass
class _Hook:
    file: ScanFile
    line: int
    command: str  # "" for setup.py
    body: str = ""  # setup.py: source of the hook code only


def _json_key_line(text: str, key: str) -> int:
    m = re.search(r'"' + re.escape(key) + r'"\s*:', text)
    return _line_of(text, m.start()) if m else 1


def _package_scripts(f: ScanFile) -> dict[str, str]:
    try:
        data = json.loads(f.text)
    except ValueError:
        return {}
    scripts = data.get("scripts") if isinstance(data, dict) else None
    if not isinstance(scripts, dict):
        return {}
    return {k: v for k, v in scripts.items() if isinstance(v, str)}


_FUNC_NODES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)


def _setup_py_hook(f: ScanFile) -> tuple[int, str] | None:
    """(line, hook-code text) for an install-time construct in setup.py, or None.

    The text covers only the hook itself: run() methods of command classes and
    module-level os.system/subprocess calls, not the whole file.
    """
    try:
        tree = parsing.py_parse(f.text)
        line = None
        for n in ast.walk(tree):
            if isinstance(n, ast.Call) and any(k.arg == "cmdclass" for k in n.keywords):
                line = n.lineno
                break
        segs: list[str] = []
        for n in ast.walk(tree):
            if isinstance(n, ast.ClassDef):
                for m in n.body:
                    if isinstance(m, (ast.FunctionDef, ast.AsyncFunctionDef)) and m.name == "run":
                        segs.append(ast.get_source_segment(f.text, m) or "")
        stack = [s for s in tree.body if not isinstance(s, _FUNC_NODES)]
        while stack:
            n = stack.pop(0)
            if isinstance(n, ast.Call):
                name = ast.unparse(n.func)
                if name == "os.system" or name.startswith("subprocess."):
                    line = line or n.lineno
                    segs.append(ast.get_source_segment(f.text, n) or "")
            stack.extend(c for c in ast.iter_child_nodes(n) if not isinstance(c, _FUNC_NODES))
        return (line, "\n".join(segs)) if line else None
    except (SyntaxError, ValueError, RecursionError):
        m = re.search(r"cmdclass\s*=|^\s*(?:os\.system|subprocess\.\w+)\(", f.text, re.M)
        return (_line_of(f.text, m.start()), f.text) if m else None


def _install_hooks(files: list[ScanFile]) -> list[_Hook]:
    hooks = []
    for f in files:
        base = _base(f.rel)
        if base == "package.json":
            scripts = _package_scripts(f)
            for key in INSTALL_KEYS:
                if key in scripts:
                    hooks.append(_Hook(f, _json_key_line(f.text, key), scripts[key]))
        elif base == "setup.py":
            hit = _setup_py_hook(f)
            if hit:
                hooks.append(_Hook(f, hit[0], "", hit[1]))
    return hooks


def _referenced_files(hook: _Hook, files: list[ScanFile]) -> list[ScanFile]:
    """Files named in the hook command (directly, or through `npm run <script>`)."""
    by_rel = {f.rel: f for f in files}
    base_dir = dirname(hook.file.rel)
    scripts = _package_scripts(hook.file) if _base(hook.file.rel) == "package.json" else {}
    out: list[ScanFile] = []
    commands = [hook.command]
    for _ in range(2):  # follow `npm run x` a couple of levels
        nxt = []
        for cmd in commands:
            for m in re.finditer(r"\b(?:npm|yarn|pnpm)\s+(?:run\s+)?([\w:-]+)", cmd):
                if m.group(1) in scripts:
                    nxt.append(scripts[m.group(1)])
        commands = nxt
        if not commands:
            break
        for cmd in commands:
            out.extend(_tokens_to_files(cmd, base_dir, by_rel))
    out.extend(_tokens_to_files(hook.command, base_dir, by_rel))
    return out


def _tokens_to_files(cmd: str, base_dir: str, by_rel: dict[str, ScanFile]) -> list[ScanFile]:
    found = []
    for tok in re.split(r"[\s;&|]+", cmd):
        tok = tok.strip("\"'")
        if not tok or tok.startswith("-"):
            continue
        rel = normpath(join(base_dir, tok))
        if rel in by_rel:
            found.append(by_rel[rel])
    return found


def _install_files(files: list[ScanFile]) -> set[str]:
    rels: set[str] = set()
    for h in _install_hooks(files):
        rels.add(h.file.rel)
        rels.update(r.rel for r in _referenced_files(h, files))
    return rels


def registry_install_adjust(files: list[ScanFile], findings: list[Finding]) -> list[Finding]:
    """R31: npm does not run `prepare` when installing from the registry, so for an npm-registry
    target a hook that is only `prepare` is listed as LOW. Git and local targets keep MED."""
    prepare = set()
    for f in files:
        if _base(f.rel) == "package.json":
            scripts = _package_scripts(f)
            if "prepare" in scripts:
                prepare.add((f.rel, _json_key_line(f.text, "prepare")))
            for key in INSTALL_KEYS:
                if key != "prepare" and key in scripts:
                    prepare.discard((f.rel, _json_key_line(f.text, key)))
    return [
        Finding(x.rule, Severity.LOW, x.source, x.evidence, file=x.file, line=x.line)
        if x.rule == "install-script" and (x.file, x.line) in prepare else x
        for x in findings
    ]


class ManifestRules:
    id = "manifest"

    def run(self, files: list[ScanFile], extra: list[ExtraText]) -> list[Finding]:
        out: list[Finding] = []
        for h in _install_hooks(files):
            out.append(_finding("install-script", Severity.MED, h.file, h.line, h.command or None))
            if h.command:
                if REMOTE_RE.search(h.command):
                    out.append(_finding("install-script.remote", Severity.CRITICAL, h.file, h.line, h.command[:200]))
            else:
                m = REMOTE_RE.search(h.body)
                if m:
                    out.append(_finding("install-script.remote", Severity.CRITICAL, h.file, h.line, m.group(0)))
            for ref in _referenced_files(h, files):
                m = REMOTE_RE.search(ref.text)
                if m:
                    out.append(_finding("install-script.remote", Severity.CRITICAL, ref, _line_of(ref.text, m.start())))
        for f in files:
            out.extend(_unpinned_deps(f))
        return out


def _unpinned_npm(spec: str) -> bool:
    spec = spec.strip()
    if spec in ("*", "latest", "x", ""):
        return True
    is_git = re.match(r"(git\+|git://|github:|gitlab:|bitbucket:)", spec) or re.search(r"\.git(#|$)", spec)
    return bool(is_git) and not re.search(r"#[0-9a-f]{7,40}$", spec)


def _unpinned_py(spec: str) -> bool:
    s = spec.strip()
    if s.endswith("*") and "git+" not in s:  # `pkg==*` / `pkg*`
        return True
    if "git+" in s or re.search(r"@\s*git", s):
        return not re.search(r"@[0-9a-f]{7,40}\s*(?:[#;].*)?$", s)
    return False


def _unpinned_deps(f: ScanFile) -> list[Finding]:
    base = _base(f.rel)
    out: list[Finding] = []

    def add(name: str, spec: str):
        m = re.search(re.escape(name), f.text)
        line = _line_of(f.text, m.start()) if m else 1
        out.append(_finding("deps.unpinned", Severity.LOW, f, line, f"{name}: {spec}"[:200]))

    if base == "package.json":
        try:
            data = json.loads(f.text)
        except ValueError:
            return out
        if isinstance(data, dict):
            for sect in ("dependencies", "devDependencies", "optionalDependencies"):
                deps = data.get(sect)
                if isinstance(deps, dict):
                    for name, spec in deps.items():
                        if isinstance(spec, str) and _unpinned_npm(spec):
                            add(name, spec)
    elif base == "pyproject.toml":
        try:
            data = tomllib.loads(f.text)
        except tomllib.TOMLDecodeError:
            return out
        proj = data.get("project", {})
        specs = list(proj.get("dependencies", []))
        for group in proj.get("optional-dependencies", {}).values():
            specs.extend(group)
        for s in specs:
            if isinstance(s, str) and _unpinned_py(s):
                add(re.split(r"[\s@=<>~!;\[]", s.strip(), 1)[0], s)
        for name, spec in data.get("tool", {}).get("poetry", {}).get("dependencies", {}).items():
            if name != "python" and (spec == "*" or (isinstance(spec, dict) and "git" in spec and not (spec.get("rev") or spec.get("tag")))):
                add(name, str(spec))
    elif re.fullmatch(r"requirements.*\.txt", base):
        for i, raw in enumerate(f.text.splitlines(), 1):
            s = raw.split(" #")[0].strip()
            if s and not s.startswith(("#", "-r", "--")) and _unpinned_py(s.removeprefix("-e").strip()):
                out.append(_finding("deps.unpinned", Severity.LOW, f, i, s[:200]))
    return out


# ---------------------------------------------------------------- comment blanking (R26a)


def _blank(text: str, spans: list[tuple[int, int]]) -> str:
    """Replace each [start, end) span with spaces, keeping newlines so line numbers hold."""
    if not spans:
        return text
    out, last = [], 0
    for a, b in sorted(spans):
        if a < last:
            a = last
        out.append(text[last:a])
        out.append(re.sub(r"[^\n]", " ", text[a:b]))
        last = max(last, b)
    out.append(text[last:])
    return "".join(out)


def _blank_bytes(src: bytes, spans: list[tuple[int, int]]) -> bytes:
    buf = bytearray(src)
    for a, b in spans:
        for i in range(a, b):
            if buf[i] != 0x0A:
                buf[i] = 0x20
    return bytes(buf)


_LINE_COMMENT_RE = re.compile(r"^[ \t]*(?:#|//).*$", re.M)


@lru_cache(maxsize=512)
def _code_info(rel: str, text: str) -> tuple[str, tuple[tuple[int, int], ...]]:
    """(text with comments blanked, character spans of JS regex literals).

    Regex literals stay in the text: they are deny-list *context*, not removed code (R27 I4).
    """
    try:
        if rel.endswith(JS_EXT + TS_EXT):
            src = text.encode()
            # No reference to the root: a visited node (and the child list py-tree-sitter caches on it) is
            # freed once popped, instead of mirroring the whole tree in Python objects (~2.4x the tree).
            comments, regexes, stack = [], [], [parsing.js_root(src, _js_lang(rel))]
            while stack:
                n = stack.pop()
                if n.type in ("comment", "html_comment"):
                    comments.append((n.start_byte, n.end_byte))
                elif n.type == "regex":
                    regexes.append((n.start_byte, n.end_byte))
                else:
                    stack.extend(n.children)
            blanked = _blank_bytes(src, comments).decode("utf-8", "replace")
            if src.isascii():
                return blanked, tuple(regexes)
            # Byte -> character offsets in one pass (decoding the prefix per literal was quadratic).
            chars, prev, at = 0, 0, {}
            for b in sorted({x for span in regexes for x in span}):
                chars += len(src[prev:b].decode("utf-8", "replace"))
                prev, at[b] = b, chars
            return blanked, tuple((at[a], at[b]) for a, b in regexes)
        if rel.endswith(PY_EXT):
            # Offsets from the same line split tokenize uses: "\n" only. str.splitlines() also
            # splits on \x0b \x0c \x1c-\x1e \x85     and would misplace spans (R27 C3).
            starts = [0]
            for line in text.split("\n"):
                starts.append(starts[-1] + len(line) + 1)
            spans = []
            for tok in tokenize.generate_tokens(io.StringIO(text).readline):
                if tok.type == tokenize.COMMENT:
                    (r1, c1), (r2, c2) = tok.start, tok.end
                    spans.append((starts[r1 - 1] + c1, starts[r2 - 1] + c2))
            out = _blank(text, spans)
            assert len(out) == len(text)
            return out, ()
    except MemoryError:
        raise
    except Exception:  # noqa: BLE001 - unparseable: conservative full-line fallback below
        pass
    return _blank(text, [m.span() for m in _LINE_COMMENT_RE.finditer(text)]), ()


def _code_text(rel: str, text: str) -> str:
    return _code_info(rel, text)[0]


# ---------------------------------------------------------------- deny-list context (R26c, R27 I4)

FILE_NET_RE = re.compile(
    NET_RE.pattern + r"|readFile|readdir|createReadStream|\bopen\(|read_text|read_bytes|listdir|\bspawn|\bexec"
)


def _decl_name(t: str, pos: int) -> str:
    line_start = t.rfind("\n", 0, pos) + 1
    m = _DECL_TAIL_RE.search(t[line_start:pos])
    return (m.group(1) or "") if m else ""


def _close_of(t: str, open_pos: int) -> int:
    depth = 0
    for j in range(open_pos, min(len(t), open_pos + 20000)):
        ch = t[j]
        if ch in "([{":
            depth += 1
        elif ch in ")]}":
            depth -= 1
            if depth == 0:
                return j + 1
    return len(t)


# Regex turned back into a string: /x/.source, re.pattern, String(re), re.toString() (R29).
_STRINGIFY_TAIL_RE = re.compile(r"\s*(?:\[[^\]\n]*\]\s*)?\.\s*(?:source|pattern)\b|\s*(?:\[[^\]\n]*\]\s*)?\.\s*toString\s*\(")
_STRINGIFY_HEAD_RE = re.compile(r"\b(?:String|str)\(\s*$")
_ELEMENT_RES = (
    r"\bfor\s*\(\s*(?:const|let|var)\s+([\w$]+)\s+(?:of|in)\s+{n}\b",
    r"\bfor\s+([\w]+)\s+in\s+{n}\b",
    r"(?<![\w$.]){n}\s*\.\s*\w+(\()\s*(?:async\s+)?(?:function\s*)?\(?\s*([\w$\s,]*?)\)?\s*(?:=>|\{{)",
)
# Glob / ignore / match libraries: a sensitive path passed to them is a matcher, not a read (R29).
GLOB_MODULES = {
    "ignore", "picomatch", "minimatch", "micromatch", "anymatch", "multimatch", "fast-glob", "globby", "glob",
    "tinyglobby", "pathspec", "fnmatch", "wcmatch", "gitignore_parser", "gitignore-parser", "outmatch",
}


def _block_end(t: str, start: int) -> int:
    """End of the loop body that starts after position start (a JS block, one statement, or a Python suite)."""
    nl = t.find("\n", start)
    head_line = t[t.rfind("\n", 0, start) + 1 : nl if nl != -1 else len(t)]
    if head_line.rstrip().endswith(":"):  # Python suite: until a line indented no deeper than the for
        indent = len(head_line) - len(head_line.lstrip())
        pos = nl
        while pos != -1 and pos < len(t):
            nxt = t.find("\n", pos + 1)
            line = t[pos + 1 : nxt if nxt != -1 else len(t)]
            if line.strip() and len(line) - len(line.lstrip()) <= indent:
                return pos
            pos = nxt
        return len(t)
    paren = t.find("(", start)
    close = _close_of(t, paren) if paren != -1 else start
    m = re.compile(r"\s*\{").match(t, close)
    if m:
        return _close_of(t, m.end() - 1)
    end = t.find("\n", close)
    return end if end != -1 else len(t)


def _holder_names(t: str, a: int) -> tuple[set[str], list[tuple[str, int, int]]]:
    """Names that hold the value at position a (its declaration, the collection around it and
    one level of aliases), plus (element name, start, end) for loops / callbacks over them."""
    names = set()
    direct = _decl_name(t, a)
    if direct:
        names.add(direct)
    depth, i, levels = 0, a - 1, 0
    while i >= max(0, a - 4000) and levels < 3 and not names:
        ch = t[i]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth:
                depth -= 1
            else:
                levels += 1
                line_start = t.rfind("\n", 0, i) + 1
                m = _DECL_TAIL_RE.search(t[line_start:i] + ("(" if ch == "(" else ""))
                if m and m.group(1):
                    names.add(m.group(1))
        i -= 1
    for n in list(names):
        leaf = re.escape(n.rsplit(".", 1)[-1])
        for m in re.finditer(rf"(?<![\w$.])([\w$]+)\s*=\s*{leaf}\s*(?:[;\n,)]|$)", t):
            names.add(m.group(1))
    elements: list[tuple[str, int, int]] = []
    for n in list(names):
        leaf = re.escape(n.rsplit(".", 1)[-1])
        for k, rx in enumerate(_ELEMENT_RES):
            for m in re.finditer(rx.format(n=leaf), t):
                if k == 2:  # NAME.some((re) => ...): the call's own arguments
                    params, end = m.group(2), _close_of(t, m.start(1))
                else:
                    params, end = m.group(1), _block_end(t, m.start())
                for p in params.split(","):
                    if re.fullmatch(r"[\w$]+", p.strip()):
                        elements.append((p.strip(), m.start(), end))
    return names, elements


def _stringify_re(leaf: str) -> re.Pattern:
    return re.compile(
        rf"(?<![\w$.]){leaf}(?:\s*\[[^\]\n]*\])?(?:\s*\.\s*(?:source|pattern)\b|\s*\.\s*toString\s*\()"
        rf"|\b(?:String|str)\(\s*{leaf}\b"
    )


# Round 5 (controller): any stringification idiom anywhere in the file, on any receiver, voids
# the regex combo-exemption for the whole file.
_ANY_STRINGIFY_RE = re.compile(
    r"""\.\s*(?:source|pattern)\b|\[\s*(['"`])(?:source|pattern)\1\s*\]"""
    r"""|\{[^{}=]*\b(?:source|pattern)\b[^{}=]*\}\s*=(?!=)|\brepr\s*\("""
    r"""|\bgetattr\s*\([^()]*,\s*(['"])(?:source|pattern)\2|\.\s*toString\s*\(\s*\)"""
    r"""|\b(?:String|str)\(\s*/"""
)
_REGEX_CTOR_RE = re.compile(r"\b(?:re\.compile|RegExp)\s*\(")


@lru_cache(maxsize=256)
def _regex_void(t: str, regexes: tuple) -> bool:
    if _ANY_STRINGIFY_RE.search(t):
        return True
    names: set[str] = set()
    starts = [a for a, _ in regexes] + [m.start() for m in _REGEX_CTOR_RE.finditer(t)]
    for a in starts:
        held, elements = _holder_names(t, a)
        names |= {n.rsplit(".", 1)[-1] for n in held} | {e for e, _, _ in elements}
    for n in names:
        n = re.escape(n)
        if re.search(
            rf"""\b(?:String|str)\(\s*{n}\b|(?<![\w$.]){n}\s*\+\s*['"`]|['"`]\s*\+\s*{n}(?![\w$])"""
            rf"""|\$\{{\s*{n}\s*\}}|\{{\s*{n}\s*(?:!r|!s)?\s*\}}""",
            t,
        ):
            return True
    return False


def _stringified(t: str, a: int, b: int, regexes: tuple = ()) -> bool:
    """The regex at [a, b) is turned back into a string somewhere (R29: then it is not exempt)."""
    if _STRINGIFY_TAIL_RE.match(t, b) or _STRINGIFY_HEAD_RE.search(t[max(0, a - 20) : a]):
        return True
    if _regex_void(t, tuple(regexes)):
        return True
    names, elements = _holder_names(t, a)
    if any(_stringify_re(re.escape(n.rsplit(".", 1)[-1])).search(t) for n in names):
        return True
    return any(_stringify_re(re.escape(e)).search(t, lo, hi) for e, lo, hi in elements)


def _predicate_reaches_io(f: ScanFile, t: str, leaf: str) -> bool:
    """isBlocked(...) is only a check if its own body does no file or network I/O."""
    n = re.escape(leaf)
    m = re.search(
        rf"(?:function\s*\*?\s*{n}\s*\(|def\s+{n}\s*\(|(?<![\w$.]){n}\s*[:=]\s*(?:async\s+)?(?:function\b|\(|[\w$]+\s*=>))",
        t,
    )
    if not m:
        return False  # defined elsewhere: keep the (low) exemption; the R27 floor still sees any combo
    line = _line_of(t, m.start())
    end = line + 40
    for lo, hi in _function_spans(f.rel, f.text) or []:
        if lo <= line <= hi:
            end = hi
            break
    body = "\n".join(t.split("\n")[line - 1 : end])
    return bool(FILE_NET_RE.search(body))


def _glob_callee(f: ScanFile, callee: str) -> bool:
    norm = _norm_callee(callee, _aliases(f.rel, f.text))
    parts = norm.split(".")
    return parts[0] in GLOB_MODULES or callee.split(".")[0] in GLOB_MODULES or (
        parts[-1] in ("isMatch", "matcher", "fnmatch", "fnmatchcase", "from_lines") and len(parts) > 1
    )


_JOIN_TAIL_RE = re.compile(r"""\s*\.\s*join\(\s*(['"])\|\1\s*\)\s*[,)]""")
_JS_REGEX_HEAD_RE = re.compile(r"""\bRegExp\(\s*$""")
_PY_REGEX_HEAD_RE = re.compile(
    r"""\bre\.(?:compile|search|match|fullmatch|findall|finditer)\(\s*[rbu]*(['"])\|\1\s*\.\s*join\(\s*$"""
)


def _joined_regex_open(t: str, i: int) -> int | None:
    """The "(" of RegExp([...].join('|')) / re.compile('|'.join([...])) for the array at i, when every
    element is a plain string literal; else None."""
    head = t[max(0, i - 200) : i]
    close = _close_of(t, i)
    if (m := _JS_REGEX_HEAD_RE.search(head)) is not None:
        if not _JOIN_TAIL_RE.match(t, close):
            return None
        open_pos = t.rindex("(", 0, i)
    elif (m := _PY_REGEX_HEAD_RE.search(head)) is not None:
        if not re.match(r"\s*\)\s*[,)]", t[close:]):
            return None
        open_pos = t.index("(", i - len(head) + m.start())
    else:
        return None
    elems = [e for e in _top_args(t, i) if e.strip()]
    if not elems or not all(_LITERAL_ARG_RE.match(re.sub(r"^\s*[rbu]+(?=['\"])", "", e)) for e in elems):
        return None
    return open_pos


def _context(f: ScanFile, t: str, pos: int, regexes) -> str | None:
    """"regex", "deny" or None (a plain reference) for a sensitive path at pos (R29).

    "regex": inside a regex literal (or a regex constructor over one literal) that is never
    turned back into a string; the only context that is exempt from exfil.combo. A regex
    that is turned into a string is judged by the collection around it, if any.
    "deny": inside a deny-list / sensitive-path collection (a literal or Set/Array/Map named
    like BLOCKED / sensitive / ignore, a membership call on one, a predicate like isBlocked(...),
    or an argument of a glob / ignore / match library). Lowered as a single signal only.
    """
    for a, b in regexes:
        if a <= pos < b:
            if not _stringified(t, a, b, regexes):
                return "regex"
            pos = a  # turned into a string: only an enclosing deny-list can still lower it
    depth, i, levels = 0, pos - 1, 0
    lo = max(0, pos - 4000)
    while i >= lo and levels < 3:
        ch = t[i]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth:
                depth -= 1
            else:
                levels += 1
                if ch == "[" and (r := _joined_regex_open(t, i)) is not None:
                    # RegExp([...literals].join('|')): a regex literal in all but syntax (10a minor)
                    if not _stringified(t, r, _close_of(t, r), regexes):
                        return "regex"
                # the declaration / callee right before the bracket: a bounded tail, so a long one-line file is
                # not rescanned from its start for every hit (r4 m3)
                line_start = max(t.rfind("\n", 0, i) + 1, i - 512)
                prefix = t[line_start:i] + ("(" if ch == "(" else "")
                m = _DECL_TAIL_RE.search(prefix)
                name, callee = (m.group(1) or "", m.group(2) or "") if m else ("", "")
                if callee in PATH_CALLEES:
                    i -= 1
                    continue
                if REGEX_CALL_RE.match(callee):
                    args = _top_args(t, i)
                    in_pattern = levels == 1 and bool(args) and i + 1 <= pos < i + 1 + len(args[0])
                    literal = in_pattern and _LITERAL_ARG_RE.match(re.sub(r"^\s*[rbu]+(?=['\"])", "", args[0]))
                    if literal and not _stringified(t, i, _close_of(t, i), regexes):
                        return "regex"
                    # the subject / replacement of re.sub(...), or a pattern turned into a string:
                    # judged by what encloses the call (round 5)
                    i -= 1
                    continue
                if callee and callee not in CONTAINER_CALLEES:
                    recv, _, leaf = callee.rpartition(".")
                    if _glob_callee(f, callee):
                        return "deny"
                    if leaf in COLLECTION_METHODS:
                        return "deny" if DENY_WORD_RE.search(recv) else None
                    if re.match(r"(?:is|should|must)[A-Z_]", leaf) and DENY_WORD_RE.search(leaf):
                        return None if _predicate_reaches_io(f, t, leaf) else "deny"
                    return None
                if name:
                    return "deny" if DENY_WORD_RE.search(name) else None
        i -= 1
    return None


# ---------------------------------------------------------------- .claude references (R26d, R27 I5)


# Calls that read, walk or copy FROM their target (R30a). For copies only the source counts.
CLAUDE_READ_LEAVES = {
    "readdir", "readdirSync", "readFile", "readFileSync", "createReadStream", "opendir", "opendirSync", "glob",
    "globSync", "globby", "walk", "walkSync", "rglob", "iterdir", "scandir", "listdir", "read_text", "read_bytes",
    "open", "cp", "cpSync", "copy", "copyFile", "copyFileSync", "copytree", "copy2", "copyfile", "copySync",
    "stream", "watch", "fg", "fastGlob",
}
CLAUDE_ARCHIVE_LEAVES = {"make_archive", "zip", "zipSync", "tar", "archive", "create", "c", "directory", "add", "write"}
CLAUDE_METHOD_LEAVES = {"rglob", "glob", "iterdir", "read_text", "read_bytes", "open", "walk", "readdir"}
_WRITE_MODE_RE = re.compile(r"""(?:^|,)\s*(?:mode\s*=\s*|flags?\s*:\s*)?['"][wax]b?\+?['"]""")
_TEMPLATE_SEG_RE = re.compile(r"""\s*\}\s*/([^/`'"{}]*)""")


_SEG_STEP_RE = re.compile(r"""\s*\)?\s*(?:,|/|\+)\s*[frbu]?(['"`])([^'"`\n]*)\1""")
GLOB_LEAVES = {"glob", "globSync", "globby", "sync", "stream", "async", "fg", "fastGlob"}


def _segments_after(text: str, pos: int) -> list[str] | None:
    """Literal path segments joined right after pos (path.join(x, 'a', 'b/c'), x / 'a', x + '/a',
    `${x}/a`), or None when nothing literal follows."""
    segs: list[str] = []
    m = _TEMPLATE_SEG_RE.match(text, pos)
    if m:
        return [x for x in m.group(1).split("/") if x]
    while (m := _SEG_STEP_RE.match(text, pos)) is not None:
        segs += [x for x in m.group(2).split("/") if x]
        pos = m.end()
    return segs or None


def _escapes(segs: list[str] | None) -> bool:
    """A bare ~/.claude joined this way reaches beyond the install dirs (round 5: '..' escapes)."""
    return not segs or ".." in segs or segs[0] not in CLAUDE_INSTALL_SUBDIRS


def _decl_names(t: str, m_start: int) -> set[str]:
    names: set[str] = set()
    prefix = t[t.rfind("\n", 0, m_start) + 1 : m_start]
    d = re.search(r"(?:^|[;{(,\s])(?:(?:const|let|var)\s+)?([\w$.]+)\s*(?::[^=;]+)?=(?![=>])[^=;]*$", prefix)
    if d:
        names.add(d.group(1))
    for n in list(names):
        for a in re.finditer(rf"(?<![\w$.])([\w$.]+)\s*(?::[^=\n]+)?=\s*{re.escape(n)}\s*(?:[;\n)]|$)", t, re.M):
            names.add(a.group(1))
    return names


def _install_dir_escapes(t: str, m: re.Match) -> bool:
    """An install-dir reference that climbs out of it: '.claude/skills/..', join(.., 'skills', '..'),
    or a name bound to it that is joined with '..', passed to dirname() or .parent (round 5)."""
    after = t[m.end() : m.end() + 40]
    if re.match(r"""/\.\.(?:[/'"`]|$)""", after) or ".." in (_segments_after(t, m.end()) or []):
        return True
    for n in _decl_names(t, m.start()):
        e = re.escape(n)
        if re.search(rf"\bdirname\s*\(\s*{e}\s*\)|(?<![\w$.]){e}\s*\.\s*parent\b", t):
            return True
        for o in re.finditer(rf"(?<![\w$.]){e}(?![\w$])", t):
            if ".." in (_segments_after(t, o.end()) or []):
                return True
    return False


def _bare_claude_read(f: ScanFile, t: str, m: re.Match, line_no: int) -> bool:
    """A bare home ~/.claude (the value itself, not joined with agents/skills/commands/plugins/
    CLAUDE.md) is the argument of a read / walk / glob / shell / copy-source call (R30a, round 5)."""
    calls = _calls(f.rel, f.text)
    if calls is None:  # unparsed: same-function read, as in round 3
        reads = [_line_of(t, r.start()) for r in READ_ITER_RE.finditer(t)]
        return bool(reads) and _same_scope(f, [line_no], reads)
    names = _decl_names(t, m.start())

    def reaches(target: str) -> bool:
        for r in CLAUDE_REF_RE.finditer(target):
            if (r.group(1) if r.group(1) is not None else (r.group(2) or "")) == "":
                return True  # the bare home .claude expression inline
        for n in names:
            for o in re.finditer(rf"(?<![\w$.]){re.escape(n)}(?![\w$])", target):
                if _escapes(_segments_after(target, o.end())):
                    return True  # bare, joined with a variable / glob / '..', or another subpath
        return False

    for c in calls:
        recv, _, leaf = c.callee.rpartition(".")
        if leaf == "open" and _WRITE_MODE_RE.search(c.args_raw[len(c.first_raw):] if c.first_raw else ""):
            continue  # open(..., 'w' / 'a'): a destination
        targets = []
        if leaf in CLAUDE_READ_LEAVES:
            targets.append(c.first_raw)
        if leaf in GLOB_LEAVES and (leaf in CLAUDE_READ_LEAVES or re.search(r"glob|fg", recv, re.I)):
            targets.append(c.args_raw)  # fg.sync('**/*', {cwd: base})
        if leaf in SHELL_FUNCS:
            targets.append(c.args_raw)  # execSync('tar czf - ' + base)
        if leaf in CLAUDE_ARCHIVE_LEAVES and re.search(r"zip|tar|archiv|shutil", c.callee, re.I):
            targets.append(c.args_raw)
        if leaf in CLAUDE_METHOD_LEAVES and recv:
            targets.append(recv)
        if any(tg and reaches(tg) for tg in targets):
            return True
    return False


def _project_claude(t: str, m: re.Match, line_no: int, home: bool) -> bool:
    """A .claude/settings*.json of the project, not the user's (FP round 2): the literal starts with .claude or
    ./.claude, or the line anchors it to a project directory (cwd, __dirname, ROOT, repo...) and names no home.
    Like the project's own .env it is "own": LOW alone, still counted for a combo and the network backstop."""
    if home or _ROOT_HOME_RE.search(_line_text(t, line_no)):
        return False
    a = m.start() - 2 if t[max(0, m.start() - 2) : m.start()] == "./" else m.start()
    q = t[a - 1 : a] if a > 0 else ""
    if q in ("'", '"', "`"):
        anchor = _join_anchor(t, a - 1)  # path.join(X, '.claude', ...), X / ".claude"
        if not anchor.strip():
            # a relative path on its own: inside the project, unless the file names the home directory anywhere
            # (`HOME_CFG = os.path.join(".claude", "settings.json")`, joined to Path.home() later)
            return not HOME_RE.search(t)
        return _PROJECT_ANCHOR_RE.search(anchor) is not None and not HOME_RE.search(anchor)
    if q in ("", " ", "\t", "\n"):
        return not HOME_RE.search(t)  # a bare relative shell word, in a file that never names the home directory
    return _PROJECT_ANCHOR_RE.search(_line_text(t, line_no)) is not None


def _claude_refs(t: str, f: ScanFile | None = None):
    """(pos, "cred" | "install") for each reference into a .claude directory.

    agents/skills/commands/plugins and project-relative paths are install dirs. Credential
    and settings files, other home subpaths (projects/, history.jsonl, todos/...), and a bare
    home ~/.claude that is itself read, walked or copied from (round 4, R30a) are credential access.
    """
    for m in CLAUDE_REF_RE.finditer(t):
        sub = m.group(1) if m.group(1) is not None else (m.group(2) or "")
        sub = sub.split("/", 1)[0]
        line_no = _line_of(t, m.start())
        home = bool(HOME_RE.search(_line_text(t, line_no)))
        if CLAUDE_CRED_FILE_RE.match(sub):
            kind = "own" if sub.startswith("settings") and _project_claude(t, m, line_no, home) else "cred"
        elif sub in CLAUDE_INSTALL_SUBDIRS and sub and home and _install_dir_escapes(t, m):
            kind = "cred"  # ~/.claude/skills/.. and the like (round 5)
        elif sub in CLAUDE_INSTALL_SUBDIRS:
            kind = "install"
            if sub == "" and home and f is not None and _bare_claude_read(f, t, m, line_no):
                kind = "cred"
        else:  # ~/.claude/projects, history.jsonl, todos/...: session data; a project .claude/x is install-dir
            kind = "cred" if home else "install"
        yield m.start(), kind


# ---------------------------------------------------------------- runtime references (R26b, R27 C1/C2)

_PATH_TOKEN_RE = re.compile(r"[\w.$@{}/-]*/[\w.$@{}/-]*")
_STRING_RE = re.compile(r"""(['"`])([^'"`\n]{1,300})\1""")
_PY_FROM_RE = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+\(?([\w\s,]+)", re.M)
_PY_IMPORT_RE = re.compile(r"^\s*import\s+([\w.]+)", re.M)
_DOTTED_RE = re.compile(r"^[A-Za-z_]\w*(?:\.[A-Za-z_]\w*)+(?::[\w.]+)?$")
_STRIP_EXT_RE = re.compile(r"\.(?:js|mjs|cjs|jsx|ts|mts|cts|tsx|py)$")
DYNAMIC_LOADERS = {
    "require", "import", "__import__", "importlib.import_module", "import_module", "runpy.run_path",
    "runpy.run_module", "imp.load_source", "importlib.util.spec_from_file_location", "spec_from_file_location",
}
_LITERAL_ARG_RE = re.compile(r"""^\s*(?:(['"])[^'"]*\1|`[^`$]*`)\s*$""")
MANIFEST_BASES = {".mcp.json", "mcp.json", "plugin.json", "hooks.json", "marketplace.json"}
PKG_RUN_KEYS = ("main", "module", "bin", "exports", "browser")
PKG_RUN_SCRIPTS = INSTALL_KEYS + ("start", "prestart", "poststart", "serve", "server", "mcp")


def _is_skill_doc(rel: str) -> bool:
    return rel.endswith(".md") and (
        _base(rel) == "SKILL.md" or bool(re.search(r"(?:^|/)(?:commands|agents)/", rel))
    )


def _strings_of(obj) -> list[str]:
    if isinstance(obj, str):
        return [obj]
    if isinstance(obj, dict):
        return [s for v in obj.values() for s in _strings_of(v)]
    if isinstance(obj, list):
        return [s for v in obj for s in _strings_of(v)]
    return []


def _manifest_tokens(f: ScanFile) -> list[str] | None:
    """Strings that name what a manifest runs, or None when the file is not a manifest."""
    base = _base(f.rel)
    if base == "package.json":
        try:
            data = json.loads(f.text)
        except ValueError:
            return []
        if not isinstance(data, dict):
            return []
        out = [s for k in PKG_RUN_KEYS for s in _strings_of(data.get(k))]
        scripts = data.get("scripts") if isinstance(data.get("scripts"), dict) else {}
        out += [s for k in PKG_RUN_SCRIPTS for s in _strings_of(scripts.get(k))]
        return out
    if base == "pyproject.toml":
        try:
            data = tomllib.loads(f.text)
        except tomllib.TOMLDecodeError:
            return []
        proj = data.get("project", {}) if isinstance(data.get("project"), dict) else {}
        out = _strings_of(proj.get("scripts")) + _strings_of(proj.get("gui-scripts")) + _strings_of(proj.get("entry-points"))
        poetry = data.get("tool", {}).get("poetry", {}) if isinstance(data.get("tool"), dict) else {}
        return out + _strings_of(poetry.get("scripts") if isinstance(poetry, dict) else None)
    if base in MANIFEST_BASES:
        try:
            return _strings_of(json.loads(f.text))
        except ValueError:
            return [m.group(2) for m in _STRING_RE.finditer(f.text)]
    return None


def _add_ref(refs: set[str], base_dir: str, tok: str) -> None:
    tok = tok.strip().strip("\"'`")
    for word in tok.split():  # "node test/x.js --flag"
        word = word.strip("\"'`")
        if not word or word.startswith("-"):
            continue
        if _DOTTED_RE.match(word) and "/" not in word:
            mod = word.split(":", 1)[0]
            refs.add(mod.replace(".", "/"))
            if not word.endswith(EXEC_EXT):
                continue
        for c in (word.rsplit("}/", 1)[-1], normpath(join(base_dir, word.rsplit("}/", 1)[-1]))):
            refs.add(_STRIP_EXT_RE.sub("", c.removeprefix("./")).rstrip("/"))


@dataclass
class _Refs:
    names: set[str]  # path stems (no extension) named by runtime code, manifests or skill docs
    run: set[str]  # stems named by manifests (what actually gets launched)
    dynamic: bool  # runtime code loads modules by computed name: any file may run


def _runtime_refs(files: list[ScanFile]) -> _Refs:
    refs: set[str] = set()
    run: set[str] = set()
    dynamic = False
    for f in files:
        base_dir = dirname(f.rel)
        manifest = _manifest_tokens(f)
        if manifest is not None:
            for tok in manifest:
                _add_ref(run, base_dir, tok)
            continue
        if _is_test(f.rel) or _is_config_code(f.rel) or _is_data(f.rel) or _base(f.rel) in LOCKFILES:
            continue
        if _is_doc(f.rel):
            if not _is_skill_doc(f.rel):
                continue
            for tok in _PATH_TOKEN_RE.findall(f.text):
                _add_ref(refs, base_dir, tok)
            for m in re.finditer(r"`([^`\n]{1,300})`", f.text):
                _add_ref(refs, base_dir, m.group(1))
            continue
        for tok in _PATH_TOKEN_RE.findall(f.text):
            _add_ref(refs, base_dir, tok)
        for m in _STRING_RE.finditer(f.text):
            _add_ref(refs, base_dir, m.group(2))
        if f.rel.endswith(PY_EXT):
            pkg = base_dir.replace("/", ".")
            for mod, names in _PY_FROM_RE.findall(f.text):
                full = (f"{pkg}{mod}" if mod.startswith(".") and pkg else mod).lstrip(".")
                refs.add(full.replace(".", "/"))
                for nm in re.findall(r"\w+", names):
                    refs.add(f"{full}.{nm}".replace(".", "/"))
            for mod in _PY_IMPORT_RE.findall(f.text):
                refs.add(mod.replace(".", "/"))
        for c in _calls(f.rel, f.text) or ():
            if c.callee in DYNAMIC_LOADERS and c.first_raw and not _LITERAL_ARG_RE.match(c.first_raw):
                dynamic = True
    return _Refs(refs | run, run, dynamic)


def _named(rel: str, stems: set[str]) -> bool:
    stem = _STRIP_EXT_RE.sub("", rel)
    if rel in stems or stem in stems:
        return True
    for idx in ("/index", "/__init__", "/__main__"):
        if stem.endswith(idx) and stem[: -len(idx)] in stems:
            return True
    return False


FILE_READ_RE = re.compile(r"readFileSync|readFile\b|\bopen\(|read_text|read_bytes|\.read\(\)|createReadStream")


def _evals_file_content(f: ScanFile) -> bool:
    """eval / new Function / exec over content read from a file: data files may be code (R27 C2)."""
    for c in _calls(f.rel, f.text) or ():
        if c.callee in EVAL_FUNCS:
            code = c.args if c.callee in ALL_ARGS_EVAL else c.first
            if FILE_READ_RE.search(_STR_LIT_RE.sub('""', code)):
                return True
    return False


# ---------------------------------------------------------------- code rules

STRONG_RULES = ("exfil.combo", "obfuscation.eval-decoded", "remote-code.eval-fetch", "remote-code.download-exec")


@lru_cache(maxsize=64)
def _download_exec(rel: str, text: str) -> tuple[dropper.Hit, ...]:
    """Fetched bytes executed, or written to disk and run / loaded / made executable (dropper.py)."""
    if not rel.endswith(PY_EXT + JS_EXT + TS_EXT):
        return ()
    net = frozenset(p for _, _, p in _net_calls_pos(rel, text, _code_text(rel, text)) if p >= 0)
    if not net:
        return ()
    al = _bindings(rel, text).al
    got = dropper.find(rel, text, net, lambda c: _norm_callee(c, al), al)
    return tuple(got or ())


def _budget_findings(f: ScanFile) -> list[Finding]:
    """What a memory budget did to this file: MED where content went unanalysed, LOW when every call was
    still analysed in degraded form (fix round 1, I3)."""
    if not f.rel.endswith(PY_EXT + JS_EXT + TS_EXT):
        return []
    if _spent(f.rel, f.text):
        return [_finding("files.truncated", Severity.MED, f, None,
                         "call-analysis memory budget for this scan exhausted; regex rules only")]
    if parsing.refused(f.text):
        return [_finding("files.truncated", Severity.MED, f, None,
                         "too large to parse within the memory budget; regex rules only")]
    calls = _calls(f.rel, f.text)
    if getattr(calls, "sink_incomplete", False):  # content a sink runs went unanalysed (fix round 2)
        return [_finding("files.truncated", Severity.MED, f, None,
                         "sink call not fully analysed: call-analysis memory budget exceeded")]
    if _over(calls):
        return [_finding("files.analysis-degraded", Severity.LOW, f, None,
                         "call-analysis memory budget exceeded: some calls analysed unresolved, with capped "
                         "argument text")]
    return []


class CodeRules:
    id = "code"

    def run(self, files: list[ScanFile], extra: list[ExtraText]) -> list[Finding]:
        out: list[Finding] = []
        # A MemoryError (the process limit, bawwab.limits) fails closed for that file only (rules.error,
        # MED); the other files are still analysed.
        failed: list[str] = []
        for f in files:
            try:
                _calls(f.rel, f.text)
            except MemoryError:
                failed.append(f.rel)
        if failed:
            files = [f for f in files if f.rel not in set(failed)]
        install = _install_files(files)
        refs = _runtime_refs(files)
        exec_data = any(
            _evals_file_content(f) for f in files
            if _is_code(f.rel) and not _is_test(f.rel) and not _is_config_code(f.rel)
        )
        for f in files:
            try:
                out.extend(self._file(f, install, refs, exec_data))
            except MemoryError:
                failed.append(f.rel)
            finally:
                proximity._index.cache_clear()  # a bundle's tree is held only while its own file is analysed
        out.extend(Finding("rules.error", Severity.MED, "gate", f"rule code failed on {rel}: MemoryError", file=rel)
                   for rel in failed)
        return out

    def _file(self, f: ScanFile, install: set[str], refs, exec_data: bool) -> list[Finding]:
        out: list[Finding] = []
        hit = _config_index(f.rel, f.text)
        if hit:
            out.append(_finding("install.custom-index", Severity.MED, f, _line_of(f.text, hit[0]),
                                f"installs Python packages from {hit[1][:120]}"))
        if _is_doc(f.rel) or _base(f.rel) in LOCKFILES:
            return out
        if _is_data(f.rel) and not (exec_data or f.rel in install or _named(f.rel, refs.run)):
            return out
        exempt = (
            (_is_test(f.rel) or _is_config_code(f.rel))
            and f.rel not in install and not refs.dynamic and not _named(f.rel, refs.names)
        )
        found = self._analyse(f, f.rel in install)
        if exempt:
            # Test code / config: listed, never decisive on its own (R26b, R27 C2).
            found = [
                Finding(x.rule, Severity.LOW, x.source, x.evidence, file=x.file, line=x.line)
                for x in found if x.rule != "exfil.combo"
            ]
        strong = self._strong(f)
        if exempt:
            # Listed only, so one floor per behaviour: where eval-fetch already marks the line (eval of a fetch
            # in one expression), the flow rule adds nothing.
            ef = {x.line for x in found if x.rule == "remote-code.eval-fetch"}
            found = [x for x in found if not (x.rule == "remote-code.download-exec" and x.line in ef)]
            strong = [(r, ln) for r, ln in strong if not (r == "remote-code.download-exec" and ln in ef)]
        out.extend(_floor(f, found, strong))
        out.extend(_budget_findings(f))  # never downgraded by the exemption: fail closed, whatever the file
        return out

    def _calls_findings(self, f: ScanFile, calls) -> list[Finding]:
        """The call rules, or the regex fallback for an unparsed file. A degraded file gets both: its
        degraded calls are unresolved and capped, which the line-based fallback covers (fix round 2)."""
        if calls is None:
            return self._fallback(f)
        found = self._ast(f, calls) + self._dropper(f)
        if _over(calls):
            seen = {(x.rule, x.line) for x in found}
            found += [x for x in self._fallback(f) if (x.rule, x.line) not in seen]
        return found

    def _analyse(self, f: ScanFile, is_install: bool) -> list[Finding]:
        calls = _calls(f.rel, f.text)
        found = self._calls_findings(f, calls)
        return found + self._text(f, calls, is_install)

    def _strong(self, f: ScanFile) -> list[tuple[str, int]]:
        """Multi-signal behaviour with no context exemption at all (R27 floor)."""
        calls = _calls(f.rel, f.text)
        found = self._calls_findings(f, calls)
        out = [(x.rule, x.line or 1) for x in found if x.rule in STRONG_RULES]
        t, regexes = _code_info(f.rel, f.text)
        # Every credential hit except a regex literal counts, deny-listed or not (R29).
        hits = [p for p, kind in _cred_hits(f, t, regexes) if kind not in ("regex", "prose") and not _write_dest(f, t, p)]
        if hits:
            cred_lines = [_line_of(t, p) for p in hits]
            if _combo_near(f, t, hits, cred_lines, _net_lines(f, t)):
                out.append(("exfil.combo", cred_lines[0]))
            elif _netcap_near(f, t, hits):
                # Backstop (round 3): a credential hit in a file that can reach the network, even
                # when the call itself is hidden behind a wrapper or computed name.
                out.append(("exfil.combo", cred_lines[0]))
        return out

    def _ast(self, f: ScanFile, calls) -> list[Finding]:
        out = []
        for c in calls:
            leaf = c.callee.rsplit(".", 1)[-1]
            if c.callee in EVAL_FUNCS:
                code = c.args if c.callee in ALL_ARGS_EVAL else c.first
                if _decodes(code):
                    out.append(_finding("obfuscation.eval-decoded", Severity.CRITICAL, f, c.line))
                elif FETCH_RE.search(code):
                    out.append(_finding("remote-code.eval-fetch", Severity.HIGH, f, c.line))
            elif c.callee in ("import", "require") and URL_IMPORT_RE.match(c.args):
                out.append(_finding("remote-code.eval-fetch", Severity.HIGH, f, c.line))
            elif leaf in SHELL_FUNCS and CURL_RE.search(c.args) and RUN_RE.search(c.args):
                out.append(_finding("remote-code.eval-fetch", Severity.HIGH, f, c.line))
        return out

    def _dropper(self, f: ScanFile) -> list[Finding]:
        out, seen = [], set()
        for h in _download_exec(f.rel, f.text):
            if h.line in seen:
                continue
            seen.add(h.line)
            sev = Severity.HIGH if h.verified else Severity.CRITICAL
            note = "; what it fetched is checked against a digest or signature first" if h.verified else ""
            out.append(_finding("remote-code.download-exec", sev, f, h.line, h.how + note))
        return out

    def _fallback(self, f: ScanFile) -> list[Finding]:
        out = []
        t = _code_text(f.rel, f.text)
        for rule, sev, rx in (
            ("obfuscation.eval-decoded", Severity.CRITICAL, FB_EVAL_DECODED_RE),
            ("remote-code.eval-fetch", Severity.HIGH, FB_EVAL_FETCH_RE),
        ):
            for m in rx.finditer(t):
                out.append(_finding(rule, sev, f, _line_of(t, m.start())))
        return out

    def _text(self, f: ScanFile, calls, is_install: bool) -> list[Finding]:
        out = []
        raw = f.text
        m = PIPE_SHELL_RE.search(raw)
        if m:
            sev = Severity.CRITICAL if is_install else Severity.HIGH
            out.append(_finding("remote-code.pipe-shell", sev, f, _line_of(raw, m.start())))
        hit = _custom_index(raw)
        if hit:
            out.append(_finding("install.custom-index", Severity.MED, f, _line_of(raw, hit[0]),
                                f"installs Python packages from {hit[1][:120]}"))
        if not f.rel.endswith(".min.js"):
            m = next((m for m in BLOB_RE.finditer(raw) if not m.group(1).isdigit() and not _image_b64(m.group(1))), None)
            if m:
                line = _line_of(raw, m.start())
                out.append(_finding("obfuscation.blob", Severity.MED, f, line, f"{len(m.group(1))}-char encoded literal"))
        t, regexes = _code_info(f.rel, raw)  # comments blanked; regex literal spans for context
        dotenv = DOTENV_RE.search(t)
        hits = _cred_hits(f, t, regexes)
        installs = [pos for pos, kind in _claude_refs(t, f) if kind == "install" and not _context(f, t, pos, regexes)]
        real = [p for p, k in hits if k == "real"]
        denied = [p for p, k in hits if k != "real"]
        comboable = [p for p, k in hits if k not in ("regex", "prose") and not _write_dest(f, t, p)]
        net = _net_calls(f, t)
        net_lines = [ln for ln, _ in net]
        over = next((c for c in _env_copies(f, t) if c.budget), None)
        if over is not None:  # R47 e: the environment flow was not followed to the end, so nothing was bound
            out.append(_finding("files.truncated", Severity.MED, f, over.line, "environment-flow analysis budget exceeded"))
        if real:
            out.append(_finding("credential-access", Severity.HIGH, f, _line_of(t, real[0])))
        elif denied:  # deny-list / regex mention: listed, not decisive on its own (R27 I4, R29)
            out.append(_finding("credential-access", Severity.LOW, f, _line_of(t, denied[0])))
        elif dotenv:
            out.append(_finding("credential-access", Severity.LOW, f, _line_of(t, dotenv.start())))
        if installs:
            lines = [_line_of(t, p) for p in installs]
            writes = [ln for ln in lines if WRITE_RE.search(_line_text(t, ln))]
            exfil_lines = [ln for ln, args in net if EXFIL_HOST_RE.search(args)]
            if writes and _same_scope(f, writes, exfil_lines):
                # Writing into Claude's install dirs next to a call to an exfil-style host. A plain
                # update check to a vendor host is not exfiltration (round 2).
                out.append(_finding("install-dir-access", Severity.MED, f, writes[0]))
            else:
                out.append(_finding("install-dir-access", Severity.LOW, f, lines[0]))
        host = EXFIL_HOST_RE.search(t)
        if host:
            out.append(_finding("exfil.host", Severity.HIGH, f, _line_of(t, host.start())))
        if comboable:  # a deny-listed path read and sent is still exfiltration (R29)
            cred_lines = [_line_of(t, p) for p in comboable]
            if _combo_near(f, t, comboable, cred_lines, net_lines):
                out.append(_finding("exfil.combo", Severity.CRITICAL, f, cred_lines[0]))
        return out


_IMPORT_LINE_RE = re.compile(
    r"^\s*(?:import\s|from\s+[\w.]+\s+import\s|export\s+\*\s+from\s)"
    r"|^\s*(?:const|let|var)\s+[\w${}\s,:]+=\s*require\(\s*['\"][^'\"]+['\"]\s*\)[\s;,]*$"
)


# Outbound network CALLS (rounds 2-4). Callees are normalised first: (0, X) and
# X.call/.apply/.bind become X; roots go through import/require/assignment aliases
# (const {get} = require('https'), import * as H, const f = fetch, import x as y,
# s = requests.Session()). A URL string or the word "fetch" in a literal is not a call.
# Round 4 (R30c): a module-based callee counts only when its root is bound to a network
# module imported or required in the file; a handler parameter named `request`, `ws` or
# `socket` is not a network client.
NET_GLOBALS = {"fetch", "XMLHttpRequest", "WebSocket", "EventSource", "navigator.sendBeacon"}  # JS/TS globals
NET_MODULES = {
    "http", "https", "http2", "net", "tls", "dgram", "dns", "undici", "node-fetch", "axios", "got", "ky",
    "superagent", "needle", "request", "ws", "websocket", "requests", "httpx", "aiohttp", "urllib3", "socket",
    "http.client", "urllib.request", "urllib2", "ftplib", "smtplib", "websockets", "pycurl",
}
NOT_NET_LEAVES = {"createServer", "Server", "STATUS_CODES", "HTTPStatus", "METHODS", "Agent", "globalAgent",
                  "parse", "format", "quote", "unquote", "urlencode", "exceptions", "codes"}
SERVER_SIDE = {"createServer", "Server", "STATUS_CODES", "METHODS", "HTTPStatus", "HTTPServer", "ThreadingHTTPServer",
               "BaseHTTPRequestHandler", "SimpleHTTPRequestHandler", "server", "cookies", "cookiejar"}
# Members of a network module that cannot reach out: a local server, constants, parsers (R30b).
NONCAP_MEMBERS = SERVER_SIDE | NOT_NET_LEAVES | {"listen", "error", "IncomingMessage", "ServerResponse"}
_MOD = r"""['"](?:node:)?([\w@/.-]+)['"]"""
_LOAD = r"""(?:await\s+)?(?:require|import)\(\s*"""
_JS_ALIAS_RES = (
    (re.compile(r"([\w$]+)\s*=\s*" + _LOAD + _MOD + r"\s*\)(?!\s*\.)"), "mod"),
    (re.compile(r"([\w$]+)\s*=\s*" + _LOAD + _MOD + r"\s*\)\s*\.\s*([\w$]+)"), "member"),
    (re.compile(r"\{([^{}]*)\}\s*=\s*" + _LOAD + _MOD + r"\s*\)"), "destructure"),
    (re.compile(r"import\s+([\w$]+)\s*(?:,\s*\{[^}]*\})?\s*from\s*" + _MOD), "mod"),
    (re.compile(r"import\s+\*\s+as\s+([\w$]+)\s+from\s*" + _MOD), "mod"),
    (re.compile(r"import\s+([\w$]+)\s*=\s*require\(\s*" + _MOD), "mod"),
    (re.compile(r"import\s*(?:[\w$]+\s*,\s*)?\{([^}]*)\}\s*from\s*" + _MOD), "named"),
)
_JS_MODS_RE = re.compile(r"""\b(?:require|import)\s*\(\s*""" + _MOD + r"""\s*\)|\bfrom\s*""" + _MOD + r"""|^\s*import\s*""" + _MOD, re.M)
_JS_ASSIGN_RE = re.compile(r"(?:const|let|var)\s+([\w$]+)\s*=\s*(?:await\s+)?(?:new\s+)?([\w$.]+)\s*(?=[(;,\n]|$)", re.M)
_PY_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(?:await\s+)?([A-Za-z_][\w.]*)\s*(?=\(|$)", re.M)
_PY_IMPORT_LIST_RE = re.compile(r"^\s*import\s+([\w.]+(?:\s+as\s+\w+)?(?:\s*,\s*[\w.]+(?:\s+as\s+\w+)?)*)", re.M)
_PY_FROM_IMPORT_RE = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+\(?([^)\n]+)", re.M)


@dataclass(frozen=True)
class _Bindings:
    al: dict  # name -> what it stands for (module path, function path or instance root)
    mods: frozenset  # module specifiers imported or required anywhere in the file
    modbind: dict  # name -> module, for names bound to a whole module (import x / x = require('m'))
    members: tuple  # (module, member) bound by destructuring, named imports or from-imports


def _dotted(node) -> str | None:
    if isinstance(node, ast.Call):
        node = node.func
    if isinstance(node, (ast.Name, ast.Attribute)):
        try:
            return ast.unparse(node)
        except MemoryError:
            raise
        except Exception:  # noqa: BLE001
            return None
    return None


def _literal_import(node) -> str | None:
    """'m' for importlib.import_module('m') / import_module('m') / __import__('m')."""
    if (
        isinstance(node, ast.Call) and node.args and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str) and _dotted(node.func) in ("importlib.import_module", "import_module", "__import__")
    ):
        return node.args[0].value
    return None


def _py_bindings(text: str) -> _Bindings:
    al: dict[str, str] = {}
    mods: set[str] = set()
    modbind: dict[str, str] = {}
    members: list[tuple[str, str]] = []
    try:
        tree = parsing.py_parse(text)
        for n in ast.walk(tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    mods.add(a.name)
                    name = a.asname or a.name.split(".")[0]
                    al[name] = a.name if a.asname else name
                    modbind[name] = a.name
            elif isinstance(n, ast.ImportFrom) and n.module and not n.level:
                mods.add(n.module)
                for a in n.names:
                    al[a.asname or a.name] = f"{n.module}.{a.name}"
                    members.append((n.module, a.name))
            elif isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                lit = _literal_import(n.value)
                if lit:  # m = importlib.import_module('requests'): m is that module (round 5)
                    mods.add(lit)
                    al[n.targets[0].id] = lit
                    modbind[n.targets[0].id] = lit
                    continue
                v = _dotted(n.value)
                if v:
                    al.setdefault(n.targets[0].id, v)
            elif isinstance(n, (ast.With, ast.AsyncWith)):
                for item in n.items:
                    v = _dotted(item.context_expr)
                    if v and isinstance(item.optional_vars, ast.Name):
                        al.setdefault(item.optional_vars.id, v)
    except (SyntaxError, ValueError, RecursionError):
        for group in _PY_IMPORT_LIST_RE.findall(text):
            for part in group.split(","):
                bits = part.split()
                if bits:
                    mods.add(bits[0])
                    name = bits[-1] if len(bits) == 3 else bits[0].split(".")[0]
                    al[name] = bits[0] if len(bits) == 3 else name
                    modbind[name] = bits[0]
        for mod, names in _PY_FROM_IMPORT_RE.findall(text):
            mods.add(mod)
            for part in names.split(","):
                bits = part.strip().split()
                if bits and re.fullmatch(r"\w+", bits[0]):
                    al[bits[-1] if len(bits) == 3 and bits[1] == "as" else bits[0]] = f"{mod}.{bits[0]}"
                    members.append((mod, bits[0]))
        for name, val in _PY_ASSIGN_RE.findall(text):
            al.setdefault(name, val)
    return _Bindings(al, frozenset(mods), modbind, tuple(members))


@lru_cache(maxsize=512)
def _bindings(rel: str, text: str) -> _Bindings:
    if rel.endswith(PY_EXT):
        return _py_bindings(text)
    al: dict[str, str] = {}
    modbind: dict[str, str] = {}
    members: list[tuple[str, str]] = []
    for rx, kind in _JS_ALIAS_RES:
        for m in rx.finditer(text):
            target, mod = m.group(1), m.group(2)
            if kind == "mod":
                al[target] = mod
                modbind[target] = mod
                continue
            if kind == "member":  # const get = require('https').get
                al[target] = f"{mod}.{m.group(3)}"
                members.append((mod, m.group(3)))
                continue
            for part in target.split(","):
                part = part.strip()
                if not part:
                    continue
                sep = ":" if kind == "destructure" else " as "
                src, _, dst = part.partition(sep)
                src, dst = src.strip(), (dst.strip() or src.strip())
                if re.fullmatch(r"[\w$]+", src) and re.fullmatch(r"[\w$]+", dst):
                    al[dst] = f"{mod}.{src}"
                    members.append((mod, src))
    for name, val in _JS_ASSIGN_RE.findall(text):
        al.setdefault(name, val)
    mods = {g for m in _JS_MODS_RE.finditer(text) for g in m.groups() if g}
    return _Bindings(al, frozenset(mods), modbind, tuple(members))


def _aliases(rel: str, text: str) -> dict[str, str]:
    """name -> what it stands for (module path, function path or instance root)."""
    return _bindings(rel, text).al


_ZERO_COMMA_RE = re.compile(r"^\(\s*0\s*,\s*([\w$.]+)\s*\)$")
_GETATTR_RE = re.compile(r"""^getattr\(\s*([\w.]+)\s*,\s*['"](\w+)['"]\s*\)$""")
_INLINE_LOAD_RE = re.compile(r"""^(?:await\s+)?\(?\s*(?:require|import|__import__)\(\s*['"](?:node:)?([\w@/.-]+)['"]\s*\)\s*\)?""")


def _norm_callee(callee: str, al: dict[str, str]) -> str:
    c = callee.strip()
    for _ in range(4):
        prev = c
        m = _ZERO_COMMA_RE.match(c) or _GETATTR_RE.match(c)
        if m:
            c = m.group(1) + ("." + m.group(2) if m.lastindex == 2 else "")
        c = _INLINE_LOAD_RE.sub(lambda mm: mm.group(1), c)  # require('https').request -> https.request
        c = re.sub(r"\.(?:call|apply|bind)$", "", c)
        c = re.sub(r"^(?:window|globalThis|self|global)\.", "", c)
        root, dot, rest = c.partition(".")
        if root in al and al[root] != root:
            c = al[root] + (dot + rest if rest else "")
        c = re.sub(r"^(?:node:)", "", c)
        if c == prev:
            break
    return c


def _is_net_callee(callee: str) -> bool:
    """A call into a network module (by its normalised path). Globals are checked separately."""
    parts = callee.split(".")
    if parts[-1] in NOT_NET_LEAVES or SERVER_SIDE & set(parts):
        return False  # a local server (and calls on it) is not an outbound call
    return parts[0] in NET_MODULES or ".".join(parts[:2]) in NET_MODULES


def _net_mod(mod: str) -> bool:
    """A module (or from-import path) through which code can reach out."""
    parts = mod.split(".")
    return not (NONCAP_MEMBERS & set(parts[1:])) and (parts[0] in NET_MODULES or ".".join(parts[:2]) in NET_MODULES)


def _imported(callee: str, mods) -> bool:
    return any(callee == m or callee.startswith(m + ".") for m in mods)


def _is_global_net(callee: str, rel: str) -> bool:
    return rel.endswith(JS_EXT + TS_EXT) and (callee in NET_GLOBALS or callee.split(".")[0] in NET_GLOBALS)


# Loopback is exempt only for a single plain literal whose host ends right there (round 3).
_LOOPBACK_LIT_RE = re.compile(
    r"""^\s*(['"`])(?:https?|wss?)://(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\])(?=[:/?#]|\1)(?:(?!\1)[^\\\s\x00-\x1f$])*\1\s*$""",
    re.I,
)


def _loopback_only(first_raw: str) -> bool:
    return bool(_LOOPBACK_LIT_RE.match(first_raw)) and "@" not in first_raw


def _net_calls(f: ScanFile, t: str) -> tuple[tuple[int, str], ...]:
    return _net_calls_cached(f.rel, f.text, t)


_HOST_SCAN = 4000  # an exfil host deep inside a huge argument (a bundle's IIFE) is exfil.host anyway


def _host_in(args: str) -> bool:
    """An exfil host in the first or last _HOST_SCAN chars of a call's arguments (review N6)."""
    if len(args) <= 2 * _HOST_SCAN:
        return EXFIL_HOST_RE.search(args) is not None
    return EXFIL_HOST_RE.search(args, 0, _HOST_SCAN) is not None or EXFIL_HOST_RE.search(args, len(args) - _HOST_SCAN) is not None


@lru_cache(maxsize=8)  # holds the texts: keep it small
def _net_calls_cached(rel: str, text: str, t: str) -> tuple[tuple[int, str], ...]:
    return tuple((ln, args) for ln, args, _ in _net_calls_pos(rel, text, t))


@lru_cache(maxsize=8)
def _net_calls_pos(rel: str, text: str, t: str) -> tuple[tuple[int, str, int], ...]:
    """(line, argument text) of outbound network calls.

    Parsed files: real call nodes to a network global, or to a network module bound in the
    file, after alias normalisation (or any call carrying an exfil host), except a call whose
    URL argument is one plain loopback literal. Unparsed files (shell...): the regex
    fallback, minus bare import lines.
    """
    f = ScanFile(rel, text)
    calls = _calls(f.rel, f.text)
    if calls is not None:
        b = _bindings(f.rel, f.text)
        out = []
        for c in calls:
            callee = _norm_callee(c.callee, b.al)
            leaf = callee.rsplit(".", 1)[-1]
            raw_root = _norm_callee(c.callee, {}).split(".", 1)[0]
            # an import/require binding (or require('m').x inline), not a parameter named like a module
            bound = raw_root in b.al or bool(_INLINE_LOAD_RE.match(c.callee.strip()))
            is_net = (
                _is_global_net(callee, f.rel)
                or (bound and _is_net_callee(callee) and _imported(callee, b.mods))
                or (leaf in SHELL_FUNCS and CURL_RE.search(c.args))
            )
            if (is_net and not _loopback_only(c.first_raw)) or _host_in(c.args):
                out.append((c.line, c.args, c.pos))
        return tuple(out)
    out = []
    for rx in (NET_RE, EXFIL_HOST_RE):
        for m in rx.finditer(t):
            ln = _line_of(t, m.start())
            line = _line_text(t, ln)
            if not _IMPORT_LINE_RE.search(line):
                out.append((ln, line, -1))
    return tuple(out)


def _net_lines(f: ScanFile, t: str) -> list[int]:
    return [ln for ln, _ in _net_calls(f, t)]


# Floor backstop (rounds 3-4, R30b): code loaded or looked up by computed name, a network
# global referenced anywhere, or a network module with any use other than a local server.
COMPUTED_LOAD_RE = re.compile(
    r"""(?<![\w$.])require\(\s*(?!['"`][^'"`$]*['"`]\s*\))|(?<![\w$.])import\(\s*(?!['"`][^'"`$]*['"`]\s*\))"""
    r"""|\b(?:globalThis|window|global|self)\[\s*(?!['"][^'"]*['"]\s*\])"""
    r"""|\bgetattr\(\s*(?:__builtins__|builtins)\b|\b__import__\(|\bimportlib\.import_module\(\s*(?!['"][^'"]*['"]\s*\))"""
)
_NET_GLOBAL_USE_RE = re.compile(
    r"(?<![\w$.])(?:fetch|XMLHttpRequest|WebSocket|EventSource)\b(?!\s*:(?!:))"
    r"|\b(?:globalThis|window|global|self)\s*\??\.\s*(?:fetch|XMLHttpRequest|WebSocket|EventSource)\b"
    r"|\bnavigator\s*\??\.\s*sendBeacon\b"
)
_NET_GLOBAL_KEY_RE = re.compile(
    r"""\b(?:globalThis|window|global|self|navigator)\s*\[\s*(['"])(?:fetch|XMLHttpRequest|WebSocket|EventSource|sendBeacon)\1"""
)
_INLINE_REQ_RE = re.compile(r"""\b(?:require|import)\(\s*['"](?:node:)?([\w@/.-]+)['"]\s*\)((?:\s*\??\.\s*[\w$]+)*)""")
_CHAIN_RE = re.compile(r"(?:\s*\??\.\s*[\w$]+)+")


@lru_cache(maxsize=512)
def _strings_blanked(rel: str, t: str) -> str:
    """t with string-literal contents replaced by spaces (newlines kept; for analysis on its own)."""
    if rel.endswith(PY_EXT):
        try:
            starts = [0]
            for line in t.split("\n"):
                starts.append(starts[-1] + len(line) + 1)
            kinds = {tokenize.STRING, getattr(tokenize, "FSTRING_MIDDLE", -1), getattr(tokenize, "TSTRING_MIDDLE", -1)}
            spans = []
            for tok in tokenize.generate_tokens(io.StringIO(t).readline):
                if tok.type in kinds:
                    (r1, c1), (r2, c2) = tok.start, tok.end
                    spans.append((starts[r1 - 1] + c1, starts[r2 - 1] + c2))
            out = _blank(t, spans)
            if len(out) == len(t):
                return out
        except MemoryError:
            raise
        except Exception:  # noqa: BLE001
            pass
    elif rel.endswith(JS_EXT + TS_EXT):
        try:  # string bodies and template text, keeping ${...} substitutions
            src = t.encode()
            spans, stack = [], [parsing.js_root(src, _js_lang(rel))]
            while stack:
                n = stack.pop()
                if n.type in ("string_fragment", "escape_sequence", "regex_pattern"):
                    spans.append((n.start_byte, n.end_byte))
                else:
                    stack.extend(n.children)
            # Lines are kept; character offsets may shift on multi-byte text, so callers use only this text.
            return _blank_bytes(src, spans).decode("utf-8", "replace")
        except MemoryError:
            raise
        except Exception:  # noqa: BLE001
            pass

    def blank(m: re.Match) -> str:
        s = m.group(0)
        return s[0] + re.sub(r"[^\n]", " ", s[1:-1]) + s[-1]

    return _STR_LIT_RE.sub(blank, t)


def _noncap_chain(chain: str) -> bool:
    return bool(NONCAP_MEMBERS & set(re.findall(r"[\w$]+", chain)))


def _network_capable(f: ScanFile, t: str) -> bool:
    """The file can reach the network somewhere (R30b): code loaded or looked up by computed
    name; a network global (fetch, XMLHttpRequest, WebSocket, EventSource, sendBeacon)
    referenced at all; or a network module with any use other than a local server. Passing
    the module as a value, destructuring it or binding its functions counts as a use."""
    if COMPUTED_LOAD_RE.search(t):
        return True
    js = f.rel.endswith(JS_EXT + TS_EXT)
    tb = _strings_blanked(f.rel, t)
    if js and _NET_GLOBAL_KEY_RE.search(t):
        return True
    if js:
        uses = Counter(tb.count("\n", 0, m.start()) + 1 for m in _NET_GLOBAL_USE_RE.finditer(tb))
        # A direct call with one plain loopback literal (fetch('http://127.0.0.1:8765/rpc')) cannot
        # reach out; any other reference (a call elsewhere, a value, a constructor) can.
        loop = Counter(
            c.line for c in _calls(f.rel, f.text) or ()
            if _norm_callee(c.callee, {}) in NET_GLOBALS and _loopback_only(c.first_raw)
        )
        if any(n > loop.get(ln, 0) for ln, n in uses.items()):
            return True
    b = _bindings(f.rel, f.text)
    if any(_net_mod(mod) and member not in NONCAP_MEMBERS for mod, member in b.members):
        return True  # const {request} = require('https') / from urllib.request import urlopen
    if js:
        for m in _INLINE_REQ_RE.finditer(t):
            if not _net_mod(m.group(1)):
                continue
            prefix = t[t.rfind("\n", 0, m.start()) + 1 : m.start()]
            if not m.group(2) and re.search(r"[\w$}]\s*=\s*(?:await\s+)?$", prefix):
                continue  # a binding (x = require('https') / {a} = require(...)): checked through its uses
            if not _noncap_chain(m.group(2) or ""):
                return True  # require('https').request(...), use(require('https'))
    for name, mod in b.modbind.items():
        if not _net_mod(mod):
            continue
        for m in re.finditer(rf"(?<![\w$.]){re.escape(name)}(?![\w$])", tb):
            line_start = tb.rfind("\n", 0, m.start()) + 1
            line = tb[line_start : tb.find("\n", m.end()) if "\n" in tb[m.end():] else len(tb)]
            if re.match(r"\s*(?:import|from)\b", line):
                continue  # the import statement itself
            if re.match(r"\s*=\s*(?:await\s+)?(?:require|import)\s*\(", tb[m.end() : m.end() + 40]):
                continue  # x = require('m'): the binding itself
            chain = _CHAIN_RE.match(tb, m.end())
            if chain and _noncap_chain(chain.group(0)):
                continue  # http.createServer(...), urllib.parse.quote(...): cannot reach out
            return True
    return False


# '.ssh' followed by any further segment in a join (round 5): path.join(home, '.ssh', name),
# Path.home() / '.ssh' / name, '.ssh' + '/' + name. A plain list ['.ssh', '.gnupg'] is not a join.
SSH_JOIN_RE = re.compile(
    r"""(?:\bpath\.(?:join|resolve)|\bos\.path\.join|\bjoinpath|\bPath)\s*\((?:[^()]|\([^()]*\))*?['"`](\.ssh)['"`]\s*,\s*[^\s)]"""
    r"""|['"`](\.ssh)['"`]\s*[/+]\s*[\w$'"`(]"""
)


# ---------------------------------------------------------------- environment copies (R45)
# Whole-environment copies, launchers and their bindings are read on the syntax tree (envflow.py):
# comments and strings never bind, casts / parens / position do not matter, and a reassigned or
# patched launcher binding or module is no launcher.


def _is_net_call(f: ScanFile, callee_raw: str, args: str, first_raw: str) -> bool:
    """One call is outbound: the same test _net_calls applies to every parsed call."""
    b = _bindings(f.rel, f.text)
    callee = _norm_callee(callee_raw, b.al)
    leaf = callee.rsplit(".", 1)[-1]
    raw_root = _norm_callee(callee_raw, {}).split(".", 1)[0]
    # an import/require binding (or require('m').x inline), not a parameter named like a module
    bound = raw_root in b.al or bool(_INLINE_LOAD_RE.match(callee_raw.strip()))
    is_net = (
        _is_global_net(callee, f.rel)
        or (bound and _is_net_callee(callee) and _imported(callee, b.mods))
        or (leaf in SHELL_FUNCS and CURL_RE.search(args))
    )
    return bool(is_net and not _loopback_only(first_raw)) or _host_in(args)


@lru_cache(maxsize=16)
def _env_copies_cached(rel: str, text: str, t: str) -> tuple[envflow.EnvCopy, ...] | None:
    f = ScanFile(rel, text)
    _bindings(rel, text)  # parsed before the envflow budget's clock starts (R47 e): the callback only looks up
    return envflow.env_copies(rel, t, lambda c, a, fr: _is_net_call(f, c, a, fr))


def _env_copies(f: ScanFile, t: str) -> tuple[envflow.EnvCopy, ...]:
    """Copies of the environment on the tree, or (unparseable file) every regex hit as unbound (R45 5)."""
    if f.rel.endswith(PY_EXT + JS_EXT + TS_EXT):
        got = _env_copies_cached(f.rel, f.text, t)
        if got is not None:
            return got
    out = []
    for rx, family in ((ENV_COPY_RE, "old"), (SPREAD_COPY_RE, "spread")):
        for m in rx.finditer(t):
            out.append(envflow.EnvCopy(m.start(), _line_of(t, m.start()), family, False, False))
    return tuple(out)


def _launcher(f: ScanFile, callee: str) -> bool:
    """A real process launcher by its callee text, resolved at module level (R42 N3, R45 2)."""
    return envflow.launcher_text(f.rel, _code_text(f.rel, f.text), callee)


# ---------------------------------------------------------------- credential-path precision (FP plan step 3)
# A credential pattern counts where code refers to a credential FILE, not where the token is part of a name,
# a sentence or a list that keeps secrets out. Applied to a pattern hit that no deny-list / regex context
# (_context) lowered already.
# * The dotenv pattern (patterns.json "name": "dotenv") is the noisy one: a module (from .env import x), a
#   method or property (.env("MCP_PROXY"), $.env.X, conn.env), help text ("create a .env file") and
#   templates (.env.example, excluded in patterns.json) are no secret file: no hit at all. In code (and JSON)
#   a .env counts only inside a string literal, as a path or as a shell argument (cat .env, curl -d @.env).
# * The project's own .env (bare, ./, a relative path, or joined to cwd / __dirname / __file__ / a *root*,
#   project or package dir) is "own": loading your own configuration is what every dotenv loader does
#   (DOTENV_RE is LOW already), so it is LOW alone. Like a deny-list entry it still counts for the combo and
#   the network backstop: a project .env read and sent out is theft all the same.
# * A .env under the home directory, behind a glob, at an absolute path or joined to an unknown directory
#   stays "real" (HIGH), as before.
# * Any credential literal that is only compared or tested for membership (x === '.netrc',
#   name in ('.npmrc', ...), [...].includes(base)), a Claude permission rule inside a deny list
#   (Read(~/.ssh/**)), or a line of an ignore-style file (.mcpbignore, _.gitignore, .worktreeinclude) is
#   "deny": LOW alone, still combo-eligible (R29).
_LIT_PY_RE = re.compile(
    r"[rRbBuUfF]{0,2}(?:'''(?:\\.|[^\\])*?'''" + r'|"""(?:\\.|[^\\])*?"""'
    + r"""|'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*")"""
)
_LIT_JS_RE = re.compile(r"""'(?:\\.|[^'\\\n])*'|"(?:\\.|[^"\\\n])*"|`(?:\\.|[^`\\])*`""")
_PROJECT_ANCHOR_RE = re.compile(
    r"__dirname|__file__|import\.meta|cwd|\bPWD\b|root|project|repo|\bpkg|package|\bapp_?dir|base_?dir"
    r"|script_?dir|\bhere\b",
    re.I,
)
_ROOT_HOME_RE = re.compile(r"(?:^|[\s'\"`=:(])/root(?:/|$)")
_SHELL_READ_WORDS = frozenset({
    "cat", "source", ".", "cp", "mv", "scp", "rsync", "tar", "zip", "base64", "curl", "wget", "xxd", "od", "head",
    "tail", "less", "more", "grep", "awk", "sed", "strings", "gpg", "openssl", "nc", "type", "Get-Content", "gc", "<",
})
_ENV_FLAG_RE = re.compile(r"^-{1,2}(?:env-file|env_file|dotenv|env)$")
_PERMISSION_RULE_RE = re.compile(
    r"""[rRbBuUfF]{0,2}['"`]\s*(?:Read|Edit|Write|MultiEdit|Bash|Grep|Glob|LS|NotebookRead|NotebookEdit|WebFetch)\("""
)
_ALLOW_KEY_RE = re.compile(r"allow|permit|grant|approv|trust", re.I)
IGNORE_LIST_RE = re.compile(r"^(?:[\w-]*\.)?[\w-]*ignore$|^\.?worktreeinclude$", re.I)
_MATCH_HEAD_RE = re.compile(
    r"(?:[!=]==?|\bnot\s+in|\bin)\s*$"
    r"|\.\s*(?:startswith|endswith|startsWith|endsWith|includes|__contains__|equals|equalsIgnoreCase)\s*\(\s*$"
    r"|\bfnmatch(?:case)?\s*\([^()\n]*,\s*$"
)
_MATCH_TAIL_RE = re.compile(r"\s*(?:[!=]==?(?!>)|(?:not\s+)?in\b(?!\s*\())")
_FOR_IN_RE = re.compile(r"\bfor\b[^\n;:]*\bin\s*$")
_BRACKET_TEST_RE = re.compile(r"\s*\.\s*(?:includes|indexOf|some|has|__contains__)\s*\(")
_JOIN_CALL_TAIL_RE = re.compile(r"(?:\bjoin|\bresolve|\bjoinpath|\bjoinPath|\bPath|\bjoin_paths?)\s*$")
_ASSIGN_SPLIT_RE = re.compile(r"(?<![=!<>])=(?![=>])|\breturn\b")


def _literal_mode(rel: str) -> str | None:
    if rel.endswith(PY_EXT):
        return "py"
    if rel.endswith(JS_EXT + TS_EXT + (".json", ".jsonc")):
        return "js"
    return None


@lru_cache(maxsize=64)
def _literal_spans(rel: str, t: str, regexes: tuple, aligned: bool) -> tuple[list[int], list[int]]:
    """Sorted (starts, ends) of the string literals in comment-blanked code (lexical, so linear). `aligned`:
    the regex-literal spans index `t` (no multi-byte comment was blanked), so a quote inside one is skipped."""
    rx = _LIT_PY_RE if _literal_mode(rel) == "py" else _LIT_JS_RE
    if regexes and aligned:
        t = _blank(t, list(regexes))
    starts, ends = [], []
    for m in rx.finditer(t):
        starts.append(m.start())
        ends.append(m.end())
    return starts, ends


def _enclosing_literal(spans: tuple[list[int], list[int]], pos: int) -> tuple[int, int] | None:
    starts, ends = spans
    i = bisect_right(starts, pos) - 1
    return (starts[i], ends[i]) if i >= 0 and pos < ends[i] else None


def _word_at(t: str, lo: int, hi: int, pos: int, end: int) -> tuple[int, int]:
    """The run of non-space, non-quote characters around [pos, end), within [lo, hi)."""
    a, b = pos, end
    while a > lo and not t[a - 1].isspace() and t[a - 1] not in "'\"`":
        a -= 1
    while b < hi and not t[b].isspace() and t[b] not in "'\"`":
        b += 1
    return a, b


def _open_bracket(t: str, pos: int) -> int | None:
    depth = 0
    for i in range(pos - 1, max(-1, pos - 2000), -1):
        ch = t[i]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if not depth:
                return i
            depth -= 1
    return None


def _only_matched(t: str, a: int, b: int) -> bool:
    """The literal (or word) at [a, b) is only compared or tested for membership: a check, not a read."""
    head = t[max(0, a - 120) : a]
    if (_MATCH_HEAD_RE.search(head) and not _FOR_IN_RE.search(head)) or _MATCH_TAIL_RE.match(t, b):
        return True
    o = _open_bracket(t, a)
    if o is None:
        return False
    head = t[max(0, o - 120) : o]
    if re.search(r"\b(?:not\s+)?in\s*$", head) and not _FOR_IN_RE.search(head):
        return True  # name in ('a', 'b')
    return bool(_BRACKET_TEST_RE.match(t, _close_of(t, o)))  # ['a', 'b'].includes(name)


def _join_anchor(t: str, lit_start: int) -> str:
    """The directory expression a literal is joined to (path.join(X, lit), X / lit, X + lit), or ""."""
    line_start = max(t.rfind("\n", 0, lit_start) + 1, lit_start - 300)
    pre = t[line_start:lit_start]
    m = re.search(r"[/+]\s*$", pre)
    if m:
        return _ASSIGN_SPLIT_RE.split(pre[: m.start()])[-1] or " "
    pre = t[max(0, lit_start - 300) : lit_start]
    if not re.search(r",\s*$", pre):
        return ""
    depth = 0
    for i in range(len(pre) - 1, -1, -1):
        ch = pre[i]
        if ch in ")]}":
            depth += 1
        elif ch in "([{":
            if depth:
                depth -= 1
                continue
            return pre[i + 1 :] if ch == "(" and _JOIN_CALL_TAIL_RE.search(pre, 0, i) else ""
    return ""


def _dotenv_anchor_kind(prefix: str, anchor: str) -> str:
    where = prefix + " " + anchor
    if "*" in prefix or HOME_RE.search(where) or _ROOT_HOME_RE.search(where):
        return "real"  # a glob harvests every one; under the home directory it is the user's, not the project's
    if anchor.strip():
        return "own" if _PROJECT_ANCHOR_RE.search(anchor) else "real"
    if re.search(r"\$\{?\w", prefix) or re.match(r"(?:[A-Za-z]:)?[\\/]", prefix):
        return "own" if _PROJECT_ANCHOR_RE.search(prefix) else "real"
    return "own"  # bare, ./ or relative: inside the project


def _dotenv_kind(t: str, pos: int, end: int, lit: tuple[int, int] | None, in_code: bool) -> str | None:
    if t[pos - 1 : pos] in ("$", ")", "]"):
        return None  # $.env.X, f().env, a[0].env: a property
    if lit is None:
        if in_code:
            return None  # code outside a string literal: a module, method or property name
        if re.match(r"\s*\(", t[end : end + 20]) or re.search(r"\bfrom\s+\.*$", t[max(0, pos - 40) : pos]):
            return None
        lo, hi = max(0, pos - 300), min(len(t), end + 300)
    else:
        lo, hi = lit
    a, b = _word_at(t, lo, hi, pos, end)
    word, head = t[a:b], t[a:pos]
    if head.endswith("\\") or "|" in word or word.startswith("^") or re.search(r"\$(?:$|\))", word):
        return "deny"  # a pattern string: a matcher, not a path
    prefix = re.split(r"[=@,;]|:-", head)[-1]
    bare = prefix in ("", "./", "/")
    if lit is not None and bare and re.search(r"\s", t[lit[0] : lit[1]]):
        words = t[lo:a].split()
        prev = words[-1].strip("'\"`") if words else ""
        if "@" in head or prev in _SHELL_READ_WORDS:
            return "real"  # a shell command reading it: cat .env, curl -d @.env
        if "=" in head or _ENV_FLAG_RE.match(prev):
            return "own"  # node --env-file=.env
        return None  # prose: "add the key to your .env file"
    anchor = _join_anchor(t, lit[0]) if lit is not None and bare else ""
    if prefix == "/" and not anchor:
        return "real"  # an absolute path at the root
    return _dotenv_anchor_kind(prefix, anchor)


def _precise_kind(f: ScanFile, t: str, m: re.Match, regexes) -> str | None:
    """"real", "own", "deny", or None (no credential file at all) for a credential-pattern hit."""
    mode = _literal_mode(f.rel)
    if mode is None and IGNORE_LIST_RE.match(_base(f.rel)):
        return "deny"
    pos, end = m.start(), m.end()
    lit = None
    if mode is not None:
        lit = _enclosing_literal(_literal_spans(f.rel, t, tuple(regexes), len(t) == len(f.text)), pos)
    if lit is not None and _PERMISSION_RULE_RE.match(t, lit[0]):
        kind = _context(f, t, lit[0], regexes)  # Read(~/.ssh/**) inside a deny list
        if kind:
            return kind
        # A permission rule names what Claude may or may not do; the code holding it reads nothing. Only an allow
        # list widens access (FP round 2): `SECRET_READ_DENY = "Read(**/.env)"`, a rule in a test's loop, are "deny".
        o = _open_bracket(t, lit[0])
        head = t[max(0, (o if o is not None else lit[0]) - 120) : o if o is not None else lit[0]]
        if not _ALLOW_KEY_RE.search(head):
            return "deny"
    kind = "real"
    if m.group("dotenv") is not None:
        kind = _dotenv_kind(t, pos, end, lit, mode is not None)
        if kind in (None, "deny"):
            return kind
    a, b = lit or _word_at(t, max(0, pos - 300), min(len(t), end + 300), pos, end)
    return "deny" if _only_matched(t, a, b) else kind


# ---------------------------------------------------------------- write destinations (FP round 2)
# Exfiltration reads a secret and sends it. A credential path that is only the DESTINATION of a write, a mkdir or a
# delete (a test fixture writing join(root, ".env"), `printf ... > "$HOME/x/.env"`) is no source for a combo or the
# network backstop. It is still a credential-access finding (writing into ~/.ssh is its own attack).
_DEST_LEAVES = {
    "writeFile", "writeFileSync", "appendFile", "appendFileSync", "outputFile", "outputFileSync", "writeJson",
    "writeJsonSync", "outputJson", "outputJsonSync", "mkdir", "mkdirSync", "mkdirp", "ensureDir", "ensureDirSync",
    "rm", "rmSync", "unlink", "unlinkSync", "rmdir", "rmdirSync", "truncate", "truncateSync", "makedirs", "remove",
}
_JOIN_LEAVES = {"join", "resolve", "Path", "joinpath", "PurePath", "expanduser"}
_DEST_TAIL_RE = re.compile(
    r"""(?:\s*/\s*[frbu]?(['"])[^'"\n]{0,200}\1)*\s*\)*\s*\.\s*(?:write_text|write_bytes|touch|mkdir|unlink|rmdir)\s*\("""
)
_SHELL_DEST_RE = re.compile(r"""(?:^|[^>&0-9<])>>?\s*['"]?[^\s'"<>|;&]*$|\b(?:mkdir|rm|touch)\s+(?:-\w+\s+)*['"]?[^\s'"<>|;&]*$""")


def _write_dest(f: ScanFile, t: str, pos: int) -> bool:
    """The credential path at pos is only where something is written, created or deleted (see above)."""
    if f.rel.endswith((".sh", ".bash", ".zsh")):
        ls = t.rfind("\n", 0, pos) + 1
        return _SHELL_DEST_RE.search(t[ls:pos]) is not None
    if not f.rel.endswith(PY_EXT + JS_EXT + TS_EXT):
        return False
    lit = re.match(r"""[^'"`\n]*['"`]""", t[pos : pos + 400])  # to the end of the string literal holding pos
    end = pos + (lit.end() if lit else 0)
    if f.rel.endswith(PY_EXT) and _DEST_TAIL_RE.match(t, end):
        return True  # (root / ".env").write_text(...)
    i = pos
    for _ in range(4):  # out through path builders: writeFileSync(path.join(dir, ".env"), ...)
        o = _open_bracket(t, i)
        if o is None or t[o] != "(":
            return False
        args = _top_args(t, o)
        m = re.search(r"([\w$.]+)\s*$", t[max(0, o - 120) : o])
        leaf = (m.group(1) if m else "").rsplit(".", 1)[-1]
        if leaf in _JOIN_LEAVES:
            i = o  # any segment of a path being built
            continue
        if not args or pos > o + 1 + len(args[0]):
            return False  # the destination is the first argument
        if leaf in _DEST_LEAVES:
            return True
        return leaf == "open" and _WRITE_MODE_RE.search(",".join(args[1:])) is not None
    return False


# ---------------------------------------------------------------- docstrings no model reads (FP round 2)
# A Python docstring is prose, not code: a path named in it is not read. But a docstring can be model-facing: an
# MCP tool's description is its function's docstring (@mcp.tool()), a pydantic model's docstring becomes its JSON
# schema description, and any code that reads __doc__ hands it on. So only docstrings no such path reaches are
# "prose" (LOW alone, never counted for a combo or the network backstop):
# * the module's, a class's whose bases are all exceptions or test cases (or a Test* class with none), and a
#   function's with no decorator but plain-Python ones (pytest, property, functools, contextlib, abc, typing...)
#   that is never referenced as a value (passed to add_tool(fn), put in a list, self.fn without a call);
# * and none at all in a file that mentions __doc__ or getdoc (fail closed).
_PLAIN_DECORATOR_RE = re.compile(
    r"^(?:pytest|unittest|mock|patch|functools|contextlib|abc|typing|typing_extensions|dataclasses|enum)(?:\.|$)"
    r"|^(?:staticmethod|classmethod|property|cached_property|wraps|lru_cache|cache|contextmanager"
    r"|asynccontextmanager|dataclass|abstractmethod|override|overload|final|unique|fixture|total_ordering)$"
    r"|\.(?:setter|getter|deleter)$"
)
_PLAIN_BASE_RE = re.compile(r"(?:Error|Exception|Warning|TestCase|Tests?)$")


@lru_cache(maxsize=256)
def _prose_docstrings(rel: str, text: str) -> tuple[tuple[int, int], ...]:
    """Character spans of the docstrings in a Python file that no model reads (see above)."""
    if not rel.endswith(PY_EXT) or re.search(r"__doc__|getdoc", text):
        return ()
    try:
        tree = parsing.py_parse(text)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return ()
    values: set[str] = set()
    callees: set[int] = set()
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            callees.add(id(n.func))
    for n in ast.walk(tree):
        if id(n) in callees:
            continue
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            values.add(n.id)
        elif isinstance(n, ast.Attribute) and isinstance(n.ctx, ast.Load):
            values.add(n.attr)
    lines = text.split("\n")
    starts = [0]
    for ln in lines:
        starts.append(starts[-1] + len(ln) + 1)

    def char(lineno: int, col: int) -> int:
        line = lines[lineno - 1] if 0 < lineno <= len(lines) else ""
        return starts[lineno - 1] + len(line.encode()[:col].decode("utf-8", "replace"))

    out = []
    for n in ast.walk(tree):
        if not isinstance(n, (ast.Module, ast.ClassDef, ast.FunctionDef, ast.AsyncFunctionDef)) or not n.body:
            continue
        d = n.body[0]
        if not (isinstance(d, ast.Expr) and isinstance(d.value, ast.Constant) and isinstance(d.value.value, str)):
            continue
        if isinstance(n, ast.ClassDef):
            bases = [ast.unparse(b) for b in n.bases]
            if n.keywords or n.decorator_list or not (
                    (bases and all(_PLAIN_BASE_RE.search(b) for b in bases)) or (not bases and n.name.startswith("Test"))):
                continue
        elif isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)):
            decos = [ast.unparse(x.func if isinstance(x, ast.Call) else x) for x in n.decorator_list]
            if any(not _PLAIN_DECORATOR_RE.search(x) for x in decos) or n.name in values:
                continue
        v = d.value
        if v.end_lineno is None or v.end_col_offset is None:
            continue
        out.append((char(v.lineno, v.col_offset), char(v.end_lineno, v.end_col_offset)))
    return tuple(out)


def _in_prose(f: ScanFile, t: str, pos: int) -> bool:
    if len(t) != len(f.text):
        return False
    return any(a <= pos < b for a, b in _prose_docstrings(f.rel, f.text))


def _cred_hits(f: ScanFile, t: str, regexes) -> list[tuple[int, str]]:
    """Sorted (pos, kind) for credential paths and .claude credential references.

    kind is "real", "deny" (deny-list / matcher collection: LOW alone, still counts for
    combos, the floor and the backstop), "env" (a copy of the environment whose use is
    unclear: LOW alone, backstop-eligible), "own" (the project's own dotenv file: LOW alone,
    combo- and backstop-eligible, FP plan step 3; also a project's own .claude/settings*.json), "prose" (in a
    docstring no model reads, _prose_docstrings: LOW alone, never combo- or backstop-eligible) or "regex" (a regex
    literal: combo-exempt, R29). A copy of the environment handed to a child process is
    not a hit at all (Task 10c B/C); copies are found on the syntax tree (R45).
    """
    hits = []
    seen = set()
    for m in CRED_RE.finditer(t):
        if not DOTENV_RE.search(_line_text(t, _line_of(t, m.start()))):
            seen.add(m.start())
            kind = _context(f, t, m.start(), regexes) or _precise_kind(f, t, m, regexes)
            if kind:  # None: the token names no credential file (FP plan step 3)
                hits.append((m.start(), kind))
    copies = _env_copies(f, t)
    if copies:
        net_lines = None
        netcap = None
        for c in copies:
            kind = _context(f, t, c.pos, regexes)
            if kind is None:
                if c.bound:
                    continue  # in a real launcher's env slot (R41, R45 3)
                if net_lines is None:
                    net_lines = _net_lines(f, t)
                if c.sink or (net_lines and _combo_near(f, t, [c.pos], [c.line], net_lines)):
                    kind = "real"  # reaches a network call or a write; or R27: same function as one
                elif c.family == "spread" and not c.untrusted and not (netcap := _network_capable(f, t) if netcap is None else netcap):
                    continue  # R26: a spread no network can reach stays silent (test_env_spread_not_dotenv)
                else:
                    kind = "env"  # LOW, counted by the R27 backstop (R45 4)
            hits.append((c.pos, kind))
    for m in SSH_JOIN_RE.finditer(t):
        pos = m.start(1) if m.group(1) else m.start(2)
        if pos not in seen and not any(a <= pos < b for a, b in [(x.start(), x.end()) for x in CRED_RE.finditer(t, max(0, pos - 2), pos + 40)]):
            hits.append((pos, _context(f, t, pos, regexes) or "real"))
    for pos, kind in _claude_refs(t, f):
        if kind in ("cred", "own"):
            hits.append((pos, _context(f, t, pos, regexes) or ("real" if kind == "cred" else "own")))
    return sorted((p, "prose" if k != "regex" and _in_prose(f, t, p) else k) for p, k in hits)


def _floor(f: ScanFile, found: list[Finding], strong: list[tuple[str, int]]) -> list[Finding]:
    """R27: context exemptions may lower single signals, never multi-signal behaviour.

    A same-function credential+network combo, eval of decoded content or eval of fetched
    content keeps at least MED (needs approval), whatever the file's path or context.
    """
    out = list(found)
    for rule, line in strong:
        if any(x.rule == rule and x.severity >= Severity.MED for x in out):
            continue
        out = [x for x in out if not (x.rule == rule and x.severity < Severity.MED)]
        out.append(_finding(rule, Severity.MED, f, line))
    return out


COMBO_WINDOW = 20


@lru_cache(maxsize=512)
def _function_spans(rel: str, text: str) -> list[tuple[int, int]] | None:
    """Line spans of outermost functions, or None when the file cannot be parsed."""
    try:
        if rel.endswith(PY_EXT):
            tree = parsing.py_parse(text)
            spans = [
                (n.lineno, n.end_lineno or n.lineno)
                for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
        elif rel.endswith(JS_EXT + TS_EXT):
            kinds = {
                "function_declaration", "function_expression", "function", "arrow_function",
                "method_definition", "generator_function", "generator_function_declaration",
            }
            spans, stack = [], [parsing.js_root(text.encode(), _js_lang(rel))]  # no root ref (see _code_info)
            while stack:
                n = stack.pop()
                if n.type in kinds:
                    spans.append((n.start_point[0] + 1, n.end_point[0] + 1))
                else:  # outermost only: nested callbacks belong to their enclosing function
                    stack.extend(n.children)
        else:
            return None
    except MemoryError:
        raise
    except Exception:  # noqa: BLE001
        return None
    spans.sort(key=lambda sp: (sp[0], -sp[1]))
    outer: list[tuple[int, int]] = []
    for sp in spans:
        if not outer or sp[0] > outer[-1][1]:
            outer.append(sp)
    return outer


def _same_scope(f: ScanFile, cred_lines: list[int], net_lines: list[int]) -> bool:
    """Credential access and an outbound call in the same function (module level is one scope)."""
    spans = _function_spans(f.rel, f.text)
    if spans is None:
        return any(abs(c - n) <= COMBO_WINDOW for c in cred_lines for n in net_lines)

    def scope(line: int) -> int:
        for i, (lo, hi) in enumerate(spans):
            if lo <= line <= hi:
                return i
        return -1

    return bool({scope(c) for c in cred_lines} & {scope(n) for n in net_lines})


# ---------------------------------------------------------------- proximity in bundles (false-positive plan step 2)
# A bundle (bundle.py) holds hundreds of unrelated libraries in one file, often on one line or inside one
# outermost function, so "same function" there means "same file". In a bundle the credential and the network
# call (or, for the backstop, a network reference) must be close (proximity.py). Anything that cannot be
# analysed (no parsed calls, a degraded call budget, a refused parse) keeps the same-function rule.


def _bundle_near(f: ScanFile, t: str, cred_pos: list[int], extra: list[int] | None = None) -> bool | None:
    if not bundle.is_bundle(f.rel, f.text):
        return None
    calls = _calls(f.rel, f.text)
    if calls is None or _over(calls) or getattr(calls, "sink_incomplete", False):
        return None
    net = [p for _, _, p in _net_calls_pos(f.rel, f.text, t)]
    if any(p < 0 for p in net):
        return None
    return proximity.near(f.rel, f.text, proximity.char_to_byte(t, cred_pos), net + (extra or []))


def _combo_near(f: ScanFile, t: str, cred_pos: list[int], cred_lines: list[int], net_lines: list[int]) -> bool:
    """Credential access and an outbound call together: close together in a bundle, else the same function."""
    if not cred_pos or not net_lines:
        return _same_scope(f, cred_lines, net_lines)
    got = _bundle_near(f, t, cred_pos)
    return _same_scope(f, cred_lines, net_lines) if got is None else got


def _netcap_near(f: ScanFile, t: str, cred_pos: list[int]) -> bool:
    """The backstop: the file can reach the network; in a bundle, a network reference near the credential
    (which also sees the module holders bundlers use: webpack's external table, esbuild's __toESM)."""
    if bundle.is_bundle(f.rel, f.text):
        got = _bundle_near(f, t, cred_pos, _netcap_positions(f, t))
        if got is not None:
            return got
    return _network_capable(f, t)


# Network references by position, for the backstop in a bundle (false-positive plan step 2): what
# _network_capable looks for anywhere, as UTF-8 byte offsets, plus the module holders bundlers use, which
# _bindings does not see: esbuild's `var import_https = __toESM(require("https"))` and webpack's external
# module table (`65692:t=>{t.exports=require("https")}`, used as `n(65692)`).
_WRAPPED_REQ_RE = re.compile(
    r"""([\w$]+)\s*=\s*(?:[\w$.]+\(\s*)+(?:require|import)\(\s*['"](?:node:)?([\w@/.-]+)['"]\s*\)"""
)
_WEBPACK_EXTERNAL_RE = re.compile(
    r"""(?<![\w$])(\d+|"[^"\n]{1,200}")\s*(?::\s*(?:\([\w$,\s]*\)|[\w$]+)\s*=>|\([\w$,\s]*\))\s*\{\s*(?:['"]use strict['"];?\s*)?"""
    r"""[\w$]+\.exports\s*=\s*require\(\s*['"](?:node:)?([\w@/.-]+)['"]\s*\)"""
)


def _netcap_positions(f: ScanFile, t: str) -> list[int]:
    """Byte offsets of network references in a JS/TS file (computed loads, network globals, network module
    loads and the names holding them)."""
    tb = _strings_blanked(f.rel, t)
    in_t: list[int] = [m.start() for m in COMPUTED_LOAD_RE.finditer(t)]
    in_t += [m.start() for m in _NET_GLOBAL_KEY_RE.finditer(t)]
    in_tb: list[int] = [m.start() for m in _NET_GLOBAL_USE_RE.finditer(tb)]
    holders: set[str] = set()
    for m in _INLINE_REQ_RE.finditer(t):
        if _net_mod(m.group(1)) and not _noncap_chain(m.group(2) or ""):
            in_t.append(m.start())
    for m in _WRAPPED_REQ_RE.finditer(t):
        if _net_mod(m.group(2)):
            holders.add(m.group(1))
    ids = {m.group(1) for m in _WEBPACK_EXTERNAL_RE.finditer(t) if _net_mod(m.group(2))}
    if ids:
        id_re = re.compile(r"(?<![\w$.])[\w$]+\(\s*(?:" + "|".join(re.escape(i) for i in sorted(ids)) + r")\s*\)")
        for m in id_re.finditer(t):
            in_t.append(m.start())
            pre = re.search(r"([\w$]+)\s*=\s*$", t[max(0, m.start() - 80):m.start()])
            if pre:
                holders.add(pre.group(1))
    b = _bindings(f.rel, f.text)
    for name, mod in b.modbind.items():
        if _net_mod(mod):
            holders.add(name)
    for name, target in b.al.items():
        mod, _, member = target.partition(".")
        if member and _net_mod(mod) and member not in NONCAP_MEMBERS and _net_mod(target):
            holders.add(name)
    holders = {h for h in holders if re.fullmatch(r"[\w$]+", h)}
    if holders:
        rx = re.compile(r"(?<![\w$.])(?:" + "|".join(re.escape(h) for h in sorted(holders)) + r")(?![\w$])")
        for m in rx.finditer(tb):
            chain = _CHAIN_RE.match(tb, m.end())
            if chain and _noncap_chain(chain.group(0)):
                continue
            in_tb.append(m.start())
    return proximity.char_to_byte(t, in_t) + proximity.char_to_byte(tb, in_tb)


CODE_RULES = [ManifestRules(), CodeRules()]
