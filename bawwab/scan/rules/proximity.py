"""Proximity of a credential read and a network call in a bundled or minified file (false-positive plan, step 2).

In a bundle (bundle.py), code._combo_near asks whether each credential read is close to some network call (or, for
the backstop, to some network reference). Close means any of:

* scope: the call is inside the credential's scope, the largest enclosing function of at most SCOPE_MAX_BYTES. A
  bundle wraps every module in a function (esbuild `__commonJS`, webpack's module table), so a small module is one
  scope; the bundle-wide IIFE or a huge library function never is;
* window: within WINDOW_BYTES bytes and WINDOW_LINES lines of each other (top-level code of a flat ESM bundle, or a
  credential read inside a helper called right next to the send);
* flow, one hop, through a rare name (at most RARE_MAX identifier uses in the whole file, so minified `e`/`t` never
  link): a name the credential value is bound to (its variable, assignment target, or the named function holding
  it) is used in the call's scope or window; or the credential sits in the arguments of a call to a function whose
  body holds the network call (a wrapper such as `post(url, readFileSync(...))`).

A credential inside a parse-error region gets the window test only. Anything that cannot be analysed (no tree,
refused parse, an exception) returns None, and the caller applies today's same-function rule: fail closed.
"""
from __future__ import annotations

import re
from collections import Counter
from functools import lru_cache

from bawwab.scan.rules import parsing

SCOPE_MAX_BYTES = 16 << 10
WINDOW_BYTES = 1024
WINDOW_LINES = 8
RARE_MAX = 12
MAX_CREDS = 256  # more credential positions than this in one file: not analysed (None, fail closed)
MAX_NAMES = 1024  # the same for names bound to them

_FUNCS = {
    "function_declaration", "function_expression", "function", "arrow_function", "method_definition",
    "generator_function", "generator_function_declaration",
}
_TS_EXT = (".ts", ".mts", ".cts", ".tsx")


def _lang(rel: str) -> str:
    if rel.endswith(".tsx"):
        return "tsx"
    return "typescript" if rel.endswith(_TS_EXT) else "javascript"


def char_to_byte(s: str, positions: list[int]) -> list[int]:
    """UTF-8 byte offsets of character offsets in s (s's bytes line up with the parsed source, see code._code_info)."""
    if s.isascii():
        return list(positions)
    out, prev, acc = {}, 0, 0
    for p in sorted(set(positions)):
        acc += len(s[prev:p].encode("utf-8", "surrogatepass"))
        prev, out[p] = p, acc
    return [out[p] for p in positions]


def _ident(src: bytes, n) -> str:
    return src[n.start_byte:n.end_byte].decode("utf-8", "replace") if n is not None else ""


def _target_name(src: bytes, n) -> str:
    """The last identifier of an assignment target or key: `exports.inspectOpts` -> inspectOpts."""
    if n is None:
        return ""
    if n.type in ("identifier", "property_identifier", "shorthand_property_identifier", "private_property_identifier"):
        return _ident(src, n)
    if n.type == "member_expression":
        return _ident(src, n.child_by_field_name("property"))
    if n.type in ("string", "string_fragment"):
        return _ident(src, n).strip("'\"`")
    return ""


def _fn_name(src: bytes, fn) -> str:
    name = fn.child_by_field_name("name")
    if name is not None:
        return _ident(src, name)
    p = fn.parent
    if p is None:
        return ""
    if p.type == "variable_declarator":
        return _target_name(src, p.child_by_field_name("name"))
    if p.type in ("assignment_expression", "augmented_assignment_expression"):
        return _target_name(src, p.child_by_field_name("left"))
    if p.type == "pair":
        return _target_name(src, p.child_by_field_name("key"))
    return ""


class _Site:
    __slots__ = ("pos", "line", "scope", "names", "callees", "fn_names")

    def __init__(self, pos: int, line: int):
        self.pos, self.line = pos, line
        self.scope: tuple[int, int] | None = None
        self.names: set[str] = set()  # names the value at this site is bound to
        self.callees: set[str] = set()  # functions this site is an argument of
        self.fn_names: set[str] = set()  # names of the functions enclosing this site, within its scope


def _site(root, src: bytes, pos: int, line: int) -> _Site:
    s = _Site(pos, line)
    n = root.descendant_for_byte_range(pos, pos)
    funcs, err, bound = [], False, False
    while n is not None:
        t = n.type
        if t == "ERROR":
            err = True
        elif t in _FUNCS:
            funcs.append(n)
        elif not funcs and not bound:
            if t == "variable_declarator":
                s.names.add(_target_name(src, n.child_by_field_name("name")))
                bound = True
            elif t in ("assignment_expression", "augmented_assignment_expression"):
                s.names.add(_target_name(src, n.child_by_field_name("left")))
                bound = True
            elif t == "pair":
                s.names.add(_target_name(src, n.child_by_field_name("key")))
            elif t in ("call_expression", "new_expression") and len(s.callees) < 3:
                fn = n.child_by_field_name("function" if t == "call_expression" else "constructor")
                if fn is not None and not (fn.start_byte <= pos < fn.end_byte):  # pos is in the arguments
                    s.callees.add(_target_name(src, fn))
        n = n.parent
    if err:
        return s  # window only
    for fn in funcs:  # innermost first; spans only grow
        if fn.end_byte - fn.start_byte > SCOPE_MAX_BYTES:
            break
        s.scope = (fn.start_byte, fn.end_byte)
        name = _fn_name(src, fn)
        if name:
            s.fn_names.add(name)
            s.names.add(name)
    s.names.discard("")
    s.callees.discard("")
    s.fn_names.discard("")
    return s


def _line_index(src: bytes):
    starts = [0]
    i = src.find(b"\n")
    while i >= 0:
        starts.append(i + 1)
        i = src.find(b"\n", i + 1)
    return starts


def _line(starts: list[int], pos: int) -> int:
    lo, hi = 0, len(starts)
    while lo + 1 < hi:
        mid = (lo + hi) // 2
        if starts[mid] <= pos:
            lo = mid
        else:
            hi = mid
    return lo + 1


def _region(s: _Site, size: int) -> tuple[int, int]:
    if s.scope is not None:
        return s.scope
    return max(0, s.pos - WINDOW_BYTES), min(size, s.pos + WINDOW_BYTES)


def near(rel: str, text: str, cred_bytes: list[int], net_bytes: list[int]) -> bool | None:
    """Whether some credential position is close to some network position (byte offsets in text's UTF-8);
    None when the file cannot be analysed (callers then apply the same-function rule)."""
    got = why_near(rel, text, cred_bytes, net_bytes)
    return got if got is None else bool(got)


def why_near(rel: str, text: str, cred_bytes: list[int], net_bytes: list[int]) -> str | None:
    """near(), with the reason: "scope", "window", "wrapper" or "flow:<name>"; "" when not close."""
    if not cred_bytes or not net_bytes:
        return ""
    try:
        if len(set(cred_bytes)) > MAX_CREDS:
            return None
        ix = _index(rel, text)
        src = ix.src
        creds = [ix.site(p) for p in sorted(set(cred_bytes))]
        nets = [ix.site(q) for q in sorted(set(net_bytes))]
        for c in creds:
            for q in nets:
                if c.scope is not None and c.scope[0] <= q.pos < c.scope[1]:
                    return "scope"
                if abs(c.pos - q.pos) <= WINDOW_BYTES and abs(c.line - q.line) <= WINDOW_LINES:
                    return "window"
                if c.callees & q.fn_names:
                    return "wrapper"  # the credential is handed to the function that sends
        names: set[str] = set()
        for c in creds:
            names |= c.names
        names = {n for n in names if len(n) >= 2 and re.fullmatch(r"[A-Za-z_$][\w$]*", n)}
        if not names:
            return ""
        if len(names) > MAX_NAMES:
            return None
        uses = ix.uses()
        rare = {n for n in names if uses.get(n.encode(), 0) <= RARE_MAX}
        if not rare:
            return ""
        rx = re.compile(rb"(?<![\w$])(?:" + b"|".join(re.escape(n.encode()) for n in sorted(rare)) + rb")(?![\w$])")
        for q in nets:
            m = rx.search(src, *_region(q, len(src)))
            if m:
                return "flow:" + m.group().decode()
        return ""
    except MemoryError:
        raise
    except Exception:  # noqa: BLE001 - not analysable: the caller's same-function rule applies
        return None


class _Index:
    """One parsed file: its tree, line starts, sites and identifier counts, built once per text. The env-copy
    check asks once per copy (thousands in a minified bundle), so nothing here is rebuilt per question."""

    def __init__(self, rel: str, text: str):
        self.src = text.encode("utf-8", "surrogatepass")
        self.root = parsing.js_root(self.src, _lang(rel))
        self.starts = _line_index(self.src)
        self._sites: dict[int, _Site] = {}
        self._uses: Counter | None = None

    def site(self, pos: int) -> _Site:
        s = self._sites.get(pos)
        if s is None:
            s = self._sites[pos] = _site(self.root, self.src, pos, _line(self.starts, pos))
        return s

    def uses(self) -> Counter:
        if self._uses is None:
            self._uses = Counter(m.group() for m in _WORD_RE.finditer(self.src))
        return self._uses


@lru_cache(maxsize=1)  # holds a tree: one file at a time (code.CodeRules drops it after each file)
def _index(rel: str, text: str) -> _Index:
    return _Index(rel, text)


_WORD_RE = re.compile(rb"[A-Za-z_$][\w$]*")
