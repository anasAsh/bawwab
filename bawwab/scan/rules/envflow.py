"""Copies of the whole environment, followed on the syntax tree (Ruling R45).

Python is read with the stdlib `ast`, JS/TS with tree-sitter, so a comment or a string never declares,
binds or copies anything, and casts, parentheses and argument position do not matter.

- A copy: any spread / `**` / Object.assign / dict() / copy() / structuredClone / Object.fromEntries(
  Object.entries(...)) whose source is `process.env` / `os.environ`, in any position (R45 1).
- A launcher: a call whose callee resolves, by scope, to an import / require binding of a process
  launcher module (child_process, subprocess, os, asyncio, execa, cross-spawn, a browser's launch, the
  MCP SDK's StdioClientTransport) that the file never reassigns, rebinds or patches: no `cp = ...`,
  `cp.spawn = ...`, Object.assign / defineProperty on it, `globalThis.cp = ...`, setattr, `globals()[...]`
  or `sys.modules[...]` write, for that binding or for its module through any binding (R45 2).
- Bound: the copy sits in a launcher's env slot, or is a variable / function return whose every use is
  one (one level of return, as for soffice's get_soffice_env). Reading or editing single keys, testing it
  and listing its keys are not uses of the whole copy (R45 3).
- Sink: the copy, or a value made from it, reaches a network call or a file write, through variables and
  function returns (R45 4: "HIGH only when it reaches a network/write call directly").
- A file that does not parse gives None; the caller then treats every copy as unbound (R45 5).
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Callable

from tree_sitter_language_pack import get_parser

PY_EXT = (".py",)
TS_EXT = (".ts", ".mts", ".cts", ".tsx")

# Process launchers (R41, R42): the leaf of a call into a launcher module that takes an env.
LAUNCH_LEAVES = {
    "Popen", "spawn", "spawnSync", "execFile", "execFileSync", "fork", "execa", "execaSync", "execaCommand",
    "execaCommandSync", "execaNode", "launch", "StdioClientTransport", "create_subprocess_exec",
    "create_subprocess_shell", "crossSpawn", "posix_spawn", "posix_spawnp", "sync",
}
LAUNCH_MODULE_LEAVES = {"run", "call", "check_call", "check_output", "exec", "execSync", "getoutput", "getstatusoutput"}
BROWSER_MODULES = ("puppeteer", "puppeteer-core", "playwright", "playwright-core", "@playwright/test", "chrome-launcher")

# The `debug` package (R41, R42 N5): env keys tested against a literal ^prefix regex, reduced into options.
PREFIX_FILTER_RE = re.compile(
    r"""\s*\.\s*filter\s*\(\s*(?:function\s*\(\s*[\w$]+\s*\)\s*\{\s*return\s*|\(?\s*[\w$]+\s*\)?\s*=>\s*)"""
    r"""/\^([A-Za-z][\w]*)/[gimsuy]*\.test\(\s*[\w$]+\s*\)\s*;?\s*\}?\s*\)\s*\.\s*reduce\s*\("""
)
SECRETISH_RE = re.compile(r"key|token|secret|pass|pwd|auth|cred|aws|gh_|github|npm|openai|anthropic|session|cookie", re.I)
OPTION_SINKS = {("util", ("inspect",)): 1, ("util", ("formatWithOptions",)): 0}  # options argument index

_WRITE_LEAF_RE = re.compile(r"^(?:write\w*|appendFile\w*|write_text|write_bytes|dump)$")
_TERMINAL_RE = re.compile(r"^(?:process|sys)\??\.std(?:out|err)\b")
_DEPTH = 4  # variable / return hops followed from one copy

IsNet = Callable[[str, str, str], bool]  # (callee text, argument text, first argument text) -> outbound call


@dataclass(frozen=True)
class EnvCopy:
    pos: int  # character offset in the analysed text
    line: int  # 1-based
    family: str  # "old": checked since round 0 (dict(os.environ), Object.entries(process.env)...); "spread": R44/R45 forms
    bound: bool
    sink: bool


def launcher_path(mod: str, members: tuple[str, ...]) -> bool:
    """A launcher module path: ('child_process', ('spawn',)), ('execa', ()), ('playwright', ('chromium', 'launch'))."""
    mod = mod.removeprefix("node:")
    members = tuple(m for m in members if m != "default")
    leaf = members[-1] if members else ""
    root = mod.split("/")[0] if not mod.startswith("@") else "/".join(mod.split("/")[:2])
    if mod == "os" or mod.startswith("os."):
        return bool(re.fullmatch(r"(?:exec|spawn|posix_spawn)\w*", leaf)) and len(members) == 1
    if mod == "asyncio":
        return leaf in ("create_subprocess_exec", "create_subprocess_shell")
    if mod in ("execa", "cross-spawn"):
        return not members or leaf in LAUNCH_LEAVES | LAUNCH_MODULE_LEAVES
    if mod in ("child_process", "subprocess"):
        return bool(members) and leaf in LAUNCH_LEAVES | LAUNCH_MODULE_LEAVES
    if root in BROWSER_MODULES or mod in BROWSER_MODULES:
        return leaf in ("launch", "launchPersistentContext")
    return mod.startswith("@modelcontextprotocol/") and leaf == "StdioClientTransport"


def _is_write(callee: str) -> bool:
    callee = re.sub(r"\s+", "", callee)
    return bool(_WRITE_LEAF_RE.match(callee.rsplit(".", 1)[-1])) and not _TERMINAL_RE.match(callee)


# ---------------------------------------------------------------- JS / TS


_JS_FUNCS = {
    "function_declaration", "function_expression", "function", "arrow_function", "method_definition",
    "generator_function", "generator_function_declaration",
}
_JS_BLOCKS = {"statement_block", "program", "switch_body", "for_statement", "for_in_statement", "class_static_block"}
_JS_WRAP = {"parenthesized_expression", "as_expression", "satisfies_expression", "non_null_expression", "type_assertion",
            "await_expression"}
_JS_PATTERNS = {"object_pattern", "array_pattern", "pair_pattern", "assignment_pattern", "object_assignment_pattern",
                "rest_pattern", "required_parameter", "optional_parameter"}
_JS_IDENTS = ("identifier", "shorthand_property_identifier", "shorthand_property_identifier_pattern")
_JS_ENV_RE = re.compile(rb"(?<![\w$])process\s*(?:\?\.\s*|\.\s*)env(?![\w$])|(?<![\w$])process\s*(?:\?\.)?\s*\[\s*['\"`]env['\"`]\s*\]")
_ENV_OBJECTS = {"process", "globalThis.process", "global.process", "window.process", "self.process"}
_GLOBAL_WRITE_RE = re.compile(
    rb"(?<![\w$.])(?:globalThis|global|window|self)\s*(?:\??\.\s*([\w$]+)|\[\s*['\"`]([\w$]+)['\"`]\s*\])\s*=(?![=>])"
)
_GLOBAL_DEFINE_RE = re.compile(
    rb"(?<![\w$.])(?:Object|Reflect)\s*\.\s*(?:defineProperty|defineProperties|assign|set)\s*\(\s*(?:globalThis|global|window|self)\b"
)
_JS_EVAL_RE = re.compile(rb"(?<![\w$.])(?:eval|Function)\s*\(")
_PATCH_CALLS = {"Object.assign", "Object.defineProperty", "Object.defineProperties", "Reflect.set", "Reflect.defineProperty",
                "Object.setPrototypeOf", "Reflect.setPrototypeOf", "Reflect.deleteProperty"}
_INTEROP_RE = re.compile(r"^(?:[\w$]+\.)?_*(?:toESM|importDefault|importStar|interopRequire\w*|toCommonJS)$")
_SHIM_RE = re.compile(r"""^\(\s*[\w$]+\s*=>\s*typeof\s+require\s*<\s*["']u["']\s*\?\s*require\b""")


def _k(n) -> tuple:
    return (n.start_byte, n.end_byte, n.type)


class _Js:
    def __init__(self, rel: str, text: str, is_net: IsNet):
        self.text = text
        self.src = text.encode()
        lang = "tsx" if rel.endswith(".tsx") else ("typescript" if rel.endswith(TS_EXT) else "javascript")
        self.root = get_parser(lang).parse(self.src).root_node
        self.is_net = is_net
        self._decls: dict[str, dict[tuple, list]] = {}
        self._decl_keys: dict[str, dict[tuple, object]] = {}
        self._occ: dict[str, list] = {}
        self._mod_memo: dict[tuple, tuple | None] = {}
        self._patched_memo: dict[tuple, bool] = {}
        self._mod_patched_memo: dict[str, bool] = {}
        self._global_names: set[str] | None = None
        self._ascii = len(self.src) == len(text)

    # -------- basics

    def t(self, n) -> str:
        return self.src[n.start_byte : n.end_byte].decode("utf-8", "replace")

    def char(self, b: int) -> int:
        return b if self._ascii else len(self.src[:b].decode("utf-8", "replace"))

    @staticmethod
    def f(n, name):
        return n.child_by_field_name(name)

    def up(self, n):
        """(n, parent), skipping parentheses, casts and await around n."""
        p = n.parent
        while p is not None and p.type in _JS_WRAP:
            n, p = p, p.parent
        return n, p

    def callee_node(self, call):
        fn = self.f(call, "function" if call.type == "call_expression" else "constructor")
        while fn is not None and fn.type in ("parenthesized_expression", "sequence_expression"):
            kids = [c for c in fn.named_children if c.type != "comment"]
            fn = kids[-1] if kids else None
        return fn

    def callee(self, call) -> str:
        fn = self.callee_node(call)
        return re.sub(r"\s+|\?(?=\.)", "", self.t(fn)) if fn is not None else ""

    def args_of(self, call) -> list:
        a = self.f(call, "arguments")
        return [c for c in a.named_children if c.type != "comment"] if a is not None else []

    def arg_index(self, call, n) -> int:
        for i, a in enumerate(self.args_of(call)):
            if a == n:
                return i
        return -1

    # -------- scopes

    def occurrences(self, name: str) -> list:
        if name not in self._occ:
            rx = re.compile(rb"(?<![\w$])" + re.escape(name.encode()) + rb"(?![\w$])")
            out = []
            for m in rx.finditer(self.src):
                n = self.root.named_descendant_for_byte_range(m.start(), m.end())
                if n is not None and n.start_byte == m.start() and n.end_byte == m.end() and n.type in _JS_IDENTS:
                    out.append(n)
            self._occ[name] = out
        return self._occ[name]

    def nearest(self, n, types):
        p = n.parent
        while p is not None and p.type not in types:
            p = p.parent
        return p

    def decl_scope(self, n):
        """The scope node a declaring identifier binds in, or None when n is not a declaration."""
        child, p = n, n.parent
        in_pattern = False
        while p is not None and p.type in _JS_PATTERNS:
            if p.type == "pair_pattern" and child == self.f(p, "key"):
                return None
            if p.type in ("assignment_pattern", "object_assignment_pattern") and child != self.f(p, "left"):
                return None
            if p.type in ("required_parameter", "optional_parameter") and child != self.f(p, "pattern"):
                return None
            in_pattern = True
            child, p = p, p.parent
        if p is None:
            return None
        t = p.type
        if t == "variable_declarator" and child == self.f(p, "name"):
            d = p.parent
            if d is not None and d.type == "variable_declaration":
                return self.nearest(p, _JS_FUNCS | {"program"})
            return self.nearest(p, _JS_BLOCKS | _JS_FUNCS)
        if t == "formal_parameters":
            return p.parent
        if t == "arrow_function" and child == self.f(p, "parameter"):
            return p
        if t == "catch_clause" and child == self.f(p, "parameter"):
            return p
        if t == "for_in_statement" and child == self.f(p, "left"):
            kind = self.f(p, "kind")
            if kind is None:
                return None  # for (k in o) with no declaration: an assignment
            return self.nearest(p, _JS_FUNCS | {"program"}) if self.t(kind) == "var" else p
        if in_pattern:
            return None
        if t in ("function_declaration", "generator_function_declaration", "class_declaration") and child == self.f(p, "name"):
            return self.nearest(p, _JS_BLOCKS | _JS_FUNCS)
        if t in ("function_expression", "function", "generator_function", "class") and child == self.f(p, "name"):
            return p
        if t == "import_specifier":
            alias = self.f(p, "alias")
            if (alias is None and child == self.f(p, "name")) or child == alias:
                return self.root
            return None
        if t in ("namespace_import", "import_clause"):
            return self.root
        return None

    def decls(self, name: str) -> dict:
        """scope key -> declaring identifiers of name in that scope."""
        if name not in self._decls:
            d: dict[tuple, list] = {}
            keys: dict[tuple, object] = {}
            for n in self.occurrences(name):
                s = self.decl_scope(n)
                if s is not None:
                    d.setdefault(_k(s), []).append(n)
            for lst in d.values():
                for n in lst:
                    keys[_k(n)] = lst[0]
            self._decls[name], self._decl_keys[name] = d, keys
        return self._decls[name]

    def resolve(self, ref):
        """The declaring identifier ref refers to, or None (a global or implicit global)."""
        name = self.t(ref)
        d = self.decls(name)
        if not d:
            return None
        own = self._decl_keys[name].get(_k(ref))
        if own is not None:
            return own
        p = ref.parent
        while p is not None:
            lst = d.get(_k(p))
            if lst:
                return lst[0]
            p = p.parent
        return None

    def refs(self, decl) -> list:
        return [r for r in self.occurrences(self.t(decl)) if r != decl and self.resolve(r) == decl]

    # -------- modules and launchers

    def require_like(self, fn) -> bool:
        """fn is `require`, a createRequire(...) result or esbuild's `__require` shim, declared in code."""
        if fn is None:
            return False
        if fn.type == "call_expression":
            return self.module_of(self.callee_node(fn)) == ("module", ("createRequire",))
        if fn.type != "identifier":
            return False
        decl = self.resolve(fn)
        if decl is None:
            return self.t(fn) == "require"
        p = decl.parent
        if p is None or p.type != "variable_declarator" or decl != self.f(p, "name"):
            return False
        v = self.f(p, "value")
        while v is not None and v.type in _JS_WRAP:
            v = v.named_children[0] if v.named_children else None
        if v is None:
            return False
        if v.type == "identifier" and self.t(v) == "require" and self.resolve(v) is None:
            return True
        if v.type == "call_expression" and self.module_of(self.callee_node(v)) == ("module", ("createRequire",)):
            return True
        return bool(_SHIM_RE.match(self.t(v)))

    def module_of(self, n, depth: int = 0) -> tuple | None:
        """(module, members) an expression stands for through import/require bindings, or None."""
        if n is None or depth > 8:
            return None
        while n.type in _JS_WRAP or n.type == "sequence_expression":
            kids = [c for c in n.named_children if c.type != "comment"]
            if not kids:
                return None
            n = kids[-1] if n.type == "sequence_expression" else kids[0]
        if n.type == "identifier":
            decl = self.resolve(n)
            return self.decl_module(decl, depth + 1) if decl is not None else None
        if n.type in ("member_expression", "subscript_expression"):
            base = self.module_of(self.f(n, "object"), depth + 1)
            if base is None:
                return None
            if n.type == "member_expression":
                prop = self.t(self.f(n, "property"))
            else:
                idx = self.f(n, "index")
                if idx is None or idx.type != "string":
                    return None
                prop = self.t(idx)[1:-1]
            return base[0], base[1] + (prop,)
        if n.type == "call_expression":
            fn = self.f(n, "function")
            args = self.args_of(n)
            if fn is not None and (fn.type == "import" or self.require_like(fn)):
                if len(args) == 1 and args[0].type == "string":
                    return self.t(args[0])[1:-1].removeprefix("node:"), ()
                return None
            if fn is not None and _INTEROP_RE.match(re.sub(r"\s+", "", self.t(fn))) and args:
                return self.module_of(args[0], depth + 1)
        return None

    def decl_module(self, decl, depth: int = 0) -> tuple | None:
        key = _k(decl)
        if key in self._mod_memo:
            return self._mod_memo[key]
        self._mod_memo[key] = None  # cycle guard
        path: list[str] = []
        child, p = decl, decl.parent
        while p is not None and p.type in _JS_PATTERNS:
            if p.type == "pair_pattern":
                path.insert(0, self.t(self.f(p, "key")).strip("'\""))
            elif p.type == "object_pattern" and child.type == "shorthand_property_identifier_pattern":
                path.insert(0, self.t(child))
            elif p.type == "object_assignment_pattern" and child == self.f(p, "left") and child.type == "shorthand_property_identifier_pattern":
                path.insert(0, self.t(child))
            elif p.type in ("array_pattern", "rest_pattern"):
                return None
            child, p = p, p.parent
        out = None
        if p is not None and p.type == "variable_declarator" and child == self.f(p, "name"):
            value = self.f(p, "value")
            base = self.module_of(value, depth + 1)
            if base is not None:
                out = (base[0], base[1] + tuple(path))
            elif path and value is not None and self.unwrap(value).type == "call_expression":
                out = self.returned_member(path, depth)
        elif p is not None and p.type in ("import_specifier", "namespace_import", "import_clause"):
            st = self.nearest(p, {"import_statement"})
            src = self.f(st, "source") if st is not None else None
            if src is not None:
                mod = self.t(src)[1:-1].removeprefix("node:")
                if p.type == "import_specifier":
                    out = (mod, (self.t(self.f(p, "name")).strip("'\""),))
                else:
                    out = (mod, ())
        self._mod_memo[key] = out
        return out

    def unwrap(self, n):
        while n.type in _JS_WRAP and n.named_children:
            n = n.named_children[0]
        return n

    def returned_member(self, path: list[str], depth: int) -> tuple | None:
        """const { puppeteer } = pkg.load(): the module, when every object property named path[0] in the
        file (return { puppeteer }, { puppeteer: x }) is that same module binding (desktop-commander's
        LazyPackage loader). Any other property of that name makes it unknown."""
        name = path[0]
        found: set[tuple] = set()
        rx = re.compile(rb"(?<![\w$.])" + re.escape(name.encode()) + rb"(?![\w$])")
        for m in rx.finditer(self.src):
            n = self.root.named_descendant_for_byte_range(m.start(), m.end())
            if n is None or n.start_byte != m.start() or n.end_byte != m.end():
                continue
            if n.type == "shorthand_property_identifier":
                decl = self.resolve(n)
                mod = self.decl_module(decl, depth + 1) if decl is not None else None
            elif n.type == "property_identifier" and n.parent is not None and n.parent.type == "pair" and n == self.f(n.parent, "key"):
                mod = self.module_of(self.f(n.parent, "value"), depth + 1)
            else:
                continue
            if mod is None:
                return None
            found.add(mod)
        if len(found) != 1:
            return None
        mod, members = found.pop()
        return mod, members + tuple(path[1:])

    def global_names(self) -> set[str]:
        """Names written through globalThis / global / window / self anywhere in code."""
        if self._global_names is None:
            names: set[str] = set()
            for m in _GLOBAL_WRITE_RE.finditer(self.src):
                if self.in_code(m.start()):
                    names.add((m.group(1) or m.group(2)).decode())
            for rx in (_GLOBAL_DEFINE_RE, _JS_EVAL_RE):
                for m in rx.finditer(self.src):
                    n = self.root.named_descendant_for_byte_range(m.start(), m.start() + 1)
                    call = n
                    while call is not None and call.type not in ("call_expression", "new_expression"):
                        call = call.parent
                    if call is None or not self.in_code(m.start()):
                        continue
                    a = self.f(call, "arguments")
                    if a is not None:
                        names.update(x.decode() for x in re.findall(rb"[A-Za-z_$][\w$]*", self.src[a.start_byte : a.end_byte]))
            self._global_names = names
        return self._global_names

    def in_code(self, b: int) -> bool:
        n = self.root.named_descendant_for_byte_range(b, b + 1)
        while n is not None:
            if n.type in ("comment", "string", "template_string", "regex", "html_comment"):
                return False
            n = n.parent
        return True

    def patched_use(self, r, namespace: bool) -> bool:
        """r (a reference) reassigns, rebinds, patches or (for a whole module) aliases its binding."""
        child, p = r, r.parent
        if p is None:
            return False
        if p.type in ("assignment_expression", "augmented_assignment_expression") and child == self.f(p, "left"):
            return True
        if p.type == "update_expression":
            return True
        if p.type == "for_in_statement" and child == self.f(p, "left"):
            return True
        q = p
        while q is not None and q.type in _JS_PATTERNS:  # ({ spawn } = x), [cp] = x
            child, q = q, q.parent
        if q is not None and q.type == "assignment_expression" and child == self.f(q, "left") and child != r:
            return True
        # cp.spawn = x, cp.a.b = x, delete cp.spawn, cp.spawn++
        top, q = r, p
        while q is not None and q.type in ("member_expression", "subscript_expression") and top == self.f(q, "object"):
            top, q = q, q.parent
        if top != r and q is not None:
            if q.type in ("assignment_expression", "augmented_assignment_expression") and top == self.f(q, "left"):
                return True
            if q.type == "update_expression" or (q.type == "unary_expression" and self.t(q).startswith("delete")):
                return True
        # Object.assign(cp, ...), Object.defineProperty(cp, ...)
        t_ = top
        n, q = self.up(t_)
        if q is not None and q.type == "arguments":
            call = q.parent
            if self.callee(call) in _PATCH_CALLS and self.arg_index(call, n) == 0:
                return True
        if namespace and top == r:
            n, q = self.up(r)
            if q is None:
                return False
            if q.type in ("call_expression", "new_expression") and n == self.callee_node(q):
                return False  # cross-spawn's default export called
            if q.type == "unary_expression" and self.t(q).split()[0] in ("typeof", "void", "!"):
                return False
            if q.type == "variable_declarator" and self.f(q, "name").type == "object_pattern":
                return False  # const { spawn } = cp: members copied out
            if q.type in ("export_specifier", "export_clause", "expression_statement"):
                return False
            if r.type == "shorthand_property_identifier" and not self.member_patched(self.t(r)):
                return False  # return { puppeteer }: read back by returned_member, patched only as x.puppeteer.k = ...
            return True  # the module object itself escapes: const m = cp; m.spawn = ... (B9)
        return False

    def member_patched(self, name: str) -> bool:
        """Some code writes through a property of that name: x.name.k = ..., Object.assign(x.name, ...)."""
        e = re.escape(name.encode())
        rx = re.compile(rb"\.\s*" + e + rb"\s*(?:(?:\.\s*[\w$]+|\[[^\]\n]*\])\s*)+(?:[-+*/|&]?=(?![=>])|\+\+|--)"
                        rb"|\b(?:assign|defineProperty|defineProperties|set)\s*\([^,)]*\.\s*" + e + rb"\s*[,)]")
        return any(self.in_code(m.start()) for m in rx.finditer(self.src))

    def binding_patched(self, decl) -> bool:
        key = _k(decl)
        if key in self._patched_memo:
            return self._patched_memo[key]
        self._patched_memo[key] = True  # cycle guard: fail closed
        name = self.t(decl)
        mod = self.decl_module(decl)
        namespace = mod is not None and not tuple(m for m in mod[1] if m != "default")
        scope = self.decl_scope(decl)
        out = (
            name in self.global_names()
            or len(self.decls(name).get(_k(scope), [])) > 1  # declared twice in one scope: var cp = require(); var cp = {}
            or any(self.patched_use(r, namespace) for r in self.refs(decl))
        )
        self._patched_memo[key] = out
        return out

    def module_patched(self, mod: str) -> bool:
        """Any binding of mod, or an inline require('mod'), is patched anywhere in the file."""
        if mod in self._mod_patched_memo:
            return self._mod_patched_memo[mod]
        self._mod_patched_memo[mod] = True
        e = re.escape(mod.encode())
        out = False
        rx = re.compile(rb"(?:require|import|[\w$]+)\s*\(\s*['\"`](?:node:)?" + e + rb"['\"`]\s*\)|\bfrom\s*['\"](?:node:)?" + e
                        + rb"['\"]|\bimport\s*['\"](?:node:)?" + e + rb"['\"]")
        for m in rx.finditer(self.src):
            n = self.root.named_descendant_for_byte_range(m.end() - 2, m.end() - 1)
            st = n
            while st is not None and st.type not in ("call_expression", "import_statement"):
                st = st.parent
            if st is None:
                continue
            if st.type == "import_statement":
                for c in self.walk(st):
                    if c.type == "identifier" and self.decl_scope(c) is not None and self.binding_patched(c):
                        out = True
                continue
            if self.module_of(st) is None or self.module_of(st)[0] != mod:
                continue
            # require('m').x = ..., Object.assign(require('m'), ...), and every binding made from it
            top, q = st, st.parent
            while q is not None and (q.type in _JS_WRAP or (q.type in ("member_expression", "subscript_expression") and top == self.f(q, "object"))):
                top, q = q, q.parent
            if q is not None and q.type in ("assignment_expression", "augmented_assignment_expression") and top == self.f(q, "left") and top != st:
                out = True
            n2, q2 = self.up(st)
            if q2 is not None and q2.type == "arguments" and self.callee(q2.parent) in _PATCH_CALLS and self.arg_index(q2.parent, n2) == 0:
                out = True
            d = self.nearest(st, {"variable_declarator", "statement_block", "program"})
            if d is not None and d.type == "variable_declarator":
                for c in self.walk(self.f(d, "name")):
                    if c.type in ("identifier", "shorthand_property_identifier_pattern") and self.decl_scope(c) is not None and self.binding_patched(c):
                        out = True
            if out:
                break
        self._mod_patched_memo[mod] = out
        return out

    def walk(self, n):
        stack = [n]
        while stack:
            x = stack.pop()
            yield x
            stack.extend(x.children)

    def launcher(self, call) -> bool:
        fn = self.callee_node(call)
        if fn is None:
            return False
        path = self.module_of(fn)
        if path is None or not launcher_path(*path):
            return False
        root = fn
        while root.type in ("member_expression", "subscript_expression"):
            root = self.f(root, "object")
            while root is not None and root.type in _JS_WRAP:
                root = root.named_children[0]
        if root is not None and root.type == "identifier":
            decl = self.resolve(root)
            if decl is None or self.binding_patched(decl):
                return False
        return not self.module_patched(path[0])

    def launcher_text(self, callee: str) -> bool:
        """For a callee given as text: resolved at module level (the r2 unit test's interface)."""
        raw = re.sub(r"^new\s+", "", callee.strip())
        parts = raw.split(".")
        d = self.decls(parts[0]).get(_k(self.root))
        if not d:
            return False
        base = self.decl_module(d[0])
        if base is None or self.binding_patched(d[0]):
            return False
        path = (base[0], base[1] + tuple(parts[1:]))
        return launcher_path(*path) and not self.module_patched(path[0])

    # -------- copies

    def env_nodes(self):
        for m in _JS_ENV_RE.finditer(self.src):
            n = self.root.named_descendant_for_byte_range(m.start(), m.end())
            if n is None or n.type not in ("member_expression", "subscript_expression"):
                continue
            obj = self.f(n, "object")
            if obj is None or re.sub(r"\s+|\?(?=\.)", "", self.t(obj)) not in _ENV_OBJECTS:
                continue
            yield n

    def copy_of(self, e):
        """(copy node, family, debug target) for an env object used as a whole copy, or None."""
        n, p = self.up(e)
        if p is None:
            return None
        if p.type == "spread_element":
            obj = p.parent
            return (obj, "spread", None) if obj is not None and obj.type == "object" else None
        if p.type != "arguments":
            return None
        call = p.parent
        c, i = self.callee(call), self.arg_index(call, n)
        if c == "Object.assign" and i >= 1:
            return call, "spread", None
        if c == "structuredClone" and i == 0:
            return call, "spread", None
        if c in ("Object.entries", "Object.values", "Object.keys") and i == 0:
            debug = None
            if c == "Object.keys":
                tail = self.src[call.end_byte : call.end_byte + 600].decode("utf-8", "replace")
                m = PREFIX_FILTER_RE.match(tail)
                if m is not None and not SECRETISH_RE.search(m.group(1)):
                    debug = True
            return self.chain(call), "old", debug
        return None

    def chain(self, call):
        """Object.fromEntries(Object.entries(process.env).filter(...).map(...)) as one copy."""
        c = call
        while True:
            n, p = self.up(c)
            if p is not None and p.type == "member_expression" and n == self.f(p, "object"):
                q = p.parent
                if q is not None and q.type == "call_expression" and self.f(q, "function") == p:
                    c = q
                    continue
            if p is not None and p.type == "arguments" and self.callee(p.parent) == "Object.fromEntries":
                c = p.parent
                continue
            return c

    def is_env_key(self, key) -> bool:
        return key is not None and self.t(key).strip("'\"`") == "env"

    # -------- bound

    def use(self, n, mode: str, depth: int) -> str:
        """"ok" (ends in a launcher's env slot), "skip" (not a use of the whole value) or "bad"."""
        while True:
            n, p = self.up(n)
            if p is None:
                return "bad"
            t = p.type
            if t == "ternary_expression":
                if n == self.f(p, "condition"):
                    return "skip"
                n = p
                continue
            if t == "binary_expression":
                op = self.f(p, "operator")
                op = self.t(op) if op is not None else ""
                if op in ("||", "??") or (op == "&&" and n == self.f(p, "right")):
                    n = p
                    continue
                if op == "&&" or op in ("===", "!==", "==", "!=", "instanceof") or (op == "in" and n == self.f(p, "right")):
                    return "skip"
                return "bad"
            if t == "sequence_expression":
                kids = [c for c in p.named_children if c.type != "comment"]
                if kids and n == kids[-1]:
                    n = p
                    continue
                return "skip"
            if t == "spread_element":
                obj = p.parent
                if obj is not None and obj.type == "object":
                    n = obj
                    continue
                return "bad"
            if t == "pair":
                if n != self.f(p, "value"):
                    return "bad"
                if mode == "env" and self.is_env_key(self.f(p, "key")):
                    n, mode = p.parent, "opts"
                    continue
                return "bad"
            if t == "arguments":
                call = p.parent
                if mode == "opts" and self.launcher(call):
                    return "ok"
                if mode == "env" and self.callee(call) == "Object.assign":
                    n = call
                    continue
                return "bad"
            if t == "variable_declarator":
                name = self.f(p, "name")
                if n != self.f(p, "value") or name is None or name.type != "identifier":
                    return "bad"
                return self.var(name, mode, depth)
            if t == "assignment_pattern":
                left = self.f(p, "left")
                if n == self.f(p, "right") and left is not None and left.type == "identifier" and self.decl_scope(left) is not None:
                    return self.var(left, mode, depth)
                return "bad"
            if t == "assignment_expression":
                if n != self.f(p, "right"):
                    return "skip"
                left = self.f(p, "left")
                if left.type == "identifier":
                    decl = self.resolve(left)
                    return self.var(decl, mode, depth) if decl is not None else "bad"
                if mode == "env" and left.type == "member_expression" and self.t(self.f(left, "property")) == "env":
                    obj = self.f(left, "object")
                    if obj.type == "identifier" and (decl := self.resolve(obj)) is not None:
                        return self.var(decl, "opts", depth)  # opts.env = copy; spawn(..., opts)
                return "bad"
            if t == "return_statement":
                fn = self.nearest(p, _JS_FUNCS)
                return self.fn(fn, mode, depth) if fn is not None else "bad"
            if t == "arrow_function" and n == self.f(p, "body"):
                return self.fn(p, mode, depth)
            if t == "expression_statement":
                return "skip"
            return "bad"

    def ref_use(self, r, mode: str, depth: int) -> str:
        if r.type == "shorthand_property_identifier":
            if mode == "env" and self.t(r) == "env":
                return self.use(r.parent, "opts", depth)  # spawn(cmd, args, { env })
            return "bad"
        p = r.parent
        if p is None:
            return "bad"
        t = p.type
        if t == "member_expression" and r == self.f(p, "object"):
            return "bad" if self.t(self.f(p, "property")) in ("toString", "valueOf", "toJSON") else "skip"
        if t == "subscript_expression" and r == self.f(p, "object"):
            return "skip"
        if t == "unary_expression":
            return "skip"
        if t in ("assignment_expression", "augmented_assignment_expression") and r == self.f(p, "left"):
            return "skip"
        if t == "update_expression":
            return "skip"
        if t == "for_in_statement" and r == self.f(p, "right") and self.t(self.f(p, "operator")) == "in":
            return "skip"
        if t == "arguments" and self.callee(p.parent) == "Object.keys":
            return "skip"
        if t == "parenthesized_expression" and p.parent is not None and p.parent.type in ("if_statement", "while_statement", "do_statement"):
            return "skip"
        if t in ("export_specifier", "export_clause"):
            return "bad"
        return self.use(r, mode, depth)

    def var(self, decl, mode: str, depth: int) -> str:
        if depth >= _DEPTH:
            return "bad"
        ok = False
        for r in self.refs(decl):
            u = self.ref_use(r, mode, depth + 1)
            if u == "bad":
                return "bad"
            ok = ok or u == "ok"
        return "ok" if ok else "bad"

    def fn_name(self, fn):
        """(name node, is_method) of a function, or (None, False)."""
        if fn.type in ("function_declaration", "generator_function_declaration"):
            return self.f(fn, "name"), False
        if fn.type == "method_definition":
            return self.f(fn, "name"), True
        n, p = self.up(fn)
        if p is not None and p.type == "variable_declarator" and n == self.f(p, "value") and self.f(p, "name").type == "identifier":
            return self.f(p, "name"), False
        if p is not None and p.type == "pair" and n == self.f(p, "value"):
            return self.f(p, "key"), True
        if p is not None and p.type == "assignment_expression" and n == self.f(p, "right"):
            left = self.f(p, "left")
            if left.type == "identifier":
                return left, False
            if left.type == "member_expression":
                return self.f(left, "property"), True
        return None, False

    def call_sites(self, fn) -> list | None:
        n, p = self.up(fn)
        if p is not None and p.type == "call_expression" and self.callee_node(p) == n:
            return [p]  # (() => copy)()
        name, method = self.fn_name(fn)
        if name is None:
            return None
        out = []
        if method:
            rx = re.compile(rb"\.\s*" + re.escape(self.src[name.start_byte : name.end_byte]) + rb"\s*\(")
            for m in rx.finditer(self.src):
                q = self.root.named_descendant_for_byte_range(m.start() + 1, m.end() - 1)
                while q is not None and q.type == "property_identifier":
                    q = q.parent
                if q is not None and q.type == "member_expression" and q.parent is not None and q.parent.type == "call_expression" \
                        and self.f(q.parent, "function") == q:
                    out.append(q.parent)
            return out
        decl = name if self.decl_scope(name) is not None else self.resolve(name)
        if decl is None:
            return None
        for r in self.refs(decl):
            q = r.parent
            if q is not None and q.type == "call_expression" and self.f(q, "function") == r:
                out.append(q)
            elif q is not None and q.type in ("export_specifier", "export_clause"):
                continue  # used from another file: not seen here
            elif q is not None and q.type == "assignment_expression" and r == self.f(q, "left"):
                continue
            elif r.type == "shorthand_property_identifier" and self.nearest(r, {"assignment_expression"}) is not None \
                    and re.match(r"(?:module\.)?exports\b", self.t(self.f(self.nearest(r, {"assignment_expression"}), "left"))):
                continue  # module.exports = { getEnv }
            else:
                return None
        return out

    def fn(self, fn, mode: str, depth: int) -> str:
        if depth >= _DEPTH:
            return "bad"
        sites = self.call_sites(fn)
        if not sites:
            return "bad"
        ok = False
        for c in sites:
            u = self.use(c, mode, depth + 1)
            if u == "bad":
                return "bad"
            ok = ok or u == "ok"
        return "ok" if ok else "bad"

    # -------- debug option filter (R42 N5)

    def debug_bound(self, chain) -> bool:
        n, p = self.up(chain)
        if p is None:
            return False
        if p.type == "assignment_expression" and n == self.f(p, "right"):
            target = self.f(p, "left")
        elif p.type == "variable_declarator" and n == self.f(p, "value"):
            target = self.f(p, "name")
        else:
            return False
        tt = self.t(target)
        if target.type not in ("identifier", "member_expression"):
            return False
        rx = re.compile(rb"(?<![\w$.])" + re.escape(self.src[target.start_byte : target.end_byte]) + rb"(?![\w$])")
        seen = False
        for m in rx.finditer(self.src):
            if m.start() == target.start_byte:
                continue
            q = self.root.named_descendant_for_byte_range(m.start(), m.end())
            if q is None or q.start_byte != m.start() or q.end_byte != m.end() or self.t(q) != tt:
                continue
            p = q.parent
            if p is None:
                return False
            if p.type == "member_expression" and q == self.f(p, "object"):
                if self.t(self.f(p, "property")) in ("valueOf", "toJSON", "toString"):
                    return False
                seen = True
                continue
            if p.type == "subscript_expression" and q == self.f(p, "object"):
                seen = True
                continue
            if p.type == "binary_expression" and q == self.f(p, "right") and self.t(self.f(p, "operator")) == "in":
                seen = True
                continue
            if p.type == "assignment_expression" and q == self.f(p, "left"):
                continue
            if p.type == "arguments":
                call = p.parent
                if self.callee(call) == "Object.keys":
                    seen = True
                    continue
                path = self.module_of(self.callee_node(call))
                slot = OPTION_SINKS.get(path) if path is not None else None
                if slot is not None and self.arg_index(call, q) == slot:
                    seen = True
                    continue
            return False
        return seen

    # -------- sinks

    def sink_call(self, call) -> bool:
        callee = self.callee(call)
        args = self.f(call, "arguments")
        args_t = self.t(args) if args is not None else ""
        first = self.args_of(call)
        return self.is_net(callee, args_t, self.t(first[0]) if first else "") or _is_write(callee)

    def sink(self, n, depth: int) -> bool:
        while True:
            p = n.parent
            if p is None:
                return False
            t = p.type
            if t in ("call_expression", "new_expression"):
                if self.sink_call(p):
                    return True
                n = p
                continue
            if t == "variable_declarator":
                name = self.f(p, "name")
                if n != self.f(p, "value") or name is None:
                    return False
                return any(self.var_sink(c, depth) for c in self.walk(name) if c.type in _JS_IDENTS[::2] and self.decl_scope(c) is not None)
            if t == "assignment_pattern" and n == self.f(p, "right"):
                left = self.f(p, "left")
                return left is not None and left.type == "identifier" and self.decl_scope(left) is not None and self.var_sink(left, depth)
            if t in ("assignment_expression", "augmented_assignment_expression"):
                if n != self.f(p, "right"):
                    return False
                left = self.f(p, "left")
                while left is not None and left.type in ("member_expression", "subscript_expression"):
                    left = self.f(left, "object")
                if left is not None and left.type == "identifier" and (decl := self.resolve(left)) is not None:
                    return self.var_sink(decl, depth)
                return False
            if t == "return_statement":
                fn = self.nearest(p, _JS_FUNCS)
                return fn is not None and self.fn_sink(fn, depth)
            if t == "arrow_function":
                return n == self.f(p, "body") and self.fn_sink(p, depth)
            if t in _JS_FUNCS or t.endswith("_statement") or t.endswith("_declaration") or t in (
                    "program", "statement_block", "class_body", "switch_body", "switch_case", "switch_default"):
                return False
            n = p

    def var_sink(self, decl, depth: int) -> bool:
        if depth >= _DEPTH:
            return False
        for r in self.refs(decl):
            p = r.parent
            if p is not None and p.type in ("assignment_expression", "augmented_assignment_expression") and r == self.f(p, "left"):
                continue
            if self.sink(r, depth + 1):
                return True
        return False

    def fn_sink(self, fn, depth: int) -> bool:
        if depth >= _DEPTH:
            return False
        return any(self.sink(c, depth + 1) for c in self.call_sites(fn) or [])

    # -------- driver

    def copies(self) -> list[EnvCopy]:
        out = []
        for e in self.env_nodes():
            c = self.copy_of(e)
            if c is None:
                continue
            node, family, debug = c
            bound = bool(debug) and self.debug_bound(node)
            if not bound:
                bound = self.use(node, "env", 0) == "ok"
            sink = not bound and self.sink(node, 0)
            out.append(EnvCopy(self.char(e.start_byte), e.start_point[0] + 1, family, bound, sink))
        return out


# ---------------------------------------------------------------- Python


_COMPS = (ast.ListComp, ast.SetComp, ast.DictComp, ast.GeneratorExp)


class _Scope:
    def __init__(self, node, parent):
        self.node, self.parent = node, parent
        self.kind = ("module" if parent is None else "class" if isinstance(node, ast.ClassDef)
                     else "comp" if isinstance(node, _COMPS) else "function")
        self.binds: dict[str, list] = {}
        self.globals: set[str] = set()
        self.nonlocals: set[str] = set()


class _Py:
    def __init__(self, text: str, is_net: IsNet):
        self.text = text
        self.tree = ast.parse(text)
        self.is_net = is_net
        self.parent: dict[int, ast.AST] = {}
        self.scope_of: dict[int, _Scope] = {}
        self.names: dict[str, list[ast.Name]] = {}
        self.module = _Scope(self.tree, None)
        self.scopes: dict[int, _Scope] = {id(self.tree): self.module}
        self._build(self.tree, self.module)
        self.lines = text.split("\n")
        self.starts = [0]
        for ln in self.lines:
            self.starts.append(self.starts[-1] + len(ln) + 1)
        self._patches()

    # -------- scopes

    def _bind(self, scope: _Scope, name: str, node) -> None:
        s = scope
        if name in s.globals:
            s = self.module
        s.binds.setdefault(name, []).append(node)

    def _build(self, node, scope: _Scope) -> None:
        for child in ast.iter_child_nodes(node):
            self.parent[id(child)] = node
        if isinstance(node, (ast.Global, ast.Nonlocal)):
            (scope.globals if isinstance(node, ast.Global) else scope.nonlocals).update(node.names)
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and node is not scope.node:
            self._bind(scope, node.name, node)
            for d in node.decorator_list:
                self._visit(d, scope)
            if isinstance(node, ast.ClassDef):
                for b in node.bases + [k.value for k in node.keywords]:
                    self._visit(b, scope)
            else:
                for d in node.args.defaults + [x for x in node.args.kw_defaults if x is not None]:
                    self._visit(d, scope)
            inner = _Scope(node, scope)
            self.scopes[id(node)] = inner
            if not isinstance(node, ast.ClassDef):
                for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs + [node.args.vararg, node.args.kwarg]:
                    if a is not None:
                        self._bind(inner, a.arg, a)
            for st in node.body:
                self.parent[id(st)] = node
                self._visit(st, inner)
            return
        for child in ast.iter_child_nodes(node):
            self._visit(child, scope)

    def _visit(self, node, scope: _Scope) -> None:
        self.scope_of[id(node)] = scope
        if isinstance(node, ast.Name):
            self.names.setdefault(node.id, []).append(node)
            if isinstance(node.ctx, (ast.Store, ast.Del)):
                self._bind(scope, node.id, node)
            return
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            self.scope_of[id(node)] = scope
            self._build(node, scope)
            return
        if isinstance(node, ast.Lambda):
            for d in node.args.defaults:
                self._visit(d, scope)
            inner = _Scope(node, scope)
            self.scopes[id(node)] = inner
            for a in node.args.posonlyargs + node.args.args + node.args.kwonlyargs + [node.args.vararg, node.args.kwarg]:
                if a is not None:
                    self._bind(inner, a.arg, a)
            for child in ast.iter_child_nodes(node):
                self.parent[id(child)] = node
            self._visit(node.body, inner)
            return
        if isinstance(node, _COMPS):
            for child in ast.iter_child_nodes(node):
                self.parent[id(child)] = node
            gens = node.generators
            self._visit(gens[0].iter, scope)  # the first iterable runs in the enclosing scope
            inner = _Scope(node, scope)
            self.scopes[id(node)] = inner
            for i, g in enumerate(gens):
                self.parent[id(g)] = node
                for child in ast.iter_child_nodes(g):
                    self.parent[id(child)] = g
                self._visit(g.target, inner)
                if i:
                    self._visit(g.iter, inner)
                for c in g.ifs:
                    self._visit(c, inner)
            for part in ((node.key, node.value) if isinstance(node, ast.DictComp) else (node.elt,)):
                self._visit(part, inner)
            return
        if isinstance(node, ast.NamedExpr):
            s = scope
            while s.kind == "comp":
                s = s.parent
            self._visit(node.target, s)
            self._visit(node.value, scope)
            for child in ast.iter_child_nodes(node):
                self.parent[id(child)] = node
            return
        if isinstance(node, (ast.Import, ast.ImportFrom)):
            for a in node.names:
                if a.name == "*":
                    continue
                self._bind(scope, a.asname or a.name.split(".")[0], node)
        elif isinstance(node, ast.ExceptHandler) and node.name:
            self._bind(scope, node.name, node)
        elif isinstance(node, (ast.MatchAs, ast.MatchStar)) and node.name:
            self._bind(scope, node.name, node)
        elif isinstance(node, ast.MatchMapping) and node.rest:
            self._bind(scope, node.rest, node)
        self._build(node, scope)

    def resolve(self, name: str, scope: _Scope) -> _Scope | None:
        s, first = scope, True
        while s is not None:
            if name in s.globals:
                return self.module if name in self.module.binds else None
            if s.kind == "class" and not first:
                s = s.parent
                continue
            if name in s.binds and name not in s.nonlocals:
                return s
            s, first = s.parent, False
        return None

    def scope_at(self, node) -> _Scope:
        n = node
        while id(n) not in self.scope_of and id(n) in self.parent:
            n = self.parent[id(n)]
        return self.scope_of.get(id(n), self.module)

    def name_refs(self, name: str, scope: _Scope) -> list[ast.Name]:
        return [n for n in self.names.get(name, []) if self.resolve(name, self.scope_of[id(n)]) is scope]

    # -------- modules and launchers

    def import_path(self, name: str, scope: _Scope | None) -> tuple | None:
        """(module, members) every binding of name in scope imports, or None (not only imports)."""
        if scope is None:
            return None
        paths = set()
        for b in scope.binds.get(name, []):
            if isinstance(b, ast.Import):
                for a in b.names:
                    if (a.asname or a.name.split(".")[0]) == name:
                        paths.add((a.name, ()) if a.asname else (a.name.split(".")[0], ()))
            elif isinstance(b, ast.ImportFrom) and b.module and not b.level:
                for a in b.names:
                    if (a.asname or a.name) == name:
                        paths.add((b.module, (a.name,)))
            elif isinstance(b, ast.Name) and isinstance(self.parent.get(id(b)), ast.Assign):
                v = self.parent[id(b)].value
                if (isinstance(v, ast.Call) and v.args and isinstance(v.args[0], ast.Constant) and isinstance(v.args[0].value, str)
                        and ast.unparse(v.func) in ("importlib.import_module", "import_module", "__import__")):
                    paths.add((v.args[0].value, ()))
                else:
                    return None
            else:
                return None
        return paths.pop() if len(paths) == 1 else None

    def path_of(self, expr, scope: _Scope) -> tuple | None:
        attrs: list[str] = []
        while isinstance(expr, ast.Attribute):
            attrs.insert(0, expr.attr)
            expr = expr.value
        if not isinstance(expr, ast.Name):
            return None
        s = self.resolve(expr.id, scope)
        if s is None or expr.id in self.patched_names or self.patch_all:
            return None
        base = self.import_path(expr.id, s)
        if base is None:
            return None
        mod, members = base
        parts = mod.split(".")
        return parts[0], tuple(parts[1:]) + members + tuple(attrs)

    def _patches(self) -> None:
        """Names and modules the file rebinds or patches anywhere (attribute writes, setattr, globals(),
        sys.modules, exec/eval strings)."""
        names: set[str] = set()
        mods: set[str] = set()
        self.patch_all = False
        self.patched_names, self.patched_mods = names, mods

        def root(e):
            while isinstance(e, (ast.Attribute, ast.Subscript)):
                e = e.value
            return e

        def patch_root(e):
            r = root(e)
            if isinstance(r, ast.Name):
                names.add(r.id)
                base = self.import_path(r.id, self.resolve(r.id, self.scope_at(r)))
                if base is not None:
                    mods.add(base[0].split(".")[0])

        def key_patch(sub):
            v = sub.value
            k = sub.slice
            lit = k.value if isinstance(k, ast.Constant) and isinstance(k.value, str) else None
            vs = ast.unparse(v)
            if vs in ("globals()", "vars()", "locals()"):
                if lit is None:
                    self.patch_all = True
                else:
                    names.add(lit)
                return True
            if vs in ("sys.modules", "modules"):
                if lit is None:
                    self.patch_all = True
                else:
                    mods.add(lit.split(".")[0])
                return True
            return False

        for n in ast.walk(self.tree):
            targets = []
            if isinstance(n, (ast.Assign, ast.Delete)):
                targets = n.targets
            elif isinstance(n, (ast.AugAssign, ast.AnnAssign)):
                targets = [n.target]
            flat = []
            for tg in targets:
                flat.extend(x for x in ast.walk(tg) if x is tg or isinstance(self.parent.get(id(x)), (ast.Tuple, ast.List, ast.Starred)))
            for x in flat:
                if isinstance(x, ast.Attribute):
                    patch_root(x)  # subprocess.run = fake, sp.Popen.x = y
                elif isinstance(x, ast.Subscript) and not key_patch(x):
                    if isinstance(x.value, ast.Attribute) and x.value.attr == "__dict__":
                        patch_root(x.value)  # subprocess.__dict__["run"] = fake
            if isinstance(n, ast.Call):
                fn = ast.unparse(n.func)
                if fn in ("setattr", "delattr") and n.args:
                    tgt = n.args[0]
                    if isinstance(tgt, ast.Subscript) and key_patch(tgt):
                        pass
                    else:
                        patch_root(tgt)
                    if len(n.args) > 1 and isinstance(n.args[1], ast.Constant) and isinstance(n.args[1].value, str):
                        names.add(n.args[1].value)
                    elif not isinstance(tgt, ast.Name):
                        self.patch_all = True
                elif fn in ("globals().update", "vars().update", "locals().update", "sys.modules.update",
                            "sys.modules.setdefault", "sys.modules.__setitem__", "globals().__setitem__", "globals().setdefault"):
                    self.patch_all = True
                elif fn in ("exec", "eval", "builtins.exec", "builtins.eval") and n.args:
                    a = n.args[0]
                    if isinstance(a, ast.Constant) and isinstance(a.value, str):
                        names.update(re.findall(r"[A-Za-z_]\w*", a.value))

    def launcher(self, call: ast.Call) -> tuple | None:
        path = self.path_of(call.func, self.scope_at(call))
        if path is None or not launcher_path(*path) or path[0] in self.patched_mods:
            return None
        return path

    def launcher_text(self, callee: str) -> bool:
        parts = callee.strip().split(".")
        base = self.import_path(parts[0], self.module if parts[0] in self.module.binds else None)
        if base is None or parts[0] in self.patched_names or self.patch_all:
            return False
        mp = base[0].split(".")
        path = (mp[0], tuple(mp[1:]) + base[1] + tuple(parts[1:]))
        return launcher_path(*path) and path[0] not in self.patched_mods

    def env_slot(self, call: ast.Call, n) -> bool:
        path = self.launcher(call)
        if path is None:
            return False
        if any(k.arg == "env" and k.value is n for k in call.keywords):
            return True
        return path[0] == "os" and bool(call.args) and call.args[-1] is n

    # -------- copies

    def is_environ(self, n) -> bool:
        if isinstance(n, ast.Attribute) and n.attr == "environ" and isinstance(n.value, ast.Name):
            nm = n.value.id
            base = self.import_path(nm, self.resolve(nm, self.scope_at(n)))
            return nm == "os" if base is None else base == ("os", ())
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            base = self.import_path(n.id, self.resolve(n.id, self.scope_at(n)))
            return base == ("os", ("environ",))
        return False

    def copy_of(self, e):
        p = self.parent.get(id(e))
        if isinstance(p, ast.Dict) and any(k is None and v is e for k, v in zip(p.keys, p.values)):
            return p, "spread"
        if isinstance(p, ast.keyword) and p.arg is None:
            call = self.parent.get(id(p))
            if isinstance(call, ast.Call) and ast.unparse(call.func) == "dict":
                return call, "spread"
            return None
        if isinstance(p, ast.Call) and e in p.args and p.args[0] is e:
            fn = ast.unparse(p.func)
            if fn == "dict":
                return p, "old"
            if fn in ("copy.copy", "copy.deepcopy", "copy", "deepcopy"):
                return p, "spread"
            return None
        if isinstance(p, ast.Attribute) and p.value is e and p.attr in ("copy", "items"):
            call = self.parent.get(id(p))
            if isinstance(call, ast.Call) and call.func is p:
                c = call
                q = self.parent.get(id(c))
                if p.attr == "items":
                    if isinstance(q, ast.Call) and ast.unparse(q.func) == "dict" and q.args and q.args[0] is c:
                        c = q
                    elif isinstance(q, ast.comprehension) and q.iter is c:
                        c = self.parent[id(q)]
                return c, "old"
        return None

    def use(self, n, mode: str, depth: int) -> str:
        while True:
            p = self.parent.get(id(n))
            if p is None:
                return "bad"
            if isinstance(p, ast.Dict):
                for k, v in zip(p.keys, p.values):
                    if v is n:
                        if k is None:
                            break
                        if mode == "env" and isinstance(k, ast.Constant) and k.value == "env":
                            mode = "opts"
                            break
                        return "bad"
                else:
                    return "bad"
                n = p
                continue
            if isinstance(p, ast.keyword):
                call = self.parent.get(id(p))
                if not isinstance(call, ast.Call):
                    return "bad"
                if mode == "env" and p.arg == "env" and self.env_slot(call, n):
                    return "ok"
                if mode == "opts" and p.arg is None and self.launcher(call) is not None:
                    return "ok"  # subprocess.run(cmd, **opts)
                if mode == "env" and p.arg is None and ast.unparse(call.func) == "dict":
                    n = call
                    continue
                return "bad"
            if isinstance(p, ast.Call):
                if n is p.func:
                    return "bad"
                if mode == "env" and self.env_slot(p, n):
                    return "ok"
                if mode == "env" and p.args and p.args[0] is n and ast.unparse(p.func) in ("dict", "copy.copy", "copy.deepcopy"):
                    n = p
                    continue
                return "bad"
            if isinstance(p, ast.Attribute) and p.value is n:
                call = self.parent.get(id(p))
                if p.attr == "copy" and isinstance(call, ast.Call) and call.func is p:
                    n = call
                    continue
                return "bad"
            if isinstance(p, ast.IfExp):
                if n is p.test:
                    return "skip"
                n = p
                continue
            if isinstance(p, ast.BoolOp):
                n = p
                continue
            if isinstance(p, ast.NamedExpr) and n is p.value:
                s = self.resolve(p.target.id, self.scope_at(p.target))
                return self.var(p.target.id, s, mode, depth) if s is not None else "bad"
            if isinstance(p, (ast.Assign, ast.AnnAssign)) and n is p.value:
                tg = p.targets if isinstance(p, ast.Assign) else [p.target]
                if len(tg) == 1 and isinstance(tg[0], ast.Name):
                    s = self.resolve(tg[0].id, self.scope_at(tg[0]))
                    return self.var(tg[0].id, s, mode, depth) if s is not None else "bad"
                if (len(tg) == 1 and mode == "env" and isinstance(tg[0], ast.Subscript) and isinstance(tg[0].value, ast.Name)
                        and isinstance(tg[0].slice, ast.Constant) and tg[0].slice.value == "env"):
                    nm = tg[0].value.id  # opts["env"] = copy; subprocess.run(cmd, **opts)
                    s = self.resolve(nm, self.scope_at(tg[0].value))
                    return self.var(nm, s, "opts", depth) if s is not None else "bad"
                return "bad"
            if isinstance(p, ast.Return):
                fn = self.func_of(p)
                return self.fn(fn, mode, depth) if fn is not None else "bad"
            if isinstance(p, ast.Expr):
                return "skip"
            return "bad"

    def func_of(self, node):
        n = self.parent.get(id(node))
        while n is not None and not isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda)):
            n = self.parent.get(id(n))
        return n if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef)) else None

    def ref_use(self, r: ast.Name, mode: str, depth: int) -> str:
        if not isinstance(r.ctx, ast.Load):
            return "skip"
        p = self.parent.get(id(r))
        if isinstance(p, ast.Subscript) and p.value is r:
            return "skip"
        if isinstance(p, ast.Attribute) and p.value is r:
            call = self.parent.get(id(p))
            if p.attr in ("copy",) and isinstance(call, ast.Call) and call.func is p:
                return self.use(call, mode, depth)
            if p.attr in ("update", "pop", "setdefault", "get", "keys", "clear", "__contains__", "__getitem__", "__setitem__", "__delitem__"):
                return "skip"
            return "bad"
        if isinstance(p, ast.Compare) and any(c is r for c in p.comparators) and all(isinstance(o, (ast.In, ast.NotIn)) for o in p.ops):
            return "skip"
        if isinstance(p, (ast.For, ast.AsyncFor, ast.comprehension)) and p.iter is r:
            return "skip"
        if isinstance(p, (ast.If, ast.While, ast.Assert)) and p.test is r:
            return "skip"
        if isinstance(p, ast.UnaryOp) and isinstance(p.op, ast.Not):
            return "skip"
        if isinstance(p, ast.Call) and ast.unparse(p.func) in ("len", "bool", "isinstance") and r in p.args:
            return "skip"
        return self.use(r, mode, depth)

    def var(self, name: str, scope: _Scope, mode: str, depth: int) -> str:
        if depth >= _DEPTH:
            return "bad"
        ok = False
        for r in self.name_refs(name, scope):
            u = self.ref_use(r, mode, depth + 1)
            if u == "bad":
                return "bad"
            ok = ok or u == "ok"
        return "ok" if ok else "bad"

    def call_sites(self, fn) -> list | None:
        scope = self.scope_at(fn)
        out = []
        if scope.kind == "class":
            for n in ast.walk(self.tree):
                if isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr == fn.name:
                    out.append(n)
            return out
        for r in self.name_refs(fn.name, scope):
            if not isinstance(r.ctx, ast.Load):
                continue
            p = self.parent.get(id(r))
            if isinstance(p, ast.Call) and p.func is r:
                out.append(p)
            else:
                return None
        return out

    def fn(self, fn, mode: str, depth: int) -> str:
        if depth >= _DEPTH:
            return "bad"
        sites = self.call_sites(fn)
        if not sites:
            return "bad"
        ok = False
        for c in sites:
            u = self.use(c, mode, depth + 1)
            if u == "bad":
                return "bad"
            ok = ok or u == "ok"
        return "ok" if ok else "bad"

    # -------- sinks

    def sink_call(self, call: ast.Call) -> bool:
        callee = ast.unparse(call.func)
        parts = [ast.unparse(a) for a in call.args] + [f"{k.arg}={ast.unparse(k.value)}" if k.arg else f"**{ast.unparse(k.value)}"
                                                       for k in call.keywords]
        first = ast.unparse(call.args[0]) if call.args else ""
        return self.is_net(callee, ", ".join(parts), first) or _is_write(callee)

    def sink(self, n, depth: int) -> bool:
        while True:
            p = self.parent.get(id(n))
            if p is None:
                return False
            if isinstance(p, ast.Call):
                if self.sink_call(p):
                    return True
                n = p
                continue
            if isinstance(p, (ast.Assign, ast.AnnAssign, ast.AugAssign)):
                if n is not p.value:
                    return False
                tgs = p.targets if isinstance(p, ast.Assign) else [p.target]
                for tg in tgs:
                    while isinstance(tg, (ast.Attribute, ast.Subscript)):
                        tg = tg.value
                    for x in ast.walk(tg):
                        if isinstance(x, ast.Name):
                            s = self.resolve(x.id, self.scope_at(x))
                            if s is not None and self.var_sink(x.id, s, depth):
                                return True
                return False
            if isinstance(p, ast.NamedExpr) and n is p.value:
                s = self.resolve(p.target.id, self.scope_at(p.target))
                if s is not None and self.var_sink(p.target.id, s, depth):
                    return True
                n = p
                continue
            if isinstance(p, ast.Return):
                fn = self.func_of(p)
                return fn is not None and self.fn_sink(fn, depth)
            if isinstance(p, (ast.stmt, ast.Lambda, ast.comprehension)):
                return False
            n = p

    def var_sink(self, name: str, scope: _Scope, depth: int) -> bool:
        if depth >= _DEPTH:
            return False
        return any(isinstance(r.ctx, ast.Load) and self.sink(r, depth + 1) for r in self.name_refs(name, scope))

    def fn_sink(self, fn, depth: int) -> bool:
        if depth >= _DEPTH:
            return False
        return any(self.sink(c, depth + 1) for c in self.call_sites(fn) or [])

    # -------- driver

    def char(self, node) -> int:
        line = self.lines[node.lineno - 1]
        col = len(line.encode()[: node.col_offset].decode("utf-8", "replace"))
        return self.starts[node.lineno - 1] + col

    def copies(self) -> list[EnvCopy]:
        out = []
        for e in ast.walk(self.tree):
            if not isinstance(e, (ast.Attribute, ast.Name)) or not self.is_environ(e):
                continue
            c = self.copy_of(e)
            if c is None:
                continue
            node, family = c
            bound = self.use(node, "env", 0) == "ok"
            sink = not bound and self.sink(node, 0)
            out.append(EnvCopy(self.char(e), e.lineno, family, bound, sink))
        return out


# ---------------------------------------------------------------- entry points


def _flow(rel: str, text: str, is_net: IsNet):
    if rel.endswith(PY_EXT):
        return _Py(text, is_net)
    return _Js(rel, text, is_net)


def env_copies(rel: str, text: str, is_net: IsNet) -> tuple[EnvCopy, ...] | None:
    """Every whole-environment copy in a Python or JS/TS file, or None when it does not parse (R45 5)."""
    if "environ" not in text and "env" not in text:
        return ()
    try:
        return tuple(_flow(rel, text, is_net).copies())
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None


def launcher_text(rel: str, text: str, callee: str) -> bool:
    """Whether `callee` (as text, resolved at module level) is a real process launcher in this file."""
    try:
        return _flow(rel, text, lambda *_: False).launcher_text(callee)
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return False
