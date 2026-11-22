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

Ruling R47 (round 5): the binding exemption is the only path that lowers severity, so it opts out on doubt.
- A copy is bound only when every use of it is a launcher env slot (or a variable / return whose every use
  is). Writing single keys, deleting them and truthiness tests are not uses; reading, iterating or merging
  the copy is (R47 a).
- "Untrusted resolution": a file that patches the loader or module system, defines a loader / interop name
  itself, evaluates non-literal code, or parses differently at runtime (`with`, unicode escapes in identifiers, an
  Annex B block function, HTML-like comments, TS `import type` of a launcher module) binds nothing (R47 b).
- A work budget (steps and about 2 s per file): when it runs out, nothing is bound and the caller adds a
  scan-limit finding (R47 e).
"""
from __future__ import annotations

import ast
import re
import time
from dataclasses import dataclass
from typing import Callable

from bawwab.scan.rules import parsing

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
    untrusted: str = ""  # why nothing in this file is bound (R47 b, e); "" when resolution is trusted
    budget: bool = False  # the work budget ran out (R47 e)


BUDGET_STEPS = 500_000  # resolution / use / sink steps per file (R47 e); real bundles stay under about 300k
BUDGET_SECONDS = 2.0


class BudgetExceeded(Exception):
    pass


class _Budget:
    def __init__(self, steps: int = BUDGET_STEPS, seconds: float = BUDGET_SECONDS):
        self.left = steps
        self.deadline = time.monotonic() + seconds

    def tick(self, n: int = 1) -> None:
        self.left -= n
        if self.left < 0 or (self.left & 0x3FF) < n and time.monotonic() > self.deadline:
            raise BudgetExceeded


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
HELPER_MODULES = ("tslib", "@swc/helpers")
_TSC_IMPORT_DEFAULT = '__importDefault=(this&&this.__importDefault)||function(mod){return(mod&&mod.__esModule)?mod:{"default":mod};}'
# Loader and interop names a file must not define itself (R47 b); createRequire / require only from the real
# module "module", the interop helpers only from a helper package or (tsc) verbatim.
LOADER_NAMES = ("require", "__importDefault", "__importStar", "__toESM", "__require", "createRequire")
PY_LOADER_NAMES = ("importlib", "__import__", "import_module")
LAUNCH_MODULES = ("child_process", "execa", "cross-spawn", "@modelcontextprotocol/sdk") + BROWSER_MODULES
_PROTO_KEYS = ("__proto__", "constructor", "prototype", "__defineGetter__", "__defineSetter__")
_MODULE_INTERNALS = ("_load", "_resolveFilename", "_extensions", "_findPath", "_nodeModulePaths", "_initPaths", "_pathCache")

_WITH_RE = re.compile(rb"(?<![\w$.])with\s*\(")
_UESC_RE = re.compile(rb"\\u")
_HTML_OPEN_RE = re.compile(rb"<!--")
_HTML_CLOSE_RE = re.compile(rb"-->")
_LOADER_WRITE_RE = re.compile(rb"(?<![\w$])(require|arguments|module|Module|" + "|".join(_MODULE_INTERNALS).encode() + rb")(?![\w$])")
_EVAL_NAME_RE = re.compile(rb"(?<![\w$.#])(?:eval|Function)(?![\w$])")
_CTOR_CALL_RE = re.compile(rb"""(?:\.\s*(constructor)|\[\s*['"`](constructor)['"`]\s*\])\s*\(""")
_VM_RE = re.compile(rb"(?<![\w$])(?:runInThisContext|runInNewContext|runInContext|compileFunction|Script|SourceTextModule)(?![\w$])")
_FUNCTION_RE = re.compile(rb"(?<![\w$.])function(?![\w$])")
_TYPE_IMPORT_RE = re.compile(rb"(?<![\w$.])import(?![\w$])")


def _k(n) -> tuple:
    return (n.start_byte, n.end_byte, n.type)


class _Js:
    def __init__(self, rel: str, text: str, is_net: IsNet):
        self.text = text
        self.src = text.encode()
        lang = "tsx" if rel.endswith(".tsx") else ("typescript" if rel.endswith(TS_EXT) else "javascript")
        self.root = parsing.js_root(self.src, lang)
        self.is_net = is_net
        self._decls: dict[str, dict[tuple, list]] = {}
        self._decl_keys: dict[str, dict[tuple, object]] = {}
        self._occ: dict[str, list] = {}
        self._mod_memo: dict[tuple, tuple | None] = {}
        self._patched_memo: dict[tuple, bool] = {}
        self._mod_patched_memo: dict[str, bool] = {}
        self._global_names: set[str] | None = None
        self._ascii = len(self.src) == len(text)
        self._refs: dict[str, dict[tuple, list]] = {}
        self._untrusted: str | None = None
        self.rel = rel
        self.ts = rel.endswith(TS_EXT)
        self.budget = _Budget()

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
            self.budget.tick(1 + (len(self.src) >> 9))  # one scan of the file per name
            for m in rx.finditer(self.src):
                self.budget.tick()
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
        if t == "import_require_clause" and child == p.named_children[0]:
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
            self.budget.tick()
            lst = d.get(_k(p))
            if lst:
                return lst[0]
            p = p.parent
        return None

    def refs(self, decl) -> list:
        """Every other occurrence that resolves to decl: indexed once per name (m3, no re-resolving per copy)."""
        name = self.t(decl)
        idx = self._refs.get(name)
        if idx is None:
            idx = {}
            for r in self.occurrences(name):
                d = self.resolve(r)
                if d is not None and r != d:
                    idx.setdefault(_k(d), []).append(r)
            self._refs[name] = idx
        return idx.get(_k(decl), [])

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
        v = self.unwrap(v) if v is not None else None
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
            n = kids[-1] if n.type in ("sequence_expression", "type_assertion") else kids[0]
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
            if fn is not None and args and self.interop_trusted(self.callee_node(n)):
                return self.module_of(args[0], depth + 1)
        return None

    def interop_trusted(self, fn) -> bool:
        """An interop helper call (__importDefault(require('m'))) passes the module through only when the helper
        is not ours to spoof (I1): an unresolved name nothing in the file writes globally, an import from tslib,
        or TypeScript's emitted __importDefault, verbatim."""
        if fn is None or not _INTEROP_RE.match(re.sub(r"\s+", "", self.t(fn))):
            return False
        if fn.type == "member_expression":
            base = self.module_of(self.f(fn, "object"))
            return base is not None and base[0] in HELPER_MODULES and not base[1]
        if fn.type != "identifier":
            return False
        decl = self.resolve(fn)
        if decl is None:
            return self.t(fn) not in self.global_names()
        mod = self.decl_module(decl)
        if mod is not None:
            return mod[0] in HELPER_MODULES
        return self.canonical_helper(decl)

    def canonical_helper(self, decl) -> bool:
        """decl declares TypeScript's own __importDefault helper, token for token, and nothing else declares it."""
        p = decl.parent
        if p is None or p.type != "variable_declarator" or decl != self.f(p, "name") or self.t(decl) != "__importDefault":
            return False
        if sum(len(v) for v in self.decls("__importDefault").values()) != 1 or self.binding_patched(decl):
            return False
        return re.sub(r"\s+", "", self.t(p)) == _TSC_IMPORT_DEFAULT

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
        elif p is not None and p.type == "import_require_clause" and child == p.named_children[0]:
            src = self.f(p, "source")  # TS: import cp = require("child_process")
            if src is not None and src.type == "string":
                out = (self.t(src)[1:-1].removeprefix("node:"), ())
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
        """The expression inside parentheses / casts; <T>x keeps its type first (m2 T7)."""
        while n.type in _JS_WRAP and n.named_children:
            kids = [c for c in n.named_children if c.type != "comment"]
            n = kids[-1] if n.type == "type_assertion" else kids[0]
        return n

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
        base, q = self.up(r)  # (<any>cp).spawn: casts and parentheses around the reference (m2 T7)
        if base != r and q is not None and (q.type == "update_expression" or (
                q.type in ("assignment_expression", "augmented_assignment_expression") and base == self.f(q, "left"))):
            return True  # (cp) = x, (cp as any) = x
        top = base
        while q is not None and q.type in ("member_expression", "subscript_expression") and top == self.f(q, "object"):
            top, q = q, q.parent
        if top != base and q is not None:
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
        if namespace and top == base:
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
            return True  # the module object itself escapes: const m = cp; m.spawn = ...; return { puppeteer } (B9, R47 c)
        return False

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
                root = self.unwrap(root)
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

    # -------- untrusted resolution (R47 b)

    def untrusted(self) -> str:
        """Why no copy in this file may be bound, or "": the file can change what a name resolves to at
        runtime in a way the tree does not follow."""
        if self._untrusted is None:
            self._untrusted = self._why_untrusted()
        return self._untrusted

    def in_code_strict(self, b: int) -> bool:
        """b is code (an HTML-like comment counts as code: Node may read it as a comment, the tree does not)."""
        n = self.root.named_descendant_for_byte_range(b, b + 1)
        while n is not None:
            if n.type in ("comment", "string", "template_string", "regex"):
                return False
            n = n.parent
        return True

    def _hits(self, rx):
        for m in rx.finditer(self.src):
            self.budget.tick()
            if self.in_code_strict(m.start()):
                yield m

    def _why_untrusted(self) -> str:
        for m in self._hits(_WITH_RE):
            n = self.root.descendant_for_byte_range(m.start(), m.start() + 4)
            if n is not None and n.parent is not None and n.parent.type == "with_statement":
                return "with statement"
        for _ in self._hits(_UESC_RE):
            return "unicode escape in an identifier"
        for m in self._hits(_HTML_OPEN_RE):
            return "HTML-like comment"
        for m in self._hits(_HTML_CLOSE_RE):
            line = self.src[self.src.rfind(b"\n", 0, m.start()) + 1 : m.start()].strip()
            if not line or line.endswith(b"*/"):
                return "HTML-like comment"
        why = self._loader_writes() or self._loader_defs() or self._dynamic_code() or self._annex_b() or self._type_imports()
        return why

    def write_target(self, n):
        """The node n is written through: (top, how) when n, or a member chain on it, is assigned, updated,
        deleted, a destructuring / for-in target, or the first argument of Object.assign / defineProperty / ..."""
        top, q = n, n.parent
        while q is not None and (q.type in _JS_WRAP or (q.type in ("member_expression", "subscript_expression") and top == self.f(q, "object"))):
            top, q = q, q.parent
        if q is None:
            return None
        if q.type in ("assignment_expression", "augmented_assignment_expression") and top == self.f(q, "left"):
            return top
        if q.type == "update_expression" or (q.type == "unary_expression" and self.t(q).startswith("delete")):
            return top
        if q.type == "for_in_statement" and top == self.f(q, "left"):
            return top
        c, p = top, q
        while p is not None and p.type in _JS_PATTERNS:
            c, p = p, p.parent
        if c != top and p is not None and p.type == "assignment_expression" and c == self.f(p, "left"):
            return top
        if q.type == "arguments" and self.callee(q.parent) in _PATCH_CALLS and self.arg_index(q.parent, self.up(top)[0]) == 0:
            return top
        return None

    def chain_props(self, top) -> list[str]:
        """The property names of a member chain, outermost last: module.constructor.prototype -> [constructor, prototype]."""
        props: list[str] = []
        n = top
        while n is not None:
            if n.type == "member_expression":
                props.insert(0, self.t(self.f(n, "property")))
                n = self.f(n, "object")
            elif n.type == "subscript_expression":
                idx = self.f(n, "index")
                props.insert(0, self.t(idx).strip("'\"`") if idx is not None and idx.type == "string" else "[]")
                n = self.f(n, "object")
            elif n.type in _JS_WRAP and self.unwrap(n) != n:
                n = self.unwrap(n)
            else:
                break
        return props

    def _loader_writes(self) -> str:
        """Writes to require / module.require / Module.* / Module._load / arguments[...] (I1, I2)."""
        for m in self._hits(_LOADER_WRITE_RE):
            n = self.root.named_descendant_for_byte_range(m.start(1), m.end(1))
            if n is None or n.start_byte != m.start(1) or n.end_byte != m.end(1):
                continue
            if n.type not in ("identifier", "property_identifier"):
                continue
            base = n
            if n.type == "property_identifier":
                base = n.parent  # x._load: the member expression
                if base is None or base.type != "member_expression":
                    continue
            top = self.write_target(base)
            if top is None:
                continue
            name = self.t(n)
            if n.type == "identifier":
                if name in ("require", "arguments"):
                    return f"writes {name}"
                if name == "module":
                    props = self.chain_props(top)
                    if props[:1] in (["require"], ["constructor"], ["paths"]):
                        return "writes module." + props[0]
                    continue
                if name == "Module" and top != n:
                    return "writes Module"
            else:  # x._load = ..., X.prototype.require = ...: only on the module system's own objects
                obj = self.f(base, "object")
                root = obj
                while root is not None and root.type in {"member_expression", "subscript_expression"} | _JS_WRAP:
                    nxt = self.f(root, "object") if root.type in ("member_expression", "subscript_expression") else self.unwrap(root)
                    if nxt == root:
                        break
                    root = nxt
                if root is None:
                    continue
                mod = self.module_of(root) if root.type in ("identifier", "call_expression") else None
                rt = self.t(root)
                if rt in ("Module", "module", "require") or (mod is not None and mod[0] == "module") or (
                        name == "require" and self.t(obj).endswith("prototype")):
                    return f"writes .{name}"
        if self.module_patched("module"):
            return "patches the module system"
        return ""

    def _loader_defs(self) -> str:
        """The file defines a loader or interop name itself (I1): only createRequire / require made from the real
        module "module", helpers imported from a helper package, and TypeScript's emitted __importDefault pass."""
        for name in LOADER_NAMES:
            for lst in self.decls(name).values():
                for decl in lst:
                    self.budget.tick()
                    mod = self.decl_module(decl)
                    if mod is not None and (mod == ("module", (name,)) or (mod[0] in HELPER_MODULES and mod[1] == (name,))):
                        continue  # import { createRequire } from "module"; import { __importDefault } from "tslib"
                    if name == "require" and self.verified_create_require(decl):
                        continue
                    if name == "__importDefault" and self.canonical_helper(decl):
                        continue
                    return f"defines {name}"
        return ""

    def verified_create_require(self, decl) -> bool:
        """const require = createRequire(import.meta.url), createRequire being the real module's, never written."""
        p = decl.parent
        if p is None or p.type != "variable_declarator" or decl != self.f(p, "name"):
            return False
        v = self.f(p, "value")
        v = self.unwrap(v) if v is not None else None
        if v is None or v.type != "call_expression" or self.module_of(self.callee_node(v)) != ("module", ("createRequire",)):
            return False
        return not self.binding_patched(decl)

    def literal(self, a) -> bool:
        a = self.unwrap(a)
        if a.type == "string":
            return True
        return a.type == "template_string" and not any(c.type == "template_substitution" for c in a.named_children)

    def _dynamic_code(self) -> str:
        """eval / Function / x.constructor(...) / vm with code that is not a literal, or eval / Function passed
        around as a value (I3)."""
        for m in self._hits(_EVAL_NAME_RE):
            n = self.root.named_descendant_for_byte_range(m.start(), m.end())
            if n is None or n.type != "identifier" or n.start_byte != m.start() or n.end_byte != m.end():
                continue
            if self.decl_scope(n) is not None:
                continue
            c, p = n, n.parent
            while p is not None and (p.type == "parenthesized_expression" or (p.type == "sequence_expression" and c == p.named_children[-1])):
                c, p = p, p.parent
            if p is not None and p.type in ("call_expression", "new_expression") and c == self.f(p, "function" if p.type == "call_expression" else "constructor"):
                if not all(self.literal(a) for a in self.args_of(p)):
                    return f"non-literal {self.t(n)}"
                continue
            if p is not None and p.type == "member_expression" and c == self.f(p, "object"):
                continue  # Function.prototype.apply.call(...): a read (a .constructor call is checked below)
            if p is not None and p.type == "unary_expression" and self.t(p).startswith("typeof"):
                continue
            if p is not None and p.type in ("binary_expression",):
                continue
            return f"{self.t(n)} as a value"
        for m in self._hits(_CTOR_CALL_RE):
            g = 1 if m.group(1) else 2
            n = self.root.named_descendant_for_byte_range(m.start(g), m.end(g))
            call = n
            while call is not None and call.type != "call_expression":
                call = call.parent
            if call is not None and not all(self.literal(a) for a in self.args_of(call)):
                return "non-literal constructor call"
        for m in self._hits(_VM_RE):
            n = self.root.named_descendant_for_byte_range(m.start(), m.end())
            call = n
            while call is not None and call.type not in ("call_expression", "new_expression"):
                call = call.parent
            if call is None:
                continue
            path = self.module_of(self.callee_node(call))
            if path is not None and path[0] == "vm" and not all(self.literal(a) for a in self.args_of(call)):
                return "non-literal vm code"
        return ""

    def strict_file(self) -> bool:
        if self.rel.endswith((".mjs", ".mts")):
            return True
        for c in self.root.named_children:
            if c.type in ("import_statement", "export_statement"):
                return True
        first = next((c for c in self.root.named_children if c.type not in ("comment", "hash_bang_line")), None)
        return first is not None and first.type == "expression_statement" and self.t(first).strip(" ;\n") in ('"use strict"', "'use strict'")

    def _annex_b(self) -> str:
        """A block-level function in sloppy code that has the name of an outer binding (Annex B, I3 F6)."""
        if self.strict_file():
            return ""
        for m in self._hits(_FUNCTION_RE):
            n = self.root.descendant_for_byte_range(m.start(), m.start() + 8)
            fd = n.parent if n is not None else None
            if fd is None or fd.type not in ("function_declaration", "generator_function_declaration"):
                continue
            blk = fd.parent
            if blk is None or blk.type in ("program",) or (blk.type == "statement_block" and blk.parent is not None and blk.parent.type in _JS_FUNCS):
                continue
            name = self.f(fd, "name")
            if name is None:
                continue
            outer = [k for k in self.decls(self.t(name)) if k != _k(blk)]
            if outer:
                return f"block function {self.t(name)} redeclares an outer binding"
        return ""

    def _type_imports(self) -> str:
        """TS `import type` of a launcher module: erased at runtime, a binding on the tree (I3 T2)."""
        if not self.ts:
            return ""
        for m in self._hits(_TYPE_IMPORT_RE):
            st = self.root.named_descendant_for_byte_range(m.start(), m.start() + 6)
            while st is not None and st.type != "import_statement":
                st = st.parent
            if st is None:
                continue
            src = self.f(st, "source")
            mod = self.t(src)[1:-1].removeprefix("node:") if src is not None else ""
            root = "/".join(mod.split("/")[:2]) if mod.startswith("@") else mod.split("/")[0]
            if root not in LAUNCH_MODULES and mod not in LAUNCH_MODULES:
                continue
            if any(c.type == "type" for c in st.children) or any(
                    c.type == "type" for s in self.walk(st) if s.type == "import_specifier" for c in s.children):
                return f"import type from {mod}"
        return ""

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
        """(copy node, family, debug target, bindable) for an env object used as a whole copy, or None."""
        n, p = self.up(e)
        if p is None:
            return None
        if p.type == "spread_element":
            obj = p.parent
            return (obj, "spread", None, True) if obj is not None and obj.type == "object" else None
        if p.type != "arguments":
            return None
        call = p.parent
        c, i = self.callee(call), self.arg_index(call, n)
        if c == "Object.assign" and i >= 1:
            return call, "spread", None, True
        if c == "structuredClone" and i == 0:
            return call, "spread", None, True
        if call.type == "new_expression" and c == "URLSearchParams" and i == 0:
            return call, "spread", None, False  # every variable, as a query string (R47 d)
        if c in ("Reflect.ownKeys", "Object.getOwnPropertyNames") and i == 0:
            return self.chain(call), "spread", None, False
        if i == 0 and (self.module_of(self.callee_node(call)) or ("", ()))[0] == "util" and c.endswith(("inspect", "format")):
            return call, "spread", None, False
        if c in ("Object.entries", "Object.values", "Object.keys") and i == 0:
            debug = None
            if c == "Object.keys":
                tail = self.src[call.end_byte : call.end_byte + 600].decode("utf-8", "replace")
                m = PREFIX_FILTER_RE.match(tail)
                if m is not None and not SECRETISH_RE.search(m.group(1)):
                    debug = True
            return self.chain(call), "old", debug, True
        return None

    def chain(self, call):
        """Object.fromEntries(Object.entries(process.env).filter(...).map(...)) as one copy."""
        c = call
        while True:
            self.budget.tick()
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

    # -------- bound (R45 3, R47 a: every use is a launcher env slot, on doubt not bound)

    def use(self, n, mode: str, depth: int) -> str:
        """"ok" (ends in a launcher's env slot), "skip" (the value is dropped) or "bad"."""
        while True:
            self.budget.tick()
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
                other = self.f(p, "right") if n == self.f(p, "left") else self.f(p, "left")
                nullish = other is not None and self.t(other) in ("null", "undefined")
                if op in ("&&", "===", "!==") or (op in ("==", "!=") and nullish) or (op == "in" and n == self.f(p, "right")):
                    return "skip"  # a truthiness / identity test: nothing of the copy is read
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
                if mode == "env" and self.callee(call) == "Object.assign" and self.fresh_assign(call, n):
                    n = call  # Object.assign({}, copy, {...}): the call's value is a new copy (C1: not into another object)
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

    def fresh_assign(self, call, n) -> bool:
        """Object.assign(<object literal>, ..., n, ...): the copy lands in a new object, not in one used elsewhere."""
        args = self.args_of(call)
        return bool(args) and args[0] != n and self.unwrap(args[0]).type == "object"

    def key_ok(self, member, write: bool = False) -> bool:
        """A single named key (x.k, x["k"], x[0]), not __proto__ / constructor / prototype."""
        if member.type == "member_expression":
            prop = self.f(member, "property")
            return prop is not None and prop.type == "property_identifier" and self.t(prop) not in _PROTO_KEYS
        idx = self.f(member, "index")
        if idx is None or idx.type not in ("string", "number"):
            return False
        return self.t(idx).strip("'\"`") not in _PROTO_KEYS

    def written(self, member) -> bool:
        """member is the target of a write: x.k = v, x.k += v, x.k++, delete x.k."""
        n, q = self.up(member)
        if q is None:
            return False
        if q.type in ("assignment_expression", "augmented_assignment_expression") and n == self.f(q, "left"):
            return True
        if q.type == "update_expression":
            return True
        return q.type == "unary_expression" and self.t(q).startswith("delete")

    def writeback(self, member, decl) -> bool:
        """A key read whose value only goes back into the same copy: env.PATH = env.PATH + ":" + dir."""
        n = member
        while True:
            self.budget.tick()
            n, p = self.up(n)
            if p is None:
                return False
            if p.type in ("binary_expression", "template_substitution", "template_string", "ternary_expression"):
                if p.type == "ternary_expression" and n == self.f(p, "condition"):
                    return False
                n = p
                continue
            if p.type in ("assignment_expression", "augmented_assignment_expression") and n == self.f(p, "right"):
                left = self.f(p, "left")
                if left is None or left.type not in ("member_expression", "subscript_expression") or not self.key_ok(left, True):
                    return False
                obj = self.unwrap(self.f(left, "object"))
                return obj.type == "identifier" and self.resolve(obj) == decl
            return False

    def tested(self, n) -> bool:
        """n is only tested: if (!env.X), typeof env.X, env.X == null, a condition."""
        n, p = self.up(n)
        if p is None:
            return False
        if p.type == "unary_expression":
            op = self.f(p, "operator")
            return op is not None and self.t(op) in ("!", "typeof")
        if p.type == "binary_expression":
            op = self.t(self.f(p, "operator"))
            other = self.f(p, "right") if n == self.f(p, "left") else self.f(p, "left")
            return op in ("==", "!=", "===", "!==") and other is not None and self.t(other) in ("null", "undefined")
        if p.type in ("if_statement", "while_statement", "do_statement", "ternary_expression"):
            return n == self.f(p, "condition")
        return False

    def ref_use(self, r, mode: str, depth: int, decl=None) -> str:
        if r.type == "shorthand_property_identifier":
            if mode == "env" and self.t(r) == "env":
                return self.use(r.parent, "opts", depth)  # spawn(cmd, args, { env })
            return "bad"
        n, p = self.up(r)
        if p is None:
            return "bad"
        t = p.type
        if t in ("member_expression", "subscript_expression") and n == self.f(p, "object"):
            if mode == "opts":
                # options holding the copy: writing an option, or reading another named one, is not a use of it
                if not self.key_ok(p, False):
                    return "bad"
                if self.written(p):
                    return "skip"
                key = self.f(p, "property") if p.type == "member_expression" else self.f(p, "index")
                return "bad" if self.is_env_key(key) or self.calls_member(p) else "skip"
            if self.written(p) and self.key_ok(p, True):
                return "skip"  # env.X = "1", env["X"] = v, delete env.X: one key written, nothing read
            if self.key_ok(p, False) and decl is not None and (self.writeback(p, decl) or self.tested(p)):
                return "skip"
            return "bad"  # a key read, a method call, iteration source (R47 a, C1)
        if t == "unary_expression":
            op = self.f(p, "operator")
            return "skip" if op is not None and self.t(op) in ("!", "typeof", "void", "delete") else "bad"
        if t in ("assignment_expression", "augmented_assignment_expression") and n == self.f(p, "left"):
            return "skip" if t == "assignment_expression" else "bad"
        if t == "update_expression":
            return "bad"
        if t in ("if_statement", "while_statement", "do_statement") and n == self.f(p, "condition"):
            return "skip"  # if (env)
        if t in ("export_specifier", "export_clause"):
            return "bad"
        return self.use(r, mode, depth)

    def calls_member(self, member) -> bool:
        n, q = self.up(member)
        return q is not None and q.type == "call_expression" and self.f(q, "function") == n

    def var(self, decl, mode: str, depth: int) -> str:
        if depth >= _DEPTH:
            return "bad"
        ok = False
        for r in self.refs(decl):
            u = self.ref_use(r, mode, depth + 1, decl)
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
                self.budget.tick()
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

    def launch_barrier(self, call) -> bool:
        """A real process launcher (resolved, in a file whose resolution is trusted) that is not itself a network
        call: what it returns is a process, its exit status or its output, not the copy handed to it (FP round 2).
        Without this, every later use of the child (`proc.stdin.write(...)`) made the copy a sink."""
        return not self.untrusted() and self.launcher(call)

    def sink_call(self, call) -> bool:
        callee = self.callee(call)
        args = self.f(call, "arguments")
        args_t = self.t(args) if args is not None else ""
        first = self.args_of(call)
        return self.is_net(callee, args_t, self.t(first[0]) if first else "") or _is_write(callee)

    def sink(self, n, depth: int) -> bool:
        while True:
            self.budget.tick()
            p = n.parent
            if p is None:
                return False
            t = p.type
            if t in ("call_expression", "new_expression"):
                if self.sink_call(p):
                    return True
                if self.launch_barrier(p):
                    return False
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

    def found(self) -> list[tuple]:
        """(pos, line, family, copy node, debug, bindable) for every copy: detection only."""
        out = []
        for e in self.env_nodes():
            c = self.copy_of(e)
            if c is not None:
                node, family, debug, bindable = c
                out.append((self.char(e.start_byte), e.start_point[0] + 1, family, node, debug, bindable))
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
        self.tree = parsing.py_parse(text)
        self.is_net = is_net
        self.parent: dict[int, ast.AST] = {}
        self.scope_of: dict[int, _Scope] = {}
        self.names: dict[str, list[ast.Name]] = {}
        self._name_refs: dict[tuple, list] = {}
        self.module = _Scope(self.tree, None)
        self.scopes: dict[int, _Scope] = {id(self.tree): self.module}
        self._build(self.tree, self.module)
        self.lines = text.split("\n")
        self.starts = [0]
        for ln in self.lines:
            self.starts.append(self.starts[-1] + len(ln) + 1)
        self._patches()
        self._untrusted: str | None = None
        self.budget = _Budget()

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
        key = (name, id(scope))
        got = self._name_refs.get(key)
        if got is None:
            names = self.names.get(name, [])
            self.budget.tick(len(names))
            got = self._name_refs[key] = [n for n in names if self.resolve(name, self.scope_of[id(n)]) is scope]
        return got

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

    # -------- untrusted resolution (R47 b)

    def untrusted(self) -> str:
        if self._untrusted is None:
            self._untrusted = self._why_untrusted()
        return self._untrusted

    def module_names(self, mod: str) -> set[str]:
        """Names some binding of which imports exactly module mod (import sys, import sys as s)."""
        out = set()
        for n in ast.walk(self.tree):
            if isinstance(n, ast.Import):
                for a in n.names:
                    if a.name == mod:
                        out.add(a.asname or a.name)
        return out

    def _why_untrusted(self) -> str:
        sys_names = self.module_names("sys")
        bi_names = self.module_names("builtins")
        for n in ast.walk(self.tree):
            self.budget.tick()
            # a loader name defined here: class importlib, def __import__, import_module = ..., from x import import_module
            if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)) and n.name in PY_LOADER_NAMES:
                return f"defines {n.name}"
            if isinstance(n, ast.Name) and n.id in PY_LOADER_NAMES and not isinstance(n.ctx, ast.Load):
                return f"defines {n.id}"
            if isinstance(n, ast.arg) and n.arg in PY_LOADER_NAMES:
                return f"defines {n.arg}"
            if isinstance(n, ast.Import):
                for a in n.names:
                    if (a.asname or a.name.split(".")[0]) in PY_LOADER_NAMES and a.name.split(".")[0] != "importlib":
                        return f"defines {a.asname or a.name}"
                    if a.asname and a.asname in PY_LOADER_NAMES:
                        return f"defines {a.asname}"
            if isinstance(n, ast.ImportFrom):
                for a in n.names:
                    bound = a.asname or a.name
                    if n.module == "sys" and a.name in ("modules", "meta_path", "path_hooks", "*"):
                        return f"imports sys.{a.name}"
                    if bound in PY_LOADER_NAMES and not (n.module == "importlib" and a.name == bound) and not (
                            n.module == "builtins" and a.name == "__import__" and bound == "__import__"):
                        return f"defines {bound}"
            # __builtins__, and builtins / sys used other than as module.attr reads
            if isinstance(n, ast.Name) and n.id == "__builtins__":
                return "uses __builtins__"
            if isinstance(n, ast.Name) and (n.id in bi_names or n.id in sys_names) and isinstance(n.ctx, ast.Load):
                why = self._module_use(n, n.id in sys_names)
                if why:
                    return why
            if isinstance(n, ast.Call):
                fn = ast.unparse(n.func)
                if fn in ("importlib.import_module", "import_module", "__import__", "importlib.__import__", "builtins.__import__"):
                    a = n.args[0] if n.args else None
                    if not (isinstance(a, ast.Constant) and isinstance(a.value, str)) or a.value.split(".")[0] in ("sys", "builtins", "importlib"):
                        return "dynamic import"
                if fn in ("exec", "eval", "compile", "builtins.exec", "builtins.eval", "builtins.compile") and self.builtin_name(n.func):
                    a = n.args[0] if n.args else None
                    if not (isinstance(a, ast.Constant) and isinstance(a.value, (str, bytes))):
                        return f"non-literal {fn}"
            if isinstance(n, ast.Name) and n.id in ("exec", "eval", "compile") and isinstance(n.ctx, ast.Load):
                p = self.parent.get(id(n))
                if not (isinstance(p, ast.Call) and p.func is n) and self.builtin_name(n):
                    return f"{n.id} as a value"
        return ""

    def builtin_name(self, f) -> bool:
        """f (a Name or builtins.x) is the builtin, not a local or imported name of that spelling."""
        if isinstance(f, ast.Attribute):
            return True
        return isinstance(f, ast.Name) and self.resolve(f.id, self.scope_at(f)) is None

    def _module_use(self, n: ast.Name, is_sys: bool) -> str:
        """sys / builtins used other than as a plain attribute read: setattr(sys, ...), vars(builtins),
        builtins.__import__ = f, sys.modules[...] = x, m = sys.modules, sys.meta_path.insert(...)."""
        if self.resolve(n.id, self.scope_at(n)) is None:
            return ""
        p = self.parent.get(id(n))
        if not (isinstance(p, ast.Attribute) and p.value is n):
            return f"{n.id} used as a value"
        if p.attr.startswith("__"):
            return f"{n.id}.{p.attr}"
        if not is_sys:
            top, q = p, self.parent.get(id(p))
            while isinstance(q, (ast.Attribute, ast.Subscript)) and q.value is top:
                top, q = q, self.parent.get(id(q))
            return "writes builtins" if not isinstance(top.ctx, ast.Load) else ""
        if p.attr in ("meta_path", "path_hooks", "path_importer_cache"):
            return f"sys.{p.attr}"
        if p.attr != "modules":
            return "writes sys" if not isinstance(p.ctx, ast.Load) else ""
        q = self.parent.get(id(p))
        if isinstance(q, ast.Compare) and any(c is p for c in q.comparators) and all(isinstance(o, (ast.In, ast.NotIn)) for o in q.ops):
            return ""  # "x" in sys.modules
        return "sys.modules"

    # -------- copies

    def is_environ(self, n) -> bool:
        if isinstance(n, ast.Attribute) and n.attr == "environ" and isinstance(n.value, ast.Name):
            nm = n.value.id
            base = self.import_path(nm, self.resolve(nm, self.scope_at(n)))
            return nm == "os" if base is None else base == ("os", ())
        if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Load):
            s = self.resolve(n.id, self.scope_at(n))
            if s is None and n.id == "environ":
                return self.star_os  # from os import *
            return self.import_path(n.id, s) == ("os", ("environ",))
        if (isinstance(n, ast.Call) and ast.unparse(n.func) == "getattr" and len(n.args) == 2 and isinstance(n.args[1], ast.Constant)
                and n.args[1].value == "environ" and isinstance(n.args[0], ast.Name)):
            return self.import_path(n.args[0].id, self.resolve(n.args[0].id, self.scope_at(n.args[0]))) == ("os", ())
        return False

    def copy_of(self, e):
        """(copy node, family, bindable) for os.environ used as a whole copy, or None."""
        p = self.parent.get(id(e))
        if isinstance(p, ast.Dict) and any(k is None and v is e for k, v in zip(p.keys, p.values)):
            return p, "spread", True
        if isinstance(p, ast.keyword) and p.arg is None:
            call = self.parent.get(id(p))
            if isinstance(call, ast.Call) and ast.unparse(call.func) == "dict":
                return call, "spread", True
            return e, "spread", False  # f(**os.environ): every variable as keyword arguments (I5, R47 d)
        if isinstance(p, ast.BinOp) and isinstance(p.op, ast.BitOr):
            return p, "spread", True  # os.environ | {...}
        if isinstance(p, ast.Call) and e in p.args and p.args[0] is e:
            fn = ast.unparse(p.func)
            if fn == "dict":
                return p, "old", True
            if fn in ("copy.copy", "copy.deepcopy", "copy", "deepcopy"):
                return p, "spread", True
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
                return c, "old", True
        return None

    def use(self, n, mode: str, depth: int) -> str:
        while True:
            self.budget.tick()
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
            if isinstance(p, ast.BinOp) and isinstance(p.op, ast.BitOr) and mode == "env":
                n = p  # {**copy} | {"A": "1"}: still a copy
                continue
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

    def writeback(self, sub: ast.Subscript, name: str) -> bool:
        """env[k] read whose value only goes back into the same copy: env["PATH"] = env["PATH"] + os.pathsep + d."""
        n = sub
        while True:
            self.budget.tick()
            p = self.parent.get(id(n))
            if isinstance(p, (ast.BinOp, ast.JoinedStr, ast.FormattedValue)) or (isinstance(p, ast.IfExp) and n is not p.test):
                n = p
                continue
            if isinstance(p, ast.Assign) and n is p.value and len(p.targets) == 1:
                tg = p.targets[0]
                return isinstance(tg, ast.Subscript) and isinstance(tg.value, ast.Name) and tg.value.id == name
            if isinstance(p, ast.AugAssign) and n is p.value:
                tg = p.target
                return isinstance(tg, ast.Subscript) and isinstance(tg.value, ast.Name) and tg.value.id == name
            return False

    def ref_use(self, r: ast.Name, mode: str, depth: int) -> str:
        """R47 a: writing or deleting keys and testing the copy are not uses of it; reading, iterating or
        merging it is."""
        if not isinstance(r.ctx, ast.Load):
            return "skip"
        p = self.parent.get(id(r))
        stmt = self.parent.get(id(self.parent.get(id(p)))) if isinstance(p, ast.Attribute) else None
        if isinstance(p, ast.Subscript) and p.value is r:
            if not isinstance(p.ctx, ast.Load):
                return "skip"  # env["X"] = "1", del env["X"]
            key = p.slice.value if isinstance(p.slice, ast.Constant) and isinstance(p.slice.value, str) else None
            if mode == "opts" and key is not None and key != "env":
                return "skip"
            return "skip" if mode == "env" and self.writeback(p, r.id) else "bad"
        if isinstance(p, ast.Attribute) and p.value is r:
            call = self.parent.get(id(p))
            if p.attr in ("copy",) and isinstance(call, ast.Call) and call.func is p and mode == "env":
                return self.use(call, mode, depth)
            if isinstance(call, ast.Call) and call.func is p and isinstance(stmt, ast.Expr) and p.attr in (
                    "update", "pop", "setdefault", "clear", "__setitem__", "__delitem__", "popitem"):
                return "skip"  # env.update(A="1"), env.pop("X", None) as a statement: the value is dropped
            if (mode == "opts" and p.attr == "get" and isinstance(call, ast.Call) and call.func is p and call.args
                    and isinstance(call.args[0], ast.Constant) and call.args[0].value != "env"):
                return "skip"
            return "bad"
        if isinstance(p, ast.Compare) and any(c is r for c in p.comparators) and all(isinstance(o, (ast.In, ast.NotIn)) for o in p.ops):
            return "skip"
        if (isinstance(p, ast.Compare) and p.left is r and all(isinstance(o, (ast.Is, ast.IsNot)) for o in p.ops)
                and all(isinstance(c, ast.Constant) and c.value is None for c in p.comparators)):
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
                self.budget.tick()
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

    def launch_barrier(self, call: ast.Call) -> bool:
        """As _Js.launch_barrier: a resolved launcher's result is not made from the copy handed to it."""
        return not self.untrusted() and self.launcher(call) is not None

    def sink_call(self, call: ast.Call) -> bool:
        callee = ast.unparse(call.func)
        parts = [ast.unparse(a) for a in call.args] + [f"{k.arg}={ast.unparse(k.value)}" if k.arg else f"**{ast.unparse(k.value)}"
                                                       for k in call.keywords]
        first = ast.unparse(call.args[0]) if call.args else ""
        return self.is_net(callee, ", ".join(parts), first) or _is_write(callee)

    def sink(self, n, depth: int) -> bool:
        while True:
            self.budget.tick()
            p = self.parent.get(id(n))
            if p is None:
                return False
            if isinstance(p, ast.Call):
                if self.sink_call(p):
                    return True
                if self.launch_barrier(p):
                    return False
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

    def found(self) -> list[tuple]:
        """(pos, line, family, copy node, debug, bindable) for every copy: detection only."""
        out = []
        self.star_os = any(isinstance(n, ast.ImportFrom) and n.module == "os" and any(a.name == "*" for a in n.names)
                           for n in ast.walk(self.tree))
        for e in ast.walk(self.tree):
            if not isinstance(e, (ast.Attribute, ast.Name, ast.Call)) or not self.is_environ(e):
                continue
            c = self.copy_of(e)
            if c is not None:
                node, family, bindable = c
                out.append((self.char(e), e.lineno, family, node, None, bindable))
        return out


# ---------------------------------------------------------------- entry points


def _flow(rel: str, text: str, is_net: IsNet):
    if rel.endswith(PY_EXT):
        return _Py(text, is_net)
    return _Js(rel, text, is_net)


def _analyse(flow, budget: _Budget | None = None) -> list[EnvCopy]:
    flow.budget = _Budget(10**12, 10**9)  # detection is linear: never cut short
    found = flow.found()
    if not found:
        return []
    flow.budget = budget or _Budget()
    try:
        why = flow.untrusted()
        out = []
        for pos, line, family, node, debug, bindable in found:
            bound = False
            if bindable and not why:
                bound = (bool(debug) and flow.debug_bound(node)) or flow.use(node, "env", 0) == "ok"
            sink = not bound and flow.sink(node, 0)
            out.append(EnvCopy(pos, line, family, bound, sink, why))
        return out
    except BudgetExceeded:
        return [EnvCopy(pos, line, family, False, False, "work budget exceeded", True) for pos, line, family, *_ in found]


def env_copies(rel: str, text: str, is_net: IsNet, budget: _Budget | None = None) -> tuple[EnvCopy, ...] | None:
    """Every whole-environment copy in a Python or JS/TS file, or None when it does not parse (R45 5)."""
    if "environ" not in text and "env" not in text:
        return ()
    try:
        return tuple(_analyse(_flow(rel, text, is_net), budget))
    except (SyntaxError, ValueError, RecursionError):
        return None


def untrusted_reason(rel: str, text: str) -> str:
    """Why nothing in this file may be bound (R47 b), or "" (for tests and reports)."""
    try:
        f = _flow(rel, text, lambda *_: False)
        f.budget = _Budget(10**12, 10**9)
        return f.untrusted()
    except (SyntaxError, ValueError, RecursionError):
        return "unparseable"


def launcher_text(rel: str, text: str, callee: str) -> bool:
    """Whether `callee` (as text, resolved at module level) is a real process launcher in this file."""
    try:
        f = _flow(rel, text, lambda *_: False)
        f.budget = _Budget()
        return not f.untrusted() and f.launcher_text(callee)
    except (SyntaxError, ValueError, RecursionError):
        return False
