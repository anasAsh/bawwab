"""Download-and-execute, followed on the syntax tree (rule remote-code.download-exec).

A *payload* is the value of an outbound network call (the positions come from code._net_calls_pos, so every
module, alias and global that counts as network there counts here) and anything made from it: attributes and
methods of the response (`.text`, `.read()`, `await r.text()`), values built from it (`b64decode(x)`,
`Buffer.from(x)`, f-strings, `+=` accumulation, `.append`/`.push` into a list), loop variables over it, callback
parameters of the network call or of a method on a payload (`res.on('data', d => ...)`, `.then(r => ...)`), and
calls to an in-file function that returns one. Status codes, headers, lengths, `len()`/`int()` and comparisons
are not payloads.

A *dropped file* is a path a payload is written to (`open(p, 'wb').write(x)`, `Path(p).write_bytes(x)`,
`urlretrieve(u, p)`, `fs.writeFileSync(p, x)`, `x.pipe(fs.createWriteStream(p))`, `pipeline(x, ws)` ...), named
by its variable, its file-name component or its literal file name, and the names it is copied or moved to.

A hit is, in the same file:
* a payload reaching code evaluation: exec / eval / compile / marshal.loads, eval / Function / vm.* / setTimeout
  with a string / module._compile, or `.then(eval)`;
* a payload run as a command: the whole command (`os.system(x)`, `cp.exec(x)`), or the code of an interpreter's
  -c / -e flag, or the stdin of an interpreter;
* a dropped file run, loaded or made executable: the program of a process call (or the script of an interpreter,
  chmod, open, msiexec ...), exec(open(p).read()), runpy / importlib / ctypes / require / import / dlopen /
  fork, os.chmod / fs.chmod with an execute bit.

A dropped file handed to a tool as data (`tar xf p`), a remote value used as one argument of a command (`pip
install tool=={tag}`, `git checkout tag`) and a download that is never run are not hits.

Severity: CRITICAL, or HIGH when the function holding the write or the sink verifies what it fetched (a sha256 /
sha512 / digest comparison, compare_digest / timingSafeEqual, a call to a verify/checksum helper, or a signature
check). A pinned checksum means a changed server cannot swap the payload, but code from the network still runs
unreviewed: listed for review, not malicious on its own.

Fail open on what cannot be analysed (no tree, over the work budget): the textual rules (remote-code.eval-fetch,
remote-code.pipe-shell) still apply there.
"""
from __future__ import annotations

import ast
import re
from dataclasses import dataclass
from typing import Callable

from bawwab.scan.rules import parsing

MAX_BYTES = 4_000_000
MAX_STEPS = 3_000_000
PASSES = 6


@dataclass(frozen=True)
class Hit:
    line: int
    kind: str  # "payload" (fetched bytes executed) or "dropped" (fetched file run / loaded / made executable)
    how: str
    verified: bool


class _Budget(Exception):
    pass


# ---------------------------------------------------------------- shared: commands and verification

P, K, X = "\x01", "\x02", "\x03"  # markers in a command template: payload, dropped file, any other value
_WRAPPERS = {"sudo", "nohup", "env", "exec", "start", "command", "nice", "setsid", "call", "/b", "/c", "cmd", "cmd.exe",
             "/min", "-b", "doas"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish", "ash", "busybox"}
_INTERPS = _SHELLS | {"python", "python2", "python3", "py", "pythonw", "node", "nodejs", "deno", "bun", "perl", "ruby",
                      "php", "pwsh", "powershell", "osascript", "lua", "tclsh"}
_CODE_FLAGS = {"-c", "-e", "--eval", "-p", "--print", "-command", "/c", "-encodedcommand", "-r", "eval", "run"}
_RUNNERS = _INTERPS | {"chmod", "msiexec", "wscript", "cscript", "mshta", "rundll32", "regsvr32",
                       "source", ".", "java", "cmd", "start-process", "launchctl", "nohup", "exec"}
_SPLIT_RE = re.compile(r"&&|\|\||[;&|\n]")
_ASSIGN_TOK_RE = re.compile(r"^[A-Za-z_]\w*=")
_MODE_RE = re.compile(r"^0?o?[0-7]{3,4}$")


def _base(tok: str) -> str:
    t = tok.strip("'\"`()").lower()
    t = t.rsplit("/", 1)[-1].rsplit("\\", 1)[-1]
    return t[:-4] if t.endswith(".exe") else t


def classify(cmd: str, stdin_payload: bool = False) -> str:
    """'payload' / 'dropped' / '' for a command template (markers P, K, X)."""
    if cmd.strip() == P:
        return "payload"
    for seg in _SPLIT_RE.split(cmd):
        toks = seg.split()
        while toks and (_base(toks[0]) in _WRAPPERS or _ASSIGN_TOK_RE.match(toks[0])):
            toks = toks[1:]
        if not toks:
            continue
        prog, rest = toks[0], toks[1:]
        if K in prog:
            return "dropped"
        base = _base(prog)
        if base not in _RUNNERS:
            continue
        if base == "chmod":
            modes = [t for t in rest if K not in t and t.strip("'\"") and not t.startswith("-")]
            if modes and all(_MODE_RE.match(m.strip("'\"")) and not int(m.strip("'\"").lstrip("0o") or "0", 8) & 0o111
                             for m in modes[:1]):
                continue
        if any(K in t for t in rest):
            return "dropped"
        if base in _INTERPS:
            flags = {t.strip("'\"").lower() for t in rest}
            if flags & _CODE_FLAGS and any(t.strip("'\"") == P for t in rest):
                return "payload"
            if stdin_payload and not any(not t.startswith("-") for t in rest if P not in t and X not in t):
                return "payload"
    return ""


_HASHWORD_RE = re.compile(r"sha\d|sha3|blake2|digest|checksum|hash|integrity", re.I)
_CMP_RE = re.compile(r"==|!=|\bcompare_digest\b|\btimingSafeEqual\b|\.equals\(|\bassert\b")
_SIG_RE = re.compile(r"gpg\b[^\n]*--verify|\bcosign\b[^\n]*verify|\bminisign\b|\bsigstore\b|verify_signature|"
                     r"\bcrypto\.verify\(|createVerify\(", re.I)
_VERIFY_CALL_RE = re.compile(r"(?<![\w.$])\w*(?:verify|checksum|integrity)\w*\s*\(", re.I)
_HASH_CALL_RE = re.compile(r"\b(?:hashlib\.\w+|sha(?:224|256|384|512)|sha3_\d+|blake2[bs]|createHash|subtle\.digest|"
                           r"hexdigest|digest)\s*\(", re.I)


def verified(text: str) -> bool:
    if _SIG_RE.search(text):
        return True
    if _HASH_CALL_RE.search(text) and any(_HASHWORD_RE.search(ln) and _CMP_RE.search(ln) for ln in text.splitlines()):
        return True
    return bool(_VERIFY_CALL_RE.search(text))


def _lit_key(s: str) -> str:
    b = s.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    return b if len(b) >= 3 and not b.startswith("-") and " " not in b else ""


_ARGV_GLUE_RE = re.compile(r"[\s;&|]")


def _argv_tok(m: str) -> str:
    """One argv element stays one token (its spaces and shell separators are only text to the program)."""
    return _ARGV_GLUE_RE.sub("\x05", m) if m.strip() else X


_TOK_SPLIT_RE = re.compile(r"[\s'\"`=,;&|()]+")


def _lit_hit(v: str, lits: set) -> bool:
    """A literal names a dropped file: one of its tokens has that file name (not a substring: "tmp" is not /tmp)."""
    if not lits:
        return False
    for tok in _TOK_SPLIT_RE.split(v):
        lk = _lit_key(tok)
        if lk and (lk in lits or ("." not in lk and any(x.rsplit(".", 1)[0] == lk for x in lits if "." in x))):
            return True
    return False


# ---------------------------------------------------------------- Python

_PY_SCOPES = (ast.FunctionDef, ast.AsyncFunctionDef, ast.Lambda, ast.Module)
_PY_NONPAY_ATTRS = {"status_code", "status", "ok", "headers", "url", "reason", "code", "elapsed", "encoding",
                    "cookies", "is_redirect", "history", "raise_for_status", "getcode", "geturl", "info", "close",
                    "length", "closed",
                    # socket bookkeeping: a local listening socket's address or descriptor is not fetched content
                    "getsockname", "getpeername", "fileno", "family", "settimeout", "gettimeout", "setsockopt",
                    "bind", "listen", "pid", "returncode"}
_PY_SANITIZERS = {"len", "int", "float", "bool", "isinstance", "hasattr", "type", "id", "print", "callable", "range",
                  "enumerate.__len__", "logging.info", "logging.debug", "logger.info", "logger.debug"}
_PY_COLLECT = {"append", "extend", "add", "insert", "update", "put", "appendleft", "setdefault"}
# compile() alone runs nothing (a syntax check of a fetched file is common); compile's result reaching exec / eval
# is caught there, because a call made from a payload is a payload.
_PY_EVAL = {"exec", "eval", "builtins.exec", "builtins.eval", "marshal.loads"}
_PY_LOAD_LEAVES = {"run_path", "load_source", "load_dynamic", "SourceFileLoader", "ExtensionFileLoader",
                   "spec_from_file_location", "import_module", "__import__", "CDLL", "WinDLL", "OleDLL", "PyDLL",
                   "LoadLibrary", "zipimporter", "load_module"}
_PY_SHELL_CALLS = {"os.system", "os.popen", "subprocess.getoutput", "subprocess.getstatusoutput",
                   "asyncio.create_subprocess_shell", "commands.getoutput", "os.popen2", "os.popen3"}
_PY_ARGV_CALLS = {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output",
                  "subprocess.check_call", "asyncio.create_subprocess_exec", "pty.spawn", "os.startfile"}
_PY_PROC_LEAVES = {"Popen", "check_output", "check_call", "getoutput", "getstatusoutput", "create_subprocess_shell",
                   "create_subprocess_exec", "startfile"}
_PY_OS_EXEC_RE = re.compile(r"^os\.(?:exec[lv]p?e?|spawn[lv]p?e?|posix_spawnp?)$")
_PY_MOVE = {"shutil.move", "shutil.copy", "shutil.copy2", "shutil.copyfile", "os.rename", "os.replace"}


def _py_dotted(n) -> str:
    parts = []
    while isinstance(n, ast.Attribute):
        parts.append(n.attr)
        n = n.value
    if isinstance(n, ast.Name):
        parts.append(n.id)
        return ".".join(reversed(parts))
    return ""


class _Py:
    def __init__(self, text: str, net_pos: frozenset, norm: Callable[[str], str]):
        self.tree = parsing.py_parse(text)
        self.text, self.norm = text, norm
        src = text.encode()
        self.starts = [0] + [m.end() for m in re.finditer(rb"\r\n|\r|\n", src)]
        self.net_pos = net_pos
        self.steps = 0
        self.parent: dict = {}
        self.nodes: list = []
        self.declared: dict = {}
        self.imported: set = set()
        self.globals_in: dict = {}
        for n in ast.walk(self.tree):
            self.nodes.append(n)
            for c in ast.iter_child_nodes(n):
                self.parent[c] = n
        self._tick(len(self.nodes))
        for n in self.nodes:
            if isinstance(n, (ast.Import, ast.ImportFrom)):
                for a in n.names:
                    self.imported.add((a.asname or a.name).split(".")[0])
            s = self.scope(n)
            if isinstance(n, ast.Name) and isinstance(n.ctx, (ast.Store, ast.Del)):
                self.declared.setdefault(s, set()).add(n.id)
            elif isinstance(n, ast.arg):
                self.declared.setdefault(self._fn_of_arg(n), set()).add(n.arg)
            elif isinstance(n, (ast.Global, ast.Nonlocal)):
                self.globals_in.setdefault(s, set()).update(n.names)
        self.pay: set = set()
        self.pay_funcs: set = set()
        self.defs: dict = {}
        self.handles: dict = {}
        self.dkeys: set = set()
        self.dlits: set = set()
        self.drop_funcs: set = set()
        self.drop_scopes: list = []

    def _tick(self, n: int = 1) -> None:
        self.steps += n
        if self.steps > MAX_STEPS:
            raise _Budget()

    def _fn_of_arg(self, n):
        p = self.parent.get(n)
        while p is not None and not isinstance(p, _PY_SCOPES):
            p = self.parent.get(p)
        return p

    def scope(self, n):
        p = self.parent.get(n)
        while p is not None and not isinstance(p, _PY_SCOPES):
            p = self.parent.get(p)
        return p if p is not None else self.tree

    def key(self, name: str, at) -> tuple:
        s = self.scope(at)
        while s is not None:
            if name in self.declared.get(s, ()) and name not in self.globals_in.get(s, ()):
                return (id(s), name)
            if s is self.tree:
                break
            s = self.scope(s)
        return (id(self.tree), name)

    def pos(self, n) -> int:
        try:
            return self.starts[n.lineno - 1] + n.col_offset
        except (AttributeError, IndexError):
            return -1

    # ---- payload
    def is_pay(self, e, depth: int = 0) -> bool:
        self._tick()
        if e is None or depth > 60:
            return False
        if isinstance(e, ast.Call):
            if self.pos(e) in self.net_pos:
                return True
            d = _py_dotted(e.func)
            if d in _PY_SANITIZERS:
                return False
            leaf = d.rsplit(".", 1)[-1] if d else ""
            if leaf and (d in self.pay_funcs or (leaf in self.pay_funcs and d.split(".")[0] in ("self", "cls"))):
                return True
            if isinstance(e.func, ast.Attribute) and e.func.attr not in _PY_NONPAY_ATTRS and self.is_pay(e.func.value, depth + 1):
                return True
            return any(self.is_pay(a, depth + 1) for a in [*e.args, *(k.value for k in e.keywords)])
        if isinstance(e, ast.Attribute):
            if isinstance(e.value, ast.Name) and e.value.id in ("self", "cls"):
                return ("self.", e.attr) in self.pay
            return e.attr not in _PY_NONPAY_ATTRS and self.is_pay(e.value, depth + 1)
        if isinstance(e, ast.Name):
            return self.key(e.id, e) in self.pay
        if isinstance(e, (ast.Compare, ast.Lambda, ast.Constant)):
            return False
        if isinstance(e, (ast.ListComp, ast.SetComp, ast.GeneratorExp, ast.DictComp)):
            return any(self.is_pay(g.iter, depth + 1) for g in e.generators) or any(
                self.is_pay(c, depth + 1) for c in ast.iter_child_nodes(e) if not isinstance(c, ast.comprehension))
        if isinstance(e, ast.IfExp):
            return self.is_pay(e.body, depth + 1) or self.is_pay(e.orelse, depth + 1)
        if isinstance(e, ast.Subscript):
            return self.is_pay(e.value, depth + 1)
        if isinstance(e, ast.expr):
            return any(self.is_pay(c, depth + 1) for c in ast.iter_child_nodes(e) if isinstance(c, ast.expr))
        return False

    def _target_keys(self, t) -> list:
        """Keys a store to `t` taints: names (through tuples / starred), `self.x`, and the root name of
        `d[k] = ...` / `obj.attr = ...` (the container now holds a payload)."""
        if isinstance(t, ast.Name):
            return [self.key(t.id, t)]
        if isinstance(t, (ast.Tuple, ast.List)):
            return [k for x in t.elts for k in self._target_keys(x)]
        if isinstance(t, ast.Starred):
            return self._target_keys(t.value)
        if isinstance(t, ast.Attribute) and isinstance(t.value, ast.Name) and t.value.id in ("self", "cls"):
            return [("self.", t.attr)]
        if isinstance(t, (ast.Attribute, ast.Subscript)):
            root = t.value
            while isinstance(root, (ast.Attribute, ast.Subscript)):
                root = root.value
            if isinstance(root, ast.Name) and root.id not in ("self", "cls") and root.id not in self.imported:
                return [self.key(root.id, root)]
        return []

    def _taint_target(self, t) -> bool:
        changed = False
        for k in self._target_keys(t):
            if k not in self.pay:
                self.pay.add(k)
                changed = True
        return changed

    def _fn_name(self, n) -> str:
        s = self.scope(n)
        return getattr(s, "name", "") if isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef)) else ""

    def propagate(self) -> None:
        for n in self.nodes:
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                self.defs[self.key(n.targets[0].id, n.targets[0])] = n.value
        for _ in range(PASSES):
            changed = False
            for n in self.nodes:
                self._tick()
                if isinstance(n, (ast.Assign, ast.AnnAssign, ast.AugAssign)) and n.value is not None:
                    if self.is_pay(n.value):
                        for t in (n.targets if isinstance(n, ast.Assign) else [n.target]):
                            changed |= self._taint_target(t)
                elif isinstance(n, (ast.For, ast.AsyncFor, ast.comprehension)):
                    if self.is_pay(n.iter):
                        changed |= self._taint_target(n.target)
                elif isinstance(n, (ast.With, ast.AsyncWith)):
                    for it in n.items:
                        if it.optional_vars is not None and self.is_pay(it.context_expr):
                            changed |= self._taint_target(it.optional_vars)
                elif isinstance(n, ast.NamedExpr):
                    if self.is_pay(n.value):
                        changed |= self._taint_target(n.target)
                elif isinstance(n, ast.Call) and isinstance(n.func, ast.Attribute) and n.func.attr in _PY_COLLECT:
                    if any(self.is_pay(a) for a in n.args):
                        changed |= self._taint_target(n.func.value)
                elif isinstance(n, ast.Return) and n.value is not None:
                    name = self._fn_name(n)
                    if name and name not in self.pay_funcs and self.is_pay(n.value):
                        self.pay_funcs.add(name)
                        changed = True
            if not changed:
                break

    # ---- dropped files
    def keys_of(self, e, depth: int = 0) -> tuple[set, set]:
        ks, ls = set(), set()
        if e is None or depth > 4:
            return ks, ls
        if isinstance(e, ast.Name):
            if e.id not in self.imported:
                k = self.key(e.id, e)
                ks.add(k)
                d = self.defs.get(k)
                if d is not None and not isinstance(d, ast.Name):
                    k2, l2 = self.keys_of(d, depth + 1)
                    ks |= k2
                    ls |= l2
        elif isinstance(e, ast.Attribute):
            if isinstance(e.value, ast.Name) and e.value.id in ("self", "cls"):
                ks.add((".", e.attr))
            elif e.attr == "name":
                return self.keys_of(e.value, depth + 1)
            else:
                ks.add((".", e.attr))
        elif isinstance(e, ast.Constant) and isinstance(e.value, str):
            lk = _lit_key(e.value)
            if lk:
                ls.add(lk)
        elif isinstance(e, ast.Call):
            if e.args:
                return self.keys_of(e.args[-1], depth + 1)
            if isinstance(e.func, ast.Attribute):
                return self.keys_of(e.func.value, depth + 1)
        elif isinstance(e, ast.BinOp):
            ks, ls = self.keys_of(e.right, depth + 1)
            if isinstance(e.right, ast.Constant) and str(e.right.value).startswith("."):
                k2, l2 = self.keys_of(e.left, depth + 1)
                ks |= k2
                ls |= l2
        elif isinstance(e, ast.JoinedStr):
            vals = [v for v in e.values if isinstance(v, ast.FormattedValue)]
            tail = e.values[-1] if e.values else None
            if isinstance(tail, ast.Constant) and _lit_key(str(tail.value)):
                ls.add(_lit_key(str(tail.value)))
            if vals:
                k2, l2 = self.keys_of(vals[-1].value, depth + 1)
                ks |= k2
                ls |= l2
        elif isinstance(e, ast.Subscript):
            return self.keys_of(e.value, depth + 1)
        return ks, ls

    def _drop(self, path_expr, at) -> bool:
        ks, ls = self.keys_of(path_expr)
        new = (ks - self.dkeys) or (ls - self.dlits)
        self.dkeys |= ks
        self.dlits |= ls
        self.drop_scopes.append(self.scope(at))
        return bool(new)

    def refers(self, e) -> bool:
        if e is None:
            return False
        for n in ast.walk(e):
            self._tick()
            if isinstance(n, ast.Name):
                if n.id not in self.imported and self.key(n.id, n) in self.dkeys:
                    return True
            elif isinstance(n, ast.Attribute):
                if (".", n.attr) in self.dkeys:
                    return True
            elif isinstance(n, ast.Constant) and isinstance(n.value, str) and self.dlits:
                v = n.value
                if _lit_hit(v, self.dlits):
                    return True
            elif isinstance(n, ast.Call):
                d = _py_dotted(n.func)
                if d and d.rsplit(".", 1)[-1] in self.drop_funcs:
                    return True
        return False

    @staticmethod
    def _mode(call) -> str | None:
        m = call.args[1] if len(call.args) > 1 else next((k.value for k in call.keywords if k.arg == "mode"), None)
        if m is None:
            return "r"
        return m.value if isinstance(m, ast.Constant) and isinstance(m.value, str) else None

    def _is_write_open(self, call) -> bool:
        if not isinstance(call, ast.Call):
            return False
        d = self.norm(_py_dotted(call.func))
        leaf = d.rsplit(".", 1)[-1]
        if d in ("open", "io.open", "codecs.open", "builtins.open") or (leaf == "open" and isinstance(call.func, ast.Attribute)):
            args = call.args if d in ("open", "io.open", "codecs.open", "builtins.open") else [None, *call.args]
            m = args[1] if len(args) > 1 else next((k.value for k in call.keywords if k.arg == "mode"), None)
            if m is None:
                return False
            if isinstance(m, ast.Constant) and isinstance(m.value, str):
                return bool(set(m.value) & set("wax+"))
            return True  # computed mode: fail closed
        return leaf in ("NamedTemporaryFile", "TemporaryFile", "SpooledTemporaryFile")

    def _open_path(self, call):
        d = self.norm(_py_dotted(call.func))
        if d in ("open", "io.open", "codecs.open", "builtins.open"):
            return call.args[0] if call.args else next((k.value for k in call.keywords if k.arg == "file"), None)
        if isinstance(call.func, ast.Attribute) and call.func.attr == "open":
            return call.func.value
        return None

    def collect_drops(self) -> None:
        for n in self.nodes:
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name) and self._is_write_open(n.value):
                self.handles[self.key(n.targets[0].id, n.targets[0])] = (self._open_path(n.value) or n.targets[0])
            elif isinstance(n, (ast.With, ast.AsyncWith)):
                for it in n.items:
                    if isinstance(it.optional_vars, ast.Name) and self._is_write_open(it.context_expr):
                        self.handles[self.key(it.optional_vars.id, it.optional_vars)] = (
                            self._open_path(it.context_expr) or it.optional_vars)
        for _ in range(PASSES):
            changed = False
            for n in self.nodes:
                self._tick()
                if isinstance(n, ast.Call):
                    changed |= self._drop_call(n)
                elif isinstance(n, ast.Assign) and self.refers(n.value):
                    for t in n.targets:
                        ks, _ = self.keys_of(t) if isinstance(t, ast.Name) else (set(), set())
                        if ks - self.dkeys:
                            self.dkeys |= ks
                            changed = True
                elif isinstance(n, ast.Return) and n.value is not None:
                    name = self._fn_name(n)
                    if name and name not in self.drop_funcs and self.refers(n.value):
                        self.drop_funcs.add(name)
                        changed = True
            if not changed:
                break

    def _drop_call(self, n) -> bool:
        d = self.norm(_py_dotted(n.func))
        leaf = d.rsplit(".", 1)[-1] if d else (n.func.attr if isinstance(n.func, ast.Attribute) else "")
        args = [*n.args, *(k.value for k in n.keywords)]
        if leaf in ("write", "writelines") and isinstance(n.func, ast.Attribute) and any(self.is_pay(a) for a in n.args):
            obj = n.func.value
            if isinstance(obj, ast.Name):
                h = self.handles.get(self.key(obj.id, obj))
                if h is not None:
                    return self._drop(h, n)
            elif isinstance(obj, ast.Call) and self._is_write_open(obj):
                return self._drop(self._open_path(obj) or obj, n)
            return False
        if leaf in ("write_bytes", "write_text") and isinstance(n.func, ast.Attribute) and any(self.is_pay(a) for a in n.args):
            return self._drop(n.func.value, n)
        if leaf == "copyfileobj" and len(n.args) >= 2 and self.is_pay(n.args[0]):
            dst = n.args[1]
            h = self.handles.get(self.key(dst.id, dst)) if isinstance(dst, ast.Name) else None
            return self._drop(h if h is not None else dst, n)
        if leaf == "urlretrieve":
            dst = n.args[1] if len(n.args) > 1 else next((k.value for k in n.keywords if k.arg == "filename"), None)
            return self._drop(dst, n) if dst is not None else False
        if d in ("wget.download",):
            dst = n.args[1] if len(n.args) > 1 else next((k.value for k in n.keywords if k.arg == "out"), None)
            return self._drop(dst, n) if dst is not None else False
        if d in _PY_MOVE and len(n.args) >= 2 and self.refers(n.args[0]):
            ks, ls = self.keys_of(n.args[1])
            if (ks - self.dkeys) or (ls - self.dlits):
                return self._drop(n.args[1], n)
        del args
        return False

    # ---- commands
    def marker(self, e, depth: int = 0) -> str:
        self._tick()
        if depth > 6 or e is None:
            return X
        if isinstance(e, ast.Constant):
            if isinstance(e.value, str):
                v = e.value
                return " ".join(K if _lit_hit(tok, self.dlits) else tok for tok in v.split(" ")) if self.dlits else v
            return X
        if isinstance(e, ast.JoinedStr):
            return "".join(self.marker(v.value if isinstance(v, ast.FormattedValue) else v, depth + 1) for v in e.values)
        if isinstance(e, ast.BinOp) and isinstance(e.op, (ast.Add, ast.Mod)):
            return self.marker(e.left, depth + 1) + self.marker(e.right, depth + 1)
        if isinstance(e, (ast.List, ast.Tuple)):
            return " ".join(_argv_tok(self.marker(x, depth + 1)) for x in e.elts)
        if isinstance(e, ast.Call) and isinstance(e.func, ast.Attribute) and e.func.attr == "format" and isinstance(e.func.value, ast.Constant):
            parts = [self.marker(a, depth + 1) for a in e.args]
            it = iter(parts)
            return re.sub(r"\{[^{}]*\}", lambda _m: next(it, X), str(e.func.value.value))
        if isinstance(e, ast.Call) and _py_dotted(e.func).endswith(("shlex.join", "join")) and e.args and isinstance(e.args[0], (ast.List, ast.Tuple)):
            return self.marker(e.args[0], depth + 1)
        if isinstance(e, ast.Starred):
            return self.marker(e.value, depth + 1)
        if isinstance(e, ast.Name) and self.key(e.id, e) not in self.dkeys:
            # A command built in a variable is read by its structure: a list holding one remote value is not a
            # remote command.
            dv = self.defs.get(self.key(e.id, e))
            if isinstance(dv, (ast.Constant, ast.JoinedStr, ast.List, ast.Tuple, ast.BinOp)):
                return self.marker(dv, depth + 1)
        if self.refers(e):
            return K
        if self.is_pay(e):
            return P
        return X

    def sinks(self) -> list[Hit]:
        out: list[Hit] = []
        for n in self.nodes:
            if not isinstance(n, ast.Call):
                continue
            self._tick()
            raw = _py_dotted(n.func)
            d = self.norm(raw) if raw else ""
            leaf = d.rsplit(".", 1)[-1] if d else (n.func.attr if isinstance(n.func, ast.Attribute) else "")
            a0 = n.args[0] if n.args else None
            kind, how = "", ""
            if d in _PY_EVAL or raw in ("exec", "eval"):
                if self.is_pay(a0):
                    kind, how = "payload", f"downloaded content passed to {leaf}()"
                elif self.refers(a0):
                    kind, how = "dropped", f"a downloaded file's content passed to {leaf}()"
            elif leaf in _PY_LOAD_LEAVES and any(self.refers(a) for a in [*n.args, *(k.value for k in n.keywords)]):
                kind, how = "dropped", f"a downloaded file is loaded with {leaf}()"
            elif d in _PY_SHELL_CALLS or d in _PY_ARGV_CALLS or _PY_OS_EXEC_RE.match(d) or (
                    leaf in _PY_PROC_LEAVES and not d.startswith(("self.", "cls."))):
                cmd = next((k.value for k in n.keywords if k.arg == "args"), a0)
                if _PY_OS_EXEC_RE.match(d):
                    cmd_s = K if any(self.refers(a) for a in n.args[:2]) else (
                        self.marker(n.args[1] if d.startswith("os.spawn") and len(n.args) > 1 else a0))
                elif leaf == "create_subprocess_exec":
                    cmd_s = " ".join(self.marker(a) for a in n.args)
                elif leaf == "startfile":
                    cmd_s = K if self.refers(a0) else X
                else:
                    cmd_s = self.marker(cmd)
                stdin = any(k.arg in ("input", "stdin") and self.is_pay(k.value) for k in n.keywords)
                got = classify(cmd_s, stdin)
                if got:
                    kind = got
                    how = (f"downloaded content run as a command by {leaf}()" if got == "payload"
                           else f"a downloaded file is run by {leaf}()")
            elif leaf in ("chmod", "lchmod", "fchmod"):
                target, mode = (a0, n.args[1] if len(n.args) > 1 else None) if d.startswith("os.") else (
                    n.func.value if isinstance(n.func, ast.Attribute) else None, a0)
                if target is not None and self.refers(target) and self._exec_mode(mode):
                    kind, how = "dropped", "a downloaded file is made executable (chmod)"
            if kind:
                out.append(Hit(n.lineno, kind, how, self._verified(n, kind)))
        return out

    @staticmethod
    def _exec_mode(mode) -> bool:
        if isinstance(mode, ast.Constant) and isinstance(mode.value, int):
            return bool(mode.value & 0o111)
        return True  # computed (st.st_mode | stat.S_IEXEC ...) or unknown: fail closed

    def _scope_text(self, s) -> str:
        if s is None or s is self.tree:
            return self.text
        lines = self.text.split("\n")
        return "\n".join(lines[s.lineno - 1: (s.end_lineno or s.lineno)])

    def _verified(self, n, kind: str) -> bool:
        return any(verified(self._scope_text(s)) for s in _check_scopes(self.scope(n), kind, self.drop_scopes, self.tree))


def _check_scopes(sink_scope, kind: str, drop_scopes: list, module) -> list:
    """Where a verification counts: the sink's function; for a dropped file also the functions that wrote it.
    The whole module counts only when the sink itself is module-level code."""
    out = [sink_scope]
    if kind == "dropped":
        for s in drop_scopes:
            if s != module and all(s != x for x in out) and len(out) < 9:  # ast: identity; tree-sitter: same node
                out.append(s)
    return out


def _py_hits(text: str, net_pos: frozenset, norm) -> list[Hit]:
    a = _Py(text, net_pos, norm)
    a.propagate()
    a.collect_drops()
    return a.sinks()


# ---------------------------------------------------------------- JS / TS

_JS_FUNCS = {"function_declaration", "function_expression", "function", "arrow_function", "method_definition",
             "generator_function", "generator_function_declaration"}
_JS_NONPAY_PROPS = {"status", "statusCode", "statusText", "ok", "headers", "url", "length", "statusMessage",
                    "redirected", "type", "bodyUsed", "readyState", "byteLength"}
_JS_SANITIZERS = {"parseInt", "parseFloat", "Number", "Boolean", "isNaN", "Array.isArray", "console.log",
                  "console.error", "console.warn", "console.info", "console.debug", "String.prototype"}
_JS_COLLECT = {"push", "unshift", "add", "set", "concat", "write"}
_JS_EVAL_LEAVES = {"runInThisContext", "runInNewContext", "runInContext", "compileFunction", "_compile"}
_JS_PROC_STRING = {"exec", "execSync", "execaCommand", "execaCommandSync"}
_JS_PROC_ARGV = {"spawn", "spawnSync", "execFile", "execFileSync", "execa", "execaSync", "fork"}
_JS_PROC_MODULES = ("child_process", "execa", "cross-spawn", "shelljs", "node:child_process")
_JS_FS_ROOTS = ("fs", "fs-extra", "fs.promises", "fs/promises", "graceful-fs", "node:fs", "fsp", "Bun", "promises")
_JS_WRITE_LEAVES = {"writeFile", "writeFileSync", "appendFile", "appendFileSync", "outputFile", "outputFileSync", "write"}
_JS_IDS = ("identifier", "shorthand_property_identifier_pattern", "shorthand_property_identifier")
_JS_WRAP = {"parenthesized_expression", "await_expression", "as_expression", "non_null_expression", "satisfies_expression",
            "type_assertion", "spread_element"}


def _k(n) -> tuple:
    return (n.start_byte, n.end_byte, n.type)


class _Js:
    def __init__(self, rel: str, text: str, net_pos: frozenset, norm, al: dict):
        self.src = text.encode()
        lang = "tsx" if rel.endswith(".tsx") else "typescript" if rel.endswith((".ts", ".mts", ".cts")) else "javascript"
        self.root = parsing.js_root(self.src, lang)
        self.text, self.net_pos, self.norm, self.al = text, net_pos, norm, al
        self.steps = 0
        self.nodes: list = []
        self.declared: dict = {}
        stack = [self.root]
        while stack:
            n = stack.pop()
            self._tick()
            self.nodes.append(n)
            stack.extend(reversed(n.children))
            t = n.type
            if t == "variable_declarator":
                nm = n.child_by_field_name("name")
                if nm is not None:
                    s = self.scope(n)
                    for i in self._ids(nm):
                        self.declared.setdefault(_k(s), set()).add(i)
            elif t in ("formal_parameters", "required_parameter", "optional_parameter") or (
                    t == "identifier" and n.parent is not None and n.parent.type == "arrow_function"
                    and n.parent.child_by_field_name("parameter") is not None
                    and _k(n.parent.child_by_field_name("parameter")) == _k(n)):
                fn = n.parent if t == "identifier" else self._enclosing_fn(n)
                if fn is not None:
                    for i in ([self.txt(n)] if t == "identifier" else self._ids(n)):
                        self.declared.setdefault(_k(fn), set()).add(i)
            elif t in ("function_declaration", "generator_function_declaration", "class_declaration"):
                nm = n.child_by_field_name("name")
                if nm is not None:
                    self.declared.setdefault(_k(self.scope(n)), set()).add(self.txt(nm))
        self.pay: set = set()
        self.pay_funcs: set = set()
        self.defs: dict = {}
        self.handles: dict = {}
        self.dkeys: set = set()
        self.dlits: set = set()
        self.drop_funcs: set = set()
        self.drop_scopes: list = []
        # Names bound to a whole module or an imported member (fs, path, os ...): never a file's name.
        self.imported: set = set()
        for n in self.nodes:
            if n.type == "import_statement":
                for c in n.named_children:
                    if c.type == "import_clause":
                        self.imported.update(self._ids(c) + [self.txt(x) for x in c.named_children if x.type == "identifier"])
            elif n.type == "variable_declarator":
                nm, v = n.child_by_field_name("name"), self._unwrap(n.child_by_field_name("value"))
                if nm is not None and v is not None and v.type == "call_expression":
                    fn = self._callee(v)
                    if fn is not None and (fn.type == "import" or self.txt(fn) == "require"):
                        self.imported.update([self.txt(nm)] if nm.type == "identifier" else self._ids(nm))

    def _tick(self, n: int = 1) -> None:
        self.steps += n
        if self.steps > MAX_STEPS:
            raise _Budget()

    def txt(self, n) -> str:
        return self.src[n.start_byte:n.end_byte].decode("utf-8", "replace")

    def _ids(self, n) -> list[str]:
        out, st = [], [n]
        while st:
            x = st.pop()
            if x.type in _JS_IDS:
                out.append(self.txt(x))
            elif x.type in ("type_annotation", "property_identifier"):
                continue
            elif x.type == "assignment_pattern" or x.type == "object_assignment_pattern":
                left = x.child_by_field_name("left")
                if left is not None:
                    st.append(left)
                continue
            elif x.type == "pair_pattern":
                v = x.child_by_field_name("value")
                if v is not None:
                    st.append(v)
                continue
            st.extend(x.named_children)
        return out

    def _enclosing_fn(self, n):
        p = n.parent
        while p is not None and p.type not in _JS_FUNCS:
            p = p.parent
        return p

    def scope(self, n):
        p = self._enclosing_fn(n)
        return p if p is not None else self.root

    def key(self, name: str, at) -> tuple:
        s = self.scope(at) if at.type != "program" else self.root
        while True:
            if name in self.declared.get(_k(s), ()):
                return (_k(s), name)
            if s.type == "program":
                return (_k(self.root), name)
            s = self.scope(s)

    @staticmethod
    def _unwrap(n):
        while n is not None and n.type in _JS_WRAP:
            c = n.named_children
            n = c[-1] if c else None
        return n

    def _callee(self, n):
        return n.child_by_field_name("function" if n.type == "call_expression" else "constructor")

    def _args(self, n) -> list:
        a = n.child_by_field_name("arguments")
        if a is None:
            return []
        return [c for c in a.named_children if c.type != "comment"]

    def is_pay(self, e, depth: int = 0) -> bool:
        self._tick()
        if e is None or depth > 60:
            return False
        t = e.type
        if t in _JS_WRAP:
            return any(self.is_pay(c, depth + 1) for c in e.named_children)
        if t in ("call_expression", "new_expression"):
            if e.start_byte in self.net_pos:
                return True
            fn = self._callee(e)
            if fn is None:
                return False
            ftxt = self.txt(fn) if fn.end_byte - fn.start_byte < 200 else ""
            if ftxt in _JS_SANITIZERS:
                return False
            if fn.type == "identifier" and ftxt in self.pay_funcs:
                return True
            if fn.type == "member_expression":
                prop = fn.child_by_field_name("property")
                pname = self.txt(prop) if prop is not None else ""
                if pname in self.pay_funcs and self.txt(fn.child_by_field_name("object")) == "this":
                    return True
                if pname not in _JS_NONPAY_PROPS and self.is_pay(fn.child_by_field_name("object"), depth + 1):
                    return True
            return any(self.is_pay(a, depth + 1) for a in self._args(e) if a.type not in _JS_FUNCS)
        if t == "member_expression":
            prop = e.child_by_field_name("property")
            if prop is not None and self.txt(prop) in _JS_NONPAY_PROPS:
                return False
            return self.is_pay(e.child_by_field_name("object"), depth + 1)
        if t == "subscript_expression":
            return self.is_pay(e.child_by_field_name("object"), depth + 1)
        if t == "identifier":
            return self.key(self.txt(e), e) in self.pay
        if t == "template_string":
            return any(self.is_pay(c, depth + 1) for c in e.named_children if c.type == "template_substitution")
        if t == "template_substitution":
            return any(self.is_pay(c, depth + 1) for c in e.named_children)
        if t == "binary_expression":
            op = e.child_by_field_name("operator")
            if op is not None and self.txt(op) not in ("+", "||", "??", "&&"):
                return False
            return self.is_pay(e.child_by_field_name("left"), depth + 1) or self.is_pay(e.child_by_field_name("right"), depth + 1)
        if t == "ternary_expression":
            return self.is_pay(e.child_by_field_name("consequence"), depth + 1) or self.is_pay(e.child_by_field_name("alternative"), depth + 1)
        if t in ("array", "object", "pair"):
            return any(self.is_pay(c if c.type != "pair" else c.child_by_field_name("value"), depth + 1)
                       for c in e.named_children)
        if t in ("assignment_expression", "augmented_assignment_expression"):
            return self.is_pay(e.child_by_field_name("right"), depth + 1)
        return False

    def _taint(self, target) -> bool:
        changed = False
        for i in self._ids(target) if target.type != "identifier" else [self.txt(target)]:
            k = self.key(i, target)
            if k not in self.pay:
                self.pay.add(k)
                changed = True
        return changed

    def _taint_params(self, fn) -> bool:
        changed = False
        ps = fn.child_by_field_name("parameters") or fn.child_by_field_name("parameter")
        if ps is None:
            return False
        for i in ([self.txt(ps)] if ps.type == "identifier" else self._ids(ps)):
            k = (_k(fn), i)
            if k not in self.pay:
                self.pay.add(k)
                changed = True
        return changed

    def _fn_name(self, fn) -> str:
        nm = fn.child_by_field_name("name")
        if nm is not None:
            return self.txt(nm)
        p = fn.parent
        if p is not None and p.type == "variable_declarator":
            nm = p.child_by_field_name("name")
            return self.txt(nm) if nm is not None and nm.type == "identifier" else ""
        return ""

    def propagate(self) -> None:
        for n in self.nodes:
            if n.type == "variable_declarator":
                nm, v = n.child_by_field_name("name"), n.child_by_field_name("value")
                if nm is not None and v is not None and nm.type == "identifier":
                    self.defs[self.key(self.txt(nm), nm)] = v
        for _ in range(PASSES):
            changed = False
            for n in self.nodes:
                self._tick()
                t = n.type
                if t == "variable_declarator":
                    v = n.child_by_field_name("value")
                    nm = n.child_by_field_name("name")
                    if v is not None and nm is not None and self.is_pay(v):
                        changed |= self._taint(nm)
                elif t in ("assignment_expression", "augmented_assignment_expression"):
                    left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                    if left is not None and self.is_pay(right):
                        while left is not None and left.type in ("member_expression", "subscript_expression"):
                            left = left.child_by_field_name("object")
                        if left is not None and left.type in ("identifier", "array_pattern", "object_pattern"):
                            changed |= self._taint(left)
                elif t == "for_in_statement":
                    left, right = n.child_by_field_name("left"), n.child_by_field_name("right")
                    if left is not None and self.is_pay(right):
                        changed |= self._taint(left)
                elif t in ("call_expression", "new_expression"):
                    fn = self._callee(n)
                    args = self._args(n)
                    on_pay = n.start_byte in self.net_pos or (
                        fn is not None and fn.type == "member_expression" and self.is_pay(fn.child_by_field_name("object")))
                    if on_pay:
                        for a in args:
                            if a.type in _JS_FUNCS:
                                changed |= self._taint_params(a)
                    if fn is not None and fn.type == "member_expression":
                        prop = fn.child_by_field_name("property")
                        if prop is not None and self.txt(prop) in _JS_COLLECT and any(
                                self.is_pay(a) for a in args if a.type not in _JS_FUNCS):
                            obj = fn.child_by_field_name("object")
                            if obj is not None and obj.type == "identifier":
                                changed |= self._taint(obj)
                elif t in _JS_FUNCS:
                    body = n.child_by_field_name("body")
                    name = self._fn_name(n)
                    if name and name not in self.pay_funcs and body is not None and self._returns_pay(n, body):
                        self.pay_funcs.add(name)
                        changed = True
            if not changed:
                break

    def _returns_pay(self, fn, body) -> bool:
        if body.type != "statement_block":
            return self.is_pay(body)
        st = [body]
        while st:
            x = st.pop()
            self._tick()
            if x.type == "return_statement":
                if any(self.is_pay(c) for c in x.named_children):
                    return True
            elif x.type not in _JS_FUNCS:
                st.extend(x.named_children)
        return False

    # ---- dropped files
    def keys_of(self, e, depth: int = 0) -> tuple[set, set]:
        ks, ls = set(), set()
        e = self._unwrap(e)
        if e is None or depth > 4:
            return ks, ls
        t = e.type
        if t == "identifier":
            name = self.txt(e)
            if name not in self.imported:
                k = self.key(name, e)
                ks.add(k)
                d = self.defs.get(k)
                if d is not None and d.type != "identifier":
                    k2, l2 = self.keys_of(d, depth + 1)
                    ks |= k2
                    ls |= l2
        elif t == "member_expression":
            prop = e.child_by_field_name("property")
            if prop is not None and len(self.txt(prop)) >= 3:
                ks.add((".", self.txt(prop)))
        elif t == "string":
            lk = _lit_key(self.txt(e)[1:-1])
            if lk:
                ls.add(lk)
        elif t in ("call_expression", "new_expression"):
            args = self._args(e)
            if args:
                return self.keys_of(args[-1], depth + 1)
        elif t == "binary_expression":
            r = e.child_by_field_name("right")
            ks, ls = self.keys_of(r, depth + 1)
            if r is not None and r.type == "string" and self.txt(r)[1:].startswith("."):
                k2, l2 = self.keys_of(e.child_by_field_name("left"), depth + 1)
                ks |= k2
                ls |= l2
        elif t == "template_string":
            subs = [c for c in e.named_children if c.type == "template_substitution"]
            tail = self.src[(subs[-1].end_byte if subs else e.start_byte + 1):e.end_byte - 1].decode("utf-8", "replace")
            lk = _lit_key(tail)
            if lk:
                ls.add(lk)
            if subs and subs[-1].named_children:
                k2, l2 = self.keys_of(subs[-1].named_children[0], depth + 1)
                ks |= k2
                ls |= l2
        return ks, ls

    def _drop(self, path_node, at) -> bool:
        ks, ls = self.keys_of(path_node)
        new = (ks - self.dkeys) or (ls - self.dlits)
        self.dkeys |= ks
        self.dlits |= ls
        self.drop_scopes.append(self.scope(at))
        return bool(new)

    def refers(self, e) -> bool:
        if e is None:
            return False
        st = [e]
        while st:
            x = st.pop()
            self._tick()
            t = x.type
            if t == "identifier":
                nm = self.txt(x)
                if nm not in self.imported and self.key(nm, x) in self.dkeys:
                    return True
            elif t == "member_expression":
                prop = x.child_by_field_name("property")
                if prop is not None and (".", self.txt(prop)) in self.dkeys:
                    return True
            elif t in ("string_fragment", "string") and self.dlits:
                v = self.txt(x)
                if _lit_hit(v, self.dlits):
                    return True
            elif t == "call_expression":
                fn = self._callee(x)
                if fn is not None and fn.type == "identifier" and self.txt(fn) in self.drop_funcs:
                    return True
            if t not in _JS_FUNCS or x is e:
                st.extend(x.named_children)
        return False

    def _norm_of(self, fn) -> str:
        if fn is None:
            return ""
        if fn.type == "import":
            return "import"
        raw = self.txt(fn) if fn.end_byte - fn.start_byte < 200 else ""
        return self.norm(raw) if raw else ""

    def _is_ws(self, n) -> bool:
        n = self._unwrap(n)
        if n is None or n.type not in ("call_expression", "new_expression"):
            return False
        return self._norm_of(self._callee(n)).rsplit(".", 1)[-1] in ("createWriteStream", "WriteStream", "createOutputStream")

    def _ws_path(self, n):
        n = self._unwrap(n)
        if n is not None and n.type == "identifier":
            return self.handles.get(self.key(self.txt(n), n))
        if self._is_ws(n):
            a = self._args(n)
            return a[0] if a else None
        return None

    def collect_drops(self) -> None:
        for n in self.nodes:
            if n.type == "variable_declarator":
                nm, v = n.child_by_field_name("name"), n.child_by_field_name("value")
                if nm is not None and nm.type == "identifier" and v is not None and self._is_ws(v):
                    a = self._args(self._unwrap(v))
                    if a:
                        self.handles[self.key(self.txt(nm), nm)] = a[0]
        for _ in range(PASSES):
            changed = False
            for n in self.nodes:
                self._tick()
                t = n.type
                if t == "call_expression":
                    changed |= self._drop_call(n)
                elif t == "variable_declarator":
                    nm, v = n.child_by_field_name("name"), n.child_by_field_name("value")
                    if nm is not None and nm.type == "identifier" and v is not None and self.refers(v):
                        k = self.key(self.txt(nm), nm)
                        if k not in self.dkeys:
                            self.dkeys.add(k)
                            changed = True
                elif t in _JS_FUNCS:
                    name = self._fn_name(n)
                    body = n.child_by_field_name("body")
                    if name and name not in self.drop_funcs and body is not None and self._returns_drop(body):
                        self.drop_funcs.add(name)
                        changed = True
            if not changed:
                break

    def _returns_drop(self, body) -> bool:
        if body.type != "statement_block":
            return self.refers(body)
        st = [body]
        while st:
            x = st.pop()
            if x.type == "return_statement":
                if any(self.refers(c) for c in x.named_children):
                    return True
            elif x.type not in _JS_FUNCS:
                st.extend(x.named_children)
        return False

    def _drop_call(self, n) -> bool:
        fn = self._callee(n)
        d = self._norm_of(fn)
        leaf = d.rsplit(".", 1)[-1]
        args = self._args(n)
        if fn is not None and fn.type == "member_expression":
            obj = fn.child_by_field_name("object")
            if leaf == "pipe" and args and self.is_pay(obj):
                p = self._ws_path(args[0])
                if p is not None:
                    return self._drop(p, n)
            if leaf == "write" and args and self.is_pay(args[0]):
                p = self._ws_path(obj)
                if p is not None:
                    return self._drop(p, n)
        if leaf in ("pipeline",) and len(args) >= 2 and self.is_pay(args[0]):
            p = self._ws_path(args[-1]) or (self._ws_path(args[-2]) if len(args) > 2 else None)
            if p is not None:
                return self._drop(p, n)
        if leaf in _JS_WRITE_LEAVES and leaf != "write" and len(args) >= 2 and any(self.is_pay(a) for a in args[1:]):
            root = d.rsplit(".", 1)[0] if "." in d else ""
            if root.endswith(_JS_FS_ROOTS) or d == leaf:
                return self._drop(args[0], n)
        if d == "Bun.write" and len(args) >= 2 and self.is_pay(args[1]):
            return self._drop(args[0], n)
        if leaf in ("rename", "renameSync", "copyFile", "copyFileSync", "move", "moveSync") and len(args) >= 2 and self.refers(args[0]):
            ks, ls = self.keys_of(args[1])
            if (ks - self.dkeys) or (ls - self.dlits):
                return self._drop(args[1], n)
        return False

    # ---- commands
    def marker(self, e, depth: int = 0) -> str:
        self._tick()
        e = self._unwrap(e)
        if e is None or depth > 6:
            return X
        t = e.type
        if t == "string":
            v = self.txt(e)[1:-1]
            return " ".join(K if _lit_hit(tok, self.dlits) else tok for tok in v.split(" ")) if self.dlits else v
        if t == "template_string":
            out, at = [], e.start_byte + 1
            for c in e.named_children:
                if c.type == "template_substitution":
                    out.append(self.src[at:c.start_byte].decode("utf-8", "replace"))
                    inner = c.named_children[0] if c.named_children else None
                    out.append(self.marker(inner, depth + 1))
                    at = c.end_byte
            out.append(self.src[at:e.end_byte - 1].decode("utf-8", "replace"))
            s = "".join(out)
            return " ".join(K if _lit_hit(tok, self.dlits) else tok for tok in s.split(" ")) if self.dlits else s
        if t == "binary_expression":
            op = e.child_by_field_name("operator")
            if op is not None and self.txt(op) == "+":
                return self.marker(e.child_by_field_name("left"), depth + 1) + self.marker(e.child_by_field_name("right"), depth + 1)
        if t == "array":
            return " ".join(_argv_tok(self.marker(c, depth + 1)) for c in e.named_children)
        if t == "identifier" and self.key(self.txt(e), e) not in self.dkeys:
            dv = self.defs.get(self.key(self.txt(e), e))
            if dv is not None and dv.type in ("string", "template_string", "array", "binary_expression"):
                return self.marker(dv, depth + 1)
        if self.refers(e):
            return K
        if self.is_pay(e):
            return P
        return X

    def sinks(self) -> list[Hit]:
        out: list[Hit] = []
        for n in self.nodes:
            if n.type not in ("call_expression", "new_expression"):
                continue
            self._tick()
            fn = self._callee(n)
            d = self._norm_of(fn)
            leaf = d.rsplit(".", 1)[-1]
            args = self._args(n)
            a0 = args[0] if args else None
            kind, how = "", ""
            is_proc = d.startswith(_JS_PROC_MODULES) or d.split(".")[0] in ("execa", "shelljs") or d in (
                "Bun.spawn", "Bun.spawnSync", "Deno.Command", "Deno.run")
            if d in ("eval", "Function", "window.eval", "globalThis.eval") or (leaf in _JS_EVAL_LEAVES and (
                    d.startswith("vm.") or leaf == "_compile")) or d == "vm.Script":
                pool = args if leaf in ("Function", "compileFunction") or d == "vm.Script" else args[:1]
                if any(self.is_pay(a) for a in pool if a.type not in _JS_FUNCS):
                    kind, how = "payload", f"downloaded content passed to {leaf}()"
            elif leaf in ("setTimeout", "setInterval", "setImmediate") and a0 is not None and a0.type not in _JS_FUNCS \
                    and a0.type != "identifier" and self.is_pay(a0):
                kind, how = "payload", f"downloaded content passed to {leaf}() as code"
            elif d == "Worker" and len(args) >= 2 and self.is_pay(a0) and "eval" in self.txt(args[1]):
                kind, how = "payload", "downloaded content run in a Worker with eval: true"
            elif is_proc and leaf in _JS_PROC_STRING:
                got = classify(self.marker(a0))
                if got:
                    kind, how = got, (f"downloaded content run as a command by {leaf}()" if got == "payload"
                                      else f"a downloaded file is run by {leaf}()")
            elif is_proc and (leaf in _JS_PROC_ARGV or d in ("Bun.spawn", "Bun.spawnSync", "Deno.Command", "Deno.run")
                              or d in ("execa", "cross-spawn")):
                if leaf == "fork":
                    got = "dropped" if self.refers(a0) else ""
                else:
                    cmd = self.marker(a0)
                    if len(args) > 1 and args[1].type == "array":
                        cmd += " " + self.marker(args[1])
                    stdin = any(self.is_pay(a) for a in args[1:] if a.type == "object" and "input" in self.txt(a))
                    got = classify(cmd, stdin)
                if got:
                    kind, how = got, (f"downloaded content run as a command by {leaf}()" if got == "payload"
                                      else f"a downloaded file is run by {leaf}()")
            elif leaf in ("chmod", "chmodSync") and a0 is not None and (d.rsplit(".", 1)[0].endswith(_JS_FS_ROOTS) or d == leaf):
                mode = args[1] if len(args) > 1 else None
                if self.refers(a0) and self._exec_mode(mode):
                    kind, how = "dropped", "a downloaded file is made executable (chmod)"
            elif d in ("require", "import", "process.dlopen", "module.require", "createRequire") or leaf == "dlopen":
                if any(self.refers(a) for a in args):
                    kind, how = "dropped", f"a downloaded file is loaded with {leaf}()"
            if not kind and fn is not None and fn.type == "member_expression" and self.is_pay(fn.child_by_field_name("object")):
                for a in args:
                    if a.type == "identifier" and self.norm(self.txt(a)) in ("eval", "Function"):
                        kind, how = "payload", f"downloaded content handed to {self.txt(a)}"
                        break
            if kind:
                out.append(Hit(n.start_point[0] + 1, kind, how, self._verified(n, kind)))
        return out

    def _exec_mode(self, mode) -> bool:
        if mode is None:
            return True
        s = self.txt(mode).strip().replace("_", "")
        try:
            v = int(s, 0) if not re.fullmatch(r"['\"]?[0-7]{3,4}['\"]?", s) else int(s.strip("'\""), 8)
        except ValueError:
            return True
        return bool(v & 0o111)

    def _verified(self, n, kind: str) -> bool:
        return any(verified(self.txt(s)) for s in _check_scopes(self.scope(n), kind, self.drop_scopes, self.root))


# ---------------------------------------------------------------- entry

def find(rel: str, text: str, net_pos: frozenset, norm: Callable[[str], str], al: dict) -> list[Hit] | None:
    """Download-exec hits in one Python / JS / TS file; None when it was not analysed (too big, unparseable,
    over the work budget). `net_pos`: UTF-8 byte offsets of the file's outbound network calls."""
    if not net_pos or len(text) > MAX_BYTES:
        return [] if not net_pos else None
    try:
        if rel.endswith(".py"):
            return _py_hits(text, net_pos, norm)
        a = _Js(rel, text, net_pos, norm, al)
        a.propagate()
        a.collect_drops()
        return a.sinks()
    except _Budget:
        return None
    except (SyntaxError, ValueError, RecursionError):
        return None

