"""Static code and manifest rules: AST detectors (Python, JS/TS) plus a regex fallback."""
from __future__ import annotations

import ast
import io
import json
import re
import tokenize
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from posixpath import dirname, join, normpath

from tree_sitter_language_pack import get_parser

from bawwab.scan.files import ExtraText, ScanFile
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


def _is_doc(rel: str) -> bool:
    return rel.endswith(DOC_EXT)


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


def _is_data_or_config(rel: str) -> bool:
    base = _base(rel)
    if rel.endswith(DATA_EXT) or base in IGNORE_FILES or CONFIG_RE.match(base):
        return True
    return rel.endswith(".json") and bool(DATA_DIR_RE.search(rel))


def _is_test(rel: str) -> bool:
    return bool(TEST_PATH_RE.search(rel))


def _is_code(rel: str) -> bool:
    return not _is_doc(rel) and _base(rel) not in LOCKFILES and not _is_data_or_config(rel)


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


def _resolve(args: str, names: dict[str, str]) -> str:
    extra = [names[w] for w in set(re.findall(r"[A-Za-z_$][\w$]*", args)) if w in names]
    return " ".join([args, *extra])


def _py_calls(text: str) -> list[Call] | None:
    try:
        tree = ast.parse(text)
        names: dict[str, str] = {}
        for n in ast.walk(tree):
            if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
                names[n.targets[0].id] = ast.unparse(n.value)
        calls = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                parts = [ast.unparse(a) for a in n.args] + [f"{k.arg}={ast.unparse(k.value)}" for k in n.keywords]
                first = _resolve(ast.unparse(n.args[0]), names) if n.args else ""
                calls.append(Call(n.lineno, ast.unparse(n.func), _resolve(", ".join(parts), names), first))
        return calls
    except (SyntaxError, ValueError, RecursionError, MemoryError):
        return None  # hostile or unparseable: caller falls back to regex


def _js_lang(rel: str) -> str:
    if rel.endswith(".tsx"):
        return "tsx"
    return "typescript" if rel.endswith(TS_EXT) else "javascript"


def _js_calls(text: str, lang: str) -> list[Call]:
    parser = get_parser(lang)
    src = text.encode()
    root = parser.parse(src).root_node

    def txt(n) -> str:
        return src[n.start_byte : n.end_byte].decode("utf-8", "replace")

    names: dict[str, str] = {}
    found = []
    stack = [root]
    while stack:
        n = stack.pop()
        stack.extend(n.children)
        if n.type == "variable_declarator":
            name, val = n.child_by_field_name("name"), n.child_by_field_name("value")
            if name is not None and val is not None and name.type == "identifier":
                names[txt(name)] = txt(val)
        elif n.type in ("call_expression", "new_expression"):
            fn = n.child_by_field_name("function" if n.type == "call_expression" else "constructor")
            args = n.child_by_field_name("arguments")
            if fn is not None and args is not None:
                named = [c for c in args.named_children if c.type != "comment"]
                found.append((n.start_point[0] + 1, txt(fn), txt(args), txt(named[0]) if named else ""))
    return [
        Call(line, callee, _resolve(args, names), _resolve(first, names) if first else "")
        for line, callee, args, first in sorted(found)
    ]


@lru_cache(maxsize=512)
def _calls(rel: str, text: str) -> tuple[Call, ...] | None:
    """Parsed calls, or None when the file is not (parseably) Python/JS/TS."""
    try:
        if rel.endswith(PY_EXT):
            c = _py_calls(text)
            return tuple(c) if c is not None else None
        if rel.endswith(JS_EXT + TS_EXT):
            return tuple(_js_calls(text, _js_lang(rel)))
    except Exception:  # noqa: BLE001 - never let a hostile file crash the scan
        return None
    return None


# ---------------------------------------------------------------- patterns

EVAL_FUNCS = {"eval", "exec", "Function", "window.eval", "globalThis.eval", "vm.runInNewContext", "vm.runInThisContext", "vm.runInContext"}
ALL_ARGS_EVAL = {"Function"}  # new Function(a, b, body): the body is the last argument
DECODE_RE = re.compile(
    r"\b(b64decode|a2b_base64|unhexlify|fromhex|rot13|rot_13|atob|decodestring|codecs\.decode)\b"
    r"|Buffer\.from\([^)]*['\"`](?:base64|hex)['\"`]|\.decode\(\s*['\"](?:base64|hex|rot13)",
    re.I,
)
FETCH_RE = re.compile(
    r"\b(fetch|requests\.\w+|urlopen|urllib\.\w+|httpx\.\w+|axios|XMLHttpRequest|http\.get|https\.get|curl|wget)\b"
)
SHELL_FUNCS = {"run", "call", "check_output", "check_call", "Popen", "system", "popen", "exec", "execSync", "spawn", "spawnSync", "execFile"}
CURL_RE = re.compile(r"\b(curl|wget)\b")
RUN_RE = re.compile(r"\b(sh|bash|zsh|chmod)\b")
URL_IMPORT_RE = re.compile(r"^\(?\s*['\"`]https?://")

PIPE_SHELL_RE = re.compile(r"\b(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z)?sh\b")
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

CRED_RES = [
    r"\.ssh/", r"\bid_rsa\b", r"\.aws/credentials",
    r"(?<![\w.])\.env\b", r"\.claude\.json", r"\.claude/\.credentials\.json", r"\.claude/settings[\w.-]*\.json",
    r"\.npmrc\b", r"\.netrc\b", r"\.pypirc\b",
    r"security\s+find-generic-password", r"\bkeychain\b",
    r"\.config/(?:google-chrome|chromium|BraveSoftware)", r"Application Support/(?:Google/Chrome|Firefox)",
    r"\.mozilla/firefox", r"\bLogin Data\b",
    r"\bdict\(\s*os\.environ\s*\)", r"\bos\.environ\.(?:copy|items)\(\)", r"\bjson\.dumps\(\s*os\.environ\b",
    r"\bstr\(\s*os\.environ\s*\)",
    r"JSON\.stringify\(\s*process\.env\b", r"Object\.(?:entries|keys|values)\(\s*process\.env\s*\)",
]
DOTENV_RE = re.compile(
    r"\b(?:load_dotenv|dotenv_values|find_dotenv)\b|require\(\s*['\"]dotenv['\"]\s*\)"
    r"|import\s+['\"]dotenv(?:/config)?['\"]|\bfrom\s+['\"]dotenv['\"]|^\s*(?:import|from)\s+dotenv\b",
    re.M,
)
CRED_RE = re.compile("|".join(CRED_RES), re.I)
# ~/.claude/{agents,skills,commands,plugins} or a project .claude/ dir: install-dir access, not credentials (R26d).
INSTALL_DIR_RE = re.compile(r"\.claude/")
# Names that mark a list/set/regex as a deny-list or matcher (R26c).
DENY_WORD_RE = re.compile(r"deny|block|forbid|sensitive|protect|refus|exclu|ignor|reject|blacklist|disallow", re.I)
REGEX_CALL_RE = re.compile(r"^(?:re\.(?:compile|search|match|fullmatch|findall|finditer|sub|split)|RegExp)$")
CONTAINER_CALLEES = {"Set", "Array", "Array.of", "Map", "set", "frozenset", "list", "tuple"}
PATH_CALLEES = {"path.join", "path.resolve", "path.posix.join", "os.path.join", "os.path.expanduser", "Path", "String", "str"}
COLLECTION_METHODS = {"add", "has", "includes", "push", "test", "match", "indexOf", "some", "append", "extend", "update", "set"}
_DECL_TAIL_RE = re.compile(r"""(?:['"]?([\w$.]+)['"]?\s*[:=]\s*)?(?:new\s+)?([\w$.]*)\s*\(?\s*$""")
EXFIL_HOST_RE = re.compile(
    r"webhook\.site|requestbin|pipedream|ngrok|pastebin|transfer\.sh"
    r"|discord(?:app)?\.com/api/webhooks|api\.telegram\.org/bot"
    r"|https?://(?!127\.|0\.0\.0\.0)\d{1,3}(?:\.\d{1,3}){3}",
    re.I,
)
NET_RE = re.compile(
    r"\b(?:fetch|axios|XMLHttpRequest|urlopen|urllib|httpx|requests\.\w+|http\.request|https\.request|http\.get|https\.get|curl|wget|socket)\b"
    r"|\bgot\(|Invoke-WebRequest|\bnc\s"
)
BLOB_RE = re.compile(r"""["'`]((?:[A-Za-z0-9+/]{200,}={0,2})|(?:[0-9a-fA-F]{200,}))["'`]""")
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
        tree = ast.parse(f.text)
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
    except (SyntaxError, ValueError, RecursionError, MemoryError):
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


# ---------------------------------------------------------------- code rules


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


_LINE_COMMENT_RE = re.compile(r"^[ \t]*(?:#|//).*$", re.M)


@lru_cache(maxsize=512)
def _code_text(rel: str, text: str) -> str:
    """The text with comments (and JS regex literals) blanked out (R26a/c)."""
    try:
        if rel.endswith(JS_EXT + TS_EXT):
            src = text.encode()
            root = get_parser(_js_lang(rel)).parse(src).root_node
            spans, stack = [], [root]
            while stack:
                n = stack.pop()
                if n.type in ("comment", "html_comment", "regex"):
                    spans.append((n.start_byte, n.end_byte))
                else:
                    stack.extend(n.children)
            return _blank_bytes(src, spans).decode("utf-8", "replace")
        if rel.endswith(PY_EXT):
            starts = [0]
            for line in text.splitlines(keepends=True):
                starts.append(starts[-1] + len(line))
            spans = []
            for tok in tokenize.generate_tokens(io.StringIO(text).readline):
                if tok.type == tokenize.COMMENT:
                    (r1, c1), (r2, c2) = tok.start, tok.end
                    spans.append((starts[r1 - 1] + c1, starts[r2 - 1] + c2))
            return _blank(text, spans)
    except Exception:  # noqa: BLE001 - unparseable: conservative full-line fallback below
        pass
    return _blank(text, [m.span() for m in _LINE_COMMENT_RE.finditer(text)])


def _blank_bytes(src: bytes, spans: list[tuple[int, int]]) -> bytes:
    buf = bytearray(src)
    for a, b in spans:
        for i in range(a, b):
            if buf[i] != 0x0A:
                buf[i] = 0x20
    return bytes(buf)


def _deny_context(t: str, pos: int) -> bool:
    """True when the match sits in a deny-list / matcher literal (R26c).

    Walks out through up to three enclosing brackets (path builders such as
    path.join are transparent); the first one with a name decides. Deny-list:
    a regex constructor, a literal or Set/Array assigned to a name like BLOCKED /
    sensitivePaths / ignore, or a membership call on one (denyList.add(...)),
    or a predicate like isBlocked(...). Any other call (fs.readFileSync(...)) is
    real use, even inside an object key named "sensitive".
    """
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
                line_start = t.rfind("\n", 0, i) + 1
                prefix = t[line_start:i] + ("(" if ch == "(" else "")
                m = _DECL_TAIL_RE.search(prefix)
                name, callee = (m.group(1) or "", m.group(2) or "") if m else ("", "")
                if callee in PATH_CALLEES:
                    i -= 1
                    continue
                if REGEX_CALL_RE.match(callee):
                    return True
                if callee and callee not in CONTAINER_CALLEES:
                    recv, _, leaf = callee.rpartition(".")
                    if leaf in COLLECTION_METHODS:
                        return bool(DENY_WORD_RE.search(recv))
                    return bool(re.match(r"(?:is|should|must)[A-Z_]", leaf) and DENY_WORD_RE.search(leaf))
                if name:
                    return bool(DENY_WORD_RE.search(name))
        i -= 1
    return False


_PATH_TOKEN_RE = re.compile(r"[\w.$@{}/-]*/[\w.$@{}/-]*")
_PY_IMPORT_RE = re.compile(r"^\s*(?:from|import)\s+([\w.]+)", re.M)
_STRIP_EXT_RE = re.compile(r"\.(?:js|mjs|cjs|jsx|ts|mts|cts|tsx|py)$")


def _runtime_refs(files: list[ScanFile]) -> set[str]:
    """Path stems (no extension) named by non-test files: a test-path file named here is not test-only."""
    refs: set[str] = set()
    for f in files:
        if _is_test(f.rel) or _is_doc(f.rel):
            continue
        base_dir = dirname(f.rel)
        for tok in _PATH_TOKEN_RE.findall(f.text):
            cands = [tok.rsplit("}/", 1)[-1], normpath(join(base_dir, tok))]
            for c in cands:
                c = _STRIP_EXT_RE.sub("", c.removeprefix("./")).rstrip("/")
                refs.add(c)
        if f.rel.endswith(PY_EXT):
            for mod in _PY_IMPORT_RE.findall(f.text):
                refs.add(mod.lstrip(".").replace(".", "/"))
    return refs


def _test_only(rel: str, install: set[str], refs: set[str]) -> bool:
    if not _is_test(rel) or rel in install:
        return False
    stem = _STRIP_EXT_RE.sub("", rel)
    return stem not in refs and not (stem.endswith("/index") and stem[: -len("/index")] in refs)


class CodeRules:
    id = "code"

    def run(self, files: list[ScanFile], extra: list[ExtraText]) -> list[Finding]:
        out: list[Finding] = []
        install = _install_files(files)
        refs = _runtime_refs(files) if any(_is_test(f.rel) for f in files) else set()
        for f in files:
            if not _is_code(f.rel):
                continue
            found: list[Finding] = []
            calls = _calls(f.rel, f.text)
            if calls is None:
                found.extend(self._fallback(f))
            else:
                found.extend(self._ast(f, calls))
            found.extend(self._text(f, f.rel in install))
            if _test_only(f.rel, install, refs):
                # Test code: listed, never decisive, never an exfil combo (R26b).
                found = [
                    Finding(x.rule, Severity.LOW, x.source, x.evidence, file=x.file, line=x.line)
                    for x in found if x.rule != "exfil.combo"
                ]
            out.extend(found)
        return out

    def _ast(self, f: ScanFile, calls) -> list[Finding]:
        out = []
        for c in calls:
            leaf = c.callee.rsplit(".", 1)[-1]
            if c.callee in EVAL_FUNCS:
                code = c.args if c.callee in ALL_ARGS_EVAL else c.first
                if DECODE_RE.search(code):
                    out.append(_finding("obfuscation.eval-decoded", Severity.CRITICAL, f, c.line))
                elif FETCH_RE.search(code):
                    out.append(_finding("remote-code.eval-fetch", Severity.HIGH, f, c.line))
            elif c.callee in ("import", "require") and URL_IMPORT_RE.match(c.args):
                out.append(_finding("remote-code.eval-fetch", Severity.HIGH, f, c.line))
            elif leaf in SHELL_FUNCS and CURL_RE.search(c.args) and RUN_RE.search(c.args):
                out.append(_finding("remote-code.eval-fetch", Severity.HIGH, f, c.line))
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

    def _text(self, f: ScanFile, is_install: bool) -> list[Finding]:
        out = []
        raw = f.text
        m = PIPE_SHELL_RE.search(raw)
        if m:
            sev = Severity.CRITICAL if is_install else Severity.HIGH
            out.append(_finding("remote-code.pipe-shell", sev, f, _line_of(raw, m.start())))
        if not f.rel.endswith(".min.js"):
            m = BLOB_RE.search(raw)
            if m:
                line = _line_of(raw, m.start())
                out.append(_finding("obfuscation.blob", Severity.MED, f, line, f"{len(m.group(1))}-char encoded literal"))
        t = _code_text(f.rel, raw)  # comments and regex literals blanked
        dotenv = DOTENV_RE.search(t)
        creds = [
            m for m in CRED_RE.finditer(t)
            if not DOTENV_RE.search(_line_text(t, _line_of(t, m.start()))) and not _deny_context(t, m.start())
        ]
        cred_starts = {m.start() for m in CRED_RE.finditer(t)}
        install_dir = [
            m for m in INSTALL_DIR_RE.finditer(t)
            if m.start() not in cred_starts and not _deny_context(t, m.start())
        ]
        host = EXFIL_HOST_RE.search(t)
        if creds:
            out.append(_finding("credential-access", Severity.HIGH, f, _line_of(t, creds[0].start())))
        elif dotenv:
            out.append(_finding("credential-access", Severity.LOW, f, _line_of(t, dotenv.start())))
        if install_dir:
            out.append(_finding("install-dir-access", Severity.LOW, f, _line_of(t, install_dir[0].start())))
        if host:
            out.append(_finding("exfil.host", Severity.HIGH, f, _line_of(t, host.start())))
        if creds:
            cred_lines = [_line_of(t, m.start()) for m in creds]
            net_lines = [_line_of(t, m.start()) for m in NET_RE.finditer(t)]
            net_lines += [_line_of(t, m.start()) for m in EXFIL_HOST_RE.finditer(t)]
            if _same_scope(f, cred_lines, net_lines):
                out.append(_finding("exfil.combo", Severity.CRITICAL, f, cred_lines[0]))
        return out


COMBO_WINDOW = 20


def _function_spans(rel: str, text: str) -> list[tuple[int, int]] | None:
    """Line spans of outermost functions, or None when the file cannot be parsed."""
    try:
        if rel.endswith(PY_EXT):
            tree = ast.parse(text)
            spans = [
                (n.lineno, n.end_lineno or n.lineno)
                for n in ast.walk(tree)
                if isinstance(n, (ast.FunctionDef, ast.AsyncFunctionDef))
            ]
        elif rel.endswith(JS_EXT + TS_EXT):
            root = get_parser(_js_lang(rel)).parse(text.encode()).root_node
            kinds = {
                "function_declaration", "function_expression", "function", "arrow_function",
                "method_definition", "generator_function", "generator_function_declaration",
            }
            spans, stack = [], [root]
            while stack:
                n = stack.pop()
                if n.type in kinds:
                    spans.append((n.start_point[0] + 1, n.end_point[0] + 1))
                else:  # outermost only: nested callbacks belong to their enclosing function
                    stack.extend(n.children)
        else:
            return None
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


CODE_RULES = [ManifestRules(), CodeRules()]
