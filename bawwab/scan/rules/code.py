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
            elif isinstance(n, ast.ImportFrom) and n.module:
                for a in n.names:
                    names[a.asname or a.name] = f"{n.module}.{a.name}"
            elif isinstance(n, ast.Import):
                for a in n.names:
                    if a.asname:
                        names[a.asname] = a.name
        calls = []
        for n in ast.walk(tree):
            if isinstance(n, ast.Call):
                parts = [ast.unparse(a) for a in n.args] + [f"{k.arg}={ast.unparse(k.value)}" for k in n.keywords]
                raw = ast.unparse(n.args[0]) if n.args else ""
                first = _resolve(_resolve(raw, names), names) if raw else ""
                calls.append(Call(n.lineno, ast.unparse(n.func), _resolve(", ".join(parts), names), first, raw))
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
        Call(line, callee, _resolve(args, names), _resolve(_resolve(first, names), names) if first else "", first)
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
    for m in re.finditer(r"\bBuffer\.from\s*\(", code):
        args = _top_args(code, m.end() - 1)
        if len(args) >= 2 and not _SAFE_BUFFER_ENC.match(args[1]):
            return True

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
    r"(?<![\w.])\.env\b", r"\.claude\.json",
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
# References into a .claude dir, as "/.claude/<sub>" or path.join(..., ".claude", "<sub>") (R26d, R27 I5).
# ".claude/x", or ".claude" then a string join: path.join(..., '.claude', 'x'), '.claude' + '/x',
# pathlib Path.home() / '.claude' / 'x' (round 3).
CLAUDE_REF_RE = re.compile(r"""\.claude(?:/([\w.-]*)|['"]\s*[,/+]\s*['"]/?([\w.-]+)|(?=['"]))""")
READ_ITER_RE = re.compile(
    r"\b(?:readdir\w*|readFile\w*|createReadStream|opendir\w*|glob\w*|walk\w*|rglob|iterdir|scandir|listdir"
    r"|read_text|read_bytes|open|copy\w*|cp\w*|archive|zip\w*|tar)\s*\("
)
CLAUDE_INSTALL_SUBDIRS = {"", "agents", "skills", "commands", "plugins"}
CLAUDE_CRED_FILE_RE = re.compile(r"^(?:\.credentials\.json|settings[\w.-]*\.json)$")
HOME_RE = re.compile(r"~|homedir|\bHOME\b|expanduser|Path\.home|USERPROFILE|os\.environ\[['\"]HOME", re.I)
WRITE_RE = re.compile(
    r"\b(?:write\w*|mkdir\w*|copy\w*|cp\w*|rename\w*|symlink\w*|appendFile\w*|createWriteStream|write_text|write_bytes)\s*\("
    r"|\bshutil\.(?:copy\w*|move)\b|\bopen\([^)\n]*['\"][wa]b?\+?['\"]"
)
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
    r"|\bgot\(|Invoke-WebRequest|\bnc\s|\b(?:net|tls)\.(?:connect|createConnection)\b"
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
            root = get_parser(_js_lang(rel)).parse(src).root_node
            comments, regexes, stack = [], [], [root]
            while stack:
                n = stack.pop()
                if n.type in ("comment", "html_comment"):
                    comments.append((n.start_byte, n.end_byte))
                elif n.type == "regex":
                    regexes.append((n.start_byte, n.end_byte))
                else:
                    stack.extend(n.children)
            blanked = _blank_bytes(src, comments).decode("utf-8", "replace")

            def char(b: int) -> int:
                return len(src[:b].decode("utf-8", "replace"))

            return blanked, tuple((char(a), char(b)) for a, b in regexes)
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
    except Exception:  # noqa: BLE001 - unparseable: conservative full-line fallback below
        pass
    return _blank(text, [m.span() for m in _LINE_COMMENT_RE.finditer(text)]), ()


def _code_text(rel: str, text: str) -> str:
    return _code_info(rel, text)[0]


# ---------------------------------------------------------------- deny-list context (R26c, R27 I4)

SINK_LEAVES = {
    "open", "readFileSync", "readFile", "read_text", "read_bytes", "createReadStream", "readdirSync", "readdir",
    "listdir", "scandir", "glob", "copyFile", "copyFileSync", "fetch", "request", "get", "post", "put", "urlopen",
    "send", "upload", "connect", "spawn", "spawnSync", "exec", "execSync", "execFile", "execFileSync", "system",
    "Popen", "run", "check_output", "check_call", "call", "expanduser", "join", "resolve",
}
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


_SOURCE_ATTR_RE = re.compile(r"\s*\.\s*(?:source|pattern)\b")


MEMBER_METHODS = {
    "has", "includes", "test", "match", "matchAll", "some", "every", "indexOf", "lastIndexOf", "startsWith",
    "endsWith", "find", "findIndex", "search", "fullmatch", "exec", "add", "push", "append", "extend", "update",
    "set", "delete", "remove", "discard", "get",
}
_MATCH_ARG_BEFORE_RE = re.compile(
    r"(?:\bre\.(?:search|match|fullmatch|findall|finditer)|\.(?:match|matchAll|search|test|replace)|\bfnmatch\w*)\(\s*$"
)


def _flows(t: str, name: str, calls) -> bool:
    """True unless EVERY non-declaration use of the deny-list name is a membership / match use (round 3).

    Allowed: NAME.has/includes/test/some/every/startsWith/... (and building it with add/push),
    NAME.size/.length, `x in NAME` / `any(... for x in NAME)`, or NAME as the pattern of a
    match call. Anything else (destructure, alias, index, spread, argument, iteration,
    .source/.pattern, export) voids the exemption.
    """
    leaf = name.rsplit(".", 1)[-1]
    if not re.fullmatch(r"[A-Za-z_$][\w$]*", leaf):
        return False
    for m in re.finditer(rf"(?<![\w$.]){re.escape(leaf)}(?![\w$])", t):
        after = t[m.end() : m.end() + 120]
        before = t[max(0, m.start() - 120) : m.start()]
        line = _line_text(t, _line_of(t, m.start()))
        if re.match(r"\s*(?::[^=\n;]*)?=(?![=>])", after):
            continue  # its own declaration / assignment target
        mm = re.match(r"\s*\??\.\s*(\w+)\s*(\()?", after)
        if mm and ((mm.group(2) and mm.group(1) in MEMBER_METHODS) or (not mm.group(2) and mm.group(1) in ("size", "length"))):
            continue
        if re.search(r"\bin\s*$", before):
            if not re.search(r"\bfor\b[^\n]*\bin\s*$", before) or re.search(r"\b(?:any|all)\(", line):
                continue
        if _MATCH_ARG_BEFORE_RE.search(before):
            continue
        return True
    return False


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


def _denied(f: ScanFile, t: str, pos: int, regexes, calls) -> bool:
    """True when the match sits in a deny-list / matcher that is not itself used as data.

    Context: a JS regex literal, a regex constructor, a literal or Set/Array assigned to a
    name like BLOCKED / sensitivePaths / ignore, a membership call on one (denyList.add),
    or a predicate like isBlocked(...). Path builders such as path.join are transparent.
    The exemption is void when the value flows into a sink or is iterated, when a regex's
    .source/.pattern is taken, or when the predicate itself does file/network I/O.
    """
    for a, b in regexes:
        if a <= pos < b:
            if _SOURCE_ATTR_RE.match(t, b):
                return False
            name = _decl_name(t, a)
            return not (name and _flows(t, name, calls))
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
                    if _SOURCE_ATTR_RE.match(t, _close_of(t, i)):
                        return False
                    return not (name and _flows(t, name, calls))
                if callee and callee not in CONTAINER_CALLEES:
                    recv, _, leaf = callee.rpartition(".")
                    if leaf in COLLECTION_METHODS:
                        return bool(DENY_WORD_RE.search(recv)) and not _flows(t, recv, calls)
                    if re.match(r"(?:is|should|must)[A-Z_]", leaf) and DENY_WORD_RE.search(leaf):
                        return not _predicate_reaches_io(f, t, leaf)
                    return False
                if name:
                    return bool(DENY_WORD_RE.search(name)) and not _flows(t, name, calls)
        i -= 1
    return False


# ---------------------------------------------------------------- .claude references (R26d, R27 I5)


def _claude_refs(t: str, f: ScanFile | None = None):
    """(pos, "cred" | "install") for each reference into a .claude directory.

    agents/skills/commands/plugins and project-relative paths are install dirs. Credential
    and settings files, other home subpaths (projects/, history.jsonl, todos/...), and a bare
    home ~/.claude that the same function reads or walks (round 3) are credential access.
    """
    for m in CLAUDE_REF_RE.finditer(t):
        sub = m.group(1) if m.group(1) is not None else (m.group(2) or "")
        sub = sub.split("/", 1)[0]
        line_no = _line_of(t, m.start())
        home = bool(HOME_RE.search(_line_text(t, line_no)))
        if CLAUDE_CRED_FILE_RE.match(sub):
            kind = "cred"
        elif sub in CLAUDE_INSTALL_SUBDIRS:
            kind = "install"
            if sub == "" and home and f is not None:
                reads = [_line_of(t, r.start()) for r in READ_ITER_RE.finditer(t)]
                if reads and _same_scope(f, [line_no], reads):
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

STRONG_RULES = ("exfil.combo", "obfuscation.eval-decoded", "remote-code.eval-fetch")


class CodeRules:
    id = "code"

    def run(self, files: list[ScanFile], extra: list[ExtraText]) -> list[Finding]:
        out: list[Finding] = []
        install = _install_files(files)
        refs = _runtime_refs(files)
        exec_data = any(
            _evals_file_content(f) for f in files
            if _is_code(f.rel) and not _is_test(f.rel) and not _is_config_code(f.rel)
        )
        for f in files:
            if _is_doc(f.rel) or _base(f.rel) in LOCKFILES:
                continue
            if _is_data(f.rel) and not (exec_data or f.rel in install or _named(f.rel, refs.run)):
                continue
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
            out.extend(_floor(f, found, self._strong(f)))
        return out

    def _analyse(self, f: ScanFile, is_install: bool) -> list[Finding]:
        calls = _calls(f.rel, f.text)
        found = self._fallback(f) if calls is None else self._ast(f, calls)
        return found + self._text(f, calls, is_install)

    def _strong(self, f: ScanFile) -> list[tuple[str, int]]:
        """Multi-signal behaviour with no context exemption at all (R27 floor)."""
        calls = _calls(f.rel, f.text)
        found = self._fallback(f) if calls is None else self._ast(f, calls)
        out = [(x.rule, x.line or 1) for x in found if x.rule in STRONG_RULES]
        t = _code_text(f.rel, f.text)
        cred_lines = [_line_of(t, m.start()) for m in CRED_RE.finditer(t)]
        cred_lines += [_line_of(t, p) for p, kind in _claude_refs(t, f) if kind == "cred"]
        if cred_lines:
            net_lines = _net_lines(f, t)
            if _same_scope(f, sorted(cred_lines), net_lines):
                out.append(("exfil.combo", min(cred_lines)))
        if not any(r == "exfil.combo" for r, _ in out) and _network_capable(f, t):
            # Backstop (round 3): a real (not deny-listed) credential hit in a file that can reach
            # the network, even when the call itself is hidden behind a wrapper or computed name.
            _, regexes = _code_info(f.rel, f.text)
            real = [p for p, denied in _cred_hits(f, t, regexes, calls) if not denied]
            if real:
                out.append(("exfil.combo", _line_of(t, real[0])))
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
        if not f.rel.endswith(".min.js"):
            m = BLOB_RE.search(raw)
            if m:
                line = _line_of(raw, m.start())
                out.append(_finding("obfuscation.blob", Severity.MED, f, line, f"{len(m.group(1))}-char encoded literal"))
        t, regexes = _code_info(f.rel, raw)  # comments blanked; regex literal spans for context
        dotenv = DOTENV_RE.search(t)
        hits = _cred_hits(f, t, regexes, calls)
        installs = [
            pos for pos, kind in _claude_refs(t, f) if kind == "install" and not _denied(f, t, pos, regexes, calls)
        ]
        real = [p for p, d in hits if not d]
        denied = [p for p, d in hits if d]
        net = _net_calls(f, t)
        net_lines = [ln for ln, _ in net]
        if real:
            out.append(_finding("credential-access", Severity.HIGH, f, _line_of(t, real[0])))
        elif denied:  # deny-list mention: listed, not decisive (R27 I4)
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
        if real:
            cred_lines = [_line_of(t, p) for p in real]
            if _same_scope(f, cred_lines, net_lines):
                out.append(_finding("exfil.combo", Severity.CRITICAL, f, cred_lines[0]))
        return out


_IMPORT_LINE_RE = re.compile(
    r"^\s*(?:import\s|from\s+[\w.]+\s+import\s|export\s+\*\s+from\s)"
    r"|^\s*(?:const|let|var)\s+[\w${}\s,:]+=\s*require\(\s*['\"][^'\"]+['\"]\s*\)[\s;,]*$"
)


# Outbound network CALLS (rounds 2-3). Callees are normalised first: (0, X) and
# X.call/.apply/.bind become X; roots go through import/require/assignment aliases
# (const {get} = require('https'), import * as H, const f = fetch, import x as y,
# s = requests.Session()). A URL string or the word "fetch" in a literal is not a call.
NET_GLOBALS = {"fetch", "XMLHttpRequest", "WebSocket", "EventSource", "urlopen"}
NET_MODULES = {
    "http", "https", "http2", "net", "tls", "dgram", "dns", "undici", "node-fetch", "axios", "got", "ky",
    "superagent", "needle", "request", "ws", "websocket", "requests", "httpx", "aiohttp", "urllib3", "socket",
    "http.client", "urllib.request", "urllib2", "ftplib", "smtplib", "websockets", "pycurl",
}
NOT_NET_LEAVES = {"createServer", "Server", "STATUS_CODES", "HTTPStatus", "METHODS", "Agent", "globalAgent",
                  "parse", "format", "quote", "unquote", "urlencode", "exceptions", "codes"}
SERVER_SIDE = {"createServer", "Server", "STATUS_CODES", "METHODS", "HTTPStatus", "HTTPServer", "ThreadingHTTPServer",
               "BaseHTTPRequestHandler", "SimpleHTTPRequestHandler", "server", "cookies", "cookiejar"}
_MOD = r"""['"](?:node:)?([\w@/.-]+)['"]"""
_JS_ALIAS_RES = (
    (re.compile(r"([\w$]+)\s*=\s*require\(\s*" + _MOD + r"\s*\)"), "mod"),
    (re.compile(r"\{([^{}]*)\}\s*=\s*require\(\s*" + _MOD + r"\s*\)"), "destructure"),
    (re.compile(r"import\s+([\w$]+)\s*(?:,\s*\{[^}]*\})?\s*from\s*" + _MOD), "mod"),
    (re.compile(r"import\s+\*\s+as\s+([\w$]+)\s+from\s*" + _MOD), "mod"),
    (re.compile(r"import\s*(?:[\w$]+\s*,\s*)?\{([^}]*)\}\s*from\s*" + _MOD), "named"),
)
_JS_ASSIGN_RE = re.compile(r"(?:const|let|var)\s+([\w$]+)\s*=\s*(?:await\s+)?(?:new\s+)?([\w$.]+)\s*(?=[(;,\n]|$)", re.M)
_PY_ASSIGN_RE = re.compile(r"^\s*([A-Za-z_]\w*)\s*=\s*(?:await\s+)?([A-Za-z_][\w.]*)\s*(?=\(|$)", re.M)
_PY_IMPORT_AS_RE = re.compile(r"^\s*import\s+([\w.]+)\s+as\s+(\w+)", re.M)
_PY_FROM_IMPORT_RE = re.compile(r"^\s*from\s+([\w.]+)\s+import\s+\(?([^)\n]+)", re.M)


@lru_cache(maxsize=512)
def _aliases(rel: str, text: str) -> dict[str, str]:
    """name -> what it stands for (module path, function path or instance root)."""
    al: dict[str, str] = {}
    if rel.endswith(PY_EXT):
        for mod, name in _PY_IMPORT_AS_RE.findall(text):
            al[name] = mod
        for mod, names in _PY_FROM_IMPORT_RE.findall(text):
            for part in names.split(","):
                bits = part.strip().split()
                if bits and re.fullmatch(r"\w+", bits[0]):
                    al[bits[-1] if len(bits) == 3 and bits[1] == "as" else bits[0]] = f"{mod}.{bits[0]}"
        for name, val in _PY_ASSIGN_RE.findall(text):
            al.setdefault(name, val)
        return al
    for rx, kind in _JS_ALIAS_RES:
        for m in rx.finditer(text):
            target, mod = m.group(1), m.group(2)
            if kind == "mod":
                al[target] = mod
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
    for name, val in _JS_ASSIGN_RE.findall(text):
        al.setdefault(name, val)
    return al


_ZERO_COMMA_RE = re.compile(r"^\(\s*0\s*,\s*([\w$.]+)\s*\)$")
_GETATTR_RE = re.compile(r"""^getattr\(\s*([\w.]+)\s*,\s*['"](\w+)['"]\s*\)$""")


def _norm_callee(callee: str, al: dict[str, str]) -> str:
    c = callee.strip()
    for _ in range(4):
        prev = c
        m = _ZERO_COMMA_RE.match(c) or _GETATTR_RE.match(c)
        if m:
            c = m.group(1) + ("." + m.group(2) if m.lastindex == 2 else "")
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
    if callee in NET_GLOBALS:
        return True
    parts = callee.split(".")
    if parts[-1] in NOT_NET_LEAVES or SERVER_SIDE & set(parts):
        return False  # a local server (and calls on it) is not an outbound call
    return parts[0] in NET_MODULES or ".".join(parts[:2]) in NET_MODULES


# Loopback is exempt only for a single plain literal whose host ends right there (round 3).
_LOOPBACK_LIT_RE = re.compile(
    r"""^\s*(['"`])(?:https?|wss?)://(?:localhost|127(?:\.\d{1,3}){3}|0\.0\.0\.0|\[::1\])(?=[:/?#]|\1)(?:(?!\1)[^\\\s\x00-\x1f$])*\1\s*$""",
    re.I,
)


def _loopback_only(first_raw: str) -> bool:
    return bool(_LOOPBACK_LIT_RE.match(first_raw)) and "@" not in first_raw


def _net_calls(f: ScanFile, t: str) -> list[tuple[int, str]]:
    """(line, argument text) of outbound network calls.

    Parsed files: real call nodes to network APIs after alias normalisation (or any call
    carrying an exfil host), except a call whose URL argument is one plain loopback literal.
    Unparsed files (shell...): the regex fallback, minus bare import lines.
    """
    calls = _calls(f.rel, f.text)
    if calls is not None:
        al = _aliases(f.rel, f.text)
        out = []
        for c in calls:
            callee = _norm_callee(c.callee, al)
            leaf = callee.rsplit(".", 1)[-1]
            is_net = _is_net_callee(callee) or (leaf in SHELL_FUNCS and CURL_RE.search(c.args))
            if (is_net and not _loopback_only(c.first_raw)) or EXFIL_HOST_RE.search(c.args):
                out.append((c.line, c.args))
        return out
    out = []
    for rx in (NET_RE, EXFIL_HOST_RE):
        for m in rx.finditer(t):
            ln = _line_of(t, m.start())
            line = _line_text(t, ln)
            if not _IMPORT_LINE_RE.search(line):
                out.append((ln, line))
    return out


def _net_lines(f: ScanFile, t: str) -> list[int]:
    return [ln for ln, _ in _net_calls(f, t)]


# Floor backstop (round 3): a network-capable module imported, or code loaded/looked up by
# computed name, anywhere in the file.
NET_IMPORT_RE = re.compile(
    r"""(?:require\(\s*|import\s*\(\s*|from\s+|import\s+)['"]?(?:node:)?"""
    r"""(?:https?|http2|net|tls|dgram|undici|node-fetch|axios|got|ky|requests|httpx|aiohttp"""
    r"""|urllib(?!\.parse|\.error)|socket|http\.client|websockets?|ws)(?![\w.-]*\.parse)['"\s;,)]""",
    re.M,
)
COMPUTED_LOAD_RE = re.compile(
    r"""\brequire\(\s*(?!['"`][^'"`$]*['"`]\s*\))|\bimport\(\s*(?!['"`][^'"`$]*['"`]\s*\))"""
    r"""|\b(?:globalThis|window|global|self)\[\s*(?!['"][^'"]*['"]\s*\])"""
    r"""|\bgetattr\(\s*(?:__builtins__|builtins)\b|\b__import__\(|\bimportlib\.import_module\(\s*(?!['"][^'"]*['"]\s*\))"""
)


_INLINE_NET_RE = re.compile(
    r"""\b(?:require|import)\(\s*['"](?:node:)?([\w@/.-]+)['"]\s*\)\s*(?:\.\s*(\w+))?"""
)
_BINDING_LINE_RE = re.compile(r"""\brequire\(\s*['"]|^\s*(?:import|from)\b""", re.M)


def _net_root(value: str) -> bool:
    parts = value.split(".")
    return not (SERVER_SIDE & set(parts)) and (parts[0] in NET_MODULES or ".".join(parts[:2]) in NET_MODULES)


def _network_capable(f: ScanFile, t: str) -> bool:
    """The file can reach the network somewhere: a network-capable module bound and USED for
    something other than running a local server, or code loaded / looked up by computed name."""
    if COMPUTED_LOAD_RE.search(t):
        return True
    if not NET_IMPORT_RE.search(t):
        return False
    for m in _INLINE_NET_RE.finditer(t):
        line = _line_text(t, _line_of(t, m.start()))
        bound = re.search(r"[\w$}]\s*=\s*(?:await\s+)?(?:require|import)\(", line)
        if _net_root(m.group(1)) and not bound and (m.group(2) or "") not in SERVER_SIDE:
            return True  # require('https').request(...) used inline
    al = _aliases(f.rel, f.text)
    names = {n for n, v in al.items() if _net_root(v.removeprefix("new ").split("(")[0])}
    if f.rel.endswith(PY_EXT):
        names |= {m for m in NET_MODULES if re.fullmatch(r"\w+", m)}
        if re.search(r"\burllib\.request\.\w+\s*\(", t):
            return True
    for n in names:
        for m in re.finditer(rf"(?<![\w$.'\"/]){re.escape(n)}(?![\w$])", t):
            line = _line_text(t, _line_of(t, m.start()))
            if _BINDING_LINE_RE.search(line) and not re.search(rf"{re.escape(n)}\s*[.(\[]", line.split("=", 1)[-1] if "=" in line else ""):
                continue  # the binding itself
            after = t[m.end() : m.end() + 60]
            use = re.match(r"\s*(?:\.\s*(\w+)|\(|\[)", after)
            if use and (use.group(1) or "") not in SERVER_SIDE:
                return True
    return False


def _cred_hits(f: ScanFile, t: str, regexes, calls) -> list[tuple[int, bool]]:
    """Sorted (pos, denied) for credential paths and .claude credential references."""
    hits = []
    for m in CRED_RE.finditer(t):
        if not DOTENV_RE.search(_line_text(t, _line_of(t, m.start()))):
            hits.append((m.start(), _denied(f, t, m.start(), regexes, calls)))
    for pos, kind in _claude_refs(t, f):
        if kind == "cred":
            hits.append((pos, _denied(f, t, pos, regexes, calls)))
    return sorted(hits)


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
