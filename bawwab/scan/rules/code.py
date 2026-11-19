"""Static code and manifest rules: AST detectors (Python, JS/TS) plus a regex fallback."""
from __future__ import annotations

import ast
import json
import re
import tomllib
from dataclasses import dataclass
from functools import lru_cache
from posixpath import dirname, join, normpath

from tree_sitter_language_pack import get_parser

from bawwab.scan.files import ExtraText, ScanFile
from bawwab.types import Finding, Severity

PY_EXT = (".py",)
JS_EXT = (".js", ".mjs", ".cjs", ".jsx")
TS_EXT = (".ts", ".mts", ".cts")
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


def _is_code(rel: str) -> bool:
    return not _is_doc(rel) and _base(rel) not in LOCKFILES


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


def _resolve(args: str, names: dict[str, str]) -> str:
    extra = [names[w] for w in set(re.findall(r"[A-Za-z_$][\w$]*", args)) if w in names]
    return " ".join([args, *extra])


def _py_calls(text: str) -> list[Call] | None:
    try:
        tree = ast.parse(text)
    except (SyntaxError, ValueError):
        return None
    names: dict[str, str] = {}
    for n in ast.walk(tree):
        if isinstance(n, ast.Assign) and len(n.targets) == 1 and isinstance(n.targets[0], ast.Name):
            names[n.targets[0].id] = ast.unparse(n.value)
    calls = []
    for n in ast.walk(tree):
        if isinstance(n, ast.Call):
            parts = [ast.unparse(a) for a in n.args] + [f"{k.arg}={ast.unparse(k.value)}" for k in n.keywords]
            calls.append(Call(n.lineno, ast.unparse(n.func), _resolve(", ".join(parts), names)))
    return calls


def _js_calls(text: str, ts: bool) -> list[Call]:
    parser = get_parser("typescript" if ts else "javascript")
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
                found.append((n.start_point[0] + 1, txt(fn), txt(args)))
    return [Call(line, callee, _resolve(args, names)) for line, callee, args in sorted(found)]


@lru_cache(maxsize=512)
def _calls(rel: str, text: str) -> tuple[Call, ...] | None:
    """Parsed calls, or None when the file is not (parseably) Python/JS/TS."""
    if rel.endswith(PY_EXT):
        c = _py_calls(text)
        return tuple(c) if c is not None else None
    if rel.endswith(JS_EXT + TS_EXT):
        return tuple(_js_calls(text, rel.endswith(TS_EXT)))
    return None


# ---------------------------------------------------------------- patterns

EVAL_FUNCS = {"eval", "exec", "Function", "window.eval", "globalThis.eval", "vm.runInNewContext", "vm.runInThisContext", "vm.runInContext"}
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
    r"(?<!\w)\.env\b", r"\.claude\.json", r"\.claude/", r"\.npmrc\b", r"\.netrc\b", r"\.pypirc\b",
    r"security\s+find-generic-password", r"\bkeychain\b",
    r"\.config/(?:google-chrome|chromium|BraveSoftware)", r"Application Support/(?:Google/Chrome|Firefox)",
    r"\.mozilla/firefox", r"\bLogin Data\b",
    r"\bdict\(\s*os\.environ\s*\)", r"\bos\.environ\.(?:copy|items)\(\)", r"\bjson\.dumps\(\s*os\.environ\b",
    r"\bstr\(\s*os\.environ\s*\)",
    r"JSON\.stringify\(\s*process\.env\b", r"Object\.(?:entries|keys|values)\(\s*process\.env\s*\)",
]
CRED_RE = re.compile("|".join(CRED_RES), re.I)
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


def _setup_py_hook(f: ScanFile) -> int | None:
    """Line of an install-time construct in setup.py, or None."""
    try:
        tree = ast.parse(f.text)
    except (SyntaxError, ValueError):
        m = re.search(r"cmdclass\s*=|^\s*(?:os\.system|subprocess\.\w+)\(", f.text, re.M)
        return _line_of(f.text, m.start()) if m else None
    for n in ast.walk(tree):
        if isinstance(n, ast.Call) and any(k.arg == "cmdclass" for k in n.keywords):
            return n.lineno
    # module-level statements only: do not descend into def/class bodies
    stack = [s for s in tree.body if not isinstance(s, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef))]
    while stack:
        n = stack.pop(0)
        if isinstance(n, ast.Call):
            name = ast.unparse(n.func)
            if name == "os.system" or name.startswith("subprocess."):
                return n.lineno
        stack.extend(c for c in ast.iter_child_nodes(n) if not isinstance(c, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef, ast.Lambda)))
    return None


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
            line = _setup_py_hook(f)
            if line:
                hooks.append(_Hook(f, line, ""))
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
            elif REMOTE_RE.search(h.file.text):
                m = REMOTE_RE.search(h.file.text)
                out.append(_finding("install-script.remote", Severity.CRITICAL, h.file, _line_of(h.file.text, m.start())))
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


class CodeRules:
    id = "code"

    def run(self, files: list[ScanFile], extra: list[ExtraText]) -> list[Finding]:
        out: list[Finding] = []
        install = _install_files(files)
        for f in files:
            if not _is_code(f.rel):
                continue
            calls = _calls(f.rel, f.text)
            if calls is None:
                out.extend(self._fallback(f))
            else:
                out.extend(self._ast(f, calls))
            out.extend(self._text(f, f.rel in install))
        return out

    def _ast(self, f: ScanFile, calls) -> list[Finding]:
        out = []
        for c in calls:
            leaf = c.callee.rsplit(".", 1)[-1]
            if c.callee in EVAL_FUNCS:
                if DECODE_RE.search(c.args):
                    out.append(_finding("obfuscation.eval-decoded", Severity.CRITICAL, f, c.line))
                elif FETCH_RE.search(c.args):
                    out.append(_finding("remote-code.eval-fetch", Severity.HIGH, f, c.line))
            elif c.callee in ("import", "require") and URL_IMPORT_RE.match(c.args):
                out.append(_finding("remote-code.eval-fetch", Severity.HIGH, f, c.line))
            elif leaf in SHELL_FUNCS and CURL_RE.search(c.args) and RUN_RE.search(c.args):
                out.append(_finding("remote-code.eval-fetch", Severity.HIGH, f, c.line))
        return out

    def _fallback(self, f: ScanFile) -> list[Finding]:
        out = []
        for rule, sev, rx in (
            ("obfuscation.eval-decoded", Severity.CRITICAL, FB_EVAL_DECODED_RE),
            ("remote-code.eval-fetch", Severity.HIGH, FB_EVAL_FETCH_RE),
        ):
            for m in rx.finditer(f.text):
                out.append(_finding(rule, sev, f, _line_of(f.text, m.start())))
        return out

    def _text(self, f: ScanFile, is_install: bool) -> list[Finding]:
        out = []
        t = f.text
        m = PIPE_SHELL_RE.search(t)
        if m:
            sev = Severity.CRITICAL if is_install else Severity.HIGH
            out.append(_finding("remote-code.pipe-shell", sev, f, _line_of(t, m.start())))
        if not f.rel.endswith(".min.js"):
            m = BLOB_RE.search(t)
            if m:
                line = _line_of(t, m.start())
                out.append(_finding("obfuscation.blob", Severity.MED, f, line, f"{len(m.group(1))}-char encoded literal"))
        cred = CRED_RE.search(t)
        host = EXFIL_HOST_RE.search(t)
        if cred:
            line = _line_of(t, cred.start())
            out.append(_finding("credential-access", Severity.HIGH, f, line))
        if host:
            out.append(_finding("exfil.host", Severity.HIGH, f, _line_of(t, host.start())))
        if cred and (host or NET_RE.search(t)):
            out.append(_finding("exfil.combo", Severity.CRITICAL, f, _line_of(t, cred.start())))
        return out


CODE_RULES = [ManifestRules(), CodeRules()]
