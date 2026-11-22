"""Reachability: which files of a target run on the user's machine or are read by the agent (FP plan, step 1).

A finding in a file that nothing runs and that Claude never reads (tests, fixtures, examples, benchmarks, CI
workflows, unreferenced dev scripts, docs) is listed as LOW: shown, never counted toward the verdict.

Runtime files are found from seeds, then transitively:
* entry points: package.json main / module / bin / exports / browser / imports (index.js when none is declared),
  the start/build/install scripts and the files they name, workspace packages; Python packages (explicit
  configuration, else setuptools' own auto-discovery rules), console scripts and root modules;
* install time: package.json pre/post/install and prepare, setup.py, pyproject build hooks;
* plugins: the manifest, hooks/hooks.json and the files hook commands name, commands/, agents/, skills/,
  output styles, .mcp.json and the command/args of each bundled server;
* model-facing files: every SKILL.md (and its sibling README.md), commands/*.md and agents/*.md, a repo's
  .claude/ folder, CLAUDE.md and AGENTS.md, and what they name by path;
* transitively: what runtime files import, require, source or name by path (a string literal or a command token
  that resolves to a file or folder of the target; relative imports and local packages resolve inside it).

Fail closed: a target with no manifest the rules understand (no package.json with an entry, Python package,
plugin, marketplace or root SKILL.md) is all runtime; a declared entry that cannot be found (a build output that
is not in a git checkout and cannot be mapped back to its source) makes its whole package runtime; a runtime code
file that was not loaded (too large, unreadable) makes its folder runtime, since its imports are unknown; code
in languages whose imports are not traced (Go, Rust, Ruby...) is always runtime.

Residual (accepted, see docs/superpowers/plans/2026-11-22-false-positives.md): a payload loaded through a computed
path. It is demoted, not dropped; the judge and the reviewer still see it.
"""
from __future__ import annotations

import fnmatch
import json
import os
import posixpath
import re
import tomllib
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path

from bawwab.types import Finding, Severity

__all__ = ["DEMOTABLE_RULES", "Reach", "classify", "demote_unreachable"]

# Rules about what a file's own code or text does: in a file that never runs and is never read, they are listed
# only. Every other rule is about the package itself (identity, install hooks in the manifest, plugin hooks,
# bundled servers, fetch / judge / sandbox / gate state, trust diffs) and is never demoted; an unknown rule is
# never demoted either (fail closed).
DEMOTABLE_RULES = frozenset({
    "credential-access", "exfil.combo", "exfil.host", "remote-code.pipe-shell", "remote-code.eval-fetch",
    "obfuscation.eval-decoded", "obfuscation.blob", "install-dir-access", "install.custom-index",
    "injection.override", "injection.covert-action", "injection.hidden-unicode", "injection.html-comment",
    "tool-shadowing", "files.truncated", "files.analysis-degraded",
})
NOTE = " [listed, not counted: nothing that runs or that the agent reads reaches this file]"

MAX_FILES = 200_000
MAX_TOKENS_PER_FILE = 50_000
MAX_PARSE_BYTES = 4_000_000

JS_EXTS = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".tsx", ".mts", ".cts")
PY_EXTS = (".py", ".pyw")
SHELL_EXTS = (".sh", ".bash", ".zsh", ".ksh", ".fish", ".command", ".csh", ".tcsh", ".ps1", ".bat", ".cmd")
TRACED_CODE = JS_EXTS + PY_EXTS + SHELL_EXTS
# Code whose imports are not traced here: never demoted.
UNTRACED_CODE = (
    ".go", ".rs", ".rb", ".php", ".pl", ".pm", ".java", ".kt", ".kts", ".scala", ".cs", ".fs", ".swift", ".c",
    ".cc", ".cpp", ".h", ".hpp", ".m", ".lua", ".r", ".jl", ".ex", ".exs", ".erl", ".clj", ".dart", ".zig",
    ".nim", ".vbs", ".psm1", ".groovy", ".gradle", ".wasm", ".node", ".so", ".dylib", ".dll", ".exe",
)
_RESOLVE_EXTS = ("", ".js", ".mjs", ".cjs", ".ts", ".tsx", ".mts", ".cts", ".jsx", ".json", ".node")
_SRC_EXTS = (".ts", ".tsx", ".mts", ".cts", ".js", ".jsx", ".mjs", ".cjs")
_OUT_DIRS = ("dist", "build", "lib", "out", "esm", "cjs", "bin", ".output", "output", "bundle", "release")
_SRC_DIRS = ("src", "", "source", "lib", "app")
VENDORED_DIRS = ("node_modules", "site-packages", ".venv", "vendor")

# package.json scripts that run on the user's machine: install lifecycle, start/serve (how a cloned server
# runs) and build (a cloned TypeScript server is built before it runs). Tests, lint, release etc. do not.
_RUN_SCRIPT_RE = re.compile(
    r"^(?:pre|post)?(?:install|prepare|prepack|start|build|serve|server|mcp|dev|bundle|compile|setup|bootstrap|"
    r"stdio|http|sse|run|main|cli)(?:[:._-].*)?$"
)
_SCRIPT_CALL_RE = re.compile(
    r"\b(?:npm|pnpm|yarn|bun)\s+(?:run(?:-script)?\s+)?([\w:.-]+)|\b(?:run-s|run-p|npm-run-all)\s+([^;&|]+)"
    r"|npm:([\w:.-]+)"
)
# setuptools' flat-layout auto-discovery leaves these out of a wheel (setuptools.discovery.FlatLayout*Finder).
_SETUPTOOLS_PKG_EXCLUDE = (
    "ci", "bin", "debian", "doc", "docs", "documentation", "manpages", "news", "newsfragments", "changelog",
    "test", "tests", "unit_test", "unit_tests", "example", "examples", "scripts", "tools", "util", "utils",
    "python", "build", "dist", "venv", "env", "requirements", "tasks", "fabfile", "site_scons", "benchmark",
    "benchmarks", "exercise", "exercises", "htmlcov",
)
_SETUPTOOLS_MOD_EXCLUDE_RE = re.compile(
    r"^(?:setup|conftest|test|tests|example|examples|build|toolchain|noxfile|pavement|dodo|tasks|fabfile|"
    r"[Ss][Cc]onstruct|conanfile|manage|benchmark|benchmarks|exercise|exercises|test_.*|.*_test|[._].*)$"
)
_LEAF_SEEDS = {"Makefile", "makefile", "GNUmakefile", "Dockerfile", "justfile", "Justfile", "Containerfile",
               "docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml", "requirements.txt"}
_BUILD_CONFIG_RE = re.compile(
    r"^(?:tsup|rollup|webpack|vite|esbuild|rspack|rolldown|tsdown|unbuild|build|bun\.build|ncc)\.config\.[\w.]+$"
    r"|^(?:build|esbuild|bundle)\.(?:[cm]?js|ts)$"
)

# A path-like token: with a folder separator, or a file name with an extension. ${CLAUDE_PLUGIN_ROOT}/ and
# similar prefixes are kept so the token resolves against the plugin root.
_EXTS_RX = r"(?:[cm]?[jt]sx?|py|sh|bash|zsh|ps1|bat|cmd|json|jsonc|md|mdx|toml|ya?ml|txt|rb|pl|php)"
_SLASH_TOKEN_RE = re.compile(r"[\w@.$+{}-]*+/[\w@.$+{}/-]*+")
_EXT_TOKEN_RE = re.compile(r"(?<![\w@.+/-])[\w@+-]++(?:\.[\w@+-]++)*?\." + _EXTS_RX + r"\b")
_JS_SPEC_RE = re.compile(
    r"""(?:\bfrom|\bimport|\brequire(?:\.resolve)?\s*\(|\bimport\s*\(|\bWorker\s*\(|\bURL\s*\(|\bfork\s*\()"""
    r"""\s*(['"`])([^'"`\n]{1,300})\1"""
)
_JS_TEMPLATE_DIR_RE = re.compile(r"""(?:\brequire|\bimport)\s*\(\s*`(\.{1,2}/[^`$\n]{0,200}/)\$\{""")
_PY_FROM_RE = re.compile(r"^\s*from\s+(\.*[\w.]*)\s+import\s+\(?([\w\s,*]+)", re.M)
_PY_IMPORT_RE = re.compile(r"^\s*import\s+([\w.]+(?:\s*,\s*[\w.]+)*)", re.M)
_DOC_EXTS = (".md", ".mdx", ".markdown", ".txt", ".rst")
# Manifests whose strings name what runs (every path-like string in them is followed).
_RUN_MANIFESTS = {"plugin.json", "hooks.json", ".mcp.json", "mcp.json", "marketplace.json", "settings.json",
                  "settings.local.json", ".lsp.json", "gemini-extension.json", "qwen-extension.json"}
_PY_DYN_RE = re.compile(r"""(?:import_module|__import__|run_module)\s*\(\s*f?['"]([\w.]+)['"]""")


@dataclass
class Reach:
    runtime: frozenset[str] | None  # None: everything is runtime (unclassified, fail closed)
    reason: str = ""
    roots: tuple[str, ...] = ()  # the code roots classified
    files: frozenset[str] = frozenset()  # every file of the target
    why: dict[str, str] = field(default_factory=dict)  # runtime file -> the file that reached it ("" = a seed)

    def is_runtime(self, rel: str | None) -> bool:
        """False only for a file of this target that nothing reaches. A label that is not a file (a tool name,
        a server prefix) is runtime."""
        if self.runtime is None or not rel or rel not in self.files or rel in self.runtime:
            return True
        return rel.lower().endswith(UNTRACED_CODE)


ALL_RUNTIME = Reach(None, "unclassified")


def demote_unreachable(findings: Iterable[Finding], reach: Reach) -> list[Finding]:
    """Demotable static findings in a non-runtime file become LOW (the evidence says why).

    CRITICAL is never demoted. It is multi-signal behaviour (a credential read sent out in one function, eval of
    decoded or fetched code), which R27 already keeps whatever a file's path or context; reachability cannot rule
    out a computed path that loads such a file; and the recall gate needs it: two DataDog samples
    (pypi/gequests, pypi/definitely-not-requests) are MALICIOUS only through a CRITICAL in sdist metadata
    (PKG-INFO), and dropping them a level is a recall regression the gate does not allow."""
    out = []
    for x in findings:
        if (x.source == "static" and x.rule in DEMOTABLE_RULES and Severity.LOW < x.severity < Severity.CRITICAL
                and not reach.is_runtime(x.file)):
            out.append(Finding(x.rule, Severity.LOW, x.source, x.evidence + NOTE, file=x.file, line=x.line))
        else:
            out.append(x)
    return out


# ------------------------------------------------------------------ helpers


def _norm(base: str, tok: str) -> str | None:
    p = posixpath.normpath(posixpath.join(base, tok)) if base else posixpath.normpath(tok)
    if p in (".", "") or p.startswith("../") or p == ".." or p.startswith("/"):
        return None
    return p


def _strings(o) -> list[str]:
    if isinstance(o, str):
        return [o]
    if isinstance(o, dict):
        return [x for v in o.values() for x in _strings(v)]
    if isinstance(o, list):
        return [x for v in o for x in _strings(v)]
    return []


def _jsonc(text: str):
    """JSON with comments and trailing commas (tsconfig.json)."""
    try:
        return json.loads(text)
    except ValueError:
        pass
    out, i, n, in_str = [], 0, len(text), False
    while i < n:
        c = text[i]
        if in_str:
            out.append(c)
            if c == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if c == '"':
                in_str = False
            i += 1
            continue
        if c == '"':
            in_str = True
            out.append(c)
            i += 1
        elif text.startswith("//", i):
            j = text.find("\n", i)
            i = n if j < 0 else j
        elif text.startswith("/*", i):
            j = text.find("*/", i + 2)
            i = n if j < 0 else j + 2
        else:
            out.append(c)
            i += 1
    try:
        return json.loads(re.sub(r",(\s*[}\]])", r"\1", "".join(out)))
    except ValueError:
        return None


def _dirname(rel: str) -> str:
    return posixpath.dirname(rel)


def _base(rel: str) -> str:
    return rel.rsplit("/", 1)[-1]


def _vendored(rel: str) -> bool:
    parts = rel.split("/")
    return any(p in VENDORED_DIRS for p in parts[:-1])


# ------------------------------------------------------------------ the classifier


@dataclass
class _State:
    root: Path
    from_disk: bool  # no loaded files were given: read texts from disk
    rels: set[str]
    dirs: set[str]
    texts: dict[str, str]
    runtime: set[str] = field(default_factory=set)
    queue: list[str] = field(default_factory=list)
    done_pkgs: set[str] = field(default_factory=set)
    open_dirs: set[str] = field(default_factory=set)  # whole subtree is runtime (fail closed)
    roots: list[str] = field(default_factory=list)  # code roots classified (for the reason)
    pkg_names: dict[str, str] = field(default_factory=dict)  # npm package name -> dir
    py_roots: set[str] = field(default_factory=set)  # dirs that absolute Python imports resolve from
    tsconfigs: dict[str, dict] = field(default_factory=dict)
    by_dir: dict[str, list[str]] = field(default_factory=dict)
    leaf: set[str] = field(default_factory=set)  # runtime, but what they name is not followed

    def exists(self, rel: str) -> bool:
        return rel in self.rels

    current: str = ""  # the runtime file being followed (for `why`)
    why: dict[str, str] = field(default_factory=dict)  # file -> what reached it (debugging, tests)

    # docs the agent reads -> their component folder (a skill's folder, a commands/ or agents/ folder): what
    # they name is followed, and a doc they name inside that folder is model-facing too
    model_facing: dict[str, str] = field(default_factory=dict)

    weak: set[str] = field(default_factory=set)  # reached only by a path string in code: imports followed only

    def add(self, rel: str | None, anchor: str | None = None, weak: bool = False) -> None:
        """anchor: rel is a model-facing doc of that component folder."""
        if not rel or rel not in self.rels:
            return
        weak = weak or self.current in self.weak
        if anchor is None and self.current in self.model_facing:
            a = self.model_facing[self.current]
            if not a or rel.startswith(a + "/"):
                anchor = a  # a doc the component names, inside the component (not the repo's maintainer docs)
        if anchor is not None and rel.lower().endswith(_DOC_EXTS) and rel not in self.model_facing:
            self.model_facing[rel] = anchor
            if rel in self.runtime:
                self.queue.append(rel)  # reached before as a plain doc: now follow what it names
        if rel not in self.runtime:
            self.runtime.add(rel)
            self.queue.append(rel)
            self.why[rel] = self.current
            if weak:
                self.weak.add(rel)
        elif not weak and rel in self.weak:
            self.weak.discard(rel)  # now reached by a strong edge: follow it fully
            self.queue.append(rel)

    def under(self, d: str) -> list[str]:
        if not d:
            return sorted(self.rels)
        pre = d + "/"
        return [r for r in self.rels if r.startswith(pre)]

    def open_dir(self, d: str) -> None:
        if d in self.open_dirs:
            return
        self.open_dirs.add(d)
        for r in self.under(d):
            self.add(r)


_SUBROOT_MARKERS = ("package.json", "pyproject.toml", "setup.py", "SKILL.md", ".claude-plugin/plugin.json",
                    ".claude-plugin/marketplace.json")


def _walk(root: Path) -> tuple[set[str], set[str]]:
    rels: set[str] = set()
    dirs: set[str] = set()
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames[:] = [d for d in dirnames if d != ".git"]
        rd = Path(dirpath).relative_to(root).as_posix()
        rd = "" if rd == "." else rd
        if rd:
            dirs.add(rd)
        for name in filenames:
            p = Path(dirpath) / name
            try:
                if p.is_symlink() or not p.is_file():
                    continue
            except OSError:
                continue
            rels.add(f"{rd}/{name}" if rd else name)
            if len(rels) > MAX_FILES:
                return rels, dirs
    return rels, dirs


def classify(root: Path | None, files: list | None = None, *, extra_seeds: Iterable[str] = ()) -> Reach:
    """Which files of the target at `root` are runtime. `files`: the loaded ScanFiles (their text is used; a
    file on disk that was not loaded is read here if small, else treated as an opaque runtime file)."""
    if root is None:
        return ALL_RUNTIME
    try:
        rels, dirs = _walk(Path(root))
    except OSError:
        return ALL_RUNTIME
    if len(rels) > MAX_FILES:
        return Reach(None, "too many files to classify", files=frozenset(rels))
    texts = {f.rel: f.text for f in files or [] if f.rel in rels}
    st = _State(Path(root), files is None, rels, dirs, texts)
    for r in rels:
        st.by_dir.setdefault(_dirname(r), []).append(r)
    for r in rels:
        if _base(r) == "package.json" and not _vendored(r):
            doc = _json(st, r)
            if isinstance(doc, dict) and isinstance(doc.get("name"), str):
                st.pkg_names.setdefault(doc["name"], _dirname(r))
    try:
        if len(rels) > MAX_FILES or not _seed_root(st, ""):
            # No code root at the top: every nested manifest is a candidate (fail closed). Still nothing: all.
            nested = sorted({_dirname(r) for r in rels if _base(r) in ("package.json", "pyproject.toml", "setup.py")
                             and not _vendored(r) and _dirname(r)}
                            | {_dirname(_dirname(r)) for r in rels if r.endswith((".claude-plugin/plugin.json",
                                                                                  ".claude-plugin/marketplace.json"))
                               and not _vendored(r) and _dirname(_dirname(r))})
            found = [d for d in nested if _seed_root(st, d)]
            if not found:
                return Reach(None, "no manifest that names what runs")
            # Code outside every package found is not known to be dead: it stays runtime.
            for r in rels:
                if r.endswith(TRACED_CODE) and not any(r.startswith(d + "/") for d in found):
                    st.add(r)
        _model_facing(st)
        for s in extra_seeds:
            st.add(s)
        _close(st)
    except RecursionError:
        return Reach(None, "classifier recursion limit")
    return Reach(frozenset(st.runtime | st.leaf), "reachability from " + ", ".join(st.roots[:8]), tuple(st.roots),
                 frozenset(rels), dict(st.why))


def _json(st: _State, rel: str):
    t = _text(st, rel)
    if t is None:
        return None
    try:
        return json.loads(t)
    except (ValueError, RecursionError):
        return None


def _text(st: _State, rel: str) -> str | None:
    t = st.texts.get(rel)
    if t is None and st.from_disk and rel in st.rels:
        try:
            p = st.root / rel
            if p.stat().st_size <= 16_000_000:
                data = p.read_bytes()
                if b"\x00" not in data[:8192]:
                    t = data.decode("utf-8", errors="replace")
        except OSError:
            t = None
        if t is not None:
            st.texts[rel] = t
    return t


def _seed_root(st: _State, d: str) -> bool:
    """Seed one package / plugin / skill root at folder d. True when d is a code root the rules understand."""
    if d in st.done_pkgs:
        return True
    st.done_pkgs.add(d)
    j = (lambda n: f"{d}/{n}" if d else n)
    real = False
    if st.exists(j(".claude-plugin/plugin.json")):
        _seed_plugin(st, d)
        real = True
    if st.exists(j(".claude-plugin/marketplace.json")):
        _seed_marketplace(st, d)
        real = True
    if st.exists(j("SKILL.md")):
        st.add(j("SKILL.md"), d)
        st.add(j("README.md"), d)
        real = True
    if st.exists(j("package.json")) and _seed_npm(st, d):
        real = True
    if _seed_python(st, d):
        real = True
    if st.exists(j(".mcp.json")):
        st.add(j(".mcp.json"))  # names servers to run; on its own it is config, not a code root
    if real:
        st.roots.append(d or ".")
        for n in _LEAF_SEEDS:
            if st.exists(j(n)):
                st.leaf.add(j(n))  # runs at install/build; what it names is not followed (it names dev targets)
    return real


# ---- npm

def _seed_npm(st: _State, d: str) -> bool:
    rel = f"{d}/package.json" if d else "package.json"
    doc = _json(st, rel)
    st.add(rel)
    if not isinstance(doc, dict):
        st.open_dir(d)  # an unreadable manifest: fail closed for its package
        return True
    entries: list[str] = []
    for k in ("main", "module", "bin", "browser", "exports", "imports", "svelte", "worker"):
        v = doc.get(k)
        if k == "browser" and isinstance(v, dict):
            v = list(v.values())
        entries += [s for s in _strings(v) if not s.startswith(("http:", "https:"))]
    scripts = doc.get("scripts") if isinstance(doc.get("scripts"), dict) else {}
    scripts = {k: v for k, v in scripts.items() if isinstance(v, str)}
    run = _run_scripts(scripts)
    resolved, unresolved = 0, 0
    for e in entries:
        if "*" in e:
            pat = _norm(d, e.lstrip("./") if e.startswith("./") else e)
            if pat:
                rx = re.compile(fnmatch.translate(pat).replace(".*", "[^\n]*"))
                hits = [r for r in st.under(d) if rx.match(r)]
                for r in hits:
                    st.add(r)
                resolved += bool(hits)
            continue
        hit = _resolve_entry(st, d, e)
        if hit:
            st.add(hit)
            resolved += 1
        else:
            unresolved += 1
    if not entries:
        idx = _resolve_entry(st, d, "index.js")
        if idx:
            st.add(idx)
            resolved += 1
    for name in run:
        for tok in _cmd_tokens(scripts[name]):
            hit = _resolve_entry(st, d, tok) if _looks_path(tok) else None
            if hit:
                st.add(hit)
                resolved += 1
    if any(re.match(r"(?:pre|post)?build|bundle|compile|prepare", n) for n in run):
        for r in st.by_dir.get(d, []):
            if _BUILD_CONFIG_RE.match(_base(r)):
                st.add(r)
                resolved += 1
    ws = doc.get("workspaces")
    globs = _strings(ws.get("packages") if isinstance(ws, dict) else ws)
    pnpm = f"{d}/pnpm-workspace.yaml" if d else "pnpm-workspace.yaml"
    if st.exists(pnpm) and _text(st, pnpm):
        globs += re.findall(r"^\s*-\s*['\"]?([^'\"\n#]+?)['\"]?\s*$", _text(st, pnpm) or "", re.M)
    for g in globs:
        if g.startswith("!"):
            continue
        pat = _norm(d, g.rstrip("/"))
        if not pat:
            continue
        for sub in sorted(st.dirs):
            if fnmatch.fnmatchcase(sub, pat) and st.exists(f"{sub}/package.json"):
                _seed_root(st, sub)
                resolved += 1
    if unresolved and not resolved:
        st.open_dir(d)  # a declared entry that is not here and maps to no source: its whole package runs
        return True
    has_install = any(re.match(r"(?:pre|post)?install$|prepare$", n) for n in scripts)
    return bool(resolved or has_install or entries)


def _run_scripts(scripts: dict[str, str]) -> list[str]:
    todo = [k for k in scripts if _RUN_SCRIPT_RE.match(k)]
    seen: list[str] = []
    while todo and len(seen) < 200:
        k = todo.pop()
        if k in seen:
            continue
        seen.append(k)
        for m in _SCRIPT_CALL_RE.finditer(scripts[k]):
            names = (m.group(1) or m.group(3) or "").split() or (m.group(2) or "").split()
            for nm in names:
                if nm in scripts and nm not in seen:
                    todo.append(nm)
                elif "*" in nm:
                    todo += [s for s in scripts if fnmatch.fnmatchcase(s, nm) and s not in seen]
        for pre in ("pre", "post"):
            if pre + k in scripts and pre + k not in seen:
                todo.append(pre + k)
    return seen


def _cmd_tokens(cmd: str) -> list[str]:
    out = []
    for tok in re.split(r"[\s;&|()<>]+", cmd):
        tok = tok.strip("\"'`")
        if "=" in tok and tok.startswith("-"):
            tok = tok.split("=", 1)[1]
        if tok and not tok.startswith("-"):
            out.append(_strip_prefix(tok))
    return out


def _looks_path(tok: str) -> bool:
    return "/" in tok or bool(re.search(r"\.[A-Za-z]{1,5}$", tok))


def _strip_prefix(tok: str) -> str:
    return re.sub(r"^(?:\$\{?CLAUDE_PLUGIN_ROOT\}?|\$\{?CLAUDE_PROJECT_DIR\}?|\{baseDir\}|"
                  r"\$\{?(?:__dirname|SCRIPT_DIR|DIR|ROOT)\}?)/", "", tok)


def _tsconfig(st: _State, d: str) -> dict:
    if d in st.tsconfigs:
        return st.tsconfigs[d]
    opts: dict = {}
    for name in ("tsconfig.json", "tsconfig.build.json", "tsconfig.base.json", "jsconfig.json"):
        rel = f"{d}/{name}" if d else name
        if st.exists(rel):
            doc = _jsonc(_text(st, rel) or "")
            co = doc.get("compilerOptions") if isinstance(doc, dict) else None
            if isinstance(co, dict):
                for k in ("outDir", "rootDir", "baseUrl", "paths"):
                    opts.setdefault(k, co.get(k))
    st.tsconfigs[d] = opts
    return opts


def _with_exts(st: _State, p: str) -> str | None:
    if p in st.rels:
        return p
    stem = re.sub(r"\.(?:[cm]?js|jsx)$", "", p)
    for cand in [p + e for e in _RESOLVE_EXTS[1:]] + [stem + e for e in _SRC_EXTS] + \
                [f"{p}/index{e}" for e in _RESOLVE_EXTS[1:]]:
        if cand in st.rels:
            return cand
    if p in st.dirs:
        for f in ("package.json",):
            if f"{p}/{f}" in st.rels:
                _seed_root(st, p)
                return f"{p}/{f}"
    return None


def _resolve_entry(st: _State, d: str, e: str) -> str | None:
    """A declared entry relative to package folder d, mapped from a build output to its source when the output
    is not here (a git checkout of a TypeScript server)."""
    e = _strip_prefix(e.strip())
    p = _norm(d, e)
    if not p:
        return None
    hit = _with_exts(st, p)
    if hit:
        return hit
    rel = posixpath.relpath(p, d) if d else p
    ts = _tsconfig(st, d)
    outs = [str(ts["outDir"]).strip("./")] if isinstance(ts.get("outDir"), str) else []
    srcs = [str(ts["rootDir"]).strip("./")] if isinstance(ts.get("rootDir"), str) else []
    for out in outs + list(_OUT_DIRS):
        if out and rel.startswith(out + "/"):
            rest = rel[len(out) + 1:]
            for src in srcs + list(_SRC_DIRS):
                cand = _norm(d, f"{src}/{rest}" if src else rest)
                if cand:
                    hit = _with_exts(st, cand)
                    if hit and hit.endswith(_SRC_EXTS):
                        return hit
    return None


# ---- python

def _seed_python(st: _State, d: str) -> bool:
    j = (lambda n: f"{d}/{n}" if d else n)
    pyproject, setup_py, setup_cfg = j("pyproject.toml"), j("setup.py"), j("setup.cfg")
    doc: dict = {}
    if st.exists(pyproject):
        try:
            doc = tomllib.loads(_text(st, pyproject) or "")
        except (tomllib.TOMLDecodeError, RecursionError, ValueError):
            doc = {}
    proj = doc.get("project") if isinstance(doc.get("project"), dict) else {}
    tool = doc.get("tool") if isinstance(doc.get("tool"), dict) else {}
    poetry = tool.get("poetry") if isinstance(tool.get("poetry"), dict) else {}
    is_pkg = bool(proj) or bool(poetry) or st.exists(setup_py) or (st.exists(setup_cfg) and "[options" in (
        _text(st, setup_cfg) or "")) or ("build-system" in doc)
    if not is_pkg:
        return False
    st.add(pyproject)
    st.add(setup_py)
    st.add(setup_cfg)
    st.py_roots.update({d, j("src")} if st.exists(j("src")) or j("src") in st.dirs else {d})
    pkgs: list[str] = []
    explicit = False
    # setuptools
    stools = tool.get("setuptools") if isinstance(tool.get("setuptools"), dict) else {}
    pkg_dir = stools.get("package-dir") if isinstance(stools.get("package-dir"), dict) else {}
    base_dir = pkg_dir.get("", "") if isinstance(pkg_dir.get(""), str) else ""
    if base_dir:
        st.py_roots.add(_norm(d, base_dir) or d)
    sp = stools.get("packages")
    if isinstance(sp, list):
        explicit = True
        pkgs += [_norm(d, posixpath.join(base_dir, str(p).replace(".", "/"))) or "" for p in sp]
    elif isinstance(sp, dict) and isinstance(sp.get("find"), dict):
        explicit = True
        pkgs += _find_packages(st, d, sp["find"])
    for m in _strings(stools.get("py-modules")):
        explicit = True
        st.add(_norm(d, posixpath.join(base_dir, m.replace(".", "/") + ".py")))
    # hatch
    hatch = tool.get("hatch") if isinstance(tool.get("hatch"), dict) else {}
    build = hatch.get("build") if isinstance(hatch.get("build"), dict) else {}
    targets = build.get("targets") if isinstance(build.get("targets"), dict) else {}
    wheel = targets.get("wheel") if isinstance(targets.get("wheel"), dict) else {}
    for src in (wheel, build):
        for k in ("packages", "only-include", "include"):
            for p in _strings(src.get(k)):
                explicit = True
                pkgs.append(_norm(d, p.strip("/")) or "")
        for k in ("sources",):
            v = src.get(k)
            for p in (list(v.keys()) if isinstance(v, dict) else _strings(v)):
                if p:
                    st.py_roots.add(_norm(d, p.strip("/")) or d)
    hooks = build.get("hooks") if isinstance(build.get("hooks"), dict) else {}
    for h in hooks.values():
        if isinstance(h, dict):
            st.add(_norm(d, str(h.get("path") or "hatch_build.py")))
    for t in targets.values():
        if isinstance(t, dict) and isinstance(t.get("hooks"), dict):
            for h in t["hooks"].values():
                if isinstance(h, dict):
                    st.add(_norm(d, str(h.get("path") or "hatch_build.py")))
    # poetry
    for p in poetry.get("packages") or [] if isinstance(poetry.get("packages"), list) else []:
        if isinstance(p, dict) and isinstance(p.get("include"), str):
            explicit = True
            frm = p.get("from") if isinstance(p.get("from"), str) else ""
            if frm:
                st.py_roots.add(_norm(d, frm) or d)
            pkgs.append(_norm(d, posixpath.join(frm, p["include"].replace(".", "/"))) or "")
    if isinstance(poetry.get("build"), (str, dict)):
        for s in _strings(poetry.get("build")):
            st.add(_norm(d, s if s.endswith(".py") else s + ".py"))
    # flit / pdm / maturin module names
    for key in ("flit", "pdm", "maturin"):
        t = tool.get(key) if isinstance(tool.get(key), dict) else {}
        mod = t.get("module") if isinstance(t.get("module"), dict) else {}
        if isinstance(mod.get("name"), str):
            explicit = True
            pkgs.append(_norm(d, mod["name"].replace(".", "/")) or "")
        if key == "maturin" and isinstance(t.get("python-source"), str):
            st.py_roots.add(_norm(d, t["python-source"]) or d)
    # build backend in the tree
    bs = doc.get("build-system") if isinstance(doc.get("build-system"), dict) else {}
    for p in _strings(bs.get("backend-path")):
        _add_tree(st, _norm(d, p) or d, py_only=True)
    # setup.cfg [options] packages / py_modules / entry points
    cfg = _text(st, setup_cfg) or ""
    if cfg:
        m = re.search(r"^packages\s*=\s*(.+(?:\n[ \t]+.+)*)", cfg, re.M)
        if m and "find:" not in m.group(1) and "find_namespace:" not in m.group(1):
            explicit = True
            pkgs += [_norm(d, p.strip().replace(".", "/")) or "" for p in re.split(r"[\s,]+", m.group(1)) if p.strip()]
    # setup.py packages=[...] literal / find_packages(exclude=...)
    sp_text = _text(st, setup_py) or ""
    if sp_text:
        m = re.search(r"packages\s*=\s*\[([^\]]*)\]", sp_text)
        if m:
            names = re.findall(r"['\"]([\w.]+)['\"]", m.group(1))
            if names:
                explicit = True
                pkgs += [_norm(d, n.replace(".", "/")) or "" for n in names]
        if re.search(r"find(?:_namespace)?_packages\s*\(", sp_text):
            explicit = True
            ex = re.search(r"exclude\s*=\s*[\[(]([^\])]*)[\])]", sp_text)
            excl = re.findall(r"['\"]([^'\"]+)['\"]", ex.group(1)) if ex else []
            where = re.search(r"(?:where\s*=\s*|find_packages\s*\(\s*)['\"]([^'\"]+)['\"]", sp_text)
            pkgs += _find_packages(st, d, {"where": [where.group(1)] if where else ["."], "exclude": excl})
    uvb = tool.get("uv") if isinstance(tool.get("uv"), dict) else {}
    uvb = uvb.get("build-backend") if isinstance(uvb.get("build-backend"), dict) else {}
    if uvb:
        root_dir = str(uvb.get("module-root", "src")).strip("/")
        names = _strings(uvb.get("module-name"))
        if names:
            explicit = True
            pkgs += [_norm(d, posixpath.join(root_dir, n.replace(".", "/"))) or "" for n in names]
        if root_dir:
            st.py_roots.add(_norm(d, root_dir) or d)
    if not explicit:
        name = str(proj.get("name") or poetry.get("name") or "")
        backend = str(bs.get("build-backend") or "")
        named = _named_packages(st, d, name)
        if named and not backend.startswith("setuptools"):
            pkgs += named  # hatchling, uv_build, flit, poetry, pdm: the package named after the project
        else:
            pkgs += _auto_discover(st, d, name)
    for p in pkgs:
        if p is not None:
            _add_tree(st, p, py_only=False)
            st.add(p + ".py")
    # console scripts / entry points: module:func
    eps: list[str] = []
    for src in (proj.get("scripts"), proj.get("gui-scripts"), proj.get("entry-points"), poetry.get("scripts"),
                poetry.get("plugins")):
        eps += _strings(src)
    eps += re.findall(r"=\s*([\w.]+)\s*:", cfg)
    eps += re.findall(r"['\"][\w.-]+\s*=\s*([\w.]+)\s*:", sp_text)
    unresolved = 0
    for ep in eps:
        mod = ep.split(":", 1)[0].strip()
        if not re.fullmatch(r"[\w.]+", mod):
            continue
        hit = _resolve_py_module(st, mod, [d, *sorted(st.py_roots)])
        if hit:
            st.add(hit)
        else:
            unresolved += 1
    if unresolved and not pkgs:
        st.open_dir(d)
    # root modules that a user runs directly (`python server.py`, `uv run main.py`)
    for r in st.by_dir.get(d, []):
        if r.endswith(".py") and not _SETUPTOOLS_MOD_EXCLUDE_RE.match(_base(r)[:-3]):
            st.add(r)
    for r in st.by_dir.get(d, []):
        if _base(r) in ("hatch_build.py", "build.py", "setup.py", "build_ext.py"):
            st.add(r)
    return True


def _add_tree(st: _State, d: str, py_only: bool) -> None:
    if not d or d not in st.dirs:
        return
    for r in st.under(d):
        if not py_only or r.endswith(PY_EXTS):
            st.add(r)


def _find_packages(st: _State, d: str, find: dict) -> list[str]:
    where = _strings(find.get("where")) or ["."]
    include = _strings(find.get("include")) or ["*"]
    exclude = _strings(find.get("exclude"))
    out = []
    for w in where:
        wd = _norm(d, w) if w not in (".", "") else d
        if wd is None:
            continue
        if wd != d:
            st.py_roots.add(wd)
        for sub in st.dirs:
            if (sub.startswith(wd + "/") if wd else True) and st.exists(f"{sub}/__init__.py"):
                name = (sub[len(wd) + 1:] if wd else sub).replace("/", ".")
                if any(fnmatch.fnmatchcase(name, p) for p in include) and \
                        not any(fnmatch.fnmatchcase(name, p) for p in exclude):
                    out.append(sub)
    return out


def _named_packages(st: _State, d: str, name: str) -> list[str]:
    norm = re.sub(r"[-_.]+", "_", name).lower()
    if not norm:
        return []
    out = []
    for base in ("src", ""):
        cand = _norm(d, posixpath.join(base, norm)) if (d or base) else norm
        if cand and (cand in st.dirs or cand + ".py" in st.rels):
            out.append(cand)
    return out


def _auto_discover(st: _State, d: str, name: str) -> list[str]:
    j = (lambda n: f"{d}/{n}" if d else n)
    src = j("src")
    if src in st.dirs:
        return [src]
    out = []
    norm = re.sub(r"[-_.]+", "_", name).lower()
    for sub in st.dirs:
        if _dirname(sub) != d:
            continue
        b = _base(sub)
        if b.lower() == norm or (st.exists(f"{sub}/__init__.py") and b not in _SETUPTOOLS_PKG_EXCLUDE
                                 and not b.startswith((".", "_"))):
            out.append(sub)
    return out


def _resolve_py_module(st: _State, mod: str, bases: Iterable[str]) -> str | None:
    path = mod.replace(".", "/")
    for b in bases:
        p = _norm(b, path) if b else path
        if not p:
            continue
        for cand in (p + ".py", p + "/__init__.py", p + "/__main__.py"):
            if cand in st.rels:
                return cand
    return None


# ---- plugins and marketplaces

def _seed_plugin(st: _State, d: str) -> None:
    j = (lambda n: f"{d}/{n}" if d else n)
    man = j(".claude-plugin/plugin.json")
    st.add(man)
    for n in ("hooks/hooks.json", ".mcp.json", ".lsp.json", "settings.json"):
        st.add(j(n))
    for sub in ("commands", "agents", "output-styles"):
        _expand_dir(st, j(sub))
    _expand_dir(st, j("skills"))
    doc = _json(st, man)
    if isinstance(doc, dict):
        for s in _strings(doc):
            _json_string_ref(st, d, s)
    # each bundled server's command and args (bawwab.scan._bundled_servers)
    try:
        from bawwab.scan import _bundled_servers

        servers = _bundled_servers(st.root / d if d else st.root)
    except Exception:  # noqa: BLE001 - best effort; the manifests' strings are followed anyway
        servers = {}
    for spec in servers.values():
        for s in [spec.get("command")] + list(spec.get("args") or []) + _strings(spec.get("env")):
            if isinstance(s, str):
                _json_string_ref(st, d, s)


def _seed_marketplace(st: _State, d: str) -> None:
    j = (lambda n: f"{d}/{n}" if d else n)
    man = j(".claude-plugin/marketplace.json")
    st.add(man)
    doc = _json(st, man)
    if not isinstance(doc, dict):
        return
    for s in _strings(doc):
        _json_string_ref(st, d, s)


def _json_string_ref(st: _State, d: str, s: str) -> None:
    """A manifest string: the whole string as a path, and each path-like token inside it (commands)."""
    if len(s) > 4000:
        return
    for tok in [s.strip()] + _cmd_tokens(s):
        tok = _strip_prefix(tok)
        # a path names a folder or has an extension: a plain word in a description ("tests") is not one
        if not tok or tok.startswith(("http:", "https:", "~")) or not _looks_path(tok):
            continue
        p = _norm(d, tok)
        if not p:
            continue
        if p in st.rels:
            st.add(p)
        elif p in st.dirs:
            _expand_dir(st, p)


def _expand_dir(st: _State, p: str, weak: bool = False) -> None:
    """A referenced folder: its sub-roots (a skill, plugin or package inside) are classified as such; every
    other file in it is runtime."""
    if p not in st.dirs:
        return
    if weak:  # a folder named by a path string in code: its files, with their imports only
        for r in st.under(p):
            st.add(r, weak=True)
        return
    sub_roots = set()
    for r in st.under(p):
        for m in _SUBROOT_MARKERS:
            if r.endswith("/" + m) or r == m:
                sr = r[: -len(m)].rstrip("/")
                if sr != p and sr.startswith(p + "/"):
                    sub_roots.add(sr)
    for sr in sorted(sub_roots):
        _seed_root(st, sr)
    for r in st.under(p):
        if not any(r.startswith(sr + "/") for sr in sub_roots):
            st.add(r, weak=weak)


def _model_facing(st: _State) -> None:
    for r in sorted(st.rels):
        if _vendored(r):
            continue
        parts = r.split("/")
        b = parts[-1]
        if any(p.startswith(".") and p not in (".claude", ".claude-plugin") for p in parts[:-1]):
            continue  # another tool's agent config (.github/agents, .codex, .cursor, .pi...): Claude does not load it
        if b == "SKILL.md":
            st.add(r, _dirname(r))
            st.add(posixpath.join(_dirname(r), "README.md") if _dirname(r) else "README.md", _dirname(r))
        elif b.lower().endswith(".md") and any(p in ("commands", "agents") for p in parts[:-1]):
            i = max(k for k, p in enumerate(parts[:-1]) if p in ("commands", "agents"))
            st.add(r, "/".join(parts[: i + 1]))
        elif parts[0] == ".claude" and len(parts) > 1:
            # A repo's own Claude config is loaded when Claude is opened in the checkout: it counts, but what its
            # docs name is developer material (tests, scripts). Settings hooks run code: they are followed.
            if b.startswith("settings") and b.endswith(".json"):
                st.add(r)
            else:
                st.leaf.add(r)
        elif r in ("CLAUDE.md", "AGENTS.md", "CLAUDE.local.md", "GEMINI.md"):
            st.leaf.add(r)  # developer instructions for working on the repo: listed as runtime, not followed
        elif r == ".mcp.json":
            st.add(r)


# ------------------------------------------------------------------ transitive closure

def _close(st: _State) -> None:
    while st.queue:
        rel = st.queue.pop()
        st.current = rel
        text = _text(st, rel)
        if text is None:
            if rel.endswith(TRACED_CODE):
                st.open_dir(_dirname(rel))  # runtime code that was not read: its imports are unknown
            continue
        if len(text) > 64_000_000:
            continue
        here = _dirname(rel)
        low = rel.lower()
        if low.endswith(JS_EXTS) or low.endswith((".html", ".htm", ".vue", ".svelte", ".astro")):
            _js_refs(st, rel, here, text)
        elif low.endswith(PY_EXTS):
            _py_refs(st, rel, here, text)
        elif _base(rel) == "package.json" and here not in st.done_pkgs:
            _seed_root(st, here)
        if rel in st.weak:
            continue  # named only by a path string in code: its imports are followed, not every path it names
        if low.endswith(TRACED_CODE) or rel in st.model_facing or _base(rel) in _RUN_MANIFESTS:
            # a doc or data file reached from code is read, not followed; a path string in code is a weak edge
            _token_refs(st, rel, here, text, weak=low.endswith(TRACED_CODE) and rel not in st.model_facing)


def _bases(st: _State, here: str) -> list[str]:
    out = [here]
    pkg = here
    while True:
        if st.exists(f"{pkg}/package.json" if pkg else "package.json") or \
                st.exists(f"{pkg}/.claude-plugin/plugin.json" if pkg else ".claude-plugin/plugin.json") or \
                st.exists(f"{pkg}/SKILL.md" if pkg else "SKILL.md") or \
                st.exists(f"{pkg}/pyproject.toml" if pkg else "pyproject.toml"):
            if pkg not in out:
                out.append(pkg)
        if not pkg:
            break
        pkg = _dirname(pkg)
    if "" not in out:
        out.append("")
    return out


def _token_refs(st: _State, rel: str, here: str, text: str, weak: bool = False) -> None:
    """Path-like tokens that resolve to a file or folder of the target (from the file's folder, the package
    and plugin roots above it, then the target root)."""
    is_doc = rel.lower().endswith((".md", ".mdx", ".txt", ".json", ".jsonc", ".yaml", ".yml", ".toml"))
    seen: set[str] = set()
    bases: list[str] | None = None
    for rx in (_SLASH_TOKEN_RE, _EXT_TOKEN_RE):
        for m in rx.finditer(text):
            s = m.start()
            if s > 0 and text[s - 1] == ":":  # a URL
                continue
            tok = m.group(0)
            if tok.startswith("/") or tok in seen or "//" in tok:
                continue
            seen.add(tok)
            if len(seen) > MAX_TOKENS_PER_FILE:
                return
            plugin_rel = tok.startswith(("${CLAUDE_PLUGIN_ROOT}", "$CLAUDE_PLUGIN_ROOT", "{baseDir}"))
            tok = _strip_prefix(tok).rstrip(".,;:")
            if not tok or tok in (".", "..", "./", "../") or "{" in tok or "$" in tok:
                continue
            if bases is None:
                bases = _bases(st, here)
            for b in (bases[1:] if plugin_rel and len(bases) > 1 else bases):
                p = _norm(b, tok)
                if not p:
                    continue
                if p in st.rels:
                    st.add(p, weak=weak)
                    break
                d = p.rstrip("/")
                if d in st.dirs and ("/" in tok.rstrip("/") or tok.endswith("/") or is_doc):
                    _expand_dir(st, d, weak=weak)
                    break


def _js_refs(st: _State, rel: str, here: str, text: str) -> None:
    if len(text) > MAX_PARSE_BYTES * 8:
        return
    for m in _JS_SPEC_RE.finditer(text):
        spec = m.group(2)
        if "${" in spec:
            continue
        _resolve_js(st, here, spec)
    for m in _JS_TEMPLATE_DIR_RE.finditer(text):
        p = _norm(here, m.group(1))
        if p and p in st.dirs:
            _expand_dir(st, p)


def _resolve_js(st: _State, here: str, spec: str) -> None:
    spec = spec.split("?", 1)[0].split("#", 1)[0] if not spec.startswith("#") else spec
    if spec.startswith(("node:", "data:", "http:", "https:", "bun:", "npm:", "jsr:")):
        return
    if spec.startswith(("./", "../", "/")) or spec in (".", ".."):
        p = _norm(here, spec.lstrip("/") if spec.startswith("/") else spec)
        if p:
            hit = _with_exts(st, p)
            if hit:
                st.add(hit)
        return
    # bare: a workspace package, a vendored node_modules package, or a tsconfig path alias
    parts = spec.split("/")
    name = "/".join(parts[:2]) if spec.startswith("@") else parts[0]
    sub = "/".join(parts[2:] if spec.startswith("@") else parts[1:])
    if name in st.pkg_names:
        pd = st.pkg_names[name]
        _seed_root(st, pd)
        if sub:
            hit = _with_exts(st, _norm(pd, sub) or "") or _resolve_entry(st, pd, sub)
            if hit:
                st.add(hit)
        return
    d = here
    while True:
        nm = _norm(d, f"node_modules/{name}") if d else f"node_modules/{name}"
        if nm and nm in st.dirs:
            _seed_root(st, nm)
            if sub:
                hit = _with_exts(st, f"{nm}/{sub}")
                if hit:
                    st.add(hit)
            return
        if not d:
            break
        d = _dirname(d)
    for pd in _bases(st, here):
        ts = _tsconfig(st, pd)
        paths = ts.get("paths") if isinstance(ts.get("paths"), dict) else {}
        base = _norm(pd, str(ts.get("baseUrl") or ".")) if ts.get("baseUrl") not in (None, ".", "./") else pd
        for pat, targets in paths.items():
            if not isinstance(pat, str):
                continue
            rx = "^" + re.escape(pat).replace(r"\*", "(.*)") + "$"
            m = re.match(rx, spec)
            if not m:
                continue
            for t in _strings(targets):
                cand = t.replace("*", m.group(1) if m.groups() else "")
                p = _norm(base or "", cand)
                hit = _with_exts(st, p) if p else None
                if hit:
                    st.add(hit)
                    return
        if ts.get("baseUrl"):
            p = _norm(base or "", spec)
            hit = _with_exts(st, p) if p else None
            if hit:
                st.add(hit)
                return


def _py_refs(st: _State, rel: str, here: str, text: str) -> None:
    mods: list[tuple[int, str, list[str]]] = []  # (level, module, names)
    # Line-based (an import in a string or docstring counts too: that only keeps more runtime)
    for mod, names in set(_PY_FROM_RE.findall(text)):
        lvl = len(mod) - len(mod.lstrip("."))
        mods.append((lvl, mod.lstrip("."), [w for w in re.findall(r"\w+", names) if w != "as"]))
    for group in set(_PY_IMPORT_RE.findall(text)):
        mods += [(0, m.strip().split()[0], []) for m in group.split(",") if m.strip()]
    mods += [(0, m, []) for m in _PY_DYN_RE.findall(text)]
    roots = sorted(st.py_roots | {""})
    for level, mod, names in mods:
        if level:
            base = here
            for _ in range(level - 1):
                base = _dirname(base)
            bases = [base]
        else:
            bases = [here, *roots]
        for b in bases:
            p = posixpath.join(b, mod.replace(".", "/")) if mod else b
            p = _norm("", p) if p else ""
            hit = next((c for c in (p + ".py", p + "/__init__.py") if c in st.rels), None) if p else None
            found = bool(hit)
            if hit:
                st.add(hit)
                _add_parents(st, b, p)
            for nm in names:
                if nm == "*":
                    continue
                q = f"{p}/{nm}" if p else nm
                for c in (q + ".py", q + "/__init__.py"):
                    if c in st.rels:
                        st.add(c)
                        found = True
            if found:
                break


def _add_parents(st: _State, base: str, p: str) -> None:
    d = _dirname(p)
    while d and d != base and (not base or d.startswith(base)):
        st.add(f"{d}/__init__.py")
        d = _dirname(d)

