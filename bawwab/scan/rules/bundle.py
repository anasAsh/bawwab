"""Bundled or minified JavaScript (false-positive plan, step 2).

A bundler puts an application and hundreds of unrelated libraries into one file, so "the same file" (or, in a
minified one-liner, "the same line"; in a webpack bundle, "the same outermost function") says nothing about whether
a credential read and a network call belong together. The combo rules ask for proximity instead in such files
(code._combo_near); every other file keeps the same-function rule.

The content decides. A file is a bundle when it is JS/TS, at least BUNDLE_MIN_BYTES long, and shows at least one of:
* minified code: most of its bytes (MINIFIED_SHARE) are in lines of LONG_LINE chars or more that look like code
  (statement punctuation), not one long string or data literal;
* a bundler runtime: webpack (`__webpack_require__`, `__webpack_modules__`, `webpackChunk...`), esbuild/tsup/bun
  (`__toESM(`, `__commonJS(`, or `__defProp` with `__export(`), Parcel (`parcelRequire`), browserify's prelude,
  SystemJS (`System.register(`), bun's `// @bun` banner, Vite's `__vitePreload`;
* the module path comments esbuild/tsup leave (`// node_modules/zod/lib/index.mjs`) for at least MODULE_COMMENTS
  modules.
A path hint (`.min.js`, `.bundle.js`, `.bundled.js`, a `dist/`, `build/` or `out/` folder) only lowers the size floor
to HINT_MIN_BYTES; it never makes a file a bundle on its own. Python is never treated as a bundle.
"""
from __future__ import annotations

import re
from functools import lru_cache

JS_TS_EXT = (".js", ".mjs", ".cjs", ".jsx", ".ts", ".mts", ".cts", ".tsx")
BUNDLE_MIN_BYTES = 64 << 10
HINT_MIN_BYTES = 24 << 10
LONG_LINE = 1000
MINIFIED_SHARE = 0.5
CODE_PUNCT_PER_KB = 8  # ; { } per 1000 chars: minified code has dozens, a base64 or prose line almost none
MODULE_COMMENTS = 8
SIGNATURE_SCAN = 4 << 20  # bundler runtimes sit in the preamble or are repeated throughout; 4 MiB is plenty

_RUNTIME_RE = re.compile(
    r"__webpack_require__|__webpack_modules__|webpackBootstrap|\bwebpackChunk\w*|"
    r"\b__toESM\(|\b__commonJS\(|\bparcelRequire\w*|\bSystem\.register\(|\b__vitePreload\b|"
    r"^// @bun\b|"
    r"\(function\(\)\{function \w\(\w,\w,\w\)\{function \w\(\w,\w\)\{if\(!\w\[\w\]\)"  # browserify prelude
    , re.M,
)
_ESBUILD_DEFPROP_RE = re.compile(r"\bvar __defProp\s*=\s*Object\.defineProperty\b")
_ESBUILD_EXPORT_RE = re.compile(r"\b__export\(")
_MODULE_COMMENT_RE = re.compile(r"^[ \t]*// (?:\.\./)*node_modules/((?:@[\w.-]+/)?[\w.-]+)/\S+$", re.M)
_HINT_RE = re.compile(r"(?:^|/)(?:dist|build|out|bundle|bundles)/|[.-](?:min|bundle|bundled)\.[cm]?js$")
_PUNCT = str.maketrans("", "", ";{}")


def _minified(text: str) -> bool:
    long_code = 0
    for line in text.split("\n"):
        n = len(line)
        if n < LONG_LINE:
            continue
        punct = n - len(line.translate(_PUNCT))
        if punct * 1000 >= CODE_PUNCT_PER_KB * n:
            long_code += n
    return long_code >= MINIFIED_SHARE * len(text)


def _runtime(text: str) -> bool:
    head = text[:SIGNATURE_SCAN]
    if _RUNTIME_RE.search(head):
        return True
    return bool(_ESBUILD_DEFPROP_RE.search(head) and _ESBUILD_EXPORT_RE.search(head))


def _module_comments(text: str) -> bool:
    seen: set[str] = set()
    for m in _MODULE_COMMENT_RE.finditer(text):
        seen.add(m.group(0).strip())
        if len(seen) >= MODULE_COMMENTS:
            return True
    return False


def why(rel: str, text: str) -> str | None:
    """Why this file is a bundle ("minified", "runtime", "modules"), or None when it is not one."""
    if not rel.endswith(JS_TS_EXT):
        return None
    floor = HINT_MIN_BYTES if _HINT_RE.search(rel) else BUNDLE_MIN_BYTES
    if len(text) < floor:
        return None
    if _runtime(text):
        return "runtime"
    if _module_comments(text):
        return "modules"
    if _minified(text):
        return "minified"
    return None


@lru_cache(maxsize=512)
def is_bundle(rel: str, text: str) -> bool:
    return why(rel, text) is not None
