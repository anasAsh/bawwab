"""Bounded parsing (fix round 1, I2): parse trees were the one unbudgeted allocation in a scan.

- JS/TS (tree-sitter): parsed through a read callback with a progress callback that cancels the parse
  once the process has grown by PARSE_GROWTH_LIMIT bytes. A dense 4 MB array needs ~1.3 GB of tree;
  the 14.5 MB @sveltejs/mcp bundle ~370 MB.
- Python (`ast`, which cannot be cancelled): a token estimate before parsing. `ast` costs up to
  ~1 KB per token (2.9 GB for 4 MB of `f()` lines).

A refused file is treated as unparseable: every rule takes its regex-level path, and the code rule adds
MED `files.truncated` (refused()). Refusals are remembered per text so later passes do not retry.
"""
from __future__ import annotations

import os
from collections import OrderedDict

from tree_sitter_language_pack import get_parser

PARSE_GROWTH_LIMIT = 512 << 20  # bytes of RSS growth allowed while one tree-sitter parse runs
PY_TOKEN_LIMIT = 600_000  # estimated tokens; real code is ~4-6 bytes/token, so ~3 MB of dense Python
_CHUNK = 1 << 16
_CHECK_EVERY = 32  # progress callbacks between RSS reads (~3 us each)

_PUNCT = b",;()[]{}.=+-*/<>!?:&|~^%@\"'`"  # quotes too: `("" "" ...)` is one token per pair (review R1-M1)
_WORDMAP = bytes(0x61 if (chr(i).isalnum() or chr(i) in "_$" or i >= 0x80) else 0x20 for i in range(256))

_refused: OrderedDict[tuple, None] = OrderedDict()  # (len, hash) of texts refused; bounded LRU
_REFUSED_MAX = 4096

try:
    _PAGE = os.sysconf("SC_PAGE_SIZE")
except (ValueError, OSError, AttributeError):  # pragma: no cover - non-POSIX
    _PAGE = 4096


def _rss() -> int:
    try:
        with open("/proc/self/statm", "rb") as fh:
            return int(fh.read().split()[1]) * _PAGE
    except (OSError, ValueError, IndexError):
        import resource

        return resource.getrusage(resource.RUSAGE_SELF).ru_maxrss * 1024  # high-water mark: conservative


def estimate_tokens(src: bytes) -> int:
    """Punctuation bytes plus word starts: an upper-bound-ish node count, linear and allocation-light."""
    punct = len(src) - len(src.translate(None, _PUNCT))
    words = src.translate(_WORDMAP)
    return punct + words.count(b" a") + (words[:1] == b"a")


def _key(src: bytes | str) -> tuple:
    return (len(src), hash(src))


def _remember(src: bytes | str) -> None:
    _refused[_key(src)] = None
    while len(_refused) > _REFUSED_MAX:
        _refused.popitem(last=False)


JS_LANGS = ("javascript", "typescript", "tsx")


def prefetch() -> None:
    """Download the JS/TS grammars now (first-run setup) rather than at the first scan: a scan that cannot fetch
    one (offline, a proxy that blocks GitHub) fails the rules that parse JS, and a failed rule is SUSPICIOUS."""
    from tree_sitter_language_pack import download

    download(list(JS_LANGS))


def refused(text: str) -> bool:
    """Whether some parse of this text (or its UTF-8 bytes) was refused for size."""
    return bool(_refused) and (_key(text) in _refused or _key(text.encode()) in _refused)


def clear() -> None:
    _refused.clear()


def js_tree(src: bytes, lang: str):
    """A tree-sitter tree, or None when the parse would grow the process past PARSE_GROWTH_LIMIT."""
    if _key(src) in _refused:
        return None
    parser = get_parser(lang)
    limit = _rss() + PARSE_GROWTH_LIMIT
    n = 0

    def progress(_offset: int, _has_error: bool) -> bool:
        nonlocal n
        n += 1
        return n % _CHECK_EVERY == 0 and _rss() > limit

    def read(offset: int, _point) -> bytes:
        return src[offset : offset + _CHUNK]

    try:
        return parser.parse(read, progress_callback=progress)
    except ValueError:  # cancelled by progress()
        parser.reset()
        _remember(src)
        return None


def js_root(src: bytes, lang: str):
    """The root node, or raise ValueError (callers' existing unparseable path) when refused."""
    tree = js_tree(src, lang)
    if tree is None:
        raise ValueError("file too large to parse within the memory budget")
    return tree.root_node


def py_ok(text: str) -> bool:
    """Whether `ast.parse(text)` fits the token budget; remembers a refusal."""
    if _key(text) in _refused:
        return False
    if len(text) < PY_TOKEN_LIMIT:  # fewer bytes than the limit: cannot have more tokens
        return True
    if estimate_tokens(text.encode()) <= PY_TOKEN_LIMIT:
        return True
    _remember(text)
    return False


def py_parse(text: str):
    """ast.parse under the token budget; ValueError (callers' existing unparseable path) when refused."""
    import ast

    if not py_ok(text):
        raise ValueError("file too large to parse within the memory budget")
    return ast.parse(text)
