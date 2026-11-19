"""Task 10c: known-malware lookup through OSV (ossf/malicious-packages MAL-* advisories).

Every test talks to a local fake OSV server; no test reaches the real network.
"""
from __future__ import annotations

import hashlib
import io
import json
import socket
import tarfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote

import pytest

from bawwab.config import Config
from bawwab.fetch import FetchOpts
from bawwab.scan import osv, scan_target
from bawwab.store import Store
from bawwab.types import Severity, Target, Verdict

pytestmark = pytest.mark.real_osv

MAL = {
    "id": "MAL-2025-1234",
    "summary": "Malicious code in evil-pkg (npm)",
    "affected": [{"package": {"ecosystem": "npm", "name": "evil-pkg"}}],
}
GHSA = {"id": "GHSA-xxxx-yyyy-zzzz", "aliases": ["CVE-2024-0001"], "summary": "Prototype pollution"}


@pytest.fixture
def fake_osv():
    state = {"vulns": {}, "status": 200, "pages": {}}
    posts: list[dict] = []
    routes: dict[str, bytes] = {}

    class H(BaseHTTPRequestHandler):
        def do_POST(self):
            body = json.loads(self.rfile.read(int(self.headers.get("Content-Length") or 0)) or b"{}")
            posts.append({"path": self.path, "body": body})
            if self.path != "/v1/query" or state["status"] != 200:
                self.send_response(state["status"] if state["status"] != 200 else 404)
                self.end_headers()
                return
            pkg = body.get("package") or {}
            key = (pkg.get("ecosystem"), pkg.get("name"), body.get("version"))
            tok = body.get("page_token")
            if tok:
                out = state["pages"].get(tok, {})
            else:
                out = {"vulns": state["vulns"].get(key, [])} if state["vulns"].get(key) else {}
                if key in state["pages"]:
                    out = state["pages"][key]
            data = json.dumps(out).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_GET(self):  # doubles as the npm registry
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
    base = f"http://127.0.0.1:{srv.server_address[1]}"
    yield base, state, posts, routes
    srv.shutdown()


def _dead_url() -> str:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return f"http://127.0.0.1:{port}"


def test_mal_advisory_is_known_malicious_critical(fake_osv):
    base, state, posts, _ = fake_osv
    state["vulns"][("npm", "evil-pkg", "1.0.0")] = [MAL]
    found = osv.known_malware("npm", "evil-pkg", "1.0.0", base=base)
    assert [(f.rule, f.severity, f.source) for f in found] == [("identity.known-malicious", Severity.CRITICAL, "identity")]
    assert "MAL-2025-1234" in found[0].evidence
    assert posts[0]["path"] == "/v1/query"
    assert posts[0]["body"] == {"package": {"name": "evil-pkg", "ecosystem": "npm"}, "version": "1.0.0"}


def test_pypi_uses_the_pypi_ecosystem_name(fake_osv):
    base, state, posts, _ = fake_osv
    state["vulns"][("PyPI", "evil-py", "0.1")] = [dict(MAL, id="MAL-2024-9")]
    found = osv.known_malware("pypi", "evil-py", "0.1", base=base)
    assert posts[0]["body"]["package"] == {"name": "evil-py", "ecosystem": "PyPI"}
    assert [f.rule for f in found] == ["identity.known-malicious"]


def test_ordinary_vulnerabilities_are_not_malware(fake_osv):
    base, state, _, _ = fake_osv
    state["vulns"][("npm", "lodash", "4.17.0")] = [GHSA]
    assert osv.known_malware("npm", "lodash", "4.17.0", base=base) == []


def test_mal_alias_counts(fake_osv):
    base, state, _, _ = fake_osv
    state["vulns"][("npm", "x", "1")] = [{"id": "GHSA-aaaa-bbbb-cccc", "aliases": ["MAL-2023-77"], "summary": "Malicious"}]
    assert [f.rule for f in osv.known_malware("npm", "x", "1", base=base)] == ["identity.known-malicious"]


def test_mal_on_a_later_page_is_found(fake_osv):
    base, state, posts, _ = fake_osv
    state["pages"][("npm", "big", "2.0.0")] = {"vulns": [GHSA], "next_page_token": "p2"}
    state["pages"]["p2"] = {"vulns": [MAL]}
    found = osv.known_malware("npm", "big", "2.0.0", base=base)
    assert [f.rule for f in found] == ["identity.known-malicious"]
    assert posts[1]["body"]["page_token"] == "p2"


def test_osv_down_is_a_low_note_not_fail_closed():
    found = osv.known_malware("npm", "anything", "1.0.0", base=_dead_url(), timeout=2)
    assert [(f.rule, f.severity) for f in found] == [("identity.osv-unavailable", Severity.LOW)]


def test_osv_http_error_is_a_low_note(fake_osv):
    base, state, _, _ = fake_osv
    state["status"] = 503
    found = osv.known_malware("npm", "anything", "1.0.0", base=base)
    assert [(f.rule, f.severity) for f in found] == [("identity.osv-unavailable", Severity.LOW)]


def test_cache_hit_makes_no_second_request(fake_osv):
    base, state, posts, _ = fake_osv
    state["vulns"][("npm", "evil-pkg", "1.0.0")] = [MAL]
    a = osv.known_malware("npm", "evil-pkg", "1.0.0", base=base)
    b = osv.known_malware("npm", "evil-pkg", "1.0.0", base=base)
    assert a == b and len(posts) == 1
    osv.known_malware("npm", "evil-pkg", "1.0.1", base=base)  # per name@version
    assert len(posts) == 2
    osv.known_malware("npm", "clean-pkg", "1.0.0", base=base)
    osv.known_malware("npm", "clean-pkg", "1.0.0", base=base)
    assert len(posts) == 3


def test_failure_is_not_cached(fake_osv):
    base, state, posts, _ = fake_osv
    state["status"] = 503
    osv.known_malware("npm", "flaky", "1.0.0", base=base)
    state["status"] = 200
    assert osv.known_malware("npm", "flaky", "1.0.0", base=base) == []
    assert len(posts) == 2


def test_other_target_kinds_are_not_looked_up(fake_osv):
    base, _, posts, _ = fake_osv
    assert osv.known_malware("git", "x", "1", base=base) == []
    assert posts == []


# ---------------------------------------------------------------- end to end through scan_target


class _Judge:
    def complete(self, system, user, schema, timeout_s):
        return '{"findings":[]}'


def _tgz(files: dict[str, bytes]) -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(f"package/{name}")
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


def _npm(base, routes, name="evil-pkg", version="1.0.0"):
    tgz = _tgz({"package.json": json.dumps({"name": name, "version": version}).encode(), "index.js": b"module.exports = 1;\n"})
    routes[f"/{name}"] = json.dumps({
        "dist-tags": {"latest": version}, "time": {"created": "2020-01-01T00:00:00.000Z"},
        "versions": {version: {"dist": {"tarball": f"{base}/t/{name}.tgz", "shasum": hashlib.sha1(tgz).hexdigest()}}},
    }).encode()
    routes[f"/t/{name}.tgz"] = tgz


def test_scan_of_a_known_malicious_npm_package_is_malicious(fake_osv, tmp_path):
    base, state, _, routes = fake_osv
    _npm(base, routes)
    state["vulns"][("npm", "evil-pkg", "1.0.0")] = [MAL]
    r = scan_target(Target("npm", "evil-pkg", name="evil-pkg"), backend=_Judge(), cfg=Config(),
                    fetch_opts=FetchOpts(npm_registry=base, osv_url=base), store=Store(tmp_path / "s.db"))
    assert r.verdict == Verdict.MALICIOUS
    assert any(f.rule == "identity.known-malicious" for f in r.findings)


def test_trusted_name_does_not_hide_a_known_malicious_hit(fake_osv, tmp_path):
    base, state, _, routes = fake_osv
    _npm(base, routes)
    state["vulns"][("npm", "evil-pkg", "1.0.0")] = [MAL]
    r = scan_target(Target("npm", "evil-pkg", name="evil-pkg"), backend=_Judge(), cfg=Config(trusted=["evil-pkg"]),
                    fetch_opts=FetchOpts(npm_registry=base, osv_url=base), store=Store(tmp_path / "s.db"))
    assert r.verdict == Verdict.MALICIOUS


def test_scan_with_osv_down_is_clean_with_a_low_note(fake_osv, tmp_path):
    base, _, _, routes = fake_osv
    _npm(base, routes, name="ok-pkg")
    r = scan_target(Target("npm", "ok-pkg", name="ok-pkg"), backend=_Judge(), cfg=Config(),
                    fetch_opts=FetchOpts(npm_registry=base, osv_url=_dead_url()), store=Store(tmp_path / "s.db"))
    assert r.verdict == Verdict.CLEAN
    assert [(f.rule, f.severity) for f in r.findings] == [("identity.osv-unavailable", Severity.LOW)]


def test_local_targets_are_not_looked_up(fake_osv, tmp_path):
    base, _, posts, _ = fake_osv
    d = tmp_path / "skill"
    d.mkdir()
    (d / "SKILL.md").write_text("---\nname: s\ndescription: d\n---\nHello\n")
    scan_target(Target("local", str(d), path=str(d)), backend=_Judge(), cfg=Config(),
                fetch_opts=FetchOpts(osv_url=base), store=Store(tmp_path / "s.db"))
    assert posts == []
