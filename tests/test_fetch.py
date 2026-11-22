import hashlib
import io
import json
import subprocess
import tarfile
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import unquote

import pytest

from bawwab.fetch import FetchError, FetchOpts, detect_artifact_type, fetch_target
from bawwab.fetch.common import hash_tree
from bawwab.types import Target


def make_tgz(files: dict[str, bytes], top="package") -> bytes:
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tf:
        for name, data in files.items():
            ti = tarfile.TarInfo(f"{top}/{name}" if top else name)
            ti.size = len(data)
            tf.addfile(ti, io.BytesIO(data))
    return buf.getvalue()


@pytest.fixture
def server():
    routes: dict[str, bytes] = {}

    class H(BaseHTTPRequestHandler):
        def do_GET(self):
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
    yield base, routes
    srv.shutdown()


def _npm_setup(base, routes, pkgjson=b'{"name":"@a/b"}'):
    routes["/@a/b"] = json.dumps(
        {
            "dist-tags": {"latest": "1.2.0"},
            "time": {"created": "2020-01-02T03:04:05.000Z"},
            "repository": {"type": "git", "url": "git+https://github.com/a/b.git"},
            "versions": {
                "1.2.0": {"dist": {"tarball": f"{base}/t/b-1.2.0.tgz"}},
                "1.0.0": {"dist": {"tarball": f"{base}/t/b-1.0.0.tgz"}},
            },
        }
    ).encode()
    routes["/t/b-1.2.0.tgz"] = make_tgz({"package.json": pkgjson, "index.js": b"1"})
    routes["/t/b-1.0.0.tgz"] = make_tgz({"package.json": b'{"v":1}'})


def test_npm_fetch(server):
    base, routes = server
    _npm_setup(base, routes)
    f = fetch_target(Target("npm", "@a/b", name="@a/b"), FetchOpts(npm_registry=base))
    assert f.resolved_version == "1.2.0"
    assert (f.root / "package.json").exists()
    assert f.artifact_type == "mcp"
    assert f.meta.repo_url == "git+https://github.com/a/b.git"
    assert f.meta.created_at is not None and f.meta.created_at.year == 2020
    root = f.root
    f.cleanup()
    assert not root.exists()


def test_npm_pinned_version(server):
    base, routes = server
    _npm_setup(base, routes)
    f = fetch_target(Target("npm", "@a/b@1.0.0", name="@a/b", version="1.0.0"), FetchOpts(npm_registry=base))
    assert f.resolved_version == "1.0.0"
    f.cleanup()


def test_npm_missing(server):
    base, _ = server
    with pytest.raises(FetchError):
        fetch_target(Target("npm", "nope", name="nope"), FetchOpts(npm_registry=base))


def test_npm_download_cap(server, monkeypatch):
    base, routes = server
    _npm_setup(base, routes)
    from bawwab.fetch import common

    monkeypatch.setattr(common, "MAX_DOWNLOAD_BYTES", 10)
    with pytest.raises(FetchError):
        fetch_target(Target("npm", "@a/b", name="@a/b"), FetchOpts(npm_registry=base))


def test_content_hash_stable_and_changes(server):
    base, routes = server
    _npm_setup(base, routes)
    t = Target("npm", "@a/b", name="@a/b")
    o = FetchOpts(npm_registry=base)
    a = fetch_target(t, o)
    b = fetch_target(t, o)
    assert a.content_hash == b.content_hash and len(a.content_hash) == 64
    a.cleanup()
    b.cleanup()
    routes["/t/b-1.2.0.tgz"] = make_tgz({"package.json": b'{"name":"@a/c"}', "index.js": b"1"})
    c = fetch_target(t, o)
    assert c.content_hash != a.content_hash
    c.cleanup()


def _pypi_setup(base, routes, sdist=True, with_wheel=True):
    sd = make_tgz({"setup.py": b"x=1", "pyproject.toml": b""}, top="mypkg-1.0")
    zbuf = io.BytesIO()
    with zipfile.ZipFile(zbuf, "w") as zf:
        zf.writestr("mypkg/__init__.py", "")
    wheel = zbuf.getvalue()
    urls = []
    if sdist:
        urls.append({"packagetype": "sdist", "url": f"{base}/f/mypkg-1.0.tar.gz", "digests": {"sha256": hashlib.sha256(sd).hexdigest()}, "upload_time_iso_8601": "2021-05-06T07:08:09.000000Z"})
    if with_wheel:
        urls.append({"packagetype": "bdist_wheel", "url": f"{base}/f/mypkg-1.0-py3-none-any.whl", "digests": {"sha256": hashlib.sha256(wheel).hexdigest()}, "upload_time_iso_8601": "2021-05-06T07:08:09.000000Z"})
    doc = json.dumps({"info": {"name": "mypkg", "version": "1.0", "project_urls": {"Source": "https://github.com/a/mypkg"}}, "urls": urls}).encode()
    routes["/pypi/mypkg/json"] = doc
    routes["/pypi/mypkg/1.0/json"] = doc
    routes["/f/mypkg-1.0.tar.gz"] = sd
    routes["/f/mypkg-1.0-py3-none-any.whl"] = wheel


def test_pypi_sdist(server):
    base, routes = server
    _pypi_setup(base, routes, with_wheel=False)  # only an sdist: that is what installs
    for v in (None, "1.0"):
        f = fetch_target(Target("pypi", "pypi:mypkg", name="mypkg", version=v), FetchOpts(pypi_base=base))
        assert f.resolved_version == "1.0"
        assert (f.root / "setup.py").exists()
        assert f.meta.repo_url == "https://github.com/a/mypkg"
        assert f.meta.created_at is not None and f.meta.created_at.year == 2021
        root = f.root
        f.cleanup()
        assert not root.exists()


def test_pypi_wheel_fallback(server):
    base, routes = server
    _pypi_setup(base, routes, sdist=False)
    f = fetch_target(Target("pypi", "pypi:mypkg", name="mypkg"), FetchOpts(pypi_base=base))
    assert (f.root / "mypkg" / "__init__.py").exists()
    f.cleanup()


def test_pypi_digest_mismatch(server):
    base, routes = server
    _pypi_setup(base, routes, with_wheel=False)
    routes["/f/mypkg-1.0.tar.gz"] = make_tgz({"setup.py": b"evil"}, top="mypkg-1.0")
    with pytest.raises(FetchError):
        fetch_target(Target("pypi", "pypi:mypkg", name="mypkg"), FetchOpts(pypi_base=base))


def _git(*args, cwd=None):
    subprocess.run(
        ["git", "-c", "user.name=t", "-c", "user.email=t@t", "-c", "commit.gpgsign=false", *args],
        cwd=cwd, check=True, capture_output=True,
    )


def test_git_fetch(tmp_path):
    bare = tmp_path / "r.git"
    _git("init", "--bare", "-b", "main", str(bare))
    work = tmp_path / "w"
    _git("clone", str(bare), str(work))
    (work / "server.py").write_text("print(1)\n")
    (work / ".claude-plugin").mkdir()
    (work / ".claude-plugin" / "plugin.json").write_text("{}")
    _git("add", "-A", cwd=work)
    _git("commit", "-m", "init", cwd=work)
    _git("push", "origin", "HEAD:main", cwd=work)
    sha = subprocess.run(["git", "rev-parse", "HEAD"], cwd=work, capture_output=True, text=True).stdout.strip()
    url = f"file://{bare}"
    t = Target("git", url, url=url)
    # production default must refuse file:// (protocol.file.allow=never)
    with pytest.raises(FetchError):
        fetch_target(t, FetchOpts())
    f = fetch_target(t, FetchOpts(git_allow_file=True))
    assert f.resolved_version == sha
    assert (f.root / "server.py").exists()
    assert not (f.root / ".git").exists()
    assert f.artifact_type == "plugin"
    root = f.root
    f.cleanup()
    assert not root.exists()


def test_git_rejects_option_url():
    with pytest.raises(FetchError):
        fetch_target(Target("git", "--upload-pack=x", url="--upload-pack=x"), FetchOpts())


def test_local(tmp_path):
    (tmp_path / "SKILL.md").write_text("# s")
    f = fetch_target(Target("local", str(tmp_path), path=str(tmp_path)))
    assert f.root == tmp_path and f.artifact_type == "skill"
    f.cleanup()
    assert tmp_path.exists()
    (tmp_path / "SKILL.md").write_text("# t")
    assert fetch_target(Target("local", str(tmp_path), path=str(tmp_path))).content_hash != f.content_hash


def test_local_missing(tmp_path):
    with pytest.raises(FetchError):
        fetch_target(Target("local", "x", path=str(tmp_path / "nope")))


def test_local_symlink_out_flagged(tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    (out / "s").write_text("secret")
    proj = tmp_path / "proj"
    proj.mkdir()
    (proj / "link").symlink_to(out / "s")
    f = fetch_target(Target("local", str(proj), path=str(proj)))
    assert any(x.rule == "fetch.unsafe-entry" for x in f.findings)


def test_docker():
    f = fetch_target(Target("docker", "docker:img:1", name="img", version="1"))
    assert f.root is None and f.resolved_version == "1"
    assert any(x.rule == "fetch.docker-unscanned" and x.severity == "med" for x in f.findings)
    f.cleanup()


def test_detect_artifact_type(tmp_path):
    assert detect_artifact_type(tmp_path) == "mcp"
    (tmp_path / "SKILL.md").write_text("")
    assert detect_artifact_type(tmp_path) == "skill"
    (tmp_path / ".claude-plugin").mkdir()
    (tmp_path / ".claude-plugin" / "plugin.json").write_text("{}")
    assert detect_artifact_type(tmp_path) == "plugin"


def test_hash_tree_empty(tmp_path):
    assert len(hash_tree(tmp_path)) == 64


def test_remote_unreachable_raises_fetch_error():
    t0 = time.monotonic()
    with pytest.raises(FetchError):
        fetch_target(Target("remote", "http://127.0.0.1:1/mcp", url="http://127.0.0.1:1/mcp"), FetchOpts(remote_timeout_s=3))
    assert time.monotonic() - t0 < 8


def test_npm_dist_tag_version(server):
    base, routes = server
    _npm_setup(base, routes)
    doc = json.loads(routes["/@a/b"])
    doc["dist-tags"]["next"] = "1.0.0"
    routes["/@a/b"] = json.dumps(doc).encode()
    for tag, want in (("latest", "1.2.0"), ("next", "1.0.0"), ("1.0.0", "1.0.0")):
        f = fetch_target(Target("npm", f"@a/b@{tag}", name="@a/b", version=tag), FetchOpts(npm_registry=base))
        assert f.resolved_version == want
        f.cleanup()
    with pytest.raises(FetchError):
        fetch_target(Target("npm", "@a/b@nope", name="@a/b", version="nope"), FetchOpts(npm_registry=base))


def test_remote_hash_lone_surrogate():
    from bawwab.fetch.remote import remote_hash
    from bawwab.types import ToolInfo

    assert len(remote_hash([ToolInfo("t", "bad \ud800 text")])) == 64


def test_remote_path_any_exception_is_fetch_error(monkeypatch):
    from bawwab.fetch import remote

    monkeypatch.setattr(remote, "fetch_remote", lambda url, t: (_ for _ in ()).throw(RuntimeError("boom")))
    with pytest.raises(FetchError):
        fetch_target(Target("remote", "http://x/", url="http://x/"), FetchOpts())
    monkeypatch.setattr(remote, "fetch_remote", lambda url, t: ("1", []))
    monkeypatch.setattr(remote, "remote_hash", lambda tools: (_ for _ in ()).throw(UnicodeEncodeError("u", "", 0, 1, "x")))
    with pytest.raises(FetchError):
        fetch_target(Target("remote", "http://x/", url="http://x/"), FetchOpts())


def test_git_env_is_isolated_from_repo(tmp_path):
    from bawwab.fetch import git as g

    env = g._env(tmp_path / "home")
    assert env["GIT_CONFIG_GLOBAL"] == "/dev/null" and env["GIT_CONFIG_NOSYSTEM"] == "1"
    assert env["HOME"] == str(tmp_path / "home")


def test_git_repo_config_not_honoured(tmp_path):
    marker = tmp_path / "MARKER"
    bare = tmp_path / "r.git"
    _git("init", "--bare", "-b", "main", str(bare))
    work = tmp_path / "w"
    _git("clone", str(bare), str(work))
    (work / "hook.sh").write_text(f"#!/bin/sh\ntouch {marker}\n")
    (work / "hook.sh").chmod(0o755)
    (work / ".gitconfig").write_text(f"[core]\n\tfsmonitor = {work}/hook.sh\n\tpager = touch {marker}\n[alias]\n\trev-parse = !touch {marker}\n")
    (work / "a.txt").write_text("a")
    _git("add", "-A", cwd=work)
    _git("commit", "-m", "x", cwd=work)
    _git("push", "origin", "HEAD:main", cwd=work)
    url = f"file://{bare}"
    f = fetch_target(Target("git", url, url=url), FetchOpts(git_allow_file=True))
    assert len(f.resolved_version) == 40 and not marker.exists()
    f.cleanup()



def _npm_integrity(base, routes, integrity=None, shasum=None):
    doc = json.loads(routes["/@a/b"])
    dist = doc["versions"]["1.2.0"]["dist"]
    dist.pop("integrity", None)
    dist.pop("shasum", None)
    if integrity is not None:
        dist["integrity"] = integrity
    if shasum is not None:
        dist["shasum"] = shasum
    routes["/@a/b"] = json.dumps(doc).encode()


def _sri(data, alg="sha512"):
    import base64

    return f"{alg}-" + base64.b64encode(hashlib.new(alg, data).digest()).decode()


def test_npm_integrity_checked(server):
    base, routes = server
    _npm_setup(base, routes)
    good = routes["/t/b-1.2.0.tgz"]
    t, o = Target("npm", "@a/b", name="@a/b"), FetchOpts(npm_registry=base)
    _npm_integrity(base, routes, integrity=f"sha1-AAAA {_sri(good)}")
    fetch_target(t, o).cleanup()  # the strongest algorithm given is the one checked
    _npm_integrity(base, routes, integrity=_sri(b"other bytes"))
    with pytest.raises(FetchError, match="integrity mismatch"):
        fetch_target(t, o)
    _npm_integrity(base, routes, shasum=hashlib.sha1(b"other").hexdigest())  # no integrity: shasum
    with pytest.raises(FetchError, match="sha1 integrity mismatch"):
        fetch_target(t, o)
    _npm_integrity(base, routes, shasum=hashlib.sha1(good).hexdigest())
    fetch_target(t, o).cleanup()


def _wheel_url(name):
    return {"packagetype": "bdist_wheel", "filename": name, "url": f"https://f.invalid/{name}"}


def test_pypi_pick_is_what_pip_installs():
    from bawwab.fetch.pypi import pick_file

    sdist = {"packagetype": "sdist", "filename": "p-1.0.tar.gz", "url": "https://f.invalid/p-1.0.tar.gz"}
    pure = _wheel_url("p-1.0-py3-none-any.whl")
    old_py = _wheel_url("p-1.0-py2-none-any.whl")
    other = _wheel_url("p-1.0-cp312-cp312-win_arm64.whl")
    assert pick_file([sdist, pure]) is pure  # a pure wheel installs, not the sdist
    assert pick_file([sdist, _wheel_url("p-1.0-py2.py3-none-any.whl")])["filename"].startswith("p-1.0-py2.py3")
    assert pick_file([sdist, old_py]) is sdist  # pip would build the sdist here
    assert pick_file([sdist, other]) is sdist
    assert pick_file([other]) is other  # nothing else to read
    from packaging.tags import sys_tags

    here = next(iter(sys_tags()))
    native = _wheel_url(f"p-1.0-{here.interpreter}-{here.abi}-{here.platform}.whl")
    assert pick_file([sdist, other, native]) is native
    assert pick_file([sdist, native, pure]) is pure
    assert pick_file([{**pure, "yanked": True}, _wheel_url("p-1.0-py3-none-any.whl")]) is not pure


def test_pypi_scans_the_wheel_when_there_is_one(server):
    base, routes = server
    _pypi_setup(base, routes)
    f = fetch_target(Target("pypi", "pypi:mypkg", name="mypkg"), FetchOpts(pypi_base=base))
    assert (f.root / "mypkg" / "__init__.py").exists() and not (f.root / "setup.py").exists()
    f.cleanup()
