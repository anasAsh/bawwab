"""Effect decisions bound to the bytes that run: local MCP server code under an unchanged, accepted config entry,
every installed copy of a plugin, and one symlink rule for the fingerprint and the content hash."""
from __future__ import annotations

import os
from pathlib import Path

import pytest

from bawwab import effects as fx
from bawwab import inventory as inv
from bawwab.agents import claude_code_watch as w
from bawwab.paths import bawwab_home
from bawwab.store import open_store
from bawwab.types import Verdict
from test_effects import FakeScan, _w

EVIL = FakeScan(Verdict.MALICIOUS)


def _idents() -> list[str]:
    return [q["ident"] for q in open_store().active_quarantine()]


def _same_stat_rewrite(f: Path, text: str) -> None:
    """New content of the same size with the old mtime: only ctime (and the bytes) change."""
    st = f.stat()
    assert len(text) == st.st_size
    f.write_text(text)
    os.utime(f, ns=(st.st_atime_ns, st.st_mtime_ns))


def _accept_all(proj: Path) -> None:
    fx.session_start(proj)
    fx.init_skip(proj)
    scan = FakeScan()
    assert fx.refresh(proj, scan=scan) == []


@pytest.fixture
def home(monkeypatch):
    monkeypatch.setattr(inv, "spawn_background", lambda cwd, full=False: None)
    return Path.home()


# ------------------------------------------------------------------ local MCP server payloads

@pytest.fixture
def local_srv(home, tmp_path):
    """Servers that run local code: a lone script, a script in a package, `uv --directory`, a local binary."""
    proj = tmp_path / "proj"
    proj.mkdir()
    srv = tmp_path / "srv"
    _w(srv / "server.js", "// server v1\n")
    pkg = tmp_path / "pkg"
    _w(pkg / "package.json", '{"name": "pkg", "main": "dist/index.js"}')
    _w(pkg / "dist/index.js", "// index v1\n")
    _w(pkg / "dist/lib/util.js", "// util v1\n")
    uvd = tmp_path / "weather"
    _w(uvd / "pyproject.toml", "[project]\nname = 'weather'\n")
    _w(uvd / "weather.py", "print('v1')\n")
    _w(uvd / "helpers/geo.py", "X = 1\n")
    binf = tmp_path / "bin/my-srv"
    _w(binf, "#!/bin/sh\necho v1\n")
    _w(home / ".claude.json", {"projects": {str(proj): {}}, "mcpServers": {
        "js": {"command": "node", "args": [str(srv / "server.js")]},
        "pkg": {"command": "node", "args": [str(pkg / "dist/index.js")]},
        "uv": {"command": "uv", "args": ["--directory", str(uvd), "run", "weather.py"]},
        "bin": {"command": str(binf), "args": []}}})
    _w(proj / ".mcp.json", {"mcpServers": {"rel": {"command": "python3", "args": ["tools/srv.py"]}}})
    _w(proj / "tools/srv.py", "print('rel v1')\n")
    _accept_all(proj)
    return proj, tmp_path


@pytest.mark.parametrize("rel,ident", [
    ("srv/server.js", "claude-code:mcp:user:js"),
    ("pkg/dist/index.js", "claude-code:mcp:user:pkg"),
    ("pkg/dist/lib/util.js", "claude-code:mcp:user:pkg"),  # a module of the script's package
    ("weather/weather.py", "claude-code:mcp:user:uv"),
    ("weather/helpers/geo.py", "claude-code:mcp:user:uv"),  # inside `uv --directory`'s project
    ("bin/my-srv", "claude-code:mcp:user:bin"),
])
def test_changed_local_code_under_an_accepted_entry_is_quarantined(local_srv, rel, ident):
    proj, root = local_srv
    f = root / rel
    _same_stat_rewrite(f, "X" * (f.stat().st_size - 1) + "\n")
    assert fx.post_tool_decision(proj, scan=EVIL) is not None
    assert ident in _idents()


def test_project_mcpjson_relative_script_is_bound(local_srv):
    proj, _ = local_srv
    _same_stat_rewrite(proj / "tools/srv.py", "print('rel v2')\n")
    assert fx.post_tool_decision(proj, scan=EVIL) is not None
    assert f"claude-code:mcp:mcpjson:{os.path.realpath(proj)}:rel" in _idents()


def test_unchanged_local_code_is_not_rescanned(local_srv):
    proj, _ = local_srv
    scan = FakeScan(Verdict.MALICIOUS)
    assert fx.refresh(proj, scan=scan) == [] and scan.calls == []
    assert fx.refresh(proj, scan=scan, force=True) == [] and scan.calls == []  # the hashes themselves are stable


def test_the_hook_fingerprint_sees_the_change(local_srv):
    """The stdlib fingerprint (cached payload paths) moves on a payload change, and only then."""
    proj, root = local_srv
    fpm, bh, h = fx.fp_module(), str(bawwab_home()), str(Path.home())
    assert fpm.check(str(proj), h, bh) == "same"
    assert fpm.check(str(proj), h, bh) == "same"  # from the payload cache
    _same_stat_rewrite(root / "srv/server.js", "// server v2\n")
    assert fpm.check(str(proj), h, bh) == "changed"


def test_payload_cache_follows_config_edits(local_srv, home):
    """A new local server added to the config is statted at once, not after the cache expires."""
    proj, root = local_srv
    fpm, bh, h = fx.fp_module(), str(bawwab_home()), str(home)
    before = fpm.fingerprint(str(proj), h, bawwab_home=bh)
    _w(root / "new/srv.js", "// new\n")
    _w(home / ".claude.json", {**__import__("json").loads((home / ".claude.json").read_text()),
                               "mcpServers": {"n": {"command": "node", "args": [str(root / "new/srv.js")]}}})
    mid = fpm.fingerprint(str(proj), h, bawwab_home=bh)
    assert mid != before
    _same_stat_rewrite(root / "new/srv.js", "// NEW\n")
    assert fpm.fingerprint(str(proj), h, bawwab_home=bh) != mid


def test_creating_a_missing_script_counts(home, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    script = tmp_path / "later/server.js"
    _w(home / ".claude.json", {"projects": {str(proj): {}}, "mcpServers": {
        "s": {"command": "node", "args": [str(script)]}}})
    _accept_all(proj)
    _w(script, "// arrives later\n")
    assert fx.post_tool_decision(proj, scan=EVIL) is not None
    assert "claude-code:mcp:user:s" in _idents()


def test_project_tree_is_not_a_payload(home, tmp_path):
    """A server that runs the project itself (`uv run` in it, `node .`) is not re-checked on every edit."""
    proj = tmp_path / "proj"
    _w(proj / "package.json", '{"name": "app"}')
    _w(proj / "src/app.js", "// app\n")
    _w(proj / "server.js", "// srv\n")
    _w(home / ".claude.json", {"projects": {str(proj): {}}})
    _w(proj / ".mcp.json", {"mcpServers": {"a": {"command": "uv", "args": ["--directory", str(proj), "run", "x"]},
                                           "b": {"command": "node", "args": ["server.js"]}}})
    _accept_all(proj)
    _same_stat_rewrite(proj / "src/app.js", "// APP\n")
    scan = FakeScan(Verdict.MALICIOUS)
    assert fx.refresh(proj, scan=scan) == [] and scan.calls == []
    _same_stat_rewrite(proj / "server.js", "// SRV\n")  # the script file itself is still bound
    assert fx.post_tool_decision(proj, scan=EVIL) is not None
    assert _idents() == [f"claude-code:mcp:mcpjson:{os.path.realpath(proj)}:b"]


def test_unresolvable_commands_keep_the_entry_value(home, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    specs = {"npx": {"command": "npx", "args": ["-y", "a@1.0.0"]}, "mod": {"command": "python3", "args": ["-m", "x"]},
             "path": {"command": "my-server"}, "var": {"command": "node", "args": ["${HOME}/s.js"]}}
    _w(home / ".claude.json", {"projects": {str(proj): {}}, "mcpServers": specs})
    items = {it.ident: it.value for it in fx.effect_items(proj) if it.category == "servers"}
    assert {k.rsplit(":", 1)[1]: v for k, v in items.items()} == specs


@pytest.mark.parametrize("spec,want", [
    ({"command": "node", "args": ["server.js"]}, ["/b/server.js"]),
    ({"command": "node", "args": ["-r", "./pre.js", "--no-warnings", "dist/i.js", "--port", "1"]},
     ["/b/pre.js", "/b/dist/i.js"]),
    ({"command": "node", "args": ["--import=./hook.mjs", "-e", "x"]}, ["/b/hook.mjs"]),
    ({"command": "/usr/bin/python3", "args": ["-u", "/a/s.py"]}, ["/a/s.py"]),
    ({"command": ".venv/bin/python", "args": ["srv.py"]}, ["/b/srv.py"]),
    ({"command": "python3", "args": ["-m", "srv"]}, []),
    ({"command": "deno", "args": ["run", "-A", "main.ts"]}, ["/b/main.ts"]),
    ({"command": "uv", "args": ["--directory", "/w", "run", "weather.py"]}, ["/w", "/w/weather.py"]),
    ({"command": "uv", "args": ["run", "--project", "../x", "--with", "mcp", "srv"]}, ["/x"]),
    ({"command": "uv", "args": ["run", "--directory=/w", "python", "s.py"]}, ["/w", "/w/s.py"]),
    ({"command": "uv", "args": ["tool", "run", "x"]}, []),
    ({"command": "uvx", "args": ["x"]}, []),
    ({"command": "docker", "args": ["run", "img"]}, []),
    ({"command": "/opt/srv"}, ["/opt/srv"]),
    ({"command": "./bin/srv"}, ["/b/bin/srv"]),
    ({"command": "srv"}, []),
    ({"url": "https://x/mcp"}, []),
])
def test_server_payloads(spec, want):
    assert w.server_payloads(spec, "/b") == want


# ------------------------------------------------------------------ every installed copy of a plugin

@pytest.fixture
def two_copies(home, tmp_path):
    proj = tmp_path / "proj"
    proj.mkdir()
    other = tmp_path / "other"
    other.mkdir()
    cache = home / ".claude/plugins/cache/mkt/p1"
    a, b = cache / "1.0.0", cache / "1.1.0"
    for d in (a, b):
        _w(d / ".claude-plugin/plugin.json", {"name": "p1"})
        _w(d / "hooks/run.sh", f"echo {d.name}\n")
    _w(home / ".claude.json", {"projects": {str(proj): {}}})
    _w(home / ".claude/plugins/installed_plugins.json", {"version": 2, "plugins": {"p1@mkt": [
        {"scope": "user", "installPath": str(a), "version": "1.0.0"},
        {"scope": "project", "projectPath": str(other), "installPath": str(b), "version": "1.1.0"}]}})
    _w(home / ".claude/settings.json", {"enabledPlugins": {"p1@mkt": True}})
    _accept_all(proj)
    return proj, other, a, b


def test_changed_second_copy_is_quarantined_and_scanned_there(two_copies):
    proj, _, a, b = two_copies
    _same_stat_rewrite(b / "hooks/run.sh", "echo EVIL!\n")
    scan = FakeScan(Verdict.MALICIOUS)
    assert fx.post_tool_decision(proj, scan=scan) is not None
    tag = __import__("hashlib").sha256(str(b).encode()).hexdigest()[:12]
    assert f"claude-code:plugin:p1@mkt:copy:{tag}" in _idents()
    assert str(b) in [t.path for t in scan.calls]  # the changed copy's own bytes were scanned


def test_plugin_value_is_the_same_from_every_project(two_copies):
    proj, other, _, _ = two_copies
    one = {it.ident: it.hash for it in fx.effect_items(proj) if it.category == "plugins"}
    two = {it.ident: it.hash for it in fx.effect_items(other) if it.category == "plugins"}
    assert one == two and len(one) == 3


def test_unchanged_copies_are_not_rescanned(two_copies):
    proj, other, _, _ = two_copies
    scan = FakeScan(Verdict.MALICIOUS)
    assert fx.refresh(proj, scan=scan, force=True) == [] and scan.calls == []


def test_one_copy_keeps_its_old_value(home, tmp_path):
    """A plugin with one install path hashes as it always did (no re-check on upgrade)."""
    from bawwab.agents.claude_code import _tree_hash

    proj = tmp_path / "proj"
    proj.mkdir()
    inst = home / ".claude/plugins/cache/mkt/p/1.0"
    _w(inst / ".claude-plugin/plugin.json", {"name": "p"})
    _w(home / ".claude/plugins/installed_plugins.json", {"version": 2, "plugins": {"p@mkt": [
        {"scope": "user", "installPath": str(inst), "version": "1.0"}]}})
    [it] = [i for i in fx.effect_items(proj) if i.category == "plugins"]
    assert it.value["content"] == _tree_hash(inst)


# ------------------------------------------------------------------ one symlink rule

@pytest.fixture
def linked(home, tmp_path):
    """A plugin whose install path is a link, with a linked subdir and a link loop inside."""
    proj = tmp_path / "proj"
    proj.mkdir()
    real = tmp_path / "real-plugin"
    _w(real / ".claude-plugin/plugin.json", {"name": "p"})
    shared = tmp_path / "shared-lib"
    _w(shared / "deep/code.js", "// v1\n")
    os.symlink(shared, real / "lib")
    os.symlink(real, real / "loop")
    inst = home / ".claude/plugins/cache/mkt/p/1.0"
    inst.parent.mkdir(parents=True)
    os.symlink(real, inst)
    _w(home / ".claude.json", {"projects": {str(proj): {}}})
    _w(home / ".claude/plugins/installed_plugins.json", {"version": 2, "plugins": {"p@mkt": [
        {"scope": "user", "installPath": str(inst), "version": "1.0"}]}})
    _accept_all(proj)
    return proj, real, shared, inst


def test_change_behind_a_linked_dir_moves_both(linked):
    proj, _, shared, _ = linked
    _same_stat_rewrite(shared / "deep/code.js", "// v2\n")
    assert fx.post_tool_decision(proj, scan=EVIL) is not None
    assert "claude-code:plugin:p@mkt" in _idents()


def test_retargeted_link_moves_both(linked, tmp_path):
    proj, real, _, _ = linked
    other = tmp_path / "other-lib"
    _w(other / "deep/code.js", "// v1\n")  # identical bytes, another place
    os.unlink(real / "lib")
    os.symlink(other, real / "lib")
    assert fx.post_tool_decision(proj, scan=EVIL) is not None


def test_linked_tree_is_stable(linked):
    proj, _, _, _ = linked
    scan = FakeScan(Verdict.MALICIOUS)
    assert fx.refresh(proj, scan=scan, force=True) == [] and scan.calls == []


def test_tree_hash_follows_dir_links_once(tmp_path):
    from bawwab.agents.claude_code import _tree_hash

    root, out = tmp_path / "r", tmp_path / "outside"
    _w(root / "a/x.js", "1")
    _w(out / "y.js", "1")
    os.symlink(root / "a", root / "b")  # the same dir twice: walked once
    os.symlink(root, root / "a/up")  # a loop
    os.symlink(out, root / "a/ext")  # nested, leaving the tree
    h1 = _tree_hash(root)
    assert _tree_hash(root) == h1
    (out / "y.js").write_text("2")
    assert _tree_hash(root) != h1


# ------------------------------------------------------------------ hot path

@pytest.mark.timing  # absolute time limit: noisy on shared CI runners
def test_hook_median_idle_with_local_servers_and_a_big_claude_json(local_srv, home):
    """The payload paths are cached by the config files' stat data: an idle hook never parses ~/.claude.json."""
    import json
    import statistics
    import subprocess
    import sys
    import time

    proj, _ = local_srv
    d = json.loads((home / ".claude.json").read_text())
    d["projects"].update({f"/p/{i}": {"history": ["x" * 200] * 25, "allowedTools": []} for i in range(1000)})
    _w(home / ".claude.json", d)  # ~5 MB
    assert fx.refresh(proj, scan=FakeScan()) == []
    hook = Path(__file__).resolve().parent.parent / "hooks" / "bawwab_hook.py"
    call = json.dumps({"tool_name": "Bash", "tool_input": {"command": "ls"}, "cwd": str(proj)})
    env = {k: v for k, v in os.environ.items() if k != "BAWWAB_CHILD"}
    ts = []
    for _ in range(9):
        t0 = time.perf_counter()
        r = subprocess.run([sys.executable, str(hook), "gate"], input=call, capture_output=True, text=True, env=env)
        ts.append(time.perf_counter() - t0)
        assert r.stdout == ""
    print(f"\nhook median {statistics.median(ts) * 1000:.1f} ms, claude.json "
          f"{(home / '.claude.json').stat().st_size / 1e6:.1f} MB")
    assert statistics.median(ts) < 0.100, ts
