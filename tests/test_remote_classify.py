"""A remote HTTP MCP endpoint on a git host (gitlab.com/api/v4/mcp) is a remote server, not a repository.

Before the fix, any URL on a known git host was cloned, so the official gitlab plugin failed closed with
`fetch.failed: git failed: ... repository 'https://gitlab.com/api/v4/mcp/' not found` on every scan.
No network: the remote MCP client is replaced by fakes.
"""
from __future__ import annotations

import json

import pytest

import bawwab.fetch.remote as remote_mod
import bawwab.scan as scan_mod
from bawwab.agents.claude_code import _server_target
from bawwab.config import Config
from bawwab.fetch import FetchError, fetch_target, parse_target
from bawwab.fetch.target import target_from_url
from bawwab.scan import _child_target, scan_target
from bawwab.store import Store
from bawwab.types import Severity, ToolInfo, Verdict

GITLAB_MCP = "https://gitlab.com/api/v4/mcp"


class _Judge:
    def complete(self, system, user, schema, timeout_s):
        return '{"findings":[]}'


@pytest.mark.parametrize("url", [
    GITLAB_MCP,
    GITLAB_MCP + "/",
    "https://github.com/api/mcp",
    "https://gitlab.com/mcp",
    "https://github.com/",
    "https://github.com",
    "https://gitlab.com/-/mcp",
    "https://gitlab.com/group/project/-/mcp",
    "https://example.com/mcp",
])
def test_non_repo_urls_are_remote(url):
    assert target_from_url(url).kind == "remote"


@pytest.mark.parametrize("url", [
    "https://github.com/o/r",
    "https://github.com/o/r/",
    "https://github.com/o/r.git",
    "https://gitlab.com/g/p",
    "https://gitlab.com/g/sub/p",
    "https://gitlab.com/g/p.git",
    "https://bitbucket.org/o/r",
    "https://codeberg.org/o/r",
    "https://git.example.com/team/r.git",
])
def test_repo_urls_still_clone(url):
    assert target_from_url(url).kind == "git"


@pytest.mark.parametrize("transport", ["http", "sse", "streamable-http", "streamableHttp"])
def test_declared_http_transport_is_remote(transport):
    assert target_from_url("https://github.com/o/r", transport).kind == "remote"


def test_parse_target_cli_gitlab_api_is_remote():
    assert parse_target(GITLAB_MCP).kind == "remote"
    assert parse_target("https://gitlab.com/g/p").kind == "git"


def test_plugin_and_inventory_server_entries_are_remote(tmp_path):
    spec = {"type": "http", "url": GITLAB_MCP}
    assert _child_target(spec, tmp_path).kind == "remote"
    assert _server_target(spec, tmp_path).kind == "remote"
    # a declared http transport wins even when the URL is repo-shaped
    assert _child_target({"type": "http", "url": "https://github.com/o/r"}, tmp_path).kind == "remote"


def _gitlab_plugin(tmp_path):
    p = tmp_path / "gitlab"
    (p / ".claude-plugin").mkdir(parents=True)
    (p / ".claude-plugin/plugin.json").write_text(json.dumps({"name": "gitlab", "description": "GitLab"}))
    (p / ".mcp.json").write_text(json.dumps({"gitlab": {"type": "http", "url": GITLAB_MCP}}))
    return p


@pytest.fixture
def no_git(monkeypatch):
    import bawwab.fetch.git as git_mod

    def boom(*a, **k):
        raise AssertionError("an HTTP MCP endpoint must not be cloned")

    monkeypatch.setattr(git_mod, "fetch_git", boom)


def test_gitlab_plugin_remote_server_scanned_via_tools_list(tmp_path, monkeypatch, no_git):
    seen = []

    def fake_remote(url, timeout_s):
        seen.append(url)
        return "1.0", [ToolInfo("list_projects", "List GitLab projects the user can see.")]

    monkeypatch.setattr(remote_mod, "fetch_remote", fake_remote)
    r = scan_target(parse_target(str(_gitlab_plugin(tmp_path))), store=Store(tmp_path / "t.db"), backend=_Judge(),
                    cfg=Config())
    assert seen == [GITLAB_MCP]
    assert not any(f.rule == "fetch.failed" for f in r.findings), r.findings
    assert r.verdict == Verdict.CLEAN, [(f.rule, f.evidence) for f in r.findings]


def test_gitlab_plugin_oauth_remote_is_low_not_suspicious(tmp_path, monkeypatch, no_git):
    def needs_signin(url, timeout_s):
        raise remote_mod.RemoteAuthRequired("remote server answered HTTP 401; sign-in required")

    monkeypatch.setattr(remote_mod, "fetch_remote", needs_signin)
    r = scan_target(parse_target(str(_gitlab_plugin(tmp_path))), store=Store(tmp_path / "t.db"), backend=_Judge(),
                    cfg=Config())
    assert {(f.rule, f.severity) for f in r.findings} == {("fetch.auth-required", Severity.LOW)}
    assert r.verdict == Verdict.CLEAN


def test_gitlab_plugin_unreachable_remote_still_fails_closed(tmp_path, monkeypatch, no_git):
    def down(url, timeout_s):
        raise FetchError("remote MCP server unreachable or invalid (http: ConnectError)")

    monkeypatch.setattr(remote_mod, "fetch_remote", down)
    r = scan_target(parse_target(str(_gitlab_plugin(tmp_path))), store=Store(tmp_path / "t.db"), backend=_Judge(),
                    cfg=Config())
    f = next(f for f in r.findings if f.rule == "fetch.failed")
    assert f.severity == Severity.MED and "[server gitlab]" in f.evidence and "git failed" not in f.evidence
    assert r.verdict == Verdict.SUSPICIOUS


def test_fetch_target_remote_kind_for_gitlab_api(monkeypatch, no_git):
    monkeypatch.setattr(remote_mod, "fetch_remote", lambda url, t: ("2", []))
    f = fetch_target(target_from_url(GITLAB_MCP))
    assert f.target.kind == "remote" and f.artifact_type == "mcp"
