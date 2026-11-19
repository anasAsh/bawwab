from __future__ import annotations

from datetime import UTC, datetime, timedelta

from bawwab.scan.identity import identity_checks
from bawwab.types import PackageMeta, Severity

NOW = datetime(2026, 11, 19, tzinfo=UTC)


def rules(meta, now=NOW):
    return {(f.rule, f.severity) for f in identity_checks(meta, now)}


def test_typosquat_scoped():
    found = identity_checks(PackageMeta("@modelcontextprotocol/server-githb"), NOW)
    assert [(f.rule, f.severity, f.source) for f in found] == [("identity.typosquat", Severity.MED, "identity")]
    assert "server-github" in found[0].evidence


def test_typosquat_exact_and_unrelated_are_clean():
    assert rules(PackageMeta("@modelcontextprotocol/server-github")) == set()
    assert rules(PackageMeta("left-padder-xyz")) == set()


def test_typosquat_unscoped_comparison():
    assert ("identity.typosquat", Severity.MED) in rules(PackageMeta("@evil/server-githb"))
    assert ("identity.typosquat", Severity.MED) in rules(PackageMeta("mcp-server-fech"))


def test_new_package():
    assert rules(PackageMeta("fresh", created_at=NOW - timedelta(days=2))) == {("identity.new-package", Severity.MED)}
    assert rules(PackageMeta("fresh", created_at=NOW - timedelta(days=30))) == set()
    naive = datetime(2026, 11, 18)
    assert ("identity.new-package", Severity.MED) in rules(PackageMeta("fresh", created_at=naive))


def test_default_now_is_current_time():
    meta = PackageMeta("fresh", created_at=datetime.now(UTC) - timedelta(hours=1))
    assert [f.rule for f in identity_checks(meta)] == ["identity.new-package"]


def test_repo_mismatch():
    assert rules(PackageMeta("cool-tool", repo_url="https://github.com/other/unrelated")) == {("identity.repo-mismatch", Severity.LOW)}
    assert rules(PackageMeta("cool-tool", repo_url="https://github.com/me/cool-tool.git")) == set()
    assert rules(PackageMeta("@modelcontextprotocol/server-github", repo_url="git+https://github.com/modelcontextprotocol/servers.git")) == set()
    assert rules(PackageMeta("cool-tool", repo_url="git@github.com:me/cool_tool.git")) == set()
    assert rules(PackageMeta("cool-tool")) == set()
