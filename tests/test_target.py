from pathlib import Path

import pytest

from bawwab.fetch.target import parse_target, target_from_command, target_from_url


@pytest.mark.parametrize(
    "spec,kind,name,version",
    [
        ("@scope/pkg@1.2.0", "npm", "@scope/pkg", "1.2.0"),
        ("@scope/pkg", "npm", "@scope/pkg", None),
        ("pkg", "npm", "pkg", None),
        ("pkg@2", "npm", "pkg", "2"),
        ("pypi:requests==2.0", "pypi", "requests", "2.0"),
        ("pypi:requests", "pypi", "requests", None),
        ("docker:img:tag", "docker", "img", "tag"),
        ("docker:img", "docker", "img", None),
    ],
)
def test_parse_named(spec, kind, name, version):
    t = parse_target(spec)
    assert (t.kind, t.name, t.version, t.raw) == (kind, name, version, spec)


@pytest.mark.parametrize(
    "spec",
    [
        "https://github.com/a/b",
        "https://gitlab.com/a/b",
        "https://bitbucket.org/a/b",
        "https://codeberg.org/a/b",
        "git@github.com:a/b.git",
        "https://example.com/x/y.git",
    ],
)
def test_parse_git(spec):
    t = parse_target(spec)
    assert t.kind == "git" and t.url == spec


def test_parse_remote():
    t = parse_target("https://x.io/mcp")
    assert t.kind == "remote" and t.url == "https://x.io/mcp"


def test_parse_local(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    (tmp_path / "dir").mkdir()
    t = parse_target("./dir")
    assert t.kind == "local" and t.path == str((tmp_path / "dir").resolve())
    t = parse_target("/abs")
    assert t.kind == "local" and t.path == "/abs"


@pytest.mark.parametrize(
    "cmd,args,kind,name,version",
    [
        ("npx", ["-y", "@a/b@1"], "npm", "@a/b", "1"),
        ("npx", ["--yes", "pkg"], "npm", "pkg", None),
        ("npx", ["-p", "foo@2", "bar"], "npm", "foo", "2"),
        ("uvx", ["mcp-x"], "pypi", "mcp-x", None),
        ("uvx", ["--from", "mcp-x==1.0", "mcp-x"], "pypi", "mcp-x", "1.0"),
        ("python", ["-m", "pkg"], "pypi", "pkg", None),
        ("python3", ["-m", "pkg", "--flag"], "pypi", "pkg", None),
        ("docker", ["run", "-i", "img"], "docker", "img", None),
        ("docker", ["run", "--rm", "-e", "A=B", "-i", "img:1", "arg"], "docker", "img", "1"),
        ("/usr/bin/npx", ["pkg"], "npm", "pkg", None),
    ],
)
def test_from_command(cmd, args, kind, name, version):
    t = target_from_command(cmd, args)
    assert t is not None
    assert (t.kind, t.name, t.version) == (kind, name, version)


def test_from_command_local():
    t = target_from_command("node", ["/p/index.js"])
    assert t is not None and t.kind == "local" and t.path == "/p"


def test_from_command_none():
    assert target_from_command("bash", ["-c", "echo hi"]) is None
    assert target_from_command("npx", ["-y"]) is None
    assert target_from_command("", []) is None


def test_from_url():
    assert target_from_url("https://github.com/a/b").kind == "git"
    assert target_from_url("https://x.io/mcp").kind == "remote"


def test_uvx_with_value_not_taken_as_package():
    from bawwab.fetch.target import runner_extras, target_from_command

    t = target_from_command("uvx", ["--with", "extra", "--python", "3.12", "pkg"])
    assert (t.kind, t.name) == ("pypi", "pkg")
    extras, reasons = runner_extras("uvx", ["--with", "extra", "--index-url", "u", "pkg"])
    assert [e.name for e in extras] == ["extra"] and reasons == ["custom package index"]
    extras, reasons = runner_extras("npx", ["-y", "-p", "a", "-p", "b@2", "cmd"])
    assert [(e.name, e.version) for e in extras] == [("b", "2")] and reasons == []
