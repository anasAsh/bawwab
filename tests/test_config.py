import json

from bawwab.config import DEFAULT_CONFIG, is_trusted, load_config
from bawwab.store import open_store
from bawwab.types import Mode, Severity


def _write(p, data):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data if isinstance(data, str) else json.dumps(data))


def test_defaults(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    cfg = load_config()
    assert cfg == DEFAULT_CONFIG
    assert cfg.mode == Mode.STANDARD
    assert cfg.llm_model == "claude-sonnet-5-5"
    assert cfg.trusted == ["@modelcontextprotocol/*"]
    assert cfg.llm_backend == "claude-cli"


def test_project_only_tightens(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("BAWWAB_HOME", str(home))
    proj = tmp_path / "proj"
    _write(
        proj / ".claude" / "bawwab.json",
        {"mode": "deep", "thresholds": {"suspicious": "low"}, "trusted": ["*"], "llm": {"backend": "api"}},
    )
    cfg = load_config(proj)
    assert cfg.mode == Mode.DEEP
    assert cfg.suspicious == Severity.LOW
    assert cfg.trusted == []  # "*" is not literally in the global list: tightened away
    assert cfg.llm_backend == "claude-cli"


def test_project_cannot_loosen(tmp_path, monkeypatch):
    home = tmp_path / "home"
    monkeypatch.setenv("BAWWAB_HOME", str(home))
    _write(home / "config.json", {"mode": "deep", "thresholds": {"suspicious": "low"}})
    proj = tmp_path / "proj"
    _write(proj / ".claude" / "bawwab.json", {"mode": "standard", "thresholds": {"suspicious": "high"}})
    cfg = load_config(proj)
    assert cfg.mode == Mode.DEEP and cfg.suspicious == Severity.LOW


def test_global_llm_and_trusted(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    _write(tmp_path / "config.json", {"llm": {"backend": "api", "model": "m"}, "trusted": ["a/*", "b"]})
    cfg = load_config()
    assert (cfg.llm_backend, cfg.llm_model, cfg.trusted) == ("api", "m", ["a/*", "b"])
    proj = tmp_path / "p"
    _write(proj / ".claude" / "bawwab.json", {"trusted": ["b", "a/x", "evil"]})
    assert sorted(load_config(proj).trusted) == ["a/x", "b"]


def test_is_trusted():
    assert is_trusted(DEFAULT_CONFIG, "@modelcontextprotocol/server-git")
    assert not is_trusted(DEFAULT_CONFIG, "evil-pkg")


def test_invalid_json_defaults_and_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    _write(tmp_path / "config.json", "{not json")
    assert load_config() == DEFAULT_CONFIG
    rows = open_store()._conn.execute("select event from audit").fetchall()
    assert ("config.invalid",) in [tuple(r) for r in rows]


def test_unknown_keys_and_bad_enums(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    _write(tmp_path / "config.json", {"bogus": 1, "mode": "weird", "thresholds": {"suspicious": "high", "malicious": "nope"}})
    cfg = load_config()
    assert cfg.mode == Mode.STANDARD
    assert cfg.suspicious == Severity.HIGH
    assert cfg.malicious == DEFAULT_CONFIG.malicious


def _trusted_with(tmp_path, monkeypatch, proj_trusted):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path / "h"))
    proj = tmp_path / "p"
    _write(proj / ".claude" / "bawwab.json", {"trusted": proj_trusted})
    return load_config(proj).trusted


def test_trusted_glob_metachars_not_widening(tmp_path, monkeypatch):
    assert _trusted_with(tmp_path, monkeypatch, ["@modelcontextprotocol/?"]) == []
    assert _trusted_with(tmp_path, monkeypatch, ["[ab]x"]) == []
    assert _trusted_with(tmp_path, monkeypatch, []) == []
    assert _trusted_with(tmp_path, monkeypatch, ["@modelcontextprotocol/*"]) == ["@modelcontextprotocol/*"]
    assert _trusted_with(tmp_path, monkeypatch, ["@modelcontextprotocol/server-git"]) == [
        "@modelcontextprotocol/server-git"
    ]
