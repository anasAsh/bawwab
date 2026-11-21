"""Task 16a: the public Top 100 report (report/collect.py, scan.py, build_site.py)."""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from report import build_site, collect, scan  # noqa: E402

SHA = "a" * 40
HOSTILE = '<script>alert("x")</script><img src=x onerror=alert(1)>"\'&'


def _npm_target(name: str = "demo-mcp", ver: str = "1.0.0", rank: int = 1) -> dict:
    row = {
        "kind": "mcp", "name": name, "source": "npm", "version": ver, "commit": None, "spec": f"{name}@{ver}",
        "url": f"https://www.npmjs.com/package/{name}/v/{ver}",
        "popularity": {"metric": "npm_weekly_downloads", "value": 10, "collected_at": "2026-11-20",
                       "source_url": "https://api.npmjs.org/x"},
        "selection": "ranked", "rank": rank, "kind_rank": rank,
    }
    row["id"] = collect.target_id(row)
    return row


def _skill_target(path: str, rank: int = 2) -> dict:
    row = {
        "kind": "skill", "name": path.rsplit("/", 1)[-1], "source": "github", "version": None, "commit": SHA,
        "repo": "owner/repo", "path": path, "spec": f"git:https://github.com/owner/repo.git@{SHA}#{path}",
        "url": f"https://github.com/owner/repo/tree/{SHA}/{path}",
        "popularity": {"metric": "github_stars", "value": 5, "collected_at": "2026-11-20", "source_url": "https://x"},
        "selection": "ranked", "rank": rank, "kind_rank": 1,
    }
    row["id"] = collect.target_id(row)
    return row


def _finding(rule="exfil.combo", sev="med", evidence="x", file="index.js", line=3, counted=True) -> dict:
    return {"key": scan.finding_key(rule, file, line, evidence), "rule": rule, "severity": sev, "source": "static",
            "file": file, "line": line, "evidence": evidence, "counted": counted}


def _result(t: dict, verdict="suspicious", findings=None, status="ok", error=None) -> dict:
    return {"id": t["id"], "spec": t["spec"], "kind": t["kind"], "name": t["name"], "status": status,
            "verdict": verdict, "error": error, "findings": findings or [], "resolved_version": "1.0.0",
            "artifact_type": None, "duration_s": 1.0, "scanned_at": "2026-11-20T00:00:00+00:00",
            "bawwab_commit": "c" * 40, "bawwab_dirty": False, "ruleset_version": "r1"}


def _write(tmp: Path, targets: list[dict], results: dict, review: dict) -> tuple[Path, Path, Path]:
    tp, rp, vp = tmp / "targets.json", tmp / "results.json", tmp / "review.json"
    tp.write_text(json.dumps({"schema": collect.SCHEMA_VERSION, "targets": targets}))
    rp.write_text(json.dumps({"schema": 1, "bawwab_commit": "c" * 40, "ruleset_version": "r1", "timeout_s": 600,
                              "results": results}))
    vp.write_text(json.dumps({"targets": review}))
    return tp, rp, vp


def _site_text(out: Path) -> str:
    return "\n".join(p.read_text() for p in sorted(out.rglob("*.html")))


# ------------------------------------------------------------------ escaping

def test_hostile_evidence_names_and_paths_are_escaped(tmp_path):
    t = _npm_target()
    sk = _skill_target('skills/<script>x</script>')
    f1 = _finding(evidence=HOSTILE, file='lib/"><script>alert(2)</script>.js')
    f2 = _finding(rule="credential-access", sev="low", evidence="</pre><script>alert(3)</script>", counted=False)
    results = {t["id"]: _result(t, findings=[f1, f2]),
               sk["id"]: _result(sk, verdict=None, status="error", error="<script>alert(4)</script>")}
    review = {t["id"]: {"summary": "<b>summary</b>", "findings": [
        {"match": {"key": f1["key"]}, "status": "false-positive", "note": "<script>alert(5)</script>"}]}}
    out = tmp_path / "site"
    build_site.build(*_write(tmp_path, [t, sk], results, review), out)
    html = _site_text(out)
    assert "alert(" in html  # the hostile text is shown...
    for n in range(1, 6):  # ...but only ever as escaped text
        assert f"<script>alert({n})" not in html
    assert "<script>alert(" not in html and "<img src=x" not in html and "<b>summary</b>" not in html
    assert "&lt;script&gt;" in html
    # The only script anywhere is our own table script, allowed by hash in the CSP.
    scripts = re.findall(r"<script>(.*?)</script>", html, re.S)
    assert scripts == [build_site.TABLE_JS]
    for p in out.rglob("*.html"):
        assert "Content-Security-Policy" in p.read_text()
        assert "'unsafe-inline'" not in p.read_text()
    # Page file names come from validated ids, never from scanned text.
    assert all(re.fullmatch(r"[a-z0-9._-]+\.html", p.name) for p in out.rglob("*.html"))


def test_escape_helpers_strip_controls_and_quote():
    assert build_site.t('a\x1b[31m"<x>​') == "a&quot;&lt;x&gt;"
    assert build_site.safe_url("javascript:alert(1)") == "#"
    assert build_site.safe_url("https://github.com/a/b") == "https://github.com/a/b"


# ------------------------------------------------------------------ review gate

def test_refuses_to_publish_unreviewed_non_clean_target(tmp_path):
    t = _npm_target()
    results = {t["id"]: _result(t, findings=[_finding()])}
    out = tmp_path / "site"
    with pytest.raises(build_site.PublishRefused) as ex:
        build_site.build(*_write(tmp_path, [t], results, {}), out)
    assert any("unreviewed" in p and t["id"] in p for p in ex.value.problems)
    assert not out.exists()


def test_refuses_when_only_some_findings_are_reviewed(tmp_path):
    t = _npm_target()
    f1, f2 = _finding(evidence="one"), _finding(rule="obfuscation.blob", evidence="two")
    results = {t["id"]: _result(t, findings=[f1, f2])}
    review = {t["id"]: {"findings": [{"match": {"key": f1["key"]}, "status": "confirmed", "note": "real"}]}}
    with pytest.raises(build_site.PublishRefused) as ex:
        build_site.build(*_write(tmp_path, [t], results, review), tmp_path / "site")
    assert len(ex.value.problems) == 1 and "obfuscation.blob" in ex.value.problems[0]


def test_cli_exits_2_and_writes_nothing_when_refusing(tmp_path, capsys):
    t = _npm_target()
    tp, rp, vp = _write(tmp_path, [t], {t["id"]: _result(t, verdict="malicious", findings=[_finding(sev="critical")])}, {})
    out = tmp_path / "site"
    assert build_site.main(["--targets", str(tp), "--results", str(rp), "--review", str(vp), "--out", str(out)]) == 2
    assert "REFUSING TO PUBLISH" in capsys.readouterr().err
    assert not out.exists()


def test_rule_level_review_with_file_glob_and_low_findings_need_no_review(tmp_path):
    t = _npm_target()
    fs = [_finding(file="bin/cli.mjs", evidence="a"), _finding(file="bin/cli.mjs", line=9, evidence="b"),
          _finding(rule="credential-access", sev="low", counted=False)]
    review = {t["id"]: {"findings": [{"match": {"rule": "exfil.combo", "file": "bin/*"},
                                      "status": "false-positive", "note": "bundled deps"}]}}
    out = tmp_path / "site"
    views, _ = build_site.build(*_write(tmp_path, [t], {t["id"]: _result(t, findings=fs)}, review), out)
    assert views[0].outcome == "Reviewed: false alarm"
    page = (out / "t" / f"{t['id']}.html").read_text()
    assert "Known false alarm" in page and "Not malicious, needs a look" in page
    assert "dispute" in page.lower() and "github.com/anasAsh/bawwab/issues/new" in page
    # a glob that does not match leaves the finding unreviewed
    review[t["id"]]["findings"][0]["match"]["file"] = "dist/*"
    with pytest.raises(build_site.PublishRefused):
        build_site.build(*_write(tmp_path, [t], {t["id"]: _result(t, findings=fs)}, review), out)


def test_review_entries_need_valid_status_and_note(tmp_path):
    p = tmp_path / "r.json"
    p.write_text(json.dumps({"targets": {"x": {"findings": [{"match": {"rule": "r"}, "status": "fine", "note": ""}]}}}))
    with pytest.raises(ValueError, match="status"):
        build_site.load_review(p)


def test_shipped_review_file_is_valid_and_prefills_notion_r49():
    rv = build_site.load_review(ROOT / "report" / "review.json")
    notion = [v for k, v in rv["targets"].items() if "notion-mcp-server" in k]
    assert notion and notion[0]["findings"][0]["match"]["rule"] == "exfil.combo"
    assert notion[0]["findings"][0]["status"] == "false-positive"


# ------------------------------------------------------------------ targets schema

def test_shipped_targets_json_validates_and_has_the_agreed_split():
    doc = json.loads((ROOT / "report" / "targets.json").read_text())
    assert collect.validate_targets(doc) == []
    kinds = [t["kind"] for t in doc["targets"]]
    assert (kinds.count("mcp"), kinds.count("skill"), kinds.count("plugin")) == (50, 30, 20)
    assert len({t["id"] for t in doc["targets"]}) == 100


@pytest.mark.parametrize("mutate, needle", [
    (lambda t: t.update(version="latest", spec=f"{t['name']}@latest"), "version"),
    (lambda t: t.update(kind="extension"), "kind"),
    (lambda t: t["popularity"].update(collected_at="yesterday"), "collected_at"),
    (lambda t: t["popularity"].update(value=-1), "value"),
    (lambda t: t.update(url="http://insecure"), "url"),
    (lambda t: t.update(spec="other@1.0.0"), "spec"),
    (lambda t: t.pop("popularity"), "popularity"),
])
def test_targets_schema_rejects_bad_npm_entries(mutate, needle):
    t = _npm_target()
    assert collect.validate_target(t) == []
    mutate(t)
    assert any(needle in e for e in collect.validate_target(t))


def test_targets_schema_requires_pinned_commit_for_github():
    t = _skill_target("skills/pdf")
    assert collect.validate_target(t) == []
    t["commit"] = "main"
    assert any("commit" in e for e in collect.validate_target(t))
    t = _skill_target("skills/pdf")
    t["path"] = "../escape"
    assert any("path" in e for e in collect.validate_target(t))


def test_targets_schema_rejects_duplicate_ids():
    t = _npm_target()
    errs = collect.validate_targets({"schema": collect.SCHEMA_VERSION, "targets": [t, dict(t)]})
    assert any("duplicate" in e for e in errs)


# ------------------------------------------------------------------ errors are never clean

@pytest.mark.parametrize("result", [
    None,
    {"status": "error", "verdict": None, "spec": "demo-mcp@1.0.0"},
    {"status": "error", "verdict": "clean", "spec": "demo-mcp@1.0.0"},
    {"status": "ok", "verdict": "clean", "spec": "demo-mcp@0.9.0"},  # result for a different pin
    {"status": "ok", "verdict": "weird", "spec": "demo-mcp@1.0.0"},
])
def test_errors_missing_and_stale_results_are_not_verified(result):
    assert build_site.state_of(result, "demo-mcp@1.0.0") == "not-verified"


def test_error_target_page_says_not_verified_and_never_clean(tmp_path):
    t = _npm_target()
    r = _result(t, verdict="clean", status="error", error="timed out after 600 s")
    out = tmp_path / "site"
    views, _ = build_site.build(*_write(tmp_path, [t], {t["id"]: r}, {}), out)
    assert views[0].state == "not-verified"
    page = (out / "t" / f"{t['id']}.html").read_text()
    assert "Not verified" in page and "timed out after 600 s" in page
    assert build_site.VERDICT_LABEL["clean"] not in page
    assert 'data-state="not-verified"' in (out / "targets.html").read_text()


def test_scan_timeout_or_crash_is_recorded_as_error(tmp_path):
    r = scan.run_child({"id": "x", "spec": "demo-mcp@1.0.0"}, tmp_path, timeout=0.01)
    assert r["status"] == "error" and r["verdict"] is None and r["findings"] == []


def test_scan_exception_in_child_is_error_not_clean(monkeypatch, capsys, tmp_path):
    def boom(t, work):
        raise RuntimeError("network down")
    monkeypatch.setattr(scan, "scan_one", boom)
    scan.child_main(json.dumps({"spec": "demo-mcp@1.0.0"}), str(tmp_path))
    out = json.loads(capsys.readouterr().out.split("@@RESULT@@", 1)[1])
    assert out["status"] == "error" and out["verdict"] is None and "network down" in out["error"]


def test_scan_fetch_failure_maps_to_error(monkeypatch, tmp_path):
    from bawwab.scan import synthetic_report

    def fake_scan(t, **kw):
        assert kw["judge"] is False  # static rules only
        return synthetic_report("fetch failed: 404", "npm:demo-mcp@unfetched", t, "fetch.failed")
    monkeypatch.setattr("bawwab.scan.scan_target", fake_scan)
    r = scan.scan_one({"spec": "demo-mcp@1.0.0"}, tmp_path)
    assert r["status"] == "error" and "404" in r["error"]


def test_scan_refuses_the_real_home(monkeypatch, real_home):
    monkeypatch.setenv("HOME", str(real_home))
    with pytest.raises(SystemExit, match="isolated"):
        scan.check_isolated_env()


# ------------------------------------------------------------------ taxonomy (R62)

def test_findings_carry_taxonomy_tags_and_overview_lists_sources(tmp_path):
    tax = json.loads(build_site.TAXONOMY_PATH.read_text())
    t = _npm_target()
    f = _finding(rule="exfil.combo")
    review = {t["id"]: {"findings": [{"match": {"key": f["key"]}, "status": "confirmed", "note": "n"}]}}
    out = tmp_path / "site"
    build_site.build(*_write(tmp_path, [t], {t["id"]: _result(t, findings=[f])}, review), out)
    page = (out / "t" / f"{t['id']}.html").read_text()
    m = tax["rules"]["exfil.combo"]
    for i in m["atlas"]:
        assert f'href="https://atlas.mitre.org/techniques/{i}"' in page
        assert tax["known_ids"]["atlas"][i].replace("&", "&amp;") in page
    for i in m["owasp_llm"]:
        assert i in page and tax["known_ids"]["owasp_llm"][i] in page and "https://genai.owasp.org/llm-top-10/" in page
    index = (out / "index.html").read_text()
    assert ">Categories</h2>" in index
    for s in tax["sources"]:
        assert build_site.e(s["version"]) in index and s["retrieved"] in index


def test_taxonomy_tags_link_cwe_and_reject_malformed_ids():
    tax = {"rules": {"r": {"cwe": ["CWE-494", 'CWE-1"><script>'], "atlas": ["javascript:alert(1)"]}},
           "known_ids": {"cwe": {"CWE-494": "Download of Code Without Integrity Check"}}}
    html = build_site.taxonomy_tags("r", tax)
    assert 'href="https://cwe.mitre.org/data/definitions/494.html"' in html
    assert "Download of Code Without Integrity Check" in html
    assert "<script>" not in html and "javascript:" not in html
    assert build_site.taxonomy_tags("files.truncated", {"rules": {"files.truncated": {"cwe": []}}}) == ""


def test_review_file_glob_matches_files_in_a_folder():
    entries = [{"match": {"rule": "files.truncated", "file": "assets/*.png"}, "status": "expected-behaviour", "note": "n"}]
    for f in ("assets/app-icon.png", "assets/antigravity-logo.png"):
        assert build_site.match_review(entries, {"rule": "files.truncated", "file": f}) is entries[0]
    assert build_site.match_review(entries, {"rule": "files.truncated", "file": "assets/x.svg"}) is None
    assert build_site.match_review(entries, {"rule": "exfil.combo", "file": "assets/a.png"}) is None


def test_review_glob_stays_in_one_folder_and_keyless_entries_match_by_rule_only():
    assert build_site.glob_match("assets/*.png", "assets/a.png")
    assert not build_site.glob_match("assets/*.png", "assets/sub/a.png")
    assert build_site.glob_match("assets/**/*.png", "assets/sub/a.png")
    assert build_site.glob_match("assets/**/*.png", "assets/a.png")
    assert build_site.glob_match("bin/cli.mjs", "bin/cli.mjs") and not build_site.glob_match("bin/cli.mjs", "bin/cli_mjs")
    entries = [{"match": {"rule": "x"}, "status": "confirmed", "note": "n"}]
    assert build_site.match_review(entries, {"rule": "y", "file": "a"}) is None


def test_needs_review_lists_open_findings_without_writing_reviews(tmp_path):
    from report import needs_review

    t = _npm_target()
    f1 = _finding(evidence="one`\x1b[31mtwo")
    f2 = _finding(rule="obfuscation.blob", evidence="blob")
    res = {t["id"]: dict(_result(t, findings=[f1, f2, _finding(rule="deps.unpinned", sev="low", counted=False)]),
                         local_path="/var/tmp/x/pkgs/demo")}
    review = {"targets": {t["id"]: {"findings": [{"match": {"key": f1["key"]}, "status": "confirmed", "note": "n"}]}}}
    text, by_rule, n = needs_review.render([t], res, review)
    assert n == 1 and by_rule == {"obfuscation.blob": 1}
    assert "/var/tmp/x/pkgs/demo" in text and "NEEDS REVIEW" in text and "deps.unpinned" not in text
    assert "\x1b" not in text and "one'" in text


def test_resume_reuses_only_same_pin_commit_and_ruleset():
    prev = {"spec": "a@1", "bawwab_commit": "c1", "ruleset_version": "r1", "status": "ok"}
    assert scan.is_done(prev, "a@1", "c1", "r1")
    assert not scan.is_done(prev, "a@2", "c1", "r1")
    assert not scan.is_done(prev, "a@1", "c2", "r1")
    assert not scan.is_done(prev, "a@1", "c1", "r2")
    assert not scan.is_done(dict(prev, status="error"), "a@1", "c1", "r1", retry_errors=True)
    assert not scan.is_done(None, "a@1", "c1", "r1")


def test_index_leads_with_reviewed_outcome(tmp_path):
    """User decision 2026-11-20: the overview leads with flagged-vs-confirmed, not the raw 'malicious' count."""
    t, results, review = _malicious_fixture()
    out = tmp_path / "site"
    build_site.build(*_write(tmp_path, [t], results, review), out)
    index = (out / "index.html").read_text()
    assert "1 flagged by static rules · 0 confirmed harmful after hand-review." in index
    assert "checked by hand before publication" in index and "AI-assisted" not in index


def test_ai_assisted_reviews_are_not_called_hand_review(tmp_path):
    """User decision 2026-11-21: AI-assisted reviews say "review", with how many a maintainer also checked."""
    t, results, review = _malicious_fixture()
    for ent in review[t["id"]]["findings"]:
        ent["reviewer"], ent["spot_check"] = "Claude (AI-assisted review)", "maintainer, 2026-11-21"
    out = tmp_path / "site"
    build_site.build(*_write(tmp_path, [t], results, review), out)
    index = (out / "index.html").read_text()
    assert "0 confirmed harmful after review." in index and "hand-review" not in index and "by hand" not in index
    assert "Reviews were AI-assisted for 1 of the 1 flagged targets" in index
    assert "1 of them were also checked by a maintainer" in index


# ------------------------------------------------------------------ why it was flagged

def _why_section(page: str) -> str:
    """The 'Why it was flagged' section of a target page, up to the next heading."""
    start = page.index("Why it was flagged")
    end = page.find("<h2", start)
    return page[start:end if end >= 0 else None]


def _malicious_fixture():
    t = _npm_target()
    crit = _finding(rule="exfil.combo", sev="critical", evidence="fetch(process.env.TOKEN)")
    med = _finding(rule="install-script", sev="med", evidence="postinstall", file="package.json", line=1)
    review = {t["id"]: {"findings": [{"match": {"key": crit["key"]}, "status": "false-positive", "note": "n"},
                                     {"match": {"key": med["key"]}, "status": "expected-behaviour", "note": "n"}]}}
    results = {t["id"]: _result(t, verdict="malicious", findings=[crit, med])}
    return t, results, review


def test_flagged_target_page_says_why(tmp_path):
    t, results, review = _malicious_fixture()
    out = tmp_path / "site"
    views, _ = build_site.build(*_write(tmp_path, [t], results, review), out)
    assert build_site.why_flagged(views[0]) == [
        ("exfil.combo", build_site.CATALOG["exfil.combo"].title, 1, "index.js:3")]
    page = (out / "t" / f"{t['id']}.html").read_text()
    why = _why_section(page)
    assert "exfil.combo" in why and build_site.CATALOG["exfil.combo"].title in why and "index.js:3" in why
    assert "install-script" not in why  # lower severity: not the reason for the label...
    assert "install-script" in page     # ...but still listed under Findings
    assert page.index("Why it was flagged") < page.index("<h2>Findings")


def test_why_names_rule_id_when_rule_is_not_in_catalog(tmp_path):
    t = _npm_target()
    f = _finding(rule="new.rule-not-in-catalog", sev="high")
    review = {t["id"]: {"findings": [{"match": {"key": f["key"]}, "status": "false-positive", "note": "n"}]}}
    out = tmp_path / "site"
    views, _ = build_site.build(*_write(tmp_path, [t], {t["id"]: _result(t, findings=[f])}, review), out)
    assert build_site.why_flagged(views[0]) == [("new.rule-not-in-catalog", "new.rule-not-in-catalog", 1, "index.js:3")]
    assert "new.rule-not-in-catalog" in _why_section((out / "t" / f"{t['id']}.html").read_text())


def test_targets_list_has_why_column(tmp_path):
    t, results, review = _malicious_fixture()
    clean = _npm_target("clean-mcp", rank=2)
    results[clean["id"]] = _result(clean, verdict="clean")
    out = tmp_path / "site"
    views, _ = build_site.build(*_write(tmp_path, [t, clean], results, review), out)
    assert build_site.why_flagged(views[1]) == []
    listing = (out / "targets.html").read_text()
    rows = re.findall(r"<tr data-kind.*?</tr>", listing, re.S)
    assert ">Why</th>" in listing
    assert build_site.CATALOG["exfil.combo"].title in rows[0]
    assert '<td class="hide-sm why"></td>' in rows[1]


def test_why_escapes_hostile_paths(tmp_path):
    t = _npm_target()
    f1 = _finding(sev="high", file="<img src=x onerror=alert(1)>.js")
    f2 = _finding(rule='r"><img src=x onerror=alert(2)>', sev="high", evidence="y")
    review = {t["id"]: {"findings": [{"match": {"key": f["key"]}, "status": "false-positive", "note": "n"}
                                     for f in (f1, f2)]}}
    out = tmp_path / "site"
    build_site.build(*_write(tmp_path, [t], {t["id"]: _result(t, findings=[f1, f2])}, review), out)
    page = (out / "t" / f"{t['id']}.html").read_text()
    why = _why_section(page)
    assert "&lt;img src=x onerror=alert(1)&gt;.js" in why and "alert(2)" in why
    assert "<img" not in page and "<img" not in (out / "targets.html").read_text()


# ------------------------------------------------------------------ --allow-unreviewed (weekly CI build)

def _cli(tmp_path, targets, results, review, *extra) -> tuple[int, Path]:
    tp, rp, vp = _write(tmp_path, targets, results, review)
    out = tmp_path / "site"
    return build_site.main(["--targets", str(tp), "--results", str(rp), "--review", str(vp), "--out", str(out),
                            *extra]), out


def test_default_still_refuses_unreviewed(tmp_path, capsys):
    t = _npm_target()
    code, out = _cli(tmp_path, [t], {t["id"]: _result(t, findings=[_finding()])}, {})
    assert code == 2 and "REFUSING TO PUBLISH" in capsys.readouterr().err and not out.exists()
    with pytest.raises(build_site.PublishRefused):
        build_site.build(*_write(tmp_path, [t], {t["id"]: _result(t, findings=[_finding()])}, {}), out,
                         allow_unreviewed=False)


def test_allow_unreviewed_publishes_with_badges(tmp_path, capsys):
    t = _npm_target()
    code, out = _cli(tmp_path, [t], {t["id"]: _result(t, verdict="malicious", findings=[_finding(sev="critical")])},
                     {}, "--allow-unreviewed")
    assert code == 0
    assert "unreviewed" in capsys.readouterr().err  # still listed, as a warning
    page = (out / "t" / f"{t['id']}.html").read_text()
    assert re.search(r'<span class="badge b-unreviewed">Not yet reviewed</span>', page)
    assert "Not yet reviewed: rule verdict only" in page
    assert "Not yet reviewed: rule verdict only" in (out / "targets.html").read_text()
    assert "Reviewed: false alarm" not in page


def test_mixed_reviewed_and_unreviewed_is_not_yet_reviewed(tmp_path):
    t = _npm_target()
    f1, f2 = _finding(evidence="one"), _finding(rule="obfuscation.blob", evidence="two")
    review = {t["id"]: {"findings": [{"match": {"key": f1["key"]}, "status": "false-positive", "note": "fine"}]}}
    out = tmp_path / "site"
    views, _ = build_site.build(*_write(tmp_path, [t], {t["id"]: _result(t, findings=[f1, f2])}, review), out,
                                allow_unreviewed=True)
    assert views[0].outcome == "Not yet reviewed: rule verdict only"
    page = (out / "t" / f"{t['id']}.html").read_text()
    assert "Known false alarm" in page and page.count('class="badge b-unreviewed">Not yet reviewed<') == 1


def test_allow_unreviewed_headline_counts(tmp_path):
    a, b, c = _npm_target("a-mcp", rank=1), _npm_target("b-mcp", rank=2), _npm_target("c-mcp", rank=3)
    fa, fb = _finding(evidence="a"), _finding(evidence="b")
    results = {a["id"]: _result(a, findings=[fa]), b["id"]: _result(b, findings=[fb]),
               c["id"]: _result(c, verdict="clean")}
    review = {a["id"]: {"findings": [{"match": {"key": fa["key"]}, "status": "false-positive", "note": "n"}]}}
    out = tmp_path / "site"
    build_site.build(*_write(tmp_path, [a, b, c], results, review), out, allow_unreviewed=True)
    index = (out / "index.html").read_text()
    assert "2 flagged by static rules · 1 reviewed · 0 confirmed harmful · 1 awaiting review" in index
    assert "Scanned 2026-11-20. 1 flagged targets are awaiting hand-review" in index
    assert "Every target that was not clean was checked by hand" not in index
    # Everything reviewed: today's wording, no banner, even with the flag on.
    review[b["id"]] = {"findings": [{"match": {"key": fb["key"]}, "status": "confirmed", "note": "n"}]}
    build_site.build(*_write(tmp_path, [a, b, c], results, review), out, allow_unreviewed=True)
    index = (out / "index.html").read_text()
    assert "2 flagged by static rules · 1 confirmed harmful after hand-review." in index
    assert "awaiting" not in index


def test_allow_unreviewed_still_blocks_unsafe_ids(tmp_path):
    t = _npm_target()
    bad = dict(_npm_target("bad-mcp", rank=2), id="../Bad ID")
    results = {t["id"]: _result(t, findings=[_finding()])}
    _, problems, _ = build_site.plan([t, bad], results, {"targets": {}}, allow_unreviewed=True)
    assert problems == ["'../Bad ID': unsafe target id"]
    # build() never gets that far: the targets file is validated first, flag or not.
    with pytest.raises(ValueError):
        build_site.build(*_write(tmp_path, [t, bad], results, {}), tmp_path / "site", allow_unreviewed=True)
    assert not (tmp_path / "site").exists()
    # A flagged verdict with nothing to review is malformed input, not "unreviewed": still blocks.
    results = {t["id"]: _result(t, findings=[])}
    with pytest.raises(build_site.PublishRefused):
        build_site.build(*_write(tmp_path, [t], results, {}), tmp_path / "site", allow_unreviewed=True)


# ------------------------------------------------------------------ discovery: meta tags, sitemap, robots, llms.txt

def test_pages_carry_description_canonical_and_og_tags(tmp_path):
    t = _npm_target()
    out = tmp_path / "site"
    build_site.build(*_write(tmp_path, [t], {t["id"]: _result(t, verdict="clean", findings=[])}, {}), out)
    base = "https://anasash.github.io/bawwab/"
    for rel, url in (("index.html", base), ("targets.html", base + "targets.html"),
                     ("method.html", base + "method.html"), (f"t/{t['id']}.html", f"{base}t/{t['id']}.html")):
        page = (out / rel).read_text()
        assert '<meta name="description" content="' in page, rel
        assert f'<link rel="canonical" href="{url}">' in page and f'<meta property="og:url" content="{url}">' in page, rel
    assert "MCP servers, Claude Code plugins and Agent Skills" in (out / "index.html").read_text()


def test_hostile_name_is_escaped_in_meta_tags(tmp_path):
    t = _npm_target(name='"><script>alert(9)</script>')
    out = tmp_path / "site"
    build_site.build(*_write(tmp_path, [t], {t["id"]: _result(t, verdict="clean", findings=[])}, {}), out)
    page = (out / "t" / f"{t['id']}.html").read_text()
    assert "<script>alert(9)" not in page and "&lt;script&gt;alert(9)" in page


def test_robots_sitemap_and_llms_txt(tmp_path):
    t = _npm_target()
    out = tmp_path / "site"
    build_site.build(*_write(tmp_path, [t], {t["id"]: _result(t, verdict="clean", findings=[])}, {}), out,
                     repo="Some-Owner/proj")
    base = "https://some-owner.github.io/proj/"
    assert (out / "robots.txt").read_text() == f"User-agent: *\nAllow: /\nSitemap: {base}sitemap.xml\n"
    sm = (out / "sitemap.xml").read_text()
    assert sm.count("<url>") == 4 and f"<loc>{base}t/{t['id']}.html</loc>" in sm
    llms = (out / "llms.txt").read_text()
    assert llms.startswith("# Bawwab: Top 1 scan\n") and f"]({base}targets.html)" in llms
    assert "github.com/Some-Owner/proj" in llms
