"""The weekly top-100 report workflow (.github/workflows/report.yml): schedule, permissions, pinning."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOW = ROOT / ".github" / "workflows" / "report.yml"


@pytest.fixture(scope="module")
def wf() -> dict:
    return yaml.safe_load(WORKFLOW.read_text())


def _on(wf: dict) -> dict:
    return wf.get("on", wf.get(True))  # YAML 1.1 reads a bare `on` key as True


def _steps(wf: dict, job: str) -> list[dict]:
    return wf["jobs"][job]["steps"]


def _step(wf: dict, job: str, needle: str) -> dict:
    hits = [s for s in _steps(wf, job) if needle in (s.get("run") or "")]
    assert len(hits) == 1, f"expected one {job} step running {needle!r}, got {len(hits)}"
    return hits[0]


def test_runs_weekly_and_on_demand(wf):
    on = _on(wf)
    assert [c["cron"] for c in on["schedule"]] == ["0 6 * * 1"]
    assert "workflow_dispatch" in on
    assert wf["concurrency"]["group"] == "report"


def test_permissions_are_least_privilege(wf):
    assert wf.get("permissions") == {}  # nothing by default; each job asks for its own
    assert wf["jobs"]["scan"]["permissions"] == {"contents": "read"}
    assert wf["jobs"]["deploy"]["permissions"] == {"pages": "write", "id-token": "write"}
    assert set(wf["jobs"]) == {"scan", "deploy"}


def test_every_action_is_pinned_by_full_sha():
    text = WORKFLOW.read_text()
    uses = re.findall(r"uses:\s*(\S+)(.*)", text)
    assert uses
    for ref, comment in uses:
        assert re.search(r"@[0-9a-f]{40}$", ref), ref
        assert re.search(r"#\s*v\d+\.\d+\.\d+", comment), f"{ref}: tag comment missing"


def test_scan_job_has_no_secrets_and_no_stored_token(wf):
    for s in _steps(wf, "scan"):
        assert "secrets." not in repr(s), s
    checkout = next(s for s in _steps(wf, "scan") if "actions/checkout@" in (s.get("uses") or ""))
    assert checkout["with"]["ref"] == "${{ env.SOURCE_REF }}"
    assert checkout["with"]["persist-credentials"] is False
    assert wf["env"]["SOURCE_REF"] == "main"


def test_scan_job_steps(wf):
    scan = wf["jobs"]["scan"]
    assert scan["timeout-minutes"] == 300  # ~300 targets; a job may run at most 360
    collect = _step(wf, "scan", "report/collect.py --refresh")
    assert collect["env"]["GH_TOKEN"] == "${{ github.token }}"
    assert "--mcp 250 --skills 150 --plugins 100" in collect["run"]
    assert "--allow-unreviewed" in _step(wf, "scan", "report/build_site.py")["run"]
    assert "GITHUB_STEP_SUMMARY" in _step(wf, "scan", "report/needs_review.py")["run"]
    scan_step = _step(wf, "scan", "report/run_scan.sh")
    assert "REPORT_PYTHON=.venv/bin/python" in scan_step["run"]
    # scan.py refuses a work dir inside the real home, and $RUNNER_TEMP is under /home/runner on GitHub
    work = scan_step["run"].split("REPORT_WORK=", 1)[1].split()[0]
    assert work.startswith("/var/tmp/") and "RUNNER_TEMP" not in scan_step["run"]
    pages = next(s for s in _steps(wf, "scan") if "upload-pages-artifact@" in (s.get("uses") or ""))
    assert pages["with"]["path"] == "report/out/site"
    data = next(s for s in _steps(wf, "scan") if "/upload-artifact@" in (s.get("uses") or ""))
    assert data["with"]["name"] == "report-data"
    assert "report/targets.json" in data["with"]["path"] and "report/results.json" in data["with"]["path"]
    assert wf["env"]["RESULTS"] == "report/results.json"
    for needle in ("report/build_site.py", "report/needs_review.py", "report/run_scan.sh"):
        assert '"$RESULTS"' in _step(wf, "scan", needle)["run"], needle


def test_short_or_failed_collect_stops_before_scanning(wf):
    """A failed or empty collect must fail the scan job, so deploy never runs and the live site stays."""
    runs = [s.get("run") or "" for s in _steps(wf, "scan")]
    i_collect = next(i for i, r in enumerate(runs) if "report/collect.py" in r)
    i_check = next(i for i, r in enumerate(runs) if "collect.load_targets" in r)
    i_scan = next(i for i, r in enumerate(runs) if "report/run_scan.sh" in r)
    assert i_collect < i_check < i_scan
    assert 'n["mcp"] >= 100' in runs[i_check] and 'n["plugin"] >= 80' in runs[i_check]  # floors, not exact counts
    assert all("continue-on-error" not in s for s in _steps(wf, "scan"))


def test_schedule_always_rescans_and_a_manual_run_may_publish_committed_data(wf):
    on = wf.get("on") or wf.get(True)
    assert on["workflow_dispatch"]["inputs"]["rescan"] == {
        "description": on["workflow_dispatch"]["inputs"]["rescan"]["description"], "type": "boolean", "default": True}
    assert wf["env"]["RESCAN"] == "${{ github.event_name == 'schedule' || inputs.rescan }}"
    gated = [s for s in _steps(wf, "scan") if any(k in (s.get("run") or "") for k in
                                                   ("report/collect.py", "collect.load_targets", "report/run_scan.sh"))]
    assert len(gated) == 3 and all(s.get("if") == "env.RESCAN == 'true'" for s in gated)
    assert "if" not in _step(wf, "scan", "report/build_site.py")  # the build always runs


def test_deploy_job(wf):
    deploy = wf["jobs"]["deploy"]
    assert deploy["needs"] == "scan"
    assert deploy["environment"]["name"] == "github-pages"
    assert any("actions/deploy-pages@" in (s.get("uses") or "") for s in deploy["steps"])
    assert all("checkout" not in (s.get("uses") or "") for s in deploy["steps"])  # never sees the packages


def test_dispute_template_matches_the_report_copy():
    tpl = ROOT / ".github" / "ISSUE_TEMPLATE" / "dispute.md"
    assert tpl.read_text() == (ROOT / "report" / "ISSUE_TEMPLATE_dispute.md").read_text()
