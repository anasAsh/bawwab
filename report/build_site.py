"""Turn report/out/results.json + report/review.json into a static site in report/out/site/.

    uv run python report/build_site.py [--repo OWNER/NAME] [--out report/out/site]

Publishing gate: every target whose static verdict is not clean must have a review entry for each of
its counted findings (severity at or above the suspicious threshold). If any is missing the build
REFUSES (exit 2) and lists what still needs a human look; nothing is written.

Everything that came out of a scan (names, paths, evidence, error text) is hostile input. It is
sanitised with Bawwab's own sanitiser and HTML-escaped before it reaches a page, and every page
carries a Content-Security-Policy that only allows the one inline script and style we ship (by hash),
so even a missed escape could not run code.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import html
import json
import re
import shutil
import sys
import urllib.parse
from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from bawwab.report import sanitise  # noqa: E402
from bawwab.scan.rules.catalog import CATALOG  # noqa: E402
from report.collect import load_targets  # noqa: E402

REPORT = ROOT / "report"
TAXONOMY_PATH = ROOT / "bawwab" / "scan" / "rules" / "data" / "taxonomy.json"
# scheme key -> (short label, id pattern, link for one id). OWASP pages have no stable per-id URL, so
# their tags link to the official list; ATLAS and CWE link to the entry itself.
SCHEMES = {
    "owasp_llm": ("OWASP LLM", re.compile(r"^LLM\d{2}$"), lambda i: "https://genai.owasp.org/llm-top-10/"),
    "owasp_agentic": ("OWASP Agentic", re.compile(r"^ASI\d{2}$"),
                      lambda i: "https://genai.owasp.org/resource/owasp-top-10-for-agentic-applications-for-2026/"),
    "atlas": ("MITRE ATLAS", re.compile(r"^AML\.T\d{4}(\.\d{3})?$"), lambda i: f"https://atlas.mitre.org/techniques/{i}"),
    "cwe": ("CWE", re.compile(r"^CWE-\d{1,5}$"), lambda i: f"https://cwe.mitre.org/data/definitions/{i[4:]}.html"),
}
DEFAULT_REPO = "anasAsh/bawwab"
STATUSES = {
    "confirmed": "Confirmed by review",
    "false-positive": "Known false alarm",
    "expected-behaviour": "Expected for what this tool does",
}
VERDICT_LABEL = {
    "clean": "No issues found",
    "suspicious": "Not malicious, needs a look",
    "malicious": "Flagged as possibly malicious",
    "not-verified": "Not verified",
}
VERDICT_NOTE = {
    "clean": "Bawwab's static rules found nothing at or above the warning level.",
    "suspicious": ("Bawwab's static rules found patterns that deserve a human look. This is not a finding "
                   "that the package is malicious; the review notes below say what each pattern turned out to be."),
    "malicious": ("Bawwab's static rules matched a pattern it treats as critical. Read the review notes: "
                  "a reviewed false alarm is marked as such."),
    "not-verified": ("The scan did not finish (download failure, timeout or scanner error), so this target "
                     "was not checked. This says nothing either way about whether it is safe."),
}
KIND_LABEL = {"mcp": "MCP server", "skill": "Skill", "plugin": "Plugin"}
_ID = re.compile(r"^[a-z0-9][a-z0-9._-]{0,120}$")


def load_taxonomy(path: Path = TAXONOMY_PATH) -> dict:
    if not path.exists():
        return {"rules": {}, "known_ids": {}, "sources": []}
    d = json.loads(path.read_text())
    return {"rules": d.get("rules") or {}, "known_ids": d.get("known_ids") or {}, "sources": d.get("sources") or []}


def taxonomy_tags(rule: str, tax: dict) -> str:
    """Small linked tags (id + title) for every scheme a rule maps to. Ids are checked against each scheme's
    pattern before they go into a URL."""
    m = (tax.get("rules") or {}).get(rule) or {}
    tags = []
    for key, (label, pat, link) in SCHEMES.items():
        for i in m.get(key) or []:
            if not isinstance(i, str) or not pat.match(i):
                continue
            title = ((tax.get("known_ids") or {}).get(key) or {}).get(i, "")
            tip = f"{label} {i}" + (f": {title}" if title else "")
            tags.append(f'<a class="tag" href="{e(link(i))}" rel="noopener noreferrer" title="{e(tip)}">'
                        f'<span class="tag-k">{e(label)}</span> {e(i)}{(" " + e(title)) if title else ""}</a>')
    if not tags:
        return ""
    return f'<p class="tags" aria-label="Threat categories">{"".join(tags)}</p>'


class PublishRefused(Exception):
    def __init__(self, problems: list[str]) -> None:
        super().__init__("\n".join(problems))
        self.problems = problems


# ---------------------------------------------------------------- escaping

def e(s: object) -> str:
    """Escape text for HTML content and attributes. Use for every dynamic value."""
    return html.escape("" if s is None else str(s), quote=True)


def t(s: object, cap: int | None = 300) -> str:
    """Untrusted scan text: strip control/format characters with Bawwab's sanitiser, then escape."""
    return e(sanitise("" if s is None else s, cap))


def safe_url(u: object) -> str:
    s = str(u or "")
    return s if re.match(r"^https://[^\s<>\"']+$", s) else "#"


# ---------------------------------------------------------------- review

def load_review(path: Path) -> dict:
    if not path.exists():
        return {"targets": {}}
    d = json.loads(path.read_text())
    errs = []
    for tid, tr in (d.get("targets") or {}).items():
        for i, ent in enumerate(tr.get("findings") or []):
            if ent.get("status") not in STATUSES:
                errs.append(f"review {tid}[{i}]: status must be one of {sorted(STATUSES)}")
            if not isinstance(ent.get("note"), str) or not ent["note"].strip():
                errs.append(f"review {tid}[{i}]: a note is required")
            m = ent.get("match") or {}
            if not (isinstance(m.get("key"), str) or isinstance(m.get("rule"), str)):
                errs.append(f"review {tid}[{i}]: match needs a finding key or a rule")
    if errs:
        raise ValueError("invalid review file:\n  " + "\n  ".join(errs))
    d.setdefault("targets", {})
    return d


def glob_match(pattern: str, path: str) -> bool:
    """Path glob: '*' and '?' stay inside one folder, '**/' spans folders. 'assets/*.png' does not match
    'assets/sub/x.png', so a review never silently covers files the reviewer did not look at."""
    rx = ""
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            rx, i = rx + "(?:.*/)?", i + 3
        elif pattern.startswith("**", i):
            rx, i = rx + ".*", i + 2
        elif pattern[i] == "*":
            rx, i = rx + "[^/]*", i + 1
        elif pattern[i] == "?":
            rx, i = rx + "[^/]", i + 1
        else:
            rx, i = rx + re.escape(pattern[i]), i + 1
    return re.fullmatch(rx, path) is not None


def match_review(entries: list[dict], f: dict) -> dict | None:
    """An entry matching this finding's key wins; otherwise the first rule (+ optional file glob) match."""
    for ent in entries:
        k = (ent.get("match") or {}).get("key")
        if k and k == f.get("key"):
            return ent
    for ent in entries:
        m = ent.get("match") or {}
        if "key" in m or m.get("rule") != f.get("rule"):
            continue
        if "file" in m and not glob_match(m["file"], f.get("file") or ""):
            continue
        return ent
    return None


# ---------------------------------------------------------------- model

@dataclass
class View:
    target: dict
    result: dict | None
    state: str  # clean | suspicious | malicious | not-verified
    findings: list[tuple[dict, dict | None]] = field(default_factory=list)  # (finding, review entry)
    summary: str = ""
    outcome: str = ""

    @property
    def id(self) -> str:
        return self.target["id"]

    @property
    def counted(self) -> list[tuple[dict, dict | None]]:
        return [(f, r) for f, r in self.findings if f.get("counted")]


def state_of(result: dict | None, spec: str) -> str:
    if not result or result.get("spec") != spec or result.get("status") != "ok":
        return "not-verified"
    v = result.get("verdict")
    return v if v in ("clean", "suspicious", "malicious") else "not-verified"


def outcome_of(v: View) -> str:
    if v.state in ("clean", "not-verified"):
        return VERDICT_LABEL[v.state]
    stats = {r["status"] for _, r in v.counted if r}
    if "confirmed" in stats:
        return "Concern confirmed by review"
    if "expected-behaviour" in stats:
        return "Reviewed: expected behaviour"
    return "Reviewed: false alarm"


def plan(targets: list[dict], results: dict, review: dict) -> tuple[list[View], list[str], list[str]]:
    """(views, publish-blocking problems, warnings)."""
    views: list[View] = []
    problems: list[str] = []
    warnings: list[str] = []
    rv = review.get("targets") or {}
    for tg in targets:
        if not _ID.match(tg["id"]):
            problems.append(f"{tg['id']!r}: unsafe target id")
            continue
        res = results.get(tg["id"])
        if res is None:
            warnings.append(f"{tg['id']}: not scanned (shown as not verified)")
        state = state_of(res, tg["spec"])
        entries = (rv.get(tg["id"]) or {}).get("findings") or []
        fs = (res or {}).get("findings") or [] if state != "not-verified" else []
        v = View(tg, res, state, [(f, match_review(entries, f)) for f in fs],
                 summary=(rv.get(tg["id"]) or {}).get("summary") or "")
        if state in ("suspicious", "malicious"):
            if not v.counted:
                problems.append(f"{tg['id']}: verdict {state} but no counted finding to review")
            for f, r in v.counted:
                if r is None:
                    problems.append(f"{tg['id']}: unreviewed {f.get('severity')} finding {f.get('rule')} "
                                    f"[{f.get('key')}] {sanitise(f.get('file') or '', 80)}:{f.get('line') or ''}")
        v.outcome = outcome_of(v)
        views.append(v)
    ids = {tg["id"] for tg in targets}
    for tid in rv:
        if tid not in ids:
            warnings.append(f"review entry {tid} matches no current target (stale after a re-pin?)")
    return views, problems, warnings


# ---------------------------------------------------------------- page chrome

CSS = """
:root{--bg:#fbfbf8;--fg:#1b1d21;--muted:#5b616b;--line:#d9dbd6;--card:#ffffff;--accent:#0b5cad;
--ok:#1d6b3a;--ok-bg:#e3f3e8;--warn:#7a4a00;--warn-bg:#fdf1d8;--bad:#9b1c1c;--bad-bg:#fbe4e4;
--nv:#3d4451;--nv-bg:#e8eaee;--code:#f1f2ee;color-scheme:light dark}
@media (prefers-color-scheme:dark){:root{--bg:#121417;--fg:#e8e9ea;--muted:#a3a8b1;--line:#30343a;
--card:#1a1d21;--accent:#7cb7ff;--ok:#8fdcaa;--ok-bg:#163222;--warn:#ffd08a;--warn-bg:#3a2b10;
--bad:#ffaaaa;--bad-bg:#401818;--nv:#c9ced6;--nv-bg:#2a2e35;--code:#1f2328}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--fg);font:16px/1.55 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
a{color:var(--accent)}a:focus-visible,button:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid var(--accent);outline-offset:2px}
.skip{position:absolute;left:-999px}.skip:focus{left:16px;top:8px;background:var(--card);padding:6px 10px;z-index:9}
header.site,main,footer.site{max-width:1080px;margin:0 auto;padding:0 16px}
header.site{display:flex;flex-wrap:wrap;gap:8px 24px;align-items:baseline;padding-top:20px;padding-bottom:12px;border-bottom:1px solid var(--line)}
header.site .brand{font-weight:700;font-size:1.1rem;text-decoration:none;color:var(--fg)}
header.site nav a{margin-right:16px}
footer.site{color:var(--muted);font-size:.875rem;padding-top:24px;padding-bottom:40px;border-top:1px solid var(--line);margin-top:40px}
h1{font-size:1.75rem;line-height:1.25;margin:24px 0 8px;overflow-wrap:anywhere}h2{font-size:1.25rem;margin:32px 0 8px}
.lede{color:var(--muted);margin-top:0}
.stats{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}
.stat{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:12px 14px}
.stat b{display:block;font-size:1.8rem;line-height:1.1}.stat span{color:var(--muted);font-size:.9rem}
.badge{display:inline-block;padding:2px 8px;border-radius:999px;font-size:.85rem;font-weight:600;white-space:nowrap}
.b-clean{color:var(--ok);background:var(--ok-bg)}.b-suspicious{color:var(--warn);background:var(--warn-bg)}
.b-malicious{color:var(--bad);background:var(--bad-bg)}.b-not-verified{color:var(--nv);background:var(--nv-bg)}
.b-confirmed{color:var(--bad);background:var(--bad-bg)}.b-false-positive{color:var(--ok);background:var(--ok-bg)}
.b-expected-behaviour{color:var(--nv);background:var(--nv-bg)}.b-low{color:var(--nv);background:var(--nv-bg)}
.card{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin:12px 0}
.card h3{margin:0 0 6px;font-size:1.05rem;overflow-wrap:anywhere}
dl.meta{display:grid;grid-template-columns:max-content 1fr;gap:4px 16px;margin:12px 0}dl.meta dt{color:var(--muted)}dl.meta dd{margin:0;overflow-wrap:anywhere}
pre.ev{background:var(--code);border:1px solid var(--line);border-radius:6px;padding:8px 10px;overflow-x:auto;white-space:pre-wrap;overflow-wrap:anywhere;font-size:.875rem;margin:6px 0}
code{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.92em}
.loc{color:var(--muted);font-size:.9rem;overflow-wrap:anywhere}
.review{border-left:4px solid var(--line);padding:4px 10px;margin-top:8px}
.filters{display:flex;flex-wrap:wrap;gap:8px 16px;align-items:end;margin:12px 0}
.filters label{display:flex;flex-direction:column;font-size:.85rem;color:var(--muted)}
.filters input,.filters select{font:inherit;padding:6px 8px;border:1px solid var(--line);border-radius:6px;background:var(--card);color:var(--fg);min-width:10rem}
.tablewrap{overflow-x:auto;border:1px solid var(--line);border-radius:8px}
table{border-collapse:collapse;width:100%;font-size:.93rem}
th,td{text-align:left;padding:8px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th button{font:inherit;font-weight:600;background:none;border:0;color:var(--fg);cursor:pointer;padding:0}
th[aria-sort=ascending] button::after{content:" \\25B2"}th[aria-sort=descending] button::after{content:" \\25BC"}
td.num,th.num{text-align:right}tbody tr:hover{background:var(--code)}
.note{background:var(--warn-bg);color:var(--fg);border-radius:8px;padding:10px 14px}
details summary{cursor:pointer;color:var(--accent)}
.tags{display:flex;flex-wrap:wrap;gap:6px;margin:6px 0}
.tag{display:inline-block;font-size:.78rem;line-height:1.4;padding:1px 8px;border:1px solid var(--line);border-radius:4px;color:var(--fg);text-decoration:none;background:var(--code);overflow-wrap:anywhere}
.tag:hover{border-color:var(--accent)}.tag-k{color:var(--muted);font-weight:600}
@media (max-width:640px){.hide-sm{display:none}h1{font-size:1.4rem}}
""".strip()

TABLE_JS = """
(function(){var tb=document.querySelector('#targets tbody');if(!tb)return;
var rows=[].slice.call(tb.rows),q=document.getElementById('q'),k=document.getElementById('kind'),
v=document.getElementById('verdict'),n=document.getElementById('shown');
function apply(){var s=q.value.toLowerCase(),kk=k.value,vv=v.value,c=0;rows.forEach(function(r){
var ok=(!s||r.dataset.search.indexOf(s)>=0)&&(!kk||r.dataset.kind===kk)&&(!vv||r.dataset.state===vv);
r.hidden=!ok;if(ok)c++;});n.textContent=c;}
[q,k,v].forEach(function(x){x.addEventListener('input',apply);});
document.querySelectorAll('#targets th[data-key] button').forEach(function(b){b.addEventListener('click',function(){
var th=b.parentNode,key=th.dataset.key,num=th.classList.contains('num'),
dir=th.getAttribute('aria-sort')==='ascending'?'descending':'ascending';
document.querySelectorAll('#targets th[data-key]').forEach(function(o){o.removeAttribute('aria-sort');});
th.setAttribute('aria-sort',dir);rows.sort(function(a,b){var x=a.dataset[key],y=b.dataset[key];
if(num){x=+x;y=+y;}var r=x<y?-1:x>y?1:0;return dir==='ascending'?r:-r;});
rows.forEach(function(r){tb.appendChild(r);});});});apply();})();
""".strip()


def _sha(s: str) -> str:
    return "sha256-" + base64.b64encode(hashlib.sha256(s.encode()).digest()).decode()


def page(title: str, body: str, depth: int = 0, script: str | None = None) -> str:
    up = "../" * depth
    csp = f"default-src 'none'; style-src '{_sha(CSS)}'; img-src 'self'; base-uri 'none'; form-action 'none'"
    if script:
        csp += f"; script-src '{_sha(script)}'"
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="{e(csp)}">
<meta name="referrer" content="no-referrer">
<title>{e(title)}</title>
<style>{CSS}</style>
</head>
<body>
<a class="skip" href="#main">Skip to content</a>
<header class="site"><a class="brand" href="{up}index.html">Bawwab: Top 100 scan</a>
<nav aria-label="Main"><a href="{up}index.html">Overview</a><a href="{up}targets.html">All 100</a><a href="{up}method.html">Method</a><a href="{up}index.html#disputes">Disputes</a></nav></header>
<main id="main">
{body}
</main>
<footer class="site">Static rules only, no AI review. Scanned text is shown escaped and is not trusted. Generated by report/build_site.py.</footer>
{f'<script>{script}</script>' if script else ''}
</body>
</html>
"""


def badge(state: str, label: str | None = None) -> str:
    return f'<span class="badge b-{e(state)}">{e(label or VERDICT_LABEL.get(state, state))}</span>'


def dispute_url(repo: str, v: View) -> str:
    q = urllib.parse.urlencode({
        "template": "dispute.md", "labels": "dispute",
        "title": f"Dispute: {sanitise(v.target['name'], 80)} ({v.id})",
    })
    return f"https://github.com/{repo}/issues/new?{q}"


def version_of(tg: dict) -> str:
    return tg.get("version") or (tg.get("commit") or "")[:12]


def pop_text(tg: dict) -> str:
    p = tg["popularity"]
    unit = {"npm_weekly_downloads": "npm downloads/week", "pypi_weekly_downloads": "PyPI downloads/week",
            "github_stars": "GitHub stars"}.get(p["metric"], p["metric"])
    return f"{p['value']:,} {unit} ({p['collected_at']})"


# ---------------------------------------------------------------- pages

def counts(views: list[View]) -> dict[str, int]:
    c = {k: 0 for k in VERDICT_LABEL}
    for v in views:
        c[v.state] += 1
    return c


def categories_section(tax: dict) -> str:
    srcs = "".join(
        f'<li><a href="{e(safe_url(s.get("url")))}" rel="noopener noreferrer">{e(s.get("name"))}</a>, '
        f'version {e(s.get("version"))}, retrieved {e(s.get("retrieved"))}</li>' for s in tax.get("sources") or [])
    return f"""<section aria-labelledby="h-cat"><h2 id="h-cat">Categories</h2>
<p>Each finding is tagged with the public threat categories its rule maps to: the OWASP Top 10 for LLM
Applications, the OWASP Top 10 for Agentic Applications, MITRE ATLAS techniques and CWE weaknesses. The tags
describe the kind of risk the rule looks for, not a confirmed attack. Rules that only say part of a target was not
checked are left untagged on purpose. Sources:</p>
<ul>{srcs or '<li>No taxonomy data available.</li>'}</ul></section>
"""


def index_page(views: list[View], meta: dict, repo: str, tax: dict | None = None) -> str:
    c = counts(views)
    flagged = [v for v in views if v.state in ("suspicious", "malicious")]
    oc: dict[str, int] = {}
    for v in flagged:
        oc[v.outcome] = oc.get(v.outcome, 0) + 1
    kinds = {k: sum(v.target["kind"] == k for v in views) for k in KIND_LABEL}
    stats = "".join(f'<div class="stat"><b>{n}</b><span>{e(lbl)}</span></div>' for n, lbl in [
        (len(views), "targets scanned"), (c["clean"], VERDICT_LABEL["clean"]),
        (c["suspicious"], VERDICT_LABEL["suspicious"]), (c["malicious"], VERDICT_LABEL["malicious"]),
        (c["not-verified"], VERDICT_LABEL["not-verified"])])
    review = "".join(f"<li>{e(k)}: {n}</li>" for k, n in sorted(oc.items())) or "<li>Nothing was flagged.</li>"
    confirmed = sum(1 for v in flagged if "confirm" in v.outcome.lower())
    commit = e(meta.get("bawwab_commit", "unknown"))
    dirty = " (with uncommitted changes)" if meta.get("bawwab_dirty") else ""
    body = f"""
<h1>Scanning the 100 most popular MCP servers, skills and plugins</h1>
<p class="lede">{kinds['mcp']} MCP servers, {kinds['skill']} skills and {kinds['plugin']} plugins, ranked by downloads or GitHub stars,
each pinned to an exact version or commit and scanned with Bawwab's static rules. Scan date: {e(meta.get('scan_date', 'unknown'))}.</p>
<section aria-labelledby="h-counts"><h2 id="h-counts">Headline counts</h2>
<p class="lede"><strong>{len(flagged)} flagged by static rules · {confirmed} confirmed harmful after hand-review.</strong>
The rule verdicts below are what the scanner said before anyone read the code; each target's page shows the reviewed outcome next to it.</p>
<div class="stats">{stats}</div>
<p>Every target that was not clean was checked by hand before publication. Review outcome for the {len(flagged)} flagged targets:</p>
<ul>{review}</ul>
<p><a href="targets.html">See all {len(views)} targets in a sortable table</a>.</p></section>
<section aria-labelledby="h-method"><h2 id="h-method">How this was done</h2>
<ul>
<li><strong>Selection.</strong> MCP servers are ranked by weekly npm or PyPI downloads (official modelcontextprotocol/servers entries always included); skills and plugins by GitHub stars of the repository that hosts them, with at most two per repository after Anthropic's official ones. <a href="method.html">Full method</a>.</li>
<li><strong>Pinned.</strong> Each target is scanned at an exact package version or git commit, listed on its page.</li>
<li><strong>Download only.</strong> Packages are fetched with Bawwab's own fetchers and read as files. Nothing is installed or run.</li>
<li><strong>Static rules only.</strong> The verdict comes from Bawwab's pattern and code-flow rules, without the AI review step Bawwab normally adds, and without running anything in a sandbox.</li>
<li><strong>Hand-checked.</strong> Each flagged finding carries a reviewer's status: confirmed, known false alarm, or expected for what the tool does.</li>
</ul></section>
{categories_section(tax or {})}
<section aria-labelledby="h-limits"><h2 id="h-limits">Limits</h2>
<ul>
<li>Static rules see code patterns, not intent. "Not malicious, needs a look" means a pattern worth reading, not an accusation.</li>
<li>No AI review was used, so findings that Bawwab's judge would normally clear are shown as raw rule hits with a human note instead.</li>
<li>Very large files are skipped by the scanner and reported as such; code that is downloaded or generated at run time is not seen.</li>
<li>A clean result means no rule fired at this version. It is not a guarantee, and later versions may differ.</li>
<li>Popularity numbers are a snapshot and can be inflated (bots, CI, star campaigns); they decide what was scanned, not how it scored.</li>
</ul></section>
<section aria-labelledby="h-repro"><h2 id="h-repro">Reproduce</h2>
<dl class="meta"><dt>Bawwab commit</dt><dd><code>{commit}</code>{e(dirty)}</dd>
<dt>Rule set</dt><dd><code>{e(meta.get('ruleset_version', 'unknown'))}</code></dd>
<dt>Per-target timeout</dt><dd>{e(meta.get('timeout_s', ''))} s</dd></dl>
<pre class="ev">git checkout {commit}
report/run_scan.sh            # reads the pinned report/targets.json, writes report/out/results.json
uv run python report/build_site.py</pre></section>
<section aria-labelledby="disputes"><h2 id="disputes">Disputes</h2>
<p>If you maintain one of these packages and think a result is wrong, <a href="{e(f'https://github.com/{repo}/issues/new?template=dispute.md&labels=dispute')}">open a dispute</a>
(each target page has a link with the target filled in). Say which finding, why it is wrong, and link to the code. We re-check and update the page and the review note.</p></section>
"""
    return page("Bawwab: Top 100 scan", body)


def targets_page(views: list[View]) -> str:
    rows = []
    for v in views:
        tg = v.target
        nfind = len(v.counted)
        search = f"{tg['name']} {tg.get('repo') or ''} {tg.get('path') or ''} {KIND_LABEL[tg['kind']]}".lower()
        rows.append(
            f'<tr data-kind="{e(tg["kind"])}" data-state="{e(v.state)}" data-search="{t(search, 300)}" '
            f'data-rank="{tg["rank"]}" data-name="{t(tg["name"].lower(), 120)}" data-pop="{tg["popularity"]["value"]}" '
            f'data-findings="{nfind}" data-statesort="{["clean", "not-verified", "suspicious", "malicious"].index(v.state)}">'
            f'<td class="num">{tg["rank"]}</td>'
            f'<td><a href="t/{e(v.id)}.html">{t(tg["name"], 120)}</a>'
            + (f'<div class="loc">{t(tg.get("repo"), 120)}{"/" + t(tg.get("path"), 160) if tg.get("path") else ""}</div>' if tg.get("repo") else "")
            + f'</td><td>{e(KIND_LABEL[tg["kind"]])}</td>'
            f'<td class="hide-sm"><code>{t(version_of(tg), 40)}</code></td>'
            f'<td class="num hide-sm">{e(pop_text(tg))}</td>'
            f'<td>{badge(v.state)}</td><td class="num">{nfind}</td>'
            f'<td class="hide-sm">{e(v.outcome)}</td></tr>')
    opts = "".join(f'<option value="{k}">{e(lbl)}</option>' for k, lbl in VERDICT_LABEL.items())
    kopts = "".join(f'<option value="{k}">{e(lbl)}</option>' for k, lbl in KIND_LABEL.items())
    body = f"""
<h1>All targets</h1>
<p class="lede">Showing <span id="shown">{len(views)}</span> of {len(views)}. Column headers sort; the filters narrow the list.</p>
<div class="filters" role="search">
<label for="q">Search<input id="q" type="search" autocomplete="off"></label>
<label for="kind">Kind<select id="kind"><option value="">All kinds</option>{kopts}</select></label>
<label for="verdict">Result<select id="verdict"><option value="">All results</option>{opts}</select></label>
</div>
<div class="tablewrap"><table id="targets">
<caption class="skip">Scan results for every target</caption>
<thead><tr><th scope="col" class="num" data-key="rank" aria-sort="ascending"><button type="button">#</button></th>
<th scope="col" data-key="name"><button type="button">Name</button></th><th scope="col">Kind</th>
<th scope="col" class="hide-sm">Version</th><th scope="col" class="num hide-sm" data-key="pop"><button type="button">Popularity</button></th>
<th scope="col" data-key="statesort"><button type="button">Result</button></th>
<th scope="col" class="num" data-key="findings"><button type="button">Findings</button></th>
<th scope="col" class="hide-sm">After review</th></tr></thead>
<tbody>{''.join(rows)}</tbody></table></div>
"""
    return page("All targets - Bawwab: Top 100 scan", body, script=TABLE_JS)


def finding_card(f: dict, r: dict | None, tax: dict | None = None) -> str:
    info = CATALOG.get(f.get("rule") or "")
    title = info.title if info else "Rule not in the catalog"
    loc = ""
    if f.get("file"):
        loc = t(f["file"], 300) + (f":{int(f['line'])}" if isinstance(f.get("line"), int) else "")
    rev = ""
    if r:
        rev = (f'<div class="review"><p>{badge(r["status"], STATUSES[r["status"]])}</p><p>{e(r["note"])}</p>'
               + (f'<p class="loc">Reviewed by {e(r.get("reviewer"))}{", " + e(r.get("date")) if r.get("date") else ""}</p>'
                  if r.get("reviewer") else "") + "</div>")
    sev = f.get("severity") or ""
    return f"""<article class="card">
<h3><code>{t(f.get('rule'), 80)}</code>: {e(title)} <span class="badge b-{'low' if not f.get('counted') else ('malicious' if sev == 'critical' else 'suspicious')}">{e(sev)}</span></h3>
{f'<p class="loc">{loc}</p>' if loc else ''}
{taxonomy_tags(f.get('rule') or '', tax or {})}
<pre class="ev"><code>{t(f.get('evidence'), 300)}</code></pre>
<p><strong>What this means:</strong> {e(info.why if info else 'No plain-language description is available for this rule.')}</p>
{f'<p><strong>The rule&#39;s general advice:</strong> {e(info.fix)} <span class="loc">(see the review note for this case)</span></p>' if info and r else (f'<p><strong>What you can do:</strong> {e(info.fix)}</p>' if info else '')}
{rev}
</article>"""


def target_page(v: View, repo: str, tax: dict | None = None) -> str:
    tg, res = v.target, v.result or {}
    meta = [("Kind", e(KIND_LABEL[tg["kind"]])), ("Source", e(tg["source"]))]
    if tg.get("repo"):
        meta.append(("Repository", t(tg["repo"], 120) + (f" / {t(tg['path'], 200)}" if tg.get("path") else "")))
    if tg.get("version"):
        meta.append(("Version", f"<code>{t(tg['version'], 60)}</code>"))
    if tg.get("commit"):
        meta.append(("Commit", f"<code>{t(tg['commit'], 40)}</code>"))
    if tg.get("marketplace"):
        meta.append(("Listed in", t(tg["marketplace"], 120)))
    meta += [("Popularity", e(pop_text(tg)) + (" (official, always included)" if tg["selection"] == "official" else "")),
             ("Link", f'<a href="{e(safe_url(tg["url"]))}" rel="noopener noreferrer">{t(tg["url"], 200)}</a>'),
             ("Scanned", e(res.get("scanned_at") or "not scanned")),
             ("Scan time", e(f"{res['duration_s']} s") if isinstance(res.get("duration_s"), (int, float)) else "-")]
    if res.get("artifact_type"):
        meta.append(("Scanned as", e(res["artifact_type"])))
    dl = "".join(f"<dt>{k}</dt><dd>{val}</dd>" for k, val in meta)
    parts = [f"<h1>{t(tg['name'], 160)}</h1>",
             f"<p>{badge(v.state)} {'' if v.state in ('clean', 'not-verified') else e(v.outcome)}</p>",
             f"<p>{e(VERDICT_NOTE[v.state])}</p>", f'<dl class="meta">{dl}</dl>']
    if v.summary:
        parts.append(f'<div class="note"><strong>Review note:</strong> {e(v.summary)}</div>')
    if v.state == "not-verified":
        err = res.get("error") if res else "This target has not been scanned yet."
        parts.append(f'<h2>Why it was not verified</h2><pre class="ev"><code>{t(err, 300)}</code></pre>')
    counted = [x for x in v.findings if x[0].get("counted")]
    low = [x for x in v.findings if not x[0].get("counted")]
    if counted:
        parts.append(f"<h2>Findings ({len(counted)})</h2>" + "".join(finding_card(f, r, tax) for f, r in counted))
    elif v.state == "clean":
        parts.append("<h2>Findings</h2><p>No finding at or above the warning level.</p>")
    if low:
        parts.append(f"<details><summary>{len(low)} low-severity notes (informational, do not affect the result)</summary>"
                     + "".join(finding_card(f, r, tax) for f, r in low) + "</details>")
    parts.append(f'<h2 id="dispute">Dispute this result</h2><p>Maintainer and think this is wrong? '
                 f'<a href="{e(dispute_url(repo, v))}" rel="noopener noreferrer">Open a dispute on GitHub</a> '
                 f'with the target id <code>{e(v.id)}</code>.</p>')
    return page(f"{sanitise(tg['name'], 80)} - Bawwab: Top 100 scan", "\n".join(parts), depth=1)


def md_to_html(md: str) -> str:
    """Tiny Markdown subset (headings, lists, paragraphs, code, bold, links) for METHOD.md. Escapes first."""
    def inline(s: str) -> str:
        s = e(s)
        s = re.sub(r"`([^`]+)`", r"<code>\1</code>", s)
        s = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", s)
        return re.sub(r"\[([^\]]+)\]\((https://[^)\s]+)\)", r'<a href="\2" rel="noopener noreferrer">\1</a>', s)
    out: list[str] = []
    para: list[str] = []
    in_list = in_code = False

    def flush() -> None:
        nonlocal para
        if para:
            out.append("<p>" + inline(" ".join(para)) + "</p>")
            para = []
    for line in md.splitlines():
        if line.startswith("```"):
            flush()
            if in_list:
                out.append("</ul>")
                in_list = False
            out.append("</code></pre>" if in_code else '<pre class="ev"><code>')
            in_code = not in_code
            continue
        if in_code:
            out.append(e(line))
            continue
        m = re.match(r"^(#{1,4})\s+(.*)", line)
        li = re.match(r"^\s*[-*]\s+(.*)", line)
        if m or li or not line.strip():
            flush()
        if in_list and not li and line.strip() and not line.startswith("  "):
            out.append("</ul>")
            in_list = False
        if m:
            lvl = min(len(m.group(1)) + (0 if len(m.group(1)) > 1 else 0), 4)
            out.append(f"<h{lvl}>{inline(m.group(2))}</h{lvl}>")
        elif li:
            if not in_list:
                out.append("<ul>")
                in_list = True
            out.append(f"<li>{inline(li.group(1))}</li>")
        elif line.strip():
            if in_list and line.startswith("  "):
                out[-1] = out[-1][:-5] + " " + inline(line.strip()) + "</li>"
            else:
                para.append(line.strip())
    flush()
    if in_list:
        out.append("</ul>")
    return "\n".join(out)


# ---------------------------------------------------------------- build

def build(targets_path: Path, results_path: Path, review_path: Path, out: Path, repo: str = DEFAULT_REPO,
          method_path: Path | None = None, taxonomy_path: Path | None = None) -> tuple[list[View], list[str]]:
    if not re.fullmatch(r"[\w.-]+/[\w.-]+", repo):
        raise ValueError("repo must be OWNER/NAME")
    targets = load_targets(targets_path)
    rdoc = json.loads(results_path.read_text()) if results_path.exists() else {"results": {}}
    review = load_review(review_path)
    views, problems, warnings = plan(targets, rdoc.get("results") or {}, review)
    if problems:
        raise PublishRefused(problems)
    scanned = [r.get("scanned_at") or "" for r in (rdoc.get("results") or {}).values()]
    meta = {
        "bawwab_commit": rdoc.get("bawwab_commit", "unknown"), "bawwab_dirty": rdoc.get("bawwab_dirty"),
        "ruleset_version": rdoc.get("ruleset_version", "unknown"), "timeout_s": rdoc.get("timeout_s", ""),
        "scan_date": max(scanned)[:10] if scanned else "not scanned",
    }
    mixed = {(r.get("bawwab_commit"), r.get("ruleset_version")) for r in (rdoc.get("results") or {}).values()}
    if len(mixed) > 1:
        warnings.append(f"results come from {len(mixed)} different Bawwab commits/rule sets; rescan for one consistent run")
    if out.exists():
        shutil.rmtree(out)
    (out / "t").mkdir(parents=True)
    tax = load_taxonomy(taxonomy_path or TAXONOMY_PATH)
    (out / "index.html").write_text(index_page(views, meta, repo, tax))
    (out / "targets.html").write_text(targets_page(views))
    method_path = method_path or (REPORT / "METHOD.md")
    method = md_to_html(method_path.read_text()) if method_path.exists() else "<p>METHOD.md is missing.</p>"
    (out / "method.html").write_text(page("Method - Bawwab: Top 100 scan", method))
    for v in views:
        (out / "t" / f"{v.id}.html").write_text(target_page(v, repo, tax))
    (out / ".nojekyll").write_text("")
    return views, warnings


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description="Build the static report site (refuses unreviewed findings).")
    ap.add_argument("--targets", type=Path, default=REPORT / "targets.json")
    ap.add_argument("--results", type=Path, default=REPORT / "out" / "results.json")
    ap.add_argument("--review", type=Path, default=REPORT / "review.json")
    ap.add_argument("--out", type=Path, default=REPORT / "out" / "site")
    ap.add_argument("--repo", default=DEFAULT_REPO, help="GitHub OWNER/NAME that receives dispute issues")
    a = ap.parse_args(argv)
    try:
        views, warnings = build(a.targets, a.results, a.review, a.out, a.repo)
    except PublishRefused as ex:
        print(f"REFUSING TO PUBLISH: {len(ex.problems)} finding(s) on non-clean targets are not reviewed.\n"
              "Add an entry for each to report/review.json (status + note), then rebuild:", file=sys.stderr)
        for p in ex.problems:
            print("  " + p, file=sys.stderr)
        return 2
    for w in warnings:
        print("warning: " + w, file=sys.stderr)
    c = counts(views)
    print(f"wrote {a.out}: {len(views)} targets {c}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    sys.exit(main())
