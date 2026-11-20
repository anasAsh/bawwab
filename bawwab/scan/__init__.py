from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from bawwab.config import Config, is_trusted, load_config
from bawwab.fetch import FetchError, FetchOpts, fetch_target, target_from_command, target_from_url
from bawwab.scan.files import ExtraText, ScanFile, load_files
from bawwab.scan.identity import identity_checks
from bawwab.scan.osv import known_malware
from bawwab.scan.judge.backends import Backend, backend_for
from bawwab.scan.judge.judge import judge
from bawwab.scan.rules import run_static_rules
from bawwab.scan.rules.code import registry_install_adjust
from bawwab.scan.rules.text import model_facing_text
from bawwab.severity import compute_verdict
from bawwab.store import Store, open_store, target_key
from bawwab.trust import diff_snapshots, make_snapshot, merge_snapshots, trust_name
from bawwab.types import Fetched, Finding, Mode, ScanReport, Severity, Target, ToolInfo, Verdict

__all__ = ["SandboxRunner", "scan_target", "synthetic_report"]

MAX_PLUGIN_DEPTH = 2
SANDBOX_TIMEOUT_S = 120.0


class SandboxRunner(Protocol):
    def run(self, f: Fetched, timeout_s: float) -> tuple[list[Finding], list[ToolInfo]]: ...


def synthetic_report(
    reason: str, key: str, target: Target | None = None, rule: str = "gate.error", mode: Mode = Mode.STANDARD
) -> ScanReport:
    """A suspicious report for a failure that must block protected actions (fail closed)."""
    t = target or Target("local", key, name=key)
    return ScanReport(
        key, t, "unknown", mode, Verdict.SUSPICIOUS,
        [Finding(rule, Severity.MED, "gate", reason)], datetime.now(UTC),
    )


def _extra_from_tools(tools: list[ToolInfo]) -> list[ExtraText]:
    out = []
    for t in tools:
        if t.name.startswith("prompt:"):
            label = f"prompt {t.name[7:]}"
        elif t.name.startswith("resource:"):
            label = f"resource {t.name[9:]}"
        else:
            label = f"tool {t.name}"
        text = t.description or ""
        if t.input_schema:
            text += "\n" + json.dumps(t.input_schema, sort_keys=True)
        out.append(ExtraText(label, text))
    return out


def _prefix(findings: list[Finding], name: str) -> list[Finding]:
    return [dataclasses.replace(f, evidence=f"[server {name}] {f.evidence}") for f in findings]


# ------------------------------------------------------------- plugin recursion

def _server_map(data: object) -> dict[str, dict]:
    if not isinstance(data, dict):
        return {}
    inner = data.get("mcpServers")
    cand = inner if isinstance(inner, dict) else data
    return {str(k): v for k, v in cand.items() if isinstance(v, dict)}


def _read_json(p: Path) -> object:
    try:
        return json.loads(p.read_text())
    except (OSError, ValueError, RecursionError):
        return None


def _bundled_servers(root: Path) -> dict[str, dict]:
    servers: dict[str, dict] = {}
    manifest = _read_json(root / ".claude-plugin" / "plugin.json")
    if isinstance(manifest, dict):
        ms = manifest.get("mcpServers")
        if isinstance(ms, str):  # path to a servers file, relative to the plugin root
            ms = _read_json(root / ms)
            servers.update(_server_map(ms))
        elif isinstance(ms, dict):
            servers.update(_server_map({"mcpServers": ms}))
    mcp = _read_json(root / ".mcp.json")
    for k, v in _server_map(mcp).items():
        servers.setdefault(k, v)
    return servers


def _child_target(spec: dict, root: Path) -> Target | None:
    def sub(s: str) -> str:
        s = s.replace("${CLAUDE_PLUGIN_ROOT}", str(root))
        return str(root / s) if s.startswith(("./", "../")) else s

    if isinstance(spec.get("url"), str) and spec["url"]:
        return target_from_url(spec["url"])
    cmd, args = spec.get("command"), spec.get("args", [])
    if not isinstance(cmd, str) or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return None
    if Path(cmd).name == "uv" and args[:1] == ["run"]:
        if not _uv_env_ok(spec.get("env")):
            return None
        return _uv_project_script(sub(cmd), [sub(a) for a in args], root)
    t = target_from_command(sub(cmd), [sub(a) for a in args])
    if t is not None and t.kind == "local" and not (t.path and Path(t.path).is_dir()):
        return None
    return t


# `uv run` flags that take no value and don't change what runs; any other flag: unresolved (fail closed)
_UV_RUN_PLAIN_FLAGS = {"--quiet", "-q", "--frozen", "--locked", "--offline", "--no-sync", "--isolated", "--no-progress"}


def _uv_project_script(cmd: str, args: list[str], root: Path) -> Target | None:
    """`uv run --project <dir inside the plugin> --frozen|--locked [plain flags] <script>`: the project's own
    console script, declared in <dir>/pyproject.toml [project.scripts] as module:function with the module inside
    <dir>, and everything uv installs for it pinned in <dir>/uv.lock to PyPI (see _uv_locked_packages).
    Anything else: None (unresolved, fail closed)."""
    import os
    import tomllib

    a, project, rest, pinned = args[1:], None, [], False
    i = 0
    while i < len(a):
        x = a[i]
        if x == "--project" and i + 1 < len(a) and project is None:
            project, i = a[i + 1], i + 2
        elif x.startswith("--project=") and project is None:
            project, i = x.split("=", 1)[1], i + 1
        elif x in _UV_RUN_PLAIN_FLAGS:
            pinned = pinned or x in ("--frozen", "--locked")
            i += 1
        elif x.startswith("-"):
            return None  # --with, --index, --extra-index-url, ...: unscanned code or another index
        else:
            rest = a[i:]
            break
    if not project or not rest or not pinned:
        return None
    base = os.path.realpath(root)
    proj = os.path.realpath(project if os.path.isabs(project) else os.path.join(base, project))
    if proj != base and not proj.startswith(base + os.sep):
        return None
    try:
        with open(os.path.join(proj, "pyproject.toml"), "rb") as fh:
            entry = tomllib.load(fh)["project"]["scripts"][rest[0]]
        module = entry.split(":", 1)[0].strip()
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return None
    rel = module.replace(".", os.sep)
    if not module or not any(os.path.isfile(os.path.join(proj, rel + ext)) for ext in (".py", os.sep + "__init__.py")):
        return None
    if _uv_locked_packages(proj) is None:
        return None
    return Target("local", " ".join([cmd, *args]), name=rest[0], path=proj)


def _uv_env_ok(env: object) -> bool:
    """Server env that can't change what uv installs or runs: no UV_*/PIP_*/PYTHON* settings, except the venv
    location in the plugin's data dir."""
    if env is None:
        return True
    if not isinstance(env, dict):
        return False
    for k, v in env.items():
        k = str(k).upper()
        if k == "UV_PROJECT_ENVIRONMENT":
            if not (isinstance(v, str) and v.startswith("${CLAUDE_PLUGIN_DATA}/") and ".." not in v):
                return False
        elif k.startswith(("UV_", "PIP_", "PYTHON")):
            return False
    return True


PYPI_SIMPLE = "https://pypi.org/simple"
PYPI_FILES_HOST = "files.pythonhosted.org"
# build backends whose package is the only build requirement allowed (fix round 1 C1c)
_BUILD_BACKENDS = {"uv_build": {"uv_build", "uv-build"}, "hatchling.build": {"hatchling"},
                   "setuptools.build_meta": {"setuptools", "wheel"}}
# [tool.uv] keys that point uv at another index, local wheels or other sources
_UV_SOURCE_KEYS = {"index", "sources", "index-url", "extra-index-url", "find-links", "indexes", "index-strategy"}
_REQ_NAME_RE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(\[[^\]]*\])?\s*(.*)$", re.S)


def _plain_req(req: object) -> str | None:
    """The distribution name of a plain registry requirement; None for a direct reference (`x @ url`) or junk."""
    if not isinstance(req, str):
        return None
    m = _REQ_NAME_RE.match(req)
    if not m or "@" in m.group(3).split(";", 1)[0]:
        return None
    return m.group(1).lower().replace("_", "-")


def _uv_locked_packages(proj: str) -> list[tuple[str, str]] | None:
    """The third-party (name, version) pairs uv installs for the project, when ALL of these hold; else None:
    - <proj>/uv.lock exists, and there is no uv.toml;
    - pyproject sets no [tool.uv] index, sources or find-links, and every requirement is a plain one;
    - the build backend is uv_build, hatchling or setuptools, and it is the only build requirement;
    - every locked package comes from PyPI (https://pypi.org/simple, files on files.pythonhosted.org), except
      the project itself (editable/virtual ".")."""
    import os
    import tomllib
    from urllib.parse import urlsplit

    try:
        if os.path.lexists(os.path.join(proj, "uv.toml")):
            return None
        with open(os.path.join(proj, "pyproject.toml"), "rb") as fh:
            py = tomllib.load(fh)
        with open(os.path.join(proj, "uv.lock"), "rb") as fh:
            lock = tomllib.load(fh)
    except (OSError, ValueError, RecursionError):
        return None
    tool_uv = (py.get("tool") or {}).get("uv") or {}
    if not isinstance(tool_uv, dict) or _has_keys(tool_uv, _UV_SOURCE_KEYS):
        return None
    project = py.get("project") or {}
    reqs = list(project.get("dependencies") or [])
    for group in (project.get("optional-dependencies") or {}).values():
        reqs += list(group or [])
    for group in (py.get("dependency-groups") or {}).values():
        reqs += [x for x in (group or []) if not isinstance(x, dict)]  # {include-group = ...} is a reference
    if any(_plain_req(r) is None for r in reqs):
        return None
    bs = py.get("build-system")
    allowed = _BUILD_BACKENDS.get(bs.get("build-backend")) if isinstance(bs, dict) else None
    if not allowed or "backend-path" in bs or not all(_plain_req(r) in allowed for r in bs.get("requires") or []):
        return None
    out: list[tuple[str, str]] = []
    pkgs = lock.get("package")
    if not isinstance(pkgs, list):
        return None
    for pk in pkgs:
        if not isinstance(pk, dict) or not isinstance(pk.get("name"), str):
            return None
        src = pk.get("source")
        if not isinstance(src, dict) or len(src) != 1:
            return None
        (kind, val), = src.items()
        if kind in ("editable", "virtual") and val == ".":
            continue  # the project itself: its files are in the tree and scanned
        if kind != "registry" or val != PYPI_SIMPLE or not isinstance(pk.get("version"), str):
            return None
        files = ([pk["sdist"]] if "sdist" in pk else []) + list(pk.get("wheels") or [])
        for fl in files:
            u = urlsplit(fl.get("url", "")) if isinstance(fl, dict) else None
            if u is None or u.scheme != "https" or u.hostname != PYPI_FILES_HOST:
                return None
        out.append((pk["name"], pk["version"]))
    return out


def _has_keys(d: object, keys: set[str]) -> bool:
    if isinstance(d, dict):
        return any(k in keys or _has_keys(v, keys) for k, v in d.items())
    if isinstance(d, list):
        return any(_has_keys(v, keys) for v in d)
    return False


def _uv_deps_findings(spec: dict, t: Target, ctx: _Ctx) -> list[Finding]:
    """For a resolved `uv run --project` server: the locked third-party packages, checked against OSV MAL-*
    advisories in one batch. An unavailable lookup is MED and never cached (fail closed)."""
    from bawwab.scan.osv import known_malware_batch

    if Path(str(spec.get("command", ""))).name != "uv" or t.kind != "local" or not t.path:
        return []
    pkgs = _uv_locked_packages(t.path)
    if pkgs is None:  # changed since it was resolved
        return [Finding("plugin.unresolved-server", Severity.MED, "gate", "uv project changed while scanning")]
    opts = ctx.fetch_opts or FetchOpts()
    return known_malware_batch("pypi", pkgs, base=opts.osv_url, timeout=min(opts.timeout_s, 10))


def _is_plugin_root(t: Target | None, root: Path) -> bool:
    """A bundled server whose code is the plugin's own tree: those files are already in this scan."""
    import os

    return t is not None and t.kind == "local" and bool(t.path) and \
        os.path.realpath(t.path) == os.path.realpath(root)


def _scan_children(f: Fetched, ctx: _Ctx, depth: int, label: str = "") -> list[Finding]:
    if f.artifact_type != "plugin" or f.root is None:
        return []
    servers = _bundled_servers(f.root)
    if depth >= MAX_PLUGIN_DEPTH:
        if not servers:
            return []
        return [Finding(
            "plugin.unresolved-server", Severity.MED, "gate",
            f"nesting depth limit reached; bundled server(s) not scanned: {', '.join(sorted(servers))[:150]}",
        )]
    out: list[Finding] = []
    prefetched = ctx.prefetched if f is ctx.prefetch_for else None
    resolved = prefetched if prefetched is not None else _resolve_children(f, servers, ctx)
    for name, (t, cf) in resolved.items():
        if t is not None:
            out.extend(_prefix(_uv_deps_findings(servers.get(name) or {}, t, ctx), name))
        if cf is None and _is_plugin_root(t, f.root):
            continue  # scanned as part of the plugin itself
        if t is None:
            out.append(Finding(
                "plugin.unresolved-server", Severity.MED, "gate",
                f"[server {name}] cannot resolve how this bundled MCP server starts; it was not scanned",
            ))
            continue
        if isinstance(cf, FetchError):
            out.append(Finding("fetch.failed", Severity.MED, "gate", f"[server {name}] {cf}"))
            continue
        try:
            out.extend(_prefix(_analyze(cf, ctx, depth + 1, f"{label}[server {name}] "), name))
        finally:
            if prefetched is None:
                cf.cleanup()
    return out


def _resolve_children(f: Fetched, servers: dict[str, dict], ctx: _Ctx) -> dict[str, tuple[Target | None, Fetched | FetchError | None]]:
    out: dict[str, tuple[Target | None, Fetched | FetchError | None]] = {}
    for name, spec in servers.items():
        t = _child_target(spec, f.root) if f.root is not None else None
        if t is None:
            out[name] = (None, None)
            continue
        if _is_plugin_root(t, f.root):
            out[name] = (t, None)
            continue
        try:
            out[name] = (t, fetch_target(t, ctx.fetch_opts))
        except FetchError as e:
            out[name] = (t, e)
    return out


def _prefetch_children(f: Fetched, ctx: _Ctx) -> str:
    """Fetch a plugin's bundled servers once, for both the cache key and the analysis. Returns key material."""
    if f.artifact_type != "plugin" or f.root is None:
        return ""
    servers = _bundled_servers(f.root)
    if not servers:
        return ""
    ctx.prefetch_for, ctx.prefetched = f, _resolve_children(f, servers, ctx)
    lines = []
    for name, (t, cf) in ctx.prefetched.items():
        if cf is None and _is_plugin_root(t, f.root):
            lines.append(f"{name}=plugin-root")  # covered by the plugin's own content hash
        elif isinstance(cf, Fetched):
            lines.append(f"{name}@{cf.resolved_version}#{cf.content_hash}")
            if _remote_children(cf):  # nested drift is not in this key: never serve from cache
                ctx.no_cache = True
        else:
            lines.append(f"{name}!{'unresolved' if t is None else 'unfetched'}")
            ctx.no_cache = True
    return "\n".join(sorted(lines))


# ------------------------------------------------------------- pipeline steps

class _Ctx:
    def __init__(self, cfg: Config, mode: Mode, backend: Backend | None, fetch_opts: FetchOpts | None,
                 sandbox: SandboxRunner | None, judge: bool = True) -> None:
        self.cfg, self.mode, self._backend = cfg, mode, backend
        self.fetch_opts, self.sandbox, self.judge = fetch_opts, sandbox, judge
        self.prefetch_for: Fetched | None = None
        self.prefetched: dict | None = None
        self.no_cache = False
        # (label prefix, files, extra, remote tools) for the target, each plugin child and sandbox results
        self.parts: list[tuple[str, list[ScanFile], list[ExtraText], list[ToolInfo]]] = []

    def cleanup_children(self) -> None:
        for _, cf in (self.prefetched or {}).values():
            if isinstance(cf, Fetched):
                cf.cleanup()

    @property
    def backend(self) -> Backend:
        if self._backend is None:
            self._backend = backend_for(self.cfg)
        return self._backend


def _static_step(f: Fetched, fetch_opts: FetchOpts | None = None) -> tuple[list[ScanFile], list[ExtraText], list[Finding]]:
    files: list[ScanFile] = []
    findings = list(f.findings)
    if f.root is not None:
        files, loaded = load_files(f.root)
        findings += loaded
    extra = _extra_from_tools(f.remote_tools)
    findings += identity_checks(f.meta)
    if f.target.kind in ("npm", "pypi"):  # known malware (OSV MAL-*): an extra signal, never fail closed
        opts = fetch_opts or FetchOpts()
        findings += known_malware(f.target.kind, f.target.name or f.meta.name, f.resolved_version,
                                  base=opts.osv_url, timeout=min(opts.timeout_s, 10))
    static = run_static_rules(files, extra)
    if f.target.kind == "npm":  # R31: registry installs do not run `prepare`
        static = registry_install_adjust(files, static)
    findings += static
    return files, extra, findings


def _judge_step(files: list[ScanFile], extra: list[ExtraText], static: list[Finding], ctx: _Ctx) -> list[Finding]:
    if not ctx.judge or not (files or extra):
        return []
    if not static and not model_facing_text(files, extra):
        return []
    try:
        backend = ctx.backend
    except Exception as e:  # noqa: BLE001 - fail closed
        return [Finding("judge.unavailable", Severity.MED, "gate", f"backend error: {type(e).__name__}")]
    return judge(files, extra, static, backend)


def _sandbox_step(f: Fetched, files: list[ScanFile], ctx: _Ctx, label: str = "") -> list[Finding]:
    if ctx.sandbox is None:
        return [Finding("sandbox.unavailable", Severity.MED, "gate", "deep scan requested but no sandbox (Docker) is available")]
    try:
        found, tools = ctx.sandbox.run(f, SANDBOX_TIMEOUT_S)
    except Exception as e:  # noqa: BLE001 - fail closed
        return [Finding("sandbox.unavailable", Severity.MED, "gate", f"sandbox failed: {type(e).__name__}")]
    out = list(found)
    sb_extra = _extra_from_tools(tools)
    if sb_extra:
        ctx.parts.append((f"{label}[sandbox] ", [], sb_extra, []))
    if sb_extra:
        text_findings = run_static_rules([], sb_extra)
        out += text_findings
        out += _judge_step([], sb_extra, text_findings, ctx)
    return out


def _analyze(f: Fetched, ctx: _Ctx, depth: int = 0, label: str = "") -> list[Finding]:
    files, extra, findings = _static_step(f, ctx.fetch_opts)
    ctx.parts.append((label, files, extra, f.remote_tools))
    findings += _scan_children(f, ctx, depth, label)
    findings += _judge_step(files, extra, findings, ctx)
    if ctx.mode == Mode.DEEP:
        findings += _sandbox_step(f, files, ctx, label)
    return findings


def _apply_trust(f: Fetched, findings: list[Finding], cfg: Config) -> list[Finding]:
    """Findings counted toward the verdict. Trusted names: low/med static/judge findings are listed only."""
    name = f.target.name  # only what the user asked to install; never package-declared names
    if f.target.kind not in ("npm", "pypi") or not name or not is_trusted(cfg, name):
        return findings
    return [x for x in findings if x.source in ("identity", "gate", "trust") or x.severity >= Severity.HIGH]


TRANSIENT_RULES = {"plugin.deps-unverified", "judge.unavailable", "sandbox.unavailable", "fetch.failed", "gate.error", "rules.error", "fetch.auth-required"}


def _remote_children(f: Fetched) -> bool:
    """A plugin bundling non-local servers can drift without its own key changing, so it is never served from cache."""
    if f.artifact_type != "plugin" or f.root is None:
        return False
    for spec in _bundled_servers(f.root).values():
        t = _child_target(spec, f.root)
        if t is None or t.kind != "local":
            return True
    return False


def _build_snapshot(parts) -> dict:
    snap: dict | None = None
    for prefix, files, extra, tools in parts:
        s = make_snapshot(files, model_facing_text(files, extra), tools)
        snap = s if snap is None else merge_snapshots(snap, s, prefix)
    return snap or make_snapshot([], [], [])


def _baseline_cached(f: Fetched, t: Target, key: str, store: Store) -> None:
    """A clean cache hit still baselines trust if no trusted snapshot exists for this name."""
    tname = trust_name(t)
    if store.latest_snapshot(tname) is not None:
        return
    snap = store.get_scan_snapshot(key)
    if snap is None and f.artifact_type != "plugin":  # plugin children cannot be rebuilt without a rescan
        files = load_files(f.root)[0] if f.root is not None else []
        extra = _extra_from_tools(f.remote_tools)
        snap = make_snapshot(files, model_facing_text(files, extra), f.remote_tools)
    if snap is not None:
        store.put_snapshot(tname, key, snap)


# Findings that mean "look again next time" without failing closed: a known-malware lookup that
# failed must run again (R41 I1, R42).
RECHECK_RULES = {"identity.osv-unavailable"}


def needs_recheck(r: ScanReport) -> bool:
    return any(f.rule in RECHECK_RULES for f in r.findings)


def _cacheable(r: ScanReport) -> bool:
    return not needs_recheck(r) and not any(f.source == "gate" and f.rule in TRANSIENT_RULES for f in r.findings)


STATIC_KEY_SUFFIX = "~static"  # scans made without the judge (judge=False)


def _fetch_key(t: Target) -> str:
    return f"{t.kind}:{t.name or t.url or t.path or t.raw}@unfetched"


def scan_target(
    t: Target,
    *,
    mode: Mode | None = None,
    cfg: Config | None = None,
    backend: Backend | None = None,
    fetch_opts: FetchOpts | None = None,
    sandbox: SandboxRunner | None = None,
    no_cache: bool = False,
    store: Store | None = None,
    judge: bool = True,
) -> ScanReport:
    """Fetch (never execute) and scan a target.

    judge=False skips the AI judge entirely (static rules only, e.g. the benchmark's --static-only run).
    Such a report is filed under its own key (suffix "~static") so it is never served from cache to a
    judged scan, and it never baselines trust.
    """
    cfg = cfg or load_config(Path.cwd())
    mode = mode or cfg.mode
    store = store or open_store()
    try:
        f = fetch_target(t, fetch_opts)
    except FetchError as e:
        r = synthetic_report(str(e), _fetch_key(t), t, "fetch.failed", mode)
        store.put_report(r)
        store.audit("scan", key=r.key, verdict=r.verdict.value, mode=mode.value)
        return r
    ctx = None
    try:
        ctx = _Ctx(cfg, mode, backend, fetch_opts, sandbox, judge=judge)
        child_material = _prefetch_children(f, ctx)
        chash = f.content_hash
        if child_material:
            chash = hashlib.sha256(f"{chash}\n{child_material}".encode()).hexdigest()
        key = target_key(t, f.resolved_version, chash) + ("" if judge else STATIC_KEY_SUFFIX)
        if not no_cache and not ctx.no_cache:
            cached = store.get_cached(key)
            if cached is not None and _cacheable(cached) and (cached.mode == mode or cached.mode == Mode.DEEP):
                if judge and cached.verdict == Verdict.CLEAN:  # an unjudged scan never baselines trust
                    _baseline_cached(f, t, key, store)
                return cached
        try:
            findings = _analyze(f, ctx)
            snap = _build_snapshot(ctx.parts)
            tname = trust_name(t)
            prev = store.latest_snapshot(tname)
            diff_summary = None
            # A sign-in-gated remote showed no tools: nothing to compare or baseline (R26f).
            unread = any(x.rule == "fetch.auth-required" for x in findings)
            if not unread and prev is not None and (prev[0] != key or prev[1] != snap):
                rug, diff_summary = diff_snapshots(prev[1], snap)
                findings += rug
        except Exception as e:  # noqa: BLE001 - fail closed on anything unexpected
            from bawwab.report import sanitise

            r = synthetic_report(
                sanitise(f"{type(e).__name__}: {e}", 200), key, t, "gate.error", mode
            )
            r.resolved_version = f.resolved_version
            store.put_report(r)
            store.audit("scan", key=key, verdict=r.verdict.value, mode=mode.value)
            return r
        counted = _apply_trust(f, findings, cfg)
        verdict = compute_verdict(counted, cfg.malicious, cfg.suspicious)
        report = ScanReport(
            key, t, f.resolved_version, mode, verdict, findings, datetime.now(UTC), diff_summary=diff_summary or None
        )
        store.put_report(report, snapshot=snap)
        if judge and verdict == Verdict.CLEAN and not unread and (prev is None or prev[1] != snap):
            store.put_snapshot(tname, key, snap)
        store.audit("scan", key=key, verdict=verdict.value, mode=mode.value)
        return report
    finally:
        if ctx is not None:
            ctx.cleanup_children()
        f.cleanup()
