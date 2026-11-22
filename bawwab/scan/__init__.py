from __future__ import annotations

import dataclasses
import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from bawwab.config import Config, is_trusted, load_config
from bawwab.fetch import FetchError, FetchOpts, fetch_target, target_from_command, target_from_url
from bawwab.scan.files import ExtraText, ScanFile, load_files
from bawwab.scan.identity import identity_checks
from bawwab.scan.osv import known_malware
from bawwab.scan.reach import classify, demote_unreachable
from bawwab.scan.judge.backends import Backend, backend_for
from bawwab.scan.judge.judge import judge
from bawwab.scan.rules import run_static_rules
from bawwab.scan.rules.code import registry_install_adjust
from bawwab.scan.rules.text import model_facing_text
from bawwab.severity import compute_verdict
from bawwab.store import Store, open_store, target_key
from bawwab.trust import diff_snapshots, make_snapshot, merge_snapshots, trust_name
from bawwab.types import Advice, Fetched, Finding, Mode, ScanReport, Severity, Target, ToolInfo, Verdict

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
        if s.startswith(("./", "../")):
            return str(root / s)
        # a bare relative script ("server.js", "dist/index.js") is relative to the plugin, never to the scanner's
        # own working directory
        if s and not s.startswith(("-", "/", "~", "$")) and "\n" not in s and len(s) < 4096:
            try:
                if (root / s).exists():
                    return str(root / s)
            except (OSError, ValueError):
                pass
        return s

    if isinstance(spec.get("url"), str) and spec["url"]:
        return target_from_url(spec["url"], spec.get("type"))
    cmd, args = spec.get("command"), spec.get("args", [])
    if not isinstance(cmd, str) or not isinstance(args, list) or not all(isinstance(a, str) for a in args):
        return None
    if _package_manager_run(cmd, args):
        return None  # R53: never resolved; see _package_manager_findings
    t = target_from_command(sub(cmd), [sub(a) for a in args])
    if t is not None and t.kind == "local":
        try:
            inside = bool(t.path) and Path(t.path).is_dir() and Path(t.path).resolve().is_relative_to(root.resolve())
        except (OSError, ValueError):  # e.g. a path too long to stat: not a server dir
            inside = False
        if not inside:  # a local server outside the plugin (or the scanner's cwd) is not this plugin's code
            return None
    return t


# Commands that run a project through a package manager (R53). Their start-up downloads and builds dependencies
# (build hooks, setup_requires, extra build deps, indexes from config or env, a shipped `uv`...), so such a server
# is never counted as resolved or fully scanned: MED plugin.unresolved-server, always.
_PM_RUN = {"uv": ("run",), "poetry": ("run",), "pipenv": ("run",), "pdm": ("run",), "hatch": ("run",),
           "rye": ("run",), "npm": ("run", "run-script", "start", "exec", "x"), "pnpm": ("run", "start", "exec"),
           "yarn": ("run", "start", "exec"), "bun": ("run", "x")}


def _package_manager_run(cmd: str, args: list) -> bool:
    words = _PM_RUN.get(Path(cmd).name)
    first = next((a for a in args if isinstance(a, str) and not a.startswith("-")), None)
    return bool(words) and first in words


def _uv_project_dir(args: list[str], root: Path) -> str | None:
    """The `--project` dir of a `uv run`, when it is inside the plugin root (else None)."""
    import os

    project = None
    for i, x in enumerate(args):
        if x == "--project" and i + 1 < len(args):
            project = args[i + 1]
            break
        if x.startswith("--project="):
            project = x.split("=", 1)[1]
            break
    if not project:
        return None
    base = os.path.realpath(root)
    proj = os.path.realpath(project if os.path.isabs(project) else os.path.join(base, project))
    return proj if proj == base or proj.startswith(base + os.sep) else None


def _uv_locked_packages(proj: str) -> list[tuple[str, str]]:
    """Third-party (name, version) pairs in <proj>/uv.lock: everything but the project itself."""
    import os
    import tomllib

    try:
        with open(os.path.join(proj, "uv.lock"), "rb") as fh:
            lock = tomllib.load(fh)
    except (OSError, ValueError, RecursionError):
        return []
    out = []
    for pk in lock.get("package") or [] if isinstance(lock, dict) else []:
        if not isinstance(pk, dict) or not isinstance(pk.get("name"), str) or not isinstance(pk.get("version"), str):
            continue
        src = pk.get("source")
        if isinstance(src, dict) and (src.get("editable") == "." or src.get("virtual") == "."):
            continue
        out.append((pk["name"], pk["version"]))
    return out


def _package_manager_findings(name: str, spec: dict, root: Path, ctx: _Ctx, depth: int, label: str) -> list[Finding]:
    """R53: a package-manager-run server is MED unresolved, whatever else is true. Its local project files are
    still scanned (a subdirectory project as a child; the plugin root already is), and a uv.lock's packages go
    to the OSV MAL batch (a hit: CRITICAL; OSV down: MED plugin.deps-unverified, never cached). Nothing here
    clears a finding."""
    from bawwab.scan.osv import known_malware_batch

    cmd, args = spec.get("command", ""), [str(a) for a in spec.get("args", [])]
    args = [a.replace("${CLAUDE_PLUGIN_ROOT}", str(root)) for a in args]
    tool = Path(cmd).name
    out = [Finding("plugin.unresolved-server", Severity.MED, "gate",
                   f"[server {name}] starts through a package manager ({tool} "
                   f"{next((a for a in args if not a.startswith('-')), '')}): it downloads and builds dependencies "
                   "when it starts, which Bawwab can't scan")]
    proj = _uv_project_dir(args, root) if tool == "uv" else None
    if proj is None:
        return out
    import os

    if os.path.realpath(proj) != os.path.realpath(root):
        try:
            cf = fetch_target(Target("local", proj, name=proj, path=proj), ctx.fetch_opts)
        except FetchError as e:
            out.append(Finding("fetch.failed", Severity.MED, "gate", f"[server {name}] {e}"))
        else:
            try:
                out.extend(_prefix(_analyze(cf, ctx, depth + 1, f"{label}[server {name}] "), name))
            finally:
                cf.cleanup()
    pkgs = _uv_locked_packages(proj)
    if pkgs:
        opts = ctx.fetch_opts or FetchOpts()
        out.extend(_prefix(known_malware_batch("pypi", pkgs, base=opts.osv_url, timeout=min(opts.timeout_s, 10)),
                           name))
    return out


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
        spec = servers.get(name) or {}
        if t is None and _package_manager_run(str(spec.get("command", "")), spec.get("args") or []):
            out.extend(_package_manager_findings(name, spec, f.root, ctx, depth, label))
            continue
        if t is None:
            out.append(Finding(
                "plugin.unresolved-server", Severity.MED, "gate",
                f"[server {name}] cannot resolve how this bundled MCP server starts; it was not scanned",
            ))
            continue
        if isinstance(cf, FetchError):
            out.append(Finding("fetch.failed", Severity.MED, "gate", f"[server {name}] {cf}"))
            continue
        if _root_id(cf.root) in ctx.active:
            # The server runs from a directory already being scanned (`node ${CLAUDE_PLUGIN_ROOT}/start.mjs`):
            # its code is in that scan. Scanning it again only repeated every finding under [server X] and
            # ended in a "nesting depth limit" MED.
            if prefetched is None:
                cf.cleanup()
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
        if isinstance(cf, Fetched):
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
        self.active: set[str] = set()  # real paths of the roots being analysed (no self-recursive servers)
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
    # FP plan step 1: a finding in a file that never runs and that the agent never reads is listed, not counted.
    try:
        findings = demote_unreachable(findings, classify(f.root, files))
    except Exception:  # noqa: BLE001 - the classifier is best effort: on any error everything stays counted
        pass
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
    from bawwab.sandbox.docker import SandboxUnavailable

    try:
        found, tools = ctx.sandbox.run(f, SANDBOX_TIMEOUT_S)
    except SandboxUnavailable as e:  # fail closed: deep mode without a sandbox run is never a pass
        from bawwab.report import sanitise

        return [Finding("sandbox.unavailable", Severity.MED, "gate", f"deep scan could not run: {sanitise(e, 200)}")]
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


def _review_step(f: Fetched, ctx: _Ctx, report: ScanReport, counted: list[Finding]) -> Advice:
    """Claude's recommendation (spec §4a), while f.root still exists. It never fails the scan and never
    changes the verdict or findings: any error is cant-tell."""
    try:
        from bawwab.scan.review import review

        files = ctx.parts[0][1] if ctx.parts else []
        extra = [ExtraText(prefix + x.label, x.text) for prefix, _, xs, _ in ctx.parts for x in xs]
        return review(f.root, report, files, ctx.backend, counted=counted, extra=extra)
    except Exception as e:  # noqa: BLE001 - the reviewer is advice; the scan stands without it
        return Advice.cant_tell(f"reviewer error: {type(e).__name__}")


def _root_id(root: Path | None) -> str | None:
    import os

    return os.path.realpath(root) if root is not None else None


def _analyze(f: Fetched, ctx: _Ctx, depth: int = 0, label: str = "") -> list[Finding]:
    files, extra, findings = _static_step(f, ctx.fetch_opts)
    ctx.parts.append((label, files, extra, f.remote_tools))
    rid = _root_id(f.root)
    added = rid is not None and rid not in ctx.active
    if added:
        ctx.active.add(rid)
    try:
        findings += _scan_children(f, ctx, depth, label)
    finally:
        if added:
            ctx.active.discard(rid)
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


def _under_current_policy(f: Fetched, cached: ScanReport, cfg: Config) -> ScanReport:
    """A cache hit judged by today's settings: the cache holds what was found, never the decision.

    The verdict is recomputed from the cached findings with the current trusted list and thresholds, exactly
    as a fresh scan would (no rescan: the findings depend on the content, which the key pins). If that
    changes the verdict, the cached recommendation was made for a different verdict (and a keep-with-care for
    SUSPICIOUS must never ride along on a now-MALICIOUS result, spec §4a), so it is replaced: by nothing when
    the result is now clean, else by cant-tell saying why. The reviewer is not re-run on a hit: it would
    need the judge's per-part inputs that only a full scan builds, and an LLM call per cache hit; a
    `--no-cache` scan gives a fresh recommendation. The stored report is left as it was.
    """
    verdict = compute_verdict(_apply_trust(f, cached.findings, cfg), cfg.malicious, cfg.suspicious)
    if verdict == cached.verdict:
        return cached
    advice = None
    if verdict != Verdict.CLEAN and cfg.review_enabled:
        advice = Advice.cant_tell(f"verdict changed from {cached.verdict.value} to {verdict.value} under the "
                                  f"current settings since the review; `bawwab scan --no-cache` gives a new one")
    return dataclasses.replace(cached, verdict=verdict, advice=advice)


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
    if mode == Mode.DEEP and sandbox is None:
        from bawwab.sandbox import default_runner

        sandbox = default_runner()
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
        try:
            child_material = _prefetch_children(f, ctx)
        except Exception as e:  # noqa: BLE001 - a bundled server that can't be prepared fails closed, never crashes
            from bawwab.report import sanitise

            r = synthetic_report(sanitise(f"could not prepare the bundled servers: {type(e).__name__}: {e}", 200),
                                 _fetch_key(t), t, "gate.error", mode)
            r.resolved_version = f.resolved_version
            store.put_report(r)
            store.audit("scan", key=r.key, verdict=r.verdict.value, mode=mode.value)
            return r
        chash = f.content_hash
        if child_material:
            chash = hashlib.sha256(f"{chash}\n{child_material}".encode()).hexdigest()
        key = target_key(t, f.resolved_version, chash) + ("" if judge else STATIC_KEY_SUFFIX)
        if not no_cache and not ctx.no_cache:
            cached = store.get_cached(key)
            if cached is not None and _cacheable(cached) and (cached.mode == mode or cached.mode == Mode.DEEP):
                cached = _under_current_policy(f, cached, cfg)
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
        if verdict != Verdict.CLEAN and judge and mode in (Mode.STANDARD, Mode.DEEP) and cfg.review_enabled:
            report.advice = _review_step(f, ctx, report, [x for x in counted if x.severity >= cfg.suspicious])
        store.put_report(report, snapshot=snap)
        if judge and verdict == Verdict.CLEAN and not unread and (prev is None or prev[1] != snap):
            store.put_snapshot(tname, key, snap)
        store.audit("scan", key=key, verdict=verdict.value, mode=mode.value)
        return report
    finally:
        if ctx is not None:
            ctx.cleanup_children()
        f.cleanup()
