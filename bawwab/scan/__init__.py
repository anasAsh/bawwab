from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Protocol

from bawwab.config import Config, is_trusted, load_config
from bawwab.fetch import FetchError, FetchOpts, fetch_target, target_from_command, target_from_url
from bawwab.scan.files import ExtraText, ScanFile, load_files
from bawwab.scan.identity import identity_checks
from bawwab.scan.judge.backends import Backend, backend_for
from bawwab.scan.judge.judge import judge
from bawwab.scan.rules import run_static_rules
from bawwab.scan.rules.text import model_facing_text
from bawwab.severity import compute_verdict
from bawwab.store import Store, open_store, target_key
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
    t = target_from_command(sub(cmd), [sub(a) for a in args])
    if t is not None and t.kind == "local" and not (t.path and Path(t.path).is_dir()):
        return None
    return t


def _scan_children(f: Fetched, ctx: _Ctx, depth: int) -> list[Finding]:
    if f.artifact_type != "plugin" or f.root is None or depth >= MAX_PLUGIN_DEPTH:
        return []
    out: list[Finding] = []
    for name, spec in _bundled_servers(f.root).items():
        t = _child_target(spec, f.root)
        if t is None:
            out.append(Finding(
                "plugin.unresolved-server", Severity.MED, "gate",
                f"[server {name}] cannot resolve how this bundled MCP server starts; it was not scanned",
            ))
            continue
        try:
            cf = fetch_target(t, ctx.fetch_opts)
        except FetchError as e:
            out.append(Finding("fetch.failed", Severity.MED, "gate", f"[server {name}] {e}"))
            continue
        try:
            out.extend(_prefix(_analyze(cf, ctx, depth + 1), name))
        finally:
            cf.cleanup()
    return out


# ------------------------------------------------------------- pipeline steps

class _Ctx:
    def __init__(self, cfg: Config, mode: Mode, backend: Backend | None, fetch_opts: FetchOpts | None,
                 sandbox: SandboxRunner | None) -> None:
        self.cfg, self.mode, self._backend = cfg, mode, backend
        self.fetch_opts, self.sandbox = fetch_opts, sandbox

    @property
    def backend(self) -> Backend:
        if self._backend is None:
            self._backend = backend_for(self.cfg)
        return self._backend


def _static_step(f: Fetched) -> tuple[list[ScanFile], list[ExtraText], list[Finding]]:
    files: list[ScanFile] = []
    findings = list(f.findings)
    if f.root is not None:
        files, loaded = load_files(f.root)
        findings += loaded
    extra = _extra_from_tools(f.remote_tools)
    findings += identity_checks(f.meta)
    findings += run_static_rules(files, extra)
    return files, extra, findings


def _judge_step(files: list[ScanFile], extra: list[ExtraText], static: list[Finding], ctx: _Ctx) -> list[Finding]:
    if not (files or extra):
        return []
    if not static and not model_facing_text(files, extra):
        return []
    return judge(files, extra, static, ctx.backend)


def _sandbox_step(f: Fetched, files: list[ScanFile], ctx: _Ctx) -> list[Finding]:
    if ctx.sandbox is None:
        return [Finding("sandbox.unavailable", Severity.MED, "gate", "deep scan requested but no sandbox (Docker) is available")]
    try:
        found, tools = ctx.sandbox.run(f, SANDBOX_TIMEOUT_S)
    except Exception as e:  # noqa: BLE001 - fail closed
        return [Finding("sandbox.unavailable", Severity.MED, "gate", f"sandbox failed: {type(e).__name__}")]
    out = list(found)
    sb_extra = _extra_from_tools(tools)
    if sb_extra:
        text_findings = run_static_rules([], sb_extra)
        out += text_findings
        out += _judge_step([], sb_extra, text_findings, ctx)
    return out


def _analyze(f: Fetched, ctx: _Ctx, depth: int = 0) -> list[Finding]:
    files, extra, findings = _static_step(f)
    findings += _scan_children(f, ctx, depth)
    findings += _judge_step(files, extra, findings, ctx)
    if ctx.mode == Mode.DEEP:
        findings += _sandbox_step(f, files, ctx)
    return findings


def _apply_trust(f: Fetched, findings: list[Finding], cfg: Config) -> list[Finding]:
    """Findings counted toward the verdict. Trusted names: low/med static/judge findings are listed only."""
    name = f.target.name or f.meta.name
    if not name or not is_trusted(cfg, name):
        return findings
    return [x for x in findings if x.source in ("identity", "gate") or x.severity >= Severity.HIGH]


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
) -> ScanReport:
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
    try:
        key = target_key(t, f.resolved_version, f.content_hash)
        if not no_cache:
            cached = store.get_cached(key)
            if cached is not None and (cached.mode == mode or cached.mode == Mode.DEEP):
                return cached
        ctx = _Ctx(cfg, mode, backend, fetch_opts, sandbox)
        findings = _analyze(f, ctx)
        # (Task 8: rug-pull / snapshot comparison goes here)
        counted = _apply_trust(f, findings, cfg)
        verdict = compute_verdict(counted, cfg.malicious, cfg.suspicious)
        report = ScanReport(key, t, f.resolved_version, mode, verdict, findings, datetime.now(UTC))
        store.put_report(report)
        store.audit("scan", key=key, verdict=verdict.value, mode=mode.value)
        return report
    finally:
        f.cleanup()
