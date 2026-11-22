from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal

from bawwab.paths import bawwab_home
from bawwab.types import Mode, Severity, Verdict

# Security levels: what a verdict that isn't clean does (spec "Security levels"). Bawwab's self-protection
# (protected actions, a failed effect check) blocks at every level.
LEVELS = ("low", "medium", "high")
DEFAULT_LEVEL = "high"


def blocks(level: str, verdict: Verdict) -> bool:
    """high blocks anything not clean; medium blocks malicious only; low never blocks (it warns)."""
    if verdict == Verdict.CLEAN:
        return False
    if level == "low":
        return False
    if level == "medium":
        return verdict == Verdict.MALICIOUS
    return True  # high, or an unknown level: fail closed


@dataclass
class Config:
    mode: Mode = Mode.STANDARD
    llm_backend: Literal["claude-cli", "api"] = "claude-cli"
    llm_model: str = "claude-sonnet-5-5"
    malicious: Severity = Severity.CRITICAL
    suspicious: Severity = Severity.MED
    trusted: list[str] = field(default_factory=lambda: ["@modelcontextprotocol/*"])
    level: str = DEFAULT_LEVEL
    review_enabled: bool = True  # "review": {"enabled": bool}, spec §4a
    # "quiet": true hides the one-line "bawwab: scanned <item>" status after an install passes. Only the global
    # config sets it (a project can't hide bawwab's output); warnings and blocks are never hidden.
    quiet: bool = False


DEFAULT_CONFIG = Config()


def is_trusted(cfg: Config, name: str) -> bool:
    return any(fnmatch.fnmatchcase(name, p) for p in cfg.trusted)


def _read(path: Path) -> tuple[dict | None, bool]:
    """Returns (data, invalid). Missing file -> (None, False)."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return None, False
    except OSError:
        return None, True
    try:
        data = json.loads(text)
    except ValueError:
        return None, True
    return (data, False) if isinstance(data, dict) else (None, True)


def _enum(cls, value, default):
    try:
        return cls(value)
    except (ValueError, TypeError):
        return default


def _apply(base: Config, d: dict) -> Config:
    """Apply a (global) config dict over base; unknown keys ignored, bad values fall back."""
    cfg = replace(base, trusted=list(base.trusted))
    cfg.mode = _enum(Mode, d.get("mode", cfg.mode), base.mode)
    if d.get("level") in LEVELS:
        cfg.level = d["level"]
    llm = d.get("llm") if isinstance(d.get("llm"), dict) else {}
    if llm.get("backend") in ("claude-cli", "api"):
        cfg.llm_backend = llm["backend"]
    if isinstance(llm.get("model"), str) and llm["model"]:
        cfg.llm_model = llm["model"]
    th = d.get("thresholds") if isinstance(d.get("thresholds"), dict) else {}
    cfg.malicious = _enum(Severity, th.get("malicious", cfg.malicious), base.malicious)
    cfg.suspicious = _enum(Severity, th.get("suspicious", cfg.suspicious), base.suspicious)
    tr = d.get("trusted")
    if isinstance(tr, list) and all(isinstance(x, str) for x in tr):
        cfg.trusted = list(tr)
    rv = d.get("review") if isinstance(d.get("review"), dict) else {}
    if isinstance(rv.get("enabled"), bool):
        cfg.review_enabled = rv["enabled"]
    if isinstance(d.get("quiet"), bool):
        cfg.quiet = d["quiet"]
    return cfg


def _tighten(cfg: Config, d: dict) -> Config:
    """Project config may only tighten: deep mode, lower thresholds, narrower trusted, review on. llm ignored."""
    out = replace(cfg, trusted=list(cfg.trusted))
    if _enum(Mode, d.get("mode"), None) == Mode.DEEP:
        out.mode = Mode.DEEP
    if d.get("level") in LEVELS and LEVELS.index(d["level"]) > LEVELS.index(out.level):
        out.level = d["level"]
    th = d.get("thresholds") if isinstance(d.get("thresholds"), dict) else {}
    m = _enum(Severity, th.get("malicious"), None)
    if m is not None and m < out.malicious:
        out.malicious = m
    s = _enum(Severity, th.get("suspicious"), None)
    if s is not None and s < out.suspicious:
        out.suspicious = s
    tr = d.get("trusted")
    if isinstance(tr, list) and all(isinstance(x, str) for x in tr):
        base = cfg.trusted
        # Exact, glob-unaware intersection: a global pattern survives only if listed
        # literally; a project entry survives if it equals a global pattern, or is a
        # plain name (no glob metacharacters) that the global patterns already trust.
        kept = [g for g in base if g in tr]
        for e in dict.fromkeys(tr):
            if e not in kept and not any(c in e for c in "*?[") and is_trusted(cfg, e):
                kept.append(e)
        out.trusted = kept
    rv = d.get("review") if isinstance(d.get("review"), dict) else {}
    if rv.get("enabled") is True:
        out.review_enabled = True
    return out


def level_is_set() -> bool:
    """The user has chosen a level (it is in ~/.bawwab/config.json); until then the level is high."""
    data, _ = _read(bawwab_home() / "config.json")
    return bool(data) and data.get("level") in LEVELS


def set_level(level: str) -> None:
    """Write the level into ~/.bawwab/config.json, keeping its other keys (an unreadable file is replaced)."""
    import os

    if level not in LEVELS:
        raise ValueError(f"level must be one of {', '.join(LEVELS)}")
    path = bawwab_home() / "config.json"
    data, _ = _read(path)
    data = dict(data or {})
    data["level"] = level
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(f".config.json.{os.getpid()}.tmp")
    tmp.write_text(json.dumps(data, indent=2) + "\n")
    os.replace(tmp, path)


def load_config(project_dir: Path | None = None) -> Config:
    invalid: list[str] = []
    cfg = replace(DEFAULT_CONFIG, trusted=list(DEFAULT_CONFIG.trusted))
    gpath = bawwab_home() / "config.json"
    data, bad = _read(gpath)
    if bad:
        invalid.append(str(gpath))
    elif data is not None:
        cfg = _apply(cfg, data)
    if project_dir is not None:
        ppath = Path(project_dir) / ".claude" / "bawwab.json"
        pdata, pbad = _read(ppath)
        if pbad:
            invalid.append(str(ppath))
        elif pdata is not None:
            cfg = _tighten(cfg, pdata)
    if invalid:
        from bawwab.store import open_store

        try:
            open_store().audit("config.invalid", paths=invalid)
        except Exception:  # config loading must never fail because of the audit log
            pass
    return cfg
