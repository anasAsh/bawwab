from __future__ import annotations

import fnmatch
import json
from dataclasses import dataclass, field, replace
from pathlib import Path
from typing import Literal

from bawwab.paths import bawwab_home
from bawwab.types import Mode, Severity


@dataclass
class Config:
    mode: Mode = Mode.STANDARD
    llm_backend: Literal["claude-cli", "api"] = "claude-cli"
    llm_model: str = "claude-sonnet-5-5"
    malicious: Severity = Severity.CRITICAL
    suspicious: Severity = Severity.MED
    trusted: list[str] = field(default_factory=lambda: ["@modelcontextprotocol/*"])


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
    return cfg


def _tighten(cfg: Config, d: dict) -> Config:
    """Project config may only tighten: deep mode, lower thresholds, narrower trusted. llm ignored."""
    out = replace(cfg, trusted=list(cfg.trusted))
    if _enum(Mode, d.get("mode"), None) == Mode.DEEP:
        out.mode = Mode.DEEP
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
        # Intersection: a global pattern survives if some project pattern covers it;
        # a project entry survives (narrowed) if the global list already covers it.
        kept = [g for g in base if any(fnmatch.fnmatchcase(g, p) for p in tr)]
        kept += [p for p in dict.fromkeys(tr) if p not in kept and is_trusted(cfg, p)]
        out.trusted = kept
    return out


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
