from __future__ import annotations

import hashlib
import json
import os
import secrets
import sqlite3
from datetime import datetime, timedelta, timezone

from bawwab.paths import bawwab_home
from bawwab.types import Finding, Mode, ScanReport, Severity, Target, Verdict

PENDING_TTL = timedelta(hours=1)
_ID_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"  # RFC 4648 base32

# Each entry migrates from user_version i to i+1. Add columns with a new entry
# (guard with _add_column so re-running is idempotent).
_SCHEMA_V1 = """
CREATE TABLE IF NOT EXISTS scans (key TEXT PRIMARY KEY, report TEXT NOT NULL, scanned_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS findings (id TEXT PRIMARY KEY, key TEXT NOT NULL, finding TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS pending (
    id TEXT PRIMARY KEY, key TEXT NOT NULL, report TEXT NOT NULL,
    created_at TEXT NOT NULL, expires_at TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending');
CREATE TABLE IF NOT EXISTS approvals (key TEXT PRIMARY KEY, approved_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS rejections (key TEXT PRIMARY KEY, rejected_at TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, event TEXT NOT NULL, fields TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS warnings (id INTEGER PRIMARY KEY AUTOINCREMENT, text TEXT NOT NULL, ts TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS snapshots (
    id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT NOT NULL, key TEXT NOT NULL,
    snap TEXT NOT NULL, ts TEXT NOT NULL);
CREATE INDEX IF NOT EXISTS snapshots_name ON snapshots(name, id);
CREATE INDEX IF NOT EXISTS findings_key ON findings(key);
"""


def _migrate_1(conn: sqlite3.Connection) -> None:
    for stmt in _SCHEMA_V1.strip().split(";"):
        if stmt.strip():
            conn.execute(stmt)


def _add_column(conn: sqlite3.Connection, table: str, column: str, decl: str) -> None:
    cols = {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {decl}")


def _migrate_2(conn: sqlite3.Connection) -> None:
    _add_column(conn, "scans", "snapshot", "TEXT")


_MIGRATIONS = [_migrate_1, _migrate_2]
_VERDICT_RANK = {Verdict.CLEAN: 0, Verdict.SUSPICIOUS: 1, Verdict.MALICIOUS: 2}


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _utc(dt: datetime) -> datetime:
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _iso(dt: datetime) -> str:
    return _utc(dt).isoformat()


def _gen_id() -> str:
    return "".join(secrets.choice(_ID_ALPHABET) for _ in range(4))


def target_key(t: Target, version: str, content_hash: str) -> str:
    return f"{t.kind}:{t.name or t.url or t.path}@{version}#{content_hash[:16]}"


def report_to_dict(r: ScanReport) -> dict:
    return {
        "key": r.key,
        "target": {
            "kind": r.target.kind, "raw": r.target.raw, "name": r.target.name,
            "version": r.target.version, "url": r.target.url, "path": r.target.path,
        },
        "resolved_version": r.resolved_version,
        "mode": r.mode.value,
        "verdict": r.verdict.value,
        "findings": [
            {"rule": f.rule, "severity": f.severity.value, "source": f.source,
             "evidence": f.evidence, "file": f.file, "line": f.line, "id": f.id}
            for f in r.findings
        ],
        "scanned_at": _iso(r.scanned_at),
        "diff_summary": r.diff_summary,
    }


def _finding_from_dict(d: dict) -> Finding:
    return Finding(
        rule=d["rule"], severity=Severity(d["severity"]), source=d["source"], evidence=d["evidence"],
        file=d.get("file"), line=d.get("line"), id=d.get("id", ""),
    )


def report_from_dict(d: dict) -> ScanReport:
    return ScanReport(
        key=d["key"],
        target=Target(**d["target"]),
        resolved_version=d["resolved_version"],
        mode=Mode(d["mode"]),
        verdict=Verdict(d["verdict"]),
        findings=[_finding_from_dict(f) for f in d["findings"]],
        scanned_at=_utc(datetime.fromisoformat(d["scanned_at"])),
        diff_summary=d.get("diff_summary"),
    )


def _hash(material: str) -> str:
    return hashlib.sha256(material.encode()).hexdigest()


def _finding_material(key: str, f: Finding, ordinal: int) -> str:
    return f"{key}\0{f.rule}\0{f.file}\0{f.line}\0{f.evidence}\0{ordinal}"


class Store:
    def __init__(self, path) -> None:
        # isolation_level=None: we manage transactions explicitly (short, IMMEDIATE).
        self._conn = sqlite3.connect(str(path), timeout=5.0, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA busy_timeout=5000")
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._migrate()

    def _migrate(self) -> None:
        with self._tx():
            v = self._conn.execute("PRAGMA user_version").fetchone()[0]
            for i in range(v, len(_MIGRATIONS)):
                _MIGRATIONS[i](self._conn)
                self._conn.execute(f"PRAGMA user_version={i + 1}")

    def _tx(self):
        return _Tx(self._conn)

    # --- scans ---
    def get_cached(self, key: str) -> ScanReport | None:
        row = self._conn.execute("SELECT report FROM scans WHERE key=?", (key,)).fetchone()
        if not row:
            return None
        try:
            return report_from_dict(json.loads(row[0]))
        except (ValueError, KeyError, TypeError):
            self.audit("store.corrupt", table="scans", key=key)
            return None

    def put_report(self, r: ScanReport, snapshot: dict | None = None) -> None:
        data = None
        with self._tx():
            self._conn.execute("DELETE FROM findings WHERE key=?", (r.key,))
            for i, f in enumerate(r.findings):
                digest = _hash(_finding_material(r.key, f, i))
                n = 6
                while True:
                    f.id = "F" + digest[:n]
                    payload = json.dumps(report_to_dict(_one(r, f))["findings"][0])
                    row = self._conn.execute(
                        "SELECT key, finding FROM findings WHERE id=?", (f.id,)
                    ).fetchone()
                    if row is None:
                        self._conn.execute(
                            "INSERT INTO findings(id, key, finding) VALUES (?,?,?)", (f.id, r.key, payload)
                        )
                        break
                    if row["key"] == r.key and row["finding"] == payload:
                        break  # identical finding already stored: no-op
                    n += 2
                    if n > len(digest):  # pragma: no cover - unreachable in practice
                        raise sqlite3.IntegrityError("finding id space exhausted")
            data = json.dumps(report_to_dict(r))
            self._conn.execute(
                "INSERT OR REPLACE INTO scans(key, report, scanned_at, snapshot) VALUES (?,?,?,?)",
                (r.key, data, _iso(r.scanned_at), json.dumps(snapshot) if snapshot is not None else None),
            )

    def get_scan_snapshot(self, key: str) -> dict | None:
        row = self._conn.execute("SELECT snapshot FROM scans WHERE key=?", (key,)).fetchone()
        if not row or not row[0]:
            return None
        try:
            return json.loads(row[0])
        except ValueError:
            return None

    def get_finding(self, finding_id: str) -> tuple[Finding, str] | None:
        row = self._conn.execute("SELECT key, finding FROM findings WHERE id=?", (finding_id,)).fetchone()
        if not row:
            return None
        try:
            return _finding_from_dict(json.loads(row["finding"])), row["key"]
        except (ValueError, KeyError, TypeError):
            self.audit("store.corrupt", table="findings", id=finding_id)
            return None

    # --- approvals ---
    def create_pending(self, r: ScanReport, now: datetime | None = None) -> str:
        now = _utc(now or _now())
        data = json.dumps(report_to_dict(r))
        with self._tx():
            while True:
                pid = _gen_id()
                row = self._conn.execute("SELECT expires_at FROM pending WHERE id=?", (pid,)).fetchone()
                if row is None or datetime.fromisoformat(row[0]) <= now:
                    break
            self._conn.execute(
                "UPDATE pending SET status='superseded' WHERE key=? AND status='pending' AND expires_at>?",
                (r.key, _iso(now)),
            )
            self._conn.execute(
                "INSERT OR REPLACE INTO pending(id, key, report, created_at, expires_at, status)"
                " VALUES (?,?,?,?,?, 'pending')",
                (pid, r.key, data, _iso(now), _iso(now + PENDING_TTL)),
            )
        return pid

    def approve(self, pid: str, force: bool = False, now: datetime | None = None) -> tuple[bool, str]:
        pid = pid.strip().upper()
        now = _utc(now or _now())
        with self._tx():
            row = self._conn.execute("SELECT * FROM pending WHERE id=?", (pid,)).fetchone()
            if row is None:
                return False, "unknown id"
            key = row["key"]
            if row["status"] == "approved" and self._conn.execute(
                "SELECT 1 FROM approvals WHERE key=?", (key,)
            ).fetchone():
                return True, key
            if datetime.fromisoformat(row["expires_at"]) <= now:
                return False, "expired"
            if row["status"] == "superseded":
                newest = self._conn.execute(
                    "SELECT id FROM pending WHERE key=? AND status!='superseded' ORDER BY rowid DESC LIMIT 1",
                    (key,),
                ).fetchone()
                return False, f"superseded: use {newest[0]}" if newest else "superseded"
            verdict = Verdict(json.loads(row["report"])["verdict"])
            cur = self._conn.execute("SELECT report FROM scans WHERE key=?", (key,)).fetchone()
            if cur:
                try:
                    cv = Verdict(json.loads(cur[0])["verdict"])
                    if _VERDICT_RANK[cv] > _VERDICT_RANK[verdict]:
                        verdict = cv  # worst of frozen pending verdict and current scan
                except (ValueError, KeyError, TypeError):
                    verdict = Verdict.MALICIOUS  # corrupt current scan: fail closed
            if verdict == Verdict.MALICIOUS and not force:
                return False, "malicious: use --force"
            self._conn.execute(
                "INSERT OR REPLACE INTO approvals(key, approved_at) VALUES (?,?)", (key, _iso(now))
            )
            self._conn.execute("DELETE FROM rejections WHERE key=?", (key,))
            self._conn.execute("UPDATE pending SET status='approved' WHERE id=?", (pid,))
            self._trust_scan_snapshot(key, now)
            self._conn.execute(
                "INSERT INTO audit(ts, event, fields) VALUES (?,?,?)",
                (_iso(now), "approve", json.dumps({"id": pid, "key": key, "force": force})),
            )
        return True, key

    def _trust_scan_snapshot(self, key: str, now: datetime) -> None:
        """Called inside approve's transaction: the approved key's scanned snapshot becomes trusted."""
        from bawwab.trust import trust_name

        row = self._conn.execute("SELECT report, snapshot FROM scans WHERE key=?", (key,)).fetchone()
        if not row or not row["snapshot"]:
            return
        try:
            name = trust_name(report_from_dict(json.loads(row["report"])).target)
            json.loads(row["snapshot"])
        except (ValueError, KeyError, TypeError):
            return
        self._conn.execute(
            "INSERT INTO snapshots(name, key, snap, ts) VALUES (?,?,?,?)", (name, key, row["snapshot"], _iso(now))
        )

    def reject(self, pid: str, now: datetime | None = None) -> tuple[bool, str]:
        pid = pid.strip().upper()
        now = _utc(now or _now())
        with self._tx():
            row = self._conn.execute("SELECT key FROM pending WHERE id=?", (pid,)).fetchone()
            if row is None:
                return False, "unknown id"
            key = row["key"]
            self._conn.execute(
                "INSERT OR REPLACE INTO rejections(key, rejected_at) VALUES (?,?)", (key, _iso(now))
            )
            self._conn.execute("DELETE FROM approvals WHERE key=?", (key,))  # reject revokes
            self._conn.execute("UPDATE pending SET status='rejected' WHERE key=?", (key,))
            self._conn.execute(
                "INSERT INTO audit(ts, event, fields) VALUES (?,?,?)",
                (_iso(now), "reject", json.dumps({"id": pid, "key": key})),
            )
        return True, key

    def is_approved(self, key: str) -> bool:
        return self._conn.execute("SELECT 1 FROM approvals WHERE key=?", (key,)).fetchone() is not None

    def is_rejected(self, key: str) -> bool:
        return self._conn.execute("SELECT 1 FROM rejections WHERE key=?", (key,)).fetchone() is not None

    # --- audit / warnings ---
    def audit(self, event: str, **fields) -> None:
        with self._tx():
            self._conn.execute(
                "INSERT INTO audit(ts, event, fields) VALUES (?,?,?)",
                (_iso(_now()), event, json.dumps(fields, default=str)),
            )

    def add_warning(self, text: str) -> None:
        with self._tx():
            self._conn.execute("INSERT INTO warnings(text, ts) VALUES (?,?)", (text, _iso(_now())))

    def take_warnings(self) -> list[str]:
        with self._tx():
            rows = self._conn.execute("SELECT id, text FROM warnings ORDER BY id").fetchall()
            if rows:
                self._conn.execute("DELETE FROM warnings WHERE id<=?", (rows[-1]["id"],))
        return [r["text"] for r in rows]

    # --- snapshots ---
    def put_snapshot(self, name: str, key: str, snap: dict) -> None:
        with self._tx():
            self._conn.execute(
                "INSERT INTO snapshots(name, key, snap, ts) VALUES (?,?,?,?)",
                (name, key, json.dumps(snap), _iso(_now())),
            )

    def latest_snapshot(self, name: str) -> tuple[str, dict] | None:
        row = self._conn.execute(
            "SELECT key, snap FROM snapshots WHERE name=? ORDER BY id DESC LIMIT 1", (name,)
        ).fetchone()
        return (row["key"], json.loads(row["snap"])) if row else None

    def all_snapshots(self) -> dict[str, dict]:
        rows = self._conn.execute(
            "SELECT name, snap FROM snapshots WHERE id IN (SELECT MAX(id) FROM snapshots GROUP BY name)"
        ).fetchall()
        return {r["name"]: json.loads(r["snap"]) for r in rows}


def _one(r: ScanReport, f: Finding) -> ScanReport:
    return ScanReport(r.key, r.target, r.resolved_version, r.mode, r.verdict, [f], r.scanned_at)


class _Tx:
    """Short IMMEDIATE transaction (takes the write lock up front; busy_timeout applies)."""

    def __init__(self, conn: sqlite3.Connection) -> None:
        self._c = conn

    def __enter__(self):
        self._c.execute("BEGIN IMMEDIATE")
        return self

    def __exit__(self, exc_type, exc, tb):
        self._c.execute("ROLLBACK" if exc_type else "COMMIT")
        return False


def open_store() -> Store:
    home = bawwab_home()
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(home, 0o700)
    db = home / "bawwab.db"
    if not db.exists():
        os.close(os.open(db, os.O_CREAT | os.O_WRONLY, 0o600))
    os.chmod(db, 0o600)
    return Store(db)
