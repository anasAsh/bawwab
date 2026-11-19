import os
import stat
from datetime import datetime, timedelta, timezone

from bawwab.store import open_store, report_from_dict, report_to_dict, target_key
from bawwab.types import Finding, Mode, ScanReport, Severity, Target, Verdict

T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


def mk(key="npm:x@1#abc", verdict=Verdict.SUSPICIOUS, findings=None):
    t = Target(kind="npm", raw="x", name="x", version="1")
    f = findings if findings is not None else [Finding("r1", Severity.MED, "static", "ev", "a.py", 3)]
    return ScanReport(key, t, "1", Mode.STANDARD, verdict, f, T0)


def test_target_key():
    t = Target(kind="npm", raw="x", name="x")
    assert target_key(t, "1.0", "a" * 40) == "npm:x@1.0#" + "a" * 16
    t2 = Target(kind="remote", raw="u", url="https://h.invalid/x")
    assert target_key(t2, "", "h" * 20).startswith("remote:https://h.invalid/x@#")


def test_report_roundtrip():
    r = mk()
    r.findings[0].id = "FABCDEF"
    r.diff_summary = "d"
    assert report_from_dict(report_to_dict(r)) == r


def test_perms(tmp_path, monkeypatch):
    home = tmp_path / "h"
    monkeypatch.setenv("BAWWAB_HOME", str(home))
    open_store()
    assert stat.S_IMODE(os.stat(home).st_mode) == 0o700
    assert stat.S_IMODE(os.stat(home / "bawwab.db").st_mode) == 0o600


def test_put_and_get(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    s = open_store()
    assert s.get_cached("nope") is None
    r = mk()
    s.put_report(r)
    fid = r.findings[0].id
    assert fid.startswith("F") and len(fid) == 7
    got = s.get_cached(r.key)
    assert got == r
    f, key = s.get_finding(fid)
    assert f.rule == "r1" and key == r.key
    assert s.get_finding("Fzzzzzz") is None
    r2 = mk()
    s.put_report(r2)
    assert r2.findings[0].id == fid  # stable


def test_approve_flow(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    s = open_store()
    r = mk("K")
    pid = s.create_pending(r, now=T0)
    assert len(pid) == 4 and set(pid) <= set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567")
    assert not s.is_approved("K")
    assert s.approve(pid.lower(), now=T0 + timedelta(minutes=5)) == (True, "K")
    assert s.is_approved("K") and not s.is_approved("K2")
    assert s.approve(pid, now=T0 + timedelta(minutes=5)) == (True, "K")


def test_expired(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    s = open_store()
    pid = s.create_pending(mk("K"), now=T0)
    assert s.approve(pid, now=T0 + timedelta(minutes=61)) == (False, "expired")
    assert not s.is_approved("K")


def test_unknown(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    s = open_store()
    assert s.approve("ZZZZ") == (False, "unknown id")
    assert s.reject("ZZZZ") == (False, "unknown id")


def test_malicious_needs_force(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    s = open_store()
    pid = s.create_pending(mk("K", Verdict.MALICIOUS), now=T0)
    assert s.approve(pid, now=T0) == (False, "malicious: use --force")
    assert not s.is_approved("K")
    assert s.approve(pid, force=True, now=T0) == (True, "K")
    assert s.is_approved("K")


def test_reject_and_change_mind(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    s = open_store()
    p1 = s.create_pending(mk("K"), now=T0)
    assert s.reject(p1) == (True, "K")
    assert s.is_rejected("K") and not s.is_approved("K")
    p2 = s.create_pending(mk("K"), now=T0)
    assert s.approve(p2, now=T0) == (True, "K")
    assert s.is_approved("K") and not s.is_rejected("K")
    s.reject(p2)
    assert not s.is_approved("K")


def test_pending_id_collision(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    import bawwab.store as st

    seq = iter(["AAAA", "AAAA", "BBBB"])
    monkeypatch.setattr(st, "_gen_id", lambda: next(seq))
    s = open_store()
    a = s.create_pending(mk("K1"), now=T0)
    b = s.create_pending(mk("K2"), now=T0)
    assert (a, b) == ("AAAA", "BBBB")
    assert s.approve("AAAA", now=T0) == (True, "K1")


def test_warnings(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    s = open_store()
    s.add_warning("one")
    s.add_warning("two")
    assert s.take_warnings() == ["one", "two"]
    assert s.take_warnings() == []


def test_snapshots(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    s = open_store()
    assert s.latest_snapshot("a") is None
    s.put_snapshot("a", "k1", {"x": 1})
    s.put_snapshot("a", "k2", {"x": 2})
    s.put_snapshot("b", "k3", {"y": 1})
    assert s.latest_snapshot("a") == ("k2", {"x": 2})
    assert s.all_snapshots() == {"a": {"x": 2}, "b": {"y": 1}}


def test_audit(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    s = open_store()
    s.audit("ev", a=1)
    assert s._conn.execute("select event, fields from audit").fetchone()[0] == "ev"


def test_reopen_persists_and_two_connections(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    s1, s2 = open_store(), open_store()
    pid = s1.create_pending(mk("K"), now=T0)
    assert s2.approve(pid, now=T0) == (True, "K")
    assert s1.is_approved("K")


def test_stale_pending_cannot_bypass_malicious(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    s = open_store()
    p1 = s.create_pending(mk("K", Verdict.SUSPICIOUS), now=T0)
    s.put_report(mk("K", Verdict.MALICIOUS))  # deep rescan, same key
    assert s.approve(p1, now=T0) == (False, "malicious: use --force")
    assert not s.is_approved("K")
    assert s.approve(p1, force=True, now=T0) == (True, "K")


def test_superseded_pending(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    s = open_store()
    p1 = s.create_pending(mk("K"), now=T0)
    p2 = s.create_pending(mk("K"), now=T0 + timedelta(minutes=1))
    assert s.approve(p1, now=T0) == (False, f"superseded: use {p2}")
    assert not s.is_approved("K")
    assert s.approve(p2, now=T0) == (True, "K")


def test_same_rule_no_file_distinct_ids(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    s = open_store()
    r = mk("K", findings=[Finding("j", Severity.MED, "judge", "one"), Finding("j", Severity.MED, "judge", "two")])
    s.put_report(r)
    a, b = r.findings
    assert a.id != b.id
    assert s.get_finding(a.id)[0].evidence == "one"
    assert s.get_finding(b.id)[0].evidence == "two"


def test_forced_hash_collision_across_keys(tmp_path, monkeypatch):
    import bawwab.store as st

    monkeypatch.setattr(st, "_hash", lambda m: "a" * 64)
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    s = open_store()
    r1 = mk("K1", findings=[Finding("r", Severity.MED, "static", "e1")])
    r2 = mk("K2", findings=[Finding("r", Severity.MED, "static", "e2")])
    s.put_report(r1)
    s.put_report(r2)
    i1, i2 = r1.findings[0].id, r2.findings[0].id
    assert i1 != i2
    assert s.get_finding(i1)[0].evidence == "e1" and s.get_finding(i1)[1] == "K1"
    assert s.get_finding(i2)[0].evidence == "e2" and s.get_finding(i2)[1] == "K2"
    s.put_report(r1)  # identical re-insert keeps the same id
    assert r1.findings[0].id == i1


def test_corrupt_rows_return_none(tmp_path, monkeypatch):
    monkeypatch.setenv("BAWWAB_HOME", str(tmp_path))
    s = open_store()
    r = mk("K")
    s.put_report(r)
    fid = r.findings[0].id
    s._conn.execute("UPDATE scans SET report='{bad'")
    s._conn.execute("UPDATE findings SET finding='{\"x\":1}'")
    assert s.get_cached("K") is None
    assert s.get_finding(fid) is None
    n = s._conn.execute("select count(*) from audit where event='store.corrupt'").fetchone()[0]
    assert n == 2
