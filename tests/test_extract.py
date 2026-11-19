import io
import tarfile
import zipfile
from pathlib import Path

from bawwab.fetch import extract as ex
from bawwab.fetch.extract import extract_archive
from bawwab.types import Severity


def _all_files(root: Path):
    return [p for p in root.rglob("*")]


def _tar(path: Path, entries):
    with tarfile.open(path, "w:gz") as tf:
        for name, kind, data in entries:
            ti = tarfile.TarInfo(name)
            if kind == "file":
                ti.size = len(data)
                tf.addfile(ti, io.BytesIO(data))
            elif kind == "sym":
                ti.type = tarfile.SYMTYPE
                ti.linkname = data
                tf.addfile(ti)
            elif kind == "hard":
                ti.type = tarfile.LNKTYPE
                ti.linkname = data
                tf.addfile(ti)


def test_hostile_tar(tmp_path):
    arc = tmp_path / "a.tgz"
    _tar(
        arc,
        [
            ("package/ok.txt", "file", b"ok"),
            ("../evil", "file", b"x"),
            ("/abs-evil", "file", b"x"),
            ("package/sym", "sym", "../../outside"),
            ("package/hard", "hard", "../../etc/passwd"),
        ],
    )
    dest = tmp_path / "out" / "dest"
    dest.mkdir(parents=True)
    findings = extract_archive(arc, dest)
    assert (dest / "package" / "ok.txt").read_bytes() == b"ok"
    assert not (tmp_path / "out" / "evil").exists()
    assert not (dest / "abs-evil").exists() and not Path("/abs-evil").exists()
    assert not (dest / "package" / "sym").exists() and not (dest / "package" / "sym").is_symlink()
    assert not (dest / "package" / "hard").exists()
    unsafe = [f for f in findings if f.rule == "fetch.unsafe-entry"]
    assert len(unsafe) >= 4 and all(f.severity == Severity.HIGH for f in unsafe)
    for p in tmp_path.rglob("*"):
        if p.is_symlink():
            raise AssertionError(p)


def test_hostile_zip(tmp_path):
    arc = tmp_path / "a.zip"
    with zipfile.ZipFile(arc, "w") as zf:
        zf.writestr("pkg/ok.txt", "ok")
        zf.writestr("../evil", "x")
        zf.writestr("/abs-evil", "x")
        zf.writestr("a/../../evil2", "x")
        zi = zipfile.ZipInfo("pkg/link")
        zi.create_system = 3
        zi.external_attr = (0o120777) << 16
        zf.writestr(zi, "../../outside")
    dest = tmp_path / "out" / "dest"
    dest.mkdir(parents=True)
    findings = extract_archive(arc, dest)
    assert (dest / "pkg" / "ok.txt").read_text() == "ok"
    assert not (tmp_path / "out" / "evil").exists()
    assert not (tmp_path / "evil2").exists() and not (tmp_path / "out" / "evil2").exists()
    assert not (dest / "pkg" / "link").exists() and not (dest / "pkg" / "link").is_symlink()
    unsafe = [f for f in findings if f.rule == "fetch.unsafe-entry"]
    assert len(unsafe) >= 4 and all(f.severity == Severity.HIGH for f in unsafe)


def test_member_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(ex, "MAX_MEMBERS", 3)
    arc = tmp_path / "a.zip"
    with zipfile.ZipFile(arc, "w") as zf:
        for i in range(10):
            zf.writestr(f"f{i}", "x")
    dest = tmp_path / "d"
    dest.mkdir()
    findings = extract_archive(arc, dest)
    assert any(f.rule == "fetch.unsafe-entry" and f.severity == Severity.HIGH for f in findings)
    assert len(list(dest.iterdir())) <= 3


def test_size_cap_tar_and_zip(tmp_path, monkeypatch):
    monkeypatch.setattr(ex, "MAX_TOTAL_BYTES", 100)
    t = tmp_path / "a.tgz"
    _tar(t, [("a", "file", b"x" * 80), ("b", "file", b"x" * 80)])
    d1 = tmp_path / "d1"
    d1.mkdir()
    f1 = extract_archive(t, d1)
    assert any(f.rule == "fetch.unsafe-entry" for f in f1)
    assert sum(p.stat().st_size for p in d1.rglob("*") if p.is_file()) <= 100
    z = tmp_path / "a.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("a", "x" * 80)
        zf.writestr("b", "x" * 80)
    d2 = tmp_path / "d2"
    d2.mkdir()
    f2 = extract_archive(z, d2)
    assert any(f.rule == "fetch.unsafe-entry" for f in f2)
    assert sum(p.stat().st_size for p in d2.rglob("*") if p.is_file()) <= 100


def test_not_an_archive(tmp_path):
    bad = tmp_path / "x.bin"
    bad.write_bytes(b"not an archive")
    d = tmp_path / "d"
    d.mkdir()
    findings = extract_archive(bad, d)
    assert any(f.rule == "fetch.unsafe-entry" for f in findings)


def test_zip_member_oserror_does_not_abort(tmp_path):
    arc = tmp_path / "a.zip"
    with zipfile.ZipFile(arc, "w") as zf:
        zf.writestr("a", "file")
        zf.writestr("a/b", "collides with file a")
        zf.writestr("z.txt", "still extracted")
    dest = tmp_path / "d"
    dest.mkdir()
    findings = extract_archive(arc, dest)
    assert (dest / "z.txt").read_text() == "still extracted"
    assert any(f.rule == "fetch.unsafe-entry" and f.file == "a/b" for f in findings)


def test_zip_bomb_compressible_over_cap(tmp_path, monkeypatch):
    monkeypatch.setattr(ex, "MAX_TOTAL_BYTES", 1024 * 1024)
    arc = tmp_path / "bomb.zip"
    with zipfile.ZipFile(arc, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("big", b"\0" * (5 * 1024 * 1024))
    dest = tmp_path / "d"
    dest.mkdir()
    findings = extract_archive(arc, dest)
    assert any(f.rule == "fetch.unsafe-entry" and "exceeds" in f.evidence for f in findings)
    assert sum(p.stat().st_size for p in dest.rglob("*") if p.is_file()) <= 1024 * 1024
