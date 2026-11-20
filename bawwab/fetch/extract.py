from __future__ import annotations

import stat
import tarfile
import zipfile
from pathlib import Path, PurePosixPath

from bawwab.fetch.common import unsafe
from bawwab.types import Finding

MAX_TOTAL_BYTES = 500 * 1024 * 1024
MAX_MEMBERS = 20_000


def _bad_name(name: str) -> str | None:
    if not name or "\0" in name:
        return "empty or NUL-containing name"
    n = name.replace("\\", "/")
    if n.startswith("/") or (len(n) > 1 and n[1] == ":"):
        return "absolute path"
    if ".." in PurePosixPath(n).parts:
        return "path traversal"
    return None


def extract_archive(file: Path, dest: Path, password: bytes | None = None) -> list[Finding]:
    """Extract file into dest without ever writing outside it. Unsafe members are skipped.

    password decrypts a ZipCrypto-encrypted zip (the benchmark's malware samples); tar ignores it.
    """
    findings: list[Finding] = []
    try:
        if zipfile.is_zipfile(file):
            _extract_zip(file, dest, findings, password)
        elif tarfile.is_tarfile(file):
            _extract_tar(file, dest, findings)
        else:
            findings.append(unsafe("downloaded file is not a recognised tar or zip archive"))
    except Exception as e:  # corrupt/hostile archive must never crash the caller
        findings.append(unsafe(f"archive could not be fully extracted: {type(e).__name__}: {e}"))
    return findings


def _extract_tar(file: Path, dest: Path, findings: list[Finding]) -> None:
    total = 0
    count = 0
    with tarfile.open(file) as tf:
        for member in tf:
            count += 1
            if count > MAX_MEMBERS:
                findings.append(unsafe(f"archive has more than {MAX_MEMBERS} members; extraction stopped"))
                return
            bad = _bad_name(member.name)
            if bad:
                findings.append(unsafe(f"{bad}: {member.name}", file=member.name))
                continue
            if member.isfile():
                if total + member.size > MAX_TOTAL_BYTES:
                    findings.append(unsafe(f"extracted size exceeds {MAX_TOTAL_BYTES} bytes; extraction stopped"))
                    return
                total += member.size
            try:
                tf.extract(member, dest, filter="data")
            except tarfile.FilterError as e:
                findings.append(unsafe(f"{type(e).__name__}: {member.name}: {e}", file=member.name))
            except (OSError, tarfile.TarError) as e:
                findings.append(unsafe(f"could not extract {member.name}: {type(e).__name__}: {e}", file=member.name))


def _extract_zip(file: Path, dest: Path, findings: list[Finding], password: bytes | None = None) -> None:
    real_dest = dest.resolve()
    total = 0
    with zipfile.ZipFile(file) as zf:
        if password:
            zf.setpassword(password)
        infos = zf.infolist()
        if len(infos) > MAX_MEMBERS:
            findings.append(unsafe(f"archive has more than {MAX_MEMBERS} members; extraction stopped"))
            infos = infos[:MAX_MEMBERS]
        for zi in infos:
            bad = _bad_name(zi.filename)
            if bad:
                findings.append(unsafe(f"{bad}: {zi.filename}", file=zi.filename))
                continue
            mode = zi.external_attr >> 16
            if stat.S_ISLNK(mode):
                findings.append(unsafe(f"symlink entry skipped: {zi.filename}", file=zi.filename))
                continue
            target = (dest / zi.filename).resolve()
            if target != real_dest and real_dest not in target.parents:
                findings.append(unsafe(f"entry resolves outside destination: {zi.filename}", file=zi.filename))
                continue
            try:
                if zi.is_dir():
                    target.mkdir(parents=True, exist_ok=True)
                    continue
                if total + zi.file_size > MAX_TOTAL_BYTES:
                    findings.append(unsafe(f"extracted size exceeds {MAX_TOTAL_BYTES} bytes; extraction stopped"))
                    return
                target.parent.mkdir(parents=True, exist_ok=True)
                written = 0
                with zf.open(zi) as src, open(target, "wb") as out:
                    while chunk := src.read(65536):
                        written += len(chunk)
                        if total + written > MAX_TOTAL_BYTES:
                            break
                        out.write(chunk)
                if total + written > MAX_TOTAL_BYTES:
                    target.unlink(missing_ok=True)
                    findings.append(unsafe(f"extracted size exceeds {MAX_TOTAL_BYTES} bytes; extraction stopped"))
                    return
                total += written
            except (OSError, zipfile.BadZipFile, RuntimeError, EOFError) as e:
                findings.append(unsafe(f"could not extract {zi.filename}: {type(e).__name__}: {e}", file=zi.filename))
