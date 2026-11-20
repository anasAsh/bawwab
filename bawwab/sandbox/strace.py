"""Parse the strace lines the sandbox harness forwards (`strace -f -qq -y -s 1024`).

Every line is untrusted: the traced program chooses the paths, argv and payloads in it, and it can even write
lines of its own into the trace pipe. The parser only ever *adds* events, so a forged line can make a target
look worse, never better. Unparseable lines are dropped.
"""
from __future__ import annotations

import posixpath
import re
from dataclasses import dataclass, field

_LINE = re.compile(r"^(?:\[pid\s+)?(?P<pid>\d+)\]?\s+(?P<sc>[a-z_0-9]+)\((?P<rest>.*)$", re.S)
_RESULT = re.compile(r"\)\s+=\s+(?P<ret>-?\d+|\?)(?:<[^>]*>)?(?:\s+(?P<errno>E[A-Z0-9]+))?")
_FD_DECOR = re.compile(r"^(?:AT_FDCWD|-?\d+)<(?P<p>.*)>$", re.S)

_WRITE_FLAGS = ("O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND")

# syscall -> indexes of (dirfd, path) argument pairs it modifies; dirfd None means "relative to cwd"
_PATH_MODS: dict[str, tuple[tuple[int | None, int], ...]] = {
    "mkdir": ((None, 0),), "mkdirat": ((0, 1),),
    "rename": ((None, 0), (None, 1)), "renameat": ((0, 1), (2, 3)), "renameat2": ((0, 1), (2, 3)),
    "unlink": ((None, 0),), "unlinkat": ((0, 1),), "rmdir": ((None, 0),),
    "symlink": ((None, 1),), "symlinkat": ((1, 2),),
    "link": ((None, 1),), "linkat": ((2, 3),),
    "truncate": ((None, 0),), "chmod": ((None, 0),), "fchmodat": ((0, 1),), "fchmodat2": ((0, 1),),
    "creat": ((None, 0),),
}
_OPENS = {"open": (None, 0, 1), "openat": (0, 1, 2), "openat2": (0, 1, 2)}
_EXECS = {"execve": (None, 0, 1), "execveat": (0, 1, 2)}
_SENDS = {"sendto", "sendmsg", "sendmmsg"}


@dataclass
class Event:
    kind: str  # open | write | exec | connect | send
    pid: int
    syscall: str
    path: str | None = None  # absolute when it could be resolved, else as given
    resolved: bool = True
    flags: str = ""
    argv: list[str] = field(default_factory=list)
    host: str | None = None
    port: int | None = None
    family: str | None = None
    data: bytes = b""
    errno: str | None = None
    sock: str | None = None  # socket inode from the -y fd decoration, to match a send to its connect


def unescape(s: str) -> bytes:
    """Decode a strace C-style string body (without the quotes) to bytes."""
    out = bytearray()
    i, n = 0, len(s)
    simple = {"n": 10, "t": 9, "r": 13, "v": 11, "f": 12, "a": 7, "b": 8, '"': 34, "\\": 92, "'": 39, "?": 63}
    while i < n:
        c = s[i]
        if c != "\\" or i + 1 >= n:
            out += c.encode("utf-8", "surrogateescape")
            i += 1
            continue
        d = s[i + 1]
        if d == "x" and re.match(r"[0-9a-fA-F]{2}", s[i + 2:i + 4]):
            out.append(int(s[i + 2:i + 4], 16))
            i += 4
        elif d in "01234567":
            m = re.match(r"[0-7]{1,3}", s[i + 1:i + 4])
            out.append(int(m.group(0), 8) & 0xFF)
            i += 1 + len(m.group(0))
        else:
            out.append(simple.get(d, ord(d) & 0xFF))
            i += 2
    return bytes(out)


def split_args(rest: str) -> list[str]:
    """Split the top-level, comma-separated arguments of a syscall, up to its closing parenthesis."""
    args, cur, depth, i, n = [], [], 0, 0, len(rest)
    while i < n:
        c = rest[i]
        if c == '"':
            j = i + 1
            while j < n and rest[j] != '"':
                j += 2 if rest[j] == "\\" else 1
            cur.append(rest[i:j + 1])
            i = j + 1
            continue
        if c == "<" and cur and re.search(r"(?:\d|AT_FDCWD)$", "".join(cur)):  # fd decoration: 3</path>
            j = rest.find(">", i)
            if j < 0:
                j = n - 1
            cur.append(rest[i:j + 1])
            i = j + 1
            continue
        if c in "[{(":
            depth += 1
        elif c in "]})":
            if depth == 0:
                break
            depth -= 1
        elif c == "," and depth == 0:
            args.append("".join(cur).strip())
            cur = []
            i += 1
            continue
        cur.append(c)
        i += 1
    tail = "".join(cur).strip()
    if tail:
        args.append(tail)
    return args


def _str(arg: str) -> str | None:
    m = re.match(r'^"((?:[^"\\]|\\.)*)"(?:\.\.\.)?', arg, re.S)
    if not m:
        return None
    return unescape(m.group(1)).decode("utf-8", "replace")


def _dir(arg: str | None) -> str | None:
    if arg is None:
        return None
    m = _FD_DECOR.match(arg.strip())
    return m.group("p") if m else None


def _resolve(dirarg: str | None, path: str) -> tuple[str, bool]:
    if path.startswith("/"):
        return posixpath.normpath(path), True
    base = _dir(dirarg)
    if base and base.startswith("/"):
        return posixpath.normpath(posixpath.join(base, path)), True
    return path, False


def _sock(arg: str | None) -> str | None:
    m = re.match(r"^\d+<(?:socket|UDP|TCP|UDPv6|TCPv6):\[([^\]]*)\]>", (arg or "").strip())
    return m.group(1) if m else None


def _addr(text: str) -> tuple[str | None, str | None, int | None]:
    fam = re.search(r"sa_family=(AF_[A-Z0-9]+)", text)
    port = re.search(r"sin6?_port=htons\((\d+)\)", text)
    host = re.search(r'sin_addr=inet_addr\("([^"]*)"\)', text) or re.search(r'inet_pton\(AF_INET6,\s*"([^"]*)"', text)
    return (fam.group(1) if fam else None, host.group(1) if host else None, int(port.group(1)) if port else None)


def parse_line(line: str) -> Event | None:
    m = _LINE.match(line.rstrip("\n"))
    if not m or "resumed>" in line[:80]:
        return None
    pid, sc, rest = int(m.group("pid")), m.group("sc"), m.group("rest")
    r = _RESULT.search(rest[-200:]) if rest else None
    errno = r.group("errno") if r else None
    args = split_args(rest)
    try:
        if sc in _OPENS:
            di, pi, fi = _OPENS[sc]
            p = _str(args[pi]) if len(args) > pi else None
            if p is None:
                return None
            path, ok = _resolve(args[di] if di is not None else None, p)
            flags = args[fi] if len(args) > fi else ""
            if any(w in flags for w in _WRITE_FLAGS):
                return Event("write", pid, sc, path, ok, flags=flags, errno=errno)
            return Event("open", pid, sc, path, ok, flags=flags, errno=errno)
        if sc in _PATH_MODS:
            for di, pi in _PATH_MODS[sc]:
                p = _str(args[pi]) if len(args) > pi else None
                if p is not None:
                    path, ok = _resolve(args[di] if di is not None else None, p)
                    return Event("write", pid, sc, path, ok, errno=errno)
            return None
        if sc in _EXECS:
            di, pi, ai = _EXECS[sc]
            p = _str(args[pi]) if len(args) > pi else None
            if p is None:
                return None
            argv = re.findall(r'"((?:[^"\\]|\\.)*)"', args[ai]) if len(args) > ai else []
            path, ok = _resolve(args[di] if di is not None else None, p)
            return Event("exec", pid, sc, path, ok, argv=[unescape(a).decode("utf-8", "replace") for a in argv],
                         errno=errno)
        if sc == "connect":
            fam, host, port = _addr(rest)
            if fam in ("AF_INET", "AF_INET6"):
                return Event("connect", pid, sc, family=fam, host=host, port=port, errno=errno,
                             sock=_sock(args[0] if args else None))
            return None
        if sc in _SENDS:
            fam, host, port = _addr(rest)
            if sc == "sendto":
                m2 = re.match(r'^"((?:[^"\\]|\\.)*)"', args[1]) if len(args) > 1 else None
                data = unescape(m2.group(1)) if m2 else b""
            else:
                data = b"".join(unescape(s) for s in re.findall(r'iov_base="((?:[^"\\]|\\.)*)"', rest))
            return Event("send", pid, sc, family=fam, host=host, port=port, data=data, errno=errno,
                         sock=_sock(args[0] if args else None))
    except (IndexError, ValueError):
        return None
    return None


def dns_qname(data: bytes) -> str | None:
    """The question name of a DNS query packet, or None."""
    if len(data) < 17:
        return None
    i, labels = 12, []
    while i < len(data) and len(labels) < 64:
        n = data[i]
        if n == 0:
            return ".".join(labels) if labels else None
        if n & 0xC0:
            return None
        labels.append(data[i + 1:i + 1 + n].decode("ascii", "replace"))
        i += 1 + n
    return None
