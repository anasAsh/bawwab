"""Bawwab sandbox harness: runs as PID 1 inside the deep-mode container.

Reads its run spec (nonce, plan, decoy files, environment, budgets) from stdin, then:
  1. makes itself non-dumpable, so the target (same uid) can't read its memory or open its fds;
  2. writes the decoy home, copies the read-only target into the workdir, snapshots the writable trees;
  3. runs the install commands, then starts the server, each under `strace -f`;
  4. speaks MCP over the server's stdio: initialize, tools/prompts/resources list, call each tool once;
  5. diffs the writable trees and looks for canaries in files that changed.
Every record goes to stdout as one JSON line carrying the nonce. Only the host decides what a record means.

Stdlib only, Python 3.9+ (the image's Debian python3). Never imported by bawwab on the host.
"""
import ctypes
import json
import os
import queue
import re
import shutil
import signal
import subprocess
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # /opt/bawwab; `python3 -I` doesn't add it
from canary import Matcher  # noqa: E402  (copied next to this file in the image)

HOME = "/home/sandbox"
WORK = "/work"
PKG = "/work/pkg"
TARGET = "/target"
UID = os.getuid()
SESSIONS = set()  # session ids of the commands we started (outside a container, only these are swept)

MAX_SYS_LINES = 20000
MAX_LINE = 4096
MAX_OUT_BYTES = 16 * 1024 * 1024
MAX_TEXT = 8192
MAX_TOOLS = 64
MAX_FS_RECORDS = 500
MAX_SCAN_FILES = 5000
MAX_SCAN_BYTES = 1024 * 1024

STRACE = ["strace", "-f", "-qq", "-y", "-s", "1024", "-e", "signal=none", "-e", "trace=%file,%process,%network"]
_KEEP = re.compile(r"^\d+\s+(?:execve|execveat|connect|sendto|sendmsg|sendmmsg|mkdir|mkdirat|rename|renameat|"
                   r"renameat2|unlink|unlinkat|rmdir|symlink|symlinkat|link|linkat|truncate|chmod|fchmodat|"
                   r"fchmodat2|creat|open|openat|openat2)\(")
_OPEN = re.compile(r"^\d+\s+open(?:at2?)?\(")
# a path syscall that only touches the workdir (absolute /work/..., or relative to a /work dirfd, no "..")
_IN_WORK = re.compile(r'^\d+\s+(?:open|openat|openat2|creat|mkdir|mkdirat|unlink|unlinkat|rmdir|truncate|chmod|'
                      r'fchmodat|fchmodat2)\((?:(?:AT_FDCWD|\d+)<[^>]*>, )?"/work/(?![^"]*\.\.)[^"]*"'
                      r'|^\d+\s+(?:open|openat|openat2|mkdirat|unlinkat|fchmodat|fchmodat2)\((?:AT_FDCWD|\d+)'
                      r'</work(?:/[^>]*)?>, "(?!/)(?![^"]*\.\.)[^"]*"')


class Emitter:
    def __init__(self, nonce):
        self.nonce = nonce
        self.lock = threading.Lock()
        self.bytes = 0
        self.sys_lines = 0
        self.cut = set()

    def emit(self, t, **kw):
        kw["n"], kw["t"] = self.nonce, t
        line = json.dumps(kw, ensure_ascii=True) + "\n"
        with self.lock:
            if self.bytes + len(line) > MAX_OUT_BYTES and t not in ("done", "limit"):
                self._limit("output")
                return
            self.bytes += len(line)
            os.write(1, line.encode())

    def _limit(self, what):
        if what not in self.cut:
            self.cut.add(what)
            line = json.dumps({"n": self.nonce, "t": "limit", "what": what}) + "\n"
            os.write(1, line.encode())

    def sys(self, phase, line):
        if not _KEEP.match(line):
            return
        if _OPEN.match(line) and "/home/" not in line and not re.search(r"O_WRONLY|O_RDWR|O_CREAT|O_TRUNC|O_APPEND",
                                                                         line):
            if not re.search(r"id_ed25519|credentials|hosts\.yml|\.npmrc|\.claude\.json|openai|\.env\b", line):
                return  # a plain read outside the decoy home
        if _IN_WORK.match(line) and "/home/" not in line:
            return  # inside the workdir
        with self.lock:
            self.sys_lines += 1
            over = self.sys_lines > MAX_SYS_LINES
        if over:
            with self.lock:
                self._limit("sys-lines")
            return
        self.emit("sys", phase=phase, line=line[:MAX_LINE])


def _no_dump():
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        return libc.prctl(4, 0, 0, 0, 0) == 0  # PR_SET_DUMPABLE = 4
    except Exception:
        return False


def _tail(b, n=MAX_TEXT):
    return b[-n:].decode("utf-8", "replace") if isinstance(b, bytes) else str(b)[-n:]


class Traced:
    """One command under strace. Its trace lines go to the emitter as they arrive."""

    def __init__(self, em, phase, argv, env, cwd, stdio_pipes):
        self.em, self.phase = em, phase
        self.stopping = False
        r, w = os.pipe()
        kw = dict(env=env, cwd=cwd, start_new_session=True, pass_fds=(w,))
        if stdio_pipes:
            kw.update(stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        else:
            kw.update(stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        self.proc = subprocess.Popen(STRACE + ["-o", "/dev/fd/%d" % w, "--"] + argv, **kw)
        SESSIONS.add(self.proc.pid)
        os.close(w)
        self.reader = threading.Thread(target=self._read, args=(r,), daemon=True)
        self.reader.start()

    def _read(self, r):
        with os.fdopen(r, "rb", buffering=1024 * 64) as fh:
            for raw in fh:
                self.em.sys(self.phase, raw.decode("utf-8", "replace").rstrip("\n"))

    def stop(self):
        self.stopping = True
        try:
            os.killpg(self.proc.pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            self.proc.wait(5)
        except subprocess.TimeoutExpired:
            pass
        self.reader.join(5)


def _survivors():
    """Live processes of our uid other than the harness. As PID 1 in the container that is every one of them;
    anywhere else (the harness's own tests) only those in sessions the harness started."""
    out = []
    for d in os.listdir("/proc"):
        if not d.isdigit() or int(d) in (1, os.getpid()):
            continue
        try:
            with open("/proc/%s/stat" % d) as fh:
                st = fh.read()
            fields = st.rsplit(")", 1)[1].split()
            if fields[0] == "Z":
                continue
            if os.getpid() != 1 and int(fields[3]) not in SESSIONS:
                continue
            if os.stat("/proc/" + d).st_uid != UID:
                continue
        except (OSError, IndexError):
            continue
        out.append(int(d))
    return out


def _kill_all():
    for pid in _survivors():
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass


def run_phase(em, phase, argv, env, budget):
    em.emit("phase", phase=phase, status="begin", ts=time.time(), argv=argv[:20])
    t = Traced(em, phase, argv, env, PKG, stdio_pipes=False)
    buf = bytearray()

    def drain():
        while True:
            b = t.proc.stdout.read(4096)
            if not b:
                return
            buf.extend(b)
            if len(buf) > 2 * MAX_TEXT:
                del buf[:len(buf) - MAX_TEXT]

    reader = threading.Thread(target=drain, daemon=True)
    reader.start()
    try:
        t.proc.wait(timeout=budget)
        status = "ok" if t.proc.returncode == 0 else "failed"
    except subprocess.TimeoutExpired:
        status = "timeout"
    out = bytes(buf)
    lost = bool(_survivors()) and status != "timeout"
    t.stop()
    _kill_all()
    em.emit("output", phase=phase, text=_tail(out or b""))
    if lost:
        em.emit("monitor", status="lost", phase=phase, detail="processes outlived the tracer")
    em.emit("phase", phase=phase, status=status, ts=time.time(), code=t.proc.returncode)
    return status == "ok"


class Session:
    """A minimal MCP client over the server's stdio (newline-delimited JSON-RPC)."""

    def __init__(self, em, traced):
        self.em, self.t = em, traced
        self.q = queue.Queue()
        self.next_id = 1
        self.err = bytearray()
        threading.Thread(target=self._out, daemon=True).start()
        threading.Thread(target=self._errs, daemon=True).start()

    def _out(self):
        long_line = False
        while True:
            raw = self.t.proc.stdout.readline(4 * 1024 * 1024)
            if not raw:
                break
            if not raw.endswith(b"\n"):
                long_line = True  # over the cap: drop it and its continuation
                continue
            if long_line:
                long_line = False
                continue
            try:
                msg = json.loads(raw)
            except ValueError:
                continue
            if isinstance(msg, dict):
                self.q.put(msg)
        self.q.put(None)

    def _errs(self):
        while True:
            b = self.t.proc.stderr.read(4096)
            if not b:
                return
            if len(self.err) < 64 * 1024:
                self.err += b

    def send(self, obj):
        try:
            self.t.proc.stdin.write((json.dumps(obj) + "\n").encode())
            self.t.proc.stdin.flush()
            return True
        except (OSError, ValueError):
            return False

    def request(self, method, params, timeout):
        rid = self.next_id
        self.next_id += 1
        if not self.send({"jsonrpc": "2.0", "id": rid, "method": method, "params": params}):
            return None
        end = time.time() + timeout
        while time.time() < end:
            try:
                msg = self.q.get(timeout=max(0.05, end - time.time()))
            except queue.Empty:
                break
            if msg is None:
                return None
            if "method" in msg and "id" in msg:  # a request from the server: answer, never act on it
                if msg.get("method") == "ping":
                    self.send({"jsonrpc": "2.0", "id": msg["id"], "result": {}})
                else:
                    self.send({"jsonrpc": "2.0", "id": msg["id"],
                               "error": {"code": -32601, "message": "not supported"}})
                continue
            if msg.get("id") == rid:
                return msg
        return None


def _dummy(schema, depth=0):
    if not isinstance(schema, dict) or depth > 4:
        return "bawwab-test"
    if isinstance(schema.get("enum"), list) and schema["enum"]:
        return schema["enum"][0]
    t = schema.get("type")
    if isinstance(t, list):
        t = next((x for x in t if x != "null"), "string")
    if t in ("integer", "number"):
        return schema.get("minimum", 1)
    if t == "boolean":
        return False
    if t == "array":
        return []
    if t == "object":
        props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
        req = schema.get("required") if isinstance(schema.get("required"), list) else []
        return {k: _dummy(props.get(k), depth + 1) for k in req if isinstance(k, str)}
    fmt = str(schema.get("format", ""))
    return "http://example.com/bawwab-test" if fmt in ("uri", "url") else "bawwab-test"


def _args_for(tool):
    schema = tool.get("inputSchema") if isinstance(tool.get("inputSchema"), dict) else {}
    props = schema.get("properties") if isinstance(schema.get("properties"), dict) else {}
    req = schema.get("required") if isinstance(schema.get("required"), list) else []
    out = {}
    for k in req:
        if isinstance(k, str):
            v = _dummy(props.get(k))
            if v == "bawwab-test" and re.search(r"url|uri|link|endpoint", k, re.I):
                v = "http://example.com/bawwab-test"
            elif v == "bawwab-test" and re.search(r"path|file|dir", k, re.I):
                v = WORK + "/bawwab-test.txt"
            out[k] = v
    return out


def _listing(sess, method, key, timeout):
    items, cursor = [], None
    for _ in range(5):
        params = {"cursor": cursor} if cursor else {}
        r = sess.request(method, params, timeout)
        res = r.get("result") if isinstance(r, dict) else None
        if not isinstance(res, dict):
            return items, r is not None
        items += [x for x in (res.get(key) or []) if isinstance(x, dict)]
        cursor = res.get("nextCursor")
        if not isinstance(cursor, str) or not cursor:
            break
    return items, True


def run_server(em, plan, env, budgets):
    em.emit("phase", phase="start", status="begin", ts=time.time(), argv=plan["start"][:20])
    t = Traced(em, "start", plan["start"], env, PKG, stdio_pipes=True)
    sess = Session(em, t)
    init = sess.request("initialize", {"protocolVersion": "2025-06-18", "capabilities": {},
                                       "clientInfo": {"name": "bawwab-sandbox", "version": "1"}},
                        budgets["start_s"])
    ok = isinstance(init, dict) and isinstance(init.get("result"), dict)
    em.emit("phase", phase="start", status="ok" if ok else ("failed" if t.proc.poll() is not None else "timeout"),
            ts=time.time(), code=t.proc.poll())
    if ok:
        sess.send({"jsonrpc": "2.0", "method": "notifications/initialized"})
        caps = init["result"].get("capabilities") if isinstance(init["result"].get("capabilities"), dict) else {}
        t.phase = "list"
        em.emit("phase", phase="list", status="begin", ts=time.time())
        tools, listed = _listing(sess, "tools/list", "tools", budgets["call_s"])
        em.emit("tools", kind="tools", items=[_tool_rec(x) for x in tools[:200]])
        for method, key in (("prompts/list", "prompts"), ("resources/list", "resources")):
            if key in caps:
                items, _ = _listing(sess, method, key, budgets["call_s"])
                em.emit("tools", kind=key, items=[_tool_rec(x) for x in items[:200]])
        em.emit("phase", phase="list", status="ok" if listed else "failed", ts=time.time())
        t.phase = "call"
        em.emit("phase", phase="call", status="begin", ts=time.time())
        deadline = time.time() + budgets["calls_total_s"]
        called = 0
        for tool in tools[:MAX_TOOLS]:
            name = tool.get("name")
            if not isinstance(name, str) or time.time() > deadline or t.proc.poll() is not None:
                break
            r = sess.request("tools/call", {"name": name, "arguments": _args_for(tool)}, budgets["call_s"])
            called += 1
            em.emit("call", tool=name[:200], answered=r is not None,
                    result=json.dumps(r.get("result", r.get("error")))[:MAX_TEXT] if isinstance(r, dict) else "")
        em.emit("phase", phase="call", status="ok", ts=time.time(), called=called, listed=len(tools))
    lost = t.proc.poll() is not None and bool(_survivors())
    t.stop()
    _kill_all()
    em.emit("stderr", phase="start", text=_tail(bytes(sess.err)))
    if lost:
        em.emit("monitor", status="lost", phase="start", detail="processes outlived the tracer")


def _tool_rec(x):
    return {"name": str(x.get("name") or x.get("uri") or "")[:200],
            "description": str(x.get("description") or "")[:MAX_TEXT],
            "inputSchema": x.get("inputSchema") if isinstance(x.get("inputSchema"), dict) else None}


def snapshot(roots):
    snap = {}
    for root in roots:
        for d, dirs, files in os.walk(root):
            if d == PKG + "/node_modules" or d.startswith(PKG + "/node_modules/"):
                dirs[:] = []
            for n in files + [x for x in dirs if os.path.islink(os.path.join(d, x))]:
                p = os.path.join(d, n)
                try:
                    st = os.lstat(p)
                except OSError:
                    continue
                snap[p] = (st.st_size, st.st_mtime_ns, st.st_mode)
            if len(snap) > 200000:
                return snap
    return snap


def fs_diff(em, before, after, matcher):
    recs, scanned = 0, 0
    changed = [p for p in after if p not in before or after[p] != before[p]]
    removed = [p for p in before if p not in after]
    for p in sorted(changed):
        inside = p == WORK or p.startswith(WORK + "/")
        found = []
        if scanned < MAX_SCAN_FILES and os.path.isfile(p) and not os.path.islink(p):
            scanned += 1
            try:
                with open(p, "rb") as fh:
                    found = matcher.find(fh.read(MAX_SCAN_BYTES))
            except OSError:
                pass
        if (inside and not found) or recs >= MAX_FS_RECORDS:
            continue
        recs += 1
        em.emit("fs", op="added" if p not in before else "changed", path=p, canaries=found)
    for p in sorted(removed):
        if p.startswith(WORK + "/") or recs >= MAX_FS_RECORDS:
            continue
        recs += 1
        em.emit("fs", op="removed", path=p, canaries=[])
    if recs >= MAX_FS_RECORDS:
        em.emit("limit", what="fs")


def setup(spec):
    global HOME, WORK, PKG, TARGET
    paths = spec.get("paths")  # test-only override; the host runner never sends it
    if isinstance(paths, dict):
        HOME, WORK, TARGET = paths["home"], paths["work"], paths["target"]
        PKG = WORK + "/pkg"
    for rel, content in spec["decoys"].items():
        p = os.path.join(HOME, rel)
        os.makedirs(os.path.dirname(p), mode=0o700, exist_ok=True)
        with open(p, "w") as fh:
            fh.write(content)
        os.chmod(p, 0o600)
    shutil.copytree(TARGET, PKG, symlinks=True)
    for d in ("tmp", ".cache", ".npm"):
        os.makedirs(os.path.join(WORK, d), exist_ok=True)
    open(os.path.join(WORK, ".npmrc"), "w").close()


def main():
    raw = sys.stdin.buffer.read(4 * 1024 * 1024)
    dumpable_off = _no_dump()
    spec = json.loads(raw)
    sys.stdin.close()
    em = Emitter(spec["nonce"])
    em.emit("hello", v=1, no_dump=dumpable_off)
    budgets, plan = spec["budgets"], spec["plan"]
    end = time.time() + budgets["total_s"]
    try:
        setup(spec)
    except Exception as e:  # noqa: BLE001
        em.emit("phase", phase="setup", status="failed", ts=time.time(), detail="%s: %s" % (type(e).__name__, e))
        em.emit("done")
        return
    env = dict(spec["env"])
    if subprocess.call(["strace", "-f", "-qq", "-o", "/dev/null", "--", "/bin/true"],
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) != 0:
        em.emit("monitor", status="unavailable", phase="setup", detail="strace cannot trace in this container")
        em.emit("done")
        return
    matcher = Matcher(spec["canaries"])
    roots = (spec.get("paths") or {}).get("roots") or [HOME, "/tmp", "/dev/shm", WORK]
    before = snapshot(roots)
    installed = True
    for argv in plan["install"]:
        left = end - time.time()
        if left <= 5 or not run_phase(em, "install", argv, env, min(budgets["install_s"], left)):
            installed = False
            break
    if not installed:
        em.emit("phase", phase="start", status="skipped", ts=time.time(), detail="install failed")
    elif end - time.time() > 5:
        run_server(em, plan, env, budgets)
    after = snapshot(roots)
    fs_diff(em, before, after, matcher)
    em.emit("done")


if __name__ == "__main__":
    main()
