"""Turn what the sandbox saw into findings.

Input is a `Observation`: the harness's JSON records (nonce-checked), the network trap's records, and the
run's canaries. Everything in it is attacker-influenced text, so every evidence string is sanitised and capped,
and nothing here can remove a finding: a run that could not be observed in full adds `sandbox.incomplete`.
"""
from __future__ import annotations

import json
import posixpath
from dataclasses import dataclass, field

from bawwab.report import sanitise
from bawwab.sandbox.canary import HOME, Matcher, decoy_paths, is_own_host
from bawwab.sandbox.strace import Event, dns_qname, parse_line
from bawwab.scan.rules.code import EXFIL_HOST_RE
from bawwab.types import Finding, Severity, ToolInfo

WORK = "/work"
EVIDENCE_CAP = 240
PER_RULE_CAP = 8

SHELLS = {"sh", "bash", "dash", "zsh", "ksh", "mksh", "ash", "fish", "csh", "tcsh", "busybox"}
# Phases in run order. "install" runs the package's own install steps; "start" is the server starting and
# answering initialize; "list" its tools/list; "call" one call of each tool with placeholder arguments.
PHASES = ("install", "start", "list", "call")
_PHASE_SEV = {"install": Severity.MED, "start": Severity.MED, "list": Severity.MED, "call": Severity.LOW}

_HIGH_HOME = (".bashrc", ".bash_profile", ".bash_login", ".bash_logout", ".profile", ".zshrc", ".zprofile",
              ".zshenv", ".ssh", ".config/autostart", ".config/systemd", ".local/bin", ".claude", ".claude.json",
              ".gitconfig", ".npmrc", ".pypirc", ".aws", ".config/gh", ".git-credentials", ".env",
              ".config/openai", ".mcp.json", ".cursor", ".codex", ".gemini", ".vscode")
_LOW_HOME = (".cache", ".npm", ".local/share", ".local/state", ".node_repl_history", ".python_history",
             ".config/configstore")
_SYSTEM = ("/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/opt", "/root", "/var/spool", "/boot", "/srv")
_IGNORE = ("/proc/", "/sys/", "/dev/null", "/dev/tty", "/dev/pts/", "/dev/stdout", "/dev/stderr", "/dev/fd/",
           "/dev/urandom", "/dev/random", "/dev/full", "/dev/zero")
# Decoy files whose name alone identifies them (for a relative path whose directory strace couldn't show)
_DISTINCT = ("id_ed25519", ".git-credentials", ".aws/credentials", ".config/gh/hosts.yml", ".config/openai/key",
             ".ssh/id_ed25519")


@dataclass
class Observation:
    records: list[dict]  # harness stdout, parsed JSON lines (any nonce)
    proxy: list[dict]  # network trap records
    canaries: dict[str, str]
    nonce: str
    proxy_ip: str | None = None
    timed_out: bool = False
    stray_lines: int = 0  # non-JSON lines on the harness channel
    exit_code: int | None = None
    notes: list[str] = field(default_factory=list)  # runner-side problems (e.g. proxy log unreadable)


def _ev(text: str) -> str:
    return sanitise(text, EVIDENCE_CAP)


class _Out:
    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.seen: set[tuple] = set()
        self.count: dict[str, int] = {}
        self.extra: dict[str, int] = {}

    def add(self, rule: str, sev: Severity, evidence: str, key: tuple | None = None) -> None:
        k = (rule, key if key is not None else evidence)
        if k in self.seen:
            return
        self.seen.add(k)
        n = self.count.get(rule, 0)
        if n >= PER_RULE_CAP:
            self.extra[rule] = self.extra.get(rule, 0) + 1
            hi = max((f.severity for f in self.findings if f.rule == rule), default=sev)
            if sev > hi:  # never let the cap hide a worse finding
                self.findings.append(Finding(rule, sev, "sandbox", _ev(evidence)))
            return
        self.count[rule] = n + 1
        self.findings.append(Finding(rule, sev, "sandbox", _ev(evidence)))

    def done(self) -> list[Finding]:
        for rule, n in sorted(self.extra.items()):
            sev = min(f.severity for f in self.findings if f.rule == rule)
            self.findings.append(Finding(rule, sev, "sandbox", f"[sandbox] and {n} more like this"))
        return self.findings


def _home_rel(p: str) -> str | None:
    if p == HOME:
        return ""
    return p[len(HOME) + 1:] if p.startswith(HOME + "/") else None


def write_severity(path: str, errno: str | None = None) -> Severity | None:
    """How bad a write to `path` is; None when it is inside the workdir or harmless."""
    p = posixpath.normpath(path)
    if p == WORK or p.startswith(WORK + "/") or p.startswith(_IGNORE) or p in ("/dev/null", "/dev/tty"):
        return None
    rel = _home_rel(p)
    if rel is not None:
        if any(rel == h or rel.startswith(h + "/") for h in _HIGH_HOME):
            return Severity.HIGH
        if any(rel == h or rel.startswith(h + "/") for h in _LOW_HOME):
            return Severity.LOW
        return Severity.MED
    if p == "/tmp" or p.startswith(("/tmp/", "/dev/shm/", "/var/tmp/")):
        return Severity.LOW
    if any(p == s or p.startswith(s + "/") for s in _SYSTEM):
        return Severity.HIGH
    return Severity.MED


def _is_decoy(ev: Event, decoys: set[str]) -> bool:
    if ev.resolved:
        return posixpath.normpath(ev.path or "") in decoys
    rel = posixpath.normpath(ev.path or "")
    return any(rel == d or rel.endswith("/" + d) for d in _DISTINCT)


def _proc(ev: Event, exe: dict[int, str]) -> str:
    return f" (process {exe[ev.pid]})" if ev.pid in exe else ""


def _phase_of(ts: object, marks: list[tuple[float, str]]) -> str | None:
    if not isinstance(ts, (int, float)):
        return None
    cur = None
    for t, ph in marks:
        if t <= ts:
            cur = ph
    return cur


def _loopback(host: str) -> bool:
    return host in ("::1", "0.0.0.0", "::", "localhost") or host.startswith("127.")


def _exfil(host: str) -> bool:
    return bool(host) and EXFIL_HOST_RE.search(host) is not None


def _host_of(rec: dict) -> str:
    h = str(rec.get("host") or rec.get("qname") or "")
    if not h and rec.get("kind") == "http":
        url = str(rec.get("url") or "")
        h = url.split("://", 1)[-1].split("/", 1)[0]
    return h.split(":")[0].strip("[]").lower()


def analyze(o: Observation) -> tuple[list[Finding], list[ToolInfo]]:
    out = _Out()
    m = Matcher(o.canaries)
    decoys = set(decoy_paths())
    good = [r for r in o.records if isinstance(r, dict) and r.get("n") == o.nonce]
    forged = len(o.records) - len(good) + o.stray_lines
    types = [r.get("t") for r in good]
    tools: list[ToolInfo] = []
    marks: list[tuple[float, str]] = []
    exe: dict[int, str] = {}
    phase_status: dict[str, str] = {}
    socks: dict[str, tuple[str | None, int | None]] = {}

    def incomplete(why: str, sev: Severity = Severity.MED) -> None:
        out.add("sandbox.incomplete", sev, f"[sandbox] {why}")

    if "hello" not in types:
        incomplete("the sandbox harness never reported in, so nothing was observed")
    if "done" not in types:
        incomplete("the sandbox run did not finish" + (" before the time limit" if o.timed_out else "")
                   + "; behaviour after that point was not observed")
    if forged:
        incomplete(f"{forged} unexpected line(s) on the sandbox's result channel (possible tampering)")
    for note in o.notes:
        incomplete(note)
    if not any(r.get("kind") == "ready" for r in o.proxy if isinstance(r, dict)):
        incomplete("the network trap did not start, so network attempts were not all logged")

    for r in good:
        t = r.get("t")
        if t == "hello" and not r.get("no_dump"):
            incomplete("the harness could not protect its own memory from the target")
        elif t == "phase":
            ph, st = str(r.get("phase")), str(r.get("status"))
            if st == "begin" and isinstance(r.get("ts"), (int, float)):
                marks.append((float(r["ts"]), ph))
                continue
            phase_status[ph] = st
            if st in ("failed", "timeout") and ph in ("setup", "install", "start"):
                what = {"setup": "sandbox setup", "install": "the install step", "start": "the server"}[ph]
                detail = sanitise(r.get("detail") or "", 120)
                verb = "timed out" if st == "timeout" else ("did not start" if ph == "start" else "failed")
                extra = " (the sandbox is offline, so dependencies that aren't bundled can't be installed)" \
                    if ph == "install" else ""
                incomplete(f"{what} {verb}{extra}" + (f": {detail}" if detail else ""))
            elif ph == "list" and st == "failed":
                incomplete("the server did not answer tools/list")
            elif ph == "call":
                called, listed = r.get("called"), r.get("listed")
                if isinstance(called, int) and isinstance(listed, int) and called < listed:
                    incomplete(f"only {called} of {listed} tools were called", Severity.LOW)
        elif t == "monitor":
            incomplete("the system-call monitor " + ("could not run" if r.get("status") == "unavailable"
                                                     else "stopped while the target was still running")
                       + f": {sanitise(r.get('detail') or '', 120)}")
        elif t == "limit":
            incomplete(f"the {sanitise(r.get('what'), 40)} log hit its size limit; later events were not seen")
        elif t == "tools":
            kind = r.get("kind")
            for it in r.get("items") or []:
                if not isinstance(it, dict) or not it.get("name"):
                    continue
                name = str(it["name"])[:200]
                if kind == "prompts":
                    name = f"prompt:{name}"
                elif kind == "resources":
                    name = f"resource:{name}"
                schema = it.get("inputSchema") if isinstance(it.get("inputSchema"), dict) else None
                tools.append(ToolInfo(name, str(it.get("description") or ""), schema))
        elif t == "call":
            for c in m.find(r.get("result")):
                out.add("sandbox.canary-leak", Severity.HIGH,
                        f"[sandbox call] tool {r.get('tool')} returned the decoy {c} credential "
                        "(the model would see it)", key=("result", c))
        elif t in ("stderr", "output"):
            for c in m.find(r.get("text")):
                out.add("sandbox.canary-leak", Severity.MED,
                        f"[sandbox {r.get('phase')}] printed the decoy {c} credential to its output",
                        key=("log", c))
        elif t == "fs":
            path = str(r.get("path") or "")
            for c in r.get("canaries") or []:
                if isinstance(c, str) and c in o.canaries:
                    out.add("sandbox.canary-leak", Severity.HIGH,
                            f"[sandbox] copied the decoy {c} credential into {path}", key=("file", c, path))
            sev = write_severity(path)
            if sev is not None:
                out.add("sandbox.write-outside", sev,
                        f"[sandbox] {r.get('op')} {path} outside the workdir", key=("w", path))

    # system calls, in order
    for r in good:
        if r.get("t") != "sys":
            continue
        ev = parse_line(str(r.get("line") or ""))
        if ev is None:
            continue
        phase = str(r.get("phase") or "")
        tag = f"[sandbox {phase}]" if phase else "[sandbox]"
        if ev.kind == "exec":
            exe[ev.pid] = posixpath.basename(ev.path or "")
            base = exe[ev.pid]
            if base in SHELLS:
                cmd = " ".join(ev.argv[:6])
                out.add("sandbox.shell-spawn", _PHASE_SEV.get(phase, Severity.MED),
                        f"{tag} started a shell: {cmd}", key=(phase, cmd[:120]))
        elif ev.kind == "open" and "O_DIRECTORY" not in ev.flags and _is_decoy(ev, decoys):
            out.add("sandbox.canary-read", Severity.HIGH,
                    f"{tag} read the decoy credential file {ev.path}{_proc(ev, exe)}", key=(ev.path,))
        elif ev.kind == "write":
            if _is_decoy(ev, decoys):
                out.add("sandbox.canary-read", Severity.HIGH,
                        f"{tag} opened the decoy credential file {ev.path} for writing{_proc(ev, exe)}",
                        key=(ev.path,))
            if ev.resolved and ev.path:
                sev = write_severity(ev.path, ev.errno)
                if sev is not None:
                    blocked = " (refused: read-only)" if ev.errno == "EROFS" else ""
                    out.add("sandbox.write-outside", sev,
                            f"{tag} {ev.syscall} {ev.path} outside the workdir{blocked}{_proc(ev, exe)}",
                            key=("w", posixpath.normpath(ev.path)))
        elif ev.kind in ("connect", "send"):
            host, port = ev.host, ev.port
            if ev.kind == "connect" and ev.sock:
                socks[ev.sock] = (host, port)
            elif host is None and ev.sock in socks:
                host, port = socks[ev.sock]
            if not host:
                continue
            dns = port == 53
            if ev.kind == "connect" and dns:
                continue  # the name being looked up comes with the send
            if _loopback(host) and not dns:
                continue
            qname = dns_qname(ev.data) if dns else None
            dest = qname or f"{host}:{port}"
            for c in m.find(ev.data) if ev.data else []:
                if qname and is_own_host(c, qname):
                    continue
                out.add("sandbox.canary-leak", Severity.CRITICAL,
                        f"{tag} sent the decoy {c} credential over the network to {dest}{_proc(ev, exe)}",
                        key=("net", c))
            if o.proxy_ip and host == o.proxy_ip and port == 3128:
                continue  # proxied: the trap's record has the detail
            if dns and not qname:
                continue
            sev = Severity.HIGH if _exfil(qname or "") else _PHASE_SEV.get(phase, Severity.MED)
            what = f"DNS lookup of {qname}" if qname else f"connection to {dest}"
            out.add("sandbox.network-attempt", sev, f"{tag} {what}{_proc(ev, exe)}",
                    key=("net", phase, (qname or host).lower()))

    # the network trap
    for r in o.proxy:
        if not isinstance(r, dict):
            continue
        kind = r.get("kind")
        if kind == "limit":
            incomplete("the network log hit its size limit; later attempts were not seen")
            continue
        if kind not in ("http", "connect", "dns", "raw"):
            continue
        phase = _phase_of(r.get("ts"), marks)
        tag = f"[sandbox {phase}]" if phase else "[sandbox]"
        host = _host_of(r)
        if kind == "http":
            what, blob = f"HTTP {r.get('method')} {r.get('url')}", json.dumps(
                [r.get("url"), r.get("headers"), r.get("body")])
        elif kind == "connect":
            what, blob = f"HTTPS connection to {host}:{r.get('port')}", json.dumps([r.get("host"), r.get("headers")])
        elif kind == "dns":
            what, blob = f"DNS lookup of {r.get('qname')}", str(r.get("qname") or "")
        else:
            what, blob = "unrecognised traffic to the network trap", str(r.get("data") or "")
        for c in m.find(blob):
            if is_own_host(c, host):
                continue  # a credential sent to its own service is ordinary use
            out.add("sandbox.canary-leak", Severity.CRITICAL,
                    f"{tag} sent the decoy {c} credential over the network ({what})", key=("net", c))
        sev = Severity.HIGH if _exfil(host) else _PHASE_SEV.get(phase or "", Severity.MED)
        out.add("sandbox.network-attempt", sev, f"{tag} {what}", key=("net", phase, host or what))

    return out.done(), tools[:200]
