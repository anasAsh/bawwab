"""Bawwab sandbox network trap: the only host on the sandbox's internal Docker network.

Listens as an HTTP(S) proxy on :3128 and as a DNS server on :53 (UDP). It logs every attempt as one JSON
line on stdout (read back by the host with `docker logs`) and refuses all of them: HTTP gets 403, CONNECT gets
403 (so TLS never starts), DNS gets REFUSED. It forwards nothing; its container has no route out anyway.

Runs in its own container, so the target cannot tamper with this log. Stdlib only, Python 3.9+.
"""
import json
import socket
import socketserver
import sys
import threading
import time

MAX_RECORDS = 2000
MAX_BYTES = 8 * 1024 * 1024
HEAD_MAX = 64 * 1024
BODY_MAX = 16 * 1024

_lock = threading.Lock()
_state = {"n": 0, "bytes": 0, "cut": False}


def log(rec):
    rec["ts"] = time.time()
    line = json.dumps(rec, ensure_ascii=True) + "\n"
    with _lock:
        if _state["cut"]:
            return
        if _state["n"] >= MAX_RECORDS or _state["bytes"] + len(line) > MAX_BYTES:
            _state["cut"] = True
            line = json.dumps({"kind": "limit", "ts": time.time()}) + "\n"
        _state["n"] += 1
        _state["bytes"] += len(line)
        sys.stdout.write(line)
        sys.stdout.flush()


def _text(b):
    return b.decode("latin-1")


class Http(socketserver.BaseRequestHandler):
    def handle(self):
        s = self.request
        s.settimeout(5)
        buf = b""
        try:
            while b"\r\n\r\n" not in buf and len(buf) < HEAD_MAX:
                chunk = s.recv(4096)
                if not chunk:
                    break
                buf += chunk
        except OSError:
            pass
        head, _, body = buf.partition(b"\r\n\r\n")
        lines = head.split(b"\r\n")
        parts = lines[0].split(b" ") if lines and lines[0] else []
        if len(parts) < 2:
            log({"kind": "raw", "peer": self.client_address[0], "data": _text(buf[:4096])})
            return self._refuse()
        method, url = _text(parts[0])[:16], _text(parts[1])[:4096]
        headers = []
        for ln in lines[1:100]:
            k, _, v = ln.partition(b":")
            headers.append([_text(k.strip())[:200], _text(v.strip())[:4096]])
        if method.upper() == "CONNECT":
            host, _, port = url.rpartition(":")
            log({"kind": "connect", "host": host or url, "port": port, "headers": headers})
            return self._refuse()
        want = 0
        for k, v in headers:
            if k.lower() == "content-length" and v.isdigit():
                want = min(int(v), BODY_MAX)
        try:
            s.settimeout(2)
            while len(body) < want:
                chunk = s.recv(4096)
                if not chunk:
                    break
                body += chunk
        except OSError:
            pass
        host = next((v for k, v in headers if k.lower() == "host"), "")
        log({"kind": "http", "method": method, "url": url, "host": host, "headers": headers,
             "body": _text(body[:BODY_MAX])})
        self._refuse()

    def _refuse(self):
        try:
            self.request.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/plain\r\nContent-Length: 34\r\n"
                                 b"Connection: close\r\n\r\nbawwab sandbox: network refused.\n")
        except OSError:
            pass


def _qname(data):
    i, labels = 12, []
    while i < len(data) and len(labels) < 64:
        n = data[i]
        if n == 0:
            qtype = int.from_bytes(data[i + 1:i + 3], "big") if len(data) >= i + 3 else 0
            return ".".join(labels), qtype, i + 5
        if n & 0xC0:
            break
        labels.append(data[i + 1:i + 1 + n].decode("latin-1"))
        i += 1 + n
    return ".".join(labels), 0, None


class Dns(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        if len(data) < 12:
            return
        name, qtype, end = _qname(data)
        log({"kind": "dns", "qname": name[:1024], "qtype": qtype})
        flags = 0x8000 | (data[2] & 0x01) << 8 | 0x0005  # QR, keep RD, RCODE=REFUSED
        question = data[12:end] if end else b""
        qd = b"\x00\x01" if end else b"\x00\x00"
        reply = data[:2] + flags.to_bytes(2, "big") + qd + b"\x00\x00\x00\x00\x00\x00" + question
        try:
            sock.sendto(reply, self.client_address)
        except OSError:
            pass


class _TCP(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True


class _UDP(socketserver.ThreadingUDPServer):
    daemon_threads = True


def main(argv):
    http_port, dns_port = (int(argv[0]), int(argv[1])) if len(argv) == 2 else (3128, 53)  # ports: tests only
    servers = []
    try:
        servers.append(_TCP(("0.0.0.0", http_port), Http))
    except OSError as e:
        log({"kind": "error", "what": "http bind", "detail": str(e)})
    try:
        servers.append(_UDP(("0.0.0.0", dns_port), Dns))
    except OSError as e:
        log({"kind": "error", "what": "dns bind", "detail": str(e)})
    if not servers:
        return 1
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except OSError:
        ip = ""
    for srv in servers:
        threading.Thread(target=srv.serve_forever, daemon=True).start()
    log({"kind": "ready", "ip": ip, "listening": len(servers)})
    while True:
        time.sleep(3600)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
