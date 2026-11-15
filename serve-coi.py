import http.server
import json
import os
import ssl
import sys
import threading
import time
import zlib
from pathlib import Path

# Cross-origin-isolated launcher for the Switch 2 payload host.
#
# host.py stays exactly as it is (443 + TLS). This script mirrors its TLS behavior but adds
# the isolation headers SharedArrayBuffer needs, and it fixes the two things that break a
# console connection: it always serves this directory, and it always finds localhost.pem
# next to itself no matter where you launch it from.
#
#   python serve-coi.py                 -> https://0.0.0.0:443/ with localhost.pem
#   PORT=8443 python serve-coi.py       -> custom port
#   TLS=0 python serve-coi.py           -> plain http (no SAB on the console)
#   CERT=other.pem python serve-coi.py  -> custom certificate chain
#
# The certificate must hold the private key and the certificate, like localhost.pem does.

BASE_DIR = Path(__file__).resolve().parent
os.chdir(BASE_DIR)

PORT = int(os.environ.get("PORT", "8443"))
TLS = os.environ.get("TLS", "1").lower() not in ("0", "false", "no")
CERT = Path(os.environ.get("CERT", "localhost.pem"))
if not CERT.is_absolute():
    CERT = BASE_DIR / CERT
FALLBACK_PORT = int(os.environ.get("FALLBACK_PORT", "8443"))

BIN_TYPES = {
    ".bin": "application/octet-stream",
    ".nro": "application/octet-stream",
    ".nsp": "application/octet-stream",
    ".xci": "application/octet-stream",
    ".nca": "application/octet-stream",
}

NO_STORE = (".bin", ".html", ".js", ".appcache", ".cache")

def local_ip():
    import socket
    for target in ("8.8.8.8", "1.1.1.1", "192.168.1.1", "10.0.0.1"):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.connect((target, 80))
                ip = s.getsockname()[0]
                if ip and not ip.startswith("127."):
                    return ip
        except OSError:
            pass

    try:
        hostname = socket.gethostname()
        for ip in socket.gethostbyname_ex(hostname)[2]:
            if not ip.startswith("127."):
                return ip
    except Exception:
        pass

    return "127.0.0.1"

# --- Netcat TCP Payload Listener (Port 9020) ---------------------------------------------------
NETCAT_PORT = int(os.environ.get("NETCAT_PORT", "9020"))

netcat_state = {
    "ip": local_ip(),
    "port": NETCAT_PORT,
    "last_client": None,
    "last_file": None,
    "last_size": 0,
    "last_type": None,
    "last_time": 0,
    "payload_ready": False,
    "payload_id": 0,
    "console_ip": None,
    "console_last_seen": 0,
    "console_fetched": False,
    "console_fetch_time": 0,
    "console_executed": False,
    "console_exec_time": 0,
}
netcat_payload_data = b""
netcat_lock = threading.Lock()

def detect_payload_type(data: bytes) -> str:
    if len(data) >= 0x20 and data[0x10:0x14] == b"NRO0":
        return "NRO Homebrew"
    if len(data) >= 4 and data[:4] == b"SW2P":
        return "SW2P Container"
    if len(data) >= 4 and data[:4] == b"PK\x03\x04":
        return "ZIP Package"
    if len(data) >= 4 and data[:4] == b"MOD0":
        return "MOD0 Module"
    return "Raw AArch64 Binary"

def start_netcat_server():
    def _listen():
        import socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", NETCAT_PORT))
            s.listen(5)
            print(f"[netcat] TCP Payload Loader dinliyor: 0.0.0.0:{NETCAT_PORT}")
            print(f"[netcat] Gönderim komutu: nc {local_ip()} {NETCAT_PORT} < payload.bin (veya .nro)")
        except Exception as e:
            print(f"[netcat] port {NETCAT_PORT} dinlenemedi: {e}")
            return

        while True:
            try:
                conn, addr = s.accept()
                print(f"[netcat] Bağlantı alındı: {addr[0]}:{addr[1]}")
                conn.settimeout(2.5)
                chunks = []
                try:
                    while True:
                        data = conn.recv(65536)
                        if not data:
                            break
                        chunks.append(data)
                except socket.timeout:
                    pass
                conn.close()

                if not chunks:
                    continue

                full_data = b"".join(chunks)
                ptype = detect_payload_type(full_data)
                fname = "payload.nro" if "NRO" in ptype else "payload.bin"

                global netcat_payload_data
                with netcat_lock:
                    netcat_payload_data = full_data
                    netcat_state["last_client"] = addr[0]
                    netcat_state["last_file"] = fname
                    netcat_state["last_size"] = len(full_data)
                    netcat_state["last_type"] = ptype
                    netcat_state["last_time"] = time.time()
                    netcat_state["payload_ready"] = True
                    netcat_state["payload_id"] += 1

                print(f"[netcat] {addr[0]} -> {len(full_data):,} bayt alındı ({ptype})")
                print(f"[netcat] '{fname}' başarıyla gönderildi ve Switch 2 için hazırlandı!")
            except Exception as e:
                print(f"[netcat] bağlantı hatası: {e}")

    t = threading.Thread(target=_listen, daemon=True)
    t.start()


class Handler(http.server.SimpleHTTPRequestHandler):
    def handle_one_request(self):
        # A console or browser that drops the connection mid-response must not kill the
        # process or dump a traceback into the window.
        try:
            super().handle_one_request()
        except (BrokenPipeError, ConnectionResetError, ConnectionAbortedError, ssl.SSLError, TimeoutError):
            self.close_connection = True

    def guess_type(self, path):
        ext = os.path.splitext(path)[1].lower()
        if ext in BIN_TYPES:
            return BIN_TYPES[ext]
        return super().guess_type(path)

    def do_GET(self):
        client = self.client_address[0] if self.client_address else ""
        if client and not client.startswith("127.") and client != "::1":
            with netcat_lock:
                netcat_state["console_ip"] = client
                netcat_state["console_last_seen"] = time.time()

        path = self.path.split("?")[0]

        # /version proves which server, which folder and which build answered.
        if path in ("/version", "/version.json"):
            payload_file = BASE_DIR / "switch2.bin"
            payload = b""
            if payload_file.exists():
                payload = payload_file.read_bytes()
            info = {
                "build": "sw2-v2.4",
                "root": str(BASE_DIR),
                "server": "serve-coi.py",
                "port": self.server.server_address[1],
                "has_sw2": (BASE_DIR / "sw2.html").exists(),
                "has_boot": (BASE_DIR / "boot.html").exists(),
                "payload_bytes": len(payload),
                # body CRC, matches the value the page computes and the header stores
                "payload_crc32": "0x%08X" % (zlib.crc32(payload[0x50:]) & 0xFFFFFFFF)
                if len(payload) > 0x50
                else None,
                "payload_file_crc32": "0x%08X" % (zlib.crc32(payload) & 0xFFFFFFFF) if payload else None,
                "payload_stage1": payload[0x38:0x3C] != b"\x00\x00\x00\x00" if len(payload) > 0x50 else False,
            }
            body = json.dumps(info).encode() + b"\n"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # /netcat/status returns current Netcat IP, port, and last received file info
        if path == "/netcat/status":
            with netcat_lock:
                info = dict(netcat_state)
            current_ip = local_ip()
            info["ip"] = current_ip
            info["server_ip"] = current_ip
            info["client_ip"] = self.client_address[0] if self.client_address else None
            body = json.dumps(info).encode() + b"\n"
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return

        # /netcat/payload returns the payload received over netcat
        if path == "/netcat/payload":
            with netcat_lock:
                data = netcat_payload_data
                if data:
                    netcat_state["console_fetched"] = True
                    netcat_state["console_fetch_time"] = time.time()
                    if self.client_address and not self.client_address[0].startswith("127."):
                        netcat_state["console_ip"] = self.client_address[0]
            if not data:
                self.send_response(404)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                return
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
            return

        # /reset forces the console to drop cached pages/storage even before JS runs.
        if path in ("/reset", "/reset/", "/reset.html"):
            self.send_response(302)
            self.send_header("Location", "/boot.html")
            self.send_header("Clear-Site-Data", '"cache", "storage", "cookies"')
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        super().do_GET()

    def do_POST(self):
        client = self.client_address[0] if self.client_address else ""
        if client and not client.startswith("127.") and client != "::1":
            with netcat_lock:
                netcat_state["console_ip"] = client
                netcat_state["console_last_seen"] = time.time()

        path = self.path.split("?")[0]
        if path in ("/netcat/ack", "/ack"):
            content_length = int(self.headers.get("Content-Length", 0))
            ack_raw = self.rfile.read(content_length) if content_length > 0 else b"{}"
            with netcat_lock:
                netcat_state["console_executed"] = True
                netcat_state["console_exec_time"] = time.time()
                try:
                    netcat_state["last_ack"] = json.loads(ack_raw.decode("utf-8", "ignore"))
                except Exception:
                    pass
            print(f"[ack] Switch 2 ({client}) payload çalıştırma onayını (ACK) bildirdi!")
            resp = b'{"status":"ok","acknowledged":true}\n'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        if path in ("/upload", "/netcat/upload"):
            content_length = int(self.headers.get("Content-Length", 0))
            if content_length <= 0:
                self.send_response(400)
                self.end_headers()
                return

            full_data = self.rfile.read(content_length)
            ptype = detect_payload_type(full_data)
            fname = self.headers.get("X-Filename", "payload.nro" if "NRO" in ptype else "payload.bin")

            global netcat_payload_data
            with netcat_lock:
                netcat_payload_data = full_data
                netcat_state["last_client"] = self.client_address[0] if self.client_address else "web-upload"
                netcat_state["last_file"] = fname
                netcat_state["last_size"] = len(full_data)
                netcat_state["last_type"] = ptype
                netcat_state["last_time"] = time.time()
                netcat_state["payload_ready"] = True
                netcat_state["payload_id"] += 1

            print(f"[upload] {len(full_data):,} bayt alındı ({ptype}, '{fname}') -> Switch 2 için hazırlandı!")
            resp = json.dumps({"status": "ok", "size": len(full_data), "type": ptype, "file": fname}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-Length", str(len(resp)))
            self.end_headers()
            self.wfile.write(resp)
            return

        self.send_error(405, "Method Not Allowed")

    def end_headers(self):
        # Malformed requests hit send_error before self.path exists; never crash the server.
        path = getattr(self, "path", "") or ""
        self.send_header("Cross-Origin-Opener-Policy", "same-origin")
        self.send_header("Cross-Origin-Embedder-Policy", "require-corp")
        self.send_header("Cross-Origin-Resource-Policy", "same-origin")
        if path.endswith(NO_STORE):
            self.send_header("Cache-Control", "no-store, must-revalidate")
        self.send_header("X-Content-Type-Options", "nosniff")
        super().end_headers()

    def log_message(self, fmt, *args):
        # Client IP is the console IP when the Switch opens this page.
        client = self.client_address[0] if self.client_address else "-"
        sys.stderr.write(f"[coi] {client} " + (fmt % args) + "\n")


def make_context():
    if not CERT.exists():
        print(f"[coi] certificate not found: {CERT}")
        print("[coi] TLS requested but no certificate - refusing to serve plain http on this port")
        print("[coi] put the key+cert pem next to this script, or run with TLS=0")
        raise SystemExit(2)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    try:
        context.load_cert_chain(str(CERT))
    except ssl.SSLError as e:
        print(f"[coi] cannot load {CERT}: {e}")
        raise SystemExit(2)
    return context


class Server(http.server.ThreadingHTTPServer):
    # Keep SO_REUSEADDR so a TIME_WAIT socket from a previous run does not block the port.
    # Double binding is prevented by the is_port_open() pre-check below instead.
    allow_reuse_address = True
    daemon_threads = True

    def handle_error(self, request, client_address):
        # A dropped console connection is not a crash: one line, no traceback.
        exc = sys.exc_info()[1]
        print(f"[coi] client {client_address[0]} error: {type(exc).__name__}: {exc}")

    def get_request(self):
        # TLS handshake happens inside accept() when the listening socket is wrapped.
        # A browser sending plain http to the https port raises SSLError here, and letting
        # it escape kills serve_forever - that is the "server crashed" case. Skip it.
        while True:
            try:
                return super().get_request()
            except ssl.SSLError as e:
                print(f"[coi] tls handshake rejected: {e.reason or e}")
                continue
            except ConnectionResetError:
                continue
            except OSError as e:
                if e.errno in (10054, 10038):
                    continue
                raise


def is_port_open(port, timeout=0.3):
    import socket

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(timeout)
        return s.connect_ex(("127.0.0.1", port)) == 0


class RedirectToHttps(http.server.BaseHTTPRequestHandler):
    """Plain :80 -> https redirect, so typing the IP without https still lands on the chain."""

    HTTPS_PORT = 443

    def do_GET(self):
        host = (self.headers.get("Host") or "").split(":")[0]
        target = f"https://{host}{self.path}" if host else f"https://{self.server.server_address[0]}{self.path}"
        self.send_response(301)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    do_HEAD = do_GET

    def log_message(self, fmt, *args):
        sys.stderr.write("[coi:80] " + (fmt % args) + "\n")


def start_http_redirect(https_port):
    try:
        srv = http.server.ThreadingHTTPServer(("0.0.0.0", 80), RedirectToHttps)
    except OSError as e:
        print(f"[coi] port 80 redirect not started ({e.strerror or e})")
        return
    srv.daemon_threads = True
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"[coi] http://0.0.0.0:80/ redirects to https port {https_port}")


def bind(port):
    return Server(("0.0.0.0", port), Handler)

context = make_context() if TLS else None
scheme = "https" if context else "http"

if is_port_open(PORT):
    print(f"[coi] port {PORT} is already in use - another server is running")
    print("[coi] close it first (or set PORT=8443)")
    raise SystemExit(3)

try:
    httpd = bind(PORT)
except OSError as e:
    if PORT == FALLBACK_PORT:
        raise
    print(f"[coi] port {PORT} unavailable ({e.strerror or e}) - trying {FALLBACK_PORT}")
    PORT = FALLBACK_PORT
    httpd = bind(PORT)

if context:
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)
    start_http_redirect(PORT)

start_netcat_server()

print(f"[coi] root:    {BASE_DIR}")
print(f"[coi] cert:    {CERT if context else 'none'}")
print(f"[coi] serving: {scheme}://0.0.0.0:{PORT}/")
print(f"[coi] chain:   {scheme}://<this-host>:{PORT}/index.html")
print(f"[coi] cache:   {scheme}://<this-host>:{PORT}/cache.html")
print(f"[coi] KONSOLDA AC: {scheme}://{local_ip()}:{PORT}/index.html")
print(f"[coi] NETCAT:  nc {local_ip()} {NETCAT_PORT} < dosya.nro (veya .bin)")
sys.stdout.flush()

try:
    httpd.serve_forever()
except KeyboardInterrupt:
    print("\n[coi] stopped")
finally:
    httpd.server_close()
