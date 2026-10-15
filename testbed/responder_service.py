"""
Responder Service for SentraIPS Testbed (runs on Gateway B).
Provides local, reproducible targets for traffic generation:
- HTTP Server on port 8080 (Web traffic, chunked video streaming simulation, bulk data)
- UDP Socket on port 5004 (VoIP / RTP packet responder)
"""

import http.server
import socketserver
import socket
import threading
import time
import json
import sys


HTTP_PORT = 8080
UDP_PORT = 5004


class TestbedHTTPRequestHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == "/" or self.path == "/status":
            body = json.dumps({"status": "ok", "service": "SentraIPS Gateway B Responder"}).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path.startswith("/api/data"):
            data = {
                "message": "Web traffic simulation response",
                "timestamp": time.time(),
                "records": [{"id": i, "value": f"sample_record_{i * 42}"} for i in range(25)],
            }
            body = json.dumps(data).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        elif self.path.startswith("/stream/video"):
            # Simulate chunked video streaming (e.g. 20 chunks of 16KB)
            self.send_response(200)
            self.send_header("Content-Type", "video/mp4")
            self.send_header("Transfer-Encoding", "chunked")
            self.end_headers()
            chunk = b"X" * 16384  # 16 KB per chunk
            for _ in range(20):
                self.wfile.write(f"{len(chunk):X}\r\n".encode("utf-8"))
                self.wfile.write(chunk)
                self.wfile.write(b"\r\n")
                self.wfile.flush()
                time.sleep(0.05)  # Simulate frame pacing
            self.wfile.write(b"0\r\n\r\n")

        elif self.path.startswith("/bulk"):
            # 256 KB bulk data
            body = b"B" * 262144
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        content_length = int(self.headers.get("Content-Length", 0))
        post_data = self.rfile.read(content_length) if content_length > 0 else b""
        response = json.dumps({
            "status": "received",
            "bytes_received": len(post_data),
            "timestamp": time.time()
        }).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(response)))
        self.end_headers()
        self.wfile.write(response)

    def log_message(self, format, *args):
        # Suppress noisy standard logs
        pass


def start_http_server(port=HTTP_PORT):
    server = socketserver.TCPServer(("0.0.0.0", port), TestbedHTTPRequestHandler)
    print(f"[Responder] HTTP Server running on 0.0.0.0:{port}", flush=True)
    server.serve_forever()


def start_udp_server(port=UDP_PORT):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", port))
    print(f"[Responder] UDP/VoIP Echo Server running on 0.0.0.0:{port}", flush=True)
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            # Echo back with timestamp
            sock.sendto(data, addr)
        except Exception:
            break


if __name__ == "__main__":
    t_http = threading.Thread(target=start_http_server, daemon=True)
    t_udp = threading.Thread(target=start_udp_server, daemon=True)
    t_http.start()
    t_udp.start()
    print("[Responder] All services started. Press Ctrl+C to terminate.", flush=True)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        sys.exit(0)
