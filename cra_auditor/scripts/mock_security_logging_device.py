import argparse
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class MockLogHandler(BaseHTTPRequestHandler):
    log_paths = {"/logs", "/api/logs"}

    def do_GET(self):
        if self.path in self.log_paths:
            payload = {
                "status": "ok",
                "message": "mock log endpoint",
                "path": self.path,
            }
            encoded = json.dumps(payload).encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(encoded)))
            self.end_headers()
            self.wfile.write(encoded)
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        return


def run_udp_listener(host: str, port: int):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((host, port))
    while True:
        data, addr = sock.recvfrom(4096)
        if data:
            try:
                sock.sendto(b"ok", addr)
            except OSError:
                pass


def main():
    parser = argparse.ArgumentParser(description="Mock security logging target for CRA scanner validation")
    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--http-port", type=int, default=8080)
    parser.add_argument("--udp-port", type=int, default=514)
    parser.add_argument("--disable-udp", action="store_true")
    args = parser.parse_args()

    if not args.disable_udp:
        udp_thread = threading.Thread(target=run_udp_listener, args=(args.host, args.udp_port), daemon=True)
        udp_thread.start()

    server = ThreadingHTTPServer((args.host, args.http_port), MockLogHandler)
    print(f"Mock logging probe target running on {args.host}")
    print(f"HTTP endpoint: http://{args.host}:{args.http_port}/logs")
    if args.disable_udp:
        print("UDP syslog listener: disabled")
    else:
        print(f"UDP syslog listener: {args.host}:{args.udp_port}")
    server.serve_forever()


if __name__ == "__main__":
    main()
