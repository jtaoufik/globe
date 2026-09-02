#!/usr/bin/env python3
"""Tiny static server with HTTP basic auth + a background refresh of data.json.

Env: GLOBE_PASSWORD (required), GLOBE_USER (default "taoufik"), PORT (default 8080),
GLOBE_REFRESH_HOURS (default 6). /healthz answers without auth for Coolify's healthcheck.
"""
import base64, os, subprocess, sys, threading, time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")
USER = os.environ.get("GLOBE_USER", "taoufik")
PASSWORD = os.environ.get("GLOBE_PASSWORD")
if not PASSWORD:
    sys.exit("GLOBE_PASSWORD is not set")
EXPECTED = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=STATIC, **kw)

    def do_GET(self):
        if self.path == "/healthz":
            body = b"ok"
            self.send_response(200); self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)
            return
        if self.headers.get("Authorization") != EXPECTED:
            self.send_response(401); self.send_header("WWW-Authenticate", 'Basic realm="globe"')
            self.send_header("Content-Length", "0"); self.end_headers()
            return
        if self.path.startswith("/data.json"):
            self.path = "/data.json"
        super().do_GET()

    def end_headers(self):
        if self.path.startswith("/data.json"):
            self.send_header("Cache-Control", "no-store")
        super().end_headers()

    def log_message(self, fmt, *args):
        sys.stderr.write("%s %s\n" % (self.address_string(), fmt % args))


def refresher():
    hours = float(os.environ.get("GLOBE_REFRESH_HOURS", "6"))
    while True:
        try:
            subprocess.run([sys.executable, os.path.join(HERE, "pull.py")], check=False, timeout=600)
        except Exception as e:  # never let the refresher die
            print("pull failed:", e, file=sys.stderr)
        time.sleep(hours * 3600)


if __name__ == "__main__":
    os.makedirs(STATIC, exist_ok=True)
    threading.Thread(target=refresher, daemon=True).start()
    port = int(os.environ.get("PORT", "8080"))
    print(f"serving {STATIC} on :{port}", file=sys.stderr)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
