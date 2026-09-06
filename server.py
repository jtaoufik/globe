#!/usr/bin/env python3
"""Tiny static server with HTTP basic auth + a background refresh of data.json.

Env: GLOBE_PASSWORD (required), GLOBE_USER (default "taoufik"), PORT (default 8080),
GLOBE_REFRESH_HOURS (default 6). /healthz answers without auth for Coolify's healthcheck.
"""
import base64, json, os, subprocess, sys, threading, time
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer

HERE = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(HERE, "static")
# Posted datasets (data-web.json, journeys-web.json) live in /data when a volume is mounted there
# (Coolify custom docker run option "-v globe-data:/data"): a redeploy used to wipe them (06/09).
DATA_DIR = "/data" if os.path.isdir("/data") and os.access("/data", os.W_OK) else STATIC
POSTED = ("data-web.json", "journeys-web.json")
USER = os.environ.get("GLOBE_USER", "taoufik")
PASSWORD = os.environ.get("GLOBE_PASSWORD")
if not PASSWORD:
    sys.exit("GLOBE_PASSWORD is not set")
EXPECTED = "Basic " + base64.b64encode(f"{USER}:{PASSWORD}".encode()).decode()


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *a, **kw):
        super().__init__(*a, directory=STATIC, **kw)

    def translate_path(self, path):
        name = path.split("?")[0].lstrip("/")
        if name in POSTED:
            return os.path.join(DATA_DIR, name)
        return super().translate_path(path)

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
        path = self.path.split("?")[0]
        if path in ("/", "/index.html"):
            self.path = "/choose.html"          # fleet chooser: mobile apps or websites
        elif path in ("/mobile", "/web", "/mobile/", "/web/"):
            self.path = "/index.html"           # same page, the script reads the fleet from the URL
        elif path == "/data.json":
            self.path = "/data.json"
        elif path in ("/data-web.json", "/journeys-web.json"):
            self.path = path
        super().do_GET()

    def do_POST(self):
        """/ingest: the box's globe-web.py posts the websites dataset; /ingest-journeys: fleet-journeys.py
        posts the human sessions (both basic auth, JSON body)."""
        if self.headers.get("Authorization") != EXPECTED:
            self.send_response(401); self.send_header("Content-Length", "0"); self.end_headers(); return
        route = self.path.split("?")[0]
        if route not in ("/ingest", "/ingest-journeys"):
            self.send_response(404); self.send_header("Content-Length", "0"); self.end_headers(); return
        n = int(self.headers.get("Content-Length") or 0)
        body = self.rfile.read(n)
        try:
            doc = json.loads(body)
            if route == "/ingest":
                assert isinstance(doc.get("points"), list) and isinstance(doc.get("apps"), list)
            else:  # /ingest-journeys: fleet-journeys.py on the box, human sessions per site per day
                assert isinstance(doc.get("days"), dict) and isinstance(doc.get("sites"), dict)
        except Exception as e:
            self.send_response(400); self.send_header("Content-Length", "0"); self.end_headers(); return
        if route == "/ingest-journeys":
            target = os.path.join(DATA_DIR, "journeys-web.json")
            tmp = target + ".tmp"
            with open(tmp, "wb") as f:
                f.write(body)
            os.replace(tmp, target)
            out = b"ok %d days" % len(doc["days"])
            self.send_response(200); self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)
            return
        target = os.path.join(DATA_DIR, "data-web.json")
        tmp = target + ".tmp"
        with open(tmp, "wb") as f:
            f.write(body)
        os.replace(tmp, target)
        out = b"ok %d points" % len(doc["points"])
        self.send_response(200); self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(out))); self.end_headers(); self.wfile.write(out)

    def end_headers(self):
        if self.path.startswith(("/data.json", "/data-web.json", "/journeys-web.json")):
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
    print(f"serving {STATIC} on :{port}, posted datasets in {DATA_DIR}", file=sys.stderr)
    ThreadingHTTPServer(("0.0.0.0", port), Handler).serve_forever()
