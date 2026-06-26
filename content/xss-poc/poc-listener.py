#!/usr/bin/env python3
# poc-listener.py — minimal exfil/callback sink for AUTHORIZED XSS PoCs only.
# Logs every GET/POST (path, query, headers, body) and serves CORS-permissive 200s so
# beacons/fetch(no-cors) succeed. Prefer Burp Collaborator / interactsh / XSS Hunter for
# real engagements (they capture source IP + DOM + screenshots). This is for quick local PoCs.
#
# Usage:   python3 poc-listener.py [port]      (default 8000)
# Expose:  ngrok http 8000   /   cloudflared tunnel --url http://localhost:8000
#
# ETHICS: only receive YOUR OWN test data from targets you are authorized to test.

import sys, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(sys.argv[1]) if len(sys.argv) > 1 else 8000
LOGFILE = "xss_callbacks.log"


def log(line: str):
    stamp = datetime.datetime.now().isoformat(timespec="seconds")
    out = f"[{stamp}] {line}"
    print(out)
    with open(LOGFILE, "a", encoding="utf-8") as f:
        f.write(out + "\n")


class Handler(BaseHTTPRequestHandler):
    def _record(self):
        src = self.client_address[0]
        body = b""
        length = int(self.headers.get("Content-Length", 0) or 0)
        if length:
            body = self.rfile.read(length)
        log(f"HIT {self.command} from {src}  path={self.path}")
        log(f"     UA={self.headers.get('User-Agent','')}  Referer={self.headers.get('Referer','')}")
        if body:
            log(f"     BODY={body[:4000]!r}")
        # CORS-permissive 1x1 response so no-cors beacons resolve
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.send_header("Content-Type", "image/gif")
        self.end_headers()
        # 1x1 transparent GIF
        self.wfile.write(
            b"GIF89a\x01\x00\x01\x00\x80\x00\x00\xff\xff\xff\x00\x00\x00"
            b"!\xf9\x04\x01\x00\x00\x00\x00,\x00\x00\x00\x00\x01\x00\x01\x00\x00\x02\x02D\x01\x00;"
        )

    do_GET = do_POST = _record

    def do_OPTIONS(self):
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "*")
        self.end_headers()

    def log_message(self, *a):
        pass  # silence default logging; we do our own


if __name__ == "__main__":
    log(f"poc-listener listening on 0.0.0.0:{PORT} (log -> {LOGFILE})")
    try:
        ThreadingHTTPServer(("0.0.0.0", PORT), Handler).serve_forever()
    except KeyboardInterrupt:
        log("shutting down")
