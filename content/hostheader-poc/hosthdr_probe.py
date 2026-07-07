#!/usr/bin/env python3
"""
hosthdr_probe.py — authorized Host-header injection prober. Fires the spoofing-header set at a URL and
reports where a marker host lands: reflected in the body, in a Location redirect, in canonical/og links,
or accepted-but-silent. (HOST_HEADER_INJECTION_TESTING_GUIDE.md §4-§6.)

Reflection is a CONDITION; escalate to a sink (reset/cache/routing) before reporting (§15/§16).

Usage:
  python3 hosthdr_probe.py -u https://target/
  python3 hosthdr_probe.py -u https://target/login
"""
import argparse, sys
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

MARK = "evil-hh-7f3a9.example"
HEADERS = [
    {"Host": MARK},
    {"X-Forwarded-Host": MARK},
    {"X-Host": MARK},
    {"X-Forwarded-Server": MARK},
    {"X-HTTP-Host-Override": MARK},
    {"X-Original-Host": MARK},
    {"Forwarded": f"host={MARK}"},
]

def probe(url, extra, timeout):
    h = {"User-Agent": "Mozilla/5.0"}
    h.update(extra)
    try:
        r = requests.get(url, headers=h, timeout=timeout, verify=False, allow_redirects=False)
    except Exception as e:
        return None, str(e)
    where = []
    if MARK in (r.headers.get("Location") or ""):
        where.append("Location/redirect (open-redirect/OAuth -> §9/§14)")
    body = r.text
    if MARK in body:
        # is it cacheable?
        cache = []
        if r.headers.get("Age"):
            cache.append("Age")
        cc = (r.headers.get("Cache-Control") or "").lower()
        if "public" in cc or "max-age" in cc:
            cache.append("Cache-Control")
        if (r.headers.get("X-Cache") or "").lower().find("hit") >= 0:
            cache.append("X-Cache:hit")
        tag = " [CACHEABLE -> cache poisoning §12]" if cache else ""
        where.append(f"response body{tag}")
        if "canonical" in body.lower() or "og:url" in body.lower():
            where.append("canonical/og links")
    return (r.status_code, where), None

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--timeout", type=float, default=12)
    a = ap.parse_args()

    print(f"== Host-header probe: {a.url} ==\n")
    any_hit = False
    for extra in HEADERS:
        name = list(extra.keys())[0]
        res, err = probe(a.url, extra, a.timeout)
        if err:
            print(f"[err] {name}: {err}")
            continue
        code, where = res
        if where:
            any_hit = True
            print(f"[LANDS] {name:22} (HTTP {code}) -> " + "; ".join(where))
        else:
            print(f"[ .. ] {name:22} (HTTP {code}) accepted but not observed reflected")

    print()
    if any_hit:
        print("[!] The host LANDS somewhere. Now find the SINK & prove impact:")
        print("    - password-reset email link? -> reset_poison.py (§11)  *highest value*")
        print("    - reflected + cacheable?      -> cache_poison.py (§12)")
        print("    - changes the backend?        -> routing SSRF (Host: 169.254.169.254 / internal) (§13)")
    else:
        print("[*] No reflection observed. Still test: the password-reset EMAIL link (trusted, not reflected),")
        print("    and whether changing Host changes the backend (routing SSRF). Reflection isn't required for those.")

if __name__ == "__main__":
    main()
