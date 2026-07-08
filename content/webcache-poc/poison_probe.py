#!/usr/bin/env python3
"""
poison_probe.py - find UNKEYED inputs for web cache poisoning, cache-buster-SAFE, low false-positive (authorized only).

For each candidate header it:
  1) picks a UNIQUE cache-buster (so your test lands on YOUR OWN key, never the shared prod entry),
  2) sends the request WITH  a benign random canary in the header (reqA) -> is the canary reflected?
  3) sends the SAME key WITHOUT the header (reqB) -> is the canary STILL there (served from cache)?
An input that reflects in reqA AND persists in reqB is UNKEYED + POISONABLE. It also classifies WHERE the canary
landed (script/link src, Location, canonical, raw HTML) to hint the impact. Benign canary only - no payloads,
nothing malicious is ever placed on a shared cache. (WEB_CACHE_TESTING_GUIDE.md §4/§5/§20.)

Usage:
  python3 poison_probe.py -u "https://target/path"
  python3 poison_probe.py -u "https://target/path" --buster-param cb --headers X-Forwarded-Host,X-Host -H "Cookie: a=b"
"""
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import argparse, re, time, urllib.request, urllib.error
from urllib.parse import urlsplit, urlunsplit

UA = "Mozilla/5.0 (X11; Linux x86_64) poison-probe/1.0"

DEFAULT_HEADERS = [
    "X-Forwarded-Host", "X-Host", "X-Forwarded-Scheme", "X-Forwarded-Proto", "X-Forwarded-Server",
    "X-Forwarded-Port", "X-Forwarded-For", "Forwarded", "X-Original-URL", "X-Rewrite-URL",
    "X-Original-Host", "X-HTTP-Method-Override", "X-Forwarded-SSL", "X-Real-IP", "X-Wap-Profile",
]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def with_buster(url, param, value):
    s = urlsplit(url)
    q = (s.query + "&" if s.query else "") + f"{param}={value}"
    return urlunsplit((s.scheme, s.netloc, s.path or "/", q, s.fragment))


def fetch(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers, method="GET")
    try:
        r = _OPENER.open(req, timeout=timeout)
        code, hdrs, body = r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        code, hdrs, body = e.code, (e.headers or {}), (e.read() if hasattr(e, "read") else b"")
    except Exception:
        return None, {}, ""
    return code, {k.lower(): v for k, v in hdrs.items()}, body.decode("utf-8", "replace")


def cache_hit(h):
    cf = h.get("cf-cache-status", "").upper()
    if cf:
        return cf == "HIT"
    return "hit" in (h.get("x-cache", "") + h.get("x-vercel-cache", "")).lower()


def classify_sink(canary, headers, body):
    """Where did the canary land? -> impact hint. Most dangerous first."""
    loc = headers.get("location", "")
    if canary in loc:
        return "redirect (Location header)", "cached OPEN REDIRECT -> OAuth token theft / phishing (guide §5)"
    # resource import contexts
    for m in re.finditer(r'(?:src|href)\s*=\s*["\']?([^"\'>\s]*%s[^"\'>\s]*)' % re.escape(canary), body, re.I):
        frag = m.group(0).lower()
        if "<script" in body[max(0, m.start() - 40):m.start()].lower() or ".js" in m.group(1).lower():
            return "resource src (script/js)", "attacker JS host in <script src> cached for ALL -> MASS XSS (guide §5/§6)"
        return "resource src/href (link/img)", "cached resource host control -> XSS/resource poisoning (guide §6)"
    if re.search(r'<(?:link|meta)[^>]*%s' % re.escape(canary), body, re.I):
        return "canonical/link/meta", "cached canonical/redirect-ish reflection (guide §5)"
    if canary in body:
        # raw reflection - is it in a dangerous, unencoded spot?
        raw_break = re.search(r'[<">\']%s|%s[<">\']' % (re.escape(canary), re.escape(canary)), body)
        return ("raw HTML (breakout-capable)" if raw_break else "raw HTML (encoded?)",
                "cached reflected-XSS if unencoded -> mass XSS; else info (guide §5/§17)")
    return None, None


def main():
    ap = argparse.ArgumentParser(description="Cache-poisoning unkeyed-input prober (cache-buster-safe, authorized only).")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--buster-param", default="cb")
    ap.add_argument("--headers", help="comma-separated header names to test (default: the built-in high-yield list)")
    ap.add_argument("-H", "--header", action="append", default=[], help="extra STATIC header 'Name: value' (e.g. Cookie)")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    base = {"User-Agent": UA}
    for hh in a.header:
        if ":" in hh:
            k, v = hh.split(":", 1)
            base[k.strip()] = v.strip()
    candidates = [x.strip() for x in a.headers.split(",")] if a.headers else DEFAULT_HEADERS

    print("== unkeyed-input (cache poisoning) probe ==   [cache-buster-safe: unique buster per header]")
    print(f"[i] url: {a.url}   buster: {a.buster_param}   headers: {len(candidates)}")

    poisonable = 0
    for name in candidates:
        canary = "cnry" + str(abs(hash((name, time.time()))))[:8]
        buster = "pb" + str(abs(hash((name, canary))))[:9]
        url = with_buster(a.url, a.buster_param, buster)

        # reqA: with the candidate header + canary  (populates OUR key)
        cA, hA, bA = fetch(url, {**base, name: canary + ".oastify.test"}, a.timeout)
        if cA is None:
            print(f"  [err] {name:22} request failed")
            continue
        sink, impact = classify_sink(canary, hA, bA)
        if sink is None:
            if a.verbose:
                print(f"  [no]  {name:22} not reflected")
            continue
        # reqB: SAME key, WITHOUT the header  (is our canary served to a request that didn't send it?)
        cB, hB, bB = fetch(url, dict(base), a.timeout)
        served = (canary in bB) or (canary in hB.get("location", ""))
        if served:
            poisonable += 1
            hit = "  [cache HIT]" if cache_hit(hB) else ""
            print(f"  [UNKEYED+REFLECTED] {name:22} -> {sink}; served to a request WITHOUT the header{hit}  *")
            print(f"       -> {impact}")
        else:
            print(f"  [reflected-but-KEYED] {name:22} -> {sink}; a request without it LOSES the canary -> not poisonable")

    print()
    if poisonable:
        print(f"[+] {poisonable} poisonable unkeyed input(s). Verify the sink, then prove 'served to others' with a BENIGN")
        print("    marker on your OWN busted key (never a live payload on the shared cache) - guide §5/§20.")
    else:
        print("[-] no unkeyed+reflected inputs from this list. Try Param Miner's full wordlist, fat-GET/param cloaking (§7),")
        print("    or pivot to DECEPTION (deception_probe.py, §12).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
