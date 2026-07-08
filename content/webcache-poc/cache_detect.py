#!/usr/bin/env python3
"""
cache_detect.py - is this URL cached? which layer? build a HIT/MISS oracle (authorized only).

Sends the URL twice with the SAME cache-buster (to see MISS->HIT / Age growth / speed-up), then once with a
DIFFERENT buster (to confirm the buster is KEYED = safe isolation for later poisoning tests). Fingerprints the
cache layer from response headers. Read-only; no payloads. (WEB_CACHE_TESTING_GUIDE.md §2/§3.)

Usage:
  python3 cache_detect.py -u "https://target/path"
  python3 cache_detect.py -u "https://target/path" --buster-param cb -H "Cookie: a=b"
"""
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # never crash a cp1252 console
except Exception:
    pass
import argparse, time, urllib.request, urllib.error
from urllib.parse import urlsplit, urlunsplit

UA = "Mozilla/5.0 (X11; Linux x86_64) cache-detect/1.0"


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None  # don't follow - we want to SEE the 3xx + Location


_OPENER = urllib.request.build_opener(_NoRedirect)


def with_buster(url, param, value):
    s = urlsplit(url)
    q = s.query
    add = f"{param}={value}"
    q = (q + "&" + add) if q else add
    return urlunsplit((s.scheme, s.netloc, s.path or "/", q, s.fragment))


def fetch(url, headers, timeout):
    req = urllib.request.Request(url, headers=headers, method="GET")
    t0 = time.time()
    try:
        r = _OPENER.open(req, timeout=timeout)
        code, hdrs, body = r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        code, hdrs, body = e.code, (e.headers or {}), (e.read() if hasattr(e, "read") else b"")
    except Exception as e:
        return None, {}, 0.0
    return code, {k.lower(): v for k, v in hdrs.items()}, (time.time() - t0) * 1000.0


def cache_state(h):
    """Normalize a hit/miss signal from headers -> 'HIT'|'MISS'|'DYNAMIC'|'?'."""
    cf = h.get("cf-cache-status", "")
    if cf:
        return cf.upper()
    xc = h.get("x-cache", "") + " " + h.get("x-vercel-cache", "") + " " + h.get("x-drupal-cache", "")
    xc_l = xc.lower()
    if "hit" in xc_l:
        return "HIT"
    if "miss" in xc_l:
        return "MISS"
    for k in ("x-proxy-cache", "x-litespeed-cache", "x-nginx-cache"):
        v = h.get(k, "").lower()
        if "hit" in v:
            return "HIT"
        if "miss" in v:
            return "MISS"
    return "?"


def age(h):
    try:
        return int(h.get("age", ""))
    except (TypeError, ValueError):
        return None


def fingerprint(h):
    tests = [
        ("Cloudflare", any(k in h for k in ("cf-ray", "cf-cache-status")) or "cloudflare" in h.get("server", "").lower()),
        ("AWS CloudFront", "cloudfront" in (h.get("via", "") + h.get("x-cache", "")).lower() or "x-amz-cf-id" in h),
        ("Fastly", "x-served-by" in h or "x-timer" in h or "fastly" in h.get("x-cache", "").lower()),
        ("Akamai", "akamaighost" in h.get("server", "").lower() or any(k.startswith("x-akamai") for k in h) or "x-check-cacheable" in h),
        ("Varnish", "x-varnish" in h or "varnish" in h.get("via", "").lower()),
        ("Vercel/Next.js", "x-vercel-cache" in h),
        ("Drupal", "x-drupal-cache" in h or "x-drupal-dynamic-cache" in h),
        ("LiteSpeed", "x-litespeed-cache" in h),
        ("nginx proxy_cache", "x-proxy-cache" in h or "x-nginx-cache" in h),
    ]
    hits = [name for name, cond in tests if cond]
    return hits or (["(generic shared cache - Age present)"] if age(h) is not None else ["(no cache headers seen)"])


def line(tag, code, h, ms):
    av = age(h)
    return (f"  {tag:12} -> status {code}  cache={cache_state(h):8} "
            f"Age={av if av is not None else '-':<4} time={ms:6.0f}ms")


def main():
    ap = argparse.ArgumentParser(description="Detect a web cache + build a HIT/MISS oracle (authorized only).")
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--buster-param", default="cb")
    ap.add_argument("-H", "--header", action="append", default=[], help="extra header 'Name: value' (repeatable)")
    ap.add_argument("--timeout", type=float, default=15.0)
    a = ap.parse_args()

    headers = {"User-Agent": UA}
    for hh in a.header:
        if ":" in hh:
            k, v = hh.split(":", 1)
            headers[k.strip()] = v.strip()

    same = "cbx" + str(int(time.time()))[-6:]
    diff = "cby" + str(int(time.time()) + 1)[-6:]
    u_same = with_buster(a.url, a.buster_param, same)
    u_diff = with_buster(a.url, a.buster_param, diff)

    print("== web cache detection ==")
    print(f"[i] url: {a.url}   buster: {a.buster_param}")

    c1, h1, t1 = fetch(u_same, headers, a.timeout)
    if c1 is None:
        sys.exit("[!] request failed (host/tls/timeout).")
    c2, h2, t2 = fetch(u_same, headers, a.timeout)     # same key again -> HIT if cacheable
    c3, h3, t3 = fetch(u_diff, headers, a.timeout)     # fresh key -> MISS if buster is keyed

    print(line("req1 (same)", c1, h1, t1))
    print(line("req2 (same)", c2, h2, t2))
    print(line("req3 (diff)", c3, h3, t3))

    st2 = cache_state(h2)
    a1, a2 = age(h1), age(h2)
    age_grew = a1 is not None and a2 is not None and a2 > a1
    faster = t2 < t1 * 0.5 and t1 > 5
    cached = st2 == "HIT" or age_grew or (st2 != "DYNAMIC" and faster and a2 is not None)

    print()
    if cached:
        why = []
        if st2 == "HIT":
            why.append("2nd request = HIT")
        if age_grew:
            why.append(f"Age grew {a1}->{a2}")
        if faster:
            why.append(f"2nd request {t2:.0f}ms << 1st {t1:.0f}ms")
        print(f"[+] CACHED: this response is cacheable ({'; '.join(why) or 'cache header present'}).")
        print(f"[+] cache layer: {', '.join(fingerprint(h2))}")
        keyed = cache_state(h3) in ("MISS", "?", "DYNAMIC") and (age(h3) in (0, None))
        if keyed:
            print(f"[+] buster '{a.buster_param}' looks KEYED (fresh value -> MISS/Age0) -> safe isolation for poisoning tests (guide §3).")
        else:
            print(f"[!] buster '{a.buster_param}' may be UNKEYED (fresh value still HIT) -> find a keyed buster BEFORE firing payloads (guide §3/§20).")
        print("[next] poison_probe.py (unkeyed inputs) ; deception_probe.py (path-confusion).")
    else:
        print(f"[-] NOT clearly cached here (state={st2}, no Age growth/speed-up).")
        print("    -> pivot to STATIC resources (JS/CSS/img are usually cached -> resource poisoning, guide §6),")
        print("       or to DECEPTION (a static-suffix URL may cache a private page, guide §12).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
