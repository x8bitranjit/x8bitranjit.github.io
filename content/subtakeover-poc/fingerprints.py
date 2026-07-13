#!/usr/bin/env python3
"""
fingerprints.py - per-service subdomain-takeover signature database + matcher.
Each entry: the CNAME pattern(s), the HTTP "not found" body signature, whether the service is (commonly) CLAIMABLE,
and a short claim note. Importable by subtakeover_scan.py.

A fingerprint is a LEAD, not a finding. ALWAYS cross-check the authoritative, continuously-updated matrix
`can-i-take-over-xyz` (EdOverflow) before calling something a takeover, then CLAIM it and serve a benign marker
(SUBDOMAIN_TAKEOVER_TESTING_GUIDE.md sections 6-8). Claimability changes over time - keep this synced.

Run directly for a self-test:
  python3 fingerprints.py --selftest
"""
import argparse, sys, re

# cp1252-safe console on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

# claimable: "yes" | "edge" (region/verification dependent) | "no"
# body_sig is matched case-insensitively as a substring against the HTTP response body.
SERVICES = [
    {"service": "AWS/S3",        "cname": [r"s3[.-].*amazonaws\.com", r"\.s3\.amazonaws\.com"],
     "body_sig": ["NoSuchBucket", "The specified bucket does not exist"], "claimable": "yes",
     "note": "Create the exact global-namespace bucket; enable static hosting."},
    {"service": "GitHub Pages",  "cname": [r"\.github\.io", r"github\.map\.fastly\.net"],
     "body_sig": ["There isn't a GitHub Pages site here"], "claimable": "yes",
     "note": "Create the repo/org page; add sub as custom domain (CNAME file)."},
    {"service": "Heroku",        "cname": [r"\.herokuapp\.com", r"\.herokudns\.com", r"herokussl"],
     "body_sig": ["No such app", "herokucdn.com/error-pages/no-such-app.html"], "claimable": "edge",
     "note": "Create an app; add sub as a custom domain."},
    {"service": "Fastly",        "cname": [r"\.fastly\.net"],
     "body_sig": ["Fastly error: unknown domain"], "claimable": "edge",
     "note": "Add the domain to a Fastly service you control."},
    {"service": "Azure",         "cname": [r"\.azurewebsites\.net", r"\.cloudapp\.azure\.com",
                                           r"\.trafficmanager\.net", r"\.blob\.core\.windows\.net",
                                           r"\.azureedge\.net"],
     "body_sig": ["404 Web Site not found", "The specified blob does not exist",
                  "The specified container does not exist"], "claimable": "edge",
     "note": "Register the app/storage name (region-locked); add custom domain."},
    {"service": "Shopify",       "cname": [r"\.myshopify\.com"],
     "body_sig": ["Sorry, this shop is currently unavailable"], "claimable": "edge",
     "note": "Often needs the exact myshopify name; verify can-i-take-over-xyz."},
    {"service": "Netlify",       "cname": [r"\.netlify\.app", r"\.netlify\.com"],
     "body_sig": ["Not Found - Request ID"], "claimable": "edge",
     "note": "Create a site; add the custom domain."},
    {"service": "Surge.sh",      "cname": [r"\.surge\.sh"],
     "body_sig": ["project not found"], "claimable": "yes",
     "note": "surge the domain."},
    {"service": "Zendesk",       "cname": [r"\.zendesk\.com"],
     "body_sig": ["Help Center Closed"], "claimable": "edge",
     "note": "Register the Zendesk subdomain."},
    {"service": "Readme.io",     "cname": [r"\.readme\.io"],
     "body_sig": ["Project doesnt exist... yet!"], "claimable": "yes",
     "note": "Claim the project name."},
    {"service": "Ghost",         "cname": [r"\.ghost\.io"],
     "body_sig": ["Domain error", "The thing you were looking for is no longer here"], "claimable": "edge",
     "note": "Claim the Ghost publication."},
    {"service": "Bitbucket",     "cname": [r"\.bitbucket\.io"],
     "body_sig": ["Repository not found"], "claimable": "yes",
     "note": "Create the repo/pages site."},
    {"service": "Unbounce",      "cname": [r"\.unbounce\.com", r"unbouncepages\.com"],
     "body_sig": ["The requested URL was not found on this server"], "claimable": "edge",
     "note": "Verify per can-i-take-over-xyz."},
    {"service": "Tumblr",        "cname": [r"\.tumblr\.com", r"domains\.tumblr\.com"],
     "body_sig": ["Whatever you were looking for doesn't currently exist at this address"], "claimable": "edge",
     "note": "Claim the blog + add the custom domain."},
    {"service": "Wordpress",     "cname": [r"\.wordpress\.com"],
     "body_sig": ["Do you want to register"], "claimable": "edge",
     "note": "Verify per can-i-take-over-xyz."},
    {"service": "Pantheon",      "cname": [r"\.pantheonsite\.io", r"\.pantheon\.io"],
     "body_sig": ["The gods are wise", "404 error unknown site"], "claimable": "edge",
     "note": "Claim the Pantheon site."},
    {"service": "Cargo",         "cname": [r"cargocollective\.com"],
     "body_sig": ["If you're moving your domain away from Cargo"], "claimable": "edge",
     "note": "Verify; add the domain to a Cargo site."},
    {"service": "Statuspage",    "cname": [r"\.statuspage\.io"],
     "body_sig": ["You are being redirected", "This page is parked"], "claimable": "no",
     "note": "Statuspage generally blocks re-registration - usually NOT takeover-able."},
    {"service": "AWS/CloudFront","cname": [r"\.cloudfront\.net"],
     "body_sig": ["The request could not be satisfied", "ERROR: The request could not be satisfied"],
     "claimable": "no",
     "note": "CloudFront distributions are usually reserved - typically NOT claimable (Info)."},
    {"service": "Acquia",        "cname": [r"\.acquia-sites\.com", r"realm\.acquia"],
     "body_sig": ["If you are an Acquia Cloud customer", "Web Site Not Found"], "claimable": "edge",
     "note": "Verify per can-i-take-over-xyz."},
    {"service": "Webflow",       "cname": [r"\.proxy\.webflow\.com", r"proxy-ssl\.webflow\.com"],
     "body_sig": ["The page you are looking for doesn't exist or has been moved"], "claimable": "edge",
     "note": "Add the domain to a Webflow project."},
]


# stock phrases that appear on countless unrelated 404/error pages - never trust these as a BODY-ONLY signal
_GENERIC = {
    "not found", "404 not found", "404 error", "page not found", "file not found",
    "the requested url was not found on this server", "you are being redirected",
    "bad request", "forbidden", "error", "domain error",
}


def _is_generic(sig):
    return sig.strip().lower() in _GENERIC


def match(cname, body):
    """Return the matching service dict (with match reasons) or None.
    Primary signal is the CNAME hitting a known provider pattern; the body signature confirms (raising confidence)
    or, on its own, is a weaker lead. A BODY-ONLY match is only trusted for a DISTINCTIVE signature - generic
    stock-404 phrases (which appear on countless unrelated pages) must not produce a body-only match."""
    cname_l = (cname or "").lower()
    body_l = (body or "").lower()
    for svc in SERVICES:
        cname_hit = any(re.search(p, cname_l) for p in svc["cname"])
        matched_sigs = [sig for sig in svc["body_sig"] if sig.lower() in body_l] if body_l else []
        body_hit = bool(matched_sigs)
        # body-only leads must rest on a distinctive signature, never a generic stock-404 string
        if body_hit and not cname_hit:
            if all(_is_generic(sig) for sig in matched_sigs):
                continue
        if cname_hit or body_hit:
            confidence = "high" if (cname_hit and body_hit) else ("cname-only" if cname_hit else "body-only")
            out = dict(svc)
            out["confidence"] = confidence
            return out
    return None


def selftest():
    cases = [
        ("old-bucket.s3.amazonaws.com", "<Error><Code>NoSuchBucket</Code></Error>", "AWS/S3", "high", "yes"),
        ("target.github.io", "There isn't a GitHub Pages site here.", "GitHub Pages", "high", "yes"),
        ("app.herokuapp.com", "No such app", "Heroku", "high", "edge"),
        ("x.fastly.net", "Fastly error: unknown domain", "Fastly", "high", "edge"),
        ("shop.myshopify.com", "Sorry, this shop is currently unavailable.", "Shopify", "high", "edge"),
        ("d123.cloudfront.net", "ERROR: The request could not be satisfied", "AWS/CloudFront", "high", "no"),
        ("x.s3.amazonaws.com", "", "AWS/S3", "cname-only", "yes"),  # no body -> weaker lead
        ("legit.example.com", "totally normal 200 page", None, None, None),  # no match
        # FP guard: an ordinary 404 with an UNMATCHED cname must NOT body-only-match Netlify/Cargo/Unbounce
        ("app.internal.example.com", "<h1>404 Not Found</h1><p>nginx</p>", None, None, None),
        ("shop.corp.example.com", "The requested URL was not found on this server.", None, None, None),
        # but a real Netlify dangler (cname hit + its distinctive sig) still matches high
        ("site.netlify.app", "Not Found - Request ID: abc123", "Netlify", "high", "edge"),
    ]
    ok = 0
    for cname, body, exp_svc, exp_conf, exp_claim in cases:
        r = match(cname, body)
        got_svc = r["service"] if r else None
        got_conf = r["confidence"] if r else None
        got_claim = r["claimable"] if r else None
        passed = (got_svc == exp_svc) and (exp_conf is None or got_conf == exp_conf) and \
                 (exp_claim is None or got_claim == exp_claim)
        ok += passed
        flag = "PASS" if passed else "FAIL"
        print(f"[{flag}] {cname:32} -> {got_svc} ({got_conf}, claimable={got_claim})")
    print(f"\n{ok}/{len(cases)} passed")
    return ok == len(cases)


def main():
    ap = argparse.ArgumentParser(description="Subdomain-takeover fingerprint DB + matcher.")
    ap.add_argument("--selftest", action="store_true")
    ap.add_argument("--list", action="store_true", help="print the service DB")
    a = ap.parse_args()
    if a.selftest:
        sys.exit(0 if selftest() else 1)
    if a.list:
        for s in SERVICES:
            print(f"{s['service']:16} claimable={s['claimable']:5} sigs={s['body_sig']}")
        return
    ap.print_help()


if __name__ == "__main__":
    main()
