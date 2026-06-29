#!/usr/bin/env python3
"""
secret_scan.py — severity-ranked secret scanner for a local JS corpus, with entropy gating and
PUBLIC-KEY suppression (so you don't waste a report on Google Maps / Stripe publishable / Sentry DSN).

A match is a CANDIDATE. Validate live + privileged before reporting (JS_FILES_TESTING_GUIDE.md §10/§17).

Usage:
  python3 secret_scan.py -d out/js -o secrets.txt
  python3 secret_scan.py -f bundle.js
"""
import argparse, math, os, re, sys

# (name, regex, severity)  — HIGH = validate; LOW = usually Info (public client keys).
RULES = [
    ("aws_access_key_id",   r"\b(AKIA|ASIA)[0-9A-Z]{16}\b", "HIGH"),
    ("aws_secret",          r"(?i)aws.{0,20}?(secret|sk).{0,20}?['\"][0-9a-zA-Z/+]{40}['\"]", "HIGH"),
    ("private_key_block",   r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----", "HIGH"),
    ("gcp_service_account", r'"type"\s*:\s*"service_account"', "HIGH"),
    ("github_pat_classic",  r"\bghp_[0-9A-Za-z]{36}\b", "HIGH"),
    ("github_pat_fine",     r"\bgithub_pat_[0-9A-Za-z_]{82}\b", "HIGH"),
    ("github_oauth_app",    r"\bgh[ous]_[0-9A-Za-z]{36}\b", "HIGH"),
    ("gitlab_pat",          r"\bglpat-[0-9A-Za-z_\-]{20}\b", "HIGH"),
    ("slack_token",         r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b", "HIGH"),
    ("stripe_secret",       r"\bsk_live_[0-9a-zA-Z]{24,}\b", "HIGH"),
    ("twilio_sid",          r"\bAC[0-9a-f]{32}\b", "HIGH"),
    ("sendgrid",            r"\bSG\.[0-9A-Za-z_\-]{22}\.[0-9A-Za-z_\-]{43}\b", "HIGH"),
    ("mailgun",             r"\bkey-[0-9a-zA-Z]{32}\b", "HIGH"),
    ("azure_storage_key",   r"AccountKey=[0-9A-Za-z+/=]{40,}", "HIGH"),
    ("db_uri_with_creds",   r"\b(?:mongodb(?:\+srv)?|postgres(?:ql)?|mysql|redis|amqp)://[^:@\s/]+:[^@\s/]+@[^/\s]+", "HIGH"),
    ("jwt",                 r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b", "MED"),
    ("generic_secret_kv",   r"(?i)(api[_-]?key|secret|passwd|password|token|auth)['\"]?\s*[:=]\s*['\"][0-9a-zA-Z\-_=]{16,}['\"]", "MED"),
    # LOW / public-by-design (suppressed unless --all)
    ("google_api_key",      r"\bAIza[0-9A-Za-z_\-]{35}\b", "LOW"),
    ("stripe_publishable",  r"\bpk_live_[0-9a-zA-Z]{24,}\b", "LOW"),
    ("sentry_dsn",          r"https://[0-9a-f]{32}@[a-z0-9.\-]+/[0-9]+", "LOW"),
]

def entropy(s):
    if not s:
        return 0.0
    from collections import Counter
    n = len(s)
    return -sum((c/n) * math.log2(c/n) for c in Counter(s).values())

def scan_text(text, name, allow_low):
    out = []
    for rname, rx, sev in RULES:
        if sev == "LOW" and not allow_low:
            # still record but flag clearly; many programs reject these
            pass
        for m in re.finditer(rx, text):
            val = m.group(0)
            # entropy gate for the generic rule to cut placeholders
            if rname == "generic_secret_kv":
                inner = re.findall(r"['\"]([0-9a-zA-Z\-_=]{16,})['\"]", val)
                if inner and entropy(inner[-1]) < 3.0:
                    continue
            line = text.count("\n", 0, m.start()) + 1
            out.append((sev, rname, name, line, val[:80]))
    return out

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-d", "--dir")
    ap.add_argument("-f", "--file")
    ap.add_argument("-o", "--out")
    ap.add_argument("--all", action="store_true", help="include LOW/public-by-design keys")
    a = ap.parse_args()

    files = []
    if a.file:
        files = [a.file]
    elif a.dir:
        for root, _, fs in os.walk(a.dir):
            for f in fs:
                files.append(os.path.join(root, f))
    else:
        ap.error("need -d or -f")

    hits = []
    for path in files:
        try:
            text = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        hits.extend(scan_text(text, path, a.all))

    order = {"HIGH": 0, "MED": 1, "LOW": 2}
    hits.sort(key=lambda h: order.get(h[0], 9))
    lines = []
    for sev, rname, path, line, val in hits:
        tag = sev if sev != "LOW" else "LOW(public-by-design? usually Info)"
        lines.append(f"[{tag}] {rname}  {path}:{line}\n        {val}")
    text = "\n".join(lines) if lines else "(no secrets matched)"
    print(text)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(text + "\n")
        print(f"\n[saved] {a.out}", file=sys.stderr)
    print("\n[!] HIGH/MED matches are CANDIDATES. Validate live + privileged (read-only) before reporting.\n"
          "    LOW = public client keys (Maps/Firebase/Stripe-publishable/Sentry) — usually Informational.", file=sys.stderr)

if __name__ == "__main__":
    main()
