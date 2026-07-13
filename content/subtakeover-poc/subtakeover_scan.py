#!/usr/bin/env python3
"""
subtakeover_scan.py - dangling-record scanner + fingerprint matcher + claimability ranker.
For each subdomain: resolves CNAME/NS/MX (follows the CNAME chain), probes HTTP for the provider "not found"
signature, matches the fingerprint DB (fingerprints.py), and RANKS candidates by claimability + record type
(NS/MX first). It flags LEADS to verify + claim by hand - it does NOT auto-claim anything.

A fingerprint is a lead, not a finding. Cross-check can-i-take-over-xyz, confirm claimability, then CLAIM the
resource and serve a benign marker (SUBDOMAIN_TAKEOVER_TESTING_GUIDE.md sections 7-8). Authorized testing only.

Usage:
  python3 subtakeover_scan.py -l subs.txt
  python3 subtakeover_scan.py -d shop.target.com
  python3 subtakeover_scan.py --selftest       # offline logic test (no network/DNS)

DNS uses dnspython if installed, else falls back to the system `dig`/`nslookup`. HTTP uses requests.
"""
import argparse, sys, subprocess, shutil

# cp1252-safe console on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

try:
    from fingerprints import match as fp_match, SERVICES  # noqa
except Exception:
    sys.exit("fingerprints.py must be in the same folder.")

# optional deps (degrade gracefully so --selftest works offline)
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except Exception:
    requests = None

try:
    import dns.resolver  # dnspython
except Exception:
    dns = None


# ---------------- DNS ----------------
def _dig(name, rtype):
    """Fallback DNS via the system dig; returns list of answer strings."""
    exe = shutil.which("dig")
    if exe:
        try:
            out = subprocess.run([exe, "+short", rtype, name], capture_output=True, text=True, timeout=10)
            return [l.strip().rstrip(".") for l in out.stdout.splitlines() if l.strip()]
        except Exception:
            return []
    exe = shutil.which("nslookup")
    if exe:
        try:
            out = subprocess.run([exe, "-type=" + rtype, name], capture_output=True, text=True, timeout=10)
            return [l for l in out.stdout.splitlines() if l.strip()]
        except Exception:
            return []
    return []


def resolve(name, rtype):
    if dns is not None:
        try:
            ans = dns.resolver.resolve(name, rtype, raise_on_no_answer=False)
            vals = []
            for r in ans:
                s = r.to_text().rstrip(".")
                # MX records: "10 mail.host" -> keep host
                if rtype == "MX":
                    s = s.split()[-1].rstrip(".")
                vals.append(s)
            return vals
        except Exception:
            return []
    return _dig(name, rtype)


def cname_chain(name, depth=6):
    """Follow CNAME hops to the tail; return (chain_list, tail)."""
    chain = []
    cur = name
    for _ in range(depth):
        cn = resolve(cur, "CNAME")
        if not cn:
            break
        nxt = cn[0]
        chain.append(nxt)
        cur = nxt
    return chain, (chain[-1] if chain else None)


# ---------------- HTTP ----------------
def http_body(host, timeout=10):
    if requests is None:
        return None
    for scheme in ("https", "http"):
        try:
            r = requests.get(f"{scheme}://{host}/", timeout=timeout, verify=False,
                             headers={"User-Agent": "subtakeover-scan (authorized)"} , allow_redirects=True)
            return r.text or ""
        except Exception:
            continue
    return None


# ---------------- ranking ----------------
def priority(rec):
    """Higher = more urgent. NS/MX + claimable=yes rank top."""
    p = 0
    if rec["record"] == "NS":
        p += 100
    elif rec["record"] == "MX":
        p += 90
    elif rec["record"] == "CNAME":
        p += 40
    claim = (rec.get("claimable") or "")
    p += {"yes": 30, "edge": 15, "no": -50}.get(claim, 0)
    if rec.get("confidence") == "high":
        p += 20
    elif rec.get("confidence") == "cname-only":
        p += 5
    return p


def scan_one(name, timeout=10):
    results = []

    # NS / MX danglers (high-impact) - report if present + point off to a non-target/expired zone (manual verify)
    ns = resolve(name, "NS")
    if ns:
        results.append({"sub": name, "record": "NS", "target": ", ".join(ns),
                        "service": "(delegation)", "claimable": "verify", "confidence": "manual",
                        "note": "Check if the nameserver domain is expired/claimable -> full DNS control (CRITICAL)."})
    mx = resolve(name, "MX")
    if mx:
        results.append({"sub": name, "record": "MX", "target": ", ".join(mx),
                        "service": "(mail)", "claimable": "verify", "confidence": "manual",
                        "note": "Check if the mail host is claimable -> email interception -> reset ATO (CRITICAL)."})

    # CNAME chain + fingerprint
    chain, tail = cname_chain(name)
    if tail:
        body = http_body(name, timeout)
        m = fp_match(tail, body or "")
        if m:
            results.append({"sub": name, "record": "CNAME", "target": tail,
                            "service": m["service"], "claimable": m["claimable"],
                            "confidence": m["confidence"], "note": m["note"]})
        else:
            # CNAME to something, but no known-service match - still worth a manual look if it 404s
            results.append({"sub": name, "record": "CNAME", "target": tail,
                            "service": "(unmatched)", "claimable": "unknown", "confidence": "low",
                            "note": "CNAME present but no known-service fingerprint - manual check."})
    return results


def print_row(r):
    tag = {"yes": "CLAIMABLE", "edge": "edge", "no": "NOT-claimable", "verify": "VERIFY",
           "unknown": "unknown"}.get(r.get("claimable"), r.get("claimable"))
    print(f"  [{r['record']:5}] {r['sub']}")
    print(f"          -> {r['target']}  ({r['service']}, {tag}, confidence={r['confidence']})")
    print(f"          {r['note']}")


def selftest():
    """Offline test of the fingerprint + ranking logic (no network)."""
    fake = [
        {"sub": "a.t.com", "record": "CNAME", "service": "AWS/S3", "claimable": "yes", "confidence": "high"},
        {"sub": "b.t.com", "record": "NS", "service": "(delegation)", "claimable": "verify", "confidence": "manual"},
        {"sub": "c.t.com", "record": "CNAME", "service": "AWS/CloudFront", "claimable": "no", "confidence": "high"},
        {"sub": "d.t.com", "record": "MX", "service": "(mail)", "claimable": "verify", "confidence": "manual"},
    ]
    ranked = sorted(fake, key=priority, reverse=True)
    order = [r["sub"] for r in ranked]
    # expect NS (b) and MX (d) on top, CloudFront (c, not claimable) last
    ok = order[0] in ("b.t.com", "d.t.com") and order[-1] == "c.t.com"
    print("ranking order:", order)
    # fingerprint matcher spot-checks
    m1 = fp_match("x.s3.amazonaws.com", "NoSuchBucket")
    m2 = fp_match("x.cloudfront.net", "The request could not be satisfied")
    ok = ok and m1 and m1["claimable"] == "yes" and m2 and m2["claimable"] == "no"
    print("s3 match:", m1["service"] if m1 else None, "| cloudfront claimable:", m2["claimable"] if m2 else None)
    print("SELFTEST:", "PASS" if ok else "FAIL")
    return ok


def main():
    ap = argparse.ArgumentParser(description="Dangling-record scanner + fingerprint + claimability ranker.")
    ap.add_argument("-l", "--list", help="file with one subdomain per line")
    ap.add_argument("-d", "--domain", help="a single subdomain")
    ap.add_argument("--timeout", type=float, default=10)
    ap.add_argument("--selftest", action="store_true", help="offline logic test (no network)")
    a = ap.parse_args()

    if a.selftest:
        sys.exit(0 if selftest() else 1)

    subs = []
    if a.domain:
        subs = [a.domain.strip()]
    elif a.list:
        with open(a.list, encoding="utf-8") as f:
            subs = [l.strip() for l in f if l.strip() and not l.startswith("#")]
    else:
        ap.error("provide -d <sub> or -l <file> (or --selftest)")

    if requests is None:
        print("[warn] `requests` not installed - HTTP fingerprinting disabled (DNS-only leads).")
    if dns is None and not shutil.which("dig") and not shutil.which("nslookup"):
        print("[warn] no dnspython and no dig/nslookup - DNS resolution unavailable.")

    all_hits = []
    for s in subs:
        for r in scan_one(s, a.timeout):
            all_hits.append(r)

    # rank: NS/MX + claimable first; drop pure NOT-claimable to the bottom
    all_hits.sort(key=priority, reverse=True)

    print(f"\n== subdomain-takeover scan: {len(subs)} host(s), {len(all_hits)} lead(s) ==\n")
    shown = 0
    for r in all_hits:
        if r["service"] == "(unmatched)" and r["confidence"] == "low":
            continue  # keep the summary focused; unmatched CNAMEs are noise unless nothing else
        print_row(r)
        shown += 1
    if shown == 0:
        print("  (no fingerprinted danglers; re-check manually - fingerprints go stale)")

    print("\n[!] Next: cross-check can-i-take-over-xyz, CONFIRM claimability, then CLAIM + serve a benign marker")
    print("    (guide sections 7-8). NS/MX leads are CRITICAL - verify the nameserver/mail host is claimable.")
    print("    A fingerprint is a LEAD, not a finding. Do not report without claiming + a trust chain.")


if __name__ == "__main__":
    main()
