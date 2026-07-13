#!/usr/bin/env python3
"""
claim_proof.py - benign takeover-proof verifier.
After you've CLAIMED the dangling resource in your own provider account and served a unique benign marker,
this fetches https://sub.target.com/<marker-path> and confirms YOUR content is being served (control proven),
and re-checks the CNAME record - the evidence-capture helper for the report.

It does NOT claim anything and does NOT weaponize. It only verifies + prints reproducible evidence. Serve the
marker only long enough to capture proof, then UNPUBLISH the claim and ask the program to remove the DNS record
(SUBDOMAIN_TAKEOVER_TESTING_GUIDE.md section 19). Authorized testing only.

Usage:
  python3 claim_proof.py --sub sub.target.com --marker st-poc-9f3a1 --path /st-poc-9f3a1.txt
  python3 claim_proof.py --sub sub.target.com --marker st-poc-9f3a1     # defaults path to /<marker>.txt
"""
import argparse, sys, subprocess, shutil, datetime

# cp1252-safe console on Windows
try:
    sys.stdout.reconfigure(encoding="utf-8")
except Exception:
    pass

try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except Exception:
    requests = None


def dig_cname(sub):
    exe = shutil.which("dig")
    if exe:
        try:
            out = subprocess.run([exe, "+short", "CNAME", sub], capture_output=True, text=True, timeout=10)
            return out.stdout.strip() or "(none)"
        except Exception:
            return "(dig failed)"
    return "(dig not available)"


def main():
    ap = argparse.ArgumentParser(description="Verify a benign subdomain-takeover proof marker is served.")
    ap.add_argument("--sub", required=True, help="the taken-over subdomain, e.g. sub.target.com")
    ap.add_argument("--marker", required=True, help="the unique marker string you placed in the proof file")
    ap.add_argument("--path", help="path to the proof file (default /<marker>.txt)")
    ap.add_argument("--timeout", type=float, default=12)
    a = ap.parse_args()

    if requests is None:
        sys.exit("pip install requests")

    path = a.path or f"/{a.marker}.txt"
    ts = datetime.datetime.utcnow().strftime("%Y-%m-%d %H:%M:%SZ")

    print("== subdomain-takeover claim proof (authorized PoC) ==")
    print(f"time (UTC):   {ts}")
    print(f"subdomain:    {a.sub}")
    print(f"CNAME record: {dig_cname(a.sub)}")
    print(f"proof URL:    https://{a.sub}{path}\n")

    served = None
    for scheme in ("https", "http"):
        url = f"{scheme}://{a.sub}{path}"
        try:
            r = requests.get(url, timeout=a.timeout, verify=False,
                             headers={"User-Agent": "claim-proof (authorized)"})
        except Exception as e:
            print(f"[..] {scheme}: {e}")
            continue
        body = r.text or ""
        hit = a.marker in body
        print(f"[{'HIT' if hit else '   '}] {scheme} {r.status_code} - marker {'FOUND' if hit else 'not found'} "
              f"({len(body)} bytes)")
        if hit:
            served = url
            snippet = body.strip().splitlines()[0][:120] if body.strip() else ""
            print(f"        served content: {snippet}")
            break

    print()
    if served:
        print("[+] CONFIRMED: your benign marker is served from the target subdomain -> takeover proven.")
        print("    Capture: this output + a screenshot of the URL in a browser + the dig record above.")
        print("    Now: (1) chain the TRUST (cookies/OAuth/CSP/CORS/NS/MX, guide sections 10-13),")
        print("         (2) UNPUBLISH the claim, (3) report + ask them to REMOVE the DNS record.")
        sys.exit(0)
    else:
        print("[-] Marker not served yet. Check: the claim propagated (DNS/CDN cache), the custom-domain binding,")
        print("    the region/namespace, and that the path matches what you uploaded.")
        sys.exit(1)


if __name__ == "__main__":
    main()
