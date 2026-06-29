#!/usr/bin/env python3
"""
cors_scan.py — authorized CORS-misconfiguration prober.

For each URL it fires a battery of Origin values and reports which produce a
DANGEROUS combination: an attacker-controlled origin (or null) reflected into
Access-Control-Allow-Origin TOGETHER WITH Access-Control-Allow-Credentials: true.

This is a DISCOVERY aid only. A hit is a *candidate* — you still must:
  1) confirm the response body holds a real secret, and
  2) prove the credentialed read in a real browser with your OWN test accounts.
(See CORS_TESTING_GUIDE.md §11/§16/§20.)

Authorized testing only. Usage:
  python3 cors_scan.py -u https://api.target.com/api/me
  python3 cors_scan.py -l live_urls.txt -o cors_hits.txt
"""
import argparse, concurrent.futures as cf, sys, urllib.parse as up
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"


def origins_for(url):
    """Build origin probes; some are derived from the target host."""
    host = up.urlparse(url).netloc.split(":")[0]
    reg = ".".join(host.split(".")[-2:]) if host.count(".") >= 1 else host  # registrable-ish
    return [
        ("reflect-any", "https://evil-cors-test.example"),
        ("null", "null"),
        ("suffix", f"https://not{reg}"),
        ("suffix2", f"https://evil{reg}"),
        ("prefix-dot", f"https://{reg}.evil-cors-test.example"),
        ("contains", f"https://{reg}-evil.example"),
        ("backtick", f"https://{reg}%60.evil-cors-test.example"),
        ("subdomain", f"https://sub.{reg}"),
        ("http-downgrade", f"http://{reg}"),
    ]


def probe(url, label, origin, timeout):
    try:
        r = requests.get(url, headers={"Origin": origin, "User-Agent": UA},
                         timeout=timeout, verify=False, allow_redirects=False)
    except Exception as e:
        return None
    acao = r.headers.get("Access-Control-Allow-Origin")
    acac = (r.headers.get("Access-Control-Allow-Credentials") or "").lower() == "true"
    if not acao:
        return None
    # Dangerous = our attacker origin (or null) is reflected/allowed.
    reflected = acao == origin or (origin == "null" and acao == "null")
    wildcard = acao == "*"
    sev = "INFO"
    note = ""
    if reflected and acac:
        sev, note = "HIGH", "attacker origin reflected + credentials -> credentialed cross-origin read"
    elif reflected and not acac:
        sev, note = "LOW", "reflected, NO credentials (only matters if data is sensitive & auth-less)"
    elif wildcard and not acac:
        sev, note = "INFO", "wildcard, no creds (Info unless sensitive no-auth data)"
    elif wildcard and acac:
        sev, note = "INFO", "*+credentials -> browser ignores for creds (not exploitable)"
    else:
        return None
    return (sev, label, origin, acao, acac, note)


def scan(url, timeout):
    out = []
    for label, origin in origins_for(url):
        res = probe(url, label, origin, timeout)
        if res:
            out.append((url,) + res)
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url")
    ap.add_argument("-l", "--list")
    ap.add_argument("-o", "--out")
    ap.add_argument("-t", "--threads", type=int, default=20)
    ap.add_argument("--timeout", type=float, default=10)
    a = ap.parse_args()

    urls = []
    if a.url:
        urls = [a.url.strip()]
    elif a.list:
        urls = [x.strip() for x in open(a.list, encoding="utf-8", errors="ignore") if x.strip()]
    else:
        ap.error("need -u or -l")

    hits = []
    with cf.ThreadPoolExecutor(max_workers=a.threads) as ex:
        for res in ex.map(lambda u: scan(u, a.timeout), urls):
            hits.extend(res)

    order = {"HIGH": 0, "LOW": 1, "INFO": 2}
    hits.sort(key=lambda h: order.get(h[1], 9))
    lines = []
    for url, sev, label, origin, acao, acac, note in hits:
        lines.append(f"[{sev}] {url}\n        probe={label} origin={origin}\n"
                     f"        ACAO={acao} ACAC={acac}\n        -> {note}")
    text = "\n".join(lines) if lines else "(no CORS reflections found)"
    print(text)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(text + "\n")
        print(f"\n[saved] {a.out}", file=sys.stderr)
    print(f"\n[!] HIGH hits are CANDIDATES — confirm a real secret in the body and prove the "
          f"credentialed browser read with your OWN accounts before reporting.", file=sys.stderr)


if __name__ == "__main__":
    main()
