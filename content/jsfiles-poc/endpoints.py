#!/usr/bin/env python3
"""
endpoints.py — extract API endpoints, paths, parameters and hidden-surface hints from a JS corpus.
Handles plain strings AND template literals (`${base}/api/...`). Discovery aid for IDOR/authz/SSRF/injection
targeting (JS_FILES_TESTING_GUIDE.md §6/§7/§14).

Usage:
  python3 endpoints.py -d out/js -o endpoints.txt
"""
import argparse, os, re, sys

URL_RX   = re.compile(r"""(?:https?:)?//[a-zA-Z0-9_.~%-]+(?:/[a-zA-Z0-9_.~%/?=&{}$-]*)?""")
PATH_RX  = re.compile(r"""['"`](/(?:api|v\d+|internal|admin|graphql|rest|auth|user|account)[a-zA-Z0-9_./{}$:-]*)['"`]""")
ANYPATH  = re.compile(r"""['"`](/[a-zA-Z0-9_]{1,}(?:/[a-zA-Z0-9_.{}$:-]+){1,})['"`]""")
PARAM_RX = re.compile(r"""[?&]([a-zA-Z0-9_]{2,})=""")
GQL_RX   = re.compile(r"""\b(query|mutation)\s+([A-Za-z0-9_]+)""")
HIDDEN_RX = re.compile(r"""(role\s*===?\s*['"]admin['"]|isAdmin|hasPermission|featureFlag|/(?:admin|internal|debug|impersonate|sudo))""", re.I)
VERB_RX  = re.compile(r"""\b(method\s*:\s*['"](GET|POST|PUT|PATCH|DELETE)['"]|\.(get|post|put|patch|delete)\s*\()""", re.I)

def walk(d):
    for root, _, fs in os.walk(d):
        for f in fs:
            yield os.path.join(root, f)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-d", "--dir", required=True)
    ap.add_argument("-o", "--out")
    a = ap.parse_args()

    urls, paths, params, gql, hidden = set(), set(), set(), set(), set()
    for path in walk(a.dir):
        try:
            t = open(path, encoding="utf-8", errors="ignore").read()
        except Exception:
            continue
        for m in URL_RX.findall(t):
            if len(m) > 6:
                urls.add(m)
        for m in PATH_RX.findall(t):
            paths.add(m)
        for m in ANYPATH.findall(t):
            if re.search(r"/(api|v\d|admin|internal|user|account|auth|graphql|rest)", m, re.I):
                paths.add(m)
        for m in PARAM_RX.findall(t):
            params.add(m)
        for kind, name in GQL_RX.findall(t):
            gql.add(f"{kind} {name}")
        for line in t.splitlines():
            if HIDDEN_RX.search(line):
                hidden.add(line.strip()[:160])

    def block(title, items):
        items = sorted(items)
        return f"\n===== {title} ({len(items)}) =====\n" + "\n".join(items)

    report = ""
    report += block("API PATHS (IDOR/authz/SSRF/injection targets §14)", paths)
    report += block("ABSOLUTE URLs / hosts", urls)
    report += block("PARAMETERS (fuzz across XSS/SQLi/SSRF/LFI kits)", params)
    report += block("GRAPHQL OPERATIONS", gql)
    report += block("HIDDEN-SURFACE HINTS (roles/flags/admin §7)", hidden)

    print(report)
    if a.out:
        open(a.out, "w", encoding="utf-8").write(report + "\n")
        print(f"\n[saved] {a.out}", file=sys.stderr)
    print("\n[!] Endpoints are RECON. The finding is an endpoint that yields IDOR/authz/SSRF/injection (§14).", file=sys.stderr)

if __name__ == "__main__":
    main()
