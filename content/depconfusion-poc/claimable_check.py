#!/usr/bin/env python3
"""
claimable_check.py - is a package name UNCLAIMED on the public registry? (authorized recon; READ-ONLY).

Read-only GETs against the public registry: 404 = the name is unregistered = a dependency-confusion CANDIDATE (if the
target also uses it privately and its resolver can reach public). Makes NO changes and publishes NOTHING. Low false-
positive: only a clean 404 is 'claimable'. (DEPENDENCY_CONFUSION_TESTING_GUIDE.md §4.)

Usage:
  python3 claimable_check.py --ecosystem npm --file names.txt
  python3 claimable_check.py --ecosystem pypi --names requests,acme-internal-utils
  manifest_scan.py -f package.json | grep '  @' | python3 claimable_check.py --ecosystem npm
"""
import sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
except Exception:
    pass
import argparse, time, urllib.parse, urllib.request, urllib.error

DEFAULT_REGISTRY = {"npm": "https://registry.npmjs.org", "pypi": "https://pypi.org"}
UA = "Mozilla/5.0 (compatible; dc-claimable-check/1.0; read-only)"


def name_path(ecosystem, name):
    if ecosystem == "npm":
        # scoped @scope/pkg -> @scope%2Fpkg
        return urllib.parse.quote(name, safe="@")
    return f"pypi/{urllib.parse.quote(name)}/json"


def status(url, timeout):
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except Exception:
        return None


def read_names(a):
    if a.names:
        return [x.strip() for x in a.names.split(",") if x.strip()]
    raw = open(a.file, encoding="utf-8", errors="replace").read() if a.file else sys.stdin.read()
    out = []
    for line in raw.splitlines():
        t = line.strip()
        # tolerate manifest_scan output lines ("  @acme/x") and plain names
        if t.startswith(("==", "[", "//", "#")) or not t:
            continue
        out.append(t)
    return out


def main():
    ap = argparse.ArgumentParser(description="Public-registry claimability check (read-only; authorized recon).")
    ap.add_argument("--ecosystem", choices=["npm", "pypi"], required=True)
    ap.add_argument("--file", help="names, one per line (default: stdin)")
    ap.add_argument("--names", help="comma-separated names")
    ap.add_argument("--registry", help="override registry base URL (for a lab/mirror)")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between lookups (be gentle)")
    ap.add_argument("--timeout", type=float, default=15.0)
    a = ap.parse_args()

    base = (a.registry or DEFAULT_REGISTRY[a.ecosystem]).rstrip("/")
    names = read_names(a)
    if not names:
        sys.exit("[!] no names given (use --file/--names/stdin).")

    print(f"== claimability check ==  ({a.ecosystem}, {base})   [read-only]")
    claimable = []
    for n in names:
        code = status(f"{base}/{name_path(a.ecosystem, n)}", a.timeout)
        if code == 404:
            claimable.append(n)
            print(f"  [CLAIMABLE] {n}   (public 404 - unregistered)")
        elif code == 200:
            print(f"  [taken]     {n}   (200 - already public)")
        elif code is None:
            print(f"  [err]       {n}   (request failed)")
        else:
            print(f"  [?]         {n}   (HTTP {code})")
        if a.delay:
            time.sleep(a.delay)

    print()
    if claimable:
        print(f"[+] {len(claimable)} CLAIMABLE name(s): {', '.join(claimable)}")
        print("    If the target uses these PRIVATELY and its resolver can reach public -> dependency-confusion candidates.")
        print("    Confirm resolution (guide §6); prove ONLY authorized names with a BENIGN beacon, then UNPUBLISH (§7-§8/§16).")
    else:
        print("[-] none claimable from this list (all taken/errored). Try more internal names, other ecosystems, or repo-jacking (§10).")
    return 0


if __name__ == "__main__":
    sys.exit(main())
