#!/usr/bin/env python3
"""
api_discover.py — authorized API surface discovery (§1).

Finds the machine-readable spec (OpenAPI/Swagger/Postman), probes common API paths, and — for a given endpoint —
enumerates allowed HTTP methods (OPTIONS Allow: + verb sweep) and version paths (v1/v2/v3/beta/internal). A found spec
is the jackpot: import it into Burp/Postman for the full test matrix.

Discipline: passive-ish discovery; add auth with --token if the API needs it. Authorized targets only; pace it.

Usage:
  python3 api_discover.py -u https://api.target.com
  python3 api_discover.py -u https://api.target.com --token "Bearer <A>" --endpoint /api/v1/users/1
"""
import argparse, sys
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"

SPECS = ["openapi.json", "openapi.yaml", "swagger.json", "swagger/v1/swagger.json", "v2/api-docs", "v3/api-docs",
         "api-docs", "swagger-ui.html", "swagger/", "redoc", "docs", "api/docs", ".well-known/openapi",
         "api/swagger.json", "postman", "api/schema/"]
COMMON = ["api", "api/v1", "api/v2", "api/v3", "api/users", "api/v1/users", "api/health", "api/status",
          "actuator", "actuator/env", "actuator/mappings", "metrics", ".env", ".git/config", "graphql"]
VERSIONS = ["v1", "v2", "v3", "beta", "internal", "api/v1", "api/v2", "api/v3", "api/beta", "api/internal"]


def head(url, token, timeout=15, method="GET"):
    h = {"User-Agent": UA, "Accept": "application/json,*/*"}
    if token:
        h["Authorization"] = token
    try:
        r = requests.request(method, url, headers=h, timeout=timeout, verify=False, allow_redirects=False)
        return r.status_code, len(r.content), r.headers.get("Content-Type", "")[:30]
    except Exception as e:
        return None, str(e), ""


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True, help="base, e.g. https://api.target.com")
    ap.add_argument("--token", help='e.g. "Bearer <A>"')
    ap.add_argument("--endpoint", help="an endpoint to enumerate methods/versions for, e.g. /api/v1/users/1")
    ap.add_argument("--timeout", type=float, default=15)
    a = ap.parse_args()
    base = a.url.rstrip("/")

    print("[*] SPEC / docs (a 200 JSON/YAML here = the whole API):")
    for p in SPECS:
        sc, ln, ct = head(f"{base}/{p}", a.token, a.timeout)
        hit = "  <-- SPEC?" if sc in range(200, 300) and ("json" in ct or "yaml" in ct or "html" in ct) else ""
        if sc in range(200, 400):
            print(f"   {p:26} {sc} {ln}b {ct}{hit}")

    print("\n[*] common API paths:")
    for p in COMMON:
        sc, ln, ct = head(f"{base}/{p}", a.token, a.timeout)
        if sc in range(200, 500) and sc != 404:
            print(f"   {p:26} {sc} {ln}b {ct}")

    if a.endpoint:
        ep = base + (a.endpoint if a.endpoint.startswith("/") else "/" + a.endpoint)
        print(f"\n[*] method enumeration on {a.endpoint} (SAFE: OPTIONS/GET/HEAD only — no state-changing verbs sent):")
        try:
            opt = requests.options(ep, headers={"User-Agent": UA, **({"Authorization": a.token} if a.token else {})},
                                   timeout=a.timeout, verify=False)
            allow = opt.headers.get("Allow") or opt.headers.get("access-control-allow-methods") or "(none)"
            print(f"   OPTIONS Allow: {allow}")
        except Exception as e:
            print(f"   OPTIONS failed: {e}")
        for m in ["GET", "HEAD"]:                       # non-mutating verbs only — discovery must never delete/modify
            sc, ln, ct = head(ep, a.token, a.timeout, method=m)
            print(f"   {m:7} -> {sc} ({ln}b)")
        print("   (to actively test state-changing verbs on an object YOU own, use method_tamper.py --allow-destructive)")

        print(f"\n[*] version paths for {a.endpoint} (test OLD versions — API9):")
        tail = a.endpoint.split("/", 3)[-1] if a.endpoint.count("/") >= 3 else a.endpoint.lstrip("/")
        for v in VERSIONS:
            sc, ln, ct = head(f"{base}/{v}/{tail}", a.token, a.timeout)
            if sc and sc != 404:
                print(f"   /{v}/{tail}  -> {sc} ({ln}b)")

    print("\n[!] Import any found spec into Burp/Postman. Old versions/hosts (API9) often re-expose fixed bugs. "
          "Authorized only; pace requests.")


if __name__ == "__main__":
    main()
