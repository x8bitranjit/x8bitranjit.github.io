#!/usr/bin/env python3
"""
introspect.py — dump a GraphQL schema and print the attack-surface "sink list".

Runs the standard introspection query; if introspection is disabled, says so and points you to
clairvoyance/suggestions (guide §6). When it works, it prints the lists you actually attack:
  - queries / mutations
  - object-lookup sinks (node, *ById, *ByEmail)  -> BOLA (guide §7)
  - input object types                            -> mass assignment (guide §12)
  - arguments that look like URLs/files/filters   -> SSRF / injection (guide §11/§16)

Authorized testing only. Schema mapping is read-only recon — but only against in-scope targets.
"""
import argparse, json, re, sys
try:
    import requests
except ImportError:
    sys.exit("pip install requests")

INTROSPECTION = """
query IntrospectionQuery {
  __schema {
    queryType { name } mutationType { name }
    types { kind name fields { name args { name type { kind name ofType { name } } } }
            inputFields { name } }
  }
}"""

URLISH = re.compile(r"(url|uri|href|link|webhook|callback|endpoint|src|fetch|import|avatar|image|path|file|template)", re.I)
INJECTISH = re.compile(r"(filter|where|query|search|order|sort|id|email|name)", re.I)


def main():
    p = argparse.ArgumentParser(description="GraphQL schema dumper + sink list (authorized testing only).")
    p.add_argument("--url", required=True)
    p.add_argument("--token", help="bearer token (yours)")
    p.add_argument("--out", default="schema.json")
    args = p.parse_args()

    headers = {"Content-Type": "application/json"}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    try:
        r = requests.post(args.url, headers=headers, data=json.dumps({"query": INTROSPECTION}), timeout=25)
        data = r.json()
    except Exception as e:
        sys.exit(f"request failed: {e}")

    schema = (data.get("data") or {}).get("__schema")
    if not schema:
        print("Introspection appears DISABLED (no __schema).")
        errs = data.get("errors")
        if errs:
            print("server said:", errs[0].get("message"))
        print("→ Recover the schema via field suggestions / clairvoyance / graphw00f (guide §6):")
        print("  clairvoyance -o schema.json", args.url)
        return

    with open(args.out, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    print(f"[+] schema saved to {args.out}\n")

    types = schema.get("types", [])
    qname = (schema.get("queryType") or {}).get("name")
    mname = (schema.get("mutationType") or {}).get("name")

    def fields_of(tn):
        for t in types:
            if t.get("name") == tn:
                return t.get("fields") or []
        return []

    print("== QUERIES ==");    [print("  ", f["name"]) for f in fields_of(qname)]
    print("\n== MUTATIONS (BFLA candidates) =="); [print("  ", f["name"]) for f in fields_of(mname)]

    bola, urlargs, injargs, inputs = [], [], [], []
    for t in types:
        if (t.get("name") or "").startswith("__"):
            continue
        if t.get("inputFields"):
            inputs.append(t["name"])
        for fld in (t.get("fields") or []):
            fn = fld["name"]
            if fn == "node" or re.search(r"(ById|ByEmail|ByUuid)$", fn):
                bola.append(f"{t['name']}.{fn}")
            for a in (fld.get("args") or []):
                if URLISH.search(a["name"]):
                    urlargs.append(f"{t['name']}.{fn}({a['name']})")
                elif INJECTISH.search(a["name"]):
                    injargs.append(f"{t['name']}.{fn}({a['name']})")

    def show(title, items, hint):
        print(f"\n== {title} ==  ({hint})")
        for i in items[:60]:
            print("  ", i)
        if not items:
            print("   (none obvious)")

    show("BOLA SINKS (node / *ById)", bola, "guide §7 — two-account test each")
    show("INPUT OBJECTS (mass assignment)", inputs, "guide §12 — try role/isAdmin/owner_id")
    show("URL/FILE ARGS (SSRF / LFI)", urlargs, "guide §16 — point at interactsh / metadata")
    show("FILTER/ID ARGS (injection)", injargs, "guide §11 — SQLi/NoSQLi/cmdi probes")
    print("\nNext: exploit each sink and PROVE per sub-bug (two-account / OOB / measured count).")


if __name__ == "__main__":
    main()
