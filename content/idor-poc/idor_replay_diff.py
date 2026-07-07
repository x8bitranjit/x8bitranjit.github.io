#!/usr/bin/env python3
"""
idor_replay_diff.py — the two-account IDOR oracle (benign, low false-positive).

Proves the ONLY thing that makes an IDOR valid: that account A (attacker) can
read account B's (victim) private object, using A's credentials — where BOTH
accounts are yours. It does this three ways so you don't get fooled:

  1. A requests B's object   (A_TOKEN + B's id)   -> "A's view of B"
  2. B requests B's object   (B_TOKEN + B's id)   -> "B's own view"  (ground truth)
  3. A requests A's object   (A_TOKEN + A's id)   -> proves the server ISN'T
                                                     just session-scoping (control)

Verdict:
  - If (1) succeeds AND (1) matches (2) AND (1) != (3)  -> IDOR CONFIRMED (A sees B's object)
  - If (1) returns A's own data (== 3)                  -> SAFE (session-scoped, not IDOR)
  - If (1) is 403/404                                   -> BLOCKED (try the bypass matrix, guide §8)

Authorized testing only. B must be YOUR second test account. No mass requests.
See IDOR_TESTING_GUIDE.md §4 / §19 / §25.
"""
import argparse, json, sys
try:
    import requests
except ImportError:
    sys.exit("pip install requests")

VOLATILE = {"timestamp", "time", "csrf", "csrf_token", "_token", "nonce",
            "request_id", "trace_id", "served_at", "etag", "last_seen"}


def strip_volatile(obj):
    """Drop fields that legitimately differ between requests, so the diff is meaningful."""
    if isinstance(obj, dict):
        return {k: strip_volatile(v) for k, v in sorted(obj.items()) if k.lower() not in VOLATILE}
    if isinstance(obj, list):
        return [strip_volatile(x) for x in obj]
    return obj


def hdr(token, scheme):
    if not token:
        return {}
    if scheme == "cookie":
        return {"Cookie": token}
    return {"Authorization": f"Bearer {token}"}


def fetch(url, token, scheme, method, body):
    try:
        r = requests.request(method, url, headers={**hdr(token, scheme),
                             **({"Content-Type": "application/json"} if body else {})},
                             data=body, timeout=20, allow_redirects=False)
    except requests.RequestException as e:
        return None, None, str(e)
    try:
        parsed = r.json()
    except ValueError:
        parsed = r.text
    return r.status_code, parsed, None


def main():
    p = argparse.ArgumentParser(description="Two-account IDOR oracle (authorized testing only).")
    p.add_argument("--url", required=True, help="e.g. https://t/api/orders/{id}  ({id} is substituted)")
    p.add_argument("--a-token", required=True, help="attacker account token/cookie (yours)")
    p.add_argument("--b-token", required=True, help="victim account token/cookie (also yours)")
    p.add_argument("--b-id", required=True, help="an object id owned by B (the victim)")
    p.add_argument("--my-id", help="an object id owned by A (the control); optional but recommended")
    p.add_argument("--scheme", choices=["bearer", "cookie"], default="bearer")
    p.add_argument("--method", default="GET")
    p.add_argument("--body", help="request body (for non-GET); use {id} if needed")
    args = p.parse_args()

    def u(i): return args.url.replace("{id}", str(i))
    def b(i): return args.body.replace("{id}", str(i)) if args.body else None

    print("== IDOR two-account oracle ==  (authorized testing only — B is your own account)\n")

    s1, d1, e1 = fetch(u(args.b_id), args.a_token, args.scheme, args.method, b(args.b_id))
    print(f"[1] A's creds + B's id   -> HTTP {s1}{'  ('+e1+')' if e1 else ''}")
    s2, d2, e2 = fetch(u(args.b_id), args.b_token, args.scheme, args.method, b(args.b_id))
    print(f"[2] B's creds + B's id   -> HTTP {s2}   (ground truth: B's own view)")
    s3 = d3 = None
    if args.my_id:
        s3, d3, e3 = fetch(u(args.my_id), args.a_token, args.scheme, args.method, b(args.my_id))
        print(f"[3] A's creds + A's id   -> HTTP {s3}   (control: A's own object)")
    print()

    if s1 in (401, 403, 404):
        print(f"VERDICT: BLOCKED (HTTP {s1}). An ownership check may exist — run the bypass matrix")
        print("         (method/array/pollution/type/path/version/header/wildcard). See guide §8.")
        return

    n1 = json.dumps(strip_volatile(d1), sort_keys=True)
    n2 = json.dumps(strip_volatile(d2), sort_keys=True)
    matches_b = (s1 == 200 and n1 == n2 and isinstance(d1, (dict, list)))
    is_own = False
    if d3 is not None:
        n3 = json.dumps(strip_volatile(d3), sort_keys=True)
        # crude self-check: if A-with-B's-id looks like A's own object, it's session-scoped
        is_own = (n1 == n3)

    if matches_b and not is_own:
        print("VERDICT: IDOR CONFIRMED — A (attacker) received B's (victim) object.")
        print("         A's response == B's own response (minus volatile fields), and != A's own object.")
        print("         -> Escalate: enumerate? auth material in the object? a write verb? (guide §11/§12)")
    elif is_own:
        print("VERDICT: SAFE — the server returned A's OWN object regardless of the id (session-scoped).")
    else:
        print("VERDICT: INCONCLUSIVE — A got HTTP 200 but the body didn't match B's ground truth.")
        print("         Inspect manually; could be partial fields, a different representation, or caching.")


if __name__ == "__main__":
    main()
