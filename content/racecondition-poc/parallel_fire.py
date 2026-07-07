#!/usr/bin/env python3
"""
parallel_fire.py — benign standalone race oracle: control -> N parallel -> measure the invariant.

A small, dependency-light helper for when you can't use Burp. It:
  1) reads the INVARIANT (e.g. wallet balance) BEFORE  (control),
  2) fires N copies of the ACTION as concurrently as asyncio + HTTP/2 allows,
  3) reads the invariant AFTER, and prints the delta.

It is NOT a true single-packet attack (Burp/Turbo are more precise) — it's an async burst over
HTTP/2, good for a quick smell test and for actions with a wider window. If it doesn't trigger,
use Burp "Send group in parallel" / Turbo Intruder (guide §5–§7).

Authorized testing only. YOUR OWN account/balance. Bounded N. No real money out. Revert state.
"""
import argparse, asyncio, json, sys
try:
    import httpx
except ImportError:
    sys.exit('pip install "httpx[http2]"')


def jpath(obj, path):
    """Tiny dotted-path getter, e.g. 'data.balance'. Returns the raw object if path is empty."""
    if not path:
        return obj
    cur = obj
    for part in path.split("."):
        if isinstance(cur, dict) and part in cur:
            cur = cur[part]
        else:
            return None
    return cur


async def read_invariant(client, url, path, headers):
    try:
        r = await client.get(url, headers=headers)
        try:
            return jpath(r.json(), path)
        except Exception:
            return r.text[:200]
    except Exception as e:
        return f"<err {e}>"


async def fire_once(client, url, method, body, headers):
    try:
        r = await client.request(method, url, headers=headers,
                                 content=body.encode() if body else None)
        return r.status_code
    except Exception as e:
        return f"ERR {e}"


async def run(args):
    headers = {}
    if args.token:
        headers["Authorization"] = f"Bearer {args.token}"
    if args.action_body:
        headers["Content-Type"] = "application/json"

    if args.n > 50:
        sys.exit("Refusing N > 50 — bounded bursts only (guide §21). 20–30 is plenty for a real race.")

    async with httpx.AsyncClient(http2=True, verify=True, timeout=20) as client:
        before = await read_invariant(client, args.invariant, args.invariant_jsonpath, headers) \
            if args.invariant else "(no invariant url given)"
        print(f"[control] invariant BEFORE: {before}\n")

        print(f"[burst] firing {args.n} parallel requests at {args.action} ...")
        results = await asyncio.gather(*[
            fire_once(client, args.action, args.method, args.action_body, headers)
            for _ in range(args.n)
        ])
        codes = {}
        for c in results:
            codes[c] = codes.get(c, 0) + 1
        print(f"[burst] status distribution: {codes}\n")

        after = await read_invariant(client, args.invariant, args.invariant_jsonpath, headers) \
            if args.invariant else "(no invariant url given)"
        print(f"[result] invariant AFTER:  {after}")

    print("\n-- interpretation --")
    print("If AFTER changed by MORE than a single action should cause (e.g. balance dropped N×,")
    print("or went negative, or a once-only flag was credited multiple times) -> RACE confirmed.")
    print("Re-run 2-3× (reset state between) to prove reproducibility (guide §15).")
    print("If AFTER == one-action result (or only 1 succeeded), it's locked/idempotent -> not a race,")
    print("or your burst didn't land tight enough — switch to Burp single-packet (guide §5).")


def main():
    p = argparse.ArgumentParser(description="Benign control-vs-parallel race oracle (authorized testing only).")
    p.add_argument("--action", required=True, help="the limited action URL (fired N× in parallel)")
    p.add_argument("--action-body", help="request body for the action (JSON)")
    p.add_argument("--method", default="POST")
    p.add_argument("--invariant", help="URL to read the invariant (e.g. wallet/balance endpoint)")
    p.add_argument("--invariant-jsonpath", default="", help="dotted path in the invariant JSON, e.g. data.balance")
    p.add_argument("--token", help="YOUR account bearer token")
    p.add_argument("-n", type=int, default=20, help="parallel requests (bounded; default 20)")
    args = p.parse_args()
    asyncio.run(run(args))


if __name__ == "__main__":
    main()
