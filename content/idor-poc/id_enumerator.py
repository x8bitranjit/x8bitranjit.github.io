#!/usr/bin/env python3
"""
id_enumerator.py — POLITE, small-proof-set id prober for IDOR enumeration evidence.

Purpose: demonstrate that an object id is ENUMERABLE (the multiplier that turns a
single read into mass-PII severity) WITHOUT scraping real users. It deliberately:
  - defaults to a TINY count (8) and a LOW rate (3 req/s),
  - reports the status / length / time per id so you can spot the 403-vs-404 oracle,
  - does NOT save response bodies (so you don't accumulate strangers' PII),
  - prints how to cite the POPULATION from server metadata instead of scraping it.

Use this to prove the *pattern* with your own / second-account ids, then state the
scale from X-Total-Count or the max id. See IDOR_TESTING_GUIDE.md §6 / §8.8 / §25.3.

Authorized testing only. Keep the count small. Stop at proof.
"""
import argparse, sys, time
try:
    import requests
except ImportError:
    sys.exit("pip install requests")


def main():
    p = argparse.ArgumentParser(description="Polite id enumeration evidence (authorized testing only).")
    p.add_argument("--url", required=True, help="e.g. https://t/api/users/{id}  ({id} substituted)")
    p.add_argument("--token", required=True, help="your account token/cookie")
    p.add_argument("--scheme", choices=["bearer", "cookie"], default="bearer")
    p.add_argument("--start", type=int, required=True, help="first id to probe")
    p.add_argument("--count", type=int, default=8, help="how many ids (KEEP SMALL; default 8)")
    p.add_argument("--rate", type=float, default=3.0, help="requests/sec (KEEP LOW; default 3)")
    args = p.parse_args()

    if args.count > 50:
        sys.exit("Refusing count > 50. Prove the pattern with a small set and cite the population "
                 "from server metadata instead (guide §6.5/§25.3). Edit the script only if you have "
                 "explicit written authorization for higher volume.")

    headers = {"Cookie": args.token} if args.scheme == "cookie" else {"Authorization": f"Bearer {args.token}"}
    delay = 1.0 / args.rate if args.rate > 0 else 0
    seen = {}
    print(f"== polite id probe: {args.count} ids from {args.start}, {args.rate}/s (bodies NOT saved) ==\n")
    print(f"{'id':>10}  {'code':>4}  {'len':>8}  {'time(s)':>7}")
    for i in range(args.start, args.start + args.count):
        url = args.url.replace("{id}", str(i))
        try:
            r = requests.get(url, headers=headers, timeout=20, allow_redirects=False)
            code, length, t = r.status_code, len(r.content), r.elapsed.total_seconds()
            # capture X-Total-Count style headers for population sizing
            for h in ("X-Total-Count", "x-total-count", "X-Total", "Total-Count"):
                if h in r.headers and "total" not in seen:
                    seen["total"] = r.headers[h]
        except requests.RequestException as e:
            code, length, t = f"ERR", 0, 0.0
            print(f"{i:>10}  {code:>4}  {length:>8}  {t:>7.2f}   ({e})")
            time.sleep(delay); continue
        seen.setdefault(code, 0)
        seen[code] += 1
        print(f"{i:>10}  {code:>4}  {length:>8}  {t:>7.2f}")
        time.sleep(delay)

    print("\n-- summary --")
    codes = {k: v for k, v in seen.items() if isinstance(k, int)}
    print("status distribution:", codes)
    if 200 in codes and (403 in codes or 404 in codes):
        print("-> Mixed 200 / 403-404: likely an ENUMERATION ORACLE — distinct ids return distinct codes.")
    if 200 in codes:
        print("-> 200s across consecutive ids -> the id is ENUMERABLE (mass-read potential, guide §11).")
    if "total" in seen:
        print(f"-> Server reported population: X-Total-Count ~ {seen['total']}  "
              f"(cite THIS for scale; do NOT scrape it).")
    else:
        print("-> For scale, find the MAX id or a pagination 'total' field and cite it — "
              "prove the pattern, don't dump real users (guide §25.3).")


if __name__ == "__main__":
    main()
