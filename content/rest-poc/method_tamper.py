#!/usr/bin/env python3
"""
method_tamper.py — authorized HTTP verb / method-override tester (BFLA/API5 + §15).

The UI shows one method; the API may allow more. DEFAULT (safe) mode: OPTIONS + baseline GET, and it flags any
state-changing verb OPTIONS advertises as a verb-tamper LEAD — nothing is mutated. With --allow-destructive it
actively sends POST/PUT/PATCH/DELETE + method-override tricks (X-HTTP-Method-Override, X-Method-Override, _method=)
that bypass edge rules blocking real DELETE/PUT. Run as a LOW-priv (or no) token against an endpoint that should be
read-only / admin-only for you.

Discipline: PUT/POST can modify/replace an object even with an empty body, so mutating verbs are gated. A non-4xx on
a state-changing verb is a LEAD — CONFIRM the action took effect (re-GET). Use --allow-destructive only against an
object YOU own; never fire DELETE/PUT at other users' real objects.

Usage:
  python3 method_tamper.py -u https://api.target.com/api/v1/orders/1002 --token "Bearer <LOW>"        # safe: OPTIONS leads
  python3 method_tamper.py -u https://api.target.com/api/v1/users/<own-test-obj> --token "Bearer <LOW>" --allow-destructive
"""
import argparse, sys
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"


def send(method, url, token, extra_headers=None, timeout=20):
    h = {"User-Agent": UA, "Accept": "application/json"}
    if token:
        h["Authorization"] = token
    if extra_headers:
        h.update(extra_headers)
    try:
        r = requests.request(method, url, headers=h, timeout=timeout, verify=False, allow_redirects=False)
        return r.status_code, len(r.text)
    except Exception as e:
        return None, str(e)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True)
    ap.add_argument("--token", help='e.g. "Bearer <LOW>" (or omit for no-token)')
    ap.add_argument("--allow-destructive", action="store_true",
                    help="actually send PUT/PATCH/DELETE/POST (use only against YOUR OWN test object)")
    ap.add_argument("--timeout", type=float, default=20)
    a = ap.parse_args()

    # 1) OPTIONS -> Allow: (the SAFE way to spot verb-tamper leads — nothing is mutated)
    allowed = set()
    try:
        opt = requests.options(a.url, headers={"User-Agent": UA, **({"Authorization": a.token} if a.token else {})},
                               timeout=a.timeout, verify=False)
        raw = opt.headers.get("Allow") or opt.headers.get("access-control-allow-methods") or ""
        allowed = {m.strip().upper() for m in raw.split(",") if m.strip()}
        print(f"[*] OPTIONS Allow: {raw or '(none)'}\n")
    except Exception as e:
        print(f"[*] OPTIONS failed: {e}\n")

    # 2) baseline GET (safe)
    sc, ln = send("GET", a.url, a.token, timeout=a.timeout)
    print(f"  GET (baseline)              -> {sc} ({ln})")

    # 3) SAFE verb-tamper LEADS from OPTIONS (nothing sent) — a state-changing verb the UI never uses = a lead
    leads = [m for m in ("POST", "PUT", "PATCH", "DELETE") if m in allowed]
    if leads:
        print(f"  [LEAD] OPTIONS advertises state-changing verb(s): {', '.join(leads)} "
              "— confirm authz with --allow-destructive on an object YOU own <===")

    # 4) ACTIVE verb + override sweep — mutating, so gated behind --allow-destructive (own object only)
    if not a.allow_destructive:
        print("\n[*] state-changing verbs NOT sent (safe mode). PUT/POST can modify/replace an object even with an "
              "empty body, so they are gated.\n    Re-run with --allow-destructive against an object YOU own to "
              "actively test POST/PUT/PATCH/DELETE + method-override.")
        return

    print("\n[*] ACTIVE verb sweep (--allow-destructive; own object only):")
    for m in ("POST", "PUT", "PATCH", "DELETE"):
        sc, ln = send(m, a.url, a.token, timeout=a.timeout)
        flag = "  [ALLOWED? confirm effect] <===" if sc and sc < 400 else ""
        print(f"  {m:6}                      -> {sc} ({ln}){flag}")

    print("\n[*] method-override (POST + override header/param, bypasses edge rules blocking real DELETE/PUT):")
    for hk, hv in [("X-HTTP-Method-Override", "DELETE"), ("X-HTTP-Method", "DELETE"),
                   ("X-Method-Override", "DELETE"), ("X-HTTP-Method-Override", "PUT")]:
        sc, ln = send("POST", a.url, a.token, {hk: hv}, a.timeout)
        flag = "  [OVERRIDE WORKED? confirm] <===" if sc and sc < 400 else ""
        print(f"  POST {hk}: {hv:6} -> {sc} ({ln}){flag}")
    sep = "&" if "?" in a.url else "?"
    sc, ln = send("POST", a.url + sep + "_method=DELETE", a.token, timeout=a.timeout)
    print(f"  POST ?_method=DELETE        -> {sc} ({ln})")

    print("\n[!] A state-changing verb/override that returns <400 is a LEAD — CONFIRM the object actually changed "
          "(re-GET). Own object for destructive proofs; never target others' real data (§9/§20).")


if __name__ == "__main__":
    main()
