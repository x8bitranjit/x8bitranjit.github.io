# JWT — PoC Scripts

Runnable, **benign-by-default** proof-of-concept scripts that back the JWT kit — one per attack. **Click a script
to open it on its own page.** *Authorized testing only:* use your own test accounts, prove with a non-destructive
marker, redact secrets, and never impersonate a real user.

| Script | What it does |
|---|---|
| [`jwt_common.py`](#/jwt/poc/jwt_common) | Shared helpers — base64url encode/decode, header & claim parsing, and HS/RS signing used by the other scripts. |
| [`alg_none.py`](#/jwt/poc/alg_none) | Forge an **`alg:none`** (unsigned) token with custom claims — tests servers that accept unsigned JWTs (all case variants). |
| [`rs256_to_hs256.py`](#/jwt/poc/rs256_to_hs256) | **RS256 → HS256 key confusion** — signs with the RSA *public* key as the HMAC secret (tries PEM/DER + newline variants). |
| [`kid_injection.py`](#/jwt/poc/kid_injection) | **`kid` injection** — path-traversal to a predictable-content key (e.g. `/dev/null` → empty key), then HS-sign. |
| [`jwks_server.py`](#/jwt/poc/jwks_server) | Stands up an attacker **JWKS** (`/jwks.json`) for **`jku` / `x5u`** header-injection. |
| [`jwk_inject.py`](#/jwt/poc/jwk_inject) | **Embedded `jwk` / `x5c`** injection — your public key in the header, signed with your private key (no hosting). |
| [`forge_token.py`](#/jwt/poc/forge_token) | Generic **forge helper** — mint a token with any algorithm + key + claims. |
| [`jwe_dos_token.py`](#/jwt/poc/jwe_dos_token) | **JWE `p2c` DoS** token (PBES2 work-factor bomb) — *only where DoS is in scope*. |

## How they fit together
1. **Decode & map** the target token (header `alg`/`kid`, claims) — start from the **Testing Guide** to pick which attack applies.
2. **Cheap wins first:** `alg:none` and weak-secret/HMAC, then **algorithm confusion** (`rs256_to_hs256.py`) if it's RS256.
3. **Key-injection family:** `jwk_inject.py` (embedded key, no hosting) → `jwks_server.py` (`jku`/`x5u`) → `kid_injection.py` (path/SQLi).
4. **Confirm impact** — a forged token accepted = auth bypass / account takeover / privilege escalation. Track coverage with the **Checklist**.

> Each script defaults to a **benign marker**. Read the **Testing Guide** for the full attack order and the
> **Zero to Expert (Q&A)** for the *why* behind each one.
