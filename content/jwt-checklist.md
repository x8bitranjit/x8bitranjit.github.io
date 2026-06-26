# JWT Testing Checklist — Per-Token, In Testing Order

> Tick this per token/endpoint. Mirrors the Master Testing Sequence in `JWT_TESTING_GUIDE.md`. The point is **coverage** (don't miss the reset-link JWT) and **escalation** (don't stop at "it uses HS256" — forge a token the server accepts and act on it). `§` = section in the main guide.

**Target:** ____________________  **Program/scope:** ____________________  **Date:** ____________
**Token location:** cookie [ ] Bearer [ ] URL [ ] body [ ] reset/verify link [ ]  **alg:** ________  **kid:** ________
**Key headers:** jku[ ] x5u[ ] jwk[ ] x5c[ ]  **JWKS URL:** _______________________
**Claims:** sub____ role/scope____ aud____ iss____ exp____ jti____ tenant____

---

## PHASE 0 — Auth & Lab (§1)
- [ ] Confirmed the asset + auth bypass testing are **in scope** (forging tokens is active testing).
- [ ] jwt_tool installed; Burp **JWT Editor** extension installed; hashcat/john ready.
- [ ] Python env: `pyjwt cryptography jwcrypto`. `poc/` scripts present.
- [ ] **Attacker-controlled HTTPS host** ready for jku/x5u (poc/jwks_server.py + ngrok, or Collaborator).
- [ ] **2+ test accounts** (low-priv + second user / a test admin) for cross-user/priv-esc proof.

## PHASE 1 — Recon & Decode (§4)
- [ ] Found **every** token: session cookie, Authorization header, URL/fragment, JSON body, OAuth id/access, **email reset/verify/magic-login links**.
- [ ] Decoded each header + payload; recorded **alg, kid, jku/x5u/jwk/x5c, all claims, where-used**.
- [ ] Pulled JWKS / public key: `/.well-known/jwks.json`, `/.well-known/openid-configuration`.
- [ ] Noted library/issuer hints (typ, errors) for CVE matching.

## PHASE 2 — Baseline: is the signature verified? (§5) — DO FIRST
- [ ] Tampered a claim, **kept** the signature → accepted? (= no verification → Critical)
- [ ] Stripped signature (`header.payload.`) → accepted?
- [ ] Garbage signature → accepted?
- [ ] **Confirmed the tampered claim changed BEHAVIOR** (admin/other-user data), not just "accepted" (§5.2).
- [ ] Tested against an endpoint that actually **uses the token for authz** (returns my data).

## PHASE 3 — Signature / Key Attacks (§6–§14) — forge an accepted token
- [ ] **alg:none** (none/None/NONE/nOnE, empty sig) (§6)
- [ ] **Crack HS256** offline (hashcat -m 16500; default secrets first) → re-sign (§7)
- [ ] **RS256→HS256** confusion (HMAC-sign with public-key PEM; try newline/DER variants) (§8)
- [ ] **Recover RSA pubkey** from 2 tokens if no JWKS (rsa_sign2n) (§9)
- [ ] **kid injection**: `../dev/null` empty key; SQLi; command-injection/LFI (§10)
- [ ] **jku/x5u**: point at my JWKS; confirm SSRF callback; try allow-list bypasses (§11)
- [ ] **jwk** embedded key (easy, no hosting) (§12)
- [ ] **x5c** self-signed cert (§13)
- [ ] **ES256** psychic signature on Java (r=s=0) (§14)
- [ ] ✅ Produced a **forged token the server accepted** on an authz request — or confirmed none work.

## PHASE 4 — Claim / Lifecycle (§15–§21)
- [ ] **sub / user_id** swap → another user (§15/§24)
- [ ] **role / isAdmin / scope / groups** bump → admin/staff (§15/§25)
- [ ] **tenant / org** swap → cross-tenant (§26)
- [ ] **email / email_verified** tamper (OAuth ATO) (§15/§27)
- [ ] **aud / iss** confusion; replay a token from another service/env/client (§16)
- [ ] **OIDC id_token (§16.1)**: aud-as-array / azp unchecked · **nonce replay** · at_hash/c_hash substitution · id_token-as-access_token · (iss,sub) identity keying
- [ ] **exp** not enforced (replay old token); **no exp**; **nbf** bypass (§17)
- [ ] **Revocation**: token still valid after logout / password change (§17)
- [ ] **Replay**: one-time reset/magic-login JWT reused (no jti) (§17)
- [ ] **Refresh token**: reuse/rotation/reuse-detection failures (§18)
- [ ] **Storage/leakage**: URL/Referer/logs/localStorage; cookie flags (§19)
- [ ] **JWE** (5-part): nested alg:none, padding oracle, weak key (§20)
- [ ] **DoS (§20.1, if in scope)**: PBES2 `p2c` bomb · JWE `zip:DEF` decompression bomb · oversized key/modulus — show one-request ratio
- [ ] **Parser confusion**: duplicate alg/claims, typ/cty, **crit** ignored (smuggle a param / gateway-vs-backend divergence) (§21)

## PHASE 5 — IMPACT ⭐ (§22–§27) — climb as high as the app allows
- [ ] Forged **any/admin** token → auth bypass / ATO, demonstrated (§23)
- [ ] **sub swap** → accessed another user's data (proven not mine) (§24)
- [ ] **role/scope** → reached an admin-only endpoint/UI (§25)
- [ ] **tenant** → read another tenant's data (§26)
- [ ] **Chain**: XSS→token theft / jku→SSRF→metadata / reset-JWT→mass ATO (§27)
- [ ] Stated impact in one sentence: *"An attacker can <forge/abuse> to <ATO/admin/cross-tenant> with <prereqs>."*

## PHASE 6 — Validate → Severity → Report (§28–§33)
- [ ] Passed **false-positive filter** (§29): NOT "decoded a token", NOT "HS256 used", NOT "alg:none in spec", NOT "accepted-but-ignored".
- [ ] Confirmed **behavior change** from the forged/tampered token.
- [ ] Set **CVSS 3.1 vector** + score; mapped CWE (347/345/287/639/918) (§30).
- [ ] Built a **safe** PoC (own accounts; offline crack; reversible) (§32).
- [ ] Captured: original + forged token (decoded) + forge command + accepted request/response.
- [ ] **De-duplicated** (one root cause = one finding); title names the **impact** (§33).
- [ ] Cleaned up any forged-admin sessions / test changes.

---

## Quick "is it worth reporting?" gate
```
Did the server ACCEPT a token I controlled the contents of?   NO → not a forge bug. (Decoding/observing ≠ vuln.)
Did the accepted token CHANGE behavior?                        NO → accepted-but-ignored = false positive (§29.5).
Can the attacker do this with few prerequisites?               (pre-auth/any-user > low-priv acct > captured token)
Did I climb to real impact (ATO/admin/cross-tenant)?           NO → tamper sub/role and demonstrate before submitting.
Confirmed on PRODUCTION keys/endpoint?                          NO → staging-only may be out of scope (§28.3).
```

## Per-token mini-loop
```
decode → baseline(sig verified?) → forge attempt (none/crack/confusion/key-inject)
       → claim tamper (sub/role/aud/tenant) → lifecycle (exp/revoke/replay)
       → ACCEPTED & behavior changed? → ESCALATE to impact → record finding
```
