# JSON Web Token (JWT) Attacks — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **attacking JSON Web Tokens** — from "what is a JWT" to forging
> tokens for any user, algorithm confusion, key-header injection, OIDC `id_token` attacks, JWE, parser confusion, DoS,
> and the account-takeover chains they unlock. Q&A format, progressive difficulty. Covers the structure, the trust
> model, every signature/key attack, claim/lifecycle abuse, tooling, methodology, real-world CVEs, **and** defense.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, and learning. **Forge only into your
> own test accounts** (your own `sub` / a test admin you control); crack secrets **offline** on a single captured
> token; demonstrate ATO with **two of your own accounts**; never impersonate or read a real user/tenant. Don't test
> systems you don't have written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- PortSwigger Web Security Academy — *JWT attacks* (+ labs) · `jwt_tool` wiki · Burp **JWT Editor**
- Auth0 — *Critical vulnerabilities in JSON Web Token libraries* · OWASP JWT Cheat Sheet · RFC 7519/7515/7516/7518/7517
- HackTricks — *JWT* · PayloadsAllTheThings — *JSON Web Token* · `wallarm/jwt-secrets`
- CVE-2015-9235 (alg confusion), CVE-2022-21449 (ES256 psychic signature), CVE-2018-0114 (embedded JWK)
- Companion kit in this repo: `Web/JWT/` (guide + arsenal + checklist + report template + `poc/`)

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q12)
- **Level 1 — Recon, decode & baseline** (Q13–Q22)
- **Level 2 — Signature & key attacks** (Q23–Q48)
- **Level 3 — Claim, lifecycle & cross-service** (Q49–Q66)
- **Level 4 — OIDC, JWE, parser confusion & DoS** (Q67–Q82)
- **Level 5 — Impact & expert chains** (Q83–Q92)
- **Tooling** (Q93–Q96)
- **Methodology & triage** (Q97–Q100)
- **Cheat sheets** (Q101–Q104)
- **Real-world & references** (Q105–Q106)
- **Defense — using JWT securely** (Q107–Q109)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is a JWT?
A JSON Web Token is a compact, URL-safe token of three base64url parts: **`header.payload.signature`**. The header names the algorithm (`alg`) and key hints (`kid`/`jku`/`jwk`/`x5c`); the payload holds **claims** (`sub`, `role`, `exp`, …); the signature authenticates header+payload. It's used as a **stateless** session/auth token — the server trusts the claims *because* the signature verifies.

> *Plain version:* think of a JWT as a **hand-stamped VIP wristband** (this analogy runs through the whole guide). Part 1 (header) = "how I'm stamped." Part 2 (payload) = "who I am / what I'm allowed" — your name and whether you're a VIP. Part 3 (signature) = the venue's tamper-proof stamp proving parts 1+2 are genuine. The door lets you in *because the stamp checks out* — no need to phone a central database, which is what "stateless" means.

### Q2. JWS vs JWE — what's the difference?
**JWS** (signed, 3 parts) is the common case — the payload is **readable** (base64, not encrypted) and only *integrity*-protected. **JWE** (encrypted, **5 parts**: `header.encrypted_key.iv.ciphertext.tag`) is *confidentiality*-protected. Most bug-bounty JWTs are JWS; if you see 5 parts, it's JWE (different attacks, Level 4).

> *Plain version:* **JWS = a stamped-but-readable wristband** (anyone can read what's printed, the stamp just proves it's real). **JWE = a sealed opaque envelope** (you can't even read what's inside without the key). Count the dots to tell them apart: **2 dots = JWS** (3 parts, think forgery), **4 dots = JWE** (5 parts, think encryption/DoS). 99% of what you'll hit in bug bounty is JWS.

### Q3. Why is JWT such a high-value target?
Because the token *is* the session. If you can **forge** a valid-looking token (or the server doesn't actually verify it), you mint a token for **any user or an admin** → **pre-auth account takeover / privilege escalation** with no credentials. A single signature/key flaw is usually **Critical**.

### Q4. What's the core trust model — and where does it break?
The server must: (1) parse the header, (2) pick the **right key** for the **right algorithm**, (3) verify the signature, (4) check claims (`exp`, `aud`, `iss`, etc.), (5) authorize on **trusted** claims. It breaks when any step is skipped or attacker-influenced: no verification, `alg:none`, wrong key (HS vs RS confusion), attacker-supplied key (`kid`/`jku`/`jwk`/`x5c`), unchecked claims, or no expiry/revocation.

### Q5. The header fields that matter for attacks?
`alg` (the algorithm — and the thing to confuse/downgrade), `kid` (key id — file/DB/command sink), `jku`/`x5u` (URL to fetch a key from → SSRF + forgery), `jwk` (embedded key), `x5c` (embedded cert chain), `typ`/`cty`/`crit` (parser-confusion levers).

### Q6. The claims that matter?
`sub`/`user_id`/`uid` (identity → IDOR/ATO), `role`/`roles`/`isAdmin`/`scope`/`groups` (authorization → priv-esc), `aud`/`iss` (audience/issuer → cross-service), `exp`/`nbf`/`iat`/`jti` (lifecycle → replay), `tenant`/`org` (multi-tenant), `email`/`email_verified` (OAuth ATO), `amr`/`acr`/`mfa` (assurance bypass).

### Q7. What's the difference between HS and RS algorithms?
**HS256/384/512** are **symmetric** (HMAC) — the **same secret** signs and verifies. **RS256/PS256/ES256/EdDSA** are **asymmetric** — a **private** key signs, the **public** key verifies. This asymmetry is the basis of the famous RS→HS confusion (Q31): the public key (which you can get) becomes the HMAC secret.

> *Plain version:* **HS = a rubber stamp in a drawer** — one password both makes and checks the stamp, so anyone who learns that password can forge. **RS/ES = a wax seal from a signet ring** — a locked-away ring stamps (private key, server-only), and a public photo of what the seal looks like lets anyone *verify* (public key). Normally you can't forge a wax seal because you don't have the ring — the danger is only when the server *checks it wrong* (Q29).

### Q8. What's the #1 mistake when reporting JWT bugs?
Reporting **observations** instead of **forgeries**: "the token uses HS256", "I decoded the token and it has an email", "alg:none exists in the spec". None of those are findings. The finding is *the server accepting a token you controlled and acting on it* — a behavior change (admin data, another user's data). Always demonstrate the forge + the effect.

### Q9. Is decoding a JWT "hacking"?
No — the payload is base64, readable by anyone. Decoding is recon. The bug is whether you can **tamper and get it accepted**. (And note: putting secrets in a JWS payload is itself a disclosure issue, since it's readable.)

> *Plain version:* reading your own wristband is not a crime — the text is printed in plain sight. base64url just looks scrambled; it's a different alphabet, not a lock. The bug is never "I read it," it's "**I changed it and the door still let me in.**"

### Q10. What's the single most important first test?
**Is the signature even verified?** Tamper a claim, keep the signature, and send it. If it's accepted *and behavior changes* → the server isn't verifying at all → you can set any claim with no forge primitive (Critical). This is the baseline (Level 1) and it shortcuts everything.

> *Plain version:* the dumbest question first — *does the guard even look at the stamp?* Scribble "admin" over "user" on your band, leave the (now-wrong) stamp as-is, and try the door. If it opens, you're done — no crypto, no cracking, the biggest bug there is. Never skip this to go chase clever attacks.

### Q11. What do I need before testing?
A proxy (Burp + **JWT Editor**), `jwt_tool`, hashcat/john (for HMAC cracking), an **attacker-controlled HTTPS host** (for `jku`/`x5u` + SSRF), Python with `pyjwt`/`cryptography`, and **two test accounts** (low-priv + a second user / test admin) to prove cross-user/priv-esc safely.

### Q12. Where do JWTs live (so I find them all)?
Session cookies, the `Authorization: Bearer` header, URL/query/fragment (OAuth, **reset/magic-login links** — a classic), JSON bodies, OAuth `id_token`/`access_token`, and `localStorage`. Don't miss the **reset/verify-link JWT** — it's often the weakest and highest-impact.

---

# LEVEL 1 — RECON, DECODE & BASELINE

### Q13. How do I decode a token without tools?
Split on `.`, base64url-decode parts 1 and 2:
```bash
echo "$T" | cut -d. -f1 | tr '_-' '/+' | base64 -d 2>/dev/null; echo   # header
echo "$T" | cut -d. -f2 | tr '_-' '/+' | base64 -d 2>/dev/null; echo   # payload
```
Record `alg`, `kid`, `jku/x5u/jwk/x5c`, all claims, and **where the token is used**.

### Q14. How do I get the public key / JWKS?
Check `/.well-known/jwks.json` and `/.well-known/openid-configuration` (which links the JWKS). For OAuth/OIDC the JWKS is usually public. If there's no JWKS, you can **recover** the RSA public key from two tokens (Q33) or reuse the TLS cert's key.

### Q15. What's the baseline "is it verified?" test, step by step?
```
1. Tamper a claim, KEEP the original signature → send → accepted? (and does behavior change?)
2. Strip the signature (header.payload.) → accepted?
3. Send a garbage signature → accepted?
4. Confirm against an endpoint that actually USES the token for authz (returns your data).
```
Any acceptance + behavior change = the server doesn't verify → Critical, no forge needed.

### Q16. Why insist on "behavior change", not just "accepted"?
Because an endpoint might accept any string (it doesn't use the token there) or echo it back without authorizing on it. The finding is that the **tampered claim took effect** — you see admin functions / another user's data. "Accepted but ignored" is a false positive (Q98).

### Q17. Which endpoint should I test against?
One that **authorizes on the token and returns identity-specific data** — `/api/me`, the dashboard, an account/settings endpoint, an admin route. That's where a tampered `sub`/`role` produces observable, reportable change.

### Q18. How do I fingerprint the library/issuer?
`typ`/header hints, error messages, the issuer (`iss`), framework cookies, and the JWKS format. Knowing the library + version lets you match known CVEs (alg:none acceptance, embedded-JWK trust, psychic signature on Java, etc.).

### Q19. What does the `kid` value tell me?
It's a key identifier the server uses to **select** the verification key — often by reading a **file** (`keys/<kid>.pem`), a **DB row** (`SELECT key WHERE id=<kid>`), or a path. That makes `kid` an injection sink: path traversal, SQLi, command/LFI (Q35).

### Q20. What do `jku`/`x5u` tell me?
They're **URLs** the server fetches the verification key (JWKS) from. If attacker-controllable, you host your own JWKS and sign with your key → forgery; even if not honored, the **fetch is SSRF** (Q37).

### Q21. What's the deliverable from recon?
A map: token location(s), `alg`, key headers, every claim, where each token is used for authz, and the JWKS/public key. That tells you which Level-2 attack to try first.

### Q22. What's the fastest path to a finding from baseline?
If the tamper-but-keep-signature test changes behavior → you're done (no verification). Otherwise, try `alg:none` and `jwk`-embedded (both need no hosting/cracking) early, then HMAC-crack / RS→HS confusion / `kid` injection.

---

# LEVEL 2 — SIGNATURE & KEY ATTACKS

### Q23. What is the `alg:none` attack?
The JWT spec defines `none` = "unsecured" (no signature). If the verifier accepts `alg:none` (and an **empty** signature), you set any claims, set `alg` to `none`, and send `header.payload.` (empty third part) → accepted with no key. A library bug, but still found.

> *Plain version:* `alg:none` is the wristband telling the guard **"I have no stamp — just trust the printing."** A broken guard shrugs and lets you in. So you set `alg` to `none`, print `role:admin`, and hand over a band with the stamp area left blank (note the trailing dot with nothing after it). Zero crypto.
```
header: {"alg":"none","typ":"JWT"}   payload: {"sub":"victim","role":"admin"}   signature: (empty)
token:  base64(header) . base64(payload) .
```

### Q24. How do I bypass `alg:none` blocklists?
Case/whitespace variants the verifier normalizes loosely: `None`, `NONE`, `nOnE`, `none ` (trailing space), `none` with a null byte. Some libraries lowercase before comparing but a different layer doesn't.

### Q25. What's weak-HMAC-secret cracking?
> *Plain version:* HS256 is the "rubber stamp in a drawer" — one password makes and checks the stamp. If it's weak (`secret`, `changeme`, a tutorial's leftover key), you can **guess it on your own laptop** by trying millions of passwords against one captured token, then stamp your own bands. "Offline" matters: you never touch the target while guessing, so it's silent and safe.

If the token is HS256/384/512, the secret is just a string. Capture one token and crack the HMAC **offline**:
```bash
hashcat -a 0 -m 16500 token.txt rockyou.txt                 # GPU
hashcat -a 0 -m 16500 token.txt jwt.secrets.list            # known/default secrets FIRST
john token.txt --wordlist=rockyou.txt --format=HMAC-SHA256
```
Then re-sign with the cracked secret. Many apps ship a default/sample secret (`secret`, `your-256-bit-secret`, `changeme`).

### Q26. Why try default secrets first?
Because framework tutorials, Docker images, and copy-pasted configs leave **well-known** secrets (`secret`, `your-256-bit-secret`, `jwtsecret`, `changeme`, sample keys). The `wallarm/jwt-secrets` list catches a large share of real findings instantly — no GPU needed.

### Q27. Where else might the HMAC secret leak?
JS bundles, `.env`, git history, mobile APKs, error pages, config endpoints. A leaked secret = **crack-free forgery** (cross-ref the JS-files kit). Always grep recon output for the signing secret.

### Q28. After cracking/leaking the HMAC secret, what can I do?
Forge **any** token: set `sub` to a victim, `role:admin`, `exp` far future, and HMAC-sign with the secret → full ATO / priv-esc. That's the whole game once you have the symmetric key.

### Q29. What is RS256 → HS256 algorithm confusion?
The classic. The server verifies RS256 with its **public** key. If it doesn't pin the algorithm and you change `alg` to **HS256**, a flawed library will verify the HMAC using that **public key as the HMAC secret** — and the public key is **public**. So you HMAC-sign your forged token with the public key → it verifies. (CVE-2015-9235 and many re-occurrences.)

> *Plain version (the tricky one — read slow):* the venue uses the wax-seal system, so you can't forge... normally. But you rewrite the header to say "check me with the **rubber-stamp** method instead." Now the guard grabs a rubber-stamp password to check you — and the only key it has on file is **the public photo of the seal** (which everyone has, including you). Rubber-stamp passwords are symmetric: whoever can *check* with it can also *stamp* with it. So you stamp your own band using that same public photo, and the check passes. You turned their public *verify-only* key into a *make-and-verify* key just by changing which method the token asks for.

### Q30. Walk the RS→HS confusion steps.
```
1. Get the RSA public key (PEM) from JWKS / .well-known / recover it (Q33).
2. Edit claims; set alg=HS256.
3. HMAC-SHA256-sign the token using the public key PEM bytes as the secret.
4. Send → a confused verifier validates with the public key → accepted → forge any user.
```
Formatting is the usual snag (PEM with/without trailing newline, DER) — try variants (the kit's `rs256_to_hs256.py` does).

### Q31. Why does the public key being public matter?
Because asymmetric verification was *supposed* to mean "only the holder of the private key can sign." Confusing the algorithm to HS turns the **public** verification key into a **shared secret** anyone has → the entire asymmetric guarantee collapses. It's a **configuration/library** bug, not a key leak.

### Q32. The server uses RS256 but I can't find the public key — options?
- Pull JWKS / `.well-known/openid-configuration`.
- **Recover** the RSA public key from **two** different tokens (same key) using `rsa_sign2n`/`jwt_forgery.py`.
- Reuse the **TLS certificate's** public key if it's the same key.
Then do RS→HS confusion (Q30).

### Q33. How does recovering the RSA public key from two tokens work?
Given two messages and their RSA signatures (same key), there's a known math technique to compute candidate public keys (modulus). Tools (`rsa_sign2n`) output candidate PEMs; try each as the HMAC secret for RS→HS. You don't need the JWKS at all.

### Q34. What is `kid` path-traversal forgery?
> *Plain version:* `kid` is a little label on the band saying **which stamp to check me with**, and the server looks that label up by reading a *file* named after it. You control the label, so you point it at a file whose contents you already know — the classic is `/dev/null`, which is *always empty*. The key becomes the empty string, so you stamp your band with an empty password and it verifies.

If `kid` selects a key **file**, point it at a file with **known/empty contents** so you know the verification key:
```
kid: ../../../../dev/null   → key = "" (empty) → sign HS256 with secret ""
kid: /proc/sys/kernel/randomize_va_space → 1-byte known content → sign HS with "0\n"/"1\n"
```
Now you control the verification key → forge any token.

### Q35. What other injections does `kid` enable?
`kid` flows into a lookup, so it's a generic injection point:
- **SQLi:** `kid: x' UNION SELECT 'attackerkey'-- -` → returns a key you chose → sign HS with `attackerkey`.
- **LFI / source disclosure:** `kid: php://filter/convert.base64-encode/resource=...`.
- **Command injection / RCE:** `kid: key|id`, `kid: $(id)` (if passed to a shell).
- **SSRF:** `kid: http://169.254.169.254/...` (if fetched as a URL).
Test these independently of forging — a `kid` RCE/SSRF is its own Critical.

### Q36. What is `jku`/`x5u` header injection?
> *Plain version:* `jku` is the band carrying **a phone number to call for the verification key** instead of the key itself. A careless guard dials whatever number you printed. So you host *your own* key at a URL you control, put that URL in `jku`, and sign with *your own* private key — the guard calls your line, gets your key, and of course your stamp matches it. (And just making the server dial a number you chose is also SSRF — Q37.)

`jku`/`x5u` is a **URL** the server fetches the JWKS/cert from. Host your own JWKS containing **your** public key, point `jku` at it, sign with your private key → the server trusts your key → forgery.
```
1. poc/jwks_server.py serves /jwks.json with your public key (expose via ngrok/Collaborator).
2. jwt_tool <T> -X s -ju https://YOUR-HOST/jwks.json -pr your_private.pem
```

### Q37. The `jku` host must match the issuer — bypasses?
SSRF-style allowlist bypasses:
```
https://trusted.com@YOUR-HOST/jwks.json     https://trusted.com.YOUR-HOST/jwks.json
https://YOUR-HOST/jwks.json#trusted.com      https://YOUR-HOST/jwks.json?x=trusted.com
https://trusted.com/open-redirect?url=https://YOUR-HOST/jwks.json   (open redirect on the trusted host)
```
And remember: even if the key isn't honored, the **fetch is SSRF** → confirm with a callback (may reach internal/metadata) — report both.

### Q38. What is `jwk` header injection?
The `jwk` header can **embed the public key in the token itself**. If the server verifies against the **embedded** key instead of its trusted key, you embed **your** public key and sign with **your** private key — no hosting needed. The easiest key-injection to try.

> *Plain version:* even lazier than `jku` — instead of a phone number to call, the band has **the key printed right on it**: "check my stamp against this attached key." A broken guard checks you against the key *you glued to your own band*. No server, no URL, one click in Burp's JWT Editor. Because it's zero-setup, try it early.
```
Burp JWT Editor → Attack → "Embedded JWK" (one click).  Or jwt_tool -X i.
```

### Q39. What is `x5c` injection?
`x5c` carries an X.509 cert chain. If the server extracts the public key from `x5c` without validating the chain to a trusted CA/pinned cert, embed a **self-signed** cert whose key you control and sign with it — same forge primitive as `jwk`.

### Q40. What is the ES256 "psychic signature" (CVE-2022-21449)?
Vulnerable **Java 15–18** accepts an ECDSA signature of **(r=0, s=0)** — a blank/all-zero signature — as valid. If the target verifies ES256 on affected Java, you forge any token with an all-zero signature. `jwt_tool -X psychic`.

### Q41. What about PS256 / EdDSA?
**PS256** = RSA-PSS → same **key-source** attacks as RS* (`jwk`/`jku`/`x5c`) and confusion if downgradeable. **EdDSA** → watch for libs accepting a zero/identity key or malleable signatures (rarer). Always test the key-injection primitives regardless of the asymmetric variant.

### Q42. What is algorithm downgrade / substitution?
Swap `alg` to a different supported algorithm and see if verification mismatches: RS512→RS256, PS→RS, ES→HS, or RS→HS (Q29). **Any** acceptance of a token signed differently than the server expects is an algorithm-confusion bug.

### Q43. Which key attack should I try first (efficiency)?
No-hosting, no-cracking first: **`alg:none`** and **`jwk`-embedded** (one-click). Then **default-secret HMAC** (instant if it's a known secret) and **RS→HS confusion** (if you have the public key). Then `kid` injection, then `jku`/`x5u` (needs hosting), then RSA-pubkey recovery.

### Q44. How do I forge a token in practice?
With the kit's `poc/`: `forge_token.py` (none/HS), `rs256_to_hs256.py` (confusion), `kid_injection.py`, `jwk_inject.py`, `jwks_server.py` (jku). Or Burp **JWT Editor** / `jwt_tool`. Edit one claim, re-sign with the primitive that works, send.

### Q45. How do I know which forge primitive "works"?
The server **accepts** the forged token on an authz endpoint **and** the tampered claim takes effect (you see another user's/admin data). Try each primitive against `/api/me`; the one that returns the forged identity is your finding.

### Q46. What if none of the signature attacks work?
Move to **claim/lifecycle/context** (Level 3) — the signature may be solid but the app might trust claims it shouldn't, fail to check `aud`/`iss`/`exp`/revocation, or accept cross-service tokens. Plenty of JWT bugs need no signature break.

### Q47. Is "HS256 is used" a vulnerability?
No. HS256 is fine if the secret is strong and the algorithm is pinned. The vuln is a **weak/leaked secret** or **algorithm confusion** — not the choice of HS256. Don't report the algorithm name.

### Q48. Is "alg:none exists / RS256 in spec" a vulnerability?
No — those are spec facts. The vuln is the **server accepting** `alg:none` / a confused algorithm and acting on the forged claims. Demonstrate acceptance + behavior change, or it's not a finding.

---

# LEVEL 3 — CLAIM, LIFECYCLE & CROSS-SERVICE

### Q49. Once I can forge (or it's unverified), what claims do I tamper?
`sub`/`user_id` → another user (IDOR/ATO); `role`/`isAdmin`/`scope`/`groups` → admin/priv-esc; `tenant`/`org` → cross-tenant; `email`/`email_verified` → OAuth ATO; `amr`/`acr`/`mfa` → claim MFA satisfied; `plan`/`tier` → unlock paid features. Change **one at a time** and confirm the behavior change.

### Q50. Can claim tampering work *without* a signature break?
Yes — if the server **trusts a claim it shouldn't** (e.g., re-reads `role` from the token instead of the DB) **and** the signature isn't actually verified (Q15), tampering alone wins. Always test "tamper + keep signature" on high-value claims even when you can't forge.

### Q51. What is `sub`-swap horizontal escalation?
Set `sub`/`user_id` to **another** user's id and re-sign → you operate as that user (IDOR). Quantify scale: are ids sequential/enumerable? Mass-IDOR across all users = **Critical**. Evidence: a response with **another** user's PII/financial data, proven not yours.

### Q52. What is vertical escalation?
Bump `role`/`isAdmin`/`scope` to admin/staff → reach admin-only endpoints/UI. Prove it by performing an admin action or loading an admin-only page with your forged token.

### Q53. What is cross-tenant compromise?
In multi-tenant SaaS, swap `tenant`/`org`/`account_id` to another tenant → read/modify their data. Especially severe on a **shared IdP** (Azure AD/Auth0) where tokens from *any* tenant validate unless `aud`+`iss`+`tenant` are strictly pinned.

### Q54. What is issuer/audience confusion?
Weak `aud`/`iss` validation lets a token meant for service A be replayed at service B, or a token from a different (attacker-registered) issuer be accepted. Take a **valid token from one context** (a second app, staging, your own OAuth client) and replay it at the target. Acceptance across audiences/issuers is High–Critical.

> *Plain version:* the band says **who issued it** (`iss`) and **where it's good** (`aud` — "main stage only"). A lazy VIP-lounge guard doesn't read the "main stage only" line and lets your main-stage band in. No forging — the stamp is genuine, the *scoping* is what's broken: you just replay a real token somewhere it was never meant to work.

### Q55. The "same signing key across environments" bug?
If staging/UAT and production share a signing key, a **staging token** is accepted in **production**. A token you can mint in a low-security environment then works against the real one → auth bypass.

### Q56. What is the OAuth "confused deputy" via tokens?
An `id_token` issued for **your** client is accepted by a **different** client/relying party that doesn't check `aud`/`azp` → you authenticate as yourself-but-trusted elsewhere, or replay a token across relying parties. (More OIDC specifics in Level 4.)

### Q57. What are expiration failures?
`exp` not enforced → set `exp` far future (or remove it) on a forged token, or replay an old captured token past its `exp` → forever-session. **No `exp` at all** → a single capture = permanent access. `nbf` in the past → use a not-yet-valid token.

### Q58. What are replay/revocation failures?
> *Plain version:* a wristband should stop working when you "leave the venue" — log out or change your password. When it doesn't, a band someone **stole from you keeps opening the door even after you did the exact thing meant to save you.** The proof is simple: grab your token, log out, replay it; if it still returns your data, that's the bug. And a *one-time* band (password-reset link) that works twice = reset again.

- **No `jti`/replay protection:** a one-time reset/magic-login JWT reused multiple times.
- **No revocation on logout / password change:** capture a token, log out (or change password), replay it → **still valid** → stolen tokens survive the user's defensive action. Very common, clearly reportable.

### Q59. How do I PoC a revocation failure?
Capture a token → perform the action that *should* invalidate it (logout / password reset) → replay it on an authenticated endpoint → show it **still returns your data**. That proves stolen tokens aren't revoked (durable session).

### Q60. What are refresh-token bugs?
Refresh tokens that aren't rotated, lack **reuse detection**, or remain valid after logout/password-change → a stolen refresh token = **persistent ATO** (mint new access tokens indefinitely). Test reuse of an already-rotated refresh token.

### Q61. Why does JWT *storage* matter?
Where the token lives decides how it's stolen and how long it lasts: in a **URL** (leaks via Referer/history/logs — classic for reset JWTs), in **localStorage** (any XSS reads it — chain to ATO), **logged** server-side, **cached/CDN** (served to others), or a cookie **missing HttpOnly/Secure/SameSite**. Leakage is the enabler for ATO when chained.

### Q62. Is token leakage alone a finding?
Usually Low–Medium **alone**, but it's the **enabler**: XSS→token theft→ATO, or a reset-JWT in a URL leaking via Referer→ATO. Report the **resulting account compromise** where you can demonstrate the chain.

### Q63. What is claim "scope" abuse?
Adding scopes (`read`→`read write`, `user`→`admin` API scope) or permissions/groups to reach functionality the token shouldn't grant. Works when the resource server authorizes on the token's `scope`/`permissions` and you can forge.

### Q64. What about `email`/`email_verified` for OAuth ATO?
If the app keys accounts on `email` and trusts `email_verified` from the token, forge `email: victim@corp.com`, `email_verified: true` → link/take over the victim's account. (See OIDC `(iss, sub)` keying, Q73.)

### Q65. What is MFA/assurance bypass via claims?
If the app gates "step-up" on token claims (`amr: ["mfa"]`, `acr: "high"`, `mfa: true`) and you can forge, set them to **claim MFA was satisfied** without doing MFA → bypass step-up auth.

### Q66. When is a tampered token *not* a finding?
When it's **accepted but ignored** — the server doesn't authorize on that claim, or re-derives identity/role from the DB regardless of the token. No behavior change = no finding. Confirm the effect (Q16).

---

# LEVEL 4 — OIDC, JWE, PARSER CONFUSION & DoS

### Q67. What OIDC-specific `id_token` attacks exist?
> *Plain version:* an `id_token` is the "Sign in with Google" ID card the login provider hands your app to prove *who you are*. It comes with several anti-fraud lines on it (who it's for, a one-time `nonce`, hashes tying it to the rest of the login). Apps constantly forget to check one or more of those lines — and each forgotten check is its own way to **sign in as someone else**. The questions below are one-per-forgotten-check.

OIDC `id_token`s carry extra security claims relying parties (RPs) routinely fail to validate: **`aud` as array** / **`azp` unchecked**, **`nonce` missing/replayed**, **`at_hash`/`c_hash` not validated**, **IdP mix-up**, **id_token used as an access_token**, and **(iss, sub) identity keying**. Each is a distinct, high-value bug.

### Q68. The `aud`-array / `azp` bug?
`aud` can be a **list**. The RP must check **its** client_id is present **and** (with multiple audiences) check `azp` (authorized party) equals its client_id. If it accepts any token whose `aud` *contains* a value, a token for **another client** is accepted → confused deputy / sign-in as victim.

### Q69. The `nonce` replay bug?
In auth-code/implicit flows the RP sends a `nonce` and the `id_token` echoes it; the RP must **bind** the returned `id_token` to the nonce it sent. **No nonce check** → an attacker can **replay** an `id_token` (or inject a stolen one) at the callback → sign in as the victim. Test by dropping/replaying the nonce.

### Q70. What are `at_hash`/`c_hash` and why do they matter?
They **bind** the `id_token` to the access_token / auth code (a hash of each). If the RP doesn't validate them, an attacker can **substitute** a different access_token/code while keeping the id_token → token **cut-and-paste** / account mix-up. Unvalidated `at_hash`/`c_hash` is a real flaw.

### Q71. What is the IdP "mix-up" attack?
In RPs that support **multiple IdPs**, the attacker swaps which IdP the response appears to come from → the RP exchanges the code at the **wrong** IdP or accepts a token from the **wrong** issuer → ATO. Defense: validate `iss` per IdP + per-request state.

### Q72. id_token used as an access_token?
Some APIs (or `/userinfo`) accept the **id_token** at protected endpoints. Since id_tokens are for the *client*, not for API access, this is audience misuse — test sending the id_token to protected APIs.

### Q73. What is `(iss, sub)` identity keying?
The RP must key the account on the **(iss, sub) pair**. If it keys on **email** or **sub alone**, register the **victim's email** at an IdP whose tokens the RP trusts, get a token, and the RP merges you into the victim's account → **cross-IdP takeover**.

### Q74. What attacks apply to JWE (encrypted, 5-part) tokens?
`alg:dir` with a guessable/static content-encryption key; **RSA1_5** key-wrap → Bleichenbacher/Million-Message padding oracle (if errors differ); a **nested `alg:none` JWS** inside the JWE (decrypt → inner unsigned token trusted); decryption-error oracles; mixing signing vs encryption keys. Rarer in bounty but check if you see 5-part tokens.

### Q75. What is parser/header confusion?
> *Plain version:* imagine two guards reading the **same** wristband and disagreeing about what it says — maybe it has *two* "role" lines and one guard reads the first, the other reads the last. If the outer guard (gateway) authorizes on one reading and the inner one (backend) acts on the other, you slip a band past that means "guest" to the bouncer but "admin" to the system inside. This is why it pays most in gateway + microservice setups.

Two JWT libraries (gateway vs backend) parsing the **same** token differently:
- **Duplicate `alg`** (`{"alg":"RS256","alg":"none"}`) → which one does each side use?
- **Duplicate claims** (two `role` entries) → last-wins vs first-wins mismatch.
- **`typ`/`cty`** confusion (nested content).
- **JSON quirks** (unicode escapes, leading zeros, big numbers, comments) → divergent acceptance.

### Q76. What is the `crit` header bypass?
Per spec, a verifier **must reject** a token whose `crit` lists a header param it doesn't understand. Abuses: **(a)** a library that **ignores** `crit` lets you smuggle a param the verifier should have rejected (bypass a required check); **(b)** listing a `crit` param the **gateway** honors but the **backend** ignores → divergence. Test if `crit` is enforced.

### Q77. Where does parser confusion pay off most?
**Gateway + microservice** setups: the gateway authorizes on one interpretation, the backend acts on another. The token is "valid" to the gateway but means something different to the backend → auth/authz bypass.

### Q78. What JWT/JWE Denial-of-Service vectors exist?
(Only where DoS is in scope.) **PBES2 `p2c` bomb** — the attacker-set PBKDF2 iteration count (`p2c: 100000000`) forces millions of rounds per verify → CPU hang. **JWE `zip:DEF` decompression bomb** — tiny payload expands to GBs. **Oversized key** (huge RSA modulus in `jwk`/`x5c`). **Deep nesting**. One crafted token can exhaust a worker.

### Q79. How do I demonstrate a JWT DoS responsibly?
Send **one** crafted token and **measure** the multi-second hang / memory spike vs a normal token; show the **ratio** (tiny token → huge work). **Never flood** production. Report only where DoS is in scope (CWE-400). Kit: `poc/jwe_dos_token.py`.

### Q80. Is the `p2c` bomb common?
Wherever **PBES2** JWE is accepted (password-based key wrapping). Many apps don't accept JWE at all (so it's N/A), but where they do and don't cap `p2c`, it's a clean resource-exhaustion bug.

### Q81. What's the difference between JWS and JWE attack surface?
JWS attacks target **signature/key trust** (forgery → ATO). JWE attacks target **encryption/key-management** (padding oracles, nested `none`, weak CEK) and **DoS** (p2c/zip). If you see 3 parts, think forgery; 5 parts, think JWE issues.

### Q82. How do I quickly classify a token I find?
Count dots: **2 dots / 3 parts** → JWS (forgery attacks). **4 dots / 5 parts** → JWE (encryption/DoS). Decode the header: `alg`/`enc` present → JWE; `alg` only → JWS. The header's `alg` + key hints tell you which attack to try.

---

# LEVEL 5 — IMPACT & EXPERT CHAINS

### Q83. What's the triager's first question on a JWT finding?
"**So what can you actually do?**" Answer with: forge for any user/admin (Critical ATO), `sub`-swap to another user (IDOR), `role`/`scope` priv-esc (Critical), cross-tenant (Critical SaaS), stolen/forged refresh token (persistent ATO), replay-after-logout (durable session), `jku` SSRF (Medium–High + ATO if key honored). Climb as high as the app allows.

### Q84. How do I demonstrate full account takeover safely?
With **two of your own accounts**: forge a token for test-account-B from test-account-A's session (any forge primitive), call `/api/me`, and show **B's** data returned. That's an unambiguous Critical (pre-auth ATO of any user) — using only your own accounts.

### Q85. How do I quantify IDOR-via-`sub` scale?
Are ids sequential/enumerable? Can you iterate all users? Mass-IDOR (read/modify any user) = **Critical**. Capture a response with **another** user's PII/financial data, proven not yours (different name/email/amount).

### Q86. Chain: JWT + XSS.
XSS reads the JWT from `localStorage`/a non-HttpOnly cookie → token theft → ATO. JWT-in-localStorage raises the impact of any XSS you find (and is itself worth flagging).

### Q87. Chain: `jku`/`kid` → SSRF → cloud metadata.
A `jku`/`x5u` (or `kid` URL) fetch is **SSRF**; steer it to `169.254.169.254` → IAM creds → cloud takeover (SSRF kit, read-only proof). Report the SSRF **and** the auth bypass if the key is honored.

### Q88. Chain: leaked HMAC secret (JS/git) → forge.
Recon (JS-files kit) finds the signing secret in a bundle/`.env`/git → forge any token with no cracking → instant ATO/admin. The JS recon *is* the JWT exploit's entry point.

### Q89. Chain: reset-link JWT.
A password-reset/magic-login JWT in a URL (weak alg, no `jti`, no `exp`) → forge or replay it → reset any user's password / log in as them. These tokens are often the weakest and highest-impact — test them first.

### Q90. Chain: cross-service token reuse.
A token from a low-priv service/staging/your own OAuth client accepted at a high-priv service (weak `aud`/`iss`) → privilege crossover. Combine with claim tampering once it's accepted.

### Q91. How do I escalate a "weak" JWT finding?
`alg:none`/confusion accepted → forge **admin** and show an admin action. `jku` SSRF → reach **metadata**. Leaked secret → forge any user. `kid` SQLi/RCE → its own Critical. Always push the primitive to a **demonstrated** impact (admin/other-user/cross-tenant), not just "accepted".

### Q92. What separates expert JWT testing from beginner?
The expert (1) **baselines verification first** (tamper-keep-signature); (2) tries the **no-cost** primitives (`none`/`jwk`) before cracking; (3) understands **algorithm confusion** and **key-header injection** (`kid`/`jku`/`jwk`/`x5c`); (4) tests **OIDC** specifics (nonce/at_hash/aud-array) and **lifecycle** (revocation/replay); (5) **chains** (SSRF/XSS/leaked-secret) to ATO; and (6) proves **behavior change** with own accounts — never reports "decoded a token".

---

# TOOLING

### Q93. Core JWT toolkit?
**Burp + JWT Editor** (decode, tamper, re-sign, one-click attacks), **jwt_tool** (all attacks + live scan), **hashcat/john** (HMAC crack, `-m 16500`), the kit's `poc/` (forge/none/RS→HS/kid/jwk/jwks-server/jwe-dos), an **attacker HTTPS host** (jku/x5u + SSRF), `rsa_sign2n` (pubkey recovery), and `wallarm/jwt-secrets`.

### Q94. How do I use jwt_tool efficiently?
`jwt_tool <T>` to decode; `-X a` (alg:none), `-X k -pk pub.pem` (key confusion), `-X i` (embedded jwk), `-X s -ju <url> -pr key.pem` (jku), `-C -d wordlist` (crack); and `-t <url> -rh "Authorization: Bearer <T>" -M at` to run the attack suite against the **live** authed endpoint. Always reproduce a "hit" by hand + confirm behavior change.

### Q95. How do I build a success oracle for automation?
Run each forge primitive against an endpoint that returns identity-specific data; flag a finding only when the response shows the **forged identity/role** (not yours). Tools false-positive on "accepted" — gate on the behavior change.

### Q96. What's the fastest practical workflow?
1. Decode + pull JWKS. 2. Baseline (tamper-keep-signature). 3. `alg:none` + `jwk`-embedded. 4. Default-secret HMAC + RS→HS confusion. 5. `kid`/`jku` injection. 6. Lifecycle/OIDC/claims. 7. Chain to ATO; prove with own accounts.

---

# METHODOLOGY & TRIAGE

### Q97. Step-by-step methodology.
**Recon** (find/decode every token, get JWKS) → **Baseline** (is it verified?) → **Signature/key attacks** (none/HMAC/confusion/kid/jku/jwk/x5c/psychic) → **Claim/lifecycle/cross-service** (sub/role/aud/iss/exp/revocation/OIDC) → **JWE/parser/DoS** → **Impact** (forge for any user/admin; prove behavior change with own accounts) → **Report** (CWE-347/345/287/639/918; one root cause = one finding).

### Q98. False positives / auto-reject.
- "I decoded a token" / "it has an email/role" (decoding ≠ a bug).
- "HS256 is used" / "alg:none is in the spec" (no demonstrated acceptance).
- A token **accepted but ignored** (no behavior change).
- `jku` SSRF with no impact and the program excludes SSRF (still note it).
- A finding only against an endpoint that doesn't authorize on the token.

### Q99. What makes a great JWT report?
The original + forged token (decoded, showing the exact change), the **forge command/primitive**, the request/response showing **acceptance + behavior change** (admin/other-user data), the impact (ATO/priv-esc/cross-tenant), CVSS + CWE, and a note that it was demonstrated with **your own** accounts (and any forged-admin session cleaned up). De-dup: one root cause = one finding.

### Q100. How do I set severity?
Forge for any user/admin → **Critical**. `sub`-swap IDOR / `role` priv-esc / cross-tenant → **High–Critical**. Refresh-token/persistent ATO → High–Critical. Replay-after-logout / no-exp → Medium–High. `jku` SSRF → Medium–High (+ATO if key honored). Leakage/info-only → Low–Info (don't lead).

---

# CHEAT SHEETS

### Q101. Attack-by-`alg`/header cheat sheet.
```
alg:none           → header.payload.   (empty sig); variants none/None/NONE/nOnE/none␠
HS256/384/512      → crack offline (hashcat -m 16500; default secrets first) OR find leaked secret → re-sign
RS256/PS256        → RS→HS confusion (HMAC-sign with the PUBLIC key PEM) ; recover pubkey from 2 tokens if no JWKS
ES256 (Java 15-18) → psychic signature (r=0,s=0) — CVE-2022-21449
kid                → ../dev/null (empty key) · SQLi UNION SELECT 'k' · LFI/RCE/SSRF
jku/x5u            → host your JWKS (poc/jwks_server.py) + sign with your key ; allowlist bypass @ / . / # / ? / open-redirect ; SSRF
jwk / x5c          → embed your key/cert + sign with its private key (no hosting) — try this EARLY
```

### Q102. Claim-tampering cheat sheet.
```
sub/user_id → victim id (IDOR/ATO)     role/isAdmin/scope/groups → admin/priv-esc
tenant/org → cross-tenant               email/email_verified → OAuth ATO (set verified:true)
amr/acr/mfa → claim MFA satisfied       exp → far future / remove (forever session)   nbf → past   jti absent → replay
aud/iss → cross-service replay          OIDC: aud-as-array/azp · nonce replay · at_hash/c_hash · (iss,sub) keying
```

### Q103. Baseline & forge commands cheat sheet.
```bash
# decode
python3 jwt_tool.py "$T"
# baseline: tamper a claim, keep sig (JWT Editor) ; strip sig: NOSIG="$(echo "$T"|cut -d. -f1,2)."
# forge primitives (kit poc/):
python3 forge_token.py "$T" --alg none --claim role=admin
python3 rs256_to_hs256.py "$T" --pubkey public.pem --claim role=admin --claim sub=<B>
python3 kid_injection.py "$T" --kid "../../../../dev/null" --secret "" --claim role=admin
python3 jwk_inject.py "$T" --claim role=admin
python3 jwks_server.py --port 8000     # then jwt_tool -X s -ju https://YOU/jwks.json -pr key.pem
# crack:
hashcat -a 0 -m 16500 token.txt jwt.secrets.list
```

### Q104. JWE / parser / DoS cheat sheet.
```
JWE (5 parts): alg:dir weak CEK · RSA1_5 padding oracle · nested alg:none JWS · key mixups
parser: duplicate alg/claims · typ/cty · crit ignored · JSON quirks  (gateway vs backend divergence)
DoS (in scope only): JWE p2c bomb (p2c:100000000) · zip:DEF bomb · oversized key · deep nesting (CWE-400; show ratio, 1 request)
```

---

# REAL-WORLD & REFERENCES

### Q105. Real-world JWT bugs / CVE classes worth knowing.
- **CVE-2015-9235** (jsonwebtoken) — RS256→HS256 algorithm confusion (the original; re-appears in forks/configs).
- **CVE-2022-21449** "Psychic Signature" (Java 15–18) — ECDSA (0,0) blank sig accepted.
- **CVE-2018-0114** (node-jose) / **CVE-2016-5431** (ruby-jwt) — embedded-JWK / key-injection acceptance.
- **alg:none** acceptance in many old `pyjwt`/`jsonwebtoken`/`php-jwt` versions.
- **`kid` path-traversal & SQLi** in real apps; **default/leaked HS secrets** in JS/git/mobile.
- **Public-key reuse** → RS→HS (a config bug, not a leak). **OIDC** RPs missing `nonce`/`at_hash`/`azp` checks.

### Q106. Resources to work through.
PortSwigger Academy → **JWT attacks** labs (all of them); `jwt_tool` wiki; **Auth0** "Critical vulnerabilities in JSON Web Token libraries"; OWASP JWT Cheat Sheet; HackTricks *JWT*; PayloadsAllTheThings *JSON Web Token*; `wallarm/jwt-secrets`; the JWT RFCs (7519/7515/7516/7518/7517). Read disclosed reports tagged "JWT / algorithm confusion / auth bypass".

---

# DEFENSE — USING JWT SECURELY

### Q107. What's the secure design?
**Pin the algorithm** server-side (accept exactly one expected `alg`; never let the token choose) — this kills `alg:none` and RS→HS confusion. Use a **strong, secret** HMAC key (or proper asymmetric keys) kept off the client. **Never** trust `jku`/`x5u`/`jwk`/`x5c`/`kid` to select an arbitrary key — use a fixed, server-controlled key set; if you must use `kid`, treat it as an untrusted index into a strict allowlist (no file/DB/URL injection). Validate **`exp`/`nbf`/`aud`/`iss`** strictly.

### Q108. Per-risk hardening?
- **Forgery:** pin `alg`; fixed key set; reject `none`; don't honor token-supplied keys.
- **Cracking:** long random HMAC secret; rotate; keep it server-side (not in JS/mobile).
- **Lifecycle:** short `exp`; **revoke** on logout/password-change (denylist or short-lived + refresh with reuse detection); enforce `jti` for one-time tokens.
- **Cross-service/OIDC:** strictly pin `aud`+`iss` (+tenant); validate `nonce`, `at_hash`/`c_hash`, `azp`; key accounts on **(iss, sub)**.
- **kid/jku:** no injection; allowlist; treat the fetch as SSRF-sensitive.
- **JWE/DoS:** cap `p2c`; disable `zip` or bound decompression; bound key/nesting size.
- **Storage:** HttpOnly+Secure+SameSite cookies (not localStorage); never put tokens in URLs.

### Q109. One-paragraph summary you can quote.
*"A JWT is only as trustworthy as the verification step — so pin exactly one expected algorithm server-side and reject everything else (this kills `alg:none` and RS256→HS256 confusion), verify against a fixed server-controlled key set and never against a key the token supplies via `jku`/`jwk`/`x5c`/`kid`, keep the signing secret strong and off the client, and strictly validate `exp`/`aud`/`iss` (plus `nonce`/`at_hash`/`azp` for OIDC). Revoke tokens on logout and password change, key accounts on the `(iss, sub)` pair, store tokens in HttpOnly cookies rather than URLs or localStorage, and cap JWE cost. A single unpinned algorithm or a token-chosen key turns 'verify my signature' into 'forge any user' — pre-authentication account takeover for the whole application."*

---

## APPENDIX — 60-second JWT field checklist
```
[ ] Find & decode EVERY token (cookie/Bearer/URL/reset-link/OAuth id+access); record alg/kid/jku/jwk/x5c + claims
[ ] BASELINE: tamper a claim + KEEP the signature → accepted AND behavior changed? = no verification (Critical)
[ ] No-cost forges first: alg:none (+none/None/NONE/␠) · jwk-embedded (one click)
[ ] HMAC: crack offline (hashcat -m 16500; default/leaked secrets) → re-sign
[ ] RS→HS confusion: HMAC-sign with the PUBLIC key PEM (recover pubkey from 2 tokens if no JWKS)
[ ] kid injection: ../dev/null empty key · SQLi · LFI/RCE/SSRF ; jku/x5u: host your JWKS + allowlist bypass (also SSRF)
[ ] Claims: sub→other user · role/scope→admin · tenant→cross-tenant · email_verified · exp/nbf/jti/revocation
[ ] Cross-service: replay a token from another app/staging/your OAuth client (weak aud/iss)
[ ] OIDC: aud-array/azp · nonce replay · at_hash/c_hash substitution · id_token-as-access_token · (iss,sub) keying
[ ] JWE(5-part): nested alg:none/padding oracle/weak CEK ; DoS (in scope): p2c bomb / zip bomb (show 1-request ratio)
[ ] Parser confusion: duplicate alg/claims · typ/cty · crit ignored (gateway vs backend)
[ ] IMPACT: forge admin/other user → prove BEHAVIOR CHANGE with OWN accounts ; CWE-347/345/287/639 ; clean up
```
*End of guide.*
