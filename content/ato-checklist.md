# Account Takeover — Testing Checklist

**Author:** x8bitranjit
Register **two of your own accounts** (attacker `A`, victim `B`) first. Tick only what you **reproduced**, and every tick ends
"as `A` (or unauth), I reached **inside `B`**." Restore `B`'s state after. The finding is the **takeover**, not the leaked token.

## Phase 0 — Map the auth surface (§1)
- [ ] Enumerated: login · register · reset · change-email/phone · change-password · 2FA/OTP · SSO/link · session/logout
- [ ] Captured each request/response; noted the missing control (re-auth? verification? rate-limit? token binding? host source?)
- [ ] Registered/controls A and B (own emails, own listener for poisoned links)

## Phase 1 — Password reset (§2–§5)  ← flagship
- [ ] Host / `X-Forwarded-Host` / `X-Host` poisoning → reset link points to my host (trigger for B)
- [ ] Caught **B's** token at my server (or via `Referer` leak) → set B's password → **logged in as B**
- [ ] Reset token in the **response** JSON / redirect / logs
- [ ] Token weakness (own tokens): sequential / timestamp / short / low-entropy / reusable / not-bound / not-invalidated
- [ ] Email HPP / array / duplicate-key / CRLF-CC (`email=victim&email=attacker`) → token mailed to me
- [ ] `reset_url` / `callback` / `domain` body field trusted → pointed at my host
- [ ] Email normalization/unicode collision → reset for B via a "different" address

## Phase 2 — 2FA / MFA / OTP (§6–§8)
- [ ] Force-browse past the 2FA step (session issued before 2FA / skip the /2fa page)
- [ ] Response manipulation (`2fa_required:true`→false / `verified:false`→true)
- [ ] 2FA not enforced on API / mobile / legacy / SSO path
- [ ] **OTP no/resettable rate-limit** → bounded proof (N wrong codes still accepted on my own account)
- [ ] OTP reuse / null / empty / `000000` / array / type-juggle accepted
- [ ] OTP leaked in the response, or delivery changeable to my phone/email
- [ ] Disable-2FA without re-auth; recovery-code path weaker than TOTP

## Phase 3 — Email change, registration & pre-ATO (§9–§10)
- [ ] Change email with **no re-auth** / **no new-address verification** (→ set to mine → reset)
- [ ] No confirmation to the **old** email on change
- [ ] **Pre-ATO:** registered B's unverified email → B's later SSO/login **merged into my account**
- [ ] Registration collision (existing email overwrite/link; case/dot/unicode/whitespace normalization)
- [ ] Mass-assignment on register/update (`email_verified:true`, `is_admin:true`)

## Phase 4 — Session & token (§11)
- [ ] Session **fixation** (id not rotated on login)
- [ ] Session valid **after** logout / password-change / email-change (not invalidated)
- [ ] Long-lived / predictable "remember me" / trusted-device token
- [ ] Session token in URL; JWT `alg:none`/weak-secret/`kid` (→ `../JWT/`)

## Phase 5 — Authz & injection chains → ATO (§12–§13)
- [ ] **IDOR** on change-email / change-password / change-phone (userId param) — as A changed **B's** creds (→ `../IDOR/`)
- [ ] Mass-assignment/broken object-authz on account update (REST/GraphQL)
- [ ] Cashed out an existing primitive: XSS/CSRF/CORS/WebCache-deception/SSRF/JNDI/SQLi/NoSQLi/OAuth → ATO

## Phase 6 — Logic / response (§14)
- [ ] Response boolean flip on a client-trusted step
- [ ] Force-browse past email-verify / 2FA / confirm-identity
- [ ] HPP / replay / one-time-token reuse across the auth flows

## Phase 7 — Validate → report (§15–§19)
- [ ] Proof ends **"as A (or unauth), I am inside B's account"** (two own accounts, B-only marker read)
- [ ] Ruled out the FP list (§15): own-token, reflection-only, no-rate-limit-alone, own-email-change, cosmetic-cookie
- [ ] Set **CVSS + CWE** matching the vector (640/287/384/639/307) (§16)
- [ ] SAFE-PoC: two own accounts; bounded OTP/token tests; **restored B's state**; no real users touched (§18)
- [ ] De-duped to one flow/root-cause; **led with the takeover** (§19)

## AUTO-REJECT (don't submit if…)
- [ ] You only saw **your own** reset token (not a victim's leak / not a reset of B)
- [ ] Host header **reflected** but you never **received B's token** / never logged in as B
- [ ] "No rate-limit" / "token in Referer" / "cookie not HttpOnly" with **no** completed takeover
- [ ] You changed **your own** email (expected) — not B's, and no re-auth bypass
- [ ] Pre-ATO "possible" but the victim's SSO/login did **not** actually merge into your account
- [ ] Logout only fails to clear a **client** cookie (server session already invalid)

## SAFE-PoC (every time)
- [ ] Two accounts **you own**; every proof = "as A, inside B"; one B-only marker, then STOP
- [ ] Reset/token analysis on **your own** tokens; **bounded** OTP wrong-code count (prove RL absent, don't crack)
- [ ] **Restore B's** password/email; note it in the report; never touch a real user
- [ ] Recommend: high-entropy single-use bound reset tokens · server-set reset host · rate-limit+lock · re-auth+verify on change · session rotate/invalidate · verify-before-merge (pre-ATO)
