# Account Takeover (ATO) — Zero to Expert (100 Q&A)

**Author:** x8bitranjit
Study guide + field reference. Impact-first: the finding is always **"as attacker A (or unauthenticated), I'm inside victim
B's account."** Pair with `ACCOUNT_TAKEOVER_TESTING_GUIDE.md`. Authorized targets only; two accounts you own, benign marker,
restore B's state, STOP.

---

## A. Fundamentals (1–12)

**1. What is account takeover?**
Gaining full control of another user's account — their session, credentials, data, and actions — usually by breaking login, recovery, or session for *someone else's* account.

**2. Why is ATO "the money bug"?**
Triagers rate impact, and "I can log into any user's (or admin's) account" tops almost every severity table; most other bugs are only valuable because they *lead* to ATO.

**3. The three surfaces of account protection?**
Who you prove you are (login/2FA), how you recover it (reset/email-change), and how the session persists (tokens/cookies). ATO breaks any one — for another user.

**4. The one-sentence proof standard?**
Every ATO PoC ends "as attacker A (or unauthenticated), I logged into victim B's account," shown with two accounts you own.

**5. Why are ATO bugs often unauthenticated?**
Password-reset, registration, and SSO flows run *before* login, so the attacker needs no account.

**6. Primary CWEs?**
CWE-640 (weak reset), CWE-287 (improper auth), CWE-384 (session fixation), CWE-620 (unverified change), CWE-307 (auth-attempt limits/OTP), CWE-639 (IDOR-ATO).

**7. What's a "0-click" vs "1-click" ATO?**
0-click needs no victim action (reset poisoning that leaks to your server, pre-ATO, IDOR). 1-click needs the victim to open a link (reset-link Referer leak, OAuth linking CSRF).

**8. Why is ATO the "impact hub" of the kit library?**
XSS, CSRF, IDOR, SSRF, cache deception, JNDI, SQLi all "cash out" as ATO — this kit is where those primitives converge into the takeover.

**9. First operational step?**
Register two of your own accounts (attacker A, victim B) and enumerate every auth flow.

**10. What's the difference between a "lead" and a "finding" here?**
A leaked token / reflected host / missing rate-limit is a *lead*; completing the takeover of B is the *finding*.

**11. Why "report the takeover, not the condition"?**
"Token in Referer" may be closed as low; "I took over the victim by capturing their token from the Referer" is Critical — same bug, right framing.

**12. The canonical two-step ATO?**
Change the account's email (no re-auth), then trigger a password reset to the new (attacker) email.

---

## B. Password reset (13–30)

**13. What is reset-link poisoning?**
The reset email's link is built from a request-controlled host (`Host`/`X-Forwarded-Host`); poison it so the victim's token is delivered to your server.

**14. Why is it 0-click when the app server-side fetches your host?**
If the reset system itself contacts the poisoned host (or the link is server-rendered to your domain), you get the token without the victim clicking.

**15. How does the token leak via `Referer`?**
If the reset page loads third-party/attacker resources, the browser sends the full reset URL (with the token) in the `Referer` header to those hosts.

**16. What request headers do you try for poisoning?**
`Host`, `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, dual-Host/CRLF, and `Host: target:@attacker` — see the HostHeader kit.

**17. What's the strongest reset-token leak?**
The "forgot password" API returning the token/link in its **response body** — instant ATO for any email you submit.

**18. Name the reset-token weaknesses that let you forge the victim's token.**
Sequential, timestamp-based, short, low-entropy, `MD5(email)`/`MD5(email+time)`, or `base64(userid+ts)` structure.

**19. What replay flaws matter for reset tokens?**
Not single-use, non-expiring, not invalidated on email/password change, or **not bound to the user** (use your token against the victim's account).

**20. How do you test token binding?**
Request a reset for your account, then submit **your** token with the **victim's** id/email on the set-password step — if it works, tokens aren't user-bound.

**21. What is email parameter pollution in reset?**
`email=victim&email=attacker` (or array / duplicate JSON key) — the app validates one address but mails the token to the other.

**22. What's CRLF second-recipient injection?**
`email=victim@t.com%0acc:attacker@evil.com` — a newline injects a CC/BCC so the reset copy reaches the attacker.

**23. How does email normalization enable ATO?**
If register/login/reset normalize differently (case, trailing dot, `+tag`, unicode look-alikes), a "different" address maps to the victim, letting you request their reset.

**24. What body fields can poison the reset host?**
`reset_url`, `callbackUrl`, `domain`, `redirect` — some APIs trust an attacker-supplied URL to build the link.

**25. How do you analyze token strength safely?**
Collect many tokens for **your own** account and score entropy/sequential/timestamp/reuse (`reset_token_analyzer.py`) — never harvest real users' tokens.

**26. What proves a reset ATO end-to-end?**
Trigger a reset for B, obtain B's token (poison/leak/HPP/forge), set B's password, log into B, read a B-only marker, then restore.

**27. Why is a cached reset page dangerous?**
Web cache deception (WebCache kit) can lift the victim's reset URL/token from the cache.

**28. What if the reset link is one-time but the page keeps the token in the URL?**
It can leak via `Referer`, browser history, logs, or analytics even if "one-time."

**29. Severity of a forgot-password API that returns the token?**
Critical, unauthenticated — ATO for any email.

**30. Severity of host-header reset poisoning?**
Critical (0-click) when you actually capture the victim's token; the reflection alone is a lead.

---

## C. 2FA / MFA / OTP (31–45)

**31. What's the simplest 2FA bypass?**
Force-browsing: after the password step, go straight to the authenticated endpoint, skipping the 2FA page — works if a session is issued before 2FA.

**32. What's response-manipulation 2FA bypass?**
The verify step returns a client-trusted boolean (`{"verified":false}`); flip it to `true`, or the login returns a usable session before the second factor is checked.

**33. Why test the API/mobile login path?**
2FA is often enforced only on the web UI; the API, mobile, legacy, or SSO path may skip it.

**34. What makes an OTP brute-forceable?**
No (or resettable) rate-limit on the verify endpoint over a 4–6 digit space (10^4–10^6).

**35. How do you *safely* prove missing OTP rate-limit?**
Send a **bounded** number of **wrong** codes to **your own** account and show no limiter engages (`otp_bruteforce.py`) — don't actually crack a real code.

**36. Name rate-limit *bypasses* even when a limiter exists.**
Re-request the OTP to reset the counter, new session per attempt, rotate `X-Forwarded-For`, casing/trailing-space on the code, or a race.

**37. What OTP value tricks bypass verification?**
Empty/null/`000000`, arrays (`otp[]=`), type-juggling (`otp=true`), leading zeros/negatives, and reusing the last valid OTP.

**38. When is the OTP leaked?**
Some APIs return the OTP in the response, or send it to an attacker-changed phone/email.

**39. What is a 2FA delivery-hijack?**
Change the victim's phone/email (no re-auth) so the OTP is delivered to you.

**40. What's a downgrade attack on 2FA?**
Falling back to a weaker factor (SMS instead of TOTP) or a forgeable/permanent "trust this device" cookie.

**41. Why are backup/recovery codes a target?**
The recovery path is often weaker than TOTP (brute-able codes, email-OTP fallback, "lost device" flow).

**42. Can you disable a victim's 2FA?**
If the disable-2FA endpoint requires no re-auth/OTP and you have another primitive to reach their account, you turn it off then log in.

**43. What's the race-condition angle on OTP?**
Fire many parallel guesses before the limiter engages (RaceCondition kit).

**44. Severity of a 2FA bypass?**
High → Critical (it removes the second factor protecting the account).

**45. What's the "session before 2FA" bug?**
The password step issues a cookie/token already valid for sensitive actions, so the 2FA step is decorative.

---

## D. Email change, registration & pre-ATO (46–57)

**46. The canonical email-change ATO?**
Change the account email without re-auth/verification, set it to yours, then reset the password to your address.

**47. Why is "new email active before verification" a bug?**
The attacker-controlled address takes effect immediately, so recovery/notifications route to the attacker.

**48. Why does "no notification to the old email" matter?**
The real owner never learns their account was changed — silent takeover.

**49. What is pre-account-takeover?**
Register the victim's email (unverified); when they later sign up — often via SSO — the app merges/links into your pre-existing account, and you still know the password.

**50. Why does pre-ATO usually involve SSO?**
"Sign in with Google" often links to an existing local account by email without verifying ownership, merging the victim into the attacker's account.

**51. How do you test pre-ATO safely?**
Use your own second email as the "victim," register it first, then SSO-login and confirm the merge lands in your first account.

**52. What registration normalization bugs enable collisions?**
Case (`Victim@x`), trailing dot, `+tag`, whitespace, or unicode look-alikes mapping two "different" strings to one account.

**53. What is registration overwrite/link?**
Registering an existing email overwrites or links the existing account instead of rejecting the signup.

**54. What mass-assignment fields help ATO?**
`email_verified:true`, `is_admin:true`, `phone_verified:true` accepted on register/update.

**55. Severity of pre-ATO?**
High → Critical (0-click for the victim, silent, and common on SaaS with SSO).

**56. Why do most hunters miss pre-ATO?**
It requires thinking about the *merge* step, not just registration — always test "register victim's email, then SSO as victim."

**57. What invite/org flows are ATO-relevant?**
Join-org/invite flows that trust an attacker-supplied email or role, granting access to the wrong account/tenant.

---

## E. Session & token (58–67)

**58. What is session fixation?**
The app accepts a session id you set and doesn't rotate it on login, so you seed the victim's session to a value you know and share it after they authenticate.

**59. Why must sessions rotate on login/privilege change?**
Otherwise a pre-auth (or lower-priv) token stays valid at the higher level.

**60. Why must sessions invalidate on logout/password change?**
Otherwise a stolen/old session survives the "fix," so any session-theft bug becomes durable ATO.

**61. What's wrong with long-lived "remember me" tokens?**
If predictable, not device-bound, or non-expiring, they're forgeable/replayable indefinitely.

**62. Why is a session token in the URL bad?**
It leaks via `Referer`, browser history, proxy logs, and shared links.

**63. How does JWT enable ATO?**
`alg:none`, a weak HMAC secret, `kid` path/SQL injection, or missing `exp` let you forge the victim's token (JWT kit).

**64. Does "log out all devices" always revoke?**
Not if the server doesn't actually invalidate the tokens — test that a captured session dies afterward.

**65. What is concurrent-session abuse?**
Multiple valid sessions where revoking one doesn't revoke others, keeping a stolen session alive.

**66. How do you prove session non-invalidation?**
Capture a session (your own B), have B log out / change password, and show the captured session still works.

**67. Severity of session fixation / non-invalidation?**
High (it converts transient access into durable ATO).

---

## F. Authz & injection chains (68–77)

**68. What's IDOR-to-ATO?**
A change-email/password/phone endpoint authorizes by a client-supplied `userId`, so account A changes account B's credentials (IDOR kit) → reset → ATO.

**69. What's mass-assignment-to-ATO?**
A profile-update endpoint accepts `email`/`role`/`isAdmin`, letting you overwrite B's email or grant yourself admin.

**70. How does XSS become ATO?**
Steal B's session cookie or act in their session (change email) → login as B (XSS kit).

**71. How does CSRF become ATO?**
Force B to change their email/password/2FA when the sensitive action lacks anti-CSRF (CSRF kit).

**72. How does CORS misconfig become ATO?**
`Access-Control-Allow-Origin: *`/reflected + credentials on `/api/me` lets you read B's token/CSRF/email cross-origin (CORS kit).

**73. How does web cache deception become ATO?**
Lift B's authenticated page (with token/CSRF) from the cache (WebCache kit).

**74. How does SSRF/JNDI become ATO?**
RCE or secret access lets you forge any session or read the DB (SSRF/JNDI kits).

**75. How does SQLi/NoSQLi become ATO?**
Auth bypass or dumping password hashes/reset tokens (SQLi/NoSQLi kits).

**76. How does OAuth become ATO?**
`redirect_uri`/code theft, `state`-CSRF account linking, `id_token` forgery, or unverified-email pre-ATO (OAuth kit).

**77. How does a race condition become ATO?**
Parallel OTP/reset/link requests bypass single-use limits (RaceCondition kit).

---

## G. Logic & response (78–83)

**78. What's a response-boolean-flip ATO?**
A client-trusted step returns `success/verified/role` that you flip to skip a control or elevate.

**79. What's step force-browsing?**
Skipping email-verify / 2FA / confirm-identity by hitting the final authenticated endpoint directly.

**80. What is HTTP parameter pollution in auth flows?**
Sending duplicate `email`/`id`/`user` values so the validation and the action disagree.

**81. What's replay in auth flows?**
Reusing a one-time token/OTP/magic-link, or using a step's token out of order or for another user.

**82. Why is client-side flow control dangerous?**
Any decision made in the response and trusted by the next request can be flipped by the attacker.

**83. What's status-code reliance?**
The client treats HTTP 200 as success — replaying a step with a changed outcome bypasses the check.

---

## H. Validity, false positives & severity (84–93)

**84. The golden proof standard again?**
"As attacker A (or unauthenticated), I'm inside victim B's account," shown with two accounts you own and a B-only marker.

**85. Top false positive?**
Seeing your **own** reset token and calling it a leak — you must leak/reset a **victim's** account.

**86. Second false positive?**
A reflected host header with no captured victim token / no login as B.

**87. Third false positive?**
"No rate-limit" or "token in Referer" with no completed takeover.

**88. Why isn't changing your own email a finding?**
That's expected; you must change **B's** (IDOR/CSRF) or bypass re-auth to reach ATO.

**89. Why isn't a missing `HttpOnly` flag alone an ATO?**
It's a hardening nit until you show a concrete session-theft → login as B.

**90. When is pre-ATO a false positive?**
When you only registered the email but the victim's later SSO/login didn't actually merge into your account.

**91. CVSS anchor for 0-click unauth ATO?**
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` ≈ 9.8.

**92. What downgrades an ATO finding?**
Requiring an implausible precondition, only working on your own account, or stopping at the primitive without the takeover.

**93. Why re-test partial fixes?**
Fixing one reset-poison header but not another, or rate-limiting web but not the API OTP path, is a fresh valid finding.

---

## I. SAFE-PoC, reporting & red-team (94–100)

**94. The one safety rule?**
Prove ATO with two accounts you control, take over B once with a benign marker, **restore B's state**, and stop — never touch a real user.

**95. How do you keep OTP/token tests safe?**
Bounded wrong-code counts (prove the limiter is absent, don't crack), and analyze only your own tokens.

**96. What must a report contain?**
The vector + endpoint + missing control, the two-account steps, the cross-account proof (B-only marker), and a note that you restored B.

**97. How do you de-duplicate?**
One flow/root-cause = one report; lead with the takeover and list the contributing primitives (reset poisoning + its host reflection = one report).

**98. Best red-team ATO play on SaaS?**
Pre-account-takeover: pre-register the target's corporate email before onboarding, so their SSO silently lands in your account.

**99. Best red-team play on stolen sessions?**
Exploit session non-invalidation so one phished/XSS'd session becomes permanent access.

**100. Final checklist before submitting?**
Ended inside B? Two own accounts + benign marker? Bounded/own-token tests? B restored? Vector-matched CWE/CVSS? Remediation given? All yes → it's the Critical it's worth.

---

> **The one rule that pays:** ATO is proven only when you end up **inside another account** — break the weakest of login / recovery / session for *someone else's* account, show it with **two accounts you own** and a benign marker, restore state, and report the **takeover** (not the token or header that got you there).
