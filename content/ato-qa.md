# Account Takeover (ATO) — Zero to Expert (120 Q&A)

**Author:** x8bitranjit
Study guide + field reference. Impact-first: the finding is always **"as attacker A (or unauthenticated), I'm inside victim
B's account."** Pair with `ACCOUNT_TAKEOVER_TESTING_GUIDE.md`. Authorized targets only; two accounts you own, benign marker,
restore B's state, STOP.

> 🧭 **New to this? The one picture to hold.** An online account is a **locked apartment** with three ways in: the **front door** (log in with password + 2FA), the **emergency spare key** (the "forgot password" / recovery flow), and the **wristband that proves you already entered** (your session cookie). A burglar only needs **one** of those to be sloppy. Account takeover = finding that one weak entry on *someone else's* apartment and walking in. Every question below is a detail about one of those three doors. Jargon is defined the first time it appears; when it piles up, come back to the apartment.

---

## A. Fundamentals (1–12)

**1. What is account takeover?**
Gaining full control of another user's account — their session, credentials, data, and actions — usually by breaking login, recovery, or session for *someone else's* account.
*Plain version:* you end up **logged in as somebody else** — reading their DMs, spending their balance, changing their settings — without legitimately knowing their password. It's the digital equivalent of getting into a stranger's locked apartment; the rest of this guide is *which* of the three doors you jimmied.

**2. Why is ATO "the money bug"?**
Triagers rate impact, and "I can log into any user's (or admin's) account" tops almost every severity table; most other bugs are only valuable because they *lead* to ATO.
*Why:* bounties pay for **impact**, and "I can become any user, including admin" is about the worst thing that can happen to an app, so it sits at the top of every payout table. That's why experienced hunters treat smaller bugs (an XSS, an IDOR) as *ingredients* and keep asking "can I cook this into a takeover?"

**3. The three surfaces of account protection?**
Who you prove you are (login/2FA), how you recover it (reset/email-change), and how the session persists (tokens/cookies). ATO breaks any one — for another user.
*The apartment again:* front door (login/2FA), spare key (reset/email-change), wristband (session/cookie). The defender must lock **all three**; you only need **one** left sloppy. Map all three before picking a fight.

**4. The one-sentence proof standard?**
Every ATO PoC ends "as attacker A (or unauthenticated), I logged into victim B's account," shown with two accounts you own.
*Meaning:* your evidence isn't "a token looked weak" — it's a screenshot of you **sitting inside a second account you own (B)**, having gotten there from A (or from no account at all). If your proof doesn't end *inside B*, you're not done.

**5. Why are ATO bugs often unauthenticated?**
Password-reset, registration, and SSO flows run *before* login, so the attacker needs no account.
*Why it matters:* "unauthenticated" (anyone on the internet, no login) makes a bug far more severe. The recovery and signup doors live *outside* the login wall by design, so a flaw there is reachable by a total stranger — which is exactly why reset-flow bugs score so high.

**6. Primary CWEs?**
CWE-640 (weak reset), CWE-287 (improper auth), CWE-384 (session fixation), CWE-620 (unverified change), CWE-307 (auth-attempt limits/OTP), CWE-639 (IDOR-ATO).
*(CWE = a standardized ID for a bug *type*, so triagers and tools speak one language. You tag your report with the one matching the door you broke — e.g. reset flaw → CWE-640.)*

**7. What's a "0-click" vs "1-click" ATO?**
0-click needs no victim action (reset poisoning that leaks to your server, pre-ATO, IDOR). 1-click needs the victim to open a link (reset-link Referer leak, OAuth linking CSRF).
*Why the distinction pays:* the **less** the victim has to do, the higher the severity. 0-click (you take over while they sleep) beats 1-click (they have to click your link) beats "they have to be socially engineered." Always note which yours is.

**8. Why is ATO the "impact hub" of the kit library?**
XSS, CSRF, IDOR, SSRF, cache deception, JNDI, SQLi all "cash out" as ATO — this kit is where those primitives converge into the takeover.
*Analogy:* those other bugs are **tools that steal a piece of someone's identity** (a cookie, a token, a form-submit); ATO is **what you spend it on**. This kit is the cash register where every stolen primitive gets converted into "I'm now inside their account."

**9. First operational step?**
Register two of your own accounts (attacker A, victim B) and enumerate every auth flow.
*Do this literally first:* make **A** (you, the attacker) and **B** (your pretend victim). Now every experiment is "as A, can I get into B?" — safe, legal, and exactly the shape of a valid report. Then list every login/reset/2FA/email/SSO/session flow to attack.

**10. What's the difference between a "lead" and a "finding" here?**
A leaked token / reflected host / missing rate-limit is a *lead*; completing the takeover of B is the *finding*.
*The hard lesson:* a lead is "the door *looks* unlocked." A finding is "I **walked through** it into B's account." Beginners file leads and get them closed as low/duplicate; pros push the lead all the way to the takeover before writing a word.

**11. Why "report the takeover, not the condition"?**
"Token in Referer" may be closed as low; "I took over the victim by capturing their token from the Referer" is Critical — same bug, right framing.
*Same evidence, different payout:* describing the *condition* invites a shrug; describing the *takeover it enables* forces the triager to see the real impact. Lead with "I got into B," then explain the token/header that let you.

**12. The canonical two-step ATO?**
Change the account's email (no re-auth), then trigger a password reset to the new (attacker) email.
*The move to memorize:* if you can point an account's email at an address **you** control (because the change needs no password re-check), then just click "forgot password" — the reset link now comes to **you**. Two ordinary features, chained, equal full takeover. This pattern shows up constantly.

---

## B. Password reset (13–30)

**13. What is reset-link poisoning?**
The reset email's link is built from a request-controlled host (`Host`/`X-Forwarded-Host`); poison it so the victim's token is delivered to your server.
*Plain version:* to build the reset link, lazy servers read their own domain from the **`Host` header of your request** — which you control. Send the "reset password for **victim**" request with `Host: attacker.com`, and the server emails the *victim* a link pointing at *your* site. They click, their secret token flies to you, you set their password. See the guide's §2 for the full walk-through.

**14. Why is it 0-click when the app server-side fetches your host?**
If the reset system itself contacts the poisoned host (or the link is server-rendered to your domain), you get the token without the victim clicking.
*Meaning:* sometimes you don't even need the victim to click — if the server *itself* reaches out to your poisoned host (e.g. to render a preview, or the token is embedded server-side), the token lands on your server automatically. No victim action = the most severe flavor.

**15. How does the token leak via `Referer`?**
If the reset page loads third-party/attacker resources, the browser sends the full reset URL (with the token) in the `Referer` header to those hosts.
*Why:* the `Referer` header is the browser politely telling every image/script/analytics call "hey, I came from *this* URL." If the reset page (whose URL contains the secret token) loads any third-party resource, the browser leaks that whole token-bearing URL to it — including anything you can get loaded on that page.

**16. What request headers do you try for poisoning?**
`Host`, `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, dual-Host/CRLF, and `Host: target:@attacker` — see the HostHeader kit.
*(These are just different envelopes for the same trick — various headers a server might trust as "my domain." When the obvious `Host` is validated, one of the `X-Forwarded-*` variants often slips through. Full menu: the HostHeader kit.)*

**17. What's the strongest reset-token leak?**
The "forgot password" API returning the token/link in its **response body** — instant ATO for any email you submit.
*Why it's the jackpot:* if the "send reset" API literally hands the token back in its **own response**, you don't need the victim, an email, or a click — type any victim's email, read the token from the response, reset. Instant, unauthenticated ATO for **anyone**. Always inspect the raw response of the forgot-password call.

**18. Name the reset-token weaknesses that let you forge the victim's token.**
Sequential, timestamp-based, short, low-entropy, `MD5(email)`/`MD5(email+time)`, or `base64(userid+ts)` structure.
*Plain version:* the token is only safe if it's **unguessable**. If it's secretly built from a recipe — a number that ticks up, the clock, or a hash of the email — you can **compute the victim's token without seeing it**. Collect several of your own and look for the pattern (Q25).

**19. What replay flaws matter for reset tokens?**
Not single-use, non-expiring, not invalidated on email/password change, or **not bound to the user** (use your token against the victim's account).
*The subtle killer is "not bound to the user":* if the token isn't tied to a *specific* account, you can take a valid token from **your** reset and submit it alongside the **victim's** email/id — one valid token, any account. The others (reusable, never-expiring, not cancelled on change) all mean an old/leaked token keeps working when it shouldn't.

**20. How do you test token binding?**
Request a reset for your account, then submit **your** token with the **victim's** id/email on the set-password step — if it works, tokens aren't user-bound.
*Concretely:* get a legit reset token for **A** (yours), then on the "set new password" step swap in **B's** id/email while keeping A's token. If the server accepts it and changes B's password, the token wasn't bound to A → direct ATO. Simple, decisive test with your two accounts.

**21. What is email parameter pollution in reset?**
`email=victim&email=attacker` (or array / duplicate JSON key) — the app validates one address but mails the token to the other.
*Plain version:* you send the email field **twice**. Buggy servers **check one copy but send the mail to the other**, so a token minted for the victim's account arrives in *your* inbox. "HPP" = HTTP Parameter Pollution, the general name for "send a parameter twice and see which one wins."

**22. What's CRLF second-recipient injection?**
`email=victim@t.com%0acc:attacker@evil.com` — a newline injects a CC/BCC so the reset copy reaches the attacker.
*Plain version:* `%0a` is an encoded newline. If the app pastes your input straight into the email headers, that newline lets you bolt on a `cc:` line — so the reset email is silently **copied to you** as well as the victim.

**23. How does email normalization enable ATO?**
If register/login/reset normalize differently (case, trailing dot, `+tag`, unicode look-alikes), a "different" address maps to the victim, letting you request their reset.
*Plain version:* `Victim@x.com`, `victim@x.com.` (trailing dot), and `vіctim@x.com` (Cyrillic "і") may look distinct to one part of the app and identical to another. That mismatch lets you request a reset the app treats as "someone else" but delivers to the victim's real mailbox (or yours).

**24. What body fields can poison the reset host?**
`reset_url`, `callbackUrl`, `domain`, `redirect` — some APIs trust an attacker-supplied URL to build the link.
*Same as Host-poisoning but easier:* instead of smuggling a header, some JSON APIs literally include a "where should the link point?" field. Set it to your domain and the reset link is built around your host — token capture handed to you.

**25. How do you analyze token strength safely?**
Collect many tokens for **your own** account and score entropy/sequential/timestamp/reuse (`reset_token_analyzer.py`) — never harvest real users' tokens.
*The safe method:* fire off a dozen resets for **your own** account, line up the tokens, and let the script measure whether they're truly random or follow a pattern. You're studying the *recipe* using your own tokens — you never collect a real user's, which would be both useless as proof and unethical.

**26. What proves a reset ATO end-to-end?**
Trigger a reset for B, obtain B's token (poison/leak/HPP/forge), set B's password, log into B, read a B-only marker, then restore.
*The full receipt:* reset **B** → get B's token by whichever flaw → set B's password → **log in as B** → read something only B can see (B's email on the profile) → put B's password back. That complete chain — not any single step — is the finding.

**27. Why is a cached reset page dangerous?**
Web cache deception (WebCache kit) can lift the victim's reset URL/token from the cache.
*Plain version:* if a shared cache (CDN) accidentally stores the victim's reset page, you may be able to request the cached copy and read their token out of it. See the WebCache kit for how to trick a cache into storing a private page.

**28. What if the reset link is one-time but the page keeps the token in the URL?**
It can leak via `Referer`, browser history, logs, or analytics even if "one-time."
*Why "one-time" isn't enough:* the token being single-*use* doesn't stop it from being **seen**. While it's sitting in the URL bar, it bleeds into the `Referer` sent to third parties (Q15), browser history, server logs, and analytics — any of which an attacker might reach before it's used.

**29. Severity of a forgot-password API that returns the token?**
Critical, unauthenticated — ATO for any email.
*(Anyone, no login, any victim, instantly — every severity dial maxed. Critical.)*

**30. Severity of host-header reset poisoning?**
Critical (0-click) when you actually capture the victim's token; the reflection alone is a lead.
*The caveat that saves your report:* it's Critical **once you've actually caught B's token and logged in**. Just showing the Host is reflected in the link is only a *lead* (Q10) — finish the capture before you claim Critical.

---

## C. 2FA / MFA / OTP (31–45)

**31. What's the simplest 2FA bypass?**
Force-browsing: after the password step, go straight to the authenticated endpoint, skipping the 2FA page — works if a session is issued before 2FA.
*Plain version:* 2FA is a second locked door after the password. "Force-browsing" is walking *around* it: if the app already gave you a logged-in cookie after the password step, just type the account-page URL directly and ignore the "enter your code" screen. The code check was only a UI speed-bump, not a real wall.

**32. What's response-manipulation 2FA bypass?**
The verify step returns a client-trusted boolean (`{"verified":false}`); flip it to `true`, or the login returns a usable session before the second factor is checked.
*Plain version:* the app foolishly asks *your own browser* "was 2FA satisfied?" and believes the answer. Intercept the response, change `false` to `true`, and you're waved through. Any security decision the server lets the client make can be flipped by the client.

**33. Why test the API/mobile login path?**
2FA is often enforced only on the web UI; the API, mobile, legacy, or SSO path may skip it.
*Why:* teams bolt 2FA onto the shiny website but forget the app's raw API endpoint or an old legacy login. Log in through *that* door and the second factor may simply never be asked. Always try every login entry point, not just the main web form.

**34. What makes an OTP brute-forceable?**
No (or resettable) rate-limit on the verify endpoint over a 4–6 digit space (10^4–10^6).
*Plain version:* a 6-digit code has a million combinations — impossible to guess in 5 tries, trivial in unlimited tries. If the server never blocks you (or the block resets), a script just tries them all. The whole safety of an OTP is the try-limit; remove it and the code is gone.

**35. How do you *safely* prove missing OTP rate-limit?**
Send a **bounded** number of **wrong** codes to **your own** account and show no limiter engages (`otp_bruteforce.py`) — don't actually crack a real code.
*The safe proof:* fire, say, 50–100 deliberately *wrong* codes at **your own** account and show you're never blocked. "The cap should be 5; I sent 100 and sailed through" fully proves the bug — you never need to actually crack a real victim's code (that's crossing into real attack).

**36. Name rate-limit *bypasses* even when a limiter exists.**
Re-request the OTP to reset the counter, new session per attempt, rotate `X-Forwarded-For`, casing/trailing-space on the code, or a race.
*Plain version:* even with a limiter, you look for the thing it *forgot* to count by — request a fresh code to zero the counter, start a new session each burst, spoof a new client IP via `X-Forwarded-For`, or tweak the code's formatting so it looks "new." Each makes the server think it's a fresh, un-limited attempt.

**37. What OTP value tricks bypass verification?**
Empty/null/`000000`, arrays (`otp[]=`), type-juggling (`otp=true`), leading zeros/negatives, and reusing the last valid OTP.
*Plain version:* sometimes the check itself is buggy — sending an empty value, an array, or `true` instead of digits can make a sloppy comparison return "match." Also try the *previous* code (some servers never expire the old one). Cheap to test, occasionally a free pass.

**38. When is the OTP leaked?**
Some APIs return the OTP in the response, or send it to an attacker-changed phone/email.
*Plain version:* the "send OTP" call sometimes hands the code back **in its own response** (there for the app's convenience, disastrous for security), or you've already redirected delivery to your own phone/email (Q39). Either way you just read the code you were supposed to have to receive.

**39. What is a 2FA delivery-hijack?**
Change the victim's phone/email (no re-auth) so the OTP is delivered to you.
*Plain version:* if you can change *where* the code is sent — swap the phone/email without re-authenticating — then the OTP the server dutifully sends "to the account owner" arrives at **your** device. You didn't beat the code; you rerouted it.

**40. What's a downgrade attack on 2FA?**
Falling back to a weaker factor (SMS instead of TOTP) or a forgeable/permanent "trust this device" cookie.
*Plain version:* if you can force the login to use the **weakest** available second factor (SMS you can intercept, an email-OTP, a "remember this device" cookie that's guessable or never expires) instead of a strong app-based code, you've quietly lowered the wall to something you can climb.

**41. Why are backup/recovery codes a target?**
The recovery path is often weaker than TOTP (brute-able codes, email-OTP fallback, "lost device" flow).
*Why:* the "I lost my authenticator" path exists so real users aren't locked out — so it's deliberately *easier*, and often under-protected. That makes it the soft underbelly of 2FA: attack the recovery route, not the strong front code.

**42. Can you disable a victim's 2FA?**
If the disable-2FA endpoint requires no re-auth/OTP and you have another primitive to reach their account, you turn it off then log in.
*Plain version:* if turning 2FA **off** doesn't itself require the password or a code, and you already have some foothold (a stolen session, a CSRF), you just flip 2FA off on the victim, then log in with only the password — second factor removed.

**43. What's the race-condition angle on OTP?**
Fire many parallel guesses before the limiter engages (RaceCondition kit).
*Plain version:* send a burst of guesses **at the exact same instant** so they all pass the "attempts left?" check before the counter can climb — effectively unlimited tries in one shot, even against a limiter. Full technique in the RaceCondition kit.

**44. Severity of a 2FA bypass?**
High → Critical (it removes the second factor protecting the account).
*(You've knocked out the entire second line of defense — often the last thing standing between a leaked password and the account. High, Critical when it lands you in the account.)*

**45. What's the "session before 2FA" bug?**
The password step issues a cookie/token already valid for sensitive actions, so the 2FA step is decorative.
*Plain version:* the root cause behind Q31 — the server hands you a **real, working session** right after the password, *before* checking the code. So the 2FA page is just for show; the wristband's already on your wrist.

---

## D. Email change, registration & pre-ATO (46–57)

**46. The canonical email-change ATO?**
Change the account email without re-auth/verification, set it to yours, then reset the password to your address.
*This is Q12 again, because it's that important:* point the account's email at yourself (no password re-check), then "forgot password" → the reset comes to you. Two harmless features, chained into a takeover.

**47. Why is "new email active before verification" a bug?**
The attacker-controlled address takes effect immediately, so recovery/notifications route to the attacker.
*Plain version:* the app should keep the *old* email in charge until you prove you own the *new* one. If the new address goes live instantly, all the "we sent a code to your email" recovery paths now point at the attacker before anyone confirmed anything.

**48. Why does "no notification to the old email" matter?**
The real owner never learns their account was changed — silent takeover.
*Why:* a "your email was changed — was this you?" alert to the *old* address is the tripwire that lets a victim react. No alert = the takeover is **invisible**, which raises severity and is a concrete thing to flag in your report.

**49. What is pre-account-takeover?**
Register the victim's email (unverified); when they later sign up — often via SSO — the app merges/links into your pre-existing account, and you still know the password.
*Plain version:* you **claim their account before they do.** Sign up with the victim's email + your own password; later, when they log in with Google, the app glues their login onto the account **you** already made — and your password still works. Analogy: you filed the deed on their house before move-in, so your key still opens the door.

**50. Why does pre-ATO usually involve SSO?**
"Sign in with Google" often links to an existing local account by email without verifying ownership, merging the victim into the attacker's account.
*Why SSO is the trigger:* when the victim clicks "Sign in with Google," the app sees a *Google-verified* email that matches an account already on file (yours) and helpfully **merges** them — trusting Google's verification to cover the account *you* created unverified. That merge is the moment of takeover.

**51. How do you test pre-ATO safely?**
Use your own second email as the "victim," register it first, then SSO-login and confirm the merge lands in your first account.
*Safe recipe:* your two-address setup **is** the test — register email B the "attacker-first" way, then do the Google login for B and check whether you land in the account you pre-made. No real victim ever involved.

**52. What registration normalization bugs enable collisions?**
Case (`Victim@x`), trailing dot, `+tag`, whitespace, or unicode look-alikes mapping two "different" strings to one account.
*Plain version:* the app should treat `Victim@x.com` and `victim@x.com` as the same person — if it doesn't during signup but *does* during login/reset, you get two "different" registrations that collapse into one account, opening collision/takeover angles.

**53. What is registration overwrite/link?**
Registering an existing email overwrites or links the existing account instead of rejecting the signup.
*Plain version:* signing up with an email that *already exists* should be refused. If instead it **overwrites or attaches to** the existing account, you've just co-opted someone else's account by "registering."

**54. What mass-assignment fields help ATO?**
`email_verified:true`, `is_admin:true`, `phone_verified:true` accepted on register/update.
*Plain version:* if the signup/update form blindly accepts whatever JSON fields you send, you slip in `"email_verified":true` (to fuel the pre-ATO merge) or `"is_admin":true` (to just become admin). The app writes fields it never meant to expose. (Deep dive: mass assignment in the IDOR/REST kits.)

**55. Severity of pre-ATO?**
High → Critical (0-click for the victim, silent, and common on SaaS with SSO).
*(The victim does nothing wrong, gets no warning, and it's rampant on SSO-enabled SaaS — a quiet, high-value bug. High to Critical.)*

**56. Why do most hunters miss pre-ATO?**
It requires thinking about the *merge* step, not just registration — always test "register victim's email, then SSO as victim."
*Why it's overlooked:* registering someone's email feels like a non-event ("so what, I can't get in"). The bug only reveals itself at the **later merge**, which most people never test. The one-line habit that catches it: *register the victim's email, then SSO-login as the victim and see where you land.*

**57. What invite/org flows are ATO-relevant?**
Join-org/invite flows that trust an attacker-supplied email or role, granting access to the wrong account/tenant.
*Plain version:* "invite a teammate" / "join this org" features often trust the email and role *you* type. Abuse them to attach yourself to someone else's organization or grant yourself a higher role — tenant-level takeover instead of single-account.

---

## E. Session & token (58–67)

**58. What is session fixation?**
The app accepts a session id you set and doesn't rotate it on login, so you seed the victim's session to a value you know and share it after they authenticate.
*Plain version:* instead of *stealing* the victim's wristband, you **hand them one you already have a copy of.** Plant a session id in their browser, wait for them to log in; if the app "upgrades" that same id to logged-in instead of issuing a fresh one, your matching copy is now an authenticated session for their account.

**59. Why must sessions rotate on login/privilege change?**
Otherwise a pre-auth (or lower-priv) token stays valid at the higher level.
*Why:* a fresh id at login is what defeats fixation (Q58) — the id you planted becomes worthless the instant they authenticate. Same on privilege change: a low-priv token shouldn't silently keep working after you're granted admin.

**60. Why must sessions invalidate on logout/password change?**
Otherwise a stolen/old session survives the "fix," so any session-theft bug becomes durable ATO.
*The nasty one:* if a session keeps working *after* the user logs out or changes their password, then a victim who suspects compromise **can't evict you** by doing the obvious thing. This turns any one-time session theft into *permanent* access — always test it.

**61. What's wrong with long-lived "remember me" tokens?**
If predictable, not device-bound, or non-expiring, they're forgeable/replayable indefinitely.
*Plain version:* "remember me" trades convenience for a long-lived key. If that key is guessable, not tied to the device, or never expires, it's a skeleton key an attacker can forge or reuse forever.

**62. Why is a session token in the URL bad?**
It leaks via `Referer`, browser history, proxy logs, and shared links.
*Plain version:* a session in the URL is a live key printed on the outside of the envelope — it bleeds into the `Referer` sent to third parties, the browser history, proxy logs, and any link the user copy-pastes. Cookies exist precisely so the key *isn't* in the URL.

**63. How does JWT enable ATO?**
`alg:none`, a weak HMAC secret, `kid` path/SQL injection, or missing `exp` let you forge the victim's token (JWT kit).
*Plain version:* a JWT is a self-contained "I am user X, signed by the server" ticket. If the signature can be skipped (`alg:none`), cracked (weak secret), or tricked (`kid` injection), you **forge a ticket that says you're the victim** — instant ATO. Full toolkit in the JWT kit.

**64. Does "log out all devices" always revoke?**
Not if the server doesn't actually invalidate the tokens — test that a captured session dies afterward.
*Why test it:* the button *claims* to kill every session, but sometimes it just clears the current cookie and leaves other tokens alive on the server. Capture a session, hit "log out all devices," and check whether your captured one still works.

**65. What is concurrent-session abuse?**
Multiple valid sessions where revoking one doesn't revoke others, keeping a stolen session alive.
*Plain version:* if a user can be logged in from many places at once and killing one session doesn't kill the rest, then a stolen session survives even when the victim logs out *their* device. Your copy keeps working.

**66. How do you prove session non-invalidation?**
Capture a session (your own B), have B log out / change password, and show the captured session still works.
*The clean two-account proof:* grab B's session token, then (as B) log out and change B's password, then replay the captured token — if it still loads B's account, you've shown the session outlives the "fix." Decisive, safe, and all on accounts you own.

**67. Severity of session fixation / non-invalidation?**
High (it converts transient access into durable ATO).
*(On its own it's High; more importantly it's a *force-multiplier* — it upgrades any fleeting session-theft bug into permanent access.)*

---

## F. Authz & injection chains (68–77)

**68. What's IDOR-to-ATO?**
A change-email/password/phone endpoint authorizes by a client-supplied `userId`, so account A changes account B's credentials (IDOR kit) → reset → ATO.
*Plain version:* the request says *which* account to edit via an id you can just change — `POST /user/1337/email`. Swap `1337` for B's id and, if the server doesn't check "is this *your* account?", you edit **B's** email, then reset to it. One of the most common real ATOs. (IDOR = Insecure Direct Object Reference.)

**69. What's mass-assignment-to-ATO?**
A profile-update endpoint accepts `email`/`role`/`isAdmin`, letting you overwrite B's email or grant yourself admin.
*Plain version:* the update form accepts extra fields it shouldn't. Send `"role":"admin"` or someone else's `"email"` and the app writes them — you promote yourself or hijack an address the app never meant to let you touch.

**70. How does XSS become ATO?**
Steal B's session cookie or act in their session (change email) → login as B (XSS kit).
*Plain version:* XSS = you get your JavaScript running inside the victim's page. That script can read their session cookie (send it to you) or click "change email" *as them*. Don't stop at "I popped an alert box" — drive it to "I'm now logged in as them."

**71. How does CSRF become ATO?**
Force B to change their email/password/2FA when the sensitive action lacks anti-CSRF (CSRF kit).
*Plain version:* CSRF tricks the victim's *own* browser into submitting a request they didn't intend. Point it at "change my email to attacker@evil" — if the form has no anti-CSRF token, the victim silently sets their email to yours, and you reset in.

**72. How does CORS misconfig become ATO?**
`Access-Control-Allow-Origin: *`/reflected + credentials on `/api/me` lets you read B's token/CSRF/email cross-origin (CORS kit).
*Plain version:* CORS rules decide which *other* sites may read a response. Misconfigured, they let **your** site fetch the victim's logged-in `/api/me` and read their token/email — handing you the secrets you need to become them.

**73. How does web cache deception become ATO?**
Lift B's authenticated page (with token/CSRF) from the cache (WebCache kit).
*Plain version:* you trick a shared cache into storing the victim's *private, logged-in* page, then fetch the cached copy yourself and read their secrets out of it. (Full trick in the WebCache kit.)

**74. How does SSRF/JNDI become ATO?**
RCE or secret access lets you forge any session or read the DB (SSRF/JNDI kits).
*Plain version:* these get you *server-side* power — reaching internal services, secrets, or code execution. With server secrets you can forge any session or read the user table directly. It's ATO from the back end instead of the front.

**75. How does SQLi/NoSQLi become ATO?**
Auth bypass or dumping password hashes/reset tokens (SQLi/NoSQLi kits).
*Plain version:* injecting into the database query lets you either **skip the login check** (`' OR '1'='1`) or **dump the password-hash / reset-token table** and work from there. Straight line from a query bug to owning accounts.

**76. How does OAuth become ATO?**
`redirect_uri`/code theft, `state`-CSRF account linking, `id_token` forgery, or unverified-email pre-ATO (OAuth kit).
*Plain version:* the "Sign in with Google/Facebook" dance has several steal-points — redirect the auth `code` to yourself, CSRF the account-linking step, forge the identity token, or ride the pre-ATO merge (Q49). Any one lands you in the account. (Full flow: OAuth kit.)

**77. How does a race condition become ATO?**
Parallel OTP/reset/link requests bypass single-use limits (RaceCondition kit).
*Plain version:* fire many OTP/reset/magic-link requests **at the same instant** so they all slip past a "once only" or "5 tries" limit before it engages — turning a limited gate into an open one. (Full technique: RaceCondition kit.)

---

## G. Logic & response (78–83)

**78. What's a response-boolean-flip ATO?**
A client-trusted step returns `success/verified/role` that you flip to skip a control or elevate.
*Plain version:* the server sends your browser a little yes/no (`"verified":false`, `"role":"user"`) and then *trusts whatever comes back*. Intercept, flip it to `true`/`admin`, and you've skipped a check or promoted yourself. The rule: never trust the client to report its own security state.

**79. What's step force-browsing?**
Skipping email-verify / 2FA / confirm-identity by hitting the final authenticated endpoint directly.
*Plain version:* multi-step flows assume you go 1→2→3. Force-browsing is jumping straight to step 3's URL, skipping the "verify" or "2FA" steps in the middle — works whenever the final step doesn't re-check that the earlier ones happened.

**80. What is HTTP parameter pollution in auth flows?**
Sending duplicate `email`/`id`/`user` values so the validation and the action disagree.
*Plain version:* send the same field twice (`email=victim&email=attacker`) so the part that *checks* it and the part that *uses* it pick different copies — the check passes on one value, the action runs on the other. (Same trick as Q21, generalized to any auth field.)

**81. What's replay in auth flows?**
Reusing a one-time token/OTP/magic-link, or using a step's token out of order or for another user.
*Plain version:* "one-time" things should die after one use. Replay = using them again, out of order, or for a *different* account — e.g. taking a step-token issued for you and submitting it against the victim. Tests whether "single-use" is actually enforced.

**82. Why is client-side flow control dangerous?**
Any decision made in the response and trusted by the next request can be flipped by the attacker.
*The principle behind Q78:* the attacker fully controls their own browser and every byte it sends back. So *any* security decision left to the client (a boolean, a hidden field, a step marker) is a decision the attacker gets to make. Security decisions must live on the server.

**83. What's status-code reliance?**
The client treats HTTP 200 as success — replaying a step with a changed outcome bypasses the check.
*Plain version:* if the app decides "it worked!" purely because the server replied `200 OK`, you can sometimes force a 200 (or replay a step) to fake success even when the underlying action failed or wasn't allowed.

---

## H. Validity, false positives & severity (84–93)

**84. The golden proof standard again?**
"As attacker A (or unauthenticated), I'm inside victim B's account," shown with two accounts you own and a B-only marker.
*It's repeated because it's the whole game:* if your write-up can't end with "here I am inside B, here's a thing only B can see," you don't have an ATO yet. Everything else is supporting detail.

**85. Top false positive?**
Seeing your **own** reset token and calling it a leak — you must leak/reset a **victim's** account.
*Why it's a non-finding:* of course you can see your own token — it's *your* reset. It's only a bug if a *different* account's token reaches you. Don't confuse "I can see my own key" with "I stole someone's key."

**86. Second false positive?**
A reflected host header with no captured victim token / no login as B.
*Why:* the header being echoed in the link is a *lead* (Q30) — it shows the door *might* be openable. Without actually catching B's token and logging in, there's no takeover to report.

**87. Third false positive?**
"No rate-limit" or "token in Referer" with no completed takeover.
*Same lesson, common form:* "there's no rate-limit" or "the token appears in the Referer" are *ingredients*. Cook them into an actual takeover (brute the code, catch the token, log in as B) before filing, or expect a "low/informational" close.

**88. Why isn't changing your own email a finding?**
That's expected; you must change **B's** (IDOR/CSRF) or bypass re-auth to reach ATO.
*Plain version:* editing *your own* account is the feature working as designed. The bug is editing *someone else's* (via IDOR/CSRF) or skipping the re-auth that's supposed to protect the change.

**89. Why isn't a missing `HttpOnly` flag alone an ATO?**
It's a hardening nit until you show a concrete session-theft → login as B.
*Plain version:* `HttpOnly` missing *would* let JavaScript read the cookie — but only if you also have a way to run JavaScript there (an XSS). By itself it's a best-practice nit; paired with a real theft it becomes part of an ATO chain.

**90. When is pre-ATO a false positive?**
When you only registered the email but the victim's later SSO/login didn't actually merge into your account.
*Why:* registering their email proves nothing on its own (Q56). It's only pre-ATO if the victim's *later* login actually lands in the account you made — you must demonstrate the merge, not just the pre-registration.

**91. CVSS anchor for 0-click unauth ATO?**
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` ≈ 9.8.
*Decoded:* remote (**AV:N**), easy (**AC:L**), no login needed (**PR:N**), no victim click (**UI:N**), full damage (**C/I/A:H**) — every dial at worst, which is why it scores ~9.8. Paste your scenario into the CVSS calculator; it builds this string for you.

**92. What downgrades an ATO finding?**
Requiring an implausible precondition, only working on your own account, or stopping at the primitive without the takeover.
*Plain version:* three things shrink your score — needing something unrealistic to be true first, only demonstrating it on your *own* account (not cross-account), or quitting at the lead instead of finishing the takeover. Close all three gaps to keep the Critical.

**93. Why re-test partial fixes?**
Fixing one reset-poison header but not another, or rate-limiting web but not the API OTP path, is a fresh valid finding.
*Why it pays:* patches are often incomplete — they block `Host` but not `X-Forwarded-Host`, or rate-limit the website but not the mobile API. Re-testing the *other* paths after a fix regularly turns up a brand-new, valid, sometimes-easy bounty.

---

## I. SAFE-PoC, reporting & red-team (94–100)

**94. The one safety rule?**
Prove ATO with two accounts you control, take over B once with a benign marker, **restore B's state**, and stop — never touch a real user.
*Why it's non-negotiable:* bug bounty pays you to *demonstrate* the unlocked door, not to rob the house. Two of your own accounts is all you ever need; touching a real user's account turns an authorized test into a crime and gets you banned or prosecuted.

**95. How do you keep OTP/token tests safe?**
Bounded wrong-code counts (prove the limiter is absent, don't crack), and analyze only your own tokens.
*Plain version:* to show "no rate-limit," send a *capped* batch of wrong codes to *your own* account and show you're never blocked — you prove the missing lock without actually cracking anyone. For tokens, study only your own account's tokens for patterns.

**96. What must a report contain?**
The vector + endpoint + missing control, the two-account steps, the cross-account proof (B-only marker), and a note that you restored B.
*In order:* what the flaw is and where, the numbered "as A → … → inside B" steps, a screenshot of the B-only marker proving you got in, and a line saying you put B back. That's a report a triager can reproduce and rate without asking follow-ups.

**97. How do you de-duplicate?**
One flow/root-cause = one report; lead with the takeover and list the contributing primitives (reset poisoning + its host reflection = one report).
*Plain version:* don't split one takeover into five tickets. The reset-poisoning ATO **and** the host-header reflection that enabled it are the *same root cause* — file one report, lead with the takeover, mention the header as the mechanism.

**98. Best red-team ATO play on SaaS?**
Pre-account-takeover: pre-register the target's corporate email before onboarding, so their SSO silently lands in your account.
*Why it's the operator's favorite:* it's silent, needs no exploit against a hardened login, and just waits. Claim the target employee's work email on a SaaS *before* they onboard; when they SSO in, they walk into your account. (Authorized engagements only — Q94.)

**99. Best red-team play on stolen sessions?**
Exploit session non-invalidation so one phished/XSS'd session becomes permanent access.
*Why:* a single stolen session is normally fragile — it dies when the victim logs out. If the app never truly invalidates sessions (Q60), that one theft becomes a **permanent** key, which is exactly what an operator wants for durable access.

**100. Final checklist before submitting?**
Ended inside B? Two own accounts + benign marker? Bounded/own-token tests? B restored? Vector-matched CWE/CVSS? Remediation given? All yes → it's the Critical it's worth.
*Run it like a pre-flight:* each item is a yes/no. Any "no" means the report is either unsafe or unfinished — fix it before you hit submit. All "yes" means you've got a clean, complete, correctly-rated finding.

---

## J. Interview questions — articulate it out loud (101–112)

> These test whether you can *explain* ATO, not just run the payloads — what a senior interviewer or a triage engineer listens for. Say each out loud; aim for plain → mechanism → the proof that ends the argument.

**101. Explain account takeover to a non-security stakeholder in thirty seconds.**
"An online account has three ways in: the front door (password + 2FA), the emergency spare key (the 'forgot password' flow), and the wristband that proves you're already inside (your session cookie). Account takeover is when one of those is built sloppily on *someone else's* account, and I can walk in without their password — read their messages, spend their money, change their settings."
*Why this framing wins:* it drops the jargon and lands the *impact* (their money, their identity) in a sentence a product manager or lawyer immediately understands — which is the same instinct you use to write a report title.

**102. Why is ATO usually Critical when the "underlying bug" might be a Medium?**
Because severity tracks **impact**, and ATO is the impact — "I can log into any user's or admin's account" tops almost every payout table.
*Mechanism:* a reflected XSS or a host-header reflection is, on its own, a mid-tier hardening issue. Chained to a takeover it becomes "full compromise of an arbitrary account," which is `C:H/I:H/A:H`. The bug is the *ingredient*; the takeover is the *dish*, and you're paid for the dish. "Report the takeover, name the bug as the mechanism."

**103. A dev says "our reset tokens are 128-bit random, so password reset is secure." Rebut it.**
Token *strength* defends one specific failure (guessing) and nothing else. The reset flow has at least four other doors: **where the link points** (host poisoning — the token can be perfect and still be *mailed to me*), **who the mail goes to** (email HPP/CRLF), **whether it's bound to the user** (my valid token + your email), and **whether it's single-use / invalidated on change**.
*Worked rebuttal:* "With `X-Forwarded-Host: attacker.com`, your 128-bit token is generated correctly, stored against the victim, and emailed to *my* domain (§2.1). Entropy never enters the picture — the failure is the link host, sourced from my header instead of your config."

**104. Explain the three surfaces, and why "weakest of three" is the attacker's structural advantage.**
The surfaces: **who you prove you are** (login/2FA), **how you recover** (reset/email-change), **how the session persists** (tokens). ATO breaks *any one* — for another user.
*Why it's asymmetric:* the defender has to get **all three** right on every flow; the attacker only has to find **one** hand-built or under-checked. "A bank can have flawless login and unbreakable 2FA, but if 'forgot password' emails the link to an address I control, none of that helps — I walked in through the spare-key box. That asymmetry is why ATO is so findable and so well paid."

**105. Compare 0-click vs 1-click ATO and why it changes the CVSS.**
0-click needs no victim action (reset poisoning that leaks to your server, pre-ATO, an IDOR on the email field); 1-click needs the victim to open a link (reset-link Referer leak, OAuth-linking CSRF).
*The CVSS lever:* it's the `UI` metric — `UI:N` (no interaction) vs `UI:R` (required). An unauth 0-click ATO is `AV:N/AC:L/PR:N/UI:N/…C:H/I:H/A:H` ≈ **9.8**; make the victim click and it drops to `UI:R` (still High/Critical). "Always state which yours is — it's worth a severity band."

**106. Walk me through password-reset poisoning out loud — where does the attacker's host come from?**
"When you hit 'forgot password,' the server mints a secret token and builds a link like `https://<HOST>/reset?token=…`. Lazy code fills `<HOST>` from the **request's `Host` (or `X-Forwarded-Host`) header** — which I control. So I trigger a reset *for the victim* with `X-Forwarded-Host: attacker.com`; the server mails the *victim* a link pointing at *my* domain carrying *their* real token. They click, their browser hands my server their token, I set their password, I'm in. 0-click for me, unauthenticated, Critical."

**107. Explain pre-account-takeover to someone who's never heard of it.**
"Normally you hijack an account that exists. Pre-account-takeover flips the timeline: I sign up *using the victim's email* (many sites don't force verification), so a half-account in their name already exists and I know its password. Later the victim signs in with 'Sign in with Google' — the site sees the email already exists and **merges** their Google login into *my* account instead of making a fresh one. Now we share an account I hold a password to, and they never notice because SSO never shows them a password prompt."
*Why it pays:* it's **0-click for the victim**, silent (no reset/hijack event to alert anyone), and most hunters never test it (USENIX 2022 found 35/75 services vulnerable).

**108. A team enforces 2FA on the website. What do you immediately ask, and why?**
"Is it enforced on **every** entry point — the mobile API, a v2/legacy login endpoint, SSO, magic-link?" Teams bolt 2FA onto the web UI and forget the others.
*Also ask:* does the password step return a **usable session *before* the code is checked** (force-browse past the OTP page)? Is the verify decision a **client-trusted boolean** (`{"verified":false}` → flip it)? "2FA only counts if the *server* refuses to issue a real session until the code verifies — I hunt the path where it doesn't."

**109. Why is "the reset token appears in the response" often NOT a valid report?**
Because on *your own* reset you're supposed to see your own token — that's not a leak, it's the feature.
*What makes it valid:* the token is exposed **for a victim** (via Referer to a third party, or host-poisoned to your server), or you use it to actually reset **B**'s account. "The rule: if my proof doesn't end with me *inside a different account*, it's a lead, not a finding. I finish the takeover of my second account before I file."

**110. How does an XSS become an ATO — and why bother escalating instead of just reporting the XSS?**
*How:* XSS runs JS in the victim's authenticated origin → read their session cookie (or CSRF token, or call the change-email endpoint as them) → log in as them.
*Why escalate:* the same bug pays several times more as "I took over an arbitrary account" than as "reflected XSS." "A triager rates impact; 'I can run script' is a Medium/High, 'I logged in as another user' is a Critical. The escalation is the difference in the bounty, for the same root cause."

**111. Curveballs — one sentence each.**
- **"Does HTTPS fix reset poisoning?"** No — the token still travels to the attacker's host over perfectly valid TLS; encryption doesn't decide *who* the link points at.
- **"Does a WAF fix it?"** No — a legitimate-looking `X-Forwarded-Host` or a duplicated `email` param isn't an attack signature; the flow is the bug.
- **"Does rotating the token more often fix it?"** No — poisoning captures the *current* valid token the instant the victim clicks; TTL doesn't matter.
- **"Does logging out fix a stolen session?"** Only if the **server** invalidates it — if sessions survive logout/password-change (CWE-613), the theft is permanent and logout is cosmetic.
- **"Is a 6-digit OTP safe because it's short-lived?"** Only if the attempt limit actually holds under concurrency — no/resettable/per-IP rate-limit makes a million-space code a throughput problem (§7).

**112. How do you keep an ATO test safe, legal, and still worth a Critical?**
Two accounts **you own** (`A` + `B`); every proof ends "as `A`/unauth, I'm inside `B`"; take over `B` **once** with a benign marker (read `B`'s own email back), **restore `B`'s state**, and stop.
*Why it's enough:* bounty pays for *demonstrating* the unlocked door, not robbing the house. "I never touch a real user. Bounded OTP/token tests on my own account prove the missing lock without cracking anyone. An un-weaponised, reverted PoC is also the one a triager can safely reproduce — which is what gets it paid."

---

## K. Scenario-based — you're handed a situation (113–120)

> Each is a realistic snapshot. The skill tested is *finishing the takeover* — turning a lead (a reflected header, a generic response, a working self-change) into "I'm inside B," or correctly recognising when you're not there yet.

**113. The "forgot password" response is generic ("if the account exists…") and reveals nothing. How do you still prove reset poisoning?**
The generic body is anti-enumeration and is *irrelevant* — you never prove reset poisoning from the response; you prove it from **the token arriving at your host**. Trigger the reset for `B` with `X-Forwarded-Host: attacker.com`, then watch your **listener** for `GET /reset?token=…` when `B`'s link is followed (or when the reset page/mail pre-fetches your resource). "The 200 is a decoy; the proof is a hit in my access log carrying `B`'s token, followed by me logging in as `B` (§2.1)."

**114. You inject `X-Forwarded-Host: attacker.com` but the email link still points at target.com. What next?**
The app isn't sourcing the link from *that* header — work the variants before giving up: try **plain `Host`**, `X-Forwarded-Host` with a port or `&`/`,` appended, **`X-Host` / `X-Forwarded-Server` / `X-Original-Host`**, a **dual `Host`** or **CRLF** injection, and the **`user@host` userinfo** trick (`Host: target.com@attacker.com`). Then check the **body/JSON** for a trusted `reset_url`/`callbackUrl`/`domain` field. If none of those move the link, pivot off host-poisoning entirely to **email HPP** (`email=[victim,attacker]`, §5) or **token weakness** (§4). "Reflection of the header in *some* response ≠ the *email link* using it — I confirm against the actual mailed link, and rotate through the header menu (cross-ref HostHeader kit)."

**115. You send 60 wrong OTPs to your own account and never get blocked — but you don't want to crack a real user. What's the report?**
The finding is the **missing rate-limit**, proven safely: "On my own account I submitted 60 incorrect codes with no lockout, throttle, or CAPTCHA — the documented attempt limit does not exist, so a 6-digit code (1,000,000 values) is brute-forceable → 2FA/OTP bypass → ATO (CWE-307)." You **do not** crack anyone; the bounded batch on your own account *is* the proof.
*Strengthen it:* note whether re-requesting a code resets the counter, and do the math ("N usable guesses/burst → the million-space falls to a throughput problem"). "That's a High/Critical without ever touching a real user (§7, §18)."

**116. Change-email works on your own account with no re-auth. Is that a finding? How do you turn it into ATO?**
On its own it's a **broken-flow / missing-reauth** finding (Medium-ish) — changing *your own* email isn't takeover. It becomes ATO when you can perform it **against `B`**: **(1)** find an **IDOR/mass-assignment** so account `A` sets `B`'s email (`PUT /api/users/{B}/email`, §12), **or (2)** a **CSRF** on the change-email form so `B`'s own browser changes their email to yours, **or (3)** chain any read of `B`'s session (XSS/CORS/cache). Then **reset the password to the new (your) address** — the canonical "change email → reset" chain. "Self-change is the lead; the ATO is doing it to `B` and landing inside their account."

**117. You can register `victim@company.com` (unverified). How do you confirm pre-ATO safely with two own accounts?**
Use your **own second email** as the "victim." **(1)** Register it with a password you choose; confirm a half-account exists (`email_verified:false`). **(2)** From a clean browser, do the victim's normal onboarding — ideally **SSO ("Sign in with Google")** for that same email. **(3)** Check whose account you land in: if the SSO login **merges into your pre-registered record** (you can still log in with your Step-1 password and see the SSO-linked session's data), that's **pre-account-takeover confirmed** (§10.1). Then **delete your pre-registered account** so nothing is left shared. "The whole test is 'register the email, SSO as the victim, see if I'm in the account I made' — on two addresses I own."

**118. You stole a session cookie via XSS; the victim then logs out. You're still logged in. What's the (bigger) finding?**
Two findings, and the second is the bigger one: **(1)** the XSS → session theft (the entry), and **(2) session non-invalidation (CWE-613)** — the server didn't kill the session on logout, so a stolen session is **permanent** and the victim *cannot evict you* by the one action they'd try. Prove it: capture a session (your own account), "log out" (and ideally change the password), then show the old session **still authenticates**. "Non-invalidation upgrades *every* session-theft bug from a fragile, self-healing issue into durable ATO — I report it as its own High, because it multiplies the impact of the XSS."

**119. `POST /api/user/1337/email` — you're user 4020. Walk the ATO and the safe proof.**
This is an **IDOR on a state-changing account field** (§12) — the id `1337` in the path selects the target, and if the server doesn't verify *you own it*, you edit `B`'s account. **Safe proof (two own accounts):** as `A` (user 4020), send `POST /api/user/<B_ID>/email {"email":"attacker@evil.com"}`; if it returns `200` and `B`'s email is now yours, **reset the password to that address** → log in as `B` → read `B`'s own email back from `/api/me`. Then **restore `B`'s email**. "One unguarded `userId` = direct Critical ATO. I test it by swapping to my *own* second account's id, never a real user's, and I check every 'update account' endpoint the same way (object-level authz)."

**120. Login enforces 2FA, but there's a mobile API `/api/v2/login`. What do you test, and what does success look like?**
Test whether **2FA is enforced on that path at all** — teams routinely protect the web UI and forget the API/mobile/legacy endpoints. **(1)** Log in via `/api/v2/login` with valid credentials and watch the response: does it return a **fully authenticated session/token without ever prompting for the code**? **(2)** If it returns a "2FA required" step, does **force-browsing** to an authenticated endpoint with that token work, or is the verify a **client-trusted boolean** you can flip? *Success looks like:* a session from `/api/v2/login` that reads `/api/me` (or performs a sensitive action) **with no OTP** — i.e., "the second factor is enforced on the website but not on the mobile API, so I authenticated fully without it" = 2FA bypass → ATO (§6). "The web path is the reinforced door; I go straight for the one they forgot to lock."

---

> **The one rule that pays:** ATO is proven only when you end up **inside another account** — break the weakest of login / recovery / session for *someone else's* account, show it with **two accounts you own** and a benign marker, restore state, and report the **takeover** (not the token or header that got you there).
