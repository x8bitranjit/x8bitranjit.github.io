# Cross-Site Request Forgery (CSRF) — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for CSRF: from "what is it" to account-takeover chains, token-defeat techniques, SameSite bypasses, JSON/CORS CSRF, OAuth/SSO CSRF, and red-team chaining. Q&A format, progressive difficulty, written as **"IF this → THEN that"** decision logic. Includes tools, payloads, methodology, real-world references, **and** defense + bypass.
>
> ⚖️ **Authorized use only.** For bug bounty (in-scope), sanctioned pentests, CTFs, and learning. Don't test systems you don't have written permission to test. CSRF PoCs auto-perform actions in a victim's session — only ever fire them against your own test accounts.

**Canonical references** (real, read them):
- PortSwigger Web Security Academy — *CSRF* (and *SameSite*, *CORS*, *OAuth* topics)
- OWASP — *CSRF Prevention Cheat Sheet* + WSTG "Testing for CSRF"
- HackTricks — *CSRF* ; PayloadsAllTheThings — *CSRF Injection*
- Chrome SameSite-by-default rollout (Chrome 80, 2020); RFC 6265bis (SameSite)

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q10)
- **Level 1 — Beginner: building working CSRF PoCs** (Q11–Q20)
- **Level 2 — Defeating CSRF tokens** (Q21–Q35)
- **Level 3 — SameSite cookies & method/Referer/Origin defenses** (Q36–Q48)
- **Level 4 — Content-Type, JSON, CORS & preflight interplay** (Q49–Q58)
- **Level 5 — Special CSRF classes (login, OAuth, GraphQL, clickjacking, cookie-tossing)** (Q59–Q72)
- **Level 6 — Expert / red-team chains & ATO** (Q73–Q84)
- **Tooling** (Q85–Q88)
- **Black-box methodology & decision tree** (Q89–Q93)
- **Payload cheat sheets** (Q94–Q97)
- **Real-world case patterns & references** (Q98–Q100)
- **Defense — how to stop CSRF properly** (Q101–Q104)
- **Appendix — 60-second field checklist**

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is CSRF in one sentence?
CSRF forces a victim's **already-authenticated browser** to send a **state-changing request** that the attacker chose, **without the victim's intent**, by abusing the browser's habit of automatically attaching credentials (cookies, HTTP Basic auth, client certs) to requests — "**confused deputy**" / "**ambient authority**" abuse.

### Q2. Why does CSRF even work? (the root cause)
Browsers auto-send a site's cookies on **any** request to that site — including requests triggered by a *different* site (an `<img>`, a form auto-submit, `fetch`). The server can't tell "the user clicked this in our app" from "a malicious page made the user's browser send it." If the server authorizes purely on the auto-sent cookie and has no *unpredictable, attacker-unknowable* proof of intent, it's CSRF-able.

### Q3. What three conditions must ALL be true for classic CSRF?
**IF** (a) the action is **state-changing/sensitive** (change email, transfer money, add admin…), **AND** (b) the app relies on an **automatically-sent credential** (session cookie, Basic auth) with no extra proof, **AND** (c) the request has **no unpredictable parameter** the attacker can't guess/obtain (no valid CSRF token, no custom header the attacker can't set, SameSite not blocking it) → **THEN CSRF is possible.** Remove any one condition → no CSRF.

### Q4. CSRF vs XSS — what's the difference?
- **XSS** = attacker runs script **in** the target origin (full read+write, steals tokens, reads responses).
- **CSRF** = attacker triggers a request **to** the target from the *outside*; they **cannot read the response** cross-origin (Same-Origin Policy blocks that), they only cause the *side effect*. CSRF is "write-only / blind." If you have XSS you don't need CSRF (XSS is strictly stronger and bypasses all CSRF defenses).

### Q5. What is the real-world impact of CSRF?
Whatever the forged action does: **change email → password reset → account takeover**, change password directly, transfer funds, add an admin/SSH key/API key, disable 2FA, link an attacker OAuth account, change DNS on a router, delete data, change privacy/security settings. Severity = the most sensitive single-request action you can forge (often **High–Critical / ATO**).

### Q6. What's "ambient authority" and which credentials enable CSRF?
Any credential the browser sends **automatically**: session **cookies** (most common), **HTTP Basic/Digest** auth, **NTLM/Kerberos** (intranet), **TLS client certs**. **IF** auth is via `Authorization: Bearer <token>` that JS must attach manually (and it's *not* in a cookie) → **THEN** there's usually **no CSRF** (the attacker's page can't add that header cross-origin). Token-in-cookie = CSRF-able; token-in-header-only = generally safe from CSRF.

### Q7. Does CSRF require the victim to be logged in?
Yes for state-changing CSRF (you ride their session). **Exception: Login CSRF** (Q60) forces the victim *into the attacker's* account, which doesn't need a victim session. Also "pre-auth" CSRF exists on endpoints reachable without auth.

### Q8. Can CSRF read data / responses?
No — Same-Origin Policy stops the attacker's origin from reading the cross-origin response. CSRF is fire-and-forget. **IF** you can also read the response → that's a **CORS misconfiguration** (Q57) or **XSS**, not plain CSRF, and it's worse.

### Q9. GET vs POST — does CSRF only work on POST?
No. **IF** a state change is reachable via **GET** → CSRF is *trivial* (`<img src=...>`) and even **SameSite=Lax** doesn't fully protect it (top-level navigation). State changes should never be GET. POST CSRF needs an auto-submitting form (Q12).

### Q10. What's the attacker's mindset / mental checklist?
For every sensitive request ask: *"Can a random evil website make the victim's browser send this exact request, with their cookies, and have the server accept it?"* Then probe each defense layer (token, SameSite, Origin/Referer, Content-Type, custom header) and find the one that's missing or bypassable.

---

# LEVEL 1 — BEGINNER: BUILDING WORKING CSRF PoCs

### Q11. How do I find CSRF-testable requests (recon)?
Proxy the app (Burp/Caido) and list every **state-changing** request: POST/PUT/PATCH/DELETE and any GET that mutates. Prioritize: change email/password, add user/role, payment/transfer, API-key/SSH-key add, OAuth link, settings, delete, disable security. For each, note: method, params, `Content-Type`, presence of a **CSRF token**, the **session cookie's SameSite** (from `Set-Cookie`), and any `Origin`/`Referer` checks.

### Q12. Basic POST CSRF PoC (form auto-submit)?
```html
<html><body onload="document.f.submit()">
<form name="f" action="https://target.com/account/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form></body></html>
```
Host it, lure the logged-in victim to visit → their browser POSTs with their cookie. **IF** no token / token not validated / SameSite=None → action succeeds.

### Q13. GET CSRF PoC?
```html
<img src="https://target.com/account/delete?confirm=1" style="display:none">
<!-- or -->
<script>location="https://target.com/transfer?to=evil&amt=1000"</script>
```
**IF** the state change accepts GET → done (and this survives SameSite=Lax via top-level nav for the `location` variant).

### Q14. How do I generate a PoC fast?
Burp → right-click the request → **Engagement tools → Generate CSRF PoC** (auto-builds the HTML form, including auto-submit). Verify it works in a **separate browser/profile that's logged into the target**. Tweak `Content-Type`/enctype as needed.

### Q15. How do I send a request body that's `application/x-www-form-urlencoded`?
Standard HTML form (`enctype="application/x-www-form-urlencoded"`, the default). Each field = one hidden input. This is a **"simple request"** → no CORS preflight → cross-origin allowed.

### Q16. The endpoint expects JSON — can a form send it?
Sometimes, via `enctype="text/plain"` (Q51) which produces `name=value` text you can shape into JSON. Real `application/json` from a form isn't possible; you'd need `fetch` (which triggers preflight cross-origin). So **IF** the server *strictly* requires `application/json` and rejects others → JSON CSRF is usually blocked (Q52).

### Q17. How do I confirm a CSRF finding properly?
In a fresh browser profile logged into the target with a **test account**, open your PoC page, confirm the action executed (email changed, etc.), capture: the PoC HTML, the resulting request, and the before/after state. **IF** it only works in the same browser tab where you're testing the app → that's same-site, not cross-site; host the PoC on a **different origin** to prove cross-site.

### Q18. What does "the action executed without a token I couldn't know" look like?
You removed/omitted the anti-CSRF token (or there never was one) and the server **still performed the action**. That's the core proof. If the server rejects without a valid token you can't obtain cross-origin → not CSRF (probe token weaknesses, Level 2).

### Q19. Common beginner false positive?
Testing the PoC in the **same browser** where the app is open (same-site context) "works," but it fails cross-site (SameSite=Lax blocks the cross-site POST). Always test from a truly different site/origin. Also: a 200 response doesn't mean the action happened — verify the state changed.

### Q20. Beginner "IF→THEN" quick map.
- IF state-change is GET → **CSRF (easy)**.
- IF POST + no token + SameSite=None/absent → **CSRF**.
- IF token present → go to Level 2 (try to defeat it).
- IF SameSite=Lax/Strict on session cookie → go to Level 3 (method/same-site bypass).
- IF requires `application/json` + custom header → go to Level 4.

---

# LEVEL 2 — DEFEATING CSRF TOKENS

### Q21. The request has a CSRF token. First tests?
Run this sequence; each is an independent bypass:
1. **Remove** the token parameter entirely → does it still work? (token only checked *if present*).
2. **Empty** the token (`csrf=`) → accepted?
3. **Use your own** valid token (from your account) against the victim → is it tied to the session/user?
4. **Reuse** an old/previously-used token → one-time or pooled?
5. **Guess/predict** it (sequential, timestamp, short, base64 of username) → weak generation?
6. **Change method** (POST→GET) → token requirement dropped?
7. **Token in cookie only** (not body/header) → it's auto-sent → no protection.

### Q22. IF removing the token still works → ?
The server validates the token **only when it's present**. Omit the param entirely (not blank — actually delete it). Very common. → **CSRF confirmed.**

### Q23. IF an empty token is accepted → ?
Validation compares to empty/whitespace or short-circuits. Send `token=` (or `token=null`). → bypass.

### Q24. IF my own account's token works on the victim → ?
The token isn't **bound to the victim's session** — it's globally valid or validated against a pool. Attacker fetches a valid token from their own session and embeds it in the PoC. → **CSRF confirmed.** This is one of the most common real bypasses.

### Q25. IF the token is reusable / not one-time → ?
Capture a token once, reuse it in the PoC. Not itself a bypass unless combined with token-leak or non-binding, but matters for replay and for tokens leaked via Referer (Q31).

### Q26. IF the token is predictable → ?
Generate the victim's token offline (e.g., it's `md5(username)`, sequential, timestamp-based, or static per build) and bake it into the PoC. Inspect multiple tokens for structure/entropy.

### Q27. IF the token is tied to a **non-session** cookie the attacker can set → ?
Some apps store the expected token in a separate cookie and just compare cookie-token == body-token (**double-submit**). **IF** the attacker can set that cookie in the victim's browser (subdomain XSS, a `Set-Cookie` from any sibling site, an app endpoint that reflects a cookie, response splitting, or "cookie tossing", Q66) → set both cookie and body to the *attacker's* known token → they match → bypass. The classic double-submit weakness.

### Q28. IF the token validation can be skipped by changing the request method → ?
App enforces token on POST but the same handler accepts GET (or `PUT`) without it. Switch method. Also try **method override**: `X-HTTP-Method-Override: POST`, `_method=POST`, `?_method=DELETE` — frameworks (Rails, Laravel, Spring) may route an unprotected verb to a protected action.

### Q29. IF the token is in a custom **header** (e.g., `X-CSRF-Token`) → ?
A cross-origin attacker page **cannot set arbitrary headers** on a simple request (and a `fetch` with custom header triggers preflight that must pass CORS). **IF** the server *requires* the header → generally **CSRF-safe**. **BUT IF** the header is only checked when present (omit it → accepted), or the value isn't validated, or only some endpoints check it → bypass. Always test omission.

### Q30. IF the app only checks `X-Requested-With: XMLHttpRequest` → ?
Same logic: can't be set cross-origin without preflight, so it's a defense — **unless** the server accepts requests missing it (legacy/mobile endpoints often do), or a Flash/`<object>`/legacy vector can set it. Test by removing it.

### Q31. How does the **Referer-leak** path defeat tokens?
**IF** the page that contains the token sends a **full Referer** to a third party (loads an external image/script with the token in the URL, or the token is in a `GET` URL) → the attacker harvests the victim's *valid, session-bound* token from their logs, then uses it in a targeted CSRF. Look for tokens in URLs and pages that leak Referer cross-origin.

### Q32. IF the token is reflected back / settable in the response → ?
Some endpoints echo a token you supply and then "validate" it on submit — effectively no protection. Or an endpoint lets you fetch a fresh token without auth — embed that flow in your attack page if it's same-site reachable.

### Q33. What about tokens delivered in the page that the attacker can read via another bug?
**IF** there's any way to read the token cross-origin** — CORS misconfig (Q57), a JSONP endpoint returning the token, an XSS, or a same-site iframe you can read — **THEN** the attacker reads the live token and the CSRF defense collapses. Hunt for token-leaking endpoints.

### Q34. IF only "sensitive" actions have tokens but a chained, less-guarded action enables them → ?
Forge the unprotected step (e.g., add a delivery address, set a recovery email *that lacks a token*) which then enables an ATO. Map which endpoints lack tokens and chain.

### Q35. Token-defeat "IF→THEN" summary.
- Removable → omit it.
- Empty accepted → blank it.
- Not session-bound → use your own.
- Predictable → compute it.
- In cookie only → ignore (auto-sent).
- Double-submit + settable cookie → cookie-toss your token.
- Method/override drops it → switch verb.
- Header-only, checked-when-present → omit header.
- Leaked via Referer/CORS/JSONP/XSS → steal the live token.

---

# LEVEL 3 — SAMESITE, METHOD, REFERER/ORIGIN DEFENSES

### Q36. What is the SameSite cookie attribute and why does it matter most today?
`SameSite` on `Set-Cookie` controls whether the cookie is sent on **cross-site** requests. It's the dominant *modern* CSRF defense (Chrome defaults cookies to **Lax** since v80/2020). Values: **Strict**, **Lax**, **None**. First thing to check: `Set-Cookie:` on the session cookie — note its SameSite.

### Q37. IF session cookie is `SameSite=None` (and Secure) → ?
Cookie is sent on **all** cross-site requests → **classic CSRF fully in play** (subject to tokens/Origin checks). Common on apps needing cross-site embedding. Best-case for the attacker.

### Q38. IF session cookie is `SameSite=Lax` (or absent → Lax-by-default) → ?
Cookie is sent on **top-level GET navigations** (clicking a link, `window.location`, a top-level form GET) but **NOT** on cross-site **POST**, `fetch`, `<img>`, iframes. So:
- **THEN** POST-based CSRF via a background form is **blocked**.
- **BUT** **GET-based state changes are still exploitable** via top-level navigation: `<script>location='https://t/transfer?...'</script>` or `window.open`, or a top-level **GET** form. → Hunt for state-changing GET endpoints or method-override that turns POST into a GET-navigable action.

### Q39. What is the "Lax+POST 2-minute window" bypass?
Chrome's "Lax-by-default" has a compatibility carve-out: a cookie set **without an explicit SameSite** is treated as **None for ~120 seconds** after being set, *for top-level POST*. **IF** you can make the victim obtain a **fresh** session cookie (e.g., force a login/SSO redirect, or the app re-sets the cookie) and fire the POST CSRF **within 2 minutes** → **THEN** cross-site POST works. Trigger a login flow then immediately submit. (Browser-version dependent; verify.)

### Q40. IF cookie is `SameSite=Strict` → ?
Cookie is **not sent on any cross-site request, including top-level navigation**. Direct cross-site CSRF is blocked. **BUT** there are three real bypasses:
- **(a) Same-site position** — an **XSS on any subdomain** or a **subdomain takeover**: a request originating from `app.target.com` to `target.com` is **same-site**, so the Strict cookie *is* sent (see Q41).
- **(b) On-site client-side redirect / SPA-router gadget (no subdomain needed)** — PortSwigger's "**SameSite bypass via client-side redirect**." SameSite is decided by the context of the **final** request. If the target's **own client-side code** re-issues the state-changing request, that request is **same-site** and the Strict cookie flows. Hunt an **on-site** gadget: a JS open-redirect (`target.com/go?to=/account/delete` where *JavaScript* does `location=to`) or an **SPA route** (`target.com/#/account/delete`) that the app's router turns into a same-site fetch. You navigate the victim **top-level** to that on-site URL; the target then fires the sensitive request itself, same-site. *(A plain server-side 302 usually does NOT help — the browser still treats the resulting navigation as cross-site for the cookie. It must be a **same-site, client-side** navigation/redirect.)*
- **(c) Mixed cookies** — Strict often breaks UX, so apps mix Strict for some cookies and Lax/None for others; check **every** auth-relevant cookie, since the action may only need a Lax/None one.

### Q41. Important: SameSite is "same-SITE", not "same-ORIGIN". Why does that matter?
"Site" = registrable domain (eTLD+1). `a.target.com`, `b.target.com`, and `target.com` are all the **same site**. **IF** you control or XSS **any subdomain** (subdomain takeover, a vulnerable sibling app, user-content subdomain) → requests from there are same-site → SameSite (even Strict) won't block them. Subdomain takeover + CSRF is a powerful combo.

### Q42. How do attackers turn a SameSite=Lax target into a hit via redirects?
**IF** the target site itself has an **open redirect** that the victim hits via **top-level navigation** (allowed under Lax) and that redirect issues the state-changing GET — or you chain a same-site page to issue the request — the cookie rides along. Lax blocks *cross-site subresource* POSTs, not *same-site* issuance.

### Q43. IF the app validates **Referer** → how to bypass?
- **Missing Referer accepted**: suppress the Referer so the check passes when absent. `<meta name="referrer" content="no-referrer">` or `Referrer-Policy`, or load the PoC over a downgrade (HTTPS→HTTP strips Referer historically), or `rel="noreferrer"`. **IF** server allows empty Referer → bypass.
- **Substring/whitelist match**: if it just checks the Referer *contains* `target.com`, host your page at `https://target.com.evil.com/` or `https://evil.com/target.com` or `https://eviltarget.com`. → bypass.
- **Prefix match**: `https://target.com.attacker.com`.
- **IF** it requires Referer to *start with* the exact origin → harder; combine with same-site/open-redirect.

### Q44. IF the app validates **Origin** header → bypass options?
`Origin` is harder to forge (browser-set, no path, sent on POST/CORS). Bypasses are narrower:
- **Missing Origin accepted** → some requests (certain navigations, older browsers) omit Origin; if the server allows null/absent Origin → bypass.
- **`Origin: null`** via sandboxed iframe (`<iframe sandbox="allow-scripts allow-forms" srcdoc=...>`) or data: URL → if server treats `null` as trusted → bypass.
- **Substring/suffix logic** mistakes (same as Referer) → `https://target.com.evil.com`.
- Otherwise a strict Origin allowlist is a solid defense; pivot to same-site/XSS.

### Q45. IF both Origin AND Referer are absent (e.g., some GET navigations) → ?
Servers that "fail open" when neither header is present are bypassable: craft a request context that omits both (top-level GET nav, certain link prefetches). Test the server's behavior with both stripped.

### Q46. How do I check SameSite quickly?
Read the `Set-Cookie` on login: `Set-Cookie: session=...; HttpOnly; Secure; SameSite=Lax`. **No SameSite shown** → Lax-by-default in modern Chrome (but **None** in old browsers / non-Chromium → still test). Use DevTools → Application → Cookies, or Burp.

### Q47. Does SameSite protect non-cookie auth?
No — it's a cookie attribute. Basic auth / NTLM / client-cert sessions ignore SameSite and remain CSRF-able (intranet apps!). Token-in-`Authorization`-header (manual) isn't auto-sent at all, so it's safe regardless.

### Q48. SameSite "IF→THEN" summary.
- None/absent(old) → full CSRF.
- Lax → POST blocked; **GET state-change** + top-level nav works; 2-min fresh-cookie POST window.
- Strict → need same-site primitive (subdomain XSS / open redirect / sister app).
- Any → subdomain control = same-site = bypass.
- Basic/NTLM/client-cert → SameSite irrelevant, CSRF still possible.

---

# LEVEL 4 — CONTENT-TYPE, JSON, CORS & PREFLIGHT

### Q49. What's a "simple request" and why does it matter for CSRF?
A cross-origin request that the browser sends **without a CORS preflight** (so it actually reaches the server with cookies). It must use method GET/POST/HEAD and `Content-Type` ∈ {`application/x-www-form-urlencoded`, `multipart/form-data`, `text/plain`} and only safe headers. **IF** an endpoint accepts one of these content-types → it's reachable by a cross-origin HTML form → CSRF-testable. Anything needing JSON content-type or custom headers triggers preflight (which CSRF can't satisfy without CORS).

### Q50. IF the JSON API accepts `application/x-www-form-urlencoded` too → ?
Many frameworks parse params regardless of content-type, or accept form-encoded as well as JSON. Send the params as a normal form (`email=evil@x`) → if accepted → standard form CSRF. Always try downgrading JSON to form-encoded.

### Q51. The `enctype="text/plain"` JSON-CSRF trick — how?
A form with `enctype="text/plain"` sends the body as `name=value` joined lines and **doesn't URL-encode**. You shape inputs so the raw body is **valid JSON**:
```html
<form action="https://t/api/account" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
```
Body becomes: `{"email":"attacker@evil.com","ignore":"="}` (the `=` from name=value lands inside a throwaway field). **IF** the server parses `text/plain` as JSON (lenient parser) → JSON CSRF works without preflight.

### Q52. IF the server **strictly** requires `Content-Type: application/json` and validates it → ?
A cross-origin form can't set that content-type, and a `fetch` with it triggers **preflight** → blocked by CORS unless misconfigured. **THEN** CSRF is generally **not possible** *unless*:
- CORS is misconfigured to allow the attacker origin with credentials (Q57), or
- there's a same-site/XSS primitive, or
- the `text/plain`→JSON lenient-parse trick works (Q51).
Strict JSON + content-type enforcement is itself a decent (accidental) CSRF defense — but it is **not** a substitute for tokens.

### Q53. IF a custom header (e.g., `X-Requested-With`, `X-CSRF`) is *required* → ?
Cross-origin can't add it without preflight → defense holds **only if enforced on every sensitive endpoint and on missing/empty values**. Test omission and per-endpoint inconsistency. Legacy SOAP/Flash/`navigator.sendBeacon` and some `<object>` vectors historically set headers; mostly dead in modern browsers.

### Q54. What about `multipart/form-data` CSRF?
`multipart` is a "simple" content-type → no preflight → an HTML form with `enctype="multipart/form-data"` can do cross-origin CSRF, including **file uploads** (CSRF-to-upload). Useful when the endpoint is multipart-only.

### Q55. `navigator.sendBeacon` / `<form>` to send POST without reading response?
`sendBeacon` sends a POST (text/plain or form) cross-origin with credentials, fire-and-forget — handy for blind CSRF. `fetch(url,{method:'POST',credentials:'include',mode:'no-cors'})` also fires the request (you just can't read the response) — works for simple content-types.

### Q56. IF the API uses a Bearer token in `Authorization` (not a cookie) → ?
The attacker page can't attach that header cross-origin → **no CSRF**. **BUT IF** the app *also* accepts the session via a cookie (dual auth), or stores the bearer in a cookie, or has a cookie-authed legacy endpoint → CSRF returns. Check whether the cookie alone authorizes the action.

### Q57. How does a CORS misconfiguration turn CSRF into something worse?
**IF** the server reflects the request `Origin` into `Access-Control-Allow-Origin` **and** sets `Access-Control-Allow-Credentials: true` → an attacker page can make **credentialed `fetch`** that both *performs the action* **and reads the response** (steal CSRF tokens, PII, anything). That's CORS exploitation > CSRF. Always test CORS reflection on JSON endpoints.

### Q58. Content-Type "IF→THEN" summary.
- Accepts form/multipart/text-plain → cross-origin form CSRF.
- Accepts text/plain-as-JSON → JSON CSRF via enctype trick.
- Strict JSON + enforced content-type → preflight blocks (unless CORS misconfig / same-site / XSS).
- Custom header required + enforced everywhere → safe; test omission.
- CORS reflects origin + credentials → read+write (worse than CSRF).

---

# LEVEL 5 — SPECIAL CSRF CLASSES

### Q59. What is CSRF-to-Account-Takeover (the money chain)?
Forge a single sensitive write that yields control: **change-email CSRF** (no current-password required) → attacker triggers password reset to the new email → ATO. Or **change-password CSRF** if no current password is needed. Or **add recovery phone/email**, **link attacker OAuth**, **add an API key/SSH key**. Always look for "change email/password without re-auth."

### Q60. What is **Login CSRF** and why is it useful?
The attacker forges a **login** request that logs the **victim into the attacker's account**. The victim then unknowingly uses the attacker's account — entering payment cards, search history, uploaded files, OAuth links — which the attacker later retrieves. Also enables **OAuth/account-stitching** attacks. Defense: CSRF-protect the login form too (often forgotten).

### Q61. Logout CSRF?
Forge a logout to disrupt the victim (low sev alone) — but combined with **Login CSRF** it can force a session swap, or be a step in an OAuth/SSO attack. Usually Low unless chained.

### Q62. CSRF in **OAuth** flows — the `state` parameter?
**IF** an OAuth client doesn't validate the `state` parameter (CSRF token for OAuth) → an attacker can perform a **login/authorization CSRF**: capture an attacker's `code`, then force the victim's browser to the callback with the attacker's code → victim's session gets linked to the **attacker's** social account (account takeover via "Sign in with X"), or the victim's account gets linked to attacker → ATO. Missing/`state` not bound to session = classic OAuth CSRF. Hugely common bounty.

### Q63. CSRF on **social-account linking**?
"Connect Google/Facebook" endpoints that lack CSRF tokens let an attacker **link their own** social identity to the victim's account → attacker then logs in via that social identity → ATO. Or force-link the victim's social to attacker's account. Test all "link/unlink provider" endpoints.

### Q64. CSRF to disable **2FA / change security settings**?
**IF** "disable 2FA", "remove authenticator", "trust this device", or "change security questions" lacks CSRF protection and re-auth → forge it → strips the victim's second factor, enabling later takeover. High impact.

### Q65. GraphQL CSRF — what's special?
- **GET-based queries/mutations**: if the GraphQL endpoint accepts queries over **GET** (`/graphql?query=mutation{...}`) → trivial GET CSRF (and Lax-survivable). Many do for caching.
- **`application/x-www-form-urlencoded` or `text/plain`** accepted by the GraphQL server → form-based CSRF on mutations.
- **Batching**: a single CSRF request firing multiple mutations.
**IF** GraphQL requires `application/json` + CSRF token/custom header → blocked. Test the content-types and GET support.

### Q66. What is **cookie tossing / cookie injection** and how does it beat double-submit?
**Double-submit CSRF defense**: server sets a random token in a cookie and expects the same value echoed in the request body/header; it just checks they're equal (no server-side state). **IF** the attacker can **write a cookie** into the victim's browser for the target site — via an **XSS on a subdomain**, a **sibling app that sets a domain cookie**, **HTTP response/header injection**, or a **less-secure HTTP subdomain** ("cookie tossing" from `sub.target.com` setting a `Domain=.target.com` cookie) — **THEN** the attacker sets BOTH the cookie and the body token to *their own* known value → they match → defense bypassed. Double-submit is only as strong as the integrity of that cookie.

### Q67. Clickjacking-assisted CSRF — when do I use it?
**IF** a token *is* present and unguessable (so blind CSRF fails) but the action is doable by a couple of clicks → frame the real app in a transparent iframe and trick the victim into clicking the genuine buttons (which carry the real token) — **UI-redress** the legitimate flow. **IF** the app lacks `X-Frame-Options`/CSP `frame-ancestors` → framable → clickjacking delivers the "CSRF-equivalent" with a valid token. (Combine concepts: token defeats classic CSRF, clickjacking defeats the token.)

### Q68. Blind CSRF — how to detect/prove with no readable response?
You can't read the response, so confirm via **side effects**: the state change itself (re-check the account), or **out-of-band** if the action triggers a callback (e.g., CSRF that adds a webhook URL pointing to your collaborator, or that emails you). For pure blind, demonstrate the state change with before/after evidence on your test account.

### Q69. CSRF on **JSON-RPC / REST `PUT`/`DELETE`** endpoints?
`PUT`/`DELETE`/`PATCH` aren't "simple methods" → cross-origin needs preflight → usually safe **unless** method-override (`_method`, `X-HTTP-Method-Override`) lets a plain POST/GET reach them, or the framework routes form POSTs to the handler. Test override params and whether a POST hits the same controller.

### Q70. CSRF + self-XSS = stored XSS?
**IF** there's a self-XSS (only fires in your own account) and a CSRF on the field that stores it → use CSRF to **inject your XSS into the victim's** account → it becomes effective stored XSS in the victim's session. A standard escalation of an otherwise "won't fix" self-XSS.

### Q71. CSRF on file upload / content that later runs?
Forge a `multipart` upload (Q54) to plant content in the victim's account (e.g., an avatar SVG with XSS, or a malicious document) — CSRF-to-stored-XSS or CSRF-to-content-injection.

### Q72. CSRF against **internal/intranet** devices (routers, IoT, admin panels)?
Real-world impact class: home routers/printers/IoT with **GET-based config** and default/Basic auth are CSRF-able from any web page the victim visits → change **DNS servers** (mass pharming), open ports, add admin, change Wi-Fi. SameSite + Basic auth = no cookie protection. (The 2014–2018 router DNS-hijack campaigns were CSRF at scale.) Also internal apps reachable from the victim's browser (SSRF-adjacent).

---

# LEVEL 6 — EXPERT / RED-TEAM CHAINS & ATO

### Q73. Give a clean CSRF→ATO chain (email change).
1. Find `POST /account/email` (or PATCH) that sets a new email and **doesn't require the current password** and **lacks a valid session-bound token** (or token is removable/own-token).
2. Host auto-submit PoC setting `email=attacker@evil.com`.
3. Lure logged-in victim → email changed.
4. Trigger **password reset** → reset link goes to attacker's email → **full ATO**. Report the chain with combined impact.

### Q74. OAuth `state`-less takeover chain (expert).
1. Target's "Login/Link with Google" callback ignores `state`.
2. Attacker starts the OAuth flow with **their** Google, grabs the `code` at the callback (don't complete it).
3. Force victim (logged into target) to hit `/oauth/callback?code=<attacker_code>` (CSRF) → target links the **attacker's Google** to the **victim's** account.
4. Attacker logs into the victim's account via "Sign in with Google." → **ATO**. (Or the inverse: victim's identity linked to attacker.)

### Q75. Strict-SameSite ATO via subdomain XSS (expert).
1. Session cookie is `SameSite=Strict` (cross-site CSRF blocked).
2. Find XSS/takeover on **any** subdomain (`blog.target.com`, an abandoned `*.target.com` CNAME).
3. From that **same-site** origin, issue the state-changing request → Strict cookie **is** sent → CSRF executes. → ATO. (Demonstrates SameSite is same-*site* not same-*origin*.)

### Q76. Double-submit defeat via cookie-tossing (expert).
1. App uses double-submit token (cookie==body).
2. Find a subdomain that can set a `Domain=.target.com` cookie (XSS, header injection, or a permissive sibling).
3. Set the CSRF cookie to attacker-known value; submit body with the same value → match → CSRF on a "protected" app. → ATO.

### Q77. CSRF → admin → RCE (red-team).
**IF** an admin panel action (add admin user, upload plugin/theme, edit a template, set a webhook, enable a feature that runs code) is CSRF-able and an admin visits your page → forge it. Chains: CSRF "add admin" → log in as admin → upload web shell (see File Upload guide) → RCE. CSRF that edits a server-side template/plugin = direct RCE. The victim must be a privileged user (spear-phish the admin).

### Q78. How do I maximize bounty severity from a CSRF?
- Push to **ATO** (email/password/2FA/OAuth) not just "settings changed."
- Show **no user interaction beyond a page visit** (auto-submit) and **works in current browsers** (handle SameSite — prove the GET path or 2-min window or same-site primitive).
- Demonstrate against a **privileged** victim where relevant.
- Quantify scope (any logged-in user, one click).

### Q79. What kills most CSRF reports in triage (and how to preempt)?
- **SameSite=Lax** blocking your POST PoC → triagers say "not exploitable in modern browsers." **Preempt**: prove a GET-based path, the Lax+POST 2-minute window, or a same-site primitive — and state the browser/version you tested.
- **Action requires re-auth/current password** → not CSRF-able alone.
- **Custom header / strict JSON enforced** → blocked.
- **Self-only / low impact** → escalate or combine.
Always test in a **current Chrome** and document it.

### Q80. CSRF on **logout/login** to enable session fixation or SSO confusion?
Login CSRF (Q60) + an app that doesn't rotate session on auth can set up session-fixation-like states; in SSO, forcing the victim into an attacker-initiated flow can stitch identities. Niche but real in complex SSO.

### Q81. WAF/filter bypass for CSRF PoCs?
- If the WAF blocks the obvious `email=` param, try param pollution (`email=a&email=evil`), case, array notation (`email[]`), JSON vs form, method override, or alternate endpoints (mobile/`/v1/`/`/internal/`).
- Host PoC on HTTPS (mixed-content blocks HTTP PoCs from HTTPS apps).
- For Referer/Origin filters, use the substring/suffix tricks (Q43–Q44).

### Q82. CSRF via **HTTP request smuggling / cache** (advanced edge)?
Front-end/back-end desync or cache poisoning can deliver a CSRF-like state change or poison a response with an attacker form. Rare and high-skill; mentioned for completeness — see request-smuggling material.

### Q83. CSRF in **mobile-app backends**?
Mobile APIs often use Bearer tokens (CSRF-safe) **but** sometimes share cookie-authed web endpoints, or have weaker `/api/v1` routes lacking the web CSRF token. Decompile the app to find endpoints/content-types not exposed on web; a cookie-authed legacy endpoint = CSRF.

### Q84. Expert mindset summary.
Treat CSRF as "**can I make the browser issue this exact authenticated request from outside, and will the server accept it?**" then peel each layer: cookie auto-sent? SameSite (and is there a same-site primitive)? token (removable/own/predictable/leaked)? Origin/Referer (absent/substring)? content-type (form/text-plain/strict-json)? custom header (enforced everywhere)? The bug is the **weakest layer**; the bounty is the **chain to ATO/RCE**.

---

# TOOLING

### Q85. Core CSRF toolkit?
- **Burp Suite** — *Generate CSRF PoC* (Engagement tools), Repeater (token/method/content-type tests), **CSRF scanner** (Pro), Match&Replace to strip tokens, Collaborator for blind/OOB callbacks.
- **OWASP ZAP** — CSRF token detection + "anti-CSRF tokens" handling + PoC.
- **XSRFProbe** — automated CSRF audit/PoC generator.
- **Bolt** — CSRF scanner.
- **Caido** — proxy alternative with workflow automation.
- Browser **DevTools** (Application → Cookies: read SameSite/HttpOnly/Secure).
- **PayloadsAllTheThings / HackTricks** CSRF payload libraries.

### Q86. How do I quickly test "is the token actually enforced" with Burp?
Repeater the request and: (1) delete the token param → resend; (2) blank it; (3) paste your *other account's* token; (4) change method; (5) strip `Origin`/`Referer`; (6) change `Content-Type` to form/text-plain. A 200 + state change on any of these = bypass. Use Match&Replace to auto-strip the token across the session and just browse.

### Q87. How to confirm SameSite behavior empirically?
Host the PoC on a different origin, open in a **current Chrome** logged into the target, and observe whether the request carries the cookie (DevTools → Network → the request → Cookies tab). If absent → SameSite blocked it cross-site; switch to GET/same-site strategies.

### Q88. Generating JSON-CSRF PoCs?
Use the `enctype="text/plain"` shaping (Q51); Burp's PoC generator can start it, then hand-tune the input name/value split so the raw body is valid JSON. Verify the server accepts `text/plain`.

---

# BLACK-BOX METHODOLOGY & DECISION TREE

### Q89. Step-by-step black-box methodology.
1. **Enumerate** every state-changing request (and any mutating GET).
2. **Read the session `Set-Cookie`**: SameSite? HttpOnly? Secure?
3. **Identify the auth model**: cookie? Bearer-in-header? Basic?
4. **Locate anti-CSRF defenses**: token (where?), custom header, Origin/Referer check, content-type requirement.
5. **Attack the weakest layer** (Levels 2–4 tests).
6. **Handle SameSite** (Level 3): GET path / 2-min window / same-site primitive.
7. **Build PoC**, verify in current Chrome with a test account.
8. **Escalate/chain** to ATO/RCE; **report** with PoC + impact + remediation.

### Q90. The master decision tree.
```
Is the action state-changing & cookie-authed?
  NO  -> (Bearer/header auth) usually NO CSRF (check dual cookie-auth)
  YES -> Check session cookie SameSite:
     None/absent(old) -> cross-site requests carry cookie -> continue
     Lax              -> POST blocked; need GET state-change OR 2-min window OR same-site primitive
     Strict           -> need same-site primitive (subdomain XSS / open redirect / sibling app)
  Now check defenses on the request:
     Token present?
        NO  -> likely CSRF (verify Origin/Referer not enforced)
        YES -> try: remove / blank / own-token / predict / method-switch / leak (Referer/CORS) / cookie-toss(double-submit)
     Origin/Referer enforced?
        try: absent-allowed / null / substring-suffix bypass
     Content-Type required?
        form/multipart/text-plain  -> HTML form CSRF
        text/plain parsed as JSON  -> enctype=text/plain JSON CSRF
        strict application/json    -> blocked unless CORS-misconfig / same-site / XSS
     Custom header required & enforced everywhere?
        try omission / per-endpoint inconsistency
  If any layer falls -> CSRF. Chain to ATO/RCE for max impact.
```

### Q91. What evidence makes a strong CSRF report?
The PoC HTML, the resulting request showing the cookie attached and **no valid token** (or the bypass used), **before/after** state proving the change, the **browser+version** you tested (to preempt SameSite objections), the **impact/chain** (e.g., → password reset → ATO), and remediation. Video helps for auto-submit/clickjacking.

### Q92. Common false positives to avoid.
- PoC "works" only same-site (testing in the app's own tab) → not cross-site.
- 200 response but state didn't change.
- Endpoint uses Bearer-in-header (not cookie) → not CSRF.
- SameSite=Lax silently blocking your POST in modern Chrome (you tested in an old browser/Postman).
- Action requires current password / re-auth.

### Q93. Quick triage of severity.
- Change email/password/2FA/OAuth → **High/Critical (ATO)**.
- Money/transfer/role/admin → **High/Critical**.
- Privacy/profile/non-sensitive settings → **Medium**.
- Logout / cosmetic → **Low** (unless chained).
- Login CSRF → **Medium–High** (context-dependent).

---

# PAYLOAD CHEAT SHEETS

### Q94. Auto-submit POST form (form-urlencoded).
```html
<html><body onload="document.forms[0].submit()">
<form action="https://target.com/account/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <!-- include token field ONLY if you have a valid/own/predicted one -->
</form></body></html>
```

### Q95. GET CSRF variants (survive SameSite=Lax via top-level nav).
```html
<img src="https://target.com/api/delete?id=1">                      <!-- subresource (Lax blocks) -->
<script>location='https://target.com/transfer?to=evil&amt=1000'</script>  <!-- top-level nav (Lax sends cookie) -->
<a href="https://target.com/promote?role=admin" id=x>go</a><script>x.click()</script>
<iframe src="https://target.com/state?change=1"></iframe>           <!-- subresource (Lax blocks) -->
```

### Q96. JSON CSRF via `enctype="text/plain"`.
```html
<form action="https://target.com/api/profile" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","x":"' value='"}'>
</form>
<script>document.forms[0].submit()</script>
<!-- raw body -> {"email":"attacker@evil.com","x":"="}  (server must parse text/plain as JSON) -->
```

### Q97. Multipart CSRF (file upload / multipart-only endpoints) & sendBeacon (blind).
```html
<form action="https://target.com/upload" method="POST" enctype="multipart/form-data">
  <input type="file" name="f"><input type="hidden" name="x" value="1">
</form>
<!-- blind fire-and-forget: -->
<script>
fetch('https://target.com/api/action',{method:'POST',credentials:'include',
  mode:'no-cors',headers:{'Content-Type':'text/plain'},body:'{"do":"x"}'});
navigator.sendBeacon('https://target.com/api/action','{"do":"x"}');
</script>
```
Referer-suppression helper (for Referer-check bypass): `<meta name="referrer" content="no-referrer">` in the PoC `<head>`.

---

# REAL-WORLD CASE PATTERNS & REFERENCES

### Q98. Recurring patterns in real CSRF bounties.
- **Change-email without re-auth, weak/own/removable token → password reset → ATO** (the perennial top earner across SaaS).
- **OAuth `state` missing → account linking/takeover via "Sign in with X"** (very common, high impact).
- **Social-account link/unlink endpoints lacking tokens → ATO.**
- **Disable-2FA / change-security-settings CSRF.**
- **GraphQL over GET / form-encoded mutations.**
- **Double-submit defeated by subdomain cookie-tossing / subdomain XSS (SameSite=Strict bypass).**
- **Router/IoT GET-config CSRF → DNS hijack** (mass real-world campaigns, 2014–2018).
- **Self-XSS + CSRF → stored XSS.**

### Q99. Resources to actually work through.
- **PortSwigger Web Security Academy → CSRF** (all labs: no defenses, token not tied to session, token not validated on method change, token in cookie/double-submit, SameSite Lax bypass via method + 2-min, Referer validation broken/absent). Plus the **SameSite**, **CORS**, and **OAuth** topics.
- **OWASP CSRF Prevention Cheat Sheet** + **WSTG "Testing for CSRF."**
- **HackTricks → CSRF**; **PayloadsAllTheThings → CSRF Injection.**
- Read 20+ **disclosed HackerOne/Bugcrowd CSRF reports** (filter "CSRF", "account takeover via CSRF", "OAuth state") to internalize chains.
- Background reading: **Chrome SameSite-by-default** announcement (2020) and **RFC 6265bis**.

### Q100. CVEs/classics worth knowing by name.
- **Mass router CSRF DNS-hijack** campaigns (e.g., 2014 Brazil router attacks, various SOHO router CSRF CVEs) — CSRF at scale via GET config.
- Countless framework advisories for **missing OAuth `state`** and **login CSRF**.
- The **SameSite-by-default** rollout (2020) that reshaped CSRF exploitability — know how it changed POST CSRF and the GET/2-minute carve-outs.
- Numerous **WordPress/plugin CSRF** CVEs (often chained to stored XSS/settings change).

---

# DEFENSE — HOW TO STOP CSRF PROPERLY

### Q101. What's the gold-standard CSRF defense (layered)?
1. **Synchronizer (anti-CSRF) token**: cryptographically-random, **per-session (or per-request)**, **bound to the user's session server-side**, validated on **every** state-changing request, rejected when **missing/empty/mismatched**, never reflected/leaked in URLs or to third parties.
2. **`SameSite=Lax` (or Strict)** on session cookies + `HttpOnly` + `Secure`. (Lax for usability, Strict for high-value; understand the GET/2-min carve-outs.)
3. **Verify `Origin`/`Referer`** for sensitive actions (strict allowlist, reject absent for sensitive ops where feasible).
4. **Re-authentication / step-up** (current password, 2FA) for the *most* sensitive actions (change email/password, disable 2FA, money) — this defeats CSRF even if a token leaks.
5. **Never use GET for state changes.**

### Q102. How to do tokens right (and double-submit safely)?
- Synchronizer pattern (server-side stored expected token) is safest.
- If using **double-submit cookies**, make the token **unguessable** and **HMAC-bind it to the session** (so a tossed cookie can't be forged), set the cookie `__Host-` prefixed + `Secure` + `SameSite` to resist subdomain cookie-tossing, and validate integrity server-side — not just equality.
- Tokens must be **session-bound**, **single-or-short-lived**, **not leaked via Referer/URL**, and validated on **all** methods/endpoints.

### Q103. Per-risk hardening map.
- **Cross-site POST**: token + SameSite=Lax/Strict.
- **GET state-change**: eliminate it (use POST + token); SameSite alone won't save GET.
- **Strict needed but subdomains exist**: lock down subdomains (no XSS/takeover), `__Host-` cookies, don't share domain cookies.
- **OAuth**: mandatory, session-bound `state`; validate `redirect_uri`; PKCE.
- **Login CSRF**: CSRF-protect the login form; rotate session on auth.
- **JSON APIs**: enforce `Content-Type: application/json` **and** a token/custom header; reject form/text-plain; correct CORS (no origin-reflection with credentials).
- **Sensitive actions**: require re-auth.
- **Framing/clickjacking**: `X-Frame-Options: DENY` / CSP `frame-ancestors 'none'` so token'd actions can't be clickjacked.

### Q104. One-paragraph summary to quote in a report.
*"CSRF defense is layered: bind an unpredictable, session-tied anti-CSRF token to every state-changing request and reject it when missing/blank/foreign; set session cookies `SameSite=Lax`/`Strict` + `HttpOnly` + `Secure`; verify `Origin`/`Referer` on sensitive actions; never perform state changes via GET; and require re-authentication for the highest-value operations (email/password/2FA/payments/OAuth-linking). Remember SameSite is same-**site**, not same-**origin** — a subdomain XSS or open redirect re-enables CSRF, and double-submit cookies fall to cookie-tossing unless the token is HMAC-bound to the session. A single missing layer on a single sensitive endpoint (especially change-email or OAuth `state`) escalates to full account takeover."*

---

## APPENDIX — 60-second field checklist
```
[ ] List every state-changing request (+ mutating GETs)
[ ] Read session Set-Cookie -> SameSite? HttpOnly? Secure?
[ ] Auth model? cookie (CSRFable) vs Bearer-in-header (usually safe) vs Basic (CSRFable, SameSite-immune)
[ ] Token present? -> remove / blank / use-own / predict / method-switch / leak(Referer,CORS,JSONP,XSS)
[ ] Double-submit? -> can I set the cookie (subdomain XSS / cookie-toss)?
[ ] SameSite=Lax? -> GET state-change path? 2-min fresh-cookie POST window?
[ ] SameSite=Strict? -> same-site primitive (subdomain XSS / open redirect / sibling app)?
[ ] Origin/Referer checked? -> absent-allowed? null? substring/suffix bypass?
[ ] Content-Type? form/multipart/text-plain -> form CSRF; text/plain-as-JSON -> JSON CSRF; strict-JSON -> CORS/same-site/XSS only
[ ] Custom header required? -> enforced on missing/empty? per-endpoint gaps?
[ ] Build auto-submit PoC; test in CURRENT Chrome, logged-in test account, DIFFERENT origin
[ ] Escalate: change-email->reset->ATO / OAuth state->ATO / disable-2FA / admin->RCE
[ ] Report: PoC + cookie-attached request + before/after + browser version + chain/impact + fix
```
*End of guide.*
