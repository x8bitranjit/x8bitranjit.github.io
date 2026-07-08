# Web Cache Poisoning & Deception — Zero to Expert (100 Q&A)

**Author:** x8bitranjit
Study guide + field reference. Impact-first: the finding is always **"the cache re-serves it to a different request."**
Pair with `WEB_CACHE_TESTING_GUIDE.md`. Authorized targets only; cache-buster + own accounts + benign markers (Guide §20).

---

## A. Fundamentals (1–15)

**1. What is a web cache, in one sentence?**
An intermediary that stores one response and re-serves it for later "matching" requests, so the origin isn't hit every time.

**2. What is a "cache key"?**
The subset of a request the cache uses to decide "same request?" — typically `scheme + host + path + (some) query params`, plus any header named in `Vary`. Everything else is **unkeyed**.

**3. What is an "unkeyed input"?**
A request element the origin reflects/acts on but the cache **omits from the key**. It's the raw material for cache **poisoning** — you influence the stored response through it, and the cache ignores it when matching.

**4. One-line difference between poisoning and deception?**
Poisoning = **attacker → cache → all victims** (your payload cached & served to everyone). Deception = **victim → cache → attacker** (the victim's private response cached & served to you).

**5. Why are cache bugs often more severe than the "same" bug uncached?**
Scale + zero interaction: a reflected-header XSS that only affected *your* request becomes **stored XSS for every visitor** once cached; an open redirect becomes a **cached** mass-phishing/token-theft primitive.

**6. Name the cache layers you might be attacking.**
CDN/edge (Cloudflare, Akamai, Fastly/Varnish, CloudFront), reverse proxies (Varnish, nginx `proxy_cache`, ATS, Squid), app/framework caches (Drupal, WordPress plugins, Rails, Next.js/Vercel), and the browser's own cache + bfcache.

**7. What decides whether a response is cached at all?**
Static extension rules (`.js/.css/.png…`), directory rules (`/static/`), the response's `Cache-Control`/`Expires`/`s-maxage`, CDN page rules, and heuristic caching of 200s with no cache headers.

**8. What is the core "mismatch" every cache bug exploits?**
The delta between **what the cache keys on / stores** and **what the origin reflects / serves**. Find that gap and you have a primitive.

**9. Why does `Vary` matter?**
`Vary` names request headers the cache **includes** in the key. A missing/incorrect `Vary` (e.g. not varying on a header the app reflects) is exactly what makes that header unkeyed and poisonable.

**10. Is HTTPS a defense against cache poisoning?**
No. TLS protects transport; the cache still keys and stores the same way. Poisoning/deception are logic bugs at the caching layer.

**11. What's the difference between a shared cache and a private (browser) cache?**
Shared caches (CDN/proxy) serve **many users** → poisoning/deception scale. A private browser cache affects **one** user (still relevant for post-logout data exposure).

**12. Define "resource poisoning."**
Poisoning a cached **static asset** (JS/CSS) rather than an HTML page — one poisoned `/app.js` runs on **every page that imports it** = site-wide.

**13. Define "cache entanglement" (Kettle 2020).**
Exploiting **cache-key normalization** differences (case/decoding/trimming/param handling) so two different requests map to one key, letting you smuggle a response under a victim's key.

**14. What is CPDoS?**
Cache-Poisoned Denial of Service — poison the cache with an **error/oversized** response so the cache serves that error to everyone → outage. Variants: HHO, HMC, HMO.

**15. Where do cache bugs sit relative to Host-header and request-smuggling bugs?**
Adjacent: `Host`/`X-Forwarded-Host` reflection (HostHeader kit) is a common poisoning source; request smuggling (RequestSmuggling kit) is a way to poison the **shared** cache directly. This kit is the caching-impact layer over both.

---

## B. Detection & the HIT/MISS oracle (16–27)

**16. First question before testing either bug?**
"Is this response actually cached, and how do I tell a HIT from a MISS?" No oracle → no valid test.

**17. Which response headers reveal a cache?**
`X-Cache`, `CF-Cache-Status`, `Age`, `X-Cache-Hits`, `X-Served-By`/`X-Timer` (Fastly), `X-Varnish`, `X-Drupal-Cache`, `X-Vercel-Cache`, plus `Cache-Control`/`Expires`/`Vary`/`ETag`.

**18. How do you build a HIT/MISS oracle with no cache headers?**
Timing (a hit is much faster) and `Age` growth; or a **dynamic marker** — if a per-request value (timestamp/nonce/CSRF) is identical on the 2nd request, it was served from cache.

**19. What does `CF-Cache-Status: DYNAMIC` mean for you?**
Cloudflare isn't caching that response → no poisoning of *it*. Pivot to static resources or to deception.

**20. `Age: 0` on every request — cached or not?**
Likely not cached (or always-revalidated). Confirm with a second identical request; if `Age` never grows and no HIT header, treat as uncached.

**21. Why send the request twice?**
The 1st populates the cache (MISS); the 2nd reveals whether it's served from cache (HIT/`Age`>0/faster) — that's your oracle.

**22. What's a "hit counter" tell?**
`X-Cache-Hits: N` (Varnish/Fastly) or `X-Varnish: <id> <id2>` (two IDs) → the response came from cache.

**23. How do you fingerprint the CDN?**
Header signatures: `cf-ray`→Cloudflare, `x-served-by`/`x-timer`→Fastly, `via: cloudfront`+`x-amz-cf-id`→CloudFront, `server: AkamaiGHost`→Akamai, `x-varnish`→Varnish, `x-vercel-cache`→Vercel. `cache_detect.py` automates this.

**24. Does a `Set-Cookie` in a response affect caching?**
Usually yes — many caches refuse to store responses with `Set-Cookie` (they're user-specific). Its presence/absence is a clue to cacheability and to deception risk.

**25. What's "heuristic caching"?**
A cache storing a 200 that has **no** explicit `Cache-Control` for some default TTL — an accidental cacheability you can exploit.

**26. Why check both the HTML page AND its resources?**
The page may be `no-store` while its JS/CSS are aggressively cached — resource poisoning (§6) works even when the page doesn't.

**27. What tool automates unkeyed-input discovery?**
**Param Miner** (Burp, by James Kettle) — brute-forces header/param names with cache-busted canaries and flags unkeyed inputs.

---

## C. Cache-buster & key discovery (28–39)

**28. What is a cache-buster and why is it non-negotiable?**
A unique **keyed** value (usually `?cb=random`) that lands your test response on **your own** key — so you never poison the shared entry real users get. It's both a **safety belt** and an **isolation microscope**.

**29. What must you verify about your buster before firing payloads?**
That it's **keyed** — each new value produces a fresh MISS. If the buster is itself unkeyed, you have no isolation and must not fire poisoning payloads at a shared prod cache.

**30. The 4-step unkeyed-input confirmation?**
(1) request with a canary in the header, (2) is it reflected?, (3) request the same key **without** the header, (4) is the canary **still** served? Yes → unkeyed + poisonable.

**31. Best high-yield headers to canary?**
`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Forwarded-Server`, `X-Forwarded-Port`, `Forwarded`, `X-Original-URL`, `X-Rewrite-URL`, plus app-custom headers via Param Miner.

**32. Why is `X-Forwarded-Host` the classic?**
Apps commonly build absolute URLs (links, redirects, resource `src`, canonical) from it, and CDNs commonly **don't** key on it → reflected + unkeyed = poisonable.

**33. What is the `X-Forwarded-Scheme: nothttps` trick?**
Some apps, seeing a non-`https` forwarded scheme, issue a redirect to `https://<X-Forwarded-Host>` — pairing the two headers turns a scheme reflection into a controllable **redirect** target.

**34. Unkeyed **query** parameters — examples?**
`utm_*`, `fbclid`, `gclid` — CDNs often strip these from the key but the app still reads/reflects them → unkeyed.

**35. What is a "fat GET"?**
A GET carrying a request **body**; some origins read body params while the cache keys only the URL → the body is fully unkeyed.

**36. What is parameter cloaking?**
Hiding a parameter from the cache using a delimiter the cache treats as one value but the origin splits (e.g. `utm_content=x;callback=payload` — cache sees one `utm_content`, origin reads `callback`).

**37. Duplicate/array parameter trick?**
`?p=1&p=2` or `p[]=…` where cache keys the first occurrence and origin uses the last (or vice-versa) → the "other" value is unkeyed.

**38. What is cache-key injection?**
Injecting characters the cache includes in the key so you can **craft or predict** a victim's cache entry (a partner to normalization attacks).

**39. Why prefer a benign canary over a real payload during discovery?**
Discovery only needs "does it reflect + persist"; a random benign token proves that without ever placing anything malicious on the cache (Guide §20).

---

## D. Poisoning exploitation (40–60)

**40. Unkeyed header reflected into `<script src>` — impact?**
**Critical mass-XSS**: your host is imported as a script on every cached visit → attacker JS runs for every visitor.

**41. Unkeyed header reflected into `Location`/canonical — impact?**
**Cached open redirect** → chain to OAuth token theft / phishing at scale; higher severity than an uncached redirect because it hits everyone.

**42. Unkeyed header reflected raw into HTML — impact?**
**Cached reflected-XSS** if unencoded (attribute/tag breakout). If properly encoded and not in a URL context, it's usually informational — try another header/context.

**43. How do you *prove* poisoning without harming users?**
Cache-buster + benign marker: show a harmless `alert(document.domain)` (from your own host) or a redirect to your own domain served to a **second** request on **your** key. Describe the shared-key blast radius in words; don't inflict it.

**44. Resource poisoning — why is it a crown jewel?**
One poisoned cached JS/CSS affects **every page** importing it → site-wide first-party code execution from a single file.

**45. How can a cached `config.json` lead to full compromise?**
If the SPA reads `apiBaseUrl`/endpoints from a cached JSON you can influence, you redirect the client's tokens/requests to your host or load code from it → Critical, even with no direct HTML reflection.

**46. What is DOM cache poisoning?**
The cached response reflects an unkeyed input into data a **client-side** script later sinks (`innerHTML`/`location`/`eval`/script `src`) → XSS is delivered by the browser from the cached data. Find the sink (XSS/JSFiles kits).

**47. What's "internal cache poisoning"?**
Poisoning a cache **between internal services** that trusts an internal header → reach admin/back-office responses the front-end wouldn't expose.

**48. Poisoning via request smuggling — why is it the strongest?**
A desync lets you plant a response the cache attributes to **another** user's request/URL — poisoning the **shared** key directly, no unkeyed input required.

**49. When the HTML is `no-store`, what are your two pivots?**
(1) **Static resources** (JS/CSS/img are cached → resource poisoning). (2) **Deception** (the cache stores things it shouldn't).

**50. What is the "served to others" proof and why does it matter?**
A second request (that didn't send your input) receiving your influence. It's the line between a **self-XSS non-issue** and a **Critical** — always demonstrate it.

**51. Give the CPDoS variants.**
HHO (oversized header the origin rejects but the CDN caches the error), HMC (meta/control char), HMO (`X-HTTP-Method-Override` making the origin error). The **error gets cached** for the shared key → outage.

**52. How do you safely demonstrate CPDoS?**
With authorization, show the error is **cacheable on your own busted key** (or on staging), and describe the shared-key blast radius. Do not knock a production page offline for real users.

**53. Why is a cached open redirect scored higher than a normal one?**
It's delivered to **every** visitor of the cached page (no per-victim interaction with a crafted link), and it can seed OAuth/token theft broadly.

**54. What contexts make a raw reflection dangerous vs safe?**
Dangerous: inside a URL (`src`/`href`/`Location`), or unencoded in HTML/attribute. Safer: HTML-entity-encoded text not used in a URL. Try to break the encoding with alternate headers before downgrading severity.

**55. Can you poison based on `Accept-Language`/`Accept-Encoding`?**
If the app reflects them and the cache **varies** on them, they're keyed (per-language cache); if it reflects but **doesn't** vary, they can be unkeyed poisoning vectors. Check `Vary`.

**56. What's the risk of poisoning a login/SSO page asset?**
Credential/token theft at scale — a cached redirect or injected script on the auth flow harvests logins from every user (red-team gold; report as Critical).

**57. How does poisoning chain into OAuth?**
A cached open redirect on an allowed host can satisfy a loose `redirect_uri` check or seed phishing → auth-code/token theft (see OAuth kit).

**58. What makes poisoning "stored" rather than "reflected"?**
The cache persists your influence and serves it to others across requests/time — functionally stored XSS, delivered by the cache.

**59. Why record the exact cache layer in your report?**
Remediation differs per CDN (key config, "Cache Deception Armor", honoring `Cache-Control`), and it proves you understood the mechanism.

**60. One-line poisoning remediation?**
Key everything that changes the response (or don't reflect request-controlled data into cached responses), and set correct `Vary`.

---

## E. Deception exploitation (61–78)

**61. Describe the classic deception attack.**
Lure a logged-in victim to `https://target/account/nonexistent.css`; the origin serves their `/account` page (ignoring the suffix), the CDN caches it (sees `.css`), and the attacker then fetches that URL to read the victim's cached private page.

**62. Why does the origin serve the private page for `/account/x.css`?**
Path-normalization/routing: the origin maps `/account/anything` (or truncates at a delimiter) back to `/account`, still authenticated via the victim's cookie.

**63. Why does the cache store it?**
A static rule (extension `.css` or a `/static/`-style dir) tells the CDN "this is a cacheable asset," often **overriding** the origin's `Cache-Control: no-store`.

**64. What does a deception attacker actually steal?**
Whatever is in the victim's authenticated body: PII, **CSRF tokens**, **API keys**, **session surrogates**, **password-reset links** — sometimes enough for full ATO.

**65. The rigorous two-request proof?**
Session A (your victim account) requests the crafted URL → private marker cached; Session B (no cookie) requests the same URL → returns A's marker from cache = cross-session theft.

**66. How do you avoid a false positive where the content is just public?**
Cold-control: fetch a random static-suffix URL **without** auth first; if your marker appears there, it's public (not deception). `deception_probe.py` does this automatically.

**67. What's the modern taxonomy of deception (USENIX 2022)?**
URL-parsing **discrepancies** between origin and cache — path parameters (`;`), encoded delimiters (`%3f %23 %2f %00 %0a`), and normalization differences — not just the naive `/page.css`.

**68. List key delimiter payloads.**
`/account.css`, `/account/x.css`, `/account;x.css`, `/account%3f.css`, `/account%23.css`, `/account%2f.css`, `/account%00.css`, `/account%0a.css`, `/account%5c.css`, `/account%252ecss`.

**69. Why try multiple extensions?**
CDNs cache different suffixes; a sensitive route may refuse `.css` routing but accept `.js` or `.jpg`. Walk `.css/.js/.jpg/.png/.ico/.svg`.

**70. What is directory-rule deception?**
Routing a dynamic page "under" a cached static directory via traversal — `/static/..%2faccount`, `/assets/%2e%2e/settings`.

**71. What's content-type confusion here?**
The origin returns `text/html` but the CDN caches on URL pattern, ignoring `Content-Type` → private HTML cached as if static.

**72. When is deception Critical vs High?**
Critical (ATO) if the cached body contains a **reusable auth artifact** (session/bearer/reset/API token); High if it's CSRF token or PII only.

**73. Does deception need victim interaction?**
Yes — the victim must load the crafted URL (a link, `<img>`, `<iframe>`, or email). It's low-interaction but not zero (reflected in the CVSS `UI:R`).

**74. Why is a leaked CSRF token still High?**
It enables **CSRF-as-the-victim** (state-changing actions in their account) even without their session cookie.

**75. How do you find the best sensitive base path?**
`/account`, `/settings`, `/profile`, `/api/me`, `/orders`, `/messages`, billing/admin pages — anything returning per-user data with tokens.

**76. What's the safe-PoC rule for deception?**
Two of **your own** accounts + a benign private marker (your test email). One cross-session retrieval proves it — then stop; never harvest a real user's page.

**77. One-line deception remediation?**
Cache by `Content-Type` (not URL suffix), **honor `Cache-Control: no-store`**, enable Cache Deception Armor, and serve authenticated pages `no-store, private`.

**78. How does bfcache/browser-cache relate to deception?**
Sensitive pages restored from bfcache/browser cache after logout leak session/PII on shared devices — recommend `no-store, private` + `Clear-Site-Data` on logout.

---

## F. Validity, false positives & severity (79–90)

**79. The single golden rule for any cache finding?**
It's only real when the cache **re-serves** your influence to a **different** request (poison) or the victim's response to you (deception). Reflection/echo alone is a lead.

**80. Top false positive #1?**
"A header is reflected" — with no proof the response is **cached** and served to a **second** request that didn't send it (that's self-XSS, not poisoning).

**81. Top false positive #2?**
Deception "works" but only with **your own cookie** present — you just fetched your own page; you must show Session B (no cookie) getting Session A's data.

**82. Why isn't `Cache-Control: public` a finding?**
A header ≠ a cached **sensitive** response. You need an actual HIT on sensitive/authenticated content (deception) or a served-to-others poison.

**83. Why isn't a Param Miner "unkeyed input" hit a finding by itself?**
It's a tool lead. Reproduce reflection + served-to-others + a concrete XSS/redirect/leak by hand.

**84. CVSS anchor for poisoning→mass-XSS?**
`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` ≈ **9+ Critical** (scope-changed, unauth, zero-interaction).

**85. CVSS anchor for deception→token theft?**
`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` ≈ **High/Critical** (victim loads the URL).

**86. Primary CWEs?**
CWE-349 (untrusted data accepted with trusted) for poisoning + the delivered CWE-79/601; CWE-524/525 (cached sensitive info) for deception; CWE-400 for CPDoS.

**87. When is an open redirect a *cache* finding vs a plain one?**
If it's **cached** (served to everyone), it's a higher, distinct finding; if not cached, it's an ordinary (lower) open redirect.

**88. How do you keep deception tests low-FP?**
Cold public-content control + require the marker in **both** the authenticated response and the session-less response + prefer a cache **HIT** header on the session-less fetch.

**89. What downgrades a poisoning finding to Informational?**
The input is **keyed** (a request without it loses your canary), or the response isn't cached, or the reflection is safely encoded and not in a URL context.

**90. Why re-test partial fixes?**
Keying one header but not another, honoring `no-store` on one route but not a sibling, or fixing `.css` but not `.js` is a **fresh** valid finding.

---

## G. SAFE-PoC, reporting & red-team (91–100)

**91. The one rule that keeps you safe on poisoning?**
Always use a cache-buster so your payload lands on **your** key, prove control with a **benign** marker, and describe the shared-key impact — don't inflict it on real users.

**92. What if you must touch a shared key (authorized)?**
Pick a low-traffic path, use a self-contained benign proof, **purge** or let it expire immediately, and document it.

**93. What must a poisoning report contain?**
The cache layer + hit/miss evidence, the unkeyed input, the reflection sink, and request/response pairs showing **MISS→HIT** + your benign marker served to a **clean** request.

**94. What must a deception report contain?**
The crafted URL + caching rule, and the **two-session** proof (A's marker retrieved by B with no cookie + a HIT), graded by the leaked artifact.

**95. How do you de-duplicate cache findings?**
One **root cause** (one unkeyed input, or one path-confusion class) = one report even across many pages; lead with the highest impact (mass-XSS > redirect).

**96. Always recommend what operational step?**
A **cache purge** of the poisoned/affected entries, plus the config fix (key/`Vary`/`no-store`/Content-Type caching/Deception Armor).

**97. Red-team: quietest high-impact cache play?**
Poison a shared JS **config** (`apiBaseUrl`) so every client silently sends tokens/requests to your host — site-wide and low-noise.

**98. Red-team: how to weaponize deception on a portal?**
Lure an admin to a crafted static-suffix URL to cache their admin page, then lift the admin CSRF/session for privilege escalation.

**99. Which kits chain with this one?**
HostHeader (reflection source), RequestSmuggling (shared-cache poisoning), OAuth (cached redirect → token theft), XSS/JSFiles (DOM sinks), SSRF (via poisoned redirect targets).

**100. Final mental checklist before submitting?**
Cache confirmed? Unkeyed/served-to-others (poison) or cross-session (deception) proven? Benign marker + cache-buster/own-accounts used? Impact + blast radius named? Purge + fix recommended? If all yes → it's the Critical/High it's worth.

---

> **The one rule that pays:** a cache bug is real only when the cache **re-serves** your influence to someone else's request. Prove that half on a **cache-busted key with a benign marker** (poisoning) or with **two of your own sessions** (deception), name the **blast radius**, and you've turned a reflected header or a `.css` suffix into a Critical.
