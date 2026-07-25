# Web Cache Poisoning & Deception — Zero to Expert (Q&A)

**Author:** x8bitranjit
Study guide + field reference, built to be read cover-to-cover **or** grepped mid-hunt. Answers are **layered** — a
plain-language explanation anyone can follow, then the theory/mechanism, then the technical detail, then the
practical/red-team angle — and most carry a **worked example** you can picture on the wire. Impact-first: the finding is
always **"the cache re-serves it to a different request."** Pair with `WEB_CACHE_TESTING_GUIDE.md`. Authorized targets
only; cache-buster + own accounts + benign markers (Guide §20).

**Levels:** A Fundamentals · B Detection & the HIT/MISS oracle · C Cache-buster & key discovery · D Poisoning
exploitation · E Deception exploitation · F Validity, false-positives & severity · G SAFE-PoC, reporting & red-team ·
**H Interview questions (articulate it out loud)** · **I Scenario-based (you're handed a situation)**.

---

## A. Fundamentals (1–15)

**1. What is a web cache, in one sentence — and why should an attacker care?**
An intermediary that stores **one** response and re-serves it for later "matching" requests, so the origin isn't hit every time.
- **Plain:** a coffee shop that brews **one batch per drink name** and hands the saved batch to everyone who orders it — instead of remaking each cup. Fast, but one spiked batch reaches every customer.
- **Theory:** the cache sits *between* the user and the origin and answers from storage whenever a new request "matches" a stored one. "Match" is decided by a **cache key** (Q2), not by the full request — so any request detail outside the key is invisible to the matching logic but still seen by the origin.
- **Why an attacker cares:** that storage is **shared across users**. A bug that normally affects only your own request (a reflected header) becomes a bug that affects **everyone who hits the same key** — the cache does the "deliver to every victim" work for you. That single property is why a Low-looking reflection becomes a Critical.

**2. What is a "cache key" and what's typically in it?**
The subset of the request the cache uses to decide "same request?" — typically `scheme + host + path + (some) query params`, plus any header named in `Vary`.
- **Plain:** the **name written on the cup.** The shop treats two cups with the same name as identical.
- **Theory:** everything you send splits into two buckets — **keyed** (part of the name → the cache distinguishes on it) and **unkeyed** (the barista hears it, the kitchen may act on it, but it's *not* written on the cup). The origin sees the *whole* request; the cache matches on the *key only*. The gap between those two sets is the entire attack surface.
- **Technical:** a default CDN key is often `Host + path + full query string`. Operators frequently *shrink* it for hit-rate — dropping `utm_*`/`fbclid` from the key, ignoring most headers — and every dropped-but-still-reflected element becomes an unkeyed primitive.
- **Practical:** your first job on any target is to *map* the key: change one thing at a time and watch whether the response identity (via the oracle, Q16) changes → that element is keyed; if the response is the *same cached one* → it's unkeyed.

**3. What is an "unkeyed input", concretely?**
A request element the origin **reflects or acts on** but the cache **omits from the key**.
- **Plain:** the ingredient the **kitchen adds but the barista never writes on the cup.** That's what lets you spike a batch invisibly — the shop can't tell your spiked cup from a plain order, so it serves your spiked batch to everyone.
- **Technical:** the canonical example is `X-Forwarded-Host`. Apps build absolute URLs from it (links, `<script src>`, `Location`, canonical); CDNs almost never key on it. So it is *reflected* (origin acts on it) **and** *unkeyed* (cache ignores it) = a poisoning primitive.
- **Worked example:**
  ```http
  GET /?cb=1 HTTP/1.1
  X-Forwarded-Host: evil.com      →  <script src="https://evil.com/app.js"></script>   (reflected)
  GET /?cb=1 HTTP/1.1             (no header, same key)  →  still evil.com, X-Cache: HIT (unkeyed + cached) ⭐
  ```
- **Practical:** "reflected" alone is a *lead*; "reflected **and** served to a request that didn't send it" is the *primitive*. Always prove the second half.

**4. One-line difference between poisoning and deception — and the direction of each?**
Poisoning = **attacker → cache → all victims** (your payload cached & served to everyone). Deception = **victim → cache → attacker** (the victim's private response cached & served to you).
- **Plain:** **poisoning** = you spike the shared batch so every customer drinks your payload. **deception** = you trick the shop into shelving *someone else's personal drink* (their secrets on the cup) on the public counter, then grab it.
- **Theory:** both exploit the *same* origin↔cache mismatch, but from opposite ends. Poisoning abuses an **unkeyed input** (the cache stores something *you* influenced under a key others hit). Deception abuses a **should-not-be-cached response** (the cache stores something the origin meant for *one authenticated user* under a URL *you* can fetch).
- **Practical:** the tell tells you which one you're in — if *your input* shows up in *others'* responses, that's poisoning; if *another session's data* shows up in *your* session-less response, that's deception.

**5. Why is a cache bug often *more* severe than the same bug uncached?**
Scale + zero interaction.
- **Theory:** a reflected-header XSS normally affects only the one request that carried the header — effectively self-XSS, near-worthless. Cache it and it becomes **stored XSS delivered to every visitor** of that key, unauthenticated, no click. An open redirect becomes a **cached** mass-phishing/token-theft primitive rather than a per-victim link.
- **Worked example:** `X-Forwarded-Host: evil.com` reflected into `<script src>` on a *non-cached* page = you XSS yourself. On a *cached* home page = you XSS every single visitor until the entry expires or is purged. Same payload, Low → Critical, purely because of the cache.
- **Practical:** this is *why* you always hunt the caching layer even when the underlying reflection looks boring.

**6. Name the cache layers you might be attacking.**
- CDN/edge: **Cloudflare, Akamai, Fastly (Varnish), AWS CloudFront, Azure CDN, Google Cloud CDN, Sucuri, Imperva.**
- Reverse proxies: **Varnish, nginx `proxy_cache`, Apache Traffic Server, Squid, HAProxy.**
- App/framework: **Drupal cache, WordPress (WP Rocket/W3TC), Rails/Rack, Next.js/Vercel data & full-route cache, Spring Cache.**
- Browser: the user's own HTTP cache + **bfcache** (Q78, §16).
- **Why it matters:** each layer keys and parses URLs **differently**, and that per-layer difference is often the exploitable delta (Q13). Fingerprint the layer first (Q23) so you test the right quirks.

**7. What decides whether a response is cached at all?**
- **Extension rules** (`.js .css .png .ico .svg .woff .jpg .pdf …`) — the classic deception lever.
- **Directory/path-prefix rules** (`/static/ /assets/ /media/`).
- **Response headers** the origin sends: `Cache-Control` / `Expires` / `s-maxage`.
- **CDN page rules** an operator configured (often over-broad).
- **Heuristic caching** — some caches store a bare `200` with no cache headers for a default TTL.
- **Practical:** the danger zone is when a **URL-shape rule** (extension/dir) **overrides** the origin's header intent — that override is the root cause of most real-world deception (Q63).

**8. What is the core "mismatch" every cache bug exploits?**
The delta between **what the cache keys on / stores** and **what the origin reflects / serves.**
- **Plain:** the gap between what the barista writes on the cup and what the kitchen actually does.
- **Practical:** find that gap and you have a primitive. Poisoning = "origin reflects it, cache doesn't key it." Deception = "origin marks it private, cache stores it anyway." Two shapes of one root idea.

**9. Why does `Vary` matter so much?**
`Vary` names the request headers the cache **includes** in the key.
- **Theory:** it's the origin's way of telling the cache "these headers change my response, so key on them." If the app reflects a header into the response but the origin **doesn't** list it in `Vary`, the cache won't key on it → that header is **unkeyed and poisonable**. `Vary` is literally the config knob that decides whether your reflected header is a bug.
- **Worked example:** app reflects `X-Forwarded-Host` into a link but responds `Vary: Accept-Encoding` (no `X-Forwarded-Host`) → the header is unkeyed → poisonable. Correct fix: add it to `Vary` (or stop reflecting it).

**10. Is HTTPS a defense against cache poisoning?**
No.
- **Theory:** TLS protects data *in transit* between hops. The cache still terminates/keys/stores exactly the same way. Poisoning and deception are **logic bugs at the caching layer**, not transport bugs — HTTPS is orthogonal.
- **Practical:** don't let "it's all HTTPS" reassure a client; it says nothing about how the CDN builds its key.

**11. Shared cache vs private (browser) cache — why does the distinction change severity?**
- **Shared** (CDN/proxy): one stored response serves **many users** → poisoning/deception **scale** → High/Critical.
- **Private** (browser cache/bfcache): affects **one** user → lower blast radius, but still relevant for post-logout data exposure on shared devices (Q78).
- **Practical:** always confirm whether the cache you've hit is shared (does a *different* client get your entry?) before you claim mass impact.

**12. Define "resource poisoning" and why it's a crown jewel.**
Poisoning a cached **static asset** (JS/CSS) rather than an HTML page.
- **Theory:** even when the HTML is `no-store`, the resources it imports (`/app.js`, `/styles.css`) are **almost always** cached — that's the entire point of a CDN. One poisoned `/app.js` executes on **every page that imports it.**
- **Worked example:** `/static/config.js` templates `window.API = "//<X-Forwarded-Host>"`. Poison the header once → the cached JS points every page's API calls (with tokens) at your host → site-wide, quiet, Critical.
- **Practical:** when the page won't cache, pivot straight to its resources (Q49).

**13. Define "cache entanglement" (Kettle, 2020).**
Exploiting **cache-key normalization** differences so two *different* requests map to **one** key.
- **Theory:** the cache normalizes the key (lowercase, URL-decode, strip, reorder, trim) **differently** from how the origin resolves the request. If the cache decodes `%61` → `a` before keying but the origin serves on the raw path, you can populate the *normalized* key real users hit while requesting a "different" raw URL — smuggling your response under their key (or vice-versa).
- **Practical:** subtle and per-CDN; you find it by probing case/encoding/trailing-char handling (Q's in level C) and watching which variants *collapse to the same cache entry.*

**14. What is CPDoS?**
Cache-Poisoned Denial of Service — poison the cache with an **error/oversized** response so it serves that error to everyone → outage.
- **Variants:** **HHO** (oversized header the origin rejects but the CDN caches the error), **HMC** (meta/control char), **HMO** (`X-HTTP-Method-Override` makes the origin error). The **error gets cached** for the shared key.
- **Practical:** it's a **DoS** — authorize it, prove the error caches on your *own* busted key, never knock a live shared page offline (Q52).

**15. Where do cache bugs sit relative to Host-header and request-smuggling bugs?**
Adjacent and complementary.
- `Host`/`X-Forwarded-Host` reflection (**HostHeader kit**) is the most common **poisoning source**.
- Request **smuggling** (**RequestSmuggling kit**) is a way to poison the **shared** cache **directly** — no unkeyed input needed (Q48).
- **This kit is the caching-impact layer over both:** HostHeader/Smuggling give you the primitive; this kit turns it into "served to every user" and rates it.

---

## B. Detection & the HIT/MISS oracle (16–27)

**16. What's the very first question before testing either bug — and why?**
"Is this response actually **cached**, and how do I tell a **HIT** from a **MISS**?"
- **Theory:** every proof in this class is "the cache *re-served* it." Without a reliable way to see hit vs miss, you can't demonstrate the one thing that makes it a finding. No oracle → no valid test.
- **Practical:** build the oracle (Q17–Q21) *before* you touch a payload; it's the instrument you measure everything else with.

**17. Which response headers reveal a cache?**
`X-Cache: HIT/MISS`, `CF-Cache-Status: HIT/MISS/DYNAMIC`, `Age: <n>`, `X-Cache-Hits: N`, `X-Served-By`/`X-Timer` (Fastly), `X-Varnish: <id> <id2>`, `X-Drupal-Cache`, `X-Vercel-Cache`, plus policy hints `Cache-Control`/`Expires`/`Vary`/`ETag`/`Last-Modified`.
- **Worked example:**
  ```
  1st:  X-Cache: MISS   Age: 0
  2nd:  X-Cache: HIT    Age: 7     ← cached; oracle established
  ```

**18. How do you build a HIT/MISS oracle when there are **no** cache headers?**
- **Timing:** a hit returns much faster (served from edge memory, no origin round-trip).
- **`Age` growth:** if `Age` climbs across identical requests, it's cached.
- **Dynamic marker:** send twice and diff a value that *should* change every time — a timestamp, nonce, or CSRF token. If it's **identical** on the second request, that response was served from cache.
- **Practical:** the dynamic-marker trick is the most reliable when the CDN hides its headers; pick any per-request-unique field in the body.

**19. `CF-Cache-Status: DYNAMIC` — what does it mean for you?**
Cloudflare is **not** caching that response → you can't poison *it*.
- **Practical:** don't stop — pivot to (a) **static resources** (JS/CSS almost always cache → resource poisoning) or (b) **deception** (which caches things that "shouldn't" be). `DYNAMIC` on the HTML is a redirect sign, not a dead end.

**20. `Age: 0` on every request — cached or not?**
Probably **not** cached (or always-revalidated).
- **Technical:** confirm with a second identical request; if `Age` never grows *and* there's no HIT header *and* a dynamic marker changes each time → treat as uncached and pivot.
- **Caveat:** some caches reset `Age` oddly; corroborate with timing and the marker before concluding.

**21. Why send the request twice?**
- **Theory:** the **first** request populates the cache (MISS → stored); the **second** reveals whether it's served from storage (HIT / `Age`>0 / faster). The pair *is* the oracle — one request alone can't tell you cacheability.

**22. What's a "hit counter" tell?**
`X-Cache-Hits: N` (Varnish/Fastly) rising, or `X-Varnish: <id1> <id2>` showing **two** IDs (the second = the cached-object ID). Both mean "came from cache."

**23. How do you fingerprint the CDN, and why bother?**
Header signatures: `cf-ray` → **Cloudflare**; `x-served-by`/`x-timer` → **Fastly**; `via: cloudfront` + `x-amz-cf-id` → **CloudFront**; `server: AkamaiGHost`/`x-akamai-*` → **Akamai**; `x-varnish` → **Varnish**; `x-vercel-cache` → **Vercel/Next.js**.
- **Why bother:** each layer keys and *parses URLs* differently, so the fingerprint tells you which deception rows and which normalization quirks to try first (e.g. Cloudflare's Cache Deception Armor vs Akamai's extension+path rules). `poc/cache_detect.py` automates this.

**24. Does a `Set-Cookie` in a response affect caching?**
Usually yes — many caches **refuse** to store responses carrying `Set-Cookie` (they're inherently user-specific).
- **Practical:** its presence/absence is a double clue — it hints whether a response is cacheable *and* flags deception risk (a `Set-Cookie`-free authenticated page is a deception candidate). Some misconfigured CDNs cache despite `Set-Cookie` → that itself is a finding.

**25. What is "heuristic caching"?**
A cache storing a `200` that has **no** explicit `Cache-Control`, for some default TTL.
- **Practical:** it's an *accidental* cacheability — a page nobody meant to cache becomes cacheable, opening both poisoning (of that page) and deception. Always test even "un-cache-controlled" pages twice.

**26. Why check both the HTML page **and** its resources?**
Because they cache **independently**. The page may be `no-store` while its `/app.js` and `/styles.css` are aggressively cached.
- **Practical:** resource poisoning (Q12/Q44) works even when the page refuses to cache — never conclude "not cacheable" from the HTML alone.

**27. What tool automates unkeyed-input discovery, and what does it actually do?**
**Param Miner** (Burp, James Kettle).
- **Technical:** it brute-forces thousands of header/param names, plants **cache-busted canaries**, and flags "unkeyed input"/"unkeyed header" candidates by detecting when a value it injected is reflected *and* the response is cacheable.
- **Practical:** treat its output as **leads**, not findings — reproduce each by hand with the 4-step canary (Q30) and prove the served-to-others half.

---

## C. Cache-buster & key discovery (28–39)

**28. What is a cache-buster and why is it non-negotiable?**
A unique **keyed** value (usually `?cb=random`) that lands your test response on **your own** key — so you never poison the shared entry real users get.
- **Plain:** **ordering under a unique name nobody else uses.** Your spiked batch is filed under *your* name only; real customers never touch it.
- **Safety (the point):** testing poisoning **without** a buster on production = you just served real people a malicious drink = out-of-scope harm. The buster is both a **safety belt** and an **isolation microscope** (a guaranteed private MISS you control).
- **Worked example:** `GET /?cb=poc7` with your payload → poisons only the `?cb=poc7` entry. The bare `/` that users hit is untouched.

**29. What must you verify about your buster **before** firing payloads?**
That it is **keyed** — each new value yields a fresh **MISS**.
- **Technical:** if the buster is *itself* unkeyed (the CDN strips `cb` from the key), your "isolation" is an illusion and your payload could hit the shared entry. Verify: `?cb=aaa` and `?cb=bbb` must each return MISS-then-HIT independently.
- **Practical:** if you can't find a keyed buster, **do not** fire poisoning payloads at a shared prod cache — describe the primitive and test on staging/own key (Q92).

**30. Walk the 4-step unkeyed-input confirmation.**
1. Request with a **canary** in the candidate header (cache-busted key).
2. Is the canary **reflected** in the response?
3. Request the **same key** again, **without** the header.
4. Is the canary **still** served (from cache)?
- **Yes to 2 and 4 → unkeyed + poisonable.** Step 4 is the one that matters — it's the "served to a request that didn't send it" proof in miniature.
- **Worked example:** `X-Forwarded-Host: cnry123.oast` → reflected in a link (step 2); re-request with no header → link still says `cnry123.oast`, `X-Cache: HIT` (step 4) → confirmed.

**31. Best high-yield headers to canary?**
`X-Forwarded-Host`, `X-Host`, `X-Forwarded-Scheme`, `X-Forwarded-Proto`, `X-Forwarded-Server`, `X-Forwarded-Port`, `Forwarded`, `X-Original-URL`, `X-Rewrite-URL`, `X-Original-Host`, `X-Forwarded-SSL`, plus **app-custom** headers discovered via Param Miner's wordlist.

**32. Why is `X-Forwarded-Host` the classic?**
- **Theory:** apps behind proxies can't trust `Host` for building absolute URLs, so frameworks read `X-Forwarded-Host` to reconstruct "the public hostname" — and drop it into links, redirects, resource `src`, canonical, `og:url`. Meanwhile CDNs treat it as a hop-by-hop routing hint and **don't key on it.** Reflected + unkeyed = poisonable, on a huge number of stacks.

**33. What is the `X-Forwarded-Scheme: nothttps` (or `X-Forwarded-Proto: http`) trick?**
- **Theory:** some apps, seeing a non-`https` forwarded scheme, "helpfully" issue a redirect to the secure URL — built as `https://<X-Forwarded-Host>/…`. Send **both** headers and you turn a passive scheme reflection into a **controllable redirect target.**
- **Worked example:**
  ```http
  X-Forwarded-Host: evil.com
  X-Forwarded-Scheme: nothttps   →   HTTP/1.1 302   Location: https://evil.com/…   (cached open redirect)
  ```

**34. Unkeyed **query** parameters — examples and why?**
`utm_*`, `fbclid`, `gclid`.
- **Theory:** CDNs deliberately **strip analytics params from the key** to raise hit-rate (so `?utm_source=a` and `?utm_source=b` share one entry), but the **app still reads/reflects them.** Reflected + excluded-from-key = unkeyed.
- **Practical:** confirm with the canary that a second request *without* the param still returns your value.

**35. What is a "fat GET"?**
A `GET` carrying a request **body**.
- **Theory:** some origins parse body params even on GET; caches key on the **URL only** → the body is **100% unkeyed.**
- **Worked example:**
  ```http
  GET /search?cb=U HTTP/1.1
  Content-Length: 30

  q="><script>alert(1)</script>      ← origin reads q= from the body, cache ignores it → unkeyed reflection
  ```

**36. What is parameter cloaking?**
Hiding a parameter from the cache using a **delimiter** the cache treats as part of one value but the origin **splits** on.
- **Worked example:** `?utm_content=x;callback=alert(1)` — the cache sees a single `utm_content` value (which it ignores/keys as one blob), while the origin splits on `;` and reads `callback=alert(1)` → unkeyed injection into a JSONP callback.

**37. Duplicate/array parameter trick?**
`?p=1&p=2` (or `p[]=…`) where the **cache keys the first** occurrence and the **origin uses the last** (or vice-versa) → the "other" value is unkeyed.
- **Practical:** parser disagreement (HPP) at the caching layer — test both orderings and watch which value survives into the cached response.

**38. What is cache-key injection?**
Injecting characters the cache **includes** in the key so you can **craft or predict** a victim's cache entry — a partner technique to normalization/entanglement (Q13). If you can compute the exact key a victim's request will produce, you can pre-populate it with your response.

**39. Why prefer a benign canary over a real payload during discovery?**
Discovery only needs to answer "does it reflect **and** persist?" — a random benign token (`cnry8f3a`) proves that without ever placing anything malicious on the cache. You escalate to a real (still benign-proof) payload only *after* the primitive is confirmed, and only on your own busted key (Guide §20).

---

## D. Poisoning exploitation (40–60)

**40. Unkeyed header reflected into `<script src>` — impact and why it's the top prize?**
**Critical mass-XSS.**
- **Plain:** your spiked ingredient landed in the part of the drink the browser **runs as code** — every customer's saved batch executes your JavaScript.
- **Theory:** a `<script src="//evil.com/app.js">` cached into the page means every visitor's browser fetches and runs *your* JS in the **origin's** security context — full DOM access, cookies (if not HttpOnly), token theft, keylogging, drive-by. Unauthenticated, zero-click, every visitor.
- **Worked example:** `X-Forwarded-Host: evil.com` → `<script src="https://evil.com/app.js">` cached on `/` → serve `alert(document.domain)` from `evil.com` → it fires first-party for everyone until the entry expires.

**41. Unkeyed header reflected into `Location`/canonical — impact?**
**Cached open redirect.**
- **Theory:** the redirect is now served to **everyone** who hits the page, not just a victim who clicked your crafted link — so it seeds mass phishing and, critically, **OAuth token/`code` theft** if the redirect lands on an SSO flow (→ OAuth kit). Higher severity than an uncached redirect precisely because of the audience.

**42. Unkeyed header reflected **raw** into HTML — impact?**
**Cached reflected-XSS** if unencoded (attribute or tag breakout).
- **Practical:** if it's properly HTML-encoded *and* not in a URL context, it's usually informational — try another header (`X-Forwarded-Scheme`, `X-Forwarded-Port`) or a second reflection point before downgrading.

**43. How do you *prove* poisoning without harming users?**
Cache-buster + benign marker.
- **Method:** show a harmless `alert(document.domain)` (served from *your* host) or a redirect to *your* domain, returned to a **second** request on **your** busted key. Describe the shared-key blast radius **in words**; don't inflict it.
- **The rule:** one benign proof on a key only you receive = the finding. Never leave a live XSS/redirect on the shared entry.

**44. Resource poisoning — why is it a crown jewel? (with example)**
One poisoned cached JS/CSS affects **every page** that imports it.
- **Worked example:** `/static/app.js` is cached and reflects `X-Forwarded-Host` into `window.API="//<host>"`. Poison it once → the app's runtime config now points at your host site-wide → every client sends its API traffic (and bearer tokens) to you. Quiet, persistent, Critical — from a single file.

**45. How can a cached `config.json` lead to full compromise?**
If the SPA reads `apiBaseUrl`/endpoints/feature-flags from a cached JSON you can influence, you redirect the client's tokens/requests to your host or flip a flag that loads code from it → Critical, even with **no direct HTML reflection** (the raw response "just reflects a value" — the impact is downstream in the client).

**46. What is DOM cache poisoning?**
The cached response reflects an unkeyed input into **data** a **client-side** script later sinks (`innerHTML`/`location`/`eval`/script `src`).
- **Theory:** the server response looks benign (no `<script>` in it), but the browser turns the cached *data* into XSS when the app's JS reads it into a sink. You need to find the sink (pair with the XSS/JSFiles kits).
- **Practical:** search the cached body for values that flow into `.innerHTML =`, `document.write`, `eval`, `location =`, `element.src =`.

**47. What's "internal cache poisoning"?**
Poisoning a cache **between internal services** (microservice-to-microservice) that trusts an **internal** header. Poison it to reach **admin/back-office** responses the front-end would never expose — a lateral-movement flavor of the same bug.

**48. Poisoning via request smuggling — why is it the strongest delivery?**
- **Theory:** a **desync** (RequestSmuggling kit) lets you plant a response the cache attributes to the **next** user's request/URL — poisoning the **shared** key **directly**, with **no unkeyed input required** and **no reflection needed.** It's how smuggling escalates from "desync" to "mass XSS/redirect."
- **Practical:** if the target is smuggling-vulnerable **and** cached, this bypasses the entire unkeyed-input hunt — build the desync there, apply this kit's impact model.

**49. When the HTML is `no-store`, what are your two pivots?**
(1) **Static resources** — JS/CSS/img are cached → **resource poisoning** (Q12/Q44). (2) **Deception** — the cache stores things it "shouldn't" (Q61). A `no-store` HTML page closes one door and points straight at these two.

**50. What is the "served to others" proof and why is it the whole game?**
A **second** request (that did **not** send your input) receiving your influence.
- **Theory:** it's the exact line between a **self-XSS non-issue** (only your own request is affected) and a **Critical** (the cache re-serves your payload to strangers). Every valid poisoning report contains this pair. If you can't produce it, you don't have the bug — you have a reflection.

**51. Give the CPDoS variants (with the mechanism).**
- **HHO** (HTTP Header Oversize): send an oversized header the **origin** rejects (`400`/`431`) but the **CDN forwards and caches** the error.
- **HMC** (HTTP Meta Character): inject a control char (`\n`, `\r`, `%00`) the origin errors on but the cache stores.
- **HMO** (HTTP Method Override): `X-HTTP-Method-Override: DELETE` makes the origin error; the error is cached for the `GET` key.
- In all three, the **error is cached** for the shared key → a normal request then gets the cached `4xx` → outage.

**52. How do you *safely* demonstrate CPDoS?**
With authorization: show the error is **cacheable on your own busted key** (or on staging), and **describe** the shared-key blast radius. Never knock a production page offline for real users — it's a genuine DoS.

**53. Why is a cached open redirect scored **higher** than a normal one?**
It's delivered to **every** visitor of the cached page (no per-victim interaction with a crafted link), and it can seed OAuth/token theft **broadly**. Audience + delivery mechanism both go up, so severity does too — and it's a **distinct** finding from the uncached redirect (say so in the report).

**54. What contexts make a raw reflection dangerous vs safe?**
- **Dangerous:** inside a URL (`src`/`href`/`Location`), or unencoded in HTML/attribute (breakout).
- **Safer:** HTML-entity-encoded text **not** used in a URL.
- **Practical:** before downgrading a "safe" reflection, try to **break the encoding** with an alternate header or a second sink — many "encoded" reflections have a sibling reflection that isn't.

**55. Can you poison based on `Accept-Language`/`Accept-Encoding`?**
Only if the cache handles them wrong.
- **Technical:** if the app reflects them **and** the cache **varies** on them, they're keyed (a per-language cache — safe-ish). If it reflects but **doesn't** vary, they're **unkeyed poisoning vectors.** Always check the `Vary` header to decide which case you're in.

**56. What's the risk of poisoning a login/SSO page asset?**
**Credential/token theft at scale.** A cached redirect or injected script on the auth flow harvests logins from **every** user hitting it — red-team gold; report as Critical and chain to the OAuth kit.

**57. How does poisoning chain into OAuth?**
A **cached open redirect on an allowed host** can satisfy a loose `redirect_uri` check or seed a convincing phishing flow → auth-`code`/token theft → ATO (OAuth kit). The cache turns a one-off redirect into a broadcast one.

**58. What makes poisoning "stored" rather than "reflected"?**
The cache **persists** your influence and serves it to others across requests and time — functionally **stored XSS**, delivered by the cache instead of a database. That persistence-to-others is why it's rated like stored, not reflected.

**59. Why record the exact cache layer in your report?**
Because **remediation differs per CDN** (key config, `Vary`, "Cache Deception Armor", honoring `Cache-Control`), and naming the layer + its hit/miss evidence proves you understood the *mechanism*, not just the symptom. It also helps the triager reproduce.

**60. One-line poisoning remediation?**
**Key everything that changes the response** (add the reflected header/param to the cache key), or better, **don't reflect request-controlled data** into cached responses at all — and set correct `Vary`.

---

## E. Deception exploitation (61–78)

**61. Describe the classic deception attack — with the mechanism and the historical origin.**
- **Plain:** you lure the logged-in victim to `/account/nonexistent.css`. The **kitchen** ignores the `.css` and makes their real private account page; the **barista** sees `.css`, calls it a standard static item, and shelves that private page on the public counter. You then order the same `.css` with no login and get handed the victim's page. One decorative suffix turned private into public.
- **Mechanism:** the origin **maps `/account/anything` back to `/account`** (extra segment ignored) and serves it **authenticated** via the victim's cookie; the cache sees a **static extension** and stores it, often **overriding** the origin's `no-store`.
- **Origin of the class:** this is exactly the attack **Omer Gil** debuted on **PayPal** at Black Hat USA 2017 — `/myaccount/home/ex.css` returned the victim's cached account page — which coined the term "Web Cache Deception."

**62. Why does the origin serve the private page for `/account/x.css`?**
Path-normalization/routing: the origin's router maps `/account/<extra>` (or **truncates at a delimiter**) back to `/account`, and it's **still authenticated** because the victim's cookie rode along. The `.css` is meaningless to the router but meaningful to the cache — that asymmetry is the whole bug.

**63. Why does the cache store it, even against `no-store`?**
A **static rule** — extension `.css` or a `/static/`-style dir — tells the CDN "this is a cacheable asset," and that URL-shape rule **overrides** the origin's `Cache-Control: no-store`. That override is the recurring **root cause**: the cache's "this looks static" heuristic beats the origin's "this is private" intent.

**64. What does a deception attacker actually steal?**
Whatever is in the victim's authenticated body: **PII**, **CSRF tokens**, **API keys**, **session surrogates**, **password-reset links/tokens** — sometimes directly enough for **full ATO** (Q72).

**65. The rigorous two-request proof?**
Session **A** (your "victim" account) requests the crafted URL → the private marker is cached; Session **B** (a different browser / **no cookie**) requests the **same URL** → returns A's marker **from cache** = cross-session theft.
- **Worked example:**
  ```http
  GET /account%3f.css   Cookie: session=A   →   200, your marker "alice-poc@…", X-Cache: MISS
  GET /account%3f.css   (no cookie)         →   200, SAME marker, X-Cache: HIT   ← cross-session ⭐
  ```

**66. How do you avoid a false positive where the content is just public?**
**Cold-control:** fetch a random static-suffix URL **without** auth *first*. If your marker appears there, the content is **public** (not deception). `deception_probe.py` runs this control automatically, so a "hit" isn't miscounted as theft.

**67. What's the modern taxonomy of deception (USENIX 2022)?**
URL-parsing **discrepancies** between origin and cache — **path parameters** (`;`), **encoded delimiters** (`%3f %23 %2f %00 %0a`), and **normalization** differences — not just the naive `/page.css`. Mirheidari et al. ("Web Cache Deception Escalates!", ≈340 sites) showed sites "protected" against the classic trick were still exploitable through a delimiter the **origin truncates but the cache keys.**

**68. List the key delimiter payloads.**
`/account.css`, `/account/x.css`, `/account;x.css`, `/account%3f.css`, `/account%23.css`, `/account%2f.css`, `/account%00.css`, `/account%0a.css`, `/account%09.css`, `/account%5c.css`, `/account%252ecss`.
- **How to read the winner:** the exploitable row is the one where the **origin still returns your private body** *and* the **cache flips to a session-less HIT** (Q65).

**69. Why try multiple extensions?**
CDNs cache different suffixes, and origins route them differently — a sensitive route may refuse `.css` routing but accept `.js` or `.jpg`. Walk `.css/.js/.jpg/.png/.ico/.svg` before concluding a page is safe.

**70. What is directory-rule deception?**
Routing a dynamic page "under" a **cached static directory** via traversal — `/static/..%2faccount`, `/assets/%2e%2e/settings`. The CDN trusts `/static/*` as always-cacheable; the traversal smuggles a dynamic page into that trusted prefix.

**71. What's content-type confusion here?**
The origin returns `text/html` but the CDN caches on **URL pattern**, ignoring `Content-Type` → private HTML cached as if it were static. The fix (cache **only** by `Content-Type`) is exactly what closes this.

**72. When is deception Critical vs High?**
- **Critical (ATO):** the cached body contains a **reusable auth artifact** — session/bearer token, password-reset link, API key.
- **High:** it contains a **CSRF token** or **PII** only.
- **Practical:** grep the stolen body (Q64) and lead the report with the highest-value artifact.

**73. Does deception need victim interaction?**
Yes — the victim must **load the crafted URL** (a link, `<img>`, `<iframe>`, or email). It's **low**-interaction but **not zero**, which is why the CVSS carries `UI:R` (Q85). Once loaded, though, *their* page sits in the shared cache for *anyone* to fetch.

**74. Why is a leaked CSRF token still High?**
It enables **CSRF-as-the-victim** — you pair the stolen token with a CSRF PoC to perform state-changing actions in their account (change email/password → often a path to ATO) **without** their session cookie.

**75. How do you find the best sensitive base path?**
`/account`, `/settings`, `/profile`, `/api/me`, `/orders`, `/messages`, `/billing`, `/dashboard`, and **password-reset landing pages** (they carry the reset token in the page). Anything that returns **per-user data with tokens** and is served **200 on a loosely-routed path** is a candidate (Guide §14.1).

**76. What's the safe-PoC rule for deception?**
**Two of your own accounts** + a benign private marker (your test email/username). One cross-session retrieval of your **own** marker proves it — then **stop.** Never harvest a real user's page.

**77. One-line deception remediation?**
**Cache by `Content-Type`** (not URL suffix), **honor `Cache-Control: no-store`**, enable **Cache Deception Armor**, and serve authenticated pages **`no-store, private`**.

**78. How does bfcache/browser-cache relate to deception?**
Sensitive pages restored from **bfcache**/browser cache **after logout** leak session/PII on shared devices. It's a **private-cache** cousin of deception (lower blast radius, per-victim). Recommend `Cache-Control: no-store, private` + `Clear-Site-Data` on logout.

---

## F. Validity, false positives & severity (79–90)

**79. The single golden rule for any cache finding?**
It's real **only** when the cache **re-serves** your influence to a **different** request (poison) or the victim's response to you (deception). Reflection/echo, a lone cache header, or "it worked in my own session" is a **lead**, not a finding.

**80. Top false positive #1 — and the fix?**
"A header is reflected" with **no** proof the response is **cached** and served to a **second** request that didn't send it. That's **self-XSS.** *Fix:* run the 4-step canary (Q30) and show the MISS→HIT served-to-others pair.

**81. Top false positive #2 — and the fix?**
Deception "works" but **only with your own cookie present** — you just fetched your own page. *Fix:* show **Session B (no cookie)** getting **Session A**'s data with a cache HIT (Q65).

**82. Why isn't `Cache-Control: public` by itself a finding?**
A **header ≠ a cached sensitive response.** You need an actual **HIT** on sensitive/authenticated content (deception) or a served-to-others poison. A policy header is a hint, not proof.

**83. Why isn't a Param Miner "unkeyed input" hit a finding by itself?**
It's a **tool lead.** Reproduce reflection + served-to-others + a **concrete** XSS/redirect/leak by hand before reporting — scanners flag cacheability heuristics that don't always land as impact.

**84. CVSS anchor for poisoning→mass-XSS?**
`AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N` → **≈9+ Critical** (network, no auth, no interaction, **scope-changed** because the cache serves other users). This vector caps out near 10.

**85. CVSS anchor for deception→token theft?**
`AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` → **≈High/Critical** (the victim must load the URL → `UI:R`; scope-changed because the cache serves another user's data). Critical with a reusable token; High for PII/CSRF-only.

**86. Primary CWEs?**
**CWE-349** (Acceptance of Extraneous Untrusted Data) for poisoning, plus the delivered **CWE-79/601**; **CWE-524/525** (Use of Cache Containing Sensitive Information) for deception; **CWE-400** for CPDoS.

**87. When is an open redirect a *cache* finding vs a plain one?**
If it's **cached** (served to everyone) it's a **higher, distinct** finding; if it's per-request only, it's an ordinary (lower) open redirect. The cache status is what separates the two — report them differently.

**88. How do you keep deception tests low-FP?**
Cold public-content control (Q66) + require the marker in **both** the authenticated response **and** the session-less response + prefer a cache **HIT** header on the session-less fetch. All three together kill the "it was just public" and "I saw my own cookie" false positives.

**89. What downgrades a poisoning finding to Informational?**
The input is **keyed** (a request without it loses your canary), or the response **isn't cached**, or the reflection is **safely encoded and not in a URL context.** Any one of those removes the "served to others / dangerous sink" half.

**90. Why re-test partial fixes?**
Because a partial fix is a **fresh** valid finding: keying one header but not another, honoring `no-store` on one route but not a sibling, or fixing `.css` but not `.js`. Always re-walk the matrix after a remediation.

---

## G. SAFE-PoC, reporting & red-team (91–100)

**91. The one rule that keeps you safe on poisoning?**
Always use a **cache-buster** so your payload lands on **your** key, prove control with a **benign** marker, and **describe** the shared-key impact — don't inflict it on real users.

**92. What if you must touch a shared key (authorized)?**
Pick a **low-traffic** path, use a **self-contained benign** proof, **purge** (or let it expire) immediately, and **document** it. Only with explicit authorization.

**93. What must a poisoning report contain?**
The **cache layer** + hit/miss evidence, the **unkeyed input**, the **reflection sink**, and **request/response pairs** showing **MISS→HIT** with your **benign marker** served to a **clean** request. Title names the **impact** ("stored XSS served to every visitor"), not the echo.

**94. What must a deception report contain?**
The **crafted URL** + the caching rule, and the **two-session** proof (A's marker retrieved by B with **no cookie** + a HIT), **graded by the leaked artifact** (token → Critical; PII/CSRF → High).

**95. How do you de-duplicate cache findings?**
**One root cause = one report**, even across many pages (one unkeyed input, or one path-confusion class). Lead with the highest impact (mass-XSS > redirect). But a **cached** redirect is a *different, higher* finding than the same redirect uncached — separate it.

**96. What operational step should you always recommend?**
A **cache purge** of the poisoned/affected entries, **plus** the config fix (key/`Vary`/`no-store`/cache-by-Content-Type/Deception Armor). The bug persists in storage until purged or expired — say so.

**97. Red-team: quietest high-impact cache play?**
Poison a shared JS **config** (`apiBaseUrl`) so **every** client silently sends tokens/requests to your host — site-wide, low-noise, no visible defacement (Q44/Q45).

**98. Red-team: how to weaponize deception on a portal?**
Lure an **admin** to a crafted static-suffix URL to cache their admin page, then lift the **admin CSRF/session** for privilege escalation — one high-value victim beats a hundred low-value ones.

**99. Which kits chain with this one?**
**HostHeader** (reflection source), **RequestSmuggling** (shared-cache poisoning), **OAuth** (cached redirect → token theft), **XSS/JSFiles** (DOM sinks), **SSRF** (via poisoned redirect targets). This kit is the caching-impact amplifier for all of them.

**100. Final mental checklist before submitting?**
Cache confirmed? Unkeyed/served-to-others (poison) **or** cross-session (deception) proven? Benign marker + cache-buster / own-accounts used? Impact + blast radius named? Purge + fix recommended? All yes → it's the Critical/High it's worth.

---

## H. Interview questions — articulate it out loud (101–112)

> These test whether you can *explain* the class, not just exploit it. Practice saying them in 60–90 seconds each.

**101. Explain web cache poisoning to a junior in under a minute.**
"A cache stores one copy of a response and hands it to everyone who asks for the 'same' URL — where 'same' is decided by a **cache key**, usually just the host and path. If the app *reflects* something from my request that the cache **doesn't** include in that key — the classic is the `X-Forwarded-Host` header — then I can send a request that pollutes the stored copy, and the cache serves my polluted copy to **every** later visitor. So a reflected header that would normally only affect my own request becomes **stored XSS for the whole site**, no clicks, no login. The key insight is the mismatch: the origin acts on something the cache ignores."

**102. Poisoning vs deception — compare them in one breath.**
"Same root cause — the origin and the cache disagree about a request — but **opposite directions.** Poisoning is **outbound**: I push my payload into the shared cache so it's served to everyone (`attacker → cache → all victims`). Deception is **inbound**: I trick the cache into storing a **victim's private** authenticated page under a URL I can fetch, so their secrets come to me (`victim → cache → attacker`). Poisoning abuses an **unkeyed input**; deception abuses a **response that shouldn't have been cached.**"

**103. Why is a cached XSS worse than a normal reflected XSS?**
"Blast radius and interaction. A reflected XSS needs me to trick each victim into clicking a crafted link, and it fires once. A **cached** XSS is stored at the edge and served to **every** visitor of that page automatically — unauthenticated, zero-click, until the entry expires or is purged. Same payload, but the cache turns a per-victim, self-XSS-grade bug into a site-wide stored-XSS Critical."

**104. Walk me through how you'd test an unknown page for cache poisoning.**
"First I build a **HIT/MISS oracle** — request it twice, watch `X-Cache`/`CF-Cache-Status`/`Age`, or diff a dynamic value if there are no headers. Then I add a **cache-buster** (`?cb=random`) so everything I do lands on my own private key, never real users'. Then I hunt **unkeyed inputs**: I plant a benign canary in `X-Forwarded-Host` and friends, check it's reflected, then re-request the **same key without the header** — if my canary is still served, it's unkeyed and poisonable. Finally I look at **where** it reflects: a `<script src>` is mass-XSS, a `Location` is a cached open redirect, raw HTML is reflected-XSS. I prove the served-to-others half with a benign marker and stop."

**105. A developer says "we're fully HTTPS and behind Cloudflare, so cache poisoning isn't a risk." Respond.**
"HTTPS protects data *in transit* — it says nothing about how the CDN builds its **cache key**, which is where this bug lives. And being behind Cloudflare is the *reason* to test, not a mitigation: the exploitable gap is exactly between what Cloudflare keys on and what your origin reflects. Cloudflare even ships 'Cache Deception Armor' as an opt-in because the default behavior is exploitable. Let me show you a cache-busted canary in `X-Forwarded-Host` — if it survives a request that didn't send it, you have an unkeyed input regardless of TLS or CDN."

**106. What's the one piece of evidence that turns a 'reflected header' into a valid finding?**
"The **served-to-a-different-request** proof. Reflection alone is self-XSS — worthless. I have to show a **second** request, one that never sent my header, receiving my injected value from the cache (a `MISS` then a `HIT` carrying my canary). That single request/response pair is the entire difference between Informational and Critical, so it's the first thing I put in the report."

**107. Curveball: does setting `Cache-Control: no-store` on a page fully prevent web cache deception?**
"Not reliably, and that surprises people. Deception's root cause is that a **CDN's URL-shape rule** (cache anything ending in `.css`, or under `/static/`) can **override** the origin's `no-store`. So the origin can *say* 'don't cache' and the edge caches it anyway because it sees a static extension. The real fixes are to cache **by `Content-Type`** (not suffix), make sure the CDN actually **honors** `Cache-Control`, and enable Cache Deception Armor — `no-store` alone is necessary but not sufficient."

**108. How would you explain the business impact of a deception bug to a non-technical stakeholder?**
"Imagine any logged-in customer clicks one link we send. Because of a caching flaw, the system accidentally files their **private account page** — name, email, and a security token — onto a **public shelf**. We can then walk up with no login and read it. At scale, that's mass exposure of customer data and, if the page holds a login or password-reset token, direct **account takeover** — a reportable data breach. The fix is a caching configuration change, not a code rewrite, but the exposure while it's open is severe."

**109. Compare `X-Forwarded-Host` poisoning with request-smuggling-based cache poisoning.**
"Both end in a poisoned **shared** cache, but the entry point differs. `X-Forwarded-Host` needs an **unkeyed input the app reflects** — I'm relying on the app echoing my header into a dangerous sink. Smuggling-based poisoning needs **no reflection at all**: a desync lets me plant a whole response that the cache attributes to the **next** victim's request, so I poison the shared key directly. Smuggling is more powerful and doesn't need a reflection, but it requires a desync primitive; the header route is far more common."

**110. Why do you always record the CDN/cache layer in the report, and how do you identify it?**
"Because the **fix is layer-specific** — the right remediation for Cloudflare (Cache Deception Armor, key config) differs from Fastly (VCL) or Akamai (cache rules), and naming it proves I understood the mechanism, which helps triage reproduce. I identify it from header fingerprints: `cf-ray` is Cloudflare, `x-served-by`/`x-timer` is Fastly, `via: cloudfront`+`x-amz-cf-id` is CloudFront, `server: AkamaiGHost` is Akamai, `x-varnish` is Varnish, `x-vercel-cache` is Vercel."

**111. What's the difference between `Vary` being wrong and a cache-buster, in terms of who they help?**
"They're two sides of the same key. `Vary` is the **defender's** knob — it tells the cache which headers to *include* in the key; a missing `Vary` on a reflected header is precisely what makes that header unkeyed and poisonable. A **cache-buster** is the **tester's** knob — a unique keyed value I add so my probe lands on my *own* key and I don't poison real users. One is the root-cause config, the other is my safety belt while I demonstrate the root cause."

**112. If you could give a team exactly three rules to prevent this entire class, what are they?**
"One: **key on everything that changes the response** (or don't reflect request-controlled data into cacheable responses) — kills poisoning. Two: **cache by `Content-Type`, never by URL suffix, and honor `Cache-Control`** — kills deception. Three: **never let authenticated responses enter a shared cache** (`no-store, private`, correct `Vary`, no `Set-Cookie` pages cached). Those three close poisoning, deception, and the sensitive-data-in-cache variants respectively."

---

## I. Scenario-based — you're handed a situation (113–120)

**113. Scenario: The home page returns `CF-Cache-Status: DYNAMIC` on every request. Your `X-Forwarded-Host` canary reflects into a `<script src>` but never survives a second request. Is there nothing here?**
There's plenty — you're just on the wrong response. `DYNAMIC` means the **HTML** isn't cached, so a reflection that only lives in the HTML won't persist. **Move to what *is* cached:**
1. Enumerate the page's **static resources** (`/static/*.js`, `/assets/*.css`) and build the oracle on each — they're almost always `HIT`. Check whether **any of them** reflects `X-Forwarded-Host`/a param into its body (config JS is the prize) → **resource poisoning**, site-wide (Q44).
2. Try **deception** on the authenticated area — the cache that refuses the HTML may still store `/account%3f.css` by its extension rule.
3. Re-confirm the buster is keyed; if the whole zone is genuinely uncached, pivot targets. `DYNAMIC` narrows the hunt, it doesn't end it.

**114. Scenario: You find `/account/x.css` returns your own account page with your data — but you're not sure it's exploitable. Walk your next five moves.**
1. **Build the oracle on that URL** — request it twice; does the second come back `X-Cache: HIT`/`Age` rising? If not cached, it's not deception (yet — try other delimiters).
2. **Cross-session proof:** request the *same* URL from a **second browser with no cookie**. If it returns **your** account data, that's the finding — cross-session theft.
3. **Cold-control:** fetch a random `*.css` unauthenticated to confirm the content isn't just public (Q66).
4. **Grade the body:** grep for session/reset/API tokens (→ Critical/ATO) vs CSRF/PII (→ High).
5. **If `.css` is the only working suffix, still walk the matrix** (`;`, `%3f`, `.js`, `.jpg`) — a stronger row may reach a more sensitive endpoint, and you want the best variant in the report. Then stop and write it with the two-session transcript.

**115. Scenario: `X-Forwarded-Host` is reflected into the response but properly HTML-encoded, and it's only in the visible page text — not in any URL. The response *is* cached. Report it or not?**
Not as XSS — encoded text in a non-URL context is **Informational** on its own. But don't drop it; **try to escalate first:**
1. Hunt a **second reflection** of the same value elsewhere on the page (many apps reflect the host in *both* a safe text spot and an unsafe `<link>`/canonical/`og:url`).
2. Try sibling headers (`X-Forwarded-Scheme: nothttps` to force a **redirect** into `Location`, `X-Forwarded-Port`) that may land in a URL context.
3. Check whether the encoded value flows into a **client-side sink** (DOM poisoning, Q46).
If none escalate, report it as a **low-severity cache-poisoning/hardening** note (unkeyed input reflected + cached) with the `Vary`/keying fix — accurate, not inflated.

**116. Scenario: Param Miner flags `X-Host` as an "unkeyed input" on `/pricing`. You reproduce the reflection, but you can only test against the live shared production cache — there's no staging and your `?cb=` is being stripped from the key. What do you do?**
Stop and **do not fire a payload at the shared entry** — without a keyed buster you can't isolate, and a live payload would hit real users (out of scope). Concretely:
1. **Find another keyed buster:** try a path-based one (`/pricing/;cb=123`), an analytics param the CDN *does* key (`?utm_x=`), or a unique `Accept-Encoding`/vhost in a lab — verify each produces an independent MISS.
2. If **nothing** isolates, prove the primitive **passively**: show the reflection + the unkeyed behavior with a **benign canary** only (which is harmless even shared, since it's just your hostname string), and **describe** the XSS/redirect impact in words without placing an executable payload.
3. Document that a keyed buster wasn't available and recommend the fix. Never trade safety for a flashier PoC.

**117. Scenario: You poisoned your own cache-busted key with an `alert()` and it fires. The triager replies "this is just self-XSS, you sent the header yourself." How do you answer?**
They're right about *what you showed* — you need the **served-to-others** half, so give it to them:
1. Re-do it as a **pair on one key**: request A **with** the header (MISS, caches your payload), request B to the **same key with no header** → B still gets your `alert`/canary with `X-Cache: HIT`. That second request **proves the cache serves your input to a request that didn't send it.**
2. Point out the only reason it's your `?cb=` key and not `/` is **safety** — on the bare shared key that "different request" is every visitor, and you deliberately didn't poison it to avoid harming users.
3. Attach both requests. That transcript converts "self-XSS" into "stored XSS served to all visitors."

**118. Scenario: A password-reset landing page (`/reset?token=…`) renders the reset token in the HTML. You suspect deception. Why is this the highest-value target, and how do you prove it safely?**
Because the cached body would contain a **single-use auth artifact** — the reset token — which is **direct ATO** (Critical), the top of the severity table.
Safely:
1. Use **two of your own accounts.** Trigger a reset for **your** "victim" account A, load the reset URL with a **deception suffix** (`/reset%3f.css?token=…` etc.) as A.
2. From **account B / no session**, fetch the same crafted URL — if you get **A's reset token** from cache, that's the proof.
3. **Immediately** complete or invalidate that reset so no live token lingers, and report with the two-session transcript. Never do this against a real user's reset — the token is live and would let you take over their account.

**119. Scenario: The site is behind Cloudflare with Cache Deception Armor enabled, so `/account.css` won't cache (Content-Type mismatch). Is deception dead here?**
Not necessarily — Armor checks that the **extension matches the Content-Type**, but it doesn't normalize every delimiter. Try the rows that make the **origin** emit a static-looking response or that Armor doesn't canonicalize:
1. **Encoded delimiters** the origin truncates but Cloudflare keys literally: `/account%3f.css`, `/account%23.css`, `/account%00.css` — the origin routes to `/account` (dynamic HTML) while the cached key ends in `.css`.
2. **Path parameters:** `/account;x.css` (origin ignores the `;`-param, cache sees `.css`).
3. **Directory-rule** confusion under a trusted static prefix (`/static/..%2faccount`).
Walk each with the two-session oracle; the USENIX-2022 research exists precisely because these bypass "protected" configs. If genuinely nothing caches an authenticated body, *then* deception is closed here — and that's a good result to state.

**120. Scenario: You have a confirmed unkeyed `X-Forwarded-Host` on a marketing page that reflects into a `<link rel="canonical">` and `og:url`, but not into any script or redirect. The page is cached. How high can you take this, and how?**
Canonical/`og:url` alone is usually **Low/Medium** (SEO/social-preview manipulation, mild phishing), so **hunt for a lift before you settle:**
1. **Redirect pivot:** add `X-Forwarded-Scheme: nothttps` — if the app now issues `Location: https://<your-host>`, you've turned it into a **cached open redirect** (High), and you can chain to OAuth token theft if any SSO flow trusts the host.
2. **Second sink:** check every other page on the same origin — the same unkeyed header often reflects into a **`<script src>`** somewhere (mass-XSS, Critical). One root cause, look for its worst landing.
3. **Resource pivot:** see if a cached JS reflects the same header into its body.
If canonical/`og:url` truly is the only sink, report it honestly at its real severity with the keying fix — but the discipline is to **always chase the header to its most dangerous reflection** before writing the number.

---

> **The one rule that pays:** a cache bug is real only when the cache **re-serves** your influence to someone else's request. Prove that half on a **cache-busted key with a benign marker** (poisoning) or with **two of your own sessions** (deception), name the **blast radius**, and you've turned a reflected header or a `.css` suffix into the Critical it's worth.
