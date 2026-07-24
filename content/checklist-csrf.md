# CSRF — Checklist

Expert per-attack **test-case matrix** for CSRF — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*18 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## CSRF-001 — List state-changing actions + lab setup
**Test Category:** Recon &amp; Lab · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Every state-changing action, ranked by impact

**Test Steps:** 1. List state-changing actions ranked by impact (auth &gt; financial/admin &gt; data &gt; trivial).<br>2. Two browser profiles (victim logged-in + attacker), DEFAULT settings; a cross-site host for the PoC.<br>3. Record each action's request: method, URL, params, content-type, token presence.

**Expected Result:** A ranked action list with each request captured.

**Payload Example:**

```
actions: change-email (POST, token) ; delete (GET) ; add-admin (POST)
```

**Impact:** The highest-impact action (ATO/admin) is the one worth chaining - rank first.

**Tools:** Burp Suite Pro

**References:** CWE-352; OWASP: CSRF Prevention Cheat Sheet; WSTG-SESS-05

---

## CSRF-002 — Baseline — the SameSite gate (decides if CSRF is possible)
**Test Category:** Baseline (the gate) · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** The session cookie + the target request

**Test Steps:** 1. Q1: is auth a COOKIE the browser auto-sends? (Bearer/localStorage = NOT CSRF, stop.)<br>2. Q2: read the session cookie SameSite (DevTools): None / Lax / Strict / absent(=Lax).<br>3. Q3: is there an anti-CSRF token, and is it validated/session-bound? Q4: Referer/Origin checked? Q5: JSON content-type/custom header required?<br>4. Verdict: possible (None / Lax+GET-sink / token bypassable) vs N/A (Lax+POST+enforced token / Bearer).

**Expected Result:** A verdict on whether CSRF is possible and which bypass class is needed.

**Payload Example:**

```
DevTools -> Cookies -> SameSite=None ; token not session-bound -> CSRF possible
```

**Impact:** SameSite is the gate - it decides whether any template can work at all.

**Tools:** Burp, DevTools

**References:** CWE-352; CWE-1275; PortSwigger Web Security Academy: CSRF + Bypassing SameSite restrictions

---

## CSRF-003 — Anti-CSRF token bypass
**Test Category:** Token Bypass · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** The anti-CSRF token in the request

**Test Steps:** 1. Remove the token entirely / send empty -&gt; accepted?<br>2. Use YOUR OWN session's token in the victim request -&gt; accepted? (= not session-bound, the most common real bug).<br>3. Correct length wrong value (presence-only); drop token on GET/multipart/text-plain; method override _method=PUT.

**Expected Result:** The action succeeds without a valid, session-bound token.

**Payload Example:**

```
remove csrf_token ; use attacker's own token in victim request ; _method=PUT
```

**Impact:** Defeats the anti-CSRF control -&gt; forgeable request. Enables the ATO chain.

**Tools:** Burp Repeater, XSRFProbe

**References:** CWE-352; PortSwigger Web Security Academy: CSRF + Bypassing SameSite restrictions

---

## CSRF-004 — Valid-token CSRF via token leak/theft
**Test Category:** Token Bypass · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Anywhere the token is exposed cross-origin

**Test Steps:** 1. Leak the token: via Referer (token in URL), a reflected page, permissive CORS (read /api/csrf cross-origin), XSS, or an open redirect carrying it.<br>2. Defeat double-submit: if you can SET the cookie (subdomain/injection), set cookie=body=attacker value -&gt; both match.<br>3. Use the leaked/matched token in a forged request.

**Expected Result:** A leaked or attacker-set token makes the forged request valid.

**Payload Example:**

```
read /api/csrf via permissive CORS ; double-submit: set cookie=body=known value
```

**Impact:** Valid-token CSRF even with strong tokens - High.

**Tools:** Burp, CORS/XSS kits

**References:** CWE-352; HackTricks: CSRF

---

## CSRF-005 — Classic CSRF — SameSite=None POST
**Test Category:** SameSite Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Session cookie SameSite=None

**Test Steps:** 1. Auto-submit POST form to the sensitive endpoint with all required params.<br>2. Cookie is sent cross-site (None) -&gt; action executes.<br>3. Verify in a default browser cross-site.

**Expected Result:** The cross-site POST executes the sensitive action.

**Payload Example:**

```
<form action=$URL/account/email method=POST><input name=email value=$ATTACKER></form> auto-submit
```

**Impact:** Classic CSRF -&gt; sensitive state change / ATO. High.

**Tools:** poc/csrf_poc_generator.py, Burp

**References:** CWE-352; PortSwigger Web Security Academy: CSRF + Bypassing SameSite restrictions

---

## CSRF-006 — Lax GET-nav state change
**Test Category:** SameSite Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Lax/absent cookie + a GET-reachable sensitive action

**Test Steps:** 1. Lax SENDS the cookie on top-level GET navigation: window.location=$URL/account/email/change?email=$ATTACKER.<br>2. Look for sibling GET routes (/delete, /confirm, /change?).<br>3. NOTE: &lt;img&gt;/&lt;iframe&gt;/fetch are NOT top-level nav -&gt; Lax won't send; use navigation.

**Expected Result:** A top-level GET navigation performs the state change under Lax.

**Payload Example:**

```
window.location='$URL/account/delete?confirm=1' ; sibling GET routes
```

**Impact:** CSRF under the Lax default via GET-accepted actions. High.

**Tools:** poc/csrf_poc_generator.py

**References:** CWE-352; PortSwigger Web Security Academy: CSRF + Bypassing SameSite restrictions

---

## CSRF-007 — Lax + POST two-minute window
**Test Category:** SameSite Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Chromium Lax default + a freshly-set session cookie

**Test Steps:** 1. A cookie &lt; 120s old is sent on a cross-site TOP-LEVEL POST (Lax+POST window).<br>2. Force the victim through login (or a flow that re-sets the cookie), then auto-POST within ~2 min.<br>3. Verify in default Chrome.

**Expected Result:** A cross-site top-level POST succeeds within the fresh-cookie window.

**Payload Example:**

```
victim just logged in -> auto top-level POST form within ~2 min
```

**Impact:** Revives classic POST CSRF under the Lax default - High.

**Tools:** poc/csrf_poc_generator.py

**References:** CWE-352; PortSwigger Web Security Academy: CSRF + Bypassing SameSite restrictions

---

## CSRF-008 — SameSite Strict bypass via client-side redirect / SPA gadget
**Test Category:** SameSite Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** SameSite=Strict + an on-site client-side redirect / SPA router

**Test Steps:** 1. The FINAL request must be SAME-SITE. Use an on-site JS open-redirect (target.com/go?to=/account/delete) or a SPA route (#/account/delete) so the target's OWN code issues the request.<br>2. Strict cookies ride a same-site client-side navigation.<br>3. Find the gadget: any ?to=/?url=/?next= JS follows, or a #/route the SPA acts on.

**Expected Result:** The target's own JS re-issues the request same-site, carrying the Strict cookie.

**Payload Example:**

```
window.location='$URL/go?to=/account/delete?confirm=1' ; $URL/#/account/delete?confirm=1
```

**Impact:** CSRF under SameSite=Strict via an on-site redirect gadget - High.

**Tools:** Burp

**References:** CWE-352; PortSwigger Web Security Academy: CSRF + Bypassing SameSite restrictions

---

## CSRF-009 — 307/308 method-preserving redirect
**Test Category:** SameSite Bypass · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** A target redirector answering 307/308

**Test Steps:** 1. Bounce a cross-site simple-POST through a target 307/308 redirector -&gt; the browser REPLAYS method+body to the endpoint (302/303 downgrade to GET and won't help).<br>2. Reach an endpoint/method a form can't craft.<br>3. If the 307 lands SAME-SITE, the Strict/Lax cookie survives.

**Expected Result:** A 307/308 replays the POST body+method to the real endpoint.

**Payload Example:**

```
cross-site POST -> target ?url=... (307) -> method+body replayed to /api/endpoint
```

**Impact:** Reaches non-form-craftable endpoints and preserves the cookie - High.

**Tools:** Burp

**References:** CWE-352; PortSwigger Web Security Academy: CSRF + Bypassing SameSite restrictions

---

## CSRF-010 — Referer / Origin check bypass
**Test Category:** Header Check Bypass · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Servers validating Referer/Origin

**Test Steps:** 1. Strip Referer: &lt;meta name=referrer content=no-referrer&gt;.<br>2. Null Origin: sandboxed iframe / data: document.<br>3. Weak regex: target.com.evil.com (as your subdomain), evil.com/target.com (path), evil.com?x=target.com.

**Expected Result:** The forged request passes the Referer/Origin check.

**Payload Example:**

```
<meta name=referrer content=no-referrer> ; Origin: null via sandboxed iframe ; target.com.evil.com
```

**Impact:** Defeats Referer/Origin-only CSRF defenses - High.

**Tools:** Burp

**References:** CWE-352; HackTricks: CSRF

---

## CSRF-011 — Content-Type / JSON CSRF (text/plain trick)
**Test Category:** Content-Type Bypass · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** JSON APIs guarded by content-type

**Test Steps:** 1. First: does the JSON API ALSO accept urlencoded? (very common) - plain form works.<br>2. text/plain trick: &lt;form enctype=text/plain&gt;&lt;input name='{"email":"$ATTACKER","x":"' value='"}'&gt; -&gt; body {"email":"$ATTACKER","x":"="}.<br>3. Multipart variant.

**Expected Result:** A form-crafted request delivers a valid JSON body the API accepts.

**Payload Example:**

```
enctype=text/plain form building {"email":"$ATTACKER","ignore":"="} ; or urlencoded accepted
```

**Impact:** CSRF on a 'JSON-only' API via content-type confusion - High.

**Tools:** poc/csrf_poc_generator.py

**References:** CWE-352; PortSwigger Web Security Academy: CSRF + Bypassing SameSite restrictions

---

## CSRF-012 — Clickjacking-assisted CSRF
**Test Category:** Clickjacking-Assisted · **Severity:** Medium · **CVSS:** 6.9 (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:H/A:N)

**Where to Test / Injection Point:** Framable settings page (no X-Frame-Options / frame-ancestors) + cookie reaches frame

**Test Steps:** 1. Check framability: no X-Frame-Options AND no CSP frame-ancestors.<br>2. Frame the REAL page (carries the victim's REAL token); overlay bait to steal the click over the submit button.<br>3. Requires the cookie to reach the frame (SameSite=None / same-site).

**Expected Result:** The victim's click on bait submits the real, token-bearing form.

**Payload Example:**

```
transparent iframe of $URL/account/settings + bait over the submit button
```

**Impact:** State change with the real token when it can't be scripted - Medium/High.

**Tools:** Burp, curl -I (framability)

**References:** CWE-352; CWE-1021; HackTricks: CSRF

---

## CSRF-013 — CSRF -&gt; account takeover
**Test Category:** Impact — ATO · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Change-email / change-password / disable-2FA / add-key endpoints

**Test Steps:** 1. CSRF change email/recovery -&gt; reset -&gt; log in as victim.<br>2. CSRF change password (no old pw) / disable-2FA / add passkey/API/SSH key.<br>3. Demonstrate end-to-end on your own two accounts, in a default browser cross-site.

**Expected Result:** The CSRF changes a recovery/credential factor, yielding takeover.

**Payload Example:**

```
CSRF POST /account/email {email:$ATTACKER} -> reset -> inside victim
```

**Impact:** Full account takeover via CSRF - the headline impact. High/Critical.

**Tools:** poc/csrf_poc_generator.py

**References:** CWE-352; CWE-640; PortSwigger Web Security Academy: CSRF + Bypassing SameSite restrictions

---

## CSRF-014 — Login CSRF / OAuth state-CSRF / GraphQL / CORS-cred CSRF
**Test Category:** Impact — Variants · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Login, OAuth callback, GraphQL, CORS-credentialed endpoints

**Test Steps:** 1. Login CSRF: silently log the victim into the attacker's account (demonstrate harm).<br>2. OAuth state-less callback CSRF -&gt; account linking takeover.<br>3. GraphQL CSRF (GET / form-encoded mutation). CORS-credentialed CSRF (ACAO reflected + ACAC:true -&gt; fetch credentials:include).

**Expected Result:** A login/OAuth/GraphQL/CORS variant produces a sensitive change.

**Payload Example:**

```
<img src=$URL/oauth/callback?code=ATTACKER_CODE&state=x> ; GraphQL GET mutation
```

**Impact:** Account-linking ATO / login-CSRF harm / API state change - High.

**Tools:** Burp, CORS/OAuth kits

**References:** CWE-352; HackTricks: CSRF

---

## CSRF-015 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: Lax+POST with an enforced token; Bearer/localStorage auth (not CSRF); 'no token' with no working PoC; logout/trivial actions; self-CSRF; Repeater-only 'it worked' (same-site, meaningless for CSRF).<br>2. REQUIRE: it FIRED in a real DEFAULT-settings browser, CROSS-SITE, and changed something sensitive.<br>3. Record the cookie's SameSite value.

**Expected Result:** Only PoCs that fire in a default browser cross-site on a sensitive action survive.

**Payload Example:**

```
Repeater-only = meaningless ; Bearer-auth = not CSRF ; SameSite-disabled test = invalid
```

**Impact:** Protects credibility; CSRF is dense with Repeater-only / Lax-blocked false positives.

**Tools:** default Chrome

**References:** CWE-352; PortSwigger Web Security Academy: CSRF + Bypassing SameSite restrictions

---

## CSRF-016 — Client-facing impact &amp; SAFE PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Title names impact + why it works ('ATO via CSRF - session cookie SameSite=None, no token'); lead with the ATO.<br>2. Provide the PoC HTML, confirmation it fired in default Chrome cross-site, the cookie's SameSite value, and screenshots.<br>3. Set CVSS 3.1 (UI:R) + CWE-352 (+ outcome CWE, +1275 for weak SameSite). Remediation: session-bound anti-CSRF tokens, SameSite=Lax/Strict, verify Origin, require re-auth for sensitive changes.<br>4. Own two accounts, reversible; de-dupe to one root cause.

**Expected Result:** A reproducible, correctly-rated, browser-confirmed PoC with clear remediation.

**Payload Example:**

```
PoC: PoC HTML + default-browser confirmation + SameSite value + CVSS(UI:R) + CWE-352 + remediation.
```

**Impact:** Converts the forged request into a defensible High report at the ATO severity.

**Tools:** CVSS calculator, CSRF_REPORT_TEMPLATE.md

**References:** CWE-352; CWE-1275; FIRST CVSS v3.1; OWASP: CSRF Prevention Cheat Sheet; WSTG-SESS-05  |  TOP REFERENCES: PortSwigger Academy CSRF + 'Bypassing SameSite'; OWASP CSRF Prevention Cheat Sheet; Chromium SameSite docs; RFC 6265bis

---

## CSRF-017 — Cookie tossing / cookie sandwich (subdomain cookie injection)
**Test Category:** Cookie Injection · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Cookie scope across subdomains; a controlled/XSS'd sibling subdomain

**Test Steps:** 1. From a sibling/less-trusted subdomain, set a cookie scoped to the parent domain (name/path collision)<br>2. 'Sandwich' the target cookie so the server reads the attacker's value<br>3. Overwrite the CSRF-token cookie or fixate the session<br>4. Confirm request forgery / session fixation

**Expected Result:** __Host- cookies, host-only scoping, cookie integrity; no implicit subdomain cookie trust

**Payload Example:**

```
Set-Cookie: sessionid=attacker; Domain=.target.com; Path=/   (from sub.target.com)
```

**Impact:** Cookie tossing -&gt; overwrite/fixate victim cookies -&gt; CSRF-token bypass / session fixation

**Tools:** Burp, browser

**References:** CWE-384; CWE-565; PortSwigger cookie security; 'Cookie Tossing/Sandwich' research (filedescriptor)

---

## CSRF-018 — Cookie bombing / jar overflow (control bypass + client DoS)
**Test Category:** Cookie Injection · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Per-domain cookie jar size/count limits

**Test Steps:** 1. Set many/large cookies for the target domain from a controlled subdomain or via injection<br>2. Overflow the cookie jar so the browser drops/rejects legitimate cookies<br>3. Force logout, break the CSRF-token cookie, or bypass a cookie-based control<br>4. Confirm the security cookie is evicted

**Expected Result:** Cookie count/size bounded; security cookies protected (__Host-, integrity checks)

**Payload Example:**

```
for i in 1..200: Set-Cookie: junk_$i=AAAA...(4KB); Domain=.target.com
```

**Impact:** Cookie bombing -&gt; evict security/CSRF cookies -&gt; control bypass or client-side DoS

**Tools:** Burp, browser

**References:** CWE-770; CWE-384; PortSwigger cookie jar limits; disclosed cookie-bomb writeups

---
