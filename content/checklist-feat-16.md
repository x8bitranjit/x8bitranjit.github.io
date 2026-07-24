# 16. Search & Discovery — Checklist

Feature-area security **test cases** for “16. Search & Discovery”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*250 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## SRCH-001 — SQL Injection in Search Query
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Basic Search

**Test Steps:** 1. Enter search query in search box 2. Intercept request 3. Inject SQL payload in search parameter 4. Observe response for SQL errors or data leakage

**Expected Result:** Application should use parameterized queries

**Payload Example:**

```
search=' OR '1'='1'-- or search='; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite / Havij

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-002 — SQL Injection via UNION
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Basic Search

**Test Steps:** 1. Test number of columns using ORDER BY 2. Craft UNION payload 3. Extract database information 4. Enumerate tables and data

**Expected Result:** Application should prevent UNION-based injection

**Payload Example:**

```
search=' UNION SELECT NULL,username,password FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-003 — Blind SQL Injection - Boolean
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Basic Search

**Test Steps:** 1. Submit search query 2. Inject boolean condition 3. Compare response for true/false 4. Extract data bit by bit

**Expected Result:** Application should not expose boolean differences

**Payload Example:**

```
search=test' AND 1=1-- vs search=test' AND 1=2--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-004 — Blind SQL Injection - Time Based
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Basic Search

**Test Steps:** 1. Submit search with time delay payload 2. Measure response time 3. Confirm injection exists 4. Extract data using delays

**Expected Result:** Application should prevent time-based injection

**Payload Example:**

```
search=test'; WAITFOR DELAY '0:0:5'-- or search=test' AND SLEEP(5)--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-005 — NoSQL Injection in Search
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Basic Search

**Test Steps:** 1. Identify NoSQL backend 2. Inject NoSQL operators 3. Bypass search filters 4. Access unauthorized data

**Expected Result:** NoSQL queries should be sanitized

**Payload Example:**

```
{"search":{"$regex":".*"},published:{"$ne":false}}
```

**Impact:** NoSQL operator injection -&gt; authentication bypass / cross-user data disclosure.

**Tools:** NoSQLMap / Burp Suite / MongoDB Compass

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger NoSQL injection

---

## SRCH-006 — Reflected XSS in Search Query
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Basic Search

**Test Steps:** 1. Enter XSS payload in search 2. Submit search 3. Check if query reflected in response 4. Verify script execution

**Expected Result:** Search results should encode output

**Payload Example:**

```
<script>alert(document.cookie)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-007 — DOM-based XSS in Search
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Basic Search

**Test Steps:** 1. Analyze search JavaScript 2. Find DOM sinks 3. Craft DOM XSS payload 4. Execute via URL parameter

**Expected Result:** Client-side code should sanitize input

**Payload Example:**

```
search="><img src=x onerror=alert(1)>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / DOM Invader / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-008 — Search Parameter Pollution
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Basic Search

**Test Steps:** 1. Send multiple search parameters 2. Check processing behavior 3. Bypass filters 4. Inject malicious content

**Expected Result:** Duplicate parameters should be handled safely

**Payload Example:**

```
?search=safe&search=malicious
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Param Miner

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## SRCH-009 — Search Length Overflow
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Basic Search

**Test Steps:** 1. Submit extremely long search query 2. Monitor server response 3. Check for buffer overflow 4. Attempt DoS

**Expected Result:** Application should limit query length

**Payload Example:**

```
search=A*100000 (100000 characters)
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-010 — Search Wildcard Abuse
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Basic Search

**Test Steps:** 1. Submit wildcard-heavy query 2. Monitor server resources 3. Cause regex/search engine stress 4. DoS via expensive queries

**Expected Result:** Wildcards should be limited or escaped

**Payload Example:**

```
search=*****************************
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Postman

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-011 — Search Index Poisoning
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Basic Search

**Test Steps:** 1. Create content with malicious keywords 2. Submit for indexing 3. Search for malicious terms 4. Rank manipulation

**Expected Result:** Content should be sanitized before indexing

**Payload Example:**

```
Create content with competitor brand names
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing / SEO Tools

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-012 — Search Result Cache Poisoning
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Basic Search

**Test Steps:** 1. Request search results 2. Inject via unkeyed headers 3. Poison cache 4. Serve malicious results to others

**Expected Result:** Search cache should validate input

**Payload Example:**

```
X-Forwarded-Host: evil.com in search request
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## SRCH-013 — Empty Search Information Disclosure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Basic Search

**Test Steps:** 1. Submit empty search query 2. Check response 3. Look for all records returned 4. Enumerate sensitive data

**Expected Result:** Empty search should return nothing or error

**Payload Example:**

```
search= or search=*
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-014 — Special Character Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Basic Search

**Test Steps:** 1. Test special characters in search 2. Check for errors or bypasses 3. Identify injection points 4. Exploit vulnerabilities

**Expected Result:** Special characters should be escaped

**Payload Example:**

```
' ; -- /* */ { } [ ] | \ ^ $ . * + ?,Medium,Burp Suite|Fuzzing Lists
Basic Search,Search Encoding Bypass,Security Bypass,1. Encode malicious payload 2. Submit encoded search 3. Bypass input validation 4. Execute injection,All encodings should be handled,%27%20OR%20%271%27%3D%271 (URL encoded),High,Burp Suite|Hackvertor
Basic Search,Unicode Normalization Attack,Security Bypass,1. Use Unicode variations 2. Bypass blocklist filters 3. Execute injection 4. Access restricted content,Unicode should be normalized before processing,search=＜script＞alert(1)＜/script＞ (fullwidth),Medium,Burp Suite|Hackvertor
Basic Search,Null Byte Injection in Search,Security Bypass,1. Insert null byte in search 2. Truncate query 3. Bypass validation 4. Inject payload,Null bytes should be rejected,search=valid%00<script>alert(1)</script>,High,Burp Suite|Hackvertor
Basic Search,LDAP Injection via Search,Injection,1. Identify LDAP-backed search 2. Inject LDAP operators 3. Bypass authentication 4. Extract directory data,LDAP queries should be escaped,search=*)(uid=*))(|(uid=*,High,Burp Suite|Custom Scripts
Basic Search,XPath Injection via Search,Injection,1. Identify XML-based search 2. Inject XPath payload 3. Extract XML data 4. Bypass access controls,XPath queries should be parameterized,search=' or '1'='1,High,Burp Suite|Custom Scripts
Basic Search,Command Injection via Search,Injection,1. Search passes to system command 2. Inject OS command 3. Execute on server 4. Achieve RCE,User input should never reach shell,search=test; cat /etc/passwd,Critical,Burp Suite|Commix
Advanced Search / Filters,SQL Injection in Filter Parameter,Injection,1. Apply advanced filter 2. Intercept request 3. Inject SQL in filter value 4. Extract database data,Filter queries should be parameterized,price_min=0' OR '1'='1'--,Critical,SQLMap|Burp Suite
Advanced Search / Filters,Filter Bypass via Parameter Manipulation,Broken Access Control,1. Apply restrictive filter 2. Modify filter parameters 3. Access restricted results 4. View unauthorized data,Filters should be server-enforced,Remove published=true filter,High,Burp Suite|Postman
Advanced Search / Filters,Filter IDOR,Broken Access Control,1. Apply user-specific filter 2. Modify user_id in filter 3. Access others' filtered results 4. Privacy violation,Filters should be user-scoped,filter[user_id]=victim_id,High,Burp Suite|Postman|Autorize
Advanced Search / Filters,Negative Value in Range Filter,Input Validation,1. Apply range filter (price min/max) 2. Set negative values 3. Check for logic errors 4. Access free items,Range values should be validated,price_min=-999&price_max=-1,Medium,Burp Suite|Postman
Advanced Search / Filters,Filter Logic Bypass,Business Logic,1. Combine multiple filters 2. Create logical contradiction 3. Bypass filter logic 4. Access all results,Filter combinations should be validated,status=active&status=deleted,Medium,Burp Suite|Postman
Advanced Search / Filters,Filter XSS in Custom Filter,Cross-Site Scripting,1. Create custom filter with XSS 2. Save filter 3. View saved filter 4. XSS executes,Filter names should be sanitized,filter_name=<script>alert(1)</script>,High,Burp Suite|XSS Hunter
Advanced Search / Filters,Filter SQL Injection via Sort,Injection,1. Apply sort parameter 2. Inject SQL in sort field 3. Execute ORDER BY injection 4. Extract data,Sort fields should be whitelisted,sort=name; DROP TABLE products--,Critical,SQLMap|Burp Suite
Advanced Search / Filters,Boolean Filter Manipulation,Business Logic,1. Toggle boolean filter 2. Modify to invalid value 3. Check default behavior 4. Access hidden content,Boolean filters should validate values,published=maybe or published=2,Medium,Burp Suite|Postman
Advanced Search / Filters,Date Filter Injection,Injection,1. Apply date filter 2. Inject SQL in date parameter 3. Execute time-based injection 4. Extract data,Date parameters should be validated,date_from=2024-01-01'; SELECT SLEEP(5)--,Critical,SQLMap|Burp Suite
Advanced Search / Filters,Hidden Filter Parameter Discovery,Information Disclosure,1. Enumerate filter parameters 2. Find hidden filters 3. Access internal filters 4. View restricted data,Hidden filters should require authorization,Discover admin_only=true filter,Medium,Burp Suite|Arjun|Param Miner
Advanced Search / Filters,Filter Combination DoS,Denial of Service,1. Apply many filters simultaneously 2. Create complex query 3. Exhaust database resources 4. DoS,Filter count should be limited,Apply 100 filters simultaneously,Medium,Burp Suite|Custom Scripts
Advanced Search / Filters,Filter Array Injection,Injection,1. Filter accepts array 2. Inject into array 3. Bypass validation 4. Access unauthorized data,Array handling should be secure,filter[]=value1&filter[]=' OR '1'='1,High,Burp Suite|Postman
Advanced Search / Filters,Filter Operator Injection,Injection,1. Identify filter operators (gt lt eq) 2. Inject additional operators 3. Bypass restrictions 4. Access all data,Operators should be whitelisted,filter[price][$gt]=0&filter[price][$lt]=9999999,Medium,Burp Suite|Postman
Advanced Search / Filters,Filter Encoding Mismatch,Security Bypass,1. Send filter in different encoding 2. Bypass server validation 3. Inject payload 4. Execute attack,Encoding should be normalized,UTF-7 or double URL encoding,Medium,Burp Suite|Hackvertor
Advanced Search / Filters,Cross-Tenant Filter Bypass,Broken Access Control,1. Filter by tenant 2. Modify tenant_id 3. Access other tenant's data 4. Cross-tenant breach,Tenant isolation should be enforced,filter[tenant_id]=competitor_tenant,Critical,Burp Suite|Postman
Autocomplete / Suggestions,Autocomplete SQL Injection,Injection,1. Type in autocomplete field 2. Intercept suggestion request 3. Inject SQL payload 4. Extract data,Autocomplete queries should be parameterized,q=a' OR '1'='1'--,Critical,SQLMap|Burp Suite
Autocomplete / Suggestions,Autocomplete XSS via Suggestion,Cross-Site Scripting,1. Create content with XSS in title 2. Type to trigger suggestion 3. XSS in dropdown 4. Execute on select,Suggestions should be sanitized,Product name: <script>alert(1)</script>,High,Burp Suite|XSS Hunter
Autocomplete / Suggestions,Autocomplete Information Disclosure,Information Disclosure,1. Type partial query 2. Analyze suggestions 3. Discover hidden content 4. Enumerate private data,Suggestions should respect access control,Suggest private or unreleased items,Medium,Burp Suite|Browser DevTools
Autocomplete / Suggestions,Autocomplete User Enumeration,Information Disclosure,1. Type username prefix 2. Check suggestions 3. Enumerate valid users 4. Build user list,User suggestions should be privacy-controlled,Type @ and see user list,Medium,Burp Suite|Intruder
Autocomplete / Suggestions,Autocomplete Rate Limiting Bypass,Security Bypass,1. Query autocomplete rapidly 2. Exhaust rate limit 3. Bypass via headers 4. Scrape all suggestions,Rate limiting should be robust,X-Forwarded-For rotation,Medium,Burp Suite|IP Rotate
Autocomplete / Suggestions,Autocomplete SSRF,Server-Side Request Forgery,1. Autocomplete fetches external data 2. Provide internal URL 3. Server fetches internal resource 4. SSRF,Autocomplete should not fetch URLs,q=http://169.254.169.254/,Critical,Burp Suite|SSRFmap
Autocomplete / Suggestions,Autocomplete Cache Poisoning,Web Cache Poisoning,1. Request autocomplete 2. Inject via headers 3. Poison cache 4. Serve malicious suggestions,Autocomplete cache should be secure,X-Forwarded-Host injection,High,Burp Suite|Param Miner
Autocomplete / Suggestions,Autocomplete API Key Exposure,Information Disclosure,1. Inspect autocomplete requests 2. Find API key 3. Extract key 4. Abuse third-party service,API keys should be server-side,Google Places API key in JavaScript,High,Browser DevTools|Burp Suite
Autocomplete / Suggestions,Autocomplete DoS via Complex Query,Denial of Service,1. Send complex regex pattern 2. Trigger catastrophic backtracking 3. Exhaust server CPU 4. DoS,Regex should be safe from ReDoS,q=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa!,Medium,Burp Suite|ReDoS Tools
Autocomplete / Suggestions,Autocomplete Minimum Character Bypass,Security Bypass,1. Autocomplete requires 3+ chars 2. Send single char via API 3. Bypass minimum 4. Enumerate all suggestions,Minimum length should be server-enforced,q=a (when minimum is 3),Low,Burp Suite|Postman
Autocomplete / Suggestions,Autocomplete NoSQL Injection,Injection,1. Identify MongoDB-backed autocomplete 2. Inject regex operators 3. Bypass search 4. Return all results,NoSQL queries should be sanitized,{q":{"$regex":".*"}}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** NoSQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-015 — Autocomplete Timing Attack
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Autocomplete / Suggestions

**Test Steps:** 1. Measure response times 2. Compare existing vs non-existing 3. Enumerate valid items 4. Map database

**Expected Result:** Response times should be consistent

**Payload Example:**

```
Time difference for valid vs invalid prefixes
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-016 — Autocomplete Template Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Autocomplete / Suggestions

**Test Steps:** 1. Inject template syntax 2. Check suggestion rendering 3. Template executes 4. Code execution

**Expected Result:** Suggestions should not be templated

**Payload Example:**

```
{{7*7}} or ${constructor.constructor('return this')()}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## SRCH-017 — Autocomplete Result Limit Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Autocomplete / Suggestions

**Test Steps:** 1. Autocomplete returns limited results 2. Modify limit parameter 3. Get all results 4. Data scraping

**Expected Result:** Limits should be server-enforced

**Payload Example:**

```
?limit=999999
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-018 — Facet SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Faceted Search

**Test Steps:** 1. Select facet filter 2. Intercept request 3. Inject SQL in facet parameter 4. Extract data

**Expected Result:** Facet queries should be parameterized

**Payload Example:**

```
facet[category]=Electronics'; SELECT * FROM users--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-019 — Facet Value Enumeration
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Faceted Search

**Test Steps:** 1. Request facet values 2. Find hidden facets 3. Enumerate internal categories 4. Information disclosure

**Expected Result:** Internal facets should be hidden

**Payload Example:**

```
Discover facets like internal_status or admin_flag
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite / Postman

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## SRCH-020 — Facet IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Faceted Search

**Test Steps:** 1. View facets for category 2. Modify category_id 3. View facets for restricted category 4. Access control bypass

**Expected Result:** Facet access should verify permissions

**Payload Example:**

```
GET /api/facets?category_id=admin_only_category
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-021 — Facet Count Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Faceted Search

**Test Steps:** 1. View facet counts 2. Intercept response 3. Modify counts 4. Display false information

**Expected Result:** Facet counts should be server-authoritative

**Payload Example:**

```
Modify count to show fake availability
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-022 — Facet XSS via Custom Value
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Faceted Search

**Test Steps:** 1. Create content with XSS in facet field 2. View facets 3. XSS in facet value 4. Execute script

**Expected Result:** Facet values should be sanitized

**Payload Example:**

```
Color: <script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-023 — Facet Combination Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Faceted Search

**Test Steps:** 1. Combine facets to narrow results 2. Combine to reveal restricted items 3. Access control bypass 4. View hidden items

**Expected Result:** All facet combinations should respect access

**Payload Example:**

```
Combine facets to isolate private items
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-024 — Facet DoS via Expensive Aggregation
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Faceted Search

**Test Steps:** 1. Select facets requiring heavy aggregation 2. Request multiple expensive facets 3. Exhaust database 4. DoS

**Expected Result:** Aggregation should be limited

**Payload Example:**

```
Request 50 facet aggregations simultaneously
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-025 — Facet Range Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Faceted Search

**Test Steps:** 1. Apply range facet 2. Inject in range bounds 3. SQL or NoSQL injection 4. Data extraction

**Expected Result:** Range parameters should be validated

**Payload Example:**

```
price_range=[0 TO 99999]; DROP TABLE--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-026 — Facet Boolean Logic Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Faceted Search

**Test Steps:** 1. Facets use AND/OR logic 2. Manipulate logic operators 3. Bypass intended filtering 4. See all results

**Expected Result:** Logic operators should be controlled

**Payload Example:**

```
Change AND to OR via parameter manipulation
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-027 — Nested Facet Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Faceted Search

**Test Steps:** 1. Facet has nested structure 2. Inject in nested level 3. Escape nested context 4. Execute injection

**Expected Result:** Nested facets should be sanitized

**Payload Example:**

```
facet[category][subcategory]=value'; --
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-028 — Facet Cache Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Faceted Search

**Test Steps:** 1. Facets are cached 2. Bypass cache 3. Get fresh restricted data 4. Access control bypass

**Expected Result:** Cache should respect permissions

**Payload Example:**

```
Add cache-busting parameter to access current data
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-029 — Facet Hierarchy Traversal
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Faceted Search

**Test Steps:** 1. View facet hierarchy 2. Traverse to parent/child 3. Access restricted branch 4. View unauthorized facets

**Expected Result:** Hierarchy access should be controlled

**Payload Example:**

```
Navigate to admin facet branch
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-030 — Facet Metadata Exposure
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Faceted Search

**Test Steps:** 1. Request facet metadata 2. Find internal attributes 3. Extract system information 4. Reconnaissance

**Expected Result:** Metadata should filter internal fields

**Payload Example:**

```
Facet response with database field names
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-031 — Full-Text SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Full-Text Search

**Test Steps:** 1. Use full-text search 2. Inject SQL in query 3. Bypass full-text parser 4. Execute SQL

**Expected Result:** Full-text queries should be escaped

**Payload Example:**

```
MATCH(content) AGAINST('"test" OR 1=1--')
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-032 — Elasticsearch Query Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Full-Text Search

**Test Steps:** 1. Identify Elasticsearch backend 2. Inject Elasticsearch DSL 3. Bypass query restrictions 4. Access all data

**Expected Result:** ES queries should be sanitized

**Payload Example:**

```
{"query":{"match_all":{}}}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-033 — Lucene Query Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Full-Text Search

**Test Steps:** 1. Identify Lucene-based search 2. Inject Lucene syntax 3. Bypass restrictions 4. Access unauthorized data

**Expected Result:** Lucene queries should be escaped

**Payload Example:**

```
title:admin OR _exists_:password
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-034 — Full-Text Script Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Full-Text Search

**Test Steps:** 1. Elasticsearch script query 2. Inject malicious script 3. Execute server-side 4. RCE

**Expected Result:** Scripting should be disabled

**Payload Example:**

```
{"script":"java.lang.Runtime.getRuntime().exec('id')"}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-035 — Full-Text Boolean Operator Abuse
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Full-Text Search

**Test Steps:** 1. Use boolean operators (AND OR NOT) 2. Craft query to reveal hidden 3. Bypass content filters 4. Access restricted

**Expected Result:** Boolean operators should be controlled

**Payload Example:**

```
secret NOT public
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-036 — Full-Text Wildcard DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Full-Text Search

**Test Steps:** 1. Use leading wildcards 2. Force expensive scans 3. Exhaust resources 4. DoS

**Expected Result:** Leading wildcards should be blocked

**Payload Example:**

```
*password* or ?????admin
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-037 — Full-Text Field Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Full-Text Search

**Test Steps:** 1. Query specific fields 2. Access restricted fields 3. Read sensitive data 4. Information disclosure

**Expected Result:** Searchable fields should be limited

**Payload Example:**

```
Search in password or internal_notes field
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-038 — Full-Text Proximity Attack
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Full-Text Search

**Test Steps:** 1. Use proximity search 2. Identify co-located terms 3. Infer sensitive information 4. Data inference

**Expected Result:** Proximity results should be filtered

**Payload Example:**

```
password~5 "admin"
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-039 — Full-Text Highlighting XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Full-Text Search

**Test Steps:** 1. Search for XSS payload 2. Results highlighted 3. XSS in highlight 4. Script executes

**Expected Result:** Highlights should be sanitized

**Payload Example:**

```
Search for <script> and check highlighted result
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-040 — Full-Text Snippet Information Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Full-Text Search

**Test Steps:** 1. Search returns snippets 2. Snippets show context 3. Context reveals sensitive data 4. Privacy violation

**Expected Result:** Snippets should filter sensitive content

**Payload Example:**

```
Snippet showing password in context
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-041 — Full-Text Index Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Full-Text Search

**Test Steps:** 1. Submit content for indexing 2. Manipulate index fields 3. Boost malicious content 4. SEO manipulation

**Expected Result:** Index fields should be controlled

**Payload Example:**

```
Inject boost factors or keywords
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-042 — Full-Text Synonym Exploitation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Full-Text Search

**Test Steps:** 1. Search uses synonyms 2. Exploit synonym mappings 3. Access through alternate terms 4. Bypass blocklist

**Expected Result:** Synonyms should respect blocklist

**Payload Example:**

```
Search synonym of blocked term
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-043 — Full-Text Analyzer Bypass
**Test Category:** Security Bypass · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Full-Text Search

**Test Steps:** 1. Identify text analyzer 2. Bypass normalization 3. Search for exact malicious term 4. Find hidden content

**Expected Result:** Analyzers should be consistent

**Payload Example:**

```
Bypass stemming to find exact matches
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-044 — Full-Text Aggregation Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Full-Text Search

**Test Steps:** 1. Search with aggregations 2. Inject in aggregation query 3. Extract grouped data 4. Information disclosure

**Expected Result:** Aggregations should be sanitized

**Payload Example:**

```
{"aggs":{"all_users":{"terms":{"field":"user.keyword"}}}}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-045 — Fuzzy Search DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Fuzzy Search / Typo Tolerance

**Test Steps:** 1. Submit query with high fuzziness 2. Force expensive matching 3. Exhaust resources 4. DoS

**Expected Result:** Fuzziness should have limits

**Payload Example:**

```
search=aaaaaaaaaa&fuzziness=10
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-046 — Fuzzy Search Bypass Blocklist
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Fuzzy Search / Typo Tolerance

**Test Steps:** 1. Blocklist contains term 2. Use typo variant 3. Bypass blocklist 4. Return blocked content

**Expected Result:** Fuzzy should check blocklist variants

**Payload Example:**

```
Search "passw0rd" to bypass "password" block
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-047 — Fuzzy Distance Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Fuzzy Search / Typo Tolerance

**Test Steps:** 1. Set fuzzy distance 2. Increase distance beyond limit 3. Get unrelated results 4. Data disclosure

**Expected Result:** Distance should be capped

**Payload Example:**

```
?fuzziness=99
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-048 — Fuzzy Match Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Fuzzy Search / Typo Tolerance

**Test Steps:** 1. Fuzzy query processed 2. Inject in fuzzy term 3. Break fuzzy parsing 4. Execute injection

**Expected Result:** Fuzzy input should be sanitized

**Payload Example:**

```
search=test~2' OR '1'='1
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-049 — Fuzzy Phonetic Attack
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Fuzzy Search / Typo Tolerance

**Test Steps:** 1. Use soundex/phonetic search 2. Find similar sounding terms 3. Discover hidden content 4. Information disclosure

**Expected Result:** Phonetic search should respect access control

**Payload Example:**

```
Search phonetic variant of secret project name
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Manual Testing

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-050 — Fuzzy Regex Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Fuzzy Search / Typo Tolerance

**Test Steps:** 1. Fuzzy uses regex internally 2. Inject regex patterns 3. Cause ReDoS 4. DoS

**Expected Result:** Regex should be sanitized

**Payload Example:**

```
(a+)+$ causing backtracking
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / ReDoS Tools

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-051 — Fuzzy Unicode Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Fuzzy Search / Typo Tolerance

**Test Steps:** 1. Use Unicode variants 2. Bypass exact match filters 3. Access restricted content 4. Security bypass

**Expected Result:** Unicode should be normalized

**Payload Example:**

```
аdmin (Cyrillic a) vs admin
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-052 — Fuzzy Transposition Attack
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Fuzzy Search / Typo Tolerance

**Test Steps:** 1. Swap characters in query 2. Match unintended content 3. Access through transposition 4. Data disclosure

**Expected Result:** Transposition should be limited

**Payload Example:**

```
Search "amdin" to find "admin" content
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-053 — Fuzzy Algorithm Exploit
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Fuzzy Search / Typo Tolerance

**Test Steps:** 1. Analyze fuzzy algorithm 2. Craft query to match everything 3. Bypass search intent 4. Get all results

**Expected Result:** Algorithm should have safeguards

**Payload Example:**

```
Query matching maximum results through fuzziness
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-054 — Search History IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search History

**Test Steps:** 1. View own search history 2. Modify user_id parameter 3. View another user's history 4. Privacy violation

**Expected Result:** History should be user-specific

**Payload Example:**

```
GET /api/users/victim_id/search-history
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-055 — Search History XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Search History

**Test Steps:** 1. Search for XSS payload 2. Payload saved to history 3. View history 4. XSS executes

**Expected Result:** History display should be sanitized

**Payload Example:**

```
<script>stealSession()</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-056 — Search History SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Search History

**Test Steps:** 1. Query search history 2. Inject SQL in filter 3. Extract all history 4. Mass privacy breach

**Expected Result:** History queries should be parameterized

**Payload Example:**

```
date_from='; SELECT * FROM search_history--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-057 — Search History Deletion IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search History

**Test Steps:** 1. Delete own history 2. Modify history_id 3. Delete another's history 4. Privacy manipulation

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/search-history/victim_history_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-058 — Search History Privacy Bypass
**Test Category:** Privacy Violation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search History

**Test Steps:** 1. Disable history 2. History still recorded 3. Privacy setting ignored 4. User tracking

**Expected Result:** Privacy settings should be enforced

**Payload Example:**

```
Searches logged despite opt-out
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SRCH-059 — Search History Export IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search History

**Test Steps:** 1. Export own history 2. Modify user_id 3. Export another's history 4. Data exfiltration

**Expected Result:** Export should verify ownership

**Payload Example:**

```
GET /api/users/victim_id/search-history/export
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-060 — Search History Correlation Attack
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search History

**Test Steps:** 1. Access search history 2. Correlate with user activity 3. Build user profile 4. Privacy violation

**Expected Result:** History should be anonymized or protected

**Payload Example:**

```
Correlate searches with purchases
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Manual Analysis

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SRCH-061 — Search History Retention Bypass
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search History

**Test Steps:** 1. History has retention period 2. Access after retention 3. View deleted history 4. Privacy breach

**Expected Result:** Retention should be enforced

**Payload Example:**

```
Access history beyond retention period
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Postman

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SRCH-062 — Search History Injection via Referrer
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search History

**Test Steps:** 1. Search logged with referrer 2. Craft malicious referrer 3. Inject payload 4. XSS or injection

**Expected Result:** Referrer should be sanitized

**Payload Example:**

```
Referer: <script>alert(1)</script>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / curl

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-063 — Bulk History Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search History

**Test Steps:** 1. Request bulk history 2. Access across users 3. Mass data access 4. Privacy breach

**Expected Result:** Bulk access should be admin-only

**Payload Example:**

```
GET /api/search-history?all=true
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-064 — Search History Timestamp Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search History

**Test Steps:** 1. View history with timestamp 2. Modify timestamp 3. Access historical data 4. Bypass time restrictions

**Expected Result:** Timestamps should be server-controlled

**Payload Example:**

```
Access history from before user joined
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-065 — Clear History CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Low · **CVSS:** 3.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search History

**Test Steps:** 1. Create malicious page 2. Auto-clear history 3. User visits 4. History deleted

**Expected Result:** Clear action should require CSRF token

**Payload Example:**

```
<img src="/search-history/clear">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SRCH-066 — Saved Search IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Saved Searches

**Test Steps:** 1. View own saved searches 2. Modify search_id 3. View another's saved search 4. Privacy violation

**Expected Result:** Saved searches should be user-specific

**Payload Example:**

```
GET /api/saved-searches/victim_search_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-067 — Saved Search IDOR Modification
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Saved Searches

**Test Steps:** 1. Edit own saved search 2. Modify search_id 3. Edit another's search 4. Modify their criteria

**Expected Result:** Modification should verify ownership

**Payload Example:**

```
PUT /api/saved-searches/victim_search_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-068 — Saved Search IDOR Deletion
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Saved Searches

**Test Steps:** 1. Delete own saved search 2. Modify search_id 3. Delete another's search 4. Disrupt their workflow

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/saved-searches/victim_search_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-069 — Saved Search XSS in Name
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Saved Searches

**Test Steps:** 1. Create saved search with XSS name 2. View saved searches 3. Name renders 4. XSS executes

**Expected Result:** Search names should be sanitized

**Payload Example:**

```
<script>alert(document.cookie)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-070 — Saved Search SQL Injection in Criteria
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Saved Searches

**Test Steps:** 1. Create saved search with criteria 2. Inject SQL in criteria 3. Search executes 4. SQL executed

**Expected Result:** Criteria should be parameterized

**Payload Example:**

```
{"price":{"$gt":"0'; DROP TABLE--"}}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-071 — Saved Search Privilege Escalation
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Saved Searches

**Test Steps:** 1. Create saved search 2. Add admin-only filters 3. Execute search 4. Access restricted data

**Expected Result:** Criteria should validate access

**Payload Example:**

```
Add is_admin=true to saved criteria
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-072 — Saved Search Sharing IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Saved Searches

**Test Steps:** 1. Share own saved search 2. Modify search_id 3. Share another's search 4. Unauthorized sharing

**Expected Result:** Sharing should verify ownership

**Payload Example:**

```
POST /api/saved-searches/victim_id/share
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-073 — Saved Search Alert Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Saved Searches

**Test Steps:** 1. Create alert for saved search 2. Inject in alert message 3. Alert triggers 4. Injection executed

**Expected Result:** Alert content should be sanitized

**Payload Example:**

```
Alert message with XSS payload
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-074 — Saved Search Mass Assignment
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Saved Searches

**Test Steps:** 1. Create saved search 2. Add extra parameters 3. Modify restricted fields 4. Bypass access

**Expected Result:** Only allowed fields should be accepted

**Payload Example:**

```
{"name":"test",is_global:true,run_as_admin:true}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman / Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## SRCH-075 — Saved Search Execution IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Saved Searches

**Test Steps:** 1. Execute own saved search 2. Modify search_id 3. Execute another's search 4. Run their query

**Expected Result:** Execution should verify ownership

**Payload Example:**

```
POST /api/saved-searches/victim_id/execute
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-076 — Saved Search Clone IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Saved Searches

**Test Steps:** 1. Clone own saved search 2. Modify source_id 3. Clone another's search 4. Steal their criteria

**Expected Result:** Clone should verify source access

**Payload Example:**

```
POST /api/saved-searches/victim_id/clone
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-077 — Saved Search Template Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Saved Searches

**Test Steps:** 1. Saved search uses template 2. Inject template syntax 3. Template executes 4. Code execution

**Expected Result:** Templates should be sandboxed

**Payload Example:**

```
{{config.SECRET_KEY}} in saved search name
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## SRCH-078 — Saved Search Notification SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Saved Searches

**Test Steps:** 1. Set webhook for search alerts 2. Provide internal URL 3. Alert triggers 4. SSRF

**Expected Result:** Webhook URLs should be validated

**Payload Example:**

```
webhook=http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SRCH-079 — Saved Search Limit Bypass
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Saved Searches

**Test Steps:** 1. User has saved search limit 2. Bypass limit 3. Create unlimited searches 4. Resource abuse

**Expected Result:** Limits should be enforced

**Payload Example:**

```
Create 1000 saved searches when limit is 10
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-080 — Voice Search Command Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Voice Search

**Test Steps:** 1. Submit audio with command 2. Speech-to-text processes 3. Command injected 4. Injection executed

**Expected Result:** Voice input should be sanitized

**Payload Example:**

```
Audio saying "search semicolon drop table"
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** Audio Tools / Burp Suite

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## SRCH-081 — Voice Search XSS via Transcription
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Voice Search

**Test Steps:** 1. Speak XSS payload 2. Transcription displayed 3. XSS in results 4. Script executes

**Expected Result:** Transcription should be sanitized

**Payload Example:**

```
Say "less than script greater than alert one"
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Audio Tools / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-082 — Voice Search Audio Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Voice Search

**Test Steps:** 1. Upload malicious audio 2. Audio contains hidden command 3. Processed by speech engine 4. Unauthorized action

**Expected Result:** Audio should be validated

**Payload Example:**

```
Ultrasonic or hidden audio commands
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Audio Tools / Custom Scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-083 — Voice Search API Key Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Voice Search

**Test Steps:** 1. Inspect voice search requests 2. Find API key 3. Extract key 4. Abuse speech service

**Expected Result:** API keys should be server-side

**Payload Example:**

```
Speech-to-text API key in JavaScript
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-084 — Voice Search Audio File Upload Vulnerability
**Test Category:** File Upload Vulnerabilities · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Voice Search

**Test Steps:** 1. Voice search accepts audio upload 2. Upload malicious file 3. File processed 4. RCE

**Expected Result:** Audio files should be validated

**Payload Example:**

```
Upload PHP disguised as audio
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Upload Scanner

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## SRCH-085 — Voice Search Rate Limiting Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Voice Search

**Test Steps:** 1. Send many voice requests 2. Exhaust speech API quota 3. DoS service 4. Financial impact

**Expected Result:** Voice requests should be limited

**Payload Example:**

```
100 voice searches per minute
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SRCH-086 — Voice Search Privacy Recording
**Test Category:** Privacy Violation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Voice Search

**Test Steps:** 1. Voice search activates 2. Recording continues after query 3. Private conversation captured 4. Privacy breach

**Expected Result:** Recording should stop after query

**Payload Example:**

```
Voice recording persists beyond search
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Manual Testing / Audio Analysis

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SRCH-087 — Voice Search SSRF via Audio URL
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Voice Search

**Test Steps:** 1. Voice search accepts audio URL 2. Provide internal URL 3. Server fetches 4. SSRF

**Expected Result:** Audio URLs should be validated

**Payload Example:**

```
audio_url=http://internal-service:8080/audio
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SRCH-088 — Voice Search Transcription IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Voice Search

**Test Steps:** 1. View own transcriptions 2. Modify transcription_id 3. View another's transcriptions 4. Privacy violation

**Expected Result:** Transcriptions should be user-specific

**Payload Example:**

```
GET /api/transcriptions/victim_transcription_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-089 — Voice Search Language Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Voice Search

**Test Steps:** 1. Set voice search language 2. Inject in language parameter 3. Path traversal or injection 4. Exploit

**Expected Result:** Language should be whitelisted

**Payload Example:**

```
language=../../../etc/passwd
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-090 — Voice Search Wake Word Abuse
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Voice Search

**Test Steps:** 1. Device listens for wake word 2. False positives 3. Unintended recording 4. Privacy violation

**Expected Result:** Wake word should be accurate

**Payload Example:**

```
Similar-sounding words triggering recording
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Manual Testing

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SRCH-091 — Voice Search Speaker Impersonation
**Test Category:** Broken Authentication · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Voice Search

**Test Steps:** 1. Record authorized speaker 2. Replay recording 3. Bypass voice auth 4. Unauthorized access

**Expected Result:** Voice auth should detect replay

**Payload Example:**

```
Replay recorded voice command
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Audio Tools / Burp Suite

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SRCH-092 — Image Search Malicious Upload
**Test Category:** File Upload Vulnerabilities · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Image Search

**Test Steps:** 1. Upload image for search 2. Upload malicious file 3. File processed 4. Code execution

**Expected Result:** Image uploads should be validated

**Payload Example:**

```
Upload PHP shell as image
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Upload Scanner / Weevely

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## SRCH-093 — Image Search SSRF via URL
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Image Search

**Test Steps:** 1. Search by image URL 2. Provide internal URL 3. Server fetches image 4. SSRF

**Expected Result:** Image URLs should be validated

**Payload Example:**

```
image_url=http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SRCH-094 — Image Search XXE via SVG
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Image Search

**Test Steps:** 1. Upload SVG for search 2. SVG contains XXE 3. Server parses 4. File disclosure

**Expected Result:** SVG parsing should disable entities

**Payload Example:**

```
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## SRCH-095 — Image Search XSS via SVG
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Image Search

**Test Steps:** 1. Upload SVG with JavaScript 2. SVG processed 3. SVG displayed 4. XSS executes

**Expected Result:** SVG should be sanitized

**Payload Example:**

```
<svg onload=alert('XSS')></svg>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-096 — Image Search ImageMagick RCE
**Test Category:** Remote Code Execution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Image Search

**Test Steps:** 1. Upload crafted image 2. ImageMagick processes 3. Code executes 4. Server compromise

**Expected Result:** ImageMagick should be patched

**Payload Example:**

```
ImageTragick payload
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** ImageTragick / Burp Suite

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## SRCH-097 — Image Search EXIF Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Image Search

**Test Steps:** 1. Upload image with malicious EXIF 2. EXIF extracted 3. Injection in metadata 4. XSS or injection

**Expected Result:** EXIF should be sanitized

**Payload Example:**

```
EXIF comment: <script>alert(1)</script>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** ExifTool / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-098 — Image Search Path Traversal
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Image Search

**Test Steps:** 1. Search references image path 2. Inject traversal in path 3. Access system files 4. Information disclosure

**Expected Result:** Paths should be validated

**Payload Example:**

```
image_path=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## SRCH-099 — Image Search DoS via Large Image
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Image Search

**Test Steps:** 1. Upload very large image 2. Server processes 3. Memory exhaustion 4. DoS

**Expected Result:** Image size should be limited

**Payload Example:**

```
Upload 100MB image
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Images

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-100 — Image Search Pixel Flood Attack
**Test Category:** Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Image Search

**Test Steps:** 1. Upload image with extreme dimensions 2. Server allocates memory 3. Memory exhaustion 4. DoS

**Expected Result:** Image dimensions should be limited

**Payload Example:**

```
10000x10000 pixel image
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Custom Images / Burp Suite

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SRCH-101 — Image Search Result IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Image Search

**Test Steps:** 1. Search returns similar images 2. Modify result_id 3. Access private similar images 4. Privacy violation

**Expected Result:** Results should verify access

**Payload Example:**

```
Access private images through similarity
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-102 — Image Search Cache Poisoning
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Image Search

**Test Steps:** 1. Request image search results 2. Poison cache 3. Serve malicious results 4. XSS to others

**Expected Result:** Cache should be properly keyed

**Payload Example:**

```
X-Forwarded-Host injection
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## SRCH-103 — Image Search Metadata Privacy Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Image Search

**Test Steps:** 1. Upload image with GPS 2. Search returns location 3. Privacy violation 4. Location tracking

**Expected Result:** Sensitive metadata should be stripped

**Payload Example:**

```
GPS coordinates exposed in results
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** ExifTool / Manual Testing

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SRCH-104 — Image Search Facial Recognition Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Image Search

**Test Steps:** 1. Face search enabled 2. Use adversarial image 3. Bypass recognition 4. Evade identification

**Expected Result:** Recognition should handle adversarial

**Payload Example:**

```
Adversarial perturbations on face
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Custom Tools / ML Testing

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-105 — Image Search Steganography
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Image Search

**Test Steps:** 1. Upload image with hidden data 2. System doesn't detect 3. Exfiltrate data 4. Data leakage

**Expected Result:** Images should be scanned

**Payload Example:**

```
Image with hidden payload
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Steganography Tools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-106 — Image Search Format Confusion
**Test Category:** File Upload Vulnerabilities · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Image Search

**Test Steps:** 1. Upload polyglot file 2. Valid image and code 3. Executes as code 4. RCE

**Expected Result:** File type should be strictly validated

**Payload Example:**

```
GIFAR or similar polyglot
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Custom Files

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## SRCH-107 — Relevance Boost Injection
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search Relevance Tuning

**Test Steps:** 1. Identify boost parameters 2. Inject extreme boost 3. Manipulate rankings 4. SEO manipulation

**Expected Result:** Boost parameters should be controlled

**Payload Example:**

```
boost=9999999 for specific result
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-108 — Relevance Algorithm IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search Relevance Tuning

**Test Steps:** 1. View own relevance settings 2. Modify settings_id 3. View competitor settings 4. Competitive intelligence

**Expected Result:** Settings should be organization-scoped

**Payload Example:**

```
GET /api/relevance-settings/competitor_org_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-109 — Relevance SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Search Relevance Tuning

**Test Steps:** 1. Modify relevance query 2. Inject SQL in relevance parameter 3. Execute SQL 4. Data extraction

**Expected Result:** Relevance queries should be parameterized

**Payload Example:**

```
relevance_field='; SELECT * FROM products--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-110 — Relevance XSS in Promoted Result
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Search Relevance Tuning

**Test Steps:** 1. Create promoted result with XSS 2. Search triggers promotion 3. Promoted result displayed 4. XSS executes

**Expected Result:** Promotions should be sanitized

**Payload Example:**

```
<script>stealSession()</script> in promoted content
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-111 — Negative Relevance Attack
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search Relevance Tuning

**Test Steps:** 1. Identify negative boost 2. Apply to competitor 3. Demote their results 4. Unfair competition

**Expected Result:** Negative boosting should be restricted

**Payload Example:**

```
Demote competitor products
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-112 — Relevance Rule Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search Relevance Tuning

**Test Steps:** 1. Identify relevance rules 2. Craft query to bypass 3. Show irrelevant results 4. User manipulation

**Expected Result:** Rules should be tamper-proof

**Payload Example:**

```
Bypass promoted content rules
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-113 — Relevance A/B Test Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search Relevance Tuning

**Test Steps:** 1. In A/B test for relevance 2. Force specific variant 3. Get preferred results 4. Unfair advantage

**Expected Result:** A/B assignment should be fixed

**Payload Example:**

```
Force favorable relevance algorithm
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Cookies

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-114 — Relevance Machine Learning Poisoning
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search Relevance Tuning

**Test Steps:** 1. ML-based relevance 2. Submit poisoned data 3. Manipulate model 4. Biased results

**Expected Result:** ML input should be validated

**Payload Example:**

```
Submit data to bias relevance model
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Custom Scripts / ML Tools

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-115 — Relevance Personalization Bypass
**Test Category:** Privacy/Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search Relevance Tuning

**Test Steps:** 1. Personalized results 2. Bypass personalization 3. See other users' results 4. Privacy violation

**Expected Result:** Personalization should be user-specific

**Payload Example:**

```
View non-personalized or other user's results
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Postman

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SRCH-116 — Relevance Score Exposure
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search Relevance Tuning

**Test Steps:** 1. View search results 2. Extract relevance scores 3. Reverse engineer algorithm 4. Gaming system

**Expected Result:** Scores should be hidden

**Payload Example:**

```
Expose _score or relevance_score in API
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-117 — Relevance Cache Manipulation
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search Relevance Tuning

**Test Steps:** 1. Relevance results cached 2. Poison cache 3. Serve manipulated relevance 4. Mass impact

**Expected Result:** Relevance cache should be secure

**Payload Example:**

```
Cache poisoning on relevance endpoints
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## SRCH-118 — Relevance CSRF
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Search Relevance Tuning

**Test Steps:** 1. Create malicious page 2. Auto-modify relevance 3. Admin visits 4. Relevance changed

**Expected Result:** Relevance changes should have CSRF token

**Payload Example:**

```
<form action="/admin/relevance/update">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SRCH-119 — Analytics IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search Analytics

**Test Steps:** 1. View own search analytics 2. Modify org_id 3. View competitor analytics 4. Competitive intelligence

**Expected Result:** Analytics should be organization-scoped

**Payload Example:**

```
GET /api/search-analytics?org_id=competitor_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-120 — Analytics XSS via Search Term
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Search Analytics

**Test Steps:** 1. Search for XSS 2. Term logged in analytics 3. Admin views analytics 4. XSS executes

**Expected Result:** Analytics should sanitize terms

**Payload Example:**

```
<script>stealAdminSession()</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-121 — Analytics SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Search Analytics

**Test Steps:** 1. Query analytics 2. Inject SQL in date range 3. Extract all analytics 4. Data breach

**Expected Result:** Analytics queries should be parameterized

**Payload Example:**

```
date_from=2024-01-01'; SELECT * FROM analytics--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-122 — Analytics Export IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search Analytics

**Test Steps:** 1. Export own analytics 2. Modify scope 3. Export all analytics 4. Mass data breach

**Expected Result:** Export should verify ownership

**Payload Example:**

```
GET /api/analytics/export?scope=all
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-123 — Analytics Real-time WebSocket
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search Analytics

**Test Steps:** 1. Connect to analytics WebSocket 2. Modify subscription 3. View other orgs' live data 4. Competitive intelligence

**Expected Result:** WebSocket should verify access

**Payload Example:**

```
Subscribe to competitor's analytics stream
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / WS King

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-124 — Analytics PII Exposure
**Test Category:** Privacy Violation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search Analytics

**Test Steps:** 1. View analytics 2. Find user identifiers 3. Link searches to users 4. Privacy breach

**Expected Result:** Analytics should be anonymized

**Payload Example:**

```
Analytics showing user_id with searches
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Manual Review

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SRCH-125 — Analytics Aggregation Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search Analytics

**Test Steps:** 1. View aggregated analytics 2. Request raw data 3. Access individual queries 4. Privacy violation

**Expected Result:** Raw data should require authorization

**Payload Example:**

```
GET /api/analytics/raw bypassing aggregation
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-126 — Analytics Dashboard Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Search Analytics

**Test Steps:** 1. Analytics displayed in dashboard 2. Inject via search term 3. Dashboard renders XSS 4. Admin compromise

**Expected Result:** Dashboard should sanitize all data

**Payload Example:**

```
XSS term appearing in admin dashboard
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-127 — Analytics API Rate Limiting Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search Analytics

**Test Steps:** 1. Query analytics rapidly 2. Bypass rate limit 3. Scrape all data 4. Data exfiltration

**Expected Result:** Rate limiting should be robust

**Payload Example:**

```
IP rotation or header manipulation
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / IP Rotate

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SRCH-128 — Analytics Date Range Manipulation
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search Analytics

**Test Steps:** 1. View analytics for allowed dates 2. Modify range 3. Access historical data 4. Unauthorized access

**Expected Result:** Date ranges should be validated

**Payload Example:**

```
Access data outside subscription period
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-129 — Analytics Metric Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search Analytics

**Test Steps:** 1. View analytics metrics 2. Intercept response 3. Modify metrics 4. Display false data

**Expected Result:** Metrics should be server-authoritative

**Payload Example:**

```
Modify click-through rates in response
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-130 — Analytics Tracking Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Search Analytics

**Test Steps:** 1. Search tracking enabled 2. Inject in tracked parameters 3. Malicious tracking 4. XSS or data corruption

**Expected Result:** Tracking should sanitize inputs

**Payload Example:**

```
Inject script in utm_source parameter
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-131 — Analytics Deletion IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search Analytics

**Test Steps:** 1. Delete own analytics 2. Modify analytics_id 3. Delete others' data 4. Evidence destruction

**Expected Result:** Deletion should verify ownership

**Payload Example:**

```
DELETE /api/analytics/victim_analytics_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-132 — Analytics Cross-Tenant Leak
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Search Analytics

**Test Steps:** 1. Multi-tenant analytics 2. Modify tenant context 3. View other tenant data 4. Cross-tenant breach

**Expected Result:** Analytics should be tenant-isolated

**Payload Example:**

```
Access competitor tenant analytics
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-133 — Trending IDOR Access
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Trending Searches

**Test Steps:** 1. View trending for own context 2. Modify context_id 3. View others' trending 4. Competitive intelligence

**Expected Result:** Trending should be context-scoped

**Payload Example:**

```
GET /api/trending?org_id=competitor_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-134 — Trending Manipulation
**Test Category:** Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Trending Searches

**Test Steps:** 1. Identify trending algorithm 2. Artificially boost searches 3. Make term trend 4. Manipulation

**Expected Result:** Trending should detect manipulation

**Payload Example:**

```
Bot searches to force trending
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Custom Scripts / Automation

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-135 — Trending XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Trending Searches

**Test Steps:** 1. Make XSS term trend 2. Trending displayed 3. XSS renders 4. Mass XSS

**Expected Result:** Trending display should sanitize

**Payload Example:**

```
Force <script>alert(1)</script> to trend
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-136 — Trending SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Trending Searches

**Test Steps:** 1. Query trending endpoint 2. Inject SQL in parameters 3. Extract trending data 4. Data breach

**Expected Result:** Trending queries should be parameterized

**Payload Example:**

```
timeframe=day'; SELECT * FROM searches--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-137 — Trending Privacy Leak
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Trending Searches

**Test Steps:** 1. View trending searches 2. Searches reveal private info 3. Infer private activities 4. Privacy violation

**Expected Result:** Private searches should not trend

**Payload Example:**

```
Trending revealing private product searches
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Manual Analysis

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SRCH-138 — Trending Blocklist Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Trending Searches

**Test Steps:** 1. Offensive term blocked 2. Use variant 3. Variant trends 4. Inappropriate content

**Expected Result:** Blocklist should handle variants

**Payload Example:**

```
Trend offensive term with typos
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-139 — Trending Cache Poisoning
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Trending Searches

**Test Steps:** 1. Request trending 2. Poison cache 3. Serve malicious trending 4. Mass impact

**Expected Result:** Trending cache should be secure

**Payload Example:**

```
Inject fake trending via cache
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## SRCH-140 — Trending Geolocation Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Trending Searches

**Test Steps:** 1. Trending by location 2. Spoof location 3. View other region trending 4. Competitive intelligence

**Expected Result:** Location should be validated

**Payload Example:**

```
Spoof IP to see other region's trending
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / VPN

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-141 — Trending Time Window Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Trending Searches

**Test Steps:** 1. View trending for timeframe 2. Modify timeframe 3. Access old trending 4. Historical data

**Expected Result:** Timeframes should be validated

**Payload Example:**

```
Access trending from 5 years ago
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-142 — Trending DoS via Calculation
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Trending Searches

**Test Steps:** 1. Trending requires computation 2. Request for large period 3. Exhaust resources 4. DoS

**Expected Result:** Calculation should be limited

**Payload Example:**

```
Request trending for 10 year period
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Postman

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-143 — Trending Category Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Trending Searches

**Test Steps:** 1. View trending by category 2. Inject in category parameter 3. SQL or path traversal 4. Exploitation

**Expected Result:** Categories should be whitelisted

**Payload Example:**

```
category=../../../etc/passwd
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-144 — Trending API Scraping
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Trending Searches

**Test Steps:** 1. Query trending API 2. Scrape all data 3. Build competitor intelligence 4. Business impact

**Expected Result:** API should be protected

**Payload Example:**

```
Mass scraping of trending data
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-145 — Trending Real-time Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Trending Searches

**Test Steps:** 1. Real-time trending updates 2. Inject via WebSocket 3. XSS in update 4. Execute on viewers

**Expected Result:** Real-time should sanitize

**Payload Example:**

```
WebSocket injection for trending
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / WS King

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-146 — Related Items IDOR
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Related / Similar Items

**Test Steps:** 1. View related items 2. Modify item_id 3. View related for restricted item 4. Information disclosure

**Expected Result:** Related should verify source access

**Payload Example:**

```
GET /api/items/restricted_item/related
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-147 — Related Items Algorithm Leak
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Related / Similar Items

**Test Steps:** 1. Analyze related items 2. Reverse engineer algorithm 3. Discover hidden relationships 4. Competitive intelligence

**Expected Result:** Algorithm details should be hidden

**Payload Example:**

```
Infer product connections from related
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Manual Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-148 — Related Items XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Related / Similar Items

**Test Steps:** 1. Related item has XSS in title 2. Related displayed 3. XSS in related section 4. Execute script

**Expected Result:** Related items should be sanitized

**Payload Example:**

```
Related item: <script>alert(1)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-149 — Related Items SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Related / Similar Items

**Test Steps:** 1. Query related items 2. Inject SQL in item_id 3. Extract data 4. Data breach

**Expected Result:** Related queries should be parameterized

**Payload Example:**

```
item_id=123'; SELECT * FROM items--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-150 — Related Items Cross-Category Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Related / Similar Items

**Test Steps:** 1. View related in category A 2. Related shows category B items 3. Access restricted category 4. Bypass access control

**Expected Result:** Related should respect categories

**Payload Example:**

```
Related items from restricted categories
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-151 — Related Items Manipulation
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Related / Similar Items

**Test Steps:** 1. Identify related algorithm 2. Create items to influence 3. Force specific related 4. Promotion abuse

**Expected Result:** Algorithm should resist manipulation

**Payload Example:**

```
Create items to appear as related to competitor
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-152 — Related Items Privacy Leak
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Related / Similar Items

**Test Steps:** 1. View related for purchase 2. Related reveals purchase 3. Privacy violation 4. User profiling

**Expected Result:** Related should not reveal private data

**Payload Example:**

```
Related items revealing user's purchase history
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Manual Analysis

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SRCH-153 — Similar Items Embedding Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Related / Similar Items

**Test Steps:** 1. Similar uses vector embeddings 2. Inject in embedding query 3. Manipulate results 4. Show malicious items

**Expected Result:** Embedding queries should be sanitized

**Payload Example:**

```
Inject in vector similarity query
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-154 — Related Items Cache Timing
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Related / Similar Items

**Test Steps:** 1. Request related items 2. Measure cache timing 3. Infer item relationships 4. Data inference

**Expected Result:** Timing should be consistent

**Payload Example:**

```
Cache timing reveals relationship existence
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-155 — Related Items DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Related / Similar Items

**Test Steps:** 1. Request related for item with many relations 2. Server computes all 3. Resource exhaustion 4. DoS

**Expected Result:** Related computation should be limited

**Payload Example:**

```
Request related for item with 1M connections
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Postman

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-156 — Related Items Personalization Bypass
**Test Category:** Privacy Violation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Related / Similar Items

**Test Steps:** 1. Related personalized 2. Bypass personalization 3. See other users' related 4. Privacy breach

**Expected Result:** Personalization should be user-specific

**Payload Example:**

```
Access non-personalized related items
```

**Impact:** Privacy violation -&gt; exposure of personal data (PII) beyond the intended audience.

**Tools:** Burp Suite / Postman

**References:** CWE-359; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Privacy Risks; GDPR

---

## SRCH-157 — Related Items Exclusion Bypass
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Related / Similar Items

**Test Steps:** 1. Item excluded from related 2. Bypass exclusion 3. See excluded items 4. Access restricted

**Expected Result:** Exclusions should be enforced

**Payload Example:**

```
See items blacklisted from related
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-158 — Similar Items API Parameter Tampering
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Related / Similar Items

**Test Steps:** 1. Query similar items 2. Modify similarity threshold 3. Get all items 4. Bypass filtering

**Expected Result:** Thresholds should be server-controlled

**Payload Example:**

```
?similarity_threshold=0
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-159 — Related Items Click Tracking IDOR
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Related / Similar Items

**Test Steps:** 1. Click tracking on related 2. Modify user_id 3. Track as another user 4. Privacy violation

**Expected Result:** Tracking should use session user

**Payload Example:**

```
Track related click as victim_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-160 — Category IDOR Access
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Browse public category 2. Modify category_id 3. Access restricted category 4. View private products

**Expected Result:** Category access should be validated

**Payload Example:**

```
GET /api/categories/internal_category_id
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-161 — Category SQL Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Select category 2. Inject SQL in category_id 3. Extract category data 4. Access all categories

**Expected Result:** Category queries should be parameterized

**Payload Example:**

```
category_id=1'; SELECT * FROM categories--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-162 — Category XSS in Name
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Category has XSS in name 2. Browse categories 3. Name renders 4. XSS executes

**Expected Result:** Category names should be sanitized

**Payload Example:**

```
<script>alert(document.cookie)</script>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-163 — Category Path Traversal
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Browse category by path 2. Inject traversal 3. Access parent categories 4. Bypass hierarchy

**Expected Result:** Paths should be validated

**Payload Example:**

```
/categories/../../admin/internal
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## SRCH-164 — Hidden Category Discovery
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Enumerate category IDs 2. Find hidden categories 3. Discover internal structure 4. Information disclosure

**Expected Result:** Hidden categories should require auth

**Payload Example:**

```
/categories/1 through /categories/10000
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite Intruder / ffuf

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-165 — Category Hierarchy Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Category requires parent access 2. Access child directly 3. Bypass parent restriction 4. Access unauthorized

**Expected Result:** Hierarchy should be enforced

**Payload Example:**

```
Access subcategory without parent access
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-166 — Category Parameter Pollution
**Test Category:** Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Select multiple categories 2. Inject via array 3. Bypass filters 4. Access restricted

**Expected Result:** Array handling should be secure

**Payload Example:**

```
category[]=public&category[]=restricted
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## SRCH-167 — Category Slug Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Access category by slug 2. Inject in slug 3. SQL or path traversal 4. Exploitation

**Expected Result:** Slugs should be validated

**Payload Example:**

```
/category/test'; DROP TABLE--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / SQLMap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-168 — Category Filter Bypass
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Category has content filter 2. Bypass filter 3. Access all category content 4. View restricted items

**Expected Result:** Filters should be enforced

**Payload Example:**

```
Remove is_published filter
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-169 — Category CSRF Modification
**Test Category:** Cross-Site Request Forgery · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Create malicious page 2. Auto-modify category 3. Admin visits 4. Category changed

**Expected Result:** Category changes should have CSRF token

**Payload Example:**

```
<form action="/admin/categories/update">
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite CSRF PoC / Custom HTML

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## SRCH-170 — Category DoS via Deep Hierarchy
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Category has deep hierarchy 2. Request full tree 3. Exhaust resources 4. DoS

**Expected Result:** Hierarchy depth should be limited

**Payload Example:**

```
Request category tree with 1000 levels
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Postman

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-171 — Category Count Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. View category item counts 2. Intercept response 3. Modify counts 4. Display false info

**Expected Result:** Counts should be server-authoritative

**Payload Example:**

```
Modify item counts in response
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-172 — Category Sorting Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Sort categories 2. Inject in sort field 3. ORDER BY injection 4. Data extraction

**Expected Result:** Sort fields should be whitelisted

**Payload Example:**

```
sort=name; SELECT * FROM categories--
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** SQLMap / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-173 — Category Metadata Exposure
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. View category API 2. Find internal metadata 3. Extract system info 4. Reconnaissance

**Expected Result:** Metadata should be filtered

**Payload Example:**

```
Category with internal_notes or admin_flags
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-174 — Category Navigation State Injection
**Test Category:** Cross-Site Scripting · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Category saves nav state 2. Inject in state 3. State rendered 4. XSS executes

**Expected Result:** Navigation state should be sanitized

**Payload Example:**

```
XSS in breadcrumb or state parameter
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-175 — Category Cross-Tenant Access
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Browse categories in tenant A 2. Modify tenant context 3. View tenant B categories 4. Cross-tenant breach

**Expected Result:** Categories should be tenant-scoped

**Payload Example:**

```
Access competitor tenant categories
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-176 — Category Pagination Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Paginate through category 2. Inject in pagination 3. SQL or out-of-bounds 4. Exploitation

**Expected Result:** Pagination should be validated

**Payload Example:**

```
page=-1 or page=99999999
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-177 — Category Image SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Category Browsing

**Test Steps:** 1. Category has image URL 2. Modify to internal URL 3. Server fetches 4. SSRF

**Expected Result:** Image URLs should be validated

**Payload Example:**

```
image_url=http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SRCH-178 — Search API Authentication Bypass
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Access search API 2. Remove auth token 3. Access without authentication 4. Unauthorized access

**Expected Result:** All search endpoints should require authentication

**Payload Example:**

```
API call without Authorization header
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / Postman

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## SRCH-179 — Search Authorization Bypass
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search own data 2. Remove access filters 3. Search all data 4. Data breach

**Expected Result:** Authorization should be enforced per query

**Payload Example:**

```
Search without ownership filters
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-180 — Search Mass Assignment
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Submit search 2. Add extra parameters 3. Modify search behavior 4. Privilege escalation

**Expected Result:** Only allowed parameters should be accepted

**Payload Example:**

```
{"query":"test",admin_mode:true,bypass_acl:true}
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / Postman / Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## SRCH-181 — Search Sensitive Data Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. View search API response 2. Find sensitive fields 3. Extract PII 4. Privacy breach

**Expected Result:** Only necessary data should be returned

**Payload Example:**

```
API returning user emails or passwords
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-182 — Search Error Message Disclosure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Trigger search errors 2. Analyze error messages 3. Extract system info 4. Reconnaissance

**Expected Result:** Errors should be generic

**Payload Example:**

```
Stack traces or SQL errors in response
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Error Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-183 — Search Rate Limiting Bypass
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Hit search rate limit 2. Bypass via headers 3. Continue scraping 4. Data exfiltration

**Expected Result:** Rate limiting should be robust

**Payload Example:**

```
X-Forwarded-For rotation
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite / IP Rotate

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## SRCH-184 — Search Result Path Traversal
**Test Category:** Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search returns file paths 2. Traverse paths 3. Access system files 4. Information disclosure

**Expected Result:** Paths should be validated

**Payload Example:**

```
result_path=../../../etc/passwd
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## SRCH-185 — Search SSRF via Content Fetch
**Test Category:** Server-Side Request Forgery · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search fetches content 2. Provide internal URL 3. Server fetches internal 4. SSRF

**Expected Result:** Content URLs should be validated

**Payload Example:**

```
url=http://169.254.169.254/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SRCH-186 — Search XXE via XML Input
**Test Category:** XML External Entity · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search accepts XML query 2. Include XXE payload 3. XML parsed 4. File disclosure

**Expected Result:** XML parsing should disable entities

**Payload Example:**

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## SRCH-187 — Search Template Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search uses templates 2. Inject template syntax 3. Template executes 4. Code execution

**Expected Result:** Search should not use templates with user input

**Payload Example:**

```
{{constructor.constructor('return this')()}}
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** Burp Suite / Tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## SRCH-188 — Search Command Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search passes to command 2. Inject OS command 3. Execute on server 4. RCE

**Expected Result:** User input should never reach shell

**Payload Example:**

```
; cat /etc/passwd ; or | whoami
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** Burp Suite / Commix

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## SRCH-189 — Search Clickjacking
**Test Category:** UI Redressing · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Frame search page 2. Create overlay 3. Trick user 4. Unauthorized action

**Expected Result:** Search should have X-Frame-Options

**Payload Example:**

```
Invisible iframe over search
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite Clickbandit / Custom HTML

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## SRCH-190 — Search CORS Misconfiguration
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

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

## SRCH-191 — Search WebSocket Security
**Test Category:** Broken Access Control · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Connect to search WebSocket 2. Access without auth 3. Receive real-time results 4. Unauthorized access

**Expected Result:** WebSocket should require authentication

**Payload Example:**

```
WS connection without auth token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / WS King

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-192 — Search GraphQL Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Query search via GraphQL 2. Inject malicious query 3. Access unauthorized data 4. Over-fetching

**Expected Result:** GraphQL should enforce field-level security

**Payload Example:**

```
{ search { results { privateField hiddenData } } }
```

**Impact:** GraphQL abuse -&gt; introspection/IDOR/batching DoS -&gt; data exposure or availability.

**Tools:** GraphQL Voyager / Altair / Burp Suite

**References:** CWE-400; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP GraphQL Cheat Sheet; PortSwigger

---

## SRCH-193 — Search GraphQL DoS
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Send complex search query 2. Deeply nested 3. Exhaust resources 4. DoS

**Expected Result:** Query depth should be limited

**Payload Example:**

```
{ search { results { related { results... } } } }
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** GraphQL Tools / Burp Suite

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-194 — Search Batch Request Abuse
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Submit batch search 2. Include many queries 3. Exhaust resources 4. DoS

**Expected Result:** Batch operations should be limited

**Payload Example:**

```
Batch with 10000 search queries
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-195 — Search Cache Key Manipulation
**Test Category:** Web Cache Poisoning · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search uses cache 2. Manipulate cache key 3. Poison cache 4. Serve malicious results

**Expected Result:** Cache keys should be secure

**Payload Example:**

```
Manipulate Vary headers or query params
```

**Impact:** Web cache poisoning/deception -&gt; mass XSS/redirect or private-data disclosure.

**Tools:** Burp Suite / Param Miner

**References:** CWE-524; -&gt;[Web Cache Poisoning checklist](#/checklist/webcache); James Kettle Web Cache Poisoning/Deception

---

## SRCH-196 — Search Session Fixation
**Test Category:** Session Management · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Get session before auth 2. User authenticates 3. Use fixed session 4. Access search data

**Expected Result:** Session should regenerate on auth

**Payload Example:**

```
Fixed session_id for search
```

**Impact:** Session fixation/hijack -&gt; attacker rides the victim's authenticated session.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-384; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Session management

---

## SRCH-197 — Search JWT Manipulation
**Test Category:** Broken Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Capture search JWT 2. Modify claims 3. Access as different user 4. Privilege escalation

**Expected Result:** JWT should be properly validated

**Payload Example:**

```
{"alg":"none"} or modify user_id claim
```

**Impact:** JWT forgery/verification flaw -&gt; identity spoofing, privilege escalation, full account takeover.

**Tools:** jwt_tool / Burp Suite JWT Editor

**References:** CWE-347; -&gt;[JWT checklist](#/checklist/jwt); Auth0 JWT library vulns; PortSwigger JWT

---

## SRCH-198 — Search Log Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search logged 2. Inject log format 3. Forge log entries 4. Audit manipulation

**Expected Result:** Logs should sanitize search terms

**Payload Example:**

```
search=valid\nFake admin action logged
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Log Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-199 — Search Email Notification Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search alert sends email 2. Inject headers 3. Send spam 4. Reputation damage

**Expected Result:** Email fields should be sanitized

**Payload Example:**

```
alert_email=test@test.com%0ABcc:spam@evil.com
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Email Analysis

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-200 — Search Prototype Pollution
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Send JSON with __proto__ 2. Pollute prototype 3. Affect application 4. Security bypass

**Expected Result:** Prototype pollution should be prevented

**Payload Example:**

```
{"query":"test",__proto__:{"isAdmin":true}}
```

**Impact:** Prototype pollution -&gt; DOM XSS (client) / RCE (server).

**Tools:** Burp Suite / Postman

**References:** CWE-1321; -&gt;[Prototype Pollution checklist](#/checklist/prototype); Olivier Arteau; PortSwigger server-side PP

---

## SRCH-201 — Search Second-Order Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Store payload in search 2. Trigger processing 3. Payload executes 4. Delayed injection

**Expected Result:** All data usage should be sanitized

**Payload Example:**

```
Payload stored then used in analytics report
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Manual Testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-202 — Search Timing Side Channel
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search with conditions 2. Measure response time 3. Infer data existence 4. Enumeration

**Expected Result:** Timing should be consistent

**Payload Example:**

```
Time difference for existing vs non-existing
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-203 — Search Multi-Tenant Data Leak
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search in tenant A 2. Modify query 3. Access tenant B data 4. Cross-tenant breach

**Expected Result:** Search should be tenant-isolated

**Payload Example:**

```
Remove tenant_id from search filter
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Postman

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-204 — Search API Key Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Inspect search requests 2. Find API key 3. Extract key 4. API abuse

**Expected Result:** API keys should be server-side

**Payload Example:**

```
Algolia/Elasticsearch key in JavaScript
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Browser DevTools / Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-205 — Search Debug Mode Exposure
**Test Category:** Security Misconfiguration · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Access search with debug param 2. Enable debug mode 3. View debug info 4. System exposure

**Expected Result:** Debug should be disabled in production

**Payload Example:**

```
?debug=true or ?explain=true
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Param Discovery

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-206 — Search Open Redirect
**Test Category:** Open Redirect · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search has redirect 2. Modify redirect URL 3. Redirect to malicious site 4. Phishing

**Expected Result:** Redirects should be validated

**Payload Example:**

```
?redirect=https://evil.com
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## SRCH-207 — Search CSP Bypass
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Analyze CSP header 2. Find bypass 3. Execute XSS 4. Data theft

**Expected Result:** CSP should be comprehensive

**Payload Example:**

```
Exploit unsafe-eval for search XSS
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** CSP Evaluator / Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SRCH-208 — Search Cookie Security Issues
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Analyze search cookies 2. Check security flags 3. Find vulnerable cookies 4. Session theft

**Expected Result:** Cookies should have security flags

**Payload Example:**

```
Missing Secure/HttpOnly/SameSite flags
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SRCH-209 — Search Missing Security Headers
**Test Category:** Security Misconfiguration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Analyze response headers 2. Check for missing headers 3. Exploit missing protections 4. Various attacks

**Expected Result:** All security headers should be present

**Payload Example:**

```
Missing X-Frame-Options/CSP/HSTS
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Security Headers Scanner / Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## SRCH-210 — Search Host Header Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Modify Host header 2. Check for injection 3. Cache poisoning 4. Password reset poisoning

**Expected Result:** Host header should be validated

**Payload Example:**

```
Host: evil.com in search request
```

**Impact:** Host-header injection into this flow -&gt; password-reset poisoning / cache poisoning -&gt; account takeover.

**Tools:** Burp Suite / curl

**References:** CWE-644; -&gt;[Host Header Injection checklist](#/checklist/hostheader); James Kettle Practical Web Cache Poisoning

---

## SRCH-211 — Search Denial of Service via Regex
**Test Category:** Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Submit regex pattern 2. Cause catastrophic backtracking 3. Exhaust CPU 4. DoS

**Expected Result:** Regex should be safe from ReDoS

**Payload Example:**

```
(a+)+$ or similar evil regex
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / ReDoS Tools

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-212 — Search Index Corruption
**Test Category:** Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Submit malformed data for indexing 2. Corrupt search index 3. Search fails 4. DoS

**Expected Result:** Index input should be validated

**Payload Example:**

```
Submit data that corrupts index
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-213 — Search Synonym Injection
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Identify synonym expansion 2. Inject malicious synonym 3. Expand to hidden content 4. Access bypass

**Expected Result:** Synonyms should be controlled

**Payload Example:**

```
Add synonym mapping to access blocked terms
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-214 — Search Stopword Bypass
**Test Category:** Security Bypass · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Identify stopword filtering 2. Bypass via encoding 3. Search for blocked term 4. Access restricted

**Expected Result:** Stopwords should handle variants

**Payload Example:**

```
Encode blocked term to bypass filter
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Hackvertor

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-215 — Search Tokenization Bypass
**Test Category:** Security Bypass · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Identify tokenizer behavior 2. Craft query to bypass 3. Search for restricted content 4. Access bypass

**Expected Result:** Tokenization should be consistent

**Payload Example:**

```
Exploit tokenizer edge cases
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Manual Testing

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-216 — Search Analyzer Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Custom analyzer used 2. Inject in analyzer config 3. Modify analysis behavior 4. Search manipulation

**Expected Result:** Analyzer config should be protected

**Payload Example:**

```
Inject malicious analyzer settings
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-217 — Search Field Boost Injection
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Field boosting enabled 2. Inject boost values 3. Manipulate relevance 4. Ranking manipulation

**Expected Result:** Boost values should be controlled

**Payload Example:**

```
field^99999 to artificially boost
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-218 — Search Highlighting Injection
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search term highlighted 2. Inject in highlight tag 3. XSS in highlight 4. Execute script

**Expected Result:** Highlight tags should be sanitized

**Payload Example:**

```
Search for </em><script>alert(1)</script><em>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-219 — Search Geo Distance Manipulation
**Test Category:** Business Logic · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search uses geo distance 2. Spoof location 3. See results from other areas 4. Access bypass

**Expected Result:** Geo parameters should be validated

**Payload Example:**

```
Spoof coordinates for different results
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / GPS Spoofing

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-220 — Search Aggregation Injection
**Test Category:** Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search with aggregations 2. Inject in agg query 3. Execute malicious agg 4. Data extraction

**Expected Result:** Aggregations should be sanitized

**Payload Example:**

```
{"aggs":{"steal_data":{"terms":{"field":"password"}}}}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-221 — Search Filter Script Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search filter uses scripts 2. Inject malicious script 3. Server-side execution 4. RCE

**Expected Result:** Scripts should be disabled

**Payload Example:**

```
{"script":"java.lang.Runtime.exec('id')"}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-222 — Search Percolator Abuse
**Test Category:** Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Percolator queries enabled 2. Create malicious percolator 3. Match unintended documents 4. Information disclosure

**Expected Result:** Percolators should be restricted

**Payload Example:**

```
Create percolator matching all documents
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-223 — Search Snapshot Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search index snapshots exist 2. Access snapshot 3. Download historical data 4. Data breach

**Expected Result:** Snapshots should be protected

**Payload Example:**

```
Access /snapshots/ or backup indices
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-224 — Search Cluster Manipulation
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Access search cluster management 2. Modify cluster settings 3. Disable security 4. Full access

**Expected Result:** Cluster management should be restricted

**Payload Example:**

```
Access /_cluster/settings without auth
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / curl

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-225 — Search Index Mapping Exposure
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Request index mapping 2. View field definitions 3. Discover sensitive fields 4. Reconnaissance

**Expected Result:** Mappings should be protected

**Payload Example:**

```
GET /index/_mapping exposing field structure
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / curl

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-226 — Search Plugin Vulnerability
**Test Category:** Remote Code Execution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Identify search plugins 2. Find vulnerable versions 3. Exploit known CVEs 4. RCE

**Expected Result:** Plugins should be updated

**Payload Example:**

```
Known plugin exploits for Elasticsearch/Solr
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** Burp Suite / CVE Database

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## SRCH-227 — Search Transport Layer Security
**Test Category:** Cryptographic Failures · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Inspect search traffic 2. Check encryption 3. Find unencrypted search 4. Data interception

**Expected Result:** Search traffic should be encrypted

**Payload Example:**

```
Search queries sent over HTTP
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** Burp Suite / Wireshark

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## SRCH-228 — Search Backup Exposure
**Test Category:** Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Enumerate backup files 2. Find search index backups 3. Download backups 4. Data breach

**Expected Result:** Backups should not be web-accessible

**Payload Example:**

```
/backup/search-index.tar.gz
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf / dirsearch

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-229 — Search Replication Abuse
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Access replication settings 2. Add malicious replica 3. Replicate to attacker 4. Data exfiltration

**Expected Result:** Replication should be restricted

**Payload Example:**

```
Add replica pointing to attacker server
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / curl

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-230 — Search Query Log Exposure
**Test Category:** Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Access search query logs 2. View all searches 3. Extract user queries 4. Privacy breach

**Expected Result:** Query logs should be protected

**Payload Example:**

```
Access to search logs without auth
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / ffuf

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-231 — Search Warm-up Abuse
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Find warm-up endpoint 2. Submit expensive warm-up 3. Exhaust resources 4. DoS

**Expected Result:** Warm-up should be restricted

**Payload Example:**

```
Submit resource-intensive warm-up query
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Postman

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-232 — Search Circuit Breaker Bypass
**Test Category:** Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Identify circuit breaker 2. Craft query to bypass 3. Cause memory overflow 4. DoS

**Expected Result:** Circuit breakers should be robust

**Payload Example:**

```
Query designed to exceed memory limits
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-233 — Search Cross-Cluster Injection
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Cross-cluster search enabled 2. Inject cluster reference 3. Access unauthorized cluster 4. Data breach

**Expected Result:** Cluster references should be validated

**Payload Example:**

```
Search into internal cluster from public
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-234 — Search Template Stored XSS
**Test Category:** Cross-Site Scripting · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Create search template with XSS 2. Template used 3. XSS rendered 4. Admin compromise

**Expected Result:** Templates should be sanitized

**Payload Example:**

```
<script>stealAdminSession()</script> in template
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / XSS Hunter

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## SRCH-235 — Search API Version Bypass
**Test Category:** Broken Access Control · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Current API has security 2. Use old API version 3. Bypass security 4. Exploit vulnerability

**Expected Result:** All API versions should be secured

**Payload Example:**

```
/api/v1/search bypassing v2 auth
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-236 — Search Content-Type Manipulation
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Expected JSON request 2. Send different Content-Type 3. Bypass validation 4. Inject payload

**Expected Result:** Content-Type should be validated

**Payload Example:**

```
Send XML with application/json
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Postman

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-237 — Search HTTP Method Override
**Test Category:** Security Bypass · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. GET search protected 2. Use method override 3. Access via POST 4. Bypass protection

**Expected Result:** Method override should be disabled

**Payload Example:**

```
X-HTTP-Method-Override: DELETE
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / curl

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-238 — Search Accept Header Manipulation
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Modify Accept header 2. Request different format 3. Get more data in alternate format 4. Information disclosure

**Expected Result:** Accept header should be validated

**Payload Example:**

```
Accept: application/xml revealing more data
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / curl

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## SRCH-239 — Search If-Match Header Bypass
**Test Category:** Broken Access Control · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search uses ETag caching 2. Bypass conditional requests 3. Access stale data 4. Information disclosure

**Expected Result:** Conditional requests should be validated

**Payload Example:**

```
Remove If-None-Match to bypass cache
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Postman

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-240 — Search Range Header Abuse
**Test Category:** Security Bypass · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search supports partial content 2. Use Range header 3. Extract specific bytes 4. Data extraction

**Expected Result:** Range requests should be validated

**Payload Example:**

```
Range: bytes=0-9999999
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / curl

**References:** CWE-840; PortSwigger Business logic

---

## SRCH-241 — Search Transfer-Encoding Attack
**Test Category:** Request Smuggling · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search behind proxy 2. Smuggle via Transfer-Encoding 3. Poison cache or hijack 4. Various attacks

**Expected Result:** HTTP parsing should be consistent

**Payload Example:**

```
CL.TE or TE.CL payload
```

**Impact:** HTTP request smuggling -&gt; cache poisoning / auth bypass / request hijacking.

**Tools:** Burp Suite HTTP Request Smuggler

**References:** CWE-444; -&gt;[Request Smuggling checklist](#/checklist/smuggling); James Kettle HTTP Desync Attacks

---

## SRCH-242 — Search Connection Pool Exhaustion
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Open many search connections 2. Hold connections open 3. Exhaust pool 4. DoS

**Expected Result:** Connection handling should be robust

**Payload Example:**

```
Open 1000 connections and hold
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-243 — Search Memory Exhaustion
**Test Category:** Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Submit search causing large allocation 2. Repeat rapidly 3. Exhaust memory 4. DoS

**Expected Result:** Memory limits should be enforced

**Payload Example:**

```
Large aggregation causing OOM
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-244 — Search CPU Exhaustion
**Test Category:** Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Submit computationally expensive search 2. Repeat 3. Exhaust CPU 4. DoS

**Expected Result:** CPU limits should be enforced

**Payload Example:**

```
Complex regex or nested query
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-245 — Search Disk Exhaustion
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Trigger excessive logging 2. Fill disk 3. Service failure 4. DoS

**Expected Result:** Disk usage should be monitored

**Payload Example:**

```
Trigger millions of error logs
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## SRCH-246 — Search Service Account Abuse
**Test Category:** Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Identify search service account 2. Compromise credentials 3. Access with elevated privileges 4. Full access

**Expected Result:** Service accounts should have minimal privileges

**Payload Example:**

```
Use leaked service account credentials
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Credential Testing / Burp Suite

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## SRCH-247 — Search Federated Query Injection
**Test Category:** Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Federated search enabled 2. Inject in federation config 3. Query unauthorized sources 4. Data breach

**Expected Result:** Federation should be controlled

**Payload Example:**

```
Inject source pointing to internal database
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-248 — Search Result Export Injection
**Test Category:** Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Export search results 2. Inject in export format 3. Code execution 4. RCE

**Expected Result:** Export should be sanitized

**Payload Example:**

```
CSV injection in exported results
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Excel

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## SRCH-249 — Search Webhook Notification SSRF
**Test Category:** Server-Side Request Forgery · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Configure search webhook 2. Set internal URL 3. Search triggers 4. SSRF

**Expected Result:** Webhooks should validate URLs

**Payload Example:**

```
webhook=http://internal-service:8080
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## SRCH-250 — Search Third-Party Integration Leak
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** General Search Security

**Test Steps:** 1. Search uses third-party API 2. Excessive data shared 3. Data leaked 4. Privacy violation

**Expected Result:** Only necessary data should be shared

**Payload Example:**

```
Full results sent to analytics
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Network Analysis

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---
