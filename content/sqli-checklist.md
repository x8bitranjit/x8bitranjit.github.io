# SQL-Injection Testing Checklist — tick per sink

> Companion to `SQL_INJECTION_TESTING_GUIDE.md`. The finding is **the query behaving differently with a concrete impact**
> (RCE / auth bypass / DB read / file R-W), not a reflected quote or a lone 500. Work top-to-bottom **per SQL sink**; stop
> and report only when you've proven the database did your bidding — **benignly** (`version()` + one row), no mass dump,
> no destructive writes.

## PHASE 0 — Recon & map sinks (§3/§1)
- [ ] Enumerated every input reaching SQL: URL params, POST/form fields, **JSON keys (incl. nested)**, cookies, and the **headers apps log** (`User-Agent`/`Referer`/`X-Forwarded-For`).
- [ ] Prioritized **login/auth**, **search/filter**, **`?sort=`/`?order=`** (identifier context), **pagination** (`?limit/offset`), **export/report** builders, **GraphQL/REST** resolvers.
- [ ] Grepped source/JS for string-built SQL (`execute("..."+x)`, `query(\`...${x}\`)`, `knex.raw`, `sequelize.literal`, `order(params[:sort])`, `String.format` into SQL) — i.e. **not** parameterized.
- [ ] **Second-order:** flagged any value **stored** then later used in a query (username, display name, address, filename, comment) (§18).

## PHASE 1 — Baseline / classify (§4/§5)
- [ ] Sent a **normal value**, then `'`, `"`, `)`, and the **arithmetic test** (`2-1` vs `1`) — recorded status / length / body / timing.
- [ ] Decided the **context**: **STRING** (`'…'`) vs **NUMERIC** (`id=1`) vs **IDENTIFIER** (`ORDER BY`/column) vs **LIKE**.
- [ ] Classified observability: **ERROR** / **BOOLEAN-diff** / **TIME** / **UNION-able** / **silent(blind)**.
- [ ] Noted **DBMS hints** (error text, concat behavior `CONCAT` vs `||` vs `+`, comment style).

## PHASE 2 — Detect (§5–§11) — work the families in order
- [ ] **Broke the query** & confirmed context: `' OR '1'='1` (true) vs `' AND '1'='2` (false), or `2-1`→row 1 (numeric), or index-probe (identifier §5.4).
- [ ] **Error-based + fingerprint** (§6): triggered a DB error; identified MySQL/PG/MSSQL/Oracle/SQLite; tried `extractvalue`/`CAST`/`CONVERT` extraction if errors shown.
- [ ] **Boolean blind** (§7): `AND 1=1` vs `AND 1=2` give a **stable, repeatable** different response.
- [ ] **Time blind** (§8): `SLEEP(5)`/`pg_sleep`/`WAITFOR` delays while `SLEEP(0)` doesn't, **repeatably** (also fingerprints DBMS).
- [ ] **UNION** (§9): found **column count** (`ORDER BY N` errors / `UNION SELECT NULL…`) and a **visible string column** (marker shows).
- [ ] **OOB** (§10): if fully blind/firewalled, triggered a **DNS/HTTP callback** carrying `database()` (Collaborator hit).
- [ ] **Stacked** (§11): tested `'; WAITFOR DELAY`/`'; SELECT pg_sleep` → does a **second statement** run? (MSSQL/PG).

## PHASE 3 — Impact (§12–§18) — escalate to the highest the engine/privs allow
- [ ] **Auth bypass (§12):** `admin'-- -` / `' OR 1=1 LIMIT 1-- -` logs in → noted **which account** (admin → Critical).
- [ ] **Dump (§13):** enumerated schema → tables → columns; pulled `version()` + **one benign row** (count + sample, not the whole table).
- [ ] **File read (§14):** `LOAD_FILE`/`pg_read_file`/`OPENROWSET` returned a **benign** file (proved read).
- [ ] **File write (§15):** if writable webroot, wrote a **benign marker** and fetched it over HTTP (proved write+serve) — **no live shell**.
- [ ] **RCE (§16):** with stacked + privilege, ran **one benign command** (`whoami`/`id`) via `xp_cmdshell`/`COPY…FROM PROGRAM`; captured one line (inline/temp-table/OOB).
- [ ] **Privesc/lateral (§17):** checked DBA/superuser; documented linked-server reach (`OPENQUERY`) — did **not** pivot out of scope.
- [ ] **Second-order (§18):** planted a time/OOB payload in a stored field; triggered the consumer (admin search/report); confirmed it fired.
- [ ] Used **benign proof**; **bounded** every read; **no** mass dump; **no** destructive writes (own-row only).

## PHASE 4 — Evade WAF/filter/ORM (§19)
- [ ] Keyword blocked (`UNION`/`SELECT`) → `/*!UNION*/` / `UNI/**/ON` / case.
- [ ] Space blocked → `/**/` / `%09` / parentheses.
- [ ] Quote blocked → hex (`0x61646d696e`) / `CHAR()`/`CHR()`.
- [ ] Response-diff normalized by WAF/cache → switched to **time** (delay survives).
- [ ] Front-end parameterized → hunted the **identifier/sort** slot (§5.4) and **second-order** (§18).
- [ ] `=` blocked → `LIKE` / `<>` / `BETWEEN` / `IN`.

## PHASE 5 — Validate → report
- [ ] Proved the **query changed** (other rows / true-false / delay / DNS hit / version / whoami) — FP check §22.
- [ ] Re-tested time/boolean oracles a few times to exclude caching/jitter; tied the change to my specific payload.
- [ ] Reproduced **by hand** (not "sqlmap said so"); confirmed the **DBMS** and the **technique**.
- [ ] Confirmed on **production**; re-tested partial fixes (`'` escaped but numeric injectable; `UNION` blocked but boolean/time work).
- [ ] Set CVSS 3.1 + **CWE-89** (+ **CWE-287** auth bypass / **CWE-78** RCE) (§23).
- [ ] De-duped to one finding per sink; led with the highest impact (RCE > auth bypass > dump on the same sink) (§26).

## AUTO-REJECT (don't submit if…)
- [ ] A `'` merely caused a **500 / stack trace** with no subsequent query change (error is a *lead*, not the finding).
- [ ] A **SQL error string reflected** in the page (verbose-error info leak ≠ injection) — unless you forced data into it (error-based).
- [ ] A **single noisy response-length blip** (could be caching/jitter — re-test for a stable oracle).
- [ ] **"sqlmap flagged it"** with no hand reproduction.
- [ ] A **slow endpoint** called "time-based" with no controlled `SLEEP(5)` vs `SLEEP(0)` proof.
- [ ] **NoSQL `$ne`/`$gt`** behavior (that's NoSQL injection — its own kit).
- [ ] **Self-DoS** via a huge/heavy query instead of a bounded, benign payload.
- [ ] Any **destructive proof** (a `DROP`/`DELETE`/table-wide `UPDATE` actually ran) — never acceptable; own-row/read-only only.
