# SQL Injection — PoC Scripts

Runnable, **benign-by-default** tooling that backs the SQLi kit. The finding is **the query behaving differently
with a concrete impact** (RCE / auth bypass / DB read / file R-W) — *not* a reflected quote or a lone 500. **Click a
script to open it on its own page.** *Authorized testing only:* prove with a benign value (`version()` + one row),
read a **bounded** sample, never mass-dump, and never run table-wide `UPDATE`/`DELETE`/`DROP`.

| Script | What it does |
|---|---|
| [`sqli_fuzz.py`](#/sqli/poc/sqli_fuzz) | Probe a `FUZZ` point across the technique families: **error-based** (+ DBMS fingerprint), **boolean** (true/false diff), **time** (`SLEEP` vs `SLEEP(0)`), **UNION** (column-count via `ORDER BY`), and **auth-bypass** (with `--true`). Boolean hits are stability-re-checked to keep false positives low. |
| [`sqli_blind.py`](#/sqli/poc/sqli_blind) | **Blind extractor** — read a scalar sub-query char-by-char via a **boolean** (response-diff) or **time** (delay) oracle. Binary-searches each char (~7 requests/char). Per-DBMS substring/sleep helpers. |
| [`sqlmap_cheat.md`](#/sqli/poc/sqlmap_cheat) | The **sqlmap** power cheat-sheet — confirm / fingerprint / characterize for the report, **PoC-safe** (no `--risk 3`, no blanket `--dump`, no `--os-shell` on bounties). |

## Typical flow
1. **Fuzz** the injection point → technique family + DBMS guess (`sqli_fuzz.py`). For a login, add `--true "<success marker>"` to test auth-bypass.
2. **Boolean/time confirmed?** Extract a **benign** value — `database()`, `@@version`, current user — to prove arbitrary read without touching real PII (`sqli_blind.py`).
3. **UNION confirmed?** Pull version + **one** benign row by hand, or use `sqlmap` to characterize (`sqlmap_cheat.md`).
4. **Impact, then stop:** for file read use a non-sensitive file (`/etc/hostname`); for write/RCE drop a benign marker or run one benign command (`whoami`) — no live shell, no post-exploitation on a bounty.

> Prove the **query changed** (other rows · a stable true/false · a controlled delay · a UNION value · a DNS hit), not
> a reflected error. `$ne`/`$gt`/`$where` operator behaviour is **NoSQL injection** — a different bug/kit, not SQLi.
> Read the **Testing Guide** for the full technique order and the **Zero to Expert (Q&A)** for the *why* behind each one.
