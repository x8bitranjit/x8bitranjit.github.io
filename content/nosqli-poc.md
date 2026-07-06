# NoSQL Injection — PoC Scripts

Tooling for the NoSQLi kit. *Authorized testing only.* The finding is a **steered, repeatable change in query behaviour** — you logged in with no password, extracted a secret, or executed JS — **not** a lone 500 from `[$ne]`. Baseline every probe against a control, use your own/test accounts, extract only enough to prove it, then stop. **Click a script to open its source.**

| Script | What it does |
|---|---|
| [`nosqli_fuzz.py`](#/nosqli/poc/nosqli_fuzz) | **Control-baselined** detector + **auth-bypass** tester. LOGIN mode fires the canonical `$ne`/`$gt`/`$regex`/`$in` payloads in **JSON and bracket-form** and decides "bypassed" vs a learned wrong-creds baseline (or an explicit success/fail marker, or a good-login baseline — most reliable). DETECT mode does the TRUE-vs-FALSE operator differential on one param. Low false-positive. |
| [`nosqli_blind.py`](#/nosqli/poc/nosqli_blind) | **Blind char-by-char extraction.** A `$regex` oracle (MongoDB prefix, auto-calibrated TRUE/FALSE) or a `$where` time oracle (bounded `sleep()`). Discovers length, then extracts the field. `--max-chars` to stop once proven. |
| [`nosqlmap_cheat.md`](#/nosqli/poc/nosqlmap_cheat) | **NoSQLMap** + **nosqli** (Go) + a manual-first workflow, and per-datastore payload switch (Mongo / CouchDB / Elasticsearch / Redis / Neo4j). |

## Typical flow
1. **Auth bypass** — `nosqli_fuzz.py` in LOGIN mode (learn success from your own good login = most reliable).
2. **Boolean oracle?** Extract a secret from **your own** account (`nosqli_blind.py --max-chars 8`) to prove impact.
3. **Search/filter param** — `nosqli_fuzz.py --param` for the operator differential.

> A finding = a **steered** TRUE/FALSE (login without a password / data out / secret extracted / JS run), not a lone error. Own/test accounts, bounded sleeps, no infinite loops or heavy `mapReduce` on prod, redact secrets. `$ne`/`$gt` operator behaviour here is NoSQLi — SQL `'`/`UNION` is a different kit.
