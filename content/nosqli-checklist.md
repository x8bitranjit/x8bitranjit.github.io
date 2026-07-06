# NoSQL Injection — Testing Checklist

**Author:** x8bitranjit
Baseline every probe against a control. Tick only what you reproduced. Impact = auth bypass / data exfil / RCE.

## Phase 0 — Fingerprint
- [ ] Datastore identified (MongoDB / CouchDB / Elasticsearch / Redis / Cassandra / Neo4j / DynamoDB / Firebase)
- [ ] Stack/driver identified (Node+Mongoose / PHP / PyMongo / …)
- [ ] Body parser behavior known (does `p[$ne]=` become an object? JSON accepted?)
- [ ] All query-reaching inputs mapped (login, search, filter, id, sort, aggregation, JSON bodies)

## Phase 1 — Detection
- [ ] Special-char/error probing (`' " ` \ ; { }`) — noted any DB error leak
- [ ] Operator differential: `[$ne]` / `[$gt]` / `[$regex]=.*` vs false-forcing controls
- [ ] Tried BOTH JSON body and bracket/form forms
- [ ] Boolean true/false payload pair diffs the response
- [ ] Time-based `$where` `sleep()` (bounded) shows repeatable delay

## Phase 2 — Authentication bypass
- [ ] `{"username":{"$ne":null},"password":{"$ne":null}}` (JSON)
- [ ] `username[$ne]=x&password[$ne]=x` (form)
- [ ] `username:"admin"` + password operator (target admin)
- [ ] `$gt`/`$regex`/`$in` variants
- [ ] `$where` string-concat bypass (`admin'||'1'=='1`)
- [ ] **Confirmed: logged in with NO valid password, in a fresh session, as the expected/admin user**

## Phase 3 — Data disclosure / filter bypass
- [ ] Filter param `[$ne]`/`$regex=.*` reveals other users'/unpublished data
- [ ] `_id`/lookup type confusion
- [ ] Aggregation `$lookup` cross-collection read / `$out`/`$merge` write

## Phase 4 — Blind extraction (→ ATO)
- [ ] Boolean oracle established (login-ok / result-count / status / length)
- [ ] `$regex` char-by-char extraction works
- [ ] Length discovery (`^.{N}$`)
- [ ] `$where` JS extraction (when regex filtered)
- [ ] **Extracted a secret** (own hash / token / **password-reset token** → ATO)

## Phase 5 — Server-side JS / per-datastore
- [ ] `$where`/`$function`/`mapReduce` JS executes
- [ ] Elasticsearch scripting → RCE (CVE-2014-3120/2015-1427) or `_all` dump
- [ ] Redis CRLF/command injection → webshell/`MODULE LOAD` (via SSRF)
- [ ] Neo4j `LOAD CSV`/`apoc` → SSRF/file/RCE
- [ ] CouchDB CVE-2017-12635 admin creation
- [ ] Firebase open rules → unauth read/write

## Phase 6 — WAF / sanitizer bypass
- [ ] Nested operator (`$not:{$eq:...}`) vs `$`-stripping sanitizer
- [ ] Content-type switch (JSON ↔ form ↔ multipart)
- [ ] HPP / type juggling / array injection
- [ ] Second-order (stored operator used later)

## Phase 7 — Escalate & validate
- [ ] Proved concrete impact (auth bypass / data out / secret / RCE), repeatable
- [ ] Chained where possible (IDOR / SSRF / GraphQL / reset-token → ATO)
- [ ] Severity + CWE-943 mapped

## AUTO-REJECT (don't report alone)
- [ ] A lone 500/error from `[$ne]` or `{` (no steered behavior change)
- [ ] `$regex=.*` returns all but the endpoint returns all by default (no diff vs false control)
- [ ] Single non-repeatable timing blip
- [ ] Reflected operator in a JSON echo (no query effect)
- [ ] "It's MongoDB" with no injecting parameter

## SAFE-PoC
- [ ] Own test account as the extraction/ATO "victim"; no real-user data dumped
- [ ] Auth bypass proven into a test/own account; one screenshot; no pivoting into real data
- [ ] Blind extraction stopped after enough chars to prove; secrets redacted
- [ ] Bounded `sleep` (≤5s); no infinite loops / heavy mapReduce on prod (DoS)
- [ ] RCE = one benign command then STOP; writes only to throwaway keys you delete; listeners torn down
