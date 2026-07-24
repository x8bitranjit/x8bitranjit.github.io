# NoSQL Injection — Zero to Expert (100 Q&A)

**Author:** x8bitranjit
Study companion + field reference for NoSQL injection. Advanced guide — pair with PortSwigger Academy, HackTricks, OWASP, PayloadsAllTheThings, and the MongoDB operator docs. Impact ceiling = auth bypass · blind data exfil · RCE.

---

## Level 0 — Fundamentals

> *Plain version:* a NoSQL query is a form the app fills out — "find a user where username = ___ and password = ___." NoSQLi is writing a **command** in the blank instead of a plain value: where they wanted your password you write `{"$ne": null}` ("any password that isn't empty"), and the database obeys, logging you in with no real password.

**Q1. What is NoSQL injection?** Manipulating a NoSQL query by supplying input the developer expected to be a scalar (string/number) but which the datastore instead interprets as a **query operator** or **code**. It subverts the query's logic — bypassing auth, leaking data, or executing code.

**Q2. How is it different from SQL injection?** SQLi breaks out of a **string** with quotes/keywords in a textual query language. NoSQLi usually injects **structured operators** (`$ne`, `$regex`) into a document/JSON query, or JS into a `$where` clause. There are no table joins/`UNION` in the classic sense; the "syntax" is JSON/BSON or a DB-specific expression language.

**Q3. Which datastores are affected?** Any NoSQL DB whose queries are built from untrusted input: **MongoDB** (most common in bounty), CouchDB, Elasticsearch/OpenSearch, Redis, Cassandra, Neo4j, DynamoDB, Firebase/Firestore.

**Q4. Why is MongoDB the flagship target?** It's the most deployed document DB, its query language is JSON with powerful operators (`$ne`,`$gt`,`$regex`,`$where`), and popular stacks (Express/Mongoose, PHP) auto-parse `field[$ne]=x` into the exact nested object the driver injects.

**Q5. What's the single most common NoSQLi bug?** **Authentication bypass** — a login that does `findOne({username, password})` with unvalidated object input, defeated by `{"username":{"$ne":null},"password":{"$ne":null}}`.

**Q6. What are the two sub-families of NoSQLi?** (1) **Operator injection** — smuggle `$ne/$gt/$regex/$where/$or/...` where a scalar was expected. (2) **Syntax/JS injection** — break out of a string concatenated into a query or into a `$where`/Cypher/CQL/Lua/Painless expression.

> *Plain version:* `$ne` = "not equal to." So `{"$ne": null}` means "match any record where this field is *not empty*" — i.e. basically everything. Dropped into a password slot, it turns "password must equal Y" into "password must be *anything*", and the login gate swings open.

**Q7. What does `{"$ne": null}` do?** "Not equal to null" — matches essentially every document where the field exists, so the query returns everything (or the first match) → auth bypass / mass match.

**Q8. What does `$regex` give an attacker?** Pattern matching. `.*` matches anything (widen a query); `^a` tests a prefix, enabling **char-by-char blind extraction** of secrets.

**Q9. What is `$where`?** A MongoDB operator that runs a **JavaScript** predicate per document. Injectable `$where` = server-side JS = blind exfil, timing oracles, DoS, and (on some stacks) code execution.

**Q10. What's the primary CWE?** **CWE-943** (Improper Neutralization of Special Elements used in a Data Query Logic). Downstream: CWE-287 (auth bypass), CWE-94 (JS/code injection), CWE-78 (OS command via ES/Redis/Neo4j).

---

## Level 1 — Input formats & recon

> *Plain version:* this is why NoSQLi is so easy — you don't need to send fancy JSON. An ordinary form field written `username[$ne]=x` gets *automatically rebuilt* by the framework's parser into the command object `{username: {$ne: "x"}}`. So a plain login form, with no JSON in sight, hands the database your injection. Devs forget the parser does this.

**Q11. Why does `username[$ne]=x` in a form body matter?** Body parsers like Express's `qs` and PHP convert bracket notation into a **nested object**: `{username: {$ne: "x"}}`. So a plain form field becomes an operator object without any JSON — devs often forget this.

**Q12. Which content-types can carry NoSQLi?** JSON (`{"u":{"$ne":null}}`), URL-encoded/form (`u[$ne]=`), multipart, and query strings (`?u[$ne]=`). **Content-type switching** is a top bypass — try the same payload in each format.

**Q13. How do you fingerprint MongoDB?** `MongoError`/`E11000` errors, 24-hex `ObjectId`s, `$where` acceptance, port 27017, Mongoose stack traces. For CouchDB: `_all_docs`, `error":"forbidden"`, port 5984. For Elasticsearch: `"took"`, `"hits"`, port 9200.

**Q14. Where does user input reach a NoSQL query?** Login, search, filters, `id`/lookup, sort/projection, aggregation pipelines, and any JSON API body mapped onto a query document.

**Q15. What source-code patterns signal risk?** `findOne({user: req.body.user, pass: req.body.pass})`, `find(req.query)`, `$where: "..." + input`, `aggregate([...userInput])`, disabled/absent input validation, `strictQuery:false` in Mongoose.

**Q16. Is `_id` injectable?** Sometimes — type confusion (`_id[$ne]=...`) or supplying an object where an ObjectId is expected can enumerate or error-leak. Also `_id[$gt]=` to walk documents.

**Q17. What's aggregation-pipeline injection?** User-controlled pipeline stages (`$match`, `$lookup`, `$out`, `$function`). `$lookup` reads other collections; `$out`/`$merge` **writes**; `$function` runs JS.

**Q18. Do ORMs/ODMs prevent NoSQLi?** Not automatically. Mongoose casts by schema type *if* the field is typed and validation runs, but mixed/`Schema.Types.Mixed` fields, `find(req.body)`, or `strictQuery` off still inject. Always test.

**Q19. What is `express-mongo-sanitize`?** Middleware that strips keys starting with `$` or containing `.`. It reduces risk but can be bypassed if it doesn't recurse into all structures or if keys are reconstructed downstream.

**Q20. Where do you look first on a target?** The **login** endpoint (auth bypass = highest value), then search/filter endpoints and any JSON API that echoes/uses query params.

---

## Level 2 — Detection

**Q21. Why baseline against a control?** NoSQLi verdicts are differential — "the operator changed the result." Without a control (valid input + clearly-invalid input) you can't tell a real steer from normal behavior → false positives.

**Q22. What's the operator-injection differential test?** Send a **true-forcing** operator (`[$ne]=bogus`, `[$gt]=`, `[$regex]=.*`) and a **false-forcing** one (`[$gt]=zzzz`, `[$regex]=^$`, `[$in]=[]`). If true-forcing returns more/login-ok and false-forcing returns none, injection is confirmed.

**Q23. How do special characters help detection?** `'`, `"`, `` ` ``, `\`, `{`, `}`, `;` can trigger DB/parse errors that both confirm input reaches a query and hint at string-context (`$where`) injection.

**Q24. What's a boolean oracle here?** Any observable that differs between a true and false query: login success/failure, result count, response length, status code, presence of an element.

**Q25. How do you detect time-based NoSQLi?** Where `$where`/JS is reachable: `{"$where":"sleep(3000)"}` or a predicate gated `sleep`. A repeatable ~3s delay = blind oracle. Keep it bounded; never infinite-loop prod.

**Q26. Why test both JSON and bracket forms?** Endpoints often validate one format but not the other; the parser may build the operator object only in one. Coverage requires both.

**Q27. What's a common false positive?** A lone 500 from `[$ne]` (generic type error), or `$regex=.*` returning "everything" when the endpoint returns everything anyway. Only a **diff vs the false control** counts.

**Q28. How do you reduce FPs in an auth-bypass test?** Reproduce in a **fresh session** with **no** valid password, confirm you're authenticated as a **different/expected** user (not your own cached session), and repeat.

**Q29. What does `$exists` detect?** Whether a field is present. `password[$exists]=false` matching users reveals accounts lacking a password field; useful for field discovery.

**Q30. Can you detect NoSQLi purely blind (no errors, no visible data)?** Yes — boolean (result present/absent, login ok/nok) and time (`$where sleep`) oracles both work without any data reflection.

---

## Level 3 — Authentication bypass

**Q31. Give the canonical Mongo auth-bypass payload.** `{"username":{"$ne":null},"password":{"$ne":null}}` — matches the first user with a non-null username and password → logs you in as them.

**Q32. How do you target the admin specifically?** Pin the username and inject only the password: `{"username":"admin","password":{"$ne":"x"}}` or `{"username":"admin","password":{"$regex":"^"}}`.

**Q33. Why might `{"$ne":null}` log you in as a random user?** `findOne` returns the **first** matching document (collection/natural order), often the seed/admin account — but not guaranteed. Pin the username to control it.

**Q34. What's the form-body equivalent?** `username[$ne]=x&password[$ne]=x` with `Content-Type: application/x-www-form-urlencoded`.

**Q35. How does `$gt` bypass auth?** `{"password":{"$gt":""}}` matches any password greater than the empty string — i.e. any non-empty password → login without knowing it.

**Q36. How does `$in` help?** `{"username":{"$in":["admin","administrator","root"]}}` targets a list of likely privileged accounts in one request.

**Q37. What's a `$where` login bypass?** When input is concatenated into a `$where` string: `username=admin'||'1'=='1` makes the JS predicate always true.

**Q38. Why is auth bypass usually Critical?** It's unauthenticated, affects the login of (potentially) every account including admin, and requires no credentials — direct, high-impact access.

**Q39. The app hashes passwords — does that stop the bypass?** If the app compares the hash **in the query** (`{password: hash(input)}`), operator injection still works on the username side and sometimes the password side. If it fetches by username then compares the hash **in code**, the password-operator trick fails but username injection may still leak the user. Test both fields.

**Q40. What if only the username is injectable?** You can enumerate/return a target user (`username[$ne]=null` → first user's data leaks) or combine with blind extraction to pull the stored hash/token.

---

## Level 4 — Blind extraction (→ ATO)

> *Plain version:* a game of 20 questions against the database. You can't ask for the password, but you *can* ask yes/no questions with `$regex`: "does it start with 'a'?" (`^a`). The page answers yes or no (login works or doesn't), you keep the letters that say yes, and rebuild the secret one character at a time. Aim it at a reset token = account takeover.

**Q41. How does `$regex` blind extraction work?** With a boolean oracle, test `password:{"$regex":"^a"}`, `^b`, … until the response flips to TRUE, revealing the first char; then `^<known>x` for the next, char by char.

**Q42. How do you find the secret's length?** `{"$regex":"^.{N}$"}` — increment N until it matches; that N is the exact length. Speeds up extraction and confirms completeness.

**Q43. What's the highest-impact thing to extract blind?** A **password-reset token** or **session/API token** for a victim account → immediate **ATO**. Then password hashes (offline crack), then other PII.

**Q44. How do you extract via `$where` when regex is filtered?** `{"$where":"this.password[0]=='a'"}` or binary-search the byte: `{"$where":"this.password.charCodeAt(0)>96"}` — halve the range each request.

**Q45. Why binary-search the charByte instead of linear?** ~log2(charset) requests per character (≈7 for ASCII) instead of up to N — far fewer requests, less noise, faster.

**Q46. What charset do you use for a hash vs a token?** Hex hash → `[0-9a-f]`. Tokens → often `[A-Za-z0-9-_]` (base64url) or `[A-Za-z0-9]`; discover by probing which classes match.

**Q47. What regex metacharacters must you escape in the known prefix?** `. ^ $ * + ? ( ) [ ] { } | \` — escape them in the already-extracted prefix so `^known` matches literally.

**Q48. How do you keep blind extraction SAFE?** Extract **your own** account's secret (or a benign marker), stop after enough characters to prove the primitive, throttle the loop, and **redact** the value in the report.

**Q49. Can you extract field names blind?** Yes — `{"$where":"Object.keys(this).indexOf('secret')>=0"}` or `{"fieldName":{"$exists":true}}` to confirm a field, then extract its value.

**Q50. What makes extraction "confirmed" vs "maybe"?** A **stable** boolean oracle: the same true payload always returns true, the same false always false, across repeats — so each extracted char is reliable, not a fluke.

---

## Level 5 — Server-side JavaScript & aggregation

> *Plain version:* `$where` lets a query carry a snippet of real JavaScript the database runs for each record — so injecting there means running code *inside the database*. On modern MongoDB it's caged (no shell, no network), so you use it to read fields and time delays; only old versions or a foolish Node `eval` turn it into a real shell.

**Q51. What can injected `$where` JS do on modern MongoDB?** Read any field of the current document, run arbitrary JS **sandboxed** (no shell/network/require), `sleep()`, and heavy compute → blind exfil, timing oracles, and DoS. Not OS RCE by itself on current versions.

**Q52. When does MongoDB JS become RCE?** Legacy `eval`/very old versions, or when the app pipes the "JS" into a Node `eval`/`vm`/`Function` sink (not the DB) — that's Node code injection, potentially full RCE. Verify the actual sink.

**Q53. What is `$function` (MongoDB 4.4+)?** An aggregation operator running a JS function body. If user-controlled, it's server-side JS execution within aggregation.

**Q54. How is `mapReduce` abused?** Its `map`/`reduce`/`finalize` are JS functions; injectable ones run attacker JS and can be heavy (DoS) or exfil data via observable effects.

**Q55. What's the risk of `$lookup` injection?** It performs a join to another collection — an attacker steering `from`/pipeline can **read collections** they shouldn't (e.g. join `users` into a public query).

**Q56. What do `$out` and `$merge` do, and why care?** They **write** the aggregation output to a collection — an integrity/persistence impact (overwrite data, plant a stored payload). Avoid on prod; if proving, use a throwaway collection.

**Q57. How do you confirm JS executes without impact?** `{"$where":"return true"}` vs `"return false"` — a clean boolean flip proves execution; then a bounded `sleep` proves timing, all benign.

**Q58. Is `$where` enabled by default?** Server-side JS can be disabled (`security.javascriptEnabled:false` / `--noscripting`). Many managed deployments disable it — test, don't assume.

**Q59. What's the DoS risk from `$where`?** A per-document JS predicate over a large collection, or a tight loop, is expensive. Bounded `sleep` is fine to demo; never run unbounded loops or full-collection heavy JS on prod.

**Q60. How do aggregation and pipeline injection differ from simple operator injection?** Simple operator injection tweaks a filter; pipeline injection controls **stages** — enabling joins, JS, and writes — a broader, often higher-impact surface (the "second-order" of NoSQLi).

---

## Level 6 — Per-datastore

**Q61. CouchDB — what's the classic critical bug?** **CVE-2017-12635**: a JSON parser differential between Couch's Erlang and JavaScript validators lets a duplicate `roles` key slip an unprivileged user into the `_admin` role → admin creation → config/query-server → RCE.

**Q62. How do you dump all docs in CouchDB via Mango?** `POST /db/_find {"selector":{"_id":{"$gt":null}}}` — `$gt null` matches every document.

**Q63. Elasticsearch — how does injection become RCE?** Dynamic scripting: MVEL **CVE-2014-3120** (the default script language in ES <1.2) and Groovy sandbox-bypass **CVE-2015-1427** (ES 1.3.x–1.4.x) allow `{"script":"..."}` to run Java/OS commands. Modern ES sandboxes Painless, but misconfigs and old versions are RCE.

**Q64. Elasticsearch — non-RCE impact?** Query-DSL injection into `_search` (boolean/blind), and **unauthenticated clusters** exposing `_all`/`_cat/indices` → mass data disclosure.

**Q65. Redis — how is it injected and exploited?** Via **CRLF/command injection** (smuggle `\r\n` + commands into a value written to the RESP protocol, often through SSRF). Then `CONFIG SET dir/dbfilename` + `SET` a webshell + `SAVE` → RCE; or `EVAL` Lua; or `MODULE LOAD`.

**Q66. Neo4j — what does Cypher injection allow?** String breakout (`' OR 1=1 //`), `RETURN`/`UNION` data theft, **`LOAD CSV FROM 'http://...'`** (SSRF/file read), and **`apoc.*`** procedures for file/HTTP/RCE, plus schema enumeration (`db.labels()`).

**Q67. DynamoDB — is it injectable?** Via **PartiQL** (`ExecuteStatement`) with string concatenation: `' OR '1'='1`. Parameterized API calls are safe; PartiQL string-building is not.

**Q68. Firebase/Firestore — what's the typical bug?** **Insecure security rules** (world-readable/writable), and REST `.json` endpoints (`https://x.firebaseio.com/users.json`) returning data without auth; PUT/PATCH to write.

**Q69. Cassandra/CQL — injection surface?** `' OR '1'='1`, `ALLOW FILTERING` to force expensive full scans; more limited because prepared statements dominate, but string-concat endpoints inject.

**Q70. How do you pick payloads per datastore?** Fingerprint first (Q13), then use that store's operators/expression language — Mongo operators won't work on Elasticsearch DSL or Cypher. The arsenal groups payloads by store.

---

## Level 7 — Bypasses & advanced

**Q71. How do you bypass a `$`-stripping sanitizer?** Nest the operator so the top-level key isn't literally `$ne`: `{"username":{"$not":{"$eq":null}}}` — if the sanitizer doesn't recurse, the inner `$eq` survives. Also exploit keys reconstructed downstream.

**Q72. How does content-type switching bypass filters?** A filter that inspects JSON bodies may ignore `application/x-www-form-urlencoded` bracket payloads (or multipart) that the framework still parses into operator objects. Try every content-type.

**Q73. What is HTTP Parameter Pollution here?** Sending a param twice (`username=admin&username[$ne]=x`) so different layers see different values, smuggling the operator past a validator that only checks the first/last occurrence.

**Q74. How does type juggling apply?** Supplying `password=0` (number) vs `"0"` (string), `true`, `null`, or arrays (`username[]=admin`) — loose comparisons/casts can match unintended documents or trigger `$in`-like behavior.

**Q75. What's second-order NoSQLi?** An operator/JS stored earlier (profile field, saved search, name) is later used **unsanitized** inside a query, triggering injection away from the original input point.

**Q76. Why send operators inside arrays?** Some parsers/sanitizers don't walk into array elements, so `{"$or":[{"a":1},{"password":{"$ne":null}}]}` or array-wrapped operators can slip through.

**Q77. How do you bypass regex filters on `$regex`?** Use `$where` JS extraction instead (`this.field.match(...)` / `charCodeAt`), or comparison operators (`$gt`/`$lt` narrowing) to binary-search values without `$regex`.

**Q78. Can NoSQLi cause prototype pollution or vice-versa?** Related but distinct: crafted keys (`__proto__`) in JSON can pollute prototypes in JS apps ([../PrototypePollution/](../PrototypePollution/)), sometimes chaining with query building (a polluted `Object.prototype` can even inject operator keys into an otherwise-clean query). Watch for `__proto__`/`constructor` keys.

**Q79. How do you evade WAF signatures for `$ne`/`$where`?** Alternate encodings/casing of keys the WAF matches, nesting (`$not:{$eq}`), moving the operator to a less-inspected format/param, and splitting via HPP. Always confirm the bypass with the differential test.

**Q80. What's the role of `qs`/deep-object parsing?** Express's `qs` builds deep objects from `a[b][$gt]=1`, enabling **nested operator** injection into sub-documents/filters — expands the surface beyond top-level fields.

---

## Level 8 — Escalation & chaining

**Q81. Turn a login bypass into maximum impact.** Land as admin (pin `username:"admin"`), then demonstrate an admin-only action (read users, config) — one screenshot — to prove privilege, without dumping real data. Critical.

**Q82. Turn a boolean oracle into ATO.** Blind-extract a victim's **password-reset token** (or session token) char-by-char, then complete the reset/replay the token → full account takeover.

**Q83. Chain NoSQLi with IDOR.** A filter-injection (`userId[$ne]=me`) returns other users' objects; combine with predictable IDs to enumerate and read at scale ([../IDOR/](../IDOR/)).

**Q84. Chain NoSQLi with SSRF.** SSRF ([../SSRF/](../SSRF/)) reaches an internal Redis/Elasticsearch/Mongo with no auth; then inject/command it directly for data or RCE.

**Q85. Chain NoSQLi with JWT.** Extract a signing secret or user record blind, then forge tokens ([../JWT/](../JWT/)) for privilege escalation/ATO.

**Q86. Chain NoSQLi through GraphQL/REST.** A GraphQL resolver or REST endpoint passes args into a Mongo query; the injection lives in the API layer ([../../API/GraphQL/](../../API/GraphQL/), [../../API/REST/](../../API/REST/)). Same operators, different entry point.

**Q87. What's the RCE path on a MEAN/MERN stack?** Rare via Mongo itself (sandboxed JS); more likely via Elasticsearch/Redis/Neo4j in the same environment, or a Node `eval`/template sink fed by the injected "JS". Verify the sink before claiming RCE.

**Q88. How do you prove data-write impact safely?** Use `$out`/`$merge` to a **throwaway** collection you name and delete, or write a **benign marker** to your own record — never overwrite real prod data.

**Q89. What's the most valuable chain overall?** Login-bypass → admin, or boolean-oracle → reset-token → ATO — both convert a query quirk into full account/system control, which is what pays.

**Q90. When is NoSQLi only Medium/Low?** A filter bypass exposing non-sensitive data, an operator differential with no exploited impact, or a bounded `$where` DoS — real but limited; report honestly with the demonstrated impact.

---

## Level 9 — Validity, severity, defense

**Q91. What separates a real NoSQLi from a lead?** A **controlled, repeatable change in query behavior**: login without a password, data you shouldn't see, a secret you extracted, or JS you executed. A lone error or single odd response is a lead, not a finding.

**Q92. What CVSS fits an unauth auth-bypass?** ~`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` ≈ 9.1 (Critical). Adjust I/A for what the account can do; blind read-only extraction may be `C:H/I:N`.

**Q93. Top false positives to auto-reject?** Lone 500 from `[$ne]`; `$regex=.*` on an endpoint that returns all by default; a single timing blip; reflected operator with no query effect; "it's MongoDB" with no injecting param.

**Q94. What's the core remediation?** **Type-check/cast** query inputs to expected primitives before querying (reject objects/arrays); use `$eq`/parameterization; recursively strip operator keys; compare passwords in app code, not in the query.

**Q95. How do you fix `$where`/JS risk?** Disable server-side JavaScript (`javascriptEnabled:false`/`--noscripting`); never build `$where`/`mapReduce`/`$function` from user input.

**Q96. How do you harden each datastore?** ES: disable dynamic scripting, require auth. Redis: require auth, bind to localhost, `rename-command` for CONFIG/EVAL/MODULE. Neo4j: restrict `apoc`/`LOAD CSV`, least-priv. CouchDB: patch (CVE-2017-12635), admin party off. Firebase: strict security rules.

**Q97. Does input allow-listing help?** Yes — constrain fields to expected types/values (e.g., username `^[a-zA-Z0-9_]+$`), reject unexpected keys, and schema-validate JSON bodies. Defense in depth with sanitizers.

**Q98. Why isn't `express-mongo-sanitize` a complete fix?** It strips `$`/`.` keys but can miss nested/reconstructed keys and doesn't address `$where` JS or string-concat injection. Combine with type-checking and disabled scripting.

**Q99. What should the SAFE-PoC always include and avoid?** Include: control vs injected requests, a minimal proof (login as test account / extracted-own-secret redacted / one benign command). Avoid: dumping real users, unbounded loops/DoS, prod writes, persistence.

**Q100. One thing to remember about NoSQLi?** *A field that should be a string must never be allowed to become an object.* Every classic NoSQLi is the app trusting attacker-supplied **structure** where it expected a **value** — send an operator, and the query does your bidding. **Report the auth bypass / the extracted secret / the executed code — not the operator.**

---

## Defense quick-reference
- **Type-check/cast** all query inputs to string/number; reject objects & arrays.
- Use **`$eq`** / parameterized queries; never pass raw `req.body`/`req.query` into `find()`.
- **Recursively strip** operator keys (`$…`, `…​.…`); schema-validate JSON.
- **Disable server-side JS** (`javascriptEnabled:false`); no `$where`/`mapReduce`/`$function` on user input.
- Compare passwords in **application code**, not inside the query.
- Per-store hardening: ES scripting off + auth; Redis auth + `rename-command`; Neo4j restrict `apoc`/`LOAD CSV`; CouchDB patched; Firebase strict rules.
- Least-privilege DB accounts; network-isolate the datastore; monitor for operator-shaped inputs.
