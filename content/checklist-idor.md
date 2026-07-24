# IDOR / BOLA — Checklist

Expert per-attack **test-case matrix** for IDOR / BOLA — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*27 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## IDOR-001 — Two accounts + map every object reference
**Test Category:** Recon &amp; Lab · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** path / query / body / JSON / header / cookie / GraphQL / file references

**Test Steps:** 1. Register TWO same-role accounts A (attacker) &amp; B (victim); optionally an admin + a 2nd tenant/org.<br>2. Proxy the app as BOTH A and B through every feature (UI + the API the mobile app calls).<br>3. Map every object reference into a table; pull id-bearing/old /v1/ endpoints from recon (gau/katana/JS), not just the live UI.<br>4. Record per object: reference location, format, and an example reference OWNED BY B.

**Expected Result:** An objects table with each reference's location, format, and a B-owned example.

**Payload Example:**

```
A=<A_TOKEN> B=<B_TOKEN> BID=124 ; /api/orders/{id} ; ?userId= ; X-Account-Id ; node(id:)
```

**Impact:** Old /v1/ and mobile-API references are the most common unguarded IDOR surface.

**Tools:** Burp Suite Pro, gau, katana

**References:** CWE-639; OWASP API Security Top 10: API1 BOLA / API3 BOPLA / API5 BFLA

---

## IDOR-002 — Baseline the object + classify ID format
**Test Category:** Baseline (the oracle) · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Each object, before swapping

**Test Steps:** 1. Capture B's request + B's reference; capture A's own equivalent request.<br>2. Classify the ID format (seq-int / base64 / hex / uuidv1 / uuidv4 / objectid / snowflake / hashids / composite) and DECODE any encoded id.<br>3. Ask: does the server enforce an ownership/role check, or trust the reference?<br>4. Assign a verdict slot: IDOR-READ / IDOR-WRITE / BLOCKED(try bypass) / SAFE(session-scoped).

**Expected Result:** The ID format is classified and the ownership-enforcement question is framed.

**Payload Example:**

```
echo -n MTIz|base64 -d -> 123 ; ObjectId first 8 hex = timestamp ; verdict = BLOCKED(try bypass)
```

**Impact:** Format drives the attack path; the ownership question is the definition of IDOR.

**Tools:** Burp Repeater, base64, jq

**References:** CWE-639; PortSwigger Web Security Academy: Access control vulnerabilities and IDOR

---

## IDOR-003 — Direct reference swap (the core test)
**Test Category:** Find — Direct Swap · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Any client-controlled object reference

**Test Steps:** 1. Put B's reference into A's authenticated request.<br>2. Read the response: 200 + B's data = IDOR-READ confirmed; 403/404 = run the mutation matrix; A's own data = SAFE.<br>3. Two-account diff to confirm fast: A-with-B's-id vs B's own response identical (minus volatile fields) = IDOR.

**Expected Result:** A's request carrying B's reference returns B's data.

**Payload Example:**

```
curl $URL/api/orders/$BID -H "$A"  -> 200 + B's order
```

**Impact:** Cross-user object read - the base IDOR. High (scale/write escalate it).

**Tools:** Burp Repeater, curl, jq

**References:** CWE-639; PortSwigger Web Security Academy: Access control vulnerabilities and IDOR

---

## IDOR-004 — Whole-app access-control sweep (Autorize)
**Test Category:** Find — Coverage · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Every authenticated request across the app

**Test Steps:** 1. In Autorize set the low-priv identity = B's headers; add an unauthenticated identity.<br>2. Browse the whole app AS A; Autorize replays each request as B/unauth.<br>3. 'Bypassed!' = B (or unauth) got A's resource -&gt; IDOR/BOLA; verify each by hand before reporting.

**Expected Result:** Autorize flags requests where the object check is missing across the app.

**Payload Example:**

```
Autorize low-priv = Bearer <B_TOKEN> ; browse as A ; flag 'Bypassed!' rows
```

**Impact:** Systematic coverage finds IDORs the manual per-object loop misses. High.

**Tools:** Burp Autorize, AuthMatrix

**References:** CWE-639; PortSwigger Web Security Academy: Access control vulnerabilities and IDOR

---

## IDOR-005 — Method / verb swap + override
**Test Category:** Bypass Matrix · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Endpoints returning 403/404 on the direct swap

**Test Steps:** 1. Try each verb: GET vs POST/PUT/PATCH/DELETE (a GET may be guarded while PUT is not).<br>2. Method override: X-HTTP-Method-Override: PUT ; ?_method=PUT.<br>3. Re-test the swap under each.

**Expected Result:** A different verb (or override) succeeds where GET was blocked.

**Payload Example:**

```
for M in GET POST PUT PATCH DELETE; do curl -X $M $URL/api/users/$BID -H "$A"; done
```

**Impact:** Restores the cross-user access via an unguarded verb. High.

**Tools:** Burp Repeater

**References:** CWE-639; CWE-285; HackTricks: IDOR

---

## IDOR-006 — Array-wrap + parameter pollution
**Test Category:** Bypass Matrix · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Blocked references accepting arrays or duplicate params

**Test Steps:** 1. Array-wrap: id[]=$BID ; {"id":[$BID]}.<br>2. Parameter pollution: id=$MY_ID&amp;id=$BID (first/last wins); duplicate JSON keys; path-vs-body mismatch.<br>3. Watch which the validator vs the handler reads.

**Expected Result:** The check inspects one value while the handler acts on the victim's.

**Payload Example:**

```
?id=$MY_ID&id=$BID ; {"id":$MY_ID,"id":$BID} ; id[]=$BID
```

**Impact:** Bypasses the ownership check via a parser disagreement. High.

**Tools:** Burp Repeater

**References:** CWE-639; HackTricks: IDOR

---

## IDOR-007 — Type juggling on the reference
**Test Category:** Bypass Matrix · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Blocked references where type coercion is possible

**Test Steps:** 1. Send the id as int / string / array / object: 123 / "123" / [123] / {"$ne":null}.<br>2. A type change can skip a strict-equality ownership check or reach a NoSQL operator.<br>3. Confirm B's data returns.

**Expected Result:** A type variant of the reference bypasses the check.

**Payload Example:**

```
{"id":[$BID]} ; {"id":{"$ne":null}} ; /api/users/"$BID"
```

**Impact:** Bypasses ownership via type coercion; NoSQL operator = broader read. High.

**Tools:** Burp Repeater

**References:** CWE-639; CWE-943; HackTricks: IDOR

---

## IDOR-008 — Path / encoding / extension / version
**Test Category:** Bypass Matrix · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Blocked references with alternate routes

**Test Steps:** 1. Append .json, trailing /, %2e/%-encoding, case variations.<br>2. Old/internal routes: /api/v1/users/$BID, /internal/users/$BID (often unguarded).<br>3. Re-test the swap on each.

**Expected Result:** An alternate path/version serves the victim's object.

**Payload Example:**

```
/api/v1/users/$BID ; /api/users/$BID.json ; /internal/users/$BID
```

**Impact:** Legacy/internal routes lack the check added to the live path. High.

**Tools:** Burp Repeater, ffuf

**References:** CWE-639; HackTricks: IDOR

---

## IDOR-009 — Header / cookie trust
**Test Category:** Bypass Matrix · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Apps trusting an id header/cookie

**Test Steps:** 1. Inject X-User-Id / X-Account-Id / uid cookie = $BID with A's session.<br>2. Internal-trust headers: X-Forwarded-For: 127.0.0.1, X-Original-URL: /admin.<br>3. Confirm the response scopes to B.

**Expected Result:** A trusted header/cookie makes the server serve B's data to A.

**Payload Example:**

```
curl $URL/api/me -H "$A" -H "X-User-Id: $BID" ; Cookie: session=<A>; uid=$BID
```

**Impact:** High-hit-rate cross-user access via header trust. High.

**Tools:** Burp Repeater

**References:** CWE-639; CWE-290; HackTricks: IDOR

---

## IDOR-010 — Wildcard / boundary + 403-vs-404 enumeration oracle
**Test Category:** Bypass Matrix · **Severity:** Medium · **CVSS:** 4.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Blocked references; enumeration surface

**Test Steps:** 1. Boundary values: 0, -1, *, %, all, me, current, null, empty.<br>2. Record the 403-vs-404 (+length+time) oracle regardless - it enables enumeration even when reads are blocked.<br>3. Note any value that widens scope.

**Expected Result:** A boundary value widens scope, or status/length differences form an enumeration oracle.

**Payload Example:**

```
for V in 0 -1 '*' all me current; do curl -w "$V=%{http_code}" $URL/api/users/$V -H "$A"; done
```

**Impact:** Wildcard scope-widening or an existence oracle for enumeration. Medium/High.

**Tools:** Burp Intruder

**References:** CWE-639; HackTricks: IDOR

---

## IDOR-011 — Nested / parent-scoped child swap
**Test Category:** Bypass Matrix · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Endpoints like /users/{me}/cards/{childId}

**Test Steps:** 1. Keep YOUR parent id, swap only the CHILD id: /api/users/$MY_ID/cards/$BID.<br>2. /api/orders/$MY_ORDER/items/$BID ; /api/projects/$MY_PROJ/members/$BID.<br>3. Servers often check only the parent's ownership.

**Expected Result:** The child object of another user is returned under your own parent scope.

**Payload Example:**

```
/api/users/$MY_ID/cards/$BID ; /api/orders/$MY_ORDER/items/$BID
```

**Impact:** Very common: child access via a checked-parent-only path. High.

**Tools:** Burp Repeater

**References:** CWE-639; HackTricks: IDOR

---

## IDOR-012 — Bulk / batch id-mixing
**Test Category:** Bypass Matrix · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Batch/bulk endpoints taking id arrays

**Test Steps:** 1. Mix your id with the victim's in the array/CSV: {"ids":[$MY_ID,$BID]} ; ?ids=$MY_ID,$BID.<br>2. The server checks the first/none but acts on the whole array.<br>3. Confirm B's data in the batch response.

**Expected Result:** The batch returns/acts on the victim's object alongside yours.

**Payload Example:**

```
{"ids":[$MY_ID,$BID]} ; ?ids=$MY_ID,$BID
```

**Impact:** Cross-user read/write hidden in a batch operation. High.

**Tools:** Burp Repeater

**References:** CWE-639; HackTricks: IDOR

---

## IDOR-013 — Predictable / sequential id enumeration
**Test Category:** ID Prediction · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Sequential / gappy integer ids (confirmed cross-user)

**Test Steps:** 1. Increment/decrement confirms cross-user, then SIZE the impact.<br>2. Enumerate a SMALL polite set (your-own + 2nd-account range) at low rate.<br>3. State the POPULATION from the server (X-Total-Count / max id) - don't scrape real PII.

**Expected Result:** A small ranged enumeration proves the pattern; the population is stated, not dumped.

**Payload Example:**

```
ffuf -u $URL/api/users/FUZZ -H "$A" -w <(seq 120 130) -rate 5 -mc 200
```

**Impact:** Read IDOR at MASS scale -&gt; bulk PII exposure. High/Critical (by scale).

**Tools:** ffuf, Burp Intruder

**References:** CWE-639; PortSwigger Web Security Academy: Access control vulnerabilities and IDOR

---

## IDOR-014 — Obfuscated-but-reversible id (Hashids/Sqids/Optimus)
**Test Category:** ID Prediction · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Short alnum ids that drift in order as objects are created

**Test Steps:** 1. Recognise ordered drift (gY6,J4Q,oE2) = reversible.<br>2. Find salt/alphabet (Hashids/Sqids) or PRIME/RAND (Optimus) in the front-end JS bundle (or default).<br>3. Decode -&gt; enumerate: Hashids(salt='SALT').decode('yr8').

**Expected Result:** The encoding is reversed and ids enumerated.

**Payload Example:**

```
grep bundle for 'Hashids'/'salt' ; python3 -c "from hashids import Hashids; Hashids(salt='S').decode('yr8')"
```

**Impact:** 'Obfuscated' ids are not access control - full enumeration. High/Critical.

**Tools:** hashids/sqids libs, JS review

**References:** CWE-639; HackTricks: IDOR

---

## IDOR-015 — Non-sequential id — predict or obtain
**Test Category:** ID Prediction · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** UUIDv1 / Mongo ObjectId / snowflake / UUIDv7 / ULID / UUIDv4

**Test Steps:** 1. Predict: UUIDv1 (time+MAC sandwich), ObjectId (timestamp+counter), snowflake/UUIDv7/ULID (bound to the creation-time window).<br>2. UUIDv4 (random) can't be predicted -&gt; OBTAIN it (list/search/profile/GraphQL/Referer/error message).<br>3. Then swap the obtained/predicted id.

**Expected Result:** A supposedly-random id is predicted or leaked, enabling the swap.

**Payload Example:**

```
ObjectId ts+counter ; UUIDv7 first 48 bits = ms -> set to B's creation window ; leak UUIDv4 via GraphQL
```

**Impact:** Defeats 'unguessable id' as the only control. High.

**Tools:** Burp, custom scripts

**References:** CWE-639; HackTricks: IDOR

---

## IDOR-016 — Mass assignment / BOPLA (owner-field &amp; privilege)
**Test Category:** Mass Assignment · **Severity:** Critical · **CVSS:** 9.6 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Create/update endpoints binding request fields to the model

**Test Steps:** 1. Inject ownership: {"owner_id":$BID} to reassign to victim/tenant.<br>2. Self-promote: {"role":"admin","isAdmin":true,"permissions":["*"]}.<br>3. JSON-Patch / merge-patch is often a SEPARATE, less-guarded code path: [{"op":"replace","path":"/role","value":"admin"}]. Discover field names from GET/GraphQL __type.

**Expected Result:** An unexpected field (owner/role/flag) is bound and changes ownership/privilege.

**Payload Example:**

```
PATCH /api/users/me {"role":"admin","isAdmin":true} ; json-patch /role=admin
```

**Impact:** Privilege escalation / ownership reassignment via mass assignment - Critical.

**Tools:** Burp Repeater

**References:** CWE-639; CWE-915; CWE-566; HackTricks: IDOR

---

## IDOR-017 — BFLA — broken function-level authorization
**Test Category:** BFLA · **Severity:** Critical · **CVSS:** 9.6 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Admin/privileged functions invoked as a normal user

**Test Steps:** 1. Invoke privileged functions as A: create-admin, role change, impersonate, delete, export-all.<br>2. Route/method variants if /admin/ is blocked: /api/v1/admin/users, /admin/api/users.<br>3. Confirm the privileged action executes.

**Expected Result:** A normal user successfully invokes an admin-only function.

**Payload Example:**

```
POST /api/admin/users {"role":"admin"} ; POST /api/users/$BID/impersonate -H "$A"
```

**Impact:** Function-level auth bypass -&gt; admin capability - usually Critical.

**Tools:** Burp Repeater

**References:** CWE-639; CWE-285; OWASP API Security Top 10: API1 BOLA / API3 BOPLA / API5 BFLA

---

## IDOR-018 — Read -&gt; enumerate -&gt; mass PII
**Test Category:** Impact — Mass Read · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Confirmed read IDOR on an enumerable id

**Test Steps:** 1. Prove the pattern on a small set; state the population from X-Total-Count / max id.<br>2. Check if leaked objects contain AUTH MATERIAL (reset token / API key / session) -&gt; pivot to ATO/RCE.<br>3. Do NOT scrape real user PII - a small proof set only.

**Expected Result:** The pattern + stated population demonstrates mass-PII exposure (proof set only).

**Payload Example:**

```
5 ids returned full PII ; X-Total-Count: 8,400,000 ; leaked object contains a reset token
```

**Impact:** Mass PII breach / auth-material leak -&gt; ATO - Critical at scale.

**Tools:** Burp Intruder, jq

**References:** CWE-639; PortSwigger Web Security Academy: Access control vulnerabilities and IDOR

---

## IDOR-019 — Write IDOR -&gt; account takeover
**Test Category:** Impact — Write/ATO · **Severity:** Critical · **CVSS:** 9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Write endpoints accepting B's id under A's creds

**Test Steps:** 1. Change B's recovery email (A's creds, B's id) -&gt; reset -&gt; own the account.<br>2. Direct password/MFA/apikey change on endpoints not requiring the old secret.<br>3. VERIFY on B (re-read as B) - a 200 is NOT proof.

**Expected Result:** B's credential/recovery is changed by A and confirmed by re-reading as B.

**Payload Example:**

```
PUT /api/users/$BID/email {"email":"victim+idor@your-inbox.test"} ; then GET as $B -> changed
```

**Impact:** Account takeover of any user via write IDOR - Critical.

**Tools:** Burp Repeater

**References:** CWE-639; CWE-620; HackTricks: IDOR

---

## IDOR-020 — BFLA -&gt; admin -&gt; RCE chain
**Test Category:** Impact — Escalation · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Self-promotion/admin functions reachable via IDOR/BFLA

**Test Steps:** 1. Self-promote or create an admin, then use admin-only features (upload/SSTI/SSRF/integration) for code exec.<br>2. Chain: IDOR write -&gt; admin -&gt; admin upload -&gt; RCE.<br>3. Benign proof only.

**Expected Result:** An IDOR/BFLA escalates to admin and then to code execution.

**Payload Example:**

```
PATCH /users/me {role:admin} -> admin theme upload -> web shell marker
```

**Impact:** Full application compromise via IDOR-&gt;admin-&gt;RCE - Critical.

**Tools:** Burp, FileUpload/SSTI kits

**References:** CWE-639; HackTricks: IDOR

---

## IDOR-021 — Files / exports / signed URLs
**Test Category:** Impact — Files · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Download/export/signed-URL endpoints

**Test Steps:** 1. Swap filename/key/id: /download?file=invoice_$BID.pdf ; /exports/$BID.csv.<br>2. Signed URL: remove/alter the signature, swap the key, tamper content-disposition; check if the CDN serves without auth.<br>3. Bulk export endpoints multiply impact.

**Expected Result:** Another user's file/export is downloaded via a swapped key/signature.

**Payload Example:**

```
/exports/$BID.csv -H "$A" ; /files?key=uploads/$BID/secret.pdf&X-Amz-Signature=...
```

**Impact:** Cross-user document/export disclosure - High/Critical (bulk export = mass).

**Tools:** Burp Repeater, aws cli

**References:** CWE-639; HackTricks: IDOR

---

## IDOR-022 — GraphQL IDOR / BOLA
**Test Category:** Impact — GraphQL · **Severity:** High · **CVSS:** 7.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** GraphQL node(id:) / *ById / mutations

**Test Steps:** 1. node(id:) - decode/iterate/encode global ids: base64('User:124').<br>2. Alias batching - many objects in one request: {a:user(id:1){email} b:user(id:2){email}}.<br>3. Write via mutation: updateUser(id:$BID,input:{email:...}). Introspect for more sinks.

**Expected Result:** GraphQL returns/changes other users' objects via global ids / aliases / mutations.

**Payload Example:**

```
{ node(id:"VXNlcjoxMjQ="){... on User{email phone}} } ; alias-batched user(id:1..N)
```

**Impact:** Batched cross-user read/write via GraphQL - High/Critical.

**Tools:** Burp, graphql tooling

**References:** CWE-639; OWASP API Security Top 10: API1 BOLA / API3 BOPLA / API5 BFLA

---

## IDOR-023 — Cross-tenant (SaaS) read &amp; write
**Test Category:** Impact — Cross-Tenant · **Severity:** Critical · **CVSS:** 9.6 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Multi-tenant apps (two orgs you own)

**Test Steps:** 1. Authenticated to tenant-1, reach tenant-2's objects: /api/workspaces/&lt;TENANT2&gt;/projects ; X-Tenant-Id: &lt;TENANT2&gt; ; subdomain-routed tenant2.target.com.<br>2. Test both READ and WRITE.<br>3. Confirm with two orgs you own.

**Expected Result:** One tenant's user reads/writes another tenant's data.

**Payload Example:**

```
curl $URL/api/projects/<T2_PROJECT_ID> -H "$A" ; -H "X-Tenant-Id: <TENANT2>"
```

**Impact:** Cross-tenant data breach - Critical in SaaS.

**Tools:** Burp Repeater

**References:** CWE-639; HackTricks: IDOR

---

## IDOR-024 — Blind / second-order IDOR
**Test Category:** Impact — Blind · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Ids consumed by async/webhook/notification sinks

**Test Steps:** 1. An id used later by an async job / webhook / notification.<br>2. Set it to B's object; confirm the effect via B or an OOB callback.<br>3. Not visible in the immediate response.

**Expected Result:** A reference consumed out-of-band affects the victim's object.

**Payload Example:**

```
set notification target_id=$BID ; confirm B receives it / OOB fires
```

**Impact:** Second-order cross-user impact - Medium/High (easily missed).

**Tools:** Burp Collaborator

**References:** CWE-639; HackTricks: IDOR

---

## IDOR-025 — False-positive filter — two-account proof
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: one-account 'proof'; public data; your-own-data; a 403 with no working bypass; anything requiring the victim's token.<br>2. REQUIRE the TWO-ACCOUNT PROOF: A's credentials + B's reference -&gt; B's data returned OR B's object verifiably changed (re-read as B).<br>3. State scale and who the victim can be.

**Expected Result:** Only findings with a clean two-account proof survive.

**Payload Example:**

```
one-account = FP ; public data = FP ; 200-but-not-verified-on-B = not proof
```

**Impact:** Protects credibility; IDOR is dense with one-account / own-data false positives.

**Tools:** manual

**References:** CWE-639; PortSwigger Web Security Academy: Access control vulnerabilities and IDOR

---

## IDOR-026 — Client-facing impact &amp; reversible PoC
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Title names object + reference + impact ('Read/change any user's &lt;object&gt; via /api/orders/{id}').<br>2. Provide A's request (show the header), B's reference (show the id), and B's data returned / B's object re-read as B; state scale (single/mass/ATO/BFLA/cross-tenant).<br>3. Set CVSS 3.1 + CWE-639 (+285/863/566/915). Remediation: enforce per-object ownership/role checks server-side on EVERY request, use unpredictable + access-checked references, deny-by-default, avoid trusting client ids/headers.<br>4. Both accounts yours, small proof set, writes reverted, no real-user PII; de-dupe.

**Expected Result:** A reproducible, correctly-rated, safe two-account PoC with clear remediation.

**Payload Example:**

```
PoC: A's request + B's id + B's data/changed-object + scale + CVSS + CWE-639 + remediation.
```

**Impact:** Converts the two-account proof into a defensible High/Critical report at the right scale.

**Tools:** CVSS calculator, IDOR_REPORT_TEMPLATE.md

**References:** CWE-639; CWE-285; CWE-863; FIRST CVSS v3.1; OWASP API Security Top 10: API1 BOLA / API3 BOPLA / API5 BFLA  |  TOP REFERENCES: PortSwigger Academy Access Control; OWASP API Security Top 10 (BOLA/BFLA); HackTricks; disclosed HackerOne IDOR writeups

---

## IDOR-027 — Fail-open authorization (force the authz check to error -&gt; default allow)
**Test Category:** Impact — Escalation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Authorization component under abnormal input (A10:2025 / CWE-636)

**Test Steps:** 1. Identify the endpoint's authorization decision point<br>2. Force the authz component to ERROR: malformed token/claim, missing tenant header, oversized/duplicate params, dependency (authz service) made to time out<br>3. Observe whether the request defaults to ALLOW (fail-open) or DENY (fail-closed)<br>4. Prove access to another user's object while the check is degraded

**Expected Result:** Authorization fails CLOSED (default-deny) on any error; no allow-on-exception path

**Payload Example:**

```
Remove X-Tenant-Id header  |  send malformed JWT so the authz service throws  |  duplicate role param
```

**Impact:** Fail-open authz -&gt; access-control bypass when the check errors (A10:2025 -&gt; A01 impact)

**Tools:** Burp Suite, authz_diff

**References:** CWE-636; CWE-285; -&gt;[IDOR / BOLA checklist](#/checklist/idor); OWASP Top 10:2025 A10 (Mishandling of Exceptional Conditions); OWASP A01

---
