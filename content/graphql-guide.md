# GraphQL Security — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** GraphQL APIs (Apollo, graphql-js/Express, Hasura, Yoga, Graphene/Python, gqlgen/Go, Ruby graphql, HotChocolate/.NET, AWS AppSync) — queries, mutations, subscriptions, batching, introspection, resolvers behind them
**Platforms:** Burp Suite + InQL; `graphql-cop`, `clairvoyance`, `graphw00f`, `batchql`; Altair/GraphQL Voyager; Kali/Windows
**Companion files in this folder:**
- `GRAPHQL_ARSENAL.md` — copy-paste queries/mutations: introspection, node/alias BOLA, batching, DoS, injection probes, CSRF
- `GRAPHQL_CHECKLIST.md` — the per-endpoint testing-order checklist
- `GRAPHQL_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — introspection dumper, alias/node enumerator, batching-brute helper (all benign, rate-limited)
- `GraphQL_Attacks_Zero_to_Expert.md` — Q&A study + field reference

> **This kit lives under `API/` (sibling of `Web/`).** GraphQL isn't a vulnerability class — it's an **API style** that concentrates several classes: **BOLA/IDOR** (object access via `node(id:)`/`*ById`), **BFLA** (unguarded mutations), **info disclosure** (introspection + verbose errors), **DoS** (nested/aliased queries), **injection** (args reaching SQL/NoSQL/OS/SSRF in resolvers), **mass assignment** (input objects), and **auth/rate-limit bypass** (batching). The expert skill is **mapping the schema** (even when introspection is "off"), then **driving each field to impact** — read another user's data, brute past a rate limit with aliases, or reach RCE through a resolver.

---

> ### ⚡ READ THIS FIRST — five truths that make GraphQL testing pay
> 1. **The schema is the map — get it even when introspection is disabled.** Full **introspection** (`__schema`) hands you every type, field, argument, and mutation. If it's off, recover it with **field suggestions** ("Did you mean …"), **clairvoyance** (brute the schema via suggestions), and **graphw00f** (engine fingerprint → known quirks). You almost always can rebuild enough of the schema to attack (§5, §6).
> 2. **Authorization is per-resolver and usually the weak point.** GraphQL centralizes data access; teams enforce authentication at the gateway but forget **object/field-level authorization** in resolvers → **BOLA** on `node(id:)`/`userById` and **BFLA** on `deleteUser`/admin mutations. This is where most GraphQL bounties are (§7, §8).
> 3. **Batching multiplies everything.** Aliases (`a:login(…) b:login(…) …`) and **JSON-array batching** let you send **hundreds of operations in one HTTP request** → brute-force credentials/OTP, **bypass per-request rate limits**, and enumerate objects at scale — often unthrottled and under one log line (§9).
> 4. **One query can be a DoS.** **Deeply nested**/circular relations, **alias overloading**, **field duplication**, and **directive overload** can make a single query do exponential work → resource exhaustion. (Test carefully and *with permission* — measure, don't flood; §10.)
> 5. **Resolvers reach real backends.** A `filter`/`search`/`id`/`url` argument that flows into SQL/Mongo/OS/HTTP is **SQLi/NoSQLi/cmdi/SSRF** with a GraphQL front-door → potential **RCE**. GraphQL is just the delivery mechanism for the classic injections (§11).
>
> **Where the money is (memorize this order):** ① **Injection → RCE/data dump** (arg → SQL/NoSQL/OS/SSRF→cloud) → ② **BOLA/BFLA → cross-user/admin data or account takeover** → ③ **Batching → auth/OTP brute & rate-limit bypass → ATO** → ④ **Mass assignment via input objects → privilege escalation** → ⑤ *then* **info disclosure** (introspection/verbose errors) and **DoS** (scope-permitting) as Medium, and pure "introspection enabled" as Low/Info.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [GraphQL Anatomy & Attack Surface](#2-graphql-anatomy--attack-surface)
3. [Reconnaissance — Find & Fingerprint the Endpoint](#3-reconnaissance--find--fingerprint-the-endpoint)
4. [Schema Mapping — Introspection & Beyond](#4-schema-mapping--introspection--beyond)

**PART II — FINDING & BYPASS (work in this order)**
5. [Introspection On — Full Schema Disclosure](#5-introspection-on--full-schema-disclosure)
6. [Introspection Off — Suggestions & Clairvoyance](#6-introspection-off--suggestions--clairvoyance)
7. [BOLA / IDOR via node & *ById](#7-bola--idor-via-node--byid)
8. [BFLA & Mutation Authorization](#8-bfla--mutation-authorization)
9. [Batching — Brute-Force & Rate-Limit Bypass](#9-batching--brute-force--rate-limit-bypass)
10. [Denial of Service — Nesting, Aliases, Duplication](#10-denial-of-service--nesting-aliases-duplication)
11. [Injection Through Resolvers (SQLi/NoSQLi/cmdi/SSRF)](#11-injection-through-resolvers)

**PART III — VARIANTS & EXPLOITATION BY IMPACT (where the money is)**
12. [Mass Assignment via Input Objects](#12-mass-assignment-via-input-objects)
13. [Information Disclosure & Verbose Errors](#13-information-disclosure--verbose-errors)
14. [CSRF & Method/Content-Type Tricks on GraphQL](#14-csrf--methodcontent-type-tricks-on-graphql)
15. [Authentication & Authorization Bypass](#15-authentication--authorization-bypass)
16. [SSRF / File Read via GraphQL](#16-ssrf--file-read-via-graphql)

**PART IV — VALIDITY, SEVERITY & REPORTING**
17. [The Escalation Mindset](#17-the-escalation-mindset)
18. [The Validity-First Mindset](#18-the-validity-first-mindset)
19. [False Positives — STOP reporting these](#19-false-positives--stop-reporting-these-auto-reject-list)
20. [Severity Calibration](#20-severity-calibration--how-triagers-rate-graphql-bugs)
21. [Impact-Escalation Playbooks — "you found X, now do Y"](#21-impact-escalation-playbooks--you-found-x-now-do-y)
22. [Building a Professional PoC](#22-building-a-professional-poc)
23. [Reporting, CWE/CVSS & De-duplication](#23-reporting-cwecvss--de-duplication)
24. [Automation & Red-Team Notes](#24-automation--red-team-notes)

**Appendices**
- [Appendix A — GraphQL Workflow Cheat Sheet](#appendix-a--graphql-workflow-cheat-sheet)
- [Appendix B — GraphQL Decision Tree](#appendix-b--graphql-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Each phase says *what to do*, *which § for detail*, and the *deliverable*.

```
PHASE 0  RECON & LAB        → find the GraphQL endpoint(s) + fingerprint the engine (§3) ·
                              two accounts for BOLA/BFLA; Burp+InQL ready (§1)
PHASE 1  MAP THE SCHEMA  ★  → introspection ON → dump it (§5); OFF → suggestions/clairvoyance/graphw00f (§6).
                              ← the schema is the map; list every query/mutation/*ById/input.
PHASE 2  FIND & BYPASS      → drive each field:
                              BOLA node/*ById (§7) · BFLA mutations (§8) · batching brute/rate-limit (§9) ·
                              DoS nesting/alias (§10) · injection in args (§11)
PHASE 3  IMPACT  ⭐ (money)  → escalate:
                              mass assignment (§12) · info disclosure (§13) · CSRF (§14) · authn/z bypass (§15) ·
                              SSRF/file read (§16) → RCE / ATO / cross-user / cloud
PHASE 4  VALIDATE → REPORT  → ★ two-account or measured proof (§18) · FP filter (§19) ·
                              severity+CVSS+CWE (§20) · clean PoC query (§22) · dedup (§23)
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon & lab.** Locate the endpoint(s) (`/graphql`, `/api/graphql`, `/v1/graphql`, …) and **fingerprint the engine** (graphw00f) (§3). Register **two accounts** for object/function-level tests; load Burp + InQL (§1). *Deliverable:* endpoint + engine + two sessions.
2. **PHASE 1 — Map the schema ★.** If introspection is on, dump the full schema (§5). If off, recover it via **field suggestions / clairvoyance / graphw00f** (§6). *Deliverable:* a list of every query, mutation, `*ById`/`node` sink, and input type.
3. **PHASE 2 — Find & bypass.** Drive each field to a finding: **BOLA** on object lookups (§7), **BFLA** on mutations (§8), **batching** to brute/bypass rate limits (§9), **DoS** (carefully) (§10), and **injection** in arguments (§11). *Deliverable:* a confirmed vuln per sink.
4. **PHASE 3 — Impact ⭐.** Escalate: **mass assignment** (§12), **info disclosure** (§13), **CSRF** (§14), **authn/authz bypass** (§15), **SSRF/file read → RCE/cloud** (§16). *Deliverable:* a demonstrated high-impact outcome.
5. **PHASE 4 — Validate → report.** Prove it (two-account for BOLA; measured rate-limit-bypass count for batching; OOB for SSRF) (§18), apply the FP filter (§19), set CVSS/CWE (§20), ship a clean PoC query (§22), de-dup (§23). *Deliverable:* the submitted report.

Reference anytime: queries → `GRAPHQL_ARSENAL.md` & `poc/`; checklist → `GRAPHQL_CHECKLIST.md`; playbooks **§21**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

| Tool | Job |
|------|-----|
| **Burp Suite + InQL** (Doyensec) | proxy GraphQL; InQL parses the schema, generates queries, and gives a point-and-click attack surface; integrates with Repeater/Intruder |
| **graphw00f** | **fingerprint the engine** (Apollo/Hasura/graphql-js/Graphene/…) → known quirks, whether introspection/suggestions are likely on |
| **clairvoyance** | recover the schema **when introspection is disabled**, by abusing field **suggestions** |
| **graphql-cop** | fast audit: introspection, suggestions, batching, CSRF, field-duplication DoS, etc. |
| **batchql** | batching/alias attack tester (rate-limit bypass, brute) |
| **CrackQL / graphql-path-enum / nuclei** | CrackQL = alias-batch brute (creds/OTP/coupons); graphql-path-enum = find query paths to reach a target type; nuclei has GraphQL detect/introspection templates |
| **wscat / websocat / Burp WebSockets** | drive `subscription` over WebSocket — handshake, replay frames, CSWSH/auth tests (§15.5) |
| **Altair / GraphiQL / GraphQL Voyager** | run queries (great for **learning** — auto-complete + docs); **Voyager** visualizes the schema graph (spot `node`, relations, cycles for DoS) |
| **Two accounts (A/B) + admin** | BOLA needs A↔B; BFLA needs a privileged baseline (see the IDOR kit) |
| **interactsh** | OOB confirmation for **SSRF**/blind injection via resolvers |

```bash
graphw00f -d -f -t https://target.com/graphql          # detect endpoint + fingerprint engine
python3 -m graphql_cop -t https://target.com/graphql    # quick audit (introspection/batching/CSRF/...)
clairvoyance -o schema.json https://target.com/graphql  # rebuild schema when introspection is OFF
```
> **The cardinal rule of GraphQL testing:** *the schema is the attack surface — map it first.* Everything downstream (BOLA sinks, dangerous mutations, injectable args, input objects) comes from the schema. Spend Phase 1 getting it, by introspection or by suggestion-brute.

> **Windows:** Burp + InQL run natively; the Python CLIs run in WSL or native Python (`pip install graphql-cop clairvoyance graphw00f`). Use two browser profiles for A/B.

---

# 2. GraphQL Anatomy & Attack Surface

## 2.0 GraphQL crash course — READ THIS FIRST if GraphQL is new to you
You don't need to be a GraphQL expert to hack it — but you must be able to **read a query, send one, and read the schema**. Here's the whole foundation in a few minutes.

**(a) The big idea.** Unlike REST (many URLs like `/users/1`, `/orders/5`), GraphQL has **one URL** (usually `POST /graphql`) and a **typed schema**. The client sends a *query* describing **exactly which fields it wants**, and the server returns **exactly that shape** as JSON. Each field is filled in by a server function called a **resolver**.

**(b) What a request actually looks like on the wire.** It's normal HTTP — a POST with a JSON body:
```http
POST /graphql HTTP/2
Host: target.com
Content-Type: application/json

{"query":"{ me { id email } }"}
```
Response:
```json
{ "data": { "me": { "id": "123", "email": "you@test" } } }
```
The JSON body has up to three keys: **`query`** (the GraphQL text), **`variables`** (a JSON object of inputs), and **`operationName`** (which operation to run if you sent several). That's it — to test it you just edit that `query` string in Burp Repeater.

**(c) The three operation types.**
```graphql
query    { order(id: 5) { total } }                  # READ data
mutation { updateEmail(email: "x@test") { id } }     # WRITE / change state
subscription { messageAdded { text } }               # LIVE stream (over WebSocket)
```
- **query** = read (the GET equivalent). **mutation** = write (POST/PUT/DELETE equivalent — this is where state changes, ATO, mass-assignment live). **subscription** = a live feed over a WebSocket (§15.5).

**(d) Query syntax you'll see.**
```graphql
query GetUser($id: ID!) {        # "GetUser" = operation name; $id = a variable of type ID, required (!)
  user(id: $id) {                # user(...) is a FIELD with an ARGUMENT (id)
    name                         # scalar field
    email
    orders {                     # nested OBJECT field → you select sub-fields
      id
      total
    }
  }
}
```
sent with `variables`: `{"id": "123"}`. Key pieces:
- **Arguments** — `field(arg: value)`. These are the inputs that reach resolvers/backends → **injection & IDOR live here** (§7, §11).
- **Aliases** — rename/duplicate a field: `a: user(id:1){email} b: user(id:2){email}` runs `user` twice in one request → the basis of **batching** attacks (§9).
- **Variables** — `$x` placeholders filled by the `variables` JSON; the clean way to send typed/complex payloads (§11.5).
- **Fragments** — reusable field sets: `fragment F on User { id email }` then `...F`.
- **`__typename`** — a meta-field that returns the object's type name; `{__typename}` is the universal "is this GraphQL?" probe.

**(e) Reading the schema (the map you attack).** The schema declares **types** and their **fields**:
```graphql
type Query   { me: User, user(id: ID!): User, orders: [Order!]! }   # entry points for reads
type Mutation{ updateUser(input: UpdateUserInput!): User }          # entry points for writes
type User    { id: ID!, email: String!, role: String, orders: [Order!] }
input UpdateUserInput { email: String, role: String }               # an INPUT object (mutation arg)
```
- **Scalars** = leaf values: `ID`, `String`, `Int`, `Float`, `Boolean` (+ custom). **Object types** (`User`, `Order`) have fields you must select into.
- **`!`** = non-null (required). **`[...]`** = a list.
- **`Query` / `Mutation` / `Subscription`** are the special **root** types — the entry points. Your whole attack surface is "which fields hang off these roots, and are they authorized?"
- **`input` types** are the argument objects for mutations — the home of **mass assignment** (§12): if `UpdateUserInput` accepts `role`, you may be able to set it.

**(f) Send your first query (two ways).**
```bash
# curl:
curl -s https://target.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{ __typename }"}'                       # → {"data":{"__typename":"Query"}}
curl -s https://target.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"query($id:ID!){ user(id:$id){ email } }","variables":{"id":"123"}}'
```
In **Burp**: send the POST to **Repeater** and just edit the `query` string. Use **GraphiQL/Playground** (if exposed) or **Altair** as an interactive editor with auto-complete, and **InQL** (Burp) / **GraphQL Voyager** to *see* the schema as a clickable map.

**(g) Why this matters for hacking.** Everything in this guide is: **get the schema → list the fields hanging off Query/Mutation → ask "is each one authorized, and do its arguments reach a backend?"** The schema *is* the attack surface. If GraphQL still feels fuzzy, also read the Q&A's beginner primer.

## 2.1 The model in one paragraph
GraphQL exposes a **single endpoint** (usually `POST /graphql`) and a **typed schema**: **Query** (reads), **Mutation** (writes), **Subscription** (live). The client asks for exactly the fields it wants; **resolvers** fetch each field from the backend. Because access is **field/resolver-shaped** and centralized, a missing authorization check in one resolver exposes that object/field to everyone who can name it.

## 2.2 The attack surface (each → a section)
- **Introspection / suggestions** → schema disclosure (the map) — §5/§6
- **`node(id:)` / `*ById` / `*ByEmail`** → BOLA/IDOR — §7
- **Mutations** (`updateUser`, `deleteX`, admin ops) → BFLA / write-IDOR / mass assignment — §8/§12
- **Aliases + array batching** → brute-force / rate-limit & OTP bypass — §9
- **Nested/circular/duplicated fields** → DoS — §10
- **Arguments** (`filter`, `id`, `search`, `url`, `orderBy`) → SQLi/NoSQLi/cmdi/SSRF in resolvers — §11/§16
- **Input objects** → mass assignment (set fields you shouldn't) — §12
- **Errors** → info disclosure (stack traces, backend hints) — §13
- **GET / form-urlencoded acceptance** → CSRF — §14
- **Subscriptions over WebSocket** → CSWSH / auth bypass / connection-exhaustion DoS — §15.5
- **`@defer` / `@stream` (and `@skip`/`@include`) directives** → response amplification / DoS — §10.6

## 2.3 The 2026 mental model
- **Authentication ≠ authorization.** Most GraphQL APIs authenticate fine; the bugs are **per-object/per-field authorization** missing in resolvers (BOLA/BFLA).
- **"Introspection disabled" is not protection.** Suggestions + clairvoyance rebuild the schema; the sensitive fields are still reachable if you can name them.
- **Batching breaks rate-limiting assumptions.** Per-HTTP-request limits are meaningless when one request carries 500 operations.
- **GraphQL is a delivery vehicle for classic bugs.** SQLi/SSRF/IDOR all appear here — test arguments and object lookups exactly as you would on REST, plus the GraphQL-specific batching/DoS/schema angles.

---

# 3. Reconnaissance — Find & Fingerprint the Endpoint

**3.1 Find the endpoint(s).** Common paths: `/graphql`, `/graphql/`, `/api/graphql`, `/v1/graphql`, `/v2/graphql`, `/query`, `/gql`, `/graphql/console`, `/playground`, `/graphiql`, `/altair`, `/hasura/v1/graphql`, AppSync `*.appsync-api.*.amazonaws.com/graphql`. Look in JS bundles for `uri:`/`fetch('/graphql')`; check the mobile app's traffic.

**3.2 Confirm it's GraphQL.** A `POST` with `{"query":"{__typename}"}` returning `{"data":{"__typename":"Query"}}` confirms it. A bare `GET /graphql` may show GraphiQL/Playground.

**3.3 Fingerprint the engine (graphw00f).** Apollo, graphql-js (Express/Yoga), Hasura, Graphene (Python), gqlgen (Go), Ruby graphql, HotChocolate (.NET), AppSync — each has **known defaults/quirks** (e.g. does it return field **suggestions**? batch by default? leak errors?). The engine tells you which attacks are likely to land.

**3.4 Note dev consoles.** Exposed **GraphiQL/Playground/Altair** in production is itself a finding (and a free attack console).

> *Deliverable:* endpoint URL(s), engine, whether introspection/suggestions/GET/batching are enabled.

---

# 4. Schema Mapping — Introspection & Beyond

The schema is the map. Get it by the easiest available route, then list the sinks.

**4.1 If introspection is ON** → dump the full schema (§5), render it in **Voyager** to see relations and cycles (DoS candidates), and list: every **query**, every **mutation**, every `*ById`/`node` (BOLA), every **input type** (mass assignment), every arg that smells injectable (`filter`, `where`, `url`, `path`, `id`).

**4.2 If introspection is OFF** → recover it via **suggestions/clairvoyance** (§6) or **graphw00f**-guided known schemas. Even partial recovery (the fields you care about) is enough.

**4.3 Build the "sink list."** From the schema, enumerate: BOLA sinks (object lookups by id), BFLA sinks (mutations, admin ops), injection sinks (args to backends), DoS candidates (self-referential/list relations), and input objects (mass assignment). This drives Part II.

> *Deliverable:* the sink list — your test plan.

---

# PART II — FINDING & BYPASS (work in this order)

# 5. Introspection On — Full Schema Disclosure

**5.1 The introspection query.** `__schema`/`__type` return the entire type system:
```graphql
{ __schema { types { name fields { name args { name type { name } } } }
  queryType { name } mutationType { name } } }
```
(Full query in the arsenal.) Save it; feed to InQL/Voyager.

**5.2 Is introspection-enabled itself a bug?** On its own it's **Low/Info** (info disclosure) on most programs — but it's the **enabler** for everything else, so report it *with* the impactful bug it unlocked, not alone, unless the program explicitly rewards it.

**5.3 What to extract:** sensitive type/field names (PII, internal, `debug`, `admin*`), every `*ById`/`node` (→ §7), every mutation (→ §8), input objects (→ §12), and args that reach backends (→ §11).

# 6. Introspection Off — Suggestions & Clairvoyance

**6.1 Field suggestions ("Did you mean …").** Many engines (esp. graphql-js/Apollo) reply to a misspelled field with `Did you mean "email"?` — leaking real field names. Probe systematically (clairvoyance automates this).

**6.2 clairvoyance.** Brute the schema using suggestions to rebuild types/fields without introspection:
```bash
clairvoyance -o schema.json https://target.com/graphql -w wordlist.txt
```
**6.3 graphw00f-known schemas / docs / JS.** The engine + the app's JS often reveal queries/mutations the client uses; mobile traffic too.

**6.4 Error-driven discovery.** Type errors ("Field 'x' of type 'Y' must have a selection of subfields") leak types; required-argument errors leak arg names.

> **IF** introspection is off **THEN** you can still rebuild enough schema via suggestions/clairvoyance to find the `*ById` and mutation sinks — "introspection disabled" rarely stops the real attack.

# 7. BOLA / IDOR via node & *ById

The #1 GraphQL bug (see the IDOR/BOLA kit for the full authorization methodology). GraphQL just concentrates the sinks.

**7.1 The Relay `node(id:)` interface.** Global ids are usually `base64("Type:pk")`. Decode, iterate, re-encode:
```graphql
{ node(id: "VXNlcjoxMjQ=") { ... on User { id email phone role } } }   # "User:124"
```
**7.2 `*ById` / `*ByEmail` resolvers.** `user(id:124){email}`, `order(id:8001){total,address}`, `invoiceById(id:…)`. Swap **B's** id while authenticated as **A** → if you get B's data, BOLA.

**7.3 Nested object traversal.** Even if `user(id:)` is guarded, a path like `order(id:mine){ customer { email phone } }` may leak another user's data through a relation whose resolver isn't checked.

**7.4 Prove it two-account.** A's session, B's id, B's data returned (exactly the IDOR validity rule — see the IDOR kit §19). Decode/iterate global ids to show scale (politely).

# 8. BFLA & Mutation Authorization

**8.1 Dangerous mutations.** `updateUser(id:<B>, input:{email:…})` (write-IDOR/ATO), `deleteUser`, `setRole`, `makeAdmin`, `impersonate`, `createApiKey`, billing/feature mutations. Run them as a **low-priv** user.

**8.2 The directive gap.** Authorization is often a schema **directive** (`@auth`, `@hasRole`) applied inconsistently — a mutation that forgot the directive is wide open. Test **every** mutation, not just obvious admin ones.

**8.3 Method/version variants.** A mutation blocked on the main endpoint may be reachable on `/v1/graphql`, via persisted-query bypass, or via a differently-authorized gateway. (Use the IDOR bypass toolbox conceptually.)

> BFLA via mutation is usually **High/Critical** — self-promotion, impersonation, deleting/ reading any object. Push to **admin → RCE** (see IDOR §13).

# 9. Batching — Brute-Force & Rate-Limit Bypass

**9.1 Alias-based batching.** One operation type, many aliases in one query → many actions in one HTTP request:
```graphql
mutation { a:login(u:"v",p:"1"){t} b:login(u:"v",p:"2"){t} c:login(u:"v",p:"3"){t} }
```
→ brute passwords/OTP/2FA while sending **one** request → **per-request rate limits are bypassed**.

**9.2 JSON-array batching.** Many engines accept an **array** of operations:
```json
[ {"query":"mutation{login(u:\"v\",p:\"1\"){t}}"}, {"query":"mutation{login(u:\"v\",p:\"2\"){t}}"}, ... ]
```
**9.3 Impact.** Credential/OTP/2FA brute-force at scale, coupon/limit abuse, enumeration — all under one request and often one log entry. Combine with the **race** kit for timing-sensitive limits.

**9.4 Confirm the bypass.** Show that N attempts succeed in one request where the per-request limit is supposedly 1 (or 5). That measured count is the proof.

> **IF** the endpoint accepts aliases or array batching on a sensitive op (login/OTP/reset) → **rate-limit/anti-automation bypass → ATO**. High/Critical.

# 10. Denial of Service — Nesting, Aliases, Duplication

> ⚠️ **Test DoS carefully and only with explicit permission** — measure, don't flood. The goal is to *demonstrate* amplification (response time / complexity), not to take the service down.

**10.1 Deeply nested / circular queries.** If types reference each other (`user → posts → author → posts → …`), a deep query forces exponential resolver work:
```graphql
{ user(id:1){ posts{ author{ posts{ author{ posts{ id } } } } } } }   # keep nesting
```
**10.2 Alias overloading.** Repeat an expensive field hundreds of times via aliases in one query → multiplied work.
**10.3 Field duplication.** Repeat the same field many times (`__typename __typename …`) — some parsers do O(n) work per duplicate.
**10.4 Directive overload.** Pile on directives (`@skip(if:false) @skip(if:false) …`) to stress the parser.
**10.5 Defenses to note (and report if missing):** query **depth/complexity limits**, **cost analysis**, **timeouts**, **introspection-off**, **persisted queries**, batching caps. Missing limits = DoS finding (severity per program; many treat as Low/Medium unless clearly impactful).

**10.6 `@defer` / `@stream` directive amplification (modern).** Newer Apollo/graphql-js builds support **incremental delivery** directives — `@defer` (send a fragment later) and `@stream` (send list items one-by-one). They can be abused to amplify work/connections: repeating `@defer` on many fragments, or `@stream(initialCount: 0)` over a huge list, forces the server to do extra bookkeeping and hold the response open. Also pile on `@skip(if:false)` / `@include(if:true)` / unknown/duplicate directives to stress the validator. **IF** the engine accepts `@defer`/`@stream` and lacks a complexity/timeout cap → report it as a DoS amplification vector (measure, don't flood — §10's warning applies).

**10.7 Introspection / suggestion as a DoS.** A full introspection query is itself heavy; on some engines repeating it (or deeply nested `__type` ofType chains) is an amplifier. Note it only where it materially adds to the depth/complexity story.

# 11. Injection Through Resolvers

GraphQL args flow into backends — test them like any input.

**11.1 SQLi.** An arg used in a SQL query: `users(filter:"' OR '1'='1")`, `orderBy:"id;--"`, error-based/UNION/time-based. **IF** it bites → data dump / auth bypass (chase RCE on stacked queries).
**11.2 NoSQLi.** Mongo-backed resolvers: `user(id:{"$ne":null})`, `filter:{"password":{"$regex":"^a"}}` → auth bypass / extraction. (Type-juggling via JSON variables is the lever.)
**11.3 OS command injection.** Args reaching shell (`export(format:"pdf; id")`, image/convert/ping features) → time-based `; sleep 10` → RCE.
**11.4 SSRF.** Any arg taking a URL/host (`fetchUrl`, `webhook`, `avatarFromUrl`, `importFrom`) → point at interactsh / cloud metadata (§16).
**11.5 Use variables to pass complex/typed payloads** cleanly:
```graphql
query($f:String!){ users(filter:$f){id} }     # variables: {"f":"' OR 1=1-- -"}
```
> Treat every argument as you would a REST parameter — the GraphQL layer doesn't sanitize for the resolver. Injection → **RCE/data dump** is the top GraphQL outcome.

---

# PART III — VARIANTS & EXPLOITATION BY IMPACT (where the money is)

# 12. Mass Assignment via Input Objects

**12.1 Over-permissive input types.** A mutation taking an `input` object may accept fields you shouldn't set:
```graphql
mutation { updateUser(input:{ id: <me>, role:"admin", isAdmin:true, balance:99999, emailVerified:true }) { id role } }
```
**12.2 Discover bindable fields** from the **input type** in the schema (`__type(name:"UpdateUserInput"){inputFields{name}}`) or suggestions. Add `owner_id`/`tenant_id` to cross objects/tenants (→ IDOR §9/§16).
**12.3 Confirm it stuck** by reading the object back. **IF** `role:"admin"` persists → privilege escalation → admin → RCE.

# 13. Information Disclosure & Verbose Errors

**13.1 Verbose errors.** Stack traces, ORM/SQL fragments, file paths, backend versions in `errors[].message`/`extensions` → recon + injection confirmation. Trigger with malformed queries/args.
**13.2 Debug/extensions.** `extensions` with `exception.stacktrace`, tracing, or query plans leak internals.
**13.3 Schema secrets.** Field/type names revealing internal systems, feature flags, PII fields, `admin*` operations.
**13.4 Severity.** Usually Medium when it materially aids exploitation (leaks SQL/paths/PII), Low/Info for bare version banners. Bundle with the bug it enabled.

# 14. CSRF & Method/Content-Type Tricks on GraphQL

**14.1 GET-based GraphQL.** If the endpoint accepts queries (or even mutations) via **GET** (`/graphql?query=mutation{...}`), and auth is cookie-based with no CSRF protection → **CSRF** (state-changing mutation via `<img>`/navigation).
**14.2 `application/x-www-form-urlencoded` / `text/plain`.** If the endpoint accepts a simple content-type (not just `application/json`), a cross-site **auto-submit form** can fire a mutation → CSRF (no preflight). (See the CSRF kit §8/§16.)
**14.3 Confirm validity** like any CSRF: cookie auth, fires in a default browser cross-site (CSRF kit §19).
**14.4 Hardening to note:** mutations should require `application/json` + a CSRF token / custom header; GET should be query-only (or off).

# 15. Authentication & Authorization Bypass

**15.1 Unauthenticated fields.** Some queries/mutations resolve **without auth** (forgotten directive) → data/actions pre-auth. Test the whole schema logged-out.
**15.2 Alias/batch to dodge auth throttles** (§9) and **introspection to find** unguarded ops (§5).
**15.3 Persisted-query / APQ bypass.** Apollo Automatic Persisted Queries can sometimes be abused to skip validation or cache-poison; test hash handling.
**15.4 Directive inconsistency** (§8.2) — the core authz bug; enumerate every field's protection.

**15.5 Subscriptions over WebSocket (CSWSH / auth bypass / DoS).** `subscription` operations run over a **WebSocket** (sub-protocols `graphql-transport-ws` (graphql-ws) or the legacy `graphql-ws` (subscriptions-transport-ws)). It's a frequently-forgotten surface:
- **Auth bypass / weaker auth.** The WS handshake/`connection_init` may **not enforce the same auth** as HTTP queries, or accept the token in the init payload without the per-field directives. Test sensitive `subscription` (and even `query`/`mutation` smuggled over the WS transport) **logged-out** or with a low-priv token.
- **CSWSH (Cross-Site WebSocket Hijacking).** WebSockets are **not protected by CORS** and the browser **auto-sends cookies** on the `ws://`/`wss://` handshake. **IF** the subscription endpoint authenticates **by cookie** and **doesn't check `Origin`** → an attacker page can open the socket in the victim's browser and **receive their live data / act** → CSRF-on-WebSocket. Confirm: replay the handshake with a foreign/again absent `Origin` header; if it still connects authenticated → CSWSH.
- **Connection-exhaustion DoS.** Opening many subscriptions / never acking can exhaust server connections (measure, with permission — §10).
- **How to test:** Burp's **WebSockets history + "Send"** (repeat/replay frames), or a small `wscat`/`websocat` / Python `websockets` client. Send `connection_init` → `subscribe` and tamper the auth/Origin.
```
# graphql-ws handshake (frames):
{"type":"connection_init","payload":{"Authorization":"Bearer <token-or-none>"}}
{"type":"subscribe","id":"1","payload":{"query":"subscription{ messageAdded{ text user{ email } } }"}}
```

# 16. SSRF / File Read via GraphQL

**16.1 URL-taking args.** `mutation{ importFromUrl(url:"http://interactsh"){id} }`, `avatarFromUrl`, `webhook`, `fetch`, `preview(url:)` → point at **interactsh** (confirm OOB), then at **cloud metadata** (`http://169.254.169.254/…`) → creds → cloud account → **RCE** (see the SSRF kit).
**16.2 File/path args.** `file(path:"/etc/passwd")`, `template(name:"../../")` → LFI/traversal via a resolver.
**16.3 Blind confirmation.** Use interactsh/your server for OOB; GraphQL SSRF is often blind (no response body) — confirm by the callback.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 17. The Escalation Mindset

Every GraphQL finding has a "now do Y."
- Introspection on → it's the *enabler*; find the BOLA/BFLA/injection it unlocks.
- `node`/`*ById` returns data → is it **another user's** (two-account)? enumerate at scale (aliases).
- A mutation works → does it accept **input fields** you shouldn't set (mass assignment → admin)?
- A URL arg → **SSRF → metadata → cloud → RCE**.
- Login/OTP mutation → **batch it → rate-limit bypass → ATO**.
- Always ask: *which resolver reaches the most sensitive data or a backend, and is it authorized?*

# 18. The Validity-First Mindset

> **The rule:** prove the *impact*, not the *capability*. Different sub-bugs need different proof:
- **BOLA** → two accounts (A's session, B's id, B's data) — exactly the IDOR proof.
- **BFLA/mass-assign** → low-priv account performing/persisting a privileged change (read it back).
- **Batching/rate-limit bypass** → a **measured count** (N operations succeeded in one request where the limit is 1/5).
- **Injection** → the classic proof (error/UNION/time delta/OOB), reproducible.
- **SSRF** → an **OOB callback** you control (interactsh), or metadata creds.
- **DoS** → a **measured** complexity/latency amplification (with permission) — never a sustained outage.

# 19. False Positives — STOP reporting these (auto-reject list)

| Pattern | Why it's NOT (yet) a valid finding | What to do instead |
|---|---|---|
| **"Introspection is enabled"** alone | Info-only on most programs; not impact | Use it to find a BOLA/BFLA/injection; report that (bundle the disclosure) |
| **`node`/`*ById` returns *your own* data** | No cross-user boundary crossed | Prove with **two accounts** (A reaches B) |
| **A mutation exists** (from the schema) | Existence ≠ exploitability | Actually invoke it as low-priv and show the effect |
| **GET works but auth is a Bearer header** | No CSRF (no auto-sent credential) | Only CSRF if cookie-auth + cross-site fire |
| **"Batching possible"** with no sensitive op | Theoretical | Show rate-limit bypass on login/OTP/limit with a measured count |
| **Deeply nested query "could" DoS** | No measurement / no permission | Measure amplification with permission; don't flood |
| **Verbose error** with no useful content | Low/Info noise | Report only if it leaks SQL/paths/PII that aids exploitation |
| **Self-XSS in GraphiQL** | Dev console, victim must self-inflict | Not a finding |

# 20. Severity Calibration — how triagers rate GraphQL bugs

**CWE:** depends on the sub-bug — **CWE-639/285/863** (BOLA), **CWE-862** (BFLA/missing authz), **CWE-915** (mass assignment), **CWE-89/943** (SQL/NoSQLi), **CWE-77/78** (cmdi), **CWE-918** (SSRF), **CWE-200** (info disclosure), **CWE-352** (CSRF), **CWE-770/400** (resource exhaustion/DoS).

| Scenario | Typical severity | CVSS 3.1 (example) |
|---|---|---|
| **Injection (SQL/cmdi) → RCE / full DB** | **Critical** | `AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H` (~9.x) |
| **SSRF → cloud metadata → creds** | **Critical/High** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **BOLA/BFLA → cross-user / admin / ATO** | **Critical/High** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` |
| **Batching → OTP/credential brute → ATO** | **High** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` |
| **Mass assignment → privilege escalation** | **High** | `…/I:H` |
| **Info disclosure (SQL/paths/PII via errors)** | **Medium** | `…/C:L–H/I:N` |
| **DoS (proven amplification)** | **Medium** | `…/A:H` (scope/permission-dependent) |
| **Introspection enabled / verbose banner only** | **Low/Info** | minimal |

> Severity tracks the **downstream class**, not "it's GraphQL." Lead with the highest proven (RCE/ATO/cross-user), and bundle the enablers (introspection/errors).

# 21. Impact-Escalation Playbooks — "you found X, now do Y"

**21.1 Introspection is enabled.** → Dump schema → list `*ById`/`node` (BOLA), mutations (BFLA), input objects (mass-assign), URL/file args (SSRF), backend-ish args (injection) → go exploit one; report *that* (bundle introspection as the enabler).

**21.2 Introspection is off.** → graphw00f (engine) → clairvoyance/suggestions to rebuild the schema → proceed as 21.1. Don't stop at "introspection disabled."

**21.3 `node(id:)`/`user(id:)` returns data.** → Two-account test (A's session, B's id) → if cross-user, BOLA → alias-batch to enumerate at scale (politely) → check for a **write** mutation on the same object → ATO (IDOR §12).

**21.4 A mutation takes an `input` object.** → Pull `__type(name:"…Input"){inputFields{name}}` → add `role/isAdmin/owner_id/tenant_id/balance` → read back → if it sticks, priv-esc/cross-tenant → admin → RCE.

**21.5 There's a `login`/`verifyOtp` mutation.** → Alias/array-batch many attempts in one request → show the per-request rate-limit is bypassed (measured count) → brute → ATO. Combine with the race kit for timing limits.

**21.6 An arg takes a URL.** → interactsh OOB → cloud metadata → creds → cloud/RCE (SSRF kit). An arg in a filter/order → SQL/NoSQL injection → dump/auth-bypass.

**21.7 GET or form-encoded mutations + cookie auth.** → Build a cross-site CSRF PoC that fires the mutation in a default browser (CSRF kit §16) → chain to a sensitive change.

# 22. Building a Professional PoC

**The non-negotiables:**
1. The **exact query/mutation** (and variables) — copy-paste runnable.
2. The **proof for the sub-bug** (per §18): two-account BOLA evidence, measured batching count, OOB SSRF callback, injection signal, persisted mass-assignment read-back.
3. **Benign markers** — your own accounts/objects, test inboxes, `interactsh` you control; no real-user data, no real DoS.
4. **Reversible** — revert any writes (demote roles, delete created keys/admins).
5. A `curl` a triager can replay.

```bash
# BOLA via node(id) — A's token, B's object:
curl -s https://target.com/graphql -H "Authorization: Bearer <A_TOKEN>" \
  -H 'Content-Type: application/json' \
  -d '{"query":"{ node(i"VXNlcjoxMjQ=\"){ ... on User { id email phone } } }"}'
# Batching rate-limit bypass (one request, many logins):
curl -s https://target.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"mutation{a:login(u:\"v\",p:\"1\"){t} b:login(u:\"v\",p:\"2\"){t} c:login(u:\"v\",p:\"3\"){t}}"}'
```

# 23. Reporting, CWE/CVSS & De-duplication

- **Title** = `<sub-bug> in GraphQL <field/mutation> → <impact>` — e.g. *"BOLA on GraphQL node(id:) → any user's PII (cross-user, enumerable)"*; *"Rate-limit bypass via GraphQL alias batching on login → credential brute-force"*; *"SSRF via importFromUrl mutation → AWS metadata creds."* Never "GraphQL misconfig."
- **Lead with the downstream impact + proof**; bundle introspection/verbose-errors as enablers, not as the headline (unless that's all the program wants).
- **CWE** per sub-bug (§20); CVSS per the highest proven. State scale (single vs batched/enumerated).
- **De-dup:** one strong injection/BOLA/ATO beats a pile of "introspection enabled / batching possible" notes. If the program already lists "introspection on," report your **distinct impactful** bug.

# 24. Automation & Red-Team Notes

**24.1 Coverage.** `graphql-cop` for a fast audit; **InQL** to generate the full query set; **clairvoyance** for schema when introspection's off; **batchql** for batching. Then *manually* drive the sinks — the bugs are in authorization logic that scanners can't judge.

**24.2 Stealth / OPSEC (red-team & program rules).**
- **Batching is quiet but powerful** — one request can carry hundreds of ops; keep counts reasonable and don't actually brute real users (prove the bypass with a measured count).
- **DoS = measure, don't flood.** Demonstrate complexity/latency amplification on a single query with permission; never sustain an outage.
- **Enumeration** (node ids) — small proof set, cite population; don't scrape real PII (IDOR §25).
- **SSRF/injection** — use **your own** OOB host; don't pivot beyond proof; revert any writes.
- **Authorized targets only.**

**24.3 Where GraphQL bugs cluster:** newly-added mutations (forgotten `@auth`), `node`/`*ById` resolvers, URL/file/filter args, login/OTP mutations (batching), and exposed dev consoles (GraphiQL/Playground).

---

# Appendix A — GraphQL Workflow Cheat Sheet

```
0. Find endpoint(s) (/graphql, /api/graphql, /v1/graphql, consoles) + graphw00f the engine.    §3
1. MAP SCHEMA: introspection on → __schema dump; off → clairvoyance/suggestions.               §5,§6
2. Build the SINK LIST: *ById/node (BOLA) · mutations (BFLA) · input objects (mass-assign) ·
   url/file args (SSRF) · filter/id args (injection) · login/otp (batching).                    §4
3. EXPLOIT each: BOLA two-account (§7) · BFLA mutation (§8) · batching brute/rate-limit (§9) ·
   injection in args (§11) · DoS measure-only (§10).
4. ESCALATE: mass assignment→admin (§12) · SSRF→metadata→RCE (§16) · CSRF (§14) · authn/z (§15).
5. VALIDATE per sub-bug (two-account / measured count / OOB / read-back) → FP filter → CVSS+CWE → PoC → dedup.  §18-§23
```

# Appendix B — GraphQL Decision Tree

```
Endpoint confirmed (POST {__typename} → Query)?            NO → keep hunting paths/JS/mobile
            │ YES
Introspection on?  ── YES → dump schema (§5)
                   └─ NO  → graphw00f + clairvoyance/suggestions (§6)  → (still got the sinks)
For each sink:
   ├─ *ById / node ............ two-account test → cross-user? BOLA → enumerate/write → ATO     §7
   ├─ mutation ................ invoke as low-priv → effect? BFLA; input fields you shouldn't? mass-assign §8/§12
   ├─ login/otp ............... alias/array batch → rate-limit bypass (measured) → brute → ATO   §9
   ├─ url/file arg ............ interactsh OOB → SSRF → metadata → cloud/RCE                      §16
   ├─ filter/id/order arg ..... SQLi/NoSQLi/cmdi probes → dump/auth-bypass/RCE                    §11
   └─ errors/GET/CSRF ......... info-disclosure / CSRF (cookie-auth + cross-site)                 §13/§14
Then: severity by DOWNSTREAM class; bundle introspection/errors as enablers; PoC; report.
```

# Appendix C — Important Links
- **OWASP** — *GraphQL Cheat Sheet*; **OWASP API Security Top 10** (BOLA/BFLA/Mass-Assignment apply directly): https://owasp.org/API-Security/
- **PortSwigger** — *GraphQL API vulnerabilities*: https://portswigger.net/web-security/graphql
- **Learn GraphQL (for newcomers)** — `graphql.org/learn` (the official tutorial: queries, mutations, schema, introspection); **PortSwigger GraphQL labs** (hands-on); **DVGA** (Damn Vulnerable GraphQL Application — practice target); try queries live in **Altair/GraphiQL**.
- **Tools** — InQL (Doyensec), graphw00f, clairvoyance, graphql-cop, batchql, **CrackQL** (alias-batch brute), **graphql-path-enum**, **nuclei** (graphql templates), GraphQL Voyager, Altair; WebSocket: wscat/websocat/Burp.
- **graphql.org** — spec (queries/mutations/subscriptions/introspection/`@defer`/`@stream`); **Apollo** docs (APQ/persisted queries, incremental delivery); **graphql-ws** & **subscriptions-transport-ws** (WebSocket sub-protocols, §15.5).
- **CWE** — 639/285/862/915 (authz/mass-assign) · 89/943/77/78 (injection) · 918 (SSRF) · 200 (info) · 352 (CSRF) · 770/400 (DoS) · 1385/CSWSH (WebSocket hijacking).
- **Real cases / patterns** — disclosed GraphQL reports: **BOLA via `node`/`*ById`** (cross-user PII), **batching → 2FA/OTP/credential brute** (rate-limit bypass → ATO), **SSRF via url-taking mutations**, **mass assignment via input objects**, **GitLab** GraphQL access-control issues, exposed **GraphiQL/Playground** in prod. Pattern: *map schema → unauthorized field/arg → BOLA/BFLA/injection/SSRF → ATO/RCE/cross-user.*

> **Authorized testing only.** Two test accounts for BOLA/BFLA, your own OOB host for SSRF, measured counts for batching, measure-don't-flood for DoS, revert writes, small enumeration sets. Report **the downstream impact** (RCE/ATO/cross-user/cloud), with introspection/errors as enablers — not "introspection is enabled."
