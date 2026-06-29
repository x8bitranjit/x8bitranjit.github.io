# GraphQL Security — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **attacking GraphQL APIs**: from "what is GraphQL" to schema recovery without introspection, BOLA via `node(id:)`, batching-driven rate-limit/OTP bypass, DoS, resolver injection (SQLi/NoSQLi/cmdi/SSRF), mass assignment, CSRF, and the chains they unlock (RCE / ATO / cloud / cross-user). Q&A format, progressive difficulty, written as **"IF this → THEN that"** decision logic. Tooling, methodology, real cases, **and** defense.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, and learning. Prove BOLA with **two accounts you own**; use **your own** OOB host for SSRF; measure batching/DoS (don't brute real users or flood the service).

**Canonical references** (real, read them):
- OWASP — *GraphQL Cheat Sheet*; OWASP **API Security Top 10** (BOLA/BFLA/Mass-Assignment apply)
- PortSwigger Web Security Academy — *GraphQL API vulnerabilities* (+ labs)
- Tools — **InQL** (Doyensec), **graphw00f**, **clairvoyance**, **graphql-cop**, **batchql**, GraphQL Voyager
- graphql.org spec; Apollo docs (APQ/persisted queries); CWE-639/285/862/915/89/943/918/352/770

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q12)
- **Level 1 — Recon, fingerprinting & schema mapping** (Q13–Q26)
- **Level 2 — BOLA / IDOR & BFLA in GraphQL** (Q27–Q40)
- **Level 3 — Batching: brute-force & rate-limit bypass** (Q41–Q50)
- **Level 4 — DoS: nesting, aliases, duplication** (Q51–Q58)
- **Level 5 — Injection through resolvers (SQLi/NoSQLi/cmdi/SSRF)** (Q59–Q72)
- **Level 6 — Mass assignment, CSRF, authn/z bypass & expert chains** (Q73–Q86)
- **Tooling** (Q87–Q91)
- **Methodology & decision tree** (Q92–Q95)
- **Severity, validity & false positives** (Q96–Q102)
- **Real-world cases & references** (Q103–Q107)
- **Defense — how to secure GraphQL** (Q108–Q113)
- **Appendix — 60-second field checklist**

---

# BEGINNER PRIMER — read this first if GraphQL is new to you
*(Plain-English basics so the attack levels make sense. Full walkthrough: guide §2.0.)*

### P1. In one picture, how is GraphQL different from REST?
REST has **many URLs** (`GET /users/1`, `GET /orders/5`). GraphQL has **one URL** (`POST /graphql`) and you send a **query** that lists **exactly the fields you want**; the server returns that exact shape as JSON. So instead of guessing URLs, you read one **schema** and ask for fields.

### P2. What does a request literally look like?
A normal HTTP POST with a JSON body: `{"query":"{ me { id email } }"}` and `Content-Type: application/json`. The body can have three keys: **`query`** (the GraphQL text), **`variables`** (JSON inputs), **`operationName`** (which op to run). To test, you just edit the `query` string in Burp Repeater.

### P3. What's a query vs a mutation vs a subscription?
`query { ... }` **reads** data (like GET). `mutation { ... }` **changes** state (like POST/PUT/DELETE — where ATO/mass-assignment live). `subscription { ... }` is a **live feed over a WebSocket** (Q-addendum / guide §15.5).

### P4. How do I read a query?
```graphql
query($id: ID!) {        # $id is a variable of type ID, required (the !)
  user(id: $id) {        # "user" is a field; "(id: $id)" is an argument
    name                 # a scalar field (leaf value)
    orders { id total }  # a nested object → you select its sub-fields
  }
}
```
**Arguments** (`field(arg: val)`) are inputs that reach resolvers/backends → that's where **IDOR & injection** live. `a:user(...) b:user(...)` are **aliases** → the basis of **batching** attacks.

### P5. What's a schema, in beginner terms?
A list of **types** and their **fields**. `type Query { me: User, user(id: ID!): User }` and `type Mutation { updateUser(input: UpdateUserInput!): User }` are the **entry points** (roots). `type User { id: ID!, email: String!, role: String }` is an object you can select into. `input UpdateUserInput { email, role }` is a **mutation argument object** — the home of **mass assignment**. Scalars are leaf values (`ID/String/Int/Boolean`); `!` = required; `[...]` = a list.

### P6. What's a resolver / `__typename` / a fragment / a variable?
**Resolver** = the server function that fills one field from the backend (the place authorization is often forgotten). **`__typename`** = a meta-field returning the type name; `{__typename}` is the "is this GraphQL?" probe. **Fragment** = a reusable set of fields. **Variable** = a `$x` placeholder filled by the `variables` JSON (the clean way to send complex/typed payloads).

### P7. How do I just *try* GraphQL hands-on?
Open **GraphiQL/Playground** (if exposed) or **Altair** — they auto-complete fields and show the docs/schema. Or `graphql.org/learn` and the PortSwigger GraphQL labs / DVGA (a deliberately-vulnerable app). Then come back to Level 0.

### P8. What's the one-sentence hacking mindset?
**Get the schema → list every field hanging off Query/Mutation/Subscription → for each, ask "is it authorized, and do its arguments reach a backend?"** The schema *is* the attack surface.

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is GraphQL in one sentence?
A query language and runtime for APIs that exposes a **single endpoint** and a **typed schema**, letting clients request exactly the fields they want; each field is fetched by a server-side **resolver**.

### Q2. Why is GraphQL a security topic if it's "just an API style"?
Because it **concentrates** several vuln classes at one endpoint: BOLA/IDOR, BFLA, info disclosure, DoS, injection, mass assignment, and rate-limit bypass. The single-endpoint, field-shaped, resolver-backed design changes *how* you find and exploit them.

### Q3. Query vs Mutation vs Subscription?
**Query** = reads, **Mutation** = writes/state-changes, **Subscription** = real-time streams (WebSocket). Mutations are the BFLA/write-IDOR/mass-assignment surface; queries are the BOLA/info surface.

### Q4. What is introspection?
A built-in query (`__schema`/`__type`) that returns the entire type system — every type, field, argument, mutation, input object. It's the **map**; attackers love it, so it's often disabled in production.

### Q5. If introspection is disabled, am I stuck?
**No.** Recover the schema via **field suggestions** ("Did you mean …"), **clairvoyance** (brute the schema using suggestions), **graphw00f** (engine fingerprint → known schema/quirks), and JS/mobile traffic. "Introspection off" rarely stops the real attack.

### Q6. What's the #1 GraphQL bug class?
**BOLA / IDOR** — object access via `node(id:)`/`*ById` resolvers that don't check ownership. Authorization is per-resolver and frequently forgotten.

### Q7. What makes batching dangerous?
Aliases and JSON-array batching let **one HTTP request carry many operations** → brute-force/enumerate at scale and **bypass per-request rate limits** (login/OTP), often under one log line.

### Q8. Is "introspection enabled" a vulnerability by itself?
On most programs it's **Low/Info** — an *enabler*, not impact. Report it bundled with the impactful bug it unlocked (BOLA/injection/etc.), unless the program explicitly rewards it.

### Q9. Where does authorization usually fail in GraphQL?
Per-**object** (BOLA) and per-**function** (BFLA) checks missing in resolvers, often because an `@auth`/`@hasRole` **directive** was applied inconsistently across fields/mutations.

### Q10. Can classic injections happen in GraphQL?
Yes — GraphQL is a **delivery vehicle**. Arguments flow into resolvers that hit SQL/NoSQL/OS/HTTP, so SQLi/NoSQLi/cmdi/SSRF all appear; the GraphQL layer doesn't sanitize for the backend.

### Q11. What's the real-world impact range?
Low (introspection/verbose error) → Critical: injection → **RCE**/DB dump, SSRF → **cloud creds**, BOLA/BFLA → **cross-user/admin/ATO**, batching → **credential/OTP brute → ATO**, mass assignment → **privilege escalation**.

### Q12. What's the attacker mindset for GraphQL?
*"Map the schema, list every sink (node/*ById, mutations, input objects, URL/filter args), and drive each to impact — is this resolver authorized, and does this argument reach a backend?"*

---

# LEVEL 1 — RECON, FINGERPRINTING & SCHEMA MAPPING

### Q13. How do I find the GraphQL endpoint?
Common paths: `/graphql`, `/api/graphql`, `/v1/graphql`, `/v2/graphql`, `/query`, `/gql`, `/graphql/console`, `/graphiql`, `/playground`, `/altair`, Hasura `/hasura/v1/graphql`, AppSync `*.appsync-api.*.amazonaws.com/graphql`. Grep JS bundles for `/graphql`/`uri:`; check mobile traffic.

### Q14. How do I confirm it's GraphQL?
`POST {"query":"{__typename}"}` → `{"data":{"__typename":"Query"}}`. A bare `GET /graphql` may render GraphiQL/Playground.

### Q15. Why fingerprint the engine?
Each engine (Apollo, graphql-js, Hasura, Graphene, gqlgen, Ruby, HotChocolate, AppSync) has **known defaults/quirks** — does it return suggestions? batch by default? leak errors? `graphw00f` tells you which attacks are likely to land.

### Q16. Is an exposed GraphiQL/Playground a finding?
Yes — exposed dev consoles in production are reportable (info disclosure + a free attack console), though usually Low/Medium on their own.

### Q17. How do I dump the schema when introspection is on?
Run the full introspection query (`__schema { types { ...FullType } }`). Save it; load into InQL/Voyager to see every query/mutation/type/relation.

### Q18. How do field suggestions leak the schema?
Misspell a field; engines like graphql-js/Apollo reply `Did you mean "email"?`, leaking real names. Systematic probing (clairvoyance) rebuilds types/fields.

### Q19. What is clairvoyance?
A tool that brute-forces the schema using **suggestions** when introspection is disabled: `clairvoyance -o schema.json <url> -w wordlist`. It reconstructs enough to find the sinks.

### Q20. What can error messages leak?
Type errors ("must have a selection of subfields") leak **types**; required-arg errors leak **argument names**; verbose stack traces leak SQL/paths/versions. All aid mapping and injection.

### Q21. After mapping, what's the "sink list"?
BOLA sinks (`node`/`*ById`), BFLA sinks (mutations/admin ops), injection sinks (args to backends), DoS candidates (self-referential/list relations), and input objects (mass assignment). It's your test plan.

### Q22. How do I spot DoS candidates from the schema?
Render it in **Voyager**; look for **cycles** (type A → B → A) and **list relations** — deep/nested traversals there force exponential resolver work.

### Q23. How do I spot injection candidates from the schema?
Arguments named `filter`, `where`, `query`, `search`, `orderBy`, `id`, plus URL/file args (`url`, `path`, `template`). These reach backends.

### Q24. How do I spot mass-assignment candidates?
**Input object types** on mutations (`UpdateUserInput`); list their `inputFields` (`__type(name:"…Input"){inputFields{name}}`) and look for `role`/`isAdmin`/`owner_id`/`balance`.

### Q25. Should I test logged-out too?
Yes — some queries/mutations resolve **without auth** (forgotten directive). Run the schema's sensitive ops unauthenticated to find pre-auth access (Q83).

### Q26. Persisted queries / APQ — what are they?
Apollo Automatic Persisted Queries send a hash instead of the full query. Test hash handling for validation bypass/cache poisoning, and whether arbitrary queries can still be sent.

---

# LEVEL 2 — BOLA / IDOR & BFLA IN GRAPHQL

### Q27. What's a GraphQL global id and why care?
Relay global ids are usually `base64("Type:pk")` (e.g. `VXNlcjoxMjQ=` = `User:124`). Decode, iterate the pk, re-encode → enumerate objects via `node(id:)` (BOLA).

### Q28. How do I exploit `node(id:)` BOLA?
`{ node(id:"VXNlcjoxMjQ="){ ... on User { email phone } } }` with **A's** token and **B's** id. **IF** B's data returns → BOLA. (Full authorization method: the IDOR/BOLA kit.)

### Q29. What about `*ById` / `*ByEmail` resolvers?
`user(id:124){email}`, `order(id:8001){total}`, `invoiceById(...)` — the same BOLA. Swap B's id while authenticated as A.

### Q30. Can BOLA hide in nested fields even if the top lookup is guarded?
Yes — `order(id:mine){ customer { email phone } }` may leak another user's data through a **relation** whose resolver isn't checked. Test nested traversals.

### Q31. How do I prove a GraphQL BOLA validly?
**Two accounts**: A's session, B's id, B's data returned (the IDOR validity rule). One account proves nothing.

### Q32. How do I show BOLA scale without scraping?
Use **aliases** to fetch many objects in one request (`a:user(id:1) b:user(id:2)…`) over a small range, then cite the population from a list/total. Don't dump real PII.

### Q33. What is BFLA in GraphQL?
Function-level: a low-priv user invoking privileged **mutations** (`deleteUser`, `setRole`, `makeAdmin`, `impersonate`, `createApiKey`) — often unguarded due to a missing directive.

### Q34. How do I test BFLA?
Invoke the sensitive mutation as **account A** (low-priv). **IF** it succeeds (or persists) → BFLA. If you have an admin account, capture its mutation and replay with A's token.

### Q35. What's the "directive gap"?
Authorization implemented as a schema directive (`@auth`, `@hasRole`) that's applied to *most* fields but **forgotten on some**. Enumerate every field/mutation's protection — the gap is the bug.

### Q36. Write-IDOR via mutation → what's the chain?
`updateUser(id:<B>, input:{email:"attacker@…"})` → change B's email → password reset → **ATO** (IDOR §12). Confirm the change as B.

### Q37. Can BOLA/BFLA reach RCE?
Via privilege escalation: BFLA/mass-assign → admin → admin upload/SSTI/SSRF/integration → **RCE** (IDOR §13). Always push admin → RCE.

### Q38. Does a UUID/opaque global id stop BOLA?
No — it's still BOLA if you can **obtain** the victim's id (leaked in list/search/other responses) and the resolver doesn't check ownership (IDOR §7.4).

### Q39. How do I find ids to test with?
List queries (`{ users { id } }`), search/autocomplete, your own objects (decode the pattern), error messages, and other responses. GraphQL often over-returns ids.

### Q40. What CWE for GraphQL BOLA/BFLA?
BOLA → CWE-639/285/863; BFLA → CWE-862 (missing authorization). Severity High/Critical when cross-user/admin/ATO.

---

# LEVEL 3 — BATCHING: BRUTE-FORCE & RATE-LIMIT BYPASS

### Q41. What is alias-based batching?
Multiple operations of the same type in one query via aliases: `mutation{ a:login(...) b:login(...) c:login(...) }`. One HTTP request = many operations.

### Q42. What is array batching?
Many engines accept a **JSON array** of operations: `[{"query":"..."},{"query":"..."}]`. Same effect — many ops, one request.

### Q43. Why does batching bypass rate limits?
Rate limiters that count **HTTP requests** see one request, but the server processes N operations → the per-request limit (login/OTP attempts) is defeated.

### Q44. How do I brute OTP/2FA with batching?
Alias many `verifyOtp(code:"0001")…(code:"9999")` in one request. **IF** the limiter is per-request → effectively unlimited guesses → brute the code → **ATO**.

### Q45. How do I prove the bypass without brute-forcing a real user?
Show a **measured count**: N operations processed in **one** request where the documented per-request limit is 1/5. The count is the proof; you don't need to crack a real account.

### Q46. Which operations are worth batching?
Anything **limited/sensitive**: login, OTP/2FA verify, password-reset submit, coupon apply, vote/like, invite — wherever a per-request limit is the only protection.

### Q47. Does batching combine with race conditions?
Yes — batching defeats per-request limits; **single-packet races** (race kit) defeat check-then-act atomicity. Combine for timing-sensitive limits (e.g. simultaneous redemptions).

### Q48. How do I test if batching is enabled?
Send an aliased query of `__typename` × N (or an array) and count processed ops. `batchql`/`graphql-cop` automate this; `poc/batch_ratelimit_test.py` measures it benignly.

### Q49. What's the defense (so I can confirm it's missing)?
Cap alias count / array size, rate-limit **per operation** (not per request), and add anti-automation on login/OTP. Missing = the finding.

### Q50. Severity for a batching bypass?
High when it reaches credential/OTP brute → ATO (CWE-770/799 + the auth outcome). Medium for limit/abuse without ATO.

---

# LEVEL 4 — DoS: NESTING, ALIASES, DUPLICATION

### Q51. ⚠️ How do I test GraphQL DoS responsibly?
**Measure, don't flood.** Demonstrate **amplification** (a single query's complexity/latency, or that no depth/cost limit exists) — never sustain an outage. Only with explicit permission/scope.

### Q52. What is a deeply nested / circular query attack?
If types reference each other (`user → posts → author → posts → …`), a deeply nested query forces exponential resolver work from **one** request.

### Q53. What is alias overloading?
Repeating an expensive field hundreds of times via aliases in one query multiplies the work (and response size).

### Q54. What is field duplication?
Repeating the same field many times (`__typename __typename …`); some parsers do O(n) work per duplicate.

### Q55. What is directive overload?
Piling on directives (`@skip(if:false) @skip(if:false) …`) to stress the parser/validator.

### Q56. What's the underlying defense GraphQL DoS exploits the absence of?
**Query depth limits, complexity/cost analysis, timeouts, and batching caps.** Their absence is the reportable issue.

### Q57. How do I demonstrate impact safely?
Show a single crafted query's response time/complexity rejection vs a normal query (a measured delta), or that the server accepts arbitrarily deep/aliased queries. Stop at proof.

### Q58. Severity for GraphQL DoS?
Usually Medium (CWE-770/400) unless you can show clear availability impact; many programs treat unbounded-query DoS as Medium/Low. Always within scope/permission.

---

# LEVEL 5 — INJECTION THROUGH RESOLVERS

### Q59. Why do injections appear in GraphQL?
Arguments flow into resolvers that build SQL/NoSQL queries, run OS commands, or make HTTP calls. The GraphQL layer validates *types*, not *backend safety*.

### Q60. How do I test SQLi in a GraphQL arg?
Put SQLi payloads in args (`users(filter:"' OR 1=1-- -")`, `orderBy:"id;--"`); use **variables** for clean payloads. Look for error-based/UNION/time-based signals. → data dump/auth bypass; chase RCE on stacked queries.

### Q61. How do I test NoSQLi (Mongo)?
Pass operator objects via typed variables: `user(id:{"$ne":null})`, `filter:{"password":{"$regex":"^a"}}`. Auth bypass / extraction. Type juggling through JSON variables is the lever.

### Q62. How do I test command injection?
Args reaching shell (export/convert/ping/image): `export(format:"pdf; sleep 10")` → time-based confirmation → **RCE**.

### Q63. How do I pass complex payloads cleanly?
**Variables**: `query($f:String!){users(filter:$f){id}}` with `{"f":"' OR 1=1-- -"}`. Avoids escaping issues and works with typed args.

### Q64. What is SSRF via GraphQL?
Any arg taking a URL/host (`importFromUrl`, `webhook`, `avatarFromUrl`, `fetch`, `preview`) → point at interactsh (OOB) then **cloud metadata** (`169.254.169.254`) → creds → cloud/RCE (SSRF kit).

### Q65. GraphQL SSRF is often blind — how do I confirm?
Use **interactsh/your server** for the OOB callback; the response body may be empty, but the callback proves the server-side request fired.

### Q66. Can GraphQL args cause LFI/file read?
Yes — `file(path:"/etc/passwd")`, `template(name:"../../")` → traversal/LFI via a resolver.

### Q67. How do I confirm an injection isn't a false positive?
Reproducible signal: a consistent **time delay** (time-based), a **UNION**/error leak, or an **OOB** callback you control. A one-off error isn't proof.

### Q68. What's the highest-impact GraphQL injection outcome?
SQLi/cmdi → **RCE / full DB**, or SSRF → **cloud metadata creds → cloud account → RCE**. Critical.

### Q69. Do GraphQL args bypass WAFs?
Sometimes — payloads inside JSON variables / nested query strings can evade signature WAFs tuned for query-string params. Don't rely on it, but it's worth trying variable-encoded payloads.

### Q70. Where are injectable args most common?
Search/filter/report/export endpoints, `orderBy`/`sort`, raw `where` passthroughs (Hasura-style), and URL args on import/webhook/avatar mutations.

### Q71. How do I combine injection with the schema map?
From introspection/clairvoyance, list every arg of type String/JSON on data/IO fields → fuzz those with SQL/NoSQL/cmd/SSRF probes. `introspect.py` flags URL/filter args.

### Q72. CWE for GraphQL injections?
SQLi CWE-89, NoSQLi CWE-943, cmdi CWE-77/78, SSRF CWE-918, path traversal CWE-22/98. Severity tracks the backend impact (often Critical).

---

# LEVEL 6 — MASS ASSIGNMENT, CSRF, AUTHN/Z BYPASS & EXPERT CHAINS

### Q73. What is mass assignment in GraphQL?
A mutation's **input object** accepts fields you shouldn't set: `updateUser(input:{id:me, role:"admin", isAdmin:true, balance:99999})`. **IF** they stick → privilege escalation / tampering.

### Q74. How do I find bindable input fields?
`__type(name:"UpdateUserInput"){inputFields{name}}` (or suggestions). Add `role`/`isAdmin`/`owner_id`/`tenant_id`/`emailVerified`/`balance`; read the object back to confirm.

### Q75. Can mass assignment cross tenants/objects?
Yes — set `owner_id`/`tenant_id` in the input to reassign objects or cross the tenant boundary (IDOR §9/§16).

### Q76. Is GraphQL vulnerable to CSRF?
**IF** it accepts mutations via **GET** (`?query=mutation{...}`) or via **form-urlencoded/text-plain** content-type, **AND** auth is cookie-based → yes, a cross-site auto-submit/navigation fires the mutation (CSRF kit §16).

### Q77. Why doesn't `application/json` CSRF normally work?
A JSON body triggers a CORS **preflight**, which a cross-site form can't satisfy. CSRF works when the endpoint accepts a **simple** content-type or GET — that's the gap to test.

### Q78. How do I find unauthenticated (pre-auth) GraphQL access?
Run sensitive queries/mutations **logged out**. A forgotten `@auth` directive exposes data/actions pre-auth (Q25). High impact if it leaks PII or allows writes.

### Q79. What's an APQ/persisted-query attack?
Abusing Automatic Persisted Queries: registering malicious query hashes, cache poisoning, or bypassing validation that's only applied to non-persisted queries.

### Q80. How do I chain GraphQL bugs for max impact?
introspection → find `importFromUrl` → **SSRF → metadata → cloud creds → RCE**; or find `login` → **batch → rate-limit bypass → brute → ATO**; or `updateUser` input → **mass-assign admin → admin → RCE**.

### Q81. What's the most common GraphQL bounty?
**BOLA via node/*ById** (cross-user PII) and **batching rate-limit bypass** (→ brute → ATO). Both are frequent, high-signal, and well-rewarded.

### Q82. How do red-teamers use GraphQL?
Batching for quiet brute/enumeration (one request), introspection/clairvoyance to map the API fast, BOLA to harvest data, and SSRF/mass-assign to pivot — all low-noise relative to REST fuzzing.

### Q83. How do I demonstrate cross-user impact cleanly?
Two accounts you own: A's token returns B's object (BOLA), or A's mutation changes B's object (write). Read back as B. Exactly the IDOR two-account proof.

### Q84. When is a GraphQL finding NOT worth reporting alone?
"Introspection enabled", "batching possible", "a mutation exists", own-data `node`, or a verbose error with no useful content — all need to be tied to **actual impact** (Q96–Q102).

### Q85. How do I prioritize sinks?
Injection/SSRF (RCE/cloud) → BOLA/BFLA (cross-user/admin/ATO) → batching (brute→ATO) → mass-assign (priv-esc) → info/DoS. Test the backend-reaching and authz sinks first.

### Q86. What's the cleanest evidence per sub-bug?
BOLA: two-account screenshot/diff. BFLA/mass-assign: low-priv change read-back. Batching: measured op count. Injection: time/UNION/error. SSRF: OOB callback/metadata. DoS: measured amplification.

---

# TOOLING

### Q87. What's the core GraphQL toolkit?
**Burp + InQL** (schema parse + query gen + attack surface), **graphw00f** (engine), **clairvoyance** (schema when introspection's off), **graphql-cop** (quick audit), **batchql** (batching), **Voyager/Altair** (visualize/run).

### Q88. How does InQL help?
It parses the schema, generates all queries/mutations, and sends them to Repeater/Intruder — turning the schema into a clickable attack surface.

### Q89. When do I use clairvoyance vs introspection?
Introspection when it's **on** (full dump); clairvoyance when it's **off** (rebuild via suggestions). graphw00f first to know which.

### Q90. What does graphql-cop check?
Introspection, suggestions, batching/aliasing, CSRF (GET/POST), field duplication, and other quick wins — a fast first pass.

### Q91. Any custom helpers?
A schema dumper + sink-lister, a node/*ById enumerator, and a batching-count measurer — exactly the `poc/` scripts (`introspect.py`, `node_enumerator.py`, `batch_ratelimit_test.py`).

---

# METHODOLOGY & DECISION TREE

### Q92. Give me the end-to-end methodology.
Find + fingerprint endpoint → map schema (introspection or clairvoyance) → build sink list → exploit each (BOLA two-account / BFLA invoke / batching count / injection signal / SSRF OOB) → escalate (mass-assign→admin→RCE, SSRF→cloud) → prove → severity → report.

### Q93. The decision tree in words?
Confirmed endpoint? → introspection on? (dump) / off? (clairvoyance) → per sink: node/*ById (BOLA), mutation (BFLA/mass-assign), login/otp (batch), url arg (SSRF), filter arg (injection) → severity by downstream class.

### Q94. How do I avoid wasting time?
Map first; don't fuzz blindly. Drop "introspection enabled" as a headline; chase the backend-reaching and authz sinks. Re-verify every hit per sub-bug before reporting.

### Q95. How do I cover the whole schema systematically?
InQL to generate every operation; tick each query (BOLA/info), each mutation (BFLA/mass-assign), each arg (injection/SSRF), each input (mass-assign), against the checklist.

---

# SEVERITY, VALIDITY & FALSE POSITIVES

### Q96. What's the validity bar (per sub-bug)?
BOLA → two-account proof; BFLA/mass-assign → persisted privileged change; batching → measured op count beyond the limit; injection → reproducible signal; SSRF → OOB callback; DoS → measured amplification. *Impact, not capability.*

### Q97. What are the classic GraphQL false positives?
"Introspection enabled" alone, own-data `node`, "a mutation exists" (never invoked), GET-CSRF with Bearer auth (no cookie), "batching possible" with no sensitive op, theoretical deep-query DoS, and empty verbose errors.

### Q98. How do I set severity?
By the **downstream class**: injection→RCE / SSRF→cloud = Critical; BOLA/BFLA→cross-user/admin/ATO = Critical/High; batching→brute→ATO = High; mass-assign→priv-esc = High; info disclosure = Medium; DoS = Medium; introspection-only = Low/Info.

### Q99. What CWE do I cite?
Per sub-bug: 639/285/863 (BOLA), 862 (BFLA), 915 (mass-assign), 89/943 (SQL/NoSQLi), 77/78 (cmdi), 918 (SSRF), 200 (info), 352 (CSRF), 770/400 (DoS).

### Q100. How do I title a GraphQL report?
`<sub-bug> in GraphQL <field/mutation> → <impact>` and lead with the downstream impact + proof. Never "GraphQL misconfiguration".

### Q101. How do I handle introspection/verbose-errors in the report?
As **enablers** bundled with the impactful bug, not the headline — unless the program explicitly rewards the disclosure on its own.

### Q102. How do I de-duplicate?
One strong injection/BOLA/ATO beats a pile of "introspection on / batching possible" notes. If the program lists a known GraphQL issue, report your **distinct impactful** bug.

---

# REAL-WORLD CASES & REFERENCES

### Q103. What are common disclosed GraphQL bugs?
BOLA via `node(id:)`/`userById` (cross-user PII), batching rate-limit bypass on login/OTP (→ ATO), SSRF via URL-taking mutations (→ cloud creds), mass assignment via input objects (→ admin), and injection in filter/search args. Recurring across HackerOne disclosures.

### Q104. Why is BOLA so common in GraphQL specifically?
Because data access is centralized in resolvers and teams enforce authentication at the gateway but forget **per-object** authorization in each resolver — and `node`/`*ById` make every object addressable.

### Q105. What changed the batching threat model?
Awareness that **per-request** rate limiting is meaningless against batched operations; tooling (batchql, graphql-cop) made it trivial to demonstrate, and the single-packet race technique amplified timing-sensitive variants.

### Q106. Where can I practice?
PortSwigger Web Security Academy **GraphQL labs** (introspection, BOLA, mutation abuse, suggestions), DVGA (Damn Vulnerable GraphQL Application), and OWASP crAPI.

### Q107. What further reading matters?
OWASP GraphQL Cheat Sheet + API Top 10, PortSwigger GraphQL topic, the InQL/clairvoyance/graphw00f docs, and the IDOR/SSRF/CSRF kits in this library for the cross-class methods.

---

# DEFENSE — HOW TO SECURE GRAPHQL

### Q108. The top fixes?
**Per-resolver object & function authorization** (consistent `@auth`/`@hasRole`), **disable introspection** in prod, **suppress verbose errors**, **rate-limit per operation** + cap batching, and **depth/complexity/cost limits**.

### Q109. How do I stop BOLA/BFLA?
Authorize **every** resolver against the caller (object ownership + role), apply directives consistently, and test it (Autorize-style) in CI. Don't rely on unguessable ids.

### Q110. How do I stop batching abuse?
Cap alias count and array-batch size, rate-limit by **operation** (not HTTP request), and add anti-automation (CAPTCHA/step-up) on login/OTP.

### Q111. How do I stop DoS?
Query **depth limits**, **complexity/cost analysis**, **timeouts**, **persisted queries** (allow-list), and disable introspection. Reject overly nested/aliased/duplicated queries.

### Q112. How do I stop injection/SSRF in resolvers?
Parameterized queries/ORM safe APIs (SQL/NoSQL), validate & **allow-list** URL args (block internal ranges/metadata), avoid shelling out, and sanitize file/path args.

### Q113. How do I stop GraphQL CSRF & mass assignment?
Require `application/json` + CSRF token/custom header for mutations (no GET state-change), and **allow-list** input fields (never bind `role`/`isAdmin`/`owner_id` from client input).

---

# ADDENDUM (rev. 2) — SUBSCRIPTIONS / WEBSOCKET, @DEFER/@STREAM, PERSISTED QUERIES

### Q114. What's the deal with `subscription` and why is it a separate attack surface?
Subscriptions are **live feeds delivered over a WebSocket** (sub-protocols `graphql-transport-ws` / the legacy `graphql-ws`). The WS handshake + `connection_init` is a **different code path** from HTTP queries, and teams frequently **forget to enforce the same auth** there — so a `subscription` (or even a smuggled `query`/`mutation`) may resolve **logged-out or with weaker auth**. Test every sensitive subscription with no token / a low-priv token.

### Q115. What is CSWSH and how does it hit GraphQL?
**Cross-Site WebSocket Hijacking.** WebSockets are **not subject to CORS**, and the browser **auto-attaches cookies** to the `wss://` handshake. **IF** the subscription endpoint authenticates **by cookie** and **doesn't validate the `Origin` header**, an attacker page can open the socket in the victim's browser and **receive their live data (or trigger actions)** — CSRF-on-WebSocket. Confirm by replaying the handshake with a **foreign/absent `Origin`**; if it still connects authenticated → CSWSH. Fix = check `Origin` + use token auth, not ambient cookies.

### Q116. How do I actually test a subscription?
Use **Burp's WebSockets** tab (connect + replay frames) or `websocat`/`wscat`/a tiny Python `websockets` client. Send:
```
{"type":"connection_init","payload":{"Authorization":"Bearer <token-or-omit>"}}
{"type":"subscribe","id":"1","payload":{"query":"subscription{ messageAdded{ text user{ email } } }"}}
```
Vary the token (none/low-priv) and the `Origin`. Opening many subscriptions / never acking → connection-exhaustion **DoS** (measure, with permission).

### Q117. What are `@defer` / `@stream` and how are they abused?
**Incremental-delivery** directives (newer Apollo/graphql-js): `@defer` sends a fragment later, `@stream` sends list items one at a time. Abuse = **amplification/DoS** — many `@defer` fragments or `@stream(initialCount:0)` over a huge list makes the server do extra bookkeeping and hold the response open. Pile on `@skip(if:false)`/`@include`/duplicate/unknown directives to stress the validator. Report missing complexity/timeout caps (measure, don't flood). (Guide §10.6)

### Q118. What's the persisted-query / APQ angle?
**Automatic Persisted Queries (APQ)** let clients send a **hash** instead of the full query (the server caches query↔hash). Test: can you **register a malicious query** under a chosen hash, **poison** the cache, or **bypass validation/allow-listing** that's only applied to non-persisted queries? Also, a mutation blocked on the normal path may be reachable via the persisted path. (Guide §15.3)

### Q119. Quick tool note for a beginner doing this?
**graphw00f** (engine) → **InQL/Voyager** (see the schema) → **graphql-cop** (fast audit) → **clairvoyance** (schema when introspection's off) → **CrackQL** (alias-batch brute) → **Burp WebSockets/websocat** (subscriptions). Learn the basics at `graphql.org/learn`, practice on **DVGA** and PortSwigger labs.

---

# APPENDIX — 60-SECOND FIELD CHECKLIST
```
[ ] Find endpoint(s) + graphw00f the engine; note introspection/suggestions/GET/batching.
[ ] Map schema: introspection __schema → dump; off → clairvoyance/suggestions.
[ ] Sink list: node/*ById (BOLA) · mutations (BFLA) · input objects (mass-assign) · url/file args (SSRF) · filter/id args (injection) · login/otp (batching).
[ ] BOLA two-account (A's token + B's id → B's data). BFLA: invoke mutation as low-priv.
[ ] Batching: measure N ops in ONE request vs per-request limit → bypass → brute → ATO.
[ ] Injection: SQLi/NoSQLi($ne)/cmdi(time)/SSRF(OOB) in args via variables.
[ ] Mass-assign input (role/isAdmin/owner_id) → read back. CSRF (GET/form + cookie auth).
[ ] Subscriptions (WebSocket): connect with no token + foreign Origin → CSWSH / auth bypass (§15.5).
[ ] DoS: measure deep/alias/duplication/@defer/@stream amplification (permission); note missing limits.
[ ] Prove per sub-bug → CVSS + correct CWE → PoC query → bundle introspection/errors as enablers → dedup.
```

> **Authorized testing only.** Two accounts for BOLA/BFLA, your own OOB host for SSRF, measured counts for batching, measure-don't-flood for DoS, revert writes, small enumeration. Report **the downstream impact** (RCE/ATO/cross-user/cloud/priv-esc) — not "introspection is enabled."
