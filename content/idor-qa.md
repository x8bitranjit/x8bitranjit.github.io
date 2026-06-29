# Insecure Direct Object Reference (IDOR / BOLA) — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **broken object/function-level authorization**: from "what is an IDOR" to mass-PII enumeration, write-IDOR account takeover, BFLA → admin → RCE, GraphQL `node` BOLA, cross-tenant breaks, and the chains they unlock. Q&A format, progressive difficulty, written as **"IF this → THEN that"** decision logic. Covers ID formats & prediction, the bypass toolbox, tooling, methodology, real-world cases, **and** defense.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, and learning. Prove every IDOR with **two accounts you own** (A reaches B). Never mass-exfiltrate real PII — prove the pattern small and cite the population from server metadata.

**Canonical references** (real, read them):
- OWASP **API Security Top 10** — API1:2023 BOLA, API3 BOPLA/Mass Assignment, API5 BFLA
- PortSwigger Web Security Academy — *Access control vulnerabilities* (IDOR)
- OWASP WSTG — *Testing for IDOR / Authorization*; CWE-639 / 285 / 863 / 566 / 915 / 862
- HackTricks — *IDOR*; PayloadsAllTheThings — *Insecure Direct Object References*

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q12)
- **Level 1 — Finding references & the two-account method** (Q13–Q25)
- **Level 2 — ID formats, prediction & disclosure** (Q26–Q40)
- **Level 3 — Access-control bypass techniques** (Q41–Q55)
- **Level 4 — Mass assignment & BFLA** (Q56–Q68)
- **Level 5 — Special contexts: GraphQL, files, multi-tenant, blind** (Q69–Q82)
- **Level 6 — Expert chains: ATO, RCE, mass breach** (Q83–Q92)
- **Tooling** (Q93–Q97)
- **Black-box methodology & decision tree** (Q98–Q101)
- **Severity, validity & false positives** (Q102–Q107)
- **Real-world case patterns & references** (Q108–Q112)
- **Defense — how to stop IDOR properly** (Q113–Q117)
- **Appendix — 60-second field checklist**

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is IDOR in one sentence?
IDOR (Insecure Direct Object Reference) is when an app uses a **client-controlled reference** (id, uuid, filename, key) to fetch or change an object **without verifying the authenticated user is authorized for that specific object** — so you swap your id for someone else's and the server hands it over.

### Q2. IDOR vs BOLA vs BFLA vs BOPLA — what's the difference?
- **IDOR** — the classic web term for object-level access-control failure via a user-controlled key.
- **BOLA** (Broken Object Level Authorization, **OWASP API #1**) — the same bug in API language. Use this term in API reports.
- **BFLA** (Broken Function Level Authorization, **API #5**) — not "which object" but "which *operation*": a normal user calling an admin/privileged function.
- **BOPLA / Mass Assignment** (API #3) — you're allowed the object but tamper a **property** you shouldn't (`isAdmin`, `owner_id`, `balance`).

### Q3. What's the root cause?
Missing/wrong **authorization** (not authentication). The code did `SELECT * FROM x WHERE id=:id` instead of `... WHERE id=:id AND owner_id=:current_user`. You're correctly logged in; the server just never checks the object is *yours*.

### Q4. Why is IDOR/BOLA the #1 bug class?
It scales with endpoints and needs no exotic primitive — it's a forgotten line of authz code. Modern SPAs/mobile apps are thin clients over APIs that expose object ids everywhere, and every new feature is a fresh chance to forget the check. It's #1 on OWASP API Top 10 and a top payout class on every platform.

### Q5. What are the three conditions for IDOR? (the gate)
**IF** (a) the request carries a **reference to an object** you control, **AND** (b) the object belongs to **another user/tenant**, **AND** (c) the server **doesn't enforce an ownership/role check** → **THEN it's IDOR.** Remove (c) and it's not.

### Q6. Authentication vs authorization — which one is IDOR?
**Authorization.** Authentication = "who are you" (login works fine). Authorization = "are you allowed *this object/action*" (the missing check). IDOR is a pure authorization failure.

### Q7. What's a "direct" object reference vs an indirect one?
**Direct** = the real internal key is exposed (`/orders/8001` where 8001 is the DB PK). **Indirect** = the server maps a per-user handle to the real object (`/orders/my-2nd` resolved server-side against your session). Indirect references *with a server-side ownership map* are the fix; direct references *without a check* are the bug.

### Q8. Does using UUIDs prevent IDOR?
**No.** UUIDv4 is unguessable but constantly **leaked** (search, autocomplete, Referer, errors, other API responses, GraphQL). Unguessable ≠ authorized. **IF** you can obtain a victim's UUID and the endpoint doesn't check ownership → it's still a full IDOR (Q33).

### Q9. Read IDOR vs write IDOR — which matters more?
Both are findings; **write is usually worse**. Read → information disclosure (and Critical if mass/PII or it leaks auth material). Write → you *change* a victim's object: email/password → **account takeover**, money, settings. Always check whether a write verb exists on a readable object (Q49).

### Q10. What's the real-world impact range?
From Low (read one low-sensitivity own-adjacent field) to **Critical**: mass-PII breach (enumerate everyone), account takeover (write to victim), privilege escalation (BFLA → admin → RCE), cross-tenant compromise (SaaS isolation break).

### Q11. What single thing makes an IDOR report valid (not a false positive)?
The **two-account proof**: account **A** (attacker, yours) reading or changing account **B**'s (victim, also yours) private object, using A's credentials. One account proves nothing — it might be your own or public data (Q14, Q102).

### Q12. What's the attacker mindset for IDOR?
For every object the app shows you, ask: *"What's the reference, who really owns it, and does the server check I'm allowed it — on every verb and every representation?"* Then swap your id for a second account's and watch.

---

# LEVEL 1 — FINDING REFERENCES & THE TWO-ACCOUNT METHOD

### Q13. How do I set up to test IDOR?
Register **two accounts of equal role** (A=attacker, B=victim) — plus, ideally, an **admin** (for BFLA baselines) and a **second tenant/org** (for cross-tenant). Proxy both through Burp. Optionally an account in a paid/elevated tier to test plan-gating.

### Q14. Why two accounts and not just one?
With one account you can't tell "I accessed someone else's data" from "I accessed my own / public data." Two accounts you own create the oracle: capture **B's** reference, replay it **in A's** session, show A got **B's** data. That's the proof a triager accepts.

### Q15. Why equal-role accounts (not admin vs user)?
Equal roles isolate the **object-level** check. If you test as admin you can't tell whether access came from your role (expected) or a missing object check (the bug). Use admin separately for **BFLA** (Q60).

### Q16. Where do object references hide? (recon checklist)
Path (`/users/123`), query (`?id=`, `?file=`, `?account=`), body (form & **nested JSON**), **headers** (`X-User-Id`, `X-Account-Id`, tenant headers), **cookies** (`uid=`), **GraphQL** (`node(id:)`, `*ById`), **files** (`/exports/{id}.pdf`, S3 keys, signed URLs), and **redirect/Referer** params. Test all of them — headers and JSON-nested ids are high-hit, low-effort.

### Q17. How do I enumerate the attack surface efficiently?
Drive every feature as **both** A and B through the proxy; Burp Sitemap + Logger then hold every reference. Add historical/JS endpoints from recon (gau/katana/JS mining) to catch **old `/v1/` and undocumented APIs** the UI dropped but the server still serves (Q47).

### Q18. What is the "objects table" I should build?
`object type | reference location | format | owner | example(B)`. You can't test ownership until you know which references exist and which belong to B.

### Q19. How exactly do I run the baseline oracle?
1) As B, do the action → note B's reference. 2) As A, do it on A's own object. 3) Take **A's request** and substitute **B's reference**. 4) Read the response: B's data → IDOR-READ; 403/404 → try bypass; A's own data → SAFE (session-scoped).

### Q20. The swap returned my own data regardless of the id. What does that mean?
The server is **session-scoping** (ignoring the client id, using your session). That's correct behaviour — **not IDOR**. Stop on that object.

### Q21. The swap returned B's data. Now what?
IDOR-READ confirmed. Immediately escalate: is the id **enumerable** → mass-read (Q83)? Does the object contain **auth material** (reset token/API key) → ATO/RCE (Q84)? Is there a **write verb** on the same object → write-IDOR/ATO (Q49)?

### Q22. The swap returned 403/404. Is it safe?
Not yet — run the bypass toolbox (Level 3) before concluding. Method swap, array-wrap, parameter pollution, type juggling, `.json`/version, header trust, wildcard. And record the **403-vs-404 oracle** regardless (Q53).

### Q23. How do I confirm a *write* IDOR (not just a 200)?
A 200 isn't proof. **Re-read the object as B** (or use an out-of-band signal) and confirm the value actually changed on B's side. Write-IDOR validity = "B's object verifiably changed by A."

### Q24. What if auth is a Bearer token in a header (not a cookie)? Can I still have IDOR?
Yes — IDOR is about **object authorization**, independent of how you authenticate. You still send your own valid token; the bug is the missing per-object check. (Contrast CSRF, which *does* require cookie-borne auth.)

### Q25. Mobile apps — why are they an IDOR goldmine?
Mobile back-ends expose **richer, older, less-guarded APIs** (the app talks to `/v1/` directly), often with ids in headers and JSON. Proxy the app (Frida/objection + Burp) and you'll find object endpoints the web UI never reveals.

---

# LEVEL 2 — ID FORMATS, PREDICTION & DISCLOSURE

### Q26. What's the first thing to do with any id?
**Identify its format** (sequential? encoded? uuid? objectid? composite?) and **decode** anything encoded. The format decides whether you *guess*, *predict*, or *obtain* the victim's reference.

### Q27. Sequential integer ids — how do I exploit them?
Increment/decrement (`123`→`124`,`122`). **IF** other users' objects come back → confirmed; then prove enumeration **politely** with a small set and state population from `X-Total-Count`/max-id. Try edges: `0`, `-1`, huge ints.

### Q28. The id looks like `MTIz` or `dXNlcl8xMjM=` — what is it?
Base64. Decode (`MTIz`→`123`; `dXNlcl8xMjM=`→`user_123`). **IF** it decodes to a sequential value → increment, re-encode, replay. Encoded ids are enumerable ids in a costume.

### Q29. The id is a 32-hex string. Could it still be enumerable?
Possibly a **hash of a small integer** (`md5("123")=202cb962…`). **IF** ids are unsalted hashes of PKs → precompute the hash space (md5/sha1/crc32 of 1..N) and map them.

### Q30. How do I attack UUIDv1?
v1 = timestamp + clock-seq + **node (MAC)**. Capture a few v1 UUIDs → the node and approximate creation time are known → "sandwich"/prediction tools narrow the random space dramatically. **IF** the app issues v1 for objects created near a time you can bound → predictable.

### Q31. How do I attack a Mongo ObjectId (24 hex)?
Structure = `4B timestamp | 5B random | 3B counter`. The timestamp and incrementing counter are partially predictable; given nearby ObjectIds you can fuzz the residual space far below brute force. Great when one ObjectId leaks and you want neighbours.

### Q32. Snowflake / big time-based ints?
Embed a millisecond timestamp + worker + sequence → bounded by the creation time window → enumerable within a known interval.

### Q33. The id is a random UUIDv4 — is the endpoint safe?
Only if it **also checks ownership**. v4 is unguessable, so **obtain** it instead of guessing: list/search/autocomplete endpoints, public profiles, error messages, `Referer`, webhooks, GraphQL `{users{id}}`, or a sequential slug sitting next to it. **IF** obtainable AND no ownership check → full IDOR.

### Q34. Where do "unguessable" ids leak in practice?
Other API responses (list/search/recent/notifications/exports), public pages (profiles/shared links/sitemaps/RSS), verbose errors, Referer/redirect URLs, emails, webhooks, and GraphQL. Harvesting is usually easier than predicting.

### Q35. Composite/signed ids (`tenant7:obj42`, `id.sig`) — how do I test them?
Tamper **each part** (swap the tenant, swap the object). If there's a signature, test whether it's **actually verified** (strip it, alter the payload, reuse another object's signature). Unverified signatures = full control.

### Q36. What's the "enumeration discipline" and why does it matter?
Prove the *class* with a **handful** of ids (your own + the second account) and **state** the population from server metadata — don't scrape real users. It keeps the finding inside safe-harbor (CFAA/GDPR) and is all the report needs (Q103, Q116).

### Q37. How do I find the population size without scraping?
`X-Total-Count`/`X-Total` headers, pagination `total` fields, the max id (request the newest object), or a count endpoint. Cite this for scale.

### Q38. Pagination cursors — can they leak others' data?
Yes. Opaque cursors sometimes decode to offsets/ids you can tamper, and "load more" endpoints occasionally skip the per-object check. Decode and mutate the cursor.

### Q39. Should I prefer prediction or disclosure?
**Disclosure** (just obtain the id) is usually faster, quieter, and more reliable than prediction. Try to *find* the victim id in a response before trying to *compute* it.

### Q40. The id is enumerable but objects return 403. Useful?
Yes — if 403 ("exists, not yours") differs from 404 ("doesn't exist"), you have an **existence/enumeration oracle** (valid usernames/objects), and a different *verb/representation* may not be guarded at all (Level 3).

---

# LEVEL 3 — ACCESS-CONTROL BYPASS TECHNIQUES

### Q41. The direct swap is blocked. What's the order of bypass attempts?
direct → **method swap** → **array-wrap** → **parameter pollution** → **type juggle** → **path/.json/version** → **header trust** → **wildcard/boundary** → (record the 403/404 oracle regardless).

### Q42. HTTP method / verb tampering?
`GET /users/123` may check ownership while `POST/PUT/PATCH/DELETE` don't. Also `HEAD`/`OPTIONS`. **IF** GET is 403 but `PUT /users/123 {…}` works → write IDOR/BFLA.

### Q43. Method override tricks?
`X-HTTP-Method-Override: PUT`, `_method=PUT` (form/body), `?_method=DELETE`. Frameworks honour these and may route past a method-specific guard.

### Q44. Array-wrapping the id?
`id=123`→`id[]=123`; `{"id":123}`→`{"id":[123]}` or `{"id":{"id":123}}`. A check on a scalar can be skipped when the value is an array/object the validator didn't expect.

### Q45. Parameter pollution / duplicate keys?
Send the reference twice — yours + the victim's: `?id=mine&id=victim`, dup JSON keys `{"id":1,"id":2}`, or split across locations (path=mine, body=victim). The authz layer may read one occurrence and the data layer another.

### Q46. Type juggling?
`123` vs `"123"` vs `123.0` vs `[123]` vs `{"$ne":null}` (NoSQL). Loose comparisons / query builders can drop the ownership filter on an unexpected type — and `$ne`/`$gt` can pull *all* objects (chase NoSQLi).

### Q47. Path, encoding, extension, and version tricks?
Append `.json`/`.xml`/`.pdf` (different handler), trailing `/`, `%2e`/`%2f`/double-encode, change **case**, add matrix/`;jsessionid` params, or path-traversal in the id. And swap **API version** — `/v1/` often runs the original unguarded logic after `/v2/` added the check.

### Q48. Wildcard / null / boundary values?
`id=*`, `%`, `all`, `0`, `-1`, empty, `null`, `me`/`current`. Some backends return **all** objects for a wildcard or the **system/admin** object for `0`.

### Q49. I have a read IDOR — how do I find the write version?
On the same object id, try `PUT`/`PATCH`/`POST` with a body (copy the GET response shape and change a field). **IF** the write lands (verify as B) → write-IDOR → push to ATO (Q84).

### Q50. Header trust bypasses?
`X-User-Id: <victim>`, `X-Account-Id`, `X-Tenant-Id`, `X-Forwarded-For: 127.0.0.1`, `X-Original-URL: /admin`. Apps and gateways sometimes trust these implicitly — very high hit-rate.

### Q51. Referer/Origin-based authz?
Some object/admin checks pass merely if `Referer` looks internal (`/admin`). Spoof it. (Fragile control = easy bypass.)

### Q52. What about CORS / response-reading on top of IDOR?
If a cross-origin page can also **read** the IDOR response (misconfigured CORS with credentials), the IDOR becomes remotely exploitable from any site the victim visits — raise severity and document the CORS combo.

### Q53. What's the 403-vs-404 oracle and how do I use it?
Different responses for "exists but not yours" (403) vs "doesn't exist" (404) — or different length/time — let you **enumerate valid ids/usernames/objects**. Report it as an info leak and use it to seed other attacks. Always measure status **and** length **and** time.

### Q54. The app uses opaque/encrypted ids I can't tamper. Dead end?
Not necessarily — look for the same object via a **different endpoint** (export, GraphQL, `/v1/`) that uses a tamperable reference, or a **write** that accepts `owner_id` (Q56). The encrypted id on one route doesn't mean every route is safe.

### Q55. How do I keep bypass testing low-false-positive?
Re-verify any "success" against the two-account oracle (A's creds, B's object, B's data). A 200 with empty/own/public data is not a bypass. Confirm B's *specific* data appears.

---

# LEVEL 4 — MASS ASSIGNMENT & BFLA

### Q56. What is mass assignment (BOPLA) and how does it relate to IDOR?
You're allowed the object, but you set a **property you shouldn't control** by adding it to the request body: `owner_id`, `user_id`, `role`, `isAdmin`, `balance`. It's the *write* sibling of IDOR and a direct priv-esc/ATO path.

### Q57. How do I exploit owner-field mass assignment?
On create/update of your own object, **add** `"owner_id":<B>` / `"account_id":<tenant2>`. **IF** the server honours it → you can reassign objects between users/tenants (and read/modify by re-pointing ownership) — sometimes without ever needing a read IDOR.

### Q58. How do I self-promote via mass assignment?
Add `"role":"admin"`, `"isAdmin":true`, `"is_staff":true`, `"verified":true`, `"permissions":["*"]`, `"plan":"enterprise"` to a profile/settings update. **IF** it sticks → privilege escalation (Q86).

### Q59. How do I discover which fields are bindable?
Read them from the object's own **GET response** (assign back whatever it returns), GraphQL **input types / `__type`**, the **mobile app's** request bodies, JS source, Swagger/OpenAPI, and error messages ("unknown field 'x'").

### Q60. What is BFLA and how is it different from object IDOR?
BFLA = **function-level**: a low-priv user invoking a privileged **operation** (`POST /admin/users`, `PATCH /users/{id}/role`, `*/impersonate`, `*/export-all`), regardless of object. The admin UI hides the button; the API often doesn't enforce the role.

### Q61. How do I find privileged functions without an admin account?
From JS bundles, Swagger, GraphQL schema, mobile traffic, and naming patterns (`/admin/`, `/internal/`, `*/approve`, `*/impersonate`). Construct the request from docs and fire it as a normal user.

### Q62. How do I test BFLA if I *do* have an admin account?
Capture the admin request, then replay it with **user A's** token. **IF** it succeeds → BFLA. Cover every admin endpoint (AuthMatrix/Autorize automate this).

### Q63. What are the highest-impact BFLA outcomes?
Self-promotion to admin, **creating** admins, **impersonation**, mass-delete/approve, and **reading the entire dataset** (export-all). Most are Critical.

### Q64. Can BFLA reach RCE?
Often, via admin: file/plugin/theme **upload** (webshell), **SSTI** in admin templates, **SSRF** in admin webhook/integration URLs, "run task"/backup/import features. Chain BFLA → admin → RCE and report the whole thing (Q88).

### Q65. The admin function is blocked on `/admin/`. Other routes?
Try `/api/v1/admin/`, `/admin/api/`, method override, or the **GraphQL mutation** that does the same thing without the directive check.

### Q66. Mass assignment is rejected with "unknown field." Now what?
Use the **exact** field names from the GET response / schema (casing matters: `isAdmin` vs `is_admin`). Try nested placement (`{"user":{"role":"admin"}}`) and alternate content-types.

### Q67. Can I combine mass assignment with object IDOR?
Yes — e.g. mass-assign `owner_id` to **move B's object to you** (then read it normally), or set your own `tenant_id` to a victim tenant. Writes can substitute for blocked reads.

### Q68. How do I prove BFLA/mass-assignment safely?
Promote **your own** test account (A), demonstrate one admin-only capability, then **revert** (demote, delete any admin you created). Never create persistent admins on production or touch real users.

---

# LEVEL 5 — SPECIAL CONTEXTS: GRAPHQL, FILES, MULTI-TENANT, BLIND

### Q69. Why is GraphQL an IDOR/BOLA hotspot?
Object access is **field-shaped** and centralized in resolvers that frequently lack per-object checks. `node(id:)`, `userById`, and friends are textbook BOLA, and aliases/batching let you enumerate at scale in one request.

### Q70. How do I exploit `node(id:)` BOLA?
Global ids are usually `base64("Type:pk")`. Decode (`VXNlcjoxMjQ=`→`User:124`), iterate the pk, re-encode, query `{ node(id:"…"){ ... on User { email } } }`. **IF** you get other users' fields → BOLA.

### Q71. What are GraphQL alias/batching attacks?
Request many objects in one query with aliases (`a:user(id:1) b:user(id:2)…`) or send a JSON **array** of operations. This enumerates at scale and **bypasses rate limits / OTP throttling** (see the `API/GraphQL/` kit).

### Q72. GraphQL mutations and IDOR?
`updateUser(id:<B>, input:{email:…})`, `deleteOrder(id:<B>)`, admin mutations without auth directives = write IDOR / BFLA. Test every mutation against the two-account oracle.

### Q73. Introspection is disabled — can I still find `*ById` sinks?
Yes — **field suggestions** ("did you mean …"), **clairvoyance** (brute the schema via suggestions), and **graphw00f** fingerprinting reveal hidden fields and types. (Full coverage in `API/GraphQL/`.)

### Q74. IDOR in file downloads/attachments?
Swap the filename/id (`invoice_8001.pdf`→`8002`), try path traversal in the name (`../`), and hit **export** endpoints that lack object checks (often bulk). `/attachments/{id}`, `/exports/{uuid}.csv`.

### Q75. IDOR in object storage (S3/GCS/Azure)?
Keys like `uploads/<userid>/<file>` served by a public bucket/CDN are IDOR-at-storage if the userid is enumerable. Test the CDN URL directly (no auth) and iterate the key segment.

### Q76. Signed-URL (pre-signed) flaws?
Test: does it **expire**? Is the **path/`response-content-disposition`** tamperable? Is the **HMAC** weak/reused? Is a signed URL minted for **any** id you pass? Any "yes" = IDOR via signed URL.

### Q77. What is cross-tenant IDOR and why is it the worst?
In SaaS, reaching **another organization's** data — isolation is the core promise, so it's almost always Critical. Find the tenant key (`tenant_id`/`org`/subdomain/header), authenticate to tenant-1, and reach tenant-2's objects.

### Q78. How do I test multi-tenant isolation?
Register **two orgs** you own. As org-1, swap org-2's object/tenant reference in path/body/header/subdomain. Test **read and write**, and whether changing **only** the tenant key (same object id) crosses over.

### Q79. What is a blind / second-order IDOR?
The missing check is on a path where you **don't see the result**: you set `notify_user_id=<B>` or `report_to=<B>`, and the object is processed later by a job/webhook without your auth context. Confirm via the victim/OOB (interactsh, your inbox).

### Q80. How do I confirm an IDOR when I can't read the response?
Prove it by **effect**: B sees the changed value, a notification fires, an OOB callback lands, a counter changes. Differential/out-of-band confirmation (Q23).

### Q81. Pre-auth IDOR — does it exist?
Yes — some object actions are reachable **logged out** or via a link. Confirm with a clean, unauthenticated client. Pre-auth IDOR raises severity (PR:N).

### Q82. WebSockets / gRPC / RPC — IDOR there too?
Yes. Any channel carrying object references is in scope. Proxy WS frames (Burp), tamper ids in messages; for gRPC, use grpcurl/Burp's gRPC support and swap the id field.

---

# LEVEL 6 — EXPERT CHAINS: ATO, RCE, MASS BREACH

### Q83. Read IDOR → mass breach — how do I escalate?
If the id is enumerable (Q27) or harvestable (Q33), demonstrate **scale**: iterating returns PII for the whole population. Prove the pattern small, cite the count → **Critical PII breach** (First American/T-Mobile pattern).

### Q84. Read IDOR returned a reset token / API key — now what?
**ATO/RCE immediately.** A leaked password-reset token → reset the victim's password. A leaked API key/session → act as them or hit privileged APIs. A read IDOR that returns **auth material** is Critical, not Medium.

### Q85. Write IDOR → account takeover — the canonical chain?
`PUT /users/<B>/email {attacker@inbox}` (A's creds) → request password reset for B → reset link hits attacker inbox → log in as B. Or direct password/MFA/passkey change. Verify on B.

### Q86. Mass assignment → privilege escalation → what's the terminal?
`PATCH /users/me {"role":"admin"}` → you're admin → drive admin to **RCE** (upload/SSTI/SSRF/integration) or full data export. Report the full chain.

### Q87. How do I chain IDOR with other bug classes?
- IDOR file read + `../` → **LFI**.
- Type-juggle `$ne` → **NoSQLi** → dump/auth-bypass.
- IDOR-leaked SSRF/webhook config or admin integration → **SSRF** → cloud metadata → keys → RCE.
- IDOR-leaked OAuth/JWT material → token forgery / ATO.
- IDOR write of a stored field rendered to others → **stored XSS**.

### Q88. BFLA → RCE — give the full chain.
Find unguarded `POST /api/admin/users` (or self-promote) → become admin → admin **file upload** → webshell → **RCE** on the app server → from there, internal pivot. Document every hop with safe, reverted actions.

### Q89. How do I demonstrate cross-tenant impact convincingly?
Two orgs you own: show org-1 **reading** org-2's record AND **writing** to it (benign marker), then re-read as org-2 to confirm. Add BFLA for platform-admin if reachable. That's a Critical isolation failure.

### Q90. What's the highest-value target object to look for?
Anything holding **auth material** (reset tokens, MFA secrets, API/SSH keys, sessions) or **money/PII at scale**, owned by **admins or every user**. The most sensitive object × the most privileged victim × the widest scale = top bounty.

### Q91. How do red-teamers use IDOR in an engagement?
As a quiet lateral/privilege primitive: enumerate users/objects to map the org, harvest credentials/tokens from leaked objects, self-promote via mass assignment, and pivot through admin integrations — all low-noise compared to exploits, if throttled.

### Q92. When is an IDOR *not* worth chaining further?
When it reads only low-sensitivity, non-enumerable, own-adjacent data with no write path and no auth material — report it as Low/Info and move on. Don't inflate; don't waste the program's time.

---

# TOOLING

### Q93. What's the single most useful IDOR tool?
**Burp + Autorize** — browse as A while it replays every request as B (and unauth) and flags "Bypassed!". Whole-app object-level coverage with two identities. Verify each hit by hand.

### Q94. AuthMatrix / Auth Analyzer — when?
For **role×endpoint matrices** and systematic **BFLA** coverage across many roles/endpoints. Great for APIs with documented roles.

### Q95. How do I enumerate ids without writing custom code?
Burp **Intruder** (Sniper, Numbers payload, throttled) or **ffuf** (`-w <(seq …) -rate 5 -mc 200`). Keep it small and polite.

### Q96. GraphQL tooling for BOLA?
**InQL** (Burp), **GraphQL Voyager/Altair** (schema), **clairvoyance** (schema when introspection is off), **graphw00f** (engine fingerprint), **batchql** (batching tests). See `API/GraphQL/`.

### Q97. What custom tooling helps most?
A **two-account replay/diff** script (A-with-B's-id vs B's own view; identical = IDOR) and a **polite id prober** that reports the 403/404 oracle — exactly what `poc/idor_replay_diff.py` and `poc/id_enumerator.py` do.

---

# BLACK-BOX METHODOLOGY & DECISION TREE

### Q98. Give me the end-to-end methodology.
Two accounts → map references → per object run the baseline oracle → if blocked, bypass toolbox → escalate (enumerate/write/BFLA/cross-tenant/blind) → two-account proof → severity → report. (Master Testing Sequence in the guide.)

### Q99. The decision tree in words?
Reference present? → object belongs to another? → A's creds + B's id → B's data? (IDOR) / own data? (SAFE) / 403-404? (bypass). Then: enumerable? write verb? function-level? cross-tenant? blind?

### Q100. How do I prioritize which objects to test first?
By impact: auth/credential objects, admin/role functions, financial/PII objects, then everything else. And by *reachability*: enumerable/leaked ids first.

### Q101. How do I avoid wasting time on non-IDOR endpoints?
If the server **session-scopes** (returns your own data regardless of id) on an object, drop it fast. If a real ownership check survives the whole bypass toolbox, drop it. Spend time where the swap or a bypass returns B's data.

---

# SEVERITY, VALIDITY & FALSE POSITIVES

### Q102. What are the classic IDOR false positives?
One-account "I changed the id and got data," **public** objects, endpoints that return **your own** data regardless of id, 403/404 with no working bypass, "I guessed a UUID" with no access, and anything needing the **victim's** token/link.

### Q103. What's the validity bar in one line?
"**A** (my account) used **A's** credentials to read/modify **B's** (my other account) private object, with no server-side ownership check." Show all four: whose object, whose creds, what came back/changed, absence of the check.

### Q104. How do I set severity?
Sensitivity × scale × read/write × victim-reach. BFLA→admin→RCE and write→ATO are Critical; mass-PII is Critical/High; single sensitive read is Medium/High; low-sensitivity read is Low. CWE-639 (+285/863/566/915/862). `PR:L` (auth) or `PR:N` (unauth).

### Q105. What CVSS vector for a mass-read PII IDOR?
e.g. `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` (~8.x) — scope-changed because you reach other principals' data; high confidentiality; integrity none for pure read.

### Q106. How do I write a title that gets triaged fast?
`IDOR/BOLA on <method> <endpoint> (<reference>) → <impact>` and lead with the highest proven impact + scale. Never "IDOR found."

### Q107. How do I avoid duplicates?
One strong, well-escalated IDOR (with the chain) beats ten "id-swap returns data" dupes. If the program already notes "BOLA on the API," frame your **distinct object/impact** (cross-tenant, ATO chain, BFLA→RCE).

---

# REAL-WORLD CASE PATTERNS & REFERENCES

### Q108. First American Financial (2019) — what happened?
**~885 million** sensitive financial documents exposed via a **sequential document id** in the URL — change the number, read anyone's documents. The archetypal mass read-IDOR.

### Q109. T-Mobile / Optus / Peloton / USPS — the API-BOLA wave?
T-Mobile (2023): a BOLA on an API exposed ~37M records. Optus (2022): unauthenticated API enumeration of customer PII. Peloton (2021): API returned account data for any user. USPS Informed Visibility (2018): API exposed ~60M users. Same root cause every time: **a reference with no object-level check, at scale.**

### Q110. Parler (2021) — what's the lesson?
**Sequential post ids** + no auth allowed bulk scraping of public+private content. Predictable references + missing checks = mass data acquisition.

### Q111. What's the common thread across all the big ones?
find reference → **no ownership check** → **enumerate or write** → mass PII / ATO / cross-tenant. The bug is boring; the scale is what makes it catastrophic.

### Q112. Where do I read more / practice?
PortSwigger Access-Control labs (IDOR), OWASP API Security Top 10 + crAPI/VAmPI deliberately-vulnerable APIs, HackerOne disclosed IDOR/BOLA reports, PayloadsAllTheThings IDOR.

---

# DEFENSE — HOW TO STOP IDOR PROPERLY

### Q113. The one fix that matters?
**Enforce server-side authorization on every object access**: bind the object to the caller (`WHERE id=:id AND owner_id=:current_user`, or a policy/ABAC check) — on **every verb and representation**.

### Q114. Do UUIDs/random ids count as a defense?
**No** — they raise the bar for guessing, not for authorization, and they leak. Treat them as opaque references, but still **check ownership**.

### Q115. How do I prevent the "v2 guarded, v1 open" gap?
Apply authz **centrally** (middleware/policy layer/gateway) rather than per-handler, deny-by-default, and decommission old API versions. Test every version/representation.

### Q116. How do I stop mass assignment / BFLA?
Allow-list bindable fields (never bind `owner_id`/`role`/`isAdmin` from input); deny-by-default on privileged functions and verify role server-side for every admin/operation endpoint.

### Q117. Defense-in-depth extras?
Consistent 404 (don't leak existence via 403-vs-404), rate-limit object access, log/alert on cross-user access patterns, indirect reference maps for sensitive objects, and automated authz tests (Autorize-style) in CI.

---

# ADDENDUM (rev. 2) — OBFUSCATED & TIME-ORDERED IDS, NESTED/BULK, JSON-PATCH, CORS

### Q118. The ids look random and short (`yr8`, `J4Q`) — am I stuck?
Probably not. That's likely **Hashids / Sqids** — a reversible encoding of a sequential integer, **not** access control. Create 3–4 of your own objects and watch the ids drift *in order* (the tell). The **alphabet + salt are almost always in the front-end JS** (grep the bundle for `Hashids`/`Sqids`/`salt`/the alphabet), or the library **default** salt is used. Recover them → decode B's id → integer → increment → re-encode → **full enumeration** (treat as §6.1 sequential). (§6.6)

### Q119. What about Optimus / "id obfuscation" libraries?
**Optimus** uses Knuth multiplicative hashing: `encoded = (id * PRIME) XOR RANDOM mod 2^31`, with an inverse prime to decode — a **bijection**. Read `PRIME`/`INVERSE`/`RANDOM` from JS/config, or recover them from a handful of `(realId, encoded)` pairs, and you can decode/encode any id → enumerate. Obfuscation ≠ authorization.

### Q120. The id is a UUIDv7 / ULID / KSUID — is it unguessable?
Only the tail. These are **timestamp-prefixed and lexicographically sortable**: UUIDv7's first 48 bits and ULID's first 10 (Crockford-base32) chars are the **creation millisecond**. You usually know roughly when B's object was made (signup/order date, a `created` field, the `Date` header at creation) → set the time prefix to that window and the search collapses to the small random suffix; in bursts, adjacent ids nearly contiguous. Sort known ids to read the cadence. (§7.5)

### Q121. The parent path is mine but there's a child id — worth testing?
Yes — **nested / parent-scoped child IDOR** is one of the most common real bugs. The server validates the **parent** (yours) and trusts the **child**: `/users/{me}/cards/{B's card}`, `/orders/{mine}/items/{not-mine}`. Keep your valid parent, swap **only** the child id. Test *every* id in a multi-segment path, not just the last. (§8.10)

### Q122. Bulk / batch endpoints — any IDOR angle?
Big one. `POST /api/users/batch {"ids":[mine, victim]}` or `?ids=mine,victim` — the server often checks the **first** id (or none) then acts on the whole array → returns/affects the victim's objects, and it's an instant **mass** vector. Mix your id with the victim's. (§8.11)

### Q123. The normal JSON body is filtered — can I still mass-assign?
Try **JSON-Patch** (`application/json-patch+json`, RFC 6902) or **merge-patch** (`application/merge-patch+json`): `[{"op":"replace","path":"/role","value":"admin"}]` or `{"owner_id":<B>}`. The patch handler is frequently a **separate, less-guarded code path** that ignores the form's allow-list. Read the object back to confirm `/role`/`/owner_id`/`/price` stuck. (§9.4)

### Q124. Does a CORS misconfig change an IDOR's severity?
Yes — a **read IDOR + credentialed CORS misconfig** (ACAO reflects the origin + `Access-Control-Allow-Credentials: true`) is **remotely exploitable**: any site the victim visits can `fetch()` their object and exfiltrate it, no attacker auth needed. That pushes it toward `PR:N`/`UI:R` and raises severity. Document the CORS combo (cross-ref the CORS kit).

---

# APPENDIX — 60-SECOND FIELD CHECKLIST
```
[ ] Two accounts I own: A (attacker), B (victim), SAME role (+admin/+2nd tenant if testing BFLA/cross-tenant).
[ ] Mapped every object reference (path/query/body/JSON/header/cookie/GraphQL/file).
[ ] Per object: A's creds + B's reference → B's data? (IDOR) / own? (SAFE) / 403-404? (bypass).
[ ] Bypass toolbox: method · array · pollution · type · path/.json/version · header · wildcard · nested-child · bulk/batch · 403/404 oracle.
[ ] Id format: seq/encoded/hash → enumerate small; hashids/sqids/optimus → decode (salt in JS); uuidv7/ulid/ksuid → time-window; objectid/v1/snowflake → predict; uuidv4 → obtain it.
[ ] Mass-assign also via JSON-Patch / merge-patch (separate code path). Read IDOR + credentialed CORS → remotely exploitable.
[ ] Escalate: read→mass-PII · read→auth-material→ATO/RCE · write→ATO · mass-assign→admin · BFLA→admin→RCE · cross-tenant · blind/2nd-order.
[ ] Two-account PROOF (A's creds, B's object, B's data/changed). FP filter passed.
[ ] CVSS + CWE-639(+285/863/566/915/862). Title = endpoint+reference+impact. Scale stated.
[ ] Benign markers, small proof set, writes reverted, no real-user data. De-duplicated.
```

> **Authorized testing only.** Prove with two of your own accounts, keep enumeration small and polite, cite population from server metadata, revert writes, and report **impact** — whose data, how many, read vs write, ATO/RCE/cross-tenant — not "I changed an id."
