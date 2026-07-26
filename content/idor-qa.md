# Insecure Direct Object Reference (IDOR / BOLA) — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

**Author:** x8bitranjit

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
- **Addendum (rev. 2) — obfuscated/time-ordered ids, nested/bulk, JSON-Patch, CORS** (Q118–Q124)
- **Level 7 — Interview questions (articulate it out loud)** (Q125–Q136)
- **Level 8 — Scenario-based (you're handed a situation)** (Q137–Q144)
- **Appendix — 60-second field checklist**

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is IDOR in one sentence?

> *Plain version:* IDOR is a coat-check that hands you whatever coat number you name without checking the ticket is yours — you gave #123 (your coat), you ask for #124, and out comes a stranger's. The login works fine; the missing step is "is this specific object *yours*?"

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

> *Plain version:* authentication is the bouncer checking your ID at the door (works fine — you're logged in). Authorization is the attendant checking that the coat you're claiming is actually yours (missing — that's the bug). IDOR is purely the second failure.

**Authorization.** Authentication = "who are you" (login works fine). Authorization = "are you allowed *this object/action*" (the missing check). IDOR is a pure authorization failure.

### Q7. What's a "direct" object reference vs an indirect one?
**Direct** = the real internal key is exposed (`/orders/8001` where 8001 is the DB PK). **Indirect** = the server maps a per-user handle to the real object (`/orders/my-2nd` resolved server-side against your session). Indirect references *with a server-side ownership map* are the fix; direct references *without a check* are the bug.

### Q8. Does using UUIDs prevent IDOR?

> *Plain version:* a UUID just makes the ticket number long and unguessable — it doesn't make the attendant check the ticket. And those "unguessable" numbers leak constantly (search results, error messages, other API responses). If you can *obtain* the victim's number and the server still doesn't check ownership, it's a full IDOR. "Hard to guess" is not "you're allowed."

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

> *Plain version:* you need **two coats you own** so you can honestly say "I walked in as A and left with B's coat." One account can't prove that — the data you got might be your own or public, and a triager will assume exactly that and close the report.

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

> *Plain version:* instead of grabbing someone's coat, you scribble an extra line on your *own* claim ticket that the system trusts — write "role: admin" or "owner: victim" into the request body. It works because the app often accepts any field you send, not just the ones its form shows. When reads are blocked, writing your way in like this frequently succeeds.

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

> *Plain version:* GraphQL is a coat-check with one giant counter that serves every object type, and the per-object check often lives in each little resolver — easy to forget. Worse, it lets you ask for hundreds of coat numbers *in a single request* (aliases/batching), so it's the ideal place to prove enumeration at scale.

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

> *Plain version:* the move that turns "I read a stranger's record" into a paid Critical — swap the *name tag* on the victim's coat. Change their recovery email to your inbox, hit "forgot password," and the reset link comes to you. Now you're logged in as them. Always confirm the change stuck by re-reading as B; a `200 OK` isn't proof.

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
e.g. `CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` (≈8.x) — scope-changed because you reach other principals' data; high confidentiality; integrity none for pure read.

### Q106. How do I write a title that gets triaged fast?
`IDOR/BOLA on <method> <endpoint> (<reference>) → <impact>` and lead with the highest proven impact + scale. Never "IDOR found."

### Q107. How do I avoid duplicates?
One strong, well-escalated IDOR (with the chain) beats ten "id-swap returns data" dupes. If the program already notes "BOLA on the API," frame your **distinct object/impact** (cross-tenant, ATO chain, BFLA→RCE).

---

# REAL-WORLD CASE PATTERNS & REFERENCES

### Q108. First American Financial (2019) — what happened?
**≈885 million** sensitive financial documents exposed via a **sequential document id** in the URL — change the number, read anyone's documents. The archetypal mass read-IDOR.

### Q109. T-Mobile / Optus / Peloton / USPS — the API-BOLA wave?
T-Mobile (2023): a BOLA on an API exposed ≈37M records. Optus (2022): unauthenticated API enumeration of customer PII. Peloton (2021): API returned account data for any user. USPS Informed Visibility (2018): API exposed ≈60M users. Same root cause every time: **a reference with no object-level check, at scale.**

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

# LEVEL 7 — INTERVIEW QUESTIONS (articulate it out loud)

> These test whether you can *explain* IDOR, not just exploit it. Practise each as a spoken 60–90-second answer.

### Q125. "Explain IDOR to a junior engineer in under a minute."
"Picture a coat-check that hands you whatever coat number you name without checking the ticket is yours. IDOR is that: the app takes a reference you control — an id in the URL, a `user_id` in the body, a filename — and uses it to fetch or change an object **without checking you're allowed that specific object**. You're correctly logged in; that part works. The missing piece is the per-object *authorization* — the code did `WHERE id = :id` instead of `WHERE id = :id AND owner_id = :me`. So I change `id=123` to `id=124` and get a stranger's record. It's the #1 API bug because every endpoint that exposes an id is a fresh chance to forget that check."

### Q126. "IDOR vs BFLA vs mass assignment — explain the difference out loud."
"Same root cause — a missing authorization check — at three different scopes. **IDOR/BOLA** is *wrong object*: I access coat #124 instead of my #123. **BFLA** is *wrong action*: I'm allowed to walk behind the counter and run an admin-only operation like `POST /admin/users`, regardless of object. **Mass assignment / BOPLA** is *wrong property*: I'm allowed the object, but I scribble an extra field on it the form never offered — `"role":"admin"` or `"owner_id":<victim>`. In interviews I say: object, function, property — three flavours of 'the server trusted input it should have authorized.'"

### Q127. "A developer says 'we switched all our ids to random UUIDs, so IDOR is fixed.' Respond."
"UUIDs make the id *hard to guess* — they don't make the server *check ownership*, and those two are completely different problems. IDOR is the missing check, not the guessable id. And 'unguessable' UUIDs leak constantly: in search results, autocomplete, `Referer` headers, error messages, webhooks, and especially other API responses — one over-permissive `{users{id}}` GraphQL query dumps them all. So if I can *obtain* a victim's UUID from anywhere and the endpoint still doesn't verify ownership, it's a full IDOR. The fix isn't the id format; it's `WHERE owner_id = current_user` on every object access."

### Q128. "Why is the two-account proof the thing that makes an IDOR report valid?"
"Because with one account you literally cannot tell 'I accessed someone else's data' from 'I accessed my own or public data' — and neither can the triager, so they'll assume the boring explanation and close it. Two accounts I own create an oracle: I capture **B's** object reference, replay it in **A's** session, and show A received **B's** data. That single artifact — A's credentials, B's object, B's data coming back — is un-false-positive-able. It's why I set up A and B before I touch anything, and why my report leads with 'as A I read B's private order,' not 'I changed an id and saw data.'"

### Q129. "Walk me through how you'd test an unknown API for IDOR."
"Register two same-role accounts, A and B, and proxy both. Drive every feature as each so my proxy captures every object reference — path ids, `?id=`, JSON bodies, `X-User-Id` headers, GraphQL `node(id:)`, file/export URLs. For each object I run the oracle: take A's authenticated request, substitute B's reference, and read the response — B's data is IDOR, my own data is safe session-scoping, a 403/404 sends me to the bypass toolbox (method swap, array-wrap, param pollution, `.json`/`/v1/`, header trust, nested child id). Then I escalate the confirmed ones: is the id enumerable for mass-PII, is there a write verb for ATO, is there a function-level admin version for BFLA, does it cross tenants. I prove everything with my own two accounts, keep enumeration small, and cite scale from `X-Total-Count`."

### Q130. "Why is IDOR/BOLA the #1 API bug, and why won't a WAF fix it?"
"It's #1 because it scales with endpoints and needs no exotic primitive — it's a forgotten line of authz code, and modern apps are thin clients over APIs that expose object ids everywhere, with every new feature a fresh chance to forget the check. A WAF won't fix it because there's **nothing malicious in the request** — `GET /api/orders/124` with a valid token is a perfectly well-formed, 'clean' request; it's only *wrong* because 124 isn't mine, and the WAF has no idea who owns order 124. Authorization is application state the WAF can't see. The only real fix is a server-side per-object ownership check."

### Q131. "Curveball: is IDOR an authentication or an authorization bug, and why does the distinction matter?"
"Authorization, purely. Authentication is 'who are you' — and it works fine; I'm a legitimately logged-in user with a valid session. Authorization is 'are you allowed *this specific object/action*' — and that's the check that's missing. The distinction matters because it points at the fix and the framing: you don't fix IDOR with stronger login, MFA, or better tokens — you fix it by binding every object to its owner on the server. In a report I'm explicit that auth is intact and the failure is object-level authorization (CWE-639), so the developer doesn't go harden the wrong layer."

### Q132. "Explain to a non-technical stakeholder why a 'small' id change is a data breach."
"Think of customer records as numbered filing-cabinet drawers. Normally the system only ever opens *your* drawer for you. This flaw means that once you're a customer, you can ask for drawer number 124 instead of your own 123 — and the system just opens it, no questions asked. Change the number again and you get 125, 126, and so on. So a single logged-in user can page through *every customer's* drawer — names, addresses, payment details — just by counting. That's how breaches like First American happened: 885 million documents, readable by changing a number in the address bar. One missing 'is this yours?' check, multiplied by every record."

### Q133. "How do you turn a single read-IDOR into a Critical? Talk me through the escalation."
"I never stop at the first read. Four questions: **Can I scale it?** — if the id is enumerable or leakable, one read becomes the whole user base (mass-PII, Critical). **Does the object contain auth material?** — a reset token, API key, or session in the body is instant ATO/RCE. **Is there a write verb?** — if I can `PUT` B's email, I point it at my inbox, trigger a reset, and take over the account. **Is there a function-level or cross-tenant version?** — user→admin (BFLA→RCE) or tenant-1→tenant-2 is the jackpot. So the articulation is: read → enumerate → auth-material → write → ATO → admin → cross-tenant, and I report the highest rung I can prove, not the first."

### Q134. "Why can't you just rely on a scanner to find IDOR? What's the human part?"
"Scanners like Autorize give great *coverage* — they replay every request as a second identity and flag look-alike responses — but they can't judge *meaning*. They don't know whether the identical response is B's private data (a bug) or a genuinely public resource (not a bug), whether the id is enumerable, whether there's a write path to ATO, or which victim would make it Critical. They also miss context-dependent bugs — nested child ids, mass-assignment fields, cross-tenant keys, blind second-order sinks. So the tool finds candidates; the human confirms the two-account semantics, discards the public-data false positives, and does the escalation that turns a Medium into a Critical. Tool for breadth, human for validity and impact."

### Q135. "How do you keep IDOR testing ethical and legal — inside safe-harbor?"
"The rule is: prove the *pattern*, not the *population*. I demonstrate the vulnerability with a handful of objects that belong to **my own** two test accounts, then *state* the scale from server metadata — `X-Total-Count`, a max id, a pagination total — rather than actually scraping thousands of real users' PII. Mass-exfiltrating real data can turn research into a CFAA/GDPR problem and blows safe-harbor. I also throttle enumeration, revert any writes, never create persistent admins on production, use my own second tenant for cross-tenant proofs, and stay strictly in scope. The report needs evidence of the missing check, which two of my own accounts provide completely — a data dump adds legal risk and zero additional proof."

### Q136. "Give me three fixes that would prevent the whole class."
"One: **enforce object-level authorization on every access** — bind the object to the caller server-side (`WHERE id=:id AND owner_id=:me`, or a policy/ABAC check), on *every* verb and *every* representation, not just the main GET. Two: **apply authz centrally and deny-by-default** — a middleware/policy layer or gateway rather than a hand-written check in each handler, so you can't forget one and old `/v1/` routes don't run unguarded logic; and allow-list bindable fields so `owner_id`/`role`/`isAdmin` can never be mass-assigned. Three: **don't rely on obscurity and test it** — treat UUIDs/Hashids as opaque references not access control, return consistent 404s so you don't leak existence, and add automated two-identity authz tests (Autorize-style) in CI so a regression is caught before ship."

---

# LEVEL 8 — SCENARIO-BASED (you're handed a situation)

> Each is a situation → what you do next. They mirror how real hunting and interviews probe judgement.

### Q137. Scenario: You swap the id and A's token returns B's data — but the object is a **public profile page**. Do you report it?
Not as-is — a public-by-design object has no authorization expectation, so "A can read it" is not a boundary crossing (a classic false positive, Q102). But don't drop it blindly: check whether the *same* endpoint returns **private fields** alongside the public ones — many `/api/users/{id}` endpoints leak email, phone, address, or internal flags that the public *page* never shows. If A's request for B's profile returns private fields, **that** subset is a real IDOR; report those fields specifically. If it's genuinely only public data, move on. The test is "does it expose something B intended to be private," not "did I get a 200."

### Q138. Scenario: `GET /api/users/8042` returns **403** with A's token. Walk your bypass sequence before concluding "safe."
Work the toolbox in order (§8), re-verifying any success against the two-account oracle: (1) **method swap** — `PUT`/`PATCH`/`POST`/`DELETE`/`HEAD` on the same path; GET-guarded/write-open is common. (2) **array-wrap / param pollution** — `id[]=8042`, `?id=7001&id=8042`, dup JSON keys. (3) **type juggle** — `"8042"`, `[8042]`, `{"$ne":null}`. (4) **path/representation** — `.json`, trailing `/`, `%2e`/case, and especially **old versions** `/api/v1/users/8042`, `/internal/`. (5) **header trust** — `X-User-Id: 8042`, `X-Original-URL`. (6) **nested child** — keep my parent, swap the child: `/api/users/7001/cards/<B's card>`. (7) record the **403-vs-404 oracle** regardless. If a genuine ownership check survives *all* of these, then it's safe — but one row opens a large fraction of "but it 403'd" endpoints.

### Q139. Scenario: You `PUT` B's email and get `200 OK`, but the password-reset link never arrives at your inbox. Debug it.
A `200` is not proof the write landed (§4.2) — so first **re-read B's object as B**: `GET /api/users/8042` with **B's** token. (a) If it still shows B's original email, the write **didn't stick** — the endpoint accepted but ignored the field (allow-list), or wrote to a shadow field; try mass-assign variants (`{"user":{"email":...}}`, JSON-Patch `/email`) or a different update route. (b) If it *does* show your email, the write worked but the **reset flow** differs: maybe reset uses a *separate* verified-email or a phone, maybe it emails the *old* address on change (anti-takeover), or there's a confirmation step. Check whether changing email requires re-verification, and whether a **direct** password/MFA endpoint (`POST /users/8042/password`) skips email entirely. Confirm the actual side effect, don't assume from the status code.

### Q140. Scenario: The ids are short strings like `gY6`, `J4Q`, `oE2`. Walk exactly how you'd attack them.
That drift-in-order is the tell for **Hashids/Sqids** — a reversible encoding of a sequential integer, not access control (§6.6/Q118). Steps: (1) **Confirm the pattern** — create 3–4 of my own objects in a row and watch the ids change predictably. (2) **Recover the alphabet + salt** — grep the front-end JS bundle for `Hashids`/`Sqids`/`new Hashids(`/`salt` and the alphabet string; if none, the **library default salt** (empty) decodes with any decoder. (3) **Decode B's id → integer** (`Hashids(salt=...).decode('gY6')` → `123`). (4) **Increment/decrement → re-encode → replay** in A's session; if I get other users' objects, it's mass-enumerable IDOR — treat exactly like a sequential id. If it's **Optimus** instead (multiplicative), recover `PRIME`/`INVERSE`/`RANDOM` from JS or a few `(realId, encoded)` pairs — it's a bijection. "We obfuscate the id" is not an ownership check.

### Q141. Scenario: The sink is a GraphQL `node(id:)` field. You can read one object — how do you prove **scale** convincingly (and politely)?
Global ids are usually `base64("Type:pk")`, so I decode (`VXNlcjoxMjQ=` → `User:124`), confirm I can read a *different* user's fields by iterating the pk, then demonstrate scale in a **single request** using aliases rather than hammering the endpoint:
```graphql
{ a:node(id:"VXNlcjox"){...on User{email}} b:node(id:"VXNlcjoy"){...on User{email}}
  c:node(id:"VXNlcjoz"){...on User{email}} }        # 3 users, one query
```
That one query returning three different users' emails proves mass-BOLA without a noisy loop. I keep the proof set to a handful (mine + my second account where possible) and **state** the population from a `totalCount`/pagination field, not a scrape. Aliases/batching also often bypass rate-limits (note that as an added finding). Then I test the matching **mutation** (`updateUser(id:<B>,…)`) for write/BFLA.

### Q142. Scenario: You confirm cross-tenant **read** between two orgs you own. How do you make it Critical and not a dupe?
Cross-tenant is almost always Critical (isolation is the core SaaS promise), but I strengthen and differentiate it: (1) **Show read AND write** across the boundary — org-1 reading org-2's record *and* changing a benign marker field, then re-reading as org-2 to confirm the change landed (a write across tenants is strictly worse than a read). (2) **Quantify** — is *every* org-2 object reachable, or just one? Demonstrate the tenant key is the only thing gating it (`X-Tenant-Id` swap, same object id). (3) **Chain to platform-admin** — if a tenant-admin can reach the *platform* admin or a third tenant (BFLA + tenant swap), that's the jackpot. (4) **De-dupe by distinctness** — if the program already lists "BOLA on the API," I frame mine as the *cross-tenant isolation failure with write*, a materially different and higher-impact bug, with the two-org proof front and center.

### Q143. Scenario: A read-IDOR response contains a field `"reset_token": "a1b2c3..."`. What are your next moves, safely?
This jumps straight to Critical — a read that returns **auth material** is ATO, not information disclosure (§11.3/Q84). Moves: (1) **Confirm it's live and usable** — using my **own** two accounts, read B's `reset_token` as A, then complete the reset flow for **my** B account with it (`/reset?token=a1b2c3...`) and show I can set B's password. That proves the token is valid and the chain is real, all on accounts I own. (2) **Don't harvest real tokens** — I demonstrate the capability against my B, then *describe* that the same read yields any user's reset token at scale (cite the enumeration). (3) **Report as Critical ATO** — CWE-639 chained to the takeover, leading with "read-IDOR returns a usable password-reset token → full account takeover of any user," and recommend the token never be serialized into any object response.

### Q144. Scenario: Autorize flags `200 "Bypassed!"` on **40 endpoints**. How do you avoid drowning the triager (and yourself) in false positives?
Autorize flags *look-alike responses*, many of which aren't bugs — so I verify before believing any of them (§19/§20). Triage the 40: (1) **Drop session-scoped ones** — where A-as-B actually returned *A's own* data (the id was decorative); the diff vs B's real view exposes these. (2) **Drop public/static** — shared assets, public profiles, anything with no private data. (3) **Keep the ones where A's response contains B's *specific private* data** — verify by the two-account diff (`A-with-B's-id` == `B's own view`, minus volatile fields). (4) **Rank the survivors by impact** — auth-material/admin/financial/cross-tenant first, then write verbs, then reads — and **report one strong, escalated chain** rather than 40 raw "id-swap returns data" dupes (Q107). Autorize gave me breadth; my job is to convert it into a handful of validated, high-impact findings.

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
