# REST API — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any HTTP/JSON (or XML/form) **REST-style API** — `/api/...`, `/v1/`, `/rest/`, mobile-app backends, SPA
back-ends (`fetch`/`XHR`/`axios`), microservice-to-microservice APIs, partner/B2B APIs, webhooks, and any endpoint
returning `application/json`. Backbone = **OWASP API Security Top 10 (2023)**. First-class: BOLA/BFLA authorization,
broken auth, mass assignment, business-logic/flow abuse.
**Backends:** framework-agnostic (Express/NestJS, Django/DRF, Rails, Spring, Laravel, ASP.NET, FastAPI, Go). Kali/WSL for tooling.
**Companion files in this folder:**
- `REST_API_ARSENAL.md` — copy-paste curl/Burp requests for every OWASP-API category (BOLA sweep, mass-assignment, verb tamper, …)
- `REST_API_CHECKLIST.md` — per-endpoint testing checklist, OWASP-API-ordered
- `REST_API_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — runnable tooling (API discovery, BOLA/authz-diff, mass-assignment fuzzer, method/verb tamper)
- `REST_API_Zero_to_Expert.md` — the 100-question study + field reference Q&A

> ⚖️ **Authorized testing only.** In-scope APIs, your own test accounts (register **two** — you need A and B to prove
> authorization bugs), benign markers, bounded reads, delete artifacts, non-destructive. APIs move real data and money;
> a careless BOLA sweep can pull thousands of real users' PII — don't. Prove the *capability* on a couple of records and stop.

> **Read the basics first.** This is advanced. For fundamentals see the **OWASP API Security Top 10 (2023)**, the
> **OWASP API Security Project** + WSTG, PortSwigger's **API testing** topic, and HackTricks "API" — then use this for depth,
> chaining, and impact.

> **This kit is the API *surface* kit — it cross-references the vuln-class kits instead of duplicating them.**
> BOLA = IDOR for APIs → see `../../Web/IDOR/`. Auth/token = `../../Web/JWT/`. API7 SSRF = `../../Web/SSRF/`.
> Injection through parameters = `../../Web/SQLi/`, `../../Web/CommandInjection/`, `../../Web/SSTI/`, `../../Web/LFI/`.
> Misconfig/CORS/host = `../../Web/CORS/`, `../../Web/HostHeader/`. Resource/flow races = `../../Web/RaceCondition/`.
> Here we go deep on the **API-specific** angle of each and how they chain.

---

## 0. Read this first — why API bugs pay (impact intro)
Modern apps are **thin clients over fat APIs**: the browser/mobile app is a shell, and every object, permission, and
business action is an API call. That inverts the classic web model — the interesting logic and the authorization
decisions all happen at the API, and they are **frequently missing or client-side-only**. That is why APIs are the
single most productive bug-bounty surface today.

The money is in **authorization**, not injection:
- **BOLA (API1)** — change an object ID (`/api/users/1023/invoice` → `1024`) and read/modify *another tenant's* object.
  This is the #1 API bug: trivial to find, **Critical** impact (mass PII, financial records, other users' data), and
  present in a huge fraction of real APIs. Bug-bounty bread-and-butter.
- **BFLA (API5)** — call an admin/privileged **function** as a low-priv user (`POST /api/admin/users`, `DELETE
  /api/orders/{id}`), or flip the HTTP method the UI never uses. → privilege escalation, tenant-wide actions.
- **Broken Authentication (API2)** — weak/forgeable tokens, no rate-limit on OTP/login, credential stuffing,
  JWT flaws → **account takeover**.
- **BOPLA / Mass Assignment + Excessive Data Exposure (API3)** — send `"role":"admin"`/`"isVerified":true` in a body
  the UI never shows → privilege escalation; or the API returns *more fields than the UI renders* (password hashes,
  internal flags, other users' data) → disclosure.
- **Business-flow abuse (API6)** + **resource consumption (API4)** — automate a sensitive flow (coupon, purchase,
  vote, referral) or exhaust a costly endpoint → fraud / DoS.

**Lead your report with impact:** "I read/modified another user's `<object>`", "I performed `<admin action>` as a
normal user", "I took over an account", "I exfiltrated `<N> records of PII`". Not "the endpoint is missing a check."

---

## Master Testing Sequence (the order to actually work in)
1. **Map the API** (§1) — find the base path, the spec (Swagger/OpenAPI/Postman), every endpoint, method, and parameter.
2. **Understand auth** (§2) — token type (JWT/opaque/API-key/session), where it's sent, roles/scopes, multi-tenancy model.
3. **Register two test accounts** (A + B, ideally also an admin/low-priv pair) — you cannot prove authorization bugs with one.
4. **API1 BOLA** (§5) — the highest-yield first pass: swap every object ID A↔B.
5. **API3 BOPLA** (§7) — excessive data exposure (read) + mass assignment (write).
6. **API5 BFLA** (§9) — privileged functions + verb/method tampering as low-priv.
7. **API2 Broken Auth** (§6) — token strength, rate-limits, reset/OTP flows.
8. **API6 / API4** (§10/§8) — business-flow automation + resource consumption.
9. **API7 SSRF** (§11), **API8 Misconfig** (§12), **API9 Inventory** (§13), **API10 Unsafe Consumption** (§14).
10. **Injection & REST-specific tricks** (§15) — verb tamper, method override, content-type confusion, param pollution, injection into params.
11. **Chain & escalate** (§16) → **validate + severity + report** (§17–§19).

---

# PART I — FIND: MAP THE API & ITS AUTH

## 1. Discover the API surface (you can't test what you can't see)
The whole game is **coverage** — most API bugs are on endpoints the UI never calls or the docs forgot. Sources, best→noisy:

**1.1 The spec / documentation (jackpot).** A machine-readable spec hands you every endpoint, method, parameter, and
auth requirement:
```
/openapi.json  /openapi.yaml  /swagger.json  /swagger/v1/swagger.json  /api-docs  /v2/api-docs  /v3/api-docs
/swagger-ui.html  /swagger/  /redoc  /docs  /api/docs  /graphql (if hybrid)  /.well-known/openapi
/postman  *.postman_collection.json   /api/schema/ (DRF)  /rails/info/routes (dev)
```
Import the spec into **Postman/Burp** and you have a testable copy of the *entire* API — including admin endpoints the
UI hides. Missing spec? Reconstruct it (§1.2–1.4).

**1.2 Client-side mining (SPA / mobile).** The front-end *is* the API client — it contains every route it calls.
- JS: pull all `.js`, grep for `fetch(`/`axios`/`XMLHttpRequest`/`$.ajax`/base URLs/`/api/` paths/route tables. See
  `../../Web/JSFiles/` (linkfinder, secret scan, source-map unpack — source maps rebuild the *whole* client incl. unused routes).
- Mobile: pull the APK/IPA (`../../Mobile/Android/ADB/`), decompile (jadx), grep for endpoints + hardcoded keys; proxy the app through Burp.

**1.3 History & fuzzing.** `gau`/`waybackurls`/katana for historical `/api/` URLs; `ffuf`/content-discovery with API
wordlists (SecLists `api/`, `common-api-endpoints`); `kiterunner` (API-route-aware brute — understands `/api/{version}/{resource}`).

**1.4 Enumerate methods & versions.** For every path found, probe **all verbs** (`OPTIONS` often lists `Allow:`) and
**every version** (`/v1/` vs `/v2/` vs `/v3/` — old versions are under-secured, see API9 §13).

**Deliverable of Part I:** a list of `{method, path, params, auth-required, role-required}` for *every* endpoint — that
list is your test matrix. Feed it to the checklist.

## 2. Understand the authentication & authorization model
Before hunting authz bugs you must know **how identity and permission are decided**:
- **Token type & location:** JWT vs opaque bearer vs API key vs session cookie; in `Authorization: Bearer`, a custom
  header (`X-Api-Key`, `X-Auth-Token`), a cookie, or a query param. JWT? → decode it, check claims/roles → `../../Web/JWT/`.
- **Roles & scopes:** how is "admin" vs "user" expressed? A claim, a DB lookup, an OAuth scope? Which endpoints need which?
- **Tenancy:** multi-tenant (org/workspace/account IDs in the path/token)? Cross-tenant access is the juiciest BOLA.
- **Where enforcement lives:** is authorization checked at the **gateway**, per-**controller**, per-**object**, or —
  the vulnerable case — **only in the UI**? APIs that trust "the client wouldn't send that" are where BOLA/BFLA live.

---

# PART II — THE OWASP API SECURITY TOP 10 (2023), IN DEPTH

> Each section = *what it is → find (request-driven, every sub-type) → bypass → impact + CVSS/CWE + real-world →
> escalate → FP auto-reject.* Test in the Master-Sequence order (BOLA first — highest yield).

## 5. API1:2023 — Broken Object Level Authorization (BOLA)  ★ the #1 API bug
**What:** the API exposes an object by an ID from the request and **fails to verify the caller owns/may access that
object**. Change the ID → access someone else's object. (This is **IDOR at the API layer** — the deep IDOR mechanics,
ID-format handling, and enumeration discipline live in `../../Web/IDOR/`; here = the API-specific angles.)

**Find — swap the identifier in every request, as account A, pointing at account B's object:**
```
GET    /api/users/{id}                 GET  /api/orders/{id}          GET /api/v1/accounts/{acct}/statements
GET    /api/users/{id}/profile         PUT  /api/orders/{id}          POST /api/documents/{id}/share
DELETE /api/messages/{id}              PATCH /api/cards/{id}          GET  /api/export?userId={id}
```
The ID appears in: **path segments**, **query params** (`?id=`, `?userId=`, `?account=`), **request bodies**
(`{"orderId": 123}`), **custom headers** (`X-Account-Id`), and **JWT claims vs a body/path value that disagree**.

**Sub-types (test each — this is where "in-depth" pays):**
- **Numeric/sequential IDs** — trivial: increment/decrement. Prove with B's object, then stop.
- **UUID/GUID/hash IDs** — "unguessable" ≠ authorized. BOLA still exists; you just need the victim's ID from *another*
  channel: a share link, a referral, an email, a different endpoint that **leaks** IDs (a list/search endpoint that
  returns other users' object IDs), a `Location` header, an autocomplete. **Find the leak, then BOLA.**
- **Nested / indirect** — `/api/users/me/orders/{orderId}`: the `me` looks safe but `{orderId}` may not be scoped to you.
- **Object in body/JWT mismatch** — server trusts a `userId` in the JSON body over the token's subject → send your token, victim's `userId`.
- **Mass-endpoints** — `POST /api/batch` / GraphQL-style `ids[]` / `?ids=1,2,3` → pull many objects at once.
- **Predictable non-int** — base64(`user:1023`), `md5(email)`, timestamp-based, incrementing UUID v1 → still enumerable.
- **Function-scoped BOLA** — `/api/admin/tenant/{tenantId}/...` where any authenticated user can set tenantId.

**Confirm safely:** as A, request B's object → you get **B's data** (a value only B should see). Two accounts you own =
clean, privacy-safe proof. Screenshot the cross-account read; do **not** iterate the whole ID space.

**Impact:** cross-user/cross-tenant **read** (mass PII/financial → **High–Critical**), **write/delete** (tamper/destroy
others' data → **Critical**). CWE-639 / CWE-284 / CWE-566. CVSS often `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` ≈ 8.1+.

**Escalate:** read → enumerate scope (how many objects, how sensitive) → find a **write** BOLA (higher) → chain with an
**ID-leak** endpoint to weaponize UUIDs → combine with **BFLA** (§9) to act on others' objects via admin functions.

**Real-world:** BOLA is the most-reported API class on every platform; historic cases — Facebook/Instagram object
reads, T-Mobile & Optus-style API data pulls, Peloton/USPS "Informed Delivery"-class user-data APIs, countless
"`/api/v1/users/{id}`" bounty reports. It's #1 for a reason.

## 6. API2:2023 — Broken Authentication
**What:** endpoints that establish or verify identity are weak/forgeable — auth *itself* is broken. → **account takeover**.

**Find & sub-types:**
- **Token weaknesses** → `../../Web/JWT/`: `alg:none`, weak HS secret, RS→HS confusion, `kid`/`jku` injection, no
  expiry, no signature check, token not invalidated on logout/reset. Opaque tokens: predictable, long-lived, leaked in logs/URLs.
- **Credential stuffing / brute** — **no rate-limit** on `POST /login`, `/token`, `/oauth/token`. Test with your own account: does the N-th wrong password still get evaluated? (See races → `../../Web/RaceCondition/`.)
- **OTP / MFA** — no rate-limit on OTP verify (brute 000000–999999), OTP reuse, OTP in the response body, MFA step
  skippable (call the post-MFA endpoint directly = **BFLA-flavored** auth bypass).
- **Password reset** — token predictable/leaked/host-header-poisoned (`../../Web/HostHeader/`), reset without old
  password, reset token not single-use, user-controlled `email`/`userId` in the reset call (BOLA-in-reset → ATO).
- **API keys** — in client-side JS/mobile, in Git, in query strings (logged), never rotated, over-scoped.
- **Session/token fixation, missing logout invalidation, "remember me" forever tokens.**

**Impact:** ATO (own → any → admin). CWE-287 / CWE-307 / CWE-798. **High–Critical.** Prove on **your** account; for
"any account" show the primitive (e.g., unlimited OTP attempts) without actually breaking a stranger's account.

## 7. API3:2023 — Broken Object Property Level Authorization (BOPLA)
Merges two classic bugs: **Excessive Data Exposure** (read too much) + **Mass Assignment** (write too much).

### 7.1 Excessive Data Exposure (read)
**What:** the API returns **more properties than the UI shows**, trusting the client to filter. → disclosure.
**Find:** read the **raw JSON**, not the rendered page. A `/api/users/me` that renders name+email may also return
`passwordHash`, `mfaSecret`, `isAdmin`, `internalNotes`, `ssn`, other users' fields in a list. Diff the JSON vs the UI.
Look at **list/search** endpoints (they often over-return per item) and **object** endpoints.
**Impact:** secret/PII disclosure. CWE-213. Med–High (Critical if it leaks credentials/tokens/other users' data).

### 7.2 Mass Assignment (write)  ★ high-value privesc
**What:** the API binds the JSON body straight onto the model, so you can set **fields the UI never exposes**.
**Find:** take a legitimate `POST/PUT/PATCH` (e.g. profile update, signup, create-order) and **add hidden properties**:
```
{"email":"...","name":"...", "role":"admin", "isAdmin":true, "isVerified":true, "emailVerified":true,
 "accountBalance":999999, "credits":100000, "planId":"enterprise", "userId":<victim>, "orgId":<other-tenant>,
 "status":"approved", "price":0, "discount":100, "permissions":["*"], "is_staff":true, "verified":1}
```
Discover the real field names from: the GET response of the same object, the spec, the JS models, error messages,
`?fields=`/GraphQL, or a leaked admin response. Try **snake_case and camelCase** variants and **nested**
(`{"role":{"name":"admin"}}`, `{"user":{"isAdmin":true}}`).
**Confirm:** re-GET the object → the privileged field **stuck**. Then verify it has effect (you can now reach an admin function, your balance changed, your order price is 0).
**Impact:** privilege escalation, price/limit/verification tampering, cross-tenant writes. CWE-915. **High–Critical.**
**Real-world:** the classic GitHub 2012 mass-assignment (setting another user's public key → repo write); countless
"add `isAdmin:true` to signup/profile" bounty reports; "set `price:0`/`discount:100`" e-commerce logic bugs.

## 8. API4:2023 — Unrestricted Resource Consumption
**What:** an endpoint lets a caller consume disproportionate resources (CPU, memory, money, SMS/email, 3rd-party API
quota) with no limit. → **DoS** or **financial** damage.
**Find:** endpoints with **no rate-limit** and a **cost multiplier**: `?limit=1000000`/`?pageSize=`, deeply-nested
`?include=`/`?expand=` (N+1 explosions), file/image/PDF/report generation, bulk export, GraphQL-style batching,
regex/search inputs (ReDoS), and endpoints that **send SMS/email/push** or call a **paid** upstream (each request = $).
**Test politely:** demonstrate the *primitive* (one huge `limit`, one unthrottled loop of a *few* requests) and the
cost math — **never** run an actual DoS or rack up a real bill. "1 request returns 500 MB / triggers an SMS with no cap"
is enough. CWE-770 / CWE-400. Med–High (High when it's a real money/SMS-bomb or trivial outage).

## 9. API5:2023 — Broken Function Level Authorization (BFLA)  ★ privilege escalation
**What:** the API exposes **functions/actions** (often admin, or another role's) and fails to check the caller's
**role/privilege**. BOLA is about *objects*; BFLA is about *operations*. → privesc, tenant-wide actions.

**Find — as a LOW-priv (or unauth) user, call privileged functions & non-UI methods:**
- **Admin endpoints directly:** `GET/POST/DELETE /api/admin/...`, `/api/internal/...`, `/api/v1/users/{id}/roles`,
  `/api/config`, `/api/feature-flags`, `/api/users/{id}` with `DELETE`. Discover them from the spec / JS / by fuzzing
  `admin|internal|manage|config|settings|role|permission`.
- **Verb/method tampering:** the UI does `GET /api/orders/{id}` — try `PUT`/`PATCH`/`DELETE` on it as a normal user.
  Read-only in the UI ≠ read-only in the API. Also `POST` where only `GET` is shown.
- **Role-scoped functions:** a "manager"-only action (`POST /api/team/{id}/invite`, approve/refund/publish) called by a
  plain member. Also **cross-role**: user calls a *different* user-type's endpoint.
- **Method override:** if `DELETE` is blocked at the edge, try `POST` + `X-HTTP-Method-Override: DELETE` /
  `_method=DELETE` / `X-Method-Override` (§15).
- **Missing-auth entirely:** admin function reachable with **no token** (gateway forgot it).

**Confirm:** as low-priv A, perform the privileged action and verify its effect (a user got created/deleted, a config
changed, B's order got refunded). Use **your own** test objects/tenant for destructive proofs.
**Impact:** privilege escalation, admin takeover, tenant-wide data ops. CWE-285 / CWE-862 / CWE-863. **High–Critical.**
**Real-world:** "call `/api/admin/*` as a normal user", verb-tamper to edit/delete others' resources, "the mobile app
hides the delete button but the API allows it" — extremely common.

## 10. API6:2023 — Unrestricted Access to Sensitive Business Flows
**What:** a business flow that *assumes human pace/quantity* (buy limited stock, apply coupon, refer-a-friend, vote,
book, create accounts) has **no anti-automation**, so it can be run at scale for advantage. Not a code bug — a
**business-logic/design** flaw the API exposes.
**Find:** identify flows where **doing it many/fast times = value or harm**: buying out limited inventory (scalping),
mass coupon/gift-card/referral redemption, review/vote/like inflation, mass account/trial creation, waitlist/queue
jumping, loyalty-point farming. Check for missing rate-limit + missing device/behavior checks + whether the *whole*
flow (not just step 1) is enforced server-side. Races belong here too → `../../Web/RaceCondition/` (limit-overrun via
parallel requests).
**Impact:** fraud, unfair advantage, financial loss. CWE-799 / CWE-841. Med–High (scales with the money involved).
Demonstrate feasibility (a few automated iterations) — don't actually defraud.

## 11. API7:2023 — Server-Side Request Forgery (SSRF)
**What:** the API fetches a **user-supplied URL/host** server-side (webhook, image-from-URL, PDF/HTML render, URL
preview, import-from-URL, SSO metadata, file fetch). → internal access / cloud-metadata creds / RCE.
**Find:** any param that is a URL/host/file: `url=`,`callback=`,`webhook=`,`image=`,`fetch=`,`dest=`,`redirect=`,
`proxy=`,`target=`,`feed=`,`svg`/XML with external entities, PDF generators. **Full technique, bypasses (IP encodings,
DNS rebinding, redirect-to-internal), cloud metadata, gopher/RCE → `../../Web/SSRF/`.** API-specific: webhooks and
"import from URL" are the classic API SSRF sinks; blind SSRF via OOB is common.
**Impact:** cloud metadata → temp creds → account/infra takeover (**Critical**), internal service access, RCE. CWE-918.

## 12. API8:2023 — Security Misconfiguration
**What:** the API stack is misconfigured — a grab-bag that often yields quick wins.
**Find:**
- **CORS** — `Access-Control-Allow-Origin` reflects arbitrary origin **with** `Allow-Credentials:true` → cross-origin
  API theft. Full technique → `../../Web/CORS/`.
- **Verbs/TRACE** — `OPTIONS`/`TRACE` enabled, dangerous methods allowed.
- **Missing security headers**, verbose **error messages** (stack traces, framework versions, SQL errors → §15/`../../Web/SQLi/`).
- **Debug endpoints** — `/actuator/*` (Spring Boot: `/actuator/env`,`/heapdump`,`/mappings`), `/debug`, `/metrics`,
  `/__debug__`, Django debug, Rails `/rails/info`, `.env`/`.git` (→ `../../Web/Recon/`, `../../Web/LFI/`).
- **Default creds / setup pages**, unauthenticated admin dashboards, Swagger UI with "try it out" hitting prod.
- **Host header** trust (cache poisoning / reset poisoning) → `../../Web/HostHeader/`.
**Impact:** varies — CORS theft (High), `/actuator/env` secret leak (**Critical**, often → RCE via property override),
debug info (Med). CWE-16 / CWE-732.

## 13. API9:2023 — Improper Inventory Management
**What:** **forgotten, undocumented, deprecated, or non-prod** API versions/hosts that are less secure than the current
one. The "shadow API" problem.
**Find:**
- **Old versions:** if `/api/v3/` is current, test `/api/v1/`, `/api/v2/`, `/api/beta/`, `/api/internal/` — old
  versions often **lack the authz fixes** applied to the new one (a patched BOLA in v3 may be wide open in v1).
- **Non-prod hosts:** `dev.`, `staging.`, `uat.`, `test.`, `api-internal.`, `sandbox.` (→ `../../Web/Recon/`
  subdomain enum) — weaker auth, real data, debug on.
- **Undocumented endpoints:** in JS/mobile but not the spec; deprecated but still routed.
**Impact:** re-open already-fixed bugs on the forgotten surface; access to real data on non-prod. CWE-1059. Med–High
(inherits the severity of whatever bug the old version still has).

## 14. API10:2023 — Unsafe Consumption of APIs
**What:** the target **trusts a third-party/upstream API** it consumes and doesn't validate that data — so if you can
influence the upstream (or MITM it, or it's compromised), you hit the target. → injection/SSRF-in-reverse.
**Find:** places the app **ingests** external data: webhooks it receives, OAuth/SSO userinfo it trusts, partner APIs,
"connect your X account", data imports. Test whether attacker-controlled upstream data is used unsafely (injected into
queries, rendered, trusted for authz — e.g. trusting an email/`sub` from an IdP without verifying). Follows redirects
from a trusted API to an internal host? → SSRF-flavored.
**Impact:** injection/SSRF/authz-bypass via the trust relationship. CWE-20 / CWE-345. Med–High. (Harder to test
black-box; strong in red-team/partner-integration scenarios.)

## 15. REST-specific techniques (cross-cutting — test on every endpoint)
- **HTTP verb / method tampering:** swap `GET`→`PUT/PATCH/DELETE/POST`; the UI's method ≠ the only allowed method.
  `OPTIONS` reveals `Allow:`. (Feeds BFLA §9.)
- **Method override headers:** `X-HTTP-Method-Override`, `X-Method-Override`, `X-HTTP-Method`, `_method=` (Rails/Laravel)
  — bypass edge rules that only block real `DELETE`/`PUT`.
- **Content-type confusion:** send JSON as `application/xml` (→ **XXE**, see below), as `text/plain` (bypass CSRF/JSON
  checks), as form-encoded; flip `Content-Type` to dodge a parser-based filter or WAF. Some frameworks parse the body
  regardless of the declared type.
- **XXE** (if the API accepts XML): external-entity file read / SSRF → see `../../Web/FileUpload/` (XXE payloads) & `../../Web/SSRF/`.
- **Injection into parameters:** REST params flow into SQL/NoSQL/OS/template/LDAP/path sinks →
  `../../Web/SQLi/`, `../../Web/CommandInjection/`, `../../Web/SSTI/`, `../../Web/LDAP/`, `../../Web/LFI/`. JSON body
  fields, query params, and **path segments** are all injectable.
- **Parameter pollution (HPP):** duplicate params (`?id=1&id=2`, JSON duplicate keys) → parser disagreement → authz/logic bypass.
- **Wildcards / operators:** `?filter=*`, `?role[$ne]=null` (NoSQL operator injection → `../../Web/NoSQLi/`), `?sort=` (SQLi in ORDER BY).
- **Version/format switches:** `.json`/`.xml`/`.csv` extensions, `Accept:` negotiation → different code paths.
- **Pagination/limit abuse:** `?limit=`/`?page[size]=` huge (API4), negative/zero, `?offset=` to walk data.

---

# PART III — IMPACT & ESCALATION

## 16. "You found X → now do Y" (turn a condition into a paid finding)
| You found | Escalate to | Target severity |
|---|---|---|
| **BOLA read** (numeric ID) | Quantify scope → find a **write** BOLA on the same object → chain an ID-leak to weaponize UUIDs | High→Critical |
| **BOLA on a list/search** returning others' IDs | Use it to feed a **UUID BOLA** you couldn't guess before | Critical enabler |
| **Mass assignment** `isAdmin/role` stuck | Now reach an **admin function** (BFLA) → full admin | Critical |
| **Mass assignment** `price/balance/credits` | Complete a purchase at 0 / inflate balance → financial | High–Critical |
| **BFLA** admin function as user | Create an admin account / change your role / act tenant-wide | Critical |
| **Verb tamper** `PUT/DELETE` on others' objects | Edit/destroy other users' data | Critical |
| **Excessive data exposure** (tokens/hashes) | Use the leaked secret → ATO / auth bypass | Critical |
| **Broken auth** (unlimited OTP/reset) | Demonstrate ATO primitive on your account | High–Critical |
| **SSRF** in webhook/import | Cloud metadata → temp creds → infra (see SSRF kit) | Critical |
| **Old version (API9)** | Re-run a *fixed* BOLA/BFLA on `/v1/` → same data, no patch | inherits (often High) |
| **Misconfig `/actuator/env`** | Extract secrets → property-override RCE (SSRF kit chains) | Critical |

**The killer chains:** ① *ID-leak endpoint → UUID BOLA → mass read.* ② *Mass-assignment role → BFLA admin function →
tenant takeover.* ③ *BOLA write on a "user" object → set another user's email → password reset → ATO.* ④ *Excessive
data exposure of a reset/JWT secret → forge tokens.* Always try to reach **ATO / admin / cross-tenant / financial**.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

## 17. False-positive auto-reject (don't submit these as-is)
| Looks like a bug | Why it's NOT (yet) | Make it real |
|---|---|---|
| Changing an ID returns **your own** object / 200 | You must reach **another account's** data | Prove with account **B**'s object (a value only B sees) |
| ID swap returns **403/404/empty** | Authorization is working | Move on (or try UUID-leak/verb-tamper variants) |
| "Sensitive" fields in JSON that are **your own** | Not exposure unless it's **secret** or **someone else's** | Show it returns *another* user's data or a real secret (hash/token) |
| Mass-assignment field **echoed** in the response | Echo ≠ persisted/effective | Re-GET the object; prove the field **stuck** and **has effect** |
| Admin endpoint returns **401/403** to low-priv | Function-level authz is enforced | Move on |
| Missing rate-limit with **no cost/impact** | Not a finding alone | Tie it to OTP/login brute, SMS-bomb, or business-flow abuse |
| Verbose error / version banner | Info-only | Bundle as low, or use it to enable a real bug |
| `OPTIONS`/`TRACE`/missing headers | Usually informational | Only report with a concrete impact |
| Self-XSS / needs victim to paste a token | No cross-user impact | Drop unless you can deliver it |

**Golden rule:** an authorization finding requires **two identities** (A acts on B's object/function). One account can't prove BOLA/BFLA.

## 18. Severity calibration (CVSS + CWE)
```
BFLA → admin/tenant takeover, or BOLA WRITE on others' objects        Critical (9.0+)   CWE-285/639
Broken auth → account takeover (any account)                          Critical–High     CWE-287
Mass assignment → privesc (isAdmin/role) or financial (price/balance) Critical–High     CWE-915
BOLA READ → mass PII / financial / cross-tenant                       High (7–8.5)      CWE-639
Excessive data exposure → credentials/tokens/other users             High–Critical     CWE-213
SSRF → cloud metadata / internal                                      Critical–High     CWE-918
Business-flow abuse / resource consumption (real money/DoS)           High–Medium       CWE-799/770
Old-version (API9) re-opening a fixed bug                             inherits the bug  CWE-1059
CORS cross-origin API theft (with credentials)                       High–Medium       CWE-942
Misconfig / info disclosure (no direct impact)                        Medium–Low        CWE-16
```
Adjust `PR:` (auth required to reach the sink), `S:` (cross-tenant = scope change), and data sensitivity. Lead with the
**demonstrated** impact, not the theoretical ceiling.

## 19. Reporting (see `REST_API_REPORT_TEMPLATE.md`)
Include: exact **request(s)** (method/path/headers/body) for **both** accounts A and B, the **response diff** proving
cross-identity access, the **specific data/field/action** reached, OWASP-API-category + CWE + CVSS, a crisp
reproduction, and the **impact in business terms** ("any user can read any other user's invoices / promote themselves to
admin"). Redact real PII. Note the SAFE-PoC discipline you followed.

## 20. SAFE-PoC discipline (APIs move real data — be careful)
- **Two of your own test accounts** (A, B) for authorization proofs; a low-priv + admin pair for BFLA. Never use a real user's data to "prove" BOLA.
- **Bounded:** read **one or two** cross-account objects to prove the capability — do **not** enumerate/exfiltrate the
  whole ID space (that's a real breach and can get you removed/prosecuted). State the scope ("IDs are sequential, ~N
  users affected") without pulling them all.
- **Non-destructive writes:** for mass-assignment/BFLA/verb-tamper writes, target **your own** test object; for
  "delete/refund/approve" prove on an object you created. Never destroy or alter real users' data.
- **No real DoS / no real fraud / no real SMS-bomb** — demonstrate the *primitive* and do the cost math.
- **Clean up:** delete test accounts/objects/uploads you created; note it in the report.
- **Rate-limit yourself:** automated API testing is loud and can outage a small API — pace it (`../../Web/Recon/` opsec).

---

## 21. Appendix A — API discovery quick-hits
```
Specs:   /openapi.json /swagger.json /v3/api-docs /api-docs /swagger-ui.html /redoc /docs /postman
Methods: OPTIONS <path>  → Allow:  ;  fuzz verbs GET/POST/PUT/PATCH/DELETE per endpoint
Versions:/api/v1 /api/v2 /api/v3 /api/beta /api/internal  (test the OLD ones — API9)
Auth:    decode JWT (jwt.io/hand) → claims/roles ;  find API keys in JS/mobile/Git
Tools:   Postman/Burp (import spec), ffuf+kiterunner (route brute), mitmproxy (mobile), Autorize/AuthMatrix (authz-diff)
```

## 22. Appendix B — the two-account authz matrix (how BOLA/BFLA are actually proven)
Run every sensitive request **four ways** and diff:
```
            as A on A's object   as A on B's object   as low-priv on admin fn   as no-token on any
GET  /x/{id}     200 (baseline)      ← BOLA if 200        ← BFLA if 200            ← missing-auth if 200
PUT  /x/{id}     200 (baseline)      ← BOLA-write if 200   ← BFLA if 200            ← ...
```
Burp **Autorize**/**AuthMatrix** automate exactly this (replay A's traffic with B's token and flag non-403s). The
`poc/authz_diff.py` script does a lightweight version.

## 23. Appendix C — canonical references

**API-specific standards & projects (the backbone)**
- **OWASP API Security Top 10 (2023)** — API1–API10, each with description + CWEs + examples (the spine of this kit).
- **OWASP API Security Project**, **OWASP WSTG** (API sections), **OWASP Cheat Sheets** (REST Security, Mass Assignment, Authorization).

**Learn / go deeper (API-matched)**
- **Corey Ball — "Hacking APIs" (No Starch)** + **APIsec University** (free API-hacking courses & labs) — the canonical modern API-hacking curriculum.
- **Inon Shkedy** — OWASP API Security Top-10 (2023) co-lead; **"31 Days of API Security Tips."**
- **Katie Paxton-Fear (InsiderPhD)** — API-hacking education / methodology.
- **PortSwigger Web Security Academy — API testing** (+ labs: mass assignment, server-side parameter pollution) and **PortSwigger Research**.
- **HackTricks — "API"/"REST"**, **PayloadsAllTheThings — API / Mass Assignment / IDOR**, **The Hacker Recipes**, **PentesterLab** (API badges).

**Research, real-world & practice targets**
- **Sam Curry et al.** — "Web Hackers vs. The Auto Industry" & web3/SSO **BOLA-at-scale** writeups; **Assetnote** — API attack-surface research.
- Real breaches/CVEs (cited in-text): GitHub-2012 mass-assignment, Optus/T-Mobile/Peloton/USPS-class BOLA data pulls; bug-bounty **BOLA/BFLA disclosed reports** (every platform).
- Practice targets: **OWASP crAPI**, **VAmPI**, APIsec University labs.

**Companion kits in this repo** (cross-referenced throughout — the API surface routes into these):
`../../Web/IDOR/` · `../../Web/JWT/` · `../../Web/SSRF/` · `../../Web/SQLi/` · `../../Web/NoSQLi/` · `../../Web/CommandInjection/` · `../../Web/SSTI/` · `../../Web/LFI/` · `../../Web/LDAP/` · `../../Web/CORS/` · `../../Web/HostHeader/` · `../../Web/RaceCondition/` · `../../Web/FileUpload/` · `../../Web/JSFiles/` · `../../Web/Recon/` · `../GraphQL/` · `../../Mobile/Android/ADB/`.

---

> **Bottom line:** a REST API is a pile of `{method, path, params}` guarded — or not — by **authorization**. Map every
> endpoint (spec/JS/mobile/brute), register **two** accounts, and run the OWASP-API-Top-10 in yield order: **BOLA**
> (swap every ID A↔B) → **mass assignment** (add hidden fields) → **BFLA** (call admin functions / tamper verbs) →
> **broken auth** → flows/SSRF/misconfig/inventory. Prove cross-identity impact on **your own** objects, chain to
> **ATO / admin / cross-tenant / financial**, calibrate with CVSS+CWE, and report impact-first. Authorized targets only.
