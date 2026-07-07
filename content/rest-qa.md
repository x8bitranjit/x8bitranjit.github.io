# REST API — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for testing **REST APIs** — from "what is an API bug" to BOLA, BFLA,
> mass assignment, broken auth, business-flow abuse, SSRF, misconfig, inventory, and chaining to ATO / admin /
> cross-tenant / financial impact. Q&A format, progressive difficulty, built on the **OWASP API Security Top 10
> (2023)**. Cross-references the vuln-class kits (IDOR/JWT/SSRF/SQLi/CORS/…) rather than repeating them.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, own labs. Prove authorization bugs with
> **two of your own accounts**, read a **bounded** sample, write only to **your own** objects, no real DoS/fraud, and
> clean up. APIs move real data and money — restraint is mandatory.

**Canonical references** (cited throughout):
- **OWASP API Security Top 10 (2023)** — API1..API10 (the backbone)
- OWASP API Security Project · OWASP WSTG (API) · OWASP Cheat Sheets (REST Security, Mass Assignment, Authorization)
- PortSwigger Web Security Academy — **API testing** (+ labs) · HackTricks "API" · PayloadsAllTheThings (API / Mass Assignment / IDOR)
- CWE-639/285/862/863 (authz), CWE-287 (auth), CWE-915 (mass assignment), CWE-213 (exposure), CWE-918 (SSRF), CWE-770/799 (consumption/flow)
- Companion kit: `API/REST/` (guide + arsenal + checklist + report template + `poc/`) and the Web kits it links to.

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q10)
- **Level 1 — Discovery & mapping** (Q11–Q20)
- **Level 2 — API1 BOLA** (Q21–Q32)
- **Level 3 — API3 BOPLA: mass assignment & data exposure** (Q33–Q42)
- **Level 4 — API5 BFLA & verb tampering** (Q43–Q52)
- **Level 5 — API2 Broken Authentication** (Q53–Q62)
- **Level 6 — API4/API6 consumption & business-flow abuse** (Q63–Q70)
- **Level 7 — API7/8/9/10 SSRF, misconfig, inventory, unsafe consumption** (Q71–Q80)
- **Level 8 — REST-specific & injection** (Q81–Q88)
- **Level 9 — Chaining, tooling, methodology** (Q89–Q95)
- **Level 10 — Severity, false positives, defense** (Q96–Q100)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is a REST API, in attacker terms?
An HTTP interface where **resources** (users, orders, files) are addressed by **URLs** and acted on with **methods**
(`GET` read, `POST` create, `PUT`/`PATCH` update, `DELETE` remove), usually exchanging **JSON**. To you it's a list of
`{method, path, params}` endpoints — each a potential entry point. The app's real logic and authorization live here;
the browser/mobile UI is just a client.

### Q2. Why are APIs the most productive modern bug-bounty surface?
Because apps became **thin clients over fat APIs**: every object and permission is an API call, and developers
routinely **forget server-side authorization** (trusting the UI to hide things). That yields **BOLA/BFLA** —
change an ID or call a hidden function and access others' data/actions — which is trivial to find and Critical in
impact. High reward, low complexity, huge prevalence.

### Q3. What's the single highest-yield API bug?
**BOLA (API1) — Broken Object Level Authorization.** Change an object identifier (`/orders/1001`→`1002`) and the API
serves someone else's object because it never checks ownership. It's #1 on the OWASP API Top 10 and the most-reported
class on every bounty platform.

### Q4. BOLA vs BFLA — what's the difference?
- **BOLA (API1):** *object*-level — you access a specific **data object** you shouldn't (another user's order). "Wrong *which*."
- **BFLA (API5):** *function*-level — you invoke an **operation/endpoint** your role shouldn't (an admin action, a
  state-changing verb). "Wrong *what*."
They chain: BFLA to an admin function that then lets you touch any object.

### Q5. What is the OWASP API Security Top 10 (2023)?
The reference taxonomy this kit is built on:
```
API1 BOLA          API2 Broken Authentication   API3 BOPLA (mass-assign + data exposure)
API4 Unrestricted Resource Consumption          API5 BFLA
API6 Unrestricted Access to Sensitive Business Flows                API7 SSRF
API8 Security Misconfiguration                  API9 Improper Inventory Management
API10 Unsafe Consumption of APIs
```
Notice it's **authorization-heavy** (API1, API3, API5) — that's where the money is.

### Q6. Why do I need TWO accounts?
Because authorization bugs are, by definition, *cross-identity*: "**A** can access **B**'s object/function." With one
account you can only show you access your own data (not a bug). Register A and B (and ideally an admin + low-priv pair
for BFLA) so you can prove — safely, with data you own — that the check is missing.

### Q7. What's the mindset difference vs classic web testing?
Classic web hunts **injection/XSS** in rendered pages. API testing hunts **authorization and logic** in raw JSON
requests. The killer skills are: reading raw responses (not the UI), manipulating IDs/fields/methods, and thinking
about *who is allowed to do what to which object* — then proving the gap with two identities.

### Q8. Is injection dead in APIs?
No — REST params still flow into SQL/NoSQL/OS/template/LDAP/path sinks (Q81). But injection is usually **not** where
API bounties are won; **authorization** (BOLA/BFLA/mass-assignment) is. Test injection, but lead with authz.

### Q9. What do I absolutely need before testing?
An intercepting proxy (Burp/Caido), two+ test accounts with tokens, the ability to send raw requests
(curl/Postman/Python), the API's **endpoint map** (Q11), and knowledge of its **auth model** (Q19). Burp **Autorize**/
**AuthMatrix** for automated authz-diffing.

### Q10. What's the #1 rule of API PoC discipline?
**Prove the capability, then stop.** Read one or two cross-account objects to demonstrate BOLA — never enumerate/
exfiltrate the whole ID space (that's a real breach). Write only to your own objects. No real DoS/fraud. Clean up.

---

# LEVEL 1 — DISCOVERY & MAPPING

### Q11. Why is coverage the whole game?
Because most API bugs live on endpoints the UI never calls and the docs forgot — old versions, admin functions,
internal endpoints. If you only test what the app visibly uses, you miss the vulnerable surface. **Enumerate
everything**, then test it.

### Q12. Where do I find the API's full endpoint list?
Best→noisy: (1) the **machine-readable spec** — `/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/api-docs`,
`/redoc`, `/docs`, Postman collections; (2) **client mining** — the SPA's JS or the mobile app *is* the client, so grep
it for `fetch`/`axios`/base URLs/routes (`../../Web/JSFiles/`, `../../Mobile/Android/ADB/`); (3) **history + brute** —
gau/katana, ffuf, `kiterunner` (API-route-aware).

### Q13. Why is finding the OpenAPI/Swagger spec a jackpot?
It's the **entire API as a document**: every path, method, parameter, and auth requirement — including admin endpoints
the UI hides. Import it into Postman/Burp and you have a runnable, editable copy of the whole attack surface. Always
look for it first.

### Q14. How do I discover which HTTP methods an endpoint allows?
Send `OPTIONS` and read the `Allow:` header, and/or sweep `GET/POST/PUT/PATCH/DELETE` per path. The UI showing a `GET`
does **not** mean `GET` is the only allowed method — a hidden `DELETE`/`PUT` is a BFLA/verb-tamper lead (Q47).

### Q15. What is `kiterunner` and why use it over ffuf for APIs?
`kiterunner` understands API route structure (`/api/{version}/{resource}/{id}`, method-aware, content-type-aware) and
ships API-specific wordlists, so it discovers REST routes that path-only brute (ffuf) misses. Use both; kiterunner for
routes, ffuf for content.

### Q16. How do I get a mobile app's API endpoints?
Pull the APK/IPA, decompile (jadx), grep for endpoints + hardcoded keys, and **proxy the running app** through Burp/
mitmproxy to capture live calls (`../../Mobile/Android/ADB/` for the ADB plumbing). Mobile backends are often
less-tested than the web API and share the same auth flaws.

### Q17. What are "shadow" / "zombie" APIs?
Undocumented, forgotten, deprecated, or non-prod API versions/hosts still routed and reachable (`/api/v1` when v3 is
current; `staging.`/`dev.` hosts). They frequently **lack the security fixes** of the current version — that's OWASP
**API9** (Q79), a cheap way to re-open patched bugs.

### Q18. What should the output of my discovery phase be?
A **test matrix**: for every endpoint, `{method, path, parameters, auth-required?, role-required?}`. That list drives
the checklist — you run BOLA/BFLA/mass-assignment against each row systematically instead of poking randomly.

### Q19. How do I map the authentication/authorization model?
Identify: **token type** (JWT/opaque/API-key/cookie) and **location** (Authorization header/custom header/cookie/
query); **roles/scopes** (how "admin" is expressed); **tenancy** (org/workspace IDs); and **where authz is enforced**
(gateway/controller/object/**UI-only** — the vulnerable case). Decode any JWT to read its claims (`../../Web/JWT/`).

### Q20. Why decode the JWT before testing?
Its claims tell you the **authorization model**: `sub`/`user_id` (your identity for BOLA mismatch tests), `role`/
`scope`/`groups` (what to target with BFLA/mass-assignment), `tenant`/`org` (cross-tenant), `exp` (expiry issues). And
the token itself may be **forgeable** (alg:none/weak-secret/confusion) → straight ATO (`../../Web/JWT/`).

---

# LEVEL 2 — API1 BOLA

### Q21. How do I test for BOLA in one sentence?
As account **A**, take every request that references an object ID and point it at **B's** object — if you get B's data
(or your write lands on B's object), it's BOLA.

### Q22. Where do object IDs hide (beyond the URL path)?
Path segments (`/orders/{id}`), **query params** (`?userId=`,`?account=`), **request bodies** (`{"orderId":123}`),
**custom headers** (`X-Account-Id`), and **JWT-vs-body mismatches** (the server trusts a body `userId` over your
token's subject). Test every location — devs protect the obvious path and forget the header/body.

### Q23. UUIDs are "unguessable" — is BOLA dead there?
No. Unguessable ≠ authorized. You just need the victim's ID from **another channel**: a share/referral link, an email,
a `Location` header, or — most commonly — a **different endpoint that leaks IDs** (a list/search/autocomplete that
returns other users' object IDs). **Find the leak, then BOLA the UUID.** Report both as one chain.

### Q24. What's the difference between read-BOLA and write-BOLA?
Read-BOLA (`GET` another user's object) → disclosure (High). Write-BOLA (`PUT/PATCH/DELETE` another user's object) →
tampering/destruction (**Critical**). Always test the state-changing verbs on the same ID, not just `GET` — write-BOLA
is higher-paying and often overlooked because the UI only does GET.

### Q25. What is "nested" or "indirect" BOLA?
`/api/users/me/orders/{orderId}` — the `me` looks safe, but the child `{orderId}` may not be scoped to `me`. The server
resolves the order by ID globally and forgets to check it belongs to you. Test child objects under a safe-looking
parent.

### Q26. What's the JWT-vs-body-ID BOLA?
The endpoint takes a `userId`/`accountId` in the body or query **and** you send your own valid token. If the server
uses the **client-supplied** id for the operation instead of the **token's** subject, you act as/on another user. Send
your token + victim's id. Classic in reset/profile/export endpoints.

### Q27. How do I safely confirm BOLA without a privacy breach?
Use **two accounts you own**. As A, read **one** of B's objects and show it returns a value only B should see
(B's email/amount/address). Screenshot that single cross-account read. Do **not** iterate IDs to pull real users' data
— proving the missing check on one owned object is sufficient and ethical.

### Q28. The ID swap returns my own data / 403 / 404 — is that a bug?
No (Q97). Returning **your own** object means you didn't actually cross identities. 403/404/empty means authorization
is **working**. A BOLA finding requires B's *actual* data returned to A. Move on (or try UUID-leak/verb/header variants).

### Q29. How do I quantify BOLA scope for the report without exfiltrating?
Reason about the ID space: sequential ints → "IDs run 1..~N, so every user is affected." State the scale from the ID
format + a couple of samples; you don't need to (and must not) pull them all. Scope drives severity without a breach.

### Q30. What are batch/mass BOLA variants?
Endpoints that accept **multiple IDs** — `?ids=1,2,3`, `{"ids":[...]}`, `POST /batch`, GraphQL-style multi-object
queries. One request can pull many objects, amplifying a single BOLA into a bulk read. Test whether per-item
authorization is enforced inside the batch.

### Q31. What real-world breaches were BOLA at heart?
Many high-profile "API returned other users' data" incidents (telco account APIs, delivery/mail user-data APIs,
fitness/social object reads) reduce to BOLA — an `/api/.../{id}` that didn't check ownership. It's the most common
root cause of mass-PII API leaks.

### Q32. How does BOLA chain to account takeover?
Write-BOLA on a "user" object → set **another user's email/phone** → trigger password reset to the value you control →
**ATO**. Or read-BOLA that exposes a reset token / session. Always ask "can this cross-object access reach *auth*?"

---

# LEVEL 3 — API3 BOPLA: MASS ASSIGNMENT & DATA EXPOSURE

### Q33. What is Excessive Data Exposure?
The API returns **more properties than the UI displays**, trusting the client to filter. Read the **raw JSON** and you
find `passwordHash`, `mfaSecret`, `isAdmin`, `ssn`, `internalNotes`, or other users' fields. It's disclosure by
over-return — especially on list/search endpoints.

### Q34. How do I find Excessive Data Exposure?
Compare the **raw API response** to what the UI renders. Hit object endpoints (`/users/me`, `/orders/{id}`) and
**list** endpoints (they often over-return per item), and inspect every field. `?fields=`/GraphQL can reveal the full
model. Secret or cross-user fields = finding.

### Q35. What is Mass Assignment?
The API **binds the request body straight onto the data model**, so you can set fields the UI never sends — `role`,
`isAdmin`, `isVerified`, `price`, `balance`, `credits`, `userId`, `orgId`. Add them to a legit write and the server
writes them. → privilege escalation / financial tampering / cross-tenant writes. CWE-915.

### Q36. How do I discover the hidden field names to inject?
From the **GET response** of the same object (the fields it returns are usually the fields it binds), the **spec**,
the **JS models**, **error messages**, or a leaked admin response. Then try **camelCase + snake_case + nested**
variants (`isAdmin`/`is_admin`/`{"user":{"isAdmin":true}}`) since the framework's naming varies.

### Q37. Which endpoints are the best mass-assignment targets?
**Signup** (set privilege at creation: `role:admin`, `isVerified:true`), **profile update** (`PATCH /users/me`),
**create-order/checkout** (`price:0`,`discount:100`), and any **create/update** that maps JSON to a model. The
sign-up and profile endpoints are the classic privesc wins.

### Q38. The privileged field appears in the response — is it a bug?
Not yet (Q98). **Echo ≠ persisted.** The server may reflect your input without saving it. **Re-GET the object** to
prove the field **stuck**, and then prove it has **effect** (you can now reach `/api/admin/*`, your balance really
changed, your order really costs 0). Persistence + effect = the finding.

### Q39. Give the canonical mass-assignment escalation.
`PATCH /users/me {"role":"admin"}` → 200 → re-GET shows `"role":"admin"` → now `GET /api/admin/users` (previously 403)
returns 200. That's mass-assignment (API3) **chained** to BFLA (API5) = full admin. Report the chain.

### Q40. What's a famous mass-assignment case?
The 2012 GitHub incident: a user mass-assigned another user's public key to a repo via an unfiltered `PUT`, gaining
commit access. It's the textbook example — binding untrusted body fields straight to the model.

### Q41. How is mass assignment different from BOLA?
BOLA = accessing the wrong **object** (authorization on *which* record). Mass assignment = writing forbidden
**properties** on an object (authorization on *which fields*). Both are API3-adjacent authz gaps; mass assignment is
specifically the **property-write** side of BOPLA.

### Q42. What's the safe way to prove financial mass assignment?
On **your own** account/order: set `price:0`/`credits:+X` and show the object persisted the value and the flow honored
it (checkout accepted 0). Don't actually complete a real fraudulent purchase or withdraw inflated balance — demonstrate
the primitive and stop.

---

# LEVEL 4 — API5 BFLA & VERB TAMPERING

### Q43. How do I test for BFLA?
As a **low-priv (or unauthenticated)** user, call **privileged functions** — `/api/admin/*`, role changes, config,
deletes, other roles' actions — and see if they succeed. Discover the endpoints from the spec/JS/fuzzing
(`admin|internal|manage|config|role`).

### Q44. What is HTTP verb tampering and why does it find BFLA?
The UI uses one method; the API may allow more. If the UI does `GET /orders/{id}`, try `PUT/PATCH/DELETE` as a normal
user — the server may enforce authorization on the **read** path but not the **write** verbs. "Read-only in the UI"
often means "wide open in the API."

### Q45. What is HTTP method override and when do I use it?
Headers/params that make a `POST` be treated as another method: `X-HTTP-Method-Override: DELETE`, `X-Method-Override`,
`_method=DELETE` (Rails/Laravel). Use them when the **edge/WAF blocks real `DELETE`/`PUT`** but the framework honors the
override — bypassing the control to reach the privileged verb.

### Q46. What's "missing function-level auth entirely"?
An admin/internal function reachable with **no token at all** — the gateway or controller forgot to require auth.
Always try privileged endpoints unauthenticated; a `200` there is an instant Critical.

### Q47. How do I confirm a BFLA safely?
Perform the privileged action and verify its **effect** — but on **your own** test object/tenant for anything
destructive (create a user then delete *that* one; change *your* config). Show low-priv A caused an admin-only effect.
Never delete/modify real users' resources to "prove" it.

### Q48. BFLA vs mass assignment — how do they combine?
Mass-assignment sets `role:admin` on your account (property-level). BFLA then lets that "admin" call admin functions
(function-level). Chain: elevate via mass-assignment → exercise via BFLA → tenant takeover. Either alone is a finding;
together they're a clean Critical.

### Q49. What are role-scoped (horizontal-function) BFLAs?
A "manager"-only or "seller"-only action called by a plain member (`approve`, `refund`, `publish`, `invite`), or one
user-type calling a **different** user-type's endpoint. Not just user→admin (vertical) but role→role (horizontal).
Test every role boundary.

### Q50. The admin endpoint returns 401/403 to my low-priv token — done?
For that endpoint/method, yes — function-level authz is enforced. But re-test **other methods** (verb tamper), **method
override**, **old versions** (API9 may not enforce it), and **no-token**. A single 403 doesn't clear the function
across all vectors.

### Q51. Why is BFLA often more impactful than BOLA?
BOLA gets you one object at a time; BFLA can get you a **function** that operates on *all* objects/users (bulk export,
user management, config, refunds). Reaching an admin function is frequently **tenant-wide** or **platform-wide** impact
— Critical.

### Q52. How do I find hidden admin functions to test?
Spec (admin paths listed), JS/mobile (admin UI code even if role-gated client-side), fuzzing
(`admin/internal/manage/root/super/config/debug`), old-version enumeration, and the `OPTIONS`/verb sweep on known
paths. The client often **contains** admin code that's only hidden by a client-side role check — read it.

---

# LEVEL 5 — API2 BROKEN AUTHENTICATION

### Q53. What falls under Broken Authentication (API2)?
Anything weak in *establishing or verifying identity*: forgeable/weak tokens, no rate-limit on login/OTP/reset, OTP
reuse, MFA-skippable, predictable/leaked reset tokens, credential stuffing, API keys in client code, sessions not
invalidated on logout/reset. → **account takeover**.

### Q54. How do token attacks fit here?
JWT flaws (`alg:none`, weak HS secret, RS→HS confusion, `kid`/`jku` injection, no expiry, no signature check, no
logout invalidation) let you **forge a valid token** = instant ATO. Opaque tokens: predictable, long-lived, leaked in
logs/URLs/referrers. Full technique → `../../Web/JWT/`.

### Q55. How do I test login/OTP rate-limiting without harming a real user?
On **your own** account: send N wrong passwords / a handful of OTP guesses and observe whether the Nth is still
evaluated (no lockout, no throttle). You demonstrate the **primitive** ("unlimited attempts, no lockout") — you do
**not** brute a stranger's credentials/OTP.

### Q56. What OTP/MFA flaws are common in APIs?
No rate-limit on OTP verify (brute the 6-digit code), OTP **reuse**/no expiry, OTP returned in the **response body**
or a debug field, and **MFA-skippable** flows — where calling the post-MFA endpoint directly (BFLA-flavored) bypasses
the second factor entirely.

### Q57. What password-reset flaws lead to ATO?
Predictable/sequential reset tokens, tokens leaked in the response, **host-header-poisoned** reset links
(`../../Web/HostHeader/`), tokens not single-use, reset without the old password, and **user-controlled target**
(`{"email":"victim","userId":<B>}`) — a BOLA-in-reset that sends *you* the victim's reset. → ATO.

### Q58. Where do leaked API keys come from?
Client-side JS, mobile APK/IPA, public Git repos, and **query strings** (which get logged in proxies/servers/browser
history). Keys that are never rotated or over-scoped turn a leak into broad access. Hunt them in JSFiles/mobile/Git
(`../../Web/JSFiles/`, `../../Web/Recon/`).

### Q59. What's credential stuffing and is it in scope?
Replaying breached username/password pairs against the login API at scale. The **testable finding** is the enabling
condition — **no rate-limit / no bot-protection / no MFA** on login — not actually running a stuffing attack (that's
attacking real users and usually out of scope). Report the missing control with your own-account demo.

### Q60. How do I prove "any account can be taken over" ethically?
Demonstrate the **primitive** on your own account and reason to the general case: "OTP verify accepts unlimited
attempts, so any 6-digit code is brute-forceable in ~X requests" — shown by your own unthrottled attempts, without
actually cracking a stranger's code. Triagers accept the demonstrated primitive + logic.

### Q61. What session/token lifecycle bugs matter?
Tokens not invalidated on **logout** or **password change/reset** (a stolen/old token keeps working), "remember-me"
tokens that never expire, token **fixation**, and refresh tokens that outlive their access tokens without rotation.
Test: log out / change password, then reuse the old token — still 200 = bug.

### Q62. How does broken auth chain with the rest?
Excessive data exposure (API3) leaking a token/hash → forge/replay → auth bypass. BOLA-in-reset (API1) → ATO. Weak JWT
→ forge admin token → BFLA everything. Auth is the hub; many chains terminate in "and therefore account/admin takeover."

---

# LEVEL 6 — API4 / API6 CONSUMPTION & BUSINESS-FLOW ABUSE

### Q63. What is Unrestricted Resource Consumption (API4)?
An endpoint that lets a caller consume disproportionate resources — CPU, memory, bandwidth, **money** (SMS/email/paid
upstream), or 3rd-party quota — with no limit. → DoS or financial damage. Think `?limit=1000000`, nested `?expand=`,
report/PDF generation, and endpoints that send messages or call paid APIs.

### Q64. How do I test API4 without causing an outage or a bill?
Demonstrate the **primitive and the cost math**, not the attack: one request with a huge `limit` returning 500 MB; one
call that triggers an SMS/email with no per-user cap; a nested-`include` that spikes response time. "1 request → N× cost,
no throttle" is the finding. Never actually DoS or spam.

### Q65. What is Unrestricted Access to Sensitive Business Flows (API6)?
A business flow that assumes human pace/quantity (buy limited stock, redeem coupon, refer-a-friend, vote, create
accounts) with **no anti-automation**, so running it at scale gives unfair advantage or causes loss. It's a **design/
logic** flaw, not a code bug.

### Q66. How do I identify an API6 flow?
Ask "does doing this **many/fast** times create value or harm?" — scalping limited inventory, mass coupon/gift-card
redemption, review/vote inflation, mass trial-account creation, loyalty farming, queue-jumping. Then check for missing
rate-limit + missing device/behavior checks + whether the **whole** flow is server-enforced.

### Q67. How do races relate to business-flow abuse?
Many limits are enforced non-atomically ("check then act"), so **parallel** requests overrun them — redeem a
one-time coupon N times, withdraw more than the balance, follow/vote past a cap. That's a **race condition** →
`../../Web/RaceCondition/` (single-packet / parallel_fire). It's the sharpest tool for API6/limit bypass.

### Q68. What severity do API4/API6 carry?
Scales with the **money/impact**: a real SMS-bomb or trivial outage or six-figure fraud flow = High; a soft
rate-limit gap with marginal impact = Low–Medium. Lead with the concrete loss ("each request sends a billed SMS with
no cap" / "coupon redeemable unlimited times = unbounded discount").

### Q69. Can API4 be a straight DoS submission?
Usually **no** — most programs forbid actual DoS and won't pay for "I took you down." Report the **amplification
primitive** (unauthenticated, unthrottled, high-cost endpoint) and the math, not a demonstrated outage. Confirm the
program's stance on resource-exhaustion before any load.

### Q70. What's the safe demo for a coupon/referral abuse?
Run the flow a **few** times (e.g., redeem the same coupon 5× on your own account) to show no single-use/rate
enforcement, and compute the impact ("unlimited → unbounded discount/credit"). Don't actually farm real value or harm
inventory.

---

# LEVEL 7 — API7/8/9/10

### Q71. Where does API SSRF (API7) usually live?
In params that make the server fetch a URL: **webhooks**, **import-from-URL**, image/avatar-from-URL, URL preview/
unfurl, PDF/HTML render, SSO metadata, and file fetch (`url=`,`callback=`,`webhook=`,`image=`,`fetch=`,`dest=`). Webhooks
and "import" are the archetypal API SSRF sinks. Full technique/bypasses/metadata/RCE → `../../Web/SSRF/`.

### Q72. What makes API SSRF Critical?
Reaching **cloud metadata** (`169.254.169.254`) → temporary IAM credentials → cloud account/infra takeover; or internal
services (databases, admin panels, k8s) not exposed externally; or gopher→RCE. SSRF is one of the few API bugs with a
straight path to infrastructure compromise.

### Q73. What quick wins live under Security Misconfiguration (API8)?
**CORS** reflecting arbitrary origin **with** credentials → cross-origin API theft (`../../Web/CORS/`); Spring
**`/actuator/env`,`/heapdump`,`/mappings`** (secrets → often RCE); exposed `.env`/`.git`; verbose stack traces
(versions, SQL errors); default creds; unauthenticated admin dashboards; dangerous verbs/TRACE.

### Q74. Why is `/actuator/env` so dangerous?
It dumps the Spring app's environment — DB creds, API keys, secrets — often unauthenticated. Worse, `/actuator` write
endpoints (`/env`, `/refresh`) can allow **property override → RCE**. Finding it is frequently a Critical on its own and
a pivot to full compromise.

### Q75. What is Improper Inventory Management (API9)?
Forgotten/undocumented/deprecated/non-prod API surface that's **less secure than current**. The classic: `/api/v3` is
patched but `/api/v1` still serves the same data **without the fix**. Also `dev.`/`staging.` hosts with real data and
debug on.

### Q76. How do I exploit API9 concretely?
Take a bug that's **fixed** on the current version (a BOLA that now 403s) and replay it on **`/v1`,`/v2`,`/beta`,
`/internal`** — old versions often lack the patch → same data, no auth. Also test non-prod hosts (subdomain enum,
`../../Web/Recon/`) which frequently expose the whole API unprotected.

### Q77. What is Unsafe Consumption of APIs (API10)?
The target **trusts data from an upstream/third-party API** it consumes without validation. If you can influence that
upstream (a webhook you control, an SSO `userinfo` you can shape, a partner feed), your data flows unsanitized into the
target → injection/SSRF/authz bypass via the trust relationship.

### Q78. Give an API10 example.
An app that trusts the `email`/`sub` from an OIDC provider without verifying the issuer/audience → you log in via a
provider you control and claim a victim's email → account linking takeover. Or a webhook receiver that renders/queries
attacker-sent JSON unsafely. It's trust-boundary abuse.

### Q79. Why does API9 (inventory) punch above its weight in bounties?
Because it **re-opens already-fixed, high-severity bugs** for free — you inherit the BOLA/BFLA severity of whatever the
old version still exposes, without finding a new vuln. Enumerate versions/hosts early; it's low-effort, high-reward.

### Q80. How do I test webhooks safely for SSRF/API10?
Point the webhook/import URL at your **OOB listener** (Interactsh/Burp Collaborator) and watch for the server-side
callback (blind SSRF), then escalate to `169.254.169.254`/internal only with care. For API10, serve controlled data
and see if the target trusts it. Bounded, authorized, OOB-first.

---

# LEVEL 8 — REST-SPECIFIC & INJECTION

### Q81. Is injection still worth testing in REST params?
Yes — JSON body fields, query params, and **path segments** flow into SQL/NoSQL/OS/template/LDAP/path sinks. Test them,
but with the right kit: `../../Web/SQLi/`, `../../Web/CommandInjection/`, `../../Web/SSTI/`, `../../Web/LDAP/`,
`../../Web/LFI/`. Lead with authz; add injection where params look dangerous.

### Q82. What is NoSQL operator injection in an API?
Sending an **operator object** where a scalar is expected: `{"password":{"$ne":null}}`, `{"role":{"$gt":""}}`,
`{"$where":"..."}`. MongoDB-style backends evaluate it → auth bypass / over-match. Classic on JSON login endpoints.
(Full technique — operator vs syntax injection, blind extraction, per-datastore — in `../../Web/NoSQLi/`.)

### Q83. What is content-type confusion?
Sending a body in a different type than declared/expected — JSON as `text/plain` (to dodge CSRF/JSON-only checks), JSON
as `application/xml` (→ **XXE**), or form-encoded — where the framework parses it anyway. It bypasses parser-based
filters/WAFs and can unlock XXE (`../../Web/FileUpload/` payloads) or CSRF.

### Q84. What is HTTP Parameter Pollution (HPP) in APIs?
Supplying a parameter twice — `?id=1&id=2`, or duplicate JSON keys `{"role":"user","role":"admin"}` — so different
layers (WAF vs app, framework vs backend) pick **different** values → authz/logic/validation bypass. Test dup query
params and dup JSON keys on sensitive fields.

### Q85. How can `?sort=`/`?filter=` params be dangerous?
`sort`/`order` params often flow into **SQL `ORDER BY`** (identifier-context SQLi → `../../Web/SQLi/`); `filter`/`q` may
allow operators/wildcards (`*`, `$ne`) → over-match or NoSQLi. Column/field-name params are a classic injection sink
because they're concatenated, not parameterized.

### Q86. What is server-side parameter pollution (the API→internal-API variant)?
Your input is placed into a **server-side** request to an internal API, and you inject extra params/path via `#`, `&`,
`%23`, `%26` to change that internal call (add fields, change the target). PortSwigger's SSPP labs cover it — an
API-specific injection that manipulates the app's own upstream request.

### Q87. Does mass assignment overlap with parameter pollution?
They're cousins: mass assignment adds **unexpected fields** the model binds; server-side param pollution adds
**unexpected params** to a server-side request. Both exploit "the server trusts the shape of my input." Test extra keys
in bodies (mass assignment) and extra params in values that reach internal calls (SSPP).

### Q88. What REST tricks bypass edge/WAF controls?
Method override (`_method`/`X-HTTP-Method-Override`) past verb rules; content-type flip past body filters; case/format
of paths (`/API/` vs `/api/`, `%2e`, trailing `/`, `.json`); param pollution past validators; and **old versions**
(API9) that never had the WAF rule. Always test the same bug across these vectors.

---

# LEVEL 9 — CHAINING, TOOLING, METHODOLOGY

### Q89. What are the highest-value API chains?
① **ID-leak endpoint → UUID BOLA → mass read.** ② **Mass-assignment `role:admin` → BFLA admin function → tenant
takeover.** ③ **Write-BOLA on a user object → change victim's email → password reset → ATO.** ④ **Excessive data
exposure of a token/secret → forge/replay → auth bypass.** Always drive toward ATO/admin/cross-tenant/financial.

### Q90. What's the fastest first-pass methodology on a new API?
Map endpoints (spec/JS/mobile) → register A+B (+admin/low) → **BOLA sweep** every ID A↔B (Autorize) → **mass-assignment**
on signup/profile → **BFLA** on admin functions + verb tamper → **broken auth** (rate-limit/reset) → then flows/SSRF/
misconfig/inventory. Authz first, always.

### Q91. What is Burp Autorize / AuthMatrix and why is it essential?
They **automate the two-account authz test**: configure account B's (or low-priv's) token, browse as A, and the tool
replays every request with B's token and flags any that **don't** get 403 — surfacing BOLA/BFLA across the whole app
without manual per-request swapping. The single biggest force-multiplier for API authz testing.

### Q92. How does the kit's `authz_diff.py` help?
It's a lightweight, scriptable Autorize: give it a file of account-A requests plus tokens A/B, and it replays each as
A / B / no-token and flags same-success-across-identities (the BOLA/BFLA/missing-auth signal). Good for headless/CI or
when you can't run Burp. Confirm flagged leads by hand (§17).

### Q93. How do I test an API that needs complex auth (OAuth, signed requests)?
Capture a **valid** request through the proxy and **replay/modify** it (so the auth is real), rather than crafting from
scratch. For OAuth, get real tokens for A and B via the normal flow. For HMAC-signed requests, you need the signing key
(often in the mobile app/JS) or must replay+tweak within what the signature covers.

### Q94. How do I keep API testing low-false-positive?
Two identities for every authz claim; **persistence + effect** (not echo) for mass assignment; **B's actual data** (not
yours) for BOLA; a **tied impact** for missing rate-limit/misconfig; and re-test flagged leads by hand before
reporting. The FP auto-reject table (§17) is the gate.

### Q95. How do I stay current on API attack techniques?
OWASP API Security Top 10 updates, PortSwigger research + API labs (mass assignment, SSPP), the API-hacking community
(APIsec/"Hacking APIs" material), bounty disclosure reports (BOLA/BFLA writeups), and new framework mass-assignment/
authz CVEs. The classes are stable; the **sinks** (new frameworks, GraphQL/gRPC crossover) evolve.

---

# LEVEL 10 — SEVERITY, FALSE POSITIVES & DEFENSE

### Q96. How do triagers rate the API classes?
```
BFLA→admin/tenant takeover · write-BOLA on others' objects       Critical
Broken auth → account takeover · mass-assignment privesc          Critical–High
BOLA read → mass PII/financial/cross-tenant                       High
Excessive exposure of secrets/tokens · SSRF→metadata              Critical–High
Business-flow/consumption (real money/DoS)                        High–Medium
Old-version re-open (API9)                                        inherits the bug
CORS-with-creds theft · misconfig with impact                     High–Medium
Info disclosure / missing header / no-impact rate-limit           Low
```

### Q97. What are the most common API false positives?
- ID swap returning **your own** object, or 403/404/empty (authz working).
- Mass-assignment field **echoed** but not persisted/effective.
- Admin endpoint correctly **401/403** to low-priv.
- "Sensitive" JSON that is **your own** non-secret data.
- Missing rate-limit / verbose error / `OPTIONS` with **no** tied impact.
- Self-only issues with no cross-user/cross-tenant effect.

### Q98. Why insist on "persistence + effect" for mass assignment?
Because servers often **reflect** input they don't save, and save fields that **do nothing**. Only a **re-GET showing
the field stuck** proves persistence, and only reaching a **privileged capability** (admin function, price 0, changed
balance) proves effect. Echo alone is a non-finding that gets closed.

### Q99. How is BOLA/BFLA fixed (what to write in remediation)?
**Enforce authorization server-side on every object access and every function**, keyed to the **authenticated
principal** (from the session/token) — never trust a client-supplied `id`/`role`. Check ownership/tenancy on each
object; check role/privilege on each endpoint **and every HTTP method**; deny by default. For mass assignment:
**allow-list bindable properties / use DTOs**. For exposure: return only needed fields.

### Q100. Give the one-paragraph defender's summary.
Treat the client as fully attacker-controlled: **authorize every request server-side** against the token's identity —
object-level (ownership/tenancy) for BOLA, function/method-level (role/privilege on all verbs) for BFLA — and **deny by
default**. **Allow-list** which properties a request may set (DTOs) to kill mass assignment; **minimize** response
fields to kill excessive exposure. **Rate-limit and add anti-automation** to auth and costly/business flows. **Validate
and scope** any URL the server fetches (SSRF) and any data it ingests from upstreams. **Inventory and retire** old
versions/hosts. Do that and the entire OWASP API Top 10 — BOLA, BFLA, mass assignment, broken auth, flow abuse, SSRF,
misconfig, inventory, unsafe consumption — collapses.

---

> **Final word:** REST-API hacking is **authorization** hacking. Map every endpoint, get two accounts, and swap IDs
> (BOLA), add hidden fields (mass assignment), call forbidden functions and tamper verbs (BFLA), and break the auth
> flows — then chain to **ATO / admin / cross-tenant / financial** and prove it on your **own** data. Impact-first,
> low-false-positive, authorized targets only, and clean up after yourself.
