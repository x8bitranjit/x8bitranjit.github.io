# OWASP API Security Top 10 (2023) — In-Depth Testing Reference & Kit Map (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Web APIs — REST/JSON, GraphQL, gRPC, SOAP, webhooks, mobile/SPA backends — anywhere a machine-consumable endpoint takes requests and returns data or performs actions. Covers the API *surface* and routes each risk to the deep per-class kit that owns the hands-on technique.
**Standard:** OWASP **API Security Top 10, 2023** edition (the current list; supersedes 2019). IDs are `API1:2023` … `API10:2023`.
**Platforms:** any; tooling in Kali/WSL + Burp/an API client (Postman/Insomnia/`curl`/`httpie`).

> **This is the API-surface umbrella, sibling of the Web/Mobile/LLM Top 10 docs.** The API Top 10 is a *different frame* from the Web Top 10: it re-centers on the things that make APIs bleed — **object- and function-level authorization** (APIs expose object IDs and privileged operations directly, with no UI to hide behind), **resource consumption**, and **business-flow abuse**. Most concrete vuln-*classes* (injection, SSRF, auth) are shared with the Web kits — so this doc explains each API risk in depth and **routes you to the kit** (`../Web/…` or `REST/` / `GraphQL/`) that carries the payloads and PoC. The mistake is treating an API like a web page; it's a *direct* interface to objects and functions, and authorization is the #1 thing that's broken.

---

> ### ⚡ READ THIS FIRST — how API bugs actually cash out
> 1. **Authorization is the whole game.** Three of the top five are authorization failures: **API1 BOLA** (object-level — swap an ID, read another user's object), **API5 BFLA** (function-level — call an admin endpoint as a peasant), **API3 BOPLA** (property-level — mass-assign `isAdmin`, or over-read hidden fields). APIs hand you the object IDs and the endpoints directly; the only thing between you and other users' data is a server-side check that is frequently missing.
> 2. **No UI means no hiding.** There's no "the button isn't shown" defense — you call the endpoint directly. Enumerate every route (including undocumented/`v1`/`internal` ones — **API9**), every method, every parameter. Shadow/legacy endpoints are where the un-patched bugs live.
> 3. **Two accounts is the master technique.** BOLA/BFLA/BOPLA all fall out of a **two-account differential**: do an action as user A, capture the request, replay it as user B (or against A's objects with B's token). Autorize/Autorepeater automate it. This single method finds the highest-value API bugs.
> 4. **The injection/SSRF/auth classes are shared with Web.** API7 SSRF, injection in resolvers/params, JWT/OAuth auth failures — these *are* the Web kits, reached through a JSON/GraphQL body instead of a form. Follow the sink to the kit.
> 5. **Business logic + resource consumption are API-native.** **API6** (abuse a sensitive flow — buy-all-the-stock, mass-refer, scalp) and **API4** (no rate/size/complexity limits → DoS / denial-of-wallet / brute-force enabler) are where "valid requests" still cause damage. Scanners miss them; you won't.
>
> **Where the money is (memorize):** ① **API1 BOLA → other users' objects → mass data breach — Critical** → ② **API5 BFLA → admin functions as low-priv → privesc/takeover — Critical** → ③ **API3 BOPLA → mass-assignment privesc / excessive-data over-read — High–Critical** → ④ **API2 broken auth → ATO** → ⑤ **API7 SSRF → cloud metadata → RCE/cloud takeover — Critical** → ⑥ **API6 business-flow abuse — High (context)** → ⑦ **API4 resource consumption → DoS/denial-of-wallet + brute enabler** → ⑧ **API8 misconfig / API9 inventory / API10 unsafe-consumption — High→context.**

> 🔰 **In plain words — what the "API Top 10" is, and why it's a separate list from the Web one:** an **API** is the *machine door* to an app — no web page, no buttons, just direct requests that return data or perform actions (it's what a phone app or a site's JavaScript talks to behind the scenes). This is OWASP's list of the *ten most common ways APIs get abused*. It's separate from the Web Top 10 because APIs bleed differently: they hand you the object IDs and the admin endpoints **directly**, so the #1 problem is always the same — the server forgets to check *"is this actually yours / are you even allowed to call this?"* Same rule as ever: this page tells you *what to worry about*; the kits tell you *what to type*.

---

## Table of Contents
- [How to use this list — the API testing method](#how-to-use-this-list--the-api-testing-method)
- [API1:2023 — Broken Object Level Authorization (BOLA)](#api12023--broken-object-level-authorization-bola)
- [API2:2023 — Broken Authentication](#api22023--broken-authentication)
- [API3:2023 — Broken Object Property Level Authorization (BOPLA)](#api32023--broken-object-property-level-authorization-bopla)
- [API4:2023 — Unrestricted Resource Consumption](#api42023--unrestricted-resource-consumption)
- [API5:2023 — Broken Function Level Authorization (BFLA)](#api52023--broken-function-level-authorization-bfla)
- [API6:2023 — Unrestricted Access to Sensitive Business Flows](#api62023--unrestricted-access-to-sensitive-business-flows)
- [API7:2023 — Server-Side Request Forgery (SSRF)](#api72023--server-side-request-forgery-ssrf)
- [API8:2023 — Security Misconfiguration](#api82023--security-misconfiguration)
- [API9:2023 — Improper Inventory Management](#api92023--improper-inventory-management)
- [API10:2023 — Unsafe Consumption of APIs](#api102023--unsafe-consumption-of-apis)
- [Category → Kit quick map](#category--kit-quick-map)
- [Severity calibration & reporting](#severity-calibration--reporting)
- [References](#references)

---

# How to use this list — the API testing method

```
0. DISCOVER THE SURFACE (API9): enumerate every endpoint, version, method, and parameter — docs/Swagger/OpenAPI,
   JS bundles, mobile app decompile, traffic capture, path/param brute. Find shadow/legacy/internal/vN routes.
1. AUTHZ FIRST (API1/API5/API3): with TWO accounts, differential-test every object ref and every function:
   - BOLA (API1): swap object IDs (own → victim) → other users' data.
   - BFLA (API5): call privileged/admin endpoints + tamper the HTTP method as a low-priv user.
   - BOPLA (API3): mass-assign extra properties (role/isAdmin/price) + look for over-returned hidden fields.
2. AUTH (API2): token issuance/validation — JWT flaws, weak/ξreset flows, credential stuffing, no rate limit. → JWT/OAuth kits.
3. INJECTION / SSRF (API7 + shared classes): the JSON/GraphQL body is just another injection surface → SQLi/NoSQLi/
   cmdi/SSTI in resolvers & params; server-fetch sinks (webhooks, url params) → SSRF → metadata.
4. RESOURCE + BUSINESS FLOW (API4/API6): missing rate/size/complexity limits → DoS/brute/denial-of-wallet; abuse the
   intended flow at scale (buy-all, refer-abuse, scalp, coupon-stack).
5. CONFIG + CONSUMPTION (API8/API10): misconfig (CORS/headers/verbose errors/no TLS); does the API blindly trust data
   from OTHER (third-party/upstream) APIs it consumes?
6. VALIDATE: prove IMPACT with two accounts + benign markers — "as user A I read/modified user B's <object>", not "the
   endpoint returned 200".
```

**Golden rule:** an API is a *direct, UI-less interface to objects and functions.* The Web Top 10 asks "what can this page be tricked into"; the API Top 10 asks "**whose object / which function can I reach that I shouldn't**." Authorization (API1/API3/API5) is the top of the list because it's the thing APIs break most and hardest.

---

# API1:2023 — Broken Object Level Authorization (BOLA)

**What it is.** The API exposes object identifiers (in the path, query, body, or headers) and fails to verify that the **authenticated caller is authorized for that specific object**. Change the ID → access someone else's object. This is the API-native name for **IDOR**, and it is the **#1 most common and impactful API vulnerability** — APIs hand out object references directly, so a missing per-object check is immediately exploitable.

> *In plain words:* BOLA = **IDOR for APIs**. The API lets you name an object by its ID (`/orders/123`) and forgets to check that order is *yours* — so change 123 to 124 and read a stranger's order. It's #1 because APIs hand out IDs directly and this ownership check is the single most commonly-missing thing.

**Why it pays / impact.** **Mass data breach** and **cross-tenant access**: iterate `/api/users/{id}`, `/orders/{id}`, `/accounts/{id}/statements` → read/modify every user's data; horizontal (other users) and cross-tenant (other customers). Often trivially automatable → bulk PII/financial exfiltration. Consistently the top source of Critical API findings and real-world breaches.

**How to test (+ the kit that owns it).**
```
□ Two-account differential (the core method): perform an action as user A, capture the request, then replay it with
   user B's session against A's object IDs — is it blocked? (Autorize/Autorepeater automate this.) → ../Web/IDOR/
□ Swap IDs everywhere: path (/users/123), query (?id=123), body ({"user_id":123}), headers (X-Account-Id), nested JSON,
   GraphQL node(id:) / *ById. Try victim IDs, adjacent IDs, and enumerated ones.
□ ID formats: numeric (increment), UUID (leak elsewhere then reuse), hashed/encoded (decode → tamper), composite keys.
□ Indirect/second-order BOLA: an ID accepted in step 2 of a flow that wasn't checked against step-1 identity.
□ Read AND write: GET (disclosure), PUT/PATCH/DELETE (tamper/destroy other users' objects) — test all verbs.
□ GraphQL: node(id:), object-by-id resolvers, and IDs surfaced by one query reused in another. → GraphQL/
```

**Real-world / examples.** BOLA in banking/social/health APIs enabling mass account access; the classic `/{id}` increment; UUIDs harvested from one endpoint and replayed at another; GraphQL `node(id:)` cross-object reads; the majority of high-bounty API reports.

**Prevention.** Enforce **per-object authorization on every request** — check the authenticated principal owns/may access the specific object, server-side, at the data layer (not by object obscurity); prefer random/unguessable IDs *and* an ownership check (defense-in-depth, not obscurity alone); centralize the authz check so no endpoint forgets it; test authz systematically (two-account diffs in CI).

**Kits.** `../Web/IDOR/` (the primary kit — BOLA/IDOR method + automation), `GraphQL/` (node/by-id BOLA), `REST/` (API1 surface), `../Web/JWT/` (if the object key rides in a tamperable token).

---

# API2:2023 — Broken Authentication

**What it is.** Weaknesses in **confirming the caller's identity** — the API's authentication mechanisms (login, tokens, API keys, session, credential recovery) are implemented incorrectly, letting attackers assume other identities. Includes weak/leaked API keys, JWT flaws, credential stuffing exposure (no rate limit/lockout), weak password/reset flows, and token mismanagement.

> *In plain words:* the "who are you?" check is broken — guessable API keys, forgeable tokens, unlimited login tries, hijackable reset flows. It's the front gate: get past it and you're whoever you want to be. (Same idea as the Web auth bucket, just reached over an API.)

**Why it pays / impact.** **Account takeover** and **impersonation** at the identity layer: forge/steal a token → act as any user; brute/stuff credentials with no rate limit → mass ATO; weak reset → hijack; a leaked long-lived API key → full backend access. The entry gate — break it and everything behind it is yours.

**How to test (+ the kit that owns it).**
```
□ JWT flaws: alg:none, weak/guessable HS256 secret (crack it), RS256→HS256 confusion, kid/jku/x5u injection, no
   signature check, no expiry, claim tampering (sub/role). → ../Web/JWT/
□ OAuth/OIDC/SSO: redirect_uri bypass, state/CSRF, code/token theft, PKCE downgrade, id_token forgery. → ../Web/OAuth/
□ Credential stuffing / brute: is there rate limiting + lockout on login/token/OTP/reset? (no limit → mass ATO, ties API4).
□ Password reset / recovery: host/link poisoning, predictable/leaked tokens, response-flip. → ../Web/AccountTakeover/
□ API keys: leaked in JS/mobile/repos? long-lived? least-privilege? revocable? (recover one → test its reach). → ../Web/JSFiles/
□ Token handling: transmitted securely? server-side revocation on logout? refresh-token rotation? replay?
□ Auth on EVERY endpoint: any route that skips auth entirely (unauthenticated access to authed data)?
```

**Real-world / examples.** JWT `alg:none`/weak-secret impersonation; OAuth `redirect_uri` token theft; unlimited-OTP 2FA bypass; leaked API keys in mobile apps / JS bundles → backend access; password-reset poisoning → ATO; endpoints missing auth entirely.

**Prevention.** Standard, vetted auth (don't roll your own); strong JWT validation (verify signature + `alg` + `exp` + `aud`/`iss`; no `none`); rate limiting + lockout + MFA on all auth/OTP/reset endpoints; short-lived, revocable, rotated tokens; scoped, revocable API keys (never client-embedded as secrets); secure reset flows (host-independent links, strong tokens); authenticate every non-public endpoint.

**Kits.** `../Web/JWT/` (token auth crypto), `../Web/OAuth/` (federated auth), `../Web/AccountTakeover/` (reset/OTP/session flows), `../Web/JSFiles/` (leaked keys), `REST/` (API2 surface).

---

# API3:2023 — Broken Object Property Level Authorization (BOPLA)

**What it is.** The API fails to authorize access at the **property (field) level** — a merge of the old "Excessive Data Exposure" and "Mass Assignment." Two directions: **over-reading** (the response returns object properties the caller shouldn't see — the API dumps the whole object and expects the client to filter) and **over-writing** (the caller can *set* properties they shouldn't — mass-assign `role`/`isAdmin`/`balance`/`verified` by adding them to the request body).

> *In plain words:* the API checks *which object* you can touch, but not *which fields*. Two flavours: it **hands back** fields you shouldn't see (a password hash the app hides only on-screen), or it **lets you set** fields you shouldn't — add `"isAdmin":true` to the save request and become an admin. "Mass assignment" = the app blindly saves whatever fields you send it.

**Why it pays / impact.** **Privilege escalation** (mass-assign `isAdmin:true`, `role:admin`, `account_type:premium` → become admin / unlock paid features), **price/limit tampering** (set `price:0`, `discount:100`), **state forgery** (`verified:true`, `approved:true`), and **sensitive-data disclosure** (the response leaks internal fields — password hashes, other users' PII, internal flags, tokens — because the API returns the full object). High-to-Critical, and easy to miss because the request/response look normal.

**How to test (+ the kit that owns it).**
```
OVER-WRITE (mass assignment):
  □ Add unexpected properties to create/update bodies: {"role":"admin"}, {"isAdmin":true}, {"verified":true},
     {"price":0}, {"balance":99999}, {"user_id":<other>}, {"status":"approved"}. Did the server accept + persist them?
  □ Discover property names: read a GET response / docs / mobile app to learn the full object schema, then set those
     fields on write. Try nested + array forms. Confirm persistence with a follow-up read. → ../Web/IDOR/ (mass-assign)
OVER-READ (excessive data exposure):
  □ Inspect full responses: does the object include fields the UI never shows — hashes, PII, internal IDs, tokens,
     flags, other-user data? The API returning them = the finding (don't rely on client-side filtering).
  □ Compare roles: does a low-priv caller get the same fat object as an admin?
GraphQL: over-selection of fields; introspect the schema and request sensitive fields directly. → GraphQL/
```

**Real-world / examples.** Mass-assignment privilege escalation (`isAdmin`/`role` in the body — a classic across frameworks); GitHub's historical mass-assignment; APIs returning full user objects (password hashes/PII) and hiding them only in the UI; setting `price`/`discount` on an order; GraphQL over-fetching sensitive fields.

**Prevention.** Explicit **allow-list of writable properties** per role/endpoint (bind only permitted fields — never blind `Model.update(req.body)`); explicit **allow-list of returned properties** (schema/DTO/serializer per role — never return the raw object and filter client-side); validate the caller may read/write *each* field; in GraphQL, field-level authorization; least-data responses.

**Kits.** `../Web/IDOR/` (mass-assignment + property-level authz — the `massassign_fuzz` method), `GraphQL/` (field over-selection/over-fetch), `REST/` (API3 surface — BOPLA is the REST kit's core), `../Web/PrototypePollution/` (adjacent: `__proto__` property injection).

---

# API4:2023 — Unrestricted Resource Consumption

**What it is.** The API serves requests **without limiting the resources they consume** — no rate limits, no request-size/response-size caps, no query-complexity limits, no quotas/spend caps — so a client can drive excessive CPU/memory/bandwidth/storage/third-party-cost. Formerly "Lack of Resources & Rate Limiting."

> *In plain words:* the API never says "that's enough." No cap on how fast, how big, or how expensive your requests are — so you can knock it over (DoS), run up its cloud bill (denial-of-wallet), or — the sneaky one — brute-force passwords/OTPs because nothing stops you trying a million times.

**Why it pays / impact.** **DoS** (resource exhaustion downs the service), **denial-of-wallet** (each request costs money — third-party API calls, SMS/email sends, compute — unbounded = unbounded bill), and — the frequently-overlooked security impact — **rate-limiting absence is the enabler for API1/API2 attacks** (BOLA enumeration, credential stuffing, OTP/token brute-force all require volume). Also **amplification** (small request → huge work: pagination `limit=99999999`, deep GraphQL nesting, expensive filters/exports).

**How to test (+ the kit that owns it).**
```
□ Rate limiting: hammer an endpoint — is there a per-user/per-IP limit? (missing = brute/enumeration/DoS enabler;
   the method overlaps rate-limit/limit-overrun testing → ../Web/RaceCondition/)
□ Request/response size: huge payloads, huge pagination (limit/page_size=<absurd>), unbounded batch/bulk operations.
□ Complexity/amplification: deeply nested GraphQL queries, aliased/batched queries (1 request → thousands of ops),
   expensive filters/sorts/exports/report-generation. → GraphQL/ (query-depth/alias/batch DoS)
□ Cost-driving actions: endpoints that send SMS/email, call paid third-party APIs, or spin compute — unbounded =
   denial-of-wallet. Quantify $/request × unlimited.
□ File/upload limits: unbounded upload size/count → storage exhaustion.
□ Concurrency: many parallel expensive requests.
```

**Real-world / examples.** No-rate-limit OTP/login → brute-force ATO; GraphQL query-depth/batching DoS; pagination `limit=<huge>` memory exhaustion; denial-of-wallet on SMS/email/paid-API endpoints; unbounded bulk export.

**Prevention.** Enforce rate limits + quotas per user/key/IP; cap request/response size, page size, array/batch length, and file size/count; **query-complexity + depth limits for GraphQL**; timeouts + resource ceilings on expensive ops; spend caps / cost circuit-breakers on cost-driving actions; throttle + alert on anomalous volume.

**Kits.** `../Web/RaceCondition/` (rate-limit/limit-testing method), `GraphQL/` (depth/alias/batch complexity DoS), `REST/` (API4 surface), and it's the *enabler* to note alongside `../Web/AccountTakeover/` (brute/OTP) and `../Web/IDOR/` (BOLA enumeration).

---

# API5:2023 — Broken Function Level Authorization (BFLA)

**What it is.** The API fails to enforce authorization on **functions/operations** — a user can invoke endpoints or actions **above their privilege level** (admin functions, other roles' operations) or use **HTTP methods** they shouldn't. Where BOLA is "whose *object*," BFLA is "which *function*." Includes reaching admin/privileged endpoints as a normal user and **verb/method tampering**.

> *In plain words:* BOLA was "whose *object*"; BFLA is "which *function*." A normal user calls an **admin-only** endpoint (`/admin/promote`) and the server just does it, because it never checked your rank. There's no hidden button stopping you — you call the endpoint directly.

**Why it pays / impact.** **Privilege escalation** and **admin takeover**: call `/api/admin/*`, `/api/users/{id}/promote`, `/api/internal/*` as a low-priv (or unauthenticated) user → create admins, delete data, change roles, access management functions → full application compromise. There's no UI hiding the endpoint — if the server doesn't check role, you're in.

**How to test (+ the kit that owns it).**
```
□ Reach privileged endpoints as low-priv: enumerate admin/management/internal routes (/admin, /internal, /manage,
   /v1/users/{id}/role) — call them with a normal-user token. Is role checked server-side? → ../Web/IDOR/ (BFLA) + REST/
□ Guess by pattern: if GET /users/{id} exists, try POST/PUT/DELETE /users/{id}, /users/{id}/promote, /users (list all).
□ HTTP method/verb tampering: swap GET↔POST↔PUT↔DELETE↔PATCH; X-HTTP-Method-Override / _method to smuggle a
   privileged verb past a method-scoped control.
□ Role/tier crossing: can a "user" call "moderator"/"admin"/"support" functions? cross-role, not just up.
□ Unauthenticated function access: any privileged endpoint reachable with NO token at all?
□ GraphQL: privileged mutations (deleteUser, setRole, adminX) callable by a low-priv session. → GraphQL/
```

**Real-world / examples.** Admin endpoints callable by normal users (create-admin, role-change); HTTP verb tampering bypassing method-scoped auth; `/internal`/`/debug` routes reachable externally; GraphQL admin mutations with no role check; unauthenticated privileged endpoints.

**Prevention.** Deny-by-default; enforce **function/role authorization server-side on every endpoint and every method** (centralized, not per-controller ad-hoc); explicitly check role/permission for privileged operations; don't rely on the route being unguessable or the UI hiding it; treat every HTTP method on a route as separately authorized; review admin/internal routes for external reachability.

**Kits.** `../Web/IDOR/` (BFLA/authz + method tampering), `REST/` (API5 — verb/method-override tampering is a REST-kit focus), `GraphQL/` (privileged mutations), `../Web/AccountTakeover/` (as an outcome — admin function → ATO).

---

# API6:2023 — Unrestricted Access to Sensitive Business Flows

**What it is.** The API exposes a **sensitive business flow** (purchase, booking, reservation, comment/review, referral, voting, ticket-buy, withdrawal) **without compensating for automated/excessive use** — the individual requests are all "valid," but the *flow* can be abused at scale in a way that harms the business. New in 2023; the "business logic at scale" category. The flaw is a *missing anti-automation/design* control, not a broken request.

> *In plain words:* every single request is legit — the abuse is doing it **a million times with bots**. Buy every concert ticket to scalp them, farm a referral bonus with 10,000 fake accounts, stack coupons. Nothing is "hacked"; the flow just has no brakes against automation.

**Why it pays / impact.** **Business/financial harm** from automated abuse: **scalping/hoarding** (bots buy all limited stock — tickets, sneakers, GPUs → resale), **inventory/DoS-of-business** (reserve everything, never pay), **referral/coupon/loyalty abuse** (mass-create accounts to farm rewards), **review/vote manipulation**, **spam**, **gift-card/credit draining**. Not a "hack" in the injection sense — it's the intended flow, weaponized by automation. Impact is real money; severity is context-driven.

**How to test (+ the kit that owns it).**
```
□ Identify sensitive flows: purchase/checkout, booking/reservation, signup/referral, review/rating/vote, withdrawal/
   transfer, ticket/limited-stock buy, promo/coupon redemption.
□ Automate it: script the flow — can you run it hundreds of times, in parallel, from one or many accounts, faster than
   a human? Are there anti-automation controls (CAPTCHA, device/velocity checks, per-user caps, rate limits)?
□ Scale abuse: buy/reserve all stock; mass-create accounts to farm referrals/coupons; stack promos; inflate votes.
□ Race the flow (overlap with limit-overrun): redeem-once/one-per-user enforced under parallelism? → ../Web/RaceCondition/
□ Cost/impact model: quantify the business harm (stock denied, rewards farmed, revenue lost) for the report.
```

**Real-world / examples.** Sneaker/ticket/console scalping bots; mass referral-bonus farming; coupon/promo stacking and abuse; fake-review/vote inflation; reserve-all-inventory denial-of-business; loyalty-point/gift-card draining.

**Prevention.** Identify sensitive flows and add **anti-automation** proportionate to the risk: device fingerprinting/attestation, CAPTCHA/challenge on abuse signals, per-user/per-payment-method/per-device velocity limits and quotas, human-review for anomalies, and business-rule enforcement (one-per-customer, hold-then-confirm). Design the flow assuming a bot will run it a million times.

**Kits.** `../Web/RaceCondition/` (the limit-overrun/one-per-user race side), `REST/` (API6 business-flow surface), `../Web/AccountTakeover/` (mass-account-creation angle); otherwise a **business-logic methodology** category (a dedicated Business-Logic kit is a planned addition).

---

# API7:2023 — Server-Side Request Forgery (SSRF)

**What it is.** The API **fetches a remote resource from a client-supplied URI without validating it**, so the server can be induced to send requests to attacker-chosen destinations. APIs are especially SSRF-prone because modern features constantly fetch URLs: webhooks, "import from URL," URL previews, file/image fetch-by-URL, SSO/OIDC metadata & JWKS URLs, PDF/screenshot generators, and third-party integrations.

> *In plain words:* you give the API a URL and it fetches it *for you* from inside the network — so you reach internal-only spots like the cloud metadata address that hands out master keys. APIs are especially prone because they're forever fetching URLs (webhooks, "import from URL", link previews).

**Why it pays / impact.** The **cloud-era Critical**: SSRF → **cloud metadata** (`169.254.169.254`) → IAM credentials → **cloud account takeover / RCE**; SSRF → **internal services** (admin panels, Redis, Elasticsearch, databases, other internal APIs) → RCE/lateral movement; internal **port scan** / info disclosure; **blind SSRF** → OOB confirmation → chain. APIs' webhook/URL-fetch features make this one of the highest-value modern API bugs.

**How to test (+ the kit that owns it).**
```
□ Find server-fetch sinks: any parameter that is a URL/host/resource the server retrieves — webhook_url, callback,
   image_url, import_url, avatar, source, ?url=, SSO metadata/JWKS URLs, XML (XXE→SSRF), PDF-from-HTML. → ../Web/SSRF/
□ Reach internal/metadata: 169.254.169.254 (AWS/GCP/Azure — mind IMDSv2), localhost/127.0.0.1, internal IP ranges,
   internal hostnames, cloud endpoints → IAM creds → cloud takeover. → ../Web/SSRF/
□ Bypass allow-lists/filters: DNS rebinding, redirect-to-internal (open redirect on an allowed host → ../Web/OpenRedirect/),
   IP encodings (decimal/hex/octal), IPv6, userinfo (@) tricks, alternate schemes.
□ Blind SSRF: OOB (interactsh/collaborator) confirmation; gopher:// / dict:// for internal-protocol smuggling → Redis/DB.
□ SSRF via adjacent classes: XXE (../Web/XXE/), Host-header routing (../Web/HostHeader/), OAuth request_uri/JWKS
   (../Web/OAuth/); and note the LLM twin: agent fetch-tools (../AI/LLM/ LLM06).
```

**Real-world / examples.** Capital One (SSRF → metadata → S3 dump); webhook/URL-import SSRF to cloud metadata across bug bounties; gopher-SSRF to internal Redis → RCE; JWKS/OIDC-metadata SSRF; redirect-based allow-list bypass.

**Prevention.** Avoid fetching client-supplied URLs where possible; if required, **allow-list schemes/hosts/ports and re-validate after every redirect**; block internal ranges + metadata IPs at the network layer (egress filtering, enforce IMDSv2); resolve-and-pin DNS to defeat rebinding; disable unused schemes (gopher/file/dict); isolate the fetcher service; never return the raw fetch response to the caller.

**Kits.** `../Web/SSRF/` (the core kit), `../Web/OpenRedirect/` (redirect allow-list bypass), `../Web/XXE/` (XXE→SSRF), `../Web/HostHeader/` (routing SSRF), `REST/` (API7 surface), `GraphQL/` (SSRF via resolver/URL args).

---

# API8:2023 — Security Misconfiguration

**What it is.** Insecure or default configuration anywhere in the API stack — servers, gateways, frameworks, cloud — including missing security hardening, unnecessary features/HTTP methods enabled, **permissive CORS**, missing/misapplied security headers, verbose error messages leaking stack traces/internals, unpatched systems, missing TLS, and improper handling of untrusted input at the transport/parsing layer (content-type/HPP confusion).

> *In plain words:* the API works, it was just **set up** sloppily — a too-generous CORS rule that lets any website read your data, error pages spilling stack traces, dangerous HTTP methods left on, no TLS. The bug isn't in the code; it's in the settings.

**Why it pays / impact.** Ranges from info-leak to full compromise: **verbose errors** → stack traces/secrets/internal paths; **permissive CORS** (reflected origin + credentials) → cross-origin theft of authenticated API data; **missing headers** → clickjacking/MIME/enabler bugs; enabled dangerous methods (TRACE/PUT) → tampering; **content-type confusion / HTTP Parameter Pollution** → filter/parser bypass; unpatched components → known-CVE exploitation; no TLS → interception.

**How to test (+ the kit that owns it).**
```
□ CORS misconfig: reflected Origin / null origin + Access-Control-Allow-Credentials:true → cross-origin read of authed
   API responses → data theft. → ../Web/CORS/
□ Verbose errors: trigger errors (bad types, malformed JSON) → stack traces, framework/DB versions, internal paths, secrets.
□ Security headers / transport: missing HSTS/CSP/X-Content-Type-Options; TLS gaps; mixed schemes.
□ HTTP methods: TRACE/OPTIONS/PUT/DELETE enabled where they shouldn't be; method override headers honored.
□ Content-type & HPP: switch JSON↔form↔XML to bypass validation/WAF; duplicate params (?a=1&a=2) → parser divergence.
□ Cache misconfig: sensitive API responses cached/served cross-user. → ../Web/WebCache/
□ Host-header handling: routing/cache/reset abuse via Host/X-Forwarded-* → ../Web/HostHeader/
□ Recon for misconfig: exposed docs/Swagger, debug endpoints, default creds, open cloud storage, unpatched versions.
   → ../Web/Recon/
```

**Real-world / examples.** Permissive CORS enabling authed-data theft; verbose stack traces leaking secrets/versions; content-type-confusion WAF bypass; HPP filter bypass; cached sensitive API responses; exposed debug/Swagger endpoints; default-cred admin.

**Prevention.** Harden by default across the stack (repeatable, automated config + patch management); strict CORS (exact-origin allow-list, no reflect-with-credentials, no `null`); disable unnecessary methods/features; security headers everywhere; generic error messages (log details server-side); TLS everywhere; consistent content-type/param handling; lock down docs/debug endpoints and cloud storage; config drift detection.

**Kits.** `../Web/CORS/` (CORS), `../Web/HostHeader/` (host/routing), `../Web/WebCache/` (cache), `../Web/Recon/` (exposure/misconfig discovery), `REST/` (API8 surface — content-type/HPP), `../Web/RequestSmuggling/` (front/back desync at gateways).

---

# API9:2023 — Improper Inventory Management

**What it is.** The organization lacks an accurate, current inventory of its **API endpoints and versions**, and of the **data flows** to third parties — so **shadow APIs** (undocumented/forgotten), **deprecated/legacy versions** (`/v1` still live and unpatched), **debug/test/staging** endpoints, and **exposed non-production hosts** persist unmonitored. Formerly "Improper Assets Management." The un-inventoried endpoint is the un-patched, un-monitored one.

> *In plain words:* the company lost track of its own doors. An old `/v1` API is still live and still has the bug that `/v2` fixed; a forgotten staging server holds real data. This bucket rarely *is* the bug — it's where you *find* everyone else's bugs, on the endpoint nobody remembers exists.

**Why it pays / impact.** **The old/shadow endpoint has the bug the new one fixed.** A deprecated `/v1` that skips a later authz fix; a debug endpoint with no auth; a staging host with prod data and weak controls; an undocumented internal API reachable externally. Improper inventory doesn't cause a class of exploit by itself — it **exposes every other category on forgotten surface** (BOLA/BFLA/auth bugs that were "fixed" only on `/v2`). Reconnaissance turns this into the entry point.

**How to test (+ the kit that owns it).**
```
□ Enumerate ALL versions/endpoints: /v1../v2../v3, /api../api-internal../beta, guessable route/param brute, method
   variants — find what's live beyond the docs. → ../Web/Recon/
□ Mine sources for hidden endpoints: JS bundles, mobile app decompile, Swagger/OpenAPI/GraphQL introspection, Wayback,
   git history, error messages. → ../Web/JSFiles/ + GraphQL/ (introspection)
□ Test OLD versions for FIXED bugs: run the API1/API2/API3/API5 tests against /v1 and legacy routes — the fix often
   only landed on the current version.
□ Non-prod hosts: staging/dev/test/uat subdomains with prod data or weaker controls (ties subdomain recon). → ../Web/SubdomainTakeover/
□ Debug/internal endpoints: /debug, /actuator, /metrics, /internal reachable externally.
□ Third-party data-flow inventory: which external APIs receive your data? (feeds API10).
```

**Real-world / examples.** Un-patched `/v1` still serving after `/v2` fixed the bug; forgotten staging APIs with prod data; undocumented internal endpoints reachable externally; Spring `/actuator` exposure; deprecated endpoints skipping new authz — a recurring high-bounty pattern ("the old API").

**Prevention.** Maintain a live **API inventory** (all endpoints, versions, environments, owners) + an OpenAPI spec kept current; retire/decommission deprecated versions (don't just "hide" them); segregate and access-control non-prod environments (no prod data); document + inventory third-party data flows; automated discovery + external attack-surface monitoring to catch shadow APIs.

**Kits.** `../Web/Recon/` (endpoint/version/host discovery — the core), `../Web/JSFiles/` (hidden endpoints in bundles), `GraphQL/` (introspection/clairvoyance for the schema), `../Web/SubdomainTakeover/` (non-prod/forgotten hosts), `REST/` (API9 shadow-API surface).

---

# API10:2023 — Unsafe Consumption of APIs

**What it is.** The application **trusts data received from other APIs** (third-party/partner/upstream services it *consumes*) more than user input, and applies weaker security to those integrations — following redirects blindly, not validating/sanitizing upstream responses, no timeouts, processing upstream data unsafely. The risk flips the usual direction: the danger comes from the **services you call**, not just the clients that call you.

> *In plain words:* the usual danger is the *users* talking to your API. This flips it: your API also **calls other** APIs (payment, KYC, a partner) and trusts their answers blindly. If one of those upstreams is malicious or hijacked, its poisoned response walks straight into your app. Treat data from services you *call* as untrusted too.

**Why it pays / impact.** A **compromised or malicious upstream/third-party API** (or a MITM/redirect into one) feeds your app data that it processes unsafely → **injection** (upstream response → SQLi/XSS/deserialization in your app), **SSRF/redirect chaining** (blindly following an upstream redirect to an internal target), **data poisoning**, or **secondary compromise** propagated from the partner. This is the API-integration face of supply-chain risk — your security is only as strong as the services you trust.

**How to test (+ the kit that owns it).**
```
□ Map upstream integrations: which third-party/partner/internal APIs does the app CALL and then process? payment,
   KYC, geo, enrichment, webhooks-in, OAuth userinfo, aggregators.
□ Trust boundary: is the upstream response validated/sanitized like user input, or trusted? Feed a malicious upstream
   response (via a controllable integration / MITM / a webhook you register) → does it become injection in your app?
   → ../Web/SQLi/ , ../Web/XSS/ , ../Web/Deserialization/ (unsafe processing of upstream data)
□ Redirect following: does the app follow upstream redirects blindly → internal targets? (SSRF chain). → ../Web/SSRF/ + ../Web/OpenRedirect/
□ Transport + timeouts: are calls to upstreams over TLS, validated certs, with timeouts + resource bounds?
□ Data flow: does upstream-supplied data reach a dangerous sink (DB/HTML/deserializer/shell) unvalidated?
□ Third-party supply chain: is the integration itself trustworthy/pinned? (ties supply-chain). → ../Web/DependencyConfusion/
```

**Real-world / examples.** Apps trusting partner-API responses that inject into DB/HTML; blind redirect-following into internal services; malicious webhook payloads processed unsafely; unvalidated OAuth `userinfo`/upstream JSON reaching a dangerous sink; poisoned third-party data.

**Prevention.** **Treat data from consumed APIs as untrusted input** — validate/sanitize/encode it for its sink exactly like client input; don't blindly follow redirects from integrations (allow-list); TLS + cert validation + timeouts + resource bounds on all upstream calls; validate upstream data against a schema; isolate/segment integration processing; vet + monitor third-party integrations.

**Kits.** `../Web/SSRF/` + `../Web/OpenRedirect/` (blind redirect/SSRF chaining), `../Web/SQLi/` · `../Web/XSS/` · `../Web/Deserialization/` (unsafe processing of upstream data at the sink), `../Web/DependencyConfusion/` (third-party supply-chain), `REST/` (API10 surface).

---

# Category → Kit quick map

| OWASP API 2023 category | This repo's kits (hands-on technique) |
|---|---|
| **API1 BOLA** (object-level authz) | `../Web/IDOR/` · `GraphQL/` · `REST/` · `../Web/JWT/` |
| **API2 Broken Authentication** | `../Web/JWT/` · `../Web/OAuth/` · `../Web/AccountTakeover/` · `../Web/JSFiles/` (leaked keys) · `REST/` |
| **API3 BOPLA** (property-level: mass-assign + over-read) | `../Web/IDOR/` (mass-assign) · `GraphQL/` (over-fetch) · `REST/` · `../Web/PrototypePollution/` |
| **API4 Unrestricted Resource Consumption** | `../Web/RaceCondition/` · `GraphQL/` (depth/batch) · `REST/` |
| **API5 BFLA** (function-level authz) | `../Web/IDOR/` (BFLA + verb tamper) · `GraphQL/` · `REST/` |
| **API6 Sensitive Business Flows** | `../Web/RaceCondition/` · `REST/` · (business-logic methodology) |
| **API7 SSRF** | `../Web/SSRF/` · `../Web/OpenRedirect/` · `../Web/XXE/` · `../Web/HostHeader/` · `REST/` · `GraphQL/` |
| **API8 Security Misconfiguration** | `../Web/CORS/` · `../Web/HostHeader/` · `../Web/WebCache/` · `../Web/Recon/` · `../Web/RequestSmuggling/` · `REST/` |
| **API9 Improper Inventory** | `../Web/Recon/` · `../Web/JSFiles/` · `GraphQL/` (introspection) · `../Web/SubdomainTakeover/` · `REST/` |
| **API10 Unsafe Consumption** | `../Web/SSRF/` · `../Web/OpenRedirect/` · `../Web/SQLi/` · `../Web/XSS/` · `../Web/Deserialization/` · `../Web/DependencyConfusion/` |

> The two API-surface kits are `REST/` (the OWASP-API-Top-10 backbone kit — API1–API10 hands-on) and `GraphQL/`
> (introspection, BOLA via `node`/`*ById`, batching→DoS/limit-bypass, resolver injection, CSWSH). This doc is the
> category *map*; those two kits + the referenced `../Web/…` kits carry the payloads and PoC. Likely-next API kits:
> `gRPC/`, `WebSocket-API/`.

---

# Severity calibration & reporting

| Category / cash-out | Typical ceiling | Via kit |
|---|---|---|
| **API1 BOLA → other users' / cross-tenant objects** | **Critical–High** | `../Web/IDOR/` |
| **API5 BFLA → admin function → privesc/takeover** | **Critical–High** | `../Web/IDOR/` `REST/` |
| **API7 SSRF → cloud metadata → cloud takeover/RCE** | **Critical** | `../Web/SSRF/` |
| **API3 BOPLA → mass-assign privesc / sensitive over-read** | **High–Critical** | `../Web/IDOR/` `REST/` |
| **API2 Broken auth → account takeover** | **High** | `../Web/JWT/` `../Web/OAuth/` `../Web/AccountTakeover/` |
| **API6 Business-flow abuse → financial/business harm** | **High–Medium** (context) | `../Web/RaceCondition/` |
| **API4 Resource consumption → DoS / denial-of-wallet / brute enabler** | **Medium–High** | `../Web/RaceCondition/` `GraphQL/` |
| **API8 Misconfig (CORS/verbose/HPP) → data theft/leak** | **High–Medium** | `../Web/CORS/` `../Web/Recon/` |
| **API9 Improper inventory → bug on shadow/old endpoint** | **(rate the underlying bug)** | `../Web/Recon/` |
| **API10 Unsafe consumption → injection/SSRF from upstream** | **High–Medium** | `../Web/SSRF/` `../Web/Deserialization/` |

**Reporting rules:** report the **concrete vuln + impact** with a **two-account/benign-marker proof**, then map to the API ID ("swap `account_id` on `GET /api/v1/accounts/{id}/statements` → read any customer's statements as a standard user → **API1 BOLA / IDOR**, CWE-639"). API9 findings are rated by the *underlying* bug you find on the shadow/old endpoint, not the inventory gap itself. Use the `REST/`/`GraphQL/` kit report templates for the hands-on finding; use this doc to place it in the API framework. Impact-first, own accounts, benign markers, safe PoC — per every kit's discipline.

---

# References

**Primary**
- **OWASP API Security Top 10 (2023)**: https://owasp.org/API-Security/editions/2023/en/0x00-header/ (per-category pages API1–API10 with prevention).
- OWASP API Security Project: https://owasp.org/www-project-api-security/
- OWASP API Security Testing Guide + the OWASP Web Security Testing Guide (WSTG) for the shared classes.

**Technique / research**
- **Corey J. Ball — *Hacking APIs*** (No Starch, 2022) — the definitive hands-on API-testing book (BOLA/BFLA/mass-assignment method).
- PortSwigger Web Security Academy — API testing, GraphQL, access control, SSRF labs: https://portswigger.net/web-security
- HackTricks — API/pentesting-web · Autorize/Autorepeater (Burp) for two-account authz differential testing.
- Real-world: API BOLA/BFLA bug-bounty writeups; the Capital One SSRF breach; mass-assignment disclosures.

**Tools**
- Burp Suite (+ **Autorize** / **Autorepeater** for authz diff, **Param Miner**, **InQL** for GraphQL) · Postman/Insomnia · `ffuf`/`kiterunner` (API route brute) · `arjun` (param discovery) · schemathesis/OpenAPI fuzzers · `nuclei`.

**Companion kits in this repo**
- The API-surface kits: `REST/` (OWASP-API-Top-10 backbone) + `GraphQL/`. The concrete vuln-classes: `../Web/IDOR/` (BOLA/BFLA/mass-assign), `../Web/JWT/`, `../Web/OAuth/`, `../Web/AccountTakeover/`, `../Web/SSRF/`, `../Web/CORS/`, `../Web/RaceCondition/`, `../Web/Recon/`, `../Web/JSFiles/`, `../Web/HostHeader/`, `../Web/WebCache/`, `../Web/SQLi/`, `../Web/XSS/`, `../Web/Deserialization/`, `../Web/DependencyConfusion/`, `../Web/SubdomainTakeover/`, `../Web/OpenRedirect/`, `../Web/XXE/`. Sibling umbrellas: `../Web/OWASP_WEB_TOP_10.md`, `../Mobile/OWASP_MOBILE_TOP_10.md`, `../AI/LLM/OWASP_LLM_TOP_10.md`.

---

> **Final reminder — the one rule that pays:** the API Top 10 re-centers the Web Top 10 on the things APIs break worst — **authorization at the object (API1), function (API5), and property (API3) level.** APIs hand you the IDs and the endpoints directly; there's no UI to hide behind, so the only defense is a server-side check that is usually missing. Enumerate the *whole* surface (including shadow/old versions — API9), run the **two-account differential** on every object and function, follow the URL-fetch sinks to SSRF (API7), and abuse the business flow at scale (API6). Report the concrete vuln + impact mapped to the API ID — categories here, payloads in the `REST/`/`GraphQL/`/`../Web/…` kits.
