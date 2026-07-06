# REST API Testing Checklist — per API / per endpoint (OWASP API Top 10)

> Authorized APIs only. Register **two** test accounts (A, B) + ideally an **admin/low-priv** pair before you start —
> you cannot prove authorization bugs with one identity. Commands: `REST_API_ARSENAL.md`. Depth: `REST_API_TESTING_GUIDE.md`.

## PHASE 0 — Map the surface (§1)
- [ ] Found the spec? (`/openapi.json` `/swagger.json` `/v3/api-docs` `/api-docs` `/docs` `/redoc` `/postman`) → imported to Burp/Postman.
- [ ] Mined the client (SPA JS / mobile APK-IPA) for endpoints + keys (`../../Web/JSFiles/`, `../../Mobile/Android/ADB/`).
- [ ] Historical + brute discovery (`gau`/katana, `ffuf`/`kiterunner`).
- [ ] Enumerated **methods** per path (`OPTIONS` → `Allow:`; fuzz verbs) and **versions** (`/v1 /v2 /v3 /beta /internal`).
- [ ] Built the `{method, path, params, auth?, role?}` matrix (the test list).

## PHASE 1 — Auth model (§2)
- [ ] Token type/location identified (JWT / opaque / API-key / cookie; header/cookie/query).
- [ ] JWT decoded → claims/roles/exp checked → token attacks queued (`../../Web/JWT/`).
- [ ] Roles/scopes + tenancy model understood; where authz is enforced (gateway/controller/object/UI-only).

## PHASE 2 — API1 BOLA (§5) ★ do first
- [ ] Swapped **every object ID** (path/query/body/header) as A → B's object.
- [ ] Numeric/sequential IDs tested; UUID/GUID tested **with a leaked victim ID** (from a list/search/share endpoint).
- [ ] Nested (`/me/orders/{id}`), body-vs-token mismatch, batch/`ids[]` tested.
- [ ] BOLA-**write** (`PUT`/`PATCH`/`DELETE` on B's object) tested (higher impact).
- [ ] Confirmed with **B's actual data**; bounded (1–2 objects, no mass pull).

## PHASE 3 — API3 BOPLA (§7)
- [ ] **Excessive data exposure:** read raw JSON, diffed vs UI — secret/other-user fields? (`passwordHash`,`mfaSecret`,`isAdmin`,`ssn`).
- [ ] **Mass assignment:** injected hidden fields (`role`/`isAdmin`/`isVerified`/`price`/`balance`/`credits`/`userId`/`orgId`) — camelCase + snake_case + nested.
- [ ] Confirmed the field **persisted** (re-GET) and **has effect** — not just echoed.

## PHASE 4 — API5 BFLA (§9)
- [ ] Admin/internal functions called as **low-priv** and as **no-token** (`/admin/*`, role change, config, delete).
- [ ] **Verb tampering:** state-changing methods on read-only-in-UI endpoints as a normal user.
- [ ] **Method override** (`X-HTTP-Method-Override`, `_method=`) to bypass edge verb rules.
- [ ] Confirmed the privileged action **took effect** (on your own object/tenant for destructive proofs).

## PHASE 5 — API2 Broken Auth (§6)
- [ ] Token strength (`../../Web/JWT/`): alg:none / weak secret / RS→HS / kid-jku / no-expiry / not-invalidated-on-logout.
- [ ] Rate-limit on login/OTP/reset (brute primitive on **your** account); OTP reuse / OTP-in-response.
- [ ] Password reset: token predictability/single-use, host-header poisoning (`../../Web/HostHeader/`), user-controlled target (BOLA-in-reset), MFA-skip.
- [ ] API keys hunted (JS/mobile/Git/query-string), over-scope/rotation.

## PHASE 6 — API4 / API6 (§8/§10)
- [ ] Resource consumption: huge `?limit=`/`?expand=`, cost endpoints (SMS/email/paid upstream), ReDoS — primitive shown, no real DoS.
- [ ] Business-flow abuse: value flows (coupon/referral/stock/vote) run at scale w/o anti-automation; races (`../../Web/RaceCondition/`).

## PHASE 7 — API7/8/9/10 (§11–§14)
- [ ] SSRF on URL/webhook/import params (`../../Web/SSRF/`) — cloud metadata/OOB.
- [ ] Misconfig: CORS-with-credentials (`../../Web/CORS/`), actuator/debug/`.env`/`.git`, verbose errors, default creds.
- [ ] Inventory: old versions re-open fixed bugs; non-prod hosts (`dev/staging/uat/sandbox`) with real data.
- [ ] Unsafe consumption: attacker-influenced upstream/webhook/SSO data trusted unsafely.

## PHASE 8 — REST-specific & injection (§15)
- [ ] Content-type confusion (JSON-as-text/xml → parser bypass / **XXE**), HTTP parameter pollution (dup params/keys).
- [ ] NoSQL operator injection (`{"$ne":null}`) → auth bypass.
- [ ] Param/path/body injection → `../../Web/SQLi/` `../../Web/CommandInjection/` `../../Web/SSTI/` `../../Web/LFI/` `../../Web/LDAP/`.

## PHASE 9 — Chain, validate, report (§16–§20)
- [ ] Chained to **ATO / admin / cross-tenant / financial** where possible (killer chains §16).
- [ ] Passed the **FP auto-reject** table (§17) — authz findings proven with **two identities**.
- [ ] Severity set (CVSS + OWASP-API category + CWE, §18); impact stated in business terms.
- [ ] SAFE-PoC honored: own accounts, bounded reads, non-destructive writes on own objects, **cleaned up** test data.

## AUTO-REJECT (not a finding by itself)
- [ ] ID swap that returns **your own** object / 403 / 404 / empty.
- [ ] Mass-assignment field **echoed** but not persisted/effective.
- [ ] Admin endpoint that correctly returns **401/403** to low-priv.
- [ ] "Sensitive" JSON fields that are **your own** non-secret data.
- [ ] Missing rate-limit / verbose error / `OPTIONS` with **no** tied impact.
- [ ] Self-only issue with no cross-user/cross-tenant effect.
