# GraphQL Testing Checklist — Per-Endpoint, In Testing Order

> Tick per GraphQL endpoint. Mirrors the Master Testing Sequence in `GRAPHQL_TESTING_GUIDE.md`. The point: **map the schema (even if introspection is off) → build the sink list → drive each sink to impact → prove per sub-bug.** `§` = section in the main guide.

**Target:** ____________  **Endpoint:** ____________  **Engine (graphw00f):** ____________  **Date:** ________
**Introspection:** on / off  **Suggestions:** on / off  **GET allowed:** y/n  **Batching (alias/array):** y/n
**Accounts:** A=__________ (attacker) B=__________ (victim) admin?___

---

## PHASE 0 — Recon & Lab (§1/§3)
- [ ] Found the GraphQL endpoint(s) (`/graphql`, `/api/graphql`, `/v1/graphql`, consoles, JS/mobile).
- [ ] Confirmed GraphQL (`{__typename}` → `Query`); checked for exposed **GraphiQL/Playground/Altair**.
- [ ] **Fingerprinted the engine** (graphw00f) → known quirks (suggestions? batching? error verbosity?).
- [ ] Registered **two accounts** (A/B) for BOLA + an **admin** for BFLA baselines; loaded Burp + InQL.

## PHASE 1 — Map the Schema ★ (§4–§6)
- [ ] Introspection **on** → dumped full `__schema`; rendered in Voyager (relations/cycles).
- [ ] Introspection **off** → recovered schema via **field suggestions / clairvoyance / graphw00f**.
- [ ] Built the **sink list**: `*ById`/`node` (BOLA) · mutations (BFLA) · input objects (mass-assign) · url/file args (SSRF) · filter/id/order args (injection) · login/otp (batching).

## PHASE 2 — Find & Bypass (§7–§11)
- [ ] **BOLA** (§7): `node(id:)` / `user(id:)` / nested relations — A's token + **B's id** → B's data? (two-account proof).
- [ ] **BFLA** (§8): invoke sensitive mutations as low-priv A (update/delete/setRole/impersonate/createApiKey); find the **directive gap**.
- [ ] **Batching** (§9): alias + JSON-array batching on login/OTP → measured **rate-limit bypass** (N ops, one request).
- [ ] **DoS** (§10, permission): deep nesting / alias overload / field duplication / directive overload / **`@defer`/`@stream`** (§10.6) → **measure** amplification (don't flood); note missing depth/complexity/cost limits.
- [ ] **Injection** (§11): args → SQLi / NoSQLi (`$ne`/`$regex`) / cmdi (time-based) / SSRF; use **variables** for typed payloads.

## PHASE 3 — IMPACT ⭐ (§12–§16)
- [ ] **Mass assignment** (§12): input object accepts `role`/`isAdmin`/`owner_id`/`tenant_id`/`balance` → read back → priv-esc/cross-tenant.
- [ ] **Info disclosure** (§13): verbose errors/stack traces/`extensions` leaking SQL/paths/PII; schema secrets.
- [ ] **CSRF** (§14): GET or form-urlencoded mutations + cookie auth → cross-site fire in a default browser.
- [ ] **Authn/Authz bypass** (§15): unauthenticated fields/mutations (logged-out); persisted-query/APQ quirks.
- [ ] **Subscriptions / WebSocket** (§15.5): `connection_init`+`subscribe` with **no token** and a **foreign Origin** → CSWSH / auth bypass; many subs → DoS.
- [ ] **SSRF / file read** (§16): url-taking arg → interactsh OOB → **cloud metadata → creds → RCE**; path arg → LFI.
- [ ] Stated impact: *"<sub-bug> in <field/mutation> → <RCE/ATO/cross-user/cloud/priv-esc>."*

## PHASE 4 — Validate → Severity → Report (§18–§23)
- [ ] ★ **Proof per sub-bug** (§18): BOLA two-account · BFLA/mass-assign read-back · batching measured count · injection signal · SSRF OOB · DoS measured amplification.
- [ ] Passed the **false-positive filter** (§19): NOT "introspection enabled" alone, NOT own-data `node`, NOT "mutation exists" without invoking, NOT GET-CSRF with Bearer auth, NOT theoretical batching/DoS.
- [ ] Set **CVSS 3.1** + the **CWE for the sub-bug** (639/285/862/915/89/943/918/352/770) (§20); stated scale.
- [ ] Built a clean **PoC query** (own accounts, your OOB host, reversible) (§22).
- [ ] **De-duplicated**; title names **sub-bug + field + impact** (§23).

---

## Quick "is it a real GraphQL finding?" gate
```
Mapped the schema (introspection or clairvoyance)?              NO → map it first (§5/§6).
Did a SINK actually produce impact (not just exist)?            NO → invoke/exploit it, don't report existence.
BOLA: A's token + B's id → B's DATA?                            NO → own/public data → not BOLA.
Batching: more attempts processed than the per-request limit?   NO → not a rate-limit bypass.
Injection/SSRF: a real signal (error/time/OOB)?                 NO → theoretical → drop.
Introspection/verbose-error ALONE?                              → Low/Info; bundle with the real bug.
```

## Per-endpoint mini-loop
```
fingerprint → map schema → sink list → per sink: BOLA(two-account) / BFLA(invoke) / batch(count) /
   inject(signal) / SSRF(OOB) → escalate (mass-assign→admin→RCE, SSRF→cloud) → proof → CVSS+CWE → PoC → dedup
```
