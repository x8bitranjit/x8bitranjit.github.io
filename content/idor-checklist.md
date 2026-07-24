# IDOR / BOLA Testing Checklist — Per-Object, In Testing Order

> Tick per object/endpoint. Mirrors the Master Testing Sequence in `IDOR_TESTING_GUIDE.md`. The point: **two accounts (A reaches B's object) is the proof → swap the reference → if blocked, run the mutation matrix → escalate read→enumerate→write→ATO→BFLA→cross-tenant.** `§` = section in the main guide.

**Target:** ____________  **Object/endpoint:** ____________  **Method:** ____________  **Date:** ________
**Reference location:** path / query / body / JSON / header / cookie / GraphQL / file  **ID format:** seq-int / encoded / uuidv1 / uuidv4 / objectid / snowflake / composite
**Accounts:** A=__________ (attacker)  B=__________ (victim, same role)  admin?___  2nd-tenant?___

---

## PHASE 0 — Recon & Lab (§1/§3)
*Why this matters:* IDOR's whole proof rests on **two coats you own** — so registering two same-role accounts first isn't optional, it's the oracle. And you can't test ownership on a reference you never found, so map *every* id (headers and nested JSON hide the easy wins) before touching a payload.
- [ ] Registered **two same-role accounts** A & B (+ optional admin, + 2nd tenant/org).
- [ ] Proxied the app as **both** A and B through every feature (UI + the API the mobile app calls).
- [ ] Mapped **every object reference** (path/query/body/JSON/header/cookie/GraphQL/file) into an objects table.
- [ ] Pulled id-bearing/old `/v1/` endpoints from recon (gau/katana/JS) — not just the live UI.
- [ ] Recorded, per object: reference location, **format**, and an **example reference owned by B**.

## PHASE 1 — Baseline ★ (§4) — THE ORACLE, DO FIRST
*Why this matters:* this phase is what makes an IDOR impossible to dismiss as a false positive. Establishing "does A's session reach B's object?" per object — and classifying the id format — is what separates a paid finding from a closed "that's your own data." Do it before any payload.
- [ ] Captured **B's** request + B's object reference; captured **A's own** equivalent request.
- [ ] Classified the **ID format** (drives §6/§7); **decoded** any encoded id.
- [ ] Asked the defining question: does the server enforce an **ownership/role check**, or trust the reference?
- [ ] Produced a per-object verdict slot: `IDOR-READ` / `IDOR-WRITE` / `BLOCKED(try bypass)` / `SAFE(session-scoped)`.

## PHASE 2 — Find & Bypass (§5–§10)
- [ ] **Direct swap** (§4): put **B's reference** into **A's** authenticated request. Read the response.
- [ ] If 403/404, run the **mutation matrix** (§8):
  - [ ] **Method/verb** swap (GET vs POST/PUT/PATCH/DELETE) + override (`_method`, `X-HTTP-Method-Override`).
  - [ ] **Array-wrap** (`id[]=`, `{"id":[..]}`) + **parameter pollution** (`id=mine&id=victim`, dup JSON keys, path-vs-body).
  - [ ] **Type juggling** (`123` / `"123"` / `[123]` / `{"$ne":null}`).
  - [ ] **Path/encoding/extension/version** (`.json`, trailing `/`, `%2e`, case, `/api/v1/`, `/internal/`).
  - [ ] **Header/cookie trust** (`X-User-Id`, `X-Account-Id`, `uid=`, `X-Forwarded-For`, `X-Original-URL`).
  - [ ] **Wildcard/null/boundary** (`*`, `%`, `all`, `0`, `-1`, empty, `me`/`current`).
  - [ ] **Nested / parent-scoped child** (§8.10): keep MY parent, swap only the child id (`/users/{me}/cards/{B}`).
  - [ ] **Bulk / batch id-mixing** (§8.11): `{"ids":[mine, victim]}` / `?ids=mine,victim`.
  - [ ] Recorded the **403-vs-404 (+length/time) enumeration oracle** regardless.
- [ ] **Predictable/enumerable id** (§6): sequential / encoded-sequential / weak-hash → confirm cross-user, then size impact.
- [ ] **Obfuscated-but-reversible id** (§6.6): Hashids/Sqids/Optimus — recognise the ordered drift, find salt/alphabet/PRIME in JS (or default) → decode → enumerate.
- [ ] **Non-sequential id** (§7): UUIDv1/ObjectId/snowflake **predict**; **UUIDv7/ULID/KSUID** bound to the creation-time window (§7.5); or UUIDv4 **obtain** (list/search/profile/GraphQL/Referer/error).
- [ ] **Mass assignment** (§9): inject `owner_id`/`user_id`/`account_id`; escalate `role`/`isAdmin`/`permissions`/`plan`/`balance`; try **JSON-Patch / merge-patch** (§9.4) as a separate code path.
- [ ] **BFLA** (§10): invoke admin/privileged functions as A (create-admin, role change, impersonate, delete, export-all).
- [ ] ✅ Produced a request in **A's session** that reads or changes **B's object** (or a confirmed function-level bypass).

## PHASE 3 — IMPACT ⭐ (§11–§17)
*Why this matters:* a single read of one record is Low–Medium; the bounty is the multiplier. Push every confirmed IDOR toward enumerate-the-population (mass PII), write→ATO, BFLA→admin→RCE, or cross-tenant — the highest one you can prove is your severity. Never submit the first read without asking "now scale it or write it."
- [ ] **Read → enumerate** (§11): prove the pattern (small set), state population (`X-Total-Count`/max-id) → mass-PII.
- [ ] Did the leaked object contain **auth material** (reset token / API key / session)? → pivot to **ATO/RCE**.
- [ ] **Write → ATO** (§12): change B's email/recovery → reset → log in as B; or direct pw/MFA/key change. **Verify on B.**
- [ ] **BFLA → admin → RCE** (§13): self-promote/create admin → admin upload/SSTI/SSRF/integration → code exec.
- [ ] **Files/exports/signed URLs** (§14): swap filename/key/signature; bulk export endpoints.
- [ ] **GraphQL** (§15): `node(id:)`/`*ById`, alias batching, write mutations, introspection for more sinks.
- [ ] **Cross-tenant** (§16): reach another org's data (two orgs you own) — read **and** write.
- [ ] **Blind/second-order** (§17): id used by async/webhook/notification sink → confirm via victim/OOB.
- [ ] Stated impact in one sentence: *"Using A's creds I read/changed B's <object>, affecting <any user/admin/tenant>, at <single/mass> scale."*

## PHASE 4 — Validate → Severity → Report (§19–§24)
*Why this matters:* the two-account proof is the single line that gets IDORs paid — "A's creds, B's object, B's data returned." If you can't state that, you don't have a finding yet. Lead with it, keep the enumeration small and ethical, and title with impact + scale, not "IDOR found."
- [ ] ★ **TWO-ACCOUNT PROOF**: A's credentials, B's object, B's data returned or B's object changed (re-read as B) (§19).
- [ ] Passed the **false-positive filter** (§20): NOT one-account, NOT public data, NOT your-own-data, NOT 403-with-no-bypass, NOT victim-token-required.
- [ ] Set **CVSS 3.1** + **CWE-639** (+ CWE-285/863/566/915 as fits) (§21); stated **scale** & **who the victim can be**.
- [ ] Built a clean **two-account PoC** (benign markers, small set, writes reverted) (§23).
- [ ] **De-duplicated**; title names the **object + reference + impact** (§24).

---

## Quick "is it a real IDOR?" gate
```
Client-controlled reference to an object?                         NO → not IDOR.
Object belongs to another user/tenant (not public, not yours)?    NO → not IDOR.
A's creds + B's reference → B's data returned / B's object changed? NO → try bypass (§8); else SAFE.
Can I show it with TWO accounts I own?                            NO → don't report (FP).
Escalated beyond one read (enumerate / write→ATO / BFLA / tenant)? NO → likely Low/Medium; push harder.
```

## Per-object mini-loop
```
capture A's request + B's reference → swap B's id into A's request → read response
   ├ 200+B's data → enumerate? auth material? write verb? → impact
   ├ 403/404 → mutation matrix (method/array/pollution/type/path/version/header/wildcard)
   └ A's own data → SAFE
→ ★ two-account proof → FP filter → CVSS+CWE-639 → reversible PoC → dedup
```
