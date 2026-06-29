# Insecure Direct Object Reference (IDOR / BOLA) — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Object-level & function-level authorization on web apps and APIs — REST, GraphQL, RPC, mobile back-ends, multi-tenant SaaS, file/export/attachment endpoints, internal admin panels
**Platforms:** Browser + proxy driven (two authenticated sessions required for validity); Kali/Windows helper scripts provided
**Companion files in this folder:**
- `IDOR_ARSENAL.md` — copy-paste payloads, Autorize/AuthMatrix setup, enumeration commands, ID-mutation matrix, GraphQL node sweeps
- `IDOR_CHECKLIST.md` — the per-object testing-order checklist you tick through
- `IDOR_REPORT_TEMPLATE.md` — the report skeleton that gets paid (two-account proof front-and-center)
- `poc/` — benign two-account replay/diff helper + a polite ID enumerator + a GraphQL node sweeper
- `IDOR_Attacks_Zero_to_Expert.md` — Q&A study + field reference (fundamentals → expert chains)

> **Companion to the JWT / CSRF / SSRF / XSS guides.** Same philosophy: *find* is Part I–III, *get paid* is Part IV. IDOR is the **#1 bug class on bug-bounty programs by volume and by payout** — it's **OWASP API Security #1 (BOLA)** — because it needs no exotic primitive: it's a missing line of authorization code. The expert skill is **proving cross-user access with two accounts you own** (so it's never a false positive), then **escalating from "I read one stranger's record" to mass-PII / account-takeover / cross-tenant breach** so it pays Critical, not Low.

---

> ### ⚡ READ THIS FIRST — the four sentences that separate a paid IDOR from an N/A
> 1. **IDOR = the server trusts a reference you control.** You send `id=124` instead of your own `id=123`, and the app returns or mutates object 124 **without checking you own it**. That's it. The whole game is *finding the reference* and *proving the missing ownership check*.
> 2. **The proof is two accounts, never one.** Account **A** (attacker) accessing Account **B**'s (victim) private object — both accounts you control — is the only proof a triager accepts. "I changed the ID and got data back" with one account proves nothing (it might be *your* data, or public data). Capture B's object reference, replay it **in A's session**, show A received/changed B's data. (§4, §19)
> 3. **Read is a finding; write and scale are the bounty.** A single read of one stranger's record is Low–Medium. The money is: **enumerate all records** (mass PII → Critical), **write** to a victim's object (**change their email/password → ATO**), **function-level** access (**BFLA → admin → RCE**), or **cross-tenant** access (SaaS isolation break). Always push read→enumerate and read→write. (§11–§17, §22)
> 4. **A 403/404 is not always a dead end.** If the object exists but you get 403, you may still have an **enumeration oracle** (403 vs 404 leaks existence), a **method/verb** that isn't protected (GET blocked, PUT works = BFLA), or a **second representation** (the `.json` export, the GraphQL `node(id:)`, the mobile API v1) that *is* unguarded. Don't stop at the first denial. (§8, §14, §15)
>
> **Where the money is (memorize this order):** ① **BFLA → admin/role escalation → RCE or full tenant control** → ② **Write IDOR → change victim email/recovery/password → account takeover** → ③ **Mass-read IDOR → enumerate the whole user base / all documents (PII breach, GDPR)** → ④ **Cross-tenant IDOR** (read/write another organization's data in a SaaS) → ⑤ *then* single-record read of sensitive PII as **Medium**, and read of low-sensitivity own-adjacent data as **Low**.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [IDOR / BOLA / BFLA Anatomy & the 2026 Reality](#2-idor--bola--bfla-anatomy--the-2026-reality)
3. [Reconnaissance — Map Objects, IDs & Ownership](#3-reconnaissance--map-objects-ids--ownership)
4. [Baseline — The Two-Account Oracle](#4-baseline--the-two-account-oracle)

**PART II — FINDING & BYPASS (work in this order)**
5. [The ID Location & Format Taxonomy](#5-the-id-location--format-taxonomy)
6. [Predictable & Enumerable Identifiers](#6-predictable--enumerable-identifiers)
7. [Non-Sequential ID Prediction & Disclosure](#7-non-sequential-id-prediction--disclosure)
8. [Access-Control Bypass Techniques](#8-access-control-bypass-techniques)
9. [Mass Assignment / Owner-Field Tampering](#9-mass-assignment--owner-field-tampering)
10. [BFLA — Broken Function-Level Authorization](#10-bfla--broken-function-level-authorization)

**PART III — VARIANTS & EXPLOITATION BY IMPACT (where the money is)**
11. [Read IDOR → PII & Mass Enumeration](#11-read-idor--pii--mass-enumeration)
12. [Write IDOR → Tamper → Account Takeover](#12-write-idor--tamper--account-takeover)
13. [BFLA → Privilege Escalation → Admin → RCE](#13-bfla--privilege-escalation--admin--rce)
14. [IDOR in Files, Exports, Attachments & Signed URLs](#14-idor-in-files-exports-attachments--signed-urls)
15. [IDOR in GraphQL](#15-idor-in-graphql)
16. [Multi-Tenant / Cross-Tenant IDOR](#16-multi-tenant--cross-tenant-idor)
17. [Blind / Second-Order IDOR](#17-blind--second-order-idor)

**PART IV — VALIDITY, SEVERITY & REPORTING**
18. [The Escalation Mindset](#18-the-escalation-mindset)
19. [The Validity-First Mindset — the Two-Account Proof](#19-the-validity-first-mindset--the-two-account-proof)
20. [False Positives — STOP reporting these](#20-false-positives--stop-reporting-these-auto-reject-list)
21. [Severity Calibration](#21-severity-calibration--how-triagers-rate-idor)
22. [Impact-Escalation Playbooks — "you found X, now do Y"](#22-impact-escalation-playbooks--you-found-x-now-do-y)
23. [Building a Professional PoC](#23-building-a-professional-poc)
24. [Reporting, CWE/CVSS & De-duplication](#24-reporting-cwecvss--de-duplication)
25. [Automation & Red-Team Notes](#25-automation--red-team-notes)

**Appendices**
- [Appendix A — IDOR Workflow Cheat Sheet](#appendix-a--idor-workflow-cheat-sheet)
- [Appendix B — IDOR Decision Tree](#appendix-b--idor-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Each phase says *what to do*, *which § for detail*, and the *deliverable*. Numbered sections (1–25) are reference detail; this is the order you execute.

```
PHASE 0  RECON & LAB        → register TWO accounts (A=attacker, B=victim, SAME role) (§1) ·
                              map every object reference & ID parameter (§3)
PHASE 1  BASELINE  ★        → for each object: capture A's request & B's object id; what is the ID
                              format/location? is there ANY server-side ownership check? (§4)
                              ← this phase produces the oracle: "does A's session reach B's object?"
PHASE 2  FIND & BYPASS      → swap the reference and defeat whatever guards it:
                              ID taxonomy (§5) · enumerable IDs (§6) · predict/leak non-seq IDs (§7) ·
                              method/array/pollution/type/path/version/403-vs-404 (§8) ·
                              owner-field mass-assignment (§9) · function-level BFLA (§10)
PHASE 3  IMPACT  ⭐ (money)  → turn the swap into a breach:
                              read→PII & mass-enumerate (§11) · write→ATO (§12) · BFLA→admin→RCE (§13) ·
                              files/exports/signed-URLs (§14) · GraphQL node/alias/batch (§15) ·
                              cross-tenant (§16) · blind/second-order (§17)
PHASE 4  VALIDATE → REPORT  → ★ TWO-ACCOUNT PROOF (A read/changed B's data) (§19) · false-positive
                              filter (§20) · severity+CVSS+CWE-639 (§21) · clean PoC (§23) · dedup (§24)
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon & lab.** Register **two same-role accounts** (A and B) plus, if possible, an admin and a second-tenant account (§1). Proxy the app and enumerate **every object reference** — every request that carries an `id`, a UUID, a filename, a `node(id:)` (§3). *Deliverable:* a table of object types + where their reference lives + an example reference owned by **B**.
2. **PHASE 1 — Baseline ★ (the oracle).** For each object, capture **A's own** request, note the **ID format and location** (§5), and ask the one question that defines IDOR: *does the server verify A owns this object, or does it trust the reference?* (§4) *Deliverable:* per-object verdict on whether an ownership check appears to exist.
3. **PHASE 2 — Find & bypass.** Substitute **B's reference** into **A's authenticated request**. If blocked, work the bypass toolbox: enumerable/predictable IDs (§6–§7), method/verb/array/pollution/type/path/version/oracle tricks (§8), owner-field mass-assignment (§9), function-level endpoints (§10). *Deliverable:* a request in A's session that touches B's object.
4. **PHASE 3 — Impact ⭐.** Escalate: from one read → **enumerate the population** (§11); from read → **write → ATO** (§12); from user → **admin/function (BFLA) → RCE** (§13); across **files/exports** (§14), **GraphQL** (§15), **tenants** (§16), and **blind/async** sinks (§17). *Deliverable:* a demonstrated high-impact outcome.
5. **PHASE 4 — Validate → report.** **The validity gate: show A (attacker) read or changed B's (victim) private object, with both accounts you own** (§19). Apply the false-positive filter (§20), set a defensible CVSS/CWE (§21), ship a clean two-account PoC (§23), de-dup (§24). *Deliverable:* the submitted report.

Reference anytime: payloads → `IDOR_ARSENAL.md`; checklist → `IDOR_CHECKLIST.md`; helpers → `poc/`; playbooks **§22**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

IDOR is **authorization-validated** — your most important asset is **two authenticated sessions of equal privilege**, because the proof is "A reached B's object." A single session can only ever show you *your own* data and lies about ownership.

| Tool | Job |
|------|-----|
| **Two same-role accounts** (A=attacker, B=victim) | the oracle; capture both sessions' cookies/tokens. Also useful: an **admin** account (for BFLA baselines) and a **second-tenant/org** account (for cross-tenant). |
| **Burp Suite** (or Caido) | proxy both sessions; capture every object request; the platform for the extensions below |
| **Autorize** (Burp ext, by Barak Tawily) | **the IDOR workhorse** — replays every A request with **B's session token** (or *no* token) and flags responses that look identical → automatic IDOR detection across the whole app |
| **AuthMatrix / Auth Analyzer / Authz** | role/endpoint authorization matrices; per-user replay; great for BFLA coverage |
| **Burp Intruder / ffuf** | enumerate sequential or pattern IDs; sniper/pitchfork over the reference |
| **Arjun / Param Miner / x8** | discover **hidden parameters** — a forgotten `owner_id`/`user_id`/`account_id` the UI never sends → mass-assignment (§9) & extra id sinks |
| **kiterunner / ffuf (routes)** | brute API **routes & old versions** (`/v1/`, `/internal/`, `/mobile/`) — a top source of unguarded IDOR endpoints (§8.7) |
| **`jq`, `unfurl`, custom Python** | diff JSON responses across A vs B; extract IDs from responses for second-order chains; decode Hashids/Sqids/ULID (§6.6/§7.5) |
| **InQL / GraphQL Voyager / Altair** | map GraphQL types & the `node(id:)`/`*ById` fields that are classic BOLA sinks |
| **DevTools / mobile proxy (Frida, objection)** | mobile apps expose the *richest* IDOR APIs (older `/v1/`, less-guarded) |

```bash
# Capture each account's auth so you can swap it cleanly:
#   A:  Cookie: session=<A>   or   Authorization: Bearer <A_JWT>
#   B:  Cookie: session=<B>   or   Authorization: Bearer <B_JWT>
# Autorize: paste B's headers as the "low-priv" identity, browse as A → it replays & flags.
```

> **The cardinal rule of IDOR tooling:** *every finding must be reproducible as "A's credentials, B's object."* Configure Autorize with **two real, equal-privilege identities** from the start — most beginners mis-set it with one identity and get false "vulnerable" flags. Verify a flagged hit by hand before believing it (§19, §20).

> **Windows:** run Burp + extensions natively; run the Python helpers in WSL or native Python. Keep A and B in **separate browser profiles** so sessions don't collide.

---

# 2. IDOR / BOLA / BFLA Anatomy & the 2026 Reality

## 2.1 What IDOR is (one paragraph)
An application exposes a **direct reference to an internal object** — a database primary key, a username, a filename, a UUID, an S3 key — in a parameter the client controls. **IDOR is when the app uses that reference to fetch or mutate the object *without verifying the authenticated user is authorized for that specific object*.** The authentication is fine (you're logged in); the **authorization** is missing or wrong. Root cause: the developer wrote `SELECT * FROM invoices WHERE id = :id` instead of `... WHERE id = :id AND owner_id = :current_user`.

## 2.2 The vocabulary (use it correctly in reports)
- **IDOR** — the classic web term: Insecure Direct Object Reference. Object-level access-control failure via a user-controlled key.
- **BOLA** — **Broken Object Level Authorization**, **OWASP API Security Top 10 #1**. Same bug, API framing; use this term for API reports — triagers and CVSS calculators map it cleanly.
- **BFLA** — **Broken Function Level Authorization**, **OWASP API #5**. Not "which object" but "which *operation*": a normal user invoking an **admin/privileged function** (e.g. `POST /api/admin/users`, `DELETE /api/users/{id}`, `role=admin`).
- **BOPLA / Mass Assignment** — Broken Object **Property** Level Authorization (OWASP API #3): you're allowed the object, but you tamper a **property** you shouldn't control (`isAdmin`, `owner_id`, `balance`). Adjacent to IDOR and frequently chained (§9).

## 2.3 The three conditions for IDOR (ALL must hold)
**IF** (a) the request contains a **reference to an object** (id/uuid/filename/key) that the client supplies or can change, **AND** (b) the object belongs to (or is accessible only to) **another user/tenant**, **AND** (c) the server **does not enforce an ownership/role check** binding that object to the caller → **THEN it's IDOR/BOLA.** Remove (c) — a real server-side `owner_id = current_user` check — and it's not.

## 2.4 The 2026 mental model
- APIs exploded: every SPA/mobile app is a thin client over a REST/GraphQL API that exposes **object IDs everywhere**. BOLA is #1 because it scales with endpoints.
- **UUIDs are not a fix.** A v4 UUID is unguessable, but it is constantly **leaked** — in search results, autocomplete, `Referer`, error messages, public profiles, other API responses, webhooks. "Unguessable ID" ≠ "authorized." If you can *obtain* B's UUID and the server doesn't check ownership, it's still IDOR. (§7)
- **404 ≠ safe.** Many apps return 404 for "not yours" — but a different code/timing for "doesn't exist" gives an **enumeration oracle**, and a different *endpoint/method* often skips the check entirely. (§8)
- **The check is per-object, not per-endpoint.** An endpoint can be correctly guarded for the listing view and wide open on the detail/export/`PUT` view. Test **every verb and every representation** of each object.

---

# 3. Reconnaissance — Map Objects, IDs & Ownership

**Goal:** produce a table of *every object the app exposes*, *where its reference lives*, and *an example reference owned by B*. You can't test ownership until you know which references exist.

**3.1 Drive the app as B, then as A, through the proxy.** Exercise every feature with **both** accounts: view profile, open an order/invoice/message, download an export, change a setting, use the API the mobile app calls. Burp's **Target → Sitemap** + **Logger** now holds every object reference.

**3.2 Hunt the reference in every location** (full taxonomy in §5):
- Path segments: `/api/users/123`, `/orders/4567`, `/u/alice`
- Query: `?id=`, `?user=`, `?account=`, `?file=`, `?doc=`, `?invoice=`, `?cid=`, `?uuid=`
- Body (form & JSON): `user_id`, `account_id`, `owner`, nested `{"order":{"id":...}}`
- Headers: `X-User-Id`, `X-Account-Id`, `X-Customer`, tenant headers
- Cookies: `uid=`, `account=`, role/tenant cookies
- GraphQL: `node(id:)`, `user(id:)`, `*ById`, `*ByEmail` fields
- Files/exports: `/download?file=`, `/export/{id}.pdf`, S3/blob keys, signed URLs

**3.3 Classify each reference's format** (drives the attack — §6/§7): sequential integer? timestamp-ish? base64/hex of something? UUIDv1 vs v4? Mongo ObjectId (24-hex)? snowflake (large int)? composite (`tenant:obj`)?

**3.4 Record ownership.** For each object, note **who owns it** (A, B, public, admin, tenant-1, tenant-2). This is the column that lets you build the two-account test.

**3.5 Grab IDs from recon, not just the UI.** `gau`/`waybackurls`/`katana` historical URLs and JS files reveal **id-bearing endpoints and undocumented `/v1/` APIs** the UI no longer uses but the server still serves (the recon kit feeds this directly). Old API versions are a top IDOR source (§8).

> *Deliverable:* an objects table — `object | reference location | format | owner | example(B)`.

---

# 4. Baseline — The Two-Account Oracle

This is the phase that makes IDOR **un-false-positive-able**. Skipping it is why reports get closed as "that's your own data."

**4.1 The oracle, step by step (per object):**
1. As **B**, perform the action → capture the request and note **B's object reference** (e.g. `GET /api/orders/8001`, order 8001 belongs to B).
2. As **A**, perform the *same* action on **A's own** object → capture it (e.g. `GET /api/orders/7001`).
3. Now take **A's request** (A's cookie/token, A's headers) and **substitute B's reference** (`/api/orders/8001`).
4. **Read the response.**
   - **IF** A receives **B's data** (200 + B's order details) → **IDOR confirmed (read).** Note exactly which of B's fields leaked.
   - **IF** A gets **403/404/empty** → an ownership check may exist; move to the bypass toolbox (§8) and try other verbs/representations before concluding "safe."
   - **IF** A receives **A's own** data (the server ignored the ID and scoped by session) → **not IDOR**; the server is correctly session-scoping. Stop on this object.

**4.2 The write oracle.** For mutating actions, do the same but **confirm the change landed on B's object** by re-reading it **as B** (or via an out-of-band signal). A 200 alone is not proof — verify the side effect on B's side (§12, §19).

**4.3 The verdict you produce here:** for each object, one of `IDOR-READ`, `IDOR-WRITE`, `BLOCKED (try bypass)`, or `SAFE (session-scoped)`. Carry the confirmed ones into Part III for impact.

> **Why two equal-role accounts (not admin vs user):** equal roles isolate the *object*-level check. If you test as admin you can't tell whether access was granted by role (expected) or by missing object check (the bug). Use admin separately, for **BFLA** (§10).

---

# PART II — FINDING & BYPASS (work in this order)

# 5. The ID Location & Format Taxonomy

You can only swap a reference you've found. Check **all** of these — IDOR hides in the boring places.

**5.1 Where the reference lives**
| Location | Examples | Notes |
|---|---|---|
| URL path | `/api/v2/users/123/cards/9` | test **every** segment, incl. nested child IDs |
| Query string | `?id=`, `?account_id=`, `?file=`, `?next=` | classic; also pagination `?cursor=` can leak others |
| Request body (form) | `user_id=123&action=update` | swap or **add** an id the UI never sends |
| Request body (JSON) | `{"orderId":123}`, nested `{"user":{"id":123}}` | check deeply nested & arrays |
| HTTP headers | `X-User-Id: 123`, `X-Account`, `X-Tenant-Id` | apps often trust these implicitly — high hit-rate |
| Cookies | `uid=123`, `account=`, `role=` | client-controlled; tamper them |
| GraphQL | `node(id:"…")`, `user(id:…)`, `invoiceById(id:…)` | §15 |
| Files/blobs | `/exports/inv_123.pdf`, S3 key, signed URL params | §14 |
| Referer / redirect params | `?return=/account/123` | second-order sinks |

**5.2 ID formats you'll meet** (drives §6/§7)
| Format | Looks like | Enumerable? |
|---|---|---|
| Sequential int | `123`, `124` | **Yes** — trivial (§6) |
| Offset/auto-increment with gaps | `1001`, `1002`, `1057` | Yes — fuzz ranges |
| Timestamp / snowflake | `1718900000`, `172983…` (large) | Partially — bounded by time window (§7) |
| UUIDv1 | `…-11ee-…` (time + MAC) | **Partially predictable** (§7.1) |
| UUIDv4 | random 128-bit | No — must **leak/obtain** it (§7.4) |
| UUIDv7 / ULID / KSUID | time-ordered (`018f…`, `01HZ…`, `2c8…`) | **Partially — timestamp-prefixed & sortable** (§7.5) |
| Mongo ObjectId | 24 hex (`65a1…`) | **Partially** — first 4 bytes = timestamp (§7.2) |
| Hashed/encoded | base64(`123`)=`MTIz`, md5(int), hex | Often **reversible/guessable** (§6.3) |
| **Hashids / Sqids / Optimus** | short alnum that *changes with the int* (`yr8`, `JR`, `1759`) | **Often reversible** — decode / recover the mapping (§6.6) |
| nanoid / short random token | `V1StGXR8_Z5jdHi6B` | only if short / low-entropy → brute |
| Composite / signed | `tenant_7:obj_42`, `id.sig` | tamper each part; check the signature is enforced |

> **First move on any encoded ID:** decode it. `?id=MTIz` → base64-decode → `123`. `?id=657a…` could be hex of an int or a hashed PK. If decoding reveals a sequential value, you have an enumerable ID wearing a costume (§6).

---

# 6. Predictable & Enumerable Identifiers

If the reference is guessable, IDOR becomes **mass** IDOR (the difference between Low and Critical — §11).

**6.1 Sequential integers.** Increment/decrement (`123`→`124`, `122`). **IF** you receive other users' objects → confirmed; then **enumerate a range** to size the impact (do it *politely* and with a *small* proof set — §25 OPSEC). Negative/zero/large edge cases (`0`, `-1`, `2147483648`) sometimes return admin/system objects or error-leak.

**6.2 Encoded sequential.** Base64 / hex / URL-encoded integers — decode, increment, re-encode. `id=dXNlcl8xMjM=` → `user_123` → `user_124` → re-encode.

**6.3 Weakly-hashed IDs.** `id=202cb962ac59075b964b07152d234b70` = `md5("123")`. If IDs are unsalted hashes of small integers, **precompute** the hash space and map it. Same for `crc32`, `sha1(int)`.

**6.4 Predictable “random”.** Sequential-with-jitter, time-prefixed, or per-user counters that reset. Capture 5–10 real IDs and **look for the pattern** before assuming randomness.

**6.5 The enumeration discipline (so it stays a valid, ethical finding).** Prove the *class* with a **handful** of IDs (3–5 of *your own* test objects + 1–2 belonging to your second test account), then **state** the population size by other means (max ID, `X-Total-Count`, pagination total) rather than scraping real users. Mass-scraping real PII can cross from "research" into a CFAA/GDPR problem and violates safe-harbor (§25). The report needs *proof of the pattern*, not a dump of strangers' data.

**6.6 Obfuscated-but-reversible IDs (Hashids / Sqids / Optimus) — the "looks random, is sequential" trap.** A *very* common false sense of security: developers wrap a sequential primary key in a reversible obfuscator so the URL shows `…/p/yr8` instead of `…/p/123`. These are **encodings, not access control** — recover the mapping and you have full enumeration.
- **Recognise it:** short alphanumeric ids (3–12 chars) that **change predictably as the underlying integer changes** — create 3–4 of your own objects in a row and compare (`gY6`, `J4Q`, `oE2`…). That ordered drift is the tell.
- **Hashids / Sqids** (Sqids is Hashids' successor): integer(s) → string via a shuffled **alphabet** + **salt** + min-length. **The alphabet/salt are client-discoverable** — they're almost always **baked into the front-end JS bundle** (search the JS for `Hashids`, `Sqids`, `new Hashids(`, `salt`, the alphabet string) or are the **library default** (default salt = empty → decodes with any Hashids decoder). Once you have alphabet+salt, decode B's id → integer → increment → re-encode → enumerate. Online/CLI Hashids & Sqids decoders make this one step.
- **Optimus / Knuth multiplicative hashing:** `encoded = (id * PRIME) XOR RANDOM mod 2^31` (and an inverse prime to decode). It's a **bijection** — capture a handful of `(realId, encoded)` pairs (or read PRIME/inverse/RANDOM from JS/config) and you recover the transform → full enumeration.
- **IF** ids look random but **decode to / track a sequential integer** (via a JS-leaked salt, a default salt, or a recovered transform) → treat them exactly like **§6.1 sequential ids**: it's mass-enumerable IDOR. "We obfuscate the id" is **not** an ownership check.

---

# 7. Non-Sequential ID Prediction & Disclosure

"Random" IDs do not stop IDOR — they change the *acquisition* method from *guess* to *obtain*.

**7.1 UUIDv1 (time + MAC).** v1 encodes a 60-bit timestamp + clock seq + **node (MAC) address**. If you can capture a few v1 UUIDs, tools like **`uuidv1-prediction` / sandwich attacks** narrow the search dramatically (you know the node and approximate time). **IF** the app issues v1 UUIDs for objects created near a known time → predictable.

**7.2 Mongo ObjectId (24 hex).** Structure = `4-byte timestamp | 5-byte random | 3-byte counter`. The timestamp and incrementing counter are **partially predictable**; given a couple of nearby ObjectIds you can fuzz the random/counter space far below 2^96. Useful when the app leaks one ObjectId and you want neighbours.

**7.3 Snowflake / time-based big ints.** Twitter-style snowflakes embed a millisecond timestamp + worker + sequence. Bounded by the creation time window → enumerable within a known interval.

**7.4 Disclosure — the most reliable path (just *get* the ID).** UUIDv4 is unguessable, so **harvest it**:
- **Other API responses** — list endpoints, search, autocomplete, "recent", notifications, activity feeds, exports often return *other users'* UUIDs.
- **Public surfaces** — profile pages, shared links, avatars/`/u/{uuid}`, sitemaps, JSON-LD, RSS.
- **Error messages & verbose responses** — "user {uuid} not found".
- **`Referer` / redirects / emails / webhooks** — IDs leak in URLs the victim's browser sends onward.
- **GraphQL** — a single over-permissive `users{ id }` or `node` query dumps every object id (§15).
- **Predictable-elsewhere** — the UUID is random but appears next to a sequential `slug`/`number` you *can* iterate.

> **IF** the ID is a random UUID **AND** you can obtain victims' UUIDs from any of the above **AND** the object endpoint doesn't check ownership → **it's still a full IDOR.** Report it; "UUIDs aren't guessable" is a non-defense if they're disclosed.

**7.5 Time-ordered IDs (UUIDv7 / ULID / KSUID / Snowflake-likes) — "sortable" means "enumerable."** The modern default for new systems is a **timestamp-prefixed, lexicographically sortable** identifier — and that orderability is exactly what makes it attackable:
- **UUIDv7** (RFC 9562, 2024): first **48 bits = Unix ms timestamp**, the rest random. Two objects made seconds apart share almost the entire prefix; the unguessable part is only the random tail within that window.
- **ULID**: 26 chars, **Crockford base32** — first **10 chars = 48-bit ms timestamp**, last 16 = randomness. Decodes trivially; the timestamp is in plain sight.
- **KSUID / Snowflake / Sonyflake**: timestamp + machine + sequence — same story.
- **How to attack:** you usually **know roughly when B's object was created** (B's signup date, an order/invoice date, a "created" field elsewhere, the `Date` header at creation). Set the timestamp prefix to that window and you've collapsed the search to the small random suffix — and where objects are created in bursts, **adjacent ids share the prefix and the sequence is near-contiguous**. Sort known ids to see the cadence.
- **IF** the id is **time-ordered (UUIDv7/ULID/KSUID)** and you can bound the creation time → it is **partially predictable / enumerable within a window**, not "random." Combine with disclosure (§7.4) for the random tail. Report the time-window enumeration explicitly.

---

# 8. Access-Control Bypass Techniques

When the direct swap returns 403/404, work this toolbox **before** concluding "protected." Each is a real, common gap.

**8.1 HTTP method / verb tampering.** The `GET /api/users/123` may check ownership, but `POST`/`PUT`/`PATCH`/`DELETE` (or `HEAD`, `OPTIONS`) on the same path may not. Also try **method override**: `X-HTTP-Method-Override: PUT`, `_method=PUT`, or `?_method=DELETE`. **IF** `GET` is 403 but `PUT /api/users/123 {…}` succeeds → BFLA/IDOR on write.

**8.2 Array / object wrapping.** Frameworks that ownership-check a scalar often skip the check when the value is wrapped:
```
id=123        →  id[]=123            (array)
{"id":123}    →  {"id":[123]}        (array)
{"id":123}    →  {"id":{"id":123}}   (nested object)
id=123        →  id=123&id=124       (parameter pollution — see 8.3)
```

**8.3 Parameter pollution / duplicate keys.** Send the reference **twice** — one yours, one the victim's. The auth layer may read the first occurrence and the data layer the last (or vice-versa): `?id=123(mine)&id=124(victim)`; in JSON `{"id":123,"id":124}`; mixed query+body. Also try **HPP across locations** (path says 123, body says 124).

**8.4 Type juggling.** `id=123` vs `id="123"` vs `id=123.0` vs `id=[123]` vs `id={"$ne":null}` (NoSQL). A loose comparison or a query-builder that mishandles types can drop the ownership filter. (Overlaps NoSQLi — chase RCE/dump if it bites.)

**8.5 Path & encoding tricks.** Append `.json`/`.xml`/`.pdf` (hits a different handler), add a trailing `/`, use `%2e`/`%2f`/double-encoding, change **case** (`/Users/` vs `/users/`), insert `;jsessionid=` or matrix params, or use **path traversal in the ID** (`123/../124`). WAFs/gateways and the app often normalize differently.

**8.6 Wildcard / null / boundary values.** `id=*`, `id=%`, `id=all`, `id=0`, `id=-1`, `id=` (empty), `id=null`, `id=me`/`id=current` vs a number. Some backends return **all** objects for a wildcard, or the **system/admin** object for `0`.

**8.7 Old / undocumented API versions.** `/api/v1/` is frequently left running with the *original, unguarded* logic after `/api/v2/` added the ownership check. Swap the version, drop `/api/`, hit `/internal/`, `/mobile/`, `/legacy/`, or the GraphQL equivalent (§15). Recon (§3.5) surfaces these.

**8.8 The 403-vs-404 enumeration oracle.** Even when reads are blocked, a server that returns **403 for "exists but not yours"** and **404 for "doesn't exist"** lets you **enumerate valid IDs** (and existence of users/objects) — itself a reportable info leak and a stepping stone. Measure status **and** response time/length.

**8.9 Referer / Origin / "internal" header trust.** Some object checks are bypassed by spoofing `Referer: https://target/admin`, `X-Forwarded-For: 127.0.0.1`, `X-Original-URL`, or a tenant/role header the gateway is supposed to strip but doesn't.

**8.10 Nested / parent-scoped child references ("the parent is mine, the child isn't checked").** One of the **most common real IDORs**: the server validates the **parent** in the path (which *is* yours) and then trusts the **child** id without re-checking it. Swap **only the child**:
```
GET /api/users/<MINE>/cards/<B's card id>          # my user, B's card → leaks B's card
GET /api/orders/<MINE>/items/<not-mine>            # my order, someone else's line item
GET /api/projects/<MINE>/members/<B>               # my project, B's member record
POST /api/accounts/<MINE>/transfer {to:<B's acct>} # parent scoped, child reference abused
```
**IF** keeping a valid (your-owned) parent while swapping a child/sub-resource id returns another user's data → IDOR. Test **every** id in a multi-segment path independently, not just the last one.

**8.11 Bulk / batch endpoints (mix your id with the victim's).** List/batch operations frequently check the **first** id (or none) and then act on the **whole array**:
```
POST /api/users/batch        {"ids":[<MINE>, <B>, <B2>]}      → returns all, incl. B's data
POST /api/cart/items/delete  {"ids":[<MINE>, <not-mine>]}     → deletes across users
GET  /api/messages?ids=<MINE>,<B>                              → mixed CSV of ids
GraphQL aliases / JSON-array batching                          → many objects, one request (§15)
```
**IF** putting a victim id alongside yours in a bulk request returns/affects the victim's object → IDOR (and an instant **mass** vector — feed the whole enumerated range).

> **Order of attempts:** direct swap → **nested child-id swap (keep your parent)** → method swap → array/pollution → type juggle → path/version → headers → wildcard/boundary → **bulk/batch id-mixing** → (record the 403/404 oracle regardless). One of these defeats a *large* fraction of "but it returned 403" endpoints.

---

# 9. Mass Assignment / Owner-Field Tampering (BOPLA)

You're allowed the object, but you set a **property you shouldn't control** — adjacent to IDOR and a direct ATO/priv-esc path.

**9.1 Inject the owner field.** On create/update, **add** a field the UI never sends:
```json
PUT /api/orders/7001   (A's own order)
{"items":[...], "owner_id":  <B's id> }     → reassign/relate to B
{"items":[...], "user_id":   <B's id> }
{"items":[...], "account_id":<victim tenant>}
```
**IF** the server honours `owner_id` from the body → you can move objects between users/tenants, or read/modify by re-pointing ownership.

**9.2 Escalate role / flags.** Add `"role":"admin"`, `"isAdmin":true`, `"is_staff":true`, `"verified":true`, `"plan":"enterprise"`, `"balance":99999`, `"permissions":["*"]` to a profile/settings update. Classic mass-assignment → **privilege escalation** (§13).

**9.3 Discover the field names.** Read them from: the **GET response** of the same object (mass-assign whatever it returns), GraphQL input types/`__type`, the mobile app's request bodies, JS source, API docs/Swagger, and error messages ("unknown field 'x'").

**9.4 JSON-Patch / Merge-Patch mass assignment (the modern variant).** APIs that accept `PATCH` with **`application/json-patch+json`** (RFC 6902) or **`application/merge-patch+json`** (RFC 7386) let you target fields the normal form never exposes — and the patch path often bypasses the allow-list applied to the form body:
```
PATCH /api/users/me   Content-Type: application/json-patch+json
[ {"op":"replace","path":"/role","value":"admin"},
  {"op":"add","path":"/permissions/-","value":"*"},
  {"op":"replace","path":"/owner_id","value":<B>} ]

PATCH /api/orders/7001   Content-Type: application/merge-patch+json
{ "owner_id": <B>, "status": "paid", "price": 0 }
```
**IF** a JSON-Patch/merge `op` on `/role`, `/isAdmin`, `/owner_id`, `/tenant_id`, `/balance`, `/price` sticks (read it back) → priv-esc / cross-tenant / financial tamper. Try it even when the plain JSON body is filtered — the patch handler is frequently a *separate*, less-guarded code path.

> **IF** read-IDOR is blocked but the object's **update** endpoint accepts an `owner_id`/`role` you control → you may not need to read at all; **write your way to impact** (reassign the object to yourself, or promote yourself to admin).

---

# 10. BFLA — Broken Function-Level Authorization

Not "which object" but "which **operation**." A normal user invoking privileged functions.

**10.1 Find privileged functions.** From JS/Swagger/GraphQL/mobile: `/api/admin/*`, `/api/users/{id}/role`, `/api/internal/*`, `*/delete`, `*/approve`, `*/impersonate`, `*/export-all`, feature-flag and billing endpoints. The admin **front-end** may hide the button, but the **API** is often unprotected.

**10.2 Invoke them as a low-priv user.** Replay the admin request you captured with the **admin** account, but with **user A's** token. **IF** it succeeds → BFLA. If you have no admin account, *construct* the request from docs/JS and fire it as A.
```
POST /api/admin/users        (create an admin)        as user A
PATCH /api/users/A {"role":"admin"}                    self-promote
POST /api/users/B/impersonate                          session as B
DELETE /api/orders/8001       (B's order)              destructive cross-user
```

**10.3 Method/route variants.** Same toolbox as §8 — admin function blocked on `/admin/` may be reachable on `/api/v1/admin/`, via method override, or via a GraphQL mutation that lacks the directive check (§15).

> **BFLA is usually Critical:** self-promotion to admin, creating admins, impersonation, mass-delete, or reading the **whole** dataset. Push every BFLA toward **admin → RCE** (admin file upload, template/settings injection, SSRF on admin integrations) (§13).

---

# PART III — VARIANTS & EXPLOITATION BY IMPACT (where the money is)

# 11. Read IDOR → PII & Mass Enumeration

**11.1 Single read.** A reads B's object (invoice, message, profile, medical record, address, payment method). Severity tracks **data sensitivity** (§21). Document exactly which fields leaked.

**11.2 Mass enumeration (the multiplier).** If the ID is enumerable (§6) or harvestable (§7), demonstrate **scale**: "iterating `/api/users/{1..N}` returns full PII for every user." This is what turns a Medium into a **Critical PII breach** (think First American, T-Mobile, Optus). Prove the pattern with a *small* set, state the population from `X-Total-Count`/max-ID (§6.5, §25).

**11.3 What to look for in the leaked object:** PII (name, email, phone, address, DOB, gov ID), financial (card last-4, bank, balance, transactions), auth material (password reset tokens, MFA secrets, API keys, session tokens — **these chain to ATO/RCE**), private content (messages, files, health), and **other users' object IDs** (feed §7 / second-order §17).

> **IF** the leaked object contains a **password-reset token, API key, or session token** → escalate immediately to **ATO/RCE** (§12, §13). A read IDOR that returns auth material is Critical, not Medium.

# 12. Write IDOR → Tamper → Account Takeover

The highest-frequency Critical IDOR.

**12.1 Change the victim's email/recovery → reset → ATO.**
```
PUT /api/users/<B>/email        {"email":"attacker@mine.test"}      (A's session)
# then trigger password reset for B → lands in attacker inbox → log in as B
```
**12.2 Change the victim's password directly** (endpoints that don't require the old password): `POST /api/users/<B>/password {"new":"…"}`.
**12.3 Disable/replace MFA, add a passkey/SSH/API key, change phone** on B's account → persistent takeover.
**12.4 Financial/state writes:** change B's payout/bank/shipping address, transfer funds, change order, cancel/approve, change subscription/plan.
**12.5 Confirm the side effect on B** (re-read as B / OOB) — a 200 isn't proof (§4.2, §19).

> Always prefer demonstrating the **terminal impact** (logged in as B / money moved) over the intermediate write — it's the difference between High and Critical and removes any "so what" from triage.

# 13. BFLA → Privilege Escalation → Admin → RCE

**13.1 Become admin** (§9.2 mass-assign role, or §10 invoke admin create/role endpoints).
**13.2 Use admin to reach code execution / total control:**
- Admin **file upload / plugin / theme** → webshell → **RCE**.
- Admin **settings**: SSTI in templates, SSRF in webhook/integration URLs, command in "run task"/backup/import features.
- Admin **user management**: read all secrets, impersonate, export the database.
- Admin **integrations**: cloud keys → metadata/SSRF → cloud account.

> The chain **IDOR/BFLA → admin → RCE** is the top-tier outcome: report the full chain, not just "I accessed an admin endpoint." (§22)

# 14. IDOR in Files, Exports, Attachments & Signed URLs

**14.1 Direct file references.** `/download?file=invoice_8001.pdf`, `/attachments/{id}`, `/exports/{uuid}.csv`. Swap the id/filename for B's. Add path traversal in the filename (`../`) → crosses into **LFI** territory (chain it).
**14.2 Predictable object-storage keys.** S3/GCS/Azure blob keys like `uploads/<userid>/<file>` — if the bucket/CDN serves them without auth and the key embeds an enumerable id, it's IDOR-at-storage.
**14.3 Signed-URL flaws.** Pre-signed URLs that (a) don't expire, (b) have a tamperable path/`response-content-disposition`, (c) reuse a weak HMAC, or (d) are generated for *any* id you pass → IDOR. Test removing/altering the signature and swapping the embedded key.
**14.4 Export/report endpoints** (`/export-all`, `/report?account=`) frequently lack object checks and return **bulk** data → instant mass-PII (§11).

# 15. IDOR in GraphQL

GraphQL concentrates IDOR because object access is **field-shaped**. (Full kit: `API/GraphQL/`.)

**15.1 `node(id:)` / `*ById` fields.** The Relay `node(id:"…")` interface and `userById`/`orderById` resolvers are textbook BOLA — pass B's (base64) global id:
```graphql
{ node(id: "VXNlcjoxMjQ=") { ... on User { id email phone } } }   # decode/encode: "User:124"
```
**15.2 Aliases for parallel enumeration** — request many objects in one query:
```graphql
{ a:user(id:1){email} b:user(id:2){email} c:user(id:3){email} }
```
**15.3 Batching** (alias-based or JSON-array) → mass-enumerate / rate-limit & OTP bypass (see the GraphQL kit).
**15.4 Mutations = write IDOR/BFLA** — `updateUser(id:<B>, input:{email:…})`, admin mutations lacking auth directives.
**15.5 Introspection / field-suggestion** reveals every `*ById`/`*ByEmail` sink even when the schema is "hidden."

> Decode global IDs (`base64`), iterate the inner value, and re-encode. GraphQL IDOR is often *un-rate-limited* and *un-logged* relative to REST → ideal for demonstrating scale (politely).

# 16. Multi-Tenant / Cross-Tenant IDOR

In SaaS, the worst IDOR crosses the **tenant** boundary — one customer reading/writing another customer's data.

**16.1 Find the tenant key.** `tenant_id`, `org_id`, `workspace`, `company`, subdomain (`acme.app.com`), or a `X-Tenant` header. Register **two orgs** (or use two test tenants).
**16.2 Swap the tenant reference** in path/body/header/subdomain while authenticated to tenant-1. **IF** you reach tenant-2's objects → cross-tenant IDOR (usually **Critical** — isolation is the core SaaS promise).
**16.3 Tenant-bound object IDs.** Even with per-tenant sequential IDs, test whether `tenant-1` session + `tenant-2`'s object id works, and whether **changing only the tenant key** (same object id) crosses over.
**16.4 Admin-within-tenant vs cross-tenant.** A tenant-admin reaching the *platform* admin or *another* tenant is the jackpot — combine §10 BFLA with the tenant swap.

# 17. Blind / Second-Order IDOR

The access check is missing on a path where you **don't see the response directly**.

**17.1 Second-order.** You write an id in one place; it's used (unchecked) later — e.g. set `notify_user_id=<B>` and B receives your data, or `report_to=<B>` exports to B. Confirm via the victim/OOB.
**17.2 Async / webhook / email sinks.** The object is processed by a job/webhook that fetches it without the caller's auth context. Use **interactsh** / your inbox as the victim signal.
**17.3 State-changing GET / pre-auth IDOR.** Some object actions are reachable **before** auth or via a link — confirm with a logged-out client.
**17.4 Differential confirmation.** When you can't read the result, prove impact by its **effect**: B sees the changed value, a notification fires, an OOB callback lands, a count changes. (§19 — write oracle.)

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 18. The Escalation Mindset

Every confirmed IDOR has a "now do Y." Don't submit the first read.
- Read one → **enumerate the population** (scale = severity).
- Read → did the object contain **auth material**? → **ATO/RCE**.
- Read → is there a **write** verb on the same object? → **tamper → ATO** (§12).
- User-object → is there a **function** (admin/role) version? → **BFLA → admin → RCE** (§13).
- Single-user → does it cross **tenants**? → cross-tenant (§16).
- Read IDOR + **credentialed CORS misconfig** (ACAO reflects origin + `ACAC:true`)? → the bug becomes **remotely exploitable**: any site the victim visits can `fetch()` their object and exfil it — no attacker auth needed. That raises severity (often `PR:N`/`UI:R`); document the CORS combo (cross-ref the CORS kit).
- Always ask: *what is the most sensitive object, owned by the most privileged victim, that this missing check exposes?*

# 19. The Validity-First Mindset — the Two-Account Proof

> **The rule that saves your reputation:** a valid IDOR is **"Account A (which I control) read or modified Account B's (which I also control) private object, using A's credentials."** Show both sides.

**The four questions a triager asks (answer them in the report):**
1. **Whose object?** — name it: B's order/profile/file, both test accounts you own.
2. **Whose credentials made the request?** — A's session/token (show the header you used).
3. **What came back / changed?** — B's data in A's response, or B's object changed (re-read as B).
4. **Is there a server-side ownership check?** — demonstrate its absence (A's request with B's id succeeds where it must not).

**Production-scope discipline:** confirm on the in-scope production host with **your own** test accounts; never use a real user's data as the "victim." If you can only show it cross-user with real accounts, **stop** and report the pattern with your own objects.

# 20. False Positives — STOP reporting these (auto-reject list)

| Pattern | Why it's NOT a valid IDOR | What to do instead |
|---|---|---|
| **One account, "I changed the id and saw data"** | Might be *your own* data or *public* data | Prove with **two** accounts (A reaches B's) (§4) |
| **Public-by-design objects** (public profiles, shared links, published posts) | No authorization expected | Drop, unless it exposes *private* fields too |
| **Returns *your own* object regardless of id** | Server session-scopes; the id is decorative | Not IDOR — stop on that object |
| **403/404 on the swap** with no working bypass | Ownership check is enforced | Try §8 toolbox; if all fail, it's not IDOR |
| **Guessed an id but got empty/denied** | No actual access | Need a successful cross-user read/write |
| **Needs the victim's own token/cookie/link to work** | That's the victim acting, not you | Not IDOR (maybe a different bug) |
| **Self-only data exposure** (you see your own secret) | No cross-user boundary crossed | Drop |
| **"Sensitive id is a UUID" with no access** | Predictable-id ≠ access; access is the bug | Only report if you can *reach the object* |
| **Rate-limit/enumeration "possible" with no data** | Theoretical | Demonstrate actual cross-user data |

> If you can't articulate "**A** used A's creds to reach **B**'s object," you don't have an IDOR yet.

# 21. Severity Calibration — how triagers rate IDOR

**CWE:** primary **CWE-639** (Authorization Bypass Through User-Controlled Key); related **CWE-284** (Improper Access Control), **CWE-285** (Improper Authorization), **CWE-863** (Incorrect Authorization), **CWE-566** (Authorization Bypass Through User-Controlled SQL Primary Key). BFLA → CWE-285/CWE-862 (Missing Authorization). Mass-assignment → CWE-915.

| Scenario | Typical severity | CVSS 3.1 vector (example) |
|---|---|---|
| **BFLA → admin / self-promote / impersonate → RCE or full control** | **Critical** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (~9.x) |
| **Write IDOR → ATO** (change victim email/pw/MFA) | **Critical/High** | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N` (~8.x) |
| **Mass-read of PII** (enumerable, whole user base) | **Critical/High** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N` (~7.5–8.5) |
| **Cross-tenant** read/write (SaaS isolation break) | **Critical/High** | scope-changed, raise C/I |
| **Single read of sensitive PII** (one record) | **Medium/High** | `AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N` (~6.5) |
| **Single write of low-sensitivity field** | **Medium** | `…/C:N/I:L/A:N` |
| **Read of low-sensitivity, own-adjacent data** | **Low** | minimal C |
| **403/404 enumeration oracle only** (no data) | **Low/Info** | info-leak framing |

> **Drivers:** *data sensitivity* × *scale (single vs mass)* × *read vs write* × *who the victim can be (any user / admin / tenant)*. `PR:L` because IDOR usually needs an authenticated attacker; `PR:N` if exploitable unauthenticated. Lead the report with the **highest proven** row.

# 22. Impact-Escalation Playbooks — "you found X, now do Y"

**22.1 You found: a read IDOR on one record (sequential id).** → Decode/confirm the id is enumerable → pull 3–5 of your own + 1 second-account object to prove the pattern → read `X-Total-Count`/max-id to state population → check the object for **auth material** (reset tokens/keys) → if present, pivot to ATO/RCE. Report as **mass-PII** with the scale stated.

**22.2 You found: a read IDOR but the id is a UUIDv4.** → Hunt the UUID in list/search/profile/GraphQL/Referer responses (§7.4) → if obtainable, it's a full IDOR → if it appears beside an enumerable slug, iterate the slug → report with the disclosure path documented.

**22.3 You found: 403 on the swap.** → Method swap (PUT/PATCH/DELETE/override) → array-wrap/param-pollution → type-juggle → `.json`/version/`/v1/` → header trust → record the 403-vs-404 **oracle** regardless. One usually works; if truly none do, drop the object.

**22.4 You found: a write endpoint you can point at B.** → Change B's **email/recovery → password reset → log in as B** (terminal ATO). If no email, try direct password/MFA/key change. Confirm the side effect as B.

**22.5 You found: a profile/settings update.** → Mass-assign `role/isAdmin/permissions/plan/balance/owner_id` (§9) → if role sticks, you're admin → drive admin → **RCE** (§13).

**22.6 You found: a GraphQL `node`/`*ById` field.** → Decode the global id, iterate, re-encode → use aliases/batching to enumerate at scale → test mutations for write/BFLA → introspect for more `*ById` sinks (→ `API/GraphQL/`).

**22.7 You found: cross-tenant access.** → Demonstrate read **and** write across the tenant boundary with two orgs you own → combine with BFLA for platform-admin → report as Critical isolation failure.

# 23. Building a Professional PoC

**The non-negotiables:**
1. **Two accounts you own** — label them A (attacker) and B (victim) with their ids/emails.
2. **Show the request** A sent (A's auth header) **with B's reference**, and the **response** containing B's data (or the confirmed change on B).
3. **Benign markers** — set B's email to `victim+idor@your-inbox.test`, change a field to an obvious test string; **never** touch real users.
4. **Minimal scale** — prove enumeration with a handful, not a dump (§6.5, §25).
5. **Reversible** — revert any writes; remove any objects/keys/admins you created.
6. A **curl/HTTP** snippet a triager can replay, plus screenshots/video of the two-account effect.

```bash
# Validity snippet (attacker A reads victim B's object):
curl -s https://target.com/api/orders/8001 \
  -H "Authorization: Bearer <A_TOKEN>" | jq '{owner, email, total}'   # → B's order, in A's session
# Write/ATO proof (then verify as B that B's email changed):
curl -s -X PUT https://target.com/api/users/<B_ID>/email \
  -H "Authorization: Bearer <A_TOKEN>" -H 'Content-Type: application/json' \
  -d '{"email":"victim+idor@your-inbox.test"}'
```

# 24. Reporting, CWE/CVSS & De-duplication

- **Title** = `IDOR/BOLA on <object> (<reference>) → <impact>` — e.g. *"BOLA on GET /api/orders/{id} → any user reads any order (full PII, enumerable)"*; *"Write IDOR on PUT /api/users/{id}/email → account takeover."* Never just "IDOR found."
- **Lead with the two-account proof and the highest impact** (mass/ATO/BFLA/cross-tenant).
- **CWE-639** (+ the related CWE that fits). CVSS per §21. State **scale** (single vs population) and **who the victim can be**.
- **De-dup:** one strong, well-escalated IDOR with the chain beats ten "id swap returns data" dupes. If the program already lists "BOLA on the API," frame your *distinct object/impact* (e.g. cross-tenant, or the ATO chain) clearly.

# 25. Automation & Red-Team Notes

**25.1 Coverage automation.** **Autorize** (browse as A while it replays as B / unauth) gives whole-app IDOR coverage; **AuthMatrix/Auth Analyzer** build a role×endpoint matrix. Run these continuously while you manually drive features — they catch the boring 80%.

**25.2 Custom diffing.** Script "request-as-A-with-B's-id → diff vs B's own response." Identical bodies (minus volatile fields) = IDOR. The `poc/` helper does exactly this for two captured sessions.

**25.3 Stealth / OPSEC (red-team & program-rules).**
- **Throttle enumeration** — IDOR enum is the noisiest thing you'll do; rate-limit, randomize order, spread over time. High-volume sequential id scans trip WAFs/anomaly detection and annoy programs.
- **Small proof sets** — never mass-exfiltrate real PII; prove the pattern with your own/second-account objects and *state* the scale. This keeps you inside safe-harbor and out of CFAA/GDPR trouble.
- **Don't destroy** — prefer read/benign-write; revert writes; never mass-delete or corrupt. Demonstrate destructive potential with **your own** objects.
- **Respect scope** — only registered in-scope assets; cross-tenant proofs use **your** second tenant, not a real customer.
- **Authorized targets only** — bug-bounty in-scope, signed engagements, CTFs, or your own labs.

**25.4 Where IDOR hides at scale:** mobile/`/v1/` APIs, GraphQL, export/report endpoints, webhooks, "internal" services exposed by misconfig, and anything added fast for a new feature (the ownership check is what gets forgotten under deadline).

---

# Appendix A — IDOR Workflow Cheat Sheet

```
0. TWO accounts A & B (same role) + (optional) admin + second tenant.
1. Proxy both → map every object reference (path/query/body/JSON/header/cookie/GraphQL/file).  §3,§5
2. Per object: capture A's request; note B's reference & format (seq/uuid/objectid/encoded).   §5,§6,§7
3. Swap B's reference into A's request. Read response.                                          §4
     200 + B's data → IDOR-READ.   403/404 → bypass toolbox.   A's own data → SAFE.
4. Bypass: method · array/pollution · type · path/.json/version · header · wildcard · 403/404.  §8
5. Owner-field mass-assign (owner_id/role/isAdmin)?  Function-level admin endpoints?            §9,§10
6. IMPACT: enumerate (mass PII) · write→ATO · BFLA→admin→RCE · files · GraphQL · cross-tenant.  §11-§17
7. VALIDATE two-account proof → FP filter → CVSS+CWE-639 → clean reversible PoC → dedup.        §19-§24
```

# Appendix B — IDOR Decision Tree

```
Is there a client-controlled reference to an object?            NO → not IDOR (look elsewhere)
            │ YES
Does the object belong to another user/tenant?                 NO (your own/public) → not IDOR
            │ YES
Swap B's reference into A's authenticated request → result?
   ├─ 200 + B's data ........................... IDOR-READ → enumerate? auth material? write verb? §11/§12
   ├─ 200 but A's own data .................... SAFE (session-scoped) → next object
   ├─ 403/404 ................................. try bypass (§8): method/array/pollution/type/path/version/header
   │        ├─ a bypass returns B's data ...... IDOR confirmed → impact
   │        └─ none work ...................... record 403-vs-404 oracle; likely SAFE
   └─ write accepted (verify on B) ........... WRITE-IDOR → ATO/owner-field/role → admin → RCE  §12/§13
Then: cross-tenant? (§16)  ·  function-level admin? (§10/§13)  ·  blind/second-order? (§17)
```

# Appendix C — Important Links
- **OWASP API Security Top 10** — API1:2023 **BOLA**, API3 **BOPLA/Mass Assignment**, API5 **BFLA**: https://owasp.org/API-Security/
- **PortSwigger Web Security Academy** — *Access control & IDOR*: https://portswigger.net/web-security/access-control
- **OWASP WSTG** — Testing for IDOR / Authorization: https://owasp.org/www-project-web-security-testing-guide/
- **CWE-639** https://cwe.mitre.org/data/definitions/639.html · **CWE-285** /285 · **CWE-863** /863 · **CWE-566** /566 · **CWE-915** (mass-assignment)
- **Tools** — **Autorize**, **AuthMatrix**, **Auth Analyzer**, **Authz** (Burp authz testing) · **Arjun** / **Param Miner** / **x8** (hidden params) · **kiterunner** (API routes) · **InQL** (GraphQL).
- **ID-format references** — Hashids (`hashids.org`) & **Sqids** (`sqids.org`) are *encodings, not security*; **Optimus** = Knuth multiplicative bijection (reversible); **UUIDv7/ULID** are timestamp-prefixed (RFC 9562 / `github.com/ulid/spec`); **UUIDv1** node+time prediction ("sandwich attack" — Versprite/Intruder UUID research).
- **Real cases / patterns** (read the writeups): First American Financial (2019, **885M** docs via sequential id), **T-Mobile API** (2023, BOLA, ~37M), **Optus** (2022, unauth API enumeration), **Peloton API** (2021, BOLA), **USPS Informed Visibility** (2018, ~60M), **Parler** (2021, sequential post ids), **Uber** (2019, account takeover via leaked UUID + IDOR), **GitLab** (multiple BOLA/access-control CVEs), **Bumble/Tinder** (geo-location IDOR), Facebook **Business/Page-role** IDORs. Pattern every time: *find reference → no ownership check → enumerate / write → mass PII / ATO / cross-tenant.*

> **Authorized testing only.** Two test accounts you own, benign markers, small proof sets, revert writes, respect scope and rate limits. Report **impact** (whose data, how many, read vs write, ATO/RCE), not "I changed an id."
