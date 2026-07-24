# OWASP Top 10:2025 — Zero to Expert (Q&A, Bug-Bounty / Red-Team / Interview Edition)

> A complete study + field + **interview** reference for the **OWASP Top 10:2025** web risk framework (the 8th
> installment). **Organized in Top-10 order** — everything for **A01** (what it is → how to test → red-team escalation →
> interview questions → defense) is together, then **A02**, … through **A10**. This is the **2025** umbrella companion;
> the **2021** edition Q&A is kept beside it (`OWASP_Web_Top_10_Zero_to_Expert.md`) — both on purpose. Learn the
> *categories* here; type the *payloads* in the deep per-class kits (see the map).
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, own labs. Two accounts + benign markers,
> prove impact, clean up, never test what you don't have written permission to test.

**Verified against the official source** (this doc tracks the *released* 2025 list, not memory):
- **OWASP Top 10:2025** — official list + per-category pages: https://owasp.org/Top10/2025/
- A03 Software Supply Chain Failures · A10 Mishandling of Exceptional Conditions (the two new categories) — official pages.
- OWASP **WSTG** · **ASVS** · **Cheat Sheet Series** · PortSwigger Academy + Research · PayloadsAllTheThings · HackTricks.
- Companion umbrella: `OWASP_WEB_TOP_10_2025.md`. Siblings: `../API/OWASP_API_TOP_10.md`, `../Mobile/OWASP_MOBILE_TOP_10.md`, `../AI/LLM/OWASP_LLM_TOP_10.md`. **2021 edition (kept):** `OWASP_WEB_TOP_10.md` + `OWASP_Web_Top_10_Zero_to_Expert.md`.

---

## TABLE OF CONTENTS
- **§0 — The framework & what changed 2021→2025** (Q1–Q14)
- **§A01 — Broken Access Control (incl. SSRF)** (Q15–Q28)
- **§A02 — Security Misconfiguration** (Q29–Q37)
- **§A03 — Software Supply Chain Failures** (Q38–Q48)
- **§A04 — Cryptographic Failures** (Q49–Q56)
- **§A05 — Injection** (Q57–Q69)
- **§A06 — Insecure Design** (Q70–Q76)
- **§A07 — Authentication Failures** (Q77–Q85)
- **§A08 — Software or Data Integrity Failures** (Q86–Q93)
- **§A09 — Security Logging & Alerting Failures** (Q94–Q99)
- **§A10 — Mishandling of Exceptional Conditions** (Q100–Q108)
- **§XC — Cross-category chaining & reporting** (Q109–Q114)

> Each `§A0x` block runs in the same order: **Core → How to test → Red-team / escalation → Interview → Prevention.**

---

# §0 — THE FRAMEWORK & WHAT CHANGED 2021→2025

### Q1. What is the OWASP Top 10:2025 and what is it *not*?
> *Plain version:* it's a "most common ways web apps get hacked" list, grouped into **10 buckets** — not 10 exact bugs. This is the newest (8th) edition. Don't tick it like a checklist: each bucket is a whole *family*, and you test every member.

The **8th installment** of OWASP's awareness document ranking the ten most critical web-application security **risk categories**. It is **not** a standard, not a checklist, not a list of individual bugs — each entry is a broad *category* several concrete vuln-classes fall under. Treating it as "ten bugs" is the beginner mistake; it's ten *families*, and you test every member.

### Q2. Name the 2025 Top 10 in order.
A01 Broken Access Control · A02 Security Misconfiguration · A03 Software Supply Chain Failures · A04 Cryptographic Failures · A05 Injection · A06 Insecure Design · A07 Authentication Failures · A08 Software or Data Integrity Failures · A09 Security Logging & Alerting Failures · A10 Mishandling of Exceptional Conditions.

### Q3. What changed from 2021 → 2025? (the #1 interview question right now)
> *Plain version:* three things to remember. **SSRF stopped being its own item** and joined A01; a **new "Supply Chain" bucket (A03)** appeared for bad/borrowed code; and a **new "Exceptional Conditions" bucket (A10)** appeared for how apps behave when they crash. Everything else just shuffled rank.

- **SSRF (2021 A10) merged into A01 Broken Access Control** — SSRF is an access-control violation; it's no longer standalone.
- **A03 Software Supply Chain Failures is NEW** — it *expands* 2021's A06 "Vulnerable and Outdated Components" into the whole supply chain (deps, CI/CD, malicious packages, vendor compromise). It was **#1 in the community survey** and had the **highest incidence (5.72%)**.
- **A10 Mishandling of Exceptional Conditions is NEW** — error/exception handling, fail-open, transaction rollback (24 CWEs).
- **A02 Security Misconfiguration rose #5 → #2.**
- **Two renames:** A07 "Identification and Authentication Failures" → **"Authentication Failures"**; A09 "Logging and **Monitoring**" → "Logging **& Alerting** Failures".
- Repositioned down: A04 Crypto (#2→#4), A05 Injection (#3→#5), A06 Insecure Design (#4→#6). **A01 stays #1.**

### Q4. Where did SSRF go, and why does that placement make sense?
> *Plain version:* SSRF is "make the server fetch something it shouldn't." That's really just *reaching something you're not allowed to* — the same idea behind all the other access-control bugs — so OWASP filed it under A01 instead of giving it its own slot. The attack itself didn't change.

Into **A01 Broken Access Control**. It makes sense because SSRF is fundamentally the *server accessing a resource it shouldn't* on the attacker's behalf — an access-control failure at the server-fetch boundary. So in 2025 you test SSRF as part of A01, though the technique (and this repo's `SSRF/` kit) is unchanged.

### Q5. What happened to 2021's "Vulnerable and Outdated Components"?
It was **expanded into A03 Software Supply Chain Failures**. Known-CVE components are still in scope, but A03 now also covers *malicious* supply-chain compromise: typosquatting, dependency confusion, compromised vendors, CI/CD pipeline attacks, and build/distribution/update integrity — the whole ecosystem, not just "old libraries."

### Q6. What are the two brand-new categories and their one-line focus?
- **A03 Software Supply Chain Failures** — vulnerabilities *or malicious changes* in third-party code, tools, dependencies, and the build/CI/CD pipeline.
- **A10 Mishandling of Exceptional Conditions** — failing to prevent/detect/respond to errors and unusual states (fail-open, no rollback, error-leak, resource-lock DoS).

### Q7. Risk category vs vulnerability class vs CWE vs CVE?
**Risk category** (A05 Injection) = the OWASP bucket. **Vulnerability class** (SQL injection) = a concrete bug kind. **CWE** (CWE-89) = the weakness *type* ID. **CVE** (CVE-2021-44228) = a specific *instance* in a product. A CVE is an instance of a CWE; the CWE falls under an OWASP category.

### Q8. Which 2025 categories carry the RCE ceiling?
**A05 Injection** (cmdi/SSTI/SQLi-file-write→RCE), **A03 Supply Chain** (known-CVE / malicious-dep → RCE), **A08 Integrity** (deserialization→RCE), and **A01** (the SSRF sub-class → cloud metadata → IAM → cloud takeover/RCE). RCE = full compromise, so bounties/CVSS peak there.

### Q9. Which category is #1 and why did it stay there?
**A01 Broken Access Control** — most prevalent, high impact (cross-user/admin data → mass PII/ATO), scanner-resistant (bespoke authz logic), and in 2025 it's *bigger* (absorbed SSRF). Start here on most engagements.

### Q10. Is 2025 final, or a Release Candidate?
It's published as the **standing 2025 edition (8th installment)**, released as **RC1**. The *structure* (new categories, top rankings, SSRF→A01) is locked; between RC and a "final 2025" stamp, expect only minor refinements (CWE mappings, wording, small rank tweaks) — not a restructuring. It stays the **2025** edition (the year label is settled).

### Q11. Should you report to a bug-bounty program using 2021 or 2025?
Match the **program's scope**. Many programs still reference **2021**; some have moved to 2025. Best practice: report the **concrete vuln + impact + CWE** (which is edition-independent), then tag *both* mappings where they differ — e.g. "SSRF = 2021-A10 / 2025-A01" or "component CVE = 2021-A06 / 2025-A03." That way it's correct regardless of which edition the program uses.

### Q12. How do you use the Top 10 as a *method*, not memorization?
Per category: **what it is → how to test (which concrete classes) → the kit that owns the payloads → the impact ceiling → prevention.** Run by **impact**: A01 (access control + SSRF) → A05 (injection) → A03 (supply chain) → A07/A08 (ATO/RCE) → A04/A02 (quick wins) → A06/A09/A10 (methodology).

### Q13. Interview cross-cutting — authN vs authZ, encoding vs encryption vs hashing, CVSS vs OWASP-rank, ASVS, defense-in-depth?
- **AuthN** = proving *who you are* (A07); **authZ** = *what you may do* (A01).
- **Encoding** (Base64/URL) reversible/no-key/representation (not security); **encryption** reversible-with-key/confidentiality; **hashing** one-way/integrity (passwords need a *slow salted* KDF).
- **Severity = CVSS** for your specific finding; **OWASP rank is not a severity** (it's average prevalence+impact). Cite category + CWE + CVSS.
- **ASVS** = the leveled, testable *requirements* you verify against; the Top 10 is *awareness*.
- **Defense in depth** = independent layers so one failure isn't fatal (XSS: validation + output-encoding + CSP + HttpOnly).

### Q14. Why does this repo keep BOTH the 2021 and 2025 docs?
Because programs and teams are mid-transition: some scope to 2021, some to 2025, and the *mapping differs* (SSRF moved, supply chain split out, a new A10). Keeping both lets you speak either framework accurately. The underlying techniques — and the 32 kits — are identical; only the category grouping/ranking changes.

---

# §A01 — BROKEN ACCESS CONTROL (incl. SSRF)

**Core**

### Q15. What is Broken Access Control in 2025 and what did it absorb?
Users acting outside intended permissions — plus, **new in 2025, SSRF**. Sub-types: **IDOR/BOLA** (object-level), **missing function-level authz / BFLA**, **vertical/horizontal** escalation, **forced browsing**, **metadata/JWT/cookie** manipulation, **CORS-enabled** cross-origin read, **path-based** bypass, **and SSRF** (server coerced to reach resources it shouldn't). → kits: `IDOR/`, `JWT/`, `CORS/`, `PathTraversal/`, `LFI/`, `SSRF/`.

### Q16. Why is SSRF now an access-control problem?
Because SSRF = the *server* being made to access a resource (internal service, cloud metadata, another user's data) that the requester isn't authorized to reach — the app fetches it on the attacker's behalf, bypassing the access boundary. OWASP re-classified it under A01 to reflect that root cause.

### Q17. IDOR vs BOLA — same thing?
Effectively yes. **IDOR** is the classic web term; **BOLA** is the API term (API1). Both = "the app exposes an object reference and doesn't check you're allowed *that* object."

**How to test**

### Q18. What's the single most productive A01 technique?
The **two-account differential**: do an action as user A, capture the exact request, replay it as user B (or against A's IDs with B's session) — success = authz not enforced server-side. Automate with Burp **Autorize/Autorepeater**.

### Q19. How do you test the SSRF sub-class under A01?
Find server-fetch sinks (URL params, webhooks, import-from-URL, link/image/PDF fetchers, SSO/OIDC metadata & JWKS). Point them at **`169.254.169.254`** (cloud metadata), localhost, internal IPs/hostnames → IAM creds / internal responses. For blind SSRF, confirm with an **OOB** listener. Bypass filters: DNS rebinding, redirect-to-internal (→ `OpenRedirect/`), IP encodings, IPv6, userinfo, alt schemes. → `SSRF/`.

### Q20. How do you test forced browsing and function-level authz?
Enumerate **unlinked/privileged paths** directly (`/admin`, `/api/internal/*`, `/user/123/promote`) with a low-priv/no token; guess by pattern; mine JS bundles for routes. If GET `/users/{id}` exists, try POST/PUT/DELETE and `/users/{id}/promote`. "Button not shown" is a UI control, not security.

**Red-team / escalation**

### Q21. How do you escalate a "read one other user's record" IDOR?
Push three axes: **breadth** (enumerate *all* IDs → mass PII), **verbs** (PUT/PATCH/DELETE unchecked → tamper/destroy), **sensitivity** (PII/payment/admin/cross-tenant). "One profile" = Medium; "enumerate + modify every account" = Critical.

### Q22. How does the SSRF sub-class reach cloud takeover?
SSRF → `http://169.254.169.254/…` → **IAM credentials** → assume the role → **cloud account takeover / RCE**; or → internal services (Redis/DB/admin) → RCE/lateral; `gopher://` for internal-protocol smuggling. Capital One is the canonical breach — now filed under A01. → `SSRF/`.

**Interview**

### Q23. "Explain why SSRF moved to Broken Access Control in 2025."
Because SSRF's root cause is an *access-control failure*: the server reaches a resource the attacker isn't authorized to reach, on their behalf. Rather than treat it as a standalone class, 2025 groups it with the other "reaching what you shouldn't" bugs. The technique is unchanged; only the bucket moved.

### Q24. "What's the difference between authentication and authorization?"
**AuthN** proves identity (A07); **authZ** decides permissions once authenticated (A01). Broken authZ is #1; broken authN is #7.

### Q25. "You can change a URL `id` and see another user's invoice — rate and escalate."
Baseline **High** (IDOR/BOLA, cross-user PII, CWE-639). Escalate: enumerate all (mass breach → Critical), modify/delete (write → higher), sensitivity (payment/PII). Prove with two own accounts, report impact-first.

**Prevention**

### Q26. How is A01 prevented (including SSRF)?
**Deny by default**; authorization **server-side on every request**, per-object *and* per-function; never trust client identity/role; ownership checks (not just unguessable IDs); centralize authz. **For SSRF**: allow-list outbound schemes/hosts/ports, re-validate after redirects, block internal ranges + metadata (egress filtering, **IMDSv2**), resolve-and-pin DNS.

### Q27. Why isn't "use UUIDs" a sufficient IDOR fix?
Security by obscurity — a UUID leaked elsewhere (referrer/logs/another endpoint) is still accepted because the server never checks *ownership*. Unguessable IDs are defense-in-depth; the fix is the per-object authorization check.

### Q28. CWEs for A01?
CWE-284, CWE-285, **CWE-639** (IDOR), CWE-862 (missing authz), CWE-863, CWE-22 (path), **CWE-918** (SSRF — now under A01).

---

# §A02 — SECURITY MISCONFIGURATION

**Core**

### Q29. What is A02 in 2025 and why did it rise to #2?
Insecure/default configuration anywhere in the stack — app, server, framework, cloud, container — **plus XXE**. It **rose from #5 (2021) to #2 (2025)** as stacks grew more complex (cloud, containers, more knobs → more ways to misconfigure). Default creds, verbose errors/debug, unnecessary features/ports, missing headers, permissive CORS, directory listing, exposed admin interfaces, open cloud storage.

### Q30. Why is XXE under Security Misconfiguration?
XXE is a **parser configuration** problem — the XML parser is left with external-entity/DTD processing enabled (insecure default). The fix is a config change (disable DOCTYPE/external entities). → `XXE/`.

**How to test**

### Q31. Fastest A02 wins on most targets?
**Exposure recon**: exposed `.git`/`.env`/backups (→ source + secrets), open cloud buckets, directory listing, default creds on admin/management interfaces, debug mode leaking stack traces/secrets, missing security headers. → `Recon/`, `JSFiles/`.

### Q32. Which concrete classes/kits route from A02?
`XXE/` (parser), `HostHeader/` (host-based reset/cache/routing), `CORS/` (permissive origin), `WebCache/` (cache poisoning/deception), `RequestSmuggling/` (front/back desync), `SubdomainTakeover/` (dangling DNS), `FileUpload/` (unrestricted upload→webshell), `Recon/`+`JSFiles/`.

**Red-team / escalation**

### Q33. How does XXE escalate beyond file read?
`file://` → local file read (`/etc/passwd`, source via `php://filter`); `http://` to internal/metadata → **SSRF → cloud IAM creds** (which is now an A01 escalation); blind OOB via external DTD; parser-specific → **RCE** (`expect://`, jar). Often Critical, not Medium. → `XXE/`.

**Interview**

### Q34. "Why did Security Misconfiguration move up in 2025?"
Because modern deployments (cloud, containers, IaC, service meshes) have far more configuration surface than a 2021 monolith — more defaults to leave on, more permissions to over-grant, more headers to forget. More knobs = more misconfigurations, so its prevalence rose, pushing it to #2.

### Q35. "You find an exposed `.git` directory. What now?"
Dump it (`git-dumper`) → recover full **source** + history → hunt hardcoded **secrets/keys/DB creds/machineKey** → map the app and find more bugs → chain (e.g. machineKey → ViewState RCE, A08). Often the start of a Critical, not just info leak.

**Prevention**

### Q36. Prevention for A02?
Harden by default (no defaults, no debug in prod, minimal features/ports); disable XXE; security headers (CSP/HSTS/X-Content-Type-Options/frame options); strict CORS + Host allow-list; lock down cloud storage; remove exposed VCS/config/backups; automated config review + drift detection.

### Q37. CWEs for A02?
CWE-16 (configuration), CWE-2, **CWE-611** (XXE), CWE-548 (directory listing), CWE-756, CWE-1032.

---

# §A03 — SOFTWARE SUPPLY CHAIN FAILURES

**Core**

### Q38. What is A03 (new in 2025) and what does it cover?
> *Plain version:* you didn't build most of your app — you assembled other people's libraries, tools and update pipelines. This new bucket is about that borrowed stuff going bad: an old library with a public hole, or an outright **malicious** package you installed by mistake. It's new, it's #3, and it's the cheapest way in.

Vulnerabilities *or malicious changes* in **third-party code, tools, and dependencies** — across building, distributing, and updating software. Covers unpatched/unmaintained deps, **malicious packages** (typosquatting, **dependency confusion**), compromised vendors, weak **CI/CD** security, and inadequate change management. It **expands** 2021's "Vulnerable and Outdated Components."

### Q39. Why is A03 ranked so high (new, at #3)?
It was **#1 in the community survey (50%)** and had the **highest incidence rate (5.72%)** — reflecting the explosion of supply-chain attacks. It's uniquely cheap for attackers (n-day exploits already exist) and uniquely high-blast-radius for the malicious variant (one poisoned package hits everyone downstream).

**How to test**

### Q40. How do you test the "vulnerable component" side of A03?
**Fingerprint** components + versions (server headers, framework tells, JS libs via retire.js, package manifests, favicon hashes → `Recon/`, `JSFiles/`); **map to known CVEs**; **verify exploitability in-context**. RCE classes: Log4Shell (`JNDI/`), deserialization gadgets (`Deserialization/`), vulnerable front-end libs → XSS/prototype pollution.

### Q41. How do you test the "malicious supply-chain" side of A03?
**Dependency confusion / typosquatting / repo-jacking**: mine leaked manifests, committed `.npmrc`/`pip.conf` (proving private package names), JS bundles; check if an internal package name is **claimable** (public 404); prove with a **benign callback** (token + hostname only) from the target's CI, then unpublish + report. → `DependencyConfusion/`.

### Q42. Why is "version-in-a-list ≠ a finding"?
A version match doesn't prove the vulnerable code path is used/reachable or that a backport isn't applied. Reporting raw scanner output causes false positives and burns triager trust. **Prove reachability/exploitability** or clearly label "potential."

**Red-team / escalation**

### Q43. What's the escalation from a dependency-confusion foothold?
A claimed internal package name → **install-hook RCE in the target's CI/CD** → cloud creds / signing keys / source access → downstream propagation to everyone who builds with it. The blast radius is the whole pipeline, not one host. (Prove benignly; describe-don't-exfil.) → `DependencyConfusion/`.

### Q44. How does A03 overlap with A08?
They share the **CI/CD + dependency** surface. A03 = "the component/package/vendor is vulnerable or malicious"; A08 = "the update/artifact/data lacks *integrity* protection (unsigned, unverified)." A malicious dependency in an unsigned pipeline is both. Follow the chain, not the label.

**Interview**

### Q45. "What's the difference between A03 (2025) and 2021's 'Vulnerable and Outdated Components'?"
2021 was narrow — *using components with known vulns* (outdated libraries). 2025's A03 **expands** it to the whole supply chain: not just old libs, but **malicious** packages, typosquatting/dependency-confusion, compromised vendors, and CI/CD pipeline attacks. It's "the entire ecosystem you depend on," not just "patch your libraries."

### Q46. "Explain dependency confusion in one minute."
An app installs an *internal* package name (e.g. `acme-internal-utils`) from a private registry. If the resolver also checks a public registry and picks the **highest version**, an attacker who publishes `acme-internal-utils` v99 to the *public* registry gets it pulled into the target's build → install-hook runs → **RCE in CI/CD**. Fix: reserve the name publicly, scope/pin, and configure the resolver to never fall back to public for internal names.

### Q47. "Name three real supply-chain attacks."
**Log4Shell** (Log4j RCE, mass-exploited); **SolarWinds** (poisoned build pipeline → signed malicious update); **dependency confusion** (Birsan 2021, benign PoC into 35+ companies) / the **Shai-Hulud npm worm (2025)**. Each shows a different facet: known-CVE, compromised pipeline, malicious package.

**Prevention**

### Q48. Prevention + CWEs for A03?
Inventory components (**SBOM**); patch continuously; monitor advisories; remove unused deps; **pin + verify integrity/provenance** (signatures); **reserve internal package names** publicly; secure CI/CD (least privilege, signed builds, no injectable steps); SCA in CI. CWEs: CWE-1104 (unmaintained third-party), CWE-1395 (vulnerable dependency), CWE-1329, CWE-477.

---

# §A04 — CRYPTOGRAPHIC FAILURES

**Core**

### Q49. What is A04 and where was it in 2021?
Failures in (or absence of) cryptography that expose sensitive data — was **A02 in 2021, dropped to #4** in 2025 (renamed from "Sensitive Data Exposure" to point at the root cause). Cleartext transport/storage, weak/deprecated algorithms, poor key management, weak password hashing, predictable tokens, improper cert validation.

### Q50. Encoding vs encryption vs hashing? (classic junior filter)
**Encoding** (Base64/URL) — reversible, no key, representation only, *not security*. **Encryption** — reversible with a key, confidentiality. **Hashing** — one-way, integrity; passwords need a **slow, salted KDF**. Calling Base64 "encryption" is an instant red flag.

**How to test**

### Q51. First things you check for A04?
Transport (cleartext HTTP for sensitive data? missing HSTS? cert gaps?), token/JWT crypto (`alg:none`, weak HS256 secret, RS256→HS256 — → `JWT/`), password-storage indicators (MD5/SHA1/unsalted in a disclosed dump), predictable reset/session/CSRF tokens (→ `AccountTakeover/`), secrets leaked in responses/JS/config (→ `JSFiles/`, `Recon/`).

**Red-team / escalation**

### Q52. How does an A04 finding become ATO/RCE?
Weak JWT secret → forge an admin token → **ATO**. Predictable reset token → seize accounts. Leaked machineKey (key-management failure) → ViewState deserialization → **RCE** (bridges A08). Sniffed session over HTTP → hijack. The crypto weakness is usually a *step* — chain it.

**Interview**

### Q53. "How would you store passwords correctly?"
A **slow, salted, password-specific KDF** — **Argon2id** (preferred), else bcrypt/scrypt/PBKDF2 — per-user salt (and ideally a server-side pepper). Never a fast general hash. Say "not MD5/SHA-*, not encryption."

### Q54. "What is HSTS and what attack does it stop?"
`Strict-Transport-Security` forces HTTPS for the domain, stopping **SSL-strip/downgrade** MITM. Pair with `includeSubDomains` + preload.

**Prevention**

### Q55. Prevention for A04?
TLS + HSTS; strong algorithms (AES-GCM, SHA-256+); adaptive KDFs for passwords; cryptographic RNG for tokens; sound key management (rotation, hardware-backed, no hardcoding); classify + minimize sensitive data; validate certs.

### Q56. CWEs for A04?
CWE-259/261, CWE-319 (cleartext transmission), CWE-321 (hardcoded key), CWE-326/327 (weak/broken crypto), CWE-328 (weak hash), CWE-331, CWE-916.

---

# §A05 — INJECTION

**Core**

### Q57. What is injection, and what unifies the class?
> *Plain version:* your input sneaks out of the "data" lane into the "commands" lane, and something downstream runs it. The one cure: keep code and data in separate lanes so input can't change the *structure* of what runs. (Same bucket as always — it just moved from #3 to #5.)

Untrusted input interpreted as **code/command/query** by a downstream interpreter because data and control share one string. The unifying fix is **separation of code and data** (parameterization / safe APIs / context-aware encoding). Was **A03 in 2021, dropped to #5** in 2025 — still **holds XSS**.

### Q58. Which concrete classes live under A05 and which kits own them?
SQLi (`SQLi/`), NoSQLi (`NoSQLi/`), OS command injection (`CommandInjection/`), SSTI (`SSTI/`), XPath/XQuery (`XPath/`), LDAP (`LDAP/`), expression-language, CRLF/header injection (`OpenRedirect/` §CRLF + `HostHeader/`), prototype pollution (`PrototypePollution/`), XSS (`XSS/`), XXE (`XXE/`, bucketed in A02). Largest kit cluster.

### Q59. Why is XSS under Injection?
Because XSS **is** injection — input interpreted as **code by the browser** (HTML/JS). Same root cause (data-as-control), same fix (context-aware output encoding + sanitization).

**How to test**

### Q60. How do you detect injection with low false positives?
**Prove interpretation, not reflection.** A reflected `'`/`;` is not a bug. Confirm the interpreter *acted*: boolean-differential pages, a **repeatable** time delay vs a control baseline (blind), an **OOB** callback carrying your marker, or real output. Control-baseline every probe.

### Q61. How do you distinguish SSTI vs XSS vs code injection?
Math probe `{{7*7}}` / `${7*7}` / `<%= 7*7 %>`: renders **49** server-side → **SSTI** (→ often RCE); reflected but executes in browser → **XSS**; language `eval` of input → **code injection**. Fingerprint the engine to pick the RCE payload. → `SSTI/`.

**Red-team / escalation**

### Q62. What's the impact ceiling per major injection class?
SQLi → dump/auth-bypass/file-RW→webshell→**RCE**/lateral; command injection & SSTI → direct **RCE**; NoSQLi → auth bypass + blind exfil; XSS → session theft/**ATO**/worm; LDAP/XPath → auth bypass + directory/XML dump.

### Q63. How does SQLi become RCE?
MSSQL `xp_cmdshell`; PostgreSQL `COPY ... FROM PROGRAM`; MySQL `INTO OUTFILE` webshell / UDF; Oracle Java procs. Also file-read of source/secrets, privesc via linked servers. → `SQLi/`.

**Interview**

### Q64. "How do you prevent SQL injection?"
**Parameterized queries / prepared statements** (separate code from data). Supplement with least-privilege DB accounts, allow-list validation, a correctly-used ORM. Say "not escaping/blacklisting" — that's the tell you know the real fix.

### Q65. "Stored vs reflected vs DOM XSS?"
**Reflected** — request payload echoed in the immediate response (needs a click). **Stored** — saved server-side, served to *every* viewer (worse). **DOM** — injection happens client-side in JS (source like `location.hash` → sink like `innerHTML`), often invisible to the server. → `XSS/`.

### Q66. "What is CSRF and how is it different from XSS?"
**CSRF** — attacker's site makes the victim's browser send a *state-changing* request to a site where they're authed, abusing ambient cookies (can't read the response). **XSS** — attacker runs *script in the victim's context* (reads data, does anything). XSS is stronger and defeats most CSRF defenses. Fix CSRF: SameSite + tokens. → `CSRF/`.

**Prevention**

### Q67. Prevention per injection class?
Parameterized queries (SQL); operator allow-listing (NoSQL); avoid the shell / exec-array APIs (command); sandbox/disable dangerous template features + never template user input (SSTI); context-aware output encoding + CSP + sanitizer (XSS); escape for the exact interpreter; least-privilege service accounts.

### Q68. What is CSP and how does it mitigate XSS?
Content-Security-Policy restricts which script sources execute (nonce/hash/allow-list, no inline). Even if an injection lands, strict CSP blocks the script — defense-in-depth behind output encoding. Mitigates, doesn't cure; still fix the injection.

### Q69. CWEs for A05?
CWE-79 (XSS), CWE-89 (SQLi), CWE-78 (OS command), CWE-90 (LDAP), CWE-91/643 (XML/XPath), CWE-94 (code), CWE-1336/917 (template/EL), CWE-74 (generic injection).

---

# §A06 — INSECURE DESIGN

**Core**

### Q70. What is Insecure Design and where was it in 2021?
A **missing or ineffective security control at the design level** — the flaw is in *what was designed*, not a coding mistake, so it needs a design change (threat modeling, secure patterns, abuse-case testing). Was **A04 in 2021, dropped to #6** in 2025.

### Q71. The canonical example distinguishing A06 from an implementation bug?
A password-reset flow with **no rate limiting by design** → unlimited OTP/token guessing → ATO. Validation doesn't help; the *design* omitted anti-automation. Contrast: an SQLi in that endpoint is an *implementation* bug (A05).

**How to test**

### Q72. What concrete testing lives under A06?
**Business-logic abuse** (negative/overflow quantities, price manipulation, workflow-step skipping, coupon stacking, one-time-action replay, state-machine bypass); **race conditions** (limit-overrun via parallel requests — → `RaceCondition/`); **missing-by-design rate limiting** (OTP/reset brute — → `AccountTakeover/`); trust-boundary failures.

**Red-team / escalation**

### Q73. What is a race condition and how does it realize an A06 flaw?
Concurrent requests hitting a **check-then-act** window assumed serial: redeem-once, withdraw-within-balance, one-vote, use-OTP-once. Parallel requests → limit enforced N times but effect applied N times (double-spend). A design failure of atomicity. → `RaceCondition/`.

**Interview**

### Q74. "Give an example of a business-logic vulnerability."
Skipping payment by calling the order-confirmation endpoint directly; a negative quantity yielding a credit; stacking one-per-user coupons via parallel requests (race); manipulating a client-set price. All "valid" requests, real financial impact — A06.

**Prevention**

### Q75. Prevention for A06?
Threat-model early; secure design patterns + a control library; enforce business rules server-side + re-validate each step; design in rate limiting / anti-automation / **atomicity** (transactions, locks); write + test abuse cases; segment trust boundaries.

### Q76. CWEs for A06?
CWE-209, CWE-256, CWE-501, CWE-522, **CWE-362** (race), CWE-841 (workflow).

---

# §A07 — AUTHENTICATION FAILURES

**Core**

### Q77. What is A07 and what was it renamed from?
Weaknesses in confirming identity, authenticating, and managing sessions — **renamed** from 2021's "Identification and Authentication Failures" to **"Authentication Failures"** (tighter focus). Credential stuffing/brute exposure, weak/default passwords, weak MFA, session flaws (fixation, no invalidation), weak reset flows, federation (OAuth/SSO/SAML) flaws.

### Q78. What's the impact ceiling and why?
**Account takeover** — the whole category is impersonating a user. Break auth and everything behind it is accessible as that user/admin. Weak reset → ATO; no rate limit → brute/OTP bypass; fixation → hijack; OAuth misconfig → token theft; stuffing → *mass* ATO.

**How to test**

### Q79. Walk through testing a password-reset flow.
Check **host/link poisoning** (Host header controls the reset link → capture token — → `HostHeader/`); **token entropy** (sequential/timestamp/short); **token leakage** (`Referer`/logs/response); **email HPP/CRLF** (second recipient); **no rate limit** (brute token/OTP); **reuse/expiry**; **user enumeration**. → `AccountTakeover/`.

### Q80. What headline OAuth/SSO flaws do you test?
`redirect_uri` bypass (→ code/token theft), missing `state` (→ login CSRF / account-linking ATO), code replay, PKCE downgrade, `id_token` forgery (`alg:none`/unverified sig/`aud` swap), SAML XSW/sig-strip. → `OAuth/` (+ `JWT/`).

**Red-team / escalation**

### Q81. What is "pre-account-takeover" and why is it a favorite?
Attacker **pre-registers** the victim's email (unverified); victim later signs up via SSO which **merges/links** to the attacker-seeded account → attacker keeps access → ATO. Silent, high-impact, commonly missed. → `OAuth/` + `AccountTakeover/`.

### Q82. How does a JWT flaw become full ATO?
`alg:none` (server accepts unsigned) → forge any `sub`/`role`; weak HS256 secret → crack + sign an admin token; RS256→HS256 confusion → sign with the public key as HMAC secret; `kid`/`jku` injection → point verification at your key. → `JWT/`.

**Interview**

### Q83. "How do you implement secure session management?"
Rotate the session ID on login (defeat fixation); invalidate server-side on logout + expiry; short-lived + idle timeout; `HttpOnly` + `Secure` + `SameSite` cookies; never put session IDs in URLs. AuthN success must issue a *new* session.

### Q84. "What is MFA and does it stop everything?"
Multi-factor requires ≥2 of know/have/are. It blocks password-only stuffing/phishing — but not **weak MFA** (no rate limit on OTP → brute; SMS → SIM-swap; response-flip; MFA-fatigue push-bombing). MFA presence ≠ MFA done right. → `AccountTakeover/`.

**Prevention**

### Q85. Prevention + CWEs for A07?
MFA; no default/weak passwords + breached-password checks; **rate limiting + lockout** on all auth/OTP/reset endpoints; secure sessions (Q83); host-independent reset links + strong tokens; exact-match OAuth `redirect_uri` + `state` + PKCE; verify email before SSO linking. CWEs: CWE-287, CWE-384, CWE-307, CWE-620, CWE-640, CWE-798, CWE-613.

---

# §A08 — SOFTWARE OR DATA INTEGRITY FAILURES

**Core**

### Q86. What is A08 and how does it relate to the new A03?
Code/infrastructure failing to protect against **integrity violations** — unverified sources/plugins/data, auto-updates without integrity checks, **insecure deserialization**, **CI/CD** compromise (unchanged from 2021 A08). In 2025 it **overlaps A03 Supply Chain** on the CI/CD + dependency side — A08 is the *integrity* lens (unsigned/unverified), A03 is the *component/ecosystem* lens.

### Q87. Why is insecure deserialization the headline?
Deserializing attacker-controlled data can instantiate arbitrary objects and trigger **gadget chains → RCE**. Per-language: Java `ObjectInputStream` (ysoserial), PHP `unserialize`/phar (PHPGGC), .NET `BinaryFormatter`/ViewState (ysoserial.net), Python `pickle`, Ruby `Marshal`, Node `node-serialize`. → `Deserialization/`.

**How to test**

### Q88. How do you *safely* confirm deserialization without a shell?
**OOB-first**: a benign gadget causing only a **DNS/HTTP callback** (Java **URLDNS**) or a `sleep` — proves the blob is deserialized *without* running attacker code on the target. Then stop and report (SAFE-PoC).

### Q89. What are ViewState and machineKey?
ASP.NET **ViewState** is a serialized blob round-tripped via the client. If **not MAC-protected** or the **machineKey** is leaked/default, an attacker forges a malicious ViewState → deserialization → **RCE** (ysoserial.net). A leaked machineKey (via `.git`/config/LFI) → RCE — bridges A02/A04/A08. → `Deserialization/`.

**Red-team / escalation**

### Q90. How does A08 cover CI/CD and updates?
Auto-updates that fetch + run code **without signature verification**, unsigned artifacts, injectable pipeline steps, compromised deps (→ `DependencyConfusion/`, also A03). **SolarWinds** is the archetype: trusted pipeline → signed-but-poisoned artifact → mass compromise.

**Interview**

### Q91. "Why is deserializing untrusted data dangerous?"
Because deserialization reconstructs arbitrary object graphs and invokes methods during/after construction; with the right **gadget chain** on the classpath, that's code execution — without the app "intending" to run code. Fix: don't deserialize untrusted data, or use data-only formats + type allow-lists + integrity checks.

**Prevention**

### Q92. Prevention for A08?
Avoid deserializing untrusted data (or safe formats + type allow-lists + integrity/signature checks); **sign + verify** updates/plugins/artifacts; verify dependency integrity/provenance + pin; secure CI/CD; never trust unsigned data for security decisions.

### Q93. CWEs for A08?
**CWE-502** (deserialization), CWE-345 (insufficient integrity), CWE-494 (download without integrity check), CWE-829, CWE-565.

---

# §A09 — SECURITY LOGGING & ALERTING FAILURES

**Core**

### Q94. What is A09 and what was renamed?
Insufficient logging, **alerting**, monitoring, and incident response — so attacks aren't detected, escalated, or investigated. **Renamed** from 2021's "Logging and **Monitoring**" to "Logging **& Alerting**", emphasizing that logs *without alerting* don't stop attacks. It **amplifies every other bug** (attackers operate unnoticed).

**How to test**

### Q95. How do you assess A09 during a test?
Do noisy things (failed logins, authz denials, injection probes, high-value actions) and ask **"was it detected AND did it alert?"** Check whether auth failures, access-control denials, input-validation failures, and high-value transactions are logged with context. Red-team: operate below alerting thresholds.

**Red-team / escalation**

### Q96. What's the offensive angle on A09?
**Log injection** (CRLF/newline into a logged field → forge/split log entries; or a value that triggers execution when logged → **Log4Shell/JNDI** — → `JNDI/`) and **sensitive data in logs** (PII/tokens/passwords, later exposed). A09 can be both a detection gap *and* a concrete finding.

**Interview**

### Q97. "Why did 2025 rename it to include 'Alerting'?"
Because logging alone is useless if no one is notified — many breaches had *logs* but no *alert*, so they went undetected for months. The rename stresses that detection requires **alerting + response**, not just recording. It's a shift from "did you log it?" to "did anyone find out in time?"

### Q98. "How is Log4Shell related to A09?"
The ultimate irony: the **logging** path became RCE. A user-controlled value (User-Agent, username) logged by vulnerable Log4j triggered a **JNDI lookup → remote class load → RCE**. Logging untrusted input *unsafely* is both an A09 concern and an A03/A08 RCE. → `JNDI/`.

**Prevention**

### Q99. Prevention + CWEs for A09?
Log security-relevant events with context + integrity; centralize + monitor + **alert** (the 2025 emphasis); protect logs (encode logged input; no sensitive data in logs); define + test incident response; retain appropriately. CWEs: CWE-778 (insufficient logging), **CWE-117** (log injection), CWE-223, CWE-532 (sensitive info in logs).

---

# §A10 — MISHANDLING OF EXCEPTIONAL CONDITIONS

**Core**

### Q100. What is A10 (new in 2025)?
> *Plain version:* this new bucket asks a simple question — when something **goes wrong** (bad input, a crash, a half-finished payment), does the app stay safe? Unsafe apps "fail open" (an error accidentally lets you in), leak internal details in the error page, or leave transactions half-done. You test it by *breaking* things on purpose.

Failing to **prevent, detect, and respond to unusual/unpredictable situations** — improper error/exception handling, missing input/environment safeguards, poor recovery, and **fail-open** behavior (defaulting to *allow* on error) instead of **fail-closed**. Also: transactions that don't roll back on error, and errors that leak internal detail. 24 CWEs.

### Q101. What's the security-relevant core of A10?
**Fail-open** decisions. If an auth/authz/validation component *errors* and the app defaults to "allow," an attacker who can *trigger* the error bypasses the control. The safe design is **fail-closed** (default-deny on error) + complete rollback of partial state. That's the difference between a crash and a breach.

**How to test**

### Q102. How do you test for A10?
**Break the app on purpose and watch how it fails**: send malformed/wrong-type/oversized/empty input; interrupt or parallelize a multi-step flow; exhaust a dependency; force an auth/validation component to error. Then observe: does it **fail open** (allow) or closed (deny)? does it **roll back** or leave partial/duplicate state? does the error **leak** stack traces / DB info / paths / secrets? does an exception leave a **resource locked** (→ DoS)?

### Q103. Which kits help test A10, given no single kit owns it?
`SQLi/` (error-based — verbose DB errors that leak schema); `Recon/` (verbose-error info disclosure → recon); `IDOR/` (an authz check that **fails open** on error = a bypass); `RaceCondition/` (interrupt/parallelize a multi-step transaction → partial/duplicate state). A10 is largely **methodology** — it's the discipline of testing the *failure* paths, not just the happy path.

**Red-team / escalation**

### Q104. Give the three canonical A10 cash-outs (OWASP's example scenarios).
1. **DoS** — an uncaught exception (e.g. a file-upload error) leaves resources/locks/handles held → exhaustion → availability loss.
2. **Data exposure** — a database/stack error reveals internal details (schema, paths, versions) → reconnaissance for injection.
3. **Financial fraud / logic abuse** — an interrupted multi-step transaction without rollback → account draining or duplicate transfers.

**Interview**

### Q105. "What does 'fail closed vs fail open' mean, with a security example?"
> *Plain version:* "fail closed" = when in doubt, say **no** (an auth check that errors → deny). "Fail open" = when in doubt, say **yes** (an auth check that errors → *let everyone in*). Security must fail closed. The classic bug: a permission check wrapped in try/catch that returns "allowed" in the catch block, so any crash grants access.

**Fail closed** = on error/uncertainty, default to *deny/safe* (e.g. an authz service that times out → deny access). **Fail open** = default to *allow* (→ timeout means everyone gets in). Security controls must fail **closed**. A classic bug: a licensing/authz check wrapped in a try/catch that returns `true` in the catch block → any exception grants access.

### Q106. "Why did OWASP add 'Mishandling of Exceptional Conditions' in 2025?"
Because a large class of real bugs lives in the **failure paths** — error handlers, exception flows, partial transactions, and fail-open defaults — which prior categories didn't cleanly capture. It's a data-and-survey-driven recognition that *how software behaves when things go wrong* is itself a top-tier risk (fail-open bypasses, error-leak recon, no-rollback fraud, resource-lock DoS).

### Q107. "How is A10 different from A06 Insecure Design and A09 Logging?"
**A06** = the *design* lacks a control (missing rate limit by design). **A09** = you don't *detect/alert* on events. **A10** = the app *mishandles the error/exception itself* — it fails open, doesn't roll back, or leaks via the error. They overlap (a verbose error is A10 + A09; a no-rollback transaction is A10 + A06), but A10's specific lens is **behavior under exceptional conditions**.

**Prevention**

### Q108. Prevention + CWEs for A10?
Catch exceptions at their source; centralized/global exception handling; **fail closed** (default-deny on error, complete rollback on partial failure); generic error messages (log detail server-side — ties A09); input validation + resource quotas + rate limiting; monitor repeated-error patterns as attack signals. CWEs: CWE-209 (sensitive error messages), CWE-234, CWE-476 (NULL deref), **CWE-636 (failing open insecurely)**.

---

# §XC — CROSS-CATEGORY CHAINING & REPORTING

### Q109. What's a canonical 2025 kill chain across categories?
**A02** (exposed `.git`) → source + leaked machineKey → **A08** ViewState deserialization → **RCE** → coerce a server fetch (**A01 SSRF**) → cloud metadata → IAM → cloud takeover. Or **A03** (dependency confusion) → CI/CD RCE → signing keys → supply-chain propagation. Chains cross categories; follow impact, not labels.

### Q110. Which 2025 categories are "enablers" vs "finishers"?
**Enablers**: A02/A03 (exposure, known-CVE/malicious-dep entry), A01 (reach objects/functions/SSRF), A04 (leaked tokens/keys), A09 (operate unseen), A10 (fail-open bypass / error-leak recon). **Finishers**: A05 (RCE/dump), A03/A08 (RCE), A01-SSRF (cloud takeover), A07 (ATO). Reports show the enabler→finisher path.

### Q111. How do you keep false positives low across the 2025 Top 10?
**Control-baseline everything**; prove *interpretation/impact* not *reflection*; two accounts for authz claims; confirm blind bugs with repeatable timing or OOB; verify component CVEs are reachable. A finding reproducible with a benign marker and a clear "as X I did Y to Z" is triager-proof.

### Q112. How do you report when a program still uses the 2021 edition?
Report the **concrete vuln + impact + CWE** (edition-independent), then give **both** mappings where they differ: "SSRF → cloud metadata (2025-**A01** Broken Access Control / 2021-**A10** SSRF, CWE-918)" or "outdated Log4j RCE (2025-**A03** Supply Chain / 2021-**A06** Components, CWE-1395)." Both edition docs are kept in this repo for exactly this.

### Q113. What are the biggest 2021→2025 mapping gotchas to memorize?
- **SSRF**: 2021-A10 → **2025-A01**.
- **Component CVE / outdated lib**: 2021-A06 → **2025-A03** (now "Software Supply Chain Failures").
- **A02 Security Misconfiguration**: #5 → **#2**.
- **New A10**: Mishandling of Exceptional Conditions (didn't exist in 2021).
- **Renames**: A07 "Authentication Failures", A09 "…& Alerting Failures".

### Q114. The one meta-lesson across all ten (2025 edition)?
**Never trust the client, separate code from data — and design your *failure* paths as carefully as your success paths.** 2025 keeps the classic lessons (A01 trust, A05 code/data) but elevates two modern truths: your security is only as strong as your **supply chain** (A03) and your app is only as safe as **how it behaves when things break** (A10, fail-closed). Zero-trust input, least privilege, verified dependencies, and fail-closed errors collapse most of the list.
