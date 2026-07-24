# OWASP Top 10 (2021) — In-Depth Testing Reference & Kit Map (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Web applications and their APIs — the classic OWASP Top 10 risk categories, mapped to how you *test* each one and to the **deep per-class kits in this repo** that own the hands-on technique. This is the index/map: each category points to the kit(s) that carry the payloads, arsenals, and PoC.
**Standard:** OWASP **Top 10:2021** (the current stable web list; a 2025 revision is in progress — noted where relevant). IDs are `A01:2021` … `A10:2021`.
**Platforms:** any; tooling in Kali/WSL + Burp.

> **This is the umbrella map over the 32 Web kits, sibling of the LLM/Mobile/API Top 10 docs.** The OWASP Top 10 is a *risk-category* framework, not a vuln list — most categories are broad buckets that several concrete vuln-classes fall into. This document does two things: (1) explains each category in depth (what it is, how to test, impact, prevention), and (2) **routes you to the deep kit** that owns each concrete technique. Use it to go from "the report scope says A03 Injection" to "so I run the SQLi / NoSQLi / CommandInjection / SSTI / XPath / LDAP kits." The mistake is treating a category as a single bug; it's a family — hit every member.

---

> ### ⚡ READ THIS FIRST — the Top 10 is categories, the kits are the bugs
> 1. **Categories ≠ vulnerabilities.** "A03 Injection" is a bucket containing SQLi, NoSQLi, command injection, SSTI, XPath, LDAP, and more — each has its own deep kit here. Map the category → the concrete classes → the kits.
> 2. **A01 Broken Access Control is #1 for a reason.** It's the most common and most impactful bucket: IDOR/BOLA, privilege escalation, forced browsing, missing function-level authz. Start here on most engagements.
> 3. **Impact-first, always.** OWASP ranks by prevalence + impact, but *your report* is rated by demonstrated impact. Every category below cashes out through a concrete kit's "impact ceiling" (RCE / ATO / mass data / SSRF-to-cloud).
> 4. **Several classes span multiple categories.** SSRF is its own A10 *and* an enabler across A01/A03; XXE lives under A05 (2021 folded it in) but reaches SSRF/RCE; deserialization is A08 but yields RCE. Follow the chain, not the label.
> 5. **The API twin.** For API-specific testing use the **OWASP API Security Top 10 (2023)** — this repo's `API/REST/` kit covers it (BOLA/BFLA/BOPLA/etc.). Web Top 10 and API Top 10 overlap but are scored differently; pick the right frame for the target.
>
> **Where the money is (memorize):** ① **A03 Injection → RCE/ATO/mass-dump (SQLi/cmdi/SSTI kits) — Critical** → ② **A01 Broken Access Control → IDOR/BOLA/privesc → mass data/ATO — Critical** → ③ **A10 SSRF → cloud metadata → RCE/cloud takeover — Critical** → ④ **A08 Integrity → insecure deserialization → RCE — Critical** → ⑤ **A07 Auth failures → ATO** → ⑥ **A02 Crypto / A05 Misconfig / A06 Components → High** → ⑦ **A04 Insecure Design / A09 Logging → context-dependent.**

> 🔰 **In plain words — what the "OWASP Top 10" actually is:** it's the security world's list of the *ten most common ways web apps get broken into*, published by a respected non-profit (OWASP). It is **not** ten specific bugs — it's ten **categories**, like a doctor's "top-10 causes of illness" where "infection" is one bucket holding flu, COVID and strep. "A03 Injection" is one bucket that holds SQLi, command injection, XSS and more. This page explains each bucket in plain terms, then hands you the exact **kit** that attacks each specific bug inside it. The one rule to remember: the Top 10 tells you *what to worry about*; the kits tell you *what to type*.

---

## Table of Contents
- [How to use this list — category → kit routing](#how-to-use-this-list--category--kit-routing)
- [A01:2021 — Broken Access Control](#a012021--broken-access-control)
- [A02:2021 — Cryptographic Failures](#a022021--cryptographic-failures)
- [A03:2021 — Injection](#a032021--injection)
- [A04:2021 — Insecure Design](#a042021--insecure-design)
- [A05:2021 — Security Misconfiguration](#a052021--security-misconfiguration)
- [A06:2021 — Vulnerable and Outdated Components](#a062021--vulnerable-and-outdated-components)
- [A07:2021 — Identification and Authentication Failures](#a072021--identification-and-authentication-failures)
- [A08:2021 — Software and Data Integrity Failures](#a082021--software-and-data-integrity-failures)
- [A09:2021 — Security Logging and Monitoring Failures](#a092021--security-logging-and-monitoring-failures)
- [A10:2021 — Server-Side Request Forgery (SSRF)](#a102021--server-side-request-forgery-ssrf)
- [Category → Kit quick map](#category--kit-quick-map)
- [Severity calibration & reporting](#severity-calibration--reporting)
- [References](#references)

---

# How to use this list — category → kit routing

```
For each Top-10 category:  WHAT it is → HOW to test (+ which concrete classes) → the KIT(s) that own the technique →
IMPACT ceiling → prevention.
Run an engagement by IMPACT, not by category order:
  1. A01 access control (IDOR/BOLA/privesc)  — most common, high impact, start here.
  2. A03 injection (SQLi/cmdi/SSTI/...)       — RCE/dump ceiling.
  3. A10 SSRF                                 — cloud/RCE ceiling.
  4. A07 auth + A08 integrity                 — ATO + RCE.
  5. A02/A05/A06 crypto/misconfig/components  — High, often quick wins.
  6. A04/A09 design/logging                   — methodology + defense-in-depth.
This repo's 32 Web kits are the hands-on layer under these categories — the map at the end lists them all.
```

**Golden rule:** the Top 10 tells you *what to think about*; the kits tell you *what to type*. A category is done when you've tested every concrete class under it (with its kit) and either found impact or cleared it.

---

# A01:2021 — Broken Access Control

**What it is.** Users can act outside their intended permissions — accessing other users' data (horizontal), gaining higher privileges (vertical), or reaching functions/objects they shouldn't. #1 on the 2021 list (moved up from #5). Includes **IDOR/BOLA** (object-level), **missing function-level authorization** (BFLA), **privilege escalation**, **forced browsing**, metadata/JWT manipulation for authz, CORS-enabled cross-origin access, and path-based access bypass.

> *In plain words:* the app checks that you're **logged in**, but forgets to check that the thing you're asking for is actually **yours**. Like a hotel where your key-card works, but the front desk hands you whatever room number you name. #1 on the list because it's everywhere and it leaks *everyone's* data.

**Why it pays / impact.** The most common source of **mass data breaches** and **account takeover**: change an ID → read/modify another user's data (mass PII); reach an admin function → privilege escalation → full compromise; cross-tenant access → multi-customer breach. Consistently a Critical/High bucket.

**How to test (+ concrete classes → kits).**
```
□ IDOR / BOLA (object-level): change identifiers (user_id, account_id, order_id, uuid, filename) → other users' objects.
   Two-account diff. → ../Web/IDOR/  (the core kit for this)
□ Missing function-level authz (BFLA): access admin/privileged endpoints/methods as a low-priv user; verb tampering. 
   → ../API/REST/ (API5) + ../Web/IDOR/
□ Privilege escalation: mass-assignment of role/isAdmin; JWT claim tampering (role/sub) → ../Web/JWT/ ; parameter/
   cookie role flags.
□ Forced browsing: reach unlinked/privileged paths directly; path-normalization bypass of access checks.
□ Path traversal (access to files outside intended scope): → ../Web/PathTraversal/ (read/write) + ../Web/LFI/ (include).
□ CORS misconfig (cross-origin read of authenticated data): → ../Web/CORS/
□ Cross-tenant: tenant-scoped objects/RAG/storage reachable across tenants.
```

**Real-world / examples.** BOLA in APIs (the #1 API risk too); Facebook/Instagram-style IDOR mass account access; mass-assignment privilege escalation; JWT `role` tampering; admin panels reachable by forced browsing.

**Prevention.** Deny-by-default; enforce access control **server-side** on every request, per-object and per-function (never trust client-supplied identity/role); use unguessable references or ownership checks (not just obscurity); centralize authz; log access-control failures (A09); test authz systematically (two-account diffs).

**Kits.** `IDOR/` (primary — BOLA/IDOR/authz), `JWT/` (claim-tamper authz), `CORS/` (cross-origin read), `PathTraversal/` + `LFI/` (file access), `AccountTakeover/` (as an outcome), `../API/REST/` (BOLA/BFLA/BOPLA).

---

# A02:2021 — Cryptographic Failures

**What it is.** Failures related to cryptography (or its absence) that expose sensitive data — formerly "Sensitive Data Exposure," renamed to point at the root cause. Includes cleartext transmission/storage of sensitive data, weak/deprecated algorithms, poor key management, weak hashing of passwords, missing encryption, predictable tokens, and improper certificate validation.

> *In plain words:* sensitive data (passwords, card numbers, session tokens) is left readable — sent in the clear, stored behind a weak or ancient lock, or "protected" by a key anyone can dig up. Like mailing a postcard instead of sealing it in an armored envelope.

**Why it pays / impact.** **Exposure of sensitive data** — credentials, session tokens, PII, financial/health data, PANs — via sniffed traffic, weak encryption, or cracked hashes → account takeover, breach, regulatory exposure. Weak token/session crypto → forgery/hijack. Improper TLS → MITM.

**How to test (+ concrete classes → kits).**
```
□ Transport: cleartext HTTP for sensitive data; TLS misconfig; missing HSTS; mixed content; cert validation gaps.
□ Weak hashing / password storage: MD5/SHA1/unsalted; crackable dumps (when disclosed via another bug).
□ Token/JWT crypto: alg:none, weak HS256 secret (crackable), RS256→HS256 confusion, kid/jku injection, no expiry.
   → ../Web/JWT/  (the token-crypto kit)
□ Predictable tokens: reset/session/CSRF tokens with low entropy or timestamp/sequential structure.
   → ../Web/AccountTakeover/ (reset-token analysis)
□ Sensitive data at rest/in responses: PII/secrets returned unnecessarily; keys in JS/config → ../Web/JSFiles/ , Recon/.
□ Improper crypto in the app: ECB, static IVs, hardcoded keys, custom crypto (usually found via source/JS/mobile).
```

**Real-world / examples.** Session tokens over HTTP; JWT with a weak/guessable secret; unsalted MD5 password dumps cracked instantly; predictable password-reset tokens → ATO; API keys in JS bundles.

**Prevention.** TLS everywhere + HSTS; strong algorithms (AES-GCM, SHA-256+), proper KDFs (Argon2/bcrypt/scrypt/PBKDF2) for passwords; strong random for all security tokens; proper key management (rotation, hardware-backed, no hardcoding); classify + minimize sensitive data; don't return secrets in responses; validate certs.

**Kits.** `JWT/` (token crypto), `AccountTakeover/` (reset/session token predictability), `JSFiles/` + `Recon/` (exposed secrets/keys), `HostHeader/` (scheme/TLS handling).

---

# A03:2021 — Injection

**What it is.** Untrusted input is interpreted as **code/commands/queries** by a downstream interpreter. The classic mega-category: **SQL injection**, **NoSQL injection**, **OS command injection**, **server-side template injection (SSTI)**, **XPath/XQuery injection**, **LDAP injection**, **expression-language injection**, **CRLF/header injection**, and (2021 folded it in) **Cross-Site Scripting (XSS)** — client-side injection.

> *In plain words:* you type a **command** into a box the app expected to hold plain data, and some engine downstream (a database, a shell, a template, the victim's browser) actually **runs** it. Like writing "…and also hand over the keys" onto a form that a clerk reads out loud to a robot that obeys every word. This is the bucket where most *total-takeover* (RCE) bugs live.

**Why it pays / impact.** The **RCE / mass-data ceiling** of web apps: SQLi → dump the DB / auth bypass / file-write → webshell → RCE; command injection / SSTI → direct **RCE**; NoSQLi → auth bypass + blind exfil; XSS → session theft / ATO; LDAP/XPath → auth bypass + directory/XML dump. Consistently the top source of Critical findings.

**How to test (+ concrete classes → kits).**
```
□ SQL injection: error/UNION/boolean/time/OOB; per-DBMS; auth bypass, dump, file R/W → RCE. → ../Web/SQLi/
□ NoSQL injection: operator ($ne/$gt/$regex) auth bypass + $where JS blind exfil → RCE. → ../Web/NoSQLi/
□ OS command injection: shell metacharacters → RCE; blind/OOB. → ../Web/CommandInjection/
□ SSTI: template expression → RCE (Jinja2/Twig/Freemarker/Velocity/etc.). → ../Web/SSTI/
□ XPath / XQuery injection: auth bypass + full-XML dump + XQuery RCE. → ../Web/XPath/
□ LDAP injection: filter injection → auth bypass + directory disclosure. → ../Web/LDAP/
□ XSS (client-side injection): reflected/stored/DOM → session theft/ATO. → ../Web/XSS/
□ CRLF / header injection / response splitting: → ../Web/OpenRedirect/ (§CRLF) + HostHeader/.
□ Server-side JS / prototype pollution as an injection primitive: → ../Web/PrototypePollution/
□ XXE (XML injection): → ../Web/XXE/ (also A05 — see below).
```

**Real-world / examples.** SQLi mass breaches (endless); Log4Shell-adjacent injection; SSTI-to-RCE in template engines; command injection in image/PDF processors; stored XSS session theft; NoSQLi auth bypass (`{"$ne":null}`).

**Prevention.** Parameterized queries / prepared statements (SQL); safe APIs / avoid interpreters; input validation (allow-list) + context-aware output encoding (XSS); sandbox/disable dangerous template features (SSTI); avoid shell (use exec-array APIs); ORM/ODM safely; escape for the exact interpreter; least-privilege DB/service accounts.

**Kits.** `SQLi/`, `NoSQLi/`, `CommandInjection/`, `SSTI/`, `XPath/`, `LDAP/`, `XSS/`, `PrototypePollution/`, `OpenRedirect/` (CRLF), `XXE/` — the largest kit cluster in the repo.

---

# A04:2021 — Insecure Design

**What it is.** Flaws in the **design and architecture** — missing or ineffective security controls by design, as opposed to implementation bugs. Introduced in 2021 to distinguish "we built the wrong thing" from "we built it wrong." Includes missing business-logic controls, lack of threat modeling, insecure workflows, missing rate limiting by design, and trust-boundary failures.

> *In plain words:* nothing is "broken" in the code — the **plan itself** is unsafe. The app faithfully does something it should never have allowed (skip the payment step, redeem one coupon a thousand times). You can't patch a bad blueprint with input filtering; it needs a redesign. Scanners miss these because every request looks *valid*.

**Why it pays / impact.** **Business-logic abuse** — bypass a purchase/refund/workflow, exploit a race condition, abuse a coupon/quota, skip a payment step, manipulate price — often high-impact and *not* caught by scanners because the requests are "valid." A design flaw can't be patched with input validation; it's a rethink.

**How to test (+ concrete classes → kits).**
```
□ Business-logic flaws: negative/overflow quantities, price/parameter manipulation, workflow-step skipping, coupon/
   discount stacking, replay of one-time actions, state-machine bypass. (methodology — test the intended flow's assumptions)
□ Race conditions: limit-overrun via parallel requests (redeem-once, balance, quota, OTP). → ../Web/RaceCondition/
□ Missing rate limiting (by design): OTP/2FA brute, reset brute, enumeration → ATO. → ../Web/AccountTakeover/
□ Trust-boundary / workflow: does the design trust the client for security decisions? multi-step flows re-validated?
□ Insufficient anti-automation: bulk abuse, scraping, credential stuffing surfaces.
```

**Real-world / examples.** Race-condition limit overruns (gift-card/balance/redeem-once); price manipulation in carts; workflow bypass skipping payment; unlimited OTP attempts → 2FA bypass; coupon stacking.

**Prevention.** Threat-model early; establish secure design patterns + a control library; enforce business rules server-side and re-validate at each step; design in rate limiting / anti-automation / atomicity (defeat races); write abuse cases + test them; segment trust boundaries.

**Kits.** `RaceCondition/` (the concrete race/limit-overrun class), `AccountTakeover/` (rate-limit/flow abuse), and the business-logic methodology across kits. (A dedicated Business-Logic kit is a planned addition.)

---

# A05:2021 — Security Misconfiguration

**What it is.** Insecure or default configuration anywhere in the stack — app, server, framework, cloud, container — plus **XXE** (folded into this category in 2021). Includes default creds, verbose errors/debug enabled, unnecessary features/ports, missing security headers, permissive CORS, directory listing, exposed admin/management interfaces, and misconfigured cloud storage.

> *In plain words:* the software is fine, but it was **set up** carelessly — default password left on, debug mode on in production, error pages spilling secrets, cloud storage left open, an XML parser that reads any file it's told to. The lock is good; someone just left it unlocked.

**Why it pays / impact.** Ranges from info leak to full compromise: **XXE** → file read / SSRF / RCE; **default creds** → admin access; **debug/verbose errors** → source/secret leak; **open cloud storage / exposed admin panels** → data breach / takeover; **missing headers / permissive CORS** → XSS/data-theft enablers; **Host-header handling** → cache poisoning / routing SSRF.

**How to test (+ concrete classes → kits).**
```
□ XXE: XML parsers → file read / SSRF / blind OOB / RCE. → ../Web/XXE/
□ Host-header misconfig: reset-poisoning, cache poisoning, routing SSRF. → ../Web/HostHeader/
□ CORS misconfig: reflected/null origin + credentials → cross-origin data theft. → ../Web/CORS/
□ Web cache poisoning/deception (cache misconfig): → ../Web/WebCache/
□ Request smuggling (front-end/back-end desync misconfig): → ../Web/RequestSmuggling/
□ Subdomain takeover (dangling DNS misconfig): → ../Web/SubdomainTakeover/
□ Recon for misconfig: default creds, exposed .git/.env/backups, directory listing, admin panels, debug endpoints,
   verbose errors, missing headers, open cloud buckets. → ../Web/Recon/ + ../Web/JSFiles/
□ File-upload misconfig: unrestricted upload → webshell. → ../Web/FileUpload/
```

**Real-world / examples.** XXE file-read/SSRF in XML APIs; open S3 buckets; exposed `.git`/`.env` → source+secrets; default admin creds; debug mode leaking secrets; permissive CORS enabling account data theft; cache-poisoning mass-XSS.

**Prevention.** Harden by default (no defaults, no debug in prod, minimal features/ports); disable XXE (disallow DOCTYPE/external entities); security headers (CSP, HSTS, X-Content-Type-Options, etc.); strict CORS + Host allow-list; lock down cloud storage; remove exposed VCS/config/backups; automated config review + drift detection.

**Kits.** `XXE/`, `HostHeader/`, `CORS/`, `WebCache/`, `RequestSmuggling/`, `SubdomainTakeover/`, `FileUpload/`, `Recon/`, `JSFiles/` — a broad cluster.

---

# A06:2021 — Vulnerable and Outdated Components

**What it is.** Using components (libraries, frameworks, runtimes, OS packages, front-end deps) with **known vulnerabilities**, or that are unmaintained/outdated, or not inventoried. You inherit the component's CVEs. Includes both server-side and client-side dependencies, and the supply chain around them.

> *In plain words:* you built on top of someone else's library, and **that** library has a publicly-known hole — usually with a ready-made exploit posted online. You inherit its bugs for free. Like a solid house with one model of window that has a factory defect everybody already knows how to pop open (Log4Shell was exactly this).

**Why it pays / impact.** A known CVE in a shipped component = a ready-made exploit (often **RCE**): Log4Shell, Struts, Spring4Shell, deserialization gadgets, vulnerable jQuery/front-end libs (→ XSS/prototype pollution). "n-day" exploitation is cheap and reliable. Also the entry point for supply-chain attacks (A08 overlaps).

**How to test (+ concrete classes → kits).**
```
□ Fingerprint components + versions: server headers, framework tells, JS library versions (retire.js), package manifests.
   → ../Web/Recon/ + ../Web/JSFiles/ (client-side libs)
□ Map to known CVEs: outdated framework/library → public exploit. Notable classes:
   - JNDI / Log4Shell (Log4j) → ../Web/JNDI/
   - Insecure deserialization gadgets (ysoserial/PHPGGC) → ../Web/Deserialization/
   - Vulnerable front-end libs → XSS / prototype pollution → ../Web/XSS/ , ../Web/PrototypePollution/
□ Dependency confusion / typosquatting (supply-chain acquisition of internal deps): → ../Web/DependencyConfusion/
□ Outdated components with CVEs: verify exploitability in-context (not just version-in-a-list).
```

**Real-world / examples.** Log4Shell (Log4j RCE, mass-exploited); Struts/Spring4Shell RCE; deserialization RCE via known gadgets; vulnerable jQuery/AngularJS → XSS; typosquatted npm/PyPI packages.

**Prevention.** Inventory components (SBOM); patch/update continuously; monitor vulnerability feeds; remove unused dependencies; pin + verify (integrity); use SCA tooling in CI; subscribe to advisories for your stack.

**Kits.** `JNDI/` (Log4Shell), `Deserialization/` (gadget CVEs), `DependencyConfusion/` (supply chain), `JSFiles/` + `Recon/` (component fingerprinting), `PrototypePollution/` + `XSS/` (front-end lib CVEs).

---

# A07:2021 — Identification and Authentication Failures

**What it is.** Weaknesses in confirming identity, authenticating, and managing sessions — formerly "Broken Authentication." Includes credential stuffing/brute-force exposure, weak/default passwords, weak MFA, session-management flaws (fixation, no invalidation, exposure), weak password-reset flows, and identity-federation (OAuth/SSO/SAML) flaws.

> *In plain words:* the "prove you are who you say you are" machinery is weak — guessable passwords, unlimited login/OTP tries, password-reset links you can hijack, sessions that never expire. The entire category is about one thing: **becoming someone else** (account takeover).

**Why it pays / impact.** **Account takeover** — the whole category is about impersonating a user. Weak reset flows → ATO; no rate limit → brute/OTP bypass; session fixation/no-invalidation → hijack; OAuth/SSO misconfig → token theft → ATO; credential stuffing → mass ATO.

**How to test (+ concrete classes → kits).**
```
□ Password-reset / recovery: host/link poisoning, token predictability/leak, email HPP → ATO. → ../Web/AccountTakeover/
□ 2FA / OTP: no rate limit (brute), response-flip, force-browse past, delivery hijack, backup-code abuse. → AccountTakeover/
□ Session management: fixation, no server-side invalidation on logout, long-lived/exposed tokens, session-in-URL. → AccountTakeover/
□ JWT auth flaws: alg:none, weak secret, kid/jku, no expiry → forge/impersonate. → ../Web/JWT/
□ OAuth / OIDC / SAML (federated auth): redirect_uri bypass, state/CSRF, code/token theft, pre-account-takeover,
   id_token forgery, SAML XSW/sig-strip. → ../Web/OAuth/
□ Registration / pre-ATO: unverified-email SSO merge, username collision. → ../Web/AccountTakeover/ + OAuth/
□ Credential stuffing / brute exposure: rate limiting, lockout, MFA presence.
```

**Real-world / examples.** Password-reset poisoning → ATO; unlimited-OTP 2FA bypass; OAuth `redirect_uri` token theft; JWT `alg:none` impersonation; pre-account-takeover via unverified-email SSO linking; session fixation.

**Prevention.** Strong auth (MFA, no default/weak passwords, breached-password checks); rate limiting + lockout on all auth/OTP/reset endpoints; secure session management (rotate on login, invalidate on logout, short-lived, HttpOnly/Secure/SameSite); host-independent reset links + strong reset tokens; exact-match OAuth `redirect_uri` + `state` + PKCE; verify email before SSO linking.

**Kits.** `AccountTakeover/` (the ATO impact-hub — reset/2FA/session/registration), `JWT/` (token auth), `OAuth/` (federated auth), `CSRF/` (login-CSRF).

---

# A08:2021 — Software and Data Integrity Failures

**What it is.** Code and infrastructure that don't protect against **integrity violations** — relying on unverified sources, plugins, or data; auto-updates without integrity checks; **insecure deserialization** (folded in here in 2021); and **CI/CD pipeline** compromise. New category in 2021, capturing supply-chain + deserialization integrity.

> *In plain words:* the app trusts data or code without checking nobody tampered with it — most famously, rebuilding a saved object out of bytes an attacker controls (**deserialization**), which can end up running the attacker's code. Like a flat-pack furniture kit that will build *and run* whatever the instruction card says — even a card that says "now start a fire."

**Why it pays / impact.** **Insecure deserialization → RCE** (the headline — Java/PHP/.NET/Python/Ruby/Node gadget chains); unverified auto-update / plugin → malicious code execution; **CI/CD compromise** → supply-chain RCE across everyone; unsigned data trusted → tampering. Predominantly a **Critical/RCE** bucket.

**How to test (+ concrete classes → kits).**
```
□ Insecure deserialization: serialized blobs (Java ObjectInputStream, PHP unserialize, .NET BinaryFormatter/ViewState,
   Python pickle, Ruby Marshal, Node node-serialize) → gadget chains → RCE. → ../Web/Deserialization/
□ ViewState / signed-blob tampering (.NET, no-MAC/leaked machineKey): → ../Web/Deserialization/ (+ JWT for signed tokens).
□ Supply-chain integrity: dependency confusion, typosquatting, unverified packages/models. → ../Web/DependencyConfusion/
□ Auto-update / plugin integrity: does the app fetch + run code without signature verification?
□ CI/CD: exposed pipeline config, unsigned artifacts, injectable build steps (also A05 misconfig).
□ Unsigned/unverified data trusted for security decisions.
```

**Real-world / examples.** ysoserial Java deserialization RCE; .NET ViewState RCE via leaked machineKey; PHP phar/POP-chain RCE; SolarWinds-style CI/CD supply-chain compromise; dependency-confusion RCE in CI.

**Prevention.** Avoid deserializing untrusted data (or use safe formats + type allow-lists + integrity checks); sign + verify updates/plugins/artifacts (digital signatures); verify dependencies (integrity/provenance, pinning); secure the CI/CD pipeline (least privilege, signed builds, no injectable steps); don't trust unsigned data for security decisions.

**Kits.** `Deserialization/` (the RCE-ceiling kit — per-language), `DependencyConfusion/` (supply-chain integrity), `JWT/` (signed-token integrity), `JNDI/` (adjacent, via deserialization gadgets).

---

# A09:2021 — Security Logging and Monitoring Failures

**What it is.** Insufficient logging, monitoring, alerting, and incident response — so attacks aren't detected, escalated, or investigated. Includes unlogged auth/access-control/high-value events, logs without enough detail, no alerting, logs not monitored, and — the offensive flip side — **log injection** and logs that leak sensitive data.

> *In plain words:* even when something bad happens, **nobody sees it** — no alarms, no camera footage, no one reading the tapes. It rarely pays as a standalone bounty, but it lets every *other* attack run unnoticed — and the logs themselves can sometimes be poisoned (log injection) or made to leak secrets.

**Why it pays / impact.** Mostly a **defensive/detection** gap (hard to demo as a standalone bounty), but real impact: undetected breaches persist; no forensics; and it *amplifies* every other bug (an attacker operates unnoticed). Offensively, **log injection** (CRLF into logs, or Log4Shell-style log-triggered execution) and **sensitive data in logs** (PII/tokens) are concrete findings.

**How to test (+ concrete classes → kits).**
```
□ Detection gap (usually assessed, not "exploited"): are auth failures, access-control denials, high-value actions,
   input-validation failures logged + alerted? test by doing noisy things and asking "was it detected?".
□ Log injection: CRLF/newline into a logged field → forge/split log entries; or a value that triggers execution when
   logged → JNDI/Log4Shell. → ../Web/JNDI/ (log-triggered RCE) + CRLF (../Web/OpenRedirect/ §CRLF)
□ Sensitive data in logs: PII/tokens/passwords written to logs (then exposed via another bug / access).
□ Monitoring bypass / anti-forensics (red-team): operate below alerting thresholds.
```

**Real-world / examples.** Breaches undetected for months (the common post-mortem); Log4Shell = a *logging* path to RCE; log-forging via CRLF; credentials/PII in application logs later exposed.

**Prevention.** Log security-relevant events (auth, authz, input failures, high-value actions) with enough context + integrity; centralize + monitor + alert; protect logs (no injection — encode logged input; no sensitive data in logs); define + test incident response; retain logs appropriately.

**Kits.** `JNDI/` (logging-path RCE — the offensive edge of this category), CRLF via `OpenRedirect/`; otherwise primarily a defensive/methodology category.

---

# A10:2021 — Server-Side Request Forgery (SSRF)

**What it is.** The server can be induced to make **requests to attacker-chosen destinations** — a URL/host/resource the app fetches on the server side (webhooks, URL previews, image/PDF fetchers, import-from-URL, PDF generators, SSO metadata, file fetchers). Added to the Top 10 in 2021 by community survey due to its rising impact. Includes classic SSRF, blind SSRF, and SSRF via redirect/parser tricks.

> *In plain words:* you trick the **server** into fetching a URL of your choosing — and because the server sits *inside* the trusted network, it can reach places you can't, like the cloud's internal "metadata" address that hands out master keys. Like ordering a building's mailroom to go fetch a document from a room only staff are allowed to enter. This is the signature *cloud-era* Critical.

**Why it pays / impact.** The **cloud-era Critical**: SSRF → **cloud metadata** (169.254.169.254) → IAM credentials → **cloud account takeover / RCE**; SSRF → internal services (admin panels, Redis, databases) → RCE/lateral; SSRF → internal port scan / info disclosure; blind SSRF → OOB confirmation → chain. One of the highest-value modern web bugs.

**How to test (+ concrete classes → kits).**
```
□ Find server-fetch sinks: URL params, webhooks, "import from URL", link previews, image/PDF fetchers, SSO/OIDC
   metadata/JWKS URLs, XML external entities (XXE→SSRF), PDF-from-HTML. → ../Web/SSRF/ (the core kit)
□ Reach internal / metadata: 169.254.169.254 (AWS/GCP/Azure metadata), localhost, internal IPs/hostnames, cloud
   provider endpoints → IAM creds → cloud takeover. → ../Web/SSRF/
□ Bypass allow-lists / filters: DNS rebinding, redirect-to-internal (open redirect on an allowed host), IP-encoding
   (decimal/hex/octal), IPv6, userinfo tricks. → ../Web/SSRF/ + ../Web/OpenRedirect/ (redirect-bypass)
□ Blind SSRF: OOB (interactsh) confirmation; gopher:// for internal protocol smuggling → Redis/DB RCE.
□ SSRF via other classes: XXE (../Web/XXE/), Host-header routing (../Web/HostHeader/), LLM agent fetch-tools
   (../AI/LLM/ LLM06), OAuth request_uri/JWKS (../Web/OAuth/).
```

**Real-world / examples.** Capital One breach (SSRF → metadata → S3 dump); SSRF-to-metadata IAM credential theft across cloud bug bounties; gopher-SSRF to Redis RCE; SSRF via image/PDF/URL-import features; redirect-based allow-list bypass.

**Prevention.** Don't fetch client-supplied URLs where avoidable; if you must, allow-list schemes/hosts/ports and **re-validate after redirects** (don't follow to non-allow-listed hosts); block internal ranges + metadata IPs at the network layer (egress filtering, IMDSv2); resolve+pin DNS to defeat rebinding; disable unused URL schemes (gopher/file/dict); isolate the fetcher.

**Kits.** `SSRF/` (the core kit), `OpenRedirect/` (redirect-based allow-list bypass), `XXE/` (XXE→SSRF), `HostHeader/` (routing SSRF), `../API/REST/` (API7 SSRF), `../AI/LLM/` (agent tool SSRF — LLM06).

---

# Category → Kit quick map

| OWASP 2021 category | This repo's kits (hands-on technique) |
|---|---|
| **A01 Broken Access Control** | `IDOR/` · `JWT/` (authz claims) · `CORS/` · `PathTraversal/` · `LFI/` · `AccountTakeover/` · `../API/REST/` |
| **A02 Cryptographic Failures** | `JWT/` · `AccountTakeover/` (token entropy) · `JSFiles/` · `Recon/` |
| **A03 Injection** | `SQLi/` · `NoSQLi/` · `CommandInjection/` · `SSTI/` · `XPath/` · `LDAP/` · `XSS/` · `PrototypePollution/` · `OpenRedirect/` (CRLF) · `XXE/` |
| **A04 Insecure Design** | `RaceCondition/` · `AccountTakeover/` · (business-logic methodology) |
| **A05 Security Misconfiguration** | `XXE/` · `HostHeader/` · `CORS/` · `WebCache/` · `RequestSmuggling/` · `SubdomainTakeover/` · `FileUpload/` · `Recon/` · `JSFiles/` |
| **A06 Vulnerable/Outdated Components** | `JNDI/` · `Deserialization/` · `DependencyConfusion/` · `JSFiles/` · `Recon/` · `PrototypePollution/` |
| **A07 Auth Failures** | `AccountTakeover/` · `JWT/` · `OAuth/` · `CSRF/` |
| **A08 Integrity Failures** | `Deserialization/` · `DependencyConfusion/` · `JWT/` · `JNDI/` |
| **A09 Logging/Monitoring** | `JNDI/` (log→RCE) · `OpenRedirect/` (CRLF) · (defensive/methodology) |
| **A10 SSRF** | `SSRF/` · `OpenRedirect/` · `XXE/` · `HostHeader/` · `../API/REST/` · `../AI/LLM/` |

> Also in the repo: `WebSocket/`, `RFI/`, `Recon/`, `JSFiles/` (span multiple categories). The **API Security Top 10 (2023)** is covered by `../API/REST/` (BOLA/BFLA/BOPLA/resource-consumption/SSRF/misconfig/inventory/unsafe-consumption) + `../API/GraphQL/`.

---

# Severity calibration & reporting

| Category / cash-out | Typical ceiling | Via kit |
|---|---|---|
| **A03 Injection → RCE** (cmdi/SSTI/SQLi-file-write) | **Critical** | `CommandInjection/` `SSTI/` `SQLi/` |
| **A10 SSRF → cloud metadata → cloud takeover/RCE** | **Critical** | `SSRF/` |
| **A08 Deserialization → RCE** | **Critical** | `Deserialization/` |
| **A06 Known-CVE component → RCE** (Log4Shell) | **Critical** | `JNDI/` `Deserialization/` |
| **A01 Broken access control → mass data / privesc** | **Critical–High** | `IDOR/` |
| **A07 Auth failure → account takeover** | **High** | `AccountTakeover/` `JWT/` `OAuth/` |
| **A02 Crypto failure → data/token exposure** | **High** | `JWT/` `AccountTakeover/` |
| **A05 Misconfig → XXE/cache-poison/takeover** | **High** | `XXE/` `WebCache/` `SubdomainTakeover/` |
| **A04 Insecure design → logic/race abuse** | **High–Medium** | `RaceCondition/` |
| **A09 Logging/monitoring gap** | **Low–Medium** (defensive) | (methodology; `JNDI/` for log→RCE) |

**Reporting rules:** report the **concrete vuln + impact**, then map it to the OWASP category (triagers/scopes speak both — "IDOR on `/api/orders/{id}` → read any user's orders (A01 Broken Access Control, CWE-639)"). Use each kit's report template for the hands-on finding; use this doc to place it in the framework. Impact-first, own accounts, benign markers, safe PoC — per every kit's discipline.

---

# References

**Primary**
- **OWASP Top 10:2021**: https://owasp.org/Top10/ (per-category pages A01–A10 with CWEs + prevention).
- OWASP Top 10 project (methodology, data): https://owasp.org/www-project-top-ten/
- **OWASP API Security Top 10 (2023)** (the API twin — see `../API/REST/`): https://owasp.org/API-Security/
- OWASP Web Security Testing Guide (WSTG) — the how-to per class: https://owasp.org/www-project-web-security-testing-guide/
- OWASP ASVS (verification requirements) + Cheat Sheet Series.

**Note on versions**
- Top 10:2021 is the current stable web list; a **2025** revision is in progress (categories may shift). This doc tracks 2021; per-kit content is version-independent (the concrete techniques don't change with the ranking).

**Companion kits in this repo**
- All 32 Web kits (see the Category → Kit map above) + `../API/REST/`, `../API/GraphQL/`, `../AI/LLM/` (LLM Top 10), `../Mobile/` (Mobile Top 10). This document is the OWASP-Web-Top-10 umbrella over the per-class kits — categories here, payloads there.

---

> **Final reminder — the one rule that pays:** the OWASP Top 10 is a *map of risk categories*, not a checklist of bugs. Each category is a family — A01 is every access-control class, A03 is every injection class, A05 is every misconfig class. Use this doc to route from the category to the **deep kit** that owns the technique, test every member of the family, and report the **concrete vuln + demonstrated impact** mapped back to the category. Categories to think, kits to type.
