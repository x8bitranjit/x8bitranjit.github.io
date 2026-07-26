# OWASP Top 10:2025 — In-Depth Testing Reference & Kit Map (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Web applications and their APIs — the **2025** OWASP Top 10 risk categories, mapped to how you *test* each one and to the **deep per-class kits in this repo** that own the hands-on technique. This is the index/map: each category points to the kit(s) that carry the payloads, arsenals, and PoC.
**Standard:** OWASP **Top 10:2025** — the 8th installment (released as RC1; the current standing edition, verified against owasp.org/Top10/2025). IDs are `A01:2025` … `A10:2025`. **The 2021 edition reference lives beside this file (`OWASP_WEB_TOP_10.md`) — both are kept on purpose.**
**Platforms:** any; tooling in Kali/WSL + Burp.

> **This is the 2025 umbrella map, sibling of the 2021 doc and of the API/Mobile/LLM Top 10 docs.** The 2025 list re-shuffles and re-buckets the same underlying vuln-classes — the concrete techniques (and this repo's 32 kits) don't change; only how OWASP groups and ranks them does. Use this to go from "the report scope says A03 Software Supply Chain" to "so I run the Dependency Confusion / JNDI / Deserialization kits." The mistake is treating a category as a single bug; it's a family — hit every member.

> ### ⚡ WHAT CHANGED 2021 → 2025 (read first — verified against owasp.org)
> - **SSRF is gone as a standalone.** 2021's A10 SSRF was **rolled into A01 Broken Access Control** (SSRF is an access-control violation — the server reaches resources it shouldn't). The **SSRF kit now lives under A01.**
> - **A03:2025 Software Supply Chain Failures is NEW** — it **expands** 2021's A06 "Vulnerable and Outdated Components" into the whole supply chain (third-party code, dependencies, CI/CD, build/distribution/update pipeline, vendor/malicious-package compromise). It topped the **community survey (#1, 50%)** and had the **highest incidence rate (5.72%)**.
> - **A10:2025 Mishandling of Exceptional Conditions is NEW** — error/exception handling, fail-open vs fail-closed, transaction rollback (24 CWEs).
> - **A02 Security Misconfiguration rose #5 → #2.** (XXE still lives here.)
> - **Two renames:** A07 "Identification and Authentication Failures" → **"Authentication Failures"**; A09 "Logging and **Monitoring**" → "Logging **& Alerting** Failures".
> - Repositioned: A04 Crypto (#2→#4), A05 Injection (#3→#5, still holds XSS), A06 Insecure Design (#4→#6).
> - **A01 Broken Access Control stays #1.**

---

> ### ⚡ READ THIS FIRST — the Top 10 is categories, the kits are the bugs
> 1. **Categories ≠ vulnerabilities.** "A05 Injection" is a bucket containing SQLi, NoSQLi, command injection, SSTI, XPath, LDAP, XSS, and more — each has its own deep kit here. Map the category → the concrete classes → the kits.
> 2. **A01 Broken Access Control is still #1** — and in 2025 it's *bigger* (it absorbed SSRF). IDOR/BOLA, privilege escalation, forced browsing, missing function-level authz, **and SSRF**. Start here on most engagements.
> 3. **Supply chain is now a headline (A03).** The cheapest reliable RCE is still an n-day in a component you didn't write — plus the new supply-chain surface (malicious packages, CI/CD, dependency confusion). This rose to #3 for a reason.
> 4. **Impact-first, always.** OWASP ranks by prevalence + impact, but *your report* is rated by demonstrated impact. Every category cashes out through a concrete kit's "impact ceiling" (RCE / ATO / mass data / SSRF-to-cloud).
> 5. **Several classes span multiple categories.** SSRF is now A01 *and* still an enabler across A05; XXE lives under A02 but reaches SSRF/RCE; deserialization is A08 but yields RCE (and overlaps A03). Follow the chain, not the label.
>
> **Where the money is (memorize):** ① **A05 Injection → RCE/ATO/mass-dump (SQLi/cmdi/SSTI kits) — Critical** → ② **A01 Broken Access Control → IDOR/BOLA/privesc + SSRF→cloud metadata → mass data/ATO/cloud takeover — Critical** → ③ **A03 Supply Chain → known-CVE / malicious-dep → RCE — Critical** → ④ **A08 Integrity → insecure deserialization → RCE — Critical** → ⑤ **A07 Auth failures → ATO** → ⑥ **A04 Crypto / A02 Misconfig → High** → ⑦ **A06 Design / A09 Logging / A10 Exceptional-conditions → context-dependent.**

> 🔰 **In plain words — what the "OWASP Top 10" is, and what "2025" changes:** the Top 10 is the security world's list of the *ten most common ways web apps get broken into*, grouped into ten **buckets** — not ten specific bugs. This is the **2025** edition; the buckets got re-shuffled from 2021 but the actual attacks (and this repo's kits) are identical. The three headline moves: **SSRF joined A01** (it's really an access-control failure), a **new A03 "Software Supply Chain"** bucket, and a **new A10 "Exceptional Conditions"** bucket. The one rule never changes: the Top 10 tells you *what to worry about*; the kits tell you *what to type*.

---

## Table of Contents
- [How to use this list — category → kit routing](#how-to-use-this-list--category--kit-routing)
- [A01:2025 — Broken Access Control (incl. SSRF)](#a012025--broken-access-control-incl-ssrf)
- [A02:2025 — Security Misconfiguration](#a022025--security-misconfiguration)
- [A03:2025 — Software Supply Chain Failures](#a032025--software-supply-chain-failures)
- [A04:2025 — Cryptographic Failures](#a042025--cryptographic-failures)
- [A05:2025 — Injection](#a052025--injection)
- [A06:2025 — Insecure Design](#a062025--insecure-design)
- [A07:2025 — Authentication Failures](#a072025--authentication-failures)
- [A08:2025 — Software or Data Integrity Failures](#a082025--software-or-data-integrity-failures)
- [A09:2025 — Security Logging & Alerting Failures](#a092025--security-logging--alerting-failures)
- [A10:2025 — Mishandling of Exceptional Conditions](#a102025--mishandling-of-exceptional-conditions)
- [Category → Kit quick map](#category--kit-quick-map)
- [Severity calibration & reporting](#severity-calibration--reporting)
- [Appendix — Verified Real-World Case Studies (deep dives)](#appendix--verified-real-world-case-studies-deep-dives)
- [References](#references)

---

# How to use this list — category → kit routing

```
For each Top-10 category:  WHAT it is → HOW to test (+ which concrete classes) → the KIT(s) that own the technique →
IMPACT ceiling → prevention.
Run an engagement by IMPACT, not by category order:
  1. A01 access control (IDOR/BOLA/privesc + SSRF)  — #1, most common + high impact, start here.
  2. A05 injection (SQLi/cmdi/SSTI/...)              — RCE/dump ceiling.
  3. A03 supply chain (known-CVE/dep-confusion)      — RCE ceiling, cheap n-days.
  4. A07 auth + A08 integrity                        — ATO + RCE.
  5. A04/A02 crypto/misconfig                        — High, often quick wins.
  6. A06/A09/A10 design/logging/exceptional          — methodology + defense-in-depth.
This repo's 32 Web kits are the hands-on layer under these categories — the map at the end lists them all.
```

**Golden rule:** the Top 10 tells you *what to think about*; the kits tell you *what to type*. A category is done when you've tested every concrete class under it (with its kit) and either found impact or cleared it.

---

# A01:2025 — Broken Access Control (incl. SSRF)

**What it is.** Users can act outside their intended permissions — accessing other users' data (horizontal), gaining higher privileges (vertical), or reaching functions/objects they shouldn't. **#1 again in 2025**, and now *broader*: **SSRF was merged in** (the server being coerced to reach resources it shouldn't is an access-control failure). Includes **IDOR/BOLA**, **missing function-level authorization (BFLA)**, **privilege escalation**, **forced browsing**, metadata/JWT manipulation, CORS-enabled cross-origin access, path-based bypass, **and SSRF**.

> *In plain words:* the app checks you're **logged in** but not that the thing you want is **yours** — so you reach other people's data or admin-only features. In 2025 this bucket got *bigger*: **SSRF moved in** (tricking the server into fetching internal URLs is just another way of reaching something you shouldn't). Still #1.

**Why it pays / impact.** The most common source of **mass data breaches**, **account takeover**, and now **cloud takeover** (via the SSRF sub-class): change an ID → read/modify another user's data; reach an admin function → privilege escalation; SSRF → **cloud metadata → IAM creds → cloud account takeover**. Consistently the top Critical/High bucket.

**How to test (+ concrete classes → kits).**
```
□ IDOR / BOLA (object-level): change identifiers (user_id, account_id, order_id, uuid) → other users' objects.
   Two-account diff. → ../Web/IDOR/  (the core kit)
□ Missing function-level authz (BFLA): access admin/privileged endpoints as low-priv; verb tampering. → ../API/REST/ (API5) + ../Web/IDOR/
□ Privilege escalation: mass-assignment of role/isAdmin; JWT claim tampering → ../Web/JWT/ ; parameter/cookie flags.
□ Forced browsing: reach unlinked/privileged paths directly; path-normalization bypass of access checks.
□ Path traversal (files outside intended scope): → ../Web/PathTraversal/ (read/write) + ../Web/LFI/ (include).
□ CORS misconfig (cross-origin read of authenticated data): → ../Web/CORS/
□ SSRF (NEW under A01): server-fetch sinks (webhooks, url params, importers, PDF/image fetchers, SSO metadata) →
   169.254.169.254 metadata / internal services → cloud/RCE. → ../Web/SSRF/ (+ ../Web/OpenRedirect/ for redirect-bypass).
```

**Real-world / examples.** **First American Financial (2019)** — sequential, **unauthenticated** document URLs → **~885 million** records (SSNs, bank statements, driver's-license images) walkable by incrementing an ID (pure IDOR at breach scale). **Capital One (2019)** — an **SSRF** on a misconfigured WAF reached the EC2 metadata service, stole an over-privileged IAM role, and dumped **~106 million** applicants from S3; **in 2025 SSRF lives here under A01**, and this breach is why AWS built IMDSv2. Others: BOLA in APIs (the #1 API risk too); mass-assignment privilege escalation; JWT `role` tampering; admin panels via forced browsing.

**Prevention.** Deny-by-default; enforce access control **server-side** on every request, per-object and per-function (never trust client identity/role); unguessable references *plus* ownership checks; centralize authz; **for the SSRF sub-class** — allow-list outbound schemes/hosts/ports, re-validate after redirects, block internal ranges + metadata IPs (egress filtering, IMDSv2); log access-control failures (A09).

**Kits.** `IDOR/` (primary), `JWT/` (claim-tamper authz), `CORS/` (cross-origin read), `PathTraversal/` + `LFI/` (file access), **`SSRF/` (now here)**, `OpenRedirect/` (SSRF allow-list bypass), `AccountTakeover/` (outcome), `../API/REST/` (BOLA/BFLA).

---

# A02:2025 — Security Misconfiguration

**What it is.** Insecure or default configuration anywhere in the stack — app, server, framework, cloud, container — plus **XXE** (still folded in here). **Rose from #5 (2021) to #2 (2025)** as stacks grew more complex. Includes default creds, verbose errors/debug enabled, unnecessary features/ports, missing security headers, permissive CORS, directory listing, exposed admin/management interfaces, misconfigured cloud storage.

> *In plain words:* the software is fine, it was just **set up** carelessly — default password left on, debug mode on in production, a cloud bucket left open, an XML parser told to read any file. The lock is good; someone left it unlocked. It jumped to #2 because modern stacks have *so many* knobs to get wrong.

**Why it pays / impact.** Info leak → full compromise: **XXE** → file read / SSRF / RCE; **default creds** → admin access; **debug/verbose errors** → source/secret leak; **open cloud storage / exposed admin panels** → data breach / takeover; **missing headers / permissive CORS** → XSS/data-theft enablers; **Host-header handling** → cache poisoning / routing.

**How to test (+ concrete classes → kits).**
```
□ XXE: XML parsers → file read / SSRF / blind OOB / RCE. → ../Web/XXE/
□ Host-header misconfig: reset-poisoning, cache poisoning, routing. → ../Web/HostHeader/
□ CORS misconfig: reflected/null origin + credentials → cross-origin data theft. → ../Web/CORS/
□ Web cache poisoning/deception (cache misconfig): → ../Web/WebCache/
□ Request smuggling (front-end/back-end desync): → ../Web/RequestSmuggling/
□ Subdomain takeover (dangling DNS misconfig): → ../Web/SubdomainTakeover/
□ Recon for misconfig: default creds, exposed .git/.env/backups, directory listing, admin panels, debug endpoints,
   verbose errors, missing headers, open cloud buckets. → ../Web/Recon/ + ../Web/JSFiles/
□ File-upload misconfig: unrestricted upload → webshell. → ../Web/FileUpload/
```

**Real-world / examples.** **Microsoft Power Apps (2021)** — the OData list API was **public by default** whenever a portal was misconfigured, exposing **~38 million** records (SSNs, COVID-19 contact-tracing PII) across 47+ organisations anonymously; Microsoft first called it "by design," then shipped a secure default — the archetypal insecure-default misconfiguration, now #2 on the list. Others: XXE file-read/SSRF in XML APIs; open S3 buckets; exposed `.git`/`.env` → source+secrets; default admin creds; debug mode leaking secrets; permissive CORS; cache-poisoning mass-XSS.

**Prevention.** Harden by default (no defaults, no debug in prod, minimal features/ports); disable XXE (no DOCTYPE/external entities); security headers (CSP, HSTS, X-Content-Type-Options); strict CORS + Host allow-list; lock down cloud storage; remove exposed VCS/config/backups; automated config review + drift detection.

**Kits.** `XXE/`, `HostHeader/`, `CORS/`, `WebCache/`, `RequestSmuggling/`, `SubdomainTakeover/`, `FileUpload/`, `Recon/`, `JSFiles/`.

---

# A03:2025 — Software Supply Chain Failures

**What it is.** **NEW for 2025**, expanding 2021's A06 "Vulnerable and Outdated Components" into the **entire software supply chain**: vulnerabilities *or malicious changes* in third-party code, tools, or dependencies — across building, distributing, and updating software. Covers unpatched/outdated/unmaintained dependencies, **malicious packages** (typosquatting, **dependency confusion**), compromised vendors, weak **CI/CD** security, and inadequate change management. **#1 in the community survey (50%); highest incidence rate (5.72%).**

> *In plain words:* you didn't write most of your app — you glued together other people's libraries, build tools and update pipelines. This bucket is about that borrowed code betraying you: a library with a public hole (Log4Shell), or an outright **malicious** package you pulled in by mistake (typosquatting, dependency confusion, a poisoned update). New for 2025 and straight to #3 — it's the cheapest, most reliable way in.

**Why it pays / impact.** A known CVE in a component = a ready-made exploit (often **RCE**): Log4Shell, Struts, Spring4Shell, deserialization gadgets. Plus the *malicious* supply-chain surface: a claimed internal package name (**dependency confusion**) → install-hook RCE in CI/CD; a compromised dependency (SolarWinds, the 2025 **Shai-Hulud npm worm**) → mass compromise. n-day exploitation is cheap and reliable; supply-chain injection is high-blast-radius.

**How to test (+ concrete classes → kits).**
```
□ Fingerprint components + versions: server headers, framework tells, JS lib versions (retire.js), package manifests.
   → ../Web/Recon/ + ../Web/JSFiles/ (client-side libs)
□ Map to known CVEs (verify reachability in-context). Notable RCE classes:
   - JNDI / Log4Shell (Log4j) → ../Web/JNDI/
   - Insecure deserialization gadgets (ysoserial/PHPGGC) → ../Web/Deserialization/ (also A08)
   - Vulnerable front-end libs → XSS / prototype pollution → ../Web/XSS/ , ../Web/PrototypePollution/
□ Dependency confusion / typosquatting / repo-jacking (malicious acquisition of internal deps):
   leaked manifests, committed .npmrc/pip.conf, public 404 = claimable → benign callback proof. → ../Web/DependencyConfusion/
□ CI/CD & pipeline: exposed pipeline config, unsigned artifacts, injectable build steps (overlaps A08).
```

**Real-world / examples.** **xz-utils / liblzma backdoor (CVE-2024-3094, 2024)** — a patient social-engineering campaign (the "Jia Tan" persona) earned *maintainer* trust over ~2 years, then planted an obfuscated backdoor in xz 5.6.0/5.6.1 that hooked `sshd` (via liblzma) for **unauthenticated RCE** — a CVSS **10.0** near-miss caught only because Andres Freund noticed sshd was ~500 ms slow. **Shai-Hulud npm worm (Sept 2025)** — the first **self-propagating** npm worm: a post-install script harvested tokens, exfiltrated them to attacker "Shai-Hulud" GitHub repos, and **auto-republished** malicious versions of every package the stolen tokens could reach, spreading to hundreds of packages (a second wave hit Nov 2025). Others: Log4Shell (mass-exploited); SolarWinds CI/CD compromise; typosquatted npm/PyPI; dependency-confusion RCE in CI (Birsan 2021). CWEs: CWE-1104 (unmaintained third-party), CWE-1395 (dependency on vulnerable component), CWE-1329, CWE-477.

**Prevention.** Inventory components (**SBOM**); patch/update continuously; monitor advisories; remove unused deps; **pin + verify integrity/provenance** (signatures); vet + reserve internal package names; secure CI/CD (least privilege, signed builds, no injectable steps); use SCA in CI.

**Kits.** `DependencyConfusion/` (malicious supply-chain), `JNDI/` (Log4Shell), `Deserialization/` (gadget CVEs — also A08), `JSFiles/` + `Recon/` (component fingerprinting), `PrototypePollution/` + `XSS/` (front-end lib CVEs).

---

# A04:2025 — Cryptographic Failures

**What it is.** Failures in (or absence of) cryptography that expose sensitive data (was A02 in 2021; **dropped to #4**). Cleartext transmission/storage, weak/deprecated algorithms, poor key management, weak password hashing, missing encryption, predictable tokens, improper certificate validation.

> *In plain words:* sensitive data (passwords, tokens, card numbers) is left readable — sent in the clear, stored with a weak or ancient lock, or "protected" by a key anyone can dig up. Like mailing a postcard instead of sealing it in an armored envelope. (This was #2 in 2021; it slipped to #4.)

**Why it pays / impact.** **Exposure of sensitive data** — credentials, session tokens, PII, financial/health data — via sniffed traffic, weak encryption, or cracked hashes → ATO, breach, regulatory exposure. Weak token/session crypto → forgery/hijack. Improper TLS → MITM.

**How to test (+ concrete classes → kits).**
```
□ Transport: cleartext HTTP for sensitive data; TLS misconfig; missing HSTS; mixed content; cert validation gaps.
□ Weak hashing / password storage: MD5/SHA1/unsalted; crackable dumps (when disclosed via another bug).
□ Token/JWT crypto: alg:none, weak HS256 secret, RS256→HS256 confusion, kid/jku injection, no expiry. → ../Web/JWT/
□ Predictable tokens: reset/session/CSRF tokens with low entropy or timestamp/sequential structure. → ../Web/AccountTakeover/
□ Secrets at rest/in responses: PII/secrets returned unnecessarily; keys in JS/config → ../Web/JSFiles/ , Recon/.
□ Improper crypto: ECB, static IVs, hardcoded keys, custom crypto (found via source/JS).
```

**Real-world / examples.** **Adobe (2013)** — **153 million** account passwords were **encrypted (3DES-ECB) instead of hashed**, with the same key for everyone and users' plaintext password *hints* stored alongside; ECB's identical-input→identical-output plus the hints made bulk recovery trivial (~1.9M used "123456"). The canonical "encrypted ≠ safely stored" failure — password storage needs a slow one-way KDF, not reversible encryption. Others: session tokens over HTTP; JWT with a weak/guessable secret; unsalted MD5 dumps cracked instantly; predictable reset tokens → ATO; API keys in JS bundles.

**Prevention.** TLS + HSTS; strong algorithms (AES-GCM, SHA-256+), adaptive KDFs (Argon2/bcrypt/scrypt/PBKDF2) for passwords; cryptographic RNG for tokens; proper key management (rotation, hardware-backed, no hardcoding); classify + minimize sensitive data; validate certs.

**Kits.** `JWT/` (token crypto), `AccountTakeover/` (reset/session token entropy), `JSFiles/` + `Recon/` (exposed secrets), `HostHeader/` (scheme/TLS handling).

---

# A05:2025 — Injection

**What it is.** Untrusted input interpreted as **code/commands/queries** by a downstream interpreter (was A03 in 2021; **dropped to #5**, still **holds XSS**). SQLi, NoSQLi, OS command injection, SSTI, XPath/XQuery, LDAP, expression-language, CRLF/header injection, and **XSS** (client-side injection).

> *In plain words:* you type a **command** into a box meant for plain data, and something downstream (database, shell, template, the victim's browser) runs it. Like writing "…and hand over the keys" on a form a clerk reads aloud to an obedient robot. Still the bucket where most *total-takeover* (RCE) bugs live — it just slid from #3 to #5.

**Why it pays / impact.** The **RCE / mass-data ceiling**: SQLi → dump / auth bypass / file-write → webshell → RCE; command injection / SSTI → direct **RCE**; NoSQLi → auth bypass + blind exfil; XSS → session theft / ATO; LDAP/XPath → auth bypass + directory/XML dump. Consistently the top source of Critical findings.

**How to test (+ concrete classes → kits).**
```
□ SQL injection: error/UNION/boolean/time/OOB; per-DBMS; auth bypass, dump, file R/W → RCE. → ../Web/SQLi/
□ NoSQL injection: operator ($ne/$gt/$regex) auth bypass + $where JS blind exfil → RCE. → ../Web/NoSQLi/
□ OS command injection: shell metacharacters → RCE; blind/OOB. → ../Web/CommandInjection/
□ SSTI: template expression → RCE (Jinja2/Twig/Freemarker/Velocity). → ../Web/SSTI/
□ XPath / XQuery injection: auth bypass + full-XML dump + XQuery RCE. → ../Web/XPath/
□ LDAP injection: filter injection → auth bypass + directory disclosure. → ../Web/LDAP/
□ XSS (client-side injection): reflected/stored/DOM → session theft/ATO. → ../Web/XSS/
□ CRLF / header injection / response splitting: → ../Web/OpenRedirect/ (§CRLF) + HostHeader/.
□ Prototype pollution as an injection primitive: → ../Web/PrototypePollution/
□ XXE (XML injection): → ../Web/XXE/ (bucketed in A02, but injection-flavored).
```

**Real-world / examples.** **TalkTalk (2015)** — a plain **SQL injection** against unpatched legacy pages exposed **156,959 customers** (15,656 with bank details) and drew a then-record **£400,000** ICO fine because the same flaw had been exploited months earlier and left unfixed. Others: SSTI-to-RCE (Jinja2/Twig); command injection in image/PDF processors (ImageTragick, Ghostscript); stored XSS session theft; NoSQLi auth bypass (`{"$ne":null}`).

**Prevention.** Parameterized queries / prepared statements (SQL); safe APIs; input validation (allow-list) + context-aware output encoding (XSS); sandbox/disable dangerous template features (SSTI); avoid shell (exec-array APIs); escape for the exact interpreter; least-privilege DB/service accounts.

**Kits.** `SQLi/`, `NoSQLi/`, `CommandInjection/`, `SSTI/`, `XPath/`, `LDAP/`, `XSS/`, `PrototypePollution/`, `OpenRedirect/` (CRLF), `XXE/` — the largest kit cluster in the repo.

---

# A06:2025 — Insecure Design

**What it is.** Flaws in the **design and architecture** — missing or ineffective security controls by design (was A04 in 2021; **dropped to #6**). Missing business-logic controls, lack of threat modeling, insecure workflows, missing rate limiting by design, trust-boundary failures.

> *In plain words:* nothing is coded wrong — the **plan** is unsafe. The app faithfully allows something it never should (skip payment, redeem one coupon a thousand times). You can't filter your way out of a bad blueprint; it needs a redesign. Scanners miss it because every request looks perfectly valid.

**Why it pays / impact.** **Business-logic abuse** — bypass a purchase/refund/workflow, exploit a race condition, abuse a coupon/quota, skip a payment step, manipulate price — high-impact and *not* caught by scanners because the requests are "valid." A design flaw needs a re-think, not input validation.

**How to test (+ concrete classes → kits).**
```
□ Business-logic flaws: negative/overflow quantities, price/parameter manipulation, workflow-step skipping, coupon
   stacking, replay of one-time actions, state-machine bypass. (methodology — test the flow's assumptions)
□ Race conditions: limit-overrun via parallel requests (redeem-once, balance, quota, OTP). → ../Web/RaceCondition/
□ Missing rate limiting (by design): OTP/2FA brute, reset brute, enumeration → ATO. → ../Web/AccountTakeover/
□ Trust-boundary / workflow: does the design trust the client for security decisions? multi-step flows re-validated?
```

**Real-world / examples.** **Experian partner-API (2021, Bill Demirkapi)** — a lender's site queried an Experian API that returned anyone's **credit score** given just a name + address, and it *accepted all-zeros for date-of-birth*; the flow was **designed with no authentication, no rate limiting, and no abuse resistance** for a sensitive lookup — an insecure *design*, not a coding bug (input-validation can't fix "this endpoint shouldn't exist unauthenticated"). Others: race-condition limit overruns; price manipulation in carts; workflow bypass skipping payment; unlimited OTP → 2FA bypass; coupon stacking.

**Prevention.** Threat-model early; secure design patterns + a control library; enforce business rules server-side + re-validate each step; design in rate limiting / anti-automation / atomicity (defeat races); write + test abuse cases; segment trust boundaries.

**Kits.** `RaceCondition/`, `AccountTakeover/`, business-logic methodology across kits. (A dedicated Business-Logic kit is a planned addition.)

---

# A07:2025 — Authentication Failures

**What it is.** Weaknesses in confirming identity, authenticating, and managing sessions (**renamed** from 2021's "Identification and Authentication Failures" → **"Authentication Failures"**). Credential stuffing/brute exposure, weak/default passwords, weak MFA, session-management flaws (fixation, no invalidation, exposure), weak password-reset flows, identity-federation (OAuth/SSO/SAML) flaws.

> *In plain words:* the "prove you are who you say you are" machinery is weak — guessable passwords, unlimited login/OTP tries, hijackable reset links, sessions that never expire. The whole bucket is about one thing: **becoming someone else** (account takeover). (Just renamed from the longer 2021 title.)

**Why it pays / impact.** **Account takeover** — the whole category is impersonating a user. Weak reset → ATO; no rate limit → brute/OTP bypass; session fixation/no-invalidation → hijack; OAuth misconfig → token theft → ATO; credential stuffing → mass ATO.

**How to test (+ concrete classes → kits).**
```
□ Password-reset / recovery: host/link poisoning, token predictability/leak, email HPP → ATO. → ../Web/AccountTakeover/
□ 2FA / OTP: no rate limit (brute), response-flip, force-browse past, delivery hijack, backup-code abuse. → AccountTakeover/
□ Session management: fixation, no server-side invalidation on logout, long-lived/exposed tokens, session-in-URL. → AccountTakeover/
□ JWT auth flaws: alg:none, weak secret, kid/jku, no expiry → forge/impersonate. → ../Web/JWT/
□ OAuth / OIDC / SAML: redirect_uri bypass, state/CSRF, code/token theft, pre-account-takeover, id_token forgery,
   SAML XSW/sig-strip. → ../Web/OAuth/
□ Registration / pre-ATO: unverified-email SSO merge, username collision. → ../Web/AccountTakeover/ + OAuth/
```

**Real-world / examples.** **Colonial Pipeline (2021)** — the DarkSide group got in through a **single legacy VPN account with no MFA**, using a password reused and exposed in a prior-breach dump; that one authentication gap let ransomware shut down the largest U.S. fuel pipeline and trigger a state of emergency. MFA on that one account would likely have stopped it. Others: password-reset poisoning → ATO; unlimited-OTP 2FA bypass; OAuth `redirect_uri` token theft; JWT `alg:none` impersonation; pre-account-takeover via unverified-email SSO; session fixation.

**Prevention.** Strong auth (MFA, no default/weak passwords, breached-password checks); rate limiting + lockout on all auth/OTP/reset endpoints; secure sessions (rotate on login, invalidate on logout, short-lived, HttpOnly/Secure/SameSite); host-independent reset links + strong tokens; exact-match OAuth `redirect_uri` + `state` + PKCE; verify email before SSO linking.

**Kits.** `AccountTakeover/` (the ATO impact-hub), `JWT/` (token auth), `OAuth/` (federated auth), `CSRF/` (login-CSRF).

---

# A08:2025 — Software or Data Integrity Failures

**What it is.** Code/infrastructure that doesn't protect against **integrity violations** — unverified sources/plugins/data, auto-updates without integrity checks, **insecure deserialization**, and **CI/CD** compromise (unchanged from 2021 A08; now overlaps A03 Supply Chain on the CI/CD + dependency side).

> *In plain words:* the app trusts data or code without checking nobody swapped it — most famously rebuilding a saved object from attacker-controlled bytes (**deserialization**), which can run their code. Like a flat-pack kit that builds *and runs* whatever the instruction card says. Overlaps the new A03 on the pipeline/dependency side.

**Why it pays / impact.** **Insecure deserialization → RCE** (the headline — Java/PHP/.NET/Python/Ruby/Node gadget chains); unverified auto-update / plugin → malicious code execution; **CI/CD compromise** → supply-chain RCE; unsigned data trusted → tampering. Predominantly **Critical/RCE**.

**How to test (+ concrete classes → kits).**
```
□ Insecure deserialization: serialized blobs (Java ObjectInputStream, PHP unserialize/phar, .NET BinaryFormatter/
   ViewState, Python pickle, Ruby Marshal, Node node-serialize) → gadget chains → RCE. → ../Web/Deserialization/
□ ViewState / signed-blob tampering (.NET no-MAC/leaked machineKey): → ../Web/Deserialization/ (+ JWT for signed tokens).
□ Supply-chain integrity: dependency confusion, typosquatting, unverified packages. → ../Web/DependencyConfusion/ (also A03)
□ Auto-update / plugin integrity: does the app fetch + run code without signature verification?
□ CI/CD: exposed pipeline config, unsigned artifacts, injectable build steps (also A02/A03).
```

**Real-world / examples.** **SolarWinds / SUNBURST (2020)** — attackers (Russia's SVR / APT29) compromised the **Orion build pipeline** and shipped a **validly code-signed** trojanised update to **18,000+** organisations; because the malicious build was signed by SolarWinds itself, every downstream integrity check passed — the definitive broken software-integrity (trusted-update) failure. *(Note the 2025 split: pure dependency/registry compromise → A03; unsigned/unverified updates + insecure deserialization live here in A08.)* Others: ysoserial Java deserialization RCE; .NET ViewState RCE via leaked machineKey; PHP phar/POP-chain RCE; dependency-confusion RCE in CI.

**Prevention.** Avoid deserializing untrusted data (or safe formats + type allow-lists + integrity checks); sign + verify updates/plugins/artifacts; verify dependency integrity/provenance + pin; secure CI/CD; don't trust unsigned data for security decisions.

**Kits.** `Deserialization/` (RCE-ceiling), `DependencyConfusion/` (supply-chain integrity — also A03), `JWT/` (signed-token integrity), `JNDI/` (adjacent, via deserialization gadgets).

---

# A09:2025 — Security Logging & Alerting Failures

**What it is.** Insufficient logging, **alerting**, monitoring, and incident response — so attacks aren't detected, escalated, or investigated (**renamed** from 2021's "Logging and **Monitoring**" → "Logging **& Alerting**", emphasizing that logs without *alerting* don't stop attacks). Includes unlogged auth/access-control/high-value events, logs without detail, no alerting, logs not monitored, and — the offensive flip side — **log injection** and logs that leak sensitive data.

> *In plain words:* even when something bad happens, **nobody's watching** — no alarm goes off. The 2025 rename adds the key word "**alerting**": logs nobody reads are useless. Rarely a standalone bounty, but it lets every *other* attack run unnoticed — and logs can sometimes be poisoned or made to leak.

**Why it pays / impact.** Mostly a **defensive/detection** gap (hard to demo standalone), but real: undetected breaches persist; no forensics; it *amplifies* every other bug. Offensively, **log injection** (CRLF into logs, or Log4Shell-style log-triggered execution) and **sensitive data in logs** (PII/tokens) are concrete findings.

**How to test (+ concrete classes → kits).**
```
□ Detection gap (usually assessed): are auth failures, access-control denials, high-value actions, input-validation
   failures logged + ALERTED? do noisy things and ask "was it detected + did it alert?".
□ Log injection: CRLF/newline into a logged field → forge/split log entries; or a value that triggers execution when
   logged → JNDI/Log4Shell. → ../Web/JNDI/ (log-triggered RCE) + CRLF (../Web/OpenRedirect/ §CRLF)
□ Sensitive data in logs: PII/tokens/passwords written to logs (then exposed via another bug / access).
□ Alerting bypass / anti-forensics (red-team): operate below alerting thresholds.
```

**Real-world / examples.** **Target (2013)** — the FireEye monitoring system **did** detect the card-stealing malware and fired alerts (even naming the exfil servers), but the security team **ignored** them and the auto-eradicate feature was switched off; **40 million** cards were stolen and the CEO and CIO resigned. Detection without a response (the "Alerting" now explicit in the 2025 name) is operationally the same as no detection. Others: breaches undetected for months; Log4Shell = a *logging* path to RCE; log-forging via CRLF; credentials/PII in application logs later exposed.

**Prevention.** Log security-relevant events (auth, authz, input failures, high-value actions) with context + integrity; centralize + monitor + **alert** (the 2025 emphasis); protect logs (encode logged input; no sensitive data in logs); define + test incident response; retain appropriately.

**Kits.** `JNDI/` (logging-path RCE — the offensive edge), CRLF via `OpenRedirect/`; otherwise primarily a defensive/methodology category.

---

# A10:2025 — Mishandling of Exceptional Conditions

**What it is.** **NEW for 2025** (24 CWEs). The application fails to **prevent, detect, and respond to unusual/unpredictable situations** — improper error/exception handling, missing input/environment safeguards, poor recovery, and **fail-open** behavior (defaulting to allow on error) instead of **fail-closed**. Also: transactions that don't roll back completely on error, and errors that leak internal detail.

> *In plain words:* what does the app do when something **goes wrong** — a weird input, a crash, a half-finished payment? Safe apps "**fail closed**" (deny, roll back, show a generic error). Unsafe ones **fail open** (an auth check errors out and defaults to *allow*), spill internal details in the error page, or leave money/half-done transactions in a broken state. New for 2025 — you test it by *breaking* the app on purpose and watching how it falls over.

**Why it pays / impact.** Three concrete cash-outs (per OWASP's example scenarios): **DoS** (an uncaught exception — e.g. a file-upload error — leaves resources locked → exhaustion); **data exposure** (a database/stack error reveals internal details → reconnaissance for injection); **financial fraud / logic abuse** (an interrupted multi-step transaction without rollback → account draining or duplicate transfers). The security-relevant core is **fail-open** decisions (an auth/authz check that errors and defaults to "allow").

**How to test (+ concrete classes → kits).**
```
□ Trigger errors deliberately: malformed input, wrong types, oversized/empty payloads, race/interrupt a multi-step flow,
   exhaust a dependency → watch the response.
□ Verbose-error info disclosure: do errors leak stack traces / DB errors / internal paths / versions / secrets?
   (feeds SQLi error-based + recon). → ../Web/SQLi/ (error-based) + ../Web/Recon/ (verbose errors)
□ Fail-open checks: force an auth/authz/validation component to ERROR — does it default to ALLOW (fail-open) or DENY?
   (a fail-open access check is an A01-flavored bypass). → ../Web/IDOR/ (authz that fails open)
□ Transaction integrity: interrupt/parallelize a multi-step transaction (payment, transfer) — does it roll back, or
   leave partial/duplicate state? (overlaps A06 design + race). → ../Web/RaceCondition/
□ Resource-lock DoS: cause an exception mid-operation that leaves a lock/handle/connection held → exhaustion.
```

**Real-world / examples.** **CrowdStrike Falcon (19 Jul 2024)** — a content update (Channel File 291) fed the kernel sensor data it couldn't validate, triggering an **out-of-bounds read** the driver failed to handle gracefully → `SYSTEM_THREAD_EXCEPTION_NOT_HANDLED` **BSOD bootloops on ~8.5 million** Windows machines worldwide (airlines, hospitals, banks grounded). The purest A10 case: an **unhandled exceptional condition in a trusted code path that failed catastrophically instead of safely**. *(Security twist: the flip side is failing **open** — an exception in an auth/authz check that defaults to "allow" — CWE-636.)* Others: uncaught file-upload exception leaving resources locked → DoS; database errors revealing schema/system info → SQLi recon; interrupted transfer without rollback → double-spend/drain. CWEs: CWE-209 (sensitive error messages), CWE-234, CWE-476 (NULL deref), **CWE-636 (failing open insecurely)**.

**Prevention.** Catch exceptions at their source; centralized/global exception handling; **fail closed** (default-deny on error, complete rollback on partial failure); generic error messages (log detail server-side — ties A09); input validation + resource quotas + rate limiting; monitor repeated-error patterns as attack signals.

**Kits.** No single kit owns this new category — it's largely **methodology + defense-in-depth**, but it routes to: `SQLi/` (error-based / verbose DB errors), `Recon/` (verbose-error info disclosure), `IDOR/` (fail-open authz), `RaceCondition/` (interrupted/partial transactions). Test it by *breaking* the app on purpose and watching how it fails.

---

# Category → Kit quick map

| OWASP 2025 category | This repo's kits (hands-on technique) |
|---|---|
| **A01 Broken Access Control (incl. SSRF)** | `IDOR/` · `JWT/` (authz claims) · `CORS/` · `PathTraversal/` · `LFI/` · **`SSRF/`** · `OpenRedirect/` (SSRF bypass) · `AccountTakeover/` · `../API/REST/` |
| **A02 Security Misconfiguration** | `XXE/` · `HostHeader/` · `CORS/` · `WebCache/` · `RequestSmuggling/` · `SubdomainTakeover/` · `FileUpload/` · `Recon/` · `JSFiles/` |
| **A03 Software Supply Chain Failures** | `DependencyConfusion/` · `JNDI/` · `Deserialization/` · `JSFiles/` · `Recon/` · `PrototypePollution/` |
| **A04 Cryptographic Failures** | `JWT/` · `AccountTakeover/` (token entropy) · `JSFiles/` · `Recon/` |
| **A05 Injection** | `SQLi/` · `NoSQLi/` · `CommandInjection/` · `SSTI/` · `XPath/` · `LDAP/` · `XSS/` · `PrototypePollution/` · `OpenRedirect/` (CRLF) · `XXE/` |
| **A06 Insecure Design** | `RaceCondition/` · `AccountTakeover/` · (business-logic methodology) |
| **A07 Authentication Failures** | `AccountTakeover/` · `JWT/` · `OAuth/` · `CSRF/` |
| **A08 Software/Data Integrity Failures** | `Deserialization/` · `DependencyConfusion/` · `JWT/` · `JNDI/` |
| **A09 Logging & Alerting Failures** | `JNDI/` (log→RCE) · `OpenRedirect/` (CRLF) · (defensive/methodology) |
| **A10 Mishandling of Exceptional Conditions** | `SQLi/` (error-based) · `Recon/` (verbose errors) · `IDOR/` (fail-open authz) · `RaceCondition/` (partial txns) · (methodology) |

> Also in the repo: `WebSocket/`, `RFI/` (span multiple categories). The **API Security Top 10 (2023)** is covered by `../API/REST/` + `../API/GraphQL/`. The 2021 edition map lives in `OWASP_WEB_TOP_10.md` (kept alongside this one).

---

# Severity calibration & reporting

| Category / cash-out | Typical ceiling | Via kit |
|---|---|---|
| **A05 Injection → RCE** (cmdi/SSTI/SQLi-file-write) | **Critical** | `CommandInjection/` `SSTI/` `SQLi/` |
| **A01 SSRF → cloud metadata → cloud takeover/RCE** | **Critical** | `SSRF/` |
| **A03 Supply chain → known-CVE / malicious-dep → RCE** | **Critical** | `JNDI/` `Deserialization/` `DependencyConfusion/` |
| **A08 Deserialization → RCE** | **Critical** | `Deserialization/` |
| **A01 Broken access control → mass data / privesc** | **Critical–High** | `IDOR/` |
| **A07 Auth failure → account takeover** | **High** | `AccountTakeover/` `JWT/` `OAuth/` |
| **A04 Crypto failure → data/token exposure** | **High** | `JWT/` `AccountTakeover/` |
| **A02 Misconfig → XXE/cache-poison/takeover** | **High** | `XXE/` `WebCache/` `SubdomainTakeover/` |
| **A06 Insecure design → logic/race abuse** | **High–Medium** | `RaceCondition/` |
| **A10 Mishandling exceptional → fail-open / txn / DoS / error-leak** | **High–Low** (context) | `IDOR/` `RaceCondition/` `SQLi/` `Recon/` |
| **A09 Logging/alerting gap** | **Low–Medium** (defensive) | (methodology; `JNDI/` for log→RCE) |

**Reporting rules:** report the **concrete vuln + impact**, then map it to the 2025 category (triagers/scopes speak both — "IDOR on `/api/orders/{id}` → read any user's orders (A01 Broken Access Control, CWE-639)"). If your program still scopes to **2021**, cross-map (e.g. SSRF = 2021-A10 / 2025-A01; component CVE = 2021-A06 / 2025-A03) — both edition docs are kept in this repo. Use each kit's report template for the hands-on finding; use this doc to place it in the framework. Impact-first, own accounts, benign markers, safe PoC.

---

# Appendix — Verified Real-World Case Studies (deep dives)

> The per-category one-liners above are the *quick* citations; these are the full mechanism→escalation→lesson write-ups for the marquee breaches. Use them in a report or an interview to show *why* the category exists and how a small root cause became a headline. All facts are from public post-mortems / advisories (see References).

**xz-utils / liblzma backdoor — CVE-2024-3094 (A03 Software Supply Chain Failures, 2024).**
*Root cause:* a **human** supply-chain compromise. A persona, "Jia Tan," spent ~2 years making legitimate contributions to the volunteer-run `xz` project while sockpuppet accounts pressured the burned-out original maintainer to hand over commit rights. Once trusted, Jia Tan shipped xz **5.6.0/5.6.1** with a backdoor hidden in *test fixture* binary blobs and activated only by the build machinery — not visible in the source tree.
*Mechanism:* on affected distros, `liblzma` is pulled into `sshd` (via a systemd/libsystemd patch), so the backdoor hooked the `sshd` symbol-resolution path and let an attacker holding the right private key achieve **pre-auth RCE** on virtually any exposed OpenSSH server — CVSS **10.0**.
*Why it was (barely) caught:* Andres Freund (Microsoft) investigated `sshd` logins that were **~500 ms slower** and a Valgrind error, and traced it to liblzma before the backdoored versions reached most stable distros.
*Lesson:* dependency trust is **transitive and human** — "it's a signed release from an established project" is not integrity. Pin/verify builds from source, watch maintainer-change and build-system anomalies (A03 + A08), and remember your real attack surface includes your dependencies' dependencies.

**Capital One (A01 Broken Access Control, incl. SSRF, 2019).**
*Root cause:* an SSRF-able request path plus an **over-privileged IAM role** on a WAF host. *Mechanism:* Paige Thompson coerced the app/WAF into requesting `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` (IMDSv1, no token required), lifted the temporary AWS credentials, and — because that role could list and read S3 — exfiltrated **~106 million** credit-card applications (SSNs, bank accounts) from ~700 buckets. *Lesson:* SSRF is now **A01** because its payoff is an access-control break — it steps *around* the perimeter into internal identity. Fixes are defense-in-depth: enforce **IMDSv2** (token-bound metadata), scope IAM roles to least privilege, and egress-filter metadata IPs.

**SolarWinds / SUNBURST (A08 Software or Data Integrity Failures, 2020).**
*Root cause:* a compromised **build pipeline**, not a stolen signing key. *Mechanism:* the SUNSPOT implant watched the Orion build and swapped a source file *during compilation*, so the malicious `SolarWinds.Orion.Core.BusinessLayer.dll` was compiled and then **legitimately code-signed** by SolarWinds' own CI; ~**18,000** customers auto-updated to a backdoored, validly-signed binary that beaconed out and enabled selective second-stage intrusion (attributed to SVR/APT29). *Lesson:* signature verification only proves *who built it*, not *that the build was clean* — you must protect build integrity (reproducible builds, isolated signing, SBOM, artifact attestation), which is exactly the A08 control set.

**Equifax (A03/A06-lineage — vulnerable component, 2017).**
*Root cause:* a **known, patch-available** Apache Struts RCE (**CVE-2017-5638**) left unremediated on an internet-facing dispute portal. *Mechanism:* a crafted `Content-Type` header triggered OGNL evaluation → RCE; attackers entered ~3 days after the fix shipped, then dwelled ~**76 days** — partly because an **expired certificate** meant inspection tooling wasn't decrypting traffic — and exfiltrated **147.9 million** identities. *Lesson:* component inventory + fast patching (A03/A06) *and* working detection (A09) are one chain; breaking any link turns a published CVE into a nation-scale breach.

**CrowdStrike Falcon (A10 Mishandling of Exceptional Conditions, 2024).**
*Root cause:* a kernel driver that **trusted its own content update** and lacked bounds validation. *Mechanism:* Channel File 291 contained a field count the sensor's parser didn't expect; dereferencing it caused an **out-of-bounds read**, and because this ran in kernel mode with no graceful failure path, ~**8.5 million** Windows hosts hit `SYSTEM_THREAD_EXCEPTION_NOT_HANDLED` BSOD bootloops within hours — grounding airlines, hospitals and banks globally. *Lesson:* exceptional conditions must fail **safely and locally**, not catastrophically — validate all inputs (even trusted-channel ones), stage/canary updates, and design for graceful degradation. The security-relevant cousin is failing **open** (an exception in an authz check that defaults to "allow" — CWE-636).

**First American Financial (A01 Broken Access Control, 2019).**
*Root cause:* **no authorization check at all** on a document-viewer endpoint. *Mechanism:* completed real-estate transactions produced links like `…/DocEdit.aspx?...=<number>`; the number was sequential and the page required **no login**, so anyone could decrement/increment it and read strangers' title files — **~885 million** documents (SSNs, bank statements, wire receipts, driver's-license images) going back years. *Lesson:* the textbook IDOR — "logged in" was never even required. Enforce per-object ownership checks server-side on every request; unguessable IDs are not a substitute for authorization.

---

# References

**Primary**
- **OWASP Top 10:2025**: https://owasp.org/Top10/2025/ (per-category pages A01–A10 with CWEs + prevention).
- A03 Software Supply Chain Failures: https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/
- A10 Mishandling of Exceptional Conditions: https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/
- OWASP Top 10 project (methodology, data): https://owasp.org/www-project-top-ten/
- **OWASP API Security Top 10 (2023)** (the API twin — see `../API/REST/`): https://owasp.org/API-Security/
- OWASP Web Security Testing Guide (WSTG) + ASVS + Cheat Sheet Series.

**Note on editions**
- **2025** is the current standing edition (8th installment, **finalized 6 November 2025** with two new categories — A03 Supply Chain, A10 Exceptional Conditions); this doc tracks it. The **2021** edition reference is kept alongside as `OWASP_WEB_TOP_10.md` (some bug-bounty programs still scope to 2021). Per-kit content is edition-independent — the concrete techniques don't change with the ranking; only the category grouping does. Biggest 2025 shifts to remember: **SSRF → A01**, **new A03 Supply Chain** (from 2021-A06), **new A10 Exceptional Conditions**, **A02 Misconfig → #2**.

**Companion kits in this repo**
- All 32 Web kits (see the Category → Kit map) + `../API/REST/`, `../API/GraphQL/`, `../AI/LLM/` (LLM Top 10), `../Mobile/` (Mobile Top 10). This document is the OWASP-Web-Top-10 **2025** umbrella over the per-class kits — categories here, payloads there. The 2021 umbrella is `OWASP_WEB_TOP_10.md`.

---

> **Final reminder — the one rule that pays:** the OWASP Top 10 is a *map of risk categories*, not a checklist of bugs. 2025 re-buckets them (SSRF into A01, a new A03 Supply Chain, a new A10 Exceptional Conditions) but the underlying techniques — and this repo's kits — are unchanged. Use this doc to route from the category to the **deep kit** that owns the technique, test every member of the family, and report the **concrete vuln + demonstrated impact** mapped back to the category. Categories to think, kits to type.
