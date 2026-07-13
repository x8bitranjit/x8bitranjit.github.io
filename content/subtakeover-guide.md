# Subdomain Takeover — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any DNS record of the target (or a domain the target's cookies/OAuth/CSP trust) that points to a **third-party service or resource the target no longer owns/controls** — a dangling `CNAME`/`A`/`NS`/`MX` to an unclaimed cloud bucket, PaaS app, CDN, SaaS endpoint, or a lapsed domain — which **you can then claim** and serve content from, on a hostname inside the target's trust boundary
**Platforms:** Any DNS/cloud stack; Kali/WSL for tooling
**Companion files in this folder:**
- `SUBDOMAIN_TAKEOVER_ARSENAL.md` — per-service fingerprints, claim steps, DNS/enum commands (copy-paste)
- `SUBDOMAIN_TAKEOVER_CHECKLIST.md` — the testing-order checklist you tick per program
- `SUBDOMAIN_TAKEOVER_REPORT_TEMPLATE.md` — the report skeleton that gets paid (benign-claim proof)
- `Subdomain_Takeover_Zero_to_Expert.md` — study + field-reference Q&A
- `poc/` — runnable tooling (dangling-CNAME/fingerprint scanner, service-signature DB, benign claim-proof helper)

> **Companion to the Recon, Open-Redirect, OAuth/SSO, CORS and Host-Header guides.** Subdomain takeover is where **recon becomes a Critical**. The mistake hunters make is stopping at "this CNAME points to an unclaimed S3 bucket — the page 404s." A 404 is a *fingerprint*, not the finding. The finding is that **you register the dangling resource and serve your content from `sub.target.com`** — a hostname the browser, the target's cookies, its CSP, its OAuth `redirect_uri` allow-list, and its users all **trust**. That trust is the whole payload: it turns a leftover DNS record into **cookie theft, credential phishing on a real domain, OAuth token theft, CSP bypass, and same-site pivots**. Read Part III before you report a dangling record.

---

> ### ⚡ READ THIS FIRST — why most subdomain-takeover reports underpay (or get closed)
> 1. **A dangling record is the *condition*; the *claim* is the finding.** "The CNAME points to a non-existent Azure/S3/Heroku target" is a fingerprint. You must **actually claim** the resource (create the bucket/app/page) and **serve a benign proof file** from `sub.target.com` — otherwise a triager can (rightly) close it as "unconfirmed / not exploitable."
> 2. **The severity is the *trust the hostname carries*, not the page you host.** Serving `hello` on `sub.target.com` is Low by itself. It's **High–Critical** when that trusted host lets you steal **domain-scoped cookies** (session ATO), phish on the **real brand domain**, satisfy an **OAuth `redirect_uri`/CSP/CORS allow-list**, or read/relay **auth flows** — because the subdomain is *inside the trust boundary* (§10–§14).
> 3. **`NS` and `MX` takeovers are the sleeper Criticals.** A dangling **`NS`** delegation you can claim = you control **all** DNS for that subdomain (and can mint valid TLS certs, catch mail, host anything). A dangling **`MX`** = you receive the target's **email** for that host → password-reset interception → ATO. These out-rank a typical CNAME-to-bucket.
> 4. **"Second-order" / stored takeovers hide the best bugs.** A subdomain that's dead now but is **referenced in the target's JS, CSP, CORS allow-list, OAuth config, or `<script src>`** is worth far more — claiming it gives you **script execution or auth-token delivery on the main app**, not just a standalone page (§13).
> 5. **Don't confuse "NXDOMAIN" with "takeover-able."** Many dangling records point to services that are **NOT claimable** (the provider prevents re-registration, or the name is reserved). The Arsenal's per-service matrix tells you which fingerprints are *actually* claimable and how — that distinction is the difference between a valid report and noise.
>
> **Where the money is (memorize this order):** ① **`NS`/`MX` takeover → full DNS control / email interception → cert issuance + reset-token capture → ATO/domain compromise — Critical** → ② **CNAME takeover on a host whose *cookies are domain-scoped* → session cookie theft → ATO — High–Critical** → ③ **takeover of a host in an OAuth `redirect_uri` / CSP / CORS allow-list → token theft / script exec on main app — High–Critical** → ④ **takeover → credential phishing on the real brand domain — High** → ⑤ *then* a bare claimed subdomain serving your content with no trust-chain — **Low–Medium**.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [Subdomain-Takeover Anatomy — Dangling Records & Why It Pays](#2-subdomain-takeover-anatomy)
3. [Reconnaissance — Enumerate Every Subdomain & Record](#3-reconnaissance--enumerate-every-subdomain--record)
4. [Baseline — Which Records Are Dangling & Claimable?](#4-baseline--which-records-are-dangling--claimable)

**PART II — DETECTION & CONFIRMATION (work in this order)**
5. [The Record Types — CNAME, A, NS, MX, and Others](#5-the-record-types--cname-a-ns-mx-and-others)
6. [Fingerprinting the Service — Is It Really Unclaimed?](#6-fingerprinting-the-service--is-it-really-unclaimed)
7. [Claimability — Proving You Can Register the Resource](#7-claimability--proving-you-can-register-the-resource)

**PART III — EXPLOITATION BY IMPACT (where the money is)**
8. [The Benign Claim — Serving Proof from `sub.target.com`](#8-the-benign-claim--serving-proof-from-subtargetcom)
9. [Mapping the Takeover to an Attack](#9-mapping-the-takeover-to-an-attack)
10. [Cookie Theft & Session ATO (domain-scoped cookies) ⭐](#10-cookie-theft--session-ato)
11. [`NS` / `MX` Takeover → DNS Control / Email Interception → ATO ⭐](#11-ns--mx-takeover--dns-control--email-interception)
12. [Credential Phishing on the Real Brand Domain](#12-credential-phishing-on-the-real-brand-domain)
13. [Second-Order: OAuth / CSP / CORS / `<script src>` Trust ⭐](#13-second-order-oauth--csp--cors--script-src-trust)
14. [TLS Certs, Same-Site Pivots & Chaining](#14-tls-certs-same-site-pivots--chaining)

**PART IV — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
15. [The Validity-First Mindset](#15-the-validity-first-mindset)
16. [False Positives — STOP reporting these](#16-false-positives--stop-reporting-these-auto-reject-list)
17. [Severity Calibration](#17-severity-calibration--how-triagers-really-rate-subdomain-takeover)
18. [Impact-Escalation Playbooks — "you found X, now do Y"](#18-impact-escalation-playbooks--you-found-x-now-do-y)
19. [Building a Professional, Safe PoC](#19-building-a-professional-safe-poc)
20. [Reporting, CWE/CVSS & De-duplication](#20-reporting-cwecvss--de-duplication)
21. [Automation & Red-Team Notes](#21-automation--red-team-notes)

**Appendices**
- [Appendix A — Subdomain-Takeover Workflow Cheat Sheet](#appendix-a--subdomain-takeover-workflow-cheat-sheet)
- [Appendix B — Subdomain-Takeover Decision Tree](#appendix-b--subdomain-takeover-decision-tree)
- [Appendix C — Important Links & References](#appendix-c--important-links--references)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Numbered sections (1–21) are reference detail; this is the order you execute.

```
PHASE 0  RECON            → enumerate ALL subdomains + their DNS records (CNAME/A/NS/MX/TXT); passive+active,
                            historical, cert-transparency, brute (§3)
PHASE 1  BASELINE  ★      → which records are DANGLING (point to a resource that returns a takeover fingerprint /
                            NXDOMAIN / SERVFAIL)? filter to CLAIMABLE services (§4)
PHASE 2  DETECT/CONFIRM   → record type (CNAME/A/NS/MX §5) · fingerprint the service (is it unclaimed? §6) ·
                            confirm CLAIMABILITY (can you actually register it? §7)
PHASE 3  IMPACT  ⭐ (money)→ CLAIM it benignly (§8), then map to attack (§9):
                            cookie theft -> session ATO (§10) · NS/MX -> DNS/email -> ATO (§11) ·
                            phishing on the real domain (§12) · OAuth/CSP/CORS/script-src trust (§13) ·
                            TLS certs / same-site pivot / chain (§14)
PHASE 4  VALIDATE→REPORT  → validity (§15) · false-positive filter (§16) · severity+CVSS+CWE-350 (§17) ·
                            SAFE PoC: benign proof file, UNPUBLISH after, report+ask them to remove the record (§19) ·
                            dedup (§20)
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon.** Enumerate **every** subdomain and resolve **each record type** (CNAME/A/NS/MX/TXT) — passive (CT logs, `amass`/`subfinder`), active (brute, permutations), historical (§3). *Deliverable:* a full `(subdomain → records)` map.
2. **PHASE 1 — Baseline ⭐.** Find the **dangling** records — ones resolving to a resource that returns a **takeover fingerprint**, `NXDOMAIN`, or `SERVFAIL` — and filter to **claimable** services (§4). *Deliverable:* a shortlist of candidate dangling+claimable records.
3. **PHASE 2 — Detect/confirm.** Nail the **record type** (§5), **fingerprint** the service to confirm it's genuinely unclaimed (§6), and **confirm claimability** — that the provider will let you register this exact resource (§7). *Deliverable:* a confirmed claimable dangling record.
4. **PHASE 3 — Impact ⭐.** **Claim** the resource and serve a **benign proof** from `sub.target.com` (§8), then escalate: cookie theft → ATO (§10), NS/MX → DNS/email → ATO (§11), phishing on the real domain (§12), OAuth/CSP/CORS/script trust (§13), TLS/same-site chains (§14). *Deliverable:* a demonstrated impact (proof served + the trust it grants).
5. **PHASE 4 — Validate → report.** Apply validity & FP filters (§15/§16), set CVSS/CWE-350 (§17), keep the PoC **benign** and **unpublish** it after capture (§19), de-dup, write it and ask them to remove the record (§20). *Deliverable:* the submitted report.

Reference anytime: fingerprints/commands → `SUBDOMAIN_TAKEOVER_ARSENAL.md`; checklist → `SUBDOMAIN_TAKEOVER_CHECKLIST.md`; scripts → `poc/`; playbooks **§18**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

| Tool | Job |
|------|-----|
| **`subfinder` / `amass` / `assetfinder`** | passive subdomain enumeration (CT logs, APIs, scraping) |
| **`dnsx` / `massdns` / `dig`** | resolve records at scale; pull CNAME/A/NS/MX/TXT chains |
| **`subzy` / `nuclei` (`-tags takeover`) / `subjack` / `can-i-take-over-xyz`** | fingerprint dangling records against the known-service matrix |
| **`poc/subtakeover_scan.py`** | resolve a subdomain list, follow CNAME chains, match the fingerprint DB, and rank claimable candidates |
| **`poc/fingerprints.py`** | the per-service signature DB (CNAME pattern + HTTP body/status fingerprint + claimable? + claim notes) |
| **`poc/claim_proof.py`** | after you've registered the resource, verify `sub.target.com` now serves *your* benign proof marker |
| **`crt.sh` / `chaos` / `github-subdomains`** | historical & cert-transparency subdomains (dead hosts still in CT are prime candidates) |
| **a cloud/SaaS account you control** | to actually claim the dangling resource (S3/Azure/Heroku/GitHub Pages/Fastly/etc.) |
| **`httpx`** | fast HTTP probing (status, title, body) to spot the "NoSuchBucket"/"There isn't a GitHub Pages site here" pages |

```bash
# Kali/WSL — enumerate, resolve, and fingerprint
subfinder -d target.com -all -silent | dnsx -silent -cname -resp -o resolved.txt
subzy run --targets resolved.txt --hide_fails
nuclei -l subs.txt -tags takeover -o takeover.txt
python3 poc/subtakeover_scan.py -l subs.txt        # our resolver + fingerprint + claimability ranker
```
> **A fingerprint is not a finding.** `subzy`/`nuclei` telling you "vulnerable to takeover" means the *pattern matches*. You still must (a) confirm the service is **actually claimable** (§7) and (b) **claim it and serve a benign proof** (§8) before reporting — many matched fingerprints are stale or non-claimable.

---

# 2. Subdomain-Takeover Anatomy

## 2.1 What it is
The target created a DNS record — usually a **`CNAME`** — pointing a subdomain (`shop.target.com`) at a third-party service (`target-shop.myshopify.com`, `s3.amazonaws.com`, `target.github.io`, `target.herokuapp.com`). Later the service resource is **deleted or de-provisioned**, but **the DNS record is left behind ("dangling")**. Because the provider lets *anyone* register that exact resource name, **you** create it → the subdomain now resolves to **your** content. It's the DNS/cloud member of the **"dangling reference to an unowned resource"** family.

## 2.2 The record types that matter (decides the attack)
```
CNAME → third-party SaaS/PaaS/CDN/bucket → claim the resource → serve content from sub.target.com (the common case). §5
A     → an IP no longer owned (cloud elastic IP, shared host) → claim the IP/host → serve content.  Rarer, harder.
NS    → delegated to a nameserver/zone you can register → you control ALL DNS for the subdomain → certs, mail, anything. ⭐ CRITICAL
MX    → mail routed to a service you can claim → you receive the target's EMAIL for that host → reset interception → ATO. ⭐
TXT/other → SPF/verification records referencing claimable resources → email spoofing / domain-verification abuse.
```

## 2.3 The dangling signals (what "unclaimed" looks like)
```
NXDOMAIN            the CNAME target itself doesn't resolve → often claimable (register the name).
SERVFAIL / no NS    broken delegation → possible NS takeover.
SERVICE 404 PAGE    a provider "not found" page: "NoSuchBucket", "There isn't a GitHub Pages site here",
                    "No such app", "Fastly error: unknown domain", "Domain not found" (Heroku/Netlify/etc.) → fingerprint.
DEAD RESOURCE       the CNAME resolves but the resource behind it is deprovisioned → claim it on the provider.
```

## 2.4 Why it pays
- **The hostname is inside the trust boundary.** `sub.target.com` inherits the brand's reputation, domain-scoped cookies, CSP/CORS/OAuth allow-list membership, and user trust.
- **Cookie theft → ATO.** If the app sets cookies on `.target.com` (domain-scoped), your page on `sub.target.com` reads/sets them → session hijack.
- **Auth-flow abuse.** A trusted subdomain in an OAuth `redirect_uri` allow-list or a CSP `script-src` becomes a token-theft or script-exec primitive on the *main* app.
- **NS/MX = keys to the kingdom.** DNS control lets you mint valid TLS certs and catch mail (reset tokens).

> **The mental model:** a subdomain takeover is a **hostname inside the target's trust boundary that you now control.** Severity = *what that trust unlocks* — domain cookies (ATO), an OAuth/CSP/CORS allow-list entry (token theft/script exec), DNS/mail control (certs/reset interception), or "just" the brand for phishing.

---

# 3. Reconnaissance — Enumerate Every Subdomain & Record

```
□ PASSIVE ENUM: subfinder/amass/assetfinder + CT logs (crt.sh, certspotter), chaos, SecurityTrails, VirusTotal, GitHub.
□ HISTORICAL: crt.sh & wayback for subdomains that once existed — DEAD hosts still in CT logs are PRIME candidates.
□ ACTIVE ENUM: DNS brute (puredns/massdns + a good wordlist) + permutations (altdns/gotator) for internal-naming patterns.
□ RESOLVE EVERY RECORD: for each subdomain pull CNAME, A/AAAA, NS, MX, TXT (dnsx -cname -a -ns -resp).
□ FOLLOW CNAME CHAINS: a CNAME to a CNAME to a dead bucket — resolve the WHOLE chain; the danglers hide at the end.
□ MAP THE THIRD-PARTY: note which SaaS/PaaS/CDN each record points at (amazonaws/github.io/herokuapp/azurewebsites/...).
□ NOTE TRUST CONTEXT: is the subdomain referenced in the main app's JS / CSP / CORS ACAO / OAuth config? (second-order §13).
□ SCOPE CHECK: only the TARGET's domains/subdomains are in scope — a dangling record on a THIRD-PARTY domain is not their bug.
```
> **If this → then that:** a subdomain appears in **CT logs** but no longer resolves / returns a provider 404 → top takeover candidate (§4). A dead subdomain is **referenced in the main app's CSP/CORS/OAuth** → that's a **second-order** takeover worth far more than a standalone page (§13) — flag it now.

---

# 4. Baseline — Which Records Are Dangling & Claimable?

**Do this before trying to claim anything.** Separate "dangling" (points at a dead resource) from "claimable" (you can actually register it).

## 4.1 The baseline checks
```
1. Resolve the subdomain. Does the CNAME target resolve? NXDOMAIN on the target → likely claimable (register the name).
2. If it resolves, fetch it over HTTP/HTTPS. Do you get a PROVIDER "not found" page (NoSuchBucket / no GitHub Pages
   site / Heroku "No such app" / Fastly "unknown domain" / Netlify "Not Found")? → dangling → fingerprint (§6).
3. Match the fingerprint against the known-service matrix (Arsenal / can-i-take-over-xyz). Is this service marked CLAIMABLE?
4. NS/MX: is the delegated nameserver / mail target itself unregistered or on a claimable provider? (§11)
```

## 4.2 Classify what you can do
```
□ CNAME → claimable SaaS/bucket with a "not found" fingerprint     → claim it (§7/§8) → escalate by trust (§10/§13).
□ CNAME → NXDOMAIN registrable name (e.g. a lapsed domain / bucket) → register it → serve proof (§8).
□ NS delegation to a claimable/expired nameserver                  → NS takeover → full DNS control (§11). ⭐ CRITICAL
□ MX to a claimable mail service                                    → email interception → reset ATO (§11). ⭐
□ Dead subdomain referenced in main-app CSP/CORS/OAuth/script       → second-order → token/script on main app (§13). ⭐
□ Fingerprint matches but service is NOT claimable (reserved)       → NOT a takeover → likely Info/N-A (§16).
□ Just a 404 with no provider fingerprint / still owned             → not dangling → keep looking.
```

> **Don't stop at "it 404s."** A 404 is a fingerprint. The report is the **claim** (you served your proof from the host) plus the **trust escalation** (cookies/OAuth/CSP/DNS/mail). A fingerprint you *can't* claim, or a bare claimed host with no trust chain, is Low/Info (§16).

---

# PART II — DETECTION & CONFIRMATION (work in this order)

> Full per-service fingerprints & claim steps are in `SUBDOMAIN_TAKEOVER_ARSENAL.md`.

# 5. The Record Types — CNAME, A, NS, MX, and Others

```
CNAME (most common): sub.target.com → some-name.provider.com.  The resource behind some-name is dead & re-registrable.
  - Detection: dig CNAME sub.target.com ; then probe the target for a provider "not found" page.
A / AAAA:            sub.target.com → 203.0.113.10 (an IP the target no longer holds). Harder — you'd need that exact IP
                     (cloud elastic-IP churn) or a shared-hosting account that answers for the vhost. Lower yield, still real.
NS:                  sub.target.com delegated to ns1.provider.com — if that zone/nameserver is claimable or the domain
                     expired, you serve ALL DNS for sub.target.com. CRITICAL (§11).
MX:                  mail.target.com → mail SaaS you can claim → you receive that host's email. CRITICAL for reset ATO (§11).
TXT / SPF / CAA:     references to claimable third-party verification/anti-spam resources → email spoofing, verification bypass.
DNAME / SRV:         rarer delegation forms; same principle — a dangling pointer to a claimable resource.
```
> **If this → then that:** a plain **CNAME to a dead SaaS** → the standard claim (§7/§8). An **`NS`** record whose nameserver domain is **expired/claimable** → NS takeover → you mint certs and control the whole subdomain (§11) — pursue this hardest, it's Critical. An **`MX`** to a claimable mail provider → email interception → reset-token capture → ATO (§11).

---

# 6. Fingerprinting the Service — Is It Really Unclaimed?

Confirm the resource is genuinely dead (not just an app that returns 404 for `/`):

```
□ HTTP BODY SIGNATURE: match the provider's specific "not found" string (the Arsenal lists them per service):
    AWS S3:        "NoSuchBucket" / "The specified bucket does not exist"
    GitHub Pages:  "There isn't a GitHub Pages site here."
    Heroku:        "No such app" / "herokucdn.com/error-pages/no-such-app.html"
    Fastly:        "Fastly error: unknown domain"
    Azure:         "404 Web Site not found" (azurewebsites) / storage "The specified ... does not exist"
    Shopify:       "Sorry, this shop is currently unavailable."
    Netlify/Surge/Readme/Ghost/Cargo/Tumblr/Zendesk/Unbounce/Wufoo/...  (see Arsenal + can-i-take-over-xyz)
□ STATUS + PROVIDER HEADERS: confirm the response is served BY the provider (Server/Via/X-Served-By), not a target error page.
□ CNAME TARGET STATE: does the CNAME target itself NXDOMAIN, or resolve to the provider's shared front-end?
□ NEGATIVE CHECK: browse a known-LIVE subdomain on the same provider to compare — don't mistake a normal 404 for a dangler.
```
> **The fingerprint rule:** the response must be the **provider's** generic "this resource doesn't exist / isn't claimed" page (matched by the exact signature), served by the **provider's** infrastructure — not the target's own 404. Use `can-i-take-over-xyz` to confirm the service is on the **"vulnerable / claimable"** list, then move to claimability (§7).

---

# 7. Claimability — Proving You Can Register the Resource

The step that separates a report from noise: can you **actually register** this exact resource?

```
□ CHECK THE PROVIDER'S RULES: some services PREVENT re-registration of a name once released, or require domain
   verification you can't pass → NOT takeover-able (mark Info). can-i-take-over-xyz tracks this per service.
□ NAME AVAILABILITY: is the exact bucket/app/page/space name FREE to create in your own account?
    - S3: try to create the bucket name (globally unique namespace). GitHub Pages: is the repo/org username free?
    - Heroku/Netlify/Fastly/Azure: is the app/site/service name available to add as a custom domain?
□ CUSTOM-DOMAIN BINDING: many services need you to ADD sub.target.com as a custom domain in YOUR resource. If the provider
   verifies domain ownership (TXT/again) you may be blocked → not claimable; if it binds purely on the CNAME, you're in.
□ REGION / NAMESPACE: match the provider's region/namespace the original used (esp. S3/Azure).
□ EXPIRED-DOMAIN case (NS/lapsed): is the base domain the CNAME/NS points at actually available to REGISTER at a registrar?
```
> **If this → then that:** the exact resource name is **free to create in your account** and the service binds on the CNAME (no extra domain-ownership check) → **claimable → proceed to the benign claim (§8)**. If the provider **blocks re-registration** or demands a verification you can't meet → **not a takeover** (report as Info at most, or move on). Never assume claimability from a fingerprint — verify it.

---

# PART III — EXPLOITATION BY IMPACT (where the money is)

> Serve only a **benign proof**, from your **own** provider account, and **unpublish** it immediately after capturing evidence (§19). Never host real phishing, malware, or leave the claim live.

# 8. The Benign Claim — Serving Proof from `sub.target.com`

The core PoC: register the dangling resource and serve an innocuous, uniquely-identifiable file from the target subdomain.

```
1. Create the resource in YOUR account with the exact name the dangling record points at (bucket/app/page/site).
2. Bind sub.target.com as the custom domain (so the existing CNAME now resolves to YOUR resource).
3. Serve a BENIGN proof: a single page/file with a unique marker, e.g.:
     /st-poc-<random>.txt   containing  "subdomain-takeover PoC by <your-handle> for <program> — <timestamp>"
   (No real content, no phishing, no script targeting users.)
4. Verify: fetch https://sub.target.com/st-poc-<random>.txt → it returns YOUR marker → takeover CONFIRMED. Screenshot.
5. UNPUBLISH: remove the content / release the resource right after capturing evidence (§19). Keep the claim as short-lived
   as the PoC needs.
```
> **If this → then that:** `https://sub.target.com/<your-marker>` returns **your** content → **confirmed subdomain takeover**. That alone is a valid (often Medium) finding. To move it up, chain the **trust** the hostname carries (§10–§14). Capture the proof, then **take it down** and tell them to remove the DNS record.

---

# 9. Mapping the Takeover to an Attack

```
Trust the subdomain carries                    Attack                                 Severity ceiling
──────────────────────────────────────────────────────────────────────────────────────────────────────
domain-scoped cookies (.target.com)            Cookie read/set → session ATO           High–Critical            §10 ⭐
NS delegation you control                      Full DNS control → certs, mail, all      Critical                 §11 ⭐
MX you control                                 Email interception → reset-token ATO     Critical                 §11 ⭐
in OAuth redirect_uri / CSP / CORS allow-list  Token theft / script exec on MAIN app    High–Critical            §13 ⭐
brand reputation only                          Credential phishing on the real domain   High (context)           §12
bare claimed host, no trust chain              Defacement / info                        Low–Medium               §16
```

# 10. Cookie Theft & Session ATO ⭐

The most common high-impact escalation. If the app sets cookies scoped to the **parent domain**, a page you control on any subdomain reads and writes them.

```
1. Confirm domain-scoped cookies: log into the main app; inspect the session cookie's Domain attribute.
   Domain=.target.com  (or target.com)  → EVERY subdomain, including your taken-over one, can read/set it.
   Domain=app.target.com (host-only)     → only that exact host → your subdomain can't read it (lower impact).
2. READ: your page on sub.target.com runs document.cookie (same-site) → if the session cookie isn't HttpOnly, you read it
   → session hijack → ATO. (HttpOnly blocks JS read but NOT the writes below.)
3. WRITE / FIXATION: set a cookie on .target.com from your subdomain (session fixation, CSRF-token overwrite, cache/lang
   poisoning, feature-flag tampering) → affects the victim on the MAIN app.
4. Cookie bomb / eviction: overflow the domain cookie jar from your subdomain to break the main app (DoS) — lower value.
```
> **If this → then that:** the session cookie is **`Domain=.target.com`** and **not HttpOnly** → your page on the taken-over subdomain **reads the victim's session** → **account takeover (High–Critical)**. Even with HttpOnly, you can **set** `.target.com` cookies → **session fixation / CSRF-token overwrite** on the main app. Confirm the cookie's `Domain` attribute — that's what turns a claimed host into an ATO.

---

# 11. `NS` / `MX` Takeover → DNS Control / Email Interception → ATO ⭐

The top-tier outcomes — these out-rank a CNAME-to-bucket.

```
NS TAKEOVER (dangling delegation):
  1. sub.target.com is delegated (NS record) to a nameserver whose domain is EXPIRED or on a claimable DNS provider.
  2. Register the nameserver domain / claim the DNS zone → you now answer ALL DNS for sub.target.com.
  3. You can: serve any A/AAAA (host anything), mint VALID TLS certs (domain-validated via the DNS you control) →
     a fully trusted https://sub.target.com; set MX (catch mail); set TXT (pass SPF/DKIM/domain-verification). CRITICAL.
MX TAKEOVER (dangling mail route):
  1. mail-ish.target.com MX → a mail SaaS you can register that hostname on.
  2. Claim it → you receive email addressed to that host.
  3. Impact: intercept PASSWORD-RESET / verification / invite emails routed there → reset-token capture → ATO;
     read internal notifications; send spoofed mail as the domain. CRITICAL for reset interception.
```
> **If this → then that:** a **dangling `NS`** you can claim → **full DNS control of the subdomain** → issue a valid cert + host/mail/verify as the target → treat as **Critical** (it's effectively owning that subdomain outright). A **dangling `MX`** you can claim → **email interception** → if any reset/verification mail is routed there, **reset-token capture → ATO**. Prove benignly (a cert issued to your own claim, a test email you send to yourself), then stop.

---

# 12. Credential Phishing on the Real Brand Domain

When there's no cookie/OAuth/DNS chain, the trusted hostname is still a potent phishing surface:

```
□ Serve a look-alike login on https://sub.target.com — a REAL target.com subdomain with (via NS takeover) a VALID TLS cert.
□ Victims (and email/URL-reputation filters) trust it because it's genuinely the brand's domain → very high credential yield.
□ Especially strong for a subdomain that historically hosted a login/portal (users have muscle memory / bookmarks).
```
> **If this → then that:** no technical trust chain but a **claimed brand subdomain** → **credential phishing (High, context-dependent)** — a phishing page on the *real* domain beats any look-alike. For the PoC, **do not** host a live credential-harvesting page against real users; describe the phishing impact and prove control with a benign marker (§19). Report the takeover; the phishing potential is the impact narrative.

---

# 13. Second-Order: OAuth / CSP / CORS / `<script src>` Trust ⭐

The highest-value takeovers are the ones the **main app already trusts** — claiming them yields script execution or token theft on the primary application, not a standalone page.

```
□ OAuth redirect_uri ALLOW-LIST: the taken-over subdomain is a registered redirect_uri (or matches a wildcard) → run the
   OAuth flow with redirect_uri=https://sub.target.com/cb → the code/token is delivered to YOUR host → ATO (OAuth kit).
□ CSP script-src / default-src: the main app's CSP allows scripts from sub.target.com → host a script there → it now
   executes on the main app (bypassing CSP) → effectively XSS on the main app → session theft/ATO (XSS kit).
□ CORS ACAO allow-list: the API reflects/allows Origin: https://sub.target.com with credentials → your page reads the
   victim's authenticated API responses cross-origin → secret/ATO (CORS kit).
□ <script src> / asset include: the main app loads JS/CSS from the dead subdomain → claim it → serve malicious JS that
   runs on the main app → XSS-equivalent on every page that includes it. ⭐ CRITICAL (supply-chain-style).
□ Cookie Domain / OAuth "trusted" subdomains: any place a config trusts *.target.com and your host matches.
```
> **If this → then that:** the dead subdomain is in a **CSP `script-src`** or loaded via **`<script src>`** on the main app → claiming it gives you **script execution on the main application** (CSP bypass / stored-asset XSS) → **High–Critical** (session theft, ATO, defacement of the real app). It's in an **OAuth `redirect_uri`** allow-list → **token theft → ATO** (hand to the OAuth kit). It's in a **CORS** allow-list → **cross-origin secret read** (hand to the CORS kit). These "second-order" takeovers are the ones that pay the most — always check what the main app references before down-scoring a dead subdomain.

---

# 14. TLS Certs, Same-Site Pivots & Chaining

```
□ VALID TLS on the taken-over host: via NS takeover (DNS-01) or the provider's auto-TLS (HTTP-01 on your claim) →
   https://sub.target.com is padlock-valid → maximally credible for phishing/cookie/OAuth chains.
□ SAME-SITE / SAMESITE=LAX PIVOT: your subdomain is "same-site" to the main app → helps satisfy SameSite=Lax cookie
   conditions and same-site fetch/postMessage assumptions in a larger chain.
□ REFERER / TRUST CHAINS: a link from the taken-over trusted subdomain launders phishing/redirects (cross-ref Open-Redirect).
□ INTERNAL TOOLING: dev/staging/CI subdomains often had privileged integrations — a takeover there can reach internal APIs,
   webhooks, or leaked secrets baked into the old resource.
□ EMAIL AUTH: NS/MX/TXT control lets you pass SPF/DKIM/DMARC for the subdomain → fully authenticated spoofed mail.
```
> **If this → then that:** you took over via **NS** → issue a **valid DV TLS cert** for `sub.target.com` (you control DNS) → now every cookie/OAuth/phishing chain is padlock-valid and indistinguishable from the real service. Combine with the **Open-Redirect** kit (a trusted-subdomain redirect) and the **OAuth/CORS** kits (allow-list membership) for the full account-takeover chains.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 15. The Validity-First Mindset

## 15.1 The four questions a triager asks (answer them in your report)
1. **Is the record actually dangling AND claimable?** Show the fingerprint (provider "not found" page) *and* that you could register it.
2. **Did you actually claim it?** Serve a **benign, unique marker** from `sub.target.com` and screenshot it — proof of control, not a fingerprint.
3. **What impact does the trust grant?** Domain cookies (ATO), OAuth/CSP/CORS allow-list (token/script on main app), NS/MX (DNS/mail → ATO), or brand phishing. Name it.
4. **Reproducible & in scope?** The exact subdomain + record + provider + the served proof — and it's the *target's* asset, not a third party's.

## 15.2 The "fingerprint vs claim" rule (most important)
| You have | Standalone verdict | Becomes valuable when… |
|---|---|---|
| A dangling-record fingerprint (404 page), not claimed | Info / unconfirmed | …you **claim it** and serve your marker (§8). |
| Claimed subdomain, benign page, no trust chain | Low–Medium | …it carries domain cookies (§10), an allow-list entry (§13), or NS/MX control (§11). |
| Takeover of a host with `Domain=.target.com` cookies | **High–Critical** | …you read/set the victim's session → ATO (§10). |
| Takeover of a host in an OAuth/CSP/CORS allow-list | **High–Critical** | …token theft / script exec on the main app (§13). |
| `NS`/`MX` takeover | **Critical** | …DNS control / email (reset) interception (§11). |
| Fingerprint on a NON-claimable service | Info / N-A | …never (the provider blocks re-registration). |

## 15.3 Production-scope discipline
Confirm on the **real** target subdomain, claim in **your own** provider account, serve a **benign** marker, and **unpublish immediately** after evidence. Never leave the claim live, never host real phishing/malware, never intercept real users' mail/cookies. For NS/MX, prove with your **own** test cert/email. Re-test after they say it's fixed (the DNS record must be *removed*, not just the resource re-created).

---

# 16. False Positives — STOP reporting these (auto-reject list)

| # | Commonly mis-reported | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **"CNAME points to an unclaimed service" (fingerprint only)** | A fingerprint isn't proof; you didn't claim it. | You **claimed** it and served your marker (§8). |
| 2 | **Service is on the NON-claimable list** (provider blocks re-registration) | You can't actually take it over. | The service is confirmed **claimable** (§7). |
| 3 | **A generic 404 with no provider signature** | The host is still owned; it's just a 404. | An exact provider "not found" fingerprint (§6). |
| 4 | **Dangling record on a THIRD-PARTY domain** you found via the target | Wrong asset / out of scope. | It's the target's own subdomain. |
| 5 | **Claimed host but cookies are host-only (`Domain=app.x`)**, reported as ATO | Your subdomain can't read them. | Cookies are `Domain=.target.com` (§10). |
| 6 | **"NXDOMAIN so it's takeover-able"** without checking registrability | NXDOMAIN ≠ claimable. | The name is actually free to register/create (§7). |
| 7 | **Internal/wildcard `*.target.com` that resolves to a live catch-all** | Not dangling. | A specific, dead, claimable record. |
| 8 | **Takeover with no impact narrative**, reported as Critical | Bare takeover is Low–Medium. | A cookie/OAuth/CSP/NS/MX chain (§10–§13). |

> Rule of thumb: if you can't say *"I **claimed** the dangling `<record>` for `<sub.target.com>` and served my proof, and the host carries `<domain cookies / an OAuth-CSP-CORS allow-list entry / DNS or mail control>` giving `<ATO / script-exec on the main app / reset interception>`,"* you have a **fingerprint or a bare claim, not an impactful takeover.** Claim it, then chain the trust.

---

# 17. Severity Calibration — how triagers really rate subdomain takeover

| Scenario | Typical | What moves it |
|---|---|---|
| **`NS` takeover → full DNS control (certs/mail/host)** | **Critical** | You own the subdomain outright. |
| **`MX` takeover → password-reset email interception → ATO** | **Critical** | Direct account takeover via reset. |
| **Takeover of a host with `Domain=.target.com` session cookies** | **High–Critical** | Read/set victim session → ATO. |
| **Takeover of a host in OAuth `redirect_uri` / CSP `script-src`** | **High–Critical** | Token theft / script exec on main app. |
| **Takeover of a host in a credentialed CORS allow-list** | **High** | Cross-origin secret read. |
| **Claimed brand subdomain → credential phishing** | **High (context)** | Real-domain phishing; higher if it was a login host. |
| **Bare claimed subdomain, no trust chain (defacement)** | **Low–Medium** | Reputation/defacement only. |
| **Fingerprint only / non-claimable service** | **Info / N-A** | Not exploitable. |

**CVSS / CWE:**
- Standard takeover (defacement/phishing): `AV:N/AC:L/PR:N/UI:N/S:C/C:L/I:L/A:N` → Medium. **CWE-350** (Reliance on Reverse DNS / untrusted inputs) — commonly cited; also **CWE-284** (Improper Access Control) / **CWE-1104** (use of unmaintained third-party components) contextually.
- Cookie-ATO chain: `C:H/I:H` → High–Critical. + **CWE-384** (Session Fixation) / CWE-565 (cookie trust).
- Second-order script-exec (CSP/`<script src>`): → High–Critical. + **CWE-79**.
- NS/MX: → Critical. + **CWE-350** and the email/DNS trust context.
> Note: subdomain takeover has no single perfect CWE; **CWE-350** is the usual anchor. Lead the report with the **impact** (ATO / script-exec / reset interception) and cite the chain CWE alongside.

---

# 18. Impact-Escalation Playbooks — "you found X, now do Y"

### 18.1 You found: *a CNAME to a provider "not found" page*
- **Escalate:** confirm the service is **claimable** (§7) → **claim it** and serve your marker (§8) → check the cookie `Domain` (§10) and whether the host is in any OAuth/CSP/CORS config (§13).
- **Evidence:** your marker at `https://sub.target.com/...` + the trust chain (cookie attr / allow-list entry).
- **Severity:** Low–Medium → High–Critical by chain.

### 18.2 You found: *a claimed subdomain but unsure of impact*
- **Escalate:** does the main app set `Domain=.target.com` cookies? (§10) Is the subdomain referenced in JS/CSP/CORS/OAuth? (§13) Is there an NS/MX angle? (§11)
- **Evidence:** the specific trust that turns control into ATO/script-exec.
- **Severity:** set by the chain found.

### 18.3 You found: *a dangling `NS` delegation*
- **Escalate:** register the nameserver domain / claim the zone → serve DNS → issue a valid TLS cert (DNS-01) → host/mail/verify as the target (§11).
- **Evidence:** the subdomain resolving to your DNS + a benign cert/record you created.
- **Severity:** **Critical**.

### 18.4 You found: *a dangling `MX`*
- **Escalate:** claim the mail service → send yourself a test mail to that host → (safely) demonstrate reset-email routing → ATO potential (§11).
- **Evidence:** a test email received at your claimed mail resource for `mail.target.com`.
- **Severity:** **Critical** (if reset/verification mail routes there).

### 18.5 You found: *the dead subdomain is in the main app's CSP `script-src` / `<script src>`*
- **Escalate:** claim it → host a benign proof script (e.g. a unique `console.log`/beacon) → show it executes on the main app (§13).
- **Evidence:** your script running in the main app's origin (CSP bypass / stored-asset XSS).
- **Severity:** **High–Critical**.

---

# 19. Building a Professional, Safe PoC

```
DO:
  □ Claim the resource in YOUR OWN provider account, with a benign, uniquely-named proof file:
      /st-poc-<random>.txt  -> "subdomain takeover PoC by <handle> for <program> - <UTC timestamp>"
  □ Screenshot https://sub.target.com/<marker> returning YOUR content + the DNS record (dig) + the provider fingerprint.
  □ For NS/MX: prove control with YOUR OWN test cert / a test email you send to yourself. Don't catch real users' mail.
  □ For cookie/OAuth/CSP chains: prove the trust safely (own accounts, benign script/marker, read the cookie ATTRIBUTE,
    catch YOUR OWN OAuth token) - see the CORS/OAuth/XSS kits' safe-PoC rules.
  □ UNPUBLISH the claim / remove the content immediately after capturing evidence. Keep it live only as long as the PoC needs.
  □ In the report, tell them to REMOVE the dangling DNS record (fixing the resource isn't enough - a new dangler can recur).
DON'T:
  □ Host real phishing, malware, or user-targeting content on the claimed subdomain.
  □ Intercept real users' password-reset emails, cookies, or OAuth tokens.
  □ Leave the claim live after reporting (someone malicious could reuse it).
  □ Report a fingerprint you didn't claim, or a non-claimable service, as a takeover.
```
> The single most important restraint: **claim it, serve a benign marker, capture proof, then take it down.** You prove full control without harming anyone. Same discipline as the Recon/Dependency-Confusion kits (benign proof, then unpublish).

**Remediation to include:** **remove the dangling DNS record** the moment a service/resource is decommissioned (make DNS cleanup part of de-provisioning); adopt an **inventory + continuous monitoring** of all DNS records vs live resources (detect danglers automatically); prefer resources that **bind to your account** (don't allow arbitrary re-registration); for critical hosts use **DNS records that can't be silently claimed** (e.g. avoid CNAMEs to shared third-party namespaces where possible); scope cookies **host-only** (not `.target.com`) where feasible; keep OAuth `redirect_uri`, CSP `script-src`, and CORS allow-lists **exact and minimal** so a subdomain takeover doesn't hand over the main app.

---

# 20. Reporting, CWE/CVSS & De-duplication

Use `SUBDOMAIN_TAKEOVER_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "Subdomain takeover of <sub.target.com> (<provider>) → <session ATO | script-exec on main app | reset
                interception | phishing on brand domain>" — name the IMPACT + provider.
2. Severity     CVSS 3.1 vector + score + CWE-350 (+ CWE-384/79/284 by outcome)
3. Asset        exact subdomain + record type + the third-party service it dangles to
4. Summary      the dangling record + that you CLAIMED it + the trust it grants
5. Steps        numbered: dig the record → the provider fingerprint → the claim → your marker served from sub.target.com
6. PoC          screenshot of https://sub.target.com/<marker> (your content) + dig output + the trust chain (cookie/OAuth/NS)
7. Impact       ATO / script-exec on main app / reset interception / brand phishing — the "so what"
8. Remediation  REMOVE the dangling DNS record + inventory/monitoring + exact allow-lists (§19)
```
**De-dup:** one dangling record = one finding. If several subdomains dangle to the **same** misconfigured service/pattern, you *can* file them together (or separately if impact differs) — but a single **root cause** (a decommissioned service left in DNS) is one issue per record. Lead with the highest-impact chain. Don't split "fingerprint" and "claim" — that's one report.

---

# 21. Automation & Red-Team Notes

**Automation (find candidates fast, verify + claim by hand):**
```bash
# 1) enumerate + resolve + fingerprint at scale
subfinder -d target.com -all -silent | dnsx -silent -cname -resp | tee resolved.txt
subzy run --targets resolved.txt --hide_fails
nuclei -l subs.txt -tags takeover -o takeover.txt
python3 poc/subtakeover_scan.py -l subs.txt        # our resolver + fingerprint DB + claimability ranking
# 2) continuous monitoring (recon-to-takeover pipeline): diff CT logs / DNS daily; alert on new danglers.
```
- **Quality gate:** never submit a **fingerprint alone**. Confirm claimability (§7), **claim** it, serve a **benign marker** (§8), and prove the **trust chain** (cookie/OAuth/CSP/NS/MX) — then **unpublish** (§19). Automated "vulnerable to takeover" output is a *lead*, not a report.

**Red-team angles:**
```
□ NS takeover of a subdomain → valid TLS cert → indistinguishable phishing/C2 on the real brand domain.
□ Second-order: claim a subdomain in the target's CSP script-src / <script src> → JS execution across the main app → mass session theft.
□ MX takeover → intercept password-reset / MFA / invite mail → account takeover at scale.
□ Cookie-scope abuse: set .target.com cookies from a taken-over subdomain → session fixation / feature-flag / CSRF-token tampering on the main app.
□ Trusted-subdomain redirect: chain with the Open-Redirect kit to launder phishing through a controlled *.target.com host.
□ Staging/dev/CI takeovers: reach internal integrations, webhooks, and secrets baked into the old resource.
□ Recon-to-takeover monitoring: whoever watches CT logs + DNS churn first claims the dangler — automate it (defensively AND offensively).
```

---

# Appendix A — Subdomain-Takeover Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                    SUBDOMAIN TAKEOVER WORKFLOW                      │
├────────────────────────────────────────────────────────────────────┤
│ 0. RECON: enumerate ALL subdomains + resolve every record          │
│    (CNAME/A/NS/MX/TXT); CT logs + historical + brute §3            │
│ 1. BASELINE ★ : which records DANGLE (provider 404 / NXDOMAIN /    │
│    SERVFAIL) AND are CLAIMABLE? §4                                 │
│ 2. DETECT/CONFIRM: record type §5 · fingerprint the service §6 ·   │
│    prove CLAIMABILITY (can you register it?) §7                    │
│ 3. IMPACT ⭐ (claim benignly §8, then map §9):                      │
│    cookie theft → session ATO ................. §10 ⭐⭐            │
│    NS/MX → DNS control / email → reset ATO .... §11 ⭐⭐⭐           │
│    OAuth/CSP/CORS/<script src> trust → main-app §13 ⭐⭐⭐           │
│    credential phishing on the real domain .... §12                │
│    TLS certs / same-site pivot / chain ....... §14                │
│ 4. VALIDATE → REPORT:                                             │
│    FP filter §16 (fingerprint≠claim; non-claimable=Info) ·        │
│    CVSS+CWE-350 §17 · SAFE PoC: benign marker, UNPUBLISH §19 ·     │
│    title = IMPACT + provider, remove the DNS record, dedup §20    │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — Subdomain-Takeover Decision Tree

```
Enumerate subs + resolve records (§3) →
│
├─ Record DANGLES (provider "not found" fingerprint / NXDOMAIN / SERVFAIL)? (§4)
│   │
│   ├─ Service CLAIMABLE (can you register the exact resource)? (§7)
│   │   │  NO → non-claimable → Info / N-A (§16).
│   │   │
│   │   └─ YES → CLAIM it, serve a benign marker from sub.target.com (§8). Confirmed takeover. Now escalate by TRUST:
│   │        │
│   │        ├─ Record is NS? → full DNS control → certs/mail/host → CRITICAL (§11). ⭐
│   │        ├─ Record is MX? → email interception → reset-token capture → ATO. CRITICAL (§11). ⭐
│   │        ├─ Cookies are Domain=.target.com? → read/set victim session → ATO. HIGH–CRIT (§10). ⭐
│   │        ├─ Host in OAuth redirect_uri / CSP script-src / <script src> / CORS? → token theft / script-exec on
│   │        │      the MAIN app → HIGH–CRIT (§13). ⭐
│   │        ├─ Brand only? → credential phishing on the real domain → HIGH (context) (§12).
│   │        └─ No trust chain? → defacement/info → LOW–MEDIUM (§16).
│   │
│   └─ Just a 404 with NO provider fingerprint / still owned? → not dangling → keep hunting.
│
└─ On a THIRD-PARTY domain (not the target's)? → out of scope, not their bug (§16).

ALWAYS: CLAIM to prove it, serve a BENIGN marker, capture evidence, then UNPUBLISH; ask them to REMOVE the DNS record (§19).
```

---

# Appendix C — Important Links & References

**Primary (learn + the service matrix)**
- **`can-i-take-over-xyz`** (EdOverflow) — the canonical per-service "is this fingerprint takeover-able?" matrix: https://github.com/EdOverflow/can-i-take-over-xyz
- OWASP WSTG — *Test for Subdomain Takeover* (WSTG-CONF-10): https://owasp.org/www-project-web-security-testing-guide/
- HackTricks — *Domain/Subdomain takeover*: https://book.hacktricks.xyz/pentesting-web/domain-subdomain-takeover
- PayloadsAllTheThings — *Subdomain takeover* notes.
- PortSwigger / Detectify blog — the foundational subdomain-takeover write-ups.

**Foundational research & real-world**
- Detectify Labs — *"Hostile subdomain takeover"* (Frans Rosén / Detectify — the class-defining research series).
- The **NS/MX** takeover write-ups (full-DNS-control / mail interception) — the highest-impact variants.
- Second-order takeovers via CSP `script-src` / `<script src>` / OAuth `redirect_uri` — numerous HackerOne disclosures.

**Bug-bounty writeups**
- Disclosed HackerOne / Bugcrowd reports — search *"subdomain takeover"*, *"NS takeover"*, *"subdomain takeover to account takeover"*, *"subdomain takeover CSP"*, *"dangling CNAME"*.

**Tools**
- `subfinder` / `amass` / `assetfinder` (enum) · `dnsx` / `massdns` / `dig` (resolve) · `subzy` / `subjack` / `nuclei -tags takeover` (fingerprint) · `crt.sh` / `chaos` (CT/historical) · this kit's `poc/` (subtakeover_scan / fingerprints / claim_proof).

**CWE / standards to cite**
- **CWE-350** (Reliance on Reverse DNS Resolution / untrusted external inputs — the usual anchor) · **CWE-284** (Improper Access Control) · **CWE-384** (Session Fixation, cookie chain) · **CWE-79** (second-order script-exec) · **CWE-1104** (unmaintained third-party components): https://cwe.mitre.org/

---

> **Final reminder — the one rule that pays:** *A dangling DNS record is a fingerprint; a subdomain takeover is a **claim**.* Register the dead resource, serve a **benign marker** from `sub.target.com`, and then chain the **trust the hostname carries** — domain-scoped cookies (session ATO), an OAuth/CSP/CORS allow-list entry (token theft / script-exec on the main app), or `NS`/`MX` control (valid certs + reset-email interception → ATO). Confirm claimability first (a fingerprint you can't register is Info), prove control benignly, **unpublish immediately**, and tell them to **remove the record**. That's how a leftover CNAME becomes the Critical it was hiding.
