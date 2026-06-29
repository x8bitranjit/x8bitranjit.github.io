# JavaScript Files — Complete In-Depth Recon-to-Exploit Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Every client-side JavaScript asset the target serves — bundles, chunks, inline scripts, source maps, service workers, third-party SDK configs, old/archived JS — mined for **secrets, hidden endpoints, parameters, DOM sinks, and logic** that escalate to real bugs
**Platforms:** Kali/Linux first-class; Windows/WSL notes provided
**Companion files in this folder:**
- `JS_FILES_ARSENAL.md` — secret regexes, endpoint/param extraction one-liners, DOM-sink grep set, source-map recovery (copy-paste)
- `JS_FILES_CHECKLIST.md` — the testing-order checklist you tick per app
- `JS_FILES_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — runnable tooling (JS harvester, secret scanner, endpoint extractor, source-map unpacker, DOM-sink finder)

> **Companion to the Recon / XSS / SSRF / JWT / CORS / FileUpload guides.** JS analysis is the **force-multiplier that feeds every other kit.** A single bundle can hand you: a live cloud key (→ SSRF kit impact / RCE), an undocumented admin API (→ IDOR/authz), a DOM-XSS sink (→ XSS kit), a hardcoded JWT secret (→ JWT kit), an internal hostname (→ SSRF), or a source map that reverses the **entire** frontend. The mistake hunters make is treating "I found a JS file" as the finding. The finding is **the secret/endpoint/sink inside it and what it unlocks.** Read Part III before you report a regex match.

---

> ### ⚡ READ THIS FIRST — why most "I found a secret in JS" reports underpay (or get closed)
> 1. **A regex match is not a finding. A *live, privileged* secret is.** `apiKey: "AIza…"` in a bundle is usually a **client-side, domain-restricted, intentionally-public** key (Google Maps, Firebase web config, Stripe **publishable** key, Sentry DSN). Reporting those is the #1 way to get closed as Informational. The bounty is a key that **actually authenticates and does something** — a cloud secret, a server/secret API key, a CI token, a private signing secret. **Always validate the key works and is privileged** before reporting (§11).
> 2. **The highest-value JS output isn't a secret — it's a map of the *hidden attack surface*.** Bundles enumerate **every** API route, parameter, feature flag, role, and admin path the app *can* call — including ones not reachable in the UI. That list feeds IDOR, authz, SSRF, and injection testing across the other kits (§7).
> 3. **Source maps reverse the whole frontend.** A reachable `.map` (or webpack `sourcesContent`) reconstructs original, commented TypeScript/JSX — variable names, dead admin code, secret comments. Always look for `//# sourceMappingURL=` and try `<bundle>.map` (§9).
> 4. **Client-side sinks are server-independent bugs.** `innerHTML`, `eval`, `document.write`, `location =`, `postMessage` handlers, `dangerouslySetInnerHTML`, and `__proto__` flows are **DOM-XSS / prototype-pollution** bugs you find by reading JS, not by fuzzing the server (§12/§13).
> 5. **Old JS is gold.** Wayback/historical bundles contain **rotated-but-still-live** keys, removed endpoints that still work, and pre-fix vulnerable code. Always diff current vs archived JS (§3).
>
> **Where the money is (memorize this order):** ① **live privileged secret (cloud key / server API key / CI token / signing secret) → cloud takeover / RCE / supply-chain (Critical)** → ② **DOM XSS from a JS sink → account takeover (High)** → ③ **prototype pollution → DOM-XSS/RCE-gadget chain (High)** → ④ **hidden admin/internal endpoint → IDOR/authz/SSRF (varies)** → ⑤ *then* low-priv/public keys, source-map "info", and endpoint lists as **leads, not headline findings**.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — HARVEST & MAP**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [Why JS Analysis Pays — Anatomy of the Attack Surface](#2-why-js-analysis-pays)
3. [Harvesting Every JS File (current + historical + chunks)](#3-harvesting-every-js-file)
4. [Deobfuscation, Beautify & Bundle Structure](#4-deobfuscation-beautify--bundle-structure)

**PART II — EXTRACT (the four veins of gold)**
5. [Secret & Credential Extraction](#5-secret--credential-extraction)
6. [Endpoint, Route & Parameter Extraction](#6-endpoint-route--parameter-extraction)
7. [Mapping Hidden Attack Surface (routes, roles, flags)](#7-mapping-hidden-attack-surface)
8. [Client-Side Sink Discovery (DOM-XSS, postMessage, proto-pollution)](#8-client-side-sink-discovery)
9. [Source Maps — Reversing the Whole Frontend](#9-source-maps--reversing-the-whole-frontend)

**PART III — EXPLOITATION BY IMPACT (where the money is)**
10. [Validating Secrets — Live? Privileged? Scope?](#10-validating-secrets)
11. [Secret → Cloud Takeover / RCE / Supply-Chain (Critical)](#11-secret--cloud-takeover--rce--supply-chain)
12. [JS Sink → DOM XSS → Account Takeover](#12-js-sink--dom-xss--account-takeover)
13. [Prototype Pollution → DOM-XSS / RCE Gadget](#13-prototype-pollution--gadget)
14. [Hidden Endpoints → IDOR / Authz / SSRF / Injection](#14-hidden-endpoints--idor--authz--ssrf--injection)
15. [Chaining JS Findings Across Kits](#15-chaining-js-findings-across-kits)

**PART IV — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
16. [The Validity-First Mindset](#16-the-validity-first-mindset)
17. [False Positives — STOP reporting these](#17-false-positives--stop-reporting-these-auto-reject-list)
18. [Severity Calibration](#18-severity-calibration--how-triagers-really-rate-js-findings)
19. [Impact-Escalation Playbooks — "you found X, now do Y"](#19-impact-escalation-playbooks--you-found-x-now-do-y)
20. [Building a Professional, Safe PoC](#20-building-a-professional-safe-poc)
21. [Reporting, CWE/CVSS & De-duplication](#21-reporting-cwecvss--de-duplication)
22. [Automation & Red-Team Notes](#22-automation--red-team-notes)

**Appendices**
- [Appendix A — JS Recon Workflow Cheat Sheet](#appendix-a--js-recon-workflow-cheat-sheet)
- [Appendix B — JS Finding Decision Tree](#appendix-b--js-finding-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Each phase says *what to do*, *which § for detail*, and the *deliverable*.

```
PHASE 0  HARVEST          → pull EVERY JS file: live bundles + chunks + inline + historical(wayback) + source maps (§3)
PHASE 1  BEAUTIFY/STRUCT  → beautify/deobfuscate; understand the bundle (webpack chunks, lazy routes, env config) (§4)
PHASE 2  EXTRACT  ★       → mine the four veins: secrets (§5) · endpoints/params (§6) · hidden surface (§7) · sinks (§8)
PHASE 3  RECOVER          → recover source via .map / sourcesContent (commented original code, dead admin code) (§9)
PHASE 4  VALIDATE+IMPACT ⭐→ turn matches into harm:
                            validate secret live+privileged (§10) → cloud/RCE/supply-chain (§11) ·
                            sink → DOM XSS → ATO (§12) · proto-pollution gadget (§13) · hidden endpoint → IDOR/SSRF (§14)
PHASE 5  VALIDATE→REPORT  → validity (§16) · false-positive filter (§17) · severity+CWE (§18) ·
                            SAFE PoC (§20) · dedup (§21) · report template
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Harvest.** Collect **every** JS asset: linked bundles, dynamically-loaded chunks, inline scripts, service workers, third-party SDK configs — plus **historical** copies from Wayback and `.map` files (§3). *Deliverable:* a local corpus of all JS (current + archived).
2. **PHASE 1 — Beautify/structure.** Beautify and deobfuscate; identify webpack runtime, chunk manifest, lazy-loaded route bundles, and the env/config object (§4). *Deliverable:* readable JS + a model of how the app is wired.
3. **PHASE 2 — Extract ⭐.** Run all four extractors over the corpus: **secrets** (§5), **endpoints/params** (§6), **hidden surface** (routes/roles/flags, §7), **DOM sinks** (§8). *Deliverable:* four tagged lists.
4. **PHASE 3 — Recover.** Pull `.map`/`sourcesContent` to reconstruct original commented source; read for secret comments, dead admin code, and logic (§9). *Deliverable:* recovered source tree.
5. **PHASE 4 — Validate + impact ⭐.** Convert leads into demonstrated bugs: validate each secret is **live + privileged** (§10) then push to cloud/RCE/supply-chain (§11); turn a sink into DOM XSS → ATO (§12); proto-pollution gadget (§13); hidden endpoint → IDOR/authz/SSRF/injection (§14). *Deliverable:* a demonstrated, highest-impact bug.
6. **PHASE 5 — Validate → report.** Apply validity & false-positive filters (§16/§17), set a defensible CVSS/CWE (§18), build a clean *safe* PoC (§20), de-dup, write it up (§21). *Deliverable:* the submitted report.

Reference anytime: payloads → `JS_FILES_ARSENAL.md`; checklist → `JS_FILES_CHECKLIST.md`; scripts → `poc/`; playbooks **§19**.

---

# PART I — HARVEST & MAP

# 1. Environment & Tooling Setup

| Tool | Job |
|------|-----|
| **Burp Suite** | capture all JS the app loads (proxy history → filter `.js`); replay; the core tool |
| **katana / gau / waybackurls / hakrawler** | crawl + pull current **and historical** JS URLs |
| **`poc/js_harvest.sh`** | download every JS (live + wayback + chunk manifest) into a local corpus |
| **js-beautify / prettier** | un-minify bundles into readable code |
| **`poc/secret_scan.py`** | severity-ranked secret regexes with entropy gating (low FP) |
| **`poc/endpoints.py` / LinkFinder / xnLinkFinder** | extract endpoints/paths/params from JS |
| **`poc/sourcemap_unpack.py` / unwebpack-sourcemap** | reconstruct original source from `.map` |
| **`poc/dom_sinks.py` / DOMDig / dom-based grep** | locate DOM-XSS / postMessage / proto-pollution sinks |
| **TruffleHog / gitleaks** | verified-secret scanning (some sources/keys are auto-validated) |
| **nuclei** (`-tags exposure,token`) | templated exposed-secret / source-map checks |
| **Chrome DevTools** | "Sources" panel auto-loads `.map`; "Coverage" finds live code paths |

```bash
# Kali/WSL — harvest everything, then mine
bash poc/js_harvest.sh target.com out/js
python3 poc/secret_scan.py -d out/js -o secrets.txt
python3 poc/endpoints.py  -d out/js -o endpoints.txt
python3 poc/dom_sinks.py  -d out/js -o sinks.txt
python3 poc/sourcemap_unpack.py -u https://target.com/static/js/main.abc123.js.map -o out/src
```
> **Windows:** drive Burp/Chrome on Windows; run the Python/bash `poc/` helpers and the Go crawlers in **WSL**.

---

# 2. Why JS Analysis Pays

## 2.1 The frontend ships you the backend's blueprint
Modern SPAs bundle the **entire** client logic — every API call, route, role check, feature flag, and sometimes config/secrets — into JS the server hands to anyone. Reading it is **white-box recon on a black-box target**.

## 2.2 The four veins of gold
```
1. SECRETS      → keys/tokens/creds hardcoded or in env config → cloud/RCE/supply-chain when LIVE + PRIVILEGED (§5/§11).
2. ENDPOINTS    → every API path + parameter the app can call, incl. undocumented/admin/internal ones (§6/§7).
3. SINKS        → client-side dangerous flows → DOM-XSS / prototype pollution / open redirect (§8/§12/§13).
4. SOURCE       → .map recovery → original commented code, dead admin features, secret comments (§9).
```

## 2.3 Why it out-impacts surface testing
- **It reveals what you can't see.** Hidden endpoints/params/roles → targeted IDOR & authz the UI never exposes.
- **It hands you pre-auth secrets.** One live cloud key skips the whole exploitation chain to **Critical**.
- **It's server-bug-independent.** DOM XSS and prototype pollution live entirely in the JS — no server cooperation needed.

> **The mental model:** the bundle is the application's **source code, leaked by design.** Your job is to read it like a developer and a thief at once — what runs, what's secret, what's reachable, and what's exploitable.

---

# 3. Harvesting Every JS File

Miss a file, miss the bug. Pull from **every** source.

```
□ Live, linked bundles:       view-source + proxy history; <script src>; preload/modulepreload; importmap.
□ Dynamic chunks:             webpack/Vite lazy chunks (read the runtime/manifest for chunk names); load every route.
□ Inline scripts:             <script>…</script> in HTML (often holds config/keys/CSRF tokens).
□ Service workers:            /sw.js, /service-worker.js — cache lists reveal more URLs/endpoints.
□ Third-party SDK config:     analytics/maps/payment SDK init blocks (project IDs, sometimes server keys).
□ Historical/archived:        gau/waybackurls → OLD bundles (rotated-but-live keys, removed endpoints). ⭐
□ Source maps:                //# sourceMappingURL= ; try <bundle>.js.map even if not referenced (§9).
□ Sub-resources:              CDN/asset hosts; *.target.com bundles (each app/subdomain has its own).
□ JSON/config endpoints:      /config.js /env.js /settings.json /manifest.json /.well-known/* (runtime config).
```
```bash
# pull current + historical JS
katana -u https://target.com -d 3 -jc -silent | grep -Ei '\.js(\?|$)' | anew js_urls.txt
echo target.com | gau --subs | grep -Ei '\.js(\?|$)' | anew js_urls.txt
echo target.com | waybackurls | grep -Ei '\.js(\?|$)' | anew js_urls.txt
# walk webpack chunks from the manifest (after loading the app in Chrome, grab chunk names)
# then download all of them
while read u; do curl -s "$u" -o "out/js/$(echo "$u"|md5sum|cut -c1-12).js"; done < js_urls.txt
```

> **If this → then that:** the app is a webpack/Vite SPA → load **every route** in Chrome (or read the chunk manifest) so lazy chunks download — the **admin** chunk (only loaded for admins) often contains the juiciest endpoints/flags and ships to everyone. Diff **historical** bundles against current — removed code/keys frequently still work (§16).

---

# 4. Deobfuscation, Beautify & Bundle Structure

## 4.1 Beautify & deobfuscate
```
□ Beautify:        js-beautify / prettier on every file (minified → readable). DevTools "{}" pretty-print for a quick look.
□ De-obfuscate:    webcrack (best for webpack + obfuscator.io), de4js, synchrony, REstringer, relativeci — recover
                   names, fold the string-array, undo control-flow flattening, unpack `eval`/packed payloads.
□ String-array (obfuscator.io): the decoder function + rotated string array sit near the top — let webcrack/synchrony
                   resolve them; then endpoints/keys become readable instead of `_0x4f2a[12]`.
□ AST grep:        use `ast-grep`/Esprima/Acorn to find `fetch(`, `require(`, sink calls structurally (beats regex).
```

## 4.2 Walk the bundle internals (webpack / Vite / Rollup / Parcel)
```
□ Runtime + manifest: find the webpack runtime (`__webpack_require__`, `webpackJsonp`/`self.webpackChunk...`) and the
                   chunk MANIFEST that maps chunkId → filename (e.g. `{12:"admin.4f2a.js", ...}`). It lists EVERY chunk —
                   including ones the UI never loads (admin/internal). Fetch them all (don't rely on what loads at runtime).
□ Module map:       modules are keyed by id/path; the path comments (or source map) reveal the original file tree.
□ Env/config object: window.__ENV__ / window.__CONFIG__ / process.env.* inlined / a `config={...}` near the top / a
                   runtime /env.js or /config.json → base URLs, feature flags, keys. Read this FIRST.
□ Route table:      React Router/Vue Router/Angular `RouterModule.forRoot([...])` → the full route list incl. admin/internal.
□ Vite:             `import.meta.env.*` inlined; `manifest.json` (build) maps entries→chunks; dynamic-import chunk names.
□ Import maps / ESM: <script type="importmap"> and dynamic `import()` reveal more module URLs to pull.
```

## 4.3 Dynamic analysis (when static is fiddly) & DOM-XSS aids
```
□ DevTools: "Sources" auto-loads .map (read original); "Coverage" shows which code actually ran; "Network" reveals the
            real API calls + auth headers; set XHR/`fetch` breakpoints; "Search all files" for a secret/endpoint string.
□ Burp DOM Invader (built into Burp's browser): auto-finds source→sink DOM-XSS flows + vulnerable postMessage handlers —
            the fastest way to confirm a DOM sink fires (guide §8/§12).
□ Trusted Types / CSP note: if `Content-Security-Policy: require-trusted-types-for 'script'` is enforced, naive
            `innerHTML` sinks throw instead of executing — you then need a Trusted-Types-policy bypass or a different sink;
            absence of Trusted Types means classic DOM XSS is in play. Always check the CSP before declaring a sink dead.
```

## 4.4 Other JS assets people forget (each is its own corpus)
```
□ Service worker (/sw.js): its precache/route list reveals more URLs/endpoints; it can also be an offline persistence foothold.
□ WASM (.wasm): rare but reachable; `wasm2wat` to read; strings/exports can leak logic/endpoints.
□ Mobile bundles: React Native `index.android.bundle` / `main.jsbundle`, Cordova/Ionic `www/` JS — pulled from the APK/IPA
            (winiapk tooling) — these hold endpoints/keys not in the web app.
□ Dependency confusion: read package names from the bundle / `package.json` / `//# sourceMappingURL` paths — an internal
            scoped package (`@target/...`) not on the public registry → you may publish it → supply-chain RCE in their build.
□ Embedded API specs: a swagger/openapi JSON or a full GraphQL schema is sometimes inlined → instant endpoint map (§6/§14).
```
> Reading the **config/env object** first is the fastest path to secrets and base URLs. Reading the **chunk manifest +
> route table** first is the fastest path to hidden admin/internal surface. Pull **every chunk from the manifest** (not
> just what the UI loads) and re-mine after deobfuscation/source-map recovery (§9) — that's where the best leads hide.

---

# PART II — EXTRACT (the four veins of gold)

> Full regex/one-liner sets are in `JS_FILES_ARSENAL.md`. These sections teach what to look for and how to triage it.

# 5. Secret & Credential Extraction

Grep the corpus for high-signal patterns, then **entropy-gate** to cut noise (random-looking long strings).
```
HIGH-VALUE (validate live — §10):
  AWS:           AKIA[0-9A-Z]{16}  (+ a 40-char secret nearby)  · ASIA… (temp)  · aws_secret_access_key
  GCP:           "private_key": "-----BEGIN PRIVATE KEY-----"  · service-account JSON  · AIza… (check scope!)
  Azure:         AccountKey=  · client_secret  · SharedAccessSignature  sig=
  Private keys:  -----BEGIN (RSA|EC|OPENSSH|PGP) PRIVATE KEY-----
  CI/VCS:        ghp_… gho_… ghs_… github_pat_…  · glpat-…  · Jenkins/CircleCI tokens
  Server keys:   Stripe SECRET sk_live_…  · Twilio AC…:…  · SendGrid SG.…  · Slack xoxb/xoxp…  · Mailgun key-…
  Signing:       jwt secret / HMAC secret in config  · cookie/session signing secret  · webhook signing secret
  DB/infra:      mongodb://user:pass@…  · postgres://…  · redis://…  · amqp://…  · internal hostnames/IPs
LOW-VALUE (usually Info — don't lead with these — §17):
  Google Maps / Firebase web apiKey (AIza…, domain-restricted, public by design)
  Stripe PUBLISHABLE pk_live_…  · Sentry DSN  · public reCAPTCHA site key  · GA/segment write keys
```
**Triage each hit:** *Is it a server-side secret or a public client key? Is it live? What can it do?* (→ §10).

> **If this → then that:** you find `AKIA…` + a 40-char string, or a `BEGIN PRIVATE KEY`, or `sk_live_`/`ghp_`/`glpat-` → **stop grepping and validate it** (§10). A live one of these is a **Critical** on its own and may reach **RCE** (§11). A bare `AIza…`/`pk_live_`/Sentry-DSN → note it, keep moving; it's usually Info (§17).

---

# 6. Endpoint, Route & Parameter Extraction

The bundle lists the API. Extract it all.
```
□ Paths/URLs:    "/api/...", `${base}/v2/...`, axios/fetch/XHR string args, GraphQL operation strings.
□ Parameters:    object keys passed to API calls; query-string builders; form field names; GraphQL variables.
□ Base URLs:     api base, internal hostnames, staging/dev hosts, CDN/upload endpoints, websocket URLs.
□ HTTP verbs:    method per route (GET/POST/PUT/DELETE) — reveals state-changing endpoints to authz-test.
□ Auth headers:  where Authorization/x-api-key/cookies are attached → which endpoints are credentialed (→ CORS kit).
```
```bash
# quick extraction (LinkFinder-style)
grep -RhoE "(https?:)?//[a-zA-Z0-9./?=_%:-]+|/[a-zA-Z0-9_./-]{2,}\?[a-zA-Z0-9_=&%-]+|/api/[a-zA-Z0-9_./-]+" out/js \
  | sort -u > endpoints.txt
python3 poc/endpoints.py -d out/js -o endpoints.txt   # smarter (handles template literals + param names)
```
> **If this → then that:** you extracted endpoints the UI never calls (e.g. `/api/admin/users/{id}/impersonate`, `/internal/...`) → these are prime **IDOR/authz** and **SSRF** targets (§14). Endpoints that attach `Authorization` + relax CORS → take them to the **CORS kit**. Every extracted **parameter** is fuzz fodder for the XSS/SQLi/SSRF/LFI kits.

---

# 7. Mapping Hidden Attack Surface (routes, roles, flags)

Beyond endpoints, bundles encode the app's **logic and gates** — exactly what to attack.
```
□ Route table:    every SPA route incl. /admin, /internal, /debug, /impersonate, role-gated routes.
□ Role/permission checks:  `if (user.role === 'admin')`, `hasPermission('billing:write')` → enumerate roles & perms.
□ Feature flags:  flag names + default values → toggle/abuse hidden features; flags often gate unfinished, weak code.
□ Client-side authz:  ANY access control done only in JS = bypassable by calling the API directly (high-yield IDOR/authz).
□ Hidden params:   debug=true, isAdmin, impersonate, internal, bypass — values the client can send.
□ Validation rules: regexes/limits enforced client-side → send the raw value server-side to test if it's enforced there.
```
> **If this → then that:** you see access control implemented **only in JavaScript** (`if(isAdmin) showAdminPanel()`) with no evidence of server enforcement → call the underlying admin API **directly** with a normal account. If it works, that's a **broken-access-control / privilege-escalation** finding (often High) — the JS *told you exactly* which call to make. Cross-ref the IDOR/authz methodology.

---

# 8. Client-Side Sink Discovery (DOM-XSS, postMessage, proto-pollution)

Read JS for dangerous flows from a **source** (attacker-controllable input) to a **sink** (dangerous execution).
```
SOURCES (attacker-controllable):
  location.*, document.URL, document.referrer, window.name, document.cookie,
  postMessage event.data, localStorage/sessionStorage, URLSearchParams, hash/query
SINKS (dangerous):
  DOM-XSS:        innerHTML, outerHTML, document.write/writeln, insertAdjacentHTML, eval, setTimeout/setInterval(string),
                  Function(), $.html(), dangerouslySetInnerHTML, jQuery $(userInput), Range.createContextualFragment
  Redirect:       location = / location.href = / location.assign/replace, window.open (open redirect → OAuth theft)
  postMessage:    addEventListener('message', …) WITHOUT origin check → cross-origin DOM-XSS / data theft
  Proto-pollution: recursive merge/extend/clone, lodash.merge, query-string parsers writing __proto__ (§13)
  Code load:      import(userControlled), script.src = userControlled, jsonp callback param
```
```bash
python3 poc/dom_sinks.py -d out/js -o sinks.txt   # flags source→sink proximity, ranks by exploitability
```
> **If this → then that:** a sink like `el.innerHTML = location.hash.slice(1)` or a `message` handler with **no `event.origin` check** → you likely have **DOM XSS** (§12). Trace the source to confirm attacker control and a context where script runs. A `merge(target, JSON.parse(location.hash))` pattern → test **prototype pollution** (§13).

---

# 9. Source Maps — Reversing the Whole Frontend

A reachable source map reconstructs the **original** TypeScript/JSX — names, comments, and code the minifier stripped. This is the single biggest "info" win and often contains secret comments + dead admin code.
```
□ Find it:   //# sourceMappingURL=main.abc.js.map  at the end of a bundle. Even if absent, TRY <bundle>.js.map.
□ Fetch it:  curl -s https://target.com/static/js/main.abc.js.map -o main.map  → it's JSON with "sourcesContent".
□ Unpack:    poc/sourcemap_unpack.py rebuilds the original src/ tree from sourcesContent.
□ DevTools:  Chrome auto-loads .map → the "Sources" panel shows original files directly.
□ Read for:  // TODO secrets, commented creds, internal URLs, dead /admin code, role logic, crypto/signing details.
```
```bash
python3 poc/sourcemap_unpack.py -u https://target.com/static/js/main.abc123.js.map -o out/src
grep -RiE "(password|secret|token|api[_-]?key|internal|admin|TODO|FIXME|HACK)" out/src
```
> **If this → then that:** `.map` is reachable in **production** → unpack the full source, then re-run the secret/endpoint/sink extractors over the **original** code (far higher signal than the minified bundle). Exposed prod source maps are themselves often a valid (Low–Medium) info-disclosure finding, but their real value is **everything they reveal** for the other kits.

---

# PART III — EXPLOITATION BY IMPACT (where the money is)

> Validate live secrets **read-only** and use **your own** accounts/tenants for any code-exec proof (§20).

# 10. Validating Secrets — Live? Privileged? Scope?

Never report a raw match. Answer three questions first:
```
1. LIVE?       Does it authenticate right now? (a single, read-only, minimal API call.)
2. PRIVILEGED? Is it a server/secret key, or a public client key restricted by design?
3. SCOPE?      What can it actually do — read? write? admin? cross-tenant?
```
Read-only liveness checks (benign):
```bash
# AWS (the gold standard non-destructive proof)
AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… aws sts get-caller-identity     # proves live + shows principal. STOP.
# GitHub token
curl -s -H "Authorization: token ghp_…" https://api.github.com/user           # shows the account + scopes
# GitLab
curl -s -H "PRIVATE-TOKEN: glpat-…" https://gitlab.com/api/v4/user
# Stripe secret (read-only)
curl -s https://api.stripe.com/v1/balance -u sk_live_…:                        # 200 = live SECRET key (vs pk_)
# Slack
curl -s -d token=xoxb-… https://slack.com/api/auth.test
# Generic: does the key’s own “whoami”/balance/account endpoint return 200 with identity?
```
> **The validation rule:** *prove the key works with the most minimal, read-only call that returns identity/scope, then stop.* `get-caller-identity`, `/user`, `/balance` are perfect — they demonstrate Critical without touching real data. Do **not** enumerate buckets, read customer data, or push commits to prove it (§20).

---

# 11. Secret → Cloud Takeover / RCE / Supply-Chain (Critical) ⭐

A validated, privileged secret is the highest JS outcome — and frequently a **shell**:
```
□ CLOUD KEY (AWS/GCP/Azure, live + privileged):
     → assume identity → a compute/SSM/Cloud-Function/Run-Command surface → REMOTE SHELL on cloud infra → RCE. CRITICAL
     (Prove with sts get-caller-identity / token introspection, then STOP. SSRF kit §11/§23 has the discipline.)
□ SERVER API KEY with code/deploy/admin scope:
     → an admin/deploy/import/template feature that runs code or uploads files → web shell → RCE. CRITICAL
□ CI / SOURCE-CONTROL TOKEN (ghp_/glpat-/Jenkins):
     → push a malicious pipeline/Action/commit → code execution on build agents → SUPPLY-CHAIN RCE. CRITICAL
□ PRIVATE SIGNING SECRET (JWT/HMAC/cookie/webhook):
     → forge tokens/sessions (→ JWT kit) → auth bypass / privilege escalation / forged webhooks. HIGH–CRITICAL
□ DB/INFRA URI with creds (mongodb://user:pass@host):
     → if the host is reachable (directly or via SSRF), authenticate → data theft; some DBs → RCE. HIGH–CRITICAL
```
> **The JS→RCE rule:** *a leaked secret is "info disclosure" until it grants code execution — then it's Critical.* Always ask "**does this key let me run a command, push code, or forge auth?**" A live cloud key (→ cloud shell), a CI token (→ pipeline RCE), or a server admin key (→ admin code-exec feature) turns a regex match into a **Critical RCE/shell**. Demonstrate code-exec **only on your own test tenant/repo**, validate live creds read-only, and stop (§20).

---

# 12. JS Sink → DOM XSS → Account Takeover

A confirmed source→sink flow is **DOM XSS**, exploitable with no server bug.
```
1. Confirm control:   attacker-controlled source (hash/query/postMessage/window.name) reaches a script-executing sink.
2. Build the payload: break into the context the sink renders (HTML → <img src=x onerror=…>; JS string → '-alert()-';
                      attribute → " onmouseover=…). Benign marker first: alert(document.domain).
3. Prove impact:      steal the session cookie/token (own account), perform an authenticated action, or hijack the
                      session → ACCOUNT TAKEOVER. (Cross-ref the XSS kit for weaponization + CSP bypass.)
```
postMessage DOM-XSS (very common, often missed):
```js
// vulnerable: no origin check, data flows to a sink
window.addEventListener('message', e => { document.getElementById('x').innerHTML = e.data; });
// attacker page:
victimFrame.postMessage('<img src=x onerror=alert(document.domain)>', '*');
```
> **If this → then that:** a `message` handler with **no `event.origin` check** whose `event.data` reaches `innerHTML`/`eval` → cross-origin DOM XSS: any site that frames or opens the target can run script in it → **account takeover**. This is one of the highest-value JS-only bugs; pair it with the XSS kit's cookie/token-theft PoC.

---

# 13. Prototype Pollution → DOM-XSS / RCE Gadget

When user input writes to `__proto__`/`constructor.prototype`, you taint **every** object — then a "gadget" elsewhere turns that into XSS (client) or even RCE (server-side JS / Node).
```
□ Find the sink:   recursive merge/clone/extend, lodash.merge/defaultsDeep, jQuery.extend(true,…), query-string
                   parsers (qs, deparam) that write nested keys from user input.
□ Pollute:         ?__proto__[x]=y  · #__proto__[innerHTML]=<img...>  · JSON {"__proto__":{"x":"y"}} into a merge.
□ Confirm:         ({}).x === 'y'  in console after the pollution.
□ Gadget → XSS:    a library that reads an undefined config off a plain object (e.g. a template/sanitizer option)
                   and you polluted it to inject markup/script → DOM XSS.
□ Gadget → RCE:    server-side (Node) prototype pollution + a gadget reaching child_process/template/`require`
                   → REMOTE CODE EXECUTION. (Several known CVEs; check the app's libs/versions.)
```
> **If this → then that:** confirmed client-side prototype pollution + a known gadget in the app's libraries → DOM XSS (High). Confirmed **server-side** prototype pollution (a JSON body merged into config) + a Node gadget → **RCE** (Critical). Identify the vulnerable library/version from the JS to find the right gadget.

---

# 14. Hidden Endpoints → IDOR / Authz / SSRF / Injection

The endpoint/param lists (§6/§7) are a targeting list for the other kits.
```
□ IDOR/BOLA:     call extracted object-scoped endpoints (/api/users/{id}, /orders/{id}) with your account but
                 another id → read/modify others' data. (The bundle gave you the exact route + id param.)
□ Broken authz:  call admin/internal endpoints (§7) directly with a low-priv account → privilege escalation.
□ SSRF:          endpoints taking a URL/host param (from §6) → SSRF kit.
□ Injection:     every extracted parameter → XSS/SQLi/SSTI/LFI/cmdi per the matching kit.
□ Mass assignment: object keys the client sends (from §6) → add isAdmin/role/verified to the body and resubmit.
□ Undocumented API versions: /api/v1 vs /v2 mentioned in old JS → old version may lack the new authz checks.
```
> **If this → then that:** the bundle exposes `/api/admin/...` plus the request shape → test it directly with a normal account (authz) and with other users' ids (IDOR). JS recon's payoff is that it **removes the guesswork** — you attack the exact route, verb, and parameters the developers built.

---

# 15. Chaining JS Findings Across Kits

JS analysis is the hub; every spoke is another kit:
```
□ Live cloud key (§11)        → SSRF kit impact / direct cloud RCE.
□ JWT secret / weak alg (§5)   → JWT kit (forge tokens → ATO).
□ Credentialed endpoint (§6)   → CORS kit (cross-origin secret theft).
□ Upload endpoint + rules (§6) → FileUpload kit (web shell).
□ URL/host param (§6)          → SSRF kit.
□ DOM sink (§8)                → XSS kit (weaponize, CSP bypass).
□ Hidden admin route (§7)      → IDOR/authz/privilege escalation.
□ Source map (§9)              → re-run ALL extractors over recovered original source (higher signal).
□ Internal hostnames/IPs (§5)  → SSRF target list / scope expansion.
```
> **If this → then that:** treat every JS finding as an **input to another kit**, not an endpoint. The biggest payouts are JS-sourced chains: *bundle → live secret → cloud RCE*, or *bundle → hidden admin API → IDOR → mass account access*.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 16. The Validity-First Mindset

## 16.1 The four questions a triager asks (answer them in your report)
1. **Is the artifact attacker-usable?** A *live, privileged* secret / a *confirmed* sink / a *reachable* hidden endpoint — not a public key or an unreachable code path.
2. **What concrete impact?** Cloud RCE, ATO via DOM XSS, privilege escalation via hidden API, data theft — name it and demonstrate it.
3. **What does the attacker need?** Often just the public JS (pre-auth) → low bar = higher severity.
4. **Reproducible & in scope?** The exact file/URL, the line/match, and a working PoC (validated secret / firing XSS / successful authz call).

## 16.2 The "match vs impact" rule (most important)
| You have | Standalone verdict | Becomes valuable when… |
|---|---|---|
| A regex secret match | Nothing yet | …it's **validated live + privileged** (§10) → then High/Critical (§11). |
| A public client key (AIza/pk_live/Sentry DSN) | Info | …rarely — only if it grants unintended privileged access. |
| An endpoint list | Recon, Info | …a specific endpoint yields IDOR/authz/SSRF/injection (§14). |
| A DOM sink | Potential | …you **prove** the source→sink flow fires script (DOM XSS, §12). |
| Proto-pollution sink | Potential | …a **gadget** turns it into DOM-XSS/RCE (§13). |
| A reachable source map | Low–Medium (info) | …it reveals a validated secret or an exploited endpoint (chain it). |

## 16.3 Production-scope discipline
Confirm on **production** assets. Validate secrets against the **real** service (read-only). For DOM XSS, fire it on the live page. Old/Wayback JS counts only if the secret/endpoint **still works** on production — verify before reporting.

---

# 17. False Positives — STOP reporting these (auto-reject list)

| # | Commonly mis-reported | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **Google Maps / Firebase `AIza…` web key** | Client-side, domain-restricted, public by design. | It's unrestricted/over-scoped and enables billable abuse or data access you can demonstrate. |
| 2 | **Stripe PUBLISHABLE `pk_live_…`** | Meant to be public; can't charge/read. | You actually found the **secret** `sk_live_…` (different key). |
| 3 | **Sentry DSN / GA / Segment write key / reCAPTCHA site key** | Designed to be in client code. | Demonstrable abuse beyond intended (rare). |
| 4 | **A secret match you never validated** | Could be dead/rotated/placeholder/example. | You proved it's **live + privileged** (§10). |
| 5 | **An endpoint list / "I found API routes"** | Recon, not a vuln. | A specific route yields IDOR/authz/SSRF/injection (§14). |
| 6 | **A DOM sink with no controllable source / unreachable** | No exploit path. | You prove a source→sink flow that fires (§12). |
| 7 | **Source map exposed** (alone, no sensitive content) | Often Low/accepted-risk by many programs. | It reveals a validated secret/exploited endpoint, or the program rates it. |
| 8 | **`.js` referencing `/admin` that requires auth & is enforced server-side** | Mentioning a path ≠ access. | The server **doesn't** enforce authz (you called it and it worked). |
| 9 | **Hardcoded localhost/test/example creds** | Not production-usable. | They work against production. |
| 10 | **A third-party CDN/library file's secrets** (not the target's) | Not the target's asset/bug. | It's the target's own bundle/config. |

> Rule of thumb: if you can't say *"this JS gave me `<a live privileged secret / a firing DOM XSS / a working unauthorized API call>` with `<demonstrated impact>`,"* you have a **lead, not a finding.** Validate and exploit before reporting — a wall of regex matches with no validation is the fastest path to "Informational / N/A."

---

# 18. Severity Calibration — how triagers really rate JS findings

| Scenario | Typical alone | Realistic chained | What moves it |
|---|---|---|---|
| **Live privileged cloud key / CI token → RCE/supply-chain** | **Critical** | Critical | Validated + reaches code exec (§11). |
| **Server secret key (sk_live/admin API) live** | **High–Critical** | Critical | Scope: write/admin/cross-tenant. |
| **DOM XSS from a JS sink → ATO** | **High** | High | Confirmed firing + session theft (§12). |
| **Prototype pollution → DOM-XSS (client) / RCE (server)** | **High** | Critical (server) | A working gadget (§13). |
| **Hidden admin/internal endpoint → privilege escalation / IDOR** | **Medium–High** | High | Server doesn't enforce authz (§14). |
| **Private signing secret (JWT/HMAC) live** | **High** | Critical | Forge auth (→ JWT kit). |
| **Exposed prod source map (sensitive content)** | **Low–Medium** | — | What it reveals (chain it). |
| **Public client key / unvalidated match / endpoint list** | **Info** | — | Not a vuln by itself. |

**CVSS / CWE:**
- Live secret in client code: **CWE-798** (Hardcoded Credentials) / **CWE-200/CWE-540** (info exposure via source). Cloud-key→RCE → Critical (~9.x).
- DOM XSS: **CWE-79**; prototype pollution: **CWE-1321**; broken authz via hidden endpoint: **CWE-639/CWE-862**.
- Source map exposure: **CWE-540 / CWE-200**.

---

# 19. Impact-Escalation Playbooks — "you found X, now do Y"

### 19.1 You found: *an AWS/GCP/Azure key in a bundle*
- **Escalate:** validate read-only (`sts get-caller-identity` / token introspection) (§10). If live+privileged → find a run-command surface → **cloud shell/RCE** (§11). STOP at proof of access.
- **Evidence:** the identity/scope output (redacted) + the principal.
- **Severity:** **Critical**.

### 19.2 You found: *a `ghp_`/`glpat-`/CI token*
- **Escalate:** `GET /user` to confirm + read scopes (§10). With write/repo scope → malicious pipeline/Action on your **own** test repo to prove code-exec → supply-chain RCE (§11).
- **Evidence:** account + scopes; the benign pipeline output on your repo.
- **Severity:** **Critical** (write) / High (read).

### 19.3 You found: *a DOM sink (`innerHTML = location.hash`)*
- **Escalate:** craft the context breakout → fire `alert(document.domain)` → then session/token theft on your own account (§12, XSS kit).
- **Evidence:** the firing payload URL + the stolen session proof.
- **Severity:** **High** (ATO).

### 19.4 You found: *a `postMessage` handler with no origin check*
- **Escalate:** an attacker page posts a script payload into the sink → cross-origin DOM XSS (§12).
- **Evidence:** the attacker page firing script in the target.
- **Severity:** **High**.

### 19.5 You found: *hidden `/api/admin/...` endpoints in the bundle*
- **Escalate:** call them directly with a normal account (authz) and with other ids (IDOR) (§14). 
- **Evidence:** the unauthorized action/data returned.
- **Severity:** Medium–High (Critical if admin takeover).

### 19.6 You found: *a reachable source map*
- **Escalate:** unpack the original source (§9), re-run all extractors over it, and chase the **highest** thing it reveals (a validated secret / an exploited endpoint).
- **Evidence:** the recovered secret/endpoint + its exploit; note the map exposure itself.
- **Severity:** the chained finding's severity (map alone Low–Medium).

---

# 20. Building a Professional, Safe PoC

```
DO:
  □ Validate secrets with the MINIMAL read-only call that returns identity/scope (sts get-caller-identity, /user,
    /balance). Screenshot that — it proves Critical without touching real data. Then STOP.
  □ For DOM XSS / proto-pollution: use a benign marker (alert(document.domain) / ({}).polluted===true), then prove
    ATO/RCE on your OWN account/tenant only.
  □ For CI tokens: prove code-exec on a repo/pipeline YOU own, never the target's.
  □ Redact live secret values in the report (show prefix + length + the validation response, mask the rest).
  □ Cite the exact file URL + the matched line/offset, and (for old JS) confirm it still works on production.
DON'T:
  □ Use a live key to read/modify real data, enumerate buckets, push to the target's repos, or rack up billing.
  □ Mass-pull other users' data via a discovered IDOR — one own-vs-own proof is enough.
  □ Fire DOM XSS at real users; don't leave PoC pages live.
  □ Dump a wall of unvalidated regex matches and call it a report.
```
> The single most important restraint: **validate read-only and prove code-exec only on your own assets, then stop.** A `get-caller-identity` line and a redacted key are a complete Critical. Same discipline as the SSRF guide.

**Remediation to include:** never ship server secrets to the client — keep them server-side and proxy; use **publishable/restricted** keys only on the client and lock them to origin/referrer; rotate any leaked key immediately; **don't deploy source maps to production** (or restrict them); add client-side **output encoding/`textContent`** instead of `innerHTML`, validate `event.origin` on every `message` handler; freeze object prototypes / use `Map`/null-proto objects to kill prototype pollution; enforce **authorization server-side** for every endpoint (never trust client-side gates); secret-scan in CI (gitleaks/trufflehog) to prevent regressions.

---

# 21. Reporting, CWE/CVSS & De-duplication

Use `JS_FILES_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "Live AWS credentials in production JS bundle → cloud account compromise / RCE" (name the IMPACT)
2. Severity     CVSS 3.1 vector + score + CWE (798 / 79 / 1321 / 639 / 540 as applicable)
3. Asset        exact JS URL + line/offset (or sink location); for secrets, which key/scope
4. Summary      what the artifact is, that it's live/privileged/reachable, and what it unlocks
5. Steps        numbered: where you found it → the validation/exploit → the impact
6. PoC          validated secret (read-only proof, redacted) / firing DOM XSS / successful unauthorized call
7. Impact       cloud RCE / ATO / privilege escalation / data theft — the "so what"
8. Remediation  keep secrets server-side, restrict client keys, no prod source maps, encode output, enforce authz (§20)
```
**De-dup:** one root cause = one finding. Many regex matches of the **same** key = one report. A DOM sink reachable via several params = one DOM-XSS finding. Don't split "found in JS" from "exploited it" — that's one chain. Separate, genuinely distinct secrets/sinks = separate reports.

---

# 22. Automation & Red-Team Notes

**Automation (find candidates fast, verify by hand):**
```bash
# Harvest + mine in one pass
bash poc/js_harvest.sh target.com out/js
python3 poc/secret_scan.py -d out/js -o secrets.txt        # entropy-gated, severity-ranked
trufflehog filesystem out/js --only-verified                # auto-validates many key types
python3 poc/endpoints.py -d out/js -o endpoints.txt
python3 poc/dom_sinks.py -d out/js -o sinks.txt
nuclei -l js_urls.txt -tags exposure,token -o nuclei_js.txt
# Continuous: re-harvest on deploys; diff new bundles for fresh secrets/endpoints.
```
- **Quality gate:** never submit a scanner's secret match. **Validate live + privileged** (§10), exploit the endpoint/sink (§12–§14), and prove impact safely (§20). A tool's job is to surface candidates; yours is to turn one into a demonstrated Critical.

**Red-team angles:**
```
□ JS-sourced cloud key → assume role → pivot the cloud account (read-only mapping for the report) → RCE surface.
□ CI token from old bundle → poison the pipeline → supply-chain compromise of every downstream deploy.
□ Hidden admin API (from bundle) + missing server authz → silent privilege escalation / mass data access.
□ postMessage DOM-XSS → watering-hole page → ATO of any logged-in visitor (no target XSS needed).
□ Diff historical vs current JS for removed-but-live endpoints/keys and pre-fix vulnerable code.
□ Service-worker / cache manifest → more hidden URLs and an offline persistence foothold.
```

---

# Appendix A — JS Recon Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                      JS FILES WORKFLOW                            │
├────────────────────────────────────────────────────────────────────┤
│ 0. HARVEST: live bundles + chunks + inline + service-worker +      │
│    HISTORICAL(wayback) + source maps  →  local corpus §3           │
│ 1. BEAUTIFY/STRUCT: un-minify; find env/config + router table §4   │
│ 2. EXTRACT ★ (4 veins):                                            │
│    secrets §5 · endpoints/params §6 · hidden surface §7 · sinks §8 │
│ 3. RECOVER: .map / sourcesContent → original source §9             │
│ 4. VALIDATE + IMPACT ⭐:                                            │
│    secret live+privileged §10 → CLOUD/RCE/supply-chain §11 ⭐⭐⭐   │
│    DOM sink → DOM XSS → ATO §12 ⭐⭐                                 │
│    prototype pollution → gadget (XSS/RCE) §13 ⭐                    │
│    hidden endpoint → IDOR/authz/SSRF/injection §14                 │
│ 5. VALIDATE → REPORT:                                              │
│    FP filter §17 (kill public keys) · CVSS+CWE §18                 │
│    SAFE PoC: read-only validate, own-tenant code-exec, redact §20  │
│    title = IMPACT (cloud RCE / ATO), dedup §21                     │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — JS Finding Decision Tree

```
Harvested + extracted the bundle (§3–§8) →
│
├─ Secret match?
│    ├─ public client key (AIza/pk_live/Sentry DSN)? → Info (§17). Move on.
│    └─ server/cloud/CI/signing/DB secret? → VALIDATE read-only (§10) →
│           ├─ live + privileged? → CLOUD/RCE/supply-chain (§11). CRITICAL ⭐
│           └─ dead/rotated/placeholder? → discard.
│
├─ DOM sink with controllable source? → confirm it fires → DOM XSS → ATO (§12). HIGH ⭐
│
├─ Recursive-merge / qs sink? → test prototype pollution → gadget? → DOM-XSS (client) / RCE (server) §13.
│
├─ Hidden endpoint / client-only authz? → call directly (authz) + other ids (IDOR) §14 →
│       works without permission? → privilege escalation / IDOR. MEDIUM–HIGH.
│
├─ Source map reachable? → unpack original source §9 → re-run all extractors → chase the highest reveal.
│
└─ Only endpoint lists / unvalidated matches / public keys? → recon/Info. Validate & exploit before reporting (§17).

ALWAYS: validate live (read-only), prove impact on your OWN assets, name the impact, then report (§20).
```

---

# Appendix C — Important Links

```
LinkFinder (endpoints from JS)            https://github.com/GerbenJavado/LinkFinder
xnLinkFinder                              https://github.com/xnl-h4ck3r/xnLinkFinder
JSluice (endpoints+secrets from JS)       https://github.com/BishopFox/jsluice
unwebpack-sourcemap (.map recovery)       https://github.com/rarecoil/unwebpack-sourcemap
webcrack (webpack/obfuscator deobfuscate) https://github.com/j4k0xb/webcrack
synchrony (deobfuscator)                  https://github.com/relative/synchrony
TruffleHog (verified secrets)             https://github.com/trufflesecurity/trufflehog
gitleaks                                  https://github.com/gitleaks/gitleaks
Burp DOM Invader (DOM-XSS/postMessage)    https://portswigger.net/burp/documentation/desktop/tools/dom-invader
PortSwigger — DOM-based XSS               https://portswigger.net/web-security/dom-based
PortSwigger — Prototype pollution         https://portswigger.net/web-security/prototype-pollution
PortSwigger — Web Cache / source-map disclosure & "Stealing secrets from JS"
PayloadsAllTheThings — Prototype Pollution https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Prototype%20Pollution
HackTricks — PostMessage / Prototype pollution / secret hunting  ·  Hackviser & PentesterLab JS/DOM modules
SecLists (keys/patterns)                  https://github.com/danielmiessler/SecLists
CWE-798 / CWE-79 / CWE-1321 / CWE-540 / CWE-200   https://cwe.mitre.org/
```

---

> **Final reminder — the one rule that pays:** *A JavaScript file is recon; the finding is the live, privileged secret / the firing DOM XSS / the working unauthorized API call inside it — and the highest of those is a leaked secret that runs code (cloud/CI/admin → shell).* Don't report regex matches or endpoint lists. Harvest everything (including old JS and source maps), extract the four veins, **validate and exploit** to demonstrated impact, and prove it safely. That's how a minified bundle becomes the Critical it was hiding.
