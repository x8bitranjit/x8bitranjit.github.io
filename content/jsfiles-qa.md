# JavaScript Files / Client-Side Recon — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **mining client-side JavaScript** — from "why JS matters" to the
> expert chains (leaked cloud key → RCE, DOM XSS → ATO, hidden admin API → privilege escalation, source-map → full
> source recovery). Q&A format, progressive difficulty. Covers harvesting, deobfuscation, bundle internals, source
> maps, secret extraction + **live validation**, endpoint/hidden-surface mapping, DOM-XSS/prototype-pollution, expert
> chaining, tooling, methodology, real-world patterns, **and** defense.
>
> ⚖️ **Authorized use only.** Everything here is for bug bounty (in-scope), sanctioned pentests, CTFs, and learning.
> Validate secrets **read-only**, prove code-exec only on your **own** tenant/repo, and never test systems you don't
> have written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- PortSwigger Web Security Academy — *DOM-based XSS*, *Prototype pollution*, and research ("Stealing secrets from JS", source-map exposure)
- OWASP — *WSTG: Information Gathering / Review Webpage Content* + *Secrets Management Cheat Sheet*
- HackTricks — *PostMessage*, *Prototype Pollution*, *Hacking JWT/Secrets*, *Source map*
- PayloadsAllTheThings — *Prototype Pollution*, *Insecure Source Code Management / secrets*
- Tooling: LinkFinder, xnLinkFinder, JSluice (BishopFox), TruffleHog, gitleaks, webcrack, synchrony, unwebpack-sourcemap, Burp DOM Invader
- Companion kit in this repo: `Web/JSFiles/` (guide + arsenal + checklist + report template + `poc/`)

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q8)
- **Level 1 — Harvesting every JS asset** (Q9–Q18)
- **Level 2 — Reading bundles (beautify, deobfuscate, webpack, source maps)** (Q19–Q30)
- **Level 3 — Secrets: extraction & live validation** (Q31–Q45)
- **Level 4 — Endpoints, hidden surface & parameters** (Q46–Q58)
- **Level 5 — Client-side vulns from JS (DOM XSS, postMessage, prototype pollution)** (Q59–Q74)
- **Level 6 — Exploitation & expert chains** (Q75–Q88)
- **Tooling** (Q89–Q92)
- **Black-box methodology & checklist** (Q93–Q95)
- **Cheat sheets** (Q96–Q98)
- **Real-world patterns & references** (Q99)
- **Defense — securing client-side JS** (Q100)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is "JavaScript file analysis" / JS recon as a discipline?
It's the systematic mining of every client-side JavaScript asset the target serves — bundles, lazy-loaded chunks, inline scripts, service workers, source maps, mobile/RN bundles, third-party SDK config — to extract **secrets, hidden endpoints, parameters, application logic, and client-side vulnerabilities**. It's effectively **white-box recon on a black-box target**: modern SPAs ship the entire client (and sometimes config/secrets) to anyone. JS recon isn't a single bug class; it's the **hub that feeds every other kit** (XSS, SSRF, JWT, CORS, IDOR, file-upload).

### Q2. Why does mining JS pay so well in bug bounty?
Because the frontend leaks the backend's blueprint. One bundle can hand you: a **live cloud key** (→ RCE/cloud takeover), an **undocumented admin API** (→ IDOR/authz), a **DOM-XSS sink** (→ ATO), a **hardcoded JWT secret** (→ token forgery), **internal hostnames** (→ SSRF), or a **source map** that reconstructs the entire commented source. It's also low-friction: the JS is public and pre-auth, so the attacker bar is low → severity goes up.

### Q3. What are the "four veins of gold" in JS?
1. **Secrets** — keys/tokens/creds hardcoded or in env config → cloud/RCE/supply-chain when **live + privileged**.
2. **Endpoints** — every API path + parameter the app can call, including undocumented/admin/internal ones.
3. **Sinks** — client-side dangerous flows → DOM-XSS / prototype pollution / open redirect.
4. **Source** — `.map` recovery → original commented code, dead admin features, secret comments.
Map all four; the highest-impact finding is usually a secret that runs code or a sink that takes over accounts.

### Q4. How is JS recon different from "finding an XSS in a parameter"?
A parameter bug is one finding. JS recon is **reconnaissance that multiplies your other findings** — it removes guesswork by telling you the exact routes, verbs, params, roles, and flags the developers built. The mistake beginners make is treating "I found a JS file" or "I found a regex match" as the finding. **The finding is the live secret / firing sink / working unauthorized call inside it** (Q6).

### Q5. What asset types must you collect (and people forget)?
Linked bundles, **dynamically-loaded chunks** (lazy routes — incl. the admin chunk that ships to everyone), **inline `<script>`** blocks (often hold config/keys/CSRF tokens), **service workers** (`/sw.js` — precache list = more URLs), **runtime config** (`/config.js`, `/env.js`, `manifest.json`), **third-party SDK init** blocks, **historical/archived** JS (Wayback/gau — rotated-but-live keys), **source maps** (`.js.map`), **WASM**, **mobile bundles** (React Native `index.android.bundle`, Cordova `www/`), and **subdomain/CDN** bundles (each app has its own).

### Q6. What's the #1 mistake — and the "match vs impact" rule?
Reporting a **regex match** or an **endpoint list** as a finding. A regex hit (`apiKey: "AIza…"`) is usually an intentionally-public, domain-restricted client key → **Informational**. The rule: *a JS artifact is recon; the finding is the live+privileged secret, the firing DOM XSS, or the working unauthorized API call — with demonstrated impact.* Validate and exploit before you report.

### Q7. What can JS tell you — and what can't it?
JS tells you the **client-side truth**: routes, params, flags, client-side checks, DOM sinks, and any secrets the devs shipped. It does **not** prove server-side behavior — a client-only authz check might still be enforced server-side, an endpoint might 403, a flag might do nothing. So JS gives you **precise hypotheses**; you must **confirm against the server** (call the endpoint, validate the key, fire the sink).

### Q8. What's the minimum you must learn before doing JS recon?
HTTP + an intercepting proxy (Burp/Caido), JavaScript fundamentals, how modern **bundlers** work (webpack/Vite chunking, source maps), regex + a bit of AST tooling, and the basics of the bug classes JS feeds (XSS/DOM-XSS, SSRF, JWT, CORS, IDOR). Plus read-only cloud-key validation (`aws sts get-caller-identity`, `GET /user`).

---

# LEVEL 1 — HARVESTING EVERY JS ASSET

### Q9. How do I find all the JS an app loads?
Crawl + proxy. Load the app through Burp/Caido and filter history for `.js`; spider with **katana**/**hakrawler**/**gospider**; pull `<script src>`, `preload`/`modulepreload`, and `<script type="importmap">`. Then add historical sources (Q10). Goal: a complete URL list before downloading.

### Q10. Why does historical/archived JS matter so much?
Old bundles in **Wayback / gau / commoncrawl** frequently contain **rotated-but-still-live keys**, **endpoints removed from the UI that still work**, and **pre-fix vulnerable code**. Diffing historical vs current JS is one of the highest-yield, least-contested moves. Always pull `echo target | gau --subs | grep '\.js'` and `waybackurls`.

### Q11. How do I make sure I get the dynamically-loaded chunks?
Two ways: (1) **load every route** in a real browser so lazy chunks download (then grab them from Network/DevTools), or (2) read the **webpack chunk manifest** — the `{id:"hash"}` map in the runtime that names *every* chunk, including the **admin/internal** chunks the UI never loads for a normal user. Reconstruct each chunk URL (`/static/js/<id>.<hash>.js`) and fetch them all. Relying only on "what loaded" misses the juiciest code.

### Q12. What about inline scripts, service workers, and runtime config?
Scrape inline `<script>` from every HTML page (config/keys/CSRF tokens live there). Pull `/sw.js`, `/service-worker.js` (its precache/route list reveals more URLs and is an offline-persistence foothold). Fetch runtime config endpoints: `/config.js`, `/env.js`, `/settings.json`, `/manifest.json`, `/.well-known/*`.

### Q13. Third-party SDKs and subdomains?
Analytics/maps/payment/error SDK init blocks carry project IDs and sometimes server keys. Each **subdomain and CDN host** serves its own bundle — harvest `api.`, `app.`, `admin.`, `dev.`, `staging.` separately. The dev/staging bundle often leaks more.

### Q14. Which tools harvest JS at scale?
```bash
katana -u https://target -d 3 -jc -kf all -silent | grep -Ei '\.js(\?|$)' | anew js_urls.txt
echo target | gau --subs | grep -Ei '\.js(\?|$)' | anew js_urls.txt
echo target | waybackurls   | grep -Ei '\.js(\?|$)' | anew js_urls.txt
subjs -i live.txt | anew js_urls.txt
# download corpus + grab referenced .map files:
bash Web/JSFiles/poc/js_harvest.sh target.com out/js
```

### Q15. How do I build a corpus I can diff across deploys?
Download every JS to a local folder keyed by a content hash + basename; store the date. On each re-scan, `anew`/diff against the previous corpus → only **new** bundles get mined → you catch fresh secrets/endpoints the moment they ship (first-mover advantage). Automate it (Q91).

### Q16. How do I get JS from a mobile app?
Decompile the APK/IPA (the `winiapk/` tooling in this repo / apktool / jadx / objection). Pull **React Native** `assets/index.android.bundle` or `main.jsbundle`, and **Cordova/Ionic** `www/**/*.js`. These bundles hold endpoints, S3 buckets, and keys the web app never exposes — a rich, low-competition surface.

### Q17. Import maps, ESM, and dynamic `import()` — anything special?
Yes: `<script type="importmap">` and runtime `import('…')` calls reveal additional module URLs that a simple crawler misses. Grep the bundle for `import(` and the import-map JSON to enumerate every module, then fetch them.

### Q18. What does "complete coverage" look like?
Current + historical bundles, **every chunk from the manifest** (not just loaded ones), inline scripts, service workers, runtime config, per-subdomain/CDN bundles, mobile bundles, and any reachable `.map`. If you only grabbed `main.js`, you're missing the admin chunk, the old keys, and the source maps — i.e., the actual findings.

---

# LEVEL 2 — READING BUNDLES (beautify, deobfuscate, webpack, source maps)

### Q19. First step after harvesting — beautify?
Yes. Run `js-beautify`/`prettier` over every file (or DevTools "{}" pretty-print for a quick look). Minified one-liners become readable. This alone surfaces strings, endpoints, and structure.

### Q20. How do I deal with obfuscated JS (obfuscator.io, packed)?
Use a deobfuscator: **webcrack** (best for webpack + obfuscator.io — folds the string array, undoes control-flow flattening, unpacks modules), **synchrony**, **de4js** (web UI), **REstringer**. Obfuscator.io hoists all strings into one rotated array with a decoder function near the top — let the tool resolve it so `_0x4f2a[12]` becomes the real endpoint/key. For surgical work, AST tools (Acorn/Esprima/`ast-grep`) beat regex.

### Q21. Explain webpack bundle internals I should map.
- **Runtime**: `__webpack_require__`, `webpackJsonp`/`self.webpackChunk…` — the loader.
- **Chunk manifest**: a map `{chunkId: "hash"}` used to build chunk URLs → lists **every** chunk incl. admin/internal.
- **Module map**: modules keyed by id/path; path comments (or the source map) reveal the original file tree.
- **Entry/env**: the env/config object and feature flags are usually near the top of the main chunk.
Mapping the manifest + module paths tells you what code exists *before* you read any of it.

### Q22. Vite / Rollup / Parcel — different?
Vite inlines `import.meta.env.*` and produces a build `manifest.json` (sometimes exposed) mapping entries→chunks; dynamic-import chunks have content-hashed names. Rollup/Parcel differ in runtime but the same ideas apply: find the entry, the config object, and the chunk map. Pull the manifest if it's reachable.

### Q23. Why read the env/config object first?
It's the **fastest path to secrets and base URLs**. Look for `window.__ENV__`, `window.__CONFIG__`, inlined `process.env.*`/`import.meta.env.*`, a `config = {…}` near the top, or a runtime `/env.js`/`/config.json`. It often contains API base URLs, feature flags, public keys, and occasionally server secrets.

### Q24. Why read the route table early?
It's the **fastest path to hidden routes**. SPA router config (React Router routes array, Vue Router, Angular `RouterModule.forRoot([...])`) enumerates every route — including `/admin`, `/internal`, `/debug`, `/impersonate`, role-gated paths — which become your authz/IDOR targets.

### Q25. What is a source map and why is it gold?
A `.map` file (JSON) maps minified code back to the **original source**, and usually embeds the original files in **`sourcesContent`**. A reachable production source map reconstructs the entire commented TypeScript/JSX — variable names, dead admin code, secret comments, crypto/signing details. It's the single biggest "info" win and a force-multiplier for the other veins.

### Q26. How do I find and fetch source maps?
Look for `//# sourceMappingURL=main.abc.js.map` at the end of a bundle. **Even if it's absent, try `<bundle>.js.map`** directly — they're often deployed but unreferenced. Fetch with curl; it's JSON. DevTools "Sources" auto-loads maps when present, showing original files directly.

### Q27. `sourcesContent` present vs absent?
If `sourcesContent` is populated, you can rebuild the whole tree offline (Q28). If it's null/absent, the map only has `sources` (paths) — try fetching those source paths from the server (sometimes exposed), or use DevTools which may resolve them. Many maps include `sourcesContent` by default in CRA/Vite builds.

### Q28. How do I unpack a source map into files?
```bash
python3 Web/JSFiles/poc/sourcemap_unpack.py -u https://target/static/js/main.abc.js.map -o out/src
# or
python3 unwebpack-sourcemap/unwebpack_sourcemap.py https://target/static/js/main.abc.js.map out/src
# then RE-MINE the recovered original source (higher signal than minified):
grep -RiE '(password|secret|token|api[_-]?key|internal|admin|TODO|FIXME|HACK|//)' out/src
```

### Q29. What do I look for in recovered source?
`// TODO`/`// FIXME` secret comments, commented-out creds, internal URLs, **dead `/admin` code paths**, role/permission logic, crypto/signing code (HMAC secrets, JWT handling), and full request shapes. The recovered comments often hand you the exact endpoint + the developer's intent.

### Q30. AST-based search vs regex — when?
Regex is fine for secret patterns and quick endpoint grabs. **AST** (`ast-grep`, Acorn) is better for *structural* queries — find every `fetch($URL)`, `el.innerHTML = $X`, `require($Y)`, or `addEventListener('message', …)` precisely, without regex false positives across minified code. Use AST when hunting sinks/calls in deobfuscated bundles.

---

# LEVEL 3 — SECRETS: EXTRACTION & LIVE VALIDATION

### Q31. What secrets live in JS, and which are HIGH vs LOW value?
**HIGH (validate live):** AWS `AKIA…` + 40-char secret, GCP service-account JSON / `private_key`, Azure storage keys, private keys (`BEGIN … PRIVATE KEY`), CI/VCS tokens (`ghp_`, `glpat-`, `npm_`), server keys (Stripe `sk_live_`, Twilio, SendGrid `SG.`, Slack `xoxb`), signing secrets (JWT/HMAC/cookie/webhook), DB/infra URIs with creds, internal hostnames. **LOW (usually Info):** Google Maps/Firebase web `AIza…`, Stripe **publishable** `pk_live_`, Sentry DSN, GA/Segment write keys, reCAPTCHA site keys.

### Q32. What's the "public-key trap" and why does it close reports?
Many keys are **public by design** — client-side, domain/referrer-restricted (Google Maps `AIza…`, Firebase web config, Stripe **publishable** key, Sentry DSN). Reporting these is the #1 way to get an Informational/N/A. They only matter if you can demonstrate they're **unrestricted/over-scoped** and enable real abuse (e.g., billable API abuse, data access). Don't lead with them.

### Q33. How do I extract secrets at scale (with low FP)?
Run severity-ranked regexes with **entropy gating** (a generic `secret: "<16+ chars>"` only counts if entropy is high enough to not be a placeholder). Use the kit's scanner which suppresses public-by-design keys:
```bash
python3 Web/JSFiles/poc/secret_scan.py -d out/js -o secrets.txt
trufflehog filesystem out/js --only-verified      # auto-validates many key types
gitleaks detect --no-git -s out/js
jsluice secrets -p out/js/*.js
```

### Q34. Which secret tools are worth it?
**TruffleHog** (`--only-verified` actually calls the provider to confirm the key is live — huge time-saver), **gitleaks** (fast regex+entropy), **JSluice** (BishopFox — endpoints **and** secrets from JS with context), and the kit's `secret_scan.py` (entropy-gated + public-key suppression). Always treat output as **candidates**.

### Q35. What's the single golden rule before reporting a secret?
**Validate that it's live AND privileged** with the most minimal, read-only call, then stop. A raw regex match could be dead, rotated, a placeholder, or a public client key. The finding starts at *"this key authenticates right now and can do X."*

### Q36. Read-only validation per provider?
```bash
# AWS — the gold-standard non-destructive proof:
AWS_ACCESS_KEY_ID=… AWS_SECRET_ACCESS_KEY=… aws sts get-caller-identity     # prints principal/account. STOP.
curl -s -H "Authorization: token ghp_…" https://api.github.com/user          # GitHub PAT + scopes
curl -s -H "PRIVATE-TOKEN: glpat-…" https://gitlab.com/api/v4/user            # GitLab
curl -s https://api.stripe.com/v1/balance -u sk_live_…:                       # Stripe SECRET (200 = live)
curl -s -d token=xoxb-… https://slack.com/api/auth.test                       # Slack
gcloud auth activate-service-account --key-file sa.json && gcloud auth print-access-token   # GCP SA
```
Each returns identity/scope without touching real data → a complete proof of Critical.

### Q37. Firebase config in JS — bug or not?
The Firebase **web config** (apiKey/projectId/databaseURL) is public by design — *but* the **Realtime Database** is frequently left **world-readable/writable**. Test it:
```bash
curl -s 'https://<project>.firebaseio.com/.json'            # unauth READ of the whole DB?
curl -s -X PUT -d '{"poc":"x"}' 'https://<project>.firebaseio.com/poc.json'   # unauth WRITE? (benign, delete after)
```
Also test Firestore rules and Firebase Storage buckets. Open RTDB/Firestore is a very common **High** finding sourced from JS.

### Q38. What does "privileged" mean for a key?
Whether it can **read/write real data, perform admin actions, or cross tenants** — not just "it's a key." A Stripe **restricted** key with read-only metadata scope is lower than a full `sk_live_`. Always determine **scope** (the validation call usually shows it) and report accordingly.

### Q39. A JWT/HMAC secret in the bundle — what now?
If you find the **signing secret** (or a weak alg), you can **forge tokens** → auth bypass / privilege escalation / ATO. Take it to the JWT kit (re-sign with the secret, set `role:admin`/`sub:<victim>`). Even a Flask `SECRET_KEY` (often in config) lets you forge session cookies. This is a direct, high-impact use of a JS-leaked secret.

### Q40. Hardcoded DB/infra URIs (`mongodb://user:pass@host`)?
If the host is reachable (directly or via SSRF), authenticate and you have **data theft** (and some DBs → RCE). Even if not directly reachable, the creds may be reused elsewhere. Validate carefully and read-only; redact in the report.

### Q41. Internal hostnames/IPs in JS — why valuable?
They give you an **SSRF target list** and **scope expansion** (new subdomains/services to test). `internal-api.target.local`, `10.x` ranges, admin hostnames → feed the SSRF and recon kits.

### Q42. CI/VCS tokens (`ghp_`/`glpat-`/`npm_`) — impact?
With write/repo scope: push a malicious pipeline/Action/commit → **code execution on build agents → supply-chain RCE** affecting every downstream deploy. Prove on a **repo you own** (a benign pipeline that echoes a marker), confirm scope via `GET /user`, and report as Critical. `npm_`/`pypi-` tokens → publish a malicious package version.

### Q43. Walk a safe "leaked cloud key → cloud takeover" proof.
1. Find `AKIA…` + secret in a bundle (or `/proc/self/environ` via another bug). 2. `aws sts get-caller-identity` → confirms live + shows the principal. **Stop there for the report.** 3. (Only if needed and authorized) enumerate the role's own permissions read-only. Never list/read customer S3 data, never modify resources — `get-caller-identity` is sufficient proof of Critical. Demonstrate any code-exec only on your own test account/tenant.

### Q44. Severity & CWE for JS-leaked secrets?
Live privileged secret in client code: **CWE-798** (Hardcoded Credentials) / **CWE-540** (source-code/info exposure) / **CWE-200**. Cloud-key→RCE or CI-token→supply-chain → **Critical (~9.x)**. Server key (sk_live/admin) live → High–Critical by scope. Public client key / unvalidated match → **Info**. Triagers rate on **demonstrated, live, privileged** access.

### Q45. Safe-PoC discipline for secrets?
Validate with the minimal read-only call; **redact** the value in the report (show prefix + length + the validation response, mask the rest); prove code-exec only on your own tenant/repo; for old/Wayback keys, **confirm they still work on production** before reporting; don't mass-harvest. A `get-caller-identity` line + a redacted key is a complete Critical.

---

# LEVEL 4 — ENDPOINTS, HIDDEN SURFACE & PARAMETERS

### Q46. How do I extract endpoints/paths/params from JS?
```bash
python3 Web/JSFiles/poc/endpoints.py -d out/js -o endpoints.txt
jsluice urls -p out/js/*.js          # context-aware (method, params)
python3 LinkFinder/linkfinder.py -i 'https://target/static/js/*.js' -o cli
python3 xnLinkFinder/xnLinkFinder.py -i out/js -sf target.com -o endpoints.txt
grep -RhoE "/(api|v[0-9]+|internal|admin|graphql)/[a-zA-Z0-9_./{}:-]+" out/js | sort -u
```
Capture paths, full URLs, **parameters** (object keys passed to API calls, query builders, form fields, GraphQL variables), **HTTP verbs**, base URLs, and which calls attach `Authorization`/cookies.

### Q47. Why do hidden endpoints matter so much?
The bundle lists API routes the **UI never exposes** — `/api/admin/users/{id}/impersonate`, `/internal/…`, old `/v1/` versions. These are prime **IDOR/BOLA**, **broken authz**, **SSRF** (URL params), and **injection** targets. JS recon's payoff is that it removes guesswork — you attack the exact route/verb/params the devs built.

### Q48. What is client-side-only authorization, and why is it the high-yield bug?
When access control is implemented **only in JavaScript** (`if (user.role === 'admin') showAdminPanel()`) with no server enforcement. Call the underlying admin API **directly** with a normal account — if it works, that's broken access control / **privilege escalation** (often High). The JS literally tells you which call to make.

### Q49. Feature flags — how do I abuse them?
Bundles list flag names + defaults (`FLAGS["new_billing"]`, `featureFlag('betaAdmin')`). Flags often gate **unfinished, less-tested, or privileged** code. Try toggling them (cookie/localStorage/param the client reads), or just call the flagged endpoints directly. Disabled-but-present features are frequently weakly protected.

### Q50. Mass assignment from object keys?
The bundle shows the exact fields the client sends to an API. Add privileged keys the UI doesn't (`isAdmin:true`, `role:"admin"`, `verified:true`, `balance:9999`) to the request body and resubmit. If the server binds them, that's privilege escalation / data tampering.

### Q51. GraphQL operations/schema in bundles?
Bundles embed GraphQL **operation strings** (`query/mutation/subscription` names + selected fields) and sometimes the **full schema**. Even with introspection disabled, you can reconstruct the schema from the bundle → enumerate sensitive queries/mutations (`viewer { apiToken }`, `adminUsers`, `impersonate`) and test authz/IDOR on them.

### Q52. Embedded swagger/openapi specs?
Sometimes the whole OpenAPI/Swagger JSON is inlined or referenced (`/swagger.json`, `/openapi.json`, `/v2/api-docs`). That's an instant, complete endpoint map (paths, params, auth) → feed straight into IDOR/authz/injection testing.

### Q53. Why note HTTP verbs?
The verb per route reveals **state-changing** endpoints (POST/PUT/PATCH/DELETE) — the ones worth CSRF/authz/IDOR testing. The JS shows which method each route uses, so you don't have to brute it.

### Q54. Which endpoints attach credentials, and why care?
Grep for `withCredentials:true` / `credentials:'include'` / `Authorization` headers. Those endpoints are **credentialed** — prime candidates for the **CORS kit** (if CORS is misconfigured, your evil origin reads their authenticated response → secret theft → ATO).

### Q55. Hidden parameters worth sending?
`debug=true`, `isAdmin`, `impersonate`, `internal`, `bypass`, `test`, `preview`, `format`/`callback` (JSONP). The client sometimes references these; send them server-side to unlock debug output, admin behavior, or alternate code paths.

### Q56. Client-side validation rules — how to exploit?
The bundle holds the regexes/length limits the client enforces. The server may **not** re-enforce them — send the raw, oversized, or specially-crafted value directly (bypassing the JS) to test for injection, overflow, or logic bugs the UI "prevents."

### Q57. How do I turn the endpoint list into IDOR/BOLA tests?
For each object-scoped endpoint (`/api/orders/{id}`, `/api/users/{id}`), call it with your account but **another user's id** (use two test accounts). If you read/modify their data, that's IDOR/BOLA. The bundle gave you the exact route + the id parameter name + the verb.

### Q58. Dependency confusion from package names in the bundle?
Read the internal **scoped package names** referenced in the bundle / `package.json` / source-map paths (`@target/internal-lib`). If a private scope isn't claimed on the public npm registry, you may be able to **publish a malicious package** with that name → it gets pulled into their build → **supply-chain RCE**. (Report responsibly; don't actually run code in their pipeline.)

---

# LEVEL 5 — CLIENT-SIDE VULNS FROM JS (DOM XSS, postMessage, prototype pollution)

### Q59. DOM XSS — what are the sources and sinks?
**Sources (attacker-controllable):** `location.*` (hash/search/href), `document.URL`, `document.referrer`, `window.name`, `document.cookie`, `postMessage` `event.data`, `localStorage`/`sessionStorage`, `URLSearchParams`. **Sinks (dangerous):** `innerHTML`/`outerHTML`, `document.write`, `insertAdjacentHTML`, `eval`, `setTimeout/setInterval(string)`, `Function()`, jQuery `$()`/`.html()`, `dangerouslySetInnerHTML`, `Range.createContextualFragment`; plus redirect sinks (`location=`) and code-load sinks (`script.src=`, `import()`). DOM XSS is a **server-bug-independent** bug found by reading JS.

### Q60. How do I confirm a source→sink flow?
Trace the data: does an attacker-controllable source reach a script-executing sink without sanitization? Use `Web/JSFiles/poc/dom_sinks.py` (ranks source→sink proximity) and **Burp DOM Invader** (auto-detects flows). Then craft a payload for the rendering context (`#<img src=x onerror=alert(document.domain)>`) and confirm it fires.

### Q61. postMessage handlers without an origin check?
A `window.addEventListener('message', e => { el.innerHTML = e.data })` with **no `event.origin` validation** is cross-origin DOM XSS: any site that frames or `window.open()`s the target can post a script payload into the sink → script runs in the target's origin → **account takeover**. This is one of the highest-value JS-only bugs and is very common.
```html
<iframe src="https://target/page-with-handler" id=f></iframe>
<script>f.onload=()=>f.contentWindow.postMessage('<img src=x onerror=alert(document.domain)>','*')</script>
```

### Q62. How does DOM Invader speed this up?
Burp's built-in browser **DOM Invader** instruments sources/sinks and **automatically reports exploitable DOM-XSS flows and vulnerable postMessage handlers** as you browse — far faster than manual tracing in minified code. Use it to confirm the candidates `dom_sinks.py` flags statically.

### Q63. Prototype pollution — what's the client-side sink?
Recursive merge/clone/extend functions and query-string parsers that write nested keys from user input: `lodash.merge`, `$.extend(true,…)`, `defaultsDeep`, `qs`/`deparam`. Polluting `Object.prototype` taints **every** object.
```
?__proto__[x]=y      #__proto__[innerHTML]=<img...>      JSON {"__proto__":{"x":"y"}} into a merge
confirm: ({}).x === 'y'
```

### Q64. Pollution → DOM XSS gadget?
Pollution alone is benign until a **gadget** reads an undefined property off a plain object and uses it dangerously — e.g., a templating/sanitizer/option object whose missing field you polluted to inject markup/script. Find the gadget in the app's libraries (or use known gadget chains for the library/version) → DOM XSS (High). PortSwigger's prototype-pollution labs + DOM Invader's "prototype pollution" mode automate finding source+gadget.

### Q65. Server-side prototype pollution (Node)?
If a JSON body is merged into config server-side (`Object.assign`/`merge` of user input) and a gadget reaches `child_process`/template/`require`, you get **RCE** (Critical). Identify the vulnerable library/version from the JS to pick the right gadget. Several known CVEs (lodash, etc.).

### Q66. Open redirect from JS → token theft?
A redirect sink (`location = userInput`, `location.href = params.next`, `window.open`) that accepts attacker-controlled values is an **open redirect**. On its own it's Medium, but it climbs when it leaks an **OAuth code/token** in the redirect (chain to CORS/JWT) or seeds phishing. Grep JS for `location=`/`returnUrl`/`redirect`/`next` sinks.

### Q67. Client-side template injection (Angular/Vue) vs SSTI?
If the framework evaluates `{{…}}` **in the browser** (AngularJS, Vue with `v-html`/template compile of user input), it's **CSTI → XSS** (not server-side RCE). AngularJS `{{constructor.constructor('alert(1)')()}}` works even when `<>` are HTML-encoded. Distinguish from SSTI (server computes the math) — CSTI is an XSS-kit bug.

### Q68. How do Trusted Types / CSP affect DOM-XSS exploitation?
If `Content-Security-Policy: require-trusted-types-for 'script'` is enforced, naive `innerHTML`/`eval` sinks **throw** instead of executing — you need a **Trusted-Types-policy bypass** (find a permissive policy/gadget) or a different sink. Absence of Trusted Types (the common case) means classic DOM XSS is in play. Always read the CSP before declaring a sink dead or alive.

### Q69. DOMPurify / sanitizer & mutation-XSS (mXSS)?
If output is sanitized (DOMPurify, sanitize-html), the bug is a **parser-roundtrip mismatch (mXSS)**: the sanitizer's parse ≠ the browser's re-parse, so markup mutates back into script after cleaning (SVG/MathML namespace confusion, `template`/`noscript` re-parse). Match the **library + version** (from the bundle) — many apps pin an old vulnerable DOMPurify. cure53's advisories list the bypass classes.

### Q70. Web-messaging / cross-window leaks beyond XSS?
A `message` handler that **sends** sensitive data with `postMessage(data, '*')` (wildcard target origin) leaks it to any framing page. Also `window.opener` access, `localStorage` shared across subdomains, and broadcast channels can leak tokens cross-context. Read every `postMessage`/`addEventListener('message')` for both **injection** and **leakage**.

### Q71. localStorage/sessionStorage secrets and token theft?
SPAs often store the **session/JWT/API token in localStorage** (not an HttpOnly cookie). Any XSS then reads it trivially (`localStorage.token`) → ATO. The bundle shows where tokens are stored and read — note it; it raises the impact of any XSS you find and is itself worth flagging (tokens in localStorage = XSS-stealable).

### Q72. Service-worker abuse / persistence?
A registrable service worker (`navigator.serviceWorker.register`) under attacker control (via XSS or an upload that lands a JS at a controlled scope) can **intercept requests and persist** across navigations. The precache list in `/sw.js` also reveals more URLs. (Demonstrate only on your own session; remove after.)

### Q73. WASM in the bundle — worth analyzing?
Occasionally. `wasm2wat` to disassemble; strings/exports can leak endpoints, logic, or licensing/crypto routines. Rare as a direct bug, but useful for understanding obfuscated client logic or finding hidden URLs.

### Q74. JSONP / script-gadget endpoints found in JS?
If the bundle (or an allow-listed host) exposes a **JSONP** endpoint (`?callback=`), it's a **CSP bypass** primitive (`<script src=//allowed/jsonp?callback=alert(document.domain)>`) and sometimes a data-leak. Also note any framework that auto-executes attribute-bound markup (Angular/Knockout/Aurelia) — those are **script gadgets** for CSP bypass (XSS kit).

---

# LEVEL 6 — EXPLOITATION & EXPERT CHAINS

### Q75. Full chain: leaked cloud key → cloud takeover.
Bundle → `AKIA…`+secret → `aws sts get-caller-identity` (live + principal) → (read-only) the role reaches a compute/SSM/Cloud-Function **run-command** surface → **remote shell on cloud infra**. For the report, stop at `get-caller-identity` (proof of Critical); demonstrate any command exec only on your own tenant. The bundle was the whole entry point.

### Q76. Chain: CI/VCS token → supply-chain RCE.
Bundle → `ghp_`/`glpat-` with repo/workflow scope → push a benign pipeline to a **repo you own** that echoes a marker (proves code-exec on build agents) → report as supply-chain RCE (Critical). Never push to the target's repos.

### Q77. Chain: DOM XSS → account takeover.
DOM sink (or no-origin-check postMessage) → fire `alert(document.domain)` → escalate to **token/cookie theft** (if token is in localStorage or cookie isn't HttpOnly) or a **CSRF-token-steal → email/password change** on your own account → full ATO. Pair with the XSS kit's exfil payloads.

### Q78. Chain: hidden admin endpoint → privilege escalation.
Bundle lists `/api/admin/...` + the request shape → call it directly with a low-priv account (authz) and with other ids (IDOR). If the server doesn't enforce role, you get privilege escalation / mass data access — often Critical if it's an admin takeover.

### Q79. Chain: JS-leaked endpoint → SSRF → metadata.
Bundle reveals an endpoint with a URL/host parameter (`?image=`, `?webhook=`, `?url=`) the UI doesn't expose → SSRF test → `169.254.169.254` → IAM creds → cloud takeover (SSRF kit). JS recon found the sink; SSRF kit exploits it.

### Q80. Chain: JS → JWT forge.
Bundle/source map leaks the **HMAC signing secret** or shows a weak alg / `alg:none` acceptance → forge a token (`role:admin`/`sub:victim`) → auth bypass / ATO (JWT kit). Flask `SECRET_KEY` in config → forge session cookies.

### Q81. Chain: JS → CORS credentialed secret theft.
Bundle shows a **credentialed** secret-bearing endpoint (`/api/me` with `credentials:'include'`) → test CORS: if `ACAO` reflects your origin + `ACAC:true`, your evil page reads the victim's token/PII cross-origin → ATO (CORS kit).

### Q82. Chain: JS → file-upload web shell.
Bundle reveals the upload endpoint + the client-side extension/type rules → bypass them server-side (FileUpload kit), land a web shell → RCE. JS told you the exact endpoint and the (bypassable) client checks.

### Q83. Source map → re-mine everything.
A reachable `.map` reconstructs the original source → re-run **all** extractors (secrets, endpoints, sinks) over the *original* commented code (far higher signal than minified) → the best leads (secret comments, dead admin code, exact request shapes) surface here. Exposed prod source maps are also a valid Low–Medium info-disclosure on their own.

### Q84. Historical-JS diffing — what wins?
Diff Wayback/old bundles vs current. Wins: **rotated-but-still-live keys**, **endpoints removed from the UI that still work server-side**, **pre-fix vulnerable code** showing how a now-"fixed" feature worked. Verify the old artifact still works on production before reporting.

### Q85. Mobile bundle → web-hidden surface.
The RN/Cordova bundle (from the APK) holds endpoints, S3 buckets, and keys the web app doesn't expose — test those endpoints against the web/API backend (often shared). Low-competition, high-yield.

### Q86. How do I detect blind/processing-side things via OOB?
If a JS-found endpoint fetches a URL server-side (SSRF) or a leaked key triggers a server action, confirm via **interactsh/Collaborator** — a DNS/HTTP hit from the server IP proves it even with no visible response. Put a marker in the callback (e.g., `$(whoami)` via a chained RCE) to carry proof.

### Q87. How do I escalate a "weak" JS finding into something that pays?
- Public key → check if **unrestricted** / enables billable abuse or data access.
- Endpoint list → find the **one** route that yields IDOR/authz/SSRF/injection.
- DOM sink → prove it **fires** and steal a session.
- Source map exposed → chase the **validated secret / exploited endpoint** it reveals.
- localStorage token → pair with any XSS for ATO.
Always push for the highest demonstrable impact in scope and **document the chain**.

### Q88. What separates an expert from a beginner in JS recon?
The expert (1) achieves **complete coverage** (chunks from the manifest, historical, mobile, source maps); (2) **validates** secrets live + privileged instead of dumping regex matches; (3) reads **bundle internals + recovered source**, not just greps; (4) treats every artifact as **input to another kit** and **chains** it; (5) confirms client-side vulns dynamically (DOM Invader) and respects Trusted Types/CSP; and (6) writes a crisp PoC with read-only proof, redaction, and a clear impact chain.

---

# TOOLING

### Q89. Core JS-recon toolkit?
- **Harvest:** katana, hakrawler, gospider, gau, waybackurls, subjs; the kit's `js_harvest.sh`.
- **Deobfuscate/read:** js-beautify/prettier, **webcrack**, synchrony, de4js, `ast-grep`; DevTools (Sources/Coverage/Network).
- **Secrets:** **TruffleHog** (`--only-verified`), gitleaks, **JSluice**, the kit's `secret_scan.py`.
- **Endpoints:** **JSluice**, LinkFinder, xnLinkFinder, the kit's `endpoints.py`.
- **DOM/sinks:** the kit's `dom_sinks.py`, **Burp DOM Invader**.
- **Source maps:** unwebpack-sourcemap, sourcemapper, the kit's `sourcemap_unpack.py`.
- **OOB:** interactsh / Burp Collaborator. **Validate keys:** `aws`/`gcloud`/`curl`.

### Q90. How do I build a reliable success oracle for automation?
Don't trust matches. For **secrets**: pipe through TruffleHog `--only-verified` or run the read-only validation call and check for a 200 + identity. For **endpoints**: only flag a finding when an authz/IDOR test returns unauthorized data. For **DOM sinks**: only flag when DOM Invader/the payload actually fires. Without an oracle you drown in false positives (exactly what gets reports closed).

### Q91. Continuous monitoring of JS?
Cron a re-harvest on a schedule; `anew`/diff the corpus → mine only **new** bundles on each deploy → catch fresh secrets/endpoints first.
```bash
bash Web/JSFiles/poc/js_harvest.sh target.com out/js
python3 Web/JSFiles/poc/secret_scan.py -d out/js | anew seen_secrets.txt | notify
# diff endpoints/chunks vs last run; alert on new admin/internal routes & new keys.
```

### Q92. The fastest Burp + DevTools workflow?
1. Browse the app through Burp; let DOM Invader run. 2. Filter proxy history for `.js`; send the corpus to a folder. 3. In DevTools: Sources (auto-load maps), Coverage (what ran), Search-all-files for a target string, set `fetch`/XHR breakpoints to see real API calls + auth headers. 4. Run the offline extractors over the saved corpus + recovered source. 5. Validate/exploit the top leads.

---

# BLACK-BOX METHODOLOGY & CHECKLIST

### Q93. Give me the step-by-step methodology.
1. **Harvest** every JS asset (current + historical + all chunks + inline + sw + mobile + `.map`).
2. **Beautify/deobfuscate**; map webpack runtime, chunk manifest, env/config object, route table.
3. **Recover source** from `.map`/`sourcesContent`; re-mine the original.
4. **Extract the four veins**: secrets, endpoints/params, hidden surface (roles/flags/authz), DOM sinks.
5. **Validate**: secrets live+privileged (read-only); confirm sinks fire (DOM Invader); confirm endpoints unauthorized.
6. **Exploit & chain** to the highest impact (cloud RCE / ATO / privilege escalation / data theft).
7. **Report** with read-only proof, redaction, and the impact chain.

### Q94. Quick triage decision tree.
- Server/cloud/CI/signing/DB secret → **validate read-only** → live+privileged? → cloud/RCE/supply-chain (**Critical**).
- Public client key / unvalidated match → **Info** (move on).
- DOM sink + controllable source that **fires** → DOM XSS → ATO (**High**).
- Recursive-merge / qs sink → prototype pollution → gadget? → DOM-XSS (client) / RCE (server).
- Hidden/admin endpoint, server doesn't enforce authz → privilege escalation / IDOR (**Medium–High**).
- Source map reachable → unpack → chase the highest reveal.
- Only endpoint lists / public keys → recon/Info → validate & exploit first.

### Q95. False positives / auto-reject (don't submit these).
- Google Maps/Firebase `AIza…`, Stripe `pk_live_`, Sentry DSN, GA/reCAPTCHA keys (public by design).
- A secret match you **never validated** (could be dead/rotated/placeholder).
- A bare endpoint list / "I found API routes" with no exploited bug.
- A DOM sink with no controllable source / unreachable code.
- A `/admin` path merely *mentioned* in JS where authz **is** enforced server-side.
- localhost/test/example creds that don't work on production.
- Source map exposed with no sensitive content (unless the program rates it).

---

# CHEAT SHEETS

### Q96. Secret regex cheat sheet (HIGH-value; validate live).
```
AWS access key      \b(AKIA|ASIA)[0-9A-Z]{16}\b           AWS secret  (?i)aws.{0,20}(secret|sk).{0,20}['"][0-9a-zA-Z/+]{40}['"]
Private key         -----BEGIN (RSA|EC|OPENSSH|DSA|PGP)? ?PRIVATE KEY-----
GCP svc-acct        "type"\s*:\s*"service_account"         GitHub  ghp_[0-9A-Za-z]{36} | github_pat_[0-9A-Za-z_]{82}
GitLab  glpat-[0-9A-Za-z_-]{20}    Slack  xox[baprs]-…     Stripe SECRET  sk_live_[0-9a-zA-Z]{24,}
SendGrid  SG\.[\w-]{22}\.[\w-]{43} Twilio  AC[0-9a-f]{32}  npm  npm_[0-9A-Za-z]{36}   Shopify  shpat_[0-9a-f]{32}
DB URI  (mongodb(\+srv)?|postgres|mysql|redis)://[^:@\s]+:[^@\s]+@[^/\s]+    JWT  eyJ[\w-]+\.eyJ[\w-]+\.[\w-]+
Firebase RTDB  https://[a-z0-9-]+\.firebaseio\.com         Bearer/x-api-key  (?i)(authorization|x-api-key)\s*[:=]\s*['"][\w.\-]{20,}
LOW (Info):  AIza[0-9A-Za-z_-]{35} (Google) · pk_live_… (Stripe pub) · Sentry DSN https://[0-9a-f]{32}@…/[0-9]+
```

### Q97. DOM source/sink + source-map recovery cheat sheet.
```
SOURCES: location.{hash,search,href}  document.{URL,referrer,cookie}  window.name  postMessage event.data  localStorage  URLSearchParams
SINKS:   innerHTML outerHTML document.write insertAdjacentHTML eval setTimeout/Interval("…") Function() $().html() dangerouslySetInnerHTML
         location=/.href/.assign/.replace  window.open  script.src=  import(  proto-pollution: merge/extend/defaultsDeep/__proto__/qs.parse
postMessage XSS: addEventListener('message', …) with NO event.origin check → data → sink = cross-origin DOM XSS
source maps:  grep -RhoE 'sourceMappingURL=[^ "'"'"']+' out/js ; try <bundle>.js.map ; unpack sourcesContent → re-mine
```

### Q98. Read-only validation one-liners.
```bash
aws sts get-caller-identity                                  # AWS — principal/account, then STOP
curl -s -H "Authorization: token ghp_…" https://api.github.com/user        # GitHub PAT + scopes
curl -s -H "PRIVATE-TOKEN: glpat-…" https://gitlab.com/api/v4/user          # GitLab
curl -s https://api.stripe.com/v1/balance -u sk_live_…:                     # Stripe SECRET (200 = live)
curl -s -d token=xoxb-… https://slack.com/api/auth.test                     # Slack
curl -s 'https://<proj>.firebaseio.com/.json'                               # Firebase RTDB unauth read?
```

---

# REAL-WORLD PATTERNS & REFERENCES

### Q99. Recurring real-world JS-recon wins + resources.
**Patterns (seen across countless disclosed reports):**
- Avatar/profile bundle → **open Firebase RTDB / hardcoded Firebase admin** → full DB read/write.
- Main bundle → **live AWS/GCP key** → cloud account compromise (validated read-only).
- Old Wayback bundle → **rotated-but-live key / removed-but-working endpoint**.
- Exposed **production source map** → full source → secret comments + hidden admin code.
- **postMessage** handler with no origin check → cross-origin DOM XSS → ATO.
- **Client-side-only authz** + a hidden `/api/admin/…` → privilege escalation by calling it directly.
- **JWT/HMAC secret in JS** → token forgery → ATO.
- **Mobile (RN) bundle** → endpoints/buckets/keys not in the web app.
- **Dependency-confusion** scope name in the bundle → supply-chain.

**Resources to work through:** PortSwigger Academy (DOM-based XSS + Prototype pollution labs) and PortSwigger research on JS-sourced secrets/source-maps; HackTricks *PostMessage* / *Prototype Pollution* / secret-hunting; PayloadsAllTheThings *Prototype Pollution*; BishopFox **JSluice** writeup; cure53 **DOMPurify** advisories; tomnomnom/0xacb JS-recon talks; Hackviser & PentesterLab JS/DOM modules. Read 20+ disclosed HackerOne/Bugcrowd reports tagged "information disclosure / secret in JS / DOM XSS" to internalize patterns.

---

# DEFENSE — SECURING CLIENT-SIDE JS

### Q100. How do I secure client-side JavaScript (and the one-paragraph summary)?
**Controls:** never ship server/cloud/CI secrets to the client — keep them server-side and proxy; use only **publishable/restricted** keys in the browser, locked to origin/referrer; **don't deploy source maps to production** (or access-restrict them); **enforce authorization server-side** on every endpoint (never trust client-side gates or feature flags); store session tokens in **HttpOnly cookies**, not localStorage; use **`textContent`/safe templating** and a **sanitizer + Trusted Types** instead of `innerHTML`; **validate `event.origin`** on every `message` handler and never `postMessage` secrets with `'*'`; **freeze prototypes / use null-proto objects** to kill prototype pollution; claim your internal **npm scopes**; rotate any leaked key immediately; and run **CI secret scanning** (gitleaks/trufflehog) to prevent regressions.

> *"The frontend is source code you publish. Treat every secret, endpoint, role, and flag in your JS as known to the attacker: keep real secrets off the client, ship no production source maps, enforce every authorization decision on the server, encode all DOM output and validate every message origin, and freeze your prototypes. A single shipped cloud key, an unguarded admin route the bundle reveals, or one origin-less postMessage handler can turn 'just JavaScript' into cloud compromise or account takeover."*

---

## APPENDIX — 60-second JS-recon field checklist
```
[ ] Harvest ALL JS: live bundles + every chunk (from the manifest) + inline + sw + runtime config + mobile + HISTORICAL
[ ] Try <bundle>.js.map (even if unreferenced) → unpack sourcesContent → re-mine original source
[ ] Beautify/deobfuscate (webcrack); read env/config object + route table FIRST
[ ] Secrets: regex + trufflehog --only-verified → VALIDATE live + privileged (read-only) → kill public-key FPs
[ ] Firebase config? → test RTDB /.json unauth read/write
[ ] Endpoints/params: jsluice/LinkFinder → find hidden /api/admin & internal routes + verbs + credentialed calls
[ ] Client-side-only authz / feature flags / mass-assignment keys → call the API directly
[ ] DOM sinks: dom_sinks.py + DOM Invader → confirm a source→sink fires (check Trusted Types/CSP first)
[ ] postMessage handler with no origin check? → cross-origin DOM XSS
[ ] prototype-pollution sink? → gadget → DOM-XSS (client) / RCE (server)
[ ] CHAIN: secret→cloud/CI/RCE · DOM XSS→ATO · hidden endpoint→IDOR/SSRF · JWT/CORS/upload pivots
[ ] Diff historical vs current; pull mobile bundle; check dependency-confusion scopes
[ ] Report: read-only proof, redacted secrets, demonstrated impact chain (not regex matches)
```
*End of guide.*
