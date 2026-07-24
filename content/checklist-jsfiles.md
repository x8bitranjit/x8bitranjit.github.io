# JavaScript Files Analysis — Checklist

Expert per-attack **test-case matrix** for JavaScript Files Analysis — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*10 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## JSF-001 — Harvest every JS (live + historical + chunks + maps)
**Test Category:** Harvest · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** live bundles, dynamic chunks, inline scripts, /sw.js, /config.js, /env.js; historical JS; subdomains/CDN

**Test Steps:** 1. Pull every LIVE bundle + dynamically-loaded chunk (load all routes / read the webpack chunk manifest).<br>2. Capture inline scripts, service workers, runtime config (/config.js, /env.js, manifest.json).<br>3. Pull HISTORICAL JS (gau + waybackurls) - old bundles hold rotated-but-live keys &amp; removed endpoints.<br>4. Pull across subdomains/CDN; look for //# sourceMappingURL= and try &lt;bundle&gt;.js.map even when not referenced.

**Expected Result:** A complete JS corpus incl. historical, chunks, and any .map files.

**Payload Example:**

```
katana -jc ; gau | grep .js ; try main.js.map ; grep chunk manifest {id:'hash'}
```

**Impact:** Historical bundles and unreferenced chunks/maps hold the highest-value leaks.

**Tools:** katana, gau, waybackurls

**References:** CWE-798; OWASP: Testing JavaScript / Information leakage

---

## JSF-002 — Beautify / deobfuscate + walk bundle internals
**Test Category:** Structure · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** The JS corpus

**Test Steps:** 1. Beautify + deobfuscate (js-beautify, webcrack for webpack/obfuscator.io).<br>2. Walk the webpack chunk manifest -&gt; download EVERY chunk (incl. admin/internal the UI never loads); Vite manifest.json if exposed.<br>3. Locate the env/config object (base URLs, keys) and the SPA router table (all routes incl. admin).

**Expected Result:** Readable code with the config object and full route table located.

**Payload Example:**

```
npx webcrack main.js -o unpacked/ ; reconstruct /static/js/<id>.<hash>.js chunks
```

**Impact:** Admin/internal chunks the UI never loads are where hidden surface hides.

**Tools:** js-beautify, webcrack, ast-grep

**References:** CWE-798; HackTricks: JS analysis / secrets in JS

---

## JSF-003 — Extract secrets (entropy-gated + trufflehog)
**Test Category:** Extract — Secrets · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** The recovered code

**Test Steps:** 1. Run entropy-gated regexes + trufflehog/gitleaks (AKIA/ASIA, private-key blocks, ghp_/glpat-/xox*, sk_live_, GCP service_account).<br>2. Separate HIGH-value (cloud/CI/admin/DB) from public client keys.<br>3. Flag each for live validation (Phase 4).

**Expected Result:** A list of candidate secrets separated into HIGH-value vs public.

**Payload Example:**

```
AKIA[0-9A-Z]{16} ; ghp_[0-9A-Za-z]{36} ; -----BEGIN PRIVATE KEY-----
```

**Impact:** HIGH-value secrets (cloud/CI/admin) are the Critical path; public keys are noise.

**Tools:** trufflehog, gitleaks, jsluice

**References:** CWE-798; CWE-540; HackTricks: JS analysis / secrets in JS

---

## JSF-004 — Extract endpoints / params / hidden surface
**Test Category:** Extract — Surface · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** The recovered code

**Test Steps:** 1. Extract all API paths, verbs, parameters, GraphQL ops, internal hosts.<br>2. Hidden surface: roles, permissions, feature flags, client-only authz, hidden params (debug/isAdmin).<br>3. Map DOM source-&gt;sink flows (innerHTML/eval/postMessage/redirect/proto-pollution).

**Expected Result:** A map of endpoints, hidden params, client-authz logic, and DOM sink flows.

**Payload Example:**

```
grep fetch/axios paths ; feature flags ; ?debug= ?isAdmin= ; innerHTML/eval sinks
```

**Impact:** Hidden endpoints/params/flags and DOM sinks drive the impact phase.

**Tools:** jsluice, LinkFinder, DOM Invader

**References:** CWE-798; PortSwigger Research: JS analysis; Tomnomnom / jsluice

---

## JSF-005 — Recover original source via source maps
**Test Category:** Source Recovery · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** .map files / sourcesContent

**Test Steps:** 1. Unpack .map / sourcesContent -&gt; the original source tree.<br>2. Re-run ALL extractors over the recovered original (higher signal); read comments/dead admin code.<br>3. Even an unreferenced .map often exposes the full app.

**Expected Result:** The original source tree is reconstructed and re-mined.

**Payload Example:**

```
npx source-map-explorer / unpack sourcesContent -> src/ tree
```

**Impact:** Recovered source yields far more secrets/endpoints and reveals dead admin code.

**Tools:** source-map tooling

**References:** CWE-798; CWE-540; HackTricks: JS analysis / secrets in JS

---

## JSF-006 — Validate a HIGH secret live + privileged -&gt; RCE
**Test Category:** Impact — Secret · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** Each HIGH-value secret

**Test Steps:** 1. Validate live + privileged with a minimal READ-ONLY call: aws sts get-caller-identity / /user / /balance.<br>2. Secret-&gt;RCE: cloud key -&gt; cloud run-command; CI token -&gt; pipeline; admin key -&gt; code-exec feature; DB URI -&gt; reachable DB (own tenant/repo only).<br>3. Redact; don't roam real data.

**Expected Result:** A leaked secret is proven live + privileged and escalated to code execution.

**Payload Example:**

```
aws sts get-caller-identity with AKIA... ; CI token -> pipeline run -> id
```

**Impact:** Cloud/CI/admin RCE from a JS-leaked secret - Critical.

**Tools:** aws cli, curl

**References:** CWE-798; CWE-522; HackTricks: JS analysis / secrets in JS

---

## JSF-007 — DOM sink -&gt; DOM XSS -&gt; ATO
**Test Category:** Impact — DOM XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** A confirmed source-&gt;sink flow

**Test Steps:** 1. Confirm the source-&gt;sink fires (innerHTML/eval/location/postMessage).<br>2. Prove session/token theft on your own account.<br>3. Prototype pollution: confirm ({}).polluted + a gadget -&gt; DOM-XSS (client) / RCE (server).

**Expected Result:** A JS source-&gt;sink flow executes attacker script and steals a session/token.

**Payload Example:**

```
location.hash -> innerHTML sink -> <img src=x onerror=steal(document.cookie)>
```

**Impact:** DOM XSS -&gt; account takeover - High.

**Tools:** DOM Invader

**References:** CWE-798; CWE-79; CWE-1321; PortSwigger Research: JS analysis; Tomnomnom / jsluice

---

## JSF-008 — Hidden endpoint -&gt; authz / IDOR
**Test Category:** Impact — Hidden Endpoint · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Admin/internal routes and ids found in JS

**Test Steps:** 1. Call admin/internal routes directly (broken authz) + other ids (IDOR) -&gt; unauthorized result.<br>2. Test old API versions and GraphQL ops found in the bundle.<br>3. Confirm you reach data/actions you shouldn't.

**Expected Result:** A JS-discovered endpoint returns unauthorized data / performs a privileged action.

**Payload Example:**

```
call /api/internal/admin/users found in bundle -> 200 as normal user ; swap id -> IDOR
```

**Impact:** Broken authz / IDOR via hidden endpoints - High/Critical.

**Tools:** Burp, IDOR kit

**References:** CWE-798; CWE-639; HackTricks: JS analysis / secrets in JS

---

## JSF-009 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: Google Maps/Firebase AIza..., Stripe pk_live_..., Sentry DSN, GA/reCAPTCHA key (public by design); a secret match you never validated (dead/rotated/placeholder); a bare endpoint list with no exploited bug; a DOM sink with no controllable source / unreachable path; an /admin path merely MENTIONED in JS but authz enforced server-side; localhost/test creds that don't work on prod; a source map with no sensitive content the program doesn't rate.<br>2. REQUIRE: an attacker-usable artifact - live/privileged secret, firing sink, or reachable unauth endpoint.

**Expected Result:** Only attacker-usable, validated artifacts survive.

**Payload Example:**

```
AIza web key = public ; unvalidated match = FP ; endpoint list alone = not a bug
```

**Impact:** Protects credibility; JS analysis is dense with public-key / unvalidated-match false positives.

**Tools:** manual

**References:** CWE-798; PortSwigger Research: JS analysis; Tomnomnom / jsluice

---

## JSF-010 — Client-facing impact &amp; SAFE PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with the highest-impact artifact (cloud RCE / ATO / privilege escalation / data theft) and demonstrate it.<br>2. Provide the JS location, the validated proof (read-only secret call / firing sink / unauth endpoint response), and confirm old-JS findings STILL work on production.<br>3. Set CVSS 3.1 + the correct CWE (798/79/1321/639/540). Remediation: keep secrets server-side, scope client keys, remove source maps from prod, enforce server-side authz, sanitize DOM sinks.<br>4. Read-only validate, own-tenant code-exec, redact secrets, take PoC pages down; de-dupe to one root cause.

**Expected Result:** A reproducible, correctly-rated PoC with the artifact demonstrated and clear remediation.

**Payload Example:**

```
PoC: JS location + validated proof (secret call / sink / endpoint) + CVSS + CWE + remediation.
```

**Impact:** Converts the JS artifact into a defensible Critical/High report at the demonstrated impact.

**Tools:** CVSS calculator, JS_FILES_REPORT_TEMPLATE.md

**References:** CWE-798; CWE-79; FIRST CVSS v3.1; OWASP: Testing JavaScript / Information leakage  |  TOP REFERENCES: Tomnomnom (jsluice/gf); Assetnote JS-analysis research; trufflehog/gitleaks; PortSwigger Research

---
