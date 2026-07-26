# Prototype Pollution — Zero to Expert (Q&A)

**Author:** x8bitranjit
Study companion + field reference + **interview prep**. Every answer is layered — a plain explanation anyone can follow, the underlying **theory**, the **technical** detail, and a **practical/scenario** angle where it helps. Pair with PortSwigger Academy (client + server PP), Gareth Heyes' research, Olivier Arteau's paper, *Silent Spring* (USENIX 2023), HackTricks, and PayloadsAllTheThings. Impact ceiling = **RCE** (server) · **DOM-XSS** (client) · **auth bypass** (gadget-free).

> **How to use this file.** Levels 0–3 build the mental model and detection; Levels 4–7 are the exploitation depth (RCE, auth bypass, client DOM-XSS, bypasses); Levels 8–9 are chaining, validity, severity and defence; **Level 10** is advanced/edge; **Level 11 is pure interview Q&A** (how to *articulate* it); **Level 12 is scenario-based** (you're handed a situation — what do you do). Read the plain line first, then the theory, then the technical.

---

## Level 0 — Fundamentals & theory

**Q1. What is prototype pollution, in one breath and then properly?**
*Plain:* it's a bug where you write a value into a shared "settings sheet" that every object in the program secretly reads from, so your value silently shows up everywhere.
*Properly:* Prototype pollution is a vulnerability where attacker-controlled input adds or modifies properties on a built-in **prototype object** — almost always `Object.prototype` — through special keys like `__proto__` or `constructor.prototype`. Because nearly every JavaScript object inherits from `Object.prototype`, the injected property becomes visible on **every object in the process** that doesn't define that property itself.
*Theory (why this is even possible):* JavaScript has no classes under the hood — it has **prototypal inheritance**. When you read `obj.x` and `obj` has no own property `x`, the engine walks up the **prototype chain** (`obj.__proto__`, then *its* `__proto__`, …) until it finds `x` or reaches `null`. `Object.prototype` sits at the top of almost every chain. So writing one property there is like editing the last page every lookup eventually consults.
*Interview framing:* "It's essentially injecting a global variable the developer never declared, by abusing prototypal inheritance, so that later code reads my value when it expects its own default."

**Q2. Why does the vulnerability exist — what exact language feature?**
The engine's property-lookup algorithm (`[[Get]]`) is **dynamic and inheritance-aware**: a missing own property is resolved up the prototype chain at *read time*, not fixed at object-creation time. Combined with `__proto__` being a **live accessor** that points at the object's prototype, any code that lets attacker input reach the key `__proto__` (or `constructor` → `prototype`) during a write operation (merge/set/clone) ends up writing to the shared prototype instead of the object. The language never forces you to declare properties, so an *undeclared-but-inherited* property is indistinguishable from a real default — that ambiguity is the bug's root.

**Q3. What's the impact ceiling, and why is it that high?**
Server-side (Node.js): **remote code execution** via gadgets, plus **authentication/authorization bypass** and **DoS**. Client-side (browser): **DOM-XSS** via library gadgets. It reaches RCE/ATO — the top of the severity scale — because the polluted property can control *what command a later `child_process` spawns*, *what code a template engine compiles*, *whether a user is admin*, or *what HTML a library injects*. You're not corrupting one request; you're changing a **process-global default** that other trusted code paths depend on.

**Q4. What is the primary CWE, and what does it escalate to?**
**CWE-1321** — "Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution')." It's a *primitive* CWE that escalates: → **CWE-94** (code injection) / **CWE-78** (OS command) for RCE, → **CWE-79** for DOM-XSS, → **CWE-287/269** for authn/authz bypass. In a report you cite CWE-1321 as the root cause and the escalation CWE for the demonstrated impact.

**Q5. Define "source" and "gadget" — and why the distinction is the whole game.**
*Source* = the pollution **primitive**: an operation that writes attacker-controlled keys into a prototype (a recursive merge, path-set, clone, or parse-then-merge). *Gadget* = a **separate** piece of code that later *reads* an undeclared property (now attacker-controlled via the prototype) and does something dangerous with it (spawns a process, compiles a template, checks `isAdmin`). **Impact = Source + Gadget.**
*Why it's the whole game:* a source with no gadget writes a line nobody reads — harmless, and triage-rejected on mature programs. The finding is *"I polluted, and then this specific code acted on my value."* Every technique in this file is either "how to become a source" or "which gadget you get to fire."
*Interview tip:* if you can crisply separate source from gadget and explain that a bare pollution is only a *primitive*, you immediately sound senior.

**Q6. Is a confirmed source, on its own, a reportable vulnerability?**
It's a **primitive**, not a full finding. To claim RCE/XSS you must land a gadget. Two honest exceptions: (a) server-side, a source that lets you inject a security-relevant *property* into responses (CORS `origin`, a redirect `location`, cache headers) is a real Medium/High even without RCE; (b) a confirmed *global* pollution with a plausible-but-unfired gadget is a defensible Medium. But your instinct should always be: **chase the gadget**, because that's what turns a shrug into a Critical.

**Q7. What are the polluting key paths, and why does each reach the prototype?**
`__proto__`, `constructor.prototype`, `constructor[prototype]`, and occasionally `__proto__.__proto__`.
- `obj.__proto__` **is** the object's prototype (a live accessor on `Object.prototype`), so writing through it writes to `Object.prototype`.
- `obj.constructor` is the function that built `obj` (usually `Object`); a function's `.prototype` is the object it stamps onto everything it builds — which is `Object.prototype`. So `obj.constructor.prototype === obj.__proto__ === Object.prototype`.
Two different paths, one shared target. That equivalence is *why* blocking only the string `__proto__` fails.

**Q8. Why does `constructor.prototype` matter so much in practice?**
It's the standard bypass. The overwhelming majority of naïve defences blocklist the literal string `__proto__` and consider themselves safe. Because `constructor.prototype` reaches the identical `Object.prototype` without ever using the string `__proto__`, you walk in the side door. Any time a `__proto__` payload gets stripped or 400'd, `constructor.prototype`/`constructor[prototype][x]` is your first move.

**Q9. Does polluting affect objects that already existed before the pollution?**
Yes — and this surprises people. Because inherited lookups are resolved **dynamically at read time**, an object created *before* you polluted will still see the new prototype property the next time it's read (unless it has its own same-named property). So pollution is retroactive in effect, not just forward-looking. This is why one pollution can change the behaviour of long-lived config/singleton objects created at boot.

**Q10. Who discovered and systematised prototype pollution?**
Olivier Arteau formalised NodeJS prototype pollution ("Prototype pollution attacks in NodeJS applications", NorthSec 2018). Gareth Heyes / PortSwigger systematised **client-side gadgets** ("widespread prototype pollution gadgets", 2020) and **server-side detection** (2022–2023, plus DOM Invader tooling). Shcherbakov, Balliu et al. produced **"Silent Spring"** (USENIX 2023), which turned server-side PP→RCE via `child_process` options into a reliable, repeatable technique. Knowing this lineage is a common interview check for whether you actually read the research.

**Q11. Explain the prototype chain concretely with a tiny example.**
```js
const user = { name: "alice" };
user.isAdmin;                 // undefined — no own prop, walk chain -> Object.prototype has none
Object.prototype.isAdmin = true;   // <-- the pollution
user.isAdmin;                 // true! — own lookup misses, chain hit on Object.prototype
({}).isAdmin;                 // true — a brand-new object inherits it too => proves it's GLOBAL
```
That three-line demo is the cleanest way to *show* (in a report or interview) the difference between reflection and true global pollution: a **fresh** `{}` carries the property.

**Q12. Why is prototype pollution called a "process-wide" bug server-side rather than per-request?**
In Node, all requests are served by **one shared process** with **one `Object.prototype`**. Polluting it isn't scoped to your request or session — every subsequent request, every other user, and every internal code path reads the same polluted prototype until the **process restarts**. That single fact drives both the high severity (huge blast radius) and the danger of testing it on shared prod.

---

## Level 1 — Sources (finding the way in)

**Q13. What operations are classic sources, and why each?**
- **Recursive merge / deep extend** (`_.merge`, `_.defaultsDeep`, `$.extend(true,…)`, `deepmerge`, hand-rolled merges): the #1 source — they walk nested keys of the *source* object, including `__proto__`, and copy them onto the target's corresponding prototype path.
- **Path-based set** (`_.set`, `_.setWith`, `dot-prop`, `object-path`, `set-value`): interpret a dotted/array path, so `set(o,'__proto__.x',v)` writes onto the prototype directly.
- **Deep clone** (`_.cloneDeep`, custom recursive clone): pollutes if it copies `__proto__` while walking.
- **Query-string / body parse** (`qs` extended, Express `req.query`): build nested objects from bracket syntax (`?__proto__[x]=y` → `{__proto__:{x:'y'}}`), which a later merge lands.
The common thread: they **trust your key names and recurse into them**.

**Q14. Why is recursive merge specifically the #1 source (interview-grade explanation)?**
A deep merge's job is "copy every nested key of source into target." It iterates `for (key of source)` and, for object-valued keys, recurses into `target[key]`. When `key` is `__proto__`, `target["__proto__"]` **is** `target`'s prototype, so recursing into it and assigning children writes onto `Object.prototype`. The merge never special-cases `__proto__` because, to the loop, it's just another key. That "eager, unguarded recursion into an attacker-named key" is the mechanism — say that in an interview and you've nailed it.

**Q15. Does `JSON.parse` by itself pollute? This is a classic trick question.**
**No.** `JSON.parse('{"__proto__":{"x":1}}')` creates an object with an **own** property literally named `__proto__` (a data property, not the accessor) — nothing is written to any prototype. Pollution happens only when that parsed object is then **recursively merged/assigned/set** into another object, at which point the merge walks into the `__proto__` key. *Practical consequence:* you hunt for the **merge/set that follows the parse**, not the parse itself. Getting this right separates people who understand the mechanism from people who memorised payloads.

**Q16. Does `Object.assign` pollute?**
Shallow `Object.assign(target, src)` does **not** — it copies *own enumerable* properties one level deep and treats `__proto__` from a parsed object as a normal own key set via `[[Set]]` (which is safe). The danger is a **nested/deep** merge built on top of it that recurses. So "they use `Object.assign`" is not automatically safe if a deep merge runs afterward.

**Q17. What dependency versions are notoriously vulnerable, and why check the lockfile first?**
lodash `<4.17.12` (`defaultsDeep` CVE-2019-10744; `merge`/`set` earlier), jQuery `<3.4.0` (`$.extend(true)` CVE-2019-11358), minimist `<1.2.3` (CVE-2020-7598), yargs-parser `<13.1.2/15.0.1/18.1.1` (CVE-2020-7608), plus `set-value`/`merge-deep`/`dot-prop` old versions. `package-lock.json`/`yarn.lock` gives you exact versions — if a vulnerable one sits on an attacker-reachable merge/set/argv path, you have a strong lead (and a known gadget map) **before sending a single payload**. Always read the lockfile first when you have it.

**Q18. How do you find sources by code review / bundle analysis?**
Grep for the operations and libs:
```bash
grep -REn "\.merge\(|defaultsDeep|\$\.extend\(\s*true|\.set\(|setWith|cloneDeep|deepmerge|object-path|dot-prop|unflatten" .
```
For client-side, pull the JS bundles, beautify, and search the same patterns plus `location.hash`/`URLSearchParams` parsing feeding a merge. For server-side, the lockfile + any `merge(req.body|req.query|userInput, …)` pattern is gold.

**Q19. What input vectors deliver the payload to the source?**
JSON bodies (`{"__proto__":{…}}`) — the primary server vector; query strings (`?__proto__[x]=y`, parser-dependent bracket vs dot); form/multipart; URL **hash** (client routers, doesn't hit the server → dodges server WAFs); path params, headers, cookies parsed into objects; and **stored data** (profiles, settings, webhooks) that's later merged → second-order.

**Q20. What is second-order prototype pollution, and why is it a WAF-beater?**
The `__proto__` payload is **stored** first (e.g., saved in your profile JSON or a webhook record) and only pollutes **later**, when some *other* operation deep-merges that stored blob. Because the payload isn't in an obvious pollution shape at request time, a request-time WAF never flags it. *Practical play:* store a benign `__proto__` marker, then trigger whatever action deep-merges stored data, and watch your oracle flip. Second-order is a favourite precisely because it sidesteps input filtering.

---

## Level 2 — Detection (client-side)

**Q21. What's the fastest client-side detection, step by step?**
Navigate to `https://target/?__proto__[polluted]=yes` (also try `#__proto__[polluted]=yes` for SPA routers), open DevTools, and check:
```js
Object.prototype.polluted   // "yes"  -> the page has a client-side source
({}).polluted               // "yes"  -> confirms it's GLOBAL, not reflection
```
If both return your value, a client-side merge/parse consumed your key. Thirty seconds, no tooling.

**Q22. Why also test `constructor[prototype][x]` during detection?**
Because a source may filter or fail on the literal `__proto__` but still honour the `constructor.prototype` path (they reach the same place). Testing both catches sources you'd otherwise miss and tells you up front whether a filter is present — which shapes your later bypass work.

**Q23. What exactly does Burp DOM Invader do for PP, and why lean on it?**
DOM Invader (in Burp's built-in browser) automates the two tedious halves: it discovers client-side **sources** (which input reaches a prototype write) *and* scans for **gadgets** (which polluted property flows into which dangerous sink), then reports exploitable source→sink pairs. Hand-hunting gadgets across minified analytics/jQuery/sanitiser bundles is slow and error-prone; DOM Invader turns hours into minutes. It's the primary client-side PP tool.

**Q24. How do you *prove* it's pollution and not reflection — and why does an assessor care?**
Reflection puts your value into *one* response; pollution makes a **fresh, unrelated object** carry the property (`({}).x`), and the effect **persists** across requests. Assessors and triagers reject "it echoed `__proto__`" constantly, so your PoC must show the global/persistent property — that's the line between a real bug and noise.

**Q25. Hash vs query vs JSON sources — what's the practical difference?**
- **Hash** (`#__proto__[x]=y`): consumed by client routers reading `location.hash`; never sent to the server, so it evades server-side WAFs and logs — great for delivering client PP.
- **Query** (`?__proto__[x]=y`): parsed by client *or* server query parsers.
- **JSON** (`{"__proto__":…}`): body-merge, primarily server-side.
Test all three on every app; they exercise different code paths.

**Q26. When is client-side PP merely self-XSS, and how do you make it a real finding?**
If the only source is something you set in *your own* tab and can't deliver to a victim (e.g., you paste into `location.hash` locally with no shareable URL), it's self-XSS — not reportable. It becomes real when the pollution rides a vector an attacker can **send to a victim**: a crafted URL query/hash the victim clicks, or stored data that pollutes another user's session. Always ask "can I deliver this to someone else's browser?"

**Q27. What does a client-side gadget look like, concretely?**
A library that reads an **undeclared config option** and passes it to a sink, e.g. `img.src = config.src` or `el.innerHTML = opts.html`, where `config`/`opts` don't own those keys and fall through to the polluted prototype. You pollute `?__proto__[src]=…` / `?__proto__[html]=…` and the library injects your value into the sink on the next render.

**Q28. How do you enumerate client-side gadgets on a target?**
Identify the loaded scripts (view-source, network tab, bundle) — jQuery, gtag/GA, Segment, sanitisers — then look up their documented gadgets in PortSwigger's "widespread prototype pollution gadgets" catalogue and BlackFan's client-side-PP collection, or let DOM Invader match them automatically. The workflow is "fingerprint the libs → map to known gadgets → trigger the sink."

**Q29. Why is PP-based DOM-XSS frequently *filter-bypassing*?**
Because the XSS value arrives as a **config property read off the prototype**, a path the application never treats as user input. Field-level sanitisers, CSP-ish input validation, and WAFs that inspect the "normal" inputs never see it. So PP DOM-XSS often lands exactly where reflected/stored XSS is blocked — a key selling point when you explain severity.

**Q30. Give a complete, minimal client PP→XSS story you could tell in an interview.**
"The page loads an analytics script that does `s.src = cfg.src || defaultSrc` and builds `cfg` by deep-merging the URL query. I send the victim `…/?__proto__[src]=data:,alert(document.domain)`. The merge writes `src` onto `Object.prototype`; `cfg.src` (which `cfg` doesn't own) resolves to my value; the script creates `<script src="data:,alert(document.domain)">` and my code runs in the victim's authenticated origin — DOM-XSS with no server input, bypassing their input filters, leading to session theft."

---

## Level 3 — Detection (server-side / SSPP, usually blind)

**Q31. Why is server-side detection fundamentally harder than client-side?**
There's no console or DOM to inspect — you can't type `Object.prototype.x`. The pollution is invisible unless it produces an **observable side effect in a response**. So you rely on **oracles**: framework properties that, when polluted, change something you *can* see (indentation, status, headers). SSPP is a **blind** bug; your whole method is "make an unrelated response change."

**Q32. Explain the `json spaces` oracle in depth — why it's the gold standard.**
Express's `res.json()` serialises with `JSON.stringify(obj, replacer, app.get('json spaces'))`. `app.get('json spaces')` reads an option that, if unset, falls through to the prototype. Pollute `{"__proto__":{"json spaces":10}}` and every later JSON response is indented by 10 spaces. It's the gold standard because it's (a) **benign** (indentation doesn't break anything or change security state), (b) **unmistakable** (compact → indented is obvious), and (c) affects **unrelated** endpoints (proving global reach). Baseline a compact JSON response, pollute, re-fetch → indented = confirmed.

**Q33. Name and explain other SSPP oracles.**
- `status` / `statusCode` → a later response returns your code (e.g., 510).
- `exposedHeaders` (cors middleware option) → `Access-Control-Expose-Headers: <your value>` appears.
- `content-type` / charset → injected into response `Content-Type`.
- `parameterLimit` / `allowDots` (qs options) → later multi-param requests error or parse differently (a clean 200→400 flip).
- **Universal fallback:** a nonce-property **canary** (`{"__proto__":{"zzcanary":"x8bit-2f1a"}}`) surfaced in any endpoint that serialises a fresh object back to you (error objects, `{}` defaults).
Each is "pollute a framework default, watch a response reflect it."

**Q34. What's the disciplined SSPP test procedure (and why each step)?**
1. **Baseline** the target response (record indentation/status/headers) — so you can prove a change.
2. **Pollute** a suspected source (JSON body or query) with a benign oracle.
3. **Re-request** the baseline endpoint — ideally on a *different* connection/session.
4. **Diff** against baseline; **repeat 3×** to rule out caching/jitter.
Automate with `pp_probe.py` (control-baselined). The discipline matters because a single blip is a false positive and shared-prod pollution is dangerous — you want confidence with minimal, benign writes.

**Q35. Why insist on benign oracles specifically?**
Server pollution is **process-global and persistent** — a bad property (a broken type, a throwing getter) can degrade or crash the app **for every user** until restart. `json spaces` / a nonce canary prove the primitive without touching security state or stability. Never confirm SSPP with `isAdmin` or a DoS property on shared prod just because it's faster.

**Q36. No oracle fires, but you strongly suspect a source — what now?**
Don't declare it safe (absence of a known oracle ≠ absence of pollution). Options: try more oracles across frameworks; look for **property injection** into headers/redirects; find a **gadget whose effect is observable** (a timing change, an error, a template quirk); or switch to a **reflected-canary** on any object-echoing endpoint. Also reconsider whether your input actually reaches a merge — maybe you found a parse but not the following merge.

**Q37. How long does server-side pollution persist, and why does it matter operationally?**
Until the Node **process restarts** (deploy, crash, or manual restart). Operationally: your test artefact lingers and affects others, so you flag it in the report ("pollution persists until restart; recommend a restart after remediation"), and you avoid stacking pollutions during testing.

**Q38. Can you detect SSPP with no body merge at all?**
Yes — if a **query parser** (`qs` extended) or another parse-then-merge path is the source, `?__proto__[json spaces]=10` works via GET. Many apps merge `req.query` into config/options, so the query vector is often live even when the endpoint takes no JSON body.

**Q39. How do you distinguish an oracle change from a caching artefact (a real assessor question)?**
**Repeatability against a clean baseline.** Re-test multiple times, ideally from a fresh session and on an endpoint you can prove wasn't cached (add a cache-buster). A one-off change that doesn't reproduce is a false positive; a deterministic compact→indented flip that survives re-testing and appears on unrelated endpoints is real.

**Q40. Beyond Express — do Fastify/Koa/hapi have oracles too?**
Yes, though `json spaces` is Express-specific. Other stacks expose their own reflected options (serializer/pretty-print settings, CORS/header option objects, error-serialisation). When the Express oracle doesn't fire, fingerprint the framework and hunt any endpoint that serialises a **fresh** object back, then use the nonce-canary approach.

---

## Level 4 — Server-side RCE gadgets (the money tier)

**Q41. Mechanically, how does prototype pollution become RCE?**
A later operation builds an **options object** — for `child_process.spawn`, a template compile, etc. — but doesn't set every key. The missing keys fall through to the **polluted prototype**, injecting attacker-controlled execution options (which shell to use, environment variables, `NODE_OPTIONS`, or a compile flag that lets code into the generated function). When that operation runs, your option takes effect → code execution. The pollution is the *setup*; the spawn/render is the *trigger*.

**Q42. Explain the `child_process` gadget family in depth.**
`spawn/exec/execFile/fork/execSync` accept an options object with keys like `env`, `shell`, `argv0`, `cwd`. If the app builds that object without those keys, they resolve off the prototype. The high-value ones:
- `env.NODE_OPTIONS` = `--require <file>` → Node loads and runs your file at child start.
- `shell` / `argv0` → control the interpreter/first-arg of the spawn.
This is the *Silent Spring* family: pollute the options once, and the *next* spawn anywhere in the app becomes your code path.

**Q43. Walk through the `NODE_OPTIONS` + `--require` chain end to end.**
1. You need a file whose contents are valid JS to execute (upload one, or use `/proc/self/environ`).
2. Pollute `{"__proto__":{"env":{"NODE_OPTIONS":"--require=/tmp/evil.js"},"shell":"node","argv0":"node"}}`.
3. `/tmp/evil.js` contains `require('child_process').execSync('id > /tmp/pp_rce')`.
4. The app spawns *any* Node child process (a worker, a CLI wrapper, a scheduled task).
5. That child reads `NODE_OPTIONS` off the polluted env, `--require`s your file, and runs it → RCE.
*Plain:* `--require=file` means "run this file first" — you scribble that instruction into the shared settings, and the next helper Node launches obeys it.

**Q44. How do you get RCE with NO file-write primitive? (advanced, high-value)**
Use `--require /proc/self/environ`. Smuggle your JS into an env var — `env.EVIL=console.log(require('child_process').execSync('id').toString())//` — and pollute `NODE_OPTIONS` to `--require /proc/self/environ`. `/proc/self/environ` is a readable pseudo-file whose bytes are the process's environment variables; Node executes it as JS, running your payload before the non-JS bytes throw. No upload, no writable directory needed. This is the trick that makes SSPP→RCE work on locked-down targets.

**Q45. Give the EJS RCE gadget and explain *why* it works.**
`{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');var y"}}`. EJS **concatenates** the `outputFunctionName` option directly into the **source string of the compiled render function** (it builds JS as text, then `new Function`s it). By setting that option to `x;<your code>;var y`, your code is spliced into the generated function body and executes on the next `render()`. It works because EJS trusts that option as an identifier and never sanitises it — classic "attacker controls generated code."

**Q46. Give the Pug/Jade gadget and its mechanism.**
`{"__proto__":{"compileDebug":true,"self":true,"line":"process.mainModule.require('child_process').execSync('id')"}}`. With `compileDebug` on, Pug injects debug instrumentation (including a `line` value) into the compiled function; the polluted `line`/`self` values let your expression land in the generated code. Like EJS, the root cause is that a compile option flows unsanitised into the function Pug builds and runs.

**Q47. Do these gadgets fire immediately, or do they need a trigger?**
They need a **trigger**: the `child_process` gadget fires on the *next spawn*; the template gadget on the *next render*. After polluting, you cause that action (hit an endpoint that renders/spawns) or wait for normal traffic. In a test, identify an endpoint that triggers the sink so you can demonstrate deterministically.

**Q48. How do you pick the *right* gadget for a target?**
Fingerprint the stack: response headers (`X-Powered-By`), error stack traces (they name `ejs`/`pug`/`handlebars`), template file extensions, and the dependency list if you have a bundle/lockfile. Then match: EJS `outputFunctionName` only helps an EJS app; the `child_process` family only helps if the app spawns processes. **Firing an EJS gadget at a Pug app does nothing** — matching is the difference between RCE and wasted requests.

**Q49. What non-template, non-`child_process` gadgets exist?**
`nodemailer` (sendmail path → command), `undici`/proxy options (polluted `proxy`/`uri` → SSRF), `mongoose`/`mquery` options (→ NoSQLi-style), `vm2` escapes, `ansi-html`, `require`-cache/module-resolution tricks, and Express internals (`view engine`, `view cache`). The catalogue grows; PortSwigger's server-side-PP research maintains a living list. Match to what the target loads.

**Q50. Kibana CVE-2019-7609 — what happened, and why is it the canonical case?**
A user-supplied Timelion expression polluted the prototype; Kibana's reporting/canvas worker later spawned a Node child process whose options were read off the (now-polluted) prototype → RCE as the Kibana user. It's canonical because it proved, in a major shipping product, the full **source (Timelion merge) + gadget (`child_process`) = RCE** chain — the reference everyone cites when arguing PP is real RCE, not theory.

**Q51. Why is PP-RCE considered *reliable* once you've matched a gadget?**
Because the gadgets are **deterministic and logic-based**, not memory-corruption. Given the right library, a working source, and a trigger, the payload is compiled/spawned-in and executes every time — no ASLR, no heap grooming, no race. That reliability is why PP→RCE is prized: it's a clean, repeatable Critical.

---

## Level 5 — Auth bypass, DoS, property injection

**Q52. How does PP cause authentication/authorization bypass, and why test it first?**
Pollute a security property the app reads off an object that doesn't own it: `{"__proto__":{"isAdmin":true}}`. A later `if (user.isAdmin)` where `user` has no own `isAdmin` inherits `true` → privilege escalation. Test it **first** because it needs **no gadget hunting**, is often a **one-line, sometimes-unauthenticated Critical**, and immediately tells you the blast radius. Try `isAdmin`, `admin`, `role`, `isAuthenticated`, `verified`, `premium`, `permissions`.

**Q53. Why is gadget-free auth bypass so attractive from an impact standpoint?**
It converts an abstract "prototype write" into a concrete, business-ending outcome (become admin, unlock paid features) with minimal, easily-demonstrated steps — no library fingerprinting, no trigger hunting. It's usually the highest ROI move: try it the moment you confirm a source, then continue to the RCE hunt.

**Q54. How does PP cause DoS, and why be extremely careful?**
Pollute a property that breaks object handling **everywhere**: a throwing getter, a type the framework misuses, or overriding `toString`/making objects look like thenables (`then`). The whole process degrades or crashes. Careful because it's **destructive and process-global** — you'd take down every user on shared prod. Demonstrate DoS only on your own instance/lab; in a report, describe the risk without triggering an outage.

**Q55. What is "property injection" into responses, and what can it chain to?**
Using SSPP to set framework option properties that shape responses — `exposedHeaders`/`origin` (CORS), `location` (redirect), cache headers, or a value reflected into HTML. Even without RCE this chains to **cross-origin data theft** (CORS), **open redirect/SSRF** (`location`), **cache poisoning**, or **XSS** (reflected config). It's how a "no known gadget" SSPP still becomes High.

**Q56. Can PP interact with CSP?**
Sometimes. Client-side, a gadget may inject into a `script-src`-allowed sink, or pollute a value used to build an allowed URL/nonce; whether it bypasses CSP depends on the specific policy and gadget. Don't assume CSP saves the target — test the actual gadget against the actual policy.

**Q57. Can PP disable other security checks generally?**
Yes — any check that reads an **undeclared** property can be flipped: `obj.sanitize`, `obj.validate`, feature flags, rate-limit toggles. Polluting those to falsy/truthy can silently disable validation/sanitisation elsewhere, enabling a *second* bug (e.g., an XSS that was previously sanitised now goes through). This is a subtle but powerful chaining primitive.

**Q58. Is `toString`/`valueOf` pollution useful, and what's the risk?**
Overriding inherited `toString`/`valueOf` affects **string/number coercions across the whole app** (logging, template output, comparisons). Occasionally it's a gadget or an information-leak/DoS vector, but it's **very disruptive** — coercions happen everywhere — so test with extreme care and prefer a lab.

**Q59. `Object.prototype` vs `Array.prototype` pollution — what's the difference?**
`Object.prototype` is broadest (nearly every object). `Array.prototype` pollution specifically affects **arrays** — indices, iteration, methods — and can break or redirect array-driven logic (e.g., a polluted index changes what a `for...in`/spread produces). Some gadgets specifically require array pollution; know both, and note that a source may reach one prototype but not the other.

---

## Level 6 — Bypasses & evasion

**Q60. `__proto__` is stripped — give the full bypass toolkit.**
- **Side door:** `constructor.prototype` / `constructor[prototype][x]` (same target, different string).
- **Strip-once reassembly:** `__pro__proto__to__` — a filter that removes `__proto__` exactly once leaves characters that re-form `__proto__`.
- **Depth:** bury the key deeper than a top-level-only guard inspects.
- **Encoding/parser-differential:** bracket vs dot forms, `qs` vs legacy `querystring` behaviour, URL-encoding for pre-decode string matchers.
Pick the trick that matches *how* the app filters (test what it strips vs rejects).

**Q61. When does encoding actually help, and when is it a waste of time?**
It helps against filters that string-match **before** decoding (URL-encoding `%5f%5fproto%5f%5f`) or that only handle one notation (bracket vs dot). It's a **waste** to try Unicode/homoglyphs of `__proto__`, because the JS runtime compares the **literal** string `"__proto__"` — a homoglyph simply isn't `__proto__` and won't resolve to the prototype. Spend your time on `constructor.prototype` and structure, not exotic encodings.

**Q62. How do parser differentials enable bypass?**
Two layers parse the same input differently. A WAF/sanitiser might not treat `a[__proto__][b]` as pollution while the app's `qs` parser builds `{a:{__proto__:{b:…}}}` and a later merge lands it. Or duplicate/`__proto__` keys survive one JSON parser but are honoured by another. You exploit the gap between what the *filter* sees and what the *app* actually builds.

**Q63. Can you bypass `Object.freeze(Object.prototype)`?**
Often, depending on *how* it's applied. Bypasses: (a) the vulnerable merge already ran **at boot before** the freeze; (b) the source targets `Array.prototype`/a class prototype that **isn't** frozen; (c) `constructor.prototype` chains on non-frozen intrinsics. Freezing **at boot, before any merge, on the right prototypes** is strong; late or partial freezing is not. In a report, note whether the freeze is early and complete.

**Q64. How does Node's `--disable-proto` flag affect you?**
`--disable-proto=delete` removes the `__proto__` accessor; `=throw` makes accessing it throw. That kills the `__proto__` vector — but **`constructor.prototype` sources are unaffected**, so pivot there. Always test both vectors; a target may block one and not the other.

**Q65. What is a "gadget chain" in a PP context?**
Using one pollution to enable another step: e.g., pollute a **sanitiser flag** to falsy (disabling escaping), *then* land an HTML gadget that's now unescaped → XSS; or pollute a config that changes how a *second* merge behaves. Chaining multiple polluted properties (or PP + another bug class) turns a limited primitive into full impact.

**Q66. How do file uploads / webhooks become PP sources?**
Any **structured input that's later deep-merged** is a source: an uploaded JSON/YAML config, a webhook payload merged into state, an imported settings file. These are prime **second-order** vectors — the payload is stored/ingested benignly and pollutes when the merge runs. Test every "import"/"webhook"/"sync" feature with a `__proto__` marker.

**Q67. How do you defeat an allow-list of merge keys?**
Allow-lists that forget `constructor` are beaten with `constructor.prototype`; ones that only check top-level keys are beaten by nesting; and there's often a **second merge** elsewhere that isn't allow-listed. A correct defence must deny `__proto__`, `constructor`, and `prototype` at every recursion level — find the merge that doesn't.

**Q68. Why test *both* client and server surfaces on the same app?**
They're **independent**: different sources, different gadgets, different fixes. A team may harden the client (safe merge, DOM Invader-clean) while a server-side `_.merge(req.body,…)` is wide open, or vice-versa. Skipping one surface misses half the attack surface — always probe both.

---

## Level 7 — Client-side gadgets & DOM-XSS (depth)

**Q69. Name libraries with documented client PP gadgets and the sink each reaches.**
jQuery (`$.extend` source; `htmlPrefilter`/`$(html)` → innerHTML), Google Analytics/gtag & Segment analytics.js (config → `script.src`), Closure, Wistia, Adobe DTM/Launch, sanitize-html/**DOMPurify** configs (flip `ALLOWED_ATTR`/`RETURN_DOM` to permit payloads), Knockout/Vue config edges. Fingerprint which are loaded, then use the matching gadget from PortSwigger's catalogue / BlackFan's collection.

**Q70. How can PP *defeat a sanitiser* like DOMPurify — explain the mechanism.**
DOMPurify and similar read a **config object** for allowed tags/attributes/behaviour. If that config is built such that missing keys fall through to the prototype, polluting `?__proto__[ALLOWED_ATTR][]=onerror` (or a `RETURN_DOM`-style flag) makes the sanitiser **permit** what it would normally strip. So an otherwise-safe `DOMPurify.sanitize()` call now passes your payload — the sanitiser is turned against itself via its own defaults.

**Q71. What sinks matter for client PP-XSS?**
`innerHTML`/`outerHTML`, `script.src`, `iframe.src`/`srcdoc`, `eval`/`Function`/`setTimeout(string)`/`setInterval(string)`, `location`/`a.href` (`javascript:`), and framework **template compilers**. The gadget is "config property → one of these sinks"; your job is to pollute the property the library reads into that sink.

**Q72. Walk an end-to-end client PP-XSS with a sanitiser bypass (scenario).**
The app renders user comments with `DOMPurify.sanitize(comment, cfg)` and builds `cfg` by merging URL params. You deliver `…/?__proto__[ALLOWED_ATTR][0]=onerror&comment=<img src=x onerror=alert(document.domain)>`. The merge pollutes `ALLOWED_ATTR`; `cfg` inherits it; DOMPurify now allows `onerror`; your `<img onerror>` survives sanitisation and fires in the victim's session → DOM-XSS despite a "safe" sanitiser.

**Q73. Does the victim have to do anything for client PP-XSS?**
Usually just **open the crafted URL** — the pollution is in a query/hash param, and the page's own code fires the gadget on load. That's a one-click, deliverable DOM-XSS (no form submit, no extra interaction), which is why it rates High and maps cleanly to session theft/ATO.

**Q74. How does client PP escalate to account takeover?**
DOM-XSS in an **authenticated** origin runs with the victim's cookies/tokens and same-origin privileges. From there you exfiltrate the session token or CSRF token, or perform state-changing actions as the victim (change email, add an OAuth link) → ATO. Cross-ref the XSS kit for the exfil/ATO playbooks.

**Q75. Why is DOM Invader specifically recommended over manual client PP hunting?**
The hard part client-side is correlating *hundreds* of minified library reads with dangerous sinks. DOM Invader instruments the runtime, tracks which polluted property flows into which sink, and surfaces the exploitable pairs — replacing hours of manual bundle spelunking with an automated source→sink map. It's the force-multiplier for client PP.

---

## Level 8 — Chaining & escalation

**Q76. Turn a confirmed SSPP into RCE — the exact steps.**
1. Fingerprint the stack (template engine? spawns processes? lockfile deps?).
2. Pick the matching gadget (EJS `outputFunctionName` / Pug `compileDebug` / `child_process` `NODE_OPTIONS`).
3. Ensure an execution medium (uploaded file or `/proc/self/environ`).
4. Send the pollution.
5. Trigger the render/spawn (hit the endpoint that does it).
6. Confirm with **one benign** proof (`id`/OOB callback), then STOP.

**Q77. Chain PP with file upload.**
Upload a `.js` file (even if served as text — it just needs to exist on disk), then pollute `env.NODE_OPTIONS=--require=/path/to/upload.js`. The next Node child process `--require`s it → RCE. This is the standard pairing when you have an upload but no direct execution; cross-ref the File Upload kit for getting the file written.

**Q78. Chain PP with CORS / open-redirect / cache.**
SSPP-inject `exposedHeaders`/`origin`/`credentials` to weaken CORS → cross-origin reads; inject a `location` → open redirect/SSRF; inject cache headers → cache poisoning. Each turns a "no-RCE" SSPP into a concrete High by borrowing another class's impact.

**Q79. Relationship between PP and NoSQL injection?**
Both abuse **attacker-controlled object keys in JSON bodies**. A `__proto__` key in a Mongo query body can *pollute*, while `$`-operators in the same body *inject* — so a single JSON API endpoint may be vulnerable to both. Test the body for pollution **and** operator injection; they often coexist.

**Q80. What makes PP a uniquely broad primitive to chain from?**
Because it changes **defaults the whole process trusts**, PP can *reach into* other subsystems: disable a validator (enabling injection), flip a CORS/redirect option (enabling data theft), or set a spawn option (enabling RCE). It's less a single exploit than a **capability** — "I can set any undeclared property anywhere" — which is why it chains into so many other classes.

**Q81. How do you demonstrate *reach* for severity?**
Show that an **unrelated request/user/session** is affected — the oracle changed for a different endpoint, or a second browser session inherits the property. That proves **process-global** impact (every user until restart), which is exactly what justifies the Critical/High rating rather than a single-request curiosity.

**Q82. When is PP honestly only Medium/Low?**
A confirmed source with a **benign global effect** but **no reachable gadget** and **no security-relevant property injection** — real, but limited. Report it honestly with the demonstrated effect (the oracle flip) and the *potential* (vulnerable pattern present), rated Medium, rather than overclaiming RCE you couldn't fire. Credibility with triage teams is worth more than an inflated title.

---

## Level 9 — Validity, severity, defence

**Q83. What does a *real* PP finding require (the golden rule)?**
Proof of **global pollution** (a fresh object carries it / an SSPP oracle flips on an unrelated response) **plus** a **concrete impact** (a fired gadget → RCE/XSS, admin access, or security-relevant property injection). A set-but-inconsequential property is a **primitive**, not a bug.

**Q84. List the top false positives to auto-reject.**
Reflected `__proto__` (not global); `?__proto__[x]=y` returning 200 with no proven effect; `Object.prototype.x` set but no gadget/impact; a **one-off** oracle blip (not repeatable); a "known gadget" whose sink never actually fires on this target; **self-only** hash pollution with no delivery; a vulnerable lib present but not on a reachable path.

**Q85. Give CVSS vectors for the main PP outcomes.**
- Server PP→RCE: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` ≈ **9.8** (Critical); raise PR/lower if auth is needed.
- Auth bypass (`isAdmin`): `…/C:H/I:H/A:N` ≈ **8.1–9.8** depending on scope.
- Client DOM-XSS (fired): `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N` ≈ **8.2** (High).
- Property-injection (CORS/redirect/cache): context-dependent **6.1–7.5**.
- Confirmed global pollution, unfired gadget: `…/C:L/I:N/A:N` ≈ **5.3** (Medium).

**Q86. What's the core remediation to recommend?**
Deny the keys `__proto__`, `constructor`, `prototype` at input boundaries and inside recursive merge/set/clone (or use PP-safe implementations); parse JSON with a reviver that drops those keys; use `Object.create(null)` / `Map` for user-keyed data; schema-validate (`ajv` with `additionalProperties:false`); `Object.freeze(Object.prototype)` **at boot**; run Node with `--disable-proto=delete`; upgrade vulnerable deps.

**Q87. Why isn't "just upgrade lodash/jQuery" a complete fix?**
Upgrading patches **those libraries'** known sources, but the application's **own** hand-rolled merges/sets and **other** dependencies can still be vulnerable. PP is a *pattern*, not a single library bug. A complete fix addresses the app's object-handling (deny-keys + safe structures + schema), not just the CVE'd package.

**Q88. How should user-keyed maps be stored to be PP-proof?**
Use a real `Map`, or objects created with `Object.create(null)` (no prototype at all), so attacker keys have no `Object.prototype` to reach. Never deep-merge arbitrary user JSON straight into config/options objects — that's the exact anti-pattern.

**Q89. What must every SAFE-PoC for PP respect?**
Benign markers only (`json spaces`, a nonce property) to prove the primitive; **no** app-breaking property on shared prod; for RCE, **one** command then stop; note that server pollution **persists until restart**; for auth bypass, use your own account and understand others may be briefly affected; deliver client PoCs to **your own** test victim; redact secrets; tear down OOB servers.

**Q90. Summarise prototype pollution in one interview-ready sentence.**
"An attacker who controls an object key can control a variable the developer never declared — I find the **source** (a merge/set that accepts `__proto__`), prove it pollutes **globally** (a fresh object or an unrelated response carries it), then land the **gadget** that turns that shared-prototype property into RCE, DOM-XSS, or admin — and I report the **impact (Source + Gadget)**, never the bare set property."

---

## Level 10 — Advanced / edge

**Q91. What exactly did *Silent Spring* (USENIX 2023) contribute?**
It systematically showed that polluting `child_process` option properties (`env`, `shell`, `argv0`, `NODE_OPTIONS`) turns *any* subsequent spawn into RCE, mapped these sources→gadgets across real Node apps, and made server-side PP→RCE a **repeatable methodology** rather than a per-app one-off. It's why "confirm SSPP → look for a spawn → `NODE_OPTIONS`/`--require`" is now a standard playbook.

**Q92. `--require` vs `--import` in `NODE_OPTIONS` — when each?**
`--require` loads a **CommonJS** module (classic, works with the `/proc/self/environ` trick); `--import` loads an **ES module** (newer Node). Both execute attacker-pointed code at child-process start. Pick whichever the target's Node version honours (older → `--require`; ESM-only contexts → `--import`).

**Q93. How do CLI tools and Electron apps get polluted, and why care?**
`minimist`/`yargs-parser` turn `argv` into objects, so `--__proto__.x=y` on the command line pollutes (relevant to CI pipelines and dev tooling). Electron apps reach Node APIs **without a browser sandbox**, so a polluted config-merge or IPC message → direct RCE. Care because these are high-value targets people forget to test — probe argv and config files, not just web JSON.

**Q94. Explain the `/proc/self/environ` RCE once more, at interview depth.**
"On Linux, `/proc/self/environ` is a virtual file containing the current process's environment variables. Node's `--require <path>` executes the file at `<path>` as JavaScript at startup. If I can set an env var to my JS and set `NODE_OPTIONS=--require /proc/self/environ`, then when the app spawns a Node child, that child reads its environ file — which contains my JS — and runs it. The trailing non-JS environ bytes throw, but *after* my payload already executed. It's elegant because it needs no writable filesystem — the environment itself is my payload file."

**Q95. Why does client-side PP so reliably beat input filters (theory restated)?**
Because the malicious value never travels the "input" path the defences guard — it arrives as a **prototype-resolved config default**, produced *inside* the app when a library reads a key its config object doesn't own. Sanitisers and WAFs inspect request fields; a prototype-sourced value isn't a request field at the moment of use. The defence and the injection are on **different planes**.

**Q96. Prove server pollution is truly global for a report — how?**
Trigger the oracle change from a **different session/connection** and on an **unrelated endpoint** than the one you polluted. That demonstrates the effect isn't request-scoped — it's the shared process prototype — which is the evidence that supports a process-global blast radius and the Critical/High severity.

**Q97. Second-order PP — restate why it's powerful and how to run it.**
The payload is **stored** benignly (profile/settings/webhook) and only pollutes when a **later** operation deep-merges the stored blob, so request-time filtering never sees a pollution shape. Run it: store a `__proto__` nonce via the feature, then trigger the code path that merges stored data (a settings reload, an export, a scheduled job), and watch the oracle flip. Great against WAF-fronted targets.

**Q98. When is `Object.freeze(Object.prototype)` *still* bypassable (deep answer)?**
When it's applied **after** a boot-time merge already polluted; when the source targets a **different prototype** (`Array.prototype`, a class prototype) that wasn't frozen; or via `constructor.prototype` on non-frozen intrinsics. Freezing must be **early** (before any user-influenced merge) and **complete** (the prototypes your sources can reach). Late/partial freezing gives false confidence.

**Q99. What's the transferable pattern behind Kibana and Blitz.js?**
Any layer that **deserialises untrusted input and deep-merges it into an options-bearing object** is a source (Timelion expressions; RPC/GraphQL variables), and a downstream `child_process`/template gadget makes it RCE. The heuristic: when you see *"user JSON → deep-merge → later spawn/render"*, you're staring at a PP→RCE chain — go find the merge and the trigger.

**Q100. If you could keep only one sentence about PP, what is it?**
Controlling an object **key** lets you control an **undeclared variable** the whole process trusts — so find the merge that accepts `__proto__`, prove it's global, and cash it out through a gadget (RCE), a permission check (admin), or a library sink (XSS).

---

## Level 11 — Interview questions (articulate it out loud)

**Q101. "Explain prototype pollution to a junior engineer in 60 seconds."**
"Every JS object shares one 'defaults sheet' called `Object.prototype`. If I read a property an object doesn't have, JS falls back to that sheet. Some code carelessly copies my input — including a magic key called `__proto__` — *onto* that shared sheet. So I can set a default the developer never wrote, like `isAdmin: true`, and suddenly every object that's asked 'are you admin?' and doesn't have its own answer says yes. Depending on what code reads my planted default, I get admin, run server commands, or inject scripts."

**Q102. "How do you explain the difference between a source and a gadget to a client on a debrief call?"**
"The *source* is the unlocked window — a place where our input gets written into the shared defaults. The *gadget* is what a burglar does once inside — the specific valuable action our own code performs when it reads that default. A window alone (source) is a weakness; the theft (gadget → RCE/admin/XSS) is the impact. We fix the window (reject `__proto__` in merges) and, defence-in-depth, remove valuables (safe defaults, freezing)."

**Q103. "Walk me through how you'd test an unknown JSON API for prototype pollution."**
"First, lockfile/dep recon if I have it — vulnerable lodash/jQuery is a lead. Then I baseline a JSON response and send `{"__proto__":{"json spaces":10}}` to each write-ish endpoint, re-fetching to see indentation flip — that confirms an SSPP source, repeatably. Early on I also try `{"__proto__":{"isAdmin":true}}` for a free auth win. Once a source is confirmed, I fingerprint the stack and match a gadget — `NODE_OPTIONS`/`--require`, EJS, or Pug — trigger the spawn/render, and prove RCE with one `id`/OOB callback. Throughout: benign markers, no prod DoS, note it persists until restart."

**Q104. "Why is prototype pollution rated Critical when 'it just sets a property'?"**
"Because that property is a **process-global default** other trusted code depends on. Setting it isn't the end — it's the setup. It lets me control what a later `child_process` spawns (RCE), what a template compiles (RCE), whether I'm admin (authz bypass), or what a library injects (XSS). One write changes behaviour for every user until the process restarts. It's Critical because of *what reads the value*, not the write itself."

**Q105. "What's the single most common mistake people make reporting PP?"**
"Reporting the **primitive** as if it were the impact — 'I set `Object.prototype.foo`' with no gadget. Mature triage rejects that. The fix is discipline: prove **global** pollution *and* demonstrate a concrete gadget outcome (fired RCE, admin access, injected script, or a security-relevant property injection). Source + Gadget + Impact, or it's Medium at best."

**Q106. "How would you remediate prototype pollution across a large Node codebase?"**
"Layered: (1) input boundary — reject/strip `__proto__`/`constructor`/`prototype`, JSON reviver, schema with `additionalProperties:false`; (2) safe data structures — `Map`/`Object.create(null)` for user-keyed data, never deep-merge raw user JSON into options; (3) safe libraries — patched lodash, PP-resistant merge; (4) runtime hardening — `Object.freeze(Object.prototype)` at boot and `--disable-proto=delete`; (5) tests — a unit test that asserts `({}).polluted` stays undefined after processing hostile input. No single layer is sufficient; upgrading a library alone isn't a fix."

**Q107. "Client-side vs server-side prototype pollution — compare."**
"Same root (a merge/parse consuming `__proto__`), different everything else. Client: source is usually the URL/hash/JSON the page merges; detection is instant (`({}).x` in console); impact is DOM-XSS via library gadgets; blast radius is the victim's tab. Server: source is a body/query merge; detection is blind via oracles (`json spaces`); impact is RCE/auth-bypass; blast radius is the whole process/all users until restart. I test both surfaces because they're independent and fixed independently."

**Q108. "Give me a hard interview curveball: does using TypeScript prevent prototype pollution?"**
"No. TypeScript is compile-time typing that erases at runtime — the running code is plain JS with the same prototype chain. If a `_.merge(userInput, …)` exists, TS types don't stop `__proto__` from being written at runtime. TS can *help* indirectly (encouraging typed schemas, discouraging `any`-typed deep merges), but it is not a mitigation. The fixes are runtime: key-denial, safe structures, freezing."

---

## Level 12 — Scenario-based (you're handed a situation)

**Q109. Scenario: A settings endpoint takes `PUT /api/prefs` with a JSON body and returns `{"ok":true}`. No visible change from any payload. How do you proceed?**
Treat it as a blind SSPP candidate. Baseline a JSON response elsewhere (e.g., `GET /api/me`). Send `PUT /api/prefs {"__proto__":{"json spaces":10}}`, then re-fetch `/api/me` — indented? SSPP confirmed. If not, try `status`, `exposedHeaders`, and a nonce canary on any object-echoing endpoint. Also try `{"__proto__":{"isAdmin":true}}` then re-check an authz-gated endpoint. If a source is confirmed but no oracle fires, fingerprint the stack for a gadget. Keep markers benign; the pollution hits every user.

**Q110. Scenario: You confirm client-side pollution via `?__proto__[x]=1` but find no obvious sink. What next?**
Enumerate every loaded library and map to known gadgets (PortSwigger catalogue / DOM Invader). Prioritise sanitiser-config gadgets (DOMPurify `ALLOWED_ATTR`/`RETURN_DOM`) and analytics/jQuery `src`/`html` gadgets. If a sink exists but needs a specific property your source won't set, look for a *second* source with fewer key restrictions. If genuinely no gadget on this page, check other pages/routes (gadgets are per-loaded-script) and consider non-XSS impact (polluted redirect URL, request options). Report the source honestly if nothing fires.

**Q111. Scenario: SSPP is confirmed, the app uses EJS, but your `outputFunctionName` payload doesn't execute. Debug it.**
Check: (1) Did a **render actually happen** after pollution? The gadget fires on the next `render()` — trigger a templated page. (2) Is `outputFunctionName` the right gadget for this **EJS version**? Try alternates (`escapeFunction`+`client`+`compileDebug`, `localsName`, `destructuredLocals`). (3) Did the pollution **land globally** (re-confirm with `json spaces`)? (4) Is EJS caching a previously-compiled template (view cache)? Force a fresh compile / uncached view. (5) Are there **multiple** template engines and this route uses a different one? Fingerprint the specific route.

**Q112. Scenario: You get RCE via PP on a shared production target during an authorised bounty. What are your exact next moves?**
Stop escalation immediately after a **single benign proof** (`id` / an OOB DNS callback with a nonce). Do **not** pollute further, run additional commands, touch data, or trigger DoS-y properties — the pollution is global and persists until restart. Capture: the exact source request, proof of global pollution (oracle flip on an unrelated response), and the single command output/callback. Write the report (Source + Gadget + Impact, CVSS ≈9.8, CWE-1321→CWE-94/78), note that **the pollution persists until the process restarts** and recommend a restart post-fix, and disclose promptly. Restraint here is both ethics and self-protection — you proved Critical without harming other users.

---

## Defense quick-reference
- **Reject** `__proto__`/`constructor`/`prototype` keys in recursive merge/set/clone (every level); use a vetted safe-merge; JSON reviver to drop them.
- **`Object.create(null)`** or **`Map`** for user-keyed data; never deep-merge arbitrary user JSON into config/options.
- **Schema-validate** input (`ajv` `additionalProperties:false`, typed fields).
- **`Object.freeze(Object.prototype)` at boot** (before any user-influenced merge) + Node **`--disable-proto=delete`**.
- **Upgrade** lodash ≥4.17.12, jQuery ≥3.4.0, minimist/yargs-parser patched; audit every `_.merge`/`$.extend(true)`/`_.set` on a user-input path.
- **Test it stays fixed:** a unit/integration test asserting `({}).polluted === undefined` after processing hostile input.
- Fix **both** surfaces: server merges **and** client library gadgets — they're independent.
