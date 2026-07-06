# Prototype Pollution — Zero to Expert (100 Q&A)

**Author:** x8bitranjit
Study companion + field reference. Advanced guide — pair with PortSwigger Academy (client + server PP), Gareth Heyes' research, Olivier Arteau's paper, HackTricks, and PayloadsAllTheThings. Impact ceiling = RCE (server) · DOM-XSS (client) · auth bypass.

---

## Level 0 — Fundamentals

**Q1. What is prototype pollution?** A vulnerability where an attacker adds/modifies properties on `Object.prototype` (or another built-in prototype) via crafted keys like `__proto__`. Because nearly every object inherits from `Object.prototype`, the injected property appears on **all** objects process-wide, changing application behavior.

**Q2. Why does it exist — what JS feature?** Prototypal inheritance: `obj.x` that isn't an own property is looked up on `obj.__proto__` (→ `Object.prototype`). If code lets attacker input reach the special key `__proto__`/`constructor.prototype` during a merge/set, it writes to the shared prototype.

**Q3. What's the impact ceiling?** Server-side (Node): **RCE** via gadgets, plus auth bypass and DoS. Client-side (browser): **DOM-XSS** via library gadgets. So Critical/High.

**Q4. What's the primary CWE?** **CWE-1321** — Improperly Controlled Modification of Object Prototype Attributes ('Prototype Pollution').

**Q5. Define "source" and "gadget".** *Source* = the pollution primitive (a vulnerable merge/set/clone/parse that writes attacker keys to a prototype). *Gadget* = code elsewhere that reads an undeclared property (now attacker-controlled via the prototype) into a dangerous sink. **Impact = Source + Gadget.**

**Q6. Is a source alone a vulnerability?** It's a *primitive*. To claim RCE/XSS you need a gadget. (Server-side, a source can still be Medium via property-injection into responses, but you should hunt the gadget.)

**Q7. What are the polluting key paths?** `__proto__`, or `constructor` then `prototype` (`constructor.prototype`), occasionally `__proto__.__proto__`. All resolve to `Object.prototype`.

**Q8. Why does `constructor.prototype` matter?** It's the bypass when a filter blocks the literal string `__proto__` — `constructor.prototype` reaches the same prototype without using `__proto__`.

**Q9. Does polluting affect existing objects too?** Yes — inherited property lookups are dynamic, so already-created objects also see the new prototype property (unless they have their own same-named property).

**Q10. Who discovered/popularized it?** Olivier Arteau formalized NodeJS prototype pollution (NorthSec 2018); PortSwigger/Gareth Heyes later systematized client-side gadgets (2020) and server-side detection (2022–2023).

---

## Level 1 — Sources

**Q11. What operations are classic sources?** Recursive **merge/extend** (`_.merge`, `$.extend(true,…)`, `_.defaultsDeep`, `_.mergeWith`, custom merges), **path-set** (`_.set`, `_.setWith`, `dot-prop`, `object-path`), **deep clone**, and **query-string/JSON parsing** that builds nested objects.

**Q12. Why is recursive merge the #1 source?** It walks the source object's keys — including `__proto__` — and copies them into the target's corresponding (prototype) path, writing to `Object.prototype`.

**Q13. How does `_.set` pollute?** `_.set(obj, '__proto__.polluted', 'x')` interprets the path and writes `polluted` onto `obj.__proto__` = `Object.prototype`. Same for `_.setWith`, `dot-prop`, `object-path`.

**Q14. How does query-string parsing pollute?** Parsers like `qs` build nested objects from bracket syntax: `?__proto__[x]=y` → `{__proto__:{x:'y'}}`, which a later merge/assign pushes onto the prototype.

**Q15. Does `JSON.parse` itself pollute?** No — `JSON.parse('{"__proto__":{"x":1}}')` creates an **own** `__proto__` property, not prototype write. Pollution happens when that parsed object is then **merged/assigned recursively** into another object.

**Q16. Does `Object.assign` pollute?** Shallow `Object.assign` does not (it sets own props). Nested/deep merge built on top of it can. The danger is recursion into `__proto__`.

**Q17. What library versions are notoriously vulnerable?** lodash <4.17.12 (`defaultsDeep` CVE-2019-10744; `merge`/`set` earlier), jQuery <3.4.0 (`$.extend` CVE-2019-11358), minimist <1.2.3 (CVE-2020-7598), yargs-parser <13.1.2 (CVE-2020-7608), various `set-value`/`merge-deep`.

**Q18. How do you find sources by code review?** Grep bundles/source for `merge(`, `extend(`, `defaultsDeep`, `_.set`, `setWith`, `cloneDeep`, `mergeWith`, `dot-prop`, `object-path`, and the vulnerable lib versions.

**Q19. What input vectors deliver the source?** JSON bodies, query strings, form/multipart, URL hash (client routers), path params, headers/cookies parsed into objects, and stored app data (second-order).

**Q20. What's second-order prototype pollution?** Attacker-supplied `__proto__` stored earlier (profile/settings JSON) is later deep-merged during another operation, triggering pollution away from the initial input.

---

## Level 2 — Detection (client)

**Q21. Fastest client-side detection?** Load `?__proto__[polluted]=yes`, open console, check `Object.prototype.polluted === 'yes'` (and `({}).polluted`). If set, the page has a client-side source.

**Q22. Why also test `constructor[prototype][x]`?** To catch sources that block/skip `__proto__` but not the `constructor.prototype` path.

**Q23. What is DOM Invader's role?** Burp's built-in-browser tool auto-detects client-side PP **sources** and scans for **gadgets** (which polluted property reaches which sink), massively speeding client-side testing.

**Q24. How do you confirm it's pollution, not reflection?** Reflection puts your value in one response; pollution makes a **fresh, unrelated object** carry the property (`({}).x`). Global effect = pollution.

**Q25. Hash vs query vs JSON sources — difference?** Hash (`#__proto__[x]=y`) targets client routers reading `location.hash`; query targets server/client query parsers; JSON targets body-merge. Test all three per app.

**Q26. Can client-side PP be self-only?** If the only source is `location.hash` you control in your own tab and it isn't deliverable, it's self-XSS. A finding needs a vector an attacker can send to a **victim** (URL param, stored data).

**Q27. What does a client gadget look like?** A library reading an undeclared config option into a sink, e.g. `cfg.src` → `script.src`, `cfg.html` → `innerHTML`. Pollute that option and the sink executes your value.

**Q28. How do you enumerate client gadgets?** Identify loaded libraries (jQuery, analytics, sanitizers), then consult the known-gadget catalog (PortSwigger's "widespread prototype pollution gadgets"), or let DOM Invader find them.

**Q29. Give an example client gadget payload.** `?__proto__[src]=data:,alert(document.domain)` when a script assigns `element.src = config.src` reading `config` off a polluted prototype.

**Q30. Why is PP-based DOM-XSS often filter-bypassing?** The XSS value enters via a *config property* the app never treats as user input, so input filters/sanitizers on normal fields don't cover it.

---

## Level 3 — Detection (server, SSPP)

**Q31. Why is server-side detection harder?** No console/DOM; pollution is invisible unless a side effect surfaces. You need **oracles** — framework properties that change observable response behavior when polluted.

**Q32. What's the `json spaces` oracle?** Express reads `app.set('json spaces')` / an options object for `res.json` indentation. Polluting `{"__proto__":{"json spaces":10}}` makes all later JSON responses indent by 10 spaces — a clean, benign, visible confirmation.

**Q33. Name other SSPP oracles.** `status` (override response code), `exposedHeaders` (CORS `Access-Control-Expose-Headers`), `content-type`/charset, `parameterLimit`/`parameters limit` (query parsing errors), `allowDots`, and various middleware option reflections.

**Q34. How do you run an SSPP test cleanly?** Baseline the target JSON response, POST the pollution to a suspected source, re-request the baseline endpoint, and diff. A repeatable change = confirmed. Automate with `pp_probe.py`.

**Q35. Why prefer benign oracles?** Server pollution is **process-global and persistent** — a bad property can break the app for everyone. `json spaces` is harmless and reversible-ish; prefer it over anything that alters security state.

**Q36. What if no oracle fires but you suspect a source?** Try more oracles, look for property-injection into headers/redirects, or find a gadget whose effect is observable (timing/error). Absence of an oracle isn't proof of safety.

**Q37. How long does server pollution last?** Until the Node process **restarts**. That's a key caution (and something to flag in the report).

**Q38. Does SSPP affect other users?** Yes — the whole process. That's why SAFE-PoC insists on benign markers and no app-breaking properties on shared prod.

**Q39. Can you detect SSPP without any body merge?** Yes if a query parser (`qs`) or another parse-then-merge path is the source; use `?__proto__[json spaces]=10`.

**Q40. What distinguishes an SSPP oracle change from a caching artifact?** Repeatability and a clean baseline. Re-test multiple times; a one-off change is a false positive.

---

## Level 4 — Server-side RCE gadgets

**Q41. How does prototype pollution reach RCE?** A later operation builds an **options object** (for `child_process`, a template compile, etc.) that omits some keys; those keys fall through to the polluted prototype, injecting attacker-controlled execution options.

**Q42. Explain the `child_process` gadget.** `spawn/exec/execFile/fork` accept an options object (`env`, `shell`, `argv0`, `cwd`). If built fresh and merged with defaults, polluting `env.NODE_OPTIONS`/`shell`/`argv0` can make the spawned process run attacker code.

**Q43. What's the `NODE_OPTIONS` + `--require` chain?** Pollute `env.NODE_OPTIONS` to `--require=/path/to/attacker.js`; when the app spawns a child Node process, it requires your file → RCE. Pair with a file you can write ([File Upload](#/fileupload/guide)) or a `/proc` trick.

**Q44. Give the EJS RCE gadget.** Pollute `{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');//"}}`. EJS concatenates `outputFunctionName` into the compiled function source → your code runs on the next render.

**Q45. Give the Pug/Jade gadget.** Pollute `compileDebug:true` + `self:true` + a `line`/`block` carrying `process.mainModule.require('child_process').execSync('id')`, which Pug compiles into the template function.

**Q46. Do these gadgets need a render/spawn after pollution?** Yes — the gadget fires when the app next compiles a template / spawns a process. Trigger that action (or wait for normal traffic).

**Q47. How do you pick the right gadget?** Match it to the target's actual dependencies (which template engine? does it shell out?). Firing an EJS gadget on a Pug app does nothing.

**Q48. What non-RCE server gadgets exist?** Property injection into **CORS** (`exposedHeaders`, `origin`), **redirects** (`location`), **cache** headers, or config that becomes reflected/XSS — Medium/High even without RCE.

**Q49. Kibana CVE-2019-7609 — what was it?** A Timelion prototype-pollution → RCE in Kibana; a classic real-world PP→RCE demonstrating the source+gadget model in a major product.

**Q50. Why is PP-RCE considered reliable once matched?** The gadgets are well-researched and deterministic: given the right library and a working source, the compiled-in payload executes — no memory corruption or race needed.

---

## Level 5 — Auth bypass, DoS, property injection

**Q51. How does PP cause auth bypass?** Pollute a security property the app reads off a non-owning object: `{"__proto__":{"isAdmin":true}}`. A later `if (user.isAdmin)` where `user` lacks its own `isAdmin` inherits `true` → privilege escalation.

**Q52. Why is auth-bypass PP attractive?** No gadget hunting — it's a direct logic subversion, often unauthenticated, and Critical. Test it early.

**Q53. What common properties to try for auth bypass?** `isAdmin`, `admin`, `role`, `isAuthenticated`, `verified`, `premium`, `access`, `permissions`. Depends on the app's checks.

**Q54. How does PP cause DoS?** Polluting a property that breaks object handling everywhere (a throwing getter, a type the framework misuses, `toString`/`hasOwnProperty` overrides) crashes or degrades the whole process.

**Q55. Why be careful with PP DoS?** It's destructive and process-global — demonstrate only on your own instance/lab; don't take down shared prod. Report the risk without triggering an outage.

**Q56. What is property injection into responses?** Using SSPP to set framework option properties (`exposedHeaders`, `status`, `location`, cache) that change response headers/behavior → chain to CORS abuse, open redirect, cache poisoning.

**Q57. Can PP bypass CSP?** Sometimes — client-side, a gadget can inject a `script-src`-allowed value or a nonce, or the DOM-XSS gadget uses an allowed sink; it depends on the CSP and gadget.

**Q58. Can PP disable security checks generally?** Yes — any check reading an undeclared prop (`obj.sanitize`, `obj.validate`, feature flags) can be flipped, weakening validation/sanitization elsewhere.

**Q59. Is `toString`/`valueOf` pollution useful?** Overriding inherited `toString` can affect string coercions widely (logging, template output) — occasionally a gadget/DoS vector; test carefully (very disruptive).

**Q60. What's the difference between polluting `Object.prototype` and `Array.prototype`?** `Array.prototype` pollution affects arrays (indices, iteration) — can break/redirect array-driven logic; `Object.prototype` is broadest. Some gadgets specifically need array pollution.

---

## Level 6 — Bypasses

**Q61. `__proto__` key is stripped — bypass?** Use `constructor.prototype` / `constructor[prototype][x]`. Also try `__proto__[__proto__]`, encodings, or a strip-once filter fooled by `__pro__proto__to__`.

**Q62. How do encodings help?** URL-encode the key (`%5f%5fproto%5f%5f`) or use bracket vs dot notation to slip past naive string filters that match the literal `__proto__`.

**Q63. What about JSON parsers and duplicate keys?** Some parsers handle duplicate/`__proto__` keys differently; a parser differential can let `__proto__` survive sanitization on one layer but be honored on another.

**Q64. How do array indices bypass?** `?__proto__[0]=x&__proto__[1]=y` or numeric keys can pollute in ways that string-key filters miss, and can target `Array.prototype` behavior.

**Q65. Can you bypass `Object.freeze(Object.prototype)`?** If the prototype is frozen, `Object.prototype` writes fail silently — but `Array.prototype`/other prototypes may be unfrozen, and some sources target those. Freezing is strong defense but not always complete.

**Q66. How does `--disable-proto` affect you?** Node's `--disable-proto=delete|throw` removes/neutralizes the `__proto__` accessor, killing that vector — but `constructor.prototype` sources may remain. Test both.

**Q67. What is a "gadget chain" in PP?** Pollution enabling one gadget whose effect enables another (e.g., disable a sanitizer flag → then land an XSS gadget). Chaining multiple polluted properties.

**Q68. Can PP be triggered via file uploads / webhooks?** Yes — any JSON/structured input that gets deep-merged (webhook payloads, imported settings, uploaded config) is a source vector.

**Q69. How do you bypass an allow-list of merge keys?** Nest the polluting key deeper, use `constructor.prototype`, or find a second merge that isn't allow-listed. Allow-listing must cover `constructor` too.

**Q70. Why test both client and server on the same app?** They're independent surfaces with different sources/gadgets; a hardened client can hide a vulnerable server merge and vice-versa.

---

## Level 7 — Client-side gadgets & DOM-XSS

**Q71. Name libraries with documented client PP gadgets.** jQuery (`$.extend`, `htmlPrefilter`, `$(html)`), Google Analytics/gtag, Segment analytics.js, Closure, Wistia, Adobe DTM/Launch, sanitize-html/DOMPurify configs, Knockout — see PortSwigger's catalog.

**Q72. How does a jQuery `$.extend` gadget lead to XSS?** Polluting a property that `$.extend` merges into an options object later used to build HTML (e.g., a template/option read into `.html()`), injecting your markup into a sink.

**Q73. How can PP bypass a sanitizer?** Pollute the sanitizer's config (e.g., DOMPurify `RETURN_DOM`, `ALLOWED_ATTR`, or a flag) so it permits your payload, defeating an otherwise-safe sanitize call.

**Q74. What sinks matter for client PP-XSS?** `innerHTML`/`outerHTML`, `script.src`, `iframe.src`/`srcdoc`, `eval`/`Function`/`setTimeout(string)`, `location`/`a.href` (javascript:), and framework template compilers.

**Q75. Example end-to-end client PP-XSS?** `?__proto__[src]=data:,alert(document.domain)` where an analytics loader does `s.src = cfg.src` reading `cfg` off the polluted prototype → script with your `src` executes.

**Q76. Does the victim need to do anything?** Usually just open the crafted URL (the pollution is in a query/hash param), then the page's own code fires the gadget on load. That's a deliverable, one-click DOM-XSS.

**Q77. How do you prove client PP-XSS safely?** `alert(document.domain)` or a benign OOB beacon, delivered to your **own** test victim; don't steal real sessions.

**Q78. Can client PP escalate to ATO?** Yes — DOM-XSS in an authenticated context can steal session tokens/perform actions → account takeover ([XSS](#/xss/guide) escalation).

**Q79. What if the gadget needs a specific property but the source only allows some keys?** Look for another source with fewer restrictions, or a different gadget matching the allowed keys; PP testing is combinatorial (sources × gadgets).

**Q80. Why is DOM Invader recommended for client PP?** It automates the tedious source-discovery and gadget-matching across the loaded scripts, surfacing exploitable source→sink pairs you'd otherwise hand-hunt.

---

## Level 8 — Chaining & escalation

**Q81. Turn confirmed SSPP into RCE — steps?** Identify the app's template engine / child_process usage → pick the matching gadget (EJS `outputFunctionName`, Pug `compileDebug`, `NODE_OPTIONS`) → pollute → trigger the render/spawn → one benign command proof.

**Q82. Chain PP with file upload.** Upload a JS file, then pollute `env.NODE_OPTIONS=--require=/path/to/upload.js`; the next spawned Node process requires it → RCE ([File Upload](#/fileupload/guide)).

**Q83. Chain PP with CORS.** SSPP-inject `exposedHeaders`/`origin` to weaken CORS, enabling cross-origin reads ([CORS](#/cors/guide)).

**Q84. Chain PP with open redirect / cache.** Inject a `location`/cache property via SSPP → open redirect or cache poisoning ([Host Header](#/hostheader/guide)).

**Q85. Relationship between PP and NoSQLi?** Both abuse attacker-controlled object keys in JSON; a `__proto__` key in a Mongo query body can pollute *and* the operators inject — test both on JSON APIs ([NoSQL Injection](#/nosqli/guide)).

**Q86. Client PP → account takeover path?** Pollute a gadget property → DOM-XSS in the authenticated app → exfiltrate session/token or perform privileged actions → ATO.

**Q87. Can PP weaken other defenses to enable a second bug?** Yes — flip a `sanitize`/`validate`/feature-flag property to disable a control, then exploit the now-unprotected path (e.g., an XSS that was previously sanitized).

**Q88. What makes PP a "process-wide" primitive vs a per-request bug?** Server-side, the prototype is shared across the whole Node process, so one pollution affects every subsequent request/user until restart — a broad, high-severity blast radius.

**Q89. How do you demonstrate reach for severity?** Show an unrelated request/user is affected (the oracle changed for a different endpoint/session), proving process-global impact, not a single-request quirk.

**Q90. When is PP only Medium/Low?** A confirmed source with a benign global effect but no reachable gadget and no security-relevant property injection — real but limited; report the primitive honestly with the demonstrated effect.

---

## Level 9 — Validity, severity, defense

**Q91. What does a real PP finding require?** Proof of **global pollution** (fresh object carries it / SSPP oracle flips) **plus** a concrete impact (fired gadget → RCE/XSS, admin access, or security-relevant property injection). A set-but-inconsequential property is a primitive, not a bug.

**Q92. Top false positives to auto-reject?** Reflected `__proto__` (not global); `?__proto__[x]=y` returning 200 with no proven effect; `Object.prototype.x` set but no gadget/impact; a one-off oracle blip; a "known gadget" whose sink never fires; self-only hash pollution.

**Q93. CVSS for server PP→RCE?** ~`CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` ≈ 9.8 (Critical), adjusting PR/UI for auth/interaction. Client DOM-XSS ≈ High.

**Q94. Core remediation?** Reject `__proto__`/`constructor`/`prototype` keys in merge/set/clone (or use safe implementations); use `Object.create(null)`/`Map` for user-keyed data; schema-validate input (`additionalProperties:false`); upgrade vulnerable deps.

**Q95. How does `Object.freeze(Object.prototype)` help and what's the catch?** It blocks writes to `Object.prototype` (defense-in-depth), but must be applied carefully (some libs write legitimately) and doesn't cover other prototypes.

**Q96. What Node flags harden against PP?** `--disable-proto=delete` (or `throw`) removes the `__proto__` accessor; combine with input validation (doesn't stop `constructor.prototype` sources alone).

**Q97. Why isn't upgrading lodash/jQuery a complete fix?** It fixes those libraries' known sources, but **application-level** merges/sets and other deps can still be vulnerable — you must fix the app's own object handling too.

**Q98. How should user-keyed maps be stored to avoid PP?** Use `Map`, or objects created with `Object.create(null)` (no prototype), so attacker keys can't reach `Object.prototype`.

**Q99. What must a SAFE-PoC for PP always respect?** Benign markers only; no app-breaking property on shared prod; RCE = one command then stop; note that server pollution persists until restart; deliver client PoCs to your own victim; redact secrets.

**Q100. One thing to remember about prototype pollution?** *An attacker who controls an object key can control a variable the developer never declared.* Find the **source** (a merge/set that accepts `__proto__`), confirm it pollutes **globally**, then land the **gadget** that turns a shared-prototype property into RCE, XSS, or admin. **Report the impact — Source + Gadget — not the set property.**

---

## Defense quick-reference
- **Reject** `__proto__`/`constructor`/`prototype` keys in recursive merge/set/clone; use vetted safe-merge.
- **`Object.create(null)`** or **`Map`** for user-keyed data; never merge arbitrary user JSON into config.
- **Schema-validate** input (`additionalProperties:false`, typed fields).
- **`Object.freeze(Object.prototype)`** (defense-in-depth, tested) + Node **`--disable-proto=delete`**.
- **Upgrade** lodash ≥4.17.12, jQuery ≥3.4.0, minimist/yargs-parser patched; audit `_.merge`/`$.extend(true)`/`_.set` usage.
- Match remediation to both surfaces: server merges **and** client library gadgets.
