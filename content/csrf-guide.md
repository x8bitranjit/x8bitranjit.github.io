# Cross-Site Request Forgery (CSRF) — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Cookie-authenticated web apps & APIs — account settings, auth changes, payments, integrations, admin actions, OAuth/SSO, GraphQL
**Platforms:** Browser-driven (real browsers required for validity); Kali/Windows helper scripts provided
**Companion files in this folder:**
- `CSRF_ARSENAL.md` — PoC HTML templates (auto-submit form, GET, JSON, multipart), bypass strings, SameSite matrix
- `CSRF_CHECKLIST.md` — the testing-order checklist you tick per action
- `CSRF_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — a CSRF-PoC generator (request → ready HTML) + template library

> **Companion to the XSS / JWT / Recon / FileUpload / SSRF guides.** Same philosophy: *find* is Part I–III, *get paid* is Part IV. But CSRF is **different from every other class in this series**: it's the most **over-reported and auto-closed** bug class on the planet, because since 2020 browsers default cookies to **SameSite=Lax**, which silently kills most classic CSRF. The expert skill here is *validity* — knowing the narrow conditions where CSRF still fires in 2026, proving it in a **real browser**, and **leading with the account-takeover impact**, not "no CSRF token." Read Part IV *first* if you've ever had a CSRF report closed as N/A.

---

> ### ⚡ READ THIS FIRST — why 90% of CSRF reports are auto-closed (and how to be the 10%)
> 1. **SameSite=Lax is the browser default now.** Chrome/Edge/Firefox default cookies to `SameSite=Lax`, which means **cross-site POST requests don't carry the session cookie** — so the "classic" form-POST CSRF *silently fails in a real browser*. If you only tested by deleting the token in Burp Repeater (which runs *same-site*), you proved nothing. **Check the cookie's `SameSite` attribute first** (§4) — it's the gate.
> 2. **CSRF requires cookie-borne, auto-sent credentials.** If the app authenticates with a **Bearer token in a header / localStorage** (not a cookie), there is **no CSRF** — the browser won't attach the token automatically. Confirm the auth model before anything else (§4).
> 3. **CSRF that *still works* in 2026 is specific:** `SameSite=None` cookies (SSO/embeds/APIs), **GET-based state changes** (Lax *allows* top-level GET navigations), subdomain/same-site position, broken/absent token validation, or a Referer/Origin check you can bypass. Those are the real bugs (Part II).
> 4. **Raw CSRF is discounted; the ATO is the bounty.** "CSRF on change-email" is a finding because it → **account takeover**, not because a token was missing. Lead with the impact chain: CSRF → change recovery email/password/2FA → ATO (§11, §22).
> 5. **Prove it in a real, default browser.** A valid CSRF PoC is an HTML page that, when the logged-in victim opens it in **Chrome with default settings**, performs the action. If your PoC only works with SameSite disabled, it's not a real-world bug — say so or don't report it (§19, §23).
>
> **In plain words — the analogy (used throughout):** your browser is an **over-eager assistant who automatically staples your ID badge (your session cookie) onto every letter addressed to a site you're logged into** — no matter *who* wrote the letter. CSRF is a stranger writing the letter ("*change this account's email to mine*"), tricking your assistant into mailing it, and the site obeying because your badge rode along and it looks like *you* sent it. The whole attack is abusing that autopilot. **`SameSite` is a newer rule the assistant follows about *when* to staple the badge on** — and since 2020 the default (`Lax`) means the assistant *won't* staple it onto the sneaky cross-site letters (a background POST), only onto letters you clearly walked in and delivered yourself (clicking a link = a top-level GET). That default is why most old-school CSRF quietly stopped working — and why the whole first half of this guide is about the narrow cases where the badge still gets stapled.
>
> **Where the money is (memorize this order):** ① **CSRF → ATO** (change email/password/2FA/recovery, with no old-password & a bypassable/absent token) → ② **CSRF on financial/admin actions** (transfer, add-admin, role change) → ③ **CSRF + self-XSS → stored XSS → ATO** (turning a "won't fix" self-XSS into impact) → ④ **OAuth CSRF** (missing `state` → account linking takeover) → ⑤ *then* login CSRF and low-value-action CSRF as **Low**, and logout/preference CSRF as **Info** (often N/A).

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [CSRF Anatomy & the SameSite Reality (2026)](#2-csrf-anatomy--the-samesite-reality-2026)
3. [Reconnaissance — Find State-Changing Actions](#3-reconnaissance--find-state-changing-actions)
4. [Baseline — Is It Even CSRF-able?](#4-baseline--is-it-even-csrf-able)

**PART II — PROTECTION BYPASS (work in this order)**
5. [Anti-CSRF Token Bypasses](#5-anti-csrf-token-bypasses)
6. [SameSite Cookie Bypasses](#6-samesite-cookie-bypasses)
7. [Referer / Origin Check Bypasses](#7-referer--origin-check-bypasses)
8. [Content-Type / JSON CSRF](#8-content-type--json-csrf)
9. [Double-Submit Cookie & Custom-Header Bypasses](#9-double-submit-cookie--custom-header-bypasses)
10. [Method & Parameter Tricks](#10-method--parameter-tricks)

**PART III — VARIANTS & EXPLOITATION BY IMPACT (where the money is)**
11. [Account-Takeover CSRF (email / password / 2FA)](#11-account-takeover-csrf)
12. [Login CSRF](#12-login-csrf)
13. [JSON / API CSRF](#13-json--api-csrf)
14. [CSRF + Self-XSS → Stored XSS](#14-csrf--self-xss--stored-xss)
15. [OAuth / SSO CSRF (missing `state` → account linking)](#15-oauth--sso-csrf)
16. [GraphQL CSRF](#16-graphql-csrf)
17. [CORS-Misconfiguration CSRF](#17-cors-misconfiguration-csrf)

**PART IV — VALIDITY, SEVERITY & REPORTING (the heavy part for CSRF)**
18. [The Escalation Mindset](#18-the-escalation-mindset)
19. [The Validity-First Mindset — the SameSite gate](#19-the-validity-first-mindset--the-samesite-gate)
20. [False Positives — STOP reporting these](#20-false-positives--stop-reporting-these-auto-reject-list)
21. [Severity Calibration](#21-severity-calibration--how-triagers-really-rate-csrf)
22. [Impact-Escalation Playbooks — "you found X, now do Y"](#22-impact-escalation-playbooks--you-found-x-now-do-y)
23. [Building a Professional PoC That Fires in a Real Browser](#23-building-a-professional-poc-that-fires-in-a-real-browser)
24. [Reporting, CWE/CVSS & De-duplication](#24-reporting-cwecvss--de-duplication)
25. [Automation & Red-Team Notes](#25-automation--red-team-notes)

**Appendices**
- [Appendix A — CSRF Workflow Cheat Sheet](#appendix-a--csrf-workflow-cheat-sheet)
- [Appendix B — CSRF Decision Tree](#appendix-b--csrf-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Each phase says *what to do*, *which § for detail*, and the *deliverable*. Numbered sections (1–25) are the reference detail; this is the order you execute.

```
PHASE 0  RECON & LAB        → find state-changing actions (§3) · two browser profiles + an attacker page host (§1)
PHASE 1  BASELINE  ★        → is auth COOKIE-based? what's the cookie's SameSite? token present? Referer/Origin/CT checks? (§4)
                              ← this phase decides whether CSRF is even POSSIBLE. Don't skip it.
PHASE 2  PROTECTION BYPASS  → defeat the control standing in your way:
                              token (§5) · SameSite (§6) · Referer/Origin (§7) · content-type/JSON (§8) ·
                              double-submit/custom-header (§9) · method/param tricks (§10)
PHASE 3  IMPACT  ⭐ (money)  → make it an ATO/financial/admin chain:
                              email/pw/2FA CSRF→ATO (§11) · login CSRF (§12) · JSON CSRF (§13) ·
                              CSRF+self-XSS (§14) · OAuth state (§15) · GraphQL (§16) · CORS (§17)
PHASE 4  VALIDATE → REPORT  → ★ FIRES IN A REAL DEFAULT BROWSER? (§19) · false-positive filter (§20) ·
                              severity+CVSS+CWE-352 (§21) · clean PoC HTML (§23) · dedup (§24)
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon & lab.** Enumerate every **state-changing** action (§3). Set up **two browser profiles** (victim logged-in, attacker), and a place to host the PoC HTML. *Deliverable:* a list of sensitive actions + their exact requests.
2. **PHASE 1 — Baseline ⭐ (the gate).** For each action: is auth via a **cookie** (auto-sent)? What is that cookie's **`SameSite`**? Is there an **anti-CSRF token**? Does the server check **Referer/Origin** or require a **custom header / JSON content-type**? (§4) *Deliverable:* a per-action verdict on whether CSRF is even possible, and which control blocks it.
3. **PHASE 2 — Protection bypass.** Defeat the specific blocking control: token (§5), SameSite (§6), Referer/Origin (§7), content-type (§8), double-submit/custom-header (§9), method tricks (§10). *Deliverable:* a forged cross-site request the server accepts.
4. **PHASE 3 — Impact ⭐.** Aim the CSRF at an **ATO/financial/admin** action and chain it (§11–§17). *Deliverable:* a demonstrated high-impact outcome (account takeover, money, admin).
5. **PHASE 4 — Validate → report.** **The validity gate: confirm the PoC fires in a real, default-settings browser** (§19). Apply the false-positive filter (§20), set a defensible CVSS/CWE-352 (§21), ship a clean PoC (§23), de-dup (§24). *Deliverable:* the submitted report.

Reference anytime: templates → `CSRF_ARSENAL.md`; checklist → `CSRF_CHECKLIST.md`; PoC generator → `poc/`; playbooks **§22**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

CSRF is **browser-validated** — your most important tool is a **real browser with default settings**, because that's the only place SameSite behaves like a victim's. Repeater/curl run *same-site* and will lie to you.

| Tool | Job |
|------|-----|
| **Two browser profiles** (Chrome/Firefox) | victim (logged in) + attacker; **default settings** (don't disable SameSite) |
| **Burp Suite** | capture the target request; **"Engagement tools → Generate CSRF PoC"** for a quick template |
| **`poc/csrf_poc_generator.py`** | turn a raw HTTP request into ready auto-submit HTML (form/GET/JSON/multipart) |
| **A web host for the PoC** | a different origin (your domain / ngrok / a static host) — CSRF must come from **cross-site** |
| **Browser DevTools → Application → Cookies** | read each cookie's **SameSite / Secure / HttpOnly / Domain** (the baseline, §4) |
| **DevTools → Network** | inspect whether the action sends a token, what content-type, what method |
| **interactsh / your server logs** | confirm the cross-site request actually reached the target (and from the victim) |

```bash
# Generate a PoC from a saved request (see poc/):
python3 poc/csrf_poc_generator.py --request req.txt --type auto --out poc.html
# Host it on a DIFFERENT origin than the target (CSRF is cross-site):
python3 -m http.server 8000      # then open http://localhost:8000/poc.html in the VICTIM browser
```
> **The cardinal rule of CSRF tooling:** *validate in a real browser, cross-origin, with default SameSite.* "I removed the token in Repeater and it worked" is **not** a CSRF PoC — Repeater is same-site and supplies the victim's own cookies/token. (See §19.)

> **Windows:** everything here works on Windows browsers; run the Python generator in WSL or native Python. Use two separate Chrome **profiles** (not just incognito) so the victim session persists.

---

# 2. CSRF Anatomy & the SameSite Reality (2026)

## 2.1 What CSRF is
The attacker makes the **victim's browser** send an **authenticated, state-changing** request to the target. It works because the browser **automatically attaches the session cookie** to requests to that site — even when the request originates from the attacker's page. The server can't tell the request wasn't intended by the user.

> *In plain words:* the key insight is that **cookies are sent by the browser automatically, based on *where the request is going*, not *who started it*.** So when your evil page tells the victim's browser "POST to target.com/change-email," the browser goes "oh, target.com — I have a cookie for that" and attaches the victim's login without asking. To the server it looks identical to the victim clicking the button themselves. That's why CSRF needs no password and no XSS — it just borrows the victim's already-logged-in browser as a puppet. (And that's also why it *only* works for cookie auth: a `Authorization: Bearer` token isn't auto-attached, so there's nothing to borrow.)

## 2.2 The four preconditions (ALL must hold)
```
1. COOKIE-based session that the browser auto-sends   → if auth is a Bearer header/localStorage token: NO CSRF.
2. A STATE-CHANGING action (not just a read)          → reads aren't CSRF (that's a CORS/info problem).
3. PREDICTABLE request (attacker knows all params)    → no unguessable secret in the body the attacker can't know.
4. NO effective anti-CSRF defense, OR you bypass it   → token / SameSite / Referer-Origin / custom-header / content-type.
```
If any precondition fails, there's no CSRF. **Precondition 1 + the cookie's SameSite is the whole ballgame in 2026.**

## 2.3 The SameSite cookie attribute (the modern gatekeeper)
> *In plain words:* `SameSite` is the cookie setting that decides "when will the browser auto-attach me on a cross-site request?" — and it's *the* thing that makes or breaks CSRF in 2026. Three values: **`Strict`** = never send on anything cross-site (CSRF basically dead). **`Lax`** (today's *default*, even if the site sets nothing) = only send when the victim does a **top-level navigation with GET** — i.e. clicks a link or the address bar changes — but **not** on a background cross-site POST/`fetch`/image/iframe. **`None`** = send on everything cross-site (classic CSRF fully alive; used by SSO/embeds/payment iframes). So your first question on any target is always "what's this session cookie's SameSite?" — it tells you whether you're hunting a GET action (Lax), anything goes (None), or should walk away (Strict).

```
SameSite=Strict  → cookie NEVER sent on any cross-site request. CSRF effectively dead for this cookie.
SameSite=Lax     → cookie sent only on TOP-LEVEL GET navigations (clicking a link / window.location).
                   NOT sent on cross-site POST, fetch, XHR, iframe, img.  ← THIS IS THE BROWSER DEFAULT.
                   ⇒ classic cross-site form-POST CSRF FAILS by default.
                   ⇒ but GET-based state changes (top-level navigation) STILL fire under Lax!  (§6)
SameSite=None    → cookie sent on ALL cross-site requests (must also be Secure). ← CSRF is fully possible. (§6)
(no attribute)   → browsers TREAT AS Lax by default (Chrome/Edge/Firefox).  ← assume Lax unless proven None.
```

## 2.4 The 2026 mental model
```
Step 1: Is the session cookie SameSite=None?  → classic CSRF (POST/JSON/etc.) is on the table → Part II/III.
Step 2: Is it Lax (or default)?               → only GET-based state changes work (§6); POST CSRF needs a SameSite bypass.
Step 3: Is it Strict?                          → cross-site is dead; CSRF only via a SAME-SITE position (subdomain XSS/takeover, §6.4).
Step 4: Is auth a cookie at all?               → if Bearer/localStorage token: NO CSRF, stop (it's not this class).
```

> **The expert difference is entirely here.** Beginners send a form POST, see it work in Repeater, and report "CSRF." Experts read the cookie's SameSite, realize default-Lax kills the POST, and either (a) find a **GET-based** sensitive action, (b) find a **SameSite=None** cookie, (c) find a **same-site position** (subdomain), or (d) move on. Knowing when to *move on* is half the skill.

---

# 3. Reconnaissance — Find State-Changing Actions

CSRF only matters on **sensitive state changes**. Map them and rank by impact.

```
□ Account / auth (highest):  change email · change password (esp. WITHOUT old password) · change/disable 2FA ·
                             add recovery email/phone · add passkey/WebAuthn · add API key/token · add SSH key ·
                             connect/disconnect OAuth · change security questions
□ Privilege / admin:         add user · change role/permissions · invite member · transfer ownership · disable logging
□ Financial:                 transfer/withdraw · change payout/bank details · place/cancel order · apply coupon ·
                             change billing address · subscribe/cancel
□ Data / integrity:          delete account/data · change critical settings · post content (→ self-XSS chain, §14) ·
                             change webhook/redirect URLs · import-from-URL (→ pair with SSRF guide)
□ Low value (usually Info):  change theme/language/preferences · logout · mark-as-read · non-sensitive toggles
```
**How to enumerate:** walk every settings/admin page in the victim browser with DevTools open; record each **state-changing request** (method, URL, params, content-type, whether a token is present). Grep JS/swagger (Recon guide §15/§16) for POST/PUT/DELETE routes.

> **If this → then that:** a **change-email** or **change-password (no old password)** endpoint → that's your ATO target; everything in Part II is about reaching *it*. A purely **GET** sensitive action (e.g. `/account/delete?confirm=1`) → CSRF works even under default-Lax (§6) — fast win.

---

# 4. Baseline — Is It Even CSRF-able?

**Do this before building any PoC.** Five questions decide whether CSRF is possible and what (if anything) blocks it.

> *In plain words:* this is the **gate that saves you from the #1 CSRF mistake** — reporting a "CSRF" that a browser silently blocks. Before you build anything, answer: is the login a **cookie** (the auto-attached thing CSRF needs)? what's that cookie's **SameSite**? is there a **token**, and is it actually checked? does the server check **Referer/Origin** or demand **JSON/a custom header**? Each answer either rules CSRF out or tells you exactly which control you must bypass. Crucially, **Burp Repeater will lie to you here** — it runs same-site and sends your own cookie+token, so *everything* "works" in Repeater. The only truth is a cross-site PoC in a real default browser (§4.2).

## 4.1 The five baseline questions (per action)
```
Q1. Is the action authenticated by a COOKIE the browser auto-sends?
     DevTools → Network → the request: is there a Cookie header carrying the session? (vs Authorization: Bearer)
     → Bearer/localStorage token only ⇒ NO CSRF. Stop. (§20.4)

Q2. What is that cookie's SameSite? (DevTools → Application → Cookies)
     → None  ⇒ classic CSRF possible.
     → Lax/empty ⇒ only GET state-changes, or you need a SameSite bypass (§6).
     → Strict ⇒ cross-site dead; need same-site position (§6.4).

Q3. Is there an anti-CSRF TOKEN in the request? (a csrf/_token/authenticity_token param or header)
     → present ⇒ test whether it's actually VALIDATED (§5).
     → absent ⇒ one less control; go to Q4.

Q4. Does the server check REFERER or ORIGIN?
     → send the request with a foreign/blank Referer & Origin (Burp) and see if it's rejected (§7).

Q5. Does it require a non-simple CONTENT-TYPE (application/json) or a CUSTOM HEADER (X-Requested-With)?
     → json/custom-header enforced ⇒ a plain HTML form can't send it (CORS-simple limits); bypass needed (§8/§9).
```

## 4.2 The decisive test (don't trust Repeater)
The **only** authoritative test: build the cross-site PoC and **open it in a real, default-settings browser as the logged-in victim.** If the action happens, it's real CSRF. If it doesn't (cookie withheld by SameSite, token enforced), it's not — regardless of what Repeater showed.
```
Repeater/curl  → runs SAME-SITE, sends the victim's own cookie + token → ALWAYS "works" → MEANINGLESS for CSRF.
Real browser, cross-origin, default SameSite → the ground truth.
```

## 4.3 The verdict you produce here
```
Cookie auth + SameSite=None + no token (or bypassable) + no Referer/CT check  → strong CSRF, go build the ATO chain.
Cookie auth + Lax + a GET sensitive action                                    → GET CSRF works (§6.1).
Cookie auth + Lax + POST + token enforced                                      → likely NOT exploitable; need a real bypass or drop.
Bearer/localStorage auth                                                        → NOT CSRF. Stop.
```

> **This phase saves you from the #1 CSRF mistake:** reporting a "CSRF" that SameSite or a token actually blocks. The honest baseline verdict is what keeps your reports valid and your reputation intact (§19/§20).

---

# PART II — PROTECTION BYPASS (work in this order)

> Bypass the *specific* control your baseline (§4) identified. Templates and strings are in `CSRF_ARSENAL.md`.

# 5. Anti-CSRF Token Bypasses

A token is only protective if it's **validated and bound to the victim's session.** Test each weakness:

> *In plain words:* an anti-CSRF token is a secret random value the real page embeds in its forms, which the attacker's page can't know or guess — so the server can tell a genuine submission from a forged one. But a token only works if the server actually **checks it** *and* checks it **belongs to this specific user**. Two shockingly common failures: (1) the server never really validates it (delete the token → still accepted), or (2) it accepts *any* valid token, not just the victim's (so you grab a token from *your own* account, paste it into the attack, and it passes). Either way the token is just decoration. Always test both before assuming a token protects the action.
```
□ Token NOT validated:        remove the token param entirely / send empty → still accepted? ⇒ CSRF.
□ Token not tied to session:  use YOUR OWN valid token in the victim's request (tokens are interchangeable) ⇒ CSRF
                              (attacker fetches a token from their session, embeds it in the PoC).
□ Validation by presence only:any value of the right length/format accepted ⇒ supply a static one.
□ Method-dependent:           token enforced on POST but the action also works via GET (no token) (§10).
□ Token leaked:               appears in a GET URL/Referer/response body reachable cross-site ⇒ steal then use.
□ Token predictable:          derived from username/timestamp/sequential ⇒ compute it.
□ Double-submit weakness:     token = a cookie value the attacker can SET (subdomain/cookie injection) ⇒ control both (§9).
□ Token shared across users:   one global token / reused ⇒ embed it.
```
> **The most common real bug:** the token is sent but **not actually checked**, or **not bound to the session** (any valid token works). Always try (a) deleting it and (b) using your own account's token in the cross-site request. If either is accepted, the token is decorative.

---

# 6. SameSite Cookie Bypasses

This is the heart of modern CSRF. Your bypass depends on the cookie's SameSite value (from §4).

## 6.1 GET-based state change (works under default Lax)
`SameSite=Lax` **still sends the cookie on top-level GET navigations.** So if a sensitive action accepts **GET**, a simple link/redirect/`window.location` fires it cross-site:

> *In plain words:* here's the crack in the default-Lax armor. Lax blocks sneaky background requests but **still attaches the cookie when the victim "walks in the front door"** — a top-level navigation via GET (they click your link, or your JS runs `window.location=...`). So if the target foolishly lets a *sensitive action* happen over a plain GET (`/account/delete?confirm=1`), you don't need any bypass at all — a link or a redirect fires it and the cookie tags along under default Lax. The catch (next paragraph): this only works for **top-level navigations**; an `<img>` or hidden `<iframe>` is a *background* request, so Lax withholds the cookie there.
```html
<!-- Lax allows this: top-level GET navigation carries the cookie -->
<a href="https://target.com/account/email/change?email=attacker@evil.com">click</a>
<script>window.location='https://target.com/account/delete?confirm=1';</script>
<img src="https://target.com/account/disable2fa?x=1">   <!-- img is a GET but NOT top-level → Lax does NOT send cookie; use navigation -->
```
> **Key nuance:** under Lax, only **top-level navigations** (the address bar changes) carry the cookie — `<img>`/`<iframe>`/`fetch` do **not**. Use `window.location`, a form with `method=GET` auto-submitted, or a link. Find a **GET** sensitive endpoint and Lax is defeated.

## 6.2 SameSite=None cookies (classic CSRF fully works)
If the session cookie is explicitly `SameSite=None` (common for SSO, embedded widgets, APIs, payment iframes), **all** cross-site methods send it → classic POST/JSON/multipart CSRF is on the table (Part III).

## 6.3 The "Lax+POST" 2-minute window (legacy, shrinking)
Chrome historically allowed cross-site **top-level POST** to send Lax cookies **within 2 minutes** of the cookie being set. Being removed; don't rely on it, but if the victim just logged in, a top-level POST may still fire. Note it as fragile.

## 6.4 Same-site position (defeats even Strict)
`SameSite` is about **site** (eTLD+1), not origin. A request from `sub.target.com` is **same-site** to `target.com` → cookies flow. So:

> *In plain words:* "same-**site**" is looser than "same-**origin**." Origin = exact scheme+host+port; site = just the registrable domain (`target.com`, technically eTLD+1). So `evil.target.com` and `api.target.com` are *different origins* but the *same site* — and SameSite cookies (even `Strict`!) flow between them. The consequence: if you can run code on **any** subdomain of the target (via an XSS there, or by taking over a dangling subdomain), your request counts as same-site and the cookie is sent even under Strict. That's why "we set SameSite=Strict" isn't safe if a single subdomain is hackable — and why CSRF chains with subdomain XSS/takeover.
```
□ XSS on any subdomain → run the "CSRF" request from there (it's same-site → cookie sent even if Strict). (XSS guide)
□ Subdomain takeover (Recon guide §17) → host your page on a target subdomain → same-site requests.
□ An open redirect on the target that bounces to your script (rare same-site nuance).
```
> **If this → then that:** baseline says `SameSite=Strict` (cross-site dead) → don't give up: a subdomain XSS or takeover gives you a **same-site** position from which the request carries the cookie. This is why subdomain hygiene matters and why CSRF + subdomain bugs chain.

## 6.5 Method override (smuggle a POST as a GET-ish navigation)
Some frameworks honor `_method=PUT/DELETE` in a body or `X-HTTP-Method-Override`. If a state change requires PUT but the app maps a POST-with-`_method` (or even a GET) to it, you may reach it within SameSite constraints (§10).

## 6.6 SameSite=Strict (and Lax) bypass via an **on-site client-side redirect / routing gadget**
`SameSite` is decided by the **last** request's context. If a **same-site** page on the target re-issues the state-changing request (a redirect or a client-side router navigation), the *final* request is same-site → **Strict/Lax cookies flow** even though *you* started cross-site. Look for an **on-site redirect gadget**:
```
□ Client-side (JS) open redirect on the target: target.com/go?to=/account/delete  (JS does location=to) → you navigate
  the victim cross-site to that on-site URL; the target's own JS then issues the SAME-SITE request → cookie sent.
  (Server-side 302s usually DON'T help — the browser still treats the resulting nav as cross-site for the cookie;
   it's the SAME-SITE *client-side* navigation/redirect that re-classifies the request.)
□ SPA client-side routing: a route like #/account/delete that the app's router turns into a same-site fetch/XHR with the
  cookie → trigger it via a top-level nav to the target page carrying that fragment/param.
□ Any 1-click on-site gadget that, once the victim is on target.com, fires the sensitive request same-site.
```
> **If this → then that:** baseline says `SameSite=Strict`/`Lax` blocks your POST → hunt an **on-site client-side redirect or SPA-router gadget** (a `?to=`/`#/` that the target's own JS follows). Land the victim on that target URL via a top-level navigation; the target then issues the request **same-site** and the cookie flows — defeating Strict. This is PortSwigger's "SameSite bypass via client-side redirect," and it's the modern way Strict still falls.

## 6.7 The 307 / 308 method-preserving redirect trick
A normal cross-site form gets you a **GET or simple POST**. A **307 (or 308)** redirect is special: the browser **re-sends the SAME method AND body** to the redirect target (302/303 downgrade to GET; 307/308 do **not**). That lets you turn one request into another that you couldn't craft cross-site directly:

> *In plain words:* redirects come in two flavors that matter here. A `302`/`303` redirect tells the browser "go there, but as a fresh **GET**" — it throws away your POST body. A `307`/`308` redirect says "go there and **repeat exactly what you just sent**" — same method, same body. That's a gift: if the target has any endpoint that answers `307` and lets you influence where it points, you can send a cross-site POST to *it*, and the browser faithfully re-POSTs your original body onward to the *real* sensitive endpoint — reaching methods/bodies a plain HTML form could never craft directly. (And if that 307 lands on a same-site URL, it combines with the client-side-redirect trick above so the cookie survives even Strict.)
```
□ Reach a method/endpoint forms can't produce: point a cross-site simple POST at a target URL that 307-redirects to the
  SENSITIVE endpoint → the method + body are preserved to the second endpoint (which a plain form couldn't target).
□ Re-POST a JSON/odd body cross-site: if an open/parameter-controlled redirector on the target answers 307 to an API
  path, the original body is replayed verbatim to that path → JSON-CSRF-style reach without a fetch.
□ Lax nuance: a 307 to a SAME-SITE endpoint can combine with the §6.6 client-side-redirect idea so the FINAL,
  method-preserving request is same-site → Strict/Lax cookie still flows.
□ Find the redirector: any endpoint returning 307/308 whose Location you influence (?url=/?next=/?redirect=), or a
  known framework 307 (trailing-slash / http→https / locale redirects often emit 307).
```
> **If this → then that:** your form can only send GET/simple-POST but the target action needs a **different method/body** → look for a **307/308 redirector** on the target: the browser **preserves method + body** across it, so a cross-site POST can be bounced into the real endpoint (and, if the 307 lands same-site, the cookie survives Strict via §6.6). 302/303 won't help (they become GET) — it must be **307/308**.

---

# 7. Referer / Origin Check Bypasses

If the server validates `Referer`/`Origin`, defeat the check:
```
□ Suppress the Referer entirely (some servers "allow if absent"):
   <meta name="referrer" content="no-referrer">         (page-level)
   <a href="..." rel="noreferrer">  ·  referrerpolicy="no-referrer"
   HTTPS→HTTP downgrade drops Referer (if target has an HTTP endpoint).
   data:/blob: iframe origin = null.
□ Weak Referer regex (substring/prefix checks):
   https://target.com.evil.com/      (target.com as a subdomain of attacker)
   https://evil.com/target.com       (target.com in the path)
   https://evil.com?target.com       /  #target.com
□ Origin null:
   sandboxed iframe (sandbox="allow-forms allow-scripts") → Origin: null  (if server allows null)
   redirect chains / data: documents → Origin: null
□ Origin not checked on GET / for some content-types.
```
> **The classic win:** the server only checks Referer **if it's present**, and accepts the request when Referer is **absent**. `<meta name="referrer" content="no-referrer">` on your PoC page strips it → check bypassed. Always test the no-Referer case.

---

# 8. Content-Type / JSON CSRF

Many APIs require `Content-Type: application/json`. An HTML form can only send **`application/x-www-form-urlencoded`**, **`multipart/form-data`**, or **`text/plain`** (the "CORS-simple" content-types) without triggering a preflight. Bypasses:
```
□ Does the server REALLY require JSON?  Try sending the same params as urlencoded or multipart — many APIs accept it.
□ text/plain JSON trick: a form can send a text/plain body that is valid JSON:
   <form enctype="text/plain" action="https://target/api" method="POST">
     <input name='{"email":"attacker@evil.com","x":"' value='"}'>     ← body becomes {"email":"attacker@evil.com","x":"="}
   </form>
   (works if the server parses text/plain bodies as JSON — some do.)
□ Flash/old tricks are dead. Don't rely on them.
□ If the server STRICTLY requires application/json AND verifies it → a simple form can't send it → likely NOT CSRF-able
   cross-site (this content-type requirement IS a (partial) CSRF defense). Note it honestly (§20).
```
> **If this → then that:** the API "requires JSON" but actually accepts `application/x-www-form-urlencoded` (very common) → a plain auto-submit form CSRFs it. If it *truly* enforces `application/json` server-side, the content-type requirement is acting as a CSRF defense and a form can't bypass it — be honest about that.

---

# 9. Double-Submit Cookie & Custom-Header Bypasses

## 9.1 Double-submit cookie pattern
The app sends the CSRF token both as a **cookie** and expects it echoed in a **param/header**, comparing the two. It fails if the attacker can **set the cookie**:
```
□ Cookie injection via a subdomain (you control sub.target.com or have XSS there) → set the csrf cookie to a known value,
  put the same value in the form → both match → bypass (the server only checks they're EQUAL, not that they're the victim's).
□ Cookie injection via CRLF/header injection or a permissive Set-Cookie path.
□ If the token cookie isn't HttpOnly and you have any script position on the site → read & submit it.
```

## 9.2 Custom-header requirement (e.g. `X-Requested-With: XMLHttpRequest`)
A required **custom header** is a **strong** CSRF defense: HTML forms can't set custom headers, and `fetch`/XHR with a custom header triggers a **CORS preflight** that a cross-origin attacker can't satisfy (unless CORS is misconfigured).
```
□ Bypass only if: CORS is misconfigured to allow the attacker origin + credentials (then fetch with the header works, §17),
  or there's a way to make the request same-origin (XSS), or the header check is inconsistently applied (some routes skip it).
□ Otherwise: a custom-header requirement effectively BLOCKS cross-site CSRF. Note it; don't report a non-working PoC (§20).
```
> Custom-header + correct CORS is the gold standard against CSRF. If you see `X-Requested-With` enforced and CORS is tight, the action is likely **not** CSRF-able — pivot to a different action or class.

---

# 10. Method & Parameter Tricks

```
□ Method override:  _method=PUT / _method=DELETE in the body, or X-HTTP-Method-Override header (if the framework honors it)
   → reach a PUT/DELETE action via a POST/GET form within SameSite limits.
□ GET↔POST interchange: the action accepts BOTH; use whichever evades the control (GET for Lax §6.1; the one without a token §5).
□ Parameter pollution: duplicate params, array syntax, nested keys to slip past validation.
□ Multi-step actions: chain two auto-submitting requests (e.g. request a change, then confirm) on the PoC page.
□ Redirect to the GET sink: POST to your own server → 302 to target GET action (top-level nav → Lax cookie sent).
```
> **If this → then that:** the sensitive action is POST-only with a token, but the same controller also handles **GET** (or honors `_method`) without the token → use the GET/override path → bypass both the token and Lax in one move.

## 10.5 Clickjacking-assisted CSRF (when the token can't be scripted)
When the request **must** carry a valid anti-CSRF token (so you can't forge it blindly) **but** the page is **framable** (missing `X-Frame-Options` / `Content-Security-Policy: frame-ancestors`), you can still force the action via **UI redress**: frame the *real* page (which has the *victim's* real token) and trick the victim into clicking the genuine submit button.
```html
<!-- the framed real page carries the victim's valid token; we just steal the click -->
<style>
  iframe{opacity:0.0001; position:absolute; top:0; left:0; width:1000px; height:800px; z-index:2;}
  #bait{position:absolute; top:<align-to-the-real-button>px; left:...px; z-index:1;}
</style>
<div id="bait">Click here to win 🎁</div>
<iframe src="https://target.com/account/settings"></iframe>   <!-- real page, real token -->
```
Requirements: the page is framable (no XFO/frame-ancestors), the action completes within the framed UI (or is multi-step you can align), and SameSite still sends the cookie **(the frame is a sub-resource → Lax does NOT send the cookie; clickjacking-CSRF works for `SameSite=None` cookies, or same-site/Strict contexts)**.
> **If this → then that:** token-based CSRF can't be scripted, but the settings page lacks `X-Frame-Options`/`frame-ancestors` **and** the session cookie is `SameSite=None` → **clickjacking-assisted CSRF**: the framed real page submits with the victim's own valid token after a redress click → state change (often ATO). This is the way "tokened" CSRF still pays. (Mind SameSite: under Lax/Strict the framed sub-resource won't get the cookie unless you're same-site.)

---

# PART III — VARIANTS & EXPLOITATION BY IMPACT (where the money is)

> Raw CSRF is discounted; **the chain to ATO/money/admin is the bounty.** Every PoC fires cross-site in a real default browser (the validity gate, §19/§23) and uses **your own two test accounts**.

# 11. Account-Takeover CSRF

The headline outcome. CSRF a victim into an action that hands you their account.

> *In plain words:* a missing CSRF token by itself is boring — triagers close it. What makes CSRF *pay* is aiming it at an action that hands you the account. The cleanest chain: CSRF the victim into **changing their account email to *your* inbox**, then click "forgot password" and receive their reset link — now you own the account. Even better if the change needs no current-password confirmation. The lesson threaded through this whole guide: don't report "no CSRF token," report "a logged-in victim who opens my page loses their account." Same request, completely different severity.

```
A) Change email/recovery → reset password:
   CSRF the "change email" (or "change recovery email") to an inbox YOU control → request password reset → own the account.
   Strongest when there's NO old-password/confirmation and NO (or bypassable) token.
B) Change password directly:
   Some apps let you set a new password WITHOUT the current one if "authenticated" → CSRF it → log in as the victim.
C) Disable / change 2FA:
   CSRF to disable 2FA or bind YOUR authenticator/recovery → removes the barrier → ATO via known/reset creds.
D) Add a passkey / API key / SSH key / OAuth grant:
   CSRF to register an attacker-controlled credential → persistent access surviving password change.
```
**PoC pattern (own two accounts):** attacker page auto-submits the "change email" request → victim (your 2nd test account) opens it in a default Chrome while logged in → the email changes to your inbox → you complete the reset → you log in as the victim. Screenshot each step. That's a defensible **High–Critical**.

> **Severity reality:** "CSRF on change-email" with a working real-browser PoC and the reset chain = **High** (often treated as ATO). The same endpoint with SameSite-Lax blocking it = **N/A**. The difference is entirely §4/§19.

---

# 12. Login CSRF

Force the victim's browser to **log into the attacker's account**. The victim then operates inside *your* account — anything they save (payment methods, searches, uploads, history) lands in the attacker's account, or sets up a follow-on attack.
```
□ CSRF the login form with the ATTACKER's credentials → victim is silently logged into attacker's account.
□ Impact: victim enters their card / personal data into attacker's account (attacker later reads it);
  or used to seed a stored-XSS/self-XSS chain (§14); or to defeat integrity of audit logs.
□ Often Low–Medium ALONE; escalate via what the victim does next.
```
> Login CSRF is real but usually **Low–Medium** unless you show a concrete harm (victim's data captured in your account, or a chain). Don't oversell it; pair it with impact.

---

# 13. JSON / API CSRF

Modern apps are JSON APIs. CSRF them when (a) the API also accepts urlencoded/multipart, (b) the text/plain JSON trick works (§8), or (c) the cookie is SameSite=None and there's no token/custom-header.
```
□ urlencoded acceptance:  send the JSON fields as a normal form → CSRF.
□ text/plain JSON form (§8) → CSRF a JSON endpoint with a plain HTML form.
□ SameSite=None + no token + no custom header → fetch()/form works cross-site.
```
> The decisive factor is again **§4**: a JSON API behind a Bearer-header token (no cookie) is **not** CSRF-able; one behind a `SameSite=None` cookie with no anti-CSRF header **is**.

---

# 14. CSRF + Self-XSS → Stored XSS

A powerful chain that **rescues a "won't fix" self-XSS**: if an input is XSS-vulnerable but only the user can inject into their own field (self-XSS), use **CSRF to inject the payload into the victim's own field** → it becomes **stored/effective XSS** in the victim's session.

> *In plain words:* "self-XSS" is XSS you can only fire in *your own* account (e.g. your own profile bio executes your own script) — programs reject it because an attacker can't make a victim paste a payload into their own settings. **CSRF removes that excuse.** You use CSRF to *save the XSS payload into the victim's own field for them* — now it's their account running your script, i.e. real stored XSS in their session → account takeover. Two bugs each rated "won't fix" (self-XSS) or "low" (CSRF) combine into one High–Critical. This is the classic way to make a self-XSS actually pay.
```
1. Find a self-XSS (a field that XSSes only when YOU put a payload in YOUR own profile).
2. Find/confirm CSRF on the "update that field" action.
3. CSRF the victim into saving the XSS payload to THEIR OWN field → it executes in THEIR session → real XSS → ATO (XSS guide).
```
> This is the canonical "self-XSS is not a vuln… unless you can deliver it" escalation (XSS guide §35.1). CSRF *is* the delivery. Two Lows become one High–Critical.

---

# 15. OAuth / SSO CSRF

OAuth flows have their own CSRF: the **`state` parameter** is the anti-CSRF token of OAuth. Missing/unvalidated `state` → **account-linking takeover**.

> *In plain words:* in a "Login/Connect with Google" flow, the `state` parameter is meant to be a random value that ties the final callback back to the browser that *started* the flow — exactly the job a CSRF token does. If the app doesn't check `state`, you can start the OAuth flow with **your** Google account, capture the resulting callback, and CSRF the *victim* into completing it — so the victim's app account gets **linked to your Google identity**. Now you just click "Login with Google" and you're inside their account. Missing `state` is CSRF wearing an OAuth costume, and it's a frequently-missed, high-impact bug.
```
□ Missing/ignored state on the callback → attacker can force the victim to link the ATTACKER's social account to the
  victim's app account (or vice-versa) → attacker logs in via "Login with Google" as the victim. → ATO.
□ CSRF on "connect/disconnect integration" (no state/token) → attach attacker-controlled identity/provider.
□ redirect_uri / pre-account-linking flaws (cross-ref JWT guide §30 OAuth and §11 jku).
```
> **If this → then that:** the OAuth callback doesn't validate `state` → craft a callback CSRF that links your identity provider to the victim's account → you can now sign in as them. Classic, high-impact, and frequently un-duped.

---

# 16. GraphQL CSRF

GraphQL is CSRF-able when it accepts **GET** queries or **form-encoded** POST and relies only on cookies:
```
□ GET-based GraphQL: ?query=mutation{...} → top-level navigation under Lax (§6.1) → CSRF a mutation.
□ form-encoded POST to /graphql (some servers accept application/x-www-form-urlencoded) → classic form CSRF.
□ Defense: if /graphql requires application/json + a custom header + checks them → not CSRF-able (note it).
```
> Many GraphQL servers accept `application/x-www-form-urlencoded` or GET for queries — test both; a state-changing **mutation** reachable that way is CSRF.

# 17. CORS-Misconfiguration CSRF

If CORS is misconfigured to **reflect the attacker origin AND allow credentials** (`Access-Control-Allow-Origin: https://evil.com` + `Access-Control-Allow-Credentials: true`), the attacker can make **credentialed `fetch`** requests cross-origin — including ones with custom headers/JSON — *and read responses*. This bypasses custom-header/JSON CSRF defenses and adds data theft.
```
fetch('https://target/api/changeEmail', {method:'POST', credentials:'include',
  headers:{'Content-Type':'application/json','X-Requested-With':'XMLHttpRequest'},
  body:'{"email":"attacker@evil.com"}'});
```
> CORS-with-credentials misconfig turns "well-defended (custom-header) actions" into CSRF-able ones *and* leaks the response. Cross-ref the recon/CORS notes; report as CORS→CSRF/ data-theft. (Requires the dangerous `ACAO:reflected + ACAC:true` combo — verify it.)

---

# PART IV — VALIDITY, SEVERITY & REPORTING (the heavy part for CSRF)

# 18. The Escalation Mindset

A triager's first question on any CSRF is **"does it work in a real browser, and what does it change?"** Answer, in descending value:
```
1. CSRF → account takeover (email/password/2FA/recovery) — fires in default browser   → High–Critical
2. CSRF → financial action (transfer/payout/order) / admin (add-admin/role)            → High
3. CSRF + self-XSS → stored XSS → ATO                                                   → High
4. OAuth state-CSRF → account linking takeover                                          → High
5. CSRF on a meaningful-but-not-ATO action (delete data, change important setting)      → Medium
6. Login CSRF (with a demonstrated harm)                                                → Low–Medium
7. CSRF on trivial actions (theme, preferences) / logout CSRF                            → Low/Info (often N/A)
```
Climb to ATO/financial/admin and **prove it in a real browser**. Raw "missing token" is not the finding; the impact chain is.

---

# 19. The Validity-First Mindset — the SameSite Gate

## 19.1 The four questions a triager asks (answer them in your report)
1. **Does it fire in a real, default-settings browser, cross-site?** Not just in Repeater. This is the make-or-break for CSRF in 2026.
2. **Is auth cookie-based and is the cookie `SameSite=None`/Lax-with-a-GET-sink?** State the cookie attributes explicitly.
3. **What's the impact?** ATO/financial/admin — named and demonstrated. Not "a token is missing."
4. **Reproducible?** A self-contained PoC HTML the triager opens while logged in, and it just happens.

## 19.2 The SameSite gate (the rule that saves your reputation)
```
Before reporting ANY CSRF, confirm in a real browser with DEFAULT SameSite:
  □ Session cookie SameSite = None?              → POST/JSON CSRF can work → proceed.
  □ Lax/empty + the action is a GET state-change? → GET CSRF works → proceed (§6.1).
  □ Lax/empty + POST + no SameSite bypass?        → it WON'T fire in a real browser → DO NOT report as CSRF.
  □ Strict, no same-site position?                → cross-site dead → not exploitable cross-site.
  □ Auth is Bearer/localStorage (no cookie)?       → NOT CSRF → don't report.
```
Test in **Chrome with default settings**. If your PoC only works after you disabled SameSite (`chrome://flags`) or only in Repeater, **it is not a real-world CSRF** — and triagers will (correctly) close it.

## 19.3 Production-scope discipline
Confirm on the **production** cookie config (SameSite can differ between staging and prod). Re-test after a fix — switching a sensitive action from GET to POST, or adding a token, is the fix; partial fixes (token added but not validated) are fresh findings.

---

# 20. False Positives — STOP reporting these (auto-reject list)

CSRF has the **longest** false-positive list of any class in this series. Internalize it.

| # | Commonly mis-reported as CSRF | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **POST CSRF where the session cookie is `SameSite=Lax`/default** | Lax withholds the cookie on cross-site POST → it doesn't fire in a real browser. | Cookie is `SameSite=None`, or there's a SameSite bypass (§6). |
| 2 | **"No CSRF token" with no PoC / no impact** | Absence of a token ≠ vulnerability if SameSite/Origin protects, or the action is trivial. | A real-browser PoC performs a sensitive action (§11). |
| 3 | **"Worked in Burp Repeater"** | Repeater is same-site & sends the victim's own cookie+token → always works → proves nothing. | It fires from a **cross-site** page in a default browser (§19). |
| 4 | **Auth is a Bearer/localStorage token (no cookie)** | The browser doesn't auto-attach it → no CSRF. | n/a (not this class). |
| 5 | **Logout CSRF** | Low/no impact; annoyance at most. | Rarely — only if logout enables a concrete attack chain. |
| 6 | **CSRF on trivial actions** (theme, language, mark-as-read, non-sensitive prefs) | No meaningful state change. | The action is actually sensitive (auth/financial/admin). |
| 7 | **Self-CSRF** (you CSRF your own account) | No cross-user effect. | Delivered to a victim (their session performs it). |
| 8 | **Login CSRF reported as Critical** | Forcing login to attacker's account is usually Low alone. | Demonstrated harm (victim's data captured / a chain) (§12). |
| 9 | **GET "CSRF" that's just a safe read** | Reads aren't CSRF (no state change). | The GET actually changes state (§6.1). |
| 10 | **Action requires a custom header / strict `application/json` + correct CORS** | A form can't send those cross-site → not exploitable. | CORS is misconfigured (§17) or the requirement isn't really enforced (§8). |
| 11 | **CSRF token present and properly validated/session-bound** | The control works. | You demonstrate it's NOT validated/bound (§5). |
| 12 | **PoC only works with SameSite disabled in the browser** | Not a real-world condition. | Works with **default** SameSite. |

> Rule of thumb: if you can't say *"with default browser settings, a logged-in victim who opens my page suffers `<sensitive change>`,"* you don't have a reportable CSRF. The single most common cause of a closed CSRF report is **SameSite** — check it (§4) before you write a word.

---

# 21. Severity Calibration — how triagers really rate CSRF

| Scenario | Typical alone | Realistic chained | What moves it |
|---|---|---|---|
| **CSRF → account takeover** (email/pw/2FA/recovery), real-browser | **High** | Critical | Full ATO of any logged-in victim. |
| **CSRF → financial action** (transfer/payout) | **High** | Critical | Money movement. |
| **CSRF → admin/role/add-user** | **High** | Critical | Privilege/mass impact. |
| **CSRF + self-XSS → stored XSS → ATO** | **High** | Critical | Chains two lows into ATO. |
| **OAuth state-CSRF → account linking ATO** | **High** | — | Sign-in as victim. |
| **CSRF on meaningful action** (delete data, change webhook) | **Medium** | High | Up by data sensitivity. |
| **Login CSRF** (with demonstrated harm) | **Low–Medium** | — | Needs a concrete consequence. |
| **CSRF on trivial action** | **Low/Info** | — | Often N/A. |
| **Logout CSRF / missing-token-no-impact** | **Info/N-A** | — | Don't lead with it. |

**CVSS / CWE:**
- CSRF→ATO: `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` → High (**8.1**). `UI:R` (victim opens the page) is inherent to CSRF. Scope is **S:U** — the forged request acts on the *same* application/security authority (the victim's own account), so it doesn't cross a scope boundary; that's part of why CSRF→ATO lands High, not Critical. (Contrast the CORS kit, where an *attacker origin* reads a *different* origin's data → `S:C`.) **CWE-352**.
- Anchor to **CWE-352** (CSRF); add the outcome (CWE-639/287 for ATO) where relevant. `UI:R` is why CSRF rarely scores Critical alone — the ATO chain is what pushes it up.

---

# 22. Impact-Escalation Playbooks — "you found X, now do Y"

### 22.1 You found: *a form/POST without a CSRF token*
- **Escalate:** **first check the cookie's SameSite (§4).** If `None` → build the cross-site PoC → aim at change-email/password → ATO (§11). If `Lax` → look for a **GET** equivalent (§6.1) or a SameSite bypass; else it's likely N/A — don't report.
- **Evidence:** the action performed from a cross-site page in a **default** browser, then the ATO chain.
- **Severity:** High (with ATO) / N/A (if SameSite blocks it).

### 22.2 You found: *a token, but unsure it's validated*
- **Escalate:** (a) delete the token param, (b) use your own account's token in the victim request, (c) try the GET/method-override path (§5/§10). If any is accepted → the token is decorative → CSRF.
- **Evidence:** the request accepted without/with-a-foreign token, in a real browser.
- **Severity:** as high as the action (ATO → High).

### 22.3 You found: *SameSite=Lax + a sensitive GET action*
- **Escalate:** GET CSRF via top-level navigation (`window.location`/link/auto-submit GET form) → the action fires under Lax (§6.1). Aim at a sensitive GET (delete/disable/change).
- **Evidence:** navigation-based PoC performing the action in default Chrome.
- **Severity:** by the action (Medium–High).

### 22.4 You found: *SameSite=Strict (cross-site dead)*
- **Escalate:** get a **same-site** position — subdomain XSS or subdomain takeover (Recon §17 / XSS guide) → run the request from there (cookie flows even under Strict) (§6.4).
- **Evidence:** the request from a `*.target.com` position performing the action.
- **Severity:** High (but now it's really an XSS/takeover→CSRF chain).

### 22.5 You found: *a self-XSS you couldn't report*
- **Escalate:** CSRF the victim into saving the XSS payload to their own field → stored XSS in their session → ATO (§14).
- **Evidence:** the CSRF saving the payload + the XSS firing in the victim (your 2nd account).
- **Severity:** High.

### 22.6 You found: *OAuth callback without `state`*
- **Escalate:** account-linking CSRF → link attacker identity to victim account → sign in as victim (§15).
- **Evidence:** the linking performed cross-site + you logging in as the victim.
- **Severity:** High.

### 22.7 You found: *JSON API, cookie auth, no token*
- **Escalate:** test urlencoded/multipart acceptance and the text/plain JSON trick (§8/§13); confirm SameSite=None. If it sends → CSRF the sensitive action.
- **Evidence:** the JSON action performed by a plain HTML form cross-site.
- **Severity:** by the action.

---

# 23. Building a Professional PoC That Fires in a Real Browser

A valid CSRF PoC is a **self-contained HTML page** that, opened by the logged-in victim in a **default-settings browser**, performs the action with **no interaction** (or one click if navigation is required).

## 23.1 The non-negotiable validity steps
```
1. Build the PoC (poc/csrf_poc_generator.py or the templates in CSRF_ARSENAL.md).
2. Host it on a DIFFERENT origin (your domain/ngrok/localhost) — CSRF is cross-site.
3. Log in as your VICTIM test account in a normal browser (DEFAULT settings — do NOT disable SameSite).
4. Open the PoC URL in that browser.
5. Confirm the action happened (email changed, etc.) — that's your proof.
6. Then complete the impact chain (reset password → log in as victim) on your OWN two accounts.
```

## 23.2 PoC forms (pick per context — full set in arsenal)
```html
<!-- Auto-submit POST form (SameSite=None) -->
<form id=f action="https://target.com/account/email" method="POST">
  <input type=hidden name="email" value="attacker@evil.com">
</form><script>f.submit()</script>

<!-- GET state-change under Lax (top-level navigation) -->
<script>window.location="https://target.com/account/email/change?email=attacker@evil.com"</script>

<!-- text/plain JSON CSRF -->
<form action="https://target.com/api/email" method="POST" enctype="text/plain">
  <input name='{"email":"attacker@evil.com","x":"' value='"}'>
</form><script>document.forms[0].submit()</script>
```

## 23.3 Make it safe & professional
```
DO:
  □ Use YOUR OWN two test accounts (attacker page changes VICTIM test-account's email to YOUR inbox).
  □ Point any "attacker" email/credential at an inbox YOU control.
  □ Keep it non-destructive & reversible; revert changes after the PoC.
  □ State the cookie's SameSite value and that the PoC fired in a DEFAULT browser (this is the credibility proof).
DON'T:
  □ Report a PoC that only works in Repeater or with SameSite disabled (§19).
  □ Fire the CSRF at real users or change real accounts.
  □ Oversell login/logout/trivial CSRF as Critical.
```
**Remediation to include:** anti-CSRF token (synchronizer, session-bound, validated server-side) on every state-changing request; `SameSite=Lax` or `Strict` on the session cookie; verify `Origin`/`Referer`; require a custom header for APIs; re-authenticate (old password / step-up) for sensitive changes (email/password/2FA); use `state` in OAuth.

---

# 24. Reporting, CWE/CVSS & De-duplication

Use `CSRF_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "CSRF on change-email (SameSite=None, no token) → account takeover"  (name the IMPACT + the why-it-works)
2. Severity     CVSS 3.1 vector + score + CWE-352 (+ outcome CWE)
3. Asset        exact endpoint + method + the cookie's SameSite value + which control is absent/bypassed
4. Summary      cookie auth + SameSite=None/GET-sink + no/bypassed token → the action → ATO
5. Steps        host PoC cross-site → log in as victim (default browser) → open PoC → action fires → reset → ATO
6. PoC          the self-contained HTML + a note it fired in DEFAULT Chrome + screenshots
7. Impact       account takeover / financial / admin — the "so what"
8. Remediation  token + SameSite + Origin check + re-auth for sensitive actions (§23.3)
```
**De-dup:** one root cause (a missing/ineffective CSRF defense) across several similar endpoints = one finding; lead with the highest-impact (the ATO one). Don't split "no token" and "ATO" — they're one report. **Always include the SameSite value** — it's the first thing the triager checks.

---

# 25. Automation & Red-Team Notes

**Automation (CSRF is mostly manual; automate the discovery):**
```
□ Burp → "Generate CSRF PoC" on any request (quick template); Burp scanner flags missing-token (verify the SameSite!).
□ poc/csrf_poc_generator.py — turn a saved request into auto-submit HTML at scale.
□ Grep responses for Set-Cookie SameSite values across the app (the validity pre-filter):
   for each Set-Cookie: note SameSite=None | Lax | Strict | (absent=Lax).
□ Param-mine state-changing endpoints (Recon/Arjun); test each for token presence + SameSite.
```
- **Quality gate:** never submit a Burp "no CSRF token" flag verbatim. **Check SameSite + build a real-browser PoC + chain to impact** (§19/§22). Most scanner CSRF flags are false positives in the SameSite era.

**Red-team angles:**
```
□ CSRF → ATO of a privileged user (admin opens a link → their account/role taken) → broad compromise.
□ CSRF + subdomain XSS/takeover → same-site position defeats even Strict (§6.4) → CSRF anything.
□ CSRF on integration/webhook/redirect-URL settings → redirect data to attacker infra (chain with SSRF).
□ Login CSRF to seed a session the victim populates with sensitive data the attacker later reads.
□ CSRF on bulk/admin actions in back-office tools reached via a targeted link to staff.
```

---

# Appendix A — CSRF Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                         CSRF WORKFLOW                              │
├────────────────────────────────────────────────────────────────────┤
│ 0. RECON: list STATE-CHANGING actions (auth/financial/admin) §3    │
│ 1. BASELINE ★ (the gate) §4:                                       │
│    Q1 cookie auth? (else NOT CSRF)  Q2 cookie SameSite=?            │
│    Q3 token? validated?  Q4 Referer/Origin check?  Q5 JSON/custom-hdr?│
│    → SameSite=None or Lax+GET-sink ⇒ possible.  Lax+POST+token ⇒ likely N/A.│
│ 2. BYPASS the blocking control:                                    │
│    token §5 · SameSite §6 (GET under Lax! / None / subdomain-Strict)│
│    · Referer/Origin §7 · content-type/JSON §8 · double-submit §9    │
│    · method/_method §10                                             │
│ 3. IMPACT ⭐ (chain it):                                            │
│    change email/pw/2FA → ATO §11 · login CSRF §12 · JSON §13        │
│    · CSRF+self-XSS → stored XSS §14 · OAuth state §15 · GraphQL §16 │
│    · CORS-cred misconfig §17                                        │
│ 4. VALIDATE → REPORT:                                              │
│    ★ FIRES IN DEFAULT BROWSER cross-site? §19  (NOT just Repeater)  │
│    false-positive filter §20 · CVSS+CWE-352 §21                    │
│    PoC HTML + state SameSite value · title=IMPACT §23/§24          │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — CSRF Decision Tree

```
A state-changing action →
│
├─ Auth via a COOKIE the browser auto-sends?
│     └─ NO (Bearer/localStorage) → NOT CSRF. Stop. (§20.4)
│
├─ Cookie SameSite = ?  (DevTools → Application → Cookies)
│     ├─ None → classic CSRF possible → check token/Referer/CT (§5/§7/§8) → build POST/JSON PoC.
│     ├─ Lax / absent →
│     │     ├─ is the sensitive action a GET (top-level nav)? → GET CSRF works (§6.1). ✔
│     │     └─ POST only? → need a SameSite bypass (subdomain §6.4 / None elsewhere) or it's N/A. ✘ (§20.1)
│     └─ Strict → cross-site dead → only via SAME-SITE position (subdomain XSS/takeover §6.4).
│
├─ Anti-CSRF token present?
│     ├─ remove it / use your own token / try GET path → accepted? → token decorative → CSRF (§5).
│     └─ properly validated + session-bound → control works → not CSRF-able (§20.11).
│
├─ Referer/Origin checked? → try no-Referer (meta no-referrer) / null Origin / weak-regex bypass (§7).
├─ Requires JSON/custom header? → urlencoded? text/plain JSON trick? CORS-cred misconfig? (§8/§9/§17). Else not CSRF-able.
│
└─ Got a forged cross-site request the server accepts?
      → aim at change-email/pw/2FA → ATO (§11) → ★ CONFIRM IN A DEFAULT BROWSER (§19) → report with impact (§24).
```

---

# Appendix C — Important Links & References

**Primary (read these first)**
- PortSwigger Web Security Academy — *Cross-site request forgery (CSRF)* (theory + labs): https://portswigger.net/web-security/csrf
- PortSwigger Web Security Academy — *Bypassing SameSite cookie restrictions* (incl. the **SameSite Strict bypass via client-side redirect** & **Lax bypass via method override**, §6.6/§6.7): https://portswigger.net/web-security/csrf/bypassing-samesite-cookie-restrictions
- OWASP — *CSRF Prevention Cheat Sheet*: https://cheatsheetseries.owasp.org/cheatsheets/Cross-Site_Request_Forgery_Prevention_Cheat_Sheet.html
- OWASP WSTG — *Testing for CSRF* (4.6.5): https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/06-Session_Management_Testing/05-Testing_for_Cross_Site_Request_Forgery

**Payloads, techniques & cheat sheets**
- PayloadsAllTheThings — *CSRF Injection*: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/CSRF%20Injection
- HackTricks — *CSRF*: https://book.hacktricks.xyz/pentesting-web/csrf-cross-site-request-forgery
- PentesterLab — CSRF badges/exercises: https://pentesterlab.com/

**Authoritative specs & browser behaviour (the SameSite ground truth, §2.3/§6)**
- MDN — *Set-Cookie: SameSite*: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Set-Cookie/SameSite
- web.dev — *SameSite cookies explained*: https://web.dev/articles/samesite-cookies-explained
- IETF — *RFC 6265bis* (cookies + SameSite): https://datatracker.ietf.org/doc/html/draft-ietf-httpbis-rfc6265bis
- Chromium — *SameSite Updates* (Lax-by-default rollout + the 2-min Lax+POST carve-out, §6.3): https://www.chromium.org/updates/same-site/
- WHATWG — *Fetch Standard* (request credentials mode / simple-request rules behind §8): https://fetch.spec.whatwg.org/

**Research & talks (the source of the modern bypasses)**
- PortSwigger Research — *SameSite bypass via client-side redirect* & OAuth `state` CSRF research: https://portswigger.net/research
- Black Hat / DEF CON — CSRF, SameSite & OAuth-`state` talks; SOHO-router CSRF DNS-hijack case studies (2014–2018)

**Real-world / bug-bounty writeups**
- Disclosed HackerOne / Bugcrowd reports — search *"CSRF → account takeover"*, *"OAuth state CSRF"*, *"SameSite bypass"*
- WordPress/plugin CSRF CVEs (frequently chained to stored XSS / settings change)

**Tooling**
- XSRFProbe (automated CSRF audit/PoC): https://github.com/0xInfection/XSRFProbe
- Bolt (CSRF scanner): https://github.com/s0md3v/Bolt
- Burp Suite — *Engagement tools → Generate CSRF PoC*

**CWE / standards to cite**
- CWE-352 — Cross-Site Request Forgery: https://cwe.mitre.org/data/definitions/352.html
- CWE-1275 — Sensitive Cookie with Improper SameSite Attribute: https://cwe.mitre.org/data/definitions/1275.html
- Outcome CWEs to add per impact: CWE-287 (improper authentication / ATO), CWE-384 (session hijacking), CWE-639 (authz bypass)

---

> **Final reminder — the one rule that pays:** *A CSRF is only a finding if it fires in a real, default-settings browser and changes something that matters.* Check the cookie's SameSite first, bypass the specific control in your way, chain it to account takeover, and prove it cross-site in default Chrome. That discipline turns the most-rejected bug class into a clean, valid, paying report — and keeps you out of the auto-close pile.
