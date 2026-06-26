# XSS Testing Checklist — Per-Target, In Testing Order

> Tick this per target/feature. It mirrors the Master Testing Sequence in `XSS_TESTING_GUIDE.md`. The point is **coverage** (most missed XSS is a missed input) and **escalation** (most underpaid XSS stopped at `alert(1)`). `§` = section in the main guide.

**Target:** ____________________  **Scope/Program:** ____________________  **Date:** ____________
**Stack/framework:** ___________  **CSP:** _____________  **WAF:** _____________  **Cookie flags:** HttpOnly[ ] Secure[ ] SameSite[ ]

---

## PHASE 0 — Authorization & Lab (§1)
- [ ] Confirmed the asset + this issue class are **in scope** (XSS is active testing).
- [ ] Read rules on PoC: allowed exfil, no real-user data, no automated mass-firing.
- [ ] Burp/Caido proxy running; **two** browser profiles (victim + attacker).
- [ ] **OOB listener live** (Collaborator / interactsh / self-hosted XSS Hunter) — URL: ____________
- [ ] Created **2+ test accounts** (needed for cross-user / ATO / stored impact).

## PHASE 1 — Recon & Surface Map (§4)
- [ ] Crawled app (katana) + harvested historical params (waybackurls/gau).
- [ ] Ran Arjun/param-miner for **hidden parameters**.
- [ ] Enumerated **every** input source:
  - [ ] Query params  [ ] Path segments  [ ] URL fragment `#` (DOM source)
  - [ ] POST body fields (incl. hidden)  [ ] JSON body keys
  - [ ] Headers: Referer, User-Agent, X-Forwarded-Host/For, Origin, Accept-Language
  - [ ] Cookies  [ ] File upload (filename + content)  [ ] WebSocket frames  [ ] postMessage
  - [ ] Inputs that render to **staff/admin** later (feedback, tickets, names) → blind candidates (§13)
- [ ] Fingerprinted: **framework** (§15), **CSP** (§19), **WAF** (§18), **cookie flags** (§1.4).

## PHASE 2 — Reflection & Context (§5) — DO NOT SKIP
> New to XSS? read **guide §1.9 (fundamentals — what's actually happening)** first, then run the decision flow below.
- [ ] Injected a **unique marker** + the char probe `xss7f3a9'"<>` into every input; found it in **raw HTML AND the live DOM**.
- [ ] Recorded **which probe characters came back RAW vs encoded** per location (that tells you the context).
- [ ] Ran the **"if I got back THIS, do THIS" decision flow** (guide **§3.4** / arsenal **§0**) → named the context:
      HTML body / attr-quoted / attr-unquoted / JS-in-attr / JS-string / URL / CSS / DOM-only.
- [ ] If everything came back **encoded** → pivoted (JS §8 / URL §9 / DOM #fragment §11 / CSTI §15) rather than fighting HTML.
- [ ] Checked the **live DOM** (not just raw HTML) for DOM-only reflections (§11).

## PHASE 3 — Context Exploitation (§6–§16)
- [ ] HTML body → tag/auto-event payload (§6)
- [ ] Attribute → break-out or event attribute (§7)
- [ ] JS string/template → string breakout (§8)
- [ ] URL/href/src → `javascript:`/`data:` (§9)
- [ ] CSS → break-out / CSS exfil (§10)
- [ ] **DOM** → DOM Invader + manual sink trace (innerHTML/eval/location/postMessage) (§11)
- [ ] **Stored** → planted in every field; rendered in **every consumer** incl. admin/email/export (§12)
- [ ] **Second-order** → traced stored value to a place it renders **raw** (§12.3)
- [ ] **Blind** → planted beacon in staff-visible inputs/headers; waiting on callback (§13)
- [ ] **mXSS / sanitizer** → identified lib+version; tried known bypass (§14)
- [ ] **DOM Clobbering** → HTML-only injection (sanitizer allows `id`/`name`)? clobber a global/config the JS reads (`<a id=x>`,`<form>`,`<img name=…>`) → steer a `src`/`href`/`innerHTML` sink → DOM XSS (§11.7)
- [ ] **Framework** → React `dangerouslySetInnerHTML` / Vue `v-html` / Angular(JS) CSTI `{{}}` (§15)
- [ ] **Files** → SVG/HTML upload served inline; filename; markdown; PDF gen (§16)
- [ ] ✅ **EXECUTION CONFIRMED** with `alert(document.domain)` or a collaborator hit (not just injection).

## PHASE 4 — Defense Bypass (§18–§22)
- [ ] If WAF-blocked: identified the trigger token, mutated it (case/encode/concat/no-paren) (§18).
- [ ] If CSP present: scored it; found `unsafe-inline`/wildcard/JSONP/gadget/report-only bypass (§19).
- [ ] If **Trusted Types** enforced (`require-trusted-types-for 'script'`, "requires TrustedHTML" error): checked for a pass-through **`default` policy** / reusable named policy / report-only-or-missing-on-API gap / non-TT `location=javascript:` sink (§19.4).
- [ ] If encoded: confirmed it's a **context mismatch**; built payload from surviving chars (§20).
- [ ] If truncated/restricted: short payload / remote load / split-input (§21).
- [ ] Confirmed execution survives on the **production** config (real CSP/WAF in place).

## PHASE 5 — IMPACT ⭐ (§23–§33) — climb as high as the app allows
- [ ] Determined auth model: cookie session vs token-in-localStorage vs OAuth.
- [ ] **Cookie not HttpOnly** → cookie theft + replay → screenshot victim account (§24)
- [ ] **Token in localStorage** → exfil + authenticated API call as victim (§25)
- [ ] **HttpOnly cookie** → read CSRF token → force email/password change → **ATO** (§26/§27)
- [ ] **Full ATO chain** demonstrated end-to-end on **my own two accounts** (§27)
- [ ] In-origin phishing / keylogger PoC where relevant (§28/§29)
- [ ] Internal recon / SSRF pivot from victim browser (red team) (§31)
- [ ] **Admin/staff context** (via blind/stored) → admin action / data read / priv-esc (§32)
- [ ] Wormability assessed & **described** (not released) for stored multi-user content (§33)
- [ ] Stated the impact as one sentence: *"An attacker can make <victim> suffer <harm> with <N> clicks."*

## PHASE 6 — Validate → Severity → Report (§34–§39)
- [ ] Passed the **false-positive filter** (§35): not self-XSS, not encoded-only, not CSP-blocked, not out-of-context.
- [ ] Set a **defensible CVSS 3.1 vector** + score; mapped **CWE-79/80/116** (§36).
- [ ] Built a **minimal, context-correct, SAFE** PoC (own data only) (§38).
- [ ] Captured evidence: trigger URL/request + screenshot/video + collaborator/XSS-Hunter log.
- [ ] **De-duplicated** (one root cause = one finding) (§39).
- [ ] Title names the **impact**, not just "XSS in X".
- [ ] Cleaned up planted payloads / added keys / service workers after testing.

---

## Quick "is it worth reporting?" gate
```
Did script EXECUTE in the app origin?            NO → not XSS (reflection/encoded only). Stop or keep digging.
Is the context AUTHENTICATED / sensitive?        NO → Low/Info unless it reaches a session. Note & move on.
Is delivery cross-user (URL/stored/forced)?      NO → likely self-XSS = invalid (§35.1). Find delivery or drop.
Did I climb past alert() to real impact?         NO → do §26 (CSRF-token→action) at minimum before submitting.
Can I write the attacker-impact sentence?        NO → severity unjustified; keep escalating.
```

## Per-input mini-loop (repeat for each parameter/field/header)
```
marker → does it reflect (HTML or DOM)? → char probe → name context → context payload
       → execution? → bypass WAF/CSP if needed → ESCALATE to impact → record finding
```
