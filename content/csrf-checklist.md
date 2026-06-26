# CSRF Testing Checklist — Per-Action, In Testing Order

> Tick per state-changing action. Mirrors the Master Testing Sequence in `CSRF_TESTING_GUIDE.md`. The point: **the SameSite gate decides if CSRF is even possible → bypass the blocking control → chain to ATO → PROVE it in a real default browser.** `§` = section in the main guide.

**Target:** ____________  **Action:** ____________  **Endpoint/method:** ____________  **Date:** ________
**Auth model:** cookie / Bearer-header / localStorage  **Session cookie SameSite:** None / Lax / Strict / absent(=Lax)

---

## PHASE 0 — Recon & Lab (§1/§3)
- [ ] Listed **state-changing** actions, ranked by impact (auth > financial/admin > data > trivial).
- [ ] Two browser profiles (victim logged-in + attacker), **default settings**; a cross-site host for the PoC.
- [ ] Recorded each action's request: method, URL, params, content-type, token presence.

## PHASE 1 — Baseline ★ (§4) — THE GATE, DO FIRST
- [ ] **Q1** Auth via a **cookie** the browser auto-sends? (Bearer/localStorage ⇒ NOT CSRF, stop.)
- [ ] **Q2** Read the session cookie **SameSite** (DevTools → Application → Cookies): None / Lax / Strict / absent.
- [ ] **Q3** Is there an anti-CSRF **token** in the request? Is it actually validated/session-bound?
- [ ] **Q4** Does the server check **Referer/Origin**? (send blank/foreign and see.)
- [ ] **Q5** Does it require **JSON content-type / a custom header**?
- [ ] Produced the verdict: CSRF **possible** (None, or Lax+GET-sink, or token bypassable) vs **N/A** (Lax+POST+enforced token, or Bearer auth).

## PHASE 2 — Protection Bypass (§5–§10) — defeat the blocking control
- [ ] **Token** (§5): remove / empty / use my own token / presence-only / GET path / method-override.
- [ ] **SameSite** (§6): GET-nav under Lax · SameSite=None classic · subdomain same-site for Strict · **Lax+POST 2-min window** (fresh login).
- [ ] **Strict/Lax bypass via on-site client-side redirect / SPA-router gadget** (§6.6): `?to=//?next=//#/route` the target's OWN JS follows → final request is **same-site** → cookie flows.
- [ ] **307/308 method-preserving redirect** (§6.7): bounce a cross-site POST through a target 307/308 redirector → method+body replayed to the real endpoint (302/303 won't — they GET-downgrade); same-site 307 keeps Strict cookie.
- [ ] **Referer/Origin** (§7): no-referrer meta · null Origin · weak-regex (`target.com.evil.com`).
- [ ] **Content-Type/JSON** (§8): urlencoded acceptance · text/plain JSON trick.
- [ ] **Double-submit / custom header** (§9): cookie-settable? CORS-cred misconfig? token leaked (Referer/CORS/XSS)?
- [ ] **Method/param tricks** (§10): `_method` override · GET↔POST · multi-step · redirect-to-GET-sink.
- [ ] **Clickjacking-assisted** (§10.5): token can't be scripted BUT page is framable (no XFO/`frame-ancestors`) + cookie reaches frame (None/same-site) → UI-redress the real submit.
- [ ] ✅ Produced a forged **cross-site** request the server accepts (or a framed real-token submit).

## PHASE 3 — IMPACT ⭐ (§11–§17) — chain to ATO/financial/admin
- [ ] **ATO**: CSRF change email/recovery → reset → log in as victim (§11).
- [ ] **ATO**: CSRF change password (no old pw) / disable-2FA / add passkey-API-SSH key (§11).
- [ ] **Login CSRF** (with demonstrated harm) (§12).
- [ ] **JSON/API CSRF** (urlencoded / text/plain) (§13).
- [ ] **CSRF + self-XSS → stored XSS → ATO** (§14).
- [ ] **OAuth state-CSRF → account linking takeover** (§15).
- [ ] **GraphQL CSRF** (GET / form-encoded mutation) (§16).
- [ ] **CORS-credentialed CSRF** (ACAO reflected + ACAC:true) (§17).
- [ ] Stated impact in one sentence: *"A logged-in victim opening my page suffers <ATO/financial/admin change>."*

## PHASE 4 — Validate → Severity → Report (§19–§24)
- [ ] ★ **FIRED IN A REAL DEFAULT-SETTINGS BROWSER, CROSS-SITE** (not Repeater, not SameSite-disabled) (§19).
- [ ] Passed **false-positive filter** (§20): NOT Lax+POST, NOT Bearer-auth, NOT "no token w/o PoC", NOT logout/trivial, NOT self-CSRF, NOT Repeater-only.
- [ ] Set **CVSS 3.1** (UI:R) + **CWE-352** (+ outcome CWE) (§21).
- [ ] Built a clean **PoC HTML** (own two accounts, reversible) (§23).
- [ ] Captured: the PoC + confirmation it fired in **default Chrome** + the cookie's **SameSite value** + screenshots.
- [ ] **De-duplicated**; title names the **impact + why it works** (§24).

---

## Quick "is it real CSRF in 2026?" gate
```
Auth via a cookie the browser auto-sends?                 NO (Bearer/localStorage) → NOT CSRF. Stop.
Session cookie SameSite = None? (or Lax+GET sensitive sink?)  NO → likely N/A; need a SameSite bypass or drop.
Did the PoC fire in a REAL default browser, cross-site?   NO → not exploitable in the real world. Don't report.
Did I chain it to a SENSITIVE change (ATO/financial/admin)? NO → Low/Info; don't lead with "missing token".
```

## Per-action mini-loop
```
baseline (cookie? SameSite? token? checks?) → bypass the blocking control → forge cross-site request
   → chain to ATO → ★ confirm in DEFAULT browser cross-site → record finding (with the SameSite value)
```
