# CSRF — PoC Scripts

Tooling for building CSRF proof-of-concept pages. The core tool turns a captured HTTP request into ready
auto-submit HTML; the templates are hand-editable variants for each delivery context. **Click a script to
open it on its own page.**

> ⚠️ **Authorized use only — and the validity rule.** Use **your own two test accounts** (the attacker page
> changes your *victim* test-account's setting to an inbox you control); revert after. **A PoC must fire in a
> real, default-settings browser, cross-site** — that's the only valid CSRF. One that only works in Burp
> Repeater, or with SameSite disabled, is **not** real-world CSRF. **Check the session cookie's `SameSite`
> first.**

| Script | Purpose |
|---|---|
| [`csrf_poc_generator.py`](#/csrf/poc/csrf_poc_generator) | Turn a saved HTTP request into auto-submit PoC HTML — `--type auto / form / get / json / multipart`. |
| [`form_post.html`](#/csrf/poc/templates-form_post) | Classic auto-submit POST form (needs `SameSite=None`). |
| [`get_nav.html`](#/csrf/poc/templates-get_nav) | GET state-change via top-level navigation (works under default `Lax`). |
| [`json_textplain.html`](#/csrf/poc/templates-json_textplain) | JSON CSRF via the `text/plain` form trick. |
| [`multipart.html`](#/csrf/poc/templates-multipart) | `multipart/form-data` CSRF. |
| [`login_csrf.html`](#/csrf/poc/templates-login_csrf) | Login CSRF — log the victim into the attacker's account. |
| [`cors_cred.html`](#/csrf/poc/templates-cors_cred) | Credentialed `fetch` CSRF (only if CORS is misconfigured). |
| [`clickjack_csrf.html`](#/csrf/poc/clickjack_csrf) | Clickjacking-assisted CSRF — frame the real (tokened) page + steal the click. Needs a framable page (no XFO/`frame-ancestors`) and the cookie reaching the frame. |

## Quickstart
1. **Save the target request:** Burp → right-click → *Copy to file* → `req.txt`.
2. **Generate:** `python3 csrf_poc_generator.py --request req.txt --type auto --out poc.html`
   (`--set email=attacker@my-inbox.example` to override a param).
3. **Host CROSS-SITE** and open in the **victim** browser with **default** settings (`python3 -m http.server 8000`).
4. **Confirm the action fired** in default Chrome → chain to ATO → report.

## Decide by `SameSite` first (DevTools → Application → Cookies)
- `None` → form / json / multipart templates can work.
- `Lax` / absent → only the **GET-navigation** template works (and only for GET sinks).
- `Strict` → cross-site is dead; you need a same-site position (subdomain XSS/takeover).
- Auth is a Bearer / localStorage token (no cookie) → **not CSRF, stop.**

> Read the **Testing Guide** for the full method order and the **Zero to Expert (Q&A)** for the *why*.
