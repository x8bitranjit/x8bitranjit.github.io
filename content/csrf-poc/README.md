# CSRF PoC Generator & Templates

Tooling for building CSRF proof-of-concept pages from `CSRF_TESTING_GUIDE.md`. The core tool turns a captured HTTP request into ready auto-submit HTML; `templates/` holds hand-editable variants.

## ⚠️ Authorized use only — and the validity rule
- Use **only** on in-scope assets, with **your own two test accounts** (the attacker page changes your *victim* test-account's email/setting to an inbox you control). Revert changes after.
- **The PoC must fire in a real, default-settings browser, cross-site** — that's the only valid CSRF test. A PoC that only works in Burp Repeater, or with SameSite disabled, is **not** a real-world CSRF (guide §19). **Check the session cookie's `SameSite` first** (guide §4).

## Files
| File | Purpose | Guide § |
|------|---------|---------|
| `csrf_poc_generator.py` | turn a saved HTTP request into auto-submit PoC HTML (form/get/json/multipart/auto) | §23 |
| `templates/form_post.html` | classic auto-submit POST form (needs SameSite=None) | §23.2 |
| `templates/get_nav.html` | GET state-change via top-level navigation (works under default Lax) | §6.1 |
| `templates/json_textplain.html` | JSON CSRF via the text/plain form trick | §8 |
| `templates/multipart.html` | multipart/form-data CSRF | §8 |
| `templates/login_csrf.html` | login CSRF (log victim into attacker's account) | §12 |
| `templates/cors_cred.html` | credentialed fetch CSRF (only if CORS misconfigured) | §17 |
| `clickjack_csrf.html` | clickjacking-assisted CSRF — frame the real (tokened) page + steal the click; needs a framable page (no XFO/`frame-ancestors`) + cookie reaching the frame (SameSite=None/same-site) | §10.5 |

## Quickstart
```bash
# 1) Save the target request: Burp → right-click → Copy to file → req.txt  (or paste the raw request)
# 2) Generate:
python3 csrf_poc_generator.py --request req.txt --type auto --out poc.html
#    --type auto  (pick by content-type)  | form | get | json | multipart
#    --set email=attacker@my-inbox.example   (override/insert a param value)
# 3) Host CROSS-SITE and open in the VICTIM browser (DEFAULT settings):
python3 -m http.server 8000        # http://localhost:8000/poc.html
# 4) Confirm the action fired in default Chrome → chain to ATO → report.
```

## Reminder
Before you even generate a PoC: read the session cookie's `SameSite` (DevTools → Application → Cookies).
- `None` → form/json/multipart templates can work.
- `Lax`/absent → only the **GET-navigation** template works (and only for GET sinks).
- `Strict` → cross-site is dead; you need a same-site position (subdomain XSS/takeover, guide §6.4).
- Auth is a Bearer/localStorage token (no cookie) → **not CSRF**, stop.
