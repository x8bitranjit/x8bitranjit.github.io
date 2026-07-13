# Open Redirect — PoC Scripts

Runnable helpers that back the Open Redirect kit. **Click a script to open it on its own page.** *Authorized testing
only:* point everything at a **host you control**, prove chains with your **own accounts**, catch your **own token**,
and take PoC pages/listeners down afterward. A redirect is a *condition* — the finding is the **escalation** (ATO /
DOM-XSS / SSRF-internal / credible phishing).

| Script | What it does |
|---|---|
| [`redirect_payloads.py`](#/openredir/poc/redirect_payloads) | Generates the full, deduplicated **bypass payload matrix** for a target + attacker host (the Arsenal, parameterized) — `//`, `\`, `@`-userinfo, whitelist, encoding, unicode-dot, CRLF, `javascript:`/`data:`. Feed Burp Intruder or build ready-to-open URLs from a template. |
| [`openredir_fuzz.py`](#/openredir/poc/openredir_fuzz) | **Control-baselined** fuzzer: sprays the matrix at a `FUZZ` param, reads the raw `Location` (no-follow) and scans meta/JS sinks, and flags any payload that lands off-origin at your host. Low false-positive (it learns the app's normal redirect first) and points you to the right escalation. |
| [`token_catcher.py`](#/openredir/poc/token_catcher) | A benign marker-host **listener** that logs any `code` / `access_token` / reset / `state` / session delivered in the query, POST body, or URL **`#fragment`** — for proving the OAuth / token-theft chain by catching **your own** token on **your own** host. |

## How they fit together

1. **Generate** — `redirect_payloads.py` gives you the bypass matrix for the target (beat the validator with the parser-gap trio `//` / `\` / `@`, or the whitelist).
2. **Detect** — `openredir_fuzz.py` finds which payloads actually steer the browser off-origin, and classifies the sink (header / meta / JS).
3. **Prove** — `token_catcher.py` sits on your marker host so an OAuth / SSO or reset chain that bounces a `code`/`token`/`#access_token` to you is captured (own account) → account takeover proven.

> Read the **Testing Guide** for the sink taxonomy and the OAuth chain-B / SSRF-allow-list-bypass / DOM-XSS escalations,
> and the **Checklist** for the per-endpoint order. A server that *fetches* the URL is **SSRF**, not open redirect —
> don't mislabel it.
