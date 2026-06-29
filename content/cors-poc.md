# CORS — PoC Scripts

Runnable, **benign-by-default** proof-of-concept tooling that backs the CORS kit. **Click a script to open it on its
own page.** *Authorized testing only:* two of your own accounts, exfil to a collector you control, redact the secret,
and prove the read in a **real browser** (curl ignores SOP — not proof of browser exploitability).

| Script | What it does |
|---|---|
| [`cors_scan.py`](#/cors/poc/cors_scan) | Bulk-probe a URL list for dangerous Origin reflection / `null` / suffix / prefix / wildcard **with credentials**. Discovery aid — a hit is a *candidate*, not a finding. |
| [`exfil.html`](#/cors/poc/exfil) | The actual exploit: a credentialed `fetch()` from your origin that reads the victim's secret response and ships it to your collector. |
| [`null_iframe.html`](#/cors/poc/null_iframe) | Same exploit for servers that allow `Origin: null` — uses a sandboxed iframe (origin `null`). |
| [`cswsh.html`](#/cors/poc/cswsh) | Cross-Site WebSocket Hijacking PoC — opens a cookie-authed cross-origin WebSocket (WS ignores CORS/SOP) and exfils the victim's stream. |

## How they fit together

1. **Discover** candidates with `cors_scan.py` over your live-URL list.
2. **Confirm the secret** — for each HIGH hit, log in as your test account A and check the credentialed body holds a real secret.
3. **Exploit in a browser** — host `exfil.html` (or `null_iframe.html`) on the reflected origin, visit it logged in as A, confirm the secret reaches your collector.
4. **Escalate** — if the secret is a token/key → replay → account takeover; if it's a cloud/admin/CI cred → CORS→RCE chain (validate read-only on your own tenant).

> Read the **Testing Guide §5/§7/§11** for the Origin-reflection matrix and the **Zero to Expert (Q&A)** for the
> CORS→ATO and CORS→RCE escalation logic.
