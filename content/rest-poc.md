# REST API — PoC Scripts

Tooling for the REST API kit. *Authorized testing only.* REST bugs are **authorization** bugs — the finding is **reaching another tenant's object/function** (BOLA/BFLA) or **persisting a field you shouldn't** (mass assignment), proven with **two accounts you own**. These scripts are **read-lean and confirmation-gated** — mutating verbs are off by default. **Click a script to open its source.**

| Script | What it does |
|---|---|
| [`api_discover.py`](#/rest/poc/api_discover) | **Surface mapper** — pulls an OpenAPI/Swagger spec, mines routes, and safely probes with **OPTIONS/GET/HEAD only** (never destructive) to enumerate the real endpoint + method set (shadow/undocumented routes included). |
| [`authz_diff.py`](#/rest/poc/authz_diff) | The **two-account BOLA/BFLA differ** (à la Autorize): replays account-A's requests with account-B's token (and unauth) and flags any object/function that answers when it shouldn't. The core REST-authz test. |
| [`massassign_fuzz.py`](#/rest/poc/massassign_fuzz) | **Mass-assignment / BOPLA** tester — adds privileged fields (`isAdmin`, `role`, `verified`) to write bodies and **re-reads to confirm they persisted** (per-combo running baseline, not a stale one). |
| [`method_tamper.py`](#/rest/poc/method_tamper) | **Verb / method-override** tampering — default is a safe OPTIONS-based lead check; mutating verbs and `X-HTTP-Method-Override` are gated behind `--allow-destructive`. |

## Typical flow
1. **Map** the surface (`api_discover.py`) — spec + client-mined + shadow routes.
2. **Register two accounts**, then run `authz_diff.py` — the highest-yield test (BOLA API1 / BFLA API5).
3. **On every write**, run `massassign_fuzz.py` (BOPLA API3) and confirm the field actually persisted.
4. **Method/verb** tampering with `method_tamper.py` (destructive verbs only with explicit `--allow-destructive`).

> Authorization is the whole game: register your own two accounts and prove cross-tenant access — don't touch real users' data. This kit is the API *surface*; the vuln-class depth (IDOR, JWT, SSRF, injection) lives in those kits, cross-referenced from the guide.
