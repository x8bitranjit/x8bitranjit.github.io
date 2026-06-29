# JavaScript Files — PoC Scripts

Runnable tooling that backs the JS-Files recon kit. **Click a script to open it on its own page.** *Authorized testing
only:* a scanner hit is a **candidate** — validate (secret live + privileged) or exploit (sink fires / endpoint
authz-bypass) before reporting; validate secrets with the **minimal read-only** call and redact.

| Script | What it does |
|---|---|
| [`js_harvest.sh`](#/jsfiles/poc/js_harvest) | Pull every JS asset — live bundles + chunks + inline + **historical (wayback/gau)** + referenced `.map` — into a local corpus. |
| [`secret_scan.py`](#/jsfiles/poc/secret_scan) | Severity-ranked secret regexes with entropy gating; **suppresses public client keys** (Maps/Firebase/Stripe-publishable/Sentry) so you don't over-report. |
| [`endpoints.py`](#/jsfiles/poc/endpoints) | Extract API paths, URLs, params, GraphQL ops, and hidden-surface hints (roles/flags/admin). |
| [`dom_sinks.py`](#/jsfiles/poc/dom_sinks) | Find DOM-XSS / redirect / `postMessage` / prototype-pollution sinks; rank by proximity to a controllable source; flag `message` handlers with **no origin check**. |
| [`sourcemap_unpack.py`](#/jsfiles/poc/sourcemap_unpack) | Reconstruct the original source tree from a `.map`'s `sourcesContent`. |

## How they fit together

1. **Harvest** every JS asset (live + historical + sourcemaps) with `js_harvest.sh`.
2. **Mine secrets** with `secret_scan.py` → then **validate** the HIGH hits read-only (`aws sts get-caller-identity`, GitHub PAT, Stripe secret).
3. **Map the surface** with `endpoints.py` → authz/IDOR/SSRF-test the interesting routes.
4. **Find sinks** with `dom_sinks.py` → confirm likely DOM-XSS/redirect flows actually fire.
5. **Recover source** with `sourcemap_unpack.py` → re-mine the recovered tree (higher signal).

> Read the **Testing Guide §5/§6/§8/§9** for validation discipline and the **Zero to Expert (Q&A)** for turning a
> harvested secret/endpoint into a real finding.
