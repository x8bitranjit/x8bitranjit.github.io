# Subdomain Takeover — PoC Scripts

Runnable helpers that back the Subdomain Takeover kit. **Click a script to open it on its own page.** *Authorized
testing only:* a fingerprint is a *lead*, not a finding — always cross-check **`can-i-take-over-xyz`**, confirm
claimability, **claim** the resource in your own account, serve a **benign marker**, prove the trust chain safely, then
**unpublish** and ask the program to **remove the DNS record**.

| Script | What it does |
|---|---|
| [`fingerprints.py`](#/subtakeover/poc/fingerprints) | Per-service **signature database** (CNAME pattern + HTTP "not found" body + `claimable?` + claim note) with a matcher and a self-test. A body-only match is only trusted for a *distinctive* signature — generic stock-404 strings never produce a false match. |
| [`subtakeover_scan.py`](#/subtakeover/poc/subtakeover_scan) | **Scanner + ranker**: resolves CNAME / NS / MX (following CNAME chains), probes HTTP for the provider fingerprint, matches the DB, and **ranks** candidates by claimability + record type (**NS / MX first** — the Critical variants). It surfaces leads to verify and claim by hand; it never auto-claims. |
| [`claim_proof.py`](#/subtakeover/poc/claim_proof) | **Proof verifier**: after you claim the resource and serve a unique benign marker, confirms `https://sub.target.com/<marker>` returns *your* content and re-checks the CNAME — the evidence-capture helper for the report. |

## How they fit together

1. **Enumerate** subdomains elsewhere (subfinder / amass / crt.sh), then **scan** — `subtakeover_scan.py` resolves every record, fingerprints the danglers via `fingerprints.py`, and ranks the claimable / NS / MX leads to the top.
2. **Confirm claimability** against `can-i-take-over-xyz`, then **claim** the exact resource in your own provider account and serve a benign marker.
3. **Prove** — `claim_proof.py` verifies your marker is served from the target subdomain (control proven); then chain the trust (domain cookies / OAuth / CSP / CORS / NS / MX) and **unpublish**.

> Read the **Testing Guide** for the record-type playbooks (NS → full DNS control, MX → reset-email interception → ATO)
> and the second-order chains (a dead subdomain in the main app's OAuth `redirect_uri` / CSP `script-src` / `<script
> src>` / CORS → token theft or script execution on the **main app**). Fingerprints go stale — sync the DB with
> `can-i-take-over-xyz` and re-verify before reporting.
