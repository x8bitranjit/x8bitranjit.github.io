# Subdomain Takeover — Checklist (tick per program)

> Companion to `SUBDOMAIN_TAKEOVER_TESTING_GUIDE.md`. The finding is the **claim + the trust it grants** (session ATO /
> script-exec on the main app / reset interception / brand phishing), never a bare "it 404s." A fingerprint is a lead;
> **claim it and serve a benign marker**, then chain the trust — then **unpublish**. Work top-to-bottom.

## PHASE 0 — Recon (§3)
- [ ] Enumerated subdomains passively (subfinder/amass/assetfinder + crt.sh CT logs + chaos/GitHub).
- [ ] Pulled **historical** subdomains (crt.sh / wayback) — dead hosts still in CT are prime candidates.
- [ ] Active DNS brute + permutations for internal-naming patterns.
- [ ] Resolved **every record type** per subdomain: CNAME, A/AAAA, **NS**, **MX**, TXT (`dnsx -cname -a -ns -resp`).
- [ ] Followed **CNAME chains** to the end (danglers hide at the tail).
- [ ] Noted **trust context**: is any subdomain referenced in the main app's JS / CSP / CORS / OAuth config? (second-order §13).
- [ ] Confirmed every candidate is the **target's own** subdomain (in scope), not a third-party domain.

## PHASE 1 — Baseline (§4)
- [ ] Identified **dangling** records: provider "not found" fingerprint / NXDOMAIN / SERVFAIL.
- [ ] Filtered to **claimable** services (cross-checked `can-i-take-over-xyz`).
- [ ] Flagged **NS** (DNS control) and **MX** (email interception) danglers as top-priority (§11).

## PHASE 2 — Detect / confirm (§5–§7)
- [ ] Classified the **record type** (CNAME/A/NS/MX) — it decides the ceiling.
- [ ] **Fingerprinted** the service: exact provider "not found" body, served by the provider (Server/Via/X-Served-By), with a **negative control** vs a live sub.
- [ ] **Confirmed claimability**: the exact bucket/app/page/name is free to create in my account; no domain-verification block.

## PHASE 3 — Impact (§8–§14)
- [ ] **Claimed** the resource in my own account and served a **benign, unique marker** — `https://sub.target.com/<marker>` returns MY content (screenshot + dig).
- [ ] **Cookie ATO (§10):** session cookie is `Domain=.target.com` → my page reads (not HttpOnly) or sets it → session hijack/fixation.
- [ ] **NS/MX (§11):** NS → full DNS control (issued a benign DV cert) / MX → received a test email → reset-interception potential.
- [ ] **Second-order (§13):** the host is in an OAuth `redirect_uri` / CSP `script-src` / `<script src>` / CORS allow-list → token theft / script-exec on the **main app**.
- [ ] **Phishing (§12):** claimed brand subdomain (+ valid TLS via NS) → credential-phishing narrative on the real domain.

## PHASE 4 — Validate → report
- [ ] Proved the **claim** (my marker served) + the **trust chain**, not just a fingerprint (FP check §16).
- [ ] Kept the PoC **benign**; **unpublished** the claim after evidence; used own accounts / own cert / own test email.
- [ ] Confirmed on the **real** target subdomain; report asks them to **REMOVE the DNS record** (not just re-create the resource).
- [ ] Set CVSS 3.1 + **CWE-350** (+ CWE-384 / CWE-79 / CWE-284 by outcome) (§17).
- [ ] De-duped: one dangling record = one finding; led with the highest-impact chain (§20).

## AUTO-REJECT (don't submit if…)
- [ ] A **fingerprint only** — you didn't actually **claim** it and serve a marker.
- [ ] The service is on the **non-claimable** list (provider blocks re-registration).
- [ ] A **generic 404** with no provider signature (host still owned).
- [ ] A dangling record on a **third-party** domain (wrong asset / out of scope).
- [ ] Claimed host but cookies are **host-only** (`Domain=app.x`) — reported as ATO without the domain-cookie chain.
- [ ] **"NXDOMAIN so it's takeover-able"** without confirming the name is actually registrable.
- [ ] A bare takeover with **no impact narrative** reported as Critical (it's Low–Medium alone).
