# SSRF Testing Checklist — Per-Sink, In Testing Order

> Tick per url-fetch sink. Mirrors the Master Testing Sequence in `SSRF_TESTING_GUIDE.md`. The point: **confirm server-side fetch → steer inward → reach metadata/internal → obtain real impact**. A callback is confirmation, not the finding. `§` = section in the main guide.

**Target:** ____________  **Sink/feature:** ____________  **Param/header:** ____________  **Date:** ________
**Observability:** in-band / semi-blind / blind  **Server source IP / cloud:** ____________  **Schemes accepted:** http https gopher file dict

---

## PHASE 0 — Recon & Lab (§1/§3)
- [ ] Found **every** fetch sink: webhook · URL preview/unfurl · import-from-URL · PDF/screenshot gen · image proxy · SSO/OIDC · file parsers (SVG/XML) · headers (XFF/Referer/X-Forwarded-Host).
- [ ] Grepped JS/swagger for `fetch/axios/request/http.get/file_get_contents/curl` with user-controlled URLs.
- [ ] **OOB listener live** (interactsh/Collaborator). **Redirect server** ready (`poc/redirect_server.py`).

## PHASE 1 — Baseline ★ (§4) — DO FIRST
- [ ] Pointed sink at OOB host; got a callback.
- [ ] **Source IP = server/cloud** (not my IP) → SSRF confirmed (client-IP = not SSRF).
- [ ] Classified: **in-band** / semi-blind (status/timing/error) / **blind**.
- [ ] Noted cloud provider (source IP/reverse DNS), accepted schemes, and whether it **follows redirects**.

## PHASE 2 — Reachability (§5)
- [ ] Probed: external → `127.0.0.1`/`localhost` → internal ranges (10/172/192) → `169.254.169.254`.
- [ ] Determined the ceiling: external-only? localhost? internal? **metadata**?

## PHASE 3 — Filter Bypass (§6–§10) — if internal/metadata blocked
- [ ] **IP obfuscation**: decimal/hex/octal/short/IPv6/IPv4-mapped for 127.0.0.1 and 169.254.169.254 (§6).
- [ ] **DNS**: wildcard DNS (nip.io/sslip.io), custom A-record, **DNS rebinding** for TOCTOU allowlists (§7).
- [ ] **Redirect**: `poc/redirect_server.py` → internal/metadata; open redirect on target's own domain (§8).
- [ ] **Parser confusion**: `@`, `#`, `\`, suffix/subdomain, CRLF, double-encode (§9).
- [ ] **Protocols**: tested `file://`, `gopher://`, `dict://`, `ftp://` acceptance (§10).
- [ ] ✅ Reached internal/metadata despite the filter.

## PHASE 4 — IMPACT ⭐ (§11–§17) — climb to the highest
- [ ] **Cloud metadata**: AWS IMDSv1 creds (or v2 via gopher/header) / GCP token (`?recursive=true` one-shot) / Azure token (§11).
- [ ] **Container/serverless creds (§11.1.1)**: EC2 IMDS dead? → **ECS/Fargate `http://169.254.170.2/v2/credentials/`** · **Lambda** `file:///proc/self/environ` (AWS_*) · **EKS/IRSA** web-identity token.
- [ ] **Proved creds LIVE** with `aws sts get-caller-identity` (read-only) — then STOP (§23).
- [ ] **Internal port scan** + host discovery (timing/status oracle if blind) (§12).
- [ ] **In-band internal read**: ES `/_cat/indices`, actuator, admin, unauth APIs (§12).
- [ ] **gopher → service**: Redis/FastCGI/MySQL → benign proof (SET marker) → RCE if authorized (§13).
- [ ] **file://**: `/etc/passwd`/`/etc/hostname` proof; minimal secret read for impact (§14).
- [ ] **Blind escalation**: oracle scan / redirect-exfil metadata into a visible field / gopher state-change (§15).
- [ ] **Feature-specific**: PDF/headless `<iframe metadata>`+`<img file://>`; image proxy; webhook; SVG/XXE (§16).
- [ ] **Stored/second-order**: planted markers; watched for delayed callback from a backend IP (§17).
- [ ] Stated impact in one sentence: *"SSRF in <sink> reaches <metadata/internal> and yields <creds/data/RCE/file>."*

## PHASE 5 — Validate → Severity → Report (§19–§24)
- [ ] Passed **false-positive filter** (§20): NOT "server pinged my collaborator" (external-only), NOT client-side, NOT intended-external-fetch, NOT blind-external-no-pivot.
- [ ] Confirmed **server-side fetch + internal/metadata reach + concrete impact**.
- [ ] Set **CVSS 3.1** + **CWE-918** (+ outcome CWE) (§21).
- [ ] Built **SAFE PoC**: `get-caller-identity` & stop; benign gopher; benign file; no destructive internal action (§23).
- [ ] Captured: exact request + bypass used + OOB/in-band evidence (creds+caller-identity / file / gopher proof).
- [ ] **De-duplicated**; title names the **impact** (§24).

---

## Quick "is it worth reporting?" gate
```
Did the SERVER (cloud IP) make the request?                    NO → client-side, not SSRF (§20).
Did I reach INTERNAL / METADATA (not just my own host)?        NO → external-only = Low/Info; pivot harder first (§20).
Did I obtain something REAL (creds/data/RCE/file)?             NO → confirmed-SSRF-no-impact = often Low. Escalate.
For metadata: did I prove creds LIVE (get-caller-identity)?    NO → do it; that's the Critical proof.
Did I keep the PoC SAFE (no real-data access, no destruction)? NO → fix before submitting (§23).
```

## Per-sink mini-loop
```
baseline (server IP? observability?) → reachability map → bypass filter to internal/metadata
   → highest impact (creds/gopher-RCE/internal-read/file) → prove safely (caller-identity & stop) → record
```
