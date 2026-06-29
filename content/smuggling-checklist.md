# Request-Smuggling Testing Checklist — tick per host

> Companion to `REQUEST_SMUGGLING_TESTING_GUIDE.md`. The finding is a **deterministic, controllable desync + a concrete
> cross-user impact** — never a timing blip. **DO NO HARM:** timing first, own connections, benign markers. Work
> top-to-bottom; stop and report only when impact (or a reliable capability) is proven safely.

## PHASE 0 — Recon (§3)
- [ ] Confirmed a **front-end + back-end** chain (CDN/LB/proxy → origin) via Server/Via/X-Cache/CF-RAY headers.
- [ ] Confirmed keep-alive (HTTP/1.1) or HTTP/2; mapped protocol to you vs to the origin (downgrade surface).
- [ ] Located a **reflection/store** endpoint, **restricted/WAF-blocked** paths, and **cacheable** pages.

## PHASE 1 — Baseline: SAFE detection (§4)
- [ ] Ran **timing-based** detection first (no socket poisoning) — CL.TE and TE.CL probes, repeated vs baseline.
- [ ] Confirmed with a **deterministic differential** on a connection **I control** (my follow-up gets the smuggled prefix's response).

## PHASE 2 — Technique (§5–§7)
- [ ] Identified the class: **CL.TE / TE.CL** (§5), **TE.TE** obfuscation (§6), or **HTTP/2 downgrade** (H2.CL/H2.TE/CRLF) (§7).
- [ ] **Modern variants (§7.1–§7.3):** **CL.0 / 0.CL** (body-as-next-request on static/redirect endpoints) · **client-side desync** (browser-powered, no front-end) · **connection-state** attacks (first-request **routing** / **validation** on a reused connection).
- [ ] **2022–2024 wave (§7.4):** **TE.0** (chunked-as-next on body-less endpoints) · **CL.CL** (duplicate/ambiguous Content-Length) · **request tunnelling** (read an internal-only response inside your own connection — blind-SSRF-grade) · **pause-based desync** (streaming/timeout-induced).
- [ ] Tuned `Content-Length`/chunk sizes byte-exact (used Burp raw / Turbo Intruder, auto-CL disabled).

## PHASE 3 — Confirm (§8)
- [ ] Proved the prefix attaches to a **follow-up** request predictably; measured reliability across trials.

## PHASE 4 — Impact (§9–§13) — benign, own connections
- [ ] **Request capture (§9):** stored/reflected the **next** request; proved capture with my **own** second session → ATO.
- [ ] **WAF/auth bypass (§10):** reached a blocked/internal/admin path the front-end disallows.
- [ ] **Cache poisoning (§11):** poisoned a **benign/unique** cache key (described shared-cache mass impact).
- [ ] **Response-queue poisoning (§12):** demonstrated on my **own** traffic only.
- [ ] **Internal → RCE/cloud (§13):** reached a back-end code-exec/SSRF/metadata endpoint → handed off to SSRF/SSTI/cmdi kit (own tenant, read-only creds).

## PHASE 5 — Validate → report
- [ ] Showed a **deterministic, controllable** desync + a **concrete** exploit (or reliable cross-connection capability) — FP check §15.
- [ ] Used **benign** prefixes, **own** sessions/connections; did **not** harvest real users' data or poison shared entries.
- [ ] Restored connection state; kept volume low; confirmed reproducibility.
- [ ] Set CVSS 3.1 + **CWE-444** (+ outcome CWE: 79/384/918/94) (§16).
- [ ] De-duped to one finding per desync primitive; led with the highest-impact exploit (§19).

## AUTO-REJECT (don't submit if…)
- [ ] A single slow/odd response (load/jitter) with no deterministic differential.
- [ ] "smuggler.py / the extension flagged it" with no manual confirmation.
- [ ] A desync you can't make **deterministic/reproducible**.
- [ ] 400/errors from malformed requests (the server **rejecting** bad framing = correct).
- [ ] A confirmed desync reported as **Critical with no exploit** (that's ~Medium).
- [ ] Self-only effects (your request to yourself, no cross-user impact).
