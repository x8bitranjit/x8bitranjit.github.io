# Host-Header Injection Checklist — tick per app

> Companion to `HOST_HEADER_INJECTION_TESTING_GUIDE.md`. The finding is the **sink impact** (ATO / mass XSS / SSRF),
> never a reflected/accepted header. Work top-to-bottom; stop and report only when you've proven an impact.

## PHASE 0 — Recon (§3)
- [ ] Found host-dependent sinks: **password-reset/verify links**, absolute redirects/canonical/og, cacheable pages, vhost routing, SSO callbacks.
- [ ] Noted which pages sit behind a **cache/CDN** (X-Cache / Age / Cache-Control).
- [ ] Noted multi-tenant / Host-based routing.

## PHASE 1 — Baseline (§4)
- [ ] Set `Host: evil.com` → accepted or rejected? reflected anywhere (body/Location/links)?
- [ ] Set `X-Forwarded-Host: evil.com` (valid Host) → reflected/used? (often yes when Host is validated)
- [ ] Classified: controllable host reaching a **reset link / cache / routing / redirect / HTML** sink.

## PHASE 2 — Inject / bypass (§5–§7)
- [ ] Tried the full spoofing set (Host, X-Forwarded-Host, X-Host, Forwarded, absolute URI, duplicate Host).
- [ ] **Related forwarding headers (§5.1):** `X-Forwarded-Scheme/Proto` (scheme downgrade), `X-Forwarded-Port` (port in links), **`X-Original-URL`/`X-Rewrite-URL`** (path override → ACL/auth bypass to /admin), `X-Forwarded-For`/`True-Client-IP` (IP-gate bypass).
- [ ] Located where the host **lands** (reflected in body/redirect/links vs trusted server-side in email/routing).
- [ ] Bypassed Host validation (X-Forwarded-Host / duplicate / absolute URI / line-wrap / suffix-prefix).

## PHASE 3 — Impact (§8–§14)
- [ ] **Reset-poisoning (§11):** own-account reset with spoofed host → email link → my host + token arrives → **ATO**.
- [ ] **Cache poisoning (§12):** reflected + cacheable + **unkeyed** (Param Miner) → poisoned XSS/redirect on a benign key.
- [ ] **Cache keying (§12.1):** used a unique `?cb=`; fuzzed the unkeyed-input set (XFH/XF-Scheme/Port/X-Original-URL); confirmed served-from-cache on the same keyed URL.
- [ ] **Web Cache Deception (§12.2):** appended `/x.css`,`;x.css`,`%2Fx.css` to an authenticated page → cached + readable unauthenticated → reads victim's private data.
- [ ] **Routing SSRF (§13):** Host → internal/`169.254.169.254`/OOB → internal content / metadata creds (read-only).
- [ ] **Host → RCE chain (§13.1):** routing-SSRF → cloud metadata/internal-admin/Redis → shell; or cache-XSS/reset → admin ATO → admin code-exec feature.
- [ ] **Redirect/SSO (§9/§14):** absolute redirect or OAuth callback built from host → open redirect / token theft.
- [ ] **Reflected XSS (§10):** host echoed unencoded → XSS (stored if cached).

## PHASE 4 — Validate → report
- [ ] Proved a **sink impact** (poisoned email / cached payload / internal reach), not just reflection (FP check §16).
- [ ] Used **own accounts** (reset), **benign markers** on a **non-shared** cache key, **own OOB**, read-only for metadata.
- [ ] Confirmed on **production**; re-tested partial fixes (Host validated but X-Forwarded-Host still trusted).
- [ ] Set CVSS 3.1 + **CWE-644** (+ CWE-640 / CWE-79 / CWE-918 by outcome) (§17).
- [ ] De-duped to one finding per root cause; led with the highest-impact sink (§20).

## AUTO-REJECT (don't submit if…)
- [ ] "Host header is reflected" with no security sink.
- [ ] `X-Forwarded-Host` merely **accepted** with no observable effect.
- [ ] Changing Host returns a **400 / canonical redirect** (the app defending correctly) and no bypass reaches a sink.
- [ ] Reset link uses a **fixed configured domain** (not host-derived).
- [ ] "Cache poisoning" with no proof of caching (Age/X-Cache) or that the header is unkeyed.
- [ ] Self-only Host change affecting only your own response (no shared/cross-user impact).
