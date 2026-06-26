# Web Recon Checklist — Per-Target, In Recon Order

> Tick this per program. Mirrors the Master Recon Sequence in `RECON_GUIDE.md`. The point is **coverage** (find the forgotten asset) + **routing** (every finding → a bug class → impact) + **discipline** (skip the time-wasters). `§` = section in the main guide.

**Program:** ____________________  **Root(s):** ____________________  **Date:** ____________
**Scope type:** wildcard [ ] single-host [ ] ASN/IP [ ]  **Acquisitions in scope:** Y/N  **Automation allowed:** Y/N

---

## PHASE 0 — Scope & Select (§3)
- [ ] Read policy; wrote `in_scope.txt` / `out_scope.txt`.
- [ ] Confirmed wildcard? acquisitions? ASN? mobile/API in scope?
- [ ] Noted out-of-scope assets + banned issue types + rate/automation rules + safe-harbor.
- [ ] Target is worth the time (broad scope + real backend + auth/APIs). If not → pick another (§3.2).

## PHASE 1 — Go Wide / Assets (§4–§7)
- [ ] **Org expand** (§4): ASN, reverse-whois, acquisitions, favicon/analytics-ID pivots → extra root domains.
- [ ] **Passive subs** (§5): subfinder + amass + crt.sh + chaos (+ GitHub subs). API keys configured.
- [ ] Grepped passive list for `admin/internal/staging/dev/uat/vpn/jenkins/jira/git/api`.
- [ ] **Active subs** (§6): resolve → DNS brute → **permutations** (the high-yield, under-used pass).
- [ ] **Extras** (§7): TLS-SAN harvest, recursive enum, internal hostnames from JS/CT, alt-TLD/region.
- [ ] Merged → `subs_all.txt` (the complete asset list).

## PHASE 2 — Resolve & Probe (§8–§11)
- [ ] `httpx` probe all subs (status/title/tech/cname/ip), multi-port.
- [ ] Built `live.txt`; **sorted by interesting** (auth/api/admin/dev/dashboards), not alphabetically.
- [ ] Flagged `401/403` auth walls (bypass candidates) and `5xx`/redirects.
- [ ] **Ports** (§9): naabu top-1000; probed open ports for HTTP; noted data-store/dashboard ports.
- [ ] **Origin-IP hunt** (§9) where WAF/CDN present (historical DNS / Shodan cert / favicon).
- [ ] **Tech + favicon hash** (§10): fingerprinted stack; Shodan favicon pivot for hidden instances.
- [ ] **vhost fuzz** (§11) on shared IPs for no-DNS sites.

## PHASE 3 — Go Deep (interesting hosts only) (§12–§16)
- [ ] **History** (§12): gau/wayback/katana → `urls_all.txt`; **gf-routed** to xss/ssrf/redirect/idor/sqli/lfi.
- [ ] Extracted forgotten sensitive files + **all historical param names**.
- [ ] **Content disco** (§13): ffuf dirs/files (context-matched list); recursed into found dirs.
- [ ] Probed direct: `/.git /.env /actuator /swagger /graphql /server-status /.DS_Store`.
- [ ] **403/401 bypass** attempts on interesting protected paths (§13).
- [ ] **Params** (§14): arjun per endpoint; tested high-value names (redirect/url/id/debug/admin/file).
- [ ] **JS analysis** (§15): collected bundles; extracted endpoints + secrets (jsluice/trufflehog).
- [ ] **SOURCE MAPS** (§15.1): probed `.js.map`; reconstructed source where exposed.
- [ ] **APIs** (§16): found swagger/openapi; tested old API versions; GraphQL introspection (or clairvoyance).

## PHASE 4 — High-Value ⭐ (§17–§22) — run early, pays fast
- [ ] **Subdomain takeover** (§17): nuclei/subzy across full list; checked cookie scope → ATO escalation.
- [ ] **Secrets** (§18): GitHub dorks + trufflehog on org & commit **history**; `.tfstate`; **verified** before believing.
- [ ] **Cloud buckets** (§19): cloud_enum/s3scanner; tested read (and benign write).
- [ ] **Exposed git/env/backups** (§20): nuclei exposures; git-dumper on any `.git`.
- [ ] **CORS / cookie-trust map** (§21): reflected-origin test; `.target.com` cookie/CORS trust noted.
- [ ] **Mobile/3rd-party** (§22): in-scope APK endpoints/keys; exposed Jira/Confluence/status pages.
- [ ] **Mobile deep-mine (§22.1):** decompiled APK/IPA (jadx/apktool) → endpoints/keys/buckets/Firebase RTDB → feed JS-files/SSRF/JWT kits.
- [ ] **Internet-wide dorking (§22.2):** Shodan/Censys (cert-CN + favicon hash) → CDN origin IP / exposed panels ; Google/GitHub dorks → leaked secrets ; Postman/Pastebin/Docker Hub.

## PHASE 5 — Route → Impact ⭐ (§23–§25)
- [ ] Every interesting asset mapped to a **bug class** via the matrix (§23).
- [ ] Built a **ranked testing queue** by impact-per-hour (Tier-1 criticals → Tier-2 API/authz) (§24).
- [ ] Consciously **dropped time-wasters** (info-disclosure noise, dead static hosts, no-impact redirects) (§25).
- [ ] For each queued item, wrote a one-line **hypothesis** ("`/api/v1/` may have BOLA via `id`").

## PHASE 6 — Automate & Monitor (§26–§29)
- [ ] Wrapped recon in `scripts/x8bit_recon.sh` (idempotent, `anew`-based, polite rate).
- [ ] **Monitoring set** (§27): daily subdomain/CT/JS diff → `notify` (first-mover on new assets). ⭐
- [ ] Applied red-team trust-edge thinking (weak sub → main app via CORS/cookie/SSO) (§28).
- [ ] OPSEC: rate-limited, in-scope only, attributable, logged actions (§29).

---

## Quick "am I doing recon right?" gate
```
Did I go WIDE before deep? (org/ASN/acquisitions, not just *.target)      NO → expand first (§4).
Did I run the PERMUTATION + SOURCE-MAP passes others skip?                 NO → do them; that's your edge (§6/§15).
Did I run Tier-1 (takeover/.git/.env/buckets) across the WHOLE surface?    NO → do it now; fast criticals (§24).
Does every asset I'll manually test route to a bug class with impact?      NO → it's coverage, not a task (§25).
Is monitoring set so new assets alert me?                                  NO → set it; first-mover = unduped bugs (§27).
Am I in scope + within rate rules?                                          NO → stop; fix before continuing (§29).
```

## Per-host mini-loop (interesting hosts)
```
probe → history+JS+source-maps → swagger/GraphQL → params → route to bug class
      → Tier-1 quick checks (takeover/.git/.env/CORS) → queue by impact → (then exploit)
```
