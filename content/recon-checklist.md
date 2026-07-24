# Web Recon Checklist — Per-Target, In Recon Order

> Tick this per program. Mirrors the Master Recon Sequence in `RECON_GUIDE.md`. The point is **coverage** (find the forgotten asset) + **routing** (every finding → a bug class → impact) + **discipline** (skip the time-wasters). `§` = section in the main guide.

**Program:** ____________________  **Root(s):** ____________________  **Date:** ____________
**Scope type:** wildcard [ ] single-host [ ] ASN/IP [ ]  **Acquisitions in scope:** Y/N  **Automation allowed:** Y/N

---

## PHASE 0 — Scope & Select (§3)
*Why this matters:* the policy decides what you're *allowed* to touch — and a brilliant bug on an out-of-scope host pays **$0 and can get you banned or sued**. Reading it also tells you *where the surface is* (acquisitions in scope → a whole extra world of soft targets; ASN in scope → naked IPs with no DNS). Picking a good target is itself recon: broad scope + a real backend = more unduplicated, higher-paying bugs.
- [ ] Read policy; wrote `in_scope.txt` / `out_scope.txt`.
- [ ] Confirmed wildcard? acquisitions? ASN? mobile/API in scope?
- [ ] Noted out-of-scope assets + banned issue types + rate/automation rules + safe-harbor.
- [ ] Target is worth the time (broad scope + real backend + auth/APIs). If not → pick another (§3.2).

## PHASE 1 — Go Wide / Assets (§4–§7)
*Why this matters:* this is where you win on **coverage** — finding the forgotten hosts nobody else mapped, which is the whole cure for duplicate reports. Go *wide*: expand the org first (acquisitions/ASN are the least-hunted surface), then list *every* subdomain via passive (silent, third-party data) and active (your own DNS queries) enumeration. The two under-used passes here — **permutations** and org-expansion — are precisely where your edge over the crowd comes from.
- [ ] **Org expand** (§4): ASN, reverse-whois, acquisitions, favicon/analytics-ID pivots → extra root domains.
- [ ] **Passive subs** (§5): subfinder + amass + crt.sh + chaos (+ GitHub subs). API keys configured.
- [ ] Grepped passive list for `admin/internal/staging/dev/uat/vpn/jenkins/jira/git/api`.
- [ ] **Active subs** (§6): resolve → DNS brute → **permutations** (the high-yield, under-used pass).
- [ ] **Extras** (§7): TLS-SAN harvest, recursive enum, internal hostnames from JS/CT, alt-TLD/region.
- [ ] Merged → `subs_all.txt` (the complete asset list).

## PHASE 2 — Resolve & Probe (§8–§11)
*Why this matters:* a list of subdomain *names* is useless until you know which are alive and *what they are*. Probing turns names into a **map of real, identified services** — and the single most important habit is **sorting by "interesting"** (auth/admin/api/dev), because your manual time is finite and belongs on the hosts with a backend behind them. The origin-IP hunt here is the trick that later lets your payloads bypass the WAF.
- [ ] `httpx` probe all subs (status/title/tech/cname/ip), multi-port.
- [ ] Built `live.txt`; **sorted by interesting** (auth/api/admin/dev/dashboards), not alphabetically.
- [ ] Flagged `401/403` auth walls (bypass candidates) and `5xx`/redirects.
- [ ] **Ports** (§9): naabu top-1000; probed open ports for HTTP; noted data-store/dashboard ports.
- [ ] **Origin-IP hunt** (§9) where WAF/CDN present (historical DNS / Shodan cert / favicon).
- [ ] **Tech + favicon hash** (§10): fingerprinted stack; Shodan favicon pivot for hidden instances.
- [ ] **vhost fuzz** (§11) on shared IPs for no-DNS sites.

## PHASE 3 — Go Deep (interesting hosts only) (§12–§16)
*Why this matters:* now you drill into the *few* interesting hosts to find the actual doors — endpoints, parameters, and APIs. This is where the two "others miss" jackpots live: **source maps** (rebuild the app's original source code) and **JS mining** (read the app's blueprint). Note the scope discipline — you go deep on the 50 hosts that matter, never all 5,000; deep-crawling the marketing site while the API sits untouched is the classic time-sink.
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
*Why this matters:* these are the **fast, clean, high-severity, low-dupe** wins — a subdomain takeover or a verified leaked key can be a Critical in your *first hour*, before you've even opened the main app. That's why the phase says "run early" despite its high number. Two rules keep them valid: **verify** secrets before believing them (most matches are dead keys), and prove buckets/takeovers with a **benign** marker you clean up — never touch real data.
- [ ] **Subdomain takeover** (§17): nuclei/subzy across full list; checked cookie scope → ATO escalation.
- [ ] **Secrets** (§18): GitHub dorks + trufflehog on org & commit **history**; `.tfstate`; **verified** before believing.
- [ ] **Cloud buckets** (§19): cloud_enum/s3scanner; tested read (and benign write).
- [ ] **Exposed git/env/backups** (§20): nuclei exposures; git-dumper on any `.git`.
- [ ] **CORS / cookie-trust map** (§21): reflected-origin test; `.target.com` cookie/CORS trust noted.
- [ ] **Mobile/3rd-party** (§22): in-scope APK endpoints/keys; exposed Jira/Confluence/status pages.
- [ ] **Mobile deep-mine (§22.1):** decompiled APK/IPA (jadx/apktool) → endpoints/keys/buckets/Firebase RTDB → feed JS-files/SSRF/JWT kits.
- [ ] **Internet-wide dorking (§22.2):** Shodan/Censys (cert-CN + favicon hash) → CDN origin IP / exposed panels ; Google/GitHub dorks → leaked secrets ; Postman/Pastebin/Docker Hub.

## PHASE 5 — Route → Impact ⭐ (§23–§25)
*Why this matters:* **this is the entire point of recon** — a pile of hosts is worthless until each one becomes "test bug class X here because Y." Routing converts "I found 3,000 endpoints" into "these 40 are IDOR/SSRF candidates worth my time," ranked by impact-per-hour. Equally important is the *skip* list: consciously dropping the info-disclosure noise and dead static hosts so you don't waste hours filing things programs auto-close.
- [ ] Every interesting asset mapped to a **bug class** via the matrix (§23).
- [ ] Built a **ranked testing queue** by impact-per-hour (Tier-1 criticals → Tier-2 API/authz) (§24).
- [ ] Consciously **dropped time-wasters** (info-disclosure noise, dead static hosts, no-impact redirects) (§25).
- [ ] For each queued item, wrote a one-line **hypothesis** ("`/api/v1/` may have BOLA via `id`").

## PHASE 6 — Automate & Monitor (§26–§29)
*Why this matters:* recon isn't a one-shot — the target's surface changes every week, and **new assets are the least-tested, least-duped surface there is**. Automating the breadth and setting monitoring means you get *alerted the hour a new subdomain ships* and can test it before the crowd's weekly scans even notice — a standing first-mover advantage. And OPSEC keeps you paid and legal: in scope, rate-limited, and logged.
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
