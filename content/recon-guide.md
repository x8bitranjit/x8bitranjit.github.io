# Web Reconnaissance for Bug Bounty — Complete In-Depth Guide (Expert / Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Web & API targets — wildcard programs, single-domain programs, SaaS, multi-tenant, cloud-native
**Platforms:** Kali/Linux first-class (recon lives in the shell); Windows/WSL notes provided
**Companion files in this folder:**
- `RECON_ARSENAL.md` — every tool + the exact one-liner per phase (copy-paste)
- `RECON_CHECKLIST.md` — the recon-order checklist you tick through per target
- `RECON_NOTES_TEMPLATE.md` — the asset inventory + finding tracker you keep per program
- `scripts/` — a runnable recon pipeline (enumerate → resolve → probe → mine JS → takeover-check → monitor)

> **Companion to every exploitation kit — Recon is the hub that feeds them all.** It routes each finding to the class that turns it into a payout (XSS · JWT/OAuth-SSO · IDOR/API · SSRF · CORS · FileUpload · subdomain-takeover — see the §23 matrix). Same impact-first philosophy as the XSS & JWT guides: don't collect data, collect **attack surface that converts to impact**. Recon is the single highest-leverage skill in bug bounty because **you can't exploit what you never found**, and the assets *other hunters never found* are where the unduplicated, high-paying bugs live. But recon also wastes more time than any other phase — this guide is ruthless about **what to skip**.

---

> ### ⚡ READ THIS FIRST — the recon rules that separate earners from data-hoarders
> 1. **Recon is not the goal — the bug is.** A list of 40,000 subdomains is worthless; *one forgotten staging admin panel* is a payout. Every recon action must answer "does this expose a place I can find a bug nobody else did?" If not, skip it.
> 2. **Breadth then depth — but depth pays.** Go *wide* first (find every asset), then go *deep* on the few assets that smell exploitable (auth panels, APIs, dashboards, dev/staging, file uploads, payment). Don't deep-dive the marketing site.
> 3. **What you find that others miss = unduplicated bugs.** Dupes are the #1 frustration in bounty. The cure is recon depth: acquisitions, ASN ranges, source maps, vhosts, archived params, fresh subdomains found *minutes* after they go live. Surface nobody else mapped → bugs nobody else reported.
> 4. **Fresh > thorough.** A subdomain that appeared today, an endpoint added in last week's JS, a newly-acquired company's assets — these have the least competition. **Monitoring beats one-shot scanning.** (§27)
> 5. **Impact lives in specific places.** Auth/SSO, admin/internal panels, APIs, dev/staging/UAT, file handling, payment, GraphQL, cloud storage, anything with `dashboard`/`internal`/`api`/`admin`/`dev`/`vpn`/`jira`/`git` in the name. Recon's job is to *route you there fast*. (§23–§24)
> 6. **Stay in scope, stay legal.** Wildcards (`*.target.com`) expand scope; acquisitions may or may not be in scope — **read the policy**. Recon touches a lot of hosts; don't port-scan or brute out-of-scope assets. (§3, §29)
>
> **Where the money is (memorize this routing order):** ① **forgotten/dev/staging/admin hosts** (least hardened, least duped) → ② **APIs & GraphQL** (authz/IDOR/logic goldmines) → ③ **leaked secrets** (GitHub dorking, source maps, `.env`, exposed `.git`) → ④ **subdomain takeover & dangling cloud** (clean, high-severity, fast) → ⑤ **newly-discovered assets via monitoring** (first-mover advantage) → ⑥ *then* the well-trodden main app, where everyone else already is.

---

## Table of Contents

**▶ [Master Recon Sequence — the recon order](#master-recon-sequence--the-recon-order)** — follow this top-to-bottom.

**PART I — FOUNDATIONS & SCOPE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [The Recon Mindset — Attack Surface = Impact Surface](#2-the-recon-mindset)
3. [Scope, Authorization & Target Selection](#3-scope-authorization--target-selection)

**PART II — ASSET DISCOVERY (go wide / horizontal)**
4. [Root-Domain & Org Expansion (ASN, acquisitions, reverse-whois)](#4-root-domain--org-expansion)
5. [Subdomain Enumeration — Passive](#5-subdomain-enumeration--passive)
6. [Subdomain Enumeration — Active (brute, permutations, DNS)](#6-subdomain-enumeration--active)
7. [Subdomain Enumeration — What People Miss](#7-subdomain-enumeration--what-people-miss)

**PART III — RESOLUTION & FINGERPRINTING**
8. [Liveness & HTTP Probing](#8-liveness--http-probing)
9. [Port Scanning & Service Discovery](#9-port-scanning--service-discovery)
10. [Technology Fingerprinting & Favicon Hashing](#10-technology-fingerprinting--favicon-hashing)
11. [Virtual-Host (vhost) Discovery](#11-virtual-host-vhost-discovery)

**PART IV — CONTENT & ENDPOINT DISCOVERY (go deep / vertical)**
12. [Historical Data Mining (Wayback, gau, archives)](#12-historical-data-mining)
13. [Content & Directory Discovery](#13-content--directory-discovery)
14. [Parameter Discovery](#14-parameter-discovery)
15. [JavaScript Analysis — Endpoints, Secrets, Source Maps](#15-javascript-analysis)
16. [API & GraphQL Discovery](#16-api--graphql-discovery)

**PART V — HIGH-VALUE RECON (where the money is)**
17. [Subdomain Takeover](#17-subdomain-takeover)
18. [Secrets Hunting — GitHub/GitLab Dorking & Leaks](#18-secrets-hunting)
19. [Cloud Asset Discovery (S3/GCS/Azure)](#19-cloud-asset-discovery)
20. [Sensitive Exposure (.git, .env, backups, debug, configs)](#20-sensitive-exposure)
21. [CORS & Subdomain-Trust Recon](#21-cors--subdomain-trust-recon)
22. [Mobile, Third-Party & Supply-Chain Recon](#22-mobile-third-party--supply-chain-recon)

**PART VI — RECON → VULN MAPPING (if this then that)**
23. [The Attack-Surface-to-Bug Decision Matrix](#23-the-attack-surface-to-bug-decision-matrix)
24. [Prioritization — What to Test First for Impact](#24-prioritization--what-to-test-first-for-impact)
25. [What NOT to Waste Time On](#25-what-not-to-waste-time-on)

**PART VII — AUTOMATION, MONITORING & RED TEAM**
26. [Building a Recon Pipeline](#26-building-a-recon-pipeline)
27. [Continuous Monitoring — First-Mover Bugs](#27-continuous-monitoring)
28. [Red-Team Recon Angles for Bug Bounty](#28-red-team-recon-angles)
29. [OPSEC, Rate-Limiting & Staying In-Scope](#29-opsec-rate-limiting--staying-in-scope)

**Appendices**
- [Appendix A — Recon Workflow Cheat Sheet](#appendix-a--recon-workflow-cheat-sheet)
- [Appendix B — Recon Decision Tree](#appendix-b--recon-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Recon Sequence — The Recon Order

> **This is the spine.** Work it top-to-bottom. Each phase says *what to do*, *which § for detail*, and the *deliverable* that feeds the next phase. The numbered sections (1–29) are the reference detail; this sequence is the order you actually run. The whole pipeline is in `scripts/x8bit_recon.sh`.

```
PHASE 0  SCOPE & SELECT     → read policy · pick a target worth your time · note in/out of scope (§3)
PHASE 1  GO WIDE (assets)   → org/ASN/acquisitions (§4) → passive subs (§5) → active subs (§6) → what-others-miss (§7)
PHASE 2  RESOLVE & PROBE    → resolve · httpx probe · ports · tech + favicon (§8–§10) · vhosts (§11)
PHASE 3  GO DEEP (content)  → wayback/gau (§12) · dirs/files (§13) · params (§14) · JS+source-maps (§15) · APIs/GraphQL (§16)
PHASE 4  HIGH-VALUE  ⭐      → takeover (§17) · secrets/GitHub (§18) · cloud buckets (§19) ·
                              exposed .git/.env/backups (§20) · CORS trust (§21) · mobile/3rd-party (§22)
PHASE 5  ROUTE → IMPACT  ⭐  → map surface→bug (§23) · prioritize for impact (§24) · skip the time-wasters (§25)
PHASE 6  AUTOMATE & WATCH    → pipeline (§26) · CONTINUOUS monitoring of new assets (§27) · red-team angles (§28)
```

**Phase-by-phase, with the deliverable before you move on:**

1. **PHASE 0 — Scope & select.** Read the policy: wildcard or single host? Are acquisitions/ASN in scope? What's explicitly out? Pick a target with a **real backend** and **broad scope** (more surface = more unduplicated bugs). *Deliverable:* a scope file (`in_scope.txt`, `out_scope.txt`) and a reason this target is worth a week.
2. **PHASE 1 — Go wide.** Expand the org (ASN, acquisitions, reverse-whois, §4), then enumerate **all** subdomains passively (§5) and actively (§6), then add the layer most hunters skip (§7). *Deliverable:* `subs_all.txt` — the complete asset list.
3. **PHASE 2 — Resolve & probe.** Resolve DNS, probe HTTP with `httpx` (status/title/tech/CDN), scan ports on interesting hosts, fingerprint tech + favicon, find vhosts (§8–§11). *Deliverable:* `live.txt` with status/title/tech, sorted by "interesting".
4. **PHASE 3 — Go deep.** On the *interesting* hosts only: mine history (§12), discover content/params (§13–§14), **analyze JS and pull source maps** (§15), enumerate APIs/GraphQL (§16). *Deliverable:* `endpoints.txt`, `params.txt`, `js_secrets.txt`, `api_routes.txt`.
5. **PHASE 4 — High-value recon ⭐.** The fast, high-severity, low-dupe wins: subdomain takeover (§17), GitHub/secret leaks (§18), cloud buckets (§19), exposed `.git`/`.env`/backups (§20), permissive CORS (§21), mobile/third-party surface (§22). *Deliverable:* a shortlist of confirmed exposures + leads.
6. **PHASE 5 — Route to impact ⭐.** Map every surface element to the bug classes it implies (§23), order by impact-per-hour (§24), and *consciously skip* the dead ends (§25). *Deliverable:* a ranked testing queue — what you'll hit first, with the hypothesis for each.
7. **PHASE 6 — Automate & watch.** Wrap it in a pipeline (§26) and **set monitoring** so new subdomains/JS/endpoints alert you within hours (§27); apply red-team angles (§28). *Deliverable:* a cron'd pipeline + alerting = a standing first-mover advantage.

Reference anytime: commands → `RECON_ARSENAL.md`; checklist → `RECON_CHECKLIST.md`; tracker → `RECON_NOTES_TEMPLATE.md`; pipeline → `scripts/`.

---

# PART I — FOUNDATIONS & SCOPE

# 1. Environment & Tooling Setup

You don't need 200 tools. You need a tight, fast, ProjectDiscovery-centric stack plus a few specialists. Install these; the rest are situational (see `RECON_ARSENAL.md`).

| Tool | Job | Why it's in the core set |
|------|-----|--------------------------|
| **subfinder** | passive subdomain enum | fast, many sources, one binary |
| **amass** (intel + enum) | deep passive + ASN/whois | best for org expansion (§4) |
| **dnsx** | resolve / DNS bruteforce / wildcard filter | the resolver glue |
| **puredns / massdns** | mass DNS bruteforce | active enum at scale (§6) |
| **httpx** | HTTP probe (status/title/tech/cdn/cname) | the single most-used recon tool |
| **naabu** | fast port scan | find non-80/443 surface (§9) |
| **katana** | crawler (incl. JS parsing) | endpoint + JS discovery (§13/§15) |
| **gau / waybackurls** | historical URLs | dead params & endpoints others miss (§12) |
| **ffuf** | content/param/vhost fuzzing | the fuzzing workhorse (§11/§13/§14) |
| **nuclei** | templated checks (takeover, exposures, CVEs) | fast triage of the whole surface |
| **gf** + patterns | grep known-vuln param patterns | route URLs to bug classes (§23) |
| **trufflehog / gitleaks** | secret scanning | GitHub & JS secret hunting (§18) |
| **subjs / getJS / jsluice** | extract & parse JS | endpoints/secrets in bundles (§15) |
| **dalfox / arjun** | param mining + XSS verify | hand-off to exploitation |
| **interactsh** | OOB callbacks | SSRF/blind during follow-up |
| **anew / qsreplace / unfurl** | tomnomnom glue | dedup, rewrite, parse URLs |

```bash
# One-shot install (Go tools) — Kali/WSL
for t in subfinder dnsx httpx naabu katana nuclei; do
  go install github.com/projectdiscovery/$t/cmd/$t@latest; done
go install github.com/owasp-amass/amass/v4/...@master
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/{waybackurls,anew,unfurl,qsreplace,gf}@latest
go install github.com/ffuf/ffuf/v2@latest
go install github.com/hahwul/dalfox/v2@latest
pipx install arjun
# secret/JS specialists
go install github.com/trufflesecurity/trufflehog@latest    # or: pip install trufflehog
go install github.com/lc/subjs@latest
pipx install gitleaks 2>/dev/null || true
# wordlists (the part everyone underrates)
git clone https://github.com/danielmiessler/SecLists /opt/SecLists
git clone https://github.com/assetnote/commonspeak2-wordlists /opt/commonspeak2
# resolvers (KEEP THESE FRESH — stale resolvers = missed/false subs)
wget -qO /opt/resolvers.txt https://raw.githubusercontent.com/trickest/resolvers/main/resolvers.txt
```
> **Windows:** run recon in **WSL2 (Ubuntu/Kali)**. Native Windows works for the Python/Go binaries but the shell glue (`anew`, pipes, `gf`) is built for *nix. Use WSL and access this `Recon/` folder via its WSL mount path (`/mnt/<drive>/…/Web/Recon`) — wherever you've placed the `Web/` kit on this machine.

**API keys are a force multiplier.** Add free/cheap keys to `subfinder`/`amass`/`gau` configs: Censys, Shodan, SecurityTrails, VirusTotal, GitHub, Chaos (ProjectDiscovery, free for bounty). Without keys you find ~60% of subdomains; with keys, ~95%. This alone is a "what others miss" edge.

---

# 2. The Recon Mindset

*New to this? Here's what "recon" even means.* **Reconnaissance** (recon) is the *map-making* phase of hacking. Before a burglar ever touches a lock, a smart one walks the whole property: how many buildings, which doors and windows exist, which are round the back where nobody looks, which were left unlocked by the builders. In bug bounty the "property" is everything a company runs online, and recon is **drawing the complete map of it** — every website, server, and hidden entry point — *before* you try to break in. The break-in itself (finding the actual bug) is what the other kits (XSS, IDOR, SSRF…) teach; **this kit is purely about finding the doors**. Why it matters so much: *you cannot exploit a door you never found* — and the doors *other hunters* never found are where the un-reported, best-paying bugs live. So the entire goal here is **"find the forgotten back door before anyone else does,"** then hand it to an exploitation kit. Every jargon term below (subdomain, ASN, DNS, vhost, source map…) is explained in plain English the first time it shows up.

Recon's deliverable is **a ranked list of places a bug is likely, that few others have looked at.** Everything maps to one of three questions:

```
WHAT to look for   → assets (hosts/IPs/buckets) + endpoints (URLs/params/APIs) + secrets + trust relationships
WHY                → each is a door to a bug class WITH impact (authz, IDOR, takeover, RCE, secret→ATO)
WHERE              → the "boring" places others skip: acquisitions, ASN, staging, JS maps, archived params, vhosts
HOW                → wide (passive+active enum) → resolve/probe → deep (content/JS/API) → high-value (takeover/secret/cloud)
WHAT ELSE          → monitor for NEW surface (first-mover), pivot via trust (CORS, SSO, shared infra), correlate (favicon/ASN)
WHAT TO SKIP       → dead marketing pages, banner-grab "info disclosures", out-of-scope, giant brute on cold targets (§25)
```

**The three recon archetypes (be all three):**
- **The wide hunter** — maps every asset; wins on *coverage* (finds the forgotten host).
- **The deep hunter** — reads every JS bundle and archived URL; wins on *endpoints* (finds the hidden API).
- **The monitor** — automates and watches; wins on *time* (reports the bug an hour after the asset ships).

> The expert edge is not a secret tool — it's **discipline about routing**: spend 80% of effort on the 20% of surface that has a backend, auth, or money behind it. The rest is noise you should *find* (for completeness/takeover/monitoring) but not *manually test*.

---

# 3. Scope, Authorization & Target Selection

## 3.1 Read the policy like it pays (because it does)
```
□ Wildcard (*.target.com) or single host(s)?     → wildcard = far more unduplicated surface; prefer these.
□ Are ACQUISITIONS / subsidiaries in scope?       → often yes for big programs = fresh, un-hunted assets (§4).
□ ASN / IP ranges in scope?                        → lets you find non-DNS assets (naked IPs, §9).
□ OUT of scope assets / issue types?               → e.g. "no automated scanning", "no DoS", "*.blog excluded".
□ Mobile apps / APIs in scope?                      → mobile = leaked endpoints/keys (§22, and the Android guide).
□ Rules on automation & rate?                       → some ban heavy scanning; respect it (§29) or get banned.
□ Safe-harbor present?                              → legal authorization to test.
```
Write `in_scope.txt` and `out_scope.txt` *now*. Every later tool reads them. **A great bug on an out-of-scope host is $0 and possibly illegal.**

## 3.2 Pick targets that pay (target selection is recon too)
Not all programs are equal. Prefer:
- **Broad scope** (`*.target.com` + acquisitions) → coverage = unduplicated bugs.
- **Real backends** (SaaS, fintech, dashboards, APIs) → impact lives here; brochure sites don't pay.
- **Large/old orgs** → tech debt, forgotten staging, acquisitions, legacy subdomains = your edge.
- **Newer programs / newly-expanded scope** → less picked-over; first-mover.
- **Programs you'll *monitor*** → recurring assets = recurring bugs (§27).

Avoid sinking a week into: tiny single-domain scopes, "VDP" (no-pay) unless you want CVEs, programs notorious for slow triage/closing-as-dup, or assets that are pure static content.

> **Worth-my-time filter:** if Phase 1–2 reveals broad scope + auth panels + APIs + dev/staging hosts, commit. If it's one hardened marketing domain with a CDN and nothing behind it, move on — recon told you the truth, listen to it.

---

# PART II — ASSET DISCOVERY (go wide / horizontal)

# 4. Root-Domain & Org Expansion

*In plain words:* a big company doesn't own just `target.com` — over the years it buys other companies, registers spare domains (`target.io`, `target.co.uk`), and rents blocks of internet addresses. The jargon: an **ASN** (Autonomous System Number) is basically *"the ID number for a company's own chunk of the internet"* — look it up and it tells you every IP address range they own. **Reverse-WHOIS** means *"search domain-registration records backwards"* — instead of "who owns target.com?", you ask "what *other* domains were registered by the same company/email?" and out pop their siblings. **Acquisitions** are companies they bought, which usually still run on the acquired company's old, less-guarded servers. This section finds all of that — the org's *whole* footprint, not just the obvious domain — which is exactly the surface other hunters skip.

**This is the #1 "what others miss" phase.** Most hunters start at `*.target.com` and stop. Experts first find **every domain the org owns** — acquisitions, alternate TLDs, and IP ranges — because those carry the least competition.

## 4.1 Find the org's other root domains
```
□ ASN → IP ranges → reverse-DNS → more domains
   amass intel -org "Target Inc"          # ASN/org search
   whois <known-IP> | grep -i origin       # find the ASN, then enumerate its prefixes
□ Reverse WHOIS (same registrant email/org) → sibling domains
   (whoxy / domaintools / amass intel -whois -d target.com)
□ Acquisitions → Crunchbase / Wikipedia / "Target acquires" news / SEC filings
   → each acquired company = its own root domain(s), often still on old infra = goldmine.
□ Favicon hash pivot (§10) → other domains serving the same favicon = same org.
□ Same Google Analytics / GTM / Adsense ID → sites run by the same org (builtwith / publicwww).
□ Certificate org/SAN pivot → certs naming the org reveal sibling domains (crt.sh org search).
□ Trademark / copyright string in page footers → publicwww "© Target Inc".
```

## 4.2 Then enumerate ASN ranges for naked assets
DNS-less assets (a bare IP running an old admin panel) never show up in subdomain enum. Scan in-scope ASN/IP ranges (§9) for live HTTP on odd ports.

> **If this → then that:** if acquisitions are in scope and the org bought a startup 2 years ago → that startup's `*.acquired.com` is probably on un-patched infra with weak auth → **prioritize it over the polished main app.**

> **Skip if:** the policy is a single explicit host with no wildcard/acquisitions clause — org expansion is out of scope, don't waste time (and don't test it).

---

# 5. Subdomain Enumeration — Passive

*In plain words:* a **subdomain** is a prefix on the main domain — `mail.target.com`, `admin.target.com`, `api.target.com` are all subdomains of `target.com`, and each is usually a *separate* server/app with its own bugs. Companies have dozens to thousands of them, and the forgotten ones (`old-admin.target.com`) are gold. **Enumeration** just means *"make the full list."* **Passive** enumeration means you build that list by asking *third-party databases* that already recorded these names — you send **zero traffic to the target itself**, so it's fast, safe, and can't get you blocked. The richest such database is **Certificate Transparency (CT) logs**: every time a site gets an HTTPS certificate, that hostname is published to a public log — so `crt.sh` is basically *"a public list of every hostname anyone ever got a certificate for,"* including internal-sounding ones the company never meant to reveal.

Passive = query third-party datasets (no packets to the target). Fast, safe, in-scope-friendly. Always do this first and most.

```bash
# Core passive sweep (configure API keys first — see §1):
subfinder -d target.com -all -recursive -o subs_subfinder.txt
amass enum -passive -d target.com -o subs_amass.txt
# Certificate transparency (catches internal-naming subs others miss):
curl -s "https://crt.sh/?q=%25.target.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u >> subs_crt.txt
# ProjectDiscovery Chaos dataset (free for bounty):
chaos -d target.com -o subs_chaos.txt
# Merge + dedup:
cat subs_*.txt | sort -u | anew subs_passive.txt
```

**Sources that matter (subfinder/amass aggregate most):** crt.sh & Censys (CT logs), VirusTotal, SecurityTrails, Shodan, AlienVault OTX, Wayback, RapidDNS, DNSDumpster, GitHub code search (subdomains hardcoded in repos).

> **What others miss here:** **certificate transparency internal names.** Devs put internal hostnames (`admin-staging`, `internal-api`, `vpn-test`) in TLS SANs. `crt.sh` reveals them even if DNS is split-horizon. Always grep CT output for `admin/internal/staging/dev/test/vpn/jenkins/jira/git`.

---

# 6. Subdomain Enumeration — Active

*In plain words:* **DNS** (Domain Name System) is the internet's phone book — it turns a name like `api.target.com` into the numeric IP address of the server. **Active** enumeration means *you* now query that phone book directly to discover names, instead of reading third-party databases. Two moves: **brute-force** = *"try thousands of common prefixes"* (`admin`, `dev`, `test`, `vpn`…) against the phone book and keep the ones that answer — this finds hosts that exist but were never published anywhere public. **Permutations** = *"take the names you already found and generate obvious variations"* — if `api.target.com` exists, automatically test `api-dev`, `api2`, `api-staging`, `dev-api`, and so on, because those siblings almost always exist and are far less locked down. **Resolve** just means *"check which names actually answer in the phone book"* (drop the dead ones). This is called active because the DNS lookups are traffic you generate — still light and normally fine, but not the pure zero-touch of passive.

Active = you send DNS queries (resolution, brute, permutations). Finds subs that exist but aren't in any public dataset.

```bash
# 1) Resolve passive results, drop dead ones, filter DNS wildcards:
puredns resolve subs_passive.txt -r /opt/resolvers.txt --write subs_resolved.txt

# 2) DNS bruteforce with a good wordlist (this finds the unlisted ones):
puredns bruteforce /opt/SecLists/Discovery/DNS/subdomains-top1million-110000.txt target.com \
  -r /opt/resolvers.txt --write subs_brute.txt
# bigger: /opt/commonspeak2/subdomains/subdomains.txt

# 3) Permutations/alterations (dev→dev2, api→api-staging, etc.) — HIGH yield, under-used:
gotator -sub subs_resolved.txt -perm /opt/SecLists/Discovery/DNS/dns-permutations.txt -depth 1 -numbers 3 \
  | puredns resolve -r /opt/resolvers.txt --write subs_perm.txt
# (alternatives: dnsgen, altdns, ripgen, dmut)

# 4) Merge everything:
cat subs_resolved.txt subs_brute.txt subs_perm.txt | sort -u | anew subs_all.txt
```

> **Permutation enumeration is the biggest "what others miss".** If `api.target.com` exists, then `api-dev`, `api2`, `api-staging`, `api-internal`, `api.eu`, `dev-api` very often exist too — and they're far less hardened. Always run a permutation pass seeded from your *resolved* subs.

> **Keep resolvers fresh.** Stale/poisoned resolvers cause both missed subs and false positives. Re-pull `resolvers.txt` weekly. Use `--write-wildcards` and verify wildcard domains so you don't drown in `*.target.com` garbage.

---

# 7. Subdomain Enumeration — What People Miss

The extra passes that separate a complete map from a partial one:

```
□ CT-log monitoring (continuous)   → new certs = new subdomains, minutes after issue (§27). First-mover.
□ VHost / SNI discovery            → subs that resolve to a shared IP but aren't in DNS (§11).
□ Recursive enum on found subs     → enumerate subs OF subs (corp.target.com → *.corp.target.com).
□ Internal names from JS/source    → bundles reference internal hosts/APIs (§15). Grep JS for *.target.com.
□ TLS SAN harvesting on live IPs   → scan IPs, read cert SANs → more hostnames (tlsx / cero).
□ Cloud metadata in repos          → GitHub-leaked configs naming hosts/buckets (§18).
□ Alternate regions/TLDs           → target.co.uk, target.de, target.io, target.dev — same org, separate infra.
□ Numeric/seq guessing             → app1..app20, node1..node50, region prefixes (us-, eu-, ap-).
□ Reverse DNS on the ASN           → PTR records reveal naming you can re-brute (§4/§9).
```
```bash
# TLS SAN harvest from live hosts (find hostnames DNS won't give you):
tlsx -l live_ips.txt -san -cn -silent | grep target.com | sort -u | anew subs_all.txt
```

> **If this → then that:** if you find `jenkins.dev.target.com` in a JS bundle but it's not in your DNS list → it may be **internal-only** (split-horizon DNS). Note it; it may still be reachable via VPN-less misconfig, an open proxy, or as an SSRF target later. Internal hostnames are gold for SSRF/Server-Side payloads.

---

# PART III — RESOLUTION & FINGERPRINTING

# 8. Liveness & HTTP Probing

*In plain words:* you now have a big list of subdomain *names*, but many are dead (no server answers) and the live ones you know nothing about yet. **Probing** means *"knock on each one and write down who answers and what they are."* The tool `httpx` visits every name and records: does it respond (**liveness**), what's the **status code** (200 = open page, 401/403 = a locked door that *exists*, 301/302 = a redirect), the page **title** ("Admin", "Login", "Jenkins" — instant jackpot signals), and the **tech stack** (what software runs it). **Fingerprinting** = *"identifying what software/version something runs"* — knowing it's a Spring Boot app or a WordPress site tells you which bugs to try. The output turns a dumb name-list into a **ranked map of real, identified web services**, which is what you actually attack.

Turn your subdomain list into a **map of live, fingerprinted web services**. `httpx` is the workhorse — run it on *everything*, then sort by interesting.

```bash
httpx -l subs_all.txt -sc -title -td -server -cname -ip -location -fr \
      -p 80,443,8080,8443,8000,8888,3000,5000,9000 \
      -json -o httpx.json
# Human-readable + the columns that matter:
httpx -l subs_all.txt -sc -title -td -cname -o live.txt
```
**What to read in the output (and route on):**
```
status:  200 (live) · 401/403 (AUTH WALL → bypass-worthy, §13/§23) · 301/302 (redirect → where?) ·
         500 (error → stack trace?) · 404 on root but app behind a path
title:   "Login", "Admin", "Dashboard", "Swagger", "Jenkins", "Grafana", "phpMyAdmin", "GraphiQL" → JACKPOT
tech:    Spring Boot, Django, Rails, GraphQL, WordPress, Jira, GitLab, Kibana → known attack surfaces
cname:   points to S3/Heroku/GitHub/Azure that 404s → TAKEOVER (§17)
cdn:     behind Cloudflare? → origin-IP hunt may bypass WAF (§9); not-behind = direct
```

> **Sort your `live.txt` by "interesting", not alphabetically.** Grep titles/tech for `admin|login|dashboard|internal|dev|staging|test|api|swagger|graphql|jenkins|grafana|kibana|jira|git|vpn|portal|status`. Those go to the top of the testing queue (§24). Everything else is coverage, not a priority.

---

# 9. Port Scanning & Service Discovery

*In plain words:* a single server can run many services at once, each behind a numbered **port** — think of one building with many numbered doors. Web traffic normally uses port **80** (http) and **443** (https), but admins often leave *other* doors open: a dev app on **8080**, a database admin screen on **9200**, a container control panel on **2375**. Those side doors are frequently unauthenticated and forgotten — the easiest wins. **Port scanning** = *"check which numbered doors are open"* on a host. (Heads-up: scanning is noisier and more intrusive than the DNS work above — some programs forbid it, so check the policy first, §29.)

Web bugs aren't only on 80/443. A forgotten service on `:8080` or a database UI on `:9200` is often the easiest win.

```bash
# Fast top-ports sweep on resolved hosts (respect program rate rules, §29):
naabu -l subs_resolved.txt -top-ports 1000 -rate 1000 -o ports.txt
# Then HTTP-probe every open port:
naabu -l subs_resolved.txt -top-ports 1000 -silent | httpx -sc -title -td -o live_allports.txt
```
**High-value non-standard ports:**
```
8080/8443/8000/8888/3000  → app/dev servers, often unauthenticated staging
9200/9300 (Elasticsearch) · 5601 (Kibana) · 5984 (CouchDB) · 27017 (Mongo) · 6379 (Redis) → exposed data stores
2375 (Docker) · 10250 (Kubelet) · 6443 (k8s API)  → container/orchestration = RCE-class
9000 (SonarQube/Portainer) · 8081 (Nexus) · 50070 (Hadoop) · 15672 (RabbitMQ)  → dashboards/creds
```

## 9.1 Origin-IP hunting (WAF/CDN bypass)
*In plain words:* many sites hide their real server behind a **CDN** (Content Delivery Network, like Cloudflare) — a middle layer that sits in front, speeds things up, and includes a **WAF** (Web Application Firewall) that *blocks attack traffic before it reaches the app*. So your payloads get stopped at the gate. But the real server (the **origin**) still has its own IP address, and if you can discover that address, you can talk to it **directly** — skipping the CDN's firewall and rate-limits entirely. **Origin-IP hunting** = *"find the real server's address so you can go around the bouncer."* It's one of the highest-value recon tricks because it rescues payloads that were "blocked."

If the app is behind Cloudflare/Akamai, the **real origin IP** may be directly reachable, bypassing the WAF and rate limits:
```
□ Historical DNS (SecurityTrails, viewdns) → IPs before they moved behind the CDN.
□ SSL cert search (Censys/Shodan) for the domain's cert on a non-CDN IP.
□ Subdomains not proxied (a forgotten `direct.target.com` pointing at origin).
□ DNS records: MX/SPF/TXT sometimes leak origin infra.
□ favicon hash in Shodan → other IPs serving the same app (§10).
```
> **If this → then that:** main app behind Cloudflare WAF blocking your payloads → find the **origin IP** → hit it directly with the `Host:` header set → WAF bypassed, often *and* no rate limit. This single trick rescues many "blocked" findings.

> **Skip if:** the program forbids port scanning, or the target is a single CDN-fronted SaaS with no IP scope — don't burn time (or risk a ban) scanning.

---

# 10. Technology Fingerprinting & Favicon Hashing

*In plain words:* the **favicon** is that tiny icon in the browser tab. Every copy of the same app serves the *same* icon, so you can compute a **hash** of it — a short fingerprint number — and then search the whole internet (via Shodan, a search engine for servers) for *"every server anywhere serving an icon with this exact fingerprint."* Why that's powerful: if a company runs a custom internal admin tool, its unique favicon lets you find **every instance of that tool the company runs** — including ones on naked IP addresses that never appeared in your DNS list. It's a way to discover assets by their *looks* instead of their *name*.

Knowing the stack tells you the bug classes (§23). Favicon hashing correlates assets across the whole internet.

```bash
# Tech stack:
httpx -l live.txt -td -server -o tech.txt          # built-in tech detect
# (also: Wappalyzer extension, whatweb)

# Favicon hash → pivot to ALL hosts (anywhere) serving the same app:
curl -s https://target.com/favicon.ico | base64 | <mmh3-hash> 
# Then search Shodan: http.favicon.hash:<hash>  → finds origin IPs, sibling apps, forgotten clones.
```
**Why favicon hashing is an expert staple:**
- A custom internal-tool favicon → Shodan `http.favicon.hash:` finds **every** instance of that tool the org runs, including ones with no DNS (naked IPs, §9) and ones in other clouds.
- Default framework favicons (Spring, Jenkins, GitLab) → confirm the stack at a glance.

> **If this → then that:** you find an internal admin tool's favicon hash → Shodan it → 6 more IPs run the same tool, 2 are unauthenticated → instant access on assets that never appeared in DNS enum.

---

# 11. Virtual-Host (vhost) Discovery

*In plain words:* one server (one IP address) can host **many different websites**, and it decides *which* site to show you based on the **`Host:` header** — a line in every web request that says "I want the site called `admin.target.com`." A **virtual host (vhost)** is one of those co-hosted sites. The catch: some of them were never added to the DNS phone book, so subdomain enumeration can't find them — but the server *will* serve them if you simply *ask* for the right name in the `Host:` header. **vhost discovery** = *"try many hostnames in the `Host:` header against one known IP and watch which ones return a real, different page"* — surfacing internal/staging sites that are otherwise invisible.

A single IP can host many sites keyed on the `Host:` header. Some vhosts have **no DNS record** and are invisible to subdomain enum — but reachable if you guess the `Host:`.

```bash
# Fuzz the Host header against a known IP (filter by size to find real vhosts):
ffuf -w /opt/SecLists/Discovery/DNS/subdomains-top1million-20000.txt \
     -u https://TARGET_IP/ -H "Host: FUZZ.target.com" -fs <baseline_size> -mc all
```
> **What others miss:** internal/staging vhosts (`admin.internal.target.com`) co-hosted on a public IP with no public DNS. vhost fuzzing surfaces them. Especially productive against shared hosting, reverse proxies, and k8s ingress.

---

# PART IV — CONTENT & ENDPOINT DISCOVERY (go deep / vertical)

> From here, work **only the interesting hosts** from §8 (auth/API/dev/admin/dashboards). Don't deep-crawl the CDN'd brochure.

# 12. Historical Data Mining

*In plain words:* the internet has **archives** — services like the Wayback Machine that have been saving snapshots of websites for 20+ years. Tools like `gau` ("get all URLs") and `waybackurls` pull *every URL of the target anyone ever recorded*, including pages and parameters the company **deleted years ago**. Why you care: developers remove a link from the website but often forget to actually turn off the underlying **endpoint** (the backend address that did the work) — so a `/api/old/debug` from 2019 may *still run*, and because everyone forgot it, it's *unguarded*. Mining archives = *"dig up the old, forgotten doors that are still unlocked."* An **endpoint** is just a specific URL/address the app responds to; a **parameter** is an input tacked onto it (`?id=123` — `id` is the parameter).

Archives remember endpoints and parameters the app **deleted** — which are often still live on the backend and **unguarded** because nobody remembers them.

```bash
# Pull every historical URL:
gau --threads 5 target.com | anew urls_gau.txt
waybackurls target.com | anew urls_wayback.txt
katana -u https://target.com -jc -d 3 -kf all | anew urls_katana.txt
cat urls_*.txt | sort -u > urls_all.txt

# Route them immediately (this is where impact starts):
cat urls_all.txt | gf xss      | anew cand_xss.txt
cat urls_all.txt | gf ssrf     | anew cand_ssrf.txt
cat urls_all.txt | gf redirect | anew cand_redirect.txt
cat urls_all.txt | gf sqli     | anew cand_sqli.txt
cat urls_all.txt | gf idor     | anew cand_idor.txt
# Interesting file types (often forgotten & sensitive):
cat urls_all.txt | grep -Ei '\.(json|xml|config|env|bak|sql|log|zip|tar|gz|yml|yaml|txt|pdf|xls)' | anew files_interesting.txt
```

> **What others miss:** **archived parameters on still-live endpoints.** Wayback shows `/api/user?id=123&debug=true` from 2019; the `debug` param may still work. Extract every historical *parameter name*, then test them against current endpoints (§14).

> **If this → then that:** gau reveals `/internal/`, `/api/v1/`, `/admin/` paths that 404 on the main host → try them on **every** subdomain (path may be live elsewhere); try API-version downgrades (`v1` when the app uses `v3` — old versions skip new authz).

---

# 13. Content & Directory Discovery

Find the unlinked: admin panels, backups, configs, API docs, debug endpoints. Be **smart** about wordlists — context-matched, not "throw the biggest list."

```bash
# Targeted, fast (raft + tech-specific lists beat giant generic ones):
ffuf -w /opt/SecLists/Discovery/Web-Content/raft-medium-directories.txt \
     -u https://api.target.com/FUZZ -mc 200,201,301,302,401,403,500 -ac -o ffuf_dirs.json
# Recurse into found dirs; add extensions matched to the stack (.php/.json/.bak/.config):
ffuf -w list.txt:FUZZ -u https://host/FUZZ -e .json,.bak,.old,.config,.zip,.sql -ac -recursion -recursion-depth 2
```
**Always probe these high-value paths directly (don't just fuzz):**
```
/.git/HEAD  /.git/config           → exposed git repo (§20) — DUMP IT, full source.
/.env  /config.json  /appsettings.json → secrets (§20).
/swagger.json  /openapi.json  /api-docs  /v2/api-docs  /graphql  /graphiql → API surface (§16).
/actuator  /actuator/env  /actuator/heapdump  → Spring Boot exposure (creds/heap = ATO).
/server-status  /server-info  /.well-known/  /metrics  /debug  /trace
/backup/  /old/  /test/  /dev/  /tmp/  /.DS_Store  /sitemap.xml  /robots.txt (read these for free paths)
```

> **403/401 is not a dead end — it's a signal.** A `403` on `/admin` means it *exists*. Try bypasses: `/admin/`, `/admin/.`, `/admin%2f`, `/Admin`, `/admin..;/`, header tricks (`X-Original-URL: /admin`, `X-Forwarded-For: 127.0.0.1`, `X-Rewrite-URL`), HTTP method change (`POST`/`PUT`). 403-bypass to an admin panel is a fast, high-value bug. (See `nuclei` 403-bypass templates.)

> **Don't waste time:** brute-forcing 200k-entry generic lists against a host that 404s everything, or on static CDN sites. Match the wordlist to the detected stack; recurse only into dirs that exist.

---

# 14. Parameter Discovery

Hidden parameters unlock hidden behavior — `debug`, `admin`, `test`, `id`, `redirect`, `file`, internal feature flags. They're invisible until you guess them.

```bash
# Mine params per endpoint:
arjun -u "https://api.target.com/v1/user" -m GET,POST -oT params.txt
# Harvest param NAMES from history + JS, then reuse everywhere:
cat urls_all.txt | unfurl keys | sort -u > param_names.txt       # all params ever seen
cat js_files.txt | xargs -I{} curl -s {} | grep -oE '[?&][a-zA-Z0-9_]+=' | sort -u >> param_names.txt
# (also: Burp param-miner extension — best for header/cookie/JSON param mining)
```
**High-value parameter names to always test:**
```
redirect, redirect_uri, next, url, return, returnUrl, dest, continue   → open redirect / SSRF (§23)
id, user_id, uid, account, order, doc, file, key                       → IDOR
debug, test, admin, is_admin, role, preview, internal, beta            → priv/feature toggle
callback, jsonp                                                         → JSONP / XSS
template, lang, theme, page, include, path                             → LFI / SSTI
q, search, query, s                                                     → XSS / injection
```

> **If this → then that:** arjun finds a `debug` param accepted with a 200 → set `debug=true`/`1` → look for verbose errors, stack traces, expanded responses, or auth bypass. Hidden `admin=true`/`role=admin` params that the server *trusts* = instant priv-esc.

---

# 15. JavaScript Analysis

*In plain words:* every modern website sends your browser a pile of **JavaScript (JS)** files — the code that makes the page work. That code is downloaded to *you*, so **you can read it**, and it's astonishingly revealing: it lists the **API routes** the app calls (`/api/v2/users/{id}/delete`), the parameter names, hidden **feature flags**, sometimes even secret keys the developer left in by mistake. Reading the JS is like *getting a copy of the building's blueprints* — you see doors that aren't linked anywhere on the visible site. Most hunters skip this because it's tedious; that's exactly why it pays. (There's a whole separate kit, JSFiles, dedicated to it.)

**The single most under-exploited recon source.** Modern apps ship their entire client logic — API routes, parameter names, feature flags, sometimes secrets — in JS bundles. Read them.

```bash
# 1) Collect all JS:
cat live.txt | katana -jc -d 2 -silent | grep -Ei '\.js(\?|$)' | sort -u > js_files.txt
subjs -i live.txt | anew js_files.txt
# 2) Pull endpoints + secrets out of every bundle:
cat js_files.txt | while read u; do curl -s "$u"; done > js_dump.txt
# endpoints:
grep -oE '"/[a-zA-Z0-9_/.?=&-]+"' js_dump.txt | tr -d '"' | sort -u > js_endpoints.txt
grep -oE 'https?://[a-zA-Z0-9./?=_-]+' js_dump.txt | sort -u >> js_endpoints.txt
# secrets (route to manual verify; many are false positives):
trufflehog filesystem js_dump.txt --only-verified
gitleaks detect --no-git -s js_dump.txt
# jsluice = best structured extractor (URLs, secrets, gadgets):
cat js_files.txt | jsluice urls -R js_dump.txt ; cat js_files.txt | jsluice secrets
```

## 15.1 SOURCE MAPS — the biggest secret most hunters skip
*In plain words:* before shipping, developers **minify** their JavaScript — crush it into unreadable one-line gibberish (short variable names, no spaces) to make it smaller. A **source map** (`.js.map` file) is a companion file that lets browser dev-tools *reverse* that crushing back into the **original, readable source code** — with the real variable names, the developers' comments, and `// TODO: remove this debug route` notes. Developers use maps to debug, but if a `.js.map` is left reachable on the web, *you* can use it to reconstruct their **entire original codebase**. That's the jackpot: you're no longer guessing at the app — *you're reading their actual code*, including the full list of API endpoints and how their permission checks work.

If a `.js.map` is exposed, you can **reconstruct the original, un-minified source** (variable names, comments, dev endpoints, sometimes secrets):
```bash
# Probe for maps next to every bundle:
cat js_files.txt | sed 's/$/.map/' | httpx -sc -mc 200 -o jsmaps.txt
# Reconstruct source from a map:
npx source-map-explorer app.js app.js.map     # or: unwebpack-sourcemap, shuffle: 'sourcemapper'
sourcemapper -url https://target.com/static/app.js.map -output ./src_recovered
```
> **What others miss:** dev comments, internal API base URLs, feature flags, and `// TODO: remove before prod` debug routes live in source maps. Reconstructed React/Angular/Vue source reveals the *entire* API contract and authz model — you're now reading their code.

## 15.2 What to extract and route
```
API base URLs / route templates   → feed §16 (API testing) and §14 (param mining).
Hardcoded keys/tokens             → verify (most Google/Firebase keys are client-side & fine; see XSS/JWT guides).
GraphQL endpoints                 → §16 (introspection).
Internal hostnames                → §7 (more assets) / SSRF target list.
Auth logic / role checks          → client-side authz = bypassable; note for the app test.
Feature flags / debug routes      → hidden functionality to test.
```

> **If this → then that:** JS references `apiInternal: "https://internal-api.target.com"` that's not in your DNS list → add to assets (§7) and to your SSRF wordlist. JS shows `if(user.role==='admin') showAdminPanel()` → the admin gate is **client-side** → call the admin API directly; the server may not re-check.

---

# 16. API & GraphQL Discovery

*In plain words:* an **API** (Application Programming Interface) is the *machine-facing* side of an app — instead of pretty web pages, it's plain addresses that return raw data (`/api/users/123` → that user's record as JSON). The mobile app and the website both talk to it behind the scenes. APIs are the richest hunting ground because they handle the real data and their access checks are often sloppy (this is where **IDOR/BOLA** — reading *other people's* records by changing an ID — lives). A **spec** (like **Swagger/OpenAPI**) is a machine-readable *menu of every API endpoint*; if you find one, you instantly have the whole map. **GraphQL** is a newer API style where the client asks for exactly the fields it wants in one flexible query — and **introspection** is a built-in feature that, if left on, hands you the *complete list of every query and data type the API supports*. Find the API + its spec/schema = you've got the full backend map most hunters never see.

APIs are where authz/IDOR/logic bugs (the highest-paying, least-duped classes) live. Find every API and its spec.

## 16.1 REST
```
□ Specs:  /swagger.json /openapi.json /v2/api-docs /api-docs /swagger-ui.html /redoc
   → import into Burp/Postman → you have EVERY endpoint + params + auth model.
□ Versions: if app uses /api/v3/, test /api/v1/ and /api/v2/ — old versions often skip new authz (BOLA/BFLA).
□ Undocumented: diff JS-found routes (§15) against the swagger; the gaps are the juicy ones.
□ Verbs: try OPTIONS to enumerate allowed methods; PUT/PATCH/DELETE often less-guarded than GET/POST.
```

## 16.2 GraphQL (a category of its own)
```bash
# Find it:
/graphql /graphiql /v1/graphql /api/graphql /graphql/console /playground
# Introspection (the whole schema if enabled — map every query/mutation):
curl -s https://target.com/graphql -H 'Content-Type: application/json' \
  -d '{"query":"{__schema{types{name fields{name}}}}"}' | jq .
# Tools: graphw00f (fingerprint), clairvoyance (recover schema even if introspection is OFF),
#        InQL (Burp), graphql-cop (audit).
```
> **GraphQL is an expert favorite** because: introspection hands you the full API; authz is often enforced per-resolver (inconsistently → BOLA); batching enables rate-limit/brute bypass; aliases enable mass data extraction; and most hunters don't know it well → **low competition, high impact**.

> **If this → then that:** introspection enabled → dump schema → look for `mutation` ops that change other users' data (`updateUser(id)`, `deleteOrder(id)`) → test IDOR by swapping IDs. Introspection disabled → run **clairvoyance** to recover the schema anyway, then proceed.

---

# PART V — HIGH-VALUE RECON (where the money is)

> These are the fast, clean, high-severity, low-dupe wins. Run them early — many are one command and pay immediately.

# 17. Subdomain Takeover

*In plain words:* companies point a subdomain at an outside service using a **CNAME** — a DNS record that means *"for `shop.target.com`, actually go to this Shopify/S3/Heroku address."* Trouble starts when the company **cancels the outside service but forgets to remove the CNAME**: now `shop.target.com` points at an empty Shopify slot that *nobody owns*. A **subdomain takeover** = *you* go sign up for that same Shopify/S3/Heroku name, and because the target's DNS still points there, **you now control `shop.target.com`** — a real subdomain of the target, serving whatever you put on it. It's clean, high-severity, and rarely duplicated (few hunters check the *dead* subdomains). It escalates to full account takeover when the parent domain's login cookies are shared with all its subdomains (see the gloss in §21).

A subdomain CNAMEs to a third-party service (S3, GitHub Pages, Heroku, Azure, Shopify, Fastly…) that's **unclaimed** → you register it → you control the subdomain (serve content, steal cookies scoped to the parent, phish, sometimes full ATO via OAuth/cookie scope).

```bash
# Detect across your whole list:
cat subs_all.txt | httpx -cname -silent | grep -Ei 's3|github|herokuapp|azure|fastly|netlify|shopify|cloudfront|surge|bitbucket|zendesk|unbounce|wpengine'
nuclei -l live.txt -t http/takeovers/ -o takeovers.txt           # templated detection
subzy run --targets subs_all.txt                                  # dedicated checker
# Confirm: the CNAME target returns a "no such bucket/app/page" fingerprint → claimable.
```
**Why it pays well and fast:** clean to prove (claim it, serve a PoC file), usually **High** (especially if the parent domain's cookies are scoped to `*.target.com` → session theft/ATO), and **rarely duplicated** because most hunters don't run a takeover pass on the *full* list including dead/forgotten subs.

> **If this → then that:** a dangling subdomain whose parent sets cookies on `.target.com` → takeover → you read those cookies → **account takeover**, not just defacement. Always check cookie scope to escalate severity. (Claim only to prove control; don't serve anything malicious — §29.)

---

# 18. Secrets Hunting (GitHub/GitLab Dorking & Leaks)

*In plain words:* a **secret** is any credential that should be private — an API key, a database password, a cloud access key. Developers constantly leak these by accident: they push code to a **public GitHub repo** with a password still in it, paste config into a public gist, or leave keys in the JS (§15). **Dorking** = *"using precise search queries to fish for those leaks"* — e.g. searching GitHub for `"target.com" password` or `org:Target filename:.env`. A `.env` file holds an app's secrets; `.tfstate` (Terraform state) files often hold *entire* infrastructure passwords. The killer detail: even a secret *deleted* in the newest commit still sits in the **commit history** (`git log`), so you scan the history, not just the current files. A live, working secret is usually an instant **Critical** — it's a key that opens a real door.

Developers leak secrets in public repos, gists, CI logs, and JS. A live secret → direct impact (API access, cloud creds, ATO) and is usually **Critical**.

```
□ GitHub code search (the org + its devs' personal repos):
   "target.com" password    "target.com" api_key    org:Target filename:.env
   "internal.target.com"     "target" AWS_SECRET     "Target" smtp password
□ Tools:  trufflehog github --org=Target --only-verified
          gitleaks · github-dorks · gitrob · shhgit · git-hound
□ Where secrets hide:  .env, config.js, application.yml, *.tfstate (Terraform!), CI files (.github/workflows),
   Dockerfiles, k8s manifests, commit HISTORY (deleted-but-in-history), gists, GitLab/Bitbucket snippets.
□ Exposed .git on the web (§20) → dump → scan history for secrets too.
```
> **What others miss:** **commit history & Terraform state.** A secret deleted in the latest commit is still in `git log`. `*.tfstate` files often contain DB passwords, cloud keys, and full infra layout — and people commit them. Scan history, not just HEAD.

> **Validity:** *verify* the secret before reporting (`--only-verified` / make one authenticated call). A revoked/example/client-side key is a false positive and burns credibility — same rule as the JWT/XSS guides: a secret is only a finding if it **authenticates a privileged action**. (Use *your own* access to confirm; don't pivot into others' data.)

---

# 19. Cloud Asset Discovery (S3/GCS/Azure)

*In plain words:* companies store files (backups, user uploads, source code) in **cloud storage buckets** — Amazon **S3**, Google **GCS**, or **Azure** blobs. Each bucket has a name and a permission setting, and admins *constantly* leave them set to **public** by mistake. If you can guess or find a bucket's name (they're often predictable — `target-backups`, `target-uploads`, `target-prod`), you test its permissions: **public read** lets you download everything inside (PII, database dumps, source → Critical); **public write** lets you upload a file the app then serves (→ stored XSS / supply-chain). Bucket names hide in JS (§15), page source, CNAMEs (§17), and GitHub (§18). Easy to find, easy to prove, often Critical — just prove it with a *benign* file you delete afterward and never touch other people's data.

Misconfigured cloud storage = public read/write of sensitive data, often **Critical** and easy to prove.

```bash
# Guess bucket names from the org/app naming:
# target-backups, target-prod, target-uploads, target-dev, target-assets, target-logs, targetcom...
# Tools:
cloud_enum -k target -k target-prod -k targetinc          # S3+GCS+Azure
s3scanner scan --bucket-list buckets.txt
# Found buckets — test perms:
aws s3 ls s3://target-uploads --no-sign-request            # public LIST?
aws s3 cp test.txt s3://target-uploads --no-sign-request   # public WRITE? (don't overwrite real data!)
```
**Find bucket names in:** JS bundles (§15), page source (`<img src=//bucket.s3...>`), CNAMEs (§17), HTTP responses, GitHub (§18), and CT logs.

> **If this → then that:** public **read** on a `*-backups`/`*-uploads` bucket → enumerate for PII/DB dumps/source (High–Critical). Public **write** → upload to a path the app serves → stored XSS / content injection / supply-chain. Prove with a *benign* file you remove afterward; never touch others' objects.

---

# 20. Sensitive Exposure (.git, .env, backups, debug, configs)

Files that should never be web-reachable but constantly are. Probe these directly on **every interesting host** — it's seconds of work for potential Critical.

```bash
# Exposed git repo → full source + secrets in history:
httpx -l live.txt -path /.git/config -mc 200 -o exposed_git.txt
git-dumper https://host/.git/ ./dumped   # reconstruct the whole repo
# Env / config / backup sweep (nuclei has curated templates):
nuclei -l live.txt -t http/exposures/ -t http/misconfiguration/ -o exposures.txt
# Manual high-value probes:
for p in /.env /.git/config /config.json /appsettings.json /wp-config.php.bak /.DS_Store \
         /actuator/env /actuator/heapdump /server-status /phpinfo.php /debug /.aws/credentials; do
  httpx -l live.txt -path "$p" -mc 200,500 -silent; done
```
**Top exposures by payoff:**
```
.git exposed            → full source code + secrets in history  → Critical
.env / config           → DB creds, API keys, cloud creds        → Critical
Spring /actuator/*      → /env (creds), /heapdump (memory→tokens) → Critical
DB backups (.sql/.bak)  → entire database                        → Critical
.DS_Store               → directory listing → find more hidden files
debug/trace/phpinfo     → internal paths, config, sometimes creds → Medium–High
```

> **Don't over-report:** `robots.txt`/`sitemap.xml` are *recon inputs* (free paths), not vulnerabilities. `phpinfo` alone is Low. Lead with the **secret/source/data** you actually obtained, not the file's existence.

---

# 21. CORS & Subdomain-Trust Recon

*In plain words:* browsers normally forbid one website from reading another website's private data — that wall is called the **same-origin policy**. **CORS** (Cross-Origin Resource Sharing) is the app's way of poking controlled holes in that wall to say *"these specific other sites are allowed to read my data."* If the app configures CORS carelessly — e.g. it trusts *any* site, or trusts *all* of `*.target.com` — then a site *you* control (or a weak subdomain you took over in §17) can read logged-in users' private data from the main app. Related trap: **cookie scope** — if login cookies are set on `.target.com` (note the leading dot), then *every* subdomain can read them, so one weak subdomain leaks the main app's sessions. This section **draws the trust graph**: which origins the strong app trusts, so you know which *weak* node can break it. (There's a dedicated CORS kit for the exploitation.)

Map which origins the app *trusts*. Misconfigured CORS or over-broad subdomain cookie trust turns one weak subdomain into a breach of the main app.

```bash
# Test reflected/permissive CORS across endpoints:
cat endpoints.txt | while read u; do
  curl -s -I -H "Origin: https://evil.com" "$u" | grep -i "access-control-allow-origin: https://evil.com" \
    && echo "REFLECTED CORS: $u"; done
```
```
□ ACAO reflects arbitrary Origin + ACAC:true   → read authenticated responses cross-origin = data theft.
□ ACAO trusts *.target.com                       → a subdomain XSS/takeover (§17) → steal main-app data.
□ Cookies scoped to .target.com                  → ANY subdomain can read them → takeover/XSS anywhere = ATO.
□ postMessage trust / SSO (subdomain shares auth) → trust map = how a weak sub compromises the strong app.
```
> **If this → then that:** main app trusts `*.target.com` for CORS/cookies → find the *weakest* subdomain (forgotten staging with XSS, or a takeover) → use that trust to exfiltrate main-app data/session. Recon's job is to **draw the trust graph** so you know which weak node breaks the strong one.

---

# 22. Mobile, Third-Party & Supply-Chain Recon

```
□ Mobile apps (if in scope) → decompile → leaked API endpoints, keys, hidden hosts (see Android guide).
   APKs reveal staging/internal APIs and secrets the web never exposes.
□ Third-party SaaS the org uses → exposed Jira/Confluence/Trello boards, public Slack, status pages,
   misconfigured Google Docs, S3 of a vendor → org data via the vendor.
□ Supply chain → npm/pip packages the org publishes (typosquat/dependency-confusion surface),
   exposed CI/CD (Jenkins/GitLab runners), webhook endpoints.
□ Employee OSINT → LinkedIn (tech stack, internal tool names), dev blogs, conference talks,
   StackOverflow questions naming internal systems → seeds for subdomain/param/tech guessing.
```
> **What others miss:** **org-published packages & dependency confusion.** If the org uses internal package names, publishing a malicious public package with the same name can achieve RCE in their build — a recon-driven supply-chain finding. (Only test where explicitly authorized.)

## 22.1 Concrete mobile-app recon (APK / IPA → endpoints, keys, buckets, source)
Mobile apps hold endpoints, S3 buckets, and API keys the web app **never exposes** — a low-competition surface. Pull them:
```bash
# get the APK (apkpure/apkmirror, or pull from a device) then decompile:
apktool d app.apk -o app_src                 # resources + smali + AndroidManifest (deep links, exported components)
jadx -d app_java app.apk                      # decompiled Java (readable)
# mine the decompiled output exactly like JS recon (JS-files kit):
grep -RhoE "https?://[a-zA-Z0-9./?=_%:-]+" app_java app_src/res | sort -u            # endpoints / hosts (incl. staging/internal)
grep -RnE "AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{35}|firebaseio\.com|s3\.amazonaws|api[_-]?key|secret|bearer" app_java
grep -RnE "BEGIN (RSA|EC) PRIVATE KEY|password|token" app_java
# Firebase config in the app → test the RTDB unauth (very common): curl https://<proj>.firebaseio.com/.json
# iOS: unzip the .ipa → Payload/*.app/ → strings the binary + read Info.plist / embedded plists for URLs/keys.
# dynamic (if needed): objection / Frida to dump runtime endpoints, bypass cert-pinning to proxy the API through Burp.
```
> **If this → then that:** the program lists a **mobile app in scope** → decompile it and mine it like a JS bundle — the
> endpoints/keys/buckets you find feed every other kit (JS-files for secret validation, SSRF/IDOR for the hidden APIs,
> the JWT kit for a leaked signing secret). Mobile-only staging/internal hosts are prime, low-dupe targets.

## 22.2 Internet-wide search & dorking (Shodan · Censys · FOFA · Google · GitHub)
Search engines surface assets DNS enum **misses** — hosts with no DNS record, exposed panels, and origin IPs behind a CDN.
```
SHODAN:   ssl.cert.subject.CN:"target.com"   ssl:"Target Inc"   org:"Target Inc"   http.favicon.hash:<hash>
          http.title:"Target Admin"   http.html:"target.com"   port:9200 org:"Target Inc"  (exposed Elasticsearch)
CENSYS:   services.tls.certificates.leaf_data.subject.common_name: target.com   services.http.response.html_title:"Target"
FOFA:     domain="target.com" || cert="target.com" || title="Target"            (ZoomEye similar)
GOOGLE:   site:target.com inurl:admin|login|dashboard|api|swagger|graphql|debug
          site:target.com ext:env|sql|bak|log|json|yml|config|txt|old
          intitle:"index of" site:target.com   |   "target.com" "AWS_SECRET" -github
          inurl:target.com site:pastebin.com|trello.com|s3.amazonaws.com|github.com|gitlab.com|postman.com
GITHUB:   org:Target "BEGIN RSA PRIVATE KEY"   "target.com" jdbc:   filename:.env DB_PASSWORD   "target.com" authorization: bearer
OTHER LEAK SURFACES:  Postman public workspaces, Pastebin, GitLab/Bitbucket snippets, Docker Hub images, public S3/GCS/Azure.
```
> **If this → then that:** subdomain enum looks "done" → run the **favicon-hash + cert-CN Shodan/Censys** pivots and the
> Google/GitHub dorks — they routinely surface a **CDN origin IP** (→ WAF bypass), an **exposed panel/Elasticsearch**, or
> a **leaked secret** that subdomain enum never shows. (Get the favicon hash from §10.)

---

# PART VI — RECON → VULN MAPPING (if this then that)

# 23. The Attack-Surface-to-Bug Decision Matrix

Recon output → the bug class to test. This table *is* the point of recon: it converts findings into a testing plan.

| You found (recon) | Test for (bug class) | Why / impact | Detail |
|---|---|---|---|
| Login / SSO / auth panel | auth bypass, JWT/OAuth flaws, default creds, user enum, 2FA bypass | ATO | JWT guide |
| `/api/`, swagger, GraphQL | **IDOR/BOLA, BFLA, mass assignment, logic** | cross-user/admin data, money | §16 |
| Params: `url/redirect/next/dest` | **open redirect → SSRF** | SSRF→metadata/RCE; OAuth token theft | §14 |
| Params: `id/user/order/doc/file` | **IDOR**, LFI | other users' data | §14 |
| Params: `q/search/name/comment` | **XSS** (reflected/stored) | session/ATO | XSS guide |
| User-content render (profile, comments) | **stored XSS**, file-upload XSS | 0-click admin ATO | XSS guide |
| File upload | RCE (web shell), SVG/HTML XSS, path traversal, XXE | RCE/stored XSS | — |
| Dangling CNAME (S3/GitHub/…) | **subdomain takeover** | session theft/ATO | §17 |
| Exposed `.git`/`.env`/`actuator` | source/secret disclosure → ATO/RCE | Critical | §20 |
| Public S3/GCS bucket | data exposure / write→XSS | Critical | §19 |
| GraphQL introspection on | BOLA via mutations, batching brute, info disclosure | data/ATO | §16 |
| Old API version live (`v1`) | authz regression (BOLA/BFLA) | cross-user | §16 |
| Permissive CORS / `*.target` cookie trust | cross-origin data theft | ATO via weak sub | §21 |
| Spring Boot / specific stack + version | known CVEs (actuator, deserialization) | RCE | §10/§20 |
| `redirect_uri`/OAuth on a sub | OAuth misconfig, token leak | ATO | JWT guide |
| Staging/dev/UAT host | everything above, **less hardened** | same impact, fewer dupes | §7 |
| Internal hostname (in JS/CT) | SSRF target, split-horizon reach | server-side | §7/§15 |
| Admin/dashboard behind 403 | **403/401 bypass** → admin | priv-esc | §13 |

# 24. Prioritization — What to Test First for Impact

Order your testing queue by **impact-per-hour**, not by what's easiest:

```
TIER 1 (do first — fast, high-severity, low-dup):
  • Subdomain takeover (§17)        — minutes, often High, rarely duped
  • Exposed .git/.env/actuator (§20)— minutes, Critical
  • Public cloud buckets (§19)      — minutes, Critical
  • Verified leaked secrets (§18)   — Critical, direct impact
  • 403-bypass to admin (§13)       — fast priv-esc

TIER 2 (the meat — where most bounties live):
  • API/GraphQL IDOR/BOLA/BFLA (§16)— High–Critical, low competition
  • Auth/JWT/OAuth on auth panels   — ATO
  • SSRF via redirect/url params    — High–Critical
  • Stored XSS in user content      — 0-click ATO
  • Business logic on payment/flows — High–Critical

TIER 3 (only after Tier 1–2, or while waiting):
  • Reflected XSS / open redirect (chain them or skip if no impact)
  • CORS (only if it yields data theft)
  • Lower-severity misconfig

Always weight toward: dev/staging/forgotten hosts (§7), newly-found assets (§27), broad APIs.
```

> **The expert move:** run Tier-1 recon checks across the *entire* surface (automated, §26), then spend manual hours on Tier-2 against the *interesting* hosts only. This front-loads the easy criticals and focuses your scarce manual time where impact compounds.

# 25. What NOT to Waste Time On

Be ruthless. Time spent here is time stolen from impact.

```
✗ Reporting recon artifacts as bugs:
   robots.txt/sitemap.xml contents · banner/version disclosure · "directory listing" of public assets ·
   open redirect with no chain · self-XSS · missing security headers · TLS config nitpicks ·
   a Firebase/Google client API key that's MEANT to be public · email SPF/DMARC "issues" on no-impact domains.
   (These are Informational; programs auto-close them and your reputation drops.)
✗ Brute-forcing huge wordlists against cold/static/CDN'd targets (no backend = no bug).
✗ Deep-crawling the marketing site while the API and admin panel sit untouched.
✗ Port-scanning / heavy automation where the policy forbids it (ban risk) or on out-of-scope assets (illegal).
✗ Chasing "subdomain takeover" on services that aren't actually takeoverable (verify the fingerprint first).
✗ Manually testing 10,000 dead subdomains — automate Tier-1 across them, manually test only the live/interesting.
✗ Re-running one-shot recon weekly by hand — automate it and MONITOR instead (§27).
✗ Hoarding data you'll never test. If a finding doesn't route to a bug class (§23), it's not worth your manual time.
```

> **The discipline:** every hour, ask *"is this moving me toward a demonstrable, in-scope, unduplicated bug with impact?"* If no, stop and re-route to a Tier-1/Tier-2 lead.

---

# PART VII — AUTOMATION, MONITORING & RED TEAM

# 26. Building a Recon Pipeline

Chain the phases so one command takes a domain to a routed, prioritized surface. `scripts/x8bit_recon.sh` implements this; the skeleton:

```bash
# domain → assets → live → endpoints → routed candidates → high-value checks
subfinder -d $D -all -silent | anew $D/subs.txt
puredns bruteforce wordlist.txt $D -r resolvers.txt | anew $D/subs.txt
cat $D/subs.txt | puredns resolve -r resolvers.txt | anew $D/resolved.txt
cat $D/resolved.txt | httpx -sc -title -td -cname -json -o $D/httpx.json
cat $D/resolved.txt | httpx -silent | katana -jc -d 2 -silent | anew $D/urls.txt
gau $D | anew $D/urls.txt
cat $D/urls.txt | gf xss | anew $D/cand_xss.txt    # ...ssrf, redirect, idor, sqli
subjs -i $D/live.txt | anew $D/js.txt              # then jsluice/trufflehog
nuclei -l $D/live.txt -t takeovers/ -t exposures/ -o $D/nuclei.txt
# Output: a per-target folder routed to bug classes (§23), Tier-1 criticals auto-flagged.
```
**Pipeline principles:**
- **Idempotent + `anew`** so re-runs only surface *new* lines (that's your monitoring signal, §27).
- **Stay polite** (`-rate`, `-delay`) to honor program limits (§29).
- **Separate "find" (broad, automated) from "verify" (narrow, manual).** The pipeline finds; you verify and exploit.
- **One folder per target**, committed to a private repo, so you have history and diffs.

# 27. Continuous Monitoring — First-Mover Bugs

**This is the single biggest edge an expert has over the crowd.** New assets have the least competition and the most bugs. Watch for them and you'll often be the *first* (and only un-duped) reporter.

```
□ CT-log monitor → new TLS cert for *.target.com = new subdomain, minutes after issue.
   (certstream, or `crt.sh` polled; pipe new hosts → httpx → nuclei → alert.)
□ Subdomain diff → re-run subfinder/puredns daily; `anew` emits ONLY new subs → probe → alert.
□ JS diff → re-fetch JS bundles; diff for NEW endpoints/params/flags (apps ship new routes constantly).
□ Content diff → watch key endpoints for new params/features (nuclei -id, or custom).
□ GitHub monitor → continuous trufflehog/github-dorks on the org for freshly-leaked secrets.
□ Nuclei on a schedule → run takeover/exposure templates over the live set daily.
□ Alert → push new findings to Slack/Discord/Telegram so you act within the hour.
```
```bash
# Minimal subdomain monitor (cron daily):
subfinder -d target.com -all -silent | anew target/subs.txt | \
  httpx -silent | nuclei -t takeovers/ -t exposures/ | notify    # notify = pd/notify → Slack/Discord
```
> **If this → then that:** a brand-new subdomain appears → it's likely a fresh deploy with default config / pre-hardening → hit it with Tier-1 checks *immediately*. The window before other hunters' weekly scans find it is your unduplicated-bug window.

# 28. Red-Team Recon Angles for Bug Bounty

Borrow red-team tradecraft to find what pure-web recon misses:

```
□ Identity-first recon → enumerate employees (LinkedIn/hunter.io) → email format → these become
   usernames for auth testing, SSO targets, and password-spray candidates (where authorized).
□ Tech-stack OSINT → job postings & dev blogs name the exact stack ("we use Spring + Kafka + Snowflake")
   → target the known CVEs/misconfigs for that stack (§10/§23).
□ Internal tooling names → conference talks/GitHub reveal internal app names → guess their subdomains/vhosts.
□ Infrastructure mapping → ASN/BGP/cloud-tenant correlation → find the org's whole footprint, incl. naked IPs.
□ Phishing-surface (recon only) → login portals, SSO, VPN, OWA, Citrix → these are the high-value auth targets;
   map them (don't phish unless the program explicitly authorizes social engineering — usually it does NOT).
□ Trust-relationship mapping → SSO/IdP, shared cookies, CORS, partner APIs → how compromise propagates (§21).
□ "Assume breach" framing → if I had ONE weak subdomain, what does it reach? (CORS/cookie/SSO trust → main app).
```
> Red-team recon is about **the org as a system**, not one domain. The bounty payoff is finding the *trust edge* (a weak acquisition, a forgotten SSO-trusted staging host) that pivots into the crown-jewel app — exactly the chains programs pay most for.

# 29. OPSEC, Rate-Limiting & Staying In-Scope

Recon is loud. Don't get banned, blocked, or in legal trouble.

```
□ Respect program rules on automation/rate — throttle (httpx -rl, naabu -rate, ffuf -rate/-p delay).
□ Identify yourself if the program asks (custom User-Agent with your handle / "bugbounty-<you>").
□ Never test OUT-OF-SCOPE assets — recon will surface them; FIND but don't TOUCH.
□ Don't DoS — no aggressive brute on fragile endpoints; no resource-exhaustion "tests".
□ Cloud/takeover: claim only to PROVE control; serve a benign PoC; never host malicious content or touch user data.
□ Secrets/buckets: VERIFY with a single benign call against YOUR access; never pivot into real users' data.
□ Use a VPS for heavy enum (don't burn your home IP); but keep it attributable to you for safe-harbor.
□ Log what you did (timestamps, hosts, actions) — for your report and your protection.
```

---

# Appendix A — Recon Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                      WEB RECON WORKFLOW                             │
├────────────────────────────────────────────────────────────────────┤
│ 0. SCOPE + SELECT                                                  │
│    └→ read policy · wildcard? acquisitions? · in/out scope files   │
│ 1. GO WIDE (assets)                                                │
│    ├→ org/ASN/acquisitions/reverse-whois        (§4)  ← others miss│
│    ├→ passive subs: subfinder+amass+crt.sh+chaos (§5)              │
│    ├→ active subs: puredns brute + PERMUTATIONS  (§6)  ← others miss│
│    └→ extras: CT-monitor·vhost·TLS-SAN·JS-hosts  (§7)              │
│ 2. RESOLVE + PROBE                                                 │
│    ├→ httpx (status/title/tech/cname)            (§8)              │
│    ├→ naabu ports + ORIGIN-IP hunt (WAF bypass)  (§9)              │
│    └→ favicon-hash pivot · vhost fuzz            (§10/§11)         │
│ 3. GO DEEP (interesting hosts only)                                │
│    ├→ gau/wayback/katana → gf-route to bug class (§12)             │
│    ├→ ffuf dirs/files · /.git /.env /actuator    (§13/§20)         │
│    ├→ arjun params + history param names         (§14)             │
│    ├→ JS endpoints/secrets + SOURCE MAPS         (§15) ← others miss│
│    └→ swagger/openapi + GraphQL introspection    (§16)            │
│ 4. HIGH-VALUE  ⭐ (fast criticals)                                  │
│    ├→ subdomain takeover (nuclei/subzy)          (§17)            │
│    ├→ GitHub/secret leaks (trufflehog, history)  (§18)            │
│    ├→ cloud buckets (cloud_enum/s3scanner)       (§19)            │
│    ├→ exposed .git/.env/backups (nuclei)         (§20)            │
│    └→ CORS/cookie trust map                      (§21)            │
│ 5. ROUTE → IMPACT  ⭐                                               │
│    ├→ surface→bug matrix                          (§23)            │
│    ├→ prioritize Tier-1 criticals, then Tier-2 API/authz (§24)    │
│    └→ SKIP the time-wasters                       (§25)           │
│ 6. AUTOMATE + MONITOR                                              │
│    ├→ pipeline (scripts/x8bit_recon.sh)                 (§26)            │
│    ├→ CT/subdomain/JS diff → notify (first-mover) (§27) ⭐         │
│    └→ red-team trust-edge angles                  (§28)           │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — Recon Decision Tree

```
New target →
│
├─ Wildcard scope? ── NO → enumerate only listed hosts; go straight to PROBE+DEEP on them.
│                  └─ YES → ORG-EXPAND (ASN/acquisitions §4) → full subdomain enum (§5–§7).
│
├─ Acquisitions in scope? ── YES → enumerate each acquired root domain too (least-duped surface).
│
├─ For each LIVE host (httpx §8): is it interesting? (auth/api/admin/dev/staging/dashboard/odd-port)
│     ├─ NO  → keep for Tier-1 automation (takeover/exposure) + monitoring; don't manually deep-dive.
│     └─ YES → DEEP: wayback+JS+source-maps (§12/§15) → swagger/GraphQL (§16) → params (§14) → route (§23).
│
├─ CNAME to a 3rd party that 404s? ───── TAKEOVER (§17). Cookie scoped to parent? → escalate to ATO.
├─ /.git /.env /actuator returns 200? ── DUMP → source/secrets (§20). Critical.
├─ Behind Cloudflare + WAF blocks you? ─ ORIGIN-IP hunt (§9) → hit origin directly.
├─ 403 on /admin? ─────────────────────── 403-BYPASS (§13) → priv-esc.
├─ GraphQL present? ───────────────────── introspect (or clairvoyance) → BOLA via mutations (§16).
├─ Old API version live? ──────────────── test v1/v2 for authz regressions (§16).
├─ Internal hostname in JS/CT? ────────── add to assets (§7) + SSRF target list.
│
└─ Did this asset route to a bug class (§23)?  YES → queue by impact (§24).  NO → it's coverage, not a task (§25).

ALWAYS, in parallel: set MONITORING (§27) so new assets hit Tier-1 checks within the hour = unduplicated bugs.
```

---

# Appendix C — Important Links

```
── TOOLS ──────────────────────────────────────────────────────────────────────
ProjectDiscovery (subfinder/dnsx/httpx/naabu/katana/nuclei/asnmap/tlsx/notify)  https://github.com/projectdiscovery
OWASP Amass                                                        https://github.com/owasp-amass/amass
tomnomnom (gau/waybackurls/gf/anew/unfurl/qsreplace — the glue)    https://github.com/tomnomnom
SecLists (wordlists)                                               https://github.com/danielmiessler/SecLists
Assetnote wordlists / commonspeak2                                 https://wordlists.assetnote.io
crt.sh (certificate transparency)                                  https://crt.sh
Chaos (PD recon dataset, free for bounty)                          https://chaos.projectdiscovery.io
gf + gf-patterns (route URLs to bug classes)                       https://github.com/tomnomnom/gf
trufflehog / gitleaks (secret scanning)                            https://github.com/trufflesecurity/trufflehog
jsluice / subjs / getJS (JS analysis)                              https://github.com/BishopFox/jsluice
graphw00f / clairvoyance / InQL (GraphQL)                          https://github.com/dolevf/graphw00f
subzy / subjack / nuclei-takeovers (subdomain takeover)            https://github.com/PentestPad/subzy
cloud_enum / s3scanner (cloud buckets)                             https://github.com/initstring/cloud_enum
notify (alerting for monitoring)                                   https://github.com/projectdiscovery/notify

── METHODOLOGY & RESEARCH (recon-matched) ─────────────────────────────────────
Jason Haddix — "The Bug Hunter's Methodology" (TBHM) — the recon canon  https://github.com/jhaddix/tbhm
NahamSec — recon education / bug-bounty recon content              https://www.youtube.com/@NahamSec
reconFTW (all-in-one recon reference pipeline to compare against)  https://github.com/six2dez/reconftw
Assetnote research (recon depth, wordlist theory, CVE deep-dives)  https://www.assetnote.io/resources
ProjectDiscovery blog (subfinder/nuclei/httpx methodology)        https://blog.projectdiscovery.io
Intigriti / HackerOne recon guides + disclosed reports (learn what pays)  https://www.intigriti.com/researchers/blog
Orange Tsai (proxy/parser/SSRF attack surface — recon-adjacent)   https://blog.orange.tw

── ALWAYS-ON (cross-class references) ─────────────────────────────────────────
PortSwigger Web Security Academy + Research (exploit after recon)  https://portswigger.net/web-security
OWASP WSTG — Information Gathering (WSTG-INFO)                      https://owasp.org/www-project-web-security-testing-guide
HackTricks — Pentesting Methodology / Recon                        https://book.hacktricks.xyz
The Hacker Recipes — recon / infrastructure                        https://www.thehacker.recipes
PayloadsAllTheThings                                               https://github.com/swisskyrepo/PayloadsAllTheThings
PentesterLab (hands-on recon modules)                              https://pentesterlab.com
```

> These are the **references-block standard** for the Recon kit: the tool set you run, the recon-matched
> methodology/research (TBHM · NahamSec · reconFTW · Assetnote · ProjectDiscovery · Orange Tsai), and the
> always-on cross-class anchors. The `RECON_ARSENAL.md` and `Recon_Zero_to_Expert.md` carry the same set.

---

> **Final reminder — the one rule that pays:** *Recon's job is to route you to an unduplicated bug with impact, fast — not to collect data.* Go wide to find the forgotten asset, go deep to find the hidden endpoint, hit the Tier-1 criticals across everything, and **monitor** so you're first. Then hand the routed surface to the XSS / JWT / API exploitation guides and turn the map into a payout.
