# Web Reconnaissance for Bug Bounty — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **recon** — from "what is recon and why it pays" to the full
> pipeline (org/ASN expansion → passive+active subdomains → resolve/probe → content/JS/API → high-value: takeover,
> secrets, cloud, mobile, dorking, monitoring) and, crucially, **routing every finding to a bug class with impact**.
> Q&A format, progressive difficulty. Explains **what everything is** (so you build real expertise) with explicit
> **"if you found THIS, test THIS"** routing. Covers tooling, methodology, **real-world high/critical wins**, and the
> defender's view.
>
> ⚖️ **Authorized use only.** Stay in scope (read the policy), respect rate limits and automation rules, never test
> out-of-scope assets, and for any "exploit" step (bucket write, takeover claim, secret validation) use **benign**
> proof on **your own** resources / read-only checks. Never test systems you don't have written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- ProjectDiscovery — subfinder / httpx / naabu / katana / nuclei / dnsx / chaos (docs + the recon tooling that defines the field)
- `tomnomnom` tooling (gau / waybackurls / qsreplace / gf / unfurl / anew) · OWASP WSTG — *Information Gathering*
- *The Bug Hunter's Methodology (TBHM)* (Jason Haddix) · `reconFTW` · PayloadsAllTheThings & HackTricks recon notes
- Shodan / Censys / FOFA (internet-wide search) · Hackviser & PentesterLab recon modules
- Companion kit in this repo: `Web/Recon/` (guide + arsenal + checklist + notes template + `scripts/` pipeline)

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q12)
- **Level 1 — Scope & target selection** (Q13–Q20)
- **Level 2 — Asset discovery (go wide)** (Q21–Q40)
- **Level 3 — Resolve & probe** (Q41–Q52)
- **Level 4 — Go deep (content / JS / API)** (Q53–Q66)
- **Level 5 — High-value recon (takeover / secrets / cloud / mobile / dorking / monitoring)** (Q67–Q86)
- **Recon → bug routing** (Q87–Q90)
- **Tooling** (Q91–Q94)
- **Methodology & discipline** (Q95–Q97)
- **Cheat sheets** (Q98–Q101)
- **Real-world wins & references** (Q102–Q103)
- **The defender's view** (Q104–Q105)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is reconnaissance, in bug bounty terms?
Recon is **mapping the target's entire attack surface** — every domain, subdomain, IP, host, endpoint, parameter, API,
JS file, secret, and cloud asset — and then **routing each finding to a bug class with impact**. It's not a phase you
rush before "real hacking"; on broad-scope programs, recon **is** most of the edge — you find and test surface nobody
else mapped.

### Q2. Why does recon pay so well (and reduce duplicates)?
Because the #1 frustration in bounty is **duplicates**, and dupes happen on the **well-trodden main app** where everyone
looks. The cure is **depth**: acquisitions, ASN ranges, source maps, vhosts, archived params, and **fresh subdomains
found minutes after they go live**. Surface nobody else mapped → bugs nobody else reported. Recon converts breadth into
unduplicated findings.

### Q3. What's the high-level recon flow?
**Wide → Resolve/Probe → Deep → High-value → Monitor.**
1. **Go wide** (assets): org/ASN/acquisitions → passive subs → active subs → what-others-miss.
2. **Resolve & probe**: DNS resolve → httpx (status/title/tech/CDN) → ports → tech/favicon → vhosts.
3. **Go deep** (on *interesting* hosts only): history/wayback → content/dirs → params → JS + source maps → APIs/GraphQL.
4. **High-value**: takeover, secrets/GitHub, cloud buckets, exposed `.git`/`.env`, CORS, mobile, dorking.
5. **Monitor**: re-run continuously → alert on NEW surface (first-mover advantage).

### Q4. What's the single most important recon skill?
**Routing discipline.** Recon's output is worthless until you map "I found X → therefore test bug class Y for impact Z."
A login panel → auth/JWT/OAuth bypass; `/api`/GraphQL → IDOR/BOLA/logic; `url=` param → SSRF; exposed `.git` →
source/secrets; dangling CNAME → takeover. The expert spends 80% of effort on the 20% of surface with a backend, auth,
or money behind it.

### Q5. "Where the money is" — the routing order to memorize?
① **forgotten/dev/staging/admin hosts** (least hardened, least duped) → ② **APIs & GraphQL** (authz/IDOR/logic
goldmines) → ③ **leaked secrets** (GitHub dorking, source maps, `.env`, exposed `.git`) → ④ **subdomain takeover &
dangling cloud** (clean, high-severity, fast) → ⑤ **newly-discovered assets via monitoring** (first-mover) → ⑥ *then*
the well-trodden main app, where everyone else already is.

### Q6. Passive vs active recon — what's the difference?
**Passive** = gather info without touching the target's infra (CT logs, search engines, Wayback, third-party datasets,
GitHub) — quiet, no rate-limit risk. **Active** = you query the target (DNS brute, port scan, httpx probing, content
fuzzing) — louder, mind rate limits/automation rules. Do **passive first** (it's free and quiet), then active to fill
gaps.

### Q7. Why are API keys a "force multiplier" for recon?
Subdomain tools aggregate dozens of sources, many gated behind free/cheap API keys (Censys, Shodan, SecurityTrails,
VirusTotal, GitHub, Chaos). **Without keys you find ~60% of subdomains; with keys ~95%.** Configuring those keys is a
"what others miss" edge that costs nothing.

### Q8. What does "go wide vs go deep" mean?
**Go wide** = enumerate *all* assets (every subdomain/IP/host) — breadth. **Go deep** = on the *interesting* assets
only, mine content/JS/params/APIs — depth. You go wide to find everything, then go deep **selectively** (you can't
manually test 5,000 hosts — you test the 50 with auth/APIs/admin/dev in the name).

### Q9. What's the mindset (the five questions)?
**WHO** (assets — every host/IP/app), **WHY** (each is a door to a bug class with impact), **WHERE** (the "boring"
places others skip — acquisitions/ASN/staging/JS-maps/archived-params/vhosts), **HOW** (wide→probe→deep→high-value),
**WHAT ELSE** (monitor for NEW surface, pivot via trust — CORS/SSO/shared infra, correlate via favicon/ASN).

### Q10. What recon output do I actually produce?
A set of artifacts: `subs_all.txt` (complete asset list), `live.txt` (probed, **sorted by interesting**),
`urls_all.txt` (historical URLs, gf-routed), `endpoints.txt`/`params.txt`, `js_secrets.txt`, `api_routes.txt`, and a
**ranked, routed testing queue** — the list of "host/endpoint → bug class to test." Recon ends when you have that queue.

### Q11. What do I need to learn first?
DNS basics, HTTP probing, the core tooling (ProjectDiscovery suite + tomnomnom tools), how to configure API keys, regex
for mining, and — most importantly — the **recon→bug routing** table. Plus discipline: stay in scope, respect rate
limits.

### Q12. How is recon different on a single-host vs wildcard program?
**Wildcard** (`*.target.com` / "all assets") → maximize breadth (org/ASN/acquisitions/subdomains) — the dupe-avoidance
edge. **Single-host** → no subdomain breadth, so go **deep** immediately (content/JS/params/API/source-maps/historical)
on that one host. Match the strategy to the scope.

---

# LEVEL 1 — SCOPE & TARGET SELECTION

### Q13. Why read the scope policy "like it pays"?
Because it defines what you may touch (wildcard? acquisitions? ASN/IP ranges? mobile/API?), what's **out of scope**
(testing it = report invalid + possible ban), rate/automation rules, banned issue types, and safe-harbor. The policy
also *tells you where the surface is* (in-scope ASN → naked IP assets; mobile in scope → leaked endpoints/keys).

### Q14. What scope facts change my whole approach?
- **Wildcard `*.target.com`** → full subdomain enum is in play.
- **Acquisitions in scope** → expand to the org's other companies (huge, low-dupe surface).
- **ASN/IP ranges in scope** → find **DNS-less** assets (a bare IP running an old panel) via ASN scanning.
- **Mobile apps/APIs in scope** → decompile apps for endpoints/keys the web never exposes.
- **Automation allowed?** → governs whether you can run aggressive scans.

### Q15. How do I pick a target worth a week?
**Broad scope + a real backend + auth/APIs/money.** More surface = more unduplicated bugs; a real backend = real logic
bugs; auth/payment/admin = high impact. Avoid tiny single-page marketing sites (everyone's tested them, low surface).
Target selection **is** recon.

### Q16. What's "out of scope" discipline?
Never enumerate-and-test assets outside scope, even if you find them (a sibling domain not listed, a third party). You
may *map* them for completeness/monitoring, but **don't probe/exploit** out-of-scope hosts — it's invalid and can get
you banned. When in doubt, ask the program.

### Q17. Are acquisitions really worth chasing?
Yes — acquired companies often run **older, less-hardened** infra under the parent's scope, and almost nobody enumerates
them. Find them via Crunchbase/Wikipedia/"Target acquires"/SEC filings, then enumerate each root domain. A classic
low-dupe edge — **only if the policy includes acquisitions**.

### Q18. What's the deliverable from scope/selection?
`in_scope.txt` / `out_scope.txt`, a note on wildcard/acquisitions/ASN/mobile, the rate/automation rules, and a one-line
reason this target is worth your time. This file governs everything that follows.

### Q19. How do I handle "ASN/IP in scope"?
ASN scanning finds **assets with no DNS record** (a bare IP running a forgotten admin panel) that subdomain enum never
sees. `amass intel -org "Target Inc"` → ASN → IP ranges → scan for live HTTP on odd ports. These are prime, low-dupe
targets.

### Q20. What if automation isn't allowed?
Respect it — switch to **passive-heavy** recon (CT logs, search engines, Wayback, GitHub, third-party datasets) and
manual/low-rate probing. Many programs allow passive recon but restrict aggressive scanning; read carefully and stay
within the rules.

---

# LEVEL 2 — ASSET DISCOVERY (GO WIDE)

### Q21. How do I expand the organization (find other root domains)?
`amass intel -org "Target Inc"` (ASN/org search), reverse-whois (`amass intel -whois`), `whois <known-IP> | grep -i
origin` → ASN → enumerate its prefixes, **acquisitions** (Crunchbase/SEC), and a **favicon-hash pivot** (hosts serving
the same favicon = same org). Each new root domain multiplies your subdomain surface.

### Q22. How do I enumerate subdomains passively?
`subfinder -d target.com -all -recursive`, `amass enum -passive`, `chaos -d target.com`, and **crt.sh** (CT logs —
catches internal-naming subs). Plus GitHub code search for subdomains hardcoded in repos. **Configure API keys first**
(Q7). Merge + dedup with `anew`.

### Q23. Which passive sources matter most?
CT logs (crt.sh, Censys), VirusTotal, SecurityTrails, Shodan, AlienVault OTX, Wayback, RapidDNS, DNSDumpster, and GitHub
code search. subfinder/amass aggregate most of these — but only with the **API keys** configured.

### Q24. How do I enumerate subdomains actively?
1. **Resolve** passive results, drop dead ones, filter DNS wildcards (`puredns resolve -r resolvers.txt`).
2. **DNS bruteforce** with a good wordlist (`puredns bruteforce subdomains-top1m.txt`) — finds unlisted ones.
3. **Permutations** (`gotator`/`dnsgen`/`altdns`: `dev`→`dev2`, `api`→`api-staging`) — **high yield, under-used**.
4. Merge everything into `subs_all.txt`.

### Q25. Why are permutations "high yield, under-used"?
Because orgs name predictably (`api`, `api-dev`, `api-staging`, `api2`, `api-internal`). Permutation tools generate
those variants from your known subs and resolve them — finding hosts that aren't in any passive source. Most hunters
skip this pass; it routinely finds the **dev/staging** hosts where the bugs are.

### Q26. Why keep DNS resolvers fresh?
Stale/dead resolvers cause **missed subdomains** (timeouts) and **false positives** (poisoned answers). A fresh,
validated resolver list is the difference between accurate active enum and garbage. Refresh it regularly.

### Q27. What's "subdomain enum — what people miss"?
The extra layer: **TLS-SAN harvest** (pull hostnames from live hosts' certificates — names DNS won't give you),
**recursive enum** on an interesting sub, **internal hostnames from JS/CT logs**, **reverse DNS on the ASN** (PTR
records reveal naming to re-brute), and **alt-TLD/region** variants. These find hosts no single source has.

### Q28. How do I harvest hostnames from TLS certs?
Resolve your subs to IPs, then `tlsx -san -cn` on those IPs → the certificate's Subject Alternative Names reveal
additional hostnames (often internal/related) that aren't in DNS enum. A quiet, high-yield "what others miss" pass.

### Q29. What's the favicon-hash pivot?
Compute the MurmurHash of the site's favicon, then search **Shodan `http.favicon.hash:<hash>`** → every host (including
**no-DNS IPs** and other orgs) serving the same favicon = likely the same app/org. Finds hidden instances and origin
IPs subdomain enum misses.

### Q30. How do I find DNS-less assets?
Scan the in-scope **ASN/IP ranges** for live HTTP (often on odd ports) — these never appear in subdomain enum because
they have no DNS record. A bare IP running a forgotten admin panel is a classic low-dupe find.

### Q31. What's GitHub code search good for in asset discovery?
Hardcoded **subdomains, internal hostnames, and API base URLs** in the org's (and employees') repos — names DNS enum
won't surface. `github-subdomains -d target.com` + manual code search for `target.com` strings.

### Q32. How do I merge and dedup the asset list?
Pipe everything through `anew` / `sort -u` into `subs_all.txt`. `anew` is especially useful for **monitoring** — it
emits only *new* lines, so you can re-run enum and immediately see freshly-appeared subdomains (first-mover, Q83).

### Q33. Do I test every subdomain I find?
No — you **map** all of them (for completeness, takeover, monitoring) but you **manually test** only the *interesting*
ones (auth/api/admin/dev/dashboards). Going deep on every host is impossible; routing discipline (Q4) decides where
your manual effort goes.

### Q34. What's the difference between a subdomain and a vhost?
A **subdomain** has its own DNS record. A **vhost** is a site served by a shared IP based on the `Host` header, possibly
with **no DNS record** — you find it by fuzzing the `Host` header against a known IP (`ffuf -H "Host: FUZZ.target.com"`).
vhost fuzzing finds no-DNS sites on shared infra (§Q49).

### Q35. How do I handle wildcard DNS during enum?
A wildcard DNS record makes *every* random subdomain "resolve," polluting your results with false positives. Detect it
(resolve a random non-existent sub) and **filter** it (`puredns` does this) so your active enum stays accurate.

### Q36. What about alt-TLDs and regional domains?
Orgs register `target.io`/`target.dev`/`target.de`/`target-corp.com`. Check the org's other TLDs/regions (and
acquisitions) — each is a fresh root to enumerate. Low effort, occasionally a whole new surface.

### Q37. How deep should org expansion go?
As deep as **scope** allows. On a big-scope program, ASN → acquisitions → favicon pivots can 10× your root-domain list.
On a single-host program, skip it. The payoff is unduplicated surface — but only test what's **in scope**.

### Q38. What's the "first-mover" concept in asset discovery?
New subdomains/hosts go live constantly (a new staging env, a new feature host). Whoever **finds and tests it first**
(before it's hardened or before other hunters notice) gets the bug. Continuous monitoring (Q83) operationalizes this.

### Q39. How do I correlate assets to confirm they're the same org?
**Favicon hash** (same favicon), **ASN** (same IP block), **analytics IDs** (same Google Analytics/Tag Manager ID),
**TLS cert** (same SAN/issuer), **WHOIS** (same registrant). These pivots both *expand* the surface and *confirm*
in-scope ownership.

### Q40. The deliverable from "go wide"?
`subs_all.txt` — the **complete** asset list (passive + active + permutations + what-others-miss + org expansion),
deduped. Now resolve and probe it (Level 3).

---

# LEVEL 3 — RESOLVE & PROBE

### Q41. What does "resolve & probe" mean?
Take `subs_all.txt`, resolve DNS, and **probe HTTP** with `httpx` to learn each host's **status code, title, tech stack,
CNAME, IP, and CDN** — turning a list of names into a map of *what each host actually is*. This is where you decide
which hosts are worth deep testing.

### Q42. What httpx columns matter most?
**status** (200/401/403/redirect), **title** + **tech** (Spring Boot/Django/Jira/GitLab/Kibana → known attack
surfaces), **cname** (points to S3/Heroku/GitHub/Azure that 404s → **takeover**), and **ip/CDN** (behind Cloudflare? →
origin-IP hunt). Probe multiple ports (80/443/8080/8443/3000/5000/9000).

### Q43. Why "sort live.txt by interesting, not alphabetically"?
Because your manual time is finite. Grep titles/tech for
`admin|login|dashboard|internal|dev|staging|test|api|swagger|graphql|jenkins|grafana|kibana|jira|git|vpn|portal` and put
those at the **top of the testing queue**. Everything else is coverage, not a priority.

### Q44. What do 401/403 hosts tell me?
They're **auth walls** guarding something — prime **403/401-bypass** candidates (header tricks, path tricks, method
tricks) and, if bypassed, often **admin/internal** functionality. Flag every `40(1|3)` for a bypass attempt.

### Q45. How do I port-scan effectively?
`naabu -top-ports 1000` on resolved hosts (rate-limited to avoid choking the network), then `httpx` the open ports.
Note **data-store/dashboard ports**: 6379 Redis, 9200 Elasticsearch, 27017 Mongo, 3306/5432 DB, 5601 Kibana, 8080/8443
internal apps, 2375 Docker, 10250 kubelet. Open internal ports = high-value targets (and SSRF reach).

### Q46. What's the origin-IP hunt and why does it matter?
When a host is behind a **WAF/CDN** (Cloudflare), finding the **real origin IP** lets you hit the app **directly**,
bypassing the WAF — often the app there is unprotected. Find it via historical DNS (SecurityTrails), Shodan cert search
(`ssl.cert.subject.cn:"target.com"`), favicon hash, or SAN leaks; verify with
`curl -H "Host: target.com" https://<origin_ip>/`.

### Q47. Why is origin-IP discovery so high-value?
Because it **defeats the WAF** — the same payloads that get blocked at the edge often sail through to the origin. A
recon win that makes *every* subsequent injection test easier. (It's also why this kit added an origin-IP module.)

### Q48. How do I fingerprint tech, and why?
`httpx -td` + Wappalyzer + favicon hash. Tech tells you the **attack surface**: Spring Boot → actuator endpoints;
WordPress → plugin CVEs; GitLab/Jira → known CVEs; GraphQL → introspection/IDOR. Fingerprint → route to the matching
bug class.

### Q49. What is vhost fuzzing and when do I use it?
Fuzz the `Host` header against a **known IP** (`ffuf -H "Host: FUZZ.target.com" -u https://<IP>/ -fs <baseline>`) to find
**no-DNS sites** on shared infra. When a host serves different content for different `Host` values, you've found vhosts
DNS enum missed.

### Q50. How do I handle CDN-fronted hosts during probing?
Note that they're behind a CDN (the IP belongs to Cloudflare/Akamai/Fastly), then **hunt the origin** (Q46). Also note
that the CDN may be a **request-smuggling/host-header** surface (the front-end+back-end chain — cross-ref those kits).

### Q51. What about cloud-hosted hosts (CNAME to AWS/Azure/GCP)?
A CNAME to a cloud service that returns a **404/NXDOMAIN** = a **dangling** record → **subdomain takeover** (Q67). A
CNAME to a live cloud bucket → check bucket permissions (Q73). Cloud CNAMEs are a takeover/cloud-misconfig goldmine.

### Q52. The deliverable from resolve & probe?
`live.txt` with status/title/tech/cname/ip, **sorted by interesting**, with auth walls flagged, ports noted, and origin
IPs found where applicable. This is your prioritized list of hosts to go deep on (Level 4).

---

# LEVEL 4 — GO DEEP (CONTENT / JS / API)

### Q53. What is "going deep" and on which hosts?
Mining **content, JS, params, and APIs** on the **interesting** hosts only (from your sorted `live.txt`). You can't go
deep on 5,000 hosts — you go deep on the 50 with auth/APIs/admin/dev. Deep recon turns a host into a list of **endpoints
+ parameters + secrets** to test.

### Q54. How do I mine historical URLs, and why?
`gau`/`waybackurls`/`katana` → `urls_all.txt` (every URL the site ever exposed, incl. **forgotten endpoints and
parameters**). Then **gf-route** them (`gf xss/ssrf/redirect/idor/sqli/lfi`) into candidate lists per bug class. History
finds dead-but-still-working endpoints and old params that current crawling misses.

### Q55. What forgotten files do historical URLs reveal?
`grep -Ei '\.(json|xml|config|env|bak|sql|log|zip|tar|gz|ya?ml|old|swp)'` over `urls_all.txt` → **forgotten sensitive
files** (a `.env.bak`, a `config.old`, a `db.sql`) that may still be reachable → secrets/source. A fast,
high-value pass.

### Q56. How do I do content/directory discovery?
`ffuf` with a **context-matched** wordlist (raft-medium + extensions `.json/.bak/.old/.config/.zip/.sql`), recursing
into found dirs; plus **direct probes** for high-value paths: `/.git/config`, `/.env`, `/actuator/env`,
`/actuator/heapdump`, `/swagger.json`, `/graphql`, `/server-status`, `/.DS_Store`, `/phpinfo.php`.

### Q57. Why probe `/.git`, `/.env`, `/actuator` directly?
Because they're **instant high-impact** when exposed: `/.git/config` → `git-dumper` → full **source + secrets**; `/.env`
→ DB/cloud creds; `/actuator/env`/`/heapdump` → Spring secrets/credentials; `/swagger.json` → the full API map. These
are fast Criticals that don't need a wordlist.

### Q58. How do I discover parameters?
`arjun` per endpoint (and param-miner in Burp for headers/cookies/JSON) → **hidden parameters** not in the UI; plus
**all historical param names** from `urls_all.txt` (`unfurl keys`). Test high-value names: `redirect/url/next` (SSRF/open
redirect), `id/user/order/doc/file` (IDOR/LFI), `debug/admin/isAdmin` (logic/authz).

### Q59. Why is JS analysis a core deep-recon step?
Because the bundle is the **backend's blueprint**: endpoints, parameters, hidden routes, roles, feature flags, and
**secrets**. Collect bundles, extract endpoints (jsluice/LinkFinder) + secrets (trufflehog), and **validate** any live
secret. (Cross-ref the JS-files kit — JS recon feeds every other bug class.)

### Q60. What are source maps and why pull them?
A reachable `.js.map` reconstructs the **original commented source** (variable names, dead admin code, secret comments).
Probe `<bundle>.js.map` (even when unreferenced); if exposed, unpack it and re-mine the original source. Exposed prod
source maps are a recon goldmine.

### Q61. How do I enumerate APIs and GraphQL?
Find specs: `/swagger.json`, `/openapi.json`, `/v2/api-docs`, `/api-docs`, `/swagger-ui.html`. For GraphQL: test
**introspection** (`{__schema{types{name fields{name}}}}`); if disabled, recover the schema with **clairvoyance** or
the bundle. Fingerprint the engine with `graphw00f`.

### Q62. Why are APIs/GraphQL such goldmines?
Because they expose **object-scoped endpoints** (→ IDOR/BOLA), **function-level** operations (→ BFLA/authz), **mass
assignment**, and **business logic** — often with weaker authz than the UI. The introspected schema hands you every
sensitive query/mutation to test.

### Q63. What about old API versions?
`/api/v1` vs `/api/v2` — the **old version** often lacks the new version's authz checks (it was left running for
backwards compatibility). Test every API version you find; the deprecated one is frequently the weak one.

### Q64. How do I route the deep-recon output?
Each artifact → a bug class: extracted **endpoints** → IDOR/authz/SSRF/injection; **params** → XSS/SSRF/LFI/SQLi;
**hidden admin routes** → privilege escalation; **JS secrets** → cloud/JWT; **API spec** → BOLA/BFLA. Deep recon's
payoff is a **targeted** test plan, not guesswork.

### Q65. 403/401 bypass during deep recon?
On interesting protected paths (`/admin`, internal endpoints), try header tricks (`X-Original-URL`, `X-Forwarded-For`),
path tricks (`/admin/`, `/admin/.`, `/%2e/admin`), and method tricks. A bypassed 403 to an admin/internal endpoint is a
fast finding (cross-ref the Host-Header/Request-Smuggling kits for header/desync bypasses).

### Q66. The deliverable from "go deep"?
`endpoints.txt`, `params.txt`, `js_secrets.txt`, `api_routes.txt` — a **routed, prioritized list** of what to test on
the high-value hosts. Now run the high-value recon passes (Level 5) and start testing.

---

# LEVEL 5 — HIGH-VALUE RECON

### Q67. What is subdomain takeover and how do I find it?
A subdomain's **CNAME points to a service (S3/Heroku/GitHub Pages/Azure/Fastly/Zendesk) that's no longer claimed** →
you register it and serve content on the org's subdomain. Find with `nuclei -t takeovers`/`subzy` over `subs_all.txt`;
confirm the dangling CNAME (a 404/NXDOMAIN fingerprint).

### Q68. Why is takeover high-value, and how do I escalate it?
Because it's a **clean, high-severity, fast, low-dupe** win — you control content on the org's origin. Escalate: if the
session **cookie is scoped to `.target.com`**, a takeover of `sub.target.com` can **steal/set cookies** for the whole
domain → ATO; or it satisfies a **`*.target.com` CORS/CSP trust** → credentialed theft (CORS kit). Check the cookie
`Domain` scope.

### Q69. How do I hunt secrets (GitHub/GitLab)?
`trufflehog github --org=Target --only-verified` (and over commit **history**), plus GitHub **dorks**: `org:Target
"BEGIN RSA PRIVATE KEY"`, `"target.com" jdbc:`, `filename:.env DB_PASSWORD`, `filename:.tfstate target`. **Verify**
every secret before believing it (verified = it actually authenticates).

### Q70. Why "verify before believing" a secret?
Because most regex matches are **dead/rotated/placeholder/example** keys. A finding starts at *"this key authenticates
right now."* trufflehog `--only-verified` and a minimal read-only call (`aws sts get-caller-identity`, `GET /user`)
separate real Criticals from noise. (Cross-ref the JS-files kit's validation discipline.)

### Q71. What's the impact of a verified leaked secret?
A live **cloud key** → cloud takeover/RCE; a **CI/VCS token** → supply-chain RCE; a **server/admin API key** →
privileged actions; a **signing secret** → forge JWTs/sessions. A single verified secret is often the fastest Critical
in the whole engagement.

### Q72. Where else do secrets leak (beyond GitHub)?
**Postman** public workspaces, **Pastebin**, GitLab/Bitbucket snippets, **Docker Hub** images (layers with `.env`/keys),
public **S3/GCS/Azure** objects, JS bundles (JS-files kit), and **mobile apps** (Q80). The dorking section (Q78) covers
the search queries.

### Q73. How do I find and test cloud buckets?
`cloud_enum`/`s3scanner` with org-based keywords (`target`, `target-prod`, `target-uploads`, `target-backups`). Test
**public list** (`aws s3 ls s3://bucket --no-sign-request`) and a **benign write** (upload a `poc.txt` you delete —
never overwrite real data). A world-readable/writable bucket = data exposure / supply-chain (overwrite a served asset).

### Q74. Exposed `.git`/`.env`/backups — how do I exploit them?
`/.git/config` reachable → `git-dumper` → reconstruct the **full repo** (source + secrets + history). `/.env` → DB/cloud
creds. Backups (`.sql`/`.bak`/`.zip`) → data/source. `nuclei -t exposures` flags these across the surface; they're fast
Criticals.

### Q75. How do I map CORS / cookie trust during recon?
Inject `Origin: https://evil.com` across hosts and grep for a **reflected ACAO** (+ `ACAC:true`); note the session
cookie's **`Domain` scope** (`.target.com` = subdomain trust). This builds a **trust map** that turns a subdomain
takeover/XSS into a credentialed-theft chain (CORS/CSRF kits).

### Q76. Why build a "trust map"?
Because the highest-impact chains come from **trust pivots**: a takeover of any `*.target.com` + a `.target.com`-scoped
cookie or a `*.target.com` CORS allowlist → ATO. Recon that maps *what trusts what* (CORS, cookie scope, SSO, shared
infra) reveals these chains.

### Q77. How do I do mobile-app recon concretely?
Decompile the in-scope APK (`apktool d` / `jadx`) or IPA (unzip → `strings` the binary + plists), then **mine it like a
JS bundle**: grep for endpoints/hosts, `AKIA…`/`AIza…`/`firebaseio.com`/`api_key`/`secret`/private keys. Test any
**Firebase RTDB** (`/.json` unauth). Mobile reveals staging/internal hosts and keys the web app never exposes.

### Q78. What is dorking and which engines?
Using search engines to find assets DNS enum misses: **Shodan/Censys** (`ssl.cert.subject.CN:"target.com"`, favicon
hash → hosts with no DNS / origin IPs / exposed panels), **FOFA**, **Google** (`site:target.com inurl:admin|api`,
`ext:env|sql|bak`, `intitle:"index of"`), **GitHub** (secret dorks). Run these *after* subdomain enum looks "done" —
they routinely add surface.

### Q79. What does dorking typically surface?
A **CDN origin IP** (→ WAF bypass), an **exposed admin panel / Elasticsearch / Kibana**, a **leaked secret** (Pastebin/
GitHub), a forgotten `index of`/backup, or a **no-DNS host** (favicon-hash pivot). The stuff subdomain enum can't find.

### Q80. What is recon monitoring (and why "first-mover")?
Cron the enum + takeover/exposure checks and pipe through `anew` (emits only NEW lines) → you get **alerted the moment a
new subdomain/asset appears**, and you test it **before** it's hardened or other hunters notice. New assets are the
least-tested, least-duped surface.

### Q81. How do I set up monitoring concretely?
```bash
subfinder -d target.com -all -silent | anew subs.txt | httpx -silent \
  | nuclei -t takeovers/ -t exposures/ -silent | notify -silent
```
`anew` only passes *new* subs → only new assets get probed → alerts on new takeovers/exposures. Run daily.

### Q82. What's the supply-chain / dependency-confusion angle?
If the org publishes **internal package names** (from the bundle/`package.json`), an unclaimed public package with that
name may get pulled into their build → **RCE on build agents**. A recon-driven supply-chain finding (only test where
explicitly authorized — claim the name responsibly, don't run code in their pipeline).

### Q83. What third-party/OSINT surface should I check?
Exposed Jira/Confluence/Trello boards, public Slack, status pages, misconfigured Google Docs, vendor S3; and **employee
OSINT** (LinkedIn tech stack, dev blogs, StackOverflow questions naming internal systems) → seeds for subdomain/param/
tech guessing. The org's data sometimes leaks via a **vendor**.

### Q84. How do I prioritize the high-value passes?
Run them **early** (they pay fast and are low-dupe): takeover + exposures + secrets + buckets first, then CORS/trust,
mobile, dorking. A confirmed takeover or a verified leaked key can be a Critical in the first hour — before you've even
opened the main app.

### Q85. How do I avoid harming the target during high-value recon?
Read-only by default: validate secrets with minimal read-only calls; for buckets, a **benign** `poc.txt` you delete
(never overwrite real objects); for takeover, claim it and serve a benign marker (don't phish). Respect the program's
rules and safe-harbor.

### Q86. The deliverable from high-value recon?
A shortlist of **confirmed exposures** (takeovers, verified secrets, public buckets, exposed `.git`/`.env`) + a **trust
map** + **leads** — the fastest Criticals, plus the routing into the deeper bug-class testing.

---

# RECON → BUG ROUTING

### Q87. What's the recon→bug decision matrix (the point of it all)?
```
Login/SSO/auth panel        → auth bypass, JWT/OAuth flaws, default creds, 2FA bypass   (JWT/CORS kits) — ATO
/api, swagger, GraphQL      → IDOR/BOLA, BFLA, mass assignment, logic                   — cross-user/admin data, money
url/redirect/next/dest param→ open redirect → SSRF                                       (SSRF kit) — metadata/RCE
id/user/order/doc/file param→ IDOR, LFI                                                  (LFI kit) — other users' data
q/search/name/comment param → XSS (reflected/stored)                                     (XSS kit) — session/ATO
user-content render         → stored XSS, file-upload XSS                                (XSS/FileUpload) — 0-click admin ATO
upload feature              → web shell, SVG-XSS, XXE, SSRF                              (FileUpload kit) — RCE
dangling CNAME              → subdomain takeover                                         — ATO via cookie/CORS trust
exposed .git/.env/actuator  → source/secret disclosure → RCE/cloud                       — Critical
host-header reflected/cache → reset-poisoning/cache-poisoning/routing-SSRF              (Host-Header kit)
CDN front-end + origin      → request smuggling / WAF bypass                            (Request-Smuggling kit)
template-rendered field     → SSTI → RCE                                                (SSTI kit)
Java app ${}/%{}            → OGNL/EL injection → RCE                                    (SSTI kit)
```

### Q88. Why is the routing matrix "the point of recon"?
Because recon without routing is just a pile of hosts. The matrix converts **every finding into a concrete test with
known impact** — it's how you turn "I found 3,000 endpoints" into "these 40 are IDOR/SSRF/SSTI candidates worth my
time." Memorize it.

### Q89. How do I prioritize the routed queue?
By **impact × dupe-probability**: high-impact + low-dupe first (admin/dev hosts, APIs, takeovers, secrets) → then the
main app's high-impact params (auth/IDOR/SSRF) → then everything else. Don't start on the homepage's reflected `q=`
param that 200 hunters already tested.

### Q90. When is recon "done"?
When you have a **ranked, routed testing queue** — a prioritized list of "host/endpoint → bug class → why it matters."
Then you switch from recon to **exploitation** (the per-class kits). Recon isn't done when you've listed assets; it's
done when you know **what to test, where, and in what order**.

---

# TOOLING

### Q91. Core recon toolkit?
**ProjectDiscovery suite** (subfinder, httpx, naabu, katana, nuclei, dnsx, chaos, notify), **tomnomnom** tools (gau,
waybackurls, qsreplace, gf, unfurl, anew), **amass** (org/ASN), **puredns**+**gotator** (active/permutations),
**ffuf** (content/vhost), **arjun** (params), **jsluice/LinkFinder/trufflehog** (JS/secrets), **subzy**/nuclei-takeovers,
**cloud_enum/s3scanner**, **Shodan/Censys/FOFA**, and **fresh resolvers + good wordlists (SecLists)**.

### Q92. Why is the wordlist/resolver quality "the part everyone underrates"?
Because active enum and content discovery are only as good as the **wordlist** (a tiny list misses the staging host /
the backup file) and the **resolvers** (stale ones miss subs and produce false positives). Good wordlists (SecLists,
commonspeak2) + fresh validated resolvers = the accuracy edge.

### Q93. How do I run this without spending all day?
Use the kit's **`scripts/` pipeline** (enumerate → resolve → probe → mine JS → takeover-check → monitor) for the wide/
probe phases, then go **manual** on the routed queue. Automate the breadth; spend your brain on the depth and routing.

### Q94. How do I avoid getting blocked/banned by tooling?
Respect **rate limits** and the program's **automation rules**; throttle naabu/ffuf; prefer passive sources; don't
hammer a single host. Aggressive scanning that knocks over a service (or violates the policy) gets you banned, not paid.

---

# METHODOLOGY & DISCIPLINE

### Q95. Step-by-step methodology.
1. **Scope & select** (read policy; pick broad-scope + real backend). 2. **Go wide** (org/ASN/acquisitions → passive →
active → permutations → what-others-miss). 3. **Resolve & probe** (httpx, ports, origin-IP, tech/favicon, vhosts; sort
by interesting). 4. **Go deep** (history/content/params/JS+maps/API/GraphQL on interesting hosts). 5. **High-value**
(takeover/secrets/cloud/CORS/mobile/dorking). 6. **Route** every finding to a bug class. 7. **Monitor** for new surface.

### Q96. What's the single biggest discipline mistake?
**Testing the main app where everyone else is** (dupes) instead of the **forgotten/dev/staging/API** surface (low-dupe,
high-impact). The second is **not routing** — collecting recon you never convert into a test. Spend 80% of effort on the
20% of surface with a backend/auth/money.

### Q97. How do I keep recon from becoming an endless rabbit hole?
Time-box the wide pass, **automate** breadth, and switch to **manual testing the moment you have a routed queue**. Recon
serves the bugs, not the other way around — if you've spent a day enumerating and haven't tested anything, you've
over-recon'd. Find broadly, but **test the high-value subset**.

---

# CHEAT SHEETS

### Q98. Asset-discovery cheat sheet.
```
org:        amass intel -org "Target Inc" ; whois <IP>|grep origin ; favicon-hash Shodan pivot ; acquisitions (Crunchbase/SEC)
passive:    subfinder -d t.com -all -recursive ; amass enum -passive ; crt.sh ; chaos ; github-subdomains   (API KEYS!)
active:     puredns resolve -r resolvers.txt ; puredns bruteforce top1m.txt ; gotator/dnsgen permutations
miss:       tlsx -san -cn (cert hostnames) ; reverse-DNS on ASN ; internal names from JS/CT ; alt-TLD/region
merge:      ... | anew subs_all.txt
```

### Q99. Probe & deep cheat sheet.
```
probe:   httpx -l subs_all.txt -sc -title -td -cname -ip -p 80,443,8080,8443,3000,5000,9000 -o live.txt
sort:    grep -Ei 'admin|login|dashboard|internal|dev|staging|api|swagger|graphql|jira|git|vpn|grafana|kibana' live.txt
ports:   naabu -top-ports 1000 ; note 6379/9200/27017/3306/5432/8080/2375/10250
origin:  SecurityTrails history · Shodan ssl.cert.subject.cn · favicon hash → curl -H "Host: t.com" https://<origin>/
deep:    gau/waybackurls/katana → gf xss/ssrf/redirect/idor/lfi ; ffuf dirs+ext ; arjun params ; jsluice+trufflehog ; .js.map
direct:  /.git/config /.env /actuator/env /actuator/heapdump /swagger.json /graphql /.DS_Store /server-status
```

### Q100. High-value cheat sheet.
```
takeover:  nuclei -t takeovers/ ; subzy run --targets subs_all.txt ; check cookie Domain=.target.com → ATO
secrets:   trufflehog github --org=Target --only-verified ; gh dorks ("BEGIN RSA PRIVATE KEY", filename:.env DB_PASSWORD)
buckets:   cloud_enum -k target -k target-prod ; aws s3 ls s3://b --no-sign-request ; benign write you delete
exposures: nuclei -t exposures/ ; git-dumper <host>/.git/
mobile:    apktool d / jadx → grep endpoints/AKIA/AIza/firebaseio/api_key ; test RTDB /.json
dorking:   Shodan ssl.cert.subject.CN:"t.com" + favicon hash ; Google site:t.com inurl:admin / ext:env|bak ; GitHub
monitor:   subfinder -silent | anew subs.txt | httpx -silent | nuclei -t takeovers/ -t exposures/ | notify
```

### Q101. Routing cheat sheet (recon → bug).
```
auth panel→ATO(JWT)   /api,GraphQL→IDOR/BOLA   url/redirect→SSRF   id/file→IDOR/LFI   q/name→XSS   upload→RCE
dangling CNAME→takeover   .git/.env/actuator→secrets/RCE   host reflected→host-header   CDN+origin→smuggling/WAF-bypass
template field→SSTI   Java ${}→OGNL/EL   leaked cloud key→cloud RCE   GraphQL introspection→full IDOR/authz map
```

---

# REAL-WORLD WINS & REFERENCES

### Q102. Recurring real-world recon→critical wins.
- **Origin IP behind Cloudflare** → bypass WAF, hit the app directly (often unprotected) → everything is easier.
- **Exposed `/.git`/`/.env`/`/actuator/heapdump`/`/swagger.json`/`.DS_Store`** → secrets/source → fast Critical.
- **Dangling CNAME → subdomain takeover** → cookie-scoped ATO / CORS-trust pivot.
- **Verified secret from JS/GitHub/mobile** → cloud key → RCE (JS-files / SSRF kits).
- **GraphQL introspection on** → full schema → IDOR/authz/mutation-abuse map.
- **Forgotten staging/dev sub with no WAF + prod data** → same bugs, no defenses, no dupes.
- **Public/writable cloud bucket** → data exposure / supply-chain (overwrite a served asset).
- **Mobile APK** → staging/internal endpoints + keys the web app never exposed.

### Q103. Resources to work through.
ProjectDiscovery docs (subfinder/httpx/naabu/katana/nuclei); `tomnomnom`'s tooling + talks; **The Bug Hunter's
Methodology (TBHM, Jason Haddix)**; **reconFTW**; OWASP WSTG *Information Gathering*; Shodan/Censys/FOFA query docs;
PayloadsAllTheThings & HackTricks recon notes; Hackviser & PentesterLab recon modules. Read disclosed reports to see how
a recon finding (origin IP / exposed `.git` / takeover / GraphQL) became the Critical.

---

# THE DEFENDER'S VIEW

### Q104. What should a blue team do about recon exposure?
**Asset inventory + attack-surface management** (you can't defend what you don't know you have): continuously enumerate
*your own* surface (the same tools), kill **dangling DNS** (takeover), keep **secrets out of repos/JS/mobile** (CI secret
scanning, rotate leaks), don't expose `.git`/`.env`/`actuator`/source-maps in prod, lock down **cloud buckets**, and
**don't trust the Host/Origin** (host-header/CORS). Monitor for **new** assets the way attackers do.

### Q105. One-paragraph summary you can quote.
*"Recon is attack-surface mapping plus routing: enumerate every domain, subdomain, IP, host, endpoint, parameter, API,
JS file, secret, and cloud asset — going wide via ASN/acquisitions/passive+active subdomains/permutations, then deep on
the interesting hosts via history, content, JS/source-maps, and APIs — and convert each finding into a concrete test
with known impact (login→ATO, /api→IDOR, url=→SSRF, .git→secrets→RCE, dangling CNAME→takeover, template field→SSTI). The
edge isn't a secret tool; it's discipline: configure API keys, keep resolvers/wordlists fresh, hunt the forgotten dev/
staging/admin surface and the leaked secrets where dupes are rare, validate before believing, monitor for new assets to
be first, and spend 80% of your effort on the 20% of surface with a backend, auth, or money behind it."*

---

## APPENDIX — 60-second recon field checklist
```
[ ] Scope: in/out, wildcard?, acquisitions?, ASN?, mobile/API?, automation/rate rules ; pick broad-scope + real backend
[ ] WIDE: org/ASN/acquisitions/favicon → passive subs (API KEYS!) → active (resolve+brute+PERMUTATIONS) → TLS-SAN/reverse-DNS
[ ] PROBE: httpx (status/title/tech/cname/ip, multi-port) → SORT BY INTERESTING ; ports ; ORIGIN-IP (WAF bypass) ; favicon ; vhosts
[ ] DEEP (interesting hosts): wayback/gau→gf-route ; ffuf dirs+ext ; arjun params ; JS+source-maps (validate secrets) ; swagger/GraphQL introspection
[ ] DIRECT probes: /.git /.env /actuator/{env,heapdump} /swagger.json /graphql /.DS_Store
[ ] HIGH-VALUE (early!): takeover (cookie-scope→ATO) · verified secrets (GitHub/JS/mobile) · cloud buckets · exposed git/env · CORS/trust map
[ ] MOBILE: decompile APK/IPA → endpoints/keys/buckets/Firebase ; DORKING: Shodan/Censys cert+favicon, Google/GitHub, Postman/Pastebin
[ ] ROUTE every finding → bug class → impact ; rank by impact × low-dupe ; MONITOR (anew→notify) for NEW surface = first-mover
[ ] STAY IN SCOPE ; benign/read-only proof ; recon is DONE when you have a ranked, routed testing queue
```
*End of guide.*
