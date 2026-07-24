# Recon — Checklist

Expert per-attack **test-case matrix** for Recon — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*16 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## RECON-001 — Scope &amp; select the target
**Test Category:** Scope &amp; Select · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** The program policy

**Test Steps:** 1. Read policy; write in_scope.txt / out_scope.txt.<br>2. Confirm wildcard? acquisitions? ASN? mobile/API in scope? Note banned issue types + rate/automation rules + safe-harbor.<br>3. Pick a worthwhile target (broad scope + real backend + auth/APIs) - a bug on an out-of-scope host pays $0.

**Expected Result:** A clear in/out-of-scope list and a target worth the time.

**Payload Example:**

```
in_scope: *.$D, acquisitions ; out_scope: blog.$D ; automation allowed: Y
```

**Impact:** A brilliant bug out of scope pays nothing and can get you banned - scope first.

**Tools:** program policy

**References:** CWE-200; OWASP Testing Guide: Information Gathering (WSTG-INFO)

---

## RECON-002 — Org expansion (ASN / acquisitions / favicon pivots)
**Test Category:** Go Wide — Assets · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** The organization's wider footprint

**Test Steps:** 1. Expand the org: ASN, reverse-whois, acquisitions, favicon/analytics-ID pivots -&gt; extra root domains.<br>2. Acquisitions/ASN are the least-hunted surface.<br>3. Feed new roots into subdomain enumeration.

**Expected Result:** Additional root domains and IP ranges owned by the org.

**Payload Example:**

```
amass intel -asn <ASN> ; reverse-whois ; favicon hash pivot (Shodan)
```

**Impact:** Org-expansion surface is where your edge over the crowd comes from (least hunted).

**Tools:** amass intel, Shodan, whoisxml

**References:** CWE-200; HackTricks: External Recon Methodology

---

## RECON-003 — Passive subdomain enumeration
**Test Category:** Go Wide — Assets · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** All roots

**Test Steps:** 1. Passive subs: subfinder + amass + crt.sh + chaos (+ GitHub subs), API keys configured.<br>2. Grep the passive list for admin/internal/staging/dev/uat/vpn/jenkins/jira/git/api.<br>3. Include HISTORICAL/CT hosts (dead ones are prime takeover candidates).

**Expected Result:** A broad passive subdomain list with interesting names flagged.

**Payload Example:**

```
subfinder -d $D -all ; crt.sh %.$D ; grep -E 'admin|dev|staging|api'
```

**Impact:** Coverage of forgotten hosts is the cure for duplicate reports.

**Tools:** subfinder, amass, crt.sh, chaos

**References:** CWE-200; HackTricks: External Recon Methodology

---

## RECON-004 — Active subs + permutations
**Test Category:** Go Wide — Assets · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Resolved subdomains

**Test Steps:** 1. Resolve -&gt; DNS brute -&gt; PERMUTATIONS (the high-yield, under-used pass).<br>2. TLS-SAN harvest, recursive enum, internal hostnames from JS/CT, alt-TLD/region.<br>3. Merge -&gt; subs_all.txt (the complete asset list).

**Expected Result:** A complete asset list including permutation-discovered hosts.

**Payload Example:**

```
puredns bruteforce ; gotator/altdns permutations ; merge -> subs_all.txt
```

**Impact:** Permutations + org-expansion are precisely where the uncontested surface is.

**Tools:** puredns, gotator, dnsx

**References:** CWE-200; HackTricks: External Recon Methodology

---

## RECON-005 — Resolve &amp; probe (sort by interesting)
**Test Category:** Resolve &amp; Probe · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** subs_all.txt

**Test Steps:** 1. httpx probe all subs (status/title/tech/cname/ip), multi-port.<br>2. Build live.txt; SORT BY INTERESTING (auth/api/admin/dev/dashboards), not alphabetically.<br>3. Flag 401/403 auth walls (bypass candidates) and 5xx/redirects.

**Expected Result:** A map of live, identified services sorted by interest.

**Payload Example:**

```
httpx -l subs_all.txt -status-code -title -tech-detect -cname -ip
```

**Impact:** Your manual time is finite - it belongs on the hosts with a real backend.

**Tools:** httpx

**References:** CWE-200; PortSwigger / Bug bounty recon methodology (Tomnomnom, Jason Haddix)

---

## RECON-006 — Ports + origin-IP hunt
**Test Category:** Resolve &amp; Probe · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Live hosts; WAF/CDN-fronted hosts

**Test Steps:** 1. naabu top-1000; probe open ports for HTTP; note data-store/dashboard ports.<br>2. Origin-IP hunt where WAF/CDN present (historical DNS / Shodan cert / favicon) -&gt; bypass the WAF later.<br>3. vhost fuzz on shared IPs for no-DNS sites.

**Expected Result:** Open ports mapped and origin IPs found behind the WAF.

**Payload Example:**

```
naabu -top-ports 1000 ; Shodan ssl.cert.subject.cn:$D ; favicon hash
```

**Impact:** The origin-IP trick lets your payloads bypass the WAF later.

**Tools:** naabu, Shodan, ffuf (vhost)

**References:** CWE-200; HackTricks: External Recon Methodology

---

## RECON-007 — URL history + gf routing
**Test Category:** Go Deep · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Interesting hosts only

**Test Steps:** 1. gau/wayback/katana -&gt; urls_all.txt; gf-route to xss/ssrf/redirect/idor/sqli/lfi.<br>2. Extract forgotten sensitive files + ALL historical param names.<br>3. Go deep on the ~50 hosts that matter, never all 5,000.

**Expected Result:** A routed URL/param corpus tagged by candidate bug class.

**Payload Example:**

```
gau $D | gf ssrf ; gf redirect ; extract historical params
```

**Impact:** Routing 'I found 3,000 endpoints' into '40 IDOR/SSRF candidates' is the point of recon.

**Tools:** gau, katana, gf

**References:** CWE-200; PortSwigger / Bug bounty recon methodology (Tomnomnom, Jason Haddix)

---

## RECON-008 — Content discovery + direct sensitive-file probes
**Test Category:** Go Deep · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Interesting hosts

**Test Steps:** 1. ffuf dirs/files (context-matched list); recurse into found dirs.<br>2. Probe direct: /.git /.env /actuator /swagger /graphql /server-status /.DS_Store.<br>3. 403/401 bypass attempts on interesting protected paths.

**Expected Result:** Hidden dirs/files and exposed sensitive endpoints found.

**Payload Example:**

```
ffuf -w list -u https://host/FUZZ ; probe /.git /.env /actuator
```

**Impact:** Exposed /.git or /.env is often a direct Critical - probe every interesting host.

**Tools:** ffuf, feroxbuster

**References:** CWE-200; HackTricks: External Recon Methodology

---

## RECON-009 — Parameter discovery (arjun)
**Test Category:** Go Deep · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Interesting endpoints

**Test Steps:** 1. arjun per endpoint; test high-value names (redirect/url/id/debug/admin/file).<br>2. Feed hidden params into the relevant attack kits (SSRF/IDOR/LFI/OpenRedirect).<br>3. Cross-ref historical param names from URL history.

**Expected Result:** Hidden parameters discovered per endpoint.

**Payload Example:**

```
arjun -u https://host/api/x ; test ?debug= ?admin= ?url= ?file=
```

**Impact:** Hidden params are the injection points other hunters never find.

**Tools:** arjun, param-miner

**References:** CWE-200; HackTricks: External Recon Methodology

---

## RECON-010 — JS analysis + source maps
**Test Category:** Go Deep · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Collected JS bundles

**Test Steps:** 1. Collect bundles; extract endpoints + secrets (jsluice/trufflehog).<br>2. Probe .js.map; reconstruct source where exposed.<br>3. Hand findings to the JS-Files kit for validation.

**Expected Result:** Endpoints/secrets/source recovered from JS (routed to the JS-Files kit).

**Payload Example:**

```
jsluice urls/secrets ; try main.js.map -> reconstruct source
```

**Impact:** JS bundles are the app's blueprint; source maps rebuild the whole thing.

**Tools:** jsluice, trufflehog, LinkFinder

**References:** CWE-200; CWE-540; HackTricks: External Recon Methodology

---

## RECON-011 — API discovery (swagger / GraphQL introspection)
**Test Category:** Go Deep · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** API hosts

**Test Steps:** 1. Find swagger/openapi; test OLD API versions; GraphQL introspection (or clairvoyance).<br>2. Enumerate operations, params, and auth requirements.<br>3. Route to the API/GraphQL/IDOR kits.

**Expected Result:** The API surface (incl. old versions and GraphQL schema) is mapped.

**Payload Example:**

```
curl /swagger.json ; /v1/ vs /v2/ ; GraphQL introspection query
```

**Impact:** Old API versions and GraphQL introspection expose un-hunted surface.

**Tools:** kiterunner, clairvoyance

**References:** CWE-200; HackTricks: External Recon Methodology

---

## RECON-012 — Subdomain takeover sweep
**Test Category:** High-Value (run early) · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** The full subdomain list

**Test Steps:** 1. nuclei/subzy across the full list; check cookie scope -&gt; ATO escalation.<br>2. A takeover can be a Critical in your first hour.<br>3. Hand confirmed danglers to the Subdomain-Takeover kit (claim + trust chain).

**Expected Result:** Dangling/claimable subdomains identified for the takeover kit.

**Payload Example:**

```
subzy run --targets subs_all.txt ; nuclei -tags takeover
```

**Impact:** A fast, clean, low-dupe Critical before you even open the main app.

**Tools:** subzy, nuclei, Subdomain-Takeover kit

**References:** CWE-200; CWE-350; HackTricks: External Recon Methodology

---

## RECON-013 — Secrets hunt (GitHub dorks / trufflehog / verify)
**Test Category:** High-Value (run early) · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Org GitHub, commit history, .tfstate

**Test Steps:** 1. GitHub dorks + trufflehog on org &amp; commit HISTORY; hunt .tfstate.<br>2. VERIFY every secret before believing (most matches are dead keys).<br>3. Route live secrets to the JS-Files/cloud kits.

**Expected Result:** Verified, live secrets from public repos/history.

**Payload Example:**

```
trufflehog github --org=<org> ; GitHub dork 'org:acme AKIA' ; verify with sts
```

**Impact:** A verified leaked key is a first-hour Critical; verify before believing.

**Tools:** trufflehog, gitleaks, GitHub dorks

**References:** CWE-200; CWE-798; HackTricks: External Recon Methodology

---

## RECON-014 — Cloud buckets + exposed git/env/backups
**Test Category:** High-Value (run early) · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Cloud storage, /.git, /.env, backup files

**Test Steps:** 1. cloud_enum/s3scanner; test read (and benign write) on buckets.<br>2. nuclei exposures; git-dumper on any /.git.<br>3. Prove with a benign marker you clean up - never touch real data.

**Expected Result:** Readable/writable buckets and dumped git/env exposures.

**Payload Example:**

```
s3scanner ; git-dumper http://host/.git out/ ; nuclei -tags exposure
```

**Impact:** Open buckets and exposed .git/.env are direct Criticals - benign proof only.

**Tools:** cloud_enum, s3scanner, git-dumper

**References:** CWE-200; HackTricks: External Recon Methodology

---

## RECON-015 — CORS / cookie-trust map + mobile/3rd-party
**Test Category:** High-Value (run early) · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Reflected-origin endpoints; APKs; Jira/Confluence/status pages

**Test Steps:** 1. Reflected-origin CORS test; note .$D cookie/CORS trust (subdomain trust map).<br>2. Mobile deep-mine: decompile APK/IPA (jadx/apktool) -&gt; endpoints/keys/buckets/Firebase RTDB.<br>3. Internet-wide dorking (Shodan/Censys cert-CN + favicon) -&gt; CDN origin IP / exposed panels; Postman/Pastebin/Docker Hub.

**Expected Result:** A trust map and mobile/3rd-party surface routed to the relevant kits.

**Payload Example:**

```
curl -H 'Origin: evil.com' ; jadx APK -> endpoints/keys ; Shodan favicon hash
```

**Impact:** The subdomain trust map + mobile endpoints feed the CORS/SSRF/JWT kits.

**Tools:** jadx, apktool, Shodan, Corsy

**References:** CWE-200; CWE-942; HackTricks: External Recon Methodology

---

## RECON-016 — Route -&gt; impact (the whole point) + discipline
**Test Category:** Route -&gt; Impact · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Every recon finding

**Test Steps:** 1. Convert each host/endpoint into 'test bug class X here because Y', ranked by impact-per-hour.<br>2. Consciously SKIP the time-wasters: info-disclosure noise, dead static hosts, auto-closed issue types.<br>3. Feed the routed surface into the per-attack kits (SSRF/IDOR/XSS/SQLi/...).

**Expected Result:** A prioritized, routed attack plan mapping surface to bug classes.

**Payload Example:**

```
these 40 endpoints -> IDOR ; these headers -> Host-header ; skip the marketing site
```

**Impact:** Recon is worthless until each host becomes a routed, ranked test - this is the payoff.

**Tools:** manual, gf

**References:** CWE-200; PortSwigger / Bug bounty recon methodology (Tomnomnom, Jason Haddix)  |  TOP REFERENCES: Jason Haddix 'The Bug Hunter's Methodology'; ProjectDiscovery toolchain; Tomnomnom; NahamSec; OWASP Amass

---
