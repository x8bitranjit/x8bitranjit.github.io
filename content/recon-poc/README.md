# x8bit_recon — expert bug-bounty recon

An impact-first, single-command recon pipeline for **web bug-bounty hunting**. Takes a
domain to a **routed, prioritized attack surface** and keeps watching for new assets.
The recon companion to **x8bit-arsenal**. Built for **Kali / WSL (bash)**.

> ⚠️ **Authorized testing only.** In-scope assets of a program you may test. Respect
> the program's automation/rate rules (guide §29). Recon **finds** out-of-scope assets
> (CDNs, third parties) — it never **tests** them (active phases are scope-locked to the
> target's own registered domain).

---

## What it does (pipeline)

```
domain
 └─ 01 subdomains   passive (subfinder/amass/chaos/crt.sh) + active (puredns brute,
                    gotator permutations, validated against a TRUSTED resolver list)
 └─ 02 hosts        httpx live probe → live_urls.txt (clean) · naabu ports (deduped IPs) ·
                    asnmap ASN/CIDR · ORIGIN-IP discovery (un-CDN) · wafw00f · gowitness
 └─ 03 urls         gau --subs + waybackurls + katana (all live hosts) → gf bucketing
                    (xss/sqli/ssrf/redirect/idor/lfi/rce/ssti) + interesting files/params
 └─ 04 javascript   subjs → JS bundles · source-map exposure · trufflehog secrets
 └─ 05 findings     Tier-1: nuclei takeovers/exposures/misconfig · subzy ·
                    content-verified path probes (.git/.env/actuator/swagger/graphql)
                    Vuln leads: dalfox XSS + nuclei CVEs (scope-filtered)
 └─ QUEUE.md        auto-generated, routed, impact-first manual-testing queue ← START HERE
```

The **`QUEUE.md`** is the edge: it doesn't just dump data, it tells you *what to test
first* (Tier-1 criticals → APIs/auth → injection candidates → SKIP noise).

---

## Files
| Script | Purpose |
|--------|---------|
| **`x8bit_recon.sh`** | the full pipeline (`recon.sh` is a backward-compatible alias) |
| `monitor.sh` | cron-able: alert on **new** subdomains/exposures/takeovers (first-mover edge) |
| `takeover_check.sh` | dedicated subdomain-takeover sweep (CNAME fingerprints + nuclei + subzy) |
| `origin_ip.sh` | **origin-IP discovery** — find the real server behind a CDN/WAF (multi-source + CDN-filter + TLS-cert/content validation). Runs as a pipeline phase and standalone |
| `js_extract.sh` | deep JS mining: endpoints + internal hosts + secrets + **source maps** |
| `setup.sh` | install Go/PD tools + apt packages + nuclei templates |
| `setup-recon-env.sh` | install puredns/gotator/massdns + fetch resolvers (no sudo) |
| **`config.env`** | your API keys (all optional) — auto-loaded; copy from `config.env.example` |
| `config.env.example` | documented key template (the only config file safe to commit) |
| `wordlists/` | `resolvers.txt` (public, breadth) · `resolvers-trusted.txt` (validation) · `permutations.txt` |

---

## Setup — WSL / Kali (primary environment)

```bash
cd <path>/Web/Recon/scripts          # e.g. /mnt/<drive>/<your-path>/Web/Recon/scripts
chmod +x *.sh

# 1) core tools (subfinder, httpx, dnsx, naabu, nuclei, katana, gau, subzy,
#    dalfox, gowitness, asnmap, wafw00f, gf, anew, unfurl, trufflehog) + templates
bash setup.sh

# 2) DNS brute/permutation engine (puredns + gotator + massdns) + resolvers — no sudo
bash setup-recon-env.sh

# 3) wordlists (SecLists) — Kali ships it; otherwise:
sudo apt install -y seclists        # → /usr/share/seclists  (auto-detected)
```
`x8bit_recon.sh` auto-detects everything: it adds `~/go/bin` to PATH, and finds
resolvers/SecLists/permutations via env → `/opt` → the co-located `wordlists/`.
Missing tools degrade gracefully (the phase is skipped, the run never aborts).

## Setup — Windows

The tool is bash; on Windows you run it **inside WSL** (the Linux tools live there).

```powershell
# one-time: install WSL2 + Kali
wsl --install -d kali-linux
# then open "Kali" from the Start menu and follow the WSL/Kali setup above.
# your drive is mounted under /mnt inside WSL, so the kit is at:
#   /mnt/<drive>/<your-path>/Web/Recon/scripts
```
Run it either **inside the Kali shell** (recommended) or **from PowerShell** via WSL:
```powershell
wsl -d kali-linux bash -lc "cd /mnt/<drive>/<your-path>/Web/Recon/scripts && ./x8bit_recon.sh target.com"
```
> Note: scripts must have **LF** line endings (not CRLF) to run in bash. They ship as
> LF; if Windows tooling rewrites them, fix with `sed -i 's/\r$//' *.sh` in WSL.

---

## API keys (`config.env`) — all optional

One file is the single place for every API key the pipeline can use. The contract:

- **Key missing** → that one source is skipped; the run still completes with full
  results. **You can run with an empty file and nothing breaks.**
- **Key present** → x8bit_recon picks it up automatically for deeper coverage
  (more subdomains, ASN ranges, etc.).

```bash
cp config.env.example config.env     # then edit config.env and paste what you have
```

The script auto-loads `./config.env` (next to `x8bit_recon.sh`). Put it elsewhere with
`X8_CONFIG=/path/to/config.env ./x8bit_recon.sh target.com`. CRLF from a Windows editor
is stripped on load, so editing it in Notepad is fine.

| Key | Unlocks | Get it (free tier) |
|-----|---------|--------------------|
| `PDCP_API_KEY` | **asnmap** (ASN/CIDR ranges) + **chaos** (passive subs). *Without it the ASN phase is skipped — asnmap now only blocks on a key prompt.* | cloud.projectdiscovery.io (or `pdcp -auth`) |
| `VIRUSTOTAL_API_KEY`, `SECURITYTRAILS_API_KEY`, `SHODAN_API_KEY`, `BEVIGIL_API_KEY`, `BINARYEDGE_API_KEY`, `FOFA_KEY`, `CENSYS_API_ID`+`CENSYS_API_SECRET` | extra **subfinder** OSINT sources → more subdomains | each provider's site |
| `GITHUB_TOKEN` | github subdomain/secret sources + higher rate limits | github.com/settings/tokens |

These are routed automatically: `PDCP_API_KEY`/`CHAOS_KEY` are exported for asnmap/chaos,
and any subfinder provider keys are written to a **private temp** provider-config passed via
`-pc` (your global `~/.config/subfinder` is never touched; the temp file is deleted on exit).
The config banner prints which key groups are active (`on`/`-`) at the top of every run.

> `config.env` holds secrets — it's **git-ignored**; only `config.env.example` is tracked.

---

## Run

```bash
./x8bit_recon.sh target.com              # full pipeline → ./output/target.com/
PASSIVE_ONLY=1 ./x8bit_recon.sh target.com   # quiet OSINT-only (no brute/ports/dalfox)
RATE=40 PUREDNS_RATE=80 ./x8bit_recon.sh target.com   # extra-polite for a strict program

# companions (run individually as needed):
./takeover_check.sh target.com           # or: ./takeover_check.sh -l subs_all.txt
./js_extract.sh https://app.target.com   # or: ./js_extract.sh -l hosts.txt
# continuous first-mover monitoring (cron):
#   0 */6 * * *  /path/scripts/monitor.sh target.com >> /path/output/target.com/monitor.log 2>&1
```

## Options (environment variables)
| Var | Default | Effect |
|-----|---------|--------|
| `PASSIVE_ONLY` | `0` | `1` = OSINT-only: skip active DNS brute, port scan, and dalfox (payloads). For tight programs. |
| `RATE` | `150` | requests/sec for httpx / nuclei (politeness). |
| `PUREDNS_RATE` | `150` | DNS qps for the puredns/massdns brute. **Keep low on WSL** — high qps fills the WSL2 NAT conntrack table and kills the network. Raise on native Linux. |
| `RESOLVERS` | auto | path to a public resolvers file (else `/opt/resolvers.txt` → `wordlists/resolvers.txt`). |
| `RESOLVERS_TRUSTED` | auto | small trusted-resolver file used to **validate** brute hits (kills FP subs). |
| `WORDLISTS` | auto | SecLists dir (else `/opt/SecLists` → `/usr/share/seclists`). |
| `X8_CONFIG` | `./config.env` | path to the API-key config file (see **API keys** above). |

> Env vars take effect for that one run. For a permanent default, set `RATE` /
> `PUREDNS_RATE` / `PASSIVE_ONLY` (uncommented) inside `config.env`. API **keys** live
> only in `config.env`.

---

## Output layout (`./output/<domain>/`)
```
subs_all.txt        all discovered subdomains (passive + brute + permutations)
resolved.txt        passive subs that resolve · brute.txt · perm.txt
live.txt            httpx live hosts — annotated (status/title/tech/cname/ip)
live_urls.txt       CLEAN url list (col-1) — fed to nuclei/httpx/subjs
interesting.txt     live hosts filtered to auth/api/admin/dev/etc.   ← start here
authwalls.txt       401/403 hosts (403-bypass + auth/JWT targets)
ports.txt           open ports (naabu, deduped IPs)   asn_ranges.txt   ASN/CIDR (asnmap)
origin_ips.txt      CONFIRMED/LIKELY origin behind the CDN/WAF (cert-validated) ← WAF bypass
origin_candidates.txt  non-CDN IP candidates probed for origin (pre-validation)
waf.txt             WAF fingerprints          screenshots/     gowitness images
urls_all.txt        historical + crawled URLs
cand_*.txt          URLs routed by bug class (xss/ssrf/redirect/sqli/idor/lfi/rce/ssti)
files_interesting.txt  juicy extensions (.json/.bak/.sql/.env/...)   param_names.txt
js_files.txt  jsmaps.txt (source maps!)  js_secrets.txt (verify!)
takeovers.txt       subdomain-takeover candidates (subzy/nuclei, VULNERABLE-only)
exposures.txt       .git/.env/actuator/etc. — content-verified (not bare 200)
nuclei_cves.txt     known CVEs (critical/high) on live hosts
dalfox.txt          reflected/DOM XSS leads (scope-filtered, confirm popup)
QUEUE.md            ← routed, prioritized testing queue. OPEN THIS FIRST.
```

## Tips
- **Start with `QUEUE.md` + `interesting.txt`.** Tier-1 first (takeover/CVE/exposure/XSS), then APIs/auth.
- **Idempotent** (`anew`): re-running surfaces only *new* lines — which `monitor.sh` turns into alerts. New assets = least competition.
- **Stealth:** lower `RATE`/`PUREDNS_RATE`; or `PASSIVE_ONLY=1` for the quietest footprint. The active phases are already scope-locked to the target domain.
- Keep `resolvers.txt` fresh (`setup-recon-env.sh` refetches it). Stale resolvers = missed/false subs.
- After recon, switch to the **XSS / JWT / API / SSRF** exploitation guides (or feed `live_urls.txt` to **x8bit-arsenal**).
