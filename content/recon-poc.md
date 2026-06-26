# Recon — Scripts

An impact-first, single-command recon pipeline for **web bug-bounty hunting** — takes a domain to a
**routed, prioritized attack surface** and keeps watching for new assets. Built for **Kali / WSL (bash)**.
**Click a script to open it on its own page.**

> ⚠️ **Authorized testing only** — in-scope assets of a program you may test. Respect the program's
> automation/rate rules. Recon **finds** out-of-scope assets (CDNs, third parties) but never **tests** them:
> the active phases are scope-locked to the target's own registered domain.

| Script | Purpose |
|---|---|
| [`x8bit_recon.sh`](#/recon/poc/x8bit_recon) | The full pipeline: subdomains → live hosts → URLs → JS mining → findings → routed `QUEUE.md`. |
| [`recon.sh`](#/recon/poc/recon) | Backward-compatible alias / entrypoint for the pipeline. |
| [`monitor.sh`](#/recon/poc/monitor) | Cron-able first-mover watch — alert on **new** subdomains / exposures / takeovers. |
| [`takeover_check.sh`](#/recon/poc/takeover_check) | Dedicated subdomain-takeover sweep (CNAME fingerprints + nuclei + subzy). |
| [`origin_ip.sh`](#/recon/poc/origin_ip) | **Origin-IP discovery** — find the real server behind a CDN/WAF (multi-source + TLS-cert/content validation). |
| [`js_extract.sh`](#/recon/poc/js_extract) | Deep JS mining: endpoints + internal hosts + secrets + **source maps**. |
| [`keys.sh`](#/recon/poc/keys) | API-key / secret hunting helper. |
| [`setup.sh`](#/recon/poc/setup) | Install Go/PD tools + apt packages + nuclei templates. |
| [`setup-recon-env.sh`](#/recon/poc/setup-recon-env) | Install puredns/gotator/massdns + fetch resolvers (no sudo). |
| [`config.env.example`](#/recon/poc/config-env-example) | Documented API-key template — every key optional; the only config safe to commit. |

## Pipeline at a glance
```
domain
 └─ 01 subdomains  passive (subfinder/amass/chaos/crt.sh) + active (puredns brute, gotator perms)
 └─ 02 hosts       httpx live probe · naabu ports · asnmap · ORIGIN-IP (un-CDN) · wafw00f · gowitness
 └─ 03 urls        gau + waybackurls + katana → gf bucketing (xss/sqli/ssrf/redirect/idor/lfi/rce/ssti)
 └─ 04 javascript  subjs · source-map exposure · trufflehog secrets
 └─ 05 findings    nuclei takeovers/exposures/CVEs · subzy · content-verified path probes
 └─ QUEUE.md       auto-generated, routed, impact-first manual-testing queue ← START HERE
```

## Run
```bash
./x8bit_recon.sh target.com                    # full pipeline → ./output/target.com/
PASSIVE_ONLY=1 ./x8bit_recon.sh target.com     # quiet OSINT-only (no brute/ports/dalfox)
RATE=40 PUREDNS_RATE=80 ./x8bit_recon.sh target.com   # extra-polite for a strict program
```

> The edge is **`QUEUE.md`** — it doesn't just dump data, it tells you *what to test first*
> (Tier-1 criticals → APIs/auth → injection candidates → SKIP noise). Read the **Guide** for the full
> methodology and the **Zero to Expert (Q&A)** for the *why* behind each phase.
