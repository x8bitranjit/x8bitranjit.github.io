# HTTP Request Smuggling (HRS) — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any target with a **front-end + back-end** chain (CDN/load-balancer/reverse-proxy/WAF in front of an app server) where the two disagree on **where one request ends and the next begins** — classic CL.TE / TE.CL / TE.TE desync, plus HTTP/2→HTTP/1.1 downgrade desync (H2.CL / H2.TE / CRLF), and client-side desync
**Platforms:** Any stack; Kali/WSL for tooling (Burp + Turbo Intruder + smuggler.py)
**Companion files in this folder:**
- `REQUEST_SMUGGLING_ARSENAL.md` — CL.TE/TE.CL/TE.TE + H2 desync probes, exploitation gadgets, header obfuscations (copy-paste)
- `REQUEST_SMUGGLING_CHECKLIST.md` — the testing-order checklist you tick per host
- `REQUEST_SMUGGLING_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — runnable tooling (timing-based desync detector, CL.TE/TE.CL probe builder, smuggler wrapper notes)

> **Companion to the Host-Header / CORS / SSRF / XSS guides.** Request smuggling is one of the **highest-skill, highest-impact** web classes: by desyncing the front-end and back-end you **prepend bytes onto another user's request**, letting you **hijack victims' requests/sessions, poison the cache for everyone, bypass front-end security controls, and reach internal/admin endpoints.** The mistakes hunters make: (1) **DoS-ing the target** while probing (smuggling probes can knock out real users — discipline matters), and (2) reporting a **timing blip** without a concrete exploit. Read §4 (safe detection) and Part III (turn desync into impact) before you report.

---

> ### ⚡ READ THIS FIRST — why request smuggling is high-impact (and high-responsibility)
> 1. **The bug is a parser disagreement.** The front-end and back-end use **different rules** to compute a request's length (`Content-Length` vs `Transfer-Encoding`, or HTTP/2 length vs the downgraded HTTP/1.1). You exploit the gap to leave a **partial request** that prefixes the **next** connection's request. That prefix is the weapon.
> 2. **Impact comes from what you prepend.** A smuggled prefix can: **capture another user's request** (steal their session/PII), **poison the cache** (mass redirect/XSS to all users), **bypass the front-end WAF/auth** to hit blocked/internal/admin paths, or **turn a reflected/redirect into a stored, victim-targeted attack**. That's where Critical lives (§9–§13).
> 3. **Probe SAFELY — you can break the site.** Smuggling desync can corrupt the shared connection and **affect real users** (errors, mixed responses). Use **timing-based** detection (no socket poisoning) first, test on **your own** connections, keep payloads benign, and avoid high-traffic shared front-ends. Never run a destructive or noisy smuggle against production users (§4/§19).
> 4. **HTTP/2 changed the game.** Even "HTTP/1.1-safe" sites desync on the **HTTP/2→1.1 downgrade** (H2.CL / H2.TE), and via **header/CRLF injection** in HTTP/2. If the edge speaks H2 to you but H1 to the origin, test the downgrade vectors (§7).
> 5. **Confirm before you exploit.** A single odd response can be load/latency. Confirm a desync with the **canonical timing test** and a **differential** (the smuggled prefix changes a *follow-up* request deterministically), then build the specific exploit (§4/§8).
>
> **Where the money is (memorize this order):** ① **request hijacking / session capture (steal victims' auth) — Critical** → ② **cache poisoning via smuggling → mass XSS/redirect — High–Critical** → ③ **front-end WAF/auth bypass → reach internal/admin (→ RCE/cloud via the reached endpoint) — High–Critical** → ④ **smuggle-to-stored XSS / response-queue poisoning — High** → ⑤ *then* a confirmed-but-unexploited desync as **Medium**, and a bare timing blip as **not yet a finding**.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [Smuggling Anatomy — Why Front-End/Back-End Desync](#2-smuggling-anatomy)
3. [Reconnaissance — Find Front-End/Back-End Chains](#3-reconnaissance--find-frontendbackend-chains)
4. [Baseline — Detect a Desync SAFELY (timing first)](#4-baseline--detect-a-desync-safely)

**PART II — DESYNC TECHNIQUES (work in this order)**
5. [CL.TE & TE.CL (HTTP/1.1 classic)](#5-clte--tecl)
6. [TE.TE (obfuscating Transfer-Encoding)](#6-tete--obfuscating-transfer-encoding)
7. [HTTP/2 Desync (H2.CL / H2.TE / CRLF / downgrade)](#7-http2-desync)
8. [Confirming & Tuning the Desync (differential)](#8-confirming--tuning-the-desync)

**PART III — EXPLOITATION BY IMPACT (where the money is)**
9. [Request Hijacking / Capturing Another User's Request](#9-request-hijacking)
10. [Bypassing Front-End Security Controls (WAF / auth / internal)](#10-bypassing-front-end-controls)
11. [Web-Cache Poisoning via Smuggling → Mass XSS/Redirect](#11-cache-poisoning-via-smuggling)
12. [Smuggle → Stored/Reflected XSS & Response-Queue Poisoning](#12-smuggle--stored-xss--response-queue-poisoning)
13. [Reaching Internal/Admin → SSRF-like → RCE/Cloud](#13-reaching-internaladmin--rcecloud)

**PART IV — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
14. [The Validity-First Mindset](#14-the-validity-first-mindset)
15. [False Positives — STOP reporting these](#15-false-positives--stop-reporting-these-auto-reject-list)
16. [Severity Calibration](#16-severity-calibration--how-triagers-really-rate-smuggling)
17. [Impact-Escalation Playbooks — "you found X, now do Y"](#17-impact-escalation-playbooks--you-found-x-now-do-y)
18. [Building a Professional, Safe PoC (do no harm)](#18-building-a-professional-safe-poc)
19. [Reporting, CWE/CVSS & De-duplication](#19-reporting-cwecvss--de-duplication)
20. [Automation & Red-Team Notes](#20-automation--red-team-notes)

**Appendices**
- [Appendix A — Smuggling Workflow Cheat Sheet](#appendix-a--smuggling-workflow-cheat-sheet)
- [Appendix B — Smuggling Decision Tree](#appendix-b--smuggling-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Numbered sections (1–20) are reference detail; this is the order you execute.

```
PHASE 0  RECON            → find front-end+back-end chains (CDN/LB/proxy → origin); note H1 vs H2 to you/origin (§3)
PHASE 1  BASELINE  ★      → detect a desync SAFELY: TIMING test first (no socket poisoning), then a differential (§4)
PHASE 2  TECHNIQUE        → identify the desync class: CL.TE/TE.CL (§5) · TE.TE obfuscation (§6) · HTTP/2 downgrade (§7)
PHASE 3  CONFIRM          → prove it deterministically (the smuggled prefix changes a FOLLOW-UP request) (§8)
PHASE 4  IMPACT  ⭐ (money)→ build the exploit:
                            request hijacking/session capture (§9) · WAF/auth bypass → internal/admin (§10) ·
                            cache poisoning → mass XSS (§11) · smuggle→stored XSS / queue poisoning (§12) ·
                            internal/admin → SSRF-like → RCE/cloud (§13)
PHASE 5  VALIDATE→REPORT  → validity (§14) · false-positive filter (§15) · severity+CVSS+CWE-444 (§16) ·
                            SAFE PoC: do-no-harm, own connections, benign (§18) · dedup (§19) · report template
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon.** Identify hosts with a **front-end + back-end** chain and note protocols (H1/H2 to you, H1 to origin) (§3). *Deliverable:* candidate chained hosts.
2. **PHASE 1 — Baseline ⭐.** Detect a desync **safely** with the timing test, then a differential — without poisoning shared connections (§4). *Deliverable:* a safely-confirmed desync signal.
3. **PHASE 2 — Technique.** Pin the class: CL.TE/TE.CL (§5), TE.TE obfuscation (§6), or HTTP/2 downgrade/CRLF (§7). *Deliverable:* the working desync primitive.
4. **PHASE 3 — Confirm.** Prove it deterministically: the smuggled prefix changes a **follow-up** request (your own) in a predictable way (§8). *Deliverable:* a reproducible, controlled desync.
5. **PHASE 4 — Impact ⭐.** Build the concrete exploit — request hijacking (§9), front-end control bypass to internal/admin (§10), cache poisoning (§11), smuggle-to-XSS/queue poisoning (§12), internal→RCE/cloud (§13) — **without harming real users**. *Deliverable:* a demonstrated impact.
6. **PHASE 5 — Validate → report.** Apply validity & FP filters (§14/§15), set CVSS/CWE-444 (§16), build a *do-no-harm* PoC (§18), de-dup, write it (§19). *Deliverable:* the submitted report.

Reference anytime: payloads → `REQUEST_SMUGGLING_ARSENAL.md`; checklist → `REQUEST_SMUGGLING_CHECKLIST.md`; scripts → `poc/`; playbooks **§17**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

| Tool | Job |
|------|-----|
| **Burp Suite** (Repeater w/ "raw"/HTTP1, Turbo Intruder) | craft byte-exact requests; **disable** auto-`Content-Length`/`Connection` fixes; the core tool |
| **HTTP Request Smuggler (BApp, Burp)** | automated desync detection + exploitation scaffolding (use carefully) |
| **smuggler.py** (defparam) | CL/TE permutation scanner from the CLI |
| **Turbo Intruder** | the engine for the canonical CL.TE/TE.CL/timing PoCs (Python scripts) |
| **`poc/desync_timing.py`** | safe timing-based desync detector (no socket poisoning) |
| **`poc/build_smuggle.py`** | build byte-exact CL.TE / TE.CL / TE.TE raw requests |
| **interactsh / Burp Collaborator** | OOB confirmation when smuggling reaches a fetch/internal endpoint |
| **curl --http1.1 / nghttp / h2 tools** | test HTTP/2 vs HTTP/1.1 behavior and the downgrade |

```bash
# Kali/WSL
python3 poc/desync_timing.py -u https://target/        # SAFE timing detection first
python3 smuggler/smuggler.py -u https://target/        # CL/TE permutations
# Burp: "HTTP Request Smuggler" extension + Turbo Intruder for the byte-exact PoC.
```
> **Byte-exactness is everything.** You must control raw bytes: exact `Content-Length`, real `\r\n`, no client auto-fixups. Use Burp Repeater in **HTTP/1** "raw" mode (turn off "Update Content-Length" when needed) or Turbo Intruder. A normal HTTP client will "helpfully" rewrite your headers and kill the desync.

> **Windows:** drive Burp/Turbo Intruder on Windows; run the Python `poc/` helpers and smuggler.py in **WSL**.

---

# 2. Smuggling Anatomy

## 2.1 What it is
Two servers in a chain reuse a TCP connection (keep-alive). If they **measure request length differently**, the front-end forwards bytes the back-end interprets as the **start of the next request**. You "smuggle" a prefix that attaches to whatever request comes next on that connection — often **another user's**.

## 2.2 The length-disagreement classes
```
CL.TE  → Front-end uses Content-Length; Back-end uses Transfer-Encoding (chunked). 
TE.CL  → Front-end uses Transfer-Encoding; Back-end uses Content-Length.
TE.TE  → Both support TE, but one is tricked by an OBFUSCATED Transfer-Encoding header into ignoring it.
H2.CL / H2.TE → HTTP/2 has an explicit length; on DOWNGRADE to HTTP/1.1 the injected CL/TE desyncs the origin.
CRLF / H2 → header or pseudo-header CRLF injection in HTTP/2 splits the downgraded request.
CL.0 / client-side desync → back-end ignores the body (treats CL as 0) → the body becomes the next request.
```

## 2.3 Where chains exist
```
□ Any CDN/WAF/LB/reverse-proxy in front of an app: Cloudflare/Akamai/Fastly/CloudFront/nginx/HAProxy/ALB → origin.
□ "Server" / "Via" / "X-Cache" / CDN headers in responses signal a front-end.
□ Keep-alive connections (Connection: keep-alive / HTTP/2) — required for the next-request attachment.
□ Mismatched HTTP versions (H2 edge, H1 origin) → downgrade desync surface.
```

## 2.4 Why it pays
- **Cross-user impact** — you affect *other* users' requests/responses, not just your own: session theft, mass cache poisoning.
- **Control bypass** — the front-end's WAF/auth/path rules are evaluated on *your* visible request, while the smuggled prefix reaches the back-end **unfiltered** → internal/admin/blocked paths.
- **Amplification** — one smuggle can poison a cache or a response queue affecting many users at once.

> **The mental model:** request smuggling is **lying to two parsers at once** so a piece of your request becomes the front of someone else's. Severity = whose request you prepend to and what you make the back-end do.

---

# 3. Reconnaissance — Find Front-End/Back-End Chains

```
□ Identify a front-end: Server/Via/X-Cache/CF-RAY/X-Served-By headers, CDN behavior, error pages, edge IPs.
□ Confirm keep-alive: Connection: keep-alive (HTTP/1.1) or HTTP/2 (always multiplexed).
□ Map protocols: do you speak HTTP/2 to the edge? does the edge speak HTTP/1.1 to the origin? (downgrade surface, §7)
□ Find a "reflection" endpoint: one whose response echoes part of the request (helps confirm capture, §9).
□ Find restricted paths: /admin, internal-only, WAF-blocked paths (targets for control bypass, §10).
□ Find cacheable pages: for cache-poisoning amplification (§11).
□ Note POST endpoints that accept arbitrary bodies (the smuggle carrier).
```
> **If this → then that:** response headers show a **CDN/proxy** (CF-RAY, Via, X-Cache) → there's a front-end+back-end chain → smuggling is in scope; run the safe timing test (§4). You speak **HTTP/2** to the edge → prioritise the **downgrade** vectors (§7), which hit many "HTTP/1-safe" targets.

---

# 4. Baseline — Detect a Desync SAFELY (timing first)

**Do this carefully — bad probes harm real users.** Start with **timing** (doesn't poison the shared socket), then confirm with a controlled differential on **your own** follow-up.

## 4.1 The safe timing test (CL.TE / TE.CL)
The idea: craft a request where, **if** the back-end uses the "wrong" length, it **waits** for bytes that never come → a measurable delay; if not, it returns fast. (Turbo Intruder / `poc/desync_timing.py` implement the canonical PortSwigger timing probes.)
```
CL.TE timing:  send headers with Transfer-Encoding: chunked and a Content-Length that makes the back-end wait
               for more chunked data → DELAY indicates the back-end honored TE while the front-end honored CL.
TE.CL timing:  the mirror. A consistent, repeatable delay (vs a fast baseline) = a desync signal.
```
> **Why timing first:** it does **not** leave a dangling prefix on the connection, so it won't corrupt the next real user's request. Only after timing suggests a desync do you move to a **controlled** confirmation (§8) on connections you isolate.

## 4.2 Differential confirmation (controlled, your own follow-up)
```
Send the smuggle, then IMMEDIATELY send YOUR OWN benign follow-up on a connection you control. If your follow-up gets
a response that proves the prefix attached (e.g., a 404/redirect for a path only your smuggled prefix specified, or
your follow-up is "poisoned" by your own prefix), the desync is confirmed — without touching other users.
```

## 4.3 Note what you'll need next
- **Which class** (CL.TE/TE.CL/TE.TE/H2) the timing/diff indicates → §5–§7.
- **Front-end protocol** (H1/H2) → whether to use downgrade vectors (§7).
- **A reflection or restricted path** → which exploit to build (§9/§10).

> **Don't report a timing blip alone.** Timing *suggests* a desync; it can also be load/latency. Confirm with a **deterministic differential** (§8) and then build a concrete exploit (§9–§13). A confirmed-but-unexploited desync is ~Medium; the bounty is the exploit.

---

# PART II — DESYNC TECHNIQUES (work in this order)

> Full byte-exact templates are in `REQUEST_SMUGGLING_ARSENAL.md`. Use Burp/Turbo Intruder for exact bytes.

# 5. CL.TE & TE.CL

```
CL.TE (front-end: Content-Length; back-end: chunked):
  POST / HTTP/1.1
  Host: target
  Content-Length: 6
  Transfer-Encoding: chunked

  0

  G            ← front-end forwards 6 bytes ("0\r\n\r\nG"); back-end sees the chunked "0" terminator,
                 leaves "G" as the start of the NEXT request → "G" prefixes the victim's request.

TE.CL (front-end: chunked; back-end: Content-Length):
  POST / HTTP/1.1
  Host: target
  Content-Length: 4
  Transfer-Encoding: chunked

  5c
  GPOST / HTTP/1.1 ...(a full smuggled request)...
  0

  (front-end uses chunked and forwards everything; back-end uses CL:4 and treats the rest as a new request)
```
> **If this → then that:** the timing test pointed at CL.TE → use the CL.TE template and confirm your prefix attaches (§8). TE.CL is the mirror; it's trickier (you embed a whole second request sized by the back-end's CL). Pick the one the detection indicated; don't fire both blindly at production.

---

# 6. TE.TE — Obfuscating Transfer-Encoding

Both ends support `Transfer-Encoding`, but you **obfuscate** the header so only **one** end honors it → it degrades to CL.TE or TE.CL.
```
Transfer-Encoding: xchunked
Transfer-Encoding : chunked          (space before colon)
Transfer-Encoding:\tchunked          (tab)
Transfer-Encoding: chunked\r\n  (then a second) Transfer-Encoding: x
X: X\nTransfer-Encoding: chunked     (header folding)
Transfer-Encoding\n: chunked
Transfer-Encoding: "chunked"
Content-Length: 5\r\nTransfer-Encoding: chunked   (both present → which wins?)
```
> **If this → then that:** both ends seem TE-aware (no plain CL.TE/TE.CL) → try the **TE obfuscations**: whichever one makes the front-end *or* back-end ignore `Transfer-Encoding` creates the desync. The space-before-colon and tab variants are the most productive.

---

# 7. HTTP/2 Desync (H2.CL / H2.TE / CRLF / downgrade)

When the edge speaks **HTTP/2** to you but **HTTP/1.1** to the origin, the edge **downgrades** your request — and your injected length/CRLF desyncs the origin.
```
H2.CL:  include a Content-Length in the H2 request that disagrees with the actual body → on downgrade, the origin
        uses your CL and mis-frames the next request.
H2.TE:  smuggle a Transfer-Encoding header via H2 → ignored in H2 but HONORED by the H1 origin after downgrade.
CRLF in H2 header values / pseudo-headers:  inject \r\n into an H2 header value → splits into extra H1 headers/requests
        on downgrade (e.g., a header value containing "foo\r\nTransfer-Encoding: chunked").
:path / :method smuggling, header-name CRLF, etc.
```
> **If this → then that:** the target serves **HTTP/2** at the edge → test the **downgrade** vectors even if HTTP/1.1 smuggling failed; many modern, "patched" sites are still vulnerable via H2.CL/H2.TE/CRLF. Burp's HTTP Request Smuggler has dedicated HTTP/2 probes — use them carefully.

## 7.1 CL.0 / 0.CL desync (the back-end/front-end ignores Content-Length)
A whole class where **one tier treats the body as 0** even though a `Content-Length` is present — so the body becomes the next request:
```
CL.0: the BACK-END ignores Content-Length on certain endpoints (static files, redirects, some GETs/OPTIONS) → it
      treats the body as empty → your body is parsed as the START of the next request on the connection.
      POST /static/x.js HTTP/1.1  Host: t  Content-Length: 34  \r\n\r\n  GET /admin HTTP/1.1\r\nFoo: bar
      If the back-end ignores CL on /static, "GET /admin" runs as the next request.
0.CL: the mirror — the FRONT-END ignores CL (treats as 0) but the back-end honors it.
```
Target endpoints that "shouldn't" have a body (static assets, 301/302 redirectors, health checks) — they're the most likely to ignore `Content-Length`.

## 7.2 Client-side desync (CSD) — browser-powered, no front-end needed
PortSwigger's "browser-powered request smuggling." Some servers can be desynced by the **victim's own browser** via a cross-origin `fetch()` with keep-alive — **no proxy/front-end required**:
```
□ The server has a CL.0-style desync reachable over a normal connection. An attacker page makes the victim's browser
  send a poisoned request whose trailing bytes prefix the victim's NEXT same-connection request → request hijack /
  stored-XSS-from-self / credential capture — all triggered by the victim visiting the attacker's page.
□ Test with the "Browser-Powered Request Smuggling" methodology (PortSwigger) + Burp's scanner; confirm in a browser.
```
This is powerful (it reaches victims directly) and dangerous — demonstrate on your **own** browser/session only.

## 7.3 Connection-state attacks (first-request routing / first-request validation)
Not framing desync at all — the bug is that the front-end applies **per-connection** decisions only to the **first** request and reuses them for the rest:
```
□ First-request ROUTING: the front-end picks the backend from the FIRST request's Host/SNI, then routes ALL later
  requests on that connection the same way. Send request #1 to an allowed vhost, then request #2 (same connection)
  with Host: internal-only → it's routed to the internal backend. (Needs connection reuse — HTTP/1.1 keep-alive / H2.)
□ First-request VALIDATION: the front-end authenticates/validates only the first request; subsequent requests on the
  connection inherit that trust → smuggle privileged requests after a benign first one.
```
> **If this → then that:** the edge speaks HTTP/1.1 to you with keep-alive (or HTTP/2) → also test **CL.0** (body-as-next-request on static/redirect endpoints), **client-side desync** (browser-powered, reaches victims), and **connection-state** attacks (first-request routing/validation) — these hit many targets that survive classic CL.TE/TE.CL. Burp's "HTTP Request Smuggler" + the browser scanner cover them; do-no-harm applies (§18).

## 7.4 TE.0, CL.CL, request tunnelling & pause-based desync (the 2022–2024 variants)
The newest classes — test these when the classics are patched but you still see HTTP/1.1 keep-alive / HTTP/2:
```
TE.0:   the mirror of CL.0 for Transfer-Encoding — one tier honors `Transfer-Encoding: chunked`, the other treats
        the body as 0/ignores TE (common on the SAME static/redirect/OPTIONS endpoints as CL.0). Your chunked body's
        trailing bytes become the next request. Test exactly like CL.0 but with a (possibly obfuscated) TE header.
CL.CL:  both tiers see Content-Length but DISAGREE on the value (duplicate `Content-Length: 6` / `Content-Length: 5`,
        or CL with leading zeros/whitespace one side trims) → the shorter view leaves trailing bytes = the next request.
        Rare and finicky, but real where a parser dedups/normalizes CL differently than its peer.
Request tunnelling: when a true desync isn't reusable across users, you can still TUNNEL a second request to the
        back-end inside your own connection (front-end forwards your "body" verbatim) → read an internal-only response
        in YOUR response. Use it for blind SSRF-to-internal / header reflection even without victim impact.
        Indicators: the front-end blindly forwards a prefixed request; you see TWO responses concatenated for one send.
Pause-based desync (browser-powered, Kettle 2024): induce a desync by PAUSING mid-request — send headers + part of the
        body, stall, and exploit servers that flush/forward early or apply a read timeout that splits the message. Some
        CDNs/origins desync only under the pause condition (and it's reachable from a victim browser via fetch streams).
```
> **If this → then that:** classic CL.TE/TE.CL/H2.* are patched but you still have keep-alive/H2 → run the **second wave**: **TE.0** (chunked-as-next on the same body-less endpoints as CL.0), **CL.CL** (duplicate/ambiguous `Content-Length`), **request tunnelling** (read an internal response inside your own connection — blind-SSRF-grade impact even with no victim), and **pause-based desync** (timing/streaming-induced). Confirm with the deterministic timing-first method (§4/§8) and **do no harm** (§18) — these still carry the full smuggling impact (cache poisoning, auth bypass, internal reach → §11–§13).

---

# 8. Confirming & Tuning the Desync (differential)

```
□ Deterministic proof (your own connection): smuggle a prefix that requests a path with a UNIQUE, distinguishable
  response (e.g., a 404 for /smuggle-<rand>, or a redirect), then send your benign follow-up and observe your
  follow-up receiving that distinctive response → the prefix attached. Repeat to confirm reliability.
□ Tune lengths: adjust Content-Length / chunk sizes byte-by-byte until the prefix is exactly the bytes you want.
□ Measure reliability: how often does it land? (connection pooling/round-robin affects which back-end you hit.)
□ Isolate: do this on connections you control; avoid leaving dangling prefixes that a real user could pick up.
```
> **If this → then that:** your follow-up reliably receives the response meant for your **smuggled prefix** → the desync is **confirmed and controllable**. Now choose the exploit by what the target offers: a reflection endpoint → request capture (§9); a WAF/blocked path → control bypass (§10); a cache → poisoning (§11).

---

# PART III — EXPLOITATION BY IMPACT (where the money is)

> **Do no harm.** Every exploit here can affect real users; demonstrate with **benign** prefixes, **your own** accounts/connections, and the **minimum** needed to prove impact. Never run a sustained or destructive smuggle against production traffic (§18).

# 9. Request Hijacking / Capturing Another User's Request

The crown jewel: prepend a prefix that makes the back-end **store or reflect the *next* (victim's) request** — capturing their headers (cookies/auth) or body.
```
Technique: smuggle a request to an endpoint that STORES or REFLECTS the request (a comment/feedback/search-log/
profile field). The victim's in-flight request gets appended to your smuggled body and ends up stored/reflected.
Result: you read the victim's Cookie/Authorization/CSRF token/PII out of the stored/reflected content → session theft → ATO.
SAFE PoC: capture YOUR OWN second request (a separate session you control) to prove capture, then describe the
cross-user impact — don't harvest real victims' data.
```
> **If this → then that:** there's an endpoint that **stores/reflects the raw request** (search history, comments, an echo) → smuggle into it so the **victim's** subsequent request is captured there → you read their session cookie → **account takeover (Critical)**. Prove it by capturing your *own* second session, not a real user's.

---

# 10. Bypassing Front-End Security Controls (WAF / auth / internal)

The front-end enforces WAF rules, auth, and path restrictions on the **request it sees** — but the **smuggled** prefix reaches the back-end **unfiltered**.
```
□ WAF bypass: the front-end blocks an attack (SQLi/XSS/path); smuggle the malicious request to the back-end past it.
□ Auth/path bypass: front-end blocks /admin or requires auth; smuggle a request to /admin that the back-end serves
  (the front-end never saw it) → access restricted/internal functionality.
□ Internal-only endpoints: reach back-end paths the edge would never route (health, debug, internal APIs).
```
> **If this → then that:** the front-end **blocks `/admin`** or a WAF blocks your payload → smuggle the request so only the **back-end** processes it → you reach admin/internal or land your blocked payload. This converts smuggling into **access control / WAF bypass**, often High–Critical depending on what the back-end then exposes (§13).

---

# 11. Web-Cache Poisoning via Smuggling → Mass XSS/Redirect

Combine smuggling with the cache to serve a malicious response to **everyone**.
```
□ Smuggle a request whose RESPONSE (a redirect/XSS/attacker content) gets cached under a popular URL's key → every
  user requesting that URL gets the poisoned response. (Smuggling provides the "response splitting"/desync to
  associate your malicious response with a victim URL.)
□ Or smuggle to control the response that the cache stores for a normal page → mass redirect to evil.com / stored XSS.
```
> **If this → then that:** the chain has a **cache** → smuggling can poison it at scale: one request stores your XSS/redirect under a real URL → **mass compromise** (High–Critical). Cross-ref the cache-poisoning material in the **Host-Header kit §12**; smuggling is another route to the same mass-impact outcome.

---

# 12. Smuggle → Stored/Reflected XSS & Response-Queue Poisoning

```
□ Response-queue poisoning: desync so responses and requests get OUT OF SYNC on the connection — a victim receives
  the response intended for YOUR request (which can contain your content / a redirect / their own leaked data),
  and you can receive theirs. Powerful and dangerous — demonstrate minimally.
□ Smuggle-to-stored-XSS: prefix a request to a stored-content endpoint with an XSS payload so it's stored and served
  to other users (turns a self-XSS or a reflected XSS into a victim-delivered one).
□ Turn a reflected XSS that needs a header you can't set in a victim's browser into a smuggled, victim-delivered XSS.
```
> **If this → then that:** you can desync the **response queue** → a victim gets your response (or you get theirs) → session/data leakage and forced content. This is among the most severe outcomes; prove it with your **own** two connections and stop — it's easy to disrupt real users here (§18).

---

# 13. Reaching Internal/Admin → SSRF-like → RCE/Cloud ⭐

The control-bypass (§10) often lands you at back-end endpoints that are themselves exploitable — that's where smuggling reaches **RCE/cloud**.
```
□ Smuggle to an internal/admin endpoint that has a code-exec/upload/deploy/template feature → web shell / RCE. CRITICAL
□ Smuggle to a back-end SSRF/fetch endpoint (or one that reaches 169.254.169.254) → cloud metadata IAM creds →
  cloud takeover / a cloud run-command surface → REMOTE SHELL. CRITICAL  (hand off to the SSRF kit §11/§13.)
□ Smuggle past the WAF to deliver an SQLi/SSTI/command-injection payload the edge was blocking → RCE via that bug. CRITICAL
□ Request-hijack an ADMIN's session (§9) → use admin functionality → code execution. CRITICAL
```
> **The smuggling→RCE rule:** smuggling is "only" a desync until the **endpoint you newly reach** (or the **session you hijack**) grants code execution. Always ask "**what does the back-end let me do now that the front-end can't stop?**" — a reachable internal admin (→ code-exec feature), a back-end SSRF to metadata (→ cloud shell), or a WAF-bypassed injection (→ RCE) turns a desync into a **Critical RCE chain**. Prove the shell on your own tenant/account, validate creds read-only, and stop (§18).

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 14. The Validity-First Mindset

## 14.1 The four questions a triager asks (answer them in your report)
1. **Is there a real, controllable desync?** Show the **timing** signal *and* a **deterministic differential** (your follow-up receives the smuggled-prefix's response) — not a one-off blip.
2. **What concrete impact?** Request/session capture, WAF/auth bypass to a sensitive endpoint, cache poisoning, response-queue poisoning → name and demonstrate it (safely).
3. **What does the attacker need?** Usually just the ability to send raw requests to the edge → low bar, cross-user impact = high severity.
4. **Reproducible & in scope?** The exact byte-level request(s), the desync class, and the controlled evidence.

## 14.2 The "timing blip vs exploit" rule (most important)
| You have | Standalone verdict | Becomes valuable when… |
|---|---|---|
| A single odd/slow response | Nothing | …it's a repeatable timing signal **and** a differential confirms it (§4/§8). |
| Confirmed, controllable desync, no exploit | **Medium** | …you build request-capture / control-bypass / cache-poisoning (§9–§13). |
| WAF/auth bypass to a sensitive endpoint | **High** | …the endpoint yields data/admin/RCE (§10/§13). |
| Request/session capture | **Critical** | …you capture auth (own-account proof) → ATO (§9). |
| Cache/response-queue poisoning | **High–Critical** | …it affects other users (mass XSS/redirect/leak) (§11/§12). |

## 14.3 Production-scope discipline
Confirm and exploit with **minimal, benign** payloads on **your own** connections/accounts; never run sustained smuggles against live traffic. Re-test partial fixes (HTTP/1.1 patched but HTTP/2 downgrade still desyncs is a fresh valid finding). Many programs explicitly want smuggling reported **without** mass exploitation — respect that.

---

# 15. False Positives — STOP reporting these (auto-reject list)

| # | Commonly mis-reported | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **A single slow/odd response** | Load/latency/jitter, not a desync. | Repeatable timing + a deterministic differential (§4/§8). |
| 2 | **"smuggler.py flagged it"** with no confirmation | Tools false-positive heavily here. | You reproduce a controlled differential by hand. |
| 3 | **A desync you can't make deterministic** | Unreliable = unproven. | You show the prefix attaches predictably (§8). |
| 4 | **400/errors from malformed requests** | The server **rejecting** bad framing is correct behavior. | A genuine parser disagreement that you exploit. |
| 5 | **Confirmed desync, but reported as Critical with no exploit** | Severity needs the impact. | You build capture/bypass/poisoning (§9–§13). |
| 6 | **Self-only effects (your own request to yourself)** | No cross-user/security impact. | Cross-user capture, cache, or control bypass. |
| 7 | **"CL and TE both present" with no demonstrated split** | Headers alone aren't a vuln. | An actual desync results from it. |
| 8 | **Behavior that disappears on retest** | Not reproducible. | Consistent across multiple controlled trials. |

> Rule of thumb: if you can't show **a deterministic, controllable desync AND a concrete exploit (or at least reliable cross-connection effect)**, you have a **timing anomaly, not request smuggling.** Confirm deterministically and build the exploit — safely — before reporting.

---

# 16. Severity Calibration — how triagers really rate smuggling

| Scenario | Typical | What moves it |
|---|---|---|
| **Request/session capture → steal auth → ATO** | **Critical** | Cross-user session theft. |
| **Response-queue poisoning (victims get wrong responses)** | **Critical** | Mass data leakage / forced content. |
| **Smuggle → internal/admin → RCE/cloud** | **Critical** | Code execution via the reached endpoint (§13). |
| **Cache poisoning via smuggling → mass XSS/redirect** | **High–Critical** | Affects all users of the URL. |
| **Front-end WAF/auth bypass to a sensitive endpoint** | **High** | What the endpoint exposes. |
| **Confirmed, controllable desync, no exploit built** | **Medium** | Up sharply once you build any impact above. |
| **Timing signal only / tool flag** | **— (not a finding)** | Confirm deterministically first. |

**CVSS / CWE:**
- Request smuggling → capture/poisoning: `AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H`-ish → High–Critical. **CWE-444** (Inconsistent Interpretation of HTTP Requests / "HTTP Request Smuggling").
- Add outcome CWEs: CWE-79 (XSS via cache/stored), CWE-384 (session), CWE-918/CWE-94 if you reach SSRF/RCE.

---

# 17. Impact-Escalation Playbooks — "you found X, now do Y"

### 17.1 You found: *a timing signal suggesting CL.TE/TE.CL*
- **Escalate:** confirm with a **deterministic differential** on your own connection (§8). Identify the class (§5).
- **Evidence:** your follow-up reliably receiving the smuggled prefix's response.
- **Severity:** Medium (confirmed) → climbs with an exploit.

### 17.2 You found: *a confirmed, controllable desync*
- **Escalate:** pick the exploit by what's available — reflection/store endpoint → **request capture** (§9); WAF/blocked path → **control bypass** (§10); cache → **poisoning** (§11).
- **Evidence:** the concrete impact (own-account capture / bypassed access / poisoned cache entry).
- **Severity:** High–Critical.

### 17.3 You found: *HTTP/2 at the edge, H1 origin*
- **Escalate:** test **H2.CL / H2.TE / CRLF** downgrade vectors even if H1 smuggling failed (§7).
- **Evidence:** a confirmed downgrade desync.
- **Severity:** as the exploit you then build.

### 17.4 You found: *a WAF/auth bypass via smuggling*
- **Escalate:** reach **internal/admin** and exploit what's there — code-exec feature, SSRF→metadata, or a WAF-bypassed injection → **RCE** (§13).
- **Evidence:** the admin/internal action / RCE marker (own tenant).
- **Severity:** **Critical**.

### 17.5 You found: *the ability to capture requests*
- **Escalate:** capture an **auth-bearing** request (your own second session for PoC) → demonstrate session theft → ATO (§9).
- **Evidence:** the captured cookie/token (own session, redacted).
- **Severity:** **Critical**.

---

# 18. Building a Professional, Safe PoC (do no harm)

```
DO:
  □ Detect with TIMING first (no socket poisoning). Confirm with a DETERMINISTIC differential on connections you control.
  □ Use BENIGN smuggled prefixes (a request to a harmless/unique path; a marker), and your OWN second session/connection
    to demonstrate capture — never harvest real users' requests/sessions.
  □ For cache/queue poisoning: prove on a NON-shared/unique key or your own client, then DESCRIBE the mass impact.
    Do not poison high-traffic shared entries that serve real users.
  □ Keep it short and low-volume; clean up; verify the connection state is restored.
  □ Capture: the exact byte-level request(s), the desync class, and the controlled evidence (timing + differential + impact).
DON'T:
  □ Run sustained/automated smuggles against production — you WILL disrupt real users (errors, mixed responses).
  □ Capture or read other users' sessions/data to "prove" it (own-session capture is enough).
  □ Leave dangling prefixes on shared connections; don't poison shared caches/queues with live payloads.
  □ Report a timing blip or a tool flag as a confirmed Critical.
```
> The single most important restraint: **request smuggling can break the site for real users — confirm with timing, exploit on your own connections with benign markers, prove the *capability*, and stop.** Do-no-harm is part of a valid PoC here more than in any other class.

**Remediation to include:** make the front-end and back-end agree on request framing — **normalize/reject** ambiguous requests (both `Content-Length` and `Transfer-Encoding`, obfuscated `TE`, invalid chunking) at the edge; prefer **HTTP/2 end-to-end** (don't downgrade to HTTP/1.1) and reject CRLF/invalid header values in H2; use the **same parser** or strict RFC parsing on both tiers; disable connection reuse to the back-end where feasible; keep proxies/CDN patched.

---

# 19. Reporting, CWE/CVSS & De-duplication

Use `REQUEST_SMUGGLING_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "HTTP request smuggling (CL.TE / H2.CL) on <host> → request capture / WAF bypass / cache poisoning" (name IMPACT)
2. Severity     CVSS 3.1 vector + score + CWE-444 (+ outcome CWE)
3. Asset        exact host + the desync class + protocol (H1/H2) 
4. Summary      the parser disagreement, how you confirmed it, what you exploited
5. Steps        numbered: the byte-exact request(s), the timing + differential proof, the impact (safely)
6. PoC          the raw requests + the controlled evidence (own-session capture / bypassed access / benign poisoned key)
7. Impact       session theft / mass cache poisoning / control bypass → internal/RCE — the "so what"
8. Remediation  consistent framing, reject ambiguous requests, H2 end-to-end (§18)
```
**De-dup:** one desync primitive/root cause = one finding even if it enables several exploits; lead with the highest-impact exploit. Don't split "desync confirmed" and "request capture" — one report. Distinct primitives (a separate H2 downgrade vs an H1 CL.TE) may be separate.

---

# 20. Automation & Red-Team Notes

**Automation (find candidates fast, verify by hand & SAFELY):**
```bash
python3 poc/desync_timing.py -u https://target/         # SAFE timing detection (no socket poisoning)
python3 smuggler/smuggler.py -u https://target/         # CL/TE permutations (confirm + be careful)
# Burp: "HTTP Request Smuggler" (detect + exploit scaffolding) + Turbo Intruder for byte-exact PoCs.
```
- **Quality gate:** never submit a tool flag or a timing blip. Confirm a **deterministic, controllable** desync by hand, build a **concrete** exploit on your own connections, and respect do-no-harm (§18).

**Red-team angles:**
```
□ Request capture of an admin session → admin code-exec feature → RCE.
□ WAF bypass to deliver an SQLi/SSTI/cmdi payload the edge blocked → RCE (hand off to the matching kit).
□ Smuggle to a back-end SSRF/metadata endpoint → cloud creds → cloud takeover (SSRF kit).
□ HTTP/2 downgrade desync on "HTTP/1-safe" targets — frequently still vulnerable.
□ Cache/response-queue poisoning for mass session/credential capture (lab/own-traffic proof only).
□ Chain with the Host-Header kit (cache poisoning) and CORS/SSRF kits for the post-access impact.
```

---

# Appendix A — Smuggling Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                 HTTP REQUEST SMUGGLING WORKFLOW                   │
├────────────────────────────────────────────────────────────────────┤
│ 0. RECON: front-end+back-end chain (CDN/LB/proxy→origin); H1 vs   │
│    H2 to you/origin; reflection/restricted/cacheable endpoints §3 │
│ 1. BASELINE ★ : SAFE timing detection first; then a deterministic │
│    differential on YOUR OWN connection §4  (DO NO HARM)           │
│ 2. TECHNIQUE: CL.TE/TE.CL §5 · TE.TE obfuscation §6 · H2 downgrade│
│    (H2.CL/H2.TE/CRLF) §7                                          │
│ 3. CONFIRM: prefix attaches to a FOLLOW-UP predictably §8         │
│ 4. IMPACT ⭐ :                                                      │
│    request/session CAPTURE → ATO ................... §9  ⭐⭐⭐     │
│    front-end WAF/auth bypass → internal/admin ...... §10 ⭐⭐       │
│    cache poisoning → mass XSS/redirect ............. §11 ⭐⭐       │
│    smuggle→stored XSS / response-queue poisoning ... §12 ⭐⭐⭐     │
│    internal/admin → SSRF-like → RCE/cloud .......... §13 ⭐⭐⭐     │
│ 5. VALIDATE → REPORT:                                            │
│    FP filter §15 (blip≠desync) · CVSS+CWE-444 §16                │
│    SAFE PoC: timing first, own connections, benign, do-no-harm §18│
│    title = IMPACT, dedup §19                                     │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — Smuggling Decision Tree

```
Is there a front-end + back-end chain (CDN/proxy/LB → origin)? (§3)
│  └─ no → smuggling unlikely; move on.
│
├─ Run SAFE timing detection (§4) →
│     ├─ no signal → try TE.TE obfuscations (§6) and, if H2 at the edge, H2 downgrade vectors (§7).
│     └─ timing signal → confirm with a DETERMINISTIC differential on your OWN connection (§8).
│
├─ Confirmed, controllable desync → what's available to exploit?
│     ├─ store/reflect-the-request endpoint? → REQUEST CAPTURE → steal auth → ATO (§9). CRITICAL ⭐
│     ├─ WAF-blocked or /admin/internal path? → CONTROL BYPASS (§10) → exploit the reached endpoint (§13). HIGH–CRITICAL
│     ├─ a cache in the chain? → CACHE POISONING → mass XSS/redirect (§11). HIGH–CRITICAL
│     ├─ can desync the response queue? → RESPONSE-QUEUE POISONING (§12). CRITICAL (own-traffic proof only)
│     └─ reach a back-end SSRF/metadata/code-exec endpoint? → RCE/cloud (§13). CRITICAL
│
├─ HTTP/2 at the edge? → ALWAYS test H2.CL/H2.TE/CRLF downgrade even if H1 failed (§7).
│
└─ Only a timing blip / tool flag / non-reproducible? → NOT a finding yet. Confirm deterministically (§15).

ALWAYS: do-no-harm — timing first, own connections, benign markers; prove the capability, then report (§18).
```

---

# Appendix C — References & Further Reading

**Always-on (start here):**
- **PortSwigger Web Security Academy — HTTP request smuggling** (topic + labs): https://portswigger.net/web-security/request-smuggling
- **HackTricks — HTTP Request Smuggling / HTTP Desync:** https://book.hacktricks.xyz/pentesting-web/http-request-smuggling
- **PayloadsAllTheThings — Request Smuggling:** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Request%20Smuggling
- **OWASP WSTG** — Testing for HTTP Splitting/Smuggling (WSTG-INPV-15)
- **PentesterLab** — HTTP request smuggling exercises

**Class research (smuggling is a research-driven class — read the primaries):**
- **James Kettle — "HTTP Desync Attacks: Request Smuggling Reborn"** (2019 — the paper that revived the class): https://portswigger.net/research/http-desync-attacks-request-smuggling-reborn
- **James Kettle — "HTTP/2: The Sequel is Always Worse"** (2021 — H2.CL / H2.TE / CRLF downgrade desync, §7): https://portswigger.net/research/http2-the-sequel-is-always-worse
- **James Kettle — "Browser-Powered Desync Attacks"** (2022 — client-side desync / CL.0 / pause-based, §7.2/§7.4): https://portswigger.net/research/browser-powered-desync-attacks
- **Assetnote** — "Practical HTTP Header Smuggling" + desync/CVE deep-dives: https://www.assetnote.io/resources

**Tools:**
- **HTTP Request Smuggler** (Burp BApp, PortSwigger): https://github.com/PortSwigger/http-request-smuggler · **smuggler.py** (defparam): https://github.com/defparam/smuggler · **Turbo Intruder** (byte-exact PoCs) · the `poc/` helpers here.

**Standards & scoring:**
- **CWE-444** (Inconsistent Interpretation of HTTP Requests / "HTTP Request Smuggling"): https://cwe.mitre.org/data/definitions/444.html · outcome CWEs — **CWE-79** (XSS via cache/stored) · **CWE-384** (session) · **CWE-918/CWE-94** (SSRF/RCE via the reached endpoint)
- **CVSS 3.1** — `AC:H` (needs timing/positioning) but the cross-user impact drives it to **High–Critical** (see §16).

---

> **Final reminder — the one rule that pays:** *Request smuggling is only a finding when you prove a **deterministic, controllable desync** and turn it into a **concrete cross-user impact** — capturing a victim's request/session, bypassing the front-end to reach internal/admin (→ RCE/cloud), or poisoning the cache/response-queue for everyone.* A timing blip or a tool flag is not a finding. Detect safely with timing, confirm with a differential, build the exploit on your **own** connections with benign markers — do no harm — and report the impact. That's how a parser disagreement becomes the Critical it's worth.
