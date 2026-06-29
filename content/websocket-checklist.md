# WebSocket Testing Checklist — Per-Endpoint, In Testing Order

> Tick per WebSocket endpoint. Mirrors the Master Testing Sequence in `WEBSOCKET_TESTING_GUIDE.md`. The point: **read the handshake (cookie-vs-token, Origin, wss) → CSWSH → per-message authz/IDOR → message injection → escalate to ATO/RCE.** `§` = section in the main guide.

**Target:** ____________  **WS endpoint:** `wss://__________________`  **Date:** ________
**Auth model:** cookie (auto-sent) / token-in-URL / subprotocol / first-message  **Origin validated:** y/n  **wss:** y/n
**Framing:** raw JSON / socket.io `42[...]` / STOMP / SignalR / SockJS / graphql-ws / binary  **Accounts:** A=____ B=____

---

## PHASE 0 — Recon & Lab (§1/§3)
- [ ] Found WS endpoint(s): DevTools→Network→WS, JS (`new WebSocket(`/`io(`/`SockJS(`/`signalr`), Burp WebSockets history.
- [ ] Tried common paths: `/ws`, `/socket`, `/socket.io/`, `/cable`, `/hub`, `/signalr`, `/graphql`, `/stomp`, `/live`.
- [ ] Proxied the socket through Burp; captured a clean handshake + sample frames.

## PHASE 1 — Baseline ★ (§4)
- [ ] Read the **handshake**: is auth a **`Cookie`** (auto-sent) or a **token** (URL/subprotocol/first-message)?
- [ ] Is the **`Origin`** header **validated**? (replay with a foreign Origin + victim cookie via websocat).
- [ ] Is it **`wss://`** (TLS)? Any **token in the URL**?
- [ ] **Mapped message types**: which carry an **id**, which **change state**, which are **rendered to others**, which **hit the backend** (DB/cmd/URL).
- [ ] Verdict: `CSWSH-able` / `IDOR-over-WS` / `injection-candidate` / `transport-weak` / `looks-locked`.

## PHASE 2 — Handshake & Auth (§5–§7)
- [ ] **CSWSH** (§5): foreign `Origin` + victim **cookie** → still connects authenticated? (cookie auth + no Origin check).
  - [ ] Tried **weak-allow-list bypasses**: `target.com.evil`, `eviltarget.com`, controlled subdomain, `null`, trailing-dot/case.
- [ ] **Per-message authz / IDOR** (§6): connect as A, send a frame with **B's id** → B's data/action? Try **privileged** message types (BFLA) and **unauthenticated** message types.
- [ ] **Channel/topic authz** (§6.4): subscribe to another user's / `admin` channel.
- [ ] **Transport** (§7): cleartext `ws://`? token in URL? socket survives logout/token-revocation?

## PHASE 3 — Message-Layer & Impact ⭐ (§8–§13)
- [ ] **Injection in message fields** (§8): **XSS** (rendered to others) · **SQLi/NoSQLi** · **cmdi/SSRF** (OOB) · **path traversal** · **mass-assignment** (`role`/`isAdmin`) · **deserialization** (binary frames).
- [ ] **CSWSH → impact** (§9): exfiltrate the victim's private data **and** send a state-change (change email → reset → **ATO**).
- [ ] **Rate-limit bypass over WS** (§10): many login/OTP attempts on one socket → brute → ATO.
- [ ] **DoS** (§11, permission): connection exhaustion / large frames / `permessage-deflate` bomb → **measure** amplification.
- [ ] **Smuggling / proxy** (§12) and **framework quirks** (§13: socket.io/SignalR/STOMP/SockJS/graphql-ws) considered.
- [ ] Stated impact: *"On `<endpoint>` a `<cross-site page / tampered frame>` could `<read victim data / ATO / RCE / cross-user action>`."*

## PHASE 4 — Validate → Severity → Report (§15–§20)
- [ ] ★ **CSWSH proof**: attacker-origin HTML, **logged-in victim, default browser** → handshake `Origin: attacker` **accepted authed** → data exfil / state change. (Not a websocat-only connect.)
- [ ] **IDOR/injection proof**: two-account data-back / XSS fires in a recipient / SQL-OOB signal — reproducible.
- [ ] Passed the **false-positive filter** (§16): NOT "no Origin check" with **token-auth**, NOT websocat-only CSWSH, NOT impact-less Origin reflection, NOT self-XSS, NOT theoretical DoS.
- [ ] Set **CVSS 3.1** + **CWE-1385/346** (CSWSH) / injection-IDOR CWEs (§17).
- [ ] Built a clean **PoC** (attacker-origin page, own victim account, exfil to your server, reverted) (§19).
- [ ] **De-duplicated**; title names **endpoint + sub-bug + impact** (§20).

---

## Quick "is it a real WebSocket finding?" gate
```
Found a ws(s):// endpoint?                                         NO → keep hunting (JS/DevTools/framework paths).
CSWSH: auth = COOKIE (auto-sent) AND Origin NOT checked?           NO (token-auth / Origin enforced) → no CSWSH.
       proven in a REAL browser, cross-site, reading/acting?       NO → not demonstrable (websocat-only ≠ proof).
Message field crosses users (XSS) / hits backend (SQLi) / swaps id (IDOR)?  NO → keep looking / drop.
Impact: data theft / ATO / RCE / cross-user / brute-ATO?           NO → Low/Info.
```

## Per-endpoint mini-loop
```
read handshake (cookie? Origin? wss?) → CSWSH oracle (foreign Origin + cookie) → real-browser PoC
   → per-message: swap B's id (IDOR) · privileged type (BFLA) · inject fields (XSS/SQLi/cmdi/SSRF)
   → escalate (CSWSH→ATO / injection→RCE / brute→ATO) → validate → CVSS+CWE-1385 → reversible PoC → dedup
```
