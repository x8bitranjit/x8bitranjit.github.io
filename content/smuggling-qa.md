# HTTP Request Smuggling — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **HTTP request smuggling / desync attacks** — from "what is a
> parser disagreement" to CL.TE/TE.CL/TE.TE, HTTP/2 downgrade desync, CL.0 / client-side desync, connection-state
> attacks, and the cross-user impact they unlock (request/session capture, WAF/auth bypass, cache & response-queue
> poisoning, internal→RCE). Q&A format, progressive difficulty. Covers safe detection, every technique, exploitation,
> tooling, methodology, real-world research, **and** defense.
>
> ⚖️ **Authorized use only — and DO NO HARM.** Request smuggling can corrupt shared connections and **disrupt real
> users** (errors, mixed responses, stolen requests). Detect with **timing** first (no socket poisoning), confirm with
> a **deterministic differential on connections you control**, exploit with **benign** prefixes and your **own**
> accounts/connections, never run a **sustained** smuggle against production, and prove the *capability* then stop.
> Many programs explicitly want this reported without mass exploitation — respect that. Never test systems you don't
> have written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- PortSwigger Web Security Academy — *HTTP request smuggling* (+ labs) and James Kettle's research papers:
  "HTTP Desync Attacks" (2019), "HTTP/2: The Sequel is Always Worse" (2021), "Browser-Powered Request Smuggling" (2022)
- `defparam/smuggler` · Burp **HTTP Request Smuggler** + Turbo Intruder · HackTricks / PayloadsAllTheThings — *Request Smuggling*
- CWE-444 (Inconsistent Interpretation of HTTP Requests)
- Companion kit in this repo: `Web/RequestSmuggling/` (guide + arsenal + checklist + report template + `poc/`)

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q12)
- **Level 1 — Recon & SAFE detection** (Q13–Q24)
- **Level 2 — Classic desync: CL.TE / TE.CL / TE.TE** (Q25–Q40)
- **Level 3 — HTTP/2, CL.0, client-side desync & connection-state** (Q41–Q56)
- **Level 4 — Exploitation by impact** (Q57–Q78)
- **Level 5 — Methodology, do-no-harm & triage** (Q79–Q88)
- **Tooling** (Q89–Q92)
- **Cheat sheets** (Q93–Q97)
- **Real-world & references** (Q98–Q99)
- **Defense — preventing desync** (Q100–Q103)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is HTTP request smuggling?
An attack where the **front-end** (CDN/load-balancer/reverse-proxy/WAF) and the **back-end** (origin app server) **disagree about where one request ends and the next begins** on a reused (keep-alive) connection. You craft a request that leaves a **partial request** behind, which then **prefixes the next request** on that connection — often **another user's**. That prefix is the weapon.

### Q2. Why is it called a "desync"?
Because after a smuggled request, the front-end and back-end are **out of sync** about the byte boundary between requests. The front-end thinks request A ended *here*; the back-end thinks it ended *there*. The bytes in between become the start of the next request the back-end parses.

### Q3. What causes the parser disagreement?
The two servers use **different rules** to compute a request's length: `Content-Length` (CL) vs `Transfer-Encoding: chunked` (TE), or — in HTTP/2 — the explicit H2 length vs the CL/TE injected on the downgrade to HTTP/1.1. When they pick different lengths for the same request, you get a desync.

### Q4. What are the main classes?
```
CL.TE  → Front-end uses Content-Length; Back-end uses Transfer-Encoding (chunked).
TE.CL  → Front-end uses Transfer-Encoding; Back-end uses Content-Length.
TE.TE  → Both support TE, but one is tricked by an OBFUSCATED Transfer-Encoding header into ignoring it.
H2.CL / H2.TE → HTTP/2 has an explicit length; on DOWNGRADE to HTTP/1.1 the injected CL/TE desyncs the origin.
CL.0 / 0.CL → one tier ignores Content-Length (treats body as 0) → the body becomes the next request.
client-side desync (CSD) → a desync the victim's own browser triggers; no front-end needed.
connection-state → the front-end applies a per-connection decision (routing/validation) only to the FIRST request.
```

### Q5. Why does smuggling pay so well?
Because it's **cross-user** and **bypasses controls**: you can **hijack victims' requests** (steal sessions/PII), **poison the cache/response-queue** for everyone (mass XSS/redirect/leak), **bypass the front-end WAF/auth** to reach internal/admin endpoints (→ RCE), and amplify one request into mass impact. Real smuggling is typically **High–Critical**.

### Q6. What's the precondition for smuggling?
A **front-end + back-end chain** that **reuses the connection** (HTTP/1.1 keep-alive or HTTP/2). Without connection reuse there's no "next request" to prepend to. (Connection-state and CL.0 also rely on reuse.)

### Q7. Where does impact actually come from?
From **what you prepend**. A smuggled prefix can: capture the next (victim's) request, request `/admin` past the front-end, deliver a WAF-blocked payload to the back-end, or make the cache store a malicious response. The desync is the *door*; the prepended prefix is the *exploit*.

### Q8. What are the two biggest mistakes hunters make?
**(1) DoS-ing the target while probing** — bad probes corrupt the shared connection and break things for real users; and **(2) reporting a timing blip** without a concrete, deterministic exploit. The discipline is: timing-first detection, deterministic confirmation on your own connection, benign exploitation.

### Q9. Why is "do no harm" central to this class specifically?
Because a smuggled prefix sits on a **shared** connection — a real user's next request can pick it up, getting an error, the wrong response, or having their request stolen. Unlike most bug classes, careless testing **directly harms third parties**. So you confirm on connections you isolate and never sustain a smuggle against production traffic.

### Q10. Why did HTTP/2 change the game?
Even sites that are "HTTP/1.1-safe" often **downgrade** HTTP/2 to HTTP/1.1 at the edge. The H2 request has an unambiguous length, but the values you inject (CL/TE/CRLF) on the downgrade desync the origin. So **H2.CL/H2.TE/CRLF** vectors hit many modern, patched-looking targets.

### Q11. What's the validity rule (so I don't report nothing)?
A finding requires **(a)** a **deterministic, controllable** desync (a smuggled prefix that changes a *follow-up* request predictably) **and (b)** a **concrete cross-user impact** (or a reliable cross-connection capability). A timing blip, a tool flag, or a one-off odd response is **not** a finding.

### Q12. What do I need to learn first?
HTTP/1.1 message framing (CL vs chunked), how to send **byte-exact** raw requests (Burp Repeater HTTP/1 "raw", auto-Content-Length **off**; Turbo Intruder), the front-end/back-end model, HTTP/2 basics (`:authority`, downgrade), and the do-no-harm methodology.

---

# LEVEL 1 — RECON & SAFE DETECTION

### Q13. How do I find a front-end/back-end chain?
Response headers reveal a front-end: `Server`, `Via`, `X-Cache`, `CF-RAY`, `X-Served-By`, CDN behavior, edge error pages. Confirm **keep-alive** (`Connection: keep-alive` on HTTP/1.1, or HTTP/2 which is always multiplexed). Map protocols: do you speak HTTP/2 to the edge, and does the edge speak HTTP/1.1 to the origin (the downgrade surface)?

### Q14. What endpoints should I note during recon?
A **reflection/store** endpoint (search-log/comment/profile that echoes or stores the raw request — for request capture), **restricted/WAF-blocked** paths (`/admin`, internal — for control bypass), **cacheable** pages (for cache poisoning), and **POST endpoints** that accept arbitrary bodies (the smuggle carrier).

### Q15. Why detect with TIMING first?
Because timing detection **does not** leave a dangling prefix on the shared connection (no socket poisoning) — so it won't corrupt the next real user's request. Only after timing suggests a desync do you move to a controlled differential on connections you isolate.

### Q16. How does the timing test work?
You craft a request where, **if** the back-end uses the "wrong" length, it **waits** for bytes that never arrive → a measurable delay; if not, it returns fast.
```
CL.TE timing: TE: chunked + a Content-Length so the back-end (honoring TE) waits for more chunked data → DELAY.
TE.CL timing: the mirror. A consistent, repeatable delay (vs a fast baseline) = a desync signal.
```
(Turbo Intruder / the kit's `desync_timing.py` implement the canonical PortSwigger timing probes.)

### Q17. How do I confirm a desync deterministically (and safely)?
Send the smuggle, then **immediately** your **own** benign follow-up on a connection you control. If your follow-up gets a response proving the prefix attached — e.g., a 404/redirect for a path only your *smuggled prefix* specified — the desync is confirmed **without touching other users**. Repeat to confirm reliability.

### Q18. Why repeat the timing test?
Because a **single** slow response is jitter/load, not proof. A **consistent** delay over multiple repeats vs a fast baseline is the signal. One slow response is a false positive (Q90).

### Q19. What does "byte-exact" mean and why does it matter?
Smuggling depends on the **exact** bytes: precise `Content-Length`, real `\r\n` line endings, no client auto-fixups. A normal HTTP client "helpfully" rewrites `Content-Length`/`Connection` and kills the desync. Use Burp Repeater in **HTTP/1 raw** mode (disable "Update Content-Length") or Turbo Intruder.

### Q20. What does the recon/baseline produce?
The desync **class** (CL.TE / TE.CL / TE.TE / H2 / CL.0 / connection-state) suggested by timing/differential, the front-end protocol (H1/H2), and a target exploit (reflection→capture, WAF/blocked path→bypass, cache→poison). That tells you what to build next.

### Q21. Can I detect smuggling with a scanner?
`smuggler.py` and Burp's "HTTP Request Smuggler" automate detection — but tools **false-positive heavily** here. Treat a flag as a *candidate*; confirm with a deterministic differential by hand before believing it (and certainly before reporting).

### Q22. Is a 400/connection-reset a finding?
No — the server **rejecting** ambiguous/malformed framing is **correct** behavior. A 400 means the desync didn't take. You need the back-end to *accept* the ambiguous framing and mis-attribute bytes.

### Q23. How do I avoid harming users during detection?
Timing-first (no poisoning). For differentials, isolate to a fresh connection you control and don't leave dangling prefixes. Keep volume low. If you must leave a prefix, send your own follow-up immediately to consume it.

### Q24. When do I move from detection to exploitation?
Only after a **deterministic, controllable** desync (your follow-up reliably receives the smuggled prefix's response). Then pick the exploit by what the target offers — never start exploiting on an unconfirmed signal.

---

# LEVEL 2 — CLASSIC DESYNC: CL.TE / TE.CL / TE.TE

### Q25. Walk a CL.TE desync.
Front-end uses `Content-Length`; back-end uses chunked:
```
POST / HTTP/1.1
Host: target
Content-Length: 6
Transfer-Encoding: chunked

0

G
```
The front-end forwards 6 bytes (`0\r\n\r\nG`); the back-end sees the chunked `0` terminator and leaves `G` as the **start of the next request** → `G` prefixes the victim's request.

### Q26. Walk a TE.CL desync.
Front-end uses chunked; back-end uses `Content-Length`:
```
POST / HTTP/1.1
Host: target
Content-Length: 4
Transfer-Encoding: chunked

5c
GPOST / HTTP/1.1 ...(a full smuggled request)...
0

```
The front-end (chunked) forwards everything; the back-end (CL:4) treats the rest as a new request. The chunk-size (`5c`) must equal the exact byte length of the smuggled request.

### Q27. Why is TE.CL trickier than CL.TE?
Because you embed a **whole second request** sized by the back-end's `Content-Length`, and you must get the **chunk size** (hex) exactly right for the smuggled bytes. CL.TE just needs a leftover byte after the `0` terminator. Tune carefully.

### Q28. What is TE.TE?
Both ends support `Transfer-Encoding`, but you **obfuscate** the header so only **one** end honors it → it degrades to CL.TE or TE.CL:
```
Transfer-Encoding: xchunked          Transfer-Encoding : chunked   (space before colon)
Transfer-Encoding:\tchunked          Transfer-Encoding: chunked\r\nTransfer-Encoding: x
X: X\nTransfer-Encoding: chunked      Transfer-Encoding\n: chunked
```

### Q29. Which TE.TE obfuscations are most productive?
The **space-before-colon** (`Transfer-Encoding : chunked`) and the **tab** (`Transfer-Encoding:\tchunked`) variants — they make one tier ignore the header while the other honors it. Try each with a CL.TE/TE.CL body; whichever creates the desync wins.

### Q30. How do I confirm a CL.TE/TE.CL once timing suggests it?
Smuggle a prefix that requests a **unique** path with a distinctive response (a 404 for `/smuggle-<rand>`), then send your own benign follow-up; if your follow-up gets that distinctive 404/redirect, the prefix attached. Repeat for reliability.

### Q31. How do I tune the lengths?
Adjust `Content-Length`/chunk sizes **byte-by-byte** until the leftover prefix is exactly the bytes you want (for TE.CL, the chunk-size hex must equal the smuggled-data length). Burp/Turbo Intruder let you iterate precisely.

### Q32. Which class do I get from which timing signal?
The CL.TE timing probe delaying → CL.TE (back-end honors TE). The TE.CL probe delaying → TE.CL (back-end honors CL). If neither plain probe fires but both ends are TE-aware → try TE.TE obfuscations.

### Q33. What if `Content-Length` and `Transfer-Encoding` are both present and the server rejects it?
Rejecting both-present is the RFC-compliant defense (good). But many real stacks **don't** reject — they pick one. The obfuscation (TE.TE) is exactly about making the two tiers pick *differently*.

### Q34. Why must I disable the client's auto-Content-Length?
Because your whole attack depends on a `Content-Length` that **disagrees** with the body length (or a specific chunk framing). If the client recomputes/fixes it, the disagreement vanishes and the desync dies. Burp Repeater → uncheck "Update Content-Length".

### Q35. Can CL.TE/TE.CL be done over HTTPS?
Yes — TLS is just transport; the framing bug is in the HTTP layer. Send the byte-exact request over the TLS connection (Burp does this). The front-end/back-end disagreement is independent of TLS.

### Q36. What's the role of `Connection: keep-alive`?
It (or HTTP/2 multiplexing) keeps the connection open so there's a **next request** to prepend to. Without reuse, the smuggled prefix has nothing to attach to. Ensure the connection is reused (Burp does by default within a tab).

### Q37. How reliable is classic smuggling?
Variable — connection pooling/round-robin affects which back-end instance you hit, so a prefix may land intermittently. Measure reliability across trials; a desync that lands, say, 1-in-3 is still exploitable (you retry) but note it.

### Q38. What if the front-end normalizes/rejects chunked?
Then CL.TE/TE.CL may not work; pivot to **TE.TE** obfuscation (defeat the normalization), **HTTP/2 downgrade** vectors (Q41), or **CL.0**/connection-state (Q49/Q53).

### Q39. Is a confirmed-but-unexploited CL.TE worth reporting?
A confirmed, **controllable** desync with **no** exploit built is ~**Medium**. The bounty is the exploit — build request capture / control bypass / cache poisoning (Level 4). Many programs still want the desync reported, but lead with the highest impact you can demonstrate.

### Q40. What's the end-state of Level 2?
A **working desync primitive** (CL.TE/TE.CL/TE.TE) confirmed deterministically and tunable to leave the exact prefix you want. Now (Level 4) turn it into a concrete cross-user impact.

---

# LEVEL 3 — HTTP/2, CL.0, CLIENT-SIDE DESYNC & CONNECTION-STATE

### Q41. What is HTTP/2 downgrade desync?
When the edge speaks **HTTP/2** to you but **HTTP/1.1** to the origin, it **downgrades** your request. The values you inject in the H2 request (a `Content-Length`, a `Transfer-Encoding`, or a CRLF in a header value) get serialized into the HTTP/1.1 request the origin parses → desync.

### Q42. What are H2.CL and H2.TE?
- **H2.CL:** include a `Content-Length` in the H2 request that disagrees with the actual body → on downgrade the origin uses your CL and mis-frames the next request.
- **H2.TE:** smuggle a `Transfer-Encoding: chunked` header via H2 → ignored in H2 (which has its own length) but **honored** by the H1 origin after downgrade.

### Q43. What is H2 CRLF injection / request splitting?
Inject `\r\n` into an HTTP/2 header **value** (or a pseudo-header) → on downgrade it splits into **extra H1 headers/requests**. E.g., a header value containing `foo\r\nTransfer-Encoding: chunked\r\n\r\n<smuggled request>`. Also test `:path`/`:method`/`:authority` smuggling and header-name CRLF.

### Q44. Why do "patched" sites still fall to HTTP/2 desync?
Because they fixed HTTP/1.1 framing but still **downgrade** H2→H1 at the edge and don't sanitize the downgraded request. Kettle's "HTTP/2: The Sequel is Always Worse" showed many such targets. Always test the downgrade vectors even if H1 smuggling failed.

### Q45. How do I test HTTP/2 vectors?
Burp's **HTTP Request Smuggler** has dedicated H2.CL/H2.TE/CRLF probes; Burp Repeater can send HTTP/2 with custom pseudo-headers and CRLF in values. Use them carefully — they can still corrupt connections.

### Q46. What is CL.0?
A class where the **back-end ignores `Content-Length`** on certain endpoints (treats the body as 0) → your body becomes the **start of the next request**. Target endpoints that "shouldn't" have a body — **static files, redirects, some GET/OPTIONS handlers** — which are most likely to ignore CL.
```
POST /static/x.js HTTP/1.1  Host: t  Content-Length: 34  \r\n\r\n  GET /admin HTTP/1.1\r\nFoo: bar
```

### Q47. What is 0.CL?
The mirror of CL.0: the **front-end** ignores `Content-Length` (treats as 0) but the back-end honors it. Same idea, opposite tier. Test both.

### Q48. Why are CL.0 / 0.CL often missed?
Because hunters fixate on CL.TE/TE.CL with chunked bodies and don't test **body-on-a-bodyless-endpoint**. CL.0 needs no `Transfer-Encoding` trickery — just a normal POST with a body to an endpoint that ignores the length. Test static/redirect endpoints specifically.

### Q49. What is client-side desync (CSD / browser-powered)?
PortSwigger 2022: a desync the **victim's own browser** triggers via a cross-origin `fetch()` with keep-alive — **no front-end/proxy needed**. An attacker page makes the victim's browser send a poisoned request whose trailing bytes prefix the victim's **next same-connection** request → request hijack / stored-XSS-from-self / credential capture, all from the victim visiting your page.

### Q50. Why is CSD significant?
Because it reaches **victims directly** (a watering-hole/ad link), without you needing to be in the request path. It turns a server desync into a **drive-by** that hijacks the visitor's own connection. It's powerful and dangerous — demonstrate on your **own** browser/session only.

### Q51. How do I test CSD?
Use the "Browser-Powered Request Smuggling" methodology + Burp's scanner (which probes CL.0-style desyncs reachable over a normal connection) and confirm in a **real browser** with your own session. The server must have a CL.0/0.CL-style desync reachable without a proxy.

### Q52. What are connection-state attacks?
Not framing desync at all — the bug is that the front-end applies a **per-connection** decision only to the **first** request and reuses it for the rest of the connection. Two variants: **first-request routing** and **first-request validation**.

### Q53. Explain first-request routing.
The front-end picks the **backend** from the **first** request's `Host`/SNI, then routes **all** later requests on that connection the same way:
```
req#1: GET / Host: allowed.target.com         (establishes the route)
req#2: GET /admin Host: internal-only.target  (same connection) → routed to the INTERNAL backend
```
You reach internal vhosts the edge would never route to — *if* you can pin two requests on one connection.

### Q54. Explain first-request validation.
The front-end **authenticates/validates** only the **first** request on a connection; subsequent requests **inherit** that trust. Send a benign first request, then a privileged/blocked one on the same connection → it bypasses the validation. Test same payload on a fresh vs reused connection.

### Q55. How do I send two requests on one connection deterministically?
Burp's "HTTP Request Smuggler" (send-group-in-single-connection) or **Turbo Intruder** with a pipelined connection (send a group of requests on one socket). Compare the result on a **reused** connection vs a **fresh** one — a difference proves the connection-state bug.

### Q56. Do connection-state attacks harm users?
Less than framing desync (you're not leaving a dangling prefix), but you're still relying on connection reuse — keep it to your own connections, confirm deterministically, and prove the capability minimally.

---

# LEVEL 4 — EXPLOITATION BY IMPACT

### Q57. What's the crown-jewel exploit?
**Request hijacking / capturing another user's request.** Smuggle a prefix that makes the back-end **store or reflect the next (victim's) request** — capturing their `Cookie`/`Authorization`/CSRF token/PII → session theft → **ATO (Critical)**.

### Q58. How does request capture work in practice?
Smuggle a request to an endpoint that **stores or reflects the raw request** (a comment/feedback/search-log/profile field). The victim's in-flight request gets **appended** to your smuggled body and ends up stored/reflected; you then read their cookie/token out of that content.

### Q59. How do I PoC request capture safely?
Capture **your own** second session's request (a separate session you control) to **prove the capability**, then *describe* the cross-user impact. **Never** harvest real victims' requests/sessions. Own-session capture is sufficient evidence.

### Q60. What is front-end WAF/auth bypass via smuggling?
The front-end enforces WAF rules, auth, and path restrictions on the **request it sees** — but the **smuggled** prefix reaches the back-end **unfiltered**. So you smuggle a request to `/admin` or with a WAF-blocked payload that **only the back-end** processes → access restricted/internal functionality or land your blocked attack.

### Q61. Why is control bypass so impactful?
Because what the back-end then exposes can be **Critical**: an internal admin panel, a debug/health endpoint, or a WAF-bypassed SQLi/SSTI/command-injection that now reaches the vulnerable code → **RCE** (Q66).

### Q62. What is cache poisoning via smuggling?
Combine smuggling with a cache so a **malicious response is stored under a popular URL's key** → every user requesting that URL gets your poisoned response (redirect/stored XSS). Smuggling provides the response/request misassociation that lands your content on a victim URL → **mass compromise (High–Critical)**.

### Q63. What is response-queue poisoning?
A desync so severe that **responses and requests get out of sync** on the connection: a victim receives the response intended for **your** request (which can leak data / force content), and you can receive **theirs**. Extremely powerful — and dangerous — so demonstrate **minimally** on your own connections.

### Q64. What is smuggle-to-stored-XSS?
Prefix a request to a stored-content endpoint with an **XSS payload** so it's stored and served to other users — turning a self-XSS or a header-only reflected XSS into a **victim-delivered** XSS. Also: turn a reflected XSS that needs a header a victim's browser can't set into a smuggled, victim-delivered one.

### Q65. How does smuggling reach internal/admin → RCE?
The control-bypass (Q60) lands you at back-end endpoints that are themselves exploitable: an internal **admin** feature that runs code/imports/templates → web shell; a back-end **SSRF/metadata** endpoint → cloud creds → cloud shell; or a **WAF-bypassed injection** (SQLi/SSTI/cmdi) → RCE. Smuggling is the access; the reached endpoint is the RCE.

### Q66. Walk a smuggling→RCE chain.
Confirm a desync → smuggle `GET /internal/admin` past the front-end → the internal admin panel (no external auth) exposes an import/deploy/template feature → web shell. Or smuggle to a back-end SSRF endpoint → `169.254.169.254` → IAM creds → cloud run-command → shell. Prove on your **own** tenant; validate creds read-only; stop at proof.

### Q67. What's the severity of request capture?
**Critical** — cross-user session theft → ATO. CWE-444 + CWE-384 (session). It's the headline smuggling outcome.

### Q68. What's the severity of cache/response-queue poisoning?
**High–Critical** — mass stored XSS / mass redirect / mass data leakage (a victim gets your or another victim's response). CWE-444 + CWE-79 (XSS via cache).

### Q69. What's the severity of WAF/auth bypass alone?
**High** (depends what the reached endpoint exposes) — and **Critical** when it leads to RCE via the back-end (Q65). CWE-444 + the outcome CWE.

### Q70. How do I prove cache poisoning without harming users?
Smuggle so your malicious response is cached under a **benign/unique** key you control; show it's served from cache (`X-Cache: hit`) with a **benign marker**; then *describe* the impact on a popular URL. **Don't** poison a high-traffic shared entry.

### Q71. How do I prove response-queue poisoning safely?
Demonstrate the response/request desync using **your own two connections** (one "victim", one attacker, both yours) and a benign marker. Show that connection B receives connection A's response. Never run it against real traffic.

### Q72. Which exploit do I pick?
By what the target offers: a **store/reflect** endpoint → request capture (Critical). A **WAF-blocked or `/admin`** path → control bypass → exploit the reached endpoint (High–Critical). A **cache** in the chain → cache poisoning (High–Critical). Ability to desync the **response queue** → queue poisoning (Critical, own-traffic proof). A back-end **SSRF/code-exec** endpoint reachable → RCE (Critical).

### Q73. Can smuggling be a DoS?
Yes — a desync that corrupts the shared connection or poisons the cache with a broken/redirect-loop response can break the app for users. Report at the appropriate severity, and **never** sustain it.

### Q74. How does smuggling relate to the Host-Header and cache kits?
A smuggling desync is **another route** to the same mass-impact outcomes as Host-header cache poisoning. The Host-header kit covers web-cache-poisoning keying (unkeyed inputs, `Vary`, WCD); smuggling provides the request/response misassociation. Cross-reference both for the post-access impact.

### Q75. Chain: smuggling + a back-end injection.
The front-end WAF blocks your SQLi/SSTI/cmdi at the edge. Smuggle the request so **only the back-end** sees it → your payload reaches the vulnerable code unfiltered → exploit it (→ RCE). Smuggling defeats the edge WAF that was your only obstacle.

### Q76. Chain: request capture of an admin session.
Smuggle into a store/reflect endpoint so an **admin's** subsequent request is captured (their session cookie) → use it → admin functionality → code-exec feature → RCE. (Demonstrate the *capture capability* with your own session; don't actually steal a real admin's.)

### Q77. Chain: client-side desync watering-hole.
A CL.0/client-side-desync + an attacker ad/link → visitors' browsers poison their **own** connections → mass session/credential capture without you being in the path. Lab/own-traffic proof only.

### Q78. How do I escalate a "confirmed desync, no exploit"?
Find the available primitive: a store/reflect endpoint (capture), a blocked path (bypass), a cache (poison), or a back-end SSRF/injection (RCE). Build *one* concrete impact on your own connections. A desync alone is ~Medium; the exploit is the bounty.

---

# LEVEL 5 — METHODOLOGY, DO-NO-HARM & TRIAGE

### Q79. Step-by-step methodology.
1. **Recon**: front-end/back-end chain; H1/H2; reflection/restricted/cacheable endpoints.
2. **SAFE detection**: timing first (no poisoning), then a deterministic differential on **your own** connection.
3. **Technique**: pin the class (CL.TE/TE.CL/TE.TE/H2/CL.0/connection-state).
4. **Confirm**: prefix attaches to a follow-up predictably; measure reliability.
5. **Impact**: build ONE concrete exploit (capture/bypass/poison/RCE) on **your own** connections, benign markers.
6. **Report**: CWE-444 + outcome; one finding per desync primitive; do-no-harm note.

### Q80. What are the do-no-harm rules (restated)?
Timing-first detection; deterministic confirmation on connections **you control**; **benign** smuggled prefixes; your **own** second session/connection for capture; **non-shared/unique** keys for cache poisoning; **no sustained** smuggles against production; restore connection state; keep volume low; **prove the capability, then stop**.

### Q81. Quick triage decision tree.
- Timing signal + deterministic differential → confirmed desync.
- Store/reflect endpoint → **request capture → ATO** (Critical).
- WAF-blocked/`/admin`/internal path → **control bypass** → exploit reached endpoint (High–Critical, → RCE §65).
- Cache in chain → **cache poisoning** (High–Critical).
- Response queue desyncable → **queue poisoning** (Critical, own-traffic).
- HTTP/2 edge → also test **H2.CL/H2.TE/CRLF** downgrade.
- Static/redirect endpoint → also test **CL.0**; reused connection → **connection-state**.
- Only a timing blip / tool flag / non-reproducible → **not a finding**.

### Q82. False positives / auto-reject.
- A **single** slow/odd response (load/jitter) with no deterministic differential.
- "smuggler.py / the extension flagged it" with no manual confirmation.
- A desync you can't make **deterministic/reproducible**.
- 400/errors from malformed requests (the server **rejecting** bad framing = correct).
- A confirmed desync reported as **Critical with no exploit** (~Medium).
- **Self-only** effects (your request to yourself, no cross-user impact).

### Q83. What makes a great smuggling report?
The **byte-exact** request(s), the desync **class** + protocol, the **timing signal + deterministic differential** (your follow-up receiving the smuggled prefix's response), and the **concrete exploit** (own-session capture / bypassed `/admin` / benign cache poison on a unique key), with CWE-444 + the outcome CWE, a **do-no-harm** note (benign, own connections), and one-finding-per-primitive dedup.

### Q84. How do I de-duplicate smuggling findings?
One **desync primitive / root cause** = one finding even if it enables several exploits; lead with the highest-impact one. Don't split "desync confirmed" and "request capture" — they're one chain. A separate, genuinely distinct primitive (e.g., a separate H2 downgrade vs an H1 CL.TE) can be a separate report.

### Q85. How do I set severity?
Request capture / response-queue poisoning / smuggle→internal→RCE → **Critical**. Cache poisoning → High–Critical. WAF/auth bypass to a sensitive endpoint → High. Confirmed controllable desync, no exploit → Medium. Timing-only → not a finding.

### Q86. Why might a program want this reported "without exploitation"?
Because exploiting it on production **harms real users**. Many programs accept a **deterministic, controllable desync + a description of the impact** demonstrated on your own connections — they don't want you mass-capturing sessions or poisoning shared caches. Respect the program's stance; prove the capability, not the mass impact.

### Q87. Red-team angles (authorized engagements)?
Request capture of an admin session → admin RCE; WAF bypass → back-end injection → RCE; smuggle to a back-end SSRF/metadata endpoint → cloud takeover; HTTP/2 downgrade on "H1-safe" targets; CL.0/client-side-desync watering-hole; cache/response-queue poisoning for mass capture (lab/own-traffic only).

### Q88. What separates expert smuggling from beginner?
The expert (1) **detects safely** (timing first) and **confirms deterministically**; (2) knows the **full taxonomy** (CL.TE/TE.CL/TE.TE/H2/CL.0/CSD/connection-state) and tests the modern variants others miss; (3) builds a **concrete** exploit (capture/bypass/poison/RCE) instead of reporting a blip; (4) **does no harm** (own connections, benign, no sustained smuggles); and (5) chains to ATO/RCE and reports the capability with a clean PoC.

---

# TOOLING

### Q89. Core smuggling toolkit?
**Burp Suite** (Repeater HTTP/1 "raw" with auto-CL **off**; **Turbo Intruder** for byte-exact + pipelined/single-connection requests; **HTTP Request Smuggler** extension for CL.TE/TE.CL/H2/CL.0/connection-state probes; the **browser-powered** scanner for CSD), **`defparam/smuggler`** (CL/TE permutation scanner), and the kit's `poc/` (`desync_timing.py` safe detector, `build_smuggle.py` byte-exact builder).

### Q90. How do I use the timing detector safely?
`python3 desync_timing.py -u https://target/` — it uses a **fresh connection per probe** (no socket poisoning) and flags CL.TE/TE.CL signals vs a baseline. A signal is a **candidate** → confirm with a deterministic differential in Burp before believing it.

### Q91. Why use Turbo Intruder for confirmation?
Because it gives **precise control** over bytes, connection reuse, and **pipelining** (sending a group of requests on one connection) — essential for the deterministic differential, CL.0, and connection-state tests, and for measuring reliability without flooding.

### Q92. How do I avoid the tooling harming users?
Timing-first; isolate to connections you control; benign prefixes; low volume; don't run the scanner's *exploit* phase against production. The detection probes are designed to be safe; the **exploitation** is where harm happens — keep it on your own connections.

---

# CHEAT SHEETS

### Q93. Class cheat sheet.
```
CL.TE : FE=Content-Length, BE=chunked       TE.CL : FE=chunked, BE=Content-Length
TE.TE : obfuscate Transfer-Encoding so one tier ignores it (space-before-colon / tab / double TE)
H2.CL / H2.TE / H2-CRLF : HTTP/2 → HTTP/1.1 downgrade desync
CL.0 / 0.CL : one tier ignores Content-Length (body becomes next request) — test static/redirect endpoints
CSD : client-side desync (victim's browser, no front-end)        connection-state : first-request routing/validation
```

### Q94. CL.TE / TE.CL payload cheat sheet.
```
CL.TE:  Content-Length: 6 + Transfer-Encoding: chunked + body "0\r\n\r\nG"   (G prefixes the next request)
TE.CL:  Content-Length: 4 + Transfer-Encoding: chunked + "5c\r\n<smuggled request>\r\n0\r\n\r\n"  (chunk-size = smuggled len)
confirm: smuggle GET /unique-7f3a9 → your follow-up GET / returns the 404 for /unique-7f3a9 = prefix attached
TE.TE obfuscations: "TE : chunked" · "TE:\tchunked" · double TE · header folding
```

### Q95. CL.0 / connection-state cheat sheet.
```
CL.0:  POST /static/x.js  Content-Length: 34  \r\n\r\n  GET /admin HTTP/1.1\r\nFoo: bar   (BE ignores CL on /static)
conn-state routing:  req#1 Host: allowed.target  +  req#2 Host: internal-only.target (same connection) → internal route
conn-state validation: benign req#1 (passes) + privileged req#2 (inherits trust) on one connection
(use Burp HTTP Request Smuggler "single connection" / Turbo Intruder pipeline; compare fresh vs reused connection)
```

### Q96. Exploitation cheat sheet.
```
REQUEST CAPTURE (§9): smuggle to a store/reflect endpoint → victim's request appended → read Cookie/Auth (own session proof)
WAF/AUTH BYPASS (§10): smuggle GET /admin or a WAF-blocked payload to the back-end only
CACHE POISONING (§11): cache a malicious response under a victim URL (prove on a benign/unique key)
RESPONSE-QUEUE POISONING (§12): victim gets your response / you get theirs (own-traffic proof only)
INTERNAL → RCE/CLOUD (§13): smuggle to a back-end code-exec/SSRF/metadata endpoint → SSRF/SSTI/cmdi kit
```

### Q97. Do-no-harm cheat sheet.
```
[ ] timing detection FIRST (no socket poisoning)
[ ] deterministic differential on YOUR OWN connection
[ ] benign prefixes ; OWN second session/connection for capture
[ ] cache poison on a UNIQUE/non-shared key only ; queue poison on OWN traffic only
[ ] NO sustained smuggles against production ; restore connection state ; prove capability then STOP
```

---

# REAL-WORLD & REFERENCES

### Q98. Real-world smuggling research / patterns.
- PortSwigger **"HTTP Desync Attacks"** (Kettle, 2019) — CL.TE/TE.CL across many CDN/proxy stacks → request hijack & cache poison.
- **"HTTP/2: The Sequel is Always Worse"** (Kettle, 2021) — H2.CL/H2.TE/CRLF downgrade desync on "H1-safe" sites.
- **"Browser-Powered Request Smuggling"** (Kettle, 2022) — CL.0 & client-side desync; the victim's browser does the smuggling.
- Stacks historically affected: mismatched front-end (Cloudflare/Akamai/Fastly/ALB/HAProxy/nginx) ↔ origin parsing (match your chain; reproduce SAFELY).
- Impact chains: request capture → ATO; WAF bypass → /admin/internal → RCE; cache/queue poisoning → mass XSS/credential leak.

### Q99. Resources to work through.
PortSwigger Web Security Academy → **HTTP request smuggling** (do all labs: CL.TE/TE.CL/TE.TE, response queue, H2 desync, CL.0/browser-powered) and James Kettle's three research papers; `defparam/smuggler`; Burp **HTTP Request Smuggler** + Turbo Intruder docs; HackTricks / PayloadsAllTheThings *Request Smuggling*. Read disclosed reports tagged "request smuggling / desync".

---

# DEFENSE — PREVENTING DESYNC

### Q100. What's the core fix?
Make the front-end and back-end **agree on request framing**. **Normalize or reject** ambiguous requests at the edge: reject requests with **both** `Content-Length` and `Transfer-Encoding`, reject **obfuscated** `TE`, reject invalid chunking, and forward a single canonical framing to the origin. Use the **same** parser/strict RFC parsing on both tiers.

### Q101. How do I prevent HTTP/2 downgrade desync?
Prefer **HTTP/2 end-to-end** (don't downgrade to HTTP/1.1 at the edge). If you must downgrade, **sanitize** the downgraded request: reject CRLF and invalid characters in HTTP/2 header values and pseudo-headers, and don't propagate attacker-supplied `CL`/`TE` that conflict with the H2 length.

### Q102. How do I prevent CL.0 / connection-state?
**CL.0:** ensure every tier consistently honors `Content-Length` (or rejects bodies) on all endpoints, including static/redirect handlers. **Connection-state:** apply routing **and** validation/authentication **per request**, not per connection — don't cache a per-connection decision for subsequent requests. Where feasible, **disable back-end connection reuse** (one request per upstream connection) to remove the "next request" entirely.

### Q103. One-paragraph summary you can quote.
*"Request smuggling exists because two servers on the path disagree about where a request ends — so the fix is to make them agree: normalize or reject ambiguous framing at the edge (no both-CL-and-TE, no obfuscated Transfer-Encoding, no invalid chunking), use the same strict parser on the front-end and back-end, and prefer HTTP/2 end-to-end rather than downgrading to HTTP/1.1 (and if you must downgrade, sanitize CRLF and conflicting lengths). Honor Content-Length consistently on every endpoint (including static/redirect handlers) to kill CL.0, apply routing and authentication per-request rather than per-connection to kill connection-state attacks, and disable back-end connection reuse where you can. A single framing disagreement on a shared connection can otherwise let an attacker hijack other users' requests and sessions, bypass your WAF and authentication to reach internal systems, and poison your cache for every visitor — so it must be tested and reported with care to avoid harming the very users it endangers."*

---

## APPENDIX — 60-second request-smuggling field checklist
```
[ ] Recon: front-end+back-end chain (Via/X-Cache/CF-RAY) ; keep-alive/H2 ; reflection/store · restricted/WAF · cacheable endpoints
[ ] SAFE detect: TIMING first (no poisoning) ; then a DETERMINISTIC differential on YOUR OWN connection (repeat)
[ ] Technique: CL.TE/TE.CL byte-exact (auto-CL OFF) ; TE.TE obfuscations ; H2.CL/H2.TE/CRLF downgrade
[ ] Modern: CL.0/0.CL (body→next-request on static/redirect) ; client-side desync (browser) ; connection-state (1st-req routing/validation)
[ ] Confirm: smuggled prefix attaches to a follow-up predictably ; measure reliability
[ ] Impact (benign, own connections): request capture→ATO · WAF/auth bypass→internal/admin→RCE · cache poison (unique key) · response-queue poison (own traffic)
[ ] DO NO HARM: no sustained smuggles ; own sessions/connections ; benign markers ; prove the CAPABILITY then STOP
[ ] Report: byte-exact reqs + timing + differential + ONE exploit ; CWE-444 (+79/384/918/94) ; one finding per primitive
```
*End of guide.*
