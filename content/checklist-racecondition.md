# Race Condition — Checklist

Expert per-attack **test-case matrix** for Race Condition — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*13 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## RACE-001 — List limited actions + name the invariant + check HTTP/2
**Test Category:** Recon &amp; Lab · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** money, OTP/2FA/reset, coupon/bonus, vote, stock, state-machine actions

**Test Steps:** 1. List limited/once-only/stateful actions; for each write the INVARIANT it protects (balance&gt;=0, coupon used once, &lt;=5 OTP tries, unique, stock&gt;=0).<br>2. Confirm protocol: HTTP/2 (single-packet viable) via curl -sI --http2.<br>3. Capture a clean request per candidate; note any 'processing' delay (wider window). Own accounts only.

**Expected Result:** A target list with each action's invariant and the raceable protocol confirmed.

**Payload Example:**

```
curl -sI --http2 $URL | head -1 -> HTTP/2 ; invariant: 'coupon used once'
```

**Impact:** You cannot race a rule you haven't named; the invariant is the whole yardstick.

**Tools:** curl --http2, Burp

**References:** CWE-362; OWASP Testing Guide: Testing for Race Conditions (WSTG-BUSL-07)

---

## RACE-002 — Baseline — control 1x (read the invariant)
**Test Category:** Baseline (control first) · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** The chosen action

**Test Steps:** 1. Run the action ONCE, the intended way; record the response AND the invariant value after (balance/count/used/attempts).<br>2. Confirm you can READ the invariant before and after.<br>3. This clean 1x baseline is what makes the race un-false-positive-able.

**Expected Result:** A clean '1x -&gt; expected invariant value' baseline is recorded.

**Payload Example:**

```
balance 100 -> apply coupon -> balance 90, used=true
```

**Impact:** Skipping the control is the #1 rookie mistake; you can't recapture a clean baseline later.

**Tools:** Burp Repeater

**References:** CWE-362; PortSwigger Research: Smashing the state machine (single-packet attack)

---

## RACE-003 — Land the race — single-packet parallel burst
**Test Category:** Landing the Race · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** HTTP/2 endpoints

**Test Steps:** 1. Burp group -&gt; duplicate 20-30x -&gt; 'Send group in parallel' (auto single-packet on HTTP/2 / last-byte-sync on HTTP/1.1).<br>2. Connection-warm first (throwaway request) so raced requests land tight.<br>3. Re-read the INVARIANT vs the 1x control - not the 200s.

**Expected Result:** N requests land in one sub-millisecond window (&gt;1 success on a once-only action).

**Payload Example:**

```
Burp: add 20-30 identical requests to group -> Send group in parallel
```

**Impact:** Making requests arrive together is the craft; a normal loop never collides.

**Tools:** Burp (single-packet), Turbo Intruder

**References:** CWE-362; PortSwigger Research: Smashing the state machine (single-packet attack)

---

## RACE-004 — Widen the window when only ONE success
**Test Category:** Landing the Race · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Endpoints that appear 'locked' (one success)

**Test Steps:** 1. One success can mean LOCKED or too-thin a window - widen before concluding safe.<br>2. Pick the SLOW variant (external API/payment/email/scan between check and commit); inflate the body; warm the connection.<br>3. Behind a load balancer, target SHARED-state (DB/Redis) actions, not per-node in-memory counters.

**Expected Result:** A wider window turns a single success into multiple, or fairly confirms 'locked'.

**Payload Example:**

```
slow variant + inflated body + warm conn ; target DB/Redis shared state
```

**Impact:** Mistaking a thin window for 'safe' is the #1 way real races get missed.

**Tools:** Turbo Intruder

**References:** CWE-362; PortSwigger Research: Smashing the state machine (single-packet attack)

---

## RACE-005 — Financial double-spend
**Test Category:** Impact — Financial · **Severity:** Critical · **CVSS:** 9.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** withdraw/transfer/refund/coupon/credit actions

**Test Steps:** 1. Race withdraw/transfer/refund &gt; balance -&gt; negative balance / money created.<br>2. Coupon/credit applied N times ('used' flag true but credited multiple times).<br>3. Control (1x) vs parallel (N) delta on the ledger; repeat 2-3x. Own funds only, revert.

**Expected Result:** The balance goes negative / a once-only credit is applied N times.

**Payload Example:**

```
apply SAVE10 x20 in one packet -> balance 100-(20x10) = -100 ; withdraw > balance
```

**Impact:** Money creation / double-spend - Critical financial impact.

**Tools:** Turbo Intruder, Burp group

**References:** CWE-362; CWE-841; HackTricks: Race Condition

---

## RACE-006 — OTP/2FA/reset rate-limit brute-race -&gt; ATO
**Test Category:** Impact — Security Gate · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** OTP/2FA/reset/login verify endpoints (own account)

**Test Steps:** 1. Queue a DIFFERENT guess per parallel request so they all pass 'attempts&lt;5' before the counter ticks.<br>2. Win = far more attempts accepted than the cap, and/or a success beyond the limit.<br>3. Chains OTP/2FA brute -&gt; account takeover. Bounded, own account.

**Expected Result:** Many more OTP attempts are processed than the documented cap.

**Payload Example:**

```
Turbo: queue otp 000..999 behind one gate -> openGate ; >cap attempts accepted
```

**Impact:** Rate-limit bypass -&gt; OTP/2FA brute -&gt; account takeover - High/Critical.

**Tools:** Turbo Intruder

**References:** CWE-362; CWE-307; PortSwigger Research: Smashing the state machine (single-packet attack)

---

## RACE-007 — Predictable / time-seeded token collision -&gt; ATO
**Test Category:** Impact — Security Gate · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Password-reset / magic-link token issuance

**Test Steps:** 1. Spot weak randomness first (request several tokens: shared prefix / time-correlation / increment = predictable).<br>2. Issue the reset token for VICTIM and for YOUR OWN account in the SAME packet -&gt; time/seed-derived tokens collide.<br>3. The token mailed to YOU is also the victim's -&gt; reset -&gt; ATO.

**Expected Result:** Simultaneous victim+self token issuance produces the same token.

**Payload Example:**

```
queue reset(victim) + reset(me) behind one gate -> collide -> my token unlocks victim
```

**Impact:** Account takeover via token collision (weak randomness) - High/Critical.

**Tools:** Turbo Intruder

**References:** CWE-362; CWE-330; PortSwigger Research: Smashing the state machine (single-packet attack)

---

## RACE-008 — OAuth single-use code / token reuse race
**Test Category:** Impact — Security Gate · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N)

**Where to Test / Injection Point:** The OAuth /token exchange (code -&gt; access_token)

**Test Steps:** 1. Group the /token exchange, duplicate x10-20, 'Send group in parallel'.<br>2. Win = the SAME single-use code mints MULTIPLE access tokens.<br>3. Same idea for one-time magic-links / email-verify.

**Expected Result:** One single-use authorization code yields multiple access tokens.

**Payload Example:**

```
parallel /token with the same code -> >1 access_token issued
```

**Impact:** Token replay / session reuse / account-linking abuse - High.

**Tools:** Burp group

**References:** CWE-362; PortSwigger Research: Smashing the state machine (single-packet attack)

---

## RACE-009 — File-upload TOCTOU -&gt; RCE
**Test Category:** Impact — TOCTOU RCE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Uploads written to a web-reachable path before scan/rename/move

**Test Steps:** 1. Queue the webshell upload PLUS a flood of GETs at its predicted URL in one window.<br>2. Payload is a BENIGN marker (&lt;?php echo 'RC-'.(7*7); ?&gt; -&gt; RC-49), not a real shell.<br>3. Win = a GET returns RC-49 before the scanner removes/renames. If the name is random, race the temp/quarantine path.

**Expected Result:** A GET executes the uploaded file before the server cleans it up.

**Payload Example:**

```
Turbo: queue upload(shell.php) + 50x GET /uploads/shell.php behind one gate -> RC-49
```

**Impact:** The one race that reaches code execution - Critical RCE.

**Tools:** Turbo Intruder, FileUpload kit

**References:** CWE-362; CWE-367; HackTricks: Race Condition

---

## RACE-010 — Uniqueness / one-per-user / state-machine / multi-endpoint
**Test Category:** Impact — Business Logic · **Severity:** High · **CVSS:** 7.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N)

**Where to Test / Injection Point:** bonus/referral, unique-email signup, vote, stock/seat; two ops on one state

**Test Steps:** 1. Uniqueness: bonus claimed N times / multiple accounts on one unique email / vote inflation / oversell.<br>2. State-machine: act on a half-built object; approve-while-pending; role-change race.<br>3. Multi-endpoint: collide two operations on one state (credit-use + checkout) via two gated templates.

**Expected Result:** An invariant (unique/limit/state) is broken by the parallel burst.

**Payload Example:**

```
claim bonus x20 ; queue credit/use + checkout behind one gate -> credit counts twice
```

**Impact:** Fraud / oversell / privilege or state abuse - High.

**Tools:** Turbo Intruder (multi-endpoint)

**References:** CWE-362; CWE-841; HackTricks: Race Condition

---

## RACE-011 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: idempotent N*200 with the invariant UNCHANGED; a single-success/'locked' burst (widen first); client-only effects; non-reproducible; impact-less.<br>2. REQUIRE: a CONTROL(1x) vs PARALLEL(N) delta on the INVARIANT (state read-out, not statuses), repeated &gt;=2-3x.<br>3. Converts to money / ATO / business harm.

**Expected Result:** Only reproducible state-breaking races with real impact survive.

**Payload Example:**

```
N*200 unchanged = not a race ; one success = widen or drop ; not reproducible = drop
```

**Impact:** Protects credibility; races are dense with idempotent-200 and single-success false positives.

**Tools:** manual

**References:** CWE-362; PortSwigger Research: Smashing the state machine (single-packet attack)

---

## RACE-012 — Client-facing impact &amp; SAFE PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Title names action + broken invariant + impact ('Coupon double-spend via single-packet race -&gt; negative balance').<br>2. Provide the control (1x) + parallel (N) burst (Turbo script/Burp group) + before/after INVARIANT state; quantify value/scale; note the ~N/N success rate.<br>3. Set CVSS 3.1 (AC:H expected) + CWE-362 (+367 TOCTOU + outcome CWE). Remediation: atomic DB transactions / row locks / unique constraints / idempotency keys, server-side rate-limit on shared state.<br>4. Own funds/accounts, bounded bursts, revert state; de-dupe.

**Expected Result:** A reproducible, correctly-rated PoC with state read-out and clear remediation.

**Payload Example:**

```
PoC: control(1x) + parallel(N) + before/after invariant + CVSS + CWE-362 + remediation.
```

**Impact:** Converts the broken invariant into a defensible Critical/High report at the right value.

**Tools:** CVSS calculator, RACE_CONDITION_REPORT_TEMPLATE.md

**References:** CWE-362; CWE-367; FIRST CVSS v3.1; OWASP Testing Guide: Testing for Race Conditions (WSTG-BUSL-07)  |  TOP REFERENCES: James Kettle 'Smashing the State Machine' (PortSwigger Research, BlackHat 2023); Turbo Intruder; OWASP WSTG; disclosed race-to-ATO writeups

---

## RACE-013 — Resource-lock / handle exhaustion via mid-operation exception (A10:2025)
**Test Category:** Impact — Security Gate · **Severity:** Medium · **CVSS:** 6.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N)

**Where to Test / Injection Point:** Operations that acquire a lock/handle/connection then may throw before release (CWE-636/400)

**Test Steps:** 1. Find an operation that grabs a resource (DB txn, file handle, row lock, connection) then does risky work<br>2. Cause an exception mid-operation (malformed/oversized input, killed upload, interrupted step)<br>3. Check whether the lock/handle/connection is released on error or leaked<br>4. Repeat to exhaust the pool -&gt; denial of service (measure, don't sustain)

**Expected Result:** Resources released in finally/using; pool bounded; errors don't leak handles

**Payload Example:**

```
Interrupt a chunked upload mid-stream x N  ->  file handles / DB connections held
```

**Impact:** Exception-driven resource-lock leak -&gt; connection/handle exhaustion -&gt; DoS

**Tools:** Burp Suite, custom script

**References:** CWE-636; CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP Top 10:2025 A10 (Mishandling of Exceptional Conditions)

---
