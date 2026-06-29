# Race Conditions (TOCTOU & Limit-Overrun) — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Web apps & APIs where concurrent requests can collide — payments/wallets, coupons/gift-cards, votes/likes, withdrawals/transfers, redemptions, invites/referrals, rate-limit & OTP/2FA gates, file uploads, account/state machines, multi-step flows
**Platforms:** Burp Suite (Repeater "send group in parallel" + Turbo Intruder); HTTP/2 single-packet & HTTP/1.1 last-byte-sync; Kali/Windows helper scripts provided
**Companion files in this folder:**
- `RACE_CONDITION_ARSENAL.md` — Turbo Intruder scripts, single-packet recipes, curl/h2 one-liners, detection patterns
- `RACE_CONDITION_CHECKLIST.md` — the per-endpoint testing-order checklist
- `RACE_CONDITION_REPORT_TEMPLATE.md` — the report skeleton (parallel-evidence front-and-center)
- `poc/` — ready Turbo Intruder templates (single-packet / pitchfork) + a benign parallel-fire helper
- `Race_Condition_Attacks_Zero_to_Expert.md` — Q&A study + field reference

> **Companion to the IDOR / CSRF / JWT guides.** Same philosophy: *find* is Part I–III, *get paid* is Part IV. Race conditions are the class where **timing is the exploit**: the app's logic is correct *sequentially* but breaks when two requests hit the same state **in the same instant**. The expert skill is (1) finding the **limited/once-only** action, (2) firing N requests so they land **inside the same race window** (HTTP/2 **single-packet attack**), and (3) proving the **anomalous side effect** (you redeemed one coupon five times, withdrew more than your balance, bypassed a rate limit) with a clean, control-baselined PoC.

---

> ### ⚡ READ THIS FIRST — the four ideas that turn "maybe a race" into a paid bug
> 1. **A race condition = a check and an action that aren't atomic.** The server *checks* ("coupon unused?", "balance ≥ amount?", "OTP attempts < 5?") then *acts* (mark used, debit, increment). If you slip many requests between the check and the action, they **all** pass the check before any of them acts → **limit overrun** (TOCTOU, §2).
> 2. **The window is tiny — you must land requests together.** Sending requests "fast" in a loop isn't enough; network jitter spreads them out. Use the **HTTP/2 single-packet attack** (20–30 requests in one TCP packet → they arrive simultaneously) or **HTTP/1.1 last-byte-synchronization** (send all but the final byte of each, then release the last bytes together). Burp Repeater's **"Send group in parallel"** does this for you (§1, §6). (Technique: PortSwigger / James Kettle, 2023.)
> 3. **Prove it with a control baseline.** One success is normal. The bug is **>1 success** where only one should be possible: 2+ redemptions of a single-use code, a balance that goes **negative**, 6 OTP guesses where the limit is 5, two accounts created with the same unique email. Always run a **single-request control** first, then the parallel burst, and show the delta (§4, §19).
> 4. **The money is in *limited* and *irreversible* actions.** Money/credits (double-spend), security gates (OTP/2FA/rate-limit bypass → ATO), and uniqueness invariants (one-per-user becomes many) pay. "I sent 10 requests and got 10 OK" on an idempotent action is **not** a finding (§20).
>
> **Where the money is (memorize this order):** ① **File-upload TOCTOU → RCE** (the one race that reaches code execution — access the upload in the window before it's scanned/renamed; §12.4) → ② **Financial double-spend** (withdraw/transfer/refund/gift-card/coupon overrun → real loss) → ③ **Security-gate races** (OTP/2FA/password-reset/rate-limit bypass, **predictable-token collision**, OAuth single-use-code reuse → **account takeover**; §10) → ④ **Limit/uniqueness bypass with business impact** (one-per-user promo claimed N×, votes/likes inflation, invite abuse) → ⑤ **Privilege/state races** (approve-while-pending, role change, partial-construction) → ⑥ *then* low-value idempotent overruns as **Low/Info**.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [Race Condition Anatomy — TOCTOU, Windows & Sub-Types](#2-race-condition-anatomy--toctou-windows--sub-types)
3. [Reconnaissance — Find Limited / Stateful Actions](#3-reconnaissance--find-limited--stateful-actions)
4. [Baseline — Control vs Parallel (the oracle)](#4-baseline--control-vs-parallel-the-oracle)

**PART II — LANDING THE RACE (techniques, in order of reliability)**
5. [The Single-Packet Attack (HTTP/2)](#5-the-single-packet-attack-http2)
6. [Burp "Send Group in Parallel" & Turbo Intruder](#6-burp-send-group-in-parallel--turbo-intruder)
7. [HTTP/1.1 Last-Byte Synchronization](#7-http11-last-byte-synchronization)
8. [Multi-Endpoint & Connection-Warming Nuances](#8-multi-endpoint--connection-warming-nuances)

**PART III — VARIANTS & EXPLOITATION BY IMPACT (where the money is)**
9. [Limit-Overrun / Double-Spend (financial)](#9-limit-overrun--double-spend-financial)
10. [Security-Gate Races — OTP / 2FA / Rate-Limit / Reset → ATO](#10-security-gate-races--otp--2fa--rate-limit--reset--ato)
11. [Uniqueness & One-Per-User Bypass](#11-uniqueness--one-per-user-bypass)
12. [State-Machine / Partial-Construction Races](#12-state-machine--partial-construction-races)
13. [Multi-Endpoint Races (cross-action)](#13-multi-endpoint-races-cross-action)

**PART IV — VALIDITY, SEVERITY & REPORTING**
14. [The Escalation Mindset](#14-the-escalation-mindset)
15. [The Validity-First Mindset — the Control Baseline](#15-the-validity-first-mindset--the-control-baseline)
16. [False Positives — STOP reporting these](#16-false-positives--stop-reporting-these-auto-reject-list)
17. [Severity Calibration](#17-severity-calibration--how-triagers-rate-races)
18. [Impact-Escalation Playbooks — "you found X, now do Y"](#18-impact-escalation-playbooks--you-found-x-now-do-y)
19. [Building a Professional PoC](#19-building-a-professional-poc)
20. [Reporting, CWE/CVSS & De-duplication](#20-reporting-cwecvss--de-duplication)
21. [Automation & Red-Team Notes](#21-automation--red-team-notes)

**Appendices**
- [Appendix A — Race Workflow Cheat Sheet](#appendix-a--race-workflow-cheat-sheet)
- [Appendix B — Race Decision Tree](#appendix-b--race-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Each phase says *what to do*, *which § for detail*, and the *deliverable*.

```
PHASE 0  RECON & LAB        → find LIMITED / once-only / stateful actions (§3) ·
                              HTTP/2 target? Burp set up for parallel/single-packet (§1)
PHASE 1  BASELINE  ★        → run the action ONCE (control): what's the normal result &
                              the invariant it should hold (balance, count, used-flag)? (§4)
PHASE 2  LAND THE RACE      → fire N requests INTO the same window:
                              single-packet HTTP/2 (§5) · Burp parallel / Turbo Intruder (§6) ·
                              HTTP/1.1 last-byte-sync (§7) · multi-endpoint nuances (§8)
PHASE 3  IMPACT  ⭐ (money)  → turn the overrun into harm:
                              double-spend (§9) · OTP/2FA/rate-limit/reset → ATO (§10) ·
                              one-per-user bypass (§11) · state/partial-construction (§12) · multi-endpoint (§13)
PHASE 4  VALIDATE → REPORT  → ★ CONTROL vs PARALLEL delta, repeatable (§15) · FP filter (§16) ·
                              severity+CVSS+CWE-362/367 (§17) · clean PoC (§19) · dedup (§20)
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon & lab.** Enumerate **limited/once-only/stateful** actions (§3): anything with a counter, a balance, a "used" flag, a uniqueness constraint, or a rate/attempt limit. Confirm the target speaks **HTTP/2** (best window) and set Burp up for parallel sends (§1). *Deliverable:* a list of candidate endpoints + the invariant each is supposed to protect.
2. **PHASE 1 — Baseline ★.** Fire the action **once** and record the normal outcome and the **invariant** (balance after, count after, used→true). *Deliverable:* the "should only happen once" ground truth.
3. **PHASE 2 — Land the race.** Send **N parallel** requests into the same window via single-packet (§5)/Burp parallel (§6)/last-byte-sync (§7). *Deliverable:* multiple requests proven to arrive together (look at timing, or simply >1 success).
4. **PHASE 3 — Impact ⭐.** Make the overrun *hurt*: double-spend (§9), bypass an OTP/2FA/rate-limit/reset gate → ATO (§10), claim a one-per-user reward N× (§11), drive a state machine into an invalid state (§12), or collide two different endpoints (§13). *Deliverable:* a demonstrated high-impact anomaly.
5. **PHASE 4 — Validate → report.** Show the **control (1×) vs parallel (N×)** delta, **repeat it** to prove it's not a fluke (§15), apply the FP filter (§16), set CVSS/CWE-362 (§17), ship a clean PoC (§19), de-dup (§20). *Deliverable:* the submitted report.

Reference anytime: scripts → `RACE_CONDITION_ARSENAL.md` & `poc/`; checklist → `RACE_CONDITION_CHECKLIST.md`; playbooks **§18**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

Races are **timing-validated** — the whole game is making requests arrive **simultaneously**. A loop with `curl` won't do it; you need a tool that synchronizes the final bytes.

| Tool | Job |
|------|-----|
| **Burp Suite** (2023.9+) | **"Send group in parallel"** in Repeater = one-click HTTP/2 single-packet / HTTP/1.1 last-byte-sync. The fastest way to test a race. |
| **Turbo Intruder** (Burp ext) | scripted high-concurrency races: `race-single-packet.py`, `examples.py`; gate-and-release, many requests, custom logic |
| **HTTP/2 endpoint** | the single-packet attack needs h2 (or h3). Confirm with `curl -sI --http2 https://target` / Burp's protocol column |
| **Two+ accounts / objects** | for per-account limits, coupons, transfers — and to keep PoCs on **your own** balances |
| **A measurable invariant** | balance, count, used-flag, attempt-counter — something you can read **before and after** (§4) |
| **interactsh / logs** | confirm async side effects (webhooks, emails) for state races |

```bash
# Is the target HTTP/2 (best race window)?
curl -sI --http2 https://target.com/ | head -1     # "HTTP/2 200" → single-packet attack viable
```
> **The cardinal rule of race tooling:** *requests must land in the same window.* Use **single-packet (HTTP/2)** when available — it removes network jitter by putting ~20–30 requests in **one TCP packet**. Fall back to **last-byte-sync (HTTP/1.1)**. "Send group in parallel" in Burp picks the right one automatically (§5–§7).

> **Windows:** Burp + Turbo Intruder run natively; the Python `poc/` helper runs in WSL or native Python (needs an async HTTP/2 client like `httpx[http2]`). Keep test balances/coupons on **your own** accounts.

---

# 2. Race Condition Anatomy — TOCTOU, Windows & Sub-Types

## 2.1 What a race condition is (one paragraph)
Two or more operations access **shared state** concurrently, and the outcome depends on **ordering/timing** the developer didn't account for. The classic shape is **TOCTOU** (Time-Of-Check to Time-Of-Use): the server **checks** a condition, then **acts** on it, and the two steps aren't **atomic**. If your requests interleave so several pass the check **before** any performs the action, the invariant the check was protecting is violated.

## 2.2 The race window
The exploitable gap between check and action. It's usually **sub-millisecond**, which is why you can't hit it by looping — you must deliver requests **simultaneously** (§5–§7). A wider window (slow DB, external call between check and commit, no row lock) = easier race.

## 2.3 The sub-types (test all that apply)
- **Limit-overrun / double-spend** — a once/limited action performed N× (coupon, gift-card, withdraw, refund, transfer, vote, like, invite). The bread-and-butter, usually financial (§9).
- **Security-gate race** — bypass an attempt/rate limit: OTP/2FA brute beyond the cap, password-reset token reuse, login throttle, CAPTCHA gate → **ATO** (§10).
- **Uniqueness bypass** — a "one per user / unique email / single signup bonus" invariant becomes many via simultaneous creates (§11).
- **State-machine / partial-construction** — act on an object **before it's fully created or locked** (use a half-initialized cart/order/account; approve-while-pending; cancel-and-use) (§12).
- **File-upload TOCTOU** — access an uploaded file in the window **between upload and validation/scan/rename/delete** → run a webshell → **RCE** (§12.4). *The highest-impact race.*
- **Time-sensitive / predictable-token** — two requests in the same instant get the **same time/seed-derived value** (e.g. a password-reset token from the server clock) → leak/reuse the victim's token → **ATO** (§10.5).
- **Multi-endpoint race** — collide **two different** operations on the same state (e.g. "apply credit" + "checkout", "add to group" + "leave") (§13).

## 2.4 The 2026 mental model
- **Single-packet attack changed the game (2023).** Before it, races needed many connections and luck; now **20–30 requests in one HTTP/2 packet** arrive within ~1ms of each other on commodity links. Most "can't reproduce" races from a few years ago are now reliably exploitable.
- **Idempotency ≠ no race.** An endpoint can be idempotent in result yet still race on a **side counter** (rate limit, bonus). Test the *invariant*, not just the response.
- **The proof is a delta, not a vibe.** Always: control (1×) → parallel (N×) → show the invariant broke (negative balance, 2× redemption, 6th OTP accepted).

---

# 3. Reconnaissance — Find Limited / Stateful Actions

**Goal:** a list of actions that are supposed to happen **once / a limited number of times / atomically**, each with the **invariant** it protects.

**3.1 Hunt the "limited" verbs.** Anything with a cap, a balance, a uniqueness rule, or an attempt counter:
- **Money/credits:** withdraw, transfer, pay, refund, top-up, convert, cash-out, apply gift-card/coupon/credit, claim bonus/cashback.
- **Security gates:** OTP/2FA verify, password-reset token submit/issue, login, email/phone verify, CAPTCHA-gated actions, anti-bruteforce counters; **OAuth `code`→token exchange** and **single-use token** consumption (§10.6); **predictable/time-seeded token** issuance (§10.5).
- **Uniqueness/limits:** signup bonus, one-vote/one-like/one-review-per-user, "first N users", referral/invite limits, seat/quantity/stock, redeem-once links.
- **State changes:** accept/decline, approve/publish, cancel, lock/unlock, role/permission change, finalize/checkout; **disable-2FA / change-email confirmation** windows.
- **File/code:** file/avatar/document **upload → scan/validate/rename/move** pipelines — the gap between "written to disk" and "validated/quarantined" is a **TOCTOU → RCE** window (§12.4).

**3.2 For each, record the invariant.** "Coupon usable once", "balance never < 0", "≤5 OTP attempts", "1 bonus per account", "stock ≥ 0". This is what you'll try to violate (and what the report measures).

**3.3 Prefer multi-step / slow paths.** Actions that do an external call or heavy work **between** check and commit have a **wider** window (easier). Note any "processing…" delays.

**3.4 Capture a clean request per candidate** (Burp) — you'll duplicate it into a parallel group (§6).

> *Deliverable:* `endpoint | action | invariant | per-account or global? | window hints`.

---

# 4. Baseline — Control vs Parallel (the oracle)

This is what makes a race **un-false-positive-able**: a measured delta between one request and many.

**4.1 The control (1×).** Fire the action **once**. Record: the response, and the **invariant value after** (balance, count, used-flag, attempts). E.g. apply coupon once → balance −$10, coupon `used=true`.

**4.2 The parallel burst (N×).** Send **N identical** requests into the same window (§5–§7). Re-read the invariant.
- **IF** the invariant broke (balance −$50 from 5 parallel applies of a once-coupon; `used` flipped but credited 5×; OTP attempt 6 accepted; 2 accounts with the same unique email) → **race confirmed.**
- **IF** only one succeeded and N−1 were rejected → the action is **properly locked**; not a race (try a wider-window variant or move on).

**4.3 Repeat to prove reliability.** Re-run the burst 2–3× (reset state between). A one-off success can be coincidence; a **repeatable** delta is the bug (§15).

**4.4 The verdict you produce here:** per endpoint — `RACE (overrun x N)`, `LOCKED (atomic)`, or `WIDEN-WINDOW (retry with more concurrency / multi-endpoint)`.

> **Measure the invariant, not the HTTP status.** Many race wins return the *same* 200 as a normal request; the proof is the **state** (balance/count), read before and after.

---

# PART II — LANDING THE RACE (techniques, in order of reliability)

# 5. The Single-Packet Attack (HTTP/2)

**The single best technique (PortSwigger / James Kettle, 2023).** Over HTTP/2 you can place **~20–30 requests in one TCP packet**; the server receives them essentially simultaneously, eliminating network jitter and hitting the same sub-ms window.

**5.1 How it works.** HTTP/2 multiplexes many requests on one connection. You withhold each request's last frame, then send all the final frames **in a single packet** → the server processes them together.

**5.2 How to fire it.**
- **Burp Repeater:** add the request to a **group** (tab → "Add to group"), duplicate it N times, then **"Send group in parallel"** — Burp uses single-packet automatically on HTTP/2.
- **Turbo Intruder:** `engine=Engine.BURP2`, `concurrentConnections=1`, gate the requests and release together (`engine.openGate` / `race-single-packet.py`).

**5.3 When to use it.** Whenever the target is HTTP/2 (or HTTP/3). It's the most reliable; try it first.

**5.4 Constraints (and when it falls back).** The single-packet trick batches roughly **20–30 requests** — bounded by the TCP **initial congestion window** (~10 packets) and the need for all the withheld final frames to ship in one go. It assumes each request is **small enough** that only its last frame is outstanding; a **large body / many big headers** can't be single-packeted cleanly. **IF** the target is **HTTP/1.1 only**, or the requests are large, or an intermediary (some CDNs/proxies) coalesces or buffers streams → **fall back to last-byte-sync (§7)**, raise N, and repeat. Burp's "Send group in parallel" auto-selects single-packet vs last-byte; if reproducibility is poor, that's usually a window/intermediary issue — widen the window (§8.5).

# 6. Burp "Send Group in Parallel" & Turbo Intruder

**6.1 Send group in parallel (the easy button).** Capture the request → right-click → **Add to group** → duplicate to N tabs (vary nothing for a pure overrun; vary the OTP/code for a brute-race) → **Send group in parallel**. Read the invariant after. This is the fastest manual race test and uses single-packet/last-byte-sync as appropriate.

**6.2 Turbo Intruder (scripted, high concurrency).** For larger N, varying payloads (OTP brute-race), or gate-and-release logic:
```python
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1,
                           engine=Engine.BURP2)            # HTTP/2 single-packet
    for i in range(30):
        engine.queue(target.req, gate='race1')             # hold at the gate
    engine.openGate('race1')                                # release together
def handleResponse(req, interesting):
    table.add(req)
```
(Full templates in `poc/` and the arsenal.)

**6.3 Reading results.** Sort responses by status/length/body. The race win is usually the **odd one out** (an extra 200, a different balance in the body) — but always confirm via the **invariant** (§4).

# 7. HTTP/1.1 Last-Byte Synchronization

When the target is **HTTP/1.1 only**, you can still synchronize: open N connections, send **all but the final byte** of each request, then release the **last bytes together**. The server completes parsing all requests at nearly the same instant.

- **Burp** "Send group in parallel" automatically uses last-byte-sync on HTTP/1.1.
- **Turbo Intruder** with multiple `concurrentConnections` + gating approximates it.
- Less precise than single-packet (per-connection jitter remains) — raise N and repeat.

# 8. Multi-Endpoint & Connection-Warming Nuances

**8.1 Connection warming.** The **first** request on a fresh connection is slower (TLS, server warm-up), which skews timing. Send a throwaway "warm-up" request first, or let Burp/Turbo handle it, so the raced requests are evenly fast.

**8.2 Multi-endpoint races (§13).** When the collision is between **two different** operations (e.g. "use credit" vs "checkout"), you can't put them in one single-packet group trivially — interleave with Turbo Intruder using two request templates and tight gating, or fire two parallel groups.

**8.3 Session/lock granularity.** Per-row locks defeat single-object races; look for actions that touch a **shared** row (a global counter, a shared wallet, a coupon table) or that **lock late**.

**8.4 Server-side queueing.** Some servers serialize per-connection; that's why **concurrentConnections=1 + single-packet** (parallel streams on one connection) often beats many connections.

**8.5 Widening the race window (when single-packet alone won't win).** A wider check→act gap = an easier race. Make the server spend longer between check and commit:
- **Pick the slow path.** Prefer the action that does heavy/synchronous work between check and commit — an external API/payment call, an email/SMS send, a file scan, a report build. Those "processing…" actions have windows orders of magnitude bigger than an in-memory decrement.
- **Inflate the request.** A larger body / extra (ignored) fields / a big but valid payload makes the server parse longer before it reaches the check — sometimes enough to align the burst.
- **Add latency upstream.** Where allowed, slow your own leg (last-byte-sync inherently delays parse completion) so all requests finish parsing together.
- **Connection-warm first (§8.1)** so the raced requests are uniformly fast.
> If a burst yields exactly one success ("LOCKED"), don't conclude "safe" yet — retry against the **slower** variant of the same operation and with a **wider** window before dropping it (§4.4 `WIDEN-WINDOW`).

**8.6 Distributed / load-balanced targets.** Behind a load balancer the requests may hit **different backend nodes**. Consequences: a limit enforced in **per-node in-memory state** (a local counter/cache) often **won't collide** across nodes — but a **shared database row** (wallet, coupon table, stock) **still does**. So: target actions whose invariant lives in **shared state** (DB/Redis), expect variance, and **raise N + repeat** to land enough requests on the colliding path. Conversely, a per-node in-memory rate-limit is itself frequently **bypassable** simply by spreading requests across nodes (a related, reportable weakness).

---

# PART III — VARIANTS & EXPLOITATION BY IMPACT (where the money is)

# 9. Limit-Overrun / Double-Spend (financial)

**9.1 The pattern.** A balance/credit/limit checked-then-decremented without a lock. Fire N parallel:
- **Withdraw/transfer/cash-out** more than your balance → **negative balance / money created**.
- **Apply a single-use coupon/gift-card/credit** N× → N× the discount/credit.
- **Refund** the same order N× ; **redeem** a one-time code N× ; **convert** points N×.

**9.2 Prove the loss.** Control: balance after 1× = X. Parallel: balance after N× = X−N·amount or **negative**. Show the wallet/ledger state. Keep it on **your own** funds; revert/withdraw nothing real.

**9.3 Escalate.** Quantify max extractable (per race × repeats), and whether it converts to **real money out** (the difference between High and Critical). Don't actually exfiltrate funds — demonstrate the mechanism and stop.

# 10. Security-Gate Races — OTP / 2FA / Rate-Limit / Reset → ATO

**10.1 OTP / 2FA brute-race.** The gate allows e.g. 5 attempts. Fire **many guesses in parallel** so they all read "attempts < 5" before the counter increments → effectively unlimited tries → brute a 4–6 digit OTP. **IF** one parallel burst lets you submit far more than the cap → rate-limit bypass → **ATO**.

**10.2 Password-reset token reuse / race.** Race the reset-submit so a single-use token is consumed by multiple requests, or so a just-issued token races a guess.

**10.3 Login / anti-bruteforce bypass.** Parallel logins bypass per-attempt throttling/lockout.

**10.4 CAPTCHA / one-time-action gates.** A CAPTCHA validated then consumed can be reused within the window.

**10.5 Time-sensitive / predictable-token collision (→ ATO).** A distinct, high-value race: when a secret is derived from the **server clock or a low-entropy seed**, two requests in the *same instant* get the **same value**. Classic: a **password-reset token = hash(timestamp)** (or a `uniqid()`/`mt_rand()` seeded by time).
- **The attack:** in one single-packet burst, trigger a reset for **the victim** *and* for **your own** account. Both tokens are generated in the same millisecond → **identical** → the token mailed to *you* is also the victim's → reset the victim's password → **ATO**. (Also applies to invite/verification/share tokens.)
- **How to spot it:** request several tokens and compare — do they share a prefix, increment, or track time? Short, time-correlated, or sequential tokens are the tell. **IF** simultaneous issuances collide → report the predictable-token race (CWE-330 + CWE-362).

**10.6 OAuth single-use code / token reuse (→ ATO / session issues).** An OAuth **authorization `code`** (and ideally any refresh/reset token) must be **single-use**. Race the **`code`→token exchange** (fire the same `code` N× in one packet): **IF** the server mints **multiple access tokens** for one code (or the PKCE/`state` check isn't atomic) → token/session reuse, replay, or account-linking abuse. Same idea for racing **one-time magic-link / email-verification** consumption.

> Security-gate races are usually **High/Critical** because they chain straight to **account takeover**. Pair with the OTP/credential context (often combine with an IDOR/known-username).

# 11. Uniqueness & One-Per-User Bypass

**11.1 Signup/referral bonus N×.** Race the "claim bonus" so one account claims it many times; or race account creation so a single unique email/phone yields multiple accounts/bonuses.

**11.2 One-vote/like/review.** Inflate counts by racing the "vote" past the one-per-user check (reputation/ranking abuse, contest fraud).

**11.3 Stock/seat oversell.** Race "add to cart"/"reserve" past available stock → oversell / inventory invariant break.

**11.4 Invite/seat limits.** Exceed plan seat limits or invite caps by racing the add.

> Impact varies — quantify the business harm (fraud, financial, ranking) to set severity.

# 12. State-Machine / Partial-Construction Races

**12.1 Act before fully created/locked.** Use a **half-initialized** object (cart/order/account) in another action before the server finishes setting it up — e.g. apply a discount to an order that's mid-creation, or use an account before email-verification flips a flag.

**12.2 Approve/cancel races.** "Approve while pending", "cancel-and-use", "publish-while-draft", "lock-while-editing" — collide the state transition with an action that assumes the old/new state.

**12.3 Role/permission change races.** Race a privilege change against an action that reads the old permission (or the new one prematurely) → priv-esc or unauthorized action.

**12.4 File-upload TOCTOU → RCE (the highest-impact race).** Many upload pipelines write the file to a **web-reachable path first**, then *asynchronously* validate / AV-scan / strip-EXIF / rename to a random name / move out of webroot / delete-if-bad. That gap is a TOCTOU window: **the malicious file is live and executable before it's neutralised.**
- **The attack:** in one burst, **upload** a webshell (e.g. `shell.php`, `.jsp`, `.aspx`, or a polyglot that passes the type check) **and simultaneously hammer GETs** at its predicted URL. **IF** a GET hits in the window **before** the validator renames/quarantines/deletes it → the shell executes → **RCE**.
```
group A: POST /upload   (multipart: shell.php with a benign-looking content-type / magic bytes)
group B: GET  /uploads/shell.php   ×N   (fire in the same single-packet window)
→ one GET returns the shell output before the scanner removes/renames it → RCE
```
- **Why it beats normal upload filters:** even when the app "correctly" rejects/cleans bad files, doing it **after** writing to a reachable path makes the cleanup a race you can win. Predictable filenames/paths (original name kept, sequential, timestamp) make the GET target known; if the final name is random, race the **read of the temp/quarantine path** instead.
- **Variants:** race **upload vs the "move out of webroot"** step; race **two uploads with the same name** (one valid, one shell) so the validated record points at the shell; race **avatar/CSV/import processors** that execute/parse server-side. Chain with the **File Upload** kit for the shell-crafting and bypasses.
> This is the one race that reaches **code execution** — report it Critical, with the upload + the winning GET (showing shell output) on **your own** account/test path, then stop (don't pivot further on production).

# 13. Multi-Endpoint Races (cross-action)

**13.1 Two operations, one state.** Collide different endpoints touching the same row: "use credit" + "checkout" (use the credit twice), "leave group" + "post as member", "delete" + "read", "deactivate" + "act". Interleave with Turbo Intruder (§8.2).

**13.2 Confirm the inconsistent state.** Show the resulting state is impossible sequentially (credit used twice, posted after leaving, acted after deactivation).

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 14. The Escalation Mindset

Every confirmed overrun has a "now do Y."
- Coupon/credit overrun → does it convert to **real money out** (cash/transfer/purchase)? → financial impact.
- OTP/rate-limit bypass → can you actually **take over** an account with it? → ATO.
- One-per-user → what's the **business** harm at scale (fraud, ranking, oversell)?
- Always: *what's the most valuable invariant this race breaks, and what's the worst real-world outcome?*

# 15. The Validity-First Mindset — the Control Baseline

> **The rule that saves your report:** show a measured **control (1×) vs parallel (N×) delta** on the **invariant**, and prove it's **repeatable**. "I sent many requests" is not evidence; "balance went negative / coupon credited 5× / 6th OTP accepted, reproduced 3×" is.

**The four questions a triager asks (answer them):**
1. **What invariant should hold?** (used-once, balance ≥ 0, ≤5 attempts, unique).
2. **What's the normal (1×) result?** (the control).
3. **What did the parallel burst produce?** (the broken invariant — with the state read-out).
4. **Is it repeatable?** (re-ran N times, reset between).

# 16. False Positives — STOP reporting these (auto-reject list)

| Pattern | Why it's NOT a valid race | What to do instead |
|---|---|---|
| **"I sent 10 requests, got 10 × 200"** on an idempotent action | No invariant broke; that's just concurrency | Measure the **invariant** (balance/count/flag), not the status |
| **Only one request succeeded, rest rejected** | The action is properly locked/atomic | Try a wider-window variant or drop |
| **Duplicate side effects with no impact** (e.g. two identical no-op log lines) | No security/business harm | Find a *limited/valuable* action |
| **Can't reproduce** (one lucky success) | Non-repeatable = not demonstrable | Re-run with single-packet; if never repeats, drop |
| **Client-side only** (UI lets you click twice but server dedupes) | Server is correct | Confirm at the API, with state |
| **Self-inflicted with no cross-impact** (you raced your own non-valuable counter) | No real-world harm | Aim at money/security/uniqueness invariants |
| **Race "possible in theory"** with no state delta | Theoretical | Show the measured before/after delta |

> If you can't show **a broken invariant, repeatably**, you don't have a race yet.

# 17. Severity Calibration — how triagers rate races

**CWE:** primary **CWE-362** (Concurrent Execution using Shared Resource with Improper Synchronization — 'Race Condition'); **CWE-367** (TOCTOU); related **CWE-841** (improper enforcement of behavioral workflow), and the *outcome* CWE (e.g. CWE-840 business-logic, or the ATO/financial CWE).

| Scenario | Typical severity | CVSS 3.1 vector (example) |
|---|---|---|
| **File-upload TOCTOU → RCE** (access before scan/rename) | **Critical** | `AV:N/AC:H/PR:L/UI:N/S:C/C:H/I:H/A:H` (~9; AC:H = timing) |
| **Financial double-spend → real money out** | **Critical/High** | `AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N` (~7–8; AC:H = timing) |
| **OTP/2FA/rate-limit / predictable-token / OAuth-code race → account takeover** | **High/Critical** | `AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N` (~8) |
| **Coupon/credit/bonus overrun (limited $ value)** | **Medium/High** | `…/I:H/A:N`, severity scales with extractable value |
| **One-per-user / vote / oversell (business abuse)** | **Medium** | `…/I:L–H`, depends on business impact |
| **State/partial-construction with security impact** | **Medium/High** | per outcome |
| **Idempotent overrun, no invariant broken** | **N/A** | not a finding (§16) |

> **AC:H is normal for races** (you need timing to win) — but a single-packet attack makes it *reliable*, so don't let "AC:H" talk you down if you reproduce it consistently. **Drivers:** value of the broken invariant × reproducibility × whether it converts to money/ATO. Lead with the **highest proven** row.

# 18. Impact-Escalation Playbooks — "you found X, now do Y"

**18.1 You found: a coupon applies 2× in parallel.** → Push N higher (single-packet, 20–30) to find the max multiplier → check it credits **real balance** → see if balance converts to **cash-out/purchase** → quantify loss per race × repeats → report as financial (state the $).

**18.2 You found: the OTP endpoint accepts a 6th attempt under parallel.** → Show you can submit **many** guesses per window → demonstrate brute-forcing a 4–6 digit code is now feasible → chain to **login/2FA bypass → ATO** → report High/Critical.

**18.3 You found: withdrawal lets balance go negative.** → Reproduce 3× → show the ledger negative / funds beyond balance → (don't cash out real money) → report Critical financial-integrity.

**18.4 You found: one-per-user bonus claimed N×.** → Quantify per-account gain × number of accounts → frame business/fraud impact → report Medium/High with the math.

**18.5 You found: a multi-endpoint inconsistency.** → Show the impossible sequential state (credit used twice / posted after leaving) → tie it to money or access → report with the two-template Turbo Intruder PoC.

**18.6 You found: "10×200 but nothing changed".** → That's not a race (§16). Re-target a **limited/valuable** action and measure the **invariant**, or drop.

**18.7 You found: an upload that's validated/scanned/renamed *after* it's written to a reachable path.** → Race the **upload vs the scan/rename/move** (§12.4): burst a webshell upload + many GETs at its predicted URL → catch one execution in the window → **RCE**. Demonstrate on **your own** account/test path with a benign marker (e.g. a script that prints a fixed token), capture the winning response, then **stop**. Report Critical.

**18.8 You found: short / time-correlated reset (or invite/verify) tokens.** → Issue several and confirm they track time/seed → in one burst, trigger the token for **the victim** and **your own** account simultaneously → if they collide, the token you receive is the victim's → reset → **ATO** (§10.5). Also race the **OAuth `code`→token** exchange for single-use reuse (§10.6).

# 19. Building a Professional PoC

**The non-negotiables:**
1. **Control first** — show the 1× normal result and the invariant value.
2. **Parallel burst** — the exact group/Turbo script (single-packet) and the **broken invariant** after (state read-out, not just 200s).
3. **Repeatable** — reproduced ≥2–3× with state reset between; note the success rate.
4. **Your own funds/accounts** — keep balances/coupons/bonuses on your test accounts; **don't** cash out real money or touch real users.
5. **Reversible & bounded** — revert state; don't drain inventory/funds; demonstrate the *mechanism*, not maximum damage.
6. A **Turbo Intruder script / Burp group** a triager can replay, plus before/after state screenshots.

```python
# Turbo Intruder — single-packet overrun PoC (apply once-only coupon N times)
def queueRequests(target, wordlists):
    engine = RequestEngine(endpoint=target.endpoint, concurrentConnections=1, engine=Engine.BURP2)
    for i in range(20):
        engine.queue(target.req, gate='g')       # withhold final frames
    engine.openGate('g')                           # release in one packet
def handleResponse(req, interesting):
    table.add(req)                                 # then re-read balance/coupon state to confirm overrun
```

# 20. Reporting, CWE/CVSS & De-duplication

- **Title** = `Race condition on <action> → <impact>` — e.g. *"Race condition on POST /wallet/withdraw → balance goes negative (double-spend)"*; *"Race on /2fa/verify → rate-limit bypass → OTP brute-force → ATO"*. Never just "race condition".
- **Lead with the control-vs-parallel delta and the impact** (money/ATO/business), and state **reproducibility**.
- **CWE-362** (+ CWE-367 TOCTOU, + outcome CWE). CVSS per §17 (AC:H is expected). Quantify value/scale.
- **De-dup:** one well-quantified financial/ATO race beats many "I got 2×200" notes. If the program knows about coupon-stacking, frame your **distinct invariant/impact** (e.g. negative balance, OTP bypass).

# 21. Automation & Red-Team Notes

**21.1 Coverage.** Turbo Intruder scripts can sweep many endpoints; but races reward **manual judgment** (you must know the invariant). Triage candidates from recon (§3), then race the valuable ones.

**21.2 Stealth / OPSEC (red-team & program rules).**
- **Bounded bursts** — a single-packet group of 20–30 is enough; don't hammer thousands of requests. Reproduce a few times, then stop.
- **Your own state** — race **your** balances/coupons/accounts; never drain real inventory, real funds, or affect other users.
- **No real money out** — demonstrate the negative balance / overrun mechanism; **do not** actually withdraw/transfer real funds.
- **Reset/clean up** — revert state, remove test artifacts.
- **Respect scope & rate** — some programs flag concurrency as abuse; keep bursts small and infrequent. Authorized targets only.

**21.3 Where races hide at scale:** wallets/ledgers, promo/coupon engines, OTP/2FA/reset gates, signup-bonus & referral systems, voting/likes, stock/seat reservations, and any "check-then-update" without a DB lock/atomic op.

---

# Appendix A — Race Workflow Cheat Sheet

```
0. Find LIMITED/once-only/stateful actions + the INVARIANT each protects.          §3
1. Is target HTTP/2? (single-packet viable)  Set Burp "Send group in parallel".     §1,§5
2. CONTROL: run action 1× → record invariant (balance/count/used/attempts).         §4
3. PARALLEL: 20–30 reqs in one window (single-packet / Burp parallel / last-byte).  §5-§7
4. Re-read invariant: broke? (RACE)  only 1 ok? (LOCKED)  → repeat 2-3× to confirm.  §4,§15
5. IMPACT: double-spend · OTP/2FA/rate-limit→ATO · one-per-user · state · multi-endpoint. §9-§13
6. VALIDATE control-vs-parallel delta (repeatable) → FP filter → CVSS+CWE-362 → PoC → dedup. §15-§20
```

# Appendix B — Race Decision Tree

```
Is the action LIMITED / once-only / stateful (has an invariant)?     NO → not a race target
            │ YES
Run it ONCE (control) → record the invariant.
Fire N parallel into one window (single-packet / Burp parallel).
   ├─ invariant BROKE (negative balance / N× redeem / 6th OTP / dup unique) → RACE
   │        └─ repeatable? ── YES → impact (money/ATO/business) → report
   │                          NO  → keep raising N / widen window / multi-endpoint; else drop
   ├─ only 1 succeeded, rest rejected ............ LOCKED (atomic) → drop or try wider window
   └─ N× 200 but invariant UNCHANGED ............. NOT a race (idempotent) → drop (§16)
```

# Appendix C — Important Links
- **PortSwigger — Race conditions** (single-packet attack, labs): https://portswigger.net/web-security/race-conditions
- **PortSwigger Research — "Smashing the state machine"** (James Kettle, 2023, single-packet attack)
- **Turbo Intruder** (Burp ext) — `race-single-packet.py`, `examples.py`
- **CWE-362** https://cwe.mitre.org/data/definitions/362.html · **CWE-367** (TOCTOU) /367 · **CWE-841** /841 · **CWE-662** (improper synchronization) · **CWE-820** (missing synchronization) · **CWE-330** (predictable token, §10.5)
- **OWASP WSTG** — Testing for Race Conditions; OWASP "Business Logic" testing
- **Tools** — Turbo Intruder (`race-single-packet.py`, `examples.py`); **requests-racer** (Python, last-byte-sync); **race-the-web** (Go, older); the `poc/` helpers here.
- **Real cases / patterns** — **Starbucks** gift-card balance race (well-known double-spend), HackerOne disclosed **coupon/gift-card overrun** and **OTP-bypass → ATO** reports, **file-upload TOCTOU → webshell** writeups, and **predictable password-reset-token** collisions. Pattern: *limited/valuable check-then-act without atomicity + simultaneous arrival → broken invariant → money / ATO / RCE.*

> **Authorized testing only.** Race your own balances/accounts, keep bursts bounded, never cash out real funds or affect real users, reset state, and report **a repeatable broken invariant with impact** (money/ATO/business) — not "I sent many requests."
