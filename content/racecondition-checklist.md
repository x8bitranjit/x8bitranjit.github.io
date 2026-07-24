# Race Condition Testing Checklist — Per-Endpoint, In Testing Order

> Tick per limited/stateful action. Mirrors the Master Testing Sequence in `RACE_CONDITION_TESTING_GUIDE.md`. The point: **identify the invariant → control (1×) → fire N parallel into one window → re-read the invariant → repeat → escalate to money/ATO.** `§` = section in the main guide.

**Target:** ____________  **Action/endpoint:** ____________  **Method:** ____________  **Date:** ________
**Invariant it should protect:** used-once / balance≥0 / ≤N attempts / unique / stock≥0 / state-machine
**Protocol:** HTTP/2 (single-packet ✓) / HTTP/1.1 (last-byte-sync)  **Scope:** per-account / global

---

## PHASE 0 — Recon & Lab (§1/§3)
*Why this matters:* you can't race a rule you haven't named. This phase builds your target list — every action that enforces a **limit** (money, attempts, "one per user," stock) — and, for each, the one-sentence **invariant** it protects ("balance ≥ 0," "coupon used once," "≤5 OTP tries"). That invariant is literally what your whole proof will measure, so writing it down now is not busywork — it's the yardstick for everything that follows. Confirming HTTP/2 here decides which weapon you'll use in Phase 2.
- [ ] Listed **limited / once-only / stateful** actions (money, OTP/2FA/reset, coupon/bonus, vote, stock, state).
- [ ] For each, wrote down the **invariant** it protects (the thing you'll try to break).
- [ ] Confirmed protocol: **HTTP/2** (single-packet viable) or HTTP/1.1 (last-byte-sync).
- [ ] Captured a clean request per candidate; noted any "processing…" delay (wider window = easier).
- [ ] Using **my own** accounts/balances/coupons only.

## PHASE 1 — Baseline ★ (§4) — CONTROL FIRST
*Why this matters:* the control is you being a scientist — do the action **once, slowly, the intended way** and record exactly what "correct" looks like. This is what makes a race un-false-positive-able: without a clean "1× → balance $90" baseline, your later "N× → balance −$400" means nothing to a triager, because they can't tell whether *your race* broke it or it was already broken. Skipping the control is the #1 rookie mistake, and you usually can't recapture a clean baseline after you've disturbed the state.
- [ ] Ran the action **once**; recorded the response **and** the invariant value after (balance/count/used/attempts).
- [ ] Confirmed I can **read the invariant** before and after (wallet, count endpoint, used-flag).

## PHASE 2 — Land the Race (§5–§8)
*Why this matters:* this is the craft — **making the requests arrive together**. A normal loop spreads them over tens of milliseconds; the race window is sub-millisecond, so they never collide. Single-packet (HTTP/2) and last-byte-sync (HTTP/1.1) exist purely to defeat that jitter. The two boxes people skip and regret: **connection warming** (the first request on a cold connection is slow and smears your timing) and **widening the window** before giving up — "only one success" often means *your window was too thin*, not *the endpoint is safe*.
- [ ] **Single-packet (HTTP/2)** (§5): Burp group → duplicate 20–30× → **"Send group in parallel"**.
- [ ] **Turbo Intruder** (§6) for higher N / varying payloads (OTP brute-race) / gate-and-release.
- [ ] **HTTP/1.1 last-byte-sync** (§7) if no HTTP/2 (raise N; jitter remains).
- [ ] **Connection warming** (§8.1): throwaway first request so raced ones land tight.
- [ ] (multi-endpoint §13) two request templates, gated and released together.
- [ ] If only ONE success ("LOCKED"): **widen the window** (§8.5) — slow variant / inflate body / warm conn — before dropping.
- [ ] Behind a load balancer? target **shared-state** (DB/Redis) actions, not per-node in-memory counters (§8.6).
- [ ] ✅ Confirmed N requests landed in the same window (timing or simply >1 success).

## PHASE 3 — IMPACT ⭐ (§9–§13)
*Why this matters:* a broken invariant is only worth as much as what it breaks — so this phase steers the overrun toward the outcomes that actually pay. The order of the boxes is deliberate, roughly highest-impact first: **file-upload TOCTOU → RCE** (the only race that reaches code execution, Critical), **financial double-spend** (money created), and the **security-gate races** (OTP/2FA/predictable-token/OAuth-code → **account takeover**). Chase those before the business-abuse ones. The last box — stating the impact in one plain sentence — is what turns "I found a race" into a rateable finding.
- [ ] **Financial double-spend** (§9): withdraw/transfer/refund > balance → **negative**; coupon/credit applied N×.
- [ ] **Security-gate** (§10): OTP/2FA/reset/login rate-limit bypass → brute the code → **ATO**.
- [ ] **Predictable / time-seeded token** (§10.5): issue victim+self tokens simultaneously → collide → reset → **ATO**.
- [ ] **OAuth single-use code / token reuse** (§10.6): race `code`→token exchange → multiple tokens.
- [ ] **File-upload TOCTOU → RCE** (§12.4): burst upload(webshell) + GET-flood the predicted URL → catch execution before scan/rename.
- [ ] **Uniqueness/one-per-user** (§11): bonus claimed N× / multiple accounts on one unique email / vote inflation / oversell.
- [ ] **State-machine / partial-construction** (§12): act on a half-built object; approve-while-pending; role-change race.
- [ ] **Multi-endpoint** (§13): collide two operations on one state (credit-use + checkout, leave + post).
- [ ] Stated impact: *"Racing <action> broke <invariant>, enabling <double-spend $ / ATO / business abuse>."*

## PHASE 4 — Validate → Severity → Report (§15–§20)
*Why this matters:* the final gate that decides whether your report is accepted or closed. A valid race report must be able to say one sentence: **"one action gives the normal result; the parallel burst gives an impossible result; and it happens again every time."** That's control + delta + **reproducibility**, measured on the *state* not the status. Reproducing it 3× also neutralises the triager's favourite down-rate ("AC:H, too flaky") — single-packet makes the timing reliably satisfiable, so a repeatable PoC keeps the severity where the impact puts it.
- [ ] ★ **CONTROL (1×) vs PARALLEL (N×)** delta on the **invariant**, with state read-out (not just statuses).
- [ ] **Repeated ≥2–3×** (state reset between) → reproducible; noted success rate.
- [ ] Passed the **false-positive filter** (§16): NOT idempotent N×200, NOT single-success/locked, NOT client-only, NOT non-reproducible, NOT impact-less.
- [ ] Set **CVSS 3.1** (AC:H expected) + **CWE-362** (+ CWE-367 TOCTOU + outcome CWE) (§17); quantified value/scale.
- [ ] Built a clean **PoC** (control + Turbo script/Burp group + before/after state; own funds; reverted) (§19).
- [ ] **De-duplicated**; title names the **action + broken invariant + impact** (§20).

---

## Quick "is it a real race?" gate
```
Does the action have an invariant (once / balance / limit / unique / state)?   NO → not a race target.
CONTROL (1×) recorded the invariant?                                           NO → record it first.
PARALLEL burst BROKE the invariant (state delta, not just 200s)?               NO → idempotent/locked → drop.
Reproducible (re-ran 2-3×)?                                                     NO → keep widening / drop.
Converts to money / ATO / business harm?                                       NO → Low/Info.
```

## Per-endpoint mini-loop
```
find invariant → control 1× (read state) → 20–30 parallel (single-packet) → re-read state
   ├ invariant broke + repeatable → impact (double-spend / OTP-bypass→ATO / one-per-user) → report
   ├ only 1 ok (locked) → widen window / multi-endpoint / drop
   └ N×200 unchanged → NOT a race → drop
→ control-vs-parallel proof → FP filter → CVSS+CWE-362 → reversible PoC → dedup
```
