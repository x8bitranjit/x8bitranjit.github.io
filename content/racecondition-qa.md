# Race Conditions (TOCTOU & Limit-Overrun) — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **race conditions**: from "what is a race" to the HTTP/2 single-packet attack, limit-overrun double-spend, OTP/2FA/rate-limit bypass → ATO, uniqueness and state-machine races, multi-endpoint collisions, and the chains they unlock. Q&A format, progressive difficulty, written as **"IF this → THEN that"** decision logic. Covers techniques, tooling, methodology, real cases, **and** defense.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, and learning. Race **your own** accounts/balances; bounded bursts; never cash out real funds or affect real users; prove a **repeatable broken invariant** and stop.

**Canonical references** (real, read them):
- PortSwigger Web Security Academy — *Race conditions* (+ labs); PortSwigger Research — *"Smashing the state machine"* (James Kettle, 2023, single-packet attack)
- OWASP WSTG — *Testing for Race Conditions*; OWASP *Business Logic* testing
- CWE-362 (Race Condition), CWE-367 (TOCTOU), CWE-841 (workflow)
- Turbo Intruder (Burp ext) — `race-single-packet.py`, `examples.py`

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q12)
- **Level 1 — Finding race targets & the control baseline** (Q13–Q24)
- **Level 2 — Landing the race (single-packet, Burp, last-byte)** (Q25–Q40)
- **Level 3 — Limit-overrun & financial double-spend** (Q41–Q52)
- **Level 4 — Security-gate races (OTP/2FA/rate-limit/reset → ATO)** (Q53–Q63)
- **Level 5 — Uniqueness, state-machine & multi-endpoint races** (Q64–Q76)
- **Level 6 — Expert chains, reliability & red-team** (Q77–Q86)
- **Tooling** (Q87–Q91)
- **Methodology & decision tree** (Q92–Q95)
- **Severity, validity & false positives** (Q96–Q102)
- **Real-world cases & references** (Q103–Q107)
- **Defense — how to stop races properly** (Q108–Q112)
- **Appendix — 60-second field checklist**

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is a race condition in one sentence?
A flaw where two or more requests touch the **same shared state at the same time**, and because the app's **check** and **action** aren't atomic, the outcome depends on timing — letting you violate an invariant the app assumed could only change one-at-a-time.

### Q2. What is TOCTOU?
**Time-Of-Check to Time-Of-Use**: the server *checks* a condition ("coupon unused?", "balance ≥ amount?", "attempts < 5?") then *acts* (mark used, debit, increment). The gap between check and use is the **race window**; slip requests into it and they all pass the check before any acts.

### Q3. Why does sending requests "fast" in a loop not work?
Network jitter spreads sequential requests out by milliseconds, so they don't land in the sub-ms window. You must deliver them **simultaneously** — the HTTP/2 single-packet attack (Q25) or HTTP/1.1 last-byte-sync (Q35).

### Q4. What's the single-packet attack and why does it matter?
Putting ~20–30 HTTP/2 requests in **one TCP packet** so the server receives them together (~within 1ms), eliminating jitter. Introduced by James Kettle/PortSwigger (2023), it turned "flaky, can't-reproduce" races into **reliably exploitable** ones.

### Q5. What are the main sub-types of race conditions?
Limit-overrun/double-spend (financial), security-gate races (OTP/2FA/rate-limit/reset → ATO), uniqueness/one-per-user bypass, state-machine/partial-construction, and multi-endpoint (cross-action) races.

### Q6. What's the difference between a race and a logic bug?
A logic bug is wrong **sequentially**; a race is wrong only **concurrently** — the logic is correct one-request-at-a-time but breaks when requests interleave. Many races are "concurrency-only business-logic" bugs.

### Q7. What's an "invariant" and why is it central?
The rule the action is supposed to keep true: "coupon used once", "balance ≥ 0", "≤5 OTP attempts", "1 bonus per user". The exploit is **breaking the invariant**; the proof is **measuring** it before/after (Q19).

### Q8. What's the real-world impact range?
From Low (idempotent overrun, no harm) to **Critical**: financial double-spend (money created), OTP/2FA bypass → account takeover, oversell/fraud, and privilege/state corruption.

### Q9. Does idempotency mean no race?
**No.** An endpoint can return the same result yet still race on a **side counter** (rate-limit, bonus, stock). Always test the **invariant/state**, not just the HTTP response (Q97).

### Q10. Do I need authentication to exploit a race?
Often yes (you race your own session's limited action), but some gates are **pre-auth** (login throttle, signup bonus, OTP for reset). Pre-auth races raise severity (PR:N).

### Q11. What single thing makes a race report valid?
A measured **control (1×) vs parallel (N×) delta on the invariant**, shown to be **repeatable**. "I sent many requests" is not evidence; "balance went negative, reproduced 3×" is (Q96).

### Q12. What's the attacker mindset for races?
For every **limited/once-only/valuable** action ask: *"What invariant protects this, and is the check-then-act atomic? If I fire 20 of these in one packet, does the invariant break?"*

---

# LEVEL 1 — FINDING RACE TARGETS & THE CONTROL BASELINE

### Q13. Which actions should I target first?
Anything **limited, valuable, or once-only**: money (withdraw/transfer/refund/top-up/convert), credits (coupon/gift-card/bonus/cashback), security gates (OTP/2FA/reset/login limits), uniqueness (signup bonus, one-vote, unique email), and stock/seat reservations.

### Q14. How do I find these endpoints?
Drive every feature through Burp; list actions with a counter/balance/used-flag/uniqueness/attempt-limit. Add API endpoints from JS/mobile/recon. For each, write down the **invariant** it protects.

### Q15. What makes a race *easier* to win?
A **wider window**: slow DB, an external/network call **between** check and commit, heavy processing, or late/absent locking. Prefer multi-step or "processing…" actions.

### Q16. Per-account vs global limits — does it matter?
Yes. A **per-account** coupon races within your session; a **global** "first 100 users" or shared wallet races across the whole system. Note the scope — it affects impact and how you set up the burst.

### Q17. What's the control baseline?
Performing the action **once** and recording the normal result **and** the invariant value after (balance, count, used-flag, attempts). It's your "should only happen once" ground truth.

### Q18. Why is the control mandatory?
Because the proof is a **delta**. Without "1× → balance 90", your "N× → balance −100" means nothing to a triager. Control first, always.

### Q19. How do I read the invariant?
Find an endpoint/UI that shows it: wallet/balance, a count, the coupon's used-status, the attempt counter, the order state. Read it **before** and **after** the burst.

### Q20. The action returns 200 on every parallel request — is that the win?
Not by itself. Re-read the **invariant**. If it broke (negative balance / N× credit / 6th OTP accepted) → win. If it's unchanged beyond one action → idempotent, **not** a race (Q97).

### Q21. How many parallel requests should I send?
20–30 in one single-packet group is plenty for most races. More isn't better past the window; raise N only if last-byte-sync (HTTP/1.1) jitter needs it.

### Q22. How do I prove reliability?
Reset state and **re-run the burst 2–3×**. Note the success rate (e.g. "12/20 streams won, reproduced 3/3"). Reproducibility separates a bug from a coincidence.

### Q23. What if only one request succeeds and the rest are rejected?
The action is **properly locked/atomic** — not a race. Try a wider-window variant or a multi-endpoint collision; otherwise drop it.

### Q24. Should I race on my own account or a victim's?
**Your own.** Race your own balances/coupons/accounts; demonstrate the mechanism. Never drain real funds/inventory or affect other users (Q101, §21).

---

# LEVEL 2 — LANDING THE RACE

### Q25. How does the single-packet attack work technically?
HTTP/2 multiplexes requests on one connection. You queue N requests but withhold each one's final frame, then send all final frames in **one packet** → the server finishes parsing them together and processes them in the same window.

### Q26. How do I do it without writing code?
Burp Repeater → add the request to a **group** → duplicate to N tabs → **"Send group in parallel"**. Burp uses single-packet on HTTP/2 (and last-byte-sync on HTTP/1.1) automatically.

### Q27. How do I do it in Turbo Intruder?
`RequestEngine(endpoint=…, concurrentConnections=1, engine=Engine.BURP2)`, `engine.queue(req, gate='g')` in a loop, then `engine.openGate('g')` to release together. (Template in `poc/race_single_packet.py`.)

### Q28. Why `concurrentConnections=1` for single-packet?
Because the power is **parallel streams on one HTTP/2 connection** released in one packet — not many connections (which add per-connection jitter). One connection, many streams, one gate.

### Q29. How do I confirm the requests actually landed together?
Turbo's results show near-identical timestamps; Burp shows the parallel send. But the **real** confirmation is the broken invariant — if it broke, they raced.

### Q30. The target is HTTP/1.1 only — what now?
Use **last-byte synchronization**: open N connections, send all but the final byte of each, then release the last bytes together. Burp "Send group in parallel" does this automatically; it's less precise, so raise N and repeat.

### Q31. What is connection warming and why do it?
The first request on a fresh connection is slower (TLS/warm-up), skewing timing. Send a throwaway request first so the raced requests are evenly fast and land tighter (§8.1).

### Q32. Can a CDN/proxy in front break the race?
Sometimes — front-ends may buffer/normalize. Test against the real origin behaviour; if a CDN serializes, the race may need the origin or a different endpoint. Reproducibility tells you.

### Q33. Does HTTP/3 (QUIC) support single-packet too?
The principle (simultaneous arrival) applies; tooling support varies. HTTP/2 single-packet is the mature path; use it when available.

### Q34. How do I race two *different* endpoints (multi-endpoint)?
You can't trivially put two different requests in one single-packet group; use Turbo Intruder with **two request templates**, both gated, released together — or fire two parallel groups timed to overlap (Q72).

### Q35. What's the failure mode if my burst is too small or too spread out?
You'll see only one success (looks "locked") even though a race exists. Increase concurrency, use single-packet, warm the connection, and target wider-window actions before concluding "safe."

### Q36. How do I vary payloads across the parallel requests (e.g. OTP brute)?
Turbo Intruder: queue each request with a different payload (`engine.queue(req, guess, gate='g')`) then open the gate — all guesses race the rate-limit together (Q56, `poc/race_otp_bruteforce.py`).

### Q37. Can I use plain curl/Python for races?
For a rough smell test (GNU parallel, async httpx) — yes, but jitter makes it unreliable. Prefer Burp/Turbo for precision. The `poc/parallel_fire.py` helper is the async-burst smell test.

### Q38. How do I keep the burst bounded and polite?
20–30 streams, reproduce a few times, then stop. Don't fire thousands — that's abuse, noise, and unnecessary (§21).

### Q39. What server-side designs are most vulnerable?
"Check-then-update" without a DB lock/atomic op, app-level uniqueness (no DB unique index), counters incremented after the check, and external calls between check and commit.

### Q40. What designs resist races?
Row locks (`SELECT … FOR UPDATE`), atomic `UPDATE … WHERE balance >= amt`, DB unique constraints, idempotency keys, and serialized queues. If you see these behaviours, the action is likely safe.

---

# LEVEL 3 — LIMIT-OVERRUN & FINANCIAL DOUBLE-SPEND

### Q41. What's the canonical limit-overrun?
A single-use coupon/gift-card/credit applied **N times** in parallel → N× the discount/credit, because all requests read "unused" before any marks it used.

### Q42. How do I exploit a withdrawal/transfer race?
Fire N parallel withdrawals/transfers each ≤ balance; if check-then-debit isn't atomic, total debited > balance → **negative balance / funds created**. Demonstrate on your own balance; **don't** cash out real money.

### Q43. How do I prove financial impact without stealing?
Show the **ledger/balance state**: negative balance, or credit applied N×. Quantify the extractable value (per race × repeats). Stop at the mechanism — never actually exfiltrate real funds (Q101).

### Q44. Refunds and chargebacks?
Race the "refund this order" so a single order is refunded multiple times, or refund + re-use. Same TOCTOU on the order's refunded-flag.

### Q45. Points/loyalty/conversion races?
Convert/redeem points N× before the balance updates → more value than you hold. Common in loyalty and crypto/wallet apps.

### Q46. Gift-card / store-credit stacking?
Apply the same gift-card to multiple carts/orders simultaneously, or redeem a one-time code N× → inflated credit.

### Q47. How do I escalate a coupon overrun to a strong report?
Show it credits **real balance** (not just a UI discount), find the **max multiplier**, and show whether balance converts to **cash-out/purchase**. That moves it from Medium to High/Critical (§18.1).

### Q48. The coupon shows used=true but still credited multiple times — explain?
Classic TOCTOU: all parallel requests passed the "unused" check, each applied the credit, then the last one set used=true. The flag is right; the **effect** happened N times.

### Q49. Inventory/stock oversell — is that financial?
It's business/financial: race "reserve/purchase" past available stock → oversell, negative inventory, fulfillment loss. Quantify the oversold count.

### Q50. Subscription/plan limit races?
Race "add seat"/"invite" past the plan's seat cap, or upgrade/downgrade timing to get paid features free. Tie to billing impact.

### Q51. How do I set severity for a financial race?
By extractable value and whether it converts to real money out, plus reproducibility. Real money created/extractable = Critical/High; bounded discount abuse = Medium/High.

### Q52. What's the safest way to PoC a money race?
Own account, small amounts, demonstrate the **negative balance / N× credit** and **revert** — never complete a real cash-out or affect the platform's real funds (§19/§21).

---

# LEVEL 4 — SECURITY-GATE RACES (→ ATO)

### Q53. What's an OTP/2FA brute-race?
The gate allows N attempts (e.g. 5). Fire **many guesses in parallel** so they all read "attempts < 5" before the counter increments → effectively unlimited attempts → brute the 4–6 digit code.

### Q54. Why is this High/Critical?
Because it bypasses the rate-limit protecting **authentication** → you can brute OTP/2FA → **account takeover**. The gate's whole purpose is defeated.

### Q55. How do I demonstrate the rate-limit bypass safely?
Show that **far more** attempts are accepted/processed than the documented cap (e.g. cap 5, but 200 guesses processed) — that proves the bypass. You don't need to actually brute a real user's code to prove it (Q101).

### Q56. How do I run the parallel OTP brute?
Turbo Intruder, code position = `%s`, queue each guess behind one gate, open together (`poc/race_otp_bruteforce.py`). Tune the success/failure signal.

### Q57. Password-reset token races?
Race the reset-submit so a single-use token is consumed by multiple requests (token reuse), or race a just-issued token against a guess. Can enable reset-link reuse or hijack.

### Q58. Login throttle / lockout bypass?
Parallel logins can bypass per-attempt throttling/lockout (all pass the "attempts" check together) → credential brute-force at scale.

### Q59. CAPTCHA / one-time-action gate races?
A CAPTCHA token validated then consumed can be **reused** within the window by parallel requests → bypass the human-check on a sensitive action.

### Q60. Email/phone verification races?
Race the verify step to mark an account verified without proper proof, or to claim a verified-only benefit.

### Q61. How do I chain an OTP-race to full ATO?
Combine with a known/guessable username (or an IDOR-leaked one) → parallel-brute the OTP/2FA → authenticate → take over. Report the full chain (rate-limit bypass → OTP brute → ATO).

### Q62. Does the race help if the OTP is 6 digits (1,000,000 space)?
It removes the *limit*, making brute feasible given enough windows/time; combined with a short OTP TTL it's borderline, but the **rate-limit bypass itself** is the reportable bug even if full brute is impractical.

### Q63. What CWE/severity for a gate race?
CWE-362 (+ CWE-307 improper restriction of excessive auth attempts for the outcome). Severity High/Critical when it reaches ATO.

---

# LEVEL 5 — UNIQUENESS, STATE-MACHINE & MULTI-ENDPOINT RACES

### Q64. How do I bypass a "one per user" limit?
Race the "claim" so one account claims a once-only reward/bonus N×, or race account creation so a single unique email/phone yields multiple accounts/bonuses.

### Q65. Vote/like/review inflation?
Race the "vote/like" past the one-per-user check → inflate counts → ranking/contest fraud. Quantify the inflation.

### Q66. Unique-email/username races?
Two simultaneous signups with the same unique value can both pass the "is it taken?" check (no DB unique index) → duplicate accounts → confusion/takeover/bonus abuse.

### Q67. What's a partial-construction race?
Acting on an object **before it's fully created or locked** — e.g. use a half-initialized cart/order/account in another action, or apply a discount mid-creation. The object is in a state the logic didn't expect.

### Q68. Approve/cancel/publish state races?
Collide a state transition with an action assuming the old/new state: approve-while-pending, cancel-and-use, publish-while-draft, lock-while-editing → invalid/exploitable states.

### Q69. Role/permission change races?
Race a privilege change against an action that reads the old permission (or the new one prematurely) → priv-esc or an action you shouldn't be allowed.

### Q70. What is a multi-endpoint race?
Two **different** operations on the same state, fired together: "use credit" + "checkout" (use the credit twice), "leave group" + "post as member", "delete" + "read". The collision produces an impossible sequential state.

### Q71. How do I confirm a state-machine race?
Show the resulting state is **impossible sequentially** (credit used twice, posted after leaving, acted after deactivation). The "impossible state" is the proof.

### Q72. How do I fire a multi-endpoint race in practice?
Turbo Intruder with two request templates both gated and released together (`poc` arsenal §E), or two parallel Burp groups overlapped. Tight gating is key.

### Q73. Business-logic + race — how do they combine?
Many races are concurrency-amplified business-logic bugs: the logic flaw exists, and concurrency lets you exploit it past its intended limit (e.g. a coupon meant once, claimed many). Frame both.

### Q74. Cart/checkout races?
Apply discount + change quantity + checkout simultaneously to lock in a wrong price, or check out the same cart twice. Test the order total/state.

### Q75. Friend/follow/invite limit races?
Exceed connection/invite/seat limits by racing the add. Impact = limit/billing bypass or abuse.

### Q76. How do I pick which race sub-type to chase?
Prioritize by impact: money first, then security gates (ATO), then uniqueness/business abuse, then state corruption. And by window width (wider = easier).

---

# LEVEL 6 — EXPERT CHAINS, RELIABILITY & RED-TEAM

### Q77. How do I maximize race reliability?
HTTP/2 single-packet, `concurrentConnections=1`, connection warming, target wider-window actions, and 20–30 streams. Reproduce to characterize the success rate.

### Q78. Why might a race work once then never again?
State wasn't reset (the coupon is now used), the window closed (cache warmed), or it was coincidence. Reset state and re-run; if it never repeats, treat as non-demonstrable.

### Q79. How do I chain a coupon race to maximum financial impact?
Coupon overrun → real balance credit → find max multiplier → convert balance to cash-out/purchase → quantify per-race × repeats. Report the money path (don't actually extract).

### Q80. How do I chain an OTP race to ATO?
rate-limit bypass (parallel) → OTP/2FA brute → authenticate as victim → demonstrate account access (on your own test victim) → report the full chain.

### Q81. Can a race lead to privilege escalation?
Yes — role-change races, partial-construction that skips an authz step, or multi-endpoint collisions that grant access in an impossible order. Tie to a concrete privileged action.

### Q82. How do red-teamers use races?
Quietly: limit/credit overrun for resource gain, OTP/rate-limit bypass for access, and state races for unauthorized transitions — all with bounded bursts to stay under anomaly detection.

### Q83. How do I keep race testing low-noise?
Bounded bursts (20–30), reproduce a handful of times, then stop; don't loop thousands of requests. Single-packet is both more effective **and** quieter than a brute loop.

### Q84. When is a race NOT worth chasing?
Idempotent actions with no invariant, properly-locked actions (single success), and races with no money/security/business impact. Don't inflate non-issues.

### Q85. How do I quantify impact for the report?
State the broken invariant, the multiplier (N× / negative balance / attempts beyond cap), reproducibility (x/x), and the real-world value (money extractable / accounts takeover-able / fraud at scale).

### Q86. What's the most impressive race outcome?
Financial double-spend that creates real money, or an OTP/2FA rate-limit bypass that yields account takeover — both Critical and both reliably demonstrable with single-packet.

---

# TOOLING

### Q87. What's the fastest way to test a race manually?
Burp Repeater **"Send group in parallel"** — capture, group, duplicate ×20–30, send parallel, re-read the invariant. Zero code.

### Q88. When do I need Turbo Intruder over the Burp group?
For higher N, **varying payloads** (OTP brute-race), multi-endpoint races, or custom gate logic. Use the `poc/` templates.

### Q89. Is there a standalone (no-Burp) option?
`poc/parallel_fire.py` (async HTTP/2 burst + invariant read) for a quick smell test — but Burp/Turbo are more precise (single-packet).

### Q90. How do I detect a race win programmatically?
Read the **invariant** before/after (balance/count/flag/attempts) and compare to the 1× control. A status-only check is unreliable.

### Q91. Any tooling caveats?
Confirm HTTP/2 first; warm the connection; reset state between runs; and always re-verify the broken invariant manually before reporting.

---

# METHODOLOGY & DECISION TREE

### Q92. Give me the end-to-end methodology.
Find limited actions + invariants → control 1× → fire 20–30 parallel (single-packet) → re-read invariant → repeat 2–3× → escalate to money/ATO/business → control-vs-parallel proof → severity → report.

### Q93. The decision tree in words?
Limited action with an invariant? → control 1× → parallel burst → invariant broke? (race) / only 1 ok? (locked) / N×200 unchanged? (idempotent). If race → repeatable? → impact → report.

### Q94. How do I prioritize targets?
Money > security gates (ATO) > uniqueness/business > state. And wider-window actions first (easier to win).

### Q95. How do I avoid wasting time?
Drop idempotent and properly-locked actions fast. Spend time on valuable, wider-window, check-then-act endpoints where the invariant is measurable.

---

# SEVERITY, VALIDITY & FALSE POSITIVES

### Q96. What's the validity bar in one line?
A **repeatable control-vs-parallel delta on the invariant** — "balance went negative / coupon credited N× / 6th OTP accepted, reproduced 3×." Show the state, not the status.

### Q97. What are the classic race false positives?
"N×200 on an idempotent action" (no invariant broke), single-success (locked/atomic), client-only duplication (server dedupes), non-reproducible one-offs, and impact-less duplicate side effects.

### Q98. How do I set severity/CVSS?
CWE-362 (+367 TOCTOU, + outcome CWE). AC:H is expected (timing) but single-packet makes it reliable. Financial double-spend / OTP→ATO = Critical/High; bounded coupon abuse = Medium/High; business abuse = Medium.

### Q99. Why is AC:H not a reason to down-rate?
Because the single-packet attack makes the timing requirement **reliably** satisfiable — if you reproduce it consistently, the practical exploitability is high despite AC:H.

### Q100. How do I title a race report?
`Race condition on <action> → <broken invariant / impact>` and lead with the delta + impact. Never just "race condition".

### Q101. What are the ethics/safety rules?
Own accounts/funds; bounded bursts; **no real money out**; no inventory drain; no effect on real users; reset state; respect scope and concurrency rules. Demonstrate the mechanism, not maximum damage.

### Q102. How do I de-duplicate?
One well-quantified financial/ATO race beats many "2×200" notes. If coupon-stacking is known, frame your **distinct invariant/impact** (negative balance, OTP bypass, oversell).

---

# REAL-WORLD CASES & REFERENCES

### Q103. What did the single-packet attack change in practice?
PortSwigger's 2023 research ("Smashing the state machine") made races that were previously "theoretical/flaky" **reliably reproducible**, re-opening many limit-overrun and gate-bypass bugs across the industry.

### Q104. What are common disclosed race patterns?
Gift-card/coupon/credit overrun (apply once-only code N×), withdrawal/transfer double-spend (negative balance), OTP/2FA/rate-limit bypass → ATO, signup-bonus farming, and vote/like inflation — recurring across HackerOne disclosures.

### Q105. Where can I practice?
PortSwigger Web Security Academy **race-condition labs** (single-packet, limit-overrun, multi-endpoint, partial-construction) — the best hands-on training.

### Q106. What's the common thread across big race bugs?
A valuable **check-then-act without atomicity** + the ability to deliver requests **simultaneously** → broken invariant → money/ATO/fraud.

### Q107. What further reading matters?
PortSwigger race-conditions topic + the 2023 research paper/talk, Turbo Intruder docs/examples, OWASP WSTG race testing, CWE-362/367/841.

---

# DEFENSE — HOW TO STOP RACES PROPERLY

### Q108. The one fix that matters?
Make **check-and-act atomic**: DB row locks (`SELECT … FOR UPDATE`), atomic conditional updates (`UPDATE … SET balance = balance - :amt WHERE balance >= :amt`), or compare-and-swap.

### Q109. How do I protect once-only / money actions?
**Idempotency keys** (reject duplicate operations), DB **unique constraints** for uniqueness invariants, and transactional integrity around the whole check-act.

### Q110. How do I protect rate/attempt gates?
Increment the counter **atomically before** the check (or use an atomic rate limiter like Redis `INCR` with expiry), so concurrent requests can't all read "under the limit."

### Q111. What about state machines and multi-step flows?
Serialize critical transitions (queues/locks), validate the full state at each step, and avoid TOCTOU gaps where an external call sits between check and commit.

### Q112. Defense-in-depth extras?
Pessimistic locking on hot rows, database-level constraints as the last line, idempotent API design, and load-testing/concurrency tests in CI to catch regressions.

---

# ADDENDUM (rev. 2) — FILE-UPLOAD TOCTOU, PREDICTABLE TOKENS, OAUTH, WINDOW-WIDENING, MULTI-NODE

### Q113. Can a race ever reach RCE?
Yes — **file-upload TOCTOU** is the one that does. If the app writes the upload to a **web-reachable path first**, then *asynchronously* scans / validates / renames / moves / deletes it, there's a window where a malicious file is **live and executable**. Burst the upload (a webshell, or a polyglot passing the type check) **and** flood GETs at its predicted URL in the same single-packet window — if a GET lands before cleanup, the shell runs → **RCE** (Critical). Use a benign marker (e.g. print `RC-49`) on your own/test path, then stop. (§12.4)

### Q114. How do I win the upload race if the final filename is random?
Race the **read of the temp/quarantine path** (often predictable: original name, `tmp_<seq>`, timestamp) instead of the final name, or race the **"move out of webroot"** step. Also try **two uploads with the same name** (one valid, one shell) so the validated DB record ends up pointing at the shell. Predictable paths + a wide scan window are what make it winnable.

### Q115. What's a time-sensitive / predictable-token race?
When a secret is derived from the **server clock or a low-entropy seed**, two requests in the same instant get the **same value**. Trigger a password-reset for the **victim** and for **your own** account in one burst — if the tokens collide, the one mailed to you is also the victim's → reset → **ATO**. Spot it by requesting several tokens: shared prefix / time-correlation / increment = predictable (CWE-330 + CWE-362). (§10.5)

### Q116. Is there a race in OAuth?
Yes — an authorization **`code`** must be single-use. Race the **`code`→token exchange** (same code, N× in one packet): if the server mints **multiple access tokens** (or the PKCE/`state` check isn't atomic) → token replay / session reuse / account-linking abuse. Same for one-time **magic-links** and **email-verification** consumption. (§10.6)

### Q117. My burst gives exactly one success — is it safe?
Not yet ("LOCKED" ≠ "safe"). **Widen the window** first (§8.5): pick the **slow** variant of the action (one that does an external API/payment/email/scan between check and commit), **inflate the request** so parsing takes longer, **connection-warm**, and on HTTP/1.1 lean on last-byte-sync + higher N. Only drop it after the wider-window retry also fails.

### Q118. The target is behind a load balancer — does that kill races?
Not for shared state. Requests may hit **different backend nodes**, so a limit kept in **per-node memory** (a local counter/cache) often won't collide — but a **shared DB/Redis row** (wallet, coupon, stock) still does. Target shared-state actions, raise N, and repeat. (Bonus: a purely per-node in-memory rate-limit is itself bypassable by spreading requests across nodes — report that too.) (§8.6)

### Q119. Why does the single-packet attack cap around 20–30 requests?
It's bounded by the TCP **initial congestion window** (~10 packets) and the need to ship all withheld final frames together; it also assumes each request is **small** (only its last frame outstanding). Large bodies / many big headers, HTTP/1.1-only targets, or buffering intermediaries break it → **fall back to last-byte-sync** (§7) and raise N. (§5.4)

---

# APPENDIX — 60-SECOND FIELD CHECKLIST
```
[ ] Found a LIMITED/once-only/valuable action + wrote down its INVARIANT.
[ ] Target HTTP/2? (single-packet) ; set Burp "Send group in parallel".
[ ] CONTROL (1×): recorded result + invariant (balance/count/used/attempts).
[ ] PARALLEL: 20–30 reqs in one window (single-packet / parallel group / last-byte-sync).
[ ] Re-read invariant: broke? (RACE) / 1 ok? (LOCKED→widen window §8.5) / N×200 unchanged? (idempotent → drop).
[ ] REPEATED 2–3× (reset between) → reproducible; noted success rate. (load-balanced? target shared-state §8.6.)
[ ] IMPACT: file-upload TOCTOU→RCE / double-spend $ / OTP-rate-limit·predictable-token·OAuth-code → ATO / one-per-user / state / multi-endpoint.
[ ] Control-vs-parallel PROOF (state delta). FP filter passed. CVSS + CWE-362(+367).
[ ] Own funds/accounts; bounded; no real money out; reverted. Title = action+invariant+impact. Dedup.
```

> **Authorized testing only.** Race your own balances/accounts, keep bursts bounded, never cash out real funds or affect real users, reset state, and report **a repeatable broken invariant with impact** — not "I sent many requests."
