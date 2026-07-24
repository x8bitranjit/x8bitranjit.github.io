# Race Conditions (TOCTOU & Limit-Overrun) — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **race conditions**: from "what is a race" to the HTTP/2 single-packet attack, limit-overrun double-spend, OTP/2FA/rate-limit bypass → ATO, uniqueness and state-machine races, multi-endpoint collisions, and the chains they unlock. Q&A format, progressive difficulty, written as **"IF this → THEN that"** decision logic. Covers techniques, tooling, methodology, real cases, **and** defense.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, and learning. Race **your own** accounts/balances; bounded bursts; never cash out real funds or affect real users; prove a **repeatable broken invariant** and stop.

> 🧭 **New to this? Read this first.** A *race condition* is what happens when two things try to grab the **same thing at the same time** and the program wasn't built to handle a tie. Picture two people reaching for **the last cookie on a plate** at the exact same second — the rule is "one cookie per person," but if nobody's refereeing the split-second grab, **both hands close on it** and the rule is broken. In a web app the "cookie" is a coupon, a wallet balance, an OTP attempt counter, a "one bonus per user" flag — and the "two hands" are two HTTP requests you send so close together that the server checks the rule for *both* of them before it has finished updating it for *either*. That's the whole idea. Everything below is just how to (1) spot those cookies, (2) get your two hands there at the exact same instant, and (3) prove you broke the rule. Don't worry if the jargon (TOCTOU, invariant, single-packet) looks scary — each term is defined in plain English the first time it appears.

**Canonical references** (real, read them):
- PortSwigger Web Security Academy — *Race conditions* (topic + free hands-on labs); PortSwigger Research — *"Smashing the state machine: The true potential of web race conditions"* (James Kettle, 2023 — the paper that introduced the single-packet attack; watch the DEF CON 31 / Black Hat talk too)
- OWASP WSTG — *Testing for Race Conditions* (WSTG-BUSL-07); OWASP *Business Logic* testing guide
- CWE-362 (Concurrent Execution using Shared Resource — the umbrella "race condition"), CWE-367 (TOCTOU — Time-of-Check Time-of-Use), CWE-841 (Improper Enforcement of Behavioral Workflow), CWE-330 (predictable values, for token-collision races)
- Turbo Intruder (Burp extension, by PortSwigger) — ships `race-single-packet.py` and `examples.py` templates; and Burp Repeater's built-in **"Send group in parallel"**
- *The Web Application Hacker's Handbook* (Stuttard & Pinto) — the "logic flaws" chapter for the business-logic mindset that races live inside

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

*In plain words:* the app does two steps — first it **looks** ("is this coupon still unused?"), then it **acts** ("okay, give the discount and mark it used"). If you can squeeze a second request into the tiny gap **between** the look and the act, that second request also sees "unused" and *also* gets the discount. Both requests "won the race" to read the value before either one changed it. *"Atomic"* just means "all-or-nothing, with no gap in the middle where someone can cut in" — the opposite of what makes a race possible.

### Q2. What is TOCTOU?
**Time-Of-Check to Time-Of-Use**: the server *checks* a condition ("coupon unused?", "balance ≥ amount?", "attempts < 5?") then *acts* (mark used, debit, increment). The gap between check and use is the **race window**; slip requests into it and they all pass the check before any acts.

*Think of it like a nightclub with one bouncer.* The bouncer **checks** the guest list (Time-Of-Check), then walks you to your table (Time-Of-Use). If ten people flash the *same* name at the bouncer in the same second, he's still looking at the list for the first one when the others push past — they all "checked in" as the one allowed guest. The **race window** is exactly how long the bouncer's back is turned. A wide window (slow database, a payment call, a virus scan in the middle) is an easy race; a razor-thin window is hard but often still winnable with the single-packet attack (Q4/Q25). TOCTOU is just the formal name for "the check and the use are two separate moments, and I'm attacking the gap between them."

### Q3. Why does sending requests "fast" in a loop not work?
Network jitter spreads sequential requests out by milliseconds, so they don't land in the sub-ms window. You must deliver them **simultaneously** — the HTTP/2 single-packet attack (Q25) or HTTP/1.1 last-byte-sync (Q35).

*Why "just loop `curl` really fast" fails:* even a fast loop sends request #1, waits for it to travel the network, then sends #2, and so on. Each one leaves at a slightly different time and the internet adds a little random delay to each (that randomness is called **jitter**). So your 20 requests arrive smeared across, say, 40 milliseconds — but the race window you're aiming for might be **half a millisecond** wide. It's like trying to get 20 runners to cross the finish line in a *tie* by starting them one-at-a-time with a stopwatch: they'll never dead-heat. You need them to cross **together**, which is what the single-packet attack arranges (Q4).

### Q4. What's the single-packet attack and why does it matter?
Putting ~20–30 HTTP/2 requests in **one TCP packet** so the server receives them together (~within 1ms), eliminating jitter. Introduced by James Kettle/PortSwigger (2023), it turned "flaky, can't-reproduce" races into **reliably exploitable** ones.

*The plain-English trick:* normally each request is its own little envelope dropped in the mail at a slightly different time. The single-packet attack stuffs ~20–30 requests into **one envelope** and mails that — so the server rips it open and finds all of them at once, arriving within about a millisecond of each other. That kills the jitter from Q3. Before this technique (pre-2023), race bugs were famous for being real but **impossible to reproduce on demand** — you'd hit it once, then never again, and triagers would reject it. James Kettle's single-packet attack made races **fire on command, every time**, which is why race conditions went from a niche curiosity to a mainstream, high-paying bug class. This is *the* technique to learn.

### Q5. What are the main sub-types of race conditions?
Limit-overrun/double-spend (financial), security-gate races (OTP/2FA/rate-limit/reset → ATO), uniqueness/one-per-user bypass, state-machine/partial-construction, and multi-endpoint (cross-action) races.

*Translated into "what you actually steal":* **limit-overrun / double-spend** = spend the same $10 or coupon many times (money out of thin air); **security-gate races** = defeat the "only 5 tries" limit on an OTP/2FA/login so you can brute-force it → take over accounts; **uniqueness bypass** = grab a "one per person" reward many times, or register two accounts on one "unique" email; **state-machine / partial-construction** = act on something before it's finished being built (use a half-made order, cancel-and-use at once); **multi-endpoint** = fire two *different* actions together so their combination lands in an impossible state. Each has its own Level below. Money and ATO are the two that pay the most.

### Q6. What's the difference between a race and a logic bug?
A logic bug is wrong **sequentially**; a race is wrong only **concurrently** — the logic is correct one-request-at-a-time but breaks when requests interleave. Many races are "concurrency-only business-logic" bugs.

*The tell:* if you can trigger the bug by clicking **one button, one time**, it's an ordinary logic bug. If the app behaves perfectly when you go slow and one-at-a-time, and *only* misbehaves when you fire several requests **at the same instant**, that's a race. Same code, but the flaw only shows up in the "traffic jam." That's why you always establish a slow, one-request **control** first (Q17) — it proves the app is *normally* correct, so the broken result under parallel fire can only be the race.

### Q7. What's an "invariant" and why is it central?
The rule the action is supposed to keep true: "coupon used once", "balance ≥ 0", "≤5 OTP attempts", "1 bonus per user". The exploit is **breaking the invariant**; the proof is **measuring** it before/after (Q19).

*"Invariant" just means "a fact that's supposed to stay true no matter what."* Your bank balance should **never go below zero**. A single-use coupon should be redeemed **exactly once**. A one-per-customer bonus should land **once**. Your whole job in a race hunt is: (1) name the invariant in one sentence, (2) measure it, (3) fire the parallel burst, (4) measure it again — and show it now says something impossible (balance = −$400, coupon credited 5×, bonus granted 3×). The broken invariant **is** the bug, and the before/after measurement **is** the proof. If you can't state the invariant, you're not ready to test the endpoint yet.

### Q8. What's the real-world impact range?
From Low (idempotent overrun, no harm) to **Critical**: financial double-spend (money created), OTP/2FA bypass → account takeover, oversell/fraud, and privilege/state corruption.

*Concretely, low → high:* at the **low** end you send 200 requests and nothing bad actually happens — the app just did the same harmless thing once (no invariant broke); that's not a bug, don't report it. At the **critical** end you turn $100 into $500 that you can withdraw, or you brute-force a victim's 2FA code and log in as them. Same *technique*, wildly different *payout* — which is why this whole guide is "impact-first": the race is only worth as much as the invariant it breaks. Chase money and account-takeover first.

### Q9. Does idempotency mean no race?
**No.** An endpoint can return the same result yet still race on a **side counter** (rate-limit, bonus, stock). Always test the **invariant/state**, not just the HTTP response (Q97).

*"Idempotent" means "doing it twice is the same as doing it once"* — like pressing a floor button in an elevator; mashing it 10 times still takes you to the same floor. Some endpoints genuinely are like that, and racing them does nothing. **But** the visible response can look idempotent while a hidden **side-effect counter** quietly races — the page says "OK" every time, yet behind the scenes a rate-limit counter, a stock number, or a bonus balance moved N times. That's why you never judge a race by the HTTP status/body alone; you go read the **actual state** (Q19). The response lies; the ledger doesn't.

### Q10. Do I need authentication to exploit a race?
Often yes (you race your own session's limited action), but some gates are **pre-auth** (login throttle, signup bonus, OTP for reset). Pre-auth races raise severity (PR:N).

*Why "pre-auth" matters for your bounty:* most races need you logged in — you're racing *your own* wallet or *your own* coupon. But some of the juiciest ones happen **before login**: the "you get 5 OTP tries" limit on a **password reset**, the login lockout, the "first-100-signups" bonus. Anyone on the internet can hit those without an account, so they're rated more dangerous (in CVSS terms, **Privileges Required: None** / PR:N bumps the score). If a gate protects something and you can reach it with no session, flag that in the report — it's worth more.

### Q11. What single thing makes a race report valid?
A measured **control (1×) vs parallel (N×) delta on the invariant**, shown to be **repeatable**. "I sent many requests" is not evidence; "balance went negative, reproduced 3×" is (Q96).

*The one sentence that gets your report accepted:* **"Doing it once gives X; doing it 20-at-once gives impossible-Y; and I reproduced that 3 times."** A triager doesn't care that you sent a lot of traffic — everyone can send traffic. They care that you can show a **number that should be impossible** (balance −$400, coupon 5×, 6th OTP accepted after a cap of 5) and that it happens **again when they retry**. Control, burst, re-measure, repeat — that four-step delta is the entire evidence standard. Screenshots of the *state before* and *state after* beat any amount of "look how many requests I sent."

### Q12. What's the attacker mindset for races?
For every **limited/once-only/valuable** action ask: *"What invariant protects this, and is the check-then-act atomic? If I fire 20 of these in one packet, does the invariant break?"*

*Train the reflex:* whenever the app says the word **"only"** — *only* one per customer, *only* if balance is enough, *only* 5 attempts, *only* while stock lasts, *only* one vote — a little alarm should go off. "Only" means there's a rule (an invariant) and a check enforcing it, and every check is a potential race window. So the mindset is a three-part question you ask on autopilot at every valuable button: **(1) What's the rule? (2) Does the server check-then-act with a gap in between? (3) What happens if 20 of these arrive in the same millisecond?** If you can't rule out the gap, test it.

---

# LEVEL 1 — FINDING RACE TARGETS & THE CONTROL BASELINE

### Q13. Which actions should I target first?
Anything **limited, valuable, or once-only**: money (withdraw/transfer/refund/top-up/convert), credits (coupon/gift-card/bonus/cashback), security gates (OTP/2FA/reset/login limits), uniqueness (signup bonus, one-vote, unique email), and stock/seat reservations.

*Rule of thumb:* the best race targets are the same things a **con artist** would eye — anything the app hands out in a **countable, limited quantity that has value**. If a feature involves a number that goes up or down (a balance, a stock count, an attempt counter), a flag that flips once (used/verified/redeemed), or a promise of "one per person," it's a candidate. Boring, unlimited actions (viewing a page, searching) have no invariant to break, so skip them.

### Q14. How do I find these endpoints?
Drive every feature through Burp; list actions with a counter/balance/used-flag/uniqueness/attempt-limit. Add API endpoints from JS/mobile/recon. For each, write down the **invariant** it protects.

*Practical workflow for a beginner:* put Burp (or any intercepting proxy) between your browser and the site, then **use the app like a normal customer** — click everything: apply a coupon, add to cart, withdraw, redeem points, request an OTP, claim a bonus. Every action you take shows up in Burp's history as a request. Now go down that list and, for each one, ask "does this enforce a limit?" and jot the invariant next to it ("`POST /coupon/apply` — invariant: each code redeemed once"). Also pull hidden API endpoints from the site's JavaScript files and mobile app so you don't miss unadvertised actions. That annotated list **is** your test plan.

### Q15. What makes a race *easier* to win?
A **wider window**: slow DB, an external/network call **between** check and commit, heavy processing, or late/absent locking. Prefer multi-step or "processing…" actions.

*Remember the bouncer (Q2):* the longer his back is turned, the easier it is to slip past. The "window" is that turned-back time. Anything that makes the server do **slow work between the check and the final commit** widens it — a call out to a payment provider, sending an email, resizing an image, scanning an upload, a heavy database query, or a spinner that says "Processing…". Those actions are your friends: a wide window can be raced even with sloppy timing, while a razor-thin one needs the full single-packet precision. So when choosing between two similar features, attack the **slower** one first.

### Q16. Per-account vs global limits — does it matter?
Yes. A **per-account** coupon races within your session; a **global** "first 100 users" or shared wallet races across the whole system. Note the scope — it affects impact and how you set up the burst.

*What the difference means for you:* a **per-account** limit (e.g. "you may use this coupon once") is protected by a counter tied to *your* login, so you race it with a burst from *your own* session. A **global** limit ("first 100 sign-ups get a prize," a shared inventory of 50 seats) is one number shared by everyone, so a successful race there affects the *whole platform* — usually higher impact, and sometimes exploitable by many accounts at once. Always note which kind you're hitting: it changes both how you set up the requests and how big the finding is.

### Q17. What's the control baseline?
Performing the action **once** and recording the normal result **and** the invariant value after (balance, count, used-flag, attempts). It's your "should only happen once" ground truth.

*Why this step exists:* the **control** is you being a scientist. Before you do anything weird, you do the action **once, slowly, the intended way**, and write down exactly what happened: "balance was $100, I withdrew $100, balance is now $0; coupon now shows used=true." That's the "this is what *correct* looks like" photo. Later, when the parallel burst produces "balance = −$400, coupon used 5×," you have a clean *before* to compare against — proof the app was fine until concurrency broke it. Skipping the control is the #1 rookie mistake; without it your evidence is just noise.

### Q18. Why is the control mandatory?
Because the proof is a **delta**. Without "1× → balance 90", your "N× → balance −100" means nothing to a triager. Control first, always.

*A "delta" is just "the difference between two measurements."* A triager reading your report needs to instantly see: *normal path* → sane result; *race path* → impossible result. That contrast is the whole finding. If you only show the impossible result with no baseline, they can't tell whether the app was *always* broken (a different, maybe-known bug) or whether **your race** broke it. The control turns "here's a weird number" into "here's a number that is provably impossible without my attack." Always capture it first — you usually can't go back and get a clean baseline after you've messed up the state.

### Q19. How do I read the invariant?
Find an endpoint/UI that shows it: wallet/balance, a count, the coupon's used-status, the attempt counter, the order state. Read it **before** and **after** the burst.

*Where to actually look:* the invariant almost always has a place it's displayed — the **wallet page** shows your balance, the **coupon** shows redeemed/not, the **orders** page shows a status, an admin/API endpoint shows a count. Find that read-only view first. Your loop is: **read it → fire the burst → read it again**. If the site hides the number, look for an API endpoint that returns it (often the same data the page uses, visible in Burp), or infer it from behaviour ("the 6th OTP attempt was accepted, so the attempt counter clearly didn't cap at 5"). No readable invariant = no measurable proof = weak report, so solving "how do I see this number?" is part of the hunt.

### Q20. The action returns 200 on every parallel request — is that the win?
Not by itself. Re-read the **invariant**. If it broke (negative balance / N× credit / 6th OTP accepted) → win. If it's unchanged beyond one action → idempotent, **not** a race (Q97).

*Don't celebrate the green lights.* Twenty `200 OK` responses feel like twenty wins, but "200" only means "the server accepted the request," not "the server did something twice." The server can happily reply 200 to all twenty while a lock quietly made only *one* of them count. The **only** thing that decides win-or-not is the invariant you re-read in Q19: did the balance actually go negative? Was the credit actually applied five times? If the state moved past what one action should do → real race. If the state matches a single action despite twenty 200s → it's locked/idempotent and you drop it. Judge by the ledger, never by the status code.

### Q21. How many parallel requests should I send?
20–30 in one single-packet group is plenty for most races. More isn't better past the window; raise N only if last-byte-sync (HTTP/1.1) jitter needs it.

*Why not thousands?* The single-packet attack physically caps at roughly 20–30 requests anyway (it's limited by how much fits in that one network packet — see Q119), and beyond the race window, extra requests don't help you win; they just add noise, load, and detection risk. Start at ~20. Only bump the number higher when you're stuck on an HTTP/1.1 target using the looser "last-byte-sync" method (Q30), where extra requests compensate for the sloppier timing. Bounded and precise beats a giant flood every time.

### Q22. How do I prove reliability?
Reset state and **re-run the burst 2–3×**. Note the success rate (e.g. "12/20 streams won, reproduced 3/3"). Reproducibility separates a bug from a coincidence.

*A one-off could just be luck; a repeat is a bug.* After a successful race, put the state back to normal (top the balance back up, get a fresh coupon, reset attempts) and **do the whole thing again** — two or three times. Record how it went each round ("12 of 20 parallel requests double-spent; worked 3 out of 3 attempts"). This does two things: it proves to the triager that this isn't a fluke they'll fail to reproduce, and it gives you a concrete **success rate** to put in the report, which is exactly what turns "AC:H, might be a coincidence" into "reliably exploitable on demand" (Q99).

### Q23. What if only one request succeeds and the rest are rejected?
The action is **properly locked/atomic** — not a race. Try a wider-window variant or a multi-endpoint collision; otherwise drop it.

*This is the app winning, and it's a normal outcome.* When you fire 20 and exactly **one** goes through while the other 19 get rejected/errored, the developer did their job: there's a lock or an atomic database update making the check-and-act indivisible (Q40). Before you give up, though, try two escape hatches: (1) find a **slower variant** of the same action to widen the window (Q15/Q117), and (2) try a **multi-endpoint** collision — two *different* actions on the same data fired together (Q70), which sometimes sneaks around a single-endpoint lock. If both fail, this target is genuinely safe — move on, don't force it.

### Q24. Should I race on my own account or a victim's?
**Your own.** Race your own balances/coupons/accounts; demonstrate the mechanism. Never drain real funds/inventory or affect other users (Q101, §21).

*This is a hard ethical + legal line, not a suggestion.* You prove the *mechanism* — that the invariant breaks — using **accounts and money you own**. Create two of your own test accounts if you need a "victim," use your own wallet, your own coupon, your own OTP. Take the negative balance on *your* account, screenshot it, then **revert** it. You never touch a real user's funds, never actually drain live inventory, never brute a stranger's real OTP. Bug bounty pays you to *demonstrate* the flaw responsibly; going further (real theft, real disruption) turns an authorized test into a crime and gets you banned or prosecuted. Show the door is unlocked — don't rob the house.

---

# LEVEL 2 — LANDING THE RACE

### Q25. How does the single-packet attack work technically?
HTTP/2 multiplexes requests on one connection. You queue N requests but withhold each one's final frame, then send all final frames in **one packet** → the server finishes parsing them together and processes them in the same window.

*Broken down slowly:* HTTP/2 (the modern version of the web protocol) can carry **many requests down one connection at the same time** — that's "multiplexing," like many lanes on one highway. A request is sent in pieces called **frames**, and the server can't start acting on a request until it has received the **last** frame ("okay, that's the whole request, go"). The trick: send *almost all* of each request — everything except that final "I'm done" frame — for all 20 requests, so the server is holding 20 half-finished requests and waiting. Then send **all 20 final frames bundled into one TCP packet**. The server receives them in the same instant, finishes all 20 at once, and runs them in the same tiny window → they race. You don't have to build this by hand; Burp and Turbo Intruder do it for you (Q26/Q27).

### Q26. How do I do it without writing code?
Burp Repeater → add the request to a **group** → duplicate to N tabs → **"Send group in parallel"**. Burp uses single-packet on HTTP/2 (and last-byte-sync on HTTP/1.1) automatically.

*Step-by-step, no coding:* (1) In Burp, right-click the request you want to race and **"Send to Repeater."** (2) In Repeater, right-click its tab → **"Add tab to group"** (create a new group). (3) **Duplicate** that tab ~20 times into the same group (Ctrl-R or right-click → Duplicate). (4) Click the group's send dropdown and choose **"Send group in parallel."** Burp automatically picks the single-packet attack on HTTP/2 targets and last-byte-sync on HTTP/1.1 ones — you don't configure anything. (5) Go read your invariant (Q19). This is the fastest way to test a race and it's where every beginner should start before touching Turbo Intruder.

### Q27. How do I do it in Turbo Intruder?
`RequestEngine(endpoint=…, concurrentConnections=1, engine=Engine.BURP2)`, `engine.queue(req, gate='g')` in a loop, then `engine.openGate('g')` to release together. (Template in `poc/race_single_packet.py`.)

*When Burp's "parallel group" isn't enough* — you need more than ~20 requests, different payloads per request (like OTP guesses), or two different endpoints — you graduate to **Turbo Intruder**, a Burp extension that scripts the burst in Python. The pattern is always the same three moves: build a request **engine**, **queue** each request onto a named "gate" (a holding pen) instead of sending it, then **open the gate** so every queued request is released together. Think of `gate='g'` as *"line everyone up at the start line labelled g,"* and `openGate('g')` as *"fire the starting pistol."* A ready-to-edit template is in `poc/race_single_packet.py` — you mostly just paste your request and set the count.

### Q28. Why `concurrentConnections=1` for single-packet?
Because the power is **parallel streams on one HTTP/2 connection** released in one packet — not many connections (which add per-connection jitter). One connection, many streams, one gate.

*The counter-intuitive part:* it feels like "more connections = more parallel = better," but for the single-packet attack the opposite is true. The magic is **one HTTP/2 connection carrying many streams**, all released in a single packet so they arrive together. If you spread requests across *many* connections, each connection has its own slightly different network delay (jitter again), smearing your arrival times back out — exactly what you were trying to avoid. So you deliberately pin it to **one** connection (`concurrentConnections=1`) and let HTTP/2's multiplexing do the parallelism. One connection, many streams, one gate, one packet.

### Q29. How do I confirm the requests actually landed together?
Turbo's results show near-identical timestamps; Burp shows the parallel send. But the **real** confirmation is the broken invariant — if it broke, they raced.

*Don't over-trust the timing readout.* Turbo Intruder prints response timestamps and Burp shows the parallel send happened, which are useful sanity checks that your burst fired tightly. But timestamps can look great and the race can still have failed (the app locked), or look mediocre and the race still won. The **only** confirmation that actually matters is Q19's invariant: **did the number break?** If the balance went negative or the coupon credited 5×, the requests provably raced — the broken state *is* the timing proof. Read the ledger, not the stopwatch.

### Q30. The target is HTTP/1.1 only — what now?
Use **last-byte synchronization**: open N connections, send all but the final byte of each, then release the last bytes together. Burp "Send group in parallel" does this automatically; it's less precise, so raise N and repeat.

*Plain version:* older HTTP/1.1 can't multiplex many requests on one connection, so the neat single-packet trick doesn't apply. The fallback mimics it: open several connections, push **all but the very last byte** of each request (so each server is one keystroke away from "done"), then fire **all the last bytes together**. It's the same idea — hold everyone at the line, then release at once — just coarser, because separate connections drift apart a bit. Burp's "Send group in parallel" does this for you automatically when it detects HTTP/1.1. Because it's less precise, **use more requests** (raise N) and repeat the burst a few extra times to land a win.

### Q31. What is connection warming and why do it?
The first request on a fresh connection is slower (TLS/warm-up), skewing timing. Send a throwaway request first so the raced requests are evenly fast and land tighter (§8.1).

*Analogy:* a car is sluggish on the first cold start. A brand-new network connection is the same — the very first request pays extra setup cost (TLS handshake, buffers warming up), so it's slower than the rest and throws your timing off. **Connection warming** means sending one harmless throwaway request first (like a `GET /` on the homepage) to "warm up the engine," so that when your real raced requests go, they're all evenly fast and bunch up tightly in the window. Burp and Turbo often handle this, but on stubborn targets, manually warming the connection can be the difference between a miss and a win.

### Q32. Can a CDN/proxy in front break the race?
Sometimes — front-ends may buffer/normalize. Test against the real origin behaviour; if a CDN serializes, the race may need the origin or a different endpoint. Reproducibility tells you.

*What's going on:* many sites sit behind a **CDN or reverse proxy** (Cloudflare, Akamai, an nginx front-end) that receives your requests first and forwards them to the real server ("origin"). That middleman can **buffer** your requests or **reshape** the timing, sometimes smearing your carefully-bundled burst so it no longer races — or, occasionally, it forwards them just fine. You can't always tell from the outside, so let **reproducibility** answer it: if the race won't fire through the front-end, try reaching the origin directly (if in scope), a different endpoint, or a slower-window action. If it never reproduces anywhere, the intermediary may genuinely be serializing your requests — note that and move on.

### Q33. Does HTTP/3 (QUIC) support single-packet too?
The principle (simultaneous arrival) applies; tooling support varies. HTTP/2 single-packet is the mature path; use it when available.

*Short version for now:* HTTP/3 runs over QUIC (a newer, UDP-based transport), and the **core idea** — get all requests to arrive at the same instant — still applies in theory. But the polished, battle-tested tooling today is built around **HTTP/2** single-packet. So in practice: if the target speaks HTTP/2 (most do), use that; treat HTTP/3 as an emerging area where tool support is still catching up. You rarely need HTTP/3 to land a race.

### Q34. How do I race two *different* endpoints (multi-endpoint)?
You can't trivially put two different requests in one single-packet group; use Turbo Intruder with **two request templates**, both gated, released together — or fire two parallel groups timed to overlap (Q72).

*Why this needs extra effort:* the single-packet trick bundles copies of **the same** request. But some races need **two different actions** to collide — e.g. "spend credit" racing "checkout," or "cancel order" racing "use order." Burp's simple parallel group can't mix two different requests cleanly, so you either (a) script it in Turbo Intruder with **two request templates, both queued behind one gate**, then open the gate to release them together, or (b) set up **two separate Burp parallel groups** and fire them at the same moment so their windows overlap. It's fiddlier and less precise than same-request racing — see Q70–Q72 for the full multi-endpoint playbook.

### Q35. What's the failure mode if my burst is too small or too spread out?
You'll see only one success (looks "locked") even though a race exists. Increase concurrency, use single-packet, warm the connection, and target wider-window actions before concluding "safe."

*The trap to avoid:* a weak burst (too few requests, or smeared out by jitter) produces **exactly one success** — which looks *identical* to a properly-locked, safe endpoint. So "only one worked" does **not** automatically mean "no bug." Before you declare a target safe, exhaust the reliability levers: switch to true single-packet (Q25), bump the request count, warm the connection (Q31), and pick the **slowest-window** variant of the action (Q15/Q117). Only after those still give a single success is "locked/safe" a fair conclusion. Many real races have been missed because someone stopped at the first weak burst.

### Q36. How do I vary payloads across the parallel requests (e.g. OTP brute)?
Turbo Intruder: queue each request with a different payload (`engine.queue(req, guess, gate='g')`) then open the gate — all guesses race the rate-limit together (Q56, `poc/race_otp_bruteforce.py`).

*The use case:* sometimes you don't want 20 *identical* requests — you want 20 requests each trying a **different value**, all racing the same limit. The classic is OTP brute-forcing: fire codes `000000`, `000001`, `000002`… all at once so they slip past the "5 attempts" cap together. In Turbo Intruder you put a placeholder in the request and, in the loop, `engine.queue(req, guess, gate='g')` once per guess — each queued with its own payload but the **same gate** — then `openGate('g')` releases the whole batch simultaneously. The ready template is `poc/race_otp_bruteforce.py`; tune it to recognise the "success" response so you know which guess hit (Q56).

### Q37. Can I use plain curl/Python for races?
For a rough smell test (GNU parallel, async httpx) — yes, but jitter makes it unreliable. Prefer Burp/Turbo for precision. The `poc/parallel_fire.py` helper is the async-burst smell test.

*Honest expectations:* you *can* throw a quick burst with `xargs -P` / GNU `parallel` / an async `httpx` script, and it's fine as a **first sniff** ("is there maybe something here?"). But these fire over separate connections with ordinary timing, so **jitter** (Q3) usually keeps you out of the sub-millisecond window — a *negative* result proves nothing. Treat plain scripts as a smoke alarm, not a verdict. When you actually want to confirm or exploit a race, use Burp's parallel group or Turbo Intruder, which implement true single-packet timing. `poc/parallel_fire.py` is provided precisely as that quick async smell-test helper.

### Q38. How do I keep the burst bounded and polite?
20–30 streams, reproduce a few times, then stop. Don't fire thousands — that's abuse, noise, and unnecessary (§21).

*This protects you as much as the target.* You do **not** need volume to prove a race — you need *precision*. 20–30 well-timed requests, reproduced two or three times, is a complete proof. Blasting thousands of requests is unnecessary (it doesn't win harder than a tight burst), it's noisy (triggers WAF/anomaly alerts and can look like a DoS), and on many programs it violates the rules of engagement. Stay bounded: it keeps you inside scope, keeps you stealthy (Q83), and keeps your conscience clear. More is not better here — *tighter* is better.

### Q39. What server-side designs are most vulnerable?
"Check-then-update" without a DB lock/atomic op, app-level uniqueness (no DB unique index), counters incremented after the check, and external calls between check and commit.

*What "vulnerable code" looks like under the hood:* the risky pattern is **read, decide, then write as three separate steps** with no lock joining them — e.g. `SELECT balance` → `if balance >= amount` (in the app) → `UPDATE balance = balance - amount`. Between the read and the write, other requests can read the same stale balance. Same story when uniqueness is enforced in application code (`if not User.exists(email)`) instead of a database `UNIQUE` constraint, or when a limit counter is bumped *after* the action rather than atomically before it, or when a slow **external call** (payment, email) sits inside the window. If you can see or infer any of these shapes, the endpoint is a prime race target.

### Q40. What designs resist races?
Row locks (`SELECT … FOR UPDATE`), atomic `UPDATE … WHERE balance >= amt`, DB unique constraints, idempotency keys, and serialized queues. If you see these behaviours, the action is likely safe.

*What "safe code" looks like — and how it behaves when you race it:* the fix is always to make check-and-act **one indivisible step**. An **atomic conditional update** — `UPDATE wallet SET balance = balance - :amt WHERE user_id = :id AND balance >= :amt` — does the check *and* the deduction in a single statement the database won't split, so only the requests that truly have the funds succeed. Same protection from **row locks** (`SELECT … FOR UPDATE` holds the row so others wait), **database `UNIQUE` constraints** (the second duplicate insert is rejected by the DB itself), **idempotency keys** (duplicate operations are recognised and ignored), and **serialized queues** (requests processed strictly one at a time). When you race one of these, you'll see **exactly one success and the rest cleanly rejected** — that's the signature of a properly-built endpoint, and your cue to move on (Q23).

---

# LEVEL 3 — LIMIT-OVERRUN & FINANCIAL DOUBLE-SPEND

### Q41. What's the canonical limit-overrun?
A single-use coupon/gift-card/credit applied **N times** in parallel → N× the discount/credit, because all requests read "unused" before any marks it used.

*This is the textbook race, so anchor on it:* you have a `$10 OFF` code meant to work **once**. Normally you apply it, the server marks it used, done. In the race, you fire the "apply coupon" request 20 times **simultaneously** — and because all 20 read the flag as "unused" in the same instant *before* any of them flips it to "used," the server hands out the $10 discount (or credit) **20 times**. "Limit-overrun" literally means you overran the limit-of-one. Once you understand this one, every other financial race (gift cards, points, refunds) is the same shape with a different noun.

### Q42. How do I exploit a withdrawal/transfer race?
Fire N parallel withdrawals/transfers each ≤ balance; if check-then-debit isn't atomic, total debited > balance → **negative balance / funds created**. Demonstrate on your own balance; **don't** cash out real money.

*Worked example:* your wallet has **$100**. You queue **five** withdrawal requests of **$100 each** and fire them in one single-packet burst. Each request runs `if balance >= 100` at the same moment — all five see $100, all five pass — then all five subtract $100. Result: **balance = −$400**, i.e. the system just let you take out **$500 you never had**. That's money created from a broken invariant ("balance ≥ 0"). You prove this on **your own** wallet, screenshot the negative balance, and stop — you never push the fake funds out to a real bank account (that's theft, Q101). See §9.4 in the main guide for the full worked withdrawal.

### Q43. How do I prove financial impact without stealing?
Show the **ledger/balance state**: negative balance, or credit applied N×. Quantify the extractable value (per race × repeats). Stop at the mechanism — never actually exfiltrate real funds (Q101).

*The evidence is the number, not the cash-out.* You do **not** need to actually withdraw money to a real account to prove a money bug — the impossible **ledger state** is the proof. Screenshot "balance = −$400" or "coupon credited 5×," then do the arithmetic for the report: "each race nets $400 of phantom funds, reproducible on demand, so a real attacker could extract $X per hour." That quantification is what earns the Critical rating. Then you stop at the mechanism and revert — demonstrating the door is unlocked, not walking off with the contents (Q24).

### Q44. Refunds and chargebacks?
Race the "refund this order" so a single order is refunded multiple times, or refund + re-use. Same TOCTOU on the order's refunded-flag.

*Same trick, "refunded" flag instead of "used" flag:* an order should be refundable **once**. Fire "refund order #123" several times at once — all reads see `refunded = false`, all issue the money back, *then* one sets the flag true. You've been refunded 3× for one purchase. A nastier variant: race **refund + re-use** so you get your money back **and** keep the product/credit. Look at whatever field records "already refunded" — that's the invariant you're breaking.

### Q45. Points/loyalty/conversion races?
Convert/redeem points N× before the balance updates → more value than you hold. Common in loyalty and crypto/wallet apps.

*Everyday version:* you have 1,000 loyalty points worth a $10 voucher. You race the "convert points → voucher" action so it fires several times before your point balance is decremented — each conversion reads "1,000 points available," so you walk away with **several $10 vouchers off a single 1,000-point balance**. Extremely common in airline/hotel loyalty programs and in crypto/wallet "convert token A → token B" flows, where the value is real and cash-outable.

### Q46. Gift-card / store-credit stacking?
Apply the same gift-card to multiple carts/orders simultaneously, or redeem a one-time code N× → inflated credit.

*Two flavours:* (a) take one gift card and apply it to **several carts at the same instant** so its value is loaded into all of them before it's marked spent; (b) redeem a one-time gift/credit code **N× in parallel** so a $25 card becomes $25 × N of store credit. Both are the coupon race (Q41) wearing a gift-card costume — same broken "redeemed once" invariant, directly convertible to goods or credit.

### Q47. How do I escalate a coupon overrun to a strong report?
Show it credits **real balance** (not just a UI discount), find the **max multiplier**, and show whether balance converts to **cash-out/purchase**. That moves it from Medium to High/Critical (§18.1).

*Turn a "meh" finding into a payday:* a coupon that only knocks money off a price you never actually pay is weak (Medium at best). To escalate, answer three questions with evidence: **(1) Does it touch real balance/credit** you could keep or spend, not just a cosmetic discount on the checkout page? **(2) What's the maximum multiplier** — does 20 parallel requests give 20× (find the ceiling)? **(3) Does that credit convert to cash-out or real goods?** If you can show "this creates real, spendable, multipliable value that leaves the platform as money or product," you've moved it from Medium to High/Critical. Impact = balance that becomes money.

### Q48. The coupon shows used=true but still credited multiple times — explain?
Classic TOCTOU: all parallel requests passed the "unused" check, each applied the credit, then the last one set used=true. The flag is right; the **effect** happened N times.

*This confuses beginners, so read slowly:* you might look afterward and see `used = true` and think "the protection worked!" It didn't. The flag being `true` at the **end** is correct — but by then the *effect* (the credit) already fired N times during the window when everyone still saw `false`. The order of events was: 20 reads all see `false` → 20 credits applied → *then* the flag flips to `true`. The final flag is a snapshot of the finish line; it says nothing about the 20 cars that already crossed. Judge by the credited amount (the effect), never by the final flag.

### Q49. Inventory/stock oversell — is that financial?
It's business/financial: race "reserve/purchase" past available stock → oversell, negative inventory, fulfillment loss. Quantify the oversold count.

*Yes — it costs the business real money.* If only 5 units are in stock and you race the "buy/reserve" action with 20 requests, all 20 read "5 available" and all 20 succeed → the store sold **20 of 5**, i.e. negative inventory. The company must now either eat the loss fulfilling orders it can't, or cancel paid orders and take the reputation hit. It's the money invariant ("units sold ≤ units in stock") wearing an inventory costume. Report it with the concrete oversold count ("sold 20 against a stock of 5, reproduced 3×").

### Q50. Subscription/plan limit races?
Race "add seat"/"invite" past the plan's seat cap, or upgrade/downgrade timing to get paid features free. Tie to billing impact.

*Where the money is here:* SaaS plans sell you a cap — "up to 5 team seats," "10 projects," "Pro features." Race the "add seat"/"invite member" action past the cap and you get **10 seats while paying for 5** — you're stealing the exact thing the plan charges for. A timing variant: race an **upgrade then immediate downgrade** to snag a paid feature for free during the window. Always tie the finding back to the **billing** impact ("bypasses the seat limit that's the core of the pricing model") — that's what makes it a real severity, not a curiosity.

### Q51. How do I set severity for a financial race?
By extractable value and whether it converts to real money out, plus reproducibility. Real money created/extractable = Critical/High; bounded discount abuse = Medium/High.

*The severity dial, in plain terms:* two questions set it. **How much value, and can it leave as real money?** Phantom balance you can actually withdraw or spend on real goods = **Critical/High**. A bounded discount that saves you a bit but can't be cashed out = **Medium/High**. Then **reproducibility** adjusts it: something you can trigger on-demand every time is worse than a rare fluke. So: "creates $500 of withdrawable funds, works 3/3 times" is Critical; "stacks a $10 coupon to $30 off a purchase, works sometimes" is Medium.

### Q52. What's the safest way to PoC a money race?
Own account, small amounts, demonstrate the **negative balance / N× credit** and **revert** — never complete a real cash-out or affect the platform's real funds (§19/§21).

*The safe recipe, start to finish:* use **your own** account, with **small** amounts (you don't need $100 — $1 proves it equally well). Fire the bounded burst, capture the **impossible state** (negative balance / N× credit) with before-and-after screenshots, then **revert** — top the balance back to correct, void the fake credits, tell the program what you changed. Never complete an actual withdrawal to a real destination, never touch the platform's live money or other users. The goal is a clean, reversible demonstration a triager can trust — impact shown, no harm done.

---

# LEVEL 4 — SECURITY-GATE RACES (→ ATO)

### Q53. What's an OTP/2FA brute-race?
The gate allows N attempts (e.g. 5). Fire **many guesses in parallel** so they all read "attempts < 5" before the counter increments → effectively unlimited attempts → brute the 4–6 digit code.

*Why this is the crown jewel of race hunting:* a one-time code (the SMS/email OTP, the 2FA digits) is only safe because you get **a few tries** before you're locked out — 5 guesses against a 6-digit code is hopeless odds for an attacker. The race **erases the lock**: fire hundreds of guesses in one simultaneous burst, they *all* read "attempts used = 0, under the limit of 5" before the counter can climb, so the server cheerfully checks *all* of them. Now you effectively have **unlimited guesses**, and a 4–6 digit code falls in seconds. You've turned "5 tries" into "as many as I can pack into a burst." That's the bug that leads straight to account takeover.

### Q54. Why is this High/Critical?
Because it bypasses the rate-limit protecting **authentication** → you can brute OTP/2FA → **account takeover**. The gate's whole purpose is defeated.

*The severity in one line:* the attempt-limit is the **only** thing standing between a guessable code and someone's account. Defeat it and you can brute the code → log in as the victim → **own their account** (read their data, change their email/password, transact as them). When a bug reliably ends in account takeover, it's High/Critical almost by definition — you've nullified the entire authentication control, not just inconvenienced it.

### Q55. How do I demonstrate the rate-limit bypass safely?
Show that **far more** attempts are accepted/processed than the documented cap (e.g. cap 5, but 200 guesses processed) — that proves the bypass. You don't need to actually brute a real user's code to prove it (Q101).

*You prove the broken lock, not the break-in.* You do **not** need to actually crack a real person's OTP to have a valid, high-severity report. The bug **is** the bypassed limit — so demonstrate exactly that: on **your own** account, show that the system is supposed to allow 5 attempts but you got **200 wrong guesses accepted and processed** in one burst without a lockout. "The cap is 5; I pushed 200 past it; here's the proof, reproduced 3×" fully establishes the vulnerability. Cracking a stranger's code adds no evidence and crosses into real attack — stop at the proven bypass (§9.4/§10.1b in the guide walk through the OTP math).

### Q56. How do I run the parallel OTP brute?
Turbo Intruder, code position = `%s`, queue each guess behind one gate, open together (`poc/race_otp_bruteforce.py`). Tune the success/failure signal.

*Concretely:* mark the OTP field in your request with Turbo Intruder's payload marker (`%s`), then in the script loop over your guess list, queuing each guess onto **one shared gate** (so nothing sends yet), and finally open the gate to release the whole batch at the same instant (see Q36 for the queue-then-gate pattern). The one setting you must get right is the **success signal** — how the script tells a correct code from a wrong one (a different status, a redirect, a "welcome" string, a length change). `poc/race_otp_bruteforce.py` is the ready template; you mainly edit the request, the guess range, and that success/failure check.

### Q57. Password-reset token races?
Race the reset-submit so a single-use token is consumed by multiple requests (token reuse), or race a just-issued token against a guess. Can enable reset-link reuse or hijack.

*Two angles on the reset flow:* (1) **Token reuse** — a reset token is supposed to work **once**; race the "submit new password with this token" request so several go through before the token is marked consumed, enabling reuse/replay of a link that should have died after one use. (2) **Collision** — race a *just-issued* token against guessing/prediction (ties into predictable-token races, Q115), especially if tokens are weak or time-based. Either can lead to hijacking a reset and taking the account. The invariant here is "reset token = single use," and you're breaking it.

### Q58. Login throttle / lockout bypass?
Parallel logins can bypass per-attempt throttling/lockout (all pass the "attempts" check together) → credential brute-force at scale.

*Same erased-lock idea, applied to the password itself:* login forms throttle or lock after N bad passwords. Fire many login attempts in parallel and they all pass the "attempts remaining?" check together, before the failed-attempt counter climbs — so the throttle never engages and you can brute-force **passwords** at scale, not just OTPs. It's the Q53 mechanism aimed at the primary login gate. Pair it with a leaked/common-password list and you have credential-stuffing that ignores the lockout entirely.

### Q59. CAPTCHA / one-time-action gate races?
A CAPTCHA token validated then consumed can be **reused** within the window by parallel requests → bypass the human-check on a sensitive action.

*Turning a one-time "prove you're human" into many uses:* a CAPTCHA gives you a token that should be **validated once and then burned**. If validation and consumption aren't atomic, race several requests carrying the **same** solved token — they all validate before it's burned, so one human-solve covers **many** automated actions. That defeats the anti-automation control on whatever it guards (mass sign-ups, spam, brute-force), effectively making the CAPTCHA optional for a burst.

### Q60. Email/phone verification races?
Race the verify step to mark an account verified without proper proof, or to claim a verified-only benefit.

*Why "verified" is worth racing:* lots of apps unlock trust or perks once your email/phone is "verified" (higher limits, posting rights, a bonus, access to features). Race the verification step to flip the **verified** flag without genuinely proving ownership, or to grab a verified-only benefit more than once. This also feeds bigger chains — e.g. an unverified-email SSO merge that leads to account takeover (see the pre-account-takeover pattern in the AccountTakeover kit).

### Q61. How do I chain an OTP-race to full ATO?
Combine with a known/guessable username (or an IDOR-leaked one) → parallel-brute the OTP/2FA → authenticate → take over. Report the full chain (rate-limit bypass → OTP brute → ATO).

*Assemble the chain like Lego:* the OTP race gives you unlimited guesses, but you still need to point it at a **victim identity**. Step 1: get a target username/email/phone — often public, guessable, or leaked via an IDOR elsewhere. Step 2: trigger that victim's OTP/2FA (or reset) flow. Step 3: parallel-brute the code using the race (Q53/Q56). Step 4: the correct code authenticates you **as the victim** → account takeover. In the report, tell the **whole story** as a chain — "rate-limit bypass → OTP brute → ATO" — because the chained impact is what earns the Critical, and each link makes the next credible. (Do the full brute only against **your own** test victim, Q55.)

### Q62. Does the race help if the OTP is 6 digits (1,000,000 space)?
It removes the *limit*, making brute feasible given enough windows/time; combined with a short OTP TTL it's borderline, but the **rate-limit bypass itself** is the reportable bug even if full brute is impractical.

*Being honest about the math:* a 6-digit code has 1,000,000 possibilities, and each single-packet burst only fits ~20–30 guesses, so fully brute-forcing it before the code **expires** (OTPs often live only 1–5 minutes) can be a real race against the clock — sometimes impractical. **But don't let that talk you out of reporting:** the vulnerability is the **removed rate-limit**, and that stands on its own regardless of whether a full brute completes in time. A 4-digit code (10,000 space) is often fully bruteable; a 6-digit with a long TTL and no per-burst cap can be too. Report the bypass as the core finding, and note the practical brute-feasibility as impact context.

### Q63. What CWE/severity for a gate race?
CWE-362 (+ CWE-307 improper restriction of excessive auth attempts for the outcome). Severity High/Critical when it reaches ATO.

*The labels for your report:* tag it **CWE-362** (the race condition itself) plus **CWE-307** (*Improper Restriction of Excessive Authentication Attempts* — the *outcome*, i.e. the broken rate-limit). Using both tells the triager "here's the mechanism (race) and here's what it broke (the auth-attempt limit)." Severity climbs with impact: a bypassed limit that reaches **account takeover** is **High/Critical**; a bypassed limit on something less sensitive is lower. Anchor the rating to how close you got to ATO.

---

# LEVEL 5 — UNIQUENESS, STATE-MACHINE & MULTI-ENDPOINT RACES

### Q64. How do I bypass a "one per user" limit?
Race the "claim" so one account claims a once-only reward/bonus N×, or race account creation so a single unique email/phone yields multiple accounts/bonuses.

*The "one per customer" sign is just another invariant to break:* whenever the app promises **one** of something per person — one welcome bonus, one free trial, one referral reward, one vote — fire the "claim" action in a parallel burst. All copies read "you haven't claimed yet" at once, so you claim it **N times** on a single account. A twist: race **account creation** with the same email/phone to spawn multiple accounts (Q66), each then eligible for its own bonus. Same shape as the coupon race, just the limit is scoped to "per user" instead of "per code."

### Q65. Vote/like/review inflation?
Race the "vote/like" past the one-per-user check → inflate counts → ranking/contest fraud. Quantify the inflation.

*Why it's more than cosmetic:* "one vote/like/review per user" guards contests, rankings, app-store positions, and reputation systems — things with real money or influence attached. Race the vote and one account casts many, skewing a poll, winning a prize contest, or burying a competitor. Report it with numbers ("one account produced 20 votes against a one-per-user rule, reproduced 3×") and tie it to the **fraud** it enables (rigged contest, manipulated ranking), which is what gives it severity beyond "a counter went up."

### Q66. Unique-email/username races?
Two simultaneous signups with the same unique value can both pass the "is it taken?" check (no DB unique index) → duplicate accounts → confusion/takeover/bonus abuse.

*The classic "no unique index" bug:* signup checks `is this email already registered?` then inserts the new user — two separate steps. Fire two sign-ups with the **same** email at the same instant: both check "not taken" (true for both, since neither has inserted yet), both insert → now **two accounts share one email/username**. When the app relies on that field being unique (for login, password reset, "is this you?"), the duplicate causes confusion, account-takeover openings, or double bonuses. The real fix is a database `UNIQUE` constraint (Q40); its absence is exactly what you're exploiting.

### Q67. What's a partial-construction race?
Acting on an object **before it's fully created or locked** — e.g. use a half-initialized cart/order/account in another action, or apply a discount mid-creation. The object is in a state the logic didn't expect.

*Analogy: using a house before the walls are up.* When the app builds something in multiple steps (create order → set price → apply tax → finalize), there's a window where the object **exists but isn't finished or locked**. Race a *second* action that grabs the object **mid-build** — e.g. check out a cart before its price finished calculating, use an account before its permissions are fully set, apply a discount during creation. The object is in an in-between state no sequential code path ever produces, so the logic mishandles it. These are subtler than money races but can unlock authz skips and impossible states (Q68).

### Q68. Approve/cancel/publish state races?
Collide a state transition with an action assuming the old/new state: approve-while-pending, cancel-and-use, publish-while-draft, lock-while-editing → invalid/exploitable states.

*Think of a status field as a traffic light you're running:* an item moves draft → pending → approved → published, and each action assumes a particular light. Race a **state change** against an action that assumes the **old (or new)** state: cancel an order **and** use it at the same instant, approve something **while** it's still pending, publish **while** it's a draft, edit **while** it locks. The collision lands the object in a contradictory state (used-and-cancelled, approved-but-unpaid) that the app never guards against because sequentially it "can't happen." That impossible state is often the exploit.

### Q69. Role/permission change races?
Race a privilege change against an action that reads the old permission (or the new one prematurely) → priv-esc or an action you shouldn't be allowed.

*Racing the moment your access changes:* permissions get read at one instant and used at another. Race a **privilege change** (role upgrade/downgrade, add/remove from a group, granting a share) against an action that checks permission — the action may read the **stale** permission (do something after you should've lost access) or the **new** one too early (act with rights before they're truly yours). Result: privilege escalation or an action you shouldn't be allowed. Tie it to a **concrete privileged operation** ("performed an admin-only delete during the role-grant window") so it's a demonstrable authz break, not a theoretical one.

### Q70. What is a multi-endpoint race?
Two **different** operations on the same state, fired together: "use credit" + "checkout" (use the credit twice), "leave group" + "post as member", "delete" + "read". The collision produces an impossible sequential state.

*Up to now most races fired the SAME request many times; this fires TWO DIFFERENT ones together.* You collide two distinct actions that both touch one piece of state, so their combination produces something impossible in order: "spend credit" + "checkout" overlapping so the credit counts **twice**; "leave group" + "post as member" so you post **after** leaving; "delete" + "read" so you read a thing that's already gone. The proof is the **impossible sequence** — a result that no single ordering of the two actions could legally produce. It's fiddlier to set up (Q34/Q72) but reaches bugs single-request racing can't.

### Q71. How do I confirm a state-machine race?
Show the resulting state is **impossible sequentially** (credit used twice, posted after leaving, acted after deactivation). The "impossible state" is the proof.

*The proof standard for these is different from money races.* For a financial race the proof is a broken number; for a state-machine race the proof is a **logically impossible situation**. So capture the contradiction plainly: "I am posting as a member of a group I have already left," "this credit shows as spent on two orders," "this action succeeded after the account was deactivated." If you can narrate an outcome that **couldn't happen if the two actions ran one-after-another in any order**, you've confirmed the race. The impossibility *is* the evidence — screenshot both facts (e.g. the "left group" confirmation and the post that shouldn't exist).

### Q72. How do I fire a multi-endpoint race in practice?
Turbo Intruder with two request templates both gated and released together (`poc` arsenal §E), or two parallel Burp groups overlapped. Tight gating is key.

*The mechanics of colliding two requests:* Burp's simple parallel group only sends copies of one request, so for two *different* requests you either (a) script **Turbo Intruder** with **two request templates**, queue both behind the **same gate**, and open it so they release together (see the arsenal's multi-endpoint template), or (b) set up **two Burp parallel groups** and trigger them at the same moment so their windows overlap. The make-or-break detail is **tight gating** — both actions must actually land in the same tiny window, or they just run in order and nothing collides. Warm the connection and repeat to land it (Q31).

### Q73. Business-logic + race — how do they combine?
Many races are concurrency-amplified business-logic bugs: the logic flaw exists, and concurrency lets you exploit it past its intended limit (e.g. a coupon meant once, claimed many). Frame both.

*Two lenses on the same bug:* a **business-logic** flaw is "the rule itself or its enforcement is weak"; a **race** is "concurrency lets me push that enforcement past its limit." They stack: the app *intends* one coupon per user, the logic *tries* to enforce it, and the race is the crowbar that pries the limit open to N. In your report, frame **both** — name the business rule being violated *and* the concurrency mechanism that violates it. Triagers who own the business logic understand "coupon abused" instantly; the race detail proves *how* and makes it reproducible. (Race conditions are formally a sub-family of business-logic testing in OWASP's WSTG.)

### Q74. Cart/checkout races?
Apply discount + change quantity + checkout simultaneously to lock in a wrong price, or check out the same cart twice. Test the order total/state.

*E-commerce is a target-rich playground because price is computed from several moving parts.* Race those parts against **checkout**: apply a discount, change the quantity, and finalize the order all in the same window so the total gets computed from a mix of old and new values → you lock in a wrong (lower) price. Or check out the **same cart twice** so one cart becomes two paid orders (or one payment covers two). Always verify against the **order total / final state**, not the mid-checkout UI, which may show a value that never actually persisted.

### Q75. Friend/follow/invite limit races?
Exceed connection/invite/seat limits by racing the add. Impact = limit/billing bypass or abuse.

*The lower-stakes cousin of the seat-limit race (Q50):* social/collaboration features cap connections, follows, invites, or team members. Race the "add/invite" action to blow past the cap. Impact ranges from mild abuse (exceed a follow limit) to real billing bypass (exceed paid seat/invite limits). Rate it by what the limit actually protects — a spam/abuse control is lower, a **paid** quota is higher.

### Q76. How do I pick which race sub-type to chase?
Prioritize by impact: money first, then security gates (ATO), then uniqueness/business abuse, then state corruption. And by window width (wider = easier).

*Two dials guide your time: payout and ease.* By **impact**, chase in this order — **money** (double-spend/withdrawal, the top payout) → **security gates** (OTP/2FA/login → ATO, also top-tier) → **uniqueness/business abuse** (bonus farming, oversell, vote fraud) → **pure state corruption** (impressive but often lower dollar impact). By **ease**, prefer **wider-window** actions (slow, multi-step, external-call, "processing…") because they race with far less timing precision (Q15). The sweet spot is a high-impact action that *also* has a wide window — start there, and don't sink hours into a thin-window, low-impact target.

---

# LEVEL 6 — EXPERT CHAINS, RELIABILITY & RED-TEAM

### Q77. How do I maximize race reliability?
HTTP/2 single-packet, `concurrentConnections=1`, connection warming, target wider-window actions, and 20–30 streams. Reproduce to characterize the success rate.

*The reliability checklist, plain:* stack every advantage so timing works *for* you — use true **single-packet** on HTTP/2 (Q25), pin to **one connection** (Q28), **warm** it first (Q31), pick the **widest-window** variant of the action (Q15), and send a tight **20–30** burst (Q21). Then **reproduce** it a few times to learn your success rate (e.g. "wins 12/20 streams, 3/3 attempts"). Each lever narrows the arrival spread; together they turn a flaky maybe into a repeatable yes. If it still won't fire reliably after all of these, that's meaningful evidence the endpoint is well-locked.

### Q78. Why might a race work once then never again?
State wasn't reset (the coupon is now used), the window closed (cache warmed), or it was coincidence. Reset state and re-run; if it never repeats, treat as non-demonstrable.

*Three usual culprits, and the fix:* (1) **State not reset** — the coupon is now used, the balance is spent, the attempts are consumed, so of course a repeat "fails"; put the state back to its starting point before retrying. (2) **Window changed** — a cold cache/DB that made the first attempt slow (wide window) is now warm and fast (thin window); this is normal timing variance. (3) **It was luck** — a single uncontrolled coincidence. The discipline for all three is the same: **reset the state cleanly and re-run**. If it reproduces, it's real (report the success rate); if it truly never repeats under clean conditions, treat it as non-demonstrable and don't report it as a solid finding.

### Q79. How do I chain a coupon race to maximum financial impact?
Coupon overrun → real balance credit → find max multiplier → convert balance to cash-out/purchase → quantify per-race × repeats. Report the money path (don't actually extract).

*Walk the value all the way to money:* a raw "coupon applied 5×" is a Medium note; the chain makes it Critical. Step through it: **overrun the coupon** → confirm it lands as **real, spendable balance/credit** (not a cosmetic discount) → **find the max multiplier** (how much per burst) → show the balance **converts to cash-out or real goods** → **quantify** total extractable value (per-race amount × how often you can repeat it). Present that as a clear money path — "$X of real credit per race, repeatable, cashes out to goods." You **demonstrate** the path and stop; you never actually pull real funds out (Q24/Q43).

### Q80. How do I chain an OTP race to ATO?
rate-limit bypass (parallel) → OTP/2FA brute → authenticate as victim → demonstrate account access (on your own test victim) → report the full chain.

*The account-takeover chain, end to end:* **parallel burst removes the attempt-limit** (Q53) → **brute the OTP/2FA code** now that you have unlimited guesses → **the correct code authenticates you as the victim** → **demonstrate account access** (using your own second test account as the "victim," Q24) → **report the full chain** so the impact reads as ATO, not just "a rate-limit is weak." Each arrow is a link the triager can follow; the last arrow (actual account access) is what turns three medium-sounding facts into one Critical.

### Q81. Can a race lead to privilege escalation?
Yes — role-change races, partial-construction that skips an authz step, or multi-endpoint collisions that grant access in an impossible order. Tie to a concrete privileged action.

*Yes — three routes to "I can now do admin things":* (1) **role-change races** (Q69) where you act during the window your permissions are shifting; (2) **partial-construction** (Q67) where an object gets used before its authorization step has run; (3) **multi-endpoint collisions** (Q70) that grant access in an order that skips a check. The report-maker in all three is proving a **concrete privileged action** you shouldn't be able to do — "performed an admin-only operation," "accessed another tenant's data" — not just "a permission looked briefly inconsistent." Land it on a real capability and it's a priv-esc finding.

### Q82. How do red-teamers use races?
Quietly: limit/credit overrun for resource gain, OTP/rate-limit bypass for access, and state races for unauthorized transitions — all with bounded bursts to stay under anomaly detection.

*In an engagement, races are a stealthy way to get resources and access:* an overrun quietly mints credit/resources without noisy exploitation; an OTP/rate-limit bypass buys **access** (into an account or past a control) without a loud brute-force flood; a state race forces an **unauthorized transition** (approve, escalate, unlock) that looks like normal traffic. The red-team edge is that a **tight single-packet burst is both more effective and far quieter** than hammering thousands of requests, so it slides under rate-based anomaly detection. Bounded, precise, low-and-slow — that's the operator's use of a race.

### Q83. How do I keep race testing low-noise?
Bounded bursts (20–30), reproduce a handful of times, then stop; don't loop thousands of requests. Single-packet is both more effective **and** quieter than a brute loop.

*Stealth and courtesy are the same discipline here:* 20–30 requests, reproduced two or three times, then **stop** — that's a complete proof *and* a small footprint. A thousand-request loop is louder, trips WAF/rate/anomaly alarms, risks looking like a DoS, and doesn't win any harder than a tight burst (the window is the limit, not the volume — Q38). Because single-packet packs its punch into one packet, it's the quietest *and* strongest option at once. Low-noise isn't a compromise on effectiveness — it *is* the effective way.

### Q84. When is a race NOT worth chasing?
Idempotent actions with no invariant, properly-locked actions (single success), and races with no money/security/business impact. Don't inflate non-issues.

*Know when to walk away so you don't waste hours or file junk:* drop it when **(1)** the action is idempotent with no side-counter — 200 requests changed nothing real (Q9/Q20); **(2)** it's properly locked — you consistently get exactly one success even after widening the window (Q23/Q35/Q40); or **(3)** even if it *does* race, there's **no money, security, or business impact** at the end. Filing "I made a harmless action happen twice" annoys triagers and burns your reputation. A non-reproducible or impact-less race is a non-issue — recognise it fast and move to the next target.

### Q85. How do I quantify impact for the report?
State the broken invariant, the multiplier (N× / negative balance / attempts beyond cap), reproducibility (x/x), and the real-world value (money extractable / accounts takeover-able / fraud at scale).

*Give the triager four numbers and you've written the impact section:* **(1) the broken invariant** in one line ("balance may never go negative"); **(2) the multiplier/magnitude** ("balance reached −$400 / coupon credited 5× / 200 OTP attempts past a cap of 5"); **(3) reproducibility** ("3/3 attempts, 12/20 streams won"); **(4) the real-world value** ("$X extractable per hour / any account takeover-able / contest riggable at scale"). Those four turn a vague "there's a race" into a concrete, rateable, hard-to-dispute finding — and they map directly onto CVSS.

### Q86. What's the most impressive race outcome?
Financial double-spend that creates real money, or an OTP/2FA rate-limit bypass that yields account takeover — both Critical and both reliably demonstrable with single-packet.

*The two trophies:* a **financial double-spend that creates real, withdrawable money** and an **OTP/2FA rate-limit bypass that ends in account takeover**. Both are Critical, both hit universally-understood impact (money and ATO need no explaining to a triager), and both are now **reliably demonstrable on demand** thanks to single-packet — which is exactly why race conditions became a respected, well-paid bug class after 2023. If you can steer a race toward either of these two outcomes, do it; they're the reports that get the top bounties.

---

# TOOLING

### Q87. What's the fastest way to test a race manually?
Burp Repeater **"Send group in parallel"** — capture, group, duplicate ×20–30, send parallel, re-read the invariant. Zero code.

*Your default first move, no scripting:* capture the request → add it to a Repeater **group** → duplicate it 20–30 times → **"Send group in parallel"** → go re-read the invariant (Q19). Five clicks, no code, and Burp silently uses single-packet on HTTP/2. This should be the very first thing you try on any candidate endpoint; only reach for Turbo Intruder when this can't express what you need (Q88). Full click-path is in Q26.

### Q88. When do I need Turbo Intruder over the Burp group?
For higher N, **varying payloads** (OTP brute-race), multi-endpoint races, or custom gate logic. Use the `poc/` templates.

*Graduate to Turbo Intruder when the simple group hits a wall*, specifically for: **higher request counts** than Repeater handles comfortably, **different payload per request** (the OTP brute where each request tries a different code, Q36/Q56), **multi-endpoint** races that need two different request templates on one gate (Q72), or any **custom gate/success logic**. It's Python, but you rarely write it from scratch — the `poc/` folder ships filled-in templates you paste your request into. Rule of thumb: Burp group for "many identical," Turbo for "many different or two-at-once."

### Q89. Is there a standalone (no-Burp) option?
`poc/parallel_fire.py` (async HTTP/2 burst + invariant read) for a quick smell test — but Burp/Turbo are more precise (single-packet).

*If you don't have Burp handy or want a scriptable smoke test*, `poc/parallel_fire.py` fires an async HTTP/2 burst and reads back the invariant for you — handy in CI, on a headless box, or for a fast "is there maybe something here?" check. Just remember its timing is looser than true single-packet, so a **negative** result from it isn't proof of safety (Q37); confirm anything promising with Burp/Turbo before you trust or report it.

### Q90. How do I detect a race win programmatically?
Read the **invariant** before/after (balance/count/flag/attempts) and compare to the 1× control. A status-only check is unreliable.

*Automate the same judgement you'd make by eye:* have your script **read the invariant before the burst, fire, read it after**, and compare the delta to the 1× control (Q17). Win = the state moved beyond what one action should do (balance negative, count > expected, flag effect N×, attempts past cap). Do **not** decide the win from HTTP status alone — twenty `200`s can hide a single-success lock (Q20). Point the script at whatever endpoint exposes the number (the wallet API, a count, the attempts field) and diff it; that's the reliable oracle.

### Q91. Any tooling caveats?
Confirm HTTP/2 first; warm the connection; reset state between runs; and always re-verify the broken invariant manually before reporting.

*The four gotchas that cause false negatives and false positives:* **(1)** check the target actually speaks **HTTP/2** before expecting single-packet (else you're on last-byte-sync, Q30); **(2) warm the connection** so the first slow request doesn't skew timing (Q31); **(3) reset state between runs** or a "used" coupon/spent balance will fake a failure (Q78); and **(4)** always **manually re-verify** the broken invariant before you write the report — never trust an automated "win" you haven't eyeballed. Skipping any of these is how people either miss real races or file false ones.

---

# METHODOLOGY & DECISION TREE

### Q92. Give me the end-to-end methodology.
Find limited actions + invariants → control 1× → fire 20–30 parallel (single-packet) → re-read invariant → repeat 2–3× → escalate to money/ATO/business → control-vs-parallel proof → severity → report.

*The whole hunt on one line, expanded:* **(1) Find** every limited/valuable action and write down each one's invariant (Q13–Q14). **(2) Control** — do it once, record the invariant (Q17). **(3) Burst** — 20–30 in parallel via single-packet (Q26). **(4) Re-read** the invariant (Q19). **(5) Repeat** 2–3× with clean state to prove reliability (Q22). **(6) Escalate** the win toward money/ATO/business impact (Q79–Q80). **(7) Prove** with the control-vs-parallel delta (Q11). **(8) Score** severity (CVSS + CWE, Q98). **(9) Report** with a clear title and the delta up front (Q100). Memorise this loop — it works on every target.

### Q93. The decision tree in words?
Limited action with an invariant? → control 1× → parallel burst → invariant broke? (race) / only 1 ok? (locked) / N×200 unchanged? (idempotent). If race → repeatable? → impact → report.

*The three outcomes after a burst — and what each means:* start with a limited action that has an invariant, take your control, fire the parallel burst, then read the invariant and land in one of three buckets. **Invariant broke** (negative balance / N× credit / 6th attempt accepted) → it's a **race**; check it's repeatable, then chase impact and report. **Only one succeeded** → it's **locked/atomic**; try a wider window or multi-endpoint, else drop (Q23). **Everything returned 200 but nothing changed** → it's **idempotent**; no bug, drop it (Q9). This little three-way fork is the fastest way to triage any endpoint in seconds.

### Q94. How do I prioritize targets?
Money > security gates (ATO) > uniqueness/business > state. And wider-window actions first (easier to win).

*Spend your limited hours where they pay:* rank by impact — **money** (double-spend) beats **security gates** (OTP/login → ATO) beats **uniqueness/business** abuse (bonus farming, oversell) beats pure **state** corruption. Then, within a tier, attack the **wider-window** actions first because they're easier wins (Q15). The ideal first target each session is a high-value action that's *also* slow/multi-step — maximum payout for minimum timing effort. (Full reasoning in Q76.)

### Q95. How do I avoid wasting time?
Drop idempotent and properly-locked actions fast. Spend time on valuable, wider-window, check-then-act endpoints where the invariant is measurable.

*Time-efficiency is a skill — here's the shortcut:* kill dead ends **fast**. If a quick burst shows idempotent (nothing moved) or cleanly locked (exactly one success even after you widen the window), stop and move on — don't romance a non-bug. Pour your hours into endpoints that have all three green flags: **valuable** (real money/security/business impact), **wide-window** (slow/multi-step/external-call), and a **measurable invariant** (a number/flag you can read before and after). Those are where races actually live; everything else is a time sink.

---

# SEVERITY, VALIDITY & FALSE POSITIVES

### Q96. What's the validity bar in one line?
A **repeatable control-vs-parallel delta on the invariant** — "balance went negative / coupon credited N× / 6th OTP accepted, reproduced 3×." Show the state, not the status.

*The single sentence a valid report must be able to say:* **"One action gives the normal result; the parallel burst gives an impossible result; and it happens again every time I try."** That's control + delta + reproducibility, measured on the **state** (the ledger/count/flag), not on the HTTP **status**. If your evidence can't be phrased that way, it isn't over the bar yet — go back and get the control or the reproduction. (This is the same standard as Q11, stated as a validity gate.)

### Q97. What are the classic race false positives?
"N×200 on an idempotent action" (no invariant broke), single-success (locked/atomic), client-only duplication (server dedupes), non-reproducible one-offs, and impact-less duplicate side effects.

*The five ways beginners fool themselves — auto-reject each:* **(1)** *"I got 20× 200 OK!"* on an idempotent action where **no invariant moved** — the status isn't the state (Q20). **(2)** *Single success* with the rest rejected — that's the app being **correctly locked**, not a race (Q23). **(3)** *Client-only duplication* — your tool shows dupes but the **server deduplicated** them, so nothing really doubled. **(4)** *A one-off you can't reproduce* — treat as coincidence until it repeats on clean state (Q78). **(5)** *A duplicate side-effect with no impact* — something happened twice but nobody's worse off. Run every "win" past this list before you get excited or hit submit.

### Q98. How do I set severity/CVSS?
CWE-362 (+367 TOCTOU, + outcome CWE). AC:H is expected (timing) but single-packet makes it reliable. Financial double-spend / OTP→ATO = Critical/High; bounded coupon abuse = Medium/High; business abuse = Medium.

*How to score it without overthinking:* tag **CWE-362** (race) plus **CWE-367** (TOCTOU) and the **outcome** CWE (e.g. CWE-307 for the auth-attempt bypass). In CVSS, **Attack Complexity: High (AC:H)** is expected because it's timing-dependent — but see Q99, single-packet neutralises that in practice. Then anchor the band to impact: **financial double-spend or OTP→ATO = Critical/High**, **bounded coupon/discount abuse = Medium/High**, **general business abuse = Medium**. Let the *outcome* drive the number, and justify it with the four quantified facts from Q85.

### Q99. Why is AC:H not a reason to down-rate?
Because the single-packet attack makes the timing requirement **reliably** satisfiable — if you reproduce it consistently, the practical exploitability is high despite AC:H.

*Pre-empt the triager's favourite down-rate:* someone may argue "it needs precise timing (AC:H), so it's only theoretical, knock it down." Counter with your **reproducibility numbers**: single-packet makes the timing condition satisfiable **on demand**, and you reproduced it 3/3. A requirement that an attacker can meet reliably, every time, with a free public tool is **not** a meaningful barrier — practical exploitability is high. This is exactly *why* races got taken seriously post-2023: the technique removed the "too flaky to matter" excuse. Put the success rate in the report and the AC:H argument evaporates.

### Q100. How do I title a race report?
`Race condition on <action> → <broken invariant / impact>` and lead with the delta + impact. Never just "race condition".

*A good title does half the triage for them:* use the shape **"Race condition on `<action>` → `<broken invariant / impact>`"**, e.g. *"Race condition on `/wallet/withdraw` → balance goes negative, $500 double-spend (reproduced 3×)."* It names the endpoint, the broken invariant, and the impact in one line — a triager knows the severity before opening the body. Then **lead** the report with the control-vs-parallel delta and the impact, not with setup. Never file a bare *"Race condition"* title; it buries the very thing that earns the bounty.

### Q101. What are the ethics/safety rules?
Own accounts/funds; bounded bursts; **no real money out**; no inventory drain; no effect on real users; reset state; respect scope and concurrency rules. Demonstrate the mechanism, not maximum damage.

*The non-negotiables, in one place:* test on **your own** accounts/funds; keep bursts **bounded** (20–30, a few repeats); take **no real money out** and drain **no real inventory**; cause **no effect on real users**; **reset state** when done; and **respect scope** and any concurrency/rate rules in the program's policy. The guiding principle: **demonstrate the mechanism, not the maximum damage.** A clean, reversible proof that the invariant breaks is worth full bounty and keeps you legal; "proving it harder" by causing real loss is how an authorized test becomes a crime (Q24). When unsure, do less and ask the program.

### Q102. How do I de-duplicate?
One well-quantified financial/ATO race beats many "2×200" notes. If coupon-stacking is known, frame your **distinct invariant/impact** (negative balance, OTP bypass, oversell).

*Quality over quantity when you submit:* one **well-quantified** financial or ATO race (with control, delta, reproduction, impact) is worth far more than a pile of shallow "I doubled this action" notes — and dumping many thin reports annoys triagers and can hurt your standing. If a generic issue like coupon-stacking is already known/reported on the program, don't re-file the same thing; instead frame **your distinct invariant and impact** — "not just a discount, this drives a **negative balance**," or "this leads to **OTP bypass → ATO**," or "this causes **oversell**." A unique, higher-impact angle survives dedup; a duplicate of a known bug won't.

---

# REAL-WORLD CASES & REFERENCES

### Q103. What did the single-packet attack change in practice?
PortSwigger's 2023 research ("Smashing the state machine") made races that were previously "theoretical/flaky" **reliably reproducible**, re-opening many limit-overrun and gate-bypass bugs across the industry.

*The "before and after" that every hunter should know:* **before 2023**, race conditions were real but treated as second-class — you might trigger one once and then fail to reproduce it, so triagers often rejected them as flukes and hunters skipped them. James Kettle's *"Smashing the state machine"* (PortSwigger Research, 2023) introduced the single-packet attack, which made races **fire reliably on command**. Overnight, a huge backlog of limit-overrun and gate-bypass bugs became **provable and payable**, and race testing went mainstream. That's why this class is worth learning *now*: the technique that unlocks it is recent, public, and built into free tools.

### Q104. What are common disclosed race patterns?
Gift-card/coupon/credit overrun (apply once-only code N×), withdrawal/transfer double-spend (negative balance), OTP/2FA/rate-limit bypass → ATO, signup-bonus farming, and vote/like inflation — recurring across HackerOne disclosures.

*The patterns that show up again and again in public reports* (study these to know what to look for): **gift-card/coupon/credit overrun** (a once-only code applied N×), **withdrawal/transfer double-spend** (balance driven negative), **OTP/2FA/rate-limit bypass → account takeover**, **signup-bonus farming** (one identity, many bonuses), and **vote/like/review inflation**. Read the disclosed HackerOne reports for each — they're free, concrete case studies that map exactly onto the sub-types in Levels 3–5, and they train your eye for the equivalent feature on your next target.

### Q105. Where can I practice?
PortSwigger Web Security Academy **race-condition labs** (single-packet, limit-overrun, multi-endpoint, partial-construction) — the best hands-on training.

*Do these before hunting for real — they're free and they're the gold standard:* PortSwigger's **Web Security Academy** has a dedicated set of race-condition labs covering the single-packet attack, limit-overrun, multi-endpoint, and partial-construction races, each with a guided solution. Working them teaches you Burp's "Send group in parallel" and Turbo Intruder **in a safe, legal sandbox** so your muscle memory is ready when you hit a live in-scope target. A beginner should not test races on a real program until they've cleared these labs.

### Q106. What's the common thread across big race bugs?
A valuable **check-then-act without atomicity** + the ability to deliver requests **simultaneously** → broken invariant → money/ATO/fraud.

*If you remember one sentence from this whole document, make it this one:* every serious race is the same recipe — a **valuable check-then-act that isn't atomic** (there's a gap between "look" and "do") **+** the ability to **deliver requests at the same instant** (single-packet) **→ broken invariant → money, ATO, or fraud**. Spotting the non-atomic check-then-act on a valuable action is the entire skill; the single-packet attack is just the delivery mechanism that lets you exploit it. Everything else in this guide is detail hanging off that one thread.

### Q107. What further reading matters?
PortSwigger race-conditions topic + the 2023 research paper/talk, Turbo Intruder docs/examples, OWASP WSTG race testing, CWE-362/367/841.

*Your reading list, roughly in order:* **(1)** PortSwigger's **race-conditions topic + labs** (the practical foundation); **(2)** the **2023 research paper and the DEF CON/Black Hat talk** *"Smashing the state machine"* (the theory and the technique's origin); **(3)** the **Turbo Intruder docs and `examples.py`/`race-single-packet.py`** templates (the tooling); **(4)** **OWASP WSTG — Testing for Race Conditions** (methodology, and where races sit inside business-logic testing); **(5)** the CWE entries **362 / 367 / 841** (the vocabulary for your reports). Read them in that order and you'll go from "what's a race?" to "I found and reported one" with no gaps.

---

# DEFENSE — HOW TO STOP RACES PROPERLY

### Q108. The one fix that matters?
Make **check-and-act atomic**: DB row locks (`SELECT … FOR UPDATE`), atomic conditional updates (`UPDATE … SET balance = balance - :amt WHERE balance >= :amt`), or compare-and-swap.

*Why you should understand the fix even as an attacker:* knowing the fix tells you instantly whether a target is exploitable (Q39 vs Q40) and lets you write a **remediation** section that gets your report resolved faster. The fix is always the same idea — **close the gap between check and act so nothing can slip in.** The cleanest form is the **atomic conditional update**: `UPDATE wallet SET balance = balance - :amt WHERE user_id = :id AND balance >= :amt`. Here the database checks `balance >= amt` **and** subtracts in one indivisible statement, so two concurrent requests can't both pass — the loser's `WHERE` simply matches nothing. Row locks (`SELECT … FOR UPDATE`) and compare-and-swap achieve the same "no gap" guarantee. When you *see* this behaviour while testing (exactly one success), that's the fix working.

### Q109. How do I protect once-only / money actions?
**Idempotency keys** (reject duplicate operations), DB **unique constraints** for uniqueness invariants, and transactional integrity around the whole check-act.

*For "do this exactly once" actions:* an **idempotency key** is a unique ID the client sends with the operation; the server records it and **rejects any duplicate** carrying the same key — so a retried/raced payment or claim only ever counts once (payment APIs like Stripe use this). For **uniqueness** invariants (one account per email), the real fix is a database **`UNIQUE` constraint** — the DB itself refuses the second insert, no application check to race (Q66). And wrap the whole check-act in a **transaction** so it commits all-or-nothing. As an attacker, the presence of idempotency keys or unique constraints is your signal the once-only action is likely safe.

### Q110. How do I protect rate/attempt gates?
Increment the counter **atomically before** the check (or use an atomic rate limiter like Redis `INCR` with expiry), so concurrent requests can't all read "under the limit."

*The fix for the OTP/login race (Q53/Q58):* the vulnerable code reads the counter, checks it, *then* increments — so a burst all reads "under the limit" together. The fix flips the order and makes it atomic: **increment first, atomically, then check** the returned value. An atomic counter like Redis `INCR` (with an expiry window) returns each caller a distinct, already-incremented number, so the 6th concurrent request gets "6 > 5" and is blocked even in a burst. No two requests can both see "under the limit," which is exactly the property the race relied on. Seeing a hard per-window cap that a burst can't exceed means the gate is properly built.

### Q111. What about state machines and multi-step flows?
Serialize critical transitions (queues/locks), validate the full state at each step, and avoid TOCTOU gaps where an external call sits between check and commit.

*For the trickier state/multi-endpoint races (Levels 5):* **serialize** critical transitions so they can't overlap — process them through a queue or hold a lock across the whole transition, not just part of it. **Re-validate the full state at each step** rather than trusting a check made earlier (defeats partial-construction and stale-state races). And critically, **don't leave a slow external call (payment, email, scan) sitting inside the check-to-commit gap** — that wide window is what makes these races winnable (Q15); either move the external call outside the critical section or lock across it. These fixes are about eliminating the gap *and* the impossible interleavings, not just row-level atomicity.

### Q112. Defense-in-depth extras?
Pessimistic locking on hot rows, database-level constraints as the last line, idempotent API design, and load-testing/concurrency tests in CI to catch regressions.

*Layered defenses, so one missed lock doesn't sink you:* **pessimistic locking** on hot/contended rows (the wallet, the stock row) forces contenders to wait their turn; **database-level constraints** (unique, check, foreign-key) act as a last line the DB enforces even if the app logic is wrong; **idempotent API design** makes accidental or malicious duplicates harmless by construction; and **concurrency/load tests in CI** (fire N parallel requests and assert the invariant holds) catch races **before** they ship and guard against regressions. The theme: don't rely on a single atomic statement — stack independent guarantees so the invariant survives even when one layer is imperfect. For a bug hunter, a target with these habits is a hard (but respectable) target; for a report, recommending them shows depth.

---

# ADDENDUM (rev. 2) — FILE-UPLOAD TOCTOU, PREDICTABLE TOKENS, OAUTH, WINDOW-WIDENING, MULTI-NODE

### Q113. Can a race ever reach RCE?
Yes — **file-upload TOCTOU** is the one that does. If the app writes the upload to a **web-reachable path first**, then *asynchronously* scans / validates / renames / moves / deletes it, there's a window where a malicious file is **live and executable**. Burst the upload (a webshell, or a polyglot passing the type check) **and** flood GETs at its predicted URL in the same single-packet window — if a GET lands before cleanup, the shell runs → **RCE** (Critical). Use a benign marker (e.g. print `RC-49`) on your own/test path, then stop. (§12.4)

*Why this is the scariest race and how it works in slow motion:* most races top out at money or ATO, but the **file-upload TOCTOU** can reach full **remote code execution** — running your code on their server. The vulnerable pattern: the app **saves your upload to a public folder first**, *then* asynchronously scans/validates/renames/moves or deletes it a moment later. In that gap the malicious file is **live and executable at a URL**. So you do two things in the same window: **upload a webshell** (or a polyglot that passes the type check) *and* **flood GET requests at its predicted URL**. If even one GET lands **before** the cleanup deletes/quarantines it, your code runs → RCE. To stay safe you use a **benign marker** — a script that just prints something like `RC-49` — on your own test path, prove it executed, and stop. Never drop a real webshell on a target. (§12.4 in the guide has the full walkthrough.)

### Q114. How do I win the upload race if the final filename is random?
Race the **read of the temp/quarantine path** (often predictable: original name, `tmp_<seq>`, timestamp) instead of the final name, or race the **"move out of webroot"** step. Also try **two uploads with the same name** (one valid, one shell) so the validated DB record ends up pointing at the shell. Predictable paths + a wide scan window are what make it winnable.

*The catch is knowing WHERE to send your GET flood — you can't hit a random name.* Three ways around it: **(1)** don't chase the final random name — race the **temporary/quarantine path**, which is often predictable (the original filename, `tmp_<sequence>`, a timestamp) and lives briefly in a reachable spot before processing. **(2)** Race the **"move out of webroot"** step itself — hit the file at its initial public location before the move completes. **(3)** Upload **two files with the same name** — one clean, one shell — so the app validates the clean one but the record/file ends up pointing at the shell. The two ingredients that make any of these winnable are a **predictable path** (so you know where to aim) and a **wide scan/processing window** (so you have time to land a GET). Recon the naming scheme first.

### Q115. What's a time-sensitive / predictable-token race?
When a secret is derived from the **server clock or a low-entropy seed**, two requests in the same instant get the **same value**. Trigger a password-reset for the **victim** and for **your own** account in one burst — if the tokens collide, the one mailed to you is also the victim's → reset → **ATO**. Spot it by requesting several tokens: shared prefix / time-correlation / increment = predictable (CWE-330 + CWE-362). (§10.5)

*A sneaky race that attacks weak randomness instead of a counter:* if a "secret" (a password-reset token, an API key, a session ID) is generated from the **server clock** or a **low-entropy seed** — e.g. `md5(timestamp)` — then two requests that arrive in the **same instant** can be handed the **same secret**. The attack: in one simultaneous burst, trigger a password reset for the **victim** *and* for **your own** account. If their tokens collide because they were minted at the same tick, the reset link **emailed to you is also valid for the victim** → you reset their password → **account takeover**. You spot the weakness by requesting several tokens and eyeballing them: a **shared prefix**, **time correlation**, or a visible **increment** means predictable. Tag it **CWE-330** (predictable value) **+ CWE-362** (race). This is a race *and* a crypto-randomness bug at once. (§10.5)

### Q116. Is there a race in OAuth?
Yes — an authorization **`code`** must be single-use. Race the **`code`→token exchange** (same code, N× in one packet): if the server mints **multiple access tokens** (or the PKCE/`state` check isn't atomic) → token replay / session reuse / account-linking abuse. Same for one-time **magic-links** and **email-verification** consumption. (§10.6)

*Where the "used once" rule lives in OAuth:* in an OAuth login, the app gets a short-lived authorization **`code`** and exchanges it for an access **token**; that code is supposed to be **single-use** (spec even says to revoke previously-issued tokens if a code is reused). Race the **code→token exchange** — send the same `code` N× in one packet — and if the server isn't atomic about marking it consumed, it may **mint multiple valid access tokens**, or skip an atomic PKCE/`state` check → token replay, session reuse, or account-linking abuse (which can chain to ATO — see the OAuth kit). The **same single-use-token logic** applies to passwordless **magic-links** and **email-verification** links: race their consumption to reuse a link that should have died after one click. Anywhere the app says "this link/code works once," there's a race to test. (§10.6)

### Q117. My burst gives exactly one success — is it safe?
Not yet ("LOCKED" ≠ "safe"). **Widen the window** first (§8.5): pick the **slow** variant of the action (one that does an external API/payment/email/scan between check and commit), **inflate the request** so parsing takes longer, **connection-warm**, and on HTTP/1.1 lean on last-byte-sync + higher N. Only drop it after the wider-window retry also fails.

*Don't declare "safe" on the first single-success — that's the most common way real races get missed.* "Only one worked" can mean *locked* **or** *your window was too thin to fit a second request*. Before concluding, actively **widen the window** (this is the bouncer's turned-back time again, Q2/Q15): pick the **slowest variant** of the action — the one that makes an external API/payment/email/virus-scan call between check and commit; **inflate the request** (bigger body/headers) so the server spends longer parsing, stretching the gap; **warm the connection** (Q31); and on HTTP/1.1 lean on last-byte-sync with a **higher N** (Q30). Only after a genuine wide-window retry *still* gives one success is "locked/atomic" a fair verdict. Patience here is what separates thorough hunters from ones who leave bounties on the table. (§8.5)

### Q118. The target is behind a load balancer — does that kill races?
Not for shared state. Requests may hit **different backend nodes**, so a limit kept in **per-node memory** (a local counter/cache) often won't collide — but a **shared DB/Redis row** (wallet, coupon, stock) still does. Target shared-state actions, raise N, and repeat. (Bonus: a purely per-node in-memory rate-limit is itself bypassable by spreading requests across nodes — report that too.) (§8.6)

*A load balancer changes the picture but doesn't end the game.* Big sites spread traffic across **many backend servers (nodes)**. If a limit is kept in **one node's local memory** (a per-process counter or cache), your parallel requests may scatter across different nodes and never collide on that in-memory value — the race seems dead. **But** anything backed by **shared state** — a wallet row, a coupon flag, or stock count in the central **database or Redis** — is still one shared thing all nodes touch, so it still races. So: aim at **shared-state actions** (money, coupons, inventory), raise N, and repeat. **Bonus finding:** a purely per-node in-memory rate-limit is itself weak — you can bypass it by *spreading* requests across nodes so no single node sees enough to trip its limit; report that as its own issue. (§8.6)

### Q119. Why does the single-packet attack cap around 20–30 requests?
It's bounded by the TCP **initial congestion window** (~10 packets) and the need to ship all withheld final frames together; it also assumes each request is **small** (only its last frame outstanding). Large bodies / many big headers, HTTP/1.1-only targets, or buffering intermediaries break it → **fall back to last-byte-sync** (§7) and raise N. (§5.4)

*The physics behind the "~20–30" number, in plain terms:* the whole point of single-packet is that all the withheld final frames travel in **one network packet** so they arrive together. But TCP won't let a fresh connection dump unlimited data at once — the **initial congestion window** (roughly 10 packets' worth) limits how much can go in that first burst. Pack too much and it spills into multiple packets, re-introducing the jitter you were killing. This also assumes each request is **small** (only its last frame is outstanding), so **large bodies or many big headers** blow the budget, as do **HTTP/1.1-only** targets and **buffering intermediaries**. When any of those apply, you **fall back to last-byte-sync** (Q30) and compensate with a higher N. That's why ~20–30 small requests is the sweet spot, not a number you should try to push to thousands. (§5.4)

---

# APPENDIX — 60-SECOND FIELD CHECKLIST

*Print this and run it on every candidate endpoint — it's the whole document compressed into nine ticks. Read top to bottom: find the invariant, take the control, fire the burst, re-read, repeat, escalate, prove, stay safe, report. If you can tick every box, you have a valid, high-quality race report; if you can't, the un-ticked line tells you exactly what's still missing.*

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
