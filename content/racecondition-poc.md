# Race Condition — PoC Scripts

Runnable, **benign-by-default** proof-of-concept templates that back the Race Condition kit. **Click a script
to open it on its own page.** *Authorized testing only:* race your own accounts/balances/coupons, reproduce
the broken invariant, then stop — never drain real funds or affect other users.

| Script | What it does |
|---|---|
| [`race_single_packet.py`](#/racecondition/poc/race_single_packet) | **Turbo Intruder template** — fires N identical requests in a single HTTP/2 packet (limit-overrun / double-spend / duplicate-action proof). Paste into Burp's Turbo Intruder script panel. |
| [`race_otp_bruteforce.py`](#/racecondition/poc/race_otp_bruteforce) | **Turbo Intruder template** — parallel OTP/code guesses in one packet to demonstrate a rate-limit bypass on an attempt-counting gate. Mark the OTP position with `%s` in the Burp request. |
| [`parallel_fire.py`](#/racecondition/poc/parallel_fire) | **Standalone helper** — reads an invariant (e.g. balance), fires N parallel HTTP/2 requests (e.g. coupon applies), re-reads the invariant, and prints the delta. No Burp needed. |

## How they fit together

1. **Control first** — run the action once, confirm the invariant holds (balance unchanged, coupon counted once).
2. **Turbo Intruder path** — paste `race_single_packet.py` into Burp's Turbo Intruder, fire 20–30 parallel requests, re-read the invariant; the status column alone lies.
3. **Standalone path** — use `parallel_fire.py` with `--action` + `--invariant` to prove the delta without Burp.
4. **OTP/rate-limit bypass** — `race_otp_bruteforce.py` shows a code-gate is not thread-safe; count accepted vs rejected.

> Read the **Testing Guide §5–§8** for the single-packet attack and window-widening detail, and the
> **Zero to Expert (Q&A)** for timing, distributed environments, and file-upload TOCTOU chains.
