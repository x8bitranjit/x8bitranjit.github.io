# Account Takeover — PoC Scripts

Runnable, **benign-by-default** proof-of-concept helpers that back the Account Takeover kit. **Click a script to open
it on its own page.** *Authorized testing only:* use **two accounts you own** (attacker `A`, victim `B`); every proof
ends "**as `A` (or unauthenticated), I'm inside `B`'s account**." The finding is the **takeover** — not the leaked
token or missing limit that got you there. Complete it, read a `B`-only marker, then **restore `B`'s state**.

| Script | What it does |
|---|---|
| [`reset_token_analyzer.py`](#/ato/poc/reset_token_analyzer) | Scores a series of **your own** password-reset tokens for predictability — length, entropy, **sequential / timestamp** structure, reuse, and decodable embedded data (userid / email / timestamp). Pure local analysis, no network. |
| [`reset_poison_probe.py`](#/ato/poc/reset_poison_probe) | Tests the reset flow (control-baselined) for **host / link poisoning** (`Host` / `X-Forwarded-Host` / `X-Host` reflected into the reset link), **token leak** in the response, and **email HPP** (dup-key / array / CRLF second recipient). |
| [`otp_bruteforce.py`](#/ato/poc/otp_bruteforce) | A **rate-limit detector** (not a cracker): sends a **bounded** number of wrong OTPs to **your own** account and reports whether a limiter ever engages — a missing / resettable limit is a **2FA bypass**. Stops as soon as it has the answer. |

## How they fit together

1. **Reset tokens** — `reset_token_analyzer.py` tells you if reset tokens are guessable or forgeable (sequential, timestamp-seeded, or reused across resets).
2. **Reset flow** — `reset_poison_probe.py` looks for the three classic reset takeovers: a poisoned reset link, a token leaked in the response, and a second attacker recipient via parameter pollution.
3. **2FA** — `otp_bruteforce.py` proves whether the OTP verify step has a real rate limit; if not, the second factor is bypassable.

> Read the **Testing Guide** for the full recovery / 2FA / session surfaces and the "cash out any bug as ATO"
> playbooks; the **Checklist** covers the per-flow order. Prove the primitive with these, then finish the takeover by
> hand and show the cross-account result.
