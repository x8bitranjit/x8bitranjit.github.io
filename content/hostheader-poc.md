# Host Header Injection — PoC Scripts

Runnable, **benign-by-default** proof-of-concept tooling that backs the Host Header kit. **Click a script to open it on
its own page.** *Authorized testing only:* the finding is the **sink impact** (ATO / mass XSS / SSRF), not a reflected
header — use your own accounts, benign markers, and **non-shared cache keys**.

| Script | What it does |
|---|---|
| [`hosthdr_probe.py`](#/hostheader/poc/hosthdr_probe) | Fire the spoofing-header set; report where the host **lands** (body / redirect / canonical) and whether the page is **cacheable**. |
| [`reset_poison.py`](#/hostheader/poc/reset_poison) | Trigger a password reset for **your own** account with spoofed hosts; you then check your mailbox for a poisoned link → **ATO**. |
| [`cache_poison.py`](#/hostheader/poc/cache_poison) | Detect reflected-host + **cacheable** + **unkeyed** on a non-shared key with a benign marker → web-cache poisoning. |
| [`wcd_test.py`](#/hostheader/poc/wcd_test) | **Web Cache Deception** tester: append static suffixes (`/x.css`, `;x.css`, `%2Fx.css`) to an authenticated page and check if it's **cached + readable unauthenticated**. |

## How they fit together

1. **Where does the host land?** Run `hosthdr_probe.py` to map reflection (body / redirect / canonical) and cacheability.
2. **The money bug** — `reset_poison.py` against your own account; read your email, a link to your evil host = ATO.
3. **Cache poisoning** — `cache_poison.py` proves reflected + cacheable + unkeyed on a unique key, then describe the shared impact.
4. **Web Cache Deception** — `wcd_test.py` checks if an authenticated page leaks via a static-suffix cache trick.

> Read the **Testing Guide §4–§6/§11/§12** for the landing-vs-sink model and the **Zero to Expert (Q&A)** for
> reset-poisoning and routing-SSRF chains.
