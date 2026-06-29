# Request Smuggling — PoC Scripts

Runnable, **benign-by-default** proof-of-concept tooling that backs the Request Smuggling kit. **Click a script to open
it on its own page.** *Authorized testing only:* **DO NO HARM** — smuggling can disrupt real users. Detect with
**timing first**, confirm deterministically on **your own** connections with benign markers, and never run sustained
smuggles against live traffic.

| Script | What it does |
|---|---|
| [`desync_timing.py`](#/smuggling/poc/desync_timing) | **Safe** timing-based desync detector (fresh connection per probe — no socket poisoning). Flags CL.TE/TE.CL signals vs a baseline. |
| [`build_smuggle.py`](#/smuggling/poc/build_smuggle) | Build **byte-exact** CL.TE / TE.CL / TE.TE requests with correct `Content-Length`/chunk sizes to paste into Burp (HTTP/1 raw) or Turbo Intruder. |

## How they fit together

1. **Safe detection first** — `desync_timing.py` (fresh connection per probe).
2. **On a signal**, build a byte-exact probe with `build_smuggle.py` and confirm deterministically in Burp Repeater / Turbo Intruder against a unique smuggle path.
3. **Modern variants** (CL.0 / 0.CL / client-side / connection-state) → use Burp's HTTP Request Smuggler + browser-powered scanner, not a sustained-smuggle script.
4. **Build the impact** (request capture / WAF bypass / cache poisoning) on **your own** connections, prove the capability, then stop.

> Read the **Testing Guide §4–§13** for the desync taxonomy and impact playbooks, and the **Zero to Expert (Q&A)** for
> the do-no-harm methodology.
