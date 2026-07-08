# JNDI Injection & Log4Shell — PoC Scripts

Runnable, **detection-only** proof-of-concept helpers that back the JNDI / Log4Shell kit. **Click a script to open it
on its own page.** *Authorized testing only:* the finding is a **target-sourced OOB callback carrying your unique
per-input token** (blind RCE) — not a reflected `${jndi:}` or a scanner banner. These tools **detect and confirm**;
they deliberately do **not** deliver a gadget (use marshalsec + ysoserial on an authorized engagement, fire **one**
benign command, then stop).

| Script | What it does |
|---|---|
| [`payload_gen.py`](#/jndi/poc/payload_gen) | Prints the full `${jndi:}` payload matrix for **your** OOB host — protocols (`ldap` / `dns` / `rmi` / `ldaps` / `iiop`), **nested-lookup WAF bypasses** (`${lower:}`, `${::-}`), **`${env}` secret-exfil**, and JVM-fingerprint lookups. Pure generator, no network. |
| [`jndi_probe.py`](#/jndi/poc/jndi_probe) | Sprays a `${jndi:}` payload into every header and parameter with a **per-input token** (`<input>-<nonce>.oob`) so a callback tells you exactly **which input** is the sink. Supports `--dns` (egress-friendly) and `--style obf` (WAF bypass). Detection only. |
| [`callback_listener.py`](#/jndi/poc/callback_listener) | A benign **multi-port TCP connection logger** for when you can't use interactsh — it confirms the target JVM **connected back** (source IP + first bytes) and serves **no** gadget. |

## How they fit together

1. **Generate** — `payload_gen.py` builds the payloads (and WAF-bypass variants) pointed at your own OOB host.
2. **Spray + attribute** — `jndi_probe.py` fires them into every logged input with a unique token each, so a single callback names the exact vulnerable header or parameter.
3. **Confirm the callback** — point the payload at `callback_listener.py` (or interactsh); a hit from the target's egress IP is the blind-RCE proof.

> Read the **Testing Guide** for the Log4j version matrix, the three RCE techniques, and the boundary vs. LDAP-filter
> injection / deserialization; the **Checklist** covers the per-input sequence. Detection only here — RCE delivery uses
> the established exploit servers on an authorized engagement, one benign command, then STOP.
