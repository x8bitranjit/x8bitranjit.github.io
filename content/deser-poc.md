# Insecure Deserialization — PoC Scripts

Tooling for the Deserialization kit. *Authorized testing only.* Deserialization is an **RCE** class — the finding is **a benign command executing** (OOB / `sleep` / `id`) or an **object-tamper auth bypass**, not "this base64 decodes to a serialized object". Confirm with a **blind DNS gadget first**, run **one** benign command, then STOP. **Click a script to open its source.**

| Script | What it does |
|---|---|
| [`deser_detect.py`](#/deser/poc/deser_detect) | **Fingerprints** a blob (cookie / ViewState / token / field) as Java / PHP / .NET / Python / Ruby / Node / JSON-gadget serialized data (handles base64 + gzip) and names the tool to use. Recognition is step 1. |
| [`pickle_poc.py`](#/deser/poc/pickle_poc) | Generates a **Python** payload (pickle `__reduce__` / PyYAML / jsonpickle) that runs a **benign** command; `--dns` for a clean blind confirm. |
| [`php_object_poc.py`](#/deser/poc/php_object_poc) | Builds **PHP** serialized objects for **object-injection / auth-bypass** (flip `isAdmin`/role) plus a `__wakeup`-bypass variant. (RCE POP chains → PHPGGC.) |
| [`ysoserial_cheat.md`](#/deser/poc/ysoserial_cheat) | The **gadget-tool** cheat: **ysoserial** (Java + URLDNS), **ysoserial.net** (.NET + **ViewState**), **PHPGGC** (PHP + **phar**), **marshalsec** (JNDI). |

## Typical flow
1. **Recognize** the format of a suspicious cookie/token (`deser_detect.py`).
2. **Confirm safely** — a blind DNS/URLDNS gadget (`ysoserial URLDNS`, `pickle_poc.py --dns`) proves exec without touching data.
3. **Exploit** with the matching tool — **one** benign command (`id` / `nslookup <token>`), then STOP.
4. **No gadget?** Tamper the object for an auth bypass (`php_object_poc.py`) on your **own** session.

> OOB/URLDNS-first, one benign command, then stop — no shells, no persistence, no data access; delete uploaded phar/pickle artifacts; tear down JNDI/LDAP/OOB listeners. Signed/MAC'd blob without the key = not exploitable; don't over-claim.
