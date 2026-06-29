# LFI — PoC Scripts

Runnable, **benign-by-default** proof-of-concept tooling that backs the LFI kit. **Click a script to open it on its own
page.** *Authorized testing only:* the finding is **secrets/source** or **RCE** — never `/etc/passwd` alone. Prove RCE
with one benign marker, validate disclosed creds read-only, and **clean up** poisoned logs / uploaded files / sessions.

| Script | What it does |
|---|---|
| [`lfi_fuzz.py`](#/lfi/poc/lfi_fuzz) | Spray traversal/encoding/wrapper payloads at a `FUZZ` point; flag responses matching real file-content **signatures** (not reflected 404s). |
| [`phpfilter_dump.py`](#/lfi/poc/phpfilter_dump) | Dump PHP **source/secrets** via `php://filter` base64 and decode locally; highlights secret indicators. |
| [`filter_chain_rce.py`](#/lfi/poc/filter_chain_rce) | Build a `php://filter` **chain → RCE** with no file write / no remote URL (or print the byte-correct synacktiv command). |
| [`logpoison.py`](#/lfi/poc/logpoison) | LFI→RCE via **log poisoning**: inject PHP into a logged field, then include the log and run a benign marker. |

## How they fit together

1. **Confirm a read** — `lfi_fuzz.py` with wrappers + depth; match real file-content signatures, not reflected 404s.
2. **Dump source + secrets** (PHP) — `phpfilter_dump.py` for `config.php` / `.env` / `database.php`.
3. **Escalate to RCE**, in order: `logpoison.py` (if logs are includable) → `filter_chain_rce.py` (no file write / no remote URL).
4. **Prove with one marker** (`echo <token>` / `id`), then STOP and clean up.

> Read the **Testing Guide §5–§12** for the wrapper/chain ladder and the **Zero to Expert (Q&A)** for the filter-chain
> RCE primitive and log-poisoning detail.
