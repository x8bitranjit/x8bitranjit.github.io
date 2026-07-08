# Dependency Confusion — PoC Scripts

Runnable proof-of-concept helpers that back the Dependency Confusion kit. **Click a script to open it on its own
page.** **Authorized + responsible-disclosure ONLY:** detect widely (read-only); publish **only** a name in your
**authorized scope**, prove with a **benign beacon** (token + hostname), **unpublish immediately**, and report so the
org reserves the namespace. The finding is a **callback from the target's build** — never a payload, never a secret dump.

| Script | What it does |
|---|---|
| [`manifest_scan.py`](#/depconfusion/poc/manifest_scan) | Extracts dependency names from `package.json` / `package-lock.json` / `requirements.txt` / `Pipfile` / `composer.json` / `Gemfile` / `pom.xml` / `*.csproj` (scoped vs. unscoped). Pure local parse, no network. |
| [`claimable_check.py`](#/depconfusion/poc/claimable_check) | **Read-only** public-registry lookups (npm / PyPI): a **404 = unregistered = claimable candidate**. Publishes nothing, changes nothing. Low false-positive. |
| [`benign_callback_pkg.py`](#/depconfusion/poc/benign_callback_pkg) | **Generates** (never publishes) an **inert** PoC package skeleton whose install hook does one fire-and-forget callback (token + hostname) — no exfil / shell / persistence. You review it, publish an **authorized** name manually, then **unpublish** after the callback. |

## How they fit together

1. **Harvest** — `manifest_scan.py` pulls internal dependency names out of a leaked manifest or lockfile.
2. **Check claimability** — `claimable_check.py` asks the public registry which of those names are unregistered (a 404 is the candidate).
3. **Prove benignly** — `benign_callback_pkg.py` generates an inert beacon package; you publish an **authorized** name, catch the callback from the target's CI, then **unpublish** and report.

> Read the **Testing Guide** for the per-ecosystem resolution rules, the responsible-disclosure gate, and the recon
> sources; the **Checklist** enforces the publish → unpublish → report discipline. A benign callback is the whole
> proof — never exfiltrate CI secrets or source.
