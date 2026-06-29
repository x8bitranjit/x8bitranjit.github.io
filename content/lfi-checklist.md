# LFI Testing Checklist — tick per sink

> Companion to `LFI_TESTING_GUIDE.md`. Work top-to-bottom **per file/path sink**. The goal is never `/etc/passwd` —
> it's **secrets/source disclosure** or **RCE/shell**. Stop and report only when you can demonstrate one (or honestly
> downgrade to "traversal confirmed = Medium").

## PHASE 0 — Recon (§3)
- [ ] Enumerated every param/feature that selects a file/path/template (page/file/template/lang/download/view/…).
- [ ] Fuzzed param **names** (Arjun) across endpoints; checked downloads/exports/PDF/report/log-viewer features.
- [ ] Grepped JS/source (JS-files kit) for include/require/readFile/sendFile/render with user input.
- [ ] Noted any base path/suffix leaked in error messages/stack traces.

## PHASE 1 — Baseline (§4)
- [ ] Confirmed traversal by reading a known file (`/etc/passwd` / `win.ini`), sweeping depth 1–12.
- [ ] Determined **READ vs INCLUDE** (raw source returned = read; executed output / poisoned PHP runs = include).
- [ ] Identified the **stack** (PHP / Java / Node / Python / .NET) and any forced **prefix dir** / **suffix extension**.

## PHASE 2 — Reach the file (§5–§8)
- [ ] Escaped the directory (depth-sweep / absolute path).
- [ ] Defeated the forced suffix (null byte / `php://filter` / poison a real on-disk path).
- [ ] Bypassed `../` filtering (`....//`, `%252f`, overlong, backslash) — found the one that lands.
- [ ] Satisfied any allowlist/prefix then traversed out.

## PHASE 3 — Wrappers (§9/§10)
- [ ] (PHP) Dumped source via `php://filter/convert.base64-encode/resource=` and decoded.
- [ ] Pulled **config/.env/keys**; checked `allow_url_include` (for data://) from a dumped config/phpinfo.

## PHASE 4 — Impact: climb to RCE (§10–§16)
- [ ] **Secrets/source disclosure (§10):** read config/.env/DB-cloud creds/private keys (redact; validate read-only).
- [ ] **RCE — log poisoning (§11):** poisoned web/SSH/mail log via User-Agent/request, included it, `id` ran.
- [ ] **RCE — filter-chain (§12):** generated a `php://filter` chain → command executed (no file write needed).
- [ ] **RCE — session/`/proc` (§13):** poisoned `$_SESSION`/`/proc/self/environ`, included it → `id`.
- [ ] **RCE — `session.upload_progress` (§13):** no reflected field → multipart `PHP_SESSION_UPLOAD_PROGRESS=<?php…?>` + **race** the `sess_<id>` include → `id`.
- [ ] **RCE — wrappers (§14):** `data://`/`php://input`/`expect://`/`phar://` executed a benign command.
- [ ] **RCE — `pearcmd.php` (§15):** default PHP image, no upload/log → `?page=/usr/local/lib/php/pearcmd.php&+config-create+…` writes a shell → include → `id`.
- [ ] **RCE — upload+include / phpinfo race (§15):** included uploaded PHP bytes / won the temp-file race.
- [ ] **Windows/other (§16):** `web.config` `machineKey`/conn strings → forge auth; non-PHP → disclosure/SSTI pivot.
- [ ] **Server/infra traversal (§16.3):** Apache 2.4.49/50 `/cgi-bin/.%2e/…` (file read + RCE) · nginx `alias` off-by-slash · IIS unicode · proxy `%2e/%2f` decode mismatch.
- [ ] **Second-order / stored LFI (§16.4):** stored a traversal/wrapper payload in a theme/template/locale/filename → triggered the consumer → read/RCE (often higher-priv context).

## PHASE 5 — Validate → report
- [ ] Escalated past `/etc/passwd` to **secrets or RCE** (FP check §18 — passwd alone ≈ Medium).
- [ ] Validated disclosed creds **read-only**; for RCE used a **benign marker** (`echo token` / `id`).
- [ ] **Cleaned up** poisoned logs / uploaded files / poisoned sessions.
- [ ] Confirmed on **production**; re-tested partial fixes (`../`→`....//`, passwd→`php://filter`).
- [ ] Set CVSS 3.1 + **CWE-98 / CWE-22 / CWE-73** (+ CWE-94 if RCE) (§19).
- [ ] SAFE PoC: minimal redacted content / single marker, artifacts removed (§21).
- [ ] De-duped to one finding per sink/root cause; led with the highest impact (§22).

## AUTO-REJECT (don't submit if…)
- [ ] `/etc/passwd` read reported as Critical (it's traversal proof ≈ Medium — escalate).
- [ ] A 404/error merely **echoing** your path (no file contents returned).
- [ ] Reading a file the app is meant to serve (a public asset), not outside the intended dir.
- [ ] `php://filter` of a non-sensitive file (no secrets/source value).
- [ ] Blind timing with no demonstrated read or RCE.
- [ ] A client-side/source-map file mislabeled as server LFI.
