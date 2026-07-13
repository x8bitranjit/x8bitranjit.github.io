# Path / Directory Traversal — Checklist (tick per sink)

> Companion to `PATH_TRAVERSAL_TESTING_GUIDE.md`. The finding is **escaping the base dir + impact** (secret/cross-user
> READ, or out-of-dir WRITE → RCE), never a same-dir path change or a bare `/etc/passwd`. An **include/execute** sink is
> an **LFI/RFI** report, not this. Send `../` raw (`--path-as-is`/Burp). Work top-to-bottom.

## PHASE 0 — Recon (§3)
- [ ] Found **READ/serve** sinks: download/export/attachment/view-file/preview/avatar/PDF/report/backup fetchers.
- [ ] Found **static routing** (`/static`,`/assets`,`/files`,`/media`) → test server-normalization (§8).
- [ ] Found **archive extract** sinks (import ZIP / restore / theme-plugin install / bulk import) → **Zip-Slip** (§12) — top priority.
- [ ] Found **upload filename/dest-path** and **save/export/log-path** sinks (§13/§14).
- [ ] Discovered hidden `file/path/name/dest/save` params (Arjun/Param Miner); noted absolute-path leaks in errors (base dir + OS).

## PHASE 1 — Baseline & classify (§4)
- [ ] Confirmed the value **is** the path (same-dir control vs traversal changes the response).
- [ ] Sent `../` **raw** (`curl --path-as-is`/Burp), not collapsed client-side.
- [ ] **Classified the sink:** READ/serve · WRITE · INCLUDE/EXECUTE(→ **LFI kit**) · absolute-path accepted (skip depth).

## PHASE 2 — Reach / bypass (§5–§8)
- [ ] Escaped the dir: varying-depth `../`, over-traverse, **absolute path**, `....//` (strip-reform), Windows `..\`.
- [ ] Encoding: `..%2f`, `%252e%252e%252f` (double), overlong `%c0%af`, unicode, legacy `%00` (§6).
- [ ] Beat **prefix/suffix/allowlist**: climb the prepended base dir; defeat forced `.ext` (target a real `.ext`/legacy truncation); traverse from an allowed name (§7).
- [ ] **Server-normalization**: nginx `alias` off-by-slash (`/static../`), Tomcat `..;/` → `WEB-INF`, encoded-slash-at-proxy, IIS (§8).
- [ ] **Language foot-gun**: tried a plain **absolute path** on Python/.NET/Java (`os.path.join`/`Path.Combine` discard the base) (§15).

## PHASE 3 — Impact (§9–§15)
- [ ] **READ → secrets/source (§10):** `.env`/config/keys/cloud-creds/source/`/proc/self/environ`/k8s token — then pivot the creds (SSRF/JWT).
- [ ] **READ → other users'/tenant (§11):** traversed/swapped to another (own second) account's files / session-token files → PII/ATO.
- [ ] **WRITE → Zip-Slip (§12):** benign marker written **outside** the extraction dir (path shown) → webshell-in-webroot escalation described.
- [ ] **WRITE → upload-path (§13):** `../` in filename/dest wrote to webroot / overwrote a served file (FileUpload kit for executability).
- [ ] **WRITE → save/export (§14):** overwrote (benign-proof) `~/.ssh/authorized_keys`/cron/config location → RCE/persistence described.

## PHASE 4 — Validate → report
- [ ] Proved **out-of-dir escape + impact** (secret/cross-user read, or out-of-dir write), not a same-dir change (FP check §17).
- [ ] READ only enough to prove it (secrets/PII **redacted**, own second account as victim); WRITE only **benign markers** to safe paths; **no real file overwritten/deleted**.
- [ ] Confirmed on **production**; re-tested partial fixes (single `../` strip but not `....//`; app fixed but nginx `alias` not).
- [ ] Set CVSS 3.1 + **CWE-22** (+ CWE-36/23/434/59/73 by variant) (§18).
- [ ] De-duped: one root cause per finding; read vs write usually separate; include/execute → LFI report (§21).

## AUTO-REJECT (don't submit if…)
- [ ] `../` **changed the response but stayed inside the base dir** (no escape).
- [ ] `/etc/passwd`/`win.ini` read reported as **Critical** (it's Medium — climb to secrets).
- [ ] The `../` was **collapsed client-side** (use `--path-as-is`/Burp).
- [ ] "Zip-Slip" with **no proof** a file landed **outside** the extraction dir.
- [ ] A write that lands **only inside your own upload dir** (no escape).
- [ ] Reading a file the app is **supposed** to serve (intended behavior).
- [ ] An **include/execute** sink reported here (→ LFI/RFI kit for the RCE).
