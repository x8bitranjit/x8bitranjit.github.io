# Path / Directory Traversal — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **Path / Directory Traversal (CWE-22)** — from "what is `../`" to the
> chains that actually pay: **read-traversal → secrets/source → creds → RCE/cloud pivot**, **cross-tenant file read →
> PII/ATO**, and the side this kit owns — **WRITE-traversal: Zip-Slip (archive extraction), upload-path, and save/export
> → webshell or `authorized_keys`/cron overwrite → RCE/persistence**, plus **web-server/framework normalization**
> bypasses (nginx `alias`, Tomcat `..;/`, IIS Unicode, Python/.NET absolute-path foot-guns). Q&A format, progressive
> difficulty.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, and your own labs. READ only enough to
> prove impact (redact secrets/PII, use a second own account as "victim"); WRITE only **benign markers** to safe paths;
> **never overwrite or delete real files**; drop a live webshell only on your own instance.
>
> **Boundary with the LFI kit:** if the sink **includes/executes** the file (PHP `include`, template eval) → that's
> **LFI/RFI** (RCE via wrappers/log-poison/filter-chain) — use that kit. This kit is for files **read, served, or
> written as bytes** (never executed as code by the sink itself).

**Canonical references** (cited throughout — real and worth reading):
- PortSwigger Web Security Academy — *Directory traversal* (+ labs) · OWASP — *Path Traversal* / WSTG-ATHZ-01
- Snyk — *Zip Slip* (2018) · Python `tarfile`/`zipfile` extraction traversal (CVE-2007-4559)
- PayloadsAllTheThings — *Directory Traversal* · HackTricks — *File path traversal*
- CWE-22 · CWE-23 · CWE-24/25 · CWE-36 · CWE-59 · CWE-73 · CWE-434
- Companion kit in this repo: `Web/PathTraversal/` (guide + arsenal + checklist + report template + `poc/`); siblings `Web/LFI/` (include→RCE), `Web/RFI/`, `Web/FileUpload/`, `Web/SSRF/`, `Web/IDOR/`, `Web/JWT/`.

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals (what/direction/why)** (Q1–Q12)
- **Level 1 — Recon & baseline** (Q13–Q24)
- **Level 2 — Reachability & bypass** (Q25–Q44)
- **Level 3 — Exploitation: READ impact** (Q45–Q56)
- **Level 4 — Exploitation: WRITE impact (Zip-Slip & friends)** (Q57–Q74)
- **Tooling** (Q75–Q80)
- **Black-box methodology & checklist** (Q81–Q85)
- **Cheat sheets** (Q86–Q90)
- **Real-world patterns & references** (Q91–Q94)
- **Defense — safe path handling** (Q95–Q100)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is path traversal in one breath?
The app uses a client-controlled value as (part of) a filesystem path and doesn't confine it to an intended base directory, so `../` (or an absolute path, or an encoded/OS variant) lets you step out and reach arbitrary files — to **read**, **serve**, or **write** them. CWE-22.

### Q2. How is this different from the LFI kit?
LFI is traversal into a sink that **includes/executes** the file (`include()`), so poisoned content **runs** → RCE via wrappers, log poisoning, and filter-chains. This kit covers traversal where the file is **read/served/written as bytes** and never executed by the sink — download endpoints, static serving, archive extraction, upload paths. Different impact ceilings, different playbooks.

### Q3. What are the three sink directions and why do they matter?
**READ/serve** → returns file bytes → disclosure (Med–High). **WRITE** → creates/overwrites a file → RCE/overwrite (High–Critical). **INCLUDE/EXECUTE** → runs the file → that's LFI. Classifying the direction in Phase 1 decides your entire approach and the severity.

### Q4. Which direction pays the most?
WRITE. A traversal in archive extraction (Zip-Slip), an upload filename, or a save/export path lets you drop a **webshell** in the webroot or overwrite **`~/.ssh/authorized_keys`**/cron → **RCE/persistence (Critical)**. Write-traversal routinely out-pays read-traversal, and this kit is where it lives.

### Q5. Is reading `/etc/passwd` a good finding?
It's **proof**, not impact — `passwd` is non-secret by design, so a read of it is **Medium**. The bounty is reading **secrets** (`.env`, config, keys, cloud creds, source) or **other users'** files. Never stop at `passwd`.

### Q6. Why is a pure read sink still valuable even though it can't do `php://filter`?
Because reading the *right* file — `.env`/config → DB/cloud creds, an SSH key, the app source — is **High**, and those creds frequently lead to **RCE or cloud takeover elsewhere**. No wrapper/log-poison RCE on a read sink, but the disclosure itself opens the door.

### Q7. What CWE do I cite?
**CWE-22** (Path Traversal) is the anchor. Variants: **CWE-23** (relative), **CWE-24/25** (`../`/`..\`), **CWE-36** (absolute path), **CWE-59** (symlink following), **CWE-73** (external control of filename/path), and **CWE-434** when the write is via file upload.

### Q8. What's the single most common filter-bypass payload?
`....//` — against a filter that strips `../` **once**, the remnant re-forms `../`. Also `..;/` for Java/Tomcat and `..%2f`/`%252e%252e%252f` for decode-layer gaps.

### Q9. Why must I use `curl --path-as-is` or Burp?
Because curl and browsers **collapse `../` client-side** before sending, so the traversal never reaches the server and you get a false negative. `--path-as-is` (curl) and Burp Repeater send the bytes verbatim.

### Q10. What's Zip-Slip in one line?
An archive (zip/tar/jar) whose entry name contains `../` — when the app extracts it and uses the entry name as the output path without confinement, the file is **written outside the extraction directory** (e.g. into the webroot) → webshell → RCE. Snyk disclosed it across many libraries in 2018.

### Q11. What's the "absolute path replaces base" foot-gun?
In Python `os.path.join(base, user)` and .NET `Path.Combine(base, user)`, if `user` is an **absolute path**, the base is **discarded** — `os.path.join('/var/data','/etc/passwd')` == `/etc/passwd`. So on Python/.NET/Java targets, try a plain absolute path *before* bothering with `../` — you may not even need traversal.

### Q12. What's the minimum I need to test traversal?
Burp/`curl --path-as-is` (so `../` transmits), knowledge of read-vs-write-vs-include, the traversal+encoding+server-normalization payload sets, and — for the write side — a way to build a Zip-Slip archive and a safe path to prove an out-of-dir write.

---

# LEVEL 1 — RECON & BASELINE

### Q13. Which endpoints are read-sink candidates?
Anything that returns a file: download/export/attachment, "view file"/preview, avatar/image-by-name, invoice/PDF/report fetchers, backup downloaders, log viewers. Params: `file`, `path`, `download`, `doc`, `name`, `key`, `resource`.

### Q14. Which features are the high-value WRITE candidates?
Archive-handling: "import ZIP", "restore backup", "install theme/plugin", "bulk import", avatar-zip, "upload .tar.gz" → **Zip-Slip**. Also uploads where you control the filename/dest, and "save report to <path>"/export/log-naming sinks. The import-ZIP feature is the top recon hit.

### Q15. Where do server-normalization traversals live?
On static routes — `/static`, `/assets`, `/files`, `/media`, `/cdn` — served by the web server/proxy, not app code. Test these even when app params are locked down (nginx `alias` off-by-slash, Tomcat `..;/`).

### Q16. How do I find hidden path params?
Arjun/Param Miner against download/upload/export endpoints; `gau`/`katana` + `gf` over historical URLs for `file`/`path`/`name`/`dest`. Error messages that leak absolute paths tell you the base dir and OS.

### Q17. What's the read baseline procedure?
Note the normal value's response; confirm the value *is* the path with a same-dir control (`./welcome.txt`); then traverse to a known file (`../../../../etc/passwd` or `..\..\windows\win.ini`) sent raw; sweep depth 1–12 or jump to an absolute path.

### Q18. How do I classify read vs write vs include?
Bytes of a file come back → **read**. A file is created/overwritten server-side → **write**. The file's content is executed/rendered as code → **include** (→ LFI kit). If an absolute path works with no `../`, note CWE-36 and skip the depth sweep.

### Q19. How do I over-traverse when I don't know the depth?
Prepend more `../` than needed — extra `../` at `/` are harmless (you can't go above root), so `../` × 8–12 almost always reaches the root regardless of base depth. Or just use an absolute path.

### Q20. The response is 404/500 on my payload — dead?
Maybe the file doesn't exist at that depth, or the payload was collapsed. Confirm you used `--path-as-is`, sweep depth, try an absolute path, and try encoding. A 404 on one payload isn't a no.

### Q21. How do I detect the OS?
Try both `../../etc/passwd` and `..\..\windows\win.ini`; a working one reveals the OS. Error messages leaking `C:\` or `/var/www` do too. It decides separator (`\` vs `/`) and target files.

### Q22. What tells me it's a server-normalization bug vs an app bug?
If a payload works on a **static route** (`/static../`) or uses **`..;/`**/encoded slashes that the app never sees decoded, it's the server/framework. Cite the exact server + version; the fix is config, not code.

### Q23. What's the deliverable after recon+baseline?
A list of `(endpoint, param/source, direction)` with at least one confirmed traversal, its direction (read/write/include), and the OS/base-dir hints — so you know which impact playbook to run.

### Q24. Should I test uploads even if there's no obvious path param?
Yes — the **filename** in a multipart upload, a JSON `path`/`dest` field, or archive **entry names** are all path sources even when there's no `?file=`. These are the write-traversal goldmine.

---

# LEVEL 2 — REACHABILITY & BYPASS

### Q25. Walk the core traversal escapes.
Relative varying-depth (`../`×N), over-traversal, absolute path (`/etc/passwd`), Windows separators (`..\`, `..%5c`), and non-recursive `....//` (survives a one-pass `../` strip). Pick based on the filter you hit.

### Q26. Why does `....//` beat a `../`-stripping filter?
The filter removes the inner `../` from `....//`, leaving `../` — the strip *creates* the very sequence it tried to remove. Any non-recursive (single-pass) strip falls to it. `..../\`, `....\/` are variants.

### Q27. When do I use encoding?
When raw `../` is filtered but the value is URL-decoded server-side: `..%2f`. When a WAF/proxy sits in front: double-encode `%252e%252e%252f` (proxy decodes to `%2e%2e/`, app decodes to `../`). Legacy IIS/older stacks: overlong UTF-8 `%c0%af`.

### Q28. What's the double-encoding mechanic exactly?
Each decode layer removes one encoding pass. If validation runs *after* one decode but the file open runs *after* two, `%252f` passes validation (looks like `%2f`) then becomes `/` at the open. The bug is the mismatch in **how many times** each layer decodes.

### Q29. What are overlong UTF-8 traversals?
Non-canonical multi-byte encodings of `.` and `/` that legacy parsers (old IIS) accept: `%c0%ae` = `.`, `%c0%af` = `/`, `%c1%9c` = `\`. `..%c0%af..%c0%afetc%c0%afpasswd`. The historical IIS Unicode traversals.

### Q30. How do I beat a forced base-dir prefix?
If the code does `open(BASE + "/" + input)`, your input just needs enough `../` to climb out of BASE: `../../../../etc/passwd` → `BASE/../../../../etc/passwd` resolves to `/etc/passwd`. You don't need an absolute path.

### Q31. How do I beat a forced suffix/extension (`.png` appended)?
Modern stacks killed the null byte, so: (a) target a file that already ends in the forced ext (a real `.log`/`.pdf`/`.bak`), (b) legacy PHP **path truncation** (pad `/././…` past ~4096 chars so the appended ext falls off), or (c) legacy `%00`. If none work, the suffix may genuinely constrain you.

### Q32. How do I beat a name allowlist?
Traverse *from* an allowed value if the code concatenates a subpath (`allowed.txt/../../../etc/passwd`), or exploit a substring/prefix check (`/var/www/allowed/../../../etc/passwd`, `/base/../../../etc/passwd`). The allowlist entry becomes your anchor to climb from.

### Q33. Explain the nginx `alias` off-by-slash traversal.
Config: `location /static { alias /var/www/app/static/; }` — the `location` has **no** trailing slash but the `alias` does. Request `/static../` maps to `/var/www/app/static/../` = `/var/www/app/`, so `/static../../etc/passwd` reaches `/etc/passwd`. A pure config bug — no app involvement.

### Q34. Explain the Tomcat `..;/` traversal.
In Java servlet containers, `;` starts a path parameter. The security constraint mapper and the file resolver disagree on where the path ends, so `/app/..;/..;/WEB-INF/web.xml` bypasses the constraint protecting `WEB-INF/` → read source, `web.xml`, DB creds. `..;/` and `/;/../` are the payloads.

### Q35. What's the encoded-slash-at-proxy trick?
A fronting proxy/CDN doesn't decode `%2f`/`%5c` but the origin does (or vice versa), so `/api/%2e%2e%2f%2e%2e%2fWEB-INF/...` passes the proxy's path checks and reaches internal paths at the origin. Layer-mismatch again, at the network edge.

### Q36. Do Express/Spring/Go have traversal quirks?
Yes — Express `express.static` has had encoded-traversal decode bugs; Spring mishandled `..%2f`/`..;` on some versions; Go's `filepath.Join`/`path.Clean` clean but don't *confine*, and `http.ServeFile` has gaps. Always test the framework's static handler, not just app code.

### Q37. What's the Windows-specific arsenal?
`..\` and `..%5c`; drive-absolute `C:\`; **UNC** `\\attacker\share\` (traversal → outbound SMB → NetNTLM capture/relay); trailing dot/space trim (`file.aspx.` == `file.aspx`); **ADS** `file.aspx::$DATA` (read .NET source); 8.3 short names.

### Q38. Why try a plain absolute path first on Python/.NET?
Because `os.path.join`/`Path.Combine` **discard the base dir** when the second argument is absolute — so `/etc/passwd` or `C:\windows\win.ini` as the input reaches the file with **no `../` needed** and often bypasses `../`-focused filters entirely. It's the cheapest win on those stacks.

### Q39. How do I know which encoding layer decodes?
Empirically: send `..%2f` (single), `%252e%252e%252f` (double), `%c0%af` (overlong) and observe which reaches the file. Or read the stack (a CDN/WAF in front strongly suggests trying double-encoding). It's a small matrix — sweep it.

### Q40. Can I chain multiple bypasses?
Yes — nest + encode: `..%c0%af....//`, mixed raw+encoded `..%2f..%2f`, or `....//` after a double-decode. When a single technique half-works (gets closer but is blocked), combine it with an encoding that targets a different layer.

### Q41. What if there's a blocklist of filenames (`etc/passwd` denied)?
Encode the target (`%65tc/%70asswd`), or target a **different** sensitive file not on the list (`.env`, `web.config`, source, a log). Blocklists are brittle; there are always other high-value files.

### Q42. How do I confirm a write actually escaped without a shell?
Write a **benign, uniquely-named marker** to a safe, readable path (`/tmp/pt-poc-<rand>.txt`) via the traversal, then read it back from that location. If it's there, the write escaped the base dir — proof without dropping anything dangerous.

### Q43. What's a symlink traversal (CWE-59)?
A tar/zip entry (or an upload) that is a **symlink** pointing to `/etc` or an absolute path; when extracted/followed, reads/writes go through the link outside the intended dir. Refusing symlink entries is part of the Zip-Slip fix.

### Q44. What's the deliverable at the end of Level 2?
An attacker-chosen path that provably reaches a file location outside the base dir — for a read sink, a sensitive file; for a write sink, a safe out-of-dir path you can verify. Now you turn that reach into impact.

---

# LEVEL 3 — EXPLOITATION: READ IMPACT

### Q45. What do I read after confirming with `/etc/passwd`?
App secrets and source: `.env`, `config.php`/`settings.py`/`application.yml`/`appsettings.json`, `wp-config.php`, `~/.aws/credentials`, `~/.ssh/id_rsa`, `/proc/self/environ`, k8s serviceaccount token, DB files, backups (`.bak`/`.old`). Then the app **source** itself.

### Q46. Why read the application source?
Because source reveals hardcoded secrets/signing keys (→ forge JWTs, JWT kit), auth-bypass logic, more sinks, and internal paths. A read-traversal that dumps source is a force-multiplier for the whole engagement.

### Q47. How does a read-traversal become RCE (elsewhere)?
The read gives you **creds**: DB creds → connect → dump/RCE (SQLi kit's file-write/xp_cmdshell); cloud creds (`~/.aws/credentials`, `/proc/self/environ`) → cloud metadata/account takeover (SSRF kit); SSH private key → shell. The traversal reads; the creds execute.

### Q48. What's `/proc/self/environ` good for?
On Linux it holds the process's environment variables — often DB passwords, API keys, cloud creds injected at runtime. A single read can hand you the app's entire secret set. `/proc/self/cmdline`, `/proc/self/cgroup` (container hints) are neighbors.

### Q49. What are the top cloud/container read targets?
`~/.aws/credentials`, `~/.gcp`/service-account JSON, `/var/run/secrets/kubernetes.io/serviceaccount/token` (+ `ca.crt`, `namespace`), `/run/secrets/*` (Docker secrets), env files. These lead straight to cloud/k8s takeover.

### Q50. How is cross-tenant read different from secret read?
Here the traversal reaches **other users'/tenants'** files in a per-user store: `/files/<me>/../<victim>/doc.pdf`. Impact is **mass PII / cross-tenant breach** (High), and reading **session/token files** is **ATO**. Often reported as IDOR-via-traversal.

### Q51. How do I prove cross-tenant read safely?
Use **two of your own** accounts — traverse from account A's path to account B's file and show A's session read B's document. Don't harvest real users' files at scale; the two-own-account proof is enough.

### Q52. When is a read Windows-specific?
`web.config` (connection strings, machine keys → ViewState RCE, Deserialization kit), `appsettings.json`, IIS logs, `unattend.xml`/`sysprep.inf` (creds), and `.aspx` source via `::$DATA`. `machineKey` from `web.config` is a direct RCE pivot.

### Q53. How much of a secret file should I read for the PoC?
Just enough to prove it — a few lines showing the key names and that values exist, with the actual secret **redacted**. You don't need to exfiltrate the whole file or the real value; disclosure of the presence + a redacted snippet proves impact.

### Q54. Read sink but only non-secret files exist at reachable paths?
Keep enumerating paths (the base dir + OS tell you where to look), try `/proc/self/environ` and the app's own config relative to the webroot, and try server-normalization to reach `WEB-INF`/`.git`/backups. If truly only `passwd`-class files are reachable, it's Medium — report honestly.

### Q55. Can a read-traversal expose `.git`?
Yes — `/static../.git/config`, `/static../.git/HEAD`, and dumping `.git/` reconstructs the **entire source history** (secrets in old commits, source, internal logic). A `.git` exposure via traversal is High. Cross-ref the Recon/JSFiles kits.

### Q56. What's the read→ATO path?
Reading **session/token files** (framework session dirs, JWT signing keys, OAuth client secrets) lets you forge/steal sessions → account takeover. Cross-ref the JWT (signing key → forge tokens) and Account-Takeover kits.

---

# LEVEL 4 — EXPLOITATION: WRITE IMPACT (ZIP-SLIP & FRIENDS)

### Q57. Walk Zip-Slip end to end.
The app extracts a user archive and writes each entry to `dest_dir + entry_name` without confining. You craft an archive with an entry named `../../../../var/www/html/shell.php`; on extraction it's written to the webroot; you request it → RCE. Build a benign version first (marker to `/tmp`) to prove the escape.

### Q58. Which archive formats are affected?
zip, tar/tar.gz, jar, war, apk, and anything using a vulnerable extractor: Java `ZipEntry`/`ZipInputStream` (the original Snyk class), Python `zipfile.extractall`/`tarfile.extractall` (CVE-2007-4559), Node `adm-zip`/`tar`, Go `archive/zip`. tar adds **symlink** and **absolute-path** entry variants.

### Q59. How do I build a Zip-Slip PoC safely?
Use `poc/zipslip_build.py` to create an archive with ONE entry named `../../../../tmp/pt-poc-<rand>.txt` containing a benign marker. Upload it, then check `/tmp/pt-poc-<rand>.txt` exists — that proves the write escaped the extraction dir. *Then describe* the webshell escalation; don't drop a live shell on prod.

### Q60. What are the best write targets for RCE?
A served script in the webroot (`.php`/`.jsp`/`.aspx` → request it), `~/.ssh/authorized_keys` (add your key → SSH), a cron/systemd file (scheduled exec), a config the app reloads, or a CI file (`.gitlab-ci.yml`, `Jenkinsfile`) the server builds (RCE on the runner).

### Q61. Why is overwriting often better than dropping a new file?
Because a new file needs an executable/served location *and* the right permissions, while overwriting a file the app **already trusts/serves/executes** (a served `.js`, a config, `authorized_keys`) reuses existing trust. Overwriting `main.js` gives client-side RCE on every user; overwriting `authorized_keys` gives SSH.

### Q62. How does upload-filename traversal work?
If the app keeps your multipart `filename` and you set it to `../../../../var/www/html/x.php`, the file lands in the webroot instead of the upload dir → request it → RCE. Combine with the **FileUpload kit** (which owns content-type/extension/magic-byte bypass to make it executable).

### Q63. What's the split of responsibility with the FileUpload kit?
This kit gets the file **out of the upload directory** (the `../` in the filename/dest). The FileUpload kit gets the file **executable** (bypassing extension/MIME/magic checks). A webshell-via-upload usually needs both.

### Q64. How do save/export/log-path sinks become RCE?
A "save report to <path>"/export/log-naming feature with a traversable path + attacker-controlled **content** lets you write your content to a security-critical location: overwrite `authorized_keys` (your key), a cron file (your command), a served script, or web.config. Content control is the extra requirement here.

### Q65. What if I can traverse the write path but NOT control the content?
Look for targets where *any* content helps: appending to `authorized_keys` (if the write appends), a log file the app later executes/includes, or a file whose mere existence triggers behavior. If content is fully fixed and benign, the write may be lower-impact (DoS via overwrite) — report accordingly.

### Q66. How do I prove write-RCE without wrecking production?
Prove the **escape** with a benign marker to a safe path, and **describe** the webshell/overwrite chain. Only drop an actual working shell or overwrite a real key on **your own test instance**. Never overwrite a real `authorized_keys`/config/served file on production — that's destructive.

### Q67. Can write-traversal cause DoS or tamper without RCE?
Yes — overwriting/corrupting a served asset, config, or data file (or filling a partition) is an availability/integrity impact even without code exec. Lower than RCE but still reportable; frame it honestly.

### Q68. What's the Windows write-RCE target set?
A Startup-folder script, a served `.aspx`, a scheduled-task XML, or `web.config` (a crafted handler → RCE). UNC write paths can also push files to attacker infrastructure.

### Q69. How does a symlink in an archive escalate?
A tar entry that's a symlink to `/etc` (or `/`) makes subsequent writes land wherever the link points — writing outside the dir even if entry-name checks catch literal `../`. This is why the Zip-Slip fix must also refuse symlink and absolute-path entries.

### Q70. Can extraction traversal read files too (not just write)?
Indirectly — a symlink entry pointing at a sensitive file, when the archive is later served/downloaded, can leak it. Mostly write-focused, but the symlink variant blurs read/write.

### Q71. What's the highest-value single write find?
An **"import ZIP"/theme-install** feature on a PHP/JSP app where you can name an entry into the webroot → **webshell → RCE (Critical)** with a single benign-looking upload. That combination (common feature + easy webroot write) is the jackpot.

### Q72. How does write-traversal give persistence (red-team)?
Overwriting/adding `~/.ssh/authorized_keys`, a cron/systemd unit, a `.bashrc`, or a startup script survives reboots and app restarts → durable foothold beyond a transient webshell. That's why save/export write-traversal is a red-team favorite.

### Q73. Can I chain write-traversal with other bugs?
Yes — an upload SSRF/XXE that fetches an archive you control → Zip-Slip on extraction; or read-traversal to learn the exact webroot/base paths, then write-traversal precisely into them. Recon (read) informs the write.

### Q74. What's the deliverable for a write finding?
The exact upload/request + the payload, the benign marker's **out-of-dir landed path** (proof of escape), and the described (or own-instance-proven) RCE/overwrite escalation — plus confirmation you didn't overwrite real files.

---

# TOOLING

### Q75. What does `poc/pt_read_fuzz.py` do?
Sprays the traversal+encoding matrix at a `FUZZ`-marked read/serve param, sends `../` raw, and flags any payload whose response contains your marker string (e.g. `root:x:0:0` for `/etc/passwd`) — **control-baselined** (learns the normal response first) to cut false positives.

### Q76. What does `poc/zipslip_build.py` do?
Builds a **benign** zip (or tar) containing an entry whose name traverses (`../../../../tmp/pt-poc-<rand>.txt`) with harmless marker content — so you can test an extraction sink's confinement without shipping anything dangerous. It refuses to embed executable payloads by design.

### Q77. What does `poc/write_probe.py` do?
Helps test an upload/save path param: submits a benign marker with a traversing filename/dest and gives you the checks to confirm where it landed (out-of-dir vs sandbox). Detection/PoC only — it never drops a shell.

### Q78. What existing tools complement the kit?
`ffuf`/`feroxbuster` (depth/encoding fuzz + `-mr` match), `nuclei -tags lfi,traversal`, Burp Intruder, `curl --path-as-is`, and the sibling kits `LFI/` (include→RCE), `RFI/`, `FileUpload/` (executability), `SSRF/`/`JWT/` (cred pivots).

### Q79. How do I fuzz depth and encoding at scale?
`ffuf -u "https://target/download?file=FUZZ" -w traversal-list.txt -mr "root:"` with a wordlist covering `../`×1–12, encodings, `....//`, and server-normalization. Match on a known marker (`root:` for passwd) to auto-detect hits.

### Q80. Why is a marker-based detector better than status codes?
Because a traversal often returns 200 with the *normal* file on failure and 200 with the *target* file on success — status alone can't tell them apart. Matching a **content marker** unique to the target file (and baselining the normal response) gives low false positives.

---

# BLACK-BOX METHODOLOGY & CHECKLIST

### Q81. Give the 5-phase method in one paragraph.
**Recon** every path sink (download/serve, static, archive-extract, upload/save) → **baseline + classify** read/write/include → **reach/bypass** (escape dir, encoding, prefix/suffix/allowlist, server-normalization) → **exploit** (read→secrets/cross-user; write→Zip-Slip/upload/save→RCE) → **validate & report** impact-first with benign markers.

### Q82. What's the one FP that gets reports closed?
Reporting a **same-dir path change** as traversal, or **`/etc/passwd` as Critical**. Escape the directory and reach something that matters (secrets/cross-user/out-of-dir write); rate passwd-class reads as Medium.

### Q83. How do I avoid mislabeling LFI as path traversal (and vice versa)?
Ask "does the sink **execute** the file?" If yes → LFI/RFI (RCE via wrappers/log-poison), report there. If it only reads/serves/writes bytes → this kit. The direction and execution decide the class and the ceiling.

### Q84. How do I set severity honestly?
Write→RCE (Zip-Slip/upload/save) → Critical; read→secrets/source→creds→RCE-elsewhere → High–Critical; read→cross-tenant PII/tokens → High; server-normalization→WEB-INF/.git/backups → High; passwd-class read → Medium; no escape → Info. Anchor CWE-22 + the variant.

### Q85. What must be in the PoC before I submit?
The exact request/upload + payload (raw `../`), and either the sensitive bytes read (redacted) or the benign marker's out-of-dir landed path — plus the pivot/escalation described, and confirmation you didn't overwrite real files or mass-exfiltrate.

---

# CHEAT SHEETS

### Q86. Fastest read shortlist?
```
../../../../../../etc/passwd            (confirm)
/etc/passwd                             (absolute; Python/.NET/Java)
....//....//....//etc/passwd            (strip-reform)
..%2f..%2f..%2fetc%2fpasswd             (encoded)
%252e%252e%252fetc%252fpasswd           (double-encoded)
/static../../../../etc/passwd           (nginx alias)
/app/..;/..;/WEB-INF/web.xml            (Tomcat)
# then climb to: .env, config, ~/.aws/credentials, id_rsa, /proc/self/environ, source
```

### Q87. Fastest write shortlist?
```
zip entry:  ../../../../var/www/html/x.php   (Zip-Slip → webshell)
zip entry:  ../../../../home/<u>/.ssh/authorized_keys   (overwrite → SSH)
filename="../../../../var/www/html/x.php"     (upload-path)
?savepath=../../../var/www/html/x.php         (save/export)
# prove ESCAPE with a benign marker to /tmp first; never overwrite real files on prod.
```

### Q88. Direction-to-severity map?
```
write → RCE (zip-slip/upload/save)     → Critical
read → secrets/source → creds → RCE    → High–Critical
read → cross-tenant PII / tokens       → High
server-normalization → WEB-INF/.git    → High
read → /etc/passwd (non-secret)        → Medium
no escape / same-dir                   → Info
```

### Q89. CWE map?
```
path traversal (anchor)     → CWE-22
absolute path               → CWE-36
relative / ../  / ..\       → CWE-23 / 24 / 25
symlink following           → CWE-59
external control of path     → CWE-73
write via upload            → CWE-434
```

### Q90. Decision-in-one-line?
Executes the file? → LFI kit. Reads? → escape dir → secrets/cross-user (not passwd). Writes? → escape dir → webshell/overwrite keys → RCE. Send `../` raw; benign markers; never overwrite real files.

---

# REAL-WORLD PATTERNS & REFERENCES

### Q91. What are the classic real-world traversal patterns?
A `download?file=` with no confinement reading `.env`; nginx `alias` off-by-slash exposing `WEB-INF`/`.git`; a theme/plugin/backup **import ZIP** with Zip-Slip → webshell; an upload keeping the client filename → webroot write; Python/.NET `os.path.join`/`Path.Combine` absolute-path reads; Tomcat `..;/` → `web.xml` creds.

### Q92. Which references should I read?
PortSwigger *Directory traversal* labs, OWASP *Path Traversal*, Snyk's *Zip Slip* research (the archive-write class), the Python `tarfile` CVE-2007-4559 write-ups, and disclosed HackerOne reports for "arbitrary file read/write" and "zip slip".

### Q93. Best disclosed-report search terms?
`path traversal`, `arbitrary file read`, `arbitrary file write`, `zip slip`, `nginx alias traversal`, `..;/ WEB-INF`, `directory traversal to RCE`, `upload filename path traversal`.

### Q94. What's the most under-tested surface?
The **WRITE** side — Zip-Slip in import/restore/theme features, and upload-filename traversal. Hunters over-focus on `?file=` reads and miss that the "import ZIP" button is a straight path to RCE.

---

# DEFENSE — SAFE PATH HANDLING

### Q95. What's the single best fix?
**Indirection**: never pass client input to the filesystem. Map a client **key/ID → a server-side known path** (a lookup table). If the user only sends an opaque ID, there's no path to traverse.

### Q96. If I must accept a name, how do I validate it?
**Canonicalize then confine**: resolve the full path (`realpath`/`getCanonicalPath`/`Path.GetFullPath`/`path.resolve`), then verify the result **still starts with the intended base dir** — reject otherwise. Validate *after* decoding, and reject `../`, absolute paths, NUL, and encoded variants. Don't rely on stripping `../` (it's bypassable).

### Q97. How do I fix Zip-Slip specifically?
For every archive entry, compute the **resolved** output path and confirm it's inside the target dir **before** writing; reject entries with `../`, absolute paths, or that resolve outside; refuse **symlink** entries. Modern libraries added this — update them.

### Q98. How do I fix upload/write sinks?
Generate **server-side filenames** (don't trust the client filename); write to a dedicated dir with a confined, canonicalized path; store uploads **outside the webroot** and serve via a handler (so even a webroot write can't execute); run the writer **least-privilege** (can't write the webroot/keys/cron).

### Q99. How do I fix server-normalization traversals?
Match nginx `location`/`alias` trailing slashes (or use `root` instead of `alias`); disable/normalize `..;/` (Tomcat `ALLOW_ENCODED_SLASH`/security constraints); ensure the proxy and origin decode consistently; block encoded traversal at the edge *and* the origin.

### Q100. What's the residual risk after fixing one sink?
Other path sinks (traversal is app-wide), server config regressions, new import/upload features re-introducing Zip-Slip, and third-party libraries with their own extraction bugs. Safe path handling is a **pattern to enforce everywhere** (indirection + canonicalize-then-confine) and to re-audit as features are added — plus least-privilege so a traversal that slips through can't read secrets or write the webroot.

---

> **The one rule that pays:** traversal is only a finding when you **escape the intended directory and reach something
> that matters** — reading your target's secrets/source/other-users' files (High–Critical pivots), or **writing a file
> outside the base dir** (Zip-Slip / upload-path / save) to drop a webshell or overwrite `authorized_keys`/cron
> (Critical RCE/persistence). Send `../` raw, beat the filter with `....//`/encoding/server-normalization, prove it with
> **benign markers** (never overwrite real files), and if the sink *executes* the file — that's the **LFI kit**.
