# XXE Testing Checklist — per XML sink

> Authorized testing only. Read a **benign** file first, bound reads, no DoS on prod, delete uploads, tear down OOB.
> Payloads: `XXE_ARSENAL.md`. Depth: `XXE_TESTING_GUIDE.md`.

## PHASE 0 — Find the sinks (§1)
- [ ] Raw XML / SOAP bodies (`Content-Type: application/xml`, `text/xml`, `application/soap+xml`).
- [ ] REST/JSON endpoints re-tested with an XML content-type (content-type switch, §12).
- [ ] File uploads that are XML-backed: **SVG**, **DOCX/XLSX/PPTX**, ODT, PDF, RSS/Atom, GPX/KML, plist, SAML metadata.
- [ ] XML features: sitemap/RSS import, XML-RPC (`/xmlrpc.php`), SAML/SSO, SVG→PNG/thumbnail, report/invoice generators.
- [ ] Grepped source/JS for XML parser calls + DOCTYPE handling.

## PHASE 1 — Detect (safe, before real payloads) (§2)
- [ ] Confirmed XML is **parsed** (malformed XML → parse error vs normal).
- [ ] **Internal entity** test (`<!ENTITY test "marker">`) — reflected? → in-band. Not reflected but parsed? → blind. DOCTYPE error? → XInclude/hardened.
- [ ] Classified observability: **in-band / blind-OOB / error-based / fully-blind**.

## PHASE 2 — In-band file read (§3, §13.1)
- [ ] `file:///etc/hostname` (benign) reflected → confirmed read.
- [ ] Escalated to sensitive: `/etc/passwd`, `.env`/`web.config`/config, source via **`php://filter` base64**.
- [ ] Windows equivalents if applicable (`win.ini`, `web.config`).

## PHASE 3 — SSRF (§4, §13.2)
- [ ] `http://` entity fetched an internal/attacker URL.
- [ ] Cloud metadata attempted (`169.254.169.254` / `metadata.google.internal`) → **IAM creds** = Critical (prove, then stop → `../SSRF/`).
- [ ] Internal service / port reachability noted.

## PHASE 4 — Blind → OOB (§8)
- [ ] Parameter-entity + **external `evil.dtd`** submitted; OOB **HTTP** callback received (Collaborator/Interactsh/`poc/oob_server.py`).
- [ ] File exfiltrated via `?x=%file;` (benign file first); `php://filter` base64 for multi-line/source.
- [ ] If HTTP egress blocked: **FTP-OOB** (Java) or **DNS-only** confirm tried.

## PHASE 5 — Error-based & local DTD (§9, §13.3)
- [ ] No outbound but errors verbose → error-based file-into-error-message.
- [ ] **Local DTD reuse** (on-box DTD + overridden param entity) when no attacker server reachable.

## PHASE 6 — XInclude, uploads, content-type (§10–§12)
- [ ] **XInclude** tried where DOCTYPE can't be added (sub-node injection).
- [ ] **SVG** upload (view rendered/converted output) — in-band + blind-OOB.
- [ ] **OOXML** (DOCX/XLSX/PPTX) built (`poc/make_ooxml_xxe.py`) and uploaded to resume/import/preview.
- [ ] **Content-type switch** on a JSON API.

## PHASE 7 — Escalate & bypass (§13–§15)
- [ ] Source + secrets read (→ DB creds/keys → chain further).
- [ ] SSRF→metadata→creds where cloud-hosted.
- [ ] RCE paths considered (`expect://`, `jar:`, upload chain) — benign proof only.
- [ ] Filters bypassed as needed: XInclude / content-type / **UTF-16** / `PUBLIC` / protocol-swap / error+local-DTD.

## PHASE 8 — Validate & report (§16–§19)
- [ ] Passed the **FP auto-reject** table (real file contents or creds — not just a reflected internal entity).
- [ ] Severity set (CVSS + **CWE-611**); impact stated in business terms.
- [ ] SAFE-PoC honored: benign file first, minimum reads, no prod DoS, uploads deleted, OOB listener torn down.

## AUTO-REJECT (not a finding by itself)
- [ ] Internal entity (`&test;`) reflected — proves parsing, **not** external fetch.
- [ ] Parse error on `<!DOCTYPE` with no confirmed fetch/OOB.
- [ ] "It fetched my URL" (SSRF-only) with no metadata/creds/file demonstrated.
- [ ] Blind **DNS-only** hit with no file read (report as blind, but escalate for High).
- [ ] Billion-laughs "crash" on a scratch box (DoS, usually out of scope — never fire on prod).
