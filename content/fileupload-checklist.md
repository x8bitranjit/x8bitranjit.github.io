# File Upload Testing Checklist — Per-Upload-Point, In Testing Order

> Tick per upload feature. Mirrors the Master Testing Sequence in `FILE_UPLOAD_TESTING_GUIDE.md`. The point: **baseline first** (it decides severity), **bypass controls in order**, **climb to the highest impact**, prove with a **benign marker**. `§` = section in the main guide.

**Target:** ____________  **Upload feature:** ____________  **Endpoint:** ____________  **Date:** ________
**Stack/handler (httpx/Wappalyzer):** ________  **Serving host:** app-origin / subdomain / sandbox-CDN

---

## PHASE 0 — Recon & Lab (§1/§3)
*Why this matters:* most hunters test the avatar and stop — the high-paying uploads are the boring server-*processed* ones (imports, KYC docs, "import from URL"). Cast wide here, and stand up your OOB listener now, because the best bugs (XXE/SSRF) are blind and you'll only see them via a callback.
- [ ] Found **every** upload point: avatar/attachment + **imports (CSV/XML/Office)** + **"import from URL"** + KYC/docs + admin theme/plugin/template + API/presigned/GraphQL.
- [ ] Burp ready (tamper multipart); **OOB listener live** (interactsh/Collaborator) for XXE/SSRF.
- [ ] 2 test accounts (for overwrite/IDOR cross-user proof).

## PHASE 1 — Baseline ★ (§4) — DECIDES SEVERITY, DO FIRST
*Why this matters:* this phase, not your payload, sets the ceiling. Following one honest file through the system — where it's stored, what URL serves it, which handler opens it — tells you whether RCE is even possible before you spend a day fuzzing. Skip it and you'll fire shells at a sandboxed CDN that could never run them.
- [ ] Uploaded a valid file; recorded **WHERE stored** (path, guessable?, user-scoped?).
- [ ] Fetched it back: **WHAT URL serves it** (app origin? subdomain? sandbox CDN?).
- [ ] Recorded **HOW served**: `Content-Type`, `Content-Disposition` (inline/attachment), `X-Content-Type-Options: nosniff`.
- [ ] Mapped controls by probing: client-only? extension allow/deny? MIME check? magic check? **re-encoded?** filename sanitized? size limit?
- [ ] Decided the severity ceiling (web-root+handler→RCE / app-origin inline→XSS / parsed→XXE/SSRF / sandboxed→low).

## PHASE 2 — Control Bypass (§5–§11)
*Why this matters:* the file passes a *line* of independent inspectors that don't coordinate well. Don't spray random payloads — identify which inspectors exist (from Phase 1) and defeat the specific weakest one. The classify-then-bypass order here is what turns a "properly validated" upload into a reachable payload.
- [ ] **Client-side** only? → tamper request / call endpoint directly (§5).
- [ ] **MIME**: classify the validation model (header-trust / ext-map / magic / image-decode / framework — §6.1), then bypass it:
      - [ ] header lie (`Content-Type: image/png` + payload); full MIME matrix incl. docs/archives/text/octet-stream (§6.3, arsenal §N).
      - [ ] structural/parser-confusion: **missing** CT, **duplicate** CT, **multiple file parts**, `file[]` array, base64 CTE, RFC-2231 `filename*=` (§6.4, arsenal §O).
      - [ ] mismatched **triple** (CT vs extension vs magic) → find which tier trusts which (§6).
- [ ] **Extension**: denylist tricks (.phtml/.pht/.phar, double-ext, case, trailing dot/space/null, `;.jpg`, `::$DATA`) (§7).
- [ ] **Magic/polyglot**: prepend `GIF89a`/`%PNG`; EXIF-comment payload; image+code polyglot (§8).
- [ ] **Filename/traversal**: `../`, `....//`, `%2f`, absolute path, Windows path; filename→XSS (§9).
- [ ] **Config-file upload (§10)**: `.htaccess` / `web.config` / **`.user.ini`** (auto_prepend_file) to force execution; **nginx `fix_pathinfo`** path trick (`avatar.jpg/x.php`).
- [ ] **Re-encoding**: payload in EXIF survives? else attack the processor (§11→§16).
- [ ] ✅ Produced a file that **survives controls and lands reachable**.

## PHASE 3 — IMPACT ⭐ (§12–§20) — climb to the highest
*Why this matters:* "it accepted my file" pays nothing — the report is what you *reach* through the door. Always climb to the highest impact the context allows (RCE > XXE/SSRF > stored XSS > overwrite > DoS) and demonstrate it end-to-end with a benign marker. A re-encoding target isn't a dead end: the processor itself (ImageMagick/Ghostscript/exiftool) is often a bigger bug than a plain web shell.
- [ ] **RCE web shell**: marker file in web-root+handler → request → `RCE-POC-<hash>-<host>` (§12).
- [ ] **Race (TOCTOU) (§12.3)**: server saves-then-validates/deletes? → hammer GET to the URL during the window → RCE before deletion.
- [ ] **Stored XSS**: SVG/HTML served **inline from app origin** → `alert(document.domain)` (§13).
- [ ] **XXE**: SVG/Office/XML parsed → file read (`/etc/passwd`) or OOB exfil (§14).
- [ ] **SSRF**: "import from URL" → `169.254.169.254` metadata / internal / OOB (§15).
- [ ] **Processor RCE**: ImageMagick(CVE-2016-3714/2022-44268) / exiftool(CVE-2021-22204) / Ghostscript / ffmpeg via OOB (§16).
- [ ] **Zip Slip** + **symlink** archives: entry `../../web-root/poc.php` → RCE; symlink entry → read/overwrite host files (§17).
- [ ] **Overwrite/IDOR**: overwrite **another user's** file / shared asset / trusted config (§18).
- [ ] **Pre-signed URL / cloud (§18.1)**: control **key** / **Content-Type** / **ACL** → overwrite served asset → stored XSS / supply-chain.
- [ ] **DoS** (only if in scope): pixel-flood / zip-bomb ratio, demonstrated safely (§19).
- [ ] **CSV injection**: imported data exported & opened by staff (§20).
- [ ] Stated impact in one sentence: *"My uploaded file causes <RCE/XXE/SSRF/XSS/overwrite> affecting <who>."*

## PHASE 4 — Validate → Severity → Report (§22–§27)
*Why this matters:* file upload has the widest false-positive surface of any class — "accepted a .php", "SVG-XSS on a sandbox CDN", "stored but served as text" all get auto-closed. The gate that separates a paid Critical from a closed report is proving the file *executes/parses/serves dangerously*, naming the serving context, and anchoring to the outcome's CWE (not just 434).
- [ ] Passed **false-positive filter** (§23): NOT "it accepted my file", NOT SVG-XSS-on-sandbox-CDN, NOT stored-but-not-executed, NOT self-only overwrite.
- [ ] Confirmed **execution/parse/serve** (not just acceptance); confirmed **serving context** for XSS/RCE.
- [ ] Set **CVSS 3.1** + outcome **CWE** (434/611/918/22/79) (§24).
- [ ] Built **SAFE marker PoC**; used own accounts; **deleted uploaded artifacts** (§26).
- [ ] Captured: crafted file + upload request + the request/response proving impact + screenshot.
- [ ] **De-duplicated**; title names the **impact** (§27).

---

## Quick "is it worth reporting?" gate
```
Does the file EXECUTE / get PARSED / serve where it RUNS?     NO → "accepted" only = not a bug (§23). Stop or dig.
For XSS: served INLINE from the APP ORIGIN?                    NO → sandbox CDN = low ceiling; don't inflate (§23).
For RCE: stored in web-root with a matching HANDLER?           NO → not RCE; pivot to parser/XXE/XSS.
Did I climb to the HIGHEST impact the context allows?         NO → check parser(§16)/URL-fetch(§15)/overwrite(§18).
Proven with a BENIGN marker / OOB (not a backdoor)?           NO → fix the PoC before submitting (§26).
```

## Per-upload mini-loop
```
baseline (stored/url/handler) → map controls → bypass in order → reach a serving/parse context
   → prove highest impact with a benign marker/OOB → delete artifacts → record finding
```
