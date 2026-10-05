# poc_files — Benign Attack PoCs — organized by attack class

Companion to **x8bittest.github.io** and the checklists in the parent folder. Every file is **benign by default** and built for **authorized** security testing only: payloads are self-referential markers (`alert()`, `id`, echo of the machine name) or point at non-resolvable placeholders — no exfiltration, no third-party targets, nothing fires until *you* edit it.

**Safe PoC** -> x8bitranjit — every file in this folder is a benign, inert-as-shipped proof of concept.

---

## WHY AM I NOT SEEING A POPUP? (read this first)

Most files here are **not "open and it pops" payloads** — they are attack *inputs* that fire only inside a vulnerable context. Opening them locally is SUPPOSED to be uneventful:

| You opened | What you see | Why |
|---|---|---|
| any PNG/JPG/GIF in `10_image_attacks/` | the image itself (a banner card) | image files never execute anything by being viewed — that is a browser/viewer guarantee, not a bug. Each carries a hidden payload (metadata chunk, COM segment, XXE entity, PHP) that fires only in the **vulnerable context described below** |
| `pdf_uri_action_poc.pdf` in Chrome/Edge/Firefox | a text page | built-in browser viewers ignore PDF actions; **Adobe Acrobat** prompts/runs them |
| `06_document_client/svg_xss_open_on_view.svg` | **an alert DOES fire** | this is the one image that pops — scripts run when an SVG is opened *directly* in a browser |
| `06_document_client/pdf_html_polyglot_poc.html` | **an alert DOES fire** | its HTML side executes in a browser |
| `*.http`, `*.txt` batteries | text | they are request/payload sets you send through a target |

**To actually see each attack work, follow the trigger steps in the `10_image_attacks/` and `06_document_client/` tables below — every row tells you the exact vulnerable context and how to demo it.**

---

## Folder structure

```
poc_files/
├── README.md                        ← this guide
├── 01_upload/                       ← upload-function testing (red-team order)
│   ├── upload_polyglot_gif_php.gif      valid GIF, PHP in comment extension
│   ├── upload_png_php_polyglot.png      CRC-correct PNG, PHP in tEXt chunk
│   ├── upload_jpeg_trailing_php.jpg     valid JPEG, PHP after EOI marker
│   ├── upload_htaccess_poc.htaccess     Apache: images -> PHP execution
│   ├── upload_user_ini_poc.ini          PHP-FPM: auto_prepend_file hijack
│   ├── upload_web_config_poc.config     IIS/ASP.NET: buildProvider execution
│   ├── upload_shell_poc.poc             benign marker page for web.config
│   ├── upload_wgetrc_poc.wgetrc         wget config-file injection (header proof)
│   ├── upload_curlrc_poc.curlrc         curl config-file injection (header proof)
│   ├── upload_package_json_poc.json     npm preinstall hook (benign echo)
│   ├── upload_composer_json_poc.json    composer post-install hook (benign echo)
│   ├── upload_phar_stub_poc.php         phar stub template (build via PHPGGC)
│   ├── upload_zip_slip_poc.zip          traversal entries (../ forms)
│   └── upload_tar_symlink_poc.tar       symlink -> /etc/passwd + traversal
├── 02_ssrf/                         ← SSRF / blind-XXE / metadata
│   ├── ssrf_oob_probe_urls.txt          full URL battery (OOB+cloud+internal+obfuscation)
│   ├── ssrf_imds2_gopher_poc.txt        AWS IMDSv2 bypass via gopher PUT
│   ├── svg_ssrf_beacon.svg              SSRF via server-side SVG rasterizers
│   ├── ffmpeg_lfi_ssrf_poc.m3u8         FFmpeg/HLS file-read + internal fetch
│   ├── xxe_oob_beacon.xml               blind XXE two-hop exfil (needs the .dtd)
│   └── xxe_oob_beacon.dtd               its external DTD (edit both files)
├── 03_rce_linux/                    ← Linux-specific command execution
│   ├── cmdi_linux_poc.http              10-request battery (.http format)
│   ├── shellshock_linux_poc.http        CVE-2014-6271 via headers on CGI
│   ├── linux_wildcard_tar_poc.txt       filename-as-argument (tar --checkpoint)
│   ├── linux_git_hooks_poc.txt          repo-upload -> post-checkout hook exec
│   └── linux_authorized_keys_poc.txt    traversal-write -> restricted SSH key
├── 04_rce_windows/                  ← Windows-specific command execution
│   ├── cmdi_windows_poc.http            cmd.exe battery + DOSfuscation
│   ├── windows_wmic_xsl_rce_poc.http    WMIC /format: remote-XSL execution
│   ├── windows_wmic_format_poc.xsl      its benign XSL (echo marker)
│   ├── windows_scf_ntlm_leak_poc.scf    Explorer NTLMv2 leak on folder view
│   └── windows_startup_folder_poc.txt   arbitrary-write -> startup cash-out
├── 05_shells/                       ← shells (AUTHORIZED ENGAGEMENTS ONLY)
│   └── revshells_linux_windows.txt      Linux + Windows one-liners & staging
├── 06_document_client/              ← document & client-side attacks
│   ├── pdf_uri_action_poc.pdf           PDF /URI OpenAction (on-open nav)
│   ├── pdf_html_polyglot_poc.html       valid PDF + valid HTML polyglot
│   ├── svg_xss_open_on_view.svg         SVG XSS on direct open
│   ├── xml_xxe_poc.xml                  benign XXE detection (needs the .dtd)
│   ├── xml_xxe_poc.dtd                  its external DTD (plain-text entity)
│   ├── csv_formula_injection_poc.csv    formula execution in data cells
│   ├── hta_on_view_poc.hta              HTA = local app on open
│   ├── html_dangling_markup_poc.html    unclosed-attribute page-tail leak
│   ├── template_ssti_poc.j2             SSTI differential probes per engine
│   ├── linux_desktop_entry_poc.desktop  .desktop launcher execution on open
│   └── docx_metadata_payload_poc.docx   inert XSS + SSTI in dc:title
├── 07_sandbox_bypass/               ← application sandbox escapes
│   ├── sandbox_node_vm_escape.js        node vm / vm2 escape payloads (inert)
│   ├── sandbox_python_eval_escape.py    Python restricted-eval escapes (inert)
│   ├── sandbox_jinja2_sandbox_escape.j2 Jinja2 SandboxedEnvironment walk
│   ├── sandbox_nashorn_java_escape.js   Java ScriptEngine/Nashorn + Groovy
│   ├── sandbox_browser_iframe_matrix.html  iframe sandbox capability self-check
│   ├── sandbox_php_disable_functions_bypass.txt  disable_functions/open_basedir ladder
│   └── sandbox_pdf_pdfjs_matrix.txt     PDF/reader sandbox honesty matrix
├── 08_modern_bypass/                ← modern server & application defenses
│   ├── evasion_waf_json_dup_keys.http   JSON duplicate-key parser differential
│   ├── evasion_waf_content_encoding.http gzip body bypass (real embedded gzip)
│   ├── evasion_waf_unicode_normalization.http  fullwidth/homoglyph/overlong battery
│   ├── evasion_h2_continuation_flood.txt        HTTP/2 CONTINUATION header-split
│   ├── evasion_csp_vectors.txt          15 CSP bypass vectors
│   ├── evasion_dompurify_mxss.html      mXSS/sanitizer bypass showcase (inert)
│   └── evasion_jndi_obfuscation.txt     JNDI nested-lookup obfuscation battery
├── 09_webshells_benign/             ← benign marker shells per stack
│   ├── webshell_benign.php              echo marker + php_uname (no command input)
│   ├── webshell_benign.aspx             echo marker + OS version (no commands)
│   └── webshell_benign.jsp              echo marker + server info (no commands)
├── 10_image_attacks/                ← PNG/JPG-carried attacks (XSS/RCE/XXE/DoS)
│   ├── png_imagemagick_read_poc.png     CVE-2022-44268: file read via convert
│   ├── png_xmp_xxe_poc.png              XMP metadata XXE (inert placeholder)
│   ├── png_metadata_xss_poc.png         tEXt metadata XSS (gallery/DMS render)
│   ├── png_html_polyglot_poc.png        valid PNG + script (serving-layer XSS)
│   ├── png_dimension_bomb_poc.png       99999x99999 in <1KB (scope-gated DoS)
│   ├── jpg_com_xss_poc.jpg              COM segment metadata XSS
│   ├── jpg_com_php_poc.jpg              PHP hidden in COM segment
│   ├── jpg_exif_beacon_poc.jpg          EXIF ImageDescription beacon (inert)
│   ├── gif_comment_xss_poc.gif          GIF comment extension XSS
│   └── image_filename_xss_poc.txt       filename-as-payload battery
├── 11_bounty_pages/                 ← attacker-hosted HTML pages (the deliverables)
│   ├── cors_exfil_poc.html             credentialed read -> beacon (CORS rows)
│   ├── csrf_autosubmit_poc.html        auto-submitting PoC form
│   ├── cswsh_poc.html                  cross-site WebSocket hijacking page
│   ├── xsleaks_timing_poc.html         timing-oracle harness (medians+separation)
│   └── oauth_callback_poc.html         redirect_uri collector (code/token capture)
└── 12_api_attacks/                  ← API-layer attack batteries
    ├── graphql_batch_bypass.http        alias/array batching + BOLA + mass-assign
    ├── jwt_tamper_battery.txt           jwt_tool command matrix
    ├── lfi_php_wrappers_poc.http        php://filter chain -> data:// -> pearcmd
    ├── host_header_poison_poc.http      reset poisoning / cache / routing SSRF
    ├── sqlmap_request_template.txt      clean single request (sqlmap -r / ghauri)
    └── README_KEEP                      folder note
└── 13_windows_defender/             ← authorized-engagement security-stack pack
    ├── README.md                        scope + what is deliberately NOT here
    ├── defender_surface_map.txt         7 protection layers + MITRE mapping
    ├── benign_inventory_probes.txt      Defender's own cmdlets (non-evasive recon)
    ├── asr_exclusions_audit.txt         overbroad exclusions/ASR = reportable findings
    ├── execution_tradecraft_taxonomy.txt technique CLASSES + research pointers
    ├── detection_mapping.txt            blue-team mirror per technique class
    └── engagement_rules.txt             when AV testing is in scope + ledger rules
```

---

## 1. The placeholder convention (read this first)

Every file that could touch the network ships with a placeholder that **cannot resolve**:

```
YOUR-OOB-HOST.example.invalid
ATTACKER.example.invalid
```

`.invalid` is a reserved TLD that never resolves — so every file is **inert exactly as shipped**. To arm a file, replace the placeholder with **your** listener:

| You use | Replace with |
|---|---|
| Burp Collaborator | `<your-id>.oast.pro` |
| interactsh | `<your-id>.oast.fun` |
| Your own VPS | `<your-ip>` or `<your-domain>` |

**Listener first, then edit, then fire** — a callback from the target's server IP is the proof. Correlation rule: one unique subdomain per parameter/field (`param1.yourid.oast.fun`) so every hit maps to the exact input that produced it.

## 2. Quickstart (any file, 3 steps)

1. **Stand up your listener** (`interactsh-client` / Burp Collaborator / `nc -lvnp 4444`).
2. **Edit the placeholder** in the file you picked (see the folder tables below — "What to edit").
3. **Deliver through the target's feature** (upload it / paste the URL / send the request), then **confirm** with the matching signal (OOB callback / marker in response / timing) and **clean up** planted files (ledger every artifact).

> Full per-file-type editing walkthrough: section **3. HOW TO EDIT** below.

---

## 3. HOW TO EDIT — step by step, per file type

### Step 0 — stand up your listener (do this before ANY edit)
1. Pick your listener: `interactsh-client` (free) / Burp Collaborator / your VPS.
2. Note your hostname, e.g. `a1b2c3d4.oast.fun`.
3. Everything below replaces `YOUR-OOB-HOST.example.invalid` / `ATTACKER.example.invalid` with it.

### Step 1 — global placeholder replacement (text files)
1. Open the file in any editor (VS Code recommended — it shows all matches).
2. Ctrl+H (find & replace), enable case-sensitive.
3. Find: `YOUR-OOB-HOST.example.invalid` → Replace: your listener hostname → Replace All.
4. Find: `ATTACKER.example.invalid` → Replace: `your-ip:port` form if the file wants host+port (revshells) → Replace All.
5. Also replace `target.com` / `https://target.example.invalid` with your authorized target.
6. Save. Then verify: search the file for `example.invalid` — **zero matches = ready** (except this README).

### Step 2 — the binary files (placeholders live INSIDE image chunks)
Two image files carry an editable placeholder inside their binary structure:
`10_image_attacks/png_xmp_xxe_poc.png` (XMP entity) and `10_image_attacks/jpg_exif_beacon_poc.jpg` (EXIF beacon).
Because PNG/JPEG chunk length fields are byte-counted, **your replacement must be EXACTLY the same length (29 chars)**:

1. Build a same-length hostname: the placeholder is exactly **29 chars** (`YOUR-OOB-HOST.example.invalid`).
   Worked example: your listener is `a1b2c3d4.oast.fun` (17 chars) → label must be 29 - 17 - 1 (the dot) = **11 chars**.
   Per-input labels: `xmp1beef123` (11) → `xmp1beef123.a1b2c3d4.oast.fun` = exactly 29. Count yours with:
   `python -c "print(len('YOUR-LABEL.a1b2c3d4.oast.fun'))"` → must print 29.
2. Open the file in a hex editor (HxD is free).
3. Ctrl+F → data type: *ASCII string* → search `YOUR-OOB-HOST`.
4. Select exactly the 29 placeholder characters → paste your 29-char hostname (Overwrite mode!).
5. Save. Do NOT add/remove bytes — chunk CRCs cover content but length mismatch corrupts the file.
6. Verify: `python -c "import zlib,struct;..."` or just re-run `_upgrade_tools/audit_poc.py` — CRC walk must pass.
   Alternative (easier): regenerate the file with your listener baked in — the generator scripts in `_upgrade_tools/make_poc_files4.py` take the placeholder constant.

All other images/GIFs/PDFs ship **zero-edit** (benign payloads already baked in).

### Step 3 — `.http` batteries (03/04/08/12 folders)
1. Open in VS Code with the "REST Client" extension (or paste a single request into Burp Repeater).
2. Replace every `target.com` with your authorized target (one per line, `Host:` header AND the URL line).
3. Replace the `YOUR-OOB-HOST.example.invalid` in the OOB rows.
4. For multi-step files: send requests **top-to-bottom** — each is numbered and the first that "fires" decides the next step (comments in the file guide you).
5. `12_api_attacks/sqlmap_request_template.txt` is a single clean request: edit target/param, then run `sqlmap -r sqlmap_request_template.txt --batch --level=3`.

### Step 4 — HTML bounty pages (`11_bounty_pages/`)
1. Open the page — every editable line is marked with an `// EDIT:` comment.
2. Replace `target.example.invalid` (the vulnerable endpoint) and `attacker.example.invalid` (your collector).
3. Host the page on YOUR origin (github.io / VPS / Burp Collaborator "copy a page").
4. Send to your own logged-in test account first (two-account discipline), confirm the callback, then involve the intended context per the kit row.

### Step 5 — XXE pairs (edit BOTH files consistently)
1. `02_ssrf/xxe_oob_beacon.xml` + `xxe_oob_beacon.dtd` — the XML fetches the DTD; the DTD beacons back.
2. Replace the placeholder in **both** files (2 occurrences each) with your listener.
3. Serve the `.dtd` from the SAME listener host the XML points at (interactsh serves DNS/HTTP but not arbitrary files — host the DTD on your VPS or use Burp Collaborator's HTTP + a manual server).
4. Deliver the XML through the target's XML importer → two-stage callback: DTD fetch, then the content beacon.

### Step 6 — config uploads (`01_upload/`)
1. `upload_user_ini_poc.ini` — set `auto_prepend_file` to the EXACT stored filename of your uploaded polyglot (check the target's response for the stored name).
2. `upload_htaccess_poc.htaccess` / `upload_web_config_poc.config` — no edits needed; the payload is the sibling polyglot/`.poc` file. Upload config FIRST, then the marker file, then fetch it.
3. `upload_wgetrc_poc.wgetrc` / `upload_curlrc_poc.curlrc` — edit the marker header value if you want per-engagement attribution.
4. `upload_package_json_poc.json` / `upload_composer_json_poc.json` — replace the `echo` with your OOB beacon on authorized targets.

### Step 7 — docx metadata payload
Three ways to edit `06_document_client/docx_metadata_payload_poc.docx`:
- Word: open → File → Info → Title → edit → save (payload goes in Title).
- 7-Zip: open archive → edit `docProps/core.xml` → drag back in.
- One-liner:
  `python -c "import zipfile;z=zipfile.ZipFile('docx_metadata_payload_poc.docx','a');z.writestr('docProps/core.xml', open('core.xml').read())"` (replace mode needs a rebuild — simplest is the two GUI routes).

### Step 8 — pre-fire verification checklist (every file, every time)
- [ ] `example.invalid` appears ZERO times in the file you are about to fire.
- [ ] Listener is running and reachable from the target's network position.
- [ ] Target is in your authorized scope; the technique matches the engagement type (bounty ≠ endpoint/AV work).
- [ ] You know the cleanup step for anything you plant (ledger it — PEXP-015).

### Step 9 — after firing
1. Correlate: the unique subdomain you embedded maps the callback to the exact input/parameter.
2. Capture evidence: callback source IP (which tier fired), marker output, timing.
3. Clean up: delete planted files, revert state, record everything in the ledger.


---

## 4. Usage per folder — which, where, what to edit, how

### `01_upload/` — upload-function testing (fire in this order per endpoint)

Each artifact defeats a different defense layer; run them as a sequence:

| Order | File | Defeats | Where to use | What to edit | How to confirm |
|---|---|---|---|---|---|
| 1 | `upload_polyglot_gif_php.gif` | magic-byte validators — **valid GIF** with PHP in a GIF comment extension | image/avatar upload on PHP stacks; upload as `shell.jpg`/`.gif` | nothing (benign marker only) | fetch via a PHP handler (rows 4/5) → marker `Safe PoC -> x8bitranjit | UPL-benign-marker: <uname>` prints |
| 2 | `upload_png_php_polyglot.png` | PNG validation — CRC-correct PNG, PHP inside a `tEXt` chunk | PNG-only upload points | nothing | same as row 1 |
| 3 | `upload_jpeg_trailing_php.jpg` | JPEG validators — valid JPEG, PHP appended after EOI | JPEG-only validators | nothing | same as row 1 |
| 4 | `upload_htaccess_poc.htaccess` | execution mapping — `.jpg/.png/.gif` execute as PHP | Apache-served dirs (AllowOverride not None). Upload FIRST, then row 1 as `shell.jpg` | nothing | `GET /uploads/shell.jpg` → marker prints |
| 5 | `upload_user_ini_poc.ini` | execution without Apache — auto-prepends your file into every PHP request | PHP-CGI/FPM. Upload named exactly `.user.ini` | `auto_prepend_file` path must match your stored polyglot name | wait cache_ttl (300s) → `GET` any `.php` in dir → marker prepends |
| 6 | `upload_web_config_poc.config` | ASP.NET execution — buildProvider maps `.poc` to compiled pages | IIS-served upload dirs. Upload FIRST, then `upload_shell_poc.poc` | nothing | `GET /uploads/shell.poc` → marker prints |
| 7 | `upload_shell_poc.poc` | (pairs with row 6) — the compiled marker page | with web.config above | nothing | marker text in response |
| 8 | `upload_wgetrc_poc.wgetrc` | config-file injection — planted `.wgetrc` adds YOUR header/behavior to every target `wget` | traversal-write to home dirs of cron/CI users | the header value; real shapes commented (post_file/input) | marker header visible at any header-echo endpoint or listener |
| 9 | `upload_curlrc_poc.curlrc` | same for curl | same | same | same |
| 10 | `upload_package_json_poc.json` | npm preinstall hook — uploaded projects run YOUR script at install | CI previews, plugin marketplaces, sandboxed builders | replace echo with OOB beacon on authorized targets | install log line / callback |
| 11 | `upload_composer_json_poc.json` | composer post-install hook (PHP equivalent) | PHP project-upload features | same | same |
| 12 | `upload_phar_stub_poc.php` | phar deserialization template — any image + `__HALT_COMPILER()` stub = phar | PHP stacks; build real one with PHPGGC (`phpggc -p phar -pj 'GIF89a'`) | nothing (inert template) | `phar://<uploaded>` trigger on a file-op → DESER-008 |
| 13 | `upload_zip_slip_poc.zip` | unsanitized extractors — `../` entries write outside destination | ZIP import/extract features | nothing | marker file outside the upload dir |
| 14 | `upload_tar_symlink_poc.tar` | symlink-following extractors | tar/backup imports (Linux) | nothing | read created symlink → passwd content |

**Expert order:** baseline headers (`curl -I`) → extension battery → MIME + magic (rows 1–3) → **config files** (rows 4–7) → archives (rows 13–14) → execution confirm → **cleanup** (ledger). Full battery: `FileUpload_CHECKLIST.csv`.

### `02_ssrf/` — SSRF, metadata, blind XXE

| File | Demonstrates | Where to use | What to edit | How to confirm |
|---|---|---|---|---|
| `ssrf_oob_probe_urls.txt` | URL battery: OOB, cloud metadata (AWS/GCP/Azure/Alibaba/Oracle), localhost/admin, obfuscation, schemes (gopher/dict/ftp/ldap) | any URL-accepting parameter | `YOUR-OOB-HOST.example.invalid` → your listener | OOB callback from target IP |
| `ssrf_imds2_gopher_poc.txt` | AWS IMDSv2 bypass — raw PUT via gopher | SSRF on AWS with IMDSv2 enforced | nothing (paste into SSRF param) | token → role → `sts get-caller-identity` read-only |
| `svg_ssrf_beacon.svg` | SSRF via server-side SVG rasterizers | SVG upload + thumbnail/convert | placeholder (2×) | OOB callback from worker IP |
| `ffmpeg_lfi_ssrf_poc.m3u8` | FFmpeg/HLS file-read + internal fetch | transcode features | placeholder (1×) | output contains file content + OOB |
| `xxe_oob_beacon.xml` + `.dtd` | blind XXE two-hop exfil | XML endpoints, OOXML imports | placeholder in BOTH files | two-stage callback |

### `03_rce_linux/` — Linux execution

| File | Demonstrates | What to edit | How to confirm |
|---|---|---|---|
| `cmdi_linux_poc.http` | separator/substitution/newline battery + IFS + quote evasion + time + OOB | `target.com` + parameter | `uid=` output / delay / OOB |
| `shellshock_linux_poc.http` | CVE-2014-6271 header trailers on CGI | target + CGI path | marker/`id` or OOB |
| `linux_wildcard_tar_poc.txt` | **filename-as-argument injection** — `touch -- '--checkpoint=1' '--checkpoint-action=exec=sh shell.sh'` in dirs a `tar *` job globs | the filenames themselves (script = benign echo) | marker in next job cycle |
| `linux_git_hooks_poc.txt` | `.git/hooks/post-checkout` executes on platforms that clone user repos | commit the hook (benign echo) | build/preview log or OOB |
| `linux_authorized_keys_poc.txt` | traversal-write → SSH cash-out — **restricted key form** (`command="echo ...",no-port-forwarding`) | YOUR public key placeholder | SSH login runs only the benign command |

### `04_rce_windows/` — Windows execution

| File | Demonstrates | What to edit | How to confirm |
|---|---|---|---|
| `cmdi_windows_poc.http` | cmd.exe battery: `&`/`\|`/`\|\|`, caret evasion, `%COMSPEC:~-7,3%`, `FOR /F`, PowerShell | target + parameter | `whoami`/`Windows_NT` or OOB |
| `windows_wmic_xsl_rce_poc.http` | **WMIC `/format:` remote-XSL execution** — signed LOLBin fetches AND runs your XSL; also via argument-injection `format=` params and after file-write | target + parameter; OOB host | OOB callback + (authorized) marker echo |
| `windows_wmic_format_poc.xsl` | the benign XSL (echo marker) — serve it at your listener | nothing | fetched when wmic fires |
| `windows_scf_ntlm_leak_poc.scf` | Explorer NTLMv2 leak on folder view (shipped benign → localhost) | localhost → Responder host | Responder auth event |
| `windows_startup_folder_poc.txt` | arbitrary-write → user Startup folder `.bat` cash-out | the .bat content (benign echo to %TEMP%) | marker file at next logon |

### `05_shells/` — reverse shells (authorized engagements ONLY)

| File | Demonstrates | What to edit | Discipline |
|---|---|---|---|
| `revshells_linux_windows.txt` | Linux: bash `/dev/tcp`, socat full-TTY, python PTY, perl, base64-smuggled. Windows: PowerShell IEX, certutil, bitsadmin, mshta, rundll32, `-enc`, netsh pivot | `ATTACKER.example.invalid` + port | **Bug bounty: `id`/`whoami` is a complete Critical proof — stop.** Shells for authorized red-team only (PEXP discipline) |

### `06_document_client/` — document & client-side attacks

| File | Demonstrates | Fires where | What to edit |
|---|---|---|---|
| `pdf_uri_action_poc.pdf` | PDF `/URI` OpenAction — on-open navigation | Adobe/JS readers | nothing |
| `pdf_html_polyglot_poc.html` | valid PDF + valid HTML in one file | served as `.html` → script fires | nothing |
| `svg_xss_open_on_view.svg` | SVG XSS on direct open (NOT via `<img>`) | direct navigation | nothing |
| `xml_xxe_poc.xml` + `.dtd` | external-entity resolution, benignly | entity-resolving parsers | nothing |
| `csv_formula_injection_poc.csv` | formulas inside data cells | spreadsheet apps | nothing |
| `hta_on_view_poc.hta` | HTA = trusted local app on open | Windows (`mshta.exe`) | nothing |
| `html_dangling_markup_poc.html` | unclosed attr swallows page tail (no JS, CSP-proof) | attacker text before victim content | nothing |
| `template_ssti_poc.j2` | SSTI differential probes per engine | server-side template engines | nothing |
| `linux_desktop_entry_poc.desktop` | `.desktop` launcher executes on open (Linux sibling of .hta) | Nautilus/Dolphin double-click; archive with exec-bit | nothing (benign echo; trust-prompt caveat documented) |
| `docx_metadata_payload_poc.docx` | inert XSS + SSTI in `dc:title` | DMS/listing UIs, chat previews | nothing |

### `07_sandbox_bypass/` — application sandbox escapes

| File | Demonstrates | What to edit | How to confirm |
|---|---|---|---|
| `sandbox_node_vm_escape.js` | node `vm` escapes (3 forms) + vm2 deprecation note — **file is inert: it prints the payloads** | nothing (paste payloads into the target's eval feature) | marker output from inside the sandbox |
| `sandbox_python_eval_escape.py` | Python restricted-eval escapes: `__subclasses__` walk, lambda `__globals__`, `catch_warnings` builtins recovery — **inert: prints payloads** | nothing | same |
| `sandbox_jinja2_sandbox_escape.j2` | SandboxedEnvironment walks: `|attr()` filter bypass, `self._TemplateReference__context`, `lipsum|attr` chains | nothing (template probes) | rendered output shows walked values |
| `sandbox_nashorn_java_escape.js` | Java ScriptEngine: `Java.type('java.lang.Runtime')`, reflective fallback, Groovy `.execute()` — **inert: prints payloads** | nothing | marker from the rule engine |
| `sandbox_browser_iframe_matrix.html` | **live self-inspection demo** — embed this page in `<iframe sandbox=...>` variants; the table shows which capabilities each token grants (opaque-origin vs allow-same-origin) | nothing (fully local) | visual table per sandbox token |
| `sandbox_php_disable_functions_bypass.txt` | the disable_functions ladder: LD_PRELOAD via mail/putenv, Imagick delegates, FFI, iconv, callbacks, COM (Windows) + open_basedir bypasses (glob://, symlinks) | your uploaded .so path etc. | surviving function executes benign marker |
| `sandbox_pdf_pdfjs_matrix.txt` | reader-sandbox honesty matrix — what runs where, and the rule: browser sandboxes are NOT bypassable from web content (no false claims) | nothing | report-writing reference |

### `08_modern_bypass/` — modern server & application defenses

| File | Demonstrates | What to edit | How to confirm |
|---|---|---|---|
| `evasion_waf_json_dup_keys.http` | **JSON duplicate-key parser differential** — WAF validates first value, backend takes last; case-dup + unicode-escape key variants | `target.com` + endpoint | naive 403 vs dup-key 200 (same payload) |
| `evasion_waf_content_encoding.http` | **gzip body bypass** — embeds a REAL gzip (base64) of the payload; WAF scans compressed bytes, app decompresses after | decode the embedded GZB64 + target | plain 403 vs gzip 200 |
| `evasion_waf_unicode_normalization.http` | fullwidth `；`, zero-width joiners, homoglyphs, `..%c0%af`, ideographic separators, `\u003c` in JSON | target + parameter | blocked-token reassembly post-normalization |
| `evasion_h2_continuation_flood.txt` | HTTP/2 CONTINUATION header-split — malicious header spread over frames past the WAF's assembly cap (technique + nghttp/python skeleton; DoS variant scope-gated) | target + payload header | direct 403 vs CONTINUATION 200 |
| `evasion_csp_vectors.txt` | 15 CSP bypass vectors: JSONP gadgets, `<base>`, strict-dynamic gadgets, nonce reuse, report-only, data:/blob:, path traversal on allowlisted CDN | per-target analysis | executed payload in CSP'd page |
| `evasion_dompurify_mxss.html` | mXSS showcase — 6 mutation payloads **displayed as text** (inert page); copy into the target's sanitizer input | nothing | sanitized output mutates into executable markup |
| `evasion_jndi_obfuscation.txt` | JNDI lookup obfuscation battery (lower-split, default-value `:-`, `::-`, unicode escapes) — WAFs matching literal `${jndi:` only | OOB placeholder (7 unique subdomains) | OOB callback per form |

### `09_webshells_benign/` — benign marker shells per stack

| File | Demonstrates | What to edit | Discipline |
|---|---|---|---|
| `webshell_benign.php` | proves PHP code execution: echoes marker + `php_uname()` — **accepts NO command input** | nothing | bounty-safe: execution proof only, no C2 shape |
| `webshell_benign.aspx` | proves ASP.NET execution: marker + OS version | nothing | same |
| `webshell_benign.jsp` | proves JSP execution: marker + server info | nothing | same |

Pair with the config-upload files in `01_upload/` (htaccess/user.ini/web.config make these execute).

---

### `10_image_attacks/` — PNG/JPG-carried attacks (XSS / RCE / XXE / DoS)

Every image now shows a **visible banner card** when you open it — so nobody mistakes a silent image for a broken PoC. The banner tells you the payload class and points back here. Attack chunks are preserved exactly.

#### The one that DOES pop on open
- `svg_xss_open_on_view.svg` (in `06_document_client/`) — open it in Chrome/Firefox → alert fires. That is the only image in the lab designed to execute on open (SVGs opened as *documents* run scripts; bitmaps never do).

#### The rest — what each does, where to use it, and how to trigger it

| File | What it does | When you open it locally | The vulnerable context it fires in — and how to demo |
|---|---|---|---|
| `png_imagemagick_read_poc.png` | **CVE-2022-44268 arbitrary file read**: `tEXt` chunk `profile=/etc/passwd` | banner card, no popup | You need an ImageMagick (<=7.1.0-49) pipeline: 1) find a target with avatar/thumbnail upload+resize, 2) upload this PNG, 3) force the convert (view the thumbnail), 4) download the PROCESSED image, 5) `identify -verbose out.png \| grep -A1 png:text` → the read file's content is embedded. Escalate: profile=/proc/self/environ |
| `png_metadata_xss_poc.png` | XSS in `tEXt` Comment/Title chunks | banner card, no popup | Fires where a web app renders PNG metadata RAW: 1) find a gallery/media library/admin table listing uploads with title/description, 2) upload, 3) open that listing → payload executes in the app origin. Also probe metadata-export endpoints |
| `jpg_com_xss_poc.jpg` | XSS in the JPEG COM comment segment | banner card, no popup | Same as above but for JPEG-comment readers (galleries using exiftool/`iptcparse`-style metadata panes) |
| `png_html_polyglot_poc.png` | valid PNG with `<script>` in a tEXt chunk | banner card as image | Fires ONLY if served as `text/html`: check the target's upload-serving headers (`curl -I` → Content-Type text/html or missing nosniff) → open the stored-file URL → script executes. If served as image/png it never fires (DOCA-012) |
| `png_xmp_xxe_poc.png` | XMP (iTXt) metadata carrying an external entity (XXE) | banner card, no popup | Fires in consumers that XML-parse XMP (Adobe XMPCore, DAM pipelines): upload → any feature that reads/converts metadata deeply → OOB callback. Honest note: exiftool-based pipelines print it as text — no XXE claim there |
| `jpg_com_php_poc.jpg` | PHP hidden in the COM segment (different slot than after-EOI) | banner card, no popup | Needs an execution context: config-file tricks (`01_upload/` htaccess/user.ini make the directory parse), phar/include flows, or stacked with an LFI. The benign marker echoes where it executes |
| `jpg_exif_beacon_poc.jpg` | hand-built EXIF (valid TIFF IFD) with a beacon in ImageDescription | banner card, no popup | Fires where EXIF description renders raw (previews, AI-tagging dashboards) or gets re-embedded into derivatives: upload → view metadata pane → OOB callback. Edit the placeholder to your listener first |
| `gif_comment_xss_poc.gif` | XSS in the GIF comment extension | banner card, no popup | Same metadata-rendering class for GIF-consuming galleries/forums |
| `png_dimension_bomb_poc.png` | 99999×99999 declared in <1KB (decompression bomb) | your viewer handles it (modern cap) — that IS the test | Old/unpatched decoders attempt ~10GB on decode: point an old ImageMagick/thumbnail service at it (SCOPE GATED — prove the missing cap, never sustain) |
| `image_filename_xss_poc.txt` | filename-as-payload battery (XSS/traversal/php-name/wildcard/CRLF) | text | Use the names as-is in upload forms that reflect the stored name: gallery listing → reflected XSS; batch-export → traversal; cron-globbed dir → tar/wildcard exec |

**The universal image-test loop (put this in your methodology):**
1. `curl -I` the stored-file URL — note Content-Type, Content-Disposition (inline?), nosniff.
2. Upload the bannered payload → check what the app STORES (name? metadata?) and what it SERVES.
3. Enumerate consumers of the image: thumbnail/convert pipeline (ImageMagick rows), metadata listings (XSS rows), XMP/XML parsers (XXE row), galleries rendering comments (COM rows).
4. Trigger the matching consumer and confirm with the described signal (embedded content / OOB callback / alert in app origin).
5. Clean up planted files (ledger, PEXP-015).

## 5. OS detection first (which RCE battery to run)

```
/api/ping?host=127.0.0.1&ver          → prints a Windows version = cmd.exe
/api/ping?host=127.0.0.1;uname        → prints Linux kernel = POSIX shell
```

Linux-silent **never** means safe — run **both** `03_rce_linux/cmdi_linux_poc.http` and `04_rce_windows/cmdi_windows_poc.http`.

## 6. Escalation discipline

- **Bug bounty:** a benign marker (`alert()`, `id`, `Safe PoC -> x8bitranjit` echo) is a **complete** Critical proof. Do not escalate to real exfiltration, persistence, or destruction.
- **Authorized red team:** escalate per `POST_EXPLOITATION_CHECKLIST.csv` (stabilize → cred-hunt → pivot → ledger → cleanup). Every planted file gets a removal command at creation time.
- **Cleanup rule:** every artifact you upload (config files, polyglots, keys) is deleted after proof — keep the ledger (PEXP-015).

## 7. Tool pairing

| Files | Listener/tool | Kit cross-ref |
|---|---|---|
| `02_ssrf/*`, `08_*/evasion_jndi_*` | interactsh-client / Burp Collaborator | `SSRF_CHECKLIST.csv`, `CLD-004` |
| `01_upload/*` | Burp Upload Scanner, curl | `FileUpload_CHECKLIST.csv`, `DESER-008` |
| `03_rce_linux/*`, `04_rce_windows/*` | Burp Repeater / VS Code REST Client | `CommandInjection_CHECKLIST.csv` |
| `07_sandbox_bypass/*` | Burp Repeater (paste payloads), browser | `SSTI_CHECKLIST` sandbox rows, CMDI-033 |
| `08_modern_bypass/*` | Burp Repeater, nghttp, csp-evaluator | `WAFBypass_CHECKLIST.csv` FILTER-130..136 |
| `05_shells/*` | pwncat-cs / socat | `POST_EXPLOITATION_CHECKLIST.csv` PEXP-001 |
| `04_rce_windows/windows_scf_ntlm_leak_poc.scf` | Responder | `RFI_CHECKLIST.csv` RFI-006 |

— **x8bitranjit** · [in/x8bitranjit](https://in.linkedin.com/in/x8bitranjit)
