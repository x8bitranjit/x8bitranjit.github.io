# File Upload — Upload Files (PoC artifact lab)

**88 benign attack artifacts**, in the original 13-folder layout, each on its own page and each
downloadable byte-exact. These are the *files you upload* — polyglots, config-file uploads, archive
traversal, metadata-carried payloads, document and client-side attacks, sandbox-escape probes and
API batteries — the companion to the Testing Guide's bypass matrix.

> **Inert as shipped.** Payloads are self-referential markers (`alert(document.domain)`, `id`, an echo of
> the machine name) or point at `*.example.invalid` — a reserved TLD that never resolves. Nothing fires
> until *you* replace a placeholder with your own listener. **Authorized testing only:** prove, don't
> weaponize, and delete every artifact you upload.

## How to use this page

1. **Download** — grab the whole lab, a single folder, or one file (buttons below and on every file page).
2. **Stand up a listener first** — `interactsh-client`, Burp Collaborator or your own VPS.
3. **Replace the placeholders** — `YOUR-OOB-HOST.example.invalid` / `ATTACKER.example.invalid` with your
   listener, and `target.example.invalid` with your authorized target. Then search the file for
   `example.invalid` — **zero matches means it is armed**. Nothing in this lab points at a registered
   domain, so an unedited file cannot reach a third party.
4. **Deliver through the target's feature**, confirm with the matching signal, then **clean up and ledger**
   every artifact you planted.

Full operating instructions — the per-file-type editing walkthrough, the binary-placeholder hex-edit
procedure, the pre-fire checklist — are in the lab's own [README](#/fileupload/files/00-readme_md).

## 01_upload — upload-function testing - polyglots, config uploads, archives

| File | Size | What it is | Fires where / how to confirm |
|---|---|---|---|
| [`upload_composer_json_poc.json`](#/fileupload/files/01-upload_composer_json_poc_json) | 458 B | Composer manifest with post-install-cmd and post-update-cmd set to 'echo Safe PoC -&gt; x8bitranjit'; empty require block. | PHP project-upload features that run composer install/update (marketplaces, CI builders); confirm: the echo line in the install log or your beacon. |
| [`upload_curlrc_poc.curlrc`](#/fileupload/files/01-upload_curlrc_poc_curlrc) | 568 B | curl config file whose only directive is header = "X-Safe-PoC: x8bitranjit"; file-write/exfil shapes (output, --post-file) appear only in comments. | Traversal-write or upload into the HOME of a service user that runs curl; confirm: X-Safe-PoC header at a header-echo endpoint or your listener. |
| [`upload_htaccess_poc.htaccess`](#/fileupload/files/01-upload_htaccess_poc_htaccess) | 1.3 KB | Apache config upload: a single 'AddType application/x-httpd-php .jpg .png .gif' directive under 26 lines of usage/cleanup comments. | Apache-served upload dir with AllowOverride != None: upload as .htaccess first, then the polyglot as shell.jpg, then GET it - marker prints. |
| [`upload_jpeg_trailing_php.jpg`](#/fileupload/files/01-upload_jpeg_trailing_php_jpg) `bin` | 705 B | Valid 1x1 JFIF JPEG with the 74-byte benign PHP marker (php_uname()) appended after the FFD9 EOI marker at offset 0x275. | JPEG-only validator where the stored file is later parsed as PHP; survives strict header checks. Confirm: marker + php_uname() in the response body. |
| [`upload_package_json_poc.json`](#/fileupload/files/01-upload_package_json_poc_json) | 646 B | npm manifest with preinstall and postinstall both set to 'echo Safe PoC -&gt; x8bitranjit'; _edit note describes swapping in an OOB beacon. | CI preview builds, plugin/theme marketplace uploads or self-hosted runners that run npm install on uploaded projects; confirm: the echo in the install log. |
| [`upload_phar_stub_poc.php`](#/fileupload/files/01-upload_phar_stub_poc_php) | 947 B | Plain PHP file documenting the phar stub shape; __HALT_COMPILER() appears only inside a comment, so it is not a valid phar. Echoes a marker if run. | Documentation/template only - fires nothing. A real phar is built with PHPGGC and triggered by a file op on phar://&lt;uploaded&gt; (file_exists/getimagesize). |
| [`upload_png_php_polyglot.png`](#/fileupload/files/01-upload_png_php_polyglot_png) `bin` | 161 B | Valid 1x1 grayscale PNG, all 4 chunk CRCs correct; the same benign PHP marker + php_uname() lives in an 82-byte tEXt 'Comment' chunk. | PNG-only upload point whose stored file later executes as PHP (.htaccess/.user.ini mapping, phar://, LFI include); confirm: marker + php_uname() in response. |
| [`upload_polyglot_gif_php.gif`](#/fileupload/files/01-upload_polyglot_gif_php_gif) `bin` | 107 B | Valid 1x1 GIF89a; a 74-byte PHP echo of a benign marker plus php_uname() sits in a 0x21/0xFE comment extension before the image descriptor. | PHP-served upload dir where the stored file is parsed as PHP (via rows 4-6 config, phar:// or LFI); confirm: marker + php_uname() in the response body. |
| [`upload_shell_poc.poc`](#/fileupload/files/01-upload_shell_poc_poc) | 370 B | ASP.NET Web Forms page that Response.Writes the benign marker plus Environment.Version and MachineName as text/plain. No commands, no exfil. | Compiles and runs only once the sibling web.config maps .poc to PageBuildProvider; confirm: marker + .NET version + machine name in a text/plain response. |
| [`upload_tar_symlink_poc.tar`](#/fileupload/files/01-upload_tar_symlink_poc_tar) `bin` | 10.0 KB | 10KB POSIX tar: benign_readme.txt, a symlink poc_symlink_etc_passwd -&gt; /etc/passwd, and a ../../../../poc_tarslip_marker.txt traversal entry. | tar/backup import on Linux with a symlink-following or non-sanitizing extractor; confirm: reading the created symlink returns /etc/passwd, plus the marker file. |
| [`upload_user_ini_poc.ini`](#/fileupload/files/01-upload_user_ini_poc_ini) | 1.4 KB | PHP .user.ini: one 'auto_prepend_file = upload_polyglot_gif_php.gif' line under commented usage notes, cache_ttl and nginx path_info alternates. | nginx/Apache + PHP-CGI/FPM with user_ini.filename enabled: upload as .user.ini, wait cache_ttl (300s), GET any .php in that dir - marker prepends. |
| [`upload_web_config_poc.config`](#/fileupload/files/01-upload_web_config_poc_config) | 1004 B | ASP.NET web.config mapping .poc to PageBuildProvider plus a PageHandlerFactory handler, with customErrors off; commented usage header. | IIS/ASP.NET upload dir that accepts web.config: upload it, then upload_shell_poc.poc, then GET /uploads/shell.poc - marker prints. |
| [`upload_wgetrc_poc.wgetrc`](#/fileupload/files/01-upload_wgetrc_poc_wgetrc) | 690 B | wget config file whose only directive is header = X-Safe-PoC: x8bitranjit; exfil shapes (post_file/input) are commented out, not active. | Traversal-write or upload into the HOME/cwd of a cron/CI user that runs wget; confirm: X-Safe-PoC header at a header-echo endpoint or your listener. |
| [`upload_zip_slip_poc.zip`](#/fileupload/files/01-upload_zip_slip_poc_zip) `bin` | 696 B | ZIP with 3 deflated text entries: benign_readme.txt plus two ../../../../poc_zipslip_marker*.txt traversal names (forward slashes only). | ZIP import/extract feature using a non-sanitizing extractor; confirm: poc_zipslip_marker.txt appears OUTSIDE the destination dir (benign text only). |

## 02_ssrf — SSRF, cloud metadata, blind XXE

| File | Size | What it is | Fires where / how to confirm |
|---|---|---|---|
| [`ffmpeg_lfi_ssrf_poc.m3u8`](#/fileupload/files/02-ffmpeg_lfi_ssrf_poc_m3u8) | 1.6 KB | HLS playlist listing file:///etc/hostname, AWS IMDS and 127.0.0.1:8080 actuator URIs plus one .invalid OOB beacon, under a long comment header. | Server-side FFmpeg/HLS transcoders that resolve playlist URIs; confirm via OOB hit from the worker IP plus file content in the output artifact. |
| [`ssrf_imds2_gopher_poc.txt`](#/fileupload/files/02-ssrf_imds2_gopher_poc_txt) | 2.4 KB | Two URL-encoded gopher:// requests to 169.254.169.254: PUT /latest/api/token, then GET iam/security-credentials/ with the token header. | An SSRF parameter whose fetcher supports gopher:// on AWS with IMDSv2 enforced; confirm token response, then read-only sts get-caller-identity. |
| [`ssrf_oob_probe_urls.txt`](#/fileupload/files/02-ssrf_oob_probe_urls_txt) | 3.6 KB | SSRF/OOB probe URL battery: OOB rows, 6 cloud-metadata endpoints, localhost+admin ports, IP-obfuscation forms, gopher/dict/ftp/ldap schemes. | Any URL-accepting param (fetch/import/avatar-from-url/webhook/export); confirm = OOB callback arriving FROM the target's own server IP, not yours or a CDN. |
| [`svg_ssrf_beacon.svg`](#/fileupload/files/02-svg_ssrf_beacon_svg) | 2.0 KB | Script-free 640x320 SVG whose two &lt;image xlink:href&gt; values fetch a .invalid OOB beacon and http://169.254.169.254/latest/meta-data/. | Server-side SVG rasterizers (thumbnail/convert/watermark/avatar pipelines) that resolve xlink:href; confirm via OOB callback from the worker IP. |
| [`xxe_oob_beacon.dtd`](#/fileupload/files/02-xxe_oob_beacon_dtd) | 901 B | External DTD of the blind-XXE pair: %file = benign text, %eval builds %send at runtime, and line 19 invokes %eval;. Exfil variant kept in comments. | Served from your listener and pulled by a vulnerable XML parser; confirm = a second-hop GET /?d=benign-local-placeholder on the listener after the DTD fetch. |
| [`xxe_oob_beacon.xml`](#/fileupload/files/02-xxe_oob_beacon_xml) | 1.1 KB | Blind-XXE OOB trigger document: DOCTYPE pulls the external DTD from your listener, then invokes %send;; body is plain benign marker text. | XML/XML-backed endpoints, OOXML (docx/xlsx) imports, SAML metadata, RSS/OPML importers; confirm = two-stage callback (DTD fetch, then the ?d= beacon). |

## 03_rce_linux — Linux command execution

| File | Size | What it is | Fires where / how to confirm |
|---|---|---|---|
| [`cmdi_linux_poc.http`](#/fileupload/files/03-cmdi_linux_poc_http) | 2.7 KB | 10-step Linux command-injection .http battery: separators, pipes, &#124;&#124;/&&, $()/backticks, %0a, quote breakouts, sleep-10, OOB, ${IFS}, keyword evasion. | A shell-reaching parameter (the /api/ping?host= placeholder); confirm = uid=... reflected, a ~10s delay stable over 3 retries vs baseline, or an nslookup OOB hit. |
| [`linux_authorized_keys_poc.txt`](#/fileupload/files/03-linux_authorized_keys_poc_txt) | 1.2 KB | Comment-only notes on turning an arbitrary file write into SSH access via ~/.ssh/authorized_keys; ships a placeholder key, no real key material. | An arbitrary-write primitive (traversal or upload landing path) reaching /home/&lt;user&gt;/.ssh/authorized_keys; confirm by SSH login running only the forced benign command. |
| [`linux_git_hooks_poc.txt`](#/fileupload/files/03-linux_git_hooks_poc_txt) | 1.1 KB | Comment-only notes on committing a .git/hooks/post-checkout that echoes a benign marker, plus the core.hooksPath/template gates to test. | CI/PR-preview/scanner runners that clone user repos run post-checkout; confirm in build log or OOB. Caveat: git won't track .git/hooks, so needs hooksPath/template. |
| [`linux_wildcard_tar_poc.txt`](#/fileupload/files/03-linux_wildcard_tar_poc_txt) | 1.2 KB | Notes + 2 live shell lines creating tar --checkpoint-action filenames and a benign shell.sh (id + echo marker); rsync/tar/zip/chown variants listed. | An upload/export/temp dir globbed by a cron tar/rsync/zip/chown job; the filenames become arguments. Confirm via marker or OOB on the next job cycle. |
| [`shellshock_linux_poc.http`](#/fileupload/files/03-shellshock_linux_poc_http) | 1.8 KB | Shellshock (CVE-2014-6271) battery: 4 requests injecting '() { :;};' function-export trailers via User-Agent, Cookie, Referer and X-Custom. | CGI endpoints that spawn bash (/cgi-bin/*, cPanel, legacy appliances); confirm = uid=... or the CVE-2014-6271-benign-marker echo in the body, or an OOB nslookup. |

## 04_rce_windows — Windows command execution

| File | Size | What it is | Fires where / how to confirm |
|---|---|---|---|
| [`cmdi_windows_poc.http`](#/fileupload/files/04-cmdi_windows_poc_http) | 2.8 KB | 11-row Windows command-injection .http battery: & / &#124; / &#124;&#124; separators, echo %OS%, cmd /c, %0A, ping-n timing, OOB, caret escapes, %COMSPEC:~% and FOR /F. | A cmd.exe-reaching parameter where the Linux battery is silent; confirm = whoami output, Windows_NT, a ver string, a 10s ping delay, or an OOB nslookup. |
| [`windows_scf_ntlm_leak_poc.scf`](#/fileupload/files/04-windows_scf_ntlm_leak_poc_scf) | 1.3 KB | INI-format Explorer .scf with IconFile on a UNC path, shipped as \\localhost\benign-share\icon.ico; Explorer authenticates on folder view. | Windows Explorer merely rendering the containing folder - no click needed; shipped form authenticates to localhost, so confirm with a loopback SMB/Responder auth event. |
| [`windows_startup_folder_poc.txt`](#/fileupload/files/04-windows_startup_folder_poc_txt) | 1.2 KB | Notes-only file: shell:startup drop paths, a benign .bat line echoing a marker to %TEMP%, a schtasks onlogon alternative, cleanup discipline. | Nothing executes - documentation only. An operator-authored .bat in shell:startup would run at that user's next logon; confirm by the marker file in %TEMP%. |
| [`windows_wmic_format_poc.xsl`](#/fileupload/files/04-windows_wmic_format_poc_xsl) | 908 B | Benign WMI XSL for wmic /FORMAT:: msxsl:script JScript runs WScript.Shell 'cmd /c echo Safe PoC -&gt; x8bitranjit' and returns an empty string. | Only when wmic - or an app passing a format=/template= option to it - fetches this file; confirm = the echo marker in wmic output plus the HTTP fetch in your log. |
| [`windows_wmic_xsl_rce_poc.http`](#/fileupload/files/04-windows_wmic_xsl_rce_poc_http) | 1.7 KB | 4-row WMIC /FORMAT: remote-XSL battery: cmdi param, app format= argument injection, local XSL after a file-write, and a fetch-only SSRF probe. | Windows hosts where a param reaches cmd.exe or an option is passed to wmic; confirm = OOB callback from the target (wmic itself fetches) plus the XSL's marker echo. |

## 05_shells — reverse shells - authorized engagements only

| File | Size | What it is | Fires where / how to confirm |
|---|---|---|---|
| [`revshells_linux_windows.txt`](#/fileupload/files/05-revshells_linux_windows_txt) | 3.3 KB | Plain-text cheat sheet: 8 Linux and 7 Windows reverse-shell / download-cradle one-liners plus listener-side TTY stabilization notes. | Nothing fires from the file; operator pastes a one-liner into an RCE sink on an authorized host. Confirm = inbound connection on their own nc -lvnp 4444 / socat listener. |

## 06_document_client — document and client-side attacks

| File | Size | What it is | Fires where / how to confirm |
|---|---|---|---|
| [`csv_formula_injection_poc.csv`](#/fileupload/files/06-csv_formula_injection_poc_csv) | 849 B | 6-row CSV: live =1+1 and =HYPERLINK("https://example.com/") cells; DDE and =WEBSERVICE rows kept inert as text with a leading apostrophe/prose. | Spreadsheet apps importing the CSV (Excel/Sheets/LibreOffice): the =1+1 cell renders 2 and the HYPERLINK cell becomes clickable - formulas run from data. |
| [`docx_metadata_payload_poc.docx`](#/fileupload/files/06-docx_metadata_payload_poc_docx) `bin` | 1.5 KB | 4-part OOXML zip; docProps/core.xml dc:title = "&gt;&lt;img src=x onerror=alert(1)&gt; {{7*7}}; document body is benign explanatory paragraphs. | DMS/file-listing/chat-preview UIs that render dc:title unescaped (alert) or pass it through a template engine ({{7*7}} -&gt; 49). Word only shows it as the Title. |
| [`hta_on_view_poc.hta`](#/fileupload/files/06-hta_on_view_poc_hta) | 1.6 KB | HTML Application whose VBScript OnLoad shows a MsgBox only; WScript.Shell/ActiveX deliberately omitted and that omission is documented inline. | Windows: double-click/open runs it under mshta.exe as a trusted local app - the MsgBox is the proof that it ran outside any browser sandbox. |
| [`html_dangling_markup_poc.html`](#/fileupload/files/06-html_dangling_markup_poc_html) | 1.9 KB | Self-contained dangling-markup demo: unclosed &lt;img src="poc_leak_target?captured= swallows the page tail incl. fake SECRET-TOKEN-123-XYZ. No JS. | Any browser rendering it: DevTools &gt; Network shows one request to relative poc_leak_target?captured=&lt;swallowed page tail&gt;. No script, so CSP does not stop it. |
| [`linux_desktop_entry_poc.desktop`](#/fileupload/files/06-linux_desktop_entry_poc_desktop) | 1.1 KB | Freedesktop launcher: Type=Application, Exec=/bin/echo "Safe PoC -&gt; x8bitranjit", Terminal=true; comments note the distro trust-prompt caveat. | Linux file managers (Nautilus/Dolphin) double-click runs Exec= with no exec bit needed; many distros mark downloaded launchers untrusted and prompt first. |
| [`pdf_html_polyglot_poc.html`](#/fileupload/files/06-pdf_html_polyglot_poc_html) `bin` | 1.5 KB | PDF 1.4 at offset 0 (inert /S /NOP OpenAction, one text page) then, after %%EOF, a complete HTML document whose &lt;script&gt; calls alert(). | Served or opened as .html the browser parses the whole file as HTML and the trailing script alerts; in a PDF reader you get the PDF page, HTML tail ignored. |
| [`pdf_uri_action_poc.pdf`](#/fileupload/files/06-pdf_uri_action_poc_pdf) `bin` | 975 B | Minimal 1-page PDF 1.4 whose catalog carries /OpenAction &lt;&lt; /S /URI /URI (https://example.com/) &gt;&gt;; the page text explains the technique. | Readers that honour document actions (Adobe Acrobat prompts, some embedded viewers auto-open) navigate to https://example.com/. Browser viewers ignore it. |
| [`svg_xss_open_on_view.svg`](#/fileupload/files/06-svg_xss_open_on_view_svg) | 1.6 KB | 640x320 SVG with an inline &lt;script&gt; calling alert() with document.domain, plus visible text noting that &lt;img&gt;-embedded SVG does not run scripts. | Direct navigation to the .svg URL or a local file open: script runs in the origin that served it. Does NOT run via &lt;img src&gt; or CSS background (image mode). |
| [`template_ssti_poc.j2`](#/fileupload/files/06-template_ssti_poc_j2) | 1.5 KB | Comment block with the per-engine 7*7 differential table plus RCE escalation one-liners, then a body line probing {{7*7}}, ${7*7}, &lt;%= 7*7 %&gt;, {7*7}. | Only when a server-side engine renders it (invoice/email/theme/PDF builders): 49 or 7777777 in the output identifies the engine. The file itself does nothing. |
| [`xml_xxe_poc.dtd`](#/fileupload/files/06-xml_xxe_poc_dtd) | 551 B | External DTD declaring one plain-text entity named readme; comment states the real XXE swaps it for SYSTEM file:// / http:// variants. | Pulled in by xml_xxe_poc.xml's DOCTYPE in a parser with external-entity resolution enabled; the entity text appearing in output is the positive signal. |
| [`xml_xxe_poc.xml`](#/fileupload/files/06-xml_xxe_poc_xml) | 1.5 KB | &lt;!DOCTYPE poc SYSTEM "xml_xxe_poc.dtd"&gt; plus &readme;; comments list the real file-read / IMDS / blind-OOB entity forms as reference only. | Entity-resolving XML parsers / document importers: resolved_entity showing the DTD text = external entities enabled. Browsers do not resolve; no file/net access. |

## 07_sandbox_bypass — application sandbox escapes

| File | Size | What it is | Fires where / how to confirm |
|---|---|---|---|
| [`sandbox_browser_iframe_matrix.html`](#/fileupload/files/07-sandbox_browser_iframe_matrix_html) | 2.0 KB | Local self-inspection page: inline script tests cookie/localStorage/top-frame/opaque-origin access and prints an iframe-sandbox capability table. | Open directly for an unsandboxed baseline, then embed in &lt;iframe sandbox=...&gt; variants; the rendered table shows which capabilities each token grants. |
| [`sandbox_jinja2_sandbox_escape.j2`](#/fileupload/files/07-sandbox_jinja2_sandbox_escape_j2) | 1.3 KB | Four Jinja2 SandboxedEnvironment probes: &#124;attr() policy bypass, __subclasses__ walk, _TemplateReference__context gadget, lipsum&#124;attr chain. | Pasted into a sandboxed-Jinja template field (CMS/plugin "safe template"); confirm when rendered output shows walked attributes or the id output. |
| [`sandbox_nashorn_java_escape.js`](#/fileupload/files/07-sandbox_nashorn_java_escape_js) | 1013 B | Prints Java ScriptEngine escapes: Nashorn Java.type(java.lang.Runtime), a reflective fallback sketch, and Groovy .execute(); echo marker only. | Java-stack business-rule / expression engines (Nashorn, Groovy); confirm when the marker echo returns from the rule engine. Nashorn is removed in JDK 15+. |
| [`sandbox_node_vm_escape.js`](#/fileupload/files/07-sandbox_node_vm_escape_js) | 1.4 KB | Prints three Node vm escape payloads (constructor chain, Function, exception leak) plus a vm2-deprecation note; payload command is echo &lt;marker&gt;. | Server-side JS eval features on Node (formula/filter fields, template playgrounds, bot builders); confirm when the marker string comes back from inside the sandbox. |
| [`sandbox_pdf_pdfjs_matrix.txt`](#/fileupload/files/07-sandbox_pdf_pdfjs_matrix_txt) | 1.6 KB | Prose matrix of PDF JavaScript execution per reader (Acrobat executes; PDFium/pdf.js/Preview do not) plus an explicit no-false-bypass-claims rule. | Nothing executes - report-writing reference for deciding whether a PDF/reader finding is real and how to scope its severity. |
| [`sandbox_php_disable_functions_bypass.txt`](#/fileupload/files/07-sandbox_php_disable_functions_bypass_txt) | 2.8 KB | disable_functions bypass ladder (proc_open, LD_PRELOAD/Chankro, mail -X, Imagick delegates, FFI, iconv, callbacks, COM) and open_basedir notes. | A PHP target where code runs but system() is disabled; the embedded &lt;?php ?&gt; probe var_dumps which functions survive. Inert as .txt - PHP never parses it. |
| [`sandbox_python_eval_escape.py`](#/fileupload/files/07-sandbox_python_eval_escape_py) | 1.3 KB | Prints four Python restricted-eval escape payloads: __subclasses__ walk, lambda __globals__, catch_warnings builtins recovery, code-object path. | Restricted eval()/exec() input fields in Python apps; confirm when the marker echo runs or the walked object-graph values appear in the response. |

## 08_modern_bypass — modern server and application defenses

| File | Size | What it is | Fires where / how to confirm |
|---|---|---|---|
| [`evasion_csp_vectors.txt`](#/fileupload/files/08-evasion_csp_vectors_txt) | 1.7 KB | Commented list of 15 CSP bypass vectors: JSONP gadget, &lt;base&gt; hijack, strict-dynamic legacy-lib gadget, nonce reuse, data:/blob:, SW importScripts. | Nowhere by itself - a vector list, not a request. Each vector needs the target's own CSP header; validate with csp-evaluator.withgoogle.com plus live header capture. |
| [`evasion_dompurify_mxss.html`](#/fileupload/files/08-evasion_dompurify_mxss_html) | 1.9 KB | Inert HTML page listing 6 mXSS/sanitizer-bypass payloads as entity-escaped display text; no script tag and no live payload markup anywhere. | Nowhere on open - only &lt;ol&gt;/&lt;li&gt;/&lt;p&gt;/&lt;style&gt; tags present, 0 raw payload tags. Fires inside a TARGET's sanitizer when a listed string is pasted into its input. |
| [`evasion_h2_continuation_flood.txt`](#/fileupload/files/08-evasion_h2_continuation_flood_txt) | 2.0 KB | HTTP/2 CONTINUATION-flood WAF-bypass notes: why it works, an nghttp command, a raw-frame python skeleton, the measurement pair, and a DoS scope gate. | H2 edges that cap header assembly (nginx 8KB, WAFs 16-32KB) in front of origins taking 64-256KB; confirm = same payload 403 direct vs 200 via CONTINUATION. |
| [`evasion_jndi_obfuscation.txt`](#/fileupload/files/08-evasion_jndi_obfuscation_txt) | 1.2 KB | JNDI/Log4Shell obfuscation battery - 7 lookup forms (${lower:} split, :- default, ::-, \u escapes, %-encoded), one unique .invalid host each. | A Log4j/JNDI-reachable sink via header spray (UA, XFF, Referer, Origin, Cookie, Authorization). Confirm by a DNS/LDAP hit on your own OOB listener, one per form. |
| [`evasion_waf_content_encoding.http`](#/fileupload/files/08-evasion_waf_content_encoding_http) | 1.8 KB | gzip-body WAF bypass: a real base64 gzip of an &lt;img onerror=alert(document.domain)&gt; JSON comment, plus curl/python senders and double-gzip/br/zstd variants. | APIs where the WAF scans only uncompressed bodies and the framework inflates after inspection; confirm = plain POST 403 (rule 942100) vs gzip POST 200. |
| [`evasion_waf_json_dup_keys.http`](#/fileupload/files/08-evasion_waf_json_dup_keys_http) | 1.8 KB | JSON duplicate-key parser-differential battery: 5 POSTs - dup-key XSS, dup-key UNION SELECT, case-dup, \u-escaped key, and an app-parser echo check. | JSON APIs where the WAF reads the FIRST duplicate value and the backend takes the LAST; confirm = same payload 403 plain vs 200 dup-keyed, then the echo row proves which won. |
| [`evasion_waf_unicode_normalization.http`](#/fileupload/files/08-evasion_waf_unicode_normalization_http) | 1.8 KB | 8-row Unicode/normalization WAF battery: fullwidth U+FF1B, zero-width joiners, homoglyphs, ..%c0%af overlong, &lt; in JSON, NFKC ligature, echo check. | Stacks whose blocklist matches ASCII while the app parser normalizes after the WAF; confirm = the blocked token reassembles post-normalization; row 8 shows which side normalizes. |

## 09_webshells_benign — benign marker shells per stack

| File | Size | What it is | Fires where / how to confirm |
|---|---|---|---|
| [`webshell_benign.aspx`](#/fileupload/files/09-webshell_benign_aspx) | 322 B | ASP.NET page shell: a Page directive (Language C#, ContentType text/plain) then Response.Write of the marker + CLR version, OSVersion, UserName. | An IIS/ASP.NET path that compiles .aspx (pair with 01_upload web.config). Confirm: GET it - text/plain body shows the marker + CLR/OS/user banner. |
| [`webshell_benign.jsp`](#/fileupload/files/09-webshell_benign_jsp) | 265 B | JSP page shell: a page directive (contentType text/plain) then out.println of the marker plus application.getServerInfo() and the os.name property. | A servlet-container path that compiles JSP (Tomcat/Jetty webroot). Confirm: GET it - text/plain body shows the marker + server info and OS name. |
| [`webshell_benign.php`](#/fileupload/files/09-webshell_benign_php) | 486 B | Pure PHP marker shell: sends text/plain, echoes "Safe PoC -&gt; x8bitranjit" + PHP_VERSION, php_uname(), get_current_user(). No command input. | Any path the server executes as PHP (pair with 01_upload .htaccess/user.ini). Confirm: GET the uploaded file - text/plain body shows the marker + version banner. |

## 10_image_attacks — PNG/JPG/GIF-carried attacks - XSS, RCE, XXE, DoS

| File | Size | What it is | Fires where / how to confirm |
|---|---|---|---|
| [`gif_comment_xss_poc.gif`](#/fileupload/files/10-gif_comment_xss_poc_gif) `bin` | 103 B | XSS in the GIF comment extension. | GIF-consuming galleries and forums that render comment metadata. |
| [`image_filename_xss_poc.txt`](#/fileupload/files/10-image_filename_xss_poc_txt) | 1.6 KB | Filename-as-payload battery: XSS, traversal, php-name, wildcard and CRLF forms. | Upload forms that reflect the stored name - gallery listing gives reflected XSS, batch-export gives traversal, a cron-globbed dir gives tar/wildcard exec. |
| [`jpg_com_php_poc.jpg`](#/fileupload/files/10-jpg_com_php_poc_jpg) `bin` | 12.0 KB | PHP hidden in the JPEG COM segment - a different slot than the after-EOI trick. | Needs an execution context: the 01_upload config files, a phar/include flow, or a stacked LFI. The benign marker echoes where it executes. |
| [`jpg_com_xss_poc.jpg`](#/fileupload/files/10-jpg_com_xss_poc_jpg) `bin` | 11.7 KB | XSS payload in the JPEG COM comment segment. | Metadata panes that render JPEG comments raw (exiftool / iptcparse-style galleries). |
| [`jpg_exif_beacon_poc.jpg`](#/fileupload/files/10-jpg_exif_beacon_poc_jpg) `bin` | 11.9 KB | Hand-built EXIF (valid TIFF IFD) with a beacon in ImageDescription. | Where EXIF description renders raw (previews, AI-tagging dashboards) or is re-embedded into derivatives. Edit the 29-char placeholder first - see the README. |
| [`png_dimension_bomb_poc.png`](#/fileupload/files/10-png_dimension_bomb_poc_png) `bin` | 287 B | 99999x99999 declared in under 1 KB - a decompression bomb. | Old/unpatched decoders attempt roughly 10 GB on decode. SCOPE-GATED: prove the missing cap, never sustain it. |
| [`png_html_polyglot_poc.png`](#/fileupload/files/10-png_html_polyglot_poc_png) `bin` | 18.6 KB | Valid PNG that also carries &lt;script&gt; in a tEXt chunk. | Fires ONLY when the stored file is served as text/html - curl -I the upload URL for Content-Type and a missing nosniff. Served as image/png it never fires. |
| [`png_imagemagick_read_poc.png`](#/fileupload/files/10-png_imagemagick_read_poc_png) `bin` | 22.5 KB | CVE-2022-44268 arbitrary file read: a tEXt chunk sets profile=/etc/passwd. | ImageMagick &lt;=7.1.0-49 resize/thumbnail pipeline. Upload, force the convert, download the PROCESSED image, then identify -verbose out.png &#124; grep -A1 png:text. |
| [`png_metadata_xss_poc.png`](#/fileupload/files/10-png_metadata_xss_poc_png) `bin` | 17.7 KB | XSS payload carried in the PNG tEXt Comment/Title chunks. | Any gallery, media library or admin table that renders PNG metadata raw - open the listing and the payload executes in the app origin. |
| [`png_xmp_xxe_poc.png`](#/fileupload/files/10-png_xmp_xxe_poc_png) `bin` | 18.1 KB | XMP (iTXt) metadata carrying an external entity - XXE, inert placeholder host. | Consumers that XML-parse XMP (Adobe XMPCore, DAM pipelines) - OOB callback. Honest note: exiftool-based pipelines print it as text, which is not XXE. |

## 11_bounty_pages — attacker-hosted HTML pages - the deliverables

| File | Size | What it is | Fires where / how to confirm |
|---|---|---|---|
| [`cors_exfil_poc.html`](#/fileupload/files/11-cors_exfil_poc_html) | 1.3 KB | Attacker-hosted page: credentialed fetch of a CORS endpoint, then navigator.sendBeacon of the response body to a collector. | A CORS endpoint reflecting arbitrary Origin with Access-Control-Allow-Credentials: true; confirm by the collector receiving the victim's credentialed response body. |
| [`csrf_autosubmit_poc.html`](#/fileupload/files/11-csrf_autosubmit_poc_html) | 1.0 KB | Auto-submitting hidden POST form (email change, deliberately empty csrf_token) fired by document.forms[0].submit() on page load. | A state-changing POST that lacks or ignores CSRF tokens under SameSite=None (or Lax+GET); confirm the second test account's email actually changed. |
| [`cswsh_poc.html`](#/fileupload/files/11-cswsh_poc_html) | 1.1 KB | Cross-site WebSocket hijacking page: opens a wss connection, sends a subscribe frame, beacons each received message to a collector. | A cookie-authenticated WebSocket endpoint that does not validate Origin; confirm the collector receives frames from the victim's authenticated WS session. |
| [`oauth_callback_poc.html`](#/fileupload/files/11-oauth_callback_poc_html) | 1012 B | OAuth redirect_uri collector: reads code/access_token/state/hash from its own URL, prints them, beacons only if a code or token is present. | Hosted at a redirect_uri the authorization server accepts (loose or bypassable redirect_uri validation); confirm a real code or access_token lands in the page and the collector. |
| [`xsleaks_timing_poc.html`](#/fileupload/files/11-xsleaks_timing_poc_html) | 1.6 KB | XS-Leaks timing harness: 40 paired no-cors credentialed fetches of two URLs, compares medians, reports separation against a 15% threshold. | A cross-origin endpoint whose response time varies with victim state; confirm &gt;15% median separation, stable across 3 runs with zero overlap. |

## 12_api_attacks — API-layer attack batteries

| File | Size | What it is | Fires where / how to confirm |
|---|---|---|---|
| [`README_KEEP`](#/fileupload/files/12-readme_keep) | 324 B | 5-line folder note for 12_api_attacks: names the five batteries, says paste into Burp/REST Client, states the edit + .invalid-is-inert discipline. | Nowhere - plain prose with no payload, URL or request; nothing to send or execute. |
| [`graphql_batch_bypass.http`](#/fileupload/files/12-graphql_batch_bypass_http) | 2.4 KB | 7-POST GraphQL battery: __typename fingerprint, alias-batched OTP brute, array batching, alias enum, node(id) BOLA, mass-assign, $ne NoSQLi variable. | A /graphql endpoint with per-request rate limiting or weak object authz; confirm = N operations served in one request, or account B's object returned to A's token. |
| [`host_header_poison_poc.http`](#/fileupload/files/12-host_header_poison_poc_http) | 1.8 KB | 10-request Host-header battery: reflection baseline, reset poisoning, XFH/X-Host overrides, duplicate Host, port@userinfo, IMDS routing, cache poisoning. | Apps that build links, route, or cache keyed off Host/XFH; confirm = your collector host inside the reset link, or a SECOND clean request served the poisoned response. |
| [`jwt_tamper_battery.txt`](#/fileupload/files/12-jwt_tamper_battery_txt) | 1.6 KB | jwt_tool command matrix: -M at sweep, alg:none, RS256-&gt;HS256, kid injection, jku JWKS, CVE-2022-21449 psychic, HMAC crack/hashcat, claim-tamper notes | Run against a token captured from your own test account; confirm = a forged token accepted AND authorization actually changed (role/sub/tenant/email_verified), not merely a 200. |
| [`lfi_php_wrappers_poc.http`](#/fileupload/files/12-lfi_php_wrappers_poc_http) | 2.2 KB | 8-row PHP LFI wrapper chain: php://filter source read, .env read, filter-chain RCE, data://, expect://, pearcmd.php, session inclusion, log poisoning. | A PHP include/page parameter; confirm = base64 source or .env bytes in the response, or the 'Safe PoC -&gt; x8bitranjit' marker echoing from the poisoned include. |
| [`sqlmap_request_template.txt`](#/fileupload/files/12-sqlmap_request_template_txt) | 666 B | One clean raw GET with sqlmap's * injection marker on host=127.0.0.1*, plus a commented sqlmap/ghauri invocation and bounded-technique discipline note. | Fed to sqlmap -r / ghauri -r against the marked parameter; confirm = the tool reports the injection point and technique (version() + ONE row, never --dump on prod). |

## 13_windows_defender — authorized-engagement security-stack methodology

| File | Size | What it is | Fires where / how to confirm |
|---|---|---|---|
| [`README.md`](#/fileupload/files/13-readme_md) | 1.9 KB | Scope note for the folder: what it is, and what it deliberately does NOT contain. | Read first - it states that no working AMSI-patch, obfuscation or crypter code ships here, and why. |
| [`asr_exclusions_audit.txt`](#/fileupload/files/13-asr_exclusions_audit_txt) | 3.0 KB | The reportable-misconfiguration generator: overbroad exclusions and audit-only ASR rules. | Get-MpPreference audit. An excluded, user-writable path reachable by an execution path is a finding with an owner and a CVSS - zero bypass needed. |
| [`benign_inventory_probes.txt`](#/fileupload/files/13-benign_inventory_probes_txt) | 3.0 KB | Non-evasive recon of the security stack using Defender's OWN cmdlets. | Run on an in-scope host to inventory the stack. Every command is inventory, echo or a Defender-cmdlet query. |
| [`defender_surface_map.txt`](#/fileupload/files/13-defender_surface_map_txt) | 2.8 KB | The 7 Defender protection layers, what each inspects, and the MITRE mapping. | Reference while scoping an authorized engagement - tells you which layer a technique class meets. |
| [`detection_mapping.txt`](#/fileupload/files/13-detection_mapping_txt) | 2.7 KB | Blue-team mirror: each technique class mapped to the event or log that catches it. | Write the detection half of the report - what the defender should have seen. |
| [`engagement_rules.txt`](#/fileupload/files/13-engagement_rules_txt) | 2.0 KB | When AV testing is in scope at all, plus cleanup-ledger rules. | Read before any endpoint work. Bug bounty: endpoint AV is out of scope. |
| [`execution_tradecraft_taxonomy.txt`](#/fileupload/files/13-execution_tradecraft_taxonomy_txt) | 3.3 KB | Technique CLASSES with MITRE IDs and pointers to the original public research. | Study reference. Ships no working bypass implementations by design - study from the cited sources under your own ROE. |

## Lab documentation

| File | Size | What it is |
|---|---|---|
| [`README.md`](#/fileupload/files/00-readme_md) | 38.0 KB | The lab's own operating manual: placeholder convention, per-file-type editing walkthrough, per-folder usage tables, OS-detection order, escalation discipline and tool pairing. |

## The placeholder convention

| You use | Replace the placeholder with |
|---|---|
| Burp Collaborator | `<your-id>.oast.pro` |
| interactsh | `<your-id>.oast.fun` |
| Your own VPS | `<your-ip>` or `<your-domain>` |

Use **one unique subdomain per parameter** (`param1.yourid.oast.fun`) so every callback maps back to the
exact input that produced it.

Two binary artifacts carry their placeholder *inside* an image chunk —
`10_image_attacks/png_xmp_xxe_poc.png` (XMP entity) and `10_image_attacks/jpg_exif_beacon_poc.jpg`
(EXIF beacon). Chunk lengths are byte-counted, so the replacement must be **exactly 29 characters** and
written in a hex editor's overwrite mode. Every other image ships zero-edit.

## Reading these pages

Text artifacts render as highlighted source. **Binary artifacts** — polyglots, archives, PDFs and the
metadata-carrying images — can't be shown as source, so their page shows the detected container, the
**embedded strings where the payload actually lives**, and a hex window. Download the file to use it;
the bytes are byte-exact, CRCs and all.

## Escalation discipline

- **Bug bounty** — a benign marker is a *complete* Critical proof. Do not escalate to real exfiltration,
  persistence or destruction. Endpoint/AV work is out of scope.
- **Authorized red team** — escalate per the Post-Exploitation checklist; every planted file gets its
  removal command written at creation time.
- **Cleanup** — every artifact you upload is deleted after proof, and ledgered.

## Tool pairing

| Files | Listener / tool | Related checklist |
|---|---|---|
| `02_ssrf/*`, `08_modern_bypass/evasion_jndi_*` | interactsh-client / Burp Collaborator | [SSRF](#/checklist/ssrf) |
| `01_upload/*` | Burp Upload Scanner, curl | [File Upload](#/checklist/fileupload) |
| `03_rce_linux/*`, `04_rce_windows/*` | Burp Repeater / VS Code REST Client | [Command Injection](#/checklist/cmdi) |
| `07_sandbox_bypass/*` | Burp Repeater, browser | [SSTI](#/checklist/ssti) |
| `08_modern_bypass/*` | Burp Repeater, nghttp, csp-evaluator | [WAF Bypass](#/checklist/wafbypass) |
| `05_shells/*` | pwncat-cs / socat | [Post-Exploitation](#/checklist/postexp) |
| `04_rce_windows/windows_scf_ntlm_leak_poc.scf` | Responder | [RFI](#/checklist/rfi) |
| `12_api_attacks/*` | Burp Repeater, sqlmap / ghauri | [REST API](#/checklist/restapi) · [GraphQL](#/checklist/graphql) |

Read the **Testing Guide** Parts II–III for the bypass matrix and parser-attack surface, the
**Attack Arsenal** for copy-paste payloads, and the **Zero to Expert (Q&A)** for the polyglot, Zip-Slip
and `.user.ini` chains.
