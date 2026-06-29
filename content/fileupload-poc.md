# File Upload — PoC Scripts & Generators

Test artifacts for the exploitation phase. **All web shells here are benign markers** — they prove code execution by
printing a unique token + hostname; they are **not** interactive backdoors. **Click a file to open it on its own page.**
*Authorized testing only:* prove don't weaponize, never drop an interactive shell, and **delete every uploaded test
file** after the PoC.

| File | Purpose |
|---|---|
| [`webshell_marker.php`](#/fileupload/poc/webshell_marker_php) | Benign RCE proof (prints `RCE-POC-<hash>-<hostname>`) — PHP. |
| [`webshell_marker.phtml`](#/fileupload/poc/webshell_marker_phtml) | Benign RCE proof — `.phtml` (bypasses `.php` blocklists). |
| [`webshell_marker.jsp`](#/fileupload/poc/webshell_marker_jsp) | Benign RCE proof — JSP / Java stacks. |
| [`webshell_marker.aspx`](#/fileupload/poc/webshell_marker_aspx) | Benign RCE proof — ASP.NET / IIS. |
| [`xss.svg`](#/fileupload/poc/xss_svg) | Stored XSS proof (`alert(document.domain)`) — valid only if served inline from app origin. |
| [`xxe.svg`](#/fileupload/poc/xxe_svg) | In-band XXE file read (`/etc/passwd`) via SVG parsing. |
| [`xxe_oob.svg`](#/fileupload/poc/xxe_oob_svg) | Blind/OOB XXE exfil SVG (pairs with the DTD below). |
| [`xxe_oob.dtd`](#/fileupload/poc/xxe_oob_dtd) | The external DTD that drives the OOB XXE exfil (host on your server). |
| [`htaccess_poc.txt`](#/fileupload/poc/htaccess_poc) | `.htaccess` that forces image extensions to run as PHP (rename to `.htaccess`). |
| [`user_ini_poc.txt`](#/fileupload/poc/user_ini_poc) | `.user.ini` (`auto_prepend_file`) PHP-FPM RCE primitive + instructions. |
| [`make_polyglot.sh`](#/fileupload/poc/make_polyglot) | Build GIF+PHP and JPEG(EXIF)+PHP marker polyglots. |
| [`make_zipslip.py`](#/fileupload/poc/make_zipslip) | Build a Zip-Slip archive (benign marker payload). |
| [`make_symlink_tar.sh`](#/fileupload/poc/make_symlink_tar) | Build a symlink tar (read a host file / overwrite a served file on extraction). |
| [`exif_rce_notes.md`](#/fileupload/poc/exif_rce_notes) | How to test the exiftool CVE-2021-22204 safely (OOB only). |
| [`upload_fuzz.sh`](#/fileupload/poc/upload_fuzz) | curl-based extension/MIME bypass tester. |

## How they fit together

1. **Baseline** — upload a clean image, note the storage URL + serving headers.
2. **Build a marker shell / polyglot** with `make_polyglot.sh` (or the raw `webshell_marker.*`).
3. **Bypass controls** (extension/MIME/magic-byte) and upload, then `curl` the stored path → a `RCE-POC-<hash>-<hostname>` response is **Critical RCE**.
4. **For parsed uploads** (SVG/XML/image libs) → XXE/XSS via `xxe_oob.svg` + `xxe_oob.dtd`.
5. **DELETE the uploaded files** and report.

> Read the **Testing Guide Parts II–III** for the bypass matrix and parser-attack surface, and the
> **Zero to Expert (Q&A)** for polyglot, Zip-Slip and `.user.ini` chains.
