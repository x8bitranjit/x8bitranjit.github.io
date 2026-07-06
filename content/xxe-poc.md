# XXE — PoC Scripts

Tooling that backs the XXE kit. *Authorized testing only.* The finding is a **file the parser read, an SSRF it made, or an OOB callback it fired** — not "the XML parsed". Confirm blind with an OOB hit, read **one** non-sensitive file, then stop; tear down the listener. **Click a script to open its source on its own page.**

| Script | What it does |
|---|---|
| [`oob_server.py`](#/xxe/poc/oob_server) | The **blind-XXE workhorse** — serves the malicious external DTD, catches the exfil callback, and **base64-decodes `php://filter`** output automatically. One server for external-DTD + parameter-entity OOB. |
| [`xxe_probe.py`](#/xxe/poc/xxe_probe) | Fires the payload families at a target and classifies the response: **in-band file read**, **`php://filter`** source disclosure, **SSRF**, **blind OOB** (external DTD + parameter entities), XInclude, and content-type switch. |
| [`make_ooxml_xxe.py`](#/xxe/poc/make_ooxml_xxe) | Builds a malicious **OOXML** (`.docx`/`.xlsx`) with XXE in the embedded XML — for **file-upload XXE** against office-doc parsers. |
| [`make_svg_xxe.py`](#/xxe/poc/make_svg_xxe) | Builds a malicious **SVG** carrying XXE — for **image-upload XXE** against SVG/rasterizer parsers. |

## Typical flow
1. Stand up `oob_server.py` (external DTD + exfil catcher).
2. `xxe_probe.py` → try **in-band** read first; if blind, point the payload's `SYSTEM` at your DTD for **OOB** exfil.
3. Upload surface? Craft an `make_svg_xxe.py` / `make_ooxml_xxe.py` artifact and upload it.
4. Escalate `doc()`/`SYSTEM` to **SSRF → cloud metadata**; read **one** benign file to prove; redact secrets; tear down the server.

> Prove the parser **did something** (a file came back, your OOB server was hit, an internal host answered) — not that a `<!DOCTYPE>` was accepted. Read the **Testing Guide** for the per-parser matrix and the **Zero to Expert (Q&A)** for the *why*.
